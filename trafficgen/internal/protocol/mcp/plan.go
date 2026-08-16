package mcp

import (
	"context"
	"fmt"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
)

// Plan emits PacketConfig objects for the MCP flow per design §6.
//
// Flow:
//  1. Validate.
//  2. Apply defaults (Transport/ProtocolVersion/etc).
//  3. TCP handshake (SYN/SYN-ACK/ACK).
//  4. initialize request -> initialize response -> notifications/initialized.
//  5. For each round: walk Requests[] emitting request + synthesized
//     response, plus any Notifications whose Step == current index.
//  6. Optional TCP teardown (3 packets: FIN-ACK up -> FIN-ACK down -> ACK up).
//
// All PacketConfig objects share the same per-flow src/dst L3/L4 ports.
// Multi-session (spec.Count > 1) is handled by the strategy layer outside
// this planner; each Plan call represents one MCP session (§6.5).
//
// 错误传递（v1.1.x M-1 修复）：Plan() goroutine 内部的构造错误通过
// p.errCh 暴露给调用方，避免错误被静默吞咽。调用方应在 drain 返回的
// packet 通道后检查 p.Err()。
func (p *Planner) Plan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) {
	if err := p.Validate(spec); err != nil {
		return nil, err
	}
	cfg := spec.MCP

	// Apply defaults.
	if cfg.Transport == "" {
		cfg.Transport = TransportStdio
	}
	if cfg.ProtocolVersion == "" {
		cfg.ProtocolVersion = DefaultProtocolVersion
	}
	// Server-side protocol version: the server (trafficgen) speaks only the
	// baseline 2024-11-05. Per design §7.1 / T11 the initialize RESPONSE must
	// downgrade to the server's supported version rather than echo the
	// client's request. The REQUEST still carries the client's version
	// (buildInitializeRequest uses cfg.ProtocolVersion).
	serverVersion := DefaultProtocolVersion
	if cfg.ServerInfo.Version == "" {
		cfg.ServerInfo.Version = "1.0.0"
	}
	if cfg.ServerInfo.Name == "" {
		cfg.ServerInfo.Name = "trafficgen-server"
	}
	if len(cfg.Requests) == 0 {
		cfg.Requests = append([]core.MCPRequest(nil), DefaultRequestSequence...)
	}
	rounds := cfg.Rounds
	if rounds == 0 {
		rounds = 1
	}
	dstPort := spec.DstPort
	if dstPort == 0 {
		if cfg.Transport == TransportStdio {
			dstPort = DefaultPortStdio
		} else {
			dstPort = DefaultPortHTTP
		}
	}
	shutdown := true
	if cfg.Shutdown != nil {
		shutdown = *cfg.Shutdown
	}

	// Per-flow state.
	ps := &planState{}
	ps.idCounter = cfg.IDCounter
	if ps.idCounter == 0 {
		ps.idCounter = 1
	}
	ps.now = time.Now()

	// Session id: honor user-provided cfg.SessionID (HTTP modes), else
	// generate a random 32-char hex id (design §4.3 / §6.5). stdio mode
	// does not use the session id on the wire but a stable id still aids
	// flow debugging.
	if cfg.SessionID != "" {
		ps.sessionID = cfg.SessionID
	} else {
		sid, err := generateSessionID()
		if err != nil {
			return nil, fmt.Errorf("mcp: generate session id: %w", err)
		}
		ps.sessionID = sid
	}

	// v1.1.x M-1 修复：每次 Plan 创建一个带 1 缓冲的 errCh，goroutine
	// 内部最早出现的错误通过 sendErr 非阻塞写入；调用方通过 Err() 读取。
	// 缓冲为 1 保证 sendErr 永不阻塞（即便调用方不读 Err()）。
	p.errCh = make(chan error, 1)
	sendErr := func(err error) {
		select {
		case p.errCh <- err:
		default:
		}
	}

	out := make(chan core.PacketConfig, 256)

	go func() {
		defer close(out)
		select {
		case <-ctx.Done():
			return
		default:
		}

		// HTTP+SSE / Streamable HTTP modes use dedicated framing logic
		// (design §6.3 / §6.4 / Appendix A.2-§A.3): GET-before-POST
		// ordering, `endpoint` event, 202 Accepted, Mcp-Session-Id
		// headers, DELETE /mcp teardown.
		if cfg.Transport == TransportHTTPSSE || cfg.Transport == TransportStreamable {
			planHTTP(ctx, out, spec, cfg, dstPort, ps, rounds, shutdown, sendErr)
			return
		}

		flowID := fmt.Sprintf("mcp-%s-%s-%d-%d", spec.SrcIP, spec.DstIP, spec.SrcPort, dstPort)
		ttl := uint8(64)

		// 1. TCP handshake.
		emitHandshake(ctx, out, spec, dstPort, flowID, ttl, ps)

		// 2. initialize request (id = IDCounter, honoring user override).
		initID := ps.idCounter
		ps.idCounter++
		initReq, err := buildInitializeRequest(initID, cfg.ProtocolVersion, cfg.ClientInfo, cfg.ClientCapabilities)
		if err != nil {
			sendErr(fmt.Errorf("mcp: build initialize request: %w", err))
			return
		}
		emitAppData(ctx, out, spec, dstPort, flowID, "up", ttl, ps, framePayload(cfg.Transport, initReq))

		// 3. initialize response (same id, server downgrades protocol version).
		initResp, err := buildInitializeResponse(initID, serverVersion, cfg.ServerInfo, cfg.ServerCapabilities)
		if err != nil {
			sendErr(fmt.Errorf("mcp: build initialize response: %w", err))
			return
		}
		emitAppData(ctx, out, spec, dstPort, flowID, "down", ttl, ps, framePayload(cfg.Transport, initResp))

		// 4. notifications/initialized (no params, strict spec §7.2).
		initdN, err := buildInitializedNotification()
		if err != nil {
			sendErr(fmt.Errorf("mcp: build initialized notification: %w", err))
			return
		}
		emitAppData(ctx, out, spec, dstPort, flowID, "up", ttl, ps, framePayload(cfg.Transport, initdN))

		// 5. Requests loop.
		respIdx := buildResponseIndex(cfg.Responses)
		anyExplicitID := len(cfg.Requests) > 0 && cfg.Requests[0].ID != 0

		for round := 0; round < rounds; round++ {
			for i, req := range cfg.Requests {
				reqID := req.ID
				if !anyExplicitID {
					reqID = ps.nextID()
				}
				emitEmpty := req.Params == nil && shouldEmitEmptyParams(req.Method)
				emitReq, err := buildRequest(reqID, req.Method, req.Params, emitEmpty)
				if err != nil {
					sendErr(fmt.Errorf("mcp: build request %q: %w", req.Method, err))
					return
				}
				emitAppData(ctx, out, spec, dstPort, flowID, "up", ttl, ps, framePayload(cfg.Transport, emitReq))

				respBytes, err := synthesizeResponse(respIdx, reqID, req.Method)
				if err != nil {
					sendErr(fmt.Errorf("mcp: synthesize response for %q: %w", req.Method, err))
					return
				}
				emitAppData(ctx, out, spec, dstPort, flowID, "down", ttl, ps, framePayload(cfg.Transport, respBytes))

				// Standalone notifications at this step (Step == i, before
				// the next request).
				for _, n := range cfg.Notifications {
					if n.Step != i {
						continue
					}
					dir := "down"
					if isClientNotification(n.Method) {
						dir = "up"
					}
					nb, err := buildNotification(n.Method, n.Params, false)
					if err != nil {
						sendErr(fmt.Errorf("mcp: build notification %q: %w", n.Method, err))
						return
					}
					emitAppData(ctx, out, spec, dstPort, flowID, dir, ttl, ps, framePayload(cfg.Transport, nb))
				}
			}

			// Notifications whose Step == len(Requests) fire after the last
			// request of each round (design §4.4 rule 12: Step ∈ [0,
			// len(Requests)] inclusive).
			for _, n := range cfg.Notifications {
				if n.Step != len(cfg.Requests) {
					continue
				}
				dir := "down"
				if isClientNotification(n.Method) {
					dir = "up"
				}
				nb, err := buildNotification(n.Method, n.Params, false)
				if err != nil {
					sendErr(fmt.Errorf("mcp: build notification %q: %w", n.Method, err))
					return
				}
				emitAppData(ctx, out, spec, dstPort, flowID, dir, ttl, ps, framePayload(cfg.Transport, nb))
			}
		}

		// 6. Teardown (3 packets per socks5 template §6.2).
		if shutdown {
			emitTeardown(ctx, out, spec, dstPort, flowID, ttl, ps)
		}
	}()

	return out, nil
}

// shouldEmitEmptyParams returns true for methods that conventionally carry
// an explicit empty `params: {}` when params are nil (e.g. tools/list).
// Methods like notifications/initialized and ping MUST NOT carry params
// (design §7.2 / §7.3 strict spec mode).
func shouldEmitEmptyParams(method string) bool {
	switch method {
	case "tools/list", "tools/call", "resources/list", "resources/read",
		"resources/subscribe", "prompts/list", "prompts/get",
		"completion/complete", "logging/setLevel":
		return true
	}
	return false
}

// framePayload applies transport-specific framing to a JSON-RPC byte
// payload. For stdio mode (design §2.3), each JSON-RPC object is a single
// line terminated by `\n`. HTTP modes (http_sse / streamable) are handled
// by planHTTP (design §6.3 / §6.4) and never reach this helper — the
// HTTP framing (request line, headers, SSE event wrappers) is applied by
// the httpPlanState builders.
func framePayload(transport string, payload []byte) []byte {
	if transport == TransportStdio || transport == "" {
		// Append the line delimiter. Avoid mutating the caller's slice.
		out := make([]byte, 0, len(payload)+1)
		out = append(out, payload...)
		out = append(out, '\n')
		return out
	}
	return payload
}

// isClientNotification returns true when the notification method is sent
// from client to server (notifications/cancelled, notifications/initialized,
// notifications/roots/list_changed). Server-to-client notifications are
// the default "down" direction.
func isClientNotification(method string) bool {
	switch method {
	case "notifications/cancelled", "notifications/initialized",
		"notifications/roots/list_changed":
		return true
	}
	return false
}
