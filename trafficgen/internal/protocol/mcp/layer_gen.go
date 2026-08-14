package mcp

// MCPGenerator is the mcp terminal-layer generator (mcp 终结层层生成器,
// P4a)。MCP 一次 flow = 一个 MCP 会话（JSON-RPC 2.0 over TCP/HTTP）：
// initialize request → initialize response → notifications/initialized →
// Requests 序列（含合成响应）→ 可选 rounds → 可选 teardown。每条 wire 消息
// 一个"报文事件"（方向 + 完整字节），构建字节由 build* 纯函数产出（复用）。
// 事件模式（http 波 2 方案 A 同款）：TCP 语义（握手/seq-ack/挥手/MSS 分段）
// 交给 tcp 层生成器。
//
// 与 legacy Plan（plan.go:29-229 / http_plan.go:245-540）的差异（文档化
// divergence）：
//   - legacy 自产 TCP 握手（3 包，emit.go emitHandshake）与挥手（stdio：
//     3 包 FIN-ACK up → FIN-ACK down → ACK up，emitTeardown；http_sse 同款；
//     streamable：DELETE /mcp + 204 在带内，http_plan.go:536-539）——事件
//     模式不产：tcp 层生成器负责（防双握手），挥手为 tcp 层标准 4 包
//     （FIN|ACK up → ACK down → FIN|ACK down → ACK up，generator.go:
//     877-947；legacy stdio 是 3 包）。streamable 的 DELETE+204 是应用层
//     HTTP 帧（与握手/挥手无关），作为事件原样保留（tcp 层按数据段处理）。
//     层模型意图：握手/挥手开关由 tcp 层 schema 默认 true 执行；validator
//     校准 Termination = spec.MCP.Shutdown（legacy 恒开，plan.go:222-225
//     读 cfg.Shutdown 决定 teardown 是否产），Handshake 恒 true。
//   - 逐包 Timestamp：legacy 恒 ps.now（plan.go:80）；链上由 ChainPlanner
//     统一回填（chain_planner.go:400），事件流不产。
//   - 构造错误路由：legacy Plan 经 p.errCh + Err()（plan.go:99-105）；链上
//     "驱动失败 → 空流"契约会把生成器错误吞成 completed+0 包
//     （chain_planner.go:382-386），因此本生成器把错误作为 Generate 的
//     同步返回值向上传播（doip/gbt32960 同款纪律）。build* 仅在 method 为
//     空时报错，而 Validate 规则 7/12 已同步拒绝空 method（mcp.go:117-121 /
//     146-148），生成器内错误检查为双保险。
//   - DstPort 默认化：legacy Plan 内默认（plan.go:61-68，stdio→22、
//     其余→8081）；链上由 validateSpecBase 默认化（chain_planner.go dst 端口
//     mcp 分支），生成器不再默认。
//   - initial_seq 随机化：legacy 由 tcp 层承担（emit.go 不产 seq）；链上
//     tcp 层生成器对 spec.TCP.InitialSeq 0 时随机（generator.go:660-663）。
//   - 会话语义：legacy Plan 每调用一个会话，idCounter/sessionID 每会话
//     重置（plan.go:75-94）；链上同样每 flow 一个 MCPGenerator.Generate，
//     语义一致（多会话由引擎侧 strategy 展开）。
//   - sessionID 默认随机 32 位 hex（generateSessionID，plan.go:86-94）：
//     stdio 模式不上线（无 Mcp-Session-Id 头），HTTP 模式进 Mcp-Session-Id
//     头与 postURI（http_plan.go:36/94）——测试须显式设置 cfg.SessionID
//     保证确定性。

import (
	"context"
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// MCPGenerator is the mcp terminal-layer generator.
type MCPGenerator struct{}

// Name returns "mcp".
func (g *MCPGenerator) Name() string { return "mcp" }

// Generate produces one message event per MCP wire message in legacy Plan
// order。TCP 层生成器负责握手/seq-ack/挥手/MSS 分段；错误（构造/emit）同步
// 返回（不做"驱动失败 → 空流"的静默吞咽）。
func (g *MCPGenerator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req.EmitMsg == nil {
		return fmt.Errorf("mcp generator: EmitMsg is nil (generator not wired to a transport layer)")
	}
	c := req.Meta.MCP
	if c == nil {
		return fmt.Errorf("mcp generator: no config (spec.mcp required)")
	}

	// --- 默认化（legacy Plan plan.go:36-72 逐行同款）---
	cfg := *c
	if cfg.Transport == "" {
		cfg.Transport = TransportStdio
	}
	if cfg.ProtocolVersion == "" {
		cfg.ProtocolVersion = DefaultProtocolVersion
	}
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
	// 注意：legacy Plan 的 dstPort 默认化（stdio→22、其余→8081，plan.go:
	// 61-68）由链上 validateSpecBase 承担（chain_planner.go dst 端口 mcp
	// 分支），此处不重复。若未来独立使用本生成器，调用方须保证
	// Meta.DstPort 已默认化。
	shutdown := true
	if cfg.Shutdown != nil {
		shutdown = *cfg.Shutdown
	}

	// Per-flow state（plan.go:74-94 同款）。
	ps := &planState{}
	ps.idCounter = cfg.IDCounter
	if ps.idCounter == 0 {
		ps.idCounter = 1
	}
	if cfg.SessionID != "" {
		ps.sessionID = cfg.SessionID
	} else {
		sid, err := generateSessionID()
		if err != nil {
			return fmt.Errorf("mcp: generate session id: %w", err)
		}
		ps.sessionID = sid
	}

	emit := func(ev layers.MessageEvent) error {
		return g.emitMsg(ctx, req.EmitMsg, ev)
	}

	// 传输分发（plan.go:121-124 同款）：http_sse / streamable 走 HTTP 帧
	// 逻辑；stdio（默认）走逐行 JSON-RPC。三路都同步返回 error——构造错误
	// （buildRequest/buildNotification 空 method）不能吞成"空流 completed"
	// （CLAUDE.md §2 反例；validator Rule 12 拦截为主，此处为双保险）。
	switch cfg.Transport {
	case TransportHTTPSSE:
		if err := g.planHTTPSSEEvents(emit, ps, &cfg); err != nil {
			return err
		}
	case TransportStreamable:
		if err := g.planStreamableEvents(emit, ps, &cfg); err != nil {
			return err
		}
	default:
		if err := g.planStdioEvents(emit, ps, &cfg, rounds, shutdown); err != nil {
			return err
		}
	}
	return nil
}

// planStdioEvents replicates the legacy stdio sequence (plan.go:126-226)
// as message events: initialize request (up) → initialize response (down)
// → notifications/initialized (up) → rounds loop（request/response 逐条 +
// Step 通知）→ teardown 由 tcp 层负责（此处不产）。
func (g *MCPGenerator) planStdioEvents(emit func(layers.MessageEvent) error, ps *planState, cfg *core.MCPConfig, rounds int, shutdown bool) error {
	// 1. initialize request（id = IDCounter，尊重用户覆盖，plan.go:132-140）。
	initID := ps.idCounter
	ps.idCounter++
	initReq, err := buildInitializeRequest(initID, cfg.ProtocolVersion, cfg.ClientInfo, cfg.ClientCapabilities)
	if err != nil {
		return fmt.Errorf("mcp: build initialize request: %w", err)
	}
	if err := emit(layers.MessageEvent{Up: true, Bytes: framePayload(TransportStdio, initReq)}); err != nil {
		return err
	}

	// 2. initialize response（同 id，服务器版本降级 §7.1/T11，plan.go:
	// 142-148）。
	initResp, err := buildInitializeResponse(initID, DefaultProtocolVersion, cfg.ServerInfo, cfg.ServerCapabilities)
	if err != nil {
		return fmt.Errorf("mcp: build initialize response: %w", err)
	}
	if err := emit(layers.MessageEvent{Up: false, Bytes: framePayload(TransportStdio, initResp)}); err != nil {
		return err
	}

	// 3. notifications/initialized（无 params，§7.2 严格模式，plan.go:
	// 150-156）。
	initdN, err := buildInitializedNotification()
	if err != nil {
		return fmt.Errorf("mcp: build initialized notification: %w", err)
	}
	if err := emit(layers.MessageEvent{Up: true, Bytes: framePayload(TransportStdio, initdN)}); err != nil {
		return err
	}

	// 4. Requests loop（plan.go:159-220）。
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
				return fmt.Errorf("mcp: build request %q: %w", req.Method, err)
			}
			if err := emit(layers.MessageEvent{Up: true, Bytes: framePayload(TransportStdio, emitReq)}); err != nil {
				return err
			}

			respBytes, err := synthesizeResponse(respIdx, reqID, req.Method)
			if err != nil {
				return fmt.Errorf("mcp: synthesize response for %q: %w", req.Method, err)
			}
			if err := emit(layers.MessageEvent{Up: false, Bytes: framePayload(TransportStdio, respBytes)}); err != nil {
				return err
			}

			// 本步独立通知（Step == i，下一请求之前，plan.go:185-199）。
			for _, n := range cfg.Notifications {
				if n.Step != i {
					continue
				}
				nb, err := buildNotification(n.Method, n.Params, false)
				if err != nil {
					return fmt.Errorf("mcp: build notification %q: %w", n.Method, err)
				}
				if err := emit(layers.MessageEvent{Up: isClientNotification(n.Method), Bytes: framePayload(TransportStdio, nb)}); err != nil {
					return err
				}
			}
		}

		// Step == len(Requests) 的通知：每轮最后一次请求后触发（plan.go:
		// 202-219，规则 12：Step ∈ [0, len(Requests)] 闭区间）。
		for _, n := range cfg.Notifications {
			if n.Step != len(cfg.Requests) {
				continue
			}
			nb, err := buildNotification(n.Method, n.Params, false)
			if err != nil {
				return fmt.Errorf("mcp: build notification %q: %w", n.Method, err)
			}
			if err := emit(layers.MessageEvent{Up: isClientNotification(n.Method), Bytes: framePayload(TransportStdio, nb)}); err != nil {
				return err
			}
		}
	}

	// 5. Teardown：由 tcp 层生成器负责（termination = shutdown 校准，
	// validator 内写入 spec.TCP）。shutdown 仅用于 validator 校准，此处
	// 无产出。
	_ = shutdown
	return nil
}

// planHTTPSSEEvents replicates the legacy HTTP+SSE sequence
// (http_plan.go:263-400) as message events: GET SSE stream (up) → 200 +
// `endpoint` + initialize response (down) → POST initialize (up) → 202
// (down) → POST notifications/initialized (up) → 202 (down) → rounds loop
// （POST request → 202 → SSE message push）→ teardown 由 tcp 层负责。
func (g *MCPGenerator) planHTTPSSEEvents(emit func(layers.MessageEvent) error, ps *planState, cfg *core.MCPConfig) error {
	hps := newHTTPPlanState(ps, cfg)

	// Step 2：GET 建立 SSE 流（GET 先于 POST，§2.4/§6.3 step 4；不带
	// Mcp-Session-Id，http_plan.go:267-268）。
	if err := emit(layers.MessageEvent{Up: true, Bytes: hps.buildGetSSERequest()}); err != nil {
		return err
	}

	// Step 3：200 OK 带 `endpoint` 事件 + initialize response 的 message
	// 事件（http_plan.go:275-285）。
	initID := ps.idCounter
	ps.idCounter++
	initResp, err := buildInitializeResponse(initID, DefaultProtocolVersion, cfg.ServerInfo, cfg.ServerCapabilities)
	if err != nil {
		return fmt.Errorf("mcp: build initialize response: %w", err)
	}
	if err := emit(layers.MessageEvent{Up: false, Bytes: hps.buildGetSSEResponse(initResp)}); err != nil {
		return err
	}

	// Step 4：initialize request 经 POST 到 endpoint URI（http_plan.go:
	// 289-297）。
	initReq, err := buildInitializeRequest(initID, cfg.ProtocolVersion, cfg.ClientInfo, cfg.ClientCapabilities)
	if err != nil {
		return fmt.Errorf("mcp: build initialize request: %w", err)
	}
	if err := emit(layers.MessageEvent{Up: true, Bytes: hps.buildPostRequest(initReq)}); err != nil {
		return err
	}
	// POST 响应：202 Accepted 无体（T78）。
	if err := emit(layers.MessageEvent{Up: false, Bytes: hps.buildPostAccepted()}); err != nil {
		return err
	}

	// Step 5：notifications/initialized 经 POST（http_plan.go:299-308）。
	initdN, err := buildInitializedNotification()
	if err != nil {
		return fmt.Errorf("mcp: build initialized notification: %w", err)
	}
	if err := emit(layers.MessageEvent{Up: true, Bytes: hps.buildPostRequest(initdN)}); err != nil {
		return err
	}
	if err := emit(layers.MessageEvent{Up: false, Bytes: hps.buildPostAccepted()}); err != nil {
		return err
	}

	// Step 6：Requests loop（http_plan.go:313-394）。
	respIdx := buildResponseIndex(cfg.Responses)
	anyExplicitID := len(cfg.Requests) > 0 && cfg.Requests[0].ID != 0

	for round := 0; round < rounds(cfg); round++ {
		for i, req := range cfg.Requests {
			reqID := req.ID
			if !anyExplicitID {
				reqID = ps.nextID()
			}
			emitEmpty := req.Params == nil && shouldEmitEmptyParams(req.Method)
			emitReq, err := buildRequest(reqID, req.Method, req.Params, emitEmpty)
			if err != nil {
				return fmt.Errorf("mcp: build request %q: %w", req.Method, err)
			}
			if err := emit(layers.MessageEvent{Up: true, Bytes: hps.buildPostRequest(emitReq)}); err != nil {
				return err
			}
			// POST 已接收（202 无体）。
			if err := emit(layers.MessageEvent{Up: false, Bytes: hps.buildPostAccepted()}); err != nil {
				return err
			}

			// 服务器响应经 GET SSE 流推送。
			respBytes, err := synthesizeResponse(respIdx, reqID, req.Method)
			if err != nil {
				return fmt.Errorf("mcp: synthesize response for %q: %w", req.Method, err)
			}
			if err := emit(layers.MessageEvent{Up: false, Bytes: hps.buildSSEMessageEvent(respBytes)}); err != nil {
				return err
			}

			// 本步独立通知（Step == i，http_plan.go:342-365）。
			for _, n := range cfg.Notifications {
				if n.Step != i {
					continue
				}
				nb, err := buildNotification(n.Method, n.Params, false)
				if err != nil {
					return fmt.Errorf("mcp: build notification %q: %w", n.Method, err)
				}
				if isClientNotification(n.Method) {
					// 客户端通知经 POST + 202 确认。
					if err := emit(layers.MessageEvent{Up: true, Bytes: hps.buildPostRequest(nb)}); err != nil {
						return err
					}
					if err := emit(layers.MessageEvent{Up: false, Bytes: hps.buildPostAccepted()}); err != nil {
						return err
					}
				} else {
					// 服务器通知经 SSE 流推送。
					if err := emit(layers.MessageEvent{Up: false, Bytes: hps.buildSSEMessageEvent(nb)}); err != nil {
						return err
					}
				}
			}
		}

		// Step == len(Requests) 的通知（http_plan.go:370-393）。
		for _, n := range cfg.Notifications {
			if n.Step != len(cfg.Requests) {
				continue
			}
			nb, err := buildNotification(n.Method, n.Params, false)
			if err != nil {
				return fmt.Errorf("mcp: build notification %q: %w", n.Method, err)
			}
			if isClientNotification(n.Method) {
				if err := emit(layers.MessageEvent{Up: true, Bytes: hps.buildPostRequest(nb)}); err != nil {
					return err
				}
				if err := emit(layers.MessageEvent{Up: false, Bytes: hps.buildPostAccepted()}); err != nil {
					return err
				}
			} else {
				if err := emit(layers.MessageEvent{Up: false, Bytes: hps.buildSSEMessageEvent(nb)}); err != nil {
					return err
				}
			}
		}
	}

	// Teardown：由 tcp 层生成器负责（http_plan.go:397-399 的 3 包挥手）。
	return nil
}

// planStreamableEvents replicates the legacy Streamable HTTP sequence
// (http_plan.go:405-540) as message events: POST initialize (up) → 200 JSON
// (down) → POST notifications/initialized (up) → 202 (down) → rounds loop
// （POST request → 200 JSON 或 SSE 流 → 客户端通知 POST+202）→ DELETE /mcp
// (up) + 204 (down)（Shutdown=true 时；DELETE 是应用层 HTTP 帧，在带内，
// 不作握手/挥手）。
func (g *MCPGenerator) planStreamableEvents(emit func(layers.MessageEvent) error, ps *planState, cfg *core.MCPConfig) error {
	hps := newHTTPPlanState(ps, cfg)

	// initialize request 经 POST /mcp（Mcp-Session-Id 头，§A.3，
	// http_plan.go:407-415）。
	initID := ps.idCounter
	ps.idCounter++
	initReq, err := buildInitializeRequest(initID, cfg.ProtocolVersion, cfg.ClientInfo, cfg.ClientCapabilities)
	if err != nil {
		return fmt.Errorf("mcp: build initialize request: %w", err)
	}
	if err := emit(layers.MessageEvent{Up: true, Bytes: hps.buildPostRequest(initReq)}); err != nil {
		return err
	}

	// initialize response：200 OK + application/json（§A.3 简单请求/响应
	// 场景，http_plan.go:417-424）。
	initResp, err := buildInitializeResponse(initID, DefaultProtocolVersion, cfg.ServerInfo, cfg.ServerCapabilities)
	if err != nil {
		return fmt.Errorf("mcp: build initialize response: %w", err)
	}
	if err := emit(layers.MessageEvent{Up: false, Bytes: hps.buildStreamableJSONResponse(initResp)}); err != nil {
		return err
	}

	// notifications/initialized 经 POST；仅通知的 POST 以 202 Accepted 确认
	// （http_plan.go:426-436）。
	initdN, err := buildInitializedNotification()
	if err != nil {
		return fmt.Errorf("mcp: build initialized notification: %w", err)
	}
	if err := emit(layers.MessageEvent{Up: true, Bytes: hps.buildPostRequest(initdN)}); err != nil {
		return err
	}
	if err := emit(layers.MessageEvent{Up: false, Bytes: hps.buildPostAccepted()}); err != nil {
		return err
	}

	// Requests loop（http_plan.go:438-505）。
	respIdx := buildResponseIndex(cfg.Responses)
	anyExplicitID := len(cfg.Requests) > 0 && cfg.Requests[0].ID != 0

	for round := 0; round < rounds(cfg); round++ {
		for i, req := range cfg.Requests {
			reqID := req.ID
			if !anyExplicitID {
				reqID = ps.nextID()
			}
			emitEmpty := req.Params == nil && shouldEmitEmptyParams(req.Method)
			emitReq, err := buildRequest(reqID, req.Method, req.Params, emitEmpty)
			if err != nil {
				return fmt.Errorf("mcp: build request %q: %w", req.Method, err)
			}
			if err := emit(layers.MessageEvent{Up: true, Bytes: hps.buildPostRequest(emitReq)}); err != nil {
				return err
			}

			respBytes, err := synthesizeResponse(respIdx, reqID, req.Method)
			if err != nil {
				return fmt.Errorf("mcp: synthesize response for %q: %w", req.Method, err)
			}

			// 本步交错服务器→客户端通知（Step == i）：存在时响应为 200 OK +
			// SSE 流（通知后接响应事件，http_plan.go:464-488）。
			var sseParts [][]byte
			for _, n := range cfg.Notifications {
				if n.Step != i || isClientNotification(n.Method) {
					continue
				}
				nb, err := buildNotification(n.Method, n.Params, false)
				if err != nil {
					return fmt.Errorf("mcp: build notification %q: %w", n.Method, err)
				}
				sseParts = append(sseParts, hps.buildSSEMessageEvent(nb))
			}
			if len(sseParts) > 0 {
				var stream []byte
				for _, part := range sseParts {
					stream = append(stream, part...)
				}
				stream = append(stream, hps.buildSSEMessageEvent(respBytes)...)
				if err := emit(layers.MessageEvent{Up: false, Bytes: hps.buildStreamableSSEResponse(stream)}); err != nil {
					return err
				}
			} else {
				if err := emit(layers.MessageEvent{Up: false, Bytes: hps.buildStreamableJSONResponse(respBytes)}); err != nil {
					return err
				}
			}

			// 本步客户端→服务器通知经 POST + 202（http_plan.go:492-504）。
			for _, n := range cfg.Notifications {
				if n.Step != i || !isClientNotification(n.Method) {
					continue
				}
				nb, err := buildNotification(n.Method, n.Params, false)
				if err != nil {
					return fmt.Errorf("mcp: build notification %q: %w", n.Method, err)
				}
				if err := emit(layers.MessageEvent{Up: true, Bytes: hps.buildPostRequest(nb)}); err != nil {
					return err
				}
				if err := emit(layers.MessageEvent{Up: false, Bytes: hps.buildPostAccepted()}); err != nil {
					return err
				}
			}
		}

		// Step == len(Requests) 的通知（http_plan.go:507-531）。
		for _, n := range cfg.Notifications {
			if n.Step != len(cfg.Requests) {
				continue
			}
			nb, err := buildNotification(n.Method, n.Params, false)
			if err != nil {
				return fmt.Errorf("mcp: build notification %q: %w", n.Method, err)
			}
			if isClientNotification(n.Method) {
				if err := emit(layers.MessageEvent{Up: true, Bytes: hps.buildPostRequest(nb)}); err != nil {
					return err
				}
				if err := emit(layers.MessageEvent{Up: false, Bytes: hps.buildPostAccepted()}); err != nil {
					return err
				}
			} else {
				if err := emit(layers.MessageEvent{Up: false, Bytes: hps.buildSSEMessageEvent(nb)}); err != nil {
					return err
				}
			}
		}
	}

	// DELETE /mcp 终止会话（§2.5/T91，http_plan.go:533-539）：Shutdown=true
	// 时产；这是应用层 HTTP 帧（带内），与握手/挥手无关。
	shutdown := true
	if cfg.Shutdown != nil {
		shutdown = *cfg.Shutdown
	}
	if shutdown {
		if err := emit(layers.MessageEvent{Up: true, Bytes: hps.buildDeleteRequest()}); err != nil {
			return err
		}
		if err := emit(layers.MessageEvent{Up: false, Bytes: hps.buildDeleteResponse()}); err != nil {
			return err
		}
	}
	return nil
}

// rounds resolves the legacy rounds default (cfg.Rounds 0 → 1, plan.go:
// 57-60)。stdio 路径在 Generate 内解析后传入；HTTP 路径共用此 helper。
func rounds(cfg *core.MCPConfig) int {
	r := cfg.Rounds
	if r == 0 {
		return 1
	}
	return r
}

// emitMsg sends one message event, honoring context cancellation so the
// generator cannot hang when the transport layer stops consuming the event
// stream (same escape hatch as the chain_planner wiring callbacks)。
func (g *MCPGenerator) emitMsg(ctx context.Context, emit func(layers.MessageEvent) error, ev layers.MessageEvent) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	return emit(ev)
}

// GenEvents marks this generator as a message event producer.
func (g *MCPGenerator) GenEvents() layers.EventGenerator { return g }

// EmitEvent is the EventGenerator interface method, present only to satisfy
// the producer marker; events flow through GenRequest.EmitMsg, so calling
// this directly is a wiring error — fail loudly.
func (g *MCPGenerator) EmitEvent(ev layers.MessageEvent) error {
	return fmt.Errorf("mcp generator: EmitEvent is not wired; events flow through GenRequest.EmitMsg only")
}

func init() {
	layers.RegisterLayerGenerator("mcp", func() (layers.LayerGenerator, error) {
		return &MCPGenerator{}, nil
	})
	layers.RegisterLayerValidator("mcp", func(spec *core.FlowSpec) error {
		if err := (&Planner{}).Validate(*spec); err != nil {
			return err
		}
		// 握手/挥手校准进 spec.TCP（gbt32960 layer_gen.go:180-198 同款陷阱）：
		// legacy plan.go 恒产 TCP 握手（emitHandshake，plan.go:130）且按
		// cfg.Shutdown 产 teardown（plan.go:222-225）——spec.TCP 零值 false
		// 必须写默认，否则 tcp 层生成器跳过握手/挥手（applySpecToChain 把
		// 零值 false 直落层 config）。握手恒 true（legacy 无开关）；挥手 =
		// cfg.Shutdown（nil → true，legacy 同款默认）。
		if spec.TCP == nil {
			spec.TCP = &core.TCPConfig{}
		}
		spec.TCP.Handshake = true
		spec.TCP.Termination = true
		if spec.MCP != nil && spec.MCP.Shutdown != nil {
			spec.TCP.Termination = *spec.MCP.Shutdown
		}
		return nil
	})
}
