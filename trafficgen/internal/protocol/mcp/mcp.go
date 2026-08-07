// Package mcp: Planner implementation. The Planner generates MCP wire
// bytes (JSON-RPC 2.0 over TCP) according to design §6: handshake ->
// initialize request/response -> notifications/initialized -> Requests
// sequence (with synthesized Responses) -> optional rounds -> optional
// teardown.
package mcp

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
)

// Planner implements the MCP protocol planner.
//
// errCh 是包内错误传递通道（v1.1.x M-1 修复）：Plan() goroutine 内部
// 的构造错误（如 buildInitializeRequest / synthesizeResponse 返回错误）
// 通过 Err() 暴露给调用方，避免错误被静默吞咽。
type Planner struct {
	errCh chan error
}

// NewPlanner creates a new MCP planner.
func NewPlanner() *Planner { return &Planner{} }

// Name returns the protocol name (used for registry lookup).
func (p *Planner) Name() string { return "mcp" }

// Err 返回一个只读通道，Plan() goroutine 内部的构造错误会通过该通道
// 传递。调用方应在 drain Plan() 返回的 packet 通道后检查 Err()：
//
//	ch, _ := p.Plan(ctx, spec)
//	for pkt := range ch { ... }
//	select {
//	case err := <-p.Err(): return err
//	default:
//	}
//
// 通道带 1 缓冲，足以容纳单次 Plan 内最早出现的错误；后续错误被丢弃
// （goroutine 已 select ctx.Done 退出）。Err() 每次调用返回同一个通道。
func (p *Planner) Err() <-chan error {
	return p.errCh
}

// generateSessionID returns a 32-char hex string suitable as the
// Mcp-Session-Id header value (design §4.3 / §6.5).
func generateSessionID() (string, error) {
	b := make([]byte, DefaultSessionIDLength/2)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// Validate applies design §4.4 validation rules to spec.MCP. It also
// checks spec.SrcIP / spec.DstIP legality (rule 14).
func (p *Planner) Validate(spec core.FlowSpec) error {
	if spec.SrcIP != "" {
		if net.ParseIP(spec.SrcIP) == nil {
			return fmt.Errorf("invalid source IP: %s", spec.SrcIP)
		}
	}
	if spec.DstIP != "" {
		if net.ParseIP(spec.DstIP) == nil {
			return fmt.Errorf("invalid destination IP: %s", spec.DstIP)
		}
	}
	if spec.MCP == nil {
		return fmt.Errorf("mcp config is required")
	}
	cfg := spec.MCP

	// Rule 2: Transport ∈ {"", "stdio", "http_sse", "streamable"}.
	switch cfg.Transport {
	case "", TransportStdio, TransportHTTPSSE, TransportStreamable:
	default:
		return fmt.Errorf("mcp: invalid transport %q (allowed: stdio, http_sse, streamable)", cfg.Transport)
	}

	// Rule 3: ProtocolVersion strict-enum.
	if !validProtocolVersions[cfg.ProtocolVersion] {
		return fmt.Errorf("mcp: invalid protocol_version %q (allowed: 2024-11-05, 2025-03-26, 2025-06-18)", cfg.ProtocolVersion)
	}

	// Rule 4: Auth.Schemes enum.
	for _, s := range cfg.Auth.Schemes {
		if !validAuthSchemes[s] {
			return fmt.Errorf("mcp: invalid auth scheme %q (allowed: Bearer, Basic, OAuth2, Negotiate)", s)
		}
	}

	// Rule 5: State values.
	if !validStateValues[cfg.State.Initial] {
		return fmt.Errorf("mcp: invalid state.initial %q", cfg.State.Initial)
	}
	if !validStateValues[cfg.State.Final] {
		return fmt.Errorf("mcp: invalid state.final %q", cfg.State.Final)
	}

	// Rule 6: Capabilities JSON optional + dup-key rejection.
	if len(cfg.ClientCapabilities) > 0 && !isNullOrEmptyRaw(cfg.ClientCapabilities) {
		if err := checkDuplicateKeys(cfg.ClientCapabilities); err != nil {
			return fmt.Errorf("mcp: client_capabilities %w", err)
		}
	}
	if len(cfg.ServerCapabilities) > 0 && !isNullOrEmptyRaw(cfg.ServerCapabilities) {
		if err := checkDuplicateKeys(cfg.ServerCapabilities); err != nil {
			return fmt.Errorf("mcp: server_capabilities %w", err)
		}
	}

	// Rule 7: each Requests[i].Method non-empty.
	for i, r := range cfg.Requests {
		if r.Method == "" {
			return fmt.Errorf("mcp: requests[%d].method is required", i)
		}
	}

	// Rule 8/9: non-negative counters.
	if cfg.IDCounter < 0 {
		return fmt.Errorf("mcp: id_counter must be >= 0 (got %d)", cfg.IDCounter)
	}
	if cfg.Rounds < 0 {
		return fmt.Errorf("mcp: rounds must be >= 0 (got %d)", cfg.Rounds)
	}

	// Rule 10/11: Parts / Content type enum.
	for i, p := range cfg.Parts {
		if !validRoles[p.Role] {
			return fmt.Errorf("mcp: parts[%d].role %q (allowed: user, assistant)", i, p.Role)
		}
		if !validContentTypes[p.Content.Type] {
			return fmt.Errorf("mcp: parts[%d].content.type %q (allowed: text, image, audio, resource, resource_link)", i, p.Content.Type)
		}
	}

	// Rule 12: Notifications[].Step ∈ [0, len(Requests)].
	for i, n := range cfg.Notifications {
		if n.Step < 0 || n.Step > len(cfg.Requests) {
			return fmt.Errorf("mcp: notifications[%d].step=%d out of range [0, %d]", i, n.Step, len(cfg.Requests))
		}
		if n.Method == "" {
			return fmt.Errorf("mcp: notifications[%d].method is required", i)
		}
	}

	// Rule 13: MCPError.Code ∈ [-32700, -32000] (JSON-RPC 2.0 reserved
	// range, design §4.4 rule 13). Exception: code -1 is the spec-documented
	// sampling rejection code (design §7.13 / §7.19 / Appendix B / T93:
	// sampling/createMessage "User rejected sampling request" uses code -1
	// per MCP spec 2024-11-05/2025-03-26/2025-06-18 client/sampling §Error
	// Handling example). Rejecting -1 would block a spec-compliant sampling
	// reject response.
	for i, m := range cfg.Responses {
		if m.Error != nil && !errCodeInRange(m.Error.Code) && m.Error.Code != -1 {
			return fmt.Errorf("mcp: responses[%d].error.code=%d out of JSON-RPC reserved range [%d, %d] (or -1 for sampling reject)", i, m.Error.Code, errCodeMin, errCodeMax)
		}
	}

	// §5.6 forbidden state ordering: tools/call before initialize is
	// allowed only because the planner auto-injects initialize (§6 step
	// 5a). We don't reject; Validate accepts user sequences as long as
	// individual Methods are non-empty.

	// Detect mixed auto/explicit id mode (§4.1 IDCounter comment): if any
	// Requests[i].ID is non-zero, all IDs must be explicitly set. ID=0
	// means "auto from IDCounter". We forbid mixing; if user sets some
	// IDs but not others, the resulting sequence would be ambiguous.
	if len(cfg.Requests) > 0 {
		anyExplicit := false
		anyAuto := false
		for _, r := range cfg.Requests {
			if r.ID == 0 {
				anyAuto = true
			} else {
				anyExplicit = true
			}
		}
		if anyExplicit && anyAuto {
			return fmt.Errorf("mcp: mixed auto and explicit id assignment is not allowed (all Requests[i].id must be 0 or all must be non-zero)")
		}
	}

	return nil
}

// isNullOrEmptyRaw returns true when raw is nil, empty, or the JSON literal
// "null". Used to treat explicit-null capabilities as "absent" (§4.4 rule
// 6).
func isNullOrEmptyRaw(raw []byte) bool {
	if len(raw) == 0 {
		return true
	}
	s := string(raw)
	if s == "null" || s == "{}" {
		return true
	}
	return false
}

// planState holds per-flow mutable state during Plan execution. Reset for
// each generated flow (count > 1 multi-session).
type planState struct {
	idCounter int
	sessionID string
	now       time.Time
	ipID      uint16
}

// nextID returns the next request id and increments the counter. Used by
// the planner to assign auto ids in order.
func (ps *planState) nextID() int {
	id := ps.idCounter
	ps.idCounter++
	return id
}

// nextIPID returns the next IPv4 identification field value.
func (ps *planState) nextIPID() uint16 {
	id := ps.ipID
	ps.ipID++
	return id
}
