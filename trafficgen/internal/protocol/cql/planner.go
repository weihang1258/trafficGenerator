package cql

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
)

// Planner implements the CQL/Cassandra native protocol planner.
type Planner struct{}

// Name returns the protocol name.
func (Planner) Name() string { return "cql" }

// Validate validates a CQL flow spec.
func (Planner) Validate(spec core.FlowSpec) error {
	cfg := spec.CQL
	if cfg == nil {
		return fmt.Errorf("cql: config is required")
	}
	// 空 events+sessions = connect-only 会话（TCP 9042 握手+挥手，0 应用帧，7
	// 包），与 cql_connect 用例契约一致（P0b-2 默认流，has_payload=false）。
	// 不再拒绝空 events —— 否则 cql_connect 及 cql_neg_*（events:[]+wire_fault/
	// 坏 profile）都会卡在这道未达具体校验的早退门。
	if len(cfg.Events) > 0 && len(cfg.Sessions) > 0 {
		return fmt.Errorf("cql: events and sessions are mutually exclusive")
	}
	if cfg.WireProfile == "" {
		return fmt.Errorf("cql: wire_profile is required")
	}
	if _, _, err := versionForProfile(cfg.WireProfile); err != nil {
		return err
	}
	if err := checkWireFault(cfg.WireFault); err != nil {
		return err
	}
	if len(cfg.Sessions) > 0 {
		for i, s := range cfg.Sessions {
			if len(s.Events) == 0 {
				return fmt.Errorf("cql: session %d: empty events", i)
			}
			if err := validateEvents(cfg.WireProfile, s.Events); err != nil {
				return fmt.Errorf("cql: session %d: %w", i, err)
			}
		}
	} else if err := validateEvents(cfg.WireProfile, cfg.Events); err != nil {
		return err
	}
	if spec.SrcIP != "" && net.ParseIP(spec.SrcIP) == nil {
		return fmt.Errorf("cql: invalid source IP")
	}
	if spec.DstIP != "" && net.ParseIP(spec.DstIP) == nil {
		return fmt.Errorf("cql: invalid destination IP")
	}
	return nil
}

// v5PreHandshakeKinds are the message kinds the v5 profile still carries
// unframed (native_protocol_v5.spec §2.3.1: the handshake — OPTIONS/STARTUP
// and their responses, plus the auth exchange — precedes the envelope).
// Every other kind is post-handshake and needs the 6-byte envelope header
// (CRC24/CRC32), which this implementation does not build yet — G-CQL-3
// transition档 (B2): reject instead of emitting a bare v4-shaped frame and
// pretending it is v5.
var v5PreHandshakeKinds = map[string]bool{
	"options": true, "supported": true, "startup": true, "ready": true,
	"authenticate": true, "auth_response": true, "auth_success": true,
}

// validateEvents validates event kind, direction, flags, and the session
// state machine (§4/§5).
func validateEvents(profile string, events []core.CQLEvent) error {
	ready := false
	authenticating := false
	for i, ev := range events {
		if _, ok := opcodeForKind(ev.Kind); !ok {
			return fmt.Errorf("cql: event %d: unknown kind %q", i, ev.Kind)
		}
		dir := ev.Direction
		if dir == "" {
			dir = "c2s"
		}
		if dir != "c2s" && dir != "s2c" {
			return fmt.Errorf("cql: event %d: invalid direction %q (want c2s|s2c)", i, dir)
		}
		// Kind-specific direction rules (CQL native protocol §3.1).
		switch ev.Kind {
		case "startup", "options", "query", "prepare", "execute":
			if dir != "c2s" {
				return fmt.Errorf("cql: event %d: %s must be c2s (client→server)", i, ev.Kind)
			}
		case "ready", "supported", "result", "authenticate", "auth_success", "error":
			if dir != "s2c" {
				return fmt.Errorf("cql: event %d: %s must be s2c (server→client)", i, ev.Kind)
			}
		case "auth_response":
			if dir != "c2s" {
				return fmt.Errorf("cql: event %d: auth_response must be c2s (client→server)", i)
			}
		}
		// G-CQL-6：header flags 逐 profile 校验（v4 §2.2 / v5 §2.2）——
		// beta（0x10）只存在于 v5；warning（0x08）只允许出现在 s2c 响应。
		if ev.Flags&FlagBeta != 0 && profile != "cql_v5" {
			return fmt.Errorf("cql: event %d: flags: beta flag 0x10 is v5-only (profile %q)", i, profile)
		}
		if ev.Flags&FlagWarning != 0 && dir != "s2c" {
			return fmt.Errorf("cql: event %d: flags: warning flag 0x08 is response-only (s2c)", i)
		}
		// G-CQL-3（B2 过渡档）：v5 握手后消息需 envelope framing（未实现）——
		// 一律拒，不冒充（W2）。
		if profile == "cql_v5" && !v5PreHandshakeKinds[ev.Kind] {
			return fmt.Errorf("cql: event %d: envelope: cql_v5 supports the pre-handshake unframed face only; %s needs the v5 envelope framing (not implemented)", i, ev.Kind)
		}
		switch ev.Kind {
		case "startup":
			// G-CQL-6：CQL_VERSION 是 STARTUP 的 mandatory 选项
			// (native_protocol_v4.spec §4.1.1)。
			if _, ok := ev.Options["CQL_VERSION"]; !ok {
				return fmt.Errorf("cql: event %d: state: STARTUP requires the mandatory CQL_VERSION option", i)
			}
		case "authenticate":
			authenticating = true
		case "auth_response", "auth_success":
			// G-CQL-6：认证次序门——AUTH_RESPONSE/AUTH_SUCCESS 必须先见
			// AUTHENTICATE；AUTH_SUCCESS 结束认证态并进入 ready。
			if !authenticating {
				return fmt.Errorf("cql: event %d: state: %s without a preceding AUTHENTICATE", i, ev.Kind)
			}
			if ev.Kind == "auth_success" {
				authenticating = false
				ready = true
			}
		case "ready":
			ready = true
			authenticating = false
		}
		// G-CQL-6：业务请求（QUERY/PREPARE/EXECUTE）需 STARTUP→READY（或
		// 认证成功）之后；认证进行中同样拒（ready 未置位）。
		switch ev.Kind {
		case "query", "prepare", "execute":
			if !ready {
				return fmt.Errorf("cql: event %d: state: %s before startup/ready", i, ev.Kind)
			}
			// W1/G-CQL-2：v4 的 QUERY/EXECUTE flags 只有 1 字节宽，超出即
			// 拒绝——静默截断会把 0x100 写成 0x00（未登记高位拒绝，§2）。
			if profile != "cql_v5" && ev.QueryFlags > 0xFF {
				return fmt.Errorf("cql: event %d: flags: query_flags %#x does not fit the v4 [byte] width (max 0xff)", i, ev.QueryFlags)
			}
		}
	}
	return nil
}

// Plan generates packet configs for a CQL flow.
func (p Planner) Plan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) {
	if err := p.Validate(spec); err != nil {
		return nil, err
	}
	if spec.DstPort == 0 {
		spec.DstPort = 9042
	}
	cfg := spec.CQL
	reqVer, respVer, err := versionForProfile(cfg.WireProfile)
	if err != nil {
		return nil, err
	}

	out := make(chan core.PacketConfig, 32)
	go func() {
		defer close(out)
		idx := uint64(0)
		emit := func(up bool, payload []byte, flags uint8, srcPort uint16) bool {
			sip, dip, sp, dp := spec.SrcIP, spec.DstIP, srcPort, spec.DstPort
			dir := "up"
			if !up {
				sip, dip, sp, dp = dip, sip, dp, sp
				dir = "down"
			}
			select {
			case out <- core.PacketConfig{
				FlowID:      "cql",
				PacketIndex: idx,
				Direction:   dir,
				L2:          core.L2Config{EtherType: core.EtherTypeFor(sip)},
				L3:          core.L3Base(sip, dip, 6, 64, uint16(idx), spec),
				L4:          core.L4Config{Protocol: "tcp", SrcPort: sp, DstPort: dp, Flags: flags, WindowSize: 65535},
				Payload:     payload,
				Timestamp:   time.Now(),
			}:
				idx++
				return true
			case <-ctx.Done():
				return false
			}
		}
		if len(cfg.Sessions) > 0 {
			for _, s := range cfg.Sessions {
				sp := s.SrcPort
				if sp == 0 {
					sp = spec.SrcPort
				}
				if err := runSession(ctx, emit, s.Events, sp, reqVer, respVer); err != nil {
					return
				}
			}
			return
		}
		runSession(ctx, emit, cfg.Events, spec.SrcPort, reqVer, respVer)
	}()
	return out, nil
}

// runSession emits the full per-session packet sequence: TCP handshake,
// CQL events as framed messages, TCP teardown.
func runSession(ctx context.Context, emit func(up bool, payload []byte, flags uint8, srcPort uint16) bool, events []core.CQLEvent, srcPort uint16, reqVer, respVer byte) error {
	// TCP handshake: SYN, SYN-ACK, ACK
	if !emit(true, nil, 0x02, srcPort) || !emit(false, nil, 0x12, srcPort) || !emit(true, nil, 0x10, srcPort) {
		return ctx.Err()
	}
	// CQL events: each builds a native protocol frame.
	for _, ev := range events {
		payload, err := buildFrame(reqVer, respVer, ev)
		if err != nil {
			return err
		}
		up := ev.Direction != "s2c"
		if !emit(up, payload, 0x18, srcPort) {
			return ctx.Err()
		}
	}
	// TCP teardown: FIN/ACK (c2s), ACK (s2c), FIN/ACK (s2c), ACK (c2s).
	emit(true, nil, 0x11, srcPort)
	emit(false, nil, 0x10, srcPort)
	emit(false, nil, 0x11, srcPort)
	emit(true, nil, 0x10, srcPort)
	return nil
}
