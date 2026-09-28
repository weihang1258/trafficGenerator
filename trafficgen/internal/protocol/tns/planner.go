package tns

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
)

// Planner plans TNS (Oracle Net, TCP 1521) traffic.
type Planner struct{}

func (Planner) Name() string { return "tns" }

func (Planner) Validate(spec core.FlowSpec) error {
	cfg := spec.TNS
	if cfg == nil {
		// P0b-2: 空配置不再报错——Plan 会默认化并产默认流 (layers 数组路径
		// 下 layer config 为空/缺省时)。
		return nil
	}
	if len(cfg.Events) == 0 && len(cfg.Sessions) == 0 {
		return fmt.Errorf("tns: at least one event or session required")
	}
	if len(cfg.Events) > 0 && len(cfg.Sessions) > 0 {
		return fmt.Errorf("tns: events and sessions are mutually exclusive")
	}
	if cfg.ChecksumMode != "" && cfg.ChecksumMode != "disabled" {
		return fmt.Errorf("tns: unsupported checksum mode %q (v1 only supports disabled)", cfg.ChecksumMode)
	}
	if err := checkWireFault(cfg.WireFault); err != nil {
		return err
	}
	evs := cfg.Events
	if len(cfg.Sessions) > 0 {
		for i, s := range cfg.Sessions {
			if len(s.Events) == 0 {
				return fmt.Errorf("tns: session %d: empty events", i)
			}
			// D-TNS-1 G-TNS-3：sessions[1..n] 全量校验（旧实现只校验
			// Sessions[0]，坏 type/data_flags 逃到生成期——见设计 §4.4）。
			if err := validateEvents(s.Events); err != nil {
				return fmt.Errorf("tns: session %d: %w", i, err)
			}
		}
		return validateSpecBase(spec)
	}
	if err := validateEvents(evs); err != nil {
		return fmt.Errorf("tns: %w", err)
	}
	return validateSpecBase(spec)
}

// validateEvents 校验一个事件序列：type 白名单 / 首事件 c2s / direction 枚举
// / data_flags / 状态机（D-TNS-1 G-TNS-8：ACCEPT 前 DATA、REFUSE|REDIRECT
// 后事件、终态语义）。
func validateEvents(evs []core.TNSEvent) error {
	for i, ev := range evs {
		if _, err := eventType(ev); err != nil {
			return fmt.Errorf("event %d: %w", i, err)
		}
		if !directionKnown(ev.Direction) {
			return fmt.Errorf("event %d: unknown direction %q (want c2s/s2c/up/down)", i, ev.Direction)
		}
	}
	if len(evs) > 0 && evs[0].Direction != "" && evs[0].Direction != "up" && evs[0].Direction != "c2s" {
		return fmt.Errorf("first event must be client->server (up)")
	}
	for i, ev := range evs {
		if ev.DataFlags != 0 {
			return fmt.Errorf("event %d: data_flags must be 0", i)
		}
	}
	// D-TNS-1 G-TNS-8（设计 §4.2 行 3）：ACCEPT/REFUSE/REDIRECT 是服务端
	// 专属类型，出现在 c2s（客户端→服务端）方向即判死——旧实现只把
	// direction 二值化（evUp），不校验类型-方向语义。
	for i, ev := range evs {
		t, err := eventType(ev)
		if err != nil {
			return fmt.Errorf("event %d: %w", i, err)
		}
		if evUp(ev) && (t == TypeAccept || t == TypeRefuse || t == TypeRedirect) {
			return fmt.Errorf("event %d: state violation: %s must not appear in the client->server direction",
				i, typeName(t))
		}
	}
	return validateStateMachine(evs)
}

// validateStateMachine 强制设计 §4.1 的会话状态机：CONNECT 首、ACCEPT 后才
// 允许 DATA、REFUSE/REDIRECT 为终态（其后不得再有事件）。
func validateStateMachine(evs []core.TNSEvent) error {
	established, terminal := false, false
	for i, ev := range evs {
		t, err := eventType(ev)
		if err != nil {
			return fmt.Errorf("event %d: %w", i, err)
		}
		if terminal {
			return fmt.Errorf("event %d: state violation: %s is terminal (no further events allowed)", i, typeName(t))
		}
		switch t {
		case TypeConnect:
			if i != 0 {
				return fmt.Errorf("event %d: state violation: CONNECT must be the first event", i)
			}
		case TypeAccept:
			established = true
		case TypeData:
			if !established {
				return fmt.Errorf("event %d: state violation: DATA before ACCEPT", i)
			}
		case TypeRefuse, TypeRedirect:
			terminal = true
		}
	}
	return nil
}

func typeName(t byte) string {
	switch t {
	case TypeConnect:
		return "CONNECT"
	case TypeAccept:
		return "ACCEPT"
	case TypeRefuse:
		return "REFUSE"
	case TypeRedirect:
		return "REDIRECT"
	case TypeData:
		return "DATA"
	}
	return fmt.Sprintf("type %#x", t)
}

// directionKnown：D-TNS-1 G-TNS-8 方向枚举白名单。旧实现的 evUp 把非法值
// 静默落 s2c（"bogus" 当服务端事件），本门在 validator 边界判死。
func directionKnown(dir string) bool {
	switch dir {
	case "", "c2s", "s2c", "up", "down":
		return true
	}
	return false
}

// validateSpecBase：IP 合法性（原 Validate 尾段，sessions/events 两条路径共用）。
func validateSpecBase(spec core.FlowSpec) error {
	if spec.SrcIP != "" && net.ParseIP(spec.SrcIP) == nil {
		return fmt.Errorf("tns: invalid source IP")
	}
	if spec.DstIP != "" && net.ParseIP(spec.DstIP) == nil {
		return fmt.Errorf("tns: invalid destination IP")
	}
	return nil
}

func (p Planner) Plan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) {
	if err := p.Validate(spec); err != nil {
		return nil, err
	}
	if spec.DstPort == 0 {
		spec.DstPort = 1521
	}
	cfg := spec.TNS
	if cfg == nil {
		cfg = &core.TNSConfig{Events: []core.TNSEvent{{Type: "DATA"}}}
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
				FlowID:      "tns",
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
		// TNS events: either a flat list on one flow, or a session per flow.
		// Multi-session expands each session into an independent 4-tuple with
		// its own src port, handshake, events, and teardown (S6).
		if len(cfg.Sessions) > 0 {
			for _, s := range cfg.Sessions {
				srcPort := s.SrcPort
				if srcPort == 0 {
					srcPort = spec.SrcPort
				}
				if !emit(true, nil, 0x02, srcPort) || !emit(false, nil, 0x12, srcPort) || !emit(true, nil, 0x10, srcPort) {
					return
				}
				for _, ev := range s.Events {
					pkt, err := buildPacket(ev)
					if err != nil {
						return
					}
					if !emit(evUp(ev), pkt, 0x18, srcPort) {
						return
					}
				}
				emit(true, nil, 0x11, srcPort)
				emit(false, nil, 0x10, srcPort)
				emit(false, nil, 0x11, srcPort)
				emit(true, nil, 0x10, srcPort)
			}
			return
		}
		// TCP handshake for flat events
		if !emit(true, nil, 0x02, spec.SrcPort) || !emit(false, nil, 0x12, spec.SrcPort) || !emit(true, nil, 0x10, spec.SrcPort) {
			return
		}
		for _, ev := range cfg.Events {
			pkt, err := buildPacket(ev)
			if err != nil {
				return
			}
			if !emit(evUp(ev), pkt, 0x18, spec.SrcPort) {
				return
			}
		}
		// TCP teardown
		emit(true, nil, 0x11, spec.SrcPort)
		emit(false, nil, 0x10, spec.SrcPort)
		emit(false, nil, 0x11, spec.SrcPort)
		emit(true, nil, 0x10, spec.SrcPort)
	}()
	return out, nil
}

// evUp resolves an event's direction: "c2s" or "up" maps to true (client→server),
// "s2c" or "down" maps to false (server→client). Empty defaults to true.
func evUp(ev core.TNSEvent) bool {
	switch ev.Direction {
	case "", "c2s", "up":
		return true
	default:
		return false
	}
}
