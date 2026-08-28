package mongodb

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
)

// Planner plans MongoDB (TCP 27017) traffic.
type Planner struct{}

func (Planner) Name() string { return "mongodb" }

func (Planner) Validate(spec core.FlowSpec) error {
	cfg := spec.MongoDB
	if cfg == nil {
		// P0b-2: 空配置不再报错——Plan 会默认化并产默认流 (layers 数组路径
		// 下 layer config 为空/缺省时)。
		return nil
	}
	if len(cfg.Messages) == 0 && len(cfg.Sessions) == 0 {
		return fmt.Errorf("mongodb: at least one message or session required")
	}
	if len(cfg.Messages) > 0 && len(cfg.Sessions) > 0 {
		return fmt.Errorf("mongodb: messages and sessions are mutually exclusive")
	}
	if err := checkWireFault(cfg.WireFault); err != nil {
		return err
	}
	msgs := cfg.Messages
	if len(cfg.Sessions) > 0 {
		for i, s := range cfg.Sessions {
			if len(s.Messages) == 0 {
				return fmt.Errorf("mongodb: session %d: empty messages", i)
			}
			for j, m := range s.Messages {
				if _, err := resolveOpcode(m.Opcode); err != nil {
					return fmt.Errorf("mongodb: session %d message %d: %w", i, j, err)
				}
			}
		}
		return nil
	}
	for i, m := range msgs {
		if _, err := resolveOpcode(m.Opcode); err != nil {
			return fmt.Errorf("mongodb: message %d: %w", i, err)
		}
	}
	if spec.SrcIP != "" && net.ParseIP(spec.SrcIP) == nil {
		return fmt.Errorf("mongodb: invalid source IP")
	}
	if spec.DstIP != "" && net.ParseIP(spec.DstIP) == nil {
		return fmt.Errorf("mongodb: invalid destination IP")
	}
	return nil
}

func (p Planner) Plan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) {
	if err := p.Validate(spec); err != nil {
		return nil, err
	}
	if spec.DstPort == 0 {
		spec.DstPort = 27017
	}
	cfg := spec.MongoDB
	if cfg == nil {
		cfg = &core.MongoDBConfig{Messages: []core.MongoDBMessage{{Opcode: "OP_QUERY"}}}
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
				FlowID:      "mongodb",
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

		// runSession emits a full TCP connection: handshake, messages, teardown.
		runSession := func(srcPort uint16, msgs []core.MongoDBMessage) bool {
			// TCP handshake
			if !emit(true, nil, 0x02, srcPort) || !emit(false, nil, 0x12, srcPort) || !emit(true, nil, 0x10, srcPort) {
				return false
			}
			// Messages
			for _, m := range msgs {
				payload, err := buildMessage(m)
				if err != nil {
					return false
				}
				op, _ := resolveOpcode(m.Opcode)
				up := opcodeDirection(op) != "s2c"
				if !emit(up, payload, 0x18, srcPort) {
					return false
				}
			}
			// TCP teardown
			emit(true, nil, 0x11, srcPort)
			emit(false, nil, 0x10, srcPort)
			emit(false, nil, 0x11, srcPort)
			emit(true, nil, 0x10, srcPort)
			return true
		}

		if len(cfg.Sessions) > 0 {
			for _, s := range cfg.Sessions {
				sp := s.SrcPort
				if sp == 0 {
					sp = spec.SrcPort
				}
				if !runSession(sp, s.Messages) {
					return
				}
			}
		} else {
			runSession(spec.SrcPort, cfg.Messages)
		}
	}()
	return out, nil
}

// resolveOpcode resolves an opcode from string or numeric value.
func resolveOpcode(op interface{}) (int32, error) {
	switch o := op.(type) {
	case string:
		c, ok := opcodeForOp(o)
		if !ok {
			return 0, fmt.Errorf("unknown opcode %q", o)
		}
		return c, nil
	case int32:
		if o == 0 {
			return 0, fmt.Errorf("unknown opcode %d", o)
		}
		return o, nil
	case float64:
		v := int32(o)
		if v == 0 {
			return 0, fmt.Errorf("unknown opcode %v", o)
		}
		return v, nil
	default:
		return 0, fmt.Errorf("invalid opcode type %T", op)
	}
}
