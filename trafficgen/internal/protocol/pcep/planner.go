package pcep

import (
	"context"
	"fmt"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// Planner plans PCEP traffic (RFC 5440) over TCP.
type Planner struct{}

func (Planner) Name() string { return "pcep" }

func (Planner) Validate(spec core.FlowSpec) error {
	if spec.PCEP == nil {
		return fmt.Errorf("pcep: config is required")
	}
	return ValidateConfig(spec.PCEP)
}

func (p Planner) Plan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) {
	if err := p.Validate(spec); err != nil {
		return nil, err
	}
	if spec.DstPort == 0 {
		spec.DstPort = 4189
	}

	payloads, ups, err := parsePCEPConfig(spec.PCEP)
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
				FlowID:      "pcep",
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

		runSession := func(srcPort uint16) bool {
			// TCP handshake
			if !emit(true, nil, 0x02, srcPort) || !emit(false, nil, 0x12, srcPort) || !emit(true, nil, 0x10, srcPort) {
				return false
			}
			// Messages
			for i, pdu := range payloads {
				if !emit(ups[i], pdu, 0x18, srcPort) { // PSH|ACK
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

		runSession(spec.SrcPort)
	}()
	return out, nil
}

// PCEPGenerator implements the layers.LayerGenerator interface.
type PCEPGenerator struct{}

func (g *PCEPGenerator) Name() string { return "pcep" }

func (g *PCEPGenerator) GenEvents() layers.EventGenerator { return g }

func (g *PCEPGenerator) EmitEvent(layers.MessageEvent) error {
	return fmt.Errorf("pcep generator: EmitEvent is not wired")
}

func (g *PCEPGenerator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req == nil || req.EmitMsg == nil {
		return fmt.Errorf("pcep generator: EmitMsg is nil")
	}
	cfg := req.Meta.PCEP
	if cfg == nil {
		return fmt.Errorf("pcep: config is required")
	}
	payloads, ups, err := parsePCEPConfig(cfg)
	if err != nil {
		return err
	}
	for i, pdu := range payloads {
		if err := emitSel(ctx, req.EmitMsg, layers.MessageEvent{Up: ups[i], Bytes: pdu}); err != nil {
			return err
		}
	}
	return nil
}

func emitSel(ctx context.Context, emit func(layers.MessageEvent) error, ev layers.MessageEvent) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return emit(ev)
	}
}

func init() {
	layers.RegisterLayerGenerator("pcep", func() (layers.LayerGenerator, error) { return &PCEPGenerator{}, nil })
	layers.RegisterLayerValidator("pcep", func(s *core.FlowSpec) error { return (Planner{}).Validate(*s) })
}
