package stun

import (
	"context"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

type Planner struct{}

func (Planner) Name() string { return "stun" }

// Validate checks the flow spec. Wire faults for the negative cases are
// rejected here (expect_error cases fail task submission synchronously).
func (Planner) Validate(spec core.FlowSpec) error {
	if spec.STUN == nil {
		// P0b-2：空配置不再报错——Generate/Plan 已默认化并产默认流
		// （BindingRequest c2s）。允许 nil。
		return nil
	}
	if spec.SrcPort == 0 {
		return fmt.Errorf("stun: source port is required")
	}
	if spec.DstPort == 0 {
		return fmt.Errorf("stun: destination port is required")
	}
	if spec.DstPort > 65535 {
		return fmt.Errorf("stun: destination port %d out of range", spec.DstPort)
	}
	return ValidateConfig(spec.STUN)
}

// legacyPlan drives the STUN event sequence on a single transport without the
// layer chain (kept for the flat-config legacy path and the unit tests).
func (p Planner) Plan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) {
	if err := p.Validate(spec); err != nil {
		return nil, err
	}
	out := make(chan core.PacketConfig, 1)
	go func() {
		defer close(out)
		// P0b-2：空配置默认化（Generate 同款：BindingRequest c2s）。
		if spec.STUN == nil {
			spec.STUN = &core.STUNConfig{Events: []core.STUNEvent{{Kind: "request", Direction: "c2s"}}}
		}
		// STUN over UDP (the only legacy carrier): one datagram per event.
		tids := map[string][]byte{}
		for _, ev := range spec.STUN.Events {
			group := ev.TransactionGroup
			tid, ok := tids[group]
			if !ok {
				var err error
				tid, err = newTransactionID()
				if err != nil {
					return
				}
				tids[group] = tid
			}
			msg, err := BuildMessageFromEvent(&ev, tid)
			if err != nil {
				return
			}
			direction := "up"
			if ev.Direction == "s2c" {
				direction = "down"
			}
			select {
			case <-ctx.Done():
				return
			case out <- core.PacketConfig{
				FlowID:      "stun",
				PacketIndex: 0,
				Direction:   direction,
				Timestamp:   time.Now(),
				L2:          core.L2Config{EtherType: core.EtherTypeFor(spec.SrcIP)},
				L3:          core.L3Base(spec.SrcIP, spec.DstIP, 17, 64, 0, spec),
				L4:          core.L4Config{Protocol: "udp", SrcPort: spec.SrcPort, DstPort: spec.DstPort},
				Payload:     msg,
			}:
			}
		}
	}()
	return out, nil
}

// Generator is the stun layer-terminator generator in the layer chain
// (事件驱动：终结层产出报文事件流，传输层消费)。
type Generator struct{}

func (*Generator) Name() string                     { return "stun" }
func (*Generator) GenEvents() layers.EventGenerator { return &Generator{} }
func (*Generator) EmitEvent(layers.MessageEvent) error {
	return fmt.Errorf("stun generator: EmitEvent is not wired")
}

// Generate emits each STUN event as a message event. It determines the
// carrier (udp/tcp) from the layer chain's transport index, and applies
// TCP framing (2-byte length prefix, RFC 5389 §8.3) for the tcp carrier.
func (g *Generator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req == nil || req.EmitMsg == nil {
		return fmt.Errorf("stun generator: invalid request")
	}
	if req.Meta.STUN == nil {
		// P0b-2：空配置默认化并产默认流（BindingRequest c2s）。与
		// Planner.Plan 的默认化一致。
		req.Meta.STUN = &core.STUNConfig{Events: []core.STUNEvent{{Kind: "request", Direction: "c2s"}}}
	}
	c := req.Meta.STUN

	// Determine the carrier from the transport layer index.
	carrier := "udp"
	for i := len(req.Chain) - 1; i >= 0; i-- {
		switch req.Chain[i].Name {
		case "tcp":
			carrier = "tcp"
			i = -1
			break
		case "udp":
			carrier = "udp"
			i = -1
			break
		}
	}

	tids := map[string][]byte{}
	for _, ev := range c.Events {
		group := ev.TransactionGroup
		tid, ok := tids[group]
		if !ok {
			var err error
			tid, err = newTransactionID()
			if err != nil {
				return err
			}
			tids[group] = tid
		}
		msg, err := BuildMessageFromEvent(&ev, tid)
		if err != nil {
			return err
		}
		if carrier == "tcp" {
			// STUN over TCP: 2-byte message length prefix (RFC 5389 §8.3).
			framed := make([]byte, 2+len(msg))
			binary.BigEndian.PutUint16(framed[:2], uint16(len(msg)))
			copy(framed[2:], msg)
			msg = framed
		}
		evOut := layers.MessageEvent{
			Up:    ev.Direction != "s2c",
			Bytes: msg,
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			if err := req.EmitMsg(evOut); err != nil {
				return err
			}
		}
	}
	return nil
}

func init() {
	layers.RegisterLayerGenerator("stun", func() (layers.LayerGenerator, error) { return &Generator{}, nil })
	layers.RegisterLayerValidator("stun", func(s *core.FlowSpec) error { return (Planner{}).Validate(*s) })
}