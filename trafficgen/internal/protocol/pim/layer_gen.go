package pim

import (
	"context"
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// PIMGenerator is the terminal-layer generator for the raw-IP [ip, pim] chain.
type PIMGenerator struct{}

func (g *PIMGenerator) Name() string                     { return "pim" }
func (g *PIMGenerator) GenEvents() layers.EventGenerator { return nil }

// Generate emits PIM-SM full packets via req.Emit (raw-IP [ip, pim] chain).
// The ChainPlanner's raw-IP branch fills L2/DSCP/TTL and swaps L3 src/dst for
// the down direction; here we set L3.SrcIP/DstIP, L3.Protocol, Direction, and
// Payload.
func (g *PIMGenerator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req == nil || req.Emit == nil {
		return fmt.Errorf("pim generator: Emit is nil")
	}
	cfg := req.Meta.PIM
	if cfg == nil {
		return fmt.Errorf("pim generator: PIM config is required")
	}
	if err := (Planner{}).Validate(core.FlowSpec{PIM: cfg, SrcIP: req.Meta.SrcIP, DstIP: req.Meta.DstIP}); err != nil {
		return err
	}
	src := req.Meta.SrcIP
	dst := req.Meta.DstIP
	emit := func(direction string, msg []byte) error {
		pkt := core.PacketConfig{
			FlowID:    "pim",
			Direction: direction,
			L3: core.L3Config{
				SrcIP:    src,
				DstIP:    dst,
				Protocol: core.ProtocolPIM,
			},
			L4:      core.L4Config{Protocol: "pim"},
			Payload: msg,
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			return req.Emit(pkt)
		}
	}

	if len(cfg.Events) > 0 {
		for i, ev := range cfg.Events {
			msg, err := buildMessageByKind(ev, cfg.ChecksumMode)
			if err != nil {
				return fmt.Errorf("pim: events[%d] %v", i, err)
			}
			if err := emit(directionFor(ev.Direction), msg); err != nil {
				return err
			}
		}
		return nil
	}
	return fmt.Errorf("pim: no events configured")
}

// directionFor maps a PIM event's direction to the packet direction. c2s →
// up, s2c → down, empty → up (the ChainPlanner raw-IP branch swaps L3 src/dst
// for "down").
func directionFor(dir string) string {
	if dir == "s2c" {
		return "down"
	}
	return "up"
}

func init() {
	layers.RegisterLayerGenerator("pim", func() (layers.LayerGenerator, error) { return &PIMGenerator{}, nil })
	layers.RegisterLayerValidator("pim", func(s *core.FlowSpec) error { return (Planner{}).Validate(*s) })
}
