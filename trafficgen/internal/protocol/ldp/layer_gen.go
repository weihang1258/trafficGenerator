package ldp

import (
	"context"
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// LDPGenerator implements the layers.LayerGenerator interface.
type LDPGenerator struct{}

// Name returns the protocol name.
func (g *LDPGenerator) Name() string { return "ldp" }

// GenEvents returns the event generator.
func (g *LDPGenerator) GenEvents() layers.EventGenerator { return g }

// EmitEvent is not wired (events flow through the chain planner).
func (g *LDPGenerator) EmitEvent(layers.MessageEvent) error {
	return fmt.Errorf("ldp generator: EmitEvent is not wired")
}

// Generate generates LDP protocol messages from the config.
func (g *LDPGenerator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req == nil || req.EmitMsg == nil {
		return fmt.Errorf("ldp generator: EmitMsg is nil")
	}
	cfg := req.Meta.LDP
	if cfg == nil {
		return fmt.Errorf("ldp: config is required")
	}
	payloads, ups, err := parseLDPConfig(cfg)
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

// emitSel sends an event respecting context cancellation.
func emitSel(ctx context.Context, emit func(layers.MessageEvent) error, ev layers.MessageEvent) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return emit(ev)
	}
}

func init() {
	layers.RegisterLayerGenerator("ldp", func() (layers.LayerGenerator, error) { return &LDPGenerator{}, nil })
	layers.RegisterLayerValidator("ldp", func(s *core.FlowSpec) error { return (Planner{}).Validate(*s) })
}
