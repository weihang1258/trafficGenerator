package kingbase

import (
	"context"
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// KingBaseGenerator implements the layers.LayerGenerator interface.
type KingBaseGenerator struct{}

// Name returns the protocol name.
func (g *KingBaseGenerator) Name() string { return "kingbase" }

// GenEvents returns the event generator.
func (g *KingBaseGenerator) GenEvents() layers.EventGenerator { return g }

// EmitEvent is not wired (events flow through the chain planner).
func (g *KingBaseGenerator) EmitEvent(layers.MessageEvent) error {
	return fmt.Errorf("kingbase generator: EmitEvent is not wired")
}

// Generate generates KingBase protocol events from the config.
func (g *KingBaseGenerator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req == nil || req.EmitMsg == nil {
		return fmt.Errorf("kingbase generator: EmitMsg is nil")
	}
	cfg := req.Meta.KingBase
	if cfg == nil {
		return fmt.Errorf("kingbase: config is required")
	}
	// Collect events from sessions or top-level events.
	events := cfg.Events
	if len(cfg.Sessions) > 0 {
		events = cfg.Sessions[0].Events
	}
	for _, ev := range events {
		payload, err := buildEventPayload(ev)
		if err != nil {
			return err
		}
		up := ev.Direction != "s2c"
		if err := emitSel(ctx, req.EmitMsg, layers.MessageEvent{Up: up, Bytes: payload}); err != nil {
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
	layers.RegisterLayerGenerator("kingbase", func() (layers.LayerGenerator, error) { return &KingBaseGenerator{}, nil })
	layers.RegisterLayerValidator("kingbase", func(s *core.FlowSpec) error { return (Planner{}).Validate(*s) })
}