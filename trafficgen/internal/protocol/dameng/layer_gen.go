package dameng

import (
	"context"
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// DamengGenerator generates Dameng message events for the TCP layer chain.
type DamengGenerator struct{}

func (g *DamengGenerator) Name() string                     { return "dameng" }
func (g *DamengGenerator) GenEvents() layers.EventGenerator { return g }
func (g *DamengGenerator) EmitEvent(layers.MessageEvent) error {
	return fmt.Errorf("dameng generator: EmitEvent is not wired")
}

func (g *DamengGenerator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req == nil || req.EmitMsg == nil {
		return fmt.Errorf("dameng generator: EmitMsg is nil")
	}
	cfg := req.Meta.Dameng
	if cfg == nil {
		// P0b-2: 空配置默认化并产默认流 (layers 数组路径下层 config 为空/缺省时)。
		// 与 Planner.Plan 的默认化一致——默认产一条 connect 事件。
		cfg = &core.DamengConfig{Events: []core.DamengEvent{{Kind: "connect"}}}
	}
	if len(cfg.Events) == 0 && len(cfg.Sessions) == 0 {
		return fmt.Errorf("dameng: at least one event or session required")
	}
	if len(cfg.Events) > 0 {
		for _, ev := range cfg.Events {
			evBytes, err := buildPacket(ev)
			if err != nil {
				return err
			}
			up, err := eventUp(ev)
			if err != nil {
				return err
			}
			if err := emitSel(ctx, req.EmitMsg, layers.MessageEvent{Up: up, Bytes: evBytes}); err != nil {
				return err
			}
		}
		return nil
	}
	for _, s := range cfg.Sessions {
		for _, ev := range s.Events {
			evBytes, err := buildPacket(ev)
			if err != nil {
				return err
			}
			up, err := eventUp(ev)
			if err != nil {
				return err
			}
			// tcp 层据 SrcPort 判定会话边界（0 = 默认流端口）。
			if err := emitSel(ctx, req.EmitMsg, layers.MessageEvent{Up: up, Bytes: evBytes, SrcPort: s.SrcPort}); err != nil {
				return err
			}
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
	layers.RegisterLayerGenerator("dameng", func() (layers.LayerGenerator, error) { return &DamengGenerator{}, nil })
	layers.RegisterLayerValidator("dameng", func(s *core.FlowSpec) error { return (Planner{}).Validate(*s) })
}