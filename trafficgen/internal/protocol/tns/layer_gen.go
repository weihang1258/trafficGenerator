package tns

import (
	"context"
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// TNSGenerator generates TNS message events for the TCP layer chain.
type TNSGenerator struct{}

func (g *TNSGenerator) Name() string                     { return "tns" }
func (g *TNSGenerator) GenEvents() layers.EventGenerator { return g }
func (g *TNSGenerator) EmitEvent(layers.MessageEvent) error {
	return fmt.Errorf("tns generator: EmitEvent is not wired")
}

func (g *TNSGenerator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req == nil || req.EmitMsg == nil {
		return fmt.Errorf("tns generator: EmitMsg is nil")
	}
	cfg := req.Meta.TNS
	if cfg == nil {
		// P0b-2: 空配置默认化并产默认流 (layers 数组路径下层 config 为空/缺省时)。
		// 与 Planner.Plan 的默认化一致——默认产一条 DATA 报文事件。
		cfg = &core.TNSConfig{Events: []core.TNSEvent{{Type: "DATA"}}}
	}
	if len(cfg.Events) == 0 && len(cfg.Sessions) == 0 {
		return fmt.Errorf("tns: at least one event or session required")
	}
	if len(cfg.Events) > 0 {
		for _, ev := range cfg.Events {
			evBytes, err := buildPacket(ev)
			if err != nil {
				return err
			}
			if err := emitSel(ctx, req.EmitMsg, layers.MessageEvent{Up: evUp(ev), Bytes: evBytes}); err != nil {
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
			// 每条 session 一条独立 TCP 连接：把 session 源端口带上事件，tcp 层
			// 据 SrcPort 判定会话边界（P0a 多会话模式，同 postgresql/kingbase）。
			if err := emitSel(ctx, req.EmitMsg, layers.MessageEvent{Up: evUp(ev), Bytes: evBytes, SrcPort: s.SrcPort}); err != nil {
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
	layers.RegisterLayerGenerator("tns", func() (layers.LayerGenerator, error) { return &TNSGenerator{}, nil })
	layers.RegisterLayerValidator("tns", func(s *core.FlowSpec) error { return (Planner{}).Validate(*s) })
}
