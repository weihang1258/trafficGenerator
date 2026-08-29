package cql

import (
	"context"
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// CQLGenerator generates CQL message events for the TCP layer chain.
type CQLGenerator struct{}

// Name returns the protocol name.
func (g *CQLGenerator) Name() string { return "cql" }

// GenEvents marks this generator as a terminal event producer.
func (g *CQLGenerator) GenEvents() layers.EventGenerator { return g }

// EmitEvent is not wired for standalone use.
func (g *CQLGenerator) EmitEvent(layers.MessageEvent) error {
	return fmt.Errorf("cql generator: EmitEvent is not wired")
}

// Generate drives CQL message events from the flow config.
func (g *CQLGenerator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req == nil || req.EmitMsg == nil {
		return fmt.Errorf("cql generator: EmitMsg is nil")
	}
	cfg := req.Meta.CQL
	if cfg == nil {
		return fmt.Errorf("cql: config is required")
	}
	reqVer, respVer, err := versionForProfile(cfg.WireProfile)
	if err != nil {
		return err
	}
	// srcPort 是 session 的 TCP 源端口覆盖（0 = 默认流端口）。
	collect := func(events []core.CQLEvent, srcPort uint16) error {
		for _, ev := range events {
			payload, err := buildFrame(reqVer, respVer, ev)
			if err != nil {
				return err
			}
			up := ev.Direction != "s2c"
			if err := emitSel(ctx, req.EmitMsg, layers.MessageEvent{Up: up, Bytes: payload, SrcPort: srcPort}); err != nil {
				return err
			}
		}
		return nil
	}
	if len(cfg.Events) > 0 {
		return collect(cfg.Events, 0)
	}
	// 每条 session 一条独立 TCP 连接（P0a 模式）：session 源端口带上事件，
	// tcp 层据 SrcPort 判定会话边界（挥旧握新）。
	for _, s := range cfg.Sessions {
		if err := collect(s.Events, s.SrcPort); err != nil {
			return err
		}
	}
	return nil
}

// emitSel sends a message event with context cancellation support.
func emitSel(ctx context.Context, emit func(layers.MessageEvent) error, ev layers.MessageEvent) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return emit(ev)
	}
}

func init() {
	layers.RegisterLayerGenerator("cql", func() (layers.LayerGenerator, error) { return &CQLGenerator{}, nil })
	layers.RegisterLayerValidator("cql", func(s *core.FlowSpec) error { return (Planner{}).Validate(*s) })
}
