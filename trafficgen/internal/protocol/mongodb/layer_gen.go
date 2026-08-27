package mongodb

import (
	"context"
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// MongoDBGenerator implements the layers.LayerGenerator interface.
type MongoDBGenerator struct{}

// Name returns the protocol name.
func (g *MongoDBGenerator) Name() string { return "mongodb" }

// GenEvents returns the event generator.
func (g *MongoDBGenerator) GenEvents() layers.EventGenerator { return g }

// EmitEvent is not wired (events flow through the chain planner).
func (g *MongoDBGenerator) EmitEvent(layers.MessageEvent) error {
	return fmt.Errorf("mongodb generator: EmitEvent is not wired")
}

// Generate generates MongoDB protocol messages from the config.
func (g *MongoDBGenerator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req == nil || req.EmitMsg == nil {
		return fmt.Errorf("mongodb generator: EmitMsg is nil")
	}
	cfg := req.Meta.MongoDB
	if cfg == nil {
		// P0b-2: 空配置默认化并产默认流 (layers 数组路径下层 config 为空/缺省时)。
		// 与 Planner.Plan 的默认化一致——默认产一条 OP_QUERY 报文事件。
		cfg = &core.MongoDBConfig{Messages: []core.MongoDBMessage{{Opcode: "OP_QUERY"}}}
	}
	msgs := cfg.Messages
	if len(cfg.Sessions) > 0 {
		msgs = cfg.Sessions[0].Messages
	}
	for _, m := range msgs {
		payload, err := buildMessage(m)
		if err != nil {
			return err
		}
		op, _ := resolveOpcode(m.Opcode)
		up := opcodeDirection(op) != "s2c"
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
	layers.RegisterLayerGenerator("mongodb", func() (layers.LayerGenerator, error) { return &MongoDBGenerator{}, nil })
	layers.RegisterLayerValidator("mongodb", func(s *core.FlowSpec) error { return (Planner{}).Validate(*s) })
}