package opcua

import (
	"context"
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

type OPCUAGenerator struct{}

func (*OPCUAGenerator) Name() string                     { return "opcua" }
func (*OPCUAGenerator) GenEvents() layers.EventGenerator { return &OPCUAGenerator{} }
func (*OPCUAGenerator) EmitEvent(layers.MessageEvent) error {
	return fmt.Errorf("opcua generator: EmitEvent is not wired")
}

func (g *OPCUAGenerator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req == nil || req.EmitMsg == nil {
		return fmt.Errorf("opcua generator: EmitMsg is nil")
	}
	cfg := req.Meta.OPCUA
	if cfg == nil {
		// P0b-2：空配置默认化并产默认流（security none + read + close）。
		cfg = &core.OPCUAConfig{Close: true}
	}
	events, err := buildEvents(cfg)
	if err != nil {
		return err
	}
	for _, ev := range events {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if err := req.EmitMsg(layers.MessageEvent{Up: ev.Up, Bytes: ev.Bytes}); err != nil {
			return err
		}
	}
	return nil
}

func init() {
	layers.RegisterLayerGenerator("opcua", func() (layers.LayerGenerator, error) { return &OPCUAGenerator{}, nil })
	layers.RegisterLayerValidator("opcua", func(spec *core.FlowSpec) error { return (Planner{}).Validate(*spec) })
}
