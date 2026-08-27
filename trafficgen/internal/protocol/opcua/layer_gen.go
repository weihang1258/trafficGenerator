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
	if req.Meta.OPCUA == nil {
		// P0b-2：空配置默认化并产默认流（security none + read + close）。
		// 与 Planner.Plan 的默认化一致。
		req.Meta.OPCUA = &core.OPCUAConfig{Read: true, Close: true}
	}
	spec := core.FlowSpec{OPCUA: req.Meta.OPCUA, SrcIP: req.Meta.SrcIP, DstIP: req.Meta.DstIP, SrcPort: req.Meta.SrcPort, DstPort: req.Meta.DstPort}
	var events []layers.MessageEvent
	ch, err := (Planner{}).Plan(ctx, spec)
	if err != nil {
		return err
	}
	for pkt := range ch {
		events = append(events, layers.MessageEvent{Up: pkt.Direction == "up", Bytes: pkt.Payload})
	}
	for _, ev := range events {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if err := req.EmitMsg(ev); err != nil {
			return err
		}
	}
	return nil
}

func init() {
	layers.RegisterLayerGenerator("opcua", func() (layers.LayerGenerator, error) { return &OPCUAGenerator{}, nil })
	layers.RegisterLayerValidator("opcua", func(spec *core.FlowSpec) error { return (Planner{}).Validate(*spec) })
}
