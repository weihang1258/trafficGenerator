package bgp

import (
	"context"
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

type BGPGenerator struct{}
func (*BGPGenerator) Name() string { return "bgp" }
func (g *BGPGenerator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req == nil || req.EmitMsg == nil { return fmt.Errorf("bgp generator: EmitMsg is nil") }
	// P0b-2：空配置默认化并产默认流（layers 数组路径层 config 为空/缺省时）。
	// 与 Planner.Plan 的默认化一致。
	cfg := req.Meta.BGP
	if cfg == nil {
		cfg = &BGPConfig{}
	}
	if err := ValidateConfig(cfg); err != nil { return err }
	n := normalized(cfg)
	open, err := BuildOpen(&n); if err != nil { return err }
	ka, err := BuildKeepalive(); if err != nil { return err }
	emit := func(up bool, b []byte) error { select { case <-ctx.Done(): return ctx.Err(); default: return req.EmitMsg(layers.MessageEvent{Up:up,Bytes:b}) } }
	if err := emit(true,open); err != nil { return err }
	if err := emit(false,open); err != nil { return err }
	if err := emit(true,ka); err != nil { return err }
	if err := emit(false,ka); err != nil { return err }
	if err := emit(true,ka); err != nil { return err }
	return emit(false,ka)
}
func (*BGPGenerator) GenEvents() layers.EventGenerator { return &BGPGenerator{} }
func (*BGPGenerator) EmitEvent(layers.MessageEvent) error { return fmt.Errorf("bgp generator: EmitEvent is not wired") }
func init() {
	layers.RegisterLayerGenerator("bgp", func() (layers.LayerGenerator,error) { return &BGPGenerator{},nil })
	layers.RegisterLayerValidator("bgp", func(spec *core.FlowSpec) error { return (Planner{}).Validate(*spec) })
}
