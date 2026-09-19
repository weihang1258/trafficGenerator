// Package icmpv6 layer generator (D-ICMPV6-1): wraps the legacy Planner.Plan
// for the [ip, icmpv6] raw-IP terminal chain. Echo pairing, Pattern steps,
// pseudo-header checksum and the IPv6-family enforcement all reuse the legacy
// implementation — zero byte divergence.
package icmpv6

import (
	"context"
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// Generator adapts the legacy Planner to the layers generator interface.
type Generator struct {
	legacy *Planner
}

func (*Generator) Name() string { return "icmpv6" }

// GenEvents returns nil: icmpv6 emits raw packets (raw-IP chain), not
// message events for a transport layer.
func (g *Generator) GenEvents() layers.EventGenerator { return nil }

// Generate relays legacy Plan packets to the chain drive. Every packet is
// forced to Direction "up" (srv6 同款防双换)：legacy 已完成 request/reply 的
// L3 地址换向并置 Direction=down；raw-IP 驱动对 down 包再换一次 L3 即双换错。
// ICMPv6 无业务 MAC（builder 缺省），强制 up 后 l2For 沿 up 侧补缺省 MAC。
func (g *Generator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req == nil || req.Emit == nil || req.Meta.ICMPv6 == nil {
		return fmt.Errorf("icmpv6 generator: invalid request")
	}
	spec := core.FlowSpec{
		SrcIP:  req.Meta.SrcIP,
		DstIP:  req.Meta.DstIP,
		TTL:    req.Meta.TTL,
		SrcMAC: req.Meta.SrcMAC,
		DstMAC: req.Meta.DstMAC,
		ICMPv6: req.Meta.ICMPv6,
	}
	ch, err := g.legacy.Plan(ctx, spec)
	if err != nil {
		return err
	}
	for pkt := range ch {
		pkt.Direction = "up"
		if err := req.Emit(pkt); err != nil {
			return err
		}
	}
	return nil
}

// validateLayer is the chain-path validator (RegisterLayerValidator). It
// reuses the legacy IPv6-family enforcement (icmpv6.go Validate — zero new
// copy) and adds the Echo semantic branches the legacy path never checked.
func validateLayer(s core.FlowSpec) error {
	if s.ICMPv6 == nil {
		return fmt.Errorf("icmpv6 config is required")
	}
	c := s.ICMPv6
	if c.Type != 128 && c.Type != 129 {
		return fmt.Errorf("icmpv6 type must be 128 (Echo Request) or 129 (Echo Reply), got %d", c.Type)
	}
	if c.Code != 0 {
		return fmt.Errorf("icmpv6 code must be 0 for Echo, got %d", c.Code)
	}
	for i, st := range c.Pattern {
		if st.Type != 128 && st.Type != 129 {
			return fmt.Errorf("icmpv6 pattern step %d type must be 128 or 129, got %d", i+1, st.Type)
		}
	}
	var p Planner
	return p.Validate(s)
}

func init() {
	layers.RegisterLayerGenerator("icmpv6", func() (layers.LayerGenerator, error) { return &Generator{legacy: NewPlanner()}, nil })
	layers.RegisterLayerValidator("icmpv6", func(s *core.FlowSpec) error { return validateLayer(*s) })
}
