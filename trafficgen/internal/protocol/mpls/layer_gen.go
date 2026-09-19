// Package mpls layer generator (D-MPLS-1): wraps the legacy Planner.Plan for
// the [ip, mpls] raw self-drive terminal chain. The legacy planner emits fully
// formed packets (Eth + label stack + inner IPv4/IPv6 TCP/UDP) and the builder
// writes the stack with the forced EtherType 0x8847/0x8848 natively — zero
// byte divergence.
package mpls

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

func (*Generator) Name() string { return "mpls" }

// GenEvents returns nil: mpls is a raw self-drive terminal layer — complete
// packets via Emit (raw-IP drive), not message events. Must stay nil
// (chain_planner.go's event-branch check routes non-nil GenEvents to the
// transport path).
func (g *Generator) GenEvents() layers.EventGenerator { return nil }

// Generate relays legacy Plan packets to the chain drive. Every packet is
// forced to Direction "up"（h323/icmpv6 同款防双换）：legacy direction=down
// 已自行交换地址+MAC（planner.go:171-176），raw-IP 驱动对 down 包的 L3
// 换向会双换错。
func (g *Generator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req == nil || req.Emit == nil || req.Meta.MPLS == nil {
		return fmt.Errorf("mpls generator: invalid request")
	}
	spec := core.FlowSpec{
		SrcIP:   req.Meta.SrcIP,
		DstIP:   req.Meta.DstIP,
		TTL:     req.Meta.TTL,
		SrcMAC:  req.Meta.SrcMAC,
		DstMAC:  req.Meta.DstMAC,
		SrcPort: req.Meta.SrcPort,
		DstPort: req.Meta.DstPort,
		MPLS:    req.Meta.MPLS,
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

// validateLayer is the chain-path validator (RegisterLayerValidator). The
// legacy Validate covers every constraint (nil-config, IP parse, empty stack,
// label 20-bit, TC 3-bit, S-bit placement, InnerProto, Frames, Direction —
// planner.go:40-95); the chain path reuses it with zero new anchors. The
// nil-config guard is chain-specific (unreachable post-translate, C-class
// backstop).
func validateLayer(s core.FlowSpec) error {
	if s.MPLS == nil {
		return fmt.Errorf("mpls: MPLS config is required")
	}
	var p Planner
	return p.Validate(s)
}

func init() {
	layers.RegisterLayerGenerator("mpls", func() (layers.LayerGenerator, error) { return &Generator{legacy: NewPlanner()}, nil })
	layers.RegisterLayerValidator("mpls", func(s *core.FlowSpec) error { return validateLayer(*s) })
}
