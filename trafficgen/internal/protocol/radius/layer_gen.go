// Package radius layer generator (D-RADIUS-1): wraps the legacy Planner.Plan
// for the [ip, radius] raw self-drive terminal chain. The legacy planner
// emits fully formed UDP packets (Eth + IPv4/IPv6 + UDP + RADIUS message) —
// zero byte divergence.
package radius

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

func (*Generator) Name() string { return "radius" }

// GenEvents returns nil: radius is a raw self-drive terminal layer — complete
// packets via Emit (raw-IP drive), not message events. Must stay nil
// (chain_planner.go's event-branch check routes non-nil GenEvents to the
// transport path).
func (g *Generator) GenEvents() layers.EventGenerator { return nil }

// Generate relays legacy Plan packets to the chain drive. Every packet is
// forced to Direction "up"（前七协议同款防双换）：响应帧 down 已自行交换
// 地址+端口+MAC（radius.go:347-368），raw-IP 驱动对 down 包的 L3 换向会
// 双换错。
func (g *Generator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req == nil || req.Emit == nil || req.Meta.Radius == nil {
		return fmt.Errorf("radius generator: invalid request")
	}
	spec := core.FlowSpec{
		SrcIP:   req.Meta.SrcIP,
		DstIP:   req.Meta.DstIP,
		TTL:     req.Meta.TTL,
		SrcMAC:  req.Meta.SrcMAC,
		DstMAC:  req.Meta.DstMAC,
		SrcPort: req.Meta.SrcPort,
		DstPort: req.Meta.DstPort,
		Radius:  req.Meta.Radius,
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
// legacy Validate covers every reachable constraint (code whitelists ×2,
// no-auto response, authenticator hex/16B, attribute bounds & formats —
// radius.go:95-153, 13 anchors); the chain path reuses it with zero new
// anchors. nil-config is rejected by legacy ("radius config is required")
// but unreachable post-translate — translate always fills a non-nil config.
// IP parse anchors are likewise unreachable (schema network checks run
// first). Kept as the C-class backstop mirroring the other raw self-drive
// protocols.
func validateLayer(s core.FlowSpec) error {
	var p Planner
	return p.Validate(s)
}

func init() {
	layers.RegisterLayerGenerator("radius", func() (layers.LayerGenerator, error) { return &Generator{legacy: NewPlanner()}, nil })
	layers.RegisterLayerValidator("radius", func(s *core.FlowSpec) error { return validateLayer(*s) })
}
