// Package ngap layer generator (D-NGAP-1): wraps the legacy Planner.Plan for
// the [ip, ngap] raw self-drive terminal chain. The legacy planner emits
// fully formed SCTP packets (Eth + IPv4 + SCTP with chunk byte sequences in
// Payload) — zero byte divergence.
package ngap

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

func (*Generator) Name() string { return "ngap" }

// GenEvents returns nil: ngap is a raw self-drive terminal layer — complete
// packets via Emit (raw-IP drive), not message events. Must stay nil
// (chain_planner.go's event-branch check routes non-nil GenEvents to the
// transport path).
func (g *Generator) GenEvents() layers.EventGenerator { return nil }

// Generate relays legacy Plan packets to the chain drive. Every packet is
// forced to Direction "up"（h323/mpls 同款防双换）：legacy direction=down
// 已自行交换地址+端口+MAC（ngap.go:282-309 emitSCTP 逐 emit 自管方向），
// raw-IP 驱动对 down 包的 L3 换向会双换错。
func (g *Generator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req == nil || req.Emit == nil || req.Meta.NGAP == nil {
		return fmt.Errorf("ngap generator: invalid request")
	}
	spec := core.FlowSpec{
		SrcIP:   req.Meta.SrcIP,
		DstIP:   req.Meta.DstIP,
		TTL:     req.Meta.TTL,
		SrcMAC:  req.Meta.SrcMAC,
		DstMAC:  req.Meta.DstMAC,
		SrcPort: req.Meta.SrcPort,
		DstPort: req.Meta.DstPort,
		NGAP:    req.Meta.NGAP,
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
// legacy Validate covers every constraint (IP parse, v4-only, port range,
// MCC/MNC, PDUSessionID/SST, DRX, NAS length — ngap.go:135-212, 16 anchors);
// the chain path reuses it with zero new anchors. nil-config is legal here
// (ngap.go:166-168 "minimal: SCTP handshake only" returns nil) — translate
// always fills a non-nil config, so this branch is unreachable post-translate
// but kept as a C-class backstop mirroring h323/mpls.
func validateLayer(s core.FlowSpec) error {
	var p Planner
	return p.Validate(s)
}

func init() {
	layers.RegisterLayerGenerator("ngap", func() (layers.LayerGenerator, error) { return &Generator{legacy: NewPlanner()}, nil })
	layers.RegisterLayerValidator("ngap", func(s *core.FlowSpec) error { return validateLayer(*s) })
}
