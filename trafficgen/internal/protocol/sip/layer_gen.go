// Package sip layer generator (D-SIP-1): wraps the legacy Planner.Plan for
// the [ip, sip] raw self-drive terminal chain. The legacy planner emits fully
// formed TCP signaling packets (Eth + IPv4/IPv6 + TCP + RFC 3261 §7 dialog
// payload) and the RTP media sub-flow (UDP frames, separate 4-tuple) — zero
// byte divergence.
package sip

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

func (*Generator) Name() string { return "sip" }

// GenEvents returns nil: sip is a raw self-drive terminal layer — complete
// packets via Emit (raw-IP drive), not message events. Must stay nil
// (chain_planner.go's event-branch check routes non-nil GenEvents to the
// transport path).
func (g *Generator) GenEvents() layers.EventGenerator { return nil }

// Generate relays legacy Plan packets to the chain drive. Every packet is
// forced to Direction "up"（前四协议同款防双换）：TCP down 包与 RTP down
// 帧均由 legacy 自换地址端口 MAC（sip.go:846-856 media 方向面/emit 逐包
// 自管），raw-IP 驱动对 down 包的 L3 换向会双换错。
func (g *Generator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req == nil || req.Emit == nil || req.Meta.SIP == nil {
		return fmt.Errorf("sip generator: invalid request")
	}
	spec := core.FlowSpec{
		SrcIP:   req.Meta.SrcIP,
		DstIP:   req.Meta.DstIP,
		TTL:     req.Meta.TTL,
		SrcMAC:  req.Meta.SrcMAC,
		DstMAC:  req.Meta.DstMAC,
		SrcPort: req.Meta.SrcPort,
		DstPort: req.Meta.DstPort,
		SIP:     req.Meta.SIP,
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
// legacy Validate covers every reachable constraint (IP parse ×2, TCP.MSS
// min — unreachable on the chain since spec.TCP stays nil, sip.go:87-105);
// the chain path reuses it with zero new anchors. nil-config is legal here
// (sip.go:120-123 falls back to an empty dialog → minimal 7-packet
// association) — translate always fills a non-nil config, so this is a
// C-class backstop mirroring the other raw self-drive protocols.
func validateLayer(s core.FlowSpec) error {
	var p Planner
	return p.Validate(s)
}

func init() {
	layers.RegisterLayerGenerator("sip", func() (layers.LayerGenerator, error) { return &Generator{legacy: NewPlanner()}, nil })
	layers.RegisterLayerValidator("sip", func(s *core.FlowSpec) error { return validateLayer(*s) })
}
