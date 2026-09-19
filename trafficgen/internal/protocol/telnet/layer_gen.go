// Package telnet layer generator (D-TELNET-1): wraps the legacy Planner.Plan
// for the [ip, telnet] raw self-drive terminal chain. The legacy planner
// emits fully formed TCP packets (Eth + IPv4/IPv6 + TCP with lifecycle
// options + NVT/IAC dialog payload) — zero byte divergence.
package telnet

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

func (*Generator) Name() string { return "telnet" }

// GenEvents returns nil: telnet is a raw self-drive terminal layer — complete
// packets via Emit (raw-IP drive), not message events. Must stay nil
// (chain_planner.go's event-branch check routes non-nil GenEvents to the
// transport path).
func (g *Generator) GenEvents() layers.EventGenerator { return nil }

// Generate relays legacy Plan packets to the chain drive. Every packet is
// forced to Direction "up"（h323/mpls/ngap 同款防双换）：legacy direction=
// down 已自行交换地址+端口+MAC（telnet.go:227-271 emit 逐 emit 自管方向），
// raw-IP 驱动对 down 包的 L3 换向会双换错。
func (g *Generator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req == nil || req.Emit == nil {
		return fmt.Errorf("telnet generator: invalid request")
	}
	spec := core.FlowSpec{
		SrcIP:   req.Meta.SrcIP,
		DstIP:   req.Meta.DstIP,
		TTL:     req.Meta.TTL,
		SrcMAC:  req.Meta.SrcMAC,
		DstMAC:  req.Meta.DstMAC,
		SrcPort: req.Meta.SrcPort,
		DstPort: req.Meta.DstPort,
		Telnet:  req.Meta.Telnet,
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
// bounds — unreachable on the chain since spec.TCP stays nil, scenario
// whitelist — telnet.go:124-157); the chain path reuses it with zero new
// anchors. nil-config is legal here (telnet.go:185-202 falls back to
// defaultDialog) — translate always fills a non-nil config, so this is a
// C-class backstop mirroring h323/mpls/ngap.
func validateLayer(s core.FlowSpec) error {
	var p Planner
	return p.Validate(s)
}

func init() {
	layers.RegisterLayerGenerator("telnet", func() (layers.LayerGenerator, error) { return &Generator{legacy: NewPlanner()}, nil })
	layers.RegisterLayerValidator("telnet", func(s *core.FlowSpec) error { return validateLayer(*s) })
}
