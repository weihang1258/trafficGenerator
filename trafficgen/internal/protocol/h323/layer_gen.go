// Package h323 layer generator (D-H323-1): wraps the legacy Planner.Plan for
// the [ip, h323] raw self-drive terminal chain. The legacy planner emits fully
// formed packets (L2+L3+L4) across its three planes — Q.931/TPKT over TCP,
// H.245 tunneled in FACILITY, RAS over UDP, RTP media — reproducing the
// reference pcap byte-for-byte. The chain drive only fills L2 defaults and
// relays; zero byte divergence.
package h323

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

func (*Generator) Name() string { return "h323" }

// GenEvents returns nil: h323 is a raw self-drive terminal layer — it emits
// complete packets through Emit (raw-IP drive), not message events for a
// transport layer. Must stay nil: chain_planner.go's event-branch check
// routes generators with non-nil GenEvents to the transport path.
func (g *Generator) GenEvents() layers.EventGenerator { return nil }

// Generate relays legacy Plan packets to the chain drive. Every packet is
// forced to Direction "up"（icmpv6 同款防双换）：legacy 逐包自管方向——
// emitQ931/emitRTP/emitRAS 已按方向给出正确 src/dst IP+MAC+端口，raw-IP
// 驱动对 down 包的 L3 换向会把它们错换成镜像地址。
func (g *Generator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req == nil || req.Emit == nil || req.Meta.H323 == nil {
		return fmt.Errorf("h323 generator: invalid request")
	}
	spec := core.FlowSpec{
		SrcIP:   req.Meta.SrcIP,
		DstIP:   req.Meta.DstIP,
		TTL:     req.Meta.TTL,
		SrcMAC:  req.Meta.SrcMAC,
		DstMAC:  req.Meta.DstMAC,
		SrcPort: req.Meta.SrcPort,
		DstPort: req.Meta.DstPort,
		H323:    req.Meta.H323,
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
// legacy Validate already covers every constraint (IP parse, role, scenario,
// calls, display_name, MSS — h323.go:102-157), so the chain path reuses it
// with zero new anchors; only the nil-config guard is chain-specific
// (unreachable post-translate, C-class backstop).
func validateLayer(s core.FlowSpec) error {
	if s.H323 == nil {
		return fmt.Errorf("h323: H323Config is required")
	}
	var p Planner
	return p.Validate(s)
}

func init() {
	layers.RegisterLayerGenerator("h323", func() (layers.LayerGenerator, error) { return &Generator{legacy: NewPlanner()}, nil })
	layers.RegisterLayerValidator("h323", func(s *core.FlowSpec) error { return validateLayer(*s) })
}
