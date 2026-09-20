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
// D-SIP-2 WP-D dual mode: the raw [ip, sip] chain self-drives complete
// packets (byte-parity line); chains carrying tcp/tls activate the event
// plane (dialog→MessageEvents, tcp layer owns handshake/seq-ack/teardown).
type Generator struct {
	legacy    *Planner
	eventMode bool // chain contains tcp or tls (set by InitChain)
	tlsMode   bool // chain contains tls (Via transport token TLS)
}

// InitChain is the chain-aware dispatch hook (instantiateGens calls it
// synchronously, before assertEventWiring/drive consult GenEvents).
func (g *Generator) InitChain(chain []layers.Layer) {
	for _, l := range chain {
		switch l.Name {
		case "tls":
			g.eventMode, g.tlsMode = true, true
		case "tcp":
			g.eventMode = true
		}
	}
}

func (*Generator) Name() string { return "sip" }

// GenEvents returns the event-plane generator only on tcp/tls chains; nil
// keeps the raw [ip, sip] chain on the self-drive path (the 80-case suite's
// byte-parity line).
func (g *Generator) GenEvents() layers.EventGenerator {
	if g.eventMode {
		return g
	}
	return nil
}

// Generate dispatches on the wiring: EmitMsg non-nil = event plane, else
// legacy self-drive relay.
func (g *Generator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req != nil && req.EmitMsg != nil {
		return g.generateEvents(ctx, req)
	}
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
		// D-SIP-2 WP-A：FlowIndex 贯通——sessions 缺省端口派生
		// base(12345)+flowIdx*M+sessIdx 与动态对象解析都锚流序号，
		// 不传则多流全部按流 0 派生撞端口（ftp layer_gen:54 先例）。
		FlowIndex: req.Meta.FlowIndex,
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
