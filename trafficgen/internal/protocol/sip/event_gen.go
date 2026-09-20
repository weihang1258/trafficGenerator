package sip

// D-SIP-2 WP-D event plane: dialog→MessageEvents for [ip,tcp,(tls),sip]
// chains (SIPS over TLS — RFC 3261 §26.2.1 requires the Via transport
// token TLS; §26.2.4 + RFC 5630 §2.6 scope TLS to signaling, so RTP
// media and multi-connection sessions have no event-plane equivalent
// and are rejected with anchors, mqtt discipline). Header completion,
// Via derivation and WP-C rport/received all reuse the same functions
// the self-drive path runs — the event plane is a second emitter of
// identical message bytes, never a second implementation.

import (
	"context"
	"fmt"
	"strings"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// generateEvents translates the dialog into transport-agnostic message
// events: each SIP message becomes one MessageEvent (Up by request/
// response; Bytes = renderSIPMessage output after the same
// completeDialogHeaders + rport/received pass the self-drive path runs).
// TCP handshake/teardown/MSS segmentation belong to the tcp layer
// generator (mqtt precedent); the tls transformer wraps events on
// [ip,tcp,tls,sip] chains.
func (g *Generator) generateEvents(ctx context.Context, req *layers.GenRequest) error {
	cfg := req.Meta.SIP
	if cfg == nil {
		return fmt.Errorf("sip generator: no config (spec.sip required)")
	}
	// Event-plane shape rejections (mqtt double-discipline: schema is the
	// create-time gate, this is the runtime backstop). One chain = one
	// connection, and RTP is a bare UDP stream — neither maps into the
	// transport's single message stream.
	if len(cfg.Sessions) > 0 {
		return fmt.Errorf("sip generator: sessions are not supported on a tcp/tls sip chain (one connection per chain; use the self-drive [ip, sip] chain for sessions)")
	}
	if cfg.Media != nil || len(cfg.Medias) > 0 {
		return fmt.Errorf("sip generator: media is not supported on a tcp/tls sip chain (RTP is a bare UDP stream outside the transport; use the self-drive [ip, sip] chain for media)")
	}
	// RFC 3261 §26.2.2: a sips: Request-URI demands TLS end-to-end —
	// reject before emitting rather than synthesizing a mislabeled flow.
	// Dialog-mode only scans dialog[].uri (sessions are already rejected).
	for _, m := range cfg.Dialog {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(m.URI)), "sips:") && !g.tlsMode {
			return fmt.Errorf("sip generator: sip: sips uri requires a tls layer in the chain")
		}
	}

	var dc dialogCtx
	dc.viaTransport = "TCP"
	if g.tlsMode {
		dc.viaTransport = "TLS"
	}
	natRPort := cfg.NAT != nil && cfg.NAT.RPort
	spec := core.FlowSpec{
		SrcIP: req.Meta.SrcIP, DstIP: req.Meta.DstIP,
		SrcPort: req.Meta.SrcPort, DstPort: req.Meta.DstPort,
	}
	srcPort := req.Meta.SrcPort

	for idx := range cfg.Dialog {
		msg := cfg.Dialog[idx]
		completeDialogHeaders(&msg, &dc, spec)
		direction := msg.Direction
		if direction == "" {
			direction = inferDirection(msg)
		}
		if direction != "up" && direction != "down" {
			continue
		}
		if direction == "up" && len(msg.Headers) > 0 {
			for hi, h := range msg.Headers {
				if strings.HasPrefix(strings.ToLower(h), "via:") {
					msg.Headers[hi] = rewriteViaRPort(h, sipHostOf(spec.SrcIP), srcPort, natRPort)
				}
			}
		}
		payload := renderSIPMessage(msg)
		if len(payload) == 0 {
			continue
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if err := req.EmitMsg(layers.MessageEvent{Up: direction == "up", Bytes: payload}); err != nil {
			return err
		}
	}
	return nil
}

// EmitEvent is the EventGenerator interface method, present only to satisfy
// it (mqtt/dns precedent): events flow through GenRequest.EmitMsg, the
// synchronous callback the ChainPlanner wires to the transport/transformer
// chain — EmitEvent is never wired.
func (g *Generator) EmitEvent(ev layers.MessageEvent) error {
	return fmt.Errorf("sip generator: EmitEvent is not wired; events flow through GenRequest.EmitMsg only")
}
