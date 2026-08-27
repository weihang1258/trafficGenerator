package rtmfp

import (
	"context"
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// RTMFPGenerator is the rtmfp terminal-layer generator ([ip→udp→rtmfp] chain).
// It produces RTMFP message events (handshake, data, ack, ping/pong, close);
// the udp layer above it wraps each event in a UDP datagram.
type RTMFPGenerator struct{}

// Name returns "rtmfp".
func (g *RTMFPGenerator) Name() string { return "rtmfp" }

// Generate produces one MessageEvent per RTMFP event across all sessions.
func (g *RTMFPGenerator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req.EmitMsg == nil {
		return fmt.Errorf("rtmfp generator: EmitMsg is nil")
	}
	hcfg := req.Meta.RTMFP
	if hcfg == nil {
		return fmt.Errorf("rtmfp generator: RTMFP config is nil")
	}

	for _, sess := range hcfg.Sessions {
		sessionID := sess.SessionID
		// Track flow sequences per (sessionID, flowID) for sequence regression check.
		flowSeqs := map[[2]uint32]uint32{} // (sessionID, flowID) → last sequence

		for _, ev := range sess.Events {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}

			// Resolve retransmit events: same as reliable with the same flow/sequence.
			// retransmit 是既有 sequence 的重发，不参与新消息的 sequence 递进，
			// 也不触发 sequence 回归检查（否则"丢包后重传"会被误判为回退）。
			origKind := ev.Kind
			kind := ev.Kind
			if kind == "retransmit" {
				kind = "reliable"
			}

			// Resolve effective session ID.
			effSessID := sessionID
			if ev.SessionID != nil {
				effSessID = *ev.SessionID
			}

			flowID := ev.FlowID

			// Track sequence per flow (for validator this is done separately,
			// but we also guard here against sequence regression). retransmit
			// 跳过：它是旧 sequence 的重发，既不检查回退也不推进 last。
			if origKind != "retransmit" && (kind == "reliable" || kind == "fragment") {
				key := [2]uint32{effSessID, flowID}
				if last, ok := flowSeqs[key]; ok && ev.Sequence < last {
					return fmt.Errorf("rtmfp: sequence regression on session %d flow %d: %d < %d", effSessID, flowID, ev.Sequence, last)
				}
				flowSeqs[key] = ev.Sequence
			}

			// Build the message bytes.
			body := resolveBody(ev.Message, ev.MessageB64)
			var msg []byte
			switch kind {
			case "hello":
				msg = buildHello(effSessID)
			case "hello_ack":
				msg = buildHelloAck(effSessID)
			case "cookie":
				msg = buildCookie(effSessID, ev.Cookie)
			case "session_confirm":
				msg = buildSessionConfirm(effSessID)
			case "reliable", "retransmit":
				msg = buildReliable(effSessID, flowID, ev.Sequence, body)
			case "unreliable":
				msg = buildUnreliable(effSessID, flowID, body)
			case "fragment":
				if ev.Fragment == nil {
					return fmt.Errorf("rtmfp: fragment event missing fragment config")
				}
				msg = buildFragment(effSessID, flowID, ev.Sequence,
					ev.Fragment.Index, ev.Fragment.Count, ev.Fragment.TotalLength,
					[]byte(ev.Fragment.Payload))
			case "ack":
				msg = buildAck(effSessID, flowID, ev.Sequence, ev.Ranges)
			case "ping":
				msg = buildPing(effSessID)
			case "pong":
				msg = buildPong(effSessID)
			case "close":
				msg = buildClose(effSessID)
			case "error":
				msg = buildError(effSessID, body)
			default:
				return fmt.Errorf("rtmfp: unhandled event kind %q", kind)
			}

			evOut := layers.MessageEvent{
				Up:    ev.Direction != "s2c",
				Bytes: msg,
			}
			// 覆盖源端口并参与 up/down 交换（udp 层 rip 波 5c 语义）：c2s 事件
			// 用会话源端口作 src、dst=1935；s2c 事件交换后 src=1935、dst=会话
			// 端口（应答发回会话 4-tuple）。不设 L4PortOverride——那是 dhcp
			// 端口方向无关语义（down 保持原值），RTMFP 需要交换。
			if sess.SrcPort > 0 {
				evOut.SrcPort = sess.SrcPort
			}
			if err := req.EmitMsg(evOut); err != nil {
				return err
			}
		}
	}
	return nil
}

// GenEvents marks this generator as a message event producer.
func (g *RTMFPGenerator) GenEvents() layers.EventGenerator { return g }

// EmitEvent satisfies the EventGenerator interface; events flow through GenRequest.EmitMsg.
func (g *RTMFPGenerator) EmitEvent(ev layers.MessageEvent) error {
	return fmt.Errorf("rtmfp generator: EmitEvent is not wired; events flow through GenRequest.EmitMsg only")
}

// validateRTMFPConfig validates the RTMFP terminal-layer config.
func validateRTMFPConfig(spec *core.FlowSpec) error {
	if spec.RTMFP == nil {
		return nil
	}
	h := spec.RTMFP

	// Wire fault negative tests.
	if h.WireFault != nil {
		return validateWireFault(h.WireFault)
	}

	if len(h.Sessions) == 0 {
		return fmt.Errorf("rtmfp: sessions is required")
	}

	// Validate profile.
	if h.Profile != "" && h.Profile != "rtmfp_baseline" && h.Profile != "rtmfp_low_latency" {
		return fmt.Errorf("rtmfp: unknown profile %q (must be rtmfp_baseline or rtmfp_low_latency)", h.Profile)
	}

	// Validate role.
	if h.Role != "" && h.Role != "initiator" && h.Role != "responder" {
		return fmt.Errorf("rtmfp: unknown role %q (must be initiator or responder)", h.Role)
	}

	// Track session state for validation.
	type sessionState struct {
		closed    bool
		handshake bool // hello sent/received
		flowSeqs  map[[2]uint32]uint32
	}
	sessions := map[uint32]*sessionState{}

	for si := range h.Sessions {
		sess := &h.Sessions[si]
		sid := sess.SessionID
		state, ok := sessions[sid]
		if !ok {
			state = &sessionState{flowSeqs: map[[2]uint32]uint32{}}
			sessions[sid] = state
		}

		for ei := range sess.Events {
			ev := &sess.Events[ei]
			if ev.Kind == "" {
				return fmt.Errorf("rtmfp: sessions[%d].events[%d]: kind is required", si, ei)
			}
			if ev.Direction == "" {
				return fmt.Errorf("rtmfp: sessions[%d].events[%d]: direction is required", si, ei)
			}
			if ev.Direction != "c2s" && ev.Direction != "s2c" {
				return fmt.Errorf("rtmfp: sessions[%d].events[%d]: invalid direction %q", si, ei, ev.Direction)
			}

			// Validate kind.
			origKind := ev.Kind
			kind := ev.Kind
			if kind == "retransmit" {
				kind = "reliable"
			}
			validKinds := map[string]bool{
				"hello": true, "hello_ack": true, "cookie": true, "session_confirm": true,
				"reliable": true, "unreliable": true, "fragment": true, "ack": true,
				"ping": true, "pong": true, "close": true, "error": true,
			}
			if !validKinds[kind] {
				return fmt.Errorf("rtmfp: sessions[%d].events[%d]: unknown kind %q", si, ei, ev.Kind)
			}

			// State order checks.
			if state.closed && kind != "close" && kind != "error" {
				return fmt.Errorf("rtmfp: sessions[%d].events[%d]: state order violation: event after close (kind=%s)", si, ei, ev.Kind)
			}
			if kind == "close" || kind == "error" {
				state.closed = true
			}
			if kind == "hello" || kind == "hello_ack" {
				state.handshake = true
			}
			if !state.handshake {
				switch kind {
				case "reliable", "unreliable", "fragment", "ack", "ping", "pong", "close":
					return fmt.Errorf("rtmfp: sessions[%d].events[%d]: state order violation: %s before handshake", si, ei, ev.Kind)
				}
			}

			// Sequence regression check (skip retransmit: old sequence replayed).
			if origKind != "retransmit" && (kind == "reliable" || kind == "fragment") {
				key := [2]uint32{sid, ev.FlowID}
				if last, ok := state.flowSeqs[key]; ok && ev.Sequence < last {
					return fmt.Errorf("rtmfp: sessions[%d].events[%d]: sequence regression on session %d flow %d: %d < %d", si, ei, sid, ev.FlowID, ev.Sequence, last)
				}
				state.flowSeqs[key] = ev.Sequence
			}

			// Cross-flow ACK check.
			if kind == "ack" {
				for _, r := range ev.Ranges {
					// Check if the acked sequence exists in ANY flow for this session.
					found := false
					for k := range state.flowSeqs {
						if k[0] == sid {
							// We only know the last sequence per flow; check if the ack range
							// covers any flow's sequences.
							if r[0] <= state.flowSeqs[k] || r[1] <= state.flowSeqs[k] {
								found = true
								break
							}
						}
					}
					if !found {
						return fmt.Errorf("rtmfp: sessions[%d].events[%d]: ack for unknown sequence (flow %d range [%d,%d])", si, ei, ev.FlowID, r[0], r[1])
					}
				}
			}

			// Fragment validation.
			if kind == "fragment" {
				if ev.Fragment == nil {
					return fmt.Errorf("rtmfp: sessions[%d].events[%d]: fragment event missing fragment config", si, ei)
				}
				f := ev.Fragment
				if f.Index >= f.Count {
					return fmt.Errorf("rtmfp: sessions[%d].events[%d]: fragment index %d >= count %d", si, ei, f.Index, f.Count)
				}
			}
		}
	}

	// Cross-session reference check: events referencing another session's session_id.
	for si := range h.Sessions {
		sess := &h.Sessions[si]
		for ei := range sess.Events {
			ev := &sess.Events[ei]
			if ev.SessionID != nil && *ev.SessionID != sess.SessionID {
				// Check target session exists.
				if _, ok := sessions[*ev.SessionID]; !ok {
					return fmt.Errorf("rtmfp: sessions[%d].events[%d]: session leak: references non-existent session %d", si, ei, *ev.SessionID)
				}
			}
		}
	}

	return nil
}

// validateWireFault validates a wire fault config and returns the appropriate error.
func validateWireFault(f *core.RTMFPFault) error {
	if f.Kind == "" {
		return fmt.Errorf("rtmfp: wire_fault kind is required")
	}
	switch f.Kind {
	case "short_header":
		return fmt.Errorf("rtmfp: header too short (%d bytes)", f.Declared)
	case "bad_length":
		return fmt.Errorf("rtmfp: message length overruns payload (%d)", f.Declared)
	case "session_mismatch":
		return fmt.Errorf("rtmfp: session mismatch: cookie/session ID mismatch")
	case "sequence_regress":
		return fmt.Errorf("rtmfp: sequence regression: reliable sequence decreased")
	case "fragment_gap":
		return fmt.Errorf("rtmfp: fragment gap: missing fragment index")
	case "ack_unknown":
		return fmt.Errorf("rtmfp: ack for unknown sequence")
	case "state_order":
		return fmt.Errorf("rtmfp: state order violation: out-of-order handshake/data/close")
	case "session_leak":
		return fmt.Errorf("rtmfp: session leak: cross-session state reference")
	default:
		return fmt.Errorf("rtmfp: unknown wire_fault kind %q", f.Kind)
	}
}

func init() {
	layers.RegisterLayerGenerator("rtmfp", func() (layers.LayerGenerator, error) {
		return &RTMFPGenerator{}, nil
	})
	layers.RegisterLayerValidator("rtmfp", validateRTMFPConfig)
}
