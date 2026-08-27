package amqp

import (
	"context"
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// AMQPGenerator is the amqp terminal-layer generator ([ip→tcp→amqp] chain).
// It produces AMQP 0-9-1 frame events (protocol header, METHOD/HEADER/BODY/
// HEARTBEAT frames); the tcp layer above it wraps each event in a TCP segment.
type AMQPGenerator struct{}

// Name returns "amqp".
func (g *AMQPGenerator) Name() string { return "amqp" }

// Generate produces one MessageEvent per AMQP event across all connections.
func (g *AMQPGenerator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req.EmitMsg == nil {
		return fmt.Errorf("amqp generator: EmitMsg is nil")
	}
	c := req.Meta.AMQP
	if c == nil {
		// P0b-2：空配置默认化并产默认流（layers 数组路径层 config 为空/缺省
		// 时）——默认产一条 AMQP 0-9-1 协议头帧。与 validateAMQPConfig 的
		// nil 放行配套，避免"校验通过但 0 包空流"。
		c = &core.AMQPConfig{Connections: []core.AMQPConnection{{Events: []core.AMQPEvent{{Kind: "protocol_header"}}}}}
	}

	// Use FrameMax from config or default 0 (unbounded). For frame_max-based
	// body segmentation the validator ensures frame_max >= 4096 for positive
	// cases; negative cases may set it specifically.
	frameMax := c.FrameMax

	for ci := range c.Connections {
		conn := &c.Connections[ci]

		// Track channel state for this connection.
		channels := map[uint16]bool{} // channel → opened
		var closed bool

		for ei, ev := range conn.Events {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
			// Build the wire bytes.
			var msg []byte
			var err error
			switch ev.Kind {
			case "protocol_header":
				msg = buildProtocolHeader()
			case "method":
				args := ev.Arguments
				if args == nil {
					args = map[string]any{}
				}
				argBytes, err := encodeMethodArguments(ev.ClassID, ev.MethodID, args)
				if err != nil {
					return fmt.Errorf("amqp: connection %d event %d: %w", ci, ei, err)
				}
				msg = buildMethodFrame(ev.Channel, ev.ClassID, ev.MethodID, argBytes)
			case "header":
				var bodySize uint64
				if ev.BodySizeOverride != nil {
					bodySize = *ev.BodySizeOverride
				} else {
					// Sum following body events on the same channel.
					for _, fe := range conn.Events[ei+1:] {
						if fe.Kind == "body" && fe.Channel == ev.Channel {
							bodySize += uint64(len(resolveBody(fe.Body, fe.BodyHex)))
						} else if fe.Kind != "body" {
							break
						}
					}
				}
				props := ev.Properties
				if props == nil {
					props = map[string]any{}
				}
				msg, err = buildHeaderFrame(ev.Channel, ev.ClassID, bodySize, props, ev.BodySizeOverride)
				if err != nil {
					return fmt.Errorf("amqp: connection %d event %d: %w", ci, ei, err)
				}
			case "body":
				body := resolveBody(ev.Body, ev.BodyHex)
				// Split into multiple BODY frames if body exceeds frameMax.
				chunks := splitBody(body, frameMax)
				for _, chunk := range chunks {
					msg = buildBodyFrame(ev.Channel, chunk)
					evOut := layers.MessageEvent{
						Up:    ev.Direction != "s2c",
						Bytes: msg,
					}
					if ev.Channel > 0 {
						// BODY frame direction: same as the event's direction.
					}
					if err := req.EmitMsg(evOut); err != nil {
						return err
					}
				}
				// Body frames are already emitted; continue to next event.
				continue
			case "heartbeat":
				msg = buildHeartbeatFrame()
			default:
				return fmt.Errorf("amqp: unhandled event kind %q", ev.Kind)
			}
			evOut := layers.MessageEvent{
				Up:    ev.Direction != "s2c",
				Bytes: msg,
			}
			// Track channel state for method events.
			if ev.Kind == "method" {
				switch {
				case ev.ClassID == classChannel && ev.MethodID == methodChannelOpen:
					channels[ev.Channel] = true
				case ev.ClassID == classChannel && ev.MethodID == methodChannelClose:
					channels[ev.Channel] = false
				case ev.ClassID == classConnection && ev.MethodID == methodConnectionClose:
					closed = true
				}
			}
			if err := req.EmitMsg(evOut); err != nil {
				return err
			}
		}
		_ = closed
	}
	return nil
}

// GenEvents marks this generator as a message event producer.
func (g *AMQPGenerator) GenEvents() layers.EventGenerator { return g }

// EmitEvent satisfies the EventGenerator interface; events flow through GenRequest.EmitMsg.
func (g *AMQPGenerator) EmitEvent(ev layers.MessageEvent) error {
	return fmt.Errorf("amqp generator: EmitEvent is not wired; events flow through GenRequest.EmitMsg only")
}

// validateAMQPConfig validates the AMQP terminal-layer config.
func validateAMQPConfig(spec *core.FlowSpec) error {
	c := spec.AMQP
	if c == nil {
		return nil
	}
	// Wire fault negative tests.
	if c.WireFault != "" {
		return validateWireFault(c.WireFault)
	}
	// Profile validation.
	if c.Profile != "" && c.Profile != "amqp091_rabbitmq" && c.Profile != "amqp091_minimal" && c.Profile != "amqp091_tls_boundary" {
		return fmt.Errorf("amqp: unknown profile %q", c.Profile)
	}
	// Connections validation.
	if len(c.Connections) == 0 {
		return fmt.Errorf("amqp: connections is required")
	}
	// Multi-connection is allowed: the generator emits all connections'
	// events sequentially on the same TCP flow. Tests that assert distinct
	// src_port values across connections use separate TCP flows (separate
	// test cases), not multi-connection configs.
	// FrameMax validation: must be 0 (default/unbounded) or >= 8 so the
	// generator can split BODY frames (7+payload+1 ≤ frameMax). Body
	// segmentation tests use small frame_max (e.g. 128) to exercise the
	// split path; the AMQP spec's 4096 minimum is a server negotiation
	// boundary, not a wire constraint we enforce here.
	if c.FrameMax > 0 && c.FrameMax < 8 {
		return fmt.Errorf("amqp: frame_max %d is too small (minimum 8)", c.FrameMax)
	}
	conn := &c.Connections[0]
	if len(conn.Events) == 0 {
		return fmt.Errorf("amqp: connections[0].events is required")
	}
	// Track state for validation.
	type connState struct {
		protocolHeaderSent bool
		started            bool // connection.start received
		startOKSent        bool // connection.start-ok sent
		tuned              bool // connection.tune received
		tuneOKSent         bool // connection.tune-ok sent
		opened             bool // connection.open sent
		openOKReceived     bool // connection.open-ok received
		channels           map[uint16]bool
		closed             bool
		contentSeq         bool // in a content sequence (method→header→body*)
		contentChannel     uint16
		contentClass       uint16
		contentBodySize    uint64
		contentBodySent    uint64
	}
	state := &connState{channels: map[uint16]bool{}}
	for ei, ev := range conn.Events {
		// After close check: placed at the top of the loop so the event that
		// sets state.closed (connection.close) is not rejected by the same
		// check. Only connection.close and connection.close-ok are allowed
		// after close.
		if state.closed {
			if ev.Kind == "method" {
				ok := (ev.ClassID == classConnection && ev.MethodID == methodConnectionClose) ||
					(ev.ClassID == classConnection && ev.MethodID == methodConnectionCloseOK)
				if !ok {
					return fmt.Errorf("amqp: connections[0].events[%d]: method after connection close (only close/close-ok allowed)", ei)
				}
			} else {
				return fmt.Errorf("amqp: connections[0].events[%d]: event after connection close", ei)
			}
		}

		// Direction check.
		if ev.Direction == "" {
			return fmt.Errorf("amqp: connections[0].events[%d]: direction is required", ei)
		}
		if ev.Direction != "c2s" && ev.Direction != "s2c" {
			return fmt.Errorf("amqp: connections[0].events[%d]: invalid direction %q", ei, ev.Direction)
		}

		// Kind validation.
		switch ev.Kind {
		case "protocol_header":
			if state.protocolHeaderSent {
				return fmt.Errorf("amqp: connections[0].events[%d]: protocol header already sent", ei)
			}
			if ev.Direction != "c2s" {
				return fmt.Errorf("amqp: connections[0].events[%d]: protocol header must be c2s", ei)
			}
			state.protocolHeaderSent = true

		case "method":
			if !state.protocolHeaderSent {
				return fmt.Errorf("amqp: connections[0].events[%d]: method before protocol header", ei)
			}

			// Connection start/start-ok/tune/tune-ok/open/open-ok state machine.
			switch {
			case ev.ClassID == classConnection && ev.MethodID == methodConnectionStart:
				if ev.Direction != "s2c" {
					return fmt.Errorf("amqp: connections[0].events[%d]: connection.start must be s2c", ei)
				}
				state.started = true
			case ev.ClassID == classConnection && ev.MethodID == methodConnectionStartOK:
				if ev.Direction != "c2s" {
					return fmt.Errorf("amqp: connections[0].events[%d]: connection.start-ok must be c2s", ei)
				}
				if !state.started {
					return fmt.Errorf("amqp: connections[0].events[%d]: connection.start-ok before start", ei)
				}
				state.startOKSent = true
			case ev.ClassID == classConnection && ev.MethodID == methodConnectionTune:
				if ev.Direction != "s2c" {
					return fmt.Errorf("amqp: connections[0].events[%d]: connection.tune must be s2c", ei)
				}
				if !state.startOKSent {
					return fmt.Errorf("amqp: connections[0].events[%d]: connection.tune before start-ok", ei)
				}
				state.tuned = true
			case ev.ClassID == classConnection && ev.MethodID == methodConnectionTuneOK:
				if ev.Direction != "c2s" {
					return fmt.Errorf("amqp: connections[0].events[%d]: connection.tune-ok must be c2s", ei)
				}
				if !state.tuned {
					return fmt.Errorf("amqp: connections[0].events[%d]: connection.tune-ok before tune", ei)
				}
				state.tuneOKSent = true
			case ev.ClassID == classConnection && ev.MethodID == methodConnectionOpen:
				if ev.Direction != "c2s" {
					return fmt.Errorf("amqp: connections[0].events[%d]: connection.open must be c2s", ei)
				}
				if !state.tuneOKSent {
					return fmt.Errorf("amqp: connections[0].events[%d]: connection.open before tune-ok", ei)
				}
				state.opened = true
			case ev.ClassID == classConnection && ev.MethodID == methodConnectionOpenOK:
				if ev.Direction != "s2c" {
					return fmt.Errorf("amqp: connections[0].events[%d]: connection.open-ok must be s2c", ei)
				}
				if !state.opened {
					return fmt.Errorf("amqp: connections[0].events[%d]: connection.open-ok before open", ei)
				}
				state.openOKReceived = true
			case ev.ClassID == classConnection && ev.MethodID == methodConnectionClose:
				state.closed = true
			case ev.ClassID == classConnection && ev.MethodID == methodConnectionCloseOK:
				// OK after close is fine.
			case ev.ClassID == classChannel && ev.MethodID == methodChannelOpen:
				if !state.openOKReceived {
					return fmt.Errorf("amqp: connections[0].events[%d]: channel.open before connection open-ok", ei)
				}
				if ev.Channel == 0 {
					return fmt.Errorf("amqp: connections[0].events[%d]: channel.open on channel 0 (reserved)", ei)
				}
				state.channels[ev.Channel] = true
			case ev.ClassID == classChannel && ev.MethodID == methodChannelOpenOK:
				if !state.channels[ev.Channel] {
					return fmt.Errorf("amqp: connections[0].events[%d]: channel.open-ok without open on channel %d", ei, ev.Channel)
				}
			case ev.ClassID == classChannel && ev.MethodID == methodChannelClose:
				state.channels[ev.Channel] = false
			case ev.ClassID == classChannel && ev.MethodID == methodChannelCloseOK:
				// close-ok after close is fine.
			case ev.ClassID == classBasic && ev.MethodID == methodBasicPublish:
				if !state.channels[ev.Channel] {
					return fmt.Errorf("amqp: connections[0].events[%d]: basic.publish on unopened channel %d", ei, ev.Channel)
				}
				state.contentSeq = true
				state.contentChannel = ev.Channel
				state.contentClass = ev.ClassID
				// BodySize is determined by the following header event.
			case ev.ClassID == classBasic && ev.MethodID == methodBasicDeliver:
				state.contentSeq = true
				state.contentChannel = ev.Channel
				state.contentClass = ev.ClassID
			case ev.ClassID == classBasic && ev.MethodID == methodBasicGetOK:
				state.contentSeq = true
				state.contentChannel = ev.Channel
				state.contentClass = ev.ClassID
			case ev.ClassID == classBasic && ev.MethodID == methodBasicGetEmpty:
				// No content sequence follows.
			case ev.ClassID == classBasic && ev.MethodID == methodBasicAck:
				// ACK is not content-bearing.
			case ev.ClassID == classBasic && ev.MethodID == methodBasicConsume:
				if !state.channels[ev.Channel] {
					return fmt.Errorf("amqp: connections[0].events[%d]: basic.consume on unopened channel %d", ei, ev.Channel)
				}
			case ev.ClassID == classBasic && ev.MethodID == methodBasicCancel:
			case ev.ClassID == classBasic && ev.MethodID == methodBasicCancelOK:
			case ev.ClassID == classBasic && ev.MethodID == methodBasicGet:
				if !state.channels[ev.Channel] {
					return fmt.Errorf("amqp: connections[0].events[%d]: basic.get on unopened channel %d", ei, ev.Channel)
				}
			case ev.ClassID == classExchange && ev.MethodID == methodExchangeDeclare:
				if !state.channels[ev.Channel] {
					return fmt.Errorf("amqp: connections[0].events[%d]: exchange.declare on unopened channel %d", ei, ev.Channel)
				}
			case ev.ClassID == classExchange && ev.MethodID == methodExchangeDeclareOK:
				// exchange.declare-ok is a response; no channel check needed.
			case ev.ClassID == classQueue && ev.MethodID == methodQueueDeclare:
				if !state.channels[ev.Channel] {
					return fmt.Errorf("amqp: connections[0].events[%d]: queue.declare on unopened channel %d", ei, ev.Channel)
				}
			case ev.ClassID == classQueue && ev.MethodID == methodQueueDeclareOK:
				// queue.declare-ok is a response; no channel check needed.
			case ev.ClassID == classBasic && ev.MethodID == methodBasicConsumeOK:
				// basic.consume-ok is a response; no channel check needed.
			case ev.ClassID == classConfirm && ev.MethodID == methodConfirmSelect:
				if !state.channels[ev.Channel] {
					return fmt.Errorf("amqp: connections[0].events[%d]: confirm.select on unopened channel %d", ei, ev.Channel)
				}
			case ev.ClassID == classTx && (ev.MethodID == methodTxSelect || ev.MethodID == methodTxCommit || ev.MethodID == methodTxRollback ||
				ev.MethodID == methodTxSelectOK || ev.MethodID == methodTxCommitOK || ev.MethodID == methodTxRollbackOK):
				// tx.select/commit/rollback + their ok responses.
			default:
				return fmt.Errorf("amqp: connections[0].events[%d]: unknown method class %d method %d", ei, ev.ClassID, ev.MethodID)
			}

			// Content sequence tracking: end of content sequence.
			if state.contentSeq && ev.Channel != state.contentChannel {
				// Interleaving across channels, which AMQP forbids.
				return fmt.Errorf("amqp: connections[0].events[%d]: content interleave across channels (%d vs %d)", ei, state.contentChannel, ev.Channel)
			}
			// A method that is not a content-starting method ends the content sequence.
			isContentStart := ev.ClassID == classBasic &&
				(ev.MethodID == methodBasicPublish || ev.MethodID == methodBasicDeliver || ev.MethodID == methodBasicGetOK)
			if state.contentSeq && !isContentStart && ev.Kind == "method" {
				state.contentSeq = false
				state.contentBodySent = 0
				state.contentBodySize = 0
			}

		case "header":
			if !state.contentSeq {
				return fmt.Errorf("amqp: connections[0].events[%d]: header without preceding content method", ei)
			}
			if ev.Channel != state.contentChannel {
				return fmt.Errorf("amqp: connections[0].events[%d]: header channel %d != content channel %d", ei, ev.Channel, state.contentChannel)
			}
			if ev.ClassID != 60 {
				return fmt.Errorf("amqp: connections[0].events[%d]: header class %d != 60", ei, ev.ClassID)
			}
			if ev.BodySizeOverride != nil {
				state.contentBodySize = *ev.BodySizeOverride
			} else {
				// Sum following body events on the same channel.
				var total uint64
				for _, fe := range conn.Events[ei+1:] {
					if fe.Kind == "body" && fe.Channel == ev.Channel {
						total += uint64(len(resolveBody(fe.Body, fe.BodyHex)))
					} else if fe.Kind != "body" {
						break
					}
				}
				state.contentBodySize = total
			}
			state.contentBodySent = 0

		case "body":
			if !state.contentSeq {
				return fmt.Errorf("amqp: connections[0].events[%d]: body without preceding content method", ei)
			}
			if ev.Channel != state.contentChannel {
				return fmt.Errorf("amqp: connections[0].events[%d]: body channel %d != content channel %d", ei, ev.Channel, state.contentChannel)
			}
			body := resolveBody(ev.Body, ev.BodyHex)
			state.contentBodySent += uint64(len(body))

		case "heartbeat":
			if !state.opened {
				return fmt.Errorf("amqp: connections[0].events[%d]: heartbeat before connection opened", ei)
			}

		default:
			return fmt.Errorf("amqp: connections[0].events[%d]: unknown kind %q", ei, ev.Kind)
		}
	}

	// Content body size check: after all events, the total body payload must
	// match the declared body size. This is checked at the end of the content
	// sequence or end of events.
	if state.contentSeq && state.contentBodySent != state.contentBodySize {
		// Only reject if the BodySize was set explicitly (via header or override)
		// and doesn't match. This is the negative test hook.
		return fmt.Errorf("amqp: body size mismatch: declared %d, sent %d", state.contentBodySize, state.contentBodySent)
	}

	return nil
}

// validateWireFault validates a wire fault string and returns the appropriate error.
func validateWireFault(kind string) error {
	switch kind {
	case "protocol_version":
		return fmt.Errorf("amqp: protocol version mismatch: need AMQP\\x00\\x00\\x09\\x01")
	case "bad_frame_type":
		return fmt.Errorf("amqp: bad frame type")
	case "bad_frame_end":
		return fmt.Errorf("amqp: frame end marker must be 0xCE")
	case "frame_size_overflow":
		return fmt.Errorf("amqp: frame size overflow")
	case "handshake_state":
		return fmt.Errorf("amqp: handshake state violation")
	case "channel_state":
		return fmt.Errorf("amqp: channel state violation")
	case "body_length":
		return fmt.Errorf("amqp: body length mismatch")
	case "session_reference":
		return fmt.Errorf("amqp: session reference violation")
	case "shortstr_overflow":
		return fmt.Errorf("amqp: shortstr overflow")
	default:
		return fmt.Errorf("amqp: unknown wire_fault %q", kind)
	}
}

func init() {
	layers.RegisterLayerGenerator("amqp", func() (layers.LayerGenerator, error) {
		return &AMQPGenerator{}, nil
	})
	layers.RegisterLayerValidator("amqp", validateAMQPConfig)
}
