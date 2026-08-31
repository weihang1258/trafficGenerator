package ams

import (
	"context"
	"fmt"
	"math/rand"
	"sort"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// AMSGenerator 事件模式（openwire 同款）：每帧一个 MessageEvent，TCP 层负责
// 握手/MSS 分段/挥手；连接级 SrcPort 边界触发 TCPGenerator 的会话切换。
// 自驱模式（连接声明显式 src_ip/dst_ip 的双栈/多流用例）：生成器自产完整
// TCP 包（每连接独立握手/数据/挥手），与 openwire 自驱分支同构。
type AMSGenerator struct{}

func (g *AMSGenerator) Name() string                     { return "ams" }
func (g *AMSGenerator) GenEvents() layers.EventGenerator { return g }
func (g *AMSGenerator) EmitEvent(layers.MessageEvent) error {
	return fmt.Errorf("ams generator: EmitEvent is not wired; events flow through GenRequest.EmitMsg only")
}

// Generate dispatches on the wiring: EmitMsg → event mode; Emit → self-drive.
func (g *AMSGenerator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req == nil {
		return fmt.Errorf("ams generator: request is nil")
	}
	cfg := req.Meta.AMS
	if cfg == nil {
		cfg = defaultConfig()
	}
	if err := ValidateConfig(cfg); err != nil {
		return err
	}
	if req.EmitMsg != nil {
		return g.generateEvents(ctx, req.EmitMsg, cfg)
	}
	if req.Emit != nil {
		return g.generatePackets(ctx, req.Emit, cfg, req.Meta)
	}
	return fmt.Errorf("ams generator: neither EmitMsg nor Emit is wired")
}

// defaultConfig is the empty-config default flow (P0b)：最小 HELLO 协商。
func defaultConfig() *core.AMSConfig {
	return &core.AMSConfig{
		Profile: defaultProfile,
		Connections: []core.AMSConnection{{
			SrcPort: 42051,
			Events:  defaultEvents(),
		}},
	}
}

func defaultEvents() []core.AMSEvent {
	return []core.AMSEvent{
		{Kind: "hello"},
		{Kind: "hello_ok"},
	}
}

// effectiveConns returns the connections to generate (空配置默认化)。
func effectiveConns(cfg *core.AMSConfig) []core.AMSConnection {
	if len(cfg.Connections) > 0 {
		return cfg.Connections
	}
	return []core.AMSConnection{{SrcPort: 42051, Events: defaultEvents()}}
}

// eventDirection resolves the event direction (缺省按 kind)。
func eventDirection(e *core.AMSEvent) (string, error) {
	if e.Direction != "" {
		if e.Direction != "c2s" && e.Direction != "s2c" {
			return "", fmt.Errorf("ams: direction %q is invalid (want c2s or s2c)", e.Direction)
		}
		return e.Direction, nil
	}
	_, _, dir, ok := eventDefaults(e)
	if !ok {
		return "", fmt.Errorf("ams: unknown frame type %q", e.Kind)
	}
	return dir, nil
}

// generateEvents emits one MessageEvent per frame in config order: 连接级
// 事件（握手，SessionID=0）先行，然后各 session 依序展开；每个事件携带
// 其连接的客户端源端口（TCPGenerator 会话边界）。
func (g *AMSGenerator) generateEvents(ctx context.Context, emit func(layers.MessageEvent) error, cfg *core.AMSConfig) error {
	for i := range effectiveConns(cfg) {
		conn := &cfg.Connections[i]
		for j := range conn.Events {
			if err := emitEventFrame(ctx, emit, cfg, &conn.Events[j], 0, conn.SrcPort, i, "conn", j); err != nil {
				return err
			}
		}
		for s := range conn.Sessions {
			sess := &conn.Sessions[s]
			for j := range sess.Events {
				if err := emitEventFrame(ctx, emit, cfg, &sess.Events[j], sess.SessionID, conn.SrcPort, i, sessKindName(sess.SessionID), j); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func sessKindName(id uint32) string { return fmt.Sprintf("session-%d", id) }

func emitEventFrame(ctx context.Context, emit func(layers.MessageEvent) error, cfg *core.AMSConfig, e *core.AMSEvent, sessionID uint32, srcPort uint16, connIdx int, scope string, j int) error {
	dir, err := eventDirection(e)
	if err != nil {
		return err
	}
	frame := BuildEventFrame(e, cfg, sessionID)
	if frame == nil {
		return fmt.Errorf("ams: connection %d %s event %d: unknown frame type %q", connIdx, scope, j, e.Kind)
	}
	if err := CheckFrameMax(frame, cfg.FrameMax); err != nil {
		return fmt.Errorf("ams: connection %d %s event %d (%s): %v", connIdx, scope, j, e.Kind, err)
	}
	ev := layers.MessageEvent{
		Up:      dir == "c2s",
		Bytes:   frame,
		SrcPort: srcPort,
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	return emit(ev)
}

// tcpFlowState tracks one self-driven connection's seq state。
type tcpFlowState struct {
	srcIP, dstIP     string
	srcPort, dstPort uint16
	clientSeq        uint32
	serverSeq        uint32
}

// emitSegment assembles one TCP segment packet for the self-drive path。
func emitSegment(emit func(core.PacketConfig) error, st *tcpFlowState, up bool, flags byte, payload []byte, seq, ack uint32) error {
	direction := "down"
	src, dst := st.dstPort, st.srcPort
	if up {
		direction = "up"
		src, dst = st.srcPort, st.dstPort
	}
	return emit(core.PacketConfig{
		Direction: direction,
		L3: core.L3Config{
			SrcIP:    st.srcIP,
			DstIP:    st.dstIP,
			Protocol: 6,
			TTL:      64,
		},
		L4: core.L4Config{
			Protocol:   "tcp",
			SrcPort:    src,
			DstPort:    dst,
			Seq:        seq,
			Ack:        ack,
			Flags:      flags,
			WindowSize: 65535,
		},
		Payload: payload,
	})
}

// generatePackets is the self-drive path（双栈/多流用例）：每连接完整握手 →
// 帧段（PSH|ACK）→ 四次挥手，方向交换在生成器内完成。
func (g *AMSGenerator) generatePackets(ctx context.Context, emit func(core.PacketConfig) error, cfg *core.AMSConfig, meta layers.FlowMeta) error {
	index := uint64(0)
	for i := range effectiveConns(cfg) {
		conn := &cfg.Connections[i]
		st := &tcpFlowState{
			srcIP:   conn.SrcIP,
			dstIP:   conn.DstIP,
			srcPort: conn.SrcPort,
		}
		if st.srcIP == "" {
			st.srcIP = meta.SrcIP
		}
		if st.dstIP == "" {
			st.dstIP = meta.DstIP
		}
		if st.srcPort == 0 {
			st.srcPort = meta.SrcPort
		}
		st.dstPort = defaultDstPort
		if conn.DstPort != 0 {
			st.dstPort = conn.DstPort
		}
		if meta.DstPort != 0 {
			st.dstPort = meta.DstPort
		}
		st.clientSeq = rand.Uint32()
		st.serverSeq = rand.Uint32()

		wrapEmit := func(pkt core.PacketConfig) error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
			if pkt.FlowID == "" {
				pkt.FlowID = meta.FlowID
			}
			pkt.PacketIndex = index
			index++
			return emit(pkt)
		}

		// 握手 SYN / SYN-ACK / ACK。
		if err := emitSegment(wrapEmit, st, true, layers.FlagSYN, nil, st.clientSeq, 0); err != nil {
			return err
		}
		st.clientSeq++
		if err := emitSegment(wrapEmit, st, false, layers.FlagSYN|layers.FlagACK, nil, st.serverSeq, st.clientSeq); err != nil {
			return err
		}
		st.serverSeq++
		if err := emitSegment(wrapEmit, st, true, layers.FlagACK, nil, st.clientSeq, st.serverSeq); err != nil {
			return err
		}

		emitFrame := func(e *core.AMSEvent, sessionID uint32) error {
			dir, err := eventDirection(e)
			if err != nil {
				return err
			}
			frame := BuildEventFrame(e, cfg, sessionID)
			if frame == nil {
				return fmt.Errorf("ams: connection %d event: unknown frame type %q", i, e.Kind)
			}
			if err := CheckFrameMax(frame, cfg.FrameMax); err != nil {
				return fmt.Errorf("ams: connection %d event (%s): %v", i, e.Kind, err)
			}
			up := dir == "c2s"
			if err := emitSegment(wrapEmit, st, up, layers.FlagPSH|layers.FlagACK, frame, st.clientSeq, st.serverSeq); err != nil {
				return err
			}
			if up {
				st.clientSeq += uint32(len(frame))
			} else {
				st.serverSeq += uint32(len(frame))
			}
			return nil
		}
		for j := range conn.Events {
			if err := emitFrame(&conn.Events[j], 0); err != nil {
				return err
			}
		}
		for s := range conn.Sessions {
			sess := &conn.Sessions[s]
			for j := range sess.Events {
				if err := emitFrame(&sess.Events[j], sess.SessionID); err != nil {
					return err
				}
			}
		}

		// 挥手 FIN|ACK(up) → ACK(down) → FIN|ACK(down) → ACK(up)。
		if err := emitSegment(wrapEmit, st, true, layers.FlagFIN|layers.FlagACK, nil, st.clientSeq, st.serverSeq); err != nil {
			return err
		}
		st.clientSeq++
		if err := emitSegment(wrapEmit, st, false, layers.FlagACK, nil, st.serverSeq, st.clientSeq); err != nil {
			return err
		}
		if err := emitSegment(wrapEmit, st, false, layers.FlagFIN|layers.FlagACK, nil, st.serverSeq, st.clientSeq); err != nil {
			return err
		}
		st.serverSeq++
		if err := emitSegment(wrapEmit, st, true, layers.FlagACK, nil, st.clientSeq, st.serverSeq); err != nil {
			return err
		}
	}
	return nil
}

// ---- validator ----

// sessState is the per-session protocol state (设计 §5)。
type sessState struct {
	opened    bool
	closed    bool
	pending   map[uint64]bool // COMMAND correlation → awaiting RESPONSE
	answered  map[uint64]bool
	messages  map[uint64]uint64 // messageID → sequence
	acked     map[uint64]bool
	unacked   map[uint64]bool // ack-required 消息（设计 §6 MUST：必须收到 ACK）
	lastSeq   uint64
	sequenced bool
}

// connState is the per-connection state machine (设计 §5)。
type connState struct {
	negotiated    bool
	authenticated bool
	sessions      map[uint32]*sessState
}

func (c *connState) sess(id uint32) *sessState {
	s := c.sessions[id]
	if s == nil {
		s = &sessState{pending: map[uint64]bool{}, answered: map[uint64]bool{}, messages: map[uint64]uint64{}, acked: map[uint64]bool{}, unacked: map[uint64]bool{}}
		c.sessions[id] = s
	}
	return s
}

// validateEvents walks one ordered event list (connection-level + sessions
// flattened) through the state machine，返回首个协议违规。
func validateEvents(connIdx int, items []validatedEvent) error {
	st := &connState{sessions: map[uint32]*sessState{}}
	for i := range items {
		e := items[i].event
		scope := items[i].scope
		if _, _, _, ok := eventDefaults(e); !ok {
			return fmt.Errorf("ams: connection %d event %d: unknown frame type %q (frame/type)", connIdx, i, e.Kind)
		}
		if e.Kind == "ping" || e.Kind == "pong" {
			// PING/PONG 只能在 session open 后出现（设计 §6）——连接级
			// （SessionID=0）与未 open 的 session 块都拒绝。
			s := st.sess(scope.sessionID)
			if !s.opened {
				return fmt.Errorf("ams: connection %d event %d: %s requires an open session (session)", connIdx, i, e.Kind)
			}
		}
		switch e.Kind {
		case "hello":
			if i != 0 {
				return fmt.Errorf("ams: connection %d handshake error: hello must be the first AMS frame, got event %d (hello/handshake)", connIdx, i)
			}
			if dir, _ := eventDirection(e); dir != "c2s" {
				return fmt.Errorf("ams: connection %d handshake error: hello must be c2s, got %s (handshake)", connIdx, dir)
			}
			st.negotiated = true
		case "hello_ok":
			if !st.negotiated {
				return fmt.Errorf("ams: connection %d handshake error: hello_ok before hello (handshake)", connIdx)
			}
			if dir, _ := eventDirection(e); dir != "s2c" {
				return fmt.Errorf("ams: connection %d handshake error: hello_ok must be s2c, got %s (handshake)", connIdx, dir)
			}
		case "auth":
			if !st.negotiated {
				return fmt.Errorf("ams: connection %d handshake error: auth before hello (hello/handshake)", connIdx)
			}
			if dir, _ := eventDirection(e); dir != "c2s" {
				return fmt.Errorf("ams: connection %d handshake error: auth must be c2s, got %s (handshake/auth)", connIdx, dir)
			}
		case "auth_ok":
			if dir, _ := eventDirection(e); dir != "s2c" {
				return fmt.Errorf("ams: connection %d handshake error: auth_ok must be s2c, got %s (handshake/auth)", connIdx, dir)
			}
			st.authenticated = true
		case "open_session":
			if !st.authenticated {
				return fmt.Errorf("ams: connection %d handshake error: open_session before auth_ok — AUTH_OK must precede OPEN_SESSION (auth/session)", connIdx)
			}
			if items[i].sessionID == 0 {
				return fmt.Errorf("ams: connection %d event %d: open_session requires a nonzero session_id (session)", connIdx, i)
			}
			if items[i].sessionID != scope.sessionID {
				return fmt.Errorf("ams: connection %d event %d: frame session_id %d does not match its session block %d (session)", connIdx, i, items[i].sessionID, scope.sessionID)
			}
			s := st.sess(scope.sessionID)
			if s.opened {
				return fmt.Errorf("ams: connection %d duplicate session %d — session ids are unique within a connection (session)", connIdx, scope.sessionID)
			}
			s.opened = true
		case "close_session":
			s := st.sess(scope.sessionID)
			if !s.opened {
				return fmt.Errorf("ams: connection %d session error: close_session references session %d which is not open (session)", connIdx, scope.sessionID)
			}
			s.closed = true
		case "close_ok":
			s := st.sess(scope.sessionID)
			if !s.closed {
				return fmt.Errorf("ams: connection %d session error: close_ok without a preceding close_session for session %d (session)", connIdx, scope.sessionID)
			}
		case "command", "response", "message", "message_ack":
			s := st.sess(scope.sessionID)
			if !s.opened {
				return fmt.Errorf("ams: connection %d session error: %s references session %d which is not open — open_session must precede session traffic (session/connection)", connIdx, e.Kind, scope.sessionID)
			}
			if s.closed {
				return fmt.Errorf("ams: connection %d state error: %s arrives after close_session — no new commands after close (session)", connIdx, e.Kind)
			}
			if err := validateSessionFrame(connIdx, i, e, s, scope.sessionID); err != nil {
				return err
			}
		case "error":
			// 任一方向显式错误（设计 §3）：不强制状态。
		}
	}
	// 设计 §6 MUST：带 ack-required 的消息必须收到同一 session 的
	// MESSAGE_ACK——事件序列结束时仍有未确认消息即拒绝（按 session id
	// 升序保证错误信息确定）。
	ids := make([]int, 0, len(st.sessions))
	for id := range st.sessions {
		ids = append(ids, int(id))
	}
	sort.Ints(ids)
	for _, id := range ids {
		if len(st.sessions[uint32(id)].unacked) > 0 {
			return fmt.Errorf("ams: connection %d: session %d has ack-required messages without a MESSAGE_ACK (message/ack)", connIdx, id)
		}
	}
	return nil
}

// validateSessionFrame checks command/response correlation and
// message/ack/sequence invariants within one open session (设计 §4)。
func validateSessionFrame(connIdx, i int, e *core.AMSEvent, s *sessState, sessionID uint32) error {
	switch e.Kind {
	case "command":
		if e.CorrelationID == 0 {
			return fmt.Errorf("ams: connection %d event %d: command requires a nonzero correlation_id (correlation)", connIdx, i)
		}
		if s.pending[e.CorrelationID] || s.answered[e.CorrelationID] {
			return fmt.Errorf("ams: connection %d event %d: command correlation_id %d is not unique within session %d (correlation)", connIdx, i, e.CorrelationID, sessionID)
		}
		if e.Command == "" || e.Resource == "" {
			return fmt.Errorf("ams: connection %d event %d: command requires both command and resource fields (command)", connIdx, i)
		}
		s.pending[e.CorrelationID] = true
	case "response":
		if !s.pending[e.CorrelationID] {
			if s.answered[e.CorrelationID] {
				return fmt.Errorf("ams: connection %d event %d: response correlation_id %d already answered — duplicate response (correlation/response)", connIdx, i, e.CorrelationID)
			}
			return fmt.Errorf("ams: connection %d event %d: response correlation_id %d has no pending command in session %d (correlation/response)", connIdx, i, e.CorrelationID, sessionID)
		}
		delete(s.pending, e.CorrelationID)
		s.answered[e.CorrelationID] = true
	case "message":
		if seq, seen := s.messages[e.MessageID]; seen {
			// 显式重传：message_id/sequence 必须与原消息一致（设计 §6）。
			if seq != e.Sequence {
				return fmt.Errorf("ams: connection %d event %d: retransmission of message %d must reuse sequence %d, got %d (message/sequence)", connIdx, i, e.MessageID, seq, e.Sequence)
			}
			return nil
		}
		if s.sequenced && e.Sequence <= s.lastSeq {
			return fmt.Errorf("ams: connection %d event %d: message sequence %d regresses below %d in session %d (sequence)", connIdx, i, e.Sequence, s.lastSeq, sessionID)
		}
		s.messages[e.MessageID] = e.Sequence
		s.lastSeq = e.Sequence
		s.sequenced = true
		if e.DeliveryMode == 1 {
			s.unacked[e.MessageID] = true
		}
	case "message_ack":
		if e.AckFor == 0 {
			return fmt.Errorf("ams: connection %d event %d: message_ack requires ack_for (ack)", connIdx, i)
		}
		if _, sent := s.messages[e.AckFor]; !sent {
			return fmt.Errorf("ams: connection %d event %d: message_ack ack_for %d references an unknown message in session %d (message/ack)", connIdx, i, e.AckFor, sessionID)
		}
		if s.acked[e.AckFor] {
			return fmt.Errorf("ams: connection %d event %d: message %d already acknowledged — duplicate ack (ack)", connIdx, i, e.AckFor)
		}
		s.acked[e.AckFor] = true
		delete(s.unacked, e.AckFor)
	}
	return nil
}

// validatedEvent is one flattened event with its owning session。
type validatedEvent struct {
	event     *core.AMSEvent
	sessionID uint32
	scope     sessScope
}

// sessScope marks which config block an event belongs to（session 块边界
// ——跨块引用即错配）。
type sessScope struct {
	sessionID uint32
}

// ValidateConfig rejects configs that must never reach the wire (设计 §3/§8/§9):
// unknown profiles, wire faults, port violations, and per-connection state
// machine violations. Explicit boundaries (empty payload ping/pong, binary
// TLV, retransmission with identical message_id/sequence) are legal and must
// NOT be rejected.
func ValidateConfig(cfg *core.AMSConfig) error {
	if cfg == nil {
		return nil
	}
	switch cfg.Profile {
	case "", "ams_management_v1", "ams_observer_v1":
	default:
		return fmt.Errorf("ams: unknown profile %q — want ams_management_v1 or ams_observer_v1 (profile)", cfg.Profile)
	}
	if err := validateWireFault(cfg.WireFault); err != nil {
		return err
	}
	for i := range cfg.Connections {
		if err := validateConnection(i, &cfg.Connections[i]); err != nil {
			return err
		}
	}
	return nil
}

// validateConnection flattens one connection's event list（连接级握手 +
// 各 session 块）并走状态机。
func validateConnection(connIdx int, conn *core.AMSConnection) error {
	var items []validatedEvent
	for j := range conn.Events {
		items = append(items, validatedEvent{event: &conn.Events[j], sessionID: 0, scope: sessScope{sessionID: 0}})
	}
	for s := range conn.Sessions {
		sess := &conn.Sessions[s]
		for j := range sess.Events {
			items = append(items, validatedEvent{event: &sess.Events[j], sessionID: sess.SessionID, scope: sessScope{sessionID: sess.SessionID}})
		}
	}
	if len(items) == 0 {
		return fmt.Errorf("ams: connection %d has no events — at least the hello negotiation is required (hello)", connIdx)
	}
	return validateEvents(connIdx, items)
}

// validateWireFault rejects every injected fault with its testcase-contract
// anchor word, and any unknown kind。
func validateWireFault(f string) error {
	if f == "" {
		return nil
	}
	switch f {
	case "bad_version":
		return fmt.Errorf("ams: wire_fault bad_version — version 1 is the only legal frame version; other values are rejected at validation (version/frame)")
	case "unknown_type":
		return fmt.Errorf("ams: wire_fault unknown_type — the frame type must be a known value; unknown types are rejected at validation (frame/type)")
	case "reserved_flags":
		return fmt.Errorf("ams: wire_fault reserved_flags — only request/response/ack-required bits are defined; reserved flag bits are rejected at validation (flags/frame)")
	case "length_overrun":
		return fmt.Errorf("ams: wire_fault length_overrun — the declared length must equal the encoded bytes and stay within frame_max; overruns are rejected at validation (length/frame)")
	case "bad_frame_end":
		return fmt.Errorf("ams: wire_fault bad_frame_end — the frame must end with the 0xae5a marker; other terminators are rejected at validation (frame end/frame)")
	case "tlv_overrun":
		return fmt.Errorf("ams: wire_fault tlv_overrun — every TLV must fit within the payload; truncation or length overflow is rejected at validation (tlv/field/length)")
	default:
		return fmt.Errorf("ams: unknown wire_fault kind %q", f)
	}
}

// ValidateSpec is the layer-level spec validator (registered in init and
// shared with tests)：端口契约 + 配置校验。
func ValidateSpec(spec *core.FlowSpec) error {
	// AMS 只走 TCP/61616：显式写其它目的端口即负例（tcp/port 锚词）；
	// 0 = 未写，由 FieldContract 补 61616。
	if spec.AMS != nil && spec.DstPort != 0 && spec.DstPort != defaultDstPort {
		return fmt.Errorf("ams: destination port %d is not the AMS TCP port %d — non-TCP carriers or wrong ports are rejected", spec.DstPort, defaultDstPort)
	}
	return ValidateConfig(spec.AMS)
}

func init() {
	layers.RegisterLayerGenerator("ams", func() (layers.LayerGenerator, error) {
		return &AMSGenerator{}, nil
	})
	layers.RegisterLayerValidator("ams", ValidateSpec)
}
