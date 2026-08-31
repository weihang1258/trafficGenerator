package swarm

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/rand"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// SwarmGenerator 双平面事件模式：discovery（[ip,udp,swarm]）每事件一个
// datagram；storage（[ip,tcp,swarm]）每帧一个 MessageEvent，TCP 层负责
// 握手/MSS 分段/挥手。连接级显式 src_ip/dst_ip 时走自驱完整包分支（双栈
// 用例，openwire/ams 同构）。
type SwarmGenerator struct{}

func (g *SwarmGenerator) Name() string                     { return "swarm" }
func (g *SwarmGenerator) GenEvents() layers.EventGenerator { return g }
func (g *SwarmGenerator) EmitEvent(layers.MessageEvent) error {
	return fmt.Errorf("swarm generator: EmitEvent is not wired; events flow through GenRequest.EmitMsg only")
}

// Generate dispatches on the wiring: EmitMsg → event mode; Emit → self-drive.
func (g *SwarmGenerator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req == nil {
		return fmt.Errorf("swarm generator: request is nil")
	}
	cfg := req.Meta.Swarm
	if cfg == nil {
		cfg = defaultConfig()
	}
	if err := ValidateConfig(cfg); err != nil {
		return err
	}
	// 平面与载体一致性：discovery 配置必须走 udp 链，storage 必须走 tcp 链
	//（设计 §1——两承载互不混装；错配在此同步拒绝而非产出错误字节）。
	udpChain := false
	for _, l := range req.Chain {
		if l.Name == "udp" {
			udpChain = true
		}
	}
	if udpChain && cfg.Discovery == nil {
		return fmt.Errorf("swarm: udp carrier requires a discovery config — storage frames cannot ride the discovery datagram plane (transport/udp)")
	}
	if !udpChain && cfg.Discovery != nil {
		return fmt.Errorf("swarm: tcp carrier cannot carry discovery datagrams — use the [ip,udp,swarm] chain (transport/tcp)")
	}
	if req.EmitMsg != nil {
		return g.generateEvents(ctx, req.EmitMsg, cfg)
	}
	if req.Emit != nil {
		return g.generatePackets(ctx, req.Emit, cfg, req.Meta)
	}
	return fmt.Errorf("swarm generator: neither EmitMsg nor Emit is wired")
}

// defaultConfig is the empty-config default flow (P0b)：UDP discovery 最小
// ping/pong。
func defaultConfig() *core.SwarmConfig {
	return &core.SwarmConfig{
		Discovery: &core.SwarmDiscovery{
			Events: []core.SwarmEvent{{Kind: "ping", Nonce: 1}, {Kind: "pong", Nonce: 1}},
		},
	}
}

// eventDirection resolves the event direction (缺省按 kind)。
func eventDirection(e *core.SwarmEvent) (string, error) {
	if e.Direction != "" {
		if e.Direction != "c2s" && e.Direction != "s2c" {
			return "", fmt.Errorf("swarm: direction %q is invalid (want c2s or s2c)", e.Direction)
		}
		return e.Direction, nil
	}
	if _, ok := discoveryKind(e.Kind); ok {
		if e.Kind == "pong" {
			return "s2c", nil
		}
		return "c2s", nil
	}
	_, _, dir, ok := eventDefaults(e)
	if !ok {
		return "", fmt.Errorf("swarm: unknown frame type %q", e.Kind)
	}
	return dir, nil
}

// flattenedItem is one storage event with its owning session/stream。
type flattenedItem struct {
	event     *core.SwarmEvent
	sessionID uint64
	streamID  uint32
}

// flattenConnection yields the connection's ordered event list (连接级握手
// → 各 session 的会话级事件与 stream 事件)。
func flattenConnection(conn *core.SwarmConnection) []flattenedItem {
	var items []flattenedItem
	for j := range conn.Events {
		items = append(items, flattenedItem{event: &conn.Events[j]})
	}
	for s := range conn.Sessions {
		sess := &conn.Sessions[s]
		for j := range sess.Events {
			items = append(items, flattenedItem{event: &sess.Events[j], sessionID: sess.SessionID})
		}
		for t := range sess.Streams {
			st := &sess.Streams[t]
			for j := range st.Events {
				items = append(items, flattenedItem{event: &st.Events[j], sessionID: sess.SessionID, streamID: st.StreamID})
			}
		}
	}
	return items
}

// generateEvents emits one MessageEvent per frame/datagram in config order。
func (g *SwarmGenerator) generateEvents(ctx context.Context, emit func(layers.MessageEvent) error, cfg *core.SwarmConfig) error {
	if cfg.Discovery != nil {
		src := cfg.Discovery.SrcPort
		for j := range cfg.Discovery.Events {
			e := &cfg.Discovery.Events[j]
			dir, err := eventDirection(e)
			if err != nil {
				return err
			}
			frame, err := BuildDiscoveryEvent(e, cfg)
			if err != nil {
				return fmt.Errorf("swarm: discovery event %d (%s): %v", j, e.Kind, err)
			}
			ev := layers.MessageEvent{Up: dir == "c2s", Bytes: frame, SrcPort: src}
			if err := emitChecked(ctx, emit, ev); err != nil {
				return err
			}
		}
		return nil
	}
	for i := range effectiveConns(cfg) {
		conn := &cfg.Connections[i]
		for _, item := range flattenConnection(conn) {
			dir, err := eventDirection(item.event)
			if err != nil {
				return err
			}
			frame, err := BuildEventFrame(item.event, cfg, item.sessionID, item.streamID)
			if err != nil {
				return fmt.Errorf("swarm: connection %d event (%s): %v", i, item.event.Kind, err)
			}
			if err := CheckFrameMax(frame, cfg.FrameMax); err != nil {
				return fmt.Errorf("swarm: connection %d event (%s): %v", i, item.event.Kind, err)
			}
			ev := layers.MessageEvent{Up: dir == "c2s", Bytes: frame, SrcPort: conn.SrcPort}
			if err := emitChecked(ctx, emit, ev); err != nil {
				return err
			}
		}
	}
	return nil
}

func emitChecked(ctx context.Context, emit func(layers.MessageEvent) error, ev layers.MessageEvent) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	return emit(ev)
}

// effectiveConns returns the connections to generate (空配置默认化)。
func effectiveConns(cfg *core.SwarmConfig) []core.SwarmConnection {
	if len(cfg.Connections) > 0 {
		return cfg.Connections
	}
	return nil
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

// generatePackets is the self-drive path（双栈用例）：每连接完整握手 → 帧段 →
// 四次挥手，方向交换在生成器内完成。
func (g *SwarmGenerator) generatePackets(ctx context.Context, emit func(core.PacketConfig) error, cfg *core.SwarmConfig, meta layers.FlowMeta) error {
	index := uint64(0)
	for i := range cfg.Connections {
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

		for _, item := range flattenConnection(conn) {
			dir, err := eventDirection(item.event)
			if err != nil {
				return err
			}
			frame, err := BuildEventFrame(item.event, cfg, item.sessionID, item.streamID)
			if err != nil {
				return fmt.Errorf("swarm: connection %d event (%s): %v", i, item.event.Kind, err)
			}
			if err := CheckFrameMax(frame, cfg.FrameMax); err != nil {
				return fmt.Errorf("swarm: connection %d event (%s): %v", i, item.event.Kind, err)
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

// streamKey scopes correlation/fragment/message state per (session, stream)
// ——设计 §5：每个 stream 的状态独立。
type streamKey struct {
	session uint64
	stream  uint32
}

// streamState is the per-stream protocol state (设计 §5)。
type streamState struct {
	pendingRetrieve map[uint64]bool // RETRIEVE correlation → awaiting CHUNK
	pendingStore    map[uint64]bool
	answered        map[uint64]bool
	usedCorr        map[uint64]bool
	messages        map[uint64]bool // message ids available for ack
	acked           map[uint64]bool
	unacked         map[uint64]bool // ack-required store/chunk
	fragments       map[uint64]*fragState
}

type fragState struct {
	count  int
	seen   map[int]bool
	addr   string
	seq    uint64
	hasSeq bool
}

func newStreamState() *streamState {
	return &streamState{
		pendingRetrieve: map[uint64]bool{}, pendingStore: map[uint64]bool{},
		answered: map[uint64]bool{}, usedCorr: map[uint64]bool{},
		messages: map[uint64]bool{}, acked: map[uint64]bool{},
		unacked: map[uint64]bool{}, fragments: map[uint64]*fragState{},
	}
}

// sessState is the per-session state (设计 §5)。
type sessState struct {
	opened  bool
	closed  bool
	streams map[uint32]*streamState
	// session-level (stream 0) state doubles as streams[0]。
}

type connState struct {
	negotiated    bool
	authenticated bool
	sessions      map[uint64]*sessState
	streamIDs     map[uint64]map[uint32]bool // session → declared stream ids
}

// validateStorage walks one connection's flattened events through the
// storage state machine (设计 §5)。
func validateStorage(connIdx int, items []flattenedItem, cfg *core.SwarmConfig) error {
	st := &connState{sessions: map[uint64]*sessState{}, streamIDs: map[uint64]map[uint32]bool{}}
	sessOf := func(id uint64) *sessState {
		s := st.sessions[id]
		if s == nil {
			s = &sessState{streams: map[uint32]*streamState{}}
			st.sessions[id] = s
			st.streamIDs[id] = map[uint32]bool{}
		}
		return s
	}
	streamOf := func(id uint64, stream uint32) *streamState {
		s := sessOf(id)
		ss := s.streams[stream]
		if ss == nil {
			ss = newStreamState()
			s.streams[stream] = ss
		}
		return ss
	}

	for i := range items {
		e := items[i].event
		if _, _, _, ok := eventDefaults(e); !ok {
			return fmt.Errorf("swarm: connection %d event %d: unknown frame type %q (frame/type)", connIdx, i, e.Kind)
		}
		switch e.Kind {
		case "hello":
			if i != 0 {
				return fmt.Errorf("swarm: connection %d handshake error: hello must be the first storage frame, got event %d (hello/handshake)", connIdx, i)
			}
			if dir, _ := eventDirection(e); dir != "c2s" {
				return fmt.Errorf("swarm: connection %d handshake error: hello must be c2s, got %s (handshake)", connIdx, dir)
			}
			st.negotiated = true
		case "hello_ok":
			if !st.negotiated {
				return fmt.Errorf("swarm: connection %d handshake error: hello_ok before hello (handshake)", connIdx)
			}
		case "auth":
			if !st.negotiated {
				return fmt.Errorf("swarm: connection %d handshake error: auth before hello (hello/handshake)", connIdx)
			}
			if dir, _ := eventDirection(e); dir != "c2s" {
				return fmt.Errorf("swarm: connection %d handshake error: auth must be c2s, got %s (handshake/auth)", connIdx, dir)
			}
		case "auth_ok":
			st.authenticated = true
		case "open_session":
			if !st.authenticated {
				return fmt.Errorf("swarm: connection %d handshake error: open_session before auth_ok — AUTH_OK must precede OPEN_SESSION (auth/session)", connIdx)
			}
			if items[i].sessionID == 0 {
				return fmt.Errorf("swarm: connection %d event %d: open_session requires a nonzero session_id (session)", connIdx, i)
			}
			s := sessOf(items[i].sessionID)
			if s.opened {
				return fmt.Errorf("swarm: connection %d duplicate session %d — session ids are unique within a connection (session)", connIdx, items[i].sessionID)
			}
			s.opened = true
		case "close":
			s := sessOf(items[i].sessionID)
			if !s.opened {
				return fmt.Errorf("swarm: connection %d session error: close references session %d which is not open (session)", connIdx, items[i].sessionID)
			}
			s.closed = true
		case "close_ok":
			s := sessOf(items[i].sessionID)
			if !s.closed {
				return fmt.Errorf("swarm: connection %d session error: close_ok without a preceding close for session %d (session)", connIdx, items[i].sessionID)
			}
		case "store", "retrieve", "manifest", "chunk", "ping", "pong", "store_ok", "message_ack", "error":
			s := sessOf(items[i].sessionID)
			if !s.opened {
				return fmt.Errorf("swarm: connection %d session error: %s references session %d which is not open — open_session must precede session traffic (session/connection)", connIdx, e.Kind, items[i].sessionID)
			}
			if s.closed {
				return fmt.Errorf("swarm: connection %d state error: %s arrives after close — no new frames after close (session)", connIdx, e.Kind)
			}
			if e.Kind == "ping" || e.Kind == "pong" {
				continue
			}
			ss := streamOf(items[i].sessionID, items[i].streamID)
			if err := validateStreamFrame(connIdx, i, e, ss, items[i].streamID, cfg); err != nil {
				return err
			}
		}
	}
	// 设计 §6 MUST：ack-required 帧必须收到 MESSAGE_ACK（按 session/stream
	// 确定性扫描）。
	for sidx, s := range st.sessions {
		streamIDs := make([]int, 0, len(s.streams))
		for id := range s.streams {
			streamIDs = append(streamIDs, int(id))
		}
		sortInts(streamIDs)
		for _, sid := range streamIDs {
			if len(s.streams[uint32(sid)].unacked) > 0 {
				return fmt.Errorf("swarm: connection %d: session %d stream %d has ack-required frames without a MESSAGE_ACK (message/ack)", connIdx, sidx, sid)
			}
		}
	}
	return nil
}

// validateStreamFrame checks correlation/chunk/fragment/ack invariants within
// one stream (设计 §4/§6)。
func validateStreamFrame(connIdx, i int, e *core.SwarmEvent, ss *streamState, streamID uint32, cfg *core.SwarmConfig) error {
	switch e.Kind {
	case "store":
		if e.CorrelationID == 0 {
			return fmt.Errorf("swarm: connection %d event %d: store requires a nonzero correlation_id (correlation)", connIdx, i)
		}
		if ss.usedCorr[e.CorrelationID] {
			return fmt.Errorf("swarm: connection %d event %d: correlation_id %d is not unique within stream %d (correlation)", connIdx, i, e.CorrelationID, streamID)
		}
		addr, err := validateChunkAddress(e.ChunkAddress)
		if err != nil {
			return fmt.Errorf("swarm: connection %d event %d: %v", connIdx, i, err)
		}
		size := e.ChunkSize
		if size == 0 {
			size = uint32(len(e.Payload))
		}
		if uint64(len(e.Payload)) != uint64(size) {
			return fmt.Errorf("swarm: connection %d event %d: chunk_payload length %d does not equal chunk_size %d (chunk/length)", connIdx, i, len(e.Payload), size)
		}
		ss.usedCorr[e.CorrelationID] = true
		ss.pendingStore[e.CorrelationID] = true
		if e.MessageID > 0 {
			ss.messages[e.MessageID] = true
		}
		if e.DeliveryMode == 1 {
			key := e.MessageID
			if key == 0 {
				key = e.CorrelationID
			}
			ss.unacked[key] = true
		}
		_ = addr
	case "store_ok":
		if !ss.pendingStore[e.CorrelationID] {
			if ss.answered[e.CorrelationID] {
				return fmt.Errorf("swarm: connection %d event %d: store_ok correlation_id %d already answered (correlation)", connIdx, i, e.CorrelationID)
			}
			return fmt.Errorf("swarm: connection %d event %d: store_ok correlation_id %d has no pending store (correlation)", connIdx, i, e.CorrelationID)
		}
		delete(ss.pendingStore, e.CorrelationID)
		ss.answered[e.CorrelationID] = true
	case "retrieve":
		if e.CorrelationID == 0 {
			return fmt.Errorf("swarm: connection %d event %d: retrieve requires a nonzero correlation_id (correlation)", connIdx, i)
		}
		if ss.usedCorr[e.CorrelationID] {
			return fmt.Errorf("swarm: connection %d event %d: correlation_id %d is not unique within stream %d (correlation)", connIdx, i, e.CorrelationID, streamID)
		}
		if _, err := validateChunkAddress(e.ChunkAddress); err != nil {
			return fmt.Errorf("swarm: connection %d event %d: %v", connIdx, i, err)
		}
		ss.usedCorr[e.CorrelationID] = true
		ss.pendingRetrieve[e.CorrelationID] = true
	case "chunk":
		if !ss.pendingRetrieve[e.CorrelationID] {
			return fmt.Errorf("swarm: connection %d event %d: chunk correlation_id %d has no pending retrieve in stream %d (correlation/chunk)", connIdx, i, e.CorrelationID, streamID)
		}
		if _, err := validateChunkAddress(e.ChunkAddress); err != nil {
			return fmt.Errorf("swarm: connection %d event %d: %v", connIdx, i, err)
		}
		if e.FragmentCount > 0 {
			f := ss.fragments[e.CorrelationID]
			if f == nil {
				f = &fragState{count: e.FragmentCount, seen: map[int]bool{}}
				ss.fragments[e.CorrelationID] = f
			}
			if e.FragmentIndex >= e.FragmentCount {
				return fmt.Errorf("swarm: connection %d event %d: fragment_index %d out of range for fragment_count %d (fragment/reassembly)", connIdx, i, e.FragmentIndex, e.FragmentCount)
			}
			if f.count != e.FragmentCount {
				return fmt.Errorf("swarm: connection %d event %d: fragment_count changed from %d to %d mid-transfer (fragment)", connIdx, i, f.count, e.FragmentCount)
			}
			if f.seen[e.FragmentIndex] {
				return fmt.Errorf("swarm: connection %d event %d: duplicate fragment_index %d in stream %d (fragment)", connIdx, i, e.FragmentIndex, streamID)
			}
			f.seen[e.FragmentIndex] = true
			if len(f.seen) == f.count {
				delete(ss.unacked, e.CorrelationID)
			}
		}
		if e.DeliveryMode == 1 {
			key := e.MessageID
			if key == 0 {
				key = e.CorrelationID
			}
			ss.unacked[key] = true
		}
	case "manifest":
		if e.CorrelationID == 0 {
			return fmt.Errorf("swarm: connection %d event %d: manifest requires a nonzero correlation_id (correlation)", connIdx, i)
		}
		if ss.usedCorr[e.CorrelationID] {
			return fmt.Errorf("swarm: connection %d event %d: correlation_id %d is not unique within stream %d (correlation)", connIdx, i, e.CorrelationID, streamID)
		}
		ss.usedCorr[e.CorrelationID] = true
		ss.answered[e.CorrelationID] = true
		if e.MessageID > 0 {
			ss.messages[e.MessageID] = true
		}
		if e.DeliveryMode == 1 {
			key := e.MessageID
			if key == 0 {
				key = e.CorrelationID
			}
			ss.unacked[key] = true
		}
	case "message_ack":
		key := e.AckFor
		if key == 0 {
			return fmt.Errorf("swarm: connection %d event %d: message_ack requires ack_for (ack)", connIdx, i)
		}
		if !ss.messages[key] && !ss.unacked[key] {
			return fmt.Errorf("swarm: connection %d event %d: message_ack ack_for %d references an unknown message in stream %d (ack/correlation)", connIdx, i, key, streamID)
		}
		if ss.acked[key] {
			return fmt.Errorf("swarm: connection %d event %d: message %d already acknowledged — duplicate ack (ack)", connIdx, i, key)
		}
		ss.acked[key] = true
		delete(ss.unacked, key)
	}
	return nil
}

// validateChunkAddress validates the 32-byte content address hex。
func validateChunkAddress(s string) ([]byte, error) {
	if s == "" {
		return nil, nil // 缺省 fixture 地址（builder 同款默认）
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("chunk address %q is not valid hex (chunk/address)", s)
	}
	if len(b) != 32 {
		return nil, fmt.Errorf("chunk address must be 32 bytes, got %d (chunk/address)", len(b))
	}
	return b, nil
}

func sortInts(v []int) {
	for i := 1; i < len(v); i++ {
		for j := i; j > 0 && v[j] < v[j-1]; j-- {
			v[j], v[j-1] = v[j-1], v[j]
		}
	}
}

// validateDiscovery walks the discovery plane events (设计 §3.1)。
func validateDiscovery(cfg *core.SwarmConfig) error {
	if len(cfg.Discovery.Events) == 0 {
		return fmt.Errorf("swarm: discovery has no events — at least one ping is required (hello)")
	}
	for i := range cfg.Discovery.Events {
		e := &cfg.Discovery.Events[i]
		if _, ok := discoveryKind(e.Kind); !ok {
			return fmt.Errorf("swarm: discovery event %d: kind %q is not a discovery frame — storage frames cannot ride the datagram plane (frame/transport)", i, e.Kind)
		}
		for j := range e.Endpoints {
			ep := &e.Endpoints[j]
			if ep.AddressFamily != 1 && ep.AddressFamily != 2 {
				return fmt.Errorf("swarm: discovery event %d endpoint %d: address_family %d is invalid (endpoint)", i, j, ep.AddressFamily)
			}
		}
	}
	return nil
}

// ValidateConfig rejects configs that must never reach the wire (设计 §8/§9):
// unknown profiles, wire faults, mixed planes, malformed node/endpoint values,
// and per-connection state machine violations.
func ValidateConfig(cfg *core.SwarmConfig) error {
	if cfg == nil {
		return nil
	}
	switch cfg.Profile {
	case "", "swarm_storage_v1", "swarm_discovery_v1":
	default:
		return fmt.Errorf("swarm: unknown profile %q — want swarm_storage_v1 or swarm_discovery_v1 (profile)", cfg.Profile)
	}
	if err := validateWireFault(cfg.WireFault); err != nil {
		return err
	}
	if cfg.NodeIDHex != "" {
		b, err := hex.DecodeString(cfg.NodeIDHex)
		if err != nil || len(b) != 32 {
			return fmt.Errorf("swarm: node_id_hex must be 64 hex chars decoding to 32 bytes (node)")
		}
	}
	if cfg.Discovery != nil && len(cfg.Connections) > 0 {
		return fmt.Errorf("swarm: discovery and storage connections are separate planes — configure one per flow (transport)")
	}
	if cfg.Discovery == nil && len(cfg.Connections) == 0 {
		// 空配置无法安全默认化（默认平面取决于载体链）——显式拒绝而非
		// 静默产出 0 包。
		return fmt.Errorf("swarm: config requires a discovery plane or storage connections — at least the hello negotiation (hello)")
	}
	if cfg.Discovery != nil {
		return validateDiscovery(cfg)
	}
	for i := range cfg.Connections {
		items := flattenConnection(&cfg.Connections[i])
		if len(items) == 0 {
			return fmt.Errorf("swarm: connection %d has no events — at least the hello negotiation is required (hello)", i)
		}
		if err := validateStorage(i, items, cfg); err != nil {
			return err
		}
	}
	return nil
}

// validateWireFault rejects every injected fault with its testcase-contract
// anchor word, and any unknown kind。
func validateWireFault(f string) error {
	if f == "" {
		return nil
	}
	switch f {
	case "bad_magic":
		return fmt.Errorf("swarm: wire_fault bad_magic — frames must start with the SWD1/SWS1 magic; other magics are rejected at validation (frame)")
	case "bad_version":
		return fmt.Errorf("swarm: wire_fault bad_version — version 1 is the only legal frame version; other values are rejected at validation (version/frame)")
	case "unknown_kind":
		return fmt.Errorf("swarm: wire_fault unknown_kind — the frame kind must be a known value; unknown kinds are rejected at validation (frame/type)")
	case "reserved_flags":
		return fmt.Errorf("swarm: wire_fault reserved_flags — only request/response/ack/fragment bits are defined; reserved flag bits are rejected at validation (flags/frame)")
	case "length_overrun":
		return fmt.Errorf("swarm: wire_fault length_overrun — the declared length must equal the encoded bytes and stay within frame_max; overruns are rejected at validation (length/frame)")
	case "bad_frame_end":
		return fmt.Errorf("swarm: wire_fault bad_frame_end — the frame must end with the 0xae5a marker; other terminators are rejected at validation (frame end/frame)")
	}
	return fmt.Errorf("swarm: unknown wire_fault kind %q", f)
}

// ValidateSpec is the layer-level spec validator (registered in init and
// shared with tests)：端口契约 + 配置校验。
func ValidateSpec(spec *core.FlowSpec) error {
	// Swarm discovery/storage 目的端口均默认 1634（设计 §2）：显式写其它
	// 目的端口即负例（port 锚词）；0 = 未写，由 FieldContract 补。
	if spec.Swarm != nil && spec.DstPort != 0 && spec.DstPort != defaultDstPort {
		return fmt.Errorf("swarm: destination port %d is not the Swarm port %d — non-TCP/UDP carriers or wrong ports are rejected", spec.DstPort, defaultDstPort)
	}
	return ValidateConfig(spec.Swarm)
}

func init() {
	layers.RegisterLayerGenerator("swarm", func() (layers.LayerGenerator, error) {
		return &SwarmGenerator{}, nil
	})
	layers.RegisterLayerValidator("swarm", ValidateSpec)
}
