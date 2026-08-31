package gnutella

import (
	"context"
	"fmt"
	"math/rand"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// GnutellaGenerator 事件模式（ams/openwire 同款）：握手帧与业务消息各一个
// MessageEvent，TCP 层负责握手/MSS 分段/挥手；连接级 SrcPort 边界触发
// TCPGenerator 的会话切换。连接声明显式 src_ip/dst_ip 时走自驱完整包分支
//（双栈用例，B5 自驱分支同构）。
type GnutellaGenerator struct{}

func (g *GnutellaGenerator) Name() string                     { return "gnutella" }
func (g *GnutellaGenerator) GenEvents() layers.EventGenerator { return g }
func (g *GnutellaGenerator) EmitEvent(layers.MessageEvent) error {
	return fmt.Errorf("gnutella generator: EmitEvent is not wired; events flow through GenRequest.EmitMsg only")
}

// Generate dispatches on the wiring: EmitMsg → event mode; Emit → self-drive.
func (g *GnutellaGenerator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req == nil {
		return fmt.Errorf("gnutella generator: request is nil")
	}
	cfg := req.Meta.Gnutella
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
	return fmt.Errorf("gnutella generator: neither EmitMsg nor Emit is wired")
}

// defaultConfig is the empty-config default flow (P0b)：最小握手。
func defaultConfig() *core.GnutellaConfig {
	return &core.GnutellaConfig{
		Connections: []core.GnutellaConn{{
			SrcPort: 42058,
			Events:  []core.GnutellaEvent{{Kind: "connect"}, {Kind: "ok"}},
		}},
	}
}

// effectiveConns returns the connections to generate (空配置默认化)。
func effectiveConns(cfg *core.GnutellaConfig) []core.GnutellaConn {
	if len(cfg.Connections) > 0 {
		return cfg.Connections
	}
	return []core.GnutellaConn{{
		SrcPort: 42058,
		Events:  []core.GnutellaEvent{{Kind: "connect"}, {Kind: "ok"}},
	}}
}

// effectiveProfile resolves the address-family profile。
func effectiveProfile(cfg *core.GnutellaConfig) string {
	if cfg.Profile == profileV6 {
		return profileV6
	}
	return profileV060
}

// eventDirection resolves the event direction (缺省按 kind)。
func eventDirection(e *core.GnutellaEvent) (string, error) {
	if e.Direction != "" {
		if e.Direction != "c2s" && e.Direction != "s2c" {
			return "", fmt.Errorf("gnutella: direction %q is invalid (want c2s or s2c)", e.Direction)
		}
		return e.Direction, nil
	}
	_, dir, _, ok := eventDefaults(e)
	if !ok {
		return "", fmt.Errorf("gnutella: unknown frame type %q", e.Kind)
	}
	return dir, nil
}

// buildEventFrame encodes one event (握手 ASCII 或二进制消息)。
func buildEventFrame(e *core.GnutellaEvent, cfg *core.GnutellaConfig) ([]byte, error) {
	if _, _, handshake, ok := eventDefaults(e); ok && handshake {
		return BuildHandshake(e.Kind, e.Headers), nil
	}
	return BuildMessage(e, effectiveProfile(cfg))
}

// generateEvents emits one MessageEvent per frame in config order。
func (g *GnutellaGenerator) generateEvents(ctx context.Context, emit func(layers.MessageEvent) error, cfg *core.GnutellaConfig) error {
	for i := range effectiveConns(cfg) {
		conn := &cfg.Connections[i]
		for j := range conn.Events {
			e := &conn.Events[j]
			dir, err := eventDirection(e)
			if err != nil {
				return err
			}
			frame, err := buildEventFrame(e, cfg)
			if err != nil {
				return fmt.Errorf("gnutella: connection %d event %d (%s): %v", i, j, e.Kind, err)
			}
			if err := CheckFrameMax(frame, cfg.FrameMax); err != nil {
				return fmt.Errorf("gnutella: connection %d event %d (%s): %v", i, j, e.Kind, err)
			}
			ev := layers.MessageEvent{Up: dir == "c2s", Bytes: frame, SrcPort: conn.SrcPort}
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
			if err := emit(ev); err != nil {
				return err
			}
		}
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
func (g *GnutellaGenerator) generatePackets(ctx context.Context, emit func(core.PacketConfig) error, cfg *core.GnutellaConfig, meta layers.FlowMeta) error {
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

		for j := range conn.Events {
			e := &conn.Events[j]
			dir, err := eventDirection(e)
			if err != nil {
				return err
			}
			frame, err := buildEventFrame(e, cfg)
			if err != nil {
				return fmt.Errorf("gnutella: connection %d event %d (%s): %v", i, j, e.Kind, err)
			}
			if err := CheckFrameMax(frame, cfg.FrameMax); err != nil {
				return fmt.Errorf("gnutella: connection %d event %d (%s): %v", i, j, e.Kind, err)
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

// connState is the per-connection state machine (设计 §5)。
type connState struct {
	connected     bool
	authenticated bool
	closed        bool
	pings         map[string]pingRecord // GUID hex → 记录（pong 关联与转发判定）
	queries       map[string]bool       // Query GUID hex
	queryHits     map[string]string     // ServentID hex → Query GUID hex
}

type pingRecord struct {
	ttl  uint8
	hops uint8
}

// ValidateConfig rejects configs that must never reach the wire (设计 §5/§7/§8):
// unknown profiles, wire faults, header/TTL/correlation violations, and
// per-connection state machine errors.
func ValidateConfig(cfg *core.GnutellaConfig) error {
	if cfg == nil {
		return nil
	}
	switch cfg.Profile {
	case "", profileV060, profileV6:
	default:
		return fmt.Errorf("gnutella: unknown profile %q — want gnutella_v060 or gnutella_ipv6_v1 (profile)", cfg.Profile)
	}
	if err := validateWireFault(cfg.WireFault); err != nil {
		return err
	}
	for i := range cfg.Connections {
		if err := validateConnection(i, &cfg.Connections[i], cfg); err != nil {
			return err
		}
	}
	return nil
}

// validateConnection walks one connection's events through the state machine。
func validateConnection(connIdx int, conn *core.GnutellaConn, cfg *core.GnutellaConfig) error {
	if len(conn.Events) == 0 {
		return fmt.Errorf("gnutella: connection %d has no events — at least the CONNECT handshake is required (handshake)", connIdx)
	}
	st := &connState{
		pings:     map[string]pingRecord{},
		queries:   map[string]bool{},
		queryHits: map[string]string{},
	}
	for i := range conn.Events {
		e := &conn.Events[i]
		desc, dir, handshake, ok := eventDefaults(e)
		if !ok {
			return fmt.Errorf("gnutella: connection %d event %d: unknown frame type %q (descriptor)", connIdx, i, e.Kind)
		}
		if dir == "" {
			return fmt.Errorf("gnutella: connection %d event %d: direction %q is invalid (state)", connIdx, i, e.Direction)
		}
		if st.closed {
			return fmt.Errorf("gnutella: connection %d state error: event %d (%s) arrives after refuse/close — no new frames after a rejected handshake (state)", connIdx, i, e.Kind)
		}
		if handshake {
			if err := validateHandshakeEvent(connIdx, i, e, dir, st); err != nil {
				return err
			}
			continue
		}
		if !st.authenticated {
			return fmt.Errorf("gnutella: connection %d handshake error: %s before the 200 OK handshake response (handshake/state)", connIdx, e.Kind)
		}
		// TTL/Hops 回绕检查（uint8 求和 ≤ 255，设计 §3.2/§7）。
		if int(e.TTL)+int(e.Hops) > 255 {
			return fmt.Errorf("gnutella: connection %d event %d: ttl %d + hops %d exceeds 255 — hop count would wrap (ttl/hops)", connIdx, i, e.TTL, e.Hops)
		}
		if err := validateMessageEvent(connIdx, i, e, desc, st, cfg); err != nil {
			return err
		}
	}
	return nil
}

// validateHandshakeEvent checks the handshake ordering and direction。
func validateHandshakeEvent(connIdx, i int, e *core.GnutellaEvent, dir string, st *connState) error {
	switch e.Kind {
	case "connect":
		if i != 0 {
			return fmt.Errorf("gnutella: connection %d handshake error: CONNECT must be the first application frame, got event %d (handshake)", connIdx, i)
		}
		if dir != "c2s" {
			return fmt.Errorf("gnutella: connection %d handshake error: CONNECT must be c2s, got %s (handshake)", connIdx, dir)
		}
		st.connected = true
	case "ok":
		if !st.connected {
			return fmt.Errorf("gnutella: connection %d handshake error: 200 OK before CONNECT (handshake/state)", connIdx)
		}
		if dir != "s2c" {
			return fmt.Errorf("gnutella: connection %d handshake error: 200 OK must be s2c, got %s (handshake)", connIdx, dir)
		}
		st.authenticated = true
	case "refuse":
		if !st.connected {
			return fmt.Errorf("gnutella: connection %d handshake error: 503 before CONNECT (handshake/state)", connIdx)
		}
		st.closed = true // 拒绝后不得有业务消息（设计 §5 Closing）
	}
	return nil
}

// validateMessageEvent checks the message correlation and payload semantics
// (设计 §4)。
func validateMessageEvent(connIdx, i int, e *core.GnutellaEvent, desc byte, st *connState, cfgRef *core.GnutellaConfig) error {
	guid, err := resolveGUID(e.MessageID)
	if err != nil {
		return fmt.Errorf("gnutella: connection %d event %d: %v", connIdx, i, err)
	}
	key := fmt.Sprintf("%x", guid)
	switch desc {
	case descPing:
		if prev, dup := st.pings[key]; dup {
			// 重复 MessageID：转发副本（ttl 减一、hops 加一）或去重副本。
			if e.TTL == prev.ttl && e.Hops == prev.hops {
				return nil // 去重副本（合法协议事件）
			}
			if e.TTL >= prev.ttl || e.Hops <= prev.hops {
				return fmt.Errorf("gnutella: connection %d event %d: forwarded ping must decrement ttl and increment hops (ttl %d→%d, hops %d→%d) (ttl/hops)", connIdx, i, prev.ttl, e.TTL, prev.hops, e.Hops)
			}
			if e.TTL == 0 {
				return fmt.Errorf("gnutella: connection %d event %d: ttl 0 message must not be forwarded (ttl)", connIdx, i)
			}
		}
		st.pings[key] = pingRecord{ttl: e.TTL, hops: e.Hops}
	case descPong:
		if _, pending := st.pings[key]; !pending {
			return fmt.Errorf("gnutella: connection %d event %d: pong message_id %s does not reference a sent ping (correlation)", connIdx, i, key)
		}
		if _, err := resolveAddress(e.PongAddress, effectiveProfile(cfgRef)); err != nil {
			return fmt.Errorf("gnutella: connection %d event %d: %v", connIdx, i, err)
		}
	case descQuery:
		if _, dup := st.queries[key]; !dup {
			st.queries[key] = true
		}
	case descQueryHit:
		qkey := fmt.Sprintf("%x", e.QueryID)
		if !st.queries[qkey] {
			return fmt.Errorf("gnutella: connection %d event %d: query_hit references query %s which was not sent (query/correlation)", connIdx, i, qkey)
		}
		if e.Hits != len(e.Results) {
			return fmt.Errorf("gnutella: connection %d event %d: query_hit hits %d does not equal %d results (payload/hits)", connIdx, i, e.Hits, len(e.Results))
		}
		if _, err := resolveAddress(e.HitAddress, effectiveProfile(cfgRef)); err != nil {
			return fmt.Errorf("gnutella: connection %d event %d: %v", connIdx, i, err)
		}
		servent, err := resolveGUID(e.ServentID)
		if err != nil {
			return fmt.Errorf("gnutella: connection %d event %d: %v", connIdx, i, err)
		}
		st.queryHits[fmt.Sprintf("%x", servent)] = qkey
	case descPush:
		servent, err := resolveGUID(e.ServentID)
		if err != nil {
			return fmt.Errorf("gnutella: connection %d event %d: %v", connIdx, i, err)
		}
		if _, src := st.queryHits[fmt.Sprintf("%x", servent)]; !src {
			return fmt.Errorf("gnutella: connection %d event %d: push servent_id %s has no preceding query_hit (servent/correlation)", connIdx, i, key)
		}
		if _, err := resolveAddress(e.PushAddress, effectiveProfile(cfgRef)); err != nil {
			return fmt.Errorf("gnutella: connection %d event %d: %v", connIdx, i, err)
		}
	case descVendor:
		// Vendor 扩展为显式业务事件：长度由 builder 校验。
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
	case "bad_handshake_line":
		return fmt.Errorf("gnutella: wire_fault bad_handshake_line — the handshake must start with the GNUTELLA CONNECT/0.6 line and CRLF boundaries (handshake/header)")
	case "header_truncation":
		return fmt.Errorf("gnutella: wire_fault header_truncation — every message needs the full 23-byte header; truncated headers are rejected at validation (message/length)")
	case "bad_descriptor":
		return fmt.Errorf("gnutella: wire_fault bad_descriptor — the descriptor must be a known value; unknown descriptors are rejected at validation (descriptor/message)")
	case "length_overrun":
		return fmt.Errorf("gnutella: wire_fault length_overrun — the payload length must equal the encoded bytes and stay within frame_max; overruns are rejected at validation (length)")
	}
	return fmt.Errorf("gnutella: unknown wire_fault kind %q", f)
}

// ValidateSpec is the layer-level spec validator (registered in init and
// shared with tests)：端口契约 + 配置校验。
func ValidateSpec(spec *core.FlowSpec) error {
	// Gnutella 只走 TCP/6346：显式写其它目的端口即负例（port 锚词）；
	// 0 = 未写，由 FieldContract 补 6346。
	if spec.Gnutella != nil && spec.DstPort != 0 && spec.DstPort != defaultDstPort {
		return fmt.Errorf("gnutella: destination port %d is not the Gnutella TCP port %d — non-TCP carriers or wrong ports are rejected", spec.DstPort, defaultDstPort)
	}
	return ValidateConfig(spec.Gnutella)
}

func init() {
	layers.RegisterLayerGenerator("gnutella", func() (layers.LayerGenerator, error) {
		return &GnutellaGenerator{}, nil
	})
	layers.RegisterLayerValidator("gnutella", ValidateSpec)
}
