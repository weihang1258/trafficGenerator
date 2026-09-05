// Package nmea implements the NMEA 0183 sentence terminal layer
// （海用电子设备数据交换标准，[tcp→nmea]/[udp→nmea] 双载体）：明文 ASCII
// 句子 `$`+地址(2 talker+3 type)+逗号字段+[`*`两位大写 hex XOR 校验和]+
// CRLF。单向通知流（恒上行，无响应）；TCP 字节流按 pack/split 切段，UDP
// 数据报按事件组报文。
//
// Wire-format authority: docs/protocol-designs/69-nmea-design.md v2.0.0
// §3 (talker 值域表/七句型逐字段/XOR 口径/82B 上界）与 testcase §3 字节
// 基线表（全句 hex 含 CRLF 尾 0d0a、XOR 复算值）。本机无 NMEA dissector，
// 全部断言走 tcp.payload/udp.payload + frames offset 54/74/42/62。
package nmea

import (
	"context"
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// NMEAGenerator is the nmea terminal-layer generator
// ([tcp→nmea]/[udp→nmea])。Each sentence event becomes one MessageEvent
// carrying the COMPLETE sentence bytes (ASCII + CRLF)；pack_next / Pack
// 合并为单事件多句（tcp 层单段），SplitAt 驱动跨段切位（tcp 层 MSS/切分）。
// UDP 载体下每会话每事件独立成报文（报文边界不切句），pack 时同会话多句
// 拼接一报文。
type NMEAGenerator struct{}

// Name returns "nmea".
func (g *NMEAGenerator) Name() string { return "nmea" }

// sessionRun is the per-session generation state (design §5：单向流，唯一
// 句间关联 = GSV 序列 total/msg_num)。
type sessionRun struct {
	sess core.NMEASession
	// gsvTotal/msgNum track the open GSV sequence for msg_num 连续性
	// （validator 已校验，生成器只做防御性一致：不同 total 即新序列）。
	gsvTotal string
	gsvNext  int
	pending  []byte
	hasPend  bool
}

// Generate walks the sessions' events and emits one MessageEvent per
// sentence (or per packed run)。Sequential mode walks session by session；
// concurrent mode interleaves round-robin by event index (设计 §5 并发会话)。
//
// Self-drive path (req.Emit != nil): mixed tcp+udp carrier.
// PCAP ordering: transport序 (tcp sessions first, then udp sessions) +
// session序 (within each transport group). TCP sessions get full handshake
// (SYN/SYN-ACK/ACK) → per-sentence PSH-ACK → teardown (FIN-ACK/ACK/FIN-ACK/ACK).
// UDP sessions get one raw datagram per sentence event.
func (g *NMEAGenerator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req == nil {
		return fmt.Errorf("nmea generator: request is nil")
	}
	cfg := req.Meta.NMEA
	if cfg == nil {
		cfg = &core.NMEAConfig{}
	}
	sessions := cfg.Sessions
	if len(sessions) == 0 {
		// 空配置默认流（P0b）：GGA 基线单句（fixture 基线值）。TCP 9 包
		// （3 握手 + 1 句 + 4 挥手）；UDP 1 报文。
		sessions = []core.NMEASession{{
			Events: []core.NMEAEvent{{
				Kind:   "sentence",
				Talker: "GP",
				Type:   "GGA",
				Fields: FixtureGGABaseline(),
			}},
		}}
	}

	// Self-drive path: emit complete packets directly (mixed tcp+udp dual-carrier).
	// TCP sessions get full TCP handshake/data/teardown; UDP sessions send raw datagrams.
	if req.Emit != nil {
		return g.generateSelfDrive(ctx, req.Emit, cfg, sessions, req.Meta)
	}

	// EmitMsg path (legacy transport-wired mode).
	if req.EmitMsg == nil {
		return fmt.Errorf("nmea generator: EmitMsg is nil (generator not wired to a transport layer)")
	}

	runs := make([]*sessionRun, len(sessions))
	for i, s := range sessions {
		cp := s
		runs[i] = &sessionRun{sess: cp}
	}

	emit := func(run *sessionRun, b []byte) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		out := layers.MessageEvent{Up: true, Bytes: b}
		if p := run.sess.SrcPort; p != 0 {
			out.SrcPort = p
		}
		return req.EmitMsg(out)
	}

	flush := func(run *sessionRun) error {
		if !run.hasPend {
			return nil
		}
		b := run.pending
		run.pending = nil
		run.hasPend = false
		return emit(run, b)
	}

	buildOne := func(run *sessionRun, ev core.NMEAEvent) error {
		line, err := BuildSentence(run, ev)
		if err != nil {
			return err
		}
		run.pending = append(run.pending, line...)
		run.hasPend = true
		pack := ev.PackNext || cfg.Pack
		if !pack {
			return flush(run)
		}
		return nil
	}

	if cfg.Concurrent {
		maxLen := 0
		for _, r := range runs {
			if len(r.sess.Events) > maxLen {
				maxLen = len(r.sess.Events)
			}
		}
		for j := 0; j < maxLen; j++ {
			for _, r := range runs {
				if j >= len(r.sess.Events) {
					continue
				}
				select {
				case <-ctx.Done():
					return ctx.Err()
				default:
				}
				if err := buildOne(r, r.sess.Events[j]); err != nil {
					return err
				}
			}
		}
	} else {
		for _, r := range runs {
			for _, ev := range r.sess.Events {
				select {
				case <-ctx.Done():
					return ctx.Err()
				default:
				}
				if err := buildOne(r, ev); err != nil {
					return err
				}
			}
		}
	}
	for _, r := range runs {
		if r.hasPend {
			// pack 尾巴：pack 语义是"与下一句合并"，末尾无下一句时直接
			// 冲刷为独立段（不报错——与 ethmining pack_next 尾错不同，
			// NMEA 的 Pack 是会话级开关，末句无后继是合法形态）。
			if err := flush(r); err != nil {
				return err
			}
		}
	}
	return nil
}

// tcpFlowState holds the TCP state machine state for one NMEA TCP session
// (self-drive path). direction up = client→server (device→collector).
// srcIP/dstIP reflect the up direction; emitSegment swaps on "down".
type tcpFlowState struct {
	srcIP, dstIP string
	srcPort      uint16
	dstPort      uint16
	clientSeq    uint32 // up-stream seq (device→collector)
	serverSeq    uint32 // down-stream seq (collector→device)
}

// emitSegment emits one TCP segment via the self-drive emit function.
// direction "up" = device→collector (NMEA unidirectional notification).
func emitSegment(emit func(core.PacketConfig) error, st *tcpFlowState, up bool, flags byte, payload []byte, seq, ack uint32) error {
	direction := "down"
	srcIP, dstIP := st.dstIP, st.srcIP // down reverses src/dst
	srcPort, dstPort := st.dstPort, st.srcPort

	if up {
		direction = "up"
		srcIP, dstIP = st.srcIP, st.dstIP
		srcPort, dstPort = st.srcPort, st.dstPort
	}

	return emit(core.PacketConfig{
		Direction: direction,
		L3:        core.L3Config{SrcIP: srcIP, DstIP: dstIP, Protocol: 6, TTL: 64},
		L4: core.L4Config{
			Protocol:   "tcp",
			SrcPort:    srcPort,
			DstPort:    dstPort,
			Seq:        seq,
			Ack:        ack,
			Flags:      flags,
			WindowSize: 65535,
		},
		Payload: payload,
	})
}

// buildSentenceBytes is a thin wrapper around BuildSentence for the self-drive path.
func buildSentenceBytes(run *sessionRun, ev core.NMEAEvent) ([]byte, error) {
	return BuildSentence(run, ev)
}

// generateSelfDrive emits complete packets for mixed tcp+udp NMEA sessions.
// PCAP ordering: session 序 (sessions array 序) — each session is emitted
// in its declared position with its declared transport (no transport-group
// reordering); design 69-nmea §5 正例 43 nmea_mixed_transport requires
// sessions[0] first, sessions[1] next.
func (g *NMEAGenerator) generateSelfDrive(ctx context.Context, emit func(core.PacketConfig) error, cfg *core.NMEAConfig, sessions []core.NMEASession, meta layers.FlowMeta) error {
	// Resolve IP/port from meta.
	srcIP := meta.SrcIP
	if srcIP == "" {
		srcIP = "10.0.0.1"
	}
	dstIP := meta.DstIP
	if dstIP == "" {
		dstIP = "20.0.0.1"
	}
	srcPort := meta.SrcPort
	if srcPort == 0 {
		srcPort = 12345
	}
	dstPort := meta.DstPort
	if dstPort == 0 {
		dstPort = 10110 // NMEA-0183 standard port
	}

	// PCAP ordering for mixed transport: keep **session order** (sessions array
	// 序) — each session emitted in its declared position with its declared
	// transport. 混合载体 fixture nmea_mixed_transport（设计 69-nmea §5 正例
	// 43）期望 sessions[0] 先出，sessions[1] 后续；不分 transport group。
	for i := range sessions {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		switch sessions[i].Transport {
		case "udp":
			if err := g.emitUDPSession(ctx, emit, sessions[i], srcIP, dstIP, srcPort, dstPort); err != nil {
				return err
			}
		case "tcp", "":
			// "" 视为 tcp（与 carrier 默认一致）
			if err := g.emitTCPSession(ctx, emit, sessions[i], srcIP, dstIP, srcPort, dstPort); err != nil {
				return err
			}
		default:
			// 未知 transport：跳过但保持位置（不报错，与 carrier_conflict
			// 校验拒绝的语义不同——校验捕获声明矛盾，生成器只接 transport
			// 已声明的 tcp/udp；其它值视为配置错误，已在 Validate 拒绝）。
		}
	}
	return nil
}

// emitTCPSession emits the full TCP session: handshake → per-sentence PSH-ACK → teardown.
func (g *NMEAGenerator) emitTCPSession(ctx context.Context, emit func(core.PacketConfig) error, sess core.NMEASession, srcIP, dstIP string, srcPort, dstPort uint16) error {
	st := &tcpFlowState{
		srcIP:     srcIP,
		dstIP:     dstIP,
		srcPort:   srcPort,
		dstPort:   dstPort,
		clientSeq: 1000,
		serverSeq: 2000,
	}

	run := &sessionRun{sess: sess}

	// --- TCP handshake ---
	// SYN (up)
	if err := emitSegment(emit, st, true, layers.FlagSYN, nil, st.clientSeq, 0); err != nil {
		return err
	}
	st.clientSeq++

	// SYN-ACK (down)
	if err := emitSegment(emit, st, false, layers.FlagSYN|layers.FlagACK, nil, st.serverSeq, st.clientSeq); err != nil {
		return err
	}
	st.serverSeq++

	// ACK (up)
	if err := emitSegment(emit, st, true, layers.FlagACK, nil, st.clientSeq, st.serverSeq); err != nil {
		return err
	}

	// --- Per-sentence data: each sentence → one PSH-ACK (up) + server ACK (down) ---
	for _, ev := range sess.Events {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		line, err := buildSentenceBytes(run, ev)
		if err != nil {
			return err
		}
		// PSH-ACK (device sends sentence up)
		if err := emitSegment(emit, st, true, layers.FlagPSH|layers.FlagACK, line, st.clientSeq, st.serverSeq); err != nil {
			return err
		}
		st.clientSeq += uint32(len(line))
		// Server ACK (down)
		if err := emitSegment(emit, st, false, layers.FlagACK, nil, st.serverSeq, st.clientSeq); err != nil {
			return err
		}
	}

	// --- TCP teardown ---
	// FIN-ACK (up, device initiates close)
	if err := emitSegment(emit, st, true, layers.FlagFIN|layers.FlagACK, nil, st.clientSeq, st.serverSeq); err != nil {
		return err
	}
	st.clientSeq++

	// ACK (down, server acknowledges FIN)
	if err := emitSegment(emit, st, false, layers.FlagACK, nil, st.serverSeq, st.clientSeq); err != nil {
		return err
	}

	// FIN-ACK (down, server closes)
	if err := emitSegment(emit, st, false, layers.FlagFIN|layers.FlagACK, nil, st.serverSeq, st.clientSeq); err != nil {
		return err
	}
	st.serverSeq++

	// ACK (up, device acknowledges server FIN)
	if err := emitSegment(emit, st, true, layers.FlagACK, nil, st.clientSeq, st.serverSeq); err != nil {
		return err
	}

	return nil
}

// emitUDPSession emits one raw UDP datagram per sentence event.
func (g *NMEAGenerator) emitUDPSession(ctx context.Context, emit func(core.PacketConfig) error, sess core.NMEASession, srcIP, dstIP string, srcPort, dstPort uint16) error {
	run := &sessionRun{sess: sess}

	for _, ev := range sess.Events {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		line, err := buildSentenceBytes(run, ev)
		if err != nil {
			return err
		}
		sp := srcPort
		if sess.SrcPort != 0 {
			sp = sess.SrcPort
		}
		if err := emit(core.PacketConfig{
			Direction: "up",
			L3:        core.L3Config{SrcIP: srcIP, DstIP: dstIP, Protocol: 17, TTL: 64},
			L4: core.L4Config{
				Protocol: "udp",
				SrcPort:  sp,
				DstPort:  dstPort,
			},
			Payload: line,
		}); err != nil {
			return err
		}
	}
	return nil
}

// GenEvents marks this generator as a message event producer.
func (g *NMEAGenerator) GenEvents() layers.EventGenerator { return g }

// EmitEvent is the EventGenerator interface method, present only to satisfy
// the producer marker. Events flow through GenRequest.EmitMsg only.
func (g *NMEAGenerator) EmitEvent(ev layers.MessageEvent) error {
	return fmt.Errorf("nmea generator: EmitEvent is not wired; events flow through GenRequest.EmitMsg only")
}

func init() {
	layers.RegisterLayerGenerator("nmea", func() (layers.LayerGenerator, error) {
		return &NMEAGenerator{}, nil
	})
	layers.RegisterLayerValidator("nmea", func(spec *core.FlowSpec) error {
		return Validate(*spec)
	})
}
