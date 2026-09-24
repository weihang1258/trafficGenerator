// Package dtls — DTLS（RFC 6347/4347 datagram TLS）终结层。
//
// Register* functions run at init() time (in builder.go), wiring the
// dtls layer into the chain planner and generator factory. The
// side-effect import _ "…/protocol/dtls" activates this registration.
//
// DTLS = [ip → udp → dtls]（udp-only 族；DependsOn ["udp"]；
// FieldContract udp.dst_port=4433——tshark dtls 分解器自动解码依赖）。
// UDP 无连接：每事件 = 一条完整 DTLS record = 一 UDP datagram，无握手/
// 挥手（bacnet 同族）。全协议大端（§4 记录头/§6 握手头——dcerpc LE 勿串）。
//
// record 头 13B：ContentType(1)+Version(2)+Epoch(2)+Sequence48(6)+Length(2)。
// 版本 "1.0"=fEff、"1.2"=fEfd（RFC 6347 §4.1 legacy_record_version 语义）。
// 加密 epoch 后 payload 全 opaque（设计 §8——CiphertextLen 确定性填充，
// 不伪造密文语义）。
package dtls

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// content types（RFC 6347 §4.1；tshark dtls.record.content_type 同值）。
const (
	ctChangeCipherSpec = 20
	ctAlert            = 21
	ctHandshake        = 22
	ctApplicationData  = 23
)

// seq48Max is the inclusive 48-bit record sequence ceiling
// （RFC 6347 §4.1：seq_num 48-bit，超出=回绕前必须重协商——超界拒绝）。
const seq48Max = 0xFFFFFFFFFFFF

// fixture 常量（契约 §3 + 用例 §4 逐例同源）。
const (
	fixtureCipherFill = 0xA5 // CiphertextLen opaque 填充字节（确定性）
	baselineBodyLen   = 8    // 基线 CH opaque body 字节
)

// ---- 版本与基本编码 ----

// versionBytes resolves the on-wire 2-byte record version.
func versionBytes(v string) ([2]byte, error) {
	switch v {
	case "", "1.2":
		return [2]byte{0xFE, 0xFD}, nil
	case "1.0":
		return [2]byte{0xFE, 0xFF}, nil
	}
	return [2]byte{}, fmt.Errorf("dtls: record version %q (version)", v)
}

func put3BE(b []byte, v int) []byte {
	return append(b, byte(v>>16), byte(v>>8), byte(v))
}

func putU16(b []byte, v int) []byte {
	return binary.BigEndian.AppendUint16(b, uint16(v))
}

// hexBytes decodes a fixture hex string（奇长/非 hex 拒）。
func hexBytes(s, what string) ([]byte, error) {
	if len(s)%2 != 0 {
		return nil, fmt.Errorf("dtls: %s hex %q has odd length", what, s)
	}
	out := make([]byte, len(s)/2)
	for i := 0; i < len(out); i++ {
		hi, lo := hexNibble(s[2*i]), hexNibble(s[2*i+1])
		if hi < 0 || lo < 0 {
			return nil, fmt.Errorf("dtls: %s hex %q has non-hex character", what, s)
		}
		out[i] = byte(hi<<4 | lo)
	}
	return out, nil
}

func hexNibble(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	}
	return -1
}

// ---- 序号单解析权威（生成器与 validator 同源同序）----

// seqKey addresses one record-sequence counter: (epoch, direction)——
// RFC 6347 §4.1 每方向、每 epoch 独立 48-bit 计数。
type seqKey struct {
	epoch int
	up    bool
}

// dtlsWalker resolves epoch/seq/msg_seq with the declared-adopt +
// default-increment semantics（bacnet invokeWalker 同款单权威）：
//   - epoch：声明采纳并前推（回退=守卫拒）；缺省沿当前值（起 0）。
//   - seq：声明值 < 计数器 = 回退/复用拒（重传不复用 record seq）；
//     ≥ 计数器 = 采纳并跳到值+1；缺省 = 计数器++。
//   - msg_seq：声明采纳（重传复用同值合法——不设回退守卫，设计 §7）；
//     缺省 = 计数器++（跨 epoch 不重置——RFC 6347 §4.2.1 msg_seq 全局序）。
type dtlsWalker struct {
	cur    [2]int         // per-direction current epoch
	ctr    map[seqKey]int // next record seq per (epoch, direction)
	msgSeq int            // next handshake message_seq
}

func newWalker() *dtlsWalker {
	return &dtlsWalker{ctr: map[seqKey]int{}}
}

// nextRecord resolves the record's (epoch, seq), enforcing the epoch/seq
// natural guards. prefix names the event in errors.
func (w *dtlsWalker) nextRecord(prefix string, ev *core.DTLSEvent) (epoch, seq int, err error) {
	upIdx := 0
	if ev.Up {
		upIdx = 1
	}
	epoch = w.cur[upIdx]
	if ev.Epoch != nil {
		if *ev.Epoch < 0 || *ev.Epoch > 0xFFFF {
			return 0, 0, fmt.Errorf("%s: record epoch %d out of u16 range (epoch)", prefix, *ev.Epoch)
		}
		if *ev.Epoch < w.cur[upIdx] {
			return 0, 0, fmt.Errorf("%s: record epoch %d regresses from current epoch %d (epoch)", prefix, *ev.Epoch, w.cur[upIdx])
		}
		epoch = *ev.Epoch
		w.cur[upIdx] = epoch
	}
	key := seqKey{epoch, ev.Up}
	next := w.ctr[key]
	if ev.Seq != nil {
		if *ev.Seq < 0 || *ev.Seq > seq48Max {
			return 0, 0, fmt.Errorf("%s: record sequence %d beyond 48-bit range (sequence)", prefix, *ev.Seq)
		}
		if *ev.Seq < next {
			return 0, 0, fmt.Errorf("%s: record sequence %d regresses/reuses below next %d on epoch %d (sequence)", prefix, *ev.Seq, next, epoch)
		}
		seq = *ev.Seq
	} else {
		seq = next
	}
	w.ctr[key] = seq + 1
	return epoch, seq, nil
}

// nextMsgSeq resolves the handshake message_seq.
func (w *dtlsWalker) nextMsgSeq(declared *int) int {
	if declared != nil {
		if *declared > w.msgSeq {
			w.msgSeq = *declared
		}
		return *declared
	}
	v := w.msgSeq
	w.msgSeq++
	return v
}

// ---- 记录/握手组装（§4/§6）----

// handshakeBody renders the 12B DTLSHandshake header + fragment body
// （msgSeq 由 walker 解析后传入）。type=3（HelloVerifyRequest）带 cookie
// 时自动组 body = server_version(2)+cookie_len(1)+cookie（RFC 6347
// §4.2.1——cookie 长度前缀恒等于实际字节数，不硬编码运行期随机值）。
func handshakeBody(h *core.DTLSHandshake, msgSeq int) ([]byte, error) {
	if h == nil {
		return nil, fmt.Errorf("dtls: handshake event requires a handshake object (handshake)")
	}
	if h.Type < 0 || h.Type > 255 {
		return nil, fmt.Errorf("dtls: handshake type %d out of u8 range (handshake)", h.Type)
	}
	if msgSeq < 0 || msgSeq > 0xFFFF {
		return nil, fmt.Errorf("dtls: handshake message_seq %d out of u16 range (handshake)", msgSeq)
	}
	body, err := hexBytes(h.Body, "handshake body")
	if err != nil {
		return nil, err
	}
	if h.Cookie != "" {
		if h.Type != 3 {
			return nil, fmt.Errorf("dtls: handshake cookie is only valid on hello_verify_request (type 3), got type %d (cookie)", h.Type)
		}
		ck, err := hexBytes(h.Cookie, "cookie")
		if err != nil {
			return nil, err
		}
		// body = server_version(2) + cookie_len(1) + cookie；body 声明与之
		// 并存时以组装结果为准（cookie 是结构性声明面）。
		version, err := versionBytes("1.2")
		if err != nil {
			return nil, err
		}
		body = append([]byte{version[0], version[1], byte(len(ck))}, ck...)
	}
	length := len(body)
	if h.Length != nil {
		length = *h.Length
	}
	if length < 0 || length > 0xFFFFFF {
		return nil, fmt.Errorf("dtls: handshake length %d beyond 24-bit range (handshake)", length)
	}
	fragLen := len(body)
	if h.FragLen != nil {
		fragLen = *h.FragLen
		// 线上 fragment body = body 本身：声明 frag_len 必须与之相等，
		// 否则记录里多出的字节是 dissector 视角的垃圾（wire 谎言拒）。
		if fragLen != len(body) {
			return nil, fmt.Errorf("dtls: fragment_length %d != fragment body %d bytes on wire (fragment)", fragLen, len(body))
		}
	}
	if h.FragOffset < 0 || h.FragOffset > 0xFFFFFF {
		return nil, fmt.Errorf("dtls: fragment_offset %d beyond 24-bit range (fragment)", h.FragOffset)
	}
	if fragLen < 0 || fragLen > 0xFFFFFF {
		return nil, fmt.Errorf("dtls: fragment_length %d beyond 24-bit range (fragment)", fragLen)
	}
	if h.FragOffset+fragLen > length {
		return nil, fmt.Errorf("dtls: fragment [%d,+%d] exceeds handshake length %d (fragment)", h.FragOffset, fragLen, length)
	}
	b := []byte{byte(h.Type)}
	b = put3BE(b, length)
	b = putU16(b, msgSeq)
	b = put3BE(b, h.FragOffset)
	b = put3BE(b, fragLen)
	return append(b, body...), nil
}

// eventPayload renders the record body for one event（kind 决定形态）。
func eventPayload(ev *core.DTLSEvent, msgSeq int) ([]byte, error) {
	switch ev.Kind {
	case "handshake":
		return handshakeBody(ev.Handshake, msgSeq)
	case "ccs":
		if ev.Payload != "" {
			return hexBytes(ev.Payload, "ccs payload")
		}
		return []byte{0x01}, nil // RFC 6347 CCS 单字节
	case "alert":
		if ev.CiphertextLen > 0 {
			return cipherFill(ev.CiphertextLen)
		}
		level, desc := 1, 0 // 缺省 warning/close_notify
		if ev.AlertLevel != nil {
			level = *ev.AlertLevel
		}
		if ev.AlertDesc != nil {
			desc = *ev.AlertDesc
		}
		if level < 0 || level > 255 || desc < 0 || desc > 255 {
			return nil, fmt.Errorf("dtls: alert level/desc out of u8 range (alert)")
		}
		return []byte{byte(level), byte(desc)}, nil
	case "appdata":
		if ev.Payload != "" {
			return hexBytes(ev.Payload, "appdata payload")
		}
		if ev.CiphertextLen > 0 {
			return cipherFill(ev.CiphertextLen)
		}
		return nil, nil // 零长 ApplicationData 合法（记录边界例）
	}
	return nil, fmt.Errorf("dtls: unknown event kind %q (kind)", ev.Kind)
}

// cipherFill renders deterministic opaque bytes（不伪造密文语义——设计 §8）。
func cipherFill(n int) ([]byte, error) {
	if n < 0 || n > 0xFFFF {
		return nil, fmt.Errorf("dtls: ciphertext_len %d out of record range (payload)", n)
	}
	return bytes.Repeat([]byte{fixtureCipherFill}, n), nil
}

// putRecord renders one full DTLS record (13B header BE + payload)。
func putRecord(ct byte, ver [2]byte, epoch, seq int, payload []byte) []byte {
	b := []byte{ct, ver[0], ver[1]}
	b = putU16(b, epoch)
	for sh := 40; sh >= 0; sh -= 8 {
		b = append(b, byte(seq>>uint(sh)))
	}
	b = putU16(b, len(payload))
	return append(b, payload...)
}

// ---- 事件渲染 ----

type frame struct {
	up    bool
	bytes []byte
}

// renderEvent resolves walker state then renders one record.
// 版本解析：事件声明 > 会话缺省 > "1.2"（versionBytes 内建缺省）。
func renderEvent(w *dtlsWalker, sess *core.DTLSSession, ev *core.DTLSEvent) (frame, error) {
	if ev.Handshake == nil && ev.Kind == "handshake" {
		return frame{}, fmt.Errorf("dtls: handshake event requires a handshake object (handshake)")
	}
	prefix := fmt.Sprintf("dtls: session %q event (%s)", sessIdent(sess), ev.Kind)
	epoch, seq, err := w.nextRecord(prefix, ev)
	if err != nil {
		return frame{}, err
	}
	effVersion := ev.Version
	if effVersion == "" {
		effVersion = sess.Version
	}
	ver, err := versionBytes(effVersion)
	if err != nil {
		return frame{}, err
	}
	var ct byte
	switch ev.Kind {
	case "handshake":
		ct = ctHandshake
	case "ccs":
		ct = ctChangeCipherSpec
	case "alert":
		ct = ctAlert
	case "appdata":
		ct = ctApplicationData
	default:
		return frame{}, fmt.Errorf("%s: unknown event kind %q (kind)", prefix, ev.Kind)
	}
	msgSeq := 0
	if ev.Kind == "handshake" {
		msgSeq = w.nextMsgSeq(ev.Handshake.MsgSeq)
	}
	payload, err := eventPayload(ev, msgSeq)
	if err != nil {
		return frame{}, err
	}
	return frame{up: ev.Up, bytes: putRecord(ct, ver, epoch, seq, payload)}, nil
}

func sessIdent(sess *core.DTLSSession) string {
	if sess.SrcIP != "" {
		return sess.SrcIP
	}
	return "default"
}

// ---- Generate（链驱动入口，bacnet 同族）----

// DTLSGenerator is the terminal-layer generator for dtls chains.
type DTLSGenerator struct{}

func (g *DTLSGenerator) Name() string { return "dtls" }

// GenEvents/EmitEvent mark the event-generator face（bacnet 同款）。
func (g *DTLSGenerator) GenEvents() layers.EventGenerator { return g }
func (g *DTLSGenerator) EmitEvent(layers.MessageEvent) error {
	return fmt.Errorf("dtls generator: EmitEvent is not wired")
}

func (g *DTLSGenerator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req == nil {
		return fmt.Errorf("dtls generator: request is nil")
	}
	if req.EmitMsg == nil {
		return fmt.Errorf("dtls generator: EmitMsg is nil")
	}
	cfg := req.Meta.DTLS
	if cfg == nil {
		cfg = &core.DTLSConfig{}
	}
	if err := (&Planner{}).Validate(core.FlowSpec{
		SrcIP:   req.Meta.SrcIP,
		DstIP:   req.Meta.DstIP,
		SrcPort: req.Meta.SrcPort,
		DstPort: req.Meta.DstPort,
		DTLS:    cfg,
	}); err != nil {
		return err
	}
	frames, err := BuildFrames(cfg)
	if err != nil {
		return err
	}
	// 会话端点覆盖（bacnet 同款）：up 直落 SrcIP/SrcPort；down 会话声明
	// SrcIP 时显式路由 服务端(=流 dst)→客户端（多会话双客户端应答回对端）。
	for _, ef := range frames {
		for _, fr := range ef.frames {
			ev := layers.MessageEvent{Up: fr.up, Bytes: fr.bytes}
			if fr.up {
				if ef.srcIP != "" {
					ev.SrcIP = ef.srcIP
				}
				if ef.srcPort != 0 {
					ev.SrcPort = ef.srcPort
				}
			} else if ef.srcIP != "" {
				ev.SrcIP = req.Meta.DstIP
				ev.DstIP = ef.srcIP
				ev.OverrideDstIP = true
			}
			if ef.dstPort != 0 {
				ev.DstPort = ef.dstPort
			}
			if err := req.EmitMsg(ev); err != nil {
				return err
			}
		}
	}
	return nil
}

// eventFrames is one event's rendered frames + endpoint overrides.
type eventFrames struct {
	frames  []frame
	srcIP   string
	srcPort uint16
	dstPort uint16
}

// BuildFrames renders all sessions' events in replay order（按序整块回放；
// UDP 每事件一 datagram，无连接概念——会话间 epoch/seq/cookie 状态隔离
// 来自逐会话独立 walker）。缺省（无 sessions）发一条最小 ClientHello
// 基线 datagram。
func BuildFrames(cfg *core.DTLSConfig) ([]eventFrames, error) {
	if cfg == nil || len(cfg.Sessions) == 0 {
		body := make([]byte, baselineBodyLen)
		hs := append([]byte{1}, put3BE(nil, baselineBodyLen)...)
		hs = putU16(hs, 0)
		hs = put3BE(hs, 0)
		hs = put3BE(hs, baselineBodyLen)
		hs = append(hs, body...)
		ver, _ := versionBytes("1.2")
		b := putRecord(ctHandshake, ver, 0, 0, hs)
		return []eventFrames{{frames: []frame{{true, b}}}}, nil
	}
	var out []eventFrames
	for si := range cfg.Sessions {
		sess := &cfg.Sessions[si]
		w := newWalker()
		for ei := range sess.Events {
			fr, err := renderEvent(w, sess, &sess.Events[ei])
			if err != nil {
				return nil, fmt.Errorf("dtls: sessions[%d].events[%d]: %w", si, ei, err)
			}
			out = append(out, eventFrames{
				frames:  []frame{fr},
				srcIP:   sess.SrcIP,
				srcPort: sess.SrcPort,
				dstPort: sess.DstPort,
			})
		}
	}
	return out, nil
}

// ---- 注册 ----

func init() {
	layers.RegisterLayerGenerator("dtls", func() (layers.LayerGenerator, error) { return &DTLSGenerator{}, nil })
	layers.RegisterLayerValidator("dtls", func(spec *core.FlowSpec) error { return (&Planner{}).Validate(*spec) })
}
