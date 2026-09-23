// Package edp builder: generates EDP wire-format frames from session configuration.
// EDP (OneNET Enhanced Device Protocol) - TCP-based byte-stream terminal protocol.
package edp

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// EDPGenerator generates EDP protocol frames.
type EDPGenerator struct{}

func (g *EDPGenerator) Name() string { return "edp" }

// GenEvents marks this generator as a terminal event producer (报文事件生产者，
// hl7/megaco 同款)——nil 会令 ChainPlanner 不接事件通道，tcp 层留在 legacy
// 单载荷模式，全链静默 0 包。
func (g *EDPGenerator) GenEvents() layers.EventGenerator { return g }

// EmitEvent is the EventGenerator interface method, present only to satisfy
// the producer marker. Events flow through GenRequest.EmitMsg only.
func (g *EDPGenerator) EmitEvent(ev layers.MessageEvent) error {
	return fmt.Errorf("edp generator: EmitEvent is not wired; events flow through GenRequest.EmitMsg only")
}

// sessionRun is per-session generation state.
type sessionRun struct {
	idx  int
	sess core.EDPSession
}

func (g *EDPGenerator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req.EmitMsg == nil {
		return fmt.Errorf("edp generator: EmitMsg is nil")
	}

	cfg := req.Meta.EDP
	if cfg == nil {
		cfg = &core.EDPConfig{}
	}

	// EDP default dst_port = 4472
	dstPort := uint16(4472)
	if len(cfg.Sessions) > 0 && cfg.Sessions[0].DstPort != 0 {
		dstPort = cfg.Sessions[0].DstPort
	}

	runs := make([]*sessionRun, len(cfg.Sessions))
	for i := range cfg.Sessions {
		runs[i] = &sessionRun{idx: i, sess: cfg.Sessions[i]}
	}

	// Build per-session frame sequences: [][]MessageEvent (each event → list of frames)
	runsFrames := make([][][]layers.MessageEvent, len(runs))
	for i, r := range runs {
		runsFrames[i] = buildSessionMessageEvents(&r.sess)
	}

	emit := func(ev layers.MessageEvent) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		return req.EmitMsg(ev)
	}

	if cfg.Concurrent {
		// Round-robin: one event index per session per round
		maxLen := 0
		for _, r := range runsFrames {
			if len(r) > maxLen {
				maxLen = len(r)
			}
		}
		for j := 0; j < maxLen; j++ {
			for si, r := range runsFrames {
				if j >= len(r) {
					continue
				}
				for _, ev := range r[j] {
					ev.DstPort = dstPort
					ev.SrcPort = cfg.Sessions[si].SrcPort
					if err := emit(ev); err != nil {
						return err
					}
				}
			}
		}
		return nil
	}

	// Sequential: session by session
	for si, r := range runsFrames {
		sess := cfg.Sessions[si]
		if sess.Coalesce {
			// JoinNext pattern: accumulate adjacent same-direction events
			if err := emitCoalescedEvents(r, dstPort, sess.SrcPort, emit); err != nil {
				return err
			}
		} else {
			for _, group := range r {
				for k := range group {
					group[k].DstPort = dstPort
					group[k].SrcPort = sess.SrcPort
					if err := emit(group[k]); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

// frame is one wire frame with its transport direction (帧级方向：同一事件
// 的请求/响应帧方向相反——CONNREQ up + CONNRESP down）。
type frame struct {
	up    bool
	bytes []byte
}

// buildSessionMessageEvents builds the per-event message events for a session.
// Each source event may produce 2 MessageEvents (e.g. CONNREQ + CONNRESP).
func buildSessionMessageEvents(sess *core.EDPSession) [][]layers.MessageEvent {
	var result [][]layers.MessageEvent
	for evIdx := range sess.Events {
		frames := buildEDPFrames(sess, evIdx)
		var evMsgs []layers.MessageEvent
		for _, f := range frames {
			evMsgs = append(evMsgs, layers.MessageEvent{
				Up:    f.up,
				Bytes: f.bytes,
			})
		}
		result = append(result, evMsgs)
	}
	return result
}

// emitCoalescedEvents joins adjacent same-direction events into a single MessageEvent (JoinNext).
func emitCoalescedEvents(eventGroups [][]layers.MessageEvent, dstPort, srcPort uint16, emit func(layers.MessageEvent) error) error {
	if len(eventGroups) == 0 {
		return nil
	}

	var buf bytes.Buffer
	var curUp bool
	for _, group := range eventGroups {
		for _, ev := range group {
			if buf.Len() > 0 && ev.Up != curUp {
				if err := emit(layers.MessageEvent{Up: curUp, Bytes: buf.Bytes(), DstPort: dstPort, SrcPort: srcPort}); err != nil {
					return err
				}
				buf.Reset()
			}
			buf.Write(ev.Bytes)
			curUp = ev.Up
		}
	}
	if buf.Len() > 0 {
		return emit(layers.MessageEvent{Up: curUp, Bytes: buf.Bytes(), DstPort: dstPort, SrcPort: srcPort})
	}
	return nil
}



// --- Event frame builders ---

// buildEDPFrames renders one event's wire frames with per-frame directions
//（契约 §3.2 方向列：CONNREQ/PINGREQ/SAVEDATA 上行 + CONNRESP/PINGRESP/
// SAVEACK 下行；CMDREQ 平台→设备下行 + CMDRESP 设备→平台上行；PUSHDATA
// 按 direction；DISCONNECT 上行）。
func buildEDPFrames(sess *core.EDPSession, evIdx int) []frame {
	ev := sess.Events[evIdx]
	switch ev.Kind {
	case "connect":
		return []frame{{true, buildCONNREQ(ev)}, {false, buildCONNRESP(ev.ConnackRtn)}}
	case "ping":
		return []frame{{true, buildPINGREQ()}, {false, buildPINGRESP()}}
	case "savedata":
		if ev.Direction == "down" {
			// 下行 SAVEDATA 同构、无应答（§3.5：下行不回 SAVEACK）。
			return []frame{{false, buildSAVEDATA(ev)}}
		}
		// SAVEACK 仅显式 ack:true 时自动补（§5 派生③；契约用例包数口径：
		// 基线存储例 10 包无 SAVEACK，ack 例 11 包）。
		if ev.Ack != nil && *ev.Ack {
			return []frame{{true, buildSAVEDATA(ev)}, {false, buildSAVEACK(ev)}}
		}
		return []frame{{true, buildSAVEDATA(ev)}}
	case "cmdreq":
		return []frame{{false, buildCMDREQ(ev)}, {true, buildCMDRESP(ev)}}
	case "pushdata":
		return []frame{{ev.Direction != "down", buildPUSHDATA(ev)}}
	case "disconnect":
		return []frame{{true, buildDISCONNECT()}}
	default:
		return nil
	}
}

// --- Varint encoding (MQTT-compatible, 1-4 byte LSB-first) ---

func encodeVarint(n int) []byte {
	if n < 0 || n > 268435455 {
		return nil
	}
	var buf [4]byte
	length := 0
	for {
		encodedByte := byte(n % 128)
		n = n / 128
		if n > 0 {
			encodedByte |= 0x80
		}
		buf[length] = encodedByte
		length++
		if n <= 0 {
			break
		}
	}
	out := make([]byte, length)
	copy(out, buf[:length])
	return out
}

// --- Big-endian helpers ---

func writeU16BE(dst []byte, v uint16) { binary.BigEndian.PutUint16(dst, v) }
func writeU32BE(dst []byte, v uint32) { binary.BigEndian.PutUint32(dst, v) }

// --- Single-frame builders ---

func buildCONNREQ(ev core.EDPEvent) []byte {
	protocolName := []byte("EDP")
	version := byte(0x01)
	keepTime := uint16(128)
	if ev.KeepTime != nil {
		keepTime = *ev.KeepTime
	}

	if ev.Auth == "userid" || ev.Auth == "2" {
		userid := ev.UserID
		authinfo := ev.AuthInfo
		remainLen := 15 + len(userid) + len(authinfo)
		remainBytes := encodeVarint(remainLen)
		total := 1 + len(remainBytes) + 2 + len(protocolName) + 1 + 1 + 2 + 2 + 2 + len(userid) + 2 + len(authinfo)

		buf := make([]byte, total)
		off := 0
		buf[off] = 0x10; off++
		off += copy(buf[off:], remainBytes)
		writeU16BE(buf[off:], uint16(len(protocolName))); off += 2
		off += copy(buf[off:], protocolName)
		buf[off] = version; off++
		buf[off] = 0xC0; off++
		writeU16BE(buf[off:], keepTime); off += 2
		writeU16BE(buf[off:], 0); off += 2 // empty devid
		writeU16BE(buf[off:], uint16(len(userid))); off += 2
		off += copy(buf[off:], userid)
		writeU16BE(buf[off:], uint16(len(authinfo))); off += 2
		off += copy(buf[off:], authinfo)
		return buf
	}

	// Mode 1: devid + apikey (default, flag 0x40)
	devid := ev.Devid
	apikey := ev.APIKey
	remainLen := 13 + len(devid) + len(apikey)
	remainBytes := encodeVarint(remainLen)
	total := 1 + len(remainBytes) + 2 + len(protocolName) + 1 + 1 + 2 + 2 + len(devid) + 2 + len(apikey)

	buf := make([]byte, total)
	off := 0
	buf[off] = 0x10; off++
	off += copy(buf[off:], remainBytes)
	writeU16BE(buf[off:], uint16(len(protocolName))); off += 2
	off += copy(buf[off:], protocolName)
	buf[off] = version; off++
	buf[off] = 0x40; off++
	writeU16BE(buf[off:], keepTime); off += 2
	writeU16BE(buf[off:], uint16(len(devid))); off += 2
	off += copy(buf[off:], devid)
	writeU16BE(buf[off:], uint16(len(apikey))); off += 2
	off += copy(buf[off:], apikey)
	return buf
}

func buildCONNRESP(rtn *int) []byte {
	code := byte(0)
	if rtn != nil {
		code = byte(*rtn)
	}
	return []byte{0x20, 0x02, 0x00, code}
}

func buildPINGREQ() []byte {
	return []byte{0xC0, 0x00}
}

func buildPINGRESP() []byte {
	return []byte{0xD0, 0x00}
}

func buildDISCONNECT() []byte {
	return []byte{0x40, 0x00}
}

func buildPUSHDATA(ev core.EDPEvent) []byte {
	data, _ := base64.StdEncoding.DecodeString(ev.DataB64)
	devid := ev.Devid
	remainLen := 2 + len(devid) + len(data)
	remainBytes := encodeVarint(remainLen)
	total := 1 + len(remainBytes) + 2 + len(devid) + len(data)

	buf := make([]byte, total)
	off := 0
	buf[off] = 0x30; off++
	off += copy(buf[off:], remainBytes)
	writeU16BE(buf[off:], uint16(len(devid))); off += 2
	off += copy(buf[off:], devid)
	off += copy(buf[off:], data)
	return buf
}

func buildSAVEDATA(ev core.EDPEvent) []byte {
	jsonBytes := []byte(ev.JSONStr)
	descBytes := []byte(ev.Desc)
	binBytes, _ := base64.StdEncoding.DecodeString(ev.BinB64)

	flags := computeFlags(ev.DevidFlag, ev.MsgIDFlag)

	// 体序（契约 §3.5）：消息标志 1B → [devid u16+str] → [msg_id u16] →
	// 数据格式标志 1B → 内容（type2 = desc u16 + desc + bin_len u32 + bin；
	// 其余 = 内容 u16 + json/str）。
	body := []byte{flags}
	if (flags & 0x80) != 0 {
		lb := []byte{0, 0}
		writeU16BE(lb, uint16(len(ev.Devid)))
		body = append(body, lb...)
		body = append(body, ev.Devid...)
	}
	if (flags & 0x40) != 0 {
		msgID := uint16(0)
		if ev.MsgID != nil {
			msgID = *ev.MsgID
		}
		mb := []byte{0, 0}
		writeU16BE(mb, msgID)
		body = append(body, mb...)
	}
	body = append(body, byte(ev.Format))

	switch ev.Format {
	case 0x02: // BIN type
		lb := []byte{0, 0}
		writeU16BE(lb, uint16(len(descBytes)))
		body = append(body, lb...)
		body = append(body, descBytes...)
		bb := []byte{0, 0, 0, 0}
		writeU32BE(bb, uint32(len(binBytes)))
		body = append(body, bb...)
		body = append(body, binBytes...)
	default: // JSON types 1/3/4/5
		lb := []byte{0, 0}
		writeU16BE(lb, uint16(len(jsonBytes)))
		body = append(body, lb...)
		body = append(body, jsonBytes...)
	}

	// remainlen = 消息体字节数（flags 起，不含类型字节与 remainlen 自身）。
	remainLen := len(body)
	remainBytes := encodeVarint(remainLen)
	total := 1 + len(remainBytes) + remainLen
	buf := make([]byte, total)
	off := 0
	buf[off] = 0x80; off++
	off += copy(buf[off:], remainBytes)
	off += copy(buf[off:], body)
	return buf
}

func computeFlags(devidFlag, msgidFlag int) byte {
	hasDev := devidFlag != 0
	hasMsg := msgidFlag != 0
	if hasDev && hasMsg {
		return 0xC0
	} else if hasDev {
		return 0x80
	} else if hasMsg {
		return 0x40
	}
	return 0x00
}

func buildSAVEACK(ev core.EDPEvent) []byte {
	msgID := uint16(0)
	if ev.MsgID != nil {
		msgID = *ev.MsgID
	}
	errCode := 0
	if ev.ErrCode != nil {
		errCode = *ev.ErrCode
	}
	ackJSON := fmt.Sprintf(`{"msg_id":%d,"err_code":%d}`, msgID, errCode)
	ackBytes := []byte(ackJSON)
	remainLen := 1 + 2 + len(ackBytes)
	remainBytes := encodeVarint(remainLen)
	total := 1 + len(remainBytes) + 1 + 2 + len(ackBytes)

	buf := make([]byte, total)
	off := 0
	buf[off] = 0x90; off++
	off += copy(buf[off:], remainBytes)
	buf[off] = 0x00; off++
	writeU16BE(buf[off:], uint16(len(ackBytes))); off += 2
	off += copy(buf[off:], ackBytes)
	return buf
}

func buildCMDREQ(ev core.EDPEvent) []byte {
	reqBytes, _ := base64.StdEncoding.DecodeString(ev.ReqB64)
	cmdid := []byte(ev.CmdID)
	remainLen := 2 + len(cmdid) + 4 + len(reqBytes)
	remainBytes := encodeVarint(remainLen)
	total := 1 + len(remainBytes) + 2 + len(cmdid) + 4 + len(reqBytes)

	buf := make([]byte, total)
	off := 0
	buf[off] = 0xA0; off++
	off += copy(buf[off:], remainBytes)
	writeU16BE(buf[off:], uint16(len(cmdid))); off += 2
	off += copy(buf[off:], cmdid)
	writeU32BE(buf[off:], uint32(len(reqBytes))); off += 4
	off += copy(buf[off:], reqBytes)
	return buf
}

func buildCMDRESP(ev core.EDPEvent) []byte {
	respData, _ := base64.StdEncoding.DecodeString(ev.RespB64)
	cmdidBytes := []byte(ev.CmdID)

	if len(respData) == 0 {
		remainLen := 2 + len(cmdidBytes)
		remainBytes := encodeVarint(remainLen)
		total := 1 + len(remainBytes) + remainLen
		buf := make([]byte, total)
		off := 0
		buf[off] = 0xB0; off++
		off += copy(buf[off:], remainBytes)
		writeU16BE(buf[off:], uint16(len(cmdidBytes))); off += 2
		off += copy(buf[off:], cmdidBytes)
		return buf
	}

	remainLen := 2 + len(cmdidBytes) + 4 + len(respData)
	remainBytes := encodeVarint(remainLen)
	total := 1 + len(remainBytes) + remainLen
	buf := make([]byte, total)
	off := 0
	buf[off] = 0xB0; off++
	off += copy(buf[off:], remainBytes)
	writeU16BE(buf[off:], uint16(len(cmdidBytes))); off += 2
	off += copy(buf[off:], cmdidBytes)
	writeU32BE(buf[off:], uint32(len(respData))); off += 4
	off += copy(buf[off:], respData)
	return buf
}

// --- Registration ---

func init() {
	layers.RegisterLayerGenerator("edp", func() (layers.LayerGenerator, error) {
		return &EDPGenerator{}, nil
	})
	layers.RegisterLayerValidator("edp", func(spec *core.FlowSpec) error {
		p := EDPPlanner{}
		return p.Validate(*spec)
	})
}

var _ layers.LayerGenerator = (*EDPGenerator)(nil)