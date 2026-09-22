// Package hl7 layer generator: walks sessions (concurrent = round-robin per
// event index, like gbt/cwmp; sequential = session by session) and emits two
// MessageEvents per HL7 transaction — the MLLP-framed request (up) and the
// auto-derived ACK frame (down). The tcp layer owns segmentation, handshake,
// and teardown; this generator only emits the complete MLLP-payload byte
// stream per event (SOB 0x0B + HL7 segments + EOB 0x1C 0x0D).
package hl7

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// HL7Generator is the hl7 terminal-layer generator.
type HL7Generator struct{}

func (g *HL7Generator) Name() string { return "hl7" }

// sessionRun is the per-session generation state.
type sessionRun struct {
	idx     int
	sess    core.HL7Session
	ctrlSeq int64
	ackSeq  int64
}

// msgDefaults pins the fixture MSH-3..6 values (testcase §4: 请求侧
// MSH-3=HIS/MSH-4=GH/MSH-5=RIS/MSH-6=GH——69 字节 MSH 段的偏移基线)。
type msgDefaults struct {
	sendingApp, sendingFac, receivingApp, receivingFac string
}

var defaultMSH = msgDefaults{sendingApp: "HIS", sendingFac: "GH", receivingApp: "RIS", receivingFac: "GH"}

func (g *HL7Generator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req.EmitMsg == nil {
		return fmt.Errorf("hl7 generator: EmitMsg is nil (generator not wired to a transport layer)")
	}
	cfg := req.Meta.HL7
	if cfg == nil {
		cfg = &core.HL7Config{}
	}
	sessions := cfg.Sessions
	if len(sessions) == 0 {
		// 空配置默认流（P0b）：基线单事务——ADT^A01 sender 端 → AA ACK。
		// TCP 9 包（3 握手 + 2 帧 + 4 挥手）。
		sessions = []core.HL7Session{{
			Role:         "sender",
			ProcessingID: "P",
			Events: []core.HL7Event{{
				Kind:        "msg",
				Direction:   "c2s",
				MessageType: "ADT^A01^ADT_A01",
				Segments: []core.HL7Segment{
					{Name: "EVN", Fields: []interface{}{"A01"}},
					{Name: "PID", Fields: []interface{}{"1", "", "PAT001^^^HOSP^MR", "", "DOE^JOHN^A", "", "19800101", "M"}},
					{Name: "PV1", Fields: []interface{}{"1", "I", "WARD^ICU^B101"}},
				},
				Ack: "auto",
			}},
		}}
	}

	dstIP := req.Meta.DstIP

	// D-HL7-1 裁定3：会话 dst_port 缺省继承链级端口（FieldContract 2575
	// 或用户显式非默认端口）——不在此硬编码 2575（port_nondefault 例实证
	// 硬编码压过链级 2675）。事件 DstPort=0 → tcp 层走链级默认。
	runs := make([]*sessionRun, len(sessions))
	for i := range sessions {
		runs[i] = &sessionRun{idx: i, sess: sessions[i]}
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
				// 并发模式逐事件独立发射（不粘连）：会话按事件索引交错，
				// 跨会话的字节流不属同一连接，合并语义不适用。
				if err := emitSessionEvent(cfg, r, r.sess.Events[j], dstIP, emit); err != nil {
					return err
				}
			}
		}
		return nil
	}
	for _, r := range runs {
		if err := emitSessionEventsCoalesced(cfg, r, dstIP, emit); err != nil {
			return err
		}
	}
	return nil
}

// emitSessionEventsCoalesced replays one session's events with MLLP burst
// coalescing (设计 §2/§8 多帧粘连)：consecutive no-ACK events in the same
// direction are concatenated into ONE MessageEvent so the tcp layer sends
// them in a single segment (testcase #61：3 帧 ack=null → 8 包 = 3+1+4)。
// An ACK-bearing event always flushes the pending run first (its request
// must precede the derived ACK frame), and the ACK itself is its own event.
func emitSessionEventsCoalesced(cfg *core.HL7Config, r *sessionRun, dstIP string, emit func(layers.MessageEvent) error) error {
	sess := r.sess
	var run []byte
	runUp := false
	haveRun := false
	flush := func() error {
		if !haveRun {
			return nil
		}
		if err := emit(layers.MessageEvent{
			Up:      runUp,
			Bytes:   run,
			DstIP:   dstIP,
			DstPort: sess.DstPort,
			SrcPort: sess.SrcPort,
		}); err != nil {
			return err
		}
		run, haveRun = nil, false
		return nil
	}
	for _, ev := range sess.Events {
		frame, dirUp, wantsAck, ctrlID := renderEvent(cfg, sess, r, ev)
		if !wantsAck && haveRun && runUp == dirUp {
			run = append(run, frame...) // coalesce into the pending segment
		} else {
			if err := flush(); err != nil {
				return err
			}
			run = append([]byte{}, frame...)
			runUp, haveRun = dirUp, true
		}
		if wantsAck {
			if err := flush(); err != nil {
				return err
			}
			ackFrame := renderACK(cfg, sess, r, ev, ctrlID)
			if err := emit(layers.MessageEvent{
				Up:      !dirUp,
				Bytes:   ackFrame,
				DstIP:   dstIP,
				DstPort: sess.DstPort,
				SrcPort: sess.SrcPort,
			}); err != nil {
				return err
			}
		}
	}
	return flush()
}

// resolveAckSpec returns the effective ack spec for one event:
// ev.Ack > sess.AckMode > cfg.AckMode > "auto" (设计 §6：消息级覆盖会话级)。
func resolveAckSpec(cfg *core.HL7Config, sess core.HL7Session, ev core.HL7Event) string {
	if ev.Ack != "" {
		return ev.Ack
	}
	if sess.AckMode != "" {
		return sess.AckMode
	}
	if cfg.AckMode != "" {
		return cfg.AckMode
	}
	return "auto"
}

// renderEvent builds one event's request frame; returns (frame, direction-is-up,
// wants-ack, resolved-MSH-10). The ack spec may be "auto"/"null"/a code, or the
// JSON object form {"code":"AE","err_segments":[...]} (设计 §6 ack 键).
func renderEvent(cfg *core.HL7Config, sess core.HL7Session, r *sessionRun, ev core.HL7Event) (frame []byte, up, wantsAck bool, ctrlID string) {
	fs, ec, version, processingID := resolveSeparators(cfg, sess, ev)
	ctrlID = resolveControlID(r, ev)
	segments := buildSegments(cfg, sess, ev, ctrlID, fs, ec, version, processingID)
	frame = buildMLLPFrame(segments)
	up = ev.Direction != "s2c"
	wantsAck = resolveAckSpec(cfg, sess, ev) != "null"
	return frame, up, wantsAck, ctrlID
}

// renderACK builds the derived ACK frame for one event (设计 §5.2 逐条：
// 方向反转、MSH-1/2 同请求、MSH-3/4↔5/6 对调、新运行期 ts、MSH-9=ACK^触发^ACK、
// 会话内递增的新 MSH-10、MSH-11/12 同请求、MSA-1=确认码、MSA-2=请求 MSH-10、
// MSA-3=可选文本、配置 err_segments 追加)。reqCtrlID 是请求帧实际使用的
// MSH-10（由 renderEvent 解析——在此重算会二次推进自增序号）。
func renderACK(cfg *core.HL7Config, sess core.HL7Session, r *sessionRun, ev core.HL7Event, reqCtrlID string) []byte {
	fs, ec, version, processingID := resolveSeparators(cfg, sess, ev)
	ackSpec := resolveAckSpec(cfg, sess, ev)
	ackCode, _ := parseAckSpec(ackSpec)
	if ackCode == "" || ackCode == "auto" {
		ackCode = "AA"
	}
	ackCtrlID := nextAckID(r)
	ackSegments := buildACKSegments(cfg, sess, ev, reqCtrlID, ackCtrlID, ackCode, fs, ec, version, processingID)
	for _, seg := range ev.ErrSegments {
		ackSegments = append(ackSegments, buildSegment(fs, seg))
	}
	return buildMLLPFrame(ackSegments)
}

// parseAckSpec splits an ack spec into (code, errSegments): "auto"/"null"/
// "AA"/"AE"/"AR" or the object form {"code":"AE","err_segments":[...]}.
func parseAckSpec(spec string) (string, []core.HL7Segment) {
	if strings.HasPrefix(spec, "{") {
		var obj struct {
			Code        string            `json:"code"`
			ErrSegments []core.HL7Segment `json:"err_segments"`
		}
		if err := json.Unmarshal([]byte(spec), &obj); err == nil {
			return obj.Code, obj.ErrSegments
		}
	}
	return spec, nil
}

// resolveSeparators resolves fs/ec/version/processingID for one event
// (event > session > config > built-in default).
func resolveSeparators(cfg *core.HL7Config, sess core.HL7Session, ev core.HL7Event) (fs, ec, version, processingID string) {
	fs = cfg.FieldSeparator
	if fs == "" {
		fs = "|"
	}
	if ev.FieldSeparator != "" {
		fs = ev.FieldSeparator
	}
	ec = cfg.EncodingChars
	if ec == "" {
		ec = "^~\\&"
	}
	if ev.EncodingChars != "" {
		ec = ev.EncodingChars
	}
	version = cfg.Version
	if version == "" {
		version = "2.5"
	}
	if ev.Version != "" {
		version = ev.Version
	}
	processingID = sess.ProcessingID
	if processingID == "" {
		processingID = "P"
	}
	if ev.ProcessingID != "" {
		processingID = ev.ProcessingID
	}
	return fs, ec, version, processingID
}

// resolveControlID returns the event's MSH-10 (explicit pin or the session's
// MSG%04d increment).
func resolveControlID(r *sessionRun, ev core.HL7Event) string {
	if ev.ControlID != "" {
		return ev.ControlID
	}
	return nextCtrlID(r)
}

// emitSessionEvent renders one HL7 transaction: the MLLP-framed request
// (up) and the auto-derived ACK frame (down). Kept for the concurrent path
// where events are emitted one by one (no coalescing across sessions).
func emitSessionEvent(cfg *core.HL7Config, r *sessionRun, ev core.HL7Event, dstIP string, emit func(layers.MessageEvent) error) error {
	frame, up, wantsAck, ctrlID := renderEvent(cfg, r.sess, r, ev)
	if err := emit(layers.MessageEvent{
		Up:      up,
		Bytes:   frame,
		DstIP:   dstIP,
		DstPort: r.sess.DstPort,
		SrcPort: r.sess.SrcPort,
	}); err != nil {
		return err
	}
	if !wantsAck {
		return nil
	}
	ackFrame := renderACK(cfg, r.sess, r, ev, ctrlID)
	return emit(layers.MessageEvent{
		Up:      !up,
		Bytes:   ackFrame,
		DstIP:   dstIP,
		DstPort: r.sess.DstPort,
		SrcPort: r.sess.SrcPort,
	})
}

func nextCtrlID(r *sessionRun) string {
	if r.ctrlSeq == 0 {
		r.ctrlSeq = 1
	}
	id := fmt.Sprintf("MSG%04d", r.ctrlSeq)
	r.ctrlSeq++
	return id
}

// nextAckID returns the session-scoped incrementing ACK control ID
// (设计 §6 Validate："控制 ID 空间会话内唯一" — ACK MSH-10 也不得跨事务复用).
func nextAckID(r *sessionRun) string {
	if r.ackSeq == 0 {
		r.ackSeq = 1
	}
	id := fmt.Sprintf("ACK%04d", r.ackSeq)
	r.ackSeq++
	return id
}

func buildSegments(cfg *core.HL7Config, sess core.HL7Session, ev core.HL7Event, ctrlID, fs, ec, version, processingID string) []string {
	msgType := ev.MessageType
	if msgType == "" {
		msgType = "ADT^A01^ADT_A01"
	}

	var segs []string
	segs = append(segs, buildMSHSegment(cfg, sess, ev, msgType, ctrlID, fs, ec, version, processingID))

	for _, s := range ev.Segments {
		segs = append(segs, buildSegment(fs, s))
	}

	return segs
}

func buildMSHSegment(cfg *core.HL7Config, sess core.HL7Session, ev core.HL7Event, msgType, ctrlID, fs, ec, version, processingID string) string {
	ts := ev.Timestamp
	if ts == "" {
		ts = time.Now().UTC().Format("20060102150405")
	}
	sendingApp := sess.SendingApp
	sendingFac := sess.SendingFac
	receivingApp := sess.ReceivingApp
	receivingFac := sess.ReceivingFac
	if sendingApp == "" {
		sendingApp = defaultMSH.sendingApp
	}
	if sendingFac == "" {
		sendingFac = defaultMSH.sendingFac
	}
	if receivingApp == "" {
		receivingApp = defaultMSH.receivingApp
	}
	if receivingFac == "" {
		receivingFac = defaultMSH.receivingFac
	}

	fields := []string{
		"MSH" + fs + ec,
		sendingApp,
		sendingFac,
		receivingApp,
		receivingFac,
		ts,
		ev.MSH8Security,
		msgType,
		ctrlID,
		processingID,
		version,
	}

	return strings.Join(fields, fs) + "\r"
}

func buildACKSegments(cfg *core.HL7Config, sess core.HL7Session, ev core.HL7Event, reqCtrlID, ackCtrlID, ackCode, fs, ec, version, processingID string) []string {
	triggerEvent := "A01"
	if ev.MessageType != "" {
		parts := strings.Split(ev.MessageType, "^")
		if len(parts) >= 2 {
			triggerEvent = parts[1]
		}
	}

	ackMsgType := "ACK^" + triggerEvent + "^ACK"

	ackSess := sess
	ackSess.SendingApp = strOr(sess.ReceivingApp, defaultMSH.receivingApp)
	ackSess.SendingFac = strOr(sess.ReceivingFac, defaultMSH.receivingFac)
	ackSess.ReceivingApp = strOr(sess.SendingApp, defaultMSH.sendingApp)
	ackSess.ReceivingFac = strOr(sess.SendingFac, defaultMSH.sendingFac)

	msh := buildMSHSegment(cfg, ackSess, core.HL7Event{}, ackMsgType, ackCtrlID, fs, ec, version, processingID)
	// MSA-3（可选文本）必须在段内 CR 之前——段终止符之后追加会拆出
	// 非法空段（review 捕获：曾产出 "MSA|AE|MSG0001|\r|OK"）。
	msa := "MSA" + fs + ackCode + fs + reqCtrlID + fs + ev.MSA3Text + "\r"

	return []string{msh, msa}
}

func strOr(v, fallback string) string {
	if v != "" {
		return v
	}
	return fallback
}

func buildSegment(fs string, seg core.HL7Segment) string {
	var fieldStrs []string
	for _, f := range seg.Fields {
		fieldStrs = append(fieldStrs, renderFieldValue(f, fs))
	}
	return seg.Name + fs + strings.Join(fieldStrs, fs) + "\r"
}

func renderFieldValue(val interface{}, fs string) string {
	if val == nil {
		return ""
	}
	switch v := val.(type) {
	case string:
		return v
	case []interface{}:
		var parts []string
		for _, p := range v {
			parts = append(parts, renderFieldValue(p, fs))
		}
		return strings.Join(parts, "^")
	default:
		return fmt.Sprintf("%v", v)
	}
}

func buildMLLPFrame(segments []string) []byte {
	var data []byte
	for _, seg := range segments {
		data = append(data, seg...)
	}
	frame := make([]byte, 0, len(data)+3)
	frame = append(frame, 0x0B)
	frame = append(frame, data...)
	frame = append(frame, 0x1C, 0x0D)
	return frame
}

// GenEvents marks this generator as a message event producer.
func (g *HL7Generator) GenEvents() layers.EventGenerator { return g }

// EmitEvent is the EventGenerator interface method, present only to satisfy
// the producer marker. Events flow through GenRequest.EmitMsg only.
func (g *HL7Generator) EmitEvent(ev layers.MessageEvent) error {
	return fmt.Errorf("hl7 generator: EmitEvent is not wired; events flow through GenRequest.EmitMsg only")
}

// init registers the hl7 generator and validator with the layer registry.
func init() {
	layers.RegisterLayerGenerator("hl7", func() (layers.LayerGenerator, error) {
		return &HL7Generator{}, nil
	})
	layers.RegisterLayerValidator("hl7", func(spec *core.FlowSpec) error {
		return Validate(*spec)
	})
}
