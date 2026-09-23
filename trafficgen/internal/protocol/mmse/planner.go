// Package mmse planner: 配置校验 + 事务关联唯一解析权威（D-MMSE-1 裁定5/8）。
// sessionTx（buildTxBindings）按「会话序 × 事件序」单次遍历产出每事件的
// TID/MsgID/GET-URI 绑定——validator 关联校验与 layer_gen 渲染同函数同序
// （megaco sessionTxState / hl7 dynamic.go 先例），杜绝 validator 与生成器
// 漂移。wire_fault 55 值闭环：注入即拒 + 主锚词（契约 §7 表逐行同词）；
// 自然面守卫（40 值）与书面豁免（14 值）见 D-MMSE-1 处置表。
package mmse

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/trafficgen/trafficgen/internal/core"
)

// txBinding is one event's resolved binding（渲染与校验共用）。
type txBinding struct {
	TID       string // wire Transaction-ID（delivery_ind 恒 ""——表 7 无此字段）
	MsgID     string // wire Message-ID（无则为 ""）
	URI       string // retrieve GET 的请求 URI（自动派生③）
	PDUType   byte   // 0 = retrieve（无 PDU，纯 GET）
	IsRequest bool   // HTTP 请求侧（up）
	// ——validator 上下文（生成器不读）——
	pairTID         string // 配对对手 TID（send_conf/notifyresp/retrieve_conf/ack）
	orphanResp      bool   // 响应侧事件无配对对手
	tidMismatch     bool   // 显式 TID 与配对对手不一致
	msgidOutOfRange bool   // same_as_send_conf 引用越界
	msgidUnsourced  bool   // delivery/read-rec 显式 msgid 解析不到任何 send-conf
}

// sessTx is one session's allocation/pairing state（会话内推进——concurrent
// 交错不改变各会话内部事件序，绑定值与会话逐块回放完全一致）。
type sessTx struct {
	tidSeq, msgidSeq   int
	pendingReqTID      string // send_req 待配对
	pendingNotifTID    string // notification_ind 待配对
	pendingRetrieveTID string // retrieve 待配对（retrieve_conf 与 ack 共用）
}

// txState is the global correlation authority（walk 序：会话序 × 事件序）。
type txState struct {
	cfg             *core.MMSEConfig
	sess            []*sessTx
	sendConfMsgIDs  []string // 0 基序数 → send_conf 已分配 MsgID（跨会话回指注册表）
	lastNotifTID    string   // 全局最近通知 TID（立即取回复用，§6.3）
	lastNotifLoc    string   // 全局最近通知 Content-Location（GET URI 派生源）
	lastRetrieveTID string
}

func newTxState(cfg *core.MMSEConfig) *txState {
	st := &txState{cfg: cfg}
	for range cfg.Sessions {
		st.sess = append(st.sess, &sessTx{})
	}
	return st
}

// autoTID/autoMsgID render the deterministic auto forms（契约 §5 确定性——
// 无墙钟；validator 判重/关联与生成器渲染同源即此函数）。
func autoTID(n int) string   { return fmt.Sprintf("T%04d", n) }
func autoMsgID(n int) string { return fmt.Sprintf("M%04d", n) }

// resolveOne advances the state for one event and returns its binding.
// 调用方必须按（会话序 × 事件序）遍历——绑定值由遍历序唯一决定。
func (st *txState) resolveOne(si int, ev *core.MMSEEvent) (*txBinding, error) {
	s := st.sess[si]
	b := &txBinding{}
	sh, ok := kindShape[ev.Kind]
	if !ok {
		return nil, fmt.Errorf("unknown mmse event kind %q (message-type unknown)", ev.Kind)
	}
	b.PDUType, b.IsRequest = sh.pt, sh.isReq

	// —— Transaction-ID（取材规则，契约 §5）——
	switch ev.Kind {
	case "delivery_ind":
		// 无 Transaction-ID 字段（表 7）；配置值不落线。
	case "send_conf":
		exp := s.pendingReqTID
		b.pairTID = exp
		b.orphanResp = exp == ""
		if isExplicitID(ev.TransactionID) {
			b.TID = ev.TransactionID
			b.tidMismatch = exp != "" && ev.TransactionID != exp
		} else {
			b.TID = exp
		}
		s.pendingReqTID = ""
	case "notifyresp_ind":
		exp := s.pendingNotifTID
		b.pairTID = exp
		b.orphanResp = exp == ""
		if isExplicitID(ev.TransactionID) {
			b.TID = ev.TransactionID
			b.tidMismatch = exp != "" && ev.TransactionID != exp
		} else {
			b.TID = exp
		}
		s.pendingNotifTID = ""
	case "retrieve_conf":
		exp := s.pendingRetrieveTID
		b.pairTID = exp
		b.orphanResp = exp == ""
		if isExplicitID(ev.TransactionID) {
			b.TID = ev.TransactionID
			b.tidMismatch = exp != "" && ev.TransactionID != exp
		} else {
			b.TID = exp
		}
	case "acknowledge_ind":
		exp := s.pendingRetrieveTID
		b.pairTID = exp
		b.orphanResp = exp == ""
		if isExplicitID(ev.TransactionID) {
			b.TID = ev.TransactionID
			b.tidMismatch = exp != "" && ev.TransactionID != exp
		} else {
			b.TID = exp
		}
	case "retrieve":
		if isExplicitID(ev.TransactionID) {
			b.TID = ev.TransactionID
		} else if s.pendingNotifTID != "" {
			b.TID = s.pendingNotifTID // 立即取回复用本会话通知 TID（§6.3）
		} else if st.lastNotifTID != "" {
			b.TID = st.lastNotifTID // 跨会话立即取回（用例 #5：通知会话→取回会话）
		} else {
			s.tidSeq++
			b.TID = autoTID(s.tidSeq)
		}
		s.pendingRetrieveTID = b.TID
		st.lastRetrieveTID = b.TID
		// GET URI 自动派生③：最近通知的 content_location 路径 > 事件 uri > /mms。
		if st.lastNotifLoc != "" {
			if u, err := url.Parse(st.lastNotifLoc); err == nil && u.RequestURI() != "" {
				b.URI = u.RequestURI()
			}
		}
		if b.URI == "" {
			if ev.URI != "" {
				b.URI = ev.URI
			} else {
				b.URI = "/mms"
			}
		}
	default: // send_req / notification_ind：请求侧新事务
		if isExplicitID(ev.TransactionID) {
			b.TID = ev.TransactionID
		} else {
			s.tidSeq++
			b.TID = autoTID(s.tidSeq)
		}
		if ev.Kind == "notification_ind" {
			s.pendingNotifTID = b.TID
			st.lastNotifTID = b.TID
			st.lastNotifLoc = ev.ContentLocation
		} else {
			s.pendingReqTID = b.TID
		}
	}
	// —— Message-ID（send_conf 分配/注册；delivery/read-rec 回指）——
	switch ev.Kind {
	case "send_conf":
		if isExplicitID(ev.MessageID) && !strings.HasPrefix(ev.MessageID, "same_as_send_conf:") {
			b.MsgID = ev.MessageID
		} else if ev.MessageID != "" { // "auto" 或引用形都按分配处理
			s.msgidSeq++
			b.MsgID = autoMsgID(s.msgidSeq)
		}
		st.sendConfMsgIDs = append(st.sendConfMsgIDs, b.MsgID)
	case "retrieve_conf":
		if isExplicitID(ev.MessageID) && !strings.HasPrefix(ev.MessageID, "same_as_send_conf:") {
			b.MsgID = ev.MessageID
		} else if ev.MessageID != "" {
			s.msgidSeq++
			b.MsgID = autoMsgID(s.msgidSeq)
		}
	case "delivery_ind", "read_rec_ind":
		mid := ev.MessageID
		if strings.HasPrefix(mid, "same_as_send_conf:") {
			idx, err := strconv.Atoi(strings.TrimPrefix(mid, "same_as_send_conf:"))
			if err != nil || idx < 0 || idx >= len(st.sendConfMsgIDs) {
				b.msgidOutOfRange = true
			} else {
				b.MsgID = st.sendConfMsgIDs[idx]
				if b.MsgID == "" {
					b.msgidUnsourced = true // 被引用 send-conf 未分配 MsgID
				}
			}
		} else if mid != "" {
			b.MsgID = mid
			b.msgidUnsourced = !containsID(st.sendConfMsgIDs, mid)
		} else {
			b.msgidUnsourced = true // 必选 MsgID 缺失走 mandatory 守卫
		}
	}
	return b, nil
}

// isExplicitID reports whether the config value is a literal (not "auto"/"").
func isExplicitID(s string) bool { return s != "" && s != "auto" }

func containsID(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// kindShape maps event kinds to (PDU type, HTTP request side).
// retrieve 是纯 GET（无 PDU 体，PDUType 0）。
var kindShape = map[string]struct {
	pt    byte
	isReq bool
}{
	"send_req":         {pduSendReq, true},
	"send_conf":        {pduSendConf, false},
	"notification_ind": {pduNotifInd, true},
	"notifyresp_ind":   {pduNotifyRespInd, true},
	"retrieve":         {0, true},
	"retrieve_conf":    {pduRetrieveConf, false},
	"acknowledge_ind":  {pduAckInd, true},
	"delivery_ind":     {pduDeliveryInd, true},
	"read_rec_ind":     {pduReadRecInd, true},
}

// buildTxBindings walks（会话序 × 事件序）once and precomputes every event's
// binding——validator 与 layer_gen 的唯一解析权威（裁定5）。
func buildTxBindings(cfg *core.MMSEConfig) ([][]*txBinding, error) {
	st := newTxState(cfg)
	out := make([][]*txBinding, len(cfg.Sessions))
	for si := range cfg.Sessions {
		out[si] = make([]*txBinding, len(cfg.Sessions[si].Events))
		for ei := range cfg.Sessions[si].Events {
			b, err := st.resolveOne(si, &cfg.Sessions[si].Events[ei])
			if err != nil {
				return nil, fmt.Errorf("mmse session %d event %d: %w", si, ei, err)
			}
			out[si][ei] = b
		}
	}
	return out, nil
}

// Validate is the layer validator entry（RegisterLayerValidator）。
func Validate(spec core.FlowSpec) error {
	cfg := spec.MMSE
	if cfg == nil {
		return nil // 空配置默认流：P0b 基线
	}
	if err := checkWireFault(cfg.WireFault); err != nil {
		return err
	}
	if err := validateConfig(cfg); err != nil {
		return err
	}
	// 裁定3：WSP/WAP Push 端口与 http 载体矛盾（carrier_port 自然面）——
	// 链级 tcp 端口与会话级 DstPort 双面执法。
	if isWSPBearerPort(spec.DstPort) {
		return fmt.Errorf("mmse: carrier port %d contradicts the http bearer — WSP/WAP Push ports require the unregistered WSP boundary (port)", spec.DstPort)
	}
	for si := range cfg.Sessions {
		if p := cfg.Sessions[si].DstPort; isWSPBearerPort(p) {
			return fmt.Errorf("mmse session %d: carrier port %d contradicts the http bearer — WSP/WAP Push ports require the unregistered WSP boundary (port)", si, p)
		}
	}
	bindings, err := buildTxBindings(cfg)
	if err != nil {
		return err
	}
	for si := range cfg.Sessions {
		sess := &cfg.Sessions[si]
		for ei := range sess.Events {
			if err := validateEvent(cfg, sess, &sess.Events[ei], bindings[si][ei], si, ei); err != nil {
				return err
			}
		}
	}
	return nil
}

// isWSPBearerPort reports WSP/WAP Push well-known ports（9200/9201 连接态、
// 2948 push）——这些端口上的 MM1 属未注册 WSP 边界（契约 §1/裁定3）。
func isWSPBearerPort(p uint16) bool {
	return p == 9200 || p == 9201 || p == 2948
}

// validateConfig checks config-level keys（裁定2/3/8 自然面）。
func validateConfig(cfg *core.MMSEConfig) error {
	switch cfg.Profile {
	case "", "mmse_http_v1", "mmse_http_v6":
	default:
		return fmt.Errorf("mmse: profile %q is not defined — HTTP bearer profiles are mmse_http_v1/mmse_http_v6; the WSP bearer profile is an unregistered boundary (carrier)", cfg.Profile)
	}
	if cfg.MMSVersion != "" {
		if _, err := versionWire(cfg.MMSVersion); err != nil {
			return err
		}
		if cfg.MMSVersion != "1.0" && cfg.MMSVersion != "1.1" && cfg.MMSVersion != "1.2" && cfg.MMSVersion != "1.3" {
			return fmt.Errorf("mmse: mms_version %q is not produced by this version (1.0/1.1/1.2/1.3)", cfg.MMSVersion)
		}
	}
	return nil
}

// validateEvent runs the natural-face guards（40 守卫的落码位）+ wire_fault
// 事件级注入（覆盖 config 级）。
func validateEvent(cfg *core.MMSEConfig, sess *core.MMSESession, ev *core.MMSEEvent, b *txBinding, si, ei int) error {
	where := fmt.Sprintf("mmse session %d event %d (%s)", si, ei, ev.Kind)
	if ev.WireFault != "" {
		return checkWireFault(ev.WireFault)
	}
	// kindShape/未知 kind 在 buildTxBindings 已拒——此处只守卫各面。

	// 关联/顺序（sequence_* / tid_* / msgid_* 守卫——binding 上下文）。
	if b.orphanResp {
		switch ev.Kind {
		case "send_conf":
			return fmt.Errorf("%s: send_conf has no preceding send_req in session (sequence)", where)
		case "notifyresp_ind":
			return fmt.Errorf("%s: notifyresp_ind has no preceding notification_ind in session (sequence)", where)
		default: // retrieve_conf / acknowledge_ind
			return fmt.Errorf("%s: %s has no preceding retrieve in session (sequence)", where, ev.Kind)
		}
	}
	if b.tidMismatch {
		return fmt.Errorf("%s: explicit transaction-id %q does not match the paired transaction %q (transaction)", where, ev.TransactionID, b.pairTID)
	}
	if b.msgidOutOfRange {
		return fmt.Errorf("%s: message-id reference %q is out of range — no such send_conf ordinal (message-id)", where, ev.MessageID)
	}
	if b.msgidUnsourced && (ev.Kind == "delivery_ind" || ev.Kind == "read_rec_ind") {
		if ev.MessageID == "" {
			// 缺失由 mandatory 守卫报（下方）。
		} else {
			return fmt.Errorf("%s: message-id %q resolves to no send_conf allocation — broken back-reference (message-id)", where, ev.MessageID)
		}
	}
	if !b.IsRequest {
		// sequence_response_first：响应侧事件先于本会话任何请求（order）。
		if !sessHasRequestBefore(sess, ei) {
			return fmt.Errorf("%s: response-side event before any request in session (order)", where)
		}
	}

	// Transaction-ID 策略上界 32B（契约 §3.4/§8）。
	if len(ev.TransactionID) > 32 {
		return fmt.Errorf("%s: transaction-id is %d bytes — policy upper bound is 32 (transaction-id)", where, len(ev.TransactionID))
	}

	// 必选头（表 1–7）。
	if ev.Kind == "send_req" {
		if ev.From == nil {
			return fmt.Errorf("%s: mandatory header From missing on m-send-req (mandatory)", where)
		}
		if len(ev.To)+len(ev.Cc)+len(ev.Bcc) == 0 {
			return fmt.Errorf("%s: mandatory recipients missing on m-send-req — at least one of To/Cc/Bcc required (mandatory)", where)
		}
	}
	if ev.Kind == "notification_ind" {
		if ev.MessageClass == "" {
			return fmt.Errorf("%s: mandatory header Message-Class missing on m-notification-ind (mandatory)", where)
		}
		if ev.MessageSize == nil {
			return fmt.Errorf("%s: mandatory header Message-Size missing on m-notification-ind (mandatory)", where)
		}
		if ev.Expiry == nil {
			return fmt.Errorf("%s: mandatory header Expiry missing on m-notification-ind (mandatory)", where)
		}
		if ev.ContentLocation == "" {
			return fmt.Errorf("%s: mandatory header Content-Location missing on m-notification-ind (mandatory)", where)
		}
		if ev.Expiry.Absolute != nil {
			return fmt.Errorf("%s: notification Expiry must use the interval (relative) form — absolute is not permitted by Table 3 (expiry)", where)
		}
	}
	if ev.Kind == "send_conf" && ev.ResponseStatus == "" {
		return fmt.Errorf("%s: mandatory header Response-Status missing on m-send-conf (response-status)", where)
	}
	if ev.Kind == "delivery_ind" {
		if ev.MessageID == "" {
			return fmt.Errorf("%s: mandatory header Message-ID missing on m-delivery-ind (mandatory)", where)
		}
		if len(ev.To) == 0 {
			return fmt.Errorf("%s: mandatory header To missing on m-delivery-ind (mandatory)", where)
		}
		if ev.Date == nil {
			return fmt.Errorf("%s: mandatory header Date missing on m-delivery-ind (mandatory)", where)
		}
		if ev.Status == "" {
			return fmt.Errorf("%s: mandatory header Status missing on m-delivery-ind (mandatory)", where)
		}
	}
	if ev.Kind == "read_rec_ind" && ev.MessageID == "" {
		return fmt.Errorf("%s: mandatory header Message-ID missing on m-read-rec-ind (message-id)", where)
	}
	if ev.Kind == "notifyresp_ind" && ev.Status == "" {
		return fmt.Errorf("%s: mandatory header Status missing on m-notifyresp-ind (status)", where)
	}

	// 无体 PDU 声明 content（body_on_bodyless 自然面）。
	if ev.Content != nil && b.PDUType != pduSendReq && b.PDUType != pduRetrieveConf {
		return fmt.Errorf("%s: body declared on a bodyless PDU — message body is only defined for send-req/retrieve-conf (body)", where)
	}

	// 越表头拒（契约 §3.5 表 1–7：每 PDU 的字段集固定——send-req 才有
	// Priority、send-conf 才有 Response-Status 等；配置声明越表头即显式
	// 拒，不静默丢键、不静默落线）。
	if b.PDUType != 0 {
		for _, f := range eventFieldCodes(ev) {
			if !pduFieldAllowance[b.PDUType][f] {
				return fmt.Errorf("%s: header field code 0x%02x is not permitted on this PDU type (Table 1-7 field sets)", where, f)
			}
		}
	}

	// 值域（value_* 守卫）。
	if ev.MessageClass != "" && enumClass[ev.MessageClass] == 0 {
		return fmt.Errorf("%s: message-class %q is outside the value domain (message-class)", where, ev.MessageClass)
	}
	if ev.Priority != "" && enumPriority[ev.Priority] == 0 {
		return fmt.Errorf("%s: priority %q is outside the value domain (priority)", where, ev.Priority)
	}
	if ev.Status != "" && enumStatus[ev.Status] == 0 {
		return fmt.Errorf("%s: status %q is outside the value domain (status)", where, ev.Status)
	}
	if ev.ReadStatus != "" && enumReadStatus[ev.ReadStatus] == 0 {
		return fmt.Errorf("%s: read-status %q is outside the value domain (read-status)", where, ev.ReadStatus)
	}
	if ev.ResponseStatus != "" && enumResponseStatus[ev.ResponseStatus] == 0 {
		return fmt.Errorf("%s: response-status %q is outside the value domain (response-status)", where, ev.ResponseStatus)
	}
	if ev.SenderVisibility != "" && enumVisibility[ev.SenderVisibility] == 0 {
		return fmt.Errorf("%s: sender-visibility %q is outside the value domain", where, ev.SenderVisibility)
	}
	if ev.Subject != nil {
		if ev.Subject.Text == "" {
			return fmt.Errorf("%s: empty Text-string subject — the empty-string form is not produced by this version (text-string)", where)
		}
		if ev.Subject.Charset != 0 && ev.Subject.Charset != 106 {
			return fmt.Errorf("%s: charset %d is not produced by this version (only 106 UTF-8) (charset)", where, ev.Subject.Charset)
		}
	}

	// 长度面（length_* 守卫）。
	if ev.Date != nil && (*ev.Date < 0 || uint64(*ev.Date) > 0xFFFFFFFF) {
		return fmt.Errorf("%s: date %d exceeds the 4-byte Long-integer range (long-integer)", where, *ev.Date)
	}
	checkTime := func(t *core.MMSETime, name string) error {
		if t == nil {
			return nil
		}
		if t.Absolute != nil && (*t.Absolute < 0 || uint64(*t.Absolute) > 0xFFFFFFFF) {
			return fmt.Errorf("%s: %s absolute %d exceeds the 4-byte Long-integer range (long-integer)", where, name, *t.Absolute)
		}
		if t.Relative != nil && *t.Relative > 0xFFFFFF {
			return fmt.Errorf("%s: %s relative %d exceeds the 3-byte Delta-seconds range (long-integer)", where, name, *t.Relative)
		}
		return nil
	}
	if err := checkTime(ev.Expiry, "expiry"); err != nil {
		return err
	}
	if err := checkTime(ev.DeliveryTime, "delivery-time"); err != nil {
		return err
	}
	if ev.MessageSize != nil && *ev.MessageSize > 0xFFFFFF {
		return fmt.Errorf("%s: message-size %d exceeds the 3-byte Long-integer range (long-integer)", where, *ev.MessageSize)
	}

	// multipart 不变式（裁定7）。
	if ev.Content != nil {
		switch ev.Content.Kind {
		case "", "multipart_related":
		default:
			return fmt.Errorf("%s: content kind %q is not produced by this version — multipart/related only (multipart)", where, ev.Content.Kind)
		}
		if len(ev.Content.Parts) == 0 {
			return fmt.Errorf("%s: multipart content declared with zero parts (part)", where)
		}
		if len(ev.Content.Parts) > 127 {
			return fmt.Errorf("%s: multipart part count %d exceeds the 127-part upper bound (overflow)", where, len(ev.Content.Parts))
		}
		if ev.Content.Start != "" {
			found := false
			for i := range ev.Content.Parts {
				if ev.Content.Parts[i].ContentID == ev.Content.Start {
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("%s: start parameter %q references no part Content-ID (start)", where, ev.Content.Start)
			}
		}
		for i := range ev.Content.Parts {
			p := &ev.Content.Parts[i]
			if p.Charset != 0 && p.Charset != 106 {
				return fmt.Errorf("%s: part %d charset %d is not produced by this version (only 106 UTF-8) (charset)", where, i, p.Charset)
			}
		}
	}

	// HTTP 覆盖偏离守卫（carrier_content_type / length_content_length）。
	pdu, err := buildPDU(cfg, ev, b)
	if err != nil {
		return fmt.Errorf("%s: %w", where, err)
	}
	if hdrs := ev.HTTP; hdrs != nil {
		if v, ok := hdrs["Content-Type"]; ok && v != mmsContentType {
			return fmt.Errorf("%s: carrier Content-Type override %q — MMSE PDUs ride application/vnd.wap.mms-message only (content-type)", where, v)
		}
		if v, ok := hdrs["Content-Length"]; ok && v != strconv.Itoa(len(pdu)) {
			return fmt.Errorf("%s: Content-Length override %q does not match the encoded PDU size %d (length)", where, v, len(pdu))
		}
	}
	return nil
}

// eventFieldCodes lists the optional/mandatory header codes an event declares
// （与 buildPDU 渲染序一致；首三头与 Content-Type 恒定不入列）。
func eventFieldCodes(ev *core.MMSEEvent) []byte {
	var codes []byte
	if ev.Date != nil {
		codes = append(codes, fDate)
	}
	if ev.From != nil {
		codes = append(codes, fFrom)
	}
	if len(ev.To) > 0 {
		codes = append(codes, fTo)
	}
	if len(ev.Cc) > 0 {
		codes = append(codes, fCc)
	}
	if len(ev.Bcc) > 0 {
		codes = append(codes, fBcc)
	}
	if ev.Subject != nil {
		codes = append(codes, fSubject)
	}
	if ev.MessageID != "" {
		codes = append(codes, fMessageID)
	}
	if ev.MessageClass != "" {
		codes = append(codes, fMessageClass)
	}
	if ev.Expiry != nil {
		codes = append(codes, fExpiry)
	}
	if ev.DeliveryTime != nil {
		codes = append(codes, fDeliveryTime)
	}
	if ev.Priority != "" {
		codes = append(codes, fPriority)
	}
	if ev.SenderVisibility != "" {
		codes = append(codes, fSenderVisibility)
	}
	if ev.DeliveryReport != nil {
		codes = append(codes, fDeliveryReport)
	}
	if ev.ReadReply != nil {
		codes = append(codes, fReadReply)
	}
	if ev.ReportAllowed != nil {
		codes = append(codes, fReportAllowed)
	}
	if ev.ResponseStatus != "" {
		codes = append(codes, fResponseStatus)
	}
	if ev.ResponseText != "" {
		codes = append(codes, fResponseText)
	}
	if ev.MessageSize != nil {
		codes = append(codes, fMessageSize)
	}
	if ev.ContentLocation != "" {
		codes = append(codes, fContentLocation)
	}
	if ev.Status != "" {
		codes = append(codes, fStatus)
	}
	if ev.ReadStatus != "" {
		codes = append(codes, fReadStatus)
	}
	return codes
}

// sessHasRequestBefore reports whether the session declared any request-side
// event before index ei（sequence_response_first 守卫的状态查询）。
func sessHasRequestBefore(sess *core.MMSESession, ei int) bool {
	for i := 0; i < ei; i++ {
		if sh, ok := kindShape[sess.Events[i].Kind]; ok && sh.isReq {
			return true
		}
	}
	return false
}

// wireFaults is the 55-value closed enumeration（契约 §6/§7/用例 §5 三方同
// 序同词）→ (说明, 主锚词)。注入即拒、不落线。
var wireFaults = map[string]struct{ detail, anchor string }{
	"carrier_no_http":             {"mmse chain requires the http carrier layer; tcp→mmse direct chain rejected", "layer"},
	"carrier_content_type":        {"carrier Content-Type is not application/vnd.wap.mms-message", "content-type"},
	"carrier_port":                {"carrier port contradicts the http bearer — WSP/WAP Push ports (9200/9201/2948) require the unregistered WSP boundary", "port"},
	"carrier_profile":             {"profile is undefined or a WSP-boundary profile — HTTP bearer profiles only", "carrier"},
	"head_order_tid_first":        {"header order violation — Message-Type/Transaction-ID/MMS-Version must lead in that order", "order"},
	"head_order_version_missing":  {"header order violation — MMS-Version is mandatory among the first three headers", "header"},
	"head_first_not_8c":           {"first header field code is not 0x8C (Message-Type)", "message-type"},
	"pdu_type_unassigned":         {"message-type value is unassigned", "unknown"},
	"pdu_type_unsupported":        {"message-type value is assigned but not produced by this version (MMS 1.1+ extension PDUs)", "message-type"},
	"content_type_missing":        {"content-type header missing on a body PDU — Content-Type must be the last header", "content-type"},
	"body_on_bodyless":            {"message body declared on a bodyless PDU", "body"},
	"mandatory_from":              {"mandatory header From missing on m-send-req", "mandatory"},
	"mandatory_recipients":        {"mandatory recipients missing on m-send-req — at least one of To/Cc/Bcc required", "mandatory"},
	"mandatory_notif_class":       {"mandatory header Message-Class missing on m-notification-ind", "mandatory"},
	"mandatory_notif_size":        {"mandatory header Message-Size missing on m-notification-ind", "mandatory"},
	"mandatory_notif_expiry":      {"mandatory header Expiry missing on m-notification-ind", "mandatory"},
	"mandatory_notif_location":    {"mandatory header Content-Location missing on m-notification-ind", "mandatory"},
	"mandatory_response_status":   {"mandatory header Response-Status missing on m-send-conf", "response-status"},
	"mandatory_delivery_msgid":    {"mandatory header Message-ID missing on m-delivery-ind", "mandatory"},
	"mandatory_delivery_to":       {"mandatory header To missing on m-delivery-ind", "mandatory"},
	"mandatory_delivery_date":     {"mandatory header Date missing on m-delivery-ind", "mandatory"},
	"mandatory_delivery_status":   {"mandatory header Status missing on m-delivery-ind", "mandatory"},
	"multipart_headers_len":       {"multipart part headersLen is out of bounds", "multipart"},
	"multipart_data_len":          {"multipart part dataLen is out of bounds", "data"},
	"multipart_partnum_zero":      {"multipart partNum is zero while parts are declared", "part"},
	"multipart_partnum_mismatch":  {"multipart partNum does not match the declared part count", "part"},
	"multipart_start_dangling":    {"start parameter references no part Content-ID", "start"},
	"multipart_partnum_over":      {"multipart partNum exceeds the 127-part upper bound", "overflow"},
	"tid_send_conf":               {"send_conf Transaction-ID does not match the request side", "transaction"},
	"tid_notifyresp":              {"notifyresp Transaction-ID does not match the notification", "transaction"},
	"tid_acknowledge":             {"acknowledge Transaction-ID does not match the previous retrieve", "transaction"},
	"msgid_delivery":              {"delivery_ind Message-ID resolves to no send_conf allocation", "message-id"},
	"msgid_read_rec":              {"read_rec_ind Message-ID resolves to no send_conf allocation", "message-id"},
	"sequence_ack_first":          {"acknowledge precedes its retrieve", "sequence"},
	"sequence_notifyresp_orphan":  {"notifyresp has no preceding notification", "sequence"},
	"sequence_conf_orphan":        {"send_conf has no preceding send_req", "sequence"},
	"sequence_response_first":     {"response-side event precedes the session's first request", "order"},
	"length_content_length":       {"Content-Length does not match the encoded PDU size", "length"},
	"length_long_int_over":        {"Long-integer length byte exceeds the 4-byte generator range", "long-integer"},
	"length_long_int_zero":        {"Long-integer length byte is zero", "long-integer"},
	"length_uintvar_over":         {"Uintvar payload exceeds the 4-byte range", "uintvar"},
	"length_value_length":         {"Value-length does not match the actual value size", "value-length"},
	"length_tid_over":             {"transaction-id exceeds the 32-byte policy upper bound", "transaction-id"},
	"value_priority":              {"priority value is outside the domain", "priority"},
	"value_status":                {"status value is outside the domain", "status"},
	"value_message_class":         {"message-class value is outside the domain", "message-class"},
	"value_response_status":       {"response-status value is outside the domain (1.1+ segments not produced)", "response-status"},
	"value_read_status":           {"read-status value is outside the domain", "read-status"},
	"value_yesno":                 {"yes/no field value is outside the domain (0x80/0x81 only)", "delivery-report"},
	"value_reply_charging":        {"reply-charging field family is not produced by this version", "reply-charging"},
	"value_empty_string":          {"empty Text-string is not produced by this version", "text-string"},
	"value_application_header":    {"application-header extension is not produced by this version", "application-header"},
	"value_charset":               {"charset is not produced by this version (only 106 UTF-8)", "charset"},
	"value_previously_sent":       {"previously-sent header family is not produced by this version", "previously-sent"},
	"value_notif_expiry_absolute": {"notification Expiry uses the absolute form — Table 3 permits interval only", "expiry"},
}

// checkWireFault rejects an injected fault with the contract anchor.
func checkWireFault(fault string) error {
	if fault == "" {
		return nil
	}
	d, ok := wireFaults[fault]
	if !ok {
		return fmt.Errorf("mmse wire_fault %q: not a known negative-path kind (unknown)", fault)
	}
	return fmt.Errorf("mmse wire_fault %q: %s (%s)", fault, d.detail, d.anchor)
}
