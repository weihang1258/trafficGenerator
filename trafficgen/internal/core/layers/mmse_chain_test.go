package layers_test

// D-MMSE-1 P4 链级红例（hl7_chain_test.go 23 例/megaco 21 例先例同构）：
// ①顶层 mmse 子映射 presence 判死；②层 config 翻译落线（钉非缺省可辨识值
// ——megaco F7 教训前置）；③registry 五键 V9 allowlist；④空层基线包数
// （3 握手 + POST + 200 + 3 挥手）；⑤HTTP 帧字节钉（POST 行/Content-Type/
// Content-Length 自洽 + PDU 首三头 8c 80 98 + 恒无 Connection 头）；⑥载体
// （缺 http 自然面拒 + wire_fault carrier_no_http 注入锚 layer + udp 载体
// transport 拒）；⑦wire_fault 55 值闭环锚词（契约 §7 同词）；⑧TID 配对
// （显式错配拒 + auto 落线同值）；⑨MsgID 回指（same_as_send_conf:0 落线
// 同值 + 孤儿字面拒）；⑩顺序状态机四拒；⑪multipart 门（start dangling/
// 恰 127/128 越界/零 parts）；⑫值域族域外拒；⑬通知必选集四缺 + expiry
// 绝对形态拒；⑭未知键严格拒（裁定8 DisallowUnknownFields）；⑮sessionTx
// 唯一权威硬证明（auto 计数器线上序列 vs 独立复算全等——megaco/hl7
// round-2 同法）；⑯carrier_content_type；⑰carrier_port；⑱TID 32B/33B
// 边界；⑲body_on_bodyless；⑳concurrent 双会话；㉑Content-Length parity；
// ㉓PDU 字段集越表头拒；
// ㉒GET URI 自动派生③；㉓越表头即拒（表 1–7 字段集）。

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	_ "github.com/trafficgen/trafficgen/internal/protocol/mmse" // init 注册 mmse 终结层生成器+校验器
)

// ——形状辅助（压平嵌套，杜绝复合字面量括号地狱）——

func mmseChain(t *testing.T, cfg map[string]interface{}) json.RawMessage {
	t.Helper()
	chain := []interface{}{
		map[string]interface{}{"ip": map[string]interface{}{"src": "192.0.2.71", "dst": "198.51.100.71"}},
		map[string]interface{}{"tcp": map[string]interface{}{"src_port": 40710}},
		map[string]interface{}{"http": map[string]interface{}{}},
		map[string]interface{}{"mmse": cfg},
	}
	out, _ := json.Marshal(chain)
	return out
}

func mmseSpec() core.FlowSpec {
	return core.FlowSpec{SrcIP: "192.0.2.71", DstIP: "198.51.100.71", SrcPort: 40710, DstPort: 80}
}

// mmseSession builds one session config; overrides attach via the extra map.
func mmseSession(role string, events []map[string]interface{}, overrides map[string]interface{}) map[string]interface{} {
	evs := make([]interface{}, len(events))
	for i, e := range events {
		evs[i] = e
	}
	m := map[string]interface{}{"role": role, "events": evs}
	for k, v := range overrides {
		m[k] = v
	}
	return m
}

func mmseConf(sessions ...map[string]interface{}) map[string]interface{} {
	ss := make([]interface{}, len(sessions))
	for i, s := range sessions {
		ss[i] = s
	}
	return map[string]interface{}{"sessions": ss}
}

// mmseSMILContent 是契约 §6 fixture 的 multipart 兄弟（非缺省可辨识值）。
func mmseSMILContent() map[string]interface{} {
	return map[string]interface{}{
		"kind": "multipart_related", "start": "<smil.smil>", "type": "application/smil",
		"parts": []interface{}{
			map[string]interface{}{"content_type": "application/smil", "content_id": "<smil.smil>", "data_b64": "PHNtaWw+Li4uPC9zbWlsPg=="},
			map[string]interface{}{"content_type": "text/plain", "charset": 106, "name": "text_1.txt",
				"content_id": "<text_1.txt>", "content_location": "text_1.txt", "data": "Hello MMSE world"},
		},
	}
}

func mmseSendReq(tid string) map[string]interface{} {
	return map[string]interface{}{
		"kind": "send_req", "transaction_id": tid,
		"date":    1725000000,
		"from":    map[string]interface{}{"address": "+8613800138000/TYPE=PLMN"},
		"to":      []interface{}{"+8613911223344/TYPE=PLMN"},
		"subject": map[string]interface{}{"text": "MMSE chain probe"},
		"content": mmseSMILContent(),
	}
}

func mmseSendConf(tid, msgid string) map[string]interface{} {
	return map[string]interface{}{
		"kind": "send_conf", "transaction_id": tid,
		"response_status": "ok", "message_id": msgid,
	}
}

func mmseNotificationInd(tid string) map[string]interface{} {
	return map[string]interface{}{
		"kind": "notification_ind", "transaction_id": tid,
		"from":             map[string]interface{}{"address": "+8613900139000/TYPE=PLMN"},
		"message_class":    "personal",
		"message_size":     4800,
		"expiry":           map[string]interface{}{"relative": 921600},
		"content_location": "http://mmsc.example/mms/MSG20260901001",
	}
}

func mmseDelivery(msgid string) map[string]interface{} {
	return map[string]interface{}{
		"kind": "delivery_ind", "message_id": msgid,
		"to":     []interface{}{"+8613800138000/TYPE=PLMN"},
		"date":   1725000000,
		"status": "retrieved",
	}
}

// mmseMSCSession is the mmsc-direction replay session (independent tuple).
func mmseMSCSession(events ...map[string]interface{}) map[string]interface{} {
	return mmseSession("mmsc", events, map[string]interface{}{
		"src_ip": "198.51.100.71", "dst_ip": "192.0.2.72", "src_port": 40711,
	})
}

// planWire plans the chain and returns all payload bytes concatenated.
func planWire(t *testing.T, raw json.RawMessage) (string, error) {
	t.Helper()
	p, err := layers.BuildLayersPlanner("mmse", raw)
	if err != nil {
		return "", err
	}
	ch, err := p.Plan(context.Background(), mmseSpec())
	if err != nil {
		return "", err
	}
	var body string
	for pkt := range ch {
		if len(pkt.Payload) > 0 {
			body += string(pkt.Payload)
		}
	}
	return body, nil
}

// validateRaw runs the planner's Validate (translate errors included).
func validateRaw(t *testing.T, raw json.RawMessage) error {
	t.Helper()
	p, err := layers.BuildLayersPlanner("mmse", raw)
	if err != nil {
		return err
	}
	return p.Validate(mmseSpec())
}

func mustContain(t *testing.T, body string, wants ...string) {
	t.Helper()
	for _, w := range wants {
		if !strings.Contains(body, w) {
			t.Fatalf("wire missing %q\nwire: %q", w, body[:min(400, len(body))])
		}
	}
}

// 红例①【D-MMSE-1 G5】：顶层 mmse 子映射 presence 判死（hl7 先例同型）。
func TestMMSEChain_FlatPresenceRejected(t *testing.T) {
	cfg := map[string]interface{}{
		"layers": []interface{}{
			map[string]interface{}{"tcp": map[string]interface{}{}},
			map[string]interface{}{"http": map[string]interface{}{}},
			map[string]interface{}{"mmse": map[string]interface{}{}},
		},
		"mmse": map[string]interface{}{},
	}
	msg := core.CheckProtoFlat("mmse", cfg)
	if msg == "" {
		t.Fatal(`CheckProtoFlat(mmse, {layers, mmse:{}}) = "", want top-level mmse presence rejection`)
	}
	if !strings.Contains(msg, "no longer accepts a top-level mmse sub-config") {
		t.Fatalf("CheckProtoFlat msg = %q, want sub-anchor `no longer accepts a top-level mmse sub-config`", msg)
	}
}

// 红例②【D-MMSE-1 裁定9③】：层 config 翻译落线——断言钉非缺省可辨识值
// （mms_version 1.3 → 版本线码 0x93、自定义 TID/URI）。
func TestMMSEChain_LayerConfigTranslates(t *testing.T) {
	ev := mmseSendReq("CHAIN-TID-77")
	ev["uri"] = "/chain/probe"
	cfg := mmseConf(mmseSession("ua", []map[string]interface{}{ev}, nil))
	cfg["mms_version"] = "1.3"
	body, err := planWire(t, mmseChain(t, cfg))
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	mustContain(t, body,
		"POST /chain/probe HTTP/1.1",
		"Content-Type: application/vnd.wap.mms-message",
		"CHAIN-TID-77", "\x8d\x93")
}

// 红例③【D-MMSE-1】：registry 五键 V9 allowlist——未知字段拒、五键放行。
func TestMMSEChain_V9Allowlist(t *testing.T) {
	bad := mmseChain(t, map[string]interface{}{"nope": 1})
	if _, err := layers.ValidateLayers(bad, "mmse"); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("unknown field must be rejected, got %v", err)
	}
	ok := mmseChain(t, map[string]interface{}{
		"profile": "mmse_http_v1", "mms_version": "1.2", "concurrent": false,
		"sessions": []interface{}{}, "wire_fault": "",
	})
	if _, err := layers.ValidateLayers(ok, "mmse"); err != nil {
		t.Fatalf("five contract keys must pass V9: %v", err)
	}
}

// 红例④【D-MMSE-1】：空层 = P0b 默认流（send_req + send_conf）。
func TestMMSEChain_EmptyLayerBaseline(t *testing.T) {
	raw := mmseChain(t, map[string]interface{}{})
	p, err := layers.BuildLayersPlanner("mmse", raw)
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v", err)
	}
	ch, err := p.Plan(context.Background(), mmseSpec())
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	n, reqs, resps := 0, 0, 0
	for pkt := range ch {
		n++
		if len(pkt.Payload) > 0 {
			if strings.HasPrefix(string(pkt.Payload), "POST ") {
				reqs++
			}
			if strings.HasPrefix(string(pkt.Payload), "HTTP/1.1 200 OK") {
				resps++
			}
		}
	}
	if reqs != 1 || resps != 1 {
		t.Fatalf("default flow: POST=%d 200=%d, want 1/1", reqs, resps)
	}
	if n < 8 || n > 10 {
		t.Fatalf("packets=%d, want 8 (3 SYN + POST + 200 + 3 FIN) [校准区间 8..10]", n)
	}
}

// 红例⑤【D-MMSE-1 裁定2/§3.2】：HTTP 帧字节钉 + PDU 首三头 8c 80 98 +
// Content-Length 自洽 + 恒无 Connection 头。
func TestMMSEChain_HTTPFrameAndPDUBytes(t *testing.T) {
	body, err := planWire(t, mmseChain(t, mmseConf(
		mmseSession("ua", []map[string]interface{}{mmseSendReq("TID56")}, nil),
	)))
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	i := strings.Index(body, "POST ")
	if i < 0 {
		t.Fatal("no POST request on the wire")
	}
	pl := body[i:]
	end := strings.Index(pl, "\r\n\r\n")
	if end < 0 {
		t.Fatalf("no header/body boundary in request frame: %q", pl[:min(200, len(pl))])
	}
	head, pdu := pl[:end], pl[end+4:]
	cl := -1
	for _, line := range strings.Split(head, "\r\n") {
		switch {
		case strings.HasPrefix(line, "Content-Length: "):
			fmt.Sscanf(line, "Content-Length: %d", &cl)
		case strings.HasPrefix(line, "Content-Type: "):
			if !strings.Contains(line, "application/vnd.wap.mms-message") {
				t.Fatalf("request Content-Type wrong: %q", line)
			}
		}
	}
	if cl != len(pdu) {
		t.Fatalf("Content-Length %d != body %d", cl, len(pdu))
	}
	if len(pdu) < 3 || pdu[0] != 0x8c || pdu[1] != 0x80 || pdu[2] != 0x98 {
		t.Fatalf("PDU head = % x, want 8c 80 98 ...", pdu[:min(6, len(pdu))])
	}
	if strings.Contains(head, "Connection:") {
		t.Fatalf("Connection header must not be sent (用例 #24 口径): %q", head)
	}
}

// 红例⑥【D-MMSE-1 裁定2】：载体——缺 http 自然面拒（预检）+ 注入
// carrier_no_http 锚 layer + udp 载体 transport 拒。
func TestMMSEChain_CarrierContract(t *testing.T) {
	noHTTP := []interface{}{
		map[string]interface{}{"tcp": map[string]interface{}{"src_port": 40710}},
		map[string]interface{}{"mmse": map[string]interface{}{}},
	}
	rawNo, _ := json.Marshal(noHTTP)
	if _, err := layers.BuildLayersPlanner("mmse", rawNo); err == nil ||
		!strings.Contains(err.Error(), "requires the http carrier layer") {
		t.Fatalf("tcp→mmse direct chain must be rejected, got %v", err)
	}
	inj := mmseChain(t, map[string]interface{}{"wire_fault": "carrier_no_http"})
	p, err := layers.BuildLayersPlanner("mmse", inj)
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v", err)
	}
	if err := p.Validate(mmseSpec()); err == nil || !strings.Contains(err.Error(), "layer") {
		t.Fatalf("wire_fault carrier_no_http must reject with anchor `layer`, got %v", err)
	}
	udpChain := []interface{}{
		map[string]interface{}{"udp": map[string]interface{}{"src_port": 40710}},
		map[string]interface{}{"http": map[string]interface{}{}},
		map[string]interface{}{"mmse": map[string]interface{}{}},
	}
	rawUDP, _ := json.Marshal(udpChain)
	if _, err := layers.BuildLayersPlanner("mmse", rawUDP); err == nil ||
		!strings.Contains(err.Error(), "transport layer duplicated") {
		t.Fatalf("udp+http+mmse chain must be rejected at build (udp and tcp transports coexist), got %v", err)
	}
}

// 红例⑦【D-MMSE-1 裁定4】：wire_fault 55 值闭环——注入即拒 + 主锚词 +
// 错误点名该故障（契约 §7 表逐行同词；55 = 40 守卫 + 14 豁免）。
func TestMMSEChain_WireFaultClosedEnum(t *testing.T) {
	anchors := map[string]string{
		"carrier_no_http": "layer", "carrier_content_type": "content-type",
		"carrier_port": "port", "carrier_profile": "carrier",
		"head_order_tid_first": "order", "head_order_version_missing": "header",
		"head_first_not_8c": "message-type", "pdu_type_unassigned": "unknown",
		"pdu_type_unsupported": "message-type", "content_type_missing": "content-type",
		"body_on_bodyless": "body", "mandatory_from": "mandatory",
		"mandatory_recipients": "mandatory", "mandatory_notif_class": "mandatory",
		"mandatory_notif_size": "mandatory", "mandatory_notif_expiry": "mandatory",
		"mandatory_notif_location": "mandatory", "mandatory_response_status": "response-status",
		"mandatory_delivery_msgid": "mandatory", "mandatory_delivery_to": "mandatory",
		"mandatory_delivery_date": "mandatory", "mandatory_delivery_status": "mandatory",
		"multipart_headers_len": "multipart", "multipart_data_len": "data",
		"multipart_partnum_zero": "part", "multipart_partnum_mismatch": "part",
		"multipart_start_dangling": "start", "multipart_partnum_over": "overflow",
		"tid_send_conf": "transaction", "tid_notifyresp": "transaction",
		"tid_acknowledge": "transaction", "msgid_delivery": "message-id",
		"msgid_read_rec": "message-id", "sequence_ack_first": "sequence",
		"sequence_notifyresp_orphan": "sequence", "sequence_conf_orphan": "sequence",
		"sequence_response_first": "order", "length_content_length": "length",
		"length_long_int_over": "long-integer", "length_long_int_zero": "long-integer",
		"length_uintvar_over": "uintvar", "length_value_length": "value-length",
		"length_tid_over": "transaction-id", "value_priority": "priority",
		"value_status": "status", "value_message_class": "message-class",
		"value_response_status": "response-status", "value_read_status": "read-status",
		"value_yesno": "delivery-report", "value_reply_charging": "reply-charging",
		"value_empty_string": "text-string", "value_application_header": "application-header",
		"value_charset": "charset", "value_previously_sent": "previously-sent",
		"value_notif_expiry_absolute": "expiry",
	}
	if len(anchors) != 55 {
		t.Fatalf("anchor probe map has %d entries, want 55", len(anchors))
	}
	for fault, anchor := range anchors {
		raw := mmseChain(t, map[string]interface{}{"wire_fault": fault})
		p, err := layers.BuildLayersPlanner("mmse", raw)
		if err != nil {
			t.Fatalf("wire_fault %s BuildLayersPlanner: %v", fault, err)
		}
		err = p.Validate(mmseSpec())
		if err == nil || !strings.Contains(err.Error(), anchor) {
			t.Fatalf("wire_fault %s must be rejected with anchor %q, got %v", fault, anchor, err)
		}
		if err != nil && !strings.Contains(err.Error(), fmt.Sprintf("wire_fault %q", fault)) {
			t.Fatalf("wire_fault %s error must name the fault, got %v", fault, err)
		}
	}
	// 未知 wire_fault 值拒（锚 unknown）。
	raw := mmseChain(t, map[string]interface{}{"wire_fault": "not_a_fault"})
	p, err := layers.BuildLayersPlanner("mmse", raw)
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v", err)
	}
	if err := p.Validate(mmseSpec()); err == nil || !strings.Contains(err.Error(), "unknown") {
		t.Fatalf("unknown wire_fault must reject with anchor `unknown`, got %v", err)
	}
}

// 红例⑧【D-MMSE-1 裁定5】：TID 配对——显式错配拒（锚 transaction）+ auto
// 配对落线同值（请求 T0001 → 响应同值；契约 §5 取材）。
func TestMMSEChain_TIDPairing(t *testing.T) {
	mism := mmseChain(t, mmseConf(mmseSession("ua", []map[string]interface{}{
		mmseSendReq("TID-REQ-1"),
		mmseSendConf("TID-WRONG-2", "M-1"),
	}, nil)))
	if err := validateRaw(t, mism); err == nil || !strings.Contains(err.Error(), "transaction") {
		t.Fatalf("mismatched send_conf TID must reject with anchor `transaction`, got %v", err)
	}
	body, err := planWire(t, mmseChain(t, mmseConf(mmseSession("ua", []map[string]interface{}{
		mmseSendReq("auto"),
		mmseSendConf("auto", "auto"),
	}, nil))))
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	mustContain(t, body, "T0001", "M0001")
	if strings.Count(body, "T0001") < 2 {
		t.Fatalf("auto TID T0001 must ride both request and response (same_as), wire: %q", body[:min(300, len(body))])
	}
}

// 红例⑨【D-MMSE-1 裁定5】：MsgID 回指——same_as_send_conf:0 落线同一值 +
// 孤儿字面拒（锚 message-id）。
func TestMMSEChain_MsgIDBackReference(t *testing.T) {
	body, err := planWire(t, mmseChain(t, mmseConf(
		mmseSession("ua", []map[string]interface{}{
			mmseSendReq("T-A"),
			mmseSendConf("T-A", "MSG-DELIV-001"),
		}, nil),
		mmseMSCSession(mmseDelivery("same_as_send_conf:0")),
	)))
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if strings.Count(body, "MSG-DELIV-001") < 2 {
		t.Fatalf("same_as_send_conf:0 must ride send-conf and delivery-ind, wire: %q", body[:min(300, len(body))])
	}
	orphan := mmseChain(t, mmseConf(
		mmseSession("ua", []map[string]interface{}{
			mmseSendReq("T-B"),
			mmseSendConf("T-B", "MSG-REAL-002"),
		}, nil),
		mmseMSCSession(mmseDelivery("MSG-ORPHAN-003")),
	))
	if err := validateRaw(t, orphan); err == nil || !strings.Contains(err.Error(), "message-id") {
		t.Fatalf("delivery_ind with unsourced msgid must reject with anchor `message-id`, got %v", err)
	}
}

// 红例⑩【D-MMSE-1 裁定5/§5】：顺序状态机四拒（order/sequence 锚）。
func TestMMSEChain_SequenceStateMachine(t *testing.T) {
	cases := []struct {
		name, anchor string
		ev           map[string]interface{}
	}{
		// sequence_response_first 的自然面与 conf_orphan 同形（响应侧先于
		// 请求必无配对对手）——注入面由红例⑦ 55 值闭环覆盖，此处不重复。
		{"conf_orphan", "sequence", mmseSendConf("S-2", "")},
		{"ack_first", "sequence", map[string]interface{}{"kind": "acknowledge_ind", "transaction_id": "S-3"}},
		{"notifyresp_orphan", "sequence", map[string]interface{}{"kind": "notifyresp_ind", "transaction_id": "S-4", "status": "deferred"}},
	}
	for _, c := range cases {
		raw := mmseChain(t, mmseConf(mmseSession("ua", []map[string]interface{}{c.ev}, nil)))
		if err := validateRaw(t, raw); err == nil || !strings.Contains(err.Error(), c.anchor) {
			t.Fatalf("%s must reject with anchor %q, got %v", c.name, c.anchor, err)
		}
	}
}

// 红例⑪【D-MMSE-1 裁定7】：multipart 门——start dangling（start）、恰 127
// 放行、128 拒（overflow）、零 parts（part）。
func TestMMSEChain_MultipartGates(t *testing.T) {
	badStart := mmseSendReq("MP-1")
	badStart["content"] = map[string]interface{}{
		"kind": "multipart_related", "start": "<absent.smil>", "type": "application/smil",
		"parts": []interface{}{
			map[string]interface{}{"content_type": "text/plain", "charset": 106, "data": "x"},
		},
	}
	if err := validateRaw(t, mmseChain(t, mmseConf(mmseSession("ua", []map[string]interface{}{badStart}, nil)))); err == nil ||
		!strings.Contains(err.Error(), "start") {
		t.Fatalf("dangling start must reject with anchor `start`, got %v", err)
	}
	zeroParts := mmseSendReq("MP-2")
	zeroParts["content"] = map[string]interface{}{"kind": "multipart_related", "parts": []interface{}{}}
	if err := validateRaw(t, mmseChain(t, mmseConf(mmseSession("ua", []map[string]interface{}{zeroParts}, nil)))); err == nil ||
		!strings.Contains(err.Error(), "part") {
		t.Fatalf("zero-part content must reject with anchor `part`, got %v", err)
	}
	part := func(i int) map[string]interface{} {
		return map[string]interface{}{"content_type": "text/plain", "charset": 106, "data": fmt.Sprintf("p%d", i)}
	}
	parts := func(n int) []interface{} {
		ps := make([]interface{}, n)
		for i := range ps {
			ps[i] = part(i)
		}
		return ps
	}
	ok127 := mmseSendReq("MP-3")
	ok127["content"] = map[string]interface{}{"kind": "multipart_related", "parts": parts(127)}
	if err := validateRaw(t, mmseChain(t, mmseConf(mmseSession("ua", []map[string]interface{}{ok127}, nil)))); err != nil {
		t.Fatalf("127-part multipart must pass: %v", err)
	}
	over := mmseSendReq("MP-4")
	over["content"] = map[string]interface{}{"kind": "multipart_related", "parts": parts(128)}
	if err := validateRaw(t, mmseChain(t, mmseConf(mmseSession("ua", []map[string]interface{}{over}, nil)))); err == nil ||
		!strings.Contains(err.Error(), "overflow") {
		t.Fatalf("128-part multipart must reject with anchor `overflow`, got %v", err)
	}
}

// 红例⑫【D-MMSE-1 §3.7】：值域族域外拒（priority/message-class/subject 空
// 串/charset + notifyresp status 域外）。
func TestMMSEChain_ValueDomainGuards(t *testing.T) {
	probes := []struct {
		field  string
		value  interface{}
		anchor string
	}{
		{"priority", "urgent", "priority"},
		{"message_class", "flash", "message-class"},
		{"subject", map[string]interface{}{"text": "", "charset": 0}, "text-string"},
		{"subject", map[string]interface{}{"text": "x", "charset": 1000}, "charset"},
	}
	for _, pr := range probes {
		ev := mmseSendReq("V-1")
		ev[pr.field] = pr.value
		raw := mmseChain(t, mmseConf(mmseSession("ua", []map[string]interface{}{ev}, nil)))
		if err := validateRaw(t, raw); err == nil || !strings.Contains(err.Error(), pr.anchor) {
			t.Fatalf("%s=%v must reject with anchor %q, got %v", pr.field, pr.value, pr.anchor, err)
		}
	}
	// 同会话通知→notifyresp（配对面先成立），status 域外才走到值域门。
	rawN := mmseChain(t, mmseConf(mmseMSCSession(
		mmseNotificationInd("V-N"),
		map[string]interface{}{"kind": "notifyresp_ind", "transaction_id": "V-N", "status": "bogus"},
	)))
	if err := validateRaw(t, rawN); err == nil || !strings.Contains(err.Error(), "status") {
		t.Fatalf("bogus status must reject with anchor `status`, got %v", err)
	}
}

// 红例⑬【D-MMSE-1 表 3】：通知必选集四缺各拒（mandatory 锚）+ expiry 绝对
// 形态拒（expiry 锚）。
func TestMMSEChain_NotificationMandatories(t *testing.T) {
	full := mmseNotificationInd("N-1")
	for _, d := range []string{"message_class", "message_size", "expiry", "content_location"} {
		ev := map[string]interface{}{}
		for k, v := range full {
			ev[k] = v
		}
		delete(ev, d)
		raw := mmseChain(t, mmseConf(mmseMSCSession(ev)))
		if err := validateRaw(t, raw); err == nil || !strings.Contains(err.Error(), "mandatory") {
			t.Fatalf("notification missing %s must reject with anchor `mandatory`, got %v", d, err)
		}
	}
	abs := mmseNotificationInd("N-2")
	abs["expiry"] = map[string]interface{}{"absolute": 1725000000}
	rawA := mmseChain(t, mmseConf(mmseMSCSession(abs)))
	if err := validateRaw(t, rawA); err == nil || !strings.Contains(err.Error(), "expiry") {
		t.Fatalf("notification absolute expiry must reject with anchor `expiry`, got %v", err)
	}
}

// 红例⑭【D-MMSE-1 裁定8】：未知键严格拒（DisallowUnknownFields）——事件级
// reply_charging / 会话级 reply_charging_deadline 经 translate 解码失败计
// 任务错误（不许静默置空——hl7 F1 教训）。
func TestMMSEChain_UnknownKeysRejected(t *testing.T) {
	ev := mmseSendReq("U-1")
	delete(ev, "content") // 保最小面
	ev["reply_charging"] = true
	raw := mmseChain(t, mmseConf(mmseSession("ua", []map[string]interface{}{ev}, nil)))
	if err := validateRaw(t, raw); err == nil ||
		(!strings.Contains(err.Error(), "mmse layer config") && !strings.Contains(err.Error(), "unknown field")) {
		t.Fatalf("event-level unknown key must fail as layer config error, got %v", err)
	}
	sess := mmseSession("ua", []map[string]interface{}{func() map[string]interface{} {
		e := mmseSendReq("U-2")
		delete(e, "content")
		return e
	}()}, map[string]interface{}{"reply_charging_deadline": 100})
	raw2 := mmseChain(t, mmseConf(sess))
	if err := validateRaw(t, raw2); err == nil ||
		(!strings.Contains(err.Error(), "mmse layer config") && !strings.Contains(err.Error(), "unknown field")) {
		t.Fatalf("session-level unknown key must fail as layer config error, got %v", err)
	}
}

// 红例⑮【D-MMSE-1 裁定5 megaco/hl7 round-2 同法】：sessionTx 唯一解析权威
// ——两会话 auto 计数器各自 T0001/T0002 + M0001/M0002 落线（每会话独立
// 计数、配对面同值；validator 判重面与生成器渲染同源）。
func TestMMSEChain_TxAuthorityParity(t *testing.T) {
	body, err := planWire(t, mmseChain(t, mmseConf(
		mmseSession("ua", []map[string]interface{}{
			mmseSendReq("auto"), mmseSendConf("auto", "auto"),
		}, map[string]interface{}{"src_port": 40710}),
		mmseSession("ua", []map[string]interface{}{
			mmseSendReq("auto"), mmseSendConf("auto", "auto"),
		}, map[string]interface{}{"src_port": 40720}),
	)))
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	// 独立复算：计数器**每会话独立**（sessTx per session，hl7 dynState 同
	// 款）——两会话各产出 T0001×2（请求+配对响应）与 M0001×1。
	mustContain(t, body, "T0001", "M0001")
	if strings.Count(body, "T0001") < 4 {
		t.Fatalf("each session's counter must emit T0001 on request+response (4 total)\nwire: %q", body[:min(400, len(body))])
	}
	if strings.Count(body, "M0001") < 2 {
		t.Fatalf("each session's send-conf must carry its own M0001 (2 total)\nwire: %q", body[:min(400, len(body))])
	}
}

// 红例⑯【D-MMSE-1 carrier_content_type】：事件 http 覆盖 Content-Type 偏离
// 即拒（锚 content-type）。
func TestMMSEChain_CarrierContentTypeGuard(t *testing.T) {
	ev := mmseSendReq("CT-1")
	ev["http"] = map[string]interface{}{"Content-Type": "text/plain"}
	raw := mmseChain(t, mmseConf(mmseSession("ua", []map[string]interface{}{ev}, nil)))
	if err := validateRaw(t, raw); err == nil || !strings.Contains(err.Error(), "content-type") {
		t.Fatalf("Content-Type override deviation must reject with anchor `content-type`, got %v", err)
	}
}

// 红例⑰【D-MMSE-1 裁定3】：WSP/Push 端口配 http 载体 → carrier_port 拒
//（锚 port）。
func TestMMSEChain_CarrierPortGuard(t *testing.T) {
	raw := mmseChain(t, mmseConf(mmseSession("ua", []map[string]interface{}{
		mmseSendReq("P-1"),
	}, map[string]interface{}{"dst_port": 9200})))
	if err := validateRaw(t, raw); err == nil || !strings.Contains(err.Error(), "port") {
		t.Fatalf("WSP port 9200 on the http bearer must reject with anchor `port`, got %v", err)
	}
}

// 红例⑱【D-MMSE-1 §3.4】：TID 33B 拒（transaction-id 锚）、恰 32B 放行。
func TestMMSEChain_TIDBoundary(t *testing.T) {
	raw := mmseChain(t, mmseConf(mmseMSCSession(mmseNotificationInd("T33"+strings.Repeat("A", 30)))))
	if err := validateRaw(t, raw); err == nil || !strings.Contains(err.Error(), "transaction-id") {
		t.Fatalf("33-byte TID must reject with anchor `transaction-id`, got %v", err)
	}
	rawOK := mmseChain(t, mmseConf(mmseMSCSession(mmseNotificationInd("T32"+strings.Repeat("A", 29)))))
	if err := validateRaw(t, rawOK); err != nil {
		t.Fatalf("32-byte TID must pass: %v", err)
	}
}

// 红例⑲【D-MMSE-1 body_on_bodyless】：无体 PDU 声明 content 即拒（锚 body）。
func TestMMSEChain_BodyOnBodyless(t *testing.T) {
	raw := mmseChain(t, mmseConf(mmseMSCSession(
		mmseNotificationInd("B-N"),
		map[string]interface{}{"kind": "notifyresp_ind", "transaction_id": "B-N", "status": "deferred", "content": mmseSMILContent()},
	)))
	if err := validateRaw(t, raw); err == nil || !strings.Contains(err.Error(), "body") {
		t.Fatalf("content on bodyless PDU must reject with anchor `body`, got %v", err)
	}
}

// 红例⑳【D-MMSE-1 C-1】：concurrent 双会话——双四元组各自 POST 落线
//（生成器 round-robin 交错 + tcp 层 concurrent 由链钩切换）。
func TestMMSEChain_ConcurrentSessions(t *testing.T) {
	cfg := mmseConf(
		mmseSession("ua", []map[string]interface{}{
			mmseSendReq("C-T1"), mmseSendConf("C-T1", "C-M1"),
		}, map[string]interface{}{"src_port": 40710}),
		mmseSession("ua", []map[string]interface{}{
			mmseSendReq("C-T2"), mmseSendConf("C-T2", "C-M2"),
		}, map[string]interface{}{"src_port": 40720}),
	)
	cfg["concurrent"] = true
	body, err := planWire(t, mmseChain(t, cfg))
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	mustContain(t, body, "C-T1", "C-T2")
	if strings.Count(body, "POST ") != 2 {
		t.Fatalf("concurrent sessions must each POST once, got %d\nwire: %q", strings.Count(body, "POST "), body[:min(300, len(body))])
	}
}

// 红例㉑【D-MMSE-1 裁定9②】parity 前置面：Content-Length 覆写偏离 → length
// 拒（validator 同步面用同一 builder 复算——非仅生成期）。
func TestMMSEChain_ContentLengthParity(t *testing.T) {
	ev := mmseSendReq("PARITY-2")
	ev["http"] = map[string]interface{}{"Content-Length": "1"}
	raw := mmseChain(t, mmseConf(mmseSession("ua", []map[string]interface{}{ev}, nil)))
	if err := validateRaw(t, raw); err == nil || !strings.Contains(err.Error(), "length") {
		t.Fatalf("Content-Length override mismatch must reject with anchor `length`, got %v", err)
	}
}

// 红例㉓【D-MMSE-1 §3.5 表 1–7】：越表头即拒（send-conf 带 priority、
// send-req 带 response_status）——字段集按 PDU 类型固定，不静默落线。
func TestMMSEChain_PDUFieldAllowance(t *testing.T) {
	conf := mmseSendConf("AL-1", "M-AL")
	conf["priority"] = "high"
	if err := validateRaw(t, mmseChain(t, mmseConf(mmseSession("ua", []map[string]interface{}{
		mmseSendReq("AL-1"), conf,
	}, nil)))); err == nil || !strings.Contains(err.Error(), "not permitted") {
		t.Fatalf("priority on send-conf must reject (Table 2 has no Priority), got %v", err)
	}
	req := mmseSendReq("AL-2")
	req["response_status"] = "ok"
	if err := validateRaw(t, mmseChain(t, mmseConf(mmseSession("ua", []map[string]interface{}{req}, nil)))); err == nil ||
		!strings.Contains(err.Error(), "not permitted") {
		t.Fatalf("response_status on send-req must reject (Table 1 has no Response-Status), got %v", err)
	}
}

// 红例㉒【D-MMSE-1 §5 自动派生③】：GET URI 自动取自通知 content_location
// 路径 + 立即取回复用通知 TID（§6.3）。
func TestMMSEChain_GetURIAutoDerived(t *testing.T) {
	body, err := planWire(t, mmseChain(t, mmseConf(
		mmseMSCSession(mmseNotificationInd("G-N")),
		mmseSession("ua", []map[string]interface{}{
			{"kind": "retrieve", "transaction_id": "auto"},
			{"kind": "retrieve_conf", "transaction_id": "auto", "date": 1725000000, "content": mmseSMILContent()},
		}, map[string]interface{}{"src_port": 40720}),
	)))
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	mustContain(t, body, "GET /mms/MSG20260901001 HTTP/1.1")
	if strings.Count(body, "G-N") < 2 {
		t.Fatalf("immediate retrieve must reuse the notification TID on the retrieve-conf\nwire: %q", body[:min(400, len(body))])
	}
}
