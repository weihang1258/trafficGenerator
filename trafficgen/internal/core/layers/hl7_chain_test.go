package layers_test

// D-HL7-1 P4 链级红例（megaco_chain_test.go 21 例先例同构）：
// ①顶层 hl7 子映射 presence 判死；②层 config 翻译落线（钉非缺省可辨识值
// ——megaco F7 教训前置）；③registry 八键 V9 allowlist；④空层基线 9 包
// （3 握手 + REQ+ACK 两帧 + 4 挥手）；⑤MLLP 帧字节钉（0x0B/0x1C 0x0D）；
// ⑥载体双拒（udp→carrier、缺 tcp→layer）；⑦wire_fault 33 值闭环锚词；
// ⑧ack 配对 MSA-2=请求 MSH-10；⑨必需段集（裁定7）；⑩EVN-1↔MSH-9 一致性；
// ⑪Z 段显式放行/未声明拒；⑫控制 ID 会话内唯一判重；⑬地址族一致；
// ⑭parity 守卫前置面（Validate 面长度天花板可复算——契约 §3.6）。

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	_ "github.com/trafficgen/trafficgen/internal/protocol/hl7" // init 注册 hl7 终结层生成器+校验器
)

func hl7Chain(t *testing.T, cfg map[string]interface{}) json.RawMessage {
	t.Helper()
	chain := []interface{}{
		map[string]interface{}{"ip": map[string]interface{}{"src": "192.0.2.68", "dst": "198.51.100.68"}},
		map[string]interface{}{"tcp": map[string]interface{}{"src_port": 42680}},
		map[string]interface{}{"hl7": cfg},
	}
	out, _ := json.Marshal(chain)
	return out
}

func hl7Spec() core.FlowSpec {
	return core.FlowSpec{SrcIP: "192.0.2.68", DstIP: "198.51.100.68", SrcPort: 42680, DstPort: 2575}
}

func hl7ADTEvent(msgType string, extraSegs ...map[string]interface{}) map[string]interface{} {
	segs := []interface{}{
		map[string]interface{}{"name": "EVN", "fields": []interface{}{"A01"}},
		map[string]interface{}{"name": "PID", "fields": []interface{}{"1", "", "PAT001^^^HOSP^MR", "", "DOE^JOHN^A"}},
		map[string]interface{}{"name": "PV1", "fields": []interface{}{"1", "I", "WARD^ICU^B101"}},
	}
	for _, s := range extraSegs {
		segs = append(segs, s)
	}
	return map[string]interface{}{
		"kind": "msg", "direction": "c2s", "message_type": msgType,
		"segments": segs, "ack": "auto",
	}
}

// 红例①【D-HL7-1 G5】：顶层 hl7 子映射 presence 判死（megaco 先例同型）。
func TestHL7Chain_FlatPresenceRejected(t *testing.T) {
	cfg := map[string]interface{}{
		"layers": []interface{}{
			map[string]interface{}{"tcp": map[string]interface{}{}},
			map[string]interface{}{"hl7": map[string]interface{}{}},
		},
		"hl7": map[string]interface{}{},
	}
	msg := core.CheckProtoFlat("hl7", cfg)
	if msg == "" {
		t.Fatal(`CheckProtoFlat(hl7, {layers, hl7:{}}) = "", want top-level hl7 presence rejection`)
	}
	if !strings.Contains(msg, "no longer accepts a top-level hl7 sub-config") {
		t.Fatalf("CheckProtoFlat msg = %q, want sub-anchor `no longer accepts a top-level hl7 sub-config`", msg)
	}
}

// 红例②【D-HL7-1 裁定9③】：层 config 翻译落线——断言钉非缺省可辨识值
// （sending_app=LABPROD、自定义 field_separator="#"），删 translate case
// 必红（megaco F7：钉缺省派生串=伪证）。
func TestHL7Chain_LayerConfigTranslates(t *testing.T) {
	raw := hl7Chain(t, map[string]interface{}{
		"field_separator": "#",
		"sessions": []interface{}{
			map[string]interface{}{
				"role": "sender", "sending_app": "LABPROD", "sending_fac": "GH",
				"receiving_app": "LIS", "receiving_fac": "GH",
				"events": []interface{}{hl7ADTEvent("ADT^A01^ADT_A01")},
			},
		},
	})
	p, err := layers.BuildLayersPlanner("hl7", raw)
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v", err)
	}
	if err := p.Validate(hl7Spec()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	ch, err := p.Plan(context.Background(), hl7Spec())
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var body string
	for pkt := range ch {
		if len(pkt.Payload) > 0 {
			body += string(pkt.Payload)
		}
	}
	if !strings.Contains(body, "MSH#") {
		t.Fatalf("custom field_separator not translated on the wire (want MSH#): %q", body[:min(200, len(body))])
	}
	if !strings.Contains(body, "LABPROD") {
		t.Fatalf("sending_app from layer config missing on the wire: %q", body[:min(200, len(body))])
	}
}

// 红例③【D-HL7-1】：registry 八键 V9 allowlist——未知字段拒、八键放行。
func TestHL7Chain_V9Allowlist(t *testing.T) {
	bad := hl7Chain(t, map[string]interface{}{"nope": 1})
	if _, err := layers.ValidateLayers(bad, "hl7"); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("unknown field must be rejected, got %v", err)
	}
	ok := hl7Chain(t, map[string]interface{}{
		"profile": "mllp", "version": "2.8", "field_separator": "|",
		"encoding_chars": "^~\\&", "ack_mode": "auto", "concurrent": false,
		"sessions": []interface{}{}, "wire_fault": "",
	})
	if _, err := layers.ValidateLayers(ok, "hl7"); err != nil {
		t.Fatalf("eight contract keys must pass V9: %v", err)
	}
}

// 红例④【D-HL7-1】：空层 = P0b 基线单事务 9 包（3 握手 + REQ+ACK 两帧
// + 4 挥手，TCP 铁律 3+N+4）。
func TestHL7Chain_EmptyLayerBaseline(t *testing.T) {
	raw := hl7Chain(t, map[string]interface{}{})
	p, err := layers.BuildLayersPlanner("hl7", raw)
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v", err)
	}
	ch, err := p.Plan(context.Background(), hl7Spec())
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	n := 0
	var frames int
	for pkt := range ch {
		n++
		if len(pkt.Payload) > 0 && pkt.Payload[0] == 0x0B {
			frames++
		}
	}
	if n != 9 {
		t.Fatalf("packets=%d, want 9 (3 SYN + REQ + ACK + 4 FIN)", n)
	}
	if frames != 2 {
		t.Fatalf("MLLP frames=%d, want 2 (request + derived ACK)", frames)
	}
}

// 红例⑤【D-HL7-1 裁定2】：MLLP 帧字节钉——REQ 帧首 0x0B、尾 0x1C 0x0D。
func TestHL7Chain_MLLPFrameBytes(t *testing.T) {
	raw := hl7Chain(t, map[string]interface{}{
		"sessions": []interface{}{
			map[string]interface{}{
				"role": "sender", "sending_app": "HIS", "sending_fac": "GH",
				"receiving_app": "RIS", "receiving_fac": "GH",
				"events": []interface{}{hl7ADTEvent("ADT^A01^ADT_A01")},
			},
		},
	})
	p, err := layers.BuildLayersPlanner("hl7", raw)
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v", err)
	}
	ch, err := p.Plan(context.Background(), hl7Spec())
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	for pkt := range ch {
		if len(pkt.Payload) > 4 && pkt.Payload[0] == 0x0B {
			last := len(pkt.Payload)
			if pkt.Payload[last-2] != 0x1C || pkt.Payload[last-1] != 0x0D {
				t.Fatalf("MLLP frame must end 0x1C 0x0D, got tail % x", pkt.Payload[last-2:])
			}
			if !strings.Contains(string(pkt.Payload), "MSH|") {
				t.Fatalf("frame payload must carry MSH segment: %q", pkt.Payload[:min(60, len(pkt.Payload))])
			}
			return
		}
	}
	t.Fatal("no MLLP-framed packet found")
}

// 红例⑥【D-HL7-1 裁定2】：载体双拒——udp → carrier；缺 tcp → layer。
func TestHL7Chain_CarrierContract(t *testing.T) {
	udp := []interface{}{
		map[string]interface{}{"ip": map[string]interface{}{"src": "192.0.2.68", "dst": "198.51.100.68"}},
		map[string]interface{}{"udp": map[string]interface{}{"src_port": 42680}},
		map[string]interface{}{"hl7": map[string]interface{}{}},
	}
	raw, _ := json.Marshal(udp)
	p, err := layers.BuildLayersPlanner("hl7", raw)
	if err == nil {
		err = p.Validate(hl7Spec())
	}
	if err == nil || !strings.Contains(err.Error(), "carrier") {
		t.Fatalf("udp carrier must be rejected with carrier anchor, got %v", err)
	}
	// carrier_no_tcp 自然面结构性不可达：hl7 DependsOn tcp 使链补全自动
	// 供给 tcp（[ip,hl7] 补成 [ip,tcp,hl7]）——"缺 tcp"形状不可构造，该值
	// 走 wire_fault 豁免（D-HL7-1 F6 处置表；注入面由红例⑦覆盖）。本段钉
	// 自动补全语义本身。
	noTCP := []interface{}{
		map[string]interface{}{"ip": map[string]interface{}{"src": "192.0.2.68", "dst": "198.51.100.68"}},
		map[string]interface{}{"hl7": map[string]interface{}{}},
	}
	raw2, _ := json.Marshal(noTCP)
	p2, err := layers.BuildLayersPlanner("hl7", raw2)
	if err != nil {
		t.Fatalf("[ip,hl7] must auto-complete tcp (DependsOn), got %v", err)
	}
	if err := p2.Validate(hl7Spec()); err != nil {
		t.Fatalf("auto-completed carrier must pass, got %v", err)
	}
}

// 红例⑦【D-HL7-1 裁定4】：wire_fault 33 值闭环枚举——每值即拒带 §7 主锚词；
// 未知值拒（枚举成员性）。
func TestHL7Chain_WireFaultClosedEnum(t *testing.T) {
	anchors := map[string]string{
		"framing_sob_missing": "mllp", "framing_eob_missing": "mllp",
		"framing_eob_malformed": "mllp", "framing_control_byte": "mllp",
		"segment_first_not_msh": "msh", "segment_no_cr": "segment",
		"segment_after_eob": "segment", "segment_name_invalid": "segment",
		"msh1_invalid": "separator", "msh2_invalid": "separator",
		"separator_mismatch": "separator", "escape_invalid": "escape",
		"msh9_missing": "msh", "msh10_missing": "msh", "msh11_missing": "msh",
		"msh12_missing": "msh", "msh9_domain": "msh",
		"ack_msa2_mismatch": "ack", "ack_no_msh9": "ack",
		"ack_no_msa": "ack", "ack_code_invalid": "ack",
		"carrier_udp": "carrier", "carrier_no_tcp": "layer", "port_invalid": "port",
		"len_msh9": "length", "len_msh10": "length", "len_msh12": "length",
		"len_msh7": "length", "len_msa2": "length",
		"event_mismatch": "event", "address_family_mixed": "address",
		"required_segment_missing": "segment", "z_segment_unconfigured": "z",
	}
	if len(anchors) != 33 {
		t.Fatalf("anchor probe map has %d entries, want 33", len(anchors))
	}
	for fault, anchor := range anchors {
		raw := hl7Chain(t, map[string]interface{}{"wire_fault": fault})
		p, err := layers.BuildLayersPlanner("hl7", raw)
		if err != nil {
			t.Fatalf("wire_fault %s BuildLayersPlanner: %v", fault, err)
		}
		err = p.Validate(hl7Spec())
		if err == nil || !strings.Contains(err.Error(), anchor) {
			t.Fatalf("wire_fault %s must be rejected with anchor %q, got %v", fault, anchor, err)
		}
	}
	unknown := hl7Chain(t, map[string]interface{}{"wire_fault": "not_a_kind"})
	p, err := layers.BuildLayersPlanner("hl7", unknown)
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v", err)
	}
	if err := p.Validate(hl7Spec()); err == nil || !strings.Contains(err.Error(), "not a known negative-path kind") {
		t.Fatalf("unknown wire_fault must be rejected, got %v", err)
	}
}

// 红例⑧【D-HL7-1 裁定5】：ack 配对——派生 ACK 的 MSA-2 = 请求 MSH-10。
func TestHL7Chain_AckPairing(t *testing.T) {
	raw := hl7Chain(t, map[string]interface{}{
		"sessions": []interface{}{
			map[string]interface{}{
				"role": "sender", "sending_app": "HIS", "sending_fac": "GH",
				"receiving_app": "RIS", "receiving_fac": "GH",
				"events": []interface{}{
					hl7ADTEvent("ADT^A01^ADT_A01"),
					map[string]interface{}{
						"kind": "msg", "direction": "c2s", "message_type": "ORU^R01^ORU_R01",
						"segments": []interface{}{
							map[string]interface{}{"name": "OBR", "fields": []interface{}{"1", "ORD-1&HIS", "FILL-1&LIS", "2339-0^Glucose^LN", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "F"}},
						},
						"ack": "auto",
					},
				},
			},
		},
	})
	p, err := layers.BuildLayersPlanner("hl7", raw)
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v", err)
	}
	if err := p.Validate(hl7Spec()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	ch, err := p.Plan(context.Background(), hl7Spec())
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var reqID, ackMSA2 string
	for pkt := range ch {
		s := string(pkt.Payload)
		if strings.Contains(s, "ORU^R01") {
			if i := strings.Index(s, "MSG"); i >= 0 {
				reqID = s[i : i+7]
			}
		}
		if strings.Contains(s, "ACK^R01") || strings.Contains(s, "ACK^") {
			if i := strings.Index(s, "MSA"); i >= 0 && i+8 <= len(s) {
				parts := strings.Split(s[i:], "|")
				if len(parts) >= 3 {
					ackMSA2 = strings.Split(parts[2], "\r")[0]
				}
			}
		}
	}
	if reqID == "" || ackMSA2 == "" {
		t.Fatalf("pairing probe incomplete: reqID=%q ackMSA2=%q", reqID, ackMSA2)
	}
	if reqID != ackMSA2 {
		t.Fatalf("ACK MSA-2 %q must echo request MSH-10 %q", ackMSA2, reqID)
	}
}

// 红例⑨【D-HL7-1 裁定7】：必需段集——ADT^A01 缺 PV1 拒（锚 segment）。
func TestHL7Chain_RequiredSegments(t *testing.T) {
	raw := hl7Chain(t, map[string]interface{}{
		"sessions": []interface{}{
			map[string]interface{}{
				"role": "sender",
				"events": []interface{}{
					map[string]interface{}{
						"kind": "msg", "direction": "c2s", "message_type": "ADT^A01^ADT_A01",
						"segments": []interface{}{
							map[string]interface{}{"name": "EVN", "fields": []interface{}{"A01"}},
							map[string]interface{}{"name": "PID", "fields": []interface{}{"1"}},
						},
						"ack": "auto",
					},
				},
			},
		},
	})
	p, err := layers.BuildLayersPlanner("hl7", raw)
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v", err)
	}
	if err := p.Validate(hl7Spec()); err == nil || !strings.Contains(err.Error(), "segment") {
		t.Fatalf("ADT^A01 missing PV1 must be rejected with segment anchor, got %v", err)
	}
}

// 红例⑩【D-HL7-1 裁定7】：EVN-1 与 MSH-9 触发事件一致——A01 vs A02 拒
// （锚 event）。
func TestHL7Chain_EventMismatch(t *testing.T) {
	raw := hl7Chain(t, map[string]interface{}{
		"sessions": []interface{}{
			map[string]interface{}{
				"role": "sender",
				"events": []interface{}{
					map[string]interface{}{
						"kind": "msg", "direction": "c2s", "message_type": "ADT^A01^ADT_A01",
						"segments": []interface{}{
							map[string]interface{}{"name": "EVN", "fields": []interface{}{"A02"}},
							map[string]interface{}{"name": "PID", "fields": []interface{}{"1"}},
							map[string]interface{}{"name": "PV1", "fields": []interface{}{"1", "I"}},
						},
						"ack": "auto",
					},
				},
			},
		},
	})
	p, err := layers.BuildLayersPlanner("hl7", raw)
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v", err)
	}
	if err := p.Validate(hl7Spec()); err == nil || !strings.Contains(err.Error(), "event") {
		t.Fatalf("EVN-1 A02 vs MSH-9 A01 must be rejected with event anchor, got %v", err)
	}
}

// 红例⑪【D-HL7-1 裁定6】：Z 段——未声明拒（锚 z）；显式 allow 放行透传。
func TestHL7Chain_ZSegmentRule(t *testing.T) {
	zSeg := map[string]interface{}{"name": "ZPI", "fields": []interface{}{"custom"}}
	mkev := func() map[string]interface{} {
		return map[string]interface{}{
			"kind": "msg", "direction": "c2s", "message_type": "ADT^A01^ADT_A01",
			"segments": []interface{}{
				map[string]interface{}{"name": "EVN", "fields": []interface{}{"A01"}},
				map[string]interface{}{"name": "PID", "fields": []interface{}{"1"}},
				map[string]interface{}{"name": "PV1", "fields": []interface{}{"1", "I"}},
				zSeg,
			},
			"ack": "auto",
		}
	}
	raw := hl7Chain(t, map[string]interface{}{
		"sessions": []interface{}{map[string]interface{}{"role": "sender", "events": []interface{}{mkev()}}},
	})
	p, err := layers.BuildLayersPlanner("hl7", raw)
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v", err)
	}
	if err := p.Validate(hl7Spec()); err == nil || !strings.Contains(err.Error(), "z") {
		t.Fatalf("undeclared Z segment must be rejected with z anchor, got %v", err)
	}
	// 显式 allow_z_segments → 放行。
	raw2 := hl7Chain(t, map[string]interface{}{
		"sessions": []interface{}{map[string]interface{}{"role": "sender", "allow_z_segments": true, "events": []interface{}{mkev()}}},
	})
	p2, err := layers.BuildLayersPlanner("hl7", raw2)
	if err != nil {
		t.Fatalf("BuildLayersPlanner(allow): %v", err)
	}
	if err := p2.Validate(hl7Spec()); err != nil {
		t.Fatalf("declared Z segment must pass, got %v", err)
	}
}

// 红例⑫【D-HL7-1 裁定9①】：控制 ID 会话内唯一——显式钉值撞号拒（megaco
// U1 教训前置：判重在解析后集合上）。
func TestHL7Chain_ControlIDUniqueness(t *testing.T) {
	mkev := func(id string) map[string]interface{} {
		return map[string]interface{}{
			"kind": "msg", "direction": "c2s", "message_type": "ORU^R01^ORU_R01",
			"control_id": id,
			"segments": []interface{}{
				map[string]interface{}{"name": "OBR", "fields": []interface{}{"1"}},
			},
			"ack": "null",
		}
	}
	raw := hl7Chain(t, map[string]interface{}{
		"sessions": []interface{}{
			map[string]interface{}{
				"role":   "sender",
				"events": []interface{}{mkev("MSG0001"), mkev("")},
			},
		},
	})
	p, err := layers.BuildLayersPlanner("hl7", raw)
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v", err)
	}
	// 显式 MSG0001 + 缺省（自动分配得 MSG0001）→ 撞号拒。
	if err := p.Validate(hl7Spec()); err == nil || !strings.Contains(err.Error(), "duplicate control id") {
		t.Fatalf("explicit + derived control-id collision must be rejected, got %v", err)
	}
}

// 红例⑬【D-HL7-1 裁定2】：地址族一致——[ipv6] 层配 IPv4 字面量拒（锚
// address）；[ip] 层配 v6 字面量同拒。
func TestHL7Chain_AddressFamily(t *testing.T) {
	// 本 registry 无独立 ipv6 层（契约 C-11 形状不可达）——可表达面 =
	// ip 层 src/dst 混族。
	v6Layer := []interface{}{
		map[string]interface{}{"ip": map[string]interface{}{"src": "192.0.2.68", "dst": "2001:db8::68"}},
		map[string]interface{}{"tcp": map[string]interface{}{"src_port": 42680}},
		map[string]interface{}{"hl7": map[string]interface{}{}},
	}
	raw, _ := json.Marshal(v6Layer)
	p, err := layers.BuildLayersPlanner("hl7", raw)
	if err == nil {
		err = p.Validate(hl7Spec())
	}
	if err == nil || !strings.Contains(err.Error(), "address") {
		t.Fatalf("mixed-family ip layer must be rejected with address anchor, got %v", err)
	}
}

// 红例⑭【D-HL7-1 裁定9③】：自然面守卫集——message_type 必填/未知码/长度
// 上界/非法转义/控制字节各一钉（守卫在 P4 落码，本例防回退）。
func TestHL7Chain_NaturalFaceGuards(t *testing.T) {
	// message_type 必填（msh9_missing 自然面）。
	noMT := hl7Chain(t, map[string]interface{}{
		"sessions": []interface{}{map[string]interface{}{"role": "sender", "events": []interface{}{
			map[string]interface{}{"kind": "msg", "direction": "c2s", "segments": []interface{}{}, "ack": "auto"}}}},
	})
	p, err := layers.BuildLayersPlanner("hl7", noMT)
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v", err)
	}
	if err := p.Validate(hl7Spec()); err == nil || !strings.Contains(err.Error(), "msh") {
		t.Fatalf("empty message_type must be rejected with msh anchor, got %v", err)
	}
	// 未知 MSH-9 码（msh9_domain 自然面）。
	badDomain := hl7Chain(t, map[string]interface{}{
		"sessions": []interface{}{map[string]interface{}{"role": "sender", "events": []interface{}{
			map[string]interface{}{"kind": "msg", "direction": "c2s", "message_type": "XYZ^Q99^XYZ_Q99", "segments": []interface{}{}, "ack": "auto"}}}},
	})
	p2, err := layers.BuildLayersPlanner("hl7", badDomain)
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v", err)
	}
	if err := p2.Validate(hl7Spec()); err == nil || !strings.Contains(err.Error(), "msh") {
		t.Fatalf("unknown message code must be rejected with msh anchor, got %v", err)
	}
	// 非法 \X 转义（escape_invalid 自然面）。
	badEscape := hl7Chain(t, map[string]interface{}{
		"sessions": []interface{}{map[string]interface{}{"role": "sender", "events": []interface{}{
			map[string]interface{}{"kind": "msg", "direction": "c2s", "message_type": "ADT^A01^ADT_A01",
				"segments": []interface{}{
					map[string]interface{}{"name": "EVN", "fields": []interface{}{"A01"}},
					map[string]interface{}{"name": "PID", "fields": []interface{}{"1", "", "BAD\\XG1\\ESC"}},
					map[string]interface{}{"name": "PV1", "fields": []interface{}{"1", "I"}},
				},
				"ack": "auto"}}}},
	})
	p3, err := layers.BuildLayersPlanner("hl7", badEscape)
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v", err)
	}
	if err := p3.Validate(hl7Spec()); err == nil || !strings.Contains(err.Error(), "escape") {
		t.Fatalf("malformed \\X escape must be rejected with escape anchor, got %v", err)
	}
}
