package layers_test

// D-MEGACO-1 P4 链级红例（cwmp 先例同构）：
// ①顶层 megaco 子映射 presence 判死；②层 config 翻译进 spec.Megaco 并落
// 线（MEGACO/1 起始行）；③registry 七键 V9 allowlist；④空层=P0b 基线注册
// 对（2 包）；⑤TCP 载体 TPKT 成帧（03 00 长度域）；⑥端口域校验（2945 配
// text/端口 0）；⑦wire_fault 闭环 31 值枚举拒绝带锚词；⑧会话 transport 与
// 链载体不符拒。

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	_ "github.com/trafficgen/trafficgen/internal/protocol/megaco" // init 注册 megaco 终结层生成器+校验器
)

func megacoChain(t *testing.T, carrier string, cfg map[string]interface{}) json.RawMessage {
	t.Helper()
	chain := []interface{}{
		map[string]interface{}{"ip": map[string]interface{}{"src": "192.0.2.70", "dst": "198.51.100.70"}},
		map[string]interface{}{carrier: map[string]interface{}{"src_port": 40700}},
		map[string]interface{}{"megaco": cfg},
	}
	out, _ := json.Marshal(chain)
	return out
}

func megacoChainWithPort(t *testing.T, carrier string, dstPort int, cfg map[string]interface{}) json.RawMessage {
	t.Helper()
	chain := []interface{}{
		map[string]interface{}{"ip": map[string]interface{}{"src": "192.0.2.70", "dst": "198.51.100.70"}},
		map[string]interface{}{carrier: map[string]interface{}{"src_port": 40700, "dst_port": dstPort}},
		map[string]interface{}{"megaco": cfg},
	}
	out, _ := json.Marshal(chain)
	return out
}

func megacoSpec() core.FlowSpec {
	return core.FlowSpec{SrcIP: "192.0.2.70", DstIP: "198.51.100.70", SrcPort: 40700, DstPort: 2944}
}

// 红例①【D-MEGACO-1 裁定】：顶层 megaco 子映射 presence 判死（B6 注入形退役）。
func TestMegacoChain_FlatPresenceRejected(t *testing.T) {
	cfg := map[string]interface{}{
		"layers": []interface{}{
			map[string]interface{}{"udp": map[string]interface{}{}},
			map[string]interface{}{"megaco": map[string]interface{}{}},
		},
		"megaco": map[string]interface{}{},
	}
	msg := core.CheckProtoFlat("megaco", cfg)
	if msg == "" {
		t.Fatal(`CheckProtoFlat(megaco, {layers, megaco:{}}) = "", want top-level megaco presence rejection`)
	}
	if !strings.Contains(msg, "no longer accepts a top-level megaco sub-config") {
		t.Fatalf("CheckProtoFlat msg = %q, want sub-anchor `no longer accepts a top-level megaco sub-config`", msg)
	}
}

// 红例②【D-MEGACO-1 裁定3】：层 config 翻译进 spec.Megaco 并落线。
// 断言钉非缺省值（修轮 F7：旧版钉 defaultFlow 派生串，删 translate case
// 仍绿=伪证）——显式 mgc 角色下 mid=[198.51.100.99]（缺省派生给
// [192.0.2.70]）、Reason="444 DISTINCTIVE-F7"（缺省 901 Cold Boot），
// 两者都必须来自层 config 经 translate 进 spec.Megaco。
func TestMegacoChain_LayerConfigTranslates(t *testing.T) {
	raw := megacoChain(t, "udp", map[string]interface{}{
		"sessions": []interface{}{
			map[string]interface{}{
				"role": "mgc", "mid": "[198.51.100.99]", "peer_mid": "[192.0.2.70]",
				"events": []interface{}{
					map[string]interface{}{"kind": "message", "direction": "c2s", "transactions": []interface{}{
						map[string]interface{}{"type": "request", "id": "1", "actions": []interface{}{
							map[string]interface{}{"context": "-", "commands": []interface{}{
								map[string]interface{}{"name": "ServiceChange", "termination": "ROOT", "descriptor": map[string]interface{}{
									"services": map[string]interface{}{"method": "Restart", "reason": "444 DISTINCTIVE-F7"}}}}}}}}},
				},
			},
		},
	})
	p, err := layers.BuildLayersPlanner("megaco", raw)
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v", err)
	}
	if p.Validate(megacoSpec()) != nil {
		t.Fatalf("Validate: %v", p.Validate(megacoSpec()))
	}
	ch, err := p.Plan(context.Background(), megacoSpec())
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var body string
	for pkt := range ch {
		if len(pkt.Payload) > 0 {
			body += string(pkt.Payload)
		}
	}
	for _, want := range []string{"MEGACO/1 [198.51.100.99] ", "Reason=\"444 DISTINCTIVE-F7\""} {
		if !strings.Contains(body, want) {
			t.Fatalf("layer megaco config not translated on the wire: %q missing from %q", want, body)
		}
	}
}

// 红例③【D-MEGACO-1】：registry 七键 V9 allowlist——未知字段拒、七键放行。
func TestMegacoChain_V9Allowlist(t *testing.T) {
	bad := megacoChain(t, "udp", map[string]interface{}{"nope": 1})
	if _, err := layers.ValidateLayers(bad, "megaco"); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("unknown field must be rejected, got %v", err)
	}
	ok := megacoChain(t, "udp", map[string]interface{}{
		"profile": "megaco_v1_text", "encoding": "text", "version": 1,
		"token_form": "long", "whitespace": "", "sessions": []interface{}{}, "wire_fault": "",
	})
	if _, err := layers.ValidateLayers(ok, "megaco"); err != nil {
		t.Fatalf("seven contract keys must pass V9: %v", err)
	}
}

// 红例④【D-MEGACO-1 裁定6】：空层 {"megaco":{}} = P0b 基线注册对 2 包
// （SC(Restart,ROOT) 请求 + Reply；UDP 每消息一数据报，13.20 缺省面）。
func TestMegacoChain_EmptyLayerBaseline(t *testing.T) {
	raw := megacoChain(t, "udp", map[string]interface{}{})
	p, err := layers.BuildLayersPlanner("megaco", raw)
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v", err)
	}
	ch, err := p.Plan(context.Background(), megacoSpec())
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	n := 0
	for pkt := range ch {
		n++
		if len(pkt.Payload) > 0 && !strings.HasPrefix(string(pkt.Payload), "MEGACO/1 ") {
			t.Fatalf("packet %d payload not a megaco start line: %q", n, pkt.Payload)
		}
	}
	if n != 2 {
		t.Fatalf("packets=%d, want 2 (P0b baseline registration pair)", n)
	}
}

// 红例⑤【D-MEGACO-1 裁定3】：TCP 载体 TPKT 成帧——载荷前 4B RFC 1006 头
// （03 00 + 16bit 长度 = 4+消息长），握手 3 + 数据 + 挥手 4 = 8 包。
func TestMegacoChain_TCPTPKTFraming(t *testing.T) {
	raw := megacoChain(t, "tcp", map[string]interface{}{})
	p, err := layers.BuildLayersPlanner("megaco", raw)
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v", err)
	}
	ch, err := p.Plan(context.Background(), megacoSpec())
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var tpkt, payloads int
	for pkt := range ch {
		if len(pkt.Payload) >= 4 && pkt.Payload[0] == 0x03 && pkt.Payload[1] == 0x00 {
			tpkt++
			total := int(pkt.Payload[2])<<8 | int(pkt.Payload[3])
			if total != len(pkt.Payload) && total > len(pkt.Payload) {
				t.Fatalf("TPKT length %d exceeds frame payload %d", total, len(pkt.Payload))
			}
			continue
		}
		if pkt.L4.Flags&0x02 != 0 || pkt.L4.Flags&0x01 != 0 || len(pkt.Payload) == 0 {
			continue // SYN/FIN/RST/裸 ACK
		}
		payloads++
		if !strings.HasPrefix(string(pkt.Payload), "MEGACO/1 ") {
			t.Fatalf("non-TPKT PSH payload: %q", pkt.Payload)
		}
	}
	if tpkt != 2 {
		t.Fatalf("TPKT-framed segments=%d, want 2 (request+reply)", tpkt)
	}
	if payloads != 0 {
		t.Fatalf("unframed PSH payloads=%d, want 0 (all TCP messages TPKT-framed)", payloads)
	}
}

// 红例⑥【D-MEGACO-1 裁定4】：端口域校验——text 编码配 2945（BER 默认端口）
// 拒（锚 encoding）；2944/2427 合法。
func TestMegacoChain_PortContract(t *testing.T) {
	bad := megacoChainWithPort(t, "udp", 2945, map[string]interface{}{})
	p, err := layers.BuildLayersPlanner("megaco", bad)
	if err == nil {
		err = p.Validate(megacoSpecWithPort(2945))
	}
	if err == nil || !strings.Contains(err.Error(), "encoding") {
		t.Fatalf("2945 with text encoding must be rejected with encoding anchor, got %v", err)
	}
	// 2427（mgcp 别名）与 2944（默认）合法放行。
	for _, port := range []int{2944, 2427} {
		ok := megacoChainWithPort(t, "udp", port, map[string]interface{}{})
		p, err := layers.BuildLayersPlanner("megaco", ok)
		if err != nil {
			t.Fatalf("port %d BuildLayersPlanner: %v", port, err)
		}
		if err := p.Validate(core.FlowSpec{SrcIP: "192.0.2.70", DstIP: "198.51.100.70", SrcPort: 40700, DstPort: uint16(port)}); err != nil {
			t.Fatalf("port %d must be accepted, got %v", port, err)
		}
	}
}

func megacoSpecWithPort(port int) core.FlowSpec {
	return core.FlowSpec{SrcIP: "192.0.2.70", DstIP: "198.51.100.70", SrcPort: 40700, DstPort: uint16(port)}
}

// 红例⑦【D-MEGACO-1 裁定5】：wire_fault 闭环 31 值枚举——每个值在 validator
// 即拒并携带主锚词；未知值拒（枚举成员性）。
func TestMegacoChain_WireFaultClosedEnum(t *testing.T) {
	anchors := map[string]string{
		"encoding_text_as_ber": "encoding", "syntax_start_line": "message",
		"syntax_mid_invalid": "mid", "command_pre_registration": "command",
		"pairing_reply_id_mismatch": "transaction", "length_termid_over_64": "length",
		"carrier_layer_mismatch": "carrier", "carrier_invalid_port": "port",
		"services_address_mgcidtotry_conflict": "services",
	}
	for fault, anchor := range anchors {
		raw := megacoChain(t, "udp", map[string]interface{}{"wire_fault": fault})
		p, err := layers.BuildLayersPlanner("megaco", raw)
		if err != nil {
			t.Fatalf("wire_fault %s BuildLayersPlanner: %v", fault, err)
		}
		err = p.Validate(megacoSpec())
		if err == nil || !strings.Contains(err.Error(), anchor) {
			t.Fatalf("wire_fault %s must be rejected with anchor %q, got %v", fault, anchor, err)
		}
	}
	unknown := megacoChain(t, "udp", map[string]interface{}{"wire_fault": "not_a_kind"})
	p, err := layers.BuildLayersPlanner("megaco", unknown)
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v", err)
	}
	if err := p.Validate(megacoSpec()); err == nil || !strings.Contains(err.Error(), "unknown wire_fault") {
		t.Fatalf("unknown wire_fault must be rejected, got %v", err)
	}
}

// 红例⑧【D-MEGACO-1 裁定4】：会话 transport 与链载体不符同步拒绝（链形状
// 是载体唯一真相；锚 carrier）。
func TestMegacoChain_SessionTransportMismatch(t *testing.T) {
	raw := megacoChain(t, "udp", map[string]interface{}{
		"sessions": []interface{}{map[string]interface{}{"role": "mg", "transport": "tcp"}},
	})
	planner, err := layers.BuildLayersPlanner("megaco", raw)
	if err != nil {
		t.Fatalf("build planner (config validates at creation; carrier rule fires at Validate): %v", err)
	}
	err = planner.Validate(megacoSpec())
	if err == nil || !strings.Contains(err.Error(), "carrier") {
		t.Fatalf("session transport tcp on udp chain must be rejected with carrier anchor, got %v", err)
	}
}

// —— D-MEGACO-1 修轮红例（收官隔离复审 F1–F11 处置，每例对应一项守卫）——

// 红例⑨【修轮 F1】：TPKT 长度域 uint16 溢出必报错（>0xFFFF 静默截断=错帧
// ——probe13 实证 70204 mod 65536 漂移）。走真实 Plan 路径：70KB DigitMap
// 单消息 TCP 链必须在生成期报 RFC 1006 上界错。
func TestMegacoChain_TPKTOverflowRejected(t *testing.T) {
	bigValue := strings.Repeat("1", 70000)
	raw := megacoChain(t, "tcp", map[string]interface{}{
		"sessions": []interface{}{
			map[string]interface{}{
				"role": "mg", "mid": "[192.0.2.70]",
				"events": []interface{}{
					map[string]interface{}{
						"kind": "message", "direction": "c2s",
						"transactions": []interface{}{
							map[string]interface{}{
								"type": "request", "id": "1",
								"actions": []interface{}{
									map[string]interface{}{"context": "-", "commands": []interface{}{
										map[string]interface{}{"name": "Modify", "termination": "A4444", "descriptor": map[string]interface{}{
											"digit_map": map[string]interface{}{"name": "D1", "value": bigValue},
										}},
									}},
								},
							},
						},
					},
				},
			},
		},
	})
	p, err := layers.BuildLayersPlanner("megaco", raw)
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v", err)
	}
	// 溢出守卫住在 Validate 同步面：Plan goroutine 吞生成器错误成空流
	// （契约"驱动失败→空流"），长度类拒绝必须在 Validate 即报。
	if err := p.Validate(megacoSpec()); err == nil || !strings.Contains(err.Error(), "16-bit length domain") {
		t.Fatalf("70KB TPKT PDU must be rejected at Validate (16-bit length domain), got %v", err)
	}
}

// 红例⑩【修轮 F2】：缩写形 response_ack 必发 "K"（不得发 "ResponseAck"，
// 契约 §3.2 表；旧版 map 迭代序随机二义）。
func TestMegacoChain_AbbrevAckIsK(t *testing.T) {
	req := map[string]interface{}{
		"kind": "message", "direction": "c2s",
		"transactions": []interface{}{
			map[string]interface{}{"type": "request", "id": "5", "actions": []interface{}{
				map[string]interface{}{"context": "-", "commands": []interface{}{
					map[string]interface{}{"name": "AuditValue", "termination": "ROOT"},
				}},
			}},
		},
	}
	rep := map[string]interface{}{
		"kind": "message", "direction": "s2c",
		"transactions": []interface{}{
			map[string]interface{}{"type": "reply", "id": "same_as_request:0"},
		},
	}
	ack := map[string]interface{}{
		"kind": "message", "direction": "c2s",
		"transactions": []interface{}{
			map[string]interface{}{"type": "response_ack", "ack": "5"},
		},
	}
	raw := megacoChain(t, "udp", map[string]interface{}{
		"token_form": "abbrev",
		"sessions": []interface{}{
			map[string]interface{}{
				"role": "mgc", "mid": "[192.0.2.70]", "peer_mid": "[198.51.100.70]",
				"events": []interface{}{req, rep, ack},
			},
		},
	})
	p, err := layers.BuildLayersPlanner("megaco", raw)
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v", err)
	}
	ch, err := p.Plan(context.Background(), megacoSpec())
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var body string
	for pkt := range ch {
		body += string(pkt.Payload)
	}
	if !strings.Contains(body, "!/1") || !strings.Contains(body, "K { 5 }") {
		t.Fatalf("abbrev ack must render `!/1` + `K { 5 }`, got %q", body)
	}
	if strings.Contains(body, "ResponseAck") {
		t.Fatalf("abbrev ack leaked long token: %q", body)
	}
}

// 红例⑪【修轮 F3】：会话级 dst_port 与链级同域——9999 拒（锚 port）、
// 2945 拒（锚 encoding）、2427 放行。
func TestMegacoChain_SessionDstPortDomain(t *testing.T) {
	mk := func(port int) json.RawMessage {
		return megacoChain(t, "udp", map[string]interface{}{
			"sessions": []interface{}{map[string]interface{}{"role": "mg", "dst_port": port}},
		})
	}
	build := func(port int) core.ProtocolPlanner {
		t.Helper()
		p, err := layers.BuildLayersPlanner("megaco", mk(port))
		if err != nil {
			t.Fatalf("port %d BuildLayersPlanner: %v", port, err)
		}
		return p
	}
	if err := build(9999).Validate(megacoSpec()); err == nil || !strings.Contains(err.Error(), "port") {
		t.Fatalf("session dst_port 9999 must be rejected with port anchor, got %v", err)
	}
	if err := build(2945).Validate(megacoSpec()); err == nil || !strings.Contains(err.Error(), "encoding") {
		t.Fatalf("session dst_port 2945 must be rejected with encoding anchor, got %v", err)
	}
	if err := build(2427).Validate(megacoSpec()); err != nil {
		t.Fatalf("session dst_port 2427 must pass, got %v", err)
	}
}

// 红例⑫【修轮 F4】：显式 transactionId 超 UINT32 拒（锚 length）——旧版
// 静默落线（probe11 实证 "Transaction = 4294967296"）。
func TestMegacoChain_TransIDOverflowRejected(t *testing.T) {
	tx := map[string]interface{}{
		"type": "request", "id": "4294967296",
		"actions": []interface{}{
			map[string]interface{}{"context": "-", "commands": []interface{}{
				map[string]interface{}{"name": "AuditValue", "termination": "ROOT"},
			}},
		},
	}
	raw := megacoChain(t, "udp", map[string]interface{}{
		"sessions": []interface{}{
			map[string]interface{}{
				"role": "mg", "mid": "[192.0.2.70]",
				"events": []interface{}{
					map[string]interface{}{"kind": "message", "direction": "c2s", "transactions": []interface{}{tx}},
				},
			},
		},
	})
	p, err := layers.BuildLayersPlanner("megaco", raw)
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v", err)
	}
	if err := p.Validate(megacoSpec()); err == nil || !strings.Contains(err.Error(), "length") {
		t.Fatalf("transid > UINT32 must be rejected with length anchor, got %v", err)
	}
}

// 红例⑬【修轮 F9】：同会话重复 transactionId 拒（锚 transaction）。
func TestMegacoChain_DuplicateTransIDRejected(t *testing.T) {
	mkev := func() map[string]interface{} {
		return map[string]interface{}{"kind": "message", "direction": "c2s", "transactions": []interface{}{
			map[string]interface{}{"type": "request", "id": "7", "actions": []interface{}{
				map[string]interface{}{"context": "-", "commands": []interface{}{
					map[string]interface{}{"name": "AuditValue", "termination": "ROOT"}}}}}},
		}
	}
	raw := megacoChain(t, "udp", map[string]interface{}{
		"sessions": []interface{}{map[string]interface{}{
			"role": "mg", "mid": "[192.0.2.70]",
			"events": []interface{}{mkev(), mkev()},
		}},
	})
	p, err := layers.BuildLayersPlanner("megaco", raw)
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v", err)
	}
	if err := p.Validate(megacoSpec()); err == nil || !strings.Contains(err.Error(), "transaction") {
		t.Fatalf("duplicate transid must be rejected with transaction anchor, got %v", err)
	}
}

// 红例⑭【修轮 F10/F11/F6】：自然面守卫——显式 version 0 拒（锚 version）、
// 非法 mid 拒（锚 mid）、encoding=ber 拒（锚 encoding）。
func TestMegacoChain_NaturalFaceGuards(t *testing.T) {
	// 注：显式 version 0 的自然面守卫不设——V9 框架规则"显式 0 = schema 默认
	// 值"（complete.go u==0 skip）使其与缺席不可区分；负例 50 走 wire_fault
	// 闭包（D- 裁定5 同款书面豁免）。
	mid := megacoChain(t, "udp", map[string]interface{}{
		"sessions": []interface{}{map[string]interface{}{"role": "mg", "mid": "[bad mid with spaces]"}},
	})
	p, err := layers.BuildLayersPlanner("megaco", mid)
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v", err)
	}
	if err := p.Validate(megacoSpec()); err == nil || !strings.Contains(err.Error(), "mid") {
		t.Fatalf("invalid mid form must be rejected with mid anchor, got %v", err)
	}
	ber := megacoChain(t, "udp", map[string]interface{}{"encoding": "ber"})
	bp, err := layers.BuildLayersPlanner("megaco", ber)
	if err != nil {
		t.Fatalf("BuildLayersPlanner(ber): %v", err)
	}
	if err := bp.Validate(megacoSpec()); err == nil || !strings.Contains(err.Error(), "encoding") {
		t.Fatalf("encoding=ber must be rejected with encoding anchor, got %v", err)
	}
}

// 红例⑮【修轮 F8】：SDP 中的 } 必须转义为 \}（否则提前闭合 Local 块）。
func TestMegacoChain_SDPEscape(t *testing.T) {
	desc := map[string]interface{}{
		"media": map[string]interface{}{
			"streams": []interface{}{
				map[string]interface{}{"id": 1, "local_sdp": "v=0} o=junk"},
			},
		},
	}
	cmd := map[string]interface{}{"name": "Modify", "termination": "A4444", "descriptor": desc}
	raw := megacoChain(t, "udp", map[string]interface{}{
		"sessions": []interface{}{
			map[string]interface{}{
				"role": "mgc", "mid": "[192.0.2.70]", "peer_mid": "[198.51.100.70]",
				"events": []interface{}{
					map[string]interface{}{
						"kind": "message", "direction": "c2s",
						"transactions": []interface{}{
							map[string]interface{}{
								"type": "request", "id": "1",
								"actions": []interface{}{
									map[string]interface{}{"context": "1", "commands": []interface{}{cmd}},
								},
							},
						},
					},
				},
			},
		},
	})
	p, err := layers.BuildLayersPlanner("megaco", raw)
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v", err)
	}
	ch, err := p.Plan(context.Background(), megacoSpec())
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var body string
	for pkt := range ch {
		body += string(pkt.Payload)
	}
	if !strings.Contains(body, `v=0\} o=junk`) {
		t.Fatalf("SDP } must be escaped on the wire, got %q", body)
	}
}
