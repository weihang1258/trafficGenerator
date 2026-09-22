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

// 红例②【D-MEGACO-1 裁定3】：层 config 翻译进 spec.Megaco 并落线——自定义
// SC(Restart) 的 mId 与 Method 必须出现在字节面（translate 无 case 时层值
// 被忽略=死配置）。
func TestMegacoChain_LayerConfigTranslates(t *testing.T) {
	raw := megacoChain(t, "udp", map[string]interface{}{
		"sessions": []interface{}{
			map[string]interface{}{
				"role": "mg", "mid": "[192.0.2.70]", "peer_mid": "[198.51.100.70]",
				"events": []interface{}{
					map[string]interface{}{"kind": "message", "direction": "c2s", "transactions": []interface{}{
						map[string]interface{}{"type": "request", "id": "1", "actions": []interface{}{
							map[string]interface{}{"context": "-", "commands": []interface{}{
								map[string]interface{}{"name": "ServiceChange", "termination": "ROOT", "descriptor": map[string]interface{}{
									"services": map[string]interface{}{"method": "Restart", "reason": "901 Cold Boot"}}}}}}}}},
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
	for _, want := range []string{"MEGACO/1 [192.0.2.70] ", "ServiceChange = ROOT", `Reason="901 Cold Boot"`} {
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
