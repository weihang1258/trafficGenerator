package layers_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	_ "github.com/trafficgen/trafficgen/internal/protocol/srv6" // init 注册 srv6 层生成器 + 校验器
)

// D-SRV6-1 步骤 0 红例族（failing 先行，P-PIPE #10 P4）。
// 实现前预期：①红（presence 未判死，放行）；②红（registry srv6 零 Fields，
// 层内业务键 V9 全拒 unknown field）；③红（无 isRawIPChain/生成器注册——
// "generator not implemented for layer srv6"）；④红（translate 无 case
// "srv6"——②修后层值仍进不了 spec.SRv6，validator 报 srv6 config 相关错误）；
// ⑤红（direction=down 双换：raw-IP drive 对 legacy 已换向的包再换 L3 地址）。

func srv6Chain(t *testing.T, srv6Cfg map[string]interface{}, extra ...interface{}) json.RawMessage {
	t.Helper()
	layers_ := []interface{}{
		map[string]interface{}{"ip": map[string]interface{}{"src": "2001:db8::1", "dst": "2001:db8::2"}},
		map[string]interface{}{"srv6": srv6Cfg},
	}
	layers_ = append(layers_, extra...)
	out, _ := json.Marshal(layers_)
	return out
}

// 红例1【D-SRV6-1 §1/§5】：顶层 srv6 子映射 presence 判死——空 map 也死
// （mcp 先例）。现状：CheckProtoFlat(srv6, {layers, srv6:{}}) 返回空。
func TestSRV6Chain_FlatPresenceRejected(t *testing.T) {
	cfg := map[string]interface{}{
		"layers": []interface{}{
			map[string]interface{}{"ip": map[string]interface{}{"src": "2001:db8::1", "dst": "2001:db8::2"}},
			map[string]interface{}{"srv6": map[string]interface{}{}},
		},
		"srv6": map[string]interface{}{},
	}
	if msg := core.CheckProtoFlat("srv6", cfg); msg == "" {
		t.Fatal("CheckProtoFlat(srv6, {layers, srv6:{}}) = \"\", want top-level srv6 presence rejection")
	} else if !strings.Contains(msg, "top-level srv6 sub-config") {
		t.Fatalf("anchor mismatch: %q", msg)
	}
}

// 红例2【D-SRV6-1 §13】：srv6 层 16 业务键 V9 放行。现状：registry srv6 零
// Fields → ValidateLayers 报 unknown field。
func TestSRV6Chain_LayerFieldsAccepted(t *testing.T) {
	raw := srv6Chain(t, map[string]interface{}{
		"segment_list":     []interface{}{"2001:db8::2"},
		"seg_type":         "end",
		"payload_protocol": "udp",
		"inner_dst_port":   53,
		"tag":              4660,
		"frames":           2,
		"reduced":          false,
	})
	if _, err := layers.ValidateLayers(raw, "srv6"); err != nil {
		t.Fatalf("ValidateLayers: %v", err)
	}
}

// 红例3+4【D-SRV6-1 §3/决策 F】：层 config 翻译上线 + inner_payload 字符串
// 字节语义。现状：无生成器注册（③ generator not implemented）；②修后仍无
// case "srv6" 翻译（④ spec.SRv6 nil → validator 拒）。实现后：Plan 产 1 帧
// IPv6+SRH 包，payload == "12345678" 原文字节（JSON 往返会 base64 误读——
// 决策 F 锁）。t091 类：vn02 锚词确认空层翻译出非 nil（VR-02 必拒不被
// Default 污染）由 validator 面覆盖，此处不重复。
func TestSRV6Chain_LayerTranslateAndPayloadBytes(t *testing.T) {
	p := layers.NewChainPlannerFromChain("srv6", []layers.Layer{
		{Name: "ip", Config: map[string]interface{}{"src": "2001:db8::1", "dst": "2001:db8::2"}},
		{Name: "srv6", Config: map[string]interface{}{
			"segment_list":     []interface{}{"2001:db8::2"},
			"seg_type":         "end",
			"payload_protocol": "udp",
			"inner_src_port":   12345,
			"inner_dst_port":   53,
			"inner_payload":    "12345678",
		}},
	})
	spec := core.FlowSpec{SrcIP: "2001:db8::1", DstIP: "2001:db8::2", SrcPort: 12345, DstPort: 53}
	if err := p.Validate(spec); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	n := 0
	for pkt := range ch {
		n++
		if pkt.L3.Protocol != 43 {
			t.Fatalf("L3.Protocol = %d, want 43 (SRH routing header)", pkt.L3.Protocol)
		}
		if string(pkt.Payload) != "12345678" {
			t.Fatalf("payload bytes = %q, want raw \"12345678\" (getByteSlice string semantics)", pkt.Payload)
		}
	}
	if n != 1 {
		t.Fatalf("packet count = %d, want 1", n)
	}
}

// 红例5【D-SRV6-1 §3/决策】：direction=down 不双换。legacy Plan 内部已完成
// MAC/IP/端口/List 全套换向并置 Direction="down"；raw-IP drive 对 down 包
// 再换 L3 地址=双换。实现后生成器强制 Direction="up" 转 Emit：L3.SrcIP 保持
// legacy 换向值（=原 DstIP），L2 MAC 保持 legacy 换向值（down: src=02..02）。
// 现状：无生成器注册，Plan 直接报错（红）。
func TestSRV6Chain_DownNoDoubleSwap(t *testing.T) {
	p := layers.NewChainPlannerFromChain("srv6", []layers.Layer{
		{Name: "ip", Config: map[string]interface{}{"src": "2001:db8::1", "dst": "2001:db8::2"}},
		{Name: "srv6", Config: map[string]interface{}{
			"segment_list":     []interface{}{"2001:db8:a::1", "2001:db8:b::1", "2001:db8:c::1"},
			"direction":        "down",
			"payload_protocol": "udp",
			"inner_src_port":   3333,
			"inner_dst_port":   4444,
		}},
	})
	spec := core.FlowSpec{
		SrcIP: "2001:db8::1", DstIP: "2001:db8::2",
		SrcMAC: core.DefaultSrcMAC, DstMAC: core.DefaultDstMAC,
		SrcPort: 12345, DstPort: 53,
	}
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	for pkt := range ch {
		// legacy down 语义（mf04 期望同款，RFC 8754 §4.1 DA=首段）：
		// L3.SrcIP = 原 SegmentList[0]，L3.DstIP = 原 List[n-1]（最终目的）。
		// 断言这两个值即锁死"drive 未二次换向"（二次换向会变回
		// src=2001:db8::1 / dst=首段）。
		if pkt.L3.SrcIP != "2001:db8:a::1" {
			t.Fatalf("down L3.SrcIP = %q, want 2001:db8:a::1 (legacy SRH swap, no double swap)", pkt.L3.SrcIP)
		}
		if pkt.L3.DstIP != "2001:db8:c::1" {
			t.Fatalf("down L3.DstIP = %q, want 2001:db8:c::1 (original final destination)", pkt.L3.DstIP)
		}
		// L2 MAC 由 legacy 换向后写入（down: src=原 dst）。drive 不再换。
		if pkt.L2.SrcMAC != core.DefaultDstMAC {
			t.Fatalf("down L2.SrcMAC = %q, want %q (legacy swapped)", pkt.L2.SrcMAC, core.DefaultDstMAC)
		}
	}
}
