package layers_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	_ "github.com/trafficgen/trafficgen/internal/protocol/sip" // init 注册 sip 层生成器 + 校验器
)

// D-SIP-1 §4 红例①②③④（failing 先行，P-PIPE #19 P4）。
// 实现前预期：①红（CheckProtoFlat 无 sip presence 分支）；②红
// （registry 无 sip 行，V9 拒 unknown layer）；③红（translate 无 case
// + 生成器未注册）；④红（translate 不落 spec.SIP → 恒 nil）。

func sipChain(t *testing.T, sipCfg map[string]interface{}) json.RawMessage {
	t.Helper()
	layers_ := []interface{}{
		map[string]interface{}{"ip": map[string]interface{}{"src": "10.0.0.1", "dst": "20.0.0.1"}},
		map[string]interface{}{"sip": sipCfg},
	}
	out, _ := json.Marshal(layers_)
	return out
}

// 红例①【D-SIP-1 §2】：顶层 sip 子映射 presence 判死——空 map 也死。
func TestSIPChain_FlatPresenceRejected(t *testing.T) {
	cfg := map[string]interface{}{
		"layers": []interface{}{
			map[string]interface{}{"ip": map[string]interface{}{"src": "10.0.0.1", "dst": "20.0.0.1"}},
			map[string]interface{}{"sip": map[string]interface{}{}},
		},
		"sip": map[string]interface{}{},
	}
	if msg := core.CheckProtoFlat("sip", cfg); msg == "" {
		t.Fatal("CheckProtoFlat(sip, {layers, sip:{}}) = \"\", want top-level sip presence rejection")
	} else if !strings.Contains(msg, "top-level sip sub-config") {
		t.Fatalf("anchor mismatch: %q", msg)
	}
}

// 红例②【D-SIP-1 §1】：sip 层 4 键 V9 放行（registry 无行 → 实现前整层
// unknown）。业务 2 键（dialog/media）+ 端口 2 键（五度已批 E1）。
func TestSIPChain_LayerFieldsAccepted(t *testing.T) {
	raw := sipChain(t, map[string]interface{}{
		"src_port": 12001,
		"dst_port": 5060,
		"dialog": []interface{}{
			map[string]interface{}{
				"method": "INVITE", "uri": "sip:callee@20.0.0.1",
				"headers": []interface{}{"From: <sip:caller@10.0.0.1>"},
				"body":    "v=0\r\no=- 1 1 IN IP4 10.0.0.1\r\n",
			},
			map[string]interface{}{"status_code": 200, "status_text": "OK"},
		},
		"media": map[string]interface{}{
			"frames": 2, "payload_type": 0,
		},
	})
	if _, err := layers.ValidateLayers(raw, "sip"); err != nil {
		t.Fatalf("ValidateLayers: %v", err)
	}
}

// 红例③【D-SIP-1 §3】：translate + 生成器上线——[ip,sip] 链最小 12 包
// （3 握手 + 5 消息 INVITE/200/ACK/BYE/200 + 4 挥手；存量等价形）。
// legacy 输出 L4.Protocol="tcp"、SIP 文本在 Payload（sip.go:161-192 emit
// 合同），每短消息 1 包。
func TestSIPChain_LayerTranslateMinimalDialog(t *testing.T) {
	p := layers.NewChainPlannerFromChain("sip", []layers.Layer{
		{Name: "ip", Config: map[string]interface{}{"src": "10.0.0.1", "dst": "20.0.0.1"}},
		{Name: "sip", Config: map[string]interface{}{
			"src_port": 12001, "dst_port": 5060,
			"dialog": []interface{}{
				map[string]interface{}{
					"method": "INVITE", "uri": "sip:callee@20.0.0.1",
					"headers": []interface{}{
						"From: <sip:caller@10.0.0.1>", "To: <sip:callee@20.0.0.1>",
						"Call-ID: sip1@10.0.0.1", "CSeq: 1 INVITE",
					},
				},
				map[string]interface{}{"status_code": 200, "status_text": "OK"},
				map[string]interface{}{"method": "ACK", "uri": "sip:callee@20.0.0.1"},
				map[string]interface{}{"method": "BYE", "uri": "sip:callee@20.0.0.1"},
				map[string]interface{}{"status_code": 200, "status_text": "OK"},
			},
		}},
	})
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1"}
	if err := p.Validate(spec); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	wantFlags := []uint8{0x02, 0x12, 0x10, 0x18, 0x18, 0x18, 0x18, 0x18, 0x11, 0x10, 0x11, 0x10}
	n := 0
	for pkt := range ch {
		if n >= len(wantFlags) {
			t.Fatalf("packet overflow: got >%d packets", len(wantFlags))
		}
		if pkt.L4.Protocol != "tcp" {
			t.Fatalf("packet %d: L4.Protocol=%q want tcp", n+1, pkt.L4.Protocol)
		}
		if pkt.L4.Flags != wantFlags[n] {
			t.Fatalf("packet %d: flags=0x%x want 0x%x (TCP lifecycle order)", n+1, pkt.L4.Flags, wantFlags[n])
		}
		if n == 3 && string(pkt.Payload[:6]) != "INVITE" {
			t.Fatalf("packet 4: payload=%q want INVITE request", pkt.Payload[:6])
		}
		n++
	}
	if n != len(wantFlags) {
		t.Fatalf("packets=%d want %d (3 handshake + 5 messages + 4 teardown)", n, len(wantFlags))
	}
}

// 红例④【D-SIP-1 决策 C】：translate 把层 config 填进 spec.SIP——经
// ValidateSpec 后 spec.SIP 非 nil 且 dialog/media round-trip 逐槽映射
// （实现前恒 nil = 空 dialog 静默）。SIPMessage 头数组保序证通路。
func TestSIPChain_PresenceFilled(t *testing.T) {
	p := layers.NewChainPlannerFromChain("sip", []layers.Layer{
		{Name: "ip", Config: map[string]interface{}{"src": "10.0.0.1", "dst": "20.0.0.1"}},
		{Name: "sip", Config: map[string]interface{}{
			"dialog": []interface{}{
				map[string]interface{}{
					"method": "INVITE", "uri": "sip:callee@20.0.0.1",
					"headers":     []interface{}{"Call-ID: fixed@host", "CSeq: 7 INVITE"},
					"body":        "v=0\r\n",
					"direction":   "up",
					"emit_media":  true,
				},
			},
			"media": map[string]interface{}{
				"src_port": 30000, "dst_port": 30001, "frames": 3,
				"payload_type": 8, "sample_rate": 8000, "frame_size": 160,
				"direction": "down",
			},
		}},
	})
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1"}
	out, err := p.ValidateSpec(spec)
	if err != nil {
		t.Fatalf("ValidateSpec: %v", err)
	}
	if out.SIP == nil {
		t.Fatal("spec.SIP must be translated from the layer config")
	}
	g := out.SIP
	if len(g.Dialog) != 1 {
		t.Fatalf("dialog not drilled: %+v", g.Dialog)
	}
	m := g.Dialog[0]
	if m.Method != "INVITE" || m.URI != "sip:callee@20.0.0.1" || m.Body != "v=0\r\n" ||
		m.Direction != "up" || !m.EmitMedia {
		t.Fatalf("message fields not mapped: %+v", m)
	}
	if len(m.Headers) != 2 || m.Headers[0] != "Call-ID: fixed@host" || m.Headers[1] != "CSeq: 7 INVITE" {
		t.Fatalf("headers order not preserved: %+v", m.Headers)
	}
	if g.Media == nil || g.Media.SrcPort != 30000 || g.Media.DstPort != 30001 ||
		g.Media.Frames != 3 || g.Media.PayloadType != 8 || g.Media.FrameSize != 160 ||
		g.Media.Direction != "down" {
		t.Fatalf("media not drilled: %+v", g.Media)
	}
}
