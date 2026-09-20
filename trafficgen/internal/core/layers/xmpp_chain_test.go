package layers_test

// D-XMPP-1 P4 链级红例：[ip→xmpp] raw 自驱链（六连协议对称：legacy 自建
// TCP wrap，防双换 Direction=up）。控制通道 5222 由链路径 DstPort switch
// 缺省（legacy Plan 无内部缺省——xmpp 与 pptp 唯一差异，rtsp 式必选）。
// 3 锚背 door 由 validator 承接。

import (
	"context"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	// 触发 xmpp 包 init 注册 raw 链生成器 + 校验器。
	_ "github.com/trafficgen/trafficgen/internal/protocol/xmpp"
)

func TestChainPlanner_XMPPRawChain(t *testing.T) {
	p := layers.NewChainPlannerFromChain("xmpp", []layers.Layer{
		{Name: "ip", Config: map[string]interface{}{"src": "10.0.0.1", "dst": "20.0.0.1"}},
		// messages 列表经 JSON 往返（mustJSONMap 同口径）。
		{Name: "xmpp", Config: mustJSONMap(t, `{
			"messages": [
				{"direction": "up", "to": "alice@example.com", "body": "ping"},
				{"direction": "down", "to": "user@example.com", "body": "pong"}
			]
		}`)},
	})
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345}
	validated, err := p.ValidateSpec(spec)
	if err != nil {
		t.Fatalf("ValidateSpec: %v", err)
	}
	if validated.Xmpp == nil {
		t.Fatalf("translate must populate spec.Xmpp from the xmpp layer config")
	}
	// DstPort switch 缺省 5222（链路径必选：legacy Plan 无内部缺省）。
	if validated.DstPort != 5222 {
		t.Fatalf("DstPort=%d want 5222 (xmpp client-to-server default)", validated.DstPort)
	}
	if len(validated.Xmpp.Messages) != 2 || validated.Xmpp.Messages[1].Direction != "down" {
		t.Fatalf("messages not populated: %+v", validated.Xmpp.Messages)
	}
	ch, err := p.Plan(context.Background(), validated)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	n := 0
	for pkt := range ch {
		n++
		if pkt.L4.Protocol != "tcp" {
			t.Fatalf("packet %d proto=%q want tcp", n, pkt.L4.Protocol)
		}
		if pkt.L4.DstPort != 5222 && pkt.L4.SrcPort != 5222 {
			t.Fatalf("packet %d ports %d->%d: 5222 must appear", n, pkt.L4.SrcPort, pkt.L4.DstPort)
		}
	}
	// 缺省 PLAIN 19 帧 + messages 2 = 21（3 握手+15 数据+3 拆链；
	// 与 suite T-1/T-6 同源互证）。
	if n != 21 {
		t.Fatalf("packets=%d want 21 (PLAIN + 2 messages)", n)
	}
}

// 背 door 锚：链上 ValidateSpec 经 protocolValidator 调用 legacy Validate。
func TestChainPlanner_XMPPValidatorAnchors(t *testing.T) {
	p := layers.NewChainPlannerFromChain("xmpp", []layers.Layer{
		{Name: "ip", Config: map[string]interface{}{"src": "10.0.0.1", "dst": "20.0.0.1"}},
		{Name: "xmpp", Config: mustJSONMap(t, `{"auth_mechanism": "NTLM"}`)},
	})
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1"}
	_, err := p.ValidateSpec(spec)
	if err == nil || !contains(err.Error(), "unsupported auth mechanism") {
		t.Fatalf("want auth-mechanism anchor, got %v", err)
	}
}
