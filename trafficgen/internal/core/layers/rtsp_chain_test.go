package layers_test

// D-RTSP-1 P4 链级红例：[ip→rtsp] raw 自驱链（ldap/rtmp 对称：legacy
// 自建 TCP wrap，防双换 Direction=up）。控制通道 554 由 validateSpecBase
// DstPort switch 缺省（dns→53 同款）。dialog 必需锚由 validator 背 door。

import (
	"context"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	// 触发 rtsp 包 init 注册 raw 链生成器 + 校验器。
	_ "github.com/trafficgen/trafficgen/internal/protocol/rtsp"
)

func TestChainPlanner_RTSPRawChain(t *testing.T) {
	p := layers.NewChainPlannerFromChain("rtsp", []layers.Layer{
		{Name: "ip", Config: map[string]interface{}{"src": "10.0.0.1", "dst": "20.0.0.1"}},
		{Name: "rtsp", Config: mustJSONMap(t, `{
			"dialog": [
				{"method": "OPTIONS"},
				{"status_code": 200, "status_text": "OK"},
				{"method": "DESCRIBE"},
				{"status_code": 200, "status_text": "OK"}
			]
		}`)},
	})
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345}
	validated, err := p.ValidateSpec(spec)
	if err != nil {
		t.Fatalf("ValidateSpec: %v", err)
	}
	if validated.RTSP == nil || len(validated.RTSP.Dialog) != 4 {
		t.Fatalf("translate must populate spec.RTSP.Dialog: %+v", validated.RTSP)
	}
	// 554 缺省（链路径 dst switch）。
	if validated.DstPort != 554 {
		t.Fatalf("DstPort=%d want 554 (rtsp control channel default)", validated.DstPort)
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
		if pkt.L4.DstPort != 554 && pkt.L4.SrcPort != 554 {
			t.Fatalf("packet %d ports %d->%d: 554 must appear", n, pkt.L4.SrcPort, pkt.L4.DstPort)
		}
	}
	// 3 握手 + OPTIONS req/resp + DESCRIBE req/resp + 挥手 4 = 11。
	if n != 11 {
		t.Fatalf("packets=%d want 11 (3 hs + 4 dialog + 4 fin)", n)
	}
}

// dialog 必需锚背 door：空 dialog → validator 拒。
func TestChainPlanner_RTSPValidatorAnchors(t *testing.T) {
	p := layers.NewChainPlannerFromChain("rtsp", []layers.Layer{
		{Name: "ip", Config: map[string]interface{}{"src": "10.0.0.1", "dst": "20.0.0.1"}},
		{Name: "rtsp", Config: mustJSONMap(t, `{"dialog": []}`)},
	})
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1"}
	_, err := p.ValidateSpec(spec)
	if err == nil || !contains(err.Error(), "dialog is required") {
		t.Fatalf("want dialog-required anchor, got %v", err)
	}
}
