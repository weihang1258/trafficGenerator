package layers_test

// D-PPTP-1 P4 链级红例：[ip→pptp] raw 自驱链（四连协议对称：legacy 自建
// TCP+GRE 数据面 wrap，防双换 Direction=up）。控制通道 1723 由 legacy
// Plan :404 缺省。7 锚背 door 由 validator 承接。

import (
	"context"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	// 触发 pptp 包 init 注册 raw 链生成器 + 校验器。
	_ "github.com/trafficgen/trafficgen/internal/protocol/pptp"
)

func TestChainPlanner_PPTPRawChain(t *testing.T) {
	p := layers.NewChainPlannerFromChain("pptp", []layers.Layer{
		{Name: "ip", Config: map[string]interface{}{"src": "10.0.0.1", "dst": "20.0.0.1"}},
		// 数值面经 JSON 往返（getInt float64 面，mustJSONMap 同口径）。
		{Name: "pptp", Config: mustJSONMap(t, `{
			"scenario": "full", "echo": true, "data_frames": 1
		}`)},
	})
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345}
	validated, err := p.ValidateSpec(spec)
	if err != nil {
		t.Fatalf("ValidateSpec: %v", err)
	}
	if validated.PPTP == nil {
		t.Fatalf("translate must populate spec.PPTP from the pptp layer config")
	}
	if !validated.PPTP.Echo {
		t.Fatalf("spec.PPTP.Echo dropped by translate")
	}
	ch, err := p.Plan(context.Background(), validated)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	n := 0
	control := 0
	for pkt := range ch {
		n++
		if pkt.L4.Protocol == "tcp" {
			control++
			if pkt.L4.DstPort != 1723 && pkt.L4.SrcPort != 1723 {
				t.Fatalf("packet %d tcp ports %d->%d: 1723 must appear on control frames", n, pkt.L4.SrcPort, pkt.L4.DstPort)
			}
		}
		// GRE 数据面帧（IP proto 47）无 TCP 端口，不在此断言。
	}
	// full 场景段数以 legacy 实测钉（首跑探形：跑后定值）；下限=控制面
	// 11 帧（3 握手+SCCRQ/SCCRP/OCRQ/OCRP/SLI×5/... 中 TCP 面）+GRE 数据。
	if n < 20 || control < 15 {
		t.Fatalf("packets=%d control=%d want >=20 total / >=15 control", n, control)
	}
}

// 背 door 锚：链上 ValidateSpec 经 protocolValidator 调用 legacy Validate。
func TestChainPlanner_PPTPValidatorAnchors(t *testing.T) {
	p := layers.NewChainPlannerFromChain("pptp", []layers.Layer{
		{Name: "ip", Config: map[string]interface{}{"src": "10.0.0.1", "dst": "20.0.0.1"}},
		{Name: "pptp", Config: mustJSONMap(t, `{"role": "switch"}`)},
	})
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1"}
	_, err := p.ValidateSpec(spec)
	if err == nil || !contains(err.Error(), "invalid pptp role") {
		t.Fatalf("want invalid role anchor, got %v", err)
	}
}
