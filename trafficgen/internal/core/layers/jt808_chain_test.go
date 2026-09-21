package layers_test

// D-JT808-1 P4 链级红例：[ip→jt808] raw 自驱链（九连协议对称）。
// 两点协议特有：①legacy Plan 硬错（曾致 0 包静默完成）——layer_gen
// 唯一入口=PlanWithConfig；②端口=legacy 内部缺省 7611（vnc/pptp 变体，
// 无 DstPort switch case、无协议层端口字段）。配置类型住 core（vnc/xmpp
// 先例），procedures V9 不下探，嵌套锚=ValidateConfig（planner validator）。

import (
	"context"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	// 触发 jt808 包 init 注册 raw 链生成器 + 校验器。
	_ "github.com/trafficgen/trafficgen/internal/protocol/jt808"
)

func TestChainPlanner_JT808RawChain(t *testing.T) {
	p := layers.NewChainPlannerFromChain("jt808", []layers.Layer{
		{Name: "ip", Config: map[string]interface{}{"src": "10.0.0.1", "dst": "20.0.0.1"}},
		{Name: "jt808", Config: mustJSONMap(t, `{
			"phone": "012345678901",
			"initial_sn": 100,
			"auth_code": "ABCDEF1234567890",
			"procedures": [{"type": "register"}, {"type": "auth"}]
		}`)},
	})
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1"}
	validated, err := p.ValidateSpec(spec)
	if err != nil {
		t.Fatalf("ValidateSpec: %v", err)
	}
	if validated.JT808 == nil {
		t.Fatalf("translate must populate spec.JT808 from the jt808 layer config")
	}
	if len(validated.JT808.Procedures) != 2 || validated.JT808.Procedures[0].Type != "register" {
		t.Fatalf("procedures not populated: %+v", validated.JT808.Procedures)
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
		if pkt.L4.DstPort != 7611 && pkt.L4.SrcPort != 7611 {
			t.Fatalf("packet %d ports %d->%d: 7611 must appear", n, pkt.L4.SrcPort, pkt.L4.DstPort)
		}
	}
	// 基线关联：3 握手+2 消息+3 挥手=8。
	if n != 8 {
		t.Fatalf("packets=%d want 8 (3 hs + 2 msg + 3 td)", n)
	}
}

// 背 door 锚：链上 ValidateSpec 经 protocolValidator 调用 ValidateConfig
// （嵌套 procedures V9 不下探——锚点必须落在 planner 校验器）。
func TestChainPlanner_JT808ValidatorAnchors(t *testing.T) {
	p := layers.NewChainPlannerFromChain("jt808", []layers.Layer{
		{Name: "ip", Config: map[string]interface{}{"src": "10.0.0.1", "dst": "20.0.0.1"}},
		{Name: "jt808", Config: mustJSONMap(t, `{
			"phone": "12345678901",
			"procedures": [{"type": "register"}]
		}`)},
	})
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1"}
	_, err := p.ValidateSpec(spec)
	if err == nil || !contains(err.Error(), "must be 12 digits") {
		t.Fatalf("want phone 12-digit anchor, got %v", err)
	}
}
