package layers_test

// D-JTT905-1 P4 链级红例：[ip→jtt905] raw 自驱链（十一连协议对称）。
// 协议特有：①legacy Plan 硬错——layer_gen 唯一入口=PlanWithConfig；
// ②端口=legacy 内部缺省 10700（mapToFlowSpec case 先补，jt808 80 穿透
// 教训移植）。嵌套锚=ValidateConfig（planner validator）。

import (
	"context"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	// 触发 jtt905 包 init 注册 raw 链生成器 + 校验器。
	_ "github.com/trafficgen/trafficgen/internal/protocol/jtt905"
)

func TestChainPlanner_JTT905RawChain(t *testing.T) {
	p := layers.NewChainPlannerFromChain("jtt905", []layers.Layer{
		{Name: "ip", Config: map[string]interface{}{"src": "10.0.0.1", "dst": "20.0.0.1"}},
		{Name: "jtt905", Config: mustJSONMap(t, `{
			"isu_id": "103456789012",
			"initial_sn": 100,
			"heartbeat_count": 1
		}`)},
	})
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1"}
	validated, err := p.ValidateSpec(spec)
	if err != nil {
		t.Fatalf("ValidateSpec: %v", err)
	}
	if validated.JTT905 == nil {
		t.Fatalf("translate must populate spec.JTT905 from the jtt905 layer config")
	}
	if validated.JTT905.ISUId != "103456789012" {
		t.Fatalf("isu_id not populated: %q", validated.JTT905.ISUId)
	}
	ch, err := p.Plan(context.Background(), validated)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	n, msgs := 0, 0
	for pkt := range ch {
		n++
		if pkt.L4.Protocol != "tcp" {
			t.Fatalf("packet %d proto=%q want tcp", n, pkt.L4.Protocol)
		}
		if pkt.L4.DstPort != 10700 && pkt.L4.SrcPort != 10700 {
			t.Fatalf("packet %d ports %d->%d: 10700 must appear", n, pkt.L4.SrcPort, pkt.L4.DstPort)
		}
		if len(pkt.Payload) > 0 {
			msgs++
		}
	}
	// 自动会话：3 握手 + 6 消息 + 3 挥手 = 12。
	if n != 12 || msgs != 6 {
		t.Fatalf("packets n=%d msgs=%d, want 12/6", n, msgs)
	}
}

// 背 door 锚：链上 ValidateSpec 经 protocolValidator 调用 ValidateConfig。
func TestChainPlanner_JTT905ValidatorAnchors(t *testing.T) {
	p := layers.NewChainPlannerFromChain("jtt905", []layers.Layer{
		{Name: "ip", Config: map[string]interface{}{"src": "10.0.0.1", "dst": "20.0.0.1"}},
		{Name: "jtt905", Config: mustJSONMap(t, `{
			"isu_id": "12345678901"
		}`)},
	})
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1"}
	_, err := p.ValidateSpec(spec)
	if err == nil || !contains(err.Error(), "must be 12 digits") {
		t.Fatalf("want isu 12-digit anchor, got %v", err)
	}
}
