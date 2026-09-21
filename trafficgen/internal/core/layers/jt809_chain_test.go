package layers_test

// D-JT809-1 P4 链级红例：[ip→jt809] raw 自驱链（十连协议对称）。
// 协议特有：①legacy Plan 硬错——layer_gen 唯一入口=PlanWithConfig；
// ②主链端口=legacy 内部缺省 8812（mapToFlowSpec case 先补，jt808 80 穿透
// 教训移植），从链 8813=生成器合成面；③双 TCP 4 元组同 GroupID（§3 真子流）。
// 配置类型住 core（jt808 先例），嵌套锚=ValidateConfig（planner validator）。

import (
	"context"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	// 触发 jt809 包 init 注册 raw 链生成器 + 校验器。
	_ "github.com/trafficgen/trafficgen/internal/protocol/jt809"
)

func TestChainPlanner_JT809RawChain(t *testing.T) {
	p := layers.NewChainPlannerFromChain("jt809", []layers.Layer{
		{Name: "ip", Config: map[string]interface{}{"src": "10.0.0.1", "dst": "20.0.0.1"}},
		{Name: "jt809", Config: mustJSONMap(t, `{
			"gnss_center_id": 291,
			"initial_sn": 100,
			"procedures": [{"type": "main_login"}, {"type": "main_keepalive"}],
			"slave_procedures": [{"type": "slave_connect"}]
		}`)},
	})
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1"}
	validated, err := p.ValidateSpec(spec)
	if err != nil {
		t.Fatalf("ValidateSpec: %v", err)
	}
	if validated.JT809 == nil {
		t.Fatalf("translate must populate spec.JT809 from the jt809 layer config")
	}
	if len(validated.JT809.Procedures) != 2 || validated.JT809.Procedures[0].Type != "main_login" {
		t.Fatalf("procedures not populated: %+v", validated.JT809.Procedures)
	}
	if len(validated.JT809.SlaveProcedures) != 1 {
		t.Fatalf("slave_procedures not populated: %+v", validated.JT809.SlaveProcedures)
	}
	ch, err := p.Plan(context.Background(), validated)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	n, mainN, slaveN := 0, 0, 0
	groups := map[string]bool{}
	mainMsg, slaveMsg := 0, 0
	for pkt := range ch {
		n++
		if pkt.L4.Protocol != "tcp" {
			t.Fatalf("packet %d proto=%q want tcp", n, pkt.L4.Protocol)
		}
		g, _ := pkt.Metadata["group_id"].(string)
		if g != "" {
			groups[g] = true
		}
		isSlave := pkt.L4.SrcPort == 8813 || pkt.L4.DstPort == 8813
		isMain := pkt.L4.SrcPort == 8812 || pkt.L4.DstPort == 8812
		if isSlave {
			slaveN++
			if len(pkt.Payload) > 0 {
				slaveMsg++
			}
		} else if isMain {
			mainN++
			if len(pkt.Payload) > 0 {
				mainMsg++
			}
		}
	}
	// 主链 8（3 握手+2 消息+3 挥手）+ 从链 7（3+1+3）= 15。
	if n != 15 || mainN != 8 || slaveN != 7 {
		t.Fatalf("packets n=%d main=%d slave=%d, want 15/8/7", n, mainN, slaveN)
	}
	if mainMsg != 2 || slaveMsg != 1 {
		t.Fatalf("message frames main=%d slave=%d, want 2/1", mainMsg, slaveMsg)
	}
	if len(groups) != 1 {
		t.Fatalf("group_id values %d, want 1 (双流同 GroupID)", len(groups))
	}
}

// 背 door 锚：链上 ValidateSpec 经 protocolValidator 调用 ValidateConfig
// （嵌套 procedures V9 不下探——锚点必须落在 planner 校验器）。
func TestChainPlanner_JT809ValidatorAnchors(t *testing.T) {
	p := layers.NewChainPlannerFromChain("jt809", []layers.Layer{
		{Name: "ip", Config: map[string]interface{}{"src": "10.0.0.1", "dst": "20.0.0.1"}},
		{Name: "jt809", Config: mustJSONMap(t, `{
			"gnss_center_id": 1000000000,
			"procedures": [{"type": "main_login"}]
		}`)},
	})
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1"}
	_, err := p.ValidateSpec(spec)
	if err == nil || !contains(err.Error(), "GNSSCenterId 1000000000 > 999999999") {
		t.Fatalf("want gnss overflow anchor, got %v", err)
	}
}
