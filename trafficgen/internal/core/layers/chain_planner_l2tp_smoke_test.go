package layers_test

import (
	"context"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	_ "github.com/trafficgen/trafficgen/internal/protocol/l2tp"
)

// 冒烟：l2tp 终结层接入 [ip→udp→l2tp] 链。默认 DstPort 1701（FieldContract
// udp.dst_port=1701）上包；tunnel_with_data 场景（控制建立 + PPP 数据 +
// 拆除）逐数据报事件（tftp 重放模式，生成器复用 legacy Plan）。UDP 无握手，
// 不校验 TCP Handshake/Termination。
func TestChainPlannerL2TPSmoke(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 1701,
		L2TP: &core.L2TPConfig{Role: "lac", Scenario: "tunnel_with_data"},
	}
	v, err := layers.NewChainPlanner("l2tp").ValidateSpec(spec)
	if err != nil {
		t.Fatalf("ValidateSpec err: %v", err)
	}
	if v.DstPort != 1701 {
		t.Fatalf("DstPort=%d, want 1701", v.DstPort)
	}
	ch, err := layers.NewChainPlanner("l2tp").Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan err: %v", err)
	}
	n, up, down := 0, 0, 0
	for p := range ch {
		n++
		if p.L4.Protocol != "udp" {
			t.Fatalf("L4.Protocol=%s, want udp", p.L4.Protocol)
		}
		if p.Direction == "up" {
			up++
		} else {
			down++
		}
	}
	if n == 0 {
		t.Fatalf("l2tp chain produced 0 packets")
	}
	if up == 0 || down == 0 {
		t.Fatalf("l2tp chain: expected both directions, got up=%d down=%d", up, down)
	}
}

// 冒烟：nil L2TP config → 校验拒绝（legacy Validate 硬要求 spec.l2tp）。
// 验证"校验通过但 0 包"不出现（validator 同步拒绝，生成器为双保险）。
func TestChainPlannerL2TPNilRejected(t *testing.T) {
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 1701}
	_, err := layers.NewChainPlanner("l2tp").Plan(context.Background(), spec)
	if err == nil {
		t.Fatalf("nil l2tp config: expected validation error (legacy requires spec.l2tp)")
	}
}
