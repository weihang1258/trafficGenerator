package layers_test

import (
	"context"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	_ "github.com/trafficgen/trafficgen/internal/protocol/ike_nat_t"
)

// 冒烟：ike_nat_t 终结层接入 [ip→udp→ike_nat_t] 链。默认 DstPort 4500
// （FieldContract udp.dst_port=4500）上包；NAT-T IKE 消息序列逐数据报事件
// （tftp 重放模式，生成器复用 legacy Plan）。UDP 无握手，不校验 TCP
// Handshake/Termination。
func TestChainPlannerIKENATTSmoke(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345,
		IKENATT: &core.IKENATTConfig{},
	}
	v, err := layers.NewChainPlanner("ike_nat_t").ValidateSpec(spec)
	if err != nil {
		t.Fatalf("ValidateSpec err: %v", err)
	}
	if v.DstPort != 4500 {
		t.Fatalf("DstPort=%d, want 4500", v.DstPort)
	}
	ch, err := layers.NewChainPlanner("ike_nat_t").Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan err: %v", err)
	}
	n, up := 0, 0
	var upPort uint16
	for p := range ch {
		n++
		if p.L4.Protocol != "udp" {
			t.Fatalf("L4.Protocol=%s, want udp", p.L4.Protocol)
		}
		if p.Direction == "up" {
			up++
			upPort = p.L4.DstPort
		}
	}
	if n == 0 {
		t.Fatalf("ike_nat_t chain produced 0 packets")
	}
	if up == 0 {
		t.Fatalf("ike_nat_t chain: no up packets")
	}
	if upPort != 4500 {
		t.Fatalf("up packet DstPort=%d, want 4500 (FieldContract default)", upPort)
	}
}

// 冒烟：nil IKENATT config → 校验拒绝（legacy 硬要求 spec.ike_nat_t）。
func TestChainPlannerIKENATTNilRejected(t *testing.T) {
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345}
	_, err := layers.NewChainPlanner("ike_nat_t").Plan(context.Background(), spec)
	if err == nil {
		t.Fatalf("nil ike_nat_t config: expected validation error (legacy requires spec.ike_nat_t)")
	}
}
