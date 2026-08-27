package layers_test

import (
	"context"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	_ "github.com/trafficgen/trafficgen/internal/protocol/ike"
)

// 冒烟：ike 终结层接入 [ip→udp→ike] 链。默认 DstPort 500（FieldContract
// udp.dst_port=500）上包；IKE 消息序列（SA_INIT/AUTH）+ ESP 数据面逐数据报
// 事件（tftp 重放模式，生成器复用 legacy Plan）。UDP 无握手，不校验 TCP
// Handshake/Termination。
func TestChainPlannerIKESmoke(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345,
		IKE: &core.IKEConfig{Role: "initiator"},
	}
	v, err := layers.NewChainPlanner("ike").ValidateSpec(spec)
	if err != nil {
		t.Fatalf("ValidateSpec err: %v", err)
	}
	if v.DstPort != 500 {
		t.Fatalf("DstPort=%d, want 500", v.DstPort)
	}
	ch, err := layers.NewChainPlanner("ike").Plan(context.Background(), spec)
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
		t.Fatalf("ike chain produced 0 packets")
	}
	if up == 0 {
		t.Fatalf("ike chain: no up packets")
	}
	if upPort != 500 {
		t.Fatalf("up packet DstPort=%d, want 500 (FieldContract default)", upPort)
	}
}

// 冒烟：nil IKE config → 校验拒绝（legacy 硬要求 spec.ike）。
func TestChainPlannerIKENilRejected(t *testing.T) {
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345}
	_, err := layers.NewChainPlanner("ike").Plan(context.Background(), spec)
	if err == nil {
		t.Fatalf("nil ike config: expected validation error (legacy requires spec.ike)")
	}
}
