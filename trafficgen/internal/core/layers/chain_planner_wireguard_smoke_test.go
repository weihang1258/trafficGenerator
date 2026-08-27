package layers_test

import (
	"context"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	_ "github.com/trafficgen/trafficgen/internal/protocol/wireguard"
)

// 冒烟：nil WireGuard config → 校验放行（Validate 对 nil 返回 nil）+ Plan
// 内默认化（Role=initiator）。验证"校验通过但 0 包"不出现。
func TestChainPlannerWireGuardNilDefaultFlow(t *testing.T) {
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12346}
	ch, err := layers.NewChainPlanner("wireguard").Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan err: %v", err)
	}
	n, upOK := 0, 0
	for p := range ch {
		n++
		if p.L4.Protocol != "udp" {
			t.Fatalf("packet L4=%s, want udp", p.L4.Protocol)
		}
		if p.Direction == "up" && p.L4.DstPort == 51820 {
			upOK++
		}
	}
	if n == 0 {
		t.Fatalf("nil wireguard config produced 0 packets; want default Initiator flow")
	}
	if upOK == 0 {
		t.Fatalf("nil config: no up packet with DstPort=51820 (FieldContract default)")
	}
}

// 冒烟：wireguard 终结层接入 [ip→udp→wireguard] 链。默认 DstPort 51820
// （FieldContract udp.dst_port=51820）上包；Initiation→Response→TransportData
// 逐数据报事件（tftp 重放模式，生成器复用 legacy Plan）。UDP 无握手，不
// 校验 TCP Handshake/Termination。
func TestChainPlannerWireGuardSmoke(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345,
		WireGuard: &core.WireGuardConfig{Role: "initiator"},
	}
	v, err := layers.NewChainPlanner("wireguard").ValidateSpec(spec)
	if err != nil {
		t.Fatalf("ValidateSpec err: %v", err)
	}
	if v.DstPort != 51820 {
		t.Fatalf("DstPort=%d, want 51820", v.DstPort)
	}
	ch, err := layers.NewChainPlanner("wireguard").Plan(context.Background(), spec)
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
		t.Fatalf("wireguard chain produced 0 packets")
	}
	if up == 0 || down == 0 {
		t.Fatalf("wireguard chain: expected both directions, got up=%d down=%d", up, down)
	}
	t.Logf("wireguard chain produced %d packets (%d up, %d down)", n, up, down)
}
