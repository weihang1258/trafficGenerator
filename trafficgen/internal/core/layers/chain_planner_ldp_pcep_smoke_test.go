package layers_test

import (
	"context"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	_ "github.com/trafficgen/trafficgen/internal/protocol/ldp"
	_ "github.com/trafficgen/trafficgen/internal/protocol/pcep"
)

// 冒烟：ldp/pcep 层链接线（main.go 空导入 + 注册后 init 反向注册生成器/校验器，
// NewChainPlanner 能实例化并产包）。默认端口来自各包默认（ldp 646 / pcep 4189），
// 链式合成路径无 FieldContract 强制。
func TestChainPlannerLDPSmoke(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 646,
		LDP: &core.LDPConfig{
			Transport: "udp", LSRID: "10.0.0.1", LabelSpace: 0,
			Events: []core.LDPEvent{{Kind: "hello", Direction: "c2s"}},
		},
	}
	v, err := layers.NewChainPlanner("ldp").ValidateSpec(spec)
	if err != nil {
		t.Fatalf("ValidateSpec err: %v", err)
	}
	ch, err := layers.NewChainPlanner("ldp").Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan err: %v", err)
	}
	n, upOK := 0, 0
	for p := range ch {
		if p.Direction == "up" && (p.L4.DstPort == 646 || v.DstPort == 646) {
			upOK++
		}
		n++
	}
	if n == 0 {
		t.Fatalf("ldp chain produced 0 packets")
	}
	if upOK == 0 {
		t.Fatalf("ldp chain: no up packet with default DstPort 646")
	}
	t.Logf("ldp chain produced %d packets (%d up@646)", n, upOK)
}

func TestChainPlannerPCEPSmoke(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 1234,
		PCEP: &core.PCEPConfig{
			Transport: "tcp",
			Events:    []core.PCEPEvent{{Kind: "open", Direction: "c2s", SID: 7}},
		},
	}
	ch, err := layers.NewChainPlanner("pcep").Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan err: %v", err)
	}
	n, upOK := 0, 0
	for p := range ch {
		if p.Direction == "up" && p.L4.DstPort == 4189 {
			upOK++
		}
		n++
	}
	if n == 0 {
		t.Fatalf("pcep chain produced 0 packets")
	}
	if upOK == 0 {
		t.Fatalf("pcep chain: no up packet with default DstPort 4189")
	}
	t.Logf("pcep chain produced %d packets (%d up@4189)", n, upOK)
}
