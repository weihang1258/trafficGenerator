package layers_test

import (
	"context"
	"encoding/json"
	"testing"

	_ "github.com/trafficgen/trafficgen/internal/protocol/s7"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

func TestChainPlannerS7EmptyConfigDefaultFlow(t *testing.T) {
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 1234}
	v, err := layers.NewChainPlanner("s7").ValidateSpec(spec)
	if err != nil {
		t.Fatalf("ValidateSpec err: %v", err)
	}
	if v.DstPort != 102 {
		t.Fatalf("DstPort=%d, want 102", v.DstPort)
	}
	ch, err := layers.NewChainPlanner("s7").Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan err: %v", err)
	}
	n := 0
	upOk := 0
	for p := range ch {
		if p.Direction == "up" && p.L4.DstPort == 102 {
			upOk++
		}
		n++
	}
	if n == 0 {
		t.Fatalf("empty config produced 0 packets; want default flow")
	}
	if upOk == 0 {
		t.Fatalf("no up packet with DstPort=102 (want FieldContract default applied)")
	}
	t.Logf("default flow produced %d packets (%d up@102)", n, upOk)
}

func TestChainPlannerS7UserExplicitPortWins(t *testing.T) {
	// 用户显式写 transport 层 dst_port=103 → 尊重用户值（用户显式 > FieldContract，
	// review P2 修复），产出 103 而非契约默认 102。走 BuildLayersPlanner 生产路径
	// （层数组），合成链路径无用户端口不适用。
	layersJSON := json.RawMessage(`[{"ip":{"src":"10.0.0.1","dst":"20.0.0.1"}},{"tcp":{"dst_port":103}},{"s7":{}}]`)
	pp, err := layers.BuildLayersPlanner("s7", layersJSON)
	if err != nil {
		t.Fatalf("BuildLayersPlanner err: %v", err)
	}
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 1234}
	ch, err := pp.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan err: %v", err)
	}
	n, up103 := 0, 0
	for p := range ch {
		if p.Direction == "up" && p.L4.DstPort == 103 {
			up103++
		}
		n++
	}
	if n == 0 {
		t.Fatalf("user-explicit-port config produced 0 packets")
	}
	if up103 == 0 {
		t.Fatalf("no up packet with DstPort=103 (user explicit port must reach wire, not FieldContract 102)")
	}
}
