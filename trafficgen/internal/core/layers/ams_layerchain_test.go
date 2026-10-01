package layers_test

import (
	"context"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	_ "github.com/trafficgen/trafficgen/internal/protocol/ams"
)

func TestAMSLayerConfigDrivesChain(t *testing.T) {
	planner := layers.NewChainPlannerFromChain("ams", []layers.Layer{
		{Name: "ip", Config: map[string]interface{}{"src": "10.0.0.1", "dst": "10.0.0.2"}},
		{Name: "tcp", Config: map[string]interface{}{"src_port": 50000, "dst_port": 61616}},
		{Name: "ams", Config: map[string]interface{}{"profile": "ams_management_v1"}},
	})
	packets, err := planner.Plan(context.Background(), core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 50000, DstPort: 61616})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var generated []core.PacketConfig
	for packet := range packets {
		generated = append(generated, packet)
	}
	if len(generated) == 0 {
		t.Fatal("Plan produced no packets")
	}
}
