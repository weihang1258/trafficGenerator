package layers_test

import (
	"context"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	_ "github.com/trafficgen/trafficgen/internal/protocol/dnp3"
)

func TestDNP3ChainLayerConfigTranslates(t *testing.T) {
	p := layers.NewChainPlannerFromChain("dnp3", []layers.Layer{
		{Name: "ip", Config: map[string]interface{}{"src": "10.0.0.1", "dst": "10.0.0.2"}},
		{Name: "tcp", Config: map[string]interface{}{"src_port": 40000, "dst_port": 20000}},
		{Name: "dnp3", Config: map[string]interface{}{
			"link_type": "master", "transport": "tcp", "app_func": "read",
			"objects": []interface{}{map[string]interface{}{"object_type": 1, "variation": 2, "qualifier": 6, "count": 1, "points": []interface{}{map[string]interface{}{"value": 1}}}},
		}},
	})
	spec, err := p.ValidateSpec(core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 40000, DstPort: 20000})
	if err != nil {
		t.Fatalf("ValidateSpec: %v", err)
	}
	if spec.DNP3 == nil || spec.DNP3.AppFunc != "read" {
		t.Fatalf("layer config was not translated: %+v", spec.DNP3)
	}
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	count := 0
	for pkt := range ch {
		count++
		if pkt.L4.Protocol != "tcp" {
			t.Fatalf("unexpected DNP3 transport: %+v", pkt)
		}
	}
	if count == 0 {
		t.Fatal("Plan produced no DNP3 packets")
	}
}
