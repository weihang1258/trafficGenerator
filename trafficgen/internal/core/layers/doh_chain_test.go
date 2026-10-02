package layers_test

import (
	"context"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	_ "github.com/trafficgen/trafficgen/internal/protocol/doh"
)

func TestDOHChainLayerConfigTranslates(t *testing.T) {
	p := layers.NewChainPlannerFromChain("doh", []layers.Layer{
		{Name: "ip", Config: map[string]interface{}{"src": "10.0.0.1", "dst": "10.0.0.2"}},
		{Name: "tcp", Config: map[string]interface{}{"src_port": 40000, "dst_port": 80}},
		{Name: "http", Config: map[string]interface{}{}},
		{Name: "doh", Config: map[string]interface{}{
			"method": "POST", "uri": "/dns-query",
			"sessions": []interface{}{map[string]interface{}{
				"events": []interface{}{map[string]interface{}{
					"kind": "query", "dns_id": 4242, "name": "www.example.com", "qtype": "A",
				}},
			}},
		}},
	})
	spec, err := p.ValidateSpec(core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 40000, DstPort: 80})
	if err != nil {
		t.Fatalf("ValidateSpec: %v", err)
	}
	if spec.DOH == nil || len(spec.DOH.Sessions) != 1 || spec.DOH.Method != "POST" {
		t.Fatalf("layer config was not translated: %+v", spec.DOH)
	}
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	count := 0
	for pkt := range ch {
		count++
		if pkt.L4.Protocol != "tcp" {
			t.Fatalf("unexpected DoH transport: %+v", pkt)
		}
	}
	if count == 0 {
		t.Fatal("Plan produced no DoH packets")
	}
}
