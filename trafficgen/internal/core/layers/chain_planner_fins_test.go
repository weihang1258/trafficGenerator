package layers_test

import (
	"testing"

	_ "github.com/trafficgen/trafficgen/internal/protocol/fins"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

func TestChainPlannerFINSDefaultsDestinationPort(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 1234,
		Metadata: map[string]interface{}{"fins": map[string]interface{}{"commands": []interface{}{map[string]interface{}{"command": float64(0x0101), "memory_area": "dm", "items": float64(1)}}}},
	}
	validated, err := layers.NewChainPlanner("fins").ValidateSpec(spec)
	if err != nil {
		t.Fatal(err)
	}
	if validated.DstPort != 9600 {
		t.Fatalf("DstPort = %d, want 9600", validated.DstPort)
	}
}
