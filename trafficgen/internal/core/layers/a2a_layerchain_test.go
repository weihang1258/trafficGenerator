package layers_test

import (
	"context"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	_ "github.com/trafficgen/trafficgen/internal/protocol/a2a"
)

func TestA2ALayerConfigDrivesChain(t *testing.T) {
	planner := layers.NewChainPlannerFromChain("a2a", []layers.Layer{
		{Name: "ip", Config: map[string]interface{}{"src": "10.0.0.1", "dst": "10.0.0.2"}},
		{Name: "tcp", Config: map[string]interface{}{"src_port": 50000, "dst_port": 8080}},
		{Name: "a2a", Config: map[string]interface{}{
			"baseUrl": "http://agent.example/a2a",
			"tasks": []interface{}{map[string]interface{}{
				"method": "message/send", "requestId": "req-1",
				"message":  map[string]interface{}{"role": "user", "parts": []interface{}{map[string]interface{}{"kind": "text", "text": "hello"}}, "messageId": "m-1", "kind": "message"},
				"response": map[string]interface{}{"result": map[string]interface{}{"id": "task-1", "kind": "task", "status": map[string]interface{}{"state": "completed"}}},
			}},
		}},
	})
	packets, err := planner.Plan(context.Background(), core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 50000, DstPort: 8080})
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

func TestA2ALayerConfigRejectsUnknownNestedField(t *testing.T) {
	raw := []byte(`[{"ip":{"src":"10.0.0.1","dst":"10.0.0.2"}},{"tcp":{"dst_port":8080}},{"a2a":{"tasks":[],"unknown":true}}]`)
	_, err := layers.ValidateLayers(raw, "a2a")
	if err == nil || !strings.Contains(err.Error(), `unknown field "unknown"`) {
		t.Fatalf("ValidateLayers error = %v, want unknown a2a field", err)
	}
}

func TestCheckProtoFlatRejectsA2APresence(t *testing.T) {
	msg := core.CheckProtoFlat("a2a", map[string]interface{}{
		"layers": []interface{}{},
		"a2a":    map[string]interface{}{},
	})
	if msg == "" || !strings.Contains(msg, "top-level a2a sub-config") {
		t.Fatalf("CheckProtoFlat message = %q, want top-level a2a presence rejection", msg)
	}
}
