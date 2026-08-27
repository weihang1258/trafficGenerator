package core

import "testing"

func TestMapToFlowSpecFINSDefaultsPortAndPreservesConfig(t *testing.T) {
	raw := map[string]interface{}{
		"src_ip": "10.0.0.1",
		"dst_ip": "20.0.0.1",
		"fins": map[string]interface{}{
			"transport": "udp",
			"commands": []interface{}{map[string]interface{}{
				"command":     float64(0x0101),
				"memory_area": "dm",
				"address":     float64(100),
				"items":       float64(1),
			}},
		},
	}
	spec := mapToFlowSpec(raw, "fins")
	if spec.DstPort != 9600 {
		t.Fatalf("DstPort = %d, want 9600", spec.DstPort)
	}
	cfg, ok := spec.Metadata["fins"].(map[string]interface{})
	if !ok || cfg["transport"] != "udp" {
		t.Fatalf("metadata fins = %#v, want transport config", spec.Metadata["fins"])
	}
}

func TestMapToFlowSpecFINSPreservesExplicitPort(t *testing.T) {
	spec := mapToFlowSpec(map[string]interface{}{
		"dst_port": float64(19600),
		"fins":     map[string]interface{}{"transport": "tcp"},
	}, "fins")
	if spec.DstPort != 19600 {
		t.Fatalf("DstPort = %d, want explicit 19600", spec.DstPort)
	}
}
