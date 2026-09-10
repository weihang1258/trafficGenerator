package core

import "testing"

// T-FTP-15 v3 batch path（D-FTP-3 §5）：batch class 内 layers+扁平四元组混用同样拒绝。
func TestValidateBatchSpec_RejectsLayerFlatConflict(t *testing.T) {
	batch := BatchSpec{Classes: []TrafficClass{{
		ID: "c1", Type: "tcp", FlowCount: 1,
		Config: map[string]any{
			"layers": []any{map[string]any{"tcp": map[string]any{}}},
			"src_ip": "10.0.0.1",
		},
	}}}
	if err := ValidateBatchSpec(batch); err == nil {
		t.Fatal("want mixed-use rejection in batch class, got clean")
	}
}
