package schema

import (
	"strings"
	"testing"
)

// T-FTP-15 v3（D-FTP-3 §7 step 1）：混用拒绝 + 层链静态复制。
func TestStrategyMixedUseRejected(t *testing.T) {
	mixed := []struct {
		name string
		cfg  map[string]any
	}{
		{"src_ip", map[string]any{"layers": []any{map[string]any{"tcp": map[string]any{}}}, "src_ip": "10.0.0.1"}},
		{"dst_ip", map[string]any{"layers": []any{map[string]any{"tcp": map[string]any{}}}, "dst_ip": "20.0.0.1"}},
		{"src_port", map[string]any{"layers": []any{map[string]any{"tcp": map[string]any{}}}, "src_port": float64(12345)}},
		{"dst_port", map[string]any{"layers": []any{map[string]any{"tcp": map[string]any{}}}, "dst_port": float64(80)}},
	}
	for _, tc := range mixed {
		t.Run(tc.name, func(t *testing.T) {
			_, errs := ValidateStrategy("synth", "tcp", tc.cfg, &FlowControl{Type: "flows", Value: 1})
			if len(errs) == 0 {
				t.Fatalf("want mixed-use rejection for %s, got clean", tc.name)
			}
			if !strings.Contains(errs[0].Message, "rejects flat config field") {
				t.Fatalf("wrong message: %v", errs)
			}
		})
	}
	// pure layers (no flat keys) passes mixed-use gate
	_, errs := ValidateStrategy("synth", "", map[string]any{
		"layers": []any{map[string]any{"tcp": map[string]any{}}, map[string]any{"http": map[string]any{}}},
	}, &FlowControl{Type: "flows", Value: 3})
	for _, e := range errs {
		if strings.Contains(e.Message, "mixes layers with flat") {
			t.Fatalf("pure layers must not trip mixed-use: %v", errs)
		}
	}
}

// T-FTP-15 v3 ⑤⑥：层链静态复制——显式标量+flows>1 拒绝；改对象通过；全缺省层通过。
func TestLayerChainStaticCopy(t *testing.T) {
	// ⑤ reject
	_, errs := ValidateStrategy("synth", "", map[string]any{
		"layers": []any{map[string]any{"ip": map[string]any{"src": "10.0.0.1"}}, map[string]any{"tcp": map[string]any{}}},
	}, &FlowControl{Type: "flows", Value: 3})
	found := false
	for _, e := range errs {
		if strings.Contains(e.Message, "static four-tuple") {
			found = true
		}
	}
	if !found {
		t.Fatalf("⑤ want layer static-copy rejection, got %v", errs)
	}
	// ⑥ dynamic object escapes
	_, errs = ValidateStrategy("synth", "", map[string]any{
		"layers": []any{map[string]any{"ip": map[string]any{"src": map[string]any{"strategy": "inc", "range": []any{"10.0.1.1", "10.0.1.5"}}}}},
	}, &FlowControl{Type: "flows", Value: 3})
	for _, e := range errs {
		if strings.Contains(e.Message, "static four-tuple") {
			t.Fatalf("⑥ dynamic object must escape: %v", errs)
		}
	}
	// ④ all-default layers pass
	_, errs = ValidateStrategy("synth", "", map[string]any{
		"layers": []any{map[string]any{"tcp": map[string]any{}}, map[string]any{"http": map[string]any{}}},
	}, &FlowControl{Type: "flows", Value: 3})
	for _, e := range errs {
		if strings.Contains(e.Message, "static four-tuple") {
			t.Fatalf("④ all-default layers must pass: %v", errs)
		}
	}
}
