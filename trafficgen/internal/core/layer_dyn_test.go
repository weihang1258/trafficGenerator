package core

import "testing"

// T-FTP-7 v3 failing tests (D-FTP-3 §7 step 2): parseLayerDyn from layers array.
func TestParseLayerDyn(t *testing.T) {
	cfg := map[string]any{
		"layers": []any{
			map[string]any{"ip": map[string]any{
				"src": map[string]any{"strategy": "inc", "range": []any{"10.0.1.1", "10.0.1.5"}},
				"dst": "20.0.0.1",
			}},
			map[string]any{"tcp": map[string]any{
				"src_port": map[string]any{"strategy": "inc", "range": []any{20000, 20009}},
				"dst_port": float64(80),
			}},
		},
	}
	spec := mapToFlowSpec(cfg, "tcp")
	if spec.LayerDyn == nil {
		t.Fatal("spec.LayerDyn nil (parseLayerDyn not implemented)")
	}
}

// T-FTP-14 v3 part (D-FTP-3 §5): garbage endpoints are loud ValidationErrors,
// never silent static fallbacks.
func TestParseLayerDyn_InvalidEndpoints(t *testing.T) {
	cases := []struct {
		name   string
		layer  map[string]any
		anchor string
	}{
		{"bad_ip", map[string]any{"ip": map[string]any{"src": map[string]any{"strategy": "inc", "range": []any{"999.1.1.1", "10.0.0.5"}}}}, "invalid IP endpoint"},
		{"bad_mac", map[string]any{"eth": map[string]any{"dst_mac": map[string]any{"strategy": "inc", "range": []any{"zz", "02:00:00:00:00:03"}}}}, "invalid MAC endpoint"},
		{"bad_port", map[string]any{"tcp": map[string]any{"src_port": map[string]any{"strategy": "list", "list": []string{"abc"}}}}, "invalid port endpoint"},
		{"bad_ttl", map[string]any{"ip": map[string]any{"ttl": map[string]any{"strategy": "inc", "range": []any{64, 999}}}}, "invalid ttl endpoint"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec := mapToFlowSpec(map[string]any{"layers": []any{tc.layer}}, "tcp")
			found := false
			for _, e := range spec.ValidationErrors {
				if len(e) >= len(tc.anchor) && containsSub(e, tc.anchor) {
					found = true
				}
			}
			if !found {
				t.Fatalf("want ValidationErrors containing %q, got %v", tc.anchor, spec.ValidationErrors)
			}
		})
	}
}

func containsSub(hay, needle string) bool {
	for i := 0; i+len(needle) <= len(hay); i++ {
		if hay[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

// T-FTP-15 v3 扁平逃生口反例（D-FTP-3 §5）：扁平四键收动态对象 →
// mapToFlowSpec 写 ValidationErrors（worker 预检终态 error），绝不静默缺省。
func TestFlatFourTupleObjectRejected(t *testing.T) {
	for _, k := range []string{"src_ip", "dst_ip", "src_port", "dst_port"} {
		t.Run(k, func(t *testing.T) {
			spec := mapToFlowSpec(map[string]any{
				k: map[string]any{"strategy": "inc", "range": []any{1, 5}},
			}, "tcp")
			found := false
			for _, e := range spec.ValidationErrors {
				if containsSub(e, k) && containsSub(e, "层字段") {
					found = true
				}
			}
			if !found {
				t.Fatalf("want ValidationErrors naming %q with layer-field guide, got %v", k, spec.ValidationErrors)
			}
		})
	}
	// 标量扁平键零回归：无 ValidationErrors。
	spec := mapToFlowSpec(map[string]any{"src_ip": "10.0.0.9", "src_port": float64(12345)}, "tcp")
	if len(spec.ValidationErrors) != 0 {
		t.Fatalf("scalar flat keys must stay clean, got %v", spec.ValidationErrors)
	}
}
