package core

import (
	"testing"
)

// snmp 顶层 snmp 子映射 presence 判死（mqtt 同款）：translateTerminalConfig
// case "snmp" 落码 + 冒烟例迁层后，此门才有执法对象。空 map 也死。
func TestMapToFlowSpec_TopSNMPSubConfigRejected(t *testing.T) {
	for _, sub := range []any{
		map[string]any{"var_binds": []any{map[string]any{"name": "1.3.6.1.2.1.1.1.0"}}},
		map[string]any{},
	} {
		spec := mapToFlowSpec(map[string]any{
			"layers": []any{map[string]any{"udp": map[string]any{}}, map[string]any{"snmp": map[string]any{}}},
			"snmp":   sub,
		}, "snmp")
		found := false
		for _, e := range spec.ValidationErrors {
			if containsSub(e, "no longer accepts a top-level snmp sub-config") {
				found = true
			}
		}
		if !found {
			t.Fatalf("want top-snmp ValidationError, got %v", spec.ValidationErrors)
		}
	}
}
