package core

import (
	"testing"
)

// D-TFTP-1 P4 红例①maptoflow 侧：在库旧策略顶层 tftp → ValidationErrors
// （worker 预检终态 error；新建/更新已在 schema 层经 CheckProtoFlat 400）。
// mqtt 先例（mqtt_flat_migrate_test.go）同款。空 map 也死（presence 语义）。
func TestMapToFlowSpec_TopTFTPSubConfigRejected(t *testing.T) {
	spec := mapToFlowSpec(map[string]any{
		"tftp": map[string]any{"mode": "read", "filename": "f.bin"},
	}, "tftp")
	found := false
	for _, e := range spec.ValidationErrors {
		if containsSub(e, "rejects a top-level tftp sub-config") {
			found = true
		}
	}
	if !found {
		t.Fatalf("want top-tftp ValidationError, got %v", spec.ValidationErrors)
	}
	// 空 map 也死（presence 语义）。
	spec = mapToFlowSpec(map[string]any{"tftp": map[string]any{}}, "tftp")
	found = false
	for _, e := range spec.ValidationErrors {
		if containsSub(e, "rejects a top-level tftp sub-config") {
			found = true
		}
	}
	if !found {
		t.Fatalf("want top-tftp ValidationError for empty map, got %v", spec.ValidationErrors)
	}
}
