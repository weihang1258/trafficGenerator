package core

import (
	"testing"
)

// D-MQTT-1 步骤 0 红例①maptoflow 侧：在库旧策略顶层 mqtt → ValidationErrors
// （worker 预检终态 error；新建/更新已在 schema 层经 CheckProtoFlat 400）。
// http 族先例同款（TestMapToFlowSpec_TopHTTPSubConfigRejected）。现状：放行。
func TestMapToFlowSpec_TopMQTTSubConfigRejected(t *testing.T) {
	spec := mapToFlowSpec(map[string]any{
		"mqtt": map[string]any{"client_id": "c1"},
	}, "mqtt")
	found := false
	for _, e := range spec.ValidationErrors {
		if containsSub(e, "no longer accepts a top-level mqtt sub-config") {
			found = true
		}
	}
	if !found {
		t.Fatalf("want top-mqtt ValidationError, got %v", spec.ValidationErrors)
	}
	// 空 map 也死（presence 语义）。
	spec = mapToFlowSpec(map[string]any{"mqtt": map[string]any{}}, "mqtt")
	found = false
	for _, e := range spec.ValidationErrors {
		if containsSub(e, "no longer accepts a top-level mqtt sub-config") {
			found = true
		}
	}
	if !found {
		t.Fatalf("want top-mqtt ValidationError for empty map, got %v", spec.ValidationErrors)
	}
}
