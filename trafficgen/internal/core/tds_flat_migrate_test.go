package core

import (
	"testing"
)

// D-TDS-1 红例①maptoflow 侧：在库旧策略顶层 tds → ValidationErrors 恰一条
// （worker 预检终态 error；新建/更新已在 schema 层经 CheckProtoFlat 400）。
// mqtt 先例同款（TestMapToFlowSpec_TopMQTTSubConfigRejected）。修轮 R3：
// 兼容块记一条 + case "tds" 只填 Payload（mqtt 同款分工），故恰一条。
func TestMapToFlowSpec_TopTDSSubConfigRejected(t *testing.T) {
	spec := mapToFlowSpec(map[string]any{
		"tds": map[string]any{"mars": true},
	}, "tds")
	n := 0
	for _, e := range spec.ValidationErrors {
		if containsSub(e, "no longer accepts a top-level tds sub-config") {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("want exactly 1 top-tds ValidationError, got %d (%v)", n, spec.ValidationErrors)
	}
	// 空 map 也死（presence 语义）。
	spec = mapToFlowSpec(map[string]any{"tds": map[string]any{}}, "tds")
	n = 0
	for _, e := range spec.ValidationErrors {
		if containsSub(e, "no longer accepts a top-level tds sub-config") {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("want exactly 1 top-tds ValidationError for empty map, got %d (%v)", n, spec.ValidationErrors)
	}
}
