package core

import (
	"testing"
)

// D-GBT32960 P4 红例①maptoflow 侧：在库旧策略顶层 gbt32960 → ValidationErrors
// 恰一条（worker 预检终态 error；新建/更新已在 schema 层经 CheckProtoFlat 400）。
// tds 先例同款（TestMapToFlowSpec_TopTDSSubConfigRejected）。
func TestMapToFlowSpec_TopGBT32960SubConfigRejected(t *testing.T) {
	spec := mapToFlowSpec(map[string]any{
		"gbt32960": map[string]any{"vin": "LXXXXXXXXXXXXXXX1"},
	}, "gbt32960")
	n := 0
	for _, e := range spec.ValidationErrors {
		if containsSub(e, "rejects a top-level gbt32960 sub-config") {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("want exactly 1 top-gbt32960 ValidationError, got %d (%v)", n, spec.ValidationErrors)
	}
	// 空 map 也死（presence 语义）。
	spec = mapToFlowSpec(map[string]any{"gbt32960": map[string]any{}}, "gbt32960")
	n = 0
	for _, e := range spec.ValidationErrors {
		if containsSub(e, "rejects a top-level gbt32960 sub-config") {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("want exactly 1 top-gbt32960 ValidationError for empty map, got %d (%v)", n, spec.ValidationErrors)
	}
}

// D-GBT32960 P4 红例②：CheckProtoFlat 五键白名单面（游离顶层键判死）。
func TestCheckProtoFlat_GBT32960StrayTopLevelKeys(t *testing.T) {
	for _, k := range []string{"src_ip", "dst_ip", "src_port", "dst_port", "count"} {
		cfg := map[string]any{"layers": []any{}, k: 1}
		msg := CheckProtoFlat("gbt32960", cfg)
		if msg == "" {
			t.Fatalf("CheckProtoFlat(gbt32960, {layers, %s}) = \"\", want flat-field rejection", k)
		}
	}
	// 层链形状（无游离键、无顶层 gbt32960）不触发。
	if msg := CheckProtoFlat("gbt32960", map[string]any{"layers": []any{}}); msg != "" {
		t.Fatalf("CheckProtoFlat(gbt32960, {layers}) = %q, want \"\"", msg)
	}
}
