package core

import (
	"testing"
)

// D-TLS-1 步骤 2 locking：tls 层 sni 动态对象 → parse 出值（failing 先行
// 红例的落盘版：allowlist 无 tls 行时本测试红）。
func TestTLSSNIDyn_ListParsed(t *testing.T) {
	spec := mapToFlowSpec(map[string]any{"layers": []any{
		map[string]any{"tls": map[string]any{
			"sni": map[string]any{"strategy": "list", "list": []string{"a.com", "b.com"}},
		}},
	}}, "tls")
	if spec.LayerDyn == nil || spec.LayerDyn.TLS.SNI == nil {
		t.Fatalf("want LayerDyn.TLS.SNI parsed, got %+v (errs=%v)", spec.LayerDyn, spec.ValidationErrors)
	}
	if got := ResolveStringValue(spec.LayerDyn.TLS.SNI, 1); got != "b.com" {
		t.Fatalf("index1 sni = %q, want b.com", got)
	}
}

// D-TLS-1 步骤 2 locking：关字段（alpn/version/role）对象不进 LayerDyn
// （allowlist 关门；create 期由 checkLayerDynObjects 报 does not support
// dynamic，本函数侧断言"无回填、无崩"——http TestHTTPLayerDyn_ClosedFieldsRejected 同款）。
func TestTLSSNIDyn_ClosedFieldsRejected(t *testing.T) {
	for _, f := range []string{"alpn", "version", "role"} {
		t.Run(f, func(t *testing.T) {
			spec := mapToFlowSpec(map[string]any{"layers": []any{
				map[string]any{"tls": map[string]any{
					f: map[string]any{"strategy": "list", "list": []string{"a", "b"}},
				}},
			}}, "tls")
			if spec.LayerDyn != nil && spec.LayerDyn.HasAny() {
				t.Fatalf("closed field %s must not parse into LayerDyn", f)
			}
		})
	}
}

// D-TLS-1 步骤 2 locking：sni string 面 inc/rand 拒绝（http 裁定表 F 同款锚词）。
func TestTLSSNIDyn_StringSurfaceRejected(t *testing.T) {
	for _, st := range []string{"inc", "rand"} {
		m := map[string]interface{}{"strategy": st, "range": []interface{}{"a", "b"}}
		if msg := CheckLayerDynShape("tls", "sni", m); msg == "" || !containsSub(msg, "not supported for string field") {
			t.Fatalf("tls/sni/%s: want string-surface rejection, got %q", st, msg)
		}
	}
}

// D-TLS-1 步骤 2 locking：worker 回填 sni 进 spec.TLS（spec.TLS nil 则建）。
func TestTLSSNIDyn_ResolveBackfillsSpecTLS(t *testing.T) {
	spec := mapToFlowSpec(map[string]any{"layers": []any{
		map[string]any{"tls": map[string]any{
			"sni": map[string]any{"strategy": "list", "list": []string{"a.com", "b.com"}},
		}},
	}}, "tls")
	resolveLayerTuple(&spec, 1)
	if spec.TLS == nil || spec.TLS.SNI != "b.com" {
		t.Fatalf("resolveLayerTuple sni = %+v, want b.com", spec.TLS)
	}
	// 空解析 no-op：fixed 空串不写
	spec2 := mapToFlowSpec(map[string]any{"layers": []any{
		map[string]any{"tls": map[string]any{
			"sni": map[string]any{"strategy": "fixed", "value": ""},
		}},
	}}, "tls")
	resolveLayerTuple(&spec2, 0)
	if spec2.TLS != nil && spec2.TLS.SNI != "" {
		t.Fatalf("empty fixed sni must be no-op, got %+v", spec2.TLS)
	}
}
