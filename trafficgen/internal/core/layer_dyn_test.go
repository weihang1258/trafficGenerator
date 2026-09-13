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

// D-HTTP-1 重走步骤 0③（failing 先行）：http 层业务字段动态对象 → parse 出值。
func TestHTTPLayerDyn_URIList(t *testing.T) {
	spec := mapToFlowSpec(map[string]any{"layers": []any{
		map[string]any{"http": map[string]any{
			"uri": map[string]any{"strategy": "list", "list": []string{"/a", "/b"}},
		}},
	}}, "http")
	if spec.LayerDyn == nil || spec.LayerDyn.HTTP.URI == nil {
		t.Fatalf("want LayerDyn.HTTP.URI parsed, got %+v (errs=%v)", spec.LayerDyn, spec.ValidationErrors)
	}
	if got := ResolveStringValue(spec.LayerDyn.HTTP.URI, 1); got != "/b" {
		t.Fatalf("index1 uri = %q, want /b", got)
	}
}

// D-HTTP-1 重走步骤 0③补齐：15 关字段对象 → parse 期 ValidationErrors
// （does not support dynamic 经 checkLayerDynObjects 在 ValidateLayers 报 400，
// mapToFlowSpec 侧 parseLayerDyn 不读非 allowlist 键，此处断言“无回填、无崩”）。
func TestHTTPLayerDyn_ClosedFieldsRejected(t *testing.T) {
	closed := []string{"method", "version", "headers", "request_headers", "keep_alive",
		"transactions", "response_headers", "response_status_text",
		"response_content_encoding", "request_content_encoding",
		"request_transfer_encoding", "response_transfer_encoding",
		"chunk_size", "pipelined", "file_source"}
	if len(closed) != 15 {
		t.Fatalf("closed list = %d, want 15 (6-open/21-key invariant)", len(closed))
	}
	for _, f := range closed {
		t.Run(f, func(t *testing.T) {
			spec := mapToFlowSpec(map[string]any{"layers": []any{
				map[string]any{"http": map[string]any{
					f: map[string]any{"strategy": "list", "list": []string{"a", "b"}},
				}},
			}}, "http")
			if spec.LayerDyn != nil && spec.LayerDyn.HasAny() {
				t.Fatalf("closed field %s must not parse into LayerDyn", f)
			}
			if msg := CheckLayerDynShape("http", f, map[string]interface{}{"strategy": "list", "list": []string{"a", "b"}}); msg != "" {
				t.Fatalf("note: closed field shape check = %q (allowlist gate is authoritative)", msg)
			}
		})
	}
}

// D-HTTP-1 重走步骤 0③补齐：string 面 inc/rand 拒绝 + status_code pattern 拒绝。
func TestHTTPLayerDyn_StringSurfaceRejected(t *testing.T) {
	for _, f := range []string{"uri", "body", "body_b64", "response_body", "response_body_b64"} {
		for _, st := range []string{"inc", "rand"} {
			m := map[string]interface{}{"strategy": st, "range": []interface{}{"a", "b"}}
			if msg := CheckLayerDynShape("http", f, m); msg == "" || !containsSub(msg, "not supported for string field") {
				t.Fatalf("%s/%s: want string-surface rejection, got %q", f, st, msg)
			}
		}
	}
	m := map[string]interface{}{"strategy": "pattern", "pattern": "/u{n}", "range": []interface{}{1, 3}}
	if msg := CheckLayerDynShape("http", "response_status_code", m); msg == "" {
		t.Fatal("status_code/pattern: want rejection, got clean")
	}
}

// D-HTTP-1 重走步骤 0③补齐：resolve 回填 6 路（index1 逐值断言）。
func TestHTTPLayerDyn_ResolveBackfill(t *testing.T) {
	mk := func(st string, v interface{}) *StrategyConfig { return &StrategyConfig{Strategy: st, Value: v} }
	list := func(v ...string) *StrategyConfig { return &StrategyConfig{Strategy: "list", List: v} }
	spec := FlowSpec{
		HTTP: &HTTPConfig{},
		LayerDyn: &LayerDynValues{HTTP: LayerHTTPDyn{
			URI:                list("/a", "/b"),
			Body:               mk("fixed", "req"),
			BodyB64:            mk("fixed", "Yg=="),
			ResponseBody:       mk("pattern", nil),
			ResponseBodyB64:    list("eA==", "eQ=="),
			ResponseStatusCode: &StrategyConfig{Strategy: "inc", Range: []interface{}{200, 202}},
		}},
	}
	spec.LayerDyn.HTTP.ResponseBody.Pattern = "/r{n}"
	spec.LayerDyn.HTTP.ResponseBody.Range = []interface{}{1, 5}
	resolveLayerTuple(&spec, 1)
	if spec.HTTP.URI != "/b" {
		t.Fatalf("URI = %q, want /b", spec.HTTP.URI)
	}
	if spec.HTTP.Body != "req" || spec.HTTP.BodyB64 != "Yg==" {
		t.Fatalf("Body = %q BodyB64 = %q", spec.HTTP.Body, spec.HTTP.BodyB64)
	}
	if spec.HTTP.ResponseBody != "/r2" {
		t.Fatalf("ResponseBody = %q, want /r2", spec.HTTP.ResponseBody)
	}
	if spec.HTTP.ResponseBodyB64 != "eQ==" {
		t.Fatalf("ResponseBodyB64 = %q, want eQ==", spec.HTTP.ResponseBodyB64)
	}
	if spec.HTTP.ResponseStatusCode != 201 {
		t.Fatalf("ResponseStatusCode = %d, want 201", spec.HTTP.ResponseStatusCode)
	}
}
