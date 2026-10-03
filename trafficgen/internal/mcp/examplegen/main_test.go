package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 选例规则：simplest + 贪心字段多样性（每协议 ≤4 条，无新键即止）。
// 仅挑 simplest 会把 headers/body/transactions 等常用定制字段全部隐藏
// （LLM 反馈：http 只有裸 GET 一例，写非默认配置必须再查 schema）。
func TestGeneratePicksDiverseExamples(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, cases []map[string]interface{}) {
		b, _ := json.Marshal(cases)
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mk := func(id string, httpKeys map[string]interface{}, flows int) map[string]interface{} {
		return map[string]interface{}{
			"id": id, "proto": "http", "summary": id,
			"spec_json": map[string]interface{}{
				"layers": []interface{}{
					map[string]interface{}{"ip": map[string]interface{}{"src": "10.0.0.1", "dst": "10.0.0.2"}},
					map[string]interface{}{"tcp": map[string]interface{}{"dst_port": 80}},
					map[string]interface{}{"http": httpKeys},
				},
				"flow_control": map[string]interface{}{"type": "flows", "value": flows},
			},
			"expect": map[string]interface{}{"expect_error": false},
		}
	}
	write("http.json", []map[string]interface{}{
		mk("http_get_baseline", map[string]interface{}{"method": "GET", "uri": "/", "version": "1.1"}, 1),
		mk("http_post_body", map[string]interface{}{"method": "POST", "uri": "/u", "version": "1.1", "body": "hi", "request_headers": map[string]interface{}{"X-A": "b"}}, 1),
		mk("http_keepalive", map[string]interface{}{"method": "GET", "uri": "/", "version": "1.1", "keep_alive": true, "transactions": []interface{}{map[string]interface{}{"method": "GET", "uri": "/2"}}}, 2),
	})

	b, err := Generate(dir)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	var env struct {
		Protocols map[string][]struct {
			CaseID string          `json:"case_id"`
			Config json.RawMessage `json:"config"`
		} `json:"protocols"`
	}
	if err := json.Unmarshal(b, &env); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	exs := env.Protocols["http"]
	if len(exs) < 3 {
		t.Fatalf("http examples = %d, want >=3 (baseline + diversity + multi-flow)", len(exs))
	}
	joined := string(b)
	for _, key := range []string{"request_headers", "\"body\"", "keep_alive", "transactions"} {
		if !strings.Contains(joined, key) {
			t.Errorf("http examples missing demonstration of %s", key)
		}
	}
}
