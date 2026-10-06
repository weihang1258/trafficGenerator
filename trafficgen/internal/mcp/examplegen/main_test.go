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
	// 事务例优先（P1-①）后 keepalive（含 transactions）排最前，其键覆盖
	// baseline 全部键时 baseline 不再单独入选——目的是键覆盖，不是条数。
	if len(exs) < 2 {
		t.Fatalf("http examples = %d, want >=2 (tx-first + diversity)", len(exs))
	}
	joined := string(b)
	for _, key := range []string{"request_headers", "\"body\"", "keep_alive", "transactions"} {
		if !strings.Contains(joined, key) {
			t.Errorf("http examples missing demonstration of %s", key)
		}
	}
}

// P1-①（提示词实测 2026-10-06）：dns 默认示例只有 query 没有 response——
// 一问一答才是正常业务。规则：语料含事务例（is_response 等）时 simplest
// 必须从事务档里选；语料只有单向例的协议（如 syslog 类）行为不变。
func TestGeneratePrefersTransactionExamples(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, cases []map[string]interface{}) {
		b, _ := json.Marshal(cases)
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mkProto := func(proto, id string, extra map[string]interface{}) map[string]interface{} {
		return map[string]interface{}{
			"id": id, "proto": proto, "summary": id,
			"spec_json": map[string]interface{}{
				"layers": []interface{}{
					map[string]interface{}{"ip": map[string]interface{}{"src": "10.0.0.1", "dst": "20.0.0.1"}},
					map[string]interface{}{"udp": map[string]interface{}{"dst_port": 53}},
					map[string]interface{}{proto: extra},
				},
			},
			"expect": map[string]interface{}{"expect_error": false},
		}
	}
	write("dns.json", []map[string]interface{}{
		// 最简（键最少）但是纯请求的半边场景
		mkProto("dns", "dns_query_only", map[string]interface{}{"name": "a.com"}),
		// 键更多，但携带响应语义 = 正常业务场景
		mkProto("dns", "dns_query_response", map[string]interface{}{"name": "a.com", "is_response": true, "response_ip": "1.2.3.4"}),
	})
	write("syslog.json", []map[string]interface{}{ // 只有单向例的协议：行为必须不变
		mkProto("syslog", "syslog_one_way", map[string]interface{}{"name": "msg"}),
	})

	b, err := Generate(dir)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	var env struct {
		Protocols map[string][]struct {
			CaseID string `json:"case_id"`
		} `json:"protocols"`
	}
	if err := json.Unmarshal(b, &env); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got := env.Protocols["dns"][0].CaseID; got != "dns_query_response" {
		t.Errorf("dns first example = %q, want the transaction example dns_query_response", got)
	}
	if got := env.Protocols["syslog"][0].CaseID; got != "syslog_one_way" {
		t.Errorf("one-way-only protocol first example = %q, want unchanged selection", got)
	}
}

// P1-②：示例照抄 + flows>1 必报错（静态四元组被拒）。规则：示例集必须
// 含至少一个多流正例——它必然已把变化字段写成动态 strategy 对象。
func TestGenerateIncludesMultiFlowExample(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, cases []map[string]interface{}) {
		b, _ := json.Marshal(cases)
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	cases := []map[string]interface{}{
		{"id": "sn_single", "proto": "snmp", "summary": "s",
			"spec_json": map[string]interface{}{
				"layers": []interface{}{
					map[string]interface{}{"ip": map[string]interface{}{"src": "10.0.0.1", "dst": "10.0.0.2"}},
					map[string]interface{}{"udp": map[string]interface{}{"dst_port": 161}},
					map[string]interface{}{"snmp": map[string]interface{}{"community": "public"}},
				},
			},
			"expect": map[string]interface{}{"expect_error": false}},
		// 多流例：src 是动态 strategy 对象（真实多流例的形状）
		{"id": "sn_multiflow", "proto": "snmp", "summary": "m",
			"spec_json": map[string]interface{}{
				"layers": []interface{}{
					map[string]interface{}{"ip": map[string]interface{}{"src": map[string]interface{}{"strategy": "rand", "range": []interface{}{"10.0.1.1", "10.0.1.9"}}, "dst": "10.0.0.2"}},
					map[string]interface{}{"udp": map[string]interface{}{"dst_port": 161}},
					map[string]interface{}{"snmp": map[string]interface{}{"community": "public"}},
				},
				"flow_control": map[string]interface{}{"type": "flows", "value": 50},
			},
			"expect": map[string]interface{}{"expect_error": false}},
	}
	write("snmp.json", cases)

	b, err := Generate(dir)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if !strings.Contains(string(b), "sn_multiflow") {
		t.Error("examples must include a verified multi-flow example (dynamic strategy fields)")
	}
}
