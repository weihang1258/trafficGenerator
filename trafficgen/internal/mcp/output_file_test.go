package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 数据获取工具的 output_path（用户裁定）：
//   - 大模型自己决定"返回数据"还是"写文件"——大数据量写文件，避免撑爆
//     模型上下文；
//   - 路径由大模型按其工作环境指定（服务器侧绝对路径）；
//   - 回执只带 {written_to, bytes, download_url?}，HTTP 传输时 download_url
//     是实时生成的绝对链接（/downloads/exports/<uuid>），stdio 剥除。

func TestOutputPathWritesFile(t *testing.T) {
	srv := newTransportTestServer(t)
	out := filepath.Join(t.TempDir(), "sub", "flows.json")

	_, outData, err := srv.handleManagePcaps(context.Background(), nil, managePcapsInput{
		Action: "list", OutputPath: out,
	})
	if err != nil {
		t.Fatalf("manage_pcaps with output_path: %v", err)
	}
	m := outData.Data.(map[string]interface{})
	if m["written_to"] != out {
		t.Errorf("receipt written_to = %v, want %s", m["written_to"], out)
	}
	if n, _ := m["bytes"].(float64); n <= 0 {
		t.Errorf("receipt bytes = %v, want > 0", m["bytes"])
	}
	if _, has := m["items"]; has {
		t.Errorf("response must not inline the data when output_path is set")
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("file not written: %v", err)
	}
	var parsed interface{}
	if err := json.Unmarshal(b, &parsed); err != nil {
		t.Fatalf("file is not valid JSON: %v", err)
	}
	// 父目录不存在时自动创建（sub/ 由 MkdirAll 落地）。
}

func TestOutputPathRejectsRelativeAndDirty(t *testing.T) {
	srv := newTransportTestServer(t)
	for _, bad := range []string{"relative/x.json", "/a/../../etc/passwd", ""} {
		if bad == "" {
			continue // 空 = 不写文件，合法
		}
		_, _, err := srv.handleManagePcaps(context.Background(), nil, managePcapsInput{
			Action: "list", OutputPath: bad,
		})
		if err == nil {
			t.Errorf("output_path %q must be rejected", bad)
		}
	}
}

func TestExportsEndpointServesRegisteredFile(t *testing.T) {
	srv := newTransportTestServer(t)
	out := filepath.Join(t.TempDir(), "big.json")

	_, outData, err := srv.handleManagePcaps(context.Background(), nil, managePcapsInput{
		Action: "list", OutputPath: out,
	})
	if err != nil {
		t.Fatal(err)
	}
	m := outData.Data.(map[string]interface{})
	id, _ := m["export_id"].(string)
	if id == "" {
		t.Fatalf("receipt missing export_id: %v", m)
	}

	hs, err := NewHTTPServer(srv, "127.0.0.1:0", "k", nil)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(hs.srv.Handler)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/downloads/exports/" + id)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("export download status = %d, want 200", resp.StatusCode)
	}
	b, _ := io.ReadAll(resp.Body)
	var parsed interface{}
	if err := json.Unmarshal(b, &parsed); err != nil {
		t.Fatalf("exported bytes not JSON: %v (%s)", err, b)
	}

	// 未注册的 uuid 一律 404（无遍历面）。
	r2, _ := http.Get(ts.URL + "/downloads/exports/00000000-0000-0000-0000-000000000000")
	r2.Body.Close()
	if r2.StatusCode != http.StatusNotFound {
		t.Errorf("unknown export: status = %d, want 404", r2.StatusCode)
	}
	r3, _ := http.Get(ts.URL + "/downloads/exports/..%2Fetc%2Fpasswd")
	r3.Body.Close()
	if r3.StatusCode != http.StatusNotFound {
		t.Errorf("traversal attempt: status = %d, want 404", r3.StatusCode)
	}
}

// 管理任务列表同样支持 output_path（数据获取面统一行为）。
func TestManageTasksOutputPath(t *testing.T) {
	srv := newTransportTestServer(t)
	out := filepath.Join(t.TempDir(), "tasks.json")
	_, outData, err := srv.handleManageTasks(context.Background(), nil, manageTasksInput{
		Action: "list", OutputPath: out,
	})
	if err != nil {
		t.Fatalf("manage_tasks with output_path: %v", err)
	}
	m := outData.Data.(map[string]interface{})
	if m["written_to"] != out {
		t.Errorf("receipt written_to = %v", m["written_to"])
	}
	if _, err := os.Stat(out); err != nil {
		t.Errorf("file missing: %v", err)
	}
}

// ---- 远程优先 + 自动导出阈值（用户裁定 2026-10-03）----
// HTTP 模式的模型不可能知道服务器路径：任何 output_path 都只当文件名，
// 服务端自管目录落盘；未指定时响应超过 maxInlineResponseBytes 自动转
// 文件（省 token），小响应原样内联。stdio 同机，绝对路径语义不变。

func withTempExports(t *testing.T) {
	t.Helper()
	old := exportsRoot
	exportsRoot = filepath.Join(t.TempDir(), "exports")
	t.Cleanup(func() { exportsRoot = old })
}

func httpCtx() context.Context {
	return context.WithValue(context.Background(), httpTransportKey{}, "http://10.10.10.35:8086")
}

func bigPayload(n int) json.RawMessage {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte('a' + i%26)
	}
	return json.RawMessage(b)
}

// 未指定 output_path：超阈值自动转导出文件，回执带绝对 download_url。
func TestAutoExportOversizedResponseHTTP(t *testing.T) {
	withTempExports(t)
	srv := newTransportTestServer(t)
	receipt := srv.maybeExport("list_flows", bigPayload(70000))
	var m map[string]interface{}
	if err := json.Unmarshal(receipt, &m); err != nil {
		t.Fatalf("oversized response must become an export receipt, got: %s", receipt)
	}
	if _, ok := m["export_id"].(string); !ok {
		t.Fatalf("oversized response must become an export receipt: %v", m)
	}
	wt, _ := m["written_to"].(string)
	if !strings.HasPrefix(wt, exportsRoot) || !strings.Contains(filepath.Base(wt), "list_flows-") {
		t.Errorf("written_to = %q, want under %s with label prefix", wt, exportsRoot)
	}
	// 绝对化发生在工具出口的 taskDataForTransport 组合，这里过同一组合。
	adapted := taskDataForTransport(httpCtx(), receipt).(map[string]interface{})
	u, _ := adapted["download_url"].(string)
	if !strings.HasPrefix(u, "http://10.10.10.35:8086/downloads/exports/") {
		t.Errorf("download_url = %q, want absolute link with request base", u)
	}
	if b, err := os.ReadFile(wt); err != nil || len(b) != 70000 {
		t.Errorf("export file: %d bytes, err %v, want 70000", len(b), err)
	}
}

// 阈值内原样内联（不写文件）。
func TestAutoExportUnderThresholdInline(t *testing.T) {
	withTempExports(t)
	srv := newTransportTestServer(t)
	data := json.RawMessage(`{"items":[]}`)
	before := len(exportRegistry.paths) // 注册表是包级全局，前后对账防跨测试污染
	got := srv.maybeExport("list_flows", data)
	if string(got) != string(data) {
		t.Errorf("small response must stay inline, got %s", got)
	}
	if n := len(exportRegistry.paths); n != before {
		t.Errorf("no export must be registered for inline data: %d -> %d", before, n)
	}
}

// stdio：同样自动转文件（同机读 written_to），download_url 被剥除。
func TestAutoExportStdioStripsURL(t *testing.T) {
	withTempExports(t)
	srv := newTransportTestServer(t)
	receipt := srv.maybeExport("list", bigPayload(70000))
	adapted := taskDataForTransport(context.Background(), receipt)
	m := adapted.(map[string]interface{})
	if _, has := m["download_url"]; has {
		t.Errorf("stdio receipt must not carry download_url: %v", m)
	}
	if _, ok := m["written_to"]; !ok {
		t.Errorf("stdio receipt must keep written_to: %v", m)
	}
}

// HTTP 下 output_path 任意值（含相对路径/遍历串）只取文件名，服务端落盘。
func TestOutputPathHTTPAcceptsAnyName(t *testing.T) {
	withTempExports(t)
	srv := newTransportTestServer(t)
	for _, in := range []string{
		"data/exports/flows_47373108.json", // 用户实测被拒的那条调用
		"../../etc/passwd",
		"/var/data/x.json",
	} {
		_, outData, err := srv.handleManagePcaps(httpCtx(), nil, managePcapsInput{
			Action: "list", OutputPath: in,
		})
		if err != nil {
			t.Fatalf("output_path %q: %v", in, err)
		}
		m := outData.Data.(map[string]interface{})
		wt, _ := m["written_to"].(string)
		if wt == "" || strings.Contains(wt, "..") || filepath.Dir(wt) != exportsRoot {
			t.Errorf("output_path %q: written_to = %q, want managed file under %s", in, wt, exportsRoot)
		}
		if u, _ := m["download_url"].(string); !strings.HasPrefix(u, "http://") {
			t.Errorf("output_path %q: download_url = %q, want absolute", in, u)
		}
	}
}

// 无可用文件名的输入在 HTTP 下也拒绝；同名导出互不覆盖。
func TestOutputPathHTTPEdgeNames(t *testing.T) {
	withTempExports(t)
	srv := newTransportTestServer(t)
	for _, bad := range []string{"..", ".", "/", "  "} {
		if _, _, err := srv.handleManagePcaps(httpCtx(), nil, managePcapsInput{
			Action: "list", OutputPath: bad,
		}); err == nil {
			t.Errorf("output_path %q must be rejected", bad)
		}
	}
	_, d1, _ := srv.handleManagePcaps(httpCtx(), nil, managePcapsInput{
		Action: "list", OutputPath: "flows.json"})
	_, d2, _ := srv.handleManagePcaps(httpCtx(), nil, managePcapsInput{
		Action: "list", OutputPath: "flows.json"})
	w1 := d1.Data.(map[string]interface{})["written_to"]
	w2 := d2.Data.(map[string]interface{})["written_to"]
	if w1 == w2 {
		t.Errorf("same-name exports must not clobber: %v", w1)
	}
}

func mustRaw(t *testing.T, v interface{}) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// ---- 阈值边界 / 降级 / 驱逐 / 接线（隔离复审缺口项）----

// 恰好 65536 内联，65537 转导出（"above 64 KB" 逐字节钉死）。
func TestAutoExportExactBoundary(t *testing.T) {
	withTempExports(t)
	srv := newTransportTestServer(t)
	if got := srv.maybeExport("a", bigPayload(65536)); len(got) != 65536 {
		t.Errorf("65536 bytes must stay inline, got %d", len(got))
	}
	receipt := srv.maybeExport("b", bigPayload(65537))
	if len(receipt) >= 65537 || !json.Valid(receipt) {
		t.Fatalf("65537 bytes must export, got %d-byte payload", len(receipt))
	}
}

// 导出写失败（目录不可建）降级内联返回原数据，不报错。
func TestAutoExportDegradesToInlineOnWriteFailure(t *testing.T) {
	blocked := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocked, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	old := exportsRoot
	exportsRoot = filepath.Join(blocked, "sub", "exports") // 父亲是文件，MkdirAll 必败
	t.Cleanup(func() { exportsRoot = old })
	srv := newTransportTestServer(t)
	data := bigPayload(70000)
	if got := srv.maybeExport("a", data); string(got) != string(data) {
		t.Errorf("write failure must degrade to inline original data")
	}
}

// 注册表驱逐时删除受管文件（磁盘有界），exportsRoot 外的 stdio 路径不删。
func TestEvictionDeletesManagedFileOnly(t *testing.T) {
	withTempExports(t)
	oldMax := maxExportEntries
	maxExportEntries = 2
	t.Cleanup(func() { maxExportEntries = oldMax })

	if err := os.MkdirAll(exportsRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	managed := filepath.Join(exportsRoot, "managed.json")
	external := filepath.Join(t.TempDir(), "external.json")
	for _, p := range []string{managed, external} {
		if err := os.WriteFile(p, []byte("{}"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	i1 := registerExport(managed)
	registerExport(external)
	registerExport(filepath.Join(exportsRoot, "third.json")) // 第 3 次注册挤出 managed
	if _, err := os.Stat(managed); !os.IsNotExist(err) {
		t.Errorf("evicted managed file must be removed, err=%v", err)
	}
	if _, err := os.Stat(external); err != nil {
		t.Errorf("external stdio path must survive eviction: %v", err)
	}
	if _, ok := exportRegistry.paths[i1]; ok {
		t.Errorf("evicted id must leave the registry")
	}
}

// suite 超限：PerCase 转导出、summary 计数保持内联。
func TestSuiteDetailAutoExport(t *testing.T) {
	withTempExports(t)
	srv := newTransportTestServer(t)
	res := suiteResult{Total: 200, Pass: 200}
	for i := 0; i < 200; i++ {
		res.PerCase = append(res.PerCase, runCaseOutput{
			CaseID: fmt.Sprintf("case_%04d_of_a_protocol_with_long_name", i),
			Status: "pass",
			Reason: strings.Repeat("x", 500),
		})
	}
	srv.exportSuiteDetail(&res)
	if res.Export == nil {
		t.Fatalf("oversized suite must carry an export receipt")
	}
	if res.PerCase != nil {
		t.Errorf("PerCase must be nil after export")
	}
	if res.Total != 200 || res.Pass != 200 {
		t.Errorf("summary counters must stay inline: %+v", res)
	}
	if u, _ := res.Export["download_url"].(string); !strings.HasPrefix(u, "/downloads/exports/") {
		t.Errorf("receipt download_url = %v", u)
	}

	small := suiteResult{Total: 1, Pass: 1, PerCase: []runCaseOutput{{CaseID: "c", Status: "pass"}}}
	srv.exportSuiteDetail(&small)
	if small.Export != nil || small.PerCase == nil {
		t.Errorf("small suite must stay inline")
	}
}

// 接线：query_layers 无 protocol 过滤的 examples（~310KB）自动转导出。
func TestQueryLayersExamplesAutoExportWiring(t *testing.T) {
	withTempExports(t)
	srv := newTransportTestServer(t)
	_, out, err := srv.handleQueryLayers(httpCtx(), nil, queryLayersInput{Action: "examples"})
	if err != nil {
		t.Fatalf("query_layers examples: %v", err)
	}
	b, _ := json.Marshal(out.Data)
	if !bytes.Contains(b, []byte(`"export_id"`)) || !bytes.Contains(b, []byte(`"download_url"`)) {
		t.Errorf("310KB examples payload must become a receipt, got %d bytes: %.200s", len(b), b)
	}
}

// 导出回执透传 total（P3：回执形态 vs items 形态的信息对齐）。
func TestExportReceiptCarriesTotal(t *testing.T) {
	withTempExports(t)
	srv := newTransportTestServer(t)
	payload := json.RawMessage(`{"total":57,"items":[` + strings.Repeat(`{"x":1},`, 5000) + `{"x":1}]}`)
	receipt := srv.maybeExport("list_flows", payload)
	var m map[string]interface{}
	if err := json.Unmarshal(receipt, &m); err != nil {
		t.Fatalf("receipt: %v", err)
	}
	if n, _ := m["total"].(float64); n != 57 {
		t.Errorf("receipt total = %v, want 57", m["total"])
	}
	// 无 total 的载荷不得带该键。
	r2 := srv.maybeExport("other", bigPayload(70000))
	var m2 map[string]interface{}
	json.Unmarshal(r2, &m2)
	if _, has := m2["total"]; has {
		t.Errorf("payload without total must not gain one")
	}
}
