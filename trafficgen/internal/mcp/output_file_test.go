package mcp

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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
