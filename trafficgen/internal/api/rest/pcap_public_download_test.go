package rest

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/trafficgen/trafficgen/internal/storage"
	"github.com/trafficgen/trafficgen/pkg/config"
)

// 公开下载直链（v1.1 产物体验）：任务 UUID 即能力凭证——
//   - GET /downloads/tasks/:id/pcap 无需鉴权（外部客户端 curl 直下）
//   - 仅 output_type=pcap 的任务可下载；其余一律 404
//   - 任务响应体（TaskResponse）对 pcap 任务携带相对 download_url

func newPublicDownloadTestEnv(t *testing.T) (*gin.Engine, *storage.DB, string) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	db, err := storage.NewDB(&config.DatabaseConfig{Type: "sqlite",
		SQLite: config.SQLiteConfig{Path: filepath.Join(t.TempDir(), "dl_test.db")}})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	dir := t.TempDir()
	pcapFile := filepath.Join(dir, "gen.pcap")
	// 最小合法 pcap 头（libpcap magic d4c3b2a1 + 一条 4 字节伪帧体）
	content := []byte("\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x01\x00\x00\x00\xaa\xbb\xcc\xdd")
	if err := os.WriteFile(pcapFile, content, 0o644); err != nil {
		t.Fatalf("write pcap: %v", err)
	}
	h := NewPcapHandler(db, dir)
	r := gin.New()
	r.GET("/downloads/tasks/:id/pcap", h.DownloadByTask)
	return r, db, pcapFile
}

func insertTask(t *testing.T, db *storage.DB, id, outputType, pcapPath string) {
	t.Helper()
	oc, _ := json.Marshal(map[string]string{"pcap_path": pcapPath})
	task := &storage.TaskModel{
		ID:           id,
		UserID:       "11111111-1111-1111-1111-111111111111",
		Name:         "dl-test",
		Protocol:     "modbus",
		StrategyIDs:  "[]",
		OutputType:   outputType,
		OutputConfig: string(oc),
		Status:       "completed",
		Progress:     100,
	}
	if err := db.Create(task).Error; err != nil {
		t.Fatalf("insert task: %v", err)
	}
}

// 无鉴权直下：200 + 原始字节 + 附件名。
func TestPublicDownloadByTask_NoAuth(t *testing.T) {
	r, db, pcapFile := newPublicDownloadTestEnv(t)
	insertTask(t, db, "22222222-2222-2222-2222-222222222222", "pcap", pcapFile)

	req := httptest.NewRequest(http.MethodGet, "/downloads/tasks/22222222-2222-2222-2222-222222222222/pcap", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (no auth required): %s", w.Code, w.Body.String())
	}
	want, _ := os.ReadFile(pcapFile)
	if w.Body.String() != string(want) {
		t.Errorf("body != source pcap bytes")
	}
	if cd := w.Header().Get("Content-Disposition"); !strings.Contains(cd, "gen.pcap") {
		t.Errorf("Content-Disposition = %q, want attachment with gen.pcap", cd)
	}
}

// 非 pcap 任务（port_group）与未知任务：一律 404，不落任何文件路径。
func TestPublicDownloadByTask_NonPcapAndUnknown(t *testing.T) {
	r, db, pcapFile := newPublicDownloadTestEnv(t)
	insertTask(t, db, "33333333-3333-3333-3333-333333333333", "port_group", pcapFile)

	for _, id := range []string{
		"33333333-3333-3333-3333-333333333333", // port_group：不可下载
		"44444444-4444-4444-4444-444444444444", // 未知任务
	} {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/downloads/tasks/"+id+"/pcap", nil))
		if w.Code != http.StatusNotFound {
			t.Errorf("task %s: status = %d, want 404", id, w.Code)
		}
	}
}

// 任务响应携带相对 download_url（仅 pcap 任务），MCP 进度透传同一响应体。
func TestConvertTaskToResponse_DownloadURL(t *testing.T) {
	pcapTask := &storage.TaskModel{ID: "55555555-5555-5555-5555-555555555555", OutputType: "pcap", OutputConfig: `{"pcap_path":"/tmp/x.pcap"}`}
	if got := convertTaskToResponse(pcapTask).DownloadURL; got != "/downloads/tasks/55555555-5555-5555-5555-555555555555/pcap" {
		t.Errorf("pcap task download_url = %q", got)
	}
	pgTask := &storage.TaskModel{ID: "66666666-6666-6666-6666-666666666666", OutputType: "port_group", OutputConfig: `{"port_group_id":"g"}`}
	if got := convertTaskToResponse(pgTask).DownloadURL; got != "" {
		t.Errorf("port_group task download_url = %q, want empty", got)
	}
}

// ServeTaskPcapPublic：纯 net/http 共享核心——gin 路由与 MCP HTTP mux
// 双挂载同一实现（外部客户端从任一端口拼 download_url 都可达）。
func TestServeTaskPcapPublic(t *testing.T) {
	r, db, pcapFile := newPublicDownloadTestEnv(t)
	_ = r
	insertTask(t, db, "77777777-7777-7777-7777-777777777777", "pcap", pcapFile)

	h := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		ServeTaskPcapPublic(db, w, req)
	})
	srv := httptest.NewServer(h)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/downloads/tasks/77777777-7777-7777-7777-777777777777/pcap")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if cd := resp.Header.Get("Content-Disposition"); !strings.Contains(cd, "gen.pcap") {
		t.Errorf("Content-Disposition = %q", cd)
	}
	// 非 pcap 任务 → 404
	resp2, _ := http.Get(srv.URL + "/downloads/tasks/00000000-0000-0000-0000-000000000000/pcap")
	if resp2.StatusCode != http.StatusNotFound {
		t.Errorf("unknown task: status = %d, want 404", resp2.StatusCode)
	}
	resp2.Body.Close()
}
