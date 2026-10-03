package rest

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/storage"
	"github.com/trafficgen/trafficgen/pkg/config"
)

func newRESTTestDB(t *testing.T) *storage.DB {
	t.Helper()
	db, err := storage.NewDB(&config.DatabaseConfig{Type: "sqlite",
		SQLite: config.SQLiteConfig{Path: filepath.Join(t.TempDir(), "auto_reg.db")}})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// 任务 pcap 自动注册资产库（v1.1 用户裁定）：
//   - output_type=pcap 且 completed 的任务，产物 ≤ PcapAutoImportMaxBytes 时
//     自动导入资产库（解析入库），task.PcapAssetID 记录资产 id；
//   - 超阈值：不自动注册（防止大文件解析阻塞完成回调），task.PcapAssetNote
//     说明原因并给出主动注册指引（flowb_manage_pcaps action=import）；
//   - 非 pcap / 非 completed / 已注册：no-op。
func TestAutoRegisterTaskPcap(t *testing.T) {
	sdb := newRESTTestDB(t)
	pcapPath := filepath.Join(t.TempDir(), "gen.pcap")
	writePcapForREST(t, pcapPath)
	task := &storage.TaskModel{
		ID: "aaaaaaaa-1111-1111-1111-111111111111", UserID: "u1", Name: "t",
		Protocol: "tcp", OutputType: "pcap", Status: "completed", Progress: 100,
		OutputConfig: `{"pcap_path":"` + pcapPath + `"}`,
	}
	p := NewPcapHandler(sdb, "")

	AutoRegisterTaskPcap(sdb, p, task)

	if task.PcapAssetID == "" {
		t.Fatalf("asset id not recorded on task (note=%q)", task.PcapAssetNote)
	}
	var asset storage.PcapAssetModel
	if err := sdb.Where("id = ?", task.PcapAssetID).First(&asset).Error; err != nil {
		t.Fatalf("asset row missing: %v", err)
	}
	if asset.Status != "ready" {
		t.Errorf("asset status = %q, want ready (err=%q)", asset.Status, asset.ParseError)
	}
	if asset.UserID != task.UserID {
		t.Errorf("asset owner = %q, want task owner %q", asset.UserID, task.UserID)
	}

	// 幂等：二次调用不重复注册。
	before := task.PcapAssetID
	AutoRegisterTaskPcap(sdb, p, task)
	if task.PcapAssetID != before {
		t.Errorf("re-register changed asset id %q -> %q", before, task.PcapAssetID)
	}
}

func TestAutoRegisterTaskPcap_SkipsOverThreshold(t *testing.T) {
	sdb := newRESTTestDB(t)
	pcapPath := filepath.Join(t.TempDir(), "big.pcap")
	if err := os.WriteFile(pcapPath, make([]byte, 128), 0o644); err != nil {
		t.Fatal(err)
	}
	task := &storage.TaskModel{
		ID: "aaaaaaaa-2222-2222-2222-222222222222", UserID: "u1", Name: "t",
		Protocol: "tcp", OutputType: "pcap", Status: "completed", Progress: 100,
		OutputConfig: `{"pcap_path":"` + pcapPath + `"}`,
	}
	p := NewPcapHandler(sdb, "")

	old := PcapAutoImportMaxBytes
	PcapAutoImportMaxBytes = 64
	defer func() { PcapAutoImportMaxBytes = old }()

	AutoRegisterTaskPcap(sdb, p, task)

	if task.PcapAssetID != "" {
		t.Errorf("over-threshold file must not auto-register, got asset %q", task.PcapAssetID)
	}
	for _, want := range []string{"exceeds", "flowb_manage_pcaps", "import", pcapPath} {
		if !strings.Contains(task.PcapAssetNote, want) {
			t.Errorf("skip note missing %q: %s", want, task.PcapAssetNote)
		}
	}
	var n int64
	sdb.Model(&storage.PcapAssetModel{}).Count(&n)
	if n != 0 {
		t.Errorf("asset rows = %d, want 0", n)
	}
}

func TestAutoRegisterTaskPcap_NoOpGuards(t *testing.T) {
	sdb := newRESTTestDB(t)
	p := NewPcapHandler(sdb, "")
	for _, tc := range []struct {
		name string
		task storage.TaskModel
	}{
		{"non-pcap output", storage.TaskModel{ID: "b-1", OutputType: "port_group", Status: "completed", OutputConfig: "{}"}},
		{"failed task", storage.TaskModel{ID: "b-2", OutputType: "pcap", Status: "failed", OutputConfig: "{}"}},
		{"missing pcap_path", storage.TaskModel{ID: "b-3", OutputType: "pcap", Status: "completed", OutputConfig: "{}"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			task := tc.task
			AutoRegisterTaskPcap(sdb, p, &task)
			if task.PcapAssetID != "" || task.PcapAssetNote != "" {
				t.Errorf("expected no-op, got id=%q note=%q", task.PcapAssetID, task.PcapAssetNote)
			}
		})
	}
}

// 任务响应携带资产 id 与提示/跳过原因；已注册时提示语必须点名
// flowb_manage_pcaps（提醒 LLM 可以做报文查看/分析/下载）。
func TestConvertTaskToResponse_PcapAssetFields(t *testing.T) {
	m := func(id, note string) *storage.TaskModel {
		return &storage.TaskModel{ID: "c-1", OutputType: "pcap",
			PcapAssetID: id, PcapAssetNote: note}
	}
	resp := convertTaskToResponse(m("asset-1", ""))
	if resp.PcapAssetID != "asset-1" {
		t.Errorf("pcap_asset_id = %q", resp.PcapAssetID)
	}
	if !strings.Contains(resp.PcapAssetNote, "flowb_manage_pcaps") {
		t.Errorf("registered task hint must point at flowb_manage_pcaps, got %q", resp.PcapAssetNote)
	}
	resp2 := convertTaskToResponse(m("", "exceeds threshold"))
	if resp2.PcapAssetID != "" || resp2.PcapAssetNote != "exceeds threshold" {
		t.Errorf("skip reason passthrough broken: %q / %q", resp2.PcapAssetID, resp2.PcapAssetNote)
	}
}

// 资产免鉴权直链：/downloads/pcaps/:id/download —— 资产 UUID 即能力凭证；
// 仅 ready 资产可下；未知名/非 ready/缺失文件一律 404。
func TestServePcapPublic(t *testing.T) {
	sdb := newRESTTestDB(t)
	dir := t.TempDir()
	pcapFile := filepath.Join(dir, "asset.pcap")
	writePcapForREST(t, pcapFile)
	asset := &storage.PcapAssetModel{
		ID: "asset-22222222", UserID: "u1", Name: "asset.pcap",
		OriginalFilename: "asset.pcap", StoragePath: pcapFile,
		FileHash: "hash-ready", FileSize: 128, Status: "ready",
	}
	if err := sdb.Create(asset).Error; err != nil {
		t.Fatal(err)
	}
	notReady := &storage.PcapAssetModel{
		ID: "asset-33333333", UserID: "u1", Name: "n.pcap",
		StoragePath: pcapFile, FileHash: "hash-importing", Status: "importing",
	}
	if err := sdb.Create(notReady).Error; err != nil {
		t.Fatal(err)
	}

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ServePcapPublic(sdb, w, r)
	})
	srv := httptest.NewServer(h)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/downloads/pcaps/asset-22222222/download")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if cd := resp.Header.Get("Content-Disposition"); !strings.Contains(cd, "asset.pcap") {
		t.Errorf("Content-Disposition = %q", cd)
	}

	for _, path := range []string{
		"/downloads/pcaps/asset-33333333/download", // not ready
		"/downloads/pcaps/unknown/download",        // unknown asset
	} {
		r2, _ := http.Get(srv.URL + path)
		r2.Body.Close()
		if r2.StatusCode != http.StatusNotFound {
			t.Errorf("%s: status = %d, want 404", path, r2.StatusCode)
		}
	}
	_ = json.Marshal
}
