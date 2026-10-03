package mcp

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	"github.com/trafficgen/trafficgen/internal/replay"
	"github.com/trafficgen/trafficgen/internal/storage"
	"github.com/trafficgen/trafficgen/pkg/config"
	"github.com/trafficgen/trafficgen/pkg/netif"
)

// 任务响应按传输通道适配（v1.1 修订）：
//   - stdio：客户端与服务器同宿，output_config.pcap_path 是直接可用的产物
//     引用（绝对路径）；相对 download_url 无法解析——不返回（恢复直链
//     引入前的行为）。
//   - HTTP：客户端在远端，download_url（免鉴权直链）才是有用句柄——保留。
func newTransportTestServer(t *testing.T) *Server {
	t.Helper()
	sdb, err := storage.NewDB(&config.DatabaseConfig{Type: "sqlite",
		SQLite: config.SQLiteConfig{Path: filepath.Join(t.TempDir(), "tt.db")}})
	if err != nil {
		t.Fatalf("new db: %v", err)
	}
	t.Cleanup(func() { sdb.Close() })

	eng := core.NewEngine(core.EngineConfig{
		ConfigWorkers: 1, PacketWorkers: 1, OutputWorkers: 1,
		BufferSize: 256, QueueSize: 64,
	})
	eng.SetLayerPlannerFactory(layers.BuildLayersPlanner)
	eng.SetBuildFunc(replay.NewBuildFunc(core.NewBuilder().Build))
	if err := eng.Start(); err != nil {
		t.Fatalf("engine start: %v", err)
	}
	t.Cleanup(eng.Stop)

	srv, err := NewServer(&config.MCPConfig{
		Enabled:                true,
		ServiceUserID:          "mcp-service",
		ServiceUserRole:        "user",
		ServiceAccountPassword: "tt-pw",
		AuditLog:               false,
		Transports:             config.MCPTransports{Stdio: false},
	}, eng, sdb, netif.NewManager())
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	return srv
}

func insertCompletedPcapTask(t *testing.T, db *storage.DB, dbUserID, id string) {
	t.Helper()
	oc, _ := json.Marshal(map[string]string{"pcap_path": "/var/lib/trafficgen/pcap/gen.pcap"})
	if err := db.Create(&storage.TaskModel{
		ID: id, UserID: dbUserID, Name: "tt", Protocol: "dns", StrategyIDs: "[]",
		OutputType: "pcap", OutputConfig: string(oc),
		Status: "completed", Progress: 100,
	}).Error; err != nil {
		t.Fatalf("insert task: %v", err)
	}
}

// stdio 调 get_task_progress：无 download_url，路径在 output_config.pcap_path。
func TestGetTaskProgressStdioPath(t *testing.T) {
	srv := newTransportTestServer(t)
	id := "88888888-8888-8888-8888-888888888888"
	insertCompletedPcapTask(t, srv.db, srv.serviceUserID, id)

	_, out, err := srv.handleGetTaskProgress(context.Background(), nil, getTaskProgressInput{TaskID: id})
	if err != nil {
		t.Fatalf("get_task_progress: %v", err)
	}
	m, ok := out.Data.(map[string]interface{})
	if !ok {
		t.Fatalf("data type %T, want object", out.Data)
	}
	if _, has := m["download_url"]; has {
		t.Errorf("stdio response carries download_url; want stripped (same-host client uses output_config.pcap_path)")
	}
	oc, ok := m["output_config"].(map[string]interface{})
	if !ok || oc["pcap_path"] != "/var/lib/trafficgen/pcap/gen.pcap" {
		t.Errorf("output_config.pcap_path missing or wrong: %v", m["output_config"])
	}

	// 同一任务走 HTTP ctx：download_url 必须保留，且带下载方法指引
	//（模型读到相对路径时无需二次猜测怎么取文件）。
	_, outH, err := srv.handleGetTaskProgress(
		context.WithValue(context.Background(), httpTransportKey{}, true), nil, getTaskProgressInput{TaskID: id})
	if err != nil {
		t.Fatalf("get_task_progress(http): %v", err)
	}
	mH := outH.Data.(map[string]interface{})
	if got, _ := mH["download_url"].(string); got != "/downloads/tasks/"+id+"/pcap" {
		t.Errorf("http response download_url = %q", got)
	}
	howto, _ := mH["download_howto"].(string)
	if !strings.Contains(howto, id) || !strings.Contains(howto, "curl") {
		t.Errorf("http response download_howto missing/unactionable: %q", howto)
	}
}

// taskDataForTransport 形状适配：单任务对象与列表逐项处理。
func TestTaskDataForTransportShapes(t *testing.T) {
	raw := json.RawMessage(`{"download_url":"/d/1","status":"completed"}`)
	stdio := taskDataForTransport(context.Background(), raw)
	m := stdio.(map[string]interface{})
	if _, has := m["download_url"]; has {
		t.Errorf("stdio single task: download_url not stripped")
	}
	if m["status"] != "completed" {
		t.Errorf("sibling fields lost")
	}

	// 列表真实形状：{items:[task...], total} 信封——逐项剥除。
	list := json.RawMessage(`{"items":[{"download_url":"/d/1"},{"download_url":"/d/2","status":"running"}],"total":2}`)
	stdioList := taskDataForTransport(context.Background(), list)
	items := stdioList.(map[string]interface{})["items"].([]interface{})
	for i, e := range items {
		if _, has := e.(map[string]interface{})["download_url"]; has {
			t.Errorf("stdio list item %d: download_url not stripped", i)
		}
	}

	httpCtx := context.WithValue(context.Background(), httpTransportKey{}, true)
	if _, has := taskDataForTransport(httpCtx, raw).(map[string]interface{})["download_url"]; !has {
		t.Errorf("http single task: download_url stripped, want kept")
	}
	// stdio 形态也不得泄漏指引字段。
	if _, has := m["download_howto"]; has {
		t.Errorf("stdio single task: download_howto present, want stripped")
	}
}
