package rest

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	sqlite "github.com/glebarez/sqlite"
	"github.com/gin-gonic/gin"
	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/protocol/tcp"
	"github.com/trafficgen/trafficgen/internal/protocol/udp"
	"github.com/trafficgen/trafficgen/internal/storage"
	"gorm.io/gorm"
)

// TestCreateBatch verifies the mixed-traffic batch endpoint accepts a BatchSpec,
// starts the task, writes packets to a pcap file, and reaches completed status.
func TestCreateBatch(t *testing.T) {
	gin.SetMode(gin.TestMode)

	gormDB, err := gorm.Open(sqlite.Open(t.TempDir()+"/test.db"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := storage.AutoMigrate(gormDB); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	db := &storage.DB{DB: gormDB}

	e := core.NewEngine(core.EngineConfig{
		ConfigWorkers: 1, PacketWorkers: 1, OutputWorkers: 1,
		BufferSize: 256, QueueSize: 64,
	})
	e.RegisterPlanner(tcp.NewPlanner())
	e.RegisterPlanner(udp.NewPlanner())
	e.SetBuildFunc(core.NewBuilder().Build)
	if err := e.Start(); err != nil {
		t.Fatalf("start engine: %v", err)
	}
	defer e.Stop()

	h := NewTaskHandler(db, e, nil)
	r := gin.New()
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.POST("/tasks/batch", h.CreateBatch)

	pcapPath := t.TempDir() + "/batch.pcap"
	body := `{"name":"batch-test","batch":{"classes":[` +
		`{"id":"tcp","type":"tcp","flow_count":2,"config":{"src_ip":"10.0.0.1","dst_ip":"10.0.0.2","tcp":{"handshake":true,"termination":true}},"tuples":{"src_ip":{"strategy":"fixed","value":"10.0.0.1"},"dst_ip":{"strategy":"fixed","value":"10.0.0.2"},"src_port":{"strategy":"fixed","value":1000},"dst_port":{"strategy":"fixed","value":80}}},` +
		`{"id":"udp","type":"udp","flow_count":2,"config":{"src_ip":"10.0.0.3","dst_ip":"10.0.0.4"},"tuples":{"src_ip":{"strategy":"fixed","value":"10.0.0.3"},"dst_ip":{"strategy":"fixed","value":"10.0.0.4"},"src_port":{"strategy":"fixed","value":2000},"dst_port":{"strategy":"fixed","value":53}}}` +
		`]},"output_type":"pcap","output_config":{"pcap_path":"` + pcapPath + `"}}`

	req := httptest.NewRequest("POST", "/tasks/batch", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	var resp struct {
		Data map[string]string `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v body=%s", err, w.Body.String())
	}
	taskID := resp.Data["id"]
	if taskID == "" {
		t.Fatal("no task id in response")
	}

	// Wait for the engine task to complete and the DB status to update.
	deadline := time.Now().Add(5 * time.Second)
	var tm storage.TaskModel
	for time.Now().Before(deadline) {
		db.First(&tm, "id = ?", taskID)
		if tm.Status == "completed" {
			break
		}
		if tm.Status == "error" {
			t.Fatalf("task errored: %s", tm.ErrorMessage)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if tm.Status != "completed" {
		t.Fatalf("task did not complete, status = %s", tm.Status)
	}

	// Verify the pcap file was written and is non-trivial in size.
	info, err := os.Stat(pcapPath)
	if err != nil {
		t.Fatalf("pcap stat: %v", err)
	}
	if info.Size() < 100 {
		t.Errorf("pcap file too small: %d bytes", info.Size())
	}
}
