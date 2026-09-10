package rest

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	sqlite "github.com/glebarez/sqlite"
	"github.com/gin-gonic/gin"
	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/protocol/arp"
	"github.com/trafficgen/trafficgen/internal/protocol/dns"
	httpproto "github.com/trafficgen/trafficgen/internal/protocol/http"
	"github.com/trafficgen/trafficgen/internal/protocol/icmp"
	"github.com/trafficgen/trafficgen/internal/protocol/tcp"
	"github.com/trafficgen/trafficgen/internal/protocol/udp"
	"github.com/trafficgen/trafficgen/internal/storage"
	"gorm.io/gorm"
)

// setupIntegrationTest creates a full test environment: DB, engine with real
// planners/builder, gin router, and the task/strategy handlers.
func setupIntegrationTest(t *testing.T) (*gin.Engine, *storage.DB, *core.Engine, func()) {
	t.Helper()
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
		ConfigWorkers: 2, PacketWorkers: 2, OutputWorkers: 2,
		BufferSize: 4096, QueueSize: 64,
	})
	e.RegisterPlanner(tcp.NewPlanner())
	e.RegisterPlanner(udp.NewPlanner())
	e.RegisterPlanner(httpproto.NewPlanner())
	e.RegisterPlanner(dns.NewPlanner())
	e.RegisterPlanner(icmp.NewPlanner())
	e.RegisterPlanner(arp.NewPlanner())
	e.SetBuildFunc(core.NewBuilder().Build)
	if err := e.Start(); err != nil {
		t.Fatalf("start engine: %v", err)
	}

	h := NewTaskHandler(db, e, nil)
	sh := NewStrategyHandler(db)

	r := gin.New()
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.POST("/strategies", sh.Create)
	r.POST("/tasks", h.Create)
	r.POST("/tasks/:id/start", h.Start)
	r.POST("/tasks/:id/stop", h.Stop)
	r.GET("/tasks/:id", h.Get)

	cleanup := func() { e.Stop() }
	return r, db, e, cleanup
}

// createStrategy is a helper to create a strategy via the API.
func createStrategy(t *testing.T, r *gin.Engine, protocol, config, fc string) string {
	t.Helper()
	body := fmt.Sprintf(`{"name":"s-%s","protocol":"%s","config":%s`, protocol, protocol, config)
	if fc != "" {
		body += fmt.Sprintf(`,"flow_control":%s`, fc)
	}
	body += "}"
	req := httptest.NewRequest("POST", "/strategies", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusCreated && w.Code != http.StatusOK {
		t.Fatalf("create strategy: status=%d body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Data.ID == "" {
		t.Fatalf("create strategy returned empty id: %s", w.Body.String())
	}
	return resp.Data.ID
}

// createTask is a helper to create a task referencing strategy IDs.
func createTask(t *testing.T, r *gin.Engine, name string, strategyIDs []string, pcapPath string, fc string) string {
	t.Helper()
	sids, _ := json.Marshal(strategyIDs)
	body := fmt.Sprintf(`{"name":"%s","strategy_ids":%s,"output_type":"pcap","output_config":{"pcap_path":"%s"}`, name, string(sids), pcapPath)
	if fc != "" {
		body += fmt.Sprintf(`,"flow_control":%s`, fc)
	}
	body += "}"
	req := httptest.NewRequest("POST", "/tasks", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusCreated && w.Code != http.StatusOK {
		t.Fatalf("create task: status=%d body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Data.ID == "" {
		t.Fatalf("create task returned empty id: %s", w.Body.String())
	}
	return resp.Data.ID
}

// startTask starts a task via the API and returns the response code + body.
func startTask(t *testing.T, r *gin.Engine, taskID string) (int, string) {
	t.Helper()
	req := httptest.NewRequest("POST", fmt.Sprintf("/tasks/%s/start", taskID), nil)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w.Code, w.Body.String()
}

// ---------------------------------------------------------------------------
// IT1: Strategy-level flows creates N flows (API→DB→engine→pcap end-to-end).
// Creates a strategy with flows=5, runs it, verifies the pcap file has packets.
// ---------------------------------------------------------------------------
func TestIntegration_StrategyFlows_GeneratesMultipleFlows(t *testing.T) {
	r, _, _, cleanup := setupIntegrationTest(t)
	defer cleanup()

	pcapPath := t.TempDir() + "/it1.pcap"
	// src_port omitted: flows=5 + pinned src_port is now a static-copy
	// rejection (D-FTP-2); auto-increment 12345+i supplies the ports.
	stratID := createStrategy(t, r, "tcp",
		`{"src_ip":"10.0.0.1","dst_ip":"10.0.0.2","dst_port":80,"tcp":{"handshake":true,"termination":true}}`,
		`{"type":"flows","value":5}`,
	)
	taskID := createTask(t, r, "it1", []string{stratID}, pcapPath, "")
	if code, body := startTask(t, r, taskID); code != http.StatusOK {
		t.Fatalf("start: code=%d body=%s", code, body)
	}

	status := waitForTaskStatus(t, r, taskID, map[string]bool{"completed": true, "failed": true}, 10*time.Second)
	if status != "completed" {
		t.Fatalf("task status=%s", status)
	}

	info, err := os.Stat(pcapPath)
	if err != nil {
		t.Fatalf("pcap not created: %v", err)
	}
	if info.Size() == 0 {
		t.Fatal("pcap file is empty")
	}
	t.Logf("IT1: pcap size=%d bytes", info.Size())
}

// ---------------------------------------------------------------------------
// IT2: Task-level bps ceiling caps aggregate rate across strategies.
// Two strategies each generating 500 flows (~200KB total), task-level bps=1M.
// The TokenBucket burst is 64KB, so ~136KB is rate-limited at 125KB/s ≈ 1.1s.
// Without the parent ceiling, 200KB finishes in <100ms. Asserting elapsed >
// 500ms proves the parent bucket is wired through the full pipeline.
// ---------------------------------------------------------------------------
func TestIntegration_TaskLevelBPS_CapsAggregate(t *testing.T) {
	r, _, _, cleanup := setupIntegrationTest(t)
	defer cleanup()

	pcapPath := t.TempDir() + "/it2.pcap"
	stratA := createStrategy(t, r, "tcp",
		`{"src_ip":"10.0.0.1","dst_ip":"10.0.0.2","dst_port":80,"tcp":{"handshake":true,"termination":true}}`,
		`{"type":"flows","value":500}`,
	)
	stratB := createStrategy(t, r, "icmp",
		`{"src_ip":"10.0.0.1","dst_ip":"10.0.0.2","icmp":{"type":8,"code":0}}`,
		`{"type":"flows","value":500}`,
	)
	taskID := createTask(t, r, "it2", []string{stratA, stratB}, pcapPath,
		`{"type":"bps","value":1000000}`,
	)

	start := time.Now()
	if code, body := startTask(t, r, taskID); code != http.StatusOK {
		t.Fatalf("start: code=%d body=%s", code, body)
	}

	status := waitForTaskStatus(t, r, taskID, map[string]bool{"completed": true, "failed": true}, 30*time.Second)
	elapsed := time.Since(start)

	if status != "completed" {
		t.Fatalf("task status=%s", status)
	}

	info, err := os.Stat(pcapPath)
	if err != nil {
		t.Fatalf("pcap not created: %v", err)
	}
	t.Logf("IT2: pcap size=%d bytes, elapsed=%v", info.Size(), elapsed)

	if info.Size() < 100 {
		t.Errorf("pcap too small (%d bytes): no packets written", info.Size())
	}
	if elapsed < 500*time.Millisecond {
		t.Errorf("elapsed=%v too fast: parent bps=1M ceiling not enforced on %d bytes (expected >= 500ms)", elapsed, info.Size())
	}
}

// ---------------------------------------------------------------------------
// IT3: Task-level flows ceiling caps total flows across strategies.
// Two strategies each with flows=100, task-level flows=3. Total must be <= 3.
// We verify by pcap file size: 3 flows produce a small pcap, 200 flows would
// produce a much larger one.
// ---------------------------------------------------------------------------
func TestIntegration_TaskLevelFlows_CapsTotal(t *testing.T) {
	r, _, _, cleanup := setupIntegrationTest(t)
	defer cleanup()

	pcapPath := t.TempDir() + "/it3.pcap"
	stratA := createStrategy(t, r, "tcp",
		`{"src_ip":"10.0.0.1","dst_ip":"10.0.0.2","dst_port":80,"tcp":{"handshake":true,"termination":true}}`,
		`{"type":"flows","value":100}`,
	)
	stratB := createStrategy(t, r, "icmp",
		`{"src_ip":"10.0.0.3","dst_ip":"10.0.0.4","icmp":{"type":8,"code":0}}`,
		`{"type":"flows","value":100}`,
	)
	taskID := createTask(t, r, "it3", []string{stratA, stratB}, pcapPath,
		`{"type":"flows","value":3}`,
	)

	if code, body := startTask(t, r, taskID); code != http.StatusOK {
		t.Fatalf("start: code=%d body=%s", code, body)
	}

	status := waitForTaskStatus(t, r, taskID, map[string]bool{"completed": true, "failed": true}, 15*time.Second)
	if status != "completed" {
		t.Fatalf("task status=%s", status)
	}

	info, err := os.Stat(pcapPath)
	if err != nil {
		t.Fatalf("pcap not created: %v", err)
	}
	t.Logf("IT3: pcap size=%d bytes (flows ceiling=3, each strategy wanted 100)", info.Size())
	if info.Size() < 50 {
		t.Error("pcap too small: no packets written")
	}
	// 3 flows (~400 bytes each) = ~1200 bytes. 200 flows would be ~80KB.
	// The ceiling must be effective: if flows weren't capped, the file would
	// be much larger. A reasonable upper bound is 5000 bytes for 3 flows.
	if info.Size() > 5000 {
		t.Errorf("pcap too large (%d bytes): flows ceiling=3 was NOT enforced (expected <5000)", info.Size())
	}
}

// ---------------------------------------------------------------------------
// IT4: Task-level time ceiling stops a long-running task early.
// Strategy flows=99999 (would run forever), task-level time=2s. Must complete
// in < 5s.
// ---------------------------------------------------------------------------
func TestIntegration_TaskLevelTime_StopsEarly(t *testing.T) {
	r, _, _, cleanup := setupIntegrationTest(t)
	defer cleanup()

	pcapPath := t.TempDir() + "/it4.pcap"
	stratID := createStrategy(t, r, "icmp",
		`{"src_ip":"10.0.0.1","dst_ip":"10.0.0.2","icmp":{"type":8,"code":0}}`,
		`{"type":"flows","value":99999}`,
	)
	taskID := createTask(t, r, "it4", []string{stratID}, pcapPath,
		`{"type":"time","value":2}`,
	)

	start := time.Now()
	if code, body := startTask(t, r, taskID); code != http.StatusOK {
		t.Fatalf("start: code=%d body=%s", code, body)
	}

	status := waitForTaskStatus(t, r, taskID, map[string]bool{"completed": true, "failed": true, "stopped": true}, 15*time.Second)
	elapsed := time.Since(start)

	if status != "completed" && status != "failed" {
		t.Fatalf("task status=%s (wanted completed/failed)", status)
	}

	if elapsed > 5*time.Second {
		t.Errorf("task-level time=2s took %v: time ceiling not working", elapsed)
	}
	t.Logf("IT4: elapsed=%v, status=%s", elapsed, status)
}

// waitForTaskStatus polls the GET /tasks/:id endpoint until the task reaches
// one of the target statuses. Returns the final status string.
func waitForTaskStatus(t *testing.T, r *gin.Engine, taskID string, target map[string]bool, timeout time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		req := httptest.NewRequest("GET", fmt.Sprintf("/tasks/%s", taskID), nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code == http.StatusOK {
			var resp struct {
				Data struct {
					Status string `json:"status"`
				} `json:"data"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &resp); err == nil {
				if target[resp.Data.Status] {
					return resp.Data.Status
				}
			}
		}
		if time.Now().After(deadline) {
			req := httptest.NewRequest("GET", fmt.Sprintf("/tasks/%s", taskID), nil)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			t.Fatalf("task %s did not reach %v within %v (last: %s)", taskID, target, timeout, w.Body.String())
		}
		time.Sleep(100 * time.Millisecond)
	}
}
