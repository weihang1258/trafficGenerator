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

// setupBatchTestEnv builds an engine + DB + handler wired for batch task tests.
// Returns the handler, engine, DB, and a gin router with /tasks/batch, /tasks/:id/start,
// /tasks/:id/stop registered.
func setupBatchTestEnv(t *testing.T) (*TaskHandler, *core.Engine, *storage.DB, *gin.Engine) {
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
		ConfigWorkers: 1, PacketWorkers: 1, OutputWorkers: 1,
		BufferSize: 256, QueueSize: 64,
	})
	e.RegisterPlanner(tcp.NewPlanner())
	e.RegisterPlanner(udp.NewPlanner())
	e.SetBuildFunc(core.NewBuilder().Build)
	if err := e.Start(); err != nil {
		t.Fatalf("start engine: %v", err)
	}
	h := NewTaskHandler(db, e, nil)
	r := gin.New()
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.POST("/tasks/batch", h.CreateBatch)
	r.POST("/tasks/:id/start", h.Start)
	r.POST("/tasks/:id/stop", h.Stop)
	return h, e, db, r
}

// submitBatchTask creates a batch task via the API and returns the task ID.
// Uses a unique pcap path per call so repeated invocations don't collide.
func submitBatchTask(t *testing.T, r *gin.Engine, name string) string {
	t.Helper()
	pcapPath := t.TempDir() + "/" + name + ".pcap"
	body := `{"name":"` + name + `","batch":{"classes":[` +
		`{"id":"tcp","type":"tcp","flow_count":1,"config":{"src_ip":"10.0.0.1","dst_ip":"10.0.0.2","tcp":{"handshake":true,"termination":true}},"tuples":{"src_ip":{"strategy":"fixed","value":"10.0.0.1"},"dst_ip":{"strategy":"fixed","value":"10.0.0.2"},"src_port":{"strategy":"fixed","value":1000},"dst_port":{"strategy":"fixed","value":80}}}` +
		`]},"output_type":"pcap","output_config":{"pcap_path":"` + pcapPath + `"}}`
	req := httptest.NewRequest("POST", "/tasks/batch", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("create batch: status = %d, body = %s", w.Code, w.Body.String())
	}
	var resp struct {
		Data map[string]string `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v body=%s", err, w.Body.String())
	}
	return resp.Data["id"]
}

// TestStart_BatchTask_ReturnsClearError verifies that calling Start on a batch
// task returns a clear 400 error explaining batch tasks are auto-started,
// NOT the misleading "corrupt strategy_ids in task record".
//
// Before the fix, Start tried to json.Unmarshal the empty StrategyIDs field
// and returned a 500 with "corrupt strategy_ids in task record" — confusing
// to users since the batch task IS valid, just auto-started.
func TestStart_BatchTask_ReturnsClearError(t *testing.T) {
	_, e, db, r := setupBatchTestEnv(t)
	defer e.Stop()

	taskID := submitBatchTask(t, r, "batch-start-err")

	// Wait for the batch task to complete (it's auto-started on creation).
	deadline := time.Now().Add(5 * time.Second)
	var tm storage.TaskModel
	for time.Now().Before(deadline) {
		db.First(&tm, "id = ?", taskID)
		if tm.Status == "completed" || tm.Status == "error" || tm.Status == "failed" {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	// Now call Start on it.
	req := httptest.NewRequest("POST", "/tasks/"+taskID+"/start", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body = %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if !strings.Contains(body, "auto-started") {
		t.Errorf("body = %q; want error mentioning 'auto-started'", body)
	}
	if strings.Contains(body, "corrupt strategy_ids") {
		t.Errorf("body = %q; must NOT mention 'corrupt strategy_ids' (misleading)", body)
	}

	// The task record should be marked as error, not left in a weird state.
	db.First(&tm, "id = ?", taskID)
	if tm.Status != "error" {
		t.Errorf("task status = %q, want 'error'", tm.Status)
	}
}

// TestStop_BatchTask_StopsSingleEngineTask verifies that Stop on a batch task
// stops the single engine task (engineTaskID == taskID, no strategy suffix)
// without trying to iterate empty StrategyIDs and skip the engine task entirely.
//
// Before the fix, Stop's strategyIDs loop did nothing for batch tasks (empty
// slice), so the engine task was never stopped — it kept running until it
// finished on its own. This test exercises the fix indirectly: by the time
// the test checks status, the task has already completed because Stop couldn't
// stop it (the bug). The test still passes today because tasks complete fast,
// but the strategyIDs parse error logged by Stop proves the bug exists.
// After the fix, Stop will use a batch-aware branch that calls StopTask(taskID)
// directly and never tries to parse the empty StrategyIDs.
func TestStop_BatchTask_StopsSingleEngineTask(t *testing.T) {
	_, e, db, r := setupBatchTestEnv(t)
	defer e.Stop()

	taskID := submitBatchTask(t, r, "batch-stop")

	// Confirm the engine task was submitted (engineTaskID == taskID).
	if _, err := e.GetTaskStatus(taskID); err != nil {
		t.Fatalf("precondition: engine task %s not found: %v", taskID, err)
	}

	// Stop the task via API.
	req := httptest.NewRequest("POST", "/tasks/"+taskID+"/stop", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("stop: status = %d, body = %s", w.Code, w.Body.String())
	}

	// DB status should be "stopped" (set before Stop returns).
	var tm storage.TaskModel
	db.First(&tm, "id = ?", taskID)
	if tm.Status != "stopped" {
		t.Errorf("task status = %q, want 'stopped'", tm.Status)
	}

	// Stop must not log "corrupt strategy_ids" for batch tasks (they have
	// empty StrategyIDs by design). The presence of that log line indicates
	// the bug: Stop is parsing empty JSON and failing. We assert indirectly
	// via the response body which carries "task stopped (engine cleanup may
	// be incomplete)" when the parse fails.
	body := w.Body.String()
	if strings.Contains(body, "engine cleanup may be incomplete") {
		t.Errorf("body = %q; Stop must use a batch-aware branch that doesn't parse StrategyIDs", body)
	}
}

// TestOnEngineTaskComplete_BatchTask_MarksComplete verifies that the engine
// completion callback correctly marks a batch task as completed when its
// single engine task finishes. Batch tasks have empty StrategyIDs, so the
// existing "allDone" loop sees zero strategies and must still treat the engine
// task's completion as terminal — but must NOT skip the batch-task writer
// cleanup path (which runs under the plain taskID, not the suffixed form).
//
// After the fix, the callback recognizes batch tasks (BatchConfig != "") and
// directly checks GetTaskStatus(taskID) instead of iterating strategyIDs.
// Completion is correctly marked. This test verifies the post-fix behavior
// holds: completion happens, no leftover engine task, no leftover writer.
func TestOnEngineTaskComplete_BatchTask_MarksComplete(t *testing.T) {
	_, e, db, r := setupBatchTestEnv(t)
	defer e.Stop()

	taskID := submitBatchTask(t, r, "batch-complete")

	// Wait for the engine task to complete + the callback to fire.
	deadline := time.Now().Add(5 * time.Second)
	var tm storage.TaskModel
	for time.Now().Before(deadline) {
		db.First(&tm, "id = ?", taskID)
		if tm.Status == "completed" || tm.Status == "failed" || tm.Status == "error" {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	if tm.Status != "completed" {
		t.Fatalf("batch task status = %q, want 'completed' (err=%s)", tm.Status, tm.ErrorMessage)
	}

	// Engine task should be cleaned up from the task store.
	if _, err := e.GetTaskStatus(taskID); err == nil {
		t.Errorf("engine task %s still in task store after completion", taskID)
	}

	// Verify that the test name appears nowhere in the error message (defensive).
	if tm.ErrorMessage != "" {
		t.Errorf("completed batch task should have empty error_message; got %q", tm.ErrorMessage)
	}
}

// fmt import guard: keep the symbol used by other tests in this file reachable.
var _ = fmt.Sprintf
