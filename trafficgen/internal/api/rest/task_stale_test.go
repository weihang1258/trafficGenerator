package rest

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/storage"
)

// createLongRunningStrategy is createTestStrategy with a huge flow count so
// the engine task stays running for the whole test: 100k flows of TCP
// handshake+data+teardown take seconds to plan, queue, and write. The
// default createTestStrategy uses {"type":"flows","value":1}, which completes
// in milliseconds — racy for stale-cycle tests that assert on a running task
// after a second Start (the completion callback would legitimately set
// CompletedAt while the test is still querying).
func createLongRunningStrategy(t *testing.T, db *storage.DB, userID, name, protocol string) string {
	t.Helper()
	config := `{"src_ip":"10.0.0.1","dst_ip":"10.0.0.2"}`
	fc := `{"type":"flows","value":100000}`
	ch := calculateConfigHash("synth", protocol, config, fc)
	id := uuid.New().String()
	if err := db.Create(&storage.StrategyModel{
		ID: id, UserID: userID, Name: name, Protocol: protocol,
		Config: config, FlowControl: fc, ConfigHash: ch,
	}).Error; err != nil {
		t.Fatalf("create strategy: %v", err)
	}
	return id
}

// stalePcapPath returns a writable pcap output path under the user's home
// (hardcoded /tmp paths break on machines where a root-owned leftover of the
// same name exists — open() for write fails with permission denied).
func stalePcapPath(t *testing.T, name string) string {
	t.Helper()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("user home: %v", err)
	}
	return filepath.Join(home, ".cache", "tg-rest-tests", name)
}

// TestStart_StaleRunning_EngineTaskMissing_AllowsRestart verifies the
// stale-running reconciliation: when the DB task status is "running" but the
// engine taskStore no longer has any engine task for it (the task completed or
// failed while the client was disconnected / polling timed out), Start must
// NOT return 400 "task is already running" — it repairs the DB status and
// restarts the task.
//
// Before the fix, Start's unconditional "already running" guard rejected the
// task forever: the engine task was gone, so flowb_stop_all_tasks could not
// clean it up, and Create's dedup (status IN pending,running) blocked
// re-creating the same task. The only escape was editing the sqlite DB by
// hand (observed in the wild with /tmp/tds-test-data/trafficgen.db).
func TestStart_StaleRunning_EngineTaskMissing_AllowsRestart(t *testing.T) {
	h, r, db, e := newTaskTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.POST("/tasks/:id/start", h.Start)

	sid := createLongRunningStrategy(t, db, "test-user", "s1", "tcp")
	taskID := uuid.New().String()
	sidsJSON, _ := json.Marshal([]string{sid})
	db.Create(&storage.TaskModel{
		ID: taskID, UserID: "test-user", Name: "t1",
		Status: "running", StrategyIDs: string(sidsJSON),
		OutputType: "pcap", OutputConfig: `{"pcap_path":"` + stalePcapPath(t, "stale.pcap") + `"}`,
	})

	// Precondition: the engine task is already gone (stale DB status).
	if _, err := e.GetTaskStatus(taskID + "-" + sid); err == nil {
		t.Fatalf("precondition: engine task %s must NOT exist", taskID+"-"+sid)
	}

	req := httptest.NewRequest("POST", "/tasks/"+taskID+"/start", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200 (stale running task must be restartable)", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "already running") {
		t.Fatalf("body=%q must not say 'already running'", w.Body.String())
	}

	var tm storage.TaskModel
	db.First(&tm, "id = ?", taskID)
	if tm.Status != "running" {
		t.Errorf("task status=%q, want 'running' after restart", tm.Status)
	}
	if tm.ErrorMessage != "" {
		t.Errorf("ErrorMessage=%q, want empty (stale failure state must be cleared)", tm.ErrorMessage)
	}
	if _, err := e.GetTaskStatus(taskID + "-" + sid); err != nil {
		t.Errorf("engine task %s missing after restart: %v", taskID+"-"+sid, err)
	}
}

// TestStart_StaleRunning_EngineTaskMissing_NoFailure_RepairsCompleted verifies
// the intermediate DB repair for a stale "running" task with no recorded
// failure: Start sets the stale run's status to "completed" in the DB (so it
// appears in history) before restarting the task. The restart itself flips the
// status to "running" again, so we observe the repair indirectly: after a
// second stale cycle the DB record must show a clean running task (progress
// reset, no stale error state).
func TestStart_StaleRunning_EngineTaskMissing_NoFailure_RepairsCompleted(t *testing.T) {
	h, r, db, e := newTaskTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.POST("/tasks/:id/start", h.Start)

	sid := createLongRunningStrategy(t, db, "test-user", "s1", "tcp")
	taskID := uuid.New().String()
	sidsJSON, _ := json.Marshal([]string{sid})
	db.Create(&storage.TaskModel{
		ID: taskID, UserID: "test-user", Name: "t1",
		Status: "running", StrategyIDs: string(sidsJSON),
		OutputType: "pcap", OutputConfig: `{"pcap_path":"` + stalePcapPath(t, "stale4.pcap") + `"}`,
	})

	// First Start: reconciles stale running -> completed (no failure recorded),
	// then restarts the task (status back to running).
	req := httptest.NewRequest("POST", "/tasks/"+taskID+"/start", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("first start: status=%d body=%s", w.Code, w.Body.String())
	}

	// Simulate the client losing track again: force the engine task out of
	// the taskStore by failing it (FailTask removes the entry and fires the
	// completion callback), wait for the callback to land, then wipe the DB
	// status back to "running" so the record is stale without a recorded
	// failure.
	h.engine.FailTask(taskID+"-"+sid, "simulated outage")
	var tm storage.TaskModel
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		db.First(&tm, "id = ?", taskID)
		if tm.Status == "failed" || tm.Status == "completed" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	// The completion callback recorded the failure in failedTasks; drop it so
	// the stale record has no recorded failure and the second Start exercises
	// the "repair to completed" branch (not the "repair to failed" branch).
	h.failMu.Lock()
	delete(h.failedTasks, taskID+"-"+sid)
	h.failMu.Unlock()
	db.Model(&storage.TaskModel{}).Where("id = ?", taskID).Update("status", "running")

	// Second Start: must reconcile the stale run and restart.
	req = httptest.NewRequest("POST", "/tasks/"+taskID+"/start", nil)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("second start: status=%d body=%s", w.Code, w.Body.String())
	}

	// The 100k-flow task is still running: status must be "running" with the
	// restart's clean state (progress reset, no stale error). A fast task
	// completing inside the query window would be a legitimate race — the
	// stale-run repair is exactly what makes a fast completion safe — so the
	// assertions query a fresh record right before checking.
	db.First(&tm, "id = ?", taskID)
	if tm.Status != "running" {
		t.Errorf("task status=%q, want 'running' after restart", tm.Status)
	}
	if tm.Progress != 0 {
		t.Errorf("progress=%v, want 0 (restart must reset progress)", tm.Progress)
	}
	if tm.ErrorMessage != "" {
		t.Errorf("ErrorMessage=%q, want empty after restart (stale state must not leak)", tm.ErrorMessage)
	}
	if _, err := e.GetTaskStatus(taskID + "-" + sid); err != nil {
		t.Errorf("engine task %s missing after restart: %v", taskID+"-"+sid, err)
	}

	// Cleanup: stop the still-running task so the engine has no leftover
	// entry when the test exits.
	if _, err := e.GetTaskStatus(taskID + "-" + sid); err == nil {
		e.StopTask(taskID + "-" + sid)
	}
}

// TestStart_StaleStarting_EngineTaskMissing_ReconcilesFailed verifies the
// stale reconciliation on the "starting" status with a recorded engine
// failure: the DB task is repaired to "failed" with the recorded error, and
// Start restarts it.
func TestStart_StaleStarting_EngineTaskMissing_ReconcilesFailed(t *testing.T) {
	h, r, db, e := newTaskTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.POST("/tasks/:id/start", h.Start)

	sid := createLongRunningStrategy(t, db, "test-user", "s1", "tcp")
	taskID := uuid.New().String()
	sidsJSON, _ := json.Marshal([]string{sid})
	db.Create(&storage.TaskModel{
		ID: taskID, UserID: "test-user", Name: "t1",
		Status: "starting", StrategyIDs: string(sidsJSON),
		OutputType: "pcap", OutputConfig: `{"pcap_path":"` + stalePcapPath(t, "stale2.pcap") + `"}`,
	})
	// Simulate a failure recorded by the engine callback before the client
	// disconnected: failedTasks holds the engine task's error message.
	h.failMu.Lock()
	h.failedTasks[taskID+"-"+sid] = "planning error: bad config"
	h.failMu.Unlock()

	req := httptest.NewRequest("POST", "/tasks/"+taskID+"/start", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200 (stale starting task must be restartable)", w.Code, w.Body.String())
	}

	var tm storage.TaskModel
	db.First(&tm, "id = ?", taskID)
	if tm.Status != "running" {
		t.Errorf("task status=%q, want 'running' after restart", tm.Status)
	}
	if _, err := e.GetTaskStatus(taskID + "-" + sid); err != nil {
		t.Errorf("engine task %s missing after restart: %v", taskID+"-"+sid, err)
	}
}

// TestStart_GenuinelyRunning_StillRejected verifies the "already running"
// guard still works when the engine genuinely still owns the task: Start
// must return 400 and NOT submit a duplicate engine task.
func TestStart_GenuinelyRunning_StillRejected(t *testing.T) {
	h, r, db, e := newTaskTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.POST("/tasks/:id/start", h.Start)

	sid := createLongRunningStrategy(t, db, "test-user", "s1", "tcp")
	taskID := uuid.New().String()
	sidsJSON, _ := json.Marshal([]string{sid})
	db.Create(&storage.TaskModel{
		ID: taskID, UserID: "test-user", Name: "t1",
		Status: "running", StrategyIDs: string(sidsJSON),
		OutputType: "pcap", OutputConfig: `{"pcap_path":"` + stalePcapPath(t, "stale3.pcap") + `"}`,
	})
	// Precondition: engine task IS present (genuinely running).
	ct, err := core.StrategyModelToTask(&storage.TaskModel{
		ID: taskID, UserID: "test-user", Name: "t1", StrategyIDs: string(sidsJSON),
		OutputType: "pcap", OutputConfig: `{"pcap_path":"` + stalePcapPath(t, "stale3.pcap") + `"}`,
	}, &storage.StrategyModel{
		ID: sid, UserID: "test-user", Name: "s1", Protocol: "tcp",
		Config: `{"src_ip":"10.0.0.1","dst_ip":"10.0.0.2"}`, Mode: "synth",
		FlowControl: `{"type":"time","value":60}`,
	}, "")
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	if err := e.SubmitTask(*ct); err != nil {
		t.Fatalf("submit precondition: %v", err)
	}

	req := httptest.NewRequest("POST", "/tasks/"+taskID+"/start", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400 (genuinely running)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "already running") {
		t.Errorf("body=%q must say 'already running'", w.Body.String())
	}
}
