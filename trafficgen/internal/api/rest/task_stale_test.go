package rest

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
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

// terminalStatusInDB reads a task's status straight from the DB.
func terminalStatusInDB(t *testing.T, db *storage.DB, id string) storage.TaskModel {
	t.Helper()
	var tm storage.TaskModel
	if err := db.First(&tm, "id = ?", id).Error; err != nil {
		t.Fatalf("read task %s: %v", id, err)
	}
	return tm
}

// seedRunningTask inserts a running task owned by test-user.
func seedRunningTask(t *testing.T, db *storage.DB, id, outputJSON string) {
	t.Helper()
	if err := db.Create(&storage.TaskModel{
		ID: id, UserID: "test-user", Name: "n", Status: "running",
		StrategyIDs: `[]`, OutputType: "pcap", OutputConfig: outputJSON,
	}).Error; err != nil {
		t.Fatalf("seed task: %v", err)
	}
}

// TestOnEngineProgress_TerminalTaskIsReadOnly 覆盖终态判定散落的第一种冲突：
// onEngineProgress 完全不看 status，挂着终态的任务照样被 progress 回调改写
// progress/packets_sent/bytes_sent/flows_count。
//
// 最直接的后果是 Stop：Stop 先把状态写成 stopped，engine 还在路上的
// OnProgress 回调随后把 progress 改成 50 —— 已经结束的任务显示"跑到一半"。
// 终态只能由终态路径改写，进度回调对终态任务必须只读。
func TestOnEngineProgress_TerminalTaskIsReadOnly(t *testing.T) {
	_, _, db, _ := newTaskTestServer(t)
	h := &TaskHandler{
		db:                 db,
		aggSlots:           make(map[string]map[string]*engineAggSlot),
		lastProgressUpdate: make(map[string]time.Time),
	}
	const taskID = "22222222-2222-2222-2222-222222222222"
	if err := db.Create(&storage.TaskModel{
		ID: taskID, UserID: "test-user", Name: "n", Status: "stopped",
		Progress: 100, PacketsSent: 500, BytesSent: 250000,
	}).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	// 迟到的进度回调（batch 任务：engine task ID == taskID）。
	h.onEngineProgress(taskID, 50, core.TaskStats{PacketsSent: 12})

	tm := terminalStatusInDB(t, db, taskID)
	if tm.Progress != 100 {
		t.Errorf("progress = %v after a late progress callback on a stopped task, want 100 "+
			"(the task is over; progress must not move again)", tm.Progress)
	}
	if tm.PacketsSent != 500 {
		t.Errorf("packets_sent = %d, want 500 — a late callback must not rewrite a finished task's stats", tm.PacketsSent)
	}
	if tm.Status != "stopped" {
		t.Errorf("status = %q, want stopped", tm.Status)
	}
}

// TestOnEngineTaskComplete_DoesNotReviveStoppedTask 覆盖第二种冲突：完成回调
// 只检查 "task.Status != running"，但 Stop 分支同样会在写 stopped 之后继续去
// 停 engine 任务。engine 的完成回调一旦在 stopped 之后到达，不能把状态改回
// completed —— Stop 是用户意图，晚到的完成回调只是副作用。
func TestOnEngineTaskComplete_DoesNotReviveStoppedTask(t *testing.T) {
	h, _, db, e := newTaskTestServer(t)
	const taskID = "33333333-3333-3333-3333-333333333333"
	sidsJSON, _ := json.Marshal([]string{"s1"})
	if err := db.Create(&storage.TaskModel{
		ID: taskID, UserID: "test-user", Name: "n", Status: "stopped",
		Progress: 42, StrategyIDs: string(sidsJSON), OutputType: "pcap",
	}).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	// 非 batch 分支：引擎任务 ID 是 {taskID}-{strategyID}。要让完成回调走到
	// "全部引擎任务已结束"的判定，必须先真有一个在跑——否则它会在
	// GetTaskStatus 处返回，本测试就白跑了。这里起一个长任务再让它失败退出
	// （FailTask 移除 taskStore 条目并触发完成回调）。
	sid := createLongRunningStrategy(t, db, "test-user", "s1", "tcp")
	if err := db.Model(&storage.TaskModel{}).Where("id = ?", taskID).
		Update("strategy_ids", `["`+sid+`"]`).Error; err != nil {
		t.Fatalf("update strategy ids: %v", err)
	}
	_ = e
	h.onEngineTaskComplete(taskID + "-" + sid)
	if tm := terminalStatusInDB(t, db, taskID); tm.Status != "stopped" {
		t.Fatalf("precondition: status = %q, want stopped before the callback", tm.Status)
	}

	tm := terminalStatusInDB(t, db, taskID)
	if tm.Status != "stopped" {
		t.Errorf("status = %q after a late completion callback, want stopped "+
			"(Stop is the user's intent; a late callback must not overwrite it)", tm.Status)
	}
	if tm.Progress != 42 {
		t.Errorf("progress = %v, want 42 untouched", tm.Progress)
	}
}

// TestTaskStop_DoesNotOverwriteConcurrentStats 覆盖"用旧快照整行覆盖数据库"：
// Stop 先整行读 task，改两个字段后 Save 全列——读和写之间落库的实发统计
// (packets_sent/bytes_sent/flows_count/progress) 全被打回读到的旧值。
//
// 用户连点停止时看到的就是这个：请求前已发出 500 包，停止后界面显示 0。
func TestTaskStop_DoesNotOverwriteConcurrentStats(t *testing.T) {
	h, r, db, _ := newTaskTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.POST("/tasks/:id/stop", h.Stop)

	const taskID = "44444444-4444-4444-4444-444444444444"
	if err := db.Create(&storage.TaskModel{
		ID: taskID, UserID: "test-user", Name: "n", Status: "running",
		Progress: 10, PacketsSent: 0, BytesSent: 0, StrategyIDs: `[]`,
		OutputType: "pcap", BatchConfig: `{"classes":[]}`,
	}).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	// 在 Stop 读到快照之后、写库之前插入并发统计写。整行 Save 会把读到
	// 的旧统计列一起写回，覆盖掉这里的 500。
	stopSnapshotHook = func() {
		if err := db.Model(&storage.TaskModel{}).Where("id = ?", taskID).Updates(map[string]interface{}{
			"packets_sent": 500, "bytes_sent": 250000, "flows_count": 7, "progress": 88,
		}).Error; err != nil {
			t.Errorf("concurrent update: %v", err)
		}
	}
	defer func() { stopSnapshotHook = nil }()

	req := httptest.NewRequest("POST", "/tasks/"+taskID+"/stop", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("stop: status=%d body=%s", w.Code, w.Body.String())
	}

	tm := terminalStatusInDB(t, db, taskID)
	if tm.Status != "stopped" {
		t.Fatalf("status = %q, want stopped", tm.Status)
	}
	// 统计列允许是并发写的值(500)或 Stop 读到之前的值(0)，但不允许被
	// Stop 的旧快照覆盖成一个互相矛盾的组合。这里断言最直接的观测：
	// 并发写确实落库了，Stop 不该把它抹掉。
	if tm.PacketsSent != 500 {
		t.Errorf("packets_sent = %d after Stop, want 500 — Stop rewrote the row from a "+
			"snapshot taken before the concurrent stats update", tm.PacketsSent)
	}
}

// TestStart_ResetsStaleProgressAndCompletedAt 覆盖重启时必须清掉的陈旧状态。
//
// Start 里原本有一段 "Reset state for re-start"：Progress=0、
// ErrorMessage=""、CompletedAt=nil，靠后面的整行 Save 一起落库。改成按列
// 更新后只写了 status/started_at/error_message，Progress 与 CompletedAt
// 两列漏了——重跑一个已完成的 100% 任务，DB 里仍留着 progress=100 和上一轮
// 的 completed_at，客户端立刻轮询会看到一个"已完成但状态是 running"的任务。
func TestStart_ResetsStaleProgressAndCompletedAt(t *testing.T) {
	h, r, db, _ := newTaskTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.POST("/tasks/:id/start", h.Start)

	sid := createLongRunningStrategy(t, db, "test-user", "s1", "tcp")
	taskID := uuid.New().String()
	sidsJSON, _ := json.Marshal([]string{sid})
	prevCompleted := time.Now().Add(-time.Hour)
	if err := db.Create(&storage.TaskModel{
		ID: taskID, UserID: "test-user", Name: "t1", Status: "completed",
		Progress: 100, StrategyIDs: string(sidsJSON),
		OutputType: "pcap", OutputConfig: `{"pcap_path":"` + stalePcapPath(t, "reset.pcap") + `"}`,
		CompletedAt: &prevCompleted,
	}).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	req := httptest.NewRequest("POST", "/tasks/"+taskID+"/start", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("start: status=%d body=%s", w.Code, w.Body.String())
	}

	tm := terminalStatusInDB(t, db, taskID)
	if tm.Status != "running" {
		t.Fatalf("status = %q, want running", tm.Status)
	}
	if tm.Progress != 0 {
		t.Errorf("progress = %v after restarting a completed task, want 0 — the "+
			"stale 100 is still in the DB and the client sees a running task at 100%%", tm.Progress)
	}
	if tm.CompletedAt != nil {
		t.Errorf("completed_at = %v after restart, want cleared — a running task "+
			"must not carry the previous run's completion time", tm.CompletedAt)
	}
}

// TestStart_WriterFailureClearsStaleProgress 覆盖 Start 里另一处
// `task.Progress = 0`：全部 output writer 创建失败时任务转 error，但那句
// 重置在改成按列更新后不再落库。重跑一个已完成的 100% 任务、writer 又开
// 不起来，DB 里就留下 status=error + progress=100 的矛盾组合——与客户端
// 报告问题 1（拒绝路径把 completed/100 改成 error/0）是同一形状的镜像。
func TestStart_WriterFailureClearsStaleProgress(t *testing.T) {
	h, r, db, _ := newTaskTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.POST("/tasks/:id/start", h.Start)

	sid := createTestStrategy(t, db, "test-user", "s1", "tcp")
	taskID := uuid.New().String()
	sidsJSON, _ := json.Marshal([]string{sid})
	prevCompleted := time.Now().Add(-time.Hour)
	// 父路径是普通文件 → pcap writer 必然打不开。
	blocker := t.TempDir() + "/blocker"
	if err := os.WriteFile(blocker, []byte("x"), 0o644); err != nil {
		t.Fatalf("seed blocker: %v", err)
	}
	if err := db.Create(&storage.TaskModel{
		ID: taskID, UserID: "test-user", Name: "t1", Status: "completed",
		Progress: 100, StrategyIDs: string(sidsJSON), OutputType: "pcap",
		OutputConfig: `{"pcap_path":"` + blocker + `/x.pcap"}`,
		CompletedAt: &prevCompleted,
	}).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	req := httptest.NewRequest("POST", "/tasks/"+taskID+"/start", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code == http.StatusOK {
		t.Fatalf("expected start to fail on the unwritable pcap path: %s", w.Body.String())
	}

	tm := terminalStatusInDB(t, db, taskID)
	if tm.Status != "error" {
		t.Fatalf("status = %q, want error", tm.Status)
	}
	if tm.Progress != 0 {
		t.Errorf("progress = %v on a task that never ran, want 0 — the stale 100 "+
			"survives, so the record reads 'error at 100%%'", tm.Progress)
	}
}

// TestStart_ErrorPathsClearStaleCompletedAt 覆盖 error 路径残留上一轮
// completed_at。
//
// markTaskError 只在 task.CompletedAt != nil 时写该列，而 Start 的每条 error
// 分支传进来的都是**从 DB 读出的**旧值——于是重跑一个已完成的 100% 任务、
// 在中途失败，库里留下 status=error + progress=0 + completed_at=<一小时前>。
// completed_at 会通过 TaskResponse 直接回给客户端，读起来像"这次跑完于
// 一小时前"。
func TestStart_ErrorPathsClearStaleCompletedAt(t *testing.T) {
	h, r, db, _ := newTaskTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.POST("/tasks/:id/start", h.Start)

	taskID := uuid.New().String()
	prevCompleted := time.Now().Add(-time.Hour)
	// strategy_ids 不是合法 JSON → 命中 Start 的第一条 error 分支。
	if err := db.Create(&storage.TaskModel{
		ID: taskID, UserID: "test-user", Name: "t1", Status: "completed",
		Progress: 100, StrategyIDs: "not-json",
		OutputType: "pcap", OutputConfig: `{}`,
		CompletedAt: &prevCompleted,
	}).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	req := httptest.NewRequest("POST", "/tasks/"+taskID+"/start", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code == http.StatusOK {
		t.Fatalf("expected the start to fail on corrupt strategy_ids: %s", w.Body.String())
	}

	tm := terminalStatusInDB(t, db, taskID)
	if tm.Status != "error" {
		t.Fatalf("status = %q, want error", tm.Status)
	}
	if tm.Progress != 0 {
		t.Errorf("progress = %v, want 0", tm.Progress)
	}
	// error 是终态，completed_at 应记录"这次失败发生的时刻"，既不能是 nil
	// （记录读起来像还在跑），也不能是一小时前上一轮的值。
	if tm.CompletedAt == nil {
		t.Errorf("completed_at is nil on a failed start; an error is terminal and " +
			"must carry the time it happened")
	} else if tm.CompletedAt.Before(prevCompleted.Add(time.Minute)) {
		t.Errorf("completed_at = %v, which is the PREVIOUS run's value (%v) — the "+
			"stale completion time is still being served to clients",
			tm.CompletedAt, prevCompleted)
	}
}

// TestOnEngineProgress_LateProgressDoesNotOverwriteTerminal 覆盖终态判定的
// TOCTOU：onEngineProgress 先 SELECT status 判终态，再单独 UPDATE 进度列，
// 两次语句之间任务可能被 Stop / 完成回调写成终态。SELECT 看到 running、
// UPDATE 落地时行已是 stopped —— 迟到的进度回调把 stopped 任务的
// progress/packets_sent 又改回"跑到一半"，正是本函数开头那段注释声称
// 要防的事（只读判定只能挡住"已经终态"的调用，挡不住"正在变终态"的调用）。
//
// 用 parentAggregateWriteHook 精确落在 SELECT 之后、UPDATE 之前：在 hook 里
// 把行写成 stopped，等价于另一个 goroutine 恰好在这个窗口里 Stop。
func TestOnEngineProgress_LateProgressDoesNotOverwriteTerminal(t *testing.T) {
	_, _, db, _ := newTaskTestServer(t)
	h := &TaskHandler{
		db:                 db,
		aggSlots:           make(map[string]map[string]*engineAggSlot),
		lastProgressUpdate: make(map[string]time.Time),
	}
	const taskID = "33333333-3333-3333-3333-333333333333"
	if err := db.Create(&storage.TaskModel{
		ID: taskID, UserID: "test-user", Name: "n", Status: "running",
		Progress: 0, PacketsSent: 0,
	}).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	var once sync.Once
	parentAggregateWriteHook = func() {
		once.Do(func() {
			// 窗口内：任务被 Stop（终态 + 终态进度）。
			if err := db.Model(&storage.TaskModel{}).Where("id = ?", taskID).
				Updates(map[string]interface{}{
					"status": "stopped", "progress": 100, "packets_sent": 500,
				}).Error; err != nil {
				t.Errorf("stop inside the window: %v", err)
			}
		})
	}
	t.Cleanup(func() { parentAggregateWriteHook = nil })

	h.onEngineProgress(taskID, 55, core.TaskStats{PacketsSent: 42})

	tm := terminalStatusInDB(t, db, taskID)
	if tm.Status != "stopped" {
		t.Fatalf("status = %q, want stopped", tm.Status)
	}
	if tm.Progress != 100 {
		t.Errorf("progress = %v after the task was stopped mid-callback, want 100 — "+
			"the progress UPDATE is unconditional, so a callback that passed the "+
			"status SELECT before the stop still overwrites the terminal row", tm.Progress)
	}
	if tm.PacketsSent != 500 {
		t.Errorf("packets_sent = %d, want 500 (the stopped task's own stats)", tm.PacketsSent)
	}
}
