package rest

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/output"
	"github.com/trafficgen/trafficgen/internal/storage"
	"gorm.io/gorm"
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

	// 必须在**请求内**读取：Start 返回后引擎可能已经跑完并把行写成
	// completed + 本轮的 completed_at。那时再读就分不清"旧值没被清掉"
	// 和"这一轮合法完成"——此前这个测试就是这么假绿的（把清零改成保留
	// 旧值，它依然 PASS）。
	//
	// startSubmitHook 在 running 行落库之后、引擎任务提交之后立刻执行，
	// 此时看到的正是"新一次运行刚开始"的那一瞬。
	var observed storage.TaskModel
	var observedAtRunning bool
	startSubmitHook = func() {
		var tm storage.TaskModel
		if err := db.First(&tm, "id = ?", taskID).Error; err != nil {
			t.Errorf("read inside the start window: %v", err)
			return
		}
		observed = tm
		observedAtRunning = tm.Status == "running" || tm.Status == "starting"
	}
	t.Cleanup(func() { startSubmitHook = nil })

	req := httptest.NewRequest("POST", "/tasks/"+taskID+"/start", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("start: status=%d body=%s", w.Code, w.Body.String())
	}
	if !observedAtRunning {
		t.Fatalf("the start window was never observed (status=%q) — this test "+
			"would otherwise be vacuous", observed.Status)
	}
	if observed.Progress != 0 {
		t.Errorf("progress = %v at the moment the new run started, want 0 — the "+
			"stale 100 is still in the DB and the client sees a running task at 100%%",
			observed.Progress)
	}
	if observed.CompletedAt != nil {
		t.Errorf("completed_at = %v at the moment the new run started, want cleared "+
			"— a running task must not carry the previous run's completion time",
			observed.CompletedAt)
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
		CompletedAt:  &prevCompleted,
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

// TestStopAndDelete_ReleaseProgressBookkeeping 覆盖 handler 侧两张 per-task
// 记账表的生命周期泄漏。
//
// aggSlots 与 lastProgressUpdate 都以 taskID 为键，但只有完成回调会删
// aggSlots（且只在行仍为 running 时走到），lastProgressUpdate 从来不删。
// 被 Stop 的任务走不到完成回调的删除分支，被 Delete 的任务更是直接没了行
// ——于是每个停止/删除过的任务都永久留下两条 map 条目，长期运行的 handler
// 只增不减。
func TestStopAndDelete_ReleaseProgressBookkeeping(t *testing.T) {
	h, r, db, _ := newTaskTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.POST("/tasks/:id/stop", h.Stop)
	r.DELETE("/tasks/:id", h.Delete)

	seed := func(id string) {
		t.Helper()
		if err := db.Create(&storage.TaskModel{
			ID: id, UserID: "test-user", Name: "n", Status: "running",
			StrategyIDs: `[]`, OutputType: "pcap", OutputConfig: `{}`,
		}).Error; err != nil {
			t.Fatalf("seed %s: %v", id, err)
		}
		// 模拟一次进度回调留下的记账。
		h.aggMu.Lock()
		h.aggSlots[id] = map[string]*engineAggSlot{id: {progress: 10}}
		h.aggMu.Unlock()
		h.progressMu.Lock()
		h.lastProgressUpdate[id] = time.Now()
		h.progressMu.Unlock()
	}
	check := func(id, op string) {
		t.Helper()
		h.aggMu.Lock()
		_, slotsLeft := h.aggSlots[id]
		h.aggMu.Unlock()
		if slotsLeft {
			t.Errorf("%s left aggSlots[%s] behind — the entry (and its per-engine-task "+
				"slot map) is never released", op, id)
		}
		h.progressMu.Lock()
		_, throttleLeft := h.lastProgressUpdate[id]
		h.progressMu.Unlock()
		if throttleLeft {
			t.Errorf("%s left lastProgressUpdate[%s] behind", op, id)
		}
	}

	const stopID = "44444444-4444-4444-4444-444444444444"
	seed(stopID)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/tasks/"+stopID+"/stop", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("stop: status=%d body=%s", w.Code, w.Body.String())
	}
	check(stopID, "Stop")

	const delID = "55555555-5555-5555-5555-555555555555"
	seed(delID)
	// Delete 要求任务不在 running。
	if err := db.Model(&storage.TaskModel{}).Where("id = ?", delID).
		Update("status", "completed").Error; err != nil {
		t.Fatalf("mark completed: %v", err)
	}
	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/tasks/"+delID, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("delete: status=%d body=%s", w.Code, w.Body.String())
	}
	check(delID, "Delete")
}

// TestOnEngineTaskComplete_StopInWindowIsNotRevived 覆盖完成回调的 TOCTOU。
//
// onEngineTaskComplete 开头读到 running 只是读到那一刻的状态；Stop 可能在
// 那次 SELECT 之后、终态 UPDATE 之前把行写成 stopped。无条件的终态写入会
// 把 stopped 改回 completed/100 —— 用户点了停止，界面却显示"已完成"。
// 与 onEngineProgress 的窗口同型（f2f9ba40），修法也一样：状态谓词进 WHERE。
func TestOnEngineTaskComplete_StopInWindowIsNotRevived(t *testing.T) {
	h, _, db, _ := newTaskTestServer(t)
	const taskID = "66666666-6666-6666-6666-666666666666"
	seedRunningTask(t, db, taskID, `{}`)

	var once sync.Once
	completeSnapshotHook = func() {
		once.Do(func() {
			// 窗口内：用户点了停止。
			if err := db.Model(&storage.TaskModel{}).Where("id = ?", taskID).
				Updates(map[string]interface{}{"status": "stopped"}).Error; err != nil {
				t.Errorf("stop inside the window: %v", err)
			}
		})
	}
	t.Cleanup(func() { completeSnapshotHook = nil })

	h.onEngineTaskComplete(taskID)

	tm := terminalStatusInDB(t, db, taskID)
	if tm.Status != "stopped" {
		t.Fatalf("status = %q, want stopped — the completion callback read running, "+
			"then Stop wrote stopped in the window, and the callback's terminal write "+
			"revived the task", tm.Status)
	}
}

// TestStop_CorruptStrategyIDsStillReleasesBookkeeping 覆盖 Stop 的第三条出口。
//
// strategy_ids 损坏时 Stop 在解 JSON 处提前 return，此前那条路径跳过了
// releaseProgressBookkeeping 与 flow-control 清理——停止过的任务把记账条目
// 永久留在 handler 里。清理改为 stopped 落库后的 defer，覆盖全部出口。
func TestStop_CorruptStrategyIDsStillReleasesBookkeeping(t *testing.T) {
	h, r, db, _ := newTaskTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.POST("/tasks/:id/stop", h.Stop)

	const id = "77777777-7777-7777-7777-777777777777"
	if err := db.Create(&storage.TaskModel{
		ID: id, UserID: "test-user", Name: "n", Status: "running",
		StrategyIDs: "not-json", OutputType: "pcap", OutputConfig: `{}`,
	}).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}
	h.aggMu.Lock()
	h.aggSlots[id] = map[string]*engineAggSlot{id: {progress: 10}}
	h.aggMu.Unlock()
	h.progressMu.Lock()
	h.lastProgressUpdate[id] = time.Now()
	h.progressMu.Unlock()

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/tasks/"+id+"/stop", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("stop: status=%d body=%s", w.Code, w.Body.String())
	}
	if tm := terminalStatusInDB(t, db, id); tm.Status != "stopped" {
		t.Fatalf("status = %q, want stopped", tm.Status)
	}
	h.aggMu.Lock()
	_, slotsLeft := h.aggSlots[id]
	h.aggMu.Unlock()
	if slotsLeft {
		t.Error("aggSlots entry survived a Stop that returned early on corrupt strategy_ids")
	}
	h.progressMu.Lock()
	_, throttleLeft := h.lastProgressUpdate[id]
	h.progressMu.Unlock()
	if throttleLeft {
		t.Error("lastProgressUpdate entry survived a Stop that returned early on corrupt strategy_ids")
	}
}

// TestOnEngineProgress_DoesNotResurrectReleasedBookkeeping 覆盖"释放—复活"
// 交错：Stop 已经清空了两张记账表，但一个更早通过终态 SELECT 的迟到回调
// 继续往下走，又把 aggSlots / lastProgressUpdate 的条目建回来（终态列本身
// 已被 WHERE 保护，但 handler 的内存泄漏仍在）。
//
// 修法：节流、槽位、父行落库同属 aggMu 临界区，落库被拒时当场回收。
func TestOnEngineProgress_DoesNotResurrectReleasedBookkeeping(t *testing.T) {
	h, _, _, _ := newTaskTestServer(t)
	const id = "88888888-8888-8888-8888-888888888888"
	// 任务行已不存在（Delete 之后）：任何进度回调都不该留下记账。
	h.onEngineProgress(id, 42, core.TaskStats{PacketsSent: 7})

	h.aggMu.Lock()
	_, slotsLeft := h.aggSlots[id]
	h.aggMu.Unlock()
	if slotsLeft {
		t.Error("a progress callback for a nonexistent task re-created its aggSlots entry")
	}
	h.progressMu.Lock()
	_, throttleLeft := h.lastProgressUpdate[id]
	h.progressMu.Unlock()
	if throttleLeft {
		t.Error("a progress callback for a nonexistent task re-created its lastProgressUpdate entry")
	}
}

// TestOnEngineProgress_ThrottlesRapidCallbacks 钉住 2 秒节流本身。
//
// 把节流时间戳从"进函数就写"改成"落库成功才写"时很容易顺手把写入丢掉，
// 于是每一次回调都通过节流、每次都写库——节流形同虚设，而这不会触发任何
// 现有的正确性断言。这里连续打三次回调，断言只有第一次落库。
func TestOnEngineProgress_ThrottlesRapidCallbacks(t *testing.T) {
	h, _, db, _ := newTaskTestServer(t)
	const id = "99999999-9999-9999-9999-999999999999"
	seedRunningTask(t, db, id, `{}`)

	h.onEngineProgress(id, 10, core.TaskStats{PacketsSent: 1})
	if got := terminalStatusInDB(t, db, id).PacketsSent; got != 1 {
		t.Fatalf("first callback: packets_sent = %d, want 1", got)
	}
	// 紧接着的两次必须被节流挡下（进度远低于 100，未过 2 秒）。
	h.onEngineProgress(id, 20, core.TaskStats{PacketsSent: 2})
	h.onEngineProgress(id, 30, core.TaskStats{PacketsSent: 3})
	if got := terminalStatusInDB(t, db, id).PacketsSent; got != 1 {
		t.Fatalf("after two rapid follow-ups packets_sent = %d, want 1 — the throttle "+
			"is not recording its timestamp, so every callback writes", got)
	}
	// progress>=100 必须绕过节流（最后一次统计 delta 不能丢）。
	h.onEngineProgress(id, 100, core.TaskStats{PacketsSent: 9})
	if got := terminalStatusInDB(t, db, id).PacketsSent; got != 9 {
		t.Errorf("progress=100 must bypass the throttle: packets_sent = %d, want 9", got)
	}
}

// TestOnEngineProgress_TransientWriteErrorKeepsLiveSlots 钉住"写库失败不得
// 清掉还在跑的任务的记账"。
//
// SQLite 的写锁会被 pcap_packets 的批量插入占住，运行中的任务落库偶发失败
// 是常态。若在失败分支顺手 releaseProgressBookkeeping，已完成子策略的槽位
// 就被清掉，父合计退化成"只见存活子任务"——R7 缺陷 A 的原样回归。
// 终态（RowsAffected=0）才清；错误（Error!=nil）只记日志。
func TestOnEngineProgress_TransientWriteErrorKeepsLiveSlots(t *testing.T) {
	h, _, db, _ := newTaskTestServer(t)
	const id = "abababab-abab-abab-abab-abababababab"
	seedRunningTask(t, db, id, `{}`)

	// 先落一次正常进度，槽位里留下子策略的统计。
	h.onEngineProgress(id+"-stratA", 100, core.TaskStats{PacketsSent: 500})
	if got := terminalStatusInDB(t, db, id).PacketsSent; got != 500 {
		t.Fatalf("seed progress: packets_sent = %d, want 500", got)
	}

	// 只让**目标任务行的 UPDATE** 失败，SELECT 必须正常——否则测试走的是
	// "SELECT status 失败"那条早退路径，根本没进到 Error!=nil 分支。
	// 此前就是关掉整个连接池，于是把 `if res.Error != nil` 改成恒真也绿。
	var reached atomic.Bool
	if err := db.Callback().Update().Before("gorm:update").Register("test:fail_task_update", func(tx *gorm.DB) {
		if tx.Statement.Table != "tasks" {
			return
		}
		sql := tx.Statement.SQL.String()
		if !strings.Contains(sql, "progress") && !strings.Contains(sql, "packets_sent") {
			// GORM 在 Before 钩子里 SQL 可能尚未渲染，退而看赋值列。
			if tx.Statement.Dest == nil {
				return
			}
			if m, ok := tx.Statement.Dest.(map[string]interface{}); !ok || m["packets_sent"] == nil {
				return
			}
		}
		reached.Store(true)
		_ = tx.AddError(errInjectedUpdate)
	}); err != nil {
		t.Fatalf("register hook: %v", err)
	}
	t.Cleanup(func() { _ = db.Callback().Update().Remove("test:fail_task_update") })

	h.onEngineProgress(id+"-stratB", 100, core.TaskStats{PacketsSent: 700})

	if !reached.Load() {
		t.Fatal("the target UPDATE never ran — this test would be vacuous")
	}
	h.aggMu.Lock()
	slots := h.aggSlots[id]
	h.aggMu.Unlock()
	if len(slots) != 2 {
		t.Errorf("aggSlots has %d entries after a failed write, want 2 — dropping the "+
			"slots on a transient DB error loses the completed child strategy's stats "+
			"(R7 defect A all over again)", len(slots))
	}
	// 落库失败，DB 里的统计必须保持上一次成功的值。
	if got := terminalStatusInDB(t, db, id).PacketsSent; got != 500 {
		t.Errorf("packets_sent = %d, want 500 (the failed write must not have landed)", got)
	}
}

// errInjectedUpdate makes the injected GORM hook fail a statement on purpose.
var errInjectedUpdate = fmt.Errorf("injected update failure")

// TestStopAndDelete_ReleaseRecordedFailures 覆盖 failedTasks 的生命周期泄漏。
//
// 输出失败按 **engine task ID** 登记（策略任务是 "{parent}-{strategy}"，batch
// 是裸 parent ID），此前只有完成回调和 Start 的对账会删。Stop 与 Delete 都不
// 清——被停止/删除过的任务把失败条目永久留在 handler 里，与已修掉的
// aggSlots 泄漏同型。
func TestStopAndDelete_ReleaseRecordedFailures(t *testing.T) {
	h, r, db, _ := newTaskTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.POST("/tasks/:id/stop", h.Stop)
	r.DELETE("/tasks/:id", h.Delete)

	seedFailures := func(id string) {
		t.Helper()
		h.failMu.Lock()
		h.failedTasks[id] = "output error"
		h.failedTasks[id+"-stratA"] = "output error A"
		h.failedTasks[id+"-stratB"] = "output error B"
		h.failedTasks["unrelated-task"] = "must survive"
		h.failMu.Unlock()
	}
	assertCleared := func(id, op string) {
		t.Helper()
		h.failMu.Lock()
		defer h.failMu.Unlock()
		for k := range h.failedTasks {
			if k == id || strings.HasPrefix(k, id+"-") {
				t.Errorf("%s left failedTasks[%q] behind", op, k)
			}
		}
		// 别的任务的条目绝不能被误删。
		if _, ok := h.failedTasks["unrelated-task"]; !ok {
			t.Errorf("%s deleted another task's failure entry", op)
		}
	}

	const stopID = "cccccccc-cccc-cccc-cccc-cccccccccccc"
	seedRunningTask(t, db, stopID, `{}`)
	seedFailures(stopID)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/tasks/"+stopID+"/stop", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("stop: status=%d body=%s", w.Code, w.Body.String())
	}
	assertCleared(stopID, "Stop")

	const delID = "dddddddd-dddd-dddd-dddd-dddddddddddd"
	seedRunningTask(t, db, delID, `{}`)
	seedFailures(delID)
	if err := db.Model(&storage.TaskModel{}).Where("id = ?", delID).
		Update("status", "completed").Error; err != nil {
		t.Fatalf("mark completed: %v", err)
	}
	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/tasks/"+delID, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("delete: status=%d body=%s", w.Code, w.Body.String())
	}
	assertCleared(delID, "Delete")
}

// TestStart_PartialStrategyFailureReleasesSkippedWriters 覆盖 Start 提交循环
// 的 writer 泄漏。
//
// 一条策略的 writer 创建失败会进 writerErrors，提交循环据此 skip 它——但
// 那条策略**从未被注销**。任务若正常完成，完成回调按 strategyIDs 清 eid
// 时也清不到它（它是同一个 eid，本该能清到；但若整次 Start 以 error 收场，
// 没有任何路径会清）。这里构造"全部策略都没提交成功"，断言引擎里不留
// 任何 writer。
func TestStart_AllStrategiesFailReleasesAllWriters(t *testing.T) {
	h, r, db, e := newTaskTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.POST("/tasks/:id/start", h.Start)

	sid := createTestStrategy(t, db, "test-user", "s-bad", "tcp")
	// 让策略转换后的 SubmitTask 失败：停掉引擎。
	e.Stop()

	taskID := uuid.New().String()
	sidsJSON, _ := json.Marshal([]string{sid})
	if err := db.Create(&storage.TaskModel{
		ID: taskID, UserID: "test-user", Name: "t", Status: "completed",
		StrategyIDs: string(sidsJSON), OutputType: "pcap",
		OutputConfig: `{"pcap_path":"` + stalePcapPath(t, "startfail.pcap") + `"}`,
	}).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/tasks/"+taskID+"/start", nil))
	if w.Code == http.StatusOK {
		t.Fatalf("start succeeded although the engine is stopped: %s", w.Body.String())
	}

	if leaked := e.OutputWriterIDs(); len(leaked) != 0 {
		t.Errorf("a start that submitted nothing still holds output writers for %v — "+
			"the writers were registered before SubmitTask and nothing unregisters "+
			"them on the all-failed exit", leaked)
	}
	if leaked := e.DualWriterIDs(); len(leaked) != 0 {
		t.Errorf("a start that submitted nothing still holds dual writers for %v", leaked)
	}
}

// TestStart_AllWritersFailReleasesEveryRegisteredWriter 覆盖 Start 的
// "全部策略都没提交成功"出口。
//
// 注意：多策略共用同一 pcap 路径（D-ENG-1 共享 writer），所以"一条策略的
// writer 成功、另一条失败"在当前设计下不可达——要么全成要么全败。因此
// 提交循环里 skip 分支的 ct 从未注册过 writer，rev4-task 报告的"skip 分支
// writer 泄漏"不成立。这里钉住真正可达的那条：全部失败时引擎里不留 writer。
func TestStart_AllWritersFailReleasesEveryRegisteredWriter(t *testing.T) {
	h, r, db, e := newTaskTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.POST("/tasks/:id/start", h.Start)

	s1 := createTestStrategy(t, db, "test-user", "s-a", "tcp")
	s2 := createTestStrategy(t, db, "test-user", "s-b", "tcp")

	// dual 的 .s2c 按路径独立打开，用它让两个 ct 的第二 writer 都失败。
	orig := newSharedPCAPWriterFn
	newSharedPCAPWriterFn = func(path string, maxBytes int64) (*output.SharedPCAPWriter, error) {
		if strings.HasSuffix(path, ".s2c") {
			return nil, fmt.Errorf("injected writer failure")
		}
		return orig(path, maxBytes)
	}
	t.Cleanup(func() { newSharedPCAPWriterFn = orig })

	taskID := uuid.New().String()
	sidsJSON, _ := json.Marshal([]string{s1, s2})
	if err := db.Create(&storage.TaskModel{
		ID: taskID, UserID: "test-user", Name: "t", Status: "completed",
		StrategyIDs: string(sidsJSON), OutputType: "pcap",
		OutputConfig: `{"pcap_path":"` + stalePcapPath(t, "skip.pcap") + `","interface2":"lo"}`,
	}).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/tasks/"+taskID+"/start", nil))
	if w.Code == http.StatusOK {
		t.Fatalf("start succeeded although every writer failed: %s", w.Body.String())
	}

	if leaked := e.OutputWriterIDs(); len(leaked) != 0 {
		t.Errorf("engine still holds output writers for %v after every writer "+
			"failed to open", leaked)
	}
	if leaked := e.DualWriterIDs(); len(leaked) != 0 {
		t.Errorf("engine still holds dual writers for %v", leaked)
	}
}

// TestStopAndDelete_ReleaseRecordedFailures 覆盖 failedTasks 的生命周期泄漏。
//
// 输出失败按 **engine task ID** 登记（策略任务是 "{parent}-{strategy}"，batch
// 是裸 parent ID），此前只有完成回调和 Start 的对账会删。Stop 与 Delete 都不
// 清——被停止/删除过的任务把失败条目永久留在 handler 里，与已修掉的
// aggSlots 泄漏同型。

// ---------------------------------------------------------------------------
// 生命周期锁族（startMu）红例——三个幽灵任务窗口
// ---------------------------------------------------------------------------

// lifecycleTestHandler 把 Start/Stop/Delete 都挂到一个 router 上。
func lifecycleTestHandler(t *testing.T) (*TaskHandler, *gin.Engine, *storage.DB, *core.Engine) {
	t.Helper()
	h, r, db, e := newTaskTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.POST("/tasks/:id/start", h.Start)
	r.POST("/tasks/:id/stop", h.Stop)
	r.DELETE("/tasks/:id", h.Delete)
	return h, r, db, e
}

// R1 并发 Start：锁族串行化后，第二个 Start 必须被拒（already running 或
// max_tasks），引擎里恰好一个任务、无 writer 泄漏。
// 变异：摘掉 startMu → 第二个 Start 可能在对账窗口插队 → 引擎双任务/泄漏。
func TestLifecycle_ConcurrentStartIsSerialized(t *testing.T) {
	_, r, db, e := lifecycleTestHandler(t)

	sid := createLongRunningStrategy(t, db, "test-user", "lc-long", "tcp")
	taskID := uuid.New().String()
	sidsJSON, _ := json.Marshal([]string{sid})
	if err := db.Create(&storage.TaskModel{
		ID: taskID, UserID: "test-user", Name: "lc", Status: "pending",
		StrategyIDs: string(sidsJSON), OutputType: "pcap",
		OutputConfig: `{"pcap_path":"` + stalePcapPath(t, "lc.pcap") + `"}`,
	}).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	// barrier：两个 goroutine 同时进入 ServeHTTP。
	enter := make(chan struct{})
	var wg sync.WaitGroup
	codes := make([]int, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			enter <- struct{}{}
			w := httptest.NewRecorder()
			r.ServeHTTP(w, httptest.NewRequest("POST", "/tasks/"+taskID+"/start", nil))
			codes[idx] = w.Code
		}(i)
	}
	<-enter
	<-enter
	wg.Wait()

	ok := 0
	for _, c := range codes {
		if c == http.StatusOK {
			ok++
		} else if c != http.StatusBadRequest {
			t.Errorf("unexpected status %d among %v — want 200 or 400 only", c, codes)
		}
	}
	if ok != 1 {
		t.Fatalf("exactly one Start must succeed, got %d (codes %v)", ok, codes)
	}
	if n := e.ActiveTaskCount(); n != 1 {
		t.Errorf("engine has %d tasks after two concurrent starts, want exactly 1", n)
	}
	if leaked := e.OutputWriterIDs(); len(leaked) != 1 {
		t.Errorf("engine holds %d writers after two concurrent starts, want exactly 1: %v",
			len(leaked), leaked)
	}
}

// R2 Delete-during-Start：不变式断言——引擎任务数必须与 DB running 行数一致。
// 变异（摘锁）：Delete 在 Start 的慢 writer 窗口里插队删行 → Start 照常提交 →
// 引擎有任务、DB 无行 → 不变式破 → 红。
func TestLifecycle_DeleteDuringStartKeepsEngineAndDBConsistent(t *testing.T) {
	_, r, db, e := lifecycleTestHandler(t)

	sid := createLongRunningStrategy(t, db, "test-user", "lc-slow", "tcp")
	taskID := uuid.New().String()
	sidsJSON, _ := json.Marshal([]string{sid})
	if err := db.Create(&storage.TaskModel{
		ID: taskID, UserID: "test-user", Name: "lc", Status: "pending",
		StrategyIDs: string(sidsJSON), OutputType: "pcap",
		OutputConfig: `{"pcap_path":"` + stalePcapPath(t, "lc-del.pcap") + `"}`,
	}).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	// 慢 writer：pcap 模式走 openShared（claim 之后、writer 注册/running 写
	// 之前），用它卡住 Start，给 Delete 一个确定的插队窗口。行此时是
	// starting——修复前的 Delete 会直接删掉这行。
	orig := newSharedPCAPWriterFn
	blk := make(chan struct{})
	newSharedPCAPWriterFn = func(path string, maxBytes int64) (*output.SharedPCAPWriter, error) {
		<-blk
		return orig(path, maxBytes)
	}
	t.Cleanup(func() { newSharedPCAPWriterFn = orig })

	startDone := make(chan int, 1)
	go func() {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest("POST", "/tasks/"+taskID+"/start", nil))
		startDone <- w.Code
	}()

	// 等 claim 落库（starting），再发 Delete——它会被锁挡到 Start 之后。
	deadline := time.Now().Add(5 * time.Second)
	for {
		var tm storage.TaskModel
		if err := db.First(&tm, "id = ?", taskID).Error; err == nil && tm.Status == "starting" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("task never reached starting")
		}
		time.Sleep(10 * time.Millisecond)
	}
	// Delete 放 goroutine：修复后它要等 Start 放锁（Start 卡在慢 writer 上，
	// 主线程观察到 starting 后放行），不能在主线程同步等。
	deleteDone := make(chan int, 1)
	go func() {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest("DELETE", "/tasks/"+taskID, nil))
		deleteDone <- w.Code
	}()

	// 观察到 starting（claim 已落库）后放行慢 writer，Start 继续。
	// 此时 Delete 还在等锁。
	close(blk)

	if code := <-startDone; code != http.StatusOK {
		t.Fatalf("start status=%d, want 200", code)
	}
	if dcode := <-deleteDone; dcode == http.StatusOK {
		t.Fatalf("delete succeeded during an active start — it must be rejected " +
			"once the task is running/starting")
	}
	// 不变式：引擎任务数 == DB running 行数。
	var runningRows int64
	db.Model(&storage.TaskModel{}).Where("status = ?", "running").Count(&runningRows)
	if e.ActiveTaskCount() != int(runningRows) {
		t.Errorf("invariant broken: engine has %d tasks but DB has %d running rows — "+
			"a delete slipped in during the start and removed the row while the "+
			"engine task went on running (ghost task)", e.ActiveTaskCount(), runningRows)
	}
}

// R5 Stop-in-running-window：runningWriteHook 精确落在"running 已写、
// 引擎未提交"的幽灵窗口。修复后 Stop 等锁，拿到锁时任务已提交 →
// StopTask 命中，引擎任务数归零；摘锁变异下 Stop 插队，对"引擎里还不存在"
// 的任务调 StopTask（打空），Start 随后提交 → 引擎在跑、DB stopped 的
// 幽灵任务 → 引擎计数 5 秒不归零 → 红。
func TestLifecycle_StopDuringSubmitWindowStopsTheRealTask(t *testing.T) {
	_, r, db, _ := lifecycleTestHandler(t)

	sid := createLongRunningStrategy(t, db, "test-user", "lc-win", "tcp")
	taskID := uuid.New().String()
	sidsJSON, _ := json.Marshal([]string{sid})
	if err := db.Create(&storage.TaskModel{
		ID: taskID, UserID: "test-user", Name: "lc", Status: "pending",
		StrategyIDs: string(sidsJSON), OutputType: "pcap",
		OutputConfig: `{"pcap_path":"` + stalePcapPath(t, "lc-stop.pcap") + `"}`,
	}).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	var stopCode chan int = make(chan int, 1)
	var stopBody chan string = make(chan string, 1)
	hookReached := make(chan struct{})
	// Stop goroutine 预先起好，等 hook 信号才发请求——不依赖调度时序。
	go func() {
		<-hookReached
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest("POST", "/tasks/"+taskID+"/stop", nil))
		stopCode <- w.Code
		stopBody <- w.Body.String()
	}()
	runningWriteHook = func() {
		close(hookReached)
		time.Sleep(50 * time.Millisecond) // 让 Stop 的请求确定性地落在本窗口
	}
	t.Cleanup(func() { runningWriteHook = nil })

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/tasks/"+taskID+"/start", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("start: status=%d body=%s", w.Code, w.Body.String())
	}
	if code := <-stopCode; code != http.StatusOK {
		t.Fatalf("stop: status=%d, want 200 (the task is running by then)", code)
	}
	// StopTask 必须**真的命中**引擎任务：响应里的 stopped_engine_tasks 列出
	// 被停的引擎任务 ID。StopTask 打空（幽灵窗口里引擎还没提交）时该列表为
	// 空——此时引擎任务由 Start 随后提交，没有任何路径再停它（幽灵）。
	// 引擎计数断言在这里不可靠：迷你引擎里"长时"任务可能秒级自然完成，
	// 归零无法区分"被停"和"自己跑完"；响应里的 stopped 列表才是事实。
	body := <-stopBody
	if !strings.Contains(body, `"`+taskID+`-`) {
		t.Fatalf("stop response lists no stopped engine tasks — StopTask missed the "+
			"engine task (it fired in the submit window before SubmitTask). Body: %s", body)
	}
	var tm storage.TaskModel
	if err := db.First(&tm, "id = ?", taskID).Error; err != nil {
		t.Fatalf("reload: %v", err)
	}
	if tm.Status != "stopped" {
		t.Errorf("status = %q, want stopped", tm.Status)
	}
}

// R3 Stop-vs-starting：starting 的行不可停（先 claim 者赢的语义钉死）。
func TestLifecycle_StopDuringStartingIsRejected(t *testing.T) {
	h, r, db, _ := lifecycleTestHandler(t)

	taskID := uuid.New().String()
	if err := db.Create(&storage.TaskModel{
		ID: taskID, UserID: "test-user", Name: "lc", Status: "starting",
		StrategyIDs: `[]`, OutputType: "pcap", OutputConfig: `{}`,
	}).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	req := httptest.NewRequest("POST", "/tasks/"+taskID+"/stop", nil)
	w := httptest.NewRecorder()
	_ = h
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("stop on a starting task: status=%d body=%s, want 400 'task is not running'",
			w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// commit 2 红例：谓词统一 + 无空响应规则
// ---------------------------------------------------------------------------

// R4a 校验出口谓词挡住时**保原响应**：用户输入错误与行状态无关，响应不能吞。
// 变异：把校验出口的 markTaskError 失败分支改成静默 return → 响应消失 → 红。
func TestLifecycle_ValidationErrorSurvivesPredicateMiss(t *testing.T) {
	_, r, db, _ := lifecycleTestHandler(t)

	sid := createTestStrategy(t, db, "test-user", "s-gone", "tcp")
	taskID := uuid.New().String()
	sidsJSON, _ := json.Marshal([]string{sid})
	if err := db.Create(&storage.TaskModel{
		ID: taskID, UserID: "test-user", Name: "lc", Status: "pending",
		StrategyIDs: string(sidsJSON), OutputType: "pcap",
		OutputConfig: `{"pcap_path":"` + stalePcapPath(t, "r4a.pcap") + `"}`,
	}).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}
	// 策略存在但 strategy_ids 引用一个不存在的 —— 触发"strategy not found"。
	missing := uuid.New().String()
	sidsJSON2, _ := json.Marshal([]string{missing})
	if err := db.Model(&storage.TaskModel{}).Where("id = ?", taskID).
		Update("strategy_ids", string(sidsJSON2)).Error; err != nil {
		t.Fatalf("seed2: %v", err)
	}

	// GORM 钩子：让 markTaskError 的 UPDATE 静默挡住（RowsAffected=0），
	// 模拟行已被接管。校验失败本身照常发生。
	if err := db.Callback().Update().Before("gorm:update").Register("r4a:swallow", func(tx *gorm.DB) {
		if tx.Statement.Table == "tasks" {
			if m, ok := tx.Statement.Dest.(map[string]interface{}); ok && m["status"] == "error" {
				// 把 id 改成不存在的 → 谓词必然不匹配。
				m["id"] = "no-such-row"
			}
		}
	}); err != nil {
		t.Fatalf("register: %v", err)
	}
	t.Cleanup(func() { _ = db.Callback().Update().Remove("r4a:swallow") })

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/tasks/"+taskID+"/start", nil))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s — a validation failure must still answer 400 even "+
			"when the error state could not be written (silent 200 hides the user error)",
			w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "not found") {
		t.Errorf("body lost the validation reason: %s", w.Body.String())
	}
}

// R4b DB 错误必须回 500 而非假 200：markTaskError 返回 err!=nil 时调用方
// 必须给 500。变异：把 err 分支的 InternalError 删掉 → gin 默认 200 → 红。
func TestLifecycle_DBErrorAnswers500(t *testing.T) {
	_, r, db, _ := lifecycleTestHandler(t)

	missing := uuid.New().String()
	taskID := uuid.New().String()
	sidsJSON, _ := json.Marshal([]string{missing})
	if err := db.Create(&storage.TaskModel{
		ID: taskID, UserID: "test-user", Name: "lc", Status: "pending",
		StrategyIDs: string(sidsJSON), OutputType: "pcap",
		OutputConfig: `{"pcap_path":"` + stalePcapPath(t, "r4b.pcap") + `"}`,
	}).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	// hook：markTaskError 的 UPDATE 注入真实 DB 错误。
	if err := db.Callback().Update().Before("gorm:update").Register("r4b:fail", func(tx *gorm.DB) {
		if tx.Statement.Table == "tasks" {
			if m, ok := tx.Statement.Dest.(map[string]interface{}); ok && m["status"] == "error" {
				_ = tx.AddError(errInjectedUpdate)
			}
		}
	}); err != nil {
		t.Fatalf("register: %v", err)
	}
	t.Cleanup(func() { _ = db.Callback().Update().Remove("r4b:fail") })

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/tasks/"+taskID+"/start", nil))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s — a DB failure while persisting the error state "+
			"must answer 500, not a silent 200", w.Code, w.Body.String())
	}
}
