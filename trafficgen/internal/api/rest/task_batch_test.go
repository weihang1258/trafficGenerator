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

	"github.com/gin-gonic/gin"
	sqlite "github.com/glebarez/sqlite"
	"github.com/google/gopacket"
	glayers "github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	httpproto "github.com/trafficgen/trafficgen/internal/protocol/http"
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
		`{"id":"tcp","type":"tcp","flow_count":2,"config":{"tcp":{"handshake":true,"termination":true}},"tuples":{"src_ip":{"strategy":"fixed","value":"10.0.0.1"},"dst_ip":{"strategy":"fixed","value":"10.0.0.2"},"src_port":{"strategy":"fixed","value":1000},"dst_port":{"strategy":"fixed","value":80}}},` +
		`{"id":"udp","type":"udp","flow_count":2,"config":{},"tuples":{"src_ip":{"strategy":"fixed","value":"10.0.0.3"},"dst_ip":{"strategy":"fixed","value":"10.0.0.4"},"src_port":{"strategy":"fixed","value":2000},"dst_port":{"strategy":"fixed","value":53}}}` +
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
		`{"id":"tcp","type":"tcp","flow_count":1,"config":{"tcp":{"handshake":true,"termination":true}},"tuples":{"src_ip":{"strategy":"fixed","value":"10.0.0.1"},"dst_ip":{"strategy":"fixed","value":"10.0.0.2"},"src_port":{"strategy":"fixed","value":1000},"dst_port":{"strategy":"fixed","value":80}}}` +
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
//
// 同时锁定：拒绝必须是无副作用的。此前 Start 先无条件把 DB 写成
// "starting" 并把 Progress 清零、ErrorMessage 清空，之后才判断 batch，
// 于是这条已成功的任务被改成 error/progress=0——流量确实发出去了，记录
// 却判失败（客户端 2026-11-23 报告问题 1）。本用例断言状态与进度原封
// 不动（原断言 want 'error' 正是把该副作用当成了规格）。
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
	if tm.Status != "completed" {
		t.Fatalf("precondition: batch task status = %q, want 'completed'", tm.Status)
	}
	statusBefore, progressBefore := tm.Status, tm.Progress

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

	// 拒绝必须只读：状态/进度/错误信息都不能被这次误调改写。
	db.First(&tm, "id = ?", taskID)
	if tm.Status != statusBefore {
		t.Errorf("task status = %q after rejected start, want unchanged %q "+
			"(a rejected start must not rewrite a finished task)", tm.Status, statusBefore)
	}
	if tm.Progress != progressBefore {
		t.Errorf("task progress = %v after rejected start, want unchanged %v", tm.Progress, progressBefore)
	}
	if tm.ErrorMessage != "" {
		t.Errorf("task error_message = %q after rejected start, want empty", tm.ErrorMessage)
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

// D-ROBUST-2（客户端复测 N1/N2）：
// N1 batch 建单期字段闸——同一非法配置单任务口拒、批量口此前放行（分叉）。
func TestCreateBatch_RejectsLayerFieldOutOfRange(t *testing.T) {
	gin.SetMode(gin.TestMode)
	gormDB, err := gorm.Open(sqlite.Open(t.TempDir()+"/test.db"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := storage.AutoMigrate(gormDB); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	e := core.NewEngine(core.EngineConfig{ConfigWorkers: 1, PacketWorkers: 1, OutputWorkers: 1, BufferSize: 256, QueueSize: 64})
	if err := e.Start(); err != nil {
		t.Fatalf("start engine: %v", err)
	}
	defer e.Stop()
	h := NewTaskHandler(&storage.DB{DB: gormDB}, e, nil)
	r := gin.New()
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.POST("/tasks/batch", h.CreateBatch)

	body := `{"name":"n1-bgp-v7","batch":{"classes":[{"id":"c1","type":"bgp","flow_count":1,"config":{"layers":[{"ip":{"src":"10.0.0.1","dst":"20.0.0.1"}},{"tcp":{"dst_port":179}},{"bgp":{"version":7}}]}}]},"output_type":"pcap","output_config":{"pcap_path":"/tmp/n1.pcap"}}`
	req := httptest.NewRequest("POST", "/tasks/batch", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 400 {
		t.Fatalf("bgp version=7 via batch = %d, want 400 (parity with single-task create)", w.Code)
	}
	if !strings.Contains(w.Body.String(), "[4,4]") {
		t.Fatalf("body = %s, want range anchor [4,4]", w.Body.String())
	}
}

// N1b：未知层字段同样拒绝（与单任务口一致）。
func TestCreateBatch_RejectsUnknownLayerField(t *testing.T) {
	gin.SetMode(gin.TestMode)
	gormDB, _ := gorm.Open(sqlite.Open(t.TempDir()+"/test.db"), &gorm.Config{})
	if err := storage.AutoMigrate(gormDB); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	e := core.NewEngine(core.EngineConfig{ConfigWorkers: 1, PacketWorkers: 1, OutputWorkers: 1, BufferSize: 256, QueueSize: 64})
	if err := e.Start(); err != nil {
		t.Fatalf("start engine: %v", err)
	}
	defer e.Stop()
	h := NewTaskHandler(&storage.DB{DB: gormDB}, e, nil)
	r := gin.New()
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.POST("/tasks/batch", h.CreateBatch)

	body := `{"name":"n1-unknown","batch":{"classes":[{"id":"c1","type":"udp","flow_count":1,"config":{"layers":[{"ip":{"src":"10.0.0.1","dst":"20.0.0.1"}},{"udp":{"dst_port":53,"bogus_field":1}}]}}]},"output_type":"pcap","output_config":{"pcap_path":"/tmp/n1u.pcap"}}`
	req := httptest.NewRequest("POST", "/tasks/batch", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 400 || !strings.Contains(w.Body.String(), "unknown field") {
		t.Fatalf("unknown layer field via batch = %d %s, want 400 + unknown-field anchor", w.Code, w.Body.String())
	}
}

// N2：flow_count 可省略，缺省 1（与单任务"省略=1 流"同语义；显式 0 同归缺省，
// §6.4 0=默认惯例同源）。
func TestCreateBatch_FlowCountDefaultsToOne(t *testing.T) {
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
	e.RegisterPlanner(udp.NewPlanner())
	e.SetBuildFunc(core.NewBuilder().Build)
	// 该用例的 class 带 layers 链，必须挂层链规划器工厂（生产 cmd/server/main.go
	// 恒挂；单任务路径未挂时 SubmitTask 直接报 "layer planner factory not wired"）。
	// 不挂则 batch 类计失败，任务止于 failed 而非产 1 包。
	e.SetLayerPlannerFactory(layers.BuildLayersPlanner)
	if err := e.Start(); err != nil {
		t.Fatalf("start engine: %v", err)
	}
	defer e.Stop()

	h := NewTaskHandler(db, e, nil)
	r := gin.New()
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.POST("/tasks/batch", h.CreateBatch)

	pcapPath := t.TempDir() + "/n2.pcap"
	body := `{"name":"n2-nofc","batch":{"classes":[{"id":"c1","type":"udp","config":{"layers":[{"ip":{"src":"10.0.0.1","dst":"20.0.0.1"}},{"udp":{"dst_port":9502}}]}}]},"output_type":"pcap","output_config":{"pcap_path":"` + pcapPath + `"}}`
	req := httptest.NewRequest("POST", "/tasks/batch", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 201 {
		t.Fatalf("flow_count omitted = %d %s, want 201 (default 1)", w.Code, w.Body.String())
	}
	var resp struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil || resp.Data.ID == "" {
		t.Fatalf("unparseable create response %s: %v", w.Body.String(), err)
	}
	// 等待完成：缺省 1 流应产出恰好 1 个 udp 数据报。
	deadline := time.Now().Add(15 * time.Second)
	var task storage.TaskModel
	for time.Now().Before(deadline) {
		if err := db.Where("id = ?", resp.Data.ID).First(&task).Error; err == nil && task.Status == "completed" {
			if task.PacketsSent != 1 {
				t.Fatalf("default flow_count task = %d packets, want 1 (one flow)", task.PacketsSent)
			}
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("task %s did not complete in time (status=%s)", resp.Data.ID, task.Status)
}

// TestCreateBatch_LayersReachWire 是层链字段落线的端到端回归：
// batch class 的 layers 里写 tcp.dst_port=8080 / http.uri / 状态码，
// 产出的 pcap 必须真的是这些值。修复前该 class 走按协议名注册的默认
// planner（chain=nil → completeSynthesized 全默认链），端口落 80、
// 请求行落 "/"、响应落 200，任务却报 completed —— 校验读层链、执行不读。
func TestCreateBatch_LayersReachWire(t *testing.T) {
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
	e.RegisterPlanner(httpproto.NewPlanner())
	e.SetBuildFunc(core.NewBuilder().Build)
	e.SetLayerPlannerFactory(layers.BuildLayersPlanner)
	if err := e.Start(); err != nil {
		t.Fatalf("start engine: %v", err)
	}
	defer e.Stop()

	h := NewTaskHandler(db, e, nil)
	r := gin.New()
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.POST("/tasks/batch", h.CreateBatch)

	pcapPath := t.TempDir() + "/layers-wire.pcap"
	body := `{"name":"layers-wire","batch":{"classes":[{"id":"c1","type":"http","flow_count":1,` +
		`"config":{"layers":[{"ip":{"src":"10.1.1.1","dst":"10.1.1.2"}},` +
		`{"tcp":{"src_port":22000,"dst_port":8080}},` +
		`{"http":{"uri":"/custom/path","response_status_code":404}}]}}]},` +
		`"output_type":"pcap","output_config":{"pcap_path":"` + pcapPath + `"}}`
	req := httptest.NewRequest("POST", "/tasks/batch", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("create = %d %s", w.Code, w.Body.String())
	}
	var resp struct {
		Data map[string]string `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v body=%s", err, w.Body.String())
	}
	taskID := resp.Data["id"]

	deadline := time.Now().Add(10 * time.Second)
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

	// 读回 pcap，逐包检查层链值是否真的落到线上。
	f, err := os.Open(pcapPath)
	if err != nil {
		t.Fatalf("open pcap: %v", err)
	}
	defer f.Close()
	rd, err := pcapgo.NewReader(f)
	if err != nil {
		t.Fatalf("pcap reader: %v", err)
	}

	var sawRequest, sawResponse bool
	var dstPorts []uint16
	for {
		data, _, rerr := rd.ReadPacketData()
		if rerr != nil {
			break
		}
		pkt := gopacket.NewPacket(data, glayers.LayerTypeEthernet, gopacket.Default)
		tcpLayer, _ := pkt.Layer(glayers.LayerTypeTCP).(*glayers.TCP)
		appLayer := pkt.ApplicationLayer()
		if tcpLayer == nil || appLayer == nil || len(appLayer.Payload()) == 0 {
			continue
		}
		dstPorts = append(dstPorts, uint16(tcpLayer.DstPort))
		payload := string(appLayer.Payload())
		if strings.HasPrefix(payload, "GET ") {
			sawRequest = true
			if want := "GET /custom/path HTTP/1.1"; !strings.HasPrefix(payload, want) {
				t.Errorf("request line = %q, want prefix %q (layers http.uri dropped)", firstLine(payload), want)
			}
			if tcpLayer.DstPort != 8080 {
				t.Errorf("request dst_port = %d, want 8080 (layers tcp.dst_port dropped)", tcpLayer.DstPort)
			}
			if tcpLayer.SrcPort != 22000 {
				t.Errorf("request src_port = %d, want 22000 (layers tcp.src_port dropped)", tcpLayer.SrcPort)
			}
		}
		if strings.HasPrefix(payload, "HTTP/1.1 ") {
			sawResponse = true
			if want := "HTTP/1.1 404"; !strings.HasPrefix(payload, want) {
				t.Errorf("status line = %q, want prefix %q (layers response_status_code dropped)", firstLine(payload), want)
			}
		}
	}
	if !sawRequest {
		t.Errorf("no HTTP request found in pcap (dst_ports seen: %v)", dstPorts)
	}
	if !sawResponse {
		t.Error("no HTTP response found in pcap")
	}
}

// firstLine returns the first CRLF-terminated line of a payload, for messages.
func firstLine(s string) string {
	if i := strings.Index(s, "\r\n"); i >= 0 {
		return s[:i]
	}
	return s
}

// newBatchTestServer 起一个最小 batch 测试环境（DB + engine + 路由）。
func newBatchTestServer(t *testing.T) (*TaskHandler, *gin.Engine, *storage.DB, *core.Engine) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	gormDB, err := gorm.Open(sqlite.Open(t.TempDir()+"/batch.db"), &gorm.Config{})
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
	e.SetLayerPlannerFactory(layers.BuildLayersPlanner)
	if err := e.Start(); err != nil {
		t.Fatalf("start engine: %v", err)
	}
	t.Cleanup(func() { e.Stop() })

	h := NewTaskHandler(db, e, nil)
	r := gin.New()
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.POST("/tasks/batch", h.CreateBatch)
	return h, r, db, e
}

// TestCreateBatch_DualPortFailureReleasesBothWriters 覆盖双端口任务的失败
// 清理路径。
//
// 双端口走 RegisterDualWriter（写 engine.dualWriters），三条失败分支
// （DB 落库失败、MTU 失败、SubmitTask 失败）必须调 UnregisterDualWriter。
// 调 UnregisterOutputWriter 的话在 dualWriters 里找不到东西，静默什么都不做
// ——失败任务把两个已打开的 writer（pcap 文件句柄 / 网卡句柄）永久留在引擎里。
//
// 关键：writer 是在两个都创建成功**之后**才注册的，所以必须让失败发生在
// 注册之后。这里停掉引擎，让 SubmitTask 返回 "engine not running"——它排在
// RegisterDualWriter 之后（此前用坏 bps 触发失败，那个在任何 writer 打开
// 之前就被 ValidateBatchSpec 拒了，什么都没注册，断言恒真，等于没测）。
func TestCreateBatch_DualPortFailureReleasesBothWriters(t *testing.T) {
	_, r, _, e := newBatchTestServer(t)

	// 让失败发生在 RegisterDualWriter **之后**。CreateBatch 的顺序是
	// 开 writer -> RegisterDualWriter -> 落库 -> ensureTaskMTU -> SubmitTask；
	// 停掉引擎后 SubmitTask 必定返回 "engine not running"，此时 writer 已经
	// 注册进 dualWriters。此前用坏 bps 触发失败，那个在任何 writer 打开之前
	// 就被 ValidateBatchSpec 拒了，什么都没注册，断言恒真（改回
	// UnregisterOutputWriter 照样绿）。
	e.Stop()

	body := `{"name":"dual-fail","batch":{"classes":[{"id":"c1","type":"udp",` +
		`"config":{"layers":[{"ip":{"src":"10.9.9.1","dst":"10.9.9.2"}},{"udp":{"dst_port":9000}}]}}]},` +
		`"output_type":"pcap","output_config":{"pcap_path":"` + t.TempDir() + `/dual.pcap","interface2":"lo"}}`
	req := httptest.NewRequest("POST", "/tasks/batch", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code == http.StatusCreated {
		t.Fatalf("batch was accepted although the engine is stopped: %s", w.Body.String())
	}

	if leaked := e.DualWriterIDs(); len(leaked) != 0 {
		t.Fatalf("dual-port task creation failed but engine still holds dual writers for %v — "+
			"the failure path calls UnregisterOutputWriter instead of UnregisterDualWriter, "+
			"so the writers (and their file/NIC handles) are never closed", leaked)
	}
}

// TestCreateBatch_FailureDoesNotDestroyExistingPcap 覆盖"先开资源后做会失败
// 的检查"造成的破坏面：pcap writer 用 os.Create 打开（O_TRUNC），所以只要
// 走到开 writer 那一步，目标路径上的旧文件就已经被清空；之后 bps 校验失败、
// 任务返回 400 —— 旧数据没了，新任务也没跑。
//
// 用户语义：任务没起来，磁盘上就不该有任何改变。
func TestCreateBatch_FailureDoesNotDestroyExistingPcap(t *testing.T) {
	_, r, _, _ := newBatchTestServer(t)

	pcapPath := t.TempDir() + "/existing.pcap"
	const previous = "PREVIOUS-RUN-BYTES"
	if err := os.WriteFile(pcapPath, []byte(previous), 0o644); err != nil {
		t.Fatalf("seed pcap: %v", err)
	}

	body := `{"name":"trunc-fail","batch":{"classes":[{"id":"c1","type":"udp","bps":"not-a-rate",` +
		`"config":{"layers":[{"ip":{"src":"10.9.9.1","dst":"10.9.9.2"}},{"udp":{"dst_port":9000}}]}}]},` +
		`"output_type":"pcap","output_config":{"pcap_path":"` + pcapPath + `"}}`
	req := httptest.NewRequest("POST", "/tasks/batch", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code == http.StatusCreated {
		t.Fatalf("invalid bps was accepted: %s", w.Body.String())
	}
	// 必须被**建单前的**校验拒（400 + bps 文案）。若坏 bps 漏到
	// engine.SubmitTask 才拒，那时 writer 早已 os.Create 截断过目标文件，
	// 后面的"文件没变"断言就会红——但只看状态码分不出这两条路径，
	// 校验被悄悄挪回开 writer 之后时这里照样绿。
	if !strings.Contains(w.Body.String(), "invalid bps") {
		t.Fatalf("rejected with %d %s, want the pre-writer bps validation "+
			"(a bps error surfacing from SubmitTask means the writer was opened first)",
			w.Code, w.Body.String())
	}

	got, err := os.ReadFile(pcapPath)
	if err != nil {
		t.Fatalf("read pcap after failed create: %v", err)
	}
	if string(got) != previous {
		t.Fatalf("the existing pcap was modified by a task that never started: got %d bytes %q, "+
			"want the previous %d bytes %q — the output writer opens with O_TRUNC before the "+
			"checks that can still fail", len(got), string(got), len(previous), previous)
	}
}

// TestCreateBatch_ReplayClassBadBPSDoesNotDestroyExistingPcap 覆盖 bps 前置
// 校验在 replay 分支上的漏洞。
//
// ValidateBatchSpec 里 replay 类在 `continue` 处提前返回，排在 bps 校验之前，
// 所以 replay class 的 bps 从没被提前验证；而 engine.SubmitTask 对**所有**
// class 校验 bps。于是 "replay + 坏 bps" 走到开 writer 之后才失败——正是
// 0b080415 声称修掉的"毁掉上一次 pcap"那个坑，在 replay 分支原样复现。
func TestCreateBatch_ReplayClassBadBPSDoesNotDestroyExistingPcap(t *testing.T) {
	_, r, db, _ := newBatchTestServer(t)

	// replay 需要一个真实存在的 pcap 资产。
	if err := db.Create(&storage.PcapAssetModel{
		ID: "ast-replay", UserID: "test-user", Name: "r.pcap", Status: "ready",
		LinkType: 1, FileHash: "hash-replay",
	}).Error; err != nil {
		t.Fatalf("seed asset: %v", err)
	}

	pcapPath := t.TempDir() + "/existing-replay.pcap"
	const previous = "PREVIOUS-RUN-BYTES"
	if err := os.WriteFile(pcapPath, []byte(previous), 0o644); err != nil {
		t.Fatalf("seed pcap: %v", err)
	}

	body := `{"name":"replay-bps","batch":{"classes":[{"id":"r1","type":"replay","bps":"not-a-rate",` +
		`"replay":{"pcap_asset_id":"ast-replay","speed":{"mode":"original"}}}]},` +
		`"output_type":"pcap","output_config":{"pcap_path":"` + pcapPath + `"}}`
	req := httptest.NewRequest("POST", "/tasks/batch", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code == http.StatusCreated {
		t.Fatalf("replay class with invalid bps was accepted: %s", w.Body.String())
	}
	// 同 TestCreateBatch_FailureDoesNotDestroyExistingPcap：必须是建单前的
	// 校验拒的。replay 类曾在 ValidateBatchSpec 里 `continue` 跳过 bps 检查，
	// 于是失败推迟到 SubmitTask——writer 已开、文件已毁。
	if !strings.Contains(w.Body.String(), "invalid bps") {
		t.Fatalf("rejected with %d %s, want the pre-writer bps validation",
			w.Code, w.Body.String())
	}

	got, err := os.ReadFile(pcapPath)
	if err != nil {
		t.Fatalf("read pcap: %v", err)
	}
	if string(got) != previous {
		t.Fatalf("existing pcap was modified by a replay task that never started: "+
			"got %d bytes %q, want %q — the replay branch returns before the bps "+
			"check, so the writer opens (os.Create truncates) before the failure",
			len(got), string(got), previous)
	}
}
