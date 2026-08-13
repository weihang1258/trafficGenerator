package rest

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	"github.com/trafficgen/trafficgen/internal/storage"
)

// TestStart_LayersStrategyNoFactoryFails: a strategy whose config carries a
// "layers" key must fail the task start when the engine has no layer-planner
// factory wired (unit-test server; the production binary wires
// layers.BuildLayersPlanner in cmd/server/main.go). This pins the P2c-1 mount
// block in TaskHandler.Start: the raw layers JSON must reach the engine, and
// the submission failure must surface as a task error — never a silent
// empty-flow success.
func TestStart_LayersStrategyNoFactoryFails(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, db, _ := newTaskTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.POST("/tasks", h.Create)
	r.POST("/tasks/:id/start", h.Start)

	// Strategy with a layers chain (single [tcp] layer = legacy-style chain,
	// valid per P3 validation) — created directly in the DB, bypassing the
	// Create handler's ValidateLayers (P3 已覆盖创建路径).
	config := `{"layers":[{"tcp":{}}],"src_ip":"10.0.0.1","dst_ip":"10.0.0.2"}`
	fc := `{"type":"flows","value":1}`
	ch := calculateConfigHash("synth", "tcp", config, fc)
	sid := uuid.New().String()
	if err := db.Create(&storage.StrategyModel{
		ID: sid, UserID: "test-user", Name: "layers-tcp", Protocol: "tcp",
		Config: config, FlowControl: fc, ConfigHash: ch,
	}).Error; err != nil {
		t.Fatalf("create strategy: %v", err)
	}

	// Create the task.
	body := `{"name":"layers-task","strategy_ids":["` + sid + `"],"output_type":"pcap","output_config":{"pcap_path":"layers.pcap"},"flow_control":{"type":"flows","value":1}}`
	req := httptest.NewRequest("POST", "/tasks", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 201 {
		t.Fatalf("create task: status=%d body=%s", w.Code, w.Body.String())
	}

	// Start: with no factory wired, the layers submission must fail loudly.
	req = httptest.NewRequest("POST", "/tasks/"+taskIDFromBody(t, w.Body.Bytes())+"/start", nil)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 500 {
		t.Fatalf("start: status=%d body=%s (want 500: no layer planner factory)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "failed to start any strategy") {
		t.Errorf("start error body=%s (want strategy failure message)", w.Body.String())
	}
}

// TestStart_LayersStrategyDispatchesChainPlanner: with the production factory
// wired (layers.BuildLayersPlanner), a strategy carrying a "layers" key must
// start successfully and generate packets — the full mount → SubmitTask →
// worker dispatch path. The engine's per-task planner entry is consumed by
// the worker and cleaned up at completion, so a completed task proves the
// layers config reached the ChainPlanner (an unmounted layers key would make
// SubmitTask fail with "layer planner factory not wired", as the no-factory
// test above pins).
func TestStart_LayersStrategyDispatchesChainPlanner(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, db, e := newTaskTestServer(t)
	e.SetLayerPlannerFactory(layers.BuildLayersPlanner)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.POST("/tasks", h.Create)
	r.POST("/tasks/:id/start", h.Start)

	// Single [tcp] layer chain (legacy-style, valid per P3 validation).
	config := `{"layers":[{"tcp":{}}],"src_ip":"10.0.0.1","dst_ip":"10.0.0.2"}`
	fc := `{"type":"flows","value":1}`
	ch := calculateConfigHash("synth", "tcp", config, fc)
	sid := uuid.New().String()
	if err := db.Create(&storage.StrategyModel{
		ID: sid, UserID: "test-user", Name: "layers-tcp", Protocol: "tcp",
		Config: config, FlowControl: fc, ConfigHash: ch,
	}).Error; err != nil {
		t.Fatalf("create strategy: %v", err)
	}

	body := `{"name":"layers-task","strategy_ids":["` + sid + `"],"output_type":"pcap","output_config":{"pcap_path":"layers.pcap"},"flow_control":{"type":"flows","value":1}}`
	req := httptest.NewRequest("POST", "/tasks", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 201 {
		t.Fatalf("create task: status=%d body=%s", w.Code, w.Body.String())
	}
	taskID := taskIDFromBody(t, w.Body.Bytes())

	req = httptest.NewRequest("POST", "/tasks/"+taskID+"/start", nil)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("start: status=%d body=%s", w.Code, w.Body.String())
	}

	// The engine task must complete (packets generated) — poll with a timeout.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := e.GetTaskStatus(taskID + "-" + sid); err != nil {
			// task gone = completed/cleaned up
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, err := e.GetTaskStatus(taskID + "-" + sid); err == nil {
		t.Error("engine task never completed")
	}
}
func taskIDFromBody(t *testing.T, body []byte) string {
	t.Helper()
	var resp struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("parse create response: %v", err)
	}
	if resp.Data.ID == "" {
		t.Fatalf("create response missing id: %s", body)
	}
	return resp.Data.ID
}
