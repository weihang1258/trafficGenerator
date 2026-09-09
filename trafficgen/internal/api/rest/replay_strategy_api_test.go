package rest

// Spec-driven tests for replay-as-strategy at the REST API layer (RS1-RS9).
// Verifies:
//   - RS1-RS3: Strategy create with mode=replay (success, validation, FC).
//   - RS4: Strategy create with mode=synth (default) succeeds.
//   - RS5: Strategy update with mode=replay updates mode correctly.
//   - RS6-RS8: Task create with replay strategy + task-level FC (bps conflict,
//     flows ok, bps+bps ok).
//   - RS9: Strategy list/get returns mode field.

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/trafficgen/trafficgen/internal/storage"
)

// createReplayStrategyForTest inserts a replay-mode strategy directly into the
// DB and returns its ID. Bypasses the REST handler so task tests can reference
// a realistic replay strategy without needing a stored pcap asset.
func createReplayStrategyForTest(t *testing.T, db *storage.DB, userID, name, speedMode string) string {
	t.Helper()
	config := `{"pcap_asset_id":"a1","speed":{"mode":"` + speedMode + `"}}`
	ch := calculateConfigHash("replay", "", config, "")
	id := uuid.New().String()
	if err := db.Create(&storage.StrategyModel{
		ID:         id,
		UserID:     userID,
		Name:       name,
		Mode:       "replay",
		Protocol:   "",
		Config:     config,
		FlowControl: "",
		ConfigHash: ch,
	}).Error; err != nil {
		t.Fatalf("create replay strategy: %v", err)
	}
	return id
}

// RS1: POST /strategies with mode=replay and valid replay config succeeds,
// persists mode="replay".
func TestReplayStrategy_Create_Success(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, db := newStrategyTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Set("username", "alice"); c.Set("roles", []string{"user"}); c.Next() })
	r.POST("/strategies", h.Create)

	body := `{"name":"r1","mode":"replay","config":{"pcap_asset_id":"a1","speed":{"mode":"original"}}}`
	req := httptest.NewRequest("POST", "/strategies", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != 201 {
		t.Fatalf("status=%d, body=%s", w.Code, w.Body.String())
	}
	var s storage.StrategyModel
	db.Where("name = ?", "r1").First(&s)
	if s.Mode != "replay" {
		t.Errorf("persisted Mode = %q, want \"replay\"", s.Mode)
	}
	if s.Protocol != "" {
		t.Errorf("persisted Protocol = %q, want empty for replay", s.Protocol)
	}
}

// RS2: POST /strategies with mode=replay and invalid speed mode -> 400.
func TestReplayStrategy_Create_InvalidSpeedMode(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, _ := newStrategyTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.POST("/strategies", h.Create)

	body := `{"name":"r1","mode":"replay","config":{"pcap_asset_id":"a1","speed":{"mode":"pps","pps":100}}}`
	req := httptest.NewRequest("POST", "/strategies", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != 400 {
		t.Errorf("status=%d, want 400 for pps speed mode; body=%s", w.Code, w.Body.String())
	}
	_, msg, _ := parseResponse(t, w.Body.Bytes())
	if !strings.Contains(msg, "invalid speed mode") {
		t.Errorf("msg=%q, want substring 'invalid speed mode'", msg)
	}
}

// RS3: POST /strategies with mode=replay and flow_control.type != "time" -> 400.
func TestReplayStrategy_Create_InvalidFCType(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, _ := newStrategyTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.POST("/strategies", h.Create)

	body := `{"name":"r1","mode":"replay","config":{"pcap_asset_id":"a1","speed":{"mode":"original"}},"flow_control":{"type":"flows","value":10}}`
	req := httptest.NewRequest("POST", "/strategies", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != 400 {
		t.Errorf("status=%d, want 400 for flows FC on replay; body=%s", w.Code, w.Body.String())
	}
	_, msg, _ := parseResponse(t, w.Body.Bytes())
	if !strings.Contains(msg, "flow_control only supports type=time") {
		t.Errorf("msg=%q, want substring 'flow_control only supports type=time'", msg)
	}
}

// RS4: POST /strategies with mode=synth (default) and valid config succeeds.
func TestReplayStrategy_Create_SynthDefault(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, db := newStrategyTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.POST("/strategies", h.Create)

	// No mode field -> defaults to synth
	body := `{"name":"s1","protocol":"tcp","config":{"src_ip":"10.0.0.1","dst_ip":"10.0.0.2"}}`
	req := httptest.NewRequest("POST", "/strategies", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != 201 {
		t.Fatalf("status=%d, body=%s", w.Code, w.Body.String())
	}
	var s storage.StrategyModel
	db.Where("name = ?", "s1").First(&s)
	if s.Mode != "synth" {
		t.Errorf("persisted Mode = %q, want \"synth\" (default)", s.Mode)
	}
	if s.Protocol != "tcp" {
		t.Errorf("persisted Protocol = %q, want \"tcp\"", s.Protocol)
	}
}

// RS5: PUT /strategies/:id with mode=replay updates mode correctly.
func TestReplayStrategy_Update_ModeSwitch(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, db := newStrategyTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.PUT("/strategies/:id", h.Update)

	// Create a synth strategy first
	sid := createTestStrategy(t, db, "test-user", "s1", "tcp")

	// Update to replay
	body := `{"name":"s1-replay","mode":"replay","config":{"pcap_asset_id":"a1","speed":{"mode":"original"}}}`
	req := httptest.NewRequest("PUT", "/strategies/"+sid, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("status=%d, body=%s", w.Code, w.Body.String())
	}
	var s storage.StrategyModel
	db.Where("id = ?", sid).First(&s)
	if s.Mode != "replay" {
		t.Errorf("updated Mode = %q, want \"replay\"", s.Mode)
	}
	if s.Protocol != "" {
		t.Errorf("updated Protocol = %q, want empty for replay", s.Protocol)
	}
}

// RS5-BR: PUT /strategies/:id WITHOUT mode field preserves the existing mode.
// A replay strategy updated without mode should stay replay (validated as
// replay, not synth). Before the fix, empty mode defaulted to "synth" and
// validation failed because replay config has no src_ip/dst_ip.
func TestReplayStrategy_Update_PreservesModeWhenOmitted(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, db := newStrategyTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.PUT("/strategies/:id", h.Update)

	// Create a replay strategy first
	sid := createReplayStrategyForTest(t, db, "test-user", "r1", "original")

	// Update WITHOUT mode field, with valid replay config + new name
	body := `{"name":"r1-updated","config":{"pcap_asset_id":"a1","speed":{"mode":"original"}}}`
	req := httptest.NewRequest("PUT", "/strategies/"+sid, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("status=%d, want 200 (mode preserved from existing replay strategy); body=%s", w.Code, w.Body.String())
	}
	var s storage.StrategyModel
	db.Where("id = ?", sid).First(&s)
	if s.Mode != "replay" {
		t.Errorf("Mode = %q, want \"replay\" (preserved from existing)", s.Mode)
	}
	if s.Name != "r1-updated" {
		t.Errorf("Name = %q, want \"r1-updated\"", s.Name)
	}
}

// RS6: POST /tasks with replay strategy (original speed) + task-level FC bps
// -> 400 (schema.ValidateTaskCreate replay+bps conflict: TimestampPacer + parent bps bucket violates R-F2).
func TestReplayStrategy_TaskBPSConflict(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, db, _ := newTaskTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.POST("/tasks", h.Create)

	sid := createReplayStrategyForTest(t, db, "test-user", "r1", "original")
	body := `{"name":"t1","strategy_ids":["` + sid + `"],"output_type":"pcap","output_config":{"pcap_path":"x.pcap"},"flow_control":{"type":"bps","value":1000000}}`
	req := httptest.NewRequest("POST", "/tasks", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != 400 {
		t.Errorf("status=%d, want 400 for replay original + bps task FC; body=%s", w.Code, w.Body.String())
	}
	_, msg, _ := parseResponse(t, w.Body.Bytes())
	if !strings.Contains(msg, "cannot combine with bps task-level flow control") {
		t.Errorf("msg=%q, want substring 'cannot combine with bps task-level flow control'", msg)
	}
}

// RS7: POST /tasks with replay strategy (original speed) + task-level FC flows
// -> success (no conflict; flows ceiling uses shared counter, not rate bucket).
func TestReplayStrategy_TaskFlowsNoConflict(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, db, _ := newTaskTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.POST("/tasks", h.Create)

	sid := createReplayStrategyForTest(t, db, "test-user", "r1", "original")
	body := `{"name":"t1","strategy_ids":["` + sid + `"],"output_type":"pcap","output_config":{"pcap_path":"x.pcap"},"flow_control":{"type":"flows","value":10}}`
	req := httptest.NewRequest("POST", "/tasks", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != 201 {
		t.Errorf("status=%d, want 201 for replay original + flows task FC (no conflict); body=%s", w.Code, w.Body.String())
	}
}

// RS8: POST /tasks with replay strategy (bps speed) + task-level FC bps -> success
// (both bps: no TimestampPacer, engine child bucket + parent bucket coexist fine).
func TestReplayStrategy_TaskBPSNoConflict(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, db, _ := newTaskTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.POST("/tasks", h.Create)

	sid := createReplayStrategyForTest(t, db, "test-user", "r1", "bps")
	// Need bps value in config for replay bps mode to be valid. Update config:
	db.Model(&storage.StrategyModel{}).Where("id = ?", sid).
		Update("config", `{"pcap_asset_id":"a1","speed":{"mode":"bps","bps":"1m"}}`)

	body := `{"name":"t1","strategy_ids":["` + sid + `"],"output_type":"pcap","output_config":{"pcap_path":"x.pcap"},"flow_control":{"type":"bps","value":2000000}}`
	req := httptest.NewRequest("POST", "/tasks", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != 201 {
		t.Errorf("status=%d, want 201 for replay bps + bps task FC (both bps, no conflict); body=%s", w.Code, w.Body.String())
	}
}

// RS9: GET /strategies returns mode field populated.
func TestReplayStrategy_List_ReturnsMode(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, db := newStrategyTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.GET("/strategies", h.List)

	createTestStrategy(t, db, "test-user", "synth1", "tcp")
	createReplayStrategyForTest(t, db, "test-user", "replay1", "original")

	req := httptest.NewRequest("GET", "/strategies", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("status=%d, body=%s", w.Code, w.Body.String())
	}
	_, _, data := parseResponse(t, w.Body.Bytes())
	var strategies []map[string]interface{}
	if err := json.Unmarshal(data, &strategies); err != nil {
		t.Fatalf("unmarshal: %v, data=%s", err, string(data))
	}
	var sawSynth, sawReplay bool
	for _, s := range strategies {
		mode, _ := s["mode"].(string)
		if mode == "synth" {
			sawSynth = true
		}
		if mode == "replay" {
			sawReplay = true
		}
	}
	if !sawSynth {
		t.Error("missing synth strategy in list (mode field)")
	}
	if !sawReplay {
		t.Error("missing replay strategy in list (mode field)")
	}
}
