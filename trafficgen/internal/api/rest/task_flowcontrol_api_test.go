package rest

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// ---------------------------------------------------------------------------
// A1: Task create with invalid FlowControl type → 400
// ---------------------------------------------------------------------------

func TestTaskCreate_FCInvalidType(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, db, _ := newTaskTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.POST("/tasks", h.Create)

	sid := createTestStrategy(t, db, "test-user", "s1", "tcp")
	body := `{"name":"t1","strategy_ids":["` + sid + `"],"output_type":"pcap","output_config":{"pcap_path":"x.pcap"},"flow_control":{"type":"xyz","value":100}}`
	req := httptest.NewRequest("POST", "/tasks", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != 400 {
		t.Errorf("status=%d, want 400 for invalid flow_control type; body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// A2: Task create with negative FlowControl value → 400
// ---------------------------------------------------------------------------

func TestTaskCreate_FCNegativeValue(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, db, _ := newTaskTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.POST("/tasks", h.Create)

	sid := createTestStrategy(t, db, "test-user", "s1", "tcp")
	body := `{"name":"t1","strategy_ids":["` + sid + `"],"output_type":"pcap","output_config":{"pcap_path":"x.pcap"},"flow_control":{"type":"bps","value":-1}}`
	req := httptest.NewRequest("POST", "/tasks", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != 400 {
		t.Errorf("status=%d, want 400 for negative flow_control value; body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// A3: Task dedup distinguishes different FlowControl
// Same strategy+output but different FC → two different tasks (no merge)
// ---------------------------------------------------------------------------

func TestTaskCreate_DedupDifferentFC(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, db, _ := newTaskTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.POST("/tasks", h.Create)

	sid := createTestStrategy(t, db, "test-user", "s1", "tcp")
	baseBody := `{"name":"t1","strategy_ids":["` + sid + `"],"output_type":"pcap","output_config":{"pcap_path":"x.pcap"}`

	// Create with bps=200M
	body1 := baseBody + `,"flow_control":{"type":"bps","value":200000000}}`
	req1 := httptest.NewRequest("POST", "/tasks", strings.NewReader(body1))
	req1.Header.Set("Content-Type", "application/json")
	w1 := httptest.NewRecorder()
	r.ServeHTTP(w1, req1)
	if w1.Code != 201 {
		t.Fatalf("first create: status=%d, body=%s", w1.Code, w1.Body.String())
	}
	_, _, data1 := parseResponse(t, w1.Body.Bytes())
	var d1 map[string]string
	json.Unmarshal(data1, &d1)

	// Create with bps=300M — should NOT dedup (different FC)
	body2 := baseBody + `,"flow_control":{"type":"bps","value":300000000}}`
	req2 := httptest.NewRequest("POST", "/tasks", strings.NewReader(body2))
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)
	if w2.Code != 201 {
		t.Fatalf("second create with different FC: status=%d (want 201, not dedup), body=%s", w2.Code, w2.Body.String())
	}
	_, _, data2 := parseResponse(t, w2.Body.Bytes())
	var d2 map[string]string
	json.Unmarshal(data2, &d2)

	if d2["id"] == d1["id"] {
		t.Error("tasks with different FlowControl were deduped (should be separate)")
	}
}

// ---------------------------------------------------------------------------
// A4: Task dedup matches same FlowControl
// Same strategy+output+FC → returns existing task (dedup)
// ---------------------------------------------------------------------------

func TestTaskCreate_DedupSameFC(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, db, _ := newTaskTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.POST("/tasks", h.Create)

	sid := createTestStrategy(t, db, "test-user", "s1", "tcp")
	body := `{"name":"t1","strategy_ids":["` + sid + `"],"output_type":"pcap","output_config":{"pcap_path":"x.pcap"},"flow_control":{"type":"bps","value":200000000}}`

	req1 := httptest.NewRequest("POST", "/tasks", strings.NewReader(body))
	req1.Header.Set("Content-Type", "application/json")
	w1 := httptest.NewRecorder()
	r.ServeHTTP(w1, req1)
	if w1.Code != 201 {
		t.Fatalf("first: status=%d", w1.Code)
	}
	_, _, data1 := parseResponse(t, w1.Body.Bytes())
	var d1 map[string]string
	json.Unmarshal(data1, &d1)

	req2 := httptest.NewRequest("POST", "/tasks", strings.NewReader(body))
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)
	if w2.Code != 200 {
		t.Fatalf("second (dedup): status=%d, want 200", w2.Code)
	}
	_, _, data2 := parseResponse(t, w2.Body.Bytes())
	var d2 map[string]string
	json.Unmarshal(data2, &d2)

	if d2["id"] != d1["id"] {
		t.Errorf("dedup failed: got %s, want %s", d2["id"], d1["id"])
	}
}
