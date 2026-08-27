package rest

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	sqlite "github.com/glebarez/sqlite"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/protocol/tcp"
	"github.com/trafficgen/trafficgen/internal/protocol/udp"
	"github.com/trafficgen/trafficgen/internal/storage"
	"gorm.io/gorm"
)

func newTaskTestServer(t *testing.T) (*TaskHandler, *gin.Engine, *storage.DB, *core.Engine) {
	t.Helper()
	gormDB, err := gorm.Open(sqlite.Open(t.TempDir()+"/task_test.db"), &gorm.Config{})
	if err != nil { t.Fatalf("open db: %v", err) }
	if err := storage.AutoMigrate(gormDB); err != nil { t.Fatalf("migrate: %v", err) }
	db := &storage.DB{DB: gormDB}

	e := core.NewEngine(core.EngineConfig{
		ConfigWorkers: 1, PacketWorkers: 1, OutputWorkers: 1,
		BufferSize: 256, QueueSize: 64,
	})
	e.RegisterPlanner(tcp.NewPlanner())
	e.RegisterPlanner(udp.NewPlanner())
	e.SetBuildFunc(core.NewBuilder().Build)
	if err := e.Start(); err != nil { t.Fatalf("start engine: %v", err) }
	t.Cleanup(func() { e.Stop() })

	h := NewTaskHandler(db, e, nil)
	r := gin.New()
	return h, r, db, e
}

// ---------------------------------------------------------------------------
// TaskHandler — Create (TASK1-*)
// ---------------------------------------------------------------------------

func TestTaskCreate_Success(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, db, _ := newTaskTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.POST("/tasks", h.Create)

	sid := createTestStrategy(t, db, "test-user", "s1", "tcp")
	body := `{"name":"t1","strategy_ids":["` + sid + `"],"output_type":"pcap","output_config":{"pcap_path":"t1.pcap"}}`
	req := httptest.NewRequest("POST", "/tasks", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != 201 { t.Fatalf("status=%d, body=%s", w.Code, w.Body.String()) }
	code, msg, data := parseResponse(t, w.Body.Bytes())
	if code != 0 { t.Errorf("code=%d", code) }
	if !strings.Contains(msg, "created") { t.Errorf("msg=%q", msg) }
	var d map[string]string
	json.Unmarshal(data, &d)
	if d["id"] == "" { t.Error("id empty") }

	var task storage.TaskModel
	db.Where("id = ?", d["id"]).First(&task)
	if task.Status != "pending" { t.Errorf("status=%q", task.Status) }
	if task.Protocol != "tcp" { t.Errorf("protocol=%q", task.Protocol) }
}

func TestTaskCreate_NoUser(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, _, _ := newTaskTestServer(t)
	r.POST("/tasks", h.Create)
	req := httptest.NewRequest("POST", "/tasks", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 401 { t.Fatalf("status=%d", w.Code) }
}

func TestTaskCreate_BadJSON(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, _, _ := newTaskTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.POST("/tasks", h.Create)
	req := httptest.NewRequest("POST", "/tasks", strings.NewReader("x"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 400 { t.Fatalf("status=%d", w.Code) }
}

func TestTaskCreate_MissingName(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, _, _ := newTaskTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.POST("/tasks", h.Create)
	req := httptest.NewRequest("POST", "/tasks", strings.NewReader(`{"strategy_ids":["x"],"output_type":"pcap","output_config":{"pcap_path":"x.pcap"}}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 400 { t.Fatalf("status=%d", w.Code) }
}

func TestTaskCreate_EmptyStrategyIDs(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, _, _ := newTaskTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.POST("/tasks", h.Create)
	body := `{"name":"t1","strategy_ids":[],"output_type":"pcap","output_config":{"pcap_path":"x.pcap"}}`
	req := httptest.NewRequest("POST", "/tasks", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 400 { t.Fatalf("status=%d", w.Code) }
	_, msg, _ := parseResponse(t, w.Body.Bytes())
	// Either the binding "min" tag or the handler's explicit check rejects empty list.
	if !strings.Contains(msg, "strategy_id") && !strings.Contains(msg, "StrategyIDs") { t.Errorf("msg=%q", msg) }
}

func TestTaskCreate_PortGroupNoID(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, _, _ := newTaskTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.POST("/tasks", h.Create)
	body := `{"name":"t1","strategy_ids":["x"],"output_type":"port_group","output_config":{}}`
	req := httptest.NewRequest("POST", "/tasks", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 400 { t.Fatalf("status=%d", w.Code) }
}

func TestTaskCreate_PcapNoPath(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, _, _ := newTaskTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.POST("/tasks", h.Create)
	body := `{"name":"t1","strategy_ids":["x"],"output_type":"pcap","output_config":{"pcap_path":""}}`
	req := httptest.NewRequest("POST", "/tasks", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 400 { t.Fatalf("status=%d", w.Code) }
}

func TestTaskCreate_StrategyNotFound(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, _, _ := newTaskTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.POST("/tasks", h.Create)
	body := `{"name":"t1","strategy_ids":["nonexistent"],"output_type":"pcap","output_config":{"pcap_path":"x.pcap"}}`
	req := httptest.NewRequest("POST", "/tasks", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 400 { t.Fatalf("status=%d", w.Code) }
	_, msg, _ := parseResponse(t, w.Body.Bytes())
	if !strings.Contains(msg, "strategy") || !strings.Contains(msg, "not found") { t.Errorf("msg=%q", msg) }
}

func TestTaskCreate_StrategyDBError(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, db, _ := newTaskTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.POST("/tasks", h.Create)
	sqlDB, _ := db.DB.DB()
	sqlDB.Close()
	body := `{"name":"t1","strategy_ids":["x"],"output_type":"pcap","output_config":{"pcap_path":"x.pcap"}}`
	req := httptest.NewRequest("POST", "/tasks", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code < 400 { t.Fatalf("status=%d", w.Code) }
}

func TestTaskCreate_MultiStrategyProtocol(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, db, _ := newTaskTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.POST("/tasks", h.Create)
	sid1 := createTestStrategy(t, db, "test-user", "s1", "tcp")
	sid2 := createTestStrategy(t, db, "test-user", "s2", "udp")

	body := `{"name":"t1","strategy_ids":["` + sid1 + `","` + sid2 + `"],"output_type":"pcap","output_config":{"pcap_path":"x.pcap"}}`
	req := httptest.NewRequest("POST", "/tasks", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 201 { t.Fatalf("status=%d", w.Code) }
	code, _, data := parseResponse(t, w.Body.Bytes())
	if code != 0 { t.Errorf("code=%d", code) }
	var d map[string]string
	json.Unmarshal(data, &d)
	var task storage.TaskModel
	db.Where("id = ?", d["id"]).First(&task)
	if task.Protocol != "tcp" { t.Errorf("protocol=%q, want tcp (first)", task.Protocol) }
}

func TestTaskCreate_Dedup(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, db, _ := newTaskTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.POST("/tasks", h.Create)
	sid := createTestStrategy(t, db, "test-user", "s1", "tcp")
	body := `{"name":"t1","strategy_ids":["` + sid + `"],"output_type":"pcap","output_config":{"pcap_path":"x.pcap"}}`

	req := httptest.NewRequest("POST", "/tasks", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 201 { t.Fatalf("first: %d", w.Code) }
	code, _, data := parseResponse(t, w.Body.Bytes())
	var d1 map[string]string
	json.Unmarshal(data, &d1)

	req2 := httptest.NewRequest("POST", "/tasks", strings.NewReader(body))
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)
	if w2.Code != 200 { t.Fatalf("second: %d", w2.Code) }
	code2, _, data2 := parseResponse(t, w2.Body.Bytes())
	if code2 != 0 { t.Errorf("code=%d", code2) }
	var d2 map[string]string
	json.Unmarshal(data2, &d2)
	if d2["id"] != d1["id"] { t.Errorf("dedup failed: %s vs %s", d2["id"], d1["id"]) }
	_ = code
}

func TestTaskCreate_DBCreateFail(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, db, _ := newTaskTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.POST("/tasks", h.Create)
	sid := createTestStrategy(t, db, "test-user", "s1", "tcp")
	sqlDB, _ := db.DB.DB()
	sqlDB.Close()

	body := `{"name":"t1","strategy_ids":["` + sid + `"],"output_type":"pcap","output_config":{"pcap_path":"x.pcap"}}`
	req := httptest.NewRequest("POST", "/tasks", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code < 400 { t.Fatalf("status=%d", w.Code) }
	// DB is closed, so the strategy query may fail before reaching the create step.
	// Accept either error path.
	_, msg, _ := parseResponse(t, w.Body.Bytes())
	if !strings.Contains(msg, "failed to") { t.Errorf("msg=%q", msg) }
}

func TestTaskCreate_FCNil(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, db, _ := newTaskTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.POST("/tasks", h.Create)
	sid := createTestStrategy(t, db, "test-user", "s1", "tcp")
	body := `{"name":"t1","strategy_ids":["` + sid + `"],"output_type":"pcap","output_config":{"pcap_path":"x.pcap"}}`
	req := httptest.NewRequest("POST", "/tasks", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 201 { t.Fatalf("status=%d", w.Code) }
}

func TestTaskCreate_CompletedNotDedup(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, db, _ := newTaskTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.POST("/tasks", h.Create)
	sid := createTestStrategy(t, db, "test-user", "s1", "tcp")
	body := `{"name":"t1","strategy_ids":["` + sid + `"],"output_type":"pcap","output_config":{"pcap_path":"x.pcap"}}`

	// Create a completed task with same config
	oc, _ := json.Marshal(OutputConfigRequest{PcapPath: "x.pcap"})
	ss, _ := json.Marshal([]string{sid})
	db.Create(&storage.TaskModel{
		ID: uuid.New().String(), UserID: "test-user", Name: "t0",
		StrategyIDs: string(ss), OutputConfig: string(oc), Status: "completed",
	})

	req := httptest.NewRequest("POST", "/tasks", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 201 { t.Fatalf("completed task should not dedup, got %d", w.Code) }
}

func TestTaskCreate_DedupUnordered(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, db, _ := newTaskTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.POST("/tasks", h.Create)
	sid1 := createTestStrategy(t, db, "test-user", "s1", "tcp")
	sid2 := createTestStrategy(t, db, "test-user", "s2", "udp")

	body1 := `{"name":"t1","strategy_ids":["` + sid1 + `","` + sid2 + `"],"output_type":"pcap","output_config":{"pcap_path":"x.pcap"}}`
	req := httptest.NewRequest("POST", "/tasks", strings.NewReader(body1))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 201 { t.Fatalf("first: %d", w.Code) }
	_, _, data := parseResponse(t, w.Body.Bytes())
	var d1 map[string]string
	json.Unmarshal(data, &d1)

	// Reverse order
	body2 := `{"name":"t2","strategy_ids":["` + sid2 + `","` + sid1 + `"],"output_type":"pcap","output_config":{"pcap_path":"x.pcap"}}`
	req2 := httptest.NewRequest("POST", "/tasks", strings.NewReader(body2))
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)
	if w2.Code != 200 { t.Fatalf("second: %d", w2.Code) }
	_, _, data2 := parseResponse(t, w2.Body.Bytes())
	var d2 map[string]string
	json.Unmarshal(data2, &d2)
	if d2["id"] != d1["id"] { t.Errorf("unordered dedup failed: %s vs %s", d2["id"], d1["id"]) }
}

// ---------------------------------------------------------------------------
// TaskHandler — List (TASK3-*)
// ---------------------------------------------------------------------------

func TestTaskList_Default(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, db, _ := newTaskTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.GET("/tasks", h.List)

	db.Create(&storage.TaskModel{ID: uuid.New().String(), UserID: "test-user", Name: "t1", Status: "pending"})

	req := httptest.NewRequest("GET", "/tasks", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 200 { t.Fatalf("status=%d", w.Code) }
	code, _, data := parseResponse(t, w.Body.Bytes())
	if code != 0 { t.Errorf("code=%d", code) }
	var d map[string]interface{}
	json.Unmarshal(data, &d)
	if d["total"].(float64) < 1 { t.Errorf("total=%v", d["total"]) }
	if d["page"].(float64) != 1 { t.Errorf("page=%v", d["page"]) }
	if d["size"].(float64) != 20 { t.Errorf("size=%v", d["size"]) }
}

func TestTaskList_CustomPage(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, db, _ := newTaskTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.GET("/tasks", h.List)

	for i := 0; i < 10; i++ {
		db.Create(&storage.TaskModel{ID: uuid.New().String(), UserID: "test-user", Name: "t", Status: "pending"})
	}

	req := httptest.NewRequest("GET", "/tasks?page=2&size=5", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 200 { t.Fatalf("status=%d", w.Code) }
	code, _, data := parseResponse(t, w.Body.Bytes())
	if code != 0 { t.Errorf("code=%d", code) }
	var d map[string]interface{}
	json.Unmarshal(data, &d)
	if d["page"].(float64) != 2 { t.Errorf("page=%v", d["page"]) }
	if d["size"].(float64) != 5 { t.Errorf("size=%v", d["size"]) }
}

func TestTaskList_InvalidPage(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, _, _ := newTaskTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.GET("/tasks", h.List)
	req := httptest.NewRequest("GET", "/tasks?page=abc", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 200 { t.Fatalf("status=%d", w.Code) }
}

func TestTaskList_InvalidSize(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, _, _ := newTaskTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.GET("/tasks", h.List)
	req := httptest.NewRequest("GET", "/tasks?size=abc", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 200 { t.Fatalf("status=%d", w.Code) }
}

func TestTaskList_SizeCapped(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, _, _ := newTaskTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.GET("/tasks", h.List)
	req := httptest.NewRequest("GET", "/tasks?size=500", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 200 { t.Fatalf("status=%d", w.Code) }
	code, _, data := parseResponse(t, w.Body.Bytes())
	if code != 0 { t.Errorf("code=%d", code) }
	var d map[string]interface{}
	json.Unmarshal(data, &d)
	if d["size"].(float64) != 100 { t.Errorf("size=%v, want 100", d["size"]) }
}

func TestTaskList_StatusFilter(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, db, _ := newTaskTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.GET("/tasks", h.List)

	db.Create(&storage.TaskModel{ID: uuid.New().String(), UserID: "test-user", Name: "running", Status: "running"})
	db.Create(&storage.TaskModel{ID: uuid.New().String(), UserID: "test-user", Name: "pending", Status: "pending"})

	req := httptest.NewRequest("GET", "/tasks?status=running", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 200 { t.Fatalf("status=%d", w.Code) }
	code, _, data := parseResponse(t, w.Body.Bytes())
	if code != 0 { t.Errorf("code=%d", code) }
	var d map[string]interface{}
	json.Unmarshal(data, &d)
	items := d["items"].([]interface{})
	for _, item := range items {
		m := item.(map[string]interface{})
		if m["status"] != "running" {
			t.Errorf("expected running, got %v", m["status"])
		}
	}
}

func TestTaskList_InvalidSortBy(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, db, _ := newTaskTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.GET("/tasks", h.List)
	db.Create(&storage.TaskModel{ID: uuid.New().String(), UserID: "test-user", Name: "t1", Status: "pending"})

	// Invalid sort_by value falls back to default "created_at" — not an error.
	req := httptest.NewRequest("GET", "/tasks?sort_by=hacked", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 200 { t.Fatalf("status=%d", w.Code) }
}

func TestTaskList_Ascending(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, _, _ := newTaskTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.GET("/tasks", h.List)
	req := httptest.NewRequest("GET", "/tasks?sort_order=ascending", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 200 { t.Fatalf("status=%d", w.Code) }
}

func TestTaskList_DescendingDefault(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, _, _ := newTaskTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.GET("/tasks", h.List)
	req := httptest.NewRequest("GET", "/tasks", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 200 { t.Fatalf("status=%d", w.Code) }
}

func TestTaskList_NoUser(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, _, _ := newTaskTestServer(t)
	r.GET("/tasks", h.List)
	req := httptest.NewRequest("GET", "/tasks", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 401 { t.Fatalf("status=%d", w.Code) }
}

func TestTaskList_DBFindFail(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, db, _ := newTaskTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.GET("/tasks", h.List)
	sqlDB, _ := db.DB.DB()
	sqlDB.Close()
	req := httptest.NewRequest("GET", "/tasks", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code < 400 { t.Fatalf("status=%d", w.Code) }
}

func TestTaskList_Empty(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, _, _ := newTaskTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.GET("/tasks", h.List)
	req := httptest.NewRequest("GET", "/tasks", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 200 { t.Fatalf("status=%d", w.Code) }
	code, _, data := parseResponse(t, w.Body.Bytes())
	if code != 0 { t.Errorf("code=%d", code) }
	var d map[string]interface{}
	json.Unmarshal(data, &d)
	if d["total"].(float64) != 0 { t.Errorf("total=%v", d["total"]) }
	items := d["items"].([]interface{})
	if len(items) != 0 { t.Errorf("expected empty items") }
}

// ---------------------------------------------------------------------------
// TaskHandler — Get (TASK4-*)
// ---------------------------------------------------------------------------

func TestTaskGet_Success(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, db, _ := newTaskTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.GET("/tasks/:id", h.Get)
	sid := createTestStrategy(t, db, "test-user", "s1", "tcp")
	ss, _ := json.Marshal([]string{sid})
	oc, _ := json.Marshal(OutputConfigRequest{PcapPath: "x.pcap"})
	taskID := uuid.New().String()
	db.Create(&storage.TaskModel{
		ID: taskID, UserID: "test-user", Name: "t1",
		StrategyIDs: string(ss), OutputConfig: string(oc), Status: "pending",
	})

	req := httptest.NewRequest("GET", "/tasks/"+taskID, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 200 { t.Fatalf("status=%d", w.Code) }
	code, _, _ := parseResponse(t, w.Body.Bytes())
	if code != 0 { t.Errorf("code=%d", code) }
}

func TestTaskGet_NoUser(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, _, _ := newTaskTestServer(t)
	r.GET("/tasks/:id", h.Get)
	req := httptest.NewRequest("GET", "/tasks/x", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 401 { t.Fatalf("status=%d", w.Code) }
}

func TestTaskGet_MissingID(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, _, _ := newTaskTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.GET("/tasks/:id", h.Get)
	// Gin doesn't match /tasks/ (no id) to the :id route - returns 404 (no route).
	req := httptest.NewRequest("GET", "/tasks/_empty", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 400 && w.Code != 404 { t.Fatalf("status=%d", w.Code) }
}

func TestTaskGet_NotFound(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, _, _ := newTaskTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.GET("/tasks/:id", h.Get)
	req := httptest.NewRequest("GET", "/tasks/nonexistent", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 404 { t.Fatalf("status=%d", w.Code) }
	_, msg, _ := parseResponse(t, w.Body.Bytes())
	if !strings.Contains(msg, "task not found") { t.Errorf("msg=%q", msg) }
}

func TestTaskGet_DBError(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, db, _ := newTaskTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.GET("/tasks/:id", h.Get)
	sqlDB, _ := db.DB.DB()
	sqlDB.Close()
	req := httptest.NewRequest("GET", "/tasks/x", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code < 400 { t.Fatalf("status=%d", w.Code) }
}

// ---------------------------------------------------------------------------
// TaskHandler — Start (TASK5-*)
// ---------------------------------------------------------------------------

func TestTaskStart_SinglePcap(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, db, e := newTaskTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.POST("/tasks/:id/start", h.Start)

	sid := createTestStrategy(t, db, "test-user", "s1", "tcp")
	ss, _ := json.Marshal([]string{sid})
	pcapPath := t.TempDir() + "/start.pcap"
	oc, _ := json.Marshal(OutputConfigRequest{PcapPath: pcapPath})
	taskID := uuid.New().String()
	db.Create(&storage.TaskModel{
		ID: taskID, UserID: "test-user", Name: "t1",
		StrategyIDs: string(ss), OutputConfig: string(oc), OutputType: "pcap", Status: "pending",
		FlowControl: `{"type":"flows","value":1}`,
	})

	req := httptest.NewRequest("POST", "/tasks/"+taskID+"/start", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 200 { t.Fatalf("status=%d, body=%s", w.Code, w.Body.String()) }
	code, msg, data := parseResponse(t, w.Body.Bytes())
	if code != 0 { t.Errorf("code=%d", code) }
	if !strings.Contains(msg, "task started") { t.Errorf("msg=%q", msg) }
	var d map[string]interface{}
	json.Unmarshal(data, &d)
	etIDs := d["engine_task_ids"].([]interface{})
	if len(etIDs) == 0 { t.Error("no engine_task_ids") }

	var task storage.TaskModel
	db.Where("id = ?", taskID).First(&task)
	if task.Status != "running" { t.Errorf("status=%q", task.Status) }
	if task.StartedAt == nil { t.Error("started_at nil") }

	// Wait for engine to complete
	time.Sleep(200 * time.Millisecond)
	_ = e
}

func TestTaskStart_NoUser(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, _, _ := newTaskTestServer(t)
	r.POST("/tasks/:id/start", h.Start)
	req := httptest.NewRequest("POST", "/tasks/x/start", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 401 { t.Fatalf("status=%d", w.Code) }
}

func TestTaskStart_MissingID(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, _, _ := newTaskTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.POST("/tasks/:id/start", h.Start)
	req := httptest.NewRequest("POST", "/tasks//start", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 400 { t.Fatalf("status=%d", w.Code) }
}

func TestTaskStart_NotFound(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, _, _ := newTaskTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.POST("/tasks/:id/start", h.Start)
	req := httptest.NewRequest("POST", "/tasks/nonexistent/start", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 404 { t.Fatalf("status=%d", w.Code) }
	_, msg, _ := parseResponse(t, w.Body.Bytes())
	if !strings.Contains(msg, "task not found") { t.Errorf("msg=%q", msg) }
}

func TestTaskStart_DBError(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, db, _ := newTaskTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.POST("/tasks/:id/start", h.Start)
	sqlDB, _ := db.DB.DB()
	sqlDB.Close()
	req := httptest.NewRequest("POST", "/tasks/x/start", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code < 400 { t.Fatalf("status=%d", w.Code) }
}

func TestTaskStart_AlreadyRunning(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, db, e := newTaskTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.POST("/tasks/:id/start", h.Start)
	sid := createTestStrategy(t, db, "test-user", "s1", "tcp")
	sidsJSON, _ := json.Marshal([]string{sid})
	taskID := uuid.New().String()
	db.Create(&storage.TaskModel{
		ID: taskID, UserID: "test-user", Name: "t1", Status: "running",
		StrategyIDs: string(sidsJSON),
		OutputType:  "pcap", OutputConfig: `{"pcap_path":"/tmp/already.pcap"}`,
	})
	// The engine must genuinely own the task for the "already running" guard
	// to fire (a stale DB status with no engine task is reconciled instead).
	ct, err := core.StrategyModelToTask(&storage.TaskModel{
		ID: taskID, UserID: "test-user", Name: "t1",
		StrategyIDs: string(sidsJSON),
		OutputType:  "pcap", OutputConfig: `{"pcap_path":"/tmp/already.pcap"}`,
	}, &storage.StrategyModel{
		ID: sid, UserID: "test-user", Name: "s1", Protocol: "tcp",
		Config: `{"src_ip":"10.0.0.1","dst_ip":"10.0.0.2"}`, Mode: "synth",
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
	if w.Code != 400 { t.Fatalf("status=%d", w.Code) }
	_, msg, _ := parseResponse(t, w.Body.Bytes())
	if !strings.Contains(msg, "already running") { t.Errorf("msg=%q", msg) }
}

func TestTaskStart_OptimisticLock(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, db, e := newTaskTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.POST("/tasks/:id/start", h.Start)
	sid := createTestStrategy(t, db, "test-user", "s1", "tcp")
	sidsJSON, _ := json.Marshal([]string{sid})
	taskID := uuid.New().String()
	db.Create(&storage.TaskModel{
		ID: taskID, UserID: "test-user", Name: "t1", Status: "pending",
		StrategyIDs: string(sidsJSON),
		OutputType:  "pcap", OutputConfig: `{"pcap_path":"/tmp/lock.pcap"}`,
	})
	// Simulate a concurrent start that already owns the engine task, then
	// pre-change status to "running" so the handler's "already running"
	// guard fires (a true optimistic-lock race — WHERE status=pending matches
	// 0 rows — cannot be simulated without intercepting the DB layer).
	ct, err := core.StrategyModelToTask(&storage.TaskModel{
		ID: taskID, UserID: "test-user", Name: "t1",
		StrategyIDs: string(sidsJSON),
		OutputType:  "pcap", OutputConfig: `{"pcap_path":"/tmp/lock.pcap"}`,
	}, &storage.StrategyModel{
		ID: sid, UserID: "test-user", Name: "s1", Protocol: "tcp",
		Config: `{"src_ip":"10.0.0.1","dst_ip":"10.0.0.2"}`, Mode: "synth",
	}, "")
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	if err := e.SubmitTask(*ct); err != nil {
		t.Fatalf("submit precondition: %v", err)
	}
	db.Model(&storage.TaskModel{}).Where("id = ?", taskID).Update("status", "running")

	req := httptest.NewRequest("POST", "/tasks/"+taskID+"/start", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 400 { t.Fatalf("status=%d", w.Code) }
	_, msg, _ := parseResponse(t, w.Body.Bytes())
	if !strings.Contains(msg, "already running") { t.Errorf("msg=%q", msg) }
}

func TestTaskStart_CorruptStrategyIDs(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, db, _ := newTaskTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.POST("/tasks/:id/start", h.Start)
	taskID := uuid.New().String()
	db.Create(&storage.TaskModel{ID: taskID, UserID: "test-user", Name: "t1", Status: "pending", StrategyIDs: "{bad"})

	req := httptest.NewRequest("POST", "/tasks/"+taskID+"/start", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code < 400 { t.Fatalf("status=%d", w.Code) }
	_, msg, _ := parseResponse(t, w.Body.Bytes())
	if !strings.Contains(msg, "corrupt") { t.Errorf("msg=%q", msg) }
}

// ---------------------------------------------------------------------------
// TaskHandler — Stop (TASK6-*)
// ---------------------------------------------------------------------------

func TestTaskStop_Single(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, db, _ := newTaskTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.POST("/tasks/:id/stop", h.Stop)
	taskID := uuid.New().String()
	sid := createTestStrategy(t, db, "test-user", "s1", "tcp")
	ss, _ := json.Marshal([]string{sid})
	oc, _ := json.Marshal(OutputConfigRequest{PcapPath: t.TempDir() + "/stop.pcap"})
	db.Create(&storage.TaskModel{
		ID: taskID, UserID: "test-user", Name: "t1",
		StrategyIDs: string(ss), OutputConfig: string(oc), OutputType: "pcap", Status: "running",
	})

	req := httptest.NewRequest("POST", "/tasks/"+taskID+"/stop", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 200 { t.Fatalf("status=%d, body=%s", w.Code, w.Body.String()) }
	code, msg, _ := parseResponse(t, w.Body.Bytes())
	if code != 0 { t.Errorf("code=%d", code) }
	if !strings.Contains(msg, "task stopped") { t.Errorf("msg=%q", msg) }
}

func TestTaskStop_NoUser(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, _, _ := newTaskTestServer(t)
	r.POST("/tasks/:id/stop", h.Stop)
	req := httptest.NewRequest("POST", "/tasks/x/stop", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 401 { t.Fatalf("status=%d", w.Code) }
}

func TestTaskStop_MissingID(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, _, _ := newTaskTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.POST("/tasks/:id/stop", h.Stop)
	// Gin doesn't match /tasks//stop (empty id) - returns 404 (no route).
	req := httptest.NewRequest("POST", "/tasks/_empty/stop", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 400 && w.Code != 404 { t.Fatalf("status=%d", w.Code) }
}

func TestTaskStop_NotFound(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, _, _ := newTaskTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.POST("/tasks/:id/stop", h.Stop)
	req := httptest.NewRequest("POST", "/tasks/nonexistent/stop", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 404 { t.Fatalf("status=%d", w.Code) }
}

func TestTaskStop_DBError(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, db, _ := newTaskTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.POST("/tasks/:id/stop", h.Stop)
	sqlDB, _ := db.DB.DB()
	sqlDB.Close()
	req := httptest.NewRequest("POST", "/tasks/x/stop", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code < 400 { t.Fatalf("status=%d", w.Code) }
}

func TestTaskStop_NotRunning(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, db, _ := newTaskTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.POST("/tasks/:id/stop", h.Stop)
	taskID := uuid.New().String()
	db.Create(&storage.TaskModel{ID: taskID, UserID: "test-user", Name: "t1", Status: "pending"})

	req := httptest.NewRequest("POST", "/tasks/"+taskID+"/stop", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 400 { t.Fatalf("status=%d", w.Code) }
	_, msg, _ := parseResponse(t, w.Body.Bytes())
	if !strings.Contains(msg, "not running") { t.Errorf("msg=%q", msg) }
}

// ---------------------------------------------------------------------------
// TaskHandler — Delete (TASK7-*)
// ---------------------------------------------------------------------------

func TestTaskDelete_Success(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, db, _ := newTaskTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.DELETE("/tasks/:id", h.Delete)
	taskID := uuid.New().String()
	db.Create(&storage.TaskModel{ID: taskID, UserID: "test-user", Name: "t1", Status: "completed"})

	req := httptest.NewRequest("DELETE", "/tasks/"+taskID, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 200 { t.Fatalf("status=%d", w.Code) }
	_, msg, _ := parseResponse(t, w.Body.Bytes())
	if !strings.Contains(msg, "task deleted") { t.Errorf("msg=%q", msg) }
	var count int64
	db.Model(&storage.TaskModel{}).Where("id = ?", taskID).Count(&count)
	if count != 0 { t.Errorf("task still exists") }
}

func TestTaskDelete_NoUser(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, _, _ := newTaskTestServer(t)
	r.DELETE("/tasks/:id", h.Delete)
	req := httptest.NewRequest("DELETE", "/tasks/x", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 401 { t.Fatalf("status=%d", w.Code) }
}

func TestTaskDelete_MissingID(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, _, _ := newTaskTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.DELETE("/tasks/:id", h.Delete)
	// Gin doesn't match /tasks/ (no id) - returns 404 (no route).
	req := httptest.NewRequest("DELETE", "/tasks/_empty", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 400 && w.Code != 404 { t.Fatalf("status=%d", w.Code) }
}

func TestTaskDelete_NotFound(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, _, _ := newTaskTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.DELETE("/tasks/:id", h.Delete)
	req := httptest.NewRequest("DELETE", "/tasks/nonexistent", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 404 { t.Fatalf("status=%d", w.Code) }
}

func TestTaskDelete_DBError(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, db, _ := newTaskTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.DELETE("/tasks/:id", h.Delete)
	sqlDB, _ := db.DB.DB()
	sqlDB.Close()
	req := httptest.NewRequest("DELETE", "/tasks/x", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code < 400 { t.Fatalf("status=%d", w.Code) }
}

func TestTaskDelete_Running(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, db, _ := newTaskTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.DELETE("/tasks/:id", h.Delete)
	taskID := uuid.New().String()
	db.Create(&storage.TaskModel{ID: taskID, UserID: "test-user", Name: "t1", Status: "running"})

	req := httptest.NewRequest("DELETE", "/tasks/"+taskID, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 400 { t.Fatalf("status=%d", w.Code) }
	_, msg, _ := parseResponse(t, w.Body.Bytes())
	if !strings.Contains(msg, "cannot delete running task") { t.Errorf("msg=%q", msg) }
}

func TestTaskDelete_DBDeleteFail(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, db, _ := newTaskTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.DELETE("/tasks/:id", h.Delete)
	taskID := uuid.New().String()
	db.Create(&storage.TaskModel{ID: taskID, UserID: "test-user", Name: "t1", Status: "completed"})
	sqlDB, _ := db.DB.DB()
	sqlDB.Close()
	req := httptest.NewRequest("DELETE", "/tasks/"+taskID, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code < 400 { t.Fatalf("status=%d", w.Code) }
	_, msg, _ := parseResponse(t, w.Body.Bytes())
	// DB is closed, so the task query may fail before reaching the delete step.
	if !strings.Contains(msg, "failed to") { t.Errorf("msg=%q", msg) }
}

// ---------------------------------------------------------------------------
// TaskHandler — History (TASK8-*)
// ---------------------------------------------------------------------------

func TestHistory_Default(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, db, _ := newTaskTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.GET("/history", h.History)

	db.Create(&storage.TaskModel{ID: uuid.New().String(), UserID: "test-user", Name: "t1", Status: "completed"})
	db.Create(&storage.TaskModel{ID: uuid.New().String(), UserID: "test-user", Name: "t2", Status: "pending"})

	req := httptest.NewRequest("GET", "/history", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 200 { t.Fatalf("status=%d", w.Code) }
	code, _, data := parseResponse(t, w.Body.Bytes())
	if code != 0 { t.Errorf("code=%d", code) }
	var d map[string]interface{}
	json.Unmarshal(data, &d)
	items := d["items"].([]interface{})
	if len(items) == 0 { t.Error("expected history items") }
}

func TestHistory_CustomPage(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, db, _ := newTaskTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.GET("/history", h.History)
	for i := 0; i < 10; i++ {
		db.Create(&storage.TaskModel{ID: uuid.New().String(), UserID: "test-user", Name: "t", Status: "completed"})
	}
	req := httptest.NewRequest("GET", "/history?page=2&size=5", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 200 { t.Fatalf("status=%d", w.Code) }
	code, _, data := parseResponse(t, w.Body.Bytes())
	if code != 0 { t.Errorf("code=%d", code) }
	var d map[string]interface{}
	json.Unmarshal(data, &d)
	if d["page"].(float64) != 2 { t.Errorf("page=%v", d["page"]) }
}

func TestHistory_StartTimeValid(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, db, _ := newTaskTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.GET("/history", h.History)
	db.Create(&storage.TaskModel{ID: uuid.New().String(), UserID: "test-user", Name: "t1", Status: "completed", CreatedAt: time.Now().Add(-2 * time.Hour)})
	req := httptest.NewRequest("GET", "/history?start_time=1000", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 200 { t.Fatalf("status=%d", w.Code) }
}

func TestHistory_StartTimeInvalid(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, _, _ := newTaskTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.GET("/history", h.History)
	req := httptest.NewRequest("GET", "/history?start_time=abc", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 200 { t.Fatalf("status=%d", w.Code) }
}

func TestHistory_EndTimeValid(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, _, _ := newTaskTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.GET("/history", h.History)
	req := httptest.NewRequest("GET", "/history?end_time=9999999999", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 200 { t.Fatalf("status=%d", w.Code) }
}

func TestHistory_EndTimeInvalid(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, _, _ := newTaskTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.GET("/history", h.History)
	req := httptest.NewRequest("GET", "/history?end_time=abc", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 200 { t.Fatalf("status=%d", w.Code) }
}

func TestHistory_StatusFilter(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, db, _ := newTaskTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.GET("/history", h.History)
	db.Create(&storage.TaskModel{ID: uuid.New().String(), UserID: "test-user", Name: "t1", Status: "completed"})
	db.Create(&storage.TaskModel{ID: uuid.New().String(), UserID: "test-user", Name: "t2", Status: "failed"})

	req := httptest.NewRequest("GET", "/history?status=failed", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 200 { t.Fatalf("status=%d", w.Code) }
	code, _, data := parseResponse(t, w.Body.Bytes())
	if code != 0 { t.Errorf("code=%d", code) }
	var d map[string]interface{}
	json.Unmarshal(data, &d)
	items := d["items"].([]interface{})
	for _, item := range items {
		m := item.(map[string]interface{})
		if m["status"] != "failed" {
			t.Errorf("expected failed, got %v", m["status"])
		}
	}
}

func TestHistory_InvalidSortBy(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, _, _ := newTaskTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.GET("/history", h.History)
	req := httptest.NewRequest("GET", "/history?sort_by=x", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 200 { t.Fatalf("status=%d", w.Code) }
}

func TestHistory_Ascending(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, _, _ := newTaskTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.GET("/history", h.History)
	req := httptest.NewRequest("GET", "/history?sort_order=ascending", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 200 { t.Fatalf("status=%d", w.Code) }
}

func TestHistory_NoUser(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, _, _ := newTaskTestServer(t)
	r.GET("/history", h.History)
	req := httptest.NewRequest("GET", "/history", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 401 { t.Fatalf("status=%d", w.Code) }
}

func TestHistory_DBFindFail(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, db, _ := newTaskTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.GET("/history", h.History)
	sqlDB, _ := db.DB.DB()
	sqlDB.Close()
	req := httptest.NewRequest("GET", "/history", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code < 400 { t.Fatalf("status=%d", w.Code) }
	_, msg, _ := parseResponse(t, w.Body.Bytes())
	if !strings.Contains(msg, "failed to list history") { t.Errorf("msg=%q", msg) }
}

func TestHistory_Empty(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, _, _ := newTaskTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.GET("/history", h.History)
	req := httptest.NewRequest("GET", "/history", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 200 { t.Fatalf("status=%d", w.Code) }
	code, _, data := parseResponse(t, w.Body.Bytes())
	if code != 0 { t.Errorf("code=%d", code) }
	var d map[string]interface{}
	json.Unmarshal(data, &d)
	if d["total"].(float64) != 0 { t.Errorf("total=%v", d["total"]) }
}

func TestHistory_ExcludesActive(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, db, _ := newTaskTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.GET("/history", h.History)
	db.Create(&storage.TaskModel{ID: uuid.New().String(), UserID: "test-user", Name: "t1", Status: "completed"})
	db.Create(&storage.TaskModel{ID: uuid.New().String(), UserID: "test-user", Name: "t2", Status: "pending"})

	req := httptest.NewRequest("GET", "/history", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 200 { t.Fatalf("status=%d", w.Code) }
	code, _, data := parseResponse(t, w.Body.Bytes())
	if code != 0 { t.Errorf("code=%d", code) }
	var d map[string]interface{}
	json.Unmarshal(data, &d)
	items := d["items"].([]interface{})
	for _, item := range items {
		m := item.(map[string]interface{})
		if m["status"] == "pending" || m["status"] == "running" {
			t.Errorf("history should exclude active, got %v", m["status"])
		}
	}
}

// ---------------------------------------------------------------------------
// PortGroupHandler (PORT1-4)
// ---------------------------------------------------------------------------

func newPortGroupTestServer(t *testing.T) (*PortGroupHandler, *gin.Engine, *storage.DB) {
	t.Helper()
	gormDB, err := gorm.Open(sqlite.Open(t.TempDir()+"/pg_test.db"), &gorm.Config{})
	if err != nil { t.Fatalf("open db: %v", err) }
	if err := storage.AutoMigrate(gormDB); err != nil { t.Fatalf("migrate: %v", err) }
	db := &storage.DB{DB: gormDB}
	h := NewPortGroupHandler(db)
	r := gin.New()
	return h, r, db
}

func TestPortGroupCreate_Success(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, db := newPortGroupTestServer(t)
	r.POST("/port-groups", h.Create)

	body := `{"ports":[{"interface":"eth0","weight":1}]}`
	req := httptest.NewRequest("POST", "/port-groups", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 201 { t.Fatalf("status=%d", w.Code) }
	code, msg, data := parseResponse(t, w.Body.Bytes())
	if code != 0 { t.Errorf("code=%d", code) }
	if !strings.Contains(msg, "created") { t.Errorf("msg=%q", msg) }
	var d map[string]string
	json.Unmarshal(data, &d)
	if d["id"] == "" { t.Error("id empty") }
	if d["name"] == "" { t.Error("name empty") }
	var pg storage.PortGroupModel
	db.Where("id = ?", d["id"]).First(&pg)
	if pg.PortsConfig == "" { t.Error("ports_config empty") }
}

func TestPortGroupCreate_BadJSON(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, _ := newPortGroupTestServer(t)
	r.POST("/port-groups", h.Create)
	req := httptest.NewRequest("POST", "/port-groups", strings.NewReader("x"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 400 { t.Fatalf("status=%d", w.Code) }
}

func TestPortGroupCreate_EmptyPorts(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, _ := newPortGroupTestServer(t)
	r.POST("/port-groups", h.Create)
	body := `{"ports":[]}`
	req := httptest.NewRequest("POST", "/port-groups", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 400 { t.Fatalf("status=%d", w.Code) }
}

func TestPortGroupCreate_EmptyInterface(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, _ := newPortGroupTestServer(t)
	r.POST("/port-groups", h.Create)
	// The binding "required" catches empty interface in JSON, but we test the
	// explicit loop check in the handler.
	body := `{"ports":[{"interface":"","weight":1}]}`
	req := httptest.NewRequest("POST", "/port-groups", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 400 { t.Fatalf("status=%d", w.Code) }
}

func TestPortGroupCreate_Dedup(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, _ := newPortGroupTestServer(t)
	r.POST("/port-groups", h.Create)
	body := `{"ports":[{"interface":"eth0","weight":1}]}`

	req := httptest.NewRequest("POST", "/port-groups", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 201 { t.Fatalf("first: %d", w.Code) }
	_, _, data := parseResponse(t, w.Body.Bytes())
	var d1 map[string]string
	json.Unmarshal(data, &d1)

	req2 := httptest.NewRequest("POST", "/port-groups", strings.NewReader(body))
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)
	if w2.Code != 200 { t.Fatalf("second: %d", w2.Code) }
	_, _, data2 := parseResponse(t, w2.Body.Bytes())
	var d2 map[string]string
	json.Unmarshal(data2, &d2)
	if d2["id"] != d1["id"] { t.Errorf("dedup failed: %s vs %s", d2["id"], d1["id"]) }
}

func TestPortGroupCreate_DBCreateFail(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, db := newPortGroupTestServer(t)
	r.POST("/port-groups", h.Create)
	sqlDB, _ := db.DB.DB()
	sqlDB.Close()
	body := `{"ports":[{"interface":"eth0","weight":1}]}`
	req := httptest.NewRequest("POST", "/port-groups", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code < 400 { t.Fatalf("status=%d", w.Code) }
	_, msg, _ := parseResponse(t, w.Body.Bytes())
	if !strings.Contains(msg, "failed to create port group") { t.Errorf("msg=%q", msg) }
}

func TestPortGroupCreate_OrderInvariant(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, _ := newPortGroupTestServer(t)
	r.POST("/port-groups", h.Create)
	body1 := `{"ports":[{"interface":"eth1","weight":1},{"interface":"eth0","weight":2}]}`
	body2 := `{"ports":[{"interface":"eth0","weight":2},{"interface":"eth1","weight":1}]}`

	req := httptest.NewRequest("POST", "/port-groups", strings.NewReader(body1))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 201 { t.Fatalf("first: %d", w.Code) }
	_, _, data := parseResponse(t, w.Body.Bytes())
	var d1 map[string]string
	json.Unmarshal(data, &d1)

	req2 := httptest.NewRequest("POST", "/port-groups", strings.NewReader(body2))
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)
	if w2.Code != 200 { t.Fatalf("second: %d", w2.Code) }
	_, _, data2 := parseResponse(t, w2.Body.Bytes())
	var d2 map[string]string
	json.Unmarshal(data2, &d2)
	if d2["id"] != d1["id"] { t.Errorf("order invariant dedup failed: %s vs %s", d2["id"], d1["id"]) }
}

func TestPortGroupList_HasItems(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, db := newPortGroupTestServer(t)
	r.GET("/port-groups", h.List)
	db.Create(&storage.PortGroupModel{ID: uuid.New().String(), Name: "pg1", PortsConfig: `[{"interface":"eth0","weight":1}]`})

	req := httptest.NewRequest("GET", "/port-groups", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 200 { t.Fatalf("status=%d", w.Code) }
	code, _, _ := parseResponse(t, w.Body.Bytes())
	if code != 0 { t.Errorf("code=%d", code) }
}

func TestPortGroupList_Empty(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, _ := newPortGroupTestServer(t)
	r.GET("/port-groups", h.List)
	req := httptest.NewRequest("GET", "/port-groups", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 200 { t.Fatalf("status=%d", w.Code) }
	code, _, data := parseResponse(t, w.Body.Bytes())
	if code != 0 { t.Errorf("code=%d", code) }
	var groups []interface{}
	json.Unmarshal(data, &groups)
	if len(groups) != 0 { t.Errorf("expected empty, got %d", len(groups)) }
}

func TestPortGroupList_DBFindFail(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, db := newPortGroupTestServer(t)
	r.GET("/port-groups", h.List)
	sqlDB, _ := db.DB.DB()
	sqlDB.Close()
	req := httptest.NewRequest("GET", "/port-groups", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code < 400 { t.Fatalf("status=%d", w.Code) }
}

func TestPortGroupList_Public(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, _ := newPortGroupTestServer(t)
	r.GET("/port-groups", h.List)
	req := httptest.NewRequest("GET", "/port-groups", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 200 { t.Fatalf("status=%d", w.Code) }
}

func TestPortGroupGet_Success(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, db := newPortGroupTestServer(t)
	r.GET("/port-groups/:id", h.Get)
	id := uuid.New().String()
	db.Create(&storage.PortGroupModel{ID: id, Name: "pg1", PortsConfig: `[{"interface":"eth0","weight":1}]`})

	req := httptest.NewRequest("GET", "/port-groups/"+id, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 200 { t.Fatalf("status=%d", w.Code) }
	code, _, _ := parseResponse(t, w.Body.Bytes())
	if code != 0 { t.Errorf("code=%d", code) }
}

func TestPortGroupGet_MissingID(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, _ := newPortGroupTestServer(t)
	r.GET("/port-groups/:id", h.Get)
	// Gin doesn't match /port-groups/ (no id) - returns 404 (no route).
	req := httptest.NewRequest("GET", "/port-groups/_empty", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 400 && w.Code != 404 { t.Fatalf("status=%d", w.Code) }
}

func TestPortGroupGet_NotFound(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, _ := newPortGroupTestServer(t)
	r.GET("/port-groups/:id", h.Get)
	req := httptest.NewRequest("GET", "/port-groups/nonexistent", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 404 { t.Fatalf("status=%d", w.Code) }
	_, msg, _ := parseResponse(t, w.Body.Bytes())
	if !strings.Contains(msg, "port group not found") { t.Errorf("msg=%q", msg) }
}

func TestPortGroupGet_DBError(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, db := newPortGroupTestServer(t)
	r.GET("/port-groups/:id", h.Get)
	sqlDB, _ := db.DB.DB()
	sqlDB.Close()
	req := httptest.NewRequest("GET", "/port-groups/x", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code < 400 { t.Fatalf("status=%d", w.Code) }
}

func TestPortGroupGet_Public(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, db := newPortGroupTestServer(t)
	r.GET("/port-groups/:id", h.Get)
	id := uuid.New().String()
	db.Create(&storage.PortGroupModel{ID: id, Name: "pg1", PortsConfig: `[{"interface":"eth0","weight":1}]`})
	req := httptest.NewRequest("GET", "/port-groups/"+id, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 200 { t.Fatalf("status=%d", w.Code) }
}

func TestPortGroupDelete_Success(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, db := newPortGroupTestServer(t)
	r.DELETE("/port-groups/:id", h.Delete)
	id := uuid.New().String()
	db.Create(&storage.PortGroupModel{ID: id, Name: "pg1", PortsConfig: `[{"interface":"eth0","weight":1}]`})

	req := httptest.NewRequest("DELETE", "/port-groups/"+id, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 200 { t.Fatalf("status=%d", w.Code) }
	_, msg, _ := parseResponse(t, w.Body.Bytes())
	if !strings.Contains(msg, "port group deleted") { t.Errorf("msg=%q", msg) }
	var count int64
	db.Model(&storage.PortGroupModel{}).Where("id = ?", id).Count(&count)
	if count != 0 { t.Errorf("port group still exists") }
}

func TestPortGroupDelete_MissingID(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, _ := newPortGroupTestServer(t)
	r.DELETE("/port-groups/:id", h.Delete)
	// Gin doesn't match /port-groups/ (no id) - returns 404 (no route).
	req := httptest.NewRequest("DELETE", "/port-groups/_empty", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 400 && w.Code != 404 { t.Fatalf("status=%d", w.Code) }
}

func TestPortGroupDelete_NotFound(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, _ := newPortGroupTestServer(t)
	r.DELETE("/port-groups/:id", h.Delete)
	req := httptest.NewRequest("DELETE", "/port-groups/nonexistent", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 404 { t.Fatalf("status=%d", w.Code) }
}

func TestPortGroupDelete_DBError(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, db := newPortGroupTestServer(t)
	r.DELETE("/port-groups/:id", h.Delete)
	sqlDB, _ := db.DB.DB()
	sqlDB.Close()
	req := httptest.NewRequest("DELETE", "/port-groups/x", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code < 400 { t.Fatalf("status=%d", w.Code) }
}

func TestPortGroupDelete_UsedByTasks(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, db := newPortGroupTestServer(t)
	r.DELETE("/port-groups/:id", h.Delete)
	id := uuid.New().String()
	db.Create(&storage.PortGroupModel{ID: id, Name: "pg1", PortsConfig: `[{"interface":"eth0","weight":1}]`})
	// Create a task referencing the port group via output_config
	db.Create(&storage.TaskModel{
		ID: uuid.New().String(), UserID: "test-user", Name: "t1",
		OutputConfig: `{"port_group_id":"` + id + `"}`, Status: "pending",
	})

	req := httptest.NewRequest("DELETE", "/port-groups/"+id, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 400 { t.Fatalf("status=%d", w.Code) }
	_, msg, _ := parseResponse(t, w.Body.Bytes())
	if !strings.Contains(msg, "cannot delete") { t.Errorf("msg=%q", msg) }
}

func TestPortGroupDelete_DBDeleteFail(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, db := newPortGroupTestServer(t)
	r.DELETE("/port-groups/:id", h.Delete)
	id := uuid.New().String()
	db.Create(&storage.PortGroupModel{ID: id, Name: "pg1", PortsConfig: `[{"interface":"eth0","weight":1}]`})
	sqlDB, _ := db.DB.DB()
	sqlDB.Close()
	req := httptest.NewRequest("DELETE", "/port-groups/"+id, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code < 400 { t.Fatalf("status=%d", w.Code) }
	_, msg, _ := parseResponse(t, w.Body.Bytes())
	// DB is closed, so the port-group query may fail before reaching the delete step.
	if !strings.Contains(msg, "failed to") { t.Errorf("msg=%q", msg) }
}

func TestPortGroupDelete_AnyUser(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, db := newPortGroupTestServer(t)
	r.DELETE("/port-groups/:id", h.Delete)
	id := uuid.New().String()
	db.Create(&storage.PortGroupModel{ID: id, Name: "pg1", PortsConfig: `[{"interface":"eth0","weight":1}]`})
	// No user context — global resource, any user can delete
	req := httptest.NewRequest("DELETE", "/port-groups/"+id, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 200 { t.Fatalf("status=%d", w.Code) }
}

// ---------------------------------------------------------------------------
// SystemHandler (SYS1-5)
// ---------------------------------------------------------------------------

func newSystemTestServer(t *testing.T) (*SystemHandler, *gin.Engine) {
	t.Helper()
	e := core.NewEngine(core.EngineConfig{
		ConfigWorkers: 1, PacketWorkers: 1, OutputWorkers: 1,
		BufferSize: 256, QueueSize: 64,
	})
	if err := e.Start(); err != nil { t.Fatalf("start: %v", err) }
	t.Cleanup(func() { e.Stop() })
	h := NewSystemHandler(e)
	r := gin.New()
	return h, r
}

func TestSystemProtocols_List(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r := newSystemTestServer(t)
	r.GET("/system/protocols", h.GetProtocols)
	req := httptest.NewRequest("GET", "/system/protocols", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 200 { t.Fatalf("status=%d", w.Code) }
	code, _, data := parseResponse(t, w.Body.Bytes())
	if code != 0 { t.Errorf("code=%d", code) }
	var protocols []string
	json.Unmarshal(data, &protocols)
	expected := []string{"tcp", "udp", "http", "dns", "icmp", "arp", "ftp", "sip", "sctp", "icmpv6", "cflow"}
	if len(protocols) != len(expected) { t.Errorf("got %v, want %v", protocols, expected) }
	for i, p := range expected {
		if i < len(protocols) && protocols[i] != p {
			t.Errorf("protocols[%d]=%q, want %q", i, protocols[i], p)
		}
	}
}

func TestHealthCheck(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r := newSystemTestServer(t)
	r.GET("/health", h.HealthCheck)
	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 200 { t.Fatalf("status=%d", w.Code) }
	if !strings.Contains(w.Body.String(), `"status":"healthy"`) {
		t.Errorf("body=%s", w.Body.String())
	}
}

func TestReadyCheck_Ready(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r := newSystemTestServer(t)
	r.GET("/ready", h.ReadyCheck)
	req := httptest.NewRequest("GET", "/ready", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 200 { t.Fatalf("status=%d", w.Code) }
}

func TestReadyCheck_NotReady(t *testing.T) {
	gin.SetMode(gin.TestMode)
	e := core.NewEngine(core.EngineConfig{
		ConfigWorkers: 1, PacketWorkers: 1, OutputWorkers: 1,
		BufferSize: 256, QueueSize: 64,
	})
	// Don't start engine
	h := NewSystemHandler(e)
	r := gin.New()
	r.GET("/ready", h.ReadyCheck)
	req := httptest.NewRequest("GET", "/ready", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 503 { t.Fatalf("status=%d, want 503", w.Code) }
	code, _, _ := parseResponse(t, w.Body.Bytes())
	if code != 0 { t.Errorf("expected 503 but code=0 means Success wasn't used") }
}

func TestReadyCheck_Public(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r := newSystemTestServer(t)
	r.GET("/ready", h.ReadyCheck)
	req := httptest.NewRequest("GET", "/ready", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code == 401 { t.Errorf("ready should be public, got 401") }
}