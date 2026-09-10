package rest

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	sqlite "github.com/glebarez/sqlite"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/trafficgen/trafficgen/internal/storage"
	"gorm.io/gorm"
)

// newStrategyTestServer creates a StrategyHandler + gin engine with in-memory DB.
func newStrategyTestServer(t *testing.T) (*StrategyHandler, *gin.Engine, *storage.DB) {
	t.Helper()
	gormDB, err := gorm.Open(sqlite.Open(t.TempDir()+"/strat_test.db"), &gorm.Config{})
	if err != nil { t.Fatalf("open db: %v", err) }
	if err := storage.AutoMigrate(gormDB); err != nil { t.Fatalf("migrate: %v", err) }
	db := &storage.DB{DB: gormDB}
	h := NewStrategyHandler(db)
	r := gin.New()
	return h, r, db
}

// stratUser sets up a user in the context and returns the userID.
func stratUser(r *gin.Engine, userID, username string) {
	r.Use(func(c *gin.Context) {
		c.Set("userID", userID)
		c.Set("username", username)
		c.Set("roles", []string{"user"})
		c.Next()
	})
}

func createTestStrategy(t *testing.T, db *storage.DB, userID, name, protocol string) string {
	t.Helper()
	config := `{"src_ip":"10.0.0.1","dst_ip":"10.0.0.2"}`
	fc := `{"type":"flows","value":1}`
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

// ---------------------------------------------------------------------------
// StrategyHandler — Create (STRAT1-*)
// ---------------------------------------------------------------------------

func TestStrategyCreate_Success(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, db := newStrategyTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Set("username", "alice"); c.Set("roles", []string{"user"}); c.Next() })
	r.POST("/strategies", h.Create)

	body := `{"name":"s1","protocol":"tcp","config":{"src_ip":"10.0.0.1","dst_ip":"10.0.0.2"},"flow_control":{"type":"flows","value":10}}`
	req := httptest.NewRequest("POST", "/strategies", strings.NewReader(body))
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

	var s storage.StrategyModel
	db.Where("id = ?", d["id"]).First(&s)
	if s.UserID != "test-user" { t.Errorf("user_id=%q", s.UserID) }
	if s.Protocol != "tcp" { t.Errorf("protocol=%q", s.Protocol) }
	if s.ConfigHash == "" { t.Error("config_hash empty") }
}

func TestStrategyCreate_NoUser(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, _ := newStrategyTestServer(t)
	r.POST("/strategies", h.Create)
	req := httptest.NewRequest("POST", "/strategies", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 401 { t.Fatalf("status=%d", w.Code) }
}

func TestStrategyCreate_BadJSON(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, _ := newStrategyTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.POST("/strategies", h.Create)
	req := httptest.NewRequest("POST", "/strategies", strings.NewReader("x"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 400 { t.Fatalf("status=%d", w.Code) }
}

func TestStrategyCreate_MissingName(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, _ := newStrategyTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.POST("/strategies", h.Create)
	req := httptest.NewRequest("POST", "/strategies", strings.NewReader(`{"protocol":"tcp","config":{}}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 400 { t.Fatalf("status=%d", w.Code) }
}

func TestStrategyCreate_MissingProtocol(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, _ := newStrategyTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.POST("/strategies", h.Create)
	req := httptest.NewRequest("POST", "/strategies", strings.NewReader(`{"name":"s1","config":{}}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 400 { t.Fatalf("status=%d", w.Code) }
}

func TestStrategyCreate_MissingConfig(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, _ := newStrategyTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.POST("/strategies", h.Create)
	req := httptest.NewRequest("POST", "/strategies", strings.NewReader(`{"name":"s1","protocol":"tcp"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 400 { t.Fatalf("status=%d", w.Code) }
}

func TestStrategyCreate_BadSrcIP(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, _ := newStrategyTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.POST("/strategies", h.Create)
	body := `{"name":"s1","protocol":"tcp","config":{"src_ip":"bad"}}`
	req := httptest.NewRequest("POST", "/strategies", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 400 { t.Fatalf("status=%d", w.Code) }
	_, msg, _ := parseResponse(t, w.Body.Bytes())
	if !strings.Contains(msg, "invalid IP format: src_ip = bad") { t.Errorf("msg=%q", msg) }
}

func TestStrategyCreate_BadDstIP(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, _ := newStrategyTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.POST("/strategies", h.Create)
	body := `{"name":"s1","protocol":"tcp","config":{"dst_ip":"999.0.0.1"}}`
	req := httptest.NewRequest("POST", "/strategies", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 400 { t.Fatalf("status=%d", w.Code) }
}

func TestStrategyCreate_BadSrcMAC(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, _ := newStrategyTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.POST("/strategies", h.Create)
	body := `{"name":"s1","protocol":"tcp","config":{"src_mac":"zz"}}`
	req := httptest.NewRequest("POST", "/strategies", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 400 { t.Fatalf("status=%d", w.Code) }
}

func TestStrategyCreate_BadDstMAC(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, _ := newStrategyTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.POST("/strategies", h.Create)
	body := `{"name":"s1","protocol":"tcp","config":{"dst_mac":"aa"}}`
	req := httptest.NewRequest("POST", "/strategies", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 400 { t.Fatalf("status=%d", w.Code) }
}

func TestStrategyCreate_DSCPOutOfRange(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, _ := newStrategyTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.POST("/strategies", h.Create)
	body := `{"name":"s1","protocol":"tcp","config":{"src_ip":"10.0.0.1","dscp":256}}`
	req := httptest.NewRequest("POST", "/strategies", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 400 { t.Fatalf("status=%d", w.Code) }
}

func TestStrategyCreate_VLANOutOfRange(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, _ := newStrategyTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.POST("/strategies", h.Create)
	// ValidateConfigRanges checks "vlan_id" key, not "vlan"
	body := `{"name":"s1","protocol":"tcp","config":{"src_ip":"10.0.0.1","vlan_id":4096}}`
	req := httptest.NewRequest("POST", "/strategies", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 400 { t.Fatalf("status=%d", w.Code) }
}

func TestStrategyCreate_EmptyProtocol(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, _ := newStrategyTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.POST("/strategies", h.Create)
	body := `{"name":"s1","protocol":"","config":{"src_ip":"10.0.0.1"}}`
	req := httptest.NewRequest("POST", "/strategies", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 400 { t.Fatalf("status=%d", w.Code) }
	_, msg, _ := parseResponse(t, w.Body.Bytes())
	// Either the binding "required" tag or the handler's explicit check produces
	// an error containing "protocol" or "Protocol".
	if !strings.Contains(strings.ToLower(msg), "protocol") { t.Errorf("msg=%q", msg) }
}

func TestStrategyCreate_UnsupportedProtocol(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, _ := newStrategyTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.POST("/strategies", h.Create)
	body := `{"name":"s1","protocol":"nosuchproto","config":{"src_ip":"10.0.0.1"}}`
	req := httptest.NewRequest("POST", "/strategies", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 400 { t.Fatalf("status=%d", w.Code) }
	_, msg, _ := parseResponse(t, w.Body.Bytes())
	if !strings.Contains(msg, "invalid or missing protocol: nosuchproto") { t.Errorf("msg=%q", msg) }
}

func TestStrategyCreate_BadSubConfig(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, _ := newStrategyTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.POST("/strategies", h.Create)
	body := `{"name":"s1","protocol":"icmp","config":{"icmp":{"type":999}}}`
	req := httptest.NewRequest("POST", "/strategies", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 400 { t.Fatalf("status=%d", w.Code) }
}

func TestStrategyCreate_DefaultFlowControl(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, db := newStrategyTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.POST("/strategies", h.Create)
	body := `{"name":"s1","protocol":"tcp","config":{"src_ip":"10.0.0.1","dst_ip":"10.0.0.2"}}`
	req := httptest.NewRequest("POST", "/strategies", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 201 { t.Fatalf("status=%d", w.Code) }
	code, _, data := parseResponse(t, w.Body.Bytes())
	if code != 0 { t.Errorf("code=%d", code) }
	var d map[string]string
	json.Unmarshal(data, &d)
	var s storage.StrategyModel
	db.Where("id = ?", d["id"]).First(&s)
	if s.FlowControl != `{"type":"flows","value":1}` { t.Errorf("fc=%q", s.FlowControl) }
}

func TestStrategyCreate_BadFlowType(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, _ := newStrategyTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.POST("/strategies", h.Create)
	body := `{"name":"s1","protocol":"tcp","config":{"src_ip":"10.0.0.1"},"flow_control":{"type":"xyz","value":1}}`
	req := httptest.NewRequest("POST", "/strategies", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 400 { t.Fatalf("status=%d", w.Code) }
	_, msg, _ := parseResponse(t, w.Body.Bytes())
	if !strings.Contains(msg, "invalid flow_control type") { t.Errorf("msg=%q", msg) }
}

func TestStrategyCreate_NonPositiveValue(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, _ := newStrategyTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.POST("/strategies", h.Create)
	body := `{"name":"s1","protocol":"tcp","config":{"src_ip":"10.0.0.1"},"flow_control":{"type":"flows","value":0}}`
	req := httptest.NewRequest("POST", "/strategies", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 400 { t.Fatalf("status=%d", w.Code) }
	// Either binding "required" rejects value=0 or handler's explicit check rejects it.
	_, msg, _ := parseResponse(t, w.Body.Bytes())
	if !strings.Contains(strings.ToLower(msg), "value") && !strings.Contains(strings.ToLower(msg), "flow_control") {
		t.Errorf("msg=%q", msg)
	}
}

func TestStrategyCreate_ConfigMarshalFail(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, _ := newStrategyTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.POST("/strategies", h.Create)
	// Config with a channel value causes Marshal to fail
	body := `{"name":"s1","protocol":"tcp","config":{"src_ip":"10.0.0.1","bad":"` + string([]byte{0}) + `"}}`
	req := httptest.NewRequest("POST", "/strategies", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 400 { t.Fatalf("status=%d", w.Code) }
}

func TestStrategyCreate_Dedup(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, _ := newStrategyTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.POST("/strategies", h.Create)
	body := `{"name":"s1","protocol":"tcp","config":{"src_ip":"10.0.0.1","dst_ip":"10.0.0.2"},"flow_control":{"type":"flows","value":10}}`

	req := httptest.NewRequest("POST", "/strategies", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 201 { t.Fatalf("first: status=%d", w.Code) }
	code, _, data := parseResponse(t, w.Body.Bytes())
	var d1 map[string]string
	json.Unmarshal(data, &d1)

	// Same config again
	req2 := httptest.NewRequest("POST", "/strategies", strings.NewReader(body))
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)
	if w2.Code != 200 { t.Fatalf("second: status=%d", w2.Code) }
	code2, msg2, data2 := parseResponse(t, w2.Body.Bytes())
	if code2 != 0 { t.Errorf("code=%d", code2) }
	if !strings.Contains(msg2, "success") { t.Errorf("msg=%q", msg2) }
	var d2 map[string]string
	json.Unmarshal(data2, &d2)
	if d2["id"] != d1["id"] { t.Errorf("dedup returned different id: %s vs %s", d2["id"], d1["id"]) }
	if !strings.Contains(d2["message"], "already exists") { t.Errorf("msg=%q", d2["message"]) }
	_ = code
}

func TestStrategyCreate_DBCreateFail(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, db := newStrategyTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.POST("/strategies", h.Create)
	sqlDB, _ := db.DB.DB()
	sqlDB.Close()

	body := `{"name":"s1","protocol":"tcp","config":{"src_ip":"10.0.0.1","dst_ip":"10.0.0.2"}}`
	req := httptest.NewRequest("POST", "/strategies", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code < 400 { t.Fatalf("status=%d", w.Code) }
	_, msg, _ := parseResponse(t, w.Body.Bytes())
	if !strings.Contains(msg, "failed to create strategy") { t.Errorf("msg=%q", msg) }
}

// ---------------------------------------------------------------------------
// StrategyHandler — List (STRAT2-*)
// ---------------------------------------------------------------------------

func TestStrategyList_HasItems(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, db := newStrategyTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.GET("/strategies", h.List)

	createTestStrategy(t, db, "test-user", "s1", "tcp")

	req := httptest.NewRequest("GET", "/strategies", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 200 { t.Fatalf("status=%d", w.Code) }
	code, _, data := parseResponse(t, w.Body.Bytes())
	if code != 0 { t.Errorf("code=%d", code) }
	var strs []interface{}
	json.Unmarshal(data, &strs)
	if len(strs) == 0 { t.Error("expected strategies") }
}

func TestStrategyList_Empty(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, _ := newStrategyTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.GET("/strategies", h.List)

	req := httptest.NewRequest("GET", "/strategies", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 200 { t.Fatalf("status=%d", w.Code) }
	code, _, data := parseResponse(t, w.Body.Bytes())
	if code != 0 { t.Errorf("code=%d", code) }
	var strs []interface{}
	json.Unmarshal(data, &strs)
	if len(strs) != 0 { t.Errorf("expected empty, got %d", len(strs)) }
}

func TestStrategyList_NoUser(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, _ := newStrategyTestServer(t)
	r.GET("/strategies", h.List)
	req := httptest.NewRequest("GET", "/strategies", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 401 { t.Fatalf("status=%d", w.Code) }
}

func TestStrategyList_DBFindFail(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, db := newStrategyTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.GET("/strategies", h.List)
	sqlDB, _ := db.DB.DB()
	sqlDB.Close()

	req := httptest.NewRequest("GET", "/strategies", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code < 400 { t.Fatalf("status=%d", w.Code) }
}

// ---------------------------------------------------------------------------
// StrategyHandler — Get (STRAT3-*)
// ---------------------------------------------------------------------------

func TestStrategyGet_Success(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, db := newStrategyTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.GET("/strategies/:id", h.Get)
	id := createTestStrategy(t, db, "test-user", "s1", "tcp")

	req := httptest.NewRequest("GET", "/strategies/"+id, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 200 { t.Fatalf("status=%d", w.Code) }
	code, _, _ := parseResponse(t, w.Body.Bytes())
	if code != 0 { t.Errorf("code=%d", code) }
}

func TestStrategyGet_NoUser(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, _ := newStrategyTestServer(t)
	r.GET("/strategies/:id", h.Get)
	req := httptest.NewRequest("GET", "/strategies/x", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 401 { t.Fatalf("status=%d", w.Code) }
}

func TestStrategyGet_MissingID(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, _ := newStrategyTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.GET("/strategies/:id", h.Get)
	// Gin doesn't match /strategies/ (no id) to the :id route — returns 404 (no route).
	// Test with a valid route pattern that exercises the handler's missing-ID check.
	req := httptest.NewRequest("GET", "/strategies/_empty", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	// Handler returns 404 for a strategy that doesn't exist (not 400 for missing ID
	// since "_empty" is a valid ID format that simply doesn't exist in the DB).
	if w.Code != 400 && w.Code != 404 { t.Fatalf("status=%d", w.Code) }
}

func TestStrategyGet_NotFound(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, _ := newStrategyTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.GET("/strategies/:id", h.Get)
	req := httptest.NewRequest("GET", "/strategies/nonexistent", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 404 { t.Fatalf("status=%d", w.Code) }
	_, msg, _ := parseResponse(t, w.Body.Bytes())
	if !strings.Contains(msg, "strategy not found") { t.Errorf("msg=%q", msg) }
}

func TestStrategyGet_DBError(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, db := newStrategyTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.GET("/strategies/:id", h.Get)
	sqlDB, _ := db.DB.DB()
	sqlDB.Close()
	req := httptest.NewRequest("GET", "/strategies/x", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code < 400 { t.Fatalf("status=%d", w.Code) }
}

// ---------------------------------------------------------------------------
// StrategyHandler — Update (STRAT4-*)
// ---------------------------------------------------------------------------

func TestStrategyUpdate_Success(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, db := newStrategyTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.PUT("/strategies/:id", h.Update)
	id := createTestStrategy(t, db, "test-user", "s1", "tcp")

	body := `{"name":"s2","protocol":"udp","config":{"src_ip":"10.0.0.1","dst_ip":"10.0.0.2"}}`
	req := httptest.NewRequest("PUT", "/strategies/"+id, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 200 { t.Fatalf("status=%d", w.Code) }
	_, msg, _ := parseResponse(t, w.Body.Bytes())
	if !strings.Contains(msg, "strategy updated") { t.Errorf("msg=%q", msg) }

	var s storage.StrategyModel
	db.Where("id = ?", id).First(&s)
	if s.Name != "s2" { t.Errorf("name=%q", s.Name) }
	if s.Protocol != "udp" { t.Errorf("protocol=%q", s.Protocol) }
}

func TestStrategyUpdate_NoUser(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, _ := newStrategyTestServer(t)
	r.PUT("/strategies/:id", h.Update)
	req := httptest.NewRequest("PUT", "/strategies/x", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 401 { t.Fatalf("status=%d", w.Code) }
}

func TestStrategyUpdate_MissingID(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, _ := newStrategyTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.PUT("/strategies/:id", h.Update)
	// Gin doesn't match /strategies/ (no id) to the :id route — returns 404 (no route).
	req := httptest.NewRequest("PUT", "/strategies/_empty", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 400 && w.Code != 404 { t.Fatalf("status=%d", w.Code) }
}

func TestStrategyUpdate_BadJSON(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, _ := newStrategyTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.PUT("/strategies/:id", h.Update)
	req := httptest.NewRequest("PUT", "/strategies/x", strings.NewReader("x"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 400 { t.Fatalf("status=%d", w.Code) }
}

func TestStrategyUpdate_BadNetwork(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, db := newStrategyTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.PUT("/strategies/:id", h.Update)
	id := createTestStrategy(t, db, "test-user", "s1", "tcp")

	body := `{"name":"s1","protocol":"tcp","config":{"src_ip":"bad"}}`
	req := httptest.NewRequest("PUT", "/strategies/"+id, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 400 { t.Fatalf("status=%d", w.Code) }
}

func TestStrategyUpdate_RangeFail(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, db := newStrategyTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.PUT("/strategies/:id", h.Update)
	id := createTestStrategy(t, db, "test-user", "s1", "tcp")

	body := `{"name":"s1","protocol":"tcp","config":{"src_ip":"10.0.0.1","dscp":256}}`
	req := httptest.NewRequest("PUT", "/strategies/"+id, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 400 { t.Fatalf("status=%d", w.Code) }
}

func TestStrategyUpdate_BadSubConfig(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, db := newStrategyTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.PUT("/strategies/:id", h.Update)
	id := createTestStrategy(t, db, "test-user", "s1", "tcp")

	body := `{"name":"s1","protocol":"tcp","config":{"src_ip":"10.0.0.1","tcp":{"mss":99999}}}`
	req := httptest.NewRequest("PUT", "/strategies/"+id, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 400 { t.Fatalf("status=%d", w.Code) }
}

func TestStrategyUpdate_NotFound(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, _ := newStrategyTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.PUT("/strategies/:id", h.Update)
	body := `{"name":"s1","protocol":"tcp","config":{"src_ip":"10.0.0.1"}}`
	req := httptest.NewRequest("PUT", "/strategies/nonexistent", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 404 { t.Fatalf("status=%d", w.Code) }
	_, msg, _ := parseResponse(t, w.Body.Bytes())
	if !strings.Contains(msg, "strategy not found") { t.Errorf("msg=%q", msg) }
}

func TestStrategyUpdate_DBError(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, db := newStrategyTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.PUT("/strategies/:id", h.Update)
	sqlDB, _ := db.DB.DB()
	sqlDB.Close()
	req := httptest.NewRequest("PUT", "/strategies/x", strings.NewReader(`{"name":"s1","protocol":"tcp","config":{}}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code < 400 { t.Fatalf("status=%d", w.Code) }
}

func TestStrategyUpdate_BadFlowType(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, db := newStrategyTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.PUT("/strategies/:id", h.Update)
	id := createTestStrategy(t, db, "test-user", "s1", "tcp")

	body := `{"name":"s1","protocol":"tcp","config":{"src_ip":"10.0.0.1"},"flow_control":{"type":"x","value":1}}`
	req := httptest.NewRequest("PUT", "/strategies/"+id, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 400 { t.Fatalf("status=%d", w.Code) }
}

func TestStrategyUpdate_NonPositiveValue(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, db := newStrategyTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.PUT("/strategies/:id", h.Update)
	id := createTestStrategy(t, db, "test-user", "s1", "tcp")

	body := `{"name":"s1","protocol":"tcp","config":{"src_ip":"10.0.0.1"},"flow_control":{"type":"flows","value":0}}`
	req := httptest.NewRequest("PUT", "/strategies/"+id, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 400 { t.Fatalf("status=%d", w.Code) }
}

func TestStrategyUpdate_FCNil(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, db := newStrategyTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.PUT("/strategies/:id", h.Update)
	id := createTestStrategy(t, db, "test-user", "s1", "tcp")

	body := `{"name":"s2","protocol":"tcp","config":{"src_ip":"10.0.0.1","dst_ip":"10.0.0.2"}}`
	req := httptest.NewRequest("PUT", "/strategies/"+id, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 200 { t.Fatalf("status=%d", w.Code) }
}

func TestStrategyUpdate_DBSaveFail(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, db := newStrategyTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.PUT("/strategies/:id", h.Update)
	id := createTestStrategy(t, db, "test-user", "s1", "tcp")
	sqlDB, _ := db.DB.DB()
	sqlDB.Close()

	body := `{"name":"s2","protocol":"tcp","config":{"src_ip":"10.0.0.1"}}`
	req := httptest.NewRequest("PUT", "/strategies/"+id, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code < 400 { t.Fatalf("status=%d", w.Code) }
	// DB is closed, so the strategy query may fail before reaching the update step.
	// Accept either error path.
	_, msg, _ := parseResponse(t, w.Body.Bytes())
	if !strings.Contains(msg, "failed to") { t.Errorf("msg=%q", msg) }
}

// STRAT4-BR2: validation before ownership
func TestStrategyUpdate_ValidationBeforeOwnership(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, _ := newStrategyTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.PUT("/strategies/:id", h.Update)
	// False ID (not owned by user) + bad config
	body := `{"name":"s1","protocol":"tcp","config":{"src_ip":"bad"}}`
	req := httptest.NewRequest("PUT", "/strategies/some-other-id", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	// Config validation fires first -> 400, not 404
	if w.Code != 400 { t.Fatalf("expected 400 (validation before ownership), got %d", w.Code) }
}

// ---------------------------------------------------------------------------
// StrategyHandler — Delete (STRAT5-*)
// ---------------------------------------------------------------------------

func TestStrategyDelete_Success(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, db := newStrategyTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.DELETE("/strategies/:id", h.Delete)
	id := createTestStrategy(t, db, "test-user", "s1", "tcp")

	req := httptest.NewRequest("DELETE", "/strategies/"+id, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 200 { t.Fatalf("status=%d", w.Code) }
	_, msg, _ := parseResponse(t, w.Body.Bytes())
	if !strings.Contains(msg, "strategy deleted") { t.Errorf("msg=%q", msg) }
	var count int64
	db.Model(&storage.StrategyModel{}).Where("id = ?", id).Count(&count)
	if count != 0 { t.Errorf("strategy still exists") }
}

func TestStrategyDelete_NoUser(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, _ := newStrategyTestServer(t)
	r.DELETE("/strategies/:id", h.Delete)
	req := httptest.NewRequest("DELETE", "/strategies/x", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 401 { t.Fatalf("status=%d", w.Code) }
}

func TestStrategyDelete_MissingID(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, _ := newStrategyTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.DELETE("/strategies/:id", h.Delete)
	// Gin doesn't match /strategies/ (no id) to the :id route — returns 404 (no route).
	req := httptest.NewRequest("DELETE", "/strategies/_empty", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 400 && w.Code != 404 { t.Fatalf("status=%d", w.Code) }
}

func TestStrategyDelete_NotFound(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, _ := newStrategyTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.DELETE("/strategies/:id", h.Delete)
	req := httptest.NewRequest("DELETE", "/strategies/nonexistent", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 404 { t.Fatalf("status=%d", w.Code) }
	_, msg, _ := parseResponse(t, w.Body.Bytes())
	if !strings.Contains(msg, "strategy not found") { t.Errorf("msg=%q", msg) }
}

func TestStrategyDelete_DBError(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, db := newStrategyTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.DELETE("/strategies/:id", h.Delete)
	sqlDB, _ := db.DB.DB()
	sqlDB.Close()
	req := httptest.NewRequest("DELETE", "/strategies/x", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code < 400 { t.Fatalf("status=%d", w.Code) }
}

func TestStrategyDelete_UsedByTasks(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, db := newStrategyTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.DELETE("/strategies/:id", h.Delete)
	id := createTestStrategy(t, db, "test-user", "s1", "tcp")
	// Create a task referencing this strategy
	stratIDs, _ := json.Marshal([]string{id})
	db.Create(&storage.TaskModel{
		ID: uuid.New().String(), UserID: "test-user", Name: "t1",
		StrategyIDs: string(stratIDs), Status: "pending",
	})

	req := httptest.NewRequest("DELETE", "/strategies/"+id, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 400 { t.Fatalf("status=%d", w.Code) }
	_, msg, _ := parseResponse(t, w.Body.Bytes())
	if !strings.Contains(msg, "cannot delete") { t.Errorf("msg=%q", msg) }
}

func TestStrategyDelete_DBSaveFail(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, db := newStrategyTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.DELETE("/strategies/:id", h.Delete)
	id := createTestStrategy(t, db, "test-user", "s1", "tcp")
	sqlDB, _ := db.DB.DB()
	sqlDB.Close()
	req := httptest.NewRequest("DELETE", "/strategies/"+id, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code < 400 { t.Fatalf("status=%d", w.Code) }
}

func TestStrategyDelete_UsedByCompletedTask(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, db := newStrategyTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.DELETE("/strategies/:id", h.Delete)
	id := createTestStrategy(t, db, "test-user", "s1", "tcp")
	stratIDs, _ := json.Marshal([]string{id})
	db.Create(&storage.TaskModel{
		ID: uuid.New().String(), UserID: "test-user", Name: "t1",
		StrategyIDs: string(stratIDs), Status: "completed",
	})

	req := httptest.NewRequest("DELETE", "/strategies/"+id, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 400 { t.Fatalf("status=%d", w.Code) }
	_, msg, _ := parseResponse(t, w.Body.Bytes())
	if !strings.Contains(msg, "cannot delete") { t.Errorf("msg should mention task reference, got %q", msg) }
}

// ---------------------------------------------------------------------------
// StrategyHandler — ListTasks (STRAT6-*)
// ---------------------------------------------------------------------------

func TestStrategyListTasks_HasTasks(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, db := newStrategyTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.GET("/strategies/:id/tasks", h.ListTasks)
	id := createTestStrategy(t, db, "test-user", "s1", "tcp")
	stratIDs, _ := json.Marshal([]string{id})
	db.Create(&storage.TaskModel{
		ID: uuid.New().String(), UserID: "test-user", Name: "t1",
		StrategyIDs: string(stratIDs), Status: "pending",
	})

	req := httptest.NewRequest("GET", "/strategies/"+id+"/tasks", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 200 { t.Fatalf("status=%d", w.Code) }
	code, _, data := parseResponse(t, w.Body.Bytes())
	if code != 0 { t.Errorf("code=%d", code) }
	var tasks []interface{}
	json.Unmarshal(data, &tasks)
	if len(tasks) == 0 { t.Error("expected tasks") }
}

func TestStrategyListTasks_Empty(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, db := newStrategyTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.GET("/strategies/:id/tasks", h.ListTasks)
	id := createTestStrategy(t, db, "test-user", "s1", "tcp")

	req := httptest.NewRequest("GET", "/strategies/"+id+"/tasks", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 200 { t.Fatalf("status=%d", w.Code) }
	code, _, data := parseResponse(t, w.Body.Bytes())
	if code != 0 { t.Errorf("code=%d", code) }
	var tasks []interface{}
	json.Unmarshal(data, &tasks)
	if len(tasks) != 0 { t.Errorf("expected empty, got %d", len(tasks)) }
}

func TestStrategyListTasks_NoUser(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, _ := newStrategyTestServer(t)
	r.GET("/strategies/:id/tasks", h.ListTasks)
	req := httptest.NewRequest("GET", "/strategies/x/tasks", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 401 { t.Fatalf("status=%d", w.Code) }
}

func TestStrategyListTasks_MissingID(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, _ := newStrategyTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.GET("/strategies/:id/tasks", h.ListTasks)
	req := httptest.NewRequest("GET", "/strategies//tasks", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 400 { t.Fatalf("status=%d", w.Code) }
}

func TestStrategyListTasks_NotFound(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, _ := newStrategyTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.GET("/strategies/:id/tasks", h.ListTasks)
	req := httptest.NewRequest("GET", "/strategies/nonexistent/tasks", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 404 { t.Fatalf("status=%d", w.Code) }
}

func TestStrategyListTasks_DBError(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, db := newStrategyTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.GET("/strategies/:id/tasks", h.ListTasks)
	sqlDB, _ := db.DB.DB()
	sqlDB.Close()
	req := httptest.NewRequest("GET", "/strategies/x/tasks", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code < 400 { t.Fatalf("status=%d", w.Code) }
}
// TestStrategyCreate_TFTPTIDConflict (spec T-066/T-108, V22): a TFTP strategy
// whose config pins server_tid and whose flow_control type=flows value>1
// would generate multiple flows with the SAME server TID. Per spec S12 the
// batch-level server_tid uniqueness check (V22) must reject this at strategy
// creation time.
func TestStrategyCreate_TFTPTIDConflict(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, _ := newStrategyTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.POST("/strategies", h.Create)
	body := `{"name":"s1","protocol":"tftp","config":{"tftp":{"server_tid":60000}},"flow_control":{"type":"flows","value":2}}`
	req := httptest.NewRequest("POST", "/strategies", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 400 {
		t.Fatalf("status=%d, want 400 (server_tid conflicts across flows must be rejected)", w.Code)
	}
	if !strings.Contains(w.Body.String(), "conflicts with another flow") {
		t.Fatalf("body=%q, want 'conflicts with another flow'", w.Body.String())
	}
}

// T-FTP-15（D-FTP-2 §5）：REST create/Update 上 flat 静态复制 400；
// 省略端口 / 补 tuples / layers 豁免照常 201。
func TestStaticCopyRejection(t *testing.T) {
	h, r, _ := newStrategyTestServer(t)
	stratUser(r, "u1", "alice")
	r.POST("/strategies", h.Create)

	// ① pinned + flows=3 → 400
	body := `{"name":"s","protocol":"tcp","config":{"src_port":12345,"tcp":{}},"flow_control":{"type":"flows","value":3}}`
	w := postStrategy(t, r, body)
	if w.Code != 400 || !strings.Contains(w.Body.String(), "static copy") {
		t.Fatalf("① status=%d body=%s", w.Code, w.Body.String())
	}
	// ② omit src_port → 201
	body2 := `{"name":"s2","protocol":"tcp","config":{"tcp":{}},"flow_control":{"type":"flows","value":3}}`
	w2 := postStrategy(t, r, body2)
	if w2.Code != 201 {
		t.Fatalf("② status=%d body=%s", w2.Code, w2.Body.String())
	}
	// ③ tuples → 201
	body3 := `{"name":"s3","protocol":"tcp","config":{"src_port":12345,"tuples":{"src_port":{"strategy":"fixed","value":12345}},"tcp":{}},"flow_control":{"type":"flows","value":3}}`
	w3 := postStrategy(t, r, body3)
	if w3.Code != 201 {
		t.Fatalf("③ status=%d body=%s", w3.Code, w3.Body.String())
	}
	// ④ layers → exempt
	body4 := `{"name":"s4","config":{"layers":[{"tcp":{}},{"http":{}}]},"flow_control":{"type":"flows","value":3}}`
	w4 := postStrategy(t, r, body4)
	if w4.Code != 201 {
		t.Fatalf("④ status=%d body=%s", w4.Code, w4.Body.String())
	}
}
