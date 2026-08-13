package rest

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/trafficgen/trafficgen/internal/storage"
)

// P3 layer-chain strategy creation tests (design §10.2 创建时校验 + §6.2
// protocol 推断 + §14.1 T14: 非法层链 → 策略创建失败，不是生成时才报)。

func postStrategy(t *testing.T, r *gin.Engine, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", "/strategies", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// 层链策略创建成功：protocol 缺失时按最外层推断并持久化。
func TestStrategyCreate_LayersInferredProtocol(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, db := newStrategyTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Set("username", "alice"); c.Set("roles", []string{"user"}); c.Next() })
	r.POST("/strategies", h.Create)

	// 不写 protocol → 由层链最外层推断 http。
	body := `{"name":"s1","config":{"layers":[{"tcp":{}},{"http":{}}]},"flow_control":{"type":"flows","value":10}}`
	w := postStrategy(t, r, body)
	if w.Code != 201 {
		t.Fatalf("status=%d, body=%s", w.Code, w.Body.String())
	}
	_, _, data := parseResponse(t, w.Body.Bytes())
	var d map[string]string
	if err := json.Unmarshal(data, &d); err != nil {
		t.Fatalf("parse data: %v", err)
	}
	if d["id"] == "" {
		t.Fatal("no strategy id")
	}
	var s storage.StrategyModel
	if err := db.Where("id = ?", d["id"]).First(&s).Error; err != nil {
		t.Fatalf("load strategy: %v", err)
	}
	if s.Protocol != "http" {
		t.Errorf("persisted protocol = %q, want %q (inferred)", s.Protocol, "http")
	}
}

// 层链创建失败（创建时报错，不是生成时报）：非法层名。
func TestStrategyCreate_LayersUnknownLayer(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, _ := newStrategyTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Set("username", "alice"); c.Set("roles", []string{"user"}); c.Next() })
	r.POST("/strategies", h.Create)

	body := `{"name":"s1","protocol":"http","config":{"layers":[{"bogus":{}}]},"flow_control":{"type":"flows","value":10}}`
	w := postStrategy(t, r, body)
	if w.Code != 400 {
		t.Fatalf("status=%d, body=%s (want 400)", w.Code, w.Body.String())
	}
	code, msg, _ := parseResponse(t, w.Body.Bytes())
	if code != 400 {
		t.Errorf("code=%d, want 400", code)
	}
	if !strings.Contains(msg, "unknown layer") {
		t.Errorf("msg=%q, want mention of unknown layer", msg)
	}
}

// 层链创建失败：protocol 与最外层不一致（V10）。
func TestStrategyCreate_LayersProtocolMismatch(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, _ := newStrategyTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Set("username", "alice"); c.Set("roles", []string{"user"}); c.Next() })
	r.POST("/strategies", h.Create)

	body := `{"name":"s1","protocol":"gre","config":{"layers":[{"tcp":{}},{"http":{}}]},"flow_control":{"type":"flows","value":10}}`
	w := postStrategy(t, r, body)
	if w.Code != 400 {
		t.Fatalf("status=%d, body=%s (want 400)", w.Code, w.Body.String())
	}
	_, msg, _ := parseResponse(t, w.Body.Bytes())
	if !strings.Contains(msg, "does not match outermost layer") {
		t.Errorf("msg=%q, want V10 mismatch error", msg)
	}
}

// 层链创建失败：字段超范围（V9）。
func TestStrategyCreate_LayersFieldRange(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, _ := newStrategyTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Set("username", "alice"); c.Set("roles", []string{"user"}); c.Next() })
	r.POST("/strategies", h.Create)

	body := `{"name":"s1","protocol":"tcp","config":{"layers":[{"tcp":{"mss":500}}]},"flow_control":{"type":"flows","value":10}}`
	w := postStrategy(t, r, body)
	if w.Code != 400 {
		t.Fatalf("status=%d, body=%s (want 400)", w.Code, w.Body.String())
	}
	_, msg, _ := parseResponse(t, w.Body.Bytes())
	if !strings.Contains(msg, "mss") {
		t.Errorf("msg=%q, want mss range error", msg)
	}
}

// 无 layers 的存量 flat 写法不受影响（legacy 路径）。
func TestStrategyCreate_FlatConfigStillWorks(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, _ := newStrategyTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Set("username", "alice"); c.Set("roles", []string{"user"}); c.Next() })
	r.POST("/strategies", h.Create)

	body := `{"name":"s1","protocol":"tcp","config":{"src_ip":"10.0.0.1","dst_ip":"10.0.0.2","tcp":{"mss":1460}},"flow_control":{"type":"flows","value":10}}`
	w := postStrategy(t, r, body)
	if w.Code != 201 {
		t.Fatalf("status=%d, body=%s (want 201)", w.Code, w.Body.String())
	}
}

// 层链数组为空 → 拒绝。
func TestStrategyCreate_LayersEmptyChain(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, _ := newStrategyTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Set("username", "alice"); c.Set("roles", []string{"user"}); c.Next() })
	r.POST("/strategies", h.Create)

	body := `{"name":"s1","protocol":"http","config":{"layers":[]},"flow_control":{"type":"flows","value":10}}`
	w := postStrategy(t, r, body)
	if w.Code != 400 {
		t.Fatalf("status=%d, body=%s (want 400)", w.Code, w.Body.String())
	}
}

// Update 路径同款层链校验（§3 每路径一测试）：protocol 缺失时推断并持久化。
func TestStrategyUpdate_LayersInferredProtocol(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, db := newStrategyTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.PUT("/strategies/:id", h.Update)
	id := createTestStrategy(t, db, "test-user", "s1", "tcp")

	body := `{"name":"s2","config":{"layers":[{"tcp":{}},{"http":{}}]},"flow_control":{"type":"flows","value":10}}`
	req := httptest.NewRequest("PUT", "/strategies/"+id, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("status=%d, body=%s (want 200)", w.Code, w.Body.String())
	}
	var s storage.StrategyModel
	if err := db.Where("id = ?", id).First(&s).Error; err != nil {
		t.Fatalf("load strategy: %v", err)
	}
	if s.Protocol != "http" {
		t.Errorf("persisted protocol = %q, want %q (inferred)", s.Protocol, "http")
	}
}

// Update 路径：非法层名 → 400（负向路径，与 Create 对称）。
func TestStrategyUpdate_LayersUnknownLayer(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, db := newStrategyTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.PUT("/strategies/:id", h.Update)
	id := createTestStrategy(t, db, "test-user", "s1", "tcp")

	body := `{"name":"s2","protocol":"http","config":{"layers":[{"bogus":{}}]},"flow_control":{"type":"flows","value":10}}`
	req := httptest.NewRequest("PUT", "/strategies/"+id, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 400 {
		t.Fatalf("status=%d, body=%s (want 400)", w.Code, w.Body.String())
	}
	_, msg, _ := parseResponse(t, w.Body.Bytes())
	if !strings.Contains(msg, "unknown layer") {
		t.Errorf("msg=%q, want mention of unknown layer", msg)
	}
}

// Update replay 分支：replay spec 里混入 layers 键必须被拒绝，不能静默忽略。
// replay 的 config 只接受 pcap_asset_id/speed/direction/checksum_mode 字段，
// layers 混入会被 ValidateReplaySpec 放过 → 层链校验被绕过 → 静默丢失。
func TestStrategyUpdate_ReplayRejectsLayers(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, db := newStrategyTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.PUT("/strategies/:id", h.Update)
	id := createTestStrategy(t, db, "test-user", "s1", "tcp")

	body := `{"mode":"replay","name":"s2","config":{"pcap_asset_id":"p1","speed":{"mode":"original"},"layers":[{"bogus":{}}]},"flow_control":{"type":"time","value":10}}`
	req := httptest.NewRequest("PUT", "/strategies/"+id, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 400 {
		t.Fatalf("status=%d, body=%s (want 400)", w.Code, w.Body.String())
	}
	_, msg, _ := parseResponse(t, w.Body.Bytes())
	if !strings.Contains(msg, "replay") {
		t.Errorf("msg=%q, want mention of layers being invalid for replay", msg)
	}
}

// Create replay 分支同款防护（与 Update 对称，§3 每路径一测试）。
func TestStrategyCreate_ReplayRejectsLayers(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, _ := newStrategyTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Set("username", "alice"); c.Set("roles", []string{"user"}); c.Next() })
	r.POST("/strategies", h.Create)

	body := `{"mode":"replay","name":"s1","config":{"pcap_asset_id":"p1","speed":{"mode":"original"},"layers":[{"http":{}}]},"flow_control":{"type":"time","value":10}}`
	w := postStrategy(t, r, body)
	if w.Code != 400 {
		t.Fatalf("status=%d, body=%s (want 400)", w.Code, w.Body.String())
	}
	_, msg, _ := parseResponse(t, w.Body.Bytes())
	if !strings.Contains(msg, "replay") {
		t.Errorf("msg=%q, want mention of layers being invalid for replay", msg)
	}
}

// 显式 protocol 与最外层一致 → 不覆盖为推断值（Create 路径回归，防
// ValidateLayers 返回 ("",nil) 被 handler 回填成空串）。
func TestStrategyCreate_LayersExplicitProtocolPreserved(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, db := newStrategyTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Set("username", "alice"); c.Set("roles", []string{"user"}); c.Next() })
	r.POST("/strategies", h.Create)

	body := `{"name":"s1","protocol":"http","config":{"layers":[{"tcp":{}},{"http":{}}]},"flow_control":{"type":"flows","value":10}}`
	w := postStrategy(t, r, body)
	if w.Code != 201 {
		t.Fatalf("status=%d, body=%s", w.Code, w.Body.String())
	}
	_, _, data := parseResponse(t, w.Body.Bytes())
	var d map[string]string
	if err := json.Unmarshal(data, &d); err != nil {
		t.Fatalf("parse data: %v", err)
	}
	var s storage.StrategyModel
	if err := db.Where("id = ?", d["id"]).First(&s).Error; err != nil {
		t.Fatalf("load strategy: %v", err)
	}
	if s.Protocol != "http" {
		t.Errorf("persisted protocol = %q, want %q (explicit, not clobbered)", s.Protocol, "http")
	}
}
