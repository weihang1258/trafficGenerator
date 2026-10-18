package rest

// D-REQ-1 批 5 红例先行：strategies/list 可选分页——page/size 给定时返回
// {items,page,size,total} 封装；缺省保持裸数组向后兼容。
import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"testing"

	sqlite "github.com/glebarez/sqlite"
	"github.com/trafficgen/trafficgen/internal/storage"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

func newStratListServer(t *testing.T) (*gin.Engine, *storage.DB) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	gormDB, err := gorm.Open(sqlite.Open(t.TempDir()+"/s.db"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := storage.AutoMigrate(gormDB); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	db := &storage.DB{DB: gormDB}
	h := NewStrategyHandler(db)
	r := gin.New()
	r.Use(func(c *gin.Context) { c.Set("userID", "u1"); c.Next() })
	r.GET("/strategies", h.List)
	return r, db
}

func seedStrategies(t *testing.T, db *storage.DB, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		s := storage.StrategyModel{ID: fmt.Sprintf("s-%03d", i), UserID: "u1", Name: fmt.Sprintf("s%03d", i), Mode: "synth", ConfigHash: fmt.Sprintf("h%d", i)}
		if err := db.Create(&s).Error; err != nil {
			t.Fatalf("seed %d: %v", i, err)
		}
	}
}

// 红例：page/size 给定 → 封装形（修复前：无分页、裸数组、参数被忽略）。
func TestStrategyList_OptionalPagination(t *testing.T) {
	r, db := newStratListServer(t)
	seedStrategies(t, db, 5)
	req := httptest.NewRequest("GET", "/strategies?page=2&size=2", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("status=%d", w.Code)
	}
	var resp struct {
		Data struct {
			Items []map[string]interface{} `json:"items"`
			Page  int                      `json:"page"`
			Size  int                      `json:"size"`
			Total int                      `json:"total"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v (body=%s)", err, w.Body.String())
	}
	if resp.Data.Total != 5 || resp.Data.Page != 2 || resp.Data.Size != 2 {
		t.Fatalf("page=%d size=%d total=%d, want 2/2/5", resp.Data.Page, resp.Data.Size, resp.Data.Total)
	}
	if len(resp.Data.Items) != 2 {
		t.Fatalf("items=%d, want 2", len(resp.Data.Items))
	}
}

// 向后兼容：缺省（无 page/size）→ 裸数组（既有调用方零破坏）。
func TestStrategyList_DefaultBareArray(t *testing.T) {
	r, db := newStratListServer(t)
	seedStrategies(t, db, 3)
	req := httptest.NewRequest("GET", "/strategies", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("status=%d", w.Code)
	}
	// 缺省形：data 直接是数组（裸数组在 data 内，与 tasks/list 的
	// {items,total} 封装相区别）。
	var resp struct {
		Data []map[string]interface{} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("bare-array data expected: %v (body=%s)", err, w.Body.String()[:min(200, len(w.Body.String()))])
	}
	if len(resp.Data) != 3 {
		t.Fatalf("data=%d items, want 3", len(resp.Data))
	}
}

// 缺省 size 上限 50：page=1&size 省略 → 5 条全返（<50 不截断）。
func TestStrategyList_PaginationSizeCap(t *testing.T) {
	r, db := newStratListServer(t)
	seedStrategies(t, db, 3)
	req := httptest.NewRequest("GET", "/strategies?page=1", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	var resp struct {
		Data struct {
			Items []map[string]interface{} `json:"items"`
			Size  int                      `json:"size"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Data.Size != 50 || len(resp.Data.Items) != 3 {
		t.Fatalf("size=%d items=%d, want size=50 items=3", resp.Data.Size, len(resp.Data.Items))
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
