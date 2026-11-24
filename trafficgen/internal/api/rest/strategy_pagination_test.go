package rest

// D-REQ-1 批 5 红例先行：strategies/list 可选分页——page/size 给定时返回
// {items,page,size,total} 封装；缺省保持裸数组向后兼容。
import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	sqlite "github.com/glebarez/sqlite"
	"github.com/trafficgen/trafficgen/internal/storage"
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

// 红例（客户端 2026-11-23 问题 7）：超大 page/size 曾让 (page-1)*size 溢出成
// 负偏移，result[start:end] 切出 [正:负] 直接 panic（HTTP 层 500 / MCP 层
// "handler panic: slice bounds out of range [:-50]"）。分页计算必须先除后乘
// 或钳位，任何输入都只能得到合法的页（越界页 = 空页，不是 500）。
func TestStrategyList_PaginationOverflowNoPanic(t *testing.T) {
	r, db := newStratListServer(t)
	seedStrategies(t, db, 5)
	cases := []struct {
		query   string
		wantLen int // size 超上限会收敛到 1000，所以 page=1 仍是满页
	}{
		{"?page=9223372036854775807&size=50", 0},      // 起点乘法溢出为负
		{"?page=1&size=9223372036854775807", 5},       // 终点加法溢出为负；size 收敛到 1000
		{"?page=4000000000000&size=4000000000000", 0}, // 两者相乘溢出 64 位
	}
	for _, tc := range cases {
		req := httptest.NewRequest("GET", "/strategies"+tc.query, nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req) // panic 会直接让本测试失败
		if w.Code != 200 {
			t.Errorf("%s: status=%d, want 200 (a page past the end is an empty page, not an error)", tc.query, w.Code)
		}
		var resp struct {
			Data struct {
				Items []map[string]interface{} `json:"items"`
			} `json:"data"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("%s: unmarshal: %v", tc.query, err)
		}
		if len(resp.Data.Items) != tc.wantLen {
			t.Errorf("%s: got %d items, want %d", tc.query, len(resp.Data.Items), tc.wantLen)
		}
	}
}

// 红例：size=0 与其余列表端点同口径＝全量，且响应 size 回实际条数。
func TestStrategyList_SizeZeroIsFullAndEchoesCount(t *testing.T) {
	r, db := newStratListServer(t)
	seedStrategies(t, db, 3)
	req := httptest.NewRequest("GET", "/strategies?size=0", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	var resp struct {
		Data struct {
			Items []map[string]interface{} `json:"items"`
			Size  int                      `json:"size"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v (body=%s)", err, w.Body.String())
	}
	if len(resp.Data.Items) != 3 {
		t.Fatalf("items=%d, want 3 (size=0 means ALL)", len(resp.Data.Items))
	}
	if resp.Data.Size != 3 {
		t.Errorf("size=%d, want 3 (echo the actual count, not the 0 sentinel)", resp.Data.Size)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
