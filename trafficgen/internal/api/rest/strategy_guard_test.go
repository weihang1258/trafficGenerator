package rest

// 复测回执 #3 发现③：畸形 strategy_ids（空串）让 json_each 守卫炸出
// SQL malformed JSON → count=0 → 被引用策略被删（发现②的放大器）。
// CASE+json_valid 守卫：空串行算"不引用"，合法行照常命中。
import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	sqlite "github.com/glebarez/sqlite"
	"github.com/trafficgen/trafficgen/internal/storage"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

func TestStrategyDeleteGuard_MalformedTaskRowsDontBypassGuard(t *testing.T) {
	gin.SetMode(gin.TestMode)
	gormDB, err := gorm.Open(sqlite.Open(t.TempDir()+"/g.db"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := storage.AutoMigrate(gormDB); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	db := &storage.DB{DB: gormDB}

	// 策略 + 两类任务行：合法引用行（JSON 数组）+ 畸形行（空串）。
	strat := storage.StrategyModel{ID: "strat-1", UserID: "u1", Name: "s1", Mode: "synth", ConfigHash: "h1"}
	if err := db.Create(&strat).Error; err != nil {
		t.Fatalf("seed strategy: %v", err)
	}
	if err := db.Create(&storage.TaskModel{ID: "t-ref", UserID: "u1", Name: "ref", Status: "completed", StrategyIDs: `["strat-1"]`}).Error; err != nil {
		t.Fatalf("seed ref task: %v", err)
	}
	if err := db.Create(&storage.TaskModel{ID: "t-bad", UserID: "u1", Name: "bad", Status: "completed", StrategyIDs: ""}).Error; err != nil {
		t.Fatalf("seed malformed task: %v", err)
	}

	h := NewStrategyHandler(db)
	r := gin.New()
	r.Use(func(c *gin.Context) { c.Set("userID", "u1"); c.Next() })
	r.DELETE("/strategies/:id", h.Delete)

	req := httptest.NewRequest("DELETE", "/strategies/strat-1", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "used by tasks") {
		t.Fatalf("delete guarded strategy with malformed rows present = %d %s, want 400 + used-by-tasks (guard bypassed)", w.Code, w.Body.String())
	}
}
