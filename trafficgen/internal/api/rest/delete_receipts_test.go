package rest

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/trafficgen/trafficgen/internal/storage"
)

// P1-10（2026-10-06 客户端复测）：删除类操作必须返回确认回执 {id, deleted:true}
// ——data:null 让调用方无从核对删的是谁、删没删成。上轮只修了 pcap delete，
// 本批补齐同类四处：strategy / task / user / port_group（同类根因一次修全）。

// assertDeleteReceipt asserts the delete response carries {id, deleted:true}.
func assertDeleteReceipt(t *testing.T, body []byte, wantID string) {
	t.Helper()
	code, msg, data := parseResponse(t, body)
	if code != CodeSuccess {
		t.Fatalf("status=%d msg=%s", code, msg)
	}
	if string(data) == "null" || len(data) == 0 {
		t.Fatalf("delete receipt missing (data=%s), msg=%s", string(data), msg)
	}
	var receipt struct {
		ID      string `json:"id"`
		Deleted bool   `json:"deleted"`
	}
	if err := json.Unmarshal(data, &receipt); err != nil {
		t.Fatalf("delete receipt not parseable: %v, data=%s", err, string(data))
	}
	if receipt.ID != wantID || !receipt.Deleted {
		t.Errorf("receipt = {id:%q deleted:%v}, want {id:%q deleted:true}", receipt.ID, receipt.Deleted, wantID)
	}
}

func TestStrategyDeleteReceipt(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, db := newStrategyTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.DELETE("/strategies/:id", h.Delete)
	id := createTestStrategy(t, db, "test-user", "s1", "tcp")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/strategies/"+id, nil))
	assertDeleteReceipt(t, w.Body.Bytes(), id)
}

func TestTaskDeleteReceipt(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, db, _ := newTaskTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.DELETE("/tasks/:id", h.Delete)
	taskID := uuid.New().String()
	db.Create(&storage.TaskModel{ID: taskID, UserID: "test-user", Name: "t1", Status: "completed"})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/tasks/"+taskID, nil))
	assertDeleteReceipt(t, w.Body.Bytes(), taskID)
}

func TestPortGroupDeleteReceipt(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, db := newPortGroupTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.DELETE("/port-groups/:id", h.Delete)
	pg := &storage.PortGroupModel{ID: uuid.New().String(), Name: "pg1-del-rcpt", PortsConfig: `[{"interface":"lo","weight":1}]`}
	if err := db.Create(pg).Error; err != nil {
		t.Fatalf("seed port group: %v", err)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/port-groups/"+pg.ID, nil))
	assertDeleteReceipt(t, w.Body.Bytes(), pg.ID)
}

func TestUserDeleteReceipt(t *testing.T) {
	gin.SetMode(gin.TestMode)
	gormDB, err := gorm.Open(sqlite.Open(t.TempDir()+"/user_test.db"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := storage.AutoMigrate(gormDB); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	db := &storage.DB{DB: gormDB}
	h := NewUserHandler(db)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("userID", "admin-id")
		c.Set("roles", []string{"admin"})
		c.Next()
	})
	r.DELETE("/users/:id", h.Delete)
	u := &storage.UserModel{ID: uuid.New().String(), Username: "del-me", Role: "user", Enabled: true}
	if err := db.Create(u).Error; err != nil {
		t.Fatalf("seed user: %v", err)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/users/"+u.ID, nil))
	assertDeleteReceipt(t, w.Body.Bytes(), u.ID)
}
