package rest

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	sqlite "github.com/glebarez/sqlite"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"github.com/trafficgen/trafficgen/internal/storage"
)

// P2-18（2026-10-05 客户端复测）：port_group create 幂等返回必须回显实际
// 组名（hash 派生）——此前只回 id+message，调用方传的名字被静默丢弃还不
// 知道真实组名，以为新建了组。
func TestPortGroupCreateReusedEchoesActualName(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := newPortGroupTestDB(t)
	h := NewPortGroupHandler(db)
	r := gin.New()
	r.POST("/port-groups", h.Create)

	post := func(name string) map[string]string {
		body := `{"name":"` + name + `","ports":[{"interface":"lo"}]}`
		req := httptest.NewRequest("POST", "/port-groups", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK && w.Code != http.StatusCreated {
			t.Fatalf("create: %d %s", w.Code, w.Body.String())
		}
		var env struct {
			Code int               `json:"code"`
			Data map[string]string `json:"data"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &env); err != nil || env.Data == nil {
			t.Fatalf("unexpected body: %s", w.Body.String())
		}
		return env.Data
	}

	first := post("pg-name-a")
	second := post("pg-name-DIFFERENT")
	if first["id"] != second["id"] {
		t.Fatalf("same interface must reuse the group: %s vs %s", first["id"], second["id"])
	}
	if second["name"] == "" || strings.Contains(second["name"], "pg-name-DIFFERENT") {
		t.Errorf("reused response must echo the actual hash-derived name, got %q", second["name"])
	}
	if !strings.HasPrefix(second["name"], "port_group_") {
		t.Errorf("actual name should be the hash form, got %q", second["name"])
	}
}

func newPortGroupTestDB(t *testing.T) *storage.DB {
	t.Helper()
	gormDB, err := gorm.Open(sqlite.Open(t.TempDir()+"/p2_test.db"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := storage.AutoMigrate(gormDB); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return &storage.DB{DB: gormDB}
}

// P2-17（2026-10-05 客户端复测）：自动注册指引必须给绝对路径——import
// 校验拒绝相对路径，旧 note 原样回显任务配置里的相对路径，照指引补注册
// 必然再失败一轮。
func TestAutoRegisterNoteGivesAbsolutePath(t *testing.T) {
	db := newPortGroupTestDB(t)
	p := NewPcapHandler(db, "")
	rel := "audit-rel-dir/missing.pcap"
	task := &storage.TaskModel{
		ID: "t-note", UserID: "u1", OutputType: "pcap", Status: "completed",
		OutputConfig: `{"pcap_path":"` + rel + `"}`,
	}
	AutoRegisterTaskPcap(db, p, task)
	if task.PcapAssetNote == "" {
		t.Fatal("missing pcap must produce a note")
	}
	want, _ := filepath.Abs(rel)
	if !strings.Contains(task.PcapAssetNote, want) {
		t.Errorf("note must carry the absolute path %q, got: %s", want, task.PcapAssetNote)
	}
	if strings.Contains(task.PcapAssetNote, `"file_path":"`+rel+`"`) {
		t.Errorf("note must not carry the raw relative path, got: %s", task.PcapAssetNote)
	}
}
