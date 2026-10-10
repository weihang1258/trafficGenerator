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

// Weight 缺省归一（客户端实测：省略 weight 命中 weight:0 组而非 weight:1
// 组——有名无实的字段制造分组噪音）。修后：省略/0/1 三写同组（默认 1），
// 落库 weight:1；真正不同的非零 weight 仍分不同组。
func TestPortGroupCreate_WeightDefaultNormalized(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := newPortGroupTestDB(t)
	h := NewPortGroupHandler(db)
	r := gin.New()
	r.POST("/port-groups", h.Create)

	post := func(body string) (int, map[string]string) {
		req := httptest.NewRequest("POST", "/port-groups", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		var env struct {
			Code int               `json:"code"`
			Data map[string]string `json:"data"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &env); err != nil || env.Data == nil {
			t.Fatalf("unexpected body for %s: %s", body, w.Body.String())
		}
		return w.Code, env.Data
	}

	_, omit := post(`{"ports":[{"interface":"ethW"}]}`)
	_, zero := post(`{"ports":[{"interface":"ethW","weight":0}]}`)
	_, one := post(`{"ports":[{"interface":"ethW","weight":1}]}`)
	if omit["id"] != zero["id"] || zero["id"] != one["id"] {
		t.Fatalf("omitted/0/1 must be the same group: %s vs %s vs %s", omit["id"], zero["id"], one["id"])
	}
	if zero["message"] != "port group already exists" || one["message"] != "port group already exists" {
		t.Errorf("second/third create must report reuse, got %q / %q", zero["message"], one["message"])
	}
	// 落库形状归一。
	var pg storage.PortGroupModel
	if err := db.Where("id = ?", omit["id"]).First(&pg).Error; err != nil {
		t.Fatalf("load group: %v", err)
	}
	if !strings.Contains(pg.PortsConfig, `"weight":1`) {
		t.Errorf("stored ports_config = %s, want normalized weight 1", pg.PortsConfig)
	}
	// 非零差异仍分流。
	_, two := post(`{"ports":[{"interface":"ethW","weight":2}]}`)
	if two["id"] == omit["id"] {
		t.Errorf("weight=2 must be a different group, got same id %s", two["id"])
	}
}
