package rest

// D-REQ-1 批 4 红例：协议语义错误建单即拒（原：开跑才报 validation failed）。
import (
	"net/http/httptest"
	"strings"
	"testing"

	sqlite "github.com/glebarez/sqlite"
	"github.com/gin-gonic/gin"
	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/storage"
	_ "github.com/trafficgen/trafficgen/internal/protocol/ike"
	"gorm.io/gorm"
)

func newDryRunServer(t *testing.T) (*gin.Engine) {
	gin.SetMode(gin.TestMode)
	gormDB, err := gorm.Open(sqlite.Open(t.TempDir()+"/d.db"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := storage.AutoMigrate(gormDB); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	db := &storage.DB{DB: gormDB}
	e := core.NewEngine(core.EngineConfig{
		ConfigWorkers: 1, PacketWorkers: 1, OutputWorkers: 1,
		BufferSize: 256, QueueSize: 64,
	})
	if err := e.Start(); err != nil {
		t.Fatalf("start engine: %v", err)
	}
	defer e.Stop()
	h := NewTaskHandler(db, e, nil)
	sh := NewStrategyHandler(db)
	r := gin.New()
	r.Use(func(c *gin.Context) { c.Set("userID", "u1"); c.Next() })
	r.POST("/strategies", sh.Create)
	r.POST("/tasks/batch", h.CreateBatch)
	return r
}

// D1：ike scenario 未知 → 策略建单即拒（原：开跑才报 validation failed）。
func TestDryRun_IkeScenarioUnknownRejected(t *testing.T) {
	r := newDryRunServer(t)
	body := `{"name":"dr-ike","mode":"synth","protocol":"ike","config":{"layers":[{"ip":{"src":"10.0.0.1","dst":"20.0.0.1"}},{"udp":{"dst_port":500}},{"ike":{"scenario":"probe-str-01"}}]}}`
	req := httptest.NewRequest("POST", "/strategies", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 400 {
		t.Fatalf("ike unknown scenario = %d %s, want 400", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "unknown") {
		t.Fatalf("msg=%s, want 'unknown' anchor", w.Body.String())
	}
}

// D2：bgp 载体不支持经批量也建单即拒（与单任务一致）。
func TestDryRun_BatchBgpV7Rejected(t *testing.T) {
	r := newDryRunServer(t)
	body := `{"name":"dr-bgp","output_type":"pcap","output_config":{"pcap_path":"/tmp/dr_bgp.pcap"},"batch":{"classes":[{"id":"c1","type":"bgp","flow_count":1,"config":{"layers":[{"ip":{"src":"10.0.0.1","dst":"20.0.0.1"}},{"tcp":{"dst_port":179}},{"bgp":{"version":7}}]}}]}}`
	req := httptest.NewRequest("POST", "/tasks/batch", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 400 || !strings.Contains(w.Body.String(), "[4,4]") {
		t.Fatalf("batch bgp v7 = %d %s, want 400 + [4,4]", w.Code, w.Body.String())
	}
}

// D3：合法策略建单不受 dry-run 影响（零回归守卫）。
func TestDryRun_LegalStrategyPasses(t *testing.T) {
	r := newDryRunServer(t)
	body := `{"name":"dr-ok","mode":"synth","protocol":"udp","config":{"layers":[{"ip":{"src":"10.0.0.1","dst":"20.0.0.1"}},{"udp":{"dst_port":5353}}]}}`
	req := httptest.NewRequest("POST", "/strategies", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 201 {
		t.Fatalf("legal strategy = %d %s, want 201", w.Code, w.Body.String())
	}
}
