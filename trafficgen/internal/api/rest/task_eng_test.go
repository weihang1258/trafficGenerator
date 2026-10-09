package rest

// T-ENG-1 (D-ENG-1): 多策略任务共享输出 pcap 写入器。
// 先红断言(T-ENG-1a):多策略 pcap 任务完成后,产物记录总数必须等于
// Σ各策略实发包数,且逐记录完整。预修树(每策略各自 os.Create 同一路径)
// 下,第二个 fd 截断第一个的产物 → 记录总数 < Σ → 本测试红。
// 修后(共享写入器+引用计数)→ 绿。

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	"github.com/trafficgen/trafficgen/internal/protocol/udp"
	"github.com/trafficgen/trafficgen/internal/storage"
)

// countPCAPRecords 数 pcap 文件里的完整记录数;遇残记录(头/体越界)返回
// 已数出的完整数并标记残尾。
func countPCAPRecords(t *testing.T, path string) (n int, tornTail bool) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if len(raw) < 24 {
		return 0, true
	}
	off := 24
	for off+16 <= len(raw) {
		caplen := int(binary.LittleEndian.Uint32(raw[off+8 : off+12]))
		if caplen < 0 || off+16+caplen > len(raw) {
			return n, true // 残记录:头在体不在
		}
		n++
		off += 16 + caplen
	}
	if off != len(raw) {
		return n, true
	}
	return n, false
}

func seedTwoUDPStrategies(t *testing.T, db *storage.DB, userID string) (sidA, sidB string) {
	t.Helper()
	mk := func(id, name string, flowCount int) *storage.StrategyModel {
		// 层链唯一真相(§1):地址住 ip 层、端口住 udp 层;flows 走 flow_control。
		cfg, _ := json.Marshal(map[string]interface{}{
			"layers": []interface{}{
				map[string]interface{}{"ip": map[string]interface{}{"src": "10.0.0.1", "dst": "10.0.0.2"}},
				map[string]interface{}{"udp": map[string]interface{}{"dst_port": 53}},
			},
		})
		fc, _ := json.Marshal(map[string]interface{}{"type": "flows", "value": flowCount})
		return &storage.StrategyModel{ID: id, UserID: userID, Name: name,
			Mode: "synth", Protocol: "udp", Config: string(cfg), FlowControl: string(fc)}
	}
	a, b := mk("11111111-1111-1111-1111-111111111111", "A3flows", 3), mk("22222222-2222-2222-2222-222222222222", "B2flows", 2)
	for _, s := range []*storage.StrategyModel{a, b} {
		if err := db.Create(s).Error; err != nil {
			t.Fatalf("seed strategy: %v", err)
		}
	}
	return a.ID, b.ID
}

// T-ENG-1a/b:多策略 pcap 产物记录总数 = Σ各策略实发包数,零残记录。
func TestENG1_MultiStrategyPcap_RecordTotal(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := newRESTTestDB(t)
	sidA, sidB := seedTwoUDPStrategies(t, db, "u1")

	e := core.NewEngine(core.EngineConfig{ConfigWorkers: 1, PacketWorkers: 1, OutputWorkers: 1,
		BufferSize: 256, QueueSize: 64})
	e.RegisterPlanner(udp.NewPlanner())
	e.SetBuildFunc(core.NewBuilder().Build)
	e.SetLayerPlannerFactory(layers.BuildLayersPlanner)
	if err := e.Start(); err != nil {
		t.Fatalf("engine: %v", err)
	}
	defer e.Stop()

	sids, _ := json.Marshal([]string{sidA, sidB})
	pcapPath := filepath.Join(t.TempDir(), "multi.pcap")
	out, _ := json.Marshal(map[string]string{"pcap_path": pcapPath})
	task := &storage.TaskModel{
		ID: "aaaaaaaa-1111-1111-1111-111111111111", UserID: "u1", Name: "multi",
		StrategyIDs: string(sids), Protocol: "udp",
		OutputType: "pcap", OutputConfig: string(out), Status: "pending",
	}
	if err := db.Create(task).Error; err != nil {
		t.Fatalf("seed task: %v", err)
	}

	// 带回调构造:完成回调必须接线,否则任务永不完结(试错教训)。
	h := NewTaskHandler(db, e, nil)
	h.SetPcapHandler(NewPcapHandler(db, ""))
	r := gin.New()
	r.Use(func(c *gin.Context) { c.Set("userID", "u1"); c.Next() })
	r.POST("/tasks/:id/start", h.Start)
	req := httptest.NewRequest("POST", "/tasks/aaaaaaaa-1111-1111-1111-111111111111/start", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("start: status = %d body=%s", w.Code, w.Body.String())
	}

	deadline := time.Now().Add(10 * time.Second)
	var tm storage.TaskModel
	for time.Now().Before(deadline) {
		db.First(&tm, "id = ?", "aaaaaaaa-1111-1111-1111-111111111111")
		if tm.Status == "completed" || tm.Status == "failed" || tm.Status == "error" {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if tm.Status != "completed" {
		var dump []string
		for _, sid := range []string{sidA, sidB} {
			eid := "aaaaaaaa-1111-1111-1111-111111111111-" + sid
			if st, err := e.GetTaskStatus(eid); err == nil {
				dump = append(dump, fmt.Sprintf("%s: status=%s progress=%.1f sent=%d", eid, st.Status, st.Progress, st.Stats.PacketsSent))
			} else {
				dump = append(dump, eid+": gone")
			}
		}
		t.Fatalf("status = %s err=%q, want completed; engine=[%s]", tm.Status, tm.ErrorMessage, strings.Join(dump, " | "))
	}

	records, torn := countPCAPRecords(t, pcapPath)
	t.Logf("records=%d torn=%v PacketsSent=%d (PacketsSent 是'最后完成者'口径,不作 Σ 依据)", records, torn, tm.PacketsSent)
	if torn {
		t.Errorf("pcap has torn tail (interleaved multi-fd writes)")
	}
	// 设计口径:记录总数 = Σ各策略计划发包数(UDP 每流 1 包:3+2=5)。
	// 预修树:第二个 fd os.Create 截断首产物 → 记录数 < 5 → 红。
	if records != 5 {
		t.Errorf("record total = %d, want 5 (3+2 两策略之和) — 预修树预期红,修后应相等", records)
	}
}
