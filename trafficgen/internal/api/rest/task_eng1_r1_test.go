package rest

// T-ENG-1 R1(rev-d1 补丁复审发现的低危尾巴,failing-first):
// dual 分支 writer2(.s2c)创建失败时,主 writer.Close() 若恰为末次 Release
// (adapter.final=true),sharedPCAPs 主路径残留死句柄;同路径后续 ct 缓存命中
// 拿到已关 writer → 注册后全部写失败 → 任务失败。修前行为:后续 ct 自开新 fd
// 正常工作——补丁在错误分支引入了比修前更差的回归。
//
// 桩法:newSharedPCAPWriterFn 缝(同 newInterfaceWriterFn 惯例)只放第一次
// ".s2c" 打开失败——真实文件系统没法只让 ct1 的 .s2c 失败(路径共享,
// ct2 的 .s2c 会同样失败,任务双双失败,分不出红绿)。
//
// 先红:ct1: 主路径开(入表)→ .s2c 失败 → Close=末次 Release(final)→
//   [红] 死句柄留表 → ct2 openShared 缓存命中已关 adapter → 注册 → 写全败
//   → 任务 failed。
// 修后:final 逐出(与影子分支对称)→ ct2 自开新 fd → 任务 completed,
//   主 pcap 恰含 ct2 的包数,.s2c 为 24B 空头(UDP 合成流全 c2s)。
//
// 运行:go test ./internal/api/rest/ -run TestENG1_R1 -v(-race 建议同跑)

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	"github.com/trafficgen/trafficgen/internal/output"
	"github.com/trafficgen/trafficgen/internal/protocol/udp"
	"github.com/trafficgen/trafficgen/internal/storage"
)

func TestENG1_R1_DualFailBranch_EvictsFinalSharedPcap(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := newRESTTestDB(t)
	sidA, sidB := seedTwoUDPStrategies(t, db, "u1") // A=3 流, B=2 流

	e := core.NewEngine(core.EngineConfig{ConfigWorkers: 1, PacketWorkers: 1, OutputWorkers: 1,
		BufferSize: 256, QueueSize: 64})
	e.RegisterPlanner(udp.NewPlanner())
	e.SetBuildFunc(core.NewBuilder().Build)
	e.SetLayerPlannerFactory(layers.BuildLayersPlanner)
	if err := e.Start(); err != nil {
		t.Fatalf("engine: %v", err)
	}
	defer e.Stop()

	// 桩:仅第一次 ".s2c" 打开失败(ct1 的),之后放行(ct2 的必须成功,
	// 否则 ct2 也进 writerErrors,注册表死活无从区分)。
	var s2cOpens int32
	oldOpen := newSharedPCAPWriterFn
	newSharedPCAPWriterFn = func(path string, maxBytes int64) (*output.SharedPCAPWriter, error) {
		if strings.HasSuffix(path, ".s2c") && atomic.AddInt32(&s2cOpens, 1) == 1 {
			return nil, errors.New("stub: first s2c open fails (R1 staging)")
		}
		return output.NewSharedPCAPWriter(path, maxBytes)
	}
	t.Cleanup(func() { newSharedPCAPWriterFn = oldOpen })

	sids, _ := json.Marshal([]string{sidA, sidB})
	dir := t.TempDir()
	pcapPath := filepath.Join(dir, "r1.pcap")
	out, _ := json.Marshal(map[string]string{"pcap_path": pcapPath, "interface2": "ethX"})
	task := &storage.TaskModel{
		ID: "bbbbbbbb-2222-2222-2222-222222222222", UserID: "u1", Name: "r1",
		StrategyIDs: string(sids), Protocol: "udp",
		OutputType: "pcap", OutputConfig: string(out), Status: "pending",
	}
	if err := db.Create(task).Error; err != nil {
		t.Fatalf("seed task: %v", err)
	}

	h := NewTaskHandler(db, e, nil)
	r := gin.New()
	r.Use(func(c *gin.Context) { c.Set("userID", "u1"); c.Next() })
	r.POST("/tasks/:id/start", h.Start)
	req := httptest.NewRequest("POST", "/tasks/"+task.ID+"/start", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("start status = %d body=%s", w.Code, w.Body.String())
	}

	// 等终态。红态预期:ct2 拿死句柄,写败 → failed;绿态:completed。
	var stored storage.TaskModel
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if err := db.Where("id = ?", task.ID).First(&stored).Error; err != nil {
			t.Fatalf("reload: %v", err)
		}
		if stored.Status == "completed" || stored.Status == "failed" || stored.Status == "error" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if stored.Status != "completed" {
		t.Fatalf("task status = %s err=%q (red symptom: ct2 cached the closed writer after ct1's final Release)", stored.Status, stored.ErrorMessage)
	}

	// 绿态对账:ct1 的 writer 被 writerErrors 跳过(不提交),ct2 正常写
	// 2 包;ct1 的死 Close 截不掉 ct2 的新 fd(共享写入器修后语义)。
	if got := stored.PacketsSent; got != 2 {
		t.Errorf("PacketsSent = %d, want 2 (only strategy B's engine task is submitted)", got)
	}
	n, torn := countPCAPRecords(t, pcapPath)
	if torn {
		t.Errorf("main pcap has torn tail")
	}
	if n != 2 {
		t.Errorf("main pcap records = %d, want 2 (strategy B flows; got torn=%v)", n, torn)
	}
	// ct1 的 .s2c 失败后,ct2 的 .s2c 成功创建(UDP 合成流无 s2c 包 → 空头)。
	fi, err := os.Stat(pcapPath + ".s2c")
	if err != nil {
		t.Fatalf("ct2 .s2c missing: %v", err)
	}
	if fi.Size() < 24 {
		t.Errorf(".s2c size = %d, want >= 24 (pcap header)", fi.Size())
	}
}
