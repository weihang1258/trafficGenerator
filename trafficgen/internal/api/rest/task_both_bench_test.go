package rest

// T-ENG-3 (D-ENG-3): both 吞吐基准——量化影子写串行成本并产出定门槛数据。
//
// 运行(需 root,同实发验收前置):
//
//	sudo -n env NIC_BENCH=1 HOME=/home/weihang \
//	  PATH=/usr/sbin:$PATH go test ./internal/api/rest/ -run TestBENCH_BothThroughput -v -timeout 0
//
// 设计依据:docs/CODE_DESIGN.md D-ENG-3。
//   - 三组:①纯接口写基线 ②both(1GB 帽,恒帽内) ③both(4MB 小帽,跑中触发截断)。
//   - 测量纪律:pps 用写侧计数(任务 PacketsSent/耗时;batch 单 engine task
//     无聚合 quirk),测量窗口内不挂全程 tcpdump;内容校验=短窗抽样(300ms),
//     失败标缺考(content_ok=false),不阻断 pps。
//   - 相位拆分口径:帽内相位 pps≈组②,帽后相位(截断后影子直通)pps≈组①,
//     组③全程 pps 应落在①②之间——用三组外推,不做运行中 flip 轮询
//     (Truncated() 仅在 Close 后可证,无运行中探针面)。
//   - 门槛:待确认——本测试只产数据;D-ENG-3 完成前置=门槛行已填+两路验收。

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/pcaptest"
	"github.com/trafficgen/trafficgen/internal/protocol/udp"
	"github.com/trafficgen/trafficgen/internal/storage"
)

const (
	benchNIC   = "enp135s0f0np0"
	benchFlows = 300000 // 每跑 UDP 流数(每流 1 包);~76B/记录 → 组②影子 ≈23MB,恒在 1GB 帽内
	benchRuns  = 3
)

type benchResult struct {
	pps        float64
	sent       int64
	elapsed    time.Duration
	shadowRecs int    // -1 = 无影子(iface 组)
	torn       bool   // 影子尾记录撕裂(D-ENG-1 对账面)
	truncated  bool   // shadow_note 报告帽截断
	note       string // shadow_note 原文
	txDrop     int64  // tx_dropped 前后差
	rssKB      int64
	heapMB     float64
	contentOK  bool // 短窗抽样有帧;false=缺考(不阻断 pps)
}

func readTxDropped(t *testing.T) int64 {
	t.Helper()
	b, err := os.ReadFile("/sys/class/net/" + benchNIC + "/statistics/tx_dropped")
	if err != nil {
		return -1
	}
	v, _ := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	return v
}

func readRSSKB(t *testing.T) int64 {
	t.Helper()
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return -1
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "VmRSS:") {
			// "VmRSS:    1234 kB" → fields[1] 纯数字(直接 ParseInt 会栽在 " kB")。
			if f := strings.Fields(line); len(f) >= 2 {
				kb, _ := strconv.ParseInt(f[1], 10, 64)
				return kb
			}
		}
	}
	return -1
}

// runBenchOne 跑一轮指定模式,返回测量结果。mode: "iface" | "both"。
// shadowCap 仅 both 生效:临时替换 defaultShadowPcapMaxBytes(组③小帽触发截断)。
func runBenchOne(t *testing.T, e *core.Engine, db *storage.DB, mode string, shadowCap int64) benchResult {
	t.Helper()
	dir := t.TempDir()

	h := NewTaskHandler(db, e, nil)
	// 故意不 SetPcapHandler:auto-register 的全量解析(300k 包 ≈ 140s)
	// 会跨跑重叠,把上一跑的解析 CPU/IO 漏进下一跑的 pps——解析不是
	// 本基准的维度,关掉。
	r := gin.New()
	r.Use(func(c *gin.Context) { c.Set("userID", "u1"); c.Next() })
	r.POST("/tasks/batch", h.CreateBatch)

	shadowPath := filepath.Join(dir, "shadow.pcap")
	oc := fmt.Sprintf(`{"port_group_id":"pgBench"}`)
	if mode == "both" {
		oc = fmt.Sprintf(`{"port_group_id":"pgBench","pcap_path":"%s"}`, shadowPath)
	}
	outputType := map[string]string{"iface": "port_group", "both": "both"}[mode]
	body := fmt.Sprintf(`{"name":"bench-%s-%d","batch":{"classes":[{"id":"u","type":"udp","flow_count":%d,"config":{},`+
		`"tuples":{"src_ip":{"strategy":"fixed","value":"10.9.0.1"},"dst_ip":{"strategy":"fixed","value":"10.9.0.2"},`+
		`"src_port":{"strategy":"inc","range":[1024,65000],"step":1},"dst_port":{"strategy":"fixed","value":53}}}]},`+
		`"output_type":"%s","output_config":%s}`, mode, time.Now().UnixNano(), benchFlows, outputType, oc)

	oldCap := defaultShadowPcapMaxBytes
	if mode == "both" {
		defaultShadowPcapMaxBytes = shadowCap
	}
	defer func() { defaultShadowPcapMaxBytes = oldCap }()

	// 内容校验短窗:开跑即抓,300ms 后停(egress 同口;测量纪律=不全程挂)。
	var capCmd *exec.Cmd
	var capPath string
	if mode == "both" {
		capPath = filepath.Join(dir, "sample.pcap")
		if cmd, err := pcaptest.StartCapture(benchNIC, capPath, pcaptest.Case{}); err == nil {
			capCmd = cmd
			time.AfterFunc(300*time.Millisecond, func() { pcaptest.StopCapture(cmd) })
		}
	}

	txDropBefore := readTxDropped(t)
	start := time.Now()

	req := httptest.NewRequest("POST", "/tasks/batch", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	var resp struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}

	deadline := time.Now().Add(300 * time.Second)
	var tm storage.TaskModel
	for time.Now().Before(deadline) {
		if err := db.Where("id = ?", resp.Data.ID).First(&tm).Error; err != nil {
			t.Fatalf("reload task: %v", err)
		}
		if tm.Status == "completed" || tm.Status == "failed" || tm.Status == "error" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	elapsed := time.Since(start)
	if capCmd != nil {
		pcaptest.StopCapture(capCmd) // 幂等停,兜底 300ms 定时器未触发的情形
	}
	if tm.Status != "completed" {
		t.Fatalf("bench task status = %s err=%q", tm.Status, tm.ErrorMessage)
	}

	res := benchResult{
		sent:       tm.PacketsSent,
		elapsed:    elapsed,
		pps:        float64(tm.PacketsSent) / elapsed.Seconds(),
		txDrop:     readTxDropped(t) - txDropBefore,
		rssKB:      readRSSKB(t),
		shadowRecs: -1,
		note:       tm.ShadowNote,
	}
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	res.heapMB = float64(ms.HeapAlloc) / (1 << 20)

	if mode == "both" {
		// 完成状态翻转 ≠ 写侧排水完成(t11 已登记的引擎行为):立刻对账会把
		// 排水中的半条记录误判成 torn、少算尾部记录。等记录数连续两次相等
		// 再对账;note 在 Close 才落库,同样重读一次任务行。
		prev := -1
		sdeadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(sdeadline) {
			n, _ := countPCAPRecords(t, shadowPath)
			if n == prev && n > 0 {
				break
			}
			prev = n
			time.Sleep(100 * time.Millisecond)
		}
		db.Where("id = ?", resp.Data.ID).First(&tm)

		n, torn := countPCAPRecords(t, shadowPath)
		res.shadowRecs, res.torn = n, torn
		res.truncated = strings.Contains(tm.ShadowNote, "was truncated")
	}
	if capPath != "" {
		if fi, err := os.Stat(capPath); err == nil && fi.Size() > 24 {
			res.contentOK = true
		}
	}
	return res
}

func TestBENCH_BothThroughput(t *testing.T) {
	if os.Getenv("NIC_BENCH") != "1" {
		t.Skip("NIC_BENCH=1 required (real NIC + root)")
	}
	if _, err := os.Stat("/sys/class/net/" + benchNIC); err != nil {
		t.Skipf("NIC %s not present", benchNIC)
	}

	gin.SetMode(gin.TestMode)
	db := newRESTTestDB(t)
	setupPortGroupRow(t, db, "pgBench", benchNIC) // 一次,共享 DB;逐跑重插会撞主键

	e := core.NewEngine(core.EngineConfig{
		ConfigWorkers: 2, PacketWorkers: 1, OutputWorkers: 1,
		BufferSize: 4096, QueueSize: 4096,
	})
	e.RegisterPlanner(udp.NewPlanner())
	e.SetBuildFunc(core.NewBuilder().Build)
	if err := e.Start(); err != nil {
		t.Fatalf("engine: %v", err)
	}
	defer e.Stop()

	report := []string{"group,run,pps,sent,elapsed_ms,shadow_recs,torn,truncated,tx_drop_delta,rss_kb,heap_mb,content_ok"}

	// 预热一轮(不计入):页缓存/AF_PACKET 路径热身。
	runBenchOne(t, e, db, "iface", 0)

	for _, g := range []struct {
		name string
		mode string
		cap  int64
	}{
		{"1-iface-baseline", "iface", 0},
		{"2-both-incap", "both", 1 << 30},
		{"3-both-smallcap", "both", 4 << 20}, // ≈55k 记录后触发截断,余程影子直通
	} {
		for run := 1; run <= benchRuns; run++ {
			res := runBenchOne(t, e, db, g.mode, g.cap)
			line := fmt.Sprintf("%s,%d,%.0f,%d,%d,%d,%t,%t,%d,%d,%.1f,%t",
				g.name, run, res.pps, res.sent, res.elapsed.Milliseconds(),
				res.shadowRecs, res.torn, res.truncated, res.txDrop, res.rssKB, res.heapMB, res.contentOK)
			report = append(report, line)
			t.Logf("%s", line)
		}
	}

	summary := strings.Join(report, "\n")
	if err := os.WriteFile("/tmp/eng3-bench-results.txt", []byte(summary+"\n"), 0o644); err != nil {
		t.Logf("write summary: %v", err)
	}
	t.Logf("bench summary written to /tmp/eng3-bench-results.txt")
}
