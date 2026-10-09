package rest

// NIC live-fire for output_type=both (真实硬件验收,非单测):
// 引擎把 UDP 帧从 enp135s0f0np0 物理发出(tcpdump 在发包口同侧抓到),
// 同时影子 pcap 落盘→auto-register→流表可查、shadow_note 干净、直链可下载。
// 验收口径 = §6.3 验收两路:wire 路(capture 有帧)与 pcap 路(影子资产出流表)。
//
// 运行(需 root——AF_PACKET 发包 + tcpdump):
//
//	sudo -n env NIC_RUN=1 HOME=/home/weihang \
//	  PATH=/usr/sbin:$PATH go test ./internal/api/rest/ -run TestNIC_BothMode -v
//
// 前置:enp135s0f0np0 up;tcpdump 在 PATH;TSO/GSO off(线上字节=引擎帧,
// 本机已关;MAC 过滤不受 offload 影响,但 checksum 会被硬件改写——本测试
// 只断言 MAC/流表面,不断言线上 checksum)。

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/gopacket/pcapgo"
	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/pcaptest"
	"github.com/trafficgen/trafficgen/internal/protocol/udp"
	"github.com/trafficgen/trafficgen/internal/storage"
)

func TestNIC_BothMode_WireAndShadow(t *testing.T) {
	if os.Getenv("NIC_RUN") != "1" {
		t.Skip("NIC_RUN=1 required (real NIC + root)")
	}
	const nicIf = "enp135s0f0np0"
	if _, err := os.Stat("/sys/class/net/" + nicIf); err != nil {
		t.Skipf("NIC %s not present: %v", nicIf, err)
	}

	gin.SetMode(gin.TestMode)
	db := newRESTTestDB(t)
	setupPortGroupRow(t, db, "pgNIC", nicIf)

	e := core.NewEngine(core.EngineConfig{
		ConfigWorkers: 2, PacketWorkers: 1, OutputWorkers: 1,
		BufferSize: 256, QueueSize: 64,
	})
	e.RegisterPlanner(udp.NewPlanner())
	e.SetBuildFunc(core.NewBuilder().Build)
	if err := e.Start(); err != nil {
		t.Fatalf("engine: %v", err)
	}
	defer e.Stop()

	// Wire 路:tcpdump 在发包口抓默认双 src MAC(引擎帧默认值)。
	dir := t.TempDir()
	capPath := filepath.Join(dir, "wire.pcap")
	capCmd, err := pcaptest.StartCapture(nicIf, capPath, pcaptest.Case{})
	if err != nil {
		t.Fatalf("capture: %v", err)
	}
	stopped := false
	stop := func() {
		if !stopped {
			stopped = true
			pcaptest.StopCapture(capCmd)
		}
	}
	defer stop()

	// captureWait=2s 只是下限(实测 1.5s 才开始写盘);刚跑完全量套件的
	// 机器上边际不够(4 received / 0 captured 假阴性)。再垫 3s。
	time.Sleep(3 * time.Second)

	// both 路:网卡主路 + 影子 pcap。影子路径显式给(缺省生成路径已被
	// 单测钉死,这里钉显式路径形态)。
	shadowPath := filepath.Join(dir, "shadow.pcap")
	h := NewTaskHandler(db, e, nil)
	// 生产由 REST server 接线;不接则 maybeAutoRegisterPcap 静默早退,
	// 影子永不注册——验收必须走与生产相同的接线。
	h.SetPcapHandler(NewPcapHandler(db, ""))
	r := gin.New()
	r.Use(func(c *gin.Context) { c.Set("userID", "u1"); c.Next() })
	r.POST("/tasks/batch", h.CreateBatch)
	body := `{"name":"both-nic-livefire","batch":{"classes":[{"id":"u","type":"udp","flow_count":4,"config":{},` +
		`"tuples":{"src_ip":{"strategy":"fixed","value":"10.0.0.1"},"dst_ip":{"strategy":"fixed","value":"10.0.0.2"},` +
		`"src_port":{"strategy":"fixed","value":2000},"dst_port":{"strategy":"fixed","value":53}}}]},` +
		`"output_type":"both","output_config":{"port_group_id":"pgNIC","pcap_path":"` + shadowPath + `"}}`
	req := httptest.NewRequest("POST", "/tasks/batch", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		stop()
		t.Fatalf("create: status = %d body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}

	// 等完成(batch 发包量小,10s 上限)。
	deadline := time.Now().Add(10 * time.Second)
	var tm storage.TaskModel
	for time.Now().Before(deadline) {
		db.First(&tm, "id = ?", resp.Data.ID)
		if tm.Status == "completed" || tm.Status == "failed" || tm.Status == "error" {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	stop()
	if tm.Status != "completed" {
		t.Fatalf("task status = %s err=%q, want completed", tm.Status, tm.ErrorMessage)
	}

	// ---- pcap 路:影子落盘 + 自动注册 + 流表全字段可查 ----
	info, err := os.Stat(shadowPath)
	if err != nil {
		t.Fatalf("shadow pcap missing: %v", err)
	}
	if info.Size() <= 24 {
		t.Errorf("shadow pcap size = %d, want records beyond the header", info.Size())
	}
	if tm.PcapAssetID == "" {
		t.Errorf("shadow not auto-registered (note=%q shadow_note=%q)", tm.PcapAssetNote, tm.ShadowNote)
	}
	if tm.ShadowNote != "" {
		t.Errorf("healthy run carries shadow_note: %q", tm.ShadowNote)
	}
	repo := storage.NewPcapRepository(db)
	flows, _, err := repo.ListFlowsByAsset(tm.PcapAssetID, "u1", 1, 10)
	if err != nil {
		t.Fatalf("list flows: %v", err)
	}
	if len(flows) == 0 {
		t.Fatalf("flow table empty for asset %s", tm.PcapAssetID)
	}
	f0 := flows[0]
	if f0.SrcIP == "" || f0.DstIP == "" || f0.DstPort != 53 || f0.C2SPackets == 0 {
		t.Errorf("flow fields thin: src=%q dst=%q dport=%d c2s=%d — want full 5-tuple + counts",
			f0.SrcIP, f0.DstIP, f0.DstPort, f0.C2SPackets)
	}
	tmResp := convertTaskToResponse(&tm)
	if tmResp.DownloadURL == "" {
		t.Errorf("both response missing download_url")
	}
	if tmResp.PcapAssetID == "" {
		t.Errorf("both response missing pcap_asset_id")
	}

	// ---- wire 路:tcpdump 抓到的帧真实存在,src MAC = 引擎默认 ----
	cf, err := os.Open(capPath)
	if err != nil {
		t.Fatalf("wire capture missing: %v", err)
	}
	defer cf.Close()
	reader, err := pcapgo.NewReader(cf)
	if err != nil {
		t.Fatalf("capture reader: %v", err)
	}
	wireFrames := 0
	macOK := false
	wantMAC := []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	for {
		data, ci, err := reader.ReadPacketData()
		if err != nil {
			break
		}
		if ci.CaptureLength >= 12 {
			wireFrames++
			if string(data[6:12]) == string(wantMAC) {
				macOK = true
			}
		}
	}
	if wireFrames == 0 {
		t.Fatalf("wire capture has 0 frames — packets did not hit the NIC")
	}
	if !macOK {
		t.Errorf("no captured frame carries engine src MAC %s — filter/path mismatch", pcaptest.FrameMAC)
	}
	t.Logf("live-fire OK: wire_frames=%d shadow_bytes=%d flows=%d asset=%s",
		wireFrames, info.Size(), len(flows), tm.PcapAssetID)
}
