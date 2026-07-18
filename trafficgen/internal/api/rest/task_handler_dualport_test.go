package rest

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	sqlite "github.com/glebarez/sqlite"
	"github.com/gin-gonic/gin"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/pcapparser"
	"github.com/trafficgen/trafficgen/internal/replay"
	"github.com/trafficgen/trafficgen/internal/storage"
	"gorm.io/gorm"
)

// setupBidirAssetForHTTP builds a bidirectional TCP pcap (SYN c2s + SYN-ACK s2c),
// parses it, stores the asset, and returns the replay planner + asset ID.
// Mirrors replay.setupBidirAsset but lives in the rest package so task-handler
// tests can construct dual-port replay scenarios end-to-end.
func setupBidirAssetForHTTP(t *testing.T, db *storage.DB) (*replay.ReplayPlanner, string) {
	t.Helper()
	macA, _ := net.ParseMAC("aa:aa:aa:aa:aa:aa")
	macB, _ := net.ParseMAC("bb:bb:bb:bb:bb:bb")
	ipA := net.ParseIP("10.0.0.1")
	ipB := net.ParseIP("10.0.0.2")
	build := func(srcIP, dstIP net.IP, srcPort, dstPort layers.TCPPort, seq uint32, flags uint8) []byte {
		buf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
		tcp := &layers.TCP{SrcPort: srcPort, DstPort: dstPort, Seq: seq, Window: 65535,
			SYN: flags&2 != 0, ACK: flags&16 != 0}
		ipv4 := &layers.IPv4{SrcIP: srcIP, DstIP: dstIP, Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP}
		tcp.SetNetworkLayerForChecksum(ipv4)
		gopacket.SerializeLayers(buf, opts,
			&layers.Ethernet{SrcMAC: macA, DstMAC: macB, EthernetType: layers.EthernetTypeIPv4}, ipv4, tcp)
		return buf.Bytes()
	}
	frames := [][]byte{
		build(ipA, ipB, 1234, 80, 100, 2),  // SYN c2s
		build(ipB, ipA, 80, 1234, 200, 18), // SYN-ACK s2c
	}
	pcapPath := filepath.Join(t.TempDir(), "bidir.pcap")
	f, err := os.Create(pcapPath)
	if err != nil {
		t.Fatalf("create pcap: %v", err)
	}
	w := pcapgo.NewWriter(f)
	w.WriteFileHeader(65535, layers.LinkTypeEthernet)
	for i, fr := range frames {
		ci := gopacket.CaptureInfo{Timestamp: time.UnixMicro(int64(1000 + i*1000)), CaptureLength: len(fr), Length: len(fr)}
		w.WritePacket(ci, fr)
	}
	f.Close()

	repo := storage.NewPcapRepository(db)
	repo.CreateAsset(&storage.PcapAssetModel{ID: "astB", UserID: "u1", Name: "bidir.pcap", StoragePath: pcapPath, Status: "ready", LinkType: 1})
	analysis, err := pcapparser.Parse(pcapPath, &pcapparser.Options{PcapAssetID: "astB", UserID: "u1"})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	repo.CreateFlows(analysis.Flows)
	repo.CreatePackets(analysis.Packets)
	return replay.NewReplayPlanner(db), "astB"
}

// setupReplayStrategyForStart inserts a replay strategy with direction=dual
// into the DB and returns its ID. Used by dual-port Start tests.
func setupReplayStrategyForStart(t *testing.T, db *storage.DB, userID, assetID string) string {
	t.Helper()
	cfg := map[string]interface{}{
		"pcap_asset_id": assetID,
		"direction":     "dual",
		"speed":          map[string]interface{}{"mode": ""},
	}
	cfgJSON, _ := json.Marshal(cfg)
	s := &storage.StrategyModel{
		ID:       "st-" + assetID,
		UserID:   userID,
		Name:     "dual-replay",
		Mode:     "replay",
		Protocol: "batch",
		Config:   string(cfgJSON),
	}
	if err := db.Create(s).Error; err != nil {
		t.Fatalf("create strategy: %v", err)
	}
	return s.ID
}

// setupReplayTaskForStart inserts a pending task referencing the given strategy
// and dual-port output config (port_group). Returns the task ID.
func setupReplayTaskForStart(t *testing.T, db *storage.DB, userID, strategyID, iface1, iface2 string) string {
	t.Helper()
	sids := []string{strategyID}
	sidsJSON, _ := json.Marshal(sids)
	out := OutputConfigRequest{Interface2: iface2}
	outJSON, _ := json.Marshal(out)
	task := &storage.TaskModel{
		ID:           "tk-" + strategyID,
		UserID:       userID,
		Name:         "dual-port task",
		StrategyIDs:  string(sidsJSON),
		Protocol:     "batch",
		OutputType:   "interface",
		OutputConfig: string(outJSON),
		Status:       "pending",
	}
	if err := db.Create(task).Error; err != nil {
		t.Fatalf("create task: %v", err)
	}
	return task.ID
}

// setupReplayTaskForStartPcap inserts a pending task with pcap output and no
// interface2 (dual-port detection comes from the strategy's direction=dual,
// which the Start fix detects and creates a "{path}.s2c" writer for).
func setupReplayTaskForStartPcap(t *testing.T, db *storage.DB, userID, strategyID, pcapPath string) string {
	t.Helper()
	sids := []string{strategyID}
	sidsJSON, _ := json.Marshal(sids)
	out := OutputConfigRequest{PcapPath: pcapPath}
	outJSON, _ := json.Marshal(out)
	task := &storage.TaskModel{
		ID:           "tk-" + strategyID,
		UserID:       userID,
		Name:         "dual-port pcap task",
		StrategyIDs:  string(sidsJSON),
		Protocol:     "batch",
		OutputType:   "pcap",
		OutputConfig: string(outJSON),
		Status:       "pending",
	}
	if err := db.Create(task).Error; err != nil {
		t.Fatalf("create task: %v", err)
	}
	return task.ID
}

// TestStart_DualPortReplay_RegistersDualWriter verifies that Start, when given
// a replay strategy with direction=dual and an interface2 in output_config,
// calls engine.RegisterDualWriter so c2s/s2c packets route to separate writers.
//
// Before the fix, Start only called RegisterOutputWriter — the second interface
// was silently ignored. This test must FAIL until the fix lands.
func TestStart_DualPortReplay_RegistersDualWriter(t *testing.T) {
	gin.SetMode(gin.TestMode)

	gormDB, err := gorm.Open(sqlite.Open(t.TempDir()+"/test.db"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := storage.AutoMigrate(gormDB); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	db := &storage.DB{DB: gormDB}

	planner, assetID := setupBidirAssetForHTTP(t, db)

	e := core.NewEngine(core.EngineConfig{
		ConfigWorkers: 1, PacketWorkers: 1, OutputWorkers: 1,
		BufferSize: 256, QueueSize: 64,
	})
	e.SetReplayPlanner(planner)
	e.SetBuildFunc(replay.NewBuildFunc(core.NewBuilder().Build))
	if err := e.Start(); err != nil {
		t.Fatalf("start engine: %v", err)
	}
	defer e.Stop()

	h := NewTaskHandler(db, e, nil)
	r := gin.New()
	r.Use(func(c *gin.Context) { c.Set("userID", "u1"); c.Next() })
	r.POST("/tasks/:id/start", h.Start)

	userID := "u1"
	sid := setupReplayStrategyForStart(t, db, userID, assetID)
	// Use pcap output to avoid requiring real network interfaces. Dual-port
	// pcap writes s2c to "{path}.s2c".
	taskID := setupReplayTaskForStartPcap(t, db, userID, sid, t.TempDir()+"/c2s.pcap")

	req := httptest.NewRequest("POST", "/tasks/"+taskID+"/start", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}

	// Engine task ID for strategy-backed tasks is "{taskID}-{strategyID}".
	engineTaskID := taskID + "-" + sid
	dw := e.GetDualWriter(engineTaskID)
	if dw == nil {
		t.Fatalf("GetDualWriter(%q) = nil, want non-nil dual-writer (Start must call RegisterDualWriter for direction=dual)", engineTaskID)
	}
	if dw.C2S == nil {
		t.Errorf("dual-writer C2S is nil")
	}
	if dw.S2C == nil {
		t.Errorf("dual-writer S2C is nil")
	}

	_ = e.StopTask(engineTaskID)
}

// TestStop_DualPortReplay_UnregistersDualWriter verifies that Stop calls
// engine.UnregisterDualWriter for dual-port tasks, so the writers are closed
// and removed from the map.
//
// Before the fix, Stop only called UnregisterOutputWriter — the dual-writer
// (and its second interface's writer) leaked.
func TestStop_DualPortReplay_UnregistersDualWriter(t *testing.T) {
	gin.SetMode(gin.TestMode)

	gormDB, err := gorm.Open(sqlite.Open(t.TempDir()+"/test.db"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := storage.AutoMigrate(gormDB); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	db := &storage.DB{DB: gormDB}

	planner, assetID := setupBidirAssetForHTTP(t, db)

	e := core.NewEngine(core.EngineConfig{
		ConfigWorkers: 1, PacketWorkers: 1, OutputWorkers: 1,
		BufferSize: 256, QueueSize: 64,
	})
	e.SetReplayPlanner(planner)
	e.SetBuildFunc(replay.NewBuildFunc(core.NewBuilder().Build))
	if err := e.Start(); err != nil {
		t.Fatalf("start engine: %v", err)
	}
	defer e.Stop()

	h := NewTaskHandler(db, e, nil)
	r := gin.New()
	r.Use(func(c *gin.Context) { c.Set("userID", "u1"); c.Next() })
	r.POST("/tasks/:id/start", h.Start)
	r.POST("/tasks/:id/stop", h.Stop)

	userID := "u1"
	sid := setupReplayStrategyForStart(t, db, userID, assetID)
	taskID := setupReplayTaskForStartPcap(t, db, userID, sid, t.TempDir()+"/c2s.pcap")

	// Start the task first to register the dual-writer.
	req := httptest.NewRequest("POST", "/tasks/"+taskID+"/start", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("start: status = %d, body = %s", w.Code, w.Body.String())
	}

	engineTaskID := taskID + "-" + sid
	if dw := e.GetDualWriter(engineTaskID); dw == nil {
		t.Fatalf("precondition: dual-writer not registered after Start")
	}

	// Stop the task and verify the dual-writer is cleaned up.
	req2 := httptest.NewRequest("POST", "/tasks/"+taskID+"/stop", strings.NewReader(""))
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)
	if w2.Code != http.StatusOK {
		t.Fatalf("stop: status = %d, body = %s", w2.Code, w2.Body.String())
	}

	// Best-effort wait for Stop to propagate; UnregisterDualWriter is called
	// synchronously inside Stop, so should already be gone.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if e.GetDualWriter(engineTaskID) == nil {
			return // pass
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("GetDualWriter(%q) still non-nil after Stop; Stop must call UnregisterDualWriter", engineTaskID)
}
