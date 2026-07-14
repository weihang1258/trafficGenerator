package replay

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	sqlite "github.com/glebarez/sqlite"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/pcapparser"
	"github.com/trafficgen/trafficgen/internal/storage"
	"gorm.io/gorm"
)

// setupBidirAsset builds a bidirectional TCP pcap (SYN c2s + SYN-ACK s2c),
// parses it, stores it. Returns the planner + asset ID.
func setupBidirAsset(t *testing.T) (*ReplayPlanner, string) {
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
		build(ipA, ipB, 1234, 80, 100, 2),        // SYN c2s
		build(ipB, ipA, 80, 1234, 200, 18),       // SYN-ACK s2c
	}
	pcapPath := filepath.Join(t.TempDir(), "bidir.pcap")
	f, _ := os.Create(pcapPath)
	w := pcapgo.NewWriter(f)
	w.WriteFileHeader(65535, layers.LinkTypeEthernet)
	for i, fr := range frames {
		ci := gopacket.CaptureInfo{Timestamp: time.UnixMicro(int64(1000 + i*1000)), CaptureLength: len(fr), Length: len(fr)}
		w.WritePacket(ci, fr)
	}
	f.Close()

	gormDB, _ := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "b.db")), &gorm.Config{})
	storage.AutoMigrate(gormDB)
	db := &storage.DB{DB: gormDB}
	repo := storage.NewPcapRepository(db)
	repo.CreateAsset(&storage.PcapAssetModel{ID: "astB", UserID: "u1", Name: "bidir.pcap", StoragePath: pcapPath, Status: "ready", LinkType: 1})
	analysis, err := pcapparser.Parse(pcapPath, &pcapparser.Options{PcapAssetID: "astB", UserID: "u1"})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	repo.CreateFlows(analysis.Flows)
	repo.CreatePackets(analysis.Packets)
	return NewReplayPlanner(db), "astB"
}

// TestReplay_DualPort verifies c2s packets route to the primary writer and s2c
// to the secondary writer (§16.11).
func TestReplay_DualPort(t *testing.T) {
	planner, assetID := setupBidirAsset(t)
	e := core.NewEngine(core.EngineConfig{ConfigWorkers: 1, PacketWorkers: 1, OutputWorkers: 1, BufferSize: 256, QueueSize: 64})
	e.SetBuildFunc(NewBuildFunc(core.NewBuilder().Build))
	e.SetReplayPlanner(planner)
	done := make(chan string, 1)
	e.OnTaskComplete = func(id string) { done <- id }
	e.OnTaskFailed = func(id, msg string) { t.Errorf("task failed: %s", msg); done <- id }
	if err := e.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer e.Stop()

	c2sW := &countingWriter{}
	s2cW := &countingWriter{}
	e.RegisterDualWriter("td", c2sW, s2cW)

	spec, _ := json.Marshal(ReplaySpec{PcapAssetID: assetID, Speed: ReplaySpeed{Mode: "max"}, Direction: "dual"})
	task := core.Task{ID: "td", Name: "dual", UserID: "u1", Protocol: "batch",
		Batch: &core.BatchSpec{Classes: []core.TrafficClass{{ID: "r", Type: "replay", Replay: spec}}}}
	if err := e.SubmitTask(task); err != nil {
		t.Fatalf("submit: %v", err)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("task did not complete")
	}
	// 1 c2s packet (SYN) -> c2sW; 1 s2c packet (SYN-ACK) -> s2cW.
	if len(c2sW.packets) != 1 {
		t.Errorf("c2s writer got %d packets, want 1", len(c2sW.packets))
	}
	if len(s2cW.packets) != 1 {
		t.Errorf("s2c writer got %d packets, want 1", len(s2cW.packets))
	}
}

// countingWriter records packets written (no direction info needed; the
// OutputWorker routes before calling WritePackets).
type countingWriter struct {
	mu      sync.Mutex
	packets [][]byte
}

func (w *countingWriter) WritePackets(p [][]byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.packets = append(w.packets, p...)
	return nil
}
func (w *countingWriter) Close() error { return nil }
