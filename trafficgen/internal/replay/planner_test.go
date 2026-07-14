package replay

import (
	"context"
	"net"
	"os"
	"path/filepath"
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

// setupReplayAsset builds a pcap, parses it, and stores the asset + flows +
// packets in a test DB. Returns the planner + asset ID + the original frames.
func setupReplayAsset(t *testing.T) (*ReplayPlanner, *storage.DB, string, [][]byte) {
	t.Helper()
	macA, _ := net.ParseMAC("aa:aa:aa:aa:aa:aa")
	macB, _ := net.ParseMAC("bb:bb:bb:bb:bb:bb")
	ipA := net.ParseIP("10.0.0.1")
	ipB := net.ParseIP("10.0.0.2")
	build := func(seq uint32, flags uint8, payload []byte) []byte {
		buf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
		tcp := &layers.TCP{SrcPort: 1234, DstPort: 80, Seq: seq, Window: 65535,
			SYN: flags&2 != 0, ACK: flags&16 != 0, FIN: flags&1 != 0, PSH: flags&8 != 0}
		ipv4 := &layers.IPv4{SrcIP: ipA, DstIP: ipB, Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP}
		tcp.SetNetworkLayerForChecksum(ipv4)
		gopacket.SerializeLayers(buf, opts,
			&layers.Ethernet{SrcMAC: macA, DstMAC: macB, EthernetType: layers.EthernetTypeIPv4},
			ipv4, tcp, gopacket.Payload(payload))
		return buf.Bytes()
	}
	frames := [][]byte{
		build(100, 2, nil),                       // SYN
		build(101, 24, []byte("hello world")),    // PSH+ACK data
		build(112, 17, nil),                      // FIN+ACK
	}
	pcapPath := filepath.Join(t.TempDir(), "replay.pcap")
	f, _ := os.Create(pcapPath)
	w := pcapgo.NewWriter(f)
	w.WriteFileHeader(65535, layers.LinkTypeEthernet)
	for i, fr := range frames {
		ci := gopacket.CaptureInfo{Timestamp: time.UnixMicro(int64(1000 + i*1000)), CaptureLength: len(fr), Length: len(fr)}
		w.WritePacket(ci, fr)
	}
	f.Close()

	// Parse + store.
	gormDB, _ := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "r.db")), &gorm.Config{})
	storage.AutoMigrate(gormDB)
	db := &storage.DB{DB: gormDB}
	repo := storage.NewPcapRepository(db)
	asset := &storage.PcapAssetModel{ID: "ast1", UserID: "u1", Name: "replay.pcap", StoragePath: pcapPath, Status: "ready", LinkType: 1}
	repo.CreateAsset(asset)
	analysis, err := pcapparser.Parse(pcapPath, &pcapparser.Options{PcapAssetID: "ast1", UserID: "u1"})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	repo.CreateFlows(analysis.Flows)
	repo.CreatePackets(analysis.Packets)
	asset.PacketCount = analysis.PacketCount
	asset.FlowCount = analysis.FlowCount
	repo.UpdateAsset(asset)

	return NewReplayPlanner(db), db, "ast1", frames
}

// TestPlanner_Plan_IPMap verifies the planner emits PacketConfigs with the raw
// bytes + ipmap patches, and applying the patches rewrites the IP.
func TestPlanner_Plan_IPMap(t *testing.T) {
	planner, _, assetID, frames := setupReplayAsset(t)
	spec := ReplaySpec{
		PcapAssetID: assetID,
		Speed:       ReplaySpeed{Mode: "max"},
		Direction:   "single",
		ChecksumMode: "recompute",
		Rewrites: []RewriteRule{{
			Kind: "ipmap", Mapping: map[string]string{"10.0.0.1": "11.0.0.1"},
		}},
	}
	ch, err := planner.Plan(context.Background(), spec, "task1", "cls1", "u1")
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var configs []core.PacketConfig
	for cfg := range ch {
		configs = append(configs, cfg)
	}
	if len(configs) != 3 {
		t.Fatalf("configs = %d, want 3", len(configs))
	}
	// Verify each config has the replay metadata + a src_ip patch.
	for i, cfg := range configs {
		if cfg.Metadata["_replay"] != true {
			t.Errorf("config %d: _replay not set", i)
		}
		raw, _ := cfg.Metadata["_raw"].([]byte)
		if len(raw) == 0 {
			t.Errorf("config %d: _raw empty", i)
		}
		patches, _ := cfg.Metadata["_patches"].([]Patch)
		// At least one patch touches src_ip (offset = layout.SrcIP).
		found := false
		for _, p := range patches {
			if p.Field == "src_ip" {
				want := net.ParseIP("11.0.0.1").To4()
				if string(p.Bytes) == string(want) {
					found = true
				}
			}
		}
		if !found {
			t.Errorf("config %d: no src_ip=11.0.0.1 patch in %+v", i, patches)
		}
		// Apply patches and verify the IP changed.
		layout := cfg.Metadata["_layout"].(pcapparser.OffsetLayout)
		out, err := ApplyPatches(raw, patches, layout, "recompute")
		if err != nil {
			t.Fatalf("config %d: ApplyPatches: %v", i, err)
		}
		gotIP := net.IP(out[layout.SrcIP : layout.SrcIP+4])
		if !gotIP.Equal(net.ParseIP("11.0.0.1")) {
			t.Errorf("config %d: patched src_ip = %v, want 11.0.0.1", i, gotIP)
		}
	}
	_ = frames
}

// TestPlanner_Plan_AssetNotReady verifies a non-ready asset is rejected.
func TestPlanner_Plan_AssetNotReady(t *testing.T) {
	planner, db, _, _ := setupReplayAsset(t)
	// Mark the asset as reindexing (legal ready->reindexing transition; "not ready").
	repo := storage.NewPcapRepository(db)
	repo.UpdateAssetStatus("ast1", "reindexing", "")
	_, err := planner.Plan(context.Background(), ReplaySpec{PcapAssetID: "ast1", Speed: ReplaySpeed{Mode: "max"}}, "t", "c", "u1")
	if err == nil {
		t.Error("expected not-ready error, got nil")
	}
}
