package replay

import (
	"context"
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	sqlite "github.com/glebarez/sqlite"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/trafficgen/trafficgen/internal/pcapparser"
	"github.com/trafficgen/trafficgen/internal/storage"
	"gorm.io/gorm"
)

// storeFrames builds a pcap from frames, parses + stores it, returns the
// (pcapPath, db, assetID) for planner tests.
func storeFrames(t *testing.T, frames [][]byte, suffix string) (string, *storage.DB, string) {
	t.Helper()
	dir := t.TempDir()
	pcapPath := filepath.Join(dir, suffix+".pcap")
	f, _ := os.Create(pcapPath)
	w := pcapgo.NewWriter(f)
	w.WriteFileHeader(65535, layers.LinkTypeEthernet)
	for i, fr := range frames {
		ci := gopacket.CaptureInfo{Timestamp: time.UnixMicro(int64(1000 + i*1000)), CaptureLength: len(fr), Length: len(fr)}
		w.WritePacket(ci, fr)
	}
	f.Close()
	gormDB, _ := gorm.Open(sqlite.Open(filepath.Join(dir, suffix+".db")), &gorm.Config{})
	storage.AutoMigrate(gormDB)
	db := &storage.DB{DB: gormDB}
	assetID := "ast-" + suffix
	repo := storage.NewPcapRepository(db)
	repo.CreateAsset(&storage.PcapAssetModel{ID: assetID, UserID: "u1", Name: suffix, StoragePath: pcapPath, Status: "ready", LinkType: 1})
	analysis, err := pcapparser.Parse(pcapPath, &pcapparser.Options{PcapAssetID: assetID, UserID: "u1"})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	repo.CreateFlows(analysis.Flows)
	repo.CreatePackets(analysis.Packets)
	return pcapPath, db, assetID
}

func plannerBg() context.Context { return context.Background() }

// TestFidelity_OutOfOrderPreserved verifies the planner emits packets in file
// order (no resequencer) -- an out-of-order capture is replayed as-is (§13).
func TestFidelity_OutOfOrderPreserved(t *testing.T) {
	// Build packets with out-of-order seq: SYN(seq=100), FIN(seq=300), data(seq=200).
	// The planner must emit them in FILE order (SYN, FIN, data), not seq order.
	macA, _ := net.ParseMAC("aa:aa:aa:aa:aa:aa")
	macB, _ := net.ParseMAC("bb:bb:bb:bb:bb:bb")
	build := func(seq uint32, flags uint8) []byte {
		buf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
		tcp := &layers.TCP{SrcPort: 1234, DstPort: 80, Seq: seq, SYN: flags&2 != 0, FIN: flags&1 != 0, ACK: flags&16 != 0}
		ipv4 := &layers.IPv4{SrcIP: net.ParseIP("10.0.0.1"), DstIP: net.ParseIP("10.0.0.2"), Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP}
		tcp.SetNetworkLayerForChecksum(ipv4)
		gopacket.SerializeLayers(buf, opts, &layers.Ethernet{SrcMAC: macA, DstMAC: macB, EthernetType: layers.EthernetTypeIPv4}, ipv4, tcp)
		return buf.Bytes()
	}
	frames := [][]byte{build(100, 2), build(300, 17), build(200, 24)} // SYN, FIN+ACK, PSH+ACK (out-of-seq order)
	// Parse + store + plan.
	pcapPath, db, assetID := storeFrames(t, frames, "oo")
	_ = pcapPath
	planner := NewReplayPlanner(db)
	ch, err := planner.Plan(plannerBg(), ReplaySpec{PcapAssetID: assetID, Speed: ReplaySpeed{Mode: "max"}}, "t", "c", "u1", nil)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var seqs []uint32
	for cfg := range ch {
		raw := cfg.Metadata["_raw"].([]byte)
		layout := cfg.Metadata["_layout"].(pcapparser.OffsetLayout)
		seqs = append(seqs, binary.BigEndian.Uint32(raw[layout.Seq:layout.Seq+4]))
	}
	// File order: seq 100, 300, 200 (as captured). Not re-sorted to 100,200,300.
	want := []uint32{100, 300, 200}
	for i, s := range seqs {
		if s != want[i] {
			t.Errorf("packet %d seq = %d, want %d (file order not preserved)", i, s, want[i])
		}
	}
}

// TestFidelity_RetransmitPreserved verifies duplicate packets (retransmit) are
// both emitted -- no dedup (§13).
func TestFidelity_RetransmitPreserved(t *testing.T) {
	macA, _ := net.ParseMAC("aa:aa:aa:aa:aa:aa")
	macB, _ := net.ParseMAC("bb:bb:bb:bb:bb:bb")
	build := func() []byte {
		buf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
		tcp := &layers.TCP{SrcPort: 1234, DstPort: 80, Seq: 100, Ack: 200, Window: 65535, PSH: true, ACK: true}
		ipv4 := &layers.IPv4{SrcIP: net.ParseIP("10.0.0.1"), DstIP: net.ParseIP("10.0.0.2"), Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP}
		tcp.SetNetworkLayerForChecksum(ipv4)
		gopacket.SerializeLayers(buf, opts, &layers.Ethernet{SrcMAC: macA, DstMAC: macB, EthernetType: layers.EthernetTypeIPv4}, ipv4, tcp, gopacket.Payload([]byte("data")))
		return buf.Bytes()
	}
	frames := [][]byte{build(), build()} // two identical packets (retransmit)
	_, db, assetID := storeFrames(t, frames, "rt")
	planner := NewReplayPlanner(db)
	ch, _ := planner.Plan(plannerBg(), ReplaySpec{PcapAssetID: assetID, Speed: ReplaySpeed{Mode: "max"}}, "t", "c", "u1", nil)
	var count int
	for range ch {
		count++
	}
	if count != 2 {
		t.Errorf("retransmit: emitted %d packets, want 2 (no dedup)", count)
	}
}

// TestFidelity_BadChecksumPreserved verifies checksum_mode=preserve keeps a
// deliberately bad IP checksum when no L3/L4 fields are patched (§16.10).
func TestFidelity_BadChecksumPreserved(t *testing.T) {
	frame, layout := buildFrame(t, net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2"), 1234, 80)
	// Corrupt the IP checksum.
	binary.BigEndian.PutUint16(frame[layout.L3Start+10:layout.L3Start+12], 0xBEEF)
	out, err := ApplyPatches(frame, nil, layout, "preserve")
	if err != nil {
		t.Fatalf("ApplyPatches: %v", err)
	}
	got := binary.BigEndian.Uint16(out[layout.L3Start+10 : layout.L3Start+12])
	if got != 0xBEEF {
		t.Errorf("bad checksum not preserved: got 0x%x, want 0xBEEF", got)
	}
}

// TestFidelity_MalformedPreserved verifies byte-patch only changes the patched
// field; the rest of a malformed packet is preserved as-is (no reconstruction).
func TestFidelity_MalformedPreserved(t *testing.T) {
	frame, layout := buildFrame(t, net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2"), 1234, 80)
	// Make the packet "malformed" by corrupting a non-patched byte (e.g., window).
	binary.BigEndian.PutUint16(frame[layout.Window:layout.Window+2], 0xFFFF)
	origWindow := binary.BigEndian.Uint16(frame[layout.Window : layout.Window+2])
	// Patch only src_ip.
	patches := []Patch{{Field: "src_ip", Offset: layout.SrcIP, Bytes: net.ParseIP("11.0.0.1").To4(), Layer: "l3"}}
	out, err := ApplyPatches(frame, patches, layout, "recompute")
	if err != nil {
		t.Fatalf("ApplyPatches: %v", err)
	}
	// src_ip changed.
	if !net.IP(out[layout.SrcIP:layout.SrcIP+4]).Equal(net.ParseIP("11.0.0.1").To4()) {
		t.Error("src_ip not patched")
	}
	// window (malformed value) preserved.
	gotWindow := binary.BigEndian.Uint16(out[layout.Window : layout.Window+2])
	if gotWindow != origWindow {
		t.Errorf("malformed window changed: got 0x%x, want 0x%x (byte-patch shouldn't touch it)", gotWindow, origWindow)
	}
}
