package replay

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/trafficgen/trafficgen/internal/pcapparser"
)

// buildBareTCPFrame builds a 54-byte Eth+IPv4+TCP frame (no payload). Returns
// the frame and its OffsetLayout.
func buildBareTCPFrame(t *testing.T) ([]byte, pcapparser.OffsetLayout) {
	t.Helper()
	macA, _ := net.ParseMAC("aa:aa:aa:aa:aa:aa")
	macB, _ := net.ParseMAC("bb:bb:bb:bb:bb:bb")
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	tcp := &layers.TCP{SrcPort: 1234, DstPort: 80, Seq: 1000, Window: 65535, SYN: true}
	ipv4 := &layers.IPv4{
		SrcIP:    net.ParseIP("10.0.0.1"),
		DstIP:    net.ParseIP("10.0.0.2"),
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}
	tcp.SetNetworkLayerForChecksum(ipv4)
	gopacket.SerializeLayers(buf, opts,
		&layers.Ethernet{SrcMAC: macA, DstMAC: macB, EthernetType: layers.EthernetTypeIPv4},
		ipv4, tcp)
	frame := buf.Bytes()
	pkt := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)
	if el := pkt.ErrorLayer(); el != nil {
		t.Fatalf("buildBareTCPFrame: %v", el.Error())
	}
	return frame, pcapparser.ExtractOffsetLayout(pkt)
}

// ---------------------------------------------------------------------------
// ApplyPatches tests — gaps not covered by rewriter_test.go
// ---------------------------------------------------------------------------

// RW1: empty patches, recompute mode, clean frame — output is a copy, checksums
// recomputed and valid via gopacket re-parse.
func TestApplyPatches_Empty(t *testing.T) {
	frame, layout := buildFrame(t, net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2"), 1234, 80)

	out, err := ApplyPatches(frame, nil, layout, "recompute")
	if err != nil {
		t.Fatalf("ApplyPatches: %v", err)
	}

	// Content preserved (byte-for-byte identical).
	if !bytes.Equal(out, frame) {
		t.Error("out should be a byte-for-byte copy of input")
	}
	// Different backing array.
	if len(out) > 0 && &out[0] == &frame[0] {
		t.Error("out shares backing array with input — should be a copy")
	}

	// IP checksum recomputed and valid.
	wantIP := ipChecksum(out, layout.L3Start)
	gotIP := binary.BigEndian.Uint16(out[layout.L3Start+10 : layout.L3Start+12])
	if wantIP != gotIP {
		t.Errorf("IP checksum = 0x%x, want 0x%x", gotIP, wantIP)
	}

	// TCP checksum recomputed and valid.
	wantL4 := l4Checksum(out, layout)
	gotL4 := binary.BigEndian.Uint16(out[layout.L4Start+16 : layout.L4Start+18])
	if wantL4 != gotL4 {
		t.Errorf("TCP checksum = 0x%x, want 0x%x", gotL4, wantL4)
	}

	// gopacket re-parse: both layers decode.
	pkt := gopacket.NewPacket(out, layers.LayerTypeEthernet, gopacket.Default)
	if el := pkt.ErrorLayer(); el != nil {
		t.Fatalf("gopacket parse error: %v", el.Error())
	}
	if pkt.Layer(layers.LayerTypeIPv4) == nil {
		t.Error("no IPv4 layer in output")
	}
	if pkt.Layer(layers.LayerTypeTCP) == nil {
		t.Error("no TCP layer in output")
	}
}

// RW3: negative offset produces an error.
func TestApplyPatches_NegativeOffset(t *testing.T) {
	frame, layout := buildFrame(t, net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2"), 1234, 80)

	patches := []Patch{{Field: "src_ip", Offset: -1, Bytes: []byte{1, 2, 3, 4}, Layer: "l3"}}
	out, err := ApplyPatches(frame, patches, layout, "recompute")
	if err == nil {
		t.Fatal("negative offset should error")
	}
	if out != nil {
		t.Error("out should be nil on error")
	}
}

// RW4: overflow bounds — offset+len(Bytes) > frame length.
func TestApplyPatches_OverflowBounds(t *testing.T) {
	frame, layout := buildBareTCPFrame(t) // 54 bytes

	// Offset = len(frame) - 1, 4 bytes -> 3 bytes past end.
	patches := []Patch{{Field: "src_ip", Offset: len(frame) - 1, Bytes: []byte{1, 2, 3, 4}, Layer: "l3"}}
	out, err := ApplyPatches(frame, patches, layout, "recompute")
	if err == nil {
		t.Fatal("overflow patch should error")
	}
	if out != nil {
		t.Error("out should be nil on error")
	}
	_ = layout // suppress unused warning
}

// RW5: patch with Layer="l3" (src_ip) triggers both IP and TCP checksum
// recompute. Verify via gopacket re-parse.
func TestApplyPatches_L3Flag(t *testing.T) {
	frame, layout := buildFrame(t, net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2"), 1234, 80)

	newIP := net.ParseIP("10.0.0.99").To4()
	patches := []Patch{{Field: "src_ip", Offset: layout.SrcIP, Bytes: newIP, Layer: "l3"}}
	out, err := ApplyPatches(frame, patches, layout, "recompute")
	if err != nil {
		t.Fatalf("ApplyPatches: %v", err)
	}

	// SrcIP changed.
	gotIP := net.IP(out[layout.SrcIP : layout.SrcIP+4])
	if !gotIP.Equal(newIP) {
		t.Errorf("src_ip = %v, want %v", gotIP, newIP)
	}

	// IP checksum valid.
	wantIP := ipChecksum(out, layout.L3Start)
	gotIPcksum := binary.BigEndian.Uint16(out[layout.L3Start+10 : layout.L3Start+12])
	if wantIP != gotIPcksum {
		t.Errorf("IP checksum = 0x%x, want 0x%x", gotIPcksum, wantIP)
	}

	// TCP checksum valid (pseudo-header changed).
	wantL4 := l4Checksum(out, layout)
	gotL4 := binary.BigEndian.Uint16(out[layout.L4Start+16 : layout.L4Start+18])
	if wantL4 != gotL4 {
		t.Errorf("TCP checksum = 0x%x, want 0x%x", gotL4, wantL4)
	}

	// gopacket re-parse: both layers decode.
	pkt := gopacket.NewPacket(out, layers.LayerTypeEthernet, gopacket.Default)
	if el := pkt.ErrorLayer(); el != nil {
		t.Fatalf("gopacket parse error: %v", el.Error())
	}
	ipLayer := pkt.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		t.Fatal("no IPv4 layer")
	}
	ip := ipLayer.(*layers.IPv4)
	if !ip.SrcIP.Equal(newIP) {
		t.Errorf("gopacket SrcIP = %v, want %v", ip.SrcIP, newIP)
	}
	tcpLayer := pkt.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		t.Fatal("no TCP layer")
	}
}

// RW6: patch with Layer="l4" (seq), preserve mode — IP checksum NOT recomputed
// (touchedL3 false), TCP checksum recomputed (touchedL4 true).
func TestApplyPatches_L4Flag(t *testing.T) {
	frame, layout := buildFrame(t, net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2"), 1234, 80)

	origIPCksum := binary.BigEndian.Uint16(frame[layout.L3Start+10 : layout.L3Start+12])

	seqBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(seqBytes, 0xDEADBEEF)
	patches := []Patch{{Field: "seq", Offset: layout.Seq, Bytes: seqBytes, Layer: "l4"}}
	out, err := ApplyPatches(frame, patches, layout, "preserve")
	if err != nil {
		t.Fatalf("ApplyPatches: %v", err)
	}

	// Seq changed.
	gotSeq := binary.BigEndian.Uint32(out[layout.Seq : layout.Seq+4])
	if gotSeq != 0xDEADBEEF {
		t.Errorf("seq = 0x%08x, want 0xDEADBEEF", gotSeq)
	}

	// IP checksum unchanged (same bytes as original).
	gotIPCksum := binary.BigEndian.Uint16(out[layout.L3Start+10 : layout.L3Start+12])
	if gotIPCksum != origIPCksum {
		t.Errorf("IP checksum changed from 0x%x to 0x%x (should be preserved)", origIPCksum, gotIPCksum)
	}

	// TCP checksum recomputed (valid).
	wantL4 := l4Checksum(out, layout)
	gotL4 := binary.BigEndian.Uint16(out[layout.L4Start+16 : layout.L4Start+18])
	if wantL4 != gotL4 {
		t.Errorf("TCP checksum = 0x%x, want 0x%x", gotL4, wantL4)
	}

	// gopacket: TCP layer decodes.
	pkt := gopacket.NewPacket(out, layers.LayerTypeEthernet, gopacket.Default)
	if el := pkt.ErrorLayer(); el != nil {
		t.Fatalf("gopacket parse error: %v", el.Error())
	}
	tcpLayer := pkt.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		t.Fatal("no TCP layer")
	}
	tcp := tcpLayer.(*layers.TCP)
	if tcp.Seq != 0xDEADBEEF {
		t.Errorf("gopacket Seq = 0x%08x, want 0xDEADBEEF", tcp.Seq)
	}
}

// RW7: patch with Layer="l2" (src_mac), preserve mode — IP/TCP checksums NOT
// recomputed. Verify via gopacket re-parse.
func TestApplyPatches_L2Flag(t *testing.T) {
	frame, layout := buildFrame(t, net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2"), 1234, 80)

	origIPCksum := binary.BigEndian.Uint16(frame[layout.L3Start+10 : layout.L3Start+12])
	origL4Cksum := binary.BigEndian.Uint16(frame[layout.L4Start+16 : layout.L4Start+18])

	newMAC, _ := net.ParseMAC("cc:cc:cc:cc:cc:cc")
	patches := []Patch{{Field: "src_mac", Offset: layout.SrcMAC, Bytes: newMAC, Layer: "l2"}}
	out, err := ApplyPatches(frame, patches, layout, "preserve")
	if err != nil {
		t.Fatalf("ApplyPatches: %v", err)
	}

	// MAC changed.
	gotMAC := out[layout.SrcMAC : layout.SrcMAC+6]
	if string(gotMAC) != string(newMAC) {
		t.Errorf("src_mac = %x, want %x", gotMAC, newMAC)
	}

	// IP checksum unchanged.
	gotIPCksum := binary.BigEndian.Uint16(out[layout.L3Start+10 : layout.L3Start+12])
	if gotIPCksum != origIPCksum {
		t.Errorf("IP checksum changed from 0x%x to 0x%x", origIPCksum, gotIPCksum)
	}

	// TCP checksum unchanged.
	gotL4Cksum := binary.BigEndian.Uint16(out[layout.L4Start+16 : layout.L4Start+18])
	if gotL4Cksum != origL4Cksum {
		t.Errorf("TCP checksum changed from 0x%x to 0x%x", origL4Cksum, gotL4Cksum)
	}

	// gopacket: Ethernet layer decodes, MAC changed.
	pkt := gopacket.NewPacket(out, layers.LayerTypeEthernet, gopacket.Default)
	if el := pkt.ErrorLayer(); el != nil {
		t.Fatalf("gopacket parse error: %v", el.Error())
	}
	ethLayer := pkt.Layer(layers.LayerTypeEthernet)
	if ethLayer == nil {
		t.Fatal("no Ethernet layer")
	}
	eth := ethLayer.(*layers.Ethernet)
	if !bytes.Equal(eth.SrcMAC, newMAC) {
		t.Errorf("gopacket SrcMAC = %x, want %x", eth.SrcMAC, newMAC)
	}
}

// RW9: no patches, recompute mode — checksums recomputed and gopacket-valid
// (clean frame version, not corrupt-then-fix).
func TestApplyPatches_RecomputeNoPatch(t *testing.T) {
	frame, layout := buildFrame(t, net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2"), 1234, 80)

	out, err := ApplyPatches(frame, nil, layout, "recompute")
	if err != nil {
		t.Fatalf("ApplyPatches: %v", err)
	}

	// IP checksum valid.
	wantIP := ipChecksum(out, layout.L3Start)
	gotIP := binary.BigEndian.Uint16(out[layout.L3Start+10 : layout.L3Start+12])
	if wantIP != gotIP {
		t.Errorf("IP checksum = 0x%x, want 0x%x", gotIP, wantIP)
	}

	// TCP checksum valid.
	wantL4 := l4Checksum(out, layout)
	gotL4 := binary.BigEndian.Uint16(out[layout.L4Start+16 : layout.L4Start+18])
	if wantL4 != gotL4 {
		t.Errorf("TCP checksum = 0x%x, want 0x%x", gotL4, wantL4)
	}

	// gopacket re-parse: both layers decode.
	pkt := gopacket.NewPacket(out, layers.LayerTypeEthernet, gopacket.Default)
	if el := pkt.ErrorLayer(); el != nil {
		t.Fatalf("gopacket parse error: %v", el.Error())
	}
	if pkt.Layer(layers.LayerTypeIPv4) == nil {
		t.Error("no IPv4 layer")
	}
	if pkt.Layer(layers.LayerTypeTCP) == nil {
		t.Error("no TCP layer")
	}
}

// RW10: preserve mode, L3 patch (dst_ip) — both IP and TCP checksums
// recomputed because touchedL3=true.
func TestApplyPatches_PreserveL3(t *testing.T) {
	frame, layout := buildFrame(t, net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2"), 1234, 80)

	newIP := net.ParseIP("10.99.0.99").To4()
	patches := []Patch{{Field: "dst_ip", Offset: layout.DstIP, Bytes: newIP, Layer: "l3"}}
	out, err := ApplyPatches(frame, patches, layout, "preserve")
	if err != nil {
		t.Fatalf("ApplyPatches: %v", err)
	}

	// dst_ip changed.
	gotIP := net.IP(out[layout.DstIP : layout.DstIP+4])
	if !gotIP.Equal(newIP) {
		t.Errorf("dst_ip = %v, want %v", gotIP, newIP)
	}

	// IP checksum valid (recomputed).
	wantIP := ipChecksum(out, layout.L3Start)
	gotIPcksum := binary.BigEndian.Uint16(out[layout.L3Start+10 : layout.L3Start+12])
	if wantIP != gotIPcksum {
		t.Errorf("IP checksum = 0x%x, want 0x%x", gotIPcksum, wantIP)
	}

	// TCP checksum valid (recomputed because touchedL3 triggers L4).
	wantL4 := l4Checksum(out, layout)
	gotL4 := binary.BigEndian.Uint16(out[layout.L4Start+16 : layout.L4Start+18])
	if wantL4 != gotL4 {
		t.Errorf("TCP checksum = 0x%x, want 0x%x", gotL4, wantL4)
	}

	// gopacket: both layers decode.
	pkt := gopacket.NewPacket(out, layers.LayerTypeEthernet, gopacket.Default)
	if el := pkt.ErrorLayer(); el != nil {
		t.Fatalf("gopacket parse error: %v", el.Error())
	}
	if pkt.Layer(layers.LayerTypeIPv4) == nil {
		t.Error("no IPv4 layer")
	}
	if pkt.Layer(layers.LayerTypeTCP) == nil {
		t.Error("no TCP layer")
	}
}

// RW11: preserve mode, L4 patch (seq) — IP checksum NOT recomputed, TCP
// checksum recomputed.
func TestApplyPatches_PreserveL4(t *testing.T) {
	frame, layout := buildFrame(t, net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2"), 1234, 80)

	origIPCksum := binary.BigEndian.Uint16(frame[layout.L3Start+10 : layout.L3Start+12])

	seqBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(seqBytes, 0xCAFEBABE)
	patches := []Patch{{Field: "seq", Offset: layout.Seq, Bytes: seqBytes, Layer: "l4"}}
	out, err := ApplyPatches(frame, patches, layout, "preserve")
	if err != nil {
		t.Fatalf("ApplyPatches: %v", err)
	}

	// IP checksum unchanged (original bytes preserved).
	gotIPCksum := binary.BigEndian.Uint16(out[layout.L3Start+10 : layout.L3Start+12])
	if gotIPCksum != origIPCksum {
		t.Errorf("IP checksum changed from 0x%x to 0x%x", origIPCksum, gotIPCksum)
	}
	// IP checksum still valid (original was valid).
	wantIP := ipChecksum(out, layout.L3Start)
	if gotIPCksum != wantIP {
		t.Errorf("IP checksum = 0x%x, want 0x%x (original valid)", gotIPCksum, wantIP)
	}

	// TCP checksum recomputed (valid).
	wantL4 := l4Checksum(out, layout)
	gotL4 := binary.BigEndian.Uint16(out[layout.L4Start+16 : layout.L4Start+18])
	if wantL4 != gotL4 {
		t.Errorf("TCP checksum = 0x%x, want 0x%x", gotL4, wantL4)
	}

	// gopacket: TCP layer decodes.
	pkt := gopacket.NewPacket(out, layers.LayerTypeEthernet, gopacket.Default)
	if el := pkt.ErrorLayer(); el != nil {
		t.Fatalf("gopacket parse error: %v", el.Error())
	}
	tcpLayer := pkt.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		t.Fatal("no TCP layer")
	}
	tcp := tcpLayer.(*layers.TCP)
	if tcp.Seq != 0xCAFEBABE {
		t.Errorf("gopacket Seq = 0x%08x, want 0xCAFEBABE", tcp.Seq)
	}
}

// RW12: preserve mode, only L2 patch — IP/TCP checksums both NOT recomputed.
func TestApplyPatches_PreserveL2Only(t *testing.T) {
	frame, layout := buildFrame(t, net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2"), 1234, 80)

	origIPCksum := binary.BigEndian.Uint16(frame[layout.L3Start+10 : layout.L3Start+12])
	origL4Cksum := binary.BigEndian.Uint16(frame[layout.L4Start+16 : layout.L4Start+18])

	newMAC, _ := net.ParseMAC("de:ad:be:ef:00:01")
	patches := []Patch{{Field: "dst_mac", Offset: layout.DstMAC, Bytes: newMAC, Layer: "l2"}}
	out, err := ApplyPatches(frame, patches, layout, "preserve")
	if err != nil {
		t.Fatalf("ApplyPatches: %v", err)
	}

	// MAC changed.
	gotMAC := out[layout.DstMAC : layout.DstMAC+6]
	if !bytes.Equal(gotMAC, newMAC) {
		t.Errorf("dst_mac = %x, want %x", gotMAC, newMAC)
	}

	// IP checksum unchanged.
	gotIPCksum := binary.BigEndian.Uint16(out[layout.L3Start+10 : layout.L3Start+12])
	if gotIPCksum != origIPCksum {
		t.Errorf("IP checksum changed from 0x%x to 0x%x", origIPCksum, gotIPCksum)
	}

	// TCP checksum unchanged.
	gotL4Cksum := binary.BigEndian.Uint16(out[layout.L4Start+16 : layout.L4Start+18])
	if gotL4Cksum != origL4Cksum {
		t.Errorf("TCP checksum changed from 0x%x to 0x%x", origL4Cksum, gotL4Cksum)
	}

	// gopacket: Ethernet layer decodes, MAC changed.
	pkt := gopacket.NewPacket(out, layers.LayerTypeEthernet, gopacket.Default)
	if el := pkt.ErrorLayer(); el != nil {
		t.Fatalf("gopacket parse error: %v", el.Error())
	}
	ethLayer := pkt.Layer(layers.LayerTypeEthernet)
	if ethLayer == nil {
		t.Fatal("no Ethernet layer")
	}
	eth := ethLayer.(*layers.Ethernet)
	if !bytes.Equal(eth.DstMAC, newMAC) {
		t.Errorf("gopacket DstMAC = %x, want %x", eth.DstMAC, newMAC)
	}
}

// RW13: preserve mode, no patches — covered by
// TestApplyPatches_NoPatches_PreserveEmpty in rewriter_test.go.

// RW15: recompute mode, only L2 patch — both IP and TCP checksums recomputed
// (mode forces recompute regardless of touched layer).
func TestApplyPatches_RecomputeL2Only(t *testing.T) {
	frame, layout := buildFrame(t, net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2"), 1234, 80)

	newMAC, _ := net.ParseMAC("cc:cc:cc:cc:cc:cc")
	patches := []Patch{{Field: "src_mac", Offset: layout.SrcMAC, Bytes: newMAC, Layer: "l2"}}
	out, err := ApplyPatches(frame, patches, layout, "recompute")
	if err != nil {
		t.Fatalf("ApplyPatches: %v", err)
	}

	// MAC changed.
	gotMAC := out[layout.SrcMAC : layout.SrcMAC+6]
	if !bytes.Equal(gotMAC, newMAC) {
		t.Errorf("src_mac = %x, want %x", gotMAC, newMAC)
	}

	// IP checksum recomputed (valid).
	wantIP := ipChecksum(out, layout.L3Start)
	gotIP := binary.BigEndian.Uint16(out[layout.L3Start+10 : layout.L3Start+12])
	if wantIP != gotIP {
		t.Errorf("IP checksum = 0x%x, want 0x%x", gotIP, wantIP)
	}

	// TCP checksum recomputed (valid).
	wantL4 := l4Checksum(out, layout)
	gotL4 := binary.BigEndian.Uint16(out[layout.L4Start+16 : layout.L4Start+18])
	if wantL4 != gotL4 {
		t.Errorf("TCP checksum = 0x%x, want 0x%x", gotL4, wantL4)
	}

	// gopacket: both layers decode.
	pkt := gopacket.NewPacket(out, layers.LayerTypeEthernet, gopacket.Default)
	if el := pkt.ErrorLayer(); el != nil {
		t.Fatalf("gopacket parse error: %v", el.Error())
	}
	if pkt.Layer(layers.LayerTypeIPv4) == nil {
		t.Error("no IPv4 layer")
	}
	if pkt.Layer(layers.LayerTypeTCP) == nil {
		t.Error("no TCP layer")
	}
}

// RW16: mid-loop OOB — 2 patches where the 2nd is out-of-bounds; the call
// returns an error and no partial result (out is nil).
func TestApplyPatches_MidLoopOOB(t *testing.T) {
	frame, layout := buildFrame(t, net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2"), 1234, 80)

	// First patch: valid src_ip.
	newIP := net.ParseIP("10.0.0.99").To4()
	// Second patch: OOB (offset beyond frame).
	patches := []Patch{
		{Field: "src_ip", Offset: layout.SrcIP, Bytes: newIP, Layer: "l3"},
		{Field: "oob", Offset: len(frame) - 1, Bytes: []byte{1, 2, 3, 4}, Layer: "l3"},
	}
	out, err := ApplyPatches(frame, patches, layout, "recompute")
	if err == nil {
		t.Fatal("mid-loop OOB should error")
	}
	if out != nil {
		t.Error("out should be nil on error — no partial result")
	}
}

// RW17: same offset, last patch wins — two patches at the same Offset with
// different Bytes; the second patch's bytes appear in the output.
func TestApplyPatches_SameOffsetLastWins(t *testing.T) {
	frame, layout := buildFrame(t, net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2"), 1234, 80)

	patches := []Patch{
		{Field: "src_ip", Offset: layout.SrcIP, Bytes: net.ParseIP("10.0.0.99").To4(), Layer: "l3"},
		{Field: "src_ip", Offset: layout.SrcIP, Bytes: net.ParseIP("10.0.0.50").To4(), Layer: "l3"},
	}
	out, err := ApplyPatches(frame, patches, layout, "recompute")
	if err != nil {
		t.Fatalf("ApplyPatches: %v", err)
	}

	gotIP := net.IP(out[layout.SrcIP : layout.SrcIP+4])
	wantIP := net.ParseIP("10.0.0.50").To4()
	if !gotIP.Equal(wantIP) {
		t.Errorf("src_ip = %v, want %v (second patch should win)", gotIP, wantIP)
	}

	// Checksums still valid.
	wantIPcksum := ipChecksum(out, layout.L3Start)
	gotIPcksum := binary.BigEndian.Uint16(out[layout.L3Start+10 : layout.L3Start+12])
	if wantIPcksum != gotIPcksum {
		t.Errorf("IP checksum = 0x%x, want 0x%x", gotIPcksum, wantIPcksum)
	}
}

// ---------------------------------------------------------------------------
// Field-specific patches via gopacket re-parse (RW2 family)
// ---------------------------------------------------------------------------

// RW-PORT: patch dst_port to 443, verify via gopacket decode.
func TestApplyPatches_PortPatch(t *testing.T) {
	frame, layout := buildFrame(t, net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2"), 1234, 80)

	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, 443)
	patches := []Patch{{Field: "dst_port", Offset: layout.DstPort, Bytes: portBytes, Layer: "l4"}}
	out, err := ApplyPatches(frame, patches, layout, "recompute")
	if err != nil {
		t.Fatalf("ApplyPatches: %v", err)
	}

	// gopacket re-parse.
	pkt := gopacket.NewPacket(out, layers.LayerTypeEthernet, gopacket.Default)
	if el := pkt.ErrorLayer(); el != nil {
		t.Fatalf("gopacket parse error: %v", el.Error())
	}
	tcpLayer := pkt.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		t.Fatal("no TCP layer")
	}
	tcp := tcpLayer.(*layers.TCP)
	if tcp.DstPort != 443 {
		t.Errorf("DstPort = %d, want 443", tcp.DstPort)
	}
	if tcp.SrcPort != 1234 {
		t.Errorf("SrcPort = %d, want 1234 (unchanged)", tcp.SrcPort)
	}

	// TCP checksum valid.
	wantL4 := l4Checksum(out, layout)
	gotL4 := binary.BigEndian.Uint16(out[layout.L4Start+16 : layout.L4Start+18])
	if wantL4 != gotL4 {
		t.Errorf("TCP checksum = 0x%x, want 0x%x", gotL4, wantL4)
	}
}

// RW-MAC: patch src_mac to de:ad:be:ef:00:01, verify via gopacket decode.
func TestApplyPatches_MACPatch(t *testing.T) {
	frame, layout := buildFrame(t, net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2"), 1234, 80)

	newMAC, _ := net.ParseMAC("de:ad:be:ef:00:01")
	patches := []Patch{{Field: "src_mac", Offset: layout.SrcMAC, Bytes: newMAC, Layer: "l2"}}
	out, err := ApplyPatches(frame, patches, layout, "recompute")
	if err != nil {
		t.Fatalf("ApplyPatches: %v", err)
	}

	// gopacket re-parse.
	pkt := gopacket.NewPacket(out, layers.LayerTypeEthernet, gopacket.Default)
	if el := pkt.ErrorLayer(); el != nil {
		t.Fatalf("gopacket parse error: %v", el.Error())
	}
	ethLayer := pkt.Layer(layers.LayerTypeEthernet)
	if ethLayer == nil {
		t.Fatal("no Ethernet layer")
	}
	eth := ethLayer.(*layers.Ethernet)
	if !bytes.Equal(eth.SrcMAC, newMAC) {
		t.Errorf("SrcMAC = %x, want %x", eth.SrcMAC, newMAC)
	}
}

// RW-IP, RW-SEQ, RW-TTL, RW-DSCP, RW-ECN, RW-IPID are all covered by existing
// tests in rewriter_test.go (TestApplyPatches_SrcIP, _Seq, _TTL, _DSCP, _ECN,
// _IPID). Skip them here to avoid duplication.

func TestApplyPatches_IPFieldPatch(t *testing.T) {
	t.Skip("covered by TestApplyPatches_SrcIP")
}

func TestApplyPatches_SeqPatch(t *testing.T) {
	t.Skip("covered by TestApplyPatches_Seq")
}

func TestApplyPatches_TTLPatch(t *testing.T) {
	t.Skip("covered by TestApplyPatches_TTL")
}

func TestApplyPatches_DSCPPatch(t *testing.T) {
	t.Skip("covered by TestApplyPatches_DSCP")
}

func TestApplyPatches_ECNPatch(t *testing.T) {
	t.Skip("covered by TestApplyPatches_ECN")
}

func TestApplyPatches_IPIDPatch(t *testing.T) {
	t.Skip("covered by TestApplyPatches_IPID")
}

// ---------------------------------------------------------------------------
// setIPChecksum unit tests (checksum.go)
// ---------------------------------------------------------------------------

// CS1: L3Start=-1 → no-op, frame unchanged.
func TestSetIPChecksum_L3Neg(t *testing.T) {
	frame, layout := buildFrame(t, net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2"), 1234, 80)
	orig := make([]byte, len(frame))
	copy(orig, frame)

	badLayout := layout
	badLayout.L3Start = -1
	setIPChecksum(frame, badLayout)

	if !bytes.Equal(frame, orig) {
		t.Error("frame changed when L3Start=-1")
	}
}

// CS2: L3Start+20 > len(frame) → no-op, frame unchanged.
func TestSetIPChecksum_TooShort(t *testing.T) {
	// Use a 10-byte frame with L3Start=0.
	frame := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
	orig := make([]byte, 10)
	copy(orig, frame)

	layout := pcapparser.OffsetLayout{L3Start: 0}
	setIPChecksum(frame, layout)

	if !bytes.Equal(frame, orig) {
		t.Error("frame changed when l3+20 > len(frame)")
	}
}

// CS3: normal frame — IP checksum written correctly.
func TestSetIPChecksum_Normal(t *testing.T) {
	frame, layout := buildFrame(t, net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2"), 1234, 80)

	// Corrupt the checksum so we can verify it gets fixed.
	binary.BigEndian.PutUint16(frame[layout.L3Start+10:layout.L3Start+12], 0xDEAD)
	setIPChecksum(frame, layout)

	want := ipChecksum(frame, layout.L3Start)
	got := binary.BigEndian.Uint16(frame[layout.L3Start+10 : layout.L3Start+12])
	if want != got {
		t.Errorf("IP checksum = 0x%x, want 0x%x", got, want)
	}

	// gopacket re-parse: IPv4 layer decodes.
	pkt := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)
	if el := pkt.ErrorLayer(); el != nil {
		t.Fatalf("gopacket parse error: %v", el.Error())
	}
	if pkt.Layer(layers.LayerTypeIPv4) == nil {
		t.Error("no IPv4 layer")
	}
}

// CS5: IHL>5 (IP options, 24-byte header) — setIPChecksum still only sums 20
// bytes (known limitation). Assert checksum matches ipChecksum of first 20 bytes.
func TestSetIPChecksum_WithOptions(t *testing.T) {
	frame, layout := buildFrame(t, net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2"), 1234, 80)

	// Change IHL from 5 to 6 (0x45 → 0x46). The header is still 20 bytes but
	// the IHL field claims 24 bytes (options).
	frame[layout.L3Start] = 0x46

	// Corrupt checksum.
	binary.BigEndian.PutUint16(frame[layout.L3Start+10:layout.L3Start+12], 0xDEAD)
	setIPChecksum(frame, layout)

	// Expected: ipChecksum only sums 20 bytes (the first 20 bytes of the header).
	want := ipChecksum(frame, layout.L3Start)
	got := binary.BigEndian.Uint16(frame[layout.L3Start+10 : layout.L3Start+12])
	if want != got {
		t.Errorf("IP checksum = 0x%x, want 0x%x (20-byte sum)", got, want)
	}
}

// ---------------------------------------------------------------------------
// setL4Checksum unit tests (checksum.go)
// ---------------------------------------------------------------------------

// CS6: L3Start=-1 → no-op, frame unchanged.
func TestSetL4Checksum_L3Neg(t *testing.T) {
	frame, layout := buildFrame(t, net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2"), 1234, 80)
	origCksum := binary.BigEndian.Uint16(frame[layout.L4Start+16 : layout.L4Start+18])

	badLayout := layout
	badLayout.L3Start = -1
	setL4Checksum(frame, badLayout)

	got := binary.BigEndian.Uint16(frame[layout.L4Start+16 : layout.L4Start+18])
	if got != origCksum {
		t.Errorf("TCP checksum changed from 0x%x to 0x%x when L3Start=-1", origCksum, got)
	}
}

// CS7: L4Start=-1 → no-op, frame unchanged.
func TestSetL4Checksum_L4Neg(t *testing.T) {
	frame, layout := buildFrame(t, net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2"), 1234, 80)
	origCksum := binary.BigEndian.Uint16(frame[layout.L4Start+16 : layout.L4Start+18])

	badLayout := layout
	badLayout.L4Start = -1
	setL4Checksum(frame, badLayout)

	got := binary.BigEndian.Uint16(frame[layout.L4Start+16 : layout.L4Start+18])
	if got != origCksum {
		t.Errorf("TCP checksum changed from 0x%x to 0x%x when L4Start=-1", origCksum, got)
	}
}

// CS8: L4Start >= len(frame) → no-op, frame unchanged.
func TestSetL4Checksum_L4OutOfBounds(t *testing.T) {
	frame, layout := buildFrame(t, net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2"), 1234, 80)
	origCksum := binary.BigEndian.Uint16(frame[layout.L4Start+16 : layout.L4Start+18])

	badLayout := layout
	badLayout.L4Start = len(frame) // exactly past end
	setL4Checksum(frame, badLayout)

	got := binary.BigEndian.Uint16(frame[layout.L4Start+16 : layout.L4Start+18])
	if got != origCksum {
		t.Errorf("TCP checksum changed when L4Start >= len(frame)")
	}
}

// CS9: TCP — checksum recomputed correctly, gopacket TCP decodes.
func TestSetL4Checksum_TCP(t *testing.T) {
	frame, layout := buildFrame(t, net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2"), 1234, 80)

	if layout.L4Protocol != "tcp" {
		t.Fatalf("expected TCP frame, got L4Protocol=%q", layout.L4Protocol)
	}

	// Corrupt TCP checksum.
	binary.BigEndian.PutUint16(frame[layout.L4Start+16:layout.L4Start+18], 0xDEAD)
	setL4Checksum(frame, layout)

	want := l4Checksum(frame, layout)
	got := binary.BigEndian.Uint16(frame[layout.L4Start+16 : layout.L4Start+18])
	if want != got {
		t.Errorf("TCP checksum = 0x%x, want 0x%x", got, want)
	}

	// gopacket: TCP layer decodes.
	pkt := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)
	if el := pkt.ErrorLayer(); el != nil {
		t.Fatalf("gopacket parse error: %v", el.Error())
	}
	if pkt.Layer(layers.LayerTypeTCP) == nil {
		t.Error("no TCP layer")
	}
}

// CS10: UDP — checksum recomputed correctly, gopacket UDP decodes.
func TestSetL4Checksum_UDP(t *testing.T) {
	frame, layout := buildUDPFrame(t, net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2"), 1234, 80)

	if layout.L4Protocol != "udp" {
		t.Fatalf("expected UDP frame, got L4Protocol=%q", layout.L4Protocol)
	}

	// Corrupt UDP checksum.
	binary.BigEndian.PutUint16(frame[layout.L4Start+6:layout.L4Start+8], 0xDEAD)
	setL4Checksum(frame, layout)

	want := l4Checksum(frame, layout)
	got := binary.BigEndian.Uint16(frame[layout.L4Start+6 : layout.L4Start+8])
	if want != got {
		t.Errorf("UDP checksum = 0x%x, want 0x%x", got, want)
	}

	// gopacket: UDP layer decodes.
	pkt := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)
	if el := pkt.ErrorLayer(); el != nil {
		t.Fatalf("gopacket parse error: %v", el.Error())
	}
	if pkt.Layer(layers.LayerTypeUDP) == nil {
		t.Error("no UDP layer")
	}
}

// CS11: ICMP — no-op (returns early), frame unchanged.
func TestSetL4Checksum_ICMP(t *testing.T) {
	// Build an Eth+IPv4+ICMP frame manually.
	macA, _ := net.ParseMAC("aa:aa:aa:aa:aa:aa")
	macB, _ := net.ParseMAC("bb:bb:bb:bb:bb:bb")
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	icmp := &layers.ICMPv4{TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0)}
	ipv4 := &layers.IPv4{
		SrcIP:    net.ParseIP("10.0.0.1"),
		DstIP:    net.ParseIP("10.0.0.2"),
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolICMPv4,
	}
	gopacket.SerializeLayers(buf, opts,
		&layers.Ethernet{SrcMAC: macA, DstMAC: macB, EthernetType: layers.EthernetTypeIPv4},
		ipv4, icmp)
	frame := buf.Bytes()
	pkt := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)
	if el := pkt.ErrorLayer(); el != nil {
		t.Fatalf("build ICMP frame: %v", el.Error())
	}
	layout := pcapparser.ExtractOffsetLayout(pkt)
	if layout.L4Protocol != "icmp" {
		t.Fatalf("expected ICMP frame, got L4Protocol=%q", layout.L4Protocol)
	}

	// Mark a known byte past the L4 header so we can detect writes.
	// ICMP checksum is at L4Start+2, but setL4Checksum should return early.
	orig := make([]byte, len(frame))
	copy(orig, frame)

	setL4Checksum(frame, layout)

	if !bytes.Equal(frame, orig) {
		t.Error("ICMP frame changed by setL4Checksum (should be no-op)")
	}
}

// CS14: checksum offset out of bounds (cksumOff+2 > len(frame)) → no-op.
func TestSetL4Checksum_CksumOOB(t *testing.T) {
	frame, layout := buildFrame(t, net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2"), 1234, 80)
	origCksum := binary.BigEndian.Uint16(frame[layout.L4Start+16 : layout.L4Start+18])

	// Set L4Start near the end so cksumOff+2 > len(frame).
	// For TCP: cksumOff = l4+16, need l4+18 > len(frame).
	// frame is ~61 bytes, so L4Start = len(frame)-1 = 60 makes cksumOff+2 = 78 > 61.
	badLayout := layout
	badLayout.L4Start = len(frame) - 1
	setL4Checksum(frame, badLayout)

	got := binary.BigEndian.Uint16(frame[layout.L4Start+16 : layout.L4Start+18])
	if got != origCksum {
		t.Errorf("TCP checksum changed when cksumOff+2 > len(frame)")
	}
}

// CS16: partial frame (l3+20 > len(frame)) — skips pseudo-header IP, only sums
// L4. No panic, checksum computed from L4 only.
func TestSetL4Checksum_PartialFrame(t *testing.T) {
	frame, layout := buildFrame(t, net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2"), 1234, 80)

	// Create a modified layout where L3Start is near the end so l3+20 > len(frame)
	// but L4Start is still valid.
	modLayout := layout
	modLayout.L3Start = len(frame) - 5 // l3+20 = len+15 > len(frame)
	// L4Start stays at the original valid position.

	// Set TCP checksum to 0 so we can detect recomputation.
	binary.BigEndian.PutUint16(frame[layout.L4Start+16:layout.L4Start+18], 0)

	// Should not panic.
	setL4Checksum(frame, modLayout)

	// Checksum was computed (non-zero).
	got := binary.BigEndian.Uint16(frame[layout.L4Start+16 : layout.L4Start+18])
	if got == 0 {
		t.Error("TCP checksum is 0 — expected recomputation")
	}
}

// CS17: even L4 length (20-byte TCP, no payload) — no padding needed.
func TestSetL4Checksum_EvenLen(t *testing.T) {
	frame, layout := buildBareTCPFrame(t) // 54 bytes, L4Len=20

	if layout.L4Protocol != "tcp" {
		t.Fatalf("expected TCP frame, got L4Protocol=%q", layout.L4Protocol)
	}

	// Corrupt checksum.
	binary.BigEndian.PutUint16(frame[layout.L4Start+16:layout.L4Start+18], 0xDEAD)
	setL4Checksum(frame, layout)

	want := l4Checksum(frame, layout)
	got := binary.BigEndian.Uint16(frame[layout.L4Start+16 : layout.L4Start+18])
	if want != got {
		t.Errorf("TCP checksum = 0x%x, want 0x%x", got, want)
	}
}

// CS18: odd L4 length (TCP header 20 + 7-byte payload = 27) — pad with 0.
func TestSetL4Checksum_OddLen(t *testing.T) {
	frame, layout := buildFrame(t, net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2"), 1234, 80) // 61 bytes, L4Len=27

	if layout.L4Protocol != "tcp" {
		t.Fatalf("expected TCP frame, got L4Protocol=%q", layout.L4Protocol)
	}

	l4Len := len(frame) - layout.L4Start
	if l4Len%2 != 1 {
		t.Fatalf("expected odd L4 length, got %d", l4Len)
	}

	// Corrupt checksum.
	binary.BigEndian.PutUint16(frame[layout.L4Start+16:layout.L4Start+18], 0xDEAD)
	setL4Checksum(frame, layout)

	want := l4Checksum(frame, layout)
	got := binary.BigEndian.Uint16(frame[layout.L4Start+16 : layout.L4Start+18])
	if want != got {
		t.Errorf("TCP checksum = 0x%x, want 0x%x", got, want)
	}
}

// CS19: empty payload (20-byte TCP header only) — only pseudo-header + header
// summed.
func TestSetL4Checksum_EmptyPayload(t *testing.T) {
	frame, layout := buildBareTCPFrame(t) // 54 bytes, L4Len=20

	if layout.L4Protocol != "tcp" {
		t.Fatalf("expected TCP frame, got L4Protocol=%q", layout.L4Protocol)
	}

	// Corrupt checksum.
	binary.BigEndian.PutUint16(frame[layout.L4Start+16:layout.L4Start+18], 0xDEAD)
	setL4Checksum(frame, layout)

	want := l4Checksum(frame, layout)
	got := binary.BigEndian.Uint16(frame[layout.L4Start+16 : layout.L4Start+18])
	if want != got {
		t.Errorf("TCP checksum = 0x%x, want 0x%x", got, want)
	}
}

// CS20: zero the TCP checksum, then recompute — new value is non-zero and valid.
func TestSetL4Checksum_ZeroedThenRecomputed(t *testing.T) {
	frame, layout := buildFrame(t, net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2"), 1234, 80)

	// Zero the TCP checksum.
	binary.BigEndian.PutUint16(frame[layout.L4Start+16:layout.L4Start+18], 0)
	setL4Checksum(frame, layout)

	got := binary.BigEndian.Uint16(frame[layout.L4Start+16 : layout.L4Start+18])
	if got == 0 {
		t.Fatal("TCP checksum is still 0 after recompute")
	}

	want := l4Checksum(frame, layout)
	if want != got {
		t.Errorf("TCP checksum = 0x%x, want 0x%x", got, want)
	}
}
