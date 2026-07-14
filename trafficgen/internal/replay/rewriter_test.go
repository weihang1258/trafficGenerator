package replay

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/trafficgen/trafficgen/internal/pcapparser"
)

// buildFrame builds an Eth+IPv4+TCP frame with valid checksums and returns it
// plus its OffsetLayout.
func buildFrame(t *testing.T, srcIP, dstIP net.IP, srcPort, dstPort layers.TCPPort) ([]byte, pcapparser.OffsetLayout) {
	t.Helper()
	macA, _ := net.ParseMAC("aa:aa:aa:aa:aa:aa")
	macB, _ := net.ParseMAC("bb:bb:bb:bb:bb:bb")
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	tcp := &layers.TCP{SrcPort: srcPort, DstPort: dstPort, Seq: 100, Window: 65535, SYN: true}
	ipv4 := &layers.IPv4{SrcIP: srcIP, DstIP: dstIP, Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP}
	tcp.SetNetworkLayerForChecksum(ipv4)
	gopacket.SerializeLayers(buf, opts,
		&layers.Ethernet{SrcMAC: macA, DstMAC: macB, EthernetType: layers.EthernetTypeIPv4},
		ipv4, tcp, gopacket.Payload([]byte("payload")))
	frame := buf.Bytes()
	pkt := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)
	return frame, pcapparser.ExtractOffsetLayout(pkt)
}

// ipChecksum computes the IPv4 header checksum of the 20-byte header at off
// (zeroing the checksum field first, per the algorithm). Does not mutate frame.
func ipChecksum(frame []byte, off int) uint16 {
	hdr := make([]byte, 20)
	copy(hdr, frame[off:off+20])
	binary.BigEndian.PutUint16(hdr[10:12], 0) // zero checksum
	sum := uint32(0)
	for i := 0; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(hdr[i : i+2]))
	}
	sum = (sum >> 16) + (sum & 0xffff)
	sum += sum >> 16
	return ^uint16(sum)
}

// TestApplyPatches_SrcIP verifies patching src_ip changes the field and
// recomputes IP + L4 checksums.
func TestApplyPatches_SrcIP(t *testing.T) {
	ipA := net.ParseIP("10.0.0.1")
	ipB := net.ParseIP("10.0.0.2")
	frame, layout := buildFrame(t, ipA, ipB, 1234, 80)

	newIP := net.ParseIP("11.0.0.1").To4()
	patches := []Patch{{Field: "src_ip", Offset: layout.SrcIP, Bytes: newIP, Layer: "l3"}}
	out, err := ApplyPatches(frame, patches, layout, "recompute")
	if err != nil {
		t.Fatalf("ApplyPatches: %v", err)
	}
	// src_ip changed to 11.0.0.1.
	gotIP := net.IP(out[layout.SrcIP : layout.SrcIP+4])
	if !gotIP.Equal(newIP) {
		t.Errorf("src_ip = %v, want %v", gotIP, newIP)
	}
	// IP checksum is correct (matches a fresh computation).
	wantCksum := ipChecksum(out, layout.L3Start)
	gotCksum := binary.BigEndian.Uint16(out[layout.L3Start+10 : layout.L3Start+12])
	if wantCksum != gotCksum {
		t.Errorf("IP checksum = 0x%x, want 0x%x", gotCksum, wantCksum)
	}
	// dst_ip unchanged.
	if !net.IP(out[layout.DstIP : layout.DstIP+4]).Equal(ipB.To4()) {
		t.Error("dst_ip changed unexpectedly")
	}
}

// TestApplyPatches_PreserveNoPatch verifies preserve mode + no patches keeps
// original checksums (bad-checksum anomaly preserved).
func TestApplyPatches_PreserveNoPatch(t *testing.T) {
	frame, layout := buildFrame(t, net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2"), 1234, 80)
	// Corrupt the IP checksum to simulate a bad-checksum anomaly.
	badCksum := uint16(0xDEAD)
	binary.BigEndian.PutUint16(frame[layout.L3Start+10:layout.L3Start+12], badCksum)

	out, err := ApplyPatches(frame, nil, layout, "preserve")
	if err != nil {
		t.Fatalf("ApplyPatches: %v", err)
	}
	got := binary.BigEndian.Uint16(out[layout.L3Start+10 : layout.L3Start+12])
	if got != badCksum {
		t.Errorf("preserve mode fixed the bad checksum: got 0x%x, want 0x%x (preserved)", got, badCksum)
	}
}

// TestApplyPatches_PreserveWithPatch verifies preserve mode + an L3 patch
// forces checksum recompute (patched field + stale checksum is contradictory).
func TestApplyPatches_PreserveWithPatch(t *testing.T) {
	frame, layout := buildFrame(t, net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2"), 1234, 80)
	// Corrupt the IP checksum.
	binary.BigEndian.PutUint16(frame[layout.L3Start+10:layout.L3Start+12], 0xDEAD)

	newIP := net.ParseIP("11.0.0.1").To4()
	patches := []Patch{{Field: "src_ip", Offset: layout.SrcIP, Bytes: newIP, Layer: "l3"}}
	out, err := ApplyPatches(frame, patches, layout, "preserve")
	if err != nil {
		t.Fatalf("ApplyPatches: %v", err)
	}
	// Checksum should now be correct (recomputed despite preserve mode).
	wantCksum := ipChecksum(out, layout.L3Start)
	gotCksum := binary.BigEndian.Uint16(out[layout.L3Start+10 : layout.L3Start+12])
	if wantCksum != gotCksum {
		t.Errorf("preserve+patch should recompute: got 0x%x, want 0x%x", gotCksum, wantCksum)
	}
}

// TestApplyPatches_L2NoChecksum verifies an L2 (MAC) patch doesn't trigger
// checksum recompute (preserve mode keeps checksums).
func TestApplyPatches_L2NoChecksum(t *testing.T) {
	frame, layout := buildFrame(t, net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2"), 1234, 80)
	origCksum := binary.BigEndian.Uint16(frame[layout.L3Start+10 : layout.L3Start+12])

	newMAC, _ := net.ParseMAC("cc:cc:cc:cc:cc:cc")
	patches := []Patch{{Field: "dst_mac", Offset: layout.DstMAC, Bytes: newMAC, Layer: "l2"}}
	out, err := ApplyPatches(frame, patches, layout, "preserve")
	if err != nil {
		t.Fatalf("ApplyPatches: %v", err)
	}
	gotCksum := binary.BigEndian.Uint16(out[layout.L3Start+10 : layout.L3Start+12])
	if gotCksum != origCksum {
		t.Errorf("L2 patch changed IP checksum: got 0x%x, want 0x%x (unchanged)", gotCksum, origCksum)
	}
	// MAC changed.
	gotMAC := out[layout.DstMAC : layout.DstMAC+6]
	if string(gotMAC) != string(newMAC) {
		t.Errorf("dst_mac = %x, want %x", gotMAC, newMAC)
	}
}

// TestApplyPatches_OutOfBounds verifies an out-of-bounds patch errors.
func TestApplyPatches_OutOfBounds(t *testing.T) {
	frame, layout := buildFrame(t, net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2"), 1234, 80)
	patches := []Patch{{Field: "src_ip", Offset: len(frame) - 1, Bytes: []byte{1, 2, 3, 4}, Layer: "l3"}}
	_, err := ApplyPatches(frame, patches, layout, "recompute")
	if err == nil {
		t.Error("out-of-bounds patch should error")
	}
}

// buildUDPFrame builds an Eth+IPv4+UDP frame with valid checksums and returns it
// plus its OffsetLayout.
func buildUDPFrame(t *testing.T, srcIP, dstIP net.IP, srcPort, dstPort layers.UDPPort) ([]byte, pcapparser.OffsetLayout) {
	t.Helper()
	macA, _ := net.ParseMAC("aa:aa:aa:aa:aa:aa")
	macB, _ := net.ParseMAC("bb:bb:bb:bb:bb:bb")
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	udp := &layers.UDP{SrcPort: srcPort, DstPort: dstPort}
	ipv4 := &layers.IPv4{SrcIP: srcIP, DstIP: dstIP, Version: 4, TTL: 64, Protocol: layers.IPProtocolUDP}
	udp.SetNetworkLayerForChecksum(ipv4)
	gopacket.SerializeLayers(buf, opts,
		&layers.Ethernet{SrcMAC: macA, DstMAC: macB, EthernetType: layers.EthernetTypeIPv4},
		ipv4, udp, gopacket.Payload([]byte("payload")))
	frame := buf.Bytes()
	pkt := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)
	return frame, pcapparser.ExtractOffsetLayout(pkt)
}

// l4Checksum computes the expected L4 (TCP/UDP) checksum including the IPv4
// pseudo-header, using the same algorithm as setL4Checksum. Does not mutate
// frame.
func l4Checksum(frame []byte, layout pcapparser.OffsetLayout) uint16 {
	l3, l4 := layout.L3Start, layout.L4Start
	if l3 < 0 || l4 < 0 || l4 >= len(frame) {
		return 0
	}
	var cksumOff int
	var proto uint32
	switch layout.L4Protocol {
	case "tcp":
		cksumOff = l4 + 16
		proto = 6
	case "udp":
		cksumOff = l4 + 6
		proto = 17
	default:
		return 0
	}
	if cksumOff+2 > len(frame) {
		return 0
	}
	// Copy and zero the checksum field.
	f := make([]byte, len(frame))
	copy(f, frame)
	binary.BigEndian.PutUint16(f[cksumOff:cksumOff+2], 0)

	l4Len := len(f) - l4
	sum := uint32(0)
	// Pseudo-header: SrcIP(4) + DstIP(4) + zero(1) + proto(1) + L4-length(2).
	sum += uint32(binary.BigEndian.Uint16(f[l3+12 : l3+14]))
	sum += uint32(binary.BigEndian.Uint16(f[l3+14 : l3+16]))
	sum += uint32(binary.BigEndian.Uint16(f[l3+16 : l3+18]))
	sum += uint32(binary.BigEndian.Uint16(f[l3+18 : l3+20]))
	sum += proto
	sum += uint32(l4Len)
	// L4 header + payload (checksum already zeroed).
	for i := 0; i+1 < l4Len; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(f[l4+i : l4+i+2]))
	}
	if l4Len%2 == 1 {
		sum += uint32(f[l4+l4Len-1]) << 8
	}
	sum = (sum >> 16) + (sum & 0xffff)
	sum += sum >> 16
	return ^uint16(sum)
}

// TestApplyPatches_TTL verifies patching TTL changes the byte and recomputes
// the IP checksum.
func TestApplyPatches_TTL(t *testing.T) {
	ipA := net.ParseIP("10.0.0.1")
	ipB := net.ParseIP("10.0.0.2")
	frame, layout := buildFrame(t, ipA, ipB, 1234, 80)

	patches := []Patch{{Field: "ttl", Offset: layout.TTL, Bytes: []byte{128}, Layer: "l3"}}
	out, err := ApplyPatches(frame, patches, layout, "recompute")
	if err != nil {
		t.Fatalf("ApplyPatches: %v", err)
	}
	// TTL changed to 128.
	if out[layout.TTL] != 128 {
		t.Errorf("ttl = %d, want 128", out[layout.TTL])
	}
	// IP checksum correct.
	wantCksum := ipChecksum(out, layout.L3Start)
	gotCksum := binary.BigEndian.Uint16(out[layout.L3Start+10 : layout.L3Start+12])
	if wantCksum != gotCksum {
		t.Errorf("IP checksum = 0x%x, want 0x%x", gotCksum, wantCksum)
	}
}

// TestApplyPatches_DstIP verifies patching dst_ip changes the field and
// recomputes IP + L4 checksums.
func TestApplyPatches_DstIP(t *testing.T) {
	ipA := net.ParseIP("10.0.0.1")
	ipB := net.ParseIP("10.0.0.2")
	frame, layout := buildFrame(t, ipA, ipB, 1234, 80)

	newIP := net.ParseIP("10.99.0.99").To4()
	patches := []Patch{{Field: "dst_ip", Offset: layout.DstIP, Bytes: newIP, Layer: "l3"}}
	out, err := ApplyPatches(frame, patches, layout, "recompute")
	if err != nil {
		t.Fatalf("ApplyPatches: %v", err)
	}
	// dst_ip changed.
	gotIP := net.IP(out[layout.DstIP : layout.DstIP+4])
	if !gotIP.Equal(newIP) {
		t.Errorf("dst_ip = %v, want %v", gotIP, newIP)
	}
	// IP checksum correct.
	wantIP := ipChecksum(out, layout.L3Start)
	gotIPcksum := binary.BigEndian.Uint16(out[layout.L3Start+10 : layout.L3Start+12])
	if wantIP != gotIPcksum {
		t.Errorf("IP checksum = 0x%x, want 0x%x", gotIPcksum, wantIP)
	}
	// src_ip unchanged.
	if !net.IP(out[layout.SrcIP : layout.SrcIP+4]).Equal(ipA.To4()) {
		t.Error("src_ip changed unexpectedly")
	}
	// L4 checksum correct (pseudo-header changed).
	wantL4 := l4Checksum(out, layout)
	gotL4 := binary.BigEndian.Uint16(out[layout.L4Start+16 : layout.L4Start+18])
	if wantL4 != gotL4 {
		t.Errorf("L4 checksum = 0x%x, want 0x%x", gotL4, wantL4)
	}
}

// TestApplyPatches_SrcPort verifies patching src_port to 5000 updates the
// 2-byte field and recomputes the L4 checksum.
func TestApplyPatches_SrcPort(t *testing.T) {
	ipA := net.ParseIP("10.0.0.1")
	ipB := net.ParseIP("10.0.0.2")
	frame, layout := buildFrame(t, ipA, ipB, 1234, 80)

	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, 5000)
	patches := []Patch{{Field: "src_port", Offset: layout.SrcPort, Bytes: portBytes, Layer: "l4"}}
	out, err := ApplyPatches(frame, patches, layout, "recompute")
	if err != nil {
		t.Fatalf("ApplyPatches: %v", err)
	}
	// src_port changed to 5000.
	gotPort := binary.BigEndian.Uint16(out[layout.SrcPort : layout.SrcPort+2])
	if gotPort != 5000 {
		t.Errorf("src_port = %d, want 5000", gotPort)
	}
	// L4 checksum correct.
	wantL4 := l4Checksum(out, layout)
	gotL4 := binary.BigEndian.Uint16(out[layout.L4Start+16 : layout.L4Start+18])
	if wantL4 != gotL4 {
		t.Errorf("L4 checksum = 0x%x, want 0x%x", gotL4, wantL4)
	}
	// dst_port unchanged.
	gotDst := binary.BigEndian.Uint16(out[layout.DstPort : layout.DstPort+2])
	if gotDst != 80 {
		t.Errorf("dst_port = %d, want 80", gotDst)
	}
}

// TestApplyPatches_DSCP verifies patching DSCP=32 sets the TOS byte to 0x80
// and recomputes the IP checksum.
func TestApplyPatches_DSCP(t *testing.T) {
	ipA := net.ParseIP("10.0.0.1")
	ipB := net.ParseIP("10.0.0.2")
	frame, layout := buildFrame(t, ipA, ipB, 1234, 80)

	// DSCP 32 -> TOS byte bits 7-2: 0x80.
	patches := []Patch{{Field: "dscp", Offset: layout.DSCPECN, Bytes: []byte{0x80}, Layer: "l3"}}
	out, err := ApplyPatches(frame, patches, layout, "recompute")
	if err != nil {
		t.Fatalf("ApplyPatches: %v", err)
	}
	// TOS byte is 0x80.
	if out[layout.DSCPECN] != 0x80 {
		t.Errorf("TOS byte = 0x%02x, want 0x80", out[layout.DSCPECN])
	}
	// IP checksum correct.
	wantCksum := ipChecksum(out, layout.L3Start)
	gotCksum := binary.BigEndian.Uint16(out[layout.L3Start+10 : layout.L3Start+12])
	if wantCksum != gotCksum {
		t.Errorf("IP checksum = 0x%x, want 0x%x", gotCksum, wantCksum)
	}
}

// TestApplyPatches_ECN verifies patching ECN=3 sets the TOS byte low 2 bits
// to 3 and recomputes the IP checksum.
func TestApplyPatches_ECN(t *testing.T) {
	ipA := net.ParseIP("10.0.0.1")
	ipB := net.ParseIP("10.0.0.2")
	frame, layout := buildFrame(t, ipA, ipB, 1234, 80)

	// ECN 3 -> TOS byte bits 1-0: 0x03.
	patches := []Patch{{Field: "ecn", Offset: layout.DSCPECN, Bytes: []byte{0x03}, Layer: "l3"}}
	out, err := ApplyPatches(frame, patches, layout, "recompute")
	if err != nil {
		t.Fatalf("ApplyPatches: %v", err)
	}
	// TOS byte low 2 bits = 3.
	if out[layout.DSCPECN] != 0x03 {
		t.Errorf("TOS byte = 0x%02x, want 0x03", out[layout.DSCPECN])
	}
	// IP checksum correct.
	wantCksum := ipChecksum(out, layout.L3Start)
	gotCksum := binary.BigEndian.Uint16(out[layout.L3Start+10 : layout.L3Start+12])
	if wantCksum != gotCksum {
		t.Errorf("IP checksum = 0x%x, want 0x%x", gotCksum, wantCksum)
	}
}

// TestApplyPatches_Seq verifies patching the sequence number changes the
// 4-byte field and recomputes the L4 checksum.
func TestApplyPatches_Seq(t *testing.T) {
	ipA := net.ParseIP("10.0.0.1")
	ipB := net.ParseIP("10.0.0.2")
	frame, layout := buildFrame(t, ipA, ipB, 1234, 80)

	seqBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(seqBytes, 0xDEADBEEF)
	patches := []Patch{{Field: "seq", Offset: layout.Seq, Bytes: seqBytes, Layer: "l4"}}
	out, err := ApplyPatches(frame, patches, layout, "recompute")
	if err != nil {
		t.Fatalf("ApplyPatches: %v", err)
	}
	// Seq changed.
	gotSeq := binary.BigEndian.Uint32(out[layout.Seq : layout.Seq+4])
	if gotSeq != 0xDEADBEEF {
		t.Errorf("seq = 0x%08x, want 0xDEADBEEF", gotSeq)
	}
	// L4 checksum correct.
	wantL4 := l4Checksum(out, layout)
	gotL4 := binary.BigEndian.Uint16(out[layout.L4Start+16 : layout.L4Start+18])
	if wantL4 != gotL4 {
		t.Errorf("L4 checksum = 0x%x, want 0x%x", gotL4, wantL4)
	}
}

// TestApplyPatches_TCPFlags verifies patching tcp_flags to FIN|ACK (0x11)
// changes the byte and recomputes the L4 checksum.
func TestApplyPatches_TCPFlags(t *testing.T) {
	ipA := net.ParseIP("10.0.0.1")
	ipB := net.ParseIP("10.0.0.2")
	frame, layout := buildFrame(t, ipA, ipB, 1234, 80)

	patches := []Patch{{Field: "tcp_flags", Offset: layout.TCPFlags, Bytes: []byte{0x11}, Layer: "l4"}}
	out, err := ApplyPatches(frame, patches, layout, "recompute")
	if err != nil {
		t.Fatalf("ApplyPatches: %v", err)
	}
	// TCP flags = FIN|ACK = 0x11.
	if out[layout.TCPFlags] != 0x11 {
		t.Errorf("tcp_flags = 0x%02x, want 0x11", out[layout.TCPFlags])
	}
	// L4 checksum correct.
	wantL4 := l4Checksum(out, layout)
	gotL4 := binary.BigEndian.Uint16(out[layout.L4Start+16 : layout.L4Start+18])
	if wantL4 != gotL4 {
		t.Errorf("L4 checksum = 0x%x, want 0x%x", gotL4, wantL4)
	}
}

// TestApplyPatches_IPID verifies patching ip_id to 0xABCD changes the 2-byte
// field and recomputes the IP checksum.
func TestApplyPatches_IPID(t *testing.T) {
	ipA := net.ParseIP("10.0.0.1")
	ipB := net.ParseIP("10.0.0.2")
	frame, layout := buildFrame(t, ipA, ipB, 1234, 80)

	idBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(idBytes, 0xABCD)
	patches := []Patch{{Field: "ip_id", Offset: layout.IPID, Bytes: idBytes, Layer: "l3"}}
	out, err := ApplyPatches(frame, patches, layout, "recompute")
	if err != nil {
		t.Fatalf("ApplyPatches: %v", err)
	}
	// IP ID changed.
	gotID := binary.BigEndian.Uint16(out[layout.IPID : layout.IPID+2])
	if gotID != 0xABCD {
		t.Errorf("ip_id = 0x%04x, want 0xABCD", gotID)
	}
	// IP checksum correct.
	wantCksum := ipChecksum(out, layout.L3Start)
	gotCksum := binary.BigEndian.Uint16(out[layout.L3Start+10 : layout.L3Start+12])
	if wantCksum != gotCksum {
		t.Errorf("IP checksum = 0x%x, want 0x%x", gotCksum, wantCksum)
	}
}

// TestApplyPatches_MultiplePatches verifies combining src_ip + dst_port + ttl
// patches produces correct fields and correct IP + L4 checksums.
func TestApplyPatches_MultiplePatches(t *testing.T) {
	ipA := net.ParseIP("10.0.0.1")
	ipB := net.ParseIP("10.0.0.2")
	frame, layout := buildFrame(t, ipA, ipB, 1234, 80)

	newIP := net.ParseIP("11.0.0.1").To4()
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, 9090)
	patches := []Patch{
		{Field: "src_ip", Offset: layout.SrcIP, Bytes: newIP, Layer: "l3"},
		{Field: "dst_port", Offset: layout.DstPort, Bytes: portBytes, Layer: "l4"},
		{Field: "ttl", Offset: layout.TTL, Bytes: []byte{200}, Layer: "l3"},
	}
	out, err := ApplyPatches(frame, patches, layout, "recompute")
	if err != nil {
		t.Fatalf("ApplyPatches: %v", err)
	}
	// src_ip changed.
	gotIP := net.IP(out[layout.SrcIP : layout.SrcIP+4])
	if !gotIP.Equal(newIP) {
		t.Errorf("src_ip = %v, want %v", gotIP, newIP)
	}
	// dst_port changed.
	gotPort := binary.BigEndian.Uint16(out[layout.DstPort : layout.DstPort+2])
	if gotPort != 9090 {
		t.Errorf("dst_port = %d, want 9090", gotPort)
	}
	// ttl changed.
	if out[layout.TTL] != 200 {
		t.Errorf("ttl = %d, want 200", out[layout.TTL])
	}
	// IP checksum correct.
	wantIP := ipChecksum(out, layout.L3Start)
	gotIPcksum := binary.BigEndian.Uint16(out[layout.L3Start+10 : layout.L3Start+12])
	if wantIP != gotIPcksum {
		t.Errorf("IP checksum = 0x%x, want 0x%x", gotIPcksum, wantIP)
	}
	// L4 checksum correct (dst_port changed + pseudo-header changed from src_ip).
	wantL4 := l4Checksum(out, layout)
	gotL4 := binary.BigEndian.Uint16(out[layout.L4Start+16 : layout.L4Start+18])
	if wantL4 != gotL4 {
		t.Errorf("L4 checksum = 0x%x, want 0x%x", gotL4, wantL4)
	}
}

// TestApplyPatches_NoPatches_Recompute verifies empty patches with recompute
// mode fixes corrupted checksums.
func TestApplyPatches_NoPatches_Recompute(t *testing.T) {
	ipA := net.ParseIP("10.0.0.1")
	ipB := net.ParseIP("10.0.0.2")
	frame, layout := buildFrame(t, ipA, ipB, 1234, 80)

	// Corrupt both checksums.
	binary.BigEndian.PutUint16(frame[layout.L3Start+10:layout.L3Start+12], 0xAAAA)
	binary.BigEndian.PutUint16(frame[layout.L4Start+16:layout.L4Start+18], 0xBBBB)

	out, err := ApplyPatches(frame, nil, layout, "recompute")
	if err != nil {
		t.Fatalf("ApplyPatches: %v", err)
	}
	// IP checksum fixed.
	wantIP := ipChecksum(out, layout.L3Start)
	gotIP := binary.BigEndian.Uint16(out[layout.L3Start+10 : layout.L3Start+12])
	if wantIP != gotIP {
		t.Errorf("IP checksum = 0x%x, want 0x%x (should be fixed)", gotIP, wantIP)
	}
	// L4 checksum fixed.
	wantL4 := l4Checksum(out, layout)
	gotL4 := binary.BigEndian.Uint16(out[layout.L4Start+16 : layout.L4Start+18])
	if wantL4 != gotL4 {
		t.Errorf("L4 checksum = 0x%x, want 0x%x (should be fixed)", gotL4, wantL4)
	}
	// Frame bytes (besides checksum fields) unchanged.
	for i := range frame {
		if i == layout.L3Start+10 || i == layout.L3Start+11 || i == layout.L4Start+16 || i == layout.L4Start+17 {
			continue
		}
		if out[i] != frame[i] {
			t.Errorf("byte %d changed from 0x%02x to 0x%02x", i, frame[i], out[i])
		}
	}
}

// TestApplyPatches_NoPatches_PreserveEmpty verifies empty patches with
// preserve mode keeps corrupted checksums intact.
func TestApplyPatches_NoPatches_PreserveEmpty(t *testing.T) {
	ipA := net.ParseIP("10.0.0.1")
	ipB := net.ParseIP("10.0.0.2")
	frame, layout := buildFrame(t, ipA, ipB, 1234, 80)

	// Corrupt both checksums.
	binary.BigEndian.PutUint16(frame[layout.L3Start+10:layout.L3Start+12], 0xAAAA)
	binary.BigEndian.PutUint16(frame[layout.L4Start+16:layout.L4Start+18], 0xBBBB)

	out, err := ApplyPatches(frame, nil, layout, "preserve")
	if err != nil {
		t.Fatalf("ApplyPatches: %v", err)
	}
	// IP checksum preserved (still corrupted).
	gotIP := binary.BigEndian.Uint16(out[layout.L3Start+10 : layout.L3Start+12])
	if gotIP != 0xAAAA {
		t.Errorf("IP checksum = 0x%x, want 0xAAAA (preserved)", gotIP)
	}
	// L4 checksum preserved (still corrupted).
	gotL4 := binary.BigEndian.Uint16(out[layout.L4Start+16 : layout.L4Start+18])
	if gotL4 != 0xBBBB {
		t.Errorf("L4 checksum = 0x%x, want 0xBBBB (preserved)", gotL4)
	}
	// All bytes unchanged.
	for i := range frame {
		if out[i] != frame[i] {
			t.Errorf("byte %d changed from 0x%02x to 0x%02x", i, frame[i], out[i])
		}
	}
}

// TestApplyPatches_UDP verifies patching src_ip in a UDP frame produces
// correct fields and correct IP + UDP checksums.
func TestApplyPatches_UDP(t *testing.T) {
	ipA := net.ParseIP("10.0.0.1")
	ipB := net.ParseIP("10.0.0.2")
	frame, layout := buildUDPFrame(t, ipA, ipB, 1234, 80)

	if layout.L4Protocol != "udp" {
		t.Fatalf("expected UDP frame, got L4Protocol=%q", layout.L4Protocol)
	}

	newIP := net.ParseIP("11.0.0.1").To4()
	patches := []Patch{{Field: "src_ip", Offset: layout.SrcIP, Bytes: newIP, Layer: "l3"}}
	out, err := ApplyPatches(frame, patches, layout, "recompute")
	if err != nil {
		t.Fatalf("ApplyPatches: %v", err)
	}
	// src_ip changed.
	gotIP := net.IP(out[layout.SrcIP : layout.SrcIP+4])
	if !gotIP.Equal(newIP) {
		t.Errorf("src_ip = %v, want %v", gotIP, newIP)
	}
	// IP checksum correct.
	wantIP := ipChecksum(out, layout.L3Start)
	gotIPcksum := binary.BigEndian.Uint16(out[layout.L3Start+10 : layout.L3Start+12])
	if wantIP != gotIPcksum {
		t.Errorf("IP checksum = 0x%x, want 0x%x", gotIPcksum, wantIP)
	}
	// UDP checksum correct (pseudo-header changed from src_ip).
	wantUDP := l4Checksum(out, layout)
	gotUDP := binary.BigEndian.Uint16(out[layout.L4Start+6 : layout.L4Start+8])
	if wantUDP != gotUDP {
		t.Errorf("UDP checksum = 0x%x, want 0x%x", gotUDP, wantUDP)
	}
	// dst_ip unchanged.
	if !net.IP(out[layout.DstIP : layout.DstIP+4]).Equal(ipB.To4()) {
		t.Error("dst_ip changed unexpectedly")
	}
}
