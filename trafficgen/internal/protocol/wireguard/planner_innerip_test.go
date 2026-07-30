package wireguard

import (
	"context"
	"encoding/binary"
	"sync"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

// ===================================================================
// Inner IP tunnel scenario tests (Transport Data carries a complete
// inner IPv4/IPv6 packet).
//
// Spec reference: WireGuard whitepaper §3 (Transport Data type=4,
// enc_payload = encrypted IP packet), §6 (transport), design_wireguard.md
// §2.5 (enc_payload 16+N bytes = encrypted inner IPv4/IPv6), §4 scenario 12
// (IPv6 inner packet), §4 scenario 3 (bidirectional data), §4 scenario 7
// (large payload). RFC 791 (IPv4 header + checksum), RFC 8200 (IPv6 header),
// RFC 768 (UDP), RFC 793 (TCP), RFC 792 (ICMP).
//
// These tests verify the dual-encapsulation (outer UDP/WG + inner IP) byte
// structure: the inner IP header sits at enc_payload offset 16 of the
// Transport Data message.
// ===================================================================

// innerSpec returns a valid FlowSpec with InnerIP configured for IPv4/UDP.
func innerSpec() core.FlowSpec {
	return core.FlowSpec{
		SrcMAC:   "02:00:00:00:00:01",
		DstMAC:   "02:00:00:00:00:02",
		SrcIP:    "192.0.2.1",
		DstIP:    "192.0.2.2",
		SrcPort:  50000,
		DstPort:  DefaultPort,
		WireGuard: &core.WireGuardConfig{
			Role:        "initiator",
			SenderIndex: 1,
			InnerIP: &core.WireGuardInnerIP{
				SrcIP:   "10.10.10.1",
				DstIP:   "10.10.10.2",
				Proto:   17, // UDP
				SrcPort: 12345,
				DstPort: 53,
				Payload: []byte("hello-wg"),
			},
		},
	}
}

// wgInnerIPv4Checksum computes the IPv4 header checksum (RFC 791) over a
// 20-byte header with the checksum field zeroed. Used by tests to verify
// the planner produced a valid checksum.
func wgInnerIPv4Checksum(hdr []byte) uint16 {
	if len(hdr) < 20 {
		return 0
	}
	sum := uint32(0)
	for i := 0; i+1 < 20; i += 2 {
		// Zero the checksum field at [10:12].
		if i == 10 {
			continue
		}
		sum += uint32(binary.BigEndian.Uint16(hdr[i : i+2]))
	}
	for sum>>16 != 0 {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}

// wgInnerIPv4ChecksumRaw computes the one's-complement checksum over an
// arbitrary byte buffer (the whole buffer participates, no zeroed field).
// Used by tests to recompute L4 checksums over a pseudo-header+L4 buffer
// where the checksum field has already been zeroed by the caller.
func wgInnerIPv4ChecksumRaw(b []byte) uint16 {
	sum := uint32(0)
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}

// --- IPv4 inner packet structure tests ---

// Test 1: InnerIP set produces a Transport Data message whose enc_payload
// begins with a complete IPv4 header (version=4, IHL=5). This is the
// dual-encapsulation observable: outer WG type=4 + inner IPv4 0x45.
func TestWireGuard_InnerIPv4_TransportEncPayloadIsIPv4(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, innerSpec()))
	// handshake(2) + transport(1) = 3 packets.
	if len(cfgs) != 3 {
		t.Fatalf("packet count = %d, want 3", len(cfgs))
	}
	trans := cfgs[2]
	if trans.Payload[0] != MsgTransportData {
		t.Fatalf("transport message_type=%d, want 4", trans.Payload[0])
	}
	// enc_payload starts at offset 16. First byte = IPv4 version/IHL = 0x45.
	if got := trans.Payload[16]; got != 0x45 {
		t.Errorf("enc_payload[0]=%02x, want 0x45 (IPv4 version=4 IHL=5)", got)
	}
}

// Test 2: Inner IPv4 header checksum is correct (RFC 791 §3.1).
func TestWireGuard_InnerIPv4_HeaderChecksumCorrect(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, innerSpec()))
	trans := cfgs[2]
	innerHdr := trans.Payload[16 : 16+20]
	stored := binary.BigEndian.Uint16(innerHdr[10:12])
	computed := wgInnerIPv4Checksum(innerHdr)
	if stored != computed {
		t.Errorf("inner IPv4 checksum=%04x, want %04x (recomputed)", stored, computed)
	}
}

// Test 3: Inner IPv4 header proto field matches configured Proto (17=UDP).
func TestWireGuard_InnerIPv4_ProtoField(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, innerSpec()))
	trans := cfgs[2]
	innerHdr := trans.Payload[16 : 16+20]
	if innerHdr[9] != 17 {
		t.Errorf("inner IPv4 proto=%d, want 17 (UDP)", innerHdr[9])
	}
}

// Test 4: Inner IPv4 src/dst addresses match config.
func TestWireGuard_InnerIPv4_Addresses(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, innerSpec()))
	trans := cfgs[2]
	innerHdr := trans.Payload[16 : 16+20]
	// SrcIP at [12:16] = 10.10.10.1
	if innerHdr[12] != 10 || innerHdr[13] != 10 || innerHdr[14] != 10 || innerHdr[15] != 1 {
		t.Errorf("inner srcIP=%d.%d.%d.%d, want 10.10.10.1",
			innerHdr[12], innerHdr[13], innerHdr[14], innerHdr[15])
	}
	// DstIP at [16:20] = 10.10.10.2
	if innerHdr[16] != 10 || innerHdr[17] != 10 || innerHdr[18] != 10 || innerHdr[19] != 2 {
		t.Errorf("inner dstIP=%d.%d.%d.%d, want 10.10.10.2",
			innerHdr[16], innerHdr[17], innerHdr[18], innerHdr[19])
	}
}

// Test 5: Inner IPv4 UDP L4 header (8 bytes) follows the IP header.
func TestWireGuard_InnerIPv4_UDPHeader(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, innerSpec()))
	trans := cfgs[2]
	// IP header (20) + UDP header (8) at offset 16+20=36.
	udpOff := 16 + 20
	srcPort := binary.BigEndian.Uint16(trans.Payload[udpOff : udpOff+2])
	dstPort := binary.BigEndian.Uint16(trans.Payload[udpOff+2 : udpOff+4])
	if srcPort != 12345 {
		t.Errorf("inner UDP srcPort=%d, want 12345", srcPort)
	}
	if dstPort != 53 {
		t.Errorf("inner UDP dstPort=%d, want 53", dstPort)
	}
	udpLen := binary.BigEndian.Uint16(trans.Payload[udpOff+4 : udpOff+6])
	// 8-byte UDP header + len("hello-wg")=8 -> 16
	if udpLen != 16 {
		t.Errorf("inner UDP length=%d, want 16", udpLen)
	}
}

// Test 6: Inner IPv4 TCP L4 header (20 bytes, data offset 5).
func TestWireGuard_InnerIPv4_TCPHeader(t *testing.T) {
	p := NewPlanner()
	spec := innerSpec()
	spec.WireGuard.InnerIP.Proto = 6 // TCP
	spec.WireGuard.InnerIP.SrcPort = 1000
	spec.WireGuard.InnerIP.DstPort = 80
	cfgs := drain(mustPlan(t, p, spec))
	trans := cfgs[2]
	tcpOff := 16 + 20
	srcPort := binary.BigEndian.Uint16(trans.Payload[tcpOff : tcpOff+2])
	dstPort := binary.BigEndian.Uint16(trans.Payload[tcpOff+2 : tcpOff+4])
	if srcPort != 1000 {
		t.Errorf("inner TCP srcPort=%d, want 1000", srcPort)
	}
	if dstPort != 80 {
		t.Errorf("inner TCP dstPort=%d, want 80", dstPort)
	}
	// Data offset at byte 12 of TCP header = 5 (20 bytes) -> 0x50.
	if trans.Payload[tcpOff+12] != 0x50 {
		t.Errorf("inner TCP data offset=%02x, want 0x50", trans.Payload[tcpOff+12])
	}
	// TCP checksum (mandatory, RFC 793) at [16:18] must be non-zero.
	// Verify it is correct by recomputing over the L4 with the IPv4
	// pseudo-header (SrcIP+DstIP from the inner IPv4 header).
	tcpCksum := binary.BigEndian.Uint16(trans.Payload[tcpOff+16 : tcpOff+18])
	if tcpCksum == 0 {
		t.Error("inner TCP checksum is 0, expected non-zero (mandatory over IPv4)")
	}
}

// Test 6b: Inner IPv4 TCP checksum is correct (RFC 793, IPv4 pseudo-header).
func TestWireGuard_InnerIPv4_TCPChecksumCorrect(t *testing.T) {
	p := NewPlanner()
	spec := innerSpec()
	spec.WireGuard.InnerIP.Proto = 6
	spec.WireGuard.InnerIP.SrcPort = 1000
	spec.WireGuard.InnerIP.DstPort = 80
	spec.WireGuard.InnerIP.Payload = []byte("data")
	cfgs := drain(mustPlan(t, p, spec))
	trans := cfgs[2]
	ipHdr := trans.Payload[16 : 16+20]
	tcpOff := 16 + 20
	tcpLen := 20 + 4 // 20-byte TCP header + 4-byte payload
	tcpSeg := trans.Payload[tcpOff : tcpOff+tcpLen]
	stored := binary.BigEndian.Uint16(tcpSeg[16:18])
	// Recompute with IPv4 pseudo-header: SrcIP(4) + DstIP(4) + zero(1) +
	// proto(1) + L4-len(2).
	pseudo := make([]byte, 12+tcpLen)
	copy(pseudo[0:4], ipHdr[12:16]) // src IP
	copy(pseudo[4:8], ipHdr[16:20]) // dst IP
	pseudo[9] = 6                   // TCP
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(tcpLen))
	// Zero the checksum field in the copy.
	copy(pseudo[12:], tcpSeg)
	pseudo[12+16] = 0
	pseudo[12+17] = 0
	computed := wgInnerIPv4ChecksumRaw(pseudo)
	if stored != computed {
		t.Errorf("inner TCP checksum=%04x, want %04x (recomputed with IPv4 pseudo-header)", stored, computed)
	}
}

// Test 6c: Inner IPv6 UDP checksum is correct (mandatory over IPv6, RFC 8200 §8.1).
func TestWireGuard_InnerIPv6_UDPChecksumCorrect(t *testing.T) {
	p := NewPlanner()
	spec := innerSpec()
	spec.WireGuard.InnerIP.SrcIP = "2001:db8:1::1"
	spec.WireGuard.InnerIP.DstIP = "2001:db8:2::2"
	cfgs := drain(mustPlan(t, p, spec))
	trans := cfgs[2]
	v6Hdr := trans.Payload[16 : 16+40]
	udpOff := 16 + 40
	udpLen := 8 + len("hello-wg")
	udpSeg := trans.Payload[udpOff : udpOff+udpLen]
	stored := binary.BigEndian.Uint16(udpSeg[6:8])
	// IPv6 pseudo-header: SrcIP(16) + DstIP(16) + UpperLayerLen(4) + zero(3) + NextHeader(1)
	pseudo := make([]byte, 40+udpLen)
	copy(pseudo[0:16], v6Hdr[8:24])   // src IP
	copy(pseudo[16:32], v6Hdr[24:40]) // dst IP
	binary.BigEndian.PutUint32(pseudo[32:36], uint32(udpLen))
	pseudo[39] = 17 // UDP
	copy(pseudo[40:], udpSeg)
	pseudo[40+6] = 0
	pseudo[40+7] = 0
	computed := wgInnerIPv4ChecksumRaw(pseudo)
	if stored != computed {
		t.Errorf("inner IPv6 UDP checksum=%04x, want %04x (recomputed with IPv6 pseudo-header)", stored, computed)
	}
}

// Test 7: Inner IPv4 ICMP echo header (8 bytes, type=8 echo request).
func TestWireGuard_InnerIPv4_ICMPHeader(t *testing.T) {
	p := NewPlanner()
	spec := innerSpec()
	spec.WireGuard.InnerIP.Proto = 1 // ICMP
	cfgs := drain(mustPlan(t, p, spec))
	trans := cfgs[2]
	icmpOff := 16 + 20
	if trans.Payload[icmpOff] != 8 {
		t.Errorf("inner ICMP type=%d, want 8 (echo request)", trans.Payload[icmpOff])
	}
}

// --- IPv6 inner packet structure tests ---

// Test 8: InnerIP with IPv6 addresses produces inner IPv6 packet
// (version=6, 40-byte header).
func TestWireGuard_InnerIPv6_VersionAndHeader(t *testing.T) {
	p := NewPlanner()
	spec := innerSpec()
	spec.WireGuard.InnerIP.SrcIP = "2001:db8:1::1"
	spec.WireGuard.InnerIP.DstIP = "2001:db8:2::2"
	cfgs := drain(mustPlan(t, p, spec))
	trans := cfgs[2]
	// enc_payload[0] = IPv6 version/TC high nibble = 0x60 (version=6).
	if got := trans.Payload[16]; got != 0x60 {
		t.Errorf("inner IPv6 first byte=%02x, want 0x60 (version=6)", got)
	}
	// NextHeader at offset 16+6 = 22 should be Proto (17=UDP).
	if trans.Payload[22] != 17 {
		t.Errorf("inner IPv6 NextHeader=%d, want 17 (UDP)", trans.Payload[22])
	}
	// HopLimit at offset 16+7 = 23 should be 64 (default TTL).
	if trans.Payload[23] != 64 {
		t.Errorf("inner IPv6 HopLimit=%d, want 64", trans.Payload[23])
	}
}

// Test 9: Inner IPv6 src/dst addresses match config.
func TestWireGuard_InnerIPv6_Addresses(t *testing.T) {
	p := NewPlanner()
	spec := innerSpec()
	spec.WireGuard.InnerIP.SrcIP = "2001:db8:1::1"
	spec.WireGuard.InnerIP.DstIP = "2001:db8:2::2"
	cfgs := drain(mustPlan(t, p, spec))
	trans := cfgs[2]
	// SrcIP at [16+8 : 16+24] = 16 bytes.
	src := trans.Payload[24 : 40]
	// 2001:db8:1::1 -> bytes: 20 01 0d b8 00 01 00 00 00 00 00 00 00 00 00 01
	wantSrc := []byte{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}
	for i, b := range wantSrc {
		if src[i] != b {
			t.Errorf("inner IPv6 src[%d]=%02x, want %02x", i, src[i], b)
		}
	}
}

// --- Complete tunnel scenario tests ---

// Test 10: Complete tunnel: Handshake Init -> Response -> Transport(inner IPv4)
// -> Keepalive. The full "握手+数据面+保活" flow (spec scenario 1+3+5).
func TestWireGuard_InnerIP_CompleteTunnelScenario(t *testing.T) {
	p := NewPlanner()
	spec := innerSpec()
	spec.WireGuard.KeepaliveInterval = 10
	cfgs := drain(mustPlan(t, p, spec))
	// Init(up) + Response(down) + Transport(up, inner IPv4) + Keepalive(up)
	if len(cfgs) != 4 {
		t.Fatalf("packet count = %d, want 4 (handshake + transport + keepalive)", len(cfgs))
	}
	if cfgs[0].Payload[0] != MsgHandshakeInitiation {
		t.Errorf("cfgs[0] type=%d, want 1 (init)", cfgs[0].Payload[0])
	}
	if cfgs[1].Payload[0] != MsgHandshakeResponse {
		t.Errorf("cfgs[1] type=%d, want 2 (response)", cfgs[1].Payload[0])
	}
	if cfgs[2].Payload[0] != MsgTransportData {
		t.Errorf("cfgs[2] type=%d, want 4 (transport)", cfgs[2].Payload[0])
	}
	// Transport carries inner IPv4.
	if cfgs[2].Payload[16] != 0x45 {
		t.Errorf("transport enc_payload[0]=%02x, want 0x45 (inner IPv4)", cfgs[2].Payload[16])
	}
	// Keepalive: 32 bytes, type=4, counter=1.
	if cfgs[3].Payload[0] != MsgTransportData {
		t.Errorf("cfgs[3] type=%d, want 4 (keepalive)", cfgs[3].Payload[0])
	}
	if len(cfgs[3].Payload) != 32 {
		t.Errorf("keepalive length=%d, want 32", len(cfgs[3].Payload))
	}
	kc := binary.LittleEndian.Uint64(cfgs[3].Payload[8:16])
	if kc != 1 {
		t.Errorf("keepalive counter=%d, want 1", kc)
	}
}

// Test 11: Multiple Transport Data messages (DataFrames=3) carrying inner
// IPv4 packets, each with distinct IPID and incrementing counter (spec
// scenario 3 bidirectional, §4 scenario 7 large payload multi-packet).
func TestWireGuard_InnerIP_MultiTransportDataFrames(t *testing.T) {
	p := NewPlanner()
	spec := innerSpec()
	spec.WireGuard.InnerIP.DataFrames = 3
	cfgs := drain(mustPlan(t, p, spec))
	// handshake(2) + transport(3) = 5 packets.
	if len(cfgs) != 5 {
		t.Fatalf("packet count = %d, want 5", len(cfgs))
	}
	ipids := make(map[uint16]bool)
	counters := make([]uint64, 0, 3)
	for i := 0; i < 3; i++ {
		trans := cfgs[2+i]
		if trans.Payload[0] != MsgTransportData {
			t.Errorf("transport[%d] type=%d, want 4", i, trans.Payload[0])
		}
		// Inner IPv4 IPID at offset 16+4 = 20.
		ipid := binary.BigEndian.Uint16(trans.Payload[20 : 20+2])
		if ipids[ipid] {
			t.Errorf("transport[%d] IPID=%d is duplicate", i, ipid)
		}
		ipids[ipid] = true
		counter := binary.LittleEndian.Uint64(trans.Payload[8:16])
		counters = append(counters, counter)
	}
	// Counters must be strictly increasing: 0, 1, 2.
	for i, c := range counters {
		if c != uint64(i) {
			t.Errorf("transport[%d] counter=%d, want %d", i, c, i)
		}
	}
}

// --- Precedence tests ---

// Test 12: InnerIP takes precedence over TransportPayloads.
func TestWireGuard_InnerIP_PrecedenceOverTransportPayloads(t *testing.T) {
	p := NewPlanner()
	spec := innerSpec()
	spec.WireGuard.TransportPayloads = [][]byte{{0xDE, 0xAD, 0xBE, 0xEF}}
	cfgs := drain(mustPlan(t, p, spec))
	trans := cfgs[2]
	// enc_payload[0] should be 0x45 (inner IPv4), NOT 0xDE.
	if trans.Payload[16] != 0x45 {
		t.Errorf("enc_payload[0]=%02x, want 0x45 (InnerIP wins over TransportPayloads)", trans.Payload[16])
	}
}

// Test 13: FileSource takes precedence over InnerIP (when cache injected).
// FileSource precedence is already covered by existing tests; here we just
// verify InnerIP alone works when FileSource is nil (the common path).
func TestWireGuard_InnerIP_NoFileSource(t *testing.T) {
	p := NewPlanner()
	spec := innerSpec()
	if spec.WireGuard.FileSource != nil {
		t.Fatal("test setup: FileSource should be nil")
	}
	cfgs := drain(mustPlan(t, p, spec))
	trans := cfgs[2]
	if trans.Payload[16] != 0x45 {
		t.Errorf("enc_payload[0]=%02x, want 0x45 (inner IPv4 with no FileSource)", trans.Payload[16])
	}
}

// --- Validation tests ---

// Test 14: InnerIP with invalid SrcIP is rejected.
func TestWireGuard_InnerIP_Validate_InvalidSrcIP(t *testing.T) {
	p := NewPlanner()
	spec := innerSpec()
	spec.WireGuard.InnerIP.SrcIP = "not-an-ip"
	if err := p.Validate(spec); err == nil {
		t.Error("expected error for invalid InnerIP.SrcIP, got nil")
	}
}

// Test 15: InnerIP with invalid DstIP is rejected.
func TestWireGuard_InnerIP_Validate_InvalidDstIP(t *testing.T) {
	p := NewPlanner()
	spec := innerSpec()
	spec.WireGuard.InnerIP.DstIP = "999.999.999.999"
	if err := p.Validate(spec); err == nil {
		t.Error("expected error for invalid InnerIP.DstIP, got nil")
	}
}

// Test 16: InnerIP with unsupported proto is rejected.
func TestWireGuard_InnerIP_Validate_InvalidProto(t *testing.T) {
	p := NewPlanner()
	spec := innerSpec()
	spec.WireGuard.InnerIP.Proto = 99 // not 1/6/17
	if err := p.Validate(spec); err == nil {
		t.Error("expected error for invalid InnerIP.Proto=99, got nil")
	}
}

// Test 17: InnerIP with mismatched address families (SrcIPv4, DstIPv6) rejected.
func TestWireGuard_InnerIP_Validate_MixedAddressFamilies(t *testing.T) {
	p := NewPlanner()
	spec := innerSpec()
	spec.WireGuard.InnerIP.SrcIP = "10.10.10.1"
	spec.WireGuard.InnerIP.DstIP = "2001:db8::2"
	if err := p.Validate(spec); err == nil {
		t.Error("expected error for mixed IPv4/IPv6 InnerIP addresses, got nil")
	}
}

// Test 18: InnerIP with negative DataFrames is rejected.
func TestWireGuard_InnerIP_Validate_NegativeDataFrames(t *testing.T) {
	p := NewPlanner()
	spec := innerSpec()
	spec.WireGuard.InnerIP.DataFrames = -1
	if err := p.Validate(spec); err == nil {
		t.Error("expected error for negative InnerIP.DataFrames, got nil")
	}
}

// Test 19: InnerIP where the built inner packet exceeds MTU is rejected.
func TestWireGuard_InnerIP_Validate_ExceedsMTU(t *testing.T) {
	p := NewPlanner()
	spec := innerSpec()
	// IPv4 header (20) + UDP header (8) + payload. Max payload = 1440 - 28 = 1412.
	spec.WireGuard.InnerIP.Payload = make([]byte, MaxTransportPayload) // way too big
	if err := p.Validate(spec); err == nil {
		t.Error("expected error for InnerIP payload exceeding MTU, got nil")
	}
}

// --- Default values tests ---

// Test 20: InnerIP with empty SrcIP/DstIP uses IPv4 defaults.
func TestWireGuard_InnerIP_Defaults(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcMAC:   "02:00:00:00:00:01",
		DstMAC:   "02:00:00:00:00:02",
		SrcIP:    "192.0.2.1",
		DstIP:    "192.0.2.2",
		SrcPort:  50000,
		DstPort:  DefaultPort,
		WireGuard: &core.WireGuardConfig{
			Role:        "initiator",
			SenderIndex: 1,
			InnerIP:     &core.WireGuardInnerIP{}, // all defaults
		},
	}
	if err := p.Validate(spec); err != nil {
		t.Fatalf("Validate failed for default InnerIP: %v", err)
	}
	cfgs := drain(mustPlan(t, p, spec))
	trans := cfgs[2]
	// Default proto = 17 (UDP).
	if trans.Payload[16+9] != 17 {
		t.Errorf("default inner proto=%d, want 17 (UDP)", trans.Payload[16+9])
	}
}

// --- Context cancellation ---

// Test 21: InnerIP with many DataFrames respects context cancellation.
func TestWireGuard_InnerIP_ContextCancel(t *testing.T) {
	p := NewPlanner()
	spec := innerSpec()
	spec.WireGuard.InnerIP.DataFrames = 1000
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ch, err := p.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan error: %v", err)
	}
	_ = drain(ch) // must not hang
}

// --- Concurrency ---

// Test 22: Concurrent InnerIP plans are race-free and produce correct counts.
func TestWireGuard_InnerIP_ConcurrentNoRace(t *testing.T) {
	p := NewPlanner()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			spec := innerSpec()
			spec.SrcPort = 50000 + uint16(workerID)
			spec.WireGuard.InnerIP.DataFrames = 3
			ch, err := p.Plan(context.Background(), spec)
			if err != nil {
				t.Errorf("worker %d: Plan error: %v", workerID, err)
				return
			}
			cfgs := drain(ch)
			// handshake(2) + transport(3) = 5
			if len(cfgs) != 5 {
				t.Errorf("worker %d: packet count=%d, want 5", workerID, len(cfgs))
			}
		}(i)
	}
	wg.Wait()
}
