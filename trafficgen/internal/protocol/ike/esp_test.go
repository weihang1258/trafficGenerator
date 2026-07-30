package ike

// esp_test.go — Spec-driven tests for ESP data-plane packets emitted by the
// IKE planner (RFC 4303 §2 ESP packet format + RFC 7296 tunnel mode).
//
// These tests were written BEFORE the implementation (failing-first per
// CLAUDE.md testing policy §7). They assert RFC 4303 §2 wire-format:
//   SPI(4B BE) + Seq(4B BE) + IV(variable) + PayloadData(variable)
//   + Padding(0..255) + PadLength(1B) + NextHeader(1B) + ICV(variable)
//
// Tunnel mode (RFC 4303 §2.6): PayloadData = inner IP header + inner payload.
// NextHeader = 4 (IPv4-in-IPv4, RFC 2003) for tunnel mode.
// Transport mode (RFC 4303 §2.4): PayloadData = inner L4 + data. NextHeader
// = inner protocol (6=TCP, 17=UDP).

import (
	"context"
	"encoding/binary"
	"net"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

// --- ESP constants (mirror planner.go) ---

const (
	espHeaderMinLen   = 8  // SPI(4) + Seq(4)
	espTrailerLen     = 2  // PadLength(1) + NextHeader(1)
	defaultESPIVLen    = 16 // AES-CBC IV
	defaultESPICVLen   = 16 // HMAC-SHA-256-128 ICV
	defaultESPPayload  = 100
	ipProtoIPv4Encap  = 4  // Next Header for IPv4-in-IPv4 tunnel (RFC 2003)
)

// espSpec returns a valid FlowSpec with ESPDataPlane configured for tunnel
// mode. Tests override individual fields on top of this baseline.
func espSpec() core.FlowSpec {
	s := validBaseSpec()
	s.IKE.ESPDataPlane = &core.ESPDataPlaneConfig{
		SPI:              0xDEADBEEF,
		Count:            1,
		Mode:             "tunnel",
		InnerSrcIP:       "192.168.1.1",
		InnerDstIP:       "192.168.2.1",
		InnerProto:       17, // UDP
		InnerSrcPort:     12345,
		InnerDstPort:     8080,
		InnerPayloadSize: 64,
	}
	return s
}

// espPayload extracts the ESP payload bytes from a PacketConfig.
func espPayload(t *testing.T, p core.PacketConfig) []byte {
	t.Helper()
	if len(p.Payload) < espHeaderMinLen {
		t.Fatalf("ESP payload too short: %d bytes", len(p.Payload))
	}
	return p.Payload
}

// --- §2.1 ESP Header: SPI + Sequence (RFC 4303 §2.2) ---

func TestESP_SPI_4Bytes_BE(t *testing.T) {
	spec := espSpec()
	spec.IKE.ESPDataPlane.SPI = 0xCAFEBABE
	pkts := mustPlan(t, spec)
	esp := findESPPacket(t, pkts)
	if len(esp) < 4 {
		t.Fatal("ESP too short for SPI")
	}
	spi := binary.BigEndian.Uint32(esp[0:4])
	if spi != 0xCAFEBABE {
		t.Errorf("SPI = 0x%08X, want 0xCAFEBABE", spi)
	}
}

func TestESP_Seq_4Bytes_BE_StartsAt1(t *testing.T) {
	spec := espSpec()
	spec.IKE.ESPDataPlane.Count = 3
	pkts := mustPlan(t, spec)
	espPkts := findAllESPPackets(t, pkts)
	if len(espPkts) < 3 {
		t.Fatalf("expected 3 ESP packets, got %d", len(espPkts))
	}
	for i, ep := range espPkts {
		if len(ep) < 8 {
			t.Fatalf("ESP[%d] too short for Seq", i)
		}
		seq := binary.BigEndian.Uint32(ep[4:8])
		if seq != uint32(i+1) {
			t.Errorf("ESP[%d] Seq = %d, want %d", i, seq, i+1)
		}
	}
}

func TestESP_SPI_NonZero(t *testing.T) {
	// RFC 4303 §2.1: SPI=0 is reserved (used locally only). Validate should
	// reject SPI=0.
	spec := espSpec()
	spec.IKE.ESPDataPlane.SPI = 0
	_, err := NewPlanner().Plan(context.Background(), spec)
	if err == nil {
		t.Fatal("Plan should reject ESPDataPlane.SPI=0 (reserved per RFC 4303)")
	}
}

// --- §2.2 ESP Trailer: PadLength + NextHeader (RFC 4303 §2.4) ---

func TestESP_Trailer_PadLengthAndNextHeader(t *testing.T) {
	spec := espSpec()
	spec.IKE.ESPDataPlane.IVLength = 16
	spec.IKE.ESPDataPlane.ICVLength = 16
	pkts := mustPlan(t, spec)
	esp := findESPPacket(t, pkts)

	ivLen := 16
	icvLen := 16
	// NextHeader and PadLength are the last 2 bytes before ICV.
	nextHdrOffset := len(esp) - icvLen - 1
	padLenOffset := nextHdrOffset - 1
	if padLenOffset < 8+ivLen {
		t.Fatalf("ESP too short: %d bytes", len(esp))
	}
	nextHdr := esp[nextHdrOffset]
	padLen := esp[padLenOffset]
	if nextHdr != ipProtoIPv4Encap {
		t.Errorf("NextHeader = %d, want %d (IPv4-in-IPv4 tunnel)", nextHdr, ipProtoIPv4Encap)
	}
	if padLen > 255 {
		t.Errorf("PadLength = %d, must be 0..255", padLen)
	}
}

func TestESP_Padding_4ByteAlignment(t *testing.T) {
	// RFC 4303 §2.4: the PayloadData + Padding + PadLength + NextHeader
	// must be a multiple of 4 bytes (for block cipher alignment).
	spec := espSpec()
	spec.IKE.ESPDataPlane.InnerPayloadSize = 37 // odd number
	pkts := mustPlan(t, spec)
	esp := findESPPacket(t, pkts)

	ivLen := 16
	icvLen := 16
	// Payload region = from after IV to start of ICV.
	payloadStart := espHeaderMinLen + ivLen
	payloadEnd := len(esp) - icvLen
	payloadRegion := payloadEnd - payloadStart
	if payloadRegion%4 != 0 {
		t.Errorf("payload+trailer region = %d bytes, not 4-byte aligned", payloadRegion)
	}
}

func TestESP_Padding_BytesSequential(t *testing.T) {
	// RFC 4303 §2.4 step 4: padding bytes are 1, 2, 3, ... in order from the
	// start of the padding region (closest to PayloadData) to the end
	// (closest to PadLength). We use InnerPayloadSize=36 to force padLen=2
	// (payloadData=20+8+36=64, +2 trailer=66, 66%4=2, padLen=2).
	spec := espSpec()
	spec.IKE.ESPDataPlane.InnerPayloadSize = 36
	pkts := mustPlan(t, spec)
	esp := findESPPacket(t, pkts)

	icvLen := 16
	nextHdrOffset := len(esp) - icvLen - 1
	padLenOffset := nextHdrOffset - 1
	padLen := int(esp[padLenOffset])
	if padLen < 2 {
		t.Skipf("padLen=%d, need >=2 to verify sequential padding (adjust payload size)", padLen)
	}
	padStart := padLenOffset - padLen
	for i := 0; i < padLen; i++ {
		got := esp[padStart+i]
		want := byte(i + 1)
		if got != want {
			t.Errorf("padding byte[%d] = %d, want %d (RFC 4303 §2.4: 1,2,3,...)", i, got, want)
		}
	}
}

// --- §2.3 Tunnel Mode: Inner IP (RFC 4303 §2.6) ---

func TestESP_TunnelMode_InnerIPv4Header(t *testing.T) {
	spec := espSpec()
	spec.IKE.ESPDataPlane.Mode = "tunnel"
	spec.IKE.ESPDataPlane.InnerSrcIP = "192.168.1.1"
	spec.IKE.ESPDataPlane.InnerDstIP = "192.168.2.1"
	pkts := mustPlan(t, spec)
	esp := findESPPacket(t, pkts)

	ivLen := 16
	icvLen := 16
	innerStart := espHeaderMinLen + ivLen
	if innerStart+20 > len(esp)-icvLen {
		t.Fatal("ESP too short to contain inner IPv4 header")
	}
	inner := esp[innerStart:]
	// Inner IPv4: Version=4, IHL=5 → byte[0] = 0x45.
	if inner[0] != 0x45 {
		t.Errorf("inner IP Version/IHL = 0x%02X, want 0x45", inner[0])
	}
	// Inner protocol field at byte[9].
	if inner[9] != 17 {
		t.Errorf("inner IP proto = %d, want 17 (UDP)", inner[9])
	}
	// Inner src IP at bytes[12:16].
	srcIP := net.IP(inner[12:16]).String()
	if srcIP != "192.168.1.1" {
		t.Errorf("inner src IP = %s, want 192.168.1.1", srcIP)
	}
	// Inner dst IP at bytes[16:20].
	dstIP := net.IP(inner[16:20]).String()
	if dstIP != "192.168.2.1" {
		t.Errorf("inner dst IP = %s, want 192.168.2.1", dstIP)
	}
}

func TestESP_TunnelMode_NextHeader4(t *testing.T) {
	// Tunnel mode IPv4 → NextHeader = 4 (IP-in-IP, RFC 2003).
	spec := espSpec()
	spec.IKE.ESPDataPlane.Mode = "tunnel"
	pkts := mustPlan(t, spec)
	esp := findESPPacket(t, pkts)

	icvLen := 16
	nextHdr := esp[len(esp)-icvLen-1]
	if nextHdr != 4 {
		t.Errorf("tunnel mode NextHeader = %d, want 4 (IPv4-in-IPv4)", nextHdr)
	}
}

func TestESP_TunnelMode_InnerIPChecksum(t *testing.T) {
	// The inner IPv4 header checksum must be valid (RFC 791).
	spec := espSpec()
	pkts := mustPlan(t, spec)
	esp := findESPPacket(t, pkts)

	ivLen := 16
	icvLen := 16
	innerStart := espHeaderMinLen + ivLen
	_ = icvLen
	innerHdr := esp[innerStart : innerStart+20]
	// Verify checksum: set checksum to 0, compute, compare.
	saved := binary.BigEndian.Uint16(innerHdr[10:12])
	binary.BigEndian.PutUint16(innerHdr[10:12], 0)
	cs := ipChecksumTest(innerHdr)
	binary.BigEndian.PutUint16(innerHdr[10:12], saved)
	if cs != saved {
		t.Errorf("inner IP checksum = 0x%04X, want 0x%04X", saved, cs)
	}
}

// --- §2.4 Transport Mode (RFC 4303 §2.4) ---

func TestESP_TransportMode_NoInnerIP(t *testing.T) {
	// Transport mode: no inner IP header. Payload = inner L4 + data.
	// NextHeader = inner protocol (e.g. 17 for UDP).
	spec := espSpec()
	spec.IKE.ESPDataPlane.Mode = "transport"
	spec.IKE.ESPDataPlane.InnerProto = 17
	pkts := mustPlan(t, spec)
	esp := findESPPacket(t, pkts)

	ivLen := 16
	icvLen := 16
	innerStart := espHeaderMinLen + ivLen
	inner := esp[innerStart : len(esp)-icvLen]
	// Transport mode: first 8 bytes should be UDP header (not IPv4 0x45).
	if inner[0] == 0x45 {
		t.Error("transport mode should NOT have inner IPv4 header (byte[0]=0x45)")
	}
	// NextHeader should be 17 (UDP) not 4 (tunnel).
	nextHdr := esp[len(esp)-icvLen-1]
	if nextHdr != 17 {
		t.Errorf("transport mode NextHeader = %d, want 17 (UDP)", nextHdr)
	}
}

func TestESP_TransportMode_InnerUDPHeader(t *testing.T) {
	spec := espSpec()
	spec.IKE.ESPDataPlane.Mode = "transport"
	spec.IKE.ESPDataPlane.InnerProto = 17
	spec.IKE.ESPDataPlane.InnerSrcPort = 12345
	spec.IKE.ESPDataPlane.InnerDstPort = 8080
	pkts := mustPlan(t, spec)
	esp := findESPPacket(t, pkts)

	ivLen := 16
	icvLen := 16
	innerStart := espHeaderMinLen + ivLen
	inner := esp[innerStart : len(esp)-icvLen]
	if len(inner) < 8 {
		t.Fatal("transport mode inner too short for UDP header")
	}
	srcPort := binary.BigEndian.Uint16(inner[0:2])
	dstPort := binary.BigEndian.Uint16(inner[2:4])
	if srcPort != 12345 {
		t.Errorf("inner UDP src port = %d, want 12345", srcPort)
	}
	if dstPort != 8080 {
		t.Errorf("inner UDP dst port = %d, want 8080", dstPort)
	}
}

// --- §2.5 L3 Protocol = 50 (ESP) ---

func TestESP_L3ProtocolIs50(t *testing.T) {
	// The outer IP header Protocol field must be 50 (ESP).
	spec := espSpec()
	pkts := mustPlan(t, spec)
	espPkt := findESPPacketConfig(t, pkts)
	if espPkt.L3.Protocol != 50 {
		t.Errorf("L3.Protocol = %d, want 50 (ESP)", espPkt.L3.Protocol)
	}
}

func TestESP_NoL4Header(t *testing.T) {
	// ESP is an IP-layer protocol (protocol 50); there is no L4 header.
	// The builder's l4Length returns 0 for unknown protocols, so the ESP
	// payload goes directly after the IP header.
	spec := espSpec()
	pkts := mustPlan(t, spec)
	espPkt := findESPPacketConfig(t, pkts)
	if espPkt.L4.Protocol != "" && espPkt.L4.Protocol != "none" {
		t.Errorf("L4.Protocol = %q, want '' (ESP has no L4 header)", espPkt.L4.Protocol)
	}
}

// --- §2.6 IKE + ESP Joint Scenario ---

func TestESP_AfterIKEControlPlane(t *testing.T) {
	// ESP packets must come AFTER the IKE control-plane handshake (4 messages
	// for standard_v2). The first 4 packets are IKE; ESP starts at index 4.
	spec := espSpec()
	pkts := mustPlan(t, spec)
	ikeCount := 0
	espCount := 0
	for _, p := range pkts {
		if isESPPacket(p) {
			espCount++
		} else {
			ikeCount++
		}
	}
	if ikeCount < 4 {
		t.Errorf("expected >=4 IKE control-plane packets, got %d", ikeCount)
	}
	if espCount < 1 {
		t.Errorf("expected >=1 ESP data-plane packets, got %d", espCount)
	}
	// Verify ordering: all IKE packets come before all ESP packets.
	firstESP := -1
	for i, p := range pkts {
		if isESPPacket(p) {
			firstESP = i
			break
		}
	}
	if firstESP < 4 {
		t.Errorf("first ESP packet at index %d, must be after 4 IKE messages", firstESP)
	}
}

func TestESP_MultiplePackets(t *testing.T) {
	spec := espSpec()
	spec.IKE.ESPDataPlane.Count = 5
	pkts := mustPlan(t, spec)
	espPkts := findAllESPPackets(t, pkts)
	if len(espPkts) != 5 {
		t.Errorf("expected 5 ESP packets, got %d", len(espPkts))
	}
	// Each ESP packet should have a different sequence number (1..5).
	for i, ep := range espPkts {
		seq := binary.BigEndian.Uint32(ep[4:8])
		if seq != uint32(i+1) {
			t.Errorf("ESP[%d] Seq = %d, want %d", i, seq, i+1)
		}
	}
}

// --- §2.7 Direction ---

func TestESP_DirectionDown(t *testing.T) {
	spec := espSpec()
	spec.IKE.ESPDataPlane.Direction = "down"
	pkts := mustPlan(t, spec)
	espPkt := findESPPacketConfig(t, pkts)
	if espPkt.Direction != "down" {
		t.Errorf("ESP Direction = %q, want 'down'", espPkt.Direction)
	}
	// Direction down → src/dst IPs and MACs should be swapped.
	if espPkt.L3.SrcIP != "10.0.0.2" {
		t.Errorf("ESP down L3.SrcIP = %q, want 10.0.0.2 (swapped)", espPkt.L3.SrcIP)
	}
}

func TestESP_DirectionDefaultUp(t *testing.T) {
	spec := espSpec()
	spec.IKE.ESPDataPlane.Direction = ""
	pkts := mustPlan(t, spec)
	espPkt := findESPPacketConfig(t, pkts)
	if espPkt.Direction != "up" {
		t.Errorf("ESP Direction = %q, want 'up' (default)", espPkt.Direction)
	}
}

// --- §2.8 Validation ---

func TestESP_Validate_BadMode(t *testing.T) {
	spec := espSpec()
	spec.IKE.ESPDataPlane.Mode = "invalid"
	_, err := NewPlanner().Plan(context.Background(), spec)
	if err == nil {
		t.Fatal("Plan should reject ESPDataPlane.Mode='invalid'")
	}
}

func TestESP_Validate_BadInnerSrcIP(t *testing.T) {
	spec := espSpec()
	spec.IKE.ESPDataPlane.InnerSrcIP = "not-an-ip"
	_, err := NewPlanner().Plan(context.Background(), spec)
	if err == nil {
		t.Fatal("Plan should reject bad InnerSrcIP")
	}
}

func TestESP_Validate_BadInnerDstIP(t *testing.T) {
	spec := espSpec()
	spec.IKE.ESPDataPlane.InnerDstIP = "999.999.999.999"
	_, err := NewPlanner().Plan(context.Background(), spec)
	if err == nil {
		t.Fatal("Plan should reject bad InnerDstIP")
	}
}

func TestESP_Validate_NegativeCount(t *testing.T) {
	spec := espSpec()
	spec.IKE.ESPDataPlane.Count = -1
	_, err := NewPlanner().Plan(context.Background(), spec)
	if err == nil {
		t.Fatal("Plan should reject negative ESPDataPlane.Count")
	}
}

func TestESP_Validate_BadDirection(t *testing.T) {
	spec := espSpec()
	spec.IKE.ESPDataPlane.Direction = "sideways"
	_, err := NewPlanner().Plan(context.Background(), spec)
	if err == nil {
		t.Fatal("Plan should reject ESPDataPlane.Direction='sideways'")
	}
}

// --- §2.9 Backward Compatibility ---

func TestESP_BackwardCompat_NoESPDataPlane(t *testing.T) {
	// When ESPDataPlane is nil, the planner must emit only IKE control-plane
	// messages (same as before this feature).
	spec := validBaseSpec()
	spec.IKE.ResponderSPI = 0
	pkts := mustPlan(t, spec)
	for i, p := range pkts {
		if isESPPacket(p) {
			t.Errorf("pkt[%d] is ESP but ESPDataPlane was nil", i)
		}
	}
}

// --- §2.10 ICV and IV ---

func TestESP_ICV_Length(t *testing.T) {
	spec := espSpec()
	spec.IKE.ESPDataPlane.ICVLength = 12
	pkts := mustPlan(t, spec)
	esp := findESPPacket(t, pkts)
	// ICV is the last ICVLength bytes.
	icvStart := len(esp) - 12
	if icvStart < espHeaderMinLen {
		t.Fatal("ESP too short for ICV")
	}
	// ICV bytes should be non-zero (deterministic pseudo-bytes).
	for i := icvStart; i < len(esp); i++ {
		if esp[i] != 0 {
			return // at least one non-zero byte
		}
	}
	t.Error("ICV is all zeros, expected non-zero pseudo-bytes")
}

func TestESP_IV_Length(t *testing.T) {
	spec := espSpec()
	spec.IKE.ESPDataPlane.IVLength = 8
	pkts := mustPlan(t, spec)
	esp := findESPPacket(t, pkts)
	// IV starts at offset 8 (after SPI+Seq).
	ivLen := 8
	if len(esp) < espHeaderMinLen+ivLen {
		t.Fatal("ESP too short for IV")
	}
	// IV bytes should be non-zero (deterministic pseudo-bytes).
	for i := 8; i < 8+ivLen; i++ {
		if esp[i] != 0 {
			return
		}
	}
	t.Error("IV is all zeros, expected non-zero pseudo-bytes")
}

// --- Helpers ---

// isESPPacket returns true if the PacketConfig is an ESP data-plane packet
// (L3.Protocol == 50).
func isESPPacket(p core.PacketConfig) bool {
	return p.L3.Protocol == 50
}

// findESPPacketConfig returns the first ESP PacketConfig from the slice.
func findESPPacketConfig(t *testing.T, pkts []core.PacketConfig) core.PacketConfig {
	t.Helper()
	for _, p := range pkts {
		if isESPPacket(p) {
			return p
		}
	}
	t.Fatal("no ESP packet found in plan output")
	return core.PacketConfig{}
}

// findESPPacket returns the ESP payload bytes from the first ESP packet.
func findESPPacket(t *testing.T, pkts []core.PacketConfig) []byte {
	t.Helper()
	p := findESPPacketConfig(t, pkts)
	return p.Payload
}

// findAllESPPackets returns the ESP payload bytes from all ESP packets.
func findAllESPPackets(t *testing.T, pkts []core.PacketConfig) [][]byte {
	t.Helper()
	var out [][]byte
	for _, p := range pkts {
		if isESPPacket(p) {
			out = append(out, p.Payload)
		}
	}
	if len(out) == 0 {
		t.Fatal("no ESP packets found")
	}
	return out
}

// ipChecksumTest computes the standard IP header checksum (RFC 791) over a
// 20-byte IPv4 header with the checksum field set to 0.
func ipChecksumTest(hdr []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(hdr); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(hdr[i : i+2]))
	}
	for sum>>16 > 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}
