// Package openvpn implements the OpenVPN protocol planner.
//
// This file contains FAILING-first tests for the "tunnel inner IP business
// flow" feature (spec: OpenVPNConfig.InnerIPPackets). When InnerIPPackets is
// non-empty, P_DATA_V2 packets carry complete inner IPv4/IPv6 packets in the
// encrypted-payload region (the inner IP bytes occupy the ciphertext slot;
// IV/nonce/packet_id/tag remain synthetic filler). Each inner IP entry
// produces one client->server P_DATA_V2 plus a matching server->client
// P_DATA_V2, REPLACING the default DataPacketCount loop.
//
// These tests are spec-driven (each test maps to a config field or behavior)
// and cover both happy and failure paths. They FAIL against the pre-feature
// planner (which has no InnerIPPackets field) and PASS after the feature is
// implemented.
package openvpn

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

// --- helpers ---

// countDataV2 returns the number of P_DATA_V2 packets (opcode 9) in pkts.
func countDataV2(pkts []core.PacketConfig) int {
	n := 0
	for _, p := range pkts {
		if len(p.Payload) > 0 && p.Payload[0]>>POpcodeShift == OpcodeDATAV2 {
			n++
		}
	}
	return n
}

// dataV2UpPackets returns the up-direction P_DATA_V2 packets in order.
func dataV2UpPackets(pkts []core.PacketConfig) []core.PacketConfig {
	var out []core.PacketConfig
	for _, p := range pkts {
		if p.Direction == "up" && len(p.Payload) > 0 && p.Payload[0]>>POpcodeShift == OpcodeDATAV2 {
			out = append(out, p)
		}
	}
	return out
}

// extractEncryptedPayload extracts the encrypted-payload region of a P_DATA_V2
// packet: everything after opcode(1B) + peer_id(3B). The IV/nonce, packet_id,
// ciphertext, and AEAD/HMAC tag all live here.
func extractEncryptedPayload(pkt []byte) []byte {
	if len(pkt) < 4 {
		return nil
	}
	return pkt[4:]
}

// findInnerIPv4InEncrypted searches the encrypted-payload region for a
// complete inner IPv4 packet with the given src/dst. The planner builds the
// inner IPv4 header with version=4, IHL=5 (first byte 0x45) and the src/dst
// at offsets 12..15 and 16..19. We search the whole encrypted region (the
// inner IP sits in the ciphertext slot, after the synthetic IV/nonce/packet_id
// prefix) for the inner IPv4 header pattern.
func findInnerIPv4InEncrypted(enc []byte, srcIP, dstIP [4]byte) bool {
	for i := 0; i+20 <= len(enc); i++ {
		if enc[i] != 0x45 {
			continue
		}
		if bytes.Equal(enc[i+12:i+16], srcIP[:]) && bytes.Equal(enc[i+16:i+20], dstIP[:]) {
			return true
		}
	}
	return false
}

// findInnerIPv6InEncrypted searches for a complete inner IPv6 packet. The
// inner IPv6 header starts with 0x60 (version=6, TC high nibble=0) and
// carries src at offset 8..23 and dst at offset 24..39.
func findInnerIPv6InEncrypted(enc []byte, srcIP, dstIP [16]byte) bool {
	for i := 0; i+40 <= len(enc); i++ {
		if enc[i] != 0x60 {
			continue
		}
		if bytes.Equal(enc[i+8:i+24], srcIP[:]) && bytes.Equal(enc[i+24:i+40], dstIP[:]) {
			return true
		}
	}
	return false
}

// --- I1: P_DATA_V2 count == len(InnerIPPackets) (client->server) ---

// Spec: InnerIPPackets non-empty REPLACES the default DataPacketCount loop.
// Each entry produces exactly one client->server P_DATA_V2.
func TestI1_DataV2CountMatchesInnerIPCount(t *testing.T) {
	spec := defaultOpenVPNSpec()
	spec.OpenVPN.InnerIPPackets = []core.OpenVPNInnerIP{
		{SrcIP: "10.10.10.1", DstIP: "10.10.10.2", Proto: 17, SrcPort: 1000, DstPort: 2000, Payload: []byte("hello")},
		{SrcIP: "10.10.10.1", DstIP: "10.10.10.3", Proto: 17, SrcPort: 1001, DstPort: 2001, Payload: []byte("world")},
		{SrcIP: "10.10.10.1", DstIP: "10.10.10.4", Proto: 17, SrcPort: 1002, DstPort: 2002, Payload: []byte("!")},
	}
	planner := NewPlanner()
	ch, err := planner.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan failed: %v", err)
	}
	pkts := collectPackets(context.Background(), t, ch)

	up := dataV2UpPackets(pkts)
	if len(up) != 3 {
		t.Fatalf("up P_DATA_V2 count: got %d, want 3 (one per InnerIPPackets entry)", len(up))
	}
}

// --- I2: opcode == 9 (P_DATA_V2) and peer_id present ---

// Spec: each inner-IP P_DATA_V2 still uses the real wire format:
// opcode(1B, value 9<<3|key_id) + peer_id(3B) + encrypted payload.
func TestI2_DataV2OpcodeAndPeerID(t *testing.T) {
	spec := defaultOpenVPNSpec()
	spec.OpenVPN.KeyID = 3
	spec.OpenVPN.SessionID = 0x0011223344556677
	spec.OpenVPN.InnerIPPackets = []core.OpenVPNInnerIP{
		{SrcIP: "10.10.10.1", DstIP: "10.10.10.2", Proto: 17},
	}
	planner := NewPlanner()
	ch, err := planner.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan failed: %v", err)
	}
	pkts := collectPackets(context.Background(), t, ch)

	up := dataV2UpPackets(pkts)
	if len(up) != 1 {
		t.Fatalf("up P_DATA_V2 count: got %d, want 1", len(up))
	}
	p := up[0].Payload
	if len(p) < 4 {
		t.Fatalf("P_DATA_V2 too short: %d", len(p))
	}
	// opcode 9, key_id 3 -> (9<<3)|3 = 0x4B.
	if p[0] != 0x4B {
		t.Errorf("header byte: got 0x%02X, want 0x4B (opcode=9, key_id=3)", p[0])
	}
	// peer_id is the low 24 bits of session_id = 0x556677 (55 66 77).
	wantPeer := [3]byte{0x55, 0x66, 0x77}
	for i := 0; i < 3; i++ {
		if p[1+i] != wantPeer[i] {
			t.Errorf("peer_id byte %d: got 0x%02X, want 0x%02X", i, p[1+i], wantPeer[i])
		}
	}
}

// --- I3: inner IPv4 packet embedded in encrypted payload ---

// Spec: the inner IPv4 packet (header + L4 + payload) is built with a
// correct checksum and occupies the ciphertext slot of the encrypted region.
// We assert the inner IPv4 header (src/dst/protocol) is findable in the
// encrypted-payload bytes.
func TestI3_InnerIPv4Embedded(t *testing.T) {
	spec := defaultOpenVPNSpec()
	spec.OpenVPN.DataCipher = "AES-256-CBC"
	spec.OpenVPN.InnerIPPackets = []core.OpenVPNInnerIP{
		{SrcIP: "10.10.10.1", DstIP: "10.10.10.2", Proto: 17, SrcPort: 1000, DstPort: 2000, Payload: []byte("hello")},
	}
	planner := NewPlanner()
	ch, err := planner.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan failed: %v", err)
	}
	pkts := collectPackets(context.Background(), t, ch)

	up := dataV2UpPackets(pkts)
	if len(up) != 1 {
		t.Fatalf("up P_DATA_V2 count: got %d, want 1", len(up))
	}
	enc := extractEncryptedPayload(up[0].Payload)
	if enc == nil {
		t.Fatal("no encrypted payload")
	}
	src := [4]byte{10, 10, 10, 1}
	dst := [4]byte{10, 10, 10, 2}
	if !findInnerIPv4InEncrypted(enc, src, dst) {
		t.Errorf("inner IPv4 (10.10.10.1 -> 10.10.10.2) not found in encrypted payload region")
	}
}

// --- I4: inner IPv4 header checksum is correct ---

// Spec: the inner IPv4 header checksum is computed per RFC 791 §3.1. We
// find the inner IPv4 header in the encrypted region and verify its
// checksum field is correct (sum of header words including checksum == 0xFFFF).
func TestI4_InnerIPv4Checksum(t *testing.T) {
	spec := defaultOpenVPNSpec()
	spec.OpenVPN.InnerIPPackets = []core.OpenVPNInnerIP{
		{SrcIP: "192.168.1.1", DstIP: "192.168.1.2", Proto: 6, SrcPort: 12345, DstPort: 80, Payload: []byte("GET /")},
	}
	planner := NewPlanner()
	ch, err := planner.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan failed: %v", err)
	}
	pkts := collectPackets(context.Background(), t, ch)

	up := dataV2UpPackets(pkts)
	if len(up) != 1 {
		t.Fatalf("up P_DATA_V2 count: got %d, want 1", len(up))
	}
	enc := extractEncryptedPayload(up[0].Payload)
	src := [4]byte{192, 168, 1, 1}
	dst := [4]byte{192, 168, 1, 2}
	// Find the inner IPv4 header start.
	idx := -1
	for i := 0; i+20 <= len(enc); i++ {
		if enc[i] == 0x45 && bytes.Equal(enc[i+12:i+16], src[:]) && bytes.Equal(enc[i+16:i+20], dst[:]) {
			idx = i
			break
		}
	}
	if idx < 0 {
		t.Fatal("inner IPv4 header not found in encrypted payload")
	}
	// Verify checksum: sum of all 10 16-bit words of the header (including
	// the checksum field) must be 0xFFFF (one's-complement of zero).
	hdr := enc[idx : idx+20]
	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(hdr[i : i+2]))
	}
	for sum>>16 != 0 {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	if uint16(sum) != 0xFFFF {
		t.Errorf("inner IPv4 header checksum invalid: sum=0x%04X, want 0xFFFF", uint16(sum))
	}
}

// --- I5: inner IPv6 packet embedded ---

// Spec: when SrcIP/DstIP are IPv6, the inner packet is a complete IPv6
// header (40B) + L4 + payload.
func TestI5_InnerIPv6Embedded(t *testing.T) {
	spec := defaultOpenVPNSpec()
	spec.OpenVPN.InnerIPPackets = []core.OpenVPNInnerIP{
		{SrcIP: "fd00::1", DstIP: "fd00::2", Proto: 17, SrcPort: 1000, DstPort: 2000, Payload: []byte("v6hi")},
	}
	planner := NewPlanner()
	ch, err := planner.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan failed: %v", err)
	}
	pkts := collectPackets(context.Background(), t, ch)

	up := dataV2UpPackets(pkts)
	if len(up) != 1 {
		t.Fatalf("up P_DATA_V2 count: got %d, want 1", len(up))
	}
	enc := extractEncryptedPayload(up[0].Payload)
	var src, dst [16]byte
	srcB := parseIPv6("fd00::1")
	dstB := parseIPv6("fd00::2")
	copy(src[:], srcB)
	copy(dst[:], dstB)
	if !findInnerIPv6InEncrypted(enc, src, dst) {
		t.Errorf("inner IPv6 (fd00::1 -> fd00::2) not found in encrypted payload region")
	}
}

// parseIPv6 returns the 16-byte representation of an IPv6 address string.
func parseIPv6(s string) []byte {
	ip := net.ParseIP(s)
	if ip == nil {
		return nil
	}
	return ip.To16()
}

// --- I6: multiple inner packets get distinct IPIDs ---

// Spec: when multiple inner IPv4 packets are configured, each gets a
// distinct IPID so tshark sees separate inner packets. We extract each
// P_DATA_V2's inner IPv4 IPID and assert they are all distinct.
func TestI6_DistinctIPIDs(t *testing.T) {
	spec := defaultOpenVPNSpec()
	spec.OpenVPN.InnerIPPackets = []core.OpenVPNInnerIP{
		{SrcIP: "10.10.10.1", DstIP: "10.10.10.2", Proto: 17, Payload: []byte("a")},
		{SrcIP: "10.10.10.1", DstIP: "10.10.10.2", Proto: 17, Payload: []byte("b")},
		{SrcIP: "10.10.10.1", DstIP: "10.10.10.2", Proto: 17, Payload: []byte("c")},
	}
	planner := NewPlanner()
	ch, err := planner.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan failed: %v", err)
	}
	pkts := collectPackets(context.Background(), t, ch)

	up := dataV2UpPackets(pkts)
	if len(up) != 3 {
		t.Fatalf("up P_DATA_V2 count: got %d, want 3", len(up))
	}
	seen := map[uint16]bool{}
	src := [4]byte{10, 10, 10, 1}
	dst := [4]byte{10, 10, 10, 2}
	for i, p := range up {
		enc := extractEncryptedPayload(p.Payload)
		idx := -1
		for j := 0; j+20 <= len(enc); j++ {
			if enc[j] == 0x45 && bytes.Equal(enc[j+12:j+16], src[:]) && bytes.Equal(enc[j+16:j+20], dst[:]) {
				idx = j
				break
			}
		}
		if idx < 0 {
			t.Fatalf("P_DATA_V2[%d]: inner IPv4 header not found", i)
		}
		ipid := binary.BigEndian.Uint16(enc[idx+4 : idx+6])
		if seen[ipid] {
			t.Errorf("P_DATA_V2[%d]: IPID %d duplicated", i, ipid)
		}
		seen[ipid] = true
	}
	if len(seen) != 3 {
		t.Errorf("distinct IPIDs: got %d, want 3", len(seen))
	}
}

// --- I7: metadata records inner IP 5-tuple ---

// Spec: each P_DATA_V2 carrying an inner IP packet records the inner 5-tuple
// in PacketConfig.Metadata so downstream consumers can identify the tunneled
// business flow.
func TestI7_MetadataInnerIPTuple(t *testing.T) {
	spec := defaultOpenVPNSpec()
	spec.OpenVPN.InnerIPPackets = []core.OpenVPNInnerIP{
		{SrcIP: "10.10.10.1", DstIP: "10.10.10.2", Proto: 6, SrcPort: 12345, DstPort: 80, Payload: []byte("GET /")},
	}
	planner := NewPlanner()
	ch, err := planner.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan failed: %v", err)
	}
	pkts := collectPackets(context.Background(), t, ch)

	up := dataV2UpPackets(pkts)
	if len(up) != 1 {
		t.Fatalf("up P_DATA_V2 count: got %d, want 1", len(up))
	}
	md := up[0].Metadata
	if md == nil {
		t.Fatal("metadata is nil for inner-IP P_DATA_V2")
	}
	if md["openvpn_inner_src_ip"] != "10.10.10.1" {
		t.Errorf("metadata openvpn_inner_src_ip: got %v, want 10.10.10.1", md["openvpn_inner_src_ip"])
	}
	if md["openvpn_inner_dst_ip"] != "10.10.10.2" {
		t.Errorf("metadata openvpn_inner_dst_ip: got %v, want 10.10.10.2", md["openvpn_inner_dst_ip"])
	}
	if md["openvpn_inner_proto"] != uint8(6) {
		t.Errorf("metadata openvpn_inner_proto: got %v, want 6", md["openvpn_inner_proto"])
	}
}

// --- I8: validation rejects mixed address families ---

// Spec (failure path): SrcIP and DstIP must be the same address family.
func TestI8_ValidateMixedFamily(t *testing.T) {
	spec := defaultOpenVPNSpec()
	spec.OpenVPN.InnerIPPackets = []core.OpenVPNInnerIP{
		{SrcIP: "10.10.10.1", DstIP: "fd00::2", Proto: 17},
	}
	planner := NewPlanner()
	_, err := planner.Plan(context.Background(), spec)
	if err == nil {
		t.Fatal("Plan succeeded with mixed v4/v6 inner IPs, want validation error")
	}
}

// --- I9: validation rejects invalid Proto ---

// Spec (failure path): Proto must be 0 (default), 1, 6, or 17.
func TestI9_ValidateBadProto(t *testing.T) {
	spec := defaultOpenVPNSpec()
	spec.OpenVPN.InnerIPPackets = []core.OpenVPNInnerIP{
		{SrcIP: "10.10.10.1", DstIP: "10.10.10.2", Proto: 89}, // OSPF, unsupported
	}
	planner := NewPlanner()
	_, err := planner.Plan(context.Background(), spec)
	if err == nil {
		t.Fatal("Plan succeeded with Proto=89, want validation error")
	}
}

// --- I10: validation rejects invalid IP ---

// Spec (failure path): SrcIP must be a valid IP address.
func TestI10_ValidateBadIP(t *testing.T) {
	spec := defaultOpenVPNSpec()
	spec.OpenVPN.InnerIPPackets = []core.OpenVPNInnerIP{
		{SrcIP: "not-an-ip", DstIP: "10.10.10.2", Proto: 17},
	}
	planner := NewPlanner()
	_, err := planner.Plan(context.Background(), spec)
	if err == nil {
		t.Fatal("Plan succeeded with invalid SrcIP, want validation error")
	}
}

// --- I11: empty InnerIPPackets falls back to legacy DataPacketCount mode ---
//
// Spec (backward compat): when InnerIPPackets is empty/nil, the planner
// behaves exactly as before (DataPacketCount P_DATA_V2 with synthetic filler).
func TestI11_EmptyInnerIPBackwardCompat(t *testing.T) {
	spec := defaultOpenVPNSpec()
	spec.OpenVPN.DataPacketCount = 2
	// InnerIPPackets intentionally nil.
	planner := NewPlanner()
	ch, err := planner.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan failed: %v", err)
	}
	pkts := collectPackets(context.Background(), t, ch)

	up := dataV2UpPackets(pkts)
	if len(up) != 2 {
		t.Fatalf("up P_DATA_V2 count: got %d, want 2 (legacy DataPacketCount)", len(up))
	}
	// Legacy packets carry synthetic 0xDD filler, not an inner IPv4 header.
	for i, p := range up {
		enc := extractEncryptedPayload(p.Payload)
		src := [4]byte{10, 10, 10, 1}
		dst := [4]byte{10, 10, 10, 2}
		if findInnerIPv4InEncrypted(enc, src, dst) {
			t.Errorf("P_DATA_V2[%d]: legacy packet unexpectedly contains inner IPv4", i)
		}
	}
}

// --- I12: server->client P_DATA_V2 also carries inner IP ---

// Spec: each inner IP entry produces BOTH a client->server AND a matching
// server->client P_DATA_V2 (bidirectional tunnel traffic).
func TestI12_BidirectionalInnerIP(t *testing.T) {
	spec := defaultOpenVPNSpec()
	spec.OpenVPN.InnerIPPackets = []core.OpenVPNInnerIP{
		{SrcIP: "10.10.10.1", DstIP: "10.10.10.2", Proto: 17, Payload: []byte("ping")},
	}
	planner := NewPlanner()
	ch, err := planner.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan failed: %v", err)
	}
	pkts := collectPackets(context.Background(), t, ch)

	var downData []core.PacketConfig
	for _, p := range pkts {
		if p.Direction == "down" && len(p.Payload) > 0 && p.Payload[0]>>POpcodeShift == OpcodeDATAV2 {
			downData = append(downData, p)
		}
	}
	if len(downData) < 1 {
		t.Fatalf("down P_DATA_V2 count: got %d, want >= 1", len(downData))
	}
	enc := extractEncryptedPayload(downData[0].Payload)
	src := [4]byte{10, 10, 10, 1}
	dst := [4]byte{10, 10, 10, 2}
	if !findInnerIPv4InEncrypted(enc, src, dst) {
		t.Errorf("server->client P_DATA_V2 does not carry inner IPv4")
	}
}

// --- I14: validation rejects InnerIPPackets with StaticKeyMode ---

// Spec (failure path): static_key_mode uses its own P_DATA_V1 data path
// (nonce+ciphertext+HMAC, not the TLS data-channel encrypted payload), so
// InnerIPPackets is rejected there.
func TestI14_ValidateStaticKeyInnerIP(t *testing.T) {
	spec := defaultOpenVPNSpec()
	spec.OpenVPN.StaticKeyMode = true
	spec.OpenVPN.InnerIPPackets = []core.OpenVPNInnerIP{
		{SrcIP: "10.10.10.1", DstIP: "10.10.10.2", Proto: 17},
	}
	planner := NewPlanner()
	_, err := planner.Plan(context.Background(), spec)
	if err == nil {
		t.Fatal("Plan succeeded with inner_ip_packets + static_key_mode, want validation error")
	}
}

// --- I15: inner IP with ICMP proto 1 ---

// Spec: Proto=1 builds an ICMP echo request inner packet (type 8 for
// IPv4, type 128 for IPv6). Asserts the inner IPv4 ICMP header is findable.
func TestI15_InnerICMP(t *testing.T) {
	spec := defaultOpenVPNSpec()
	spec.OpenVPN.InnerIPPackets = []core.OpenVPNInnerIP{
		{SrcIP: "10.10.10.1", DstIP: "10.10.10.2", Proto: 1, Payload: []byte("p")},
	}
	planner := NewPlanner()
	ch, err := planner.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan failed: %v", err)
	}
	pkts := collectPackets(context.Background(), t, ch)

	up := dataV2UpPackets(pkts)
	if len(up) != 1 {
		t.Fatalf("up P_DATA_V2 count: got %d, want 1", len(up))
	}
	enc := extractEncryptedPayload(up[0].Payload)
	src := [4]byte{10, 10, 10, 1}
	dst := [4]byte{10, 10, 10, 2}
	if !findInnerIPv4InEncrypted(enc, src, dst) {
		t.Errorf("inner IPv4 (ICMP) not found in encrypted payload region")
	}
	// Find the inner IPv4 header and verify the protocol byte is 1 (ICMP).
	idx := -1
	for i := 0; i+20 <= len(enc); i++ {
		if enc[i] == 0x45 && bytes.Equal(enc[i+12:i+16], src[:]) && bytes.Equal(enc[i+16:i+20], dst[:]) {
			idx = i
			break
		}
	}
	if idx < 0 {
		t.Fatal("inner IPv4 header not found")
	}
	if enc[idx+9] != 1 {
		t.Errorf("inner IPv4 protocol: got %d, want 1 (ICMP)", enc[idx+9])
	}
}

// --- I16: inner TCP proto 6 ---

// Spec: Proto=6 builds an inner TCP segment (20-byte header). Asserts
// the inner IPv4 TCP header is findable.
func TestI16_InnerTCP(t *testing.T) {
	spec := defaultOpenVPNSpec()
	spec.OpenVPN.InnerIPPackets = []core.OpenVPNInnerIP{
		{SrcIP: "10.10.10.1", DstIP: "10.10.10.2", Proto: 6, SrcPort: 12345, DstPort: 80, Payload: []byte("GET /")},
	}
	planner := NewPlanner()
	ch, err := planner.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan failed: %v", err)
	}
	pkts := collectPackets(context.Background(), t, ch)

	up := dataV2UpPackets(pkts)
	if len(up) != 1 {
		t.Fatalf("up P_DATA_V2 count: got %d, want 1", len(up))
	}
	enc := extractEncryptedPayload(up[0].Payload)
	idx := -1
	src := [4]byte{10, 10, 10, 1}
	dst := [4]byte{10, 10, 10, 2}
	for i := 0; i+20 <= len(enc); i++ {
		if enc[i] == 0x45 && bytes.Equal(enc[i+12:i+16], src[:]) && bytes.Equal(enc[i+16:i+20], dst[:]) {
			idx = i
			break
		}
	}
	if idx < 0 {
		t.Fatal("inner IPv4 header not found")
	}
	if enc[idx+9] != 6 {
		t.Errorf("inner IPv4 protocol: got %d, want 6 (TCP)", enc[idx+9])
	}
	// Inner TCP source port at offset 20-21 (after 20-byte IP header).
	if idx+22 > len(enc) {
		t.Fatal("encrypted region too short for inner TCP header")
	}
	innerSP := binary.BigEndian.Uint16(enc[idx+20 : idx+22])
	if innerSP != 12345 {
		t.Errorf("inner TCP src port: got %d, want 12345", innerSP)
	}
}

// --- I17: V3 uses inner IP too ---

// Spec: V3 (opcode 10) also carries inner IP in P_DATA_V2. Asserts the
// P_DATA_V2 count and inner IP presence for a V3 config.
func TestI17_V3InnerIP(t *testing.T) {
	spec := defaultOpenVPNSpec()
	spec.OpenVPN.Version = "3"
	spec.OpenVPN.InnerIPPackets = []core.OpenVPNInnerIP{
		{SrcIP: "10.10.10.1", DstIP: "10.10.10.2", Proto: 17, Payload: []byte("v3")},
	}
	planner := NewPlanner()
	ch, err := planner.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan failed: %v", err)
	}
	pkts := collectPackets(context.Background(), t, ch)

	up := dataV2UpPackets(pkts)
	if len(up) != 1 {
		t.Fatalf("up P_DATA_V2 count: got %d, want 1", len(up))
	}
	enc := extractEncryptedPayload(up[0].Payload)
	src := [4]byte{10, 10, 10, 1}
	dst := [4]byte{10, 10, 10, 2}
	if !findInnerIPv4InEncrypted(enc, src, dst) {
		t.Errorf("V3 inner IPv4 not found in encrypted payload region")
	}
}

// Spec: in TCP mode, each P_DATA_V2 is framed with the 2-byte BE length
// prefix (OpenVPN-over-TCP stream framing). The inner IP bytes live inside
// the encrypted region of the P_DATA_V2, and the length prefix must still
// be correct. This is a regression guard for W9.
func TestI13_TCPModeInnerIPFraming(t *testing.T) {
	spec := defaultOpenVPNSpec()
	spec.UDP = nil
	spec.TCP = &core.TCPConfig{Handshake: true, Termination: true, MSS: 1460}
	spec.OpenVPN.Proto = "tcp"
	spec.OpenVPN.InnerIPPackets = []core.OpenVPNInnerIP{
		{SrcIP: "10.10.10.1", DstIP: "10.10.10.2", Proto: 17, Payload: []byte("tcp-tunnel")},
	}
	planner := NewPlanner()
	ch, err := planner.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan failed: %v", err)
	}
	pkts := collectPackets(context.Background(), t, ch)

	// Find a TCP PSH-ACK up packet whose payload (after 2B prefix) is a
	// P_DATA_V2. The payload may be segmented across multiple PSH-ACK
	// segments by emitTCPData; we reassemble consecutive up PSH-ACK
	// segments into one OpenVPN frame by following the 2B length prefix.
	var frame []byte
	for _, p := range pkts {
		if p.Direction != "up" || p.L4.Protocol != "tcp" || p.L4.Flags != 0x18 {
			continue
		}
		if len(p.Payload) < 3 {
			continue
		}
		declared := int(p.Payload[0])<<8 | int(p.Payload[1])
		// A P_DATA_V2 header (opcode 9<<3) at offset 2.
		if p.Payload[2]>>POpcodeShift == OpcodeDATAV2 && declared == len(p.Payload)-2 {
			frame = p.Payload
			break
		}
	}
	if frame == nil {
		t.Fatal("no TCP-framed P_DATA_V2 up packet found")
	}
	// Verify the inner IPv4 is present after the prefix + P_DATA_V2 header.
	// frame = [2B len][opcode(1)][peer_id(3)][encrypted...]
	if len(frame) < 2+4 {
		t.Fatalf("frame too short: %d", len(frame))
	}
	enc := frame[2+4:]
	src := [4]byte{10, 10, 10, 1}
	dst := [4]byte{10, 10, 10, 2}
	if !findInnerIPv4InEncrypted(enc, src, dst) {
		t.Errorf("TCP-mode P_DATA_V2 does not carry inner IPv4 in encrypted region")
	}
}
