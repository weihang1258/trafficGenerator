package sctp

// Test points for the SCTP planner. Each test asserts observable
// PacketConfig field values, not just "no error". Derived from the
// session-level structure documented in sctp.go (RFC 4960).

import (
	"context"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

// drain collects all configs from the channel.
func drain(ch <-chan core.PacketConfig) []core.PacketConfig {
	var out []core.PacketConfig
	for c := range ch {
		out = append(out, c)
	}
	return out
}

// validSCTPSpec returns a spec with a minimal DATA chunk. Models a single
// up-direction SCTP DATA chunk (e.g. NGAP payload) on port 38412.
func validSCTPSpec() core.FlowSpec {
	return core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 38413, DstPort: 38412,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		SCTP: &core.SCTPConfig{
			Chunks: []core.SCTPChunk{
				{
					SID:  1,
					SSN:  0,
					PPID: 60, // NGAP
					Data: []byte("ping"),
					Direction: "up",
				},
			},
		},
	}
}

// --- Validate ---

func TestSCTPValidate_ValidIPs(t *testing.T) {
	p := NewPlanner()
	spec := validSCTPSpec()
	if err := p.Validate(spec); err != nil {
		t.Errorf("valid spec: %v", err)
	}
}

func TestSCTPValidate_InvalidSrcIP(t *testing.T) {
	p := NewPlanner()
	spec := validSCTPSpec()
	spec.SrcIP = "bad"
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "invalid source IP") {
		t.Errorf("err=%v, want contains 'invalid source IP'", err)
	}
}

func TestSCTPValidate_InvalidDstIP(t *testing.T) {
	p := NewPlanner()
	spec := validSCTPSpec()
	spec.DstIP = "bad"
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "invalid destination IP") {
		t.Errorf("err=%v, want contains 'invalid destination IP'", err)
	}
}

func TestSCTPValidate_NilSCTPConfig(t *testing.T) {
	p := NewPlanner()
	spec := validSCTPSpec()
	spec.SCTP = nil
	if err := p.Validate(spec); err != nil {
		t.Errorf("nil SCTP config should be accepted: %v", err)
	}
}

// TestSCTPValidate_AltPathIPv6Rejected verifies that an IPv6 AltPath address
// is rejected at Validate time. Without this, buildIPv4AddrParam silently
// returns nil for IPv6 -> INIT has no multi-homing param but HEARTBEATs
// still originate from the IPv6 alt address -> DPI sees two unrelated flows.
func TestSCTPValidate_AltPathIPv6Rejected(t *testing.T) {
	p := NewPlanner()
	spec := validSCTPSpec()
	spec.SCTP.Heartbeats = &core.SCTPHeartbeatConfig{
		Count:   1,
		AltPath: &core.SCTPAltPath{SrcIP: "2001:db8::1", DstIP: "10.0.0.4"},
	}
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "AltPath.SrcIP") {
		t.Errorf("err=%v, want contains 'AltPath.SrcIP' (IPv6 rejected)", err)
	}
}

// TestSCTPValidate_AltPathGarbageRejected verifies that an unparseable
// AltPath IP is rejected at Validate time.
func TestSCTPValidate_AltPathGarbageRejected(t *testing.T) {
	p := NewPlanner()
	spec := validSCTPSpec()
	spec.SCTP.Heartbeats = &core.SCTPHeartbeatConfig{
		Count:   1,
		AltPath: &core.SCTPAltPath{SrcIP: "garbage", DstIP: "10.0.0.4"},
	}
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "AltPath.SrcIP") {
		t.Errorf("err=%v, want contains 'AltPath.SrcIP' (garbage rejected)", err)
	}
}

// TestSCTPValidate_AltPathIPv4Accepted verifies that a valid IPv4 AltPath
// passes Validate (the happy path for multi-homing).
func TestSCTPValidate_AltPathIPv4Accepted(t *testing.T) {
	p := NewPlanner()
	spec := validSCTPSpec()
	spec.SCTP.Heartbeats = &core.SCTPHeartbeatConfig{
		Count:   1,
		AltPath: &core.SCTPAltPath{SrcIP: "10.0.0.3", DstIP: "10.0.0.4"},
	}
	if err := p.Validate(spec); err != nil {
		t.Errorf("valid IPv4 AltPath: %v", err)
	}
}

// TestSCTPValidate_AltPathDstIPv6Rejected verifies that an IPv6 DstIP on
// AltPath (with valid IPv4 SrcIP) is rejected at Validate time. Pre-fix
// only the SrcIP branch was tested, so the DstIP IPv6 path could be
// silently broken.
func TestSCTPValidate_AltPathDstIPv6Rejected(t *testing.T) {
	p := NewPlanner()
	spec := validSCTPSpec()
	spec.SCTP.Heartbeats = &core.SCTPHeartbeatConfig{
		Count:   1,
		AltPath: &core.SCTPAltPath{SrcIP: "10.0.0.3", DstIP: "2001:db8::1"},
	}
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "AltPath.DstIP") {
		t.Errorf("err=%v, want contains 'AltPath.DstIP' (IPv6 DstIP rejected)", err)
	}
}

// TestSCTPValidate_AltPathFamilyMismatchRejected verifies that an IPv4
// AltPath paired with an IPv6 parent spec is rejected. Per RFC 4960 §6.4
// multi-homing addresses must be in the same family as the primary path.
// Pre-fix this case passed Validate but produced semantically broken
// INIT-ACK (IPv4 Address params inside an IPv6 SCTP packet).
func TestSCTPValidate_AltPathFamilyMismatchRejected(t *testing.T) {
	p := NewPlanner()
	spec := validSCTPSpec()
	spec.SrcIP = "2001:db8::1"
	spec.DstIP = "2001:db8::2"
	spec.SCTP.Heartbeats = &core.SCTPHeartbeatConfig{
		Count:   1,
		AltPath: &core.SCTPAltPath{SrcIP: "10.0.0.3", DstIP: "10.0.0.4"},
	}
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "same address family") {
		t.Errorf("err=%v, want contains 'same address family' (family mismatch rejected)", err)
	}
}

// --- Plan: structure ---

// TestSCTPPlan_Handshake verifies the first 4 packets are INIT, INIT-ACK,
// COOKIE-ECHO, COOKIE-ACK with the correct directions and IP protocol 132.
func TestSCTPPlan_Handshake(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validSCTPSpec()))
	if len(cfgs) < 4 {
		t.Fatalf("len=%d, want >= 4 (handshake)", len(cfgs))
	}
	// INIT up
	if cfgs[0].Direction != "up" {
		t.Errorf("cfg[0]: dir=%s, want up", cfgs[0].Direction)
	}
	if cfgs[0].L3.Protocol != core.ProtocolSCTP {
		t.Errorf("cfg[0]: protocol=%d, want %d (SCTP=132)", cfgs[0].L3.Protocol, core.ProtocolSCTP)
	}
	if cfgs[0].L4.Protocol != "sctp" {
		t.Errorf("cfg[0]: L4 protocol=%s, want sctp", cfgs[0].L4.Protocol)
	}
	// INIT carries VerificationTag=0 per RFC 4960 §5.1.1
	if cfgs[0].L4.Ack != 0 {
		t.Errorf("cfg[0] (INIT): VerificationTag=%d, want 0 per RFC 4960 §5.1.1", cfgs[0].L4.Ack)
	}
	// INIT chunk type = 1
	if len(cfgs[0].Payload) < 4 || cfgs[0].Payload[0] != ChunkINIT {
		t.Errorf("cfg[0] payload: expected INIT chunk (type 1), got %v", cfgs[0].Payload)
	}
	// INIT-ACK down
	if cfgs[1].Direction != "down" {
		t.Errorf("cfg[1]: dir=%s, want down", cfgs[1].Direction)
	}
	if cfgs[1].L4.Ack == 0 {
		t.Errorf("cfg[1] (INIT-ACK): VerificationTag=0, want non-zero (client's tag from INIT)")
	}
	if len(cfgs[1].Payload) < 4 || cfgs[1].Payload[0] != ChunkINITAck {
		t.Errorf("cfg[1] payload: expected INIT-ACK chunk (type 2), got %v", cfgs[1].Payload)
	}
	// INIT-ACK ports must be swapped relative to INIT: src=server's port
	// (spec.DstPort), dst=client's port (spec.SrcPort). Pre-fix the swap was
	// missing and INIT-ACK carried the same (src,dst) as INIT.
	if cfgs[1].L4.SrcPort != cfgs[0].L4.DstPort {
		t.Errorf("cfg[1] (INIT-ACK) SrcPort=%d, want %d (server's port = INIT DstPort)",
			cfgs[1].L4.SrcPort, cfgs[0].L4.DstPort)
	}
	if cfgs[1].L4.DstPort != cfgs[0].L4.SrcPort {
		t.Errorf("cfg[1] (INIT-ACK) DstPort=%d, want %d (client's port = INIT SrcPort)",
			cfgs[1].L4.DstPort, cfgs[0].L4.SrcPort)
	}
	// COOKIE-ECHO up
	if cfgs[2].Direction != "up" {
		t.Errorf("cfg[2]: dir=%s, want up", cfgs[2].Direction)
	}
	if cfgs[2].L4.Ack == 0 {
		t.Errorf("cfg[2] (COOKIE-ECHO): VerificationTag=0, want non-zero (server's tag from INIT-ACK)")
	}
	if len(cfgs[2].Payload) < 4 || cfgs[2].Payload[0] != ChunkCOOKIEEcho {
		t.Errorf("cfg[2] payload: expected COOKIE-ECHO chunk (type 10), got %v", cfgs[2].Payload)
	}
	// COOKIE-ACK down
	if cfgs[3].Direction != "down" {
		t.Errorf("cfg[3]: dir=%s, want down", cfgs[3].Direction)
	}
	if len(cfgs[3].Payload) < 4 || cfgs[3].Payload[0] != ChunkCOOKIEAck {
		t.Errorf("cfg[3] payload: expected COOKIE-ACK chunk (type 11), got %v", cfgs[3].Payload)
	}
}

// TestSCTPPlan_Teardown verifies the last 3 packets are SHUTDOWN,
// SHUTDOWN-ACK, SHUTDOWN-COMPLETE in the standard order.
func TestSCTPPlan_Teardown(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validSCTPSpec()))
	n := len(cfgs)
	if n < 3 {
		t.Fatalf("len=%d, want >= 3 (teardown)", n)
	}
	// SHUTDOWN up
	if cfgs[n-3].Direction != "up" {
		t.Errorf("cfg[%d]: dir=%s, want up", n-3, cfgs[n-3].Direction)
	}
	if len(cfgs[n-3].Payload) < 4 || cfgs[n-3].Payload[0] != ChunkSHUTDOWN {
		t.Errorf("cfg[%d] payload: expected SHUTDOWN chunk (type 7), got %v", n-3, cfgs[n-3].Payload)
	}
	// SHUTDOWN-ACK down
	if cfgs[n-2].Direction != "down" {
		t.Errorf("cfg[%d]: dir=%s, want down", n-2, cfgs[n-2].Direction)
	}
	if len(cfgs[n-2].Payload) < 4 || cfgs[n-2].Payload[0] != ChunkSHUTDOWNAck {
		t.Errorf("cfg[%d] payload: expected SHUTDOWN-ACK chunk (type 8), got %v", n-2, cfgs[n-2].Payload)
	}
	// SHUTDOWN-COMPLETE up
	if cfgs[n-1].Direction != "up" {
		t.Errorf("cfg[%d]: dir=%s, want up", n-1, cfgs[n-1].Direction)
	}
	if len(cfgs[n-1].Payload) < 4 || cfgs[n-1].Payload[0] != ChunkSHUTDOWNComplete {
		t.Errorf("cfg[%d] payload: expected SHUTDOWN-COMPLETE chunk (type 14), got %v", n-1, cfgs[n-1].Payload)
	}
}

// TestSCTPPlan_DataChunkEmitted verifies that the DATA chunk is emitted
// between the handshake and teardown with the correct TSN/SID/SSN/PPID.
func TestSCTPPlan_DataChunkEmitted(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validSCTPSpec()))
	// handshake(4) + DATA(1) + teardown(3) = 8 packets
	if len(cfgs) != 8 {
		t.Fatalf("len=%d, want 8", len(cfgs))
	}
	data := cfgs[4]
	if data.Direction != "up" {
		t.Errorf("cfg[4]: dir=%s, want up", data.Direction)
	}
	if len(data.Payload) < 4+12+len("ping") {
		t.Fatalf("cfg[4] payload too short: %d bytes", len(data.Payload))
	}
	// DATA chunk: type(1) + flags(1) + length(2) + TSN(4) + SID(2) + SSN(2) + PPID(4) + data
	if data.Payload[0] != ChunkDATA {
		t.Errorf("cfg[4]: chunk type=%d, want %d (DATA)", data.Payload[0], ChunkDATA)
	}
	if data.Payload[1] != ChunkFlagBeginEnd {
		t.Errorf("cfg[4]: flags=%#x, want %#x (B+E)", data.Payload[1], ChunkFlagBeginEnd)
	}
	tsn := binary.BigEndian.Uint32(data.Payload[4:8])
	if tsn == 0 {
		t.Errorf("cfg[4]: TSN=0, want non-zero (planner auto-increments)")
	}
	sid := binary.BigEndian.Uint16(data.Payload[8:10])
	if sid != 1 {
		t.Errorf("cfg[4]: SID=%d, want 1", sid)
	}
	ssn := binary.BigEndian.Uint16(data.Payload[10:12])
	if ssn != 0 {
		t.Errorf("cfg[4]: SSN=%d, want 0", ssn)
	}
	ppid := binary.BigEndian.Uint32(data.Payload[12:16])
	if ppid != 60 {
		t.Errorf("cfg[4]: PPID=%d, want 60 (NGAP)", ppid)
	}
	// User data
	if string(data.Payload[16:]) != "ping" {
		t.Errorf("cfg[4]: data=%q, want 'ping'", data.Payload[16:])
	}
	// VerificationTag in DATA chunk must equal server's tag (non-zero)
	if data.L4.Ack == 0 {
		t.Errorf("cfg[4]: VerificationTag=0, want non-zero (server's tag from INIT-ACK)")
	}
}

// TestSCTPPlan_EmptyChunksEmitsHandshakeAndTeardownOnly verifies the
// degenerate case: no chunks → just SCTP handshake + teardown.
func TestSCTPPlan_EmptyChunksEmitsHandshakeAndTeardownOnly(t *testing.T) {
	p := NewPlanner()
	spec := validSCTPSpec()
	spec.SCTP.Chunks = nil
	cfgs := drain(mustPlan(t, p, spec))
	// handshake(4) + teardown(3) = 7 packets
	if len(cfgs) != 7 {
		t.Fatalf("len=%d, want 7 (4 handshake + 3 teardown)", len(cfgs))
	}
}

// TestSCTPPlan_InitialSeqOverride verifies that spec.SCTP.VerificationTag
// fixes the client's verification tag for reproducible tests.
func TestSCTPPlan_InitialSeqOverride(t *testing.T) {
	p := NewPlanner()
	spec := validSCTPSpec()
	spec.SCTP.VerificationTag = 0xdeadbeef
	cfgs := drain(mustPlan(t, p, spec))
	// INIT-ACK carries the client's tag in the common header
	if cfgs[1].L4.Ack != 0xdeadbeef {
		t.Errorf("cfg[1] (INIT-ACK): VerificationTag=%x, want deadbeef (client's tag)", cfgs[1].L4.Ack)
	}
	// COOKIE-ACK also carries the client's tag
	if cfgs[3].L4.Ack != 0xdeadbeef {
		t.Errorf("cfg[3] (COOKIE-ACK): VerificationTag=%x, want deadbeef", cfgs[3].L4.Ack)
	}
}

// TestSCTPPlan_FlowIDShared verifies all packets share one flow ID (the
// session-level invariant: one SCTP association = one flow).
func TestSCTPPlan_FlowIDShared(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validSCTPSpec()))
	flowID := cfgs[0].FlowID
	if flowID == "" {
		t.Fatal("FlowID empty")
	}
	for i, c := range cfgs {
		if c.FlowID != flowID {
			t.Errorf("cfg[%d].FlowID=%q, want %q (one flow per session)", i, c.FlowID, flowID)
		}
	}
}

// TestSCTPPlan_IPIDIncrementsPerPacket verifies that every packet has a
// distinct IP ID (no cross-packet ID reuse within the flow).
func TestSCTPPlan_IPIDIncrementsPerPacket(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validSCTPSpec()))
	seen := make(map[uint16]bool)
	for i, c := range cfgs {
		if seen[c.L3.IPID] {
			t.Errorf("cfg[%d] IPID=%d duplicated", i, c.L3.IPID)
		}
		seen[c.L3.IPID] = true
	}
}

// TestSCTPPlan_ChunkPadding verifies that SCTP chunks are padded to a
// 4-byte boundary per RFC 4960 §3.2. A 4-byte "ping" payload in a DATA
// chunk = 4 (chunk header) + 12 (TSN/SID/SSN/PPID) + 4 (data) = 20 bytes,
// which is already 4-aligned, so no padding. A 5-byte payload would
// produce 21 bytes, padded to 24.
func TestSCTPPlan_ChunkPadding(t *testing.T) {
	p := NewPlanner()
	spec := validSCTPSpec()
	spec.SCTP.Chunks = []core.SCTPChunk{
		{SID: 1, PPID: 60, Data: []byte("12345"), Direction: "up"},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// handshake(4) + DATA(1) + teardown(3) = 8 packets
	if len(cfgs) != 8 {
		t.Fatalf("len=%d, want 8", len(cfgs))
	}
	data := cfgs[4]
	// 4 (chunk header) + 12 (TSN/SID/SSN/PPID) + 5 (data) = 21, padded to 24
	want := 4 + 12 + 5
	if len(data.Payload) < want {
		t.Fatalf("cfg[4] payload len=%d, want >= %d (before padding)", len(data.Payload), want)
	}
	padded := (want + 3) &^ 3
	if len(data.Payload) != padded {
		t.Errorf("cfg[4] payload len=%d, want %d (padded to 4-byte boundary)", len(data.Payload), padded)
	}
	// Chunk Length field (bytes 2-3) must be the unpadded length (21)
	chunkLen := binary.BigEndian.Uint16(data.Payload[2:4])
	if int(chunkLen) != want {
		t.Errorf("cfg[4] chunk Length=%d, want %d (unpadded)", chunkLen, want)
	}
}

// TestSCTPPlan_DownDirectionDataChunk verifies that a chunk with
// Direction="down" emits from the server side with the server's tag.
func TestSCTPPlan_DownDirectionDataChunk(t *testing.T) {
	p := NewPlanner()
	spec := validSCTPSpec()
	spec.SCTP.Chunks = []core.SCTPChunk{
		{SID: 1, PPID: 60, Data: []byte("resp"), Direction: "down"},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// handshake(4) + DATA(1) + teardown(3) = 8 packets
	if len(cfgs) != 8 {
		t.Fatalf("len=%d, want 8", len(cfgs))
	}
	data := cfgs[4]
	if data.Direction != "down" {
		t.Errorf("cfg[4]: dir=%s, want down", data.Direction)
	}
	// Down-direction DATA chunks carry the client's tag (server->client
	// uses the tag the client advertised in INIT)
	if data.L4.Ack == 0 {
		t.Errorf("cfg[4]: VerificationTag=0, want non-zero (client's tag)")
	}
}

// TestSCTPPlan_MultipleDataChunksTSNIncrements verifies that when multiple
// DATA chunks are emitted in the same direction without explicit TSNs,
// the planner auto-increments TSN per chunk.
func TestSCTPPlan_MultipleDataChunksTSNIncrements(t *testing.T) {
	p := NewPlanner()
	spec := validSCTPSpec()
	spec.SCTP.Chunks = []core.SCTPChunk{
		{SID: 1, Data: []byte("a"), Direction: "up"},
		{SID: 1, Data: []byte("b"), Direction: "up"},
		{SID: 1, Data: []byte("c"), Direction: "up"},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// handshake(4) + DATA(3) + teardown(3) = 10 packets
	if len(cfgs) != 10 {
		t.Fatalf("len=%d, want 10", len(cfgs))
	}
	tsns := make([]uint32, 0, 3)
	for i := 4; i < 7; i++ {
		tsn := binary.BigEndian.Uint32(cfgs[i].Payload[4:8])
		tsns = append(tsns, tsn)
	}
	// TSNs must be strictly increasing
	for i := 1; i < len(tsns); i++ {
		if tsns[i] != tsns[i-1]+1 {
			t.Errorf("TSN[%d]=%d, want %d (strict +1 increment)", i, tsns[i], tsns[i-1]+1)
		}
	}
}

// TestSCTPPlan_ProtocolField verifies that the L3 Protocol field is 132
// (SCTP) on every packet in the flow.
func TestSCTPPlan_ProtocolField(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validSCTPSpec()))
	for i, c := range cfgs {
		if c.L3.Protocol != core.ProtocolSCTP {
			t.Errorf("cfg[%d]: L3 Protocol=%d, want %d (SCTP)", i, c.L3.Protocol, core.ProtocolSCTP)
		}
	}
}

// mustPlan is a helper that fails the test if Plan returns an error.
func mustPlan(t *testing.T, p *Planner, spec core.FlowSpec) <-chan core.PacketConfig {
	t.Helper()
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan returned error: %v", err)
	}
	return ch
}
