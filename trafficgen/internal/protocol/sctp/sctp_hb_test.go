package sctp

// HEARTBEAT chunk test points for the SCTP planner. These verify that
// HEARTBEAT/HEARTBEAT-ACK chunks are emitted at the right position
// (between COOKIE-ACK and the first DATA chunk), with the right chunk
// type bytes, and that AltPath produces multi-homing (different IPs on
// the heartbeat packets). Derived from SCTPHeartbeatConfig in types.go
// and the emit-SCTP-heartbeats algorithm in sctp.go.

import (
	"context"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

// heartbeatSpec returns a spec with one DATA chunk and 3 heartbeat pairs
// on the primary path. The dialog is:
//
//	INIT → INIT-ACK → COOKIE-ECHO → COOKIE-ACK
//	  → [HB, HB-ACK] × 3
//	  → DATA
//	  → SHUTDOWN → SHUTDOWN-ACK → SHUTDOWN-COMPLETE
func heartbeatSpec() core.FlowSpec {
	return core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 38413, DstPort: 38412,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		SCTP: &core.SCTPConfig{
			Chunks: []core.SCTPChunk{
				{SID: 1, PPID: 60, Data: []byte("ping"), Direction: "up"},
			},
			Heartbeats: &core.SCTPHeartbeatConfig{
				Count: 3,
			},
		},
	}
}

// findHeartbeatPackets returns configs whose Payload starts with the
// HEARTBEAT chunk type byte (0x04) or HEARTBEAT-ACK (0x05).
func findHeartbeatPackets(cfgs []core.PacketConfig) []core.PacketConfig {
	var out []core.PacketConfig
	for _, c := range cfgs {
		if len(c.Payload) >= 1 && (c.Payload[0] == 0x04 || c.Payload[0] == 0x05) {
			out = append(out, c)
		}
	}
	return out
}

// findFirstChunkType returns the index of the first config whose Payload
// starts with the given SCTP chunk type byte.
func findFirstChunkType(cfgs []core.PacketConfig, chunkType byte) int {
	for i, c := range cfgs {
		if len(c.Payload) >= 1 && c.Payload[0] == chunkType {
			return i
		}
	}
	return -1
}

// TestSCTPHeartbeat_PairsEmitted verifies Count=3 produces 6 heartbeat
// packets (3 pairs of HEARTBEAT + HEARTBEAT-ACK).
func TestSCTPHeartbeat_PairsEmitted(t *testing.T) {
	spec := heartbeatSpec()
	ch, err := NewPlanner().Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	cfgs := drain(ch)

	hb := findHeartbeatPackets(cfgs)
	if got, want := len(hb), 6; got != want {
		t.Errorf("len(heartbeats)=%d, want %d (3 pairs)", got, want)
	}
}

// TestSCTPHeartbeat_DefaultCount verifies Count=0 defaults to 1 pair
// (2 packets).
func TestSCTPHeartbeat_DefaultCount(t *testing.T) {
	spec := heartbeatSpec()
	spec.SCTP.Heartbeats.Count = 0
	ch, err := NewPlanner().Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	cfgs := drain(ch)

	hb := findHeartbeatPackets(cfgs)
	if got, want := len(hb), 2; got != want {
		t.Errorf("Count=0 -> len(heartbeats)=%d, want %d (1 pair default)",
			got, want)
	}
}

// TestSCTPHeartbeat_NoHeartbeats verifies Heartbeats=nil produces no
// heartbeat packets (backward compat).
func TestSCTPHeartbeat_NoHeartbeats(t *testing.T) {
	spec := validSCTPSpec() // no Heartbeats
	ch, err := NewPlanner().Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	cfgs := drain(ch)
	hb := findHeartbeatPackets(cfgs)
	if len(hb) != 0 {
		t.Errorf("Heartbeats=nil but got %d heartbeat packets, want 0", len(hb))
	}
}

// TestSCTPHeartbeat_PositionBetweenCookieAckAndData verifies heartbeats
// land AFTER COOKIE-ACK (type 11) and BEFORE the first DATA chunk (type 0).
// This is the SCTP heartbeat semantic: heartbeats ride the association
// after it's established but before user data flows.
func TestSCTPHeartbeat_PositionBetweenCookieAckAndData(t *testing.T) {
	spec := heartbeatSpec()
	ch, err := NewPlanner().Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	cfgs := drain(ch)

	idxCookieAck := findFirstChunkType(cfgs, 0x0B) // COOKIE-ACK = 11
	if idxCookieAck < 0 {
		t.Fatalf("COOKIE-ACK not found")
	}
	idxData := findFirstChunkType(cfgs, 0x00) // DATA = 0
	if idxData < 0 {
		t.Fatalf("DATA chunk not found")
	}
	if idxCookieAck >= idxData {
		t.Fatalf("COOKIE-ACK at %d should precede DATA at %d",
			idxCookieAck, idxData)
	}

	firstHB := findFirstChunkType(cfgs, 0x04) // HEARTBEAT = 4
	if firstHB < 0 {
		t.Fatalf("HEARTBEAT not found")
	}
	if firstHB <= idxCookieAck {
		t.Errorf("first HB at %d should be after COOKIE-ACK at %d",
			firstHB, idxCookieAck)
	}
	if firstHB >= idxData {
		t.Errorf("first HB at %d should be before DATA at %d",
			firstHB, idxData)
	}
}

// TestSCTPHeartbeat_AlternatingHBandAck verifies heartbeat packets
// alternate HB (up) → HB-ACK (down) → HB (up) → HB-ACK (down).
func TestSCTPHeartbeat_AlternatingHBandAck(t *testing.T) {
	spec := heartbeatSpec()
	ch, err := NewPlanner().Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	cfgs := drain(ch)
	hb := findHeartbeatPackets(cfgs)
	if len(hb) < 2 {
		t.Fatalf("len(hb)=%d, want >= 2", len(hb))
	}
	for i, c := range hb {
		expectedType := byte(0x04) // HB
		expectedDir := "up"
		if i%2 == 1 {
			expectedType = 0x05 // HB-ACK
			expectedDir = "down"
		}
		if c.Payload[0] != expectedType {
			t.Errorf("hb[%d] type=%#02x, want %#02x", i, c.Payload[0], expectedType)
		}
		if c.Direction != expectedDir {
			t.Errorf("hb[%d] dir=%q, want %q", i, c.Direction, expectedDir)
		}
	}
}

// TestSCTPHeartbeat_AckEchoesHBInfo verifies HEARTBEAT-ACK echoes the
// Heartbeat Info TLV from the corresponding HEARTBEAT (RFC 4960 §3.5.2).
// The HB-Info is bytes 4..end of the chunk value (after Type+Flags+Length
// chunk header + 4-byte TLV header).
func TestSCTPHeartbeat_AckEchoesHBInfo(t *testing.T) {
	spec := heartbeatSpec()
	spec.SCTP.Heartbeats.Count = 1
	ch, err := NewPlanner().Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	cfgs := drain(ch)
	hb := findHeartbeatPackets(cfgs)
	if len(hb) != 2 {
		t.Fatalf("len(hb)=%d, want 2", len(hb))
	}
	hbPkt := hb[0]
	ackPkt := hb[1]

	// Extract HB-Info: skip 4-byte chunk header + 4-byte TLV header.
	if len(hbPkt.Payload) < 8 {
		t.Fatalf("HB payload too short: %d", len(hbPkt.Payload))
	}
	hbInfo := hbPkt.Payload[8:]
	if len(ackPkt.Payload) < 8 {
		t.Fatalf("HB-ACK payload too short: %d", len(ackPkt.Payload))
	}
	ackInfo := ackPkt.Payload[8:]
	if string(hbInfo) != string(ackInfo) {
		t.Errorf("HB-ACK info=%v, want %v (echo of HB info)", ackInfo, hbInfo)
	}
}

// TestSCTPHeartbeat_MultiHomingAltPath verifies AltPath puts heartbeats
// on the alternate IP tuple while non-heartbeat packets stay on primary.
// HB (up) uses alt-src→alt-dst; HB-ACK (down) swaps them (server→client).
func TestSCTPHeartbeat_MultiHomingAltPath(t *testing.T) {
	spec := heartbeatSpec()
	spec.SCTP.Heartbeats.AltPath = &core.SCTPAltPath{
		SrcIP:  "10.0.0.3",
		DstIP:  "10.0.0.4",
		SrcMAC: "aa:bb:cc:dd:ee:11",
		DstMAC: "11:22:33:44:55:22",
	}
	ch, err := NewPlanner().Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	cfgs := drain(ch)
	hb := findHeartbeatPackets(cfgs)
	if len(hb) == 0 {
		t.Fatalf("no heartbeat packets")
	}
	// HB packets at even indices go up (alt-src→alt-dst); HB-ACK at odd
	// indices go down (alt-dst→alt-src, since the server replies).
	for i, c := range hb {
		if i%2 == 0 {
			// HB up: alt-src → alt-dst
			if c.L3.SrcIP != "10.0.0.3" {
				t.Errorf("hb[%d] SrcIP=%q, want 10.0.0.3 (alt-src)", i, c.L3.SrcIP)
			}
			if c.L3.DstIP != "10.0.0.4" {
				t.Errorf("hb[%d] DstIP=%q, want 10.0.0.4 (alt-dst)", i, c.L3.DstIP)
			}
			if c.L2.SrcMAC != "aa:bb:cc:dd:ee:11" {
				t.Errorf("hb[%d] SrcMAC=%q, want alt", i, c.L2.SrcMAC)
			}
		} else {
			// HB-ACK down: alt-dst → alt-src (swap)
			if c.L3.SrcIP != "10.0.0.4" {
				t.Errorf("hb[%d] SrcIP=%q, want 10.0.0.4 (alt-dst, swapped)",
					i, c.L3.SrcIP)
			}
			if c.L3.DstIP != "10.0.0.3" {
				t.Errorf("hb[%d] DstIP=%q, want 10.0.0.3 (alt-src, swapped)",
					i, c.L3.DstIP)
			}
		}
	}

	// Non-heartbeat packets should remain on primary path.
	for i, c := range cfgs {
		if strings.HasSuffix(c.FlowID, ":hb") {
			continue
		}
		if c.L3.SrcIP == "10.0.0.3" || c.L3.SrcIP == "10.0.0.4" {
			t.Errorf("non-hb packet[%d] on alt path SrcIP=%q",
				i, c.L3.SrcIP)
		}
	}
}

// TestSCTPHeartbeat_MultiHomingFlowIDSuffix verifies AltPath produces
// heartbeats with FlowID "{parent}:hb".
func TestSCTPHeartbeat_MultiHomingFlowIDSuffix(t *testing.T) {
	spec := heartbeatSpec()
	spec.SCTP.Heartbeats.AltPath = &core.SCTPAltPath{
		SrcIP: "10.0.0.3", DstIP: "10.0.0.4",
	}
	ch, err := NewPlanner().Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	cfgs := drain(ch)
	hb := findHeartbeatPackets(cfgs)
	if len(hb) == 0 {
		t.Fatalf("no heartbeat packets")
	}
	want := "10.0.0.1-10.0.0.2-38413-38412:hb"
	for i, c := range hb {
		if c.FlowID != want {
			t.Errorf("hb[%d].FlowID=%q, want %q", i, c.FlowID, want)
		}
	}
}

// TestSCTPHeartbeat_NoAltPathUsesPrimaryFlowID verifies heartbeats without
// AltPath use the parent's FlowID (no suffix).
func TestSCTPHeartbeat_NoAltPathUsesPrimaryFlowID(t *testing.T) {
	spec := heartbeatSpec() // no AltPath
	ch, err := NewPlanner().Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	cfgs := drain(ch)
	hb := findHeartbeatPackets(cfgs)
	if len(hb) == 0 {
		t.Fatalf("no heartbeat packets")
	}
	want := "10.0.0.1-10.0.0.2-38413-38412"
	for i, c := range hb {
		if c.FlowID != want {
			t.Errorf("hb[%d].FlowID=%q, want %q (no suffix)", i, c.FlowID, want)
		}
	}
}

// TestSCTPHeartbeat_VerificationTag verifies HB carries serverVerTag (up)
// and HB-ACK carries clientVerTag (down), matching the SCTP common-header
// VerificationTag rules (packets to server carry server's tag, packets to
// client carry client's tag).
func TestSCTPHeartbeat_VerificationTag(t *testing.T) {
	spec := heartbeatSpec()
	spec.SCTP.Heartbeats.Count = 1
	// Use fixed tags so we can assert exact values.
	spec.SCTP.VerificationTag = 0x11111111 // client's tag (server→client)
	spec.SCTP.InitiateTag = 0x22222222      // server's tag (client→server)
	ch, err := NewPlanner().Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	cfgs := drain(ch)
	hb := findHeartbeatPackets(cfgs)
	if len(hb) != 2 {
		t.Fatalf("len(hb)=%d, want 2", len(hb))
	}
	// HEARTBEAT up → carries serverVerTag = InitiateTag.
	if hb[0].L4.Ack != 0x22222222 {
		t.Errorf("HB VerificationTag=%#x, want 0x22222222 (server tag)",
			hb[0].L4.Ack)
	}
	// HEARTBEAT-ACK down → carries clientVerTag = VerificationTag.
	if hb[1].L4.Ack != 0x11111111 {
		t.Errorf("HB-ACK VerificationTag=%#x, want 0x11111111 (client tag)",
			hb[1].L4.Ack)
	}
}

// TestSCTPHeartbeat_HBInfoMagic verifies the Heartbeat Info TLV starts
// with the 4-byte magic "HBTC" (0x48425443).
func TestSCTPHeartbeat_HBInfoMagic(t *testing.T) {
	spec := heartbeatSpec()
	spec.SCTP.Heartbeats.Count = 1
	ch, err := NewPlanner().Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	cfgs := drain(ch)
	hb := findHeartbeatPackets(cfgs)
	if len(hb) == 0 {
		t.Fatalf("no heartbeat packets")
	}
	// HB-Info TLV: bytes [8:12] of payload (after 4-byte chunk header + 4-byte TLV header).
	for i, c := range hb {
		if len(c.Payload) < 12 {
			t.Errorf("hb[%d] payload len=%d, want >= 12", i, len(c.Payload))
			continue
		}
		magic := binary.BigEndian.Uint32(c.Payload[8:12])
		if magic != 0x48425443 {
			t.Errorf("hb[%d] magic=%#x, want 0x48425443 (\"HBTC\")", i, magic)
		}
	}
}

// TestSCTPHeartbeat_PacketIndexContinuity verifies heartbeat packets
// continue from the parent's PacketIndex (no reset, no gaps).
func TestSCTPHeartbeat_PacketIndexContinuity(t *testing.T) {
	spec := heartbeatSpec()
	ch, err := NewPlanner().Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	cfgs := drain(ch)

	// Verify all packets (including heartbeats) have monotonic PacketIndex.
	for i := 1; i < len(cfgs); i++ {
		if cfgs[i].PacketIndex != cfgs[i-1].PacketIndex+1 {
			t.Errorf("cfgs[%d].PacketIndex=%d, want %d (prev+1)",
				i, cfgs[i].PacketIndex, cfgs[i-1].PacketIndex+1)
			break
		}
	}
}

// TestSCTPHeartbeat_AltPathPartialOverride verifies that empty fields in
// AltPath fall back to the parent's value (partial override).
// HB (up) uses alt-src→parent-dst; HB-ACK (down) swaps them.
func TestSCTPHeartbeat_AltPathPartialOverride(t *testing.T) {
	spec := heartbeatSpec()
	// Only override SrcIP; DstIP inherits from parent.
	spec.SCTP.Heartbeats.AltPath = &core.SCTPAltPath{
		SrcIP: "10.0.0.3",
	}
	ch, err := NewPlanner().Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	cfgs := drain(ch)
	hb := findHeartbeatPackets(cfgs)
	if len(hb) == 0 {
		t.Fatalf("no heartbeat packets")
	}
	for i, c := range hb {
		if i%2 == 0 {
			// HB up: alt-src → parent-dst
			if c.L3.SrcIP != "10.0.0.3" {
				t.Errorf("hb[%d] SrcIP=%q, want 10.0.0.3 (alt override)",
					i, c.L3.SrcIP)
			}
			if c.L3.DstIP != "10.0.0.2" {
				t.Errorf("hb[%d] DstIP=%q, want 10.0.0.2 (inherited from parent)",
					i, c.L3.DstIP)
			}
		} else {
			// HB-ACK down: parent-dst → alt-src (swap)
			if c.L3.SrcIP != "10.0.0.2" {
				t.Errorf("hb[%d] SrcIP=%q, want 10.0.0.2 (parent, swapped)",
					i, c.L3.SrcIP)
			}
			if c.L3.DstIP != "10.0.0.3" {
				t.Errorf("hb[%d] DstIP=%q, want 10.0.0.3 (alt-src, swapped)",
					i, c.L3.DstIP)
			}
		}
	}
}

// TestSCTPHeartbeat_PortsInheritFromParent verifies heartbeats use the
// parent's SrcPort/DstPort (SCTP heartbeats always ride the association's
// 4-tuple port pair, even on multi-homing).
func TestSCTPHeartbeat_PortsInheritFromParent(t *testing.T) {
	spec := heartbeatSpec()
	spec.SCTP.Heartbeats.AltPath = &core.SCTPAltPath{
		SrcIP: "10.0.0.3", DstIP: "10.0.0.4",
	}
	ch, err := NewPlanner().Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	cfgs := drain(ch)
	hb := findHeartbeatPackets(cfgs)
	if len(hb) == 0 {
		t.Fatalf("no heartbeat packets")
	}
	for i, c := range hb {
		if c.L4.SrcPort != 38413 {
			t.Errorf("hb[%d] SrcPort=%d, want 38413 (parent's)",
				i, c.L4.SrcPort)
		}
		if c.L4.DstPort != 38412 {
			t.Errorf("hb[%d] DstPort=%d, want 38412 (parent's)",
				i, c.L4.DstPort)
		}
	}
}
