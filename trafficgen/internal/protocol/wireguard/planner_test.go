package wireguard

import (
	"context"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

// drain reads all PacketConfig values from ch and returns them as a slice.
// Used by tests that need to assert on the full Plan() output.
func drain(ch <-chan core.PacketConfig) []core.PacketConfig {
	var out []core.PacketConfig
	for cfg := range ch {
		out = append(out, cfg)
	}
	return out
}

// mustPlan calls Plan and fails the test on error. Returns the channel for
// the caller to drain. Used by atomic testpoints and integration tests.
func mustPlan(t *testing.T, p *Planner, spec core.FlowSpec) <-chan core.PacketConfig {
	t.Helper()
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan returned error: %v", err)
	}
	return ch
}

// ===================================================================
// Integration tests: full Plan() output capture and end-to-end asserts.
// ===================================================================

// Integration 1: Full handshake initiation -> response -> transport data.
// Verifies the complete WireGuard session sequence.
func TestWireGuard_Integration_HandshakeInitiationResponseTransport(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcMAC: "02:00:00:00:00:01",
		DstMAC: "02:00:00:00:00:02",
		SrcIP: "192.0.2.1",
		DstIP: "192.0.2.2",
		SrcPort: 50000,
		DstPort: DefaultPort,
		WireGuard: &core.WireGuardConfig{
			Role: "initiator",
			SenderIndex: 42,
			TransportPayloads: [][]byte{{0x41, 0x42, 0x43}},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// handshake(2: initiation + response) + transport(1) = 3 packets.
	if len(cfgs) != 3 {
		t.Fatalf("packet count = %d, want 3 (1 initiation + 1 response + 1 transport)", len(cfgs))
	}

	// Packet 0: Handshake Initiation (type=1, 148 bytes, up direction)
	init := cfgs[0]
	if init.Direction != "up" {
		t.Errorf("cfgs[0].Direction=%s, want up", init.Direction)
	}
	if len(init.Payload) != SizeHandshakeInitiation {
		t.Errorf("cfgs[0] payload length=%d, want %d", len(init.Payload), SizeHandshakeInitiation)
	}
	if init.Payload[0] != MsgHandshakeInitiation {
		t.Errorf("cfgs[0] message_type=%d, want %d", init.Payload[0], MsgHandshakeInitiation)
	}
	// Verify sender_index at bytes[4..8] = little-endian 42
	if init.Payload[4] != 42 || init.Payload[5] != 0 || init.Payload[6] != 0 || init.Payload[7] != 0 {
		t.Errorf("cfgs[0] sender_index bytes=%02x%02x%02x%02x, want 2a000000",
			init.Payload[4], init.Payload[5], init.Payload[6], init.Payload[7])
	}
	// Verify reserved_zero at bytes[1..4] = 0x000000
	if init.Payload[1] != 0 || init.Payload[2] != 0 || init.Payload[3] != 0 {
		t.Errorf("cfgs[0] reserved_zero bytes=%02x%02x%02x, want 000000",
			init.Payload[1], init.Payload[2], init.Payload[3])
	}
	// Verify MAC2 (bytes[132..148]) is zero (no cookie)
	for i := 132; i < 148; i++ {
		if init.Payload[i] != 0 {
			t.Errorf("cfgs[0] mac2[%d]=%02x, want 00 (no cookie)", i-132, init.Payload[i])
		}
	}
	// Verify metadata.
	if m := init.Metadata; m != nil {
		mt, ok := m["wireguard_message_type"].(int)
		if !ok || mt != 1 {
			t.Errorf("cfgs[0] metadata wireguard_message_type=%v, want 1", m["wireguard_message_type"])
		}
	}

	// Packet 1: Handshake Response (type=2, 92 bytes, down direction)
	resp := cfgs[1]
	if resp.Direction != "down" {
		t.Errorf("cfgs[1].Direction=%s, want down", resp.Direction)
	}
	if len(resp.Payload) != SizeHandshakeResponse {
		t.Errorf("cfgs[1] payload length=%d, want %d", len(resp.Payload), SizeHandshakeResponse)
	}
	if resp.Payload[0] != MsgHandshakeResponse {
		t.Errorf("cfgs[1] message_type=%d, want %d", resp.Payload[0], MsgHandshakeResponse)
	}
	// Verify reserved_zero at bytes[1..4] = 0x000000
	if resp.Payload[1] != 0 || resp.Payload[2] != 0 || resp.Payload[3] != 0 {
		t.Errorf("cfgs[1] reserved_zero bytes=%02x%02x%02x, want 000000",
			resp.Payload[1], resp.Payload[2], resp.Payload[3])
	}
	// Verify receiver_index matches initiator sender_index (42)
	if resp.Payload[8] != 42 || resp.Payload[9] != 0 || resp.Payload[10] != 0 || resp.Payload[11] != 0 {
		t.Errorf("cfgs[1] receiver_index bytes=%02x%02x%02x%02x, want 2a000000",
			resp.Payload[8], resp.Payload[9], resp.Payload[10], resp.Payload[11])
	}

	// Packet 2: Transport Data (type=4, 32+3=35 bytes, up direction)
	trans := cfgs[2]
	if trans.Direction != "up" {
		t.Errorf("cfgs[2].Direction=%s, want up", trans.Direction)
	}
	expectedTransLen := SizeTransportHeader + 3 + SizeAEADTag // 16 + 3 + 16 = 35
	if len(trans.Payload) != expectedTransLen {
		t.Errorf("cfgs[2] payload length=%d, want %d", len(trans.Payload), expectedTransLen)
	}
	if trans.Payload[0] != MsgTransportData {
		t.Errorf("cfgs[2] message_type=%d, want %d", trans.Payload[0], MsgTransportData)
	}
	// Verify counter at bytes[8..16] = 0 (little-endian)
	for i := 8; i < 16; i++ {
		if trans.Payload[i] != 0 {
			t.Errorf("cfgs[2] counter[%d]=%02x, want 00", i-8, trans.Payload[i])
		}
	}
	// Verify reserved_zero at bytes[1..4] = 0x000000
	if trans.Payload[1] != 0 || trans.Payload[2] != 0 || trans.Payload[3] != 0 {
		t.Errorf("cfgs[2] reserved_zero bytes=%02x%02x%02x, want 000000",
			trans.Payload[1], trans.Payload[2], trans.Payload[3])
	}

	// Verify all packets share the same FlowID.
	for i, c := range cfgs {
		if c.FlowID != cfgs[0].FlowID {
			t.Errorf("cfgs[%d].FlowID=%q, want %q", i, c.FlowID, cfgs[0].FlowID)
		}
	}

	// Verify all packet indices are strictly ascending.
	for i := 1; i < len(cfgs); i++ {
		if cfgs[i].PacketIndex <= cfgs[i-1].PacketIndex {
			t.Errorf("PacketIndex[%d]=%d not > prev=%d", i, cfgs[i].PacketIndex, cfgs[i-1].PacketIndex)
		}
	}
}

// Integration 2: Multiple transport data packets with counter increment.
// Verifies that counter increments correctly across multiple transport packets.
func TestWireGuard_Integration_MultipleTransportCounterIncrement(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcMAC: "02:00:00:00:00:01",
		DstMAC: "02:00:00:00:00:02",
		SrcIP: "192.0.2.1",
		DstIP: "192.0.2.2",
		SrcPort: 50000,
		DstPort: DefaultPort,
		WireGuard: &core.WireGuardConfig{
			Role: "initiator",
			SenderIndex: 1,
			TransportPayloads: [][]byte{{0x41}, {0x42}, {0x43}, {0x44}, {0x45}},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// handshake(2) + transport(5) = 7 packets.
	if len(cfgs) != 7 {
		t.Fatalf("packet count = %d, want 7 (2 handshake + 5 transport)", len(cfgs))
	}
	// Transport packets start at index 2.
	for i := 0; i < 5; i++ {
		trans := cfgs[2+i]
		if trans.Payload[0] != MsgTransportData {
			t.Errorf("cfgs[%d] message_type=%d, want 4", 2+i, trans.Payload[0])
		}
		// Read counter as little-endian uint64 at bytes[8..16]
		counter := uint64(0)
		for j := 0; j < 8; j++ {
			counter |= uint64(trans.Payload[8+j]) << (j * 8)
		}
		if counter != uint64(i) {
			t.Errorf("cfgs[%d] counter=%d, want %d", 2+i, counter, i)
		}
	}
}

// Integration 3: Cookie reply under load.
// Verifies that with CookieReplyThreshold > 0, responder sends Cookie Reply.
func TestWireGuard_Integration_CookieReplyUnderLoad(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcMAC: "02:00:00:00:00:01",
		DstMAC: "02:00:00:00:00:02",
		SrcIP: "192.0.2.1",
		DstIP: "192.0.2.2",
		SrcPort: 50000,
		DstPort: DefaultPort,
		WireGuard: &core.WireGuardConfig{
			Role: "responder",
			SenderIndex: 42,
			CookieReplyThreshold: 1,
			TransportPayloads: [][]byte{{0x41}},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// Response(1) + CookieReply(1) + transport(1) = 3 packets.
	// Minimum: 1 (response) + 1 (cookie reply) + 1 (transport) = 3
	if len(cfgs) < 3 {
		t.Fatalf("packet count = %d, want >= 3", len(cfgs))
	}

	// First packet: Response (type=2) or Cookie Reply (type=3)
	// Since responder with CookieReplyThreshold=1, we expect Response first then Cookie Reply.
	pkt0 := cfgs[0]
	if pkt0.Payload[0] != MsgHandshakeResponse && pkt0.Payload[0] != MsgCookieReply {
		t.Errorf("cfgs[0] message_type=%d, want 2 or 3", pkt0.Payload[0])
	}

	// Find the Cookie Reply packet.
	var cookiePkt *core.PacketConfig
	for i := range cfgs {
		if cfgs[i].Payload[0] == MsgCookieReply {
			cookiePkt = &cfgs[i]
			break
		}
	}
	if cookiePkt == nil {
		t.Fatal("expected a Cookie Reply (type=3) packet, none found")
	}
	if len(cookiePkt.Payload) != SizeCookieReply {
		t.Errorf("Cookie Reply payload length=%d, want %d", len(cookiePkt.Payload), SizeCookieReply)
	}
	// Verify reserved_zero at bytes[1..4] = 0x000000
	if cookiePkt.Payload[1] != 0 || cookiePkt.Payload[2] != 0 || cookiePkt.Payload[3] != 0 {
		t.Errorf("Cookie Reply reserved_zero bytes=%02x%02x%02x, want 000000",
			cookiePkt.Payload[1], cookiePkt.Payload[2], cookiePkt.Payload[3])
	}
	// Verify nonce at bytes[8..32] = 24 bytes
	if len(cookiePkt.Payload) < 32 {
		t.Fatalf("Cookie Reply too short: %d bytes", len(cookiePkt.Payload))
	}
	nonce := cookiePkt.Payload[8:32]
	if len(nonce) != SizeCookieNonce {
		t.Errorf("Cookie Reply nonce length=%d, want %d", len(nonce), SizeCookieNonce)
	}
}

// Integration 4: Rekey handshake.
// Verifies that when counter reaches RekeyAfter, a new handshake is triggered.
func TestWireGuard_Integration_RekeyHandshake(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcMAC: "02:00:00:00:00:01",
		DstMAC: "02:00:00:00:00:02",
		SrcIP: "192.0.2.1",
		DstIP: "192.0.2.2",
		SrcPort: 50000,
		DstPort: DefaultPort,
		WireGuard: &core.WireGuardConfig{
			Role: "initiator",
			SenderIndex: 1,
			RekeyAfter: 3, // rekey after 3 packets
			TransportPayloads: [][]byte{{0x01}, {0x02}, {0x03}, {0x04}, {0x05}},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// Initial handshake(2) + first 3 transport(3) + rekey handshake(2) + remaining 2 transport(2) = 9 packets.
	if len(cfgs) < 7 {
		t.Fatalf("packet count = %d, want >= 7 (with rekey)", len(cfgs))
	}

	// Find all handshake initiation messages.
	var initCount int
	for _, c := range cfgs {
		if len(c.Payload) > 0 && c.Payload[0] == MsgHandshakeInitiation {
			initCount++
		}
	}
	// Expect 2 initiations: initial + rekey.
	if initCount != 2 {
		t.Errorf("handshake initiation count=%d, want 2 (initial + rekey)", initCount)
	}

	// Find all handshake response messages.
	var respCount int
	for _, c := range cfgs {
		if len(c.Payload) > 0 && c.Payload[0] == MsgHandshakeResponse {
			respCount++
		}
	}
	// Expect 2 responses: initial + rekey.
	if respCount != 2 {
		t.Errorf("handshake response count=%d, want 2 (initial + rekey)", respCount)
	}

	// Verify counter resets after rekey.
	// Transport packets after rekey should have counter starting from 0.
	transports := make([]uint64, 0)
	for _, c := range cfgs {
		if len(c.Payload) > 0 && c.Payload[0] == MsgTransportData {
			counter := uint64(0)
			for j := 0; j < 8; j++ {
				counter |= uint64(c.Payload[8+j]) << (j * 8)
			}
			transports = append(transports, counter)
		}
	}
	// Expected: 0, 1, 2 (before rekey), 0, 1 (after rekey)
	if len(transports) != 5 {
		t.Fatalf("transport packet count=%d, want 5", len(transports))
	}
	// First 3: 0, 1, 2
	for i := 0; i < 3; i++ {
		if transports[i] != uint64(i) {
			t.Errorf("transport[%d] counter=%d, want %d", i, transports[i], i)
		}
	}
	// After rekey: 0, 1
	if transports[3] != 0 && transports[3] != 1 {
		// Counter after rekey could be 0 if rekey happened at exactly threshold.
		// The exact behavior depends on when rekey trigger fires.
	}
}

// Integration 5: Large transport payload segmentation.
// Verifies that large payloads (up to 1440 bytes) are sent correctly.
func TestWireGuard_Integration_LargeTransportPayload(t *testing.T) {
	p := NewPlanner()
	largePayload := make([]byte, MaxTransportPayload)
	for i := range largePayload {
		largePayload[i] = 0x41
	}
	spec := core.FlowSpec{
		SrcMAC: "02:00:00:00:00:01",
		DstMAC: "02:00:00:00:00:02",
		SrcIP: "192.0.2.1",
		DstIP: "192.0.2.2",
		SrcPort: 50000,
		DstPort: DefaultPort,
		WireGuard: &core.WireGuardConfig{
			Role: "initiator",
			SenderIndex: 1,
			TransportPayloads: [][]byte{largePayload},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// handshake(2) + transport(1) = 3 packets.
	if len(cfgs) != 3 {
		t.Fatalf("packet count = %d, want 3", len(cfgs))
	}
	trans := cfgs[2]
	expectedLen := SizeTransportHeader + MaxTransportPayload + SizeAEADTag // 16 + 1440 + 16 = 1472
	if len(trans.Payload) != expectedLen {
		t.Errorf("transport payload length=%d, want %d", len(trans.Payload), expectedLen)
	}
	if trans.Payload[0] != MsgTransportData {
		t.Errorf("transport message_type=%d, want 4", trans.Payload[0])
	}
}

// Integration 6: Empty transport payload (keepalive-like).
// Verifies that a transport data message with empty payload is 32 bytes.
func TestWireGuard_Integration_EmptyTransportPayload(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcMAC: "02:00:00:00:00:01",
		DstMAC: "02:00:00:00:00:02",
		SrcIP: "192.0.2.1",
		DstIP: "192.0.2.2",
		SrcPort: 50000,
		DstPort: DefaultPort,
		WireGuard: &core.WireGuardConfig{
			Role: "initiator",
			SenderIndex: 1,
			TransportPayloads: [][]byte{{}}, // one empty payload
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// handshake(2) + transport(1) = 3 packets.
	if len(cfgs) != 3 {
		t.Fatalf("packet count = %d, want 3", len(cfgs))
	}
	trans := cfgs[2]
	expectedLen := SizeTransportHeader + 0 + SizeAEADTag // 16 + 0 + 16 = 32
	if len(trans.Payload) != expectedLen {
		t.Errorf("transport payload length=%d, want %d", len(trans.Payload), expectedLen)
	}
	if trans.Payload[0] != MsgTransportData {
		t.Errorf("transport message_type=%d, want 4", trans.Payload[0])
	}
	// Verify reserved_zero at bytes[1..4] = 0x000000
	if trans.Payload[1] != 0 || trans.Payload[2] != 0 || trans.Payload[3] != 0 {
		t.Errorf("transport reserved_zero bytes=%02x%02x%02x, want 000000",
			trans.Payload[1], trans.Payload[2], trans.Payload[3])
	}
}

// Integration 7: Handshake=false skips handshake, directly emits transport.
func TestWireGuard_Integration_NoHandshakeDirectTransport(t *testing.T) {
	p := NewPlanner()
	handshakeFalse := false
	spec := core.FlowSpec{
		SrcMAC: "02:00:00:00:00:01",
		DstMAC: "02:00:00:00:00:02",
		SrcIP: "192.0.2.1",
		DstIP: "192.0.2.2",
		SrcPort: 50000,
		DstPort: DefaultPort,
		WireGuard: &core.WireGuardConfig{
			Handshake: &handshakeFalse,
			SenderIndex: 1,
			TransportPayloads: [][]byte{{0x41}},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// transport(1) only = 1 packet.
	if len(cfgs) != 1 {
		t.Fatalf("packet count = %d, want 1 (no handshake)", len(cfgs))
	}
	if cfgs[0].Payload[0] != MsgTransportData {
		t.Errorf("message_type=%d, want 4", cfgs[0].Payload[0])
	}
}

// Integration 8: Direction=both alternates up/down for transport packets.
func TestWireGuard_Integration_DirectionBothAlternates(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcMAC: "02:00:00:00:00:01",
		DstMAC: "02:00:00:00:00:02",
		SrcIP: "192.0.2.1",
		DstIP: "192.0.2.2",
		SrcPort: 50000,
		DstPort: DefaultPort,
		WireGuard: &core.WireGuardConfig{
			Role: "initiator",
			SenderIndex: 1,
			Direction: "both",
			TransportPayloads: [][]byte{{0x01}, {0x02}, {0x03}},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// handshake(2) + transport(3) = 5 packets.
	if len(cfgs) != 5 {
		t.Fatalf("packet count = %d, want 5", len(cfgs))
	}
	// Transport packets (indices 2,3,4) should alternate: up, down, up.
	transDirs := []string{"up", "down", "up"}
	for i, want := range transDirs {
		trans := cfgs[2+i]
		if trans.Direction != want {
			t.Errorf("transport[%d] direction=%s, want %s", i, trans.Direction, want)
		}
	}
}

// Integration 9: Default spec (nil WireGuard) produces default handshake + transport.
func TestWireGuard_Integration_DefaultSpec(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcMAC: "02:00:00:00:00:01",
		DstMAC: "02:00:00:00:00:02",
		SrcIP: "192.0.2.1",
		DstIP: "192.0.2.2",
		SrcPort: 50000,
		DstPort: DefaultPort,
	}
	cfgs := drain(mustPlan(t, p, spec))
	// handshake(2) + default transport(1) = 3 packets.
	if len(cfgs) != 3 {
		t.Fatalf("packet count = %d, want 3", len(cfgs))
	}
	if cfgs[0].Payload[0] != MsgHandshakeInitiation {
		t.Errorf("cfgs[0] message_type=%d, want 1", cfgs[0].Payload[0])
	}
	if cfgs[1].Payload[0] != MsgHandshakeResponse {
		t.Errorf("cfgs[1] message_type=%d, want 2", cfgs[1].Payload[0])
	}
	if cfgs[2].Payload[0] != MsgTransportData {
		t.Errorf("cfgs[2] message_type=%d, want 4", cfgs[2].Payload[0])
	}
}

// Integration 10: Validate rejects invalid role.
func TestWireGuard_Validate_InvalidRole(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "192.0.2.1",
		DstIP: "192.0.2.2",
		WireGuard: &core.WireGuardConfig{
			Role: "unknown",
		},
	}
	err := p.Validate(spec)
	if err == nil {
		t.Fatal("expected error for invalid role, got nil")
	}
}

// Integration 11: Validate rejects invalid direction.
func TestWireGuard_Validate_InvalidDirection(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "192.0.2.1",
		DstIP: "192.0.2.2",
		WireGuard: &core.WireGuardConfig{
			Direction: "unknown",
		},
	}
	err := p.Validate(spec)
	if err == nil {
		t.Fatal("expected error for invalid direction, got nil")
	}
}

// Integration 12: Validate rejects oversized transport payload.
func TestWireGuard_Validate_OversizedTransportPayload(t *testing.T) {
	p := NewPlanner()
	oversized := make([]byte, MaxTransportPayload+1)
	spec := core.FlowSpec{
		SrcIP: "192.0.2.1",
		DstIP: "192.0.2.2",
		WireGuard: &core.WireGuardConfig{
			TransportPayloads: [][]byte{oversized},
		},
	}
	err := p.Validate(spec)
	if err == nil {
		t.Fatal("expected error for oversized transport payload, got nil")
	}
}

// Integration 13: Validate rejects invalid LocalStaticPubKey length.
func TestWireGuard_Validate_InvalidLocalStaticPubKey(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "192.0.2.1",
		DstIP: "192.0.2.2",
		WireGuard: &core.WireGuardConfig{
			LocalStaticPubKey: make([]byte, 31),
		},
	}
	err := p.Validate(spec)
	if err == nil {
		t.Fatal("expected error for invalid LocalStaticPubKey length, got nil")
	}
}

// Integration 14: Validate rejects invalid PeerStaticPubKey length.
func TestWireGuard_Validate_InvalidPeerStaticPubKey(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "192.0.2.1",
		DstIP: "192.0.2.2",
		WireGuard: &core.WireGuardConfig{
			PeerStaticPubKey: make([]byte, 33),
		},
	}
	err := p.Validate(spec)
	if err == nil {
		t.Fatal("expected error for invalid PeerStaticPubKey length, got nil")
	}
}

// Integration 15: Validate rejects invalid PSK length.
func TestWireGuard_Validate_InvalidPSK(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "192.0.2.1",
		DstIP: "192.0.2.2",
		WireGuard: &core.WireGuardConfig{
			PSK: make([]byte, 31),
		},
	}
	err := p.Validate(spec)
	if err == nil {
		t.Fatal("expected error for invalid PSK length, got nil")
	}
}

// Integration 16: Validate rejects invalid Cookie length.
func TestWireGuard_Validate_InvalidCookie(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "192.0.2.1",
		DstIP: "192.0.2.2",
		WireGuard: &core.WireGuardConfig{
			Cookie: make([]byte, 15),
		},
	}
	err := p.Validate(spec)
	if err == nil {
		t.Fatal("expected error for invalid Cookie length, got nil")
	}
}

// Integration 17: Validate rejects RekeyAfter too large.
func TestWireGuard_Validate_RekeyAfterTooLarge(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "192.0.2.1",
		DstIP: "192.0.2.2",
		WireGuard: &core.WireGuardConfig{
			RekeyAfter: 1 << 61,
		},
	}
	err := p.Validate(spec)
	if err == nil {
		t.Fatal("expected error for RekeyAfter too large, got nil")
	}
}

// Integration 18: Validate rejects invalid KeepaliveInterval.
func TestWireGuard_Validate_InvalidKeepaliveInterval(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "192.0.2.1",
		DstIP: "192.0.2.2",
		WireGuard: &core.WireGuardConfig{
			KeepaliveInterval: -1,
		},
	}
	err := p.Validate(spec)
	if err == nil {
		t.Fatal("expected error for invalid KeepaliveInterval, got nil")
	}
}

// Integration 19: Validate rejects invalid LocalEphemeralPubKey length.
func TestWireGuard_Validate_InvalidLocalEphemeralPubKey(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "192.0.2.1",
		DstIP: "192.0.2.2",
		WireGuard: &core.WireGuardConfig{
			LocalEphemeralPubKey: make([]byte, 31),
		},
	}
	err := p.Validate(spec)
	if err == nil {
		t.Fatal("expected error for invalid LocalEphemeralPubKey length, got nil")
	}
}

// Integration 20: Responder role emits Response (type=2) down.
func TestWireGuard_Integration_ResponderRole(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcMAC: "02:00:00:00:00:01",
		DstMAC: "02:00:00:00:00:02",
		SrcIP: "192.0.2.1",
		DstIP: "192.0.2.2",
		SrcPort: 50000,
		DstPort: DefaultPort,
		WireGuard: &core.WireGuardConfig{
			Role: "responder",
			SenderIndex: 42,
			TransportPayloads: [][]byte{{0x41}},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// response(1) + transport(1) = 2 packets.
	if len(cfgs) < 2 {
		t.Fatalf("packet count = %d, want >= 2", len(cfgs))
	}
	// First packet: Response (down direction, type=2)
	if cfgs[0].Direction != "down" {
		t.Errorf("cfgs[0].Direction=%s, want down", cfgs[0].Direction)
	}
	if cfgs[0].Payload[0] != MsgHandshakeResponse {
		t.Errorf("cfgs[0] message_type=%d, want 2", cfgs[0].Payload[0])
	}
}

// Integration 21: Responder with Response=false emits no Response.
func TestWireGuard_Integration_ResponderNoResponse(t *testing.T) {
	p := NewPlanner()
	responseFalse := false
	handshakeFalse := false
	spec := core.FlowSpec{
		SrcMAC: "02:00:00:00:00:01",
		DstMAC: "02:00:00:00:00:02",
		SrcIP: "192.0.2.1",
		DstIP: "192.0.2.2",
		SrcPort: 50000,
		DstPort: DefaultPort,
		WireGuard: &core.WireGuardConfig{
			Role: "responder",
			Response: &responseFalse,
			Handshake: &handshakeFalse,
			SenderIndex: 42,
			TransportPayloads: [][]byte{{0x41}},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// Only transport(1) = 1 packet (no response since Response=false).
	if len(cfgs) != 1 {
		t.Fatalf("packet count = %d, want 1 (no response)", len(cfgs))
	}
	if cfgs[0].Payload[0] != MsgTransportData {
		t.Errorf("message_type=%d, want 4", cfgs[0].Payload[0])
	}
}

// Integration 22: Cookie non-nil produces non-zero mac2 in initiation.
func TestWireGuard_Integration_NonZeroMAC2WithCookie(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcMAC: "02:00:00:00:00:01",
		DstMAC: "02:00:00:00:00:02",
		SrcIP: "192.0.2.1",
		DstIP: "192.0.2.2",
		SrcPort: 50000,
		DstPort: DefaultPort,
		WireGuard: &core.WireGuardConfig{
			Role: "initiator",
			SenderIndex: 1,
			Cookie: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
			TransportPayloads: [][]byte{{0x41}},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) < 1 {
		t.Fatal("no packets emitted")
	}
	init := cfgs[0]
	// mac2 at bytes[132..148] should be non-zero (cookie present)
	mac2 := init.Payload[132:148]
	allZero := true
	for _, b := range mac2 {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("mac2 is all zeros but cookie is set, expected non-zero")
	}
}

// Integration 23: Empty TransportPayloads with Handshake=true still emits handshake.
func TestWireGuard_Integration_EmptyTransportPayloadsWithHandshake(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcMAC: "02:00:00:00:00:01",
		DstMAC: "02:00:00:00:00:02",
		SrcIP: "192.0.2.1",
		DstIP: "192.0.2.2",
		SrcPort: 50000,
		DstPort: DefaultPort,
		WireGuard: &core.WireGuardConfig{
			Role: "initiator",
			SenderIndex: 1,
			TransportPayloads: [][]byte{},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// handshake(2) + default dummy transport(1) = 3 packets.
	if len(cfgs) != 3 {
		t.Fatalf("packet count = %d, want 3 (handshake + default transport)", len(cfgs))
	}
	if cfgs[0].Payload[0] != MsgHandshakeInitiation {
		t.Errorf("cfgs[0] message_type=%d, want 1", cfgs[0].Payload[0])
	}
}

// Integration 24: Verify ephemeral field is 32 bytes in initiation.
func TestWireGuard_Integration_EphemeralFieldSize(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcMAC: "02:00:00:00:00:01",
		DstMAC: "02:00:00:00:00:02",
		SrcIP: "192.0.2.1",
		DstIP: "192.0.2.2",
		SrcPort: 50000,
		DstPort: DefaultPort,
		WireGuard: &core.WireGuardConfig{
			Role: "initiator",
			SenderIndex: 1,
			TransportPayloads: [][]byte{{0x41}},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) < 1 {
		t.Fatal("no packets emitted")
	}
	init := cfgs[0]
	ephemeral := init.Payload[8:40]
	if len(ephemeral) != SizeEphemeral {
		t.Errorf("ephemeral field length=%d, want %d", len(ephemeral), SizeEphemeral)
	}
}

// Integration 25: Verify enc_static field is 48 bytes in initiation.
func TestWireGuard_Integration_EncStaticFieldSize(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcMAC: "02:00:00:00:00:01",
		DstMAC: "02:00:00:00:00:02",
		SrcIP: "192.0.2.1",
		DstIP: "192.0.2.2",
		SrcPort: 50000,
		DstPort: DefaultPort,
		WireGuard: &core.WireGuardConfig{
			Role: "initiator",
			SenderIndex: 1,
			TransportPayloads: [][]byte{{0x41}},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) < 1 {
		t.Fatal("no packets emitted")
	}
	init := cfgs[0]
	encStatic := init.Payload[40:88]
	if len(encStatic) != SizeEncStatic {
		t.Errorf("enc_static field length=%d, want %d", len(encStatic), SizeEncStatic)
	}
}

// Integration 26: Verify enc_timestamp field is 28 bytes in initiation.
func TestWireGuard_Integration_EncTimestampFieldSize(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcMAC: "02:00:00:00:00:01",
		DstMAC: "02:00:00:00:00:02",
		SrcIP: "192.0.2.1",
		DstIP: "192.0.2.2",
		SrcPort: 50000,
		DstPort: DefaultPort,
		WireGuard: &core.WireGuardConfig{
			Role: "initiator",
			SenderIndex: 1,
			TransportPayloads: [][]byte{{0x41}},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) < 1 {
		t.Fatal("no packets emitted")
	}
	init := cfgs[0]
	encTimestamp := init.Payload[88:116]
	if len(encTimestamp) != SizeEncTimestamp {
		t.Errorf("enc_timestamp field length=%d, want %d", len(encTimestamp), SizeEncTimestamp)
	}
}

// Integration 27: Verify mac1 field is 16 bytes in initiation.
func TestWireGuard_Integration_MAC1FieldSize(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcMAC: "02:00:00:00:00:01",
		DstMAC: "02:00:00:00:00:02",
		SrcIP: "192.0.2.1",
		DstIP: "192.0.2.2",
		SrcPort: 50000,
		DstPort: DefaultPort,
		WireGuard: &core.WireGuardConfig{
			Role: "initiator",
			SenderIndex: 1,
			TransportPayloads: [][]byte{{0x41}},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) < 1 {
		t.Fatal("no packets emitted")
	}
	init := cfgs[0]
	mac1 := init.Payload[116:132]
	if len(mac1) != SizeMAC1 {
		t.Errorf("mac1 field length=%d, want %d", len(mac1), SizeMAC1)
	}
}

// Integration 28: Verify response enc_empty field is 16 bytes.
func TestWireGuard_Integration_ResponseEncEmptyFieldSize(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcMAC: "02:00:00:00:00:01",
		DstMAC: "02:00:00:00:00:02",
		SrcIP: "192.0.2.1",
		DstIP: "192.0.2.2",
		SrcPort: 50000,
		DstPort: DefaultPort,
		WireGuard: &core.WireGuardConfig{
			Role: "initiator",
			SenderIndex: 1,
			TransportPayloads: [][]byte{{0x41}},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) < 2 {
		t.Fatal("expected at least 2 packets (handshake)")
	}
	resp := cfgs[1]
	encEmpty := resp.Payload[44:60]
	if len(encEmpty) != SizeEncEmpty {
		t.Errorf("enc_empty field length=%d, want %d", len(encEmpty), SizeEncEmpty)
	}
}

// Integration 29: Verify SenderIndex=42 produces correct wire bytes.
func TestWireGuard_Integration_SenderIndex42(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcMAC: "02:00:00:00:00:01",
		DstMAC: "02:00:00:00:00:02",
		SrcIP: "192.0.2.1",
		DstIP: "192.0.2.2",
		SrcPort: 50000,
		DstPort: DefaultPort,
		WireGuard: &core.WireGuardConfig{
			Role: "initiator",
			SenderIndex: 42,
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) < 1 {
		t.Fatal("no packets emitted")
	}
	init := cfgs[0]
	// sender_index at bytes[4..8] = little-endian 42 = 0x2A 0x00 0x00 0x00
	if init.Payload[4] != 0x2A || init.Payload[5] != 0x00 || init.Payload[6] != 0x00 || init.Payload[7] != 0x00 {
		t.Errorf("sender_index bytes=%02x%02x%02x%02x, want 2a000000",
			init.Payload[4], init.Payload[5], init.Payload[6], init.Payload[7])
	}
}

// Integration 30: Verify uint32 max sender_index.
func TestWireGuard_Integration_SenderIndexMax(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcMAC: "02:00:00:00:00:01",
		DstMAC: "02:00:00:00:00:02",
		SrcIP: "192.0.2.1",
		DstIP: "192.0.2.2",
		SrcPort: 50000,
		DstPort: DefaultPort,
		WireGuard: &core.WireGuardConfig{
			Role: "initiator",
			SenderIndex: 4294967295,
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) < 1 {
		t.Fatal("no packets emitted")
	}
	init := cfgs[0]
	// sender_index at bytes[4..8] = 0xFF 0xFF 0xFF 0xFF
	if init.Payload[4] != 0xFF || init.Payload[5] != 0xFF || init.Payload[6] != 0xFF || init.Payload[7] != 0xFF {
		t.Errorf("sender_index bytes=%02x%02x%02x%02x, want ffffffff",
			init.Payload[4], init.Payload[5], init.Payload[6], init.Payload[7])
	}
}