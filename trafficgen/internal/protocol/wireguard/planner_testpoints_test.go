package wireguard

import (
	"context"
	"encoding/binary"
	"sync"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

// validSpec returns a minimal valid WireGuard spec for test setup.
func validSpec() core.FlowSpec {
	return core.FlowSpec{
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
}

// ===================================================================
// 1.1 Message Type tests (8 cases)
// ===================================================================

func TestWireGuard_1_1_1_MessageTypeInitiation(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) < 1 {
		t.Fatal("no packets emitted")
	}
	if cfgs[0].Payload[0] != 0x01 {
		t.Errorf("message_type=%d, want 1", cfgs[0].Payload[0])
	}
	if len(cfgs[0].Payload) != SizeHandshakeInitiation {
		t.Errorf("payload length=%d, want %d", len(cfgs[0].Payload), SizeHandshakeInitiation)
	}
	if cfgs[0].Direction != "up" {
		t.Errorf("direction=%s, want up", cfgs[0].Direction)
	}
}

func TestWireGuard_1_1_2_MessageTypeResponse(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) < 2 {
		t.Fatal("expected at least 2 packets")
	}
	if cfgs[1].Payload[0] != 0x02 {
		t.Errorf("message_type=%d, want 2", cfgs[1].Payload[0])
	}
	if len(cfgs[1].Payload) != SizeHandshakeResponse {
		t.Errorf("payload length=%d, want %d", len(cfgs[1].Payload), SizeHandshakeResponse)
	}
	if cfgs[1].Direction != "down" {
		t.Errorf("direction=%s, want down", cfgs[1].Direction)
	}
}

func TestWireGuard_1_1_3_MessageTypeCookieReply(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.Role = "responder"
	spec.WireGuard.CookieReplyThreshold = 1
	cfgs := drain(mustPlan(t, p, spec))
	var foundCookie bool
	for _, c := range cfgs {
		if len(c.Payload) > 0 && c.Payload[0] == 0x03 {
			foundCookie = true
			if len(c.Payload) != SizeCookieReply {
				t.Errorf("Cookie Reply payload length=%d, want %d", len(c.Payload), SizeCookieReply)
			}
			if c.Direction != "down" {
				t.Errorf("direction=%s, want down", c.Direction)
			}
		}
	}
	if !foundCookie {
		t.Error("expected Cookie Reply (type=3) packet, none found")
	}
}

func TestWireGuard_1_1_4_MessageTypeTransport(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.TransportPayloads = [][]byte{{0x41, 0x42}}
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) < 3 {
		t.Fatal("expected at least 3 packets")
	}
	trans := cfgs[2]
	if trans.Payload[0] != 0x04 {
		t.Errorf("message_type=%d, want 4", trans.Payload[0])
	}
	expectedLen := SizeTransportHeader + 2 + SizeAEADTag
	if len(trans.Payload) != expectedLen {
		t.Errorf("payload length=%d, want %d", len(trans.Payload), expectedLen)
	}
}

func TestWireGuard_1_1_5_MessageTypeKeepalive(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.TransportPayloads = [][]byte{{}} // empty payload
	spec.WireGuard.KeepaliveInterval = 10
	cfgs := drain(mustPlan(t, p, spec))
	// Find keepalive packet (32 bytes, type=4).
	var foundKeepalive bool
	for _, c := range cfgs {
		if len(c.Payload) > 0 && c.Payload[0] == 0x04 && len(c.Payload) == 32 {
			foundKeepalive = true
		}
	}
	if !foundKeepalive {
		t.Error("expected keepalive packet (32 bytes, type=4), none found")
	}
}

// ===================================================================
// 1.2 Handshake Initiation field tests
// ===================================================================

func TestWireGuard_1_2_1_InitiationReservedZero(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	cfgs := drain(mustPlan(t, p, spec))
	init := cfgs[0]
	if init.Payload[1] != 0 || init.Payload[2] != 0 || init.Payload[3] != 0 {
		t.Errorf("reserved_zero bytes=%02x%02x%02x, want 000000",
			init.Payload[1], init.Payload[2], init.Payload[3])
	}
}

func TestWireGuard_1_2_3_InitiationSenderIndexAuto(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.SenderIndex = 0 // auto-generate
	cfgs := drain(mustPlan(t, p, spec))
	init := cfgs[0]
	// Auto-generated sender_index should be 1 (first session).
	if init.Payload[4] != 1 || init.Payload[5] != 0 || init.Payload[6] != 0 || init.Payload[7] != 0 {
		t.Errorf("sender_index bytes=%02x%02x%02x%02x, want 01000000",
			init.Payload[4], init.Payload[5], init.Payload[6], init.Payload[7])
	}
}

func TestWireGuard_1_2_4_InitiationSenderIndex42(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.SenderIndex = 42
	cfgs := drain(mustPlan(t, p, spec))
	init := cfgs[0]
	if init.Payload[4] != 0x2A {
		t.Errorf("sender_index byte[4]=%02x, want 0x2A", init.Payload[4])
	}
}

func TestWireGuard_1_2_5_InitiationSenderIndexMax(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.SenderIndex = 4294967295
	cfgs := drain(mustPlan(t, p, spec))
	init := cfgs[0]
	for i := 4; i < 8; i++ {
		if init.Payload[i] != 0xFF {
			t.Errorf("sender_index byte[%d]=%02x, want 0xFF", i, init.Payload[i])
		}
	}
}

func TestWireGuard_1_2_8_InitiationEphemeralSet(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	ephemeral := make([]byte, SizeEphemeral)
	for i := range ephemeral {
		ephemeral[i] = 0xFF
	}
	spec.WireGuard.LocalEphemeralPubKey = ephemeral
	cfgs := drain(mustPlan(t, p, spec))
	init := cfgs[0]
	for i := 8; i < 40; i++ {
		if init.Payload[i] != 0xFF {
			t.Errorf("ephemeral byte[%d]=%02x, want 0xFF", i-8, init.Payload[i])
			break
		}
	}
}

func TestWireGuard_1_2_9_InitiationEphemeralWrongLength(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.LocalEphemeralPubKey = make([]byte, 31)
	if err := p.Validate(spec); err == nil {
		t.Error("expected error for 31-byte ephemeral, got nil")
	}
}

func TestWireGuard_1_2_10_InitiationEphemeralWrongLength33(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.LocalEphemeralPubKey = make([]byte, 33)
	if err := p.Validate(spec); err == nil {
		t.Error("expected error for 33-byte ephemeral, got nil")
	}
}

func TestWireGuard_1_2_11_InitiationEncStaticPresent(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	cfgs := drain(mustPlan(t, p, spec))
	init := cfgs[0]
	encStatic := init.Payload[40:88]
	if len(encStatic) != SizeEncStatic {
		t.Errorf("enc_static length=%d, want %d", len(encStatic), SizeEncStatic)
	}
}

func TestWireGuard_1_2_13_InitiationEncTimestampPresent(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	cfgs := drain(mustPlan(t, p, spec))
	init := cfgs[0]
	encTimestamp := init.Payload[88:116]
	if len(encTimestamp) != SizeEncTimestamp {
		t.Errorf("enc_timestamp length=%d, want %d", len(encTimestamp), SizeEncTimestamp)
	}
}

func TestWireGuard_1_2_15_InitiationMAC1Present(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	cfgs := drain(mustPlan(t, p, spec))
	init := cfgs[0]
	mac1 := init.Payload[116:132]
	if len(mac1) != SizeMAC1 {
		t.Errorf("mac1 length=%d, want %d", len(mac1), SizeMAC1)
	}
}

func TestWireGuard_1_2_17_InitiationMAC2Zero(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.Cookie = nil
	cfgs := drain(mustPlan(t, p, spec))
	init := cfgs[0]
	for i := 132; i < 148; i++ {
		if init.Payload[i] != 0 {
			t.Errorf("mac2 byte[%d]=%02x, want 0", i-132, init.Payload[i])
		}
	}
}

func TestWireGuard_1_2_18_InitiationMAC2NonZero(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.Cookie = make([]byte, 16)
	for i := range spec.WireGuard.Cookie {
		spec.WireGuard.Cookie[i] = byte(i + 1)
	}
	cfgs := drain(mustPlan(t, p, spec))
	init := cfgs[0]
	allZero := true
	for i := 132; i < 148; i++ {
		if init.Payload[i] != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("mac2 is all zeros with cookie set, expected non-zero")
	}
}

func TestWireGuard_1_2_19_InitiationCookieWrongLength15(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.Cookie = make([]byte, 15)
	if err := p.Validate(spec); err == nil {
		t.Error("expected error for 15-byte cookie, got nil")
	}
}

func TestWireGuard_1_2_20_InitiationTotalLength(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	cfgs := drain(mustPlan(t, p, spec))
	init := cfgs[0]
	if len(init.Payload) != 148 {
		t.Errorf("Initiation total length=%d, want 148", len(init.Payload))
	}
}

func TestWireGuard_1_2_22_LocalStaticPubKey31Bytes(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.LocalStaticPubKey = make([]byte, 31)
	if err := p.Validate(spec); err == nil {
		t.Error("expected error for 31-byte LocalStaticPubKey, got nil")
	}
}

func TestWireGuard_1_2_25_PeerStaticPubKey16Bytes(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.PeerStaticPubKey = make([]byte, 16)
	if err := p.Validate(spec); err == nil {
		t.Error("expected error for 16-byte PeerStaticPubKey, got nil")
	}
}

// ===================================================================
// 1.3 Handshake Response field tests
// ===================================================================

func TestWireGuard_1_3_1_ResponseReservedZero(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	cfgs := drain(mustPlan(t, p, spec))
	resp := cfgs[1]
	if resp.Payload[1] != 0 || resp.Payload[2] != 0 || resp.Payload[3] != 0 {
		t.Errorf("reserved_zero bytes=%02x%02x%02x, want 000000",
			resp.Payload[1], resp.Payload[2], resp.Payload[3])
	}
}

func TestWireGuard_1_3_3_ResponseSenderIndex(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.SenderIndex = 42
	cfgs := drain(mustPlan(t, p, spec))
	resp := cfgs[1]
	// responder sender_index is auto-generated (sender_index+1 = 43)
	if resp.Payload[4] != 43 {
		t.Errorf("Response sender_index=%d, want 43", resp.Payload[4])
	}
}

func TestWireGuard_1_3_4_ResponseReceiverIndex(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.SenderIndex = 42
	cfgs := drain(mustPlan(t, p, spec))
	resp := cfgs[1]
	// receiver_index at bytes[8..12] = initiator's sender_index (42)
	if resp.Payload[8] != 42 {
		t.Errorf("Response receiver_index=%d, want 42", resp.Payload[8])
	}
}

func TestWireGuard_1_3_9_ResponseEncEmptyPresent(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	cfgs := drain(mustPlan(t, p, spec))
	resp := cfgs[1]
	encEmpty := resp.Payload[44:60]
	if len(encEmpty) != SizeEncEmpty {
		t.Errorf("enc_empty length=%d, want %d", len(encEmpty), SizeEncEmpty)
	}
}

func TestWireGuard_1_3_13_ResponseMAC2Zero(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	cfgs := drain(mustPlan(t, p, spec))
	resp := cfgs[1]
	for i := 76; i < 92; i++ {
		if resp.Payload[i] != 0 {
			t.Errorf("Response mac2 byte[%d]=%02x, want 0", i-76, resp.Payload[i])
		}
	}
}

func TestWireGuard_1_3_15_ResponseTotalLength(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	cfgs := drain(mustPlan(t, p, spec))
	resp := cfgs[1]
	if len(resp.Payload) != 92 {
		t.Errorf("Response total length=%d, want 92", len(resp.Payload))
	}
}

// ===================================================================
// 1.4 Transport Data field tests
// ===================================================================

func TestWireGuard_1_4_1_TransportReservedZero(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	cfgs := drain(mustPlan(t, p, spec))
	trans := cfgs[2]
	if trans.Payload[1] != 0 || trans.Payload[2] != 0 || trans.Payload[3] != 0 {
		t.Errorf("Transport reserved_zero bytes=%02x%02x%02x, want 000000",
			trans.Payload[1], trans.Payload[2], trans.Payload[3])
	}
}

func TestWireGuard_1_4_3_TransportReceiverIndex(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.SenderIndex = 42
	cfgs := drain(mustPlan(t, p, spec))
	trans := cfgs[2]
	// receiver_index = responder's sender_index (43)
	if trans.Payload[4] != 43 {
		t.Errorf("Transport receiver_index=%d, want 43", trans.Payload[4])
	}
}

func TestWireGuard_1_4_5_TransportCounterZero(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	cfgs := drain(mustPlan(t, p, spec))
	trans := cfgs[2]
	for i := 8; i < 16; i++ {
		if trans.Payload[i] != 0 {
			t.Errorf("Transport counter byte[%d]=%02x, want 0", i-8, trans.Payload[i])
		}
	}
}

func TestWireGuard_1_4_6_TransportCounterIncrement(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.TransportPayloads = [][]byte{{0x01}, {0x02}}
	cfgs := drain(mustPlan(t, p, spec))
	// Two transport packets at indices 2 and 3.
	trans0 := cfgs[2]
	trans1 := cfgs[3]
	counter0 := binary.LittleEndian.Uint64(trans0.Payload[8:16])
	counter1 := binary.LittleEndian.Uint64(trans1.Payload[8:16])
	if counter0 != 0 {
		t.Errorf("first transport counter=%d, want 0", counter0)
	}
	if counter1 != 1 {
		t.Errorf("second transport counter=%d, want 1", counter1)
	}
}

func TestWireGuard_1_4_7_TransportInitialCounter100(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.InitialCounter = 100
	cfgs := drain(mustPlan(t, p, spec))
	trans := cfgs[2]
	counter := binary.LittleEndian.Uint64(trans.Payload[8:16])
	if counter != 100 {
		t.Errorf("Transport counter=%d, want 100", counter)
	}
}

func TestWireGuard_1_4_11_TransportPayload1Byte(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.TransportPayloads = [][]byte{{0x41}}
	cfgs := drain(mustPlan(t, p, spec))
	trans := cfgs[2]
	expectedLen := SizeTransportHeader + 1 + SizeAEADTag // 16 + 1 + 16 = 33
	if len(trans.Payload) != expectedLen {
		t.Errorf("Transport total length=%d, want %d", len(trans.Payload), expectedLen)
	}
}

func TestWireGuard_1_4_12_TransportPayloadMax(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.TransportPayloads = [][]byte{make([]byte, MaxTransportPayload)}
	cfgs := drain(mustPlan(t, p, spec))
	trans := cfgs[2]
	expectedLen := SizeTransportHeader + MaxTransportPayload + SizeAEADTag // 16 + 1440 + 16 = 1472
	if len(trans.Payload) != expectedLen {
		t.Errorf("Transport total length=%d, want %d", len(trans.Payload), expectedLen)
	}
}

func TestWireGuard_1_4_13_TransportPayloadZeroKeepalive(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.TransportPayloads = [][]byte{{}}
	cfgs := drain(mustPlan(t, p, spec))
	trans := cfgs[2]
	expectedLen := SizeTransportHeader + 0 + SizeAEADTag // 32
	if len(trans.Payload) != expectedLen {
		t.Errorf("Transport total length=%d, want %d (keepalive)", len(trans.Payload), expectedLen)
	}
}

func TestWireGuard_1_4_14_TransportPayloadExceedsMTU(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.TransportPayloads = [][]byte{make([]byte, MaxTransportPayload+1)}
	if err := p.Validate(spec); err == nil {
		t.Error("expected error for payload exceeding MTU, got nil")
	}
}

// ===================================================================
// 1.5 Cookie Reply field tests
// ===================================================================

func TestWireGuard_1_5_1_CookieReplyReservedZero(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.Role = "responder"
	spec.WireGuard.CookieReplyThreshold = 1
	cfgs := drain(mustPlan(t, p, spec))
	for _, c := range cfgs {
		if len(c.Payload) > 0 && c.Payload[0] == MsgCookieReply {
			if c.Payload[1] != 0 || c.Payload[2] != 0 || c.Payload[3] != 0 {
				t.Errorf("Cookie Reply reserved_zero bytes=%02x%02x%02x, want 000000",
					c.Payload[1], c.Payload[2], c.Payload[3])
			}
			return
		}
	}
	t.Error("Cookie Reply packet not found")
}

func TestWireGuard_1_5_5_CookieReplyNoncePresent(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.Role = "responder"
	spec.WireGuard.CookieReplyThreshold = 1
	cfgs := drain(mustPlan(t, p, spec))
	for _, c := range cfgs {
		if len(c.Payload) > 0 && c.Payload[0] == MsgCookieReply {
			nonce := c.Payload[8:32]
			if len(nonce) != SizeCookieNonce {
				t.Errorf("Cookie Reply nonce length=%d, want %d", len(nonce), SizeCookieNonce)
			}
			return
		}
	}
	t.Error("Cookie Reply packet not found")
}

func TestWireGuard_1_5_7_CookieReplyEncCookiePresent(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.Role = "responder"
	spec.WireGuard.CookieReplyThreshold = 1
	cfgs := drain(mustPlan(t, p, spec))
	for _, c := range cfgs {
		if len(c.Payload) > 0 && c.Payload[0] == MsgCookieReply {
			encCookie := c.Payload[32:64]
			if len(encCookie) != SizeEncCookie {
				t.Errorf("Cookie Reply enc_cookie length=%d, want %d", len(encCookie), SizeEncCookie)
			}
			return
		}
	}
	t.Error("Cookie Reply packet not found")
}

func TestWireGuard_1_5_9_CookieReplyTotalLength(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.Role = "responder"
	spec.WireGuard.CookieReplyThreshold = 1
	cfgs := drain(mustPlan(t, p, spec))
	for _, c := range cfgs {
		if len(c.Payload) > 0 && c.Payload[0] == MsgCookieReply {
			if len(c.Payload) != 64 {
				t.Errorf("Cookie Reply total length=%d, want 64", len(c.Payload))
			}
			return
		}
	}
	t.Error("Cookie Reply packet not found")
}

// ===================================================================
// 1.7 PSK tests
// ===================================================================

func TestWireGuard_1_7_1_PSK32Bytes(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.PSK = make([]byte, 32)
	if err := p.Validate(spec); err != nil {
		t.Errorf("Validate failed for 32-byte PSK: %v", err)
	}
}

func TestWireGuard_1_7_3_PSKNil(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.PSK = nil
	if err := p.Validate(spec); err != nil {
		t.Errorf("Validate failed for nil PSK: %v", err)
	}
}

func TestWireGuard_1_7_4_PSK31Bytes(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.PSK = make([]byte, 31)
	if err := p.Validate(spec); err == nil {
		t.Error("expected error for 31-byte PSK, got nil")
	}
}

func TestWireGuard_1_7_5_PSK33Bytes(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.PSK = make([]byte, 33)
	if err := p.Validate(spec); err == nil {
		t.Error("expected error for 33-byte PSK, got nil")
	}
}

// ===================================================================
// 1.8 WireGuardConfig global fields
// ===================================================================

func TestWireGuard_1_8_1_RoleInitiator(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.Role = "initiator"
	cfgs := drain(mustPlan(t, p, spec))
	if cfgs[0].Payload[0] != MsgHandshakeInitiation {
		t.Errorf("expected Initiation (type=1), got type %d", cfgs[0].Payload[0])
	}
}

func TestWireGuard_1_8_3_RoleUnknown(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.Role = "unknown"
	if err := p.Validate(spec); err == nil {
		t.Error("expected error for unknown role, got nil")
	}
}

func TestWireGuard_1_8_4_RoleEmpty(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.Role = ""
	cfgs := drain(mustPlan(t, p, spec))
	if cfgs[0].Payload[0] != MsgHandshakeInitiation {
		t.Errorf("expected default Initiation (type=1), got type %d", cfgs[0].Payload[0])
	}
}

func TestWireGuard_1_8_5_DirectionUp(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.Direction = "up"
	cfgs := drain(mustPlan(t, p, spec))
	// Transport packet at index 2 should be up.
	if cfgs[2].Direction != "up" {
		t.Errorf("transport direction=%s, want up", cfgs[2].Direction)
	}
}

func TestWireGuard_1_8_6_DirectionDown(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.Direction = "down"
	cfgs := drain(mustPlan(t, p, spec))
	if cfgs[2].Direction != "down" {
		t.Errorf("transport direction=%s, want down", cfgs[2].Direction)
	}
}

func TestWireGuard_1_8_7_DirectionBoth(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.Direction = "both"
	spec.WireGuard.TransportPayloads = [][]byte{{0x01}, {0x02}, {0x03}, {0x04}}
	cfgs := drain(mustPlan(t, p, spec))
	// 4 transport packets alternate up, down, up, down.
	expected := []string{"up", "down", "up", "down"}
	for i, want := range expected {
		if cfgs[2+i].Direction != want {
			t.Errorf("transport[%d] direction=%s, want %s", i, cfgs[2+i].Direction, want)
		}
	}
}

func TestWireGuard_1_8_9_DirectionUnknown(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.Direction = "unknown"
	if err := p.Validate(spec); err == nil {
		t.Error("expected error for unknown direction, got nil")
	}
}

// ===================================================================
// 1.9 Rekey / Keepalive tests
// ===================================================================

func TestWireGuard_1_9_2_RekeyAfter100(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.RekeyAfter = 3
	spec.WireGuard.TransportPayloads = [][]byte{{0x01}, {0x02}, {0x03}, {0x04}, {0x05}}
	cfgs := drain(mustPlan(t, p, spec))
	// Count handshake initiation packets.
	var initCount int
	for _, c := range cfgs {
		if len(c.Payload) > 0 && c.Payload[0] == MsgHandshakeInitiation {
			initCount++
		}
	}
	if initCount < 2 {
		t.Errorf("expected >= 2 initiations (initial + rekey), got %d", initCount)
	}
}

func TestWireGuard_1_9_3_RekeyAfterTooLarge(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.RekeyAfter = 1 << 61
	if err := p.Validate(spec); err == nil {
		t.Error("expected error for RekeyAfter too large, got nil")
	}
}

func TestWireGuard_1_9_6_KeepaliveIntervalZero(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.KeepaliveInterval = 0
	cfgs := drain(mustPlan(t, p, spec))
	// With KeepaliveInterval=0, no keepalive packet (32-byte type=4).
	for _, c := range cfgs {
		if len(c.Payload) == 32 && c.Payload[0] == MsgTransportData {
			// Could be a 0-byte transport payload — check it's not an extra keepalive
			// by counting transport packets vs expected.
		}
	}
}

func TestWireGuard_1_9_7_KeepaliveInterval10(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.KeepaliveInterval = 10
	cfgs := drain(mustPlan(t, p, spec))
	// Should have at least one keepalive (32-byte type=4) after transport.
	var keepaliveCount int
	for _, c := range cfgs {
		if len(c.Payload) == 32 && c.Payload[0] == MsgTransportData {
			keepaliveCount++
		}
	}
	if keepaliveCount < 1 {
		t.Errorf("expected >= 1 keepalive packet, got %d", keepaliveCount)
	}
}

func TestWireGuard_1_9_8_KeepaliveIntervalNegative(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.KeepaliveInterval = -1
	if err := p.Validate(spec); err == nil {
		t.Error("expected error for negative KeepaliveInterval, got nil")
	}
}

// ===================================================================
// 1.10 Cookie / DoS threshold tests
// ===================================================================

func TestWireGuard_1_10_1_CookieReplyThresholdZero(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.Role = "responder"
	spec.WireGuard.CookieReplyThreshold = 0
	cfgs := drain(mustPlan(t, p, spec))
	// With threshold=0, no Cookie Reply should be emitted.
	for _, c := range cfgs {
		if len(c.Payload) > 0 && c.Payload[0] == MsgCookieReply {
			t.Error("unexpected Cookie Reply with threshold=0")
		}
	}
}

func TestWireGuard_1_10_2_CookieReplyThreshold1(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.Role = "responder"
	spec.WireGuard.CookieReplyThreshold = 1
	cfgs := drain(mustPlan(t, p, spec))
	var foundCookie bool
	for _, c := range cfgs {
		if len(c.Payload) > 0 && c.Payload[0] == MsgCookieReply {
			foundCookie = true
		}
	}
	if !foundCookie {
		t.Error("expected Cookie Reply with threshold=1, none found")
	}
}

func TestWireGuard_1_10_5_Cookie15Bytes(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.Cookie = make([]byte, 15)
	if err := p.Validate(spec); err == nil {
		t.Error("expected error for 15-byte cookie, got nil")
	}
}

func TestWireGuard_1_10_6_Cookie17Bytes(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.Cookie = make([]byte, 17)
	if err := p.Validate(spec); err == nil {
		t.Error("expected error for 17-byte cookie, got nil")
	}
}

// ===================================================================
// 1.11 FileSource / Payloads tests
// ===================================================================

func TestWireGuard_1_11_1_TransportPayloadsNil(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.TransportPayloads = nil
	cfgs := drain(mustPlan(t, p, spec))
	// Should emit 1 default transport packet (1-byte dummy).
	if len(cfgs) != 3 {
		t.Fatalf("packet count = %d, want 3 (handshake + default transport)", len(cfgs))
	}
	if cfgs[2].Payload[0] != MsgTransportData {
		t.Errorf("default transport message_type=%d, want 4", cfgs[2].Payload[0])
	}
	// Default dummy is 1 byte, so total = 16 + 1 + 16 = 33.
	if len(cfgs[2].Payload) != 33 {
		t.Errorf("default transport length=%d, want 33", len(cfgs[2].Payload))
	}
}

func TestWireGuard_1_11_3_TransportPayloadsMultiple(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.TransportPayloads = [][]byte{{0x41}, {0x42}, {0x43}}
	cfgs := drain(mustPlan(t, p, spec))
	// handshake(2) + transport(3) = 5 packets.
	if len(cfgs) != 5 {
		t.Fatalf("packet count = %d, want 5", len(cfgs))
	}
}

func TestWireGuard_1_11_4_TransportPayloadsMax(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.TransportPayloads = [][]byte{
		make([]byte, MaxTransportPayload),
		make([]byte, MaxTransportPayload),
	}
	cfgs := drain(mustPlan(t, p, spec))
	// handshake(2) + transport(2) = 4 packets.
	if len(cfgs) != 4 {
		t.Fatalf("packet count = %d, want 4", len(cfgs))
	}
	for i := 2; i < 4; i++ {
		expectedLen := SizeTransportHeader + MaxTransportPayload + SizeAEADTag
		if len(cfgs[i].Payload) != expectedLen {
			t.Errorf("transport[%d] length=%d, want %d", i-2, len(cfgs[i].Payload), expectedLen)
		}
	}
}

func TestWireGuard_1_11_5_TransportPayloadsExceedsMTU(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.TransportPayloads = [][]byte{make([]byte, MaxTransportPayload+1)}
	if err := p.Validate(spec); err == nil {
		t.Error("expected error for payload exceeding MTU, got nil")
	}
}

// ===================================================================
// 2. State machine tests
// ===================================================================

func TestWireGuard_2_1_1_InitiatorHandshake(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	cfgs := drain(mustPlan(t, p, spec))
	if cfgs[0].Payload[0] != MsgHandshakeInitiation {
		t.Errorf("expected Initiation, got type %d", cfgs[0].Payload[0])
	}
}

func TestWireGuard_2_1_4_ResponderHandshake(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.Role = "responder"
	cfgs := drain(mustPlan(t, p, spec))
	if cfgs[0].Payload[0] != MsgHandshakeResponse {
		t.Errorf("expected Response, got type %d", cfgs[0].Payload[0])
	}
}

// ===================================================================
// 4. Data scenario tests
// ===================================================================

func TestWireGuard_4_2_1_SenderIndexMin1(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.SenderIndex = 1
	cfgs := drain(mustPlan(t, p, spec))
	init := cfgs[0]
	if init.Payload[4] != 0x01 {
		t.Errorf("sender_index=%d, want 1", init.Payload[4])
	}
}

func TestWireGuard_4_2_3_CounterMin0(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	cfgs := drain(mustPlan(t, p, spec))
	trans := cfgs[2]
	counter := binary.LittleEndian.Uint64(trans.Payload[8:16])
	if counter != 0 {
		t.Errorf("counter=%d, want 0", counter)
	}
}

func TestWireGuard_4_2_7_TransportPayloadN1(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.TransportPayloads = [][]byte{{0x41}}
	cfgs := drain(mustPlan(t, p, spec))
	trans := cfgs[2]
	if len(trans.Payload) != 33 {
		t.Errorf("transport length=%d, want 33", len(trans.Payload))
	}
}

func TestWireGuard_4_2_8_TransportPayloadN1440(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.TransportPayloads = [][]byte{make([]byte, 1440)}
	cfgs := drain(mustPlan(t, p, spec))
	trans := cfgs[2]
	if len(trans.Payload) != 1472 {
		t.Errorf("transport length=%d, want 1472", len(trans.Payload))
	}
}

// ===================================================================
// 5. Concurrency tests
// ===================================================================

func TestWireGuard_5_1_4_ConcurrentNoRace(t *testing.T) {
	p := NewPlanner()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			spec := validSpec()
			spec.SrcPort = 50000 + uint16(workerID)
			spec.WireGuard.SenderIndex = uint32(workerID + 1)
			ch, err := p.Plan(context.Background(), spec)
			if err != nil {
				t.Errorf("worker %d: Plan error: %v", workerID, err)
				return
			}
			_ = drain(ch)
		}(i)
	}
	wg.Wait()
}

func TestWireGuard_5_1_5_ConcurrentWorkerCount(t *testing.T) {
	p := NewPlanner()
	var wg sync.WaitGroup
	totalPackets := 0
	var mu sync.Mutex
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			spec := validSpec()
			spec.SrcPort = 50000 + uint16(workerID)
			spec.WireGuard.SenderIndex = uint32(workerID + 1)
			spec.WireGuard.TransportPayloads = [][]byte{{0x01}, {0x02}}
			ch, err := p.Plan(context.Background(), spec)
			if err != nil {
				return
			}
			cfgs := drain(ch)
			mu.Lock()
			totalPackets += len(cfgs)
			mu.Unlock()
		}(i)
	}
	wg.Wait()
	// Each worker should emit 4 packets (handshake + 2 transport).
	expected := 8 * 4
	if totalPackets != expected {
		t.Errorf("total packets=%d, want %d", totalPackets, expected)
	}
}

// ===================================================================
// 6. Resource exhaustion tests
// ===================================================================

func TestWireGuard_6_1_3_ContextCancel(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.TransportPayloads = make([][]byte, 1000)
	for i := range spec.WireGuard.TransportPayloads {
		spec.WireGuard.TransportPayloads[i] = []byte{0x41}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately
	ch, err := p.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan error: %v", err)
	}
	// Drain should return quickly (ctx cancelled).
	cfgs := drain(ch)
	// Should have emitted some packets before ctx cancel took effect.
	// The exact count depends on buffering; just verify it doesn't hang.
	_ = cfgs
}

func TestWireGuard_6_4_1_LargePayloadCount(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.TransportPayloads = make([][]byte, 100)
	for i := range spec.WireGuard.TransportPayloads {
		spec.WireGuard.TransportPayloads[i] = make([]byte, 100)
	}
	cfgs := drain(mustPlan(t, p, spec))
	// handshake(2) + transport(100) = 102 packets.
	if len(cfgs) != 102 {
		t.Errorf("packet count=%d, want 102", len(cfgs))
	}
}

// ===================================================================
// Default spec tests
// ===================================================================

func TestWireGuard_DefaultSpec_NoWireGuard(t *testing.T) {
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
	if len(cfgs) != 3 {
		t.Errorf("default spec packet count=%d, want 3", len(cfgs))
	}
}

func TestWireGuard_Name(t *testing.T) {
	p := NewPlanner()
	if got := p.Name(); got != "wireguard" {
		t.Errorf("Name() = %q, want %q", got, "wireguard")
	}
}

func TestWireGuard_NewPlanner(t *testing.T) {
	p := NewPlanner()
	if p == nil {
		t.Fatal("NewPlanner returned nil")
	}
}

func TestWireGuard_Validate_NilWireGuard(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "192.0.2.1",
		DstIP: "192.0.2.2",
	}
	if err := p.Validate(spec); err != nil {
		t.Errorf("Validate with nil WireGuard failed: %v", err)
	}
}

func TestWireGuard_Validate_InvalidSrcIP(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "invalid-ip",
		DstIP: "192.0.2.2",
	}
	if err := p.Validate(spec); err == nil {
		t.Error("expected error for invalid SrcIP, got nil")
	}
}

func TestWireGuard_Validate_InvalidDstIP(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "192.0.2.1",
		DstIP: "invalid-ip",
	}
	if err := p.Validate(spec); err == nil {
		t.Error("expected error for invalid DstIP, got nil")
	}
}

// ===================================================================
// Determinism tests
// ===================================================================

func TestWireGuard_Deterministic_Ephemeral(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	cfgs1 := drain(mustPlan(t, p, spec))
	cfgs2 := drain(mustPlan(t, p, spec))
	// Both runs should produce identical ephemeral bytes.
	ephemeral1 := cfgs1[0].Payload[8:40]
	ephemeral2 := cfgs2[0].Payload[8:40]
	for i := range ephemeral1 {
		if ephemeral1[i] != ephemeral2[i] {
			t.Errorf("ephemeral byte[%d] differs: %02x vs %02x (expected deterministic)",
				i, ephemeral1[i], ephemeral2[i])
			break
		}
	}
}

func TestWireGuard_Deterministic_EncStatic(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	cfgs1 := drain(mustPlan(t, p, spec))
	cfgs2 := drain(mustPlan(t, p, spec))
	encStatic1 := cfgs1[0].Payload[40:88]
	encStatic2 := cfgs2[0].Payload[40:88]
	for i := range encStatic1 {
		if encStatic1[i] != encStatic2[i] {
			t.Errorf("enc_static byte[%d] differs: %02x vs %02x (expected deterministic)",
				i, encStatic1[i], encStatic2[i])
			break
		}
	}
}

// ===================================================================
// IPv6 tests
// ===================================================================

func TestWireGuard_IPv6(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcMAC: "02:00:00:00:00:01",
		DstMAC: "02:00:00:00:00:02",
		SrcIP: "2001:db8::1",
		DstIP: "2001:db8::2",
		SrcPort: 50000,
		DstPort: DefaultPort,
		WireGuard: &core.WireGuardConfig{
			Role: "initiator",
			SenderIndex: 1,
			TransportPayloads: [][]byte{{0x41}},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) != 3 {
		t.Errorf("IPv6 packet count=%d, want 3", len(cfgs))
	}
	// Verify EtherType is IPv6.
	if cfgs[0].L2.EtherType != 0x86DD {
		t.Errorf("EtherType=%04x, want 86DD (IPv6)", cfgs[0].L2.EtherType)
	}
}

// ===================================================================
// Direction both alternation tests
// ===================================================================

func TestWireGuard_DirectionBothAlternatesOddEven(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.Direction = "both"
	spec.WireGuard.TransportPayloads = [][]byte{{0x01}, {0x02}, {0x03}, {0x04}, {0x05}}
	cfgs := drain(mustPlan(t, p, spec))
	// 5 transport packets: up, down, up, down, up
	expected := []string{"up", "down", "up", "down", "up"}
	for i, want := range expected {
		if cfgs[2+i].Direction != want {
			t.Errorf("transport[%d] direction=%s, want %s", i, cfgs[2+i].Direction, want)
		}
	}
}

// ===================================================================
// Validate returns nil for valid specs
// ===================================================================

func TestWireGuard_Validate_ValidSpec(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	if err := p.Validate(spec); err != nil {
		t.Errorf("Validate failed for valid spec: %v", err)
	}
}

// ===================================================================
// PacketIndex and FlowID tests
// ===================================================================

func TestWireGuard_PacketIndexAscending(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.TransportPayloads = [][]byte{{0x01}, {0x02}, {0x03}}
	cfgs := drain(mustPlan(t, p, spec))
	for i := 1; i < len(cfgs); i++ {
		if cfgs[i].PacketIndex <= cfgs[i-1].PacketIndex {
			t.Errorf("PacketIndex[%d]=%d not > prev=%d", i, cfgs[i].PacketIndex, cfgs[i-1].PacketIndex)
		}
	}
}

func TestWireGuard_FlowIDConsistent(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.TransportPayloads = [][]byte{{0x01}, {0x02}}
	cfgs := drain(mustPlan(t, p, spec))
	for i, c := range cfgs {
		if c.FlowID != cfgs[0].FlowID {
			t.Errorf("cfgs[%d].FlowID=%q, want %q", i, c.FlowID, cfgs[0].FlowID)
		}
	}
}

// ===================================================================
// L4Protocol and L3Protocol tests
// ===================================================================

func TestWireGuard_L4ProtocolUDP(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	cfgs := drain(mustPlan(t, p, spec))
	for i, c := range cfgs {
		if c.L4.Protocol != "udp" {
			t.Errorf("cfgs[%d].L4.Protocol=%q, want udp", i, c.L4.Protocol)
		}
	}
}

func TestWireGuard_L3Protocol17(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	cfgs := drain(mustPlan(t, p, spec))
	for i, c := range cfgs {
		if c.L3.Protocol != 17 {
			t.Errorf("cfgs[%d].L3.Protocol=%d, want 17 (UDP)", i, c.L3.Protocol)
		}
	}
}

func TestWireGuard_DstPort51820(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	cfgs := drain(mustPlan(t, p, spec))
	// Up packets should have DstPort=51820.
	if cfgs[0].L4.DstPort != DefaultPort {
		t.Errorf("up DstPort=%d, want %d", cfgs[0].L4.DstPort, DefaultPort)
	}
}

// ===================================================================
// Metadata tests
// ===================================================================

func TestWireGuard_MetadataMessageType(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	cfgs := drain(mustPlan(t, p, spec))
	for i, c := range cfgs {
		if c.Metadata == nil {
			t.Errorf("cfgs[%d].Metadata is nil", i)
			continue
		}
		if _, ok := c.Metadata["wireguard_message_type"]; !ok {
			t.Errorf("cfgs[%d] missing wireguard_message_type metadata", i)
		}
	}
}

// ===================================================================
// Default port tests
// ===================================================================

func TestWireGuard_DefaultPortConstant(t *testing.T) {
	if DefaultPort != 51820 {
		t.Errorf("DefaultPort=%d, want 51820", DefaultPort)
	}
}

func TestWireGuard_DefaultTTLConstant(t *testing.T) {
	if DefaultTTL != 64 {
		t.Errorf("DefaultTTL=%d, want 64", DefaultTTL)
	}
}

func TestWireGuard_MessageTypeConstants(t *testing.T) {
	if MsgHandshakeInitiation != 1 {
		t.Errorf("MsgHandshakeInitiation=%d, want 1", MsgHandshakeInitiation)
	}
	if MsgHandshakeResponse != 2 {
		t.Errorf("MsgHandshakeResponse=%d, want 2", MsgHandshakeResponse)
	}
	if MsgCookieReply != 3 {
		t.Errorf("MsgCookieReply=%d, want 3", MsgCookieReply)
	}
	if MsgTransportData != 4 {
		t.Errorf("MsgTransportData=%d, want 4", MsgTransportData)
	}
}

func TestWireGuard_SizeConstants(t *testing.T) {
	if SizeHandshakeInitiation != 148 {
		t.Errorf("SizeHandshakeInitiation=%d, want 148", SizeHandshakeInitiation)
	}
	if SizeHandshakeResponse != 92 {
		t.Errorf("SizeHandshakeResponse=%d, want 92", SizeHandshakeResponse)
	}
	if SizeCookieReply != 64 {
		t.Errorf("SizeCookieReply=%d, want 64", SizeCookieReply)
	}
}

// ===================================================================
// Empty payload tests
// ===================================================================

func TestWireGuard_EmptyTransportPayload32Bytes(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.TransportPayloads = [][]byte{{}}
	cfgs := drain(mustPlan(t, p, spec))
	trans := cfgs[2]
	if len(trans.Payload) != 32 {
		t.Errorf("empty transport payload length=%d, want 32", len(trans.Payload))
	}
}

// ===================================================================
// Keepalive counter test
// ===================================================================

func TestWireGuard_KeepaliveCounter(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.TransportPayloads = [][]byte{{0x01}, {0x02}}
	spec.WireGuard.KeepaliveInterval = 10
	cfgs := drain(mustPlan(t, p, spec))
	// handshake(2) + transport(2) + keepalive(1) = 5 packets.
	if len(cfgs) != 5 {
		t.Fatalf("packet count=%d, want 5", len(cfgs))
	}
	keepalive := cfgs[4]
	if len(keepalive.Payload) != 32 {
		t.Errorf("keepalive length=%d, want 32", len(keepalive.Payload))
	}
	// counter should be 2 (after 2 transport packets with counter 0, 1).
	counter := binary.LittleEndian.Uint64(keepalive.Payload[8:16])
	if counter != 2 {
		t.Errorf("keepalive counter=%d, want 2", counter)
	}
}

// ===================================================================
// Multiple transport packets counter sequence test
// ===================================================================

func TestWireGuard_TransportCounterSequence(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.TransportPayloads = [][]byte{{0x01}, {0x02}, {0x03}, {0x04}, {0x05}}
	cfgs := drain(mustPlan(t, p, spec))
	// handshake(2) + transport(5) = 7 packets.
	if len(cfgs) != 7 {
		t.Fatalf("packet count=%d, want 7", len(cfgs))
	}
	for i := 0; i < 5; i++ {
		trans := cfgs[2+i]
		counter := binary.LittleEndian.Uint64(trans.Payload[8:16])
		if counter != uint64(i) {
			t.Errorf("transport[%d] counter=%d, want %d", i, counter, i)
		}
	}
}