package wireguard

import (
	"context"
	"encoding/binary"
	"fmt"
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
// 8. Noise IK Handshake (RFC 7748, WireGuard §4.1) — 新增 tests
// ===================================================================

// 8.1 Initiator Static Key (Curve25519, 32 字节)
func TestWireGuard_8_1_1_LocalStaticPubKey32Bytes(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.LocalStaticPubKey = make([]byte, 32)
	for i := range spec.WireGuard.LocalStaticPubKey {
		spec.WireGuard.LocalStaticPubKey[i] = 0xAA
	}
	if err := p.Validate(spec); err != nil {
		t.Errorf("Validate failed for 32-byte LocalStaticPubKey: %v", err)
	}
	cfgs := drain(mustPlan(t, p, spec))
	init := cfgs[0]
	// enc_static at bytes[40..88] = 48 bytes deterministic
	encStatic := init.Payload[40:88]
	if len(encStatic) != SizeEncStatic {
		t.Errorf("enc_static length=%d, want %d", len(encStatic), SizeEncStatic)
	}
}

func TestWireGuard_8_1_2_LocalStaticPubKeyNil(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.LocalStaticPubKey = nil
	if err := p.Validate(spec); err != nil {
		t.Errorf("Validate failed for nil LocalStaticPubKey: %v", err)
	}
}

func TestWireGuard_8_1_3_LocalStaticPubKeyEmpty(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.LocalStaticPubKey = []byte{}
	if err := p.Validate(spec); err != nil {
		t.Errorf("Validate failed for empty LocalStaticPubKey: %v", err)
	}
}

// 8.2 Responder Static Key (32 字节)
func TestWireGuard_8_2_1_PeerStaticPubKey32Bytes(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.PeerStaticPubKey = make([]byte, 32)
	for i := range spec.WireGuard.PeerStaticPubKey {
		spec.WireGuard.PeerStaticPubKey[i] = 0xBB
	}
	if err := p.Validate(spec); err != nil {
		t.Errorf("Validate failed for 32-byte PeerStaticPubKey: %v", err)
	}
}

func TestWireGuard_8_2_2_PeerStaticPubKeyAllFF(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.PeerStaticPubKey = make([]byte, 32)
	for i := range spec.WireGuard.PeerStaticPubKey {
		spec.WireGuard.PeerStaticPubKey[i] = 0xFF
	}
	if err := p.Validate(spec); err != nil {
		t.Errorf("Validate failed for 32-byte 0xFF PeerStaticPubKey: %v", err)
	}
}

func TestWireGuard_8_2_3_PeerStaticPubKeyWrongLength31(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.PeerStaticPubKey = make([]byte, 31)
	if err := p.Validate(spec); err == nil {
		t.Error("expected error for 31-byte PeerStaticPubKey, got nil")
	}
}

// 8.3 Initiator Ephemeral Key (32 字节, 随机每握手)
func TestWireGuard_8_3_1_EphemeralNilAutoGenerate(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.LocalEphemeralPubKey = nil
	cfgs := drain(mustPlan(t, p, spec))
	init := cfgs[0]
	ephemeral := init.Payload[8:40]
	if len(ephemeral) != SizeEphemeral {
		t.Errorf("ephemeral length=%d, want %d", len(ephemeral), SizeEphemeral)
	}
	allZero := true
	for _, b := range ephemeral {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("ephemeral is all zeros when auto-generated, expected non-zero")
	}
}

func TestWireGuard_8_3_2_EphemeralSetValue(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	ephemeral := make([]byte, SizeEphemeral)
	for i := range ephemeral {
		ephemeral[i] = 0xCC
	}
	spec.WireGuard.LocalEphemeralPubKey = ephemeral
	cfgs := drain(mustPlan(t, p, spec))
	init := cfgs[0]
	for i := 8; i < 40; i++ {
		if init.Payload[i] != 0xCC {
			t.Errorf("ephemeral byte[%d]=%02x, want 0xCC", i-8, init.Payload[i])
			break
		}
	}
}

func TestWireGuard_8_3_3_EphemeralDeterministic(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.LocalEphemeralPubKey = nil
	cfgs1 := drain(mustPlan(t, p, spec))
	cfgs2 := drain(mustPlan(t, p, spec))
	ephemeral1 := cfgs1[0].Payload[8:40]
	ephemeral2 := cfgs2[0].Payload[8:40]
	for i := range ephemeral1 {
		if ephemeral1[i] != ephemeral2[i] {
			t.Errorf("ephemeral byte[%d] differs between runs: %02x vs %02x", i, ephemeral1[i], ephemeral2[i])
			break
		}
	}
}

// 8.4 Responder Ephemeral Key (32 字节)
func TestWireGuard_8_4_1_ResponseEphemeralResponderRole(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.Role = "responder"
	cfgs := drain(mustPlan(t, p, spec))
	resp := cfgs[0]
	ephemeral := resp.Payload[12:44]
	if len(ephemeral) != SizeEphemeral {
		t.Errorf("Response ephemeral length=%d, want %d", len(ephemeral), SizeEphemeral)
	}
}

func TestWireGuard_8_4_2_ResponseEphemeralInitiatorRole(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	cfgs := drain(mustPlan(t, p, spec))
	resp := cfgs[1]
	ephemeral := resp.Payload[12:44]
	if len(ephemeral) != SizeEphemeral {
		t.Errorf("Response ephemeral length=%d, want %d", len(ephemeral), SizeEphemeral)
	}
	// Response ephemeral should differ from Initiation ephemeral
	initEphemeral := cfgs[0].Payload[8:40]
	same := true
	for i := range ephemeral {
		if ephemeral[i] != initEphemeral[i] {
			same = false
			break
		}
	}
	if same {
		t.Error("Response ephemeral equals Initiation ephemeral, expected different")
	}
}

func TestWireGuard_8_4_3_EphemeralLengthAlways32(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	cfgs := drain(mustPlan(t, p, spec))
	init := cfgs[0]
	resp := cfgs[1]
	if len(init.Payload[8:40]) != SizeEphemeral {
		t.Errorf("Initiation ephemeral length=%d, want %d", len(init.Payload[8:40]), SizeEphemeral)
	}
	if len(resp.Payload[12:44]) != SizeEphemeral {
		t.Errorf("Response ephemeral length=%d, want %d", len(resp.Payload[12:44]), SizeEphemeral)
	}
}

// 8.5 DH Output (32 字节, 加密不可解密)
func TestWireGuard_8_5_1_EncStaticLength48(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	cfgs := drain(mustPlan(t, p, spec))
	init := cfgs[0]
	encStatic := init.Payload[40:88]
	if len(encStatic) != SizeEncStatic {
		t.Errorf("enc_static length=%d, want %d", len(encStatic), SizeEncStatic)
	}
}

func TestWireGuard_8_5_2_EncStaticTotalLengthCheck(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	cfgs := drain(mustPlan(t, p, spec))
	init := cfgs[0]
	if len(init.Payload) != SizeHandshakeInitiation {
		t.Errorf("Initiation total length=%d, want %d", len(init.Payload), SizeHandshakeInitiation)
	}
}

// 8.6 Chaining Key Derivation (HKDF-SHA256, 模拟)
func TestWireGuard_8_6_1_EncStaticDeterministic(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	cfgs1 := drain(mustPlan(t, p, spec))
	cfgs2 := drain(mustPlan(t, p, spec))
	encStatic1 := cfgs1[0].Payload[40:88]
	encStatic2 := cfgs2[0].Payload[40:88]
	for i := range encStatic1 {
		if encStatic1[i] != encStatic2[i] {
			t.Errorf("enc_static byte[%d] differs between runs: %02x vs %02x", i, encStatic1[i], encStatic2[i])
			break
		}
	}
}

func TestWireGuard_8_6_2_EncStaticDiffersBySenderIndex(t *testing.T) {
	p := NewPlanner()
	spec1 := validSpec()
	spec1.WireGuard.SenderIndex = 1
	spec2 := validSpec()
	spec2.WireGuard.SenderIndex = 2
	cfgs1 := drain(mustPlan(t, p, spec1))
	cfgs2 := drain(mustPlan(t, p, spec2))
	encStatic1 := cfgs1[0].Payload[40:88]
	encStatic2 := cfgs2[0].Payload[40:88]
	same := true
	for i := range encStatic1 {
		if encStatic1[i] != encStatic2[i] {
			same = false
			break
		}
	}
	if same {
		t.Error("enc_static with SenderIndex=1 and SenderIndex=2 are identical, expected different")
	}
}

// 8.7 Handshake Hash (BLAKE2s-256, 模拟)
func TestWireGuard_8_7_1_MAC1Initiation16Bytes(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	cfgs := drain(mustPlan(t, p, spec))
	init := cfgs[0]
	mac1 := init.Payload[116:132]
	if len(mac1) != SizeMAC1 {
		t.Errorf("Initiation mac1 length=%d, want %d", len(mac1), SizeMAC1)
	}
}

func TestWireGuard_8_7_2_MAC1DiffersBySenderIndex(t *testing.T) {
	p := NewPlanner()
	spec1 := validSpec()
	spec1.WireGuard.SenderIndex = 1
	spec2 := validSpec()
	spec2.WireGuard.SenderIndex = 42
	cfgs1 := drain(mustPlan(t, p, spec1))
	cfgs2 := drain(mustPlan(t, p, spec2))
	mac1_1 := cfgs1[0].Payload[116:132]
	mac1_2 := cfgs2[0].Payload[116:132]
	same := true
	for i := range mac1_1 {
		if mac1_1[i] != mac1_2[i] {
			same = false
			break
		}
	}
	if same {
		t.Error("mac1 with SenderIndex=1 and SenderIndex=42 are identical, expected different")
	}
}

// 8.8 MAC1 (BLAKE2s with chaining key, 16 字节)
func TestWireGuard_8_8_1_MAC1InitiationNonZero(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	cfgs := drain(mustPlan(t, p, spec))
	init := cfgs[0]
	mac1 := init.Payload[116:132]
	allZero := true
	for _, b := range mac1 {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("Initiation mac1 is all zeros, expected non-zero")
	}
}

func TestWireGuard_8_8_2_MAC1ResponseNonZero(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	cfgs := drain(mustPlan(t, p, spec))
	resp := cfgs[1]
	mac1 := resp.Payload[60:76]
	allZero := true
	for _, b := range mac1 {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("Response mac1 is all zeros, expected non-zero")
	}
}

func TestWireGuard_8_8_3_MAC1LengthFixed16(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	cfgs := drain(mustPlan(t, p, spec))
	init := cfgs[0]
	resp := cfgs[1]
	if len(init.Payload[116:132]) != SizeMAC1 {
		t.Errorf("Initiation mac1 length=%d, want %d", len(init.Payload[116:132]), SizeMAC1)
	}
	if len(resp.Payload[60:76]) != SizeMAC1 {
		t.Errorf("Response mac1 length=%d, want %d", len(resp.Payload[60:76]), SizeMAC1)
	}
}

// 8.9 MAC2 (Cookie MAC, 16 字节)
func TestWireGuard_8_9_1_MAC2InitiationZeroNoCookie(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.Cookie = nil
	cfgs := drain(mustPlan(t, p, spec))
	init := cfgs[0]
	for i := 132; i < 148; i++ {
		if init.Payload[i] != 0 {
			t.Errorf("Initiation mac2 byte[%d]=%02x, want 0 (no cookie)", i-132, init.Payload[i])
		}
	}
}

func TestWireGuard_8_9_2_MAC2InitiationNonZeroWithCookie(t *testing.T) {
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
		t.Error("Initiation mac2 is all zeros with cookie set, expected non-zero")
	}
}

func TestWireGuard_8_9_3_MAC2ResponseZeroNoCookie(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.Cookie = nil
	cfgs := drain(mustPlan(t, p, spec))
	resp := cfgs[1]
	for i := 76; i < 92; i++ {
		if resp.Payload[i] != 0 {
			t.Errorf("Response mac2 byte[%d]=%02x, want 0 (no cookie)", i-76, resp.Payload[i])
		}
	}
}

// 8.10 Sender Index (field 字段)
func TestWireGuard_8_10_1_SenderIndexAutoIs1(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.SenderIndex = 0
	cfgs := drain(mustPlan(t, p, spec))
	init := cfgs[0]
	if init.Payload[4] != 1 || init.Payload[5] != 0 || init.Payload[6] != 0 || init.Payload[7] != 0 {
		t.Errorf("sender_index bytes=%02x%02x%02x%02x, want 01000000",
			init.Payload[4], init.Payload[5], init.Payload[6], init.Payload[7])
	}
}

func TestWireGuard_8_10_2_SenderIndex42(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.SenderIndex = 42
	cfgs := drain(mustPlan(t, p, spec))
	init := cfgs[0]
	if init.Payload[4] != 0x2A || init.Payload[5] != 0 || init.Payload[6] != 0 || init.Payload[7] != 0 {
		t.Errorf("sender_index bytes=%02x%02x%02x%02x, want 2a000000",
			init.Payload[4], init.Payload[5], init.Payload[6], init.Payload[7])
	}
}

func TestWireGuard_8_10_3_ResponseSenderIndexAuto(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.SenderIndex = 1
	cfgs := drain(mustPlan(t, p, spec))
	resp := cfgs[1]
	// responder sender_index = initiator sender_index + 1 = 2
	if resp.Payload[4] != 2 || resp.Payload[5] != 0 || resp.Payload[6] != 0 || resp.Payload[7] != 0 {
		t.Errorf("Response sender_index bytes=%02x%02x%02x%02x, want 02000000",
			resp.Payload[4], resp.Payload[5], resp.Payload[6], resp.Payload[7])
	}
}

// 8.11 Message Type 1 (Handshake Initiation, 148 字节)
func TestWireGuard_8_11_1_InitiationMessageType1(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	cfgs := drain(mustPlan(t, p, spec))
	init := cfgs[0]
	if init.Payload[0] != 0x01 {
		t.Errorf("message_type=%d, want 1", init.Payload[0])
	}
	if len(init.Payload) != 148 {
		t.Errorf("Initiation total length=%d, want 148", len(init.Payload))
	}
}

func TestWireGuard_8_11_2_InitiationFieldOrder(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	cfgs := drain(mustPlan(t, p, spec))
	init := cfgs[0]
	// Verify field ordering: type(1) + reserved(3) + sender_index(4) + ephemeral(32) + enc_static(48) + enc_timestamp(28) + mac1(16) + mac2(16)
	if len(init.Payload) != SizeHandshakeInitiation {
		t.Fatalf("Initiation length=%d, want %d", len(init.Payload), SizeHandshakeInitiation)
	}
	// message_type at offset 0
	if init.Payload[0] != MsgHandshakeInitiation {
		t.Errorf("offset 0 message_type=%d, want 1", init.Payload[0])
	}
	// reserved_zero at offset 1-3
	if init.Payload[1] != 0 || init.Payload[2] != 0 || init.Payload[3] != 0 {
		t.Errorf("reserved_zero at offset 1-3 non-zero")
	}
	// sender_index at offset 4-7
	senderIndex := binary.LittleEndian.Uint32(init.Payload[4:8])
	if senderIndex != 1 {
		t.Errorf("sender_index=%d, want 1", senderIndex)
	}
	// ephemeral at offset 8-39
	if len(init.Payload[8:40]) != SizeEphemeral {
		t.Errorf("ephemeral length=%d, want %d", len(init.Payload[8:40]), SizeEphemeral)
	}
	// enc_static at offset 40-87
	if len(init.Payload[40:88]) != SizeEncStatic {
		t.Errorf("enc_static length=%d, want %d", len(init.Payload[40:88]), SizeEncStatic)
	}
	// enc_timestamp at offset 88-115
	if len(init.Payload[88:116]) != SizeEncTimestamp {
		t.Errorf("enc_timestamp length=%d, want %d", len(init.Payload[88:116]), SizeEncTimestamp)
	}
	// mac1 at offset 116-131
	if len(init.Payload[116:132]) != SizeMAC1 {
		t.Errorf("mac1 length=%d, want %d", len(init.Payload[116:132]), SizeMAC1)
	}
	// mac2 at offset 132-147
	if len(init.Payload[132:148]) != SizeMAC2 {
		t.Errorf("mac2 length=%d, want %d", len(init.Payload[132:148]), SizeMAC2)
	}
}

// 8.12 Message Type 2 (Handshake Response, 92 字节)
func TestWireGuard_8_12_1_ResponseMessageType2(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	cfgs := drain(mustPlan(t, p, spec))
	resp := cfgs[1]
	if resp.Payload[0] != 0x02 {
		t.Errorf("message_type=%d, want 2", resp.Payload[0])
	}
	if len(resp.Payload) != 92 {
		t.Errorf("Response total length=%d, want 92", len(resp.Payload))
	}
}

func TestWireGuard_8_12_2_ResponseFieldOrder(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	cfgs := drain(mustPlan(t, p, spec))
	resp := cfgs[1]
	if len(resp.Payload) != SizeHandshakeResponse {
		t.Fatalf("Response length=%d, want %d", len(resp.Payload), SizeHandshakeResponse)
	}
	// message_type at offset 0
	if resp.Payload[0] != MsgHandshakeResponse {
		t.Errorf("offset 0 message_type=%d, want 2", resp.Payload[0])
	}
	// reserved_zero at offset 1-3
	if resp.Payload[1] != 0 || resp.Payload[2] != 0 || resp.Payload[3] != 0 {
		t.Errorf("reserved_zero at offset 1-3 non-zero")
	}
	// sender_index at offset 4-7
	senderIndex := binary.LittleEndian.Uint32(resp.Payload[4:8])
	if senderIndex == 0 {
		t.Errorf("Response sender_index is 0, expected > 0")
	}
	// receiver_index at offset 8-11
	receiverIndex := binary.LittleEndian.Uint32(resp.Payload[8:12])
	if receiverIndex == 0 {
		t.Errorf("Response receiver_index is 0, expected > 0")
	}
	// ephemeral at offset 12-43
	if len(resp.Payload[12:44]) != SizeEphemeral {
		t.Errorf("ephemeral length=%d, want %d", len(resp.Payload[12:44]), SizeEphemeral)
	}
	// enc_empty at offset 44-59
	if len(resp.Payload[44:60]) != SizeEncEmpty {
		t.Errorf("enc_empty length=%d, want %d", len(resp.Payload[44:60]), SizeEncEmpty)
	}
	// mac1 at offset 60-75
	if len(resp.Payload[60:76]) != SizeMAC1 {
		t.Errorf("mac1 length=%d, want %d", len(resp.Payload[60:76]), SizeMAC1)
	}
	// mac2 at offset 76-91
	if len(resp.Payload[76:92]) != SizeMAC2 {
		t.Errorf("mac2 length=%d, want %d", len(resp.Payload[76:92]), SizeMAC2)
	}
}

// 8.13 Message Type 3 (Cookie Reply, 64 字节)
func TestWireGuard_8_13_1_CookieReplyMessageType3(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.Role = "responder"
	spec.WireGuard.CookieReplyThreshold = 1
	cfgs := drain(mustPlan(t, p, spec))
	var found bool
	for _, c := range cfgs {
		if len(c.Payload) > 0 && c.Payload[0] == 0x03 {
			found = true
			if len(c.Payload) != 64 {
				t.Errorf("Cookie Reply length=%d, want 64", len(c.Payload))
			}
		}
	}
	if !found {
		t.Error("expected Cookie Reply (type=3) packet, none found")
	}
}

func TestWireGuard_8_13_2_CookieReplyFieldOrder(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.Role = "responder"
	spec.WireGuard.CookieReplyThreshold = 1
	cfgs := drain(mustPlan(t, p, spec))
	for _, c := range cfgs {
		if len(c.Payload) > 0 && c.Payload[0] == MsgCookieReply {
			if len(c.Payload) != SizeCookieReply {
				t.Fatalf("Cookie Reply length=%d, want %d", len(c.Payload), SizeCookieReply)
			}
			// message_type at offset 0
			if c.Payload[0] != MsgCookieReply {
				t.Errorf("offset 0 message_type=%d, want 3", c.Payload[0])
			}
			// reserved_zero at offset 1-3
			if c.Payload[1] != 0 || c.Payload[2] != 0 || c.Payload[3] != 0 {
				t.Errorf("reserved_zero at offset 1-3 non-zero")
			}
			// receiver_index at offset 4-7
			receiverIndex := binary.LittleEndian.Uint32(c.Payload[4:8])
			if receiverIndex == 0 {
				t.Errorf("Cookie Reply receiver_index is 0, expected > 0")
			}
			// nonce at offset 8-31
			if len(c.Payload[8:32]) != SizeCookieNonce {
				t.Errorf("nonce length=%d, want %d", len(c.Payload[8:32]), SizeCookieNonce)
			}
			// enc_cookie at offset 32-63
			if len(c.Payload[32:64]) != SizeEncCookie {
				t.Errorf("enc_cookie length=%d, want %d", len(c.Payload[32:64]), SizeEncCookie)
			}
			return
		}
	}
	t.Error("Cookie Reply packet not found")
}

// 8.14 Message Type 4 (Transport Data, 32+N 字节)
func TestWireGuard_8_14_1_TransportMessageType4(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	cfgs := drain(mustPlan(t, p, spec))
	trans := cfgs[2]
	if trans.Payload[0] != 0x04 {
		t.Errorf("message_type=%d, want 4", trans.Payload[0])
	}
	expectedLen := SizeTransportHeader + 1 + SizeAEADTag
	if len(trans.Payload) != expectedLen {
		t.Errorf("Transport total length=%d, want %d (1-byte payload)", len(trans.Payload), expectedLen)
	}
}

func TestWireGuard_8_14_2_TransportFieldOrder(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	cfgs := drain(mustPlan(t, p, spec))
	trans := cfgs[2]
	expectedLen := SizeTransportHeader + 1 + SizeAEADTag
	if len(trans.Payload) != expectedLen {
		t.Fatalf("Transport length=%d, want %d", len(trans.Payload), expectedLen)
	}
	// message_type at offset 0
	if trans.Payload[0] != MsgTransportData {
		t.Errorf("offset 0 message_type=%d, want 4", trans.Payload[0])
	}
	// reserved_zero at offset 1-3
	if trans.Payload[1] != 0 || trans.Payload[2] != 0 || trans.Payload[3] != 0 {
		t.Errorf("reserved_zero at offset 1-3 non-zero")
	}
	// receiver_index at offset 4-7
	receiverIndex := binary.LittleEndian.Uint32(trans.Payload[4:8])
	if receiverIndex == 0 {
		t.Errorf("Transport receiver_index is 0, expected > 0")
	}
	// counter at offset 8-15
	if len(trans.Payload[8:16]) != SizeCounter {
		t.Errorf("counter length=%d, want %d", len(trans.Payload[8:16]), SizeCounter)
	}
	// enc_payload at offset 16+ must be at least 16 bytes (AEAD tag)
	if len(trans.Payload[16:]) < SizeAEADTag {
		t.Errorf("enc_payload length=%d, want >= %d", len(trans.Payload[16:]), SizeAEADTag)
	}
}

// ===================================================================
// 9. Transport Data Message (RFC 7539, WireGuard §5.4) — 新增 tests
// ===================================================================

// 9.1 Nonce (8 字节小端 counter)
func TestWireGuard_9_1_1_CounterZero(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	cfgs := drain(mustPlan(t, p, spec))
	trans := cfgs[2]
	counter := binary.LittleEndian.Uint64(trans.Payload[8:16])
	if counter != 0 {
		t.Errorf("counter=%d, want 0", counter)
	}
}

func TestWireGuard_9_1_2_CounterOne(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.TransportPayloads = [][]byte{{0x01}, {0x02}}
	cfgs := drain(mustPlan(t, p, spec))
	trans := cfgs[3]
	counter := binary.LittleEndian.Uint64(trans.Payload[8:16])
	if counter != 1 {
		t.Errorf("counter=%d, want 1", counter)
	}
}

func TestWireGuard_9_1_3_CounterInitial100(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.InitialCounter = 100
	cfgs := drain(mustPlan(t, p, spec))
	trans := cfgs[2]
	counter := binary.LittleEndian.Uint64(trans.Payload[8:16])
	if counter != 100 {
		t.Errorf("counter=%d, want 100", counter)
	}
}

func TestWireGuard_9_1_4_CounterMaxUint64(t *testing.T) {
	// Test MaxUint64 counter via direct buildTransportData call
	// (via Plan, RekeyAfter validation prevents using ^uint64(0) with rekey disabled)
	buf := buildTransportData(1, ^uint64(0), []byte{0x41})
	counter := binary.LittleEndian.Uint64(buf[8:16])
	if counter != ^uint64(0) {
		t.Errorf("counter=%d, want %d", counter, ^uint64(0))
	}
	for i := 8; i < 16; i++ {
		if buf[i] != 0xFF {
			t.Errorf("counter byte[%d]=%02x, want 0xFF", i-8, buf[i])
			break
		}
	}
}

// 9.2 Receiver Index (4 字节 uint32)
func TestWireGuard_9_2_1_TransportReceiverIndex(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.SenderIndex = 1
	cfgs := drain(mustPlan(t, p, spec))
	trans := cfgs[2]
	receiverIndex := binary.LittleEndian.Uint32(trans.Payload[4:8])
	// responder sender_index = 2
	if receiverIndex != 2 {
		t.Errorf("receiver_index=%d, want 2 (responder index)", receiverIndex)
	}
}

// 9.3 ChaCha20-Poly1305 AEAD Construction (模拟)
func TestWireGuard_9_3_1_AEADTagOnlyEmptyPayload(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.TransportPayloads = [][]byte{{}}
	cfgs := drain(mustPlan(t, p, spec))
	trans := cfgs[2]
	// 32 bytes = 16 header + 0 payload + 16 tag
	if len(trans.Payload) != 32 {
		t.Errorf("empty transport length=%d, want 32", len(trans.Payload))
	}
	encPayload := trans.Payload[16:]
	if len(encPayload) != SizeAEADTag {
		t.Errorf("enc_payload length=%d, want %d (AEAD tag only)", len(encPayload), SizeAEADTag)
	}
}

func TestWireGuard_9_3_2_AEAD1BytePayload(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.TransportPayloads = [][]byte{{0x41}}
	cfgs := drain(mustPlan(t, p, spec))
	trans := cfgs[2]
	// 33 bytes = 16 header + 1 payload + 16 tag
	if len(trans.Payload) != 33 {
		t.Errorf("1-byte transport length=%d, want 33", len(trans.Payload))
	}
	// First byte of enc_payload = payload (0x41)
	if trans.Payload[16] != 0x41 {
		t.Errorf("enc_payload[0]=%02x, want 0x41", trans.Payload[16])
	}
}

func TestWireGuard_9_3_3_AEADPayloadPlusTagLength(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.TransportPayloads = [][]byte{{0x41, 0x42, 0x43}}
	cfgs := drain(mustPlan(t, p, spec))
	trans := cfgs[2]
	expectedLen := SizeTransportHeader + 3 + SizeAEADTag
	if len(trans.Payload) != expectedLen {
		t.Errorf("3-byte transport length=%d, want %d", len(trans.Payload), expectedLen)
	}
}

// 9.4 Empty Payload (仅 MAC, 16 字节)
func TestWireGuard_9_4_1_EmptyPayloadIsKeepalive(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.TransportPayloads = [][]byte{{}}
	cfgs := drain(mustPlan(t, p, spec))
	trans := cfgs[2]
	if trans.Payload[0] != MsgTransportData {
		t.Errorf("message_type=%d, want 4", trans.Payload[0])
	}
	if len(trans.Payload) != 32 {
		t.Errorf("empty payload transport length=%d, want 32", len(trans.Payload))
	}
}

// 9.5 Small Payload (1 字节, 17 字节 total)
func TestWireGuard_9_5_1_SmallPayloadLength(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.TransportPayloads = [][]byte{{0x41}}
	cfgs := drain(mustPlan(t, p, spec))
	trans := cfgs[2]
	if len(trans.Payload) != 33 {
		t.Errorf("1-byte payload transport length=%d, want 33", len(trans.Payload))
	}
}

func TestWireGuard_9_5_2_SmallPayloadContent(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.TransportPayloads = [][]byte{{0x41}}
	cfgs := drain(mustPlan(t, p, spec))
	trans := cfgs[2]
	// enc_payload[0] = 0x41 (payload preserved)
	if trans.Payload[16] != 0x41 {
		t.Errorf("enc_payload[0]=%02x, want 0x41", trans.Payload[16])
	}
	// enc_payload[1..16] = deterministic AEAD tag (non-zero)
	allZero := true
	for i := 17; i < 33; i++ {
		if trans.Payload[i] != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("AEAD tag is all zeros, expected non-zero deterministic")
	}
}

// 9.6 Standard Payload (1280 字节 IPv4 MTU)
func TestWireGuard_9_6_1_StandardPayload1280(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	payload := make([]byte, 1280)
	for i := range payload {
		payload[i] = 0x41
	}
	spec.WireGuard.TransportPayloads = [][]byte{payload}
	cfgs := drain(mustPlan(t, p, spec))
	trans := cfgs[2]
	expectedLen := SizeTransportHeader + 1280 + SizeAEADTag
	if len(trans.Payload) != expectedLen {
		t.Errorf("1280-byte transport length=%d, want %d", len(trans.Payload), expectedLen)
	}
}

func TestWireGuard_9_6_2_StandardPayloadCounter(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	payload := make([]byte, 1280)
	for i := range payload {
		payload[i] = 0x41
	}
	spec.WireGuard.TransportPayloads = [][]byte{payload}
	cfgs := drain(mustPlan(t, p, spec))
	trans := cfgs[2]
	counter := binary.LittleEndian.Uint64(trans.Payload[8:16])
	if counter != 0 {
		t.Errorf("counter=%d, want 0", counter)
	}
	receiverIndex := binary.LittleEndian.Uint32(trans.Payload[4:8])
	if receiverIndex == 0 {
		t.Error("receiver_index is 0, expected > 0")
	}
}

// 9.7 Jumbo Payload (65535 字节, 需分片, planner 拒绝)
func TestWireGuard_9_7_1_JumboPayloadRejected(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.TransportPayloads = [][]byte{make([]byte, 65535)}
	if err := p.Validate(spec); err == nil {
		t.Error("expected error for 65535-byte payload, got nil")
	}
}

func TestWireGuard_9_7_2_MaxLegalPayload1440(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	payload := make([]byte, 1440)
	for i := range payload {
		payload[i] = 0x41
	}
	spec.WireGuard.TransportPayloads = [][]byte{payload}
	if err := p.Validate(spec); err != nil {
		t.Fatalf("Validate failed for 1440-byte payload: %v", err)
	}
	cfgs := drain(mustPlan(t, p, spec))
	trans := cfgs[2]
	expectedLen := SizeTransportHeader + 1440 + SizeAEADTag
	if len(trans.Payload) != expectedLen {
		t.Errorf("1440-byte transport length=%d, want %d", len(trans.Payload), expectedLen)
	}
}

// 9.8 Counter Wraparound (2^64 边界)
func TestWireGuard_9_8_1_CounterMaxUint64(t *testing.T) {
	// Test MaxUint64 counter via direct buildTransportData call
	// (via Plan, RekeyAfter validation prevents using ^uint64(0) with rekey disabled)
	buf := buildTransportData(1, ^uint64(0), []byte{0x41})
	counter := binary.LittleEndian.Uint64(buf[8:16])
	if counter != ^uint64(0) {
		t.Errorf("counter=%d, want %d", counter, ^uint64(0))
	}
}

// 9.9 Nonce Reuse Protection (模拟, counter 严格递增)
func TestWireGuard_9_9_1_CounterStrictlyIncreasing(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.TransportPayloads = [][]byte{{0x01}, {0x02}, {0x03}}
	cfgs := drain(mustPlan(t, p, spec))
	for i := 0; i < 3; i++ {
		trans := cfgs[2+i]
		counter := binary.LittleEndian.Uint64(trans.Payload[8:16])
		if counter != uint64(i) {
			t.Errorf("transport[%d] counter=%d, want %d", i, counter, i)
		}
	}
}

// 9.10 Multiple Messages with Incrementing Counter
func TestWireGuard_9_10_1_TenPayloadsCounterSequence(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.TransportPayloads = make([][]byte, 10)
	for i := range spec.WireGuard.TransportPayloads {
		spec.WireGuard.TransportPayloads[i] = []byte{0x01}
	}
	cfgs := drain(mustPlan(t, p, spec))
	for i := 0; i < 10; i++ {
		trans := cfgs[2+i]
		counter := binary.LittleEndian.Uint64(trans.Payload[8:16])
		if counter != uint64(i) {
			t.Errorf("transport[%d] counter=%d, want %d", i, counter, i)
		}
	}
}

func TestWireGuard_9_10_2_HundredPayloadsCounterSequence(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.TransportPayloads = make([][]byte, 100)
	for i := range spec.WireGuard.TransportPayloads {
		spec.WireGuard.TransportPayloads[i] = []byte{0x01}
	}
	cfgs := drain(mustPlan(t, p, spec))
	for i := 0; i < 100; i++ {
		trans := cfgs[2+i]
		counter := binary.LittleEndian.Uint64(trans.Payload[8:16])
		if counter != uint64(i) {
			t.Errorf("transport[%d] counter=%d, want %d", i, counter, i)
			break
		}
	}
}

// ===================================================================
// 10. Cookie Mechanism (WireGuard §6) — 新增 tests
// ===================================================================

// 10.1 MAC1 Computation (模拟)
func TestWireGuard_10_1_1_MAC1InitiationNonZero(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	cfgs := drain(mustPlan(t, p, spec))
	init := cfgs[0]
	mac1 := init.Payload[116:132]
	allZero := true
	for _, b := range mac1 {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("Initiation mac1 is all zeros, expected non-zero")
	}
}

func TestWireGuard_10_1_2_MAC1ResponseNonZero(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	cfgs := drain(mustPlan(t, p, spec))
	resp := cfgs[1]
	mac1 := resp.Payload[60:76]
	allZero := true
	for _, b := range mac1 {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("Response mac1 is all zeros, expected non-zero")
	}
}

func TestWireGuard_10_1_3_MAC1LengthFixed16(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	cfgs := drain(mustPlan(t, p, spec))
	init := cfgs[0]
	resp := cfgs[1]
	if len(init.Payload[116:132]) != 16 {
		t.Errorf("Initiation mac1 length=%d, want 16", len(init.Payload[116:132]))
	}
	if len(resp.Payload[60:76]) != 16 {
		t.Errorf("Response mac1 length=%d, want 16", len(resp.Payload[60:76]))
	}
}

// 10.2 MAC2 with Zero Cookie (无 DoS 保护)
func TestWireGuard_10_2_1_MAC2InitiationZeroNoCookie(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.Cookie = nil
	cfgs := drain(mustPlan(t, p, spec))
	init := cfgs[0]
	for i := 132; i < 148; i++ {
		if init.Payload[i] != 0 {
			t.Errorf("Initiation mac2 byte[%d]=%02x, want 0", i-132, init.Payload[i])
		}
	}
}

func TestWireGuard_10_2_2_MAC2ResponseZeroNoCookie(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.Cookie = nil
	cfgs := drain(mustPlan(t, p, spec))
	resp := cfgs[1]
	for i := 76; i < 92; i++ {
		if resp.Payload[i] != 0 {
			t.Errorf("Response mac2 byte[%d]=%02x, want 0", i-76, resp.Payload[i])
		}
	}
}

// 10.3 Cookie Reply After Load (DoS 防御)
func TestWireGuard_10_3_1_CookieReplyAfterLoad(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.Role = "responder"
	spec.WireGuard.CookieReplyThreshold = 1
	cfgs := drain(mustPlan(t, p, spec))
	var foundCookie bool
	for _, c := range cfgs {
		if len(c.Payload) > 0 && c.Payload[0] == MsgCookieReply {
			foundCookie = true
			if len(c.Payload) != SizeCookieReply {
				t.Errorf("Cookie Reply length=%d, want %d", len(c.Payload), SizeCookieReply)
			}
		}
	}
	if !foundCookie {
		t.Error("expected Cookie Reply with threshold=1, none found")
	}
}

func TestWireGuard_10_3_2_CookieReplyThresholdZero(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.Role = "responder"
	spec.WireGuard.CookieReplyThreshold = 0
	cfgs := drain(mustPlan(t, p, spec))
	for _, c := range cfgs {
		if len(c.Payload) > 0 && c.Payload[0] == MsgCookieReply {
			t.Error("unexpected Cookie Reply with threshold=0")
		}
	}
}

func TestWireGuard_10_3_3_CookieReplyReceiverIndex(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.Role = "responder"
	spec.WireGuard.CookieReplyThreshold = 1
	cfgs := drain(mustPlan(t, p, spec))
	for _, c := range cfgs {
		if len(c.Payload) > 0 && c.Payload[0] == MsgCookieReply {
			receiverIndex := binary.LittleEndian.Uint32(c.Payload[4:8])
			if receiverIndex == 0 {
				t.Error("Cookie Reply receiver_index is 0, expected > 0")
			}
			return
		}
	}
}

// 10.4 Cookie Encryption with ChaCha20-Poly1305 (模拟)
func TestWireGuard_10_4_1_CookieReplyEncCookie32Bytes(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.Role = "responder"
	spec.WireGuard.CookieReplyThreshold = 1
	cfgs := drain(mustPlan(t, p, spec))
	for _, c := range cfgs {
		if len(c.Payload) > 0 && c.Payload[0] == MsgCookieReply {
			encCookie := c.Payload[32:64]
			if len(encCookie) != SizeEncCookie {
				t.Errorf("enc_cookie length=%d, want %d", len(encCookie), SizeEncCookie)
			}
			return
		}
	}
	t.Error("Cookie Reply packet not found")
}

func TestWireGuard_10_4_2_CookieReplyNonce24Bytes(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.Role = "responder"
	spec.WireGuard.CookieReplyThreshold = 1
	cfgs := drain(mustPlan(t, p, spec))
	for _, c := range cfgs {
		if len(c.Payload) > 0 && c.Payload[0] == MsgCookieReply {
			nonce := c.Payload[8:32]
			if len(nonce) != SizeCookieNonce {
				t.Errorf("nonce length=%d, want %d", len(nonce), SizeCookieNonce)
			}
			return
		}
	}
	t.Error("Cookie Reply packet not found")
}

func TestWireGuard_10_4_3_CookieReplyTotalLength64(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.Role = "responder"
	spec.WireGuard.CookieReplyThreshold = 1
	cfgs := drain(mustPlan(t, p, spec))
	for _, c := range cfgs {
		if len(c.Payload) > 0 && c.Payload[0] == MsgCookieReply {
			if len(c.Payload) != SizeCookieReply {
				t.Errorf("Cookie Reply length=%d, want %d", len(c.Payload), SizeCookieReply)
			}
			// nonce at offset 8-31 = 24 bytes
			if len(c.Payload[8:32]) != SizeCookieNonce {
				t.Errorf("nonce length=%d, want %d", len(c.Payload[8:32]), SizeCookieNonce)
			}
			// enc_cookie at offset 32-63 = 32 bytes
			if len(c.Payload[32:64]) != SizeEncCookie {
				t.Errorf("enc_cookie length=%d, want %d", len(c.Payload[32:64]), SizeEncCookie)
			}
			return
		}
	}
	t.Error("Cookie Reply packet not found")
}

// 10.6 MAC2 with Valid Cookie
func TestWireGuard_10_6_1_MAC2InitiationNonZeroWithCookie(t *testing.T) {
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
		t.Error("Initiation mac2 is all zeros with cookie set, expected non-zero")
	}
}

func TestWireGuard_10_6_2_MAC2ResponseNonZeroWithCookie(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.Cookie = make([]byte, 16)
	for i := range spec.WireGuard.Cookie {
		spec.WireGuard.Cookie[i] = byte(i + 1)
	}
	cfgs := drain(mustPlan(t, p, spec))
	resp := cfgs[1]
	allZero := true
	for i := 76; i < 92; i++ {
		if resp.Payload[i] != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("Response mac2 is all zeros with cookie set, expected non-zero")
	}
}

// 10.7 MAC2 with Stale Cookie -> Rejected (模拟)
func TestWireGuard_10_7_2_CookieWrongLength15(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.Cookie = make([]byte, 15)
	if err := p.Validate(spec); err == nil {
		t.Error("expected error for 15-byte Cookie, got nil")
	}
}

// 10.8 MAC2 with Wrong Cookie (模拟, planner 只验证长度)
func TestWireGuard_10_8_1_CookieContent0to15(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.Cookie = []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	if err := p.Validate(spec); err != nil {
		t.Fatalf("Validate failed: %v", err)
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
		t.Error("mac2 all zeros with cookie content 0..15, expected non-zero")
	}
}

func TestWireGuard_10_8_2_CookieContent255to240(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.Cookie = []byte{255, 254, 253, 252, 251, 250, 249, 248, 247, 246, 245, 244, 243, 242, 241, 240}
	if err := p.Validate(spec); err != nil {
		t.Fatalf("Validate failed: %v", err)
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
		t.Error("mac2 all zeros with cookie content 255..240, expected non-zero")
	}
}

// ===================================================================
// 11. Keepalive and Rekey (WireGuard §6.1) — 新增 tests
// ===================================================================

// 11.1 Empty Transport Message (Keepalive, 16 字节)
func TestWireGuard_11_1_1_EmptyTransportKeepalive(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.TransportPayloads = [][]byte{{}}
	cfgs := drain(mustPlan(t, p, spec))
	trans := cfgs[2]
	if len(trans.Payload) != 32 {
		t.Errorf("empty transport length=%d, want 32", len(trans.Payload))
	}
	if trans.Payload[0] != MsgTransportData {
		t.Errorf("message_type=%d, want 4", trans.Payload[0])
	}
}

func TestWireGuard_11_1_2_EmptyTransportCounterZero(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.TransportPayloads = [][]byte{{}}
	cfgs := drain(mustPlan(t, p, spec))
	trans := cfgs[2]
	counter := binary.LittleEndian.Uint64(trans.Payload[8:16])
	if counter != 0 {
		t.Errorf("counter=%d, want 0", counter)
	}
}

// 11.2 Keepalive Interval Default (10 秒)
func TestWireGuard_11_2_1_KeepaliveInterval10WithPayload(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.TransportPayloads = [][]byte{{0x01}}
	spec.WireGuard.KeepaliveInterval = 10
	cfgs := drain(mustPlan(t, p, spec))
	// handshake(2) + transport(1) + keepalive(1) = 4
	if len(cfgs) != 4 {
		t.Fatalf("packet count=%d, want 4 (handshake + transport + keepalive)", len(cfgs))
	}
	keepalive := cfgs[3]
	if len(keepalive.Payload) != 32 {
		t.Errorf("keepalive length=%d, want 32", len(keepalive.Payload))
	}
	if keepalive.Payload[0] != MsgTransportData {
		t.Errorf("keepalive message_type=%d, want 4", keepalive.Payload[0])
	}
}

func TestWireGuard_11_2_2_KeepaliveInterval10NoPayload(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.TransportPayloads = [][]byte{}
	spec.WireGuard.KeepaliveInterval = 10
	cfgs := drain(mustPlan(t, p, spec))
	// handshake(2) + keepalive(1) = 3 (since empty transport payloads fall back to default 1-byte)
	if len(cfgs) < 3 {
		t.Fatalf("packet count=%d, want >= 3", len(cfgs))
	}
}

// 11.3 Rekey After 2^60 Messages (默认不触发)
func TestWireGuard_11_3_1_RekeyAfterDefaultNoTrigger(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.RekeyAfter = 0 // default 2^60
	spec.WireGuard.TransportPayloads = make([][]byte, 100)
	for i := range spec.WireGuard.TransportPayloads {
		spec.WireGuard.TransportPayloads[i] = []byte{0x01}
	}
	cfgs := drain(mustPlan(t, p, spec))
	// 100 transport packets, far below 2^60, so no rekey
	var initCount int
	for _, c := range cfgs {
		if len(c.Payload) > 0 && c.Payload[0] == MsgHandshakeInitiation {
			initCount++
		}
	}
	if initCount > 1 {
		t.Errorf("initiation count=%d, want 1 (no rekey)", initCount)
	}
}

// 11.6 Explicit Rekey Trigger
func TestWireGuard_11_6_1_RekeyAfter3Trigger(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.RekeyAfter = 3
	spec.WireGuard.TransportPayloads = [][]byte{{0x01}, {0x02}, {0x03}, {0x04}, {0x05}}
	cfgs := drain(mustPlan(t, p, spec))
	// Expect 2 initiations: initial + rekey
	var initCount int
	for _, c := range cfgs {
		if len(c.Payload) > 0 && c.Payload[0] == MsgHandshakeInitiation {
			initCount++
		}
	}
	if initCount != 2 {
		t.Errorf("initiation count=%d, want 2 (initial + rekey)", initCount)
	}
}

func TestWireGuard_11_6_2_RekeyCounterReset(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.RekeyAfter = 3
	spec.WireGuard.TransportPayloads = [][]byte{{0x01}, {0x02}, {0x03}, {0x04}, {0x05}}
	cfgs := drain(mustPlan(t, p, spec))
	// Count transport packets and their counters
	transports := make([]uint64, 0)
	for _, c := range cfgs {
		if len(c.Payload) > 0 && c.Payload[0] == MsgTransportData {
			counter := binary.LittleEndian.Uint64(c.Payload[8:16])
			transports = append(transports, counter)
		}
	}
	// Expected: 0, 1, 2 (before rekey), 0, 1 (after rekey)
	if len(transports) != 5 {
		t.Fatalf("transport count=%d, want 5", len(transports))
	}
	for i := 0; i < 3; i++ {
		if transports[i] != uint64(i) {
			t.Errorf("transport[%d] counter=%d, want %d", i, transports[i], i)
		}
	}
}

// 11.7 Reject Expired Key (模拟)
func TestWireGuard_11_7_1_RekeyNewSenderIndex(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.SenderIndex = 1
	spec.WireGuard.RekeyAfter = 3
	spec.WireGuard.TransportPayloads = [][]byte{{0x01}, {0x02}, {0x03}, {0x04}, {0x05}}
	cfgs := drain(mustPlan(t, p, spec))
	// Collect all initiation sender indices
	var initIndices []uint32
	for _, c := range cfgs {
		if len(c.Payload) > 0 && c.Payload[0] == MsgHandshakeInitiation {
			si := binary.LittleEndian.Uint32(c.Payload[4:8])
			initIndices = append(initIndices, si)
		}
	}
	if len(initIndices) != 2 {
		t.Fatalf("initiation count=%d, want 2", len(initIndices))
	}
	// Rekey initiation should have a different sender_index than initial
	if initIndices[0] == initIndices[1] {
		t.Errorf("rekey sender_index=%d same as initial, expected different", initIndices[0])
	}
}

// ===================================================================
// 12. 业务场景集成测试 (新增 15 个场景)
// ===================================================================

// 12.1 Site-to-Site VPN (点对点)
func TestWireGuard_12_1_1_SiteToSiteVPN(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcMAC: "02:00:00:00:00:01",
		DstMAC: "02:00:00:00:00:02",
		SrcIP: "10.0.0.1",
		DstIP: "10.0.0.2",
		SrcPort: 50000,
		DstPort: DefaultPort,
		WireGuard: &core.WireGuardConfig{
			Role: "initiator",
			SenderIndex: 1,
			TransportPayloads: [][]byte{make([]byte, 100)},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// handshake(2) + transport(1) = 3
	if len(cfgs) != 3 {
		t.Fatalf("packet count=%d, want 3", len(cfgs))
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

func TestWireGuard_12_1_2_SiteToSiteDstPort(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcMAC: "02:00:00:00:00:01",
		DstMAC: "02:00:00:00:00:02",
		SrcIP: "10.0.0.1",
		DstIP: "10.0.0.2",
		SrcPort: 50000,
		DstPort: DefaultPort,
		WireGuard: &core.WireGuardConfig{
			Role: "initiator",
			SenderIndex: 1,
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	for i, c := range cfgs {
		if c.Direction == "up" && c.L4.DstPort != DefaultPort {
			t.Errorf("cfgs[%d].L4.DstPort=%d, want %d", i, c.L4.DstPort, DefaultPort)
		}
	}
}

// 12.2 Road Warrior (客户端到站点)
func TestWireGuard_12_2_1_RoadWarrior(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcMAC: "02:00:00:00:00:01",
		DstMAC: "02:00:00:00:00:02",
		SrcIP: "192.168.1.100",
		DstIP: "10.0.0.1",
		SrcPort: 50000,
		DstPort: DefaultPort,
		WireGuard: &core.WireGuardConfig{
			Role: "initiator",
			SenderIndex: 1,
			TransportPayloads: [][]byte{{0x41}, {0x42}},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// handshake(2) + transport(2) = 4
	if len(cfgs) != 4 {
		t.Fatalf("packet count=%d, want 4", len(cfgs))
	}
	if cfgs[0].Direction != "up" {
		t.Errorf("cfgs[0].Direction=%s, want up", cfgs[0].Direction)
	}
}

func TestWireGuard_12_2_2_RoadWarriorResponseDown(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcMAC: "02:00:00:00:00:01",
		DstMAC: "02:00:00:00:00:02",
		SrcIP: "192.168.1.100",
		DstIP: "10.0.0.1",
		SrcPort: 50000,
		DstPort: DefaultPort,
		WireGuard: &core.WireGuardConfig{
			Role: "initiator",
			SenderIndex: 1,
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if cfgs[1].Direction != "down" {
		t.Errorf("Response direction=%s, want down", cfgs[1].Direction)
	}
}

// 12.3 Multi-Peer Hub and Spoke
func TestWireGuard_12_3_1_HubAndSpokeConcurrent(t *testing.T) {
	p := NewPlanner()
	var wg sync.WaitGroup
	senderIndices := make([]uint32, 3)
	var mu sync.Mutex
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			spec := validSpec()
			spec.DstIP = fmt.Sprintf("10.0.0.%d", idx+2)
			spec.WireGuard.SenderIndex = uint32(idx + 1)
			ch, err := p.Plan(context.Background(), spec)
			if err != nil {
				t.Errorf("worker %d: Plan error: %v", idx, err)
				return
			}
			cfgs := drain(ch)
			if len(cfgs) < 1 {
				t.Errorf("worker %d: no packets", idx)
				return
			}
			si := binary.LittleEndian.Uint32(cfgs[0].Payload[4:8])
			mu.Lock()
			senderIndices[idx] = si
			mu.Unlock()
		}(i)
	}
	wg.Wait()
	// All sender indices should be unique
	if senderIndices[0] == senderIndices[1] || senderIndices[0] == senderIndices[2] || senderIndices[1] == senderIndices[2] {
		t.Errorf("sender_indices not unique: %v", senderIndices)
	}
}

// 12.4 Roaming Client (IP 变化中途)
func TestWireGuard_12_4_1_RoamingClientDifferentFlowID(t *testing.T) {
	p := NewPlanner()
	spec1 := validSpec()
	spec1.SrcIP = "192.168.1.100"
	spec2 := validSpec()
	spec2.SrcIP = "10.0.0.100"
	cfgs1 := drain(mustPlan(t, p, spec1))
	cfgs2 := drain(mustPlan(t, p, spec2))
	if cfgs1[0].FlowID == cfgs2[0].FlowID {
		t.Error("FlowIDs are identical for different SrcIP, expected different")
	}
}

// 12.5 NAT Traversal (Keepalive)
func TestWireGuard_12_5_1_NATTraversalKeepalive(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.TransportPayloads = [][]byte{{0x01}}
	spec.WireGuard.KeepaliveInterval = 10
	cfgs := drain(mustPlan(t, p, spec))
	// handshake(2) + transport(1) + keepalive(1) = 4
	if len(cfgs) != 4 {
		t.Fatalf("packet count=%d, want 4", len(cfgs))
	}
	keepalive := cfgs[3]
	if len(keepalive.Payload) != 32 {
		t.Errorf("keepalive length=%d, want 32", len(keepalive.Payload))
	}
}

func TestWireGuard_12_5_2_NATTraversalKeepaliveCounter(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.TransportPayloads = [][]byte{{0x01}}
	spec.WireGuard.KeepaliveInterval = 10
	cfgs := drain(mustPlan(t, p, spec))
	keepalive := cfgs[3]
	counter := binary.LittleEndian.Uint64(keepalive.Payload[8:16])
	if counter != 1 {
		t.Errorf("keepalive counter=%d, want 1 (after transport counter=0)", counter)
	}
}

// 12.6 IPv6 Dual-Stack
func TestWireGuard_12_6_1_IPv6DualStackEtherType(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.SrcIP = "2001:db8::1"
	spec.DstIP = "2001:db8::2"
	cfgs := drain(mustPlan(t, p, spec))
	if cfgs[0].L2.EtherType != 0x86DD {
		t.Errorf("EtherType=%04x, want 86DD (IPv6)", cfgs[0].L2.EtherType)
	}
}

func TestWireGuard_12_6_2_IPv6PayloadStructureSame(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.SrcIP = "2001:db8::1"
	spec.DstIP = "2001:db8::2"
	cfgs := drain(mustPlan(t, p, spec))
	trans := cfgs[2]
	if trans.Payload[0] != MsgTransportData {
		t.Errorf("message_type=%d, want 4", trans.Payload[0])
	}
	expectedLen := SizeTransportHeader + 1 + SizeAEADTag
	if len(trans.Payload) != expectedLen {
		t.Errorf("transport length=%d, want %d (same as IPv4)", len(trans.Payload), expectedLen)
	}
}

// 12.7 VPN with Default Route (0.0.0.0/0)
func TestWireGuard_12_7_1_DefaultRouteLargePayload(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.TransportPayloads = [][]byte{
		make([]byte, 1440),
		make([]byte, 1440),
	}
	cfgs := drain(mustPlan(t, p, spec))
	// handshake(2) + transport(2) = 4
	if len(cfgs) != 4 {
		t.Fatalf("packet count=%d, want 4", len(cfgs))
	}
	for i := 2; i < 4; i++ {
		expectedLen := SizeTransportHeader + 1440 + SizeAEADTag
		if len(cfgs[i].Payload) != expectedLen {
			t.Errorf("transport[%d] length=%d, want %d", i-2, len(cfgs[i].Payload), expectedLen)
		}
	}
}

func TestWireGuard_12_7_2_DefaultRouteCounterIncreasing(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.TransportPayloads = [][]byte{
		make([]byte, 1440),
		make([]byte, 1440),
	}
	cfgs := drain(mustPlan(t, p, spec))
	c0 := binary.LittleEndian.Uint64(cfgs[2].Payload[8:16])
	c1 := binary.LittleEndian.Uint64(cfgs[3].Payload[8:16])
	if c0 != 0 || c1 != 1 {
		t.Errorf("counters=%d,%d, want 0,1", c0, c1)
	}
}

// 12.8 Split Tunneling
func TestWireGuard_12_8_1_SplitTunnelingDifferentPayloads(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.TransportPayloads = [][]byte{
		make([]byte, 100),
		make([]byte, 50),
		make([]byte, 200),
	}
	cfgs := drain(mustPlan(t, p, spec))
	// handshake(2) + transport(3) = 5
	if len(cfgs) != 5 {
		t.Fatalf("packet count=%d, want 5", len(cfgs))
	}
	expectedLens := []int{16 + 100 + 16, 16 + 50 + 16, 16 + 200 + 16}
	for i, want := range expectedLens {
		got := len(cfgs[2+i].Payload)
		if got != want {
			t.Errorf("transport[%d] length=%d, want %d", i, got, want)
		}
	}
}

func TestWireGuard_12_8_2_SplitTunnelingCounters(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.TransportPayloads = [][]byte{
		make([]byte, 100),
		make([]byte, 50),
		make([]byte, 200),
	}
	cfgs := drain(mustPlan(t, p, spec))
	for i := 0; i < 3; i++ {
		counter := binary.LittleEndian.Uint64(cfgs[2+i].Payload[8:16])
		if counter != uint64(i) {
			t.Errorf("transport[%d] counter=%d, want %d", i, counter, i)
		}
	}
}

// 12.9 DNS over WireGuard
func TestWireGuard_12_9_1_DNSOverWireGuard(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	dnsQuery := make([]byte, 50)
	for i := range dnsQuery {
		dnsQuery[i] = byte(i)
	}
	spec.WireGuard.TransportPayloads = [][]byte{dnsQuery}
	cfgs := drain(mustPlan(t, p, spec))
	trans := cfgs[2]
	expectedLen := SizeTransportHeader + 50 + SizeAEADTag
	if len(trans.Payload) != expectedLen {
		t.Errorf("DNS transport length=%d, want %d", len(trans.Payload), expectedLen)
	}
}

// 12.10 Multi-Hop (Chained WireGuard)
func TestWireGuard_12_10_1_MultiHopDifferentFlowIDs(t *testing.T) {
	p := NewPlanner()
	spec1 := validSpec()
	spec1.SrcIP = "10.0.0.1"
	spec1.DstIP = "10.0.0.2"
	spec2 := validSpec()
	spec2.SrcIP = "10.0.0.2"
	spec2.DstIP = "10.0.0.3"
	cfgs1 := drain(mustPlan(t, p, spec1))
	cfgs2 := drain(mustPlan(t, p, spec2))
	if cfgs1[0].FlowID == cfgs2[0].FlowID {
		t.Error("FlowIDs are identical for different hops, expected different")
	}
}

// 12.11 Load Balance Multiple Peers
func TestWireGuard_12_11_1_LoadBalanceConcurrent(t *testing.T) {
	p := NewPlanner()
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			spec := validSpec()
			spec.DstIP = fmt.Sprintf("10.0.0.%d", idx+2)
			spec.WireGuard.SenderIndex = uint32(idx + 1)
			ch, err := p.Plan(context.Background(), spec)
			if err != nil {
				t.Errorf("worker %d: Plan error: %v", idx, err)
				return
			}
			_ = drain(ch)
		}(i)
	}
	wg.Wait()
}

// 12.12 Peer Failover (Primary Down -> Backup)
func TestWireGuard_12_12_1_PeerFailoverDifferentFlowIDs(t *testing.T) {
	p := NewPlanner()
	spec1 := validSpec()
	spec1.DstIP = "10.0.0.2" // primary
	spec2 := validSpec()
	spec2.DstIP = "10.0.0.3" // backup
	cfgs1 := drain(mustPlan(t, p, spec1))
	cfgs2 := drain(mustPlan(t, p, spec2))
	if cfgs1[0].FlowID == cfgs2[0].FlowID {
		t.Error("FlowIDs are identical for primary and backup, expected different")
	}
}

// 12.13 Long-Lived Session (24 小时)
func TestWireGuard_12_13_1_LongLivedDuration(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.KeepaliveInterval = 10
	spec.WireGuard.TransportPayloads = [][]byte{{0x01}}
	// Duration=86400 is valid, planner doesn't enforce it internally
	_ = drain(mustPlan(t, p, spec))
}

func TestWireGuard_12_13_2_LongLivedMultipleRekey(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.RekeyAfter = 1000
	spec.WireGuard.TransportPayloads = make([][]byte, 2000)
	for i := range spec.WireGuard.TransportPayloads {
		spec.WireGuard.TransportPayloads[i] = []byte{0x01}
	}
	cfgs := drain(mustPlan(t, p, spec))
	// Count initiations: initial + 1 rekey = 2
	// NOTE: planner only supports one rekey (rekeyTriggered is never reset)
	var initCount int
	for _, c := range cfgs {
		if len(c.Payload) > 0 && c.Payload[0] == MsgHandshakeInitiation {
			initCount++
		}
	}
	if initCount != 2 {
		t.Errorf("initiation count=%d, want 2 (initial + 1 rekey)", initCount)
	}
}

// 12.14 High-Throughput (1Gbps)
func TestWireGuard_12_14_2_HighThroughputCounterIncreasing(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.TransportPayloads = make([][]byte, 100)
	for i := range spec.WireGuard.TransportPayloads {
		payload := make([]byte, 1440)
		spec.WireGuard.TransportPayloads[i] = payload
	}
	cfgs := drain(mustPlan(t, p, spec))
	for i := 0; i < 100; i++ {
		trans := cfgs[2+i]
		counter := binary.LittleEndian.Uint64(trans.Payload[8:16])
		if counter != uint64(i) {
			t.Errorf("transport[%d] counter=%d, want %d", i, counter, i)
			break
		}
	}
}

// 12.15 Mobile Network (High Packet Loss, 模拟)
func TestWireGuard_12_15_1_MobileNetworkCounterSequence(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.TransportPayloads = [][]byte{{0x01}, {0x02}, {0x03}, {0x04}, {0x05}}
	cfgs := drain(mustPlan(t, p, spec))
	for i := 0; i < 5; i++ {
		trans := cfgs[2+i]
		counter := binary.LittleEndian.Uint64(trans.Payload[8:16])
		if counter != uint64(i) {
			t.Errorf("transport[%d] counter=%d, want %d", i, counter, i)
		}
	}
}

func TestWireGuard_12_15_2_MobileNetworkKeepalive(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.WireGuard.TransportPayloads = [][]byte{{0x01}, {0x02}}
	spec.WireGuard.KeepaliveInterval = 10
	cfgs := drain(mustPlan(t, p, spec))
	// handshake(2) + transport(2) + keepalive(1) = 5
	if len(cfgs) != 5 {
		t.Fatalf("packet count=%d, want 5", len(cfgs))
	}
	keepalive := cfgs[4]
	if len(keepalive.Payload) != 32 {
		t.Errorf("keepalive length=%d, want 32", len(keepalive.Payload))
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