// Package openvpn implements the OpenVPN protocol planner.
//
// This file contains failing tests for the 5 confirmed CRITICAL code-review
// findings (F1-F5). Each test asserts the CORRECT spec behavior per
// design_openvpn.md, fails against the buggy code, and passes after the fix.
package openvpn

import (
	"context"
	"testing"
)

// F1 — V1/V3 control-channel code paths are dead code.
// The Plan() function always emits V2 opcodes (4/5) regardless of cfg.Version.
// Per design §2.2.1, §2.2.6, version "1" must emit opcode 1/2 (no session_id,
// 4-byte BE packet_id) and version "3" must emit opcode 6 for the client reset.

func TestF1_V1VersionEmitsV1Opcodes(t *testing.T) {
	spec := defaultOpenVPNSpec()
	spec.OpenVPN.Version = "1"
	spec.OpenVPN.DataPacketCount = 1
	planner := NewPlanner()
	ctx := context.Background()

	configChan, err := planner.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan failed: %v", err)
	}
	packets := collectPackets(ctx, t, configChan)

	if len(packets) < 2 {
		t.Fatalf("expected at least 2 packets, got %d", len(packets))
	}

	// Packet 0: HARD_RESET_CLIENT_V1 (opcode=1, key_id=0) = (1<<5)|0 = 0x20
	if packets[0].Payload[0] != 0x20 {
		t.Errorf("V1 client reset first byte: expected 0x20 (opcode=1), got 0x%02X", packets[0].Payload[0])
	}

	// Packet 1: HARD_RESET_SERVER_V1 (opcode=2, key_id=0) = (2<<5)|0 = 0x40
	if packets[1].Payload[0] != 0x40 {
		t.Errorf("V1 server reset first byte: expected 0x40 (opcode=2), got 0x%02X", packets[1].Payload[0])
	}

	// V1 has NO session_id. Format: opcode(1B) + packet_id(4B BE) + payload.
	// So bytes 1-4 are packet_id (0x00000000 for first packet).
	if len(packets[0].Payload) < 5 {
		t.Fatalf("V1 client reset too short: %d bytes", len(packets[0].Payload))
	}
	if packets[0].Payload[1] != 0x00 || packets[0].Payload[2] != 0x00 ||
		packets[0].Payload[3] != 0x00 || packets[0].Payload[4] != 0x00 {
		t.Errorf("V1 client reset: expected packet_id=0x00000000 at bytes 1-4, got %02X %02X %02X %02X",
			packets[0].Payload[1], packets[0].Payload[2], packets[0].Payload[3], packets[0].Payload[4])
	}

	// V1 data packets should use P_DATA_V1 (opcode=7 = 0xE0), not P_DATA_V2 (0x40).
	if len(packets) < 4 {
		t.Fatalf("expected at least 4 packets (2 control + 2 data), got %d", len(packets))
	}
	if packets[2].Payload[0]&0xE0 != 0xE0 {
		t.Errorf("V1 data packet: expected P_DATA_V1 (opcode=7, high 3 bits=111), got 0x%02X", packets[2].Payload[0])
	}
}

func TestF1_V3VersionEmitsV3ClientOpcode(t *testing.T) {
	spec := defaultOpenVPNSpec()
	spec.OpenVPN.Version = "3"
	spec.OpenVPN.KeyID = 2
	spec.OpenVPN.DataPacketCount = 1
	planner := NewPlanner()
	ctx := context.Background()

	configChan, err := planner.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan failed: %v", err)
	}
	packets := collectPackets(ctx, t, configChan)

	if len(packets) < 2 {
		t.Fatalf("expected at least 2 packets, got %d", len(packets))
	}

	// Packet 0: HARD_RESET_CLIENT_V3 (opcode=6, key_id=2) = (6<<5)|2 = 0xC2
	if packets[0].Payload[0] != 0xC2 {
		t.Errorf("V3 client reset first byte: expected 0xC2 (opcode=6, key_id=2), got 0x%02X", packets[0].Payload[0])
	}

	// V3 server still uses V2 opcode=5 (no V3 server opcode per design §2.1).
	// (5<<5)|2 = 0xA2
	if packets[1].Payload[0] != 0xA2 {
		t.Errorf("V3 server reset first byte: expected 0xA2 (opcode=5, key_id=2), got 0x%02X", packets[1].Payload[0])
	}

	// V3 has session_id (3 bytes) after opcode, like V2.
	// bytes 1-3 = session_id
	if len(packets[0].Payload) < 4 {
		t.Fatalf("V3 client reset too short: %d bytes", len(packets[0].Payload))
	}
	// session_id should be non-zero (random or configured) — just check it's present
	_ = packets[0].Payload[1:4]
}

// F2 — tls-crypt-v2 field order wrong.
// Per design §2.5.1: length_prefix(2B) comes BEFORE wrapped_key_id(4B).
// Current code emits wrapped_key_id first, then length_prefix.

func TestF2_TLSCryptV2FieldOrder(t *testing.T) {
	// Per design §2.5.1 byte example:
	// 0x00 0x50                          (2B length prefix = 80)
	// 0x00 0x00 0x00 0x01                 (4B wrapped_key_id = 1)
	// [32B auth-tag]
	// [16B IV]
	// [32B cipher_key]
	wrappedKey := buildWrappedKey(true)

	// Total: 2 + 4 + 32 + 16 + 32 = 86
	if len(wrappedKey) != 86 {
		t.Fatalf("tls-crypt-v2 wrapped key: expected 86 bytes, got %d", len(wrappedKey))
	}

	// Length prefix at offset 0: 0x00 0x50 (80)
	if wrappedKey[0] != 0x00 || wrappedKey[1] != 0x50 {
		t.Errorf("length prefix: expected 0x0050 at offset 0, got 0x%02X%02X",
			wrappedKey[0], wrappedKey[1])
	}

	// wrapped_key_id at offset 2: 0x00 0x00 0x00 0x01
	if wrappedKey[2] != 0x00 || wrappedKey[3] != 0x00 ||
		wrappedKey[4] != 0x00 || wrappedKey[5] != 0x01 {
		t.Errorf("wrapped_key_id: expected 0x00000001 at offset 2, got 0x%02X%02X%02X%02X",
			wrappedKey[2], wrappedKey[3], wrappedKey[4], wrappedKey[5])
	}

	// auth-tag at offset 6: 0xBB filler (32 bytes)
	for i := 6; i < 6+32; i++ {
		if wrappedKey[i] != 0xBB {
			t.Errorf("auth-tag byte %d: expected 0xBB, got 0x%02X", i, wrappedKey[i])
			break
		}
	}

	// IV at offset 38: 0xCC filler (16 bytes)
	for i := 38; i < 38+16; i++ {
		if wrappedKey[i] != 0xCC {
			t.Errorf("IV byte %d: expected 0xCC, got 0x%02X", i, wrappedKey[i])
			break
		}
	}
}

// F3 — static-key format wrong.
// Per design §2.10.2 + §6.3: P_DATA_V1 in static key mode should contain
// StaticKeyNonce(16B) + StaticKeyCiphertext(NB) + StaticKeyHMAC(20B).
// Current code builds these variables but never uses them (dead code),
// instead calling buildDataV1 which produces the generic encrypted payload format.

func TestF3_StaticKeyFormat(t *testing.T) {
	spec := defaultOpenVPNSpec()
	spec.OpenVPN.StaticKeyMode = true
	spec.OpenVPN.DataPacketCount = 1
	spec.OpenVPN.DataPayload = make([]byte, 64)
	for i := range spec.OpenVPN.DataPayload {
		spec.OpenVPN.DataPayload[i] = 0xAB
	}
	planner := NewPlanner()
	ctx := context.Background()

	configChan, err := planner.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan failed: %v", err)
	}
	packets := collectPackets(ctx, t, configChan)

	if len(packets) < 1 {
		t.Fatal("no packets")
	}

	pkt := packets[0].Payload
	// P_DATA_V1: opcode+key_id(1B) + packet_id(4B BE) + nonce(16B) + ciphertext(N) + HMAC(20B)
	// opcode = (7<<5)|0 = 0xE0
	if pkt[0] != 0xE0 {
		t.Errorf("expected P_DATA_V1 opcode 0xE0, got 0x%02X", pkt[0])
	}

	// packet_id at bytes 1-4 (4-byte BE)
	// nonce at bytes 5-20 (16 bytes, 0xCC filler per design §2.10.2)
	nonceStart := 5
	if len(pkt) < nonceStart+16 {
		t.Fatalf("packet too short for nonce: %d bytes", len(pkt))
	}
	for i := nonceStart; i < nonceStart+16; i++ {
		if pkt[i] != 0xCC {
			t.Errorf("nonce byte %d: expected 0xCC, got 0x%02X", i, pkt[i])
			break
		}
	}

	// ciphertext after nonce: 64 bytes of 0xDD filler (per design §2.10.2)
	cipherStart := nonceStart + 16
	if len(pkt) < cipherStart+64 {
		t.Fatalf("packet too short for ciphertext: %d bytes, need %d", len(pkt), cipherStart+64)
	}
	for i := cipherStart; i < cipherStart+64; i++ {
		if pkt[i] != 0xDD {
			t.Errorf("ciphertext byte %d: expected 0xDD, got 0x%02X", i, pkt[i])
			break
		}
	}

	// HMAC at end: 20 bytes of 0xAA filler (per design §2.10.2)
	hmacStart := cipherStart + 64
	if len(pkt) < hmacStart+20 {
		t.Fatalf("packet too short for HMAC: %d bytes, need %d", len(pkt), hmacStart+20)
	}
	for i := hmacStart; i < hmacStart+20; i++ {
		if pkt[i] != 0xAA {
			t.Errorf("HMAC byte %d: expected 0xAA, got 0x%02X", i, pkt[i])
			break
		}
	}

	// Total: 1(opcode) + 4(packet_id) + 16(nonce) + 64(ciphertext) + 20(HMAC) = 105
	expectedLen := 1 + 4 + 16 + 64 + 20
	if len(pkt) != expectedLen {
		t.Errorf("static key P_DATA_V1 length: expected %d, got %d", expectedLen, len(pkt))
	}
}

// F4 — ExitNotify emits bare 0x05.
// Per design §2.10.5: exit_notify should be a P_CONTROL message carrying
// 1-byte type=0x05, not a bare 0x05 byte. The current code emits []byte{0x05}
// as the entire UDP payload with no OpenVPN header.

func TestF4_ExitNotifyFraming(t *testing.T) {
	spec := defaultOpenVPNSpec()
	spec.OpenVPN.ExitNotifyCount = 1
	spec.OpenVPN.DataPacketCount = 1
	spec.OpenVPN.SessionID = 0xAABBCC
	planner := NewPlanner()
	ctx := context.Background()

	configChan, err := planner.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan failed: %v", err)
	}
	packets := collectPackets(ctx, t, configChan)

	if len(packets) < 5 {
		t.Fatalf("expected at least 5 packets, got %d", len(packets))
	}

	exitPkt := packets[len(packets)-1].Payload

	// Must NOT be a bare 0x05 — must be a framed P_CONTROL message.
	if len(exitPkt) == 1 && exitPkt[0] == 0x05 {
		t.Fatal("exit_notify emits bare 0x05 — expected framed P_CONTROL message with opcode header")
	}

	// Should start with a valid P_CONTROL opcode in the high 3 bits (1-6).
	firstByte := exitPkt[0]
	opcode := firstByte >> 5
	if opcode < 1 || opcode > 6 {
		t.Errorf("exit_notify first byte: expected P_CONTROL opcode (1-6 in high 3 bits), got opcode=%d (0x%02X)", opcode, firstByte)
	}

	// The exit_notify type byte (0x05) must be present in the payload.
	found := false
	for _, b := range exitPkt {
		if b == 0x05 {
			found = true
			break
		}
	}
	if !found {
		t.Error("exit_notify payload: expected to contain 0x05 type byte")
	}

	// Must have more than 1 byte (at minimum: opcode + type).
	if len(exitPkt) < 2 {
		t.Errorf("exit_notify payload: expected at least 2 bytes (opcode + type), got %d", len(exitPkt))
	}
}

// F5 — TLS record length off-by-4.
// Per RFC 8446 §5.2 and design §2.8: TLS Record Length = length of fragment,
// which includes the 4-byte handshake header (1B type + 3B length) + body.
// Current code sets Length = len(body), missing the 4-byte handshake header.

func TestF5_TLSRecordLengthClientHello(t *testing.T) {
	ch := buildSynthClientHello("1.3")
	if len(ch) < 5 {
		t.Fatal("ClientHello too short")
	}

	// TLS Record: ContentType(1B) + Version(2B) + Length(2B) + fragment
	// Length field should equal the actual fragment length (everything after 5-byte header).
	recordLen := int(ch[3])<<8 | int(ch[4])
	fragmentLen := len(ch) - 5
	if recordLen != fragmentLen {
		t.Errorf("ClientHello TLS record length: expected %d (actual fragment length), got %d (off by %d)",
			fragmentLen, recordLen, fragmentLen-recordLen)
	}
}

func TestF5_TLSRecordLengthServerHello(t *testing.T) {
	sh := buildSynthServerHello("1.3")
	if len(sh) < 5 {
		t.Fatal("ServerHello too short")
	}

	recordLen := int(sh[3])<<8 | int(sh[4])
	fragmentLen := len(sh) - 5
	if recordLen != fragmentLen {
		t.Errorf("ServerHello TLS record length: expected %d (actual fragment length), got %d (off by %d)",
			fragmentLen, recordLen, fragmentLen-recordLen)
	}
}
