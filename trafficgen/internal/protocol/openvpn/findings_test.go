// Package openvpn implements the OpenVPN protocol planner.
//
// This file contains failing tests for the 5 confirmed CRITICAL code-review
// findings (F1-F5). Each test asserts the CORRECT spec behavior per
// design_openvpn.md, fails against the buggy code, and passes after the fix.
package openvpn

import (
	"context"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
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

	// Packet 0: HARD_RESET_CLIENT_V1 (opcode=1, key_id=0) = (1<<3)|0 = 0x08
	if packets[0].Payload[0] != 0x08 {
		t.Errorf("V1 client reset first byte: expected 0x08 (opcode=1), got 0x%02X", packets[0].Payload[0])
	}

	// Packet 1: HARD_RESET_SERVER_V1 (opcode=2, key_id=0) = (2<<3)|0 = 0x10
	if packets[1].Payload[0] != 0x10 {
		t.Errorf("V1 server reset first byte: expected 0x10 (opcode=2), got 0x%02X", packets[1].Payload[0])
	}

	// V1 control packets carry the 8-byte session_id (Wireshark parses
	// session_id for opcode 1). Format: opcode(1B) + session_id(8B) +
	// ack_count(1B) + message_packet_id(4B) + payload.
	// So bytes 1-8 are session_id, byte 9 is ack_count(0), bytes 10-13 are
	// message_packet_id(0x00000000 for first packet).
	if len(packets[0].Payload) < 14 {
		t.Fatalf("V1 client reset too short: %d bytes", len(packets[0].Payload))
	}
	if packets[0].Payload[9] != 0x00 {
		t.Errorf("V1 client reset ack_count: expected 0x00, got 0x%02X", packets[0].Payload[9])
	}
	if packets[0].Payload[10] != 0x00 || packets[0].Payload[11] != 0x00 ||
		packets[0].Payload[12] != 0x00 || packets[0].Payload[13] != 0x00 {
		t.Errorf("V1 client reset: expected message_packet_id=0x00000000 at bytes 10-13, got %02X %02X %02X %02X",
			packets[0].Payload[10], packets[0].Payload[11], packets[0].Payload[12], packets[0].Payload[13])
	}

	// V1 data packets should use P_DATA_V1 (opcode=6 = (6<<3)|0 = 0x30), not P_DATA_V2 (0x48).
	if len(packets) < 4 {
		t.Fatalf("expected at least 4 packets (2 control + 2 data), got %d", len(packets))
	}
	if packets[2].Payload[0]>>3 != OpcodeDATAV1 {
		t.Errorf("V1 data packet: expected P_DATA_V1 (opcode=6, high 5 bits=6), got 0x%02X", packets[2].Payload[0])
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

	// Packet 0: HARD_RESET_CLIENT_V3 (opcode=10, key_id=2) = (10<<3)|2 = 0x52
	if packets[0].Payload[0] != 0x52 {
		t.Errorf("V3 client reset first byte: expected 0x52 (opcode=10, key_id=2), got 0x%02X", packets[0].Payload[0])
	}

	// V3 server still uses V2 opcode=8 (no V3 server opcode per ssl_pkt.h).
	// (8<<3)|2 = 0x42
	if packets[1].Payload[0] != 0x42 {
		t.Errorf("V3 server reset first byte: expected 0x42 (opcode=8, key_id=2), got 0x%02X", packets[1].Payload[0])
	}

	// V3 has 8-byte session_id (SID_SIZE) after opcode, like V2.
	// bytes 1-8 = session_id
	if len(packets[0].Payload) < 9 {
		t.Fatalf("V3 client reset too short: %d bytes", len(packets[0].Payload))
	}
	// session_id should be non-zero (random or configured) — just check it's present
	_ = packets[0].Payload[1:9]
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
	// P_DATA_V1: opcode(1B) + payload. No packet_id parsed by Wireshark.
	// opcode = (6<<3)|0 = 0x30
	if pkt[0] != 0x30 {
		t.Errorf("expected P_DATA_V1 opcode 0x30, got 0x%02X", pkt[0])
	}

	// payload starts at byte 1: nonce(16B) + ciphertext(N) + HMAC(20B)
	// nonce at bytes 1-16 (16 bytes, 0xCC filler per design §2.10.2)
	nonceStart := 1
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

	// Total: 1(opcode) + 16(nonce) + 64(ciphertext) + 20(HMAC) = 101
	expectedLen := 1 + 16 + 64 + 20
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

// F6 — OpenVPN-over-TCP missing 2-byte big-endian length prefix.
// Per the real OpenVPN protocol (src/openvpn/mtu.c frame_link_mtu_set +
// forward.c), when running over TCP each OpenVPN packet is prefixed with a
// 2-byte big-endian length (the byte count of the following OpenVPN packet,
// excluding the prefix itself). This is the TCP stream framing — without it,
// the receiver/Wireshark cannot delimit individual OpenVPN packets on the TCP
// byte stream. UDP mode needs no prefix (datagrams are self-delimiting).
//
// Pre-fix: emitTCPData sends the raw OpenVPN packet bytes with no length
// prefix, so Wireshark's openvpn dissector cannot parse TCP-mode captures.
// This test fails against the buggy code (first payload byte is the opcode,
// not a length high byte) and passes after the fix.
func TestF6_TCPModeLengthPrefix(t *testing.T) {
	spec := defaultOpenVPNSpec()
	spec.UDP = nil
	spec.TCP = &core.TCPConfig{
		Handshake:   true,
		Termination: true,
		MSS:         1460,
	}
	spec.OpenVPN.Proto = "tcp"
	spec.OpenVPN.Version = "2"
	spec.OpenVPN.TLSVersion = "1.3"
	spec.OpenVPN.DataPacketCount = 1
	spec.OpenVPN.SessionID = 0xAABBCC

	planner := NewPlanner()
	ctx := context.Background()

	configChan, err := planner.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan failed: %v", err)
	}
	packets := collectPackets(ctx, t, configChan)

	// Find the first PSH-ACK data packet (TCP flags 0x18) in the up direction
	// — that carries the client HARD_RESET_CLIENT_V2 OpenVPN packet.
	var dataPayload []byte
	for _, p := range packets {
		if p.Direction == "up" && p.L4.Protocol == "tcp" && p.L4.Flags == 0x18 && len(p.Payload) > 0 {
			dataPayload = p.Payload
			break
		}
	}
	if dataPayload == nil {
		t.Fatal("no up-direction PSH-ACK data packet found")
	}
	if len(dataPayload) < 3 {
		t.Fatalf("data payload too short: %d bytes", len(dataPayload))
	}

	// The first 2 bytes must be the big-endian length of the OpenVPN packet
	// that follows (excluding the 2-byte prefix). For a single TCP segment
	// carrying one full OpenVPN packet, this equals len(payload)-2.
	declaredLen := int(dataPayload[0])<<8 | int(dataPayload[1])
	if declaredLen != len(dataPayload)-2 {
		t.Errorf("TCP length prefix: declared %d, want %d (len(payload)-2); "+
			"first bytes = %02X %02X %02X (no length prefix — raw opcode at byte 0)",
			declaredLen, len(dataPayload)-2, dataPayload[0], dataPayload[1], dataPayload[2])
	}

	// The byte after the prefix must be a valid V2 client reset opcode
	// (P_CONTROL_HARD_RESET_CLIENT_V2 = opcode 7, high 5 bits = 7 when
	// key_id=0 -> (7<<3)|0 = 0x38).
	opcodeByte := dataPayload[2]
	if opcodeByte>>POpcodeShift != OpcodeHARDResetClientV2 {
		t.Errorf("after length prefix: opcode=%d, want %d", opcodeByte>>POpcodeShift, OpcodeHARDResetClientV2)
	}
}

// TestF6_TCPModeLengthPrefix_NoPrefixInUDP confirms UDP mode does NOT get a
// length prefix — UDP datagrams are self-delimiting. This guards against an
// over-broad fix that prefixes both transports.
func TestF6_TCPModeLengthPrefix_NoPrefixInUDP(t *testing.T) {
	spec := defaultOpenVPNSpec() // UDP mode
	spec.OpenVPN.Version = "2"
	spec.OpenVPN.DataPacketCount = 1
	spec.OpenVPN.SessionID = 0xAABBCC

	planner := NewPlanner()
	ctx := context.Background()

	configChan, err := planner.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan failed: %v", err)
	}
	packets := collectPackets(ctx, t, configChan)

	// First up packet is the client HARD_RESET — in UDP it must start with
	// the opcode byte directly (no 2-byte length prefix). V2 client reset
	// = opcode 7 -> (7<<3)|0 = 0x38.
	for _, p := range packets {
		if p.Direction == "up" && p.L4.Protocol == "udp" && len(p.Payload) > 0 {
			opcodeByte := p.Payload[0]
			if opcodeByte>>POpcodeShift != OpcodeHARDResetClientV2 {
				t.Errorf("UDP mode: first byte should be V2 client reset opcode (7), got opcode=%d (0x%02X) (length prefix leaked into UDP?)", opcodeByte>>POpcodeShift, opcodeByte)
			}
			return
		}
	}
	t.Fatal("no up-direction UDP data packet found")
}

// F7 — Static-key (P2P 静态密钥) TCP mode missing the 2-byte big-endian
// length prefix.
//
// The F6 fix added the 2B BE length prefix to the *normal* TCP path by routing
// all control/data packets through emitTCPData. However the static-key branch
// (cfg.StaticKeyMode=true, Plan() ~line 503) still calls emitPacket directly,
// bypassing emitTCPData, so its P_DATA_V1 packets carry the raw opcode byte
// (0x30 = (P_DATA_V1=6)<<3) as the first TCP payload byte with no length
// prefix. Wireshark's openvpn dissector therefore cannot delimit the
// P_DATA_V1 packet on the TCP byte stream and reports no openvpn layer
// (Protocols in frame: ...:tcp only).
//
// Per the OpenVPN TCP framing spec (src/openvpn/mtu.c frame_link_mtu_set +
// forward.c), EVERY OpenVPN packet on a TCP connection — control OR data,
// normal OR static-key — is prefixed with a 2-byte big-endian length giving
// the byte count of the following OpenVPN packet (excluding the prefix). UDP
// static-key mode keeps no prefix (datagrams are self-delimiting).
//
// This test fails on the buggy code (first payload byte is 0x30, the raw
// P_DATA_V1 opcode) and passes after the static-key TCP path is routed
// through emitTCPData.

func TestF7_StaticKeyTCPModeLengthPrefix(t *testing.T) {
	spec := defaultOpenVPNSpec()
	spec.UDP = nil
	spec.TCP = &core.TCPConfig{
		Handshake:   true,
		Termination: true,
		MSS:         1460,
	}
	spec.OpenVPN.Proto = "tcp"
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

	// Collect every PSH-ACK (0x18) TCP data packet. In static-key TCP mode
	// these carry the P_DATA_V1 OpenVPN packets (both client->server "up"
	// and server->client "down"). Both directions must be length-prefixed.
	var dataPkts []core.PacketConfig
	for _, p := range packets {
		if p.L4.Protocol == "tcp" && p.L4.Flags == 0x18 && len(p.Payload) > 0 {
			dataPkts = append(dataPkts, p)
		}
	}
	if len(dataPkts) == 0 {
		t.Fatal("no PSH-ACK TCP data packets found in static-key TCP mode")
	}

	for idx, p := range dataPkts {
		payload := p.Payload
		if len(payload) < 3 {
			t.Fatalf("data pkt %d: payload too short (%d bytes)", idx, len(payload))
		}

		// Bytes 0-1: big-endian length of the OpenVPN packet that follows
		// (excluding the 2-byte prefix). For a single TCP segment carrying
		// one full OpenVPN packet this equals len(payload)-2.
		declaredLen := int(payload[0])<<8 | int(payload[1])
		if declaredLen != len(payload)-2 {
			t.Errorf("data pkt %d (dir=%s): TCP length prefix declared %d, want %d (len-2); "+
				"first bytes = %02X %02X %02X (raw opcode at byte 0 — no length prefix)",
				idx, p.Direction, declaredLen, len(payload)-2,
				payload[0], payload[1], payload[2])
			continue
		}

		// Byte 2 must be a valid P_DATA_V1 header byte: opcode 6 in the high
		// 5 bits -> (6<<3)|key_id = 0x30 when key_id=0. The byte must NOT be
		// the raw opcode at offset 0 (which is the bug signature).
		opcodeByte := payload[2]
		if opcodeByte>>POpcodeShift != OpcodeDATAV1 {
			t.Errorf("data pkt %d (dir=%s): after length prefix, opcode=%d, want P_DATA_V1 (%d); "+
				"byte[2]=0x%02X",
				idx, p.Direction, opcodeByte>>POpcodeShift, OpcodeDATAV1, opcodeByte)
		}
	}
}

// TestF7_StaticKeyUDPModeNoPrefix confirms static-key UDP mode does NOT get a
// length prefix — UDP datagrams are self-delimiting, and static-key mode is
// agnostic to transport framing. Guards against an over-broad fix that
// prefixes static-key packets on both transports.
func TestF7_StaticKeyUDPModeNoPrefix(t *testing.T) {
	spec := defaultOpenVPNSpec() // UDP mode
	spec.OpenVPN.StaticKeyMode = true
	spec.OpenVPN.DataPacketCount = 1

	planner := NewPlanner()
	ctx := context.Background()

	configChan, err := planner.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan failed: %v", err)
	}
	packets := collectPackets(ctx, t, configChan)

	// In UDP static-key mode the first up packet must start with the raw
	// P_DATA_V1 opcode byte (6<<3 = 0x30), NOT a 2-byte length prefix.
	for _, p := range packets {
		if p.Direction == "up" && p.L4.Protocol == "udp" && len(p.Payload) > 0 {
			opcodeByte := p.Payload[0]
			if opcodeByte>>POpcodeShift != OpcodeDATAV1 {
				t.Errorf("UDP static-key: first byte should be P_DATA_V1 opcode (6), got opcode=%d (0x%02X) (length prefix leaked into UDP?)",
					opcodeByte>>POpcodeShift, opcodeByte)
			}
			return
		}
	}
	t.Fatal("no up-direction UDP static-key data packet found")
}
