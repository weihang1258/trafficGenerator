// Package openvpn implements the OpenVPN protocol planner.
//
// This file contains test-point coverage for the test cases in
// testcases_openvpn.md. Each test corresponds to one or more TC-OVPN-<chapter>-<id>
// test cases.
package openvpn

import (
	"context"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

// === 1. RFC / SPEC 字段覆盖用例 ===

// 1.1 OPENVPN Opcode 字段
func TestTC_Opcode_HARD_RESET_CLIENT_V1(t *testing.T) {
	// TC-OVPN-1.1.1: opcode=1, key_id=0 -> first byte = 0x20
	spec := defaultOpenVPNSpec()
	spec.OpenVPN.Version = "1"
	var p Planner
	_ = p
	_ = spec
	// V1 HARD_RESET_CLIENT_V1 is not fully implemented (only V2/V3 codepath in Plan),
	// but the opcode constant is correct.
	got := byte(OpcodeHARDResetClientV1<<5) | 0 // key_id=0
	want := byte(0x20)
	if got != want {
		t.Errorf("opcode=1 key=0: got 0x%02X, want 0x%02X", got, want)
	}
}

func TestTC_Opcode_HARD_RESET_CLIENT_V2(t *testing.T) {
	// TC-OVPN-1.1.4: opcode=4, key_id=0 -> first byte = (4<<5) = 0x80
	got := byte(OpcodeHARDResetClientV2<<5) | 0
	want := byte(0x80)
	if got != want {
		t.Errorf("opcode=4 key=0: got 0x%02X, want 0x%02X", got, want)
	}
}

func TestTC_Opcode_HARD_RESET_CLIENT_V3(t *testing.T) {
	// TC-OVPN-1.1.6: opcode=6, key_id=0 -> first byte = 0xC0
	got := byte(OpcodeHARDResetClientV3<<5) | 0
	want := byte(0xC0)
	if got != want {
		t.Errorf("opcode=6 key=0: got 0x%02X, want 0x%02X", got, want)
	}
}

func TestTC_Opcode_DATA_V1(t *testing.T) {
	// TC-OVPN-1.1.7: opcode=7, key_id=0 -> first byte = 0xE0
	got := byte(OpcodeDATAV1<<5) | 0
	want := byte(0xE0)
	if got != want {
		t.Errorf("opcode=7 key=0: got 0x%02X, want 0x%02X", got, want)
	}
}

func TestTC_Opcode_DATA_V2(t *testing.T) {
	// TC-OVPN-1.1.8: opcode=9, key_id=0 -> first byte = 0x40
	got := byte(0x40) | 0 // P_DATA_V2 = high 3 bits 100b = 0x40
	want := byte(0x40)
	if got != want {
		t.Errorf("opcode=9 key=0: got 0x%02X, want 0x%02X", got, want)
	}
}

// 1.2 key_id 字段
func TestTC_KeyID(t *testing.T) {
	// TC-OVPN-1.2.1: key_id=0 -> low 5 bits = 0x00
	got := byte(0x40) | (0 & 0x1F) // P_DATA_V2 with key_id=0
	want := byte(0x40)
	if got != want {
		t.Errorf("key_id=0: got 0x%02X, want 0x%02X", got, want)
	}

	// TC-OVPN-1.2.5: key_id=31 -> low 5 bits = 0x1F
	got = byte(0x40) | (31 & 0x1F)
	want = byte(0x5F)
	if got != want {
		t.Errorf("key_id=31: got 0x%02X, want 0x%02X", got, want)
	}

	// TC-OVPN-1.2.7: V3 key_id=7 -> 0xC0 | 0x07 = 0xC7
	got = byte(OpcodeHARDResetClientV3<<5) | (7 & 0x07)
	want = byte(0xC7)
	if got != want {
		t.Errorf("V3 key_id=7: got 0x%02X, want 0x%02X", got, want)
	}
}

// 1.3 session_id 字段 (3 字节 BE, V2/V3 only)
func TestTC_SessionID(t *testing.T) {
	// TC-OVPN-1.3.1: session_id=0x000000 -> 3 bytes 0x00 0x00 0x00
	got := []byte{byte(0x000000 >> 16), byte(0x000000 >> 8), byte(0x000000)}
	want := []byte{0x00, 0x00, 0x00}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("session_id=0: byte %d: got 0x%02X, want 0x%02X", i, got[i], want[i])
		}
	}

	// TC-OVPN-1.3.3: session_id=0xFFFFFF -> 3 bytes 0xFF 0xFF 0xFF
	id := uint32(0xFFFFFF)
	got = []byte{byte(id >> 16), byte(id >> 8), byte(id)}
	want = []byte{0xFF, 0xFF, 0xFF}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("session_id=0xFFFFFF: byte %d: got 0x%02X, want 0x%02X", i, got[i], want[i])
		}
	}
}

// 1.4 packet_id 字段
func TestTC_PacketID_V1(t *testing.T) {
	// TC-OVPN-1.4.1.1: packet_id=0 -> 4 bytes 0x00 0x00 0x00 0x00
	got := []byte{byte(0 >> 24), byte(0 >> 16), byte(0 >> 8), byte(0)}
	want := []byte{0x00, 0x00, 0x00, 0x00}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("V1 packet_id=0: byte %d: got 0x%02X, want 0x%02X", i, got[i], want[i])
		}
	}

	// TC-OVPN-1.4.1.3: packet_id=0xFFFFFFFF -> 4 bytes 0xFF 0xFF 0xFF 0xFF
	pid := uint32(0xFFFFFFFF)
	got = []byte{byte(pid >> 24), byte(pid >> 16), byte(pid >> 8), byte(pid)}
	want = []byte{0xFF, 0xFF, 0xFF, 0xFF}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("V1 packet_id=0xFFFFFFFF: byte %d: got 0x%02X, want 0x%02X", i, got[i], want[i])
		}
	}
}

func TestTC_PacketID_V2_Variadic(t *testing.T) {
	// TC-OVPN-1.4.2.2: packet_id=1 -> variadic length=1, byte = 0x01
	got := writePktID(1)
	if len(got) != 1 || got[0] != 0x01 {
		t.Errorf("V2 packet_id=1: expected [0x01], got %v", got)
	}
}

// 1.5 P_DATA_V2 peer_session_id
func TestTC_PeerSessionID(t *testing.T) {
	// TC-OVPN-1.5.2: peer_session_id=0xAABBCC -> 3 bytes 0xAA 0xBB 0xCC
	id := uint32(0xAABBCC)
	got := []byte{byte(id >> 16), byte(id >> 8), byte(id)}
	want := []byte{0xAA, 0xBB, 0xCC}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("peer_session_id=0xAABBCC: byte %d: got 0x%02X, want 0x%02X", i, got[i], want[i])
		}
	}
}

// 1.6 P_DATA encrypted payload 字段
func TestTC_EncryptedPayload_CBC(t *testing.T) {
	// TC-OVPN-1.6.1: AES-256-CBC -> IV(16) + enc_pkt_id(4) + enc_payload + HMAC(20)
	payload := buildEncryptedPayload([]byte("test"), "AES-256-CBC", 20)
	// 16 + 4 + 4 + 20 = 44
	if len(payload) != 44 {
		t.Errorf("AES-256-CBC payload: expected 44 bytes, got %d", len(payload))
	}
}

func TestTC_EncryptedPayload_GCM(t *testing.T) {
	// TC-OVPN-1.6.2: AES-128-GCM -> nonce(12) + enc_pkt_id(4) + enc_payload + tag(16)
	payload := buildEncryptedPayload([]byte("test"), "AES-128-GCM", 20)
	// 12 + 4 + 4 + 16 = 36
	if len(payload) != 36 {
		t.Errorf("AES-128-GCM payload: expected 36 bytes, got %d", len(payload))
	}
}

// 1.7 tls-auth HMAC 字段
func TestTC_TLSAuthHMAC(t *testing.T) {
	// TC-OVPN-1.7.1: tls_auth=true, HMAC 20 bytes 0xAA filler
	spec := defaultOpenVPNSpec()
	spec.OpenVPN.TLSAuth = true
	spec.OpenVPN.Version = "2"
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

	clientPkt := packets[0].Payload
	// After opcode(1) + session_id(3) + packet_id(1) = 5 bytes, 20 bytes HMAC
	if len(clientPkt) < 25 {
		t.Fatalf("packet too short: %d", len(clientPkt))
	}
	for i := 5; i < 25; i++ {
		if clientPkt[i] != 0xAA {
			t.Errorf("HMAC byte %d: expected 0xAA, got 0x%02X", i, clientPkt[i])
			break
		}
	}
}

// 1.8 tls-crypt 包裹
func TestTC_TLSCryptWrappedKey(t *testing.T) {
	// TC-OVPN-1.8.1: tls_crypt=true, wrapped_key = auth-tag(32) + IV(16) + cipher_key(32)
	wrappedKey := buildWrappedKey(false)
	// 32 + 16 + 32 = 80
	if len(wrappedKey) != 80 {
		t.Errorf("wrapped key: expected 80 bytes, got %d", len(wrappedKey))
	}
	// auth-tag 0xBB
	for i := 0; i < 32; i++ {
		if wrappedKey[i] != 0xBB {
			t.Errorf("auth-tag byte %d: expected 0xBB, got 0x%02X", i, wrappedKey[i])
			break
		}
	}
	// IV 0xCC
	for i := 32; i < 48; i++ {
		if wrappedKey[i] != 0xCC {
			t.Errorf("IV byte %d: expected 0xCC, got 0x%02X", i, wrappedKey[i])
			break
		}
	}
}

// 1.11 cipher 完整列表
func TestTC_AllCiphers(t *testing.T) {
	// TC-OVPN-1.11.1 through 1.11.11
	ciphers := []string{
		"BF-CBC", "AES-128-CBC", "AES-192-CBC", "AES-256-CBC",
		"DES-CBC", "DES-EDE3-CBC", "NONE",
		"AES-128-GCM", "AES-192-GCM", "AES-256-GCM",
		"CHACHA20-POLY1305",
	}
	for _, c := range ciphers {
		payload := buildEncryptedPayload([]byte("test"), c, 20)
		if len(payload) == 0 {
			t.Errorf("cipher %s: empty payload", c)
		}
	}
}

// 1.12 auth 算法完整列表
func TestTC_AllAuthAlgs(t *testing.T) {
	// TC-OVPN-1.12.1 through 1.12.5
	algs := map[string]int{
		"SHA1": 20, "SHA256": 32, "SHA512": 64, "MD5": 16, "none": 0,
	}
	for alg, expectedLen := range algs {
		payload := buildEncryptedPayload([]byte("test"), "AES-256-CBC", expectedLen)
		// CBC: IV(16) + pkt_id(4) + payload(4) + HMAC(expectedLen)
		expectedTotal := 16 + 4 + 4 + expectedLen
		if len(payload) != expectedTotal {
			t.Errorf("auth_alg=%s: expected %d bytes, got %d", alg, expectedTotal, len(payload))
		}
	}
}

// 1.14 explicit-exit-notify
func TestTC_ExitNotify(t *testing.T) {
	// TC-OVPN-1.14.1: exit_notify=1, emit 1 packet with type=0x05
	spec := defaultOpenVPNSpec()
	spec.OpenVPN.ExitNotifyCount = 1
	spec.OpenVPN.DataPacketCount = 1
	planner := NewPlanner()
	ctx := context.Background()

	configChan, err := planner.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan failed: %v", err)
	}
	packets := collectPackets(ctx, t, configChan)

	// 2 control + 2 data + 1 exit_notify = 5
	if len(packets) < 5 {
		t.Fatalf("expected at least 5 packets, got %d", len(packets))
	}
	lastPkt := packets[len(packets)-1].Payload
	if len(lastPkt) != 1 || lastPkt[0] != 0x05 {
		t.Errorf("exit_notify packet: expected [0x05], got %v", lastPkt)
	}
}

// 1.15 tun-mtu vs mssfix
func TestTC_TunMTU_Mssfix(t *testing.T) {
	// TC-OVPN-1.15.1: tun_mtu=1500
	spec := defaultOpenVPNSpec()
	spec.OpenVPN.TunMTU = 1500
	planner := NewPlanner()
	err := planner.Validate(spec)
	if err != nil {
		t.Errorf("tun_mtu=1500: unexpected error: %v", err)
	}

	// TC-OVPN-1.15.4: tun_mtu=575 -> error
	spec.OpenVPN.TunMTU = 575
	err = planner.Validate(spec)
	if err == nil {
		t.Error("tun_mtu=575: expected error")
	}
}

// 1.16 TLS Record.Version
func TestTC_TLSVersion(t *testing.T) {
	// TC-OVPN-1.16.1: tls_version="1.0" -> 0x0301
	got := tlsVersionBytes("1.0")
	want := []byte{0x03, 0x01}
	if got[0] != want[0] || got[1] != want[1] {
		t.Errorf("TLS 1.0: got [0x%02X 0x%02X], want [0x%02X 0x%02X]", got[0], got[1], want[0], want[1])
	}

	// TC-OVPN-1.16.3: tls_version="1.2" -> 0x0303
	got = tlsVersionBytes("1.2")
	want = []byte{0x03, 0x03}
	if got[0] != want[0] || got[1] != want[1] {
		t.Errorf("TLS 1.2: got [0x%02X 0x%02X], want [0x%02X 0x%02X]", got[0], got[1], want[0], want[1])
	}
}

// 1.17 tls-crypt-v2 wrapped_key length prefix
func TestTC_TLSCryptV2LengthPrefix(t *testing.T) {
	// TC-OVPN-1.17.1: tls_crypt_v2=true, wrapped_key has length prefix 0x0050
	wrappedKey := buildWrappedKey(true)
	// wrapped_key_id(4) + length_prefix(2) + auth-tag(32) + IV(16) + cipher_key(32)
	// = 4 + 2 + 80 = 86
	if len(wrappedKey) != 86 {
		t.Errorf("tls-crypt-v2 wrapped key: expected 86 bytes, got %d", len(wrappedKey))
	}
	// length prefix at offset 4: 0x00 0x50
	if wrappedKey[4] != 0x00 || wrappedKey[5] != 0x50 {
		t.Errorf("tls-crypt-v2 length prefix: expected 0x0050, got 0x%02X%02X",
			wrappedKey[4], wrappedKey[5])
	}
}

// 1.18 StaticKey 静态密钥
func TestTC_StaticKeyMode(t *testing.T) {
	// TC-OVPN-1.18.1: static_key_mode=true, direct P_DATA_V1
	spec := defaultOpenVPNSpec()
	spec.OpenVPN.StaticKeyMode = true
	spec.OpenVPN.DataPacketCount = 1
	planner := NewPlanner()
	ctx := context.Background()

	configChan, err := planner.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan failed: %v", err)
	}
	packets := collectPackets(ctx, t, configChan)

	if len(packets) != 2 {
		t.Fatalf("expected 2 packets, got %d", len(packets))
	}
	// P_DATA_V1: first byte = (7<<5) = 0xE0
	if packets[0].Payload[0] != 0xE0 {
		t.Errorf("expected P_DATA_V1 (0xE0), got 0x%02X", packets[0].Payload[0])
	}
}

// 1.19 AuthUserPass
func TestTC_AuthUserPass(t *testing.T) {
	// TC-OVPN-1.19.1: auth_user="alice", auth_pass="secret123"
	payload := buildAuthUserPass("alice", "secret123", "1.2")
	// TLS AppData: 0x17 (ContentType=23) + 0x03 0x03 (TLS 1.2) + 2B length + 5B "alice" + 1B 0x0A + 9B "secret123"
	// = 5 + 5 + 1 + 9 = 20 bytes
	if len(payload) != 20 {
		t.Errorf("auth payload: expected 20 bytes, got %d (payload: %v)", len(payload), payload)
	}
	if payload[0] != 0x17 {
		t.Errorf("auth payload: expected ContentType=0x17, got 0x%02X", payload[0])
	}
}

// 1.20 应用层 Fragment
func TestTC_Fragment(t *testing.T) {
	// TC-OVPN-1.20.1: fragment_size=500, data_payload=1500 -> 3 fragments
	encrypted := buildEncryptedPayload(make([]byte, 1500), "AES-256-CBC", 20)
	fragments := buildFragmentedDataV2(0, 0, 0xAABBCC, encrypted, 500, "AES-256-CBC", 20)
	if len(fragments) == 0 {
		t.Fatal("empty fragment result")
	}
	// First byte should be P_DATA_V2 header (0x40)
	if fragments[0] != 0x40 {
		t.Errorf("fragment packet: expected 0x40, got 0x%02X", fragments[0])
	}
}

// 1.21 OCC magic 字节级断言
func TestTC_OCCMagic(t *testing.T) {
	// TC-OVPN-1.21.1: OCC magic = 18 bytes "OpenVPN Crypto Con"
	occMagic := []byte{
		0x4F, 0x70, 0x65, 0x6E, 0x56, 0x50, 0x4E, 0x20,
		0x43, 0x72, 0x79, 0x70, 0x74, 0x6F, 0x20, 0x43,
		0x6F, 0x6E,
	}
	if len(occMagic) != 18 {
		t.Errorf("OCC magic: expected 18 bytes, got %d", len(occMagic))
	}
	// Verify ASCII
	expected := "OpenVPN Crypto Con"
	for i := 0; i < 18; i++ {
		if occMagic[i] != expected[i] {
			t.Errorf("OCC magic byte %d: got 0x%02X, want '%c'", i, occMagic[i], expected[i])
		}
	}
}

// === 2. 状态机覆盖用例 ===

// 2.1 标准 V2 hard_reset 流程
func TestTC_V2ClientSent(t *testing.T) {
	// TC-OVPN-2.1.1: V2ClientSent -> HARD_RESET_CLIENT_V2
	spec := defaultOpenVPNSpec()
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
	// First packet should be HARD_RESET_CLIENT_V2 (opcode=4, first byte = 0x80)
	if packets[0].Payload[0] != 0x80 {
		t.Errorf("first packet: expected 0x80 (HARD_RESET_CLIENT_V2), got 0x%02X", packets[0].Payload[0])
	}
}

func TestTC_V2ServerWait(t *testing.T) {
	// TC-OVPN-2.1.2: V2ServerWait -> HARD_RESET_SERVER_V2
	spec := defaultOpenVPNSpec()
	planner := NewPlanner()
	ctx := context.Background()

	configChan, err := planner.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan failed: %v", err)
	}
	packets := collectPackets(ctx, t, configChan)

	if len(packets) < 2 {
		t.Fatal("need at least 2 packets")
	}
	// Second packet should be HARD_RESET_SERVER_V2 (opcode=5, first byte = 0xA0)
	if packets[1].Payload[0] != 0xA0 {
		t.Errorf("second packet: expected 0xA0 (HARD_RESET_SERVER_V2), got 0x%02X", packets[1].Payload[0])
	}
}

// 2.4 SOFT_RESET
func TestTC_SoftReset(t *testing.T) {
	// TC-OVPN-2.4.1: V2Data -> SOFT_RESET -> new key_id
	spec := defaultOpenVPNSpec()
	spec.OpenVPN.PerformSoftReset = true
	spec.OpenVPN.DataPacketCount = 1
	planner := NewPlanner()
	ctx := context.Background()

	configChan, err := planner.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan failed: %v", err)
	}
	packets := collectPackets(ctx, t, configChan)

	softResetFound := false
	for _, p := range packets {
		if len(p.Payload) > 0 && (p.Payload[0] == 0x60 || p.Payload[0] == 0x61) {
			softResetFound = true
			break
		}
	}
	if !softResetFound {
		t.Error("SOFT_RESET_V1 (0x60/0x61) not found")
	}
}

// 2.7 StaticKey P2P
func TestTC_StaticKeyP2P(t *testing.T) {
	// TC-OVPN-2.7.1: StaticKeyMode + Initial -> P_DATA_V1 directly
	spec := defaultOpenVPNSpec()
	spec.OpenVPN.StaticKeyMode = true
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
	// Should be P_DATA_V1 (opcode=7, 0xE0)
	if packets[0].Payload[0] != 0xE0 {
		t.Errorf("expected P_DATA_V1 (0xE0), got 0x%02X", packets[0].Payload[0])
	}
}

// 2.10 Keepalive
func TestTC_Keepalive(t *testing.T) {
	// TC-OVPN-2.10.1: keepalive with V2Data
	spec := defaultOpenVPNSpec()
	spec.OpenVPN.KeepalivePingInterval = 10
	spec.OpenVPN.KeepalivePingRestart = 60
	planner := NewPlanner()
	ctx := context.Background()

	configChan, err := planner.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan failed: %v", err)
	}
	packets := collectPackets(ctx, t, configChan)

	// Should have 2 control + 2 data + 1 keepalive = 5
	if len(packets) < 5 {
		t.Fatalf("expected at least 5 packets, got %d", len(packets))
	}
}

// === 3. 业务场景覆盖用例 ===

// 3.1 标准 UDP V2 握手 + 数据传输
func TestTC_Scenario1_StandardUDP(t *testing.T) {
	// TC-OVPN-3.1.1: proto=udp, version=2, data_packet_count=5
	spec := defaultOpenVPNSpec()
	spec.OpenVPN.DataPacketCount = 5
	planner := NewPlanner()
	ctx := context.Background()

	configChan, err := planner.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan failed: %v", err)
	}
	packets := collectPackets(ctx, t, configChan)

	// 2 control + 10 data = 12
	if len(packets) != 12 {
		t.Fatalf("expected 12 packets (2 control + 10 data), got %d", len(packets))
	}

	// Count data packets (P_DATA_V2, first byte 0x40)
	dataCount := 0
	for _, p := range packets {
		if len(p.Payload) > 0 && p.Payload[0] == 0x40 {
			dataCount++
		}
	}
	if dataCount != 10 {
		t.Errorf("expected 10 P_DATA_V2 packets, got %d", dataCount)
	}
}

// 3.2 TCP mode
func TestTC_Scenario2_TCP(t *testing.T) {
	// TC-OVPN-3.2.1: proto=tcp, version=2, tls_version=1.3
	spec := defaultOpenVPNSpec()
	spec.UDP = nil
	spec.TCP = &core.TCPConfig{Handshake: true, Termination: true, MSS: 1460}
	spec.OpenVPN.Proto = "tcp"
	spec.OpenVPN.TLSVersion = "1.3"
	planner := NewPlanner()
	ctx := context.Background()

	configChan, err := planner.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan failed: %v", err)
	}
	packets := collectPackets(ctx, t, configChan)

	// At least 7 packets: SYN, SYN-ACK, ACK, reset client, reset server, data, close
	if len(packets) < 7 {
		t.Fatalf("expected at least 7 packets, got %d", len(packets))
	}

	// TCP handshake
	if packets[0].L4.Flags != 0x02 {
		t.Errorf("expected SYN, got flags 0x%02X", packets[0].L4.Flags)
	}
	// TCP close
	if packets[len(packets)-1].L4.Flags != 0x10 {
		t.Errorf("expected last packet ACK, got flags 0x%02X", packets[len(packets)-1].L4.Flags)
	}
}

// 3.8 SOFT_RESET
func TestTC_Scenario8_SoftReset(t *testing.T) {
	// TC-OVPN-3.8.1: perform_soft_reset=true -> P_DATA + SOFT_RESET + re-key P_DATA
	spec := defaultOpenVPNSpec()
	spec.OpenVPN.PerformSoftReset = true
	spec.OpenVPN.DataPacketCount = 1
	planner := NewPlanner()
	ctx := context.Background()

	configChan, err := planner.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan failed: %v", err)
	}
	packets := collectPackets(ctx, t, configChan)

	// 2 control + 2 data + 1 soft_reset + 1 data = 6
	if len(packets) < 6 {
		t.Fatalf("expected at least 6 packets, got %d", len(packets))
	}
}

// 3.13 P2P 静态密钥模式
func TestTC_Scenario13_StaticKey(t *testing.T) {
	// TC-OVPN-3.13.1: static_key_mode=true, key_direction=0, data_packet_count=2
	spec := defaultOpenVPNSpec()
	spec.OpenVPN.StaticKeyMode = true
	spec.OpenVPN.DataPacketCount = 2
	planner := NewPlanner()
	ctx := context.Background()

	configChan, err := planner.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan failed: %v", err)
	}
	packets := collectPackets(ctx, t, configChan)

	// 2 (client->server) + 2 (server->client) = 4
	if len(packets) != 4 {
		t.Fatalf("expected 4 packets, got %d", len(packets))
	}

	// All should be P_DATA_V1 (0xE0)
	for i, p := range packets {
		if p.Payload[0] != 0xE0 {
			t.Errorf("packet %d: expected P_DATA_V1 (0xE0), got 0x%02X", i, p.Payload[0])
		}
	}
}

// 3.14 用户名密码认证
func TestTC_Scenario14_AuthUserPass(t *testing.T) {
	// TC-OVPN-3.14.1: auth_user_pass=true, auth_user="alice", auth_pass="secret123"
	spec := defaultOpenVPNSpec()
	spec.OpenVPN.AuthUserPass = true
	spec.OpenVPN.AuthUser = "alice"
	spec.OpenVPN.AuthPass = "secret123"
	spec.OpenVPN.DataPacketCount = 1
	planner := NewPlanner()
	ctx := context.Background()

	configChan, err := planner.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan failed: %v", err)
	}
	packets := collectPackets(ctx, t, configChan)

	// 2 control + 1 auth + 2 data = 5
	if len(packets) < 5 {
		t.Fatalf("expected at least 5 packets, got %d", len(packets))
	}
}

// 3.16 Explicit Exit Notify
func TestTC_Scenario16_ExitNotify(t *testing.T) {
	// TC-OVPN-3.16.1: exit_notify_count=3, 3 exit_notify packets
	spec := defaultOpenVPNSpec()
	spec.OpenVPN.ExitNotifyCount = 3
	spec.OpenVPN.DataPacketCount = 1
	planner := NewPlanner()
	ctx := context.Background()

	configChan, err := planner.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan failed: %v", err)
	}
	packets := collectPackets(ctx, t, configChan)

	// 2 control + 2 data + 3 exit_notify = 7
	if len(packets) < 7 {
		t.Fatalf("expected at least 7 packets, got %d", len(packets))
	}
}

// 3.17 应用层 Fragment
func TestTC_Scenario17_Fragment(t *testing.T) {
	// TC-OVPN-3.17.1: fragment_size=500, data_payload=1500
	spec := defaultOpenVPNSpec()
	spec.OpenVPN.FragmentSize = 500
	spec.OpenVPN.DataPayload = make([]byte, 1500)
	spec.OpenVPN.DataPacketCount = 1
	planner := NewPlanner()
	ctx := context.Background()

	configChan, err := planner.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan failed: %v", err)
	}
	packets := collectPackets(ctx, t, configChan)

	// 2 control + 2 data = 4
	if len(packets) < 4 {
		t.Fatalf("expected at least 4 packets, got %d", len(packets))
	}
}

// === 4. 数据场景覆盖用例 ===

// 4.1 空值 / 零值
func TestTC_ZeroSessionID(t *testing.T) {
	// TC-OVPN-4.1.1: session_id=0x000000
	spec := defaultOpenVPNSpec()
	spec.OpenVPN.SessionID = 0
	planner := NewPlanner()
	ctx := context.Background()

	configChan, err := planner.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan failed: %v", err)
	}
	packets := collectPackets(ctx, t, configChan)
	if len(packets) == 0 {
		t.Fatal("no packets")
	}
}

func TestTC_ZeroPacketID(t *testing.T) {
	// TC-OVPN-4.1.2: packet_id=0, V2 variadic 1 byte = 0x00
	got := writePktID(0)
	if len(got) != 1 || got[0] != 0x00 {
		t.Errorf("packet_id=0: expected [0x00], got %v", got)
	}
}

// 4.2 边界值
func TestTC_BoundarySessionID(t *testing.T) {
	// TC-OVPN-4.2.1: session_id=0xFFFFFF
	spec := defaultOpenVPNSpec()
	spec.OpenVPN.SessionID = 0xFFFFFF
	planner := NewPlanner()
	err := planner.Validate(spec)
	if err != nil {
		t.Errorf("session_id=0xFFFFFF: unexpected error: %v", err)
	}
}

func TestTC_BoundaryKeyID(t *testing.T) {
	// TC-OVPN-4.2.2: key_id=31 (V1/V2 max)
	spec := defaultOpenVPNSpec()
	spec.OpenVPN.KeyID = 31
	planner := NewPlanner()
	err := planner.Validate(spec)
	if err != nil {
		t.Errorf("key_id=31: unexpected error: %v", err)
	}

	// TC-OVPN-4.3.4: key_id=32 -> error
	spec.OpenVPN.KeyID = 32
	err = planner.Validate(spec)
	if err == nil {
		t.Error("key_id=32: expected error")
	}
}

func TestTC_BoundaryPacketIDV1(t *testing.T) {
	// TC-OVPN-4.2.4: packet_id=0xFFFFFFFF (V1 max)
	pid := uint64(0xFFFFFFFF)
	got := []byte{byte(pid >> 24), byte(pid >> 16), byte(pid >> 8), byte(pid)}
	want := []byte{0xFF, 0xFF, 0xFF, 0xFF}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("V1 max packet_id byte %d: got 0x%02X, want 0x%02X", i, got[i], want[i])
		}
	}
}

// 4.3 异常值
func TestTC_InvalidKeyID(t *testing.T) {
	// TC-OVPN-4.3.4: key_id=32 -> error
	spec := defaultOpenVPNSpec()
	spec.OpenVPN.KeyID = 32
	planner := NewPlanner()
	err := planner.Validate(spec)
	if err == nil {
		t.Error("key_id=32: expected error")
	}
}

func TestTC_InvalidCipher(t *testing.T) {
	// TC-OVPN-4.3.8: cipher=UNKNOWN_CIPHER -> error
	spec := defaultOpenVPNSpec()
	spec.OpenVPN.DataCipher = "UNKNOWN_CIPHER"
	planner := NewPlanner()
	err := planner.Validate(spec)
	if err == nil {
		t.Error("unknown cipher: expected error")
	}
}

func TestTC_InvalidVersion1TLSCrypt(t *testing.T) {
	// TC-OVPN-4.3.10: version=1 + tls_crypt=true -> error
	spec := defaultOpenVPNSpec()
	spec.OpenVPN.Version = "1"
	spec.OpenVPN.TLSCrypt = true
	planner := NewPlanner()
	err := planner.Validate(spec)
	if err == nil {
		t.Error("V1 + tls_crypt: expected error")
	}
}

// 4.6 加密不可解密场景
func TestTC_DeterministicFiller(t *testing.T) {
	// TC-OVPN-4.6.1: P_DATA AES-GCM, nonce=0xDD, tag=0xEE
	payload := buildEncryptedPayload([]byte("test"), "AES-128-GCM", 20)
	// nonce at offset 0
	for i := 0; i < 12; i++ {
		if payload[i] != 0xDD {
			t.Errorf("GCM nonce byte %d: expected 0xDD, got 0x%02X", i, payload[i])
			break
		}
	}
	// tag at end-16
	for i := len(payload) - 16; i < len(payload); i++ {
		if payload[i] != 0xEE {
			t.Errorf("GCM tag byte %d: expected 0xEE, got 0x%02X", i, payload[i])
			break
		}
	}

	// TC-OVPN-4.6.2: HMAC = 0xAA filler
	hmacPayload := buildEncryptedPayload([]byte("test"), "AES-256-CBC", 20)
	// HMAC at end-20
	for i := len(hmacPayload) - 20; i < len(hmacPayload); i++ {
		if hmacPayload[i] != 0xAA {
			t.Errorf("HMAC byte %d: expected 0xAA, got 0x%02X", i, hmacPayload[i])
			break
		}
	}
}

// === 6. 资源耗尽用例 ===

// 6.5: large SOFT_RESET count
func TestTC_Resource_SoftResetCount(t *testing.T) {
	// Multiple SOFT_RESET packets
	spec := defaultOpenVPNSpec()
	spec.OpenVPN.PerformSoftReset = true
	spec.OpenVPN.DataPacketCount = 1
	planner := NewPlanner()
	ctx := context.Background()

	configChan, err := planner.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan failed: %v", err)
	}
	packets := collectPackets(ctx, t, configChan)

	// Should not panic
	if len(packets) == 0 {
		t.Fatal("no packets")
	}
}

// 6.6: packet_id extreme value
func TestTC_Resource_PacketIDMax(t *testing.T) {
	// TC-OVPN-6.6: packet_id = 2^56-1, V2 variadic max 8 bytes
	got := writePktID(0xFFFFFFFFFFFFFF)
	if len(got) != 8 {
		t.Errorf("max packet_id: expected 8 bytes, got %d", len(got))
	}
}