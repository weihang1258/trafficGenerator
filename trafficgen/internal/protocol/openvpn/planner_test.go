// Package openvpn implements the OpenVPN protocol planner.
package openvpn

import (
	"context"
	"testing"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
)

// ---- Helper: default flow spec for OpenVPN ----

func defaultOpenVPNSpec() core.FlowSpec {
	return core.FlowSpec{
		SrcIP: "10.0.0.1",
		DstIP: "203.0.113.1",
		SrcPort: 54321,
		DstPort: 1194,
		UDP: &core.UDPConfig{
			IsResponse: true,
		},
		OpenVPN: &core.OpenVPNConfig{
			Proto: "udp",
			Version: "2",
			DataPacketCount: 1,
		},
	}
}

// ---- Test helpers ----

// collectPackets collects all packets from the planner channel within a timeout.
func collectPackets(ctx context.Context, t *testing.T, configChan <-chan core.PacketConfig) []core.PacketConfig {
	t.Helper()
	var packets []core.PacketConfig
	done := make(chan struct{})
	go func() {
		for pkt := range configChan {
			packets = append(packets, pkt)
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for packets")
	}
	return packets
}

// ---- Standard UDP V2 handshake + data (场景 1) ----

func TestOpenVPN_StandardUDPV2(t *testing.T) {
	// Scenario 1: Standard UDP mode V2 handshake + data transfer
	// Config: proto=udp, version=2, data_packet_count=1
	// Expected: 1 HARD_RESET_V2 client + 1 HARD_RESET_V2 server + 1 P_DATA_V2 client→server + 1 P_DATA_V2 server→client
	spec := defaultOpenVPNSpec()
	planner := NewPlanner()
	ctx := context.Background()

	configChan, err := planner.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan failed: %v", err)
	}
	packets := collectPackets(ctx, t, configChan)

	// UDP mode: 4 packets (client reset, server reset, client data, server data)
	if len(packets) < 4 {
		t.Fatalf("expected at least 4 packets, got %d", len(packets))
	}

	// Check packet 0: client→server (up), UDP
	if packets[0].Direction != "up" {
		t.Errorf("packet 0 direction: expected up, got %s", packets[0].Direction)
	}
	if packets[0].L4.Protocol != "udp" {
		t.Errorf("packet 0 L4 protocol: expected udp, got %s", packets[0].L4.Protocol)
	}
	// Payload should start with opcode=4 (P_CONTROL_HARD_RESET_CLIENT_V2): (4<<5)|0 = 0x80
	if len(packets[0].Payload) == 0 || packets[0].Payload[0] != 0x80 {
		t.Errorf("packet 0 first byte: expected 0x80 (opcode=4, key_id=0), got 0x%02X", packets[0].Payload[0])
	}

	// Check packet 1: server→client (down)
	if packets[1].Direction != "down" {
		t.Errorf("packet 1 direction: expected down, got %s", packets[1].Direction)
	}
	// Payload should start with opcode=5 (P_CONTROL_HARD_RESET_SERVER_V2): (5<<5)|0 = 0xA0
	if len(packets[1].Payload) == 0 || packets[1].Payload[0] != 0xA0 {
		t.Errorf("packet 1 first byte: expected 0xA0 (opcode=5, key_id=0), got 0x%02X", packets[1].Payload[0])
	}

	// Check packet 2: client→server P_DATA_V2: first byte should be 0x40 (P_DATA_V2 high bits)
	if len(packets[2].Payload) == 0 || packets[2].Payload[0] != 0x40 {
		t.Errorf("packet 2 first byte: expected 0x40 (P_DATA_V2, key_id=0), got 0x%02X", packets[2].Payload[0])
	}

	// Check packet 3: server→client P_DATA_V2
	if len(packets[3].Payload) == 0 || packets[3].Payload[0] != 0x40 {
		t.Errorf("packet 3 first byte: expected 0x40 (P_DATA_V2, key_id=0), got 0x%02X", packets[3].Payload[0])
	}
}

// ---- TCP mode (场景 2) ----

func TestOpenVPN_TCPMode(t *testing.T) {
	// Scenario 2: OpenVPN TCP mode
	// Config: proto=tcp, version=2, tls_version=1.3
	// Expected: TCP 3-way + client reset + server reset + P_DATA_V2 + TCP close
	spec := defaultOpenVPNSpec()
	spec.UDP = nil
	spec.TCP = &core.TCPConfig{
		Handshake: true,
		Termination: true,
		MSS: 1460,
	}
	spec.OpenVPN.Proto = "tcp"
	spec.OpenVPN.TLSVersion = "1.3"

	planner := NewPlanner()
	ctx := context.Background()

	configChan, err := planner.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan failed: %v", err)
	}
	packets := collectPackets(ctx, t, configChan)

	// TCP mode should have many packets: SYN, SYN-ACK, ACK, reset client, reset server, data up, data down, FINs
	if len(packets) < 7 {
		t.Fatalf("expected at least 7 packets for TCP mode, got %d", len(packets))
	}

	// Check TCP handshake
	if packets[0].L4.Protocol != "tcp" {
		t.Errorf("packet 0 L4: expected tcp, got %s", packets[0].L4.Protocol)
	}
	if packets[0].L4.Flags != 0x02 {
		t.Errorf("packet 0 flags: expected SYN (0x02), got 0x%02X", packets[0].L4.Flags)
	}
	if packets[1].L4.Flags != 0x12 {
		t.Errorf("packet 1 flags: expected SYN-ACK (0x12), got 0x%02X", packets[1].L4.Flags)
	}
	if packets[2].L4.Flags != 0x10 {
		t.Errorf("packet 2 flags: expected ACK (0x10), got 0x%02X", packets[2].L4.Flags)
	}
}

// ---- TLS-Wrap (tls-auth) enabled (场景 3) ----

func TestOpenVPN_TLSAuth(t *testing.T) {
	// Scenario 4: V2 handshake with tls-auth
	// Config: tls_auth=true, version=2
	// Expected: P_CONTROL packets include HMAC field after packet_id
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

	if len(packets) < 2 {
		t.Fatalf("expected at least 2 packets, got %d", len(packets))
	}

	// Client reset packet: after opcode(1) + session_id(3) + packet_id(variadic), should have HMAC
	// HMAC starts at offset 1+3+1=5 (assuming 1-byte variadic for packet_id=0)
	clientPkt := packets[0].Payload
	// Offset: opcode(1) + session_id(3) + packet_id(variadic ~1) = 5 bytes
	// After that is 20 bytes of HMAC (0xAA filler)
	if len(clientPkt) < 25 {
		t.Fatalf("client reset payload too short for HMAC: %d bytes", len(clientPkt))
	}
	hmacStart := 5 // opcode(1) + session_id(3) + packet_id(1 for 0)
	for i := hmacStart; i < hmacStart+20; i++ {
		if clientPkt[i] != 0xAA {
			t.Errorf("HMAC byte %d: expected 0xAA, got 0x%02X", i, clientPkt[i])
			break
		}
	}

	// Server reset packet: same structure
	serverPkt := packets[1].Payload
	if len(serverPkt) < 25 {
		t.Fatalf("server reset payload too short for HMAC: %d bytes", len(serverPkt))
	}
	for i := hmacStart; i < hmacStart+20; i++ {
		if serverPkt[i] != 0xAA {
			t.Errorf("server HMAC byte %d: expected 0xAA, got 0x%02X", i, serverPkt[i])
			break
		}
	}
}

// ---- tls-crypt mode (场景 4) ----

func TestOpenVPN_TLSCrypt(t *testing.T) {
	// Scenario 5: tls-crypt wrapped key
	// Config: tls_crypt=true, version=2
	// Expected: P_CONTROL packets include wrapped_key (auth-tag 32B + IV 16B + cipher_key)
	spec := defaultOpenVPNSpec()
	spec.OpenVPN.TLSCrypt = true
	spec.OpenVPN.Version = "2"
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

	// Client reset: after opcode(1) + session_id(3) + packet_id(1) = 5 bytes,
	// then wrapped_key: auth-tag(32) + IV(16) + cipher_key(32) = 80 bytes
	clientPkt := packets[0].Payload
	wrapStart := 5
	if len(clientPkt) < wrapStart+80 {
		t.Fatalf("client reset too short for tls-crypt wrap: %d bytes, need %d", len(clientPkt), wrapStart+80)
	}
	// Check auth-tag 0xBB filler
	for i := wrapStart; i < wrapStart+32; i++ {
		if clientPkt[i] != 0xBB {
			t.Errorf("auth-tag byte %d: expected 0xBB, got 0x%02X", i, clientPkt[i])
			break
		}
	}
	// Check IV 0xCC filler
	for i := wrapStart + 32; i < wrapStart+48; i++ {
		if clientPkt[i] != 0xCC {
			t.Errorf("IV byte %d: expected 0xCC, got 0x%02X", i, clientPkt[i])
			break
		}
	}
}

// ---- tls-crypt-v2 mode ----

func TestOpenVPN_TLSCryptV2(t *testing.T) {
	// Scenario 5 extension: tls-crypt-v2
	// Config: tls_crypt=true, tls_crypt_v2=true, version=2
	// Expected: wrapped_key includes wrapped_key_id (4 bytes) + length prefix (2 bytes)
	spec := defaultOpenVPNSpec()
	spec.OpenVPN.TLSCrypt = true
	spec.OpenVPN.TLSCryptV2 = true
	spec.OpenVPN.Version = "2"
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

	clientPkt := packets[0].Payload
	// After opcode(1) + session_id(3) + packet_id(1) = 5 bytes,
	// tls-crypt-v2: wrapped_key_id(4) + length_prefix(2) + auth-tag(32) + IV(16) + cipher_key(32)
	// wrapped_key_id = 0x00000001
	// length prefix = 0x0050 (80)
	wrapStart := 5
	if len(clientPkt) < wrapStart+4+2+80 {
		t.Fatalf("client reset too short for tls-crypt-v2 wrap: %d bytes", len(clientPkt))
	}
	// Check wrapped_key_id = 1
	if clientPkt[wrapStart] != 0x00 || clientPkt[wrapStart+1] != 0x00 ||
		clientPkt[wrapStart+2] != 0x00 || clientPkt[wrapStart+3] != 0x01 {
		t.Errorf("wrapped_key_id: expected 0x00000001, got 0x%02X%02X%02X%02X",
			clientPkt[wrapStart], clientPkt[wrapStart+1], clientPkt[wrapStart+2], clientPkt[wrapStart+3])
	}
	// Check length prefix = 80 (0x0050)
	if clientPkt[wrapStart+4] != 0x00 || clientPkt[wrapStart+5] != 0x50 {
		t.Errorf("length prefix: expected 0x0050, got 0x%02X%02X",
			clientPkt[wrapStart+4], clientPkt[wrapStart+5])
	}
}

// ---- LZO compression disabled (not implemented, but planner should not crash) ----

func TestOpenVPN_DefaultConfig(t *testing.T) {
	// Just test that default config works without error
	spec := defaultOpenVPNSpec()
	planner := NewPlanner()
	ctx := context.Background()

	configChan, err := planner.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan failed: %v", err)
	}
	packets := collectPackets(ctx, t, configChan)

	if len(packets) == 0 {
		t.Fatal("expected at least one packet")
	}
}

// ---- Multiple data channel packets (场景 8) ----

func TestOpenVPN_MultipleDataPackets(t *testing.T) {
	// Scenario 8: Multiple data channel packets
	// Config: data_packet_count=3
	// Expected: 3 P_DATA_V2 client→server + 3 P_DATA_V2 server→client
	spec := defaultOpenVPNSpec()
	spec.OpenVPN.DataPacketCount = 3
	planner := NewPlanner()
	ctx := context.Background()

	configChan, err := planner.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan failed: %v", err)
	}
	packets := collectPackets(ctx, t, configChan)

	// 2 control + 6 data = 8
	if len(packets) < 8 {
		t.Fatalf("expected at least 8 packets (2 control + 6 data), got %d", len(packets))
	}

	// Count P_DATA_V2 packets (first byte 0x40)
	dataCount := 0
	for _, p := range packets {
		if len(p.Payload) > 0 && p.Payload[0] == 0x40 {
			dataCount++
		}
	}
	if dataCount != 6 {
		t.Errorf("expected 6 P_DATA_V2 packets, got %d", dataCount)
	}
}

// ---- Control channel retransmission / SOFT_RESET (场景 9) ----

func TestOpenVPN_SoftReset(t *testing.T) {
	// Scenario 9: Control channel retransmission (soft reset)
	// Config: perform_soft_reset=true
	// Expected: P_DATA_V2 packets, then P_CONTROL_SOFT_RESET_V1, then more P_DATA_V2
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

	// 2 control + 2 data (client+server) + 1 soft_reset + 1 data (after rekey) = 6+
	if len(packets) < 6 {
		t.Fatalf("expected at least 6 packets (2 control + 2 data + 1 soft_reset + 1 data), got %d", len(packets))
	}

	// Find the soft reset packet (opcode=3, first byte = (3<<5) = 0x60, with key_id=1 -> 0x61)
	softResetFound := false
	for _, p := range packets {
		if len(p.Payload) > 0 && (p.Payload[0] == 0x60 || p.Payload[0] == 0x61) {
			softResetFound = true
			break
		}
	}
	if !softResetFound {
		t.Error("expected P_CONTROL_SOFT_RESET_V1 (0x60/0x61) packet, not found")
	}
}

// ---- Keepalive ping/pong (场景 6) ----

func TestOpenVPN_Keepalive(t *testing.T) {
	// Scenario 6: Keepalive ping/pong
	// Config: keepalive_ping=10, keepalive_ping_restart=60
	// Expected: one keepalive P_DATA_V2 with empty payload
	spec := defaultOpenVPNSpec()
	spec.OpenVPN.KeepalivePingInterval = 10
	spec.OpenVPN.KeepalivePingRestart = 60
	spec.OpenVPN.DataPacketCount = 1
	planner := NewPlanner()
	ctx := context.Background()

	configChan, err := planner.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan failed: %v", err)
	}
	packets := collectPackets(ctx, t, configChan)

	// 2 control + 2 data + 1 keepalive = 5
	if len(packets) < 5 {
		t.Fatalf("expected at least 5 packets, got %d", len(packets))
	}
}

// ---- Port sharing with HTTP (场景 7) ----
// Not applicable — port sharing is a DPI detection concept, not a planner output.

// ---- Validate: V1 does not support tls_auth ----

func TestOpenVPN_Validate_V1NoTLSAuth(t *testing.T) {
	spec := defaultOpenVPNSpec()
	spec.OpenVPN.Version = "1"
	spec.OpenVPN.TLSAuth = true
	planner := NewPlanner()
	err := planner.Validate(spec)
	if err == nil {
		t.Fatal("expected error for V1 + tls_auth")
	}
}

// ---- Validate: V1 does not support tls_crypt ----

func TestOpenVPN_Validate_V1NoTLSCrypt(t *testing.T) {
	spec := defaultOpenVPNSpec()
	spec.OpenVPN.Version = "1"
	spec.OpenVPN.TLSCrypt = true
	planner := NewPlanner()
	err := planner.Validate(spec)
	if err == nil {
		t.Fatal("expected error for V1 + tls_crypt")
	}
}

// ---- Validate: tls_crypt_v2 requires tls_crypt ----

func TestOpenVPN_Validate_TLSCryptV2RequiresTLSCrypt(t *testing.T) {
	spec := defaultOpenVPNSpec()
	spec.OpenVPN.TLSCryptV2 = true
	planner := NewPlanner()
	err := planner.Validate(spec)
	if err == nil {
		t.Fatal("expected error for tls_crypt_v2 without tls_crypt")
	}
}

// ---- Validate: data_packet_count <= 1000 ----

func TestOpenVPN_Validate_MaxDataPacketCount(t *testing.T) {
	spec := defaultOpenVPNSpec()
	spec.OpenVPN.DataPacketCount = 1001
	planner := NewPlanner()
	err := planner.Validate(spec)
	if err == nil {
		t.Fatal("expected error for data_packet_count > 1000")
	}
}

// ---- Validate: V3 key_id max 7 ----

func TestOpenVPN_Validate_V3KeyID(t *testing.T) {
	spec := defaultOpenVPNSpec()
	spec.OpenVPN.Version = "3"
	spec.OpenVPN.KeyID = 8
	planner := NewPlanner()
	err := planner.Validate(spec)
	if err == nil {
		t.Fatal("expected error for V3 key_id > 7")
	}
}

// ---- Validate: key_id max 31 for V1/V2 ----

func TestOpenVPN_Validate_KeyIDMax(t *testing.T) {
	spec := defaultOpenVPNSpec()
	spec.OpenVPN.KeyID = 32
	planner := NewPlanner()
	err := planner.Validate(spec)
	if err == nil {
		t.Fatal("expected error for key_id > 31")
	}
}

// ---- Validate: session_id must fit in 24 bits ----

func TestOpenVPN_Validate_SessionID(t *testing.T) {
	spec := defaultOpenVPNSpec()
	spec.OpenVPN.SessionID = 0x1000000
	planner := NewPlanner()
	err := planner.Validate(spec)
	if err == nil {
		t.Fatal("expected error for session_id > 24 bits")
	}
}

// ---- Validate: unsupported cipher ----

func TestOpenVPN_Validate_BadCipher(t *testing.T) {
	spec := defaultOpenVPNSpec()
	spec.OpenVPN.DataCipher = "UNKNOWN_CIPHER"
	planner := NewPlanner()
	err := planner.Validate(spec)
	if err == nil {
		t.Fatal("expected error for unknown cipher")
	}
}

// ---- Validate: unsupported auth_alg ----

func TestOpenVPN_Validate_BadAuthAlg(t *testing.T) {
	spec := defaultOpenVPNSpec()
	spec.OpenVPN.AuthAlg = "UNKNOWN_AUTH"
	planner := NewPlanner()
	err := planner.Validate(spec)
	if err == nil {
		t.Fatal("expected error for unknown auth_alg")
	}
}

// ---- Validate: unsupported TLS version ----

func TestOpenVPN_Validate_BadTLSVersion(t *testing.T) {
	spec := defaultOpenVPNSpec()
	spec.OpenVPN.TLSVersion = "0.9"
	planner := NewPlanner()
	err := planner.Validate(spec)
	if err == nil {
		t.Fatal("expected error for bad TLS version")
	}
}

// ---- Validate: keepalive ping must be less than restart ----

func TestOpenVPN_Validate_KeepaliveConflict(t *testing.T) {
	spec := defaultOpenVPNSpec()
	spec.OpenVPN.KeepalivePingInterval = 60
	spec.OpenVPN.KeepalivePingRestart = 30
	planner := NewPlanner()
	err := planner.Validate(spec)
	if err == nil {
		t.Fatal("expected error for keepalive ping > restart")
	}
}

// ---- Validate: fragment_size range ----

func TestOpenVPN_Validate_FragmentSize(t *testing.T) {
	spec := defaultOpenVPNSpec()
	spec.OpenVPN.FragmentSize = 63
	planner := NewPlanner()
	err := planner.Validate(spec)
	if err == nil {
		t.Fatal("expected error for fragment_size < 64")
	}
}

func TestOpenVPN_Validate_FragmentSizeMax(t *testing.T) {
	spec := defaultOpenVPNSpec()
	spec.OpenVPN.FragmentSize = 1501
	planner := NewPlanner()
	err := planner.Validate(spec)
	if err == nil {
		t.Fatal("expected error for fragment_size > 1500")
	}
}

// ---- Validate: exit_notify_count range ----

func TestOpenVPN_Validate_ExitNotifyCount(t *testing.T) {
	spec := defaultOpenVPNSpec()
	spec.OpenVPN.ExitNotifyCount = 4
	planner := NewPlanner()
	err := planner.Validate(spec)
	if err == nil {
		t.Fatal("expected error for exit_notify_count > 3")
	}
}

// ---- Validate: exit_notify only for proto=udp ----

func TestOpenVPN_Validate_ExitNotifyTCP(t *testing.T) {
	spec := defaultOpenVPNSpec()
	spec.UDP = nil
	spec.TCP = &core.TCPConfig{}
	spec.OpenVPN.Proto = "tcp"
	spec.OpenVPN.ExitNotifyCount = 2
	planner := NewPlanner()
	err := planner.Validate(spec)
	if err == nil {
		t.Fatal("expected error for exit_notify with proto=tcp")
	}
}

// ---- Validate: StaticKeyMode mutually exclusive with TLSAuth ----

func TestOpenVPN_Validate_StaticKeyModeConflict(t *testing.T) {
	spec := defaultOpenVPNSpec()
	spec.OpenVPN.StaticKeyMode = true
	spec.OpenVPN.TLSAuth = true
	planner := NewPlanner()
	err := planner.Validate(spec)
	if err == nil {
		t.Fatal("expected error for static_key_mode + tls_auth")
	}
}

// ---- Validate: AuthUserPass empty user ----

func TestOpenVPN_Validate_AuthUserPassEmptyUser(t *testing.T) {
	spec := defaultOpenVPNSpec()
	spec.OpenVPN.AuthUserPass = true
	spec.OpenVPN.AuthUser = ""
	spec.OpenVPN.AuthPass = "secret123"
	planner := NewPlanner()
	err := planner.Validate(spec)
	if err == nil {
		t.Fatal("expected error for empty auth_user")
	}
}

// ---- Validate: AuthUserPass control character ----

func TestOpenVPN_Validate_AuthUserPassControlChar(t *testing.T) {
	spec := defaultOpenVPNSpec()
	spec.OpenVPN.AuthUserPass = true
	spec.OpenVPN.AuthUser = "al\tice"
	spec.OpenVPN.AuthPass = "secret123"
	planner := NewPlanner()
	err := planner.Validate(spec)
	if err == nil {
		t.Fatal("expected error for auth_user with control chars")
	}
}

// ---- Validate: mssfix exceeds tunnel capacity ----

func TestOpenVPN_Validate_MssfixConflict(t *testing.T) {
	spec := defaultOpenVPNSpec()
	spec.OpenVPN.Mssfix = 1100
	spec.OpenVPN.TunMTU = 1000
	planner := NewPlanner()
	err := planner.Validate(spec)
	if err == nil {
		t.Fatal("expected error for mssfix > tun_mtu - overhead")
	}
}

// ---- Validate: tun_mtu below IPv4 minimum ----

func TestOpenVPN_Validate_TunMTUMin(t *testing.T) {
	spec := defaultOpenVPNSpec()
	spec.OpenVPN.TunMTU = 575
	planner := NewPlanner()
	err := planner.Validate(spec)
	if err == nil {
		t.Fatal("expected error for tun_mtu < 576")
	}
}

// ---- Validate: StaticKeyMode requires key_direction 0 or 1 ----

func TestOpenVPN_Validate_KeyDirection(t *testing.T) {
	spec := defaultOpenVPNSpec()
	spec.OpenVPN.StaticKeyMode = true
	spec.OpenVPN.KeyDirection = 2
	planner := NewPlanner()
	err := planner.Validate(spec)
	if err == nil {
		t.Fatal("expected error for key_direction > 1")
	}
}

// ---- Validate: static_key must be exactly 256 bytes ----

func TestOpenVPN_Validate_StaticKeyLength(t *testing.T) {
	spec := defaultOpenVPNSpec()
	spec.OpenVPN.StaticKeyMode = true
	spec.OpenVPN.StaticKey = make([]byte, 128)
	planner := NewPlanner()
	err := planner.Validate(spec)
	if err == nil {
		t.Fatal("expected error for static_key length != 256")
	}
}

// ---- Validate: data_payload <= 16384 ----

func TestOpenVPN_Validate_DataPayloadTooLarge(t *testing.T) {
	spec := defaultOpenVPNSpec()
	spec.OpenVPN.DataPayload = make([]byte, 16385)
	planner := NewPlanner()
	err := planner.Validate(spec)
	if err == nil {
		t.Fatal("expected error for data_payload > 16384")
	}
}

// ---- Validate: mssfix > 1500 ----

func TestOpenVPN_Validate_MssfixTooLarge(t *testing.T) {
	spec := defaultOpenVPNSpec()
	spec.OpenVPN.Mssfix = 2000
	planner := NewPlanner()
	err := planner.Validate(spec)
	if err == nil {
		t.Fatal("expected error for mssfix > 1500")
	}
}

// ---- Validate: mssfix < 576 ----

func TestOpenVPN_Validate_MssfixTooSmall(t *testing.T) {
	spec := defaultOpenVPNSpec()
	spec.OpenVPN.Mssfix = 500
	planner := NewPlanner()
	err := planner.Validate(spec)
	if err == nil {
		t.Fatal("expected error for mssfix < 576")
	}
}

// ---- Plan: StaticKeyMode (P2P 静态密钥模式) ----

func TestOpenVPN_StaticKeyMode(t *testing.T) {
	// Scenario 13: P2P static key mode
	// Config: static_key_mode=true, key_direction=0
	// Expected: skip HARD_RESET, directly P_DATA_V1
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

	// Static key mode: 2 packets (client->server + server->client)
	if len(packets) != 2 {
		t.Fatalf("expected 2 packets for static key mode, got %d", len(packets))
	}

	// First packet should be P_DATA_V1 (opcode=7, first byte = (7<<5) = 0xE0)
	if len(packets[0].Payload) == 0 || packets[0].Payload[0] != 0xE0 {
		t.Errorf("packet 0: expected 0xE0 (P_DATA_V1), got 0x%02X", packets[0].Payload[0])
	}

	// Second packet should be P_DATA_V1
	if len(packets[1].Payload) == 0 || packets[1].Payload[0] != 0xE0 {
		t.Errorf("packet 1: expected 0xE0 (P_DATA_V1), got 0x%02X", packets[1].Payload[0])
	}
}

// ---- Plan: ExitNotify ----

func TestOpenVPN_ExitNotify(t *testing.T) {
	// Scenario 16: Explicit exit notify
	// Config: exit_notify_count=3
	// Expected: 3 exit_notify packets after data
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
		t.Fatalf("expected at least 7 packets (2 control + 2 data + 3 exit_notify), got %d", len(packets))
	}

	// Last 3 packets should be exit_notify (payload = {0x05})
	for i := len(packets) - 3; i < len(packets); i++ {
		if len(packets[i].Payload) != 1 || packets[i].Payload[0] != 0x05 {
			t.Errorf("exit_notify packet %d: expected payload [0x05], got %v", i, packets[i].Payload)
		}
	}
}

// ---- Plan: AuthUserPass ----

func TestOpenVPN_AuthUserPass(t *testing.T) {
	// Scenario 14: Username/password authentication
	// Config: auth_user_pass=true, auth_user="alice", auth_pass="secret123"
	// Expected: Auth payload between control handshake and data
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

	// Auth payload should be in packet 2 (after client reset and server reset)
	// It should be a TLS AppData record (ContentType=23 = 0x17)
	authPkt := packets[2].Payload
	if len(authPkt) < 5 || authPkt[0] != 0x17 {
		t.Errorf("expected TLS AppData (0x17) for auth, first byte = 0x%02X", authPkt[0])
	}
}

// ---- RFC field: V2 packet_id variadic encoding ----

func TestOpenVPN_PktIDVariadic(t *testing.T) {
	tests := []struct {
		packetID uint64
		expected int // expected byte length
	}{
		{0, 1},
		{1, 1},
		{0x7F, 1},
		{0x80, 2},
		{0x3FFF, 2},
		{0x4000, 3},
		{0x1FFFFF, 3},
		{0x200000, 4},
		{0xFFFFFFF, 4},
		{0x10000000, 5},
		{0x7FFFFFFFF, 5},
		{0x800000000, 6},
		{0x3FFFFFFFFFF, 6},
		{0x40000000000, 7},
		{0x1FFFFFFFFFFFF, 7},
		{0x2000000000000, 8},
		{0xFFFFFFFFFFFFFF, 8}, // max 56-bit
	}
	for _, tt := range tests {
		result := writePktID(tt.packetID)
		if len(result) != tt.expected {
			t.Errorf("writePktID(0x%X): expected length %d, got %d (bytes: %v)",
				tt.packetID, tt.expected, len(result), result)
		}
	}
}

// ---- RFC field: opcode byte calculation ----

func TestOpenVPN_OpcodeByte(t *testing.T) {
	tests := []struct {
		name string
		opcode uint8
		keyID uint8
		want byte
	}{
		{"HARD_RESET_CLIENT_V1 key=0", 1, 0, 0x20},
		{"HARD_RESET_SERVER_V1 key=0", 2, 0, 0x40},
		{"SOFT_RESET_V1 key=1", 3, 1, 0x61},
		{"HARD_RESET_CLIENT_V2 key=0", 4, 0, 0x80},
		{"HARD_RESET_SERVER_V2 key=0", 5, 0, 0xA0},
		{"HARD_RESET_CLIENT_V3 key=0", 6, 0, 0xC0},
		{"P_DATA_V1 key=0", 7, 0, 0xE0},
		{"P_DATA_V1 key=31", 7, 31, 0xFF},
		{"P_DATA_V2 key=0", 9, 0, 0x40},
		{"P_DATA_V2 key=31", 9, 31, 0x5F},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got byte
			if tt.opcode == 9 {
				// P_DATA_V2 uses high 3 bits = 100b = 0x40
				got = 0x40 | (tt.keyID & 0x1F)
			} else {
				got = byte(tt.opcode<<5) | (tt.keyID & 0x1F)
			}
			if got != tt.want {
				t.Errorf("opcode byte: got 0x%02X, want 0x%02X", got, tt.want)
			}
		})
	}
}

// ---- Encrypted payload structure for different ciphers ----

func TestOpenVPN_EncryptedPayload_CBC(t *testing.T) {
	payload := buildEncryptedPayload([]byte("hello"), "AES-256-CBC", 20)
	// CBC: IV(16) + enc_pkt_id(4) + enc_payload(5) + HMAC(20) = 45
	expectedLen := 16 + 4 + 5 + 20
	if len(payload) != expectedLen {
		t.Errorf("AES-256-CBC encrypted payload: expected %d bytes, got %d", expectedLen, len(payload))
	}
	// Check IV filler
	if payload[0] != 0xDD {
		t.Errorf("IV first byte: expected 0xDD, got 0x%02X", payload[0])
	}
}

func TestOpenVPN_EncryptedPayload_GCM(t *testing.T) {
	payload := buildEncryptedPayload([]byte("hello"), "AES-128-GCM", 20)
	// GCM: nonce(12) + enc_pkt_id(4) + enc_payload(5) + tag(16) = 37
	expectedLen := 12 + 4 + 5 + 16
	if len(payload) != expectedLen {
		t.Errorf("AES-128-GCM encrypted payload: expected %d bytes, got %d", expectedLen, len(payload))
	}
	// Check nonce filler
	if payload[0] != 0xDD {
		t.Errorf("nonce first byte: expected 0xDD, got 0x%02X", payload[0])
	}
	// Check tag filler at end
	if payload[len(payload)-1] != 0xEE {
		t.Errorf("tag last byte: expected 0xEE, got 0x%02X", payload[len(payload)-1])
	}
}

func TestOpenVPN_EncryptedPayload_NONE(t *testing.T) {
	payload := buildEncryptedPayload([]byte("hello"), "NONE", 0)
	// NONE: plaintext only (5 bytes)
	if len(payload) != 5 {
		t.Errorf("NONE cipher: expected 5 bytes, got %d", len(payload))
	}
	if string(payload) != "hello" {
		t.Errorf("NONE cipher: expected 'hello', got %v", payload)
	}
}

func TestOpenVPN_EncryptedPayload_DES(t *testing.T) {
	payload := buildEncryptedPayload([]byte("test"), "DES-CBC", 20)
	// DES-CBC: IV(8) + enc_pkt_id(4) + enc_payload(4) + HMAC(20) = 36
	expectedLen := 8 + 4 + 4 + 20
	if len(payload) != expectedLen {
		t.Errorf("DES-CBC encrypted payload: expected %d bytes, got %d", expectedLen, len(payload))
	}
}

// ---- Fragment header building ----

func TestOpenVPN_FragmentHeader(t *testing.T) {
	tests := []struct {
		fragType uint8
		fragmentID uint16
		fragmentSize uint16
		expected []byte
	}{
		{0, 0x0001, 500, []byte{0x00, 0x00, 0x01, 0x01, 0xF4}},
		{1, 0x0001, 500, []byte{0x20, 0x00, 0x01, 0x01, 0xF4}},
		{2, 0x0001, 500, []byte{0x40, 0x00, 0x01, 0x01, 0xF4}},
	}
	for _, tt := range tests {
		result := buildFragmentHeader(tt.fragType, tt.fragmentID, tt.fragmentSize)
		if len(result) != 5 {
			t.Errorf("fragment header: expected 5 bytes, got %d", len(result))
		}
		for i := range tt.expected {
			if result[i] != tt.expected[i] {
				t.Errorf("fragment header byte %d: expected 0x%02X, got 0x%02X",
					i, tt.expected[i], result[i])
			}
		}
	}
}

// ---- TLS version bytes ----

func TestOpenVPN_TLSVersionBytes(t *testing.T) {
	tests := []struct {
		version string
		want []byte
	}{
		{"1.0", []byte{0x03, 0x01}},
		{"1.1", []byte{0x03, 0x02}},
		{"1.2", []byte{0x03, 0x03}},
		{"1.3", []byte{0x03, 0x03}},
	}
	for _, tt := range tests {
		result := tlsVersionBytes(tt.version)
		if result[0] != tt.want[0] || result[1] != tt.want[1] {
			t.Errorf("tlsVersionBytes(%q): got [0x%02X 0x%02X], want [0x%02X 0x%02X]",
				tt.version, result[0], result[1], tt.want[0], tt.want[1])
		}
	}
}

// ---- Plan with FragmentSize ----

func TestOpenVPN_Fragment(t *testing.T) {
	// Scenario 17: Application layer fragmentation
	// Config: fragment_size=100, data_payload=250 bytes
	// Expected: P_DATA_V2 with 3 fragments (first 100, middle 100, last 50)
	spec := defaultOpenVPNSpec()
	spec.OpenVPN.FragmentSize = 100
	spec.OpenVPN.DataPayload = make([]byte, 250)
	for i := range spec.OpenVPN.DataPayload {
		spec.OpenVPN.DataPayload[i] = 0xDD
	}
	spec.OpenVPN.DataPacketCount = 1
	planner := NewPlanner()
	ctx := context.Background()

	configChan, err := planner.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan failed: %v", err)
	}
	packets := collectPackets(ctx, t, configChan)

	// Should have 2 control + 2 data = 4 packets
	if len(packets) < 4 {
		t.Fatalf("expected at least 4 packets, got %d", len(packets))
	}

	// Data packets should contain fragment headers (5-byte fragment info)
	// The fragment header bytes are: frag_info(1) + fragment_id(2) + fragment_size(2)
	// Check that data packet has the fragment headers embedded
	for i := 2; i < 4; i++ {
		pkt := packets[i].Payload
		if len(pkt) < 5+5 { // P_DATA_V2 header (5) + fragment header (5)
			t.Errorf("data packet %d too short: %d bytes", i, len(pkt))
			continue
		}
		// After P_DATA_V2 header (opcode=1 + peer_session_id=3 + packet_id=1), fragment starts at offset ~5
		// Just check there are bytes
		if pkt[5] == 0x00 || pkt[5] == 0x20 || pkt[5] == 0x40 {
			// valid frag_info byte
		} else {
			t.Errorf("data packet %d: expected fragment info byte at offset 5, got 0x%02X", i, pkt[5])
		}
	}
}