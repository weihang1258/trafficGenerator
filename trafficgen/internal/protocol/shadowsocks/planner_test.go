package shadowsocks

// Integration tests for the Shadowsocks planner. Tests cover scenarios
// from the design doc (§6): TCP relay, IPv4/Domain/IPv6 target addresses,
// large payload chunking, AEAD tag boundaries, empty payload, UDP relay.
//
// Each test asserts observable PacketConfig field values and payload
// byte layout — not just "no error". Spec-driven from design_shadowsocks.md.

import (
	"context"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/protocol/testutil"
)

// validTCPSpec returns a canonical valid TCP-mode spec for tests.
func validTCPSpec() core.FlowSpec {
	return core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 50000, DstPort: 8388,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		Shadowsocks: &core.ShadowsocksConfig{
			Mode: "tcp",
			Cipher: "aes-256-gcm",
			Chunks: 1,
			ChunkPayloadSize: 100,
		},
	}
}

// drain collects all configs from the channel.
func drain(ch <-chan core.PacketConfig) []core.PacketConfig {
	var out []core.PacketConfig
	for c := range ch {
		out = append(out, c)
	}
	return out
}

// mustPlan fails the test if Plan returns an error.
func mustPlan(t *testing.T, p *Planner, spec core.FlowSpec) <-chan core.PacketConfig {
	t.Helper()
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan returned error: %v", err)
	}
	return ch
}

// findFirstPayloadByDirection returns the first payload with the given
// direction and TCP flags (0x18 = PSH-ACK for data; 0x02 = SYN; 0x11 = FIN-ACK).
func findFirstPayloadByDirection(cfgs []core.PacketConfig, direction string, flags uint8) []byte {
	for _, c := range cfgs {
		if c.Direction == direction && c.L4.Flags == flags {
			return c.Payload
		}
	}
	return nil
}

// collectAllPayloadsByDirection returns all payloads with the given
// direction and TCP flags.
func collectAllPayloadsByDirection(cfgs []core.PacketConfig, direction string, flags uint8) [][]byte {
	var out [][]byte
	for _, c := range cfgs {
		if c.Direction == direction && c.L4.Flags == flags {
			out = append(out, c.Payload)
		}
	}
	return out
}

// --- Validate ---

func TestValidate_ValidTCP(t *testing.T) {
	p := NewPlanner()
	if err := p.Validate(validTCPSpec()); err != nil {
		t.Errorf("valid spec: %v", err)
	}
}

func TestValidate_InvalidSrcIP(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.SrcIP = "bad"
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "SrcIP") {
		t.Errorf("err=%v, want contains 'SrcIP'", err)
	}
}

func TestValidate_NilConfig(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2"}
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "required") {
		t.Errorf("err=%v, want contains 'required'", err)
	}
}

func TestValidate_UnsupportedCipher(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.Cipher = "rc4-md5"
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "unsupported cipher") {
		t.Errorf("err=%v, want contains 'unsupported cipher'", err)
	}
}

func TestValidate_ChunkPayloadSizeTooLarge(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.ChunkPayloadSize = 16384
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "exceeds max") {
		t.Errorf("err=%v, want contains 'exceeds max'", err)
	}
}

func TestValidate_ObfuscationHTTPWithSocks5(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.Obfuscation = "http"
	spec.Shadowsocks.SOCKS5Handshake = true
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("err=%v, want contains 'mutually exclusive'", err)
	}
}

func TestValidate_ObfuscationHTTPWithUDP(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.Mode = "udp"
	spec.Shadowsocks.Obfuscation = "http"
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "requires Mode=tcp") {
		t.Errorf("err=%v, want 'requires Mode=tcp'", err)
	}
}

func TestValidate_UDPCmdOnTCP(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.SOCKS5Handshake = true
	spec.Shadowsocks.SOCKS5Cmd = "udp_associate"
	spec.Shadowsocks.Mode = "tcp"
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "requires Mode=udp") {
		t.Errorf("err=%v, want 'requires Mode=udp'", err)
	}
}

func TestValidate_PasswordNoUsername(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.SOCKS5Handshake = true
	spec.Shadowsocks.SOCKS5AuthMethod = "password"
	spec.Shadowsocks.SOCKS5Password = "x"
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "Username required") {
		t.Errorf("err=%v, want 'Username required'", err)
	}
}

func TestValidate_PasswordNoPassword(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.SOCKS5Handshake = true
	spec.Shadowsocks.SOCKS5AuthMethod = "password"
	spec.Shadowsocks.SOCKS5Username = "x"
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "Password required") {
		t.Errorf("err=%v, want 'Password required'", err)
	}
}

// --- Plan: TCP relay ---

// TestPlan_TCPStandardRelay verifies the TCP-mode relay produces:
// TCP handshake (SYN/SYN-ACK/ACK) -> salt -> 1 chunk -> FIN-ACK/ACK/FIN-ACK/ACK.
func TestPlan_TCPStandardRelay(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	cfgs := drain(mustPlan(t, p, spec))

	// Expect at least 3 (handshake) + 2 (salt + chunk) + 4 (teardown) = 9 packets.
	// Salt + chunk may each be split into multiple segments by MSS, but
	// with payloadSize=100 and MSS=1460, each fits in one PSH-ACK.
	if len(cfgs) < 9 {
		t.Fatalf("expected at least 9 packets, got %d", len(cfgs))
	}

	// Verify handshake (握手)
	if cfgs[0].L4.Flags != 0x02 || cfgs[0].Direction != "up" {
		t.Errorf("packet[0] want SYN up, got flags=0x%02x dir=%s", cfgs[0].L4.Flags, cfgs[0].Direction)
	}
	if cfgs[1].L4.Flags != 0x12 || cfgs[1].Direction != "down" {
		t.Errorf("packet[1] want SYN-ACK down, got flags=0x%02x dir=%s", cfgs[1].L4.Flags, cfgs[1].Direction)
	}
	if cfgs[2].L4.Flags != 0x10 || cfgs[2].Direction != "up" {
		t.Errorf("packet[2] want ACK up, got flags=0x%02x dir=%s", cfgs[2].L4.Flags, cfgs[2].Direction)
	}

	// Verify PacketIndex is strictly increasing
	for i := 1; i < len(cfgs); i++ {
		if cfgs[i].PacketIndex != cfgs[i-1].PacketIndex+1 {
			t.Errorf("packet[%d].PacketIndex=%d, want %d", i, cfgs[i].PacketIndex, cfgs[i-1].PacketIndex+1)
			break
		}
	}

	// Verify last 4 packets are FIN-ACK/ACK/FIN-ACK/ACK teardown
	n := len(cfgs)
	if cfgs[n-4].L4.Flags != 0x11 || cfgs[n-4].Direction != "up" {
		t.Errorf("packet[n-4] want FIN-ACK up, got flags=0x%02x dir=%s", cfgs[n-4].L4.Flags, cfgs[n-4].Direction)
	}
	if cfgs[n-3].L4.Flags != 0x10 || cfgs[n-3].Direction != "down" {
		t.Errorf("packet[n-3] want ACK down, got flags=0x%02x dir=%s", cfgs[n-3].L4.Flags, cfgs[n-3].Direction)
	}
	if cfgs[n-2].L4.Flags != 0x11 || cfgs[n-2].Direction != "down" {
		t.Errorf("packet[n-2] want FIN-ACK down, got flags=0x%02x dir=%s", cfgs[n-2].L4.Flags, cfgs[n-2].Direction)
	}
	if cfgs[n-1].L4.Flags != 0x10 || cfgs[n-1].Direction != "up" {
		t.Errorf("packet[n-1] want ACK up, got flags=0x%02x dir=%s", cfgs[n-1].L4.Flags, cfgs[n-1].Direction)
	}
}

// TestPlan_SaltLength verifies the 32-byte salt is emitted as the first
// PSH-ACK up payload after the TCP handshake.
func TestPlan_SaltLength(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	cfgs := drain(mustPlan(t, p, spec))

	salt := findFirstPayloadByDirection(cfgs, "up", 0x18)
	if salt == nil {
		t.Fatalf("no PSH-ACK up payload found")
	}
	if len(salt) != SaltLen {
		t.Errorf("salt length=%d, want %d", len(salt), SaltLen)
	}
}

// TestPlan_NoSaltForNoneCipher verifies cipher="none" skips the salt.
func TestPlan_NoSaltForNoneCipher(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.Cipher = "none"
	cfgs := drain(mustPlan(t, p, spec))

	// For none cipher: first PSH-ACK up is the chunk, no salt
	first := findFirstPayloadByDirection(cfgs, "up", 0x18)
	if first == nil {
		t.Fatalf("no PSH-ACK up payload")
	}
	// Chunk for none cipher with payloadSize=100: 2 + 100 = 102 bytes
	if len(first) != 102 {
		t.Errorf("none-chunk length=%d, want 102", len(first))
	}
}

// TestPlan_AEADTagBoundary verifies each AEAD chunk ends with a 16-byte tag.
func TestPlan_AEADTagBoundary(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.Chunks = 2
	spec.Shadowsocks.ChunkPayloadSize = 50
	cfgs := drain(mustPlan(t, p, spec))

	// Salt is the first up PSH-ACK; subsequent up PSH-ACKs are chunks.
	payloads := collectAllPayloadsByDirection(cfgs, "up", 0x18)
	if len(payloads) < 3 {
		t.Fatalf("expected at least 3 up payloads (salt + 2 chunks), got %d", len(payloads))
	}

	// payloads[0] = salt (32B), payloads[1] = chunk1, payloads[2] = chunk2
	if len(payloads[0]) != SaltLen {
		t.Errorf("salt length=%d, want %d", len(payloads[0]), SaltLen)
	}

	expectedChunkLen := 2 + 50 + TagLen // 68
	if len(payloads[1]) != expectedChunkLen {
		t.Errorf("chunk1 length=%d, want %d", len(payloads[1]), expectedChunkLen)
	}
	if len(payloads[2]) != expectedChunkLen {
		t.Errorf("chunk2 length=%d, want %d", len(payloads[2]), expectedChunkLen)
	}
}

// TestPlan_EmptyPayload tests chunk with payload_size=0 (zero-payload chunk).
func TestPlan_EmptyPayload(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.Chunks = 1
	spec.Shadowsocks.ChunkPayloadSize = 0
	cfgs := drain(mustPlan(t, p, spec))

	// Find first chunk (after salt) — should be 2 + 0 + 16 = 18 bytes.
	payloads := collectAllPayloadsByDirection(cfgs, "up", 0x18)
	if len(payloads) < 2 {
		t.Fatalf("expected at least 2 up payloads, got %d", len(payloads))
	}
	if len(payloads[0]) != SaltLen {
		t.Errorf("salt length=%d, want %d", len(payloads[0]), SaltLen)
	}
	// Chunk: 2 (len) + 0 (payload) + 16 (tag) = 18 bytes
	if len(payloads[1]) != 18 {
		t.Errorf("empty-payload chunk length=%d, want 18", len(payloads[1]))
	}
}

// TestPlan_IPv4Target verifies SOCKS5 ATYP=0x01 and IPv4 ADDR encoding.
func TestPlan_IPv4Target(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.SOCKS5Handshake = true
	spec.Shadowsocks.SOCKS5DstAddr = "192.0.2.1"
	spec.Shadowsocks.SOCKS5DstPort = 443
	cfgs := drain(mustPlan(t, p, spec))

	// SOCKS5 request is the 3rd up PSH-ACK (after greeting, possibly auth).
	// For no-auth: greeting (up) -> method_response (down) -> request (up).
	upPayloads := collectAllPayloadsByDirection(cfgs, "up", 0x18)
	if len(upPayloads) < 2 {
		t.Fatalf("expected at least 2 up payloads, got %d", len(upPayloads))
	}
	// upPayloads[0] = greeting (3B: 0x05 0x01 0x00)
	// upPayloads[1] = SOCKS5 request
	req := upPayloads[1]
	if len(req) < 10 {
		t.Fatalf("SOCKS5 request too short: %d", len(req))
	}
	if req[0] != SOCKS5Ver {
		t.Errorf("req[0]=0x%02x, want 0x05 (VER)", req[0])
	}
	if req[1] != SOCKS5CmdConnect {
		t.Errorf("req[1]=0x%02x, want 0x01 (CONNECT)", req[1])
	}
	if req[2] != SOCKS5RSV {
		t.Errorf("req[2]=0x%02x, want 0x00 (RSV)", req[2])
	}
	if req[3] != SOCKS5ATYPIPv4 {
		t.Errorf("req[3]=0x%02x, want 0x01 (ATYP=IPv4)", req[3])
	}
	// IPv4: 192.0.2.1 = 0xC0 0x00 0x02 0x01
	if req[4] != 0xC0 || req[5] != 0x00 || req[6] != 0x02 || req[7] != 0x01 {
		t.Errorf("IPv4 ADDR=0x%02x%02x%02x%02x, want 0xC0000201", req[4], req[5], req[6], req[7])
	}
	// Port 443 = 0x01 0xBB
	if req[8] != 0x01 || req[9] != 0xBB {
		t.Errorf("PORT=0x%02x%02x, want 0x01BB (443)", req[8], req[9])
	}
}

// TestPlan_DomainTarget verifies SOCKS5 ATYP=0x03 and domain ADDR encoding.
func TestPlan_DomainTarget(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.SOCKS5Handshake = true
	spec.Shadowsocks.SOCKS5DstAddr = "example.com"
	spec.Shadowsocks.SOCKS5DstPort = 443
	cfgs := drain(mustPlan(t, p, spec))

	upPayloads := collectAllPayloadsByDirection(cfgs, "up", 0x18)
	if len(upPayloads) < 2 {
		t.Fatalf("expected at least 2 up payloads, got %d", len(upPayloads))
	}
	req := upPayloads[1]
	if req[3] != SOCKS5ATYPDomain {
		t.Errorf("req[3]=0x%02x, want 0x03 (ATYP=Domain)", req[3])
	}
	// Domain length prefix
	domainLen := int(req[4])
	if domainLen != len("example.com") {
		t.Errorf("domain length=%d, want %d", domainLen, len("example.com"))
	}
	// Domain content
	if string(req[5:5+domainLen]) != "example.com" {
		t.Errorf("domain=%q, want 'example.com'", string(req[5:5+domainLen]))
	}
	// Port
	portStart := 5 + domainLen
	if req[portStart] != 0x01 || req[portStart+1] != 0xBB {
		t.Errorf("PORT=0x%02x%02x, want 0x01BB (443)", req[portStart], req[portStart+1])
	}
}

// TestPlan_IPv6Target verifies SOCKS5 ATYP=0x04 and IPv6 ADDR encoding.
func TestPlan_IPv6Target(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.SOCKS5Handshake = true
	spec.Shadowsocks.SOCKS5DstAddr = "2001:db8::1"
	spec.Shadowsocks.SOCKS5DstPort = 443
	cfgs := drain(mustPlan(t, p, spec))

	upPayloads := collectAllPayloadsByDirection(cfgs, "up", 0x18)
	if len(upPayloads) < 2 {
		t.Fatalf("expected at least 2 up payloads, got %d", len(upPayloads))
	}
	req := upPayloads[1]
	if req[3] != SOCKS5ATYPIPv6 {
		t.Errorf("req[3]=0x%02x, want 0x04 (ATYP=IPv6)", req[3])
	}
	// IPv6 address: 16 bytes starting at offset 4
	// 2001:db8::1 = 20 01 0d b8 00 00 00 00 00 00 00 00 00 00 00 01
	if req[4] != 0x20 || req[5] != 0x01 {
		t.Errorf("IPv6[0:2]=0x%02x%02x, want 0x2001", req[4], req[5])
	}
	if req[6] != 0x0d || req[7] != 0xb8 {
		t.Errorf("IPv6[2:4]=0x%02x%02x, want 0x0db8", req[6], req[7])
	}
	// Bytes 8-18 should be 0 (the "::" part, bytes 4-14 of the 16-byte IPv6 addr)
	for i := 8; i < 19; i++ {
		if req[i] != 0x00 {
			t.Errorf("IPv6[%d]=0x%02x, want 0x00", i, req[i])
			break
		}
	}
	// Byte 19 should be 0x01 (the "::1" part, byte 15 of 16-byte IPv6 addr)
	if req[19] != 0x01 {
		t.Errorf("IPv6[15]=0x%02x, want 0x01", req[19])
	}
	// Port at offset 20
	if req[20] != 0x01 || req[21] != 0xBB {
		t.Errorf("PORT=0x%02x%02x, want 0x01BB (443)", req[20], req[21])
	}
}

// TestPlan_LargePayloadChunked verifies a large payload is split across
// multiple TCP segments (MSS-based segmentation).
func TestPlan_LargePayloadChunked(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	// Set MSS to a small value to force segmentation (must be >= MinMSS=536).
	testutil.EnsureTCP(&spec).MSS = 536
	// Chunk: 2 (len) + 200 (payload) + 16 (tag) = 218 bytes -> 1 segment (218 < 536)
	// Salt: 32 bytes -> 1 segment
	// To force multiple segments, use a larger chunk payload.
	spec.Shadowsocks.Chunks = 1
	spec.Shadowsocks.ChunkPayloadSize = 1000
	cfgs := drain(mustPlan(t, p, spec))

	// With MSS=536, chunk = 2 + 1000 + 16 = 1018 bytes
	// Segments: ceil(1018/536) = 2 segments
	upPayloads := collectAllPayloadsByDirection(cfgs, "up", 0x18)
	if len(upPayloads) < 3 { // salt (1 segment) + chunk (2 segments) = 3
		t.Fatalf("expected at least 3 up payloads, got %d", len(upPayloads))
	}

	// Salt: 32 bytes (fits in 1 segment since 32 < 536)
	if len(upPayloads[0]) != SaltLen {
		t.Errorf("salt length=%d, want %d", len(upPayloads[0]), SaltLen)
	}

	// Chunk segments: each should be <= MSS=536
	for i := 1; i < len(upPayloads); i++ {
		if len(upPayloads[i]) > 536 {
			t.Errorf("chunk segment %d length=%d, want <= 536 (MSS)", i, len(upPayloads[i]))
		}
	}

	// Total chunk bytes across segments should equal 2 + 1000 + 16 = 1018
	totalChunkBytes := 0
	for i := 1; i < len(upPayloads); i++ {
		totalChunkBytes += len(upPayloads[i])
	}
	if totalChunkBytes != 1018 {
		t.Errorf("total chunk bytes=%d, want 1018", totalChunkBytes)
	}
}

// TestPlan_UDPRelay verifies UDP-mode emits salt + AEAD packet per datagram.
func TestPlan_UDPRelay(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.Mode = "udp"
	spec.Shadowsocks.Cipher = "aes-256-gcm"
	spec.Shadowsocks.SOCKS5DstAddr = "8.8.8.8"
	spec.Shadowsocks.SOCKS5DstPort = 53
	spec.Shadowsocks.ChunkPayloadSize = 100
	spec.Count = 3
	cfgs := drain(mustPlan(t, p, spec))

	// Expect 3 UDP packets
	if len(cfgs) != 3 {
		t.Fatalf("expected 3 UDP packets, got %d", len(cfgs))
	}

	// Each packet: salt(32) + AEAD(RSV(2)+FRAG(1)+ATYP(1)+ADDR(4)+PORT(2)+PAYLOAD(100)=110) + tag(16)
	// = 32 + 110 + 16 = 158 bytes
	for i, c := range cfgs {
		if c.L4.Protocol != "udp" {
			t.Errorf("packet[%d] protocol=%q, want 'udp'", i, c.L4.Protocol)
		}
		if len(c.Payload) != 158 {
			t.Errorf("packet[%d] payload length=%d, want 158", i, len(c.Payload))
		}
		// First 32 bytes = salt (should be random)
		if c.Payload[0] == c.Payload[1] && c.Payload[1] == c.Payload[2] {
			// Could be coincidence but very unlikely for random salt
			t.Errorf("packet[%d] salt looks zero-filled", i)
		}
		// Salt should differ between packets
		if i > 0 {
			prev := cfgs[i-1].Payload[:32]
			curr := c.Payload[:32]
			same := true
			for j := 0; j < 32; j++ {
				if prev[j] != curr[j] {
					same = false
					break
				}
			}
			if same {
				t.Errorf("packet[%d] salt same as packet[%d]", i, i-1)
			}
		}
	}

	// Verify packet indices are strictly increasing
	for i := 1; i < len(cfgs); i++ {
		if cfgs[i].PacketIndex != cfgs[i-1].PacketIndex+1 {
			t.Errorf("packet[%d].PacketIndex=%d, want %d", i, cfgs[i].PacketIndex, cfgs[i-1].PacketIndex+1)
			break
		}
	}
}

// TestPlan_UDPRelayNoneCipher verifies UDP mode with cipher="none" emits plaintext.
func TestPlan_UDPRelayNoneCipher(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.Mode = "udp"
	spec.Shadowsocks.Cipher = "none"
	spec.Shadowsocks.SOCKS5DstAddr = "8.8.8.8"
	spec.Shadowsocks.SOCKS5DstPort = 53
	spec.Shadowsocks.ChunkPayloadSize = 10
	spec.Count = 1
	cfgs := drain(mustPlan(t, p, spec))

	if len(cfgs) != 1 {
		t.Fatalf("expected 1 UDP packet, got %d", len(cfgs))
	}
	// Plaintext: RSV(2) + FRAG(1) + ATYP(1) + ADDR(4) + PORT(2) + PAYLOAD(10) = 20 bytes
	if len(cfgs[0].Payload) != 20 {
		t.Errorf("payload length=%d, want 20", len(cfgs[0].Payload))
	}
	// RSV = 0x0000
	if cfgs[0].Payload[0] != 0x00 || cfgs[0].Payload[1] != 0x00 {
		t.Errorf("RSV=0x%02x%02x, want 0x0000", cfgs[0].Payload[0], cfgs[0].Payload[1])
	}
	// FRAG = 0x00
	if cfgs[0].Payload[2] != 0x00 {
		t.Errorf("FRAG=0x%02x, want 0x00", cfgs[0].Payload[2])
	}
	// ATYP = 0x01 (IPv4)
	if cfgs[0].Payload[3] != SOCKS5ATYPIPv4 {
		t.Errorf("ATYP=0x%02x, want 0x01 (IPv4)", cfgs[0].Payload[3])
	}
	// ADDR = 8.8.8.8 = 0x08 0x08 0x08 0x08
	if cfgs[0].Payload[4] != 0x08 || cfgs[0].Payload[5] != 0x08 ||
		cfgs[0].Payload[6] != 0x08 || cfgs[0].Payload[7] != 0x08 {
		t.Errorf("ADDR=0x%02x%02x%02x%02x, want 0x08080808 (8.8.8.8)",
			cfgs[0].Payload[4], cfgs[0].Payload[5], cfgs[0].Payload[6], cfgs[0].Payload[7])
	}
	// PORT = 53 = 0x00 0x35
	if cfgs[0].Payload[8] != 0x00 || cfgs[0].Payload[9] != 0x35 {
		t.Errorf("PORT=0x%02x%02x, want 0x0035 (53)", cfgs[0].Payload[8], cfgs[0].Payload[9])
	}
}

// TestPlan_HTTPTransferTCPSequence verifies TCP seq/ack advancement for
// HTTP-style request/response.
func TestPlan_TCPSequenceAdvancement(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.Chunks = 2
	spec.Shadowsocks.ChunkPayloadSize = 50
	cfgs := drain(mustPlan(t, p, spec))

	// Verify each up PSH-ACK advances client seq by payload length
	var prevSeq uint32
	var prevDir string
	for i, c := range cfgs {
		if c.L4.Flags == 0x18 { // PSH-ACK
			if c.Direction == "up" {
				if prevDir == "up" {
					// Verify seq advanced by previous payload length
					expectedSeq := prevSeq + uint32(len(cfgs[i-1].Payload))
					if c.L4.Seq != expectedSeq {
						t.Errorf("up packet[%d] seq=%d, want %d (prev=%d + payload=%d)",
							i, c.L4.Seq, expectedSeq, prevSeq, len(cfgs[i-1].Payload))
						break
					}
				}
				prevSeq = c.L4.Seq
				prevDir = "up"
			}
		}
	}
}

// TestPlan_CTXCancel verifies planner exits when context is canceled.
func TestPlan_CTXCancel(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.Chunks = 1000 // would take a while
	spec.Shadowsocks.ChunkPayloadSize = 16383

	ctx, cancel := context.WithCancel(context.Background())
	ch, err := p.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan returned error: %v", err)
	}

	// Drain a few packets, then cancel
	go func() {
		count := 0
		for range ch {
			count++
			if count >= 5 {
				cancel()
				return
			}
		}
	}()

	// Should not block forever; channel should close after cancel
	for range ch {
	}
}

// TestPlan_SOCKS5NoAuthGreeting verifies the SOCKS5 greeting structure.
func TestPlan_SOCKS5NoAuthGreeting(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.SOCKS5Handshake = true
	spec.Shadowsocks.SOCKS5AuthMethod = "none"
	spec.Shadowsocks.SOCKS5DstAddr = "192.0.2.1"
	spec.Shadowsocks.SOCKS5DstPort = 443
	cfgs := drain(mustPlan(t, p, spec))

	// First up PSH-ACK should be the greeting: 0x05 0x01 0x00
	greeting := findFirstPayloadByDirection(cfgs, "up", 0x18)
	if greeting == nil {
		t.Fatalf("no up PSH-ACK payload found")
	}
	if len(greeting) < 3 {
		t.Fatalf("greeting too short: %d", len(greeting))
	}
	if greeting[0] != SOCKS5Ver {
		t.Errorf("greeting[0]=0x%02x, want 0x05 (VER)", greeting[0])
	}
	if greeting[1] != 0x01 {
		t.Errorf("greeting[1]=0x%02x, want 0x01 (NMETHODS=1)", greeting[1])
	}
	if greeting[2] != SOCKS5MethodNoAuth {
		t.Errorf("greeting[2]=0x%02x, want 0x00 (NO_AUTH)", greeting[2])
	}
}

// TestPlan_SOCKS5PasswordAuth verifies the username/password sub-negotiation.
func TestPlan_SOCKS5PasswordAuth(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.SOCKS5Handshake = true
	spec.Shadowsocks.SOCKS5AuthMethod = "password"
	spec.Shadowsocks.SOCKS5Username = "foo"
	spec.Shadowsocks.SOCKS5Password = "bar"
	spec.Shadowsocks.SOCKS5DstAddr = "192.0.2.1"
	spec.Shadowsocks.SOCKS5DstPort = 443
	cfgs := drain(mustPlan(t, p, spec))

	// Greeting should list PASSWORD method
	greeting := findFirstPayloadByDirection(cfgs, "up", 0x18)
	if greeting == nil {
		t.Fatalf("no greeting")
	}
	if greeting[1] != 0x01 || greeting[2] != SOCKS5MethodPassword {
		t.Errorf("greeting METHODS=0x%02x, want 0x02 (PASSWORD)", greeting[2])
	}

	// Method response should select PASSWORD
	methodResp := findFirstPayloadByDirection(cfgs, "down", 0x18)
	if methodResp == nil {
		t.Fatalf("no method response")
	}
	if methodResp[1] != SOCKS5MethodPassword {
		t.Errorf("method response=0x%02x, want 0x02 (PASSWORD)", methodResp[1])
	}

	// Auth request should be: VER(0x01) ULEN(3) UNAME("foo") PLEN(3) PASS("bar")
	authReqs := collectAllPayloadsByDirection(cfgs, "up", 0x18)
	if len(authReqs) < 2 {
		t.Fatalf("expected at least 2 up payloads (greeting + auth), got %d", len(authReqs))
	}
	authReq := authReqs[1] // greeting, then auth
	if authReq[0] != SOCKS5AuthVer {
		t.Errorf("auth VER=0x%02x, want 0x01", authReq[0])
	}
	if authReq[1] != 0x03 {
		t.Errorf("ULEN=0x%02x, want 0x03", authReq[1])
	}
	if string(authReq[2:5]) != "foo" {
		t.Errorf("UNAME=%q, want 'foo'", string(authReq[2:5]))
	}
	if authReq[5] != 0x03 {
		t.Errorf("PLEN=0x%02x, want 0x03", authReq[5])
	}
	if string(authReq[6:9]) != "bar" {
		t.Errorf("PASS=%q, want 'bar'", string(authReq[6:9]))
	}
}

// TestPlan_HTTPobfuscation verifies the HTTP CONNECT header is emitted
// before the salt.
func TestPlan_HTTPObfuscation(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.Obfuscation = "http"
	spec.Shadowsocks.SOCKS5DstAddr = "example.com"
	spec.Shadowsocks.SOCKS5DstPort = 443
	spec.Shadowsocks.Chunks = 1
	spec.Shadowsocks.ChunkPayloadSize = 100
	cfgs := drain(mustPlan(t, p, spec))

	// First up PSH-ACK should be the HTTP CONNECT header
	first := findFirstPayloadByDirection(cfgs, "up", 0x18)
	if first == nil {
		t.Fatalf("no up PSH-ACK payload")
	}
	if !strings.HasPrefix(string(first), "CONNECT example.com:443 HTTP/1.1\r\n") {
		t.Errorf("first payload does not start with CONNECT: %q", string(first[:min(50, len(first))]))
	}
	if !strings.Contains(string(first), "Host: example.com:443\r\n") {
		t.Errorf("missing Host header: %q", string(first))
	}
	if !strings.HasSuffix(string(first), "\r\n\r\n") {
		t.Errorf("missing CRLF CRLF suffix: %q", string(first))
	}
}

// TestPlan_AEADChunkLengthEncoding verifies the 2-byte length field is
// emitted for AEAD ciphers (random bytes simulating AEAD encryption).
func TestPlan_AEADChunkLengthEncoding(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.Cipher = "aes-128-gcm"
	spec.Shadowsocks.Chunks = 1
	spec.Shadowsocks.ChunkPayloadSize = 100
	cfgs := drain(mustPlan(t, p, spec))

	payloads := collectAllPayloadsByDirection(cfgs, "up", 0x18)
	if len(payloads) < 2 {
		t.Fatalf("expected at least 2 up payloads, got %d", len(payloads))
	}
	// Salt(32) + chunk(2+100+16=118) = 150 bytes total
	if len(payloads[0]) != SaltLen {
		t.Errorf("salt length=%d, want %d", len(payloads[0]), SaltLen)
	}
	if len(payloads[1]) != 118 {
		t.Errorf("chunk length=%d, want 118 (2+100+16)", len(payloads[1]))
	}
}

// TestPlan_ChaCha20Cipher verifies ChaCha20-Poly1305 cipher path.
func TestPlan_ChaCha20Cipher(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.Cipher = "chacha20-ietf-poly1305"
	spec.Shadowsocks.Chunks = 1
	spec.Shadowsocks.ChunkPayloadSize = 50
	cfgs := drain(mustPlan(t, p, spec))

	payloads := collectAllPayloadsByDirection(cfgs, "up", 0x18)
	if len(payloads) < 2 {
		t.Fatalf("expected at least 2 up payloads, got %d", len(payloads))
	}
	// Chunk: 2 + 50 + 16 = 68 bytes
	if len(payloads[1]) != 68 {
		t.Errorf("chunk length=%d, want 68 (2+50+16)", len(payloads[1]))
	}
}

// TestPlan_SIP022Cipher verifies SIP022 AEAD 2022 framework.
func TestPlan_SIP022Cipher(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.Cipher = "2022-blake3-aes-256-gcm"
	spec.Shadowsocks.Chunks = 1
	spec.Shadowsocks.ChunkPayloadSize = 100
	cfgs := drain(mustPlan(t, p, spec))

	payloads := collectAllPayloadsByDirection(cfgs, "up", 0x18)
	if len(payloads) < 2 {
		t.Fatalf("expected at least 2 up payloads, got %d", len(payloads))
	}
	// SIP022 uses same framework as SIP003: salt(32) + chunk(2+100+16=118)
	if len(payloads[0]) != SaltLen {
		t.Errorf("salt length=%d, want %d", len(payloads[0]), SaltLen)
	}
	if len(payloads[1]) != 118 {
		t.Errorf("chunk length=%d, want 118", len(payloads[1]))
	}
}

// TestPlan_DefaultCipher verifies default cipher is aes-256-gcm.
func TestPlan_DefaultCipher(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.Cipher = "" // default
	cfgs := drain(mustPlan(t, p, spec))

	// Should still produce salt + chunk + tag (default = aes-256-gcm = AEAD)
	payloads := collectAllPayloadsByDirection(cfgs, "up", 0x18)
	if len(payloads) < 2 {
		t.Fatalf("expected at least 2 up payloads, got %d", len(payloads))
	}
	// salt(32) + chunk(2+100+16=118) = 150 bytes
	if len(payloads[0]) != SaltLen {
		t.Errorf("salt length=%d, want %d", len(payloads[0]), SaltLen)
	}
	if len(payloads[1]) != 118 {
		t.Errorf("chunk length=%d, want 118 (default AEAD cipher)", len(payloads[1]))
	}
}

// TestPlan_MultipleChunks verifies multiple chunks are emitted in order.
func TestPlan_MultipleChunks(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.Chunks = 5
	spec.Shadowsocks.ChunkPayloadSize = 20
	cfgs := drain(mustPlan(t, p, spec))

	payloads := collectAllPayloadsByDirection(cfgs, "up", 0x18)
	// 1 salt + 5 chunks = 6
	if len(payloads) != 6 {
		t.Fatalf("expected 6 up payloads (salt + 5 chunks), got %d", len(payloads))
	}

	// Verify each chunk is exactly 2+20+16 = 38 bytes
	for i := 1; i < 6; i++ {
		if len(payloads[i]) != 38 {
			t.Errorf("chunk[%d] length=%d, want 38", i, len(payloads[i]))
		}
	}
}

// TestPlan_NoneCipherMultipleChunks verifies none cipher emits 2+N chunks.
func TestPlan_NoneCipherMultipleChunks(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	spec.Shadowsocks.Cipher = "none"
	spec.Shadowsocks.Chunks = 3
	spec.Shadowsocks.ChunkPayloadSize = 10
	cfgs := drain(mustPlan(t, p, spec))

	payloads := collectAllPayloadsByDirection(cfgs, "up", 0x18)
	// 3 chunks, each 2+10 = 12 bytes (no salt, no tag)
	if len(payloads) != 3 {
		t.Fatalf("expected 3 chunk payloads, got %d", len(payloads))
	}
	for i := 0; i < 3; i++ {
		if len(payloads[i]) != 12 {
			t.Errorf("chunk[%d] length=%d, want 12", i, len(payloads[i]))
		}
		// Verify length field encoding (BE uint16)
		expectedLen := uint16(10)
		actualLen := binary.BigEndian.Uint16(payloads[i][:2])
		if actualLen != expectedLen {
			t.Errorf("chunk[%d] length field=%d, want %d", i, actualLen, expectedLen)
		}
	}
}

// TestPlan_FlowID verifies all packets share the same FlowID.
func TestPlan_FlowID(t *testing.T) {
	p := NewPlanner()
	spec := validTCPSpec()
	cfgs := drain(mustPlan(t, p, spec))

	expected := "10.0.0.1-10.0.0.2-50000-8388"
	for i, c := range cfgs {
		if c.FlowID != expected {
			t.Errorf("packet[%d] FlowID=%q, want %q", i, c.FlowID, expected)
			break
		}
	}
}

// min returns the smaller of a and b.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
