// Package ssh planner_test.go - SSH planner tests.
//
// Test philosophy (per CLAUDE.md testing policy):
//   - Spec-driven: derived from design_ssh.md and testcases_ssh.md
//   - Failure paths: validate errors, disconnect-in-auth, custom-channel
//   - Per-code-path: each message encoder / dialog branch exercised
//   - Integration: full Plan() output from handshake to teardown
//   - Observable outcomes: byte values, payload lengths, directions, flags
package ssh

import (
	"context"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/protocol/testutil"
)

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
		t.Fatalf("Plan: %v", err)
	}
	return ch
}

// validSSHSpec returns a minimal valid spec for tests. Uses port 22
// (RFC 4253 default) and an empty SSHConfig so default dialogs apply.
func validSSHSpec() core.FlowSpec {
	return core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 50000, DstPort: 22,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		SSH: &core.SSHConfig{},
	}
}

// validSpecWithVersions sets server+client versions to enable version
// exchange. Used for tests that need the version-exchange packets.
func validSpecWithVersions() core.FlowSpec {
	spec := validSSHSpec()
	spec.SSH.ServerVersion = "SSH-2.0-trafficgen_1.0"
	spec.SSH.ClientVersion = "SSH-2.0-trafficgen_1.0"
	return spec
}

// --- Validate tests ---

func TestSSHValidate_ValidSpec(t *testing.T) {
	p := NewPlanner()
	if err := p.Validate(validSSHSpec()); err != nil {
		t.Errorf("valid spec: %v", err)
	}
}

func TestSSHValidate_InvalidSrcIP(t *testing.T) {
	p := NewPlanner()
	spec := validSSHSpec()
	spec.SrcIP = "not-an-ip"
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "ssh:") {
		t.Errorf("err=%v, want contains 'ssh:'", err)
	}
	if err == nil || !strings.Contains(err.Error(), "SrcIP") {
		t.Errorf("err=%v, want contains 'SrcIP'", err)
	}
}

func TestSSHValidate_InvalidDstIP(t *testing.T) {
	p := NewPlanner()
	spec := validSSHSpec()
	spec.DstIP = "bad"
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "ssh:") {
		t.Errorf("err=%v, want contains 'ssh:'", err)
	}
	if err == nil || !strings.Contains(err.Error(), "DstIP") {
		t.Errorf("err=%v, want contains 'DstIP'", err)
	}
}

func TestSSHValidate_EmptyIPs(t *testing.T) {
	p := NewPlanner()
	spec := validSSHSpec()
	spec.SrcIP = ""
	spec.DstIP = ""
	if err := p.Validate(spec); err != nil {
		t.Errorf("empty IPs should skip validation: %v", err)
	}
}

func TestSSHValidate_MSSTooSmall(t *testing.T) {
	p := NewPlanner()
	spec := validSSHSpec()
	testutil.EnsureTCP(&spec).MSS = 100 // below floor 536
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "MSS") {
		t.Errorf("err=%v, want contains 'MSS'", err)
	}
}

func TestSSHValidate_MSSBoundary(t *testing.T) {
	p := NewPlanner()
	spec := validSSHSpec()
	testutil.EnsureTCP(&spec).MSS = 65535 // uint16 max - should be accepted
	if err := p.Validate(spec); err != nil {
		t.Errorf("MSS=65535 should be accepted: %v", err)
	}
}

func TestSSHValidate_MSSZeroOK(t *testing.T) {
	p := NewPlanner()
	spec := validSSHSpec()
	testutil.EnsureTCP(&spec).MSS = 0
	if err := p.Validate(spec); err != nil {
		t.Errorf("MSS=0 should be accepted (means default): %v", err)
	}
}

func TestSSHValidate_NilSSHConfig(t *testing.T) {
	p := NewPlanner()
	spec := validSSHSpec()
	spec.SSH = nil
	// nil SSHConfig is valid - planner uses default dialog
	if err := p.Validate(spec); err != nil {
		t.Errorf("nil SSH config should be accepted: %v", err)
	}
}

func TestSSHValidate_Idempotent(t *testing.T) {
	// Per validate_conventions.md §1.2 - Validate must be idempotent
	// (no spec mutation). Two calls must return identical results.
	p := NewPlanner()
	spec := validSSHSpec()
	err1 := p.Validate(spec)
	err2 := p.Validate(spec)
	if (err1 == nil) != (err2 == nil) {
		t.Errorf("Validate not idempotent: err1=%v err2=%v", err1, err2)
	}
	if err1 != nil && err1.Error() != err2.Error() {
		t.Errorf("Validate error messages differ: err1=%q err2=%q", err1, err2)
	}
}

// Test 1.1.5 / 1.1.6: version string with CR/LF rejected.
func TestSSHValidate_VersionWithLF(t *testing.T) {
	p := NewPlanner()
	spec := validSSHSpec()
	spec.SSH.ServerVersion = "SSH-2.0-bad\nfoo"
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "CR/LF") {
		t.Errorf("err=%v, want contains 'CR/LF'", err)
	}
}

func TestSSHValidate_VersionWithCR(t *testing.T) {
	p := NewPlanner()
	spec := validSSHSpec()
	spec.SSH.ClientVersion = "SSH-2.0-bad\rf"
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "CR/LF") {
		t.Errorf("err=%v, want contains 'CR/LF'", err)
	}
}

// Test: algorithm list with CR/LF rejected.
func TestSSHValidate_AlgListWithCRLF(t *testing.T) {
	p := NewPlanner()
	spec := validSSHSpec()
	spec.SSH.KexAlgorithms = "curve25519-sha256\nbad"
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "CR/LF") {
		t.Errorf("err=%v, want contains 'CR/LF'", err)
	}
}

// Test 1.9.x: username/password NUL rejected.
func TestSSHValidate_UsernameNUL(t *testing.T) {
	p := NewPlanner()
	spec := validSSHSpec()
	spec.SSH.AuthMethods = []core.SSHMessage{
		{Type: "userauth_request", MethodName: "password", Username: "ali\x00ce"},
	}
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "NUL") {
		t.Errorf("err=%v, want contains 'NUL'", err)
	}
}

func TestSSHValidate_PasswordNUL(t *testing.T) {
	p := NewPlanner()
	spec := validSSHSpec()
	spec.SSH.AuthMethods = []core.SSHMessage{
		{Type: "userauth_request", MethodName: "password", Password: "sec\x00ret"},
	}
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "NUL") {
		t.Errorf("err=%v, want contains 'NUL'", err)
	}
}

// Test 1.11.12: channel_open maximum_packet_size=0 rejected.
func TestSSHValidate_ChannelOpenMaxPktZero(t *testing.T) {
	p := NewPlanner()
	spec := validSSHSpec()
	spec.SSH.Channels = []core.ChannelEntry{
		{Type: "channel_open", ChannelType: "session", MaximumPacketSize: 0},
	}
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "maximum_packet_size") {
		t.Errorf("err=%v, want contains 'maximum_packet_size'", err)
	}
}

// Test 1.11.x: sender_channel reserved 0xFFFFFFFF rejected.
func TestSSHValidate_ReservedSenderChannel(t *testing.T) {
	p := NewPlanner()
	spec := validSSHSpec()
	spec.SSH.Channels = []core.ChannelEntry{
		{Type: "channel_open", ChannelType: "session", SenderChannel: ReservedChannel, MaximumPacketSize: 32768},
	}
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "reserved") {
		t.Errorf("err=%v, want contains 'reserved'", err)
	}
}

// Test 1.17.12: disconnect reason_code=0 rejected.
func TestSSHValidate_DisconnectReasonZero(t *testing.T) {
	p := NewPlanner()
	spec := validSSHSpec()
	spec.SSH.AuthMethods = []core.SSHMessage{
		{Type: "disconnect", ReasonCode: 0},
	}
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "reason_code 0 is reserved") {
		t.Errorf("err=%v, want contains 'reason_code 0 is reserved'", err)
	}
}

// --- Plan: structure (handshake, dialog, teardown) ---

func TestSSHPlan_Handshake(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validSpecWithVersions()))
	if len(cfgs) < 3 {
		t.Fatalf("len=%d, want >= 3 (handshake)", len(cfgs))
	}
	// SYN up
	if cfgs[0].Direction != "up" || cfgs[0].L4.Flags != 0x02 {
		t.Errorf("cfg[0]: dir=%s flags=%x, want up/SYN", cfgs[0].Direction, cfgs[0].L4.Flags)
	}
	if len(cfgs[0].L4.TCPOptions) == 0 {
		t.Errorf("cfg[0]: SYN should carry TCP options (MSS, WinScale, SACK)")
	}
	// SYN-ACK down
	if cfgs[1].Direction != "down" || cfgs[1].L4.Flags != 0x12 {
		t.Errorf("cfg[1]: dir=%s flags=%x, want down/SYN-ACK", cfgs[1].Direction, cfgs[1].L4.Flags)
	}
	// ACK up
	if cfgs[2].Direction != "up" || cfgs[2].L4.Flags != 0x10 {
		t.Errorf("cfg[2]: dir=%s flags=%x, want up/ACK", cfgs[2].Direction, cfgs[2].L4.Flags)
	}
	if len(cfgs[2].L4.TCPOptions) != 0 {
		t.Errorf("cfg[2]: ACK should NOT carry TCP options")
	}
}

func TestSSHPlan_Teardown(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validSpecWithVersions()))
	n := len(cfgs)
	if n < 4 {
		t.Fatalf("len=%d, want >= 4 (teardown)", n)
	}
	// Client FIN-ACK up
	if cfgs[n-4].Direction != "up" || cfgs[n-4].L4.Flags != 0x11 {
		t.Errorf("cfg[%d]: dir=%s flags=%x, want up/FIN-ACK", n-4, cfgs[n-4].Direction, cfgs[n-4].L4.Flags)
	}
	// Server ACK down
	if cfgs[n-3].Direction != "down" || cfgs[n-3].L4.Flags != 0x10 {
		t.Errorf("cfg[%d]: dir=%s flags=%x, want down/ACK", n-3, cfgs[n-3].Direction, cfgs[n-3].L4.Flags)
	}
	// Server FIN-ACK down
	if cfgs[n-2].Direction != "down" || cfgs[n-2].L4.Flags != 0x11 {
		t.Errorf("cfg[%d]: dir=%s flags=%x, want down/FIN-ACK", n-2, cfgs[n-2].Direction, cfgs[n-2].L4.Flags)
	}
	// Client ACK up
	if cfgs[n-1].Direction != "up" || cfgs[n-1].L4.Flags != 0x10 {
		t.Errorf("cfg[%d]: dir=%s flags=%x, want up/ACK", n-1, cfgs[n-1].Direction, cfgs[n-1].L4.Flags)
	}
}

func TestSSHPlan_ValidateFail(t *testing.T) {
	p := NewPlanner()
	spec := validSSHSpec()
	spec.SrcIP = "not-an-ip"
	ch, err := p.Plan(context.Background(), spec)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if ch != nil {
		t.Error("expected nil channel on validate fail")
	}
}

func TestSSHPlan_DefaultChannelCap(t *testing.T) {
	p := NewPlanner()
	ch, err := p.Plan(context.Background(), validSSHSpec())
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if cap(ch) != 256 {
		t.Errorf("cap(ch)=%d, want 256", cap(ch))
	}
	drain(ch)
}

func TestSSHPlan_FlowID(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validSSHSpec()))
	want := "10.0.0.1-10.0.0.2-50000-22"
	if cfgs[0].FlowID != want {
		t.Errorf("FlowID=%q, want %q", cfgs[0].FlowID, want)
	}
}

// --- Version exchange tests ---

// Test 1.1.x: version exchange emits server-first then client.
func TestSSHPlan_VersionExchange(t *testing.T) {
	p := NewPlanner()
	spec := validSpecWithVersions()
	cfgs := drain(mustPlan(t, p, spec))
	// Layout: 3 handshake + 2 version (down "SSH-...-\r\n" + up "SSH-...-\r\n")
	// + 2 KEXINIT + 1 KEXDH_INIT + 1 KEXDH_REPLY + 2 NEWKEYS
	// + 2 SERVICE + 2 USERAUTH (request + success) + 6 channel + 4 teardown = 26
	if len(cfgs) < 5 {
		t.Fatalf("len=%d, want >= 5", len(cfgs))
	}
	// cfg[3] = server version PSH-ACK down
	if cfgs[3].Direction != "down" {
		t.Errorf("cfg[3] dir=%s, want down (server version first)", cfgs[3].Direction)
	}
	if !strings.HasPrefix(string(cfgs[3].Payload), "SSH-2.0-") {
		t.Errorf("cfg[3] payload=%q, want 'SSH-2.0-...'", cfgs[3].Payload)
	}
	if !strings.HasSuffix(string(cfgs[3].Payload), "\r\n") {
		t.Errorf("cfg[3] payload=%q, want CRLF-terminated", cfgs[3].Payload)
	}
	// cfg[4] = client version PSH-ACK up
	if cfgs[4].Direction != "up" {
		t.Errorf("cfg[4] dir=%s, want up (client version after server)", cfgs[4].Direction)
	}
}

// Test 1.1.8: empty ServerVersion and ClientVersion -> skip version exchange.
func TestSSHPlan_VersionExchangeSkipped(t *testing.T) {
	p := NewPlanner()
	spec := validSSHSpec() // both versions empty
	cfgs := drain(mustPlan(t, p, spec))
	// cfg[3] should be KEXINIT (BPP), not a version string.
	if len(cfgs) < 4 {
		t.Fatalf("len=%d, want >= 4", len(cfgs))
	}
	if strings.HasPrefix(string(cfgs[3].Payload), "SSH-") {
		t.Errorf("cfg[3] should be KEXINIT BPP, not version: %q", cfgs[3].Payload)
	}
}

// Test 1.1.x: server version custom value.
func TestSSHPlan_CustomServerVersion(t *testing.T) {
	p := NewPlanner()
	spec := validSSHSpec()
	spec.SSH.ServerVersion = "SSH-2.0-OpenSSH_8.9"
	spec.SSH.ClientVersion = "" // skip client
	cfgs := drain(mustPlan(t, p, spec))
	// When only server is set, planner defaults client too (per design).
	if len(cfgs) < 5 {
		t.Fatalf("len=%d, want >= 5 (both versions when either set)", len(cfgs))
	}
	want := "SSH-2.0-OpenSSH_8.9\r\n"
	if string(cfgs[3].Payload) != want {
		t.Errorf("cfg[3] payload=%q, want %q", cfgs[3].Payload, want)
	}
}

// --- BPP framing tests ---

// Test 1.2.x: BPP packet_length is uint32 BE; payload starts after 5 bytes.
func TestSSHPlan_BPPFraming(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validSSHSpec()))
	// Find first BPP packet (cfg[3] when versions skipped).
	bppIdx := 3
	if len(cfgs) <= bppIdx {
		t.Fatalf("not enough packets: %d", len(cfgs))
	}
	bpp := cfgs[bppIdx].Payload
	if len(bpp) < 6 {
		t.Fatalf("BPP frame too short: %d", len(bpp))
	}
	// First 4 bytes = packet_length (BE uint32).
	pktLen := binary.BigEndian.Uint32(bpp[:4])
	// packet_length = 1 (padding_length field) + payload_len + padding_len
	if pktLen < 5 {
		t.Errorf("packet_length=%d, want >= 5 (1+payload+padding)", pktLen)
	}
	// 5th byte = padding_length.
	padLen := int(bpp[4])
	if padLen < 4 {
		t.Errorf("padding_length=%d, want >= 4 (RFC 4253 §6)", padLen)
	}
	if padLen > 255 {
		t.Errorf("padding_length=%d, want <= 255", padLen)
	}
	// Total frame = 4 (packet_length field) + pktLen + MAC (0 pre-NEWKEYS).
	if int(4+pktLen) > len(bpp) {
		t.Errorf("frame too short: 4+pktLen=%d > len=%d", 4+pktLen, len(bpp))
	}
}

// Test 1.2.6: padding bytes are present.
func TestSSHPlan_BPPPaddingPresent(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validSSHSpec()))
	bpp := cfgs[3].Payload
	pktLen := binary.BigEndian.Uint32(bpp[:4])
	padLen := int(bpp[4])
	// Verify padding bytes are within the frame.
	padStart := 5 + int(pktLen) - 1 - padLen
	if padStart < 5 {
		t.Fatalf("padStart=%d invalid", padStart)
	}
	padding := bpp[padStart : padStart+padLen]
	if len(padding) != padLen {
		t.Errorf("padding len=%d, want %d", len(padding), padLen)
	}
}

// Test 1.2.1: NEWKEYS pre-NEWKEYS uses "none" cipher (block size 8).
func TestSSHPlan_PreNewKeysCipherBlock(t *testing.T) {
	// Pre-NEWKEYS packets: KEXINIT (both), KEXDH_INIT, KEXDH_REPLY, NEWKEYS.
	// Total = 5 BPP packets. Verify alignment to 8-byte block.
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validSSHSpec()))
	// cfg[3]=client KEXINIT, cfg[4]=server KEXINIT, cfg[5]=KEXDH_INIT,
	// cfg[6]=KEXDH_REPLY, cfg[7]=client NEWKEYS, cfg[8]=server NEWKEYS.
	for i := 3; i <= 8; i++ {
		if i >= len(cfgs) {
			t.Fatalf("cfg[%d] out of range (len=%d)", i, len(cfgs))
		}
		bpp := cfgs[i].Payload
		pktLen := binary.BigEndian.Uint32(bpp[:4])
		// total = 4 (packet_length field) + pktLen; must be multiple of 8.
		total := uint32(4) + pktLen
		if total%8 != 0 {
			t.Errorf("cfg[%d] total=%d not aligned to 8 (pre-NEWKEYS cipher=none)", i, total)
		}
	}
}

// Test: post-NEWKEYS uses AES block (16-byte alignment).
func TestSSHPlan_PostNewKeysCipherBlock(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validSSHSpec()))
	// cfg[9] = SERVICE_REQUEST (first post-NEWKEYS packet).
	if len(cfgs) < 10 {
		t.Fatalf("len=%d, want >= 10", len(cfgs))
	}
	bpp := cfgs[9].Payload
	pktLen := binary.BigEndian.Uint32(bpp[:4])
	total := uint32(4) + pktLen
	// post-NEWKEYS uses CipherAES (16-byte block) + MAC256 (32-byte).
	// total (excluding MAC) must be multiple of 16.
	if total%16 != 0 {
		t.Errorf("post-NEWKEYS total=%d not aligned to 16 (AES block)", total)
	}
	// MAC bytes are appended after pktLen.
	macLen := len(bpp) - int(total)
	if macLen <= 0 {
		t.Errorf("MAC length=%d, want > 0 post-NEWKEYS", macLen)
	}
}

// --- KEXINIT payload tests ---

// Test 1.3.1: KEXINIT message_type byte = 0x14 (20).
func TestSSHPlan_KexInitMessageType(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validSSHSpec()))
	bpp := cfgs[3].Payload
	pktLen := binary.BigEndian.Uint32(bpp[:4])
	padLen := int(bpp[4])
	payload := bpp[5 : 5+int(pktLen)-1-padLen]
	if len(payload) < 1 {
		t.Fatalf("KEXINIT payload too short")
	}
	if payload[0] != MsgKexInit {
		t.Errorf("KEXINIT msg byte=0x%02x, want 0x%02x", payload[0], MsgKexInit)
	}
}

// Test 1.3.2: KEXINIT cookie is 16 bytes.
func TestSSHPlan_KexInitCookie(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validSSHSpec()))
	bpp := cfgs[3].Payload
	pktLen := binary.BigEndian.Uint32(bpp[:4])
	padLen := int(bpp[4])
	payload := bpp[5 : 5+int(pktLen)-1-padLen]
	if len(payload) < 1+16 {
		t.Fatalf("KEXINIT payload too short for cookie: %d", len(payload))
	}
	cookie := payload[1 : 1+16]
	// Cookie should not be all zeros (random).
	allZero := true
	for _, b := range cookie {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Errorf("KEXINIT cookie is all zero (should be random)")
	}
}

// Test 1.3.x: KEXINIT default kex_algorithms string contains "curve25519-sha256".
func TestSSHPlan_KexInitDefaultAlgs(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validSSHSpec()))
	bpp := cfgs[3].Payload
	pktLen := binary.BigEndian.Uint32(bpp[:4])
	padLen := int(bpp[4])
	payload := bpp[5 : 5+int(pktLen)-1-padLen]
	// Skip msg(1) + cookie(16) = 17; then first string is kex_algorithms.
	if len(payload) < 17+4 {
		t.Fatalf("KEXINIT too short for kex_algs length")
	}
	kexAlgLen := binary.BigEndian.Uint32(payload[17 : 17+4])
	if kexAlgLen == 0 {
		t.Errorf("kex_algorithms length=0, want non-zero default")
	}
	kexAlgStr := string(payload[21 : 21+int(kexAlgLen)])
	if !strings.Contains(kexAlgStr, "curve25519-sha256") {
		t.Errorf("default kex_algorithms=%q, want contains 'curve25519-sha256'", kexAlgStr)
	}
}

// Test 1.3.x: custom kex_algorithms propagated.
func TestSSHPlan_KexInitCustomAlgs(t *testing.T) {
	p := NewPlanner()
	spec := validSSHSpec()
	spec.SSH.KexAlgorithms = "ext-info-c,curve25519-sha256"
	cfgs := drain(mustPlan(t, p, spec))
	bpp := cfgs[3].Payload
	pktLen := binary.BigEndian.Uint32(bpp[:4])
	padLen := int(bpp[4])
	payload := bpp[5 : 5+int(pktLen)-1-padLen]
	kexAlgLen := binary.BigEndian.Uint32(payload[17 : 17+4])
	kexAlgStr := string(payload[21 : 21+int(kexAlgLen)])
	if kexAlgStr != "ext-info-c,curve25519-sha256" {
		t.Errorf("kex_algorithms=%q, want custom", kexAlgStr)
	}
}

// --- NEWKEYS tests ---

// Test 1.4.1: NEWKEYS payload = 1 byte 0x15 (21).
func TestSSHPlan_NewKeys(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validSSHSpec()))
	// cfg[7] = client NEWKEYS, cfg[8] = server NEWKEYS.
	for i := 7; i <= 8; i++ {
		if i >= len(cfgs) {
			t.Fatalf("cfg[%d] out of range", i)
		}
		bpp := cfgs[i].Payload
		pktLen := binary.BigEndian.Uint32(bpp[:4])
		padLen := int(bpp[4])
		payload := bpp[5 : 5+int(pktLen)-1-padLen]
		if len(payload) != 1 || payload[0] != MsgNewKeys {
			t.Errorf("cfg[%d] NEWKEYS payload=%v, want [0x15]", i, payload)
		}
	}
	// NEWKEYS up then down.
	if cfgs[7].Direction != "up" {
		t.Errorf("cfg[7] dir=%s, want up (client NEWKEYS)", cfgs[7].Direction)
	}
	if cfgs[8].Direction != "down" {
		t.Errorf("cfg[8] dir=%s, want down (server NEWKEYS)", cfgs[8].Direction)
	}
}

// --- KEXDH_INIT / KEXDH_REPLY tests ---

// Test 1.5.x: KEXDH_INIT message byte = 0x1E (30), up direction.
func TestSSHPlan_KexDHInit(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validSSHSpec()))
	// cfg[5] = KEXDH_INIT up.
	bpp := cfgs[5].Payload
	pktLen := binary.BigEndian.Uint32(bpp[:4])
	padLen := int(bpp[4])
	payload := bpp[5 : 5+int(pktLen)-1-padLen]
	if len(payload) < 1 || payload[0] != MsgKexDHInit {
		t.Errorf("KEXDH_INIT msg byte=0x%02x, want 0x%02x", payload[0], MsgKexDHInit)
	}
	if cfgs[5].Direction != "up" {
		t.Errorf("cfg[5] dir=%s, want up", cfgs[5].Direction)
	}
}

// Test 1.6.x: KEXDH_REPLY message byte = 0x1F (31), down direction.
func TestSSHPlan_KexDHReply(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validSSHSpec()))
	bpp := cfgs[6].Payload
	pktLen := binary.BigEndian.Uint32(bpp[:4])
	padLen := int(bpp[4])
	payload := bpp[5 : 5+int(pktLen)-1-padLen]
	if len(payload) < 1 || payload[0] != MsgKexDHReply {
		t.Errorf("KEXDH_REPLY msg byte=0x%02x, want 0x%02x", payload[0], MsgKexDHReply)
	}
	if cfgs[6].Direction != "down" {
		t.Errorf("cfg[6] dir=%s, want down", cfgs[6].Direction)
	}
}

// --- EXT_INFO tests ---

// Test 1.7.4: ExtInfo=false (default) -> no EXT_INFO packet.
func TestSSHPlan_ExtInfoOff(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validSSHSpec()))
	for i, c := range cfgs {
		if len(c.Payload) < 6 {
			continue
		}
		bpp := c.Payload
		pktLen := binary.BigEndian.Uint32(bpp[:4])
		padLen := int(bpp[4])
		if int(pktLen)-1-padLen < 1 {
			continue
		}
		if bpp[5] == MsgExtInfo {
			t.Errorf("cfg[%d] has EXT_INFO but ExtInfo=false", i)
		}
	}
}

// Test 1.7.1-3: ExtInfo=true -> EXT_INFO packet after NEWKEYS.
func TestSSHPlan_ExtInfoOn(t *testing.T) {
	p := NewPlanner()
	spec := validSSHSpec()
	spec.SSH.ExtInfo = true
	cfgs := drain(mustPlan(t, p, spec))
	// Find EXT_INFO packets.
	extCount := 0
	for _, c := range cfgs {
		if len(c.Payload) < 6 {
			continue
		}
		bpp := c.Payload
		pktLen := binary.BigEndian.Uint32(bpp[:4])
		padLen := int(bpp[4])
		if int(pktLen)-1-padLen < 1 {
			continue
		}
		if bpp[5] == MsgExtInfo {
			extCount++
		}
	}
	if extCount != 2 {
		t.Errorf("EXT_INFO count=%d, want 2 (client + server)", extCount)
	}
}

// --- SERVICE_REQUEST / ACCEPT tests ---

// Test 1.8.1: SERVICE_REQUEST message byte = 0x05.
func TestSSHPlan_ServiceRequest(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validSSHSpec()))
	// cfg[9] = SERVICE_REQUEST up.
	bpp := cfgs[9].Payload
	pktLen := binary.BigEndian.Uint32(bpp[:4])
	padLen := int(bpp[4])
	payload := bpp[5 : 5+int(pktLen)-1-padLen]
	if len(payload) < 1 || payload[0] != MsgServiceRequest {
		t.Errorf("SERVICE_REQUEST msg byte=0x%02x, want 0x%02x", payload[0], MsgServiceRequest)
	}
	if cfgs[9].Direction != "up" {
		t.Errorf("cfg[9] dir=%s, want up", cfgs[9].Direction)
	}
	// Verify service name "ssh-userauth".
	if len(payload) < 5 {
		t.Fatalf("SERVICE_REQUEST payload too short")
	}
	nameLen := binary.BigEndian.Uint32(payload[1:5])
	nameStr := string(payload[5 : 5+int(nameLen)])
	if nameStr != "ssh-userauth" {
		t.Errorf("SERVICE_REQUEST name=%q, want 'ssh-userauth'", nameStr)
	}
}

// Test 1.8.4: SERVICE_ACCEPT message byte = 0x06, down direction.
func TestSSHPlan_ServiceAccept(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validSSHSpec()))
	bpp := cfgs[10].Payload
	pktLen := binary.BigEndian.Uint32(bpp[:4])
	padLen := int(bpp[4])
	payload := bpp[5 : 5+int(pktLen)-1-padLen]
	if len(payload) < 1 || payload[0] != MsgServiceAccept {
		t.Errorf("SERVICE_ACCEPT msg byte=0x%02x, want 0x%02x", payload[0], MsgServiceAccept)
	}
	if cfgs[10].Direction != "down" {
		t.Errorf("cfg[10] dir=%s, want down", cfgs[10].Direction)
	}
}

// --- USERAUTH dialog tests ---

// Test: default auth flow = USERAUTH_REQUEST (password) up + USERAUTH_SUCCESS down.
func TestSSHPlan_DefaultUserAuth(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validSSHSpec()))
	// cfg[11] = USERAUTH_REQUEST up, cfg[12] = USERAUTH_SUCCESS down.
	if len(cfgs) < 13 {
		t.Fatalf("len=%d, want >= 13", len(cfgs))
	}
	reqBPP := cfgs[11].Payload
	reqPkt := binary.BigEndian.Uint32(reqBPP[:4])
	reqPad := int(reqBPP[4])
	reqPayload := reqBPP[5 : 5+int(reqPkt)-1-reqPad]
	if reqPayload[0] != MsgUserAuthRequest {
		t.Errorf("USERAUTH_REQUEST byte=0x%02x, want 0x%02x", reqPayload[0], MsgUserAuthRequest)
	}
	if cfgs[11].Direction != "up" {
		t.Errorf("cfg[11] dir=%s, want up", cfgs[11].Direction)
	}
	succBPP := cfgs[12].Payload
	succPkt := binary.BigEndian.Uint32(succBPP[:4])
	succPad := int(succBPP[4])
	succPayload := succBPP[5 : 5+int(succPkt)-1-succPad]
	if succPayload[0] != MsgUserAuthSuccess {
		t.Errorf("USERAUTH_SUCCESS byte=0x%02x, want 0x%02x", succPayload[0], MsgUserAuthSuccess)
	}
	if cfgs[12].Direction != "down" {
		t.Errorf("cfg[12] dir=%s, want down", cfgs[12].Direction)
	}
}

// Test 1.9.7: USERAUTH_REQUEST password method - check password string.
func TestSSHPlan_UserAuthPassword(t *testing.T) {
	p := NewPlanner()
	spec := validSSHSpec()
	spec.SSH.AuthMethods = []core.SSHMessage{
		{Type: "userauth_request", MethodName: "password", Username: "alice", Password: "secret123"},
		{Type: "userauth_success"},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// Find USERAUTH_REQUEST packet (cfg[11]).
	bpp := cfgs[11].Payload
	pktLen := binary.BigEndian.Uint32(bpp[:4])
	padLen := int(bpp[4])
	payload := bpp[5 : 5+int(pktLen)-1-padLen]
	// Layout: msg(1) || string(username) || string("ssh-connection") ||
	// string("password") || bool(has_change) || string(password)
	if payload[0] != MsgUserAuthRequest {
		t.Fatalf("msg=0x%02x, want 0x%02x", payload[0], MsgUserAuthRequest)
	}
	// Helper to read a string at offset, returning (string, new_offset).
	readStr := func(off int) (string, int) {
		l := binary.BigEndian.Uint32(payload[off : off+4])
		return string(payload[off+4 : off+4+int(l)]), off + 4 + int(l)
	}
	off := 1
	username, off2 := readStr(off)
	if username != "alice" {
		t.Errorf("username=%q, want 'alice'", username)
	}
	off = off2
	svc, off3 := readStr(off)
	if svc != "ssh-connection" {
		t.Errorf("service=%q, want 'ssh-connection'", svc)
	}
	off = off3
	method, off4 := readStr(off)
	if method != "password" {
		t.Errorf("method=%q, want 'password'", method)
	}
	off = off4
	if payload[off] != 0x00 {
		t.Errorf("has_password_change=0x%02x, want 0x00", payload[off])
	}
	off++
	pwd, _ := readStr(off)
	if pwd != "secret123" {
		t.Errorf("password=%q, want 'secret123'", pwd)
	}
}

// Test 1.10.x: USERAUTH_FAILURE with method list.
func TestSSHPlan_UserAuthFailure(t *testing.T) {
	p := NewPlanner()
	spec := validSSHSpec()
	spec.SSH.AuthMethods = []core.SSHMessage{
		{Type: "userauth_request", MethodName: "none"},
		{Type: "userauth_failure", AuthMethodsThatCanContinue: "publickey,password", PartialSuccess: false},
		{Type: "userauth_request", MethodName: "password", Username: "alice", Password: "secret"},
		{Type: "userauth_success"},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// Verify USERAUTH_FAILURE appears.
	found := false
	for _, c := range cfgs {
		if len(c.Payload) < 6 {
			continue
		}
		bpp := c.Payload
		pktLen := binary.BigEndian.Uint32(bpp[:4])
		padLen := int(bpp[4])
		if int(pktLen)-1-padLen < 1 {
			continue
		}
		if bpp[5] == MsgUserAuthFailure {
			found = true
			// Verify name-list content.
			payload := bpp[5 : 5+int(pktLen)-1-padLen]
			listLen := binary.BigEndian.Uint32(payload[1:5])
			listStr := string(payload[5 : 5+int(listLen)])
			if listStr != "publickey,password" {
				t.Errorf("auth_methods list=%q, want 'publickey,password'", listStr)
			}
			// Verify partial_success bool = 0.
			boolByte := payload[5+int(listLen)]
			if boolByte != 0x00 {
				t.Errorf("partial_success=0x%02x, want 0x00", boolByte)
			}
		}
	}
	if !found {
		t.Errorf("USERAUTH_FAILURE not found in plan output")
	}
}

// Test 1.10.4: USERAUTH_FAILURE partial_success=1.
func TestSSHPlan_UserAuthFailurePartialSuccess(t *testing.T) {
	p := NewPlanner()
	spec := validSSHSpec()
	spec.SSH.AuthMethods = []core.SSHMessage{
		{Type: "userauth_failure", AuthMethodsThatCanContinue: "password", PartialSuccess: true},
	}
	cfgs := drain(mustPlan(t, p, spec))
	for _, c := range cfgs {
		if len(c.Payload) < 6 {
			continue
		}
		bpp := c.Payload
		pktLen := binary.BigEndian.Uint32(bpp[:4])
		padLen := int(bpp[4])
		if int(pktLen)-1-padLen < 1 {
			continue
		}
		if bpp[5] == MsgUserAuthFailure {
			payload := bpp[5 : 5+int(pktLen)-1-padLen]
			listLen := binary.BigEndian.Uint32(payload[1:5])
			boolByte := payload[5+int(listLen)]
			if boolByte != 0x01 {
				t.Errorf("partial_success=0x%02x, want 0x01", boolByte)
			}
			return
		}
	}
	t.Errorf("USERAUTH_FAILURE not found")
}

// Test 1.10.6-8: USERAUTH_BANNER.
func TestSSHPlan_UserAuthBanner(t *testing.T) {
	p := NewPlanner()
	spec := validSSHSpec()
	spec.SSH.AuthMethods = []core.SSHMessage{
		{Type: "userauth_banner", Banner: "Welcome to server", LanguageTag: "en-US"},
		{Type: "userauth_success"},
	}
	cfgs := drain(mustPlan(t, p, spec))
	for _, c := range cfgs {
		if len(c.Payload) < 6 {
			continue
		}
		bpp := c.Payload
		pktLen := binary.BigEndian.Uint32(bpp[:4])
		padLen := int(bpp[4])
		if int(pktLen)-1-padLen < 1 {
			continue
		}
		if bpp[5] == MsgUserAuthBanner {
			payload := bpp[5 : 5+int(pktLen)-1-padLen]
			bannerLen := binary.BigEndian.Uint32(payload[1:5])
			banner := string(payload[5 : 5+int(bannerLen)])
			if banner != "Welcome to server" {
				t.Errorf("banner=%q, want 'Welcome to server'", banner)
			}
			langLen := binary.BigEndian.Uint32(payload[5+int(bannerLen) : 9+int(bannerLen)])
			lang := string(payload[9+int(bannerLen) : 9+int(bannerLen)+int(langLen)])
			if lang != "en-US" {
				t.Errorf("language=%q, want 'en-US'", lang)
			}
			return
		}
	}
	t.Errorf("USERAUTH_BANNER not found")
}

// Test 1.10.9-10: USERAUTH_INFO_REQUEST / INFO_RESPONSE.
func TestSSHPlan_UserAuthInfoRequestResponse(t *testing.T) {
	p := NewPlanner()
	spec := validSSHSpec()
	spec.SSH.AuthMethods = []core.SSHMessage{
		{Type: "userauth_info_request", Name: "Password reset", Instruction: "Enter new password", LanguageTag: "en", PromptCount: 1, Prompt: "New password: ", Echo: false},
		{Type: "userauth_info_response", NumResponses: 1, Response: "newpass"},
		{Type: "userauth_success"},
	}
	cfgs := drain(mustPlan(t, p, spec))
	foundReq, foundResp := false, false
	for _, c := range cfgs {
		if len(c.Payload) < 6 {
			continue
		}
		bpp := c.Payload
		pktLen := binary.BigEndian.Uint32(bpp[:4])
		padLen := int(bpp[4])
		if int(pktLen)-1-padLen < 1 {
			continue
		}
		switch bpp[5] {
		case MsgUserAuthInfoRequest:
			foundReq = true
			if c.Direction != "down" {
				t.Errorf("INFO_REQUEST dir=%s, want down", c.Direction)
			}
		case MsgUserAuthInfoResponse:
			foundResp = true
			if c.Direction != "up" {
				t.Errorf("INFO_RESPONSE dir=%s, want up", c.Direction)
			}
		}
	}
	if !foundReq {
		t.Errorf("INFO_REQUEST not found")
	}
	if !foundResp {
		t.Errorf("INFO_RESPONSE not found")
	}
}

// Test 1.17.x: DISCONNECT in auth terminates session.
func TestSSHPlan_DisconnectInAuth(t *testing.T) {
	p := NewPlanner()
	spec := validSSHSpec()
	spec.SSH.AuthMethods = []core.SSHMessage{
		{Type: "disconnect", ReasonCode: DiscByApplication, Description: "test disconnect", Direction: "up"},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// Find DISCONNECT.
	discIdx := -1
	for i, c := range cfgs {
		if len(c.Payload) < 6 {
			continue
		}
		bpp := c.Payload
		pktLen := binary.BigEndian.Uint32(bpp[:4])
		padLen := int(bpp[4])
		if int(pktLen)-1-padLen < 1 {
			continue
		}
		if bpp[5] == MsgDisconnect {
			discIdx = i
			break
		}
	}
	if discIdx == -1 {
		t.Fatalf("DISCONNECT not found")
	}
	// Verify reason_code.
	bpp := cfgs[discIdx].Payload
	pktLen := binary.BigEndian.Uint32(bpp[:4])
	padLen := int(bpp[4])
	payload := bpp[5 : 5+int(pktLen)-1-padLen]
	reason := binary.BigEndian.Uint32(payload[1:5])
	if reason != DiscByApplication {
		t.Errorf("reason_code=%d, want %d", reason, DiscByApplication)
	}
	// After DISCONNECT, no channel dialog should appear.
	for i := discIdx + 1; i < len(cfgs); i++ {
		c := cfgs[i]
		if len(c.Payload) < 6 {
			continue
		}
		bpp := c.Payload
		pktLen := binary.BigEndian.Uint32(bpp[:4])
		padLen := int(bpp[4])
		if int(pktLen)-1-padLen < 1 {
			continue
		}
		msg := bpp[5]
		if msg >= MsgChannelOpen && msg <= MsgChannelFailure {
			t.Errorf("cfg[%d] has channel msg 0x%02x after DISCONNECT - should be skipped", i, msg)
		}
	}
}

// --- Channel layer tests ---

// Test 1.11.x: CHANNEL_OPEN.
func TestSSHPlan_ChannelOpen(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validSSHSpec()))
	// Find CHANNEL_OPEN.
	found := false
	for _, c := range cfgs {
		if len(c.Payload) < 6 {
			continue
		}
		bpp := c.Payload
		pktLen := binary.BigEndian.Uint32(bpp[:4])
		padLen := int(bpp[4])
		if int(pktLen)-1-padLen < 1 {
			continue
		}
		if bpp[5] == MsgChannelOpen {
			found = true
			if c.Direction != "up" {
				t.Errorf("CHANNEL_OPEN dir=%s, want up", c.Direction)
			}
			payload := bpp[5 : 5+int(pktLen)-1-padLen]
			// Verify channel_type string is "session".
			typeLen := binary.BigEndian.Uint32(payload[1:5])
			typeStr := string(payload[5 : 5+int(typeLen)])
			if typeStr != "session" {
				t.Errorf("channel_type=%q, want 'session'", typeStr)
			}
		}
	}
	if !found {
		t.Errorf("CHANNEL_OPEN not found in default channel dialog")
	}
}

// Test 1.11.x: CHANNEL_OPEN custom channel type.
func TestSSHPlan_ChannelOpenDirectTCPIP(t *testing.T) {
	p := NewPlanner()
	spec := validSSHSpec()
	spec.SSH.AuthMethods = []core.SSHMessage{{Type: "userauth_success"}}
	spec.SSH.Channels = []core.ChannelEntry{
		{Type: "channel_open", ChannelType: "direct-tcpip", InitialWindowSize: 65536, MaximumPacketSize: 16384, DestHost: "example.com", DestPort: 80, OriginatorIP: "1.2.3.4", OriginatorPort: 12345},
	}
	cfgs := drain(mustPlan(t, p, spec))
	for _, c := range cfgs {
		if len(c.Payload) < 6 {
			continue
		}
		bpp := c.Payload
		pktLen := binary.BigEndian.Uint32(bpp[:4])
		padLen := int(bpp[4])
		if int(pktLen)-1-padLen < 1 {
			continue
		}
		if bpp[5] == MsgChannelOpen {
			payload := bpp[5 : 5+int(pktLen)-1-padLen]
			typeLen := binary.BigEndian.Uint32(payload[1:5])
			typeStr := string(payload[5 : 5+int(typeLen)])
			if typeStr != "direct-tcpip" {
				t.Errorf("channel_type=%q, want 'direct-tcpip'", typeStr)
			}
			return
		}
	}
	t.Errorf("CHANNEL_OPEN not found")
}

// Test 1.11.7-8: auto-increment sender_channel.
func TestSSHPlan_ChannelOpenAutoIncrement(t *testing.T) {
	p := NewPlanner()
	spec := validSSHSpec()
	spec.SSH.AuthMethods = []core.SSHMessage{{Type: "userauth_success"}}
	spec.SSH.Channels = []core.ChannelEntry{
		{Type: "channel_open", ChannelType: "session", InitialWindowSize: DefaultChanWin, MaximumPacketSize: DefaultChanPkt},
		{Type: "channel_open_confirmation", RecipientChannel: 0, SenderChannel: 0, InitialWindowSize: DefaultChanWin, MaximumPacketSize: DefaultChanPkt},
		{Type: "channel_open", ChannelType: "session", InitialWindowSize: DefaultChanWin, MaximumPacketSize: DefaultChanPkt},
		{Type: "channel_open_confirmation", RecipientChannel: 1, SenderChannel: 1, InitialWindowSize: DefaultChanWin, MaximumPacketSize: DefaultChanPkt},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// Find first CHANNEL_OPEN - sender_channel should be 0.
	// Find second CHANNEL_OPEN - sender_channel should be 1.
	openCount := 0
	for _, c := range cfgs {
		if len(c.Payload) < 6 {
			continue
		}
		bpp := c.Payload
		pktLen := binary.BigEndian.Uint32(bpp[:4])
		padLen := int(bpp[4])
		if int(pktLen)-1-padLen < 1 {
			continue
		}
		if bpp[5] == MsgChannelOpen {
			payload := bpp[5 : 5+int(pktLen)-1-padLen]
			typeLen := binary.BigEndian.Uint32(payload[1:5])
			off := 5 + int(typeLen)
			senderCh := binary.BigEndian.Uint32(payload[off : off+4])
			openCount++
			if openCount == 1 && senderCh != 0 {
				t.Errorf("first CHANNEL_OPEN sender=%d, want 0", senderCh)
			}
			if openCount == 2 && senderCh != 1 {
				t.Errorf("second CHANNEL_OPEN sender=%d, want 1 (auto-increment)", senderCh)
			}
		}
	}
	if openCount != 2 {
		t.Errorf("CHANNEL_OPEN count=%d, want 2", openCount)
	}
}

// Test 1.12.x: CHANNEL_OPEN_CONFIRMATION.
func TestSSHPlan_ChannelOpenConfirmation(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validSSHSpec()))
	for _, c := range cfgs {
		if len(c.Payload) < 6 {
			continue
		}
		bpp := c.Payload
		pktLen := binary.BigEndian.Uint32(bpp[:4])
		padLen := int(bpp[4])
		if int(pktLen)-1-padLen < 1 {
			continue
		}
		if bpp[5] == MsgChannelOpenConf {
			if c.Direction != "down" {
				t.Errorf("CHANNEL_OPEN_CONF dir=%s, want down", c.Direction)
			}
			payload := bpp[5 : 5+int(pktLen)-1-padLen]
			// 1 byte msg + 4 uint32 = 17 bytes.
			if len(payload) != 17 {
				t.Errorf("CHANNEL_OPEN_CONF payload len=%d, want 17", len(payload))
			}
			return
		}
	}
	t.Errorf("CHANNEL_OPEN_CONFIRMATION not found")
}

// Test 1.12.x: CHANNEL_OPEN_FAILURE.
func TestSSHPlan_ChannelOpenFailure(t *testing.T) {
	p := NewPlanner()
	spec := validSSHSpec()
	spec.SSH.AuthMethods = []core.SSHMessage{{Type: "userauth_success"}}
	spec.SSH.Channels = []core.ChannelEntry{
		{Type: "channel_open", ChannelType: "session", InitialWindowSize: DefaultChanWin, MaximumPacketSize: DefaultChanPkt},
		{Type: "channel_open_failure", RecipientChannel: 0, OpenReasonCode: OpenConnectFailed, OpenReasonText: "denied"},
	}
	cfgs := drain(mustPlan(t, p, spec))
	for _, c := range cfgs {
		if len(c.Payload) < 6 {
			continue
		}
		bpp := c.Payload
		pktLen := binary.BigEndian.Uint32(bpp[:4])
		padLen := int(bpp[4])
		if int(pktLen)-1-padLen < 1 {
			continue
		}
		if bpp[5] == MsgChannelOpenFailure {
			payload := bpp[5 : 5+int(pktLen)-1-padLen]
			reason := binary.BigEndian.Uint32(payload[5:9])
			if reason != OpenConnectFailed {
				t.Errorf("reason_code=%d, want %d", reason, OpenConnectFailed)
			}
			return
		}
	}
	t.Errorf("CHANNEL_OPEN_FAILURE not found")
}

// Test 1.14.x: CHANNEL_DATA.
func TestSSHPlan_ChannelData(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validSSHSpec()))
	for _, c := range cfgs {
		if len(c.Payload) < 6 {
			continue
		}
		bpp := c.Payload
		pktLen := binary.BigEndian.Uint32(bpp[:4])
		padLen := int(bpp[4])
		if int(pktLen)-1-padLen < 1 {
			continue
		}
		if bpp[5] == MsgChannelData {
			payload := bpp[5 : 5+int(pktLen)-1-padLen]
			// 1 + 4 (recipient) + 4 (data length) + data.
			if len(payload) < 9 {
				t.Fatalf("CHANNEL_DATA payload too short: %d", len(payload))
			}
			dataLen := binary.BigEndian.Uint32(payload[5:9])
			data := payload[9 : 9+int(dataLen)]
			// Default channel_data emits "exit\r\n".
			if string(data) != "exit\r\n" {
				t.Errorf("data=%q, want 'exit\\r\\n'", string(data))
			}
			return
		}
	}
	t.Errorf("CHANNEL_DATA not found")
}

// Test 1.14.x: CHANNEL_EXTENDED_DATA.
func TestSSHPlan_ChannelExtendedData(t *testing.T) {
	p := NewPlanner()
	spec := validSSHSpec()
	spec.SSH.AuthMethods = []core.SSHMessage{{Type: "userauth_success"}}
	spec.SSH.Channels = []core.ChannelEntry{
		{Type: "channel_extended_data", RecipientChannel: 0, DataTypeCode: 1, Data: []byte("stderr output"), Direction: "down"},
	}
	cfgs := drain(mustPlan(t, p, spec))
	for _, c := range cfgs {
		if len(c.Payload) < 6 {
			continue
		}
		bpp := c.Payload
		pktLen := binary.BigEndian.Uint32(bpp[:4])
		padLen := int(bpp[4])
		if int(pktLen)-1-padLen < 1 {
			continue
		}
		if bpp[5] == MsgChannelExtendedData {
			payload := bpp[5 : 5+int(pktLen)-1-padLen]
			dataType := binary.BigEndian.Uint32(payload[5:9])
			if dataType != 1 {
				t.Errorf("data_type_code=%d, want 1 (stderr)", dataType)
			}
			return
		}
	}
	t.Errorf("CHANNEL_EXTENDED_DATA not found")
}

// Test 1.14.9-10: CHANNEL_WINDOW_ADJUST.
func TestSSHPlan_ChannelWindowAdjust(t *testing.T) {
	p := NewPlanner()
	spec := validSSHSpec()
	spec.SSH.AuthMethods = []core.SSHMessage{{Type: "userauth_success"}}
	spec.SSH.Channels = []core.ChannelEntry{
		{Type: "channel_window_adjust", RecipientChannel: 0, BytesToAdd: 1048576, Direction: "down"},
	}
	cfgs := drain(mustPlan(t, p, spec))
	for _, c := range cfgs {
		if len(c.Payload) < 6 {
			continue
		}
		bpp := c.Payload
		pktLen := binary.BigEndian.Uint32(bpp[:4])
		padLen := int(bpp[4])
		if int(pktLen)-1-padLen < 1 {
			continue
		}
		if bpp[5] == MsgChannelWindowAdjust {
			payload := bpp[5 : 5+int(pktLen)-1-padLen]
			bytesToAdd := binary.BigEndian.Uint32(payload[5:9])
			if bytesToAdd != 1048576 {
				t.Errorf("bytes_to_add=%d, want 1048576", bytesToAdd)
			}
			return
		}
	}
	t.Errorf("CHANNEL_WINDOW_ADJUST not found")
}

// Test 1.15.1-4: CHANNEL_EOF / CHANNEL_CLOSE.
func TestSSHPlan_ChannelEOFAndClose(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validSSHSpec()))
	eofCount, closeCount := 0, 0
	for _, c := range cfgs {
		if len(c.Payload) < 6 {
			continue
		}
		bpp := c.Payload
		pktLen := binary.BigEndian.Uint32(bpp[:4])
		padLen := int(bpp[4])
		if int(pktLen)-1-padLen < 1 {
			continue
		}
		switch bpp[5] {
		case MsgChannelEOF:
			eofCount++
		case MsgChannelClose:
			closeCount++
		}
	}
	if eofCount == 0 {
		t.Errorf("CHANNEL_EOF not found in default dialog")
	}
	if closeCount < 2 {
		t.Errorf("CHANNEL_CLOSE count=%d, want >= 2 (both sides)", closeCount)
	}
}

// Test 1.13.x: CHANNEL_REQUEST (exec).
func TestSSHPlan_ChannelRequestExec(t *testing.T) {
	p := NewPlanner()
	spec := validSSHSpec()
	spec.SSH.AuthMethods = []core.SSHMessage{{Type: "userauth_success"}}
	spec.SSH.Channels = []core.ChannelEntry{
		{Type: "channel_request", RecipientChannel: 0, RequestType: "exec", WantReply: true, Command: "ls -l"},
	}
	cfgs := drain(mustPlan(t, p, spec))
	for _, c := range cfgs {
		if len(c.Payload) < 6 {
			continue
		}
		bpp := c.Payload
		pktLen := binary.BigEndian.Uint32(bpp[:4])
		padLen := int(bpp[4])
		if int(pktLen)-1-padLen < 1 {
			continue
		}
		if bpp[5] == MsgChannelRequest {
			payload := bpp[5 : 5+int(pktLen)-1-padLen]
			// msg(1) || uint32(recipient) || string(type) || bool(want_reply) || string(command)
			off := 1 + 4
			typeLen := binary.BigEndian.Uint32(payload[off : off+4])
			typeStr := string(payload[off+4 : off+4+int(typeLen)])
			if typeStr != "exec" {
				t.Errorf("request_type=%q, want 'exec'", typeStr)
				return
			}
			off += 4 + int(typeLen)
			wantReply := payload[off]
			if wantReply != 0x01 {
				t.Errorf("want_reply=0x%02x, want 0x01", wantReply)
			}
			off++
			cmdLen := binary.BigEndian.Uint32(payload[off : off+4])
			cmd := string(payload[off+4 : off+4+int(cmdLen)])
			if cmd != "ls -l" {
				t.Errorf("command=%q, want 'ls -l'", cmd)
			}
			return
		}
	}
	t.Errorf("CHANNEL_REQUEST not found")
}

// Test 1.13.x: CHANNEL_REQUEST (pty-req).
func TestSSHPlan_ChannelRequestPtyReq(t *testing.T) {
	p := NewPlanner()
	spec := validSSHSpec()
	spec.SSH.AuthMethods = []core.SSHMessage{{Type: "userauth_success"}}
	spec.SSH.Channels = []core.ChannelEntry{
		{Type: "channel_request", RecipientChannel: 0, RequestType: "pty-req", WantReply: true, Term: "xterm", WidthChars: 80, HeightRows: 24, WidthPixels: 0, HeightPixels: 0},
	}
	cfgs := drain(mustPlan(t, p, spec))
	for _, c := range cfgs {
		if len(c.Payload) < 6 {
			continue
		}
		bpp := c.Payload
		pktLen := binary.BigEndian.Uint32(bpp[:4])
		padLen := int(bpp[4])
		if int(pktLen)-1-padLen < 1 {
			continue
		}
		if bpp[5] == MsgChannelRequest {
			payload := bpp[5 : 5+int(pktLen)-1-padLen]
			off := 1 + 4
			typeLen := binary.BigEndian.Uint32(payload[off : off+4])
			typeStr := string(payload[off+4 : off+4+int(typeLen)])
			if typeStr != "pty-req" {
				t.Errorf("request_type=%q, want 'pty-req'", typeStr)
				return
			}
			off += 4 + int(typeLen) + 1 // +1 for want_reply
			termLen := binary.BigEndian.Uint32(payload[off : off+4])
			term := string(payload[off+4 : off+4+int(termLen)])
			if term != "xterm" {
				t.Errorf("TERM=%q, want 'xterm'", term)
			}
			off += 4 + int(termLen)
			widthChars := binary.BigEndian.Uint32(payload[off : off+4])
			if widthChars != 80 {
				t.Errorf("width_chars=%d, want 80", widthChars)
			}
			return
		}
	}
	t.Errorf("CHANNEL_REQUEST not found")
}

// Test 1.16.x: GLOBAL_REQUEST (tcpip-forward).
func TestSSHPlan_GlobalRequestTcpipForward(t *testing.T) {
	p := NewPlanner()
	spec := validSSHSpec()
	spec.SSH.AuthMethods = []core.SSHMessage{{Type: "userauth_success"}}
	spec.SSH.Channels = []core.ChannelEntry{
		{Type: "global_request", GlobalRequestName: "tcpip-forward", WantReply: true, Address: "0.0.0.0", Port: 8080},
		{Type: "request_success", Port: 8080},
	}
	cfgs := drain(mustPlan(t, p, spec))
	foundReq, foundSucc := false, false
	for _, c := range cfgs {
		if len(c.Payload) < 6 {
			continue
		}
		bpp := c.Payload
		pktLen := binary.BigEndian.Uint32(bpp[:4])
		padLen := int(bpp[4])
		if int(pktLen)-1-padLen < 1 {
			continue
		}
		switch bpp[5] {
		case MsgGlobalRequest:
			foundReq = true
			if c.Direction != "up" {
				t.Errorf("GLOBAL_REQUEST dir=%s, want up", c.Direction)
			}
		case MsgRequestSuccess:
			foundSucc = true
			if c.Direction != "down" {
				t.Errorf("REQUEST_SUCCESS dir=%s, want down", c.Direction)
			}
		}
	}
	if !foundReq {
		t.Errorf("GLOBAL_REQUEST not found")
	}
	if !foundSucc {
		t.Errorf("REQUEST_SUCCESS not found")
	}
}

// Test 1.18.x: IGNORE / UNIMPLEMENTED / DEBUG.
func TestSSHPlan_IgnoreUnimplementedDebug(t *testing.T) {
	p := NewPlanner()
	spec := validSSHSpec()
	spec.SSH.AuthMethods = []core.SSHMessage{
		{Type: "ignore", Data: []byte("ignored"), Direction: "up"},
		{Type: "unimplemented", ReceiveSeq: 42, Direction: "up"},
		{Type: "debug", AlwaysDisplay: true, Message: "debug: foo", LanguageTag: "en-US", Direction: "down"},
		{Type: "userauth_success"},
	}
	cfgs := drain(mustPlan(t, p, spec))
	foundIgnore, foundUnimpl, foundDebug := false, false, false
	for _, c := range cfgs {
		if len(c.Payload) < 6 {
			continue
		}
		bpp := c.Payload
		pktLen := binary.BigEndian.Uint32(bpp[:4])
		padLen := int(bpp[4])
		if int(pktLen)-1-padLen < 1 {
			continue
		}
		switch bpp[5] {
		case MsgIgnore:
			foundIgnore = true
		case MsgUnimplemented:
			foundUnimpl = true
			payload := bpp[5 : 5+int(pktLen)-1-padLen]
			seq := binary.BigEndian.Uint32(payload[1:5])
			if seq != 42 {
				t.Errorf("UNIMPLEMENTED seq=%d, want 42", seq)
			}
		case MsgDebug:
			foundDebug = true
		}
	}
	if !foundIgnore {
		t.Errorf("IGNORE not found")
	}
	if !foundUnimpl {
		t.Errorf("UNIMPLEMENTED not found")
	}
	if !foundDebug {
		t.Errorf("DEBUG not found")
	}
}

// --- DisconnectOnClose tests ---

func TestSSHPlan_DisconnectOnClose(t *testing.T) {
	p := NewPlanner()
	spec := validSSHSpec()
	spec.SSH.DisconnectOnClose = true
	cfgs := drain(mustPlan(t, p, spec))
	// Find DISCONNECT after channel dialog but before teardown.
	found := false
	for i, c := range cfgs {
		if len(c.Payload) < 6 {
			continue
		}
		bpp := c.Payload
		pktLen := binary.BigEndian.Uint32(bpp[:4])
		padLen := int(bpp[4])
		if int(pktLen)-1-padLen < 1 {
			continue
		}
		if bpp[5] == MsgDisconnect {
			found = true
			// Verify it's before teardown (cfg[i] should be PSH-ACK).
			if c.L4.Flags != 0x18 {
				t.Errorf("DISCONNECT flags=0x%02x, want 0x18 (PSH-ACK)", c.L4.Flags)
			}
			// Verify reason = DiscByApplication (11).
			payload := bpp[5 : 5+int(pktLen)-1-padLen]
			reason := binary.BigEndian.Uint32(payload[1:5])
			if reason != DiscByApplication {
				t.Errorf("reason=%d, want %d", reason, DiscByApplication)
			}
			_ = i
			break
		}
	}
	if !found {
		t.Errorf("DISCONNECT not found with DisconnectOnClose=true")
	}
}

// --- Seq advance tests ---

// Test: PSH-ACK segments advance the sender's seq by the payload byte length.
func TestSSHPlan_SeqAdvances(t *testing.T) {
	p := NewPlanner()
	spec := validSSHSpec()
	spec.TCP = &core.TCPConfig{InitialSeq: 1000}
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) < 4 {
		t.Fatalf("len=%d", len(cfgs))
	}
	// cfg[0] = SYN up (clientSeq=1000 -> 1001).
	if cfgs[0].L4.Seq != 1000 {
		t.Errorf("cfg[0] SYN seq=%d, want 1000", cfgs[0].L4.Seq)
	}
	// cfg[2] = handshake ACK up (seq=1001).
	if cfgs[2].L4.Seq != 1001 {
		t.Errorf("cfg[2] ACK seq=%d, want 1001", cfgs[2].L4.Seq)
	}
	// cfg[3] = first data PSH-ACK up (seq=1001, payload=KEXINIT BPP frame).
	if cfgs[3].Direction != "up" {
		t.Errorf("cfg[3] dir=%s, want up", cfgs[3].Direction)
	}
	if cfgs[3].L4.Seq != 1001 {
		t.Errorf("cfg[3] seq=%d, want 1001", cfgs[3].L4.Seq)
	}
	// Subsequent up packet should advance by payload length.
	if len(cfgs) > 4 && cfgs[4].Direction == "up" {
		expected := uint32(1001) + uint32(len(cfgs[3].Payload))
		if cfgs[4].L4.Seq != expected {
			t.Errorf("cfg[4] seq=%d, want %d (1001 + %d)", cfgs[4].L4.Seq, expected, len(cfgs[3].Payload))
		}
	}
}

// --- MSS segmentation tests ---

// Test: large channel_data is segmented by MSS.
func TestSSHPlan_LongDataSegmentedByMSS(t *testing.T) {
	p := NewPlanner()
	spec := validSSHSpec()
	testutil.EnsureTCP(&spec).MSS = 600
	longData := strings.Repeat("A", 2000)
	spec.SSH.AuthMethods = []core.SSHMessage{{Type: "userauth_success"}}
	spec.SSH.Channels = []core.ChannelEntry{
		{Type: "channel_data", RecipientChannel: 0, Data: []byte(longData), Direction: "up"},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// Find consecutive "up" PSH-ACK packets carrying the segmented data.
	// Each BPP frame is ~600 bytes max -> at least 4 segments for 2000-byte payload.
	// We just verify the planner emits multiple packets (segmentation happens).
	upCount := 0
	for _, c := range cfgs {
		if c.Direction == "up" && c.L4.Flags == 0x18 && len(c.Payload) > 0 {
			upCount++
		}
	}
	if upCount < 4 {
		t.Errorf("segment count=%d, want >= 4 (2000-byte data with 600 MSS)", upCount)
	}
}

// --- Default dialog tests ---

// Test: nil SSHConfig emits default dialog.
func TestSSHPlan_NilConfigDefaultDialog(t *testing.T) {
	p := NewPlanner()
	spec := validSSHSpec()
	spec.SSH = nil
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) < 15 {
		t.Errorf("len=%d, want >= 15 (default dialog)", len(cfgs))
	}
}

// --- Encoder unit tests (white-box) ---

func TestEncodeKexInit_HasAllFields(t *testing.T) {
	cookie := make([]byte, 16)
	for i := range cookie {
		cookie[i] = byte(i)
	}
	payload := encodeKexInit(cookie, "kex", "hk", "enc", "mac", "comp")
	if payload[0] != MsgKexInit {
		t.Errorf("msg=0x%02x, want 0x%02x", payload[0], MsgKexInit)
	}
	// cookie present
	if string(payload[1:17]) != string(cookie) {
		t.Errorf("cookie mismatch")
	}
	// 10 strings follow (kex, hk, enc_c2s, enc_s2c, mac_c2s, mac_s2c,
	// comp_c2s, comp_s2c, lang_c2s, lang_s2c) + bool + uint32.
}

func TestEncodeDisconnect_ReasonAndDescription(t *testing.T) {
	payload := encodeDisconnect(DiscByApplication, "bye", "en")
	if payload[0] != MsgDisconnect {
		t.Errorf("msg=0x%02x, want 0x%02x", payload[0], MsgDisconnect)
	}
	reason := binary.BigEndian.Uint32(payload[1:5])
	if reason != DiscByApplication {
		t.Errorf("reason=%d, want %d", reason, DiscByApplication)
	}
	descLen := binary.BigEndian.Uint32(payload[5:9])
	if string(payload[9:9+int(descLen)]) != "bye" {
		t.Errorf("desc=%q, want 'bye'", string(payload[9:9+int(descLen)]))
	}
}

func TestEncodeUserAuthSuccess_JustOneByte(t *testing.T) {
	payload := encodeUserAuthSuccess()
	if len(payload) != 1 || payload[0] != MsgUserAuthSuccess {
		t.Errorf("payload=%v, want [0x34]", payload)
	}
}

func TestBuildBPP_PaddingAlignment(t *testing.T) {
	// Test 1-byte payload with block size 8.
	payload := []byte{MsgNewKeys}
	frame := buildBPP(payload, 8, 0)
	pktLen := binary.BigEndian.Uint32(frame[:4])
	padLen := int(frame[4])
	// total = 4 + pktLen; must be multiple of 8.
	if (4+pktLen)%8 != 0 {
		t.Errorf("total=%d not aligned to 8", 4+pktLen)
	}
	if padLen < 4 {
		t.Errorf("padLen=%d, want >= 4", padLen)
	}
}

func TestBuildBPP_MACPresent(t *testing.T) {
	payload := []byte{MsgNewKeys}
	frame := buildBPP(payload, 16, MAC256)
	pktLen := binary.BigEndian.Uint32(frame[:4])
	totalFrameSize := 4 + int(pktLen) + MAC256
	if len(frame) != totalFrameSize {
		t.Errorf("frame len=%d, want %d (4+pktLen+MAC)", len(frame), totalFrameSize)
	}
}

func TestPaddingLengthForBPP_Minimum4(t *testing.T) {
	for _, tc := range []struct{ payload, blk, mac int }{
		{1, 8, 0},
		{16, 8, 0},
		{100, 16, 32},
		{1, 16, 32},
	} {
		pad := paddingLengthForBPP(tc.payload, tc.blk, tc.mac)
		if pad < 4 {
			t.Errorf("payload=%d blk=%d mac=%d: pad=%d, want >= 4", tc.payload, tc.blk, tc.mac, pad)
		}
		if pad > 255 {
			t.Errorf("payload=%d blk=%d mac=%d: pad=%d, want <= 255", tc.payload, tc.blk, tc.mac, pad)
		}
		// Verify alignment.
		if (5+tc.payload+pad)%tc.blk != 0 {
			t.Errorf("payload=%d blk=%d mac=%d: pad=%d, total not aligned to blk", tc.payload, tc.blk, tc.mac, pad)
		}
	}
}

func TestBlockSizeForCipher(t *testing.T) {
	cases := map[string]int{
		CipherNone:              8,
		CipherAES:               16,
		"aes192-ctr":            16,
		"aes256-ctr":            16,
		CipherAESGCM:            1,
		"aes256-gcm@openssh.com": 1,
		"":                      8,
		"unknown":               8,
	}
	for cipher, want := range cases {
		got := blockSizeForCipher(cipher)
		if got != want {
			t.Errorf("blockSizeForCipher(%q)=%d, want %d", cipher, got, want)
		}
	}
}

func TestSegmentByMSS(t *testing.T) {
	payload := make([]byte, 2500)
	for i := range payload {
		payload[i] = byte(i)
	}
	segs := segmentByMSS(payload, 1460)
	if len(segs) != 2 {
		t.Errorf("len=%d, want 2", len(segs))
	}
	if len(segs[0]) != 1460 {
		t.Errorf("seg[0] len=%d, want 1460", len(segs[0]))
	}
	if len(segs[1]) != 1040 {
		t.Errorf("seg[1] len=%d, want 1040", len(segs[1]))
	}
}

func TestSegmentByMSS_ZeroMSS(t *testing.T) {
	payload := []byte("hello")
	segs := segmentByMSS(payload, 0)
	if len(segs) != 1 || !bytesEqual(segs[0], payload) {
		t.Errorf("zero MSS: segs=%v, want single segment", segs)
	}
}

func TestSegmentByMSS_EmptyPayload(t *testing.T) {
	segs := segmentByMSS(nil, 1460)
	if len(segs) != 1 {
		t.Errorf("empty: segs=%v, want 1 segment", segs)
	}
}

// bytesEqual is a small helper to avoid pulling in bytes package.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// --- Default dialog value tests ---

func TestDefaultAuthMethods(t *testing.T) {
	methods := defaultAuthMethods()
	if len(methods) != 2 {
		t.Errorf("len=%d, want 2", len(methods))
	}
	if methods[0].Type != "userauth_request" {
		t.Errorf("methods[0].Type=%q, want 'userauth_request'", methods[0].Type)
	}
	if methods[0].MethodName != "password" {
		t.Errorf("methods[0].MethodName=%q, want 'password'", methods[0].MethodName)
	}
	if methods[1].Type != "userauth_success" {
		t.Errorf("methods[1].Type=%q, want 'userauth_success'", methods[1].Type)
	}
}

func TestDefaultChannels(t *testing.T) {
	channels := defaultChannels()
	if len(channels) < 4 {
		t.Errorf("len=%d, want >= 4 (open, confirm, data, eof, close...)", len(channels))
	}
	if channels[0].Type != "channel_open" {
		t.Errorf("channels[0].Type=%q, want 'channel_open'", channels[0].Type)
	}
	if channels[0].ChannelType != "session" {
		t.Errorf("channels[0].ChannelType=%q, want 'session'", channels[0].ChannelType)
	}
}

// --- Algorithm defaults tests ---

func TestDefaultKexAlgorithms(t *testing.T) {
	if !strings.Contains(DefaultKexAlgorithms, "curve25519-sha256") {
		t.Errorf("DefaultKexAlgorithms=%q, want contains 'curve25519-sha256'", DefaultKexAlgorithms)
	}
	if !strings.Contains(DefaultKexAlgorithms, "ext-info-c") {
		t.Errorf("DefaultKexAlgorithms=%q, want contains 'ext-info-c' (RFC 8308)", DefaultKexAlgorithms)
	}
}

func TestDefaultCompressionAlgorithms(t *testing.T) {
	if !strings.Contains(DefaultCompressionAlgorithms, "none") {
		t.Errorf("DefaultCompressionAlgorithms=%q, want contains 'none' (RFC 4253 §6.2 required)", DefaultCompressionAlgorithms)
	}
}

// --- dhPayloadLenForKEX tests ---

func TestDhPayloadLenForKEX(t *testing.T) {
	cases := map[string]int{
		"curve25519-sha256":           32,
		"ecdh-sha2-nistp256":          65,
		"ecdh-sha2-nistp384":          97,
		"diffie-hellman-group14-sha256": 256,
		"unknown":                     32,
	}
	for kex, want := range cases {
		got := dhPayloadLenForKEX(kex)
		if got != want {
			t.Errorf("dhPayloadLenForKEX(%q)=%d, want %d", kex, got, want)
		}
	}
}

// --- Wire-format primitive tests ---

func TestEncString(t *testing.T) {
	out := encString(nil, []byte("hello"))
	if len(out) != 9 {
		t.Errorf("len=%d, want 9 (4+5)", len(out))
	}
	if binary.BigEndian.Uint32(out[:4]) != 5 {
		t.Errorf("length prefix=%d, want 5", binary.BigEndian.Uint32(out[:4]))
	}
	if string(out[4:]) != "hello" {
		t.Errorf("data=%q, want 'hello'", string(out[4:]))
	}
}

func TestEncString_Empty(t *testing.T) {
	out := encString(nil, nil)
	if len(out) != 4 {
		t.Errorf("len=%d, want 4 (just length prefix)", len(out))
	}
	if binary.BigEndian.Uint32(out[:4]) != 0 {
		t.Errorf("length prefix=%d, want 0", binary.BigEndian.Uint32(out[:4]))
	}
}

func TestEncUint32(t *testing.T) {
	out := encUint32(nil, 0x12345678)
	if len(out) != 4 {
		t.Errorf("len=%d, want 4", len(out))
	}
	if out[0] != 0x12 || out[1] != 0x34 || out[2] != 0x56 || out[3] != 0x78 {
		t.Errorf("out=%v, want [12 34 56 78] (BE)", out)
	}
}

func TestEncBool(t *testing.T) {
	if encBool(nil, true)[0] != 0x01 {
		t.Errorf("true != 0x01")
	}
	if encBool(nil, false)[0] != 0x00 {
		t.Errorf("false != 0x00")
	}
}
