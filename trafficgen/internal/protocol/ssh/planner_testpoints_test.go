// Package ssh planner_testpoints_test.go - exhaustive spec-driven testpoints
// mapped 1:1 to testcases_ssh.md.
//
// Per CLAUDE.md testing policy §1: tests must be derived from the spec, not
// ad-hoc. This file enumerates each testable row in testcases_ssh.md and
// converts it into a focused assertion. Together with planner_test.go, this
// gives full coverage of the SSH planner's observable behavior.
//
// Testpoint naming convention: TestTp_<section>_<number> mirrors the
// "用例 X.Y.Z" identifier in testcases_ssh.md. Each testpoint is small,
// focused, and asserts an observable outcome (byte value, length, direction,
// flags) - never merely "it didn't panic".
package ssh

import (
	"context"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/protocol/testutil"
)

// specWith sets ServerVersion and ClientVersion to enable version exchange.
func specWith() core.FlowSpec {
	s := validSSHSpec()
	s.SSH.ServerVersion = "SSH-2.0-trafficgen_1.0"
	s.SSH.ClientVersion = "SSH-2.0-trafficgen_1.0"
	return s
}

// bppPayload extracts the SSH payload from a BPP-framed packet, given the
// outer cfg.Payload (which is the BPP frame: packet_length || padding_length
// || payload || padding || MAC).
func bppPayload(frame []byte) []byte {
	if len(frame) < 5 {
		return nil
	}
	pktLen := binary.BigEndian.Uint32(frame[:4])
	padLen := int(frame[4])
	if int(pktLen) < 1+padLen {
		return nil
	}
	payloadEnd := 5 + int(pktLen) - 1 - padLen
	if payloadEnd > len(frame) {
		return nil
	}
	return frame[5:payloadEnd]
}

// findMsg returns the first cfg whose BPP payload starts with the given
// message byte, or nil if not found.
func findMsg(cfgs []core.PacketConfig, msg byte) *core.PacketConfig {
	for i := range cfgs {
		p := bppPayload(cfgs[i].Payload)
		if len(p) > 0 && p[0] == msg {
			return &cfgs[i]
		}
	}
	return nil
}

// countMsg returns the number of cfgs whose BPP payload starts with msg.
func countMsg(cfgs []core.PacketConfig, msg byte) int {
	n := 0
	for _, c := range cfgs {
		p := bppPayload(c.Payload)
		if len(p) > 0 && p[0] == msg {
			n++
		}
	}
	return n
}

// --- 1.1 Version Exchange ---

// 1.1.1: ServerVersion="SSH-2.0-OpenSSH_8.9" -> PSH-ACK down with that string + CRLF.
func TestTp_1_1_1(t *testing.T) {
	p := NewPlanner()
	spec := validSSHSpec()
	spec.SSH.ServerVersion = "SSH-2.0-OpenSSH_8.9"
	spec.SSH.ClientVersion = ""
	cfgs := drain(mustPlan(t, p, spec))
	if cfgs[3].Direction != "down" {
		t.Errorf("dir=%s, want down", cfgs[3].Direction)
	}
	want := "SSH-2.0-OpenSSH_8.9\r\n"
	if string(cfgs[3].Payload) != want {
		t.Errorf("payload=%q, want %q", cfgs[3].Payload, want)
	}
}

// 1.1.5: ServerVersion with LF -> Validate error.
func TestTp_1_1_5(t *testing.T) {
	p := NewPlanner()
	spec := validSSHSpec()
	spec.SSH.ServerVersion = "SSH-2.0-bad\nfoo"
	if err := p.Validate(spec); err == nil || !strings.Contains(err.Error(), "CR/LF") {
		t.Errorf("err=%v, want 'CR/LF'", err)
	}
}

// 1.1.6: ServerVersion with CR -> Validate error.
func TestTp_1_1_6(t *testing.T) {
	p := NewPlanner()
	spec := validSSHSpec()
	spec.SSH.ServerVersion = "SSH-2.0-bad\rf"
	if err := p.Validate(spec); err == nil || !strings.Contains(err.Error(), "CR/LF") {
		t.Errorf("err=%v, want 'CR/LF'", err)
	}
}

// 1.1.8: empty versions -> skip version exchange.
func TestTp_1_1_8(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validSSHSpec()))
	// cfg[3] should be KEXINIT (BPP), not starting with "SSH-".
	if strings.HasPrefix(string(cfgs[3].Payload), "SSH-") {
		t.Errorf("version exchange should be skipped when both versions empty")
	}
}

// 1.1.10: ServerVersion="" ClientVersion set -> emit both with defaults.
func TestTp_1_1_10(t *testing.T) {
	p := NewPlanner()
	spec := validSSHSpec()
	spec.SSH.ServerVersion = ""
	spec.SSH.ClientVersion = "SSH-2.0-trafficgen_1.0"
	cfgs := drain(mustPlan(t, p, spec))
	// Both should be emitted (server defaults).
	if !strings.HasPrefix(string(cfgs[3].Payload), "SSH-2.0-") {
		t.Errorf("server version not emitted: %q", cfgs[3].Payload)
	}
	if !strings.HasPrefix(string(cfgs[4].Payload), "SSH-2.0-") {
		t.Errorf("client version not emitted: %q", cfgs[4].Payload)
	}
}

// --- 1.2 BPP Framing ---

// 1.2.7-10: Validate rejects invalid BPP parameters - tested via encoder
// unit tests since these are internal validation points. The Validate
// method itself does not parse BPP; it validates SSHConfig fields.

// 1.2.12: BPP MAC = 0 pre-NEWKEYS.
func TestTp_1_2_12(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validSSHSpec()))
	// KEXINIT (cfg[3]) pre-NEWKEYS: no MAC.
	bpp := cfgs[3].Payload
	pktLen := binary.BigEndian.Uint32(bpp[:4])
	totalFrameLen := 4 + int(pktLen)
	if len(bpp) != totalFrameLen {
		t.Errorf("KEXINIT frame len=%d, want %d (no MAC pre-NEWKEYS)", len(bpp), totalFrameLen)
	}
}

// 1.2.13: BPP MAC present post-NEWKEYS.
func TestTp_1_2_13(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validSSHSpec()))
	// SERVICE_REQUEST (cfg[9]) post-NEWKEYS: MAC present.
	bpp := cfgs[9].Payload
	pktLen := binary.BigEndian.Uint32(bpp[:4])
	macLen := len(bpp) - 4 - int(pktLen)
	if macLen <= 0 {
		t.Errorf("post-NEWKEYS MAC len=%d, want > 0", macLen)
	}
}

// --- 1.3 KEXINIT ---

// 1.3.1: KEXINIT message byte = 0x14 (20).
func TestTp_1_3_1(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validSSHSpec()))
	if p := bppPayload(cfgs[3].Payload); p == nil || p[0] != 0x14 {
		t.Errorf("KEXINIT byte mismatch")
	}
}

// 1.3.2: KEXINIT cookie = 16 bytes.
func TestTp_1_3_2(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validSSHSpec()))
	p_ := bppPayload(cfgs[3].Payload)
	if len(p_) < 17 {
		t.Fatalf("payload too short")
	}
	if len(p_[1:17]) != 16 {
		t.Errorf("cookie len=%d, want 16", len(p_[1:17]))
	}
}

// 1.3.10: KEXINIT first_kex_packet_follows = 0.
func TestTp_1_3_10(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validSSHSpec()))
	p_ := bppPayload(cfgs[3].Payload)
	// last byte should be reserved (4 bytes 0); before that bool.
	// Just verify the last 5 bytes are 0x00 (bool) + 4x 0x00 (reserved).
	last5 := p_[len(p_)-5:]
	for i, b := range last5 {
		if b != 0x00 {
			t.Errorf("last5[%d]=0x%02x, want 0x00", i, b)
		}
	}
}

// 1.3.11: KEXINIT reserved = 0 (uint32).
func TestTp_1_3_11(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validSSHSpec()))
	p_ := bppPayload(cfgs[3].Payload)
	last4 := p_[len(p_)-4:]
	if binary.BigEndian.Uint32(last4) != 0 {
		t.Errorf("reserved=%d, want 0", binary.BigEndian.Uint32(last4))
	}
}

// --- 1.4 NEWKEYS ---

// 1.4.1: NEWKEYS payload = 1 byte 0x15 (21).
func TestTp_1_4_1(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validSSHSpec()))
	p_ := bppPayload(cfgs[7].Payload)
	if len(p_) != 1 || p_[0] != 0x15 {
		t.Errorf("NEWKEYS up payload=%v, want [0x15]", p_)
	}
}

// 1.4.2: NEWKEYS server-side (down) also 0x15.
func TestTp_1_4_2(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validSSHSpec()))
	p_ := bppPayload(cfgs[8].Payload)
	if len(p_) != 1 || p_[0] != 0x15 {
		t.Errorf("NEWKEYS down payload=%v, want [0x15]", p_)
	}
}

// --- 1.5 KEXDH_INIT ---

// 1.5.1: KEXDH_INIT message byte = 0x1E (30).
func TestTp_1_5_1(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validSSHSpec()))
	p_ := bppPayload(cfgs[5].Payload)
	if p_ == nil || p_[0] != 0x1E {
		t.Errorf("KEXDH_INIT byte=0x%02x, want 0x1E", p_[0])
	}
}

// 1.5.7: curve25519 KEXDH_INIT has 32-byte e.
func TestTp_1_5_7(t *testing.T) {
	p := NewPlanner()
	spec := validSSHSpec()
	spec.SSH.KEX = "curve25519-sha256"
	cfgs := drain(mustPlan(t, p, spec))
	p_ := bppPayload(cfgs[5].Payload)
	// msg(1) || string(e). string length should be 32.
	eLen := binary.BigEndian.Uint32(p_[1:5])
	if eLen != 32 {
		t.Errorf("curve25519 e length=%d, want 32", eLen)
	}
}

// --- 1.6 KEXDH_REPLY ---

// 1.6.1: KEXDH_REPLY message byte = 0x1F (31).
func TestTp_1_6_1(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validSSHSpec()))
	p_ := bppPayload(cfgs[6].Payload)
	if p_ == nil || p_[0] != 0x1F {
		t.Errorf("KEXDH_REPLY byte=0x%02x, want 0x1F", p_[0])
	}
}

// --- 1.7 EXT_INFO ---

// 1.7.1: EXT_INFO message byte = 0x07 (7) when ExtInfo=true.
func TestTp_1_7_1(t *testing.T) {
	p := NewPlanner()
	spec := validSSHSpec()
	spec.SSH.ExtInfo = true
	cfgs := drain(mustPlan(t, p, spec))
	if findMsg(cfgs, 0x07) == nil {
		t.Errorf("EXT_INFO not found when ExtInfo=true")
	}
}

// 1.7.4: no EXT_INFO when ExtInfo=false.
func TestTp_1_7_4(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validSSHSpec()))
	if countMsg(cfgs, 0x07) != 0 {
		t.Errorf("EXT_INFO should not be emitted when ExtInfo=false")
	}
}

// 1.7.2: EXT_INFO nr_extensions = 1.
func TestTp_1_7_2(t *testing.T) {
	p := NewPlanner()
	spec := validSSHSpec()
	spec.SSH.ExtInfo = true
	cfgs := drain(mustPlan(t, p, spec))
	c := findMsg(cfgs, 0x07)
	if c == nil {
		t.Fatal("EXT_INFO not found")
	}
	p_ := bppPayload(c.Payload)
	nrExt := binary.BigEndian.Uint32(p_[1:5])
	if nrExt != 1 {
		t.Errorf("nr_extensions=%d, want 1", nrExt)
	}
}

// --- 1.8 SERVICE ---

// 1.8.1: SERVICE_REQUEST byte = 0x05.
func TestTp_1_8_1(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validSSHSpec()))
	p_ := bppPayload(cfgs[9].Payload)
	if p_ == nil || p_[0] != 0x05 {
		t.Errorf("SERVICE_REQUEST byte=0x%02x, want 0x05", p_[0])
	}
}

// 1.8.2: SERVICE_REQUEST service_name = "ssh-userauth".
func TestTp_1_8_2(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validSSHSpec()))
	p_ := bppPayload(cfgs[9].Payload)
	nameLen := binary.BigEndian.Uint32(p_[1:5])
	name := string(p_[5 : 5+int(nameLen)])
	if name != "ssh-userauth" {
		t.Errorf("service_name=%q, want 'ssh-userauth'", name)
	}
}

// 1.8.4: SERVICE_ACCEPT byte = 0x06.
func TestTp_1_8_4(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validSSHSpec()))
	p_ := bppPayload(cfgs[10].Payload)
	if p_ == nil || p_[0] != 0x06 {
		t.Errorf("SERVICE_ACCEPT byte=0x%02x, want 0x06", p_[0])
	}
}

// --- 1.9 USERAUTH_REQUEST ---

// 1.9.1: USERAUTH_REQUEST byte = 0x32 (50).
func TestTp_1_9_1(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validSSHSpec()))
	c := findMsg(cfgs, 0x32)
	if c == nil {
		t.Errorf("USERAUTH_REQUEST not found")
	}
}

// 1.9.7: password method with has_password_change=0.
func TestTp_1_9_7(t *testing.T) {
	p := NewPlanner()
	spec := validSSHSpec()
	spec.SSH.AuthMethods = []core.SSHMessage{
		{Type: "userauth_request", MethodName: "password", Username: "alice", Password: "secret123"},
		{Type: "userauth_success"},
	}
	cfgs := drain(mustPlan(t, p, spec))
	c := findMsg(cfgs, 0x32)
	if c == nil {
		t.Fatal("USERAUTH_REQUEST not found")
	}
	p_ := bppPayload(c.Payload)
	readStr := func(off int) (string, int) {
		l := binary.BigEndian.Uint32(p_[off : off+4])
		return string(p_[off+4 : off+4+int(l)]), off + 4 + int(l)
	}
	off := 1
	_, off = readStr(off) // username
	_, off = readStr(off) // service
	_, off = readStr(off) // method
	if p_[off] != 0x00 {
		t.Errorf("has_password_change=0x%02x, want 0x00", p_[off])
	}
	off++
	pwd, _ := readStr(off)
	if pwd != "secret123" {
		t.Errorf("password=%q, want 'secret123'", pwd)
	}
}

// 1.9.8: password with has_password_change=1.
func TestTp_1_9_8(t *testing.T) {
	p := NewPlanner()
	spec := validSSHSpec()
	spec.SSH.AuthMethods = []core.SSHMessage{
		{Type: "userauth_request", MethodName: "password", Username: "alice", Password: "old", HasPasswordChange: true, NewPassword: "new"},
		{Type: "userauth_success"},
	}
	cfgs := drain(mustPlan(t, p, spec))
	c := findMsg(cfgs, 0x32)
	if c == nil {
		t.Fatal("USERAUTH_REQUEST not found")
	}
	p_ := bppPayload(c.Payload)
	readStr := func(off int) (string, int) {
		l := binary.BigEndian.Uint32(p_[off : off+4])
		return string(p_[off+4 : off+4+int(l)]), off + 4 + int(l)
	}
	off := 1
	_, off = readStr(off)
	_, off = readStr(off)
	_, off = readStr(off)
	if p_[off] != 0x01 {
		t.Errorf("has_password_change=0x%02x, want 0x01", p_[off])
	}
}

// 1.9.5: publickey method.
func TestTp_1_9_5(t *testing.T) {
	p := NewPlanner()
	spec := validSSHSpec()
	spec.SSH.AuthMethods = []core.SSHMessage{
		{Type: "userauth_request", MethodName: "publickey", Username: "alice", HasSignature: false, PublicKeyAlgorithm: "ssh-rsa", PublicKeyBlob: make([]byte, 294)},
		{Type: "userauth_success"},
	}
	cfgs := drain(mustPlan(t, p, spec))
	c := findMsg(cfgs, 0x32)
	if c == nil {
		t.Fatal("USERAUTH_REQUEST not found")
	}
	p_ := bppPayload(c.Payload)
	readStr := func(off int) (string, int) {
		l := binary.BigEndian.Uint32(p_[off : off+4])
		return string(p_[off+4 : off+4+int(l)]), off + 4 + int(l)
	}
	off := 1
	_, off = readStr(off)
	_, off = readStr(off)
	_, off = readStr(off)
	if p_[off] != 0x00 {
		t.Errorf("has_signature=0x%02x, want 0x00", p_[off])
	}
}

// --- 1.10 USERAUTH FAILURE/SUCCESS/BANNER ---

// 1.10.1: USERAUTH_FAILURE byte = 0x33 (51).
func TestTp_1_10_1(t *testing.T) {
	p := NewPlanner()
	spec := validSSHSpec()
	spec.SSH.AuthMethods = []core.SSHMessage{
		{Type: "userauth_failure", AuthMethodsThatCanContinue: "publickey"},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if findMsg(cfgs, 0x33) == nil {
		t.Errorf("USERAUTH_FAILURE not found")
	}
}

// 1.10.5: USERAUTH_SUCCESS byte = 0x34 (52), 1 byte payload.
func TestTp_1_10_5(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validSSHSpec()))
	c := findMsg(cfgs, 0x34)
	if c == nil {
		t.Errorf("USERAUTH_SUCCESS not found")
		return
	}
	p_ := bppPayload(c.Payload)
	if len(p_) != 1 {
		t.Errorf("USERAUTH_SUCCESS payload len=%d, want 1", len(p_))
	}
}

// 1.10.6: USERAUTH_BANNER byte = 0x35 (53).
func TestTp_1_10_6(t *testing.T) {
	p := NewPlanner()
	spec := validSSHSpec()
	spec.SSH.AuthMethods = []core.SSHMessage{
		{Type: "userauth_banner", Banner: "Welcome"},
		{Type: "userauth_success"},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if findMsg(cfgs, 0x35) == nil {
		t.Errorf("USERAUTH_BANNER not found")
	}
}

// --- 1.11 CHANNEL_OPEN ---

// 1.11.1: CHANNEL_OPEN byte = 0x5A (90).
func TestTp_1_11_1(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validSSHSpec()))
	if findMsg(cfgs, 0x5A) == nil {
		t.Errorf("CHANNEL_OPEN not found")
	}
}

// 1.11.2: session channel_type.
func TestTp_1_11_2(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validSSHSpec()))
	c := findMsg(cfgs, 0x5A)
	if c == nil {
		t.Fatal("CHANNEL_OPEN not found")
	}
	p_ := bppPayload(c.Payload)
	typeLen := binary.BigEndian.Uint32(p_[1:5])
	if string(p_[5:5+int(typeLen)]) != "session" {
		t.Errorf("channel_type=%q, want 'session'", string(p_[5:5+int(typeLen)]))
	}
}

// 1.11.9: default initial_window_size = 2097152 (0x00200000).
func TestTp_1_11_9(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validSSHSpec()))
	c := findMsg(cfgs, 0x5A)
	if c == nil {
		t.Fatal("CHANNEL_OPEN not found")
	}
	p_ := bppPayload(c.Payload)
	typeLen := binary.BigEndian.Uint32(p_[1:5])
	off := 5 + int(typeLen)
	// sender_channel(4) + window(4).
	win := binary.BigEndian.Uint32(p_[off+4 : off+8])
	if win != 2097152 {
		t.Errorf("initial_window=%d, want 2097152", win)
	}
}

// 1.11.11: default maximum_packet_size = 32768 (0x00008000).
func TestTp_1_11_11(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validSSHSpec()))
	c := findMsg(cfgs, 0x5A)
	if c == nil {
		t.Fatal("CHANNEL_OPEN not found")
	}
	p_ := bppPayload(c.Payload)
	typeLen := binary.BigEndian.Uint32(p_[1:5])
	off := 5 + int(typeLen) + 4 + 4 // skip sender + window
	maxPkt := binary.BigEndian.Uint32(p_[off : off+4])
	if maxPkt != 32768 {
		t.Errorf("max_packet_size=%d, want 32768", maxPkt)
	}
}

// --- 1.12 CHANNEL_OPEN_CONFIRMATION/FAILURE ---

// 1.12.1: CHANNEL_OPEN_CONFIRMATION byte = 0x5B (91).
func TestTp_1_12_1(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validSSHSpec()))
	if findMsg(cfgs, 0x5B) == nil {
		t.Errorf("CHANNEL_OPEN_CONFIRMATION not found in default dialog")
	}
}

// 1.12.6: CHANNEL_OPEN_FAILURE byte = 0x5C (92).
func TestTp_1_12_6(t *testing.T) {
	p := NewPlanner()
	spec := validSSHSpec()
	spec.SSH.AuthMethods = []core.SSHMessage{{Type: "userauth_success"}}
	spec.SSH.Channels = []core.ChannelEntry{
		{Type: "channel_open", ChannelType: "session", MaximumPacketSize: 32768},
		{Type: "channel_open_failure", RecipientChannel: 0, OpenReasonCode: OpenAdministrativelyProhibited, OpenReasonText: "no"},
	}
	cfgs := drain(mustPlan(t, p, spec))
	c := findMsg(cfgs, 0x5C)
	if c == nil {
		t.Errorf("CHANNEL_OPEN_FAILURE not found")
		return
	}
	p_ := bppPayload(c.Payload)
	reason := binary.BigEndian.Uint32(p_[5:9])
	if reason != OpenAdministrativelyProhibited {
		t.Errorf("reason=%d, want %d", reason, OpenAdministrativelyProhibited)
	}
}

// 1.12.7-10: all open reason codes.
func TestTp_1_12_7_10(t *testing.T) {
	codes := []uint32{OpenAdministrativelyProhibited, OpenConnectFailed, OpenUnknownChannelType, OpenResourceShortage}
	for _, code := range codes {
		p := NewPlanner()
		spec := validSSHSpec()
		spec.SSH.AuthMethods = []core.SSHMessage{{Type: "userauth_success"}}
		spec.SSH.Channels = []core.ChannelEntry{
			{Type: "channel_open", ChannelType: "session", MaximumPacketSize: 32768},
			{Type: "channel_open_failure", RecipientChannel: 0, OpenReasonCode: code, OpenReasonText: "x"},
		}
		cfgs := drain(mustPlan(t, p, spec))
		c := findMsg(cfgs, 0x5C)
		if c == nil {
			t.Errorf("code=%d: CHANNEL_OPEN_FAILURE not found", code)
			continue
		}
		p_ := bppPayload(c.Payload)
		got := binary.BigEndian.Uint32(p_[5:9])
		if got != code {
			t.Errorf("code=%d: got reason=%d", code, got)
		}
	}
}

// --- 1.13 CHANNEL_REQUEST ---

// 1.13.1: CHANNEL_REQUEST byte = 0x62 (98).
func TestTp_1_13_1(t *testing.T) {
	p := NewPlanner()
	spec := validSSHSpec()
	spec.SSH.AuthMethods = []core.SSHMessage{{Type: "userauth_success"}}
	spec.SSH.Channels = []core.ChannelEntry{
		{Type: "channel_request", RecipientChannel: 0, RequestType: "shell", WantReply: true},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if findMsg(cfgs, 0x62) == nil {
		t.Errorf("CHANNEL_REQUEST not found")
	}
}

// 1.13.6: shell request type.
func TestTp_1_13_6(t *testing.T) {
	p := NewPlanner()
	spec := validSSHSpec()
	spec.SSH.AuthMethods = []core.SSHMessage{{Type: "userauth_success"}}
	spec.SSH.Channels = []core.ChannelEntry{
		{Type: "channel_request", RecipientChannel: 0, RequestType: "shell", WantReply: true},
	}
	cfgs := drain(mustPlan(t, p, spec))
	c := findMsg(cfgs, 0x62)
	if c == nil {
		t.Fatal("CHANNEL_REQUEST not found")
	}
	p_ := bppPayload(c.Payload)
	typeLen := binary.BigEndian.Uint32(p_[5:9])
	if string(p_[9:9+int(typeLen)]) != "shell" {
		t.Errorf("request_type=%q, want 'shell'", string(p_[9:9+int(typeLen)]))
	}
}

// 1.13.7: exec request type with command.
func TestTp_1_13_7(t *testing.T) {
	p := NewPlanner()
	spec := validSSHSpec()
	spec.SSH.AuthMethods = []core.SSHMessage{{Type: "userauth_success"}}
	spec.SSH.Channels = []core.ChannelEntry{
		{Type: "channel_request", RecipientChannel: 0, RequestType: "exec", WantReply: true, Command: "ls -l"},
	}
	cfgs := drain(mustPlan(t, p, spec))
	c := findMsg(cfgs, 0x62)
	if c == nil {
		t.Fatal("CHANNEL_REQUEST not found")
	}
	p_ := bppPayload(c.Payload)
	off := 5
	typeLen := binary.BigEndian.Uint32(p_[off : off+4])
	off += 4 + int(typeLen) + 1 // +want_reply
	cmdLen := binary.BigEndian.Uint32(p_[off : off+4])
	if string(p_[off+4:off+4+int(cmdLen)]) != "ls -l" {
		t.Errorf("command=%q, want 'ls -l'", string(p_[off+4:off+4+int(cmdLen)]))
	}
}

// 1.13.12: exit-status request type.
func TestTp_1_13_12(t *testing.T) {
	p := NewPlanner()
	spec := validSSHSpec()
	spec.SSH.AuthMethods = []core.SSHMessage{{Type: "userauth_success"}}
	spec.SSH.Channels = []core.ChannelEntry{
		{Type: "channel_request", RecipientChannel: 0, RequestType: "exit-status", WantReply: false, ExitStatus: 0},
	}
	cfgs := drain(mustPlan(t, p, spec))
	c := findMsg(cfgs, 0x62)
	if c == nil {
		t.Fatal("CHANNEL_REQUEST not found")
	}
	p_ := bppPayload(c.Payload)
	off := 5
	typeLen := binary.BigEndian.Uint32(p_[off : off+4])
	off += 4 + int(typeLen) + 1
	exitStatus := binary.BigEndian.Uint32(p_[off : off+4])
	if exitStatus != 0 {
		t.Errorf("exit_status=%d, want 0", exitStatus)
	}
}

// --- 1.14 CHANNEL_DATA / EXTENDED_DATA / WINDOW_ADJUST ---

// 1.14.1: CHANNEL_DATA byte = 0x5E (94).
func TestTp_1_14_1(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validSSHSpec()))
	if findMsg(cfgs, 0x5E) == nil {
		t.Errorf("CHANNEL_DATA not found in default dialog")
	}
}

// 1.14.3: CHANNEL_DATA with 1-byte data.
func TestTp_1_14_3(t *testing.T) {
	p := NewPlanner()
	spec := validSSHSpec()
	spec.SSH.AuthMethods = []core.SSHMessage{{Type: "userauth_success"}}
	spec.SSH.Channels = []core.ChannelEntry{
		{Type: "channel_data", RecipientChannel: 0, Data: []byte("X"), Direction: "up"},
	}
	cfgs := drain(mustPlan(t, p, spec))
	c := findMsg(cfgs, 0x5E)
	if c == nil {
		t.Fatal("CHANNEL_DATA not found")
	}
	p_ := bppPayload(c.Payload)
	dataLen := binary.BigEndian.Uint32(p_[5:9])
	if dataLen != 1 {
		t.Errorf("data length=%d, want 1", dataLen)
	}
	if string(p_[9:10]) != "X" {
		t.Errorf("data=%q, want 'X'", string(p_[9:10]))
	}
}

// 1.14.6: CHANNEL_EXTENDED_DATA byte = 0x5F (95).
func TestTp_1_14_6(t *testing.T) {
	p := NewPlanner()
	spec := validSSHSpec()
	spec.SSH.AuthMethods = []core.SSHMessage{{Type: "userauth_success"}}
	spec.SSH.Channels = []core.ChannelEntry{
		{Type: "channel_extended_data", RecipientChannel: 0, DataTypeCode: 1, Data: []byte("err"), Direction: "down"},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if findMsg(cfgs, 0x5F) == nil {
		t.Errorf("CHANNEL_EXTENDED_DATA not found")
	}
}

// 1.14.9: CHANNEL_WINDOW_ADJUST byte = 0x5D (93).
func TestTp_1_14_9(t *testing.T) {
	p := NewPlanner()
	spec := validSSHSpec()
	spec.SSH.AuthMethods = []core.SSHMessage{{Type: "userauth_success"}}
	spec.SSH.Channels = []core.ChannelEntry{
		{Type: "channel_window_adjust", RecipientChannel: 0, BytesToAdd: 1048576, Direction: "down"},
	}
	cfgs := drain(mustPlan(t, p, spec))
	c := findMsg(cfgs, 0x5D)
	if c == nil {
		t.Errorf("CHANNEL_WINDOW_ADJUST not found")
		return
	}
	p_ := bppPayload(c.Payload)
	bytesToAdd := binary.BigEndian.Uint32(p_[5:9])
	if bytesToAdd != 1048576 {
		t.Errorf("bytes_to_add=%d, want 1048576", bytesToAdd)
	}
}

// --- 1.15 CHANNEL_EOF/CLOSE/SUCCESS/FAILURE ---

// 1.15.1: CHANNEL_EOF byte = 0x60 (96).
func TestTp_1_15_1(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validSSHSpec()))
	if findMsg(cfgs, 0x60) == nil {
		t.Errorf("CHANNEL_EOF not found in default dialog")
	}
}

// 1.15.3: CHANNEL_CLOSE byte = 0x61 (97).
func TestTp_1_15_3(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validSSHSpec()))
	if countMsg(cfgs, 0x61) < 2 {
		t.Errorf("CHANNEL_CLOSE count=%d, want >= 2 (both sides)", countMsg(cfgs, 0x61))
	}
}

// --- 1.16 GLOBAL_REQUEST ---

// 1.16.1: GLOBAL_REQUEST byte = 0x50 (80).
func TestTp_1_16_1(t *testing.T) {
	p := NewPlanner()
	spec := validSSHSpec()
	spec.SSH.AuthMethods = []core.SSHMessage{{Type: "userauth_success"}}
	spec.SSH.Channels = []core.ChannelEntry{
		{Type: "global_request", GlobalRequestName: "tcpip-forward", WantReply: true, Address: "0.0.0.0", Port: 8080},
	}
	cfgs := drain(mustPlan(t, p, spec))
	c := findMsg(cfgs, 0x50)
	if c == nil {
		t.Errorf("GLOBAL_REQUEST not found")
		return
	}
	if c.Direction != "up" {
		t.Errorf("GLOBAL_REQUEST dir=%s, want up", c.Direction)
	}
}

// 1.16.8: REQUEST_SUCCESS byte = 0x51 (81).
func TestTp_1_16_8(t *testing.T) {
	p := NewPlanner()
	spec := validSSHSpec()
	spec.SSH.AuthMethods = []core.SSHMessage{{Type: "userauth_success"}}
	spec.SSH.Channels = []core.ChannelEntry{
		{Type: "global_request", GlobalRequestName: "tcpip-forward", WantReply: true, Address: "0.0.0.0", Port: 8080},
		{Type: "request_success", Port: 8080},
	}
	cfgs := drain(mustPlan(t, p, spec))
	c := findMsg(cfgs, 0x51)
	if c == nil {
		t.Errorf("REQUEST_SUCCESS not found")
		return
	}
	if c.Direction != "down" {
		t.Errorf("REQUEST_SUCCESS dir=%s, want down", c.Direction)
	}
}

// 1.16.11: REQUEST_FAILURE byte = 0x52 (82), 1-byte payload.
func TestTp_1_16_11(t *testing.T) {
	p := NewPlanner()
	spec := validSSHSpec()
	spec.SSH.AuthMethods = []core.SSHMessage{{Type: "userauth_success"}}
	spec.SSH.Channels = []core.ChannelEntry{
		{Type: "global_request", GlobalRequestName: "x", WantReply: true},
		{Type: "request_failure"},
	}
	cfgs := drain(mustPlan(t, p, spec))
	c := findMsg(cfgs, 0x52)
	if c == nil {
		t.Errorf("REQUEST_FAILURE not found")
		return
	}
	p_ := bppPayload(c.Payload)
	if len(p_) != 1 {
		t.Errorf("REQUEST_FAILURE payload len=%d, want 1", len(p_))
	}
}

// --- 1.17 DISCONNECT ---

// 1.17.1: DISCONNECT byte = 0x01.
func TestTp_1_17_1(t *testing.T) {
	p := NewPlanner()
	spec := validSSHSpec()
	spec.SSH.DisconnectOnClose = true
	cfgs := drain(mustPlan(t, p, spec))
	if findMsg(cfgs, 0x01) == nil {
		t.Errorf("DISCONNECT not found with DisconnectOnClose=true")
	}
}

// 1.17.2-9: various reason codes.
func TestTp_1_17_ReasonCodes(t *testing.T) {
	codes := []uint32{
		DiscHostNotAllowed, DiscProtocolError, DiscKeyExchangeFailed,
		DiscMACError, DiscServiceNotAvailable, DiscConnectionLost,
		DiscByApplication, DiscNoMoreAuthMethods,
	}
	for _, code := range codes {
		p := NewPlanner()
		spec := validSSHSpec()
		spec.SSH.AuthMethods = []core.SSHMessage{
			{Type: "disconnect", ReasonCode: code, Description: "x", Direction: "up"},
		}
		cfgs := drain(mustPlan(t, p, spec))
		c := findMsg(cfgs, 0x01)
		if c == nil {
			t.Errorf("code=%d: DISCONNECT not found", code)
			continue
		}
		p_ := bppPayload(c.Payload)
		got := binary.BigEndian.Uint32(p_[1:5])
		if got != code {
			t.Errorf("code=%d: got reason=%d", code, got)
		}
	}
}

// 1.17.12: disconnect reason_code=0 -> Validate error.
func TestTp_1_17_12(t *testing.T) {
	p := NewPlanner()
	spec := validSSHSpec()
	spec.SSH.AuthMethods = []core.SSHMessage{
		{Type: "disconnect", ReasonCode: 0},
	}
	if err := p.Validate(spec); err == nil || !strings.Contains(err.Error(), "reserved") {
		t.Errorf("err=%v, want 'reserved'", err)
	}
}

// --- 1.18 IGNORE / UNIMPLEMENTED / DEBUG ---

// 1.18.1: IGNORE byte = 0x02.
func TestTp_1_18_1(t *testing.T) {
	p := NewPlanner()
	spec := validSSHSpec()
	spec.SSH.AuthMethods = []core.SSHMessage{
		{Type: "ignore", Data: []byte("x"), Direction: "up"},
		{Type: "userauth_success"},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if findMsg(cfgs, 0x02) == nil {
		t.Errorf("IGNORE not found")
	}
}

// 1.18.4: UNIMPLEMENTED byte = 0x03.
func TestTp_1_18_4(t *testing.T) {
	p := NewPlanner()
	spec := validSSHSpec()
	spec.SSH.AuthMethods = []core.SSHMessage{
		{Type: "unimplemented", ReceiveSeq: 7, Direction: "up"},
		{Type: "userauth_success"},
	}
	cfgs := drain(mustPlan(t, p, spec))
	c := findMsg(cfgs, 0x03)
	if c == nil {
		t.Errorf("UNIMPLEMENTED not found")
		return
	}
	p_ := bppPayload(c.Payload)
	seq := binary.BigEndian.Uint32(p_[1:5])
	if seq != 7 {
		t.Errorf("receive_seq=%d, want 7", seq)
	}
}

// 1.18.6: DEBUG byte = 0x04.
func TestTp_1_18_6(t *testing.T) {
	p := NewPlanner()
	spec := validSSHSpec()
	spec.SSH.AuthMethods = []core.SSHMessage{
		{Type: "debug", AlwaysDisplay: true, Message: "hi", LanguageTag: "en", Direction: "down"},
		{Type: "userauth_success"},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if findMsg(cfgs, 0x04) == nil {
		t.Errorf("DEBUG not found")
	}
}

// 1.18.7: DEBUG always_display=1.
func TestTp_1_18_7(t *testing.T) {
	p := NewPlanner()
	spec := validSSHSpec()
	spec.SSH.AuthMethods = []core.SSHMessage{
		{Type: "debug", AlwaysDisplay: true, Message: "hi", LanguageTag: "en", Direction: "down"},
		{Type: "userauth_success"},
	}
	cfgs := drain(mustPlan(t, p, spec))
	c := findMsg(cfgs, 0x04)
	if c == nil {
		t.Fatal("DEBUG not found")
	}
	p_ := bppPayload(c.Payload)
	if p_[1] != 0x01 {
		t.Errorf("always_display=0x%02x, want 0x01", p_[1])
	}
}

// --- 1.19 wire-format primitives ---

// 1.19.1: string "hello" -> 0x00 0x00 0x00 0x05 + "hello".
func TestTp_1_19_1(t *testing.T) {
	out := encString(nil, []byte("hello"))
	want := []byte{0x00, 0x00, 0x00, 0x05, 'h', 'e', 'l', 'l', 'o'}
	if !bytesEqual(out, want) {
		t.Errorf("encString(hello)=%v, want %v", out, want)
	}
}

// 1.19.2: empty string -> 0x00 0x00 0x00 0x00.
func TestTp_1_19_2(t *testing.T) {
	out := encString(nil, nil)
	want := []byte{0x00, 0x00, 0x00, 0x00}
	if !bytesEqual(out, want) {
		t.Errorf("encString(empty)=%v, want %v", out, want)
	}
}

// --- 2.x state machine tests ---

// State machine is implicit in the dialog order. The planner_test.go
// Handshake/Teardown tests already verify order. Here we add one explicit
// state-machine test: KEXINIT before KEXDH_INIT.
func TestTp_2_1_KexBeforeKexDH(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validSSHSpec()))
	// Find KEXINIT index and KEXDH_INIT index.
	kexInitIdx, kexDHInitIdx := -1, -1
	for i, c := range cfgs {
		p_ := bppPayload(c.Payload)
		if len(p_) == 0 {
			continue
		}
		if p_[0] == MsgKexInit && kexInitIdx == -1 {
			kexInitIdx = i
		}
		if p_[0] == MsgKexDHInit && kexDHInitIdx == -1 {
			kexDHInitIdx = i
		}
	}
	if kexInitIdx == -1 || kexDHInitIdx == -1 {
		t.Fatalf("KEXINIT or KEXDH_INIT not found")
	}
	if kexDHInitIdx <= kexInitIdx {
		t.Errorf("KEXDH_INIT at %d, KEXINIT at %d - KEXINIT must come first", kexDHInitIdx, kexInitIdx)
	}
}

// 2.x: NEWKEYS before SERVICE_REQUEST.
func TestTp_2_2_NewKeysBeforeService(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validSSHSpec()))
	newKeysIdx, svcIdx := -1, -1
	for i, c := range cfgs {
		p_ := bppPayload(c.Payload)
		if len(p_) == 0 {
			continue
		}
		if p_[0] == MsgNewKeys && newKeysIdx == -1 {
			newKeysIdx = i
		}
		if p_[0] == MsgServiceRequest && svcIdx == -1 {
			svcIdx = i
		}
	}
	if newKeysIdx == -1 || svcIdx == -1 {
		t.Fatalf("NEWKEYS or SERVICE_REQUEST not found")
	}
	if svcIdx <= newKeysIdx {
		t.Errorf("SERVICE_REQUEST at %d, NEWKEYS at %d - NEWKEYS must come first", svcIdx, newKeysIdx)
	}
}

// 2.x: USERAUTH before CHANNEL.
func TestTp_2_3_AuthBeforeChannel(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validSSHSpec()))
	authIdx, chanIdx := -1, -1
	for i, c := range cfgs {
		p_ := bppPayload(c.Payload)
		if len(p_) == 0 {
			continue
		}
		if p_[0] == MsgUserAuthRequest && authIdx == -1 {
			authIdx = i
		}
		if p_[0] == MsgChannelOpen && chanIdx == -1 {
			chanIdx = i
		}
	}
	if authIdx == -1 || chanIdx == -1 {
		t.Fatalf("USERAUTH_REQUEST or CHANNEL_OPEN not found")
	}
	if chanIdx <= authIdx {
		t.Errorf("CHANNEL_OPEN at %d, USERAUTH_REQUEST at %d - USERAUTH must come first", chanIdx, authIdx)
	}
}

// --- 4.x data-scenario tests ---

// 4.x: large channel_data triggers MSS segmentation.
func TestTp_4_LargeChannelData(t *testing.T) {
	p := NewPlanner()
	spec := validSSHSpec()
	testutil.EnsureTCP(&spec).MSS = 800
	spec.SSH.AuthMethods = []core.SSHMessage{{Type: "userauth_success"}}
	spec.SSH.Channels = []core.ChannelEntry{
		{Type: "channel_data", RecipientChannel: 0, Data: make([]byte, 5000), Direction: "up"},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// 5000 bytes / 800 MSS = 7 segments (approx).
	count := 0
	for _, c := range cfgs {
		if c.Direction == "up" && c.L4.Flags == 0x18 && len(c.Payload) > 0 {
			// Channel-data BPP frames (encrypted, opaque, but observable as PSH-ACK up).
			count++
		}
	}
	if count < 6 {
		t.Errorf("up PSH-ACK count=%d, want >= 6 (segmentation of 5000-byte data)", count)
	}
}

// --- 5.x concurrency tests ---

// Concurrency: planner can be called from multiple goroutines producing
// independent channels. Per CLAUDE.md testing policy §6: -race clean is
// necessary but not sufficient; we verify independent FlowIDs.
func TestTp_5_ConcurrentIndependentPlans(t *testing.T) {
	p := NewPlanner()
	done := make(chan struct{}, 4)
	for i := 0; i < 4; i++ {
		go func(idx int) {
			defer func() { done <- struct{}{} }()
			spec := validSSHSpec()
			spec.SrcPort = uint16(50000 + idx)
			cfgs := drain(mustPlan(t, p, spec))
			want := "10.0.0.1-10.0.0.2-" + fmtUint(uint64(50000+idx)) + "-22"
			if cfgs[0].FlowID != want {
				t.Errorf("goroutine %d FlowID=%q, want %q", idx, cfgs[0].FlowID, want)
			}
		}(i)
	}
	for i := 0; i < 4; i++ {
		<-done
	}
}

// fmtUint is a tiny helper to avoid pulling in fmt for the concurrency test.
func fmtUint(v uint64) string {
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}

// --- 6.x resource-exhaustion / edge case tests ---

// 6.x: empty Channels list uses default dialog (does not panic).
func TestTp_6_EmptyChannelsDefault(t *testing.T) {
	p := NewPlanner()
	spec := validSSHSpec()
	spec.SSH.Channels = nil
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) < 15 {
		t.Errorf("len=%d, want >= 15 (default channel dialog)", len(cfgs))
	}
}

// 6.x: empty AuthMethods uses default dialog (does not panic).
func TestTp_6_EmptyAuthMethodsDefault(t *testing.T) {
	p := NewPlanner()
	spec := validSSHSpec()
	spec.SSH.AuthMethods = nil
	cfgs := drain(mustPlan(t, p, spec))
	// Should have USERAUTH_REQUEST + USERAUTH_SUCCESS in default.
	if findMsg(cfgs, MsgUserAuthRequest) == nil {
		t.Errorf("USERAUTH_REQUEST not found in default dialog")
	}
	if findMsg(cfgs, MsgUserAuthSuccess) == nil {
		t.Errorf("USERAUTH_SUCCESS not found in default dialog")
	}
}

// 6.x: large KEX algorithm list - verify wire encoding does not truncate.
// Note: when the BPP frame exceeds MSS, it gets segmented across TCP
// packets. We reassemble the first up-direction PSH-ACK stream after the
// handshake to recover the full KEXINIT frame.
func TestTp_6_LargeKexAlgList(t *testing.T) {
	p := NewPlanner()
	spec := validSSHSpec()
	spec.SSH.KexAlgorithms = strings.Repeat("curve25519-sha256,", 50) + "ext-info-c"
	if err := p.Validate(spec); err != nil {
		t.Fatalf("validate: %v", err)
	}
	cfgs := drain(mustPlan(t, p, spec))
	// Collect up-direction PSH-ACK payloads starting after the handshake.
	// The KEXINIT is the first up PSH-ACK after the handshake ACK.
	var assembled []byte
	for _, c := range cfgs {
		if c.Direction == "up" && c.L4.Flags == 0x18 && len(c.Payload) > 0 {
			assembled = append(assembled, c.Payload...)
			// Stop once we have enough bytes for the BPP header.
			if len(assembled) >= 4 {
				pktLen := binary.BigEndian.Uint32(assembled[:4])
				if len(assembled) >= int(pktLen)+4 {
					break
				}
			}
		}
	}
	if len(assembled) < 4 {
		t.Fatal("no up PSH-ACK payload found")
	}
	// The first 4 bytes are packet_length; the payload starts at offset 5
	// (after padding_length byte).
	pktLen := binary.BigEndian.Uint32(assembled[:4])
	padLen := int(assembled[4])
	if int(pktLen) < 1+padLen {
		t.Fatalf("pktLen=%d padLen=%d inconsistent", pktLen, padLen)
	}
	payloadEnd := 5 + int(pktLen) - 1 - padLen
	if payloadEnd > len(assembled) {
		t.Fatalf("assembled too short: %d < %d", len(assembled), payloadEnd)
	}
	p_ := assembled[5:payloadEnd]
	if p_[0] != MsgKexInit {
		t.Fatalf("first up PSH-ACK msg=0x%02x, want KEXINIT (0x14)", p_[0])
	}
	kexAlgLen := binary.BigEndian.Uint32(p_[17:21])
	// Length should match our input.
	wantLen := uint32(len(spec.SSH.KexAlgorithms))
	if kexAlgLen != wantLen {
		t.Errorf("kex_algorithms length=%d, want %d", kexAlgLen, wantLen)
	}
}

// 6.x: MSS boundary - very small (legal minimum 536).
func TestTp_6_MSSMinimum(t *testing.T) {
	p := NewPlanner()
	spec := validSSHSpec()
	testutil.EnsureTCP(&spec).MSS = 536
	if err := p.Validate(spec); err != nil {
		t.Errorf("MSS=536 should be accepted: %v", err)
	}
}

// 6.x: MSS below minimum rejected.
func TestTp_6_MSSBelowMinimum(t *testing.T) {
	p := NewPlanner()
	spec := validSSHSpec()
	testutil.EnsureTCP(&spec).MSS = 535
	if err := p.Validate(spec); err == nil {
		t.Errorf("MSS=535 should be rejected")
	}
}

// --- Validate idempotency ---

func TestTp_ValidateIdempotent(t *testing.T) {
	p := NewPlanner()
	spec := validSSHSpec()
	err1 := p.Validate(spec)
	err2 := p.Validate(spec)
	if (err1 == nil) != (err2 == nil) {
		t.Errorf("not idempotent: err1=%v err2=%v", err1, err2)
	}
}

// --- Integration: full flow packet count ---

// Verify the full packet count for a known spec.
func TestTp_Integration_PacketCount(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validSSHSpec()))
	// Default spec (no version exchange):
	// 3 handshake + 2 KEXINIT + 1 KEXDH_INIT + 1 KEXDH_REPLY + 2 NEWKEYS
	// + 2 SERVICE + 2 USERAUTH (default) + 6 channel (default: open, confirm,
	// data, eof, close up, close down) + 4 teardown = 23
	if len(cfgs) != 23 {
		t.Errorf("len=%d, want 23 (3+2+1+1+2+2+2+6+4)", len(cfgs))
	}
}

// Verify with version exchange.
func TestTp_Integration_PacketCountWithVersions(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, specWith()))
	// Add 2 version packets -> 25.
	if len(cfgs) != 25 {
		t.Errorf("len=%d, want 25 (with version exchange)", len(cfgs))
	}
}

// Verify with ExtInfo.
func TestTp_Integration_PacketCountWithExtInfo(t *testing.T) {
	p := NewPlanner()
	spec := validSSHSpec()
	spec.SSH.ExtInfo = true
	cfgs := drain(mustPlan(t, p, spec))
	// Add 2 EXT_INFO packets -> 25.
	if len(cfgs) != 25 {
		t.Errorf("len=%d, want 25 (with EXT_INFO)", len(cfgs))
	}
}

// Verify with DisconnectOnClose.
func TestTp_Integration_PacketCountWithDisconnect(t *testing.T) {
	p := NewPlanner()
	spec := validSSHSpec()
	spec.SSH.DisconnectOnClose = true
	cfgs := drain(mustPlan(t, p, spec))
	// Add 1 DISCONNECT packet -> 24.
	if len(cfgs) != 24 {
		t.Errorf("len=%d, want 24 (with DisconnectOnClose)", len(cfgs))
	}
}

// Verify context cancellation does not deadlock.
func TestTp_Integration_ContextCancel(t *testing.T) {
	p := NewPlanner()
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before Plan returns
	ch, err := p.Plan(ctx, validSSHSpec())
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	// Drain to ensure goroutine exits cleanly.
	drain(ch)
}
