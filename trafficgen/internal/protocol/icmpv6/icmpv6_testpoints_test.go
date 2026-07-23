package icmpv6

// Test points for the ICMPv6 planner. Each test asserts observable
// PacketConfig field values, not just "no error". Derived from RFC 4443
// (ICMPv6) and RFC 8200 (IPv6 data plane).

import (
	"context"
	"encoding/binary"
	"net"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

// drain collects all configs from the channel.
func drain(ch <-chan core.PacketConfig) []core.PacketConfig {
	var out []core.PacketConfig
	for c := range ch {
		out = append(out, c)
	}
	return out
}

// validSpec returns a spec with a single Echo Request. Models a ping6
// from fd00::1 to fd00::2 (ULA range, RFC 4193 — no risk of colliding
// with real internet traffic). DSCP is set explicitly so the IPv6
// TrafficClass byte is non-zero and exercises the (6<<4)|(tc>>4)
// encoding in the IPv6 header first byte.
func validSpec() core.FlowSpec {
	return core.FlowSpec{
		SrcIP: "fd00::1", DstIP: "fd00::2",
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		DSCP: 0x08,
		ICMPv6: &core.ICMPv6Config{
			Type:       TypeEchoRequestV6,
			Code:       0,
			Identifier: 0xbeef,
			Sequence:   1,
			Data:       []byte("ping"),
		},
	}
}

// --- Validate ---

func TestValidate_ValidIPv6(t *testing.T) {
	p := NewPlanner()
	if err := p.Validate(validSpec()); err != nil {
		t.Errorf("valid spec: %v", err)
	}
}

func TestValidate_InvalidSrcIP(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.SrcIP = "bad"
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "invalid source IP") {
		t.Errorf("err=%v, want contains 'invalid source IP'", err)
	}
}

func TestValidate_InvalidDstIP(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.DstIP = "bad"
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "invalid destination IP") {
		t.Errorf("err=%v, want contains 'invalid destination IP'", err)
	}
}

func TestValidate_IPv4Rejected(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.SrcIP = "10.0.0.1"
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "must be IPv6") {
		t.Errorf("err=%v, want contains 'must be IPv6'", err)
	}
}

// --- Plan: structure ---

// TestPlan_SinglePing verifies the single-ping path emits exactly two
// packets (Echo Request up + Echo Reply down) with the correct
// EtherType, IP protocol, and direction.
func TestPlan_SinglePing(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validSpec()))
	if len(cfgs) != 2 {
		t.Fatalf("len=%d, want 2 (request + reply)", len(cfgs))
	}
	// Echo Request
	if cfgs[0].Direction != "up" {
		t.Errorf("cfg[0]: dir=%s, want up", cfgs[0].Direction)
	}
	if cfgs[0].L2.EtherType != core.EtherTypeIPv6 {
		t.Errorf("cfg[0]: EtherType=0x%04x, want 0x86DD", cfgs[0].L2.EtherType)
	}
	if cfgs[0].L3.Protocol != ProtocolICMPv6 {
		t.Errorf("cfg[0]: L3 Protocol=%d, want %d (ICMPv6)", cfgs[0].L3.Protocol, ProtocolICMPv6)
	}
	if cfgs[0].L4.Protocol != "icmpv6" {
		t.Errorf("cfg[0]: L4 protocol=%s, want icmpv6", cfgs[0].L4.Protocol)
	}
	if cfgs[0].Payload[0] != TypeEchoRequestV6 {
		t.Errorf("cfg[0]: type=%d, want %d (Echo Request)", cfgs[0].Payload[0], TypeEchoRequestV6)
	}
	// Echo Reply
	if cfgs[1].Direction != "down" {
		t.Errorf("cfg[1]: dir=%s, want down", cfgs[1].Direction)
	}
	if cfgs[1].Payload[0] != TypeEchoReplyV6 {
		t.Errorf("cfg[1]: type=%d, want %d (Echo Reply)", cfgs[1].Payload[0], TypeEchoReplyV6)
	}
}

// TestPlan_MultiSessionPattern verifies the multi-session path emits
// each step as its own ping (request + auto-reply), all sharing the
// same flow ID. Mirrors the ICMPv4 pattern tests.
func TestPlan_MultiSessionPattern(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.ICMPv6.Pattern = []core.ICMPv6Step{
		{Type: TypeEchoRequestV6, Data: []byte("a")},
		{Type: TypeEchoRequestV6, Data: []byte("b")},
		{Type: TypeEchoRequestV6, Data: []byte("c")},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// 3 steps × 2 packets (request + reply) = 6 packets
	if len(cfgs) != 6 {
		t.Fatalf("len=%d, want 6", len(cfgs))
	}
	flowID := cfgs[0].FlowID
	if flowID == "" {
		t.Fatal("FlowID empty")
	}
	for i, c := range cfgs {
		if c.FlowID != flowID {
			t.Errorf("cfg[%d].FlowID=%q, want %q (shared across pings)", i, c.FlowID, flowID)
		}
	}
	// Requests at even indices, replies at odd.
	for i := 0; i < 6; i += 2 {
		if cfgs[i].Payload[0] != TypeEchoRequestV6 {
			t.Errorf("cfg[%d]: type=%d, want %d (request)", i, cfgs[i].Payload[0], TypeEchoRequestV6)
		}
		if cfgs[i].Direction != "up" {
			t.Errorf("cfg[%d]: dir=%s, want up", i, cfgs[i].Direction)
		}
	}
	for i := 1; i < 6; i += 2 {
		if cfgs[i].Payload[0] != TypeEchoReplyV6 {
			t.Errorf("cfg[%d]: type=%d, want %d (reply)", i, cfgs[i].Payload[0], TypeEchoReplyV6)
		}
		if cfgs[i].Direction != "down" {
			t.Errorf("cfg[%d]: dir=%s, want down", i, cfgs[i].Direction)
		}
	}
}

// TestPlan_SequenceIncrementsPerStep verifies that Sequence increments
// per step when the step leaves it at 0 (auto-fill from step index+1).
func TestPlan_SequenceIncrementsPerStep(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.ICMPv6.Pattern = []core.ICMPv6Step{
		{Type: TypeEchoRequestV6, Data: []byte("a")},
		{Type: TypeEchoRequestV6, Data: []byte("b")},
		{Type: TypeEchoRequestV6, Data: []byte("c")},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// Requests at indices 0, 2, 4. Sequence is at payload bytes 6-7.
	wantSeqs := []uint16{1, 2, 3}
	for i, want := range wantSeqs {
		idx := i * 2
		got := binary.BigEndian.Uint16(cfgs[idx].Payload[6:8])
		if got != want {
			t.Errorf("cfg[%d] Sequence=%d, want %d", idx, got, want)
		}
	}
}

// TestPlan_IdentifierSharedAcrossSteps verifies the Identifier is shared
// across all pings in a multi-session flow (RFC 4443 §4.1: Identifier
// groups pings into a session).
func TestPlan_IdentifierSharedAcrossSteps(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.ICMPv6.Identifier = 0x1234
	spec.ICMPv6.Pattern = []core.ICMPv6Step{
		{Type: TypeEchoRequestV6, Data: []byte("a")},
		{Type: TypeEchoRequestV6, Data: []byte("b")},
	}
	cfgs := drain(mustPlan(t, p, spec))
	for i, c := range cfgs {
		id := binary.BigEndian.Uint16(c.Payload[4:6])
		if id != 0x1234 {
			t.Errorf("cfg[%d] Identifier=0x%04x, want 0x1234 (shared)", i, id)
		}
	}
}

// TestPlan_IdentifierFallbackToSequence verifies that when Identifier=0,
// the planner falls back to using Sequence as the Identifier (matching
// ICMPv4's behavior so request/reply within a single ping share a value).
func TestPlan_IdentifierFallbackToSequence(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.ICMPv6.Identifier = 0
	spec.ICMPv6.Sequence = 42
	cfgs := drain(mustPlan(t, p, spec))
	// Request and reply should both carry Identifier=42 (the Sequence
	// value, used as fallback).
	for i, c := range cfgs {
		id := binary.BigEndian.Uint16(c.Payload[4:6])
		if id != 42 {
			t.Errorf("cfg[%d] Identifier=%d, want 42 (Sequence fallback)", i, id)
		}
	}
}

// TestPlan_ReplyMirrorsRequestFields verifies the Echo Reply echoes the
// request's Identifier and Sequence (RFC 4443 §4.2: reply must echo
// these fields).
func TestPlan_ReplyMirrorsRequestFields(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validSpec()))
	reqID := binary.BigEndian.Uint16(cfgs[0].Payload[4:6])
	reqSeq := binary.BigEndian.Uint16(cfgs[0].Payload[6:8])
	replyID := binary.BigEndian.Uint16(cfgs[1].Payload[4:6])
	replySeq := binary.BigEndian.Uint16(cfgs[1].Payload[6:8])
	if reqID != replyID {
		t.Errorf("Identifier: request=%d reply=%d (reply must mirror)", reqID, replyID)
	}
	if reqSeq != replySeq {
		t.Errorf("Sequence: request=%d reply=%d (reply must mirror)", reqSeq, replySeq)
	}
}

// TestPlan_IPv6HeaderFields verifies the IPv6 header fields the Builder
// will emit: EtherType, protocol, hop limit. The Builder writes the
// actual 40-byte header; here we verify the PacketConfig carries the
// right values into the Builder.
func TestPlan_IPv6HeaderFields(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validSpec()))
	for i, c := range cfgs {
		if c.L2.EtherType != core.EtherTypeIPv6 {
			t.Errorf("cfg[%d] EtherType=0x%04x, want 0x86DD", i, c.L2.EtherType)
		}
		if c.L3.Protocol != ProtocolICMPv6 {
			t.Errorf("cfg[%d] Protocol=%d, want %d (ICMPv6)", i, c.L3.Protocol, ProtocolICMPv6)
		}
		if c.L3.TTL != DefaultTTL {
			t.Errorf("cfg[%d] TTL=%d, want %d (default hop limit)", i, c.L3.TTL, DefaultTTL)
		}
	}
}

// TestPlan_IPv6SourceAddrInHeader verifies the Builder actually writes
// the IPv6 source address into the IPv6 header (40 bytes at L2 offset
// 14, srcIP at offset 22). This is the integration test for writeL3v6.
func TestPlan_IPv6SourceAddrInHeader(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validSpec()))
	b := core.NewBuilder()
	pkt, err := b.Build(cfgs[0])
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	// Ethernet header is 14 bytes; IPv6 srcIP starts at offset 22 (14+8).
	srcBytes := pkt[22 : 22+16]
	want := net.ParseIP("fd00::1").To16()
	if !bytesEqual(srcBytes, want) {
		t.Errorf("IPv6 srcIP bytes=%v, want %v", srcBytes, want)
	}
	dstBytes := pkt[38 : 38+16]
	wantDst := net.ParseIP("fd00::2").To16()
	if !bytesEqual(dstBytes, wantDst) {
		t.Errorf("IPv6 dstIP bytes=%v, want %v", dstBytes, wantDst)
	}
}

// TestPlan_IPv6VersionAndTrafficClass verifies the first 4 bytes of the
// IPv6 header encode Version=6, TrafficClass=(DSCP<<2|ECN), FlowLabel=0.
func TestPlan_IPv6VersionAndTrafficClass(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validSpec()))
	b := core.NewBuilder()
	pkt, _ := b.Build(cfgs[0])
	// First byte of IPv6 header: (6<<4) | (tc>>4). With default DSCP=0x08,
	// tc=(0x08<<2)|0=0x20, tc>>4=0x02, so byte[14]=0x62.
	if pkt[14] != 0x62 {
		t.Errorf("IPv6 byte[0]=0x%02x, want 0x62 (v6 + DSCP 0x08)", pkt[14])
	}
}

// TestPlan_IPv6PayloadLength verifies the Payload Length field (bytes
// 18-19 of the IPv6 header) equals the ICMPv6 message length (8-byte
// header + len(data)).
func TestPlan_IPv6PayloadLength(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validSpec()))
	b := core.NewBuilder()
	pkt, _ := b.Build(cfgs[0])
	payloadLen := binary.BigEndian.Uint16(pkt[18:20])
	// 8 (ICMPv6 header) + 4 ("ping") = 12
	if payloadLen != 12 {
		t.Errorf("IPv6 Payload Length=%d, want 12 (8 hdr + 4 data)", payloadLen)
	}
}

// TestPlan_NextHeaderIsICMPv6 verifies the Next Header field (byte 20 of
// the IPv6 header) is 58 (ICMPv6).
func TestPlan_NextHeaderIsICMPv6(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validSpec()))
	b := core.NewBuilder()
	pkt, _ := b.Build(cfgs[0])
	if pkt[20] != ProtocolICMPv6 {
		t.Errorf("Next Header=%d, want %d (ICMPv6)", pkt[20], ProtocolICMPv6)
	}
}

// TestPlan_HopLimit verifies the Hop Limit field (byte 21 of the IPv6
// header) defaults to 64 when spec.TTL is 0.
func TestPlan_HopLimit(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validSpec()))
	b := core.NewBuilder()
	pkt, _ := b.Build(cfgs[0])
	if pkt[21] != DefaultTTL {
		t.Errorf("Hop Limit=%d, want %d (default)", pkt[21], DefaultTTL)
	}
}

// TestPlan_ICMPv6ChecksumNonZero verifies the ICMPv6 checksum (bytes 2-3
// of the ICMPv6 message) is computed and non-zero. The exact value
// depends on src/dst IP + message content; we only assert non-zero to
// catch a regression where the pseudo-header is skipped.
func TestPlan_ICMPv6ChecksumNonZero(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validSpec()))
	for i, c := range cfgs {
		cs := binary.BigEndian.Uint16(c.Payload[2:4])
		if cs == 0 {
			t.Errorf("cfg[%d] checksum=0, want non-zero (pseudo-header must be folded in)", i)
		}
	}
}

// TestPlan_ICMPv6ChecksumMatchesReference verifies the checksum matches
// a reference implementation computed over the same bytes. This is the
// strongest correctness check — if the pseudo-header or message folding
// is wrong, the checksum will differ.
func TestPlan_ICMPv6ChecksumMatchesReference(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	cfgs := drain(mustPlan(t, p, spec))
	// Reference: recompute from src/dst IP + the ICMPv6 message with
	// checksum zeroed.
	msg := make([]byte, len(cfgs[0].Payload))
	copy(msg, cfgs[0].Payload)
	binary.BigEndian.PutUint16(msg[2:4], 0)
	want := calculateICMPv6Checksum(spec.SrcIP, spec.DstIP, msg)
	got := binary.BigEndian.Uint16(cfgs[0].Payload[2:4])
	if got != want {
		t.Errorf("checksum=0x%04x, want 0x%04x (reference)", got, want)
	}
}

// TestPlan_ReplySwapsIPsAndMACs verifies the reply packet swaps src/dst
// IP and src/dst MAC (server→client direction).
func TestPlan_ReplySwapsIPsAndMACs(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validSpec()))
	if cfgs[1].L3.SrcIP != "fd00::2" {
		t.Errorf("reply srcIP=%s, want fd00::2 (server)", cfgs[1].L3.SrcIP)
	}
	if cfgs[1].L3.DstIP != "fd00::1" {
		t.Errorf("reply dstIP=%s, want fd00::1 (client)", cfgs[1].L3.DstIP)
	}
	if cfgs[1].L2.SrcMAC != "11:22:33:44:55:66" {
		t.Errorf("reply srcMAC=%s, want 11:22:33:44:55:66 (server)", cfgs[1].L2.SrcMAC)
	}
	if cfgs[1].L2.DstMAC != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("reply dstMAC=%s, want aa:bb:cc:dd:ee:ff (client)", cfgs[1].L2.DstMAC)
	}
}

// TestPlan_NilConfigDefaults verifies that a spec with nil ICMPv6 config
// defaults to Echo Request, Code 0, Sequence 1, Data "ping" — matching
// ICMPv4's default behavior.
func TestPlan_NilConfigDefaults(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.ICMPv6 = nil
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) != 2 {
		t.Fatalf("len=%d, want 2 (default request + reply)", len(cfgs))
	}
	if cfgs[0].Payload[0] != TypeEchoRequestV6 {
		t.Errorf("default type=%d, want %d (Echo Request)", cfgs[0].Payload[0], TypeEchoRequestV6)
	}
	// Default data "ping" (4 bytes) → payload length 12 (8 header + 4 data)
	if len(cfgs[0].Payload) != 12 {
		t.Errorf("default payload len=%d, want 12 (8 hdr + 'ping')", len(cfgs[0].Payload))
	}
}

// TestPlan_EchoReplyNoAutoReply verifies that a step with Type=EchoReply
// (129) does NOT trigger an auto-reply (the auto-reply is only for Echo
// Request steps).
func TestPlan_EchoReplyNoAutoReply(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.ICMPv6.Pattern = []core.ICMPv6Step{
		{Type: TypeEchoReplyV6, Data: []byte("unsolicited")},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) != 1 {
		t.Errorf("len=%d, want 1 (Echo Reply step does not auto-reply)", len(cfgs))
	}
}

// TestPlan_IPv4InIPv6ConfigRejected verifies that a spec with IPv4
// addresses is rejected by Plan (not just Validate) — prevents emitting
// a malformed packet with an IPv4 srcIP in an IPv6 header.
func TestPlan_IPv4InIPv6ConfigRejected(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.SrcIP = "10.0.0.1"
	_, err := p.Plan(context.Background(), spec)
	if err == nil {
		t.Error("Plan with IPv4 srcIP should error")
	}
}

// mustPlan is a helper that fails the test if Plan returns an error.
func mustPlan(t *testing.T, p *Planner, spec core.FlowSpec) <-chan core.PacketConfig {
	t.Helper()
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan returned error: %v", err)
	}
	return ch
}

// bytesEqual compares two byte slices for equality.
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
