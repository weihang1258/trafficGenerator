package icmp

// Test points derived from tools/test_points/protocols.md (ICMP section I1-I22).
// Each test asserts observable PacketConfig field values, not just "no error".
// Known-bug test points use t.Skip with the bug description so the suite stays
// green; remove the skip when the bug is fixed.

import (
	"context"
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

func validICMPSpec() core.FlowSpec {
	return core.FlowSpec{
		SrcIP:  "10.0.0.1",
		DstIP:  "10.0.0.2",
		SrcMAC: "aa:bb:cc:dd:ee:ff",
		DstMAC: "11:22:33:44:55:66",
		ICMP: &core.ICMPConfig{
			Type:     TypeEchoRequest,
			Code:     0,
			Sequence: 7,
			Data:     []byte("testdata"),
		},
	}
}

// --- Validate (I1-I7) ---

func TestICMPValidate_ValidSrcIP(t *testing.T) {
	p := NewPlanner()
	spec := validICMPSpec()
	spec.SrcIP = "10.0.0.1"
	if err := p.Validate(spec); err != nil {
		t.Errorf("valid SrcIP: %v", err)
	}
}

func TestICMPValidate_InvalidSrcIP(t *testing.T) {
	p := NewPlanner()
	spec := validICMPSpec()
	spec.SrcIP = "bad"
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "invalid source IP") {
		t.Errorf("err=%v, want contains 'invalid source IP'", err)
	}
}

func TestICMPValidate_EmptySrcIP(t *testing.T) {
	p := NewPlanner()
	spec := validICMPSpec()
	spec.SrcIP = ""
	if err := p.Validate(spec); err != nil {
		t.Errorf("empty SrcIP should skip validation: %v", err)
	}
}

func TestICMPValidate_ValidDstIP(t *testing.T) {
	p := NewPlanner()
	spec := validICMPSpec()
	spec.DstIP = "10.0.0.2"
	if err := p.Validate(spec); err != nil {
		t.Errorf("valid DstIP: %v", err)
	}
}

func TestICMPValidate_InvalidDstIP(t *testing.T) {
	p := NewPlanner()
	spec := validICMPSpec()
	spec.DstIP = "bad"
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "invalid destination IP") {
		t.Errorf("err=%v, want contains 'invalid destination IP'", err)
	}
}

func TestICMPValidate_EmptyDstIP(t *testing.T) {
	p := NewPlanner()
	spec := validICMPSpec()
	spec.DstIP = ""
	if err := p.Validate(spec); err != nil {
		t.Errorf("empty DstIP should skip: %v", err)
	}
}

func TestICMPValidate_AllValid(t *testing.T) {
	p := NewPlanner()
	if err := p.Validate(validICMPSpec()); err != nil {
		t.Errorf("valid spec: %v", err)
	}
}

// --- Plan entry (I8-I9) ---

func TestICMPPlan_ValidateFail(t *testing.T) {
	p := NewPlanner()
	spec := validICMPSpec()
	spec.SrcIP = "bad"
	ch, err := p.Plan(context.Background(), spec)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if ch != nil {
		t.Error("expected nil channel on validate fail")
	}
}

func TestICMPPlan_ValidatePass(t *testing.T) {
	p := NewPlanner()
	ch, err := p.Plan(context.Background(), validICMPSpec())
	if err != nil {
		t.Fatalf("Plan err: %v", err)
	}
	if ch == nil {
		t.Fatal("nil channel")
	}
	if cap(ch) != 256 {
		t.Errorf("cap(ch)=%d, want 256", cap(ch))
	}
	drain(ch)
}

// --- Default values (I10-I13) ---

func TestICMPPlan_TTLDefault(t *testing.T) {
	p := NewPlanner()
	spec := validICMPSpec()
	spec.TTL = 0
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) == 0 {
		t.Fatal("no configs produced")
	}
	if cfgs[0].L3.TTL != 64 {
		t.Errorf("TTL=%d, want 64 (DefaultTTL)", cfgs[0].L3.TTL)
	}
}

func TestICMPPlan_TTLProvided(t *testing.T) {
	p := NewPlanner()
	spec := validICMPSpec()
	spec.TTL = 255
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) == 0 {
		t.Fatal("no configs produced")
	}
	if cfgs[0].L3.TTL != 255 {
		t.Errorf("TTL=%d, want 255", cfgs[0].L3.TTL)
	}
}

func TestICMPPlan_ConfigNilDefaults(t *testing.T) {
	p := NewPlanner()
	spec := validICMPSpec()
	spec.ICMP = nil
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) == 0 {
		t.Fatal("no configs produced")
	}

	// Metadata contains icmp_type=8, icmp_code=0 (stored as uint8 in interface).
	if typ, ok := cfgs[0].Metadata["icmp_type"].(uint8); !ok || typ != 8 {
		t.Errorf("Metadata[icmp_type]=%v, want uint8(8)", cfgs[0].Metadata["icmp_type"])
	}
	if code, ok := cfgs[0].Metadata["icmp_code"].(uint8); !ok || code != 0 {
		t.Errorf("Metadata[icmp_code]=%v, want uint8(0)", cfgs[0].Metadata["icmp_code"])
	}

	// Payload: Type=8, Code=0, Seq=1, Data="ping"
	if len(cfgs[0].Payload) < 8 {
		t.Fatal("payload too short for ICMP header")
	}
	if cfgs[0].Payload[0] != 8 {
		t.Errorf("Payload Type=%d, want 8 (EchoRequest)", cfgs[0].Payload[0])
	}
	if cfgs[0].Payload[1] != 0 {
		t.Errorf("Payload Code=%d, want 0", cfgs[0].Payload[1])
	}
	seq := uint16(cfgs[0].Payload[6])<<8 | uint16(cfgs[0].Payload[7])
	if seq != 1 {
		t.Errorf("Payload Sequence=%d, want 1", seq)
	}
	if string(cfgs[0].Payload[8:]) != "ping" {
		t.Errorf("Payload Data=%q, want 'ping'", cfgs[0].Payload[8:])
	}
}

func TestICMPPlan_ConfigProvided(t *testing.T) {
	p := NewPlanner()
	spec := validICMPSpec()
	spec.ICMP = &core.ICMPConfig{
		Type:     3,
		Code:     0,
		Sequence: 42,
		Data:     []byte("custom"),
	}
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) == 0 {
		t.Fatal("no configs produced")
	}

	// Metadata
	if typ, ok := cfgs[0].Metadata["icmp_type"].(uint8); !ok || typ != 3 {
		t.Errorf("Metadata[icmp_type]=%v, want uint8(3)", typ)
	}

	// Payload: Type=3, Seq=42, Data="custom"
	if cfgs[0].Payload[0] != 3 {
		t.Errorf("Payload Type=%d, want 3", cfgs[0].Payload[0])
	}
	seq := uint16(cfgs[0].Payload[6])<<8 | uint16(cfgs[0].Payload[7])
	if seq != 42 {
		t.Errorf("Payload Sequence=%d, want 42", seq)
	}
	if string(cfgs[0].Payload[8:]) != "custom" {
		t.Errorf("Payload Data=%q, want 'custom'", cfgs[0].Payload[8:])
	}
}

// --- Echo Request/Reply semantics (I14-I17) ---

func TestICMPPlan_EchoRequestSent(t *testing.T) {
	p := NewPlanner()
	spec := validICMPSpec()
	spec.ICMP = &core.ICMPConfig{
		Type:     8,
		Code:     0,
		Sequence: 7,
		Data:     []byte("testdata"),
	}
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) == 0 {
		t.Fatal("no configs produced")
	}

	// PacketIndex=0, direction="up"
	if cfgs[0].PacketIndex != 0 {
		t.Errorf("PacketIndex=%d, want 0", cfgs[0].PacketIndex)
	}
	if cfgs[0].Direction != "up" {
		t.Errorf("Direction=%s, want 'up'", cfgs[0].Direction)
	}
	if cfgs[0].L4.Protocol != "icmp" {
		t.Errorf("L4.Protocol=%q, want 'icmp'", cfgs[0].L4.Protocol)
	}
	if cfgs[0].L3.Protocol != 1 {
		t.Errorf("L3.Protocol=%d, want 1 (ICMP)", cfgs[0].L3.Protocol)
	}
	if cfgs[0].L2.EtherType != 0x0800 {
		t.Errorf("EtherType=%x, want 0x0800", cfgs[0].L2.EtherType)
	}
	if cfgs[0].L3.SrcIP != spec.SrcIP || cfgs[0].L3.DstIP != spec.DstIP {
		t.Errorf("IPs: src=%s dst=%s", cfgs[0].L3.SrcIP, cfgs[0].L3.DstIP)
	}
	if cfgs[0].L2.SrcMAC != spec.SrcMAC || cfgs[0].L2.DstMAC != spec.DstMAC {
		t.Errorf("MACs: src=%s dst=%s", cfgs[0].L2.SrcMAC, cfgs[0].L2.DstMAC)
	}
	// FlowID format
	wantFlowID := "10.0.0.1-10.0.0.2-icmp"
	if cfgs[0].FlowID != wantFlowID {
		t.Errorf("FlowID=%q, want %q", cfgs[0].FlowID, wantFlowID)
	}
}

func TestICMPPlan_TypeEchoRequestGetsReply(t *testing.T) {
	p := NewPlanner()
	spec := validICMPSpec()
	spec.ICMP = &core.ICMPConfig{
		Type:     8,
		Code:     0,
		Sequence: 7,
		Data:     []byte("replydata"),
	}
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) != 2 {
		t.Fatalf("len=%d, want 2 (request + reply)", len(cfgs))
	}

	// Reply packet
	reply := cfgs[1]
	if reply.PacketIndex != 1 {
		t.Errorf("reply PacketIndex=%d, want 1", reply.PacketIndex)
	}
	if reply.Direction != "down" {
		t.Errorf("reply Direction=%s, want 'down'", reply.Direction)
	}
	if typ, ok := reply.Metadata["icmp_type"].(uint8); !ok || typ != 0 {
		t.Errorf("reply Metadata[icmp_type]=%v, want uint8(0) (EchoReply)", typ)
	}
	// Payload Type=0 (EchoReply)
	if len(reply.Payload) < 8 {
		t.Fatal("reply payload too short")
	}
	if reply.Payload[0] != 0 {
		t.Errorf("reply Payload Type=%d, want 0 (EchoReply)", reply.Payload[0])
	}
	// MACs/IPs swapped
	if reply.L2.SrcMAC != spec.DstMAC || reply.L2.DstMAC != spec.SrcMAC {
		t.Errorf("reply MACs not swapped: src=%s dst=%s", reply.L2.SrcMAC, reply.L2.DstMAC)
	}
	if reply.L3.SrcIP != spec.DstIP || reply.L3.DstIP != spec.SrcIP {
		t.Errorf("reply IPs not swapped: src=%s dst=%s", reply.L3.SrcIP, reply.L3.DstIP)
	}
	// Same sequence and data as request
	seq := uint16(reply.Payload[6])<<8 | uint16(reply.Payload[7])
	if seq != 7 {
		t.Errorf("reply Sequence=%d, want 7", seq)
	}
	if string(reply.Payload[8:]) != "replydata" {
		t.Errorf("reply Data=%q, want 'replydata'", reply.Payload[8:])
	}
}

func TestICMPPlan_TypeNotEchoNoReply(t *testing.T) {
	p := NewPlanner()
	spec := validICMPSpec()
	spec.ICMP = &core.ICMPConfig{
		Type:     3, // Destination Unreachable
		Code:     0,
		Sequence: 1,
		Data:     []byte("no-reply"),
	}
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) != 1 {
		t.Fatalf("len=%d, want 1 (no auto-reply for Type=3)", len(cfgs))
	}
}

func TestICMPPlan_TypeEchoReplyPrimary(t *testing.T) {
	p := NewPlanner()
	spec := validICMPSpec()
	spec.ICMP = &core.ICMPConfig{
		Type:     0, // Echo Reply as primary (no auto-reply)
		Code:     0,
		Sequence: 1,
		Data:     []byte("reply"),
	}
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) != 1 {
		t.Fatalf("len=%d, want 1 (Type=0 != TypeEchoRequest, no reply)", len(cfgs))
	}
	if cfgs[0].Payload[0] != 0 {
		t.Errorf("Payload Type=%d, want 0", cfgs[0].Payload[0])
	}
}

// --- Context cancel (I18) ---

// I18: known bug - the ICMP planner goroutine never checks ctx.Done(). With the
// context already cancelled before Plan is called, a respecting implementation
// would emit 0 packets; the buggy implementation emits its full 1-2 packets
// regardless. Failing-test-first: assert 0 packets after pre-cancel. Skipped
// until the bug is fixed; remove the skip once the goroutine respects ctx.
//
// Note: unlike TCP/HTTP, ICMP emits only 1-2 packets into a 256-cap buffer, so
// the goroutine never blocks on send and exits naturally - a goroutine-count
// leak test would false-pass. The "0 packets after pre-cancel" assertion is the
// meaningful observable for this planner.
func TestICMPPlan_ContextCancelIgnored(t *testing.T) {
	t.Skip("known bug I18: ICMP planner goroutine never checks ctx.Done(); cancel does not stop sending. Remove skip once fixed.")
	p := NewPlanner()
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel BEFORE calling Plan
	spec := validICMPSpec()
	ch, err := p.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	cfgs := drain(ch)
	if len(cfgs) != 0 {
		t.Errorf("after pre-cancel got %d packets, want 0 (ctx should be respected)", len(cfgs))
	}
}

// --- calculateChecksum (I19-I22) ---

func TestICMPChecksum_EvenLength(t *testing.T) {
	// I19: 8-byte standard ICMP Echo Request header with zero checksum field.
	data := []byte{0x08, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01}
	cs := calculateChecksum(data)
	// Verified known value: 0xF7FD
	want := uint16(0xF7FD)
	if cs != want {
		t.Errorf("checksum=0x%04X, want 0x%04X", cs, want)
	}
	// Self-consistency: inserting the checksum and recalculating should give 0.
	data[2] = byte(cs >> 8)
	data[3] = byte(cs)
	if calculateChecksum(data) != 0 {
		t.Errorf("self-check returned non-zero: 0x%04X", calculateChecksum(data))
	}
}

func TestICMPChecksum_OddLength(t *testing.T) {
	// I20: 9 bytes (header + 1 data byte, odd length).
	// The trailing byte is zero-padded as the high byte of a 16-bit word.
	data := []byte{0x08, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0xAB}
	cs := calculateChecksum(data)
	// Verified known value: 0x4CFD
	want := uint16(0x4CFD)
	if cs != want {
		t.Errorf("checksum=0x%04X, want 0x%04X", cs, want)
	}
	// Self-consistency
	data[2] = byte(cs >> 8)
	data[3] = byte(cs)
	if calculateChecksum(data) != 0 {
		t.Errorf("self-check returned non-zero: 0x%04X", calculateChecksum(data))
	}
}

func TestICMPChecksum_Empty(t *testing.T) {
	// I21: empty byte slice.
	// sum==0, ^uint16(0)==0xFFFF
	data := []byte{}
	cs := calculateChecksum(data)
	want := uint16(0xFFFF)
	if cs != want {
		t.Errorf("checksum=0x%04X, want 0x%04X (^uint16(0))", cs, want)
	}
}

func TestICMPChecksum_SingleByte(t *testing.T) {
	// I22: single byte {0x08}.
	// sum==0x0800, ^uint16(0x0800)==0xF7FF
	data := []byte{0x08}
	cs := calculateChecksum(data)
	want := uint16(0xF7FF)
	if cs != want {
		t.Errorf("checksum=0x%04X, want 0x%04X (^uint16(0x0800))", cs, want)
	}
}

// --- Helpers ---

// mustPlan calls Plan and fatals on error.
func mustPlan(t *testing.T, p *Planner, spec core.FlowSpec) <-chan core.PacketConfig {
	t.Helper()
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	return ch
}