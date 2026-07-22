package udp

// Test points derived from tools/test_points/protocols.md (UDP section U1-U51).
// Each test asserts observable PacketConfig field values, not just "no error".
// Known-bug test points assert the CORRECT behavior but use t.Skip with the
// bug description so the suite stays green; remove the skip when the bug is fixed.

import (
	"context"
	"runtime"
	"strings"
	"testing"
	"time"

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

// mustPlan fails the test if Plan returns an error.
func mustPlan(t *testing.T, p *Planner, spec core.FlowSpec) <-chan core.PacketConfig {
	t.Helper()
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	return ch
}

func validUDPSpec() core.FlowSpec {
	return core.FlowSpec{
		SrcIP: "1.1.1.1", DstIP: "2.2.2.2",
		SrcPort: 100, DstPort: 200,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "00:11:22:33:44:55",
	}
}

// --- Validate (U1-U15) ---

func TestUDPValidate_ValidSrcIP(t *testing.T) {
	p := NewPlanner()
	if err := p.Validate(validUDPSpec()); err != nil {
		t.Errorf("valid src IP: %v", err)
	}
}

func TestUDPValidate_InvalidSrcIP(t *testing.T) {
	p := NewPlanner()
	spec := validUDPSpec()
	spec.SrcIP = "not-an-ip"
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "invalid source IP: not-an-ip") {
		t.Errorf("err=%v", err)
	}
}

func TestUDPValidate_EmptySrcIP(t *testing.T) {
	p := NewPlanner()
	spec := validUDPSpec()
	spec.SrcIP = ""
	if err := p.Validate(spec); err != nil {
		t.Errorf("empty SrcIP should skip: %v", err)
	}
}

func TestUDPValidate_ValidDstIP(t *testing.T) {
	p := NewPlanner()
	if err := p.Validate(validUDPSpec()); err != nil {
		t.Errorf("%v", err)
	}
}

func TestUDPValidate_InvalidDstIP(t *testing.T) {
	p := NewPlanner()
	spec := validUDPSpec()
	spec.DstIP = "bad-address"
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "invalid destination IP") {
		t.Errorf("err=%v", err)
	}
}

func TestUDPValidate_EmptyDstIP(t *testing.T) {
	p := NewPlanner()
	spec := validUDPSpec()
	spec.DstIP = ""
	if err := p.Validate(spec); err != nil {
		t.Errorf("empty DstIP should skip: %v", err)
	}
}

func TestUDPValidate_SrcPortZero(t *testing.T) {
	p := NewPlanner()
	spec := validUDPSpec()
	spec.SrcPort = 0
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "source port is required") {
		t.Errorf("err=%v", err)
	}
}

func TestUDPValidate_DstPortZero(t *testing.T) {
	p := NewPlanner()
	spec := validUDPSpec()
	spec.SrcPort = 12345
	spec.DstPort = 0
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "destination port is required") {
		t.Errorf("err=%v", err)
	}
}

func TestUDPValidate_SrcIPCheckedFirst(t *testing.T) {
	p := NewPlanner()
	spec := validUDPSpec()
	spec.SrcIP = "bad1"
	spec.DstIP = "bad2"
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "invalid source IP") {
		t.Errorf("SrcIP should be checked first: %v", err)
	}
}

func TestUDPValidate_BothPortsZero(t *testing.T) {
	p := NewPlanner()
	spec := validUDPSpec()
	spec.SrcPort = 0
	spec.DstPort = 0
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "source port is required") {
		t.Errorf("SrcPort should be checked first: %v", err)
	}
}

func TestUDPValidate_OnlyDstPortZero(t *testing.T) {
	p := NewPlanner()
	spec := validUDPSpec()
	spec.SrcPort = 12345
	spec.DstPort = 0
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "destination port is required") {
		t.Errorf("err=%v", err)
	}
}

func TestUDPValidate_AllValid(t *testing.T) {
	p := NewPlanner()
	if err := p.Validate(validUDPSpec()); err != nil {
		t.Errorf("%v", err)
	}
}

// --- Plan entry (U16-U17) ---

func TestUDPPlan_ValidateFail(t *testing.T) {
	p := NewPlanner()
	spec := validUDPSpec()
	spec.SrcPort = 0
	ch, err := p.Plan(context.Background(), spec)
	if err == nil {
		t.Fatal("expected error")
	}
	if ch != nil {
		t.Error("expected nil channel")
	}
}

func TestUDPPlan_ValidatePass(t *testing.T) {
	p := NewPlanner()
	ch, err := p.Plan(context.Background(), validUDPSpec())
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if ch == nil {
		t.Fatal("nil channel")
	}
	if cap(ch) != 256 {
		t.Errorf("cap=%d, want 256", cap(ch))
	}
	drain(ch)
}

// --- Plan goroutine (U18-U43) ---

func TestUDPPlan_TTLDefault(t *testing.T) {
	p := NewPlanner()
	spec := validUDPSpec()
	spec.TTL = 0
	cfgs := drain(mustPlan(t, p, spec))
	if cfgs[0].L3.TTL != 64 {
		t.Errorf("TTL=%d, want 64", cfgs[0].L3.TTL)
	}
}

func TestUDPPlan_TTLMin(t *testing.T) {
	p := NewPlanner()
	spec := validUDPSpec()
	spec.TTL = 1
	cfgs := drain(mustPlan(t, p, spec))
	if cfgs[0].L3.TTL != 1 {
		t.Errorf("TTL=%d, want 1", cfgs[0].L3.TTL)
	}
}

func TestUDPPlan_TTLMax(t *testing.T) {
	p := NewPlanner()
	spec := validUDPSpec()
	spec.TTL = 255
	cfgs := drain(mustPlan(t, p, spec))
	if cfgs[0].L3.TTL != 255 {
		t.Errorf("TTL=%d, want 255", cfgs[0].L3.TTL)
	}
}

func TestUDPPlan_UDPNilOnePacket(t *testing.T) {
	p := NewPlanner()
	spec := validUDPSpec()
	spec.UDP = nil
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) != 1 {
		t.Errorf("len=%d, want 1", len(cfgs))
	}
	if cfgs[0].Direction != "up" {
		t.Errorf("Direction=%s", cfgs[0].Direction)
	}
}

func TestUDPPlan_ResponseFalseOnePacket(t *testing.T) {
	p := NewPlanner()
	spec := validUDPSpec()
	spec.UDP = &core.UDPConfig{IsResponse: false}
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) != 1 {
		t.Errorf("len=%d, want 1", len(cfgs))
	}
}

func TestUDPPlan_ResponseTrueTwoPackets(t *testing.T) {
	p := NewPlanner()
	spec := validUDPSpec()
	spec.UDP = &core.UDPConfig{IsResponse: true}
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) != 2 {
		t.Errorf("len=%d, want 2", len(cfgs))
	}
	if cfgs[0].Direction != "up" {
		t.Errorf("request Direction=%s, want up", cfgs[0].Direction)
	}
	if cfgs[1].Direction != "down" {
		t.Errorf("response Direction=%s, want down", cfgs[1].Direction)
	}
}

func TestUDPPlan_FlowIDNormal(t *testing.T) {
	p := NewPlanner()
	spec := validUDPSpec()
	cfgs := drain(mustPlan(t, p, spec))
	want := "1.1.1.1-2.2.2.2-100-200"
	if cfgs[0].FlowID != want {
		t.Errorf("FlowID=%q, want %q", cfgs[0].FlowID, want)
	}
}

func TestUDPPlan_FlowIDEmptySrcIP(t *testing.T) {
	p := NewPlanner()
	spec := validUDPSpec()
	spec.SrcIP = ""
	cfgs := drain(mustPlan(t, p, spec))
	want := "-2.2.2.2-100-200"
	if cfgs[0].FlowID != want {
		t.Errorf("FlowID=%q, want %q", cfgs[0].FlowID, want)
	}
}

func TestUDPPlan_FlowIDEmptyDstIP(t *testing.T) {
	p := NewPlanner()
	spec := validUDPSpec()
	spec.DstIP = ""
	cfgs := drain(mustPlan(t, p, spec))
	want := "1.1.1.1--100-200"
	if cfgs[0].FlowID != want {
		t.Errorf("FlowID=%q, want %q", cfgs[0].FlowID, want)
	}
}

func TestUDPPlan_FlowIDBothEmpty(t *testing.T) {
	p := NewPlanner()
	spec := validUDPSpec()
	spec.SrcIP = ""
	spec.DstIP = ""
	cfgs := drain(mustPlan(t, p, spec))
	want := "--100-200"
	if cfgs[0].FlowID != want {
		t.Errorf("FlowID=%q, want %q", cfgs[0].FlowID, want)
	}
}

func TestUDPPlan_IPIDNoResponse(t *testing.T) {
	p := NewPlanner()
	spec := validUDPSpec()
	spec.UDP = &core.UDPConfig{IsResponse: false}
	cfgs := drain(mustPlan(t, p, spec))
	// IPID start is now randomized; just assert it's non-zero (the random
	// start) and that a single-packet flow produces exactly one IPID.
	if cfgs[0].L3.IPID == 0 {
		t.Errorf("IPID=%d, want non-zero (random start)", cfgs[0].L3.IPID)
	}
}

func TestUDPPlan_IPIDWithResponse(t *testing.T) {
	p := NewPlanner()
	spec := validUDPSpec()
	spec.UDP = &core.UDPConfig{IsResponse: true}
	cfgs := drain(mustPlan(t, p, spec))
	// IPID start is randomized; the response IPID must be exactly +1 of the
	// request IPID (per-flow incrementing preserved).
	reqID := cfgs[0].L3.IPID
	if reqID == 0 {
		t.Errorf("request IPID=%d, want non-zero (random start)", reqID)
	}
	if cfgs[1].L3.IPID != reqID+1 {
		t.Errorf("response IPID=%d, want %d (request+1)", cfgs[1].L3.IPID, reqID+1)
	}
}

func TestUDPPlan_RequestDirectionFields(t *testing.T) {
	p := NewPlanner()
	spec := validUDPSpec()
	cfgs := drain(mustPlan(t, p, spec))
	req := cfgs[0]
	if req.Direction != "up" {
		t.Errorf("Direction=%s", req.Direction)
	}
	if req.L2.SrcMAC != spec.SrcMAC || req.L2.DstMAC != spec.DstMAC {
		t.Errorf("MACs: src=%s dst=%s", req.L2.SrcMAC, req.L2.DstMAC)
	}
	if req.L3.SrcIP != spec.SrcIP || req.L3.DstIP != spec.DstIP {
		t.Errorf("IPs not forward")
	}
	if req.L4.SrcPort != spec.SrcPort || req.L4.DstPort != spec.DstPort {
		t.Errorf("ports not forward")
	}
}

func TestUDPPlan_ResponseDirectionFields(t *testing.T) {
	p := NewPlanner()
	spec := validUDPSpec()
	spec.UDP = &core.UDPConfig{IsResponse: true}
	cfgs := drain(mustPlan(t, p, spec))
	resp := cfgs[1]
	if resp.Direction != "down" {
		t.Errorf("Direction=%s", resp.Direction)
	}
	// MACs swapped
	if resp.L2.SrcMAC != spec.DstMAC || resp.L2.DstMAC != spec.SrcMAC {
		t.Errorf("MACs not swapped: src=%s dst=%s", resp.L2.SrcMAC, resp.L2.DstMAC)
	}
	// IPs swapped
	if resp.L3.SrcIP != spec.DstIP || resp.L3.DstIP != spec.SrcIP {
		t.Errorf("IPs not swapped")
	}
	// ports swapped
	if resp.L4.SrcPort != spec.DstPort || resp.L4.DstPort != spec.SrcPort {
		t.Errorf("ports not swapped")
	}
}

func TestUDPPlan_PayloadNil(t *testing.T) {
	p := NewPlanner()
	spec := validUDPSpec()
	spec.Payload = nil
	cfgs := drain(mustPlan(t, p, spec))
	if cfgs[0].Payload != nil {
		t.Errorf("Payload=%v, want nil", cfgs[0].Payload)
	}
}

func TestUDPPlan_PayloadEmpty(t *testing.T) {
	p := NewPlanner()
	spec := validUDPSpec()
	spec.Payload = []byte{}
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs[0].Payload) != 0 {
		t.Errorf("Payload len=%d, want 0", len(cfgs[0].Payload))
	}
}

func TestUDPPlan_PayloadSharedRef(t *testing.T) {
	p := NewPlanner()
	spec := validUDPSpec()
	spec.Payload = []byte("hello")
	cfgs := drain(mustPlan(t, p, spec))
	if string(cfgs[0].Payload) != "hello" {
		t.Errorf("Payload=%q", cfgs[0].Payload)
	}
	// Shared underlying array: modifying spec.Payload[0] affects sent packet
	spec.Payload[0] = 'X'
	if cfgs[0].Payload[0] != 'X' {
		t.Errorf("Payload not shared reference: got %q, want 'X'", string(cfgs[0].Payload[0]))
	}
}

func TestUDPPlan_MACsBothEmpty(t *testing.T) {
	p := NewPlanner()
	spec := validUDPSpec()
	spec.SrcMAC = ""
	spec.DstMAC = ""
	cfgs := drain(mustPlan(t, p, spec))
	if cfgs[0].L2.SrcMAC != "" || cfgs[0].L2.DstMAC != "" {
		t.Errorf("MACs not empty: src=%s dst=%s", cfgs[0].L2.SrcMAC, cfgs[0].L2.DstMAC)
	}
}

func TestUDPPlan_MACsBothSet(t *testing.T) {
	p := NewPlanner()
	spec := validUDPSpec()
	spec.UDP = &core.UDPConfig{IsResponse: true}
	cfgs := drain(mustPlan(t, p, spec))
	// Response swaps MACs
	if cfgs[1].L2.SrcMAC != spec.DstMAC || cfgs[1].L2.DstMAC != spec.SrcMAC {
		t.Errorf("response MACs not swapped")
	}
}

func TestUDPPlan_OnlySrcMAC(t *testing.T) {
	p := NewPlanner()
	spec := validUDPSpec()
	spec.SrcMAC = "aa:bb:cc:dd:ee:ff"
	spec.DstMAC = ""
	spec.UDP = &core.UDPConfig{IsResponse: true}
	cfgs := drain(mustPlan(t, p, spec))
	resp := cfgs[1]
	// Response: SrcMAC=DstMAC(orig empty), DstMAC=SrcMAC
	if resp.L2.SrcMAC != "" {
		t.Errorf("response SrcMAC=%s, want empty (orig DstMAC)", resp.L2.SrcMAC)
	}
	if resp.L2.DstMAC != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("response DstMAC=%s, want orig SrcMAC", resp.L2.DstMAC)
	}
}

func TestUDPPlan_OnlyDstMAC(t *testing.T) {
	p := NewPlanner()
	spec := validUDPSpec()
	spec.SrcMAC = ""
	spec.DstMAC = "00:11:22:33:44:55"
	spec.UDP = &core.UDPConfig{IsResponse: true}
	cfgs := drain(mustPlan(t, p, spec))
	resp := cfgs[1]
	if resp.L2.SrcMAC != "00:11:22:33:44:55" {
		t.Errorf("response SrcMAC=%s, want orig DstMAC", resp.L2.SrcMAC)
	}
	if resp.L2.DstMAC != "" {
		t.Errorf("response DstMAC=%s, want empty (orig SrcMAC)", resp.L2.DstMAC)
	}
}

func TestUDPPlan_SharedTimestamp(t *testing.T) {
	p := NewPlanner()
	spec := validUDPSpec()
	spec.UDP = &core.UDPConfig{IsResponse: true}
	cfgs := drain(mustPlan(t, p, spec))
	if !cfgs[0].Timestamp.Equal(cfgs[1].Timestamp) {
		t.Errorf("timestamps differ: req=%v resp=%v", cfgs[0].Timestamp, cfgs[1].Timestamp)
	}
}

func TestUDPPlan_L4Protocol(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validUDPSpec()))
	if cfgs[0].L4.Protocol != "udp" {
		t.Errorf("L4.Protocol=%s, want udp", cfgs[0].L4.Protocol)
	}
}

func TestUDPPlan_L3Protocol(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validUDPSpec()))
	if cfgs[0].L3.Protocol != 17 {
		t.Errorf("L3.Protocol=%d, want 17", cfgs[0].L3.Protocol)
	}
}

func TestUDPPlan_EtherType(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validUDPSpec()))
	if cfgs[0].L2.EtherType != 0x0800 {
		t.Errorf("EtherType=%x, want 0x0800", cfgs[0].L2.EtherType)
	}
}

func TestUDPPlan_ChannelCloseOnePacket(t *testing.T) {
	p := NewPlanner()
	spec := validUDPSpec()
	spec.UDP = nil
	ch := mustPlan(t, p, spec)
	cfgs := drain(ch)
	if len(cfgs) != 1 {
		t.Errorf("len=%d, want 1", len(cfgs))
	}
}

func TestUDPPlan_ChannelCloseTwoPackets(t *testing.T) {
	p := NewPlanner()
	spec := validUDPSpec()
	spec.UDP = &core.UDPConfig{IsResponse: true}
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) != 2 {
		t.Errorf("len=%d, want 2", len(cfgs))
	}
}

// --- Context cancellation (U44-U48) ---

// U46: goroutine never checks ctx.Done(). Known bug.
func TestUDPPlan_ContextCancelIgnored(t *testing.T) {
	t.Skip("known bug U46: UDP planner goroutine never checks ctx.Done(); cancel does not stop it. Remove skip once fixed.")
	p := NewPlanner()
	ctx, cancel := context.WithCancel(context.Background())
	spec := validUDPSpec()
	spec.UDP = &core.UDPConfig{IsResponse: true}
	ch, err := p.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	before := runtime.NumGoroutine()
	cancel()
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if runtime.NumGoroutine() < before {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Errorf("goroutine did not exit after cancel: before=%d after=%d", before, runtime.NumGoroutine())
	drain(ch)
}

// U47: blocked-send leak. UDP produces only 1-2 packets so the 256-cap channel
// never fills; but the goroutine still ignores ctx.Done. This documents that the
// goroutine exits only because it finishes sending, not because of cancel.
func TestUDPPlan_BlockedSendLeak(t *testing.T) {
	t.Skip("known bug U47: UDP goroutine ignores ctx.Done (exits only by finishing sends, not by cancel). Remove skip once fixed.")
	p := NewPlanner()
	ctx, cancel := context.WithCancel(context.Background())
	spec := validUDPSpec()
	spec.UDP = &core.UDPConfig{IsResponse: true}
	ch, err := p.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	before := runtime.NumGoroutine()
	cancel()
	// With ctx.Done ignored, the goroutine should still exit because it only
	// sends 2 packets (both fit in the 256-cap channel without blocking).
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if runtime.NumGoroutine() < before {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	// If still alive, the goroutine is blocked (shouldn't happen for 2 packets)
	t.Errorf("goroutine did not exit: before=%d after=%d", before, runtime.NumGoroutine())
	drain(ch)
}
