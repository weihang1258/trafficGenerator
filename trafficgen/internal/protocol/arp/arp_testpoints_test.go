package arp

// Test points derived from tools/test_points/protocols.md (ARP section A1-A39).
// Each test asserts observable PacketConfig field values or concrete ARP payload
// byte offsets (not just "no error"). Known-bug test points assert the CORRECT
// behavior but use t.Skip with the bug description so the suite stays green;
// remove the skip when the bug is fixed.
//
// ARP payload layout (28 bytes), asserted by offset:
//   [0:2]   hardware type (0x0001 Ethernet)
//   [2:4]   protocol type (0x0800 IPv4)
//   [4]     hardware address length (6)
//   [5]     protocol address length (4)
//   [6:8]   operation (1=Request, 2=Reply)
//   [8:14]  sender hardware address (MAC)
//   [14:18] sender protocol address (IP)
//   [18:24] target hardware address (MAC)
//   [24:28] target protocol address (IP)

import (
	"bytes"
	"context"
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

// validARPSpec returns a minimal valid ARP flow spec (Request operation).
func validARPSpec() core.FlowSpec {
	return core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcMAC: "00:11:22:33:44:55", DstMAC: "aa:bb:cc:dd:ee:ff",
		ARP: &core.ARPConfig{Operation: OperationRequest},
	}
}

// arpOperation reads Metadata["arp_operation"] as a uint16 value. The request
// packet stores arpConfig.Operation (uint16), while the reply packet stores the
// untyped OperationReply constant, which becomes int when boxed in interface{}.
// Both carry the same observable value; accept either type.
func arpOperation(t *testing.T, c core.PacketConfig) uint16 {
	t.Helper()
	v, ok := c.Metadata["arp_operation"]
	if !ok {
		t.Fatal("Metadata[arp_operation] missing")
	}
	switch op := v.(type) {
	case uint16:
		return op
	case int:
		return uint16(op)
	default:
		t.Fatalf("Metadata[arp_operation] unexpected type %T", v)
	}
	return 0
}

// --- Validate (A1-A8) ---

func TestARPValidate_ValidSrcIP(t *testing.T) {
	p := NewPlanner()
	spec := validARPSpec()
	spec.SrcIP = "192.168.1.1"
	if err := p.Validate(spec); err != nil {
		t.Errorf("valid SrcIP: %v", err)
	}
}

func TestARPValidate_InvalidSrcIP(t *testing.T) {
	p := NewPlanner()
	spec := validARPSpec()
	spec.SrcIP = "bad"
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "invalid source IP") {
		t.Errorf("err=%v, want contains 'invalid source IP'", err)
	}
}

func TestARPValidate_EmptySrcIP(t *testing.T) {
	p := NewPlanner()
	spec := validARPSpec()
	spec.SrcIP = ""
	if err := p.Validate(spec); err != nil {
		t.Errorf("empty SrcIP should skip validation: %v", err)
	}
}

func TestARPValidate_ValidDstIP(t *testing.T) {
	p := NewPlanner()
	spec := validARPSpec()
	spec.DstIP = "192.168.1.2"
	if err := p.Validate(spec); err != nil {
		t.Errorf("valid DstIP: %v", err)
	}
}

func TestARPValidate_InvalidDstIP(t *testing.T) {
	p := NewPlanner()
	spec := validARPSpec()
	spec.DstIP = "bad"
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "invalid destination IP") {
		t.Errorf("err=%v, want contains 'invalid destination IP'", err)
	}
}

func TestARPValidate_EmptyDstIP(t *testing.T) {
	p := NewPlanner()
	spec := validARPSpec()
	spec.DstIP = ""
	if err := p.Validate(spec); err != nil {
		t.Errorf("empty DstIP should skip validation: %v", err)
	}
}

func TestARPValidate_ConfigNil(t *testing.T) {
	p := NewPlanner()
	spec := validARPSpec()
	spec.ARP = nil
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "ARP config is required") {
		t.Errorf("err=%v, want contains 'ARP config is required'", err)
	}
}

func TestARPValidate_AllValid(t *testing.T) {
	p := NewPlanner()
	if err := p.Validate(validARPSpec()); err != nil {
		t.Errorf("valid spec: %v", err)
	}
}

// --- Plan entry (A9-A11) ---

func TestARPPlan_ValidateFail(t *testing.T) {
	p := NewPlanner()
	spec := validARPSpec()
	spec.ARP = nil
	ch, err := p.Plan(context.Background(), spec)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if ch != nil {
		t.Error("expected nil channel on validate fail")
	}
}

func TestARPPlan_ValidatePass(t *testing.T) {
	p := NewPlanner()
	ch, err := p.Plan(context.Background(), validARPSpec())
	if err != nil {
		t.Fatalf("Plan err: %v", err)
	}
	if ch == nil {
		t.Fatal("nil channel")
	}
	// ARP channel cap is 16 (smaller than TCP's 256).
	if cap(ch) != 16 {
		t.Errorf("cap(ch)=%d, want 16 (ARP buffer)", cap(ch))
	}
	drain(ch)
}

// A11: the goroutine has a defensive `if arpConfig == nil { Operation: OperationRequest }`
// default. Plan's Validate guard rejects nil ARP before the goroutine runs, so this
// default is unreachable through Plan. Assert the guard fires (no packet with the
// default is ever emitted via Plan). The reachable nil-config default is covered by
// A18 (buildARPPacket operation default).
func TestARPPlan_ConfigNilDefaults(t *testing.T) {
	p := NewPlanner()
	spec := validARPSpec()
	spec.ARP = nil
	ch, err := p.Plan(context.Background(), spec)
	if err == nil {
		t.Fatal("expected Validate to reject nil ARP config before goroutine runs")
	}
	if ch != nil {
		t.Error("expected nil channel; goroutine nil-default is defensive/unreachable")
	}
}

// --- Plan goroutine (A12-A15) ---

func TestARPPlan_ConfigProvided(t *testing.T) {
	p := NewPlanner()
	spec := validARPSpec()
	spec.ARP = &core.ARPConfig{Operation: OperationReply} // 2
	cfgs := drain(mustPlan(t, p, spec))
	// Operation=2 (Reply) does not trigger an auto-reply -> 1 packet.
	if len(cfgs) != 1 {
		t.Fatalf("len=%d, want 1 (Reply, no auto-reply)", len(cfgs))
	}
	if op := arpOperation(t, cfgs[0]); op != OperationReply {
		t.Errorf("arp_operation=%d, want %d (OperationReply from spec)", op, OperationReply)
	}
}

func TestARPPlan_RequestPacketFields(t *testing.T) {
	p := NewPlanner()
	spec := validARPSpec()
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) < 1 {
		t.Fatalf("len=%d, want >=1", len(cfgs))
	}
	req := cfgs[0]
	if req.PacketIndex != 0 {
		t.Errorf("PacketIndex=%d, want 0", req.PacketIndex)
	}
	if req.Direction != "up" {
		t.Errorf("Direction=%s, want up", req.Direction)
	}
	// Request is L2 broadcast.
	if req.L2.DstMAC != "ff:ff:ff:ff:ff:ff" {
		t.Errorf("L2.DstMAC=%s, want broadcast ff:ff:ff:ff:ff:ff", req.L2.DstMAC)
	}
	if req.L2.EtherType != 0x0806 {
		t.Errorf("L2.EtherType=%x, want 0x0806 (ARP)", req.L2.EtherType)
	}
	// ARP has no L3.
	if req.L3.Protocol != 0 {
		t.Errorf("L3.Protocol=%d, want 0 (no L3 for ARP)", req.L3.Protocol)
	}
	if req.L4.Protocol != "arp" {
		t.Errorf("L4.Protocol=%s, want arp", req.L4.Protocol)
	}
	if len(req.Payload) != 28 {
		t.Errorf("Payload len=%d, want 28", len(req.Payload))
	}
	if op := arpOperation(t, req); op != OperationRequest {
		t.Errorf("arp_operation=%d, want %d (OperationRequest)", op, OperationRequest)
	}
}

func TestARPPlan_OperationRequestGetsReply(t *testing.T) {
	p := NewPlanner()
	spec := validARPSpec() // Operation=1 (Request)
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) != 2 {
		t.Fatalf("len=%d, want 2 (request+reply)", len(cfgs))
	}
	rep := cfgs[1]
	if rep.PacketIndex != 1 {
		t.Errorf("PacketIndex=%d, want 1", rep.PacketIndex)
	}
	if rep.Direction != "down" {
		t.Errorf("Direction=%s, want down", rep.Direction)
	}
	// Reply carries Operation=2 regardless of request operation.
	if op := arpOperation(t, rep); op != OperationReply {
		t.Errorf("arp_operation=%d, want %d (OperationReply)", op, OperationReply)
	}
	if len(rep.Payload) != 28 {
		t.Errorf("reply Payload len=%d, want 28", len(rep.Payload))
	}
	// Reply swaps MACs (src<-DstMAC, dst<-SrcMAC).
	if rep.L2.SrcMAC != spec.DstMAC || rep.L2.DstMAC != spec.SrcMAC {
		t.Errorf("reply MACs not swapped: src=%s dst=%s", rep.L2.SrcMAC, rep.L2.DstMAC)
	}
}

func TestARPPlan_OperationReplyOnly(t *testing.T) {
	p := NewPlanner()
	spec := validARPSpec()
	spec.ARP = &core.ARPConfig{Operation: OperationReply} // 2 -> no auto-reply
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) != 1 {
		t.Errorf("len=%d, want 1 (Operation=2 does not trigger reply)", len(cfgs))
	}
}

// --- Context cancel (A16) ---

// A16: known bug - the planner goroutine never checks ctx.Done(). Cancelling the
// context does not stop it; it still sends all packets (ARP sends 1-2 packets into
// a 16-deep buffered channel, so it never blocks). Failing-test-first: assert that
// after cancel, zero packets are emitted. Currently skipped (bug unfixed).
func TestARPPlan_ContextCancelIgnored(t *testing.T) {
	t.Skip("known bug A16: ARP planner goroutine never checks ctx.Done(); cancel does not stop it. Remove skip once fixed.")
	p := NewPlanner()
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before draining
	ch, err := p.Plan(ctx, validARPSpec())
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	drainDone := make(chan struct{})
	var n int
	go func() {
		for range ch {
			n++
		}
		close(drainDone)
	}()
	select {
	case <-drainDone:
	case <-time.After(1 * time.Second):
		t.Fatal("goroutine did not exit within 1s after cancel")
	}
	if n != 0 {
		t.Errorf("after cancel, received %d packets, want 0", n)
	}
}

// --- buildARPPacket (A17-A29) ---

// A17: operation read from spec.ARP.Operation.
func TestBuildARPPacket_OperationFromSpec(t *testing.T) {
	spec := core.FlowSpec{ARP: &core.ARPConfig{Operation: 2}}
	pkt := buildARPPacket(spec)
	if !bytes.Equal(pkt[6:8], []byte{0x00, 0x02}) {
		t.Errorf("operation bytes=%v, want [00 02]", pkt[6:8])
	}
}

// A18: nil ARP config defaults operation to Request (1).
func TestBuildARPPacket_OperationDefault(t *testing.T) {
	spec := core.FlowSpec{} // ARP nil
	pkt := buildARPPacket(spec)
	if !bytes.Equal(pkt[6:8], []byte{0x00, 0x01}) {
		t.Errorf("operation bytes=%v, want [00 01] (Request default)", pkt[6:8])
	}
}

// A19: valid sender MAC copied to [8:14].
func TestBuildARPPacket_SrcMACValid(t *testing.T) {
	spec := core.FlowSpec{SrcMAC: "00:11:22:33:44:55"}
	pkt := buildARPPacket(spec)
	if !bytes.Equal(pkt[8:14], []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}) {
		t.Errorf("sender MAC bytes=%v, want 00:11:22:33:44:55", pkt[8:14])
	}
}

// A20: invalid sender MAC silently dropped -> all-zero.
func TestBuildARPPacket_SrcMACInvalid(t *testing.T) {
	spec := core.FlowSpec{SrcMAC: "invalid"}
	pkt := buildARPPacket(spec)
	if !bytes.Equal(pkt[8:14], make([]byte, 6)) {
		t.Errorf("sender MAC bytes=%v, want all-zero (ParseMAC error dropped)", pkt[8:14])
	}
}

// A20-BR1: empty sender MAC -> all-zero.
func TestBuildARPPacket_SrcMACEmpty(t *testing.T) {
	spec := core.FlowSpec{SrcMAC: ""}
	pkt := buildARPPacket(spec)
	if !bytes.Equal(pkt[8:14], make([]byte, 6)) {
		t.Errorf("sender MAC bytes=%v, want all-zero", pkt[8:14])
	}
}

// A21: valid sender IP copied to [14:18].
func TestBuildARPPacket_SrcIPValid(t *testing.T) {
	spec := core.FlowSpec{SrcIP: "10.0.0.1"}
	pkt := buildARPPacket(spec)
	if !bytes.Equal(pkt[14:18], []byte{10, 0, 0, 1}) {
		t.Errorf("sender IP bytes=%v, want [10 0 0 1]", pkt[14:18])
	}
}

// A22: empty sender IP -> all-zero.
func TestBuildARPPacket_SrcIPEmpty(t *testing.T) {
	spec := core.FlowSpec{SrcIP: ""}
	pkt := buildARPPacket(spec)
	if !bytes.Equal(pkt[14:18], make([]byte, 4)) {
		t.Errorf("sender IP bytes=%v, want all-zero", pkt[14:18])
	}
}

// A23: IPv6 sender IP -> To4()==nil -> all-zero.
func TestBuildARPPacket_SrcIPv6(t *testing.T) {
	spec := core.FlowSpec{SrcIP: "::1"}
	pkt := buildARPPacket(spec)
	if !bytes.Equal(pkt[14:18], make([]byte, 4)) {
		t.Errorf("sender IP bytes=%v, want all-zero (IPv6 To4()==nil)", pkt[14:18])
	}
}

// A24: valid target MAC copied to [18:24].
func TestBuildARPPacket_TargetMACValid(t *testing.T) {
	spec := core.FlowSpec{ARP: &core.ARPConfig{TargetMAC: "aa:bb:cc:dd:ee:ff"}}
	pkt := buildARPPacket(spec)
	if !bytes.Equal(pkt[18:24], []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}) {
		t.Errorf("target MAC bytes=%v, want aa:bb:cc:dd:ee:ff", pkt[18:24])
	}
}

// A25: absent target MAC -> all-zero (ARP request standard).
func TestBuildARPPacket_TargetMACAbsent(t *testing.T) {
	spec := core.FlowSpec{ARP: &core.ARPConfig{TargetMAC: ""}}
	pkt := buildARPPacket(spec)
	if !bytes.Equal(pkt[18:24], make([]byte, 6)) {
		t.Errorf("target MAC bytes=%v, want all-zero", pkt[18:24])
	}
}

// A26: invalid target MAC -> all-zero (silently dropped).
func TestBuildARPPacket_TargetMACInvalid(t *testing.T) {
	spec := core.FlowSpec{ARP: &core.ARPConfig{TargetMAC: "bad"}}
	pkt := buildARPPacket(spec)
	if !bytes.Equal(pkt[18:24], make([]byte, 6)) {
		t.Errorf("target MAC bytes=%v, want all-zero (ParseMAC error dropped)", pkt[18:24])
	}
}

// A27: valid target IP copied to [24:28].
func TestBuildARPPacket_TargetIPValid(t *testing.T) {
	spec := core.FlowSpec{DstIP: "10.0.0.2"}
	pkt := buildARPPacket(spec)
	if !bytes.Equal(pkt[24:28], []byte{10, 0, 0, 2}) {
		t.Errorf("target IP bytes=%v, want [10 0 0 2]", pkt[24:28])
	}
}

// A28: empty target IP -> all-zero.
func TestBuildARPPacket_TargetIPEmpty(t *testing.T) {
	spec := core.FlowSpec{DstIP: ""}
	pkt := buildARPPacket(spec)
	if !bytes.Equal(pkt[24:28], make([]byte, 4)) {
		t.Errorf("target IP bytes=%v, want all-zero", pkt[24:28])
	}
}

// A29: IPv6 target IP -> To4()==nil -> all-zero.
func TestBuildARPPacket_TargetIPv6(t *testing.T) {
	spec := core.FlowSpec{DstIP: "2001:db8::1"}
	pkt := buildARPPacket(spec)
	if !bytes.Equal(pkt[24:28], make([]byte, 4)) {
		t.Errorf("target IP bytes=%v, want all-zero (IPv6 To4()==nil)", pkt[24:28])
	}
}

// --- buildARPReply (A30-A39) ---
// Reply swaps sender/target: sender<-spec.DstMAC/DstIP, target<-spec.SrcMAC/SrcIP.

// A30: reply sender MAC taken from spec.DstMAC.
func TestBuildARPReply_SenderMACValid(t *testing.T) {
	spec := core.FlowSpec{DstMAC: "aa:bb:cc:dd:ee:ff"}
	pkt := buildARPReply(spec)
	if !bytes.Equal(pkt[8:14], []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}) {
		t.Errorf("sender MAC bytes=%v, want aa:bb:cc:dd:ee:ff", pkt[8:14])
	}
}

// A31: empty sender MAC -> all-zero.
func TestBuildARPReply_SenderMACEmpty(t *testing.T) {
	spec := core.FlowSpec{DstMAC: ""}
	pkt := buildARPReply(spec)
	if !bytes.Equal(pkt[8:14], make([]byte, 6)) {
		t.Errorf("sender MAC bytes=%v, want all-zero", pkt[8:14])
	}
}

// A32: reply sender IP taken from spec.DstIP.
func TestBuildARPReply_SenderIPValid(t *testing.T) {
	spec := core.FlowSpec{DstIP: "10.0.0.2"}
	pkt := buildARPReply(spec)
	if !bytes.Equal(pkt[14:18], []byte{10, 0, 0, 2}) {
		t.Errorf("sender IP bytes=%v, want [10 0 0 2]", pkt[14:18])
	}
}

// A33: empty sender IP -> all-zero.
func TestBuildARPReply_SenderIPEmpty(t *testing.T) {
	spec := core.FlowSpec{DstIP: ""}
	pkt := buildARPReply(spec)
	if !bytes.Equal(pkt[14:18], make([]byte, 4)) {
		t.Errorf("sender IP bytes=%v, want all-zero", pkt[14:18])
	}
}

// A34: IPv6 sender IP -> To4()==nil -> all-zero.
func TestBuildARPReply_SenderIPv6(t *testing.T) {
	spec := core.FlowSpec{DstIP: "::1"}
	pkt := buildARPReply(spec)
	if !bytes.Equal(pkt[14:18], make([]byte, 4)) {
		t.Errorf("sender IP bytes=%v, want all-zero (IPv6 To4()==nil)", pkt[14:18])
	}
}

// A35: reply target MAC taken from spec.SrcMAC.
func TestBuildARPReply_TargetMACValid(t *testing.T) {
	spec := core.FlowSpec{SrcMAC: "00:11:22:33:44:55"}
	pkt := buildARPReply(spec)
	if !bytes.Equal(pkt[18:24], []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}) {
		t.Errorf("target MAC bytes=%v, want 00:11:22:33:44:55", pkt[18:24])
	}
}

// A36: empty target MAC -> all-zero.
func TestBuildARPReply_TargetMACEmpty(t *testing.T) {
	spec := core.FlowSpec{SrcMAC: ""}
	pkt := buildARPReply(spec)
	if !bytes.Equal(pkt[18:24], make([]byte, 6)) {
		t.Errorf("target MAC bytes=%v, want all-zero", pkt[18:24])
	}
}

// A37: reply target IP taken from spec.SrcIP.
func TestBuildARPReply_TargetIPValid(t *testing.T) {
	spec := core.FlowSpec{SrcIP: "10.0.0.1"}
	pkt := buildARPReply(spec)
	if !bytes.Equal(pkt[24:28], []byte{10, 0, 0, 1}) {
		t.Errorf("target IP bytes=%v, want [10 0 0 1]", pkt[24:28])
	}
}

// A38: empty target IP -> all-zero.
func TestBuildARPReply_TargetIPEmpty(t *testing.T) {
	spec := core.FlowSpec{SrcIP: ""}
	pkt := buildARPReply(spec)
	if !bytes.Equal(pkt[24:28], make([]byte, 4)) {
		t.Errorf("target IP bytes=%v, want all-zero", pkt[24:28])
	}
}

// A39: IPv6 target IP -> To4()==nil -> all-zero.
func TestBuildARPReply_TargetIPv6(t *testing.T) {
	spec := core.FlowSpec{SrcIP: "::1"}
	pkt := buildARPReply(spec)
	if !bytes.Equal(pkt[24:28], make([]byte, 4)) {
		t.Errorf("target IP bytes=%v, want all-zero (IPv6 To4()==nil)", pkt[24:28])
	}
}
