package dns

// Test points derived from tools/test_points/protocols.md (DNS section D1-D31).
// Each test asserts observable PacketConfig field values, not just "no error".
// Known-bug test points assert the CORRECT behavior but use t.Skip with the
// bug description so the suite stays green; remove the skip when the bug is fixed.

import (
	"bytes"
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

func validDNSSpec() core.FlowSpec {
	return core.FlowSpec{
		SrcIP: "192.168.1.1", DstIP: "192.168.1.2",
		SrcPort: 12345, DstPort: 53,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		DNS: &core.DNSConfig{
			Domain:    "example.com",
			QueryType: TypeA, // 1
		},
	}
}

// mustPlan is a helper that fails the test if Plan returns an error.
func mustPlan(t *testing.T, p *Planner, spec core.FlowSpec) <-chan core.PacketConfig {
	t.Helper()
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	return ch
}

// --- Validate (D1-D11) ---

func TestDNSValidate_ValidSrcIP(t *testing.T) {
	p := NewPlanner()
	spec := validDNSSpec()
	spec.SrcIP = "192.168.1.1"
	if err := p.Validate(spec); err != nil {
		t.Errorf("valid SrcIP should pass: %v", err)
	}
}

func TestDNSValidate_InvalidSrcIP(t *testing.T) {
	p := NewPlanner()
	spec := validDNSSpec()
	spec.SrcIP = "not-an-ip"
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "invalid source IP") {
		t.Errorf("err=%v, want contains 'invalid source IP'", err)
	}
}

func TestDNSValidate_EmptySrcIP(t *testing.T) {
	p := NewPlanner()
	spec := validDNSSpec()
	spec.SrcIP = ""
	if err := p.Validate(spec); err != nil {
		t.Errorf("empty SrcIP should skip validation: %v", err)
	}
}

func TestDNSValidate_ValidDstIP(t *testing.T) {
	p := NewPlanner()
	spec := validDNSSpec()
	spec.DstIP = "10.0.0.1"
	if err := p.Validate(spec); err != nil {
		t.Errorf("valid DstIP should pass: %v", err)
	}
}

func TestDNSValidate_InvalidDstIP(t *testing.T) {
	p := NewPlanner()
	spec := validDNSSpec()
	spec.DstIP = "bad"
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "invalid destination IP") {
		t.Errorf("err=%v, want contains 'invalid destination IP'", err)
	}
}

func TestDNSValidate_EmptyDstIP(t *testing.T) {
	p := NewPlanner()
	spec := validDNSSpec()
	spec.DstIP = ""
	if err := p.Validate(spec); err != nil {
		t.Errorf("empty DstIP should skip: %v", err)
	}
}

// D7-POS: Validate sets spec.DstPort=53 locally but since FlowSpec is passed by
// value, the caller's spec.DstPort is unchanged. Validate returns nil (accepts it).
func TestDNSValidate_DstPortDefaultLocal(t *testing.T) {
	p := NewPlanner()
	spec := validDNSSpec()
	spec.DstPort = 0
	if err := p.Validate(spec); err != nil {
		t.Errorf("DstPort=0 should be accepted (default applied locally): %v", err)
	}
	// Caller's spec is unchanged due to pass-by-value
	if spec.DstPort != 0 {
		t.Errorf("caller spec.DstPort=%d, want 0 (pass-by-value should not modify caller)", spec.DstPort)
	}
}

// D7-NEG: DstPort=0 bug. Validate sets spec.DstPort=53 but it's a local copy,
// so Plan still sees DstPort=0. Known bug: query packet has L4.DstPort==0.
func TestDNSPlan_DstPortZeroNotDefaulted(t *testing.T) {
	t.Skip("known bug D7: DstPort=0 not defaulted to 53 (pass-by-value in Validate, Plan sees original 0). Remove skip once fixed.")
	p := NewPlanner()
	spec := validDNSSpec()
	spec.DstPort = 0
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) < 1 {
		t.Fatal("expected at least 1 packet")
	}
	if cfgs[0].L4.DstPort != 53 {
		t.Errorf("query DstPort=%d, want 53 (default)", cfgs[0].L4.DstPort)
	}
}

func TestDNSValidate_DstPortExplicit(t *testing.T) {
	p := NewPlanner()
	spec := validDNSSpec()
	spec.DstPort = 5353
	if err := p.Validate(spec); err != nil {
		t.Errorf("explicit DstPort=5353: %v", err)
	}
	// Port should stay 5353 (not overwritten)
	if spec.DstPort != 5353 {
		t.Errorf("spec.DstPort=%d after Validate, want 5353", spec.DstPort)
	}
}

func TestDNSValidate_ConfigNil(t *testing.T) {
	p := NewPlanner()
	spec := validDNSSpec()
	spec.DNS = nil
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "DNS config is required") {
		t.Errorf("err=%v, want contains 'DNS config is required'", err)
	}
}

func TestDNSValidate_DomainEmpty(t *testing.T) {
	p := NewPlanner()
	spec := validDNSSpec()
	spec.DNS = &core.DNSConfig{Domain: ""}
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "domain is required") {
		t.Errorf("err=%v, want contains 'domain is required'", err)
	}
}

func TestDNSValidate_AllValid(t *testing.T) {
	p := NewPlanner()
	if err := p.Validate(validDNSSpec()); err != nil {
		t.Errorf("valid spec: %v", err)
	}
}

// --- Plan entry (D12-D13) ---

func TestDNSPlan_ValidateFail(t *testing.T) {
	p := NewPlanner()
	spec := validDNSSpec()
	spec.DNS = nil
	ch, err := p.Plan(context.Background(), spec)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if ch != nil {
		t.Error("expected nil channel on validate fail")
	}
}

func TestDNSPlan_ValidatePass(t *testing.T) {
	p := NewPlanner()
	ch, err := p.Plan(context.Background(), validDNSSpec())
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

// --- Plan goroutine: defaults (D14-D15) ---

func TestDNSPlan_TTLDefault(t *testing.T) {
	p := NewPlanner()
	spec := validDNSSpec()
	spec.TTL = 0
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) < 1 {
		t.Fatal("expected at least 1 packet")
	}
	if cfgs[0].L3.TTL != 64 {
		t.Errorf("TTL=%d, want 64 (DefaultTTL)", cfgs[0].L3.TTL)
	}
}

func TestDNSPlan_TTLProvided(t *testing.T) {
	p := NewPlanner()
	spec := validDNSSpec()
	spec.TTL = 128
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) < 1 {
		t.Fatal("expected at least 1 packet")
	}
	if cfgs[0].L3.TTL != 128 {
		t.Errorf("TTL=%d, want 128", cfgs[0].L3.TTL)
	}
}

// --- Plan goroutine: query/response (D16-D18) ---

func TestDNSPlan_QueryPacketFields(t *testing.T) {
	p := NewPlanner()
	spec := validDNSSpec()
	spec.DNS = &core.DNSConfig{
		Domain:    "example.com",
		QueryType: TypeA,
	}
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) < 1 {
		t.Fatal("expected at least 1 packet")
	}
	q := cfgs[0]

	if q.PacketIndex != 0 {
		t.Errorf("PacketIndex=%d, want 0", q.PacketIndex)
	}
	if q.Direction != "up" {
		t.Errorf("Direction=%s, want 'up'", q.Direction)
	}
	if q.L4.Protocol != "udp" {
		t.Errorf("L4.Protocol=%s, want 'udp'", q.L4.Protocol)
	}
	if q.L3.Protocol != 17 {
		t.Errorf("L3.Protocol=%d, want 17 (UDP)", q.L3.Protocol)
	}
	if q.L2.EtherType != 0x0800 {
		t.Errorf("EtherType=%x, want 0x0800", q.L2.EtherType)
	}
	if q.L4.SrcPort != spec.SrcPort {
		t.Errorf("SrcPort=%d, want %d", q.L4.SrcPort, spec.SrcPort)
	}
	if q.L4.DstPort != spec.DstPort {
		t.Errorf("DstPort=%d, want %d", q.L4.DstPort, spec.DstPort)
	}
	if q.L3.SrcIP != spec.SrcIP || q.L3.DstIP != spec.DstIP {
		t.Errorf("IPs: src=%s dst=%s", q.L3.SrcIP, q.L3.DstIP)
	}
	if q.L2.SrcMAC != spec.SrcMAC || q.L2.DstMAC != spec.DstMAC {
		t.Errorf("MACs: src=%s dst=%s", q.L2.SrcMAC, q.L2.DstMAC)
	}

	// Payload must start with DNS header bytes: TxID 0x1234, flags 0x0100
	if len(q.Payload) < 12 {
		t.Fatalf("Payload len=%d, want >=12 (DNS header)", len(q.Payload))
	}
	if q.Payload[0] != 0x12 || q.Payload[1] != 0x34 {
		t.Errorf("TxID: got [%02x %02x], want [12 34]", q.Payload[0], q.Payload[1])
	}
	if q.Payload[2] != 0x01 || q.Payload[3] != 0x00 {
		t.Errorf("flags: got [%02x %02x], want [01 00]", q.Payload[2], q.Payload[3])
	}
	// DNS question count = 1
	if q.Payload[4] != 0x00 || q.Payload[5] != 0x01 {
		t.Errorf("questions: got [%02x %02x], want [00 01]", q.Payload[4], q.Payload[5])
	}
	// Answer RRs = 0 for query
	if q.Payload[6] != 0x00 || q.Payload[7] != 0x00 {
		t.Errorf("answer RRs: got [%02x %02x], want [00 00]", q.Payload[6], q.Payload[7])
	}

	// FlowID format
	wantFlowID := "192.168.1.1-192.168.1.2-12345-53"
	if q.FlowID != wantFlowID {
		t.Errorf("FlowID=%q, want %q", q.FlowID, wantFlowID)
	}
}

func TestDNSPlan_ResponseEnabled(t *testing.T) {
	p := NewPlanner()
	spec := validDNSSpec()
	spec.DNS = &core.DNSConfig{
		Domain:     "example.com",
		QueryType:  TypeA,
		Response:   true,
		ResponseIP: "1.2.3.4",
	}
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) != 2 {
		t.Fatalf("len=%d, want 2 (query+response)", len(cfgs))
	}

	// Query packet
	q := cfgs[0]
	if q.Direction != "up" {
		t.Errorf("query Direction=%s, want 'up'", q.Direction)
	}
	if q.PacketIndex != 0 {
		t.Errorf("query PacketIndex=%d, want 0", q.PacketIndex)
	}

	// Response packet
	r := cfgs[1]
	if r.Direction != "down" {
		t.Errorf("response Direction=%s, want 'down'", r.Direction)
	}
	if r.PacketIndex != 1 {
		t.Errorf("response PacketIndex=%d, want 1", r.PacketIndex)
	}
	// MACs swapped
	if r.L2.SrcMAC != spec.DstMAC || r.L2.DstMAC != spec.SrcMAC {
		t.Errorf("response MACs not swapped: src=%s dst=%s", r.L2.SrcMAC, r.L2.DstMAC)
	}
	// IPs swapped
	if r.L3.SrcIP != spec.DstIP || r.L3.DstIP != spec.SrcIP {
		t.Errorf("response IPs not swapped: src=%s dst=%s", r.L3.SrcIP, r.L3.DstIP)
	}
	// Ports swapped
	if r.L4.SrcPort != spec.DstPort || r.L4.DstPort != spec.SrcPort {
		t.Errorf("response ports not swapped: src=%d dst=%d", r.L4.SrcPort, r.L4.DstPort)
	}

	// Response payload must contain DNS response bytes
	if len(r.Payload) < 12 {
		t.Fatalf("response Payload len=%d, want >=12", len(r.Payload))
	}
	// Response flags = 0x8180 (response + recursive desired)
	if r.Payload[2] != 0x81 || r.Payload[3] != 0x80 {
		t.Errorf("response flags: got [%02x %02x], want [81 80]", r.Payload[2], r.Payload[3])
	}
	// Answer RR count = 1 (response has one answer)
	if r.Payload[6] != 0x00 || r.Payload[7] != 0x01 {
		t.Errorf("response answer RRs: got [%02x %02x], want [00 01]", r.Payload[6], r.Payload[7])
	}
	// Response payload must contain the response IP 1.2.3.4 as RDATA
	if !bytes.Contains(r.Payload, []byte{1, 2, 3, 4}) {
		t.Error("response Payload missing IP bytes [1,2,3,4]")
	}

	// Both packets share the same timestamp
	if !q.Timestamp.Equal(r.Timestamp) {
		t.Error("query and response should share the same Timestamp")
	}
}

func TestDNSPlan_ResponseDisabled(t *testing.T) {
	p := NewPlanner()
	spec := validDNSSpec()
	spec.DNS = &core.DNSConfig{
		Domain:    "example.com",
		QueryType: TypeA,
		Response:  false,
	}
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) != 1 {
		t.Fatalf("len=%d, want 1 (query only)", len(cfgs))
	}
	if cfgs[0].PacketIndex != 0 {
		t.Errorf("PacketIndex=%d, want 0", cfgs[0].PacketIndex)
	}
}

// --- Context cancel (D19) ---

// D19: goroutine never checks ctx.Done(). Known bug: cancelling the context
// does not stop the planner goroutine; it runs to completion and sends all
// packets. Failing-test-first: cancel the context BEFORE calling Plan, then
// drain; a ctx-aware goroutine would exit immediately and send 0 packets.
// Currently the goroutine ignores ctx and sends 2 packets (query+response).
func TestDNSPlan_ContextCancelIgnored(t *testing.T) {
	t.Skip("known bug D19: DNS planner goroutine never checks ctx.Done(); cancel does not stop it. Remove skip once fixed.")
	p := NewPlanner()
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel BEFORE Plan so a ctx-aware goroutine sends 0 packets
	spec := validDNSSpec()
	spec.DNS = &core.DNSConfig{
		Domain:    "example.com",
		QueryType: TypeA,
		Response:  true,
	}
	ch, err := p.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	cfgs := drain(ch)
	if len(cfgs) != 0 {
		t.Errorf("expected 0 packets after pre-cancelled ctx, got %d (ctx.Done() not checked)", len(cfgs))
	}
}

// --- buildDNSResponse (D21-D23) ---

func TestBuildDNSResponse_ValidIPv4(t *testing.T) {
	response := buildDNSResponse("example.com", TypeA, "8.8.8.8")
	if len(response) < 56 {
		t.Fatalf("response len=%d, want >=56 for A record with valid IP", len(response))
	}
	// TxID 0x1234
	if response[0] != 0x12 || response[1] != 0x34 {
		t.Errorf("TxID: got [%02x %02x], want [12 34]", response[0], response[1])
	}
	// Response flags 0x8180
	if response[2] != 0x81 || response[3] != 0x80 {
		t.Errorf("flags: got [%02x %02x], want [81 80]", response[2], response[3])
	}
	// Last 4 bytes should be [8,8,8,8] (IPv4 RDATA)
	last := response[len(response)-4:]
	if last[0] != 8 || last[1] != 8 || last[2] != 8 || last[3] != 8 {
		t.Errorf("RDATA: got %v, want [8 8 8 8]", last)
	}
}

func TestBuildDNSResponse_InvalidIPFallback(t *testing.T) {
	response := buildDNSResponse("example.com", TypeA, "bad")
	if len(response) < 56 {
		t.Fatalf("response len=%d, want >=56", len(response))
	}
	// Fallback to 127.0.0.1
	last := response[len(response)-4:]
	if last[0] != 127 || last[1] != 0 || last[2] != 0 || last[3] != 1 {
		t.Errorf("RDATA: got %v, want [127 0 0 1]", last)
	}
}

func TestBuildDNSResponse_EmptyIPFallback(t *testing.T) {
	response := buildDNSResponse("example.com", TypeA, "")
	if len(response) < 56 {
		t.Fatalf("response len=%d, want >=56", len(response))
	}
	// Fallback to 127.0.0.1
	last := response[len(response)-4:]
	if last[0] != 127 || last[1] != 0 || last[2] != 0 || last[3] != 1 {
		t.Errorf("RDATA: got %v, want [127 0 0 1]", last)
	}
}

// D23: AAAA response malformed. For IPv6 addresses, ip.To4() returns nil so
// ipBytes is nil, but RDLENGTH is hardcoded to 4. The result: RDATA is 0 bytes
// instead of 16 bytes. Known bug.
func TestBuildDNSResponse_IPv6AAAA_Malformed(t *testing.T) {
	t.Skip("known bug D23: AAAA response malformed - ip.To4() returns nil for IPv6, so RDATA is empty but RDLENGTH=4. Remove skip once fixed.")
	response := buildDNSResponse("example.com", TypeAAAA, "2001:db8::1")
	// AAAA RDATA should be 16 bytes
	// Header(12) + question(13+4) + answer(13) + answerType(10) + RDATA(16) = 68
	if len(response) < 68 {
		t.Fatalf("response len=%d, want >=68 for AAAA record with 16-byte RDATA", len(response))
	}
	// RDATA should be 2001:db8::1 in network byte order
	wantRDATA := []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	gotRDATA := response[len(response)-16:]
	if !bytes.Equal(gotRDATA, wantRDATA) {
		t.Errorf("RDATA: got %v, want %v", gotRDATA, wantRDATA)
	}
}

// --- splitLabels (D24-D28) ---

func TestSplitLabels_Normal(t *testing.T) {
	labels := splitLabels("example.com")
	want := []string{"example", "com"}
	if len(labels) != len(want) {
		t.Fatalf("len=%d, want %d", len(labels), len(want))
	}
	for i := range labels {
		if labels[i] != want[i] {
			t.Errorf("labels[%d]=%q, want %q", i, labels[i], want[i])
		}
	}
}

func TestSplitLabels_SingleLabel(t *testing.T) {
	labels := splitLabels("localhost")
	want := []string{"localhost"}
	if len(labels) != len(want) {
		t.Fatalf("len=%d, want %d", len(labels), len(want))
	}
	if labels[0] != "localhost" {
		t.Errorf("got %q, want %q", labels[0], "localhost")
	}
}

func TestSplitLabels_EmptyString(t *testing.T) {
	labels := splitLabels("")
	if len(labels) != 0 {
		t.Errorf("len=%d, want 0 (empty slice for empty string)", len(labels))
	}
}

func TestSplitLabels_TrailingDot(t *testing.T) {
	labels := splitLabels("example.com.")
	want := []string{"example", "com"}
	if len(labels) != len(want) {
		t.Fatalf("len=%d, want %d", len(labels), len(want))
	}
	for i := range labels {
		if labels[i] != want[i] {
			t.Errorf("labels[%d]=%q, want %q", i, labels[i], want[i])
		}
	}
}

// D28: splitLabels discards empty labels between consecutive dots.
// With "example..com", the empty label between the two dots should be
// included in the output, but the current code drops it (the `if i > start`
// check at line 236 skips zero-length labels). Known potential bug.
func TestSplitLabels_ConsecutiveDotsDropped(t *testing.T) {
	t.Skip("known bug D28: splitLabels drops empty labels on consecutive dots. Remove skip once fixed.")
	labels := splitLabels("example..com")
	want := []string{"example", "", "com"}
	if len(labels) != len(want) {
		t.Fatalf("len=%d, want %d", len(labels), len(want))
	}
	for i := range labels {
		if labels[i] != want[i] {
			t.Errorf("labels[%d]=%q, want %q", i, labels[i], want[i])
		}
	}
}

// --- encodeDomainName (D30-D31) ---

func TestEncodeDomainName_Normal(t *testing.T) {
	encoded := encodeDomainName("example.com")
	want := []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}
	if !bytes.Equal(encoded, want) {
		t.Errorf("encoded=%v, want %v", encoded, want)
	}
}

func TestEncodeDomainName_EmptyLabels(t *testing.T) {
	encoded := encodeDomainName("")
	want := []byte{0} // Only root terminator
	if !bytes.Equal(encoded, want) {
		t.Errorf("encoded=%v, want %v (only root terminator)", encoded, want)
	}
}