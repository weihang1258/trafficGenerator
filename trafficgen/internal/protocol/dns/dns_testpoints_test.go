package dns

// Test points derived from tools/test_points/protocols.md (DNS section D1-D31).
// Each test asserts observable PacketConfig field values, not just "no error".
// Test points for previously known bugs (D7/D19/D23/D28) are no longer skipped --
// the bugs have been fixed.

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

// D7-NEG: DstPort=0 must default to 53. Plan now applies the default
// directly (bypassing the value-receiver in Validate) so the output packet
// carries DstPort=53.
func TestDNSPlan_DstPortZeroNotDefaulted(t *testing.T) {
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
	// Error message must mention both "domain" and "required" so users
	// understand which field is missing and why. The legacy message was
	// "domain is required"; the new message is "dns query_name (domain) is
	// required" to also catch users who set query_name instead of domain.
	if err == nil || !strings.Contains(err.Error(), "domain") || !strings.Contains(err.Error(), "required") {
		t.Errorf("err=%v, want contains 'domain' and 'required'", err)
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
		IsResponse: true,
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
		IsResponse: false,
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

// D19: context cancel stops the planner goroutine. Cancel BEFORE Plan,
// then drain; the ctx-aware goroutine exits immediately and sends 0 packets.
func TestDNSPlan_ContextCancelIgnored(t *testing.T) {
	p := NewPlanner()
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel BEFORE Plan so a ctx-aware goroutine sends 0 packets
	spec := validDNSSpec()
	spec.DNS = &core.DNSConfig{
		Domain:    "example.com",
		QueryType: TypeA,
		IsResponse: true,
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

// D23: AAAA response uses 16-byte RDATA and RDLENGTH=16 when IPv6
// (ip.To4() returns nil for IPv6, so the planner falls back to ip.To16()).
func TestBuildDNSResponse_IPv6AAAA_Malformed(t *testing.T) {
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

// D28: splitLabels preserves empty labels between consecutive dots.
// With "example..com", the empty label between the two dots is included.
func TestSplitLabels_ConsecutiveDotsDropped(t *testing.T) {
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

// --- CNAME RDATA (Type=5) ---

func TestBuildDNSResponse_CNAME(t *testing.T) {
	response := buildDNSResponse("example.com", TypeCNAME, "www.example.com")
	// CNAME RDATA format: encoded domain name.
	// Header(12) + question(13+4) + answer(13) + answerType(10) + RDATA(encoded target)
	// www.example.com encodes as [3,w,w,w,7,e,x,a,m,p,l,e,3,c,o,m,0] = 16 bytes
	// Total = 12+17+13+10+16 = 68
	if len(response) < 68 {
		t.Fatalf("response len=%d, want >=68 for CNAME", len(response))
	}
	// RDATA should be the encoded target domain name "www.example.com"
	wantSuffix := []byte{3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}
	gotSuffix := response[len(response)-len(wantSuffix):]
	if !bytes.Equal(gotSuffix, wantSuffix) {
		t.Errorf("CNAME RDATA: got %v, want %v", gotSuffix, wantSuffix)
	}
	// RDLENGTH must match the encoded domain length
	rdlength := len(wantSuffix)
	rdlengthBytes := response[len(response)-len(wantSuffix)-2 : len(response)-len(wantSuffix)]
	wantRDLength := []byte{byte(rdlength >> 8), byte(rdlength & 0xFF)}
	if !bytes.Equal(rdlengthBytes, wantRDLength) {
		t.Errorf("RDLENGTH: got %v, want %v", rdlengthBytes, wantRDLength)
	}
}

func TestBuildDNSResponse_CNAME_EmptyTarget(t *testing.T) {
	response := buildDNSResponse("example.com", TypeCNAME, "")
	// Empty target falls back to "target.example.com" (16 bytes encoded)
	wantSuffix := []byte{6, 't', 'a', 'r', 'g', 'e', 't', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}
	gotSuffix := response[len(response)-len(wantSuffix):]
	if !bytes.Equal(gotSuffix, wantSuffix) {
		t.Errorf("CNAME RDATA (empty fallback): got %v, want %v", gotSuffix, wantSuffix)
	}
}

// --- MX RDATA (Type=15) ---

func TestBuildDNSResponse_MX(t *testing.T) {
	response := buildDNSResponse("example.com", TypeMX, "mail.example.com")
	// MX RDATA format: 2-byte preference + encoded domain name
	// mail.example.com encodes as [4,m,a,i,l,7,e,x,a,m,p,l,e,3,c,o,m,0] = 17 bytes
	// preference = 10 (0x00, 0x0A)
	// Total = 12+17+23+20 = 72
	if len(response) < 72 {
		t.Fatalf("response len=%d, want >=72 for MX", len(response))
	}
	// Last 2 bytes should be the root terminator plus the last char of the domain
	// Check for the preference bytes at position (len-20) to (len-18)
	pref := response[len(response)-20 : len(response)-18]
	if pref[0] != 0x00 || pref[1] != 0x0A {
		t.Errorf("MX preference: got [%02x %02x], want [00 0A]", pref[0], pref[1])
	}
	// Check that the RDATA ends with the encoded domain "mail.example.com" (18 bytes)
	wantSuffix := []byte{4, 'm', 'a', 'i', 'l', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}
	gotSuffix := response[len(response)-len(wantSuffix):]
	if !bytes.Equal(gotSuffix, wantSuffix) {
		t.Errorf("MX exchange: got %v, want %v", gotSuffix, wantSuffix)
	}
}

func TestBuildDNSResponse_MX_DefaultPreference(t *testing.T) {
	response := buildDNSResponse("example.com", TypeMX, "")
	// Empty responseIP falls back to "mail.example.com" with preference 10
	pref := response[len(response)-20 : len(response)-18]
	if pref[0] != 0x00 || pref[1] != 0x0A {
		t.Errorf("MX default preference: got [%02x %02x], want [00 0A]", pref[0], pref[1])
	}
}

// --- TXT RDATA (Type=16) ---

func TestBuildDNSResponse_TXT(t *testing.T) {
	response := buildDNSResponse("example.com", TypeTXT, "hello")
	// TXT RDATA format: 1-byte length prefix + text data = 1+5 = 6 bytes
	// Total = 12+17+13+10+6 = 58
	if len(response) < 58 {
		t.Fatalf("response len=%d, want >=58 for TXT", len(response))
	}
	// RDATA should be [5, 'h', 'e', 'l', 'l', 'o']
	wantRDATA := []byte{5, 'h', 'e', 'l', 'l', 'o'}
	gotRDATA := response[len(response)-6:]
	if !bytes.Equal(gotRDATA, wantRDATA) {
		t.Errorf("TXT RDATA: got %v, want %v", gotRDATA, wantRDATA)
	}
}

func TestBuildDNSResponse_TXT_EmptyString(t *testing.T) {
	response := buildDNSResponse("example.com", TypeTXT, "")
	// Empty string RDATA = [0] (1 byte length 0x00)
	// Total = 12+17+13+10+1 = 53
	if len(response) < 53 {
		t.Fatalf("response len=%d, want >=53 for TXT empty", len(response))
	}
	gotRDATA := response[len(response)-1:]
	if gotRDATA[0] != 0x00 {
		t.Errorf("TXT empty RDATA: got [%02x], want [00]", gotRDATA[0])
	}
}

func TestBuildDNSResponse_TXT_LongString(t *testing.T) {
	// 255-byte string (max single TXT chunk)
	longData := make([]byte, 255)
	for i := range longData {
		longData[i] = 'a'
	}
	response := buildDNSResponse("example.com", TypeTXT, string(longData))
	// RDATA = 1 byte length + 255 bytes data = 256 bytes
	// Total = 12+17+13+10+256 = 308
	if len(response) < 308 {
		t.Fatalf("response len=%d, want >=308 for TXT long", len(response))
	}
	// Length prefix should be 255 (0xFF)
	gotLen := response[len(response)-256]
	if gotLen != 0xFF {
		t.Errorf("TXT long RDATA length: got %02x, want FF", gotLen)
	}
}

// --- EDNS0 OPT 伪记录 (中文解释: EDNS0 OPT 伪记录) ---

func TestBuildDNSQuery_EDNS0Enabled(t *testing.T) {
	// Query with EDNS0 OPT record: build a DNS query that includes OPT RR.
	payload := buildDNSQueryWithEDNS0("example.com", TypeA, 4096, true)
	// Verify OPT RR is present: TYPE=41 (0x0029) at the end of the payload
	if len(payload) < 12+17+11 {
		t.Fatalf("payload too short for EDNS0: %d bytes", len(payload))
	}
	// OPT RR starts at offset after question section
	optStart := 12 + 17 // header + question
	// OPT TYPE = 41 (0x00, 0x29) at bytes optStart+1 and optStart+2
	// (byte optStart is NAME = 0x00 for root)
	if payload[optStart+1] != 0x00 || payload[optStart+2] != 0x29 {
		t.Errorf("OPT TYPE: got [%02x %02x], want [00 29]",
			payload[optStart+1], payload[optStart+2])
	}
	// OPT UDP payload size at bytes optStart+3 and optStart+4
	udpSize := uint16(payload[optStart+3])<<8 | uint16(payload[optStart+4])
	if udpSize != 4096 {
		t.Errorf("OPT UDP payload size: %d, want 4096", udpSize)
	}
	// OPT DO bit at byte optStart+7 (TTL[2] = high byte of DO|Z field)
	doBit := payload[optStart+7] & 0x80
	if doBit != 0x80 {
		t.Errorf("DO bit: got %02x, want 80", doBit)
	}
}

func TestBuildDNSQuery_EDNS0Disabled(t *testing.T) {
	payload := buildDNSQueryWithEDNS0("example.com", TypeA, 0, false)
	// No OPT RR: payload should be exactly header + question = 12 + 17 = 29 bytes
	if len(payload) != 29 {
		t.Fatalf("payload len=%d, want 29 (no OPT RR)", len(payload))
	}
}

func TestBuildDNSQuery_EDNS0_NoDO(t *testing.T) {
	payload := buildDNSQueryWithEDNS0("example.com", TypeA, 4096, false)
	optStart := 12 + 17
	doBit := payload[optStart+7] & 0x80
	if doBit != 0x00 {
		t.Errorf("DO bit: got %02x, want 00 (DO bit disabled)", doBit)
	}
}

// --- AAAA response (Type=28) with Plan integration ---

func TestDNSPlan_AAAAQuery(t *testing.T) {
	p := NewPlanner()
	spec := validDNSSpec()
	spec.DNS = &core.DNSConfig{
		Domain: "example.com",
		QueryType: TypeAAAA,
	}
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) < 1 {
		t.Fatal("expected at least 1 packet")
	}
	q := cfgs[0]
	// Check QTYPE in payload = 0x001C (28)
	qtypeOffset := len(q.Payload) - 4
	if q.Payload[qtypeOffset] != 0x00 || q.Payload[qtypeOffset+1] != 0x1C {
		t.Errorf("QTYPE: got [%02x %02x], want [00 1C]",
			q.Payload[qtypeOffset], q.Payload[qtypeOffset+1])
	}
}

func TestDNSPlan_AAAAResponse(t *testing.T) {
	p := NewPlanner()
	spec := validDNSSpec()
	spec.DNS = &core.DNSConfig{
		Domain: "example.com",
		QueryType: TypeAAAA,
		IsResponse: true,
		ResponseIP: "2001:db8::1",
	}
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) != 2 {
		t.Fatalf("len=%d, want 2 (query+response)", len(cfgs))
	}
	r := cfgs[1]
	// Response payload must contain the IPv6 RDATA: 2001:db8::1 = 16 bytes
	wantRDATA := []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	if !bytes.Contains(r.Payload, wantRDATA) {
		t.Error("AAAA response payload missing 2001:db8::1 RDATA bytes")
	}
}

// --- CNAME/MX/TXT Plan integration ---

func TestDNSPlan_CNAMEResponse(t *testing.T) {
	p := NewPlanner()
	spec := validDNSSpec()
	spec.DNS = &core.DNSConfig{
		Domain: "example.com",
		QueryType: TypeCNAME,
		IsResponse: true,
		ResponseIP: "www.example.com",
	}
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) != 2 {
		t.Fatalf("len=%d, want 2 (query+response)", len(cfgs))
	}
	r := cfgs[1]
	// CNAME RDATA should contain the encoded target "www.example.com"
	wantRDATA := []byte{3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}
	if !bytes.Contains(r.Payload, wantRDATA) {
		t.Error("CNAME response payload missing target domain RDATA bytes")
	}
}

func TestDNSPlan_MXResponse(t *testing.T) {
	p := NewPlanner()
	spec := validDNSSpec()
	spec.DNS = &core.DNSConfig{
		Domain: "example.com",
		QueryType: TypeMX,
		IsResponse: true,
		ResponseIP: "mail.example.com",
	}
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) != 2 {
		t.Fatalf("len=%d, want 2 (query+response)", len(cfgs))
	}
	r := cfgs[1]
	// MX RDATA should contain preference bytes [0x00, 0x0A] and the encoded domain
	if !bytes.Contains(r.Payload, []byte{0x00, 0x0A}) {
		t.Error("MX response payload missing preference bytes [00 0A]")
	}
	wantDomain := []byte{4, 'm', 'a', 'i', 'l', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}
	if !bytes.Contains(r.Payload, wantDomain) {
		t.Error("MX response payload missing exchange domain RDATA bytes")
	}
}

func TestDNSPlan_TXTResponse(t *testing.T) {
	p := NewPlanner()
	spec := validDNSSpec()
	spec.DNS = &core.DNSConfig{
		Domain: "example.com",
		QueryType: TypeTXT,
		IsResponse: true,
		ResponseIP: "hello",
	}
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) != 2 {
		t.Fatalf("len=%d, want 2 (query+response)", len(cfgs))
	}
	r := cfgs[1]
	// TXT RDATA should contain length prefix 0x05 + "hello"
	wantRDATA := []byte{5, 'h', 'e', 'l', 'l', 'o'}
	if !bytes.Contains(r.Payload, wantRDATA) {
		t.Error("TXT response payload missing RDATA bytes")
	}
}

// --- EDNS0 Plan integration ---

func TestDNSPlan_EDNS0Query(t *testing.T) {
	p := NewPlanner()
	spec := validDNSSpec()
	spec.DNS = &core.DNSConfig{
		Domain: "example.com",
		QueryType: TypeA,
	}
	// Currently the planner does not emit EDNS0. This test documents that
	// EDNS0 is unsupported and will be added in a future changeset.
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) < 1 {
		t.Fatal("expected at least 1 packet")
	}
	q := cfgs[0]
	// ARCOUNT should be 0 (no EDNS0)
	if q.Payload[10] != 0x00 || q.Payload[11] != 0x00 {
		t.Errorf("ARCOUNT: got [%02x %02x], want [00 00] (no EDNS0)",
			q.Payload[10], q.Payload[11])
	}
}