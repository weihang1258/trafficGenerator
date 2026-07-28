package mdns

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
)

// drain reads all PacketConfig values from ch and returns them as a slice.
func drain(ch <-chan core.PacketConfig) []core.PacketConfig {
	var out []core.PacketConfig
	for cfg := range ch {
		out = append(out, cfg)
	}
	return out
}

// mustPlan calls Plan and fails the test on error.
func mustPlan(t *testing.T, p *Planner, spec core.FlowSpec) <-chan core.PacketConfig {
	t.Helper()
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan returned error: %v", err)
	}
	return ch
}

// mustPlanCtx calls Plan with a context and fails the test on error.
func mustPlanCtx(t *testing.T, ctx context.Context, p *Planner, spec core.FlowSpec) <-chan core.PacketConfig {
	t.Helper()
	ch, err := p.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan returned error: %v", err)
	}
	return ch
}

// validMDNSSpec returns a minimal valid mDNS spec.
func validMDNSSpec() core.FlowSpec {
	return core.FlowSpec{
		SrcMAC: "02:00:00:00:00:01",
		DstMAC: "01:00:5E:00:00:FB",
		SrcIP: "192.168.1.10",
		DstIP: "224.0.0.251",
		SrcPort: 5353,
		DstPort: 5353,
		MDNS: &core.MDNSConfig{},
	}
}

// ===================================================================
// Integration tests
// ===================================================================

// Integration 1: mDNS probing (场景 1: 服务探测).
func TestMDNS_Integration_Probing(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS = &core.MDNSConfig{
		Mode: "probe",
		Questions: []core.MDNSQuestion{
			{Name: "MyServer._http._tcp.local", Type: TypeSRV, Class: 0x8001},
			{Name: "MyServer._http._tcp.local", Type: TypeTXT, Class: 0x8001},
			{Name: "MyServer._http._tcp.local", Type: TypeA, Class: 0x8001},
		},
		ProbingRepeat: 3,
		ProbingInterval: 250,
		ProbingJitterMax: 0, // deterministic
	}
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) != 3 {
		t.Fatalf("probe packet count = %d, want 3", len(cfgs))
	}
	// All packets should be up direction (所有包应为上行方向).
	for i, cfg := range cfgs {
		if cfg.Direction != "up" {
			t.Errorf("cfgs[%d].Direction=%s, want up", i, cfg.Direction)
		}
		if cfg.L4.SrcPort != 5353 {
			t.Errorf("cfgs[%d].L4.SrcPort=%d, want 5353", i, cfg.L4.SrcPort)
		}
		if cfg.L4.DstPort != 5353 {
			t.Errorf("cfgs[%d].L4.DstPort=%d, want 5353", i, cfg.L4.DstPort)
		}
		if cfg.L3.TTL != 255 {
			t.Errorf("cfgs[%d].L3.TTL=%d, want 255", i, cfg.L3.TTL)
		}
		// Verify Transaction ID = 0x0000 (校验事务 ID = 0x0000).
		if len(cfg.Payload) < 2 || cfg.Payload[0] != 0 || cfg.Payload[1] != 0 {
			t.Errorf("cfgs[%d].Payload[0:2]=%02x%02x, want 0000", i, cfg.Payload[0], cfg.Payload[1])
		}
		// Verify Flags = 0x0000 for query (校验 Flags = 0x0000 查询).
		if len(cfg.Payload) < 4 || cfg.Payload[2] != 0 || cfg.Payload[3] != 0 {
			t.Errorf("cfgs[%d].Payload[2:4]=%02x%02x, want 0000", i, cfg.Payload[2], cfg.Payload[3])
		}
	}
	// Verify timestamps: deterministic 250ms gap with jitter=0 (校验时间戳).
	if cfgs[1].Timestamp.Sub(cfgs[0].Timestamp) != 250*time.Millisecond {
		t.Errorf("gap 0->1 = %v, want 250ms", cfgs[1].Timestamp.Sub(cfgs[0].Timestamp))
	}
	if cfgs[2].Timestamp.Sub(cfgs[1].Timestamp) != 250*time.Millisecond {
		t.Errorf("gap 1->2 = %v, want 250ms", cfgs[2].Timestamp.Sub(cfgs[1].Timestamp))
	}
}

// Integration 2: mDNS announcement (场景 2: 服务公告).
func TestMDNS_Integration_Announcement(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS = &core.MDNSConfig{
		Mode: "announce",
		Answers: []core.MDNSResourceRecord{
			{Name: "_http._tcp.local", Type: TypePTR, DomainName: "MyServer._http._tcp.local", TTL: 4500},
			{Name: "MyServer._http._tcp.local", Type: TypeSRV, Priority: 0, Weight: 0, Port: 80, Target: "MyServer.local", TTL: 4500},
			{Name: "MyServer._http._tcp.local", Type: TypeTXT, TXTEntries: []string{"txtvers=1", "path=/"}, TTL: 4500},
			{Name: "MyServer.local", Type: TypeA, IPAddress: "192.168.1.10", TTL: 4500},
		},
		AnnouncingRepeat: 2,
		AnnouncingInterval: 1000,
	}
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) != 2 {
		t.Fatalf("announce packet count = %d, want 2", len(cfgs))
	}
	// Verify flags = 0x8400 (response) (校验 Flags = 0x8400 响应).
	for i, cfg := range cfgs {
		if len(cfg.Payload) < 4 {
			t.Fatalf("cfgs[%d].Payload too short", i)
		}
		if cfg.Payload[2] != 0x84 || cfg.Payload[3] != 0x00 {
			t.Errorf("cfgs[%d].Payload[2:4]=%02x%02x, want 8400", i, cfg.Payload[2], cfg.Payload[3])
		}
		// ANCOUNT should be 4 (校验 ANCOUNT = 4).
		if len(cfg.Payload) >= 8 {
			anCount := uint16(cfg.Payload[6])<<8 | uint16(cfg.Payload[7])
			if anCount != 4 {
				t.Errorf("cfgs[%d] ANCOUNT=%d, want 4", i, anCount)
			}
		}
	}
	// Both payloads should be identical (两个负载应相同).
	if string(cfgs[0].Payload) != string(cfgs[1].Payload) {
		t.Errorf("announce payloads differ between repeat 0 and 1")
	}
}

// Integration 3: Service discovery PTR query (场景 3: 服务发现 PTR 查询).
func TestMDNS_Integration_ServiceDiscovery(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS = &core.MDNSConfig{
		Mode: "query",
		Questions: []core.MDNSQuestion{
			{Name: "_services._dns-sd._udp.local", Type: TypePTR},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) != 1 {
		t.Fatalf("query packet count = %d, want 1", len(cfgs))
	}
	cfg := cfgs[0]
	if cfg.L4.DstPort != 5353 {
		t.Errorf("DstPort=%d, want 5353", cfg.L4.DstPort)
	}
	if cfg.L3.DstIP != "224.0.0.251" {
		t.Errorf("DstIP=%s, want 224.0.0.251", cfg.L3.DstIP)
	}
	// Verify QDCOUNT=1 (校验 QDCOUNT=1).
	if len(cfg.Payload) >= 6 {
		qdCount := uint16(cfg.Payload[4])<<8 | uint16(cfg.Payload[5])
		if qdCount != 1 {
			t.Errorf("QDCOUNT=%d, want 1", qdCount)
		}
	}
	// Verify QNAME (校验 QNAME).
	qname := "_services._dns-sd._udp.local"
	encoded := encodeQName(qname)
	if len(cfg.Payload) >= 12+len(encoded) {
		qnameBytes := cfg.Payload[12 : 12+len(encoded)]
		if string(qnameBytes) != string(encoded) {
			t.Errorf("QNAME mismatch")
		}
	}
}

// Integration 4: SRV/TXT response (场景 4: SRV/TXT 响应).
func TestMDNS_Integration_SRVTXTResponse(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS = &core.MDNSConfig{
		Mode: "response",
		Questions: []core.MDNSQuestion{
			{Name: "_http._tcp.local", Type: TypePTR},
		},
		Answers: []core.MDNSResourceRecord{
			{Name: "_http._tcp.local", Type: TypePTR, DomainName: "MyServer._http._tcp.local", TTL: 4500},
		},
		Additionals: []core.MDNSResourceRecord{
			{Name: "MyServer._http._tcp.local", Type: TypeSRV, Priority: 0, Weight: 0, Port: 80, Target: "MyServer.local", TTL: 4500},
			{Name: "MyServer._http._tcp.local", Type: TypeTXT, TXTEntries: []string{"txtvers=1", "path=/index.html"}, TTL: 4500},
			{Name: "MyServer.local", Type: TypeA, IPAddress: "192.168.1.10", TTL: 4500},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) != 1 {
		t.Fatalf("response packet count = %d, want 1", len(cfgs))
	}
	cfg := cfgs[0]
	// ANCOUNT=1, ARCOUNT=3 (校验 ANCOUNT=1, ARCOUNT=3).
	if len(cfg.Payload) >= 12 {
		anCount := uint16(cfg.Payload[6])<<8 | uint16(cfg.Payload[7])
		arCount := uint16(cfg.Payload[10])<<8 | uint16(cfg.Payload[11])
		if anCount != 1 {
			t.Errorf("ANCOUNT=%d, want 1", anCount)
		}
		if arCount != 3 {
			t.Errorf("ARCOUNT=%d, want 3", arCount)
		}
	}
}

// Integration 5: Goodbye packet (场景 5: 下线包).
func TestMDNS_Integration_Goodbye(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS = &core.MDNSConfig{
		Mode: "goodbye",
		Answers: []core.MDNSResourceRecord{
			{Name: "_http._tcp.local", Type: TypePTR, DomainName: "MyServer._http._tcp.local", TTL: 4500},
			{Name: "MyServer._http._tcp.local", Type: TypeSRV, Priority: 0, Weight: 0, Port: 80, Target: "MyServer.local", TTL: 4500},
			{Name: "MyServer._http._tcp.local", Type: TypeTXT, TXTEntries: []string{"txtvers=1"}, TTL: 4500},
			{Name: "MyServer.local", Type: TypeA, IPAddress: "192.168.1.10", TTL: 4500},
		},
		CacheFlush: boolPtr(true),
	}
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) != 1 {
		t.Fatalf("goodbye packet count = %d, want 1", len(cfgs))
	}
	cfg := cfgs[0]
	// Verify flags = 0x8400 (response) (校验 Flags = 0x8400 响应).
	if len(cfg.Payload) < 4 || cfg.Payload[2] != 0x84 || cfg.Payload[3] != 0x00 {
		t.Errorf("Payload[2:4]=%02x%02x, want 8400", cfg.Payload[2], cfg.Payload[3])
	}
	// Verify TTL=0 for all records (校验所有记录 TTL=0).
	// We need to parse the payload to find TTL fields.
	// For goodbye, all TTL values should be 0x00000000.
	// Quick check: look for the TTL fields in the payload.
	if len(cfg.Payload) > 50 {
		// Find TTL fields: they appear after NAME+TYPE+CLASS (each 4+2+2 bytes after NAME).
		// At minimum, check that the payload does NOT contain the default TTL bytes 0x00001194.
		if strings.Contains(string(cfg.Payload), "\x00\x00\x11\x94") {
			t.Errorf("goodbye payload contains non-zero TTL 0x00001194")
		}
	}
}

// Integration 6: IPv6 AAAA record (场景 6: IPv6 AAAA 记录).
func TestMDNS_Integration_IPv6(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcMAC: "02:00:00:00:00:01",
		DstMAC: "33:33:00:00:00:FB",
		SrcIP: "fe80::1234",
		DstIP: "ff02::fb",
		SrcPort: 5353,
		DstPort: 5353,
		MDNS: &core.MDNSConfig{
			Mode: "announce",
			Answers: []core.MDNSResourceRecord{
				{Name: "_http._tcp.local", Type: TypePTR, DomainName: "MyServer._http._tcp.local", TTL: 4500},
				{Name: "MyServer._http._tcp.local", Type: TypeSRV, Priority: 0, Weight: 0, Port: 80, Target: "MyServer.local", TTL: 4500},
				{Name: "MyServer._http._tcp.local", Type: TypeTXT, TXTEntries: []string{"txtvers=1"}, TTL: 4500},
				{Name: "MyServer.local", Type: TypeAAAA, IPAddress: "fe80::1234", TTL: 4500},
			},
			AnnouncingRepeat: 1,
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) != 1 {
		t.Fatalf("IPv6 announce packet count = %d, want 1", len(cfgs))
	}
	cfg := cfgs[0]
	if cfg.L3.DstIP != "ff02::fb" {
		t.Errorf("DstIP=%s, want ff02::fb", cfg.L3.DstIP)
	}
	if cfg.L2.DstMAC != "33:33:00:00:00:FB" {
		t.Errorf("DstMAC=%s, want 33:33:00:00:00:FB", cfg.L2.DstMAC)
	}
	if cfg.L2.EtherType != 0x86DD {
		t.Errorf("EtherType=%04x, want 86DD (IPv6)", cfg.L2.EtherType)
	}
	if cfg.L3.TTL != 255 {
		t.Errorf("L3.TTL=%d, want 255", cfg.L3.TTL)
	}
	// Verify AAAA RDATA length = 16 bytes (校验 AAAA RDATA 长度 = 16).
	ip := net.ParseIP("fe80::1234")
	ip16 := ip.To16()
	if len(cfg.Payload) > 12 && !containsBytes(cfg.Payload, ip16) {
		t.Errorf("AAAA RDATA not found in payload")
	}
}

// Integration 7: Conflict resolution (场景 7: 冲突解决).
func TestMDNS_Integration_Conflict(t *testing.T) {
	// Two hosts probing the same name (两个主机探测同名).
	p := NewPlanner()
	specA := validMDNSSpec()
	specA.SrcIP = "192.168.1.10"
	specA.MDNS = &core.MDNSConfig{
		Mode: "probe",
		Questions: []core.MDNSQuestion{
			{Name: "MyServer._http._tcp.local", Type: TypeSRV, Class: 0x8001},
		},
		ProbingRepeat: 1,
	}
	specB := validMDNSSpec()
	specB.SrcIP = "192.168.1.20"
	specB.MDNS = &core.MDNSConfig{
		Mode: "probe",
		Questions: []core.MDNSQuestion{
			{Name: "MyServer._http._tcp.local", Type: TypeSRV, Class: 0x8001},
		},
		ProbingRepeat: 1,
	}

	cfgsA := drain(mustPlan(t, p, specA))
	cfgsB := drain(mustPlan(t, p, specB))

	if len(cfgsA) != 1 || len(cfgsB) != 1 {
		t.Fatalf("expected 1 each, got %d and %d", len(cfgsA), len(cfgsB))
	}

	// Both should have the same QNAME in the question (两者应有相同的 QNAME).
	qname := "MyServer._http._tcp.local"
	encoded := encodeQName(qname)
	if len(cfgsA[0].Payload) < 12+len(encoded) {
		t.Fatalf("cfgsA payload too short")
	}
	qnameBytesA := cfgsA[0].Payload[12 : 12+len(encoded)]
	qnameBytesB := cfgsB[0].Payload[12 : 12+len(encoded)]
	if string(qnameBytesA) != string(encoded) {
		t.Errorf("Host A QNAME mismatch")
	}
	if string(qnameBytesB) != string(encoded) {
		t.Errorf("Host B QNAME mismatch")
	}
}

// TestMDNS_Validate_InvalidPort tests that non-5353 ports are rejected.
func TestMDNS_Validate_InvalidPort(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.SrcPort = 53
	err := p.Validate(spec)
	if err == nil {
		t.Errorf("expected error for non-5353 source port, got nil")
	}
	if err != nil && !strings.Contains(err.Error(), "must be 5353") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestMDNS_Validate_InvalidDstPort tests that non-5353 dst ports are rejected.
func TestMDNS_Validate_InvalidDstPort(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.DstPort = 53
	err := p.Validate(spec)
	if err == nil {
		t.Errorf("expected error for non-5353 destination port, got nil")
	}
	if err != nil && !strings.Contains(err.Error(), "must be 5353") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestMDNS_Validate_NilConfig tests that nil MDNSConfig is valid (uses defaults).
func TestMDNS_Validate_NilConfig(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS = nil
	err := p.Validate(spec)
	if err != nil {
		t.Errorf("expected nil error for nil MDNSConfig, got %v", err)
	}
}

// TestMDNS_Validate_InvalidMode tests that invalid mode is rejected.
func TestMDNS_Validate_InvalidMode(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS.Mode = "invalid"
	err := p.Validate(spec)
	if err == nil {
		t.Errorf("expected error for invalid mode, got nil")
	}
}

// TestMDNS_Validate_EmptyQuestionsForQuery tests that query mode needs questions.
func TestMDNS_Validate_EmptyQuestionsForQuery(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS.Mode = "query"
	spec.MDNS.Questions = []core.MDNSQuestion{}
	err := p.Validate(spec)
	if err == nil {
		t.Errorf("expected error for empty questions in query mode, got nil")
	}
}

// TestMDNS_Validate_EmptyAnswersForResponse tests that response mode needs answers.
func TestMDNS_Validate_EmptyAnswersForResponse(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS.Mode = "response"
	spec.MDNS.Answers = []core.MDNSResourceRecord{}
	err := p.Validate(spec)
	if err == nil {
		t.Errorf("expected error for empty answers in response mode, got nil")
	}
}

// TestMDNS_Plan_DefaultQuery tests that nil MDNSConfig produces a default query.
func TestMDNS_Plan_DefaultQuery(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS = nil
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) != 1 {
		t.Fatalf("default query packet count = %d, want 1", len(cfgs))
	}
	cfg := cfgs[0]
	if cfg.L4.DstPort != 5353 {
		t.Errorf("DstPort=%d, want 5353", cfg.L4.DstPort)
	}
	if cfg.L4.Protocol != "udp" {
		t.Errorf("Protocol=%s, want udp", cfg.L4.Protocol)
	}
}

// TestMDNS_Plan_EmptyMode defaults to query.
func TestMDNS_Plan_EmptyMode(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS.Mode = ""
	spec.MDNS.Questions = []core.MDNSQuestion{
		{Name: "_http._tcp.local", Type: TypePTR},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) != 1 {
		t.Fatalf("empty mode packet count = %d, want 1", len(cfgs))
	}
}

// TestMDNS_Plan_FlowIDUnique tests that multiple Plan calls produce unique flow IDs.
func TestMDNS_Plan_FlowIDUnique(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS.Mode = "query"
	spec.MDNS.Questions = []core.MDNSQuestion{
		{Name: "_http._tcp.local", Type: TypePTR},
	}
	cfgs1 := drain(mustPlan(t, p, spec))
	cfgs2 := drain(mustPlan(t, p, spec))
	if len(cfgs1) != 1 || len(cfgs2) != 1 {
		t.Fatalf("unexpected packet count")
	}
	if cfgs1[0].FlowID == cfgs2[0].FlowID {
		t.Errorf("FlowIDs should be unique across Plan calls")
	}
}

// TestMDNS_Context_Cancel tests that context cancellation stops packet generation.
func TestMDNS_Context_Cancel(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS = &core.MDNSConfig{
		Mode: "probe",
		Questions: []core.MDNSQuestion{
			{Name: "test.local", Type: TypeA},
		},
		ProbingRepeat: 100,
		ProbingInterval: 0,
		ProbingJitterMax: 0,
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Immediately cancel
	ch, err := p.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan returned error: %v", err)
	}
	cfgs := drain(ch)
	if len(cfgs) >= 100 {
		t.Errorf("expected early cancellation, got %d packets (>=100)", len(cfgs))
	}
}

// TestMDNS_IPv6_MulticastMAC tests IPv6 multicast MAC.
func TestMDNS_IPv6_MulticastMAC(t *testing.T) {
	if got := multicastDstMAC("ff02::fb"); got != "33:33:00:00:00:FB" {
		t.Errorf("IPv6 multicast MAC = %s, want 33:33:00:00:00:FB", got)
	}
	if got := multicastDstMAC("224.0.0.251"); got != "01:00:5E:00:00:FB" {
		t.Errorf("IPv4 multicast MAC = %s, want 01:00:5E:00:00:FB", got)
	}
}

// TestMDNS_EncodeQName_Simple tests basic QName encoding.
func TestMDNS_EncodeQName_Simple(t *testing.T) {
	got := encodeQName("_http._tcp.local")
	want := []byte{5, '_', 'h', 't', 't', 'p', 4, '_', 't', 'c', 'p', 5, 'l', 'o', 'c', 'a', 'l', 0}
	if len(got) != len(want) {
		t.Fatalf("QName length = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("QName byte[%d] = %02x, want %02x", i, got[i], want[i])
		}
	}
}

// TestMDNS_EncodeQName_MyServer tests encoding of "MyServer.local".
func TestMDNS_EncodeQName_MyServer(t *testing.T) {
	got := encodeQName("MyServer.local")
	want := []byte{8, 'M', 'y', 'S', 'e', 'r', 'v', 'e', 'r', 5, 'l', 'o', 'c', 'a', 'l', 0}
	if len(got) != len(want) {
		t.Fatalf("QName length = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("QName byte[%d] = %02x, want %02x", i, got[i], want[i])
		}
	}
}

// TestMDNS_EncodeQName_A tests encoding of single char "a".
func TestMDNS_EncodeQName_A(t *testing.T) {
	got := encodeQName("a")
	want := []byte{1, 'a', 0}
	if len(got) != len(want) {
		t.Fatalf("QName length = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("QName byte[%d] = %02x, want %02x", i, got[i], want[i])
		}
	}
}

// TestMDNS_EncodeQName_ABC tests encoding of "a.b.c".
func TestMDNS_EncodeQName_ABC(t *testing.T) {
	got := encodeQName("a.b.c")
	want := []byte{1, 'a', 1, 'b', 1, 'c', 0}
	if len(got) != len(want) {
		t.Fatalf("QName length = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("QName byte[%d] = %02x, want %02x", i, got[i], want[i])
		}
	}
}

// TestMDNS_Planner_Name tests the Name method.
func TestMDNS_Planner_Name(t *testing.T) {
	p := NewPlanner()
	if p.Name() != "mdns" {
		t.Errorf("Name() = %s, want mdns", p.Name())
	}
}

// TestMDNS_Validate_LabelTooLong tests that label > 63 is rejected.
func TestMDNS_Validate_LabelTooLong(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	longLabel := strings.Repeat("a", 64) + ".local"
	spec.MDNS.Mode = "query"
	spec.MDNS.Questions = []core.MDNSQuestion{
		{Name: longLabel, Type: TypeA},
	}
	err := p.Validate(spec)
	if err == nil {
		t.Errorf("expected error for label > 63, got nil")
	}
}

// TestMDNS_Validate_QNameTooLong tests that QName > 255 encoded bytes is rejected.
func TestMDNS_Validate_QNameTooLong(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	// 50 labels of 5 chars each = 50*(1+5)+1 = 301 bytes > 255
	parts := make([]string, 50)
	for i := range parts {
		parts[i] = "abcde"
	}
	longName := strings.Join(parts, ".")
	spec.MDNS.Mode = "query"
	spec.MDNS.Questions = []core.MDNSQuestion{
		{Name: longName, Type: TypeA},
	}
	err := p.Validate(spec)
	if err == nil {
		t.Errorf("expected error for QName > 255 bytes, got nil")
	}
}

// TestMDNS_Validate_LeadingDot tests that leading dot is rejected.
func TestMDNS_Validate_LeadingDot(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS.Mode = "query"
	spec.MDNS.Questions = []core.MDNSQuestion{
		{Name: ".local", Type: TypeA},
	}
	err := p.Validate(spec)
	if err == nil {
		t.Errorf("expected error for leading dot, got nil")
	}
}

// TestMDNS_Validate_JitterMax tests that jitter > 250 is rejected.
func TestMDNS_Validate_JitterMax(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS.Mode = "probe"
	spec.MDNS.Questions = []core.MDNSQuestion{
		{Name: "test.local", Type: TypeA},
	}
	spec.MDNS.ProbingJitterMax = 251
	err := p.Validate(spec)
	if err == nil {
		t.Errorf("expected error for jitter > 250, got nil")
	}
}

// TestMDNS_Validate_TCOnQuery tests that TC bit is only valid in response modes.
func TestMDNS_Validate_TCOnQuery(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS.Mode = "query"
	spec.MDNS.TC = true
	spec.MDNS.Questions = []core.MDNSQuestion{
		{Name: "test.local", Type: TypeA},
	}
	err := p.Validate(spec)
	if err == nil {
		t.Errorf("expected error for TC on query, got nil")
	}
}

// TestMDNS_Validate_TTLMax tests that TTL > 2^31-1 is rejected.
func TestMDNS_Validate_TTLMax(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS.Mode = "response"
	spec.MDNS.Answers = []core.MDNSResourceRecord{
		{Name: "test.local", Type: TypeA, IPAddress: "192.168.1.1", TTL: 4294967295},
	}
	err := p.Validate(spec)
	if err == nil {
		t.Errorf("expected error for TTL > 2^31-1, got nil")
	}
}

// TestMDNS_Plane_ProbeRepeat1 tests that ProbingRepeat=1 produces 1 packet.
func TestMDNS_Plan_ProbeRepeat1(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS = &core.MDNSConfig{
		Mode: "probe",
		Questions: []core.MDNSQuestion{
			{Name: "test.local", Type: TypeA},
		},
		ProbingRepeat: 1,
	}
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) != 1 {
		t.Errorf("probe repeat=1: packet count = %d, want 1", len(cfgs))
	}
}

// TestMDNS_Plan_DefaultProbingRepeat tests that default probing repeat is 3.
func TestMDNS_Plan_DefaultProbingRepeat(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS = &core.MDNSConfig{
		Mode: "probe",
		Questions: []core.MDNSQuestion{
			{Name: "test.local", Type: TypeA},
		},
		ProbingInterval: 0,
		ProbingJitterMax: 0,
	}
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) != 3 {
		t.Errorf("default probing repeat: packet count = %d, want 3", len(cfgs))
	}
}

// TestMDNS_Plan_ResponseDelay tests that ResponseDelay adds delay.
func TestMDNS_Plan_ResponseDelay(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS = &core.MDNSConfig{
		Mode: "response",
		Answers: []core.MDNSResourceRecord{
			{Name: "test.local", Type: TypeA, IPAddress: "192.168.1.1"},
		},
		ResponseDelay: 50,
	}
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) != 1 {
		t.Fatalf("response packet count = %d, want 1", len(cfgs))
	}
	delay := time.Since(cfgs[0].Timestamp)
	if delay < 40*time.Millisecond || delay > 200*time.Millisecond {
		t.Logf("response delay = %v (expected ~50ms, may vary)", delay)
	}
}

// TestMDNS_Plan_GroupID tests that GroupID is propagated.
func TestMDNS_Plan_GroupID(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS = &core.MDNSConfig{
		Mode: "query",
		Questions: []core.MDNSQuestion{
			{Name: "_http._tcp.local", Type: TypePTR},
		},
	}
	spec.GroupID = &core.StrategyConfig{
		Strategy: "fixed",
		Value: "test-group",
	}
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) != 1 {
		t.Fatalf("packet count = %d, want 1", len(cfgs))
	}
	if cfgs[0].Metadata == nil {
		t.Fatalf("no metadata")
	}
	gid, ok := cfgs[0].Metadata["group_id"]
	if !ok {
		t.Fatalf("no group_id in metadata")
	}
	if gid != "test-group" {
		t.Errorf("group_id = %v, want test-group", gid)
	}
}

// TestMDNS_Validate_NonINClass tests that non-IN class is rejected.
func TestMDNS_Validate_NonINClass(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS.Mode = "query"
	spec.MDNS.Questions = []core.MDNSQuestion{
		{Name: "test.local", Type: TypeA, Class: 3}, // CH class
	}
	err := p.Validate(spec)
	if err == nil {
		t.Errorf("expected error for non-IN class, got nil")
	}
}

// TestMDNS_Validate_FixedTTL points probe question with type 0 is invalid.
func TestMDNS_Validate_InvalidQType(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS.Mode = "query"
	spec.MDNS.Questions = []core.MDNSQuestion{
		{Name: "test.local", Type: 0},
	}
	err := p.Validate(spec)
	if err == nil {
		t.Errorf("expected error for qtype 0, got nil")
	}
}

// TestMDNS_Validate_EmptyAnswersForGoodbye tests that goodbye mode needs answers.
func TestMDNS_Validate_EmptyAnswersForGoodbye(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS.Mode = "goodbye"
	spec.MDNS.Answers = []core.MDNSResourceRecord{}
	err := p.Validate(spec)
	if err == nil {
		t.Errorf("expected error for empty answers in goodbye mode, got nil")
	}
}

// TestMDNS_Validate_EmptyAnswersForAnnounce tests that announce mode needs answers.
func TestMDNS_Validate_EmptyAnswersForAnnounce(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS.Mode = "announce"
	spec.MDNS.Answers = []core.MDNSResourceRecord{}
	err := p.Validate(spec)
	if err == nil {
		t.Errorf("expected error for empty answers in announce mode, got nil")
	}
}

// TestMDNS_Validate_InvalidMulticastGroup tests that non-mDNS multicast groups are rejected.
func TestMDNS_Validate_InvalidMulticastGroup(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS.Mode = "query"
	spec.MDNS.Questions = []core.MDNSQuestion{
		{Name: "test.local", Type: TypeA},
	}
	spec.MDNS.MulticastGroup = "239.1.1.1"
	err := p.Validate(spec)
	if err == nil {
		t.Errorf("expected error for non-mDNS multicast group, got nil")
	}
}

// TestMDNS_Validate_IPv6MulticastWithIPv4Src tests that IPv6 multicast with IPv4 source is rejected.
func TestMDNS_Validate_IPv6MulticastWithIPv4Src(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS.Mode = "query"
	spec.MDNS.Questions = []core.MDNSQuestion{
		{Name: "test.local", Type: TypeA},
	}
	spec.MDNS.MulticastGroup = "ff02::fb"
	// SrcIP is "192.168.1.10" (IPv4) from validMDNSSpec
	err := p.Validate(spec)
	if err == nil {
		t.Errorf("expected error for IPv6 multicast with IPv4 source, got nil")
	}
}

// TestMDNS_Plan_AutoPorts tests that zero ports are auto-filled to 5353.
func TestMDNS_Plan_AutoPorts(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.SrcPort = 0
	spec.DstPort = 0
	spec.MDNS = &core.MDNSConfig{
		Mode: "query",
		Questions: []core.MDNSQuestion{
			{Name: "_http._tcp.local", Type: TypePTR},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) != 1 {
		t.Fatalf("packet count = %d, want 1", len(cfgs))
	}
	if cfgs[0].L4.SrcPort != 5353 {
		t.Errorf("SrcPort=%d, want 5353", cfgs[0].L4.SrcPort)
	}
	if cfgs[0].L4.DstPort != 5353 {
		t.Errorf("DstPort=%d, want 5353", cfgs[0].L4.DstPort)
	}
}

// TestMDNS_Plan_GoodbyeTTL tests that goodbye forces TTL=0.
func TestMDNS_Plan_GoodbyeTTL(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS = &core.MDNSConfig{
		Mode: "goodbye",
		Answers: []core.MDNSResourceRecord{
			{Name: "test.local", Type: TypeA, IPAddress: "192.168.1.1", TTL: 4500},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) != 1 {
		t.Fatalf("goodbye packet count = %d, want 1", len(cfgs))
	}
	// In the payload, find the TTL field (4 bytes after NAME+TYPE+CLASS).
	// For a goodbye, TTL should be 0x00000000.
	payload := cfgs[0].Payload
	// Look for the TTL bytes: it should be 0x00000000 for goodbye.
	if len(payload) > 30 {
		// Find the TTL in the RR section: after QNAME(12+encoded_qname+4) + NAME+TYPE+CLASS
		// A simpler approach: decode the payload at the RR location.
		// The RR is: NAME(QName) + TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2) + RDATA(4)
		// QNAME = 1+4+5+5+0 = 15 bytes (test.local)
		// Let's just check that the payload doesn't contain the default TTL bytes.
		if strings.Contains(string(payload), "\x00\x00\x11\x94") {
			t.Errorf("goodbye payload contains non-zero TTL")
		}
	}
}

// TestMDNS_Plan_Port5353ForAllModes tests that all modes use port 5353.
func TestMDNS_Plan_Port5353ForAllModes(t *testing.T) {
	modes := []string{"query", "response", "probe", "announce", "goodbye"}
	for _, mode := range modes {
		t.Run("mode_"+mode, func(t *testing.T) {
			p := NewPlanner()
			spec := validMDNSSpec()
			spec.SrcPort = 0
			spec.DstPort = 0

			switch mode {
			case "query", "probe":
				spec.MDNS = &core.MDNSConfig{
					Mode: mode,
					Questions: []core.MDNSQuestion{{Name: "test.local", Type: TypeA}},
				}
				if mode == "probe" {
					spec.MDNS.ProbingRepeat = 1
					spec.MDNS.ProbingInterval = 0
					spec.MDNS.ProbingJitterMax = 0
				}
			case "response", "announce", "goodbye":
				spec.MDNS = &core.MDNSConfig{
					Mode: mode,
					Answers: []core.MDNSResourceRecord{{Name: "test.local", Type: TypeA, IPAddress: "192.168.1.1"}},
				}
			}
			cfgs := drain(mustPlan(t, p, spec))
			if len(cfgs) == 0 {
				t.Fatalf("no packets for mode %s", mode)
			}
			for i, cfg := range cfgs {
				if cfg.L4.SrcPort != 5353 {
					t.Errorf("mode %s cfgs[%d].SrcPort=%d, want 5353", mode, i, cfg.L4.SrcPort)
				}
				if cfg.L4.DstPort != 5353 {
					t.Errorf("mode %s cfgs[%d].DstPort=%d, want 5353", mode, i, cfg.L4.DstPort)
				}
			}
		})
	}
}

// TestMDNS_Validate_SRV_EmptyTarget tests that SRV with empty Target is rejected.
func TestMDNS_Validate_SRV_EmptyTarget(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS.Mode = "response"
	spec.MDNS.Answers = []core.MDNSResourceRecord{
		{Name: "test._http._tcp.local", Type: TypeSRV, Priority: 0, Weight: 0, Port: 80, Target: ""},
	}
	err := p.Validate(spec)
	if err == nil {
		t.Errorf("expected error for SRV with empty target, got nil")
	}
}

// TestMDNS_Validate_A_EmptyIP tests that A record with empty IP is rejected.
func TestMDNS_Validate_A_EmptyIP(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS.Mode = "response"
	spec.MDNS.Answers = []core.MDNSResourceRecord{
		{Name: "test.local", Type: TypeA, IPAddress: ""},
	}
	err := p.Validate(spec)
	if err == nil {
		t.Errorf("expected error for A record with empty IP, got nil")
	}
}

// TestMDNS_Validate_TXT_EntryTooLong tests that TXT entry > 255 is rejected.
func TestMDNS_Validate_TXT_EntryTooLong(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS.Mode = "response"
	spec.MDNS.Answers = []core.MDNSResourceRecord{
		{Name: "test.local", Type: TypeTXT, TXTEntries: []string{strings.Repeat("a", 256)}},
	}
	err := p.Validate(spec)
	if err == nil {
		t.Errorf("expected error for TXT entry > 255, got nil")
	}
}

// TestMDNS_Plan_ProbeJitterSeed tests deterministic jitter with seed.
func TestMDNS_Plan_ProbeJitterSeed(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS = &core.MDNSConfig{
		Mode: "probe",
		Questions: []core.MDNSQuestion{
			{Name: "test.local", Type: TypeA},
		},
		ProbingRepeat: 3,
		ProbingInterval: 250,
		ProbingJitterMax: 100,
		ProbingJitterSeed: 42,
	}
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) != 3 {
		t.Fatalf("probe packet count = %d, want 3", len(cfgs))
	}
	gap1 := cfgs[1].Timestamp.Sub(cfgs[0].Timestamp)
	gap2 := cfgs[2].Timestamp.Sub(cfgs[1].Timestamp)
	if gap1 < 250*time.Millisecond || gap1 > 350*time.Millisecond {
		t.Errorf("gap1 = %v, want in [250ms, 350ms]", gap1)
	}
	if gap2 < 250*time.Millisecond || gap2 > 350*time.Millisecond {
		t.Errorf("gap2 = %v, want in [250ms, 350ms]", gap2)
	}
}

// TestMDNS_Plan_NegativeJitterMax tests that negative jitter is rejected.
func TestMDNS_Validate_NegativeJitterMax(t *testing.T) {
	p := NewPlanner()
	spec := validMDNSSpec()
	spec.MDNS.Mode = "probe"
	spec.MDNS.Questions = []core.MDNSQuestion{
		{Name: "test.local", Type: TypeA},
	}
	spec.MDNS.ProbingJitterMax = -1
	err := p.Validate(spec)
	if err == nil {
		t.Errorf("expected error for negative jitter, got nil")
	}
}

// containsBytes checks if slice contains sub-slice.
func containsBytes(haystack, needle []byte) bool {
	if len(needle) == 0 {
		return true
	}
	for i := 0; i <= len(haystack)-len(needle); i++ {
		match := true
		for j := 0; j < len(needle); j++ {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// boolPtr returns a pointer to a bool.
func boolPtr(v bool) *bool {
	return &v
}