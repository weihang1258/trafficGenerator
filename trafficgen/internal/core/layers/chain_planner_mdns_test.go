// 外部测试包：mdns 链的字节级对比需要 legacy mdns.NewPlanner 与 chain
// （internal/protocol/mdns + internal/core/layers）。测试贴近真实调用方
// （main.go 的 layers.NewChainPlanner("mdns")）。
package layers_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	"github.com/trafficgen/trafficgen/internal/protocol/mdns"
)

// mdnsSpec builds a minimal mDNS query spec (5353/5353, IPv4 group). Both
// planners force ports to 5353 when 0, so the spec omits them to also cover
// the default path (validateSpecBase 的 mdns→5353 默认 + udp 层读取 spec
// 端口双路验证)。
func mdnsSpec() core.FlowSpec {
	return core.FlowSpec{
		SrcIP:  "192.168.1.10",
		DstIP:  "224.0.0.251",
		SrcMAC: "02:00:00:00:00:01",
		DstMAC: "01:00:5E:00:00:FB",
		MDNS: &core.MDNSConfig{
			Mode: "query",
			Questions: []core.MDNSQuestion{
				{Name: "MyServer._http._tcp.local", Type: mdns.TypePTR},
			},
		},
	}
}

// mdnsAnswers builds the answer sections used by the response/announce/
// goodbye tests (与 legacy planner_test.go 同款记录)。
func mdnsAnswers() []core.MDNSResourceRecord {
	return []core.MDNSResourceRecord{
		{Name: "_http._tcp.local", Type: mdns.TypePTR, DomainName: "MyServer._http._tcp.local", TTL: 4500},
		{Name: "MyServer._http._tcp.local", Type: mdns.TypeSRV, Priority: 0, Weight: 0, Port: 80, Target: "MyServer.local", TTL: 4500},
		{Name: "MyServer._http._tcp.local", Type: mdns.TypeTXT, TXTEntries: []string{"txtvers=1"}, TTL: 4500},
		{Name: "MyServer.local", Type: mdns.TypeA, IPAddress: "192.168.1.10", TTL: 4500},
	}
}

// maskMDNSVolatile zeroes the volatile fields that differ between two
// independent runs: IPv4 ID (18-19) and IP checksum (24-25). The payload is
// deterministic (fixed TTL/records); UDP checksum depends only on payload.
func maskMDNSVolatile(pkt []byte) []byte {
	out := append([]byte(nil), pkt...)
	if len(out) > 25 {
		out[18], out[19] = 0, 0 // IPID
		out[24], out[25] = 0, 0 // IP header checksum
	}
	return out
}

// assertMDNSIdentical builds both packets and compares wire bytes after
// masking the volatile fields.
func assertMDNSIdentical(t *testing.T, chain, legacy core.PacketConfig, idx int) {
	t.Helper()
	b := core.NewBuilder()
	cb, err := b.Build(chain)
	if err != nil {
		t.Fatalf("Build(chain[%d]): %v", idx, err)
	}
	lb, err := b.Build(legacy)
	if err != nil {
		t.Fatalf("Build(legacy[%d]): %v", idx, err)
	}
	if !bytes.Equal(maskMDNSVolatile(cb), maskMDNSVolatile(lb)) {
		t.Errorf("packet %d bytes differ:\nchain  %x\nlegacy %x", idx, cb, lb)
	}
}

// TestChainPlanner_MDNS_Query verifies the [ip→udp→mdns] chain emits one up
// datagram to the multicast group 224.0.0.251 with the derived multicast MAC,
// byte-identical to legacy mdns.NewPlanner.
func TestChainPlanner_MDNS_Query(t *testing.T) {
	spec := mdnsSpec()
	chain := collectPlanner(t, layers.NewChainPlanner("mdns"), spec)
	legacy := collectPlanner(t, mdns.NewPlanner(), spec)

	if len(chain) != 1 {
		t.Fatalf("chain produced %d packets, want 1", len(chain))
	}
	if chain[0].Direction != "up" {
		t.Errorf("direction = %s, want up", chain[0].Direction)
	}
	if chain[0].L3.DstIP != mdns.MulticastIPv4 {
		t.Errorf("L3.DstIP = %q, want %q", chain[0].L3.DstIP, mdns.MulticastIPv4)
	}
	if chain[0].L3.SrcIP != "192.168.1.10" {
		t.Errorf("L3.SrcIP = %q, want 192.168.1.10", chain[0].L3.SrcIP)
	}
	// 多播 MAC 推导（RFC 1112 §6.4）：224.0.0.251 → 01:00:5e:00:00:fb。
	if chain[0].L2.DstMAC != "01:00:5e:00:00:fb" {
		t.Errorf("L2.DstMAC = %q, want 01:00:5e:00:00:fb", chain[0].L2.DstMAC)
	}
	if chain[0].L2.SrcMAC != "02:00:00:00:00:01" {
		t.Errorf("L2.SrcMAC = %q, want 02:00:00:00:00:01", chain[0].L2.SrcMAC)
	}
	if chain[0].L4.Protocol != "udp" || chain[0].L4.SrcPort != 5353 || chain[0].L4.DstPort != 5353 {
		t.Errorf("L4 = %s %d/%d, want udp 5353/5353", chain[0].L4.Protocol, chain[0].L4.SrcPort, chain[0].L4.DstPort)
	}
	// mDNS 强制 TTL=255（RFC 6762 §11）。
	if chain[0].L3.TTL != 255 {
		t.Errorf("L3.TTL = %d, want 255", chain[0].L3.TTL)
	}
	// 报文结构：Transaction ID=0x0000、Flags=0x0000（query）。
	if len(chain[0].Payload) < 12 {
		t.Fatalf("payload too short: %d bytes", len(chain[0].Payload))
	}
	if chain[0].Payload[0] != 0 || chain[0].Payload[1] != 0 {
		t.Errorf("Payload[0:2] = %02x%02x, want 0000 (txid)", chain[0].Payload[0], chain[0].Payload[1])
	}
	if chain[0].Payload[2] != 0 || chain[0].Payload[3] != 0 {
		t.Errorf("Payload[2:4] = %02x%02x, want 0000 (flags)", chain[0].Payload[2], chain[0].Payload[3])
	}
	assertMDNSIdentical(t, chain[0], legacy[0], 0)
}

// TestChainPlanner_MDNS_DefaultDstPort verifies the chain defaults the
// destination port to 5353 (validateSpecBase) when the spec omits it —
// udp 层从默认化后的 spec 端口装配数据报。
func TestChainPlanner_MDNS_DefaultDstPort(t *testing.T) {
	spec := mdnsSpec()
	spec.DstPort = 0
	chain := collectPlanner(t, layers.NewChainPlanner("mdns"), spec)
	if chain[0].L4.DstPort != 5353 {
		t.Errorf("dst port = %d, want 5353 (mdns default)", chain[0].L4.DstPort)
	}
}

// TestChainPlanner_MDNS_Probe verifies probe mode emits 3 packets at
// deterministic 250ms wall-clock pacing (jitter 0), each byte-identical to
// legacy. Per-packet Timestamp gaps are not asserted: Plan overwrites every
// packet's Timestamp with time.Now() at collection (chain_planner.go 收集段),
// so timestamps never carry the pacing gaps — pacing is the engine Pacer's
// job. The wall-clock assertion below still proves the generator sleeps
// between emits (3 packets at 250ms would otherwise finish instantly).
func TestChainPlanner_MDNS_Probe(t *testing.T) {
	spec := mdnsSpec()
	spec.MDNS = &core.MDNSConfig{
		Mode: "probe",
		Questions: []core.MDNSQuestion{
			{Name: "MyServer._http._tcp.local", Type: mdns.TypeSRV, Class: 0x8001},
			{Name: "MyServer._http._tcp.local", Type: mdns.TypeTXT, Class: 0x8001},
		},
		ProbingRepeat:    3,
		ProbingInterval:  250,
		ProbingJitterMax: 0, // deterministic
	}
	start := time.Now()
	chain := collectPlanner(t, layers.NewChainPlanner("mdns"), spec)
	elapsed := time.Since(start)
	legacy := collectPlanner(t, mdns.NewPlanner(), spec)

	if len(chain) != 3 {
		t.Fatalf("chain produced %d packets, want 3", len(chain))
	}
	// 确定性子种子抖动 0：间隔精确 250ms（wall-clock，见上注释）。
	if elapsed < 2*250*time.Millisecond {
		t.Errorf("3 probe packets finished in %v, want >= 500ms (2 x 250ms gaps)", elapsed)
	}
	// QU 位（QCLASS 高位置位，Class 0x8001）+ 3 个 question。
	if !bytes.Contains(chain[0].Payload, []byte{0x00, 0x21, 0x80, 0x01}) {
		t.Errorf("payload missing QU-bit question (type 0x0021 class 0x8001)")
	}
	for i := 0; i < 3; i++ {
		if chain[i].L3.TTL != 255 {
			t.Errorf("packet %d TTL = %d, want 255", i, chain[i].L3.TTL)
		}
		assertMDNSIdentical(t, chain[i], legacy[i], i)
	}
}

// TestChainPlanner_MDNS_Announce verifies announce mode emits AnnouncingRepeat
// packets with the cache-flush bit (0x8000) on answer CLASS, byte-identical
// to legacy.
func TestChainPlanner_MDNS_Announce(t *testing.T) {
	spec := mdnsSpec()
	spec.MDNS = &core.MDNSConfig{
		Mode:               "announce",
		Answers:            mdnsAnswers(),
		AnnouncingRepeat:   2,
		AnnouncingInterval: 0, // no sleep (fast test)
	}
	chain := collectPlanner(t, layers.NewChainPlanner("mdns"), spec)
	legacy := collectPlanner(t, mdns.NewPlanner(), spec)

	if len(chain) != 2 {
		t.Fatalf("chain produced %d packets, want 2", len(chain))
	}
	// 响应标志 0x8400（QR=1 AA=1）。
	if chain[0].Payload[2] != 0x84 || chain[0].Payload[3] != 0x00 {
		t.Errorf("Payload[2:4] = %02x%02x, want 8400 (response)", chain[0].Payload[2], chain[0].Payload[3])
	}
	// 缓存刷新位：A 记录 CLASS 0x0001 | 0x8000 = 0x8001。
	if !bytes.Contains(chain[0].Payload, []byte{0x80, 0x01}) {
		t.Errorf("payload missing cache-flush class 0x8001")
	}
	for i := 0; i < 2; i++ {
		assertMDNSIdentical(t, chain[i], legacy[i], i)
	}
}

// TestChainPlanner_MDNS_Goodbye verifies goodbye mode forces TTL=0 on every
// record (RFC 6762 §10.1), byte-identical to legacy.
func TestChainPlanner_MDNS_Goodbye(t *testing.T) {
	spec := mdnsSpec()
	spec.MDNS = &core.MDNSConfig{
		Mode:    "goodbye",
		Answers: mdnsAnswers(),
	}
	chain := collectPlanner(t, layers.NewChainPlanner("mdns"), spec)
	legacy := collectPlanner(t, mdns.NewPlanner(), spec)

	if len(chain) != 1 {
		t.Fatalf("chain produced %d packets, want 1", len(chain))
	}
	// 任一 RR 的 TTL 字段（NAME 之后 TYPE(2)+CLASS(2)+TTL(4)）全 0。
	// 搜索 0x8001 CLASS 后 4 字节 TTL=00000000。
	payload := chain[0].Payload
	found := false
	for i := 0; i+7 < len(payload); i++ {
		if payload[i] == 0x80 && payload[i+1] == 0x01 {
			if payload[i+2] == 0 && payload[i+3] == 0 && payload[i+4] == 0 && payload[i+5] == 0 {
				found = true
				break
			}
		}
	}
	if !found {
		t.Errorf("payload missing TTL=0 record (goodbye)")
	}
	assertMDNSIdentical(t, chain[0], legacy[0], 0)
}

// TestChainPlanner_MDNS_IPv6 verifies the IPv6 multicast path: ff02::fb group
// + 33:33:00:00:00:fb MAC + 0x86DD EtherType, byte-identical to legacy.
func TestChainPlanner_MDNS_IPv6(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP:  "fe80::1234",
		DstIP:  "ff02::fb",
		SrcMAC: "02:00:00:00:00:01",
		DstMAC: "33:33:00:00:00:FB",
		MDNS: &core.MDNSConfig{
			Mode: "announce",
			Answers: []core.MDNSResourceRecord{
				{Name: "MyServer.local", Type: mdns.TypeAAAA, IPAddress: "fe80::1234", TTL: 4500},
			},
			AnnouncingRepeat: 1,
		},
	}
	chain := collectPlanner(t, layers.NewChainPlanner("mdns"), spec)
	legacy := collectPlanner(t, mdns.NewPlanner(), spec)

	if len(chain) != 1 {
		t.Fatalf("chain produced %d packets, want 1", len(chain))
	}
	if chain[0].L3.DstIP != mdns.MulticastIPv6 {
		t.Errorf("L3.DstIP = %q, want %q", chain[0].L3.DstIP, mdns.MulticastIPv6)
	}
	if chain[0].L2.DstMAC != "33:33:00:00:00:fb" {
		t.Errorf("L2.DstMAC = %q, want 33:33:00:00:00:fb", chain[0].L2.DstMAC)
	}
	if chain[0].L2.EtherType != 0x86DD {
		t.Errorf("EtherType = %04x, want 86DD (IPv6)", chain[0].L2.EtherType)
	}
	if chain[0].L3.TTL != 255 {
		t.Errorf("L3.TTL = %d, want 255", chain[0].L3.TTL)
	}
	// IPv6 多播 MAC 含 16 字节 AAAA RDATA（net.IP To16）。
	ip16 := []byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x12, 0x34}
	if !bytes.Contains(chain[0].Payload, ip16) {
		t.Errorf("AAAA RDATA not found in payload")
	}
	assertMDNSIdentical(t, chain[0], legacy[0], 0)
}

// TestChainPlanner_MDNS_ValidateNegative mirrors the legacy Validate contract:
// non-5353 ports, unknown mode, question-less query, answer-less response,
// jitter too large, TC on query must fail.
func TestChainPlanner_MDNS_ValidateNegative(t *testing.T) {
	p := layers.NewChainPlanner("mdns")

	spec := mdnsSpec()
	spec.SrcPort = 53
	if err := p.Validate(spec); err == nil {
		t.Error("Validate(src port 53) = nil, want error")
	}

	spec = mdnsSpec()
	spec.DstPort = 53
	if err := p.Validate(spec); err == nil {
		t.Error("Validate(dst port 53) = nil, want error")
	}

	spec = mdnsSpec()
	spec.MDNS.Mode = "bogus"
	if err := p.Validate(spec); err == nil {
		t.Error("Validate(unknown mode) = nil, want error")
	}

	spec = mdnsSpec()
	spec.MDNS.Questions = nil
	if err := p.Validate(spec); err == nil {
		t.Error("Validate(query without questions) = nil, want error")
	}

	spec = mdnsSpec()
	spec.MDNS.Mode = "response"
	spec.MDNS.Questions = nil
	spec.MDNS.Answers = nil
	if err := p.Validate(spec); err == nil {
		t.Error("Validate(response without answers) = nil, want error")
	}

	spec = mdnsSpec()
	spec.MDNS.ProbingJitterMax = 300
	if err := p.Validate(spec); err == nil {
		t.Error("Validate(jitter 300 > 250) = nil, want error")
	}

	spec = mdnsSpec()
	spec.MDNS.TC = true
	if err := p.Validate(spec); err == nil {
		t.Error("Validate(TC on query) = nil, want error")
	}

	spec = mdnsSpec()
	spec.MDNS.Answers = mdnsAnswers()
	spec.MDNS.Questions = nil
	spec.MDNS.Mode = "announce"
	spec.MDNS.TC = true
	if err := p.Validate(spec); err != nil {
		t.Errorf("Validate(TC on announce) = %v, want nil", err)
	}
}

// TestChainPlanner_MDNS_ValidateNilConfig verifies a spec with MDNS == nil is
// accepted (legacy Validate 同款：nil 配置走默认值)。
func TestChainPlanner_MDNS_ValidateNilConfig(t *testing.T) {
	p := layers.NewChainPlanner("mdns")
	spec := mdnsSpec()
	spec.MDNS = nil
	if err := p.Validate(spec); err != nil {
		t.Errorf("Validate(nil MDNS) = %v, want nil", err)
	}
}

// TestChainPlanner_MDNS_DefaultIPv6Group verifies the group auto-selection by
// source IP version when MulticastGroup is empty: IPv6 source → ff02::fb.
func TestChainPlanner_MDNS_DefaultIPv6Group(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP:  "fe80::1",
		DstIP:  "fe80::2",
		SrcMAC: "02:00:00:00:00:01",
		DstMAC: "11:22:33:44:55:66",
		MDNS: &core.MDNSConfig{
			Mode: "query",
			Questions: []core.MDNSQuestion{
				{Name: "srv.local", Type: mdns.TypeA},
			},
		},
	}
	chain := collectPlanner(t, layers.NewChainPlanner("mdns"), spec)
	if chain[0].L3.DstIP != mdns.MulticastIPv6 {
		t.Errorf("L3.DstIP = %q, want %q (default IPv6 group)", chain[0].L3.DstIP, mdns.MulticastIPv6)
	}
	if chain[0].L2.DstMAC != "33:33:00:00:00:fb" {
		t.Errorf("L2.DstMAC = %q, want 33:33:00:00:00:fb", chain[0].L2.DstMAC)
	}
}
