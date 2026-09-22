// 外部测试包：dns 链的字节级对比需要 legacy dns.NewPlanner 与 chain
// （internal/protocol/dns + internal/core/layers）。测试贴近真实调用方
// （main.go 的 layers.NewChainPlanner("dns")）。
package layers_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	"github.com/trafficgen/trafficgen/internal/protocol/dns"
)

// dnsSpec builds a minimal DNS flow spec (defaults: query type A,
// EDNS0 off, TxID 0x1234 by builder default).
func dnsSpec() core.FlowSpec {
	return core.FlowSpec{
		SrcIP:   "10.0.0.1",
		DstIP:   "10.0.0.2",
		SrcPort: 50000,
		DstPort: 53,
		SrcMAC:  "aa:bb:cc:dd:ee:ff",
		DstMAC:  "11:22:33:44:55:66",
		DNS: &core.DNSConfig{
			Domain:    "example.com",
			QueryType: 1, // A
		},
	}
}

// collect runs a planner's Plan and gathers all packets.
func collectPlanner(t *testing.T, p core.ProtocolPlanner, spec core.FlowSpec) []core.PacketConfig {
	t.Helper()
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var pkts []core.PacketConfig
	for c := range ch {
		pkts = append(pkts, c)
	}
	return pkts
}

// assertByteIdentical builds both packets and compares wire bytes.
// (maskRandomIPFields 在 chain_planner_udp_test.go 已声明，同包复用。)
func assertByteIdentical(t *testing.T, chain, legacy core.PacketConfig, idx int) {
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
	if !bytes.Equal(maskRandomIPFields(cb), maskRandomIPFields(lb)) {
		t.Errorf("packet %d bytes differ:\nchain  %x\nlegacy %x", idx, cb, lb)
	}
}

// TestChainPlanner_DNS_Query verifies the [ip→udp→dns] chain produces one up
// datagram carrying the DNS query, byte-identical to legacy dns.NewPlanner.
func TestChainPlanner_DNS_Query(t *testing.T) {
	spec := dnsSpec()
	chain := collectPlanner(t, layers.NewChainPlanner("dns"), spec)
	legacy := collectPlanner(t, dns.NewPlanner(), spec)

	if len(chain) != 1 {
		t.Fatalf("chain produced %d packets, want 1", len(chain))
	}
	if chain[0].Direction != "up" {
		t.Errorf("direction = %s, want up", chain[0].Direction)
	}
	if chain[0].L4.Protocol != "udp" || chain[0].L4.SrcPort != 50000 || chain[0].L4.DstPort != 53 {
		t.Errorf("L4 = %s %d/%d, want udp 50000/53", chain[0].L4.Protocol, chain[0].L4.SrcPort, chain[0].L4.DstPort)
	}
	if chain[0].L3.Protocol != core.ProtocolUDP {
		t.Errorf("L3.Protocol = %d, want %d (UDP 17)", chain[0].L3.Protocol, core.ProtocolUDP)
	}
	// Query header: 2-byte TxID 0x1234 + 2-byte flags 0x0100.
	if len(chain[0].Payload) < 12 || chain[0].Payload[0] != 0x12 || chain[0].Payload[1] != 0x34 {
		t.Errorf("payload header = %x, want TxID 0x1234", chain[0].Payload[:4])
	}
	assertByteIdentical(t, chain[0], legacy[0], 0)
}

// TestChainPlanner_DNS_QueryResponse verifies IsResponse=true adds the down
// datagram (swapped ports/MACs, server response), byte-identical to legacy.
func TestChainPlanner_DNS_QueryResponse(t *testing.T) {
	spec := dnsSpec()
	spec.DNS.IsResponse = true
	spec.DNS.ResponseIP = "93.184.216.34"
	chain := collectPlanner(t, layers.NewChainPlanner("dns"), spec)
	legacy := collectPlanner(t, dns.NewPlanner(), spec)

	if len(chain) != 2 {
		t.Fatalf("chain produced %d packets, want 2", len(chain))
	}
	if chain[0].Direction != "up" || chain[1].Direction != "down" {
		t.Errorf("directions = %s/%s, want up/down", chain[0].Direction, chain[1].Direction)
	}
	if chain[1].L4.SrcPort != 53 || chain[1].L4.DstPort != 50000 {
		t.Errorf("response ports = %d/%d, want 53/50000", chain[1].L4.SrcPort, chain[1].L4.DstPort)
	}
	if chain[1].L2.SrcMAC != "11:22:33:44:55:66" || chain[1].L2.DstMAC != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("response MACs = %s→%s, want swapped", chain[1].L2.SrcMAC, chain[1].L2.DstMAC)
	}
	for i := 0; i < 2; i++ {
		assertByteIdentical(t, chain[i], legacy[i], i)
	}
}

// TestChainPlanner_DNS_DefaultPorts verifies the chain defaults dst port to
// 53 (legacy Plan 语义) when the spec omits it, so a minimal spec works.
func TestChainPlanner_DNS_DefaultPorts(t *testing.T) {
	spec := dnsSpec()
	spec.DstPort = 0
	chain := collectPlanner(t, layers.NewChainPlanner("dns"), spec)
	legacy := collectPlanner(t, dns.NewPlanner(), spec)

	if len(chain) != 1 {
		t.Fatalf("chain produced %d packets, want 1", len(chain))
	}
	if chain[0].L4.DstPort != 53 {
		t.Errorf("dst port = %d, want 53 (defaulted)", chain[0].L4.DstPort)
	}
	assertByteIdentical(t, chain[0], legacy[0], 0)
}

// TestChainPlanner_DNS_MultiQuestion verifies the multi-question path
// (buildDNSMessage) flows through the chain and matches legacy bytes.
func TestChainPlanner_DNS_MultiQuestion(t *testing.T) {
	spec := dnsSpec()
	spec.DNS = &core.DNSConfig{
		Questions: []core.DNSQuestion{
			{Name: "example.com", Type: 1},  // A, class defaults IN
			{Name: "example.com", Type: 28}, // AAAA
			{Name: "www.example.com", Type: 1},
		},
		IsResponse: true,
	}
	chain := collectPlanner(t, layers.NewChainPlanner("dns"), spec)
	legacy := collectPlanner(t, dns.NewPlanner(), spec)

	if len(chain) != 2 {
		t.Fatalf("chain produced %d packets, want 2", len(chain))
	}
	// QDCOUNT = 3 at offset 4-5.
	if qd := uint16(chain[0].Payload[4])<<8 | uint16(chain[0].Payload[5]); qd != 3 {
		t.Errorf("QDCOUNT = %d, want 3", qd)
	}
	for i := 0; i < 2; i++ {
		assertByteIdentical(t, chain[i], legacy[i], i)
	}
}

// TestChainPlanner_DNS_EDNS0 verifies EDNS0 (OPT RR) flows through the chain
// and matches legacy bytes.
func TestChainPlanner_DNS_EDNS0(t *testing.T) {
	spec := dnsSpec()
	spec.DNS.EDNS0Enabled = true
	spec.DNS.UDPPayloadSize = 4096
	spec.DNS.DnssecOK = true
	chain := collectPlanner(t, layers.NewChainPlanner("dns"), spec)
	legacy := collectPlanner(t, dns.NewPlanner(), spec)

	if len(chain) != 1 {
		t.Fatalf("chain produced %d packets, want 1", len(chain))
	}
	// ARCOUNT = 1 at offset 10-11 (OPT pseudo-RR).
	if ar := uint16(chain[0].Payload[10])<<8 | uint16(chain[0].Payload[11]); ar != 1 {
		t.Errorf("ARCOUNT = %d, want 1 (EDNS0 OPT)", ar)
	}
	assertByteIdentical(t, chain[0], legacy[0], 0)
}

// TestChainPlanner_DNS_GeneralResponse verifies the multi-answer response
// path (buildDNSResponseGeneral) matches legacy bytes.
func TestChainPlanner_DNS_GeneralResponse(t *testing.T) {
	spec := dnsSpec()
	spec.DNS.IsResponse = true
	spec.DNS.Answers = []core.DNSRR{
		{Name: "example.com", Type: 1, IP: "93.184.216.34"},
		{Name: "example.com", Type: 1, IP: "93.184.216.35"},
	}
	spec.DNS.RCode = 0
	chain := collectPlanner(t, layers.NewChainPlanner("dns"), spec)
	legacy := collectPlanner(t, dns.NewPlanner(), spec)

	if len(chain) != 2 {
		t.Fatalf("chain produced %d packets, want 2", len(chain))
	}
	// ANCOUNT = 2 at offset 6-7.
	if an := uint16(chain[1].Payload[6])<<8 | uint16(chain[1].Payload[7]); an != 2 {
		t.Errorf("ANCOUNT = %d, want 2", an)
	}
	for i := 0; i < 2; i++ {
		assertByteIdentical(t, chain[i], legacy[i], i)
	}
}

// TestChainPlanner_DNS_TCPVariantRejected verifies the TCP carriage is
// deferred: a spec with Transport=="tcp" must fail loudly (wire semantics
// differ from legacy — full handshake vs bare PSH+ACK), not silently
// produce divergent packets.
func TestChainPlanner_DNS_TCPVariantRejected(t *testing.T) {
	spec := dnsSpec()
	spec.DNS.Transport = "tcp"
	_, err := layers.NewChainPlanner("dns").Plan(context.Background(), spec)
	if err == nil {
		t.Fatal("Plan(tcp carriage) = nil err, want explicit rejection")
	}
}

// TestChainPlanner_DNS_ValidateNegative mirrors the legacy Validate contract:
// empty domain and nil DNS config must both fail.
func TestChainPlanner_DNS_ValidateNegative(t *testing.T) {
	p := layers.NewChainPlanner("dns")

	spec := dnsSpec()
	spec.DNS = nil
	if err := p.Validate(spec); err == nil {
		t.Error("Validate(nil DNS config) = nil, want error")
	}

	spec = dnsSpec()
	spec.DNS.Domain = ""
	if err := p.Validate(spec); err == nil {
		t.Error("Validate(empty domain) = nil, want error")
	}

	spec = dnsSpec()
	spec.DNS.Transport = "sctp"
	if err := p.Validate(spec); err == nil {
		t.Error("Validate(bad transport) = nil, want error")
	}
}
