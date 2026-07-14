package replay

import (
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/pcapparser"
	"github.com/trafficgen/trafficgen/internal/storage"
)

// testLayout builds a standard Eth+IPv4+TCP frame and returns its layout.
func testLayout(t *testing.T) pcapparser.OffsetLayout {
	t.Helper()
	macA, _ := net.ParseMAC("aa:aa:aa:aa:aa:aa")
	macB, _ := net.ParseMAC("bb:bb:bb:bb:bb:bb")
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	tcp := &layers.TCP{SrcPort: 1234, DstPort: 80, Seq: 1, SYN: true}
	ipv4 := &layers.IPv4{SrcIP: net.ParseIP("10.0.0.1"), DstIP: net.ParseIP("10.0.0.2"), Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP}
	tcp.SetNetworkLayerForChecksum(ipv4)
	gopacket.SerializeLayers(buf, opts, &layers.Ethernet{SrcMAC: macA, DstMAC: macB, EthernetType: layers.EthernetTypeIPv4}, ipv4, tcp)
	pkt := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	return pcapparser.ExtractOffsetLayout(pkt)
}

func testFlow() storage.FlowModel {
	return storage.FlowModel{
		ID:         "f1",
		L4Protocol: "tcp",
		SrcIP:      "10.0.0.1",
		SrcPort:    1234,
		DstIP:      "10.0.0.2",
		DstPort:    80,
	}
}

// TestMatchRule_Bidirectional verifies a matcher hits both directions.
func TestMatchRule_Bidirectional(t *testing.T) {
	f := testFlow()
	// Forward.
	if !matchRule(FlowMatcher{Protocol: "tcp", SrcIP: "10.0.0.1", DstIP: "10.0.0.2"}, f) {
		t.Error("forward match failed")
	}
	// Reverse (matcher's src/dst swapped) should also match (bidirectional).
	if !matchRule(FlowMatcher{Protocol: "tcp", SrcIP: "10.0.0.2", DstIP: "10.0.0.1"}, f) {
		t.Error("reverse match failed (should be bidirectional)")
	}
	// Different IP pair -> no match.
	if matchRule(FlowMatcher{SrcIP: "10.0.0.1", DstIP: "10.0.0.3"}, f) {
		t.Error("non-matching pair matched")
	}
	// Protocol filter.
	if matchRule(FlowMatcher{Protocol: "udp"}, f) {
		t.Error("udp matcher matched tcp flow")
	}
}

// TestComputeFlowPatches_FieldRule verifies a field rule generates a patch at
// the right offset.
func TestComputeFlowPatches_FieldRule(t *testing.T) {
	layout := testLayout(t)
	f := testFlow()
	rules := []RewriteRule{{
		Kind: "field", Target: "src_ip", Apply: "set",
		Strategy: core.StrategyConfig{Strategy: "fixed", Value: "11.0.0.1"},
	}}
	patches, err := computeFlowPatches(f, layout, rules)
	if err != nil {
		t.Fatalf("computeFlowPatches: %v", err)
	}
	if len(patches) != 1 {
		t.Fatalf("patches = %d, want 1", len(patches))
	}
	p := patches[0]
	if p.Offset != layout.SrcIP {
		t.Errorf("patch offset = %d, want %d (SrcIP)", p.Offset, layout.SrcIP)
	}
	want := net.ParseIP("11.0.0.1").To4()
	if string(p.Bytes) != string(want) {
		t.Errorf("patch bytes = %v, want %v", p.Bytes, want)
	}
	if p.Layer != "l3" {
		t.Errorf("patch layer = %q, want l3", p.Layer)
	}
}

// TestComputeFlowPatches_IPMap verifies an ipmap rule patches matching IPs.
func TestComputeFlowPatches_IPMap(t *testing.T) {
	layout := testLayout(t)
	f := testFlow()
	rules := []RewriteRule{{
		Kind: "ipmap", Mapping: map[string]string{"10.0.0.1": "11.0.0.1", "10.0.0.2": "11.0.0.2"},
	}}
	patches, err := computeFlowPatches(f, layout, rules)
	if err != nil {
		t.Fatalf("computeFlowPatches: %v", err)
	}
	if len(patches) != 2 {
		t.Fatalf("patches = %d, want 2 (both IPs mapped)", len(patches))
	}
}

// TestComputeFlowPatches_Conflict verifies two rules setting the same field to
// different values error.
func TestComputeFlowPatches_Conflict(t *testing.T) {
	layout := testLayout(t)
	f := testFlow()
	rules := []RewriteRule{
		{Kind: "field", Target: "src_ip", Apply: "set", Strategy: core.StrategyConfig{Strategy: "fixed", Value: "11.0.0.1"}},
		{Kind: "field", Target: "src_ip", Apply: "set", Strategy: core.StrategyConfig{Strategy: "fixed", Value: "12.0.0.1"}},
	}
	_, err := computeFlowPatches(f, layout, rules)
	if err == nil {
		t.Error("expected conflict error, got nil")
	}
}

// TestComputeFlowPatches_Idempotent verifies two rules setting the same field
// to the SAME value are allowed (idempotent).
func TestComputeFlowPatches_Idempotent(t *testing.T) {
	layout := testLayout(t)
	f := testFlow()
	rules := []RewriteRule{
		{Kind: "field", Target: "ttl", Apply: "set", Strategy: core.StrategyConfig{Strategy: "fixed", Value: "128"}},
		{Kind: "field", Target: "ttl", Apply: "set", Strategy: core.StrategyConfig{Strategy: "fixed", Value: "128"}},
	}
	patches, err := computeFlowPatches(f, layout, rules)
	if err != nil {
		t.Fatalf("idempotent rules should not error: %v", err)
	}
	if len(patches) != 1 {
		t.Errorf("idempotent patches = %d, want 1", len(patches))
	}
}

// TestEndpointPatch verifies client_ip patches src on c2s and dst on s2c.
func TestEndpointPatch(t *testing.T) {
	layout := testLayout(t)
	newIP := net.ParseIP("11.0.0.1")
	// c2s: client is src -> patch SrcIP.
	p, err := endpointPatch("c2s", "client_ip", newIP, layout)
	if err != nil {
		t.Fatalf("c2s endpointPatch: %v", err)
	}
	if p.Offset != layout.SrcIP {
		t.Errorf("c2s client_ip offset = %d, want %d (SrcIP)", p.Offset, layout.SrcIP)
	}
	// s2c: client is dst -> patch DstIP.
	p, err = endpointPatch("s2c", "client_ip", newIP, layout)
	if err != nil {
		t.Fatalf("s2c endpointPatch: %v", err)
	}
	if p.Offset != layout.DstIP {
		t.Errorf("s2c client_ip offset = %d, want %d (DstIP)", p.Offset, layout.DstIP)
	}
	// server_ip: c2s patches DstIP (server is dst).
	p, _ = endpointPatch("c2s", "server_ip", newIP, layout)
	if p.Offset != layout.DstIP {
		t.Errorf("c2s server_ip offset = %d, want %d (DstIP)", p.Offset, layout.DstIP)
	}
}

// TestMatchRule_CIDR verifies a CIDR matcher matches flows in the subnet.
func TestMatchRule_CIDR(t *testing.T) {
	f := testFlow()
	if !matchRule(FlowMatcher{SrcIP: "10.0.0.0/8"}, f) {
		t.Error("10.0.0.0/8 should match 10.0.0.1")
	}
	if matchRule(FlowMatcher{SrcIP: "192.168.0.0/16"}, f) {
		t.Error("192.168.0.0/16 should NOT match 10.0.0.1")
	}
	if !matchRule(FlowMatcher{SrcIP: "10.0.0.1"}, f) {
		t.Error("exact IP match failed")
	}
}

// TestComputeFlowPatches_DSCP_ECN_Conflict verifies dscp+ecn on same byte conflict.
func TestComputeFlowPatches_DSCP_ECN_Merge(t *testing.T) {
	layout := testLayout(t)
	f := testFlow()
	rules := []RewriteRule{
		{Kind: "field", Target: "dscp", Apply: "set", Strategy: core.StrategyConfig{Strategy: "fixed", Value: "32"}},
		{Kind: "field", Target: "ecn", Apply: "set", Strategy: core.StrategyConfig{Strategy: "fixed", Value: "3"}},
	}
	patches, err := computeFlowPatches(f, layout, rules)
	if err != nil {
		t.Fatalf("dscp+ecn should merge, not conflict: %v", err)
	}
	if len(patches) != 1 {
		t.Fatalf("patches = %d, want 1 (merged TOS byte)", len(patches))
	}
	// DSCP=32 (0x80) + ECN=3 (0x03) = 0x83
	if len(patches[0].Bytes) != 1 || patches[0].Bytes[0] != 0x83 {
		t.Errorf("merged TOS byte = 0x%x, want 0x83", patches[0].Bytes[0])
	}
}

// TestComputeFlowPatches_DSCP_ECN_Idempotent verifies dscp+ecn same value is ok.
func TestComputeFlowPatches_DSCP_ECN_Idempotent(t *testing.T) {
	layout := testLayout(t)
	f := testFlow()
	rules := []RewriteRule{
		{Kind: "field", Target: "dscp", Apply: "set", Strategy: core.StrategyConfig{Strategy: "fixed", Value: "0"}},
		{Kind: "field", Target: "ecn", Apply: "set", Strategy: core.StrategyConfig{Strategy: "fixed", Value: "0"}},
	}
	patches, err := computeFlowPatches(f, layout, rules)
	if err != nil {
		t.Fatalf("same value should be idempotent: %v", err)
	}
	if len(patches) != 1 {
		t.Errorf("patches = %d, want 1 (only one TOS byte)", len(patches))
	}
}
