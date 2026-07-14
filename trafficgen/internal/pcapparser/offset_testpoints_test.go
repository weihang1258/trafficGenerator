package pcapparser

// Test points for offset.go, derived from tools/test_points/pcapparser.md
// (components O1). REAL tests exercising ExtractOffsetLayout directly.

import (
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Most offset tests are already in parser_test.go (TestExtractOffsetLayout,
// TestExtractOffsetLayout_VLAN, TestExtractOffsetLayout_ARP). This file covers
// remaining O1.4-O1.11 boundary cases.

// --- O1.4: ExtractOffset IPv6 ---

func TestExtractOffset_IPv6(t *testing.T) {
	ip6A := net.ParseIP("2001:db8::1")
	ip6B := net.ParseIP("2001:db8::2")
	frame := buildIPv6UDPFrame(t, macA, macB, ip6A, ip6B, 12345, 53, []byte("data"))
	pkt := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)
	layout := ExtractOffsetLayout(pkt)
	if layout.L3Start != 14 {
		t.Errorf("IPv6 L3Start = %d, want 14", layout.L3Start)
	}
	// IPv4 fields should be -1 (IPv6 has no IHL/SrcIP-at-12 layout).
	if layout.SrcIP != -1 || layout.DstIP != -1 {
		t.Errorf("IPv4 fields set in IPv6 packet: SrcIP=%d DstIP=%d", layout.SrcIP, layout.DstIP)
	}
	// UDP overrides the "ipv6" marker.
	if layout.L4Protocol != "udp" {
		t.Errorf("L4Protocol = %q, want udp (UDP overrides ipv6 marker)", layout.L4Protocol)
	}
}

// --- O1.5: ExtractOffset TCP (covered by TestExtractOffsetLayout) ---

// --- O1.6: ExtractOffset UDP ---

func TestExtractOffset_UDP(t *testing.T) {
	frame := buildUDPFrame(t, macA, macB, ipA, ipB, 2000, 53, []byte("data"))
	pkt := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)
	layout := ExtractOffsetLayout(pkt)
	if layout.L4Protocol != "udp" {
		t.Errorf("L4Protocol = %q, want udp", layout.L4Protocol)
	}
	// UDP ports at offset 34 (Eth14+IP20)
	if layout.SrcPort != 34 {
		t.Errorf("UDP SrcPort offset = %d, want 34", layout.SrcPort)
	}
	if layout.DstPort != 36 {
		t.Errorf("UDP DstPort offset = %d, want 36", layout.DstPort)
	}
}

// --- O1.7: ExtractOffset ICMPv4 ---

func TestExtractOffset_ICMPv4(t *testing.T) {
	buf := gopacket.NewSerializeBuffer()
	o := gopacket.SerializeOptions{FixLengths: true}
	icmp := &layers.ICMPv4{TypeCode: layers.CreateICMPv4TypeCode(8, 0), Id: 42}
	ipv4 := &layers.IPv4{SrcIP: ipA, DstIP: ipB, Version: 4, TTL: 64, Protocol: layers.IPProtocolICMPv4}
	gopacket.SerializeLayers(buf, o, &layers.Ethernet{SrcMAC: macA, DstMAC: macB, EthernetType: layers.EthernetTypeIPv4}, ipv4, icmp)
	pkt := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	layout := ExtractOffsetLayout(pkt)
	if layout.L4Protocol != "icmp" {
		t.Errorf("L4Protocol = %q, want icmp", layout.L4Protocol)
	}
	// L4Start should be 34 (Eth14+IP20)
	if layout.L4Start != 34 {
		t.Errorf("ICMP L4Start = %d, want 34", layout.L4Start)
	}
	// TCP fields should be -1 (no TCP).
	if layout.Seq != -1 || layout.Ack != -1 || layout.Window != -1 {
		t.Errorf("TCP fields set in ICMP packet: Seq=%d Ack=%d Window=%d", layout.Seq, layout.Ack, layout.Window)
	}
}

// --- O1.10: Multi-layer VLAN ---

func TestExtractOffset_MultiLayerVLAN(t *testing.T) {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	ipv4 := &layers.IPv4{SrcIP: ipA, DstIP: ipB, Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP}
	tcp := &layers.TCP{SrcPort: 1234, DstPort: 80, Seq: 1, Window: 65535, SYN: true}
	tcp.SetNetworkLayerForChecksum(ipv4)
	gopacket.SerializeLayers(buf, opts,
		&layers.Ethernet{SrcMAC: macA, DstMAC: macB, EthernetType: layers.EthernetTypeDot1Q},
		&layers.Dot1Q{VLANIdentifier: 100, Priority: 3, Type: layers.EthernetTypeIPv4},
		ipv4, tcp)
	pkt := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	layout := ExtractOffsetLayout(pkt)
	// VlanTCO at 14, L3Start at 18 (14+4), L4Start at 38 (18+20).
	if layout.VlanTCO != 14 {
		t.Errorf("VlanTCO = %d, want 14", layout.VlanTCO)
	}
	if layout.L3Start != 18 {
		t.Errorf("L3Start = %d, want 18 (shifted by VLAN)", layout.L3Start)
	}
	if layout.L4Start != 38 {
		t.Errorf("L4Start = %d, want 38", layout.L4Start)
	}
	if layout.SrcPort != 38 {
		t.Errorf("SrcPort = %d, want 38 (VLAN shifted)", layout.SrcPort)
	}
}

// --- O1.11: No layers (empty packet) ---

func TestExtractOffset_NoLayers(t *testing.T) {
	// A packet with no layers yields all -1.
	pkt := gopacket.NewPacket([]byte{}, layers.LayerTypeEthernet, gopacket.Default)
	layout := ExtractOffsetLayout(pkt)
	if layout.L2Start != 0 || layout.SrcMAC != -1 || layout.DstMAC != -1 {
		t.Errorf("empty-packet offsets: L2Start=%d SrcMAC=%d DstMAC=%d", layout.L2Start, layout.SrcMAC, layout.DstMAC)
	}
	if layout.L3Start != -1 || layout.L4Start != -1 {
		t.Errorf("empty-packet L3Start=%d L4Start=%d, want -1/-1", layout.L3Start, layout.L4Start)
	}
}