package pcapparser

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// OffsetLayout records the byte offsets of patchable fields within a flow's
// packets (§9). It relies on the encapsulation-constant principle: all packets
// in a flow share the same L2/L3/L4 header structure, so field offsets are
// constant across the flow (only payload length varies). Stored per-flow as
// JSON in FlowModel.OffsetLayout; consumed by the replay rewriter for byte
// patching without re-parsing.
//
// Offsets are absolute byte positions within the frame. A value of -1 means
// the field is absent (e.g. no VLAN, or L4 fields for a non-TCP flow).
type OffsetLayout struct {
	L2Start int `json:"l2_start"`
	L3Start int `json:"l3_start"`
	L4Start int `json:"l4_start"`

	SrcMAC int `json:"src_mac"`
	DstMAC int `json:"dst_mac"`
	VlanTCO int `json:"vlan_tco"` // VLAN TCI (priority+ID), -1 if no VLAN

	SrcIP     int `json:"src_ip"`
	DstIP     int `json:"dst_ip"`
	TTL       int `json:"ttl"`
	DSCPECN   int `json:"dscp_ecn"` // TOS byte
	IPFlagsFrag int `json:"ip_flags_frag"`
	IPID      int `json:"ip_id"`

	SrcPort int `json:"src_port"`
	DstPort int `json:"dst_port"`
	Seq     int `json:"seq"`       // TCP
	Ack     int `json:"ack"`       // TCP
	Window  int `json:"window"`    // TCP
	TCPFlags int `json:"tcp_flags"` // TCP

	L4Protocol string `json:"l4_protocol"` // tcp|udp|icmp|arp|""

	// Variants holds alternate layouts for flows whose encapsulation changes
	// mid-flow (e.g. some packets carry VLAN, others don't). Populated in P5
	// (fragment/variant handling); v1 uses a single layout per flow.
	Variants []OffsetVariant `json:"variants,omitempty"`
}

// OffsetVariant is an alternate OffsetLayout for packets in a flow with a
// different encapsulation (e.g. VLAN-bearing vs not). Each PacketModel records
// which variant applies. Stub for P5.
type OffsetVariant struct {
	Tag      string `json:"tag"`       // e.g. "vlan", "non-first-frag"
	OffsetLayout
}

// newOffsetLayout returns an OffsetLayout with all field offsets set to -1
// (absent) so that only fields actually present in the packet are set.
func newOffsetLayout() OffsetLayout {
	return OffsetLayout{
		SrcMAC: -1, DstMAC: -1, VlanTCO: -1,
		SrcIP: -1, DstIP: -1, TTL: -1, DSCPECN: -1, IPFlagsFrag: -1, IPID: -1,
		SrcPort: -1, DstPort: -1, Seq: -1, Ack: -1, Window: -1, TCPFlags: -1,
		L3Start: -1, L4Start: -1,
	}
}

// extractOffsetLayout walks a packet's layers and records the byte offset of
// each patchable field. Layers are contiguous (Contents followed by Payload),
// so a running offset accumulated from len(LayerContents) gives each layer's
// start. The first packet of a flow defines the layout (encapsulation-constant).
func ExtractOffsetLayout(pkt gopacket.Packet) OffsetLayout {
	layout := newOffsetLayout()
	offset := 0
	for _, layer := range pkt.Layers() {
		start := offset
		contents := layer.LayerContents()
		switch layer.(type) {
		case *layers.Ethernet:
			layout.L2Start = start
			layout.DstMAC = start + 0
			layout.SrcMAC = start + 6
		case *layers.Dot1Q:
			// Dot1Q Contents = TCI(2) + inner EtherType(2). TCI holds priority
			// + VLAN ID -- the patchable field.
			layout.VlanTCO = start + 0
		case *layers.IPv4:
			layout.L3Start = start
			layout.SrcIP = start + 12
			layout.DstIP = start + 16
			layout.TTL = start + 8
			layout.DSCPECN = start + 1
			layout.IPFlagsFrag = start + 6
			layout.IPID = start + 4
		case *layers.IPv6:
			layout.L3Start = start
			layout.L4Protocol = "ipv6" // marker; v1 replay IPv6 address rewrite is v2
		case *layers.TCP:
			layout.L4Start = start
			layout.L4Protocol = "tcp"
			layout.SrcPort = start + 0
			layout.DstPort = start + 2
			layout.Seq = start + 4
			layout.Ack = start + 8
			layout.Window = start + 14
			layout.TCPFlags = start + 13
		case *layers.UDP:
			layout.L4Start = start
			layout.L4Protocol = "udp"
			layout.SrcPort = start + 0
			layout.DstPort = start + 2
		case *layers.ICMPv4:
			layout.L4Start = start
			layout.L4Protocol = "icmp"
		case *layers.ARP:
			layout.L4Start = start
			layout.L4Protocol = "arp"
		}
		offset += len(contents)
	}
	return layout
}
