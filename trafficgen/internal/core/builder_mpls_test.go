package core

import (
	"bytes"
	"encoding/binary"
	"net"
	"strings"
	"testing"
)

// Reference bytes are taken from real captured MPLS traffic (verified with
// tshark -r <file> -x / -V):
//
//	/home/pcap_auto/mypcap/idc3/3.mpls2.5_sample.pcap  frame 1: single
//	  label (16, TC 6, S 1, TTL 255) + IPv4/UDP LDP Hello (EtherType 0x8847)
//	/home/pcap_auto/mypcap/idc3/7、mpls_http.pcap   frame 1: TWO labels
//	  (586, 2859, both TTL 255) + inner IPv4/TCP SYN (EtherType 0x8847).
//	  NOTE: the pcap carries Ethernet-over-MPLS (PW control word + inner
//	  Ethernet header, a pseudowire) after the label stack — the builder
//	  emits the label stack + inner L3 directly, so this test asserts the
//	  pcap's outer Ethernet + label stack (bytes 0-21) and its inner
//	  IPv4/TCP (pcap bytes 40-87) verbatim.
//	/home/pcap_auto/mypcap/idc3/8、mpls_icmp.pcapng frame 1: VLAN(146) +
//	  single label (16, TC 6, S 1, TTL 255) + IPv4/ICMP time-exceeded
//	  (EtherType 0x8847 after the 0x8100 VLAN tag)
//
// pcap gotcha (MPLS LDP frame): 3.mpls2.5_sample.pcap was MAC-anonymized
// (aa:bb:cc:00:xx:xx addresses) and the anonymizer recomputed the IP
// checksum but NOT the UDP checksum — the captured UDP checksum 0x05ce is
// stale (independent RFC 768 recomputation over pseudo-header + zeroed
// checksum field yields 0xe5cd). The tests assert the correct value 0xe5cd
// and the pcap's (valid) IP checksum 0xa55b.

// TestBuilder_MPLS_SingleLabel_PcapBytes reproduces pcap
// 3.mpls2.5_sample.pcap frame 1 byte-for-byte (80 bytes, no padding):
//
//	aa bb cc 00 ca 02 | aa bb cc 00 cb 01 | 88 47 |
//	00 01 0d ff |   <- MPLS: label 16, TC 6, S 1, TTL 255
//	45 c0 00 3e 00 00 00 00 ff 11 a5 5b 0a 00 00 cb 0a 00 00 c9 |
//	02 86 02 86 00 2a e5 cd | <34-byte LDP Hello payload>
//
// Covers (RFC 3032 §3.1/§3.10): the forced unicast EtherType 0x8847, the
// 4-byte label entry layout ((label<<12)|(tc<<9)|(s<<8)|ttl = 0x00010dff),
// and the inner IPv4/UDP written normally after the stack (IP total length
// 62 = 20 + 8 + 34 — the label stack is NOT counted, it precedes the IP
// header). The outer IP checksum (0xa55b, valid in the pcap) and the UDP
// checksum (0xe5cd — the pcap's 0x05ce is stale, see header comment) must
// match.
func TestBuilder_MPLS_SingleLabel_PcapBytes(t *testing.T) {
	builder := NewBuilder()

	// LDP Hello payload, pcap frame 1 bytes verbatim (34 bytes; the pcap
	// was MAC-anonymized, so the exact LDP field alignment is not
	// guaranteed — the test only needs the raw bytes).
	ldpHello := []byte{
		0x00, 0x01, 0x00, 0x1e,
		0x0a, 0x00, 0x00, 0xcb,
		0x00, 0x00, 0x01, 0x00,
		0x00, 0x14, 0x00, 0x00,
		0x00, 0x00, 0x04, 0x00,
		0x00, 0x04, 0x00, 0x5a,
		0xe0, 0x00, 0x04, 0x01,
		0x00, 0x04, 0x0a, 0x00,
		0x00, 0xcb,
	}
	if len(ldpHello) != 34 {
		t.Fatalf("LDP Hello length = %d, want 34", len(ldpHello))
	}

	config := PacketConfig{
		L2: L2Config{
			SrcMAC: "aa:bb:cc:00:cb:01",
			DstMAC: "aa:bb:cc:00:ca:02",
			MPLS: &MPLSConfig{
				Labels: []MPLSLabel{
					{Label: 16, TC: 6, S: true, TTL: 255}, // pcap: label 16, TC 6, S 1, TTL 255
				},
			},
		},
		L3: L3Config{
			SrcIP:    "10.0.0.203",
			DstIP:    "10.0.0.201",
			Protocol: 17, // UDP
			TTL:      255,
			IPID:     0,
			Flags:    0,  // pcap carries flags/frag 0x0000 (no DF)
			DSCP:     48, // pcap TOS 0xc0 = DSCP CS6
			ECN:      0,
		},
		L4: L4Config{
			Protocol: "udp",
			SrcPort:  646,
			DstPort:  646,
		},
		Payload: ldpHello,
	}

	packet, err := builder.Build(config)
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	want := []byte{
		0xaa, 0xbb, 0xcc, 0x00, 0xca, 0x02, // dst MAC
		0xaa, 0xbb, 0xcc, 0x00, 0xcb, 0x01, // src MAC
		0x88, 0x47, // EtherType = MPLS unicast (0x8847)
		0x00, 0x01, 0x0d, 0xff, // MPLS: label 16, TC 6, S 1, TTL 255
		0x45, 0xc0, // version 4, IHL 5, TOS 0xc0
		0x00, 0x3e, // total length 62 = 20 IP + 8 UDP + 34 LDP (no MPLS)
		0x00, 0x00, // IPID 0
		0x00, 0x00, // flags 0, frag offset 0
		0xff,       // TTL 255
		0x11,       // protocol 17 (UDP)
		0xa5, 0x5b, // header checksum (pcap-valid)
		0x0a, 0x00, 0x00, 0xcb, // src 10.0.0.203
		0x0a, 0x00, 0x00, 0xc9, // dst 10.0.0.201
		0x02, 0x86, 0x02, 0x86, // UDP 646 -> 646
		0x00, 0x2a, // UDP length 42
		0xe5, 0xcd, // UDP checksum (independent recomputation; pcap 0x05ce is stale)
	}
	want = append(want, ldpHello...)

	if len(packet) != len(want) {
		t.Fatalf("len(packet) = %d, want %d", len(packet), len(want))
	}
	if !bytes.Equal(packet, want) {
		t.Errorf("packet mismatch:\n got % x\nwant % x", packet, want)
	}
}

// TestBuilder_MPLS_MultiLabel_PcapBytes reproduces pcap 7、mpls_http.pcap
// frame 1's outer layer byte-for-byte: the Ethernet header + TWO-label MPLS
// stack (RFC 3032 §3.1: top entry 586 with S=0, bottom entry 2859 with
// S=1, both TTL 255), then the pcap's inner IPv4/TCP SYN (bytes 40-87 of
// the capture — the pcap carries a PW control word + inner Ethernet header
// between the stack and the IP packet, which the builder does not emit)
// written as a normal L3/L4 by the builder:
//
//	00 22 56 cc 2c ec | 00 22 56 cd ce 92 | 88 47 |
//	00 24 a0 ff | 00 b2 b1 ff |  <- labels 586 (S 0), 2859 (S 1), TTL 255
//	45 00 00 30 0f f8 40 00 7f 06 ff e1 ac 10 00 b3 d1 7b 6d af |
//	07 89 00 50 de 82 dd 1e 00 00 00 00 70 02 ff ff d4 7e 00 00 |
//	02 04 04 ec 01 01 04 02   <- MSS 1260, NOP, SACK-permitted (+pad NOP)
//
// Covers the multi-entry stack: S=0 on the non-bottom entry, S=1 on the
// bottom, both entries written top-of-stack first. The inner IP checksum
// (0xffe1) and TCP checksum (0xd47e) are the pcap's values — both verified
// valid by independent recomputation.
func TestBuilder_MPLS_MultiLabel_PcapBytes(t *testing.T) {
	builder := NewBuilder()

	config := PacketConfig{
		L2: L2Config{
			SrcMAC: "00:22:56:cd:ce:92",
			DstMAC: "00:22:56:cc:2c:ec",
			MPLS: &MPLSConfig{
				Labels: []MPLSLabel{
					{Label: 586, TC: 0, S: false, TTL: 255}, // top, S=0
					{Label: 2859, TC: 0, S: true, TTL: 255}, // bottom, S=1
				},
			},
		},
		L3: L3Config{
			SrcIP:    "172.16.0.179",
			DstIP:    "209.123.109.175",
			Protocol: 6, // TCP
			TTL:      127,
			IPID:     0x0ff8,
			Flags:    IPFlagDF,
		},
		L4: L4Config{
			Protocol:   "tcp",
			SrcPort:    1929,
			DstPort:    80,
			Seq:        0xde82dd1e,
			Flags:      0x02, // SYN
			WindowSize: 0xffff,
			TCPOptions: []TCPOption{
				{Kind: 2, Data: []byte{0x04, 0xec}}, // MSS 1260
				{Kind: TCPOptNOP},
				{Kind: TCPOptNOP},
				{Kind: 4}, // SACK-permitted
			},
		},
	}

	packet, err := builder.Build(config)
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	want := []byte{
		0x00, 0x22, 0x56, 0xcc, 0x2c, 0xec, // dst MAC
		0x00, 0x22, 0x56, 0xcd, 0xce, 0x92, // src MAC
		0x88, 0x47, // EtherType = MPLS unicast (0x8847)
		0x00, 0x24, 0xa0, 0xff, // MPLS top: label 586, TC 0, S 0, TTL 255
		0x00, 0xb2, 0xb1, 0xff, // MPLS bottom: label 2859, TC 0, S 1, TTL 255
		0x45, 0x00, // version 4, IHL 5, TOS 0
		0x00, 0x30, // total length 48 = 20 IP + 28 TCP (no MPLS)
		0x0f, 0xf8, // IPID 0x0ff8 (pcap)
		0x40, 0x00, // flags DF, frag offset 0 (pcap)
		0x7f,       // TTL 127 (pcap)
		0x06,       // protocol 6 (TCP)
		0xff, 0xe1, // header checksum (pcap-valid)
		0xac, 0x10, 0x00, 0xb3, // src 172.16.0.179
		0xd1, 0x7b, 0x6d, 0xaf, // dst 209.123.109.175
		0x07, 0x89, 0x00, 0x50, // TCP 1929 -> 80
		0xde, 0x82, 0xdd, 0x1e, // seq (pcap)
		0x00, 0x00, 0x00, 0x00, // ack 0
		0x70, 0x02, // data offset 28, flags SYN
		0xff, 0xff, // window 65535 (pcap)
		0xd4, 0x7e, // checksum (pcap-valid)
		0x00, 0x00, // urgent pointer
		0x02, 0x04, 0x04, 0xec, // MSS 1260
		0x01, 0x01, // NOP, NOP (pcap)
		0x04, 0x02, // SACK-permitted
	}

	if len(packet) != len(want) {
		t.Fatalf("len(packet) = %d, want %d", len(packet), len(want))
	}
	if !bytes.Equal(packet, want) {
		t.Errorf("packet mismatch:\n got % x\nwant % x", packet, want)
	}
}

// TestBuilder_MPLS_VLAN_PcapBytes reproduces pcap 8、mpls_icmp.pcapng frame
// 1 byte-for-byte (194 bytes): an 802.1Q VLAN tag (ID 146, priority 0)
// between the Ethernet header and the MPLS label stack, then the label
// (16, TC 6, S 1, TTL 255), then the outer IPv4 header and the full
// 152-byte ICMP time-exceeded message (type 11, checksum 0x5ad2 — verified
// valid over the whole message) with its embedded IPv4/UDP packet and the
// RFC 4950 MPLS-in-ICMP extension:
//
//	aa bb cc 00 04 00 | aa bb cc 00 05 00 | 81 00 00 92 | 88 47 |
//	00 01 0d ff |
//	45 c0 00 ac 1e 68 00 00 ff 01 36 1a 9b 01 2d 04 96 01 08 08 |
//	<152-byte ICMP time-exceeded message>
//
// Covers the VLAN+MPLS offset combination: the label stack sits at frame
// offset 18 (14 Ethernet + 4 VLAN), the forced EtherType 0x8847 is written
// at 16:18 (after the 0x8100 TPID + tag), the IP total length 0x00ac = 20 +
// 152 counts the ICMP message but not the stack, and the outer IP checksum
// 0x361a (pcap-valid) is computed by the builder. ICMP has no L4 header —
// the message is carried in Payload.
func TestBuilder_MPLS_VLAN_PcapBytes(t *testing.T) {
	builder := NewBuilder()

	// ICMP time-exceeded (RFC 792 type 11) carrying the offending packet
	// + RFC 4950 MPLS extension, pcap frame 1 payload verbatim.
	icmpMsg := []byte{
		0x0b, 0x00, 0x5a, 0xd2, 0x00, 0x00, 0x00, 0x00, // type 11, code 0, checksum 0x5ad2, unused
		// Embedded IPv4/UDP probe (150.1.8.8 -> 192.168.7.7), checksum 0x516f
		0x45, 0x00, 0x00, 0x1c, 0x02, 0xaa, 0x00, 0x00, 0x01, 0x11, 0x51, 0x6f,
		0x96, 0x01, 0x08, 0x08, 0xc0, 0xa8, 0x07, 0x07,
		// Embedded UDP: 49159 -> 33439, len 8, checksum 0x577e, payload 00 00
		0xc0, 0x07, 0x82, 0x9f, 0x00, 0x08, 0x57, 0x7e, 0x00, 0x00,
	}
	// 98 zero bytes (the captured message's padding), then the RFC 4950
	// MPLS label stack object (class 1, C-type 1, MPLS stack entry
	// 0x2000cdee + TLV list) — pcap bytes verbatim.
	icmpMsg = append(icmpMsg, make([]byte, 98)...)
	icmpMsg = append(icmpMsg,
		0x20, 0x00, 0xcd, 0xee, // MPLS stack entry: label 3294, TC 0, S 0, TTL 238
		0x00, 0x0c, 0x01, 0x01, 0x00, 0x01, 0x10, 0x01, 0x00, 0x01, 0x01, 0x01,
	)
	if len(icmpMsg) != 152 {
		t.Fatalf("ICMP message length = %d, want 152", len(icmpMsg))
	}

	config := PacketConfig{
		L2: L2Config{
			SrcMAC: "aa:bb:cc:00:05:00",
			DstMAC: "aa:bb:cc:00:04:00",
			VLAN:   &VLAN{ID: 146},
			MPLS: &MPLSConfig{
				Labels: []MPLSLabel{
					{Label: 16, TC: 6, S: true, TTL: 255},
				},
			},
		},
		L3: L3Config{
			SrcIP:    "155.1.45.4",
			DstIP:    "150.1.8.8",
			Protocol: 1, // ICMP
			TTL:      255,
			IPID:     0x1e68,
			Flags:    0,  // pcap: flags/frag 0x0000
			DSCP:     48, // pcap TOS 0xc0
		},
		Payload: icmpMsg,
	}

	packet, err := builder.Build(config)
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	want := []byte{
		0xaa, 0xbb, 0xcc, 0x00, 0x04, 0x00, // dst MAC
		0xaa, 0xbb, 0xcc, 0x00, 0x05, 0x00, // src MAC
		0x81, 0x00, // TPID 802.1Q
		0x00, 0x92, // VLAN tag: priority 0, ID 146
		0x88, 0x47, // EtherType = MPLS unicast (0x8847) at 16:18
		0x00, 0x01, 0x0d, 0xff, // MPLS: label 16, TC 6, S 1, TTL 255 at offset 18
		0x45, 0xc0, // version 4, IHL 5, TOS 0xc0
		0x00, 0xac, // total length 172 = 20 IP + 152 ICMP (no MPLS/VLAN)
		0x1e, 0x68, // IPID
		0x00, 0x00, // flags 0, frag offset 0
		0xff,       // TTL 255
		0x01,       // protocol 1 (ICMP)
		0x36, 0x1a, // header checksum (pcap-valid)
		0x9b, 0x01, 0x2d, 0x04, // src 155.1.45.4
		0x96, 0x01, 0x08, 0x08, // dst 150.1.8.8
	}
	want = append(want, icmpMsg...)

	if len(packet) != len(want) {
		t.Fatalf("len(packet) = %d, want %d", len(packet), len(want))
	}
	if !bytes.Equal(packet, want) {
		t.Errorf("packet mismatch:\n got % x\nwant % x", packet, want)
	}
}

// TestBuilder_MPLS_MulticastEtherType verifies the multicast selector
// (RFC 3032 §3.10): MPLSConfig.Multicast forces the EtherType to 0x8848
// instead of 0x8847, with everything else identical.
func TestBuilder_MPLS_MulticastEtherType(t *testing.T) {
	builder := NewBuilder()
	config := PacketConfig{
		L2: L2Config{
			SrcMAC: "aa:bb:cc:00:cb:01",
			DstMAC: "aa:bb:cc:00:ca:02",
			MPLS: &MPLSConfig{
				Labels:    []MPLSLabel{{Label: 100, S: true}},
				Multicast: true,
			},
		},
		L3: L3Config{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", Protocol: 17},
		L4: L4Config{Protocol: "udp", SrcPort: 1000, DstPort: 2000},
	}
	packet, err := builder.Build(config)
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}
	if got := binary.BigEndian.Uint16(packet[12:14]); got != EtherTypeMPLSMulticast {
		t.Errorf("EtherType = 0x%04x, want 0x8848 (multicast)", got)
	}
}

// TestBuilder_MPLS_FieldEncoding verifies the per-field encoding of a label
// entry: TC, TTL and the S bit land in the exact bit positions (RFC 3032
// §3.1: ((label&0xFFFFF)<<12)|(tc<<9)|(s<<8)|ttl).
func TestBuilder_MPLS_FieldEncoding(t *testing.T) {
	builder := NewBuilder()
	config := PacketConfig{
		L2: L2Config{
			SrcMAC: "aa:bb:cc:00:cb:01",
			DstMAC: "aa:bb:cc:00:ca:02",
			MPLS: &MPLSConfig{
				Labels: []MPLSLabel{
					{Label: 0xABCDE, TC: 5, S: false, TTL: 7},
					{Label: 0x12345, TC: 3, S: true, TTL: 9},
				},
			},
		},
		L3: L3Config{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", Protocol: 17},
		L4: L4Config{Protocol: "udp", SrcPort: 1000, DstPort: 2000},
	}
	packet, err := builder.Build(config)
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}
	// entry = (label<<12)|(tc<<9)|(s<<8)|ttl
	want1 := (uint32(0xABCDE) << 12) | (5 << 9) | (0 << 8) | 7
	want2 := (uint32(0x12345) << 12) | (3 << 9) | (1 << 8) | 9
	if got := binary.BigEndian.Uint32(packet[14:18]); got != want1 {
		t.Errorf("top entry = 0x%08x, want 0x%08x", got, want1)
	}
	if got := binary.BigEndian.Uint32(packet[18:22]); got != want2 {
		t.Errorf("bottom entry = 0x%08x, want 0x%08x", got, want2)
	}
}

// TestBuilder_MPLS_AutoCorrectS verifies the S-bit auto-correction
// (documented on MPLSConfig): a stack where the user left S unset on every
// entry still emits a valid stack — the bottom entry is written with S=1,
// non-bottom entries with S=0 — and a TTL of 0 is written as 64
// (DefaultMPLSTTL).
func TestBuilder_MPLS_AutoCorrectS(t *testing.T) {
	builder := NewBuilder()
	config := PacketConfig{
		L2: L2Config{
			SrcMAC: "aa:bb:cc:00:cb:01",
			DstMAC: "aa:bb:cc:00:ca:02",
			MPLS: &MPLSConfig{
				Labels: []MPLSLabel{
					{Label: 100}, // no S, no TTL
					{Label: 200}, // no S, no TTL
				},
			},
		},
		L3: L3Config{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", Protocol: 17},
		L4: L4Config{Protocol: "udp", SrcPort: 1000, DstPort: 2000},
	}
	packet, err := builder.Build(config)
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}
	// top: S=0 (not bottom), TTL 64; bottom: S=1, TTL 64.
	want1 := (uint32(100) << 12) | (0 << 9) | (0 << 8) | 64
	want2 := (uint32(200) << 12) | (0 << 9) | (1 << 8) | 64
	if got := binary.BigEndian.Uint32(packet[14:18]); got != want1 {
		t.Errorf("top entry = 0x%08x, want 0x%08x (S auto-corrected off)", got, want1)
	}
	if got := binary.BigEndian.Uint32(packet[18:22]); got != want2 {
		t.Errorf("bottom entry = 0x%08x, want 0x%08x (S auto-corrected on)", got, want2)
	}
}

// TestBuilder_MPLS_InnerIPv6 verifies an IPv6 inner packet behind the label
// stack: L2.EtherType 0x86DD selects the 40-byte IPv6 inner header
// (RFC 8200), while the wire EtherType is still forced to 0x8847. The IPv6
// header has no checksum; the UDP checksum uses the 40-byte IPv6
// pseudo-header (RFC 8200 §8.1).
func TestBuilder_MPLS_InnerIPv6(t *testing.T) {
	builder := NewBuilder()
	config := PacketConfig{
		L2: L2Config{
			SrcMAC:    "aa:bb:cc:00:cb:01",
			DstMAC:    "aa:bb:cc:00:ca:02",
			EtherType: EtherTypeIPv6,
			MPLS: &MPLSConfig{
				Labels: []MPLSLabel{{Label: 300, S: true, TTL: 255}},
			},
		},
		L3: L3Config{
			SrcIP:    "2001:db8::1",
			DstIP:    "2001:db8::2",
			Protocol: 17, // UDP
			TTL:      64,
		},
		L4:      L4Config{Protocol: "udp", SrcPort: 1234, DstPort: 5678},
		Payload: []byte("v6payload0"), // 10 bytes: UDP len 18
	}
	packet, err := builder.Build(config)
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	if got := binary.BigEndian.Uint16(packet[12:14]); got != EtherTypeMPLSUnicast {
		t.Errorf("wire EtherType = 0x%04x, want 0x8847 (inner is IPv6 but outer stays MPLS)", got)
	}
	if got := binary.BigEndian.Uint32(packet[14:18]); got != (uint32(300)<<12)|(1<<8)|255 {
		t.Errorf("label entry = 0x%08x, want 0x%08x", got, (uint32(300)<<12)|(1<<8)|255)
	}
	v6 := packet[18:58]
	if v6[0] != 0x60 {
		t.Errorf("IPv6 version/TrafficClass byte = 0x%02x, want 0x60", v6[0])
	}
	// Payload length = 8 UDP + 10 payload = 18 (0x12); next header 17; hop limit 64.
	if got := binary.BigEndian.Uint16(v6[4:6]); got != 18 {
		t.Errorf("IPv6 payload length = %d, want 18", got)
	}
	if v6[6] != 17 || v6[7] != 64 {
		t.Errorf("IPv6 next header/hop limit = %d/%d, want 17/64", v6[6], v6[7])
	}
	if !bytes.Equal(v6[8:24], netParseIP16(t, "2001:db8::1")) || !bytes.Equal(v6[24:40], netParseIP16(t, "2001:db8::2")) {
		t.Errorf("IPv6 addresses = % x % x, want 2001:db8::1 / 2001:db8::2", v6[8:24], v6[24:40])
	}
	// UDP checksum over the IPv6 pseudo-header: independent recomputation.
	udpHdr := packet[58:66]
	gotCk := binary.BigEndian.Uint16(udpHdr[6:8])
	wantCk := udpChecksumV6(t, config.L3.SrcIP, config.L3.DstIP, udpHdr[:6], config.Payload)
	if gotCk != wantCk {
		t.Errorf("IPv6 UDP checksum = 0x%04x, independent recomputation = 0x%04x", gotCk, wantCk)
	}
}

// TestBuilder_MPLS_Explicit8847EtherType verifies the effectiveEtherType
// normalization: a config that sets L2.EtherType to 0x8847 (the wire value
// a user might copy from a capture) still resolves the INNER L3 as IPv4 —
// an inner IPv4 header is written instead of a zero-length L3.
func TestBuilder_MPLS_Explicit8847EtherType(t *testing.T) {
	builder := NewBuilder()
	config := PacketConfig{
		L2: L2Config{
			SrcMAC:    "aa:bb:cc:00:cb:01",
			DstMAC:    "aa:bb:cc:00:ca:02",
			EtherType: EtherTypeMPLSUnicast, // user copied the wire value
			MPLS: &MPLSConfig{
				Labels: []MPLSLabel{{Label: 16, S: true}},
			},
		},
		L3: L3Config{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", Protocol: 17, TTL: 64},
		L4: L4Config{Protocol: "udp", SrcPort: 1000, DstPort: 2000},
	}
	packet, err := builder.Build(config)
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}
	// Inner IPv4 must be present at offset 18 (14 eth + 4 label): version 4.
	if packet[18] != 0x45 {
		t.Errorf("inner L3 byte = 0x%02x, want 0x45 (IPv4 written after the stack)", packet[18])
	}
	// 14 eth + 4 label + 20 IPv4 + 8 UDP = 46 < MinEthernetFrame, padded.
	if len(packet) != MinEthernetFrame {
		t.Errorf("len = %d, want %d (eth + label + IPv4 + UDP, padded to minimum)", len(packet), MinEthernetFrame)
	}
	// The IP total length still counts only IP payload (28), not padding.
	if got := binary.BigEndian.Uint16(packet[20:22]); got != 28 {
		t.Errorf("IP total length = %d, want 28", got)
	}
}

// TestBuilder_MPLS_NilRegression verifies the MPLS==nil path is untouched:
// the same config minus MPLS emits the plain Ethernet+IPv4+UDP frame
// (EtherType 0x0800, no label stack), byte-for-byte identical to an
// independently computed frame (Python RFC 791/768 checksums, padded to
// MinEthernetFrame with zeros — the IP total length stays 33).
func TestBuilder_MPLS_NilRegression(t *testing.T) {
	builder := NewBuilder()
	config := PacketConfig{
		L2: L2Config{
			SrcMAC: "aa:bb:cc:00:cb:01",
			DstMAC: "aa:bb:cc:00:ca:02",
		},
		L3: L3Config{
			SrcIP:    "10.0.0.203",
			DstIP:    "10.0.0.201",
			Protocol: 17,
			TTL:      64,
			IPID:     0,
			Flags:    0,
		},
		L4:      L4Config{Protocol: "udp", SrcPort: 646, DstPort: 646},
		Payload: []byte("hello"),
	}
	packet, err := builder.Build(config)
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	// Independently computed (Python): eth 0x0800, IP total 33, IP checksum
	// 0x6539, UDP length 13, UDP checksum 0xa162, zero-padded to 60 bytes.
	want := []byte{
		0xaa, 0xbb, 0xcc, 0x00, 0xca, 0x02, // dst MAC
		0xaa, 0xbb, 0xcc, 0x00, 0xcb, 0x01, // src MAC
		0x08, 0x00, // EtherType = IPv4 (no MPLS forcing)
		0x45, 0x00, 0x00, 0x21, 0x00, 0x00, 0x00, 0x00, // IPv4: total 33, ID 0, flags 0
		0x40, 0x11, 0x65, 0x39, // TTL 64, UDP, checksum 0x6539
		0x0a, 0x00, 0x00, 0xcb, 0x0a, 0x00, 0x00, 0xc9, // 10.0.0.203 -> 10.0.0.201
		0x02, 0x86, 0x02, 0x86, 0x00, 0x0d, 0xa1, 0x62, // UDP 646/646, len 13, cksum 0xa162
		'h', 'e', 'l', 'l', 'o', // payload
	}
	want = append(want, make([]byte, 60-len(want))...) // Ethernet padding

	if len(packet) != len(want) {
		t.Fatalf("len(packet) = %d, want %d", len(packet), len(want))
	}
	if !bytes.Equal(packet, want) {
		t.Errorf("packet mismatch:\n got % x\nwant % x", packet, want)
	}
}

// TestBuilder_MPLS_Validation verifies validateMPLSConfig's rejection of
// configs that would produce corrupt frames (spec §MPLS-validate): empty
// stack, label > 20 bits, TC > 7, explicit S=true on a non-bottom entry,
// MPLS+GRE, MPLS+PPPoE, and a non-IP inner layer.
func TestBuilder_MPLS_Validation(t *testing.T) {
	builder := NewBuilder()
	base := PacketConfig{
		L2: L2Config{
			SrcMAC: "aa:bb:cc:00:cb:01",
			DstMAC: "aa:bb:cc:00:ca:02",
			MPLS:   &MPLSConfig{Labels: []MPLSLabel{{Label: 100, S: true}}},
		},
		L3: L3Config{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", Protocol: 17, TTL: 64},
		L4: L4Config{Protocol: "udp", SrcPort: 1000, DstPort: 2000},
	}

	tests := []struct {
		name       string
		mutate     func(*PacketConfig)
		wantErrSub string // optional substring of the expected error
	}{
		{
			name: "empty label stack",
			mutate: func(c *PacketConfig) {
				c.L2.MPLS.Labels = nil
			},
			wantErrSub: "at least one entry",
		},
		{
			name: "label exceeds 20 bits",
			mutate: func(c *PacketConfig) {
				c.L2.MPLS.Labels = []MPLSLabel{{Label: 0x100000, S: true}}
			},
			wantErrSub: "exceeds 20 bits",
		},
		{
			name: "TC exceeds 3 bits",
			mutate: func(c *PacketConfig) {
				c.L2.MPLS.Labels = []MPLSLabel{{Label: 100, TC: 8, S: true}}
			},
			wantErrSub: "exceeds 3 bits",
		},
		{
			name: "explicit S on non-bottom entry",
			mutate: func(c *PacketConfig) {
				c.L2.MPLS.Labels = []MPLSLabel{{Label: 100, S: true}, {Label: 200, S: true}}
			},
			wantErrSub: "not the bottom of stack",
		},
		{
			name: "MPLS combined with GRE",
			// Make the GRE config otherwise valid (outer protocol 47, no
			// L4) so the GRE validator passes and the MPLS+GRE rejection
			// in validateMPLSConfig is the one that fires.
			mutate: func(c *PacketConfig) {
				c.L2.GRE = &GREConfig{ProtocolType: EtherTypeIPv4}
				c.L3.Protocol = ProtocolGRE
				c.L4 = L4Config{}
			},
			wantErrSub: "cannot combine MPLS with GRE",
		},
		{
			name: "MPLS combined with PPPoE",
			mutate: func(c *PacketConfig) {
				c.L2.PPPoE = &PPPoEConfig{Code: PPPoECodeSessionData}
			},
			wantErrSub: "cannot combine MPLS with PPPoE",
		},
		{
			name: "non-IP inner layer",
			mutate: func(c *PacketConfig) {
				c.L2.EtherType = EtherTypeARP
			},
			wantErrSub: "inner layer must be IP",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base
			// Deep-copy the MPLS config so a case's mutation (e.g. replacing
			// Labels) does not leak into the next case via the shared slice.
			mplsCopy := *base.L2.MPLS
			mplsCopy.Labels = append([]MPLSLabel(nil), base.L2.MPLS.Labels...)
			cfg.L2.MPLS = &mplsCopy
			tc.mutate(&cfg)
			_, err := builder.Build(cfg)
			if err == nil {
				t.Errorf("Build succeeded, want error for %s", tc.name)
				return
			}
			if tc.wantErrSub != "" && !strings.Contains(err.Error(), tc.wantErrSub) {
				t.Errorf("error %q does not contain %q", err.Error(), tc.wantErrSub)
			}
		})
	}

	// Sanity: the base config itself must build.
	if _, err := builder.Build(base); err != nil {
		t.Fatalf("base config rejected: %v", err)
	}
}

// netParseIP16 parses an IPv6 address and returns its 16-byte form (test
// helper).
func netParseIP16(t *testing.T, s string) []byte {
	t.Helper()
	ip := net.ParseIP(s).To16()
	if len(ip) != 16 {
		t.Fatalf("To16(%s) = %d bytes, want 16", s, len(ip))
	}
	return ip
}

// udpChecksumV6 is an independent RFC 8200 §8.1 UDP checksum for tests
// (does not reuse the code under test): 40-byte pseudo-header + UDP header
// (checksum field zeroed) + payload.
func udpChecksumV6(t *testing.T, srcIP, dstIP string, udpHeaderNoCksum []byte, payload []byte) uint16 {
	t.Helper()
	src := net.ParseIP(srcIP).To16()
	dst := net.ParseIP(dstIP).To16()
	// UDP length = 8-byte header + payload (the 6 bytes passed in exclude
	// the checksum field).
	upperLen := uint32(8 + len(payload))
	ph := make([]byte, 40)
	copy(ph[0:16], src)
	copy(ph[16:32], dst)
	binary.BigEndian.PutUint32(ph[32:36], upperLen)
	ph[39] = 17 // UDP
	msg := append(ph, udpHeaderNoCksum...)
	msg = append(msg, payload...)
	return onesComplementSum(msg)
}

// onesComplementSum computes the 16-bit one's-complement checksum (RFC 1071)
// over b, zero-padding an odd tail.
func onesComplementSum(b []byte) uint16 {
	sum := uint32(0)
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}
