package core

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

// Reference bytes are taken from real captured GRE traffic (verified with
// tshark -r <file> -x):
//
//	/home/pcap_auto/mypcap/idc3/1.ARPoverGRE.pcap   frame 1: ARP-over-GRE
//	  (GRE flags 0x0000, Protocol Type 0x0806, no option fields)
//	/home/pcap_auto/mypcap/idc3/6、gre_dns.pcap    frame 1: inner IPv4/UDP/DNS
//	  (GRE flags 0x2000 = K bit, Key 0x00000000, RFC 2890)
//	/home/pcap_auto/mypcap/publicpcap/IPv4/HTTP_gre_nm4.pcap  frame 1: VLAN +
//	  inner IPv4/TCP SYN (GRE flags 0x0000, Protocol Type 0x0800)

// TestBuilder_GRE_ARPOverGRE_PcapBytes reproduces pcap 1.ARPoverGRE.pcap
// frame 1 byte-for-byte (66 bytes, no padding):
//
//	c8 01 16 93 00 00 | c8 02 16 a6 00 00 | 08 00 |
//	45 00 00 34 00 38 00 00 ff 2f 7d 60 0a 00 15 02 0a 00 15 01 |
//	00 00 08 06 | <28-byte ARP reply>
//
// Covers (RFC 2784 §2/§4): outer IPv4 with protocol 47 (0x2f), outer
// total length 0x0034 = 20 (IP) + 4 (GRE) + 28 (ARP), GRE flags 0x0000
// (no C/R/K/S option fields), Protocol Type 0x0806 (ARP), ARP message
// carried verbatim after the 4-byte GRE header. The outer IP checksum
// (0x7d60) is computed by the builder and must match.
func TestBuilder_GRE_ARPOverGRE_PcapBytes(t *testing.T) {
	builder := NewBuilder()

	arp := []byte{
		0x00, 0x01, // hardware type: Ethernet
		0x08, 0x00, // protocol type: IPv4
		0x06, 0x04, // hw addr len, proto addr len
		0x00, 0x02, // operation: reply
		0xc8, 0x02, 0x16, 0xa6, 0x00, 0x01, // sender HW
		0x0a, 0x00, 0x0c, 0x02, // sender proto 10.0.12.2
		0xc8, 0x01, 0x16, 0x93, 0x00, 0x01, // target HW
		0x0a, 0x00, 0x0c, 0x01, // target proto 10.0.12.1
	}
	config := PacketConfig{
		L2: L2Config{
			SrcMAC: "c8:02:16:a6:00:00",
			DstMAC: "c8:01:16:93:00:00",
			GRE: &GREConfig{
				ProtocolType: EtherTypeARP, // 0x0806
			},
		},
		L3: L3Config{
			SrcIP:    "10.0.21.2",
			DstIP:    "10.0.21.1",
			Protocol: ProtocolGRE, // 47
			TTL:      255,
			IPID:     0x0038,
			Flags:    0, // pcap carries flags/frag 0x0000 (no DF)
		},
		Payload: arp,
	}

	packet, err := builder.Build(config)
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	want := []byte{
		0xc8, 0x01, 0x16, 0x93, 0x00, 0x00, // dst MAC
		0xc8, 0x02, 0x16, 0xa6, 0x00, 0x00, // src MAC
		0x08, 0x00, // EtherType = IPv4
		0x45, 0x00, // version 4, IHL 5, TOS 0
		0x00, 0x34, // total length 52 = 20 IP + 4 GRE + 28 ARP
		0x00, 0x38, // IPID
		0x00, 0x00, // flags 0, frag offset 0
		0xff,       // TTL 255
		0x2f,       // protocol 47 (IPPROTO_GRE)
		0x7d, 0x60, // header checksum
		0x0a, 0x00, 0x15, 0x02, // src 10.0.21.2
		0x0a, 0x00, 0x15, 0x01, // dst 10.0.21.1
		0x00, 0x00, // GRE flags 0x0000 (no options)
		0x08, 0x06, // GRE Protocol Type = ARP
	}
	want = append(want, arp...)

	if len(packet) != len(want) {
		t.Fatalf("len(packet) = %d, want %d", len(packet), len(want))
	}
	if !bytes.Equal(packet, want) {
		t.Errorf("packet mismatch:\n got % x\nwant % x", packet, want)
	}
}

// TestBuilder_GRE_DNSOverGRE_PcapBytes reproduces pcap 6、gre_dns.pcap
// frame 1's outer layer + GRE header byte-for-byte, with the inner
// IPv4/UDP/DNS packet (from the same pcap) carried verbatim in Payload:
//
//	18 03 73 db 74 0b | 2c b0 5d 93 e4 b4 | 08 00 |
//	45 00 00 5d 49 d4 00 00 3e 2f fd 94 9b 00 00 05 9a 00 00 04 |
//	20 00 08 00 00 00 00 00 | <inner IPv4+UDP+DNS, 65 bytes>
//
// Covers (RFC 2784 §2 + RFC 2890): GRE flags 0x2000 = K (Key Present)
// with the 4-byte Key 0x00000000 (NOT the checksum bit — bit 15 is C,
// 0x8000), Protocol Type 0x0800 (IPv4), outer total length 0x005d = 20
// (IP) + 8 (GRE base + Key) + 65 (inner). The outer IP checksum (0xfd94)
// and the inner packet's checksums (0x9191 IP / 0x1ee4 UDP, verified
// against the pcap) are untouched by the builder.
func TestBuilder_GRE_DNSOverGRE_PcapBytes(t *testing.T) {
	builder := NewBuilder()

	// Inner IPv4+UDP+DNS query for clients3.google.com (pcap frame 1).
	inner := []byte{
		// IPv4 header: total length 0x0041 (65), IPID 0, DF, TTL 64, UDP
		0x45, 0x00, 0x00, 0x41, 0x00, 0x00, 0x40, 0x00,
		0x40, 0x11, 0x91, 0x91, 0x99, 0x00, 0x00, 0x0b, 0x08, 0x08, 0x08, 0x08,
		// UDP: 45078 -> 53, len 45, checksum 0x1ee4
		0xb0, 0x16, 0x00, 0x35, 0x00, 0x2d, 0x1e, 0xe4,
		// DNS query: id 0x4c87, RD, one question
		0x4c, 0x87, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x08, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x73, 0x33, // clients3
		0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, // google
		0x03, 0x63, 0x6f, 0x6d, 0x00, // com
		0x00, 0x01, 0x00, 0x01, // type A, class IN
	}
	if len(inner) != 65 {
		t.Fatalf("inner packet length = %d, want 65", len(inner))
	}

	config := PacketConfig{
		L2: L2Config{
			SrcMAC: "2c:b0:5d:93:e4:b4",
			DstMAC: "18:03:73:db:74:0b",
			GRE: &GREConfig{
				ProtocolType: EtherTypeIPv4, // 0x0800
				KeyPresent:   true,          // K bit: 0x2000
				Key:          0x00000000,    // pcap tunnel key
			},
		},
		L3: L3Config{
			SrcIP:    "155.0.0.5",
			DstIP:    "154.0.0.4",
			Protocol: ProtocolGRE,
			TTL:      62,
			IPID:     0x49d4,
			Flags:    0,
		},
		Payload: inner,
	}

	packet, err := builder.Build(config)
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	want := []byte{
		0x18, 0x03, 0x73, 0xdb, 0x74, 0x0b, // dst MAC
		0x2c, 0xb0, 0x5d, 0x93, 0xe4, 0xb4, // src MAC
		0x08, 0x00, // EtherType = IPv4
		0x45, 0x00, // version 4, IHL 5, TOS 0
		0x00, 0x5d, // total length 93 = 20 IP + 8 GRE + 65 inner
		0x49, 0xd4, // IPID
		0x00, 0x00, // flags 0, frag offset 0
		0x3e,       // TTL 62
		0x2f,       // protocol 47
		0xfd, 0x94, // header checksum (computed by the builder)
		0x9b, 0x00, 0x00, 0x05, // src 155.0.0.5
		0x9a, 0x00, 0x00, 0x04, // dst 154.0.0.4
		0x20, 0x00, // GRE flags: K bit (0x2000) — NOT the C bit (0x8000)
		0x08, 0x00, // GRE Protocol Type = IPv4
		0x00, 0x00, 0x00, 0x00, // Key = 0x00000000 (RFC 2890)
	}
	want = append(want, inner...)

	if len(packet) != len(want) {
		t.Fatalf("len(packet) = %d, want %d", len(packet), len(want))
	}
	if !bytes.Equal(packet, want) {
		t.Errorf("packet mismatch:\n got % x\nwant % x", packet, want)
	}
}

// TestBuilder_GRE_HTTPVLAN_PcapBytes reproduces pcap HTTP_gre_nm4.pcap
// frame 1 byte-for-byte (94 bytes): an 802.1Q VLAN tag (ID 0x07d8)
// between the Ethernet header and the outer IPv4, then GRE (flags 0x0000,
// Protocol Type 0x0800), then the inner IPv4/TCP SYN (with MSS/SACK/WS
// options) carried verbatim:
//
//	d4 c1 c8 21 62 60 | ac 75 1d 32 01 82 | 81 00 07 d8 | 08 00 |
//	45 00 00 4c 0d e4 00 00 fa 2f 91 66 73 aa 75 22 24 66 14 06 |
//	00 00 08 00 | <inner IPv4/TCP SYN, 52 bytes>
//
// Covers the VLAN+GRE offset combination: the GRE header sits at frame
// offset 38 (14 Ethernet + 4 VLAN + 20 outer IP), the outer total length
// 0x004c = 20 + 4 + 52 covers the GRE header, and the outer IP checksum
// 0x9166 is computed by the builder.
func TestBuilder_GRE_HTTPVLAN_PcapBytes(t *testing.T) {
	builder := NewBuilder()

	// Inner IPv4/TCP SYN: src 10.101.215.129:41468 -> 101.200.205.176:80,
	// seq 0xa185446b, MSS 1360 + SACK-permitted + WS 512 (12 option bytes).
	inner := []byte{
		// IPv4: TOS 0x38 (DSCP 14), total 0x0034 (52), IPID 0xeda1, DF,
		// TTL 63, TCP, checksum 0x388b
		0x45, 0x38, 0x00, 0x34, 0xed, 0xa1, 0x40, 0x00,
		0x3f, 0x06, 0x38, 0x8b, 0x0a, 0x65, 0xd7, 0x81, 0x65, 0xc8, 0xcd, 0xb0,
		// TCP: 41468 -> 80, seq, ack 0, data offset 8 (32 bytes), SYN,
		// window 65535, checksum 0xd1d6
		0xa1, 0xfc, 0x00, 0x50, 0xa1, 0x85, 0x44, 0x6b, 0x00, 0x00, 0x00, 0x00,
		0x80, 0x02, 0xff, 0xff, 0xd1, 0xd6, 0x00, 0x00,
		// options: MSS 1360, SACK-permitted, NOP NOP NOP, WS 512
		0x02, 0x04, 0x05, 0x50, 0x04, 0x02, 0x01, 0x01, 0x01, 0x03, 0x03, 0x09,
	}
	if len(inner) != 52 {
		t.Fatalf("inner packet length = %d, want 52", len(inner))
	}

	config := PacketConfig{
		L2: L2Config{
			SrcMAC: "ac:75:1d:32:01:82",
			DstMAC: "d4:c1:c8:21:62:60",
			VLAN:   &VLAN{ID: 0x07d8},
			GRE: &GREConfig{
				ProtocolType: EtherTypeIPv4,
			},
		},
		L3: L3Config{
			SrcIP:    "115.170.117.34",
			DstIP:    "36.102.20.6",
			Protocol: ProtocolGRE,
			TTL:      250,
			IPID:     0x0de4,
			Flags:    0,
		},
		Payload: inner,
	}

	packet, err := builder.Build(config)
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	want := []byte{
		0xd4, 0xc1, 0xc8, 0x21, 0x62, 0x60, // dst MAC
		0xac, 0x75, 0x1d, 0x32, 0x01, 0x82, // src MAC
		0x81, 0x00, // TPID 0x8100
		0x07, 0xd8, // VLAN tag: ID 0x07d8, priority 0
		0x08, 0x00, // EtherType = IPv4
		0x45, 0x00, // version 4, IHL 5, TOS 0
		0x00, 0x4c, // total length 76 = 20 IP + 4 GRE + 52 inner
		0x0d, 0xe4, // IPID
		0x00, 0x00, // flags 0, frag offset 0
		0xfa,       // TTL 250
		0x2f,       // protocol 47
		0x91, 0x66, // header checksum (computed by the builder)
		0x73, 0xaa, 0x75, 0x22, // src 115.170.117.34
		0x24, 0x66, 0x14, 0x06, // dst 36.102.20.6
		0x00, 0x00, // GRE flags 0x0000
		0x08, 0x00, // GRE Protocol Type = IPv4
	}
	want = append(want, inner...)

	if len(packet) != len(want) {
		t.Fatalf("len(packet) = %d, want %d", len(packet), len(want))
	}
	if !bytes.Equal(packet, want) {
		t.Errorf("packet mismatch:\n got % x\nwant % x", packet, want)
	}
}

// TestBuilder_GRE_FlagCombinations verifies the GRE option fields
// (RFC 2784 §2 + RFC 2890) byte-for-byte: each flag bit selects its 4-byte
// option field, the fields are emitted in the order Checksum+Reserved (C),
// Routing (R), Key (K), Sequence (S), and the payload starts immediately
// after — so the header length always equals 4 + 4*(number of options).
func TestBuilder_GRE_FlagCombinations(t *testing.T) {
	builder := NewBuilder()
	noPad := false
	base := PacketConfig{
		L2: L2Config{
			SrcMAC: "02:00:00:00:00:01",
			DstMAC: "02:00:00:00:00:02",
			Pad:    &noPad, // natural frame size: exact header-length math
		},
		L3: L3Config{
			SrcIP:    "10.0.0.1",
			DstIP:    "20.0.0.1",
			Protocol: ProtocolGRE,
			TTL:      64,
			IPID:     0x0001,
			Flags:    IPFlagDF,
		},
		Payload: []byte("HELLO"),
	}

	tests := []struct {
		name string
		gre  *GREConfig
		want []byte // expected GRE header region (flags..options)
	}{
		{
			name: "no options",
			gre:  &GREConfig{ProtocolType: EtherTypeIPv4},
			want: []byte{0x00, 0x00, 0x08, 0x00},
		},
		{
			name: "key only",
			gre:  &GREConfig{ProtocolType: EtherTypeIPv4, KeyPresent: true, Key: 0xdeadbeef},
			want: []byte{0x20, 0x00, 0x08, 0x00, 0xde, 0xad, 0xbe, 0xef},
		},
		{
			name: "sequence only",
			gre:  &GREConfig{ProtocolType: EtherTypeIPv4, SequencePresent: true, Sequence: 7},
			want: []byte{0x10, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x07},
		},
		{
			name: "checksum only",
			gre:  &GREConfig{ProtocolType: EtherTypeIPv4, Checksum: true},
			want: []byte{0x80, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00},
		},		{
			name: "routing only",
			gre:  &GREConfig{ProtocolType: EtherTypeIPv4, RoutingPresent: true, Routing: []byte{0x00, 0x01}},
			want: []byte{0x40, 0x00, 0x08, 0x00, 0x00, 0x04, 0x00, 0x01},
		},
		{
			name: "checksum+key+sequence",
			gre: &GREConfig{
				ProtocolType:    EtherTypeIPv4,
				Checksum:        true,
				KeyPresent:      true,
				Key:             0x00000042,
				SequencePresent: true,
				Sequence:        0x00000009,
			},
			want: []byte{
				0xb0, 0x00, 0x08, 0x00, // C|K|S
				0x00, 0x00, 0x00, 0x00, // Checksum (placeholder, filled post-pass) + Reserved
				0x00, 0x00, 0x00, 0x42, // Key
				0x00, 0x00, 0x00, 0x09, // Sequence Number
			},
		},
		{
			name: "routing+key+sequence",
			gre: &GREConfig{
				ProtocolType:    EtherTypeIPv4,
				RoutingPresent:  true,
				Routing:         []byte{0xab, 0xcd, 0xef, 0x01},
				KeyPresent:      true,
				Key:             0x00000005,
				SequencePresent: true,
				Sequence:        0x00000006,
			},
			want: []byte{
				0x70, 0x00, 0x08, 0x00, // R|K|S
				0x00, 0x06, 0xab, 0xcd, 0xef, 0x01, // Routing Length(6) + routing data
				0x00, 0x00, 0x00, 0x05, // Key
				0x00, 0x00, 0x00, 0x06, // Sequence Number
			},
		},
		{
			name: "auto protocol type defaults to ipv4",
			gre:  &GREConfig{KeyPresent: true, Key: 1}, // ProtocolType 0
			want: []byte{0x20, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x01},
		},
		{
			name: "arp protocol type",
			gre:  &GREConfig{ProtocolType: EtherTypeARP},
			want: []byte{0x00, 0x00, 0x08, 0x06},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base
			cfg.L2.GRE = tc.gre
			packet, err := builder.Build(cfg)
			if err != nil {
				t.Fatalf("Build failed: %v", err)
			}
			// GRE header starts at 14 (Ethernet) + 20 (outer IPv4).
			greStart := 34
			greLen := len(tc.want)
			want := tc.want
			if tc.gre.Checksum {
				// The Checksum field carries the RFC 2784 §3.1 value
				// (computed over the GRE header + payload), not a zero
				// placeholder — verify it equals an independent
				// computation.
				payloadEnd := greStart + greLen + len(base.Payload)
				computed := greChecksumIndependent(packet[greStart:payloadEnd])
				wire := binary.BigEndian.Uint16(packet[greStart+4 : greStart+6])
				if wire != computed {
					t.Errorf("wire checksum = 0x%04x, independent computation = 0x%04x", wire, computed)
				}
				want = append([]byte(nil), want...)
				binary.BigEndian.PutUint16(want[4:6], computed)
			}
			if len(packet) != greStart+greLen+len(base.Payload) {
				t.Fatalf("len(packet) = %d, want %d (header length must match flag bits)", len(packet), greStart+greLen+len(base.Payload))
			}
			if !bytes.Equal(packet[greStart:greStart+greLen], want) {
				t.Errorf("GRE header = % x, want % x", packet[greStart:greStart+greLen], want)
			}
			if !bytes.Equal(packet[greStart+greLen:], base.Payload) {
				t.Errorf("payload = % x, want % x (must follow the GRE options directly)", packet[greStart+greLen:], base.Payload)
			}
			// Outer total length must cover GRE header + payload.
			totalLen := binary.BigEndian.Uint16(packet[16:18])
			if int(totalLen) != 20+greLen+len(base.Payload) {
				t.Errorf("outer total length = %d, want %d (GRE header included)", totalLen, 20+greLen+len(base.Payload))
			}
		})
	}
}

// TestBuilder_GRE_Checksum verifies the RFC 2784 §3.1 GRE checksum: the
// 16-bit one's-complement sum over the GRE header (Checksum field zeroed)
// plus the payload, padded to a 4-byte boundary. The wire value must equal
// an independent computation, and a receiver summing every word (checksum
// included) must get 0xFFFF. Odd-length payloads exercise the padding.
func TestBuilder_GRE_Checksum(t *testing.T) {
	builder := NewBuilder()

	for _, tc := range []struct {
		name    string
		payload []byte
	}{
		{"even payload", []byte("HELLO-WORLD-1234")},
		{"odd payload", []byte("abc")},
		{"empty payload", nil},
		{"payload len 2 mod 4", []byte("abcdef")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := PacketConfig{
				L2: L2Config{
					SrcMAC: "02:00:00:00:00:01",
					DstMAC: "02:00:00:00:00:02",
					GRE: &GREConfig{
						ProtocolType: EtherTypeIPv4,
						Checksum:     true,
					},
				},
				L3: L3Config{
					SrcIP:    "10.0.0.1",
					DstIP:    "20.0.0.1",
					Protocol: ProtocolGRE,
					TTL:      64,
					IPID:     1,
					Flags:    IPFlagDF,
				},
				Payload: tc.payload,
			}
			// Pad off: a padded frame would not change the checksum (padding
			// is excluded) but shrinks the frame; keep natural size here.
			noPad := false
			config.L2.Pad = &noPad

			packet, err := builder.Build(config)
			if err != nil {
				t.Fatalf("Build failed: %v", err)
			}

			greStart := 34 // 14 Ethernet + 20 outer IPv4
			payloadEnd := greStart + 4 + 4 + len(tc.payload)

			// 1. Receiver verification (RFC 2784 §3.1): the sum of every
			// 16-bit word of [GRE header + payload] — checksum included —
			// folds to 0xFFFF. The checksum computation pads with zero
			// octets to a 4-byte boundary; zeros do not change the sum, so
			// the trailing byte of an odd-length region is its high byte.
			region := packet[greStart:payloadEnd]
			sum := uint32(0)
			for i := 0; i+1 < len(region); i += 2 {
				sum += uint32(binary.BigEndian.Uint16(region[i : i+2]))
			}
			if len(region)%2 == 1 {
				sum += uint32(region[len(region)-1]) << 8
			}
			for sum>>16 != 0 {
				sum = (sum >> 16) + (sum & 0xffff)
			}
			if sum != 0xFFFF {
				t.Errorf("receiver sum = 0x%04x, want 0xFFFF (RFC 2784 §3.1)", sum)
			}

			// 2. The checksum value must equal an independent computation
			// over the header (checksum zeroed) + payload.
			computed := greChecksumIndependent(packet[greStart:payloadEnd])
			wire := binary.BigEndian.Uint16(packet[greStart+4 : greStart+6])
			if wire != computed {
				t.Errorf("wire checksum = 0x%04x, independent computation = 0x%04x", wire, computed)
			}
			if wire == 0 {
				t.Errorf("checksum must not be 0x0000 on the wire (RFC 2784 §3.1 transmits 0xFFFF)")
			}
		})
	}
}

// greChecksumIndependent is a standalone RFC 2784 §3.1 implementation used
// only by tests: 16-bit one's-complement sum of the region with the
// checksum field zeroed, padded to a 4-byte boundary, complemented, with
// 0x0000 mapped to 0xFFFF.
func greChecksumIndependent(region []byte) uint16 {
	// Zero the Checksum field (bytes 4:6 of the GRE header).
	zeroed := append([]byte(nil), region...)
	zeroed[4] = 0
	zeroed[5] = 0
	// Pad to a 4-byte boundary (zeros — do not affect the sum).
	for len(zeroed)%4 != 0 {
		zeroed = append(zeroed, 0)
	}
	sum := uint32(0)
	for i := 0; i < len(zeroed); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(zeroed[i : i+2]))
	}
	for sum>>16 != 0 {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	cksum := ^uint16(sum)
	if cksum == 0 {
		cksum = 0xFFFF
	}
	return cksum
}

// TestBuilder_GRE_Validate_Errors verifies that contradictory GRE configs
// are rejected instead of emitting corrupt frames: non-IP outer layer,
// outer IP protocol != 47, a non-empty L4Config (the inner packet must
// live entirely in Payload), an unsupported ProtocolType, an invalid
// Routing length, and the PPPoE+GRE combination.
func TestBuilder_GRE_Validate_Errors(t *testing.T) {
	builder := NewBuilder()
	valid := PacketConfig{
		L2: L2Config{
			SrcMAC: "02:00:00:00:00:01",
			DstMAC: "02:00:00:00:00:02",
			GRE:    &GREConfig{ProtocolType: EtherTypeIPv4},
		},
		L3: L3Config{
			SrcIP:    "10.0.0.1",
			DstIP:    "20.0.0.1",
			Protocol: ProtocolGRE,
			TTL:      64,
			IPID:     1,
		},
		Payload: []byte("inner"),
	}
	if _, err := builder.Build(valid); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*PacketConfig)
	}{
		{
			name: "outer ethertype is ARP",
			mutate: func(c *PacketConfig) {
				c.L2.EtherType = EtherTypeARP
				c.L2.GRE.ProtocolType = EtherTypeARP
			},
		},
		{
			name: "outer IP protocol != 47",
			mutate: func(c *PacketConfig) {
				c.L3.Protocol = ProtocolUDP
			},
		},
		{
			name: "outer IP protocol unset",
			mutate: func(c *PacketConfig) {
				c.L3.Protocol = 0
			},
		},
		{
			name: "L4Config present",
			mutate: func(c *PacketConfig) {
				c.L4 = L4Config{Protocol: "udp", SrcPort: 1, DstPort: 2}
			},
		},
		{
			name: "unsupported protocol type",
			mutate: func(c *PacketConfig) {
				c.L2.GRE.ProtocolType = 0x1234
			},
		},
		{
			name: "routing odd length",
			mutate: func(c *PacketConfig) {
				c.L2.GRE.RoutingPresent = true
				c.L2.GRE.Routing = []byte{0x01, 0x02, 0x03}
			},
		},
		{
			name: "routing shorter than 2 bytes",
			mutate: func(c *PacketConfig) {
				c.L2.GRE.RoutingPresent = true
				c.L2.GRE.Routing = []byte{0x01}
			},
		},
		{
			name: "routing empty",
			mutate: func(c *PacketConfig) {
				c.L2.GRE.RoutingPresent = true
			},
		},
		{
			name: "pppoe and gre combined",
			mutate: func(c *PacketConfig) {
				c.L2.PPPoE = &PPPoEConfig{Code: PPPoECodeSessionData}
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := valid
			cfg.L2.GRE = &GREConfig{ProtocolType: EtherTypeIPv4}
			tc.mutate(&cfg)
			if _, err := builder.Build(cfg); err == nil {
				t.Errorf("Build succeeded, want error for %s", tc.name)
			}
		})
	}
}

// TestBuilder_GRE_Nil_Regression proves GRE==nil keeps the pre-GRE builder
// behavior byte-for-byte: the exact frame below was computed independently
// (Python) for a plain eth+IPv4+UDP packet with the same fields — any
// change to the non-GRE path (layout, padding, checksums) fails this test.
// The VLAN variant exercises the 18-byte L2 offset.
func TestBuilder_GRE_Nil_Regression(t *testing.T) {
	builder := NewBuilder()
	noPad := false
	config := PacketConfig{
		L2: L2Config{
			SrcMAC: "02:00:00:00:00:01",
			DstMAC: "02:00:00:00:00:02",
			Pad:    &noPad, // natural size so the GRE-vs-no-GRE delta is exact
		},
		L3: L3Config{
			SrcIP:    "10.0.0.1",
			DstIP:    "20.0.0.1",
			Protocol: ProtocolUDP,
			TTL:      64,
			IPID:     0x1234,
			Flags:    IPFlagDF,
		},
		L4: L4Config{
			Protocol: "udp",
			SrcPort:  12345,
			DstPort:  53,
		},
		Payload: []byte("hi"),
	}

	packet, err := builder.Build(config)
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}
	want := []byte{
		0x02, 0x00, 0x00, 0x00, 0x00, 0x02, // dst MAC
		0x02, 0x00, 0x00, 0x00, 0x00, 0x01, // src MAC
		0x08, 0x00, // EtherType
		0x45, 0x00, // version 4, IHL 5, TOS 0
		0x00, 0x1e, // total length 30 = 20 IP + 8 UDP + 2 payload
		0x12, 0x34, // IPID
		0x40, 0x00, // DF
		0x40,       // TTL 64
		0x11,       // protocol 17 (UDP)
		0x0a, 0x9a, // header checksum
		0x0a, 0x00, 0x00, 0x01, // src 10.0.0.1
		0x14, 0x00, 0x00, 0x01, // dst 20.0.0.1
		0x30, 0x39, // UDP src port 12345
		0x00, 0x35, // UDP dst port 53
		0x00, 0x0a, // UDP length 10
		0x49, 0x01, // UDP checksum
		0x68, 0x69, // payload "hi"
	}
	if len(packet) != 44 {
		t.Fatalf("len(packet) = %d, want 44 (14 eth + 20 IP + 8 UDP + 2 payload, padding off)", len(packet))
	}
	if !bytes.Equal(packet, want) {
		t.Errorf("packet mismatch (GRE must not alter the non-GRE path):\n got % x\nwant % x", packet, want)
	}

	// The related GRE variant uses the same MACs/IPs and the UDP datagram
	// as the GRE inner payload: the outer IP protocol becomes 47, the GRE
	// header (flags K + proto IPv4 + key) sits at offset 34, the inner UDP
	// datagram follows it, and the outer total length covers GRE + inner.
	// The Ethernet prefix and the IP fields that do not depend on length
	// (version/TOS, IPID, flags, TTL, addresses) are identical.
	greCfg := config
	greCfg.L3.Protocol = ProtocolGRE
	greCfg.L4 = L4Config{} // no L4: the inner packet lives in Payload
	greCfg.Payload = packet[34:] // the non-GRE frame's UDP datagram
	greCfg.L2.GRE = &GREConfig{ProtocolType: EtherTypeIPv4, KeyPresent: true, Key: 0x11223344}
	grePacket, err := builder.Build(greCfg)
	if err != nil {
		t.Fatalf("Build (GRE) failed: %v", err)
	}
	greLen := 8 // 4 base + 4 key
	if len(grePacket) != len(packet)+greLen {
		t.Fatalf("GRE frame len = %d, want %d (base frame + %d GRE bytes)", len(grePacket), len(packet)+greLen, greLen)
	}
	if !bytes.Equal(grePacket[0:14], packet[0:14]) {
		t.Errorf("Ethernet header changed with GRE enabled:\n got % x\nwant % x", grePacket[0:14], packet[0:14])
	}
	// IP fields independent of the total length/protocol (IPID, flags,
	// TTL, addresses) must be unchanged. Total length [16:18], protocol
	// [23] and the checksum [24:26] legitimately differ (47 vs 17, longer
	// payload).
	if !bytes.Equal(grePacket[14:16], packet[14:16]) || !bytes.Equal(grePacket[18:23], packet[18:23]) || !bytes.Equal(grePacket[26:34], packet[26:34]) {
		t.Errorf("IP fields changed with GRE enabled:\n got % x\nwant % x", grePacket[14:34], packet[14:34])
	}
	// Outer total length covers GRE + inner (20 IP + 8 GRE + 10 inner).
	if total := binary.BigEndian.Uint16(grePacket[16:18]); int(total) != 20+greLen+10 {
		t.Errorf("outer total length = %d, want %d", total, 20+greLen+10)
	}
	// GRE header (flags K + proto IPv4 + key) at offset 34.
	if !bytes.Equal(grePacket[34:42], []byte{0x20, 0x00, 0x08, 0x00, 0x11, 0x22, 0x33, 0x44}) {
		t.Errorf("GRE header = % x, want 20 00 08 00 11 22 33 44", grePacket[34:42])
	}
	// The inner UDP datagram starts right after the GRE header (offset 42).
	if !bytes.Equal(grePacket[42:52], packet[34:44]) {
		t.Errorf("inner datagram = % x, want % x at offset 42", grePacket[42:52], packet[34:44])
	}
}

// TestBuilder_GRE_OuterIPv6 verifies GRE over an outer IPv6 header
// (RFC 2784 §4 supports both): the IPv6 Payload Length field must cover
// GRE + inner payload, the Next Header must be 47, and the GRE header sits
// at offset 14+40 = 54.
func TestBuilder_GRE_OuterIPv6(t *testing.T) {
	builder := NewBuilder()
	config := PacketConfig{
		L2: L2Config{
			SrcMAC:    "02:00:00:00:00:01",
			DstMAC:    "02:00:00:00:00:02",
			EtherType: EtherTypeIPv6,
			GRE: &GREConfig{
				ProtocolType:    EtherTypeIPv6,
				KeyPresent:      true,
				Key:             9,
				SequencePresent: true,
				Sequence:        10,
			},
		},
		L3: L3Config{
			SrcIP:    "2001:db8::1",
			DstIP:    "2001:db8::2",
			Protocol: ProtocolGRE,
			TTL:      64,
		},
		Payload: []byte("inner6"),
	}
	packet, err := builder.Build(config)
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}
	if len(packet) != 14+40+12+len(config.Payload) {
		t.Fatalf("len(packet) = %d, want %d", len(packet), 14+40+12+len(config.Payload))
	}
	// IPv6 Payload Length = GRE header (12) + inner payload.
	if pl := binary.BigEndian.Uint16(packet[18:20]); int(pl) != 12+len(config.Payload) {
		t.Errorf("IPv6 payload length = %d, want %d (GRE header included)", pl, 12+len(config.Payload))
	}
	if packet[20] != ProtocolGRE {
		t.Errorf("IPv6 next header = %d, want 47", packet[20])
	}
	// GRE header at offset 54: flags 0x3000 (K|S), proto 0x86DD, key, seq.
	wantGRE := []byte{0x30, 0x00, 0x86, 0xdd, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x0a}
	if !bytes.Equal(packet[54:66], wantGRE) {
		t.Errorf("GRE header = % x, want % x", packet[54:66], wantGRE)
	}
	if !bytes.Equal(packet[66:], config.Payload) {
		t.Errorf("payload = % x, want % x", packet[66:], config.Payload)
	}
}

// --- PPTP mode (RFC 2637 §4.1) ---

// 2.7/2.8: PPTP mode rejects the standard-mode option bits and an explicit
// Protocol Type that conflicts with the forced 0x880B (PPP).
func TestBuilder_GRE_PPTP_Validate_Errors(t *testing.T) {
	builder := NewBuilder()
	base := PacketConfig{
		L2: L2Config{
			SrcMAC: "02:00:00:00:00:01",
			DstMAC: "02:00:00:00:00:02",
			GRE:    &GREConfig{PPTP: true},
		},
		L3: L3Config{
			SrcIP:    "10.0.0.1",
			DstIP:    "20.0.0.1",
			Protocol: ProtocolGRE,
			TTL:      64,
			IPID:     0x0001,
			Flags:    IPFlagDF,
		},
		Payload: []byte("HELLO"),
	}
	tests := []struct {
		name    string
		mutate  func(*GREConfig)
		wantSub string
	}{
		{"checksum", func(g *GREConfig) { g.Checksum = true }, "never sets the C bit"},
		{"routing", func(g *GREConfig) { g.RoutingPresent = true }, "never sets the R bit"},
		{"key_present", func(g *GREConfig) { g.KeyPresent = true }, "manages the K/S bits itself"},
		{"sequence_present", func(g *GREConfig) { g.SequencePresent = true }, "manages the K/S bits itself"},
		{"protocol_type_ipv4", func(g *GREConfig) { g.ProtocolType = EtherTypeIPv4 }, "forces Protocol Type 0x880B"},
		{"protocol_type_arp", func(g *GREConfig) { g.ProtocolType = EtherTypeARP }, "forces Protocol Type 0x880B"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base
			cfg.L2.GRE = &GREConfig{PPTP: true}
			tc.mutate(cfg.L2.GRE)
			_, err := builder.Build(cfg)
			if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("err = %v, want substring %q", err, tc.wantSub)
			}
		})
	}
}

// 2.9/2.10: the PPTP-GRE header bytes — no AckPresent → 12-byte header with
// flags 0x3001 (K|S|Ver=1); AckPresent → 16-byte header with flags 0x3081
// (K|S|A|Ver=1). In both cases the Key field is split into Payload Length
// (high 16, backfilled by fillPPTPGRE) + Call ID (low 16), protocol 0x880B,
// and the outer IP carries protocol 47 with the total length covering the
// GRE header + payload.
func TestBuilder_GRE_PPTP_HeaderBytes(t *testing.T) {
	builder := NewBuilder()
	noPad := false
	payload := []byte("PPTPDATA") // 8 bytes
	build := func(gre *GREConfig) []byte {
		cfg := PacketConfig{
			L2: L2Config{
				SrcMAC: "02:00:00:00:00:01",
				DstMAC: "02:00:00:00:00:02",
				Pad:    &noPad,
				GRE:    gre,
			},
			L3: L3Config{
				SrcIP:    "10.0.0.1",
				DstIP:    "20.0.0.1",
				Protocol: ProtocolGRE,
				TTL:      64,
				IPID:     0x0001,
				Flags:    IPFlagDF,
			},
			Payload: payload,
		}
		packet, err := builder.Build(cfg)
		if err != nil {
			t.Fatalf("Build failed: %v", err)
		}
		return packet
	}

	// No ack: 12-byte GRE header at offset 34, flags 0x3001.
	p := build(&GREConfig{PPTP: true, CallID: 0x35c9, Sequence: 5})
	if len(p) != 14+20+12+len(payload) {
		t.Fatalf("len = %d, want %d (12-byte header, no ack)", len(p), 14+20+12+len(payload))
	}
	if p[23] != ProtocolGRE {
		t.Errorf("outer IP protocol = %d, want 47", p[23])
	}
	if tl := binary.BigEndian.Uint16(p[16:18]); tl != uint16(20+12+len(payload)) {
		t.Errorf("outer IP total length = %d, want %d", tl, 20+12+len(payload))
	}
	g := p[34:]
	if got := binary.BigEndian.Uint16(g[0:2]); got != 0x3001 {
		t.Errorf("flags = %04x, want 3001 (K|S|Ver=1, no A)", got)
	}
	if got := binary.BigEndian.Uint16(g[2:4]); got != 0x880B {
		t.Errorf("protocol type = %04x, want 880b (PPP)", got)
	}
	if got := binary.BigEndian.Uint16(g[4:6]); got != uint16(len(payload)) {
		t.Errorf("payload length = %d, want %d (Key high 16)", got, len(payload))
	}
	if got := binary.BigEndian.Uint16(g[6:8]); got != 0x35c9 {
		t.Errorf("call id = %04x, want 35c9 (Key low 16)", got)
	}
	if got := binary.BigEndian.Uint32(g[8:12]); got != 5 {
		t.Errorf("sequence = %d, want 5", got)
	}
	if !bytes.Equal(g[12:], payload) {
		t.Errorf("payload must follow the 12-byte header directly")
	}

	// With ack: 16-byte header, flags 0x3081, ack after the sequence.
	p = build(&GREConfig{PPTP: true, CallID: 0xa9c0, Sequence: 7, AckPresent: true, Ack: 3})
	if len(p) != 14+20+16+len(payload) {
		t.Fatalf("len = %d, want %d (16-byte header, with ack)", len(p), 14+20+16+len(payload))
	}
	if tl := binary.BigEndian.Uint16(p[16:18]); tl != uint16(20+16+len(payload)) {
		t.Errorf("outer IP total length = %d, want %d", tl, 20+16+len(payload))
	}
	g = p[34:]
	if got := binary.BigEndian.Uint16(g[0:2]); got != 0x3081 {
		t.Errorf("flags = %04x, want 3081 (K|S|A|Ver=1)", got)
	}
	if got := binary.BigEndian.Uint16(g[4:6]); got != uint16(len(payload)) {
		t.Errorf("payload length = %d, want %d (Key high 16)", got, len(payload))
	}
	if got := binary.BigEndian.Uint16(g[6:8]); got != 0xa9c0 {
		t.Errorf("call id = %04x, want a9c0", got)
	}
	if got := binary.BigEndian.Uint32(g[8:12]); got != 7 {
		t.Errorf("sequence = %d, want 7", got)
	}
	if got := binary.BigEndian.Uint32(g[12:16]); got != 3 {
		t.Errorf("ack = %d, want 3", got)
	}
	if !bytes.Equal(g[16:], payload) {
		t.Errorf("payload must follow the 16-byte header directly")
	}

	// fillPPTPGRE payload length must track a longer payload too (not a
	// hardcoded value): 30-byte payload → Key high 16 = 30.
	big := []byte("0123456789abcdef0123456789abcdef") // 32 bytes
	cfg := PacketConfig{
		L2: L2Config{
			SrcMAC: "02:00:00:00:00:01",
			DstMAC: "02:00:00:00:00:02",
			Pad:    &noPad,
			GRE:    &GREConfig{PPTP: true, CallID: 0x1111, AckPresent: true},
		},
		L3: L3Config{
			SrcIP:    "10.0.0.1",
			DstIP:    "20.0.0.1",
			Protocol: ProtocolGRE,
			TTL:      64,
			IPID:     0x0001,
			Flags:    IPFlagDF,
		},
		Payload: big,
	}
	p, err := builder.Build(cfg)
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}
	if got := binary.BigEndian.Uint16(p[38:40]); got != uint16(len(big)) {
		t.Errorf("payload length = %d, want %d", got, len(big))
	}
	if got := binary.BigEndian.Uint16(p[40:42]); got != 0x1111 {
		t.Errorf("call id = %04x, want 1111", got)
	}
	if !bytes.Equal(p[50:], big) {
		t.Errorf("payload mismatch after the 16-byte header")
	}
}
