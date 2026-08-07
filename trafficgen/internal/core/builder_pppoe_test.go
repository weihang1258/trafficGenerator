package core

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

// Reference bytes are taken from real captured PPPoE traffic (verified with
// tshark -r <file> -x):
//
//	/home/pcap_auto/mypcap/idc3/4.pppoe_sample.pcap  frame 1: LCP
//	  Configure-Request (session data, SessionID 0x000f)
//	/home/pcap_auto/mypcap/idc3/9、pppoe_http.pcap   frame 1: inner IPv4
//	  TCP segment (session data, SessionID 0x1a58)

// TestBuilder_PPPoE_LCPFrame_PcapBytes reproduces pcap 4.pppoe_sample.pcap
// frame 1 byte-for-byte (including the zero padding to 60 bytes):
//
//	00 03 a0 12 30 cc 00 01 00 02 00 03 | 88 64 | 11 00 | 00 0f | 00 10 |
//	c0 21 | 01 01 00 0e 01 04 05 d4 05 06 09 e5 f1 45 | <padding>
//
// Covers (RFC 2516 §4 + RFC 1661 §4/§6): EtherType forced to 0x8864 (Session
// Data), Ver/Type 0x11, Code 0x00, SessionID 0x000f, Payload_Length 0x0010 =
// 16 = 2 (PPP Protocol) + 14 (LCP), PPP Protocol 0xc021 (LCP), LCP
// Configure-Request (code 1, id 1, length 0x000e) with MRU 0x05d4 and
// Magic-Number 0x09e5f145. Padding bytes are zero-filled and NOT counted in
// the PPPoE Payload_Length field.
func TestBuilder_PPPoE_LCPFrame_PcapBytes(t *testing.T) {
	builder := NewBuilder()

	config := PacketConfig{
		L2: L2Config{
			SrcMAC:    "00:01:00:02:00:03",
			DstMAC:    "00:03:a0:12:30:cc",
			EtherType: 0, // must be ignored: PPPoE forces 0x8864
			PPPoE: &PPPoEConfig{
				Code:        PPPoECodeSessionData,
				SessionID:   0x000f,
				PPPProtocol: PPPProtocolLCP, // 0xc021
			},
		},
		// LCP Configure-Request: MRU(0x0104 0x05d4) + Magic-Number(0x0506
		// 09 e5 f1 45), 14 bytes total (RFC 1661 §4.1/§6.1/§6.13).
		Payload: []byte{0x01, 0x01, 0x00, 0x0e, 0x01, 0x04, 0x05, 0xd4, 0x05, 0x06, 0x09, 0xe5, 0xf1, 0x45},
	}

	packet, err := builder.Build(config)
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	// Full frame must be exactly the pcap bytes: 60 bytes (36 data + 24
	// zero padding).
	want := []byte{
		0x00, 0x03, 0xa0, 0x12, 0x30, 0xcc, // dst MAC
		0x00, 0x01, 0x00, 0x02, 0x00, 0x03, // src MAC
		0x88, 0x64, // EtherType = PPPoE Session Data
		0x11, 0x00, // Ver=1 Type=1, Code=0x00 (Session Data)
		0x00, 0x0f, // SessionID = 0x000f
		0x00, 0x10, // Payload_Length = 16 = 2 (PPP proto) + 14 (LCP)
		0xc0, 0x21, // PPP Protocol = LCP
		0x01, 0x01, 0x00, 0x0e, // LCP Configure-Request, id 1, len 14
		0x01, 0x04, 0x05, 0xd4, // option MRU (1492)
		0x05, 0x06, 0x09, 0xe5, 0xf1, 0x45, // option Magic-Number
		// 24 zero padding bytes to reach the 60-byte minimum
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	if len(packet) != 60 {
		t.Fatalf("len(packet) = %d, want 60 (padded to MinEthernetFrame)", len(packet))
	}
	if !bytes.Equal(packet, want) {
		t.Errorf("packet mismatch:\n got % x\nwant % x", packet, want)
	}
}

// TestBuilder_PPPoE_IPv4Session_PcapBytes reproduces pcap
// 9、pppoe_http.pcap frame 1's header fields. The inner IPv4 packet has
// total length 0x01eb (491), so the PPPoE Payload_Length must be 0x01ed =
// 493 = 2 (PPP Protocol 0x0021) + 491 (IPv4 total length) — the Length
// field counts the PPP frame, not the Ethernet frame. Frame is 513 bytes
// (no padding: > 60).
func TestBuilder_PPPoE_IPv4Session_PcapBytes(t *testing.T) {
	builder := NewBuilder()

	// 439-byte payload makes the inner IPv4 total length 0x01eb
	// (20 IP + 32 TCP with TS option + 439 payload), matching the pcap.
	payload := bytes.Repeat([]byte{0x41}, 439)

	config := PacketConfig{
		L2: L2Config{
			SrcMAC: "00:0d:60:7b:2d:9b",
			DstMAC: "00:90:1a:10:15:59",
			PPPoE: &PPPoEConfig{
				Code:        PPPoECodeSessionData,
				SessionID:   0x1a58,
				PPPProtocol: PPPProtocolIPv4, // 0x0021
			},
		},
		L3: L3Config{
			SrcIP:    "213.39.160.150", // d5 27 a0 96
			DstIP:    "193.99.144.85",  // c1 63 90 55
			Protocol: ProtocolTCP,
			TTL:      64,
			IPID:     0xf8a9,
			Flags:    IPFlagDF,
		},
		L4: L4Config{
			Protocol:   "tcp",
			SrcPort:    0x85b7,
			DstPort:    80,
			Seq:        0xc7f8a790,
			Ack:        0x402b3a19,
			Flags:      0x18, // PSH|ACK
			WindowSize: 0x05ac,
			TCPOptions: []TCPOption{
				{Kind: TCPOptNOP},
				{Kind: TCPOptNOP},
				{Kind: TCPOptTimestamp, Data: []byte{0x00, 0x63, 0x5f, 0x71, 0x0c, 0x1b, 0x2c, 0x9f}},
			},
		},
		Payload: payload,
	}

	packet, err := builder.Build(config)
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	// Frame = 14 + 6 (PPPoE) + 2 (PPP proto) + 491 (IPv4) = 513 bytes.
	if len(packet) != 513 {
		t.Fatalf("len(packet) = %d, want 513 (no padding, frame > 60)", len(packet))
	}

	// Ethernet header.
	if !bytes.Equal(packet[0:6], []byte{0x00, 0x90, 0x1a, 0x10, 0x15, 0x59}) {
		t.Errorf("dst MAC = % x, want 00 90 1a 10 15 59", packet[0:6])
	}
	if !bytes.Equal(packet[6:12], []byte{0x00, 0x0d, 0x60, 0x7b, 0x2d, 0x9b}) {
		t.Errorf("src MAC = % x, want 00 0d 60 7b 2d 9b", packet[6:12])
	}
	// PPPoE header (RFC 2516 §4): EtherType | Ver/Type | Code | SessionID |
	// Payload_Length | PPP Protocol.
	wantPPPoE := []byte{
		0x88, 0x64, // EtherType = PPPoE Session Data
		0x11, 0x00, // Ver=1 Type=1, Code=0x00
		0x1a, 0x58, // SessionID = 0x1a58
		0x01, 0xed, // Payload_Length = 493 = 2 + 491
		0x00, 0x21, // PPP Protocol = IPv4
	}
	if !bytes.Equal(packet[12:22], wantPPPoE) {
		t.Errorf("PPPoE header = % x, want % x", packet[12:22], wantPPPoE)
	}

	// Inner IPv4 header (RFC 791): version/IHL, TOS, total length 0x01eb,
	// IPID 0xf8a9, DF, TTL 64, proto 6, checksum, src/dst IPs.
	wantInnerIP := []byte{
		0x45, 0x00, 0x01, 0xeb, 0xf8, 0xa9, 0x40, 0x00,
		0x40, 0x06, 0x78, 0xec, 0xd5, 0x27, 0xa0, 0x96,
		0xc1, 0x63, 0x90, 0x55,
	}
	if !bytes.Equal(packet[22:42], wantInnerIP) {
		t.Errorf("inner IPv4 header = % x, want % x", packet[22:42], wantInnerIP)
	}
	// The IPv4 header checksum (0x78ec, asserted byte-wise above) must be
	// a valid RFC 791 checksum: recomputing over the header INCLUDING the
	// stored checksum field yields 0x0000.
	if got := calculateIPChecksum(packet[22:42]); got != 0x0000 {
		t.Errorf("inner IPv4 header checksum sum = 0x%04x, want 0x0000 (valid RFC 791 header)", got)
	}

	// Inner TCP header: src port 0x85b7, dst port 80, seq/ack from config,
	// data offset 32 (12 option bytes), PSH|ACK, window 0x05ac.
	if !bytes.Equal(packet[42:46], []byte{0x85, 0xb7, 0x00, 0x50}) {
		t.Errorf("inner TCP ports = % x, want 85 b7 00 50", packet[42:46])
	}
	if packet[54] != 0x80 {
		t.Errorf("inner TCP data offset byte = 0x%02x, want 0x80 (32 bytes)", packet[54])
	}
	if packet[55] != 0x18 {
		t.Errorf("inner TCP flags = 0x%02x, want 0x18 (PSH|ACK)", packet[55])
	}
	// Payload follows the 32-byte TCP header (with options) at offset 74.
	if !bytes.Equal(packet[74:], payload) {
		t.Errorf("payload mismatch at offset 74")
	}
}

// TestBuilder_PPPoE_VLAN_Offsets verifies the PPPoE header position with an
// 802.1Q VLAN tag (RFC 2516 §4: the PPPoE header follows the complete
// Ethernet header): [dst 6][src 6][TPID 2][tag 2][EtherType 2][PPPoE 6]
// [PPP proto 2][inner IPv4 20][UDP 8][payload]. l2Len = 18 + 6 + 2 = 26.
func TestBuilder_PPPoE_VLAN_Offsets(t *testing.T) {
	builder := NewBuilder()

	config := PacketConfig{
		L2: L2Config{
			SrcMAC: "aa:bb:cc:dd:ee:01",
			DstMAC: "aa:bb:cc:dd:ee:02",
			VLAN:   &VLAN{ID: 100},
			PPPoE: &PPPoEConfig{
				Code:        PPPoECodeSessionData,
				SessionID:   7,
				PPPProtocol: 0, // default -> 0x0021 IPv4
			},
		},
		L3: L3Config{
			SrcIP:    "10.0.0.1",
			DstIP:    "10.0.0.2",
			Protocol: ProtocolUDP,
			TTL:      64,
		},
		L4: L4Config{
			Protocol: "udp",
			SrcPort:  1000,
			DstPort:  2000,
		},
		Payload: []byte("vlan-pppoe"),
	}

	packet, err := builder.Build(config)
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	// VLAN TPID + tag at 12:16.
	if !bytes.Equal(packet[12:16], []byte{0x81, 0x00, 0x00, 0x64}) {
		t.Errorf("VLAN TPID/tag = % x, want 81 00 00 64", packet[12:16])
	}
	// EtherType forced to 0x8864 at 16:18.
	if !bytes.Equal(packet[16:18], []byte{0x88, 0x64}) {
		t.Errorf("EtherType = % x, want 88 64 (PPPoE session)", packet[16:18])
	}
	// PPPoE header at 18:24. Payload_Length = 2 (PPP proto) + 20 (IPv4) +
	// 8 (UDP) + 10 ("vlan-pppoe") = 40 = 0x0028.
	if !bytes.Equal(packet[18:24], []byte{0x11, 0x00, 0x00, 0x07, 0x00, 0x28}) {
		t.Errorf("PPPoE header = % x, want 11 00 00 07 00 28", packet[18:24])
	}
	// PPP Protocol at 24:26, defaulted to 0x0021 (IPv4).
	if !bytes.Equal(packet[24:26], []byte{0x00, 0x21}) {
		t.Errorf("PPP Protocol = % x, want 00 21 (default IPv4)", packet[24:26])
	}
	// Inner IPv4 header starts at 26 (l2Len = 18+6+2).
	if packet[26] != 0x45 {
		t.Errorf("inner IPv4 version/IHL byte = 0x%02x, want 0x45 at offset 26", packet[26])
	}
	// Payload_Length = 2 + 20 (IP) + 8 (UDP) + len("vlan-pppoe") = 40.
	wantLen := 2 + 20 + 8 + len("vlan-pppoe")
	if got := binary.BigEndian.Uint16(packet[22:24]); int(got) != wantLen {
		t.Errorf("PPPoE Payload_Length = %d, want %d", got, wantLen)
	}
	// Frame length = 26 + 20 + 8 + 10 = 64 (> 60, no padding).
	if len(packet) != 64 {
		t.Errorf("len(packet) = %d, want 64", len(packet))
	}
}

// TestBuilder_PPPoE_DiscoveryPADI verifies a Discovery frame (RFC 2516
// §5.2): EtherType 0x8863, Code 0x09, SessionID 0x0000, Payload_Length =
// tag TLV bytes only (4 for an empty Service-Name tag), no PPP Protocol
// field, no L3/L4, and the frame padded to 60 bytes without touching the
// Length field.
func TestBuilder_PPPoE_DiscoveryPADI(t *testing.T) {
	builder := NewBuilder()

	config := PacketConfig{
		L2: L2Config{
			SrcMAC: "aa:bb:cc:dd:ee:01",
			DstMAC: "ff:ff:ff:ff:ff:ff",
			PPPoE: &PPPoEConfig{
				Code: PPPoECodePADI, // 0x09
				DiscoveryTags: []PPPoETag{
					{Type: PPPoETagServiceName}, // zero-length = any service
				},
			},
		},
	}

	packet, err := builder.Build(config)
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	if len(packet) != 60 {
		t.Fatalf("len(packet) = %d, want 60 (padded)", len(packet))
	}
	want := []byte{
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // dst MAC (broadcast)
		0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01, // src MAC
		0x88, 0x63, // EtherType = PPPoE Discovery
		0x11, 0x09, // Ver=1 Type=1, Code=0x09 (PADI)
		0x00, 0x00, // SessionID = 0x0000 (discovery)
		0x00, 0x04, // Payload_Length = 4 (empty Service-Name tag)
		0x01, 0x01, 0x00, 0x00, // Service-Name tag, zero length
	}
	if !bytes.Equal(packet[0:24], want) {
		t.Errorf("discovery frame = % x, want % x", packet[0:24], want)
	}
	// No PPP Protocol field: the tag bytes start right after the PPPoE
	// header, and everything past the tags is zero padding.
	for i := 24; i < 60; i++ {
		if packet[i] != 0 {
			t.Errorf("packet[%d] = 0x%02x, want 0 (padding)", i, packet[i])
		}
	}
}

// TestBuilder_PPPoE_DiscoveryTags_Serialization verifies multi-tag TLV
// serialization (RFC 2516 §5.1): Tag_Type(2) + Tag_Length(2, value only) +
// Tag_Value, and the Payload_Length = total tag bytes.
func TestBuilder_PPPoE_DiscoveryTags_Serialization(t *testing.T) {
	builder := NewBuilder()

	config := PacketConfig{
		L2: L2Config{
			SrcMAC: "aa:bb:cc:dd:ee:01",
			DstMAC: "aa:bb:cc:dd:ee:02",
			PPPoE: &PPPoEConfig{
				Code: PPPoECodePADO, // 0x07
				DiscoveryTags: []PPPoETag{
					{Type: PPPoETagServiceName, Value: []byte("isp")},
					{Type: PPPoETagACName, Value: []byte("bras1")},
					{Type: PPPoETagACCookie, Value: []byte{0xde, 0xad, 0xbe, 0xef}},
				},
			},
		},
	}

	packet, err := builder.Build(config)
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	// Tags: 3+4+1=7 bytes (Service-Name "isp"), 4+5=9 bytes (AC-Name
	// "bras1"), 4+4=8 bytes (AC-Cookie) = 24 bytes total.
	wantTags := []byte{
		0x01, 0x01, 0x00, 0x03, 'i', 's', 'p',
		0x01, 0x02, 0x00, 0x05, 'b', 'r', 'a', 's', '1',
		0x01, 0x04, 0x00, 0x04, 0xde, 0xad, 0xbe, 0xef,
	}
	if !bytes.Equal(packet[20:44], wantTags) {
		t.Errorf("tags = % x, want % x", packet[20:44], wantTags)
	}
	if got := binary.BigEndian.Uint16(packet[18:20]); got != 24 {
		t.Errorf("Payload_Length = %d, want 24", got)
	}
	if !bytes.Equal(packet[12:14], []byte{0x88, 0x63}) {
		t.Errorf("EtherType = % x, want 88 63 (discovery)", packet[12:14])
	}
}

// TestBuilder_PPPoE_DiscoveryPayloadPath verifies that a Discovery frame
// with pre-serialized tag bytes in Payload (DiscoveryTags empty) passes
// them through verbatim — the builder also supports raw single-frame
// crafting without going through DiscoveryTags.
func TestBuilder_PPPoE_DiscoveryPayloadPath(t *testing.T) {
	builder := NewBuilder()

	tagBytes := []byte{0x01, 0x03, 0x00, 0x02, 'h', 'i'} // Host-Uniq "hi"
	config := PacketConfig{
		L2: L2Config{
			SrcMAC: "aa:bb:cc:dd:ee:01",
			DstMAC: "aa:bb:cc:dd:ee:02",
			PPPoE: &PPPoEConfig{
				Code:          PPPoECodePADR, // 0x19
				SessionID:     0,
				PayloadLength: 6, // deliberate: matches the 6 tag bytes
			},
		},
		Payload: tagBytes,
	}

	packet, err := builder.Build(config)
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	if !bytes.Equal(packet[20:26], tagBytes) {
		t.Errorf("payload = % x, want % x", packet[20:26], tagBytes)
	}
	if !bytes.Equal(packet[14:16], []byte{0x11, 0x19}) {
		t.Errorf("Ver/Code = % x, want 11 19 (PADR)", packet[14:16])
	}
}

// TestBuilder_PPPoE_PayloadLengthOverride verifies the user override: a
// non-zero PayloadLength is written verbatim even when it contradicts the
// actual payload (fault injection for DUT testing, RFC 2516 §4).
func TestBuilder_PPPoE_PayloadLengthOverride(t *testing.T) {
	builder := NewBuilder()

	config := PacketConfig{
		L2: L2Config{
			SrcMAC: "aa:bb:cc:dd:ee:01",
			DstMAC: "aa:bb:cc:dd:ee:02",
			PPPoE: &PPPoEConfig{
				Code:          PPPoECodeSessionData,
				SessionID:     1,
				PPPProtocol:   PPPProtocolLCP,
				PayloadLength: 0x1234, // wrong on purpose
			},
		},
		Payload: []byte{0x01, 0x01, 0x00, 0x04}, // 4-byte LCP
	}

	packet, err := builder.Build(config)
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	if got := binary.BigEndian.Uint16(packet[18:20]); got != 0x1234 {
		t.Errorf("Payload_Length = 0x%04x, want 0x1234 (override)", got)
	}
}

// TestBuilder_PPPoE_PadDisabled verifies Pad=false leaves the short LCP
// frame at its natural size (38 bytes) while the Payload_Length field still
// counts only the PPP frame (16).
func TestBuilder_PPPoE_PadDisabled(t *testing.T) {
	builder := NewBuilder()
	pad := false

	config := PacketConfig{
		L2: L2Config{
			SrcMAC: "aa:bb:cc:dd:ee:01",
			DstMAC: "aa:bb:cc:dd:ee:02",
			Pad:    &pad,
			PPPoE: &PPPoEConfig{
				Code:        PPPoECodeSessionData,
				SessionID:   1,
				PPPProtocol: PPPProtocolLCP,
			},
		},
		Payload: []byte{0x01, 0x01, 0x00, 0x0e, 0x01, 0x04, 0x05, 0xd4, 0x05, 0x06, 0x09, 0xe5, 0xf1, 0x45},
	}

	packet, err := builder.Build(config)
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	if len(packet) != 36 {
		t.Errorf("len(packet) = %d, want 36 (14+6+2+14, no padding)", len(packet))
	}
	if got := binary.BigEndian.Uint16(packet[18:20]); got != 16 {
		t.Errorf("Payload_Length = %d, want 16", got)
	}
}

// TestBuilder_PPPoE_InvalidCode verifies unknown Code values are rejected
// (RFC 2516 §5 defines exactly six codes) rather than emitting a corrupt
// frame.
func TestBuilder_PPPoE_InvalidCode(t *testing.T) {
	builder := NewBuilder()

	config := PacketConfig{
		L2: L2Config{
			SrcMAC: "aa:bb:cc:dd:ee:01",
			DstMAC: "aa:bb:cc:dd:ee:02",
			PPPoE: &PPPoEConfig{
				Code: 0x55,
			},
		},
	}

	_, err := builder.Build(config)
	if err == nil {
		t.Fatal("Build succeeded, want error for invalid code 0x55")
	}
	if !strings.Contains(err.Error(), "invalid code") {
		t.Errorf("error = %q, want mention of invalid code", err.Error())
	}
}

// TestBuilder_PPPoE_ControlPPPWithL3 verifies the L3/L4 contradiction is
// rejected: Session Data with a control PPP Protocol (0xc021 LCP) must
// carry the PPP control message in Payload with no inner L3/L4.
func TestBuilder_PPPoE_ControlPPPWithL3(t *testing.T) {
	builder := NewBuilder()

	config := PacketConfig{
		L2: L2Config{
			SrcMAC: "aa:bb:cc:dd:ee:01",
			DstMAC: "aa:bb:cc:dd:ee:02",
			PPPoE: &PPPoEConfig{
				Code:        PPPoECodeSessionData,
				SessionID:   1,
				PPPProtocol: PPPProtocolLCP,
			},
		},
		L3: L3Config{SrcIP: "10.0.0.1"},
	}

	_, err := builder.Build(config)
	if err == nil {
		t.Fatal("Build succeeded, want error (0xc021 PPP with L3 config)")
	}
	if !strings.Contains(err.Error(), "PPPProtocol") {
		t.Errorf("error = %q, want mention of PPPProtocol", err.Error())
	}
}

// TestBuilder_PPPoE_DiscoveryWithL3L4 verifies Discovery frames reject L3/
// L4 config (a Discovery payload is the tag TLV list and nothing else,
// RFC 2516 §5.1).
func TestBuilder_PPPoE_DiscoveryWithL3L4(t *testing.T) {
	builder := NewBuilder()

	for name, mutate := range map[string]func(*PacketConfig){
		"l3": func(c *PacketConfig) { c.L3.SrcIP = "10.0.0.1" },
		"l4": func(c *PacketConfig) { c.L4.Protocol = "udp" },
	} {
		t.Run(name, func(t *testing.T) {
			config := PacketConfig{
				L2: L2Config{
					SrcMAC: "aa:bb:cc:dd:ee:01",
					DstMAC: "aa:bb:cc:dd:ee:02",
					PPPoE: &PPPoEConfig{
						Code: PPPoECodePADI,
					},
				},
			}
			mutate(&config)
			_, err := builder.Build(config)
			if err == nil {
				t.Fatalf("Build succeeded, want error (discovery with %s)", name)
			}
			if !strings.Contains(err.Error(), "discovery") {
				t.Errorf("error = %q, want mention of discovery", err.Error())
			}
		})
	}
}

// TestBuilder_PPPoE_DiscoveryTagsAndPayload verifies a Discovery frame
// cannot carry both DiscoveryTags and a user Payload (the payload IS the
// tag list — ambiguous config is rejected).
func TestBuilder_PPPoE_DiscoveryTagsAndPayload(t *testing.T) {
	builder := NewBuilder()

	config := PacketConfig{
		L2: L2Config{
			SrcMAC: "aa:bb:cc:dd:ee:01",
			DstMAC: "aa:bb:cc:dd:ee:02",
			PPPoE: &PPPoEConfig{
				Code: PPPoECodePADI,
				DiscoveryTags: []PPPoETag{
					{Type: PPPoETagServiceName},
				},
			},
		},
		Payload: []byte{0x01, 0x01, 0x00, 0x00},
	}

	_, err := builder.Build(config)
	if err == nil {
		t.Fatal("Build succeeded, want error (tags + payload)")
	}
	if !strings.Contains(err.Error(), "both") {
		t.Errorf("error = %q, want mention of both", err.Error())
	}
}

// TestBuilder_PPPoE_LengthOverflow verifies a payload that cannot fit the
// 16-bit Payload_Length field (RFC 2516 §4) is rejected for both Session
// Data (payload bytes) and Discovery (serialized tags).
func TestBuilder_PPPoE_LengthOverflow(t *testing.T) {
	builder := NewBuilder()
	big := make([]byte, 65540) // 2 + 20 + 8 + 65540 > 65535

	t.Run("session-payload", func(t *testing.T) {
		config := PacketConfig{
			L2: L2Config{
				SrcMAC: "aa:bb:cc:dd:ee:01",
				DstMAC: "aa:bb:cc:dd:ee:02",
				PPPoE: &PPPoEConfig{
					Code:        PPPoECodeSessionData,
					SessionID:   1,
					PPPProtocol: PPPProtocolIPv4,
				},
			},
			L3:      L3Config{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", Protocol: ProtocolUDP},
			L4:      L4Config{Protocol: "udp"},
			Payload: big,
		}
		_, err := builder.Build(config)
		if err == nil {
			t.Fatal("Build succeeded, want length overflow error")
		}
		if !strings.Contains(err.Error(), "65535") {
			t.Errorf("error = %q, want mention of 65535", err.Error())
		}
	})

	t.Run("discovery-tags", func(t *testing.T) {
		config := PacketConfig{
			L2: L2Config{
				SrcMAC: "aa:bb:cc:dd:ee:01",
				DstMAC: "aa:bb:cc:dd:ee:02",
				PPPoE: &PPPoEConfig{
					Code: PPPoECodePADI,
					DiscoveryTags: []PPPoETag{
						{Type: PPPoETagServiceName, Value: big},
					},
				},
			},
		}
		_, err := builder.Build(config)
		if err == nil {
			t.Fatal("Build succeeded, want length overflow error")
		}
		if !strings.Contains(err.Error(), "65535") {
			t.Errorf("error = %q, want mention of 65535", err.Error())
		}
	})
}

// TestBuilder_PPPoE_IPv6EtherTypeRejected is a regression test for a crash
// found during the #38 hop-by-hop review: session data forces a 20-byte
// IPv4 inner slot (RFC 1661 §6), but writeL3 dispatches on
// L2Config.EtherType — a config with PPPoE + EtherType 0x86DD used to
// panic in writeL3v6 (slice bounds out of range). It must now be rejected
// with a clear error instead of emitting a corrupt frame.
func TestBuilder_PPPoE_IPv6EtherTypeRejected(t *testing.T) {
	builder := NewBuilder()
	config := PacketConfig{
		L2: L2Config{
			SrcMAC:    "aa:bb:cc:dd:ee:ff",
			DstMAC:    "11:22:33:44:55:66",
			EtherType: EtherTypeIPv6,
			PPPoE:     &PPPoEConfig{Code: PPPoECodeSessionData},
		},
		L3: L3Config{
			SrcIP:    "2001:db8::1",
			DstIP:    "2001:db8::2",
			Protocol: ProtocolUDP,
			TTL:      64,
		},
		L4: L4Config{Protocol: "udp", SrcPort: 12345, DstPort: 53},
	}
	_, err := builder.Build(config)
	if err == nil || !strings.Contains(err.Error(), "IPv4-only inner layer") {
		t.Errorf("err = %v, want IPv4-only inner layer rejection", err)
	}
}
