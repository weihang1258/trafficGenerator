package core

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

// TestBuild_IPv6HopByHop_UDP_RouterAlert verifies the full Build() path for
// an IPv6 UDP packet carrying a hop-by-hop extension header (RFC 8200 §4.3)
// with a Router Alert option (RFC 2711: type 5, 2-octet value). Asserts the
// fixed-header NextHeader chaining (0x00), PayloadLength covering the
// extension header, the extension header bytes (options + PadN to the
// 8-octet boundary), and the shifted L4 offsets.
func TestBuild_IPv6HopByHop_UDP_RouterAlert(t *testing.T) {
	builder := NewBuilder()
	payload := []byte("ping")
	config := PacketConfig{
		L2: L2Config{
			SrcMAC:    "aa:bb:cc:dd:ee:ff",
			DstMAC:    "11:22:33:44:55:66",
			EtherType: EtherTypeIPv6,
		},
		L3: L3Config{
			SrcIP:    "2001:db8::1",
			DstIP:    "2001:db8::2",
			Protocol: 17, // UDP
			TTL:      64,
			HopByHop: []IPv6Option{
				{Type: 5, Value: []byte{0x00, 0x00}}, // Router Alert (RFC 2711)
			},
		},
		L4: L4Config{
			Protocol: "udp",
			SrcPort:  12345,
			DstPort:  53,
		},
		Payload: payload,
	}

	pkt, err := builder.Build(config)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	// 14 (Eth) + 40 (IPv6 fixed) + 8 (hop-by-hop) + 8 (UDP) + 4 = 74 bytes.
	if len(pkt) != 74 {
		t.Errorf("frame length = %d, want 74 (14+40+8+8+4)", len(pkt))
	}
	if got := binary.BigEndian.Uint16(pkt[12:14]); got != EtherTypeIPv6 {
		t.Errorf("EtherType = 0x%04x, want 0x86DD (IPv6)", got)
	}

	// Payload Length at offset 18-19 must cover the extension header too:
	// 8 (hop-by-hop) + 8 (UDP) + 4 (payload) = 20 (RFC 8200 §3).
	if got := binary.BigEndian.Uint16(pkt[18:20]); got != 20 {
		t.Errorf("Payload Length = %d, want 20 (8 ext + 8 UDP + 4 payload)", got)
	}

	// Next Header at offset 20: 0x00 chains to the hop-by-hop header
	// (RFC 8200 §3); the extension header's own NextHeader is 17 (UDP).
	if pkt[20] != 0x00 {
		t.Errorf("Next Header = 0x%02x, want 0x00 (hop-by-hop)", pkt[20])
	}

	// Extension header at offset 54 (14+40): NextHeader=17, HdrExtLen=0
	// (8 octets total, RFC 8200 §4.3), Router Alert option 05 02 00 00,
	// then PadN 01 00 filling to the 8-octet boundary (RFC 8200 §4.2).
	wantExt := []byte{17, 0, 5, 2, 0x00, 0x00, 0x01, 0x00}
	if !bytes.Equal(pkt[54:62], wantExt) {
		t.Errorf("hop-by-hop header = % x, want % x", pkt[54:62], wantExt)
	}

	// UDP header shifted to offset 62 by the extension header.
	if got := binary.BigEndian.Uint16(pkt[62:64]); got != 12345 {
		t.Errorf("UDP SrcPort = %d, want 12345", got)
	}
	if got := binary.BigEndian.Uint16(pkt[64:66]); got != 53 {
		t.Errorf("UDP DstPort = %d, want 53", got)
	}
	if got := binary.BigEndian.Uint16(pkt[66:68]); got != 12 {
		t.Errorf("UDP Length = %d, want 12 (8 hdr + 4 payload)", got)
	}
	if got := binary.BigEndian.Uint16(pkt[68:70]); got == 0 {
		t.Errorf("UDP checksum = 0 on IPv6 — RFC 6936 forbids this")
	}
	if !bytes.Equal(pkt[70:74], payload) {
		t.Errorf("UDP payload = %q, want %q", pkt[70:74], payload)
	}
}

// TestBuild_IPv6HopByHop_ChecksumExcludesExtHeader verifies RFC 8200 §8.1:
// the upper-layer (TCP/UDP) checksum pseudo-header length excludes extension
// headers, so the TCP and UDP checksums of a packet are identical with and
// without the hop-by-hop header. The observable outcome: checksum bytes must
// be equal across the two frames (and non-zero).
func TestBuild_IPv6HopByHop_ChecksumExcludesExtHeader(t *testing.T) {
	builder := NewBuilder()
	base := PacketConfig{
		L2: L2Config{
			SrcMAC:    "aa:bb:cc:dd:ee:ff",
			DstMAC:    "11:22:33:44:55:66",
			EtherType: EtherTypeIPv6,
		},
		L3: L3Config{
			SrcIP:    "2001:db8::1",
			DstIP:    "2001:db8::2",
			Protocol: 6, // TCP
			TTL:      64,
		},
		L4: L4Config{
			Protocol: "tcp",
			SrcPort:  12345,
			DstPort:  80,
			Seq:      1000,
			Flags:    0x02, // SYN
		},
	}
	opts := []IPv6Option{{Type: 5, Value: []byte{0x00, 0x00}}}

	noExt := base
	noExtPkt, err := builder.Build(noExt)
	if err != nil {
		t.Fatalf("Build (no ext): %v", err)
	}
	// TCP header at 14+40, checksum at +16 → frame offset 70.
	noExtSum := noExtPkt[70:72]

	withExt := base
	withExt.L3.HopByHop = opts
	withExtPkt, err := builder.Build(withExt)
	if err != nil {
		t.Fatalf("Build (with ext): %v", err)
	}
	// TCP header shifted by 8 → checksum at frame offset 78.
	withExtSum := withExtPkt[78:80]

	if !bytes.Equal(withExtSum, noExtSum) {
		t.Errorf("TCP checksum with hop-by-hop % x != without % x — RFC 8200 §8.1 says the pseudo-header length excludes extension headers", withExtSum, noExtSum)
	}
	if noExtSum[0] == 0 && noExtSum[1] == 0 {
		t.Errorf("TCP checksum = 0 — invalid")
	}

	// UDP variant: same rule, checksum over UDP header + payload only.
	udpBase := base
	udpBase.L3.Protocol = 17
	udpBase.L4 = L4Config{Protocol: "udp", SrcPort: 54321, DstPort: 53}
	udpBase.Payload = []byte("hello")

	udpNoExt := udpBase
	udpNoExtPkt, err := builder.Build(udpNoExt)
	if err != nil {
		t.Fatalf("Build (udp no ext): %v", err)
	}
	// UDP header at 14+40, checksum at +6 → frame offset 60.
	udpNoExtSum := udpNoExtPkt[60:62]

	udpWithExt := udpBase
	udpWithExt.L3.HopByHop = opts
	udpWithExtPkt, err := builder.Build(udpWithExt)
	if err != nil {
		t.Fatalf("Build (udp with ext): %v", err)
	}
	// UDP checksum at frame offset 68.
	udpWithExtSum := udpWithExtPkt[68:70]

	if !bytes.Equal(udpWithExtSum, udpNoExtSum) {
		t.Errorf("UDP checksum with hop-by-hop % x != without % x — RFC 8200 §8.1", udpWithExtSum, udpNoExtSum)
	}
	if udpNoExtSum[0] == 0 && udpNoExtSum[1] == 0 {
		t.Errorf("UDP checksum = 0 — RFC 6936 forbids this on IPv6")
	}
}

// TestBuild_IPv6HopByHop_Pad1 verifies single-octet alignment padding:
// with options totaling 7 octets (Pad1 + Router Alert), the header is
// completed with a single Pad1 option (RFC 8200 §4.2: one octet of padding
// uses Pad1, two or more use PadN).
func TestBuild_IPv6HopByHop_Pad1(t *testing.T) {
	builder := NewBuilder()
	config := PacketConfig{
		L2: L2Config{
			SrcMAC:    "aa:bb:cc:dd:ee:ff",
			DstMAC:    "11:22:33:44:55:66",
			EtherType: EtherTypeIPv6,
		},
		L3: L3Config{
			SrcIP:    "2001:db8::1",
			DstIP:    "2001:db8::2",
			Protocol: 17,
			TTL:      64,
			HopByHop: []IPv6Option{
				{Type: 0x00},               // Pad1
				{Type: 5, Value: []byte{0, 0}}, // Router Alert: 4 octets
			},
		},
		L4: L4Config{Protocol: "udp", SrcPort: 1, DstPort: 2},
	}

	pkt, err := builder.Build(config)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	// 2 fixed + 1 Pad1 + 4 option = 7 → one more Pad1 octet completes 8.
	wantExt := []byte{17, 0, 0x00, 5, 2, 0, 0, 0x00}
	if !bytes.Equal(pkt[54:62], wantExt) {
		t.Errorf("hop-by-hop header = % x, want % x", pkt[54:62], wantExt)
	}
}

// TestSerializeIPv6HopByHop checks the extension-header serializer byte for
// byte: NextHeader, HdrExtLen (8-octet units after the first 8), option
// encoding (Type + Opt Data Len + Value), and Pad1/PadN completion. Case B
// exercises HdrExtLen=1 (16-octet header).
func TestSerializeIPv6HopByHop(t *testing.T) {
	cases := []struct {
		name     string
		options  []IPv6Option
		nextHdr  uint8
		want     []byte
		wantLen  int
	}{
		{
			name:    "router alert single option",
			options: []IPv6Option{{Type: 5, Value: []byte{0, 0}}},
			nextHdr: 17,
			want:    []byte{17, 0, 5, 2, 0, 0, 1, 0},
			wantLen: 8,
		},
		{
			name: "two options 16-octet header",
			options: []IPv6Option{
				{Type: 1, Value: []byte{0, 0}}, // PadN 4 octets
				{Type: 5, Value: []byte{0, 0}}, // Router Alert 4 octets
			},
			nextHdr: 6,
			want:    []byte{6, 1, 1, 2, 0, 0, 5, 2, 0, 0, 1, 4, 0, 0, 0, 0},
			wantLen: 16,
		},
		{
			name:     "pad1 completes 8 octets",
			options:  []IPv6Option{{Type: 0}, {Type: 5, Value: []byte{0, 0}}},
			nextHdr:  17,
			want:     []byte{17, 0, 0, 5, 2, 0, 0, 0},
			wantLen:  8,
		},
		{
			name: "long option shifts hdrexlen",
			options: []IPv6Option{
				{Type: 0xC2, Value: []byte{0, 0, 0, 100}}, // Jumbo Payload (RFC 2675)
			},
			nextHdr: 17,
			want:    []byte{17, 0, 0xC2, 4, 0, 0, 0, 100},
			wantLen: 8,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := hopByHopHeaderLen(tc.options); got != tc.wantLen {
				t.Errorf("hopByHopHeaderLen = %d, want %d", got, tc.wantLen)
			}
			got := serializeIPv6HopByHop(tc.options, tc.nextHdr)
			if !bytes.Equal(got, tc.want) {
				t.Errorf("serialize = % x, want % x", got, tc.want)
			}
		})
	}
}

// TestBuild_IPv6HopByHop_Validation covers the negative paths: options on
// IPv4 (RFC 8200 §4.3 is IPv6-only), an option Value over the 8-bit Opt
// Data Len field (255 maximum, RFC 8200 §4.2), a total header over the
// 2048-octet HdrExtLen limit (RFC 8200 §4.3), and PPPoE's IPv4-only inner
// layer. The boundary case (7 max-size options = 1808 octets) must still
// build.
func TestBuild_IPv6HopByHop_Validation(t *testing.T) {
	builder := NewBuilder()
	v6 := L3Config{
		SrcIP:    "2001:db8::1",
		DstIP:    "2001:db8::2",
		Protocol: 17,
		TTL:      64,
	}
	cfg := func(l3 L3Config, etherType uint16) PacketConfig {
		return PacketConfig{
			L2:      L2Config{SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66", EtherType: etherType},
			L3:      l3,
			L4:      L4Config{Protocol: "udp", SrcPort: 1, DstPort: 2},
			Payload: []byte("x"),
		}
	}

	t.Run("ipv4 frame rejected", func(t *testing.T) {
		l3 := v6
		l3.HopByHop = []IPv6Option{{Type: 5, Value: []byte{0, 0}}}
		_, err := builder.Build(cfg(l3, EtherTypeIPv4))
		if err == nil || !strings.Contains(err.Error(), "require an IPv6 frame") {
			t.Errorf("err = %v, want IPv6-frame rejection", err)
		}
	})

	t.Run("value over 255 rejected", func(t *testing.T) {
		l3 := v6
		l3.HopByHop = []IPv6Option{{Type: 5, Value: make([]byte, 256)}}
		_, err := builder.Build(cfg(l3, EtherTypeIPv6))
		if err == nil || !strings.Contains(err.Error(), "Opt Data Len") {
			t.Errorf("err = %v, want Opt Data Len rejection", err)
		}
	})

	t.Run("header over 2048 rejected", func(t *testing.T) {
		l3 := v6
		opts := make([]IPv6Option, 8)
		for i := range opts {
			opts[i] = IPv6Option{Type: 5, Value: make([]byte, 255)}
		}
		l3.HopByHop = opts
		_, err := builder.Build(cfg(l3, EtherTypeIPv6))
		if err == nil || !strings.Contains(err.Error(), "2048-octet maximum") {
			t.Errorf("err = %v, want 2048-octet maximum rejection", err)
		}
	})

	t.Run("2048 boundary accepted", func(t *testing.T) {
		l3 := v6
		opts := make([]IPv6Option, 7) // 2 + 7*257 = 1801 → 1808 octets
		for i := range opts {
			opts[i] = IPv6Option{Type: 5, Value: make([]byte, 255)}
		}
		l3.HopByHop = opts
		if _, err := builder.Build(cfg(l3, EtherTypeIPv6)); err != nil {
			t.Errorf("Build: %v, want success at 1808 octets", err)
		}
	})

	t.Run("pppoe inner layer rejected", func(t *testing.T) {
		l3 := v6
		l3.HopByHop = []IPv6Option{{Type: 5, Value: []byte{0, 0}}}
		c := cfg(l3, EtherTypeIPv6)
		c.L2.PPPoE = &PPPoEConfig{Code: PPPoECodeSessionData}
		_, err := builder.Build(c)
		if err == nil || !strings.Contains(err.Error(), "IPv4-only inner layer") {
			t.Errorf("err = %v, want PPPoE inner-layer rejection", err)
		}
	})
}

// TestL3Base_CopiesHopByHop verifies L3Base propagates the flow-level
// hop-by-hop option list into the L3Config, so planners using L3Base (all
// IPv6 planners) inherit it without extra code.
func TestL3Base_CopiesHopByHop(t *testing.T) {
	opts := []IPv6Option{{Type: 5, Value: []byte{0, 0}}}
	spec := FlowSpec{
		SrcIP:    "2001:db8::1",
		DstIP:    "2001:db8::2",
		HopByHop: opts,
	}
	l3 := L3Base(spec.SrcIP, spec.DstIP, 17, 64, 0, spec)
	if len(l3.HopByHop) != 1 || l3.HopByHop[0].Type != 5 {
		t.Fatalf("L3Base.HopByHop = %+v, want the flow-level option list", l3.HopByHop)
	}
}

// TestMapToFlowSpec_HopByHop verifies the "hop_by_hop" JSON key parses into
// FlowSpec.HopByHop (an array of {type, value} option objects), and that
// absent/non-array/empty input yields nil (plain IPv6 header).
func TestMapToFlowSpec_HopByHop(t *testing.T) {
	t.Run("two options parsed", func(t *testing.T) {
		cfg := map[string]interface{}{
			"hop_by_hop": []interface{}{
				map[string]interface{}{"type": float64(5), "value": "\x00\x00"},
				map[string]interface{}{"type": float64(0xC2), "value": "\x00\x00\x00d"},
			},
		}
		spec := mapToFlowSpec(cfg, "udp")
		if len(spec.HopByHop) != 2 {
			t.Fatalf("HopByHop = %+v, want 2 options", spec.HopByHop)
		}
		if spec.HopByHop[0].Type != 5 || !bytes.Equal(spec.HopByHop[0].Value, []byte{0, 0}) {
			t.Errorf("option[0] = %+v, want {5, [0 0]}", spec.HopByHop[0])
		}
		if spec.HopByHop[1].Type != 0xC2 || !bytes.Equal(spec.HopByHop[1].Value, []byte{0, 0, 0, 'd'}) {
			t.Errorf("option[1] = %+v, want {0xC2, [0 0 0 d]}", spec.HopByHop[1])
		}
	})

	t.Run("absent yields nil", func(t *testing.T) {
		if spec := mapToFlowSpec(map[string]interface{}{}, "udp"); spec.HopByHop != nil {
			t.Errorf("HopByHop = %+v, want nil", spec.HopByHop)
		}
	})

	t.Run("non-array yields nil", func(t *testing.T) {
		cfg := map[string]interface{}{"hop_by_hop": "05 02"}
		if spec := mapToFlowSpec(cfg, "udp"); spec.HopByHop != nil {
			t.Errorf("HopByHop = %+v, want nil for non-array", spec.HopByHop)
		}
	})

	t.Run("empty array yields nil", func(t *testing.T) {
		cfg := map[string]interface{}{"hop_by_hop": []interface{}{}}
		if spec := mapToFlowSpec(cfg, "udp"); spec.HopByHop != nil {
			t.Errorf("HopByHop = %+v, want nil for empty array", spec.HopByHop)
		}
	})

	t.Run("non-object entries dropped", func(t *testing.T) {
		cfg := map[string]interface{}{"hop_by_hop": []interface{}{"x"}}
		if spec := mapToFlowSpec(cfg, "udp"); spec.HopByHop != nil {
			t.Errorf("HopByHop = %+v, want nil for non-object entries", spec.HopByHop)
		}
	})
}
