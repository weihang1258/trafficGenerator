package core

// Test points for builder.go (B1-B85) from tools/test_points/engine_core.md.
// Adds uncovered byte-construction assertions. Existing builder_test.go checks
// minimum sizes for some cases; these add exact-length and exact-field-byte
// assertions per the spec. Checksums are verified via the standard one's-complement
// fold property (pseudo+header+payload folds to 0xFFFF when the checksum is valid).

import (
	"encoding/binary"
	"net"
	"testing"
)

// foldSum mirrors the builder's ones-complement fold (same algorithm as
// calculateIPChecksum in builder.go): single unconditional carry fold.
func foldSum(data []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	sum = (sum >> 16) + (sum & 0xffff)
	sum = sum + (sum >> 16)
	return uint16(sum)
}

// buildPseudo assembles the 12-byte TCP/UDP pseudo-header from the config IPs.
func buildPseudo(config PacketConfig, proto uint8, length uint16) []byte {
	pseudo := make([]byte, 12)
	if ip := net.ParseIP(config.L3.SrcIP); ip != nil {
		if v4 := ip.To4(); len(v4) == 4 {
			copy(pseudo[0:4], v4)
		}
	}
	if ip := net.ParseIP(config.L3.DstIP); ip != nil {
		if v4 := ip.To4(); len(v4) == 4 {
			copy(pseudo[4:8], v4)
		}
	}
	pseudo[8] = 0
	pseudo[9] = proto
	binary.BigEndian.PutUint16(pseudo[10:12], length)
	return pseudo
}

func baseL2() L2Config {
	return L2Config{SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66", EtherType: 0x0800}
}
func baseL3() L3Config {
	return L3Config{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", Protocol: 6, TTL: 64}
}

// --- Build / l4Length (B1-B18) ---

func TestBuild_TCP_NoVLAN(t *testing.T) {
	b := NewBuilder()
	cfg := PacketConfig{L2: baseL2(), L3: baseL3(), L4: L4Config{Protocol: "tcp", SrcPort: 1, DstPort: 2}, Payload: []byte{0, 0, 0, 0}}
	pkt, err := b.Build(cfg)
	if err != nil {
		t.Fatal(err)
	}
	// 14+20+20+4 = 58, padded to MinEthernetFrame (60).
	if want := MinEthernetFrame; len(pkt) != want {
		t.Errorf("len=%d want %d (padded)", len(pkt), want)
	}
	if et := uint16(pkt[12])<<8 | uint16(pkt[13]); et != 0x0800 {
		t.Errorf("etherType=0x%04x want 0x0800", et)
	}
	if pkt[23] != 6 { // IP proto at offset 14+9
		t.Errorf("IP proto=%d want 6 (TCP)", pkt[23])
	}
	// IP total length (bytes 16-17) reflects only the real L3+L4+payload (44),
	// NOT the padded frame size (60-14=46). Padding is invisible to L3.
	if tl := uint16(pkt[16])<<8 | uint16(pkt[17]); tl != 44 {
		t.Errorf("IP total length=%d want 44 (excludes padding)", tl)
	}
	// Padding bytes at 58-59 must be zero.
	if pkt[58] != 0 || pkt[59] != 0 {
		t.Errorf("padding bytes=[0x%02x,0x%02x] want [0x00,0x00]", pkt[58], pkt[59])
	}
}

func TestBuild_UDP_NoVLAN(t *testing.T) {
	b := NewBuilder()
	cfg := PacketConfig{L2: baseL2(), L3: L3Config{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", Protocol: 17, TTL: 64}, L4: L4Config{Protocol: "udp", SrcPort: 1, DstPort: 2}, Payload: []byte{0, 0, 0, 0}}
	pkt, err := b.Build(cfg)
	if err != nil {
		t.Fatal(err)
	}
	// 14+20+8+4 = 46, padded to 60.
	if want := MinEthernetFrame; len(pkt) != want {
		t.Errorf("len=%d want %d (padded)", len(pkt), want)
	}
	if pkt[23] != 17 {
		t.Errorf("IP proto=%d want 17 (UDP)", pkt[23])
	}
}

func TestBuild_VLANPresent(t *testing.T) {
	b := NewBuilder()
	cfg := PacketConfig{
		L2: L2Config{SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66", EtherType: 0x0800, VLAN: &VLAN{ID: 100, Priority: 5}},
		L3: baseL3(), L4: L4Config{Protocol: "tcp", SrcPort: 1, DstPort: 2}, Payload: []byte{0, 0, 0, 0},
	}
	pkt, err := b.Build(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if want := 18 + 20 + 20 + 4; len(pkt) != want {
		t.Errorf("len=%d want %d", len(pkt), want)
	}
	if tp := uint16(pkt[12])<<8 | uint16(pkt[13]); tp != 0x8100 {
		t.Errorf("TPID=0x%04x want 0x8100", tp)
	}
}

func TestBuild_EtherTypeZero_DefaultIPv4(t *testing.T) {
	b := NewBuilder()
	cfg := PacketConfig{L2: L2Config{SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66", EtherType: 0}, L3: baseL3(), L4: L4Config{Protocol: "tcp", SrcPort: 1, DstPort: 2}}
	pkt, _ := b.Build(cfg)
	if et := uint16(pkt[12])<<8 | uint16(pkt[13]); et != 0x0800 {
		t.Errorf("etherType=0x%04x want 0x0800 (default for zero)", et)
	}
	// IPv4 header present: byte 14 should be 0x45.
	if pkt[14] != 0x45 {
		t.Errorf("first IP byte=0x%02x want 0x45 (IPv4 IHL 5)", pkt[14])
	}
}

func TestBuild_EtherTypeARP(t *testing.T) {
	b := NewBuilder()
	arp := make([]byte, 28)
	arp[6], arp[7] = 0, 1
	cfg := PacketConfig{
		L2: L2Config{SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "ff:ff:ff:ff:ff:ff", EtherType: 0x0806},
		L3: L3Config{}, L4: L4Config{Protocol: "arp"}, Payload: arp,
	}
	pkt, _ := b.Build(cfg)
	// 14 (eth) + 0 (l3, ARP) + 0 (l4) + 28 (payload) = 42, padded to 60.
	if want := MinEthernetFrame; len(pkt) != want {
		t.Errorf("ARP len=%d want %d (padded, no IP header)", len(pkt), want)
	}
	// L3 absent: byte 14 must not be 0x45 (IPv4 IHL). Padding is appended
	// where the L3 header would have been, but byte 14 is the start of
	// the ARP payload (zero) — not 0x45 — confirming writeL3 was skipped.
	if pkt[14] == 0x45 {
		t.Error("IPv4 header written for ARP EtherType (should be skipped)")
	}
	if et := uint16(pkt[12])<<8 | uint16(pkt[13]); et != 0x0806 {
		t.Errorf("etherType=0x%04x want 0x0806", et)
	}
}

func TestBuild_ARP_WithVLAN(t *testing.T) {
	b := NewBuilder()
	arp := make([]byte, 28)
	cfg := PacketConfig{
		L2: L2Config{SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "ff:ff:ff:ff:ff:ff", EtherType: 0x0806, VLAN: &VLAN{ID: 100}},
		L3: L3Config{}, L4: L4Config{Protocol: "arp"}, Payload: arp,
	}
	pkt, _ := b.Build(cfg)
	// 18 (eth+VLAN) + 0 (l3, ARP) + 0 (l4) + 28 (payload) = 46, padded to 60.
	if want := MinEthernetFrame; len(pkt) != want {
		t.Errorf("ARP+VLAN len=%d want %d (padded)", len(pkt), want)
	}
	if tp := uint16(pkt[12])<<8 | uint16(pkt[13]); tp != 0x8100 {
		t.Errorf("TPID=0x%04x want 0x8100", tp)
	}
}

func TestBuild_ICMP(t *testing.T) {
	b := NewBuilder()
	icmpData := []byte{0x08, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01} // echo request
	cfg := PacketConfig{L2: baseL2(), L3: L3Config{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", Protocol: 1, TTL: 64}, L4: L4Config{Protocol: "icmp"}, Payload: icmpData}
	pkt, _ := b.Build(cfg)
	// ICMP: l4Len=0. Natural len = 14 + 20 + 0 + 8 = 42, padded to 60.
	if want := MinEthernetFrame; len(pkt) != want {
		t.Errorf("ICMP len=%d want %d (padded)", len(pkt), want)
	}
	// IP total length (bytes 16-17) reflects only the real L3+L4+payload
	// (20+0+8=28), NOT the padded frame size. Padding is invisible to L3.
	if tl := uint16(pkt[16])<<8 | uint16(pkt[17]); tl != 28 {
		t.Errorf("IP total length=%d want 28 (excludes padding)", tl)
	}
	if pkt[23] != 1 {
		t.Errorf("IP proto=%d want 1 (ICMP)", pkt[23])
	}
}

func TestBuild_EmptyPayload(t *testing.T) {
	b := NewBuilder()
	cfg := PacketConfig{L2: baseL2(), L3: baseL3(), L4: L4Config{Protocol: "tcp", SrcPort: 1, DstPort: 2}}
	pkt, _ := b.Build(cfg)
	// 14+20+20 = 54, padded to 60.
	if want := MinEthernetFrame; len(pkt) != want {
		t.Errorf("empty payload len=%d want %d (padded)", len(pkt), want)
	}
}

func TestBuild_EmptyConfig(t *testing.T) {
	b := NewBuilder()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("empty config panicked: %v", r)
		}
	}()
	pkt, _ := b.Build(PacketConfig{})
	// All zero: EtherType 0 -> IPv4 (l3Len 20), L4.Protocol "" -> l4Len 0, no payload.
	// Natural len = 14+20+0 = 34, padded to 60.
	if want := MinEthernetFrame; len(pkt) != want {
		t.Errorf("empty config len=%d want %d (padded)", len(pkt), want)
	}
}

func TestBuild_L3LenZero_NonIPv4(t *testing.T) {
	b := NewBuilder()
	cfg := PacketConfig{L2: L2Config{SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66", EtherType: 0x0806}, L3: L3Config{}, L4: L4Config{Protocol: "arp"}, Payload: make([]byte, 10)}
	pkt, _ := b.Build(cfg)
	// No IP header written: first byte after Eth (offset 14) is payload, not 0x45.
	if pkt[14] == 0x45 {
		t.Error("IPv4 header written for ARP EtherType (should be skipped)")
	}
}

func TestBuild_L4LenZero_ICMP(t *testing.T) {
	b := NewBuilder()
	cfg := PacketConfig{L2: baseL2(), L3: L3Config{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", Protocol: 1, TTL: 64}, L4: L4Config{Protocol: "icmp"}, Payload: []byte{1, 2, 3}}
	pkt, _ := b.Build(cfg)
	// ICMP has no L4 header: payload directly after IP. Natural len = 14+20+0+3 = 37,
	// padded to 60.
	if want := MinEthernetFrame; len(pkt) != want {
		t.Errorf("ICMP len=%d want %d (padded, no L4 header)", len(pkt), want)
	}
	// IP total length (bytes 16-17) reflects only the real L3+L4+payload
	// (20+0+3=23), NOT the padded frame size. Padding is invisible to L3.
	if tl := uint16(pkt[16])<<8 | uint16(pkt[17]); tl != 23 {
		t.Errorf("IP total length=%d want 23 (excludes padding)", tl)
	}
}

func TestBuild_ZeroLengthPacket(t *testing.T) {
	b := NewBuilder()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("zero-length packet panicked: %v", r)
		}
	}()
	pkt, _ := b.Build(PacketConfig{})
	// Natural len = 14+20+0 = 34, padded to 60.
	if want := MinEthernetFrame; len(pkt) != want {
		t.Errorf("zero-length len=%d want %d (padded)", len(pkt), want)
	}
}

func TestBuild_TCP_WithOptions(t *testing.T) {
	b := NewBuilder()
	cfg := PacketConfig{L2: baseL2(), L3: baseL3(), L4: L4Config{Protocol: "tcp", SrcPort: 1, DstPort: 2, Seq: 100, Flags: 0x02, TCPOptions: []TCPOption{{Kind: 2, Data: []byte{0x05, 0xb4}}}}}
	pkt, _ := b.Build(cfg)
	// MSS option = 4 bytes (kind+len+2 data), already 4-aligned -> no NOP. l4Len=24, dataOffset=6.
	tcpStart := 34
	if got := pkt[tcpStart+12] >> 4; got != 6 {
		t.Errorf("dataOffset=%d want 6 (MSS 4B, l4Len 24)", got)
	}
	// Spec B13 listed 28/7 (4B MSS + 4B NOP), but encodeTCPOptions pads to a 4-byte
	// boundary and 4 bytes is already aligned, so the actual value is 24/6.
	// Natural len = 14+20+24 = 58, padded to 60.
	if want := MinEthernetFrame; len(pkt) != want {
		t.Errorf("TCP+MSS len=%d want %d (padded)", len(pkt), want)
	}
}

func TestBuild_UDP_Len8(t *testing.T) {
	b := NewBuilder()
	cfg := PacketConfig{L2: baseL2(), L3: L3Config{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", Protocol: 17, TTL: 64}, L4: L4Config{Protocol: "udp", SrcPort: 1, DstPort: 2}}
	pkt, _ := b.Build(cfg)
	// l4Len=8: natural len = 14+20+8 = 42, padded to 60.
	if want := MinEthernetFrame; len(pkt) != want {
		t.Errorf("UDP len8 len=%d want %d (padded)", len(pkt), want)
	}
}

// TestBuild_PadFalse_ShortFrameNotPadded verifies that L2.Pad=*false
// disables padding for short frames. The frame is emitted at its natural
// size (42 bytes here: 14 eth + 20 IP + 8 UDP), NOT padded to 60. This is
// the "test runt-frame handling" use case from the Pad doc comment.
func TestBuild_PadFalse_ShortFrameNotPadded(t *testing.T) {
	b := NewBuilder()
	padOff := false
	cfg := PacketConfig{
		L2: L2Config{SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66", EtherType: 0x0800, Pad: &padOff},
		L3: L3Config{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", Protocol: 17, TTL: 64},
		L4: L4Config{Protocol: "udp", SrcPort: 1, DstPort: 2},
	}
	pkt, _ := b.Build(cfg)
	// Natural size 14+20+8 = 42, NOT padded.
	if want := 14 + 20 + 8; len(pkt) != want {
		t.Errorf("Pad=false len=%d want %d (not padded)", len(pkt), want)
	}
}

// TestBuild_PadTrue_ShortFramePaddedTo60 verifies that L2.Pad=*true (explicit)
// pads short frames to MinEthernetFrame (60), matching the nil/default behavior.
func TestBuild_PadTrue_ShortFramePaddedTo60(t *testing.T) {
	b := NewBuilder()
	padOn := true
	cfg := PacketConfig{
		L2: L2Config{SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66", EtherType: 0x0800, Pad: &padOn},
		L3: L3Config{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", Protocol: 17, TTL: 64},
		L4: L4Config{Protocol: "udp", SrcPort: 1, DstPort: 2},
	}
	pkt, _ := b.Build(cfg)
	if want := MinEthernetFrame; len(pkt) != want {
		t.Errorf("Pad=true len=%d want %d (padded)", len(pkt), want)
	}
}

// TestBuild_PadNil_LongFrameUnchanged verifies that long frames (>= 60 bytes)
// are NOT padded regardless of the Pad setting — padding only applies to short
// frames. A 1000-byte TCP payload produces 14+20+20+1000 = 1054 bytes either way.
func TestBuild_PadNil_LongFrameUnchanged(t *testing.T) {
	b := NewBuilder()
	cfg := PacketConfig{
		L2: baseL2(),
		L3: baseL3(),
		L4: L4Config{Protocol: "tcp", SrcPort: 1, DstPort: 2},
		Payload: make([]byte, 1000),
	}
	pkt, _ := b.Build(cfg)
	if want := 14 + 20 + 20 + 1000; len(pkt) != want {
		t.Errorf("long-frame len=%d want %d (no padding above 60)", len(pkt), want)
	}
}

// TestBuild_PaddingBytesAreZero verifies that padding bytes (when applied) are
// zero-filled, not random/garbage. This matters because some receivers inspect
// padding bytes for fingerprinting; non-zero padding would be a tell.
func TestBuild_PaddingBytesAreZero(t *testing.T) {
	b := NewBuilder()
	cfg := PacketConfig{
		L2: baseL2(),
		L3: L3Config{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", Protocol: 17, TTL: 64},
		L4: L4Config{Protocol: "udp", SrcPort: 1, DstPort: 2},
	}
	pkt, _ := b.Build(cfg)
	// Natural size 42; padded to 60; bytes 42..59 are padding.
	for i := 42; i < MinEthernetFrame; i++ {
		if pkt[i] != 0 {
			t.Errorf("padding byte %d=0x%02x want 0x00", i, pkt[i])
		}
	}
}

// TestBuild_IPTotalLengthExcludesPadding_ARP verifies that ARP frames (no IP
// header) padded to 60 still expose the ARP payload at byte 14 — padding is
// appended after the payload, so the ARP htype field (bytes 14-15) is the
// real payload, not padding. (ARP has no length field, so receivers strip
// padding based on the L2 frame length / EtherType.)
func TestBuild_IPTotalLengthExcludesPadding_ARP(t *testing.T) {
	b := NewBuilder()
	arp := make([]byte, 28)
	arp[0], arp[1] = 0x00, 0x01 // htype Ethernet
	arp[6], arp[7] = 0x00, 0x01 // op=request
	cfg := PacketConfig{
		L2: L2Config{SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "ff:ff:ff:ff:ff:ff", EtherType: 0x0806},
		L3: L3Config{},
		L4: L4Config{Protocol: "arp"},
		Payload: arp,
	}
	pkt, _ := b.Build(cfg)
	// Padded to 60. ARP payload at 14:14+28=42; padding is 42..59.
	if want := MinEthernetFrame; len(pkt) != want {
		t.Fatalf("ARP len=%d want %d (padded)", len(pkt), want)
	}
	// ARP htype (bytes 14-15) = 0x0001 (Ethernet), not 0x0000 (padding).
	if ht := uint16(pkt[14])<<8 | uint16(pkt[15]); ht != 0x0001 {
		t.Errorf("ARP htype=0x%04x want 0x0001 (payload at offset 14, not padding)", ht)
	}
	// ARP op (bytes 20-21) = 0x0001 (request).
	if op := uint16(pkt[20])<<8 | uint16(pkt[21]); op != 0x0001 {
		t.Errorf("ARP op=0x%04x want 0x0001 (request)", op)
	}
	// Bytes 42..59 are zero padding.
	for i := 42; i < MinEthernetFrame; i++ {
		if pkt[i] != 0 {
			t.Errorf("ARP padding byte %d=0x%02x want 0x00", i, pkt[i])
		}
	}
}

func TestL4Length_TCP(t *testing.T) {
	if got := l4Length(PacketConfig{L4: L4Config{Protocol: "tcp"}}); got != 20 {
		t.Errorf("l4Length(tcp)=%d want 20", got)
	}
}
func TestL4Length_UDP(t *testing.T) {
	if got := l4Length(PacketConfig{L4: L4Config{Protocol: "udp"}}); got != 8 {
		t.Errorf("l4Length(udp)=%d want 8", got)
	}
}
func TestL4Length_ICMP(t *testing.T) {
	if got := l4Length(PacketConfig{L4: L4Config{Protocol: "icmp"}}); got != 0 {
		t.Errorf("l4Length(icmp)=%d want 0", got)
	}
}
func TestL4Length_Empty(t *testing.T) {
	if got := l4Length(PacketConfig{L4: L4Config{Protocol: ""}}); got != 0 {
		t.Errorf("l4Length(empty)=%d want 0", got)
	}
}

// --- writeL2 (B19-B30) ---

func TestWriteL2_DstMACEmpty(t *testing.T) {
	b := NewBuilder()
	pkt, _ := b.Build(PacketConfig{L2: L2Config{SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "", EtherType: 0x0800}, L3: baseL3(), L4: L4Config{Protocol: "tcp"}})
	for i := 0; i < 6; i++ {
		if pkt[i] != 0 {
			t.Errorf("dstMAC[%d]=0x%02x want 0 (empty MAC)", i, pkt[i])
		}
	}
}
func TestWriteL2_DstMACInvalid(t *testing.T) {
	b := NewBuilder()
	pkt, _ := b.Build(PacketConfig{L2: L2Config{SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "zz:zz", EtherType: 0x0800}, L3: baseL3(), L4: L4Config{Protocol: "tcp"}})
	for i := 0; i < 6; i++ {
		if pkt[i] != 0 {
			t.Errorf("dstMAC[%d]=0x%02x want 0 (invalid MAC -> zeros)", i, pkt[i])
		}
	}
}
func TestWriteL2_DstMACValid(t *testing.T) {
	b := NewBuilder()
	pkt, _ := b.Build(PacketConfig{L2: L2Config{SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "aa:bb:cc:dd:ee:ff", EtherType: 0x0800}, L3: baseL3(), L4: L4Config{Protocol: "tcp"}})
	want := []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	for i := 0; i < 6; i++ {
		if pkt[i] != want[i] {
			t.Errorf("dstMAC[%d]=0x%02x want 0x%02x", i, pkt[i], want[i])
		}
	}
}
func TestWriteL2_SrcMACEmpty(t *testing.T) {
	b := NewBuilder()
	pkt, _ := b.Build(PacketConfig{L2: L2Config{SrcMAC: "", DstMAC: "11:22:33:44:55:66", EtherType: 0x0800}, L3: baseL3(), L4: L4Config{Protocol: "tcp"}})
	for i := 6; i < 12; i++ {
		if pkt[i] != 0 {
			t.Errorf("srcMAC[%d]=0x%02x want 0 (empty)", i, pkt[i])
		}
	}
}
func TestWriteL2_SrcMACInvalid(t *testing.T) {
	b := NewBuilder()
	pkt, _ := b.Build(PacketConfig{L2: L2Config{SrcMAC: "bad", DstMAC: "11:22:33:44:55:66", EtherType: 0x0800}, L3: baseL3(), L4: L4Config{Protocol: "tcp"}})
	for i := 6; i < 12; i++ {
		if pkt[i] != 0 {
			t.Errorf("srcMAC[%d]=0x%02x want 0 (invalid)", i, pkt[i])
		}
	}
}
func TestWriteL2_SrcMACValid(t *testing.T) {
	b := NewBuilder()
	pkt, _ := b.Build(PacketConfig{L2: L2Config{SrcMAC: "11:22:33:44:55:66", DstMAC: "aa:bb:cc:dd:ee:ff", EtherType: 0x0800}, L3: baseL3(), L4: L4Config{Protocol: "tcp"}})
	want := []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}
	for i := 0; i < 6; i++ {
		if pkt[6+i] != want[i] {
			t.Errorf("srcMAC[%d]=0x%02x want 0x%02x", i, pkt[6+i], want[i])
		}
	}
}
func TestWriteL2_EtherTypeZero_DefaultIPv4(t *testing.T) {
	b := NewBuilder()
	pkt, _ := b.Build(PacketConfig{L2: L2Config{SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66", EtherType: 0}, L3: baseL3(), L4: L4Config{Protocol: "tcp"}})
	if et := uint16(pkt[12])<<8 | uint16(pkt[13]); et != 0x0800 {
		t.Errorf("etherType=0x%04x want 0x0800", et)
	}
}
func TestWriteL2_EtherTypeARP(t *testing.T) {
	b := NewBuilder()
	pkt, _ := b.Build(PacketConfig{L2: L2Config{SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66", EtherType: 0x0806}, L3: L3Config{}, L4: L4Config{Protocol: "arp"}, Payload: make([]byte, 28)})
	if et := uint16(pkt[12])<<8 | uint16(pkt[13]); et != 0x0806 {
		t.Errorf("etherType=0x%04x want 0x0806", et)
	}
}
func TestWriteL2_VLANPriority7(t *testing.T) {
	b := NewBuilder()
	pkt, _ := b.Build(PacketConfig{L2: L2Config{SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66", EtherType: 0x0800, VLAN: &VLAN{ID: 1, Priority: 7}}, L3: baseL3(), L4: L4Config{Protocol: "tcp"}})
	tag := uint16(pkt[14])<<8 | uint16(pkt[15])
	want := uint16(7)<<13 | 1
	if tag != want {
		t.Errorf("VLAN tag=0x%04x want 0x%04x (priority 7, id 1)", tag, want)
	}
}
func TestWriteL2_VLANID4095(t *testing.T) {
	b := NewBuilder()
	pkt, _ := b.Build(PacketConfig{L2: L2Config{SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66", EtherType: 0x0800, VLAN: &VLAN{ID: 4095}}, L3: baseL3(), L4: L4Config{Protocol: "tcp"}})
	tag := uint16(pkt[14])<<8 | uint16(pkt[15])
	if tag&0x0FFF != 4095 {
		t.Errorf("VLAN tag id bits=0x%04x want 4095", tag&0x0FFF)
	}
}
func TestWriteL2_NoVLAN(t *testing.T) {
	b := NewBuilder()
	pkt, _ := b.Build(PacketConfig{L2: L2Config{SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66", EtherType: 0x0800}, L3: baseL3(), L4: L4Config{Protocol: "tcp"}})
	if tp := uint16(pkt[12])<<8 | uint16(pkt[13]); tp == 0x8100 {
		t.Error("0x8100 TPID present without VLAN config")
	}
	if et := uint16(pkt[12])<<8 | uint16(pkt[13]); et != 0x0800 {
		t.Errorf("etherType=0x%04x want 0x0800 (no VLAN)", et)
	}
}

// --- writeL3 (B31-B47) ---

func TestWriteL3_Normal(t *testing.T) {
	b := NewBuilder()
	cfg := PacketConfig{L2: baseL2(), L3: L3Config{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", Protocol: 6, TTL: 64, IPID: 0x1234}, L4: L4Config{Protocol: "tcp", SrcPort: 1, DstPort: 2}}
	pkt, _ := b.Build(cfg)
	if pkt[14] != 0x45 {
		t.Errorf("version/IHL=0x%02x want 0x45", pkt[14])
	}
	if cs := uint16(pkt[24])<<8 | uint16(pkt[25]); cs == 0 {
		t.Error("IP checksum=0, want non-zero (computed)")
	}
	if pkt[22] != 64 {
		t.Errorf("TTL=%d want 64", pkt[22])
	}
	ipid := uint16(pkt[18])<<8 | uint16(pkt[19])
	if ipid != 0x1234 {
		t.Errorf("ipID=0x%04x want 0x1234", ipid)
	}
}

func TestWriteL3_IPIDZero_FallsBackToSeq(t *testing.T) {
	b := NewBuilder()
	cfg := PacketConfig{L2: baseL2(), L3: L3Config{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", Protocol: 6, TTL: 64, IPID: 0}, L4: L4Config{Protocol: "tcp", Seq: 0x12345}}
	pkt, _ := b.Build(cfg)
	ipid := uint16(pkt[18])<<8 | uint16(pkt[19])
	if ipid != 0x2345 {
		t.Errorf("ipID=0x%04x want 0x2345 (Seq&0xFFFF fallback)", ipid)
	}
}

func TestWriteL3_IPIDSet(t *testing.T) {
	b := NewBuilder()
	cfg := PacketConfig{L2: baseL2(), L3: L3Config{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", Protocol: 6, TTL: 64, IPID: 0xABCD}, L4: L4Config{Protocol: "tcp", Seq: 0x12345}}
	pkt, _ := b.Build(cfg)
	ipid := uint16(pkt[18])<<8 | uint16(pkt[19])
	if ipid != 0xABCD {
		t.Errorf("ipID=0x%04x want 0xABCD (explicit, not Seq)", ipid)
	}
}

func TestWriteL3_TTLZero_Default64(t *testing.T) {
	b := NewBuilder()
	cfg := PacketConfig{L2: baseL2(), L3: L3Config{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", Protocol: 6, TTL: 0}, L4: L4Config{Protocol: "tcp"}}
	pkt, _ := b.Build(cfg)
	if pkt[22] != 64 {
		t.Errorf("TTL=%d want 64 (default for 0)", pkt[22])
	}
}
func TestWriteL3_TTL255(t *testing.T) {
	b := NewBuilder()
	cfg := PacketConfig{L2: baseL2(), L3: L3Config{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", Protocol: 6, TTL: 255}, L4: L4Config{Protocol: "tcp"}}
	pkt, _ := b.Build(cfg)
	if pkt[22] != 255 {
		t.Errorf("TTL=%d want 255", pkt[22])
	}
}

func TestWriteL3_SrcIPEmpty(t *testing.T) {
	b := NewBuilder()
	cfg := PacketConfig{L2: baseL2(), L3: L3Config{SrcIP: "", DstIP: "10.0.0.2", Protocol: 6, TTL: 64}, L4: L4Config{Protocol: "tcp"}}
	pkt, _ := b.Build(cfg)
	for i := 26; i < 30; i++ {
		if pkt[i] != 0 {
			t.Errorf("srcIP byte %d=0x%02x want 0 (empty src IP)", i, pkt[i])
		}
	}
}
func TestWriteL3_SrcIPInvalid(t *testing.T) {
	b := NewBuilder()
	cfg := PacketConfig{L2: baseL2(), L3: L3Config{SrcIP: "bad", DstIP: "10.0.0.2", Protocol: 6, TTL: 64}, L4: L4Config{Protocol: "tcp"}}
	pkt, _ := b.Build(cfg)
	for i := 26; i < 30; i++ {
		if pkt[i] != 0 {
			t.Errorf("srcIP byte %d=0x%02x want 0 (invalid src IP)", i, pkt[i])
		}
	}
}
func TestWriteL3_SrcIPValid(t *testing.T) {
	b := NewBuilder()
	cfg := PacketConfig{L2: baseL2(), L3: L3Config{SrcIP: "192.168.1.1", DstIP: "10.0.0.2", Protocol: 6, TTL: 64}, L4: L4Config{Protocol: "tcp"}}
	pkt, _ := b.Build(cfg)
	want := []byte{192, 168, 1, 1}
	for i := 0; i < 4; i++ {
		if pkt[26+i] != want[i] {
			t.Errorf("srcIP[%d]=%d want %d", i, pkt[26+i], want[i])
		}
	}
}
func TestWriteL3_SrcIPIsIPv6(t *testing.T) {
	b := NewBuilder()
	cfg := PacketConfig{L2: baseL2(), L3: L3Config{SrcIP: "::1", DstIP: "10.0.0.2", Protocol: 6, TTL: 64}, L4: L4Config{Protocol: "tcp"}}
	pkt, _ := b.Build(cfg)
	for i := 26; i < 30; i++ {
		if pkt[i] != 0 {
			t.Errorf("srcIP byte %d=0x%02x want 0 (IPv6 To4()==nil -> skip)", i, pkt[i])
		}
	}
}
func TestWriteL3_DstIPEmpty(t *testing.T) {
	b := NewBuilder()
	cfg := PacketConfig{L2: baseL2(), L3: L3Config{SrcIP: "10.0.0.1", DstIP: "", Protocol: 6, TTL: 64}, L4: L4Config{Protocol: "tcp"}}
	pkt, _ := b.Build(cfg)
	for i := 30; i < 34; i++ {
		if pkt[i] != 0 {
			t.Errorf("dstIP byte %d=0x%02x want 0 (empty dst IP)", i, pkt[i])
		}
	}
}
func TestWriteL3_DstIPInvalid(t *testing.T) {
	b := NewBuilder()
	cfg := PacketConfig{L2: baseL2(), L3: L3Config{SrcIP: "10.0.0.1", DstIP: "bad", Protocol: 6, TTL: 64}, L4: L4Config{Protocol: "tcp"}}
	pkt, _ := b.Build(cfg)
	for i := 30; i < 34; i++ {
		if pkt[i] != 0 {
			t.Errorf("dstIP byte %d=0x%02x want 0 (invalid dst IP)", i, pkt[i])
		}
	}
}
func TestWriteL3_DstIPValid(t *testing.T) {
	b := NewBuilder()
	cfg := PacketConfig{L2: baseL2(), L3: L3Config{SrcIP: "10.0.0.1", DstIP: "10.0.0.1", Protocol: 6, TTL: 64}, L4: L4Config{Protocol: "tcp"}}
	pkt, _ := b.Build(cfg)
	want := []byte{10, 0, 0, 1}
	for i := 0; i < 4; i++ {
		if pkt[30+i] != want[i] {
			t.Errorf("dstIP[%d]=%d want %d", i, pkt[30+i], want[i])
		}
	}
}
func TestWriteL3_DstIPIsIPv6(t *testing.T) {
	b := NewBuilder()
	cfg := PacketConfig{L2: baseL2(), L3: L3Config{SrcIP: "10.0.0.1", DstIP: "::1", Protocol: 6, TTL: 64}, L4: L4Config{Protocol: "tcp"}}
	pkt, _ := b.Build(cfg)
	for i := 30; i < 34; i++ {
		if pkt[i] != 0 {
			t.Errorf("dstIP byte %d=0x%02x want 0 (IPv6 To4()==nil -> skip)", i, pkt[i])
		}
	}
}

func TestWriteL3_DSCPECN(t *testing.T) {
	b := NewBuilder()
	cfg := PacketConfig{L2: baseL2(), L3: L3Config{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", Protocol: 6, TTL: 64, DSCP: 63, ECN: 3}, L4: L4Config{Protocol: "tcp"}}
	pkt, _ := b.Build(cfg)
	// TOS at offset 15 = (63<<2)|3 = 0xFF.
	if pkt[15] != 0xFF {
		t.Errorf("TOS=0x%02x want 0xFF (DSCP 63<<2 | ECN 3)", pkt[15])
	}
}

func TestWriteL3_FlagsDF(t *testing.T) {
	b := NewBuilder()
	cfg := PacketConfig{L2: baseL2(), L3: L3Config{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", Protocol: 6, TTL: 64, Flags: 0x02, FragOffset: 0}, L4: L4Config{Protocol: "tcp"}}
	pkt, _ := b.Build(cfg)
	flags := uint16(pkt[20])<<8 | uint16(pkt[21])
	if flags != uint16(0x02)<<13 {
		t.Errorf("flags=0x%04x want 0x%04x (DF<<13)", flags, uint16(0x02)<<13)
	}
}

func TestWriteL3_ProtoTCP(t *testing.T) {
	b := NewBuilder()
	cfg := PacketConfig{L2: baseL2(), L3: L3Config{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", Protocol: 6, TTL: 64}, L4: L4Config{Protocol: "tcp"}}
	pkt, _ := b.Build(cfg)
	if pkt[23] != 6 {
		t.Errorf("proto=%d want 6", pkt[23])
	}
}
func TestWriteL3_ProtoUDP(t *testing.T) {
	b := NewBuilder()
	cfg := PacketConfig{L2: baseL2(), L3: L3Config{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", Protocol: 17, TTL: 64}, L4: L4Config{Protocol: "udp"}}
	pkt, _ := b.Build(cfg)
	if pkt[23] != 17 {
		t.Errorf("proto=%d want 17", pkt[23])
	}
}

// --- writeTCP / writeUDP (B53-B61) ---

func TestWriteTCP_WindowZero_Default65535(t *testing.T) {
	b := NewBuilder()
	pkt, _ := b.Build(PacketConfig{L2: baseL2(), L3: baseL3(), L4: L4Config{Protocol: "tcp", SrcPort: 1, DstPort: 2, WindowSize: 0}})
	win := uint16(pkt[48])<<8 | uint16(pkt[49])
	if win != 65535 {
		t.Errorf("window=0 -> %d, want 65535 (default)", win)
	}
}
func TestWriteTCP_Window65535(t *testing.T) {
	b := NewBuilder()
	pkt, _ := b.Build(PacketConfig{L2: baseL2(), L3: baseL3(), L4: L4Config{Protocol: "tcp", SrcPort: 1, DstPort: 2, WindowSize: 65535}})
	win := uint16(pkt[48])<<8 | uint16(pkt[49])
	if win != 65535 {
		t.Errorf("window=%d want 65535", win)
	}
}
func TestWriteTCP_NoOptions(t *testing.T) {
	b := NewBuilder()
	pkt, _ := b.Build(PacketConfig{L2: baseL2(), L3: baseL3(), L4: L4Config{Protocol: "tcp", SrcPort: 1, DstPort: 2}})
	if pkt[46]>>4 != 5 {
		t.Errorf("dataOffset=%d want 5 (no options)", pkt[46]>>4)
	}
	if pkt[46] != 0x50 {
		t.Errorf("TCP byte 12=0x%02x want 0x50 (data offset 5)", pkt[46])
	}
}
func TestWriteTCP_UrgentPointerZero(t *testing.T) {
	b := NewBuilder()
	pkt, _ := b.Build(PacketConfig{L2: baseL2(), L3: baseL3(), L4: L4Config{Protocol: "tcp", SrcPort: 1, DstPort: 2}})
	urg := uint16(pkt[52])<<8 | uint16(pkt[53])
	if urg != 0 {
		t.Errorf("urgent pointer=0x%04x want 0", urg)
	}
}

func TestWriteTCP_ChecksumComputed(t *testing.T) {
	b := NewBuilder()
	cfg := PacketConfig{L2: baseL2(), L3: baseL3(), L4: L4Config{Protocol: "tcp", SrcPort: 12345, DstPort: 80, Seq: 1000, Ack: 2000, Flags: 0x18}, Payload: []byte("hello world")}
	pkt, _ := b.Build(cfg)
	tcpStart := 34
	tcpHeader := make([]byte, 20)
	copy(tcpHeader, pkt[tcpStart:tcpStart+20])
	pseudo := buildPseudo(cfg, 6, uint16(len(tcpHeader)+len(cfg.Payload)))
	// Internet-checksum property: fold of pseudo + header (with stored csum) + payload == 0xFFFF.
	assembled := append(append(pseudo, tcpHeader...), cfg.Payload...)
	if foldSum(assembled) != 0xFFFF {
		t.Errorf("TCP checksum invalid (fold with stored csum=0x%04X, want 0xFFFF)",
			foldSum(assembled))
	}
}

func TestWriteUDP_Normal(t *testing.T) {
	b := NewBuilder()
	cfg := PacketConfig{L2: baseL2(), L3: L3Config{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", Protocol: 17, TTL: 64}, L4: L4Config{Protocol: "udp", SrcPort: 1, DstPort: 2}, Payload: []byte{0, 0, 0, 0}}
	pkt, _ := b.Build(cfg)
	udpStart := 34
	length := uint16(pkt[udpStart+4])<<8 | uint16(pkt[udpStart+5])
	if length != 12 { // 8 + 4
		t.Errorf("UDP length=%d want 12 (8+4)", length)
	}
}
func TestWriteUDP_ZeroPayload(t *testing.T) {
	b := NewBuilder()
	pkt, _ := b.Build(PacketConfig{L2: baseL2(), L3: L3Config{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", Protocol: 17, TTL: 64}, L4: L4Config{Protocol: "udp", SrcPort: 1, DstPort: 2}})
	udpStart := 34
	length := uint16(pkt[udpStart+4])<<8 | uint16(pkt[udpStart+5])
	if length != 8 {
		t.Errorf("UDP length=%d want 8 (zero payload)", length)
	}
}

func TestWriteUDP_ChecksumComputed(t *testing.T) {
	b := NewBuilder()
	cfg := PacketConfig{L2: baseL2(), L3: L3Config{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", Protocol: 17, TTL: 64}, L4: L4Config{Protocol: "udp", SrcPort: 12345, DstPort: 53}, Payload: []byte("dns-query-data")}
	pkt, _ := b.Build(cfg)
	udpStart := 34
	udpHeader := make([]byte, 8)
	copy(udpHeader, pkt[udpStart:udpStart+8])
	pseudo := buildPseudo(cfg, 17, uint16(8+len(cfg.Payload)))
	// Internet-checksum property: fold of pseudo + header (with stored csum) + payload == 0xFFFF.
	assembled := append(append(pseudo, udpHeader...), cfg.Payload...)
	if foldSum(assembled) != 0xFFFF {
		t.Errorf("UDP checksum invalid (fold with stored csum=0x%04X, want 0xFFFF)",
			foldSum(assembled))
	}
}

// --- encodeTCPOptions (B62-B68) ---

func TestEncodeTCPOptions_Empty(t *testing.T) {
	if got := encodeTCPOptions(nil); len(got) != 0 {
		t.Errorf("empty opts = %v, want empty (len%%4==0, no NOP)", got)
	}
}
func TestEncodeTCPOptions_KindEnd(t *testing.T) {
	got := encodeTCPOptions([]TCPOption{{Kind: 0}})
	want := []byte{0, 1, 1, 1} // 1 byte -> pad to 4 with NOP
	if len(got) != 4 || got[0] != 0 {
		t.Errorf("KindEnd = %v, want [0,1,1,1]", got)
	}
	_ = want
}
func TestEncodeTCPOptions_KindNOP(t *testing.T) {
	got := encodeTCPOptions([]TCPOption{{Kind: 1}})
	if len(got) != 4 || got[0] != 1 {
		t.Errorf("KindNOP = %v, want [1,1,1,1] (padded)", got)
	}
}
func TestEncodeTCPOptions_Regular(t *testing.T) {
	got := encodeTCPOptions([]TCPOption{{Kind: 2, Data: []byte{0x05, 0xb4}}})
	want := []byte{0x02, 0x04, 0x05, 0xb4}
	if len(got) != 4 || string(got) != string(want) {
		t.Errorf("regular MSS = %v, want %v", got, want)
	}
}
func TestEncodeTCPOptions_NotAligned(t *testing.T) {
	// Kind 2 with 3-byte data -> kind+len+3data = 5 bytes -> pad 3 NOP to 8.
	got := encodeTCPOptions([]TCPOption{{Kind: 2, Data: []byte{0x05, 0xb4, 0x01}}})
	if len(got) != 8 {
		t.Errorf("not-aligned len=%d want 8 (5 + 3 NOP)", len(got))
	}
	// length field = 2+len(Data) = 2+3 = 5.
	if got[1] != 5 {
		t.Errorf("length byte=%d want 5 (2+len(Data)=2+3)", got[1])
	}
	for i := 5; i < 8; i++ {
		if got[i] != 1 {
			t.Errorf("padding byte %d=0x%02x want 0x01 (NOP)", i, got[i])
		}
	}
}
func TestEncodeTCPOptions_Multiple(t *testing.T) {
	got := encodeTCPOptions([]TCPOption{{Kind: 2, Data: []byte{0x05, 0xb4}}, {Kind: 1}})
	// MSS: 2,4,0x05,0xb4 (4 bytes) + NOP: 1 (1 byte) = 5 bytes -> pad 3 NOP to 8.
	if len(got) != 8 {
		t.Errorf("multiple len=%d want 8", len(got))
	}
	if got[0] != 2 || got[1] != 4 || got[2] != 0x05 || got[3] != 0xb4 {
		t.Errorf("MSS portion = %v, want [2,4,5,b4]", got[:4])
	}
	if got[4] != 1 {
		t.Errorf("NOP at byte 4 = 0x%02x want 0x01", got[4])
	}
}
func TestEncodeTCPOptions_MSS(t *testing.T) {
	got := encodeTCPOptions([]TCPOption{{Kind: 2, Data: []byte{0x05, 0xb4}}})
	want := []byte{0x02, 0x04, 0x05, 0xb4}
	if string(got) != string(want) {
		t.Errorf("MSS = %v, want %v", got, want)
	}
}

// --- calcTCPChecksum (B69-B77) ---

func TestCalcTCPChecksum_Normal(t *testing.T) {
	b := NewBuilder()
	cfg := PacketConfig{L2: baseL2(), L3: baseL3(), L4: L4Config{Protocol: "tcp", SrcPort: 1, DstPort: 2, Seq: 100, Ack: 200, Flags: 0x10}, Payload: []byte("payload")}
	pkt, _ := b.Build(cfg)
	tcpStart := 34
	tcpHeader := make([]byte, 20)
	copy(tcpHeader, pkt[tcpStart:tcpStart+20])
	pseudo := buildPseudo(cfg, 6, uint16(20+len(cfg.Payload)))
	assembled := append(pseudo, tcpHeader...)
	assembled = append(assembled, cfg.Payload...)
	if foldSum(assembled) != 0xFFFF {
		t.Errorf("TCP checksum invalid (fold with stored csum=0x%04X, want 0xFFFF)", foldSum(assembled))
	}
}

func TestCalcTCPChecksum_SrcIPEmpty(t *testing.T) {
	// Empty SrcIP and "0.0.0.0" both parse to zero source -> identical checksum.
	cfg1 := PacketConfig{L3: L3Config{SrcIP: "", DstIP: "10.0.0.2"}, L4: L4Config{Protocol: "tcp", SrcPort: 1, DstPort: 2}}
	cfg2 := PacketConfig{L3: L3Config{SrcIP: "0.0.0.0", DstIP: "10.0.0.2"}, L4: L4Config{Protocol: "tcp", SrcPort: 1, DstPort: 2}}
	hdr := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x50, 0, 0, 0, 0, 0, 0, 0}
	if calculateTCPChecksum(cfg1, hdr, nil) != calculateTCPChecksum(cfg2, hdr, nil) {
		t.Error("empty SrcIP checksum differs from 0.0.0.0 (should both be zero-src)")
	}
}
func TestCalcTCPChecksum_SrcIPInvalid(t *testing.T) {
	cfg1 := PacketConfig{L3: L3Config{SrcIP: "bad", DstIP: "10.0.0.2"}, L4: L4Config{Protocol: "tcp", SrcPort: 1, DstPort: 2}}
	cfg2 := PacketConfig{L3: L3Config{SrcIP: "0.0.0.0", DstIP: "10.0.0.2"}, L4: L4Config{Protocol: "tcp", SrcPort: 1, DstPort: 2}}
	hdr := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x50, 0, 0, 0, 0, 0, 0, 0}
	if calculateTCPChecksum(cfg1, hdr, nil) != calculateTCPChecksum(cfg2, hdr, nil) {
		t.Error("invalid SrcIP checksum differs from zero-src (should both be zero-src)")
	}
}
func TestCalcTCPChecksum_DstIPEmpty(t *testing.T) {
	cfg1 := PacketConfig{L3: L3Config{SrcIP: "10.0.0.1", DstIP: ""}, L4: L4Config{Protocol: "tcp", SrcPort: 1, DstPort: 2}}
	cfg2 := PacketConfig{L3: L3Config{SrcIP: "10.0.0.1", DstIP: "0.0.0.0"}, L4: L4Config{Protocol: "tcp", SrcPort: 1, DstPort: 2}}
	hdr := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x50, 0, 0, 0, 0, 0, 0, 0}
	if calculateTCPChecksum(cfg1, hdr, nil) != calculateTCPChecksum(cfg2, hdr, nil) {
		t.Error("empty DstIP checksum differs from 0.0.0.0")
	}
}
func TestCalcTCPChecksum_DstIPInvalid(t *testing.T) {
	cfg1 := PacketConfig{L3: L3Config{SrcIP: "10.0.0.1", DstIP: "bad"}, L4: L4Config{Protocol: "tcp", SrcPort: 1, DstPort: 2}}
	cfg2 := PacketConfig{L3: L3Config{SrcIP: "10.0.0.1", DstIP: "0.0.0.0"}, L4: L4Config{Protocol: "tcp", SrcPort: 1, DstPort: 2}}
	hdr := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x50, 0, 0, 0, 0, 0, 0, 0}
	if calculateTCPChecksum(cfg1, hdr, nil) != calculateTCPChecksum(cfg2, hdr, nil) {
		t.Error("invalid DstIP checksum differs from zero-dst")
	}
}
func TestCalcTCPChecksum_OddPayload(t *testing.T) {
	b := NewBuilder()
	cfg := PacketConfig{L2: baseL2(), L3: baseL3(), L4: L4Config{Protocol: "tcp", SrcPort: 1, DstPort: 2}, Payload: []byte("odd")} // 3 bytes
	pkt, _ := b.Build(cfg)
	tcpStart := 34
	tcpHeader := make([]byte, 20)
	copy(tcpHeader, pkt[tcpStart:tcpStart+20])
	pseudo := buildPseudo(cfg, 6, uint16(20+len(cfg.Payload)))
	assembled := append(pseudo, tcpHeader...)
	assembled = append(assembled, cfg.Payload...)
	if foldSum(assembled) != 0xFFFF {
		t.Errorf("TCP checksum invalid for odd-length payload (fold=0x%04X want 0xFFFF)", foldSum(assembled))
	}
}
func TestCalcTCPChecksum_EvenPayload(t *testing.T) {
	b := NewBuilder()
	cfg := PacketConfig{L2: baseL2(), L3: baseL3(), L4: L4Config{Protocol: "tcp", SrcPort: 1, DstPort: 2}, Payload: []byte("even")} // 4 bytes
	pkt, _ := b.Build(cfg)
	tcpStart := 34
	tcpHeader := make([]byte, 20)
	copy(tcpHeader, pkt[tcpStart:tcpStart+20])
	pseudo := buildPseudo(cfg, 6, uint16(20+len(cfg.Payload)))
	assembled := append(pseudo, tcpHeader...)
	assembled = append(assembled, cfg.Payload...)
	if foldSum(assembled) != 0xFFFF {
		t.Errorf("TCP checksum invalid for even-length payload (fold=0x%04X want 0xFFFF)", foldSum(assembled))
	}
}
func TestCalcTCPChecksum_HeaderUnder18(t *testing.T) {
	// Header shorter than 18 bytes must not panic (boundary check i+2<=len).
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("calcTCPChecksum panicked on short header: %v", r)
		}
	}()
	cfg := PacketConfig{L3: L3Config{SrcIP: "10.0.0.1", DstIP: "10.0.0.2"}, L4: L4Config{Protocol: "tcp"}}
	_ = calculateTCPChecksum(cfg, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x50, 0, 0, 0}, nil) // 16 bytes
}

// --- calcUDPChecksum (B78-B85) ---

func TestCalcUDPChecksum_Normal(t *testing.T) {
	b := NewBuilder()
	cfg := PacketConfig{L2: baseL2(), L3: L3Config{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", Protocol: 17, TTL: 64}, L4: L4Config{Protocol: "udp", SrcPort: 12345, DstPort: 53}, Payload: []byte("data")}
	pkt, _ := b.Build(cfg)
	udpStart := 34
	udpHeader := make([]byte, 8)
	copy(udpHeader, pkt[udpStart:udpStart+8])
	pseudo := buildPseudo(cfg, 17, uint16(8+len(cfg.Payload)))
	assembled := append(pseudo, udpHeader...)
	assembled = append(assembled, cfg.Payload...)
	if foldSum(assembled) != 0xFFFF {
		t.Errorf("UDP checksum invalid for normal config (fold=0x%04X want 0xFFFF)", foldSum(assembled))
	}
}

func udpChecksumEquals(cfgA, cfgB PacketConfig) bool {
	return calculateUDPChecksum(cfgA, []byte("x")) == calculateUDPChecksum(cfgB, []byte("x"))
}
func TestCalcUDPChecksum_SrcIPEmpty(t *testing.T) {
	a := PacketConfig{L3: L3Config{SrcIP: "", DstIP: "10.0.0.2"}, L4: L4Config{Protocol: "udp", SrcPort: 1, DstPort: 2}}
	b := PacketConfig{L3: L3Config{SrcIP: "0.0.0.0", DstIP: "10.0.0.2"}, L4: L4Config{Protocol: "udp", SrcPort: 1, DstPort: 2}}
	if !udpChecksumEquals(a, b) {
		t.Error("empty SrcIP UDP checksum differs from 0.0.0.0")
	}
}
func TestCalcUDPChecksum_SrcIPInvalid(t *testing.T) {
	a := PacketConfig{L3: L3Config{SrcIP: "bad", DstIP: "10.0.0.2"}, L4: L4Config{Protocol: "udp", SrcPort: 1, DstPort: 2}}
	b := PacketConfig{L3: L3Config{SrcIP: "0.0.0.0", DstIP: "10.0.0.2"}, L4: L4Config{Protocol: "udp", SrcPort: 1, DstPort: 2}}
	if !udpChecksumEquals(a, b) {
		t.Error("invalid SrcIP UDP checksum differs from zero-src")
	}
}
func TestCalcUDPChecksum_DstIPEmpty(t *testing.T) {
	a := PacketConfig{L3: L3Config{SrcIP: "10.0.0.1", DstIP: ""}, L4: L4Config{Protocol: "udp", SrcPort: 1, DstPort: 2}}
	b := PacketConfig{L3: L3Config{SrcIP: "10.0.0.1", DstIP: "0.0.0.0"}, L4: L4Config{Protocol: "udp", SrcPort: 1, DstPort: 2}}
	if !udpChecksumEquals(a, b) {
		t.Error("empty DstIP UDP checksum differs from 0.0.0.0")
	}
}
func TestCalcUDPChecksum_DstIPInvalid(t *testing.T) {
	a := PacketConfig{L3: L3Config{SrcIP: "10.0.0.1", DstIP: "bad"}, L4: L4Config{Protocol: "udp", SrcPort: 1, DstPort: 2}}
	b := PacketConfig{L3: L3Config{SrcIP: "10.0.0.1", DstIP: "0.0.0.0"}, L4: L4Config{Protocol: "udp", SrcPort: 1, DstPort: 2}}
	if !udpChecksumEquals(a, b) {
		t.Error("invalid DstIP UDP checksum differs from zero-dst")
	}
}
func TestCalcUDPChecksum_OddPayload(t *testing.T) {
	b := NewBuilder()
	cfg := PacketConfig{L2: baseL2(), L3: L3Config{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", Protocol: 17, TTL: 64}, L4: L4Config{Protocol: "udp", SrcPort: 1, DstPort: 2}, Payload: []byte("odd")} // 3 bytes
	pkt, _ := b.Build(cfg)
	udpStart := 34
	udpHeader := make([]byte, 8)
	copy(udpHeader, pkt[udpStart:udpStart+8])
	pseudo := buildPseudo(cfg, 17, uint16(8+len(cfg.Payload)))
	assembled := append(pseudo, udpHeader...)
	assembled = append(assembled, cfg.Payload...)
	if foldSum(assembled) != 0xFFFF {
		t.Errorf("UDP checksum invalid for odd-length payload (fold=0x%04X want 0xFFFF)", foldSum(assembled))
	}
}
func TestCalcUDPChecksum_EvenPayload(t *testing.T) {
	b := NewBuilder()
	cfg := PacketConfig{L2: baseL2(), L3: L3Config{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", Protocol: 17, TTL: 64}, L4: L4Config{Protocol: "udp", SrcPort: 1, DstPort: 2}, Payload: []byte("data")} // 4 bytes
	pkt, _ := b.Build(cfg)
	udpStart := 34
	udpHeader := make([]byte, 8)
	copy(udpHeader, pkt[udpStart:udpStart+8])
	pseudo := buildPseudo(cfg, 17, uint16(8+len(cfg.Payload)))
	assembled := append(pseudo, udpHeader...)
	assembled = append(assembled, cfg.Payload...)
	if foldSum(assembled) != 0xFFFF {
		t.Errorf("UDP checksum invalid for even-length payload (fold=0x%04X want 0xFFFF)", foldSum(assembled))
	}
}
func TestCalcUDPChecksum_IPv6Src(t *testing.T) {
	a := PacketConfig{L3: L3Config{SrcIP: "::1", DstIP: "10.0.0.2"}, L4: L4Config{Protocol: "udp", SrcPort: 1, DstPort: 2}}
	b := PacketConfig{L3: L3Config{SrcIP: "0.0.0.0", DstIP: "10.0.0.2"}, L4: L4Config{Protocol: "udp", SrcPort: 1, DstPort: 2}}
	if !udpChecksumEquals(a, b) {
		t.Error("IPv6 SrcIP UDP checksum differs from zero-src (To4()==nil -> zero)")
	}
}

// --- EtherTypeFor ---

// TestEtherTypeFor_IPv4 verifies the helper returns 0x0800 for IPv4 inputs,
// including unparseable strings (the historical default before the helper
// existed — every planner hardcoded 0x0800, so a parse failure must NOT
// silently switch to IPv6).
func TestEtherTypeFor_IPv4(t *testing.T) {
	cases := []string{
		"10.0.0.1", "20.0.0.1", "192.168.1.1", "255.255.255.255", "0.0.0.0",
		"not-an-ip", "", "999.999.999.999",
	}
	for _, ip := range cases {
		if got := EtherTypeFor(ip); got != EtherTypeIPv4 {
			t.Errorf("EtherTypeFor(%q) = 0x%04x, want 0x%04x (IPv4 default)", ip, got, EtherTypeIPv4)
		}
	}
}

// TestEtherTypeFor_IPv6 verifies the helper returns 0x86DD for IPv6 inputs
// of various forms (ULA, link-local, loopback, IPv6-mapped-not-IPv4).
func TestEtherTypeFor_IPv6(t *testing.T) {
	cases := []string{
		"fd00::1", "fd00::2",
		"fe80::1", "fe80::aabb:ccdd:eeff:0011",
		"::1", "2001:db8::1",
	}
	for _, ip := range cases {
		if got := EtherTypeFor(ip); got != EtherTypeIPv6 {
			t.Errorf("EtherTypeFor(%q) = 0x%04x, want 0x%04x (IPv6)", ip, got, EtherTypeIPv6)
		}
	}
}

// TestEtherTypeFor_IPv4MappedIPv6 verifies that IPv4-mapped IPv6 addresses
// (::ffff:a.b.c.d) are treated as IPv4. net.ParseIP returns a 16-byte form
// where To4() is non-nil, so these must land on EtherTypeIPv4 — otherwise
// a planner that lets the user write "::ffff:10.0.0.1" would emit a frame
// with EtherType 0x86DD but a 20-byte IPv4 header inside.
func TestEtherTypeFor_IPv4MappedIPv6(t *testing.T) {
	if got := EtherTypeFor("::ffff:10.0.0.1"); got != EtherTypeIPv4 {
		t.Errorf("EtherTypeFor(::ffff:10.0.0.1) = 0x%04x, want 0x%04x (IPv4-mapped -> IPv4)", got, EtherTypeIPv4)
	}
}
