package core

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
)

func TestBuilder_BuildEthernet(t *testing.T) {
	builder := NewBuilder()

	config := PacketConfig{
		L2: L2Config{
			SrcMAC:    "aa:bb:cc:dd:ee:ff",
			DstMAC:    "11:22:33:44:55:66",
			EtherType: 0x0800,
		},
		L3: L3Config{
			SrcIP:    "192.168.1.1",
			DstIP:    "192.168.1.2",
			Protocol: 6,
			TTL:      64,
		},
		L4: L4Config{
			Protocol: "tcp",
			SrcPort:  12345,
			DstPort:  80,
			Seq:      1000,
			Ack:      0,
			Flags:    0x02, // SYN
		},
	}

	packet, err := builder.Build(config)
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	// Check minimum size (Ethernet + IP + TCP = 14 + 20 + 20 = 54)
	if len(packet) < 54 {
		t.Errorf("Packet size = %d, want at least 54", len(packet))
	}

	// Check Ethernet header
	// Destination MAC
	if !bytes.Equal(packet[0:6], []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}) {
		t.Errorf("Wrong destination MAC")
	}
	// Source MAC
	if !bytes.Equal(packet[6:12], []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}) {
		t.Errorf("Wrong source MAC")
	}
	// EtherType (0x0800 = IPv4)
	if packet[12] != 0x08 || packet[13] != 0x00 {
		t.Errorf("Wrong EtherType")
	}
}

func TestBuilder_BuildUDP(t *testing.T) {
	builder := NewBuilder()

	config := PacketConfig{
		L2: L2Config{
			SrcMAC:    "aa:bb:cc:dd:ee:ff",
			DstMAC:    "11:22:33:44:55:66",
			EtherType: 0x0800,
		},
		L3: L3Config{
			SrcIP:    "192.168.1.1",
			DstIP:    "192.168.1.2",
			Protocol: 17, // UDP
			TTL:      64,
		},
		L4: L4Config{
			Protocol: "udp",
			SrcPort:  12345,
			DstPort:  53,
		},
		Payload: []byte("test payload"),
	}

	packet, err := builder.Build(config)
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	// Check minimum size (Ethernet + IP + UDP = 14 + 20 + 8 = 42 + payload)
	if len(packet) < 42+len(config.Payload) {
		t.Errorf("Packet size = %d, want at least %d", len(packet), 42+len(config.Payload))
	}
}

func TestBuilder_BuildWithVLAN(t *testing.T) {
	builder := NewBuilder()

	config := PacketConfig{
		L2: L2Config{
			SrcMAC:    "aa:bb:cc:dd:ee:ff",
			DstMAC:    "11:22:33:44:55:66",
			EtherType: 0x0800,
			VLAN: &VLAN{
				ID:       100,
				Priority: 5,
			},
		},
		L3: L3Config{
			SrcIP:    "192.168.1.1",
			DstIP:    "192.168.1.2",
			Protocol: 6,
			TTL:      64,
		},
		L4: L4Config{
			Protocol: "tcp",
			SrcPort:  12345,
			DstPort:  80,
			Flags:    0x02,
		},
	}

	packet, err := builder.Build(config)
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	// With VLAN, Ethernet header is 18 bytes instead of 14
	if len(packet) < 58 { // 18 + 20 + 20
		t.Errorf("Packet size = %d, want at least 58 (with VLAN)", len(packet))
	}

	// Check VLAN tag position (after 12 bytes of MACs)
	// VLAN TPID should be 0x8100
	if packet[12] != 0x81 || packet[13] != 0x00 {
		t.Errorf("Wrong VLAN TPID")
	}
}

// TestBuilder_DSCP_ECN verifies DSCP and ECN are encoded into the TOS byte.
// header[1] = (DSCP << 2) | (ECN & 0x03).
func TestBuilder_DSCP_ECN(t *testing.T) {
	builder := NewBuilder()

	// DSCP=46 (EF, expedited forwarding), ECN=0 -> 0xB8
	config := PacketConfig{
		L2: L2Config{SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66", EtherType: 0x0800},
		L3: L3Config{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", Protocol: 6, TTL: 64, DSCP: 46, ECN: 0},
		L4: L4Config{Protocol: "tcp", SrcPort: 1, DstPort: 2},
	}
	packet, err := builder.Build(config)
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}
	// L3 starts at byte 14 (Ethernet header). TOS is L3 byte 1 = packet[15].
	if packet[15] != 0xB8 {
		t.Errorf("DSCP=46 ECN=0: TOS byte = 0x%02x, want 0xB8", packet[15])
	}

	// DSCP=0, ECN=3 (CE, congestion experienced) -> 0x03
	config.L3.DSCP = 0
	config.L3.ECN = 3
	packet, _ = builder.Build(config)
	if packet[15] != 0x03 {
		t.Errorf("DSCP=0 ECN=3: TOS byte = 0x%02x, want 0x03", packet[15])
	}

	// DSCP=10, ECN=1 -> (10<<2)|1 = 41 = 0x29
	config.L3.DSCP = 10
	config.L3.ECN = 1
	packet, _ = builder.Build(config)
	if packet[15] != 0x29 {
		t.Errorf("DSCP=10 ECN=1: TOS byte = 0x%02x, want 0x29", packet[15])
	}
}

// TestBuilder_Fragmentation verifies IP flags and fragment offset encoding.
// header[6:8] = (Flags << 13) | (FragOffset & 0x1FFF). The builder encodes
// L3Config.Flags faithfully (0 = no flags / fragmentable); the DF default for
// normal traffic is applied by L3Base, tested separately.
func TestBuilder_Fragmentation(t *testing.T) {
	builder := NewBuilder()

	config := PacketConfig{
		L2: L2Config{SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66", EtherType: 0x0800},
		L3: L3Config{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", Protocol: 6, TTL: 64},
		L4: L4Config{Protocol: "tcp", SrcPort: 1, DstPort: 2},
	}

	// Flags=0 (no flags) -> 0x0000
	packet, err := builder.Build(config)
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}
	got := uint16(packet[20])<<8 | uint16(packet[21])
	if got != 0x0000 {
		t.Errorf("no flags: 0x%04x, want 0x0000", got)
	}

	// DF set explicitly -> 0x4000
	config.L3.Flags = IPFlagDF
	packet, _ = builder.Build(config)
	got = uint16(packet[20])<<8 | uint16(packet[21])
	if got != 0x4000 {
		t.Errorf("DF: 0x%04x, want 0x4000", got)
	}

	// MF set, FragOffset=100 -> (0x01<<13)|100 = 0x2064
	config.L3.Flags = IPFlagMF
	config.L3.FragOffset = 100
	packet, _ = builder.Build(config)
	got = uint16(packet[20])<<8 | uint16(packet[21])
	if got != 0x2064 {
		t.Errorf("MF+offset=100: 0x%04x, want 0x2064", got)
	}

	// No flags, offset=185 -> 0x00B9
	config.L3.Flags = 0
	config.L3.FragOffset = 185
	packet, _ = builder.Build(config)
	got = uint16(packet[20])<<8 | uint16(packet[21])
	if got != 185 {
		t.Errorf("no flags offset=185: 0x%04x, want 0x00B9", got)
	}
}

// TestL3Base_DefaultDF verifies L3Base passes spec.IPFlags through unchanged.
// Defaulting (DF=1 when user did not specify) is now owned by mapToFlowSpec
// via the defaultIPFlags presence-check helper; L3Base no longer silently
// rewrites an explicit ip_flags=0 to DF=1. Code paths that construct FlowSpec
// directly (bypassing mapToFlowSpec) must set spec.IPFlags explicitly.
func TestL3Base_DefaultDF(t *testing.T) {
	// Empty FlowSpec (no flags) -> Flags=0 (no DF default applied here).
	// mapToFlowSpec's defaultIPFlags helper is the single source of the DF=1
	// default; direct FlowSpec construction must opt in explicitly.
	l3 := L3Base("10.0.0.1", "10.0.0.2", 6, 64, 1, FlowSpec{})
	if l3.Flags != 0 {
		t.Errorf("empty FlowSpec flags = 0x%02x, want 0 (L3Base no longer defaults DF)", l3.Flags)
	}
	// Explicit MF + offset -> MF and offset carried through
	l3 = L3Base("10.0.0.1", "10.0.0.2", 6, 64, 1, FlowSpec{IPFlags: IPFlagMF, FragOffset: 100})
	if l3.Flags != IPFlagMF || l3.FragOffset != 100 {
		t.Errorf("explicit frag: flags=0x%02x off=%d, want MF/100", l3.Flags, l3.FragOffset)
	}
	// Explicit DF -> carried through
	l3 = L3Base("10.0.0.1", "10.0.0.2", 6, 64, 1, FlowSpec{IPFlags: IPFlagDF})
	if l3.Flags != IPFlagDF {
		t.Errorf("explicit DF: flags=0x%02x, want DF", l3.Flags)
	}
	// DSCP/ECN carried through
	l3 = L3Base("10.0.0.1", "10.0.0.2", 6, 64, 1, FlowSpec{DSCP: 46, ECN: 1})
	if l3.DSCP != 46 || l3.ECN != 1 {
		t.Errorf("dscp/ecn: %d/%d, want 46/1", l3.DSCP, l3.ECN)
	}
	// Legacy TOS splits into DSCP/ECN
	l3 = L3Base("10.0.0.1", "10.0.0.2", 6, 64, 1, FlowSpec{TOS: 0xB8}) // 0xB8 = DSCP 46, ECN 0
	if l3.DSCP != 46 || l3.ECN != 0 {
		t.Errorf("TOS=0xB8: dscp=%d ecn=%d, want 46/0", l3.DSCP, l3.ECN)
	}
}


// TestBuilder_TCPOptions_MSS verifies a TCP packet with an MSS option encodes
// the data offset and option bytes correctly. Ethernet(14)+IP(20)=34, so TCP
// starts at byte 34; data offset is the high nibble of TCP byte 12.
func TestBuilder_TCPOptions_MSS(t *testing.T) {
	builder := NewBuilder()
	config := PacketConfig{
		L2: L2Config{SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66", EtherType: 0x0800},
		L3: L3Config{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", Protocol: 6, TTL: 64},
		L4: L4Config{
			Protocol: "tcp", SrcPort: 1, DstPort: 2, Seq: 100, Flags: 0x02, // SYN
			TCPOptions: []TCPOption{{Kind: 2, Data: []byte{0x05, 0xB4}}}, // MSS=1460
		},
	}
	packet, err := builder.Build(config)
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}
	tcpStart := 34 // 14 (eth) + 20 (ip)
	// MSS option is 4 bytes -> data offset = (20+4)/4 = 6 (24-byte TCP header)
	if packet[tcpStart+12]>>4 != 6 {
		t.Errorf("data offset = %d, want 6", packet[tcpStart+12]>>4)
	}
	// Option bytes at tcpStart+20: kind=2, len=4, mss=0x05B4
	opts := packet[tcpStart+20 : tcpStart+24]
	want := []byte{0x02, 0x04, 0x05, 0xB4}
	if !bytes.Equal(opts, want) {
		t.Errorf("MSS option = %x, want %x", opts, want)
	}
}

// TestBuilder_TCPOptions_MultipleAndPadding verifies multiple options are
// encoded in order and padded to a 4-byte boundary.
func TestBuilder_TCPOptions_MultipleAndPadding(t *testing.T) {
	builder := NewBuilder()
	// SACK-Permitted (2 bytes) + Window Scale (3 bytes) = 5 bytes -> padded to 8
	config := PacketConfig{
		L2: L2Config{SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66", EtherType: 0x0800},
		L3: L3Config{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", Protocol: 6, TTL: 64},
		L4: L4Config{
			Protocol: "tcp", SrcPort: 1, DstPort: 2, Flags: 0x02,
			TCPOptions: []TCPOption{
				{Kind: 4},                       // SACK-Permitted (no data)
				{Kind: 3, Data: []byte{0x07}},   // Window Scale shift=7
			},
		},
	}
	packet, err := builder.Build(config)
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}
	tcpStart := 34
	// 20 + 5 options + 3 padding = 28 -> data offset = 7
	if packet[tcpStart+12]>>4 != 7 {
		t.Errorf("data offset = %d, want 7", packet[tcpStart+12]>>4)
	}
	// SACK-Permitted: 04 02 ; Window Scale: 03 03 07 ; NOP padding: 01 01 01
	opts := packet[tcpStart+20 : tcpStart+28]
	want := []byte{0x04, 0x02, 0x03, 0x03, 0x07, 0x01, 0x01, 0x01}
	if !bytes.Equal(opts, want) {
		t.Errorf("options = %x, want %x", opts, want)
	}
}

// TestBuild_Allocs verifies single-buffer construction keeps allocations low
// (packet buffer + stdlib IP parsing). Guards against reintroducing per-layer
// temporary allocations.
func TestBuild_Allocs(t *testing.T) {
	b := NewBuilder()
	cfg := PacketConfig{
		L2: L2Config{SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66", EtherType: 0x0800},
		L3: L3Config{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", Protocol: 6, TTL: 64},
		L4: L4Config{Protocol: "tcp", SrcPort: 1, DstPort: 2, Seq: 100, Flags: 0x02},
	}
	allocs := testing.AllocsPerRun(200, func() {
		b.Build(cfg)
	})
	// 1 packet buffer + 2 net.ParseIP (src/dst). MACs parse from cache-friendly
	// inputs; allow slack for stdlib variance but catch per-layer regressions.
	if allocs > 4 {
		t.Errorf("Build allocs = %v, want <= 4 (single-buffer)", allocs)
	}
}

// TestBuilder_ARPNoL3Header verifies ARP packets (EtherType 0x0806) have NO IP
// header: the 28-byte ARP payload sits directly after the 14-byte Ethernet
// header (total 42 bytes). Previously the builder unconditionally wrote a
// 20-byte IP header, shifting the ARP payload and corrupting the packet
// (captured as "Unknown Hardware 0x4500").
func TestBuilder_ARPNoL3Header(t *testing.T) {
	b := NewBuilder()
	// Minimal ARP request payload (28 bytes): htype=1, ptype=0x0800, hlen=6,
	// plen=4, op=1, sender MAC+IP, target MAC(0)+IP.
	arp := make([]byte, 28)
	arp[0], arp[1] = 0x00, 0x01 // htype Ethernet
	arp[2], arp[3] = 0x08, 0x00 // ptype IPv4
	arp[4] = 6                  // hlen
	arp[5] = 4                  // plen
	arp[6], arp[7] = 0x00, 0x01 // op=request
	copy(arp[8:14], []byte{0x0c, 0x42, 0xa1, 0x09, 0x9e, 0x5e})

	config := PacketConfig{
		L2: L2Config{
			SrcMAC:    "0c:42:a1:09:9e:5e",
			DstMAC:    "ff:ff:ff:ff:ff:ff",
			EtherType: 0x0806, // ARP
		},
		L3: L3Config{Protocol: 0}, // no L3 for ARP
		L4: L4Config{Protocol: "arp"},
		Payload: arp,
	}

	packet, err := b.Build(config)
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	// Expect 14 (Eth) + 28 (ARP) = 42 bytes natural, padded to 60 (MinEthernetFrame).
	// Padding is appended after the ARP payload; bytes 42-59 are zero. The ARP
	// payload at 14:42 is unaffected — receivers parse ARP by EtherType, then
	// strip padding based on the L2 payload length (ARP has no length field, so
	// padding is implicitly stripped by the receiver's frame-length check).
	if len(packet) != MinEthernetFrame {
		t.Errorf("ARP packet size = %d, want %d (padded, Eth 14 + ARP 28 + 18 pad)", len(packet), MinEthernetFrame)
	}

	// EtherType at bytes 12:14 must be 0x0806.
	if et := uint16(packet[12])<<8 | uint16(packet[13]); et != 0x0806 {
		t.Errorf("EtherType = 0x%04x, want 0x0806 (ARP)", et)
	}

	// ARP payload starts at byte 14: hardware type must be 0x0001, not 0x4500
	// (the IP-version byte that appeared when an IP header was wrongly written).
	if ht := uint16(packet[14])<<8 | uint16(packet[15]); ht != 0x0001 {
		t.Errorf("ARP htype = 0x%04x, want 0x0001 (corrupted by IP header?)", ht)
	}
	// Operation at bytes 20:21 must be 1 (request).
	if op := uint16(packet[20])<<8 | uint16(packet[21]); op != 1 {
		t.Errorf("ARP op = %d, want 1 (request)", op)
	}
}

// TestBuilder_VLAN8021Q verifies a VLAN-tagged packet has the 802.1Q TPID
// (0x8100) and the VLAN tag (priority+ID) inserted between the Ethernet
// header and the EtherType. Previously planners never propagated spec.VLAN to
// PacketConfig.L2.VLAN, so the tag was silently omitted.
func TestBuilder_VLAN8021Q(t *testing.T) {
	b := NewBuilder()
	vlan := &VLAN{ID: 100, Priority: 5}
	config := PacketConfig{
		L2: L2Config{
			SrcMAC:    "aa:bb:cc:dd:ee:ff",
			DstMAC:    "11:22:33:44:55:66",
			EtherType: 0x0800,
			VLAN:      vlan,
		},
		L3: L3Config{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", Protocol: 6, TTL: 64},
		L4: L4Config{Protocol: "tcp", SrcPort: 1, DstPort: 2, Seq: 1, Flags: 0x02},
	}

	packet, err := b.Build(config)
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	// Ethernet header is 18 bytes with VLAN (vs 14 without).
	// [dst(6)][src(6)][TPID 0x8100(2)][VLAN tag(2)][EtherType(2)]
	if tpID := uint16(packet[12])<<8 | uint16(packet[13]); tpID != 0x8100 {
		t.Errorf("TPID = 0x%04x, want 0x8100 (VLAN)", tpID)
	}
	tag := uint16(packet[14])<<8 | uint16(packet[15])
	wantTag := (uint16(5) << 13) | (100 & 0x0FFF) // priority 5, ID 100
	if tag != wantTag {
		t.Errorf("VLAN tag = 0x%04x, want 0x%04x (pri=5 id=100)", tag, wantTag)
	}
	// Inner EtherType at 16:18 must be 0x0800 (IPv4).
	if et := uint16(packet[16])<<8 | uint16(packet[17]); et != 0x0800 {
		t.Errorf("inner EtherType = 0x%04x, want 0x0800", et)
	}
}

// TestTCPChecksum_IPv6 verifies the TCP checksum is computed correctly when
// SrcIP/DstIP are IPv6 addresses. The pre-IPv6 implementation only built the
// 12-byte IPv4 pseudo-header (srcIP.To4()), which returned nil for IPv6 —
// leaving the pseudo-header zero-filled and producing a wrong checksum that
// IPv6 stacks would drop. This test feeds a known IPv6 4-tuple + payload and
// verifies the checksum matches the value computed by an independent reference
// implementation (the same algorithm inlined here).
//
// Reference: RFC 8200 §8.1 — IPv6 pseudo-header is 40 bytes:
// SrcIP(16) + DstIP(16) + UpperLayerPacketLength(4) + zero(3) + NextHeader(1).
// NextHeader for TCP is 6.
func TestTCPChecksum_IPv6(t *testing.T) {
	srcIP := "2001:db8::1"
	dstIP := "2001:db8::2"
	srcPort := uint16(12345)
	dstPort := uint16(80)
	payload := []byte("hello tcp ipv6")

	// Build a TCP header (20 bytes, no options). Checksum field at offset 16-17
	// is zero during computation.
	tcpHeader := make([]byte, 20)
	binary.BigEndian.PutUint16(tcpHeader[0:2], srcPort)
	binary.BigEndian.PutUint16(tcpHeader[2:4], dstPort)
	// seq=0, ack=0
	tcpHeader[12] = 0x50 // data offset = 5 (20 bytes)
	tcpHeader[13] = 0x02 // SYN
	// window=0, checksum=0, urgent=0

	config := PacketConfig{
		L3: L3Config{SrcIP: srcIP, DstIP: dstIP, Protocol: 6, TTL: 64},
		L4: L4Config{Protocol: "tcp", SrcPort: srcPort, DstPort: dstPort, Seq: 0, Ack: 0, Flags: 0x02},
	}
	got := calculateTCPChecksum(config, tcpHeader, payload)

	// Compute expected checksum independently.
	src := net.ParseIP(srcIP).To16()
	dst := net.ParseIP(dstIP).To16()
	upperLen := len(tcpHeader) + len(payload)
	ph := make([]byte, 40)
	copy(ph[0:16], src)
	copy(ph[16:32], dst)
	binary.BigEndian.PutUint32(ph[32:36], uint32(upperLen))
	ph[39] = 6 // TCP

	var sum uint32
	for i := 0; i < len(ph); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(ph[i : i+2]))
	}
	for i := 0; i < len(tcpHeader); i += 2 {
		if i == 16 {
			continue
		}
		if i+2 <= len(tcpHeader) {
			sum += uint32(binary.BigEndian.Uint16(tcpHeader[i : i+2]))
		}
	}
	for i := 0; i < len(payload)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(payload[i : i+2]))
	}
	if len(payload)%2 == 1 {
		sum += uint32(payload[len(payload)-1]) << 8
	}
	sum = (sum >> 16) + (sum & 0xffff)
	sum = sum + (sum >> 16)
	want := ^uint16(sum)

	if got != want {
		t.Errorf("IPv6 TCP checksum = 0x%04x, want 0x%04x (independent calc)", got, want)
	}
	// Sanity: checksum must NOT be zero (zero pseudo-header bug would produce
	// a different value, possibly zero on some inputs).
	if got == 0 {
		t.Errorf("IPv6 TCP checksum = 0 — pseudo-header likely not applied")
	}
}

// TestTCPChecksum_IPv4Unchanged verifies the IPv4 TCP checksum path still
// produces the same value as the original (pre-IPv6) implementation. Catches
// regressions where the IPv6 branch was added but broke the IPv4 branch.
func TestTCPChecksum_IPv4Unchanged(t *testing.T) {
	srcIP := "10.0.0.1"
	dstIP := "20.0.0.1"
	srcPort := uint16(12345)
	dstPort := uint16(80)
	payload := []byte("hello tcp ipv4")

	tcpHeader := make([]byte, 20)
	binary.BigEndian.PutUint16(tcpHeader[0:2], srcPort)
	binary.BigEndian.PutUint16(tcpHeader[2:4], dstPort)
	tcpHeader[12] = 0x50
	tcpHeader[13] = 0x02

	config := PacketConfig{
		L3: L3Config{SrcIP: srcIP, DstIP: dstIP, Protocol: 6, TTL: 64},
		L4: L4Config{Protocol: "tcp", SrcPort: srcPort, DstPort: dstPort, Flags: 0x02},
	}
	got := calculateTCPChecksum(config, tcpHeader, payload)

	// Independent IPv4 pseudo-header calculation (12 bytes).
	src := net.ParseIP(srcIP).To4()
	dst := net.ParseIP(dstIP).To4()
	ph := make([]byte, 12)
	copy(ph[0:4], src)
	copy(ph[4:8], dst)
	ph[9] = 6 // TCP
	binary.BigEndian.PutUint16(ph[10:12], uint16(len(tcpHeader)+len(payload)))

	var sum uint32
	for i := 0; i < 12; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(ph[i : i+2]))
	}
	for i := 0; i < len(tcpHeader); i += 2 {
		if i == 16 {
			continue
		}
		if i+2 <= len(tcpHeader) {
			sum += uint32(binary.BigEndian.Uint16(tcpHeader[i : i+2]))
		}
	}
	for i := 0; i < len(payload)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(payload[i : i+2]))
	}
	if len(payload)%2 == 1 {
		sum += uint32(payload[len(payload)-1]) << 8
	}
	sum = (sum >> 16) + (sum & 0xffff)
	sum = sum + (sum >> 16)
	want := ^uint16(sum)

	if got != want {
		t.Errorf("IPv4 TCP checksum = 0x%04x, want 0x%04x (regression)", got, want)
	}
}

// TestUDPChecksum_IPv6 verifies the UDP checksum is computed correctly for
// IPv6 src/dst. Same rationale as TestTCPChecksum_IPv6: pre-IPv6 code only
// built IPv4 pseudo-header.
func TestUDPChecksum_IPv6(t *testing.T) {
	srcIP := "2001:db8::1"
	dstIP := "2001:db8::2"
	srcPort := uint16(12345)
	dstPort := uint16(53)
	payload := []byte("dns query ipv6")

	config := PacketConfig{
		L3: L3Config{SrcIP: srcIP, DstIP: dstIP, Protocol: 17, TTL: 64},
		L4: L4Config{Protocol: "udp", SrcPort: srcPort, DstPort: dstPort},
	}
	got := calculateUDPChecksum(config, payload)

	// Independent IPv6 UDP pseudo-header calc.
	src := net.ParseIP(srcIP).To16()
	dst := net.ParseIP(dstIP).To16()
	udpLen := uint16(8 + len(payload))
	ph := make([]byte, 40)
	copy(ph[0:16], src)
	copy(ph[16:32], dst)
	binary.BigEndian.PutUint32(ph[32:36], uint32(udpLen))
	ph[39] = 17 // UDP

	var sum uint32
	for i := 0; i < 40; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(ph[i : i+2]))
	}
	// UDP header fields: src_port + dst_port + length (checksum=0 during calc)
	sum += uint32(srcPort)
	sum += uint32(dstPort)
	sum += uint32(udpLen)
	for i := 0; i < len(payload)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(payload[i : i+2]))
	}
	if len(payload)%2 == 1 {
		sum += uint32(payload[len(payload)-1]) << 8
	}
	sum = (sum >> 16) + (sum & 0xffff)
	sum = sum + (sum >> 16)
	want := ^uint16(sum)
	if want == 0 {
		want = 0xFFFF // IPv6 UDP zero-checksum rule
	}

	if got != want {
		t.Errorf("IPv6 UDP checksum = 0x%04x, want 0x%04x", got, want)
	}
	if got == 0 {
		t.Errorf("IPv6 UDP checksum = 0 — RFC 6936 forbids zero on IPv6")
	}
}

// TestUDPChecksum_IPv4Unchanged verifies the IPv4 UDP checksum is unchanged.
func TestUDPChecksum_IPv4Unchanged(t *testing.T) {
	srcIP := "10.0.0.1"
	dstIP := "20.0.0.1"
	srcPort := uint16(12345)
	dstPort := uint16(53)
	payload := []byte("dns query ipv4")

	config := PacketConfig{
		L3: L3Config{SrcIP: srcIP, DstIP: dstIP, Protocol: 17, TTL: 64},
		L4: L4Config{Protocol: "udp", SrcPort: srcPort, DstPort: dstPort},
	}
	got := calculateUDPChecksum(config, payload)

	src := net.ParseIP(srcIP).To4()
	dst := net.ParseIP(dstIP).To4()
	udpLen := uint16(8 + len(payload))
	ph := make([]byte, 12)
	copy(ph[0:4], src)
	copy(ph[4:8], dst)
	ph[9] = 17
	binary.BigEndian.PutUint16(ph[10:12], udpLen)

	var sum uint32
	for i := 0; i < 12; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(ph[i : i+2]))
	}
	sum += uint32(srcPort)
	sum += uint32(dstPort)
	sum += uint32(udpLen)
	for i := 0; i < len(payload)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(payload[i : i+2]))
	}
	if len(payload)%2 == 1 {
		sum += uint32(payload[len(payload)-1]) << 8
	}
	sum = (sum >> 16) + (sum & 0xffff)
	sum = sum + (sum >> 16)
	want := ^uint16(sum)

	if got != want {
		t.Errorf("IPv4 UDP checksum = 0x%04x, want 0x%04x (regression)", got, want)
	}
}

// TestBuild_IPv6TCPIntegration verifies the full Build() path for an IPv6
// TCP packet: EtherType 0x86DD, 40-byte IPv6 header at offset 14, Next
// Header=6 (TCP) at offset 20, and the IPv6 source/destination addresses
// written into bytes 22-37 and 38-53. This is the end-to-end integration
// test for writeL3's EtherType dispatch + writeL3v6 — unit tests above
// (TestTCPChecksum_IPv6) cover the checksum in isolation, but a planner
// that emits IPv6 PacketConfigs depends on Build() wiring the header
// layout correctly.
func TestBuild_IPv6TCPIntegration(t *testing.T) {
	builder := NewBuilder()
	srcIP := "2001:db8::1"
	dstIP := "2001:db8::2"

	config := PacketConfig{
		L2: L2Config{
			SrcMAC:    "aa:bb:cc:dd:ee:ff",
			DstMAC:    "11:22:33:44:55:66",
			EtherType: EtherTypeIPv6, // 0x86DD — planner sets via EtherTypeFor()
		},
		L3: L3Config{
			SrcIP:    srcIP,
			DstIP:    dstIP,
			Protocol: 6, // TCP
			TTL:      64,
			DSCP:     0x08,
		},
		L4: L4Config{
			Protocol: "tcp",
			SrcPort:  12345,
			DstPort:  80,
			Seq:      1000,
			Flags:    0x02, // SYN
		},
	}

	pkt, err := builder.Build(config)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	// Frame layout: 14 (Eth) + 40 (IPv6) + 20 (TCP, no options) = 74 bytes.
	if len(pkt) != 74 {
		t.Errorf("frame length = %d, want 74 (14+40+20)", len(pkt))
	}

	// EtherType at offset 12-13.
	if got := binary.BigEndian.Uint16(pkt[12:14]); got != EtherTypeIPv6 {
		t.Errorf("EtherType = 0x%04x, want 0x%04x (IPv6)", got, EtherTypeIPv6)
	}

	// IPv6 Version (4 bits) = 6, TrafficClass high 4 bits from DSCP=0x08.
	// tc = (0x08<<2) | 0 = 0x20, tc>>4 = 0x02, byte[14] = (6<<4) | 0x02 = 0x62.
	if pkt[14] != 0x62 {
		t.Errorf("IPv6 byte[0] = 0x%02x, want 0x62 (Version=6, DSCP=0x08)", pkt[14])
	}

	// Payload Length at offset 18-19: TCP header (20) + no payload = 20.
	if got := binary.BigEndian.Uint16(pkt[18:20]); got != 20 {
		t.Errorf("Payload Length = %d, want 20", got)
	}

	// Next Header at offset 20: 6 (TCP).
	if pkt[20] != 6 {
		t.Errorf("Next Header = %d, want 6 (TCP)", pkt[20])
	}

	// Hop Limit at offset 21: 64.
	if pkt[21] != 64 {
		t.Errorf("Hop Limit = %d, want 64", pkt[21])
	}

	// SrcIP at offset 22-37 (14+8).
	wantSrc := net.ParseIP(srcIP).To16()
	if !bytes.Equal(pkt[22:38], wantSrc) {
		t.Errorf("SrcIP bytes = %v, want %v", pkt[22:38], wantSrc)
	}

	// DstIP at offset 38-53.
	wantDst := net.ParseIP(dstIP).To16()
	if !bytes.Equal(pkt[38:54], wantDst) {
		t.Errorf("DstIP bytes = %v, want %v", pkt[38:54], wantDst)
	}
}

// TestBuild_IPv6UDPIntegration verifies the full Build() path for an IPv6
// UDP packet, mirroring TestBuild_IPv6TCPIntegration. UDP Next Header = 17.
func TestBuild_IPv6UDPIntegration(t *testing.T) {
	builder := NewBuilder()
	srcIP := "fd00::1"
	dstIP := "fd00::2"
	payload := []byte("hello ipv6 udp")

	config := PacketConfig{
		L2: L2Config{
			SrcMAC: "aa:bb:cc:dd:ee:ff",
			DstMAC: "11:22:33:44:55:66",
			EtherType: EtherTypeIPv6,
		},
		L3: L3Config{
			SrcIP:    srcIP,
			DstIP:    dstIP,
			Protocol: 17, // UDP
			TTL:      64,
		},
		L4: L4Config{
			Protocol: "udp",
			SrcPort:  54321,
			DstPort:  53,
		},
		Payload: payload,
	}

	pkt, err := builder.Build(config)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	// 14 + 40 + 8 + 14 = 76 bytes.
	if len(pkt) != 76 {
		t.Errorf("frame length = %d, want 76 (14+40+8+14)", len(pkt))
	}

	if got := binary.BigEndian.Uint16(pkt[12:14]); got != EtherTypeIPv6 {
		t.Errorf("EtherType = 0x%04x, want 0x%04x (IPv6)", got, EtherTypeIPv6)
	}

	// Next Header at offset 20: 17 (UDP).
	if pkt[20] != 17 {
		t.Errorf("Next Header = %d, want 17 (UDP)", pkt[20])
	}

	// Payload Length: 8 (UDP hdr) + 14 (payload) = 22.
	if got := binary.BigEndian.Uint16(pkt[18:20]); got != 22 {
		t.Errorf("Payload Length = %d, want 22 (8+14)", got)
	}

	// UDP header at offset 54 (14+40). SrcPort, DstPort, Length, Checksum.
	if got := binary.BigEndian.Uint16(pkt[54:56]); got != 54321 {
		t.Errorf("UDP SrcPort = %d, want 54321", got)
	}
	if got := binary.BigEndian.Uint16(pkt[56:58]); got != 53 {
		t.Errorf("UDP DstPort = %d, want 53", got)
	}
	if got := binary.BigEndian.Uint16(pkt[58:60]); got != 22 {
		t.Errorf("UDP Length = %d, want 22", got)
	}
	// UDP checksum at offset 60-61: must be non-zero (RFC 6936 forbids zero on IPv6).
	if got := binary.BigEndian.Uint16(pkt[60:62]); got == 0 {
		t.Errorf("UDP checksum = 0 on IPv6 — RFC 6936 forbids this; want 0xFFFF substitute at minimum")
	}

	// Payload at offset 62.
	if !bytes.Equal(pkt[62:], payload) {
		t.Errorf("UDP payload = %q, want %q", pkt[62:], payload)
	}
}
