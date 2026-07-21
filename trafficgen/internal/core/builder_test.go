package core

import (
	"bytes"
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

// TestL3Base_DefaultDF verifies L3Base passes spec.Flags through unchanged.
// Defaulting (DF=1 when user did not specify) is now owned by mapToFlowSpec
// via the defaultIPFlags presence-check helper; L3Base no longer silently
// rewrites an explicit flags=0 to DF=1. Code paths that construct FlowSpec
// directly (bypassing mapToFlowSpec) must set spec.Flags explicitly.
func TestL3Base_DefaultDF(t *testing.T) {
	// Empty FlowSpec (no flags) -> Flags=0 (no DF default applied here).
	// mapToFlowSpec's defaultIPFlags helper is the single source of the DF=1
	// default; direct FlowSpec construction must opt in explicitly.
	l3 := L3Base("10.0.0.1", "10.0.0.2", 6, 64, 1, FlowSpec{})
	if l3.Flags != 0 {
		t.Errorf("empty FlowSpec flags = 0x%02x, want 0 (L3Base no longer defaults DF)", l3.Flags)
	}
	// Explicit MF + offset -> MF and offset carried through
	l3 = L3Base("10.0.0.1", "10.0.0.2", 6, 64, 1, FlowSpec{Flags: IPFlagMF, FragOffset: 100})
	if l3.Flags != IPFlagMF || l3.FragOffset != 100 {
		t.Errorf("explicit frag: flags=0x%02x off=%d, want MF/100", l3.Flags, l3.FragOffset)
	}
	// Explicit DF -> carried through
	l3 = L3Base("10.0.0.1", "10.0.0.2", 6, 64, 1, FlowSpec{Flags: IPFlagDF})
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
