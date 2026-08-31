package nvgre

import (
	"bytes"
	"context"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// collectEmit drives the generator and collects emitted PacketConfigs.
func collectEmit(t *testing.T, cfg *core.NVGREConfig, srcIP, dstIP string) []core.PacketConfig {
	t.Helper()
	var out []core.PacketConfig
	req := &layers.GenRequest{
		Meta: layers.FlowMeta{NVGRE: cfg, SrcIP: srcIP, DstIP: dstIP},
		Emit: func(pkt core.PacketConfig) error {
			out = append(out, pkt)
			return nil
		},
	}
	if err := (&NVGREGenerator{}).Generate(context.Background(), req); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	return out
}

// TestGREKeyBytes pins the wire Key arithmetic (design §3.1): Key = VSID(24)<<8
// | FlowID(8), serialized network byte order by the builder's
// binary.BigEndian.PutUint32 — VSID high 24 bits, FlowID low 8, no truncation,
// no host order, no FlowID leakage into VSID.
func TestGREKeyBytes(t *testing.T) {
	cases := []struct {
		vsid   uint32
		flowID uint8
		want   []byte // the exact 4 wire bytes
	}{
		{0x000000, 0x00, []byte{0x00, 0x00, 0x00, 0x00}},
		{0x000001, 0x01, []byte{0x00, 0x00, 0x01, 0x01}},
		{0x123456, 0x7a, []byte{0x12, 0x34, 0x56, 0x7a}},
		{0xffffff, 0xff, []byte{0xff, 0xff, 0xff, 0xff}},
		{0x0000aa, 0x00, []byte{0x00, 0x00, 0xaa, 0x00}},
		{0x000000, 0xff, []byte{0x00, 0x00, 0x00, 0xff}},
	}
	for _, c := range cases {
		key := GREKey(c.vsid, c.flowID)
		got := make([]byte, 4)
		binary.BigEndian.PutUint32(got, key)
		if !bytes.Equal(got, c.want) {
			t.Errorf("GREKey(vsid=0x%06x, flow=0x%02x) wire bytes % x, want % x", c.vsid, c.flowID, got, c.want)
		}
	}
}

// fixture returns a valid inner Ethernet fixture for generator tests.
func fixture() *core.EncapEthernetFixture {
	return &core.EncapEthernetFixture{
		SrcMAC:    "02:aa:00:00:00:01",
		DstMAC:    "02:bb:00:00:00:01",
		EtherType: "ipv4",
		SrcIP:     "172.16.1.1",
		DstIP:     "172.16.1.2",
		Payload:   []byte("nvgre-inner-01"),
	}
}

// wireBuild applies the raw-IP branch's finalEmit L2 semantics (MACs +
// EtherType from the up-oriented outer addresses) and builds wire bytes.
func wireBuild(t *testing.T, pkt core.PacketConfig) []byte {
	t.Helper()
	pkt.L2.SrcMAC = "02:00:00:00:00:01"
	pkt.L2.DstMAC = "02:00:00:00:00:02"
	pkt.L2.EtherType = core.EtherTypeFor(pkt.L3.SrcIP)
	b, err := core.NewBuilder().Build(pkt)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	return b
}

// TestGenerateWireIPv4Outer locks the IPv4-outer NVGRE wire layout
// (design §2 fixed offsets): flags 34, protocol 36, key 38, inner Ethernet 42.
func TestGenerateWireIPv4Outer(t *testing.T) {
	cfg := &core.NVGREConfig{VSID: 0x123456, FlowID: 0x7a, Inner: fixture()}
	pkts := collectEmit(t, cfg, "192.0.2.10", "198.51.100.10")
	if len(pkts) != 1 {
		t.Fatalf("got %d packets, want 1", len(pkts))
	}
	pkt := pkts[0]
	if pkt.Direction != "up" {
		t.Errorf("direction %q, want up", pkt.Direction)
	}
	if pkt.L3.Protocol != core.ProtocolGRE {
		t.Errorf("L3.Protocol %d, want 47", pkt.L3.Protocol)
	}
	if pkt.L3.TTL != 64 {
		t.Errorf("L3.TTL %d, want 64 (nil TTL default)", pkt.L3.TTL)
	}
	gre := pkt.L2.GRE
	if gre == nil || !gre.KeyPresent {
		t.Fatalf("L2.GRE nil or KeyPresent false: %+v", gre)
	}
	if gre.ProtocolType != core.EtherTypeTEB {
		t.Errorf("GRE.ProtocolType 0x%04x, want 0x6558", gre.ProtocolType)
	}
	if got := []byte{byte(gre.Key >> 24), byte(gre.Key >> 16), byte(gre.Key >> 8), byte(gre.Key)}; !bytes.Equal(got, []byte{0x12, 0x34, 0x56, 0x7a}) {
		t.Errorf("GRE.Key bytes % x, want 12 34 56 7a", got)
	}
	if pkt.L4.Protocol != "" {
		t.Errorf("L4.Protocol %q must stay empty for GRE frames", pkt.L4.Protocol)
	}

	wire := wireBuild(t, pkt)
	// GRE flags/version + protocol at 34 (design §2 fixed offsets).
	if !bytes.Equal(wire[34:38], []byte{0x20, 0x00, 0x65, 0x58}) {
		t.Errorf("wire[34:38] = % x, want 20 00 65 58", wire[34:38])
	}
	if !bytes.Equal(wire[38:42], []byte{0x12, 0x34, 0x56, 0x7a}) {
		t.Errorf("wire[38:42] key = % x, want 12 34 56 7a", wire[38:42])
	}
	// Inner Ethernet dst MAC at 42.
	if !bytes.Equal(wire[42:48], []byte{0x02, 0xbb, 0x00, 0x00, 0x00, 0x01}) {
		t.Errorf("wire[42:48] inner dst MAC = % x", wire[42:48])
	}
	if !bytes.Equal(wire[48:54], []byte{0x02, 0xaa, 0x00, 0x00, 0x00, 0x01}) {
		t.Errorf("wire[48:54] inner src MAC = % x", wire[48:54])
	}
	if !bytes.Equal(wire[54:56], []byte{0x08, 0x00}) {
		t.Errorf("wire[54:56] inner EtherType = % x, want 08 00", wire[54:56])
	}
	// Inner IPv4 src/dst at 56+12 / 56+16.
	if !bytes.Equal(wire[68:72], []byte{172, 16, 1, 1}) || !bytes.Equal(wire[72:76], []byte{172, 16, 1, 2}) {
		t.Errorf("inner IPv4 addresses wrong: % x / % x", wire[68:72], wire[72:76])
	}
}

// TestGenerateWireIPv6Outer locks the IPv6-outer layout (design §2): flags 54,
// key 58, inner Ethernet 62 — Next Header 47 on the outer IPv6.
func TestGenerateWireIPv6Outer(t *testing.T) {
	cfg := &core.NVGREConfig{VSID: 0x000001, FlowID: 0x02, Inner: fixture()}
	pkts := collectEmit(t, cfg, "2001:db8::10", "2001:db8::20")
	if len(pkts) != 1 {
		t.Fatalf("got %d packets, want 1", len(pkts))
	}
	wire := wireBuild(t, pkts[0])
	if !bytes.Equal(wire[54:58], []byte{0x20, 0x00, 0x65, 0x58}) {
		t.Errorf("wire[54:58] = % x, want 20 00 65 58", wire[54:58])
	}
	if !bytes.Equal(wire[58:62], []byte{0x00, 0x00, 0x01, 0x02}) {
		t.Errorf("wire[58:62] key = % x, want 00 00 01 02", wire[58:62])
	}
	// Outer IPv6 next header at 14+6=20 must be 47.
	if wire[20] != 47 {
		t.Errorf("outer IPv6 next header %d, want 47", wire[20])
	}
	if !bytes.Equal(wire[62:68], []byte{0x02, 0xbb, 0x00, 0x00, 0x00, 0x01}) {
		t.Errorf("wire[62:68] inner dst MAC = % x", wire[62:68])
	}
	if !bytes.Equal(wire[74:76], []byte{0x08, 0x00}) {
		t.Errorf("wire[74:76] inner EtherType = % x, want 08 00", wire[74:76])
	}
}

// TestGenerateTTLSemantics pins the *uint8 TTL contract: nil → 64; explicit 0
// and 255 are legal boundaries and must survive (design §5.1/§7).
func TestGenerateTTLSemantics(t *testing.T) {
	zero := uint8(0)
	max := uint8(255)
	cases := []struct {
		ttl  *uint8
		want uint8
	}{
		{nil, 64},
		{&zero, 0},
		{&max, 255},
		{func() *uint8 { v := uint8(1); return &v }(), 1},
	}
	for _, c := range cases {
		cfg := &core.NVGREConfig{VSID: 1, Inner: fixture(), TTL: c.ttl}
		pkts := collectEmit(t, cfg, "192.0.2.10", "198.51.100.10")
		if len(pkts) != 1 || pkts[0].L3.TTL != c.want {
			t.Errorf("TTL %v: got %d packets, TTL %d; want TTL %d", c.ttl, len(pkts), pkts[0].L3.TTL, c.want)
		}
	}
}

// TestDatagramFolding pins the folding contract (design §6): empty Datagrams
// → one packet from top-level VSID/FlowID/Inner; N entries → N packets with
// per-entry values; entry Inner nil falls back to the top-level fixture; Up
// false → Direction down (the raw-IP branch swaps L3, the generator must not
// pre-swap).
func TestDatagramFolding(t *testing.T) {
	// Empty → single top-level packet.
	cfg := &core.NVGREConfig{VSID: 0x123456, FlowID: 0x7a, Inner: fixture()}
	pkts := collectEmit(t, cfg, "192.0.2.10", "198.51.100.10")
	if len(pkts) != 1 {
		t.Fatalf("empty datagrams: got %d packets, want 1", len(pkts))
	}

	// N entries → N packets, per-entry key/inner, inner fallback, down flag.
	up := true
	down := false
	innerA := fixture()
	innerB := &core.EncapEthernetFixture{
		SrcMAC: "02:aa:00:00:00:02", DstMAC: "02:bb:00:00:00:02",
		EtherType: "ipv4", SrcIP: "172.16.2.1", DstIP: "172.16.2.2",
		Payload: []byte("vsid-bb-frame"),
	}
	cfg = &core.NVGREConfig{
		Inner: innerA, // fallback for entries without Inner
		Datagrams: []core.NVGREDatagram{
			{VSID: 0x0000aa, FlowID: 1},
			{VSID: 0x0000bb, FlowID: 1, Inner: innerB},
			{VSID: 0x0000aa, FlowID: 2, Up: &down},
			{VSID: 0x0000aa, FlowID: 3, Up: &up},
		},
	}
	pkts = collectEmit(t, cfg, "192.0.2.10", "198.51.100.10")
	if len(pkts) != 4 {
		t.Fatalf("4 datagrams: got %d packets, want 4", len(pkts))
	}
	wantKeys := []uint32{
		GREKey(0x0000aa, 1),
		GREKey(0x0000bb, 1),
		GREKey(0x0000aa, 2),
		GREKey(0x0000aa, 3),
	}
	for i, want := range wantKeys {
		if pkts[i].L2.GRE == nil || pkts[i].L2.GRE.Key != want {
			t.Errorf("packet %d key mismatch", i+1)
		}
	}
	// Entry without Inner falls back to the top-level fixture (packet 1).
	if !bytes.Contains(pkts[0].Payload, []byte("nvgre-inner-01")) {
		t.Errorf("packet 1 payload not from top-level inner fallback")
	}
	// Entry with explicit Inner uses it (packet 2).
	if !bytes.Contains(pkts[1].Payload, []byte("vsid-bb-frame")) {
		t.Errorf("packet 2 payload not from datagram inner")
	}
	// Direction: entries 3 is down, others up; down must NOT pre-swap L3.
	if pkts[2].Direction != "down" {
		t.Errorf("packet 3 direction %q, want down", pkts[2].Direction)
	}
	if pkts[2].L3.SrcIP != "192.0.2.10" || pkts[2].L3.DstIP != "198.51.100.10" {
		t.Errorf("down packet L3 must stay up-oriented (finalEmit swaps): %v", pkts[2].L3)
	}
	if pkts[3].Direction != "up" {
		t.Errorf("packet 4 direction %q, want up", pkts[3].Direction)
	}
}

// TestGenerateEmptyConfigDefaultFlow (P0b contract): a nil config must still
// produce one parseable datagram with the default VSID=0/FlowID=0.
func TestGenerateEmptyConfigDefaultFlow(t *testing.T) {
	pkts := collectEmit(t, nil, "192.0.2.10", "198.51.100.10")
	if len(pkts) != 1 {
		t.Fatalf("nil config: got %d packets, want 1", len(pkts))
	}
	if pkts[0].L2.GRE == nil || pkts[0].L2.GRE.Key != 0 {
		t.Errorf("nil config default key must be 0")
	}
}

// TestGenerateNilEmit: nil request / nil Emit is a hard error, never a panic.
func TestGenerateNilEmit(t *testing.T) {
	if err := (&NVGREGenerator{}).Generate(context.Background(), nil); err == nil {
		t.Errorf("nil request: want error")
	}
	req := &layers.GenRequest{Meta: layers.FlowMeta{NVGRE: &core.NVGREConfig{}}}
	if err := (&NVGREGenerator{}).Generate(context.Background(), req); err == nil {
		t.Errorf("nil Emit: want error")
	}
}

// TestGenerateCtxCancel: context cancellation propagates instead of emitting.
func TestGenerateCtxCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cfg := &core.NVGREConfig{VSID: 1, Inner: fixture()}
	req := &layers.GenRequest{
		Meta: layers.FlowMeta{NVGRE: cfg, SrcIP: "192.0.2.10", DstIP: "198.51.100.10"},
		Emit: func(pkt core.PacketConfig) error { return nil },
	}
	if err := (&NVGREGenerator{}).Generate(ctx, req); err == nil {
		t.Errorf("cancelled ctx: want error")
	}
}

// TestBuildInnerFrameVariants covers all 4 ether_type variants: byte layout,
// TCI bits (PCP<<13|VID), inner IP header fields, checksum/next-header.
func TestBuildInnerFrameVariants(t *testing.T) {
	// ipv4
	f := fixture()
	b, err := buildInnerFrame(f)
	if err != nil {
		t.Fatalf("ipv4: %v", err)
	}
	if len(b) != 14+20+14 {
		t.Fatalf("ipv4 frame len %d, want 48", len(b))
	}
	if !bytes.Equal(b[12:14], []byte{0x08, 0x00}) {
		t.Errorf("ipv4 EtherType % x", b[12:14])
	}
	if !verifyIPv4Checksum(b[14:34]) {
		t.Errorf("ipv4 inner header checksum invalid")
	}
	if b[14+9] != 253 {
		t.Errorf("inner IPv4 protocol %d, want 253", b[14+9])
	}

	// ipv6
	f6 := &core.EncapEthernetFixture{SrcMAC: "02:aa:00:00:00:11", DstMAC: "02:bb:00:00:00:11", EtherType: "ipv6", SrcIP: "fc00::1", DstIP: "fc00::2", Payload: []byte("v6")}
	b, err = buildInnerFrame(f6)
	if err != nil {
		t.Fatalf("ipv6: %v", err)
	}
	if len(b) != 14+40+2 {
		t.Fatalf("ipv6 frame len %d, want 56", len(b))
	}
	if !bytes.Equal(b[12:14], []byte{0x86, 0xdd}) {
		t.Errorf("ipv6 EtherType % x", b[12:14])
	}
	if b[14]>>4 != 6 {
		t.Errorf("inner IPv6 version %d", b[14]>>4)
	}
	if binary.BigEndian.Uint16(b[14+4:14+6]) != 2 {
		t.Errorf("inner IPv6 payload length %d, want 2", binary.BigEndian.Uint16(b[14+4:14+6]))
	}
	if b[14+6] != 59 {
		t.Errorf("inner IPv6 next header %d, want 59 (No Next Header)", b[14+6])
	}
	if b[14+7] != 64 {
		t.Errorf("inner IPv6 hop limit %d, want 64", b[14+7])
	}

	// vlan_ipv4: TPID 0x8100, TCI = PCP<<13 | VID.
	fv := fixture()
	fv.EtherType = "vlan_ipv4"
	fv.VLANID = 100
	fv.VLANPriority = 3
	b, err = buildInnerFrame(fv)
	if err != nil {
		t.Fatalf("vlan_ipv4: %v", err)
	}
	if len(b) != 18+20+14 {
		t.Fatalf("vlan_ipv4 frame len %d, want 52", len(b))
	}
	if !bytes.Equal(b[12:16], []byte{0x81, 0x00, 0x60, 0x64}) { // 3<<13|100 = 0x6064
		t.Errorf("vlan tag % x, want 81 00 60 64", b[12:16])
	}
	if !bytes.Equal(b[16:18], []byte{0x08, 0x00}) {
		t.Errorf("post-VLAN EtherType % x", b[16:18])
	}
	if !verifyIPv4Checksum(b[18:38]) {
		t.Errorf("vlan_ipv4 inner checksum invalid")
	}

	// vlan_ipv6 + TCI boundary: priority 7 / VID 4095 → 0xEFFF.
	fv6 := &core.EncapEthernetFixture{SrcMAC: "02:aa:00:00:00:11", DstMAC: "02:bb:00:00:00:11", EtherType: "vlan_ipv6", SrcIP: "fc00::1", DstIP: "fc00::2", VLANID: 4095, VLANPriority: 7}
	b, err = buildInnerFrame(fv6)
	if err != nil {
		t.Fatalf("vlan_ipv6: %v", err)
	}
	if !bytes.Equal(b[12:16], []byte{0x81, 0x00, 0xef, 0xff}) {
		t.Errorf("vlan_ipv6 TCI % x, want ef ff", b[12:16])
	}
	if !bytes.Equal(b[16:18], []byte{0x86, 0xdd}) {
		t.Errorf("vlan_ipv6 EtherType % x", b[16:18])
	}

	// Empty payload is a legal boundary (design §7).
	fe := fixture()
	fe.Payload = nil
	b, err = buildInnerFrame(fe)
	if err != nil {
		t.Fatalf("empty payload: %v", err)
	}
	if len(b) != 34 {
		t.Errorf("empty-payload frame len %d, want 34", len(b))
	}
}

// verifyIPv4Checksum reports whether a 20-byte IPv4 header carries a valid
// RFC 1071 checksum (sum of all 16-bit words, checksum included, == 0xFFFF).
func verifyIPv4Checksum(hdr []byte) bool {
	if len(hdr) < 20 {
		return false
	}
	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(hdr[i : i+2]))
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return sum == 0xffff
}

// TestValidatorAnchors covers every rejection rule and its testcase-contract
// anchor word (strings.Contains, case-sensitive).
func TestValidatorAnchors(t *testing.T) {
	cases := []struct {
		name   string
		cfg    *core.NVGREConfig
		anchor string
	}{
		{"vsid_overflow_top", &core.NVGREConfig{VSID: 0x1000000, Inner: fixture()}, "vsid"},
		{"vsid_overflow_datagram", &core.NVGREConfig{Inner: fixture(), Datagrams: []core.NVGREDatagram{{VSID: 0xffffff + 1}}}, "vsid"},
		{"fault_flags_reserved", &core.NVGREConfig{VSID: 1, Inner: fixture(), WireFault: &core.EncapWireFault{Kind: "flags_reserved"}}, "flags"},
		{"fault_protocol_not_teb", &core.NVGREConfig{VSID: 1, Inner: fixture(), WireFault: &core.EncapWireFault{Kind: "protocol_not_teb"}}, "protocol"},
		{"fault_key_missing", &core.NVGREConfig{VSID: 1, Inner: fixture(), WireFault: &core.EncapWireFault{Kind: "key_missing"}}, "key"},
		{"fault_key_endian", &core.NVGREConfig{VSID: 1, Inner: fixture(), WireFault: &core.EncapWireFault{Kind: "key_endian"}}, "key"},
		{"fault_vsid_flow_isolation", &core.NVGREConfig{VSID: 1, Inner: fixture(), WireFault: &core.EncapWireFault{Kind: "vsid_flow_isolation"}}, "isolation"},
		{"fault_carrier_protocol", &core.NVGREConfig{VSID: 1, Inner: fixture(), WireFault: &core.EncapWireFault{Kind: "carrier_protocol"}}, "carrier"},
		{"fault_length_wrap", &core.NVGREConfig{VSID: 1, Inner: fixture(), WireFault: &core.EncapWireFault{Kind: "length_wrap"}}, "length"},
		{"unknown_fault_kind", &core.NVGREConfig{VSID: 1, Inner: fixture(), WireFault: &core.EncapWireFault{Kind: "bogus"}}, "unknown wire_fault"},
		{"bad_src_mac", &core.NVGREConfig{VSID: 1, Inner: &core.EncapEthernetFixture{SrcMAC: "nope", DstMAC: "02:bb:00:00:00:01", EtherType: "ipv4", SrcIP: "172.16.1.1", DstIP: "172.16.1.2"}}, "inner"},
		{"bad_dst_mac", &core.NVGREConfig{VSID: 1, Inner: &core.EncapEthernetFixture{SrcMAC: "02:aa:00:00:00:01", DstMAC: "02:bb:00:00:00", EtherType: "ipv4", SrcIP: "172.16.1.1", DstIP: "172.16.1.2"}}, "inner"},
		{"bad_ether_type", &core.NVGREConfig{VSID: 1, Inner: &core.EncapEthernetFixture{SrcMAC: "02:aa:00:00:00:01", DstMAC: "02:bb:00:00:00:01", EtherType: "gre", SrcIP: "172.16.1.1", DstIP: "172.16.1.2"}}, "inner"},
		{"vid_overflow", &core.NVGREConfig{VSID: 1, Inner: &core.EncapEthernetFixture{SrcMAC: "02:aa:00:00:00:01", DstMAC: "02:bb:00:00:00:01", EtherType: "vlan_ipv4", VLANID: 5000, SrcIP: "172.16.1.1", DstIP: "172.16.1.2"}}, "vlan"},
		{"pcp_overflow", &core.NVGREConfig{VSID: 1, Inner: &core.EncapEthernetFixture{SrcMAC: "02:aa:00:00:00:01", DstMAC: "02:bb:00:00:00:01", EtherType: "vlan_ipv4", VLANID: 1, VLANPriority: 8, SrcIP: "172.16.1.1", DstIP: "172.16.1.2"}}, "vlan"},
		{"family_mismatch_v6type_v4addr", &core.NVGREConfig{VSID: 1, Inner: &core.EncapEthernetFixture{SrcMAC: "02:aa:00:00:00:01", DstMAC: "02:bb:00:00:00:01", EtherType: "ipv6", SrcIP: "172.16.1.1", DstIP: "fc00::2"}}, "family"},
		{"family_mismatch_v4type_v6addr", &core.NVGREConfig{VSID: 1, Inner: &core.EncapEthernetFixture{SrcMAC: "02:aa:00:00:00:01", DstMAC: "02:bb:00:00:00:01", EtherType: "ipv4", SrcIP: "fc00::1", DstIP: "172.16.1.2"}}, "family"},
		{"inner_ip_unparseable", &core.NVGREConfig{VSID: 1, Inner: &core.EncapEthernetFixture{SrcMAC: "02:aa:00:00:00:01", DstMAC: "02:bb:00:00:00:01", EtherType: "ipv4", SrcIP: "not-an-ip", DstIP: "172.16.1.2"}}, "inner"},
		{"payload_overflow", &core.NVGREConfig{VSID: 1, Inner: &core.EncapEthernetFixture{SrcMAC: "02:aa:00:00:00:01", DstMAC: "02:bb:00:00:00:01", EtherType: "ipv4", SrcIP: "172.16.1.1", DstIP: "172.16.1.2", Payload: make([]byte, maxInnerPayload+1)}}, "length"},
		{"datagram_fault", &core.NVGREConfig{Inner: fixture(), Datagrams: []core.NVGREDatagram{{VSID: 1, Inner: &core.EncapEthernetFixture{SrcMAC: "x", DstMAC: "02:bb:00:00:00:01", EtherType: "ipv4", SrcIP: "172.16.1.1", DstIP: "172.16.1.2"}}}}, "inner"},
	}
	for _, c := range cases {
		err := ValidateConfig(c.cfg)
		if err == nil {
			t.Errorf("%s: want error, got nil", c.name)
			continue
		}
		if !strings.Contains(err.Error(), c.anchor) {
			t.Errorf("%s: error %q missing anchor %q", c.name, err.Error(), c.anchor)
		}
	}
}

// TestValidatorBoundariesLegal: explicit zero values and boundaries must NOT
// be rejected (design §7: VSID=0, FlowID=0, empty payload, VID=0/4095,
// TTL=0/1/255, broadcast MAC).
func TestValidatorBoundariesLegal(t *testing.T) {
	max := uint8(255)
	cfgs := []*core.NVGREConfig{
		{VSID: 0, FlowID: 0, Inner: fixture(), TTL: &max},
		{VSID: 0xffffff, FlowID: 0xff, Inner: fixture()},
		{Inner: &core.EncapEthernetFixture{SrcMAC: "ff:ff:ff:ff:ff:ff", DstMAC: "01:00:5e:00:00:01", EtherType: "ipv4", SrcIP: "172.16.1.1", DstIP: "172.16.1.2"}},
		{Inner: &core.EncapEthernetFixture{SrcMAC: "02:aa:00:00:00:01", DstMAC: "02:bb:00:00:00:01", EtherType: "vlan_ipv4", VLANID: 4095, VLANPriority: 7, SrcIP: "172.16.1.1", DstIP: "172.16.1.2"}},
		{Inner: &core.EncapEthernetFixture{SrcMAC: "02:aa:00:00:00:01", DstMAC: "02:bb:00:00:00:01", EtherType: "vlan_ipv4", VLANID: 0, SrcIP: "172.16.1.1", DstIP: "172.16.1.2"}},
		{Inner: &core.EncapEthernetFixture{SrcMAC: "02:aa:00:00:00:01", DstMAC: "02:bb:00:00:00:01", EtherType: "ipv4", SrcIP: "172.16.1.1", DstIP: "172.16.1.2", Payload: make([]byte, maxInnerPayload)}},
		{VSID: 1, Inner: fixture(), WireFault: nil},
	}
	for i, cfg := range cfgs {
		if err := ValidateConfig(cfg); err != nil {
			t.Errorf("boundary %d: unexpected error %v", i, err)
		}
	}
}

// TestGenerateRejectsInvalidConfig mirrors the validator in the generator
// (dual insurance): a bad config never reaches Emit.
func TestGenerateRejectsInvalidConfig(t *testing.T) {
	emitted := 0
	req := &layers.GenRequest{
		Meta: layers.FlowMeta{NVGRE: &core.NVGREConfig{VSID: 0x1000000}, SrcIP: "192.0.2.10", DstIP: "198.51.100.10"},
		Emit: func(pkt core.PacketConfig) error { emitted++; return nil },
	}
	if err := (&NVGREGenerator{}).Generate(context.Background(), req); err == nil {
		t.Errorf("want error for vsid overflow")
	}
	if emitted != 0 {
		t.Errorf("emitted %d packets on invalid config", emitted)
	}
}

// TestGeneratorInterface pins the layer contract: raw-IP generators produce no
// events and are registered under "nvgre".
func TestGeneratorInterface(t *testing.T) {
	g := &NVGREGenerator{}
	if g.Name() != "nvgre" {
		t.Errorf("Name %q", g.Name())
	}
	if g.GenEvents() != nil {
		t.Errorf("GenEvents must be nil for raw-IP generators")
	}
	factory, err := layers.NewLayerGenerator("nvgre")
	if err != nil {
		t.Fatalf("NewLayerGenerator: %v", err)
	}
	if factory.Name() != "nvgre" {
		t.Errorf("registered generator name %q", factory.Name())
	}
}
