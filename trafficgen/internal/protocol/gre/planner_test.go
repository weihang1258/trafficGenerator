package gre

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

// planAll runs the planner to completion and returns every emitted config.
func planAll(t *testing.T, spec core.FlowSpec) []core.PacketConfig {
	t.Helper()
	p := NewPlanner()
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var out []core.PacketConfig
	for cfg := range ch {
		out = append(out, cfg)
	}
	return out
}

// buildAll builds every config with the core builder.
func buildAll(t *testing.T, cfgs []core.PacketConfig) [][]byte {
	t.Helper()
	builder := core.NewBuilder()
	frames := make([][]byte, 0, len(cfgs))
	for i, cfg := range cfgs {
		frame, err := builder.Build(cfg)
		if err != nil {
			t.Fatalf("Build packet[%d]: %v", i, err)
		}
		frames = append(frames, frame)
	}
	return frames
}

// ipv4HeaderChecksum is an independent RFC 791 §3.1 checksum for test
// verification (does not reuse the code under test). b must be the full
// 20-byte IPv4 header; the checksum field is zeroed before summing.
func ipv4HeaderChecksum(b []byte) uint16 {
	hdr := append([]byte(nil), b...)
	hdr[10], hdr[11] = 0, 0
	sum := uint32(0)
	for i := 0; i < len(hdr); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(hdr[i : i+2]))
	}
	for sum>>16 != 0 {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}

// TestPlanner_ARPOverGRE verifies the ARP-over-GRE scenario (RFC 2784
// Protocol Type 0x0806): the outer IPv4 (protocol 47) + 4-byte GRE header
// (no option fields) + a 28-byte ARP message with the flow's MAC/IP
// addresses, matching the structure of pcap 1.ARPoverGRE.pcap frame 1.
func TestPlanner_ARPOverGRE(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP:   "10.0.21.2",
		DstIP:   "10.0.21.1",
		SrcMAC:  "c8:02:16:a6:00:01",
		DstMAC:  "c8:01:16:93:00:01",
		SrcPort: 0,
		DstPort: 0,
		ARP:     &core.ARPConfig{Operation: 2}, // reply, like the pcap
		GRE: &core.GREConfig{
			ProtocolType: core.EtherTypeARP,
		},
	}

	cfgs := planAll(t, spec)
	if len(cfgs) != 1 {
		t.Fatalf("emitted %d packets, want 1", len(cfgs))
	}
	cfg := cfgs[0]

	// Outer layer: IPv4 with protocol 47, GRE with Protocol Type 0x0806.
	if cfg.L2.EtherType != core.EtherTypeIPv4 {
		t.Errorf("outer EtherType = 0x%04x, want 0x0800", cfg.L2.EtherType)
	}
	if cfg.L3.Protocol != core.ProtocolGRE {
		t.Errorf("outer IP protocol = %d, want 47", cfg.L3.Protocol)
	}
	if cfg.L3.SrcIP != spec.SrcIP || cfg.L3.DstIP != spec.DstIP {
		t.Errorf("outer IPs = %s->%s, want %s->%s", cfg.L3.SrcIP, cfg.L3.DstIP, spec.SrcIP, spec.DstIP)
	}
	if cfg.L4.Protocol != "" {
		t.Errorf("L4 protocol = %q, want empty (inner packet lives in Payload)", cfg.L4.Protocol)
	}
	gre := cfg.L2.GRE
	if gre == nil || gre.ProtocolType != core.EtherTypeARP {
		t.Fatalf("GRE config = %+v, want ProtocolType 0x0806", gre)
	}
	if gre.Checksum || gre.KeyPresent || gre.SequencePresent || gre.RoutingPresent {
		t.Errorf("GRE options enabled, want none (flags 0x0000 like the pcap)")
	}

	// Inner ARP message: 28 bytes with the flow's addresses.
	wantARP := []byte{
		0x00, 0x01, // hardware type Ethernet
		0x08, 0x00, // protocol type IPv4
		0x06, 0x04, // address lengths
		0x00, 0x02, // operation: reply
		0xc8, 0x02, 0x16, 0xa6, 0x00, 0x01, // sender HW = SrcMAC
		0x0a, 0x00, 0x15, 0x02, // sender proto = SrcIP 10.0.21.2
		0xc8, 0x01, 0x16, 0x93, 0x00, 0x01, // target HW = DstMAC
		0x0a, 0x00, 0x15, 0x01, // target proto = DstIP 10.0.21.1
	}
	if !bytes.Equal(cfg.Payload, wantARP) {
		t.Errorf("ARP payload = % x, want % x", cfg.Payload, wantARP)
	}

	// End-to-end: the built frame is eth(14) + outer IP(20) + GRE(4) + ARP(28)
	// = 66 bytes; the GRE header sits at offset 34 and the ARP after it.
	frames := buildAll(t, cfgs)
	frame := frames[0]
	if len(frame) != 66 {
		t.Fatalf("frame len = %d, want 66", len(frame))
	}
	if !bytes.Equal(frame[34:38], []byte{0x00, 0x00, 0x08, 0x06}) {
		t.Errorf("GRE header = % x, want 00 00 08 06 at offset 34", frame[34:38])
	}
	if !bytes.Equal(frame[38:66], wantARP) {
		t.Errorf("ARP on wire = % x, want % x at offset 38", frame[38:66], wantARP)
	}
	// Outer total length covers GRE + ARP.
	if total := binary.BigEndian.Uint16(frame[16:18]); int(total) != 20+4+28 {
		t.Errorf("outer total length = %d, want 52", total)
	}
}

// TestPlanner_DNSOverGRE verifies the DNS-over-GRE scenario against pcap
// 6、gre_dns.pcap frame 1: outer IPv4 + GRE (K bit, Key 0x00000000, RFC
// 2890) + inner IPv4/UDP/DNS. The inner IP checksum must equal the pcap's
// 0x9191 and the UDP checksum the pcap's 0x1ee4 — real-wire ground truth
// for the planner's inner checksum code.
func TestPlanner_DNSOverGRE(t *testing.T) {
	// DNS query for clients3.google.com (pcap frame 1, 37 bytes).
	dnsQuery := []byte{
		0x4c, 0x87, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x08, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x73, 0x33, // clients3
		0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, // google
		0x03, 0x63, 0x6f, 0x6d, 0x00, // com
		0x00, 0x01, 0x00, 0x01, // type A, class IN
	}
	spec := core.FlowSpec{
		SrcIP:   "155.0.0.5", // outer (pcap)
		DstIP:   "154.0.0.4",
		SrcPort: 45078,
		DstPort: 53,
		SrcMAC:  "2c:b0:5d:93:e4:b4",
		DstMAC:  "18:03:73:db:74:0b",
		TTL:     62, // outer TTL (pcap 0x3e)
		GRE: &core.GREConfig{
			ProtocolType: core.EtherTypeIPv4,
			KeyPresent:   true, // K bit (pcap flags 0x2000)
			Key:          0x00000000,
			InnerSrcIP:   "153.0.0.11", // inner (pcap)
			InnerDstIP:   "8.8.8.8",
			InnerProto:   17, // UDP
			InnerTTL:     64, // pcap 0x40
			InnerIPID:    0,  // pcap 0x0000
		},
		Payload: dnsQuery,
	}

	cfgs := planAll(t, spec)
	if len(cfgs) != 1 {
		t.Fatalf("emitted %d packets, want 1", len(cfgs))
	}
	cfg := cfgs[0]
	if cfg.L2.GRE == nil || cfg.L2.GRE.ProtocolType != core.EtherTypeIPv4 || !cfg.L2.GRE.KeyPresent || cfg.L2.GRE.Key != 0 {
		t.Errorf("GRE config = %+v, want K=1 Key=0", cfg.L2.GRE)
	}
	if cfg.L4.Protocol != "" {
		t.Errorf("L4 protocol = %q, want empty", cfg.L4.Protocol)
	}

	frames := buildAll(t, cfgs)
	frame := frames[0]
	if len(frame) != 107 {
		t.Fatalf("frame len = %d, want 107 (14 eth + 20 outer IP + 8 GRE + 65 inner)", len(frame))
	}

	// GRE header at 34: flags 0x2000 (K), Protocol Type 0x0800, Key 0.
	if !bytes.Equal(frame[34:42], []byte{0x20, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00}) {
		t.Errorf("GRE header = % x, want 20 00 08 00 00 00 00 00 at offset 34", frame[34:42])
	}

	// Inner IPv4 header at 42 (pcap bytes, checksum 0x9191 recomputed by
	// the planner and verified against the pcap).
	if !bytes.Equal(frame[42:52], []byte{0x45, 0x00, 0x00, 0x41, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11}) {
		t.Errorf("inner IP header prefix = % x, want 45 00 00 41 00 00 40 00 40 11", frame[42:52])
	}
	if got := binary.BigEndian.Uint16(frame[52:54]); got != 0x9191 {
		t.Errorf("inner IP checksum = 0x%04x, want 0x9191 (pcap value)", got)
	}
	if !bytes.Equal(frame[54:62], []byte{0x99, 0x00, 0x00, 0x0b, 0x08, 0x08, 0x08, 0x08}) {
		t.Errorf("inner IPs = % x, want 153.0.0.11 -> 8.8.8.8", frame[54:62])
	}

	// Inner UDP header at 62: ports, length 45, checksum 0x1ee4 (pcap).
	if !bytes.Equal(frame[62:68], []byte{0xb0, 0x16, 0x00, 0x35, 0x00, 0x2d}) {
		t.Errorf("inner UDP header = % x, want b0 16 00 35 00 2d at offset 62", frame[62:68])
	}
	if got := binary.BigEndian.Uint16(frame[68:70]); got != 0x1ee4 {
		t.Errorf("inner UDP checksum = 0x%04x, want 0x1ee4 (pcap value)", got)
	}
	if !bytes.Equal(frame[70:107], dnsQuery) {
		t.Errorf("DNS payload mismatch:\n got % x\nwant % x", frame[70:107], dnsQuery)
	}

	// Outer IP: total length 0x5d covers GRE + inner; checksum recomputed
	// independently must equal the wire value (the pcap's 0xfd94 differs
	// only because the planner's outer IPID is 1, not 0x49d4).
	if total := binary.BigEndian.Uint16(frame[16:18]); int(total) != 20+8+65 {
		t.Errorf("outer total length = %d, want 93", total)
	}
	if got, want := binary.BigEndian.Uint16(frame[24:26]), ipv4HeaderChecksum(frame[14:34]); got != want {
		t.Errorf("outer IP checksum = 0x%04x, independent recomputation = 0x%04x", got, want)
	}
	if frame[22] != 62 {
		t.Errorf("outer TTL = %d, want 62", frame[22])
	}
}

// TestPlanner_HTTPOverGRE_PcapChecksums verifies the HTTP-over-GRE scenario
// against pcap HTTP_gre_nm4.pcap frame 3 (the GET request): the inner
// IPv4/TCP checksums must equal the pcap's 0x37d7 (IP) and 0x965c (TCP) —
// real-wire ground truth for the planner's inner TCP checksum code.
func TestPlanner_HTTPOverGRE_PcapChecksums(t *testing.T) {
	get := "GET /ip HTTP/1.1\r\n" +
		"accept: */*\r\n" +
		"connection: Keep-Alive\r\n" +
		"User-Agent: Dalvik/2.1.0 (Linux; U; Android 9; MI 8 SE MIUI/V10.3.2.0.PEBCNXM)\r\n" +
		"Host: proxy.api.adoceans.com\r\n" +
		"Accept-Encoding: gzip\r\n\r\n"
	if len(get) != 190 {
		t.Fatalf("GET payload len = %d, want 190 (pcap inner total 0xe6 = 20 IP + 20 TCP + 190)", len(get))
	}

	spec := core.FlowSpec{
		SrcIP:   "115.170.117.34", // outer (pcap frame 3)
		DstIP:   "36.102.20.6",
		SrcPort: 41468,
		DstPort: 80,
		TCP: &core.TCPConfig{
			Seq:        0xa185446c, // pcap
			Ack:        0x68e1cf52,
			Flags:      0x18, // PSH|ACK
			WindowSize: 0x00ac,
		},
		GRE: &core.GREConfig{
			ProtocolType: core.EtherTypeIPv4,
			InnerSrcIP:   "10.101.215.129", // inner (pcap)
			InnerDstIP:   "101.200.205.176",
			InnerProto:   6, // TCP
			InnerTTL:     63, // pcap 0x3f
			InnerIPID:    0xeda3, // pcap
		},
		Payload: []byte(get),
	}

	cfgs := planAll(t, spec)
	frames := buildAll(t, cfgs)
	frame := frames[0]

	// GRE: no options (flags 0x0000), Protocol Type 0x0800.
	if !bytes.Equal(frame[34:38], []byte{0x00, 0x00, 0x08, 0x00}) {
		t.Errorf("GRE header = % x, want 00 00 08 00 at offset 34", frame[34:38])
	}

	// Inner IPv4 header at 38 (14 eth + 20 outer IP + 4 GRE): TOS 0 (the
	// pcap's inner carries DSCP 14 -> TOS 0x38, but the planner writes TOS
	// 0 like the L2TP inner builder — the checksum is verified against an
	// independent recomputation of THIS header), total 0x00e6, IPID 0xeda3,
	// DF, TTL 63, TCP.
	if !bytes.Equal(frame[38:48], []byte{0x45, 0x00, 0x00, 0xe6, 0xed, 0xa3, 0x40, 0x00, 0x3f, 0x06}) {
		t.Errorf("inner IP header prefix = % x, want 45 00 00 e6 ed a3 40 00 3f 06", frame[38:48])
	}
	if got, want := binary.BigEndian.Uint16(frame[48:50]), ipv4HeaderChecksum(frame[38:58]); got != want {
		t.Errorf("inner IP checksum = 0x%04x, independent recomputation = 0x%04x", got, want)
	}

	// Inner TCP header at 58 (20 bytes, no options): ports, seq, ack,
	// data offset 5, PSH|ACK, window 0x00ac, checksum must equal the
	// pcap's 0x965c.
	wantTCP := []byte{
		0xa1, 0xfc, 0x00, 0x50, // 41468 -> 80
		0xa1, 0x85, 0x44, 0x6c, // seq
		0x68, 0xe1, 0xcf, 0x52, // ack
		0x50, 0x18, // data offset 5, PSH|ACK
		0x00, 0xac, // window
		0x96, 0x5c, // checksum (pcap value)
		0x00, 0x00, // urgent
	}
	if !bytes.Equal(frame[58:78], wantTCP) {
		t.Errorf("inner TCP header = % x, want % x at offset 58", frame[58:78], wantTCP)
	}
	if !bytes.Equal(frame[78:], []byte(get)) {
		t.Errorf("HTTP payload mismatch at offset 78")
	}

	// Outer total length covers GRE + the 230-byte inner packet.
	if total := binary.BigEndian.Uint16(frame[16:18]); int(total) != 20+4+230 {
		t.Errorf("outer total length = %d, want 254", total)
	}
}

// TestPlanner_KeyMultiTunnel verifies the Key field distinguishes parallel
// GRE tunnels (RFC 2890): two flows with different Keys emit GRE headers
// carrying their own Key.
func TestPlanner_KeyMultiTunnel(t *testing.T) {
	keys := []uint32{0x00001000, 0x00002000}
	for i, key := range keys {
		spec := core.FlowSpec{
			SrcIP: "10.0.0.1", DstIP: "20.0.0.1",
			SrcPort: uint16(1000 + i), DstPort: 53,
			GRE: &core.GREConfig{
				ProtocolType: core.EtherTypeIPv4,
				KeyPresent:   true,
				Key:          key,
				InnerSrcIP:   "192.168.1.1",
				InnerDstIP:   "192.168.1.2",
				InnerProto:   17,
			},
			Payload: []byte("tunnel-data"),
		}
		cfgs := planAll(t, spec)
		if len(cfgs) != 1 {
			t.Fatalf("tunnel %d: emitted %d packets, want 1", i, len(cfgs))
		}
		if cfgs[0].L2.GRE == nil || !cfgs[0].L2.GRE.KeyPresent || cfgs[0].L2.GRE.Key != key {
			t.Errorf("tunnel %d: GRE key = %+v, want 0x%08x", i, cfgs[0].L2.GRE, key)
		}
		frames := buildAll(t, cfgs)
		frame := frames[0]
		// GRE at 34: flags 0x2000 + proto 0x0800 + Key (4 bytes at 38).
		if !bytes.Equal(frame[34:38], []byte{0x20, 0x00, 0x08, 0x00}) {
			t.Errorf("tunnel %d: GRE header = % x, want 20 00 08 00", i, frame[34:38])
		}
		if got := binary.BigEndian.Uint32(frame[38:42]); got != key {
			t.Errorf("tunnel %d: wire Key = 0x%08x, want 0x%08x", i, got, key)
		}
	}
}

// TestPlanner_Sequence_Increment verifies the Sequence Number (RFC 2890, S
// bit) increments per emitted frame: base 100 over 3 frames -> 100, 101,
// 102, each with its own inner IPID.
func TestPlanner_Sequence_Increment(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1",
		SrcPort: 1000, DstPort: 53,
		GRE: &core.GREConfig{
			ProtocolType:    core.EtherTypeIPv4,
			SequencePresent: true,
			Sequence:        100,
			Frames:          3,
			InnerSrcIP:      "192.168.1.1",
			InnerDstIP:      "192.168.1.2",
			InnerProto:      17,
			InnerIPID:       0,
		},
		Payload: []byte("seq"),
	}
	cfgs := planAll(t, spec)
	if len(cfgs) != 3 {
		t.Fatalf("emitted %d packets, want 3", len(cfgs))
	}
	frames := buildAll(t, cfgs)
	for i := 0; i < 3; i++ {
		if !cfgs[i].L2.GRE.SequencePresent {
			t.Fatalf("packet %d: SequencePresent = false", i)
		}
		if got := cfgs[i].L2.GRE.Sequence; got != uint32(100+i) {
			t.Errorf("packet %d: GRE sequence = %d, want %d", i, got, 100+i)
		}
		frame := frames[i]
		// GRE at 34: flags 0x1000 (S) + proto 0x0800 + Sequence at 38.
		if !bytes.Equal(frame[34:38], []byte{0x10, 0x00, 0x08, 0x00}) {
			t.Errorf("packet %d: GRE header = % x, want 10 00 08 00", i, frame[34:38])
		}
		if got := binary.BigEndian.Uint32(frame[38:42]); got != uint32(100+i) {
			t.Errorf("packet %d: wire sequence = %d, want %d", i, got, 100+i)
		}
		// Inner IPID increments per frame: 0, 1, 2 at inner header offset
		// 42+4 = 46.
		if got := binary.BigEndian.Uint16(frame[46:48]); got != uint16(i) {
			t.Errorf("packet %d: inner IPID = %d, want %d", i, got, i)
		}
	}
}

// TestPlanner_Checksum_OddLength verifies the C-bit checksum (RFC 2784
// §3.1) end-to-end through the planner: the wire checksum must satisfy the
// receiver verification formula (sum of all 16-bit words including the
// checksum folds to 0xFFFF) — with an odd-length inner packet (UDP payload
// 3 bytes -> inner 31 bytes -> GRE region 39 bytes) exercising the
// 4-byte-boundary padding.
func TestPlanner_Checksum_OddLength(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1",
		SrcPort: 1000, DstPort: 53,
		GRE: &core.GREConfig{
			ProtocolType: core.EtherTypeIPv4,
			Checksum:     true,
			InnerSrcIP:   "192.168.1.1",
			InnerDstIP:   "192.168.1.2",
			InnerProto:   17,
		},
		Payload: []byte("abc"), // odd inner payload
	}
	cfgs := planAll(t, spec)
	frames := buildAll(t, cfgs)
	frame := frames[0]

	greStart := 34
	payloadEnd := len(frame) // no padding: 14+20+8+31 = 73 > 60
	if payloadEnd != 73 {
		t.Fatalf("frame len = %d, want 73", payloadEnd)
	}
	region := frame[greStart:payloadEnd]
	if len(region) != 39 {
		t.Fatalf("GRE checksum region len = %d, want 39 (odd -> padding exercised)", len(region))
	}

	// Receiver verification: sum of every word (checksum included) == 0xFFFF.
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
}

// TestPlanner_Direction_Down verifies the down direction swaps the outer
// MACs/IPs and the inner addresses.
func TestPlanner_Direction_Down(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP:   "10.0.0.1",
		DstIP:   "20.0.0.1",
		SrcMAC:  "02:00:00:00:00:01",
		DstMAC:  "02:00:00:00:00:02",
		SrcPort: 1000, DstPort: 53,
		GRE: &core.GREConfig{
			ProtocolType: core.EtherTypeIPv4,
			InnerSrcIP:   "192.168.1.1",
			InnerDstIP:   "192.168.1.2",
			InnerProto:   17,
			Direction:    "down",
		},
		Payload: []byte("down"),
	}
	cfgs := planAll(t, spec)
	if len(cfgs) != 1 {
		t.Fatalf("emitted %d packets, want 1", len(cfgs))
	}
	cfg := cfgs[0]
	if cfg.Direction != "down" {
		t.Errorf("direction = %q, want down", cfg.Direction)
	}
	if cfg.L2.SrcMAC != spec.DstMAC || cfg.L2.DstMAC != spec.SrcMAC {
		t.Errorf("outer MACs = %s->%s, want swapped", cfg.L2.SrcMAC, cfg.L2.DstMAC)
	}
	if cfg.L3.SrcIP != spec.DstIP || cfg.L3.DstIP != spec.SrcIP {
		t.Errorf("outer IPs = %s->%s, want swapped", cfg.L3.SrcIP, cfg.L3.DstIP)
	}
	// Inner packet: IPv4 header at 38 (GRE is 4 bytes here); src at
	// 38+12=50 must be 192.168.1.2 (swapped).
	frames := buildAll(t, cfgs)
	frame := frames[0]
	if !bytes.Equal(frame[50:54], []byte{0xc0, 0xa8, 0x01, 0x02}) {
		t.Errorf("inner src = % x, want 192.168.1.2 (swapped)", frame[50:54])
	}
	if !bytes.Equal(frame[54:58], []byte{0xc0, 0xa8, 0x01, 0x01}) {
		t.Errorf("inner dst = % x, want 192.168.1.1 (swapped)", frame[54:58])
	}
}

// TestPlanner_IPv6OverGRE verifies IPv6-over-GRE (Protocol Type 0x86DD):
// outer IPv4 (protocol 47) + GRE + a complete inner IPv6 packet with the
// UDP checksum over the IPv6 pseudo-header (RFC 8200 §8.1).
func TestPlanner_IPv6OverGRE(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1", // outer IPv4
		SrcPort: 1234, DstPort: 5678,
		GRE: &core.GREConfig{
			ProtocolType: core.EtherTypeIPv6, // 0x86DD
			InnerSrcIP:   "2001:db8::1",
			InnerDstIP:   "2001:db8::2",
			InnerProto:   17, // UDP
		},
		Payload: []byte("v6data"),
	}
	cfgs := planAll(t, spec)
	if len(cfgs) != 1 {
		t.Fatalf("emitted %d packets, want 1", len(cfgs))
	}
	cfg := cfgs[0]
	if cfg.L2.GRE.ProtocolType != core.EtherTypeIPv6 {
		t.Errorf("GRE ProtocolType = 0x%04x, want 0x86DD", cfg.L2.GRE.ProtocolType)
	}

	frames := buildAll(t, cfgs)
	frame := frames[0]
	// GRE at 34: flags 0x0000 + Protocol Type 0x86DD.
	if !bytes.Equal(frame[34:38], []byte{0x00, 0x00, 0x86, 0xdd}) {
		t.Errorf("GRE header = % x, want 00 00 86 dd at offset 34", frame[34:38])
	}

	// Inner IPv6 header at 38: version 6, payload length 14 (UDP), next
	// header 17, hop limit 64, src/dst.
	wantV6 := []byte{
		0x60, 0x00, 0x00, 0x00, // version 6, traffic class 0, flow label 0
		0x00, 0x0e, // payload length 14 = 8 (UDP) + 6 (payload)
		0x11, // next header UDP
		0x40, // hop limit 64
	}
	if !bytes.Equal(frame[38:46], wantV6) {
		t.Errorf("inner IPv6 header = % x, want % x at offset 38", frame[38:46], wantV6)
	}
	if !bytes.Equal(frame[46:62], []byte(netIP16(t, "2001:db8::1"))) {
		t.Errorf("inner IPv6 src mismatch at offset 46")
	}
	if !bytes.Equal(frame[62:78], []byte(netIP16(t, "2001:db8::2"))) {
		t.Errorf("inner IPv6 dst mismatch at offset 62")
	}

	// Inner UDP at 78: ports 1234/5678, length 14, checksum computed with
	// the IPv6 pseudo-header — verify independently.
	if !bytes.Equal(frame[78:84], []byte{0x04, 0xd2, 0x16, 0x2e, 0x00, 0x0e}) {
		t.Errorf("inner UDP header = % x, want 04 d2 16 2e 00 0e at offset 78", frame[78:84])
	}
	if !bytes.Equal(frame[86:92], []byte("v6data")) {
		t.Errorf("inner payload mismatch at offset 86")
	}
	// UDP checksum over the IPv6 pseudo-header (RFC 8200 §8.1): an
	// independent computation over the pseudo-header + the UDP header with
	// the checksum field zeroed + the payload.
	pseudo := append([]byte{}, netIP16(t, "2001:db8::1")...)
	pseudo = append(pseudo, netIP16(t, "2001:db8::2")...)
	pseudo = binary.BigEndian.AppendUint32(pseudo, 14)
	pseudo = append(pseudo, 0, 0, 0, 17)
	udp := append([]byte(nil), frame[78:86]...)
	udp[6], udp[7] = 0, 0 // zero the checksum field before summing
	sum := uint32(0)
	for i := 0; i < len(pseudo); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(pseudo[i : i+2]))
	}
	for i := 0; i < len(udp); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(udp[i : i+2]))
	}
	for i := 0; i+1 < len(frame[86:]); i += 2 { // payload words (RFC 768: data included)
		sum += uint32(binary.BigEndian.Uint16(frame[86+i : 86+i+2]))
	}
	for sum>>16 != 0 {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	if want := ^uint16(sum); want != binary.BigEndian.Uint16(frame[84:86]) {
		t.Errorf("inner UDP checksum = 0x%04x, independent computation = 0x%04x", binary.BigEndian.Uint16(frame[84:86]), want)
	}
}

// netIP16 returns the 16-byte form of an IPv6 address for test assertions.
func netIP16(t *testing.T, s string) []byte {
	t.Helper()
	ip := net.ParseIP(s)
	if ip == nil || ip.To4() != nil {
		t.Fatalf("%s is not a valid IPv6 address", s)
	}
	return ip.To16()
}

// TestPlanner_Validate verifies Validate() rejects contradictory specs
// (spec-driven failure paths): missing GRE config, an unsupported
// ProtocolType, ARP mode mixed with inner-IP fields, inner-IP mode mixed
// with an ARP config, invalid/incompatible inner IPs and protocols,
// negative Frames, and an unknown Direction.
func TestPlanner_Validate(t *testing.T) {
	valid := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1",
		GRE: &core.GREConfig{
			ProtocolType: core.EtherTypeIPv4,
			InnerSrcIP:   "192.168.1.1",
			InnerDstIP:   "192.168.1.2",
			InnerProto:   17,
		},
	}
	if err := NewPlanner().Validate(valid); err != nil {
		t.Fatalf("valid spec rejected: %v", err)
	}

	// Auto mode with defaulted inner IPs: empty InnerSrcIP over an IPv4
	// flow must resolve to IPv4 (not IPv6) and pass.
	autoValid := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1",
		GRE: &core.GREConfig{InnerProto: 17}, // ProtocolType 0, no inner IPs
	}
	if err := NewPlanner().Validate(autoValid); err != nil {
		t.Fatalf("auto-mode spec with defaulted inner IPs rejected: %v", err)
	}
	// And the IPv6 twin: an IPv6 flow with no inner IPs resolves to 0x86DD.
	autoValid6 := core.FlowSpec{
		SrcIP: "2001:db8::1", DstIP: "2001:db8::2",
		GRE: &core.GREConfig{InnerProto: 17},
	}
	if err := NewPlanner().Validate(autoValid6); err != nil {
		t.Fatalf("auto-mode IPv6 spec rejected: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*core.GREConfig, *core.FlowSpec)
	}{
		{
			name: "missing GRE config",
			mutate: func(g *core.GREConfig, s *core.FlowSpec) {
				s.GRE = nil
			},
		},
		{
			name: "unsupported protocol type",
			mutate: func(g *core.GREConfig, s *core.FlowSpec) {
				g.ProtocolType = 0x1234
			},
		},
		{
			name: "ARP protocol type with inner proto",
			mutate: func(g *core.GREConfig, s *core.FlowSpec) {
				g.ProtocolType = core.EtherTypeARP
				g.InnerProto = 17
			},
		},
		{
			name: "ARP protocol type with inner src ip",
			mutate: func(g *core.GREConfig, s *core.FlowSpec) {
				g.ProtocolType = core.EtherTypeARP
				g.InnerSrcIP = "192.168.1.1"
			},
		},
		{
			name: "ARP protocol type with inner dst ip",
			mutate: func(g *core.GREConfig, s *core.FlowSpec) {
				g.ProtocolType = core.EtherTypeARP
				g.InnerDstIP = "192.168.1.2"
			},
		},
		{
			name: "auto ARP with inner proto",
			mutate: func(g *core.GREConfig, s *core.FlowSpec) {
				g.ProtocolType = 0 // auto
				s.ARP = &core.ARPConfig{}
				g.InnerProto = 6
			},
		},
		{
			name: "inner IP mode with ARP config",
			mutate: func(g *core.GREConfig, s *core.FlowSpec) {
				g.ProtocolType = core.EtherTypeIPv4
				s.ARP = &core.ARPConfig{}
			},
		},
		{
			name: "invalid inner src ip",
			mutate: func(g *core.GREConfig, s *core.FlowSpec) {
				g.InnerSrcIP = "not-an-ip"
			},
		},
		{
			name: "ipv6 mode with ipv4 inner ip",
			mutate: func(g *core.GREConfig, s *core.FlowSpec) {
				g.ProtocolType = core.EtherTypeIPv6
				g.InnerSrcIP = "192.168.1.1"
				g.InnerDstIP = "2001:db8::2"
			},
		},
		{
			name: "ipv4 mode with ipv6 inner ip",
			mutate: func(g *core.GREConfig, s *core.FlowSpec) {
				g.ProtocolType = core.EtherTypeIPv4
				g.InnerSrcIP = "2001:db8::1"
				g.InnerDstIP = "192.168.1.2"
			},
		},
		{
			name: "auto mode with mismatched inner ip versions",
			mutate: func(g *core.GREConfig, s *core.FlowSpec) {
				g.ProtocolType = 0 // auto resolves from InnerSrcIP: IPv6
				g.InnerSrcIP = "2001:db8::1"
				g.InnerDstIP = "192.168.1.2"
			},
		},
		{
			name: "auto ipv6 mode with icmp inner proto",
			mutate: func(g *core.GREConfig, s *core.FlowSpec) {
				g.ProtocolType = 0 // auto resolves from InnerSrcIP: IPv6
				g.InnerSrcIP = "2001:db8::1"
				g.InnerDstIP = "2001:db8::2"
				g.InnerProto = 1 // ICMP is IPv4-only; IPv6 needs 58
			},
		},
		{
			name: "icmp inner proto in ipv6 mode",
			mutate: func(g *core.GREConfig, s *core.FlowSpec) {
				g.ProtocolType = core.EtherTypeIPv6
				g.InnerSrcIP = "2001:db8::1"
				g.InnerDstIP = "2001:db8::2"
				g.InnerProto = 1
			},
		},
		{
			name: "icmpv6 inner proto in ipv4 mode",
			mutate: func(g *core.GREConfig, s *core.FlowSpec) {
				g.ProtocolType = core.EtherTypeIPv4
				g.InnerSrcIP = "192.168.1.1"
				g.InnerDstIP = "192.168.1.2"
				g.InnerProto = 58
			},
		},
		{
			name: "unsupported inner proto",
			mutate: func(g *core.GREConfig, s *core.FlowSpec) {
				g.InnerProto = 99
			},
		},
		{
			name: "negative frames",
			mutate: func(g *core.GREConfig, s *core.FlowSpec) {
				g.Frames = -1
			},
		},
		{
			name: "unknown direction",
			mutate: func(g *core.GREConfig, s *core.FlowSpec) {
				g.Direction = "sideways"
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			spec := valid
			cfgCopy := *spec.GRE
			spec.GRE = &cfgCopy
			tc.mutate(spec.GRE, &spec)
			if err := NewPlanner().Validate(spec); err == nil {
				t.Errorf("Validate succeeded, want error for %s", tc.name)
			}
		})
	}
}

// TestPlanner_EndToEnd drives the full path MapToFlowSpec -> planner ->
// builder: the JSON-decoded "gre" strategy must reach the planner, and the
// built frame must carry a correct outer IP (total length covering GRE +
// inner, checksum valid), a correct GRE header (K bit, Key), and a correct
// inner IP (checksum valid).
func TestPlanner_EndToEnd(t *testing.T) {
	raw := map[string]interface{}{
		"src_ip": "10.0.0.1",
		"dst_ip": "20.0.0.1",
		"gre": map[string]interface{}{
			"inner_src_ip": "192.168.1.1",
			"inner_dst_ip": "192.168.1.2",
			"inner_proto":  float64(17),
			"key_present":  true,
			"key":          float64(42),
			"frames":       float64(1),
			"inner_payload": "dnspayload",
		},
	}
	spec := core.MapToFlowSpec(raw, "gre")
	if spec.GRE == nil {
		t.Fatal("MapToFlowSpec did not populate spec.GRE")
	}
	if spec.GRE.InnerSrcIP != "192.168.1.1" || spec.GRE.InnerDstIP != "192.168.1.2" {
		t.Errorf("inner IPs = %s/%s, want 192.168.1.1/192.168.1.2", spec.GRE.InnerSrcIP, spec.GRE.InnerDstIP)
	}
	if spec.GRE.InnerProto != 17 || !spec.GRE.KeyPresent || spec.GRE.Key != 42 {
		t.Errorf("GRE config = %+v, want InnerProto 17, KeyPresent, Key 42", spec.GRE)
	}
	if string(spec.GRE.InnerPayload) != "dnspayload" {
		t.Errorf("InnerPayload = %q, want dnspayload", spec.GRE.InnerPayload)
	}

	cfgs := planAll(t, spec)
	frames := buildAll(t, cfgs)
	frame := frames[0]

	// Inner packet: 20 IP + 8 UDP + 10 payload = 38 bytes; GRE = 8 bytes
	// (K bit); outer total = 20 + 8 + 38 = 66.
	innerLen := 20 + 8 + 10
	if total := binary.BigEndian.Uint16(frame[16:18]); int(total) != 20+8+innerLen {
		t.Errorf("outer total length = %d, want %d (GRE header + inner included)", total, 20+8+innerLen)
	}
	// Outer IP checksum: independent recomputation == wire.
	if got, want := binary.BigEndian.Uint16(frame[24:26]), ipv4HeaderChecksum(frame[14:34]); got != want {
		t.Errorf("outer IP checksum = 0x%04x, independent recomputation = 0x%04x", got, want)
	}
	// GRE: flags 0x2000 (K), proto 0x0800, Key 42.
	if !bytes.Equal(frame[34:42], []byte{0x20, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x2a}) {
		t.Errorf("GRE header = % x, want 20 00 08 00 00 00 00 2a at offset 34", frame[34:42])
	}
	// Inner IP: 192.168.1.1 -> 192.168.1.2, protocol 17, checksum valid.
	if !bytes.Equal(frame[54:62], []byte{0xc0, 0xa8, 0x01, 0x01, 0xc0, 0xa8, 0x01, 0x02}) {
		t.Errorf("inner IPs = % x, want 192.168.1.1 -> 192.168.1.2 at offset 54", frame[54:62])
	}
	if got, want := binary.BigEndian.Uint16(frame[52:54]), ipv4HeaderChecksum(frame[42:62]); got != want {
		t.Errorf("inner IP checksum = 0x%04x, independent recomputation = 0x%04x", got, want)
	}
	if !bytes.Equal(frame[70:], []byte("dnspayload")) {
		t.Errorf("inner payload = % x, want dnspayload at offset 70", frame[70:])
	}
}
