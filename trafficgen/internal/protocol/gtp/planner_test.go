package gtp

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

// wireOffsets for the built frame: Ethernet(14) + IPv4(20) + UDP(8), so the
// GTP message starts at 42; the GTP header's fields sit at:
//
//	[42] flags, [43] message type, [44:46] length, [46:50] TEID,
//	[50:54] optional block (iff E|S|PN), [54:] payload.
const (
	gtpOff = 42 // first octet of the GTP message inside the built frame
	// Ethernet header: 14; IPv4 header: 20 (proto byte at 14+9=23).
)

// TestPlanner_TPDU_Pcap1 reproduces 2.gtp_tunneling_udp.pcap frame 1:
// flags 0x32 (V=1, PT=1, S=1), message type 0xFF (T-PDU), Length 204, TEID
// 0x002dc715, Sequence 0x5ee5, N-PDU 0, Next-Ext-Type 0; the inner packet
// is an IPv4/UDP packet of total length 200. The Length field semantics are
// the spec rule (TS 29.281 §5.1): everything after the first 8 octets —
// 4 (optional block) + 200 (inner) = 204 — with the TEID excluded.
func TestPlanner_TPDU_Pcap1(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP:   "192.168.100.1",
		DstIP:   "192.168.100.5",
		SrcMAC:  "02:04:ee:f2:ac:1d",
		DstMAC:  "02:04:ee:f2:ac:24",
		SrcPort: 13370, // inner L4 ports (the outer 4-tuple mirrors them)
		DstPort: 13370,
		TTL:     128,
		GTP: &core.GTPConfig{
			TEID:            0x002dc715,
			SequencePresent: true,
			Sequence:        0x5ee5,
			InnerSrcIP:      "192.168.21.1",
			InnerDstIP:      "192.168.43.87",
			InnerProto:      17, // UDP
			InnerPayload:    bytes.Repeat([]byte{0x41}, 172), // inner total = 20+8+172 = 200
		},
	}
	cfgs := planAll(t, spec)
	if len(cfgs) != 1 {
		t.Fatalf("packets = %d, want 1", len(cfgs))
	}
	frame := buildAll(t, cfgs)[0]

	// GTP header (TS 29.281 §5.1).
	if frame[gtpOff] != 0x32 {
		t.Errorf("flags = 0x%02x, want 0x32 (V=1, PT=1, S=1)", frame[gtpOff])
	}
	if frame[gtpOff+1] != 0xFF {
		t.Errorf("message type = 0x%02x, want 0xFF (T-PDU)", frame[gtpOff+1])
	}
	if got := binary.BigEndian.Uint16(frame[gtpOff+2 : gtpOff+4]); got != 204 {
		t.Errorf("GTP length = %d, want 204 (4 optional + 200 inner, TEID excluded)", got)
	}
	if got := binary.BigEndian.Uint32(frame[gtpOff+4 : gtpOff+8]); got != 0x002dc715 {
		t.Errorf("TEID = 0x%08x, want 0x002dc715", got)
	}
	if got := binary.BigEndian.Uint16(frame[gtpOff+8 : gtpOff+10]); got != 0x5ee5 {
		t.Errorf("sequence = 0x%04x, want 0x5ee5", got)
	}
	if frame[gtpOff+10] != 0 || frame[gtpOff+11] != 0 {
		t.Errorf("N-PDU/Next-Ext-Type = %02x %02x, want 00 00", frame[gtpOff+10], frame[gtpOff+11])
	}

	// Inner IPv4 packet at [54:]: total length 200, proto 17, valid header
	// checksum.
	inner := frame[gtpOff+12:]
	if inner[0] != 0x45 {
		t.Errorf("inner version/IHL = 0x%02x, want 0x45", inner[0])
	}
	if got := binary.BigEndian.Uint16(inner[2:4]); got != 200 {
		t.Errorf("inner total length = %d, want 200", got)
	}
	if inner[9] != 17 {
		t.Errorf("inner protocol = %d, want 17 (UDP)", inner[9])
	}
	if got := ipv4HeaderChecksum(inner[:20]); got != binary.BigEndian.Uint16(inner[10:12]) {
		t.Errorf("inner IPv4 header checksum mismatch: stored %04x, computed %04x",
			binary.BigEndian.Uint16(inner[10:12]), got)
	}
	if !bytes.Equal(inner[12:16], net.ParseIP("192.168.21.1").To4()) ||
		!bytes.Equal(inner[16:20], net.ParseIP("192.168.43.87").To4()) {
		t.Errorf("inner IPs = %v -> %v, want 192.168.21.1 -> 192.168.43.87",
			inner[12:16], inner[16:20])
	}

	// Outer IPv4: protocol 17 (UDP), total length covering UDP + GTP.
	if frame[23] != 17 {
		t.Errorf("outer protocol = %d, want 17 (UDP)", frame[23])
	}
	if got := binary.BigEndian.Uint16(frame[16:18]); got != uint16(20+8+len(frame[gtpOff:])) {
		t.Errorf("outer IP total length = %d, want %d (20+8+%d)",
			got, 20+8+len(frame[gtpOff:]), len(frame[gtpOff:]))
	}
}

// TestPlanner_TPDU_Pcap2 reproduces 2-1_gtp.pcap frame 1: flags 0x30 (V=1,
// PT=1, no optional), message type 0xFF, TEID 0x0000000a, and an inner
// IPv4/TCP SYN with an MSS option (0x05b4, 24-byte TCP header). The source
// capture's Length field (54) is malformed — the actual inner packet is 44
// bytes — and is NOT reproduced: the planner computes the spec-correct
// Length = len(inner) = 44.
func TestPlanner_TPDU_Pcap2(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP:  "11.12.0.1",
		DstIP:  "21.12.0.1",
		SrcMAC: "02:1e:2f:a5:3c:27",
		DstMAC: "02:1e:2f:a5:3c:1e",
		TTL:    64,
		GTP: &core.GTPConfig{
			TEID:        0x0a,
			InnerSrcIP:  "192.168.52.45",
			InnerDstIP:  "116.211.162.248",
			InnerProto:  6, // TCP
			InnerTTL:    128,
			InnerIPID:   0x404d,
			InnerPayload: nil,
			TCPOptions: []core.TCPOption{
				{Kind: 2, Data: []byte{0x05, 0xb4}}, // MSS 1460
			},
		},
		TCP: &core.TCPConfig{
			Seq:        0x5e7d7671,
			Flags:      0x02, // SYN
			WindowSize: 0x8000,
		},
		SrcPort: 46900, // inner TCP ports
		DstPort: 80,
	}
	cfgs := planAll(t, spec)
	if len(cfgs) != 1 {
		t.Fatalf("packets = %d, want 1", len(cfgs))
	}
	frame := buildAll(t, cfgs)[0]

	if frame[gtpOff] != 0x30 {
		t.Errorf("flags = 0x%02x, want 0x30 (V=1, PT=1, no optional)", frame[gtpOff])
	}
	if got := binary.BigEndian.Uint16(frame[gtpOff+2 : gtpOff+4]); got != 44 {
		t.Errorf("GTP length = %d, want 44 (inner packet only; the source pcap's 54 is malformed)", got)
	}
	if got := binary.BigEndian.Uint32(frame[gtpOff+4 : gtpOff+8]); got != 0x0a {
		t.Errorf("TEID = 0x%08x, want 0x0a", got)
	}

	// Inner IPv4/TCP at [54:]: total length 44, proto 6, SYN, MSS option.
	inner := frame[gtpOff+8:]
	if got := binary.BigEndian.Uint16(inner[2:4]); got != 44 {
		t.Errorf("inner total length = %d, want 44", got)
	}
	if inner[9] != 6 {
		t.Errorf("inner protocol = %d, want 6 (TCP)", inner[9])
	}
	tcp := inner[20:]
	if tcp[13] != 0x02 {
		t.Errorf("inner TCP flags = 0x%02x, want 0x02 (SYN)", tcp[13])
	}
	if got := binary.BigEndian.Uint32(tcp[4:8]); got != 0x5e7d7671 {
		t.Errorf("inner TCP seq = 0x%08x, want 0x5e7d7671", got)
	}
	// TCP data offset must be 6 (24-byte header: 20 + 4 MSS).
	if tcp[12]>>4 != 6 {
		t.Errorf("inner TCP data offset = %d, want 6 (MSS option present)", tcp[12]>>4)
	}
	if !bytes.Equal(tcp[20:24], []byte{0x02, 0x04, 0x05, 0xb4}) {
		t.Errorf("inner TCP options = % x, want 02 04 05 b4 (MSS 1460)", tcp[20:24])
	}
}

// TestPlanner_TPDU_NoOptionalFlags verifies the message with no E/S/PN
// flags has no optional block: the payload starts right after the 8-octet
// mandatory header, and Length = len(payload) only.
func TestPlanner_TPDU_NoOptionalFlags(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP:  "10.0.0.1",
		DstIP:  "20.0.0.1",
		SrcMAC: "02:00:00:00:00:01",
		DstMAC: "02:00:00:00:00:02",
		GTP: &core.GTPConfig{
			TEID:        0x1234,
			InnerSrcIP:  "192.168.1.1",
			InnerDstIP:  "192.168.1.2",
			InnerProto:  17,
			InnerPayload: []byte("hi"),
		},
	}
	frame := buildAll(t, planAll(t, spec))[0]
	if frame[gtpOff] != 0x30 { // V=1 (0x20) + PT=1 (0x10), no optional
		t.Errorf("flags = 0x%02x, want 0x30", frame[gtpOff])
	}
	// Inner IPv4(20) + UDP(8) + 2 = 30.
	if got := binary.BigEndian.Uint16(frame[gtpOff+2 : gtpOff+4]); got != 30 {
		t.Errorf("GTP length = %d, want 30 (no optional block)", got)
	}
	// Payload begins at octet 8 of the message: inner IP version byte.
	if frame[gtpOff+8] != 0x45 {
		t.Errorf("first payload byte = 0x%02x, want 0x45 (inner IPv4 header)", frame[gtpOff+8])
	}
}

// TestPlanner_SequenceIncrementPerFrame verifies the data plane increments
// the Sequence Number per frame (TS 29.281 §5.1 S flag) and gives each
// frame a distinct inner IPID, while the TEID stays constant (the tunnel
// identifier).
func TestPlanner_SequenceIncrementPerFrame(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP:  "10.0.0.1",
		DstIP:  "20.0.0.1",
		SrcMAC: "02:00:00:00:00:01",
		DstMAC: "02:00:00:00:00:02",
		GTP: &core.GTPConfig{
			TEID:            0x11111111,
			SequencePresent: true,
			Sequence:        100,
			Frames:          3,
			InnerSrcIP:      "192.168.1.1",
			InnerDstIP:      "192.168.1.2",
			InnerProto:      17,
		},
	}
	frames := buildAll(t, planAll(t, spec))
	if len(frames) != 3 {
		t.Fatalf("packets = %d, want 3", len(frames))
	}
	for i, frame := range frames {
		if got := binary.BigEndian.Uint16(frame[gtpOff+8 : gtpOff+10]); got != 100+uint16(i) {
			t.Errorf("frame %d sequence = %d, want %d", i, got, 100+i)
		}
		if got := binary.BigEndian.Uint32(frame[gtpOff+4 : gtpOff+8]); got != 0x11111111 {
			t.Errorf("frame %d TEID = 0x%08x, want constant 0x11111111", i, got)
		}
		// Inner IPID at inner[4:6] increments 0, 1, 2.
		inner := frame[gtpOff+12:]
		if got := binary.BigEndian.Uint16(inner[4:6]); got != uint16(i) {
			t.Errorf("frame %d inner IPID = %d, want %d", i, got, i)
		}
	}
}

// TestPlanner_InnerIPv6 verifies an IPv6 inner packet: 40-byte header, no
// checksum, and a NON-ZERO inner UDP checksum (RFC 6936 §2 forbids the zero
// checksum over IPv6).
func TestPlanner_InnerIPv6(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP:  "10.0.0.1",
		DstIP:  "20.0.0.1",
		SrcMAC: "02:00:00:00:00:01",
		DstMAC: "02:00:00:00:00:02",
		GTP: &core.GTPConfig{
			TEID:        0xaa,
			InnerSrcIP:  "2001:db8::1",
			InnerDstIP:  "2001:db8::2",
			InnerProto:  17, // UDP
			InnerPayload: []byte("v6"),
		},
	}
	frame := buildAll(t, planAll(t, spec))[0]
	inner := frame[gtpOff+8:]
	if inner[0] != 0x60 {
		t.Errorf("inner version = 0x%02x, want 0x60 (IPv6)", inner[0])
	}
	if inner[6] != 17 {
		t.Errorf("inner next header = %d, want 17 (UDP)", inner[6])
	}
	if got := binary.BigEndian.Uint16(inner[40+6 : 40+8]); got == 0 {
		t.Errorf("inner UDP checksum = 0, want non-zero (RFC 6936: IPv6 UDP must not have a zero checksum)")
	}
}

// TestPlanner_DirectionDown verifies "down" swaps the outer MACs/IPs/ports
// and the inner addresses, so the peer's side of the tunnel is emitted.
func TestPlanner_DirectionDown(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP:   "10.0.0.1",
		DstIP:   "20.0.0.1",
		SrcMAC:  "02:00:00:00:00:01",
		DstMAC:  "02:00:00:00:00:02",
		SrcPort: 2000,
		DstPort: 2152,
		GTP: &core.GTPConfig{
			TEID:        0x1,
			Direction:   "down",
			InnerSrcIP:  "192.168.1.1",
			InnerDstIP:  "192.168.1.2",
			InnerProto:  17,
			InnerPayload: []byte("x"),
		},
	}
	cfg := planAll(t, spec)[0]
	if cfg.Direction != "down" {
		t.Errorf("Direction = %q, want down", cfg.Direction)
	}
	if cfg.L3.SrcIP != "20.0.0.1" || cfg.L3.DstIP != "10.0.0.1" {
		t.Errorf("outer IPs = %s -> %s, want 20.0.0.1 -> 10.0.0.1", cfg.L3.SrcIP, cfg.L3.DstIP)
	}
	if cfg.L4.SrcPort != 2152 || cfg.L4.DstPort != 2000 {
		t.Errorf("outer ports = %d -> %d, want 2152 -> 2000", cfg.L4.SrcPort, cfg.L4.DstPort)
	}
	frame := buildAll(t, []core.PacketConfig{cfg})[0]
	inner := frame[gtpOff+8:]
	if !bytes.Equal(inner[12:16], net.ParseIP("192.168.1.2").To4()) ||
		!bytes.Equal(inner[16:20], net.ParseIP("192.168.1.1").To4()) {
		t.Errorf("inner IPs = %v -> %v, want swapped 192.168.1.2 -> 192.168.1.1",
			inner[12:16], inner[16:20])
	}
}

// TestPlanner_Defaults verifies the empty-config defaults: one T-PDU frame,
// GTP-U ports 2152/2152, inner proto UDP (17), TTL 64.
func TestPlanner_Defaults(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP:  "10.0.0.1",
		DstIP:  "20.0.0.1",
		SrcMAC: "02:00:00:00:00:01",
		DstMAC: "02:00:00:00:00:02",
		GTP:    &core.GTPConfig{TEID: 0x7},
	}
	cfg := planAll(t, spec)[0]
	if cfg.L4.SrcPort != 2152 || cfg.L4.DstPort != 2152 {
		t.Errorf("ports = %d -> %d, want GTP-U default 2152 -> 2152", cfg.L4.SrcPort, cfg.L4.DstPort)
	}
	frame := buildAll(t, []core.PacketConfig{cfg})[0]
	if frame[gtpOff+1] != 0xFF {
		t.Errorf("message type = 0x%02x, want 0xFF (T-PDU default)", frame[gtpOff+1])
	}
	inner := frame[gtpOff+8:]
	if inner[9] != 17 {
		t.Errorf("inner protocol = %d, want 17 (UDP default)", inner[9])
	}
	if inner[8] != 64 {
		t.Errorf("inner TTL = %d, want 64 default", inner[8])
	}
}

// TestPlanner_InnerTCPViaSpecTCP verifies inner_proto 0 resolves to TCP
// when spec.TCP is set (matching the gre/mpls auto rule), honoring the TCP
// config (Seq/Flags/WindowSize).
func TestPlanner_InnerTCPViaSpecTCP(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP:  "10.0.0.1",
		DstIP:  "20.0.0.1",
		SrcMAC: "02:00:00:00:00:01",
		DstMAC: "02:00:00:00:00:02",
		GTP: &core.GTPConfig{
			TEID:        0x5,
			InnerSrcIP:  "192.168.9.9",
			InnerDstIP:  "192.168.9.10",
			InnerPayload: []byte("data"),
		},
		TCP: &core.TCPConfig{
			Seq:    0xabcdef01,
			Flags:  0x18, // PSH|ACK
			WindowSize: 4096,
		},
	}
	frame := buildAll(t, planAll(t, spec))[0]
	inner := frame[gtpOff+8:]
	if inner[9] != 6 {
		t.Errorf("inner protocol = %d, want 6 (TCP auto via spec.TCP)", inner[9])
	}
	tcp := inner[20:]
	if got := binary.BigEndian.Uint32(tcp[4:8]); got != 0xabcdef01 {
		t.Errorf("inner TCP seq = 0x%08x, want 0xabcdef01", got)
	}
	if tcp[13] != 0x18 {
		t.Errorf("inner TCP flags = 0x%02x, want 0x18", tcp[13])
	}
	if got := binary.BigEndian.Uint16(tcp[14:16]); got != 4096 {
		t.Errorf("inner TCP window = %d, want 4096", got)
	}
}

// TestPlanner_GTPCDialog_Echo verifies the GTP-C signaling plane: an Echo
// Request (type 1, Recovery IE type 14) from the client and the Echo
// Response (type 2) from the peer, on the GTP-C default port 2123. The
// response's direction "down" swaps the outer addresses/ports, and its
// TEIDOverride (0x1234) replaces the config TEID. The S flag is set so the
// optional block carries each step's explicit Sequence.
func TestPlanner_GTPCDialog_Echo(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP:   "10.0.0.1",
		DstIP:   "20.0.0.1",
		SrcMAC:  "02:00:00:00:00:01",
		DstMAC:  "02:00:00:00:00:02",
		SrcPort: 49152,
		DstPort: 0, // GTP-C default 2123
		GTP: &core.GTPConfig{
			Mode:            "c",
			TEID:            0, // Echo messages carry TEID 0 (pre-assignment)
			SequencePresent: true,
			Sequence:        10,
			Scenarios: []core.GTPStep{
				{MessageType: 0x01, Sequence: 10, Direction: "up", IEs: []core.GTPIE{{Type: 0x0E, Value: []byte{0x80}}}}, // Echo Request, Recovery
				{MessageType: 0x02, Sequence: 11, Direction: "down", TEIDOverride: uint32Ptr(0x1234), IEs: []core.GTPIE{{Type: 0x0E, Value: []byte{0x40}}}}, // Echo Response
			},
		},
	}
	cfgs := planAll(t, spec)
	if len(cfgs) != 2 {
		t.Fatalf("packets = %d, want 2 (echo request + response)", len(cfgs))
	}
	frames := buildAll(t, cfgs)

	// Request: client side, port 49152 -> 2123.
	if cfgs[0].L4.SrcPort != 49152 || cfgs[0].L4.DstPort != 2123 {
		t.Errorf("request ports = %d -> %d, want 49152 -> 2123 (GTP-C)", cfgs[0].L4.SrcPort, cfgs[0].L4.DstPort)
	}
	req := frames[0][gtpOff:]
	if req[0] != 0x32 { // V=1 (0x20) + PT=1 (0x10) + S=1 (0x02)
		t.Errorf("request flags = 0x%02x, want 0x32 (V=1, PT=1, S=1)", req[0])
	}
	if req[1] != 0x01 {
		t.Errorf("request message type = 0x%02x, want 0x01 (Echo Request)", req[1])
	}
	if got := binary.BigEndian.Uint32(req[4:8]); got != 0 {
		t.Errorf("request TEID = 0x%08x, want 0 (echo)", got)
	}
	// Length = 4 optional + 2 IE bytes (TV format: type 14 + 1 value octet).
	if got := binary.BigEndian.Uint16(req[2:4]); got != 6 {
		t.Errorf("request length = %d, want 6 (4 optional + 2 Recovery IE)", got)
	}
	if got := binary.BigEndian.Uint16(req[8:10]); got != 10 {
		t.Errorf("request sequence = %d, want 10", got)
	}
	// IEs at [54:] — slice by the declared length so Ethernet padding
	// (the frame is 56 bytes < the 60-byte minimum) is excluded:
	// 0e 80 (Recovery IE, type 14, TV format, value 0x80).
	reqLen := int(binary.BigEndian.Uint16(req[2:4]))
	ies := frames[0][gtpOff+12 : gtpOff+12+reqLen-4]
	if !bytes.Equal(ies, []byte{0x0e, 0x80}) {
		t.Errorf("request IEs = % x, want 0e 80 (Recovery 0x80)", ies)
	}

	// Response: peer side (direction down), ports swapped, TEID override.
	if cfgs[1].L4.SrcPort != 2123 || cfgs[1].L4.DstPort != 49152 {
		t.Errorf("response ports = %d -> %d, want 2123 -> 49152", cfgs[1].L4.SrcPort, cfgs[1].L4.DstPort)
	}
	if cfgs[1].L3.SrcIP != "20.0.0.1" || cfgs[1].L3.DstIP != "10.0.0.1" {
		t.Errorf("response outer IPs = %s -> %s, want 20.0.0.1 -> 10.0.0.1", cfgs[1].L3.SrcIP, cfgs[1].L3.DstIP)
	}
	resp := frames[1][gtpOff:]
	if resp[1] != 0x02 {
		t.Errorf("response message type = 0x%02x, want 0x02 (Echo Response)", resp[1])
	}
	if got := binary.BigEndian.Uint32(resp[4:8]); got != 0x1234 {
		t.Errorf("response TEID = 0x%08x, want 0x1234 (override)", got)
	}
	if got := binary.BigEndian.Uint16(resp[8:10]); got != 11 {
		t.Errorf("response sequence = %d, want 11", got)
	}
}

// TestPlanner_GTPC_CreatePDPContext verifies a multi-IE GTP-C scenario: a
// Create PDP Context Request (type 16) carrying an APN IE, a GSN Address IE
// and a TEID-U IE. TV IEs (Type < 0x80, fixed length, e.g. TEID Data I) are
// serialized as Type+Value; TLV IEs (Type >= 0x80, variable length, e.g. APN
// and GSN Address) as Type+2-octet big-endian Length+Value (TS 29.060 §7.7.0).
func TestPlanner_GTPC_CreatePDPContext(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP:  "10.0.0.1",
		DstIP:  "20.0.0.1",
		SrcMAC: "02:00:00:00:00:01",
		DstMAC: "02:00:00:00:00:02",
		GTP: &core.GTPConfig{
			Mode: "c",
			TEID: 0xdeadbeef,
			Scenarios: []core.GTPStep{
				{
					MessageType: 0x10, // Create PDP Context Request
					IEs: []core.GTPIE{
						{Type: 0x83, Value: []byte("internet")},          // Access Point Name (TLV)
						{Type: 0x85, Value: []byte{10, 1, 1, 1}},        // GSN Address (TLV)
						{Type: 0x10, Value: []byte{0x00, 0x11, 0x22, 0x33}}, // TEID Data I (TV)
					},
				},
			},
		},
	}
	frame := buildAll(t, planAll(t, spec))[0]
	msg := frame[gtpOff:]
	if msg[1] != 0x10 {
		t.Errorf("message type = 0x%02x, want 0x10 (Create PDP Context Request)", msg[1])
	}
	if got := binary.BigEndian.Uint32(msg[4:8]); got != 0xdeadbeef {
		t.Errorf("TEID = 0x%08x, want 0xdeadbeef", got)
	}
	want := []byte{
		0x83, 0x00, 0x08, 'i', 'n', 't', 'e', 'r', 'n', 'e', 't',
		0x85, 0x00, 0x04, 10, 1, 1, 1,
		0x10, 0x00, 0x11, 0x22, 0x33,
	}
	ies := frame[gtpOff+8:]
	if !bytes.Equal(ies, want) {
		t.Errorf("IEs = % x, want % x", ies, want)
	}
	// No optional flags: length = len(IEs).
	if got := binary.BigEndian.Uint16(msg[2:4]); got != uint16(len(want)) {
		t.Errorf("length = %d, want %d (no optional block)", got, len(want))
	}
}

// TestPlanner_ExtensionHeader verifies the E flag: flags bit, the 4-octet
// optional block's Next-Ext-Type, and the extension header itself
// (Next-Ext-Type 0x00 + Length in 4-octet units including the Length octet,
// content padded to a 4-octet multiple — TS 29.281 §5.2.1).
func TestPlanner_ExtensionHeader(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP:  "10.0.0.1",
		DstIP:  "20.0.0.1",
		SrcMAC: "02:00:00:00:00:01",
		DstMAC: "02:00:00:00:00:02",
		GTP: &core.GTPConfig{
			TEID:             0x99,
			ExtensionPresent: true,
			ExtensionType:    0x40, // PDU Session Container (5G, TS 38.413 style)
			ExtensionData:    []byte{0xaa, 0xbb}, // 2 bytes -> padded block = 4 octets, Len = 1
			InnerSrcIP:       "192.168.1.1",
			InnerDstIP:       "192.168.1.2",
			InnerProto:       17,
			InnerPayload:     []byte("z"),
		},
	}
	frame := buildAll(t, planAll(t, spec))[0]
	msg := frame[gtpOff:]
	// flags: V=1 (0x20) + PT=1 (0x10) + E=1 (0x04) = 0x34.
	if msg[0] != 0x34 {
		t.Errorf("flags = 0x%02x, want 0x34 (V=1, PT=1, E=1)", msg[0])
	}
	// Optional block: seq 0, npdu 0, next-ext-type 0x40.
	if msg[8] != 0 || msg[9] != 0 || msg[10] != 0 || msg[11] != 0x40 {
		t.Errorf("optional block = % x, want 00 00 00 40", msg[8:12])
	}
	// Extension header at [12:]: Next-Ext-Type 0x00, Length 1 (4-octet
	// units incl. the Length octet), content aa bb + 1 pad byte.
	ext := msg[12:]
	if ext[0] != 0x00 || ext[1] != 0x01 {
		t.Errorf("extension header = % x, want 00 01 ... (next-ext 0x00, len 1)", ext[:2])
	}
	if !bytes.Equal(ext[2:5], []byte{0xaa, 0xbb, 0x00}) {
		t.Errorf("extension content = % x, want aa bb 00 (padded to 4 octets)", ext[2:5])
	}
	// Length = 4 optional + 5 extension (Next-Ext-Type + Len + 2 content
	// + 1 pad) + inner (20+8+1=29) = 38.
	if got := binary.BigEndian.Uint16(msg[2:4]); got != 38 {
		t.Errorf("length = %d, want 38 (4 optional + 5 extension + 29 inner)", got)
	}
}

// TestPlanner_NPDUPresent verifies the PN flag carries the N-PDU Number in
// the optional block.
func TestPlanner_NPDUPresent(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP:  "10.0.0.1",
		DstIP:  "20.0.0.1",
		SrcMAC: "02:00:00:00:00:01",
		DstMAC: "02:00:00:00:00:02",
		GTP: &core.GTPConfig{
			TEID:        0x4,
			NPDUPresent: true,
			NPDUValue:   0x77,
			InnerProto:  17,
			InnerPayload: []byte("p"),
		},
	}
	frame := buildAll(t, planAll(t, spec))[0]
	msg := frame[gtpOff:]
	// flags: V=1 (0x20) + PT=1 (0x10) + PN=1 (0x01) = 0x31.
	if msg[0] != 0x31 {
		t.Errorf("flags = 0x%02x, want 0x31 (V=1, PT=1, PN=1)", msg[0])
	}
	if msg[10] != 0x77 {
		t.Errorf("N-PDU = 0x%02x, want 0x77", msg[10])
	}
}

// TestPlanner_CtxCancel verifies Plan stops emitting once the context is
// cancelled (the select on ctx.Done in the emit path).
func TestPlanner_CtxCancel(t *testing.T) {
	p := NewPlanner()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	spec := core.FlowSpec{
		SrcIP:  "10.0.0.1",
		DstIP:  "20.0.0.1",
		SrcMAC: "02:00:00:00:00:01",
		DstMAC: "02:00:00:00:00:02",
		GTP: &core.GTPConfig{
			TEID:    0x1,
			Frames:  1000,
			InnerProto: 17,
			InnerPayload: []byte("x"),
		},
	}
	ch, err := p.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	n := 0
	for cfg := range ch {
		n++
		if n == 3 {
			cancel()
		}
		if cfg.FlowID == "" {
			t.Fatalf("packet %d: empty FlowID", n)
		}
	}
	if n == 1000 {
		t.Errorf("planner emitted all %d frames despite cancellation", n)
	}
	if n < 3 {
		t.Errorf("planner emitted %d frames, want at least 3 before cancellation", n)
	}
}

// TestValidate_GTPConfigRequired verifies Validate rejects a flow without
// the GTP config.
func TestValidate_GTPConfigRequired(t *testing.T) {
	if err := NewPlanner().Validate(core.FlowSpec{}); err == nil {
		t.Fatalf("Validate(nil GTP) = nil, want error")
	}
}

// TestValidate_Rejects verifies the failure paths enumerated in Validate
// (spec-driven from the GTPConfig field list): invalid version/mode/PT,
// unparseable or version-mismatched inner IPs, invalid inner protocol,
// oversized extension data, negative frames, invalid direction, and the
// scenario rules (required message type, valid direction, IE value cap).
func TestValidate_Rejects(t *testing.T) {
	base := core.FlowSpec{
		SrcIP:  "10.0.0.1",
		DstIP:  "20.0.0.1",
		SrcMAC: "02:00:00:00:00:01",
		DstMAC: "02:00:00:00:00:02",
		GTP: &core.GTPConfig{
			TEID:        0x1,
			InnerSrcIP:  "192.168.1.1",
			InnerDstIP:  "192.168.1.2",
			InnerProto:  17,
			InnerPayload: []byte("x"),
		},
	}
	cases := []struct {
		name string
		mut  func(*core.GTPConfig)
		want string // substring of the error message
	}{
		{"version GTPv2", func(c *core.GTPConfig) { c.Version = 2 }, "not supported"},
		{"mode invalid", func(c *core.GTPConfig) { c.Mode = "x" }, "Mode"},
		{"PT invalid", func(c *core.GTPConfig) { c.PT = 2 }, "PT"},
		{"inner src IP invalid", func(c *core.GTPConfig) { c.InnerSrcIP = "nope" }, "not a valid IP"},
		{"inner dst IP invalid", func(c *core.GTPConfig) { c.InnerDstIP = "nope" }, "not a valid IP"},
		{"inner proto invalid", func(c *core.GTPConfig) { c.InnerProto = 99 }, "not in supported list"},
		{"ICMP over IPv6 inner", func(c *core.GTPConfig) {
			c.InnerProto = 1
			c.InnerSrcIP = "2001:db8::1"
			c.InnerDstIP = "2001:db8::2"
		}, "use 58"},
		{"ICMPv6 over IPv4 inner", func(c *core.GTPConfig) { c.InnerProto = 58 }, "use 1"},
		{"extension data oversized", func(c *core.GTPConfig) {
			c.ExtensionPresent = true
			c.ExtensionData = make([]byte, 1019)
		}, "exceeds"},
		{"frames negative", func(c *core.GTPConfig) { c.Frames = -1 }, "Frames"},
		{"direction invalid", func(c *core.GTPConfig) { c.Direction = "sideways" }, "Direction"},
		{"scenario message type zero", func(c *core.GTPConfig) {
			c.Scenarios = []core.GTPStep{{MessageType: 0}}
		}, "message_type is required"},
		{"scenario direction invalid", func(c *core.GTPConfig) {
			c.Scenarios = []core.GTPStep{{MessageType: 0x01, Direction: "x"}}
		}, "Direction"},
		{"scenario TLV IE value oversized", func(c *core.GTPConfig) {
			c.Scenarios = []core.GTPStep{{
				MessageType: 0x01,
				IEs:         []core.GTPIE{{Type: 0x83, Value: make([]byte, 65536)}},
			}}
		}, "65535-byte maximum"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec := base
			cfg := *base.GTP
			spec.GTP = &cfg
			tc.mut(spec.GTP)
			err := NewPlanner().Validate(spec)
			if err == nil {
				t.Fatalf("Validate = nil, want error containing %q", tc.want)
			}
			if !bytes.Contains([]byte(err.Error()), []byte(tc.want)) {
				t.Errorf("Validate error = %q, want it to contain %q", err, tc.want)
			}
		})
	}
}

// TestValidate_Accepts verifies the valid edge values pass Validate:
// version 0 (auto), mode u/c, PT 0/1, ICMP over IPv4 inner, ICMPv6 over
// IPv6 inner, and a well-formed scenario dialog.
func TestValidate_Accepts(t *testing.T) {
	good := []core.FlowSpec{
		{ // minimal: every field at its zero/default value
			SrcIP: "10.0.0.1", DstIP: "20.0.0.1",
			GTP: &core.GTPConfig{TEID: 1},
		},
		{ // control plane + dialog with overrides
			SrcIP: "10.0.0.1", DstIP: "20.0.0.1",
			GTP: &core.GTPConfig{
				Mode: "c", Version: 0, PT: 0,
				Scenarios: []core.GTPStep{
					{MessageType: 0x01, TEIDOverride: uint32Ptr(0), Sequence: 1, Direction: "up"},
					{MessageType: 0x02, TEIDOverride: uint32Ptr(0x9), Direction: "down"},
				},
			},
		},
		{ // ICMP inner over IPv4
			SrcIP: "10.0.0.1", DstIP: "20.0.0.1",
			GTP: &core.GTPConfig{
				TEID: 1, InnerSrcIP: "192.168.1.1", InnerDstIP: "192.168.1.2", InnerProto: 1,
			},
		},
		{ // ICMPv6 inner over IPv6
			SrcIP: "10.0.0.1", DstIP: "20.0.0.1",
			GTP: &core.GTPConfig{
				TEID: 1, InnerSrcIP: "2001:db8::1", InnerDstIP: "2001:db8::2", InnerProto: 58,
			},
		},
	}
	for i, spec := range good {
		if err := NewPlanner().Validate(spec); err != nil {
			t.Errorf("case %d: Validate = %v, want nil", i, err)
		}
	}
}

// TestEndToEnd_OuterUDP verifies the full plan+build path: the outer
// packet is IPv4/UDP with a valid computed UDP checksum and the correct IP
// total length, and the EtherType selects the outer IP version.
func TestEndToEnd_OuterUDP(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP:  "10.0.0.1",
		DstIP:  "20.0.0.1",
		SrcMAC: "02:00:00:00:00:01",
		DstMAC: "02:00:00:00:00:02",
		GTP: &core.GTPConfig{
			TEID:        0x2,
			InnerProto:  17,
			InnerPayload: []byte("payload"),
		},
	}
	frame := buildAll(t, planAll(t, spec))[0]
	if got := binary.BigEndian.Uint16(frame[12:14]); got != 0x0800 {
		t.Errorf("EtherType = 0x%04x, want 0x0800 (outer IPv4)", got)
	}
	// UDP header at [34:42]: length = 8 + GTP message, checksum non-zero
	// (the builder computes it over the pseudo-header).
	if got := binary.BigEndian.Uint16(frame[38:40]); got != uint16(8+len(frame[gtpOff:])) {
		t.Errorf("UDP length = %d, want %d (8 + %d GTP message)", got, 8+len(frame[gtpOff:]), len(frame[gtpOff:]))
	}
	if got := binary.BigEndian.Uint16(frame[40:42]); got == 0 {
		t.Errorf("outer UDP checksum = 0, want computed non-zero")
	}
}

// uint32Ptr returns a pointer to v (for TEIDOverride).
func uint32Ptr(v uint32) *uint32 { return &v }
