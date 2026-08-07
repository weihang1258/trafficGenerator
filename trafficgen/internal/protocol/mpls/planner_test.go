package mpls

import (
	"bytes"
	"context"
	"encoding/binary"
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

// TestPlanner_DefaultDataPlane verifies the default MPLS data plane
// (RFC 3032 §3.1/§3.10): a single-label stack (label 16, TC 6, S auto-
// corrected to 1, TTL 255), the forced unicast EtherType 0x8847, an inner
// IPv4/UDP packet from the flow's addresses and ports, and the default
// Frames 0 = 1 frame.
func TestPlanner_DefaultDataPlane(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1",
		SrcPort: 1234, DstPort: 5678,
		SrcMAC: "aa:bb:cc:00:01:02", DstMAC: "aa:bb:cc:00:03:04",
		Payload: []byte("mpls-data"),
		MPLS: &core.MPLSConfig{
			Labels: []core.MPLSLabel{
				{Label: 16, TC: 6, TTL: 255}, // S unset -> auto-corrected at the bottom
			},
		},
	}
	cfgs := planAll(t, spec)
	if len(cfgs) != 1 {
		t.Fatalf("emitted %d configs, want 1 (Frames 0 = 1)", len(cfgs))
	}
	cfg := cfgs[0]
	if cfg.Direction != "up" {
		t.Errorf("Direction = %q, want up (default)", cfg.Direction)
	}
	if cfg.L2.MPLS == nil || len(cfg.L2.MPLS.Labels) != 1 {
		t.Fatalf("L2.MPLS = %+v, want 1 label", cfg.L2.MPLS)
	}
	// Planner resolves the TTL default; the builder auto-corrects S.
	if cfg.L2.MPLS.Labels[0].TTL != 255 {
		t.Errorf("label TTL = %d, want 255", cfg.L2.MPLS.Labels[0].TTL)
	}
	if cfg.L3.Protocol != 17 {
		t.Errorf("inner protocol = %d, want 17 (UDP default)", cfg.L3.Protocol)
	}
	if cfg.L4.Protocol != "udp" || cfg.L4.SrcPort != 1234 || cfg.L4.DstPort != 5678 {
		t.Errorf("L4 = %+v, want udp 1234->5678", cfg.L4)
	}

	frames := buildAll(t, cfgs)
	frame := frames[0]
	if got := binary.BigEndian.Uint16(frame[12:14]); got != core.EtherTypeMPLSUnicast {
		t.Errorf("EtherType = 0x%04x, want 0x8847", got)
	}
	if got := binary.BigEndian.Uint32(frame[14:18]); got != (uint32(16)<<12)|(6<<9)|(1<<8)|255 {
		t.Errorf("label entry = 0x%08x, want 0x%08x", got, (uint32(16)<<12)|(6<<9)|(1<<8)|255)
	}
	// Inner IPv4 at offset 18: 10.0.0.1 -> 20.0.0.1, UDP, valid checksum.
	if frame[18] != 0x45 {
		t.Errorf("inner L3 byte = 0x%02x, want 0x45", frame[18])
	}
	if !bytes.Equal(frame[30:34], []byte{10, 0, 0, 1}) || !bytes.Equal(frame[34:38], []byte{20, 0, 0, 1}) {
		t.Errorf("inner IPs = % x -> % x, want 10.0.0.1 -> 20.0.0.1", frame[30:34], frame[34:38])
	}
	if got, want := binary.BigEndian.Uint16(frame[28:30]), ipv4HeaderChecksum(frame[18:38]); got != want {
		t.Errorf("inner IP checksum = 0x%04x, independent recomputation = 0x%04x", got, want)
	}
	// Payload at 14 eth + 4 label + 20 IP + 8 UDP = 46; the frame is
	// padded to MinEthernetFrame, so assert the natural-length slice.
	if !bytes.Equal(frame[46:55], []byte("mpls-data")) {
		t.Errorf("payload = %q, want mpls-data", frame[46:55])
	}
}

// TestPlanner_InnerTCP verifies the TCP inner path: spec.TCP selects
// InnerProto 6 and its Seq/Ack/Flags/WindowSize reach the inner TCP header
// (RFC 3032 §3.12: MPLS labels a packet in place — the inner L4 config is
// the flow's own).
func TestPlanner_InnerTCP(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1",
		SrcPort: 40000, DstPort: 80,
		TCP: &core.TCPConfig{Seq: 0x11223344, Ack: 0x55667788, Flags: 0x02, WindowSize: 8192},
		MPLS: &core.MPLSConfig{
			Labels: []core.MPLSLabel{{Label: 100}},
		},
	}
	cfgs := planAll(t, spec)
	if len(cfgs) != 1 {
		t.Fatalf("emitted %d configs, want 1", len(cfgs))
	}
	cfg := cfgs[0]
	if cfg.L3.Protocol != 6 {
		t.Errorf("inner protocol = %d, want 6 (TCP via spec.TCP)", cfg.L3.Protocol)
	}
	if cfg.L4.Seq != 0x11223344 || cfg.L4.Ack != 0x55667788 || cfg.L4.Flags != 0x02 || cfg.L4.WindowSize != 8192 {
		t.Errorf("L4 = %+v, want seq 0x11223344 ack 0x55667788 flags 0x02 window 8192", cfg.L4)
	}

	frame := buildAll(t, cfgs)[0]
	tcp := frame[38:58] // 14 eth + 4 label + 20 IP
	if got := binary.BigEndian.Uint32(tcp[4:8]); got != 0x11223344 {
		t.Errorf("TCP seq = 0x%08x, want 0x11223344", got)
	}
	if tcp[13] != 0x02 {
		t.Errorf("TCP flags = 0x%02x, want 0x02 (SYN)", tcp[13])
	}
}

// TestPlanner_MultiLayerStack verifies a 2-label stack end-to-end: the
// planner carries both entries (top first), the builder writes S=0 on the
// top and S=1 on the bottom (RFC 3032 §2.1), and the frame matches the
// structure of pcap 7、mpls_http.pcap frame 1's outer layer.
func TestPlanner_MultiLayerStack(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "172.16.0.179", DstIP: "209.123.109.175",
		SrcPort: 1929, DstPort: 80,
		SrcMAC: "00:22:56:cd:ce:92", DstMAC: "00:22:56:cc:2c:ec",
		MPLS: &core.MPLSConfig{
			Labels: []core.MPLSLabel{
				{Label: 586, TTL: 255},  // top: S auto-corrected to 0
				{Label: 2859, TTL: 255}, // bottom: S auto-corrected to 1
			},
		},
	}
	cfgs := planAll(t, spec)
	if len(cfgs) != 1 {
		t.Fatalf("emitted %d configs, want 1", len(cfgs))
	}
	if len(cfgs[0].L2.MPLS.Labels) != 2 {
		t.Fatalf("label stack = %d entries, want 2", len(cfgs[0].L2.MPLS.Labels))
	}

	frame := buildAll(t, cfgs)[0]
	if got := binary.BigEndian.Uint16(frame[12:14]); got != 0x8847 {
		t.Errorf("EtherType = 0x%04x, want 0x8847", got)
	}
	// Top entry: label 586, S=0, TTL 255; bottom: label 2859, S=1, TTL 255.
	if got := binary.BigEndian.Uint32(frame[14:18]); got != (uint32(586)<<12)|255 {
		t.Errorf("top entry = 0x%08x, want 0x%08x (S=0)", got, (uint32(586)<<12)|255)
	}
	if got := binary.BigEndian.Uint32(frame[18:22]); got != (uint32(2859)<<12)|(1<<8)|255 {
		t.Errorf("bottom entry = 0x%08x, want 0x%08x (S=1)", got, (uint32(2859)<<12)|(1<<8)|255)
	}
}

// TestPlanner_Direction_Down verifies the "down" direction: the emitted
// packet's MACs and IPs are swapped and the Direction field carries "down"
// (matching the GRE/PPPoE planner convention).
func TestPlanner_Direction_Down(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1",
		SrcPort: 1234, DstPort: 5678,
		SrcMAC: "aa:bb:cc:00:01:02", DstMAC: "aa:bb:cc:00:03:04",
		MPLS: &core.MPLSConfig{
			Labels:    []core.MPLSLabel{{Label: 16}},
			Direction: "down",
		},
	}
	cfgs := planAll(t, spec)
	if len(cfgs) != 1 {
		t.Fatalf("emitted %d configs, want 1", len(cfgs))
	}
	cfg := cfgs[0]
	if cfg.Direction != "down" {
		t.Errorf("Direction = %q, want down", cfg.Direction)
	}
	if cfg.L2.SrcMAC != spec.DstMAC || cfg.L2.DstMAC != spec.SrcMAC {
		t.Errorf("MACs = %s -> %s, want swapped", cfg.L2.SrcMAC, cfg.L2.DstMAC)
	}
	if cfg.L3.SrcIP != spec.DstIP || cfg.L3.DstIP != spec.SrcIP {
		t.Errorf("IPs = %s -> %s, want swapped", cfg.L3.SrcIP, cfg.L3.DstIP)
	}

	frame := buildAll(t, cfgs)[0]
	// Inner IPs swapped: 20.0.0.1 -> 10.0.0.1.
	if !bytes.Equal(frame[30:34], []byte{20, 0, 0, 1}) || !bytes.Equal(frame[34:38], []byte{10, 0, 0, 1}) {
		t.Errorf("inner IPs = % x -> % x, want 20.0.0.1 -> 10.0.0.1", frame[30:34], frame[34:38])
	}
}

// TestPlanner_Frames_IPID verifies the Frames field: 0 = 1 frame (covered
// by TestPlanner_DefaultDataPlane), N = N frames each with a distinct
// inner IP ID (RFC 791 §3.1) and the same label stack.
func TestPlanner_Frames_IPID(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1",
		SrcPort: 1234, DstPort: 5678,
		MPLS: &core.MPLSConfig{
			Labels: []core.MPLSLabel{{Label: 16}},
			Frames: 3,
		},
	}
	cfgs := planAll(t, spec)
	if len(cfgs) != 3 {
		t.Fatalf("emitted %d configs, want 3 (Frames=3)", len(cfgs))
	}
	frames := buildAll(t, cfgs)
	ipids := make(map[uint16]bool)
	for i, f := range frames {
		ipid := binary.BigEndian.Uint16(f[22:24]) // offset 14+4 = inner IP ID
		if ipids[ipid] {
			t.Errorf("frame %d: duplicate inner IPID %d", i, ipid)
		}
		ipids[ipid] = true
		if got := binary.BigEndian.Uint32(f[14:18]); got != (uint32(16)<<12)|(1<<8)|64 {
			t.Errorf("frame %d: label entry = 0x%08x, want 0x%08x", i, got, (uint32(16)<<12)|(1<<8)|64)
		}
	}
	if len(ipids) != 3 {
		t.Errorf("distinct IPIDs = %d, want 3", len(ipids))
	}
}

// TestPlanner_Multicast verifies MPLSConfig.Multicast reaches the builder:
// the wire EtherType is 0x8848 (RFC 3032 §3.10).
func TestPlanner_Multicast(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1",
		SrcPort: 1234, DstPort: 5678,
		MPLS: &core.MPLSConfig{
			Labels:    []core.MPLSLabel{{Label: 16}},
			Multicast: true,
		},
	}
	frame := buildAll(t, planAll(t, spec))[0]
	if got := binary.BigEndian.Uint16(frame[12:14]); got != core.EtherTypeMPLSMulticast {
		t.Errorf("EtherType = 0x%04x, want 0x8848 (multicast)", got)
	}
}

// TestPlanner_Validate verifies the read-only validation: a valid spec
// passes unchanged (no defaults filled — TTL stays 0, Direction stays
// empty), and each spec §MPLS-validate row is rejected.
func TestPlanner_Validate(t *testing.T) {
	valid := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1",
		MPLS: &core.MPLSConfig{
			Labels: []core.MPLSLabel{
				{Label: 16, TC: 6, TTL: 255},
				{Label: 2859, TTL: 255},
			},
		},
	}
	if err := NewPlanner().Validate(valid); err != nil {
		t.Fatalf("valid spec rejected: %v", err)
	}

	// Validate must be read-only: no defaults filled, no auto-correction.
	unchanged := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1",
		MPLS: &core.MPLSConfig{Labels: []core.MPLSLabel{{Label: 16}}},
	}
	if err := NewPlanner().Validate(unchanged); err != nil {
		t.Fatalf("minimal spec rejected: %v", err)
	}
	if unchanged.MPLS.Labels[0].TTL != 0 || unchanged.MPLS.Labels[0].S {
		t.Errorf("Validate mutated the spec (TTL=%d S=%v), want untouched zero values",
			unchanged.MPLS.Labels[0].TTL, unchanged.MPLS.Labels[0].S)
	}

	tests := []struct {
		name   string
		mutate func(*core.MPLSConfig, *core.FlowSpec)
	}{
		{
			name: "missing MPLS config",
			mutate: func(c *core.MPLSConfig, s *core.FlowSpec) {
				s.MPLS = nil
			},
		},
		{
			name: "empty label stack",
			mutate: func(c *core.MPLSConfig, s *core.FlowSpec) {
				c.Labels = nil
			},
		},
		{
			name: "label exceeds 20 bits",
			mutate: func(c *core.MPLSConfig, s *core.FlowSpec) {
				c.Labels = []core.MPLSLabel{{Label: 0x100000}}
			},
		},
		{
			name: "TC exceeds 3 bits",
			mutate: func(c *core.MPLSConfig, s *core.FlowSpec) {
				c.Labels = []core.MPLSLabel{{Label: 16, TC: 8}}
			},
		},
		{
			name: "explicit S on non-bottom entry",
			mutate: func(c *core.MPLSConfig, s *core.FlowSpec) {
				c.Labels = []core.MPLSLabel{{Label: 16, S: true}, {Label: 17, S: true}}
			},
		},
		{
			name: "invalid source IP",
			mutate: func(c *core.MPLSConfig, s *core.FlowSpec) {
				s.SrcIP = "not-an-ip"
			},
		},
		{
			name: "invalid destination IP",
			mutate: func(c *core.MPLSConfig, s *core.FlowSpec) {
				s.DstIP = "not-an-ip"
			},
		},
		{
			name: "unsupported inner proto",
			mutate: func(c *core.MPLSConfig, s *core.FlowSpec) {
				c.InnerProto = 99
			},
		},
		{
			name: "negative frames",
			mutate: func(c *core.MPLSConfig, s *core.FlowSpec) {
				c.Frames = -1
			},
		},
		{
			name: "unknown direction",
			mutate: func(c *core.MPLSConfig, s *core.FlowSpec) {
				c.Direction = "sideways"
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			spec := valid
			cfgCopy := *spec.MPLS
			cfgCopy.Labels = append([]core.MPLSLabel(nil), spec.MPLS.Labels...)
			spec.MPLS = &cfgCopy
			tc.mutate(spec.MPLS, &spec)
			if err := NewPlanner().Validate(spec); err == nil {
				t.Errorf("Validate succeeded, want error for %s", tc.name)
			}
		})
	}
}

// TestPlanner_EndToEnd drives the full path MapToFlowSpec -> planner ->
// builder: the JSON-decoded "mpls" strategy must reach the planner, and the
// built frame must carry the forced 0x8847 EtherType, the exact label-stack
// bytes, and a valid inner IP checksum (independent recomputation).
func TestPlanner_EndToEnd(t *testing.T) {
	raw := map[string]interface{}{
		"src_ip": "10.0.0.1",
		"dst_ip": "20.0.0.1",
		"mpls": map[string]interface{}{
			"labels": []interface{}{
				map[string]interface{}{"label": float64(16), "tc": float64(6), "ttl": float64(255)},
				map[string]interface{}{"label": float64(2859), "ttl": float64(255)},
			},
			"multicast":     false,
			"inner_proto":   float64(17),
			"inner_payload": "mpayload",
			"frames":        float64(1),
		},
	}
	spec := core.MapToFlowSpec(raw, "mpls")
	if spec.MPLS == nil {
		t.Fatal("MapToFlowSpec did not populate spec.MPLS")
	}
	if len(spec.MPLS.Labels) != 2 {
		t.Fatalf("label stack = %d entries, want 2", len(spec.MPLS.Labels))
	}
	if spec.MPLS.Labels[0].Label != 16 || spec.MPLS.Labels[0].TC != 6 || spec.MPLS.Labels[0].TTL != 255 {
		t.Errorf("labels[0] = %+v, want label 16 TC 6 TTL 255", spec.MPLS.Labels[0])
	}
	if spec.MPLS.Labels[1].Label != 2859 || spec.MPLS.Labels[1].TTL != 255 {
		t.Errorf("labels[1] = %+v, want label 2859 TTL 255", spec.MPLS.Labels[1])
	}
	if spec.MPLS.InnerProto != 17 || string(spec.MPLS.InnerPayload) != "mpayload" || spec.MPLS.Frames != 1 {
		t.Errorf("MPLS config = %+v, want InnerProto 17, InnerPayload mpayload, Frames 1", spec.MPLS)
	}

	cfgs := planAll(t, spec)
	frames := buildAll(t, cfgs)
	frame := frames[0]

	// Wire EtherType forced to 0x8847.
	if got := binary.BigEndian.Uint16(frame[12:14]); got != core.EtherTypeMPLSUnicast {
		t.Errorf("EtherType = 0x%04x, want 0x8847", got)
	}
	// Label stack: top (label 16, TC 6, S 0, TTL 255), bottom (2859, S 1,
	// TTL 255) — RFC 3032 §3.1 bit layout: ((label)<<12)|(tc<<9)|(s<<8)|ttl.
	// top = 0x10000 | 0x0C00 | 0x00 | 0xFF = 0x10CFF; bottom = 0x0B2B00 |
	// 0x00 | 0x100 | 0xFF = 0x0B2B1FF.
	if !bytes.Equal(frame[14:18], []byte{0x00, 0x01, 0x0c, 0xff}) {
		t.Errorf("top label = % x, want 00 01 0c ff (label 16, TC 6, S 0, TTL 255)", frame[14:18])
	}
	if !bytes.Equal(frame[18:22], []byte{0x00, 0xb2, 0xb1, 0xff}) {
		t.Errorf("bottom label = % x, want 00 b2 b1 ff (label 2859, S 1, TTL 255)", frame[18:22])
	}
	// Inner IPv4 at offset 22: 10.0.0.1 -> 20.0.0.1, protocol 17, valid
	// checksum (independent recomputation == wire).
	if frame[22] != 0x45 {
		t.Errorf("inner L3 byte = 0x%02x, want 0x45", frame[22])
	}
	if got, want := binary.BigEndian.Uint16(frame[32:34]), ipv4HeaderChecksum(frame[22:42]); got != want {
		t.Errorf("inner IP checksum = 0x%04x, independent recomputation = 0x%04x", got, want)
	}
	// Inner payload carried after the inner UDP header (offset 22 + 20 + 8
	// = 50; natural frame 58 bytes, padded to 60 — assert the natural slice).
	if !bytes.Equal(frame[50:58], []byte("mpayload")) {
		t.Errorf("inner payload = %q, want mpayload", frame[50:58])
	}
	// Flow identity on the config. mapToFlowSpec defaults the ports
	// (12345/80) when the JSON leaves them unset.
	if cfgs[0].FlowID != "10.0.0.1-20.0.0.1-12345-80" {
		t.Errorf("FlowID = %q, want 10.0.0.1-20.0.0.1-12345-80", cfgs[0].FlowID)
	}
	if cfgs[0].PacketIndex != 0 {
		t.Errorf("PacketIndex = %d, want 0", cfgs[0].PacketIndex)
	}
}
