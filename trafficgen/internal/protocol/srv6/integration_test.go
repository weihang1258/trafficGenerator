package srv6

import (
	"context"
	"encoding/binary"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

// TestPlannerToBuilder_Integration verifies the planner produces a
// PacketConfig that the core builder can serialize into correct bytes.
func TestPlannerToBuilder_Integration(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "fc00:1::1",
		SRv6: &core.SRv6Config{
			SegmentList: []string{"fc00:11::1", "fc00:22::1", "fc00:bb::1"},
			SegType:     "end",
			PayloadProtocol: "tcp",
		},
	}
	cfgs := planAll(t, spec)
	if len(cfgs) != 1 {
		t.Fatalf("emitted %d configs, want 1", len(cfgs))
	}
	cfg := cfgs[0]

	// Build frame using core builder.
	builder := core.NewBuilder()
	frame, err := builder.Build(cfg)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	// Ethernet (14) + IPv6 (40) + SRH (56) + TCP (20) = 130 bytes.
	// Ethernet offset 12-13 = EtherType = 0x86DD (IPv6).
	if got := binary.BigEndian.Uint16(frame[12:14]); got != 0x86DD {
		t.Errorf("EtherType = 0x%04x, want 0x86DD", got)
	}
	// IPv6 NextHeader at offset 14+6 = 20 = 43 (Routing).
	if frame[20] != 43 {
		t.Errorf("IPv6 NextHeader = %d, want 43 (Routing)", frame[20])
	}
	// Total IPv6 payload length = SRH (56) + TCP (20) = 76.
	if got := binary.BigEndian.Uint16(frame[14+4 : 14+6]); got != 76 {
		t.Errorf("IPv6 payload length = %d, want 76", got)
	}
	// SRH at offset 14+40 = 54.
	// SRH NextHeader = 6 (TCP).
	if frame[54] != 6 {
		t.Errorf("SRH NextHeader = %d, want 6 (TCP)", frame[54])
	}
	// SRH HdrExtLen = 6 (2*3).
	if frame[55] != 6 {
		t.Errorf("SRH HdrExtLen = %d, want 6", frame[55])
	}
	// SRH RoutingType = 4.
	if frame[56] != 4 {
		t.Errorf("SRH RoutingType = %d, want 4", frame[56])
	}
	// SRH SegmentsLeft = 2.
	if frame[57] != 2 {
		t.Errorf("SRH SegmentsLeft = %d, want 2", frame[57])
	}
	// SRH LastEntry = 2.
	if frame[58] != 2 {
		t.Errorf("SRH LastEntry = %d, want 2", frame[58])
	}
	// SRH Flags = 0.
	if frame[59] != 0 {
		t.Errorf("SRH Flags = %d, want 0", frame[59])
	}
	// TCP at offset 14+40+56 = 110.
	if frame[110] != 0 {
		t.Errorf("TCP byte 0 = %d, want 0 (high byte of SrcPort)", frame[110])
	}
}

// TestPlannerToBuilder_ReducedSRH verifies the reduced SRH is correctly
// serialized: only 1 segment in the wire list, HdrExtLen = 2.
func TestPlannerToBuilder_ReducedSRH(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "fc00:1::1",
		SRv6: &core.SRv6Config{
			SegmentList:     []string{"fc00:11::1", "fc00:22::1"},
			Reduced:         true,
			SegType:         "end.b6.encaps.red",
			PayloadProtocol: "ipv6", // VR-15 (RFC 8986 §4.14)
			InnerPayload:    make([]byte, 40),
		},
	}
	cfgs := planAll(t, spec)
	if len(cfgs) != 1 {
		t.Fatalf("emitted %d configs, want 1", len(cfgs))
	}
	cfg := cfgs[0]

	builder := core.NewBuilder()
	frame, err := builder.Build(cfg)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	// IPv6 NextHeader at offset 20 = 43 (Routing).
	if frame[20] != 43 {
		t.Errorf("IPv6 NextHeader = %d, want 43 (Routing)", frame[20])
	}
	// SRH at offset 54. HdrExtLen = 2 (2*(n-1) = 2*1 = 2).
	if frame[55] != 2 {
		t.Errorf("SRH HdrExtLen = %d, want 2 (reduced)", frame[55])
	}
	// SRH SegmentsLeft = 1 (n-1).
	if frame[57] != 1 {
		t.Errorf("SRH SegmentsLeft = %d, want 1", frame[57])
	}
	// SRH LastEntry = 0 (n-2, reduced).
	if frame[58] != 0 {
		t.Errorf("SRH LastEntry = %d, want 0 (reduced)", frame[58])
	}
	// DstIP (offset 24-39) = S1 (first segment, the omitted one).
	// Expected DstIP bytes (offset 24-39) = fc00:11::1:
	// fc 00 00 11 00 00 00 00 00 00 00 00 00 00 00 01
}

// TestPlannerToBuilder_HMAC verifies HMAC TLV is correctly serialized.
func TestPlannerToBuilder_HMAC(t *testing.T) {
	hmacValue := make([]byte, 38)
	// HMAC TLV Value layout: D+RES[0:2] + Key ID[2:6] + HMAC[6:38]
	// (RFC 8754 §2.1.2). Key ID is big-endian, so value[5]=1 → KeyID 0x00000001.
	hmacValue[5] = 1 // Key ID = 0x00000001
	spec := core.FlowSpec{
		SrcIP: "fc00:1::1",
		SRv6: &core.SRv6Config{
			SegmentList: []string{"fc00:11::1"},
			SegType:     "end",
			PayloadProtocol: "udp",
			TLV: []core.SRv6TLV{
				{Type: 5, Value: hmacValue},
			},
		},
	}
	cfgs := planAll(t, spec)
	if len(cfgs) != 1 {
		t.Fatalf("emitted %d configs, want 1", len(cfgs))
	}
	cfg := cfgs[0]
	builder := core.NewBuilder()
	frame, err := builder.Build(cfg)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	// HMAC TLV starts at offset 14+40+8+16 = 78 (IPv6 + SRH fixed + 1 segment).
	// Type = 5.
	if frame[78] != 5 {
		t.Errorf("HMAC TLV type = %d, want 5", frame[78])
	}
	// Length = 38 (0x26).
	if frame[79] != 0x26 {
		t.Errorf("HMAC TLV length = %d, want 0x26 (38)", frame[79])
	}
	// Key ID at offset 78+4 = 82 should have 0x00000001.
	if got := binary.BigEndian.Uint32(frame[82:86]); got != 1 {
		t.Errorf("HMAC Key ID = %d, want 1", got)
	}
}

// TestPlannerToBuilder_HopByHop verifies HopByHop + SRH chaining.
// IPv6 NH=0 → HopByHop → SRH (NH=43) → inner L4.
func TestPlannerToBuilder_HopByHopAndSRH(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "fc00:1::1",
		HopByHop: []core.IPv6Option{
			{Type: 0x00, Value: nil}, // Pad1
		},
		SRv6: &core.SRv6Config{
			SegmentList: []string{"fc00:11::1"},
			SegType:     "end",
			PayloadProtocol: "udp",
		},
	}
	cfgs := planAll(t, spec)
	if len(cfgs) != 1 {
		t.Fatalf("emitted %d configs, want 1", len(cfgs))
	}
	cfg := cfgs[0]
	builder := core.NewBuilder()
	frame, err := builder.Build(cfg)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	// IPv6 NH at offset 14+6 = 20 = 0 (HopByHop).
	if frame[20] != 0 {
		t.Errorf("IPv6 NextHeader = %d, want 0 (HopByHop)", frame[20])
	}
	// HopByHop at offset 14+40 = 54. HBH NextHeader = 43 (Routing).
	if frame[54] != 43 {
		t.Errorf("HopByHop NextHeader = %d, want 43 (Routing)", frame[54])
	}
	// SRH at offset 14+40+8 = 62 (HBH is 8 bytes after Pad1).
	// SRH NextHeader = 17 (UDP).
	if frame[62] != 17 {
		t.Errorf("SRH NextHeader = %d, want 17 (UDP)", frame[62])
	}
}

// TestPlannerToBuilder_InnerEnsureIgnored is a placeholder for ensuring
// the build pipeline doesn't crash on inner IPv6.
func TestPlannerToBuilder_InnerIPv6(t *testing.T) {
	innerIPv6 := make([]byte, 56)
	innerIPv6[0] = 0x60
	spec := core.FlowSpec{
		SrcIP: "fc00:51::1", DstIP: "fc00:52::1",
		SRv6: &core.SRv6Config{
			SegmentList: []string{"fc00:52::1"},
			SegmentsLeftPtr: func() *uint8 { v := uint8(0); return &v }(),
			SegType:     "end.dx6",
			PayloadProtocol: "ipv6",
			InnerPayload: innerIPv6,
		},
	}
	cfgs := planAll(t, spec)
	if len(cfgs) != 1 {
		t.Fatalf("emitted %d configs, want 1", len(cfgs))
	}
	cfg := cfgs[0]
	builder := core.NewBuilder()
	_, err := builder.Build(cfg)
	if err != nil {
		t.Errorf("Build failed: %v", err)
	}
}

// TestPlanner_Metadata verifies the Metadata fields are populated with
// srv6_* keys for report aggregation.
func TestPlanner_Metadata(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "fc00:1::1",
		SRv6: &core.SRv6Config{
			SegmentList: []string{"fc00:11::1", "fc00:22::1", "fc00:bb::1"},
			SegType:     "end",
			PayloadProtocol: "tcp",
		},
	}
	cfgs := planAll(t, spec)
	if len(cfgs) != 1 {
		t.Fatalf("emitted %d configs, want 1", len(cfgs))
	}
	md := cfgs[0].Metadata
	if md == nil {
		t.Fatal("Metadata is nil")
	}
	if md["srv6_seg_type"] != "end" {
		t.Errorf("srv6_seg_type = %v, want end", md["srv6_seg_type"])
	}
	if md["srv6_segments_left"] != uint8(2) {
		t.Errorf("srv6_segments_left = %v, want 2", md["srv6_segments_left"])
	}
	if md["srv6_last_entry"] != uint8(2) {
		t.Errorf("srv6_last_entry = %v, want 2", md["srv6_last_entry"])
	}
	if md["srv6_segment_count"] != 3 {
		t.Errorf("srv6_segment_count = %v, want 3", md["srv6_segment_count"])
	}
	if md["srv6_policy_segments"] != 3 {
		t.Errorf("srv6_policy_segments = %v, want 3", md["srv6_policy_segments"])
	}
	if md["srv6_reduced"] != false {
		t.Errorf("srv6_reduced = %v, want false", md["srv6_reduced"])
	}
	if md["srv6_hdr_ext_len"] != uint8(6) {
		t.Errorf("srv6_hdr_ext_len = %v, want 6", md["srv6_hdr_ext_len"])
	}
}

// Verify the planner can be invoked with Plan+ctx.
func TestPlanner_PlanWithContext(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "fc00:1::1",
		SRv6: &core.SRv6Config{
			SegmentList: []string{"fc00:11::1"},
			PayloadProtocol: "udp",
		},
	}
	p := NewPlanner()
	ctx := context.Background()
	ch, err := p.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if ch == nil {
		t.Fatal("channel is nil")
	}
	count := 0
	for range ch {
		count++
	}
	if count != 1 {
		t.Errorf("frame count = %d, want 1", count)
	}
}
