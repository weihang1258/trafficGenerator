package srv6

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"net"
	"strings"
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

// resolveAll runs the resolver directly on the user-facing config.
func resolveAll(t *testing.T, cfg *SRv6Config) *ResolvedConfig {
	t.Helper()
	r, err := Resolve(cfg, "fc00:1::1", "", false)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	return r
}

// TestS1_SingleSegment tests S1: single-segment SRH, non-reduced, source-node
// view. Verifies wire layout matches design §6.1.
func TestS1_SingleSegment(t *testing.T) {
	cfg := &SRv6Config{
		SegmentList:     []string{"fc00:2::2"},
		SegType:         "end",
		PayloadProtocol: "udp",
	}
	r := resolveAll(t, cfg)
	if r.SegmentsLeft != 0 {
		t.Errorf("SegmentsLeft = %d, want 0", r.SegmentsLeft)
	}
	if r.LastEntry != 0 {
		t.Errorf("LastEntry = %d, want 0", r.LastEntry)
	}
	if r.Flags != 0 {
		t.Errorf("Flags = 0x%02x, want 0", r.Flags)
	}
	if r.HdrExtLen != 2 {
		t.Errorf("HdrExtLen = %d, want 2", r.HdrExtLen)
	}
	if r.NextHeader != 17 {
		t.Errorf("NextHeader = %d, want 17 (UDP)", r.NextHeader)
	}
	if len(r.SegmentList) != 1 {
		t.Errorf("wire SegmentList len = %d, want 1", len(r.SegmentList))
	}
	// Build frame and verify the wire bytes.
	frame, err := r.BuildFrame([]byte{0x30, 0x39, 0x00, 0x35, 0x00, 0x08, 0x00, 0x00})
	if err != nil {
		t.Fatalf("BuildFrame: %v", err)
	}
	// IPv6 header byte 0-3: 60 00 00 00 (version=6, TC=0, flow=0)
	if frame[0] != 0x60 || frame[1] != 0x00 || frame[2] != 0x00 || frame[3] != 0x00 {
		t.Errorf("IPv6 first 4 bytes = %x %x %x %x, want 60 00 00 00", frame[0], frame[1], frame[2], frame[3])
	}
	// Byte 6 = NextHeader = 43 (Routing / SRH)
	if frame[6] != 43 {
		t.Errorf("IPv6 NextHeader = %d, want 43 (Routing)", frame[6])
	}
	// Byte 7 = HopLimit = 64 (default)
	if frame[7] != 64 {
		t.Errorf("HopLimit = %d, want 64", frame[7])
	}
	// SRH starts at offset 40: byte 40 = NextHeader = 17 (UDP).
	if frame[40] != 17 {
		t.Errorf("SRH NextHeader = %d, want 17 (UDP)", frame[40])
	}
	// Byte 41 = HdrExtLen = 2
	if frame[41] != 2 {
		t.Errorf("SRH HdrExtLen = %d, want 2", frame[41])
	}
	// Byte 42 = RoutingType = 4
	if frame[42] != 4 {
		t.Errorf("SRH RoutingType = %d, want 4", frame[42])
	}
	// Byte 43 = SegmentsLeft = 0
	if frame[43] != 0 {
		t.Errorf("SRH SegmentsLeft = %d, want 0", frame[43])
	}
	// Byte 44 = LastEntry = 0
	if frame[44] != 0 {
		t.Errorf("SRH LastEntry = %d, want 0", frame[44])
	}
	// Byte 45 = Flags = 0
	if frame[45] != 0 {
		t.Errorf("SRH Flags = %d, want 0", frame[45])
	}
}

// TestS2_MultiSegmentReverseOrder tests S2: 3-segment SRH, the wire
// SegmentList MUST be in reverse order (RFC 8754 §2) and DstIP = first
// segment (highest index in wire list).
func TestS2_MultiSegmentReverseOrder(t *testing.T) {
	cfg := &SRv6Config{
		SegmentList:     []string{"fc00:11::1", "fc00:22::1", "fc00:bb::1"},
		SegType:         "end",
		PayloadProtocol: "tcp",
	}
	r := resolveAll(t, cfg)
	if r.SegmentsLeft != 2 {
		t.Errorf("SegmentsLeft = %d, want 2", r.SegmentsLeft)
	}
	if r.LastEntry != 2 {
		t.Errorf("LastEntry = %d, want 2", r.LastEntry)
	}
	if r.HdrExtLen != 6 {
		t.Errorf("HdrExtLen = %d, want 6 (2*3)", r.HdrExtLen)
	}
	if len(r.SegmentList) != 3 {
		t.Fatalf("wire SegmentList len = %d, want 3", len(r.SegmentList))
	}
	// Wire order: [B, S2, S1] (B is final, S1 is first).
	// DstIP = wire SegmentList[2] = S1 (first segment).
	wantDst := mustParseNetIP(t, "fc00:11::1")
	if !bytesEqual(r.DstIPv6, wantDst) {
		t.Errorf("DstIP = %x, want S1", r.DstIPv6)
	}
	// Wire[0] = B, Wire[2] = S1.
	wantB := mustParseNetIP(t, "fc00:bb::1")
	wantS1 := mustParseNetIP(t, "fc00:11::1")
	if !bytesEqual(r.SegmentList[0], wantB) {
		t.Errorf("Wire[0] = %x, want B (last segment)", r.SegmentList[0])
	}
	if !bytesEqual(r.SegmentList[2], wantS1) {
		t.Errorf("Wire[2] = %x, want S1 (first segment)", r.SegmentList[2])
	}

	// Build frame and verify HdrExtLen byte.
	frame, err := r.BuildFrame(nil)
	if err != nil {
		t.Fatalf("BuildFrame: %v", err)
	}
	if frame[41] != 6 {
		t.Errorf("SRH HdrExtLen byte = %d, want 6", frame[41])
	}
}

// TestS3_ReducedSRH tests S3: 2-segment reduced SRH (RFC 8754 §4.1.1):
// wire SegmentList has only 1 entry (the last segment, S1 is in DstIP).
func TestS3_ReducedSRH(t *testing.T) {
	cfg := &SRv6Config{
		SegmentList:     []string{"fc00:11::1", "fc00:22::1"},
		Reduced:         true,
		SegType:         "end.b6.encaps.red",
		PayloadProtocol: "udp",
	}
	r := resolveAll(t, cfg)
	if r.SegmentsLeft != 1 {
		t.Errorf("SegmentsLeft = %d, want 1 (n-1)", r.SegmentsLeft)
	}
	if r.LastEntry != 0 {
		t.Errorf("LastEntry = %d, want 0 (n-2, reduced)", r.LastEntry)
	}
	if r.HdrExtLen != 2 {
		t.Errorf("HdrExtLen = %d, want 2 (reduced: 2*(n-1))", r.HdrExtLen)
	}
	if len(r.SegmentList) != 1 {
		t.Fatalf("reduced wire SegmentList len = %d, want 1 (S1 omitted)", len(r.SegmentList))
	}
	wantS2 := mustParseNetIP(t, "fc00:22::1")
	if !bytesEqual(r.SegmentList[0], wantS2) {
		t.Errorf("Wire[0] = %x, want S2 (last segment)", r.SegmentList[0])
	}
	wantS1 := mustParseNetIP(t, "fc00:11::1")
	if !bytesEqual(r.DstIPv6, wantS1) {
		t.Errorf("DstIP = %x, want S1 (first segment, in DstIP)", r.DstIPv6)
	}
}

// TestS4_HMACTLV tests S4: HMAC TLV (Type=5) with 32-byte digest. Length
// field = 38 (0x26), total TLV = 40 bytes, 8n aligned.
func TestS4_HMACTLV(t *testing.T) {
	// HMAC TLV Value layout (RFC 8754 §2.1.2): D(1bit)+RES(15bits)=2 bytes
	// + Key ID(4 bytes) + HMAC digest(8n bytes). For digest=32 bytes the
	// total Value length = 2+4+32 = 38 bytes. Hex: 0000 (D+RES) + 00000001
	// (Key ID) + 32 zero bytes (digest).
	hmacValue := strings.Repeat("00", 2) + "00000001" + strings.Repeat("00", 32)
	hmacBytes, _ := hex.DecodeString(hmacValue)
	cfg := &SRv6Config{
		SegmentList:     []string{"fc00:11::1"},
		SegType:         "end",
		PayloadProtocol: "udp",
		TLV: []SRv6TLV{
			{Type: 5, Value: hmacBytes},
		},
	}
	r := resolveAll(t, cfg)
	frame, err := r.BuildFrame(make([]byte, 8))
	if err != nil {
		t.Fatalf("BuildFrame: %v", err)
	}
	// SRH starts at offset 40. HMAC TLV starts at offset 40+8+16 = 64.
	if frame[64] != 5 {
		t.Errorf("HMAC TLV type = %d, want 5", frame[64])
	}
	if frame[65] != 0x26 {
		t.Errorf("HMAC TLV length = %d, want 0x26 (38)", frame[65])
	}
	// SRH total = 8 + 16 + 40 = 64 bytes (already 8n aligned, no Pad1).
	// HdrExtLen = (64/8) - 1 = 7.
	if frame[41] != 7 {
		t.Errorf("HdrExtLen = %d, want 7", frame[41])
	}
	// Verify no tail PadN: offset 104 (= 40+64) should be the UDP start.
	// Check SRH total len = 64 means the inner payload starts at offset 40+64 = 104.
	if len(frame) < 104 {
		t.Errorf("frame length = %d, want >= 104", len(frame))
	}
}

// TestS5_PadNAlignment tests S5: 1-segment + experimental TLV (Type=200,
// Value=2 bytes) → SRH base = 8+16+4 = 28 bytes, needs 4 bytes PadN tail
// alignment to 32 bytes.
func TestS5_PadNAlignment(t *testing.T) {
	cfg := &SRv6Config{
		SegmentList: []string{"fc00:11::1"},
		TLV: []SRv6TLV{
			{Type: 200, Value: []byte{0xab, 0xcd}},
		},
	}
	r := resolveAll(t, cfg)
	frame, err := r.BuildFrame(make([]byte, 8))
	if err != nil {
		t.Fatalf("BuildFrame: %v", err)
	}
	// SRH starts at offset 40. Custom TLV at offset 40+8+16 = 64.
	if frame[64] != 200 {
		t.Errorf("Custom TLV type = %d, want 200", frame[64])
	}
	if frame[65] != 2 {
		t.Errorf("Custom TLV length = %d, want 2", frame[65])
	}
	// PadN at offset 68: type=4, length=2, value=00 00.
	if frame[68] != 4 {
		t.Errorf("PadN type = %d, want 4", frame[68])
	}
	if frame[69] != 2 {
		t.Errorf("PadN length = %d, want 2", frame[69])
	}
	// Total SRH = 32 bytes; HdrExtLen = 32/8 - 1 = 3.
	if frame[41] != 3 {
		t.Errorf("HdrExtLen = %d, want 3", frame[41])
	}
}

// TestS6_EndDX6Encapsulation tests S6: end.dx6 with payload_protocol=ipv6
// (Next Header = 41, IPv6-in-IPv6, NOT 59 per RFC 8986 §4.4).
func TestS6_EndDX6Encapsulation(t *testing.T) {
	innerIPv6 := make([]byte, 56)
	innerIPv6[0] = 0x60 // IPv6 Version
	cfg := &SRv6Config{
		SegmentList:     []string{"fc00:52::1"},
		SegType:         "end.dx6",
		SegmentsLeftPtr: func() *uint8 { v := uint8(0); return &v }(),
		PayloadProtocol: "ipv6",
		InnerPayload:    innerIPv6,
	}
	r := resolveAll(t, cfg)
	if r.NextHeader != 41 {
		t.Errorf("NextHeader = %d, want 41 (IPv6)", r.NextHeader)
	}
	frame, err := r.BuildFrame(innerIPv6)
	if err != nil {
		t.Fatalf("BuildFrame: %v", err)
	}
	// SRH NextHeader at offset 40 = 41 (IPv6).
	if frame[40] != 41 {
		t.Errorf("SRH NextHeader = %d, want 41 (IPv6)", frame[40])
	}
	// Inner IPv6 starts at offset 40 + 24 = 64.
	if frame[64] != 0x60 {
		t.Errorf("Inner IPv6 version byte = 0x%02x, want 0x60", frame[64])
	}
}

// TestPlanner_PlanDefaultDataPlane verifies the planner emits a PacketConfig
// with L3.SRH populated and IPv6 EtherType.
func TestPlanner_PlanDefaultDataPlane(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "fc00:1::1", DstIP: "fc00:2::2",
		SrcPort: 1234, DstPort: 5678,
		SRv6: &core.SRv6Config{
			SegmentList:     []string{"fc00:2::2"},
			SegType:         "end",
			PayloadProtocol: "udp",
		},
	}
	cfgs := planAll(t, spec)
	if len(cfgs) != 1 {
		t.Fatalf("emitted %d configs, want 1", len(cfgs))
	}
	cfg := cfgs[0]
	if cfg.L2.EtherType != core.EtherTypeIPv6 {
		t.Errorf("EtherType = 0x%04x, want 0x86DD", cfg.L2.EtherType)
	}
	if cfg.L3.SRH == nil {
		t.Fatal("L3.SRH is nil")
	}
	if cfg.L3.SRH.HdrExtLen != 2 {
		t.Errorf("SRH HdrExtLen = %d, want 2", cfg.L3.SRH.HdrExtLen)
	}
	if cfg.L3.SRH.NextHeader != 17 {
		t.Errorf("SRH NextHeader = %d, want 17 (UDP)", cfg.L3.SRH.NextHeader)
	}
	if cfg.L3.SRH.SegmentsLeft != 0 {
		t.Errorf("SRH SegmentsLeft = %d, want 0", cfg.L3.SRH.SegmentsLeft)
	}
	if cfg.L3.SRH.LastEntry != 0 {
		t.Errorf("SRH LastEntry = %d, want 0", cfg.L3.SRH.LastEntry)
	}
	if cfg.L3.Protocol != 43 {
		t.Errorf("L3.Protocol = %d, want 43 (Routing)", cfg.L3.Protocol)
	}
}

// TestPlanner_ReverseSegmentList verifies the planner reverses the
// user-facing SegmentList to wire order (RFC 8754 §2).
func TestPlanner_ReverseSegmentList(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "fc00:1::1",
		SRv6: &core.SRv6Config{
			SegmentList:     []string{"fc00:11::1", "fc00:22::1", "fc00:bb::1"},
			PayloadProtocol: "tcp",
		},
	}
	cfgs := planAll(t, spec)
	if len(cfgs) != 1 {
		t.Fatalf("emitted %d configs, want 1", len(cfgs))
	}
	srh := cfgs[0].L3.SRH
	if srh == nil {
		t.Fatal("L3.SRH is nil")
	}
	if len(srh.SegmentList) != 3 {
		t.Fatalf("SRH SegmentList len = %d, want 3", len(srh.SegmentList))
	}
	// Wire[0] = B (last segment); Wire[2] = S1 (first segment).
	wantB := mustParseNetIP(t, "fc00:bb::1")
	wantS1 := mustParseNetIP(t, "fc00:11::1")
	if srh.SegmentList[0] != [16]byte(wantB) {
		t.Errorf("Wire[0] = %x, want B (last segment)", srh.SegmentList[0])
	}
	if srh.SegmentList[2] != [16]byte(wantS1) {
		t.Errorf("Wire[2] = %x, want S1 (first segment)", srh.SegmentList[2])
	}
	// DstIP = S1 (first segment).
	wantDst := mustParseNetIP(t, "fc00:11::1")
	if cfgs[0].L3.DstIP != "fc00:11::1" {
		t.Errorf("L3.DstIP = %s, want fc00:11::1", cfgs[0].L3.DstIP)
	}
	_ = wantDst
}

// TestPlanner_Frames verifies Frames=5 emits 5 PacketConfigs with
// SRH metadata present.
func TestPlanner_Frames(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "fc00:1::1",
		SRv6: &core.SRv6Config{
			SegmentList:     []string{"fc00:2::2"},
			PayloadProtocol: "udp",
			Frames:          5,
		},
	}
	cfgs := planAll(t, spec)
	if len(cfgs) != 5 {
		t.Errorf("emitted %d configs, want 5", len(cfgs))
	}
	for i, cfg := range cfgs {
		if cfg.L3.SRH == nil {
			t.Errorf("frame %d: L3.SRH is nil", i)
		}
	}
}

// TestPlanner_DirectionDown verifies the down direction inverts the
// SegmentList so DstIP = reversed List[n-1] = original List[0] (design §5.4).
func TestPlanner_DirectionDown(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "fc00:1::1", DstIP: "fc00:2::2",
		SrcPort: 1234, DstPort: 5678,
		SrcMAC: "aa:bb:cc:00:01:02", DstMAC: "aa:bb:cc:00:03:04",
		SRv6: &core.SRv6Config{
			SegmentList:     []string{"fc00:11::1", "fc00:22::1", "fc00:bb::1"},
			PayloadProtocol: "tcp",
			Direction:       "down",
		},
	}
	cfgs := planAll(t, spec)
	if len(cfgs) != 1 {
		t.Fatalf("emitted %d configs, want 1", len(cfgs))
	}
	cfg := cfgs[0]
	if cfg.Direction != "down" {
		t.Errorf("Direction = %s, want down", cfg.Direction)
	}
	if cfg.L2.SrcMAC != "aa:bb:cc:00:03:04" || cfg.L2.DstMAC != "aa:bb:cc:00:01:02" {
		t.Errorf("MACs not swapped on down: %s -> %s", cfg.L2.SrcMAC, cfg.L2.DstMAC)
	}
	// After reversal, wire[0] = original user[0] = S1.
	wantS1 := mustParseNetIP(t, "fc00:11::1")
	if cfg.L3.SRH.SegmentList[0] != [16]byte(wantS1) {
		t.Errorf("Reversed wire[0] = %x, want S1 (original user[0])", cfg.L3.SRH.SegmentList[0])
	}
	// DstIP = reversed wire[2] = original user[2] = B (final destination).
	if cfg.L3.DstIP != "fc00:bb::1" {
		t.Errorf("DstIP = %s, want fc00:bb::1 (original final dest)", cfg.L3.DstIP)
	}
}

// TestValidate_Positive checks the basic valid spec passes.
func TestValidate_Positive(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "fc00:1::1",
		SRv6: &core.SRv6Config{
			SegmentList:     []string{"fc00:11::1", "fc00:22::1"},
			PayloadProtocol: "tcp",
		},
	}
	if err := Validate(spec); err != nil {
		t.Errorf("Validate failed: %v", err)
	}
}

// TestValidate_Negative covers the negative paths.
func TestValidate_Negative(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*core.SRv6Config, *core.FlowSpec)
	}{
		{"missing SRv6 config", func(c *core.SRv6Config, s *core.FlowSpec) { s.SRv6 = nil }},
		{"empty segment_list", func(c *core.SRv6Config, s *core.FlowSpec) { c.SegmentList = nil }},
		{"128 segments", func(c *core.SRv6Config, s *core.FlowSpec) {
			segList := make([]string, 128)
			for i := range segList {
				segList[i] = "fc00:11::1"
			}
			c.SegmentList = segList
		}},
		{"seg too large", func(c *core.SRv6Config, s *core.FlowSpec) {
			c.SegmentList = []string{"fc00:11::1"}
			v := uint8(5)
			c.SegmentsLeftPtr = &v
			c.LastEntry = 1
		}},
		{"invalid IPv6 in segment", func(c *core.SRv6Config, s *core.FlowSpec) {
			c.SegmentList = []string{"not-an-ip"}
		}},
		{"flags non-zero", func(c *core.SRv6Config, s *core.FlowSpec) {
			c.Flags = 0x01
		}},
		{"pad1 manual", func(c *core.SRv6Config, s *core.FlowSpec) {
			c.TLV = []core.SRv6TLV{{Type: 0}}
		}},
		{"padN manual", func(c *core.SRv6Config, s *core.FlowSpec) {
			c.TLV = []core.SRv6TLV{{Type: 4, Value: []byte{0}}}
		}},
		{"reserved TLV 6", func(c *core.SRv6Config, s *core.FlowSpec) {
			c.TLV = []core.SRv6TLV{{Type: 6, Value: []byte{0}}}
		}},
		{"unknown seg_type", func(c *core.SRv6Config, s *core.FlowSpec) {
			c.SegType = "unknown"
		}},
		{"direction down + explicit segments_left", func(c *core.SRv6Config, s *core.FlowSpec) {
			c.Direction = "down"
			v := uint8(2)
			c.SegmentsLeftPtr = &v
		}},
		{"end.x without dst_mac", func(c *core.SRv6Config, s *core.FlowSpec) {
			c.SegType = "end.x"
			s.DstMAC = ""
		}},
		{"end.dx6 with no inner payload", func(c *core.SRv6Config, s *core.FlowSpec) {
			c.SegType = "end.dx6"
			c.PayloadProtocol = "ipv6"
			c.InnerPayload = []byte{0x60}
		}},
		{"end.dx6 with wrong payload_protocol", func(c *core.SRv6Config, s *core.FlowSpec) {
			c.SegType = "end.dx6"
			c.PayloadProtocol = "udp"
			c.InnerPayload = make([]byte, 40)
		}},
		{"frames negative", func(c *core.SRv6Config, s *core.FlowSpec) {
			c.Frames = -1
		}},
		{"combined with MPLS", func(c *core.SRv6Config, s *core.FlowSpec) {
			s.MPLS = &core.MPLSConfig{}
		}},
		{"combined with GRE", func(c *core.SRv6Config, s *core.FlowSpec) {
			s.GRE = &core.GREConfig{}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			spec := core.FlowSpec{
				SrcIP: "fc00:1::1",
				SRv6: &core.SRv6Config{
					SegmentList:     []string{"fc00:11::1"},
					PayloadProtocol: "udp",
				},
			}
			tc.mutate(spec.SRv6, &spec)
			if err := Validate(spec); err == nil {
				t.Errorf("Validate succeeded, want error for %s", tc.name)
			}
		})
	}
}

// TestValidate_IPv6Required verifies spec.SrcIP must be IPv6.
func TestValidate_IPv6Required(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", // IPv4!
		SRv6: &core.SRv6Config{
			SegmentList: []string{"fc00:11::1"},
		},
	}
	if err := Validate(spec); err == nil {
		t.Error("Validate succeeded for IPv4 source, want error")
	}
}

// TestValidate_ReducedDefault verifies SegType="end.b6.encaps.red" sets
// Reduced=true by default (design §5.3 S11).
func TestValidate_ReducedDefault(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "fc00:1::1",
		SRv6: &core.SRv6Config{
			SegmentList: []string{"fc00:11::1", "fc00:22::1"},
			SegType:     "end.b6.encaps.red",
			// VR-15 (RFC 8986 §4.14): end.b6.encaps.red requires ipv6
			// payload with inner_payload >= 40 bytes.
			PayloadProtocol: "ipv6",
			InnerPayload:    make([]byte, 40),
		},
	}
	if err := Validate(spec); err != nil {
		t.Errorf("Validate failed for end.b6.encaps.red: %v", err)
	}
	// Verify the planner applies reduced.
	cfgs := planAll(t, spec)
	if len(cfgs) != 1 {
		t.Fatalf("emitted %d, want 1", len(cfgs))
	}
	if cfgs[0].L3.SRH.LastEntry != 0 {
		t.Errorf("LastEntry = %d, want 0 (n-2, reduced)", cfgs[0].L3.SRH.LastEntry)
	}
}

// TestEndToEnd_JSONMapToFlowSpec verifies the JSON → FlowSpec → planner
// path produces a valid config.
func TestEndToEnd_JSONMapToFlowSpec(t *testing.T) {
	raw := map[string]interface{}{
		"src_ip": "fc00:1::1",
		"dst_ip": "fc00:2::2",
		"srv6": map[string]interface{}{
			"segment_list":     []interface{}{"fc00:2::2", "fc00:11::1"},
			"seg_type":         "end",
			"payload_protocol": "udp",
		},
	}
	spec := core.MapToFlowSpec(raw, "srv6")
	if spec.SRv6 == nil {
		t.Fatal("spec.SRv6 is nil")
	}
	if len(spec.SRv6.SegmentList) != 2 {
		t.Errorf("SegmentList len = %d, want 2", len(spec.SRv6.SegmentList))
	}
	cfgs := planAll(t, spec)
	if len(cfgs) != 1 {
		t.Fatalf("emitted %d configs, want 1", len(cfgs))
	}
	cfg := cfgs[0]
	if cfg.L3.SRH == nil {
		t.Fatal("L3.SRH is nil")
	}
	if cfg.L3.SRH.HdrExtLen != 4 {
		t.Errorf("HdrExtLen = %d, want 4 (2*2)", cfg.L3.SRH.HdrExtLen)
	}
}

// TestValidate_ReducedSRHRequiresMinTwoSegments 验证 M1 修复：reduced SRH
// 要求 SegmentList 长度 n≥2（RFC 8754 §4.1.1）。reduced 模式剥离首段（S1 已
// 在 DstIP 中），若 n=1 则剥离后 wire 列表为空，无法形成有效 SRH，且
// SegmentsLeft=0 时无段可递减，语义无效。
func TestValidate_ReducedSRHRequiresMinTwoSegments(t *testing.T) {
	// n=1 + reduced：必须报错
	spec := core.FlowSpec{
		SrcIP: "fc00:1::1",
		SRv6: &core.SRv6Config{
			SegmentList:     []string{"fc00:11::1"}, // n=1
			Reduced:         true,
			SegType:         "end.b6.encaps.red",
			PayloadProtocol: "udp",
		},
	}
	if err := Validate(spec); err == nil {
		t.Error("Validate succeeded for reduced SRH with n=1, want error (RFC 8754 §4.1.1 requires n>=2)")
	}
}

// TestValidate_ReducedSRHTwoSegmentsOK 验证 n=2 + reduced 通过。
func TestValidate_ReducedSRHTwoSegmentsOK(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "fc00:1::1",
		SRv6: &core.SRv6Config{
			SegmentList:     []string{"fc00:11::1", "fc00:22::1"}, // n=2
			Reduced:         true,
			SegType:         "end.b6.encaps.red",
			PayloadProtocol: "ipv6", // VR-15 (RFC 8986 §4.14)
			InnerPayload:    make([]byte, 40),
		},
	}
	if err := Validate(spec); err != nil {
		t.Errorf("Validate failed for reduced SRH with n=2: %v", err)
	}
}

// TestPlanner_FlowIDFormatIPv6String 验证 H3 修复：FlowID 必须使用
// net.IP([]byte).String() 格式化的规范 IPv6 文本，而非 16 字节原始 []byte
// 字符串（不可读且每次地址不同会破坏聚合）。
func TestPlanner_FlowIDFormatIPv6String(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "fc00:1::1",
		SRv6: &core.SRv6Config{
			SegmentList:     []string{"fc00:11::1"},
			SegType:         "end",
			PayloadProtocol: "udp",
		},
	}
	cfgs := planAll(t, spec)
	if len(cfgs) != 1 {
		t.Fatalf("emitted %d configs, want 1", len(cfgs))
	}
	flowID := cfgs[0].FlowID
	if flowID == "" {
		t.Fatal("FlowID is empty")
	}
	// FlowID 必须包含规范 IPv6 文本 "fc00:1::1"，而非 16 字节原始字节串。
	// net.IP(fc00:1::1).String() 返回 "fc00:1::1"（压缩格式）。
	if !strings.Contains(flowID, "fc00:1::1") {
		t.Errorf("FlowID = %q, want it to contain canonical IPv6 text \"fc00:1::1\" (H3: must use net.IP.String(), not raw []byte)", flowID)
	}
	// FlowID 必须不能包含非可打印的 16 字节原始 IPv6 字节（如 0xfc 0x00 ...）
	// 规范格式 "fc00:1::1" 长度 9，原始字节 16 字节。如果 FlowID 第一段长度 = 16
	// 且包含非 ASCII 可打印字符，说明用了原始字节。
	parts := strings.Split(flowID, "-")
	if len(parts) < 1 {
		t.Fatalf("FlowID parts = %v, want at least 1", parts)
	}
	if len(parts[0]) == 16 {
		t.Errorf("FlowID first part length = 16 (raw []byte?), want canonical IPv6 text length (H3): %q", parts[0])
	}
}

// TestValidate_HMACTLVValueLength 验证 M1-NEW 修复：HMAC TLV（Type=5）
// 的 Value 长度必须为 14/22/30/38（6+8n，n=1..4），对应
// D+RES(2) + Key ID(4) + HMAC digest(8/16/24/32)（RFC 8754 §2.1.2）。
// 其他长度在 wire 上无法构成合法 HMAC TLV，接收端会丢弃。
func TestValidate_HMACTLVValueLength(t *testing.T) {
	// 非法长度：8 字节（不足 14）
	spec8 := core.FlowSpec{
		SrcIP: "fc00:1::1",
		SRv6: &core.SRv6Config{
			SegmentList:     []string{"fc00:11::1"},
			PayloadProtocol: "udp",
			TLV: []core.SRv6TLV{
				{Type: 5, Value: make([]byte, 8)},
			},
		},
	}
	if err := Validate(spec8); err == nil {
		t.Error("Validate succeeded for HMAC TLV with Value length 8 (want error: must be 14/22/30/38)")
	}

	// 非法长度：16 字节（不是 14/22/30/38 之一）
	spec16 := core.FlowSpec{
		SrcIP: "fc00:1::1",
		SRv6: &core.SRv6Config{
			SegmentList:     []string{"fc00:11::1"},
			PayloadProtocol: "udp",
			TLV: []core.SRv6TLV{
				{Type: 5, Value: make([]byte, 16)},
			},
		},
	}
	if err := Validate(spec16); err == nil {
		t.Error("Validate succeeded for HMAC TLV with Value length 16 (want error: must be 14/22/30/38)")
	}

	// 正值：14 字节（最小合法 HMAC，HMAC_len=8）
	spec14 := core.FlowSpec{
		SrcIP: "fc00:1::1",
		SRv6: &core.SRv6Config{
			SegmentList:     []string{"fc00:11::1"},
			PayloadProtocol: "udp",
			TLV: []core.SRv6TLV{
				{Type: 5, Value: make([]byte, 14)},
			},
		},
	}
	if err := Validate(spec14); err != nil {
		t.Errorf("Validate failed for HMAC TLV with Value length 14: %v", err)
	}
}

// TestValidate_HMACTLVValueLength38 验证 38 字节 HMAC TLV（HMAC_len=32，
// RFC 8754 最大截断长度）通过校验。
func TestValidate_HMACTLVValueLength38(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "fc00:1::1",
		SRv6: &core.SRv6Config{
			SegmentList:     []string{"fc00:11::1"},
			PayloadProtocol: "udp",
			TLV: []core.SRv6TLV{
				{Type: 5, Value: make([]byte, 38)},
			},
		},
	}
	if err := Validate(spec); err != nil {
		t.Errorf("Validate failed for HMAC TLV with Value length 38: %v", err)
	}
}

// TestValidate_VR22SpecPayloadNonEmpty 验证 M2-NEW 修复：payload_protocol="none"
// 但 cfg.InnerPayload 为空、spec.Payload 非空时，VR-22 必须报错。
// 原实现只检查 cfg.InnerPayload，但 planner 的 payload 解析链为
// cfg.InnerPayload → spec.Payload，因此 spec.Payload 非空时 wire
// 上仍然携带数据，应被 VR-22 拦截。
func TestValidate_VR22SpecPayloadNonEmpty(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP:   "fc00:1::1",
		Payload: []byte("hello"), // spec.Payload 非空
		SRv6: &core.SRv6Config{
			SegmentList:     []string{"fc00:11::1"},
			PayloadProtocol: "none",
			// InnerPayload 为空，planner 会 fallback 到 spec.Payload
		},
	}
	if err := Validate(spec); err == nil {
		t.Error("Validate succeeded for payload_protocol=none with non-empty spec.Payload (want error per VR-22 / RFC 8200 §4.7)")
	}
}

// TestValidate_VR22SpecPayloadEmpty 验证 payload_protocol="none" + 两处
// payload 均为空 → 通过（纯 SRH 无内层，VR-22 不应误报）。
func TestValidate_VR22SpecPayloadEmpty(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP:   "fc00:1::1",
		Payload: nil,
		SRv6: &core.SRv6Config{
			SegmentList:     []string{"fc00:11::1"},
			PayloadProtocol: "none",
			InnerPayload:    nil,
		},
	}
	if err := Validate(spec); err != nil {
		t.Errorf("Validate failed for payload_protocol=none with both payloads nil: %v", err)
	}
}

// TestPlanner_ICMPv6EchoDefault 验证 M3-NEW 修复：payload_protocol="icmpv6"
// 且未提供 payload 时，planner 生成默认 ICMPv6 Echo Request。
// 校验和按伪头（DstIP=SegmentList[0]）计算。设计 §6.16 S16。
func TestPlanner_ICMPv6EchoDefault(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "fc00:1::1",
		SRv6: &core.SRv6Config{
			SegmentList:     []string{"fc00:2::2"},
			SegType:         "end",
			PayloadProtocol: "icmpv6",
		},
	}
	cfgs := planAll(t, spec)
	if len(cfgs) != 1 {
		t.Fatalf("emitted %d configs, want 1", len(cfgs))
	}
	cfg := cfgs[0]
	// L4 协议必须为 icmpv6
	if cfg.L4.Protocol != "icmpv6" {
		t.Errorf("L4.Protocol = %q, want icmpv6", cfg.L4.Protocol)
	}
	// Payload 必须非空（包含 ICMPv6 Echo Request 头 + 数据）
	if len(cfg.Payload) == 0 {
		t.Fatal("Payload is empty, want ICMPv6 Echo Request bytes")
	}
	// 前 8 字节为 ICMPv6 Echo Request 头
	if len(cfg.Payload) < 16 {
		t.Fatalf("Payload length = %d, want >= 16 (8 header + 8 data)", len(cfg.Payload))
	}
	// Type=128 (Echo Request)
	if cfg.Payload[0] != 128 {
		t.Errorf("ICMPv6 Type[0] = %d, want 128 (Echo Request)", cfg.Payload[0])
	}
	// Code=0
	if cfg.Payload[1] != 0 {
		t.Errorf("ICMPv6 Code[1] = %d, want 0", cfg.Payload[1])
	}
	// Identifier=1 (offset 4-5)
	if binary.BigEndian.Uint16(cfg.Payload[4:6]) != 1 {
		t.Errorf("ICMPv6 Identifier = %d, want 1", binary.BigEndian.Uint16(cfg.Payload[4:6]))
	}
	// Sequence=1 (offset 6-7)
	if binary.BigEndian.Uint16(cfg.Payload[6:8]) != 1 {
		t.Errorf("ICMPv6 Sequence = %d, want 1", binary.BigEndian.Uint16(cfg.Payload[6:8]))
	}
	// Data="12345678" (offset 8-15)
	if string(cfg.Payload[8:16]) != "12345678" {
		t.Errorf("ICMPv6 Data = %q, want \"12345678\"", string(cfg.Payload[8:16]))
	}
	// 校验和必须非零（RFC 4443 §2.3，伪头含 IPv6 地址 vs 全 0 的差）
	cksum := binary.BigEndian.Uint16(cfg.Payload[2:4])
	if cksum == 0 {
		t.Error("ICMPv6 Checksum is 0, want non-zero (pseudo-header checksum per RFC 4443 §2.3)")
	}
	// 设计 §6.16 S16 HexDump 指定 Checksum=0xB6D6（地址 fc00:1::1→fc00:2::2）
	if cksum != 0xB6D6 {
		t.Errorf("ICMPv6 Checksum = 0x%04X, want 0xB6D6 (design §6.16 S16 with fc00:1::1→fc00:2::2)", cksum)
	}
}

// TestPlanner_ICMPv6UserPayload pass-through 验证：当用户已提供 innerPayload
// 时，planner 不覆盖——直接透传用户提供的字节（不作默认化）。
func TestPlanner_ICMPv6UserPayload(t *testing.T) {
	userPayload := make([]byte, 20)
	userPayload[0] = 129 // Echo Reply
	spec := core.FlowSpec{
		SrcIP: "fc00:1::1",
		SRv6: &core.SRv6Config{
			SegmentList:     []string{"fc00:2::2"},
			SegType:         "end",
			PayloadProtocol: "icmpv6",
			InnerPayload:    userPayload,
		},
	}
	cfgs := planAll(t, spec)
	if len(cfgs) != 1 {
		t.Fatalf("emitted %d configs, want 1", len(cfgs))
	}
	cfg := cfgs[0]
	if len(cfg.Payload) != 20 {
		t.Errorf("Payload length = %d, want 20 (user-provided)", len(cfg.Payload))
	}
	// 不应被默认化覆盖（ICMPv6 Type 保持 129，非默认 128）
	if cfg.Payload[0] != 129 {
		t.Errorf("ICMPv6 Type[0] = %d, want 129 (user payload pass-through, not overridden to 128)", cfg.Payload[0])
	}
}

// TestValidate_ExplicitReducedFalseOverridesSegTypeDefault 验证 M1：
// seg_type=end.b6.encaps.red 默认 Reduced=true，但用户显式 reduced=false
// 时（ReducedPtr=&false）必须以用户值为准（设计 §5.3 S11"用户显式配
// reduced 时以用户值为准"）。
func TestValidate_ExplicitReducedFalseOverridesSegTypeDefault(t *testing.T) {
	f := false
	spec := core.FlowSpec{
		SrcIP: "fc00:1::1",
		SRv6: &core.SRv6Config{
			SegmentList: []string{"fc00:11::1", "fc00:22::1"},
			SegType:     "end.b6.encaps.red",
			ReducedPtr:  &f, // 显式 false
			Reduced:     false,
			// VR-15 (RFC 8986 §4.14): end.b6.encaps.red requires ipv6
			// payload with inner_payload >= 40 bytes.
			PayloadProtocol: "ipv6",
			InnerPayload:    make([]byte, 40),
		},
	}
	if err := Validate(spec); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if got := resolveReduced(spec.SRv6); got {
		t.Error("resolveReduced = true, want false (explicit reduced=false overrides end.b6.encaps.red default)")
	}
	// 非 reduced：LastEntry = n-1 = 1（而非 reduced 的 n-2 = 0）。
	cfgs := planAll(t, spec)
	if len(cfgs) != 1 {
		t.Fatalf("emitted %d configs, want 1", len(cfgs))
	}
	if cfgs[0].L3.SRH.LastEntry != 1 {
		t.Errorf("LastEntry = %d, want 1 (n-1, explicit reduced=false)", cfgs[0].L3.SRH.LastEntry)
	}
	if len(cfgs[0].L3.SRH.SegmentList) != 2 {
		t.Errorf("wire SegmentList len = %d, want 2 (non-reduced)", len(cfgs[0].L3.SRH.SegmentList))
	}
}

// TestResolve_DirectionDown 验证 M-3：Resolve 路径对 Direction=down 的
// 处理与 Plan 路径一致（设计 §5.4 / DD-01..DD-07）：交换 SrcIP/DstIP、
// 反转 wire SegmentList、DstIP = 反转后最后一个 = 原最终目的。
func TestResolve_DirectionDown(t *testing.T) {
	tf := false
	cfg := &SRv6Config{
		SrcIPv6:         "fc00:1::1",
		SegmentList:     []string{"fc00:11::1", "fc00:22::1", "fc00:bb::1"},
		PayloadProtocol: "tcp",
		Direction:       "down",
		ReducedPtr:      &tf,
		Reduced:         false,
	}
	r, err := Resolve(cfg, "fc00:1::1", "", false)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	// 原用户列表 [S1,S2,B]；down 反转 wireList 后 DstIP = 反转后 wire[n-1]
	// = 原最后一段 fc00:bb::1（与 TestPlanner_DirectionDown 断言一致）。
	wantDst := mustParseNetIP(t, "fc00:bb::1")
	if !bytesEqual(r.DstIPv6, wantDst) {
		t.Errorf("DstIPv6 = %x, want fc00:bb::1 (reversed wire[n-1] = original last)", r.DstIPv6)
	}
	// down 交换 spec.SrcIP<->spec.DstIP；此处 src_ipv6 显式指定（无 dst_ipv6），
	// 交换后 effectiveSrc = 原 dstStr = SegmentList[0] = fc00:11::1。
	wantSrc := mustParseNetIP(t, "fc00:11::1")
	if !bytesEqual(r.SrcIPv6, wantSrc) {
		t.Errorf("SrcIPv6 = %x, want fc00:11::1 (swapped dst = SegmentList[0])", r.SrcIPv6)
	}
	// 反转后的 wire list：up 方向 wire 序 = [B, S2, S1]（wire[0]=最后段）；
	// down 反转 = [S1, S2, B]。
	wantW0 := mustParseNetIP(t, "fc00:11::1")
	wantW2 := mustParseNetIP(t, "fc00:bb::1")
	if len(r.SegmentList) != 3 {
		t.Fatalf("wire SegmentList len = %d, want 3", len(r.SegmentList))
	}
	if !bytesEqual(r.SegmentList[0], wantW0) {
		t.Errorf("Wire[0] = %x, want fc00:11::1 (original first)", r.SegmentList[0])
	}
	if !bytesEqual(r.SegmentList[2], wantW2) {
		t.Errorf("Wire[2] = %x, want fc00:bb::1 (original last)", r.SegmentList[2])
	}
}

// TestPlanner_HopLimitWrap 验证 L-2：Hop Limit 超过 64 帧后从 1 wrap 到
// 255 再递减（设计 BND-06 "0 之后 wrap 1..255"），永不发出 0。
func TestPlanner_HopLimitWrap(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "fc00:1::1",
		SRv6: &core.SRv6Config{
			SegmentList:     []string{"fc00:11::1"},
			PayloadProtocol: "udp",
			Frames:          320, // 覆盖 64 + 255 + 1 个 wrap 周期
		},
	}
	cfgs := planAll(t, spec)
	if len(cfgs) != 320 {
		t.Fatalf("emitted %d configs, want 320", len(cfgs))
	}
	// i=0:64, i=1:63, ..., i=63:1, i=64:255, i=65:254, ..., i=318:255, i=319:254
	// 前 64 帧：64-i。
	for i := 0; i < 64; i++ {
		if cfg := cfgs[i].L3.TTL; cfg != uint8(64-i) {
			t.Errorf("frame %d TTL = %d, want %d", i, cfg, 64-i)
		}
	}
	// wrap 首帧 i=64 → 255。
	if got := cfgs[64].L3.TTL; got != 255 {
		t.Errorf("frame 64 TTL = %d, want 255 (wrap to 255 after 1)", got)
	}
	// 第二帧 i=65 → 254。
	if got := cfgs[65].L3.TTL; got != 254 {
		t.Errorf("frame 65 TTL = %d, want 254", got)
	}
	// 全 320 帧不允许出现 0。
	for i, cfg := range cfgs {
		if cfg.L3.TTL == 0 {
			t.Errorf("frame %d TTL = 0 (Hop Limit must never be 0)", i)
		}
	}
}

// helpers
func mustParseNetIP(t *testing.T, s string) []byte {
	t.Helper()
	ip := net.ParseIP(s)
	if ip == nil {
		t.Fatalf("parse %q failed", s)
	}
	v6 := ip.To16()
	if v6 == nil {
		t.Fatalf("not IPv6: %q", s)
	}
	return v6
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
