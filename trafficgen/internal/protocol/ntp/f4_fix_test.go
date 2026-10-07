package ntp

// F4 regression test: Mode=6 control message header byte 0 must use the
// standard NTP layout LI(2)|VN(3)|Mode(3) per RFC 5906 §4 (which references
// RFC 5905 §7.3 for the LI/VN/Mode fields). An earlier revision packed byte 0
// as Version(2)|LI(2)|Mode(4) per a non-standard design doc, producing
// invalid VN and Mode bits. This test guards against regression.

import (
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

// TestF4_ControlModeByte0_StandardLayout verifies that a Mode=6 config
// produces a packet whose byte 0 has the correct LI/VN/Mode bit layout:
//   - LI in bits 7-6 (top 2 bits)
//   - VN in bits 5-3 (middle 3 bits)
//   - Mode in bits 2-0 (bottom 3 bits) = 6 (control)
func TestF4_ControlModeByte0_StandardLayout(t *testing.T) {
	spec := validNTPSpec()
	spec.NTP = &core.NTPConfig{
		Mode:        ModeControl,
		Version:     4,
		Sequence:    1,
		RequestCode: 1,
		ControlData: []byte{0x01, 0x02},
		RequestOnly: true, // D-NTP-2：布局单测只看请求形状
	}
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	if len(cfgs) != 1 {
		t.Fatalf("expected 1 control packet, got %d", len(cfgs))
	}
	b0 := cfgs[0].Payload[0]

	// Mode bits (bottom 3) must be 6 (control).
	if got := b0 & 0x07; got != ModeControl {
		t.Errorf("byte[0] Mode bits = %d, want %d (ModeControl)", got, ModeControl)
	}
	// VN bits (bits 5-3) must be 4 (NTPv4).
	if got := (b0 >> 3) & 0x07; got != 4 {
		t.Errorf("byte[0] VN bits = %d, want 4 (NTPv4)", got)
	}
	// LI bits (bits 7-6) must be 0 (no leap warning).
	if got := (b0 >> 6) & 0x03; got != 0 {
		t.Errorf("byte[0] LI bits = %d, want 0 (no warning)", got)
	}
}

// TestF4_ControlModeByte0_Version3 verifies the VN bits are correctly set
// when Version=3 is used.
func TestF4_ControlModeByte0_Version3(t *testing.T) {
	spec := validNTPSpec()
	spec.NTP = &core.NTPConfig{
		Mode:        ModeControl,
		Version:     3,
		Sequence:    1,
		RequestCode: 1,
		RequestOnly: true, // D-NTP-2：布局单测只看请求形状
	}
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	if len(cfgs) != 1 {
		t.Fatalf("expected 1 control packet, got %d", len(cfgs))
	}
	b0 := cfgs[0].Payload[0]

	// Mode bits must be 6.
	if got := b0 & 0x07; got != ModeControl {
		t.Errorf("byte[0] Mode bits = %d, want %d", got, ModeControl)
	}
	// VN bits must be 3.
	if got := (b0 >> 3) & 0x07; got != 3 {
		t.Errorf("byte[0] VN bits = %d, want 3 (NTPv3)", got)
	}
}

// TestF4_ControlModeByte0_NonStandardLayoutRejected verifies that byte 0 uses
// the standard LI(2)|VN(3)|Mode(3) layout, not the old non-standard
// Version(2)|LI(2)|Mode(4) packing from design_ntp.md §2.3 (which placed
// Version in bits 7-6 and was deliberately rejected — see planner.go:508-526).
//
// The old layout hardcoded Version=2, producing byte0 = (2<<6)|(0<<4)|6 = 0x86
// for LI=0, Mode=6 (NOT 0xC6 — that would require Version=4 in the old layout,
// but the old code never used Version=4). The standard layout with the same
// Version=4 produces byte0 = (0<<6)|(4<<3)|6 = 0x26.
//
// The authoritative guard below asserts byte0 == 0x26, which catches any
// regression to the old layout (0x86) or any other non-standard packing.
func TestF4_ControlModeByte0_NonStandardLayoutRejected(t *testing.T) {
	spec := validNTPSpec()
	spec.NTP = &core.NTPConfig{
		Mode:        ModeControl,
		Version:     4,
		Sequence:    1,
		RequestCode: 1,
	}
	cfgs := drain(mustPlan(t, NewPlanner(), spec))
	b0 := cfgs[0].Payload[0]

	// Standard layout: LI(0)<<6 | VN(4)<<3 | Mode(6) = 0x26.
	// Any non-standard packing (old 0x86, or a wrong bit field) fails here.
	if b0 != 0x26 {
		t.Errorf("byte[0] = 0x%02x, want 0x26 (standard LI(2)|VN(3)|Mode(3); "+
			"LI=0, VN=4, Mode=6). Old non-standard Version(2)|LI(2)|Mode(4) "+
			"layout would produce 0x86 (Version=2 hardcoded).", b0)
	}
}
