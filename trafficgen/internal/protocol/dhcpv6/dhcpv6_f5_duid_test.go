package dhcpv6

// F5 regression tests: autoClientDUID with empty SrcMAC.
//
// When ClientDUID is nil (auto mode) and SrcMAC is empty, the auto-generated
// DUID-LLT has an empty LinkLayerAddr. serializeDUID then calls parseMAC("")
// which returns an error, causing the planner to silently emit zero packets
// (the goroutine returns without emitting on the channel).
//
// Fix: Validate returns a clear error when ClientDUID is nil and SrcMAC is
// empty, instead of silently producing zero packets.

import (
	"context"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

// TestF5_AutoClientDUID_EmptySrcMAC_ReturnsError verifies that when
// ClientDUID is nil (auto mode) and SrcMAC is empty, Validate returns a
// clear error instead of silently failing at serialization time.
func TestF5_AutoClientDUID_EmptySrcMAC_ReturnsError(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "2001:db8::1", DstIP: "2001:db8::2",
		SrcMAC: "", // intentionally empty
		DHCPv6: &core.DHCPv6Config{
			Messages: []core.DHCPv6Message{
				{MsgType: MsgTypeSolicit},
			},
			// ClientDUID intentionally nil -> auto mode
		},
	}
	err := p.Validate(spec)
	if err == nil {
		// Even if Validate passes, Plan should not silently emit zero
		// packets. Check Plan too.
		ch, planErr := p.Plan(context.Background(), spec)
		if planErr != nil {
			return // Plan returned an error - acceptable
		}
		cfgs := drain(ch)
		if len(cfgs) == 0 {
			t.Fatalf("Validate returned nil and Plan emitted 0 packets - " +
				"autoClientDUID with empty SrcMAC silently fails (pre-F5 bug); " +
				"expected a Validate error or non-empty output")
		}
		return
	}
	// Validate returned an error - this is the expected fix path.
}

// TestF5_AutoClientDUID_ExplicitSrcMAC_Works verifies that the normal path
// (SrcMAC set, ClientDUID nil -> auto) still works after the guard.
func TestF5_AutoClientDUID_ExplicitSrcMAC_Works(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "2001:db8::1", DstIP: "2001:db8::2",
		SrcMAC: "aa:bb:cc:dd:ee:ff",
		DHCPv6: &core.DHCPv6Config{
			Messages: []core.DHCPv6Message{
				{MsgType: MsgTypeSolicit},
			},
			// ClientDUID nil -> auto mode (should work with SrcMAC set)
		},
	}
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan with explicit SrcMAC should succeed: %v", err)
	}
	cfgs := drain(ch)
	if len(cfgs) == 0 {
		t.Fatalf("expected at least 1 packet with explicit SrcMAC")
	}
}

// TestF5_ExplicitClientDUID_EmptySrcMAC_Works verifies that when the user
// provides an explicit ClientDUID, empty SrcMAC is fine (no auto-generation).
func TestF5_ExplicitClientDUID_EmptySrcMAC_Works(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "2001:db8::1", DstIP: "2001:db8::2",
		SrcMAC: "", // empty, but ClientDUID is explicit
		DHCPv6: &core.DHCPv6Config{
			Messages: []core.DHCPv6Message{
				{MsgType: MsgTypeSolicit},
			},
			ClientDUID: &core.DUID{
				Type:          DUIDTypeEN,
				EnterpriseNum: 1234,
				VendorSpecific: []byte("test"),
			},
		},
	}
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan with explicit ClientDUID should succeed even with empty SrcMAC: %v", err)
	}
	cfgs := drain(ch)
	if len(cfgs) == 0 {
		t.Fatalf("expected at least 1 packet with explicit ClientDUID")
	}
}
