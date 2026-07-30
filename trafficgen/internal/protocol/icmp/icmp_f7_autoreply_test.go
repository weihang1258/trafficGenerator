package icmp

// F7 verification tests: ICMP auto-reply scope.
//
// The finding F7 claimed "auto-reply only triggers on Type=8 (Echo Request).
// Other request types that warrant replies are not handled."
//
// Verification against RFC 792 and the planner's design intent:
//
// RFC 792 defines several request/reply pairs:
//   - Echo Request (8) -> Echo Reply (0): the ping mechanism
//   - Timestamp (13) -> Timestamp Reply (14): obsolete
//   - Information Request (15) -> Information Reply (16): obsolete
//   - Address Mask Request (17) -> Address Mask Reply (18): obsolete
//
// The ICMP planner only defines TypeEchoRequest=8 and TypeEchoReply=0 (line
// 17-18 of icmp.go). The planner's doc comment says "Two emission modes:
// single ping / multi-session ping" - it is explicitly a ping (echo) tool.
// The auto-reply on Type=8 is the ONLY intended auto-reply behavior; other
// request types (Timestamp, etc.) are NOT part of the design scope.
//
// This is BY-DESIGN, not a bug. These tests document the expected behavior
// so future changes don't accidentally break the Echo-only auto-reply
// contract.

import (
	"context"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

// TestF7_EchoRequestTriggersAutoReply verifies that Type=8 (Echo Request)
// triggers an automatic Echo Reply (Type=0). This is the expected, by-design
// behavior.
func TestF7_EchoRequestTriggersAutoReply(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		ICMP: &core.ICMPConfig{
			Type:     TypeEchoRequest, // 8
			Code:     0,
			Sequence: 1,
			Data:     []byte("ping"),
		},
	}
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	cfgs := drain(ch)
	// Expect: 1 Echo Request (up) + 1 Echo Reply (down) = 2 packets
	if len(cfgs) != 2 {
		t.Fatalf("expected 2 packets (request + auto-reply), got %d", len(cfgs))
	}
	if cfgs[0].Direction != "up" {
		t.Errorf("packet[0] direction=%q, want up (request)", cfgs[0].Direction)
	}
	if cfgs[1].Direction != "down" {
		t.Errorf("packet[1] direction=%q, want down (auto-reply)", cfgs[1].Direction)
	}
	// The reply must be Type=0 (Echo Reply)
	replyType, ok := cfgs[1].Metadata["icmp_type"].(uint8)
	if !ok {
		t.Fatalf("packet[1] missing icmp_type metadata")
	}
	if replyType != TypeEchoReply {
		t.Errorf("packet[1] icmp_type=%d, want %d (Echo Reply)", replyType, TypeEchoReply)
	}
}

// TestF7_NonEchoTypeDoesNotTriggerAutoReply verifies that a non-Echo type
// (e.g. Type=0, Echo Reply itself) does NOT trigger an auto-reply. This is
// by-design: only Echo Request (Type=8) gets an auto-reply. Other types are
// emitted as-is without a synthesized reply.
func TestF7_NonEchoTypeDoesNotTriggerAutoReply(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		ICMP: &core.ICMPConfig{
			Type:     TypeEchoReply, // 0 - not a request, no auto-reply
			Code:     0,
			Sequence: 1,
			Data:     []byte("pong"),
		},
	}
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	cfgs := drain(ch)
	// Expect: 1 packet only (the Echo Reply itself, no auto-auto-reply)
	if len(cfgs) != 1 {
		t.Fatalf("expected 1 packet (no auto-reply for Type=0), got %d", len(cfgs))
	}
	if cfgs[0].Direction != "up" {
		t.Errorf("packet[0] direction=%q, want up", cfgs[0].Direction)
	}
}

// TestF7_PatternEchoRequestTriggersAutoReply verifies that in the multi-
// session Pattern path, only Echo Request steps get auto-replies.
func TestF7_PatternEchoRequestTriggersAutoReply(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		ICMP: &core.ICMPConfig{
			Identifier: 0x1234,
			Pattern: []core.ICMPStep{
				{Type: TypeEchoRequest, Code: 0, Sequence: 1}, // -> auto-reply
				{Type: TypeEchoReply, Code: 0, Sequence: 2},   // -> no auto-reply
				{Type: TypeEchoRequest, Code: 0, Sequence: 3}, // -> auto-reply
			},
		},
	}
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	cfgs := drain(ch)
	// 3 steps + 2 auto-replies (steps 1 and 3 are Echo Requests) = 5 packets
	if len(cfgs) != 5 {
		t.Fatalf("expected 5 packets (3 steps + 2 auto-replies), got %d", len(cfgs))
	}
}
