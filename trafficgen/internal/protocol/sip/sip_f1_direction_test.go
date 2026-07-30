package sip

// F1 regression tests: SDP direction attribute (a=sendonly / a=recvonly /
// a=sendrecv) must drive the RTP media direction when the user has not
// set SIPMedia.Direction explicitly.
//
// Per RFC 4566 §6.4.1 + RFC 3264 §5.1, the SDP media attribute
// "a=sendonly" means the offerer SENDS media (RTP flows offerer→answerer,
// i.e. "up" when the offerer is the caller). "a=recvonly" means the
// offerer only RECEIVES (RTP flows answerer→offerer, i.e. "down").
// "a=sendrecv" (or no attribute) is bidirectional; a single SIPMedia
// invocation models one direction, defaulting to "up".
//
// Pre-fix: emitSIPMedia always defaulted media.Direction to "up" without
// consulting the SDP body's a= direction attribute, so an INVITE
// advertising "a=recvonly" still emitted caller→callee RTP — the
// direction was silently lost.

import (
	"context"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

// sdpDirectionSpec returns a spec whose INVITE body carries the given SDP
// direction attribute. media.Direction is left EMPTY so the planner must
// derive the RTP direction from the SDP body.
func sdpDirectionSpec(sdpAttr string) core.FlowSpec {
	inviteBody := "v=0\r\no=SIP-UA 1200 3400 IN IP4 10.0.0.1\r\ns=call\r\nc=IN IP4 10.0.0.1\r\nt=0 0\r\nm=audio 10000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n"
	if sdpAttr != "" {
		inviteBody += sdpAttr + "\r\n"
	}
	return core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 54100, DstPort: 5060,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		SIP: &core.SIPConfig{
			Dialog: []core.SIPMessage{
				{Method: "INVITE", URI: "sip:callee@example.com", Direction: "up", Body: inviteBody},
				{StatusCode: 200, StatusText: "OK", Direction: "down"},
				{Method: "ACK", URI: "sip:callee@example.com", Direction: "up", EmitMedia: true},
				{Method: "BYE", URI: "sip:callee@example.com", Direction: "up"},
				{StatusCode: 200, StatusText: "OK", Direction: "down"},
			},
			Media: &core.SIPMedia{
				Frames:     3,
				PayloadType: 0,
				FrameSize:  160,
				// Direction intentionally left empty — must be derived
				// from the SDP a= attribute.
			},
		},
	}
}

// TestF1_SDPSendonly_DerivesUp verifies that an INVITE SDP body with
// "a=sendonly" causes the RTP sub-flow to flow "up" (caller→callee),
// because the caller is the sender.
func TestF1_SDPSendonly_DerivesUp(t *testing.T) {
	spec := sdpDirectionSpec("a=sendonly")
	ch, err := NewPlanner().Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	cfgs := drain(ch)
	rtp := findRTPPackets(cfgs)
	if len(rtp) == 0 {
		t.Fatalf("no RTP packets emitted")
	}
	for i, c := range rtp {
		if c.Direction != "up" {
			t.Errorf("rtp[%d].Direction=%q, want \"up\" (a=sendonly → caller sends → up)", i, c.Direction)
		}
	}
}

// TestF1_SDPRecvonly_DerivesDown verifies that an INVITE SDP body with
// "a=recvonly" causes the RTP sub-flow to flow "down" (callee→caller),
// because the caller only receives — the callee is the sender.
func TestF1_SDPRecvonly_DerivesDown(t *testing.T) {
	spec := sdpDirectionSpec("a=recvonly")
	ch, err := NewPlanner().Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	cfgs := drain(ch)
	rtp := findRTPPackets(cfgs)
	if len(rtp) == 0 {
		t.Fatalf("no RTP packets emitted")
	}
	for i, c := range rtp {
		if c.Direction != "down" {
			t.Errorf("rtp[%d].Direction=%q, want \"down\" (a=recvonly → caller receives → callee sends → down)", i, c.Direction)
		}
		// Under "down" the IP path is reversed: server→client.
		if c.L3.SrcIP != spec.DstIP {
			t.Errorf("rtp[%d] L3.SrcIP=%q, want %q (server IP under down)", i, c.L3.SrcIP, spec.DstIP)
		}
	}
}

// TestF1_SDPSendrecv_DerivesUp verifies that "a=sendrecv" (bidirectional)
// defaults to "up" since one SIPMedia models one direction.
func TestF1_SDPSendrecv_DerivesUp(t *testing.T) {
	spec := sdpDirectionSpec("a=sendrecv")
	ch, err := NewPlanner().Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	cfgs := drain(ch)
	rtp := findRTPPackets(cfgs)
	if len(rtp) == 0 {
		t.Fatalf("no RTP packets emitted")
	}
	for i, c := range rtp {
		if c.Direction != "up" {
			t.Errorf("rtp[%d].Direction=%q, want \"up\" (a=sendrecv defaults to up)", i, c.Direction)
		}
	}
}

// TestF1_UserDirectionOverridesSDP verifies that an explicit
// media.Direction wins over the SDP a= attribute. The user is the final
// authority — the SDP parse is only a default when media.Direction is
// empty.
func TestF1_UserDirectionOverridesSDP(t *testing.T) {
	spec := sdpDirectionSpec("a=recvonly") // SDP says "down"
	spec.SIP.Media.Direction = "up"        // user overrides to "up"
	ch, err := NewPlanner().Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	cfgs := drain(ch)
	rtp := findRTPPackets(cfgs)
	if len(rtp) == 0 {
		t.Fatalf("no RTP packets emitted")
	}
	for i, c := range rtp {
		if !strings.EqualFold(c.Direction, "up") {
			t.Errorf("rtp[%d].Direction=%q, want \"up\" (user override beats SDP a=recvonly)", i, c.Direction)
		}
	}
}

// TestF1_200OK_AnswererBodyNotScanned locks in the contract that only the
// INVITE/ACK offerer-side SDP body drives the derived RTP direction. The
// 200-OK answerer body is intentionally NOT scanned, because per RFC 3264
// §6.1 the answerer may flip the direction attribute, and blindly honoring
// it would require full offer/answer correlation the planner does not do.
//
// Setup: INVITE body carries "a=sendonly" (offerer sends → "up"). The 200-OK
// answerer body carries "a=recvonly" (the OPPOSITE direction). If the planner
// wrongly scanned the 200-OK body, the last-scanned attribute ("recvonly")
// would win and RTP would flow "down". The correct behavior is "up" (from the
// INVITE offerer).
func TestF1_200OK_AnswererBodyNotScanned(t *testing.T) {
	spec := sdpDirectionSpec("a=sendonly") // INVITE offerer: sendonly → up
	// Inject a 200-OK answerer body with the OPPOSITE direction attribute.
	// scanSDPDirection must skip this (Method != INVITE/ACK).
	for i := range spec.SIP.Dialog {
		if spec.SIP.Dialog[i].StatusCode == 200 {
			spec.SIP.Dialog[i].Body = "v=0\r\nm=audio 10010 RTP/AVP 0\r\na=recvonly\r\n"
			break
		}
	}
	ch, err := NewPlanner().Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	cfgs := drain(ch)
	rtp := findRTPPackets(cfgs)
	if len(rtp) == 0 {
		t.Fatalf("no RTP packets emitted")
	}
	for i, c := range rtp {
		if c.Direction != "up" {
			t.Errorf("rtp[%d].Direction=%q, want \"up\" — 200-OK answerer body "+
				"a=recvonly must NOT override the INVITE offerer a=sendonly "+
				"(answerer body is not scanned per RFC 3264 §6.1)", i, c.Direction)
		}
	}
}
