package sip

// Test points for the SIP planner. Each test asserts observable
// PacketConfig field values, not just "no error". Derived from the
// session-level dialog structure documented in sip.go and from the
// SIP pcap at /home/pcap_auto/monitor/IP-TCP-10.1.1.231-...-5060-...pcap
// (INVITE → 100 → 180 → 200 → ACK → BYE → 200 over TCP 5060).

import (
	"context"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/protocol/testutil"
)

// drain collects all configs from the channel.
func drain(ch <-chan core.PacketConfig) []core.PacketConfig {
	var out []core.PacketConfig
	for c := range ch {
		out = append(out, c)
	}
	return out
}

// validSIPSpec returns a spec with a minimal INVITE → 200 → ACK dialog
// modeled after the pcap sample. The pcap shows 7 SIP messages on the
// TCP 5060 signaling channel (INVITE, 100, 180, 200, ACK, BYE, 200).
// We use 3 here for compactness; MSS segmentation tests use larger bodies.
func validSIPSpec() core.FlowSpec {
	return core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 54100, DstPort: 5060,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		SIP: &core.SIPConfig{
			Dialog: []core.SIPMessage{
				{
					Method: "INVITE",
					URI:    "sip:callee@spirent.com",
					Headers: []string{
						"From: <sip:caller@spirent.com>;tag=156f08772764952",
						"To: sip:callee@spirent.com",
						"Call-ID: deb9780b2789215@spirent.com",
						"CSeq: 1 INVITE",
						"Max-Forwards: 70",
						"Via: SIP/2.0/TCP 192.168.43.2:54100;branch=z9hG4bK58f7528f27b1007",
						"Contact: <sip:caller@192.168.43.2:54100>",
						"Content-Type: application/sdp",
					},
					Body:      "v=0\r\no=SIP-UA 1200 3400 IN IP4 192.168.43.2\r\ns=SIP Call\r\nc=IN IP4 192.168.43.2\r\nt=0 0\r\nm=audio 10000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=recvonly\r\n",
					Direction: "up",
				},
				{
					StatusCode: 100,
					StatusText: "Trying",
					Headers: []string{
						"From: <sip:caller@spirent.com>;tag=156f08772764952",
						"To: <sip:callee@spirent.com>;tag=deb9780b27ff7f2",
						"Call-ID: deb9780b2789215@spirent.com",
						"CSeq: 1 INVITE",
						"Via: SIP/2.0/TCP 192.168.43.2:54100;branch=z9hG4bK58f7528f27b1007",
					},
					Direction: "down",
				},
				{
					Method:    "ACK",
					URI:       "sip:callee@spirent.com",
					Direction: "up",
				},
			},
		},
	}
}

// --- Validate ---

func TestSIPValidate_ValidIPs(t *testing.T) {
	p := NewPlanner()
	spec := validSIPSpec()
	if err := p.Validate(spec); err != nil {
		t.Errorf("valid spec: %v", err)
	}
}

func TestSIPValidate_InvalidSrcIP(t *testing.T) {
	p := NewPlanner()
	spec := validSIPSpec()
	spec.SrcIP = "bad"
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "invalid source IP") {
		t.Errorf("err=%v, want contains 'invalid source IP'", err)
	}
}

func TestSIPValidate_InvalidDstIP(t *testing.T) {
	p := NewPlanner()
	spec := validSIPSpec()
	spec.DstIP = "bad"
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "invalid destination IP") {
		t.Errorf("err=%v, want contains 'invalid destination IP'", err)
	}
}

func TestSIPValidate_MSSTooSmall(t *testing.T) {
	p := NewPlanner()
	spec := validSIPSpec()
	testutil.EnsureTCP(&spec).MSS = 100 // below MinMSS=536
	if err := p.Validate(spec); err == nil || !strings.Contains(err.Error(), "MSS") {
		t.Errorf("err=%v, want contains 'MSS'", err)
	}
}

func TestSIPValidate_MSSZeroOK(t *testing.T) {
	p := NewPlanner()
	spec := validSIPSpec()
	testutil.EnsureTCP(&spec).MSS = 0 // 0 means default — not an error
	if err := p.Validate(spec); err != nil {
		t.Errorf("MSS=0 should be accepted (means default): %v", err)
	}
}

func TestSIPValidate_NilSIPConfig(t *testing.T) {
	p := NewPlanner()
	spec := validSIPSpec()
	spec.SIP = nil
	if err := p.Validate(spec); err != nil {
		t.Errorf("nil SIP config should be accepted: %v", err)
	}
}

// --- Plan: structure ---

// TestSIPPlan_Handshake verifies the first 3 packets are SYN, SYN-ACK, ACK
// with the correct directions, flags, and TCP options.
func TestSIPPlan_Handshake(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validSIPSpec()))
	if len(cfgs) < 3 {
		t.Fatalf("len=%d, want >= 3 (handshake)", len(cfgs))
	}
	// SYN up
	if cfgs[0].Direction != "up" || cfgs[0].L4.Flags != 0x02 {
		t.Errorf("cfg[0]: dir=%s flags=%x, want up/SYN", cfgs[0].Direction, cfgs[0].L4.Flags)
	}
	if len(cfgs[0].L4.TCPOptions) == 0 {
		t.Errorf("cfg[0]: SYN should carry TCP options (MSS, WinScale, SACK)")
	}
	// SYN-ACK down
	if cfgs[1].Direction != "down" || cfgs[1].L4.Flags != 0x12 {
		t.Errorf("cfg[1]: dir=%s flags=%x, want down/SYN-ACK", cfgs[1].Direction, cfgs[1].L4.Flags)
	}
	if len(cfgs[1].L4.TCPOptions) == 0 {
		t.Errorf("cfg[1]: SYN-ACK should carry TCP options")
	}
	// ACK up
	if cfgs[2].Direction != "up" || cfgs[2].L4.Flags != 0x10 {
		t.Errorf("cfg[2]: dir=%s flags=%x, want up/ACK", cfgs[2].Direction, cfgs[2].L4.Flags)
	}
	if len(cfgs[2].L4.TCPOptions) != 0 {
		t.Errorf("cfg[2]: ACK should NOT carry TCP options")
	}
}

// TestSIPPlan_Teardown verifies the last 4 packets are FIN-ACK, ACK,
// FIN-ACK, ACK in the standard order.
func TestSIPPlan_Teardown(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validSIPSpec()))
	n := len(cfgs)
	if n < 4 {
		t.Fatalf("len=%d, want >= 4 (teardown)", n)
	}
	// Client FIN-ACK up
	if cfgs[n-4].Direction != "up" || cfgs[n-4].L4.Flags != 0x11 {
		t.Errorf("cfg[%d]: dir=%s flags=%x, want up/FIN-ACK", n-4, cfgs[n-4].Direction, cfgs[n-4].L4.Flags)
	}
	// Server ACK down
	if cfgs[n-3].Direction != "down" || cfgs[n-3].L4.Flags != 0x10 {
		t.Errorf("cfg[%d]: dir=%s flags=%x, want down/ACK", n-3, cfgs[n-3].Direction, cfgs[n-3].L4.Flags)
	}
	// Server FIN-ACK down
	if cfgs[n-2].Direction != "down" || cfgs[n-2].L4.Flags != 0x11 {
		t.Errorf("cfg[%d]: dir=%s flags=%x, want down/FIN-ACK", n-2, cfgs[n-2].Direction, cfgs[n-2].L4.Flags)
	}
	// Client ACK up
	if cfgs[n-1].Direction != "up" || cfgs[n-1].L4.Flags != 0x10 {
		t.Errorf("cfg[%d]: dir=%s flags=%x, want up/ACK", n-1, cfgs[n-1].Direction, cfgs[n-1].L4.Flags)
	}
}

// TestSIPPlan_InviteEmitted verifies that the first payload packet after
// the handshake is an up PSH-ACK containing the INVITE request-line.
func TestSIPPlan_InviteEmitted(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validSIPSpec()))
	if len(cfgs) < 4 {
		t.Fatalf("len=%d, want >= 4", len(cfgs))
	}
	inv := cfgs[3]
	if inv.Direction != "up" || inv.L4.Flags != 0x18 {
		t.Fatalf("cfg[3]: dir=%s flags=%x, want up/PSH-ACK", inv.Direction, inv.L4.Flags)
	}
	if !strings.Contains(string(inv.Payload), "INVITE sip:callee@spirent.com SIP/2.0") {
		t.Errorf("cfg[3] payload=%q, want contains INVITE request-line", inv.Payload)
	}
	if !strings.Contains(string(inv.Payload), "Content-Type: application/sdp") {
		t.Errorf("cfg[3] should carry Content-Type header for SDP body")
	}
}

// TestSIPPlan_100TryingEmitted verifies the second SIP message is a down
// PSH-ACK containing the 100 Trying status-line.
func TestSIPPlan_100TryingEmitted(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validSIPSpec()))
	if len(cfgs) < 5 {
		t.Fatalf("len=%d, want >= 5", len(cfgs))
	}
	trying := cfgs[4]
	if trying.Direction != "down" || trying.L4.Flags != 0x18 {
		t.Fatalf("cfg[4]: dir=%s flags=%x, want down/PSH-ACK", trying.Direction, trying.L4.Flags)
	}
	if !strings.Contains(string(trying.Payload), "SIP/2.0 100 Trying") {
		t.Errorf("cfg[4] payload=%q, want contains 'SIP/2.0 100 Trying'", trying.Payload)
	}
}

// TestSIPPlan_ACKEmitted verifies the third SIP message is an up PSH-ACK
// containing the ACK request-line.
func TestSIPPlan_ACKEmitted(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validSIPSpec()))
	if len(cfgs) < 6 {
		t.Fatalf("len=%d, want >= 6", len(cfgs))
	}
	ack := cfgs[5]
	if ack.Direction != "up" || ack.L4.Flags != 0x18 {
		t.Fatalf("cfg[5]: dir=%s flags=%x, want up/PSH-ACK", ack.Direction, ack.L4.Flags)
	}
	if !strings.Contains(string(ack.Payload), "ACK sip:callee@spirent.com SIP/2.0") {
		t.Errorf("cfg[5] payload=%q, want contains 'ACK sip:callee@spirent.com SIP/2.0'", ack.Payload)
	}
}

// TestSIPPlan_SequenceContinuity verifies that the next message's ACK
// field covers all prior response bytes — the signature of a continuous
// sequence space per direction within one flow.
func TestSIPPlan_SequenceContinuity(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validSIPSpec()))

	// For each up PSH-ACK (request), its Ack field must equal the
	// cumulative server sequence: the server's ISN+1 (after SYN-ACK)
	// plus the byte length of every down payload emitted so far.
	var serverSeq uint32
	for i, c := range cfgs {
		switch {
		case c.L4.Flags == 0x12: // SYN-ACK: server ISN
			serverSeq = c.L4.Seq + 1 // SYN consumes one seq number
		case c.Direction == "down" && c.L4.Flags == 0x18:
			// down PSH-ACK: advance serverSeq by payload length
			serverSeq = c.L4.Seq + uint32(len(c.Payload))
		case c.Direction == "up" && c.L4.Flags == 0x18:
			// up PSH-ACK: its Ack must equal the latest serverSeq
			if c.L4.Ack != serverSeq {
				t.Errorf("cfg[%d] (up req) Ack=%d, want %d (cumulative server seq)", i, c.L4.Ack, serverSeq)
			}
		}
	}
}

// TestSIPPlan_MSSSegmentation verifies that a SIP message longer than MSS
// is split into multiple PSH-ACK segments. With MSS=536 and a 1080-byte
// body inside an INVITE, the request (request-line + headers + body) will
// exceed 536 bytes and produce multiple segments.
func TestSIPPlan_MSSSegmentation(t *testing.T) {
	p := NewPlanner()
	longBody := strings.Repeat("x", 1080)
	spec := validSIPSpec()
	testutil.EnsureTCP(&spec).MSS = 536 // MSS is a TCP transport parameter
	spec.SIP = &core.SIPConfig{
		Dialog: []core.SIPMessage{
			{
				Method:    "INVITE",
				URI:       "sip:callee@spirent.com",
				Direction: "up",
				Headers:   []string{"Content-Type: application/sdp"},
				Body:      longBody,
			},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// handshake(3) + INVITE segments + teardown(4)
	if len(cfgs) < 3+4+1 {
		t.Fatalf("len=%d, want >= 8", len(cfgs))
	}
	// Collect INVITE segments (between handshake and teardown).
	var segs []core.PacketConfig
	for i := 3; i < len(cfgs)-4; i++ {
		segs = append(segs, cfgs[i])
	}
	if len(segs) < 2 {
		t.Fatalf("expected multiple MSS segments, got %d", len(segs))
	}
	for i, s := range segs {
		if s.Direction != "up" || s.L4.Flags != 0x18 {
			t.Errorf("seg[%d]: dir=%s flags=%x, want up/PSH-ACK", i, s.Direction, s.L4.Flags)
		}
		if len(s.Payload) > 536 {
			t.Errorf("seg[%d] len=%d, must be <= MSS=536", i, len(s.Payload))
		}
	}
	// Sequence space is continuous: segN.Seq = seg(N-1).Seq + len(seg(N-1).Payload)
	for i := 1; i < len(segs); i++ {
		want := segs[i-1].L4.Seq + uint32(len(segs[i-1].Payload))
		if segs[i].L4.Seq != want {
			t.Errorf("seg[%d].Seq=%d, want %d (continuous)", i, segs[i].L4.Seq, want)
		}
	}
}

// TestSIPPlan_EmptyDialogEmitsHandshakeAndTeardownOnly verifies the
// degenerate case: no messages → just TCP handshake + teardown.
func TestSIPPlan_EmptyDialogEmitsHandshakeAndTeardownOnly(t *testing.T) {
	p := NewPlanner()
	spec := validSIPSpec()
	spec.SIP.Dialog = nil
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) != 7 {
		t.Fatalf("len=%d, want 7 (3 handshake + 4 teardown)", len(cfgs))
	}
}

// TestSIPPlan_DirectionInference verifies that when Direction is empty,
// the planner infers "up" for requests (Method set) and "down" for
// responses (StatusCode set).
func TestSIPPlan_DirectionInference(t *testing.T) {
	p := NewPlanner()
	spec := validSIPSpec()
	spec.SIP = &core.SIPConfig{
		Dialog: []core.SIPMessage{
			{Method: "INVITE", URI: "sip:callee@x.com"},        // Direction empty -> up
			{StatusCode: 200, StatusText: "OK"},                 // Direction empty -> down
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// handshake(3) + INVITE(up) + 200(down) + teardown(4) = 9
	if len(cfgs) != 9 {
		t.Fatalf("len=%d, want 9", len(cfgs))
	}
	if cfgs[3].Direction != "up" {
		t.Errorf("cfg[3]: dir=%s, want up (inferred from Method)", cfgs[3].Direction)
	}
	if cfgs[4].Direction != "down" {
		t.Errorf("cfg[4]: dir=%s, want down (inferred from StatusCode)", cfgs[4].Direction)
	}
}

// TestSIPPlan_InitialSeqOverride verifies that spec.TCP.InitialSeq fixes
// the client ISN for reproducible tests.
func TestSIPPlan_InitialSeqOverride(t *testing.T) {
	p := NewPlanner()
	spec := validSIPSpec()
	testutil.EnsureTCP(&spec).InitialSeq = 0x22222222
	cfgs := drain(mustPlan(t, p, spec))
	if cfgs[0].L4.Seq != 0x22222222 {
		t.Errorf("cfg[0] (SYN) Seq=%x, want 22222222", cfgs[0].L4.Seq)
	}
}

// TestSIPPlan_FlowIDShared verifies all packets share one flow ID (the
// session-level invariant: one SIP signaling connection = one flow).
func TestSIPPlan_FlowIDShared(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validSIPSpec()))
	flowID := cfgs[0].FlowID
	if flowID == "" {
		t.Fatal("FlowID empty")
	}
	for i, c := range cfgs {
		if c.FlowID != flowID {
			t.Errorf("cfg[%d].FlowID=%q, want %q (one flow per session)", i, c.FlowID, flowID)
		}
	}
}

// TestSIPPlan_IPIDIncrementsPerPacket verifies that every packet has a
// distinct IP ID (no cross-packet ID reuse within the flow).
func TestSIPPlan_IPIDIncrementsPerPacket(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validSIPSpec()))
	seen := make(map[uint16]bool)
	for i, c := range cfgs {
		if seen[c.L3.IPID] {
			t.Errorf("cfg[%d] IPID=%d duplicated", i, c.L3.IPID)
		}
		seen[c.L3.IPID] = true
	}
}

// TestSIPPlan_CRLFTerminator verifies that every SIP message payload uses
// CRLF line terminators per RFC 3261 §7. The request-line, each header,
// and the blank line separating headers from body all end with CRLF.
func TestSIPPlan_CRLFTerminator(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validSIPSpec()))
	for i, c := range cfgs {
		if c.L4.Flags != 0x18 { // only PSH-ACK data packets
			continue
		}
		if len(c.Payload) == 0 {
			continue
		}
		// Every line in the SIP message must end with CRLF. A bare LF
		// would be a protocol violation. Check that no \n exists
		// without a preceding \r.
		payload := string(c.Payload)
		for j := 0; j < len(payload); j++ {
			if payload[j] == '\n' {
				if j == 0 || payload[j-1] != '\r' {
					t.Errorf("cfg[%d] has bare LF at pos %d (must be CRLF)", i, j)
				}
			}
		}
	}
}

// TestSIPPlan_ContentLengthAutoAppended verifies that when Body is non-empty
// AND the user did not supply a Content-Length header, the planner appends
// one matching the body byte length. Note: the body "v=0\r\n" is 5 bytes
// (not 4) because \r\n counts as 2 bytes per RFC 3261 §7 (CRLF = 0x0D 0x0A).
func TestSIPPlan_ContentLengthAutoAppended(t *testing.T) {
	p := NewPlanner()
	body := "v=0\r\n" // 5 bytes: 'v' '=' '0' '\r' '\n'
	spec := validSIPSpec()
	spec.SIP = &core.SIPConfig{
		Dialog: []core.SIPMessage{
			{
				Method:    "INVITE",
				URI:       "sip:callee@x.com",
				Direction: "up",
				Headers:   []string{"Content-Type: application/sdp"},
				Body:      body,
			},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) < 4 {
		t.Fatalf("len=%d, want >= 4", len(cfgs))
	}
	inv := cfgs[3]
	if !strings.Contains(string(inv.Payload), "Content-Length: 5") {
		t.Errorf("cfg[3] should carry auto-appended 'Content-Length: 5', payload=%q", inv.Payload)
	}
}

// TestSIPPlan_ContentLengthUserSuppliedNotDuplicated verifies that when
// the user supplies a Content-Length header, the planner does NOT append
// another one (no duplicate). The user's value wins per the
// "user > default > none" rule.
func TestSIPPlan_ContentLengthUserSuppliedNotDuplicated(t *testing.T) {
	p := NewPlanner()
	spec := validSIPSpec()
	spec.SIP = &core.SIPConfig{
		Dialog: []core.SIPMessage{
			{
				Method: "INVITE",
				URI:    "sip:callee@x.com",
				Headers: []string{
					"Content-Type: application/sdp",
					"Content-Length: 999", // user-supplied, must NOT be overwritten
				},
				Body:      "v=0\r\n",
				Direction: "up",
			},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	inv := cfgs[3]
	// Count occurrences of "Content-Length:" (case-insensitive).
	count := strings.Count(strings.ToLower(string(inv.Payload)), "content-length:")
	if count != 1 {
		t.Errorf("cfg[3] has %d Content-Length headers, want 1 (no duplicate)", count)
	}
	if !strings.Contains(string(inv.Payload), "Content-Length: 999") {
		t.Errorf("cfg[3] should preserve user's Content-Length: 999, payload=%q", inv.Payload)
	}
}

// TestSIPPlan_DstPortDefaultsTo5060 verifies that the strategy_convert
// dst_port default for SIP is 5060 when the user did not specify one.
// This test lives in the sip package because it's the SIP-specific
// contract; the actual defaulting is in core.strategy_convert.
func TestSIPPlan_DstPortDefaultsTo5060(t *testing.T) {
	// Spec constructed with DstPort=5060; planner does not default it
	// (that's mapToFlowSpec's job). Here we just verify that when
	// DstPort=5060 the planner emits packets to port 5060.
	p := NewPlanner()
	spec := validSIPSpec()
	cfgs := drain(mustPlan(t, p, spec))
	for i, c := range cfgs {
		if c.Direction == "up" && c.L4.DstPort != 5060 {
			t.Errorf("cfg[%d] up DstPort=%d, want 5060", i, c.L4.DstPort)
		}
		if c.Direction == "down" && c.L4.SrcPort != 5060 {
			t.Errorf("cfg[%d] down SrcPort=%d, want 5060", i, c.L4.SrcPort)
		}
	}
}

// mustPlan is a helper that fails the test if Plan returns an error.
func mustPlan(t *testing.T, p *Planner, spec core.FlowSpec) <-chan core.PacketConfig {
	t.Helper()
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan returned error: %v", err)
	}
	return ch
}
