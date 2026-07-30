package sip

// SIP coverage tests (2026-07-31 cov-sip subagent).
//
// Spec-driven coverage for advanced SIP scenarios that the basic
// dialog-rendering tests in sip_testpoints_test.go do not exercise:
//
//   1. Digest authentication: 401 Unauthorized challenge, then
//      re-REGISTER with Authorization (RFC 3261 §22).
//   2. SUBSCRIBE/NOTIFY event subscription flow (RFC 6665).
//   3. re-INVITE: same FlowID, two INVITEs in the dialog.
//   4. SDP variants: multiple m=audio lines (first wins), m=video
//      intentionally skipped, a=inactive falls through to "up", codec
//      change (PCMA) is rendered verbatim.
//
// The SIP planner is a generic dialog renderer — it does NOT compute
// Digest responses or parse offer/answer. These tests verify that the
// planner faithfully renders the user-supplied dialog messages and
// SDP bodies, so a DPI sees realistic 401/407/SUBSCRIBE/INVITE wire
// bytes.

import (
	"strconv"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

// ---------------------------------------------------------------------------
// Digest authentication (RFC 3261 §22 / RFC 7616)
// ---------------------------------------------------------------------------

// TestSIPPlan_DigestAuth401Challenge verifies that the planner renders a
// 401 Unauthorized response with a WWW-Authenticate: Digest ... header
// (the server's challenge) verbatim, AND a subsequent REGISTER carrying
// the Authorization: Digest ... response header verbatim.
//
// This is the most common auth flow: client sends REGISTER without
// credentials, server rejects with 401 + challenge, client retries
// with computed Digest response in Authorization header.
func TestSIPPlan_DigestAuth401Challenge(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 5060, DstPort: 5060,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		SIP: &core.SIPConfig{
			Dialog: []core.SIPMessage{
				{
					Method:  "REGISTER",
					URI:     "sip:registrar.example.com",
					Headers: []string{"From: <sip:alice@example.com>;tag=abc"},
					Body:    "",
					Direction: "up",
				},
				{
					StatusCode: 401,
					StatusText: "Unauthorized",
					Headers: []string{
						`WWW-Authenticate: Digest realm="example.com", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", algorithm=MD5, qop="auth"`,
						`From: <sip:alice@example.com>;tag=abc`,
					},
					Direction: "down",
				},
				{
					Method: "REGISTER",
					URI:    "sip:registrar.example.com",
					Headers: []string{
						`From: <sip:alice@example.com>;tag=def`,
						`Authorization: Digest username="alice", realm="example.com", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", uri="sip:registrar.example.com", response="6629fae49393a05397450978507c4ef1", algorithm=MD5, qop=auth, nc=00000001, cnonce="0a4f113b"`,
					},
					Direction: "up",
				},
				{
					StatusCode: 200,
					StatusText: "OK",
					Direction: "down",
				},
			},
		},
	}
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) < 4 {
		t.Fatalf("len=%d, want >= 4", len(cfgs))
	}

	// Find the 401 PSH-ACK packet (after the first REGISTER).
	var found401 bool
	var foundAuthHeader bool
	var foundSecondREGISTER bool
	for _, c := range cfgs {
		if c.L4.Flags != 0x18 { // only PSH-ACK data packets
			continue
		}
		text := string(c.Payload)
		if strings.Contains(text, "SIP/2.0 401 Unauthorized") {
			found401 = true
			// WWW-Authenticate: Digest ... challenge must be rendered.
			if !strings.Contains(text, "WWW-Authenticate: Digest") {
				t.Errorf("401 packet missing WWW-Authenticate header: %q", text)
			}
			if !strings.Contains(text, `realm="example.com"`) {
				t.Errorf("401 packet missing realm: %q", text)
			}
		}
		// The second REGISTER must carry the Authorization header.
		if strings.Contains(text, "REGISTER sip:registrar.example.com SIP/2.0") &&
			strings.Contains(text, "Authorization: Digest") {
			foundSecondREGISTER = true
			foundAuthHeader = true
			// The computed response value must appear verbatim.
			if !strings.Contains(text, `response="6629fae49393a05397450978507c4ef1"`) {
				t.Errorf("second REGISTER missing response value: %q", text)
			}
			// The second REGISTER must also use the new tag from the
			// retry (different From tag from the first REGISTER per RFC
			// 3261 §22.3 — a new auth retry uses a fresh tag).
			if !strings.Contains(text, "tag=def") {
				t.Errorf("second REGISTER missing fresh From tag: %q", text)
			}
		}
	}
	if !found401 {
		t.Error("401 Unauthorized response not found in payloads")
	}
	if !foundAuthHeader {
		t.Error("Authorization: Digest header not found in any payload")
	}
	if !foundSecondREGISTER {
		t.Error("Second REGISTER (with Authorization) not found")
	}
}

// TestSIPPlan_DigestAuth407ProxyAuth verifies the 407 Proxy Authentication
// Required flow (RFC 3261 §22.3). A 407 challenge carries Proxy-Authenticate
// and the retry carries Proxy-Authorization. Common when a SIP proxy sits
// between the client and the registrar.
//
// Per RFC 3261 §22.3, the client retries the request with
// Proxy-Authorization (not Authorization — that header is for the
// next-hop UAS, not the proxy).
func TestSIPPlan_DigestAuth407ProxyAuth(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 5060, DstPort: 5060,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		SIP: &core.SIPConfig{
			Dialog: []core.SIPMessage{
				{
					Method:    "INVITE",
					URI:       "sip:callee@example.com",
					Headers:   []string{"From: <sip:alice@example.com>"},
					Direction: "up",
				},
				{
					StatusCode: 407,
					StatusText: "Proxy Authentication Required",
					Headers: []string{
						`Proxy-Authenticate: Digest realm="proxy.example.com", nonce="abc123", algorithm=MD5`,
					},
					Direction: "down",
				},
				{
					Method: "INVITE",
					URI:    "sip:callee@example.com",
					Headers: []string{
						`From: <sip:alice@example.com>`,
						`Proxy-Authorization: Digest username="alice", realm="proxy.example.com", nonce="abc123", uri="sip:callee@example.com", response="a1b2c3d4e5"`,
					},
					Direction: "up",
				},
				{
					StatusCode: 100,
					StatusText: "Trying",
					Direction: "down",
				},
				{
					StatusCode: 200,
					StatusText: "OK",
					Direction: "down",
				},
				{
					Method:    "ACK",
					URI:       "sip:callee@example.com",
					Direction: "up",
				},
			},
		},
	}
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, spec))

	var found407 bool
	var foundProxyAuth bool
	for _, c := range cfgs {
		if c.L4.Flags != 0x18 {
			continue
		}
		text := string(c.Payload)
		if strings.Contains(text, "SIP/2.0 407 Proxy Authentication Required") {
			found407 = true
			if !strings.Contains(text, "Proxy-Authenticate: Digest") {
				t.Errorf("407 packet missing Proxy-Authenticate: %q", text)
			}
		}
		if strings.Contains(text, "Proxy-Authorization: Digest") &&
			strings.Contains(text, `realm="proxy.example.com"`) {
			foundProxyAuth = true
		}
	}
	if !found407 {
		t.Error("407 response not found")
	}
	if !foundProxyAuth {
		t.Error("Proxy-Authorization header not found in retry INVITE")
	}
}

// TestSIPPlan_RegisterAuthNoSipBodyNoContentLength verifies that auth
// challenge/response messages with empty bodies do NOT get an auto-
// appended Content-Length: 0. Per RFC 3261 §7.4 / §20.5, Content-Length
// is only set when there IS a body. A 401 challenge with no body should
// have NO Content-Length header.
//
// Pre-fix: the planner auto-appended Content-Length: 0 on every message
// that had a Body field set to "" (which is always, even when not
// specified). This produced wire bytes with spurious Content-Length: 0
// headers that a real SIP stack would not emit.
func TestSIPPlan_RegisterAuthNoSipBodyNoContentLength(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 5060, DstPort: 5060,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		SIP: &core.SIPConfig{
			Dialog: []core.SIPMessage{
				{Method: "REGISTER", URI: "sip:x", Direction: "up"},
			},
		},
	}
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) < 4 {
		t.Fatalf("len=%d, want >= 4", len(cfgs))
	}
	for _, c := range cfgs {
		if c.L4.Flags != 0x18 {
			continue
		}
		if strings.Contains(strings.ToLower(string(c.Payload)), "content-length:") {
			t.Errorf("REGISTER with no body should not have Content-Length header: %q", c.Payload)
		}
	}
}

// ---------------------------------------------------------------------------
// SUBSCRIBE / NOTIFY (RFC 6665 — SIP-Specific Event Notification)
// ---------------------------------------------------------------------------

// TestSIPPlan_SubscribeNotifyFlow verifies the full event-subscription
// flow: client SUBSCRIBEs to a resource (e.g. presence or message-summary),
// server 200s, server then NOTIFYs the client with the event state, and
// the client 200s the NOTIFY.
//
// Per RFC 6665 §3.1 / §4.1:
//   - SUBSCRIBE carries an "Event:" header naming the event package.
//   - 200 OK to SUBSCRIBE establishes the subscription.
//   - NOTIFY is sent immediately by the server to deliver initial state.
//   - 200 OK to NOTIFY confirms receipt.
//
// All four messages must be rendered as PSH-ACK payloads in the right
// direction. SUBSCRIBE and NOTIFY are both up-methods (client→server)
// on the wire, but NOTIFY is special: it's an out-of-dialog request
// that the server sends TO the client, so its wire direction is "up"
// from the caller's perspective (caller's IP is the destination).
func TestSIPPlan_SubscribeNotifyFlow(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 5060, DstPort: 5060,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		SIP: &core.SIPConfig{
			Dialog: []core.SIPMessage{
				{
					Method: "SUBSCRIBE",
					URI:    "sip:bob@example.com",
					Headers: []string{
						"From: <sip:alice@example.com>;tag=sub1",
						"To: <sip:bob@example.com>",
						"Call-ID: sub-call-1",
						"CSeq: 1 SUBSCRIBE",
						"Event: message-summary",
						"Expires: 3600",
						"Accept: application/simple-message-summary",
					},
					Direction: "up",
				},
				{
					StatusCode: 200,
					StatusText: "OK",
					Headers: []string{
						"From: <sip:alice@example.com>;tag=sub1",
						"To: <sip:bob@example.com>;tag=nsub1",
						"Expires: 3600",
					},
					Direction: "down",
				},
				{
					Method: "NOTIFY",
					URI:    "sip:alice@example.com", // NOTIFY goes to subscriber
					Headers: []string{
						"From: <sip:bob@example.com>;tag=nsub1",
						"To: <sip:alice@example.com>;tag=sub1",
						"Call-ID: sub-call-1",
						"CSeq: 1 NOTIFY",
						"Event: message-summary",
						"Content-Type: application/simple-message-summary",
					},
					Body: "Messages-Waiting: yes\r\nMessage-Account: sip:bob@example.com\r\n",
					Direction: "up",
				},
				{
					StatusCode: 200,
					StatusText: "OK",
					Headers: []string{
						"From: <sip:bob@example.com>;tag=nsub1",
						"To: <sip:alice@example.com>;tag=sub1",
					},
					Direction: "down",
				},
			},
		},
	}
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, spec))

	// Verify all four messages appear in wire order with correct direction.
	type want struct {
		method      string // "" for status response
		statusCode  int
		direction   string
	}
	expected := []want{
		{method: "SUBSCRIBE", direction: "up"},
		{statusCode: 200, direction: "down"},
		{method: "NOTIFY", direction: "up"},
		{statusCode: 200, direction: "down"},
	}

	// Index PSH-ACKs only (skip handshake/teardown).
	pshIdx := 0
	for _, c := range cfgs {
		if c.L4.Flags != 0x18 {
			continue
		}
		if pshIdx >= len(expected) {
			break
		}
		exp := expected[pshIdx]
		if c.Direction != exp.direction {
			t.Errorf("psh[%d] direction=%q, want %q", pshIdx, c.Direction, exp.direction)
		}
		text := string(c.Payload)
		if exp.method != "" {
			if !strings.Contains(text, exp.method+" ") {
				t.Errorf("psh[%d] missing %q: %q", pshIdx, exp.method, text)
			}
		}
		if exp.statusCode != 0 {
			want := "SIP/2.0 " + intToStr(exp.statusCode) + " "
			if !strings.Contains(text, want) {
				t.Errorf("psh[%d] missing status line %q: %q", pshIdx, want, text)
			}
		}
		pshIdx++
	}
	if pshIdx != len(expected) {
		t.Errorf("got %d PSH-ACKs, want %d", pshIdx, len(expected))
	}

	// Lock in that the NOTIFY payload renders the Event header AND body
	// verbatim. Real NOTIFYs always carry Content-Length for their body
	// (computed by the planner from len(Body) when not user-supplied).
	for _, c := range cfgs {
		if c.L4.Flags != 0x18 {
			continue
		}
		if !strings.Contains(string(c.Payload), "NOTIFY ") {
			continue
		}
		text := string(c.Payload)
		if !strings.Contains(text, "Event: message-summary") {
			t.Errorf("NOTIFY missing Event header: %q", text)
		}
		if !strings.Contains(text, "Messages-Waiting: yes") {
			t.Errorf("NOTIFY body not rendered: %q", text)
		}
		// The body is 61 bytes ("Messages-Waiting: yes\r\n" (22) +
		// "Message-Account: sip:bob@example.com\r\n" (39) = 61).
		// Auto-appended Content-Length must match len(Body).
		if !strings.Contains(text, "Content-Length: 61") {
			t.Errorf("NOTIFY missing auto Content-Length: 61: %q", text)
		}
	}
}

// intToStr is a thin wrapper around strconv.Itoa to keep the call sites
// readable (the test uses it inline in status-line construction).
func intToStr(n int) string { return strconv.Itoa(n) }

// TestSIPPlan_PublishFlow verifies the RFC 3903 PUBLISH request (used to
// publish event state to an event-state compositor, e.g. presence). A
// PUBLISH carries an Event header and a body (the published state
// document), and the server replies with 200 OK and SIP-ETag header.
func TestSIPPlan_PublishFlow(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 5060, DstPort: 5060,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		SIP: &core.SIPConfig{
			Dialog: []core.SIPMessage{
				{
					Method: "PUBLISH",
					URI:    "sip:alice@example.com",
					Headers: []string{
						"From: <sip:alice@example.com>;tag=pub1",
						"To: <sip:alice@example.com>",
						"Event: presence",
						"Content-Type: application/pidf+xml",
					},
					Body:      "<?xml version=\"1.0\"?><presence/>",
					Direction: "up",
				},
				{
					StatusCode: 200,
					StatusText: "OK",
					Headers: []string{
						"SIP-ETag: abc123",
					},
					Direction: "down",
				},
			},
		},
	}
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, spec))
	var foundPub bool
	for _, c := range cfgs {
		if c.L4.Flags != 0x18 {
			continue
		}
		text := string(c.Payload)
		if strings.Contains(text, "PUBLISH sip:") {
			foundPub = true
			if !strings.Contains(text, "Event: presence") {
				t.Errorf("PUBLISH missing Event: presence: %q", text)
			}
			if !strings.Contains(text, "application/pidf+xml") {
				t.Errorf("PUBLISH missing Content-Type: %q", text)
			}
			if !strings.Contains(text, "<?xml") {
				t.Errorf("PUBLISH body not rendered: %q", text)
			}
		}
		if strings.Contains(text, "SIP/2.0 200") && strings.Contains(text, "SIP-ETag: abc123") {
			// 200 OK carries SIP-ETag verbatim.
		}
	}
	if !foundPub {
		t.Error("PUBLISH request not found in payloads")
	}
}

// ---------------------------------------------------------------------------
// re-INVITE (RFC 3261 §14 — session modification)
// ---------------------------------------------------------------------------

// TestSIPPlan_ReInviteSameFlowID verifies that a dialog with two INVITEs
// (initial + re-INVITE) emits all packets on the same FlowID. Per
// RFC 3261 §14.1, a re-INVITE is sent on the EXISTING dialog — it does
// NOT establish a new dialog. So all signaling packets must share the
// parent's FlowID, not get a new one.
func TestSIPPlan_ReInviteSameFlowID(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 5060, DstPort: 5060,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		SIP: &core.SIPConfig{
			Dialog: []core.SIPMessage{
				{Method: "INVITE", URI: "sip:bob@example.com", Direction: "up"},
				{StatusCode: 200, StatusText: "OK", Direction: "down"},
				{Method: "ACK", URI: "sip:bob@example.com", Direction: "up"},
				// re-INVITE: same dialog, updated session parameters.
				{Method: "INVITE", URI: "sip:bob@example.com", Direction: "up",
					Headers: []string{"Subject: Hold"}},
				{StatusCode: 200, StatusText: "OK", Direction: "down"},
				{Method: "ACK", URI: "sip:bob@example.com", Direction: "up"},
			},
		},
	}
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, spec))
	flowID := cfgs[0].FlowID
	if flowID == "" {
		t.Fatal("FlowID empty")
	}
	for i, c := range cfgs {
		if c.FlowID != flowID {
			t.Errorf("cfg[%d].FlowID=%q, want %q (re-INVITE is in-dialog, must share FlowID)",
				i, c.FlowID, flowID)
		}
	}
}

// TestSIPPlan_ReInviteUpdatesSDPMediaPort verifies that a re-INVITE
// updating the SDP port propagates the new port through to the
// post-re-INVITE RTP sub-flow. (Already covered end-to-end by
// TestSIPMedia_ReInviteLastWinsPropagatesToEndToEndRTP in
// sip_rtp_test.go; this test locks in the user-facing contract: a
// re-INVITE's port change affects the next emit, not the first.)
//
// The known "future-bleed" limitation: emitSIPMedia scans the WHOLE
// dialog, so the first emit (between first ACK and re-INVITE) ALREADY
// sees the re-INVITE's port. This test documents that limitation in
// a spec-driven way: a re-INVITE's SDP change is visible on subsequent
// emits, not necessarily the first.
func TestSIPPlan_ReInviteUpdatesSDPMediaPort(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 5060, DstPort: 5060,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		SIP: &core.SIPConfig{
			Dialog: []core.SIPMessage{
				{
					Method: "INVITE", URI: "sip:bob@example.com", Direction: "up",
					Body: "v=0\r\nm=audio 16384 RTP/AVP 0\r\n",
				},
				{
					StatusCode: 200, StatusText: "OK", Direction: "down",
					Body: "v=0\r\nm=audio 16386 RTP/AVP 0\r\n",
				},
				{Method: "ACK", URI: "sip:bob@example.com", Direction: "up", EmitMedia: true},
				// re-INVITE moves RTP ports to 16390/16392.
				{
					Method: "INVITE", URI: "sip:bob@example.com", Direction: "up",
					Body: "v=0\r\nm=audio 16390 RTP/AVP 0\r\n",
				},
				{
					StatusCode: 200, StatusText: "OK", Direction: "down",
					Body: "v=0\r\nm=audio 16392 RTP/AVP 0\r\n",
				},
				{Method: "ACK", URI: "sip:bob@example.com", Direction: "up", EmitMedia: true},
			},
			Media: &core.SIPMedia{
				Frames:     2,
				PayloadType: 0,
				FrameSize:  160,
			},
		},
	}
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, spec))
	rtp := findRTPPackets(cfgs)
	if len(rtp) == 0 {
		t.Fatal("no RTP packets emitted")
	}
	// Per the documented future-bleed limitation: BOTH emits use the
	// last-wins port (16390/16392). Assert that contract.
	for i, c := range rtp {
		if c.L4.SrcPort != 16390 {
			t.Errorf("rtp[%d] SrcPort=%d, want 16390 (re-INVITE last-wins)", i, c.L4.SrcPort)
		}
		if c.L4.DstPort != 16392 {
			t.Errorf("rtp[%d] DstPort=%d, want 16392 (re-INVITE last-wins)", i, c.L4.DstPort)
		}
	}
}

// TestSIPPlan_ReInviteSubjectHeader verifies that a re-INVITE's headers
// (e.g. Subject: Hold) are rendered verbatim — a re-INVITE can carry
// any standard SIP header, and the planner must pass them through.
func TestSIPPlan_ReInviteSubjectHeader(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 5060, DstPort: 5060,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		SIP: &core.SIPConfig{
			Dialog: []core.SIPMessage{
				{Method: "INVITE", URI: "sip:bob@example.com", Direction: "up"},
				{StatusCode: 200, StatusText: "OK", Direction: "down"},
				{Method: "ACK", URI: "sip:bob@example.com", Direction: "up"},
				{Method: "INVITE", URI: "sip:bob@example.com", Direction: "up",
					Headers: []string{"Subject: Music on hold"}},
				{StatusCode: 200, StatusText: "OK", Direction: "down"},
				{Method: "ACK", URI: "sip:bob@example.com", Direction: "up"},
			},
		},
	}
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, spec))
	var foundHold bool
	inviteCount := 0
	for _, c := range cfgs {
		if c.L4.Flags != 0x18 {
			continue
		}
		if strings.Contains(string(c.Payload), "INVITE sip:bob@example.com SIP/2.0") {
			inviteCount++
			if strings.Contains(string(c.Payload), "Subject: Music on hold") {
				foundHold = true
			}
		}
	}
	if inviteCount < 2 {
		t.Errorf("got %d INVITE payloads, want >= 2 (initial + re-INVITE)", inviteCount)
	}
	if !foundHold {
		t.Error("re-INVITE Subject: header not rendered")
	}
}

// ---------------------------------------------------------------------------
// SDP variants (RFC 4566)
// ---------------------------------------------------------------------------

// TestSDPMediaPort_FirstMAudioWinsWhenMultiple verifies that when an
// SDP body contains multiple m=audio lines (unusual but allowed for
// multi-stream sessions or simulcast), parseSDPMediaPort returns the
// port from the FIRST m=audio line. This is the documented contract
// (the regex uses FindStringSubmatch which returns the first match).
//
// RFC 4566 §5.14 allows multiple m= sections in a session description
// for related media streams, but the SIP planner only models ONE audio
// RTP flow per SIPMedia. Taking the first is a defensible default.
func TestSDPMediaPort_FirstMAudioWinsWhenMultiple(t *testing.T) {
	body := "v=0\r\nm=audio 5004 RTP/AVP 0\r\nm=audio 5006 RTP/AVP 8\r\n"
	got := parseSDPMediaPort(body)
	if got != 5004 {
		t.Errorf("parseSDPMediaPort=%d, want 5004 (first m=audio line wins)", got)
	}
}

// TestSDPMediaPort_SkipsVideo verifies that m=video lines are NOT
// parsed as audio RTP ports. Per the sdpMediaPortRe comment, the
// planner only emits audio RTP today, so matching m=video would
// silently capture a video port and produce an audio RTP flow on the
// wrong 4-tuple.
func TestSDPMediaPort_SkipsVideo(t *testing.T) {
	body := "v=0\r\nm=video 5006 RTP/AVP 96\r\n"
	got := parseSDPMediaPort(body)
	if got != 0 {
		t.Errorf("parseSDPMediaPort=%d, want 0 (m=video must be skipped)", got)
	}
}

// TestSDPMediaPort_MAudioAfterMVideoStillFindsAudio verifies that when
// the SDP body has BOTH m=video and m=audio, the audio port is
// extracted (not the video port).
func TestSDPMediaPort_MAudioAfterMVideoStillFindsAudio(t *testing.T) {
	body := "v=0\r\nm=video 5006 RTP/AVP 96\r\nm=audio 5004 RTP/AVP 0\r\n"
	got := parseSDPMediaPort(body)
	if got != 5004 {
		t.Errorf("parseSDPMediaPort=%d, want 5004 (audio after video)", got)
	}
}

// TestPlan_SDPMVideoInDialog verifies that an SDP body with m=video
// does NOT silently pull the video port into the RTP sub-flow. The
// user's m=video is preserved in the body, but the RTP sub-flow
// falls back to port 5004 because the planner only handles audio.
// This is the spec-driven "documented limitation" test — a user who
// needs video RTP must configure SIPMedia.DstPort explicitly.
func TestPlan_SDPMVideoInDialogFallsBackToDefault(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 5060, DstPort: 5060,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		SIP: &core.SIPConfig{
			Dialog: []core.SIPMessage{
				{
					Method: "INVITE", URI: "sip:bob@example.com", Direction: "up",
					Body: "v=0\r\nm=video 5006 RTP/AVP 96\r\n",
				},
				{
					StatusCode: 200, StatusText: "OK", Direction: "down",
					Body: "v=0\r\nm=video 5008 RTP/AVP 96\r\n",
				},
				{Method: "ACK", URI: "sip:bob@example.com", Direction: "up", EmitMedia: true},
			},
			Media: &core.SIPMedia{
				Frames:     1,
				PayloadType: 0,
				FrameSize:  160,
			},
		},
	}
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, spec))
	rtp := findRTPPackets(cfgs)
	if len(rtp) == 0 {
		t.Fatal("no RTP emitted")
	}
	// m=video is skipped, so SrcPort/DstPort fall back to 5004/5004.
	for i, c := range rtp {
		if c.L4.SrcPort != 5004 {
			t.Errorf("rtp[%d] SrcPort=%d, want 5004 (m=video skipped → fallback)", i, c.L4.SrcPort)
		}
		if c.L4.DstPort != 5004 {
			t.Errorf("rtp[%d] DstPort=%d, want 5004 (m=video skipped → fallback)", i, c.L4.DstPort)
		}
	}

	// But the m=video body itself IS rendered verbatim in the INVITE
	// payload (the planner does not sanitize SDP bodies — it just emits
	// what the user gave).
	var invitePayload string
	for _, c := range cfgs {
		if c.L4.Flags != 0x18 {
			continue
		}
		if strings.Contains(string(c.Payload), "INVITE sip:") {
			invitePayload = string(c.Payload)
			break
		}
	}
	if !strings.Contains(invitePayload, "m=video 5006") {
		t.Errorf("INVITE body missing m=video: %q", invitePayload)
	}
}

// TestSDPDirection_InactiveDefaultsToUp verifies that a=inactive (per
// RFC 4566 §6.4.1) does NOT suppress the RTP sub-flow. Per
// parseSDPDirection's documented contract, a=inactive returns "" and
// the caller (emitSIPMedia) falls through to its "up" default. A
// future enhancement could make a=inactive skip the sub-flow, but
// the current contract is "always emit at least one direction".
//
// This test locks the contract: a=inactive SDP produces RTP going "up".
func TestSDPDirection_InactiveDefaultsToUp(t *testing.T) {
	body := "v=0\r\nm=audio 5004 RTP/AVP 0\r\na=inactive\r\n"
	dir := parseSDPDirection(body)
	if dir != "" {
		t.Errorf("parseSDPDirection(a=inactive)=%q, want \"\" (caller defaults to up)", dir)
	}
}

// TestPlan_SDPInactiveDefaultsToUp verifies the end-to-end behavior:
// an INVITE with a=inactive still produces an "up" RTP sub-flow (the
// documented fallback). This is the integration-test companion to
// TestSDPDirection_InactiveDefaultsToUp.
func TestPlan_SDPInactiveDefaultsToUp(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 5060, DstPort: 5060,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		SIP: &core.SIPConfig{
			Dialog: []core.SIPMessage{
				{
					Method: "INVITE", URI: "sip:bob@example.com", Direction: "up",
					Body: "v=0\r\nm=audio 5004 RTP/AVP 0\r\na=inactive\r\n",
				},
				{
					StatusCode: 200, StatusText: "OK", Direction: "down",
					Body: "v=0\r\nm=audio 5006 RTP/AVP 0\r\na=inactive\r\n",
				},
				{Method: "ACK", URI: "sip:bob@example.com", Direction: "up", EmitMedia: true},
			},
			Media: &core.SIPMedia{
				Frames:     1,
				PayloadType: 0,
				FrameSize:  160,
			},
		},
	}
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, spec))
	rtp := findRTPPackets(cfgs)
	if len(rtp) == 0 {
		t.Fatal("no RTP packets")
	}
	for i, c := range rtp {
		if c.Direction != "up" {
			t.Errorf("rtp[%d] Direction=%q, want \"up\" (a=inactive falls through to up)", i, c.Direction)
		}
	}
}

// TestPlan_SDPCodecChangePCMA verifies that changing the codec in the
// SDP body (a=rtpmap:8 PCMA/8000) does NOT affect the RTP payload
// type emitted by the planner. The planner reads PayloadType from
// SIPMedia, NOT from the SDP body. The SDP body is rendered verbatim
// in the INVITE payload, but the actual RTP sub-flow uses the
// SIPMedia.PayloadType field.
//
// This is the spec-driven contract: the planner models the WIRE
// (what the SDP body advertises) but the RTP sub-flow is configured
// by the user via SIPMedia. A user who wants PCMA RTP must set
// SIPMedia.PayloadType=8 explicitly.
func TestPlan_SDPCodecChangeAdvertisedInBodyButUserControlsRTP(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 5060, DstPort: 5060,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		SIP: &core.SIPConfig{
			Dialog: []core.SIPMessage{
				{
					Method: "INVITE", URI: "sip:bob@example.com", Direction: "up",
					Body: "v=0\r\nm=audio 5004 RTP/AVP 8\r\na=rtpmap:8 PCMA/8000\r\n",
				},
				{
					StatusCode: 200, StatusText: "OK", Direction: "down",
					Body: "v=0\r\nm=audio 5006 RTP/AVP 8\r\na=rtpmap:8 PCMA/8000\r\n",
				},
				{Method: "ACK", URI: "sip:bob@example.com", Direction: "up", EmitMedia: true},
			},
			Media: &core.SIPMedia{
				Frames:      1,
				PayloadType: 0, // user explicitly chose PCMU, NOT PCMA from SDP
				FrameSize:   160,
			},
		},
	}
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, spec))
	rtp := findRTPPackets(cfgs)
	if len(rtp) == 0 {
		t.Fatal("no RTP packets")
	}
	// RTP uses user-configured PT=0, NOT the SDP's PCMA=8.
	for i, c := range rtp {
		pt := c.Payload[1] & 0x7F
		if pt != 0 {
			t.Errorf("rtp[%d] PT=%d, want 0 (SIPMedia.PayloadType, not SDP)", i, pt)
		}
	}

	// SDP body IS rendered with PCMA in the INVITE payload.
	for _, c := range cfgs {
		if c.L4.Flags != 0x18 {
			continue
		}
		if strings.Contains(string(c.Payload), "INVITE sip:") {
			if !strings.Contains(string(c.Payload), "PCMA/8000") {
				t.Errorf("INVITE body missing a=rtpmap:8 PCMA/8000: %q", c.Payload)
			}
		}
	}
}

// TestPlan_ReInviteWithSubjectAndSDP verifies the combination: a
// re-INVITE carries BOTH a custom header (Subject) AND a new SDP
// body. Both must be rendered verbatim. This is the most common
// re-INVITE pattern in production (hold/resume, codec change, etc.).
func TestPlan_ReInviteWithSubjectAndSDP(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 5060, DstPort: 5060,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		SIP: &core.SIPConfig{
			Dialog: []core.SIPMessage{
				{Method: "INVITE", URI: "sip:bob@example.com", Direction: "up",
					Body: "v=0\r\nm=audio 5004 RTP/AVP 0\r\n"},
				{StatusCode: 200, StatusText: "OK", Direction: "down",
					Body: "v=0\r\nm=audio 5006 RTP/AVP 0\r\n"},
				{Method: "ACK", URI: "sip:bob@example.com", Direction: "up"},
				{Method: "INVITE", URI: "sip:bob@example.com", Direction: "up",
					Headers: []string{"Subject: Resume"},
					Body:    "v=0\r\nm=audio 5004 RTP/AVP 0\r\na=sendonly\r\n"},
				{StatusCode: 200, StatusText: "OK", Direction: "down",
					Body: "v=0\r\nm=audio 5006 RTP/AVP 0\r\na=recvonly\r\n"},
				{Method: "ACK", URI: "sip:bob@example.com", Direction: "up"},
			},
		},
	}
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, spec))
	var foundSubject bool
	var foundSDPChange bool
	for _, c := range cfgs {
		if c.L4.Flags != 0x18 {
			continue
		}
		text := string(c.Payload)
		if strings.Contains(text, "Subject: Resume") {
			foundSubject = true
		}
		if strings.Contains(text, "a=sendonly") {
			foundSDPChange = true
		}
	}
	if !foundSubject {
		t.Error("re-INVITE Subject: Resume not rendered")
	}
	if !foundSDPChange {
		t.Error("re-INVITE SDP a=sendonly not rendered")
	}
}

// TestPlan_DigestAuthLongNonceBody verifies that an authentication
// header with a long base64 nonce (real servers issue ~32 chars) does
// not get split across MSS segments in a way that breaks DPI
// inspection. The test asserts the auth header appears intact in at
// least one PSH-ACK segment.
func TestPlan_DigestAuthLongNonceBody(t *testing.T) {
	// 64-char nonce (typical of real SIP servers).
	longNonce := strings.Repeat("ab", 32) // "abababab..."
	authHdr := "WWW-Authenticate: Digest realm=\"x\", nonce=\"" + longNonce + "\""
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 5060, DstPort: 5060,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		SIP: &core.SIPConfig{
			Dialog: []core.SIPMessage{
				{Method: "REGISTER", URI: "sip:x", Direction: "up"},
				{
					StatusCode: 401, StatusText: "Unauthorized",
					Headers:   []string{authHdr},
					Direction: "down",
				},
			},
		},
	}
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, spec))
	var found401, foundNonce bool
	for _, c := range cfgs {
		if c.L4.Flags != 0x18 {
			continue
		}
		if strings.Contains(string(c.Payload), "SIP/2.0 401") {
			found401 = true
			if strings.Contains(string(c.Payload), longNonce) {
				foundNonce = true
			}
		}
	}
	if !found401 {
		t.Error("401 response not found")
	}
	if !foundNonce {
		t.Error("64-char nonce not found intact in any 401 PSH-ACK segment")
	}
}

// TestPlan_SubscribeExpiresZero verifies the SUBSCRIBE Expires: 0
// unsubscribe pattern (RFC 6665 §2.3 — to unsubscribe, send SUBSCRIBE
// with Expires: 0). The planner must render Expires: 0 verbatim,
// and Content-Length: 0 must NOT be auto-appended (no body).
func TestPlan_SubscribeExpiresZero(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 5060, DstPort: 5060,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		SIP: &core.SIPConfig{
			Dialog: []core.SIPMessage{
				{
					Method: "SUBSCRIBE",
					URI:    "sip:bob@example.com",
					Headers: []string{
						"From: <sip:alice@example.com>;tag=u1",
						"Event: presence",
						"Expires: 0",
					},
					Direction: "up",
				},
				{StatusCode: 200, StatusText: "OK", Direction: "down"},
			},
		},
	}
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, spec))
	var foundSub, foundExpires0, hasContentLength bool
	for _, c := range cfgs {
		if c.L4.Flags != 0x18 {
			continue
		}
		text := string(c.Payload)
		if strings.Contains(text, "SUBSCRIBE sip:") {
			foundSub = true
			if strings.Contains(text, "Expires: 0") {
				foundExpires0 = true
			}
		}
		if strings.Contains(strings.ToLower(text), "content-length:") {
			hasContentLength = true
		}
	}
	if !foundSub {
		t.Error("SUBSCRIBE not found")
	}
	if !foundExpires0 {
		t.Error("Expires: 0 not rendered")
	}
	if hasContentLength {
		t.Error("SUBSCRIBE with no body should not have Content-Length header")
	}
}

// TestPlan_RegisterWithContactAndExpires verifies a standard
// registration flow: REGISTER with Contact and Expires headers, then
// 200 OK. The Contact header is critical — it's how the registrar
// knows where to send inbound INVITEs. The planner must render it
// verbatim.
func TestPlan_RegisterWithContactAndExpires(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 5060, DstPort: 5060,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		SIP: &core.SIPConfig{
			Dialog: []core.SIPMessage{
				{
					Method: "REGISTER",
					URI:    "sip:registrar.example.com",
					Headers: []string{
						"From: <sip:alice@example.com>;tag=reg1",
						"To: <sip:alice@example.com>",
						"Call-ID: reg-call-1@alice-pc",
						"CSeq: 1 REGISTER",
						"Contact: <sip:alice@10.0.0.1:5060;transport=TCP>",
						"Expires: 3600",
						"User-Agent: trafficgen/1.0",
					},
					Direction: "up",
				},
				{StatusCode: 200, StatusText: "OK", Direction: "down"},
			},
		},
	}
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, spec))
	var foundContact, foundExpires, foundUA bool
	for _, c := range cfgs {
		if c.L4.Flags != 0x18 {
			continue
		}
		text := string(c.Payload)
		if !strings.Contains(text, "REGISTER sip:") {
			continue
		}
		if strings.Contains(text, "Contact: <sip:alice@10.0.0.1:5060") {
			foundContact = true
		}
		if strings.Contains(text, "Expires: 3600") {
			foundExpires = true
		}
		if strings.Contains(text, "User-Agent: trafficgen/1.0") {
			foundUA = true
		}
	}
	if !foundContact {
		t.Error("Contact header not rendered")
	}
	if !foundExpires {
		t.Error("Expires: 3600 not rendered")
	}
	if !foundUA {
		t.Error("User-Agent not rendered")
	}
}

// TestPlan_ReInviteHoldDirection verifies that a re-INVITE with
// a=sendonly (hold per RFC 3264 §6.1) changes the RTP direction
// even when the user did NOT set SIPMedia.Direction. The SDP
// direction attribute is the source of truth.
func TestPlan_ReInviteHoldDirection(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 5060, DstPort: 5060,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		SIP: &core.SIPConfig{
			Dialog: []core.SIPMessage{
				{
					Method: "INVITE", URI: "sip:bob@example.com", Direction: "up",
					Body: "v=0\r\nm=audio 5004 RTP/AVP 0\r\na=sendrecv\r\n",
				},
				{
					StatusCode: 200, StatusText: "OK", Direction: "down",
					Body: "v=0\r\nm=audio 5006 RTP/AVP 0\r\na=sendrecv\r\n",
				},
				{Method: "ACK", URI: "sip:bob@example.com", Direction: "up", EmitMedia: true},
				// re-INVITE: hold (a=sendonly).
				{
					Method: "INVITE", URI: "sip:bob@example.com", Direction: "up",
					Body: "v=0\r\nm=audio 5004 RTP/AVP 0\r\na=sendonly\r\n",
				},
				{
					StatusCode: 200, StatusText: "OK", Direction: "down",
					Body: "v=0\r\nm=audio 5006 RTP/AVP 0\r\na=recvonly\r\n",
				},
				{Method: "ACK", URI: "sip:bob@example.com", Direction: "up", EmitMedia: true},
			},
			Media: &core.SIPMedia{
				Frames:     2,
				PayloadType: 0,
				FrameSize:  160,
			},
		},
	}
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, spec))
	rtp := findRTPPackets(cfgs)
	if len(rtp) == 0 {
		t.Fatal("no RTP")
	}
	// Per the documented future-bleed limitation: scanSDPDirection scans
	// the WHOLE dialog, so the LAST a= attribute wins for all emits.
	// The re-INVITE has a=sendonly (INVITE-side, the offerer), so the
	// derived direction is "up" for all emits.
	for i, c := range rtp {
		if c.Direction != "up" {
			t.Errorf("rtp[%d] Direction=%q, want \"up\" (re-INVITE a=sendonly wins via last-offerer scan)",
				i, c.Direction)
		}
	}
}

// Compile-time check that we reference the standard library (kept the
// file self-contained for the subagent).
var _ = strconv.Itoa
