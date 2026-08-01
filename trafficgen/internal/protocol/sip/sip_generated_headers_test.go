package sip

// Auto-generated dialog headers tests. Derived from the user's
// Wireshark-verified report (MCP case sip_1_20): a dialog whose INVITE
// carries NO headers at all (only request-line + SDP body) rendered
// verbatim, and Wireshark flagged "Call ID is mandatory" on the INVITE.
//
// RFC 3261 §8.1.1: Via, From, To, Call-ID, CSeq and Max-Forwards are
// MANDATORY in every request, and §8.1.1.4: the UAC MUST generate a
// Call-ID — it is the UAC's job, not a user-config courtesy. A user
// config that omits the headers is shorthand for "the planner should
// behave as a real UAC", so the planner generates the missing mandatory
// request headers instead of emitting a bare request-line.
//
// The contract under test:
//   - The first request of a dialog (the INVITE) that omits Call-ID gets
//     a generated one (sip<8hex>@<srcIP>) and activates the dialog
//     context; every later request inherits it (one Call-ID per dialog).
//   - From/To/Via/CSeq/Max-Forwards are generated the same way (§8.1.1):
//     From from the source address, To from the Request-URI (the
//     callee's address-of-record, §13.2.1), Via with the z9hG4bK magic
//     cookie (§8.1.1.7), Max-Forwards 70 (§20.22), CSeq numbered 1 for
//     the INVITE, reusing the number for the ACK that completes it
//     (§13.2.2.4) and incrementing for BYE (§12.2.1.1).
//   - Responses still only echo the request they answer — the response
//     side is untouched.
//   - User-supplied headers always win (user > default > none): a user
//     From/To/Call-ID/CSeq on the INVITE is preserved verbatim and only
//     the remaining mandatory headers are generated.

import (
	"regexp"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

// headerlessDialogSpec mirrors the sip_1_20 report: the INVITE has NO
// headers (only request-line + SDP body) and no message in the dialog
// carries any header.
func headerlessDialogSpec() core.FlowSpec {
	return core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1",
		SrcPort: 12001, DstPort: 5060,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		SIP: &core.SIPConfig{
			Dialog: []core.SIPMessage{
				{
					Method: "INVITE", URI: "sip:bob@example.com", Direction: "up",
					Body: "v=0\r\n" +
						"o=alice 2890844526 2890844526 IN IP4 10.0.0.1\r\n" +
						"s=session\r\n" +
						"c=IN IP4 10.0.0.1\r\n" +
						"t=0 0\r\n" +
						"m=audio 5004 RTP/AVP 0\r\n",
				},
				{StatusCode: 100, StatusText: "Trying", Direction: "down"},
				{StatusCode: 200, StatusText: "OK", Direction: "down"},
				{Method: "ACK", URI: "sip:bob@example.com", Direction: "up"},
				{Method: "BYE", URI: "sip:bob@example.com", Direction: "up"},
				{StatusCode: 200, StatusText: "OK", Direction: "down"},
			},
		},
	}
}

// generatedCallIDRe matches the planner's generated Call-ID format:
// "sip" + 8 lowercase hex digits + "@" + source IP (RFC 3261 §20.8:
// callid = word [ "@" word ]).
var generatedCallIDRe = regexp.MustCompile(`^sip[0-9a-f]{8}@10\.0\.0\.1$`)

// TestSIPPlan_HeaderlessDialogGetsGeneratedCallID is the failing-test
// reproduction of the reported bug: a dialog where NO message carries a
// Call-ID must still render Wireshark-clean, because the UAC MUST
// generate a Call-ID (RFC 3261 §8.1.1.4). The INVITE gets the generated
// Call-ID, and ACK/BYE share it (one dialog, one Call-ID, §20.8).
func TestSIPPlan_HeaderlessDialogGetsGeneratedCallID(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, headerlessDialogSpec()))
	payloads := pshPayloads(cfgs)

	invite := findPayload(payloads, "INVITE sip:bob@example.com SIP/2.0")
	if invite == "" {
		t.Fatal("INVITE payload not found")
	}

	// INVITE: the UAC must carry a generated Call-ID (§8.1.1.4), in the
	// planner's documented format, and it must not be empty.
	inviteCallID, ok := headerValueOf(invite, "Call-ID")
	if !ok {
		t.Fatalf("INVITE missing Call-ID (RFC 3261 §8.1.1.4 — UAC MUST generate one): %q", invite)
	}
	if inviteCallID == "" {
		t.Fatalf("INVITE Call-ID is empty: %q", invite)
	}
	if !generatedCallIDRe.MatchString(inviteCallID) {
		t.Errorf("INVITE Call-ID=%q, want generated form %q (sip<8hex>@srcIP)", inviteCallID, generatedCallIDRe.String())
	}

	// ACK and BYE must carry the SAME Call-ID as the INVITE — the dialog
	// identifier (§20.8) — even though they too have no headers.
	ack := findPayload(payloads, "ACK sip:bob@example.com SIP/2.0")
	if ack == "" {
		t.Fatal("ACK payload not found")
	}
	if ackCallID, ok := headerValueOf(ack, "Call-ID"); !ok || ackCallID != inviteCallID {
		t.Errorf("ACK Call-ID=%q, want INVITE's %q (same dialog)", ackCallID, inviteCallID)
	}
	bye := findPayload(payloads, "BYE sip:bob@example.com SIP/2.0")
	if bye == "" {
		t.Fatal("BYE payload not found")
	}
	if byeCallID, ok := headerValueOf(bye, "Call-ID"); !ok || byeCallID != inviteCallID {
		t.Errorf("BYE Call-ID=%q, want INVITE's %q (same dialog)", byeCallID, inviteCallID)
	}

	// Exactly one Call-ID per message (no duplicates).
	for name, payload := range map[string]string{"INVITE": invite, "ACK": ack, "BYE": bye} {
		if n := strings.Count(payload, "Call-ID:"); n != 1 {
			t.Errorf("%s has %d Call-ID headers, want 1: %q", name, n, payload)
		}
	}

	// The INVITE also gets the other mandatory request headers (§8.1.1),
	// with a Via branch carrying the z9hG4bK magic cookie (§8.1.1.7).
	for _, name := range []string{"From", "To", "Via", "CSeq", "Max-Forwards"} {
		if _, ok := headerValueOf(invite, name); !ok {
			t.Errorf("INVITE missing mandatory header %s (RFC 3261 §8.1.1): %q", name, invite)
		}
	}
	if via, _ := headerValueOf(invite, "Via"); !strings.Contains(via, "z9hG4bK") {
		t.Errorf("INVITE Via=%q, want branch with z9hG4bK magic cookie", via)
	}

	// Generated identity values: From is the caller (source address),
	// To is the callee named by the Request-URI (§13.2.1).
	if from, _ := headerValueOf(invite, "From"); from != "<sip:user@10.0.0.1>" {
		t.Errorf("INVITE From=%q, want %q (caller identity from source address)", from, "<sip:user@10.0.0.1>")
	}
	if to, _ := headerValueOf(invite, "To"); to != "<sip:bob@example.com>" {
		t.Errorf("INVITE To=%q, want %q (callee from Request-URI)", to, "<sip:bob@example.com>")
	}

	// CSeq numbering (§20.16): method matches the request; ACK reuses the
	// INVITE's number (§13.2.2.4); BYE increments (§12.2.1.1).
	for _, tc := range []struct {
		name, payload, want string
	}{
		{"INVITE", invite, "1 INVITE"},
		{"ACK", ack, "1 ACK"},
		{"BYE", bye, "2 BYE"},
	} {
		if cseq, ok := headerValueOf(tc.payload, "CSeq"); !ok || cseq != tc.want {
			t.Errorf("%s CSeq=%q, want %q", tc.name, cseq, tc.want)
		}
	}

	// Response side unchanged: the 100/180.../200 responses echo the
	// request they answer (RFC 3261 §8.1.3.2) — same Call-ID, same CSeq
	// line. Here the 100 and both 200 OKs answer requests with CSeq 1
	// (INVITE, ACK...) — the 100 and the first 200 answer the INVITE.
	for _, status := range []string{"SIP/2.0 100", "SIP/2.0 200"} {
		payload := findPayload(payloads, status)
		if payload == "" {
			t.Errorf("%s response not found", status)
			continue
		}
		if callID, ok := headerValueOf(payload, "Call-ID"); !ok || callID != inviteCallID {
			t.Errorf("%s Call-ID=%q, want INVITE's %q (response echoes request)", status, callID, inviteCallID)
		}
	}
	var trying100 string
	for _, status := range []string{"SIP/2.0 100"} {
		if payload := findPayload(payloads, status); payload != "" {
			trying100 = payload
		}
	}
	if cseq, ok := headerValueOf(trying100, "CSeq"); !ok || cseq != "1 INVITE" {
		t.Errorf("100 Trying CSeq=%q, want %q (echo of INVITE's CSeq)", cseq, "1 INVITE")
	}
	// The LAST 200 OK answers the BYE, so its CSeq echoes "2 BYE".
	var bye200 string
	for _, payload := range payloads {
		if strings.Contains(payload, "SIP/2.0 200") {
			bye200 = payload
		}
	}
	if cseq, ok := headerValueOf(bye200, "CSeq"); !ok || cseq != "2 BYE" {
		t.Errorf("200-to-BYE CSeq=%q, want %q (echo of BYE's CSeq)", cseq, "2 BYE")
	}
}

// TestSipHostOf locks the host-formatting helper used by the generated
// Call-ID/From/To/Via values: IPv6 literals are bracketed per RFC 3261
// §19.1.1 and an empty address falls back to 0.0.0.0 so a spec without
// SrcIP still renders parseable header values.
func TestSipHostOf(t *testing.T) {
	for _, tc := range []struct {
		in, want string
	}{
		{"10.0.0.1", "10.0.0.1"},
		{"2001:db8::1", "[2001:db8::1]"},
		{"", "0.0.0.0"},
	} {
		if got := sipHostOf(tc.in); got != tc.want {
			t.Errorf("sipHostOf(%q)=%q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestSIPPlan_UserFromToWinOverGenerated verifies user > default > none
// on the generated path: when the user supplies From/To on the INVITE
// but no Call-ID/CSeq/Via/Max-Forwards, the user's identity headers are
// preserved verbatim (never overwritten by generated ones) while the
// missing mandatory headers are still generated; the ACK inherits the
// user's From/To and the generated Call-ID.
func TestSIPPlan_UserFromToWinOverGenerated(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1",
		SrcPort: 12001, DstPort: 5060,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		SIP: &core.SIPConfig{
			Dialog: []core.SIPMessage{
				{
					Method: "INVITE", URI: "sip:bob@example.com", Direction: "up",
					Headers: []string{
						"From: <sip:alice@example.com>",
						"To: <sip:bob@example.com>",
					},
				},
				{StatusCode: 200, StatusText: "OK", Direction: "down"},
				{Method: "ACK", URI: "sip:bob@example.com", Direction: "up"},
			},
		},
	}
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, spec))
	payloads := pshPayloads(cfgs)

	invite := findPayload(payloads, "INVITE sip:bob@example.com SIP/2.0")
	if invite == "" {
		t.Fatal("INVITE payload not found")
	}
	ack := findPayload(payloads, "ACK sip:bob@example.com SIP/2.0")
	if ack == "" {
		t.Fatal("ACK payload not found")
	}

	// User's From/To preserved verbatim — the planner's generated values
	// (which would be <sip:user@10.0.0.1> / <sip:bob@example.com>) must
	// not override them.
	if from, _ := headerValueOf(invite, "From"); from != "<sip:alice@example.com>" {
		t.Errorf("INVITE From=%q, want user-supplied %q (user > default)", from, "<sip:alice@example.com>")
	}
	if to, _ := headerValueOf(invite, "To"); to != "<sip:bob@example.com>" {
		t.Errorf("INVITE To=%q, want user-supplied %q (user > default)", to, "<sip:bob@example.com>")
	}

	// Missing mandatory headers are still generated on the INVITE.
	inviteCallID, ok := headerValueOf(invite, "Call-ID")
	if !ok {
		t.Fatalf("INVITE missing generated Call-ID: %q", invite)
	}
	if !generatedCallIDRe.MatchString(inviteCallID) {
		t.Errorf("INVITE Call-ID=%q, want generated form %q", inviteCallID, generatedCallIDRe.String())
	}
	for _, name := range []string{"Via", "CSeq", "Max-Forwards"} {
		if _, ok := headerValueOf(invite, name); !ok {
			t.Errorf("INVITE missing generated header %s: %q", name, invite)
		}
	}
	if cseq, _ := headerValueOf(invite, "CSeq"); cseq != "1 INVITE" {
		t.Errorf("INVITE CSeq=%q, want %q", cseq, "1 INVITE")
	}
	if n := strings.Count(invite, "Call-ID:"); n != 1 {
		t.Errorf("INVITE has %d Call-ID headers, want 1: %q", n, invite)
	}

	// ACK inherits the user's From/To (dialog values) and the generated
	// Call-ID; its CSeq reuses the INVITE's number with method ACK.
	if from, _ := headerValueOf(ack, "From"); from != "<sip:alice@example.com>" {
		t.Errorf("ACK From=%q, want dialog From (user's)", from)
	}
	if to, _ := headerValueOf(ack, "To"); to != "<sip:bob@example.com>" {
		t.Errorf("ACK To=%q, want dialog To (user's)", to)
	}
	if ackCallID, _ := headerValueOf(ack, "Call-ID"); ackCallID != inviteCallID {
		t.Errorf("ACK Call-ID=%q, want INVITE's %q (same dialog)", ackCallID, inviteCallID)
	}
	if cseq, ok := headerValueOf(ack, "CSeq"); !ok || cseq != "1 ACK" {
		t.Errorf("ACK CSeq=%q, want %q", cseq, "1 ACK")
	}
}
