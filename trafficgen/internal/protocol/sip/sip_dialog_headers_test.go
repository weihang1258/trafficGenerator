package sip

// Dialog header completion tests. Derived from RFC 3261 and the user's
// Wireshark-verified report: an ACK generated from a dialog whose INVITE
// carries the dialog headers (From/To/Call-ID/CSeq) but whose ACK (and
// BYE/CANCEL, and the provisional/final responses) carry none was emitted
// with only a request-line — Wireshark flagged "Mandatory header Call-ID
// missing".
//
// The contract under test (RFC 3261 §20.8, §8.1.1, §13.2.2.4, §9.1):
//   - Call-ID: mandatory in every request and every response (except
//     responses to REGISTER). All messages of one dialog share the
//     INVITE's Call-ID.
//   - CSeq: mandatory; within a dialog the method must match the request
//     method. ACK-for-2xx and CANCEL reuse the INVITE's CSeq number;
//     each new request (BYE, re-INVITE, INFO, ...) increments it.
//   - From/To/Via: mandatory; responses echo the request's values.
//   - Via/Max-Forwards: mandatory in requests (RFC 3261 §8.1.1).
//
// User-supplied headers always win (user > default > none, matching the
// HTTP planner's rule). The planner only fills headers that are MISSING,
// from the dialog context or — for requests that omit the mandatory
// headers entirely — by generating them like a real UAC (RFC 3261
// §8.1.1.4; see sip_generated_headers_test.go). The one case that still
// renders verbatim: a dialog with no request at all (only responses),
// which no context can activate.

import (
	"context"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

// dialogBasicSpec mirrors the MCP test script's dialog_basic: the INVITE
// carries From/To/Call-ID/CSeq, every other message carries no headers.
func dialogBasicSpec() core.FlowSpec {
	return core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1",
		SrcPort: 12001, DstPort: 5060,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		SIP: &core.SIPConfig{
			Dialog: []core.SIPMessage{
				{
					Method: "INVITE",
					URI:    "sip:bob@example.com",
					Direction: "up",
					Headers: []string{
						"From: <sip:alice@example.com>",
						"To: <sip:bob@example.com>",
						"Call-ID: sip1@example.com",
						"CSeq: 1 INVITE",
					},
				},
				{StatusCode: 100, StatusText: "Trying", Direction: "down"},
				{StatusCode: 180, StatusText: "Ringing", Direction: "down"},
				{StatusCode: 200, StatusText: "OK", Direction: "down"},
				{Method: "ACK", URI: "sip:bob@example.com", Direction: "up"},
			},
		},
	}
}

// pshPayloads returns the payload bytes of every PSH-ACK data packet as
// text (handshake and teardown packets carry no payload).
func pshPayloads(cfgs []core.PacketConfig) []string {
	var out []string
	for _, c := range cfgs {
		if c.L4.Flags != 0x18 {
			continue
		}
		out = append(out, string(c.Payload))
	}
	return out
}

// headerValueOf extracts the value of the first header with the given
// name (case-insensitive per RFC 3261 §7.3.1) from a rendered payload.
func headerValueOf(payload, name string) (string, bool) {
	for _, line := range strings.Split(payload, "\r\n") {
		idx := strings.Index(line, ":")
		if idx < 0 {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(line[:idx]), name) {
			return strings.TrimSpace(line[idx+1:]), true
		}
	}
	return "", false
}

// findPayload returns the first PSH-ACK payload containing substr.
func findPayload(payloads []string, substr string) string {
	for _, p := range payloads {
		if strings.Contains(p, substr) {
			return p
		}
	}
	return ""
}

// TestSIPPlan_AckCarriesInviteCallID is the failing-test reproduction of
// the reported bug: the ACK must carry the SAME Call-ID as the INVITE
// (RFC 3261 §20.8 — Call-ID is mandatory in every request and is the
// dialog identifier; the ACK completes the INVITE's dialog). It also
// locks the other mandatory request headers (§8.1.1) and the ACK CSeq
// rule (§13.2.2.4: same number as the INVITE, method ACK).
func TestSIPPlan_AckCarriesInviteCallID(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, dialogBasicSpec()))
	payloads := pshPayloads(cfgs)

	invite := findPayload(payloads, "INVITE sip:bob@example.com SIP/2.0")
	if invite == "" {
		t.Fatal("INVITE payload not found")
	}
	ack := findPayload(payloads, "ACK sip:bob@example.com SIP/2.0")
	if ack == "" {
		t.Fatal("ACK payload not found")
	}

	inviteCallID, ok := headerValueOf(invite, "Call-ID")
	if !ok {
		t.Fatalf("INVITE missing Call-ID: %q", invite)
	}
	ackCallID, ok := headerValueOf(ack, "Call-ID")
	if !ok {
		t.Fatalf("ACK missing mandatory Call-ID header (RFC 3261 §20.8): %q", ack)
	}
	if ackCallID != inviteCallID {
		t.Errorf("ACK Call-ID=%q, want INVITE's Call-ID %q (same dialog)", ackCallID, inviteCallID)
	}

	// CSeq: method must match the request method, number must equal the
	// INVITE's (RFC 3261 §13.2.2.4 — the ACK completes the INVITE
	// transaction, it does not start a new CSeq sequence).
	if cseq, ok := headerValueOf(ack, "CSeq"); !ok || cseq != "1 ACK" {
		t.Errorf("ACK CSeq=%q, want %q", cseq, "1 ACK")
	}

	// Mandatory request headers per RFC 3261 §8.1.1.
	for _, name := range []string{"From", "To", "Via", "Max-Forwards"} {
		if _, ok := headerValueOf(ack, name); !ok {
			t.Errorf("ACK missing mandatory header %s: %q", name, ack)
		}
	}
	// From/To must be the dialog's (echoed from the INVITE).
	if from, _ := headerValueOf(ack, "From"); from != "<sip:alice@example.com>" {
		t.Errorf("ACK From=%q, want dialog From", from)
	}
	if to, _ := headerValueOf(ack, "To"); to != "<sip:bob@example.com>" {
		t.Errorf("ACK To=%q, want dialog To", to)
	}

	// Exactly one Call-ID (no duplicates).
	if n := strings.Count(ack, "Call-ID:"); n != 1 {
		t.Errorf("ACK has %d Call-ID headers, want 1: %q", n, ack)
	}

	// The INVITE itself gets the remaining mandatory headers filled too
	// (the dialog context is active from the INVITE's own Call-ID), so
	// the whole dialog is Wireshark-clean, not just the ACK.
	for _, name := range []string{"Via", "Max-Forwards"} {
		if _, ok := headerValueOf(invite, name); !ok {
			t.Errorf("INVITE missing mandatory header %s: %q", name, invite)
		}
	}
}

// TestSIPPlan_ResponsesCarryDialogCallID verifies RFC 3261 §20.8 for the
// response side: every response in the dialog must carry the INVITE's
// Call-ID, and its CSeq/From/To/Via echo the request it answers (the
// headerless 100/180/200 in the MCP scenario).
func TestSIPPlan_ResponsesCarryDialogCallID(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, dialogBasicSpec()))
	payloads := pshPayloads(cfgs)

	for _, status := range []string{"SIP/2.0 100", "SIP/2.0 180", "SIP/2.0 200"} {
		payload := findPayload(payloads, status)
		if payload == "" {
			t.Errorf("%s response not found", status)
			continue
		}
		callID, ok := headerValueOf(payload, "Call-ID")
		if !ok {
			t.Errorf("%s missing Call-ID (RFC 3261 §20.8): %q", status, payload)
			continue
		}
		if callID != "sip1@example.com" {
			t.Errorf("%s Call-ID=%q, want sip1@example.com", status, callID)
		}
		if cseq, ok := headerValueOf(payload, "CSeq"); !ok || cseq != "1 INVITE" {
			t.Errorf("%s CSeq=%q, want %q (echo of INVITE's CSeq)", status, cseq, "1 INVITE")
		}
		for _, name := range []string{"From", "To", "Via"} {
			if _, ok := headerValueOf(payload, name); !ok {
				t.Errorf("%s missing mandatory header %s: %q", status, name, payload)
			}
		}
	}
}

// TestSIPPlan_ByeIncrementsCSeq verifies that a BYE in the same dialog
// carries the INVITE's Call-ID and the NEXT CSeq number (RFC 3261
// §12.2.1.1 — each new request within a dialog increments CSeq by 1).
func TestSIPPlan_ByeIncrementsCSeq(t *testing.T) {
	spec := dialogBasicSpec()
	spec.SIP.Dialog = append(spec.SIP.Dialog,
		core.SIPMessage{Method: "BYE", URI: "sip:bob@example.com", Direction: "up"},
		core.SIPMessage{StatusCode: 200, StatusText: "OK", Direction: "down"},
	)
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, spec))
	payloads := pshPayloads(cfgs)

	bye := findPayload(payloads, "BYE sip:bob@example.com SIP/2.0")
	if bye == "" {
		t.Fatal("BYE payload not found")
	}
	if callID, _ := headerValueOf(bye, "Call-ID"); callID != "sip1@example.com" {
		t.Errorf("BYE Call-ID=%q, want sip1@example.com (same dialog)", callID)
	}
	if cseq, ok := headerValueOf(bye, "CSeq"); !ok || cseq != "2 BYE" {
		t.Errorf("BYE CSeq=%q, want %q (dialog CSeq increments)", cseq, "2 BYE")
	}
	// The 200-to-BYE echoes the BYE's CSeq (the LAST 200 OK in the
	// dialog — the first 200 OK answers the INVITE).
	var bye200 string
	for _, p := range payloads {
		if strings.Contains(p, "SIP/2.0 200") {
			bye200 = p
		}
	}
	if bye200 == "" {
		t.Fatal("200 OK payload not found")
	}
	if cseq, ok := headerValueOf(bye200, "CSeq"); !ok || cseq != "2 BYE" {
		t.Errorf("200-to-BYE CSeq=%q, want %q", cseq, "2 BYE")
	}
}

// TestSIPPlan_CancelUsesInviteCSeq verifies the CANCEL CSeq rule (RFC
// 3261 §9.1): the CANCEL's CSeq number equals the INVITE's, with the
// method CANCEL — it does not start a new CSeq sequence.
func TestSIPPlan_CancelUsesInviteCSeq(t *testing.T) {
	spec := dialogBasicSpec()
	spec.SIP.Dialog = append(spec.SIP.Dialog,
		core.SIPMessage{Method: "CANCEL", URI: "sip:bob@example.com", Direction: "up"},
		core.SIPMessage{StatusCode: 200, StatusText: "OK", Direction: "down"},
	)
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, spec))
	payloads := pshPayloads(cfgs)

	cancel := findPayload(payloads, "CANCEL sip:bob@example.com SIP/2.0")
	if cancel == "" {
		t.Fatal("CANCEL payload not found")
	}
	if callID, _ := headerValueOf(cancel, "Call-ID"); callID != "sip1@example.com" {
		t.Errorf("CANCEL Call-ID=%q, want sip1@example.com", callID)
	}
	if cseq, ok := headerValueOf(cancel, "CSeq"); !ok || cseq != "1 CANCEL" {
		t.Errorf("CANCEL CSeq=%q, want %q (same number as INVITE per RFC 3261 §9.1)", cseq, "1 CANCEL")
	}
}

// TestSIPPlan_ReinviteCSeqNumbering verifies CSeq numbering across a
// re-INVITE (the SIP.1.8 MCP scenario): the initial INVITE is 1, its ACK
// is "1 ACK", the re-INVITE starts a new transaction at 2, its ACK is
// "2 ACK", and a subsequent BYE is 3.
func TestSIPPlan_ReinviteCSeqNumbering(t *testing.T) {
	spec := dialogBasicSpec()
	spec.SIP.Dialog = append(spec.SIP.Dialog,
		core.SIPMessage{Method: "INVITE", URI: "sip:bob@example.com", Direction: "up"},
		core.SIPMessage{StatusCode: 200, StatusText: "OK", Direction: "down"},
		core.SIPMessage{Method: "ACK", URI: "sip:bob@example.com", Direction: "up"},
		core.SIPMessage{Method: "BYE", URI: "sip:bob@example.com", Direction: "up"},
		core.SIPMessage{StatusCode: 200, StatusText: "OK", Direction: "down"},
	)
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, spec))
	payloads := pshPayloads(cfgs)

	// Expect per request-line: INVITE→1 INVITE, ACK→1 ACK, re-INVITE→2
	// INVITE, ACK#2→2 ACK, BYE→3 BYE.
	want := map[string]string{
		"INVITE sip:bob@example.com SIP/2.0": "1 INVITE",
		"ACK sip:bob@example.com SIP/2.0":    "1 ACK",
	}
	// The second INVITE and second ACK appear twice in payloads; the
	// FIRST occurrence is the initial dialog, the LAST is the re-INVITE
	// transaction. Collect CSeq values per request-line occurrence.
	got := map[string][]string{}
	for _, payload := range payloads {
		for line := range want {
			if strings.Contains(payload, line) {
				cseq, _ := headerValueOf(payload, "CSeq")
				got[line] = append(got[line], cseq)
			}
		}
		if strings.Contains(payload, "BYE sip:bob@example.com SIP/2.0") {
			cseq, _ := headerValueOf(payload, "CSeq")
			got["BYE"] = append(got["BYE"], cseq)
		}
	}
	if len(got["INVITE sip:bob@example.com SIP/2.0"]) != 2 {
		t.Fatalf("want 2 INVITE payloads, got %d", len(got["INVITE sip:bob@example.com SIP/2.0"]))
	}
	if cseq := got["INVITE sip:bob@example.com SIP/2.0"][0]; cseq != "1 INVITE" {
		t.Errorf("INVITE#1 CSeq=%q, want %q", cseq, "1 INVITE")
	}
	if cseq := got["INVITE sip:bob@example.com SIP/2.0"][1]; cseq != "2 INVITE" {
		t.Errorf("re-INVITE CSeq=%q, want %q", cseq, "2 INVITE")
	}
	if len(got["ACK sip:bob@example.com SIP/2.0"]) != 2 {
		t.Fatalf("want 2 ACK payloads, got %d", len(got["ACK sip:bob@example.com SIP/2.0"]))
	}
	if cseq := got["ACK sip:bob@example.com SIP/2.0"][0]; cseq != "1 ACK" {
		t.Errorf("ACK#1 CSeq=%q, want %q", cseq, "1 ACK")
	}
	if cseq := got["ACK sip:bob@example.com SIP/2.0"][1]; cseq != "2 ACK" {
		t.Errorf("ACK#2 CSeq=%q, want %q", cseq, "2 ACK")
	}
	if cseq := got["BYE"]; len(cseq) != 1 || cseq[0] != "3 BYE" {
		t.Errorf("BYE CSeq=%q, want [3 BYE]", cseq)
	}
}

// TestSIPPlan_UserSuppliedHeadersWin verifies the user > default > none
// rule: a user-supplied Call-ID/CSeq on a dialog message is preserved
// verbatim and never duplicated or overridden by the dialog fill.
func TestSIPPlan_UserSuppliedHeadersWin(t *testing.T) {
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
						"Call-ID: sip1@example.com",
						"CSeq: 1 INVITE",
					},
				},
				{StatusCode: 200, StatusText: "OK", Direction: "down"},
				{
					Method: "ACK", URI: "sip:bob@example.com", Direction: "up",
					Headers: []string{
						"Call-ID: custom-call@example.com", // user's own dialog identifier
						"CSeq: 7 ACK",                      // user's own numbering
					},
				},
			},
		},
	}
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, spec))
	payloads := pshPayloads(cfgs)

	ack := findPayload(payloads, "ACK sip:bob@example.com SIP/2.0")
	if ack == "" {
		t.Fatal("ACK payload not found")
	}
	if callID, _ := headerValueOf(ack, "Call-ID"); callID != "custom-call@example.com" {
		t.Errorf("ACK Call-ID=%q, want user-supplied %q", callID, "custom-call@example.com")
	}
	if cseq, ok := headerValueOf(ack, "CSeq"); !ok || cseq != "7 ACK" {
		t.Errorf("ACK CSeq=%q, want user-supplied %q", cseq, "7 ACK")
	}
	if n := strings.Count(ack, "Call-ID:"); n != 1 {
		t.Errorf("ACK has %d Call-ID headers, want 1 (no duplicate): %q", n, ack)
	}
	if n := strings.Count(ack, "CSeq:"); n != 1 {
		t.Errorf("ACK has %d CSeq headers, want 1 (no duplicate): %q", n, ack)
	}
}

// TestSIPPlan_ResponsesOnlyDialogRendersVerbatim locks the residual
// boundary of the header completion: only REQUESTS trigger generation
// (the UAC generates a Call-ID per RFC 3261 §8.1.1.4 — see
// sip_generated_headers_test.go). A dialog with no request at all
// (only responses) activates no context — a response echoes the request
// it answers and never invents one — so every message renders verbatim.
func TestSIPPlan_ResponsesOnlyDialogRendersVerbatim(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1",
		SrcPort: 12005, DstPort: 5060,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		SIP: &core.SIPConfig{
			Dialog: []core.SIPMessage{
				{StatusCode: 100, StatusText: "Trying", Direction: "down"},
				{StatusCode: 200, StatusText: "OK", Direction: "down"},
			},
		},
	}
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, spec))
	payloads := pshPayloads(cfgs)

	if len(payloads) != 2 {
		t.Fatalf("want 2 response payloads, got %d", len(payloads))
	}
	if payloads[0] != "SIP/2.0 100 Trying\r\n\r\n" {
		t.Errorf("100 Trying must render verbatim (no request to echo): %q", payloads[0])
	}
	if payloads[1] != "SIP/2.0 200 OK\r\n\r\n" {
		t.Errorf("200 OK must render verbatim (no request to echo): %q", payloads[1])
	}
}

// compile-time guard: ensure the package test file uses context (kept
// for symmetry with the other test files that plan synchronously).
var _ = context.Background
