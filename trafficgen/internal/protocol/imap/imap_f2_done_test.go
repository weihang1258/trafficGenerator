package imap

// F2 regression tests: the IMAP IDLE terminating DONE per RFC 2177 §3-§4.
//
// RFC 2177 ABNF (§4):  idle ::= "IDLE" CRLF "DONE"
// The DONE is a CONTINUATION response to the server's "+" prompt, NOT a
// tagged command. So DONE is sent bare as "DONE\r\n" with NO tag prefix.
//
// The finding F2 claimed "DONE is emitted with an empty/missing tag".
// After verification (see planner.go:554-581 + RFC 2177 §4), the existing
// code is ALREADY correct for the default case: when DoneTag is empty,
// doneTag is set to the cmd's tag, and the branch `if doneTag == tag`
// emits the bare IDLEDone ("DONE\r\n"). So the default is spec-correct.
//
// BUT there is a real bug in the explicit-DoneTag branch: when the user
// sets a DoneTag DIFFERENT from the cmd's tag, the code emits
// "<DoneTag> DONE\r\n" (planner.go:579), which is WRONG per RFC 2177 —
// DONE is always bare "DONE\r\n" regardless of any tag. The tag belongs
// only on the server's completion response, not on the client's DONE.
// The design doc testcases_imap.md §1.16.4 also encodes this wrong
// behavior ("output B002 DONE\r\n"), so we fix both the code and document
// the design correction.
//
// These tests assert the spec-correct wire bytes.

import (
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

// findIDLEDONE returns the first up-direction config whose payload is the
// bare DONE terminator. Per RFC 2177, DONE is sent by the client (up) as
// "DONE\r\n" with no tag.
func findIDLEDONE(t *testing.T, cfgs []core.PacketConfig) core.PacketConfig {
	t.Helper()
	for _, c := range cfgs {
		if c.Direction == "up" && strings.HasPrefix(string(c.Payload), "DONE") {
			return c
		}
	}
	t.Fatalf("no DONE terminator found in up-direction payloads")
	return core.PacketConfig{}
}

// TestF2_DoneBareNoTag_Default verifies that when DoneTag is empty (the
// default), the DONE terminator is the bare "DONE\r\n" with no tag.
func TestF2_DoneBareNoTag_Default(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	spec.IMAP.IDLE = &core.IMAPIDLE{DoneResponse: "A001 OK IDLE terminated"}
	spec.IMAP.Commands = []core.IMAPCommand{
		{Tag: "A001", Cmd: "IDLE", EmitIDLE: true},
	}
	cfgs := drain(mustPlan(t, p, spec))
	done := findIDLEDONE(t, cfgs)
	if got, want := string(done.Payload), "DONE\r\n"; got != want {
		t.Errorf("default DONE wire bytes = %q, want %q (RFC 2177 §4: bare DONE, no tag)", got, want)
	}
}

// TestF2_DoneBareNoTag_ExplicitDoneTag verifies that even when DoneTag is
// set to a value DIFFERENT from the cmd's tag, the client's DONE
// terminator is STILL the bare "DONE\r\n" with no tag prefix. Per RFC
// 2177 §4, DONE is a continuation, never a tagged command. The DoneTag
// only affects the SERVER's completion response (which is separately
// provided via DoneResponse).
//
// Pre-fix: planner.go:579 emitted "<DoneTag> DONE\r\n" (e.g.
// "B002 DONE\r\n") when DoneTag differed from the cmd tag — a
// spec-violating tagged DONE.
func TestF2_DoneBareNoTag_ExplicitDoneTag(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	spec.IMAP.IDLE = &core.IMAPIDLE{
		DoneTag:       "B002",
		DoneResponse:  "B002 OK IDLE terminated",
	}
	spec.IMAP.Commands = []core.IMAPCommand{
		{Tag: "A001", Cmd: "IDLE", EmitIDLE: true},
	}
	cfgs := drain(mustPlan(t, p, spec))
	done := findIDLEDONE(t, cfgs)
	if got, want := string(done.Payload), "DONE\r\n"; got != want {
		t.Errorf("explicit-DoneTag DONE wire bytes = %q, want %q (RFC 2177 §4: DONE is always bare; DoneTag only tags the server response, not the client DONE)", got, want)
	}
}

// TestF2_DoneResponseCarriesTag verifies the server's completion response
// (the only place a tag legitimately appears in the IDLE exchange) carries
// the user-provided DoneResponse verbatim. This guards against a fix that
// over-corrects by stripping the tag from the response too.
func TestF2_DoneResponseCarriesTag(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	spec.IMAP.IDLE = &core.IMAPIDLE{
		DoneTag:       "B002",
		DoneResponse:  "B002 OK IDLE terminated",
	}
	spec.IMAP.Commands = []core.IMAPCommand{
		{Tag: "A001", Cmd: "IDLE", EmitIDLE: true},
	}
	cfgs := drain(mustPlan(t, p, spec))
	found := false
	for _, c := range cfgs {
		if c.Direction == "down" && strings.Contains(string(c.Payload), "B002 OK IDLE terminated") {
			found = true
		}
	}
	if !found {
		t.Errorf("server done-response should carry DoneResponse %q verbatim (tagged), got payloads: %v", "B002 OK IDLE terminated", payloads(cfgs))
	}
}

// payloads is a helper for error messages.
func payloads(cfgs []core.PacketConfig) []string {
	out := make([]string, 0, len(cfgs))
	for _, c := range cfgs {
		out = append(out, string(c.Payload))
	}
	return out
}
