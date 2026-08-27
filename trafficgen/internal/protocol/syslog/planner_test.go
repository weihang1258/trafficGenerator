package syslog

// Test points for the Syslog planner. Each test asserts observable
// PacketConfig field values, not just "no error". Derived from
// /tmp/l7_planner_design/testcases_syslog.md and design_syslog.md §2-§6.
//
// Conventions:
//   - drain collects all configs from the channel.
//   - validSyslogSpec returns a spec with RFC 5424 UDP defaults.
//   - mustPlan wraps Plan and fails on error.

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

// drain collects all configs from the channel.
func drain(ch <-chan core.PacketConfig) []core.PacketConfig {
	var out []core.PacketConfig
	for c := range ch {
		out = append(out, c)
	}
	return out
}

// validSyslogSpec returns a spec with sensible RFC 5424 UDP defaults.
// Facility=16 (local0), Severity=6 (info), DST port=514.
func validSyslogSpec() core.FlowSpec {
	return core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 12345, DstPort: 514,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		Syslog: &core.SyslogConfig{
			Facility: 16, // local0
			Severity: 6,  // info
			Version:  1,
			Hostname: "server01",
			AppName:  "cron",
			MsgID:    "HEARTBEAT",
			Msg:      "Job ran",
		},
	}
}

// mustPlan is a helper that fails the test if Plan returns an error.
func mustPlan(t *testing.T, p *Planner, spec core.FlowSpec) <-chan core.PacketConfig {
	t.Helper()
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	return ch
}

// --- Validate: IP / port / required ---

func TestSyslogValidate_Valid(t *testing.T) {
	p := NewPlanner()
	if err := p.Validate(validSyslogSpec()); err != nil {
		t.Errorf("valid spec: %v", err)
	}
}

func TestSyslogValidate_NilConfig(t *testing.T) {
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog = nil
	if err := p.Validate(spec); err != nil {
		t.Errorf("Empty config should default to a flow, got err=%v", err)
	}
}

func TestSyslogValidate_InvalidSrcIP(t *testing.T) {
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.SrcIP = "not-an-ip"
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "SrcIP") {
		t.Errorf("err=%v, want contains 'SrcIP'", err)
	}
}

func TestSyslogValidate_InvalidDstIP(t *testing.T) {
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.DstIP = "bad"
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "DstIP") {
		t.Errorf("err=%v, want contains 'DstIP'", err)
	}
}

func TestSyslogValidate_EmptySrcIP(t *testing.T) {
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.SrcIP = ""
	if err := p.Validate(spec); err != nil {
		t.Errorf("empty SrcIP should skip: %v", err)
	}
}

// --- Validate: PRI bounds (RFC 5424 §6.2.1) ---

// Facility=0 (kern) + Severity=6 (info) -> PRI=6
func TestSyslogValidate_PRI_KernInfo(t *testing.T) {
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.Facility = 0
	spec.Syslog.Severity = 6
	cfgs := drain(mustPlan(t, p, spec))
	// PRI = 0*8+6 = 6
	pri, ok := cfgs[0].Metadata["syslog_priority"].(int)
	if !ok || pri != 6 {
		t.Errorf("priority=%v, want 6", cfgs[0].Metadata["syslog_priority"])
	}
}

// Facility=4 (security/auth) + Severity=2 (crit) -> PRI=34
// This is the testcase 1.1.1.5+1.1.2.3 combo from the design doc.
func TestSyslogValidate_PRI_SecurityCrit(t *testing.T) {
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.Facility = 4
	spec.Syslog.Severity = 2
	cfgs := drain(mustPlan(t, p, spec))
	pri, ok := cfgs[0].Metadata["syslog_priority"].(int)
	if !ok || pri != 34 {
		t.Errorf("priority=%v, want 34 (4*8+2)", cfgs[0].Metadata["syslog_priority"])
	}
}

// Facility=23 (reserved) + Severity=7 (debug) -> PRI=191 (max).
func TestSyslogValidate_PRI_MaxValue(t *testing.T) {
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.Facility = 23
	spec.Syslog.Severity = 7
	cfgs := drain(mustPlan(t, p, spec))
	pri, ok := cfgs[0].Metadata["syslog_priority"].(int)
	if !ok || pri != 191 {
		t.Errorf("priority=%v, want 191 (23*8+7)", cfgs[0].Metadata["syslog_priority"])
	}
}

// Facility=24 -> Validate fails.
func TestSyslogValidate_FacilityOutOfRange(t *testing.T) {
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.Facility = 24
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "Facility") {
		t.Errorf("err=%v, want contains 'Facility'", err)
	}
}

// Facility=255 (uint8 max) -> Validate fails.
func TestSyslogValidate_FacilityTooLarge(t *testing.T) {
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.Facility = 255
	err := p.Validate(spec)
	if err == nil {
		t.Error("Facility=255 should fail")
	}
}

// Severity=8 -> Validate fails.
func TestSyslogValidate_SeverityOutOfRange(t *testing.T) {
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.Severity = 8
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "Severity") {
		t.Errorf("err=%v, want contains 'Severity'", err)
	}
}

// --- Validate: VERSION (RFC 5424 §6.2.2) ---

func TestSyslogValidate_VersionInvalid(t *testing.T) {
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.Version = 2
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "Version") {
		t.Errorf("err=%v, want contains 'Version'", err)
	}
}

func TestSyslogValidate_VersionZeroRfc5424Fails(t *testing.T) {
	// Version=0 with Format=rfc5424 -> fail (RFC 5424 requires VERSION=1).
	// This is the testcase 1.2.2 / 4.3.3 case.
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.Version = 0
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "Version") {
		t.Errorf("err=%v, want contains 'Version'", err)
	}
}

func TestSyslogValidate_VersionZeroBsdOk(t *testing.T) {
	// Version=0 with Format=bsd is fine (RFC 3164 has no VERSION field).
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.Version = 0
	spec.Syslog.Format = "bsd"
	if err := p.Validate(spec); err != nil {
		t.Errorf("Version=0 with Format=bsd should pass: %v", err)
	}
}

// --- Validate: Format / Transport / TCPFraming ---

func TestSyslogValidate_FormatUnknown(t *testing.T) {
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.Format = "unknown"
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "Format") {
		t.Errorf("err=%v, want contains 'Format'", err)
	}
}

func TestSyslogValidate_TransportUnknown(t *testing.T) {
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.Transport = "icmp"
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "Transport") {
		t.Errorf("err=%v, want contains 'Transport'", err)
	}
}

func TestSyslogValidate_TCPFramingUnknown(t *testing.T) {
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.Transport = "tcp"
	spec.Syslog.TCPFraming = "weird"
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "TCPFraming") {
		t.Errorf("err=%v, want contains 'TCPFraming'", err)
	}
}

func TestSyslogValidate_MsgWithLF_NonTransparent(t *testing.T) {
	// TCP non-transparent framing forbids LF in MSG (RFC 6587 §4).
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.Transport = "tcp"
	spec.Syslog.TCPFraming = "non_transparent"
	spec.Syslog.Msg = "line1\nline2"
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "LF") {
		t.Errorf("err=%v, want contains 'LF'", err)
	}
}

func TestSyslogValidate_MsgWithLF_OctetCountingOk(t *testing.T) {
	// TCP octet-counting framing allows LF in MSG (length prefix delimiting).
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.Transport = "tcp"
	spec.Syslog.TCPFraming = "octet_counting"
	spec.Syslog.Msg = "line1\nline2"
	if err := p.Validate(spec); err != nil {
		t.Errorf("Msg LF in octet-counting should pass: %v", err)
	}
}

// --- Validate: field length limits ---

func TestSyslogValidate_HostnameTooLong(t *testing.T) {
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.Hostname = strings.Repeat("a", 256)
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "HOSTNAME") {
		t.Errorf("err=%v, want contains 'HOSTNAME'", err)
	}
}

func TestSyslogValidate_HostnameContainsSP(t *testing.T) {
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.Hostname = "host name"
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "HOSTNAME") || !strings.Contains(err.Error(), "SP") {
		t.Errorf("err=%v, want contains 'HOSTNAME' and 'SP'", err)
	}
}

func TestSyslogValidate_AppNameTooLong(t *testing.T) {
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.AppName = strings.Repeat("a", 49)
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "APP-NAME") {
		t.Errorf("err=%v, want contains 'APP-NAME'", err)
	}
}

func TestSyslogValidate_ProcIDTooLong(t *testing.T) {
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.ProcID = strings.Repeat("a", 129)
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "PROCID") {
		t.Errorf("err=%v, want contains 'PROCID'", err)
	}
}

func TestSyslogValidate_MsgIDTooLong(t *testing.T) {
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.MsgID = strings.Repeat("a", 33)
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "MSGID") {
		t.Errorf("err=%v, want contains 'MSGID'", err)
	}
}

// --- Validate: TIMESTAMP ---

func TestSyslogValidate_TimestampInvalid(t *testing.T) {
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.Timestamp = "not-a-timestamp"
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "Timestamp") {
		t.Errorf("err=%v, want contains 'Timestamp'", err)
	}
}

func TestSyslogValidate_TimestampRFC3339Valid(t *testing.T) {
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.Timestamp = "2026-07-28T10:00:00Z"
	if err := p.Validate(spec); err != nil {
		t.Errorf("RFC 3339 timestamp should pass: %v", err)
	}
}

func TestSyslogValidate_TimestampNILVALUE(t *testing.T) {
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.Timestamp = "-"
	if err := p.Validate(spec); err != nil {
		t.Errorf("NILVALUE '-' timestamp should pass: %v", err)
	}
}

// --- Validate: STRUCTURED-DATA ---

func TestSyslogValidate_SDUnclosed(t *testing.T) {
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.StructuredData = []string{"[origin ip=\"1.2.3.4\""} // missing ]
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "unclosed") {
		t.Errorf("err=%v, want contains 'unclosed'", err)
	}
}

func TestSyslogValidate_SDEmpty(t *testing.T) {
	// Empty element in the list is invalid (use nil slice for NILVALUE).
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.StructuredData = []string{""}
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "empty") {
		t.Errorf("err=%v, want contains 'empty'", err)
	}
}

func TestSyslogValidate_SDIDTooLong(t *testing.T) {
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.StructuredData = []string{"[" + strings.Repeat("a", 33) + "]"}
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "SD-ID") {
		t.Errorf("err=%v, want contains 'SD-ID'", err)
	}
}

// --- Plan: PRI encoding ---

// Testcase 1.1.1.1: Facility=0 (kern) + Severity=6 (info) -> PRI=`<6>`
func TestSyslogPlan_PRIPrefix_KernInfo(t *testing.T) {
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.Facility = 0
	spec.Syslog.Severity = 6
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) != 1 {
		t.Fatalf("len=%d, want 1", len(cfgs))
	}
	if !bytes.HasPrefix(cfgs[0].Payload, []byte("<6>1 ")) {
		t.Errorf("payload starts with %q, want '<6>1 ' (Facility=0, Severity=6 -> PRI=6)", cfgs[0].Payload[:min(10, len(cfgs[0].Payload))])
	}
}

// Testcase 1.1.1.16: Facility=15 (local0) + Severity=6 -> PRI=126
func TestSyslogPlan_PRIPrefix_Local0Info(t *testing.T) {
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.Facility = 15
	spec.Syslog.Severity = 6
	cfgs := drain(mustPlan(t, p, spec))
	if !bytes.HasPrefix(cfgs[0].Payload, []byte("<126>1 ")) {
		t.Errorf("payload starts with %q, want '<126>1 '", cfgs[0].Payload[:min(10, len(cfgs[0].Payload))])
	}
}

// --- Plan: default field values are NILVALUE (RFC 5424 §3.2.2) ---

// Testcase 4.1.3: spec.Syslog={Facility:0, Severity:0, Version:1} -> `<0>1 - - - - - -`
// With all explicit fields empty, output uses NILVALUE for each.
func TestSyslogPlan_MinimalMessage_NILVALUE(t *testing.T) {
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog = &core.SyslogConfig{
		Facility: 0, Severity: 0, Version: 1,
	}
	cfgs := drain(mustPlan(t, p, spec))
	want := "<0>1 - - - - - -"
	if string(cfgs[0].Payload) != want {
		t.Errorf("payload=%q, want %q", cfgs[0].Payload, want)
	}
}

// Testcase 4.1.4: spec.Syslog={..., Msg:""} -> `<0>1 - - - - - -` (no MSG, no trailing SP)
// Per RFC 5424 §6.2.9, an empty MSG is omitted entirely (no SP, no BOM).
// This is the canonical NILVALUE form, see testcase 4.5.1.
func TestSyslogPlan_EmptyMsg_NoTrailingSP(t *testing.T) {
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog = &core.SyslogConfig{
		Facility: 0, Severity: 0, Version: 1,
		Msg: "",
	}
	cfgs := drain(mustPlan(t, p, spec))
	want := "<0>1 - - - - - -" // no trailing SP (MSG omitted)
	if string(cfgs[0].Payload) != want {
		t.Errorf("payload=%q, want %q", cfgs[0].Payload, want)
	}
}

// --- Plan: TIMESTAMP handling ---

// Empty timestamp -> NILVALUE "-".
func TestSyslogPlan_TimestampEmpty_NILVALUE(t *testing.T) {
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.Timestamp = ""
	cfgs := drain(mustPlan(t, p, spec))
	// Format: <PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD MSG
	// First 4 bytes are "<134>1 " (16*8+6=134, version 1, space).
	// Next is TIMESTAMP field up to next SP. Empty Timestamp -> "-".
	if !bytes.HasPrefix(cfgs[0].Payload, []byte("<134>1 - ")) {
		t.Errorf("payload starts with %q, want '<134>1 - '", cfgs[0].Payload[:min(12, len(cfgs[0].Payload))])
	}
}

// "-" timestamp -> NILVALUE "-".
func TestSyslogPlan_TimestampDash_NILVALUE(t *testing.T) {
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.Timestamp = "-"
	cfgs := drain(mustPlan(t, p, spec))
	if !bytes.HasPrefix(cfgs[0].Payload, []byte("<134>1 - ")) {
		t.Errorf("payload starts with %q, want '<134>1 - '", cfgs[0].Payload[:min(12, len(cfgs[0].Payload))])
	}
}

// User-supplied RFC 3339 timestamp emitted as-is.
func TestSyslogPlan_TimestampRFC3339(t *testing.T) {
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.Timestamp = "2026-07-28T10:00:00Z"
	cfgs := drain(mustPlan(t, p, spec))
	if !bytes.Contains(cfgs[0].Payload, []byte("2026-07-28T10:00:00Z")) {
		t.Errorf("payload missing user timestamp, got %q", cfgs[0].Payload)
	}
}

// Pre-formatted BSD timestamp emitted verbatim (RFC 3164 §4.1.2).
// When Format=bsd and Timestamp is a non-RFC3339 string, encodeBSD emits it
// verbatim rather than reformatting. This guards the verbatim branch in
// planner.go:634-639 (timestampWritten flag) against regression — e.g. a
// change that drops timestampWritten would append the auto-generated "now"
// timestamp after the user value, corrupting the payload.
func TestSyslogPlan_BSD_PreFormattedTimestampVerbatim(t *testing.T) {
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.Format = "bsd"
	spec.Syslog.Version = 0 // BSD has no VERSION field
	spec.Syslog.Timestamp = "Jan  1 00:00:01"
	cfgs := drain(mustPlan(t, p, spec))
	// The pre-formatted timestamp must appear verbatim in the payload,
	// exactly once (no duplicate auto-generated timestamp appended).
	body := string(cfgs[0].Payload)
	if !strings.Contains(body, "Jan  1 00:00:01") {
		t.Errorf("payload missing verbatim BSD timestamp, got %q", body)
	}
	// Count occurrences: the user timestamp must appear exactly once. A
	// broken timestampWritten flag would emit it once verbatim AND then
	// again from the now-UTC branch, or emit only the now-UTC value.
	if n := strings.Count(body, "Jan  1 00:00:01"); n != 1 {
		t.Errorf("verbatim BSD timestamp appears %d times, want 1; payload=%q", n, body)
	}
}

// --- Plan: STRUCTURED-DATA ---

// Testcase 1.8.1.1: StructuredData=`[origin ip="192.0.2.1"]` -> 24 bytes pre-frame
// The full pre-framed form is passed as-is.
func TestSyslogPlan_SDElement_Single(t *testing.T) {
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.StructuredData = []string{`[origin ip="192.0.2.1"]`}
	cfgs := drain(mustPlan(t, p, spec))
	if !bytes.Contains(cfgs[0].Payload, []byte(`[origin ip="192.0.2.1"]`)) {
		t.Errorf("payload missing SD element, got %q", cfgs[0].Payload)
	}
}

// Testcase 1.8.2.1: Multiple SD-ELEMENTs concatenated without spaces.
func TestSyslogPlan_SDElement_Multiple(t *testing.T) {
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.StructuredData = []string{
		`[origin ip="192.0.2.1"]`,
		`[meta sequenceId="1"]`,
	}
	cfgs := drain(mustPlan(t, p, spec))
	if !bytes.Contains(cfgs[0].Payload, []byte(`[origin ip="192.0.2.1"][meta sequenceId="1"]`)) {
		t.Errorf("payload missing concatenated SD elements, got %q", cfgs[0].Payload)
	}
}

// Testcase 1.8.3.1: SD-ID with PEN.
func TestSyslogPlan_SDElement_WithPEN(t *testing.T) {
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.StructuredData = []string{`[eventID@32473 id="1234"]`}
	cfgs := drain(mustPlan(t, p, spec))
	if !bytes.Contains(cfgs[0].Payload, []byte(`[eventID@32473 id="1234"]`)) {
		t.Errorf("payload missing SD with PEN, got %q", cfgs[0].Payload)
	}
}

// Testcase 1.8.4.1: PARAM-VALUE escape for `"`. User pre-escapes, planner
// trusts (Validate checks framing only).
func TestSyslogPlan_SDElement_EscapedQuote(t *testing.T) {
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.StructuredData = []string{`[x val="say \"hi\""]`}
	cfgs := drain(mustPlan(t, p, spec))
	if !bytes.Contains(cfgs[0].Payload, []byte(`[x val="say \"hi\""]`)) {
		t.Errorf("payload missing escaped SD, got %q", cfgs[0].Payload)
	}
}

// Bare form (no brackets) is auto-wrapped.
func TestSyslogPlan_SDElement_BareFormWrapped(t *testing.T) {
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.StructuredData = []string{`origin ip="192.0.2.1"`}
	cfgs := drain(mustPlan(t, p, spec))
	if !bytes.Contains(cfgs[0].Payload, []byte(`[origin ip="192.0.2.1"]`)) {
		t.Errorf("bare SD not wrapped, got %q", cfgs[0].Payload)
	}
}

// --- Plan: MSG / UTF-8 BOM ---

// Testcase 3.9.1: ASCII MSG + MsgHasBOM=false -> SP + MSG (no BOM)
func TestSyslogPlan_Msg_ASCII_NoBOM(t *testing.T) {
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.Msg = "hello"
	spec.Syslog.MsgHasBOM = false
	cfgs := drain(mustPlan(t, p, spec))
	// Payload ends with "SP hello".
	if !bytes.HasSuffix(cfgs[0].Payload, []byte(" hello")) {
		t.Errorf("payload does not end with ' hello', got %q", cfgs[0].Payload)
	}
}

// Testcase 3.9.2: ASCII MSG + MsgHasBOM=true -> BOM + MSG (no SP)
func TestSyslogPlan_Msg_ASCII_WithBOM(t *testing.T) {
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.Msg = "hello"
	spec.Syslog.MsgHasBOM = true
	cfgs := drain(mustPlan(t, p, spec))
	wantSuffix := append([]byte{0xEF, 0xBB, 0xBF}, []byte("hello")...)
	if !bytes.HasSuffix(cfgs[0].Payload, wantSuffix) {
		t.Errorf("payload does not end with BOM+hello, got %q", cfgs[0].Payload)
	}
}

// Testcase 3.13.3: empty MSG + MsgHasBOM=true -> no BOM (MSG missing)
func TestSyslogPlan_Msg_Empty_WithBOMNoBOM(t *testing.T) {
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.Msg = ""
	spec.Syslog.MsgHasBOM = true
	cfgs := drain(mustPlan(t, p, spec))
	// No BOM (0xEF 0xBB 0xBF) should appear.
	if bytes.Contains(cfgs[0].Payload, []byte{0xEF, 0xBB, 0xBF}) {
		t.Errorf("BOM should not appear when Msg is empty, got %q", cfgs[0].Payload)
	}
}

// Testcase 3.8.1: UTF-8 MSG with BOM.
func TestSyslogPlan_Msg_UTF8_WithBOM(t *testing.T) {
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.Msg = "系统已启动"
	spec.Syslog.MsgHasBOM = true
	cfgs := drain(mustPlan(t, p, spec))
	wantSuffix := append([]byte{0xEF, 0xBB, 0xBF}, []byte("系统已启动")...)
	if !bytes.HasSuffix(cfgs[0].Payload, wantSuffix) {
		t.Errorf("payload does not end with BOM+utf8, got %q", cfgs[0].Payload)
	}
}

// --- Plan: BSD format (RFC 3164) ---

// Testcase 1.10.1: Format=bsd + Facility=13 + Severity=5 + (timestamp 2026-07-28)
// -> `<13>Jul 28 10:00:00 host1 sshd[1234]: Login from alice`
func TestSyslogPlan_BSD_BasicMessage(t *testing.T) {
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.Format = "bsd"
	spec.Syslog.Facility = 13
	spec.Syslog.Severity = 5
	spec.Syslog.Timestamp = "2026-07-28T10:00:00Z"
	spec.Syslog.Hostname = "host1"
	spec.Syslog.AppName = "sshd"
	spec.Syslog.ProcID = "1234"
	spec.Syslog.Msg = "Login from alice"
	cfgs := drain(mustPlan(t, p, spec))
	// PRI = 13*8+5 = 109.
	// Format: <PRI>TIMESTAMP SP HOSTNAME SP TAG[PID]: SP MSG
	want := "<109>Jul 28 10:00:00 host1 sshd[1234]: Login from alice"
	if string(cfgs[0].Payload) != want {
		t.Errorf("payload=%q, want %q", cfgs[0].Payload, want)
	}
}

// Testcase 1.10.3: BSD + no PID -> `sshd: Login` (no [PID])
func TestSyslogPlan_BSD_NoPID(t *testing.T) {
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.Format = "bsd"
	spec.Syslog.Timestamp = "2026-07-28T10:00:00Z"
	spec.Syslog.Hostname = "host1"
	spec.Syslog.AppName = "sshd"
	spec.Syslog.ProcID = "" // empty
	spec.Syslog.Msg = "Login"
	cfgs := drain(mustPlan(t, p, spec))
	if !bytes.HasSuffix(cfgs[0].Payload, []byte("sshd: Login")) {
		t.Errorf("payload does not end with 'sshd: Login', got %q", cfgs[0].Payload)
	}
}

// Testcase 1.3.2.1: BSD timestamp format "Jul 28 10:00:00" (15 bytes).
func TestSyslogPlan_BSD_Timestamp_Format(t *testing.T) {
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.Format = "bsd"
	spec.Syslog.Timestamp = "2026-07-28T10:00:00Z"
	cfgs := drain(mustPlan(t, p, spec))
	// PRI + space + "Jul 28 10:00:00" -> "<134>Jul 28 10:00:00 ..."
	wantPrefix := []byte("Jul 28 10:00:00")
	if !bytes.Contains(cfgs[0].Payload, wantPrefix) {
		t.Errorf("payload missing BSD timestamp, got %q", cfgs[0].Payload)
	}
}

// Testcase 1.3.2.2: BSD timestamp with day 1-9 -> space-padded "Jan  5".
func TestSyslogPlan_BSD_Timestamp_DayPadding(t *testing.T) {
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.Format = "bsd"
	spec.Syslog.Timestamp = "2026-01-05T03:04:05Z"
	cfgs := drain(mustPlan(t, p, spec))
	// Day 5 should be space-padded: "Jan  5 03:04:05"
	wantPrefix := []byte("Jan  5 03:04:05")
	if !bytes.Contains(cfgs[0].Payload, wantPrefix) {
		t.Errorf("payload missing day-padded BSD timestamp, got %q", cfgs[0].Payload)
	}
}

// --- Plan: Count (multi-message flow) ---

// Testcase 2.6.1: Count=0 -> defaults to 1 message
func TestSyslogPlan_CountZero_DefaultsOne(t *testing.T) {
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.Count = 0
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) != 1 {
		t.Errorf("len=%d, want 1 (Count=0 defaults to 1)", len(cfgs))
	}
}

// Testcase 2.6.3: Count=10 -> 10 packets
func TestSyslogPlan_Count10(t *testing.T) {
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.Count = 10
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) != 10 {
		t.Errorf("len=%d, want 10", len(cfgs))
	}
	// PacketIndex should be 0-9.
	for i, cfg := range cfgs {
		if cfg.PacketIndex != uint64(i) {
			t.Errorf("cfgs[%d].PacketIndex=%d, want %d", i, cfg.PacketIndex, i)
		}
	}
}

// Testcase 3.3.1: UDP, Count=10 -> all packets Direction="up"
func TestSyslogPlan_UDPDirection_Up(t *testing.T) {
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.Count = 5
	cfgs := drain(mustPlan(t, p, spec))
	for i, cfg := range cfgs {
		if cfg.Direction != "up" {
			t.Errorf("cfgs[%d].Direction=%s, want 'up'", i, cfg.Direction)
		}
	}
}

// --- Plan: TCP mode (handshake + frames + teardown) ---

// Testcase 2.2.1: TCP transport -> 3 (handshake) + N (frames) + 4 (teardown) packets
func TestSyslogPlan_TCP_HandshakeTeardown(t *testing.T) {
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.Transport = "tcp"
	spec.Syslog.Count = 1
	cfgs := drain(mustPlan(t, p, spec))
	// 3 handshake + 1 frame + 4 teardown = 8 packets
	if len(cfgs) != 8 {
		t.Errorf("len=%d, want 8 (3+1+4)", len(cfgs))
	}
	// First 3 are SYN(0x02), SYN-ACK(0x12), ACK(0x10).
	if cfgs[0].L4.Flags != 0x02 {
		t.Errorf("cfgs[0].Flags=%#x, want 0x02 (SYN)", cfgs[0].L4.Flags)
	}
	if cfgs[1].L4.Flags != 0x12 {
		t.Errorf("cfgs[1].Flags=%#x, want 0x12 (SYN-ACK)", cfgs[1].L4.Flags)
	}
	if cfgs[2].L4.Flags != 0x10 {
		t.Errorf("cfgs[2].Flags=%#x, want 0x10 (ACK)", cfgs[2].L4.Flags)
	}
	// PSH-ACK frame(s) at index 3.
	if cfgs[3].L4.Flags != 0x18 {
		t.Errorf("cfgs[3].Flags=%#x, want 0x18 (PSH-ACK)", cfgs[3].L4.Flags)
	}
	// Last 4 are FIN-ACK(0x11), ACK(0x10), FIN-ACK(0x11), ACK(0x10).
	last4 := []uint8{cfgs[4].L4.Flags, cfgs[5].L4.Flags, cfgs[6].L4.Flags, cfgs[7].L4.Flags}
	wantLast4 := []uint8{0x11, 0x10, 0x11, 0x10}
	for i := range wantLast4 {
		if last4[i] != wantLast4[i] {
			t.Errorf("cfgs[%d].Flags=%#x, want %#x", 4+i, last4[i], wantLast4[i])
		}
	}
}

// Testcase 3.4.1: TCP octet-counting frame = `<len> SP <full-msg> LF`.
// The planner frames the entire RFC 5424 message (not just Msg). For our
// spec the full message is "<134>1 - server01 cron - HEARTBEAT - hello"
// (42 bytes), so the frame is "42 <full-msg>\n" (45 bytes).
func TestSyslogPlan_TCP_OctetCounting_Frame(t *testing.T) {
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.Transport = "tcp"
	spec.Syslog.TCPFraming = "octet_counting"
	spec.Syslog.Msg = "hello" // 5 bytes
	spec.Syslog.Count = 1
	cfgs := drain(mustPlan(t, p, spec))
	// Frame payload is the PSH-ACK at index 3.
	frame := cfgs[3].Payload
	// Expected: "<len> <msg>\n" where len is the byte length of the
	// syslog message and msg is the full RFC 5424 frame.
	// Encode the message ourselves to compute the expected frame.
	wantMsg := []byte("<134>1 - server01 cron - HEARTBEAT - hello")
	want := []byte(fmt.Sprintf("%d %s\n", len(wantMsg), wantMsg))
	if !bytes.Equal(frame, want) {
		t.Errorf("frame=%q, want %q", frame, want)
	}
}

// Testcase 3.5.1: TCP non-transparent frame = `<full-msg> LF`.
// The planner frames the entire RFC 5424 message; non-transparent just
// appends LF (no length prefix).
func TestSyslogPlan_TCP_NonTransparent_Frame(t *testing.T) {
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.Transport = "tcp"
	spec.Syslog.TCPFraming = "non_transparent"
	spec.Syslog.Msg = "hello"
	spec.Syslog.Count = 1
	cfgs := drain(mustPlan(t, p, spec))
	frame := cfgs[3].Payload
	wantMsg := []byte("<134>1 - server01 cron - HEARTBEAT - hello")
	want := append(wantMsg, '\n')
	if !bytes.Equal(frame, want) {
		t.Errorf("frame=%q, want %q", frame, want)
	}
}

// --- Plan: EtherType for IPv6 (must dual-stack per multicast_ipv6_vlan.md §5) ---

func TestSyslogPlan_IPv6_EtherType(t *testing.T) {
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.SrcIP = "2001:db8::1"
	spec.DstIP = "2001:db8::2"
	cfgs := drain(mustPlan(t, p, spec))
	if cfgs[0].L2.EtherType != 0x86DD {
		t.Errorf("EtherType=%#x, want 0x86DD (IPv6)", cfgs[0].L2.EtherType)
	}
}

func TestSyslogPlan_IPv4_EtherType(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validSyslogSpec()))
	if cfgs[0].L2.EtherType != 0x0800 {
		t.Errorf("EtherType=%#x, want 0x0800 (IPv4)", cfgs[0].L2.EtherType)
	}
}

// --- Plan: UDP/L4 fields ---

func TestSyslogPlan_UDP_L4Fields(t *testing.T) {
	p := NewPlanner()
	spec := validSyslogSpec()
	cfgs := drain(mustPlan(t, p, spec))
	cfg := cfgs[0]
	if cfg.L4.Protocol != "udp" {
		t.Errorf("L4.Protocol=%s, want 'udp'", cfg.L4.Protocol)
	}
	if cfg.L3.Protocol != 17 {
		t.Errorf("L3.Protocol=%d, want 17 (UDP)", cfg.L3.Protocol)
	}
	if cfg.L4.SrcPort != 12345 {
		t.Errorf("SrcPort=%d, want 12345", cfg.L4.SrcPort)
	}
	if cfg.L4.DstPort != 514 {
		t.Errorf("DstPort=%d, want 514 (syslog)", cfg.L4.DstPort)
	}
}

// --- Plan: FlowID format ---

func TestSyslogPlan_FlowID(t *testing.T) {
	p := NewPlanner()
	spec := validSyslogSpec()
	cfgs := drain(mustPlan(t, p, spec))
	want := "10.0.0.1-10.0.0.2-12345-514"
	if cfgs[0].FlowID != want {
		t.Errorf("FlowID=%q, want %q", cfgs[0].FlowID, want)
	}
}

// --- Plan: Metadata ---

func TestSyslogPlan_Metadata_PriorityTransport(t *testing.T) {
	p := NewPlanner()
	spec := validSyslogSpec()
	cfgs := drain(mustPlan(t, p, spec))
	md := cfgs[0].Metadata
	if md["syslog_priority"].(int) != 134 {
		t.Errorf("syslog_priority=%v, want 134", md["syslog_priority"])
	}
	if md["syslog_transport"].(string) != "udp" {
		t.Errorf("syslog_transport=%v, want 'udp'", md["syslog_transport"])
	}
}

// --- Plan: SignBlocks (RFC 5848) ---

// Testcase 3.14.1: SignBlocks=["signature1"] -> STRUCTURED-DATA contains sign SD-ELEMENT.
func TestSyslogPlan_SignBlocks_Single(t *testing.T) {
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.SignBlocks = []string{"signature1"}
	cfgs := drain(mustPlan(t, p, spec))
	want := `[sign@32473 signature="signature1"]`
	if !bytes.Contains(cfgs[0].Payload, []byte(want)) {
		t.Errorf("payload missing sign block, got %q", cfgs[0].Payload)
	}
}

// Testcase 3.14.2: Multiple SignBlocks -> multiple sign SD-ELEMENTs.
func TestSyslogPlan_SignBlocks_Multiple(t *testing.T) {
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.SignBlocks = []string{"sig1", "sig2"}
	cfgs := drain(mustPlan(t, p, spec))
	if !bytes.Contains(cfgs[0].Payload, []byte(`[sign@32473 signature="sig1"][sign@32473 signature="sig2"]`)) {
		t.Errorf("payload missing multiple sign blocks, got %q", cfgs[0].Payload)
	}
}

// Testcase 3.14.3: base64 signature with `+` `/` `=` chars.
func TestSyslogPlan_SignBlocks_Base64Chars(t *testing.T) {
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.SignBlocks = []string{"a+b/c="}
	cfgs := drain(mustPlan(t, p, spec))
	want := `[sign@32473 signature="a+b/c="]`
	if !bytes.Contains(cfgs[0].Payload, []byte(want)) {
		t.Errorf("payload missing base64 sign block, got %q", cfgs[0].Payload)
	}
}

// Sign block value with `"` gets escaped.
func TestSyslogPlan_SignBlocks_EscapedQuote(t *testing.T) {
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.SignBlocks = []string{`has"quote`}
	cfgs := drain(mustPlan(t, p, spec))
	want := `[sign@32473 signature="has\"quote"]`
	if !bytes.Contains(cfgs[0].Payload, []byte(want)) {
		t.Errorf("payload missing escaped sign block, got %q", cfgs[0].Payload)
	}
}

// --- Plan: TTL default ---

func TestSyslogPlan_TTLDefault(t *testing.T) {
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.TTL = 0
	cfgs := drain(mustPlan(t, p, spec))
	if cfgs[0].L3.TTL != 64 {
		t.Errorf("TTL=%d, want 64 (DefaultTTL)", cfgs[0].L3.TTL)
	}
}

func TestSyslogPlan_TTLProvided(t *testing.T) {
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.TTL = 128
	cfgs := drain(mustPlan(t, p, spec))
	if cfgs[0].L3.TTL != 128 {
		t.Errorf("TTL=%d, want 128", cfgs[0].L3.TTL)
	}
}

// --- Plan: Validate fail returns nil channel ---

func TestSyslogPlan_ValidateFail_NilChannel(t *testing.T) {
	p := NewPlanner()
	spec := validSyslogSpec()
	spec.Syslog.Facility = 100 // invalid
	ch, err := p.Plan(context.Background(), spec)
	if err == nil {
		t.Error("expected error")
	}
	if ch != nil {
		t.Error("expected nil channel")
	}
}

// min is a tiny helper to avoid pulling in the new min() builtin at Go 1.21+
// which isn't available in older Go versions.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
