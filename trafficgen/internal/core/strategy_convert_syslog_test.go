package core

// Tests for the Syslog structured-data (SD) structured-form parser
// (parseSyslogStructuredData) and the per-message parser
// (parseSyslogMessages). These test the strategy_convert layer that
// sits between the JSON config and the planner.
//
// Spec-driven (RFC 5424 §6.2.8 + design_syslog.md §1.8 + testcases
// §3.3.2 / §3.4.2). Each test fails BEFORE the corresponding fix:
//   - DeterministicOrder fails before the sort.Strings fix (map
//     iteration was randomized, so the wire output varied across runs).
//   - StructuredForm_NoParams passes only after the `id`-only branch.
//   - parseSyslogMessages tests fail before the new helper exists.

import (
	"strings"
	"testing"
)

// --- parseSyslogStructuredData: structured map form ---

// Testcase 1.8.1.1 via structured form: {id:"origin",
// parameters:{ip:"192.0.2.1"}} -> "[origin ip=\"192.0.2.1\"]".
func TestParseSyslogStructuredData_StructuredForm_SingleParam(t *testing.T) {
	in := []interface{}{
		map[string]interface{}{
			"id":         "origin",
			"parameters": map[string]interface{}{"ip": "192.0.2.1"},
		},
	}
	out := parseSyslogStructuredData(in)
	if len(out) != 1 {
		t.Fatalf("len=%d, want 1", len(out))
	}
	want := `[origin ip="192.0.2.1"]`
	if out[0] != want {
		t.Errorf("out[0]=%q, want %q", out[0], want)
	}
}

// Testcase 1.8.3.1 via structured form: {id:"eventID@32473",
// parameters:{id:"1234"}} -> "[eventID@32473 id=\"1234\"]".
func TestParseSyslogStructuredData_StructuredForm_WithPEN(t *testing.T) {
	in := []interface{}{
		map[string]interface{}{
			"id":         "eventID@32473",
			"parameters": map[string]interface{}{"id": "1234"},
		},
	}
	out := parseSyslogStructuredData(in)
	if len(out) != 1 {
		t.Fatalf("len=%d, want 1", len(out))
	}
	want := `[eventID@32473 id="1234"]`
	if out[0] != want {
		t.Errorf("out[0]=%q, want %q", out[0], want)
	}
}

// Testcase 1.8.1.3 via structured form: {id:"x"} (no params) -> "[x]".
func TestParseSyslogStructuredData_StructuredForm_NoParams(t *testing.T) {
	in := []interface{}{
		map[string]interface{}{"id": "x"},
	}
	out := parseSyslogStructuredData(in)
	if len(out) != 1 {
		t.Fatalf("len=%d, want 1", len(out))
	}
	want := `[x]`
	if out[0] != want {
		t.Errorf("out[0]=%q, want %q", out[0], want)
	}
}

// Testcase 1.8.2.1: multiple structured-form SD elements concatenated.
func TestParseSyslogStructuredData_StructuredForm_Multiple(t *testing.T) {
	in := []interface{}{
		map[string]interface{}{
			"id":         "origin",
			"parameters": map[string]interface{}{"ip": "192.0.2.1"},
		},
		map[string]interface{}{
			"id":         "meta",
			"parameters": map[string]interface{}{"sequenceId": "1"},
		},
	}
	out := parseSyslogStructuredData(in)
	if len(out) != 2 {
		t.Fatalf("len=%d, want 2", len(out))
	}
	want0 := `[origin ip="192.0.2.1"]`
	want1 := `[meta sequenceId="1"]`
	if out[0] != want0 {
		t.Errorf("out[0]=%q, want %q", out[0], want0)
	}
	if out[1] != want1 {
		t.Errorf("out[1]=%q, want %q", out[1], want1)
	}
}

// Testcase 3.7.1 (multi-param): two parameters in one SD element.
// The wire output must be DETERMINISTIC across runs (sorted key order).
// Without the sort.Strings fix, this test would flake on runs where Go's
// randomized map iteration put sysUpTime before sequenceId.
func TestParseSyslogStructuredData_StructuredForm_DeterministicMultiParam(t *testing.T) {
	in := []interface{}{
		map[string]interface{}{
			"id": "meta",
			"parameters": map[string]interface{}{
				"sequenceId": "1234",
				"sysUpTime":  "0",
			},
		},
	}
	// Run many times to catch any non-determinism from map iteration.
	var last string
	for i := 0; i < 50; i++ {
		out := parseSyslogStructuredData(in)
		if len(out) != 1 {
			t.Fatalf("iter %d: len=%d, want 1", i, len(out))
		}
		if last != "" && out[0] != last {
			t.Fatalf("iter %d: non-deterministic output: was %q, now %q", i, last, out[0])
		}
		last = out[0]
	}
	// With sorted keys: sequenceId < sysUpTime (alphabetical), so the
	// output is `[meta sequenceId="1234" sysUpTime="0"]`.
	want := `[meta sequenceId="1234" sysUpTime="0"]`
	if last != want {
		t.Errorf("out=%q, want %q (sorted keys)", last, want)
	}
}

// Testcase 1.8.4.1: PARAM-VALUE with `"` must be escaped to `\"` when
// built via the structured form (the parser calls escapeSDValue).
func TestParseSyslogStructuredData_StructuredForm_EscapeQuote(t *testing.T) {
	in := []interface{}{
		map[string]interface{}{
			"id":         "x",
			"parameters": map[string]interface{}{"val": `say "hi"`},
		},
	}
	out := parseSyslogStructuredData(in)
	if len(out) != 1 {
		t.Fatalf("len=%d, want 1", len(out))
	}
	want := `[x val="say \"hi\""]`
	if out[0] != want {
		t.Errorf("out[0]=%q, want %q", out[0], want)
	}
}

// Testcase 1.8.4.2: PARAM-VALUE with `\` must be escaped to `\\`.
func TestParseSyslogStructuredData_StructuredForm_EscapeBackslash(t *testing.T) {
	in := []interface{}{
		map[string]interface{}{
			"id":         "x",
			"parameters": map[string]interface{}{"val": `a\b`},
		},
	}
	out := parseSyslogStructuredData(in)
	if len(out) != 1 {
		t.Fatalf("len=%d, want 1", len(out))
	}
	want := `[x val="a\\b"]`
	if out[0] != want {
		t.Errorf("out[0]=%q, want %q", out[0], want)
	}
}

// Testcase 1.8.4.3: PARAM-VALUE with `]` must be escaped to `\]`.
func TestParseSyslogStructuredData_StructuredForm_EscapeRightBracket(t *testing.T) {
	in := []interface{}{
		map[string]interface{}{
			"id":         "x",
			"parameters": map[string]interface{}{"val": "a]b"},
		},
	}
	out := parseSyslogStructuredData(in)
	if len(out) != 1 {
		t.Fatalf("len=%d, want 1", len(out))
	}
	want := `[x val="a\]b"]`
	if out[0] != want {
		t.Errorf("out[0]=%q, want %q", out[0], want)
	}
}

// Testcase 1.8.4.4: PARAM-VALUE with UTF-8 Chinese chars preserved.
func TestParseSyslogStructuredData_StructuredForm_UTF8Value(t *testing.T) {
	in := []interface{}{
		map[string]interface{}{
			"id":         "x",
			"parameters": map[string]interface{}{"val": "系统"},
		},
	}
	out := parseSyslogStructuredData(in)
	if len(out) != 1 {
		t.Fatalf("len=%d, want 1", len(out))
	}
	want := `[x val="系统"]`
	if out[0] != want {
		t.Errorf("out[0]=%q, want %q", out[0], want)
	}
}

// String form (pre-framed) is passed through unchanged.
func TestParseSyslogStructuredData_StringForm_Passthrough(t *testing.T) {
	in := []interface{}{`[origin ip="192.0.2.1"]`}
	out := parseSyslogStructuredData(in)
	if len(out) != 1 {
		t.Fatalf("len=%d, want 1", len(out))
	}
	want := `[origin ip="192.0.2.1"]`
	if out[0] != want {
		t.Errorf("out[0]=%q, want %q", out[0], want)
	}
}

// Mixed string + structured entries.
func TestParseSyslogStructuredData_MixedForms(t *testing.T) {
	in := []interface{}{
		`[origin ip="192.0.2.1"]`, // pre-framed string
		map[string]interface{}{    // structured
			"id":         "meta",
			"parameters": map[string]interface{}{"sequenceId": "1"},
		},
	}
	out := parseSyslogStructuredData(in)
	if len(out) != 2 {
		t.Fatalf("len=%d, want 2", len(out))
	}
	if out[0] != `[origin ip="192.0.2.1"]` {
		t.Errorf("out[0]=%q", out[0])
	}
	if out[1] != `[meta sequenceId="1"]` {
		t.Errorf("out[1]=%q", out[1])
	}
}

// Empty / nil / non-list inputs return nil.
func TestParseSyslogStructuredData_NilInputs(t *testing.T) {
	cases := []interface{}{nil, "", 42, "hello", map[string]interface{}{"id": "x"}}
	for i, in := range cases {
		out := parseSyslogStructuredData(in)
		if out != nil {
			t.Errorf("case %d: in=%v -> out=%v, want nil", i, in, out)
		}
	}
}

// Empty string entries are filtered out.
func TestParseSyslogStructuredData_EmptyStringFiltered(t *testing.T) {
	in := []interface{}{"", `[x]`, ""}
	out := parseSyslogStructuredData(in)
	if len(out) != 1 {
		t.Fatalf("len=%d, want 1 (empty filtered)", len(out))
	}
	if out[0] != `[x]` {
		t.Errorf("out[0]=%q, want '[x]'", out[0])
	}
}

// Structured entry with empty id is skipped.
func TestParseSyslogStructuredData_EmptyIDSkipped(t *testing.T) {
	in := []interface{}{
		map[string]interface{}{"id": ""}, // skipped
		map[string]interface{}{"id": "x"},
	}
	out := parseSyslogStructuredData(in)
	if len(out) != 1 {
		t.Fatalf("len=%d, want 1 (empty id skipped)", len(out))
	}
	if out[0] != `[x]` {
		t.Errorf("out[0]=%q, want '[x]'", out[0])
	}
}

// --- parseSyslogMessages: per-message overrides ---

// Testcase 3.4.2: two messages with different Msg -> two override entries.
func TestParseSyslogMessages_TwoMessages(t *testing.T) {
	in := []interface{}{
		map[string]interface{}{"msg": "hi"},
		map[string]interface{}{"msg": "world"},
	}
	out := parseSyslogMessages(in)
	if len(out) != 2 {
		t.Fatalf("len=%d, want 2", len(out))
	}
	if out[0].Msg != "hi" {
		t.Errorf("out[0].Msg=%q, want 'hi'", out[0].Msg)
	}
	if out[1].Msg != "world" {
		t.Errorf("out[1].Msg=%q, want 'world'", out[1].Msg)
	}
}

// Testcase 3.3.2: per-message SD with incrementing sequenceId.
func TestParseSyslogMessages_PerMessageSD(t *testing.T) {
	in := []interface{}{
		map[string]interface{}{"structured_data": []interface{}{`[meta sequenceId="1"]`}},
		map[string]interface{}{"structured_data": []interface{}{`[meta sequenceId="2"]`}},
	}
	out := parseSyslogMessages(in)
	if len(out) != 2 {
		t.Fatalf("len=%d, want 2", len(out))
	}
	if len(out[0].StructuredData) != 1 || out[0].StructuredData[0] != `[meta sequenceId="1"]` {
		t.Errorf("out[0].SD=%v, want [meta sequenceId=\"1\"]", out[0].StructuredData)
	}
	if len(out[1].StructuredData) != 1 || out[1].StructuredData[0] != `[meta sequenceId="2"]` {
		t.Errorf("out[1].SD=%v, want [meta sequenceId=\"2\"]", out[1].StructuredData)
	}
}

// Per-message structured SD (map form) is parsed via parseSyslogStructuredData.
func TestParseSyslogMessages_PerMessageStructuredSD(t *testing.T) {
	in := []interface{}{
		map[string]interface{}{
			"structured_data": []interface{}{
				map[string]interface{}{
					"id":         "meta",
					"parameters": map[string]interface{}{"sequenceId": "1"},
				},
			},
		},
	}
	out := parseSyslogMessages(in)
	if len(out) != 1 {
		t.Fatalf("len=%d, want 1", len(out))
	}
	if len(out[0].StructuredData) != 1 {
		t.Fatalf("SD len=%d, want 1", len(out[0].StructuredData))
	}
	want := `[meta sequenceId="1"]`
	if out[0].StructuredData[0] != want {
		t.Errorf("SD=%q, want %q", out[0].StructuredData[0], want)
	}
}

// Per-message MsgID override.
func TestParseSyslogMessages_PerMessageMsgID(t *testing.T) {
	in := []interface{}{
		map[string]interface{}{"msg_id": "EVT1"},
		map[string]interface{}{"msg_id": "EVT2"},
	}
	out := parseSyslogMessages(in)
	if len(out) != 2 {
		t.Fatalf("len=%d, want 2", len(out))
	}
	if out[0].MsgID != "EVT1" {
		t.Errorf("out[0].MsgID=%q", out[0].MsgID)
	}
	if out[1].MsgID != "EVT2" {
		t.Errorf("out[1].MsgID=%q", out[1].MsgID)
	}
}

// Per-message MsgHasBOM override.
func TestParseSyslogMessages_PerMessageBOM(t *testing.T) {
	in := []interface{}{
		map[string]interface{}{"msg": "ascii", "msg_has_bom": false},
		map[string]interface{}{"msg": "中文", "msg_has_bom": true},
	}
	out := parseSyslogMessages(in)
	if len(out) != 2 {
		t.Fatalf("len=%d, want 2", len(out))
	}
	if out[0].MsgHasBOM != false {
		t.Errorf("out[0].MsgHasBOM=%v, want false", out[0].MsgHasBOM)
	}
	if out[1].MsgHasBOM != true {
		t.Errorf("out[1].MsgHasBOM=%v, want true", out[1].MsgHasBOM)
	}
}

// Per-message Timestamp override.
func TestParseSyslogMessages_PerMessageTimestamp(t *testing.T) {
	in := []interface{}{
		map[string]interface{}{"timestamp": "2026-01-01T00:00:00Z"},
		map[string]interface{}{"timestamp": "2026-01-02T00:00:00Z"},
	}
	out := parseSyslogMessages(in)
	if len(out) != 2 {
		t.Fatalf("len=%d, want 2", len(out))
	}
	if out[0].Timestamp != "2026-01-01T00:00:00Z" {
		t.Errorf("out[0].Timestamp=%q", out[0].Timestamp)
	}
	if out[1].Timestamp != "2026-01-02T00:00:00Z" {
		t.Errorf("out[1].Timestamp=%q", out[1].Timestamp)
	}
}

// Per-message Hostname/AppName/ProcID overrides.
func TestParseSyslogMessages_PerMessageHostApp(t *testing.T) {
	in := []interface{}{
		map[string]interface{}{
			"hostname": "h1", "app_name": "sshd", "proc_id": "1",
		},
	}
	out := parseSyslogMessages(in)
	if len(out) != 1 {
		t.Fatalf("len=%d, want 1", len(out))
	}
	if out[0].Hostname != "h1" {
		t.Errorf("Hostname=%q", out[0].Hostname)
	}
	if out[0].AppName != "sshd" {
		t.Errorf("AppName=%q", out[0].AppName)
	}
	if out[0].ProcID != "1" {
		t.Errorf("ProcID=%q", out[0].ProcID)
	}
}

// Per-message SignBlocks override.
func TestParseSyslogMessages_PerMessageSignBlocks(t *testing.T) {
	in := []interface{}{
		map[string]interface{}{"sign_blocks": []interface{}{"sig1", "sig2"}},
	}
	out := parseSyslogMessages(in)
	if len(out) != 1 {
		t.Fatalf("len=%d, want 1", len(out))
	}
	if len(out[0].SignBlocks) != 2 {
		t.Fatalf("SignBlocks len=%d, want 2", len(out[0].SignBlocks))
	}
	if out[0].SignBlocks[0] != "sig1" || out[0].SignBlocks[1] != "sig2" {
		t.Errorf("SignBlocks=%v", out[0].SignBlocks)
	}
}

// Empty / nil / non-list inputs return nil.
func TestParseSyslogMessages_NilInputs(t *testing.T) {
	cases := []interface{}{nil, "", 42, "hello", map[string]interface{}{"msg": "x"}}
	for i, in := range cases {
		out := parseSyslogMessages(in)
		if out != nil {
			t.Errorf("case %d: in=%v -> out=%v, want nil", i, in, out)
		}
	}
}

// Empty list returns nil (not an empty slice).
func TestParseSyslogMessages_EmptyList(t *testing.T) {
	out := parseSyslogMessages([]interface{}{})
	if out != nil {
		t.Errorf("empty list -> out=%v, want nil", out)
	}
}

// Non-map entries are skipped.
func TestParseSyslogMessages_NonMapEntriesSkipped(t *testing.T) {
	in := []interface{}{
		"badstring", // skipped
		map[string]interface{}{"msg": "ok"},
		42, // skipped
	}
	out := parseSyslogMessages(in)
	if len(out) != 1 {
		t.Fatalf("len=%d, want 1 (non-map skipped)", len(out))
	}
	if out[0].Msg != "ok" {
		t.Errorf("out[0].Msg=%q, want 'ok'", out[0].Msg)
	}
}

// All-empty entries return nil (filtered to empty -> nil).
func TestParseSyslogMessages_AllEmptyEntries(t *testing.T) {
	in := []interface{}{
		map[string]interface{}{}, // no fields set
	}
	out := parseSyslogMessages(in)
	// An entry with no fields is still a valid SyslogMessage (all
	// inherit from parent); the parser keeps it.
	if len(out) != 1 {
		t.Errorf("len=%d, want 1 (empty entry still valid)", len(out))
	}
}

// --- escapeSDValue helper (RFC 5424 §6.2.8) ---

func TestEscapeSDValue_AllChars(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{`plain`, `plain`},
		{`say "hi"`, `say \"hi\"`},
		{`a\b`, `a\\b`},
		{`a]b`, `a\]b`},
		{`"\]`, `\"\\\]`},
		{`系统`, `系统`}, // UTF-8 preserved
		{``, ``},
	}
	for _, c := range cases {
		got := escapeSDValue(c.in)
		if got != c.want {
			t.Errorf("escapeSDValue(%q)=%q, want %q", c.in, got, c.want)
		}
	}
}

// --- integration: parseSyslogStructuredData result is stable across runs ---

// Run the structured-form parser 100 times on a 3-param SD element to
// catch any non-determinism. Without the sort.Strings fix this would
// fail intermittently.
func TestParseSyslogStructuredData_StableAcrossIterations(t *testing.T) {
	in := []interface{}{
		map[string]interface{}{
			"id": "meta",
			"parameters": map[string]interface{}{
				"sequenceId": "1",
				"sysUpTime":  "2",
				"host":       "h",
			},
		},
	}
	first := parseSyslogStructuredData(in)[0]
	for i := 0; i < 100; i++ {
		got := parseSyslogStructuredData(in)[0]
		if got != first {
			t.Fatalf("iter %d: got %q, want %q (stable)", i, got, first)
		}
	}
	// Sorted keys: host, sequenceId, sysUpTime.
	want := `[meta host="h" sequenceId="1" sysUpTime="2"]`
	if first != want {
		t.Errorf("first=%q, want %q", first, want)
	}
	// Sanity: the keys should be in sorted (alphabetical) order.
	if !strings.HasPrefix(first, `[meta host=`) {
		t.Errorf("first should start with sorted key 'host', got %q", first)
	}
}
