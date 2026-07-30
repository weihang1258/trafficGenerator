package postgresql

// Coverage-gap tests for the PostgreSQL planner, targeting the spec-driven
// gaps identified by /tmp/l7_planner_design/testcases_postgresql.md:
//   - Simple Query error path (ErrorResponse + ReadyForQuery with status 'E'
//     when in a transaction) — §2.2.2, §2.2.5, §2.9.4
//   - Standalone "error" operation — §1.3.10
//   - "notice" operation (NoticeResponse server push) — §1.3.9, §3.11
//   - Describe NoData for non-row-producing statements — §1.3.12.4, §2.3.1.2
//   - Describe ParameterDescription for Mode="statement" — §1.3.12.5
//   - Multi-statement Simple Query (multiple result sets, no intermediate
//     ReadyForQuery) — §2.2.4
//   - Multi-statement mid-query error (subsequent statements cancelled) —
//     §2.2.5
//   - ROLLBACK recovers from failed transaction — §2.2.5.5
//
// These tests are written BEFORE the planner changes (CLAUDE.md §7: failing-
// test-first). They reference fields/methods that the current planner does
// not yet implement (ErrorFields on PGOperation, "error"/"notice" kinds,
// ExpectNoData, multi-statement splitting). They are expected to FAIL on
// the unmodified planner and PASS after the planner is extended.

import (
	"bytes"
	"context"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

// findPayloadsByType returns all packet payloads whose first byte matches
// typeTag, in emit order. Useful for asserting message sequences.
func findPayloadsByType(cfgs []core.PacketConfig, typeTag byte) [][]byte {
	var out [][]byte
	for _, c := range cfgs {
		if len(c.Payload) > 0 && c.Payload[0] == typeTag {
			out = append(out, c.Payload)
		}
	}
	return out
}

// firstPayloadByType returns the first payload matching typeTag, or nil.
func firstPayloadByType(cfgs []core.PacketConfig, typeTag byte) []byte {
	for _, c := range cfgs {
		if len(c.Payload) > 0 && c.Payload[0] == typeTag {
			return c.Payload
		}
	}
	return nil
}

// rfqStatuses returns the ReadyForQuery status bytes in emit order.
func rfqStatuses(cfgs []core.PacketConfig) []byte {
	var out []byte
	for _, c := range cfgs {
		if len(c.Payload) >= 6 && c.Payload[0] == 'Z' {
			out = append(out, c.Payload[5])
		}
	}
	return out
}

// --- §2.2.2 Simple Query error path ---

// TestPGGap_QueryErrorEmitsErrorResponse: a "query" operation with
// ErrorFields set must emit ErrorResponse (E) + ReadyForQuery (Z) instead
// of the normal RowDescription/DataRow/CommandComplete response.
//
// Spec: PostgreSQL §52.2.3 — when a query fails, the server sends
// ErrorResponse then ReadyForQuery. No RowDescription, DataRow, or
// CommandComplete is sent for the failed query.
func TestPGGap_QueryErrorEmitsErrorResponse(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpecNoHandshake()
	spec.PostgreSQL.Operations = []core.PGOperation{
		{
			Kind: "query",
			SQL:  "SELECT * FROM notexists",
			ErrorFields: []core.PGErrorField{
				{Type: 'V', Value: "ERROR"},
				{Type: 'C', Value: "42P01"},
				{Type: 'M', Value: `relation "notexists" does not exist`},
			},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// Must have an ErrorResponse (E) down packet.
	errPkt := firstPayloadByType(cfgs, 'E')
	if errPkt == nil {
		t.Fatalf("no ErrorResponse (E) packet emitted for failed query")
	}
	// Body after type+length must contain the SQLSTATE 42P01.
	if !bytes.Contains(errPkt[5:], []byte("42P01")) {
		t.Errorf("ErrorResponse missing SQLSTATE 42P01: %q", errPkt)
	}
	// Must NOT emit RowDescription (T), DataRow (D), or CommandComplete (C)
	// for the failed query (the auth-phase ParameterStatus uses 'S', and
	// CommandComplete uses 'C' — distinguish by checking there is no C
	// after the Q).
	qIdx := -1
	for i, c := range cfgs {
		if c.Direction == "up" && len(c.Payload) > 0 && c.Payload[0] == 'Q' {
			qIdx = i
			break
		}
	}
	if qIdx == -1 {
		t.Fatalf("no Query (Q) up packet found")
	}
	for i := qIdx + 1; i < len(cfgs); i++ {
		t0 := cfgs[i].Payload[0]
		if t0 == 'T' || t0 == 'D' {
			t.Errorf("after failed query, cfg[%d] type=%c should not appear (no result set)", i, t0)
		}
	}
	// The ReadyForQuery after the error must be status 'I' (not in txn).
	statuses := rfqStatuses(cfgs)
	if len(statuses) == 0 {
		t.Fatalf("no ReadyForQuery emitted")
	}
	last := statuses[len(statuses)-1]
	if last != 'I' {
		t.Errorf("non-txn error RFQ status=%c, want 'I'", last)
	}
}

// TestPGGap_QueryErrorInTxnFlipsStatusToE: when a query fails inside a
// BEGIN transaction, the ReadyForQuery status must flip to 'E' (in failed
// transaction) per PostgreSQL §52.2.
func TestPGGap_QueryErrorInTxnFlipsStatusToE(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpecNoHandshake()
	spec.PostgreSQL.Operations = []core.PGOperation{
		{Kind: "query", SQL: "BEGIN"},
		{
			Kind: "query",
			SQL:  "SELECT * FROM notexists",
			ErrorFields: []core.PGErrorField{
				{Type: 'V', Value: "ERROR"},
				{Type: 'C', Value: "42P01"},
				{Type: 'M', Value: `relation "notexists" does not exist`},
			},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	statuses := rfqStatuses(cfgs)
	// statuses[0] = auth-phase RFQ ('I'); [1] = after BEGIN ('T');
	// [2] = after error ('E').
	if len(statuses) < 3 {
		t.Fatalf("expected >= 3 RFQ packets (auth+BEGIN+error), got %d", len(statuses))
	}
	if statuses[1] != 'T' {
		t.Errorf("after BEGIN: status=%c, want 'T'", statuses[1])
	}
	if statuses[2] != 'E' {
		t.Errorf("after error in txn: status=%c, want 'E' (failed transaction)", statuses[2])
	}
}

// TestPGGap_RollbackRecoversFailedTxn: after a failed-transaction status
// 'E', ROLLBACK must return to status 'I' (idle).
func TestPGGap_RollbackRecoversFailedTxn(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpecNoHandshake()
	spec.PostgreSQL.Operations = []core.PGOperation{
		{Kind: "query", SQL: "BEGIN"},
		{
			Kind: "query",
			SQL:  "INVALID",
			ErrorFields: []core.PGErrorField{
				{Type: 'V', Value: "ERROR"},
				{Type: 'C', Value: "42601"},
				{Type: 'M', Value: "syntax error"},
			},
		},
		{Kind: "query", SQL: "ROLLBACK"},
	}
	cfgs := drain(mustPlan(t, p, spec))
	statuses := rfqStatuses(cfgs)
	// statuses[0] = auth RFQ ('I'); [1] = BEGIN ('T'); [2] = error ('E');
	// [3] = ROLLBACK ('I').
	if len(statuses) < 4 {
		t.Fatalf("expected >= 4 RFQ (auth+BEGIN+error+ROLLBACK), got %d", len(statuses))
	}
	if statuses[1] != 'T' {
		t.Errorf("after BEGIN: %c, want T", statuses[1])
	}
	if statuses[2] != 'E' {
		t.Errorf("after error: %c, want E", statuses[2])
	}
	if statuses[3] != 'I' {
		t.Errorf("after ROLLBACK: %c, want I (recovered)", statuses[3])
	}
}

// --- §1.3.10 / §3.11 standalone "error" operation ---

// TestPGGap_ErrorOperationEmitsErrorResponse: a standalone "error" kind
// operation emits ErrorResponse (E) + ReadyForQuery (Z), using the
// current transaction status (or 'I' if idle).
func TestPGGap_ErrorOperationEmitsErrorResponse(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpecNoHandshake()
	spec.PostgreSQL.Operations = []core.PGOperation{
		{
			Kind: "error",
			ErrorFields: []core.PGErrorField{
				{Type: 'V', Value: "ERROR"},
				{Type: 'C', Value: "23505"},
				{Type: 'M', Value: "duplicate key value violates unique constraint"},
			},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	errPkt := firstPayloadByType(cfgs, 'E')
	if errPkt == nil {
		t.Fatalf("standalone error op: no E packet emitted")
	}
	body := errPkt[5:]
	// Body is field-type + C-string + ... + terminator \0.
	if !bytes.Contains(body, []byte("23505")) {
		t.Errorf("E body missing SQLSTATE 23505: %q", body)
	}
	if !bytes.Contains(body, []byte("duplicate key")) {
		t.Errorf("E body missing message: %q", body)
	}
	// Last byte must be the \0 terminator.
	if len(body) == 0 || body[len(body)-1] != 0 {
		t.Errorf("E body must end with \\0 terminator: %q", body)
	}
	// Must be followed by ReadyForQuery (status 'I', not in txn).
	statuses := rfqStatuses(cfgs)
	if len(statuses) == 0 {
		t.Fatalf("no RFQ after standalone error")
	}
	if statuses[len(statuses)-1] != 'I' {
		t.Errorf("standalone error RFQ status=%c, want I", statuses[len(statuses)-1])
	}
}

// --- §1.3.9 / §3.11 "notice" operation ---

// TestPGGap_NoticeOperationEmitsNoticeResponse: a "notice" kind operation
// emits NoticeResponse (N) as a server->client push, with no client
// request and no ReadyForQuery (notices are informational).
func TestPGGap_NoticeOperationEmitsNoticeResponse(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpecNoHandshake()
	spec.PostgreSQL.Operations = []core.PGOperation{
		{
			Kind: "notice",
			ErrorFields: []core.PGErrorField{
				{Type: 'V', Value: "NOTICE"},
				{Type: 'M', Value: "relation already exists, skipping"},
			},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	nPkt := firstPayloadByType(cfgs, 'N')
	if nPkt == nil {
		t.Fatalf("notice op: no N packet emitted")
	}
	body := nPkt[5:]
	if !bytes.Contains(body, []byte("NOTICE")) {
		t.Errorf("N body missing severity NOTICE: %q", body)
	}
	if !bytes.Contains(body, []byte("relation already exists")) {
		t.Errorf("N body missing message: %q", body)
	}
	// Notice must be server->client (down).
	found := false
	for _, c := range cfgs {
		if len(c.Payload) > 0 && c.Payload[0] == 'N' && c.Direction == "down" {
			found = true
		}
	}
	if !found {
		t.Errorf("NoticeResponse not emitted in down direction")
	}
}

// --- §1.3.12.4 / §2.3.1.2 Describe NoData ---

// TestPGGap_DescribeExpectNoDataEmitsNoData: a "describe" with
// ExpectNoData=true must emit NoData ('n') instead of RowDescription ('T').
// Spec: PostgreSQL §52.7 — Describe on a statement/portal that does not
// produce rows returns NoData.
func TestPGGap_DescribeExpectNoDataEmitsNoData(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpecNoHandshake()
	spec.PostgreSQL.Operations = []core.PGOperation{
		{Kind: "parse", Statement: "s1", SQL: "INSERT INTO t VALUES ($1)", ParamCount: 1},
		{Kind: "describe", Mode: "statement", Statement: "s1", ExpectNoData: true},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// Must emit NoData ('n'); must NOT emit RowDescription ('T').
	nPkt := firstPayloadByType(cfgs, 'n')
	if nPkt == nil {
		t.Fatalf("describe with ExpectNoData: no 'n' (NoData) packet emitted")
	}
	if firstPayloadByType(cfgs, 'T') != nil {
		t.Errorf("describe with ExpectNoData should not emit RowDescription ('T')")
	}
}

// --- §1.3.12.5 Describe ParameterDescription (statement mode) ---

// TestPGGap_DescribeStatementEmitsParameterDescription: a "describe" with
// Mode="statement" must emit ParameterDescription ('t') before NoData or
// RowDescription, listing the prepared statement's parameter type OIDs.
// Spec: PostgreSQL §52.7 — Describe statement returns ParameterDescription
// then NoData (or RowDescription if the statement returns rows).
func TestPGGap_DescribeStatementEmitsParameterDescription(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpecNoHandshake()
	spec.PostgreSQL.Operations = []core.PGOperation{
		{Kind: "parse", Statement: "s1", SQL: "SELECT $1::int, $2::text", ParamCount: 2},
		// ParamCount on describe mirrors what the server learned from
		// Parse; the planner is stateless so the user repeats it here.
		{Kind: "describe", Mode: "statement", Statement: "s1", ParamCount: 2},
	}
	cfgs := drain(mustPlan(t, p, spec))
	tPkt := firstPayloadByType(cfgs, 't')
	if tPkt == nil {
		t.Fatalf("describe statement: no 't' (ParameterDescription) packet emitted")
	}
	// Body: int16 count + N × int32 type_oid.
	body := tPkt[5:]
	if len(body) < 2 {
		t.Fatalf("ParameterDescription body too short: %d", len(body))
	}
	count := binary.BigEndian.Uint16(body[0:2])
	// ParamCount=2 in parse; planner should reflect 2 param OIDs.
	if count != 2 {
		t.Errorf("ParameterDescription count=%d, want 2", count)
	}
}

// --- §2.2.4 Multi-statement Simple Query ---

// TestPGGap_MultiStatementQueryProducesMultipleResultSets: a "query" with
// SQL containing multiple statements separated by ';' must produce one
// RowDescription+DataRow+CommandComplete per statement, with only a single
// ReadyForQuery at the end (no intermediate ReadyForQuery).
// Spec: PostgreSQL §52.2.3 — multiple statements in one Query message are
// executed in sequence; only the last emits ReadyForQuery.
func TestPGGap_MultiStatementQueryProducesMultipleResultSets(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpecNoHandshake()
	spec.PostgreSQL.Operations = []core.PGOperation{
		{Kind: "query", SQL: "SELECT 1; SELECT 2"},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// Expect 2 RowDescription (T), 2 DataRow (D), 2 CommandComplete (C).
	// The only ReadyForQuery from the user operation is the one after
	// the multi-statement query. The initial auth-phase RFQ is skipped
	// by counting Z packets that come AFTER the first Q (user query).
	tPkts := findPayloadsByType(cfgs, 'T')
	dPkts := findPayloadsByType(cfgs, 'D')
	cPkts := findPayloadsByType(cfgs, 'C')
	if len(tPkts) != 2 {
		t.Errorf("multi-stmt: RowDescription count=%d, want 2", len(tPkts))
	}
	if len(dPkts) != 2 {
		t.Errorf("multi-stmt: DataRow count=%d, want 2", len(dPkts))
	}
	if len(cPkts) != 2 {
		t.Errorf("multi-stmt: CommandComplete count=%d, want 2", len(cPkts))
	}
	// Count Z packets emitted after the first Q (user query).
	qIdx := -1
	for i, c := range cfgs {
		if c.Direction == "up" && len(c.Payload) > 0 && c.Payload[0] == 'Q' {
			qIdx = i
			break
		}
	}
	if qIdx < 0 {
		t.Fatalf("no Q packet found")
	}
	zAfterQ := 0
	for i := qIdx + 1; i < len(cfgs); i++ {
		if cfgs[i].Direction == "down" && len(cfgs[i].Payload) > 0 && cfgs[i].Payload[0] == 'Z' {
			zAfterQ++
		}
	}
	if zAfterQ != 1 {
		t.Errorf("multi-stmt: ReadyForQuery after Q count=%d, want 1 (no intermediate RFQ)", zAfterQ)
	}
}

// --- §2.2.5 Multi-statement mid-query error ---

// TestPGGap_MultiStatementMidErrorCancelsSubsequent: a multi-statement
// query where a middle statement fails must emit the first statement's
// result set, then ErrorResponse, then ReadyForQuery — subsequent
// statements are NOT executed.
// Spec: PostgreSQL §52.2.3 — on error in a multi-statement query, the
// server skips remaining statements and sends ErrorResponse + ReadyForQuery.
func TestPGGap_MultiStatementMidErrorCancelsSubsequent(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpecNoHandshake()
	spec.PostgreSQL.Operations = []core.PGOperation{
		{
			Kind: "query",
			SQL:  "SELECT 1; INVALID_STMT; SELECT 2",
			ErrorFields: []core.PGErrorField{
				{Type: 'V', Value: "ERROR"},
				{Type: 'C', Value: "42601"},
				{Type: 'M', Value: `syntax error at or near "INVALID_STMT"`},
			},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// Expect 1 RowDescription (for SELECT 1), 1 DataRow, 1 CommandComplete,
	// then ErrorResponse (E), then ReadyForQuery (Z). The third statement
	// (SELECT 2) must NOT produce any T/D/C.
	tPkts := findPayloadsByType(cfgs, 'T')
	dPkts := findPayloadsByType(cfgs, 'D')
	cPkts := findPayloadsByType(cfgs, 'C')
	ePkts := findPayloadsByType(cfgs, 'E')
	if len(tPkts) != 1 {
		t.Errorf("mid-error: RowDescription count=%d, want 1 (only SELECT 1)", len(tPkts))
	}
	if len(dPkts) != 1 {
		t.Errorf("mid-error: DataRow count=%d, want 1", len(dPkts))
	}
	if len(cPkts) != 1 {
		t.Errorf("mid-error: CommandComplete count=%d, want 1", len(cPkts))
	}
	if len(ePkts) != 1 {
		t.Errorf("mid-error: ErrorResponse count=%d, want 1", len(ePkts))
	}
	// Count Z packets emitted after the first Q (user query).
	qIdx := -1
	for i, c := range cfgs {
		if c.Direction == "up" && len(c.Payload) > 0 && c.Payload[0] == 'Q' {
			qIdx = i
			break
		}
	}
	zAfterQ := 0
	for i := qIdx + 1; i < len(cfgs); i++ {
		if cfgs[i].Direction == "down" && len(cfgs[i].Payload) > 0 && cfgs[i].Payload[0] == 'Z' {
			zAfterQ++
		}
	}
	if zAfterQ != 1 {
		t.Errorf("mid-error: ReadyForQuery after Q count=%d, want 1", zAfterQ)
	}
	// Error must contain the syntax-error SQLSTATE.
	if len(ePkts) == 1 && !bytes.Contains(ePkts[0][5:], []byte("42601")) {
		t.Errorf("mid-error E missing SQLSTATE 42601: %q", ePkts[0])
	}
}

// --- §1.3.10.5 ErrorResponse terminator invariant ---

// TestPGGap_ErrorResponseTerminator: every ErrorResponse must end with a
// \0 byte terminator after the last field.
func TestPGGap_ErrorResponseTerminator(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpecNoHandshake()
	spec.PostgreSQL.Operations = []core.PGOperation{
		{
			Kind: "error",
			ErrorFields: []core.PGErrorField{
				{Type: 'V', Value: "ERROR"},
				{Type: 'C', Value: "42601"},
				{Type: 'M', Value: "syntax error"},
			},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	ePkts := findPayloadsByType(cfgs, 'E')
	if len(ePkts) != 1 {
		t.Fatalf("want 1 E packet, got %d", len(ePkts))
	}
	body := ePkts[0][5:]
	if len(body) == 0 || body[len(body)-1] != 0 {
		t.Errorf("ErrorResponse body must end with \\0 terminator: %q", body)
	}
}

// --- §2.2.2.2 / §2.2.5.2 different SQLSTATE codes ---

// TestPGGap_ErrorResponseDifferentSQLSTATEs: verify the planner propagates
// the SQLSTATE code from ErrorFields into the ErrorResponse body for
// several common codes (42601 syntax, 42P01 undefined_table, 23505
// unique_violation).
func TestPGGap_ErrorResponseDifferentSQLSTATEs(t *testing.T) {
	codes := []string{"42601", "42P01", "23505"}
	for _, code := range codes {
		t.Run(code, func(t *testing.T) {
			p := NewPlanner()
			spec := validPGSpecNoHandshake()
			spec.PostgreSQL.Operations = []core.PGOperation{
				{
					Kind: "error",
					ErrorFields: []core.PGErrorField{
						{Type: 'V', Value: "ERROR"},
						{Type: 'C', Value: code},
						{Type: 'M', Value: "test message"},
					},
				},
			}
			cfgs := drain(mustPlan(t, p, spec))
			ePkt := firstPayloadByType(cfgs, 'E')
			if ePkt == nil {
				t.Fatalf("no E packet for code %s", code)
			}
			if !bytes.Contains(ePkt[5:], []byte(code)) {
				t.Errorf("E body missing code %s: %q", code, ePkt)
			}
		})
	}
}

// --- §3.4 Extended Query full sequence assertions ---

// TestPGGap_ExtendedQueryFullSequence: Parse→Bind→Describe(portal)→
// Execute→Sync must produce the canonical response sequence
// 1, 2, T, D*, C, Z in order.
func TestPGGap_ExtendedQueryFullSequence(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpecNoHandshake()
	spec.PostgreSQL.Operations = []core.PGOperation{
		{Kind: "parse", Statement: "s1", SQL: "SELECT $1::int", ParamCount: 1},
		{Kind: "bind", Portal: "p1", Statement: "s1", ParamValues: []string{"42"}},
		{Kind: "describe", Mode: "portal", Portal: "p1"},
		{Kind: "execute", Portal: "p1"},
		{Kind: "sync"},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// Collect down-direction message types after the auth phase (first
	// non-S/K/Z packet that is part of the extended-query response).
	var downTypes []byte
	for _, c := range cfgs {
		if c.Direction != "down" || len(c.Payload) == 0 {
			continue
		}
		t0 := c.Payload[0]
		// Skip auth-phase messages (S=ParameterStatus, K=BackendKeyData,
		// Z=initial ReadyForQuery).
		if t0 == 'S' || t0 == 'K' {
			continue
		}
		downTypes = append(downTypes, t0)
	}
	// Expected: 1(ParseComplete), 2(BindComplete), T(RowDescription),
	// D(DataRow), C(CommandComplete), Z(ReadyForQuery).
	// The initial ReadyForQuery (after auth) appears first; skip it.
	// Find the first '1' to align.
	start := bytes.IndexByte(downTypes, '1')
	if start < 0 {
		t.Fatalf("no ParseComplete ('1') in down stream: %q", downTypes)
	}
	seq := downTypes[start:]
	want := []byte{'1', '2', 'T', 'D', 'C', 'Z'}
	if len(seq) < len(want) {
		t.Fatalf("extended-query seq too short: %q, want prefix %q", seq, want)
	}
	for i, w := range want {
		if seq[i] != w {
			t.Errorf("extended-query seq[%d]=%c, want %c (full: %q)", i, seq[i], w, seq)
		}
	}
}

// --- §2.3.1.4 Execute MaxRows=1 PortalSuspended ---

// TestPGGap_ExecuteMaxRowsEmitsPortalSuspended: Execute with MaxRows=1 and
// RowCount>=2 must emit PortalSuspended ('s') instead of CommandComplete.
// Spec: PostgreSQL §52.7 — Execute with max_rows limit returns
// PortalSuspended when more rows remain.
func TestPGGap_ExecuteMaxRowsEmitsPortalSuspended(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpecNoHandshake()
	spec.PostgreSQL.RowCount = 3
	spec.PostgreSQL.Operations = []core.PGOperation{
		{Kind: "parse", Statement: "s1", SQL: "SELECT generate_series(1,3)"},
		{Kind: "bind", Portal: "p1", Statement: "s1"},
		{Kind: "execute", Portal: "p1", MaxRows: 1},
		{Kind: "sync"},
	}
	cfgs := drain(mustPlan(t, p, spec))
	sPkt := firstPayloadByType(cfgs, 's')
	if sPkt == nil {
		t.Fatalf("Execute MaxRows=1 with 3 rows: no PortalSuspended ('s') emitted")
	}
}

// --- helper to ensure context import is used even if no direct ctx test ---

var _ = context.Background

// --- ensure strings import is used (for future message-text checks) ---

var _ = strings.Contains
