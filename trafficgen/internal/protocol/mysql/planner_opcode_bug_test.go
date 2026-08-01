package mysql

// Regression tests for the COM_PING / COM_STMT_* opcode bug found via
// Wireshark capture verification (2026-08-01).
//
// The canonical scenario config (validMySQLSpec) used opcode 0x0f for
// COM_PING, but the real MySQL opcode is 0x0e (my_command.h); 0x0f is
// COM_TIME, which requires extra payload bytes, so Wireshark dissects
// the generated packet as "Request Time [Malformed Packet]". The same
// shifted-opcode bug hit the prepared-statement family: the planner
// auto-encoder emitted 0x1b for COM_STMT_EXECUTE (real: 0x17) and the
// tests drove COM_STMT_PREPARE/COM_STMT_CLOSE with 0x1a/0x1d (real:
// 0x16/0x19) — Wireshark shows "Request Set Option" / "Request Reset
// Statement" / "Request Daemon" for those.
//
// These tests drive the canonical spec and assert the exact wire bytes
// a real MySQL server/client exchange.

import (
	"bytes"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

// COM_PING (0x0e): request = 4-byte header (len=1, seq=0) + 0x0e.
// FAILS before the fix: validMySQLSpec used 0x0f (COM_TIME), so the
// emitted request is 01 00 00 00 0f.
func TestMySQLBug_COMPingRequestUsesOpcode0x0e(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validMySQLSpec()))
	cmd := cfgs[6].Payload
	want := []byte{0x01, 0x00, 0x00, 0x00, 0x0e} // len=1, seq=0, COM_PING
	if !bytes.Equal(cmd, want) {
		t.Errorf("COM_PING request=%x, want %x (0x0e; 0x0f is COM_TIME -> Wireshark Malformed)", cmd, want)
	}
}

// COM_PING reply: OK body must be at least
// 0x00 header + affected_rows + last_insert_id + 2B status + 2B
// warnings (= 6 bytes); framed packet >= 9 bytes. A real MySQL server
// replies payload 00 00 00 02 00 00 00 -> packet 07 00 00 01 00 00 00
// 02 00 00 00 (length 7, seq 1). This is a regression guard: the reply
// path must never regress to a 1-byte payload.
func TestMySQLBug_COMPingReplyHasMinOKStructure(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validMySQLSpec()))
	reply := cfgs[7].Payload
	if len(reply) < 9 {
		t.Fatalf("reply packet len=%d, want >= 9 (4 header + >= 6 body)", len(reply))
	}
	body := reply[4:]
	if len(body) < 6 {
		t.Fatalf("OK body len=%d, want >= 6", len(body))
	}
	if body[0] != 0x00 {
		t.Errorf("OK marker=0x%02x, want 0x00", body[0])
	}
	// status_flags at body[3:5] (after header + 1B affected + 1B last_id).
	status := uint16(body[3]) | uint16(body[4])<<8
	if status != serverStatusAutocommit {
		t.Errorf("status_flags=0x%04x, want 0x0002 (AUTOCOMMIT)", status)
	}
}

// COM_STMT_EXECUTE (0x17) with StmtID and empty Body must auto-encode
// the request: 0x17 + stmt_id(4 LE) + flags(1) + iteration_count(4 LE).
// FAILS before the fix: the auto-encode branch keyed on 0x1b, so a
// correctly-configured 0x17 command emitted a bare 1-byte body.
func TestMySQLBug_StmtExecuteAutoEncodeUsesOpcode0x17(t *testing.T) {
	p := NewPlanner()
	spec := validMySQLSpec()
	spec.MySQL.Commands = []core.MySQLCommand{
		{Opcode: 0x17, StmtID: 42, IterationCount: 1, ReplyMode: "binary-result"},
	}
	cfgs := drain(mustPlan(t, p, spec))
	body := cfgs[6].Payload[4:]
	want := []byte{
		0x17,
		0x2a, 0x00, 0x00, 0x00, // stmt_id=42
		0x00,                   // flags
		0x01, 0x00, 0x00, 0x00, // iteration_count=1
	}
	if !bytes.Equal(body, want) {
		t.Errorf("STMT_EXECUTE body=%x, want %x (0x17; 0x1b is COM_SET_OPTION)", body, want)
	}
}

// Validate must reject COM_STMT_EXECUTE (0x17) with StmtID == 0.
// FAILS before the fix: the check keyed on 0x1b.
func TestMySQLBug_StmtExecuteValidateRequiresStmtID(t *testing.T) {
	p := NewPlanner()
	spec := validMySQLSpec()
	spec.MySQL.Commands = []core.MySQLCommand{{Opcode: 0x17, ReplyMode: "binary-result"}}
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "StmtID") {
		t.Errorf("Validate err=%v, want contains 'StmtID'", err)
	}
}
