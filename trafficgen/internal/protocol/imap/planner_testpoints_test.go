package imap

// Atomic test points for the IMAP planner. Each test corresponds to one
// or more test cases in /tmp/l7_planner_design/testcases_imap.md (RFC
// 9051 §2-§6, RFC 2177 IDLE, RFC 5161 ENABLE, RFC 6851 MOVE, RFC 7162
// CONDSTORE, RFC 6855 UTF-8). Tests assert observable PacketConfig
// field values, not just "no error".

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/protocol/testutil"
)

// --- 1.1.1 Tag field ---

// 1.1.1.1: Tag="A001" emits "A001 LOGIN alice secret\r\n" PSH-ACK up.
func TestIMAPPoint_1_1_1_1_TagA001(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	spec.IMAP.Commands = []core.IMAPCommand{
		{Tag: "A001", Cmd: "LOGIN alice secret", Responses: []string{"A001 OK LOGIN completed"}},
	}
	cfgs := drain(mustPlan(t, p, spec))
	loginPkt := cfgs[3]
	if loginPkt.Direction != "up" || string(loginPkt.Payload) != "A001 LOGIN alice secret\r\n" {
		t.Errorf("got dir=%s payload=%q, want up/'A001 LOGIN alice secret\\r\\n'", loginPkt.Direction, loginPkt.Payload)
	}
}

// 1.1.1.2: Tag="" (empty) auto-increments: A001, A002, A003.
func TestIMAPPoint_1_1_1_2_TagAutoIncrement(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	spec.IMAP.Commands = []core.IMAPCommand{
		{Cmd: "NOOP", Responses: []string{"A001 OK"}},
		{Cmd: "NOOP", Responses: []string{"A002 OK"}},
		{Cmd: "NOOP", Responses: []string{"A003 OK"}},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if !strings.HasPrefix(string(cfgs[3].Payload), "A001 NOOP") {
		t.Errorf("cmd1: %q, want 'A001 NOOP'", cfgs[3].Payload)
	}
	if !strings.HasPrefix(string(cfgs[5].Payload), "A002 NOOP") {
		t.Errorf("cmd2: %q, want 'A002 NOOP'", cfgs[5].Payload)
	}
	if !strings.HasPrefix(string(cfgs[7].Payload), "A003 NOOP") {
		t.Errorf("cmd3: %q, want 'A003 NOOP'", cfgs[7].Payload)
	}
}

// 1.1.1.3: Tag="tag.42" (with dot) emits "tag.42 NOOP\r\n".
func TestIMAPPoint_1_1_1_3_TagWithDot(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	spec.IMAP.Commands = []core.IMAPCommand{
		{Tag: "tag.42", Cmd: "NOOP", Responses: []string{"tag.42 OK"}},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if string(cfgs[3].Payload) != "tag.42 NOOP\r\n" {
		t.Errorf("got %q, want 'tag.42 NOOP\\r\\n'", cfgs[3].Payload)
	}
}

// 1.1.1.4: Tag="X-Custom-1" (with hyphen) emits "X-Custom-1 NOOP\r\n".
func TestIMAPPoint_1_1_1_4_TagWithHyphen(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	spec.IMAP.Commands = []core.IMAPCommand{
		{Tag: "X-Custom-1", Cmd: "NOOP", Responses: []string{"X-Custom-1 OK"}},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if string(cfgs[3].Payload) != "X-Custom-1 NOOP\r\n" {
		t.Errorf("got %q, want 'X-Custom-1 NOOP\\r\\n'", cfgs[3].Payload)
	}
}

// 1.1.1.5: Tag="001" (numeric) emits "001 NOOP\r\n".
func TestIMAPPoint_1_1_1_5_TagNumeric(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	spec.IMAP.Commands = []core.IMAPCommand{
		{Tag: "001", Cmd: "NOOP", Responses: []string{"001 OK"}},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if string(cfgs[3].Payload) != "001 NOOP\r\n" {
		t.Errorf("got %q, want '001 NOOP\\r\\n'", cfgs[3].Payload)
	}
}

// --- 1.1.2 Command field ---

// 1.1.2.1: Cmd="NOOP" emits "A001 NOOP\r\n" with no arguments.
func TestIMAPPoint_1_1_2_1_CmdNoop(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	spec.IMAP.Commands = []core.IMAPCommand{
		{Tag: "A001", Cmd: "NOOP", Responses: []string{"A001 OK"}},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if string(cfgs[3].Payload) != "A001 NOOP\r\n" {
		t.Errorf("got %q, want 'A001 NOOP\\r\\n'", cfgs[3].Payload)
	}
}

// 1.1.2.2: Cmd="LOGIN alice secret" emits with 2 arguments.
func TestIMAPPoint_1_1_2_2_CmdLoginTwoArgs(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	spec.IMAP.Commands = []core.IMAPCommand{
		{Tag: "A001", Cmd: "LOGIN alice secret", Responses: []string{"A001 OK"}},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if string(cfgs[3].Payload) != "A001 LOGIN alice secret\r\n" {
		t.Errorf("got %q", cfgs[3].Payload)
	}
}

// 1.1.2.3: Cmd="FETCH 1:5 (FLAGS UID)" emits with parens sequence.
func TestIMAPPoint_1_1_2_3_CmdFetchWithParens(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	spec.IMAP.Commands = []core.IMAPCommand{
		{Tag: "A001", Cmd: "FETCH 1:5 (FLAGS UID)", Responses: []string{"A001 OK"}},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if string(cfgs[3].Payload) != "A001 FETCH 1:5 (FLAGS UID)\r\n" {
		t.Errorf("got %q", cfgs[3].Payload)
	}
}

// 1.1.2.4: Cmd="" (empty) skips client command packet.
func TestIMAPPoint_1_1_2_4_CmdEmptySkipped(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	spec.IMAP.Commands = []core.IMAPCommand{
		{Tag: "A001", Cmd: "", Responses: []string{"+ challenge"}},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// handshake(3) + resp(1) + teardown(4) = 8
	if len(cfgs) != 8 {
		t.Fatalf("len=%d, want 8 (empty Cmd skipped)", len(cfgs))
	}
	if cfgs[3].Direction != "down" {
		t.Errorf("cfg[3] should be down (only resp, no cmd)")
	}
}

// --- 1.1.4 CRLF field ---

// 1.1.4.1: Each command ends with CRLF.
func TestIMAPPoint_1_1_4_1_CmdEndsWithCRLF(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	spec.IMAP.Commands = []core.IMAPCommand{
		{Tag: "A001", Cmd: "NOOP", Responses: []string{"A001 OK"}},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if !strings.HasSuffix(string(cfgs[3].Payload), "\r\n") {
		t.Errorf("cmd should end with CRLF: %q", cfgs[3].Payload)
	}
}

// 1.1.4.3: IDLE DONE line ends with CRLF.
func TestIMAPPoint_1_1_4_3_DoneEndsWithCRLF(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	spec.IMAP.IDLE = &core.IMAPIDLE{DoneResponse: "A001 OK IDLE terminated"}
	spec.IMAP.Commands = []core.IMAPCommand{
		{Tag: "A001", Cmd: "IDLE", Responses: []string{"+ idling"}, EmitIDLE: true},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// Find the DONE packet (up, contains "DONE")
	for i, c := range cfgs {
		if c.Direction == "up" && strings.HasPrefix(string(c.Payload), "DONE") {
			if !strings.HasSuffix(string(c.Payload), "\r\n") {
				t.Errorf("cfg[%d] DONE should end with CRLF: %q", i, c.Payload)
			}
			return
		}
	}
	t.Errorf("no DONE packet found")
}

// --- 1.2 CAPABILITY ---

// 1.2.1: CAPABILITY command + multi-keyword untagged + tagged OK.
func TestIMAPPoint_1_2_1_Capability(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	spec.IMAP.Commands = []core.IMAPCommand{
		{
			Tag: "A001",
			Cmd: "CAPABILITY",
			Responses: []string{
				"* CAPABILITY IMAP4rev2 STARTTLS AUTH=PLAIN ENABLE IDLE",
				"A001 OK CAPABILITY completed",
			},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// handshake(3) + cmd(1) + 2 resps(2) + teardown(4) = 10
	if len(cfgs) != 10 {
		t.Fatalf("len=%d, want 10", len(cfgs))
	}
	if !strings.Contains(string(cfgs[4].Payload), "* CAPABILITY IMAP4rev2") {
		t.Errorf("cfg[4] should contain '* CAPABILITY IMAP4rev2': %q", cfgs[4].Payload)
	}
	if !strings.Contains(string(cfgs[5].Payload), "A001 OK CAPABILITY") {
		t.Errorf("cfg[5] should contain 'A001 OK CAPABILITY': %q", cfgs[5].Payload)
	}
}

// --- 1.3 NOOP ---

// 1.3.1: NOOP command + tagged OK.
func TestIMAPPoint_1_3_1_Noop(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	spec.IMAP.Commands = []core.IMAPCommand{
		{Tag: "A001", Cmd: "NOOP", Responses: []string{"A001 OK NOOP completed"}},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// handshake(3) + cmd(1) + resp(1) + teardown(4) = 9
	if len(cfgs) != 9 {
		t.Fatalf("len=%d, want 9", len(cfgs))
	}
	if !strings.Contains(string(cfgs[3].Payload), "A001 NOOP") {
		t.Errorf("cfg[3] should be 'A001 NOOP'")
	}
	if !strings.Contains(string(cfgs[4].Payload), "A001 OK NOOP") {
		t.Errorf("cfg[4] should be 'A001 OK NOOP'")
	}
}

// --- 1.4 LOGOUT ---

// 1.4.1: LOGOUT command + * BYE + tagged OK.
func TestIMAPPoint_1_4_1_Logout(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	spec.IMAP.Commands = []core.IMAPCommand{
		{
			Tag: "A001",
			Cmd: "LOGOUT",
			Responses: []string{
				"* BYE IMAP4rev2 Server logging out",
				"A001 OK LOGOUT completed",
			},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if !strings.Contains(string(cfgs[4].Payload), "* BYE") {
		t.Errorf("cfg[4] should contain '* BYE': %q", cfgs[4].Payload)
	}
	if !strings.Contains(string(cfgs[5].Payload), "A001 OK LOGOUT") {
		t.Errorf("cfg[5] should contain 'A001 OK LOGOUT': %q", cfgs[5].Payload)
	}
}

// 1.4.2: LOGOUT followed by TCP 4-way teardown.
func TestIMAPPoint_1_4_2_LogoutTeardown(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	spec.IMAP.Commands = []core.IMAPCommand{
		{Tag: "A001", Cmd: "LOGOUT", Responses: []string{"* BYE", "A001 OK"}},
	}
	cfgs := drain(mustPlan(t, p, spec))
	n := len(cfgs)
	// Last 4 packets are FIN-ACK/ACK/FIN-ACK/ACK
	if cfgs[n-4].L4.Flags != 0x11 || cfgs[n-3].L4.Flags != 0x10 ||
		cfgs[n-2].L4.Flags != 0x11 || cfgs[n-1].L4.Flags != 0x10 {
		t.Errorf("last 4 packets should be FIN-ACK/ACK/FIN-ACK/ACK")
	}
}

// --- 1.6 AUTHENTICATE ---

// 1.6.1: AUTHENTICATE PLAIN with empty "+ " continuation.
func TestIMAPPoint_1_6_1_AuthenticatePlain(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	spec.IMAP.Commands = []core.IMAPCommand{
		{
			Tag:      "A001",
			Cmd:      "AUTHENTICATE PLAIN",
			Responses: []string{"+ ", "A001 OK AUTHENTICATE completed"},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// handshake(3) + cmd(1) + 2 resps(2) + teardown(4) = 10
	if len(cfgs) != 10 {
		t.Fatalf("len=%d, want 10", len(cfgs))
	}
	if !strings.Contains(string(cfgs[3].Payload), "AUTHENTICATE PLAIN") {
		t.Errorf("cfg[3] should contain 'AUTHENTICATE PLAIN': %q", cfgs[3].Payload)
	}
	// cfg[4] should be "+ \r\n"
	if string(cfgs[4].Payload) != "+ \r\n" {
		t.Errorf("cfg[4] should be '+ \\r\\n': %q", cfgs[4].Payload)
	}
}

// 1.6.2: AUTHENTICATE LOGIN with 2 challenges.
func TestIMAPPoint_1_6_2_AuthenticateLogin(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	spec.IMAP.Commands = []core.IMAPCommand{
		{
			Tag:      "A001",
			Cmd:      "AUTHENTICATE LOGIN",
			Responses: []string{
				"+ VXNlcm5hbWU6",
				"+ UGFzc3dvcmQ6",
				"A001 OK AUTHENTICATE completed",
			},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// handshake(3) + cmd(1) + 3 resps(3) + teardown(4) = 11
	if len(cfgs) != 11 {
		t.Fatalf("len=%d, want 11", len(cfgs))
	}
	if string(cfgs[4].Payload) != "+ VXNlcm5hbWU6\r\n" {
		t.Errorf("cfg[4] should be '+ VXNlcm5hbWU6\\r\\n': %q", cfgs[4].Payload)
	}
	if string(cfgs[5].Payload) != "+ UGFzc3dvcmQ6\r\n" {
		t.Errorf("cfg[5] should be '+ UGFzc3dvcmQ6\\r\\n': %q", cfgs[5].Payload)
	}
}

// --- 1.7 LOGIN ---

// 1.7.1: LOGIN success.
func TestIMAPPoint_1_7_1_LoginSuccess(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	spec.IMAP.Commands = []core.IMAPCommand{
		{Tag: "A001", Cmd: "LOGIN alice secret", Responses: []string{"A001 OK LOGIN completed"}},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if !strings.Contains(string(cfgs[4].Payload), "A001 OK LOGIN") {
		t.Errorf("cfg[4] should contain 'A001 OK LOGIN': %q", cfgs[4].Payload)
	}
}

// 1.7.2: LOGIN failure (wrong password) -> tagged NO.
func TestIMAPPoint_1_7_2_LoginFailure(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	spec.IMAP.Commands = []core.IMAPCommand{
		{Tag: "A001", Cmd: "LOGIN alice wrong", Responses: []string{"A001 NO LOGIN failed"}},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if !strings.Contains(string(cfgs[4].Payload), "A001 NO LOGIN failed") {
		t.Errorf("cfg[4] should contain 'A001 NO LOGIN failed': %q", cfgs[4].Payload)
	}
}

// 1.7.3: LOGIN with quoted password (containing space).
func TestIMAPPoint_1_7_3_LoginQuotedPassword(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	spec.IMAP.Commands = []core.IMAPCommand{
		{Tag: "A001", Cmd: `LOGIN alice "my password"`, Responses: []string{"A001 OK"}},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if !strings.Contains(string(cfgs[3].Payload), `"my password"`) {
		t.Errorf("cfg[3] should contain '\"my password\"': %q", cfgs[3].Payload)
	}
}

// --- 1.9 SELECT ---

// 1.9.1: SELECT INBOX with full response set.
func TestIMAPPoint_1_9_1_SelectInbox(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	spec.IMAP.Commands = []core.IMAPCommand{
		{
			Tag: "A001",
			Cmd: "SELECT INBOX",
			Responses: []string{
				"* 5 EXISTS",
				"* 2 RECENT",
				"* OK [UIDVALIDITY 1234567890] Uidvalidity",
				"* OK [UIDNEXT 6] Predicted next UID",
				"* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)",
				"A001 OK [READ-WRITE] SELECT completed",
			},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// handshake(3) + cmd(1) + 6 resps(6) + teardown(4) = 14
	if len(cfgs) != 14 {
		t.Fatalf("len=%d, want 14", len(cfgs))
	}
	if !strings.Contains(string(cfgs[4].Payload), "* 5 EXISTS") {
		t.Errorf("cfg[4] should contain '* 5 EXISTS': %q", cfgs[4].Payload)
	}
	if !strings.Contains(string(cfgs[9].Payload), "A001 OK [READ-WRITE]") {
		t.Errorf("cfg[9] should contain 'A001 OK [READ-WRITE]': %q", cfgs[9].Payload)
	}
}

// 1.9.2: SELECT non-existent mailbox -> tagged NO.
func TestIMAPPoint_1_9_2_SelectNonExistent(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	spec.IMAP.Commands = []core.IMAPCommand{
		{Tag: "A001", Cmd: "SELECT INBOX.NonExistent", Responses: []string{"A001 NO SELECT failure"}},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if !strings.Contains(string(cfgs[4].Payload), "A001 NO SELECT failure") {
		t.Errorf("cfg[4] should contain 'A001 NO SELECT failure': %q", cfgs[4].Payload)
	}
}

// --- 1.11 CREATE/DELETE/RENAME ---

// 1.11.1: CREATE success.
func TestIMAPPoint_1_11_1_Create(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	spec.IMAP.Commands = []core.IMAPCommand{
		{Tag: "A001", Cmd: "CREATE INBOX.Junk", Responses: []string{"A001 OK CREATE completed"}},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if !strings.Contains(string(cfgs[4].Payload), "A001 OK CREATE") {
		t.Errorf("cfg[4] should contain 'A001 OK CREATE': %q", cfgs[4].Payload)
	}
}

// 1.11.2: DELETE success.
func TestIMAPPoint_1_11_2_Delete(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	spec.IMAP.Commands = []core.IMAPCommand{
		{Tag: "A001", Cmd: "DELETE INBOX.Junk", Responses: []string{"A001 OK DELETE completed"}},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if !strings.Contains(string(cfgs[4].Payload), "A001 OK DELETE") {
		t.Errorf("cfg[4] should contain 'A001 OK DELETE': %q", cfgs[4].Payload)
	}
}

// 1.11.3: RENAME success.
func TestIMAPPoint_1_11_3_Rename(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	spec.IMAP.Commands = []core.IMAPCommand{
		{Tag: "A001", Cmd: "RENAME INBOX.Junk INBOX.Spam", Responses: []string{"A001 OK RENAME completed"}},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if !strings.Contains(string(cfgs[4].Payload), "A001 OK RENAME") {
		t.Errorf("cfg[4] should contain 'A001 OK RENAME': %q", cfgs[4].Payload)
	}
}

// 1.11.4: DELETE INBOX -> tagged NO.
func TestIMAPPoint_1_11_4_DeleteInbox(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	spec.IMAP.Commands = []core.IMAPCommand{
		{Tag: "A001", Cmd: "DELETE INBOX", Responses: []string{"A001 NO CANNOT DELETE INBOX"}},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if !strings.Contains(string(cfgs[4].Payload), "A001 NO CANNOT DELETE INBOX") {
		t.Errorf("cfg[4] should contain 'A001 NO CANNOT DELETE INBOX': %q", cfgs[4].Payload)
	}
}

// --- 1.13 LIST ---

// 1.13.1: LIST returns multiple mailboxes + tagged OK.
func TestIMAPPoint_1_13_1_List(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	spec.IMAP.Commands = []core.IMAPCommand{
		{
			Tag: "A001",
			Cmd: `LIST "" "*"`,
			Responses: []string{
				`* LIST (\HasNoChildren) "/" "INBOX"`,
				`* LIST (\HasChildren) "/" "Sent"`,
				`* LIST (\HasNoChildren) "/" "Drafts"`,
				"A001 OK LIST completed",
			},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// handshake(3) + cmd(1) + 4 resps(4) + teardown(4) = 12
	if len(cfgs) != 12 {
		t.Fatalf("len=%d, want 12", len(cfgs))
	}
	if !strings.Contains(string(cfgs[4].Payload), "INBOX") {
		t.Errorf("cfg[4] should contain 'INBOX': %q", cfgs[4].Payload)
	}
	if !strings.Contains(string(cfgs[7].Payload), "A001 OK LIST") {
		t.Errorf("cfg[7] should contain 'A001 OK LIST': %q", cfgs[7].Payload)
	}
}

// --- 1.14 STATUS ---

// 1.14.1: STATUS with full status items.
func TestIMAPPoint_1_14_1_Status(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	spec.IMAP.Commands = []core.IMAPCommand{
		{
			Tag: "A001",
			Cmd: "STATUS INBOX (MESSAGES UIDNEXT UIDVALIDITY UNSEEN RECENT)",
			Responses: []string{
				"* STATUS INBOX (MESSAGES 5 UIDNEXT 6 UIDVALIDITY 1234 UNSEEN 2 RECENT 1)",
				"A001 OK STATUS completed",
			},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if !strings.Contains(string(cfgs[4].Payload), "MESSAGES 5") {
		t.Errorf("cfg[4] should contain 'MESSAGES 5': %q", cfgs[4].Payload)
	}
}

// --- 1.15 APPEND ---

// 1.15.1: APPEND with literal body.
func TestIMAPPoint_1_15_1_AppendLiteralBody(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	mailBody := "From: alice@example.com\r\nSubject: Test\r\n\r\nHello"
	spec.IMAP.Commands = []core.IMAPCommand{
		{
			Tag:         "A001",
			Cmd:         "APPEND INBOX {" + itoa(len(mailBody)) + "}",
			Responses:   []string{"+ Ready for literal data", "* 1 EXISTS", "A001 OK APPEND completed"},
			LiteralBody: mailBody,
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// handshake(3) + cmd(1) + literal body up(1) + 3 resps down(3) + teardown(4) = 12
	if len(cfgs) != 12 {
		t.Fatalf("len=%d, want 12", len(cfgs))
	}
	// cfg[4] should be the literal body up.
	if cfgs[4].Direction != "up" {
		t.Errorf("cfg[4] should be up (literal body)")
	}
	if string(cfgs[4].Payload) != mailBody {
		t.Errorf("cfg[4] payload=%q, want %q", cfgs[4].Payload, mailBody)
	}
	// cfg[5] should be "+ Ready for literal data\r\n" down.
	if !strings.HasPrefix(string(cfgs[5].Payload), "+ Ready") {
		t.Errorf("cfg[5] should be '+ Ready...': %q", cfgs[5].Payload)
	}
}

// 1.15.2: APPEND with flags.
func TestIMAPPoint_1_15_2_AppendWithFlags(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	spec.IMAP.Commands = []core.IMAPCommand{
		{
			Tag:         "A001",
			Cmd:         `APPEND INBOX (\Seen) {5}`,
			Responses:   []string{"+ Ready", "A001 OK APPEND completed"},
			LiteralBody: "hello",
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if !strings.Contains(string(cfgs[3].Payload), `APPEND INBOX (\Seen) {5}`) {
		t.Errorf("cfg[3] should contain 'APPEND INBOX (\\Seen) {5}': %q", cfgs[3].Payload)
	}
}

// 1.15.4: APPEND with LiteralBodyB64.
func TestIMAPPoint_1_15_4_AppendLiteralBodyB64(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	body := "Hello, world!"
	spec.IMAP.Commands = []core.IMAPCommand{
		{
			Tag:            "A001",
			Cmd:            "APPEND INBOX {13}",
			Responses:      []string{"+ Ready", "A001 OK APPEND completed"},
			LiteralBodyB64: base64.StdEncoding.EncodeToString([]byte(body)),
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// cfg[4] should be the literal body up.
	if string(cfgs[4].Payload) != body {
		t.Errorf("cfg[4] payload=%q, want %q (decoded base64)", cfgs[4].Payload, body)
	}
}

// --- 1.16 IDLE ---

// 1.16.1: IDLE with push responses + DONE + tagged OK.
func TestIMAPPoint_1_16_1_IDLEWithPushes(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	spec.IMAP.IDLE = &core.IMAPIDLE{
		PushResponses: []string{"* 2 EXISTS", "* 1 EXPUNGE"},
		DoneResponse:  "A001 OK IDLE terminated",
	}
	spec.IMAP.Commands = []core.IMAPCommand{
		{Tag: "A001", Cmd: "IDLE", Responses: []string{"+ idling"}, EmitIDLE: true},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// Find the push responses.
	foundExists := false
	foundExpunge := false
	foundDone := false
	foundDoneResp := false
	for _, c := range cfgs {
		s := string(c.Payload)
		if strings.Contains(s, "* 2 EXISTS") {
			foundExists = true
		}
		if strings.Contains(s, "* 1 EXPUNGE") {
			foundExpunge = true
		}
		if strings.HasPrefix(s, "DONE") {
			foundDone = true
		}
		if strings.Contains(s, "A001 OK IDLE terminated") {
			foundDoneResp = true
		}
	}
	if !foundExists {
		t.Errorf("missing '* 2 EXISTS' push")
	}
	if !foundExpunge {
		t.Errorf("missing '* 1 EXPUNGE' push")
	}
	if !foundDone {
		t.Errorf("missing DONE terminator")
	}
	if !foundDoneResp {
		t.Errorf("missing done response")
	}
}

// 1.16.3: IDLE with 0 push responses.
func TestIMAPPoint_1_16_3_IDLENoPushes(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	spec.IMAP.IDLE = &core.IMAPIDLE{
		PushResponses: nil,
		DoneResponse:  "A001 OK IDLE terminated",
	}
	spec.IMAP.Commands = []core.IMAPCommand{
		{Tag: "A001", Cmd: "IDLE", Responses: []string{"+ idling"}, EmitIDLE: true},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// Should still have DONE + done response.
	foundDone := false
	for _, c := range cfgs {
		if strings.HasPrefix(string(c.Payload), "DONE") {
			foundDone = true
		}
	}
	if !foundDone {
		t.Errorf("DONE should still be emitted with 0 pushes")
	}
}

// --- 1.17 CHECK/CLOSE/UNSELECT ---

// 1.17.1: CHECK command.
func TestIMAPPoint_1_17_1_Check(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	spec.IMAP.Commands = []core.IMAPCommand{
		{Tag: "A001", Cmd: "CHECK", Responses: []string{"A001 OK CHECK completed"}},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if !strings.Contains(string(cfgs[4].Payload), "A001 OK CHECK") {
		t.Errorf("cfg[4] should contain 'A001 OK CHECK': %q", cfgs[4].Payload)
	}
}

// 1.17.2: CLOSE command.
func TestIMAPPoint_1_17_2_Close(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	spec.IMAP.Commands = []core.IMAPCommand{
		{Tag: "A001", Cmd: "CLOSE", Responses: []string{"A001 OK CLOSE completed"}},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if !strings.Contains(string(cfgs[4].Payload), "A001 OK CLOSE") {
		t.Errorf("cfg[4] should contain 'A001 OK CLOSE': %q", cfgs[4].Payload)
	}
}

// 1.17.3: UNSELECT command.
func TestIMAPPoint_1_17_3_Unselect(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	spec.IMAP.Commands = []core.IMAPCommand{
		{Tag: "A001", Cmd: "UNSELECT", Responses: []string{"A001 OK UNSELECT completed"}},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if !strings.Contains(string(cfgs[4].Payload), "A001 OK UNSELECT") {
		t.Errorf("cfg[4] should contain 'A001 OK UNSELECT': %q", cfgs[4].Payload)
	}
}

// --- 1.18 EXPUNGE ---

// 1.18.1: EXPUNGE with untagged * N EXPUNGE responses.
func TestIMAPPoint_1_18_1_Expunge(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	spec.IMAP.Commands = []core.IMAPCommand{
		{
			Tag: "A001",
			Cmd: "EXPUNGE",
			Responses: []string{
				"* 1 EXPUNGE",
				"* 2 EXPUNGE",
				"A001 OK EXPUNGE completed",
			},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if !strings.Contains(string(cfgs[4].Payload), "* 1 EXPUNGE") {
		t.Errorf("cfg[4] should contain '* 1 EXPUNGE': %q", cfgs[4].Payload)
	}
}

// --- 1.19 SEARCH ---

// 1.19.1: SEARCH ALL returns sequence numbers.
func TestIMAPPoint_1_19_1_SearchAll(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	spec.IMAP.Commands = []core.IMAPCommand{
		{
			Tag: "A001",
			Cmd: "SEARCH ALL",
			Responses: []string{
				"* SEARCH 1 2 3 4 5",
				"A001 OK SEARCH completed",
			},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if !strings.Contains(string(cfgs[4].Payload), "* SEARCH 1 2 3 4 5") {
		t.Errorf("cfg[4] should contain '* SEARCH 1 2 3 4 5': %q", cfgs[4].Payload)
	}
}

// 1.19.6: SEARCH UNSEEN with empty result -> "* SEARCH" (empty list).
func TestIMAPPoint_1_19_6_SearchEmpty(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	spec.IMAP.Commands = []core.IMAPCommand{
		{
			Tag: "A001",
			Cmd: "SEARCH UNSEEN",
			Responses: []string{
				"* SEARCH",
				"A001 OK SEARCH completed",
			},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if string(cfgs[4].Payload) != "* SEARCH\r\n" {
		t.Errorf("cfg[4] should be '* SEARCH\\r\\n': %q", cfgs[4].Payload)
	}
}

// --- 1.21 FETCH ---

// 1.21.1: FETCH FLAGS.
func TestIMAPPoint_1_21_1_FetchFlags(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	spec.IMAP.Commands = []core.IMAPCommand{
		{
			Tag: "A001",
			Cmd: "FETCH 1 FLAGS",
			Responses: []string{
				"* 1 FETCH (FLAGS (\\Seen))",
				"A001 OK FETCH completed",
			},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if !strings.Contains(string(cfgs[4].Payload), "FLAGS (\\Seen)") {
		t.Errorf("cfg[4] should contain 'FLAGS (\\Seen)': %q", cfgs[4].Payload)
	}
}

// 1.21.5: FETCH BODY[] with literal.
func TestIMAPPoint_1_21_5_FetchBodyLiteral(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	mailBody := "From: alice@example.com\r\nSubject: Test\r\n\r\nHello, world!"
	spec.IMAP.Commands = []core.IMAPCommand{
		{
			Tag:         "A001",
			Cmd:         "FETCH 1 BODY[]",
			Responses:   []string{"* 1 FETCH (BODY[] {" + itoa(len(mailBody)) + "})", "A001 OK FETCH completed"},
			LiteralBody: mailBody,
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// cfg[4] = "* 1 FETCH (BODY[] {<len>})\r\n" down
	if !strings.Contains(string(cfgs[4].Payload), "BODY[] {"+itoa(len(mailBody))+"}") {
		t.Errorf("cfg[4] should contain 'BODY[] {%d}': %q", len(mailBody), cfgs[4].Payload)
	}
	// cfg[5] = literal body bytes
	if string(cfgs[5].Payload) != mailBody {
		t.Errorf("cfg[5] payload=%q, want %q", cfgs[5].Payload, mailBody)
	}
	// cfg[6] = trailing CRLF
	if string(cfgs[6].Payload) != "\r\n" {
		t.Errorf("cfg[6] should be '\\r\\n': %q", cfgs[6].Payload)
	}
	// cfg[7] = A001 OK FETCH completed
	if !strings.Contains(string(cfgs[7].Payload), "A001 OK FETCH") {
		t.Errorf("cfg[7] should contain 'A001 OK FETCH': %q", cfgs[7].Payload)
	}
}

// --- 1.22 STORE ---

// 1.22.1: STORE +FLAGS \Seen.
func TestIMAPPoint_1_22_1_StoreAddFlags(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	spec.IMAP.Commands = []core.IMAPCommand{
		{
			Tag: "A001",
			Cmd: "STORE 1 +FLAGS \\Seen",
			Responses: []string{
				"* 1 FETCH (FLAGS (\\Seen))",
				"A001 OK STORE completed",
			},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if !strings.Contains(string(cfgs[3].Payload), "STORE 1 +FLAGS \\Seen") {
		t.Errorf("cfg[3] should contain 'STORE 1 +FLAGS \\Seen': %q", cfgs[3].Payload)
	}
}

// 1.22.2: STORE -FLAGS \Seen.
func TestIMAPPoint_1_22_2_StoreRemoveFlags(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	spec.IMAP.Commands = []core.IMAPCommand{
		{Tag: "A001", Cmd: "STORE 1 -FLAGS \\Seen", Responses: []string{"A001 OK STORE completed"}},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if !strings.Contains(string(cfgs[3].Payload), "STORE 1 -FLAGS \\Seen") {
		t.Errorf("cfg[3] should contain 'STORE 1 -FLAGS \\Seen': %q", cfgs[3].Payload)
	}
}

// --- 1.23 COPY ---

// 1.23.1: COPY success.
func TestIMAPPoint_1_23_1_Copy(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	spec.IMAP.Commands = []core.IMAPCommand{
		{Tag: "A001", Cmd: "COPY 1 INBOX.Saved", Responses: []string{"A001 OK COPY completed"}},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if !strings.Contains(string(cfgs[4].Payload), "A001 OK COPY") {
		t.Errorf("cfg[4] should contain 'A001 OK COPY': %q", cfgs[4].Payload)
	}
}

// 1.23.2: COPY to non-existent mailbox -> tagged NO.
func TestIMAPPoint_1_23_2_CopyNonExistent(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	spec.IMAP.Commands = []core.IMAPCommand{
		{Tag: "A001", Cmd: "COPY 1 INBOX.NonExistent", Responses: []string{"A001 NO COPY failed"}},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if !strings.Contains(string(cfgs[4].Payload), "A001 NO COPY failed") {
		t.Errorf("cfg[4] should contain 'A001 NO COPY failed': %q", cfgs[4].Payload)
	}
}

// --- 1.24 MOVE ---

// 1.24.1: MOVE success.
func TestIMAPPoint_1_24_1_Move(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	spec.IMAP.Commands = []core.IMAPCommand{
		{Tag: "A001", Cmd: "MOVE 1 INBOX.Trash", Responses: []string{"* 1 EXPUNGE", "A001 OK MOVE completed"}},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if !strings.Contains(string(cfgs[3].Payload), "MOVE 1 INBOX.Trash") {
		t.Errorf("cfg[3] should contain 'MOVE 1 INBOX.Trash': %q", cfgs[3].Payload)
	}
}

// --- 3.19.1 C-IMAP-1.1: literal cross-segment PSH ---

// 3.19.1.1: FETCH BODY[] with 10000-byte literal + MSS=1460 -> 7 segments.
func TestIMAPPoint_3_19_1_1_LiteralCrossSegmentPSH(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	testutil.EnsureTCP(&spec).MSS = 1460
	body := strings.Repeat("x", 10000)
	spec.IMAP.Commands = []core.IMAPCommand{
		{
			Tag:         "A001",
			Cmd:         "FETCH 1 BODY[]",
			Responses:   []string{"* 1 FETCH (BODY[] {10000})", "A001 OK FETCH completed"},
			LiteralBody: body,
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// Count the literal body segments: 10000 / 1460 = 6.85 -> 7 segments
	// (1460 * 6 = 8760; 10000 - 8760 = 1240 -> 7th segment)
	// Find segments that are pure "x" bytes.
	var bodySegs int
	for _, c := range cfgs {
		if c.Direction == "down" && c.L4.Flags == 0x18 {
			s := string(c.Payload)
			if len(s) > 0 && strings.Trim(s, "x") == "" {
				bodySegs++
			}
		}
	}
	if bodySegs != 7 {
		t.Errorf("bodySegs=%d, want 7 (10000/1460 = 6.85 -> 7 segments)", bodySegs)
	}
}

// 3.19.1.3: FETCH BODY[] with empty literal -> single segment (no multi-segment).
func TestIMAPPoint_3_19_1_3_LiteralEmptySingleSegment(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	testutil.EnsureTCP(&spec).MSS = 1460
	spec.IMAP.Commands = []core.IMAPCommand{
		{
			Tag:         "A001",
			Cmd:         "FETCH 1 BODY[]",
			Responses:   []string{"* 1 FETCH (BODY[] {0})", "A001 OK FETCH completed"},
			LiteralBody: "",
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// handshake(3) + cmd(1) + resp header(1) + [no body] + CRLF(1) + OK(1) + teardown(4) = 11
	if len(cfgs) != 11 {
		t.Fatalf("len=%d, want 11 (empty literal produces no body segment)", len(cfgs))
	}
}

// --- 3.19.2 C-IMAP-1.2: IDLE server timeout ---

// 3.19.2.1: ServerTimeoutBehavior="close_after_idle" -> BYE emitted.
func TestIMAPPoint_3_19_2_1_IDLETimeoutCloseAfter(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	spec.IMAP.IDLE = &core.IMAPIDLE{
		PushResponses:         nil,
		DoneResponse:          "A001 OK IDLE terminated",
		ServerTimeoutBehavior: "close_after_idle",
	}
	spec.IMAP.Commands = []core.IMAPCommand{
		{Tag: "A001", Cmd: "IDLE", Responses: []string{"+ idling"}, EmitIDLE: true},
	}
	cfgs := drain(mustPlan(t, p, spec))
	foundBye := false
	for _, c := range cfgs {
		if strings.Contains(string(c.Payload), "BYE IDLE timeout") {
			foundBye = true
			break
		}
	}
	if !foundBye {
		t.Errorf("close_after_idle should emit '* BYE IDLE timeout'")
	}
}

// 3.19.2.2: ServerTimeoutBehavior="keep_idle" -> BYE emitted (no teardown).
func TestIMAPPoint_3_19_2_2_IDLETimeoutKeepIdle(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	spec.IMAP.IDLE = &core.IMAPIDLE{
		PushResponses:         []string{"* 2 EXISTS"},
		DoneResponse:          "A001 OK IDLE terminated",
		ServerTimeoutBehavior: "keep_idle",
	}
	spec.IMAP.Commands = []core.IMAPCommand{
		{Tag: "A001", Cmd: "IDLE", Responses: []string{"+ idling"}, EmitIDLE: true},
	}
	cfgs := drain(mustPlan(t, p, spec))
	foundBye := false
	for _, c := range cfgs {
		if strings.Contains(string(c.Payload), "BYE IDLE timeout") {
			foundBye = true
			break
		}
	}
	if !foundBye {
		t.Errorf("keep_idle should emit '* BYE IDLE timeout'")
	}
}

// 3.19.2.3: ServerTimeoutBehavior="none" -> no BYE.
func TestIMAPPoint_3_19_2_3_IDLETimeoutNone(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	spec.IMAP.IDLE = &core.IMAPIDLE{
		PushResponses:         nil,
		DoneResponse:          "A001 OK IDLE terminated",
		ServerTimeoutBehavior: "none",
	}
	spec.IMAP.Commands = []core.IMAPCommand{
		{Tag: "A001", Cmd: "IDLE", Responses: []string{"+ idling"}, EmitIDLE: true},
	}
	cfgs := drain(mustPlan(t, p, spec))
	for i, c := range cfgs {
		if strings.Contains(string(c.Payload), "BYE IDLE timeout") {
			t.Errorf("cfg[%d]: none should NOT emit BYE: %q", i, c.Payload)
		}
	}
}

// --- 3.19.3 C-IMAP-1.3: AUTHENTICATE cancellation ---

// 3.19.3.1: AUTHENTICATE PLAIN + CancelAfterResponses=1 -> "* \r\n" cancel.
func TestIMAPPoint_3_19_3_1_AuthCancelAfter1(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	spec.IMAP.Commands = []core.IMAPCommand{
		{
			Tag:                  "A001",
			Cmd:                  "AUTHENTICATE PLAIN",
			Responses:            []string{"+ ", "A001 NO AUTHENTICATE cancelled"},
			CancelAfterResponses: 1,
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// Find the cancel packet (up, "*\r\n").
	foundCancel := false
	for _, c := range cfgs {
		if c.Direction == "up" && string(c.Payload) == "*\r\n" {
			foundCancel = true
			break
		}
	}
	if !foundCancel {
		t.Errorf("cancel line '*\\r\\n' not found")
	}
}

// 3.19.3.3: CancelAfterResponses=0 (default) -> no cancel line.
func TestIMAPPoint_3_19_3_3_NoCancelWhenZero(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	spec.IMAP.Commands = []core.IMAPCommand{
		{
			Tag:                  "A001",
			Cmd:                  "AUTHENTICATE PLAIN",
			Responses:            []string{"+ ", "A001 OK AUTHENTICATE completed"},
			CancelAfterResponses: 0,
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	for i, c := range cfgs {
		if c.Direction == "up" && string(c.Payload) == "*\r\n" {
			t.Errorf("cfg[%d]: no cancel line should be emitted when CancelAfterResponses=0: %q", i, c.Payload)
		}
	}
}

// --- 3.19.4 C-IMAP-1.4: tag mismatch ---

// 3.19.4.1: Command tag A001, response tag B002 -> both replayed.
func TestIMAPPoint_3_19_4_1_TagMismatchReplayed(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	spec.IMAP.Commands = []core.IMAPCommand{
		{Tag: "A001", Cmd: "LOGIN alice secret", Responses: []string{"B002 OK LOGIN completed"}},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if !strings.Contains(string(cfgs[3].Payload), "A001 LOGIN") {
		t.Errorf("cfg[3] should contain 'A001 LOGIN': %q", cfgs[3].Payload)
	}
	if !strings.Contains(string(cfgs[4].Payload), "B002 OK LOGIN") {
		t.Errorf("cfg[4] should contain 'B002 OK LOGIN' (mismatched tag replayed): %q", cfgs[4].Payload)
	}
}

// --- 3.19.5 C-IMAP-1.5: pipelined commands ---

// 3.19.5.1: PipelinedCommands=true -> all commands first, then all responses.
func TestIMAPPoint_3_19_5_1_PipelinedCommands(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	spec.IMAP.PipelinedCommands = true
	spec.IMAP.Commands = []core.IMAPCommand{
		{Tag: "A001", Cmd: "LOGIN alice secret", Responses: []string{"A001 OK LOGIN completed"}},
		{Tag: "A002", Cmd: "SELECT INBOX", Responses: []string{"* 1 EXISTS", "A002 OK SELECT completed"}},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// cfg[3] = A001 LOGIN up
	if !strings.Contains(string(cfgs[3].Payload), "A001 LOGIN") {
		t.Errorf("cfg[3] should contain 'A001 LOGIN': %q", cfgs[3].Payload)
	}
	// cfg[4] = A002 SELECT up (pipelined: no response between commands)
	if cfgs[4].Direction != "up" || !strings.Contains(string(cfgs[4].Payload), "A002 SELECT") {
		t.Errorf("cfg[4]: dir=%s payload=%q, want up/A002 SELECT (pipelined)", cfgs[4].Direction, cfgs[4].Payload)
	}
	// cfg[5] = A001 OK LOGIN down (first response)
	if cfgs[5].Direction != "down" || !strings.Contains(string(cfgs[5].Payload), "A001 OK LOGIN") {
		t.Errorf("cfg[5]: dir=%s payload=%q, want down/A001 OK LOGIN", cfgs[5].Direction, cfgs[5].Payload)
	}
}

// 3.19.5.2: PipelinedCommands=false (default) -> alternating cmd/resp.
func TestIMAPPoint_3_19_5_2_NonPipelinedDefault(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	spec.IMAP.PipelinedCommands = false
	spec.IMAP.Commands = []core.IMAPCommand{
		{Tag: "A001", Cmd: "LOGIN alice secret", Responses: []string{"A001 OK LOGIN completed"}},
		{Tag: "A002", Cmd: "SELECT INBOX", Responses: []string{"* 1 EXISTS", "A002 OK SELECT completed"}},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// cfg[3] = A001 LOGIN up
	if !strings.Contains(string(cfgs[3].Payload), "A001 LOGIN") {
		t.Errorf("cfg[3] should contain 'A001 LOGIN': %q", cfgs[3].Payload)
	}
	// cfg[4] = A001 OK LOGIN down (immediately after cmd1, before cmd2)
	if cfgs[4].Direction != "down" || !strings.Contains(string(cfgs[4].Payload), "A001 OK LOGIN") {
		t.Errorf("cfg[4]: dir=%s payload=%q, want down/A001 OK LOGIN (non-pipelined)", cfgs[4].Direction, cfgs[4].Payload)
	}
	// cfg[5] = A002 SELECT up (cmd2 after resp1)
	if cfgs[5].Direction != "up" || !strings.Contains(string(cfgs[5].Payload), "A002 SELECT") {
		t.Errorf("cfg[5]: dir=%s payload=%q, want up/A002 SELECT", cfgs[5].Direction, cfgs[5].Payload)
	}
}

// --- 3.19.6 C-IMAP-1.6: {0} literal ---

// 3.19.6.1: APPEND INBOX {0} with empty LiteralBody -> "{0}\r\n\r\n" wire format.
func TestIMAPPoint_3_19_6_1_AppendZeroLiteral(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	spec.IMAP.Commands = []core.IMAPCommand{
		{
			Tag:         "A001",
			Cmd:         "APPEND INBOX {0}",
			Responses:   []string{"+ Ready", "A001 OK APPEND completed"},
			LiteralBody: "",
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// handshake(3) + cmd(1) + [no literal body up since len==0] + 2 resps(2) + teardown(4) = 10
	// Note: the user-provided Cmd "APPEND INBOX {0}" has a placeholder,
	// but the literal body is empty so emitCommandWithOptionalLiteral
	// skips the body packet (len(body)==0 check).
	if len(cfgs) != 10 {
		t.Fatalf("len=%d, want 10", len(cfgs))
	}
	if !strings.Contains(string(cfgs[3].Payload), "APPEND INBOX {0}") {
		t.Errorf("cfg[3] should contain 'APPEND INBOX {0}': %q", cfgs[3].Payload)
	}
}

// 3.19.6.2: FETCH 1 BODY[] with empty LiteralBody -> "{0}\r\n\r\n" wire format.
func TestIMAPPoint_3_19_6_2_FetchZeroLiteral(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	spec.IMAP.Commands = []core.IMAPCommand{
		{
			Tag:         "A001",
			Cmd:         "FETCH 1 BODY[]",
			Responses:   []string{"* 1 FETCH (BODY[] {0})", "A001 OK FETCH completed"},
			LiteralBody: "",
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// cfg[4] = "* 1 FETCH (BODY[] {0})\r\n" down (the {0} is preserved as-is since len==0)
	if !strings.Contains(string(cfgs[4].Payload), "{0}") {
		t.Errorf("cfg[4] should contain '{0}': %q", cfgs[4].Payload)
	}
	if !strings.HasSuffix(string(cfgs[4].Payload), "\r\n") {
		t.Errorf("cfg[4] should end with CRLF: %q", cfgs[4].Payload)
	}
	// cfg[5] = trailing CRLF (the closing CRLF of the FETCH response)
	if string(cfgs[5].Payload) != "\r\n" {
		t.Errorf("cfg[5] should be '\\r\\n' (trailing CRLF): %q", cfgs[5].Payload)
	}
}

// --- 3.19.7 C-IMAP-1.7: UTF-8 mailbox ---

// 3.19.7.1: AllowUTF8Mailbox=true + non-ASCII mailbox -> UTF-8 bytes verbatim.
func TestIMAPPoint_3_19_7_1_UTF8MailboxTrue(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	spec.IMAP.AllowUTF8Mailbox = true
	spec.IMAP.Commands = []core.IMAPCommand{
		{Tag: "A001", Cmd: "SELECT 收发室", Responses: []string{"A001 OK SELECT completed"}},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if !strings.Contains(string(cfgs[3].Payload), "SELECT 收发室") {
		t.Errorf("cfg[3] should contain 'SELECT 收发室' (UTF-8 verbatim): %q", cfgs[3].Payload)
	}
}

// 3.19.7.2: AllowUTF8Mailbox=false + non-ASCII mailbox -> Validate error.
func TestIMAPPoint_3_19_7_2_UTF8MailboxFalseRejected(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	spec.IMAP.AllowUTF8Mailbox = false
	spec.IMAP.Commands[0].Cmd = "SELECT 收发室"
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "non-ASCII") {
		t.Errorf("err=%v, want contains 'non-ASCII'", err)
	}
}

// 3.19.7.3: AllowUTF8Mailbox=true + ASCII mailbox -> same as ASCII.
func TestIMAPPoint_3_19_7_3_UTF8MailboxASCIISame(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	spec.IMAP.AllowUTF8Mailbox = true
	spec.IMAP.Commands = []core.IMAPCommand{
		{Tag: "A001", Cmd: "SELECT INBOX", Responses: []string{"A001 OK SELECT completed"}},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if string(cfgs[3].Payload) != "A001 SELECT INBOX\r\n" {
		t.Errorf("cfg[3] should be 'A001 SELECT INBOX\\r\\n': %q", cfgs[3].Payload)
	}
}

// --- 3.19.9 C-IMAP-1.9: UID cache invalidation ---

// 3.19.9.2: UIDCacheInvalidation=true -> "* OK [HIGHESTMODSEQ 1] cache invalidated" appended.
func TestIMAPPoint_3_19_9_2_UIDCacheInvalidation(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	spec.IMAP.Commands = []core.IMAPCommand{
		{
			Tag:                  "A001",
			Cmd:                  "SELECT INBOX",
			Responses:            []string{"* OK [UIDVALIDITY 5678]", "* 1 EXISTS", "A001 OK SELECT completed"},
			UIDCacheInvalidation: true,
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// Find the invalidation response (should be after the 3 normal responses).
	foundInvalidation := false
	for _, c := range cfgs {
		if strings.Contains(string(c.Payload), "HIGHESTMODSEQ 1") &&
			strings.Contains(string(c.Payload), "cache invalidated") {
			foundInvalidation = true
			break
		}
	}
	if !foundInvalidation {
		t.Errorf("UIDCacheInvalidation=true should emit '* OK [HIGHESTMODSEQ 1] cache invalidated'")
	}
}

// 3.19.9.3: UIDCacheInvalidation=false (default) -> no invalidation response.
func TestIMAPPoint_3_19_9_3_NoUIDCacheInvalidation(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	spec.IMAP.Commands = []core.IMAPCommand{
		{
			Tag:                  "A001",
			Cmd:                  "SELECT INBOX",
			Responses:            []string{"* OK [UIDVALIDITY 5678]", "* 1 EXISTS", "A001 OK SELECT completed"},
			UIDCacheInvalidation: false,
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	for i, c := range cfgs {
		if strings.Contains(string(c.Payload), "HIGHESTMODSEQ 1") {
			t.Errorf("cfg[%d]: no invalidation response should be emitted: %q", i, c.Payload)
		}
	}
}

// --- 3.19.10 C-IMAP-1.10: concurrent SELECT (per-flow independence) ---

// 3.19.10.1: 8 concurrent flows each emit complete SELECT + FETCH responses.
func TestIMAPPoint_3_19_10_1_ConcurrentSelectIndependence(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 50000, DstPort: 143,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		IMAP: &core.IMAPConfig{
			Commands: []core.IMAPCommand{
				{Tag: "A001", Cmd: "SELECT INBOX", Responses: []string{"* 1 EXISTS", "A001 OK"}},
				{Tag: "A002", Cmd: "FETCH 1 FLAGS", Responses: []string{"* 1 FETCH (FLAGS (\\Seen))", "A002 OK"}},
			},
		},
	}
	const N = 8
	done := make(chan struct {
		idx  int
		cfgs []core.PacketConfig
		err  error
	}, N)
	for i := 0; i < N; i++ {
		i := i
		go func() {
			s := spec
			s.SrcPort = uint16(50000 + i)
			ch, err := p.Plan(context.Background(), s)
			if err != nil {
				done <- struct {
					idx  int
					cfgs []core.PacketConfig
					err  error
				}{i, nil, err}
				return
			}
			done <- struct {
				idx  int
				cfgs []core.PacketConfig
				err  error
			}{i, drain(ch), nil}
		}()
	}
	results := make(map[int][]core.PacketConfig)
	for i := 0; i < N; i++ {
		r := <-done
		if r.err != nil {
			t.Fatalf("flow %d: %v", r.idx, r.err)
		}
		results[r.idx] = r.cfgs
	}
	// Each flow should have the same number of packets.
	firstLen := len(results[0])
	for i, cfgs := range results {
		if len(cfgs) != firstLen {
			t.Errorf("flow %d: len=%d, want %d (per-flow independence)", i, len(cfgs), firstLen)
		}
		// Each flow should have its own FlowID (unique per 4-tuple).
		flowID := cfgs[0].FlowID
		if flowID == "" {
			t.Errorf("flow %d: empty FlowID", i)
		}
	}
	// All FlowIDs should be distinct.
	seen := make(map[string]bool)
	for i, cfgs := range results {
		fid := cfgs[0].FlowID
		if seen[fid] {
			t.Errorf("flow %d: FlowID %q duplicated", i, fid)
		}
		seen[fid] = true
	}
}

// --- 4.1 empty values ---

// 4.1.1: SELECT INBOX with * 0 EXISTS (empty mailbox).
func TestIMAPPoint_4_1_1_EmptyMailbox(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	spec.IMAP.Commands = []core.IMAPCommand{
		{Tag: "A001", Cmd: "SELECT INBOX", Responses: []string{"* 0 EXISTS", "A001 OK SELECT completed"}},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if !strings.Contains(string(cfgs[4].Payload), "* 0 EXISTS") {
		t.Errorf("cfg[4] should contain '* 0 EXISTS': %q", cfgs[4].Payload)
	}
}

// 4.1.4: 0-byte email -> "BODY[] {0}\r\n\r\n".
func TestIMAPPoint_4_1_4_EmptyEmailBody(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	spec.IMAP.Commands = []core.IMAPCommand{
		{
			Tag:         "A001",
			Cmd:         "FETCH 1 BODY[]",
			Responses:   []string{"* 1 FETCH (BODY[] {0})", "A001 OK FETCH completed"},
			LiteralBody: "",
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if !strings.Contains(string(cfgs[4].Payload), "{0}") {
		t.Errorf("cfg[4] should contain '{0}': %q", cfgs[4].Payload)
	}
}

// --- 4.2 boundary values ---

// 4.2.1: UIDVALIDITY = 0xFFFFFFFF (max uint32).
func TestIMAPPoint_4_2_1_UIDVALIDITYMax(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	spec.IMAP.Commands = []core.IMAPCommand{
		{Tag: "A001", Cmd: "SELECT INBOX", Responses: []string{"* OK [UIDVALIDITY 4294967295]", "A001 OK"}},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if !strings.Contains(string(cfgs[4].Payload), "UIDVALIDITY 4294967295") {
		t.Errorf("cfg[4] should contain 'UIDVALIDITY 4294967295': %q", cfgs[4].Payload)
	}
}

// 4.2.3: EXISTS = 4294967295 (max uint32).
func TestIMAPPoint_4_2_3_EXISTSMax(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	spec.IMAP.Commands = []core.IMAPCommand{
		{Tag: "A001", Cmd: "SELECT INBOX", Responses: []string{"* 4294967295 EXISTS", "A001 OK"}},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if !strings.Contains(string(cfgs[4].Payload), "4294967295 EXISTS") {
		t.Errorf("cfg[4] should contain '4294967295 EXISTS': %q", cfgs[4].Payload)
	}
}

// --- 4.5 small data ---

// 4.5.1: A001 NOOP is 11 bytes ("A001 NOOP\r\n"), single PSH-ACK.
func TestIMAPPoint_4_5_1_MinimalCommand(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	spec.IMAP.Commands = []core.IMAPCommand{
		{Tag: "A001", Cmd: "NOOP", Responses: []string{"A001 OK"}},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs[3].Payload) != 11 {
		t.Errorf("cfg[3] payload len=%d, want 11 ('A001 NOOP\\r\\n' = 9+2)", len(cfgs[3].Payload))
	}
}

// 4.5.2: "* OK" is 4 bytes response.
func TestIMAPPoint_4_5_2_MinimalResponse(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	spec.IMAP.Commands = []core.IMAPCommand{
		{Tag: "A001", Cmd: "NOOP", Responses: []string{"* OK"}},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// cfg[4] = "* OK\r\n" (6 bytes)
	if len(cfgs[4].Payload) != 6 {
		t.Errorf("cfg[4] payload len=%d, want 6 ('* OK\\r\\n')", len(cfgs[4].Payload))
	}
}
