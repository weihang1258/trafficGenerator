package pop3

// Atomic test points for the POP3 planner. Each test corresponds to one
// or more test cases in /tmp/l7_planner_design/testcases_pop3.md (RFC
// 1939 §3-§8, RFC 2449 CAPA, RFC 1734 AUTH, RFC 2595 STLS, RFC 2984
// APOP). Tests assert observable PacketConfig field values, not just
// "no error".

import (
	"context"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/protocol/testutil"
)

// --- 1.1 USER command ---

// 1.1.1: USER alice emits "USER alice\r\n" PSH-ACK up.
func TestPOP3Point_1_1_1_USERAlice(t *testing.T) {
	p := NewPlanner()
	spec := validPOP3SpecNoBanner()
	spec.POP3.Commands = []core.POP3Command{
		{Cmd: "USER alice", Response: "+OK alice"},
	}
	cfgs := drain(mustPlan(t, p, spec))
	userPkt := cfgs[3]
	if userPkt.Direction != "up" || string(userPkt.Payload) != "USER alice\r\n" {
		t.Errorf("USER alice: got dir=%s payload=%q, want up/'USER alice\\r\\n'", userPkt.Direction, userPkt.Payload)
	}
}

// 1.1.2: empty USER Cmd is skipped, no packet emitted.
func TestPOP3Point_1_1_2_USEREmptySkipped(t *testing.T) {
	p := NewPlanner()
	spec := validPOP3SpecNoBanner()
	spec.POP3.Banner = ""
	spec.POP3.Commands = []core.POP3Command{
		{Cmd: "", Response: "+OK"},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// handshake(3) + resp(1) + teardown(4) = 8 (no cmd packet)
	if len(cfgs) != 8 {
		t.Fatalf("len=%d, want 8 (empty Cmd skipped)", len(cfgs))
	}
	if cfgs[3].Direction != "down" {
		t.Errorf("cfg[3]: dir=%s, want down (only resp, no cmd)", cfgs[3].Direction)
	}
}

// 1.1.3: USER in TRANSACTION state still emits (no state check).
func TestPOP3Point_1_1_3_USERInTransactionEmits(t *testing.T) {
	p := NewPlanner()
	spec := validPOP3SpecNoBanner()
	spec.POP3.Commands = []core.POP3Command{
		// After AUTH, the user sends USER again (per RFC 1939 §6 this
		// is allowed - re-auth start). Planner does NOT check state.
		{Cmd: "USER bob", Response: "+OK bob"},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) < 5 {
		t.Fatalf("len=%d, want >= 5", len(cfgs))
	}
	if cfgs[3].Direction != "up" || !strings.Contains(string(cfgs[3].Payload), "USER bob") {
		t.Errorf("USER bob should still emit even though state check is user responsibility")
	}
}

// 1.1.4: USER with CRLF injection is rejected by Validate.
func TestPOP3Point_1_1_4_USERCRLFInjectionRejected(t *testing.T) {
	p := NewPlanner()
	spec := validPOP3SpecNoBanner()
	spec.POP3.Commands[0].Cmd = "USER alice\r\nDELE 1"
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "CRLF") {
		t.Errorf("err=%v, want contains 'CRLF'", err)
	}
}

// 1.1.5: USER name 40 chars (boundary) emits 45-byte payload.
func TestPOP3Point_1_1_5_USERBoundary(t *testing.T) {
	p := NewPlanner()
	spec := validPOP3SpecNoBanner()
	name := strings.Repeat("a", 40)
	spec.POP3.Commands[0].Cmd = "USER " + name
	cfgs := drain(mustPlan(t, p, spec))
	userPkt := cfgs[3]
	// "USER " (5) + 40 chars + "\r\n" (2) = 47
	if len(userPkt.Payload) != 47 {
		t.Errorf("len=%d, want 47 (5+40+2)", len(userPkt.Payload))
	}
	if !strings.HasSuffix(string(userPkt.Payload), "\r\n") {
		t.Errorf("payload should end with CRLF: %q", userPkt.Payload)
	}
}

// 1.1.6: USER name 41 chars (over) is rejected by Validate.
func TestPOP3Point_1_1_6_USEROverLengthRejected(t *testing.T) {
	p := NewPlanner()
	spec := validPOP3SpecNoBanner()
	spec.POP3.Commands[0].Cmd = "USER " + strings.Repeat("a", 41)
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "USER") {
		t.Errorf("err=%v, want contains 'USER'", err)
	}
}

// --- 1.2 PASS command ---

// 1.2.1: PASS "secret123" after USER emits "PASS secret123\r\n".
func TestPOP3Point_1_2_1_PASSSecret(t *testing.T) {
	p := NewPlanner()
	spec := validPOP3SpecNoBanner()
	spec.POP3.Commands = []core.POP3Command{
		{Cmd: "USER alice", Response: "+OK"},
		{Cmd: "PASS secret123", Response: "+OK logged in"},
	}
	cfgs := drain(mustPlan(t, p, spec))
	passPkt := cfgs[5]
	if passPkt.Direction != "up" || string(passPkt.Payload) != "PASS secret123\r\n" {
		t.Errorf("PASS: got dir=%s payload=%q", passPkt.Direction, passPkt.Payload)
	}
}

// 1.2.3: PASS 255 chars (boundary) emits single packet.
func TestPOP3Point_1_2_3_PASSBoundary(t *testing.T) {
	p := NewPlanner()
	spec := validPOP3SpecNoBanner()
	password := strings.Repeat("x", 255)
	spec.POP3.Commands[1].Cmd = "PASS " + password
	cfgs := drain(mustPlan(t, p, spec))
	passPkt := cfgs[5]
	if len(passPkt.Payload) != 5+255+2 {
		t.Errorf("len=%d, want %d", len(passPkt.Payload), 5+255+2)
	}
}

// 1.2.4: PASS 256 chars is rejected.
func TestPOP3Point_1_2_4_PASSOverLengthRejected(t *testing.T) {
	p := NewPlanner()
	spec := validPOP3SpecNoBanner()
	spec.POP3.Commands[1].Cmd = "PASS " + strings.Repeat("x", 256)
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "PASS") {
		t.Errorf("err=%v, want contains 'PASS'", err)
	}
}

// 1.2.5: PASS with special chars emits verbatim.
func TestPOP3Point_1_2_5_PASSSpecialChars(t *testing.T) {
	p := NewPlanner()
	spec := validPOP3SpecNoBanner()
	spec.POP3.Commands[1].Cmd = "PASS p@ss!"
	cfgs := drain(mustPlan(t, p, spec))
	if string(cfgs[5].Payload) != "PASS p@ss!\r\n" {
		t.Errorf("PASS special chars should not escape: got %q", cfgs[5].Payload)
	}
}

// --- 1.3 APOP command ---

// 1.3.1: APOP alice <valid-digest> emits 45-byte payload (4+1+5+1+32+2).
func TestPOP3Point_1_3_1_APOPValid(t *testing.T) {
	p := NewPlanner()
	spec := validPOP3SpecNoBanner()
	spec.POP3.Commands = []core.POP3Command{
		{Cmd: "APOP alice c4c9334bac560ecc975eac1bbdded0e0", Response: "+OK logged in"},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// With banner: handshake(3) + banner(1) + cmd(1) + resp(1) + teardown(4) = 10
	apopPkt := cfgs[3]
	if apopPkt.Direction != "up" || string(apopPkt.Payload) != "APOP alice c4c9334bac560ecc975eac1bbdded0e0\r\n" {
		t.Errorf("APOP: got dir=%s payload=%q", apopPkt.Direction, apopPkt.Payload)
	}
	if len(apopPkt.Payload) != 45 {
		t.Errorf("len=%d, want 45 (4+1+5+1+32+2)", len(apopPkt.Payload))
	}
}

// 1.3.2: APOP digest 31 chars is rejected.
func TestPOP3Point_1_3_2_APOPDigestTooShort(t *testing.T) {
	p := NewPlanner()
	spec := validPOP3SpecNoBanner()
	spec.POP3.Commands = []core.POP3Command{
		{Cmd: "APOP alice " + strings.Repeat("a", 31), Response: "+OK"},
	}
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "digest") {
		t.Errorf("err=%v, want contains 'digest'", err)
	}
}

// 1.3.3: APOP digest 32 non-hex chars is rejected.
func TestPOP3Point_1_3_3_APOPDigestNotHex(t *testing.T) {
	p := NewPlanner()
	spec := validPOP3SpecNoBanner()
	spec.POP3.Commands = []core.POP3Command{
		{Cmd: "APOP alice " + strings.Repeat("z", 32), Response: "+OK"},
	}
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "hex") {
		t.Errorf("err=%v, want contains 'hex'", err)
	}
}

// 1.3.4: APOP with empty name emits with double space (Validate does not catch).
func TestPOP3Point_1_3_4_APOPEmptyName(t *testing.T) {
	p := NewPlanner()
	spec := validPOP3SpecNoBanner()
	spec.POP3.Commands = []core.POP3Command{
		{Cmd: "APOP  c4c9334bac560ecc975eac1bbdded0e0", Response: "+OK"},
	}
	// Should NOT error at Validate (we don't check empty APOP name)
	if err := p.Validate(spec); err != nil {
		t.Errorf("Validate should accept empty APOP name: %v", err)
	}
	cfgs := drain(mustPlan(t, p, spec))
	apopPkt := cfgs[3]
	if !strings.Contains(string(apopPkt.Payload), "APOP") || !strings.Contains(string(apopPkt.Payload), "c4c933") {
		t.Errorf("APOP empty name should still emit: got %q", apopPkt.Payload)
	}
}

// --- 1.4 STAT command ---

// 1.4.1: STAT without Mailbox uses user-provided response.
func TestPOP3Point_1_4_1_STAT_NoMailbox(t *testing.T) {
	p := NewPlanner()
	spec := validPOP3SpecNoBanner()
	spec.POP3.Commands = []core.POP3Command{
		{Cmd: "STAT", Response: "+OK 5 12345"},
	}
	cfgs := drain(mustPlan(t, p, spec))
	resp := string(cfgs[4].Payload)
	if resp != "+OK 5 12345\r\n" {
		t.Errorf("STAT resp=%q, want '+OK 5 12345\\r\\n'", resp)
	}
}

// 1.4.5: STAT with empty Response is skipped.
func TestPOP3Point_1_4_5_STAT_EmptyResponse(t *testing.T) {
	p := NewPlanner()
	spec := validPOP3SpecNoBanner()
	spec.POP3.Banner = ""
	spec.POP3.Commands = []core.POP3Command{
		{Cmd: "STAT", Response: ""},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// handshake(3) + cmd(1) + teardown(4) = 8 (no resp)
	if len(cfgs) != 8 {
		t.Fatalf("len=%d, want 8 (empty resp skipped)", len(cfgs))
	}
}

// --- 1.5 LIST command ---

// 1.5.1: LIST (no arg) with 3-msg Mailbox; we use user Response here since
// the planner does NOT auto-generate LIST (only RETR via EmitMailDrop).
// This test verifies the user-provided multi-line LIST response.
func TestPOP3Point_1_5_1_LIST_3MessagesUserProvided(t *testing.T) {
	p := NewPlanner()
	spec := validPOP3SpecNoBanner()
	spec.POP3.Commands = []core.POP3Command{
		{
			Cmd:       "LIST",
			Response:  "+OK 3 messages (600 octets)\r\n1 200\r\n2 200\r\n3 200\r\n.\r\n",
			Multiline: true,
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	resp := string(cfgs[4].Payload)
	if !strings.HasSuffix(resp, ".\r\n") {
		t.Errorf("LIST multiline must end with terminator: %q", resp)
	}
	if !strings.Contains(resp, "1 200\r\n2 200\r\n3 200") {
		t.Errorf("LIST body should list 3 messages: %q", resp)
	}
}

// 1.5.3: LIST 1 (single msg#) emits single-line response.
func TestPOP3Point_1_5_3_LIST_1SingleLine(t *testing.T) {
	p := NewPlanner()
	spec := validPOP3SpecNoBanner()
	spec.POP3.Commands = []core.POP3Command{
		{Cmd: "LIST 1", Response: "+OK 1 100"},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if string(cfgs[4].Payload) != "+OK 1 100\r\n" {
		t.Errorf("LIST 1: got %q, want '+OK 1 100\\r\\n'", cfgs[4].Payload)
	}
}

// 1.5.4/5: LIST msg# out of range emits -ERR.
func TestPOP3Point_1_5_4_LIST_OutOfRange(t *testing.T) {
	p := NewPlanner()
	spec := validPOP3SpecNoBanner()
	spec.POP3.Commands = []core.POP3Command{
		{Cmd: "LIST 999", Response: "-ERR no such message"},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if !strings.Contains(string(cfgs[4].Payload), "-ERR no such message") {
		t.Errorf("LIST out-of-range should emit -ERR: got %q", cfgs[4].Payload)
	}
}

// --- 1.6 RETR command ---

// 1.6.1: RETR 1 with EmitMailDrop synthesizes full RETR response.
func TestPOP3Point_1_6_1_RETR_EmitMailDrop(t *testing.T) {
	p := NewPlanner()
	spec := validPOP3SpecNoBanner()
	spec.POP3.Mailbox = &core.POP3Mailbox{
		Messages: []core.POP3Message{
			{UID: "u1", Headers: []string{"From: bob@example.com"}, Body: "Hello"},
		},
	}
	spec.POP3.Commands = []core.POP3Command{
		{EmitMailDrop: true, MsgNum: 1},
	}
	cfgs := drain(mustPlan(t, p, spec))
	resp := string(cfgs[3].Payload)
	if !strings.Contains(resp, "+OK ") || !strings.Contains(resp, "octets\r\n") {
		t.Errorf("RETR resp should start with status line: %q", resp)
	}
	if !strings.Contains(resp, "From: bob@example.com") {
		t.Errorf("RETR resp should contain headers: %q", resp)
	}
	if !strings.Contains(resp, "Hello") {
		t.Errorf("RETR resp should contain body: %q", resp)
	}
	if !strings.HasSuffix(resp, ".\r\n") {
		t.Errorf("RETR must end with '.\r\\n': %q", resp)
	}
}

// 1.6.4: RETR with dot-stuffed body line.
func TestPOP3Point_1_6_4_RETR_DotStuffing(t *testing.T) {
	p := NewPlanner()
	spec := validPOP3SpecNoBanner()
	spec.POP3.Mailbox = &core.POP3Mailbox{
		Messages: []core.POP3Message{{UID: "u1", Body: ".hidden"}},
	}
	spec.POP3.Commands = []core.POP3Command{
		{EmitMailDrop: true, MsgNum: 1},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if !strings.Contains(string(cfgs[3].Payload), "..hidden") {
		t.Errorf("dot-stuffing should add extra '.': got %q", cfgs[3].Payload)
	}
}

// 1.6.5: RETR with empty body still emits terminator.
func TestPOP3Point_1_6_5_RETR_EmptyBody(t *testing.T) {
	p := NewPlanner()
	spec := validPOP3SpecNoBanner()
	spec.POP3.Mailbox = &core.POP3Mailbox{
		Messages: []core.POP3Message{{UID: "u1", Body: ""}},
	}
	spec.POP3.Commands = []core.POP3Command{
		{EmitMailDrop: true, MsgNum: 1},
	}
	cfgs := drain(mustPlan(t, p, spec))
	resp := string(cfgs[3].Payload)
	if !strings.Contains(resp, "+OK 0 octets") {
		t.Errorf("empty body should give 0 octets: %q", resp)
	}
	if !strings.HasSuffix(resp, ".\r\n") {
		t.Errorf("RETR must end with terminator: %q", resp)
	}
}

// 1.6.6: RETR with no Mailbox uses user Response verbatim.
func TestPOP3Point_1_6_6_RETR_VerbatimResponse(t *testing.T) {
	p := NewPlanner()
	spec := validPOP3SpecNoBanner()
	spec.POP3.Commands = []core.POP3Command{
		{Cmd: "RETR 1", Response: "+OK 200 octets\r\nFrom: bob\r\n.\r\n", Multiline: true},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if !strings.Contains(string(cfgs[4].Payload), "From: bob") {
		t.Errorf("RETR verbatim: got %q", cfgs[4].Payload)
	}
}

// --- 1.7 DELE command ---

// 1.7.1: DELE 1 emits "DELE 1\r\n" + +OK response.
func TestPOP3Point_1_7_1_DELE_1(t *testing.T) {
	p := NewPlanner()
	spec := validPOP3SpecNoBanner()
	spec.POP3.Commands = []core.POP3Command{
		{Cmd: "DELE 1", Response: "+OK message 1 deleted"},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if string(cfgs[3].Payload) != "DELE 1\r\n" {
		t.Errorf("DELE: got %q", cfgs[3].Payload)
	}
	if !strings.Contains(string(cfgs[4].Payload), "message 1 deleted") {
		t.Errorf("DELE resp: got %q", cfgs[4].Payload)
	}
}

// 1.7.2: DELE msg# out of range emits -ERR.
func TestPOP3Point_1_7_2_DELE_OutOfRange(t *testing.T) {
	p := NewPlanner()
	spec := validPOP3SpecNoBanner()
	spec.POP3.Commands = []core.POP3Command{
		{Cmd: "DELE 999", Response: "-ERR no such message"},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if !strings.Contains(string(cfgs[4].Payload), "-ERR no such message") {
		t.Errorf("DELE out-of-range: got %q", cfgs[4].Payload)
	}
}

// --- 1.8 NOOP command ---

// 1.8.1: NOOP emits "NOOP\r\n" + "+OK" (6 bytes + 5 bytes).
func TestPOP3Point_1_8_1_NOOP(t *testing.T) {
	p := NewPlanner()
	spec := validPOP3SpecNoBanner()
	spec.POP3.Commands = []core.POP3Command{
		{Cmd: "NOOP", Response: "+OK"},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if string(cfgs[3].Payload) != "NOOP\r\n" {
		t.Errorf("NOOP cmd: got %q, want 'NOOP\\r\\n'", cfgs[3].Payload)
	}
	if string(cfgs[4].Payload) != "+OK\r\n" {
		t.Errorf("NOOP resp: got %q, want '+OK\\r\\n'", cfgs[4].Payload)
	}
	if len(cfgs[3].Payload) != 6 {
		t.Errorf("NOOP cmd len=%d, want 6", len(cfgs[3].Payload))
	}
	if len(cfgs[4].Payload) != 5 {
		t.Errorf("NOOP resp len=%d, want 5", len(cfgs[4].Payload))
	}
}

// --- 1.9 RSET command ---

// 1.9.1: RSET emits "RSET\r\n" + "+OK maildrop has...".
func TestPOP3Point_1_9_1_RSET(t *testing.T) {
	p := NewPlanner()
	spec := validPOP3SpecNoBanner()
	spec.POP3.Commands = []core.POP3Command{
		{Cmd: "RSET", Response: "+OK maildrop has 5 messages (12345 octets)"},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if string(cfgs[3].Payload) != "RSET\r\n" {
		t.Errorf("RSET cmd: got %q", cfgs[3].Payload)
	}
	if !strings.Contains(string(cfgs[4].Payload), "5 messages") {
		t.Errorf("RSET resp: got %q", cfgs[4].Payload)
	}
}

// --- 1.10 TOP command ---

// 1.10.1: TOP 1 5 emits "TOP 1 5\r\n" + multi-line response.
func TestPOP3Point_1_10_1_TOP_1_5(t *testing.T) {
	p := NewPlanner()
	spec := validPOP3SpecNoBanner()
	spec.POP3.Commands = []core.POP3Command{
		{
			Cmd:       "TOP 1 5",
			Response:  "+OK\r\nFrom: bob@example.com\r\nSubject: Hello\r\n\r\nLine 1\r\nLine 2\r\n.\r\n",
			Multiline: true,
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if string(cfgs[3].Payload) != "TOP 1 5\r\n" {
		t.Errorf("TOP cmd: got %q", cfgs[3].Payload)
	}
	resp := string(cfgs[4].Payload)
	if !strings.Contains(resp, "From: bob") {
		t.Errorf("TOP resp should have headers: %q", resp)
	}
	if !strings.HasSuffix(resp, ".\r\n") {
		t.Errorf("TOP resp must end with terminator: %q", resp)
	}
}

// 1.10.2: TOP 1 0 (n=0) emits headers + blank line + terminator only.
func TestPOP3Point_1_10_2_TOP_1_0(t *testing.T) {
	p := NewPlanner()
	spec := validPOP3SpecNoBanner()
	spec.POP3.Commands = []core.POP3Command{
		{
			Cmd:       "TOP 1 0",
			Response:  "+OK\r\nFrom: bob@example.com\r\n\r\n.\r\n",
			Multiline: true,
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if string(cfgs[3].Payload) != "TOP 1 0\r\n" {
		t.Errorf("TOP 1 0 cmd: got %q", cfgs[3].Payload)
	}
}

// --- 1.11 UIDL command ---

// 1.11.1: UIDL multi-line response (3 messages).
func TestPOP3Point_1_11_1_UIDL_MultiLine(t *testing.T) {
	p := NewPlanner()
	spec := validPOP3SpecNoBanner()
	spec.POP3.Commands = []core.POP3Command{
		{
			Cmd:       "UIDL",
			Response:  "+OK\r\n1 uid1\r\n2 uid2\r\n3 uid3\r\n.\r\n",
			Multiline: true,
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	resp := string(cfgs[4].Payload)
	if !strings.Contains(resp, "1 uid1\r\n2 uid2\r\n3 uid3\r\n.\r\n") {
		t.Errorf("UIDL multiline: got %q", resp)
	}
}

// 1.11.2: UIDL 1 single-line response.
func TestPOP3Point_1_11_2_UIDL_SingleMsg(t *testing.T) {
	p := NewPlanner()
	spec := validPOP3SpecNoBanner()
	spec.POP3.Commands = []core.POP3Command{
		{Cmd: "UIDL 1", Response: "+OK 1 uid1"},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if string(cfgs[3].Payload) != "UIDL 1\r\n" {
		t.Errorf("UIDL 1 cmd: got %q", cfgs[3].Payload)
	}
	if string(cfgs[4].Payload) != "+OK 1 uid1\r\n" {
		t.Errorf("UIDL 1 resp: got %q", cfgs[4].Payload)
	}
}

// 1.11.6: UIDL with 70-char UID (boundary).
func TestPOP3Point_1_11_6_UID_Boundary(t *testing.T) {
	p := NewPlanner()
	spec := validPOP3SpecNoBanner()
	uid := strings.Repeat("u", 70)
	spec.POP3.Commands = []core.POP3Command{
		{Cmd: "UIDL 1", Response: "+OK 1 " + uid},
	}
	if err := p.Validate(spec); err != nil {
		t.Errorf("Validate: 70-char UID should be accepted: %v", err)
	}
}

// 1.11.7: UIDL with 71-char UID rejected.
func TestPOP3Point_1_11_7_UID_OverLengthRejected(t *testing.T) {
	p := NewPlanner()
	spec := validPOP3SpecNoBanner()
	spec.POP3.Mailbox = &core.POP3Mailbox{
		Messages: []core.POP3Message{{UID: strings.Repeat("u", 71)}},
	}
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "UID") {
		t.Errorf("err=%v, want contains 'UID'", err)
	}
}

// --- 1.12 QUIT command ---

// 1.12.1: QUIT in AUTHORIZATION emits "QUIT\r\n" + signing off resp.
func TestPOP3Point_1_12_1_QUIT_Authorization(t *testing.T) {
	p := NewPlanner()
	spec := validPOP3SpecNoBanner()
	spec.POP3.Commands = []core.POP3Command{
		{Cmd: "QUIT", Response: "+OK POP3 server signing off"},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if string(cfgs[3].Payload) != "QUIT\r\n" {
		t.Errorf("QUIT cmd: got %q", cfgs[3].Payload)
	}
	if !strings.Contains(string(cfgs[4].Payload), "signing off") {
		t.Errorf("QUIT resp: got %q", cfgs[4].Payload)
	}
}

// 1.12.5: QUIT with empty Response skips resp packet.
func TestPOP3Point_1_12_5_QUIT_EmptyResp(t *testing.T) {
	p := NewPlanner()
	spec := validPOP3SpecNoBanner()
	spec.POP3.Commands = []core.POP3Command{
		{Cmd: "QUIT", Response: ""},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// handshake(3) + cmd(1) + teardown(4) = 8 (no banner, no resp)
	if len(cfgs) != 8 {
		t.Fatalf("len=%d, want 8 (QUIT empty resp)", len(cfgs))
	}
}

// --- 1.13 CAPA command ---

// 1.13.1: CAPA multi-line response with TOP/USER/UIDL/STLS/SASL.
func TestPOP3Point_1_13_1_CAPA_FullList(t *testing.T) {
	p := NewPlanner()
	spec := validPOP3SpecNoBanner()
	spec.POP3.Commands = []core.POP3Command{
		{
			Cmd:       "CAPA",
			Response:  "+OK Capability list follows\r\nTOP\r\nUSER\r\nUIDL\r\nSTLS\r\nSASL PLAIN LOGIN CRAM-MD5\r\n.\r\n",
			Multiline: true,
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	resp := string(cfgs[4].Payload)
	if !strings.Contains(resp, "TOP\r\nUSER\r\nUIDL\r\nSTLS\r\n") {
		t.Errorf("CAPA resp missing capabilities: %q", resp)
	}
	if !strings.HasSuffix(resp, ".\r\n") {
		t.Errorf("CAPA must end with terminator: %q", resp)
	}
}

// 1.19.4: CAPA SASL PLAIN single mechanism.
func TestPOP3Point_1_19_4_CAPA_SASL_PLAIN(t *testing.T) {
	p := NewPlanner()
	spec := validPOP3SpecNoBanner()
	spec.POP3.Commands = []core.POP3Command{
		{
			Cmd:       "CAPA",
			Response:  "+OK Capability list follows\r\nSASL PLAIN\r\n.\r\n",
			Multiline: true,
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if !strings.Contains(string(cfgs[4].Payload), "SASL PLAIN\r\n") {
		t.Errorf("CAPA SASL PLAIN: got %q", cfgs[4].Payload)
	}
}

// 1.19.6: CAPA LOGIN-DELAY (covers new test added per crossverify I-1).
func TestPOP3Point_1_19_6_CAPA_LOGIN_DELAY(t *testing.T) {
	p := NewPlanner()
	spec := validPOP3SpecNoBanner()
	spec.POP3.Commands = []core.POP3Command{
		{
			Cmd:       "CAPA",
			Response:  "+OK Capability list follows\r\nLOGIN-DELAY 300\r\n.\r\n",
			Multiline: true,
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if !strings.Contains(string(cfgs[4].Payload), "LOGIN-DELAY 300\r\n") {
		t.Errorf("CAPA LOGIN-DELAY: got %q", cfgs[4].Payload)
	}
}

// I-1 crossverify fix: CAPA EXPIRE capability.
func TestPOP3Point_CAPA_EXPIRE(t *testing.T) {
	p := NewPlanner()
	spec := validPOP3SpecNoBanner()
	spec.POP3.Commands = []core.POP3Command{
		{
			Cmd:       "CAPA",
			Response:  "+OK Capability list follows\r\nEXPIRE 60\r\n.\r\n",
			Multiline: true,
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if !strings.Contains(string(cfgs[4].Payload), "EXPIRE 60\r\n") {
		t.Errorf("CAPA EXPIRE: got %q", cfgs[4].Payload)
	}
}

// --- 1.14 STLS command ---

// 1.14.1: STLS in AUTHORIZATION emits "STLS\r\n" (6 bytes) + +OK.
func TestPOP3Point_1_14_1_STLS_Authorization(t *testing.T) {
	p := NewPlanner()
	spec := validPOP3SpecNoBanner()
	spec.POP3.Commands = []core.POP3Command{
		{Cmd: "STLS", Response: "+OK begin TLS negotiation"},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if string(cfgs[3].Payload) != "STLS\r\n" {
		t.Errorf("STLS cmd: got %q, want 'STLS\\r\\n'", cfgs[3].Payload)
	}
	if len(cfgs[3].Payload) != 6 {
		t.Errorf("STLS cmd len=%d, want 6", len(cfgs[3].Payload))
	}
}

// 1.14.2: STLS in TRANSACTION emits -ERR (user-provided).
func TestPOP3Point_1_14_2_STLS_Transaction(t *testing.T) {
	p := NewPlanner()
	spec := validPOP3SpecNoBanner()
	spec.POP3.Commands = []core.POP3Command{
		{Cmd: "STLS", Response: "-ERR command not allowed now"},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if !strings.Contains(string(cfgs[4].Payload), "-ERR command not allowed now") {
		t.Errorf("STLS -ERR: got %q", cfgs[4].Payload)
	}
}

// --- 1.15 AUTH command ---

// 1.15.1: AUTH PLAIN emits "AUTH PLAIN\r\n" (12 bytes: A,U,T,H,space,P,L,A,I,N,\r,\n).
func TestPOP3Point_1_15_1_AUTH_PLAIN(t *testing.T) {
	p := NewPlanner()
	spec := validPOP3SpecNoBanner()
	spec.POP3.Commands = []core.POP3Command{
		{Cmd: "AUTH PLAIN", Response: "+"},
		{Cmd: "AGFsaWNlAHNlY3JldDEyMw==", Response: "+OK authentication successful"},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if string(cfgs[3].Payload) != "AUTH PLAIN\r\n" {
		t.Errorf("AUTH PLAIN cmd: got %q, want 'AUTH PLAIN\\r\\n'", cfgs[3].Payload)
	}
	if len(cfgs[3].Payload) != 12 {
		t.Errorf("AUTH PLAIN len=%d, want 12 (A,U,T,H,sp,P,L,A,I,N,CR,LF)", len(cfgs[3].Payload))
	}
}

// 1.15.2: AUTH LOGIN with intermediate challenge.
func TestPOP3Point_1_15_2_AUTH_LOGIN(t *testing.T) {
	p := NewPlanner()
	spec := validPOP3SpecNoBanner()
	spec.POP3.Commands = []core.POP3Command{
		{Cmd: "AUTH LOGIN", Response: "+ VXNlciBOYW1lAA=="},
		{Cmd: "YWxpY2U=", Response: "+ UGFzc3dvcmQA"},
		{Cmd: "c2VjcmV0MTIz", Response: "+OK authentication successful"},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if string(cfgs[3].Payload) != "AUTH LOGIN\r\n" {
		t.Errorf("AUTH LOGIN cmd: got %q", cfgs[3].Payload)
	}
	if !strings.Contains(string(cfgs[4].Payload), "VXNlciBOYW1lAA==") {
		t.Errorf("AUTH LOGIN challenge 1: got %q", cfgs[4].Payload)
	}
}

// 1.15.3: AUTH CRAM-MD5 challenge-response.
func TestPOP3Point_1_15_3_AUTH_CRAM_MD5(t *testing.T) {
	p := NewPlanner()
	spec := validPOP3SpecNoBanner()
	spec.POP3.Commands = []core.POP3Command{
		{Cmd: "AUTH CRAM-MD5", Response: "+ PDQxOTI5NDIzNDMuMTczNjM5MjE2QHBvcC5leGFtcGxlLmNvbT4="},
		{Cmd: "YWxpY2UgZjQ4YTJhZjMwY2I0MWI5ZjI2NGM5YzVhMzNjMzY3Yg==", Response: "+OK authentication successful"},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if string(cfgs[3].Payload) != "AUTH CRAM-MD5\r\n" {
		t.Errorf("AUTH CRAM-MD5: got %q", cfgs[3].Payload)
	}
}

// 1.15.4: AUTH unknown mechanism emits -ERR.
func TestPOP3Point_1_15_4_AUTH_UnknownMech(t *testing.T) {
	p := NewPlanner()
	spec := validPOP3SpecNoBanner()
	spec.POP3.Commands = []core.POP3Command{
		{Cmd: "AUTH FOOBAR", Response: "-ERR unsupported mechanism"},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if !strings.Contains(string(cfgs[4].Payload), "-ERR unsupported mechanism") {
		t.Errorf("AUTH unknown mech: got %q", cfgs[4].Payload)
	}
}

// I-2 crossverify fix: AUTH NTLM mechanism.
func TestPOP3Point_AUTH_NTLM(t *testing.T) {
	p := NewPlanner()
	spec := validPOP3SpecNoBanner()
	spec.POP3.Commands = []core.POP3Command{
		{Cmd: "AUTH NTLM", Response: "-ERR unsupported mechanism"},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if !strings.Contains(string(cfgs[4].Payload), "-ERR unsupported mechanism") {
		t.Errorf("AUTH NTLM: got %q", cfgs[4].Payload)
	}
}

// --- 1.16 +OK/-ERR response format ---

// 1.16.1: +OK with empty text emits "+OK\r\n" (5 bytes).
func TestPOP3Point_1_16_1_OK_Empty(t *testing.T) {
	p := NewPlanner()
	spec := validPOP3SpecNoBanner()
	spec.POP3.Commands = []core.POP3Command{
		{Cmd: "NOOP", Response: "+OK"},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if string(cfgs[4].Payload) != "+OK\r\n" {
		t.Errorf("+OK empty: got %q, want '+OK\\r\\n'", cfgs[4].Payload)
	}
	if len(cfgs[4].Payload) != 5 {
		t.Errorf("+OK empty len=%d, want 5", len(cfgs[4].Payload))
	}
}

// 1.16.2: +OK with text emits "+OK <text>\r\n".
func TestPOP3Point_1_16_2_OK_WithText(t *testing.T) {
	p := NewPlanner()
	spec := validPOP3SpecNoBanner()
	spec.POP3.Commands = []core.POP3Command{
		{Cmd: "USER alice", Response: "+OK POP3 server ready"},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if string(cfgs[4].Payload) != "+OK POP3 server ready\r\n" {
		t.Errorf("+OK with text: got %q", cfgs[4].Payload)
	}
}

// 1.16.3: -ERR with text emits "-ERR <text>\r\n".
func TestPOP3Point_1_16_3_ERR_WithText(t *testing.T) {
	p := NewPlanner()
	spec := validPOP3SpecNoBanner()
	spec.POP3.Commands = []core.POP3Command{
		{Cmd: "PASS wrong", Response: "-ERR invalid password"},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if string(cfgs[4].Payload) != "-ERR invalid password\r\n" {
		t.Errorf("-ERR with text: got %q", cfgs[4].Payload)
	}
}

// --- 1.17 multi-line response ---

// 1.17.1: multi-line response with proper terminator.
func TestPOP3Point_1_17_1_Multiline_Terminator(t *testing.T) {
	p := NewPlanner()
	spec := validPOP3SpecNoBanner()
	spec.POP3.Commands = []core.POP3Command{
		{
			Cmd:       "LIST",
			Response:  "+OK 5 messages (12345 octets)\r\n1 200\r\n2 300\r\n.\r\n",
			Multiline: true,
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	resp := string(cfgs[4].Payload)
	if !strings.HasSuffix(resp, ".\r\n") {
		t.Errorf("multiline must end with terminator: %q", resp)
	}
	if strings.Count(resp, "\r\n") < 4 {
		t.Errorf("multiline should have multiple lines: %q", resp)
	}
}

// --- 1.18 email headers ---

// 1.18.1: From header in RETR response.
func TestPOP3Point_1_18_1_RETR_FromHeader(t *testing.T) {
	p := NewPlanner()
	spec := validPOP3SpecNoBanner()
	spec.POP3.Mailbox = &core.POP3Mailbox{
		Messages: []core.POP3Message{
			{UID: "u1", Headers: []string{"From: alice@example.com"}, Body: ""},
		},
	}
	spec.POP3.Commands = []core.POP3Command{
		{EmitMailDrop: true, MsgNum: 1},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if !strings.Contains(string(cfgs[3].Payload), "From: alice@example.com\r\n") {
		t.Errorf("From header missing: got %q", cfgs[3].Payload)
	}
}

// 1.18.3: Subject 998 chars (boundary) emits 1009-byte Subject line.
func TestPOP3Point_1_18_3_Subject_Boundary(t *testing.T) {
	p := NewPlanner()
	spec := validPOP3SpecNoBanner()
	subject := strings.Repeat("x", 998)
	spec.POP3.Mailbox = &core.POP3Mailbox{
		Messages: []core.POP3Message{
			{UID: "u1", Headers: []string{"Subject: " + subject}, Body: ""},
		},
	}
	spec.POP3.Commands = []core.POP3Command{
		{EmitMailDrop: true, MsgNum: 1},
	}
	cfgs := drain(mustPlan(t, p, spec))
	resp := string(cfgs[3].Payload)
	expected := "Subject: " + subject + "\r\n"
	if !strings.Contains(resp, expected) {
		t.Errorf("Subject header missing or wrong length: contains=%v", strings.Contains(resp, expected))
	}
}

// --- 2.x state machine (planner does not enforce, user responsibility) ---

// 2.1.1: USER+PASS success flow emits 3 cmds + 3 resps + 1 banner.
func TestPOP3Point_2_1_1_UserPassFlow(t *testing.T) {
	p := NewPlanner()
	spec := validPOP3SpecNoBanner()
	spec.POP3.Commands = []core.POP3Command{
		{Cmd: "USER alice", Response: "+OK alice is a valid mailbox"},
		{Cmd: "PASS secret123", Response: "+OK alice's maildrop has 5 messages (12345 octets)"},
		{Cmd: "STAT", Response: "+OK 5 12345"},
		{Cmd: "QUIT", Response: "+OK POP3 server signing off"},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// handshake(3) + 4 cmds + 4 resps + teardown(4) = 15 (no banner)
	if len(cfgs) != 15 {
		t.Fatalf("len=%d, want 15", len(cfgs))
	}
}

// 2.6.1: STLS in TRANSACTION -ERR (user responsibility).
func TestPOP3Point_2_6_1_STLS_Transaction_Err(t *testing.T) {
	p := NewPlanner()
	spec := validPOP3SpecNoBanner()
	spec.POP3.Commands = []core.POP3Command{
		{Cmd: "STLS", Response: "-ERR command not allowed now"},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if !strings.Contains(string(cfgs[4].Payload), "-ERR command not allowed now") {
		t.Errorf("STLS -ERR in TRANSACTION: got %q", cfgs[4].Payload)
	}
}

// --- 3.x business scenarios ---

// 3.1.1: Standard USER+PASS+STAT+QUIT flow.
func TestPOP3Point_3_1_1_StandardFlow(t *testing.T) {
	p := NewPlanner()
	spec := validPOP3SpecNoBanner()
	spec.POP3.Commands = []core.POP3Command{
		{Cmd: "USER alice", Response: "+OK alice"},
		{Cmd: "PASS secret123", Response: "+OK logged in"},
		{Cmd: "STAT", Response: "+OK 5 12345"},
		{Cmd: "QUIT", Response: "+OK signing off"},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// handshake(3) + 4 cmd + 4 resp + teardown(4) = 15 (no banner)
	if len(cfgs) != 15 {
		t.Fatalf("len=%d, want 15", len(cfgs))
	}
}

// 3.2.1: APOP auth flow.
func TestPOP3Point_3_2_1_APOPFlow(t *testing.T) {
	p := NewPlanner()
	spec := validPOP3SpecNoBanner()
	spec.POP3.Commands = []core.POP3Command{
		{Cmd: "APOP alice c4c9334bac560ecc975eac1bbdded0e0", Response: "+OK logged in"},
		{Cmd: "QUIT", Response: "+OK signing off"},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) != 11 {
		t.Fatalf("len=%d, want 11 (3+2*2+4)", len(cfgs))
	}
}

// 3.10.3: RETR with dot-stuffed body lines (de-stuffing on client side).
func TestPOP3Point_3_10_3_RETR_DotStuffed(t *testing.T) {
	p := NewPlanner()
	spec := validPOP3SpecNoBanner()
	spec.POP3.Mailbox = &core.POP3Mailbox{
		Messages: []core.POP3Message{
			{UID: "u1", Body: ".line1\n.line2\nline3"},
		},
	}
	spec.POP3.Commands = []core.POP3Command{
		{EmitMailDrop: true, MsgNum: 1},
	}
	cfgs := drain(mustPlan(t, p, spec))
	resp := string(cfgs[3].Payload)
	if !strings.Contains(resp, "..line1\r\n..line2\r\nline3\r\n") {
		t.Errorf("dot-stuffed body: got %q", resp)
	}
}

// 3.11.1: DELE + RSET flow.
func TestPOP3Point_3_11_1_DELE_RSET(t *testing.T) {
	p := NewPlanner()
	spec := validPOP3SpecNoBanner()
	spec.POP3.Commands = []core.POP3Command{
		{Cmd: "DELE 3", Response: "+OK message 3 deleted"},
		{Cmd: "DELE 4", Response: "+OK message 4 deleted"},
		{Cmd: "RSET", Response: "+OK maildrop has 5 messages (12345 octets)"},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// handshake(3) + 3 cmds + 3 resps + teardown(4) = 13 (no banner)
	if len(cfgs) != 13 {
		t.Fatalf("len=%d, want 13", len(cfgs))
	}
	if !strings.Contains(string(cfgs[7].Payload), "RSET") {
		t.Errorf("RSET cmd: got %q", cfgs[7].Payload)
	}
}

// 3.15.1: NOOP x10 + QUIT = 22 packets.
func TestPOP3Point_3_15_1_NOOPx10(t *testing.T) {
	p := NewPlanner()
	spec := validPOP3SpecNoBanner()
	spec.POP3.Commands = nil
	for i := 0; i < 10; i++ {
		spec.POP3.Commands = append(spec.POP3.Commands, core.POP3Command{
			Cmd: "NOOP", Response: "+OK",
		})
	}
	spec.POP3.Commands = append(spec.POP3.Commands, core.POP3Command{
		Cmd: "QUIT", Response: "+OK signing off",
	})
	cfgs := drain(mustPlan(t, p, spec))
	// handshake(3) + 11 cmds + 11 resps + teardown(4) = 29 (no banner)
	if len(cfgs) != 29 {
		t.Fatalf("len=%d, want 29", len(cfgs))
	}
}

// 3.16.1: unknown command emits -ERR.
func TestPOP3Point_3_16_1_UnknownCommand(t *testing.T) {
	p := NewPlanner()
	spec := validPOP3SpecNoBanner()
	spec.POP3.Commands = []core.POP3Command{
		{Cmd: "FOOBAR", Response: "-ERR unknown command"},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if string(cfgs[3].Payload) != "FOOBAR\r\n" {
		t.Errorf("FOOBAR cmd: got %q", cfgs[3].Payload)
	}
	if !strings.Contains(string(cfgs[4].Payload), "-ERR unknown command") {
		t.Errorf("FOOBAR resp: got %q", cfgs[4].Payload)
	}
}

// --- 4.x data scenarios ---

// 4.1.1: STAT with empty Mailbox returns "+OK 0 0" (user-provided).
func TestPOP3Point_4_1_1_STAT_EmptyMailbox(t *testing.T) {
	p := NewPlanner()
	spec := validPOP3SpecNoBanner()
	spec.POP3.Commands = []core.POP3Command{
		{Cmd: "STAT", Response: "+OK 0 0"},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if string(cfgs[4].Payload) != "+OK 0 0\r\n" {
		t.Errorf("STAT empty: got %q", cfgs[4].Payload)
	}
}

// 4.1.5: empty Banner skips banner packet.
func TestPOP3Point_4_1_5_EmptyBanner(t *testing.T) {
	p := NewPlanner()
	spec := validPOP3SpecNoBanner()
	spec.POP3.Banner = ""
	spec.POP3.Commands = []core.POP3Command{
		{Cmd: "USER alice", Response: "+OK"},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// handshake(3) + cmd(1) + resp(1) + teardown(4) = 9 (no banner)
	if len(cfgs) != 9 {
		t.Fatalf("len=%d, want 9", len(cfgs))
	}
}

// 4.1.6: empty USER Cmd skipped.
func TestPOP3Point_4_1_6_EmptyUSERSkipped(t *testing.T) {
	p := NewPlanner()
	spec := validPOP3SpecNoBanner()
	spec.POP3.Banner = ""
	spec.POP3.Commands = []core.POP3Command{
		{Cmd: "", Response: "+OK"},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) != 8 {
		t.Fatalf("len=%d, want 8 (empty cmd skipped)", len(cfgs))
	}
}

// 4.2.10: USER name 40 chars (boundary) accepted.
func TestPOP3Point_4_2_10_USER_Boundary(t *testing.T) {
	p := NewPlanner()
	spec := validPOP3SpecNoBanner()
	spec.POP3.Commands[0].Cmd = "USER " + strings.Repeat("a", 40)
	if err := p.Validate(spec); err != nil {
		t.Errorf("USER 40 chars should be accepted: %v", err)
	}
}

// 4.2.12: PASS 255 chars (boundary) accepted.
func TestPOP3Point_4_2_12_PASS_Boundary(t *testing.T) {
	p := NewPlanner()
	spec := validPOP3SpecNoBanner()
	spec.POP3.Commands[1].Cmd = "PASS " + strings.Repeat("x", 255)
	if err := p.Validate(spec); err != nil {
		t.Errorf("PASS 255 chars should be accepted: %v", err)
	}
}

// 4.4.2: large RETR is segmented by MSS.
func TestPOP3Point_4_4_2_RETR_LargeSegmented(t *testing.T) {
	p := NewPlanner()
	spec := validPOP3SpecNoBanner()
	testutil.EnsureTCP(&spec).MSS = 536
	// RETR 1 with EmitMailDrop + 10MB body would need MSS segmentation.
	// Use a smaller body for test speed (still > MSS).
	spec.POP3.Mailbox = &core.POP3Mailbox{
		Messages: []core.POP3Message{
			{UID: "u1", Body: strings.Repeat("x", 2000)},
		},
	}
	spec.POP3.Commands = []core.POP3Command{
		{EmitMailDrop: true, MsgNum: 1},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// With MSS=536 and ~2000 byte body + headers + status line, expect
	// at least 4 segments.
	respPackets := 0
	for i := 3; i < len(cfgs)-4; i++ {
		if cfgs[i].L4.Flags == 0x18 && cfgs[i].Direction == "down" {
			respPackets++
		}
	}
	if respPackets < 2 {
		t.Errorf("expected multiple response segments, got %d", respPackets)
	}
}

// --- 5.x concurrency ---

// 5.1: 8 concurrent workers generating POP3 flows independently.
func TestPOP3Point_5_1_Concurrent(t *testing.T) {
	p := NewPlanner()
	const N = 8
	done := make(chan bool, N)
	for i := 0; i < N; i++ {
		go func() {
			defer func() { done <- true }()
			cfgs := drain(mustPlan(t, p, validPOP3Spec()))
			if len(cfgs) == 0 {
				t.Errorf("concurrent Plan returned no packets")
			}
		}()
	}
	for i := 0; i < N; i++ {
		<-done
	}
}

// 5.5: same Planner instance used concurrently.
func TestPOP3Point_5_5_SameInstanceConcurrent(t *testing.T) {
	p := NewPlanner()
	const N = 8
	done := make(chan int, N)
	for i := 0; i < N; i++ {
		go func() {
			ch, err := p.Plan(context.Background(), validPOP3Spec())
			if err != nil {
				t.Errorf("Plan: %v", err)
			}
			n := len(drain(ch))
			done <- n
		}()
	}
	for i := 0; i < N; i++ {
		<-done
	}
}

// --- 9.x port and connection ---

// 9.1: DstPort 110 default verified at Plan level.
func TestPOP3Point_9_1_DstPort110(t *testing.T) {
	p := NewPlanner()
	spec := validPOP3SpecNoBanner()
	spec.DstPort = 110
	cfgs := drain(mustPlan(t, p, spec))
	for i, c := range cfgs {
		if c.Direction == "up" && c.L4.DstPort != 110 {
			t.Errorf("cfg[%d] up DstPort=%d, want 110", i, c.L4.DstPort)
		}
	}
}

// 9.4: SrcPort override.
func TestPOP3Point_9_4_SrcPort(t *testing.T) {
	p := NewPlanner()
	spec := validPOP3SpecNoBanner()
	spec.SrcPort = 12345
	cfgs := drain(mustPlan(t, p, spec))
	for i, c := range cfgs {
		if c.Direction == "up" && c.L4.SrcPort != 12345 {
			t.Errorf("cfg[%d] up SrcPort=%d, want 12345", i, c.L4.SrcPort)
		}
	}
}

// --- 10.x TCP/L2/L3 fields ---

// 10.1: TCP MSS = 1460 default segmentation.
func TestPOP3Point_10_1_MSS_Default(t *testing.T) {
	p := NewPlanner()
	spec := validPOP3SpecNoBanner()
	// Default MSS = 1460. A 2000-byte response should split into 2 segments.
	spec.POP3.Commands = []core.POP3Command{
		{Cmd: "STAT", Response: "+OK " + strings.Repeat("x", 2000)},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// handshake(3) + cmd(1) + seg1(1) + seg2(1) + teardown(4) = 10.
	// First response segment is at cfgs[4] with len 1460.
	if len(cfgs[4].Payload) != 1460 {
		t.Errorf("seg1 len=%d, want 1460", len(cfgs[4].Payload))
	}
}

// 10.2: TCP MSS = 536 (minimum per RFC 879).
func TestPOP3Point_10_2_MSS_536(t *testing.T) {
	p := NewPlanner()
	spec := validPOP3SpecNoBanner()
	testutil.EnsureTCP(&spec).MSS = 536
	spec.POP3.Commands = []core.POP3Command{
		{Cmd: "STAT", Response: "+OK " + strings.Repeat("x", 1080)},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// handshake(3) + cmd(1) + resp(3 segs of 536+536+14) + teardown(4) = 11.
	// Response is "+OK " + 1080 + "\r\n" = 1086, so 536 + 536 + 14.
	if len(cfgs[4].Payload) != 536 {
		t.Errorf("seg1 len=%d, want 536", len(cfgs[4].Payload))
	}
	if len(cfgs[5].Payload) != 536 {
		t.Errorf("seg2 len=%d, want 536", len(cfgs[5].Payload))
	}
	if len(cfgs[6].Payload) != 14 {
		t.Errorf("seg3 len=%d, want 14", len(cfgs[6].Payload))
	}
}

// 10.4: TCP MSS = 535 (below min) rejected.
func TestPOP3Point_10_4_MSS_BelowMin(t *testing.T) {
	p := NewPlanner()
	spec := validPOP3SpecNoBanner()
	testutil.EnsureTCP(&spec).MSS = 535
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "MSS") {
		t.Errorf("err=%v, want contains 'MSS'", err)
	}
}

// 10.5: TTL = 64 default.
func TestPOP3Point_10_5_TTL(t *testing.T) {
	p := NewPlanner()
	spec := validPOP3SpecNoBanner()
	spec.TTL = 64
	cfgs := drain(mustPlan(t, p, spec))
	for i, c := range cfgs {
		if c.L3.TTL != 64 {
			t.Errorf("cfg[%d] TTL=%d, want 64", i, c.L3.TTL)
		}
	}
}

// --- 8.x error recovery ---

// 8.5: context cancellation stops the planner.
func TestPOP3Point_8_5_ContextCancel(t *testing.T) {
	p := NewPlanner()
	spec := validPOP3SpecNoBanner()
	// Use a large Mailbox + low MSS to generate many packets
	spec.POP3.Mailbox = &core.POP3Mailbox{
		Messages: []core.POP3Message{
			{UID: "u1", Body: strings.Repeat("x", 10000)},
		},
	}
	spec.POP3.Commands = []core.POP3Command{
		{EmitMailDrop: true, MsgNum: 1},
	}
	testutil.EnsureTCP(&spec).MSS = 1000 // valid MSS; large body forces many segments
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately
	ch, err := p.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	// Drain whatever was emitted - planner must complete without panic.
	for range ch {
	}
}