package smtp

// Spec-driven atomic test points from /tmp/l7_planner_design/testcases_smtp.md.
// Each test asserts observable PacketConfig field values for one atomic
// test case ID. Failure paths are covered (testcases §1.1.5, §2.1.3,
// §2.1.4, §4.3.x).

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/protocol/testutil"
)

// --- Testcase §1.1 HELO commands (RFC 5321 §4.1.1) ---

// TestSMTP_1_1_1_HELO_CMD_Basic covers testcase 1.1.1: HELO.Cmd in
// GREETING state -> emit "HELO client.example.org\r\n" (22 bytes).
func TestSMTP_1_1_1_HELO_CMD_Basic(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 50000, DstPort: 25,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		SMTP: &core.SMTPConfig{
			Banner: "220 x",
			Dialog: []core.SMTPCommand{{Cmd: "HELO client.example.org", Response: "250 ok"}},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// Find the first up PSH-ACK after the handshake+banner.
	var helo []byte
	for _, c := range cfgs {
		if c.Direction == "up" && c.L4.Flags == 0x18 && strings.Contains(string(c.Payload), "HELO") {
			helo = c.Payload
			break
		}
	}
	if string(helo) != "HELO client.example.org\r\n" {
		t.Errorf("HELO payload=%q, want exactly 'HELO client.example.org\\r\\n' (22 bytes)", helo)
	}
}

// TestSMTP_1_1_2_HELO_SingleCharDomain covers testcase 1.1.2: HELO
// with a single-char-domain boundary (a.b).
func TestSMTP_1_1_2_HELO_SingleCharDomain(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 50000, DstPort: 25,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		SMTP: &core.SMTPConfig{
			Banner: "220 x",
			Dialog: []core.SMTPCommand{{Cmd: "HELO a.b", Response: "250 ok"}},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	var helo []byte
	for _, c := range cfgs {
		if c.Direction == "up" && c.L4.Flags == 0x18 && strings.Contains(string(c.Payload), "HELO") {
			helo = c.Payload
			break
		}
	}
	if string(helo) != "HELO a.b\r\n" {
		t.Errorf("HELO payload=%q, want 'HELO a.b\\r\\n' (10 bytes)", helo)
	}
	if len(helo) != 10 {
		t.Errorf("HELO len=%d, want 10", len(helo))
	}
}

// TestSMTP_1_1_4_HELO_MixedCase covers testcase 1.1.4: commands are
// not case-sensitive; planner emits the bytes verbatim (no
// normalization).
func TestSMTP_1_1_4_HELO_MixedCase(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 50000, DstPort: 25,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		SMTP: &core.SMTPConfig{
			Banner: "220 x",
			Dialog: []core.SMTPCommand{{Cmd: "helO MiXeD.example.org", Response: "250 ok"}},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	var helo []byte
	for _, c := range cfgs {
		if c.Direction == "up" && c.L4.Flags == 0x18 && strings.Contains(string(c.Payload), "helO") {
			helo = c.Payload
			break
		}
	}
	if string(helo) != "helO MiXeD.example.org\r\n" {
		t.Errorf("mixed-case HELO should be emitted verbatim, got %q", helo)
	}
}

// --- Testcase §1.2 EHLO commands (RFC 5321 §4.1.1.1) ---

// TestSMTP_1_2_1_EHLO_CRLFTerminator covers testcase 1.2.1: EHLO
// command ends with \r\n.
func TestSMTP_1_2_1_EHLO_CRLFTerminator(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 50000, DstPort: 25,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		SMTP: &core.SMTPConfig{
			Banner: "220 x",
			Dialog: []core.SMTPCommand{{Cmd: "EHLO client.example.org", Response: "250-mail.example.org\r\n250 HELP"}},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	var ehlo []byte
	for _, c := range cfgs {
		if c.Direction == "up" && c.L4.Flags == 0x18 && strings.Contains(string(c.Payload), "EHLO") {
			ehlo = c.Payload
			break
		}
	}
	if !strings.HasSuffix(string(ehlo), "\r\n") {
		t.Errorf("EHLO must end with CRLF, got %q", ehlo)
	}
}

// TestSMTP_1_2_2_EHLO_MultilineResponse covers testcase 1.2.2: EHLO
// response can be multi-line ("250-" continuation).
func TestSMTP_1_2_2_EHLO_MultilineResponse(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 50000, DstPort: 25,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		SMTP: &core.SMTPConfig{
			Banner: "220 x",
			Dialog: []core.SMTPCommand{
				{Cmd: "EHLO client.example.org", Response: "250-mail.example.org\r\n250-SIZE 10240000\r\n250 HELP"},
			},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	var resp []byte
	for _, c := range cfgs {
		if c.Direction == "down" && c.L4.Flags == 0x18 && strings.Contains(string(c.Payload), "250-") {
			resp = c.Payload
			break
		}
	}
	// Multi-line emitted as single payload with embedded "\r\n".
	if !strings.Contains(string(resp), "250-mail.example.org") || !strings.Contains(string(resp), "250 HELP") {
		t.Errorf("multi-line EHLO response not preserved: %q", resp)
	}
}

// --- Testcase §1.3 MAIL FROM ---

// TestSMTP_1_3_1_MAIL_Basic covers testcase 1.3.1: MAIL FROM with
// full email address.
func TestSMTP_1_3_1_MAIL_Basic(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 50000, DstPort: 25,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		SMTP: &core.SMTPConfig{
			Banner: "220 x",
			Dialog: []core.SMTPCommand{{Cmd: "MAIL FROM:<alice@example.org>", Response: "250 ok"}},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	var mail []byte
	for _, c := range cfgs {
		if c.Direction == "up" && c.L4.Flags == 0x18 && strings.Contains(string(c.Payload), "MAIL FROM") {
			mail = c.Payload
			break
		}
	}
	if string(mail) != "MAIL FROM:<alice@example.org>\r\n" {
		t.Errorf("MAIL payload=%q, want exact match", mail)
	}
}

// TestSMTP_1_3_3_MAIL_BODY_8BITMIME covers testcase 1.3.3: MAIL with
// BODY=8BITMIME parameter.
func TestSMTP_1_3_3_MAIL_BODY_8BITMIME(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 50000, DstPort: 25,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		SMTP: &core.SMTPConfig{
			Banner: "220 x",
			Dialog: []core.SMTPCommand{{Cmd: "MAIL FROM:<a@x> BODY=8BITMIME", Response: "250 ok"}},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	var mail []byte
	for _, c := range cfgs {
		if c.Direction == "up" && c.L4.Flags == 0x18 && strings.Contains(string(c.Payload), "MAIL FROM") {
			mail = c.Payload
			break
		}
	}
	if !strings.Contains(string(mail), "BODY=8BITMIME") {
		t.Errorf("MAIL should contain BODY=8BITMIME, got %q", mail)
	}
}

// TestSMTP_1_3_4_MAIL_SIZE covers testcase 1.3.4: MAIL with SIZE=n.
func TestSMTP_1_3_4_MAIL_SIZE(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 50000, DstPort: 25,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		SMTP: &core.SMTPConfig{
			Banner: "220 x",
			Dialog: []core.SMTPCommand{{Cmd: "MAIL FROM:<a@x> SIZE=12345", Response: "250 ok"}},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	var mail []byte
	for _, c := range cfgs {
		if c.Direction == "up" && c.L4.Flags == 0x18 && strings.Contains(string(c.Payload), "MAIL FROM") {
			mail = c.Payload
			break
		}
	}
	if !strings.Contains(string(mail), "SIZE=12345") {
		t.Errorf("MAIL should contain SIZE=12345, got %q", mail)
	}
}

// --- Testcase §1.4 RCPT TO ---

// TestSMTP_1_4_1_RCPT_Basic covers testcase 1.4.1: RCPT TO with full
// email address.
func TestSMTP_1_4_1_RCPT_Basic(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 50000, DstPort: 25,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		SMTP: &core.SMTPConfig{
			Banner: "220 x",
			Dialog: []core.SMTPCommand{{Cmd: "RCPT TO:<bob@example.com>", Response: "250 ok"}},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	var rcpt []byte
	for _, c := range cfgs {
		if c.Direction == "up" && c.L4.Flags == 0x18 && strings.Contains(string(c.Payload), "RCPT TO") {
			rcpt = c.Payload
			break
		}
	}
	if string(rcpt) != "RCPT TO:<bob@example.com>\r\n" {
		t.Errorf("RCPT payload=%q, want exact match", rcpt)
	}
}

// TestSMTP_1_4_2_RCPT_Accumulation covers testcase 1.4.2: multiple
// RCPT TO commands accumulate in the same flow.
func TestSMTP_1_4_2_RCPT_Accumulation(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 50000, DstPort: 25,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		SMTP: &core.SMTPConfig{
			Banner: "220 x",
			Dialog: []core.SMTPCommand{
				{Cmd: "RCPT TO:<bob@example.com>", Response: "250 ok"},
				{Cmd: "RCPT TO:<charlie@example.com>", Response: "250 ok"},
			},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	var bobFound, charlieFound bool
	for _, c := range cfgs {
		if c.Direction != "up" || c.L4.Flags != 0x18 {
			continue
		}
		s := string(c.Payload)
		if strings.Contains(s, "RCPT TO:<bob@example.com>") {
			bobFound = true
		}
		if strings.Contains(s, "RCPT TO:<charlie@example.com>") {
			charlieFound = true
		}
	}
	if !bobFound || !charlieFound {
		t.Errorf("both RCPT TO commands should appear in up PSH-ACKs; bob=%v charlie=%v", bobFound, charlieFound)
	}
}

// --- Testcase §1.5 DATA command (RFC 5321 §4.1.1.4) ---

// TestSMTP_1_5_1_DATA_Basic covers testcase 1.5.1: DATA command is 5
// bytes ("DATA\r\n").
func TestSMTP_1_5_1_DATA_Basic(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 50000, DstPort: 25,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		SMTP: &core.SMTPConfig{
			Banner: "220 x",
			Dialog: []core.SMTPCommand{{Cmd: "DATA", Response: "354 ok"}},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	var data []byte
	for _, c := range cfgs {
		if c.Direction == "up" && c.L4.Flags == 0x18 && c.L4.SrcPort != 0 && len(c.Payload) == 6 {
			// DATA\r\n = 6 bytes (D,A,T,A,\r,\n)
			if string(c.Payload) == "DATA\r\n" {
				data = c.Payload
				break
			}
		}
	}
	if len(data) != 6 {
		t.Errorf("DATA payload should be 6 bytes 'DATA\\r\\n', got %q (%d bytes)", data, len(data))
	}
}

// TestSMTP_1_5_2_DATA_354Response covers testcase 1.5.2: server
// responds with 354 after DATA.
func TestSMTP_1_5_2_DATA_354Response(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 50000, DstPort: 25,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		SMTP: &core.SMTPConfig{
			Banner: "220 x",
			Dialog: []core.SMTPCommand{{Cmd: "DATA", Response: "354 End data with <CR><LF>.<CR><LF>"}},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	var resp []byte
	for _, c := range cfgs {
		if c.Direction == "down" && c.L4.Flags == 0x18 && strings.Contains(string(c.Payload), "354") {
			resp = c.Payload
			break
		}
	}
	if !strings.Contains(string(resp), "354") {
		t.Errorf("expected 354 response, got %q", resp)
	}
}

// TestSMTP_1_5_4_DATA_FullRFC5322 covers testcase 1.5.4: full RFC
// 5322 email body in DATA.
func TestSMTP_1_5_4_DATA_FullRFC5322(t *testing.T) {
	p := NewPlanner()
	headers := "From: a\r\nTo: b\r\nSubject: t\r\n\r\nBody\r\n."
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 50000, DstPort: 25,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		SMTP: &core.SMTPConfig{
			Banner: "220 x",
			Dialog: []core.SMTPCommand{
				{Cmd: "DATA", Response: "354"},
				{Cmd: headers, Response: "250 ok"},
			},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	var body []byte
	for _, c := range cfgs {
		if c.Direction == "up" && c.L4.Flags == 0x18 && strings.Contains(string(c.Payload), "From: a") {
			body = c.Payload
			break
		}
	}
	expected := headers + "\r\n"
	if string(body) != expected {
		t.Errorf("full email body should be emitted verbatim, got %q want %q", body, expected)
	}
}

// --- Testcase §1.6 QUIT ---

// TestSMTP_1_6_1_QUIT_Basic covers testcase 1.6.1: QUIT command is
// "QUIT\r\n" (6 bytes).
func TestSMTP_1_6_1_QUIT_Basic(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 50000, DstPort: 25,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		SMTP: &core.SMTPConfig{
			Banner: "220 x",
			Dialog: []core.SMTPCommand{{Cmd: "QUIT", Response: "221 Bye"}},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	var quit []byte
	for _, c := range cfgs {
		if c.Direction == "up" && c.L4.Flags == 0x18 && len(c.Payload) == 6 {
			if string(c.Payload) == "QUIT\r\n" {
				quit = c.Payload
				break
			}
		}
	}
	if len(quit) != 6 {
		t.Errorf("QUIT should be 6 bytes 'QUIT\\r\\n', got %q (%d)", quit, len(quit))
	}
}

// TestSMTP_1_6_2_QUIT_221Response covers testcase 1.6.2: server
// responds with 221 to QUIT.
func TestSMTP_1_6_2_QUIT_221Response(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 50000, DstPort: 25,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		SMTP: &core.SMTPConfig{
			Banner: "220 x",
			Dialog: []core.SMTPCommand{{Cmd: "QUIT", Response: "221 2.0.0 Bye"}},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	var resp []byte
	for _, c := range cfgs {
		if c.Direction == "down" && c.L4.Flags == 0x18 && strings.Contains(string(c.Payload), "221") {
			resp = c.Payload
			break
		}
	}
	if !strings.Contains(string(resp), "221") {
		t.Errorf("expected 221 response, got %q", resp)
	}
}

// --- Testcase §1.19 Response codes ---

// TestSMTP_1_19_X_ResponseCodes covers the response code family: each
// common code (220/221/235/250/251/334/354/421/450/451/452/500/
// 501/502/503/504/535/550/551/552/553/554) must be passable as the
// Response field of an SMTPCommand and emitted verbatim in the
// server->client PSH-ACK.
func TestSMTP_1_19_X_ResponseCodes(t *testing.T) {
	codes := []string{
		"220", "221", "235", "250", "251",
		"334 VXNlcm5hbWU6",
		"354",
		"421", "450", "451", "452",
		"500", "501", "502", "503", "504",
		"535 5.7.8 auth failed",
		"550 5.1.1 user unknown",
		"551", "552", "553",
		"554 5.7.1 spam rejected",
	}
	for _, code := range codes {
		t.Run(code, func(t *testing.T) {
			p := NewPlanner()
			spec := core.FlowSpec{
				SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
				SrcPort: 50000, DstPort: 25,
				SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
				SMTP: &core.SMTPConfig{
					Banner: "220 x",
					Dialog: []core.SMTPCommand{{Cmd: "NOOP", Response: code}},
				},
			}
			cfgs := drain(mustPlan(t, p, spec))
			var resp []byte
			for _, c := range cfgs {
				if c.Direction == "down" && c.L4.Flags == 0x18 && strings.Contains(string(c.Payload), code) {
					resp = c.Payload
					break
				}
			}
			if len(resp) == 0 {
				t.Errorf("code %q not found in any down PSH-ACK", code)
			}
		})
	}
}

// --- Testcase §2.1 State transitions ---

// TestSMTP_2_1_3_GREETING_DATA_503 covers testcase 2.1.3: DATA in
// GREETING (before EHLO/HELO) is a sequence error -> 503 response.
// The planner plays back verbatim, so the user models the 503 by
// providing it as the Response.
func TestSMTP_2_1_3_GREETING_DATA_503(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 50000, DstPort: 25,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		SMTP: &core.SMTPConfig{
			Banner: "220 x",
			Dialog: []core.SMTPCommand{{Cmd: "DATA", Response: "503 5.5.1 Command out of sequence"}},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	var resp []byte
	for _, c := range cfgs {
		if c.Direction == "down" && c.L4.Flags == 0x18 {
			// Skip the banner (first down PSH-ACK) to find the 503
			// response that follows the user-provided Dialog.
			if strings.HasPrefix(string(c.Payload), "220") {
				continue
			}
			resp = c.Payload
			break
		}
	}
	if !strings.Contains(string(resp), "503") {
		t.Errorf("expected 503 out-of-sequence response, got %q", resp)
	}
}

// TestSMTP_2_1_4_GREETING_MAIL_503 covers testcase 2.1.4: MAIL
// before EHLO/HELO -> 503.
func TestSMTP_2_1_4_GREETING_MAIL_503(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 50000, DstPort: 25,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		SMTP: &core.SMTPConfig{
			Banner: "220 x",
			Dialog: []core.SMTPCommand{{Cmd: "MAIL FROM:<a@x>", Response: "503 5.5.1 need EHLO first"}},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	var resp []byte
	for _, c := range cfgs {
		if c.Direction == "down" && c.L4.Flags == 0x18 {
			// Skip the banner (first down PSH-ACK) to find the 503
			// response that follows the user-provided Dialog.
			if strings.HasPrefix(string(c.Payload), "220") {
				continue
			}
			resp = c.Payload
			break
		}
	}
	if !strings.Contains(string(resp), "503") {
		t.Errorf("expected 503 response, got %q", resp)
	}
}

// --- Testcase §2.3 MAIL -> RCPT -> DATA ---

// TestSMTP_2_3_1_FullSession covers testcase 2.3.1: full HELO +
// MAIL + RCPT + DATA + body + QUIT session.
func TestSMTP_2_3_1_FullSession(t *testing.T) {
	p := NewPlanner()
	spec := validSMTPSpec()
	cfgs := drain(mustPlan(t, p, spec))
	// Expect at least: handshake(3) + banner(1) + HELO+250 + MAIL+250
	// + RCPT+250 + DATA+354 + body+250 + QUIT+221 + teardown(4)
	// = 3 + 1 + 12 + 4 = 20 packets.
	if len(cfgs) != 20 {
		t.Errorf("len=%d, want 20 (full session)", len(cfgs))
	}
}

// --- Testcase §2.5 INIT -> AUTH -> MAIL ---

// TestSMTP_2_5_1_AUTH_PLAIN_Success covers testcase 2.5.1: AUTH
// PLAIN success path.
func TestSMTP_2_5_1_AUTH_PLAIN_Success(t *testing.T) {
	p := NewPlanner()
	// base64(NUL alice@example.org NUL hunter2) is a sample; planner
	// emits it verbatim as the AUTH PLAIN one-shot payload.
	const authData = "AGFsaWNlQGV4YW1wbGUub3JnAGh1bnRlcjI="
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 50000, DstPort: 25,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		SMTP: &core.SMTPConfig{
			Banner: "220 x",
			Dialog: []core.SMTPCommand{
				{Cmd: "AUTH PLAIN " + authData, Response: "235 2.7.0 Authentication successful"},
			},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	var found bool
	for _, c := range cfgs {
		if c.Direction == "up" && c.L4.Flags == 0x18 && strings.Contains(string(c.Payload), "AUTH PLAIN") && strings.Contains(string(c.Payload), authData) {
			found = true
		}
	}
	if !found {
		t.Errorf("AUTH PLAIN one-shot payload not found")
	}
}

// TestSMTP_2_5_3_AUTH_BeforeEHLO_503 covers testcase 2.5.3: AUTH
// before EHLO -> 503.
func TestSMTP_2_5_3_AUTH_BeforeEHLO_503(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 50000, DstPort: 25,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		SMTP: &core.SMTPConfig{
			Banner: "220 x",
			Dialog: []core.SMTPCommand{
				{Cmd: "AUTH PLAIN AGFz", Response: "503 5.5.1 EHLO first"},
			},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	var resp []byte
	for _, c := range cfgs {
		if c.Direction == "down" && c.L4.Flags == 0x18 {
			// Skip the banner (first down PSH-ACK) to find the 503
			// response that follows the user-provided Dialog.
			if strings.HasPrefix(string(c.Payload), "220") {
				continue
			}
			resp = c.Payload
			break
		}
	}
	if !strings.Contains(string(resp), "503") {
		t.Errorf("expected 503 response, got %q", resp)
	}
}

// --- Testcase §2.6 INIT -> STARTTLS ---

// TestSMTP_2_6_1_STARTTLS_Upgrade covers testcase 2.6.1: STARTTLS
// upgrade flow.
func TestSMTP_2_6_1_STARTTLS_Upgrade(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 50000, DstPort: 25,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		SMTP: &core.SMTPConfig{
			Banner: "220 x",
			Dialog: []core.SMTPCommand{
				{Cmd: "EHLO x", Response: "250-STARTTLS"},
				{Cmd: "STARTTLS", Response: "220 2.0.0 Ready to start TLS"},
			},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	var foundSTARTTLS bool
	for _, c := range cfgs {
		if c.Direction == "up" && c.L4.Flags == 0x18 && strings.HasPrefix(string(c.Payload), "STARTTLS\r\n") {
			foundSTARTTLS = true
		}
	}
	if !foundSTARTTLS {
		t.Errorf("STARTTLS command not found in up PSH-ACKs")
	}
}

// --- Testcase §2.7 INIT -> QUIT ---

// TestSMTP_2_7_1_Minimal_HELO_QUIT covers testcase 2.7.1: minimal
// valid session is HELO + 250 + QUIT + 221.
func TestSMTP_2_7_1_Minimal_HELO_QUIT(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 50000, DstPort: 25,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		SMTP: &core.SMTPConfig{
			Banner: "220 x",
			Dialog: []core.SMTPCommand{
				{Cmd: "HELO x", Response: "250 ok"},
				{Cmd: "QUIT", Response: "221 Bye"},
			},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// handshake(3) + banner(1) + HELO+250(2) + QUIT+221(2) + teardown(4) = 12
	if len(cfgs) != 12 {
		t.Fatalf("len=%d, want 12 (minimal session)", len(cfgs))
	}
}

// --- Testcase §3.x scenarios ---

// TestSMTP_3_1_2_SimpleSend_MissingMAIL_503 covers testcase 3.1.2:
// RCPT without prior MAIL -> 503.
func TestSMTP_3_1_2_SimpleSend_MissingMAIL_503(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 50000, DstPort: 25,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		SMTP: &core.SMTPConfig{
			Banner: "220 x",
			Dialog: []core.SMTPCommand{
				{Cmd: "HELO x", Response: "250 ok"},
				{Cmd: "RCPT TO:<a@x>", Response: "503 5.5.1 MAIL required first"},
			},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	var resp []byte
	for _, c := range cfgs {
		if c.Direction == "down" && c.L4.Flags == 0x18 && strings.Contains(string(c.Payload), "503") {
			resp = c.Payload
			break
		}
	}
	if len(resp) == 0 {
		t.Errorf("expected 503 response")
	}
}

// TestSMTP_3_3_3_AUTH_PLAIN_EmptyData covers testcase 3.3.3: AUTH
// PLAIN with empty base64 payload is still valid (some servers
// accept this for pre-auth).
func TestSMTP_3_3_3_AUTH_PLAIN_EmptyData(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 50000, DstPort: 25,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		SMTP: &core.SMTPConfig{
			Banner: "220 x",
			Dialog: []core.SMTPCommand{
				{Cmd: "AUTH PLAIN ", Response: "235 ok"},
			},
		},
	}
	if _, err := p.Plan(context.Background(), spec); err != nil {
		t.Errorf("AUTH PLAIN with empty initial payload should be accepted: %v", err)
	}
}

// TestSMTP_3_9_1_MultipleRCPT covers testcase 3.9.1: 3 RCPT TO
// recipients in one session.
func TestSMTP_3_9_1_MultipleRCPT(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 50000, DstPort: 25,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		SMTP: &core.SMTPConfig{
			Banner: "220 x",
			Dialog: []core.SMTPCommand{
				{Cmd: "MAIL FROM:<a@x>", Response: "250 ok"},
				{Cmd: "RCPT TO:<b@x>", Response: "250 ok"},
				{Cmd: "RCPT TO:<c@x>", Response: "250 ok"},
				{Cmd: "RCPT TO:<d@x>", Response: "250 ok"},
			},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	count := 0
	for _, c := range cfgs {
		if c.Direction == "up" && c.L4.Flags == 0x18 && strings.HasPrefix(string(c.Payload), "RCPT TO") {
			count++
		}
	}
	if count != 3 {
		t.Errorf("expected 3 RCPT TO up packets, got %d", count)
	}
}

// TestSMTP_3_14_3_InvalidAddressSyntax covers testcase 3.14.3:
// MAIL FROM with bad address syntax -> 501.
func TestSMTP_3_14_3_InvalidAddressSyntax(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 50000, DstPort: 25,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		SMTP: &core.SMTPConfig{
			Banner: "220 x",
			Dialog: []core.SMTPCommand{
				{Cmd: "MAIL FROM:not-an-address", Response: "501 5.1.7 Bad sender address syntax"},
			},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	var resp []byte
	for _, c := range cfgs {
		if c.Direction == "down" && c.L4.Flags == 0x18 {
			// Skip the banner (first down PSH-ACK) to find the 501
			// response that follows the user-provided Dialog.
			if strings.HasPrefix(string(c.Payload), "220") {
				continue
			}
			resp = c.Payload
			break
		}
	}
	if !strings.Contains(string(resp), "501") {
		t.Errorf("expected 501 response, got %q", resp)
	}
}

// --- Testcase §4.1 Empty values ---

// TestSMTP_4_1_2_EmptyBannerAutoGen covers testcase 4.1.2: empty
// Banner triggers auto-generation.
func TestSMTP_4_1_2_EmptyBannerAutoGen(t *testing.T) {
	p := NewPlanner()
	spec := validSMTPSpec()
	spec.SMTP.Banner = ""
	cfgs := drain(mustPlan(t, p, spec))
	banner := string(cfgs[3].Payload)
	if !strings.HasPrefix(banner, "220") {
		t.Errorf("auto-banner should start with 220, got %q", banner)
	}
}

// --- Testcase §4.4 Large body ---

// TestSMTP_4_4_2_LargeBody covers testcase 4.4.2: large body
// payload is segmented by MSS.
func TestSMTP_4_4_2_LargeBody(t *testing.T) {
	p := NewPlanner()
	// 10KB body with MSS=536 -> many segments
	body := strings.Repeat("x", 10000)
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 50000, DstPort: 25,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		TCP:   &core.TCPConfig{MSS: 536},
		SMTP: &core.SMTPConfig{
			Banner: "220 x",
			Dialog: []core.SMTPCommand{
				{Cmd: "DATA", Response: "354"},
				{Cmd: body + "\r\n.", Response: "250 ok"},
			},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// Count the body segments (up PSH-ACKs whose payload is the
	// body bytes).
	var bodySegCount int
	for _, c := range cfgs {
		if c.Direction == "up" && c.L4.Flags == 0x18 && len(c.Payload) == 536 {
			bodySegCount++
		}
	}
	// At least 18 full 536-byte segments of the 10KB body
	if bodySegCount < 18 {
		t.Errorf("expected >= 18 full 536-byte segments, got %d", bodySegCount)
	}
}

// --- Testcase §5.x Concurrency ---

// TestSMTP_5_1_TenWorkers_RaceClean covers testcase 5.1: 10
// goroutines running Plan on the same spec must be race-clean
// (each worker has independent clientSeq / serverSeq since
// they're local goroutine variables).
func TestSMTP_5_1_TenWorkers_RaceClean(t *testing.T) {
	p := NewPlanner()
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			spec := validSMTPSpec()
			cfgs := drain(mustPlan(t, p, spec))
			if len(cfgs) == 0 {
				t.Errorf("worker %d emitted no packets", idx)
			}
		}(i)
	}
	wg.Wait()
}

// TestSMTP_5_5_CountSequences covers testcase 5.5: same spec
// reproduced N times produces independent flows with different
// sequence numbers.
func TestSMTP_5_5_CountSequences(t *testing.T) {
	p := NewPlanner()
	seen := make(map[uint32]bool) // client SYN seqs
	for i := 0; i < 20; i++ {
		spec := validSMTPSpec()
		testutil.EnsureTCP(&spec).InitialSeq = 0 // force random
		cfgs := drain(mustPlan(t, p, spec))
		seen[cfgs[0].L4.Seq] = true
	}
	if len(seen) < 15 {
		t.Errorf("expected >= 15 unique SYN seqs across 20 runs, got %d (random may collide)", len(seen))
	}
}

// --- Testcase §6.x Resource exhaustion ---

// TestSMTP_6_4_ContextCancel covers testcase 6.4: ctx cancellation
// must not panic; Plan goroutine must terminate cleanly.
//
// Note: trafficgen planners currently run to completion (they don't
// check ctx). This test verifies that even with a pre-cancelled
// context, Plan doesn't panic and returns the full channel.
func TestSMTP_6_4_ContextCancel(t *testing.T) {
	p := NewPlanner()
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // immediately cancel before Plan starts
	spec := validSMTPSpec()
	ch, err := p.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan with cancelled ctx should not error: %v", err)
	}
	// Drain the channel; planner emits all packets regardless of
	// ctx (which is the current behavior per design_smtp.md §6.4
	// notes - ctx-cancellation is enforced at a higher level).
	cfgs := drain(ch)
	if len(cfgs) == 0 {
		t.Errorf("planner should still emit packets when ctx is cancelled (currently non-blocking)")
	}
}

// --- Testcase §1.16 8BITMIME (RFC 6152/1652) ---

// TestSMTP_1_16_1_8BITMIME_MAILParam covers testcase 1.16.1: MAIL
// with BODY=8BITMIME parameter round-trips.
func TestSMTP_1_16_1_8BITMIME_MAILParam(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 50000, DstPort: 25,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		SMTP: &core.SMTPConfig{
			Banner: "220 x",
			Dialog: []core.SMTPCommand{{Cmd: "MAIL FROM:<a@x> BODY=8BITMIME", Response: "250 ok"}},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	var found8bit bool
	for _, c := range cfgs {
		if c.Direction == "up" && c.L4.Flags == 0x18 && strings.Contains(string(c.Payload), "BODY=8BITMIME") {
			found8bit = true
		}
	}
	if !found8bit {
		t.Errorf("BODY=8BITMIME not found in up PSH-ACKs")
	}
}

// TestSMTP_3_7_1_UTF8Body covers testcase 3.7.1: UTF-8 body content
// round-trips without re-encoding (planner plays back verbatim).
func TestSMTP_3_7_1_UTF8Body(t *testing.T) {
	p := NewPlanner()
	const utf8Body = "From: a@example.org\r\nTo: b@example.com\r\nSubject: 你好\r\n\r\n这是中文内容。\r\n."
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 50000, DstPort: 25,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		SMTP: &core.SMTPConfig{
			Banner: "220 x",
			Dialog: []core.SMTPCommand{
				{Cmd: "DATA", Response: "354"},
				{Cmd: utf8Body, Response: "250 ok"},
			},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	var body []byte
	for _, c := range cfgs {
		if c.Direction == "up" && c.L4.Flags == 0x18 && strings.Contains(string(c.Payload), "Subject: 你好") {
			body = c.Payload
			break
		}
	}
	expected := utf8Body + "\r\n"
	if string(body) != expected {
		t.Errorf("UTF-8 body should be emitted verbatim, got %q want %q", body, expected)
	}
}

// --- Testcase §4.3.x Abnormal values ---

// TestSMTP_4_3_4_DoubleAt covers testcase 4.3.4: malformed address
// (double @) is the user's responsibility to encode as a 501
// response in the Dialog.
func TestSMTP_4_3_4_DoubleAt(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 50000, DstPort: 25,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		SMTP: &core.SMTPConfig{
			Banner: "220 x",
			Dialog: []core.SMTPCommand{
				{Cmd: "RCPT TO:<alice@@example.com>", Response: "501 5.1.3 Bad address syntax"},
			},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	var found501 bool
	for _, c := range cfgs {
		if c.Direction == "down" && c.L4.Flags == 0x18 && strings.Contains(string(c.Payload), "501") {
			found501 = true
		}
	}
	if !found501 {
		t.Errorf("expected 501 response for double-at address")
	}
}

// --- Testcase §2.4 DATA -> RCPT (nested MAIL) ---

// TestSMTP_2_4_3_QUIT_After_DATA covers testcase 2.4.3: QUIT
// immediately after DATA completes without separate teardown
// transitions.
func TestSMTP_2_4_3_QUIT_After_DATA(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 50000, DstPort: 25,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		SMTP: &core.SMTPConfig{
			Banner: "220 x",
			Dialog: []core.SMTPCommand{
				{Cmd: "DATA", Response: "354"},
				{Cmd: "From: a\r\n.\r\n", Response: "250 ok"},
				{Cmd: "QUIT", Response: "221 Bye"},
			},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) < 10 {
		t.Errorf("expected >= 10 packets for DATA + QUIT sequence, got %d", len(cfgs))
	}
	// QUIT must be in the dialog before the teardown.
	var foundQuit bool
	for _, c := range cfgs {
		if c.Direction == "up" && c.L4.Flags == 0x18 && string(c.Payload) == "QUIT\r\n" {
			foundQuit = true
		}
	}
	if !foundQuit {
		t.Errorf("QUIT not found")
	}
}

// --- Testcase §1.7 RSET ---

// TestSMTP_1_7_1_RSET covers testcase 1.7.1: RSET resets session
// state.
func TestSMTP_1_7_1_RSET(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 50000, DstPort: 25,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		SMTP: &core.SMTPConfig{
			Banner: "220 x",
			Dialog: []core.SMTPCommand{
				{Cmd: "RSET", Response: "250 ok"},
			},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	var foundRSET bool
	for _, c := range cfgs {
		if c.Direction == "up" && c.L4.Flags == 0x18 && string(c.Payload) == "RSET\r\n" {
			foundRSET = true
		}
	}
	if !foundRSET {
		t.Errorf("RSET not found as standalone PSH-ACK")
	}
}

// --- Testcase §1.8 NOOP ---

// TestSMTP_1_8_1_NOOP covers testcase 1.8.1: NOOP is a 0-effect
// command.
func TestSMTP_1_8_1_NOOP(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 50000, DstPort: 25,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		SMTP: &core.SMTPConfig{
			Banner: "220 x",
			Dialog: []core.SMTPCommand{{Cmd: "NOOP", Response: "250 ok"}},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	var foundNOOP bool
	for _, c := range cfgs {
		if c.Direction == "up" && c.L4.Flags == 0x18 && string(c.Payload) == "NOOP\r\n" {
			foundNOOP = true
		}
	}
	if !foundNOOP {
		t.Errorf("NOOP not found as standalone PSH-ACK")
	}
}

// --- Testcase §1.9 VRFY ---

// TestSMTP_1_9_1_VRFY covers testcase 1.9.1: VRFY returns
// 250/252/550 depending on user existence.
func TestSMTP_1_9_1_VRFY(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 50000, DstPort: 25,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		SMTP: &core.SMTPConfig{
			Banner: "220 x",
			Dialog: []core.SMTPCommand{
				{Cmd: "VRFY alice", Response: "250 2.1.5 Alice Smith <alice@example.org>"},
			},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	var foundVRFY bool
	for _, c := range cfgs {
		if c.Direction == "up" && c.L4.Flags == 0x18 && strings.HasPrefix(string(c.Payload), "VRFY ") {
			foundVRFY = true
		}
	}
	if !foundVRFY {
		t.Errorf("VRFY not found as up PSH-ACK")
	}
}

// --- Testcase §1.12 AUTH LOGIN (3-step) ---

// TestSMTP_1_12_3_AUTH_LOGIN_3Step covers testcase 1.12.3:
// AUTH LOGIN -> 334 -> base64(user) -> 334 -> base64(pass) -> 235.
func TestSMTP_1_12_3_AUTH_LOGIN_3Step(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 50000, DstPort: 25,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		SMTP: &core.SMTPConfig{
			Banner: "220 x",
			Dialog: []core.SMTPCommand{
				{Cmd: "AUTH LOGIN", Response: "334 VXNlcm5hbWU6"},
				{Cmd: "YWxpY2VAZXhhbXBsZS5vcmc=", Response: "334 UGFzc3dvcmQ6"},
				{Cmd: "aHVudGVyMg==", Response: "235 2.7.0 Authentication successful"},
			},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// Expect 3 up PSH-ACKs (AUTH LOGIN, base64(user), base64(pass))
	upCount := 0
	for _, c := range cfgs {
		if c.Direction == "up" && c.L4.Flags == 0x18 {
			upCount++
		}
	}
	if upCount != 3 {
		t.Errorf("expected 3 up PSH-ACKs in AUTH LOGIN 3-step, got %d", upCount)
	}
}

// --- Testcase §1.14 ETRN ---

// TestSMTP_1_14_1_ETRN covers testcase 1.14.1: ETRN command.
func TestSMTP_1_14_1_ETRN(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 50000, DstPort: 25,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		SMTP: &core.SMTPConfig{
			Banner: "220 x",
			Dialog: []core.SMTPCommand{
				{Cmd: "ETRN remote.example.com", Response: "251 2.0.0 Queued"},
			},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	var foundETRN bool
	for _, c := range cfgs {
		if c.Direction == "up" && c.L4.Flags == 0x18 && strings.HasPrefix(string(c.Payload), "ETRN ") {
			foundETRN = true
		}
	}
	if !foundETRN {
		t.Errorf("ETRN not found as up PSH-ACK")
	}
}

// --- Testcase §2.4 Server-only / client-only turns ---

// TestSMTP_2_5_OneWayTurns covers scenarios where one of Cmd/Response
// is empty (server-only or client-only turn).
func TestSMTP_2_5_OneWayTurns(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 50000, DstPort: 25,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		SMTP: &core.SMTPConfig{
			Banner: "220 x",
			Dialog: []core.SMTPCommand{
				{Cmd: "NOOP", Response: ""},   // client only
				{Cmd: "", Response: "250 ok"}, // server only
			},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// Expect: handshake(3) + banner(1) + cmd(1) + resp(1) + teardown(4) = 10
	if len(cfgs) != 10 {
		t.Errorf("len=%d, want 10 (NOOP no-resp + empty-cmd resp)", len(cfgs))
	}
}

// --- Testcase §1.18 Email header fields (RFC 5322 §3.6) ---

// TestSMTP_1_18_7_Subject covers testcase 1.18.7: Subject header
// round-trips in body.
func TestSMTP_1_18_7_Subject(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 50000, DstPort: 25,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		SMTP: &core.SMTPConfig{
			Banner: "220 x",
			Dialog: []core.SMTPCommand{
				{Cmd: "DATA", Response: "354"},
				{Cmd: "From: a\r\nSubject: Meeting tomorrow\r\n\r\nBody\r\n.", Response: "250"},
			},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	var body []byte
	for _, c := range cfgs {
		if c.Direction == "up" && c.L4.Flags == 0x18 && strings.Contains(string(c.Payload), "Subject:") {
			body = c.Payload
			break
		}
	}
	if !strings.Contains(string(body), "Subject: Meeting tomorrow\r\n") {
		t.Errorf("Subject header should round-trip, got %q", body)
	}
}
