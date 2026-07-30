package smtp

// Spec-driven tests for SMTP MIME multipart (RFC 2046) email construction.
// Derived from:
//   - RFC 5321 §4.1.1.4 (DATA terminator: <CRLF>.<CRLF>)
//   - RFC 5322 §3.6 (message = headers + blank line + body)
//   - RFC 2045 §4    (MIME-Version header)
//   - RFC 2045 §6/7  (Content-Transfer-Encoding, Content-Type)
//   - RFC 2045 §6.8  (base64 encoding for binary attachments)
//   - RFC 2046 §5.1.1 (multipart boundary: "--boundary" / "--boundary--")
//   - RFC 2046 §5.1.4 (multipart/alternative for text+html)
//   - RFC 2183       (Content-Disposition: attachment; filename="...")
//   - RFC 5321 §4.5.2 (dot-stuffing: lines starting "." get extra ".")
//
// Each test asserts observable payload bytes, not just "no error".

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

// emailDialogSpec builds a spec with HELO + MAIL + RCPT + DATA + QUIT and
// an Email field set. The planner auto-injects the multipart body + 250
// response after the DATA/354 pair. The user must NOT include a body
// command in Dialog when Email is set (the planner fills it in).
func emailDialogSpec(email *core.SMTPEmail) core.FlowSpec {
	return core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 50000, DstPort: 25,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		SMTP: &core.SMTPConfig{
			Banner: "220 mail.example.org ESMTP",
			Email:  email,
			Dialog: []core.SMTPCommand{
				{Cmd: "HELO client.example.org", Response: "250 ok"},
				{Cmd: "MAIL FROM:<alice@example.org>", Response: "250 2.1.0 Ok"},
				{Cmd: "RCPT TO:<bob@example.com>", Response: "250 2.1.5 Ok"},
				{Cmd: "DATA", Response: "354 End data with <CR><LF>.<CR><LF>"},
				{Cmd: "QUIT", Response: "221 2.0.0 Bye"},
			},
		},
	}
}

// findEmailBodyPayload locates the injected DATA body packet: an up
// PSH-ACK that appears after the 354 response and contains the email
// content (boundary or text). Returns the payload or empty string.
func findEmailBodyPayload(cfgs []core.PacketConfig) string {
	saw354 := false
	for _, c := range cfgs {
		if c.Direction == "down" && c.L4.Flags == 0x18 && strings.Contains(string(c.Payload), "354") {
			saw354 = true
			continue
		}
		if saw354 && c.Direction == "up" && c.L4.Flags == 0x18 && len(c.Payload) > 0 {
			return string(c.Payload)
		}
	}
	return ""
}

// findAuto250Payload locates the auto-emitted 250 response after the
// injected body. Returns the payload or empty string.
func findAuto250Payload(cfgs []core.PacketConfig) string {
	saw354 := false
	sawBody := false
	for _, c := range cfgs {
		if c.Direction == "down" && c.L4.Flags == 0x18 && strings.Contains(string(c.Payload), "354") {
			saw354 = true
			continue
		}
		if saw354 && c.Direction == "up" && c.L4.Flags == 0x18 && len(c.Payload) > 0 {
			sawBody = true
			continue
		}
		if sawBody && c.Direction == "down" && c.L4.Flags == 0x18 {
			return string(c.Payload)
		}
	}
	return ""
}

// --- RFC 5322 §3: simple text email (non-multipart) ---

// TestSMTPPlan_Email_SimpleText verifies a text-only email (no
// attachments) produces a non-multipart DATA body: headers + blank line
// + text + terminator. No MIME-Version or multipart headers.
func TestSMTPPlan_Email_SimpleText(t *testing.T) {
	p := NewPlanner()
	spec := emailDialogSpec(&core.SMTPEmail{
		Headers:  []string{"From: alice@example.org", "To: bob@example.com", "Subject: Hello"},
		TextBody: "Hello, world!",
	})
	cfgs := drain(mustPlan(t, p, spec))
	body := findEmailBodyPayload(cfgs)
	if body == "" {
		t.Fatal("email body payload not found")
	}
	// Headers present.
	if !strings.Contains(body, "From: alice@example.org\r\n") {
		t.Errorf("From header missing: %q", body)
	}
	if !strings.Contains(body, "Subject: Hello\r\n") {
		t.Errorf("Subject header missing: %q", body)
	}
	// Blank line separating headers from body.
	if !strings.Contains(body, "\r\n\r\n") {
		t.Errorf("blank line separator missing: %q", body)
	}
	// Text body present.
	if !strings.Contains(body, "Hello, world!") {
		t.Errorf("text body missing: %q", body)
	}
	// NOT multipart (no MIME-Version, no boundary).
	if strings.Contains(body, "MIME-Version") {
		t.Errorf("simple text email should NOT have MIME-Version: %q", body)
	}
	// DATA terminator: body must end with "\r\n.\r\n".
	if !strings.HasSuffix(body, "\r\n.\r\n") {
		t.Errorf("body must end with terminator '\\r\\n.\\r\\n', got %q", body)
	}
}

// TestSMTPPlan_Email_EmptyBody verifies an email with empty TextBody and
// no attachments produces a valid empty-body email: headers + blank line
// + terminator.
func TestSMTPPlan_Email_EmptyBody(t *testing.T) {
	p := NewPlanner()
	spec := emailDialogSpec(&core.SMTPEmail{
		Headers: []string{"From: a@b.com"},
	})
	cfgs := drain(mustPlan(t, p, spec))
	body := findEmailBodyPayload(cfgs)
	if body == "" {
		t.Fatal("email body payload not found")
	}
	// Must end with terminator (headers + blank + terminator).
	if !strings.HasSuffix(body, "\r\n.\r\n") {
		t.Errorf("empty body must end with terminator, got %q", body)
	}
}

// --- RFC 2046 §5.1.1: multipart/mixed boundary structure ---

// TestSMTPPlan_Email_MultipartStructure verifies an email with one
// attachment produces a valid multipart/mixed body: MIME-Version header,
// Content-Type with boundary, opening/closing delimiters, base64 part.
func TestSMTPPlan_Email_MultipartStructure(t *testing.T) {
	p := NewPlanner()
	spec := emailDialogSpec(&core.SMTPEmail{
		Headers:  []string{"From: a@b.com", "Subject: With attachment"},
		TextBody: "See attached",
		Attachments: []core.SMTPAttachment{
			{
				Filename:    "test.bin",
				ContentType: "application/octet-stream",
				Data:        []byte("Hello World"),
			},
		},
		Boundary: "TESTBOUND",
	})
	cfgs := drain(mustPlan(t, p, spec))
	body := findEmailBodyPayload(cfgs)
	if body == "" {
		t.Fatal("email body payload not found")
	}
	// MIME-Version per RFC 2045 §4.
	if !strings.Contains(body, "MIME-Version: 1.0\r\n") {
		t.Errorf("MIME-Version: 1.0 header missing: %q", body)
	}
	// Content-Type: multipart/mixed; boundary="..." per RFC 2046 §5.1.1.
	if !strings.Contains(body, `Content-Type: multipart/mixed; boundary="TESTBOUND"`) {
		t.Errorf("Content-Type multipart header missing: %q", body)
	}
	// Opening boundary delimiter.
	if !strings.Contains(body, "--TESTBOUND\r\n") {
		t.Errorf("opening boundary '--TESTBOUND' missing: %q", body)
	}
	// Closing boundary delimiter per RFC 2046 §5.1.1.
	if !strings.Contains(body, "--TESTBOUND--\r\n") {
		t.Errorf("closing boundary '--TESTBOUND--' missing: %q", body)
	}
	// Text part present.
	if !strings.Contains(body, "Content-Type: text/plain") {
		t.Errorf("text part Content-Type missing: %q", body)
	}
	if !strings.Contains(body, "See attached") {
		t.Errorf("text body 'See attached' missing: %q", body)
	}
	// Attachment part headers.
	if !strings.Contains(body, "Content-Type: application/octet-stream\r\n") {
		t.Errorf("attachment Content-Type missing: %q", body)
	}
	if !strings.Contains(body, "Content-Transfer-Encoding: base64\r\n") {
		t.Errorf("Content-Transfer-Encoding: base64 missing: %q", body)
	}
	if !strings.Contains(body, `Content-Disposition: attachment; filename="test.bin"`) {
		t.Errorf("Content-Disposition with filename missing: %q", body)
	}
	// DATA terminator at end.
	if !strings.HasSuffix(body, "\r\n.\r\n") {
		t.Errorf("multipart body must end with terminator, got %q", body)
	}
}

// TestSMTPPlan_Email_MultipleAttachments verifies multiple attachments
// are each delimited by the boundary, with a single closing delimiter.
func TestSMTPPlan_Email_MultipleAttachments(t *testing.T) {
	p := NewPlanner()
	spec := emailDialogSpec(&core.SMTPEmail{
		Headers:  []string{"From: a@b.com"},
		TextBody: "body",
		Attachments: []core.SMTPAttachment{
			{Filename: "a.txt", ContentType: "text/plain", Data: []byte("AAAA")},
			{Filename: "b.bin", ContentType: "application/octet-stream", Data: []byte("BBBB")},
		},
		Boundary: "B",
	})
	cfgs := drain(mustPlan(t, p, spec))
	body := findEmailBodyPayload(cfgs)
	// Two opening attachment boundaries (text part also has one) = 3 total.
	openCount := strings.Count(body, "--B\r\n")
	if openCount != 3 {
		t.Errorf("opening boundary count=%d, want 3 (text+2 attachments): %q", openCount, body)
	}
	// Single closing delimiter.
	if strings.Count(body, "--B--\r\n") != 1 {
		t.Errorf("closing boundary count!=1: %q", body)
	}
	// Both filenames present.
	if !strings.Contains(body, `filename="a.txt"`) {
		t.Errorf("filename a.txt missing: %q", body)
	}
	if !strings.Contains(body, `filename="b.bin"`) {
		t.Errorf("filename b.bin missing: %q", body)
	}
}

// --- RFC 2045 §6.8: base64 attachment encoding ---

// TestSMTPPlan_Email_Base64Encoding verifies raw Data bytes are
// base64-encoded by the planner (RFC 2045 §6.8). The encoded text must
// appear in the part body.
func TestSMTPPlan_Email_Base64Encoding(t *testing.T) {
	p := NewPlanner()
	raw := []byte("Hello World")
	expectedB64 := base64.StdEncoding.EncodeToString(raw)
	spec := emailDialogSpec(&core.SMTPEmail{
		Headers:  []string{"From: a@b.com"},
		TextBody: "x",
		Attachments: []core.SMTPAttachment{
			{Filename: "h.bin", ContentType: "application/octet-stream", Data: raw},
		},
		Boundary: "BND",
	})
	cfgs := drain(mustPlan(t, p, spec))
	body := findEmailBodyPayload(cfgs)
	if !strings.Contains(body, expectedB64) {
		t.Errorf("base64-encoded data %q missing in body: %q", expectedB64, body)
	}
}

// TestSMTPPlan_Email_DataB64_Verbatim verifies DataB64 is emitted
// verbatim (the planner does NOT decode+re-encode it).
func TestSMTPPlan_Email_DataB64_Verbatim(t *testing.T) {
	p := NewPlanner()
	// Pre-encoded base64 of "Test content".
	preB64 := base64.StdEncoding.EncodeToString([]byte("Test content"))
	spec := emailDialogSpec(&core.SMTPEmail{
		Headers:  []string{"From: a@b.com"},
		TextBody: "x",
		Attachments: []core.SMTPAttachment{
			{Filename: "t.bin", ContentType: "application/octet-stream", DataB64: preB64},
		},
		Boundary: "BND",
	})
	cfgs := drain(mustPlan(t, p, spec))
	body := findEmailBodyPayload(cfgs)
	if !strings.Contains(body, preB64) {
		t.Errorf("DataB64 verbatim text %q missing: %q", preB64, body)
	}
}

// TestSMTPPlan_Email_Base64LineWrapping verifies base64 output is wrapped
// at 76 characters per line per RFC 2045 §6.8 (max 76 chars per line).
func TestSMTPPlan_Email_Base64LineWrapping(t *testing.T) {
	p := NewPlanner()
	// 300 bytes of data -> 400 base64 chars -> needs wrapping at 76.
	raw := make([]byte, 300)
	for i := range raw {
		raw[i] = byte('A' + (i % 26))
	}
	spec := emailDialogSpec(&core.SMTPEmail{
		Headers:  []string{"From: a@b.com"},
		TextBody: "x",
		Attachments: []core.SMTPAttachment{
			{Filename: "big.bin", ContentType: "application/octet-stream", Data: raw},
		},
		Boundary: "BND",
	})
	cfgs := drain(mustPlan(t, p, spec))
	body := findEmailBodyPayload(cfgs)
	// Find the base64 lines (after Content-Transfer-Encoding: base64).
	idx := strings.Index(body, "Content-Transfer-Encoding: base64\r\n")
	if idx < 0 {
		t.Fatal("base64 CTE header not found")
	}
	afterHeader := body[idx+len("Content-Transfer-Encoding: base64\r\n"):]
	// Skip the blank line after headers.
	if strings.HasPrefix(afterHeader, "\r\n") {
		afterHeader = afterHeader[2:]
	}
	// Split into lines and verify each is <= 76 chars.
	b64Lines := strings.SplitN(afterHeader, "\r\n", 10)
	for i, line := range b64Lines {
		// Stop at the boundary delimiter.
		if strings.HasPrefix(line, "--BND") {
			break
		}
		if len(line) > 76 {
			t.Errorf("base64 line %d is %d chars, max 76 per RFC 2045 §6.8", i, len(line))
		}
		if len(line) == 0 {
			break
		}
	}
}

// --- RFC 2046 §5.1.4: multipart/alternative ---

// TestSMTPPlan_Email_TextAndHTML_Alternative verifies both TextBody and
// HTMLBody produce a multipart/alternative nested part inside
// multipart/mixed (when attachments present) per RFC 2046 §5.1.4.
func TestSMTPPlan_Email_TextAndHTML_Alternative(t *testing.T) {
	p := NewPlanner()
	spec := emailDialogSpec(&core.SMTPEmail{
		Headers:  []string{"From: a@b.com"},
		TextBody: "plain text",
		HTMLBody: "<p>html</p>",
		Attachments: []core.SMTPAttachment{
			{Filename: "x.bin", ContentType: "application/octet-stream", Data: []byte("X")},
		},
		Boundary: "OUTER",
	})
	cfgs := drain(mustPlan(t, p, spec))
	body := findEmailBodyPayload(cfgs)
	// Outer multipart/mixed.
	if !strings.Contains(body, `boundary="OUTER"`) {
		t.Errorf("outer multipart/mixed boundary missing: %q", body)
	}
	// Inner multipart/alternative.
	if !strings.Contains(body, "multipart/alternative") {
		t.Errorf("multipart/alternative missing: %q", body)
	}
	// Both text and html parts.
	if !strings.Contains(body, "Content-Type: text/plain") {
		t.Errorf("text/plain part missing: %q", body)
	}
	if !strings.Contains(body, "Content-Type: text/html") {
		t.Errorf("text/html part missing: %q", body)
	}
	if !strings.Contains(body, "plain text") {
		t.Errorf("plain text body missing: %q", body)
	}
	if !strings.Contains(body, "<p>html</p>") {
		t.Errorf("html body missing: %q", body)
	}
}

// TestSMTPPlan_Email_HTMLOnly verifies HTMLBody without TextBody produces
// a single text/html part (no multipart/alternative).
func TestSMTPPlan_Email_HTMLOnly(t *testing.T) {
	p := NewPlanner()
	spec := emailDialogSpec(&core.SMTPEmail{
		Headers:  []string{"From: a@b.com"},
		HTMLBody: "<p>html only</p>",
	})
	cfgs := drain(mustPlan(t, p, spec))
	body := findEmailBodyPayload(cfgs)
	// Single text/html part, no multipart/alternative.
	if strings.Contains(body, "multipart/alternative") {
		t.Errorf("single HTML body should NOT use multipart/alternative: %q", body)
	}
	if !strings.Contains(body, "Content-Type: text/html") {
		t.Errorf("Content-Type: text/html missing: %q", body)
	}
}

// --- RFC 2046 §5.1.1: boundary handling ---

// TestSMTPPlan_Email_BoundaryAutoGenerated verifies an empty Boundary
// produces a deterministic auto-generated boundary.
func TestSMTPPlan_Email_BoundaryAutoGenerated(t *testing.T) {
	p := NewPlanner()
	spec := emailDialogSpec(&core.SMTPEmail{
		Headers:  []string{"From: a@b.com"},
		TextBody: "x",
		Attachments: []core.SMTPAttachment{
			{Filename: "a.bin", ContentType: "application/octet-stream", Data: []byte("A")},
		},
	})
	cfgs := drain(mustPlan(t, p, spec))
	body := findEmailBodyPayload(cfgs)
	// Must contain a Content-Type multipart header with a boundary.
	if !strings.Contains(body, `Content-Type: multipart/mixed; boundary="`) {
		t.Errorf("auto-generated boundary header missing: %q", body)
	}
	// The boundary must be deterministic (not empty). Run twice and compare.
	cfgs2 := drain(mustPlan(t, p, spec))
	body2 := findEmailBodyPayload(cfgs2)
	if body != body2 {
		t.Errorf("auto-generated boundary must be deterministic:\nfirst:  %q\nsecond: %q", body, body2)
	}
}

// TestSMTPPlan_Email_BoundaryUserProvided verifies a user-provided
// boundary is used verbatim.
func TestSMTPPlan_Email_BoundaryUserProvided(t *testing.T) {
	p := NewPlanner()
	spec := emailDialogSpec(&core.SMTPEmail{
		Headers:  []string{"From: a@b.com"},
		TextBody: "x",
		Attachments: []core.SMTPAttachment{
			{Filename: "a.bin", ContentType: "application/octet-stream", Data: []byte("A")},
		},
		Boundary: "MY_BOUNDARY_123",
	})
	cfgs := drain(mustPlan(t, p, spec))
	body := findEmailBodyPayload(cfgs)
	if !strings.Contains(body, `boundary="MY_BOUNDARY_123"`) {
		t.Errorf("user boundary not used verbatim: %q", body)
	}
	if !strings.Contains(body, "--MY_BOUNDARY_123\r\n") {
		t.Errorf("opening delimiter with user boundary missing: %q", body)
	}
	if !strings.Contains(body, "--MY_BOUNDARY_123--\r\n") {
		t.Errorf("closing delimiter with user boundary missing: %q", body)
	}
}

// --- RFC 5321 §4.5.2: dot-stuffing ---

// TestSMTPPlan_Email_DotStuffing verifies lines in the text body starting
// with "." get an extra "." prepended per RFC 5321 §4.5.2, preventing
// premature DATA termination.
func TestSMTPPlan_Email_DotStuffing(t *testing.T) {
	p := NewPlanner()
	spec := emailDialogSpec(&core.SMTPEmail{
		Headers:  []string{"From: a@b.com"},
		TextBody: "..hidden dot line\r\nnormal line",
	})
	cfgs := drain(mustPlan(t, p, spec))
	body := findEmailBodyPayload(cfgs)
	// The "..hidden dot line" should become "...hidden dot line" after
	// dot-stuffing (RFC 5321 §4.5.2). The ".." at start triggers stuffing
	// of one extra ".".
	if !strings.Contains(body, "...hidden dot line") {
		t.Errorf("dot-stuffing not applied to line starting with '.': %q", body)
	}
}

// --- RFC 5321 §4.1.1.4: injection after DATA ---

// TestSMTPPlan_Email_InjectsAfterDATA verifies the body is injected after
// the DATA/354 pair (not before), and a 250 response follows the body.
func TestSMTPPlan_Email_InjectsAfterDATA(t *testing.T) {
	p := NewPlanner()
	spec := emailDialogSpec(&core.SMTPEmail{
		Headers:  []string{"From: a@b.com"},
		TextBody: "injected body text",
	})
	cfgs := drain(mustPlan(t, p, spec))
	// Verify order: 354 down -> body up -> 250 down.
	var saw354, sawBody, saw250 bool
	for _, c := range cfgs {
		if c.Direction == "down" && c.L4.Flags == 0x18 && strings.Contains(string(c.Payload), "354") {
			saw354 = true
			continue
		}
		if saw354 && c.Direction == "up" && c.L4.Flags == 0x18 && strings.Contains(string(c.Payload), "injected body text") {
			if !saw354 {
				t.Fatal("body emitted before 354 response")
			}
			sawBody = true
			continue
		}
		if sawBody && c.Direction == "down" && c.L4.Flags == 0x18 && strings.Contains(string(c.Payload), "250") {
			saw250 = true
			break
		}
	}
	if !saw354 {
		t.Error("354 response not found")
	}
	if !sawBody {
		t.Error("injected body not found after 354")
	}
	if !saw250 {
		t.Error("250 response not found after body")
	}
}

// TestSMTPPlan_Email_Auto250Response verifies the auto-emitted 250 after
// the body has the expected format.
func TestSMTPPlan_Email_Auto250Response(t *testing.T) {
	p := NewPlanner()
	spec := emailDialogSpec(&core.SMTPEmail{
		Headers:  []string{"From: a@b.com"},
		TextBody: "x",
	})
	cfgs := drain(mustPlan(t, p, spec))
	resp := findAuto250Payload(cfgs)
	if resp == "" {
		t.Fatal("auto 250 response not found")
	}
	if !strings.HasPrefix(resp, "250") {
		t.Errorf("auto response should start with 250, got %q", resp)
	}
	if !strings.HasSuffix(resp, "\r\n") {
		t.Errorf("auto 250 should end with CRLF, got %q", resp)
	}
}

// TestSMTPPlan_Email_NoDialogGeneratesDefault verifies that when Email
// is set and Dialog is empty, the planner generates a default session
// (HELO + MAIL + RCPT + DATA + body + 250 + QUIT) with the email body.
func TestSMTPPlan_Email_NoDialogGeneratesDefault(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 50000, DstPort: 25,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		SMTP: &core.SMTPConfig{
			Email: &core.SMTPEmail{
				Headers:  []string{"From: a@b.com"},
				TextBody: "default session body",
			},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// Must find the email body somewhere in the up packets.
	var found bool
	for _, c := range cfgs {
		if c.Direction == "up" && c.L4.Flags == 0x18 && strings.Contains(string(c.Payload), "default session body") {
			found = true
			break
		}
	}
	if !found {
		t.Error("email body not found in default session")
	}
}

// --- Backward compatibility ---

// TestSMTPPlan_Email_NilEmailUsesDialogVerbatim verifies that when Email
// is nil, the planner uses the Dialog body verbatim (old path, unchanged).
func TestSMTPPlan_Email_NilEmailUsesDialogVerbatim(t *testing.T) {
	p := NewPlanner()
	spec := validSMTPSpec() // Email is nil, Dialog has a hand-written body
	cfgs := drain(mustPlan(t, p, spec))
	// handshake(3) + banner(1) + 6 commands * 2 + teardown(4) = 20
	if len(cfgs) != 20 {
		t.Fatalf("len=%d, want 20 (Dialog path unchanged when Email nil)", len(cfgs))
	}
	// The hand-written body must still be present.
	var found bool
	for _, c := range cfgs {
		if c.Direction == "up" && strings.Contains(string(c.Payload), "From: alice@example.org") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Dialog body not emitted when Email is nil")
	}
}

// --- Validate: failure paths ---

// TestSMTPValidate_Email_BoundaryWithCRLFRejected verifies a boundary
// containing CRLF is rejected (RFC 2046 §5.1.1 + injection protection).
func TestSMTPValidate_Email_BoundaryWithCRLFRejected(t *testing.T) {
	p := NewPlanner()
	spec := emailDialogSpec(&core.SMTPEmail{
		Headers:  []string{"From: a@b.com"},
		TextBody: "x",
		Attachments: []core.SMTPAttachment{
			{Filename: "a.bin", ContentType: "application/octet-stream", Data: []byte("A")},
		},
		Boundary: "evil\r\nboundary",
	})
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "boundary") {
		t.Errorf("err=%v, want contains 'boundary'", err)
	}
}

// TestSMTPValidate_Email_AttachmentEmptyDataRejected verifies an
// attachment with neither Data nor DataB64 is rejected.
func TestSMTPValidate_Email_AttachmentEmptyDataRejected(t *testing.T) {
	p := NewPlanner()
	spec := emailDialogSpec(&core.SMTPEmail{
		Headers:  []string{"From: a@b.com"},
		TextBody: "x",
		Attachments: []core.SMTPAttachment{
			{Filename: "a.bin", ContentType: "application/octet-stream"},
		},
	})
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "Data") {
		t.Errorf("err=%v, want contains 'Data'", err)
	}
}

// TestSMTPValidate_Email_BoundaryTooLongRejected verifies a boundary
// exceeding 70 chars is rejected (RFC 2046 §5.1.1 limit).
func TestSMTPValidate_Email_BoundaryTooLongRejected(t *testing.T) {
	p := NewPlanner()
	longBoundary := strings.Repeat("x", 71)
	spec := emailDialogSpec(&core.SMTPEmail{
		Headers:  []string{"From: a@b.com"},
		TextBody: "x",
		Attachments: []core.SMTPAttachment{
			{Filename: "a.bin", ContentType: "application/octet-stream", Data: []byte("A")},
		},
		Boundary: longBoundary,
	})
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "boundary") {
		t.Errorf("err=%v, want contains 'boundary'", err)
	}
}

// TestSMTPValidate_Email_NoAttachmentsNoMultipart verifies that an Email
// with only TextBody (no attachments) is accepted and does not require
// multipart structure (no boundary needed).
func TestSMTPValidate_Email_NoAttachmentsNoMultipart(t *testing.T) {
	p := NewPlanner()
	spec := emailDialogSpec(&core.SMTPEmail{
		Headers:  []string{"From: a@b.com"},
		TextBody: "just text",
	})
	if err := p.Validate(spec); err != nil {
		t.Errorf("text-only email should be accepted: %v", err)
	}
}
