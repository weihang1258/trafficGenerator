package imap

// Spec-driven tests for IMAP FETCH with multipart MIME literal bodies
// (RFC 9051 §6.4.6 FETCH, RFC 2045 MIME, RFC 2046 multipart).
//
// These tests are derived from the spec:
// - RFC 9051 §6.4.6: FETCH BODY[] returns "* N FETCH (BODY[] {N}\r\n<mail>)"
//   where {N} is the exact byte count of the literal body.
// - RFC 2045 §4: MIME-Version header required for MIME messages.
// - RFC 2046 §5.1.1: multipart body = delimiter (CRLF "--" boundary) +
//   body parts + close delimiter (CRLF "--" boundary "--").
// - RFC 2045 §6.8: base64 lines max 76 chars.
// - RFC 2183: Content-Disposition: attachment; filename="...".
//
// Coverage:
//   1. Multipart with text + part (structure + boundary + {N} accuracy)
//   2. Multipart with attachment (base64 + Content-Disposition)
//   3. Simple (non-multipart) text message
//   4. Boundary auto-generation (consistency)
//   5. Boundary override (verbatim)
//   6. Large MIME body triggers MSS segmentation
//   7. Multi-session multi-mailbox (SELECT INBOX → FETCH → COPY → SELECT Sent → FETCH)
//   8. Backward compat: LiteralBody still works (no regression)
//   9. Validate: MIMEBody mutually exclusive with LiteralBody/LiteralBodyB64
//  10. {N} matches constructed byte length exactly (observable outcome)

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/protocol/testutil"
)

// --- helpers ---

// fetchMIMECommands returns a single FETCH command with the given MIMEBody.
// Uses {0} as the literal placeholder per the existing IMAP planner
// convention: the placeholder number is OVERWRITTEN by the planner with
// the actual constructed MIME byte length (see replaceLiteralPlaceholder).
// This lets the user avoid pre-computing the MIME body size.
func fetchMIMECommands(mime *core.IMAPMIMEBody) []core.IMAPCommand {
	return []core.IMAPCommand{
		{
			Tag:      "A001",
			Cmd:      "FETCH 1 BODY[]",
			Responses: []string{"* 1 FETCH (BODY[] {0})", "A001 OK FETCH completed"},
			MIMEBody:  mime,
		},
	}
}

// findLiteralBody locates the FETCH response header packet and returns the
// concatenation of all literal-body segments that follow it (before the
// trailing CRLF). Returns the N value from {N} and the body bytes.
func findLiteralBody(t *testing.T, cfgs []core.PacketConfig) (n int, body []byte) {
	t.Helper()
	for i, c := range cfgs {
		pl := string(c.Payload)
		if c.Direction == "down" && strings.Contains(pl, "FETCH") && strings.Contains(pl, "{") && strings.Contains(pl, "}") {
			// Extract N from {N}
			s := pl
			start := strings.Index(s, "{")
			end := strings.Index(s[start:], "}")
			if start < 0 || end < 0 {
				t.Fatalf("cannot parse {N} from payload %q", pl)
			}
			nStr := s[start+1 : start+end]
			n = 0
			for _, ch := range nStr {
				n = n*10 + int(ch-'0')
			}
			// Collect literal body segments: all subsequent down packets
			// until we hit the trailing CRLF ("\r\n") or a tagged response.
			for j := i + 1; j < len(cfgs); j++ {
				p := string(cfgs[j].Payload)
				if p == "\r\n" {
					break // trailing CRLF closes the FETCH response
				}
				if strings.HasPrefix(p, "A001 OK") {
					break // tagged completion
				}
				body = append(body, cfgs[j].Payload...)
			}
			return n, body
		}
	}
	t.Fatalf("no FETCH response header with {N} found in configs")
	return 0, nil
}

// --- Test 1: Multipart with text + one additional part ---

func TestIMAPMIME_MultipartBasic(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	spec.IMAP.Commands = fetchMIMECommands(&core.IMAPMIMEBody{
		Headers:  []string{"From: alice@example.com", "To: bob@example.com", "Subject: Multipart test"},
		Boundary: "TESTBOUNDARY",
		Text:     "Hello, this is the plain text body.",
		Parts: []core.IMAPMIMEPart{
			{ContentType: "text/html; charset=utf-8", Body: "<html><body><p>HTML part</p></body></html>"},
		},
	})
	cfgs := drain(mustPlan(t, p, spec))
	n, body := findLiteralBody(t, cfgs)
	bodyStr := string(body)

	// RFC 2045 §4: MIME-Version header required.
	if !strings.Contains(bodyStr, "MIME-Version: 1.0") {
		t.Errorf("multipart body must contain 'MIME-Version: 1.0', got: %q", bodyStr)
	}
	// RFC 2046 §5.1: Content-Type: multipart/mixed with boundary.
	if !strings.Contains(bodyStr, "multipart/mixed") {
		t.Errorf("body must contain 'multipart/mixed', got: %q", bodyStr)
	}
	if !strings.Contains(bodyStr, `boundary="TESTBOUNDARY"`) {
		t.Errorf("body must contain boundary declaration, got: %q", bodyStr)
	}
	// Top-level headers preserved.
	if !strings.Contains(bodyStr, "From: alice@example.com") {
		t.Errorf("body must preserve From header, got: %q", bodyStr)
	}
	// RFC 2046 §5.1.1: first delimiter "--TESTBOUNDARY".
	if !strings.Contains(bodyStr, "--TESTBOUNDARY\r\n") {
		t.Errorf("body must contain first delimiter '--TESTBOUNDARY', got: %q", bodyStr)
	}
	// Text part present.
	if !strings.Contains(bodyStr, "Hello, this is the plain text body.") {
		t.Errorf("body must contain text part, got: %q", bodyStr)
	}
	// HTML part present.
	if !strings.Contains(bodyStr, "text/html") {
		t.Errorf("body must contain HTML part Content-Type, got: %q", bodyStr)
	}
	if !strings.Contains(bodyStr, "<html>") {
		t.Errorf("body must contain HTML part body, got: %q", bodyStr)
	}
	// RFC 2046 §5.1.1: close delimiter "--TESTBOUNDARY--".
	if !strings.Contains(bodyStr, "--TESTBOUNDARY--\r\n") {
		t.Errorf("body must contain close delimiter '--TESTBOUNDARY--', got: %q", bodyStr)
	}
	// RFC 9051 §6.4.6: {N} must equal the actual byte count.
	if n != len(body) {
		t.Errorf("{N}=%d does not match actual literal body length %d", n, len(body))
	}
}

// --- Test 2: Multipart with attachment (base64 + Content-Disposition) ---

func TestIMAPMIME_MultipartWithAttachment(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	attData := []byte("This is binary attachment data!")
	spec.IMAP.Commands = fetchMIMECommands(&core.IMAPMIMEBody{
		Headers:  []string{"From: alice@example.com", "Subject: With attachment"},
		Boundary: "ATTBOUND",
		Text:     "See attached file.",
		Attachments: []core.IMAPAttachment{
			{Filename: "test.bin", ContentType: "application/octet-stream", Data: attData},
		},
	})
	cfgs := drain(mustPlan(t, p, spec))
	n, body := findLiteralBody(t, cfgs)
	bodyStr := string(body)

	// RFC 2045 §6.8: base64 encoding for binary attachment.
	if !strings.Contains(bodyStr, "Content-Transfer-Encoding: base64") {
		t.Errorf("attachment must have base64 transfer encoding, got: %q", bodyStr)
	}
	// RFC 2183: Content-Disposition: attachment; filename="...".
	if !strings.Contains(bodyStr, `Content-Disposition: attachment; filename="test.bin"`) {
		t.Errorf("attachment must have Content-Disposition, got: %q", bodyStr)
	}
	// The base64-encoded data must be present.
	expectedB64 := base64.StdEncoding.EncodeToString(attData)
	if !strings.Contains(bodyStr, expectedB64) {
		t.Errorf("attachment body must contain base64 data %q, got: %q", expectedB64, bodyStr)
	}
	// Close delimiter present.
	if !strings.Contains(bodyStr, "--ATTBOUND--\r\n") {
		t.Errorf("body must contain close delimiter, got: %q", bodyStr)
	}
	// {N} accuracy.
	if n != len(body) {
		t.Errorf("{N}=%d does not match actual body length %d", n, len(body))
	}
}

// --- Test 3: Simple (non-multipart) text message ---

func TestIMAPMIME_SimpleTextMessage(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	spec.IMAP.Commands = fetchMIMECommands(&core.IMAPMIMEBody{
		Headers: []string{"From: alice@example.com", "Subject: Simple"},
		Text:    "Just a plain text email.",
	})
	cfgs := drain(mustPlan(t, p, spec))
	n, body := findLiteralBody(t, cfgs)
	bodyStr := string(body)

	// Simple message must NOT be multipart.
	if strings.Contains(bodyStr, "multipart") {
		t.Errorf("simple message must not contain 'multipart', got: %q", bodyStr)
	}
	if strings.Contains(bodyStr, "--") && strings.Contains(bodyStr, "boundary") {
		t.Errorf("simple message must not have boundary delimiters, got: %q", bodyStr)
	}
	// Headers present.
	if !strings.Contains(bodyStr, "From: alice@example.com") {
		t.Errorf("body must contain From header, got: %q", bodyStr)
	}
	// Body text present.
	if !strings.Contains(bodyStr, "Just a plain text email.") {
		t.Errorf("body must contain text, got: %q", bodyStr)
	}
	// {N} accuracy.
	if n != len(body) {
		t.Errorf("{N}=%d does not match actual body length %d", n, len(body))
	}
}

// --- Test 4: Boundary auto-generated (consistent across delimiters) ---

func TestIMAPMIME_BoundaryAutoGenerated(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	spec.IMAP.Commands = fetchMIMECommands(&core.IMAPMIMEBody{
		Text: "Body text",
		Parts: []core.IMAPMIMEPart{
			{Body: "Second part"},
		},
		// Boundary intentionally empty — planner must auto-generate.
	})
	cfgs := drain(mustPlan(t, p, spec))
	_, body := findLiteralBody(t, cfgs)
	bodyStr := string(body)

	// Find the boundary from the Content-Type header.
	ctIdx := strings.Index(bodyStr, `boundary="`)
	if ctIdx < 0 {
		t.Fatalf("body must contain auto-generated boundary declaration, got: %q", bodyStr)
	}
	ctEnd := strings.Index(bodyStr[ctIdx+len(`boundary="`):], `"`)
	if ctEnd < 0 {
		t.Fatalf("cannot find closing quote for boundary, got: %q", bodyStr)
	}
	boundary := bodyStr[ctIdx+len(`boundary="`) : ctIdx+len(`boundary="`)+ctEnd]
	if boundary == "" {
		t.Errorf("auto-generated boundary must be non-empty")
	}
	// The boundary must appear as a delimiter ("--<boundary>") at least twice
	// (first delimiter + close delimiter).
	firstDelim := "--" + boundary + "\r\n"
	closeDelim := "--" + boundary + "--\r\n"
	countDelim := strings.Count(bodyStr, firstDelim)
	if countDelim < 2 {
		t.Errorf("boundary %q must appear as delimiter at least 2 times (first + parts), got %d", boundary, countDelim)
	}
	if !strings.Contains(bodyStr, closeDelim) {
		t.Errorf("body must contain close delimiter %q, got: %q", closeDelim, bodyStr)
	}
}

// --- Test 5: Boundary override (user-provided used verbatim) ---

func TestIMAPMIME_BoundaryOverride(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	spec.IMAP.Commands = fetchMIMECommands(&core.IMAPMIMEBody{
		Boundary: "MyCustomBoundary123",
		Text:     "Body",
		Parts:    []core.IMAPMIMEPart{{Body: "Part 2"}},
	})
	cfgs := drain(mustPlan(t, p, spec))
	_, body := findLiteralBody(t, cfgs)
	bodyStr := string(body)

	if !strings.Contains(bodyStr, `boundary="MyCustomBoundary123"`) {
		t.Errorf("body must use user-provided boundary, got: %q", bodyStr)
	}
	if !strings.Contains(bodyStr, "--MyCustomBoundary123\r\n") {
		t.Errorf("body must contain delimiter with user boundary, got: %q", bodyStr)
	}
	if !strings.Contains(bodyStr, "--MyCustomBoundary123--\r\n") {
		t.Errorf("body must contain close delimiter with user boundary, got: %q", bodyStr)
	}
}

// --- Test 6: Large MIME body triggers MSS segmentation ---

func TestIMAPMIME_LargeBodyMSSSegmentation(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	testutil.EnsureTCP(&spec).MSS = 536
	// Build a MIME body larger than 536 bytes: text + large HTML part.
	largeHTML := strings.Repeat("<p>Hello</p>", 100) // ~1200 bytes
	spec.IMAP.Commands = fetchMIMECommands(&core.IMAPMIMEBody{
		Boundary: "LARGEBOUND",
		Text:     "Plain text body.",
		Parts: []core.IMAPMIMEPart{
			{ContentType: "text/html; charset=utf-8", Body: largeHTML},
		},
	})
	cfgs := drain(mustPlan(t, p, spec))
	_, body := findLiteralBody(t, cfgs)
	if len(body) <= 536 {
		t.Fatalf("MIME body should exceed MSS (536), got %d bytes", len(body))
	}
	// The literal body must span multiple PSH-ACK segments.
	// Count down-direction PSH-ACK packets between the FETCH header and the
	// trailing CRLF.
	segCount := 0
	inLiteral := false
	for _, c := range cfgs {
		pl := string(c.Payload)
		if c.Direction == "down" && strings.Contains(pl, "FETCH") && strings.Contains(pl, "{") {
			inLiteral = true
			continue
		}
		if inLiteral {
			if pl == "\r\n" {
				break
			}
			if strings.HasPrefix(pl, "A001 OK") {
				break
			}
			segCount++
		}
	}
	if segCount < 2 {
		t.Errorf("large MIME body (%d bytes) should span multiple PSH-ACK segments, got %d", len(body), segCount)
	}
	// All literal segments must be PSH-ACK (flags=0x18) per C-IMAP-1.1.
	inLiteral = false
	for _, c := range cfgs {
		pl := string(c.Payload)
		if c.Direction == "down" && strings.Contains(pl, "FETCH") && strings.Contains(pl, "{") {
			inLiteral = true
			continue
		}
		if inLiteral {
			if pl == "\r\n" || strings.HasPrefix(pl, "A001 OK") {
				break
			}
			if c.L4.Flags != 0x18 {
				t.Errorf("literal segment must be PSH-ACK (0x18), got 0x%x", c.L4.Flags)
			}
		}
	}
}

// --- Test 7: Multi-session multi-mailbox ---

func TestIMAPMIME_MultiSessionMultiMailbox(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	mime1 := &core.IMAPMIMEBody{Headers: []string{"Subject: INBOX mail"}, Text: "INBOX message", Boundary: "B1", Parts: []core.IMAPMIMEPart{{Body: "Part 1"}}}
	mime2 := &core.IMAPMIMEBody{Headers: []string{"Subject: Sent mail"}, Text: "Sent message", Boundary: "B2", Parts: []core.IMAPMIMEPart{{Body: "Part 2"}}}
	spec.IMAP.Commands = []core.IMAPCommand{
		{Tag: "A001", Cmd: "LOGIN alice secret", Responses: []string{"A001 OK LOGIN completed"}},
		{Tag: "A002", Cmd: "SELECT INBOX", Responses: []string{"* 1 EXISTS", "A002 OK SELECT completed"}},
		{Tag: "A003", Cmd: "FETCH 1 BODY[]", Responses: []string{"* 1 FETCH (BODY[] {0})", "A003 OK FETCH completed"}, MIMEBody: mime1},
		{Tag: "A004", Cmd: "COPY 1 Sent", Responses: []string{"A004 OK COPY completed"}},
		{Tag: "A005", Cmd: "SELECT Sent", Responses: []string{"* 1 EXISTS", "A005 OK SELECT completed"}},
		{Tag: "A006", Cmd: "FETCH 1 BODY[]", Responses: []string{"* 1 FETCH (BODY[] {0})", "A006 OK FETCH completed"}, MIMEBody: mime2},
		{Tag: "A007", Cmd: "LOGOUT", Responses: []string{"* BYE", "A007 OK LOGOUT completed"}},
	}
	cfgs := drain(mustPlan(t, p, spec))

	// Collect all up-direction command payloads.
	upCmds := []string{}
	for _, c := range cfgs {
		if c.Direction == "up" && c.L4.Flags == 0x18 && len(c.Payload) > 0 {
			upCmds = append(upCmds, string(c.Payload))
		}
	}
	// Verify the multi-mailbox sequence is present.
	upJoined := strings.Join(upCmds, "")
	expectedCmds := []string{
		"LOGIN alice secret",
		"SELECT INBOX",
		"FETCH 1 BODY[]",
		"COPY 1 Sent",
		"SELECT Sent",
		"FETCH 1 BODY[]",
		"LOGOUT",
	}
	for _, cmd := range expectedCmds {
		if !strings.Contains(upJoined, cmd) {
			t.Errorf("multi-session missing command %q in up payloads", cmd)
		}
	}
	// Verify both FETCH responses are present (A003 and A006).
	downJoined := ""
	for _, c := range cfgs {
		if c.Direction == "down" {
			downJoined += string(c.Payload)
		}
	}
	if !strings.Contains(downJoined, "A003 OK FETCH completed") {
		t.Errorf("missing A003 OK FETCH completion (first mailbox)")
	}
	if !strings.Contains(downJoined, "A006 OK FETCH completed") {
		t.Errorf("missing A006 OK FETCH completion (second mailbox)")
	}
	// Verify both MIME bodies are present (INBOX message + Sent message).
	if !strings.Contains(downJoined, "INBOX message") {
		t.Errorf("missing first FETCH literal body (INBOX message)")
	}
	if !strings.Contains(downJoined, "Sent message") {
		t.Errorf("missing second FETCH literal body (Sent message)")
	}
	// Verify both boundaries are present (proves two distinct multipart bodies).
	if !strings.Contains(downJoined, "boundary=\"B1\"") {
		t.Errorf("missing first MIME boundary B1")
	}
	if !strings.Contains(downJoined, "boundary=\"B2\"") {
		t.Errorf("missing second MIME boundary B2")
	}
}

// --- Test 8: Backward compat — LiteralBody still works ---

func TestIMAPMIME_BackwardCompat_LiteralBodyStillWorks(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	spec.IMAP.Commands = []core.IMAPCommand{
		{
			Tag:         "A001",
			Cmd:         "FETCH 1 BODY[]",
			Responses:   []string{"* 1 FETCH (BODY[] {13})", "A001 OK FETCH completed"},
			LiteralBody: "Hello, world!",
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	n, body := findLiteralBody(t, cfgs)
	if n != 13 {
		t.Errorf("{N}=%d, want 13", n)
	}
	if string(body) != "Hello, world!" {
		t.Errorf("literal body=%q, want 'Hello, world!'", string(body))
	}
}

// --- Test 9: Validate — MIMEBody mutually exclusive with LiteralBody ---

func TestIMAPValidate_MIMEBodyAndLiteralBodyMutex(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	spec.IMAP.Commands = []core.IMAPCommand{
		{
			Tag:         "A001",
			Cmd:         "FETCH 1 BODY[]",
			LiteralBody: "raw bytes",
			MIMEBody:    &core.IMAPMIMEBody{Text: "mime body"},
		},
	}
	err := p.Validate(spec)
	if err == nil {
		t.Errorf("Validate should reject MIMEBody + LiteralBody (mutually exclusive)")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("error should mention 'mutually exclusive', got: %v", err)
	}
}

func TestIMAPValidate_MIMEBodyAndLiteralBodyB64Mutex(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	spec.IMAP.Commands = []core.IMAPCommand{
		{
			Tag:            "A001",
			Cmd:            "FETCH 1 BODY[]",
			LiteralBodyB64: base64.StdEncoding.EncodeToString([]byte("raw")),
			MIMEBody:       &core.IMAPMIMEBody{Text: "mime body"},
		},
	}
	err := p.Validate(spec)
	if err == nil {
		t.Errorf("Validate should reject MIMEBody + LiteralBodyB64 (mutually exclusive)")
	}
}

// --- Test 10: {N} matches constructed byte length exactly ---

func TestIMAPMIME_LiteralLengthMatchesExactly(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	spec.IMAP.Commands = fetchMIMECommands(&core.IMAPMIMEBody{
		Headers:  []string{"From: a@b.com", "Subject: Exact length"},
		Boundary: "EXACTBOUND",
		Text:     "Some text content here.",
		Attachments: []core.IMAPAttachment{
			{Filename: "data.bin", Data: []byte("0123456789")},
		},
	})
	cfgs := drain(mustPlan(t, p, spec))
	n, body := findLiteralBody(t, cfgs)
	if n != len(body) {
		t.Errorf("RFC 9051 §6.4.6: {N}=%d must exactly equal literal body byte count %d", n, len(body))
	}
	// Also verify the FETCH response header contains the exact {N}.
	found := false
	for _, c := range cfgs {
		pl := string(c.Payload)
		if strings.Contains(pl, "FETCH") && strings.Contains(pl, "{") {
			expected := "{" + itoa(len(body)) + "}"
			if !strings.Contains(pl, expected) {
				t.Errorf("FETCH header must contain %q, got %q", expected, pl)
			}
			found = true
		}
	}
	if !found {
		t.Errorf("no FETCH response header found")
	}
}

// --- Test 11: MIMEBody usable for APPEND (client-side literal) ---

func TestIMAPMIME_AppendWithMIMEBody(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	spec.IMAP.Commands = []core.IMAPCommand{
		{
			Tag:      "A001",
			Cmd:      "APPEND INBOX (\\Seen) {0}",
			Responses: []string{"+ Ready", "A001 OK APPEND completed"},
			MIMEBody: &core.IMAPMIMEBody{
				Headers:  []string{"From: a@b.com", "Subject: Appended"},
				Boundary: "APPENDBOUND",
				Text:     "Appended message body.",
				Parts:    []core.IMAPMIMEPart{{Body: "Second part"}},
			},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// The APPEND command ends with {N} — the planner should emit the
	// command line (with {N} replaced by actual MIME byte count), then
	// the MIME body bytes as a client-side literal (up direction).
	upJoined := ""
	for _, c := range cfgs {
		if c.Direction == "up" && c.L4.Flags == 0x18 {
			upJoined += string(c.Payload)
		}
	}
	if !strings.Contains(upJoined, "APPEND INBOX") {
		t.Errorf("missing APPEND command, got: %q", upJoined)
	}
	// The MIME body should appear in the up direction (client -> server).
	if !strings.Contains(upJoined, "Appended message body.") {
		t.Errorf("missing MIME body in APPEND upload, got: %q", upJoined)
	}
	if !strings.Contains(upJoined, "multipart/mixed") {
		t.Errorf("APPEND MIME body should be multipart, got: %q", upJoined)
	}
}

// --- Test 12: Empty MIMEBody (no text, no parts, no attachments) ---

func TestIMAPMIME_EmptyMIMEBody(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	spec.IMAP.Commands = fetchMIMECommands(&core.IMAPMIMEBody{
		Headers: []string{"From: a@b.com", "Subject: Empty"},
	})
	cfgs := drain(mustPlan(t, p, spec))
	n, body := findLiteralBody(t, cfgs)
	// Should produce a valid (empty-body) message with just headers.
	if n != len(body) {
		t.Errorf("{N}=%d must match body length %d", n, len(body))
	}
	if !strings.Contains(string(body), "From: a@b.com") {
		t.Errorf("empty MIME body should still contain headers, got: %q", string(body))
	}
}
