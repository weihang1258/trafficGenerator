package smtp

// MIME email construction for the SMTP DATA phase. Implements RFC 5322
// (message format), RFC 2045 (MIME headers, base64), RFC 2046 §5.1.1
// (multipart/mixed), RFC 2046 §5.1.4 (multipart/alternative), and RFC
// 2183 (Content-Disposition: attachment).
//
// The planner calls buildSMTPEmailBody when SMTPConfig.Email is set,
// producing the full DATA payload (headers + body + dot-stuffing +
// "\r\n.\r\n" terminator). The payload is then segmented by MSS and
// emitted as PSH-ACK segments in the up direction, followed by an
// auto-emitted 250 response.

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/trafficgen/trafficgen/internal/core"
)

// smtpDefaultBoundary is the deterministic auto-generated boundary used
// when SMTPEmail.Boundary is empty and the email is multipart (RFC 2046
// §5.1.1: any valid chars, <= 70 chars). Fixed rather than random so
// test captures are reproducible.
const smtpDefaultBoundary = "----=_SMTP_BOUND_0001"

// smtpDefaultAltBoundary is the deterministic boundary for the nested
// multipart/alternative part when both TextBody and HTMLBody are set
// inside a multipart/mixed email.
const smtpDefaultAltBoundary = "----=_SMTP_ALT_0001"

// smtpDefault250Response is the auto-emitted server response after the
// injected email body, matching the defaultDialog body response.
const smtpDefault250Response = "250 2.0.0 Ok: queued as 1"

// buildSMTPEmailBody constructs the full DATA payload for an SMTPEmail,
// including the "\r\n.\r\n" terminator (RFC 5321 §4.1.1.4). Dot-stuffing
// (RFC 5321 §4.5.2) is applied to all body lines so lines beginning with
// "." get an extra "." prepended, preventing premature DATA termination.
//
// The structure depends on the Email fields:
//
//   - TextBody only, no attachments: simple non-MIME body (headers +
//     blank + text). Wire-compatible with non-MIME clients.
//   - HTMLBody only, no attachments: single text/html MIME part.
//   - Both TextBody and HTMLBody, no attachments: multipart/alternative.
//   - Any attachments: multipart/mixed; the first part is the text
//     body, HTML body, or a nested multipart/alternative, followed by
//     one part per attachment (base64-encoded).
func buildSMTPEmailBody(email *core.SMTPEmail) []byte {
	hasAttachments := len(email.Attachments) > 0
	hasText := email.TextBody != ""
	hasHTML := email.HTMLBody != ""
	// isMultipart = needs a boundary delimiter structure.
	isMultipart := hasAttachments || (hasText && hasHTML)
	// isMIME = needs MIME-Version header (any non-trivial-text body).
	isMIME := isMultipart || hasHTML

	var b strings.Builder

	// Top-level RFC 5322 headers (user-provided).
	for _, h := range email.Headers {
		b.WriteString(h)
		b.WriteString("\r\n")
	}

	// MIME headers when the email is multipart or HTML-only.
	if isMIME {
		b.WriteString("MIME-Version: 1.0\r\n")
		if isMultipart {
			b.WriteString(fmt.Sprintf("Content-Type: %s\r\n", topContentType(email, hasAttachments, hasText, hasHTML)))
		} else {
			// HTML-only: single text/html part (not multipart).
			b.WriteString("Content-Type: text/html; charset=UTF-8\r\n")
		}
	}

	// Blank line separating headers from body (RFC 5322 §3.6).
	b.WriteString("\r\n")

	// Body content (without terminator). Dot-stuffing is applied to the
	// assembled body text so it wraps the whole body uniformly. We must
	// preserve the trailing CRLF so the terminator "." starts on its
	// own line; dotStuffWithSuffix handles this.
	bodyText := buildEmailBodyText(email, hasAttachments, hasText, hasHTML)
	stuffed := dotStuff(bodyText)
	b.WriteString(stuffed)

	// Ensure the body ends with CRLF before the terminator so the
	// terminator "." starts on its own line (RFC 5321 §4.1.1.4 requires
	// "<CRLF>.<CRLF>"). If the body is empty, the blank line above
	// already provides the preceding CRLF.
	if !strings.HasSuffix(stuffed, "\r\n") && stuffed != "" {
		b.WriteString("\r\n")
	}

	// DATA terminator: ".\r\n" (the preceding CRLF comes from the body
	// or the blank line). Per RFC 5321 §4.1.1.4 the full terminator is
	// "<CRLF>.<CRLF>".
	b.WriteString(".\r\n")

	return []byte(b.String())
}

// topContentType returns the top-level Content-Type header value for a
// multipart email. When attachments are present it is multipart/mixed
// with the outer boundary; otherwise (text+html, no attachments) it is
// multipart/alternative with the (only) boundary.
func topContentType(email *core.SMTPEmail, hasAttachments, hasText, hasHTML bool) string {
	boundary := resolveSMTPBoundary(email.Boundary)
	if hasAttachments {
		return fmt.Sprintf(`multipart/mixed; boundary="%s"`, boundary)
	}
	// text+html, no attachments -> multipart/alternative.
	return fmt.Sprintf(`multipart/alternative; boundary="%s"`, boundary)
}

// buildEmailBodyText assembles the body content (after the header blank
// line, before the terminator) without dot-stuffing. The caller applies
// dot-stuffing and the terminator.
func buildEmailBodyText(email *core.SMTPEmail, hasAttachments, hasText, hasHTML bool) string {
	if !hasAttachments {
		// No attachments: either simple text, HTML-only, or
		// multipart/alternative (text+html).
		if hasText && hasHTML {
			return buildMultipartAlternative(email.TextBody, email.HTMLBody, resolveSMTPBoundary(email.Boundary))
		}
		if hasHTML {
			// HTML-only: the top-level Content-Type: text/html header
			// is already emitted by buildSMTPEmailBody, so the body is
			// just the raw HTML (no per-part header).
			return email.HTMLBody
		}
		// Text only: raw text, no MIME part wrapping (the top-level
		// Content-Type is omitted by buildSMTPEmailBody in this case).
		return email.TextBody
	}

	// Attachments present: multipart/mixed.
	outer := resolveSMTPBoundary(email.Boundary)
	var b strings.Builder

	// First part: text, html, or nested multipart/alternative.
	if hasText && hasHTML {
		// Nested multipart/alternative needs its own Content-Type header
		// (RFC 2046 §5.1.4) so the receiver knows the nested boundary.
		altBoundary := altBoundaryFor(outer)
		altBody := buildMultipartAlternativeWithBoundary(email.TextBody, email.HTMLBody, altBoundary)
		nestedPart := fmt.Sprintf("Content-Type: multipart/alternative; boundary=\"%s\"\r\n\r\n%s", altBoundary, altBody)
		writeMultipartPart(&b, outer, nestedPart)
	} else if hasText {
		writeMultipartPart(&b, outer, partBody("text/plain; charset=UTF-8", "", email.TextBody))
	} else if hasHTML {
		writeMultipartPart(&b, outer, partBody("text/html; charset=UTF-8", "", email.HTMLBody))
	}
	// If neither text nor html, the first part is skipped and the email
	// is just attachments (still valid multipart/mixed).

	// Attachment parts.
	for _, att := range email.Attachments {
		writeMultipartPart(&b, outer, buildAttachmentPart(att))
	}

	// Closing delimiter per RFC 2046 §5.1.1.
	b.WriteString("--")
	b.WriteString(outer)
	b.WriteString("--\r\n")

	return b.String()
}

// writeMultipartPart writes one part of a multipart body: opening
// delimiter, part content, ensuring the part ends with CRLF so the next
// delimiter starts on its own line.
func writeMultipartPart(b *strings.Builder, boundary, part string) {
	b.WriteString("--")
	b.WriteString(boundary)
	b.WriteString("\r\n")
	b.WriteString(part)
	if !strings.HasSuffix(part, "\r\n") {
		b.WriteString("\r\n")
	}
}

// partBody builds a simple (non-multipart) part: Content-Type header,
// optional extra headers, blank line, body. The body is emitted without
// a trailing CRLF; the caller (writeMultipartPart) adds it.
func partBody(contentType, extraHeaders, body string) string {
	var b strings.Builder
	b.WriteString("Content-Type: ")
	b.WriteString(contentType)
	b.WriteString("\r\n")
	if extraHeaders != "" {
		b.WriteString(extraHeaders)
	}
	b.WriteString("\r\n")
	b.WriteString(body)
	return b.String()
}

// buildMultipartAlternative builds a multipart/alternative body
// containing a text/plain part and a text/html part (RFC 2046 §5.1.4).
// Uses the provided boundary.
func buildMultipartAlternative(textBody, htmlBody, boundary string) string {
	return buildMultipartAlternativeWithBoundary(textBody, htmlBody, boundary)
}

// buildMultipartAlternativeWithBoundary is the boundary-parameterized
// implementation shared by the top-level alternative and the nested
// alternative inside multipart/mixed.
func buildMultipartAlternativeWithBoundary(textBody, htmlBody, boundary string) string {
	var b strings.Builder
	writeMultipartPart(&b, boundary, partBody("text/plain; charset=UTF-8", "", textBody))
	writeMultipartPart(&b, boundary, partBody("text/html; charset=UTF-8", "", htmlBody))
	b.WriteString("--")
	b.WriteString(boundary)
	b.WriteString("--\r\n")
	return b.String()
}

// buildAttachmentPart builds a single attachment part: Content-Type,
// Content-Transfer-Encoding: base64, Content-Disposition with filename,
// blank line, base64-encoded body (wrapped at 76 chars/line per RFC
// 2045 §6.8). When DataB64 is set, it is emitted verbatim (the planner
// does NOT decode+re-encode; the user is responsible for line wrapping).
func buildAttachmentPart(att core.SMTPAttachment) string {
	ct := att.ContentType
	if ct == "" {
		ct = "application/octet-stream"
	}
	var b strings.Builder
	b.WriteString("Content-Type: ")
	b.WriteString(ct)
	b.WriteString("\r\n")
	b.WriteString("Content-Transfer-Encoding: base64\r\n")
	b.WriteString(fmt.Sprintf("Content-Disposition: attachment; filename=\"%s\"\r\n", att.Filename))
	b.WriteString("\r\n")
	if att.DataB64 != "" {
		b.WriteString(att.DataB64)
	} else {
		b.WriteString(base64Wrap(att.Data))
	}
	return b.String()
}

// base64Wrap encodes data with standard base64 and wraps the output at
// 76 characters per line per RFC 2045 §6.8. Each line (except possibly
// the last) is exactly 76 chars, terminated by CRLF.
func base64Wrap(data []byte) string {
	encoded := base64.StdEncoding.EncodeToString(data)
	if len(encoded) <= 76 {
		return encoded
	}
	var b strings.Builder
	for i := 0; i < len(encoded); i += 76 {
		end := i + 76
		if end > len(encoded) {
			end = len(encoded)
		}
		b.WriteString(encoded[i:end])
		b.WriteString("\r\n")
	}
	return strings.TrimRight(b.String(), "\r\n")
}

// resolveSMTPBoundary returns the user-provided boundary when non-empty,
// or the deterministic default otherwise.
func resolveSMTPBoundary(boundary string) string {
	if boundary != "" {
		return boundary
	}
	return smtpDefaultBoundary
}

// altBoundaryFor derives the nested multipart/alternative boundary from
// the outer multipart/mixed boundary. Appending "_ALT" keeps it
// deterministic and avoids collisions with the outer boundary (RFC 2046
// §5.1.1 requires nested boundaries to differ).
func altBoundaryFor(outer string) string {
	if outer == "" {
		return smtpDefaultAltBoundary
	}
	return outer + "_ALT"
}

// dotStuff applies RFC 5321 §4.5.2 dot-stuffing: every line of content
// that begins with "." gets an extra "." prepended. Line endings are
// normalized to CRLF. The receiver de-stuffs on receive. This prevents
// a body line starting with "." from being interpreted as the DATA
// terminator.
//
// Trailing CRLF is preserved: if the input ends with "\r\n" the output
// also ends with "\r\n" (after stuffing the last line). This is critical
// for the caller to correctly place the DATA terminator "." on its own
// line.
func dotStuff(content string) string {
	if content == "" {
		return ""
	}
	// Detect whether the content ends with CRLF so we can restore it
	// after the split/join (strings.Split would drop the trailing empty
	// line otherwise).
	endsCRLF := strings.HasSuffix(content, "\r\n")
	// Split on "\n" to handle both "\n" and "\r\n" input. Trim trailing
	// "\r" so the rejoin with "\r\n" produces canonical CRLF.
	trimmed := strings.TrimRight(content, "\r\n")
	lines := strings.Split(trimmed, "\n")
	for i, line := range lines {
		line = strings.TrimRight(line, "\r")
		if strings.HasPrefix(line, ".") {
			line = "." + line
		}
		lines[i] = line
	}
	out := strings.Join(lines, "\r\n")
	if endsCRLF {
		out += "\r\n"
	}
	return out
}

// isDATACommand reports whether cmd is a DATA command (case-insensitive,
// trimmed). Used to locate the injection point for the email body.
func isDATACommand(cmd string) bool {
	return strings.EqualFold(strings.TrimSpace(cmd), "DATA")
}

// validateSMTPEmail validates an SMTPEmail spec per RFC 2046 §5.1.1
// (boundary rules) and RFC 2045 §6.8 (attachment data). Read-only: does
// not mutate email.
func validateSMTPEmail(email *core.SMTPEmail) error {
	if email == nil {
		return nil
	}
	// Boundary rules (RFC 2046 §5.1.1): max 70 chars, no CRLF (also
	// reject bare CR/LF to prevent header injection). Only enforced when
	// the email is actually multipart (attachments present, or both
	// text+html); a text-only email has no boundary.
	isMultipart := len(email.Attachments) > 0 ||
		(email.TextBody != "" && email.HTMLBody != "")
	if isMultipart && email.Boundary != "" {
		if len(email.Boundary) > 70 {
			return fmt.Errorf("smtp: Email.Boundary length %d exceeds max 70 chars (RFC 2046 §5.1.1 boundary)", len(email.Boundary))
		}
		if strings.ContainsAny(email.Boundary, "\r\n") {
			return fmt.Errorf("smtp: Email.Boundary %q contains CRLF (RFC 2046 §5.1.1 boundary + injection protection)", email.Boundary)
		}
	}
	// Attachment data: each must have Data or DataB64 (RFC 2045 §6.8).
	for i, att := range email.Attachments {
		if len(att.Data) == 0 && att.DataB64 == "" {
			return fmt.Errorf("smtp: Email.Attachments[%d] has neither Data nor DataB64 (RFC 2045 §6.8)", i)
		}
	}
	return nil
}
