// Package megaco builder: assembles Megaco/H.248 v1 text-encoded wire bytes
// per RFC 3525 Annex B. Long and abbrev token forms both supported. TCP
// carrier adds an RFC 1006 TPKT 4B header per Annex D.2.
package megaco

import (
	"fmt"
	"strings"

	"github.com/trafficgen/trafficgen/internal/core"
)

// longTokens maps abbrev → long form for the wire encoder.
var longTokens = map[string]string{
	"MEGACO/": "MEGACO/",
	"!/":      "MEGACO/",
	"Transaction": "Transaction",
	"T":          "Transaction",
	"Reply":      "Reply",
	"P":          "Reply",
	"Pending":    "Pending",
	"PN":         "Pending",
	"ResponseAck": "TransactionResponseAck",
	"K":           "TransactionResponseAck",
	"Context":    "Context",
	"C":          "Context",
	"Add":      "Add",
	"A":        "Add",
	"Modify":   "Modify",
	"MF":       "Modify",
	"Subtract": "Subtract",
	"S":        "Subtract",
	"Move":     "Move",
	"MV":       "Move",
	"AuditValue":      "AuditValue",
	"AV":              "AuditValue",
	"AuditCapability": "AuditCapability",
	"AC":              "AuditCapability",
	"Notify":          "Notify",
	"N":               "Notify",
	"ServiceChange":   "ServiceChange",
	"SC":              "ServiceChange",
	"Media":            "Media",
	"M":                "Media",
	"Stream":           "Stream",
	"ST":               "Stream",
	"LocalControl":     "LocalControl",
	"O":                "LocalControl",
	"Local":            "Local",
	"L":                "Local",
	"Remote":           "Remote",
	"R":                "Remote",
	"TerminationState": "TerminationState",
	"TS":               "TerminationState",
	"Events":            "Events",
	"E":                 "Events",
	"EventBuffer":       "EventBuffer",
	"EB":                "EventBuffer",
	"Signals":           "Signals",
	"SG":                "Signals",
	"DigitMap":          "DigitMap",
	"DM":                "DigitMap",
	"ObservedEvents":    "ObservedEvents",
	"OE":                "ObservedEvents",
	"Statistics":        "Statistics",
	"SA":                "Statistics",
	"Packages":          "Packages",
	"PG":                "Packages",
	"Audit":             "Audit",
	"AT":                "Audit",
	"Services":          "Services",
	"SV":                "Services",
	"Error":             "Error",
	"ER":                "Error",
}

// tokenToWire renders a command/descriptor name in the configured form
// (long or abbrev). Falls back to the input unchanged if the abbrev table
// doesn't carry it (e.g. custom pkgdnames pass through).
func tokenToWire(tok, form string) string {
	if form == "abbrev" {
		// Reverse: long → abbrev. Build lazily on first call.
		if ab, ok := reverseTokens[tok]; ok {
			return ab
		}
		return tok
	}
	// long or default.
	if long, ok := longTokens[tok]; ok {
		// If user already passed a long-form, return as-is. Abbrev falls
		// back to long by the table above.
		return long
	}
	return tok
}

// reverseTokens is built once from longTokens for abbrev lookups.
var reverseTokens = map[string]string{}

func init() {
	seen := map[string]bool{}
	// longTokens maps abbrev→long. We want long→abbrev. Walk known abbrev
	// forms; for each, the value is the long form.
	for ab, long := range longTokens {
		if !seen[long] && ab != long {
			reverseTokens[long] = ab
			seen[long] = true
		}
	}
}

// buildStartLine emits the megaco start line:
// "MEGACO/<version> <mId> "  (with trailing space before messageBody).
func buildStartLine(version int, mid, form string) string {
	v := version
	if v == 0 {
		v = 1
	}
	verStr := fmt.Sprintf("%d", v)
	pre := "MEGACO/"
	if form == "abbrev" {
		pre = "!/"
	}
	return pre + verStr + " " + mid + " "
}

// pre is kept stable for MEGACO/! distinction; verStr/abbrev output uses
// the same single-digit convention. The "  " double-space seen in some
// outputs comes from the trailing space the start line + the form-specific
// " " followed by the transaction list's "Transaction" — the start line
// itself emits one space after the version digit.

// buildServicesBlock renders the Services { ... } block. Per RFC 3525 §7.1.13
// Method/Reason are required in requests; replies may carry only
// Profile/Version — empty fields are omitted rather than emitted as "Method=".
func buildServicesBlock(s *core.MegacoServices, form string) string {
	if s == nil {
		return ""
	}
	var parts []string
	if s.Method != "" {
		parts = append(parts, "Method="+s.Method)
	}
	if s.Reason != "" {
		parts = append(parts, "Reason=\""+s.Reason+"\"")
	}
	if s.Delay != nil {
		parts = append(parts, fmt.Sprintf("Delay=%d", *s.Delay))
	}
	if s.ServiceChangeAddress != "" {
		parts = append(parts, "ServiceChangeAddress="+s.ServiceChangeAddress)
	}
	if s.MgcIDToTry != "" {
		parts = append(parts, "MgcIdToTry="+s.MgcIDToTry)
	}
	if s.ServiceChangeMgcID != "" {
		parts = append(parts, "ServiceChangeMgcId="+s.ServiceChangeMgcID)
	}
	if s.Profile != "" {
		parts = append(parts, "Profile="+s.Profile)
	}
	if s.Version != nil {
		parts = append(parts, fmt.Sprintf("Version=%d", *s.Version))
	}
	if s.Timestamp != "" {
		parts = append(parts, "TimeStamp="+s.Timestamp)
	}
	return tokenToWire("Services", form) + " { " + strings.Join(parts, ", ") + " }"
}

// buildMediaBlock renders the Media { Stream = <id> { ... } } block.
func buildMediaBlock(m *core.MegacoMedia, form string) string {
	if m == nil {
		return ""
	}
	var parts []string
	for _, s := range m.Streams {
		var inner []string
		if s.LocalControl != nil {
			lc := s.LocalControl
			var lcParts []string
			if lc.Mode != "" {
				lcParts = append(lcParts, "Mode="+lc.Mode)
			}
			if lc.ReservedValue != "" {
				lcParts = append(lcParts, "RV="+lc.ReservedValue)
			}
			if lc.ReservedGroup != "" {
				lcParts = append(lcParts, "RG="+lc.ReservedGroup)
			}
			lcParts = append(lcParts, lc.Properties...)
			inner = append(inner, "LocalControl { "+strings.Join(lcParts, ", ")+" }")
		}
		if s.LocalSDP != "" {
			inner = append(inner, "Local { "+s.LocalSDP+" }")
		}
		if s.RemoteSDP != "" {
			inner = append(inner, "Remote { "+s.RemoteSDP+" }")
		}
		parts = append(parts, fmt.Sprintf("%s = %d { %s }", tokenToWire("Stream", form), s.ID, strings.Join(inner, ", ")))
	}
	if m.TerminationState != nil {
		ts := m.TerminationState
		var tsParts []string
		if ts.ServiceStates != "" {
			tsParts = append(tsParts, "ServiceStates="+ts.ServiceStates)
		}
		if ts.EventBufferControl != "" {
			tsParts = append(tsParts, "EventBufferControl="+ts.EventBufferControl)
		}
		tsParts = append(tsParts, ts.Properties...)
		parts = append(parts, "TerminationState { "+strings.Join(tsParts, ", ")+" }")
	}
	return "Media { " + strings.Join(parts, ", ") + " }"
}

// buildEventsBlock renders Events [=RequestID] { ... }.
func buildEventsBlock(e *core.MegacoEvents, form string) string {
	if e == nil {
		return ""
	}
	prefix := "Events"
	if e.RequestID != 0 {
		prefix = fmt.Sprintf("Events=%d", e.RequestID)
	}
	return prefix + " { " + strings.Join(e.Items, ", ") + " }"
}

// buildDigitMapBlock renders the DigitMap descriptor body.
func buildDigitMapBlock(d *core.MegacoDigitMap, form string) string {
	if d == nil {
		return ""
	}
	pre := fmt.Sprintf("DigitMap = %s { ", d.Name)
	var parts []string
	if d.T != nil {
		parts = append(parts, fmt.Sprintf("T:%d", *d.T))
	}
	if d.S != nil {
		parts = append(parts, fmt.Sprintf("S:%d", *d.S))
	}
	if d.L != nil {
		parts = append(parts, fmt.Sprintf("L:%d", *d.L))
	}
	if d.Value != "" {
		parts = append(parts, d.Value)
	}
	return pre + strings.Join(parts, ", ") + " }"
}

// buildSignalsBlock renders the Signals descriptor.
func buildSignalsBlock(s *core.MegacoSignals, form string) string {
	if s == nil {
		return ""
	}
	pre := "Signals { "
	post := " }"
	var parts []string
	parts = append(parts, s.Items...)
	for _, sl := range s.SignalList {
		parts = append(parts, fmt.Sprintf("SignalList=%d { %s }", sl.ID, strings.Join(sl.Items, ", ")))
	}
	return pre + strings.Join(parts, ", ") + post
}

// buildObservedEventsBlock renders the ObservedEvents descriptor.
func buildObservedEventsBlock(oe *core.MegacoObservedEvents, form string) string {
	if oe == nil {
		return ""
	}
	return fmt.Sprintf("ObservedEvents=%d { %s }", oe.RequestID, strings.Join(oe.Items, ", "))
}

// buildAuditBlock renders the Audit descriptor.
func buildAuditBlock(a *core.MegacoAudit, form string) string {
	if a == nil {
		return ""
	}
	return "Audit { " + strings.Join(a.Items, ", ") + " }"
}

// buildEventBufferBlock renders the EventBuffer descriptor.
func buildEventBufferBlock(eb *core.MegacoEventBuffer, form string) string {
	if eb == nil {
		return ""
	}
	return "EventBuffer { " + strings.Join(eb.Items, ", ") + " }"
}

// buildErrorBlock renders the errorDescriptor.
func buildErrorBlock(e *core.MegacoError, form string) string {
	if e == nil {
		return ""
	}
	return fmt.Sprintf("%s = %d { \"%s\" }", tokenToWire("Error", form), e.Code, e.Text)
}

// buildDescriptor renders a full descriptor block. Multiple sub-blocks join
// with ", ". Descriptor order: Services/Media/Events/etc. as configured.
func buildDescriptor(d *core.MegacoDescriptor, form string) string {
	if d == nil {
		return ""
	}
	var parts []string
	if d.Services != nil {
		parts = append(parts, buildServicesBlock(d.Services, form))
	}
	if d.Media != nil {
		parts = append(parts, buildMediaBlock(d.Media, form))
	}
	if d.Events != nil {
		parts = append(parts, buildEventsBlock(d.Events, form))
	}
	if d.EventBuffer != nil {
		parts = append(parts, buildEventBufferBlock(d.EventBuffer, form))
	}
	if d.Embed != nil {
		// Embed is rendered as a nested Events inside the parent.
		parts = append(parts, "Embed { "+buildEventsBlock(d.Embed, form)+" }")
	}
	if d.Signals != nil {
		parts = append(parts, buildSignalsBlock(d.Signals, form))
	}
	if d.DigitMap != nil {
		parts = append(parts, buildDigitMapBlock(d.DigitMap, form))
	}
	if d.ObservedEvents != nil {
		parts = append(parts, buildObservedEventsBlock(d.ObservedEvents, form))
	}
	if len(d.Statistics) > 0 {
		parts = append(parts, "Statistics { "+strings.Join(d.Statistics, ", ")+" }")
	}
	if len(d.Packages) > 0 {
		parts = append(parts, "Packages { "+strings.Join(d.Packages, ", ")+" }")
	}
	if d.Audit != nil {
		parts = append(parts, buildAuditBlock(d.Audit, form))
	}
	if d.Error != nil {
		parts = append(parts, buildErrorBlock(d.Error, form))
	}
	return "{ " + strings.Join(parts, ", ") + " }"
}

// buildCommand renders one command line, e.g.:
//   "ServiceChange = ROOT { Services { ... } }"
// or with optional/wildcard prefixes:
//   "O-AuditValue = * { ... }"
func buildCommand(cmd core.MegacoCommand, form string) string {
	var pre string
	if cmd.Optional {
		pre += "O-"
	}
	if cmd.WildcardResponse {
		pre += "W-"
	}
	pre += tokenToWire(cmd.Name, form)
	tw := cmd.Termination
	if tw == "" {
		tw = "ROOT"
	}
	body := pre + " = " + tw
	if cmd.Descriptor != nil {
		body += " " + buildDescriptor(cmd.Descriptor, form)
	}
	return body
}

// buildAction renders one action: "Context = <ctx> { cmd1, cmd2, ... }".
func buildAction(act core.MegacoAction, form string) string {
	ctx := act.Context
	if ctx == "" {
		ctx = "-"
	}
	var parts []string
	for _, c := range act.Commands {
		parts = append(parts, buildCommand(c, form))
	}
	return fmt.Sprintf("%s = %s { %s }", tokenToWire("Context", form), ctx, strings.Join(parts, ", "))
}

// buildTransaction renders one transaction. Returns its text body starting
// with the token ("Transaction" / "Reply" / "Pending" / "ResponseAck") and
// ending with the closing "}". For response_ack, only the ack coverage is
// emitted.
func buildTransaction(tx core.MegacoTransaction, form string) string {
	switch tx.Type {
	case "pending":
		return fmt.Sprintf("%s = %s { }", tokenToWire("Pending", form), tx.ID)
	case "response_ack":
		return fmt.Sprintf("%s { %s }", tokenToWire("ResponseAck", form), tx.Ack)
	case "reply":
		var pre string
		if tx.ImmAckRequired {
			pre = "IA, "
		}
		// Transaction-level errorDescriptor (RFC 3525 §8.2.3):
		// actionReplyList / errorDescriptor are mutually exclusive — a
		// reply carrying Error renders only the errorDescriptor.
		if tx.Error != nil {
			return fmt.Sprintf("%s = %s { %s%s }", tokenToWire("Reply", form), tx.ID, pre, buildErrorBlock(tx.Error, form))
		}
		var parts []string
		for _, act := range tx.Actions {
			parts = append(parts, buildAction(act, form))
		}
		return fmt.Sprintf("%s = %s { %s%s }", tokenToWire("Reply", form), tx.ID, pre, strings.Join(parts, ", "))
	default: // request
		var parts []string
		for _, act := range tx.Actions {
			parts = append(parts, buildAction(act, form))
		}
		return fmt.Sprintf("%s = %s { %s }", tokenToWire("Transaction", form), tx.ID, strings.Join(parts, ", "))
	}
}

// BuildMessageText assembles a complete Megaco text-encoded message body
// (without the TCP/UDP carrier header). Includes the start line, the
// transaction list (newline-separated), and the trailing CRLF. Whitespace
// variants (RFC 3525 Annex B.2 LWSP/EOL/COMMENT, testcase #23): "cr" uses
// CR-only EOLs; "comment" inserts a standalone "; ..." comment line between
// the start line and the transaction list; "lwsp" pads the start-line SEP
// with a second space.
func BuildMessageText(cfg *core.MegacoConfig, version int, mid string, transactions []core.MegacoTransaction, form string) string {
	if form == "" {
		if cfg.TokenForm != "" {
			form = cfg.TokenForm
		} else {
			form = "long"
		}
	}
	v := version
	if v == 0 && cfg.Version != 0 {
		v = cfg.Version
	}
	if v == 0 {
		v = 1
	}
	start := buildStartLine(v, mid, form)
	eol := "\n"
	sep := ""
	switch cfg.Whitespace {
	case "cr":
		eol = "\r"
	case "comment":
		sep = "\n; trafficgen fixture\n"
	case "lwsp":
		sep = " "
	}
	var txs []string
	for _, tx := range transactions {
		txs = append(txs, buildTransaction(tx, form))
	}
	return start + sep + strings.Join(txs, eol) + eol
}

// WrapTPKT prepends the 4-byte RFC 1006 TPKT header (version 0x03, reserved
// 0x00, total length = 4 + body) used by TCP carrier (RFC 3525 Annex D.2).
func WrapTPKT(body []byte) []byte {
	plen := uint16(len(body) + 4)
	return append([]byte{0x03, 0x00, byte(plen >> 8), byte(plen)}, body...)
}
