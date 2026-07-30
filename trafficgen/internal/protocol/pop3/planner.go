// Package pop3 implements the POP3 (Post Office Protocol version 3,
// 邮局协议第三版) protocol planner per RFC 1939.
//
// POP3 is a session-level protocol: a single TCP connection on port 110
// (the well-known POP3 port) carries a sequence of command/response pairs
// across three states (AUTHORIZATION / TRANSACTION / UPDATE). The planner
// emits:
//
//  1. TCP 3-way handshake (SYN, SYN-ACK, ACK) with MSS/WinScale/SACK
//     options, mirroring the FTP/HTTP/SIP control-channel pattern.
//  2. Optional server banner (e.g. "+OK POP3 server ready <timestamp@domain>")
//     as the first PSH-ACK payload. Real POP3 servers send this greeting
//     right after the handshake; the APOP timestamp is parsed from it by
//     real clients.
//  3. Each POP3Command: client command (PSH-ACK up) + server response
//     (PSH-ACK down). Single-line responses get CRLF appended; multi-line
//     responses are emitted verbatim (the user includes the terminating
//     "\r\n.\r\n"). Payloads longer than MSS are segmented; each segment
//     advances the sender's sequence number by its byte length.
//  4. Optional EmitMailDrop: when true, the planner synthesizes a RETR-like
//     multi-line response from Mailbox.Messages[MsgNum-1] (headers, blank
//     line, dot-stuffed body, terminator) and emits it as the response.
//  5. TCP 4-way teardown (FIN-ACK, ACK, FIN-ACK, ACK).
//
// The planner does NOT enforce POP3 state-machine transitions. The user is
// responsible for providing a syntactically valid dialog (USER before PASS,
// STAT/LIST/RETR/DELE only after authentication, QUIT to end). This matches
// the trafficgen contract: synthesize test packets, not a real POP3 server.
//
// IPv6 / multicast MAC / VLAN behavior follows the unified convention at
// /tmp/l7_planner_design/multicast_ipv6_vlan.md. POP3 is "transparent" for
// IP version (works over IPv4 or IPv6); it is unicast-only.
package pop3

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
)

const (
	// DefaultTTL mirrors internal/protocol/tcp.DefaultTTL and
	// internal/protocol/ftp.DefaultTTL (64). Standard IP TTL for
	// forwarded traffic; matches Linux/macOS defaults.
	DefaultTTL = 64

	// DefaultMSS mirrors internal/protocol/tcp.DefaultMSS and
	// internal/protocol/http.DefaultMSS (1460). Duplicated here to avoid
	// an import cycle. RFC 879 floor is 536; 1460 is the Ethernet-friendly
	// value used by Linux.
	DefaultMSS = 1460

	// MinMSS per RFC 879 (IP+TCP header 20+20+536 = 576-byte minimum
	// packet). Smaller values produce malformed SYNs or pathological
	// fragmentation.
	MinMSS = 536

	// DefaultPort is the well-known POP3 port per RFC 1939 §6.
	// mapToFlowSpec sets this when the user did not specify a dst_port.
	DefaultPort = 110

	// MaxMessages caps Mailbox.Messages count. 100000 matches the design
	// doc upper bound; protects against memory blowup when synthesizing
	// LIST/UIDL responses (each message generates one response line).
	MaxMessages = 100000

	// MaxUsernameLen per RFC 1939 §6 USER command (1-40 chars).
	MaxUsernameLen = 40

	// MaxPasswordLen per RFC 1939 §6 PASS command (1-255 chars).
	MaxPasswordLen = 255

	// MaxUIDLen per RFC 1939 §7 UIDL command (1-70 chars).
	MaxUIDLen = 70

	// HexDigestLen is the length of an MD5 hex digest (RFC 1321).
	// APOP digest per RFC 1939 §6 must be exactly 32 hex chars.
	HexDigestLen = 32
)

// Planner implements the POP3 protocol planner.
type Planner struct{}

// NewPlanner creates a new POP3 planner.
func NewPlanner() *Planner { return &Planner{} }

// Name returns the protocol name. Used by the registry to look up the
// planner by the "pop3" string in FlowSpec JSON tags and Task.Protocol.
func (p *Planner) Name() string { return "pop3" }

// Validate validates a POP3 flow spec. Read-only: never modifies spec.
// Per the validate_conventions.md §1.1 contract, default-value filling
// happens in Plan(), not here.
func (p *Planner) Validate(spec core.FlowSpec) error {
	// IP validity (read-only; "" = use default filled by Plan).
	if spec.SrcIP != "" {
		if net.ParseIP(spec.SrcIP) == nil {
			return fmt.Errorf("pop3: SrcIP %q is not a valid IP address", spec.SrcIP)
		}
	}
	if spec.DstIP != "" {
		if net.ParseIP(spec.DstIP) == nil {
			return fmt.Errorf("pop3: DstIP %q is not a valid IP address", spec.DstIP)
		}
	}

	// MSS is a TCP transport parameter; lives on TCPConfig. 0 = default
	// (filled by Plan). RFC 879 floor is 536.
	if spec.TCP != nil && spec.TCP.MSS > 0 {
		if spec.TCP.MSS < MinMSS {
			return fmt.Errorf("pop3: MSS %d too small (min %d per RFC 879)", spec.TCP.MSS, MinMSS)
		}
	}

	if spec.POP3 == nil {
		return nil
	}

	// Mailbox structural checks.
	if spec.POP3.Mailbox != nil {
		if len(spec.POP3.Mailbox.Messages) > MaxMessages {
			return fmt.Errorf("pop3: Mailbox has %d messages, max %d", len(spec.POP3.Mailbox.Messages), MaxMessages)
		}
		for i, msg := range spec.POP3.Mailbox.Messages {
			if len(msg.UID) > MaxUIDLen {
				return fmt.Errorf("pop3: Mailbox.Messages[%d].UID length %d exceeds max %d (RFC 1939 §7 UIDL)", i, len(msg.UID), MaxUIDLen)
			}
		}
	}

	// Per-command structural checks.
	for i, cmd := range spec.POP3.Commands {
		// CRLF injection protection. Commands are single-line; responses
		// may be multi-line only when Multiline=true (then \r\n is the
		// line separator and is allowed).
		if strings.ContainsAny(cmd.Cmd, "\r\n") {
			return fmt.Errorf("pop3: Commands[%d].Cmd %q contains CRLF (command injection per RFC 1939 §3)", i, cmd.Cmd)
		}
		if !cmd.Multiline && strings.ContainsAny(cmd.Response, "\r\n") {
			return fmt.Errorf("pop3: Commands[%d].Response contains CRLF but Multiline=false; set Multiline=true for multi-line responses", i)
		}

		// EmitMailDrop requires Mailbox and in-range MsgNum.
		if cmd.EmitMailDrop {
			if spec.POP3.Mailbox == nil {
				return fmt.Errorf("pop3: Commands[%d].EmitMailDrop=true but Mailbox is nil", i)
			}
			if cmd.MsgNum < 1 || int(cmd.MsgNum) > len(spec.POP3.Mailbox.Messages) {
				return fmt.Errorf("pop3: Commands[%d].MsgNum %d out of range [1, %d]", i, cmd.MsgNum, len(spec.POP3.Mailbox.Messages))
			}
		}

		// EmitTop (RFC 1939 §6 TOP) requires Mailbox and in-range MsgNum.
		// Mutually exclusive with EmitMailDrop (ambiguous which response
		// shape to synthesize: RETR "+OK <size> octets" vs TOP "+OK").
		if cmd.EmitTop {
			if cmd.EmitMailDrop {
				return fmt.Errorf("pop3: Commands[%d].EmitTop and EmitMailDrop are mutually exclusive", i)
			}
			if spec.POP3.Mailbox == nil {
				return fmt.Errorf("pop3: Commands[%d].EmitTop=true but Mailbox is nil", i)
			}
			if cmd.MsgNum < 1 || int(cmd.MsgNum) > len(spec.POP3.Mailbox.Messages) {
				return fmt.Errorf("pop3: Commands[%d].MsgNum %d out of range [1, %d]", i, cmd.MsgNum, len(spec.POP3.Mailbox.Messages))
			}
		}

		// Command-name-specific checks: USER/PASS/APOP length and digest
		// format per RFC 1939 §6. State is NOT checked (user responsibility).
		cmdName, args := splitCmd(cmd.Cmd)
		switch strings.ToUpper(cmdName) {
		case "USER":
			if len(args) > 0 && len(args[0]) > MaxUsernameLen {
				return fmt.Errorf("pop3: Commands[%d].USER name length %d exceeds max %d (RFC 1939 §6)", i, len(args[0]), MaxUsernameLen)
			}
		case "PASS":
			if len(args) > 0 && len(args[0]) > MaxPasswordLen {
				return fmt.Errorf("pop3: Commands[%d].PASS password length %d exceeds max %d (RFC 1939 §6)", i, len(args[0]), MaxPasswordLen)
			}
		case "APOP":
			// Per RFC 1939 §6 APOP requires name + digest, but we tolerate
			// extra whitespace (strings.Fields collapses runs of whitespace).
			// Only validate the digest format when 2 args are present; an
			// empty name (e.g. "APOP  <digest>") still parses to 2 fields
			// after Fields, so the digest check fires. When only 1 arg is
			// present (no digest), skip validation - the user may be testing
			// malformed input by providing a custom -ERR response.
			if len(args) == 2 {
				digest := args[1]
				if len(digest) != HexDigestLen {
					return fmt.Errorf("pop3: Commands[%d].APOP digest length %d, must be %d hex chars (RFC 1939 §6)", i, len(digest), HexDigestLen)
				}
				if _, err := hex.DecodeString(digest); err != nil {
					return fmt.Errorf("pop3: Commands[%d].APOP digest %q must be hex (RFC 1939 §6)", i, digest)
				}
			}
		}
	}

	return nil
}

// Plan generates packet configs for a POP3 flow. Returns a channel that
// yields PacketConfig values in wire order. The channel is closed when
// generation completes or when ctx is cancelled.
func (p *Planner) Plan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) {
	if err := p.Validate(spec); err != nil {
		return nil, err
	}

	configChan := make(chan core.PacketConfig, 256)

	go func() {
		defer close(configChan)

		flowID := fmt.Sprintf("%s-%s-%d-%d", spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort)

		pop3Config := spec.POP3
		if pop3Config == nil {
			pop3Config = &core.POP3Config{}
		}

		effectiveTTL := spec.TTL
		if effectiveTTL == 0 {
			effectiveTTL = DefaultTTL
		}

		// MSS resolution: 0 -> DefaultMSS (1460). MSS is a TCP transport
		// parameter; it lives on TCPConfig (spec.TCP.MSS).
		mss := uint16(DefaultMSS)
		if spec.TCP != nil && spec.TCP.MSS > 0 {
			mss = spec.TCP.MSS
		}
		synOpts := synOptions(mss)

		now := time.Now()
		packetIndex := uint64(0)
		ipID := uint16(rand.Uint32())
		nextIPID := func() uint16 {
			id := ipID
			ipID++
			return id
		}

		// Random ISN per RFC 6528. User can override client ISN via
		// spec.TCP.InitialSeq for reproducible tests.
		clientSeq := uint32(0)
		if spec.TCP != nil {
			clientSeq = spec.TCP.InitialSeq
		}
		if clientSeq == 0 {
			clientSeq = rand.Uint32()
		}
		serverSeq := rand.Uint32()

		winSize := uint16(65535)

		// emit writes one packet to configChan. Mirrors FTP/HTTP/SIP
		// pattern. Pre-writes Metadata["group_id"] when spec carries a
		// GroupID strategy, so direct consumers (parsers, replays) see
		// the same group the worker would stamp via computeHashKey.
		emit := func(direction, srcMAC, dstMAC, srcIP, dstIP string, srcPort, dstPort uint16, seq, ack uint32, flags uint8, payload []byte) {
			l3 := core.L3Base(srcIP, dstIP, 6, effectiveTTL, nextIPID(), spec)
			l4 := core.L4Config{
				Protocol:   "tcp",
				SrcPort:    srcPort,
				DstPort:    dstPort,
				Seq:        seq,
				Ack:        ack,
				Flags:      flags,
				WindowSize: winSize,
			}
			if flags == 0x02 || flags == 0x12 {
				// SYN or SYN-ACK carries TCP options.
				l4.TCPOptions = synOpts
			}
			var meta map[string]interface{}
			if spec.GroupID != nil && spec.GroupID.Strategy != "" {
				if g := core.FlowGroupIDValue(spec.GroupID, 0); g != "" {
					meta = map[string]interface{}{"group_id": g}
				}
			}
			cfg := core.PacketConfig{
				FlowID:      flowID,
				PacketIndex: packetIndex,
				Direction:   direction,
				Timestamp:   now,
				L2: core.L2Config{
					SrcMAC:    srcMAC,
					DstMAC:    dstMAC,
					EtherType: core.EtherTypeFor(spec.SrcIP),
				},
				L3:       l3,
				L4:       l4,
				Payload:  payload,
				Metadata: meta,
			}
			configChan <- cfg
			packetIndex++
		}

		// --- TCP handshake (SYN, SYN-ACK, ACK) ---
		emit("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, 0, 0x02, nil)
		clientSeq++
		emit("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, 0x12, nil)
		serverSeq++
		emit("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, 0x10, nil)

		// emitData segments payload by MSS and emits each chunk as a
		// PSH-ACK in the given direction, advancing the sender's seq.
		// The peer's seq is unchanged (no ACK emission here - the next
		// peer-side packet will carry the updated ACK covering these
		// bytes).
		emitData := func(direction, srcMAC, dstMAC, srcIP, dstIP string, srcPort, dstPort uint16, senderSeq, peerSeq uint32, payload []byte) (newSenderSeq uint32) {
			for _, seg := range segmentByMSS(payload, int(mss)) {
				emit(direction, srcMAC, dstMAC, srcIP, dstIP, srcPort, dstPort, senderSeq, peerSeq, 0x18, seg)
				senderSeq += uint32(len(seg))
			}
			return senderSeq
		}

		// --- Server banner (optional) ---
		// Real POP3 servers send "+OK POP3 server ready <timestamp@domain>"
		// as the greeting; the APOP timestamp is parsed from it by clients.
		if pop3Config.Banner != "" {
			payload := []byte(pop3Config.Banner + "\r\n")
			serverSeq = emitData("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, payload)
		}

		// --- POP3 command/response pairs ---
		for _, cmd := range pop3Config.Commands {
			// Command (client -> server). Append CRLF per RFC 1939 §3.
			// Empty Cmd is skipped (lets users model server-only turns,
			// e.g. for AUTH PLAIN's intermediate "+" challenge).
			if cmd.Cmd != "" {
				payload := []byte(cmd.Cmd + "\r\n")
				clientSeq = emitData("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, payload)
			}

			// Response (server -> client). When EmitMailDrop=true,
			// synthesize the multi-line RETR response from Mailbox and
			// emit it INSTEAD of any user-provided Response. When EmitTop
			// is true, synthesize a TOP response (headers + first N body
			// lines). Otherwise, emit the user-provided Response verbatim
			// when Multiline=true (user includes the CRLF.CRLF terminator)
			// or with CRLF appended when Multiline=false (single-line
			// +OK/-ERR). EmitMailDrop and EmitTop are mutually exclusive
			// (enforced by Validate); EmitMailDrop takes precedence here
			// for safety.
			if cmd.EmitMailDrop && pop3Config.Mailbox != nil {
				respBytes := buildMailDropResponse(pop3Config.Mailbox.Messages[cmd.MsgNum-1])
				serverSeq = emitData("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, respBytes)
			} else if cmd.EmitTop && pop3Config.Mailbox != nil {
				respBytes := buildTopResponse(pop3Config.Mailbox.Messages[cmd.MsgNum-1], cmd.TopLines)
				serverSeq = emitData("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, respBytes)
			} else if cmd.Response != "" {
				var payload []byte
				if cmd.Multiline {
					// User includes the terminator; emit verbatim.
					payload = []byte(cmd.Response)
				} else {
					// Single-line +OK/-ERR: planner appends CRLF.
					payload = []byte(cmd.Response + "\r\n")
				}
				serverSeq = emitData("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, payload)
			}
		}

		// --- TCP teardown (FIN-ACK, ACK, FIN-ACK, ACK) ---
		emit("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, 0x11, nil)
		clientSeq++
		emit("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, 0x10, nil)
		emit("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, 0x11, nil)
		serverSeq++
		emit("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, 0x10, nil)
	}()

	return configChan, nil
}

// splitCmd splits a command string into the command name (first token)
// and its arguments (remaining tokens). Returns ("", nil) for empty cmd.
// Used by Validate to dispatch command-specific checks (USER/PASS/APOP).
// Whitespace is per RFC 1939 §3 (one or more SP between tokens).
func splitCmd(cmd string) (string, []string) {
	fields := strings.Fields(cmd)
	if len(fields) == 0 {
		return "", nil
	}
	return fields[0], fields[1:]
}

// buildMailDropResponse synthesizes a RETR-style multi-line POP3 response
// from a POP3Message per RFC 1939 §3 (multi-line response format) and
// §3 (dot-stuffing rule). The format is:
//
//	"+OK <size> octets\r\n"             <- status line
//	"<header1>\r\n"                     <- each header followed by CRLF
//	"<header2>\r\n"
//	"\r\n"                              <- blank line separating headers from body
//	"<dot-stuffed body line 1>\r\n"     <- body lines; lines starting with "."
//	"<dot-stuffed body line 2>\r\n"        get an extra "." prepended
//	".\r\n"                             <- termination line
//
// When MIMEParts is non-empty, the planner builds a multipart/mixed body
// per RFC 2046 §5.1.1: it prepends "MIME-Version: 1.0" and
// "Content-Type: multipart/mixed; boundary=..." to the message headers,
// then emits each part between "--<boundary>" delimiters, terminated by
// "--<boundary>--". Dot-stuffing (RFC 1939 §3) applies to the entire
// message body (including multipart delimiters and part content), because
// dot-stuffing is a POP3 transport concern, not a MIME concern.
//
// When Size > 0 the user's value is used verbatim; otherwise the planner
// computes it from the body bytes only (matches testcase 4.5.5:
// "+OK 0 octets\r\n\r\n.\r\n" for an empty email). The wire format still
// emits the blank line CRLF between (possibly empty) headers and (possibly
// empty) body; only the status-line size field omits the header/blank-line
// overhead. This matches the design_pop3.md §6.2 contract where the size
// is informational and the actual wire bytes are the user's responsibility
// (via Headers/Body fields).
//
// Dot-stuffing per RFC 1939 §3: when a line of the body begins with ".",
// the server prepends another "." to it. The client de-stuffs on receive.
// Header lines are NOT dot-stuffed (RFC 1939 §3 implies dot-stuffing is
// for the message body only; headers are RFC 5322 mailbox metadata and
// cannot legitimately start with "." anyway).
func buildMailDropResponse(msg core.POP3Message) []byte {
	// Build the message body. When MIMEParts is present, the body is the
	// full multipart content; otherwise it is the simple Body field.
	// effectiveHeaders carries the message-level headers (with MIME
	// headers prepended for multipart).
	effectiveHeaders := msg.Headers
	bodyText := ""
	if len(msg.MIMEParts) > 0 {
		bodyText = buildMultipartBody(msg.MIMEParts, msg.Boundary)
		effectiveHeaders = buildMIMEHeaders(msg.Headers, msg.Boundary)
	} else {
		bodyText = msg.Body
	}

	// Compute Size if user did not set it. Per testcases 1.6.1 + 4.5.5
	// the size is the body octets; headers + blank-line overhead are
	// reported as 0 when the message is empty.
	size := msg.Size
	if size == 0 {
		size = uint32(len(bodyText))
	}

	var b strings.Builder
	// Status line: "+OK <size> octets\r\n" per RFC 1939 §6 RETR success.
	fmt.Fprintf(&b, "+OK %d octets\r\n", size)

	// Headers (RFC 5322): each header line followed by CRLF.
	for _, h := range effectiveHeaders {
		b.WriteString(h)
		b.WriteString("\r\n")
	}

	// Blank line separating headers from body.
	b.WriteString("\r\n")

	// Body with dot-stuffing per RFC 1939 §3.
	writeDotStuffedBody(&b, bodyText)

	// Termination line: ".\r\n" per RFC 1939 §3.
	b.WriteString(".\r\n")

	return []byte(b.String())
}

// buildTopResponse synthesizes a TOP-style multi-line POP3 response from
// a POP3Message per RFC 1939 §6 TOP. TOP returns the message headers, a
// blank line, then the first topLines lines of the message body. The
// status line is "+OK" (no size, matching RFC 1939 §6 TOP). The response
// is terminated by ".\r\n" per RFC 1939 §3.
//
// When MIMEParts is non-empty, the "body" for TOP is the full multipart
// body (the planner does not parse into individual parts - TOP operates
// on the raw message body after the header/body separator). Dot-stuffing
// applies per RFC 1939 §3.
//
// topLines=0 means headers only (RFC 1939 §6 TOP with n=0): after the
// blank line, the terminator immediately follows.
func buildTopResponse(msg core.POP3Message, topLines uint32) []byte {
	// For TOP, the body is the raw body text (simple Body, or the full
	// multipart body when MIMEParts is present). MIME headers are NOT
	// emitted as separate message headers for TOP - the user provides
	// message-level headers via msg.Headers, and TOP returns those +
	// the body. This matches RFC 1939 §6: "the header of the message"
	// and "the first n lines of the body".
	bodyText := msg.Body
	if len(msg.MIMEParts) > 0 {
		bodyText = buildMultipartBody(msg.MIMEParts, msg.Boundary)
	}

	var b strings.Builder
	// Status line: "+OK\r\n" per RFC 1939 §6 TOP success (no size).
	b.WriteString("+OK\r\n")

	// Headers (RFC 5322): each header line followed by CRLF.
	for _, h := range msg.Headers {
		b.WriteString(h)
		b.WriteString("\r\n")
	}

	// Blank line separating headers from body.
	b.WriteString("\r\n")

	// First topLines body lines with dot-stuffing per RFC 1939 §3.
	if topLines > 0 && len(bodyText) > 0 {
		bodyLines := strings.Split(strings.TrimRight(bodyText, "\r\n"), "\n")
		for i, line := range bodyLines {
			if uint32(i) >= topLines {
				break
			}
			line = strings.TrimRight(line, "\r")
			if strings.HasPrefix(line, ".") {
				b.WriteString(".")
			}
			b.WriteString(line)
			b.WriteString("\r\n")
		}
	}

	// Termination line: ".\r\n" per RFC 1939 §3.
	b.WriteString(".\r\n")

	return []byte(b.String())
}

// buildMIMEHeaders prepends MIME-Version and Content-Type multipart headers
// to the user-provided message headers. The boundary is resolved via
// resolveBoundary. Returns a new slice; does not mutate the input.
func buildMIMEHeaders(userHeaders []string, boundary string) []string {
	resolved := resolveBoundary(boundary)
	out := make([]string, 0, len(userHeaders)+2)
	out = append(out, "MIME-Version: 1.0")
	out = append(out, fmt.Sprintf(`Content-Type: multipart/mixed; boundary="%s"`, resolved))
	out = append(out, userHeaders...)
	return out
}

// buildMultipartBody constructs the multipart/mixed body per RFC 2046 §5.1.1:
//
//	--<boundary>\r\n
//	<part headers>\r\n
//	\r\n
//	<part body>\r\n
//	--<boundary>\r\n
//	... (repeat for each part)
//	--<boundary>--\r\n
//
// The boundary is resolved via resolveBoundary. Each part's body is
// BodyB64 when non-empty (emitted verbatim - the client decodes via the
// Content-Transfer-Encoding: base64 header), otherwise Body. Dot-stuffing
// is NOT applied here: it is applied to the entire assembled body in
// buildMailDropResponse/buildTopResponse, because dot-stuffing is a POP3
// transport concern that must wrap the whole message body uniformly.
func buildMultipartBody(parts []core.POP3MIMEPart, boundary string) string {
	resolved := resolveBoundary(boundary)
	var b strings.Builder
	for _, part := range parts {
		// Opening delimiter: "--<boundary>\r\n" per RFC 2046 §5.1.1.
		b.WriteString("--")
		b.WriteString(resolved)
		b.WriteString("\r\n")

		// Part headers (RFC 822/5322): each followed by CRLF.
		for _, h := range part.Headers {
			b.WriteString(h)
			b.WriteString("\r\n")
		}

		// Blank line separating part headers from part body.
		b.WriteString("\r\n")

		// Part body. BodyB64 takes precedence (RFC 2045 §6.8 base64).
		body := part.Body
		if part.BodyB64 != "" {
			body = part.BodyB64
		}
		// Normalize the part body's trailing line ending to CRLF so the
		// next boundary delimiter starts on its own line. If the body
		// already ends with "\r\n", leave it; if it ends with "\n" only,
		// strip the "\n" and let the CRLF append below handle it; if it
		// has no trailing newline, append CRLF. This prevents a stray
		// "\n\r\n" sequence (which would create an extra empty line).
		if strings.HasSuffix(body, "\r\n") {
			b.WriteString(body)
		} else if strings.HasSuffix(body, "\n") {
			b.WriteString(body[:len(body)-1])
			b.WriteString("\r\n")
		} else if len(body) > 0 {
			b.WriteString(body)
			b.WriteString("\r\n")
		}
	}
	// Closing delimiter: "--<boundary>--\r\n" per RFC 2046 §5.1.1.
	b.WriteString("--")
	b.WriteString(resolved)
	b.WriteString("--\r\n")
	return b.String()
}

// resolveBoundary returns the user-provided boundary when non-empty, or a
// deterministic auto-generated boundary otherwise. The auto boundary is
// RFC 2046 §5.1.1 compliant (any valid chars, <= 70 chars). We use a
// fixed deterministic string rather than a random one so test captures
// are reproducible.
func resolveBoundary(boundary string) string {
	if boundary != "" {
		return boundary
	}
	return "----=_POP3_BOUND_0001"
}

// writeDotStuffedBody writes bodyText to b with dot-stuffing per RFC 1939 §3.
// Lines beginning with "." get an extra "." prepended. Line endings are
// normalized to CRLF. Empty body writes nothing (the caller writes the
// terminator). This is the shared dot-stuffing implementation used by
// buildMailDropResponse; extracted to avoid divergence between the simple
// Body and multipart paths.
func writeDotStuffedBody(b *strings.Builder, bodyText string) {
	if len(bodyText) == 0 {
		return
	}
	bodyLines := strings.Split(strings.TrimRight(bodyText, "\r\n"), "\n")
	for _, line := range bodyLines {
		line = strings.TrimRight(line, "\r")
		if strings.HasPrefix(line, ".") {
			b.WriteString(".")
		}
		b.WriteString(line)
		b.WriteString("\r\n")
	}
}

// segmentByMSS splits payload into chunks of at most mss bytes. The last
// chunk may be smaller. A nil/empty payload returns a single empty chunk
// so the caller emits one PSH-ACK segment (matching the pre-segmentation
// behavior where an empty body still produced one response packet).
//
// Mirrors internal/protocol/http.segmentByMSS and ftp.segmentByMSS -
// duplicated to avoid an import cycle.
func segmentByMSS(payload []byte, mss int) [][]byte {
	if mss <= 0 {
		return [][]byte{payload}
	}
	if len(payload) == 0 {
		return [][]byte{{}}
	}
	chunks := make([][]byte, 0, (len(payload)+mss-1)/mss)
	for len(payload) > 0 {
		n := len(payload)
		if n > mss {
			n = mss
		}
		chunks = append(chunks, payload[:n])
		payload = payload[n:]
	}
	return chunks
}

// synOptions builds TCP options for SYN packets: MSS, Window Scale, and
// SACK-Permitted, matching real-world SYN capture characteristics. Mirrors
// internal/protocol/tcp.synOptions, http.synOptions, and ftp.synOptions -
// duplicated to avoid an import cycle.
func synOptions(mss uint16) []core.TCPOption {
	if mss == 0 {
		mss = DefaultMSS
	}
	opts := make([]core.TCPOption, 0, 3)
	opts = append(opts, core.TCPOption{Kind: core.TCPOptMSS, Data: []byte{byte(mss >> 8), byte(mss)}})
	opts = append(opts, core.TCPOption{Kind: core.TCPOptWinScale, Data: []byte{0x07}})
	opts = append(opts, core.TCPOption{Kind: core.TCPOptSACKPermit})
	return opts
}

// computeAPOPDigest returns the MD5 hex digest of (timestamp + password)
// per RFC 1939 §6 APOP. This is a helper for users who want to compute
// a valid APOP digest from a banner timestamp and a password; the planner
// itself does NOT call this (the user provides the digest in the APOP
// command string verbatim).
//
// Exported so tests and external tools can construct valid APOP commands
// without re-implementing MD5. The returned string is 32 lowercase hex
// chars per RFC 1321.
func computeAPOPDigest(timestamp, password string) string {
	sum := md5.Sum([]byte(timestamp + password))
	return hex.EncodeToString(sum[:])
}
