// Package imap implements the IMAP4rev2 (Internet Message Access Protocol
// version 4 revision 2, 互联网邮件访问协议第四版第二修订) protocol
// planner per RFC 9051.
//
// IMAP is a session-level protocol: a single TCP connection on port 143
// (the well-known IMAP port) carries a sequence of tagged client
// commands and tagged / untagged / continuation server responses across
// four states (NOT-AUTHENTICATED / AUTHENTICATED / SELECTED / LOGOUT).
// The planner emits:
//
//  1. TCP 3-way handshake (SYN, SYN-ACK, ACK) with MSS/WinScale/SACK
//     options, mirroring the FTP/HTTP/SIP/POP3 control-channel pattern.
//  2. Optional server greeting (e.g. "* OK [CAPABILITY IMAP4rev2 ...]
//     imap.example.com ready") as the first PSH-ACK payload.
//  3. For each IMAPCommand: client command (PSH-ACK up) + one or more
//     server responses (PSH-ACK down). Multi-response sequences model
//     tagged/untagged/continuation interleaving per RFC 9051 §2.2.4.
//  4. IMAP literals (the "{N}\r\n<N bytes>" syntax used by APPEND and
//     FETCH BODY[]) are synthesized from LiteralBody /
//     LiteralBodyB64 / FileSource on a per-command basis. Precedence:
//     FileSource > LiteralBodyB64 > LiteralBody.
//  5. Optional IMAP IDLE mode (RFC 2177) per cmd.EmitIDLE: the planner
//     emits "+ idling" continuation, any IDLE.PushResponses (server
//     pushes), the "DONE" terminator from the client, the IDLE
//     completion tagged response, and (optionally) a server timeout
//     BYE per IDLE.ServerTimeoutBehavior.
//  6. TCP 4-way teardown (FIN-ACK, ACK, FIN-ACK, ACK).
//
// The planner does NOT enforce IMAP state-machine transitions or
// tag-matching. The user is responsible for providing a syntactically
// valid dialog (LOGIN before SELECT, DONE to exit IDLE, LOGOUT to end).
// This matches the trafficgen contract: synthesize test packets, not a
// real IMAP server.
//
// IPv6 / multicast MAC / VLAN behavior follows the unified convention
// at /tmp/l7_planner_design/multicast_ipv6_vlan.md. IMAP is
// "transparent" for IP version (works over IPv4 or IPv6); it is
// unicast-only.
package imap

import (
	"context"
	"encoding/base64"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
)

const (
	// DefaultTTL mirrors internal/protocol/tcp.DefaultTTL,
	// internal/protocol/ftp.DefaultTTL, and
	// internal/protocol/pop3.DefaultTTL (64). Standard IP TTL for
	// forwarded traffic; matches Linux/macOS defaults.
	DefaultTTL = 64

	// DefaultMSS mirrors internal/protocol/tcp.DefaultMSS,
	// internal/protocol/http.DefaultMSS, and
	// internal/protocol/pop3.DefaultMSS (1460). Duplicated here to
	// avoid an import cycle. RFC 879 floor is 536; 1460 is the
	// Ethernet-friendly value used by Linux.
	DefaultMSS = 1460

	// MinMSS per RFC 879 (IP+TCP header 20+20+536 = 576-byte minimum
	// packet). Smaller values produce malformed SYNs or pathological
	// fragmentation.
	MinMSS = 536

	// DefaultPort is the well-known IMAP port per RFC 9051 §3.1.
	// mapToFlowSpec sets this when the user did not specify a dst_port.
	DefaultPort = 143

	// MaxTagLen per RFC 9051 §2.2.1 (tag is 1-256 octets). We enforce
	// 1-256; longer tags are a Validate error.
	MaxTagLen = 256

	// MaxResponsesPerCommand caps the number of responses per
	// IMAPCommand. 10000 is generous; protects against accidental
	// memory blowup when synthesizing large untagged response lists
	// (e.g. LIST 1000 mailboxes + FETCH 10000 messages).
	MaxResponsesPerCommand = 10000

	// MaxPushResponses caps IDLE.PushResponses count. 1000 matches
	// the design doc upper bound; protects against memory blowup
	// when synthesizing long IDLE push sequences.
	MaxPushResponses = 1000

	// MaxLiteralLen caps the length of a synthesized literal body
	// (LiteralBody / LiteralBodyB64 decoded / FileSource loaded).
	// 100 MB matches the design doc upper bound; protects against
	// memory blowup when a user accidentally sets a huge literal.
	MaxLiteralLen = 100 * 1024 * 1024

	// IDLETimeoutBye is the RFC 2177 §4 server-side IDLE timeout
	// BYE line. Real servers emit this after 29 minutes of inactivity;
	// the planner emits it immediately after the done response when
	// ServerTimeoutBehavior="close_after_idle" (we do NOT actually
	// wait 29 minutes — see edge case C-IMAP-1.2).
	IDLETimeoutBye = "* BYE IDLE timeout\r\n"

	// IDLEContuation is the server's continuation response to the
	// client's IDLE command per RFC 2177 §3.
	IDLEContuation = "+ idling\r\n"

	// IDLEDone is the client's DONE terminator per RFC 2177 §4.
	// When DoneTag is empty, the planner emits this verbatim; when
	// DoneTag is set, the planner emits "<DoneTag> DONE\r\n".
	IDLEDone = "DONE\r\n"

	// AuthCancelLine is the client's AUTHENTICATE cancellation line
	// per RFC 9051 §6.2.2: a single "*" on a line by itself tells
	// the server to cancel the in-progress AUTHENTICATE.
	AuthCancelLine = "*\r\n"

	// UIDCacheInvalidationResponse is the untagged response the
	// planner synthesizes when UIDCacheInvalidation=true, modeling
	// RFC 7162 CONDSTORE cache invalidation (edge case C-IMAP-1.9).
	UIDCacheInvalidationResponse = "* OK [HIGHESTMODSEQ 1] mailbox cache invalidated\r\n"
)

// Planner implements the IMAP protocol planner.
type Planner struct{}

// NewPlanner creates a new IMAP planner.
func NewPlanner() *Planner { return &Planner{} }

// Name returns the protocol name. Used by the registry to look up the
// planner by the "imap" string in FlowSpec JSON tags and Task.Protocol.
func (p *Planner) Name() string { return "imap" }

// Validate validates an IMAP flow spec. Read-only: never modifies spec.
// Per the validate_conventions.md §1.1 contract, default-value filling
// happens in Plan(), not here.
func (p *Planner) Validate(spec core.FlowSpec) error {
	// IP validity (read-only; "" = use default filled by Plan).
	if spec.SrcIP != "" {
		if net.ParseIP(spec.SrcIP) == nil {
			return fmt.Errorf("imap: SrcIP %q is not a valid IP address", spec.SrcIP)
		}
	}
	if spec.DstIP != "" {
		if net.ParseIP(spec.DstIP) == nil {
			return fmt.Errorf("imap: DstIP %q is not a valid IP address", spec.DstIP)
		}
	}

	// MSS is a TCP transport parameter; lives on TCPConfig. 0 = default
	// (filled by Plan). RFC 879 floor is 536.
	if spec.TCP != nil && spec.TCP.MSS > 0 {
		if spec.TCP.MSS < MinMSS {
			return fmt.Errorf("imap: MSS %d too small (min %d per RFC 879)", spec.TCP.MSS, MinMSS)
		}
	}

	if spec.IMAP == nil {
		return nil
	}

	// AllowUTF8Mailbox pre-check: when false, reject any Cmd whose
	// mailbox argument contains bytes with the high bit set (edge case
	// C-IMAP-1.7). When true, permit 8-bit mailbox names verbatim.
	allowUTF8 := spec.IMAP.AllowUTF8Mailbox

	// Per-command structural checks.
	for i, cmd := range spec.IMAP.Commands {
		// Tag length per RFC 9051 §2.2.1 (1-256 octets).
		if len(cmd.Tag) > MaxTagLen {
			return fmt.Errorf("imap: Commands[%d].Tag length %d exceeds max %d (RFC 9051 §2.2.1)", i, len(cmd.Tag), MaxTagLen)
		}
		// Tag must not contain CR/LF/SP (RFC 9051 §2.2.1: tag is
		// atom-char + tag-char; SP/CRLF are separators).
		if strings.ContainsAny(cmd.Tag, " \r\n") {
			return fmt.Errorf("imap: Commands[%d].Tag %q contains SP/CRLF (RFC 9051 §2.2.1)", i, cmd.Tag)
		}

		// CRLF injection protection. Commands are single-line; the
		// planner appends CRLF. Any embedded CRLF is a command
		// injection per RFC 9051 §2.2.1 (tagged command is one line).
		if strings.ContainsAny(cmd.Cmd, "\r\n") {
			return fmt.Errorf("imap: Commands[%d].Cmd %q contains CRLF (command injection per RFC 9051 §2.2.1)", i, cmd.Cmd)
		}

		// UTF-8 mailbox check (edge case C-IMAP-1.7). When
		// AllowUTF8Mailbox=false, reject any Cmd with non-ASCII bytes.
		// The user is expected to encode non-ASCII mailbox names as
		// Modified UTF-7 per RFC 3501 §5.1.3 in that case.
		if !allowUTF8 && hasNonASCII(cmd.Cmd) {
			return fmt.Errorf("imap: Commands[%d].Cmd %q contains non-ASCII bytes; set AllowUTF8Mailbox=true or encode as Modified UTF-7 per RFC 3501 §5.1.3 (C-IMAP-1.7)", i, cmd.Cmd)
		}

		// Responses: each response must not contain CRLF when it is
		// a single-line response. The planner appends "\r\n" to each
		// entry. Multi-line responses (e.g. FETCH BODY[] literals)
		// are modeled via LiteralBody / LiteralBodyB64 / FileSource;
		// raw CRLF in Responses entries is rejected to keep the
		// model simple (the user splits multi-line into multiple
		// entries).
		if len(cmd.Responses) > MaxResponsesPerCommand {
			return fmt.Errorf("imap: Commands[%d].Responses count %d exceeds max %d", i, len(cmd.Responses), MaxResponsesPerCommand)
		}
		for j, resp := range cmd.Responses {
			if strings.ContainsAny(resp, "\r\n") {
				return fmt.Errorf("imap: Commands[%d].Responses[%d] contains CRLF; split into multiple entries or use LiteralBody for multi-line responses", i, j)
			}
		}

		// LiteralBody / LiteralBodyB64 mutual exclusivity + length
		// caps. Precedence: FileSource > LiteralBodyB64 > LiteralBody.
		// We only validate the inline forms here; FileSource is
		// resolved at Plan time via PayloadCache.
		if cmd.LiteralBody != "" && cmd.LiteralBodyB64 != "" {
			return fmt.Errorf("imap: Commands[%d].LiteralBody and LiteralBodyB64 are mutually exclusive; use one or the other (or FileSource)", i)
		}
		if cmd.LiteralBody != "" && len(cmd.LiteralBody) > MaxLiteralLen {
			return fmt.Errorf("imap: Commands[%d].LiteralBody length %d exceeds max %d", i, len(cmd.LiteralBody), MaxLiteralLen)
		}
		if cmd.LiteralBodyB64 != "" {
			decoded, err := base64.StdEncoding.DecodeString(cmd.LiteralBodyB64)
			if err != nil {
				return fmt.Errorf("imap: Commands[%d].LiteralBodyB64 decode error: %v", i, err)
			}
			if len(decoded) > MaxLiteralLen {
				return fmt.Errorf("imap: Commands[%d].LiteralBodyB64 decoded length %d exceeds max %d", i, len(decoded), MaxLiteralLen)
			}
		}

		// EmitIDLE requires IMAPConfig.IDLE.
		if cmd.EmitIDLE && spec.IMAP.IDLE == nil {
			return fmt.Errorf("imap: Commands[%d].EmitIDLE=true but IMAPConfig.IDLE is nil", i)
		}

		// CancelAfterResponses sanity: when > 0, must be <= len(Responses)
		// (otherwise the cancel would never fire).
		if cmd.CancelAfterResponses > 0 && cmd.CancelAfterResponses > len(cmd.Responses) {
			return fmt.Errorf("imap: Commands[%d].CancelAfterResponses %d > len(Responses) %d (cancel would never fire)", i, cmd.CancelAfterResponses, len(cmd.Responses))
		}
	}

	// IDLE structural checks.
	if spec.IMAP.IDLE != nil {
		if len(spec.IMAP.IDLE.PushResponses) > MaxPushResponses {
			return fmt.Errorf("imap: IDLE.PushResponses count %d exceeds max %d", len(spec.IMAP.IDLE.PushResponses), MaxPushResponses)
		}
		for j, push := range spec.IMAP.IDLE.PushResponses {
			if strings.ContainsAny(push, "\r\n") {
				return fmt.Errorf("imap: IDLE.PushResponses[%d] contains CRLF; split into multiple entries", j)
			}
		}
		// ServerTimeoutBehavior must be one of the allowed values.
		switch spec.IMAP.IDLE.ServerTimeoutBehavior {
		case "", "none", "close_after_idle", "keep_idle":
			// ok
		default:
			return fmt.Errorf("imap: IDLE.ServerTimeoutBehavior %q must be one of: \"\", \"none\", \"close_after_idle\", \"keep_idle\"", spec.IMAP.IDLE.ServerTimeoutBehavior)
		}
		// DoneTag must not contain SP/CRLF (it's a tag).
		if strings.ContainsAny(spec.IMAP.IDLE.DoneTag, " \r\n") {
			return fmt.Errorf("imap: IDLE.DoneTag %q contains SP/CRLF", spec.IMAP.IDLE.DoneTag)
		}
		if len(spec.IMAP.IDLE.DoneTag) > MaxTagLen {
			return fmt.Errorf("imap: IDLE.DoneTag length %d exceeds max %d", len(spec.IMAP.IDLE.DoneTag), MaxTagLen)
		}
		// DoneResponse must not contain CRLF (single-line).
		if strings.ContainsAny(spec.IMAP.IDLE.DoneResponse, "\r\n") {
			return fmt.Errorf("imap: IDLE.DoneResponse contains CRLF; must be single-line")
		}
	}

	return nil
}

// Plan generates packet configs for an IMAP flow. Returns a channel that
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

		imapConfig := spec.IMAP
		if imapConfig == nil {
			imapConfig = &core.IMAPConfig{}
		}

		effectiveTTL := spec.TTL
		if effectiveTTL == 0 {
			effectiveTTL = DefaultTTL
		}

		// MSS resolution: 0 -> DefaultMSS (1460). MSS is a TCP
		// transport parameter; it lives on TCPConfig (spec.TCP.MSS).
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

		// emit writes one packet to configChan. Mirrors FTP/HTTP/SIP/
		// POP3 pattern. Pre-writes Metadata["group_id"] when spec
		// carries a GroupID strategy, so direct consumers (parsers,
		// replays) see the same group the worker would stamp via
		// computeHashKey.
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
		// The peer's seq is unchanged (no ACK emission here - the
		// next peer-side packet will carry the updated ACK covering
		// these bytes).
		emitData := func(direction, srcMAC, dstMAC, srcIP, dstIP string, srcPort, dstPort uint16, senderSeq, peerSeq uint32, payload []byte) (newSenderSeq uint32) {
			for _, seg := range segmentByMSS(payload, int(mss)) {
				emit(direction, srcMAC, dstMAC, srcIP, dstIP, srcPort, dstPort, senderSeq, peerSeq, 0x18, seg)
				senderSeq += uint32(len(seg))
			}
			return senderSeq
		}

		// --- Server greeting (optional) ---
		// Real IMAP servers send "* OK [CAPABILITY IMAP4rev2 ...]
		// imap.example.com ready" as the greeting. The user includes
		// the trailing CRLF or not; we add it when missing (single-
		// line untagged greeting per RFC 9051 §2.2).
		if imapConfig.Banner != "" {
			banner := imapConfig.Banner
			if !strings.HasSuffix(banner, "\r\n") {
				banner += "\r\n"
			}
			serverSeq = emitData("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, []byte(banner))
		}

		// autoTag returns the next auto-incremented tag for a command
		// whose Tag is empty. Format: "A001", "A002", ... per RFC 9051
		// §2.2.1 recommendation.
		autoTagCounter := 0
		autoTag := func() string {
			autoTagCounter++
			return fmt.Sprintf("A%03d", autoTagCounter)
		}

		// resolveLiteral returns the literal body bytes for a command,
		// applying precedence: FileSource > LiteralBodyB64 > LiteralBody.
		// Returns nil when no literal source is set. When FileSource
		// is set but no PayloadCache is in ctx, returns (nil, false)
		// to signal "skip emitting the literal packet" — matches the
		// FTP contract.
		resolveLiteral := func(cmd core.IMAPCommand) ([]byte, bool) {
			if cmd.FileSource != nil {
				pc := core.PayloadCacheFrom(ctx)
				if pc == nil {
					return nil, false
				}
				b, _ := pc.GetOrLoad(ctx, *cmd.FileSource)
				return b, true
			}
			if cmd.LiteralBodyB64 != "" {
				decoded, err := base64.StdEncoding.DecodeString(cmd.LiteralBodyB64)
				if err != nil {
					// Validate already checked this; defensive.
					return nil, true
				}
				return decoded, true
			}
			if cmd.LiteralBody != "" {
				return []byte(cmd.LiteralBody), true
			}
			return nil, false
		}

		// emitCommandWithLiteral handles the case where a client
		// command itself carries a literal body (e.g. "APPEND INBOX
		// (\\Seen) {100}" followed by 100 bytes of email). The
		// command line is emitted first, then the literal body bytes
		// are emitted as additional PSH-ACK segments. The "{N}" prefix
		// is part of the user-provided Cmd string (per design §7.3
		// the user includes "{N}" in the Cmd; the planner synthesizes
		// the literal bytes that follow).
		//
		// NOTE: this is the C-IMAP-1.6 pattern. When Cmd ends with
		// "{N}" and LiteralBody / LiteralBodyB64 / FileSource is set,
		// the planner emits the command line (with the {N} prefix)
		// then the literal body bytes.
		emitCommandWithOptionalLiteral := func(cmd core.IMAPCommand, tag string) {
			if cmd.Cmd == "" {
				return
			}
			line := formatCommandLine(tag, cmd.Cmd) + "\r\n"
			clientSeq = emitData("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, []byte(line))

			// If the command ends with "{N}" and a literal source is
			// set, emit the literal body bytes as additional PSH-ACK
			// segments up (client -> server).
			if hasLiteralPlaceholder(cmd.Cmd) {
				if body, ok := resolveLiteral(cmd); ok {
					if len(body) > 0 {
						clientSeq = emitData("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, body)
					}
				}
			}
		}

		// emitResponses emits each server response in order. When a
		// response contains the literal placeholder "{N}" (e.g.
		// "* 1 FETCH (BODY[] {10000}"), the planner synthesizes the
		// literal body bytes that follow the placeholder. The
		// placeholder syntax is "{N}" where N is the byte count; the
		// planner replaces "{N}" with "{<actual-len>}\r\n" then emits
		// the literal body bytes, then continues with the rest of
		// the response. The CRLF that follows the literal bytes is
		// the user's responsibility (modeled as part of the next
		// Responses entry or appended by the planner when the literal
		// is the last thing in the response).
		//
		// For the C-IMAP-1.6 "{0}" case (empty literal), the planner
		// emits "{0}\r\n\r\n" — the literal header + empty body + the
		// trailing CRLF that closes the response line. This matches
		// the design §5.6 contract.
		//
		// hasLiteral is determined per-response by checking for the
		// "{N}" placeholder, NOT by checking whether a literal source
		// is set. This is so that "{0}" in a response with no
		// LiteralBody/LiteralBodyB64/FileSource still produces the
		// correct "{0}\r\n\r\n" wire format (edge case C-IMAP-1.6).
		// When a literal source IS set, its bytes are used; when not,
		// the literal body is empty (zero bytes).
		emitResponses := func(cmd core.IMAPCommand, tag string, cancelAfter int) {
			literalBody, _ := resolveLiteral(cmd)
			cancelEmitted := false
			for j, resp := range cmd.Responses {
				// Cancel after N responses (edge case C-IMAP-1.3):
				// after the CancelAfterResponses-th response, the
				// client sends "*\r\n" to cancel the in-progress
				// AUTHENTICATE.
				if cancelAfter > 0 && j == cancelAfter && !cancelEmitted {
					clientSeq = emitData("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, []byte(AuthCancelLine))
					cancelEmitted = true
				}

				if hasLiteralPlaceholder(resp) {
					// Replace "{N}" with "{<len>}\r\n", emit the
					// response header, then emit the literal body
					// bytes (if any), then emit a trailing "\r\n"
					// that closes the response.
					replaced := replaceLiteralPlaceholder(resp, len(literalBody))
					payload := []byte(replaced + "\r\n")
					serverSeq = emitData("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, payload)
					if len(literalBody) > 0 {
						serverSeq = emitData("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, literalBody)
					}
					// Trailing CRLF closes the FETCH response line
					// per RFC 9051 §2.2.4 (literal is followed by
					// the rest of the response; if the literal is
					// the last thing, a CRLF closes the line).
					serverSeq = emitData("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, []byte("\r\n"))
				} else {
					// Single-line response: append CRLF.
					payload := []byte(resp + "\r\n")
					serverSeq = emitData("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, payload)
				}
			}

			// UIDCacheInvalidation (edge case C-IMAP-1.9): after the
			// command's normal responses, synthesize the
			// "* OK [HIGHESTMODSEQ 1] cache invalidated" untagged
			// response.
			if cmd.UIDCacheInvalidation {
				serverSeq = emitData("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, []byte(UIDCacheInvalidationResponse))
			}
		}

		// emitIDLE emits the IDLE mode sequence per RFC 2177:
		//   1. client "IDLE\r\n" (using the cmd's tag or auto)
		//   2. server "+ idling\r\n" continuation
		//   3. each IDLE.PushResponses as server push
		//   4. client "DONE\r\n" (or "<DoneTag> DONE\r\n")
		//   5. server done-response (typically "<tag> OK IDLE terminated")
		//   6. optional server timeout BYE per ServerTimeoutBehavior
		emitIDLE := func(cmd core.IMAPCommand, tag string) {
			idle := imapConfig.IDLE

			// 1. Client IDLE command.
			idleCmd := formatCommandLine(tag, "IDLE") + "\r\n"
			clientSeq = emitData("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, []byte(idleCmd))

			// 2. Server continuation.
			serverSeq = emitData("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, []byte(IDLEContuation))

			// 3. Server pushes.
			for _, push := range idle.PushResponses {
				serverSeq = emitData("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, []byte(push+"\r\n"))
			}

			// 4. Client DONE.
			doneTag := idle.DoneTag
			if doneTag == "" {
				doneTag = tag
			}
			var doneLine string
			if doneTag == tag {
				// RFC 2177 §4: DONE is untagged (no tag prefix).
				doneLine = IDLEDone
			} else {
				doneLine = doneTag + " DONE\r\n"
			}
			clientSeq = emitData("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, []byte(doneLine))

			// 5. Server done response.
			if idle.DoneResponse != "" {
				serverSeq = emitData("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, []byte(idle.DoneResponse+"\r\n"))
			}

			// 6. Optional server timeout BYE.
			switch idle.ServerTimeoutBehavior {
			case "close_after_idle":
				serverSeq = emitData("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, []byte(IDLETimeoutBye))
			case "keep_idle":
				serverSeq = emitData("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, []byte(IDLETimeoutBye))
			case "", "none":
				// no timeout BYE
			}
		}

		// --- IMAP command/response pairs ---
		//
		// PipelinedCommands (edge case C-IMAP-1.5): when true, all
		// commands are emitted first (back-to-back), then all
		// responses are emitted in command order. When false
		// (default), each command is followed by its responses
		// before the next command.
		if imapConfig.PipelinedCommands {
			// Phase 1: emit all commands.
			tags := make([]string, len(imapConfig.Commands))
			for i, cmd := range imapConfig.Commands {
				tag := cmd.Tag
				if tag == "" {
					tag = autoTag()
				}
				tags[i] = tag
				if cmd.Cmd != "" {
					emitCommandWithOptionalLiteral(cmd, tag)
				}
			}
			// Phase 2: emit all responses in command order.
			for i, cmd := range imapConfig.Commands {
				emitResponses(cmd, tags[i], cmd.CancelAfterResponses)
				if cmd.EmitIDLE && imapConfig.IDLE != nil {
					emitIDLE(cmd, tags[i])
				}
			}
		} else {
			// Default: each command followed by its responses.
			for _, cmd := range imapConfig.Commands {
				tag := cmd.Tag
				if tag == "" {
					tag = autoTag()
				}
				if cmd.Cmd != "" {
					emitCommandWithOptionalLiteral(cmd, tag)
				}
				emitResponses(cmd, tag, cmd.CancelAfterResponses)
				if cmd.EmitIDLE && imapConfig.IDLE != nil {
					emitIDLE(cmd, tag)
				}
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

// formatCommandLine combines tag and cmd into the wire format
// "<tag> <cmd>" per RFC 9051 §2.2.1. When cmd is empty, returns just
// the tag (should not happen in practice; callers skip empty cmds).
func formatCommandLine(tag, cmd string) string {
	if cmd == "" {
		return tag
	}
	return tag + " " + cmd
}

// hasLiteralPlaceholder returns true if s contains a "{N}" literal
// placeholder per RFC 9051 §2.5 / RFC 3501 §4.3. The placeholder syntax
// is "{" + digits + "}". We use a simple byte scan rather than regexp
// to keep the planner allocation-free.
func hasLiteralPlaceholder(s string) bool {
	i := 0
	for i < len(s) {
		if s[i] == '{' {
			j := i + 1
			for j < len(s) && s[j] >= '0' && s[j] <= '9' {
				j++
			}
			if j > i+1 && j < len(s) && s[j] == '}' {
				return true
			}
		}
		i++
	}
	return false
}

// replaceLiteralPlaceholder replaces the first "{N}" placeholder in s
// with "{<newLen>}\r\n". Used when synthesizing FETCH BODY[] responses
// where the actual literal body length is known at Plan time. The
// trailing "\r\n" is the literal header terminator per RFC 9051 §4.1.2
// (literal = "{" number "}" CRLF *CHAR8).
func replaceLiteralPlaceholder(s string, newLen int) string {
	i := 0
	for i < len(s) {
		if s[i] == '{' {
			j := i + 1
			for j < len(s) && s[j] >= '0' && s[j] <= '9' {
				j++
			}
			if j > i+1 && j < len(s) && s[j] == '}' {
				return s[:i] + fmt.Sprintf("{%d}\r\n", newLen) + s[j+1:]
			}
		}
		i++
	}
	return s
}

// hasNonASCII returns true if s contains any byte with the high bit set
// (>= 0x80). Used for the AllowUTF8Mailbox check (edge case C-IMAP-1.7).
func hasNonASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return true
		}
	}
	return false
}

// segmentByMSS splits payload into chunks of at most mss bytes. The last
// chunk may be smaller. A nil/empty payload returns a single empty chunk
// so the caller emits one PSH-ACK segment (matching the pre-segmentation
// behavior where an empty body still produced one response packet).
//
// Mirrors internal/protocol/http.segmentByMSS, ftp.segmentByMSS, and
// pop3.segmentByMSS — duplicated to avoid an import cycle.
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
// SACK-Permitted, matching real-world SYN capture characteristics.
// Mirrors internal/protocol/tcp.synOptions, http.synOptions,
// ftp.synOptions, and pop3.synOptions — duplicated to avoid an import
// cycle.
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
