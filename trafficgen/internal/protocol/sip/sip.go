// Package sip implements the SIP protocol planner.
//
// SIP (Session Initiation Protocol, RFC 3261) is a session-level protocol:
// a single TCP connection on port 5060 carries a sequence of signaling
// messages (INVITE → 100 → 180 → 200 → ACK → BYE → 200). The planner emits:
//
//  1. TCP 3-way handshake (SYN, SYN-ACK, ACK) with MSS/WinScale/SACK options.
//  2. Each SIPMessage in Dialog as a PSH-ACK payload. Messages longer than
//     MSS are segmented; each segment advances the sender's sequence number.
//  3. (Optional) RTP media sub-flow: when SIPConfig.Media is set AND a
//     message has EmitMedia=true, the planner emits N RTP frames as UDP
//     sub-flow packets. The sub-flow shares the parent's GroupID so it
//     routes to the same PacketWorker — wire order = emit order, so RTP
//     frames land between the ACK and the next message (usually BYE).
//  4. TCP 4-way teardown (FIN-ACK, ACK, FIN-ACK, ACK).
//
// All packets share the same 4-tuple (one flow). The sequence space is
// continuous per direction — the next message ACKs all prior bytes.
//
// Each SIPMessage is rendered as text per RFC 3261 §7:
//
//	request-line (or status-line) CRLF
//	header1 CRLF
//	header2 CRLF
//	...
//	CRLF
//	body
//
// Direction "up" = client→server (request), "down" = server→client
// (response). When the user leaves Direction empty, the planner infers
// it: Method set → up request; StatusCode set → down response.
//
// Content-Length is auto-appended when Body is non-empty AND the user
// did not supply a Content-Length header (matched case-insensitively).
// This matches the behavior of real SIP stacks, which always set
// Content-Length on requests with bodies.
//
// Dialog header completion: the RFC 3261 mandatory dialog headers
// (Call-ID, From, To, Via, CSeq — §8.1.1 / §20.8, and Max-Forwards for
// requests) are auto-appended to messages that omit them, derived from
// the dialog context (see completeDialogHeaders). The user's own
// headers always win (user > default > none), and a dialog in which no
// message carries a Call-ID renders every message verbatim.
package sip

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
)

const (
	DefaultTTL = 64
	// DefaultMSS mirrors internal/protocol/tcp.DefaultMSS and
	// internal/protocol/http.DefaultMSS / ftp.DefaultMSS (1460). Duplicated
	// here to avoid an import cycle. RFC 879 floor is 536; 1460 is the
	// Ethernet-friendly value used by Linux.
	DefaultMSS = 1460

	// MinMSS per RFC 879 (IP+TCP header 20+20+536 = 576-byte minimum
	// packet). Smaller values produce malformed SYNs or pathological
	// fragmentation.
	MinMSS = 536
)

// Planner implements the SIP protocol planner.
type Planner struct{}

// NewPlanner creates a new SIP planner.
func NewPlanner() *Planner { return &Planner{} }

// Name returns the protocol name.
func (p *Planner) Name() string { return "sip" }

// Validate validates a SIP flow spec.
func (p *Planner) Validate(spec core.FlowSpec) error {
	if spec.SrcIP != "" {
		if net.ParseIP(spec.SrcIP) == nil {
			return fmt.Errorf("invalid source IP: %s", spec.SrcIP)
		}
	}
	if spec.DstIP != "" {
		if net.ParseIP(spec.DstIP) == nil {
			return fmt.Errorf("invalid destination IP: %s", spec.DstIP)
		}
	}
	// MSS is a TCP transport parameter; it lives on TCPConfig (spec.TCP.MSS).
	if spec.TCP != nil && spec.TCP.MSS > 0 {
		if spec.TCP.MSS < MinMSS {
			return fmt.Errorf("MSS %d too small (min %d per RFC 879)", spec.TCP.MSS, MinMSS)
		}
	}
	return nil
}

// Plan generates packet configs for a SIP flow.
func (p *Planner) Plan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) {
	if err := p.Validate(spec); err != nil {
		return nil, err
	}

	configChan := make(chan core.PacketConfig, 256)

	go func() {
		defer close(configChan)

		flowID := fmt.Sprintf("%s-%s-%d-%d", spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort)

		sipConfig := spec.SIP
		if sipConfig == nil {
			sipConfig = &core.SIPConfig{}
		}

		effectiveTTL := spec.TTL
		if effectiveTTL == 0 {
			effectiveTTL = DefaultTTL
		}

		// Resolve MSS: 0 -> DefaultMSS (1460). MSS is a TCP transport
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

		// --- TCP handshake (SYN, SYN-ACK, ACK) ---
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
				L3:      l3,
				L4:      l4,
				Payload: payload,
			}
			configChan <- cfg
			packetIndex++
		}

		// SYN (client -> server)
		emit("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, 0, 0x02, nil)
		clientSeq++
		// SYN-ACK (server -> client)
		emit("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, 0x12, nil)
		serverSeq++
		// ACK (client -> server)
		emit("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, 0x10, nil)

		// emitData segments payload by MSS and emits each chunk as a
		// PSH-ACK in the given direction, advancing the sender's seq.
		emitData := func(direction, srcMAC, dstMAC, srcIP, dstIP string, srcPort, dstPort uint16, senderSeq, peerSeq uint32, payload []byte) (newSenderSeq uint32) {
			for _, seg := range segmentByMSS(payload, int(mss)) {
				emit(direction, srcMAC, dstMAC, srcIP, dstIP, srcPort, dstPort, senderSeq, peerSeq, 0x18, seg)
				senderSeq += uint32(len(seg))
			}
			return senderSeq
		}

		// --- SIP dialog (each message becomes one or more PSH-ACK segments) ---
		var dc dialogCtx
		for _, msg := range sipConfig.Dialog {
			completeDialogHeaders(&msg, &dc, spec)
			payload := renderSIPMessage(msg)
			if len(payload) == 0 {
				continue
			}
			direction := msg.Direction
			if direction == "" {
				direction = inferDirection(msg)
			}
			if direction != "up" && direction != "down" {
				continue
			}
			if direction == "up" {
				clientSeq = emitData("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, payload)
			} else {
				serverSeq = emitData("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, payload)
			}

			// Emit RTP media sub-flow after this message when the user
			// flagged it. The sub-flow is a UDP flow (separate 4-tuple)
			// but shares the parent's GroupID so it routes to the same
			// PacketWorker — wire order = emit order, so RTP frames land
			// between this message and the next (usually ACK → BYE).
			if msg.EmitMedia && sipConfig.Media != nil {
				emitSIPMedia(ctx, configChan, sipConfig.Media, spec, flowID, now, &packetIndex, nextIPID)
			}
		}

		// --- TCP teardown (FIN-ACK, ACK, FIN-ACK, ACK) ---
		// Client FIN
		emit("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, 0x11, nil)
		clientSeq++
		// Server ACK
		emit("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, 0x10, nil)
		// Server FIN
		emit("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, 0x11, nil)
		serverSeq++
		// Client ACK
		emit("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, 0x10, nil)
	}()

	return configChan, nil
}

// renderSIPMessage converts a SIPMessage into the RFC 3261 §7 wire format:
//
//	request-line or status-line CRLF
//	each header CRLF
//	CRLF (empty line separating headers from body)
//	body (if any)
//
// Content-Length is auto-appended when Body is non-empty AND the user did
// not supply one (matched case-insensitively on the header name). This
// matches real SIP stack behavior: requests/responses with bodies always
// carry Content-Length so the receiver knows where the next message starts
// (important for TCP transport where multiple SIP messages may share a
// connection).
func renderSIPMessage(msg core.SIPMessage) []byte {
	var b strings.Builder
	if msg.Method != "" {
		// Request-Line: Method SP Request-URI SP SIP-Version CRLF
		b.WriteString(msg.Method)
		b.WriteByte(' ')
		b.WriteString(msg.URI)
		b.WriteString(" SIP/2.0\r\n")
	} else if msg.StatusCode != 0 {
		// Status-Line: SIP-Version SP Status-Code SP Reason-Phrase CRLF
		b.WriteString("SIP/2.0 ")
		b.WriteString(fmt.Sprintf("%d ", msg.StatusCode))
		b.WriteString(msg.StatusText)
		b.WriteString("\r\n")
	} else {
		// Neither Method nor StatusCode — nothing to emit.
		return nil
	}

	// Headers. Track whether the user supplied Content-Length so we can
	// auto-append one when Body is non-empty and none was provided.
	hasContentLength := false
	for _, h := range msg.Headers {
		b.WriteString(h)
		b.WriteString("\r\n")
		// Header name is everything before the first colon; compare
		// case-insensitively per RFC 3261 §7.3.1.
		if idx := strings.Index(h, ":"); idx >= 0 {
			name := strings.TrimSpace(h[:idx])
			if strings.EqualFold(name, "Content-Length") {
				hasContentLength = true
			}
		}
	}

	if msg.Body != "" {
		if !hasContentLength {
			b.WriteString(fmt.Sprintf("Content-Length: %d\r\n", len(msg.Body)))
		}
		// Blank line separating headers from body.
		b.WriteString("\r\n")
		b.WriteString(msg.Body)
	} else {
		// No body: still need the blank line to terminate headers.
		b.WriteString("\r\n")
	}

	return []byte(b.String())
}

// dialogCtx tracks the dialog-scoped header values the planner inherits
// into messages that omit them. RFC 3261 §8.1.1 / §20.8: Call-ID, From,
// To, Via and CSeq are mandatory in every request and every response,
// and all messages of one dialog share the dialog's values (the ACK
// completes the INVITE's dialog — it must carry the INVITE's Call-ID).
//
// The context activates on the first Call-ID seen (normally the INVITE)
// and is only seeded from requests: a response echoes the request it
// answers — it never defines dialog values. While active, the planner
// appends the missing mandatory headers to each message; the user's own
// headers always win (user > default > none). When no message carries a
// Call-ID the context stays inactive and every message renders verbatim
// — the planner never invents a Call-ID (a dialog without one is the
// user's config choice, e.g. digest-auth REGISTER dialogs that supply
// only From).
type dialogCtx struct {
	active      bool   // a Call-ID has been seen in the dialog
	callID      string // dialog Call-ID (first occurrence wins)
	from        string // dialog From (first occurrence wins)
	to          string // dialog To (first occurrence wins)
	via         string // dialog Via (first occurrence wins; generated when none)
	maxForwards string // dialog Max-Forwards (first occurrence wins)

	inviteCSeq int    // CSeq number of the most recent INVITE
	cseqNext   int    // CSeq number of the last non-ACK/CANCEL request (0 before the INVITE)
	lastCSeq   string // full CSeq line of the last request (responses echo it)
	lastFrom   string // full From line of the last request (responses echo it)
	lastTo     string // full To line of the last request (responses echo it)
	lastVia    string // full Via line of the last request (responses echo it)
}

// completeDialogHeaders fills the RFC 3261 mandatory headers that a
// dialog message omits, deriving them from the dialog context carried in
// dc. Mutates msg.Headers in place (msg is a per-iteration copy in Plan,
// so the user's SIPConfig.Dialog is untouched). Messages without both
// Method and StatusCode are left alone — renderSIPMessage emits nothing
// for them anyway.
func completeDialogHeaders(msg *core.SIPMessage, dc *dialogCtx, spec core.FlowSpec) {
	isRequest := msg.Method != ""
	isResponse := !isRequest && msg.StatusCode != 0
	if !isRequest && !isResponse {
		return
	}

	// Seed the dialog context from request headers (first occurrence
	// wins). Responses only consume the context.
	if isRequest {
		if v, ok := findHeader(msg.Headers, "Call-ID"); ok && dc.callID == "" {
			dc.callID = v
			dc.active = true
		}
		if v, ok := findHeader(msg.Headers, "From"); ok && dc.from == "" {
			dc.from = v
		}
		if v, ok := findHeader(msg.Headers, "To"); ok && dc.to == "" {
			dc.to = v
		}
		if v, ok := findHeader(msg.Headers, "Via"); ok && dc.via == "" {
			dc.via = v
		}
		if v, ok := findHeader(msg.Headers, "Max-Forwards"); ok && dc.maxForwards == "" {
			dc.maxForwards = v
		}
	}

	if isRequest {
		completeRequestHeaders(msg, dc, spec)
	} else if dc.active {
		completeResponseHeaders(msg, dc)
	}
}

// completeRequestHeaders fills the mandatory request headers (RFC 3261
// §8.1.1: Via, From, To, Call-ID, CSeq, Max-Forwards) that the request
// omits, and advances the dialog CSeq state.
//
// CSeq rules: the CSeq method must match the request's method (§20.16).
// ACK-for-2xx and CANCEL reuse the INVITE's CSeq number (§13.2.2.4 for
// the ACK that completes an INVITE; §9.1 for CANCEL — it cancels the
// INVITE transaction, not a new one). Every other request — including a
// re-INVITE — starts a new transaction with the next CSeq number
// (§12.2.1.1, §14.1). A user-supplied CSeq always wins and re-syncs the
// counters so subsequent fills stay consistent with it.
func completeRequestHeaders(msg *core.SIPMessage, dc *dialogCtx, spec core.FlowSpec) {
	if line, ok := findHeader(msg.Headers, "CSeq"); ok {
		n := parseCSeqNumber(line)
		switch msg.Method {
		case "INVITE":
			dc.inviteCSeq, dc.cseqNext = n, n
		case "ACK", "CANCEL":
			// References the INVITE transaction; counters unchanged.
		default:
			dc.cseqNext = n
		}
		dc.lastCSeq = line
	} else if dc.active {
		n := dc.cseqNext
		switch msg.Method {
		case "INVITE":
			if n == 0 {
				n = 1
			} else {
				n++ // re-INVITE: new transaction, next number
			}
			dc.inviteCSeq, dc.cseqNext = n, n
		case "ACK", "CANCEL":
			n = dc.inviteCSeq
			if n == 0 {
				n = 1
			}
		default:
			if n == 0 {
				n = 1
			} else {
				n++
			}
			dc.cseqNext = n
		}
		line := fmt.Sprintf("CSeq: %d %s", n, msg.Method)
		msg.Headers = append(msg.Headers, line)
		dc.lastCSeq = line
	}

	if !dc.active {
		return
	}
	if _, ok := findHeader(msg.Headers, "Call-ID"); !ok {
		msg.Headers = append(msg.Headers, dc.callID)
	}
	if _, ok := findHeader(msg.Headers, "From"); !ok && dc.from != "" {
		msg.Headers = append(msg.Headers, dc.from)
	}
	if _, ok := findHeader(msg.Headers, "To"); !ok && dc.to != "" {
		msg.Headers = append(msg.Headers, dc.to)
	}
	if _, ok := findHeader(msg.Headers, "Via"); !ok {
		if dc.via == "" {
			dc.via = generateVia(spec)
		}
		msg.Headers = append(msg.Headers, dc.via)
	}
	if _, ok := findHeader(msg.Headers, "Max-Forwards"); !ok {
		mf := dc.maxForwards
		if mf == "" {
			mf = "Max-Forwards: 70" // RFC 3261 §20.22 default
		}
		msg.Headers = append(msg.Headers, mf)
	}

	// The response that answers this request echoes its headers
	// (RFC 3261 §8.1.3.2) — record them for completeResponseHeaders.
	dc.lastFrom, _ = findHeader(msg.Headers, "From")
	dc.lastTo, _ = findHeader(msg.Headers, "To")
	dc.lastVia, _ = findHeader(msg.Headers, "Via")
}

// completeResponseHeaders fills the mandatory response headers that the
// response omits by echoing the request it answers (RFC 3261 §8.1.3.2):
// same Call-ID, CSeq line (number AND method), From, To and Via.
func completeResponseHeaders(msg *core.SIPMessage, dc *dialogCtx) {
	if _, ok := findHeader(msg.Headers, "Call-ID"); !ok {
		msg.Headers = append(msg.Headers, dc.callID)
	}
	if _, ok := findHeader(msg.Headers, "From"); !ok && dc.lastFrom != "" {
		msg.Headers = append(msg.Headers, dc.lastFrom)
	}
	if _, ok := findHeader(msg.Headers, "To"); !ok && dc.lastTo != "" {
		msg.Headers = append(msg.Headers, dc.lastTo)
	}
	if _, ok := findHeader(msg.Headers, "Via"); !ok && dc.lastVia != "" {
		msg.Headers = append(msg.Headers, dc.lastVia)
	}
	if _, ok := findHeader(msg.Headers, "CSeq"); !ok && dc.lastCSeq != "" {
		msg.Headers = append(msg.Headers, dc.lastCSeq)
	}
}

// findHeader returns the full "Name: value" line of the first header
// with the given name, matched case-insensitively per RFC 3261 §7.3.1
// (the header name is everything before the first colon). The boolean
// reports presence; the line is the whole header, e.g.
// "Call-ID: sip1@example.com". Returns ("", false) when absent.
func findHeader(headers []string, name string) (string, bool) {
	for _, h := range headers {
		idx := strings.Index(h, ":")
		if idx < 0 {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(h[:idx]), name) {
			return h, true
		}
	}
	return "", false
}

// parseCSeqNumber extracts the leading sequence number from a CSeq
// header line ("CSeq: 1 INVITE" -> 1). Returns 0 when absent or
// malformed (the caller then falls back to its default numbering).
func parseCSeqNumber(line string) int {
	idx := strings.Index(line, ":")
	if idx < 0 {
		return 0
	}
	n := 0
	for _, c := range strings.TrimLeft(line[idx+1:], " \t") {
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + int(c-'0')
	}
	return n
}

// generateVia builds a Via header for the client when the dialog carries
// none. RFC 3261 §8.1.1.7: the branch parameter MUST begin with the
// magic cookie "z9hG4bK"; the sent-by field identifies the sender's
// address:port (bracketed for IPv6 literals per §19.1.1).
func generateVia(spec core.FlowSpec) string {
	sentBy := spec.SrcIP
	if strings.Contains(sentBy, ":") {
		sentBy = "[" + sentBy + "]"
	}
	return fmt.Sprintf("Via: SIP/2.0/TCP %s:%d;branch=z9hG4bK%08x", sentBy, spec.SrcPort, rand.Uint32())
}

// inferDirection returns "up" for requests (Method set) and "down" for
// responses (StatusCode set). When neither is set the caller rejects the
// message.
func inferDirection(msg core.SIPMessage) string {
	if msg.Method != "" {
		return "up"
	}
	if msg.StatusCode != 0 {
		return "down"
	}
	return ""
}

// segmentByMSS splits payload into chunks of at most mss bytes. The last
// chunk may be smaller. A nil/empty payload returns a single empty chunk
// so the caller emits one PSH-ACK segment.
//
// Mirrors internal/protocol/http.segmentByMSS and ftp.segmentByMSS —
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
// SACK-Permitted. Mirrors internal/protocol/tcp.synOptions,
// internal/protocol/http.synOptions, and internal/protocol/ftp.synOptions
// — duplicated to avoid an import cycle.
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

// emitSIPMedia emits the RTP media sub-flow. Each RTP frame is one UDP
// datagram carrying a 12-byte RTP header (RFC 3550 §5.1) + FrameSize
// bytes of payload. Frames flow in the direction given by media.Direction
// (default "up" = caller→callee). Real RTP is bidirectional; users model
// each direction with one SIPMedia invocation.
//
// Port derivation priority (so the RTP 4-tuple matches what the SDP body
// actually advertised — without this, a DPI can't associate the RTP stream
// with the SIP signaling):
//  1. Explicit user override (media.SrcPort / media.DstPort).
//  2. Parsed from SDP body "m=audio <port>" lines in the SIP dialog
//     (INVITE advertises the caller's RTP port; 200 OK advertises the
//     callee's). The up-direction (caller→callee) SrcPort comes from
//     INVITE's m=, DstPort from 200 OK's m=. The down-direction swaps them.
//  3. Hardcoded fallback (5004, the standard RTP audio port).
//
// Per RFC 3550 §5.1, RTP sequence number and timestamp start at RANDOM
// values (not 0) to mitigate off-path spoofing and known-plaintext attacks.
// We use rand.Uint32() for both initial values.
//
// Timestamps increment by FrameSize per packet (frame samples at the
// RTP clock rate = SampleRate). E.g. G.711 20ms @ 8kHz: FrameSize=160,
// so timestamp += 160 per packet.
//
// All RTP frames share the FlowID "{parent}:rtp" so they resequence
// together at the PacketWorker — one RTP stream, one flow.
//
// FileSource resolution (Task 12):
//   - media.FileSource != nil -> resolve bytes via PayloadCache.GetOrLoad
//     from the cache injected through WithPayloadCache. The bytes are
//     split into FrameSize-sized chunks; each RTP frame carries one
//     chunk (the last chunk may be smaller). When FrameSize <= 0 the
//     whole bytes go on the first frame.
//   - media.FileSource == nil -> behavior unchanged (synthesize zero
//     bytes of length FrameSize per frame).
//
// When FileSource is set but no cache is injected (e.g. a unit test that
// forgot WithPayloadCache, or a controller path that doesn't wire the
// cache yet), the function returns WITHOUT emitting the RTP sub-flow
// rather than silently falling through to the synthesized zero-byte
// payload. Falling through would violate the FileSource > inline
// precedence contract. The production engine (Task 13) always injects
// the cache.
//
// Binary payloads (NUL bytes or invalid UTF-8 per core.IsText) ride
// through directly in the RTP UDP payload — the inline-RTP path builds
// udpPayload as []byte, no JSON string-field marshalling. (Compare FTP,
// which routes through SubFlowSpec.Payload / PayloadB64 and so needs
// core.IsText to pick the field.) core.IsText is NOT called anywhere
// in SIP today because RTP builds []byte directly without SubFlowSpec
// indirection; future refactors that move RTP onto a SubFlowSpec will
// use it.
func emitSIPMedia(
	ctx context.Context,
	configChan chan<- core.PacketConfig,
	media *core.SIPMedia,
	spec core.FlowSpec,
	parentFlowID string,
	now time.Time,
	packetIndex *uint64,
	nextIPID func() uint16,
) {
	frames := media.Frames
	if frames <= 0 {
		frames = 1
	}

	// Resolve RTP frame payload bytes when FileSource is set. The bytes
	// are split into FrameSize-sized chunks; each RTP frame carries one
	// chunk (the last chunk may be smaller). When FrameSize <= 0 the
	// whole bytes go on a single frame (do not divide by zero).
	//
	// When FileSource is set but no cache is in the context, return
	// without emitting. Falling through to the zero-byte synthesized
	// path would violate the FileSource > inline precedence contract.
	var rtpFramePayloads [][]byte
	if media.FileSource != nil {
		pc := core.PayloadCacheFrom(ctx)
		if pc == nil {
			return
		}
		bytes, _ := pc.GetOrLoad(ctx, *media.FileSource)
		rtpFramePayloads = splitRTPFrames(bytes, media.FrameSize)
		// Override the legacy frame-count math: the number of RTP
		// frames is driven by the bytes/FrameSize split, NOT by
		// SIPMedia.Frames. The user sets FrameSize to chunk the
		// bytes; Frames is informational here. If the split yields
		// fewer frames than Frames, we emit fewer (we don't pad with
		// zero-byte frames — that would misrepresent the bytes the
		// cache resolved). If the split yields more, we emit them all
		// (more bytes than expected is a user-config error, but we
		// honor the bytes).
		frames = len(rtpFramePayloads)
		if frames == 0 {
			// bytes was empty — still emit one frame so the RTP
			// stream is non-empty (matches legacy Frames=0 -> 1
			// defaulting for the synthesized path).
			frames = 1
		}
	}

	// Scan the SIP dialog for SDP-declared media ports. INVITE's m= line
	// advertises the caller's RTP port; 200 OK's m= advertises the callee's.
	// For "up" direction (caller→callee): SrcPort=caller's (INVITE),
	// DstPort=callee's (200 OK). For "down": swap.
	//
	// KNOWN LIMITATION: this scans the WHOLE dialog, not just the prefix
	// up to the current EmitMedia index. So a re-INVITE that appears
	// AFTER this EmitMedia point still affects this emit's ports
	// (future-bleed). Fixing this would require passing the current
	// dialog index into emitSIPMedia, which is a larger refactor.
	invitePort, ok200Port := scanSDPMediaPorts(spec.SIP.Dialog)

	srcPort := media.SrcPort
	if srcPort == 0 {
		srcPort = invitePort
	}
	if srcPort == 0 {
		srcPort = 5004
	}
	dstPort := media.DstPort
	if dstPort == 0 {
		dstPort = ok200Port
	}
	if dstPort == 0 {
		dstPort = 5004
	}
	pt := media.PayloadType // 0 is a valid PT (PCMU), so no defaulting.
	sampleRate := media.SampleRate
	if sampleRate == 0 {
		sampleRate = 8000
	}
	frameSize := media.FrameSize
	if frameSize == 0 {
		frameSize = 160
	}
	dir := media.Direction
	if dir == "" {
		// Derive the RTP direction from the SDP body's directional
		// media attribute (a=sendonly / a=recvonly / a=sendrecv) per
		// RFC 3264 §5.1. We scan the WHOLE dialog (same limitation as
		// scanSDPMediaPorts) for the first a= direction attribute; the
		// INVITE's attribute describes what the offerer (caller) does:
		// sendonly → caller sends → "up"; recvonly → caller receives →
		// callee sends → "down"; sendrecv → bidirectional, default "up".
		// When no a= attribute is present, parseSDPDirection returns ""
		// and we fall back to the original "up" default.
		dir = scanSDPDirection(spec.SIP.Dialog)
	}
	if dir == "" {
		dir = "up"
	}

	// Per RFC 3550 §5.1, seq and timestamp start at random values.
	ssrc := rand.Uint32()
	rtpSeq := uint16(rand.Uint32())
	rtpTimestamp := rand.Uint32()
	rtpFlowID := parentFlowID + ":rtp"

	// Direction determines L2/L3 tuple. "up" = caller→callee (spec.SrcIP →
	// spec.DstIP); "down" = callee→caller (swap). Case-insensitive to
	// match FTP's Mode comparison (ftp.go:445 strings.EqualFold) — a user
	// setting "Down" or "DOWN" should not silently fall through to "up".
	var srcMAC, dstMAC, srcIP, dstIP string
	var srcPortWire, dstPortWire uint16
	if strings.EqualFold(dir, "down") {
		srcMAC, dstMAC = spec.DstMAC, spec.SrcMAC
		srcIP, dstIP = spec.DstIP, spec.SrcIP
		srcPortWire, dstPortWire = dstPort, srcPort
	} else {
		srcMAC, dstMAC = spec.SrcMAC, spec.DstMAC
		srcIP, dstIP = spec.SrcIP, spec.DstIP
		srcPortWire, dstPortWire = srcPort, dstPort
	}

	for i := 0; i < frames; i++ {
		// RTP header (12 bytes, no CSRC or extension):
		//   V=2, P=0, X=0, CC=0 -> byte 0 = 0x80
		//   M=0, PT=pt -> byte 1 = pt & 0x7F
		//   Sequence number (16-bit) -> bytes 2-3
		//   Timestamp (32-bit) -> bytes 4-7
		//   SSRC (32-bit) -> bytes 8-11
		// Audio payload follows. When FileSource resolved bytes, the
		// payload is the i-th FrameSize-sized chunk (length may vary).
		// Otherwise, the payload is frameSize bytes of zeros — a
		// placeholder so DPI sees the right packet size.
		var framePayload []byte
		if media.FileSource != nil {
			if i < len(rtpFramePayloads) {
				framePayload = rtpFramePayloads[i]
			}
		} else {
			framePayload = make([]byte, frameSize)
		}
		udpPayload := make([]byte, 12+len(framePayload))
		udpPayload[0] = 0x80 // V=2
		udpPayload[1] = pt & 0x7F
		udpPayload[2] = byte(rtpSeq >> 8)
		udpPayload[3] = byte(rtpSeq)
		udpPayload[4] = byte(rtpTimestamp >> 24)
		udpPayload[5] = byte(rtpTimestamp >> 16)
		udpPayload[6] = byte(rtpTimestamp >> 8)
		udpPayload[7] = byte(rtpTimestamp)
		udpPayload[8] = byte(ssrc >> 24)
		udpPayload[9] = byte(ssrc >> 16)
		udpPayload[10] = byte(ssrc >> 8)
		udpPayload[11] = byte(ssrc)
		copy(udpPayload[12:], framePayload)

		cfg := core.PacketConfig{
			FlowID:      rtpFlowID,
			PacketIndex: *packetIndex,
			Direction:   dir,
			Timestamp:   now,
			L2: core.L2Config{
				SrcMAC:    srcMAC,
				DstMAC:    dstMAC,
				EtherType: core.EtherTypeFor(srcIP),
			},
			L3:      core.L3Base(srcIP, dstIP, 17, effectiveTTLOf(spec), nextIPID(), spec),
			L4:      core.L4Config{Protocol: "udp", SrcPort: srcPortWire, DstPort: dstPortWire},
			Payload: udpPayload,
		}
		configChan <- cfg
		*packetIndex++
		rtpSeq++
		rtpTimestamp += uint32(frameSize)
	}

	// sampleRate is currently informational — we use it to compute the
	// timestamp increment, which is frameSize = sampleRate * frameDur.
	// The user sets frameSize directly, so we don't need sampleRate for
	// the math. We keep it on SIPMedia for future use (e.g. RTCP SR
	// generation, which needs the clock rate).
	_ = sampleRate
}

// sdpMediaPortRe matches an SDP "m=audio <port> ..." line per RFC 4566
// §5.14: the media field is "m=" type SP port SP proto [fmt] CRLF. We
// extract the port. Only "m=audio" is matched — video/application/data
// media types are skipped because the SIP planner only emits audio RTP
// (PCMU/PCMA) today; matching m=video would silently capture a video
// port and produce an audio RTP flow on the wrong 4-tuple.
//
// The separator between "m=audio" and the port is `[ \t]+` (space or
// tab, but NOT \r or \n). A `\s+` here would match CRLF and extract a
// bogus port from the NEXT line of a malformed body like
// "m=audio\r\n5004" — the port belongs to no media line at all.
var sdpMediaPortRe = regexp.MustCompile(`(?m)^m=audio[ \t]+(\d+)`)

// parseSDPMediaPort scans an SDP body for the first "m=<type> <port>" line
// and returns the port. Returns 0 if not found.
// Example: "m=audio 5004 RTP/AVP 0" -> 5004.
func parseSDPMediaPort(body string) uint16 {
	m := sdpMediaPortRe.FindStringSubmatch(body)
	if m == nil {
		return 0
	}
	p, err := strconv.Atoi(m[1])
	if err != nil || p < 0 || p > 65535 {
		return 0
	}
	return uint16(p)
}

// sdpDirectionRe matches an SDP "a=<direction>" attribute line per RFC 4566
// §6.4.1 + RFC 3264 §5.1. The direction is one of sendonly / recvonly /
// sendrecv / inactive. The SDP attribute line format is "a=<value>" (with an
// equals sign, NOT a space) per RFC 4566 §5.13: "a=<attribute>" or
// "a=<attribute>:<value>". We match case-insensitively and anchor the line
// end so "a=sendonly\r\nfoo" doesn't spuriously match a hypothetical
// "a=sendonlyx". The `[ \t]*` before the line terminator tolerates trailing
// whitespace; `\r?$` accepts CRLF or bare LF.
var sdpDirectionRe = regexp.MustCompile(`(?im)^[ \t]*a=(sendonly|recvonly|sendrecv|inactive)[ \t]*\r?$`)

// parseSDPDirection scans an SDP body for the first directional media
// attribute (a=sendonly / a=recvonly / a=sendrecv / a=inactive) and returns
// the RTP flow direction the offerer's attribute implies:
//
//   - "sendonly": the offerer (caller, who sent the INVITE) SENDS media, so
//     RTP flows caller→callee = "up".
//   - "recvonly": the offerer only RECEIVES, so the answerer (callee) sends
//     → RTP flows callee→caller = "down".
//   - "sendrecv": bidirectional; a single SIPMedia models one direction, so
//     we return "up" (the caller-side stream default).
//   - "inactive": no media flows either way per RFC 3264 §5.1. We return ""
//     (empty) so the caller (emitSIPMedia) can decide; the current contract
//     is that one SIPMedia always emits frames, so "" falls through to the
//     existing "up" default rather than silently suppressing RTP. A future
//     enhancement could make inactive skip the sub-flow.
//   - absent: no a= direction attribute. Returns "" (caller defaults to "up").
//
// The mapping comes from RFC 3264 §5.1: the direction attribute describes
// what the offerer (INVITE sender) will do with media. sendonly from the
// offerer means the offerer sends; recvonly means the offerer wants to
// receive (so the answerer sends).
func parseSDPDirection(body string) string {
	m := sdpDirectionRe.FindStringSubmatch(body)
	if m == nil {
		return ""
	}
	switch strings.ToLower(m[1]) {
	case "sendonly":
		return "up"
	case "recvonly":
		return "down"
	case "sendrecv":
		return "up"
	case "inactive":
		return "" // fall through to caller's default ("up")
	}
	return ""
}

// scanSDPMediaPorts walks the SIP dialog and returns (invitePort, ok200Port)
// — the RTP media ports declared in the INVITE's SDP body and the 200 OK's
// SDP body. Returns 0 for either if the corresponding message has no SDP
// body or no m= line.
//
// Per RFC 3261 §13.2.1, the INVITE's SDP advertises the caller's RTP
// receive port; the 200 OK's SDP advertises the callee's. For "up"
// direction (caller→callee) the caller is the source so SrcPort=invitePort,
// and the callee is the destination so DstPort=ok200Port.
//
// State machine (tracks "what's the next 200 OK responding to?"):
//   - INVITE: sets lastWasInvite=true AND clears any pending non-INVITE
//     method (a new INVITE supersedes any prior transaction per RFC 3261
//     §17.2.1 — the prior PRACK/UPDATE transaction's 200 OK, if it
//     arrives late, must NOT be misattributed to this new INVITE).
//     Captures invitePort (last-wins for re-INVITE) if SDP present.
//   - Non-INVITE request (PRACK/UPDATE/BYE/OPTIONS/etc.): sets
//     pendingNonInviteMethod. The next 200 OK belongs to this transaction,
//     not the INVITE — so its SDP is NOT captured as ok200Port.
//   - 200 OK:
//     - If pendingNonInviteMethod set AND the pending method is UPDATE
//       (RFC 3311 session modification): capture ok200Port (the callee's
//       updated port — UPDATE modifies the session, so its answer is the
//       new media port). Consume pending.
//     - Else if pendingNonInviteMethod set: consume pending but DO NOT
//       capture ok200Port (e.g. 200-to-PRACK's SDP is the PRACK's answer,
//       not the INVITE's callee port per RFC 3262 §3).
//     - Else if lastWasInvite: this is 200-to-INVITE. Capture ok200Port
//       (last-wins) if SDP present. Consume lastWasInvite.
//   - ACK: delayed-offer path — captures invitePort if SDP present.
//     Resets both flags.
//
// This correctly handles RFC 3262 early media via PRACK: a 200-to-PRACK
// with SDP arriving before 200-to-INVITE is NOT misattributed to the
// INVITE transaction (which would pollute ok200Port with the PRACK's
// answer port).
//
// LIMITATION 1: when both 200-to-INVITE and 200-to-PRACK are pending
// (both transactions in flight), the state machine attributes the FIRST
// arriving 200 OK to the most recently sent request. If 200-to-INVITE
// arrives BEFORE 200-to-PRACK (network reordering), it is misattributed
// to PRACK and the real 200-to-PRACK's SDP is captured as ok200Port.
// Correctly disambiguating requires CSeq/Via headers, which are not
// modeled here. The user can work around this with explicit media.DstPort.
//
// LIMITATION 2: early-media port from reliable 1xx (RFC 3262 §3,
// e.g. 183 with SDP) is NOT captured. The callee's actual RTP port in
// an early-media session comes from the 183, but this scan returns it
// as 0 — emitSIPMedia then falls back to 5004 for DstPort, producing
// RTP to the wrong port. The user must set explicit media.DstPort for
// early-media scenarios.
func scanSDPMediaPorts(dialog []core.SIPMessage) (invitePort, ok200Port uint16) {
	lastWasInvite := false
	var pendingNonInviteMethod string
	for _, msg := range dialog {
		port := parseSDPMediaPort(msg.Body) // 0 for empty/non-matching body
		if msg.Method == "INVITE" {
			lastWasInvite = true
			// A new INVITE supersedes any pending non-INVITE transaction:
			// its 200 OK is the callee's answer, not the prior PRACK's.
			// Without this clear, PRACK → INVITE → 200-to-INVITE would
			// misattribute the 200-to-INVITE to the stale PRACK.
			pendingNonInviteMethod = ""
			if port != 0 {
				invitePort = port // last-wins for re-INVITE
			}
			continue
		}
		// Non-INVITE request (PRACK/UPDATE/BYE/OPTIONS/INFO/REFER/...).
		// The next 200 OK responds to this method, not the INVITE.
		if msg.Method != "" && msg.Method != "ACK" {
			pendingNonInviteMethod = msg.Method
			continue
		}
		if msg.StatusCode == 200 {
			if pendingNonInviteMethod != "" {
				if strings.EqualFold(pendingNonInviteMethod, "UPDATE") && port != 0 {
					// 200-to-UPDATE per RFC 3311 is a session-modification
					// answer — the callee's new RTP port. Update ok200Port
					// (last-wins) so mid-call port changes propagate.
					ok200Port = port
				}
				// For all non-UPDATE non-INVITE 200 OKs (PRACK, OPTIONS,
				// BYE, etc.), the SDP answer belongs to that transaction,
				// NOT to the INVITE's callee — discard it.
				pendingNonInviteMethod = ""
			} else if lastWasInvite {
				// 200-to-INVITE. Capture callee's port (last-wins). Consume
				// the flag so a subsequent 200-to-non-INVITE isn't
				// misattributed to a stale INVITE.
				if port != 0 {
					ok200Port = port
				}
				lastWasInvite = false
			}
			continue
		}
		if msg.Method == "ACK" {
			// Delayed-offer: INVITE had no SDP, ACK carries the answer.
			// Always update (last-wins) so re-INVITE delayed-offer picks
			// up the new caller port rather than holding the stale first
			// INVITE's port.
			if port != 0 {
				invitePort = port
			}
			lastWasInvite = false
			pendingNonInviteMethod = ""
			continue
		}
		// 1xx provisional responses (100/180/183) and unknown message
		// shapes fall through here. They don't affect the flags. RFC 3262
		// reliable provisionals with SDP (183) carry the callee's early
		// media port, but scanSDPMediaPorts's contract is "200 OK's SDP
		// body" — early-media port extraction is left to the user via
		// explicit media.DstPort override.
	}
	return invitePort, ok200Port
}

// scanSDPDirection walks the SIP dialog searching for the first SDP body
// that carries a directional media attribute (a=sendonly / a=recvonly /
// a=sendrecv / a=inactive) and returns the implied RTP flow direction
// (via parseSDPDirection). Returns "" when no a= attribute is present in
// any body, so the caller falls back to its existing default ("up").
//
// We scan INVITE and ACK bodies (the offerer-side messages per RFC 3264
// §5.1 — the direction attribute describes what the offerer, i.e. the
// INVITE/ACK sender, will do with media). 200-OK answerer bodies are NOT
// scanned: the answerer's a= attribute may flip direction per RFC 3264
// §6.1 (an answerer can answer sendonly→recvonly), but modeling that
// requires correlating offer/answer pairs — the user controls the final
// direction via media.Direction when they need answerer-driven semantics.
//
// KNOWN LIMITATION (mirrors scanSDPMediaPorts): this scans the WHOLE
// dialog, not just the prefix up to the current EmitMedia point, so a
// re-INVITE's a= attribute affects the first emit too (future-bleed).
// Use explicit media.Direction to override.
func scanSDPDirection(dialog []core.SIPMessage) string {
	for _, msg := range dialog {
		// Only offerer-side messages describe the offerer's direction.
		// INVITE is the initial offer; ACK is the delayed-offer offer.
		if msg.Method != "INVITE" && msg.Method != "ACK" {
			continue
		}
		if d := parseSDPDirection(msg.Body); d != "" {
			return d
		}
	}
	return ""
}

// effectiveTTLOf returns the spec's TTL or DefaultTTL if unset. Kept here
// to avoid importing DefaultTTL from the planner's outer scope into the
// sub-flow emit function (which doesn't close over effectiveTTL).
func effectiveTTLOf(spec core.FlowSpec) uint8 {
	if spec.TTL == 0 {
		return DefaultTTL
	}
	return spec.TTL
}

// splitRTPFrames splits a byte slice into FrameSize-sized chunks for RTP
// payload carriage. The last chunk may be smaller than FrameSize. A
// FrameSize <= 0 yields a single chunk containing the whole bytes (do not
// divide by zero; the RTP stream carries all bytes in one frame).
//
// Empty input yields a single empty chunk so the caller still emits one
// RTP frame (matching the legacy Frames=0 -> 1 defaulting for the
// synthesized zero-byte path).
//
// Mirrors the chunking behavior of segmentByMSS but does NOT collapse
// empty input to a single empty chunk when the input is nil — we want
// the bytes to drive the frame count. Caller handles the empty case
// explicitly (returns frames=1).
//
// splitRTPFrames is the only helper needed for the inline-RTP path.
// The SubFlowSpec-based carriage (FTP-style Payload / PayloadB64
// selection via core.IsText) is not needed here because emitSIPMedia
// builds udpPayload directly (no SubFlowSpec indirection). Task 13
// follow-up: if emitSIPMedia is refactored to use SubFlowSpec, add a
// helper that mirrors ftp's Payload / PayloadB64 selection.
func splitRTPFrames(b []byte, frameSize int) [][]byte {
	if frameSize <= 0 {
		return [][]byte{b}
	}
	if len(b) == 0 {
		return [][]byte{{}}
	}
	chunks := make([][]byte, 0, (len(b)+frameSize-1)/frameSize)
	for len(b) > 0 {
		n := len(b)
		if n > frameSize {
			n = frameSize
		}
		chunks = append(chunks, b[:n])
		b = b[n:]
	}
	return chunks
}
