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
		for _, msg := range sipConfig.Dialog {
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
				emitSIPMedia(configChan, sipConfig.Media, spec, flowID, now, &packetIndex, nextIPID)
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
func emitSIPMedia(
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

	// Scan the SIP dialog for SDP-declared media ports. INVITE's m= line
	// advertises the caller's RTP port; 200 OK's m= advertises the callee's.
	// For "up" direction (caller→callee): SrcPort=caller's (INVITE),
	// DstPort=callee's (200 OK). For "down": swap.
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
		dir = "up"
	}

	// Per RFC 3550 §5.1, seq and timestamp start at random values.
	ssrc := rand.Uint32()
	rtpSeq := uint16(rand.Uint32())
	rtpTimestamp := rand.Uint32()
	rtpFlowID := parentFlowID + ":rtp"

	// Direction determines L2/L3 tuple. "up" = caller→callee (spec.SrcIP →
	// spec.DstIP); "down" = callee→caller (swap).
	var srcMAC, dstMAC, srcIP, dstIP string
	var srcPortWire, dstPortWire uint16
	if dir == "down" {
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
		// Audio payload follows (frameSize bytes of zeros — placeholder
		// samples; for traffic generation we only need the bytes present
		// so DPI sees the right packet size).
		udpPayload := make([]byte, 12+frameSize)
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
		// bytes 12: are zero (placeholder audio payload).

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

// sdpMediaPortRe matches an SDP "m=audio <port> ..." line per RFC 4566 §5.14:
// the media field is "m=" type SP port SP proto [fmt] CRLF. We extract the
// port. Other media types (m=video, m=application) also match; we capture
// any "m=<type> <port>" line so this works for non-audio media too.
var sdpMediaPortRe = regexp.MustCompile(`(?m)^m=\w+\s+(\d+)`)

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

// scanSDPMediaPorts walks the SIP dialog and returns (invitePort, ok200Port)
// — the RTP media ports declared in the INVITE's SDP body and the 200 OK's
// SDP body. Returns 0 for either if the corresponding message has no SDP
// body or no m= line.
//
// Per RFC 3261 §13.2.1, the INVITE's SDP advertises the caller's RTP
// receive port; the 200 OK's SDP advertises the callee's. For "up"
// direction (caller→callee) the caller is the source so SrcPort=invitePort,
// and the callee is the destination so DstPort=ok200Port.
func scanSDPMediaPorts(dialog []core.SIPMessage) (invitePort, ok200Port uint16) {
	for _, msg := range dialog {
		if msg.Body == "" {
			continue
		}
		port := parseSDPMediaPort(msg.Body)
		if port == 0 {
			continue
		}
		if msg.Method == "INVITE" && invitePort == 0 {
			invitePort = port
		}
		if msg.StatusCode == 200 && ok200Port == 0 {
			ok200Port = port
		}
	}
	return invitePort, ok200Port
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
