// Package sip implements the SIP protocol planner.
//
// SIP (Session Initiation Protocol, RFC 3261) is a session-level protocol:
// a single TCP connection on port 5060 carries a sequence of signaling
// messages (INVITE → 100 → 180 → 200 → ACK → BYE → 200). The planner emits:
//
//  1. TCP 3-way handshake (SYN, SYN-ACK, ACK) with MSS/WinScale/SACK options.
//  2. Each SIPMessage in Dialog as a PSH-ACK payload. Messages longer than
//     MSS are segmented; each segment advances the sender's sequence number.
//  3. TCP 4-way teardown (FIN-ACK, ACK, FIN-ACK, ACK).
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
// This planner does NOT generate RTP media. RTP runs over UDP on a
// separate 4-tuple (negotiated inside the SDP body of INVITE/200 OK);
// users who need media run a second trafficgen flow with protocol=udp.
// The SIP signaling session is what defines a "SIP flow" for testing.
package sip

import (
	"context"
	"fmt"
	"math/rand"
	"net"
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
					EtherType: 0x0800,
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
