// Package smtp implements the SMTP protocol planner (RFC 5321).
//
// SMTP (Simple Mail Transfer Protocol, RFC 5321) is a session-level
// text protocol: a single TCP connection on port 25 carries a sequence
// of command/response pairs. The planner emits:
//
//  1. TCP 3-way handshake (SYN, SYN-ACK, ACK) with MSS/WinScale/SACK
//     options.
//  2. Server banner (220 greeting) as the first PSH-ACK payload. When
//     SMTPConfig.Banner is empty the planner auto-generates
//     "220 <DstIP> ESMTP trafficgen".
//  3. Each SMTPCommand in Dialog: client command (PSH-ACK up) + server
//     response (PSH-ACK down). Payloads longer than MSS are segmented;
//     each segment advances the sender's sequence number by its byte
//     length, so the peer's next ACK covers all bytes.
//  4. TCP 4-way teardown (FIN-ACK, ACK, FIN-ACK, ACK).
//
// All packets share the same 4-tuple (one flow). The sequence space is
// continuous per direction - the next command ACKs all prior response
// bytes and vice versa.
//
// The planner plays back the user-provided Dialog verbatim. It does NOT
// implement a real SMTP state machine - this matches the trafficgen
// contract (synthesize test packets, not a real server). When Dialog is
// empty, a default session is emitted (HELO + MAIL FROM + RCPT TO +
// DATA + empty body + QUIT) so trivial specs produce a complete SMTP
// pcap.
//
// SMTP commands and responses are CRLF-terminated text per RFC 5321
// §2.3. The planner appends "\r\n" to every Cmd and Response. The
// DATA terminator "\r\n.\r\n" is the user's responsibility: write the
// body Cmd ending with "\r\n." and the planner's appended "\r\n"
// completes the terminator. Dot-stuffing (RFC 5321 §4.5.2) is also the
// user's responsibility - the planner emits body bytes verbatim so
// users control the exact wire format. See design_smtp.md §8.2.
//
// IPv6 / multicast MAC / VLAN behavior follows the unified convention
// at /tmp/l7_planner_design/multicast_ipv6_vlan.md. SMTP is "IP version
// transparent" (works over IPv4 or IPv6); the planner does not enforce
// IP version in Validate.
package smtp

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
)

const (
	DefaultTTL = 64
	// DefaultMSS mirrors internal/protocol/tcp.DefaultMSS and
	// internal/protocol/ftp.DefaultMSS (1460). Duplicated here to
	// avoid an import cycle. RFC 879 floor is 536; 1460 is the
	// Ethernet-friendly value used by Linux.
	DefaultMSS = 1460

	// MinMSS per RFC 879 (IP+TCP header 20+20+536 = 576-byte minimum
	// packet). Smaller values produce malformed SYNs or pathological
	// fragmentation.
	MinMSS = 536

	// DefaultPort is the canonical SMTP port (RFC 5321 §3.1). The
	// controller's mapToFlowSpec fills this in when the user omits
	// dst_port; the planner does not override it.
	DefaultPort = 25
)

// Planner implements the SMTP protocol planner.
type Planner struct{}

// NewPlanner creates a new SMTP planner.
func NewPlanner() *Planner { return &Planner{} }

// Name returns the protocol name.
func (p *Planner) Name() string { return "smtp" }

// Validate validates an SMTP flow spec. It is read-only: it does not
// modify spec. Default values (port 25, TTL 64, MSS 1460) are filled in
// by Plan entry or by the controller's mapToFlowSpec.
func (p *Planner) Validate(spec core.FlowSpec) error {
	if spec.SrcIP != "" {
		if net.ParseIP(spec.SrcIP) == nil {
			return fmt.Errorf("smtp: invalid SrcIP %q (not a valid IP address)", spec.SrcIP)
		}
	}
	if spec.DstIP != "" {
		if net.ParseIP(spec.DstIP) == nil {
			return fmt.Errorf("smtp: invalid DstIP %q (not a valid IP address)", spec.DstIP)
		}
	}
	// MSS is a TCP transport parameter; it lives on TCPConfig
	// (spec.TCP.MSS).
	if spec.TCP != nil && spec.TCP.MSS > 0 {
		if spec.TCP.MSS < MinMSS {
			return fmt.Errorf("smtp: TCP.MSS %d too small (min %d per RFC 879)", spec.TCP.MSS, MinMSS)
		}
	}
	// Port is NOT enforced here. SMTP defaults to 25 (set by
	// mapToFlowSpec), but submission (587) and SMTPS (465) are also
	// valid per validate_conventions.md §3.3. Enforcing port 25
	// exclusively would break submission/SMTPS test scenarios.
	return nil
}

// Plan generates packet configs for an SMTP flow.
func (p *Planner) Plan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) {
	if err := p.Validate(spec); err != nil {
		return nil, err
	}

	configChan := make(chan core.PacketConfig, 256)

	go func() {
		defer close(configChan)

		flowID := fmt.Sprintf("%s-%s-%d-%d", spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort)

		smtpConfig := spec.SMTP
		if smtpConfig == nil {
			smtpConfig = &core.SMTPConfig{}
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
			// Pre-write Metadata["group_id"] when the spec carries a
			// GroupID strategy, mirroring ftp.go's pattern. The worker
			// overwrites this at worker.go with the flowIdx-resolved
			// gID; for nil GroupID we leave Metadata nil.
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

		// --- Server banner ---
		// When Banner is empty, auto-generate "220 <DstIP> ESMTP
		// trafficgen" per design_smtp.md §8.6. This ensures a
		// well-formed SMTP pcap even when the user provides an empty
		// Banner.
		banner := smtpConfig.Banner
		if banner == "" {
			banner = fmt.Sprintf("220 %s ESMTP trafficgen", spec.DstIP)
		}
		// Banner is always emitted (auto-generated when empty). The
		// 220 greeting is the first server->client payload after the
		// handshake and is required for a valid SMTP session per
		// RFC 5321 §3.1.
		{
			payload := []byte(banner + "\r\n")
			serverSeq = emitData("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, payload)
		}

		// --- SMTP command/response pairs ---
		dialog := smtpConfig.Dialog
		if len(dialog) == 0 {
			// Default session per design_smtp.md §6.6: HELO + MAIL +
			// RCPT + DATA + empty body + QUIT.
			dialog = defaultDialog()
		}

		for _, cmd := range dialog {
			// Client command (client -> server). Append CRLF per RFC
			// 5321 §2.3. Empty Cmd is skipped (lets users model
			// server-only turns, e.g. the 354 response after DATA).
			if cmd.Cmd != "" {
				direction := cmd.Direction
				if direction == "" {
					direction = "up"
				}
				payload := []byte(cmd.Cmd + "\r\n")
				if direction == "down" {
					serverSeq = emitData("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, payload)
				} else {
					clientSeq = emitData("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, payload)
				}
			}
			// Server response (server -> client). Append CRLF per RFC
			// 5321 §4.2. Empty Response is skipped (lets users model
			// client-only turns, e.g. the DATA body itself).
			if cmd.Response != "" {
				direction := cmd.Direction
				if direction == "" {
					direction = "down"
				}
				payload := []byte(cmd.Response + "\r\n")
				if direction == "up" {
					clientSeq = emitData("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, payload)
				} else {
					serverSeq = emitData("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, payload)
				}
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

// defaultDialog returns a minimal valid SMTP session per design_smtp.md
// §6.6: HELO + MAIL FROM + RCPT TO + DATA + empty body + QUIT. The body
// Cmd ends with "\r\n." so the planner's appended "\r\n" completes the
// "\r\n.\r\n" DATA terminator per RFC 5321 §4.1.1.4.
func defaultDialog() []core.SMTPCommand {
	return []core.SMTPCommand{
		{Cmd: "HELO client.example.org", Response: "250 mail.example.org"},
		{Cmd: "MAIL FROM:<alice@example.org>", Response: "250 2.1.0 Ok"},
		{Cmd: "RCPT TO:<bob@example.com>", Response: "250 2.1.5 Ok"},
		{Cmd: "DATA", Response: "354 End data with <CR><LF>.<CR><LF>"},
		// Body: minimal RFC 5322 headers + empty line + body + "."
		// (the planner appends "\r\n" to complete the terminator).
		{Cmd: "From: alice@example.org\r\nTo: bob@example.com\r\nSubject: Test\r\n\r\nHello\r\n.", Response: "250 2.0.0 Ok: queued as 1"},
		{Cmd: "QUIT", Response: "221 2.0.0 Bye"},
	}
}

// segmentByMSS splits payload into chunks of at most mss bytes. The last
// chunk may be smaller. A nil/empty payload returns a single empty chunk
// so the caller emits one PSH-ACK segment (matching the pre-segmentation
// behavior where an empty body still produced one response packet).
//
// Mirrors internal/protocol/ftp.segmentByMSS and
// internal/protocol/http.segmentByMSS - duplicated to avoid an import
// cycle.
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
// Mirrors internal/protocol/tcp.synOptions and
// internal/protocol/ftp.synOptions - duplicated to avoid an import
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
