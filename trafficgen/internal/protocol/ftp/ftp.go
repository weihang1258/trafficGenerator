// Package ftp implements the FTP protocol planner.
//
// FTP (File Transfer Protocol, RFC 959) is a session-level protocol: a
// single TCP connection on port 21 (the control channel) carries a
// sequence of command/response pairs. The planner emits:
//
//  1. TCP 3-way handshake (SYN, SYN-ACK, ACK) with MSS/WinScale/SACK options.
//  2. Optional server banner (e.g. "220 ...") as the first PSH-ACK payload.
//  3. Each FTPCommand: client command (PSH-ACK up) + server response
//     (PSH-ACK down). Payloads longer than MSS are segmented; each segment
//     advances the sender's sequence number by its byte length, so the
//     peer's next ACK covers all bytes.
//  4. (Optional) FTP data channel sub-flow: when FTPConfig.DataChannel
//     is set AND a command has EmitDataChannel=true, the planner emits
//     a second TCP flow (own 4-tuple, handshake, sequence space, teardown)
//     carrying the file body. The sub-flow's packets are interleaved
//     between the command's "150 Opening data connection" response and
//     the next "226 Transfer complete" response — exactly as a real
//     PASV/PORT data channel would land in a pcap.
//  5. TCP 4-way teardown (FIN-ACK, ACK, FIN-ACK, ACK).
//
// The control channel and data channel share the same GroupID (inherited
// from the parent FlowSpec) so they route to the same PacketWorker — wire
// order = emit order, so the data packets land between the 150 and 226
// responses. See internal/core/subflow.go EmitSubFlow for the sub-flow
// wire format.
package ftp

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
	// internal/protocol/http.DefaultMSS (1460). Duplicated here to avoid
	// an import cycle. RFC 879 floor is 536; 1460 is the Ethernet-friendly
	// value used by Linux.
	DefaultMSS = 1460

	// MinMSS per RFC 879 (IP+TCP header 20+20+536 = 576-byte minimum
	// packet). Smaller values produce malformed SYNs or pathological
	// fragmentation.
	MinMSS = 536
)

// Planner implements the FTP protocol planner.
type Planner struct{}

// NewPlanner creates a new FTP planner.
func NewPlanner() *Planner { return &Planner{} }

// Name returns the protocol name.
func (p *Planner) Name() string { return "ftp" }

// Validate validates an FTP flow spec.
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

// Plan generates packet configs for an FTP flow.
func (p *Planner) Plan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) {
	if err := p.Validate(spec); err != nil {
		return nil, err
	}

	configChan := make(chan core.PacketConfig, 256)

	go func() {
		defer close(configChan)

		flowID := fmt.Sprintf("%s-%s-%d-%d", spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort)

		ftpConfig := spec.FTP
		if ftpConfig == nil {
			ftpConfig = &core.FTPConfig{}
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
		// The peer's seq is unchanged (no ACK emission here — the next
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
		if ftpConfig.Banner != "" {
			payload := []byte(ftpConfig.Banner + "\r\n")
			serverSeq = emitData("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, payload)
		}

		// --- FTP command/response pairs ---
		for _, cmd := range ftpConfig.Commands {
			// Command (client -> server). Append CRLF per RFC 959 §4.1.
			// Empty Cmd is skipped (lets users model server-only turns,
			// though real FTP is always command-then-response).
			if cmd.Cmd != "" {
				payload := []byte(cmd.Cmd + "\r\n")
				clientSeq = emitData("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, payload)
			}
			if cmd.Response != "" {
				payload := []byte(cmd.Response + "\r\n")
				serverSeq = emitData("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, payload)
			}

			// Emit data channel sub-flow after this command's response
			// when the user flagged it. The sub-flow is a separate TCP
			// connection (own handshake/seq/teardown) but shares the
			// parent's GroupID so it routes to the same PacketWorker —
			// wire order = emit order, so these packets land between
			// the "150" response (above) and the next "226" response
			// (the next loop iteration).
			if cmd.EmitDataChannel && ftpConfig.DataChannel != nil {
				emitFTPDataChannel(configChan, ftpConfig.DataChannel, spec, flowID, now, &packetIndex, nextIPID, mss)
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

// segmentByMSS splits payload into chunks of at most mss bytes. The last
// chunk may be smaller. A nil/empty payload returns a single empty chunk
// so the caller emits one PSH-ACK segment (matching the pre-segmentation
// behavior where an empty body still produced one response packet).
//
// Mirrors internal/protocol/http.segmentByMSS — duplicated to avoid an
// import cycle.
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
// internal/protocol/tcp.synOptions and internal/protocol/http.synOptions
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

// emitFTPDataChannel emits the FTP data-channel sub-flow. The sub-flow is
// a second TCP connection carrying the file body — it has its own 4-tuple,
// handshake, sequence space, and teardown, but shares the parent's GroupID
// so it routes to the same PacketWorker (wire order = emit order).
//
// Port derivation (RFC 959 §5.2):
//   - active mode (PORT): server connects from port 20 to client's
//     data-port (control_src_port + 1 is the conventional choice).
//     SubFlowSpec.ServerInitiated=true so SYN goes server→client.
//   - passive mode (PASV): client connects from an ephemeral port to
//     server's data-port (control_src_port + 1 is a reasonable ephemeral
//     choice; the real port would be parsed from the PASV 227 response,
//     but we keep it deterministic for test reproducibility).
//     SubFlowSpec.ServerInitiated=false so SYN goes client→server.
//
// SrcPort/DstPort on SubFlowSpec are always CLIENT's port / SERVER's port
// (regardless of who opens the connection). For active mode this means
// SrcPort=client's data port (e.g. 20001), DstPort=20; for passive mode
// SrcPort=client's ephemeral (e.g. 20001), DstPort=server's PASV port
// (default 50000).
//
// The sub-flow's Direction is taken verbatim from FTPDataChannel.Direction:
//   - "down" = RETR (server sends file bytes to client)
//   - "up"   = STOR (client sends file bytes to server)
//
// Direction is independent of Mode: an active-mode RETR has the server
// opening the data connection AND sending the file bytes; a passive-mode
// RETR has the client opening the connection but the server still sending
// the file bytes.
func emitFTPDataChannel(
	configChan chan<- core.PacketConfig,
	dc *core.FTPDataChannel,
	spec core.FlowSpec,
	parentFlowID string,
	now time.Time,
	packetIndex *uint64,
	nextIPID func() uint16,
	parentMSS uint16,
) {
	// Default mode is passive (the modern default; active is rare outside
	// legacy clients). Case-insensitive comparison so "Active", "PASSIVE",
	// etc. all work.
	mode := dc.Mode
	if mode == "" {
		mode = "passive"
	}
	isActive := strings.EqualFold(mode, "active")

	// Resolve data-channel ports. SubFlowSpec uses SrcPort=client's port,
	// DstPort=server's port always.
	clientDataPort := dc.SrcPort
	serverDataPort := dc.DstPort

	if isActive {
		// Server connects from port 20 (server's port) to client's data port.
		if serverDataPort == 0 {
			serverDataPort = 20
		}
		if clientDataPort == 0 {
			// Convention: client's data port = control src_port + 1.
			// Guard against overflow: if control port is 65535, wrap to
			// an ephemeral port (e.g. 1024) rather than producing 0
			// (which would be interpreted as "derive" and loop).
			if spec.SrcPort == 65535 {
				clientDataPort = 1024
			} else {
				clientDataPort = spec.SrcPort + 1
			}
		}
	} else {
		// Passive: client connects from an ephemeral port to server's data port.
		if clientDataPort == 0 {
			if spec.SrcPort == 65535 {
				clientDataPort = 1024
			} else {
				clientDataPort = spec.SrcPort + 1
			}
		}
		if serverDataPort == 0 {
			// Default to 50000 when no PASV response to parse. This is
			// a common high port for test scenarios; users can override.
			serverDataPort = 50000
		}
	}

	// Resolve MSS: data channel MSS defaults to parent's TCP MSS (so a
	// single MSS setting on the FTP spec covers both channels).
	mss := dc.MSS
	if mss == 0 {
		mss = parentMSS
	}

	sub := core.SubFlowSpec{
		Protocol:        "tcp",
		SrcPort:         clientDataPort,
		DstPort:         serverDataPort,
		Direction:       dc.Direction,
		Payload:         dc.Payload,
		PayloadB64:      dc.PayloadB64,
		Handshake:       true,
		Termination:     true,
		MSS:             mss,
		ServerInitiated: isActive,
	}
	core.EmitSubFlow(configChan, 0, sub, spec, parentFlowID, now, packetIndex, nextIPID)
}
