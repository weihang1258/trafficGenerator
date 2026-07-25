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
	"encoding/base64"
	"fmt"
	"math/rand"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/trafficgen/trafficgen/internal/core"
)

// payloadCacheKey is the context-key type used to inject a PayloadCache
// into the FTP planner via WithPayloadCache. The planner reads the cache
// from ctx.Value(payloadCacheKey{}) when dc.FileSource is set.
//
// Task 11 keeps the key and WithPayloadCache helper in the ftp package
// so the planner is testable in isolation; Task 13 will refactor callers
// to use core.WithPayloadCache (a controller-level helper) which uses
// the same key type so the planner's lookup continues to work.
type payloadCacheKey struct{}

// WithPayloadCache returns a context carrying the payload cache. The
// FTP planner reads the cache via ctx.Value(payloadCacheKey{}) when
// dc.FileSource is set; the cache is used to resolve file/literal/fill/
// seeded-random payload bytes via PayloadCache.GetOrLoad.
func WithPayloadCache(ctx context.Context, pc *core.PayloadCache) context.Context {
	return context.WithValue(ctx, payloadCacheKey{}, pc)
}

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
		for cmdIdx, cmd := range ftpConfig.Commands {
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
				emitFTPDataChannel(ctx, configChan, ftpConfig.DataChannel, spec, flowID, now, &packetIndex, nextIPID, mss, cmdIdx)
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

// pasvPortRe matches a 227 PASV response line per RFC 959 §4.1.2:
//   "227 Entering Passive Mode (h1,h2,h3,h4,p1,p2)"
// The data-port is p1*256+p2.
//
// Flags:
//   - (?i) case-insensitive: "227" matches any casing (per RFC 959 §5.3.1
//     the response code is case-insensitive).
//   - (?m) multiline: `^` matches start of EACH line, so a multi-line 227
//     response (RFC 959 §4.2 continuation format
//     "227-Welcome\r\n227 Entering Passive Mode (...)") parses the final
//     227 line correctly.
//
// `^227 ` requires a literal SPACE after "227" — this prevents
// matching "227-" continuation lines, which carry their own 6-tuple
// in malformed replies and would otherwise hijack the real 227 line.
// We use a literal space (not `\s`) because `\s` also matches tab,
// vertical-tab, form-feed, CR, and LF — a malformed continuation
// "227\t-Welcome (..)" would then match `^227\s` and hijack the real
// 227 line that follows. RFC 959 §5.4 specifies SPACE as the
// separator between response code and text, so a literal space is
// both correct and narrower.
//
// `[^\n]*?` is non-greedy so the FIRST 6-tuple on the line wins. A greedy
// `*` would backtrack to the LAST `(...)` on the line, picking the wrong
// tuple when a server packs extra debug info into the reply.
var pasvPortRe = regexp.MustCompile(`(?im)^227 [^\n]*?\((\d+),(\d+),(\d+),(\d+),(\d+),(\d+)\)`)

// portCmdRe matches a PORT command per RFC 959 §4.1.2:
//   "PORT h1,h2,h3,h4,p1,p2"
// The client tells the server "I'm listening on IP h1.h2.h3.h4 port p1*256+p2".
// Per RFC 959 §5.3.1 FTP commands are case-insensitive — the regex uses
// (?i) so "port", "Port", "PORT" all parse. The (?m) flag makes ^ match
// the start of each line (mirroring pasvPortRe's (?im)) so a multi-line
// command string (e.g. "USER ...\r\nPORT 10,0,0,1,78,17") parses the PORT
// line regardless of which line it's on. Today callers pass single-line
// commands, but the (?m) flag future-proofs against callers that join
// commands with CRLF.
var portCmdRe = regexp.MustCompile(`(?im)^PORT\s+(\d+),(\d+),(\d+),(\d+),(\d+),(\d+)`)

// parsePASVPort scans a server response string for a 227 PASV 6-tuple and
// returns the derived data-port (p1*256+p2). Returns 0 if not found or if
// the port components don't parse as integers in [0, 65535].
// Example: "227 Entering Passive Mode (20,0,0,1,195,80)" -> 50000.
func parsePASVPort(response string) uint16 {
	m := pasvPortRe.FindStringSubmatch(response)
	if m == nil {
		return 0
	}
	p1, err1 := strconv.Atoi(m[5])
	p2, err2 := strconv.Atoi(m[6])
	if err1 != nil || err2 != nil {
		return 0
	}
	port := p1*256 + p2
	if port < 0 || port > 65535 {
		return 0
	}
	return uint16(port)
}

// parsePORTPort scans a client command for a PORT 6-tuple and returns the
// derived data-port (p1*256+p2). Returns 0 if not found or if the port
// components don't parse as integers in [0, 65535].
// Example: "PORT 10,0,0,1,78,17" -> 20001 (78*256+17).
func parsePORTPort(cmd string) uint16 {
	m := portCmdRe.FindStringSubmatch(cmd)
	if m == nil {
		return 0
	}
	p1, err1 := strconv.Atoi(m[5])
	p2, err2 := strconv.Atoi(m[6])
	if err1 != nil || err2 != nil {
		return 0
	}
	port := p1*256 + p2
	if port < 0 || port > 65535 {
		return 0
	}
	return uint16(port)
}

// scanCommandsForDataPort walks the FTP control-channel dialog to find the
// data-port declared in signaling. For passive mode it looks for the 227
// PASV response (server-advertised port). For active mode it looks for the
// PORT command (client-advertised port). Returns 0 if no signaling-derived
// port is found.
//
// This is the mechanism that lets the data-channel 4-tuple match what the
// signaling plane actually advertised — without it, a pcap showing "227 ...(
// 20,0,0,1,195,80)" followed by a data SYN to port 50001 would look like
// two unrelated flows to a DPI.
func scanCommandsForDataPort(commands []core.FTPCommand, isActive bool, upToIdx int) uint16 {
	if upToIdx < 0 {
		return 0
	}
	if upToIdx >= len(commands) {
		upToIdx = len(commands) - 1
	}
	var port uint16
	if isActive {
		for i := 0; i <= upToIdx; i++ {
			if p := parsePORTPort(commands[i].Cmd); p != 0 {
				port = p
			}
		}
	} else {
		for i := 0; i <= upToIdx; i++ {
			if p := parsePASVPort(commands[i].Response); p != 0 {
				port = p
			}
		}
	}
	return port
}

// emitFTPDataChannel emits the FTP data-channel sub-flow. The sub-flow is
// a second TCP connection carrying the file body — it has its own 4-tuple,
// handshake, sequence space, and teardown, but shares the parent's GroupID
// so it routes to the same PacketWorker (wire order = emit order).
//
// Port derivation (RFC 959 §5.2), in priority order:
//  1. Explicit user override (dc.SrcPort / dc.DstPort).
//  2. Parsed from signaling (PASV 227 response for passive; PORT command
//     for active) — this is what makes the data-channel 4-tuple match what
//     the control channel actually advertised.
//  3. Hardcoded fallback (server port 20 for active; ephemeral
//     control_src_port+1 for the client's side; 50000 when no PASV response
//     in dialog).
//
//   - active mode (PORT): server connects from port 20 to client's data-port.
//     SubFlowSpec.ServerInitiated=true so SYN goes server→client.
//   - passive mode (PASV): client connects from an ephemeral port to
//     server's data-port.
//     SubFlowSpec.ServerInitiated=false so SYN goes client→server.
//
// SrcPort/DstPort on SubFlowSpec are always CLIENT's port / SERVER's port
// (regardless of who opens the connection). For active mode this means
// SrcPort=client's data port (e.g. 20001), DstPort=20; for passive mode
// SrcPort=client's ephemeral (e.g. 20001), DstPort=server's PASV port
// (e.g. 50000).
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
	ctx context.Context,
	configChan chan<- core.PacketConfig,
	dc *core.FTPDataChannel,
	spec core.FlowSpec,
	parentFlowID string,
	now time.Time,
	packetIndex *uint64,
	nextIPID func() uint16,
	parentMSS uint16,
	cmdIdx int,
) {
	// Default mode is passive (the modern default; active is rare outside
	// legacy clients). Case-insensitive comparison so "Active", "PASSIVE",
	// etc. all work.
	mode := dc.Mode
	if mode == "" {
		mode = "passive"
	}
	isActive := strings.EqualFold(mode, "active")

	// Scan the control-channel dialog up to cmdIdx to find the data-port
	// declared in signaling (227 PASV response for passive; PORT command for
	// active). This lets the data-channel 4-tuple match what the control
	// channel actually advertised, so DPI sees them as related. Scanning up
	// to cmdIdx (not the whole dialog) ensures multi-transfer dialogs
	// associate each data channel with its own preceding PASV/PORT.
	signalingDataPort := scanCommandsForDataPort(spec.FTP.Commands, isActive, cmdIdx)

	// Resolve data-channel ports. SubFlowSpec uses SrcPort=client's port,
	// DstPort=server's port always.
	clientDataPort := dc.SrcPort
	serverDataPort := dc.DstPort

	if isActive {
		// Server connects from port 20 (server's port) to client's data port.
		// serverDataPort = server's data port (20 fallback).
		if serverDataPort == 0 {
			serverDataPort = 20
		}
		// clientDataPort = client's advertised PORT port (parsed from the
		// PORT command) or control_src_port+1 fallback.
		if clientDataPort == 0 {
			if signalingDataPort != 0 {
				clientDataPort = signalingDataPort
			} else if spec.SrcPort == 65535 {
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
		// serverDataPort = server's advertised PASV port (parsed from the
		// 227 response) or 50000 fallback.
		if serverDataPort == 0 {
			if signalingDataPort != 0 {
				serverDataPort = signalingDataPort
			} else {
				serverDataPort = 50000
			}
		}
	}

	// Resolve MSS: data channel MSS defaults to parent's TCP MSS (so a
	// single MSS setting on the FTP spec covers both channels).
	mss := dc.MSS
	if mss == 0 {
		mss = parentMSS
	}

	// Resolve payload bytes per the FileSource precedence contract:
	//  1. dc.FileSource != nil -> PayloadCache.GetOrLoad(ctx, *dc.FileSource)
	//  2. else dc.PayloadB64 != "" -> base64-decode
	//  3. else []byte(dc.Payload)
	//
	// When FileSource is set but no cache is injected (e.g. a unit test
	// that forgot WithPayloadCache, or a controller path that doesn't
	// wire the cache yet), we return WITHOUT emitting the data channel
	// rather than silently falling through to Payload — falling through
	// would violate the FileSource > Payload precedence contract. The
	// production engine (Task 13) always injects the cache.
	//
	// We resolve to []byte and then carry it through SubFlowSpec via
	// Payload (text) or PayloadB64 (binary) so the sub-flow emitter
	// (core.EmitSubFlow) reads the exact same bytes regardless of whether
	// the source was inline text, inline base64, or a FileSource that
	// produced arbitrary bytes (file body, fill pattern, seeded random).
	// The isText heuristic picks the right field so JSON marshalling of
	// SubFlowSpec (for debugging) stays readable when possible.
	var payloadBytes []byte
	if dc.FileSource != nil {
		pc, _ := ctx.Value(payloadCacheKey{}).(*core.PayloadCache)
		if pc == nil {
			return
		}
		payloadBytes, _ = pc.GetOrLoad(ctx, *dc.FileSource)
	} else if dc.PayloadB64 != "" {
		payloadBytes, _ = base64.StdEncoding.DecodeString(dc.PayloadB64)
	} else {
		payloadBytes = []byte(dc.Payload)
	}

	var subPayload string
	var subPayloadB64 string
	if len(payloadBytes) > 0 {
		// Prefer the text field when the bytes are valid UTF-8 and contain
		// no NUL bytes (a heuristic for "this is text"). Otherwise encode
		// as base64 so binary payloads round-trip exactly. This mirrors
		// how a user would write the same bytes inline.
		if isText(payloadBytes) {
			subPayload = string(payloadBytes)
		} else {
			subPayloadB64 = base64.StdEncoding.EncodeToString(payloadBytes)
		}
	}

	sub := core.SubFlowSpec{
		Protocol:        "tcp",
		SrcPort:         clientDataPort,
		DstPort:         serverDataPort,
		Direction:       dc.Direction,
		Payload:         subPayload,
		PayloadB64:      subPayloadB64,
		Handshake:       true,
		Termination:     true,
		MSS:             mss,
		ServerInitiated: isActive,
	}
	core.EmitSubFlow(configChan, 0, sub, spec, parentFlowID, now, packetIndex, nextIPID)
}

// isText reports whether b is a safe text payload: valid UTF-8 with no NUL
// bytes. Used to choose between SubFlowSpec.Payload (text) and .PayloadB64
// (binary) when carrying resolved []byte through the sub-flow spec.
func isText(b []byte) bool {
	for _, c := range b {
		if c == 0 {
			return false
		}
	}
	return utf8.Valid(b)
}
