// Package telnet implements the RFC 854 Telnet protocol planner.
//
// Telnet (Telecommunication Network Protocol, RFC 854) is a session-level
// protocol running over a single TCP connection on port 23. The stream is a
// mix of NVT (Network Virtual Terminal, 网络虚拟终端) ASCII data bytes and
// IAC (Interpret As Command, 解释为命令, 0xFF) command sequences. The planner
// emits:
//
//  1. TCP 3-way handshake (SYN, SYN-ACK, ACK) with MSS/WinScale/SACK options.
//  2. Optional server banner (e.g. "login: ") as the first PSH-ACK payload.
//  3. Each TelnetEvent in Dialog, in order:
//     - Data events: NVT ASCII bytes (with 0xFF escaped as 0xFF 0xFF)
//     - IAC command events: WILL/WONT/DO/DONT + Option code
//     - Sub-option events: SB <opt> <data> IAC SE
//     - Special command events: IP, DM, AYT, NOP, BRK, AO, EC, EL, GA, Synch
//  4. TCP 4-way teardown (FIN-ACK, ACK, FIN-ACK, ACK).
//
// The planner does NOT implement Option negotiation state (RFC 1143 Q
// method); it emits the dialog verbatim as specified by the user. This
// matches the trafficgen contract: synthesize test packets, not a real
// Telnet server. Users craft the negotiation sequence they want to model.
//
// IAC escaping (RFC 854 §3): any 0xFF byte that appears as DATA (not as a
// command introducer) MUST be doubled to 0xFF 0xFF. The planner applies
// this escaping to "data" events and to the sub-option payload of "sb"
// events. IAC command sequences themselves (WILL/WONT/DO/DONT/SB...SE/
// NOP/IP/DM/etc.) are emitted verbatim — they are the introducer, not data.
//
// IPv6 / multicast MAC / VLAN behavior follows the unified convention at
// /tmp/l7_planner_design/multicast_ipv6_vlan.md. Telnet is "transparent"
// over IPv4 or IPv6 (no Validate enforcement on IP version).
package telnet

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
)

const (
	DefaultTTL = 64
	// DefaultMSS mirrors internal/protocol/tcp.DefaultMSS (1460). Duplicated
	// here to avoid an import cycle. RFC 879 floor is 536; 1460 is the
	// Ethernet-friendly value used by Linux.
	DefaultMSS = 1460

	// MinMSS per RFC 879 (IP+TCP header 20+20+536 = 576-byte minimum
	// packet). Smaller values produce malformed SYNs or pathological
	// fragmentation.
	MinMSS = 536

	// DefaultTelnetPort is the IANA-assigned Telnet port (RFC 854).
	DefaultTelnetPort = 23

	// DefaultTerminalType is the terminal type sent in SB TTYPE IS when
	// neither TelnetEvent.Value nor TelnetConfig.TerminalType is set.
	DefaultTerminalType = "xterm"

	// DefaultWindowCols / DefaultWindowRows are the NAWS defaults when
	// neither TelnetEvent.Cols/Rows nor TelnetConfig.WindowCols/Rows is set.
	DefaultWindowCols = 80
	DefaultWindowRows = 24
)

// IAC command bytes (RFC 854 §3).
const (
	IACSE  = 240 // Subnegotiation End
	IACNOP = 241 // No Operation
	IACDM  = 242 // Data Mark
	IACBRK = 243 // Break
	IACIP  = 244 // Interrupt Process
	IACAO  = 245 // Abort Output
	IACAYT = 246 // Are You There
	IACEC  = 247 // Erase Character
	IACEL  = 248 // Erase Line
	IACGA  = 249 // Go Ahead
	IACSB  = 250 // Subnegotiation Begin
	IACWILL = 251 // Will
	IACWONT = 252 // Wont
	IACDO   = 253 // Do
	IACDONT = 254 // Dont
	IAC     = 255 // Interpret As Command (escape byte)
)

// Common Option codes (RFC 855 + subsequent RFCs).
const (
	OptBinary      = 0  // RFC 856
	OptEcho        = 1  // RFC 857
	OptSGA         = 3  // RFC 858 (Suppress Go Ahead)
	OptStatus      = 5  // RFC 859
	OptTM          = 6  // RFC 860 (Timing Mark)
	OptTType       = 24 // RFC 1091 (Terminal Type)
	OptNAWS        = 31 // RFC 1073 (Window Size)
	OptTSpeed      = 32 // RFC 1079
	OptLFLOW       = 33 // RFC 1372
	OptLinemode    = 34 // RFC 1184
	OptNewEnviron  = 39 // RFC 1572
)

// TTYPE sub-option commands (RFC 1091).
const (
	TTypeIS   = 0
	TTypeSEND = 1
)

// Planner implements the Telnet protocol planner.
type Planner struct{}

// NewPlanner creates a new Telnet planner.
func NewPlanner() *Planner { return &Planner{} }

// Name returns the protocol name.
func (p *Planner) Name() string { return "telnet" }

// Validate validates a Telnet flow spec. Read-only — does NOT mutate spec.
// Defaults (port 23, MSS 1460, terminal type "xterm", etc.) are applied in
// Plan's emit goroutine, not here, per /tmp/l7_planner_design/validate_conventions.md §1.1.
func (p *Planner) Validate(spec core.FlowSpec) error {
	if spec.SrcIP != "" {
		if net.ParseIP(spec.SrcIP) == nil {
			return fmt.Errorf("telnet: SrcIP %q is not a valid IP address", spec.SrcIP)
		}
	}
	if spec.DstIP != "" {
		if net.ParseIP(spec.DstIP) == nil {
			return fmt.Errorf("telnet: DstIP %q is not a valid IP address", spec.DstIP)
		}
	}
	// Telnet runs over TCP, so MSS lives on TCPConfig.MSS.
	if spec.TCP != nil && spec.TCP.MSS > 0 {
		if spec.TCP.MSS < MinMSS {
			return fmt.Errorf("telnet: TCP.MSS %d too small (min %d per RFC 879)", spec.TCP.MSS, MinMSS)
		}
		if spec.TCP.MSS > 65535 {
			return fmt.Errorf("telnet: TCP.MSS %d too large (max 65535)", spec.TCP.MSS)
		}
	}
	// Per validate_conventions.md §3.3, Telnet's default port (23) is
	// "✅ 是 (warn)" — non-default port is accepted (e.g. for testing
	// alternate ports). We do NOT hard-enforce port 23 here.

	// Scenario mode: validate the scenario name. Manual mode (empty
	// Scenario) skips this and uses Dialog/defaultDialog (backward
	// compatible). Per design_telnet.md §4 + scenario.go.
	if spec.Telnet != nil && spec.Telnet.Scenario != "" {
		if err := validateScenario(spec.Telnet); err != nil {
			return err
		}
	}
	return nil
}

// Plan generates packet configs for a Telnet flow.
func (p *Planner) Plan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) {
	if err := p.Validate(spec); err != nil {
		return nil, err
	}

	configChan := make(chan core.PacketConfig, 256)

	go func() {
		defer close(configChan)

		flowID := fmt.Sprintf("%s-%s-%d-%d", spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort)

		// Effective defaults — applied here, not in Validate, so spec stays
		// untouched (per validate_conventions.md §1.3).
		effectiveTTL := spec.TTL
		if effectiveTTL == 0 {
			effectiveTTL = DefaultTTL
		}
		mss := uint16(DefaultMSS)
		if spec.TCP != nil && spec.TCP.MSS > 0 {
			mss = spec.TCP.MSS
		}
		synOpts := synOptions(mss)

		// Resolve Telnet config (nil -> default minimal dialog).
		telnetConfig := spec.Telnet
		if telnetConfig == nil {
			telnetConfig = &core.TelnetConfig{}
		}

		// Default dialog when user provided none: a minimal but realistic
		// login-shaped session so the planner still emits something
		// observable. Per design_telnet.md §6.6.
		//
		// Scenario mode (cfg.Scenario != "") auto-generates the full
		// interactive dialog and overrides any manual Dialog (per
		// design_telnet.md §4 + scenario.go).
		dialog := telnetConfig.Dialog
		if telnetConfig.Scenario != "" {
			dialog = buildScenarioDialog(telnetConfig)
		} else if len(dialog) == 0 {
			dialog = defaultDialog()
		}

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

		// emit sends one packet in the given direction. payload may be nil
		// for handshake/teardown segments. SYN/SYN-ACK carry synOpts.
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
			// GroupID strategy, mirroring ftp.go. The worker overwrites
			// this at worker.go:325 with the flowIdx-resolved gID; for
			// strategies with flow_count > 1 the pre-write is a placeholder
			// (flowIdx=0 evaluation). When spec.GroupID is nil the worker
			// falls back to the 4-tuple hash, so we leave Metadata nil.
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

		// emitData segments payload by MSS and emits each chunk as a
		// PSH-ACK in the given direction, advancing the sender's seq.
		emitData := func(direction, srcMAC, dstMAC, srcIP, dstIP string, srcPort, dstPort uint16, senderSeq, peerSeq uint32, payload []byte) (newSenderSeq uint32) {
			for _, seg := range segmentByMSS(payload, int(mss)) {
				emit(direction, srcMAC, dstMAC, srcIP, dstIP, srcPort, dstPort, senderSeq, peerSeq, 0x18, seg)
				senderSeq += uint32(len(seg))
			}
			return senderSeq
		}

		// --- TCP handshake (SYN, SYN-ACK, ACK) ---
		emit("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, 0, 0x02, nil)
		clientSeq++
		emit("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, 0x12, nil)
		serverSeq++
		emit("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, 0x10, nil)

		// --- Optional server banner (NVT ASCII) ---
		if telnetConfig.Banner != "" {
			payload := escapeIAC([]byte(telnetConfig.Banner))
			serverSeq = emitData("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, payload)
		}

		// --- FileSource payload (optional, emitted before Dialog per design §8.8) ---
		if telnetConfig.FileSource != nil {
			if pc := core.PayloadCacheFrom(ctx); pc != nil {
				if fileBytes, err := pc.GetOrLoad(ctx, *telnetConfig.FileSource); err == nil && len(fileBytes) > 0 {
					escaped := escapeIAC(fileBytes)
					clientSeq = emitData("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, escaped)
				}
			}
		}

		// --- Telnet dialog events ---
		for _, ev := range dialog {
			payload, ok := renderTelnetEvent(ev, telnetConfig)
			if !ok {
				// Event type produced no bytes (e.g. empty data or unknown
				// type with empty data). Skip — do not emit a PSH-ACK.
				continue
			}
			if len(payload) == 0 {
				// Explicit empty data event: design §4.1.1 says "skip".
				continue
			}
			dir := ev.Direction
			if dir != "up" && dir != "down" {
				dir = "up"
			}
			if dir == "up" {
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

// defaultDialog returns a minimal Telnet dialog used when the user provides
// no Dialog. Shape: IAC WILL SGA (server) -> IAC DO SGA (client) -> "login: "
// prompt -> "alice\r\n" -> "$ " shell prompt -> "exit\r\n". Per design §6.6.
func defaultDialog() []core.TelnetEvent {
	return []core.TelnetEvent{
		{Type: "will", Direction: "down", Option: OptSGA},
		{Type: "do", Direction: "up", Option: OptSGA},
		{Type: "data", Direction: "down", Data: "login: "},
		{Type: "data", Direction: "up", Data: "alice\r\n"},
		{Type: "data", Direction: "down", Data: "$ "},
		{Type: "data", Direction: "up", Data: "exit\r\n"},
	}
}

// renderTelnetEvent converts a single TelnetEvent to its on-wire byte
// sequence. Returns (bytes, true) when the event produces output, or
// (nil, false) when the event should be skipped (unknown type with no
// data, or explicit empty data event). The caller is responsible for
// checking len(bytes)==0 to skip emitting a PSH-ACK for empty data.
//
// IAC escaping (RFC 854 §3):
//   - "data" events: every 0xFF in the data is doubled to 0xFF 0xFF.
//   - "sb" events: every 0xFF in SubData is doubled.
//   - IAC command sequences (will/wont/do/dont/sb headers/ttype_*/naws/
//     ip/dm/nop/etc.) are emitted verbatim — they ARE the introducer.
func renderTelnetEvent(ev core.TelnetEvent, cfg *core.TelnetConfig) ([]byte, bool) {
	switch ev.Type {
	case "", "data":
		// Empty Type defaults to "data" with the Data field. Empty Data
		// produces no bytes — caller skips.
		if ev.DataB64 != "" {
			if decoded, err := base64.StdEncoding.DecodeString(ev.DataB64); err == nil {
				return escapeIAC(decoded), true
			}
			return nil, false
		}
		return escapeIAC([]byte(ev.Data)), true

	case "will":
		return []byte{IAC, IACWILL, ev.Option}, true
	case "wont":
		return []byte{IAC, IACWONT, ev.Option}, true
	case "do":
		return []byte{IAC, IACDO, ev.Option}, true
	case "dont":
		return []byte{IAC, IACDONT, ev.Option}, true

	case "sb":
		// IAC SB <opt> <sub_data with 0xFF escaped> IAC SE
		var sub []byte
		if ev.SubDataB64 != "" {
			if decoded, err := base64.StdEncoding.DecodeString(ev.SubDataB64); err == nil {
				sub = escapeIAC(decoded)
			}
		} else {
			sub = escapeIAC(ev.SubData)
		}
		out := make([]byte, 0, 4+len(sub)+2)
		out = append(out, IAC, IACSB, ev.Option)
		out = append(out, sub...)
		out = append(out, IAC, IACSE)
		return out, true

	case "ttype_send":
		// IAC SB TTYPE SEND IAC SE (RFC 1091)
		return []byte{IAC, IACSB, OptTType, TTypeSEND, IAC, IACSE}, true

	case "ttype_is":
		// IAC SB TTYPE IS <value> IAC SE. Value defaults to
		// TelnetConfig.TerminalType, then to "xterm".
		value := ev.Value
		if value == "" && cfg != nil {
			value = cfg.TerminalType
		}
		if value == "" {
			value = DefaultTerminalType
		}
		out := make([]byte, 0, 4+len(value)+2)
		out = append(out, IAC, IACSB, OptTType, TTypeIS)
		// Per RFC 1091 the terminal-type string is ASCII; no 0xFF escaping
		// is needed for normal terminal names, but apply escaping for
		// safety in case a user embeds a 0xFF byte in the value.
		out = append(out, escapeIAC([]byte(value))...)
		out = append(out, IAC, IACSE)
		return out, true

	case "naws":
		// IAC SB NAWS <cols_hi> <cols_lo> <rows_hi> <rows_lo> IAC SE
		// (RFC 1073). 4-byte big-endian window size. Defaults to
		// TelnetConfig.WindowCols/Rows, then to 80x24.
		cols := ev.Cols
		rows := ev.Rows
		if cols == 0 && cfg != nil {
			cols = cfg.WindowCols
		}
		if rows == 0 && cfg != nil {
			rows = cfg.WindowRows
		}
		if cols == 0 {
			cols = DefaultWindowCols
		}
		if rows == 0 {
			rows = DefaultWindowRows
		}
		var dims [4]byte
		binary.BigEndian.PutUint16(dims[0:2], cols)
		binary.BigEndian.PutUint16(dims[2:4], rows)
		out := make([]byte, 0, 9)
		out = append(out, IAC, IACSB, OptNAWS)
		out = append(out, dims[:]...)
		out = append(out, IAC, IACSE)
		return out, true

	case "ip":
		return []byte{IAC, IACIP}, true
	case "dm":
		return []byte{IAC, IACDM}, true
	case "nop":
		return []byte{IAC, IACNOP}, true
	case "ayt":
		return []byte{IAC, IACAYT}, true
	case "brk":
		return []byte{IAC, IACBRK}, true
	case "ao":
		return []byte{IAC, IACAO}, true
	case "ec":
		return []byte{IAC, IACEC}, true
	case "el":
		return []byte{IAC, IACEL}, true
	case "ga":
		return []byte{IAC, IACGA}, true

	case "synch":
		// IAC IP followed by IAC DM (RFC 854 §3 Synch signal). Note: the
		// DM segment should ideally carry TCP URG, but core.L4Config has
		// no UrgentPointer field — documented limitation per design §8.5.
		return []byte{IAC, IACIP, IAC, IACDM}, true

	default:
		// Unknown type: per testcases §4.3.11, treat as data event with
		// empty Data -> produces no bytes -> caller skips.
		return nil, false
	}
}

// escapeIAC replaces every 0xFF byte in data with 0xFF 0xFF per RFC 854 §3.
// This is the core IAC-escape rule: a literal 0xFF in the data stream must
// be doubled so the receiver does not interpret it as a command introducer.
// Returns a new slice; the input is not modified.
func escapeIAC(data []byte) []byte {
	if len(data) == 0 {
		return []byte{}
	}
	// Count 0xFF bytes to size the output slice precisely.
	count := 0
	for _, b := range data {
		if b == IAC {
			count++
		}
	}
	if count == 0 {
		// No 0xFF bytes — return a copy so callers can mutate without
		// aliasing the input.
		out := make([]byte, len(data))
		copy(out, data)
		return out
	}
	out := make([]byte, 0, len(data)+count)
	for _, b := range data {
		if b == IAC {
			out = append(out, IAC, IAC)
		} else {
			out = append(out, b)
		}
	}
	return out
}

// segmentByMSS splits payload into chunks of at most mss bytes. The last
// chunk may be smaller. A nil/empty payload returns a single empty chunk
// so the caller emits one PSH-ACK segment (matching the pre-segmentation
// behavior where an empty body still produced one response packet).
//
// Mirrors internal/protocol/ftp.segmentByMSS — duplicated to avoid an
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
// internal/protocol/tcp.synOptions and internal/protocol/ftp.synOptions
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

