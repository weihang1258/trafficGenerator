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
	if err := validateDynFields(spec.FTP); err != nil {
		return err
	}
	if err := validateSessionStaticCopy(spec); err != nil {
		return err
	}
	return nil
}

// validateSessionStaticCopy (D-FTP-2, CORE_MEMORY §12): flows>1 whose session
// ports are all pinned (explicit session SrcPort, or all-inherit when the
// user pinned spec.SrcPort) and with no dynamic session port would emit N
// identical control connections — the static copy anti-pattern. spec.Count=0
// (batch planner semantics) never triggers: batch classes are exempt (each
// class's tuples pool owns per-flow variation). Resolution paths: leave
// src_port unpinned (auto-increment), configure spec.Tuples, or make a
// session port dynamic.
func validateSessionStaticCopy(spec core.FlowSpec) error {
	ftpConfig := spec.FTP
	if ftpConfig == nil || len(ftpConfig.Sessions) == 0 || spec.Count <= 1 {
		return nil
	}
	anyDyn := false
	anyPinned := false
	for _, sess := range ftpConfig.Sessions {
		if sess.SrcPortDyn != nil {
			anyDyn = true
			break
		}
		if sess.SrcPort != 0 {
			anyPinned = true
		}
	}
	if anyDyn {
		return nil
	}
	if anyPinned || spec.HasExplicitSrcPort {
		return fmt.Errorf("ftp: flows=%d with pinned session src_port emits %d identical control connections (static copy). Omit src_port (auto-increment per flow), add tuples, or use dynamic session src_port", spec.Count, spec.Count)
	}
	return nil
}

// dynRangeEnds extracts the numeric range endpoints for validation (mirrors
// core.toInt: float64/int/int64/string accepted).
func dynRangeEnds(r []interface{}) (int, int) {
	toIntLocal := func(v interface{}) int {
		switch x := v.(type) {
		case float64:
			return int(x)
		case int:
			return x
		case int64:
			return int(x)
		case string:
			n, _ := strconv.Atoi(x)
			return n
		}
		return 0
	}
	return toIntLocal(r[0]), toIntLocal(r[1])
}

// validateDynFields (D-FTP-2): reject malformed dynamic variants BEFORE any
// emission — a bad dynamic object must fail the task (or skip the flow in
// batch), never silently fall back to the static value. Rules mirror the
// core algorithms: inc/rand need a 2-element ordered range; list needs
// non-empty entries; pattern needs a non-empty template plus a 2-element
// range; strategy must be one of fixed/inc/rand/list/pattern.
func validateDynFields(ftpConfig *core.FTPConfig) error {
	if ftpConfig == nil || len(ftpConfig.Sessions) == 0 {
		return nil
	}
	check := func(where string, s *core.StrategyConfig) error {
		if s == nil {
			return nil
		}
		switch s.Strategy {
		case "fixed", "":
			return nil // empty strategy = treated as absent by resolvers
		case "inc", "rand":
			if len(s.Range) != 2 {
				return fmt.Errorf("ftp %s: %s strategy requires a 2-element range", where, s.Strategy)
			}
			if a, b := dynRangeEnds(s.Range); a > b {
				return fmt.Errorf("ftp %s: %s range start must not exceed end", where, s.Strategy)
			}
			return nil
		case "list":
			if len(s.List) == 0 {
				return fmt.Errorf("ftp %s: list strategy requires a non-empty list", where)
			}
			return nil
		case "pattern":
			if s.Pattern == "" || len(s.Range) != 2 {
				return fmt.Errorf("ftp %s: pattern strategy requires a template and a 2-element range", where)
			}
			if a, b := dynRangeEnds(s.Range); a > b {
				return fmt.Errorf("ftp %s: pattern range start must not exceed end", where)
			}
			return nil
		default:
			return fmt.Errorf("ftp %s: unknown dynamic strategy %q", where, s.Strategy)
		}
	}
	for si, sess := range ftpConfig.Sessions {
		if err := check(fmt.Sprintf("sessions[%d].src_port", si), sess.SrcPortDyn); err != nil {
			return err
		}
		if err := check(fmt.Sprintf("sessions[%d].banner", si), sess.BannerDyn); err != nil {
			return err
		}
		for ti, tx := range sess.Transactions {
			if tx.DataChannel != nil {
				if err := check(fmt.Sprintf("sessions[%d].transactions[%d].data_channel.payload", si, ti), tx.DataChannel.PayloadDyn); err != nil {
					return err
				}
			}
			for ci, cmd := range tx.Commands {
				if err := check(fmt.Sprintf("sessions[%d].transactions[%d].commands[%d].cmd", si, ti, ci), cmd.CmdDyn); err != nil {
					return err
				}
				if err := check(fmt.Sprintf("sessions[%d].transactions[%d].commands[%d].response", si, ti, ci), cmd.ResponseDyn); err != nil {
					return err
				}
			}
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

		now := time.Now()
		ftpConfig := spec.FTP
		if ftpConfig == nil {
			ftpConfig = &core.FTPConfig{}
		}

		// Multi-session static shape (D-FTP-1 phase 1): each session is one
		// independent TCP connection. Empty Sessions = legacy single-control
		// path below (byte-for-byte unchanged).
		if len(ftpConfig.Sessions) > 0 {
			p.planSessions(ctx, configChan, spec, ftpConfig, now)
			return
		}

		flowID := fmt.Sprintf("%s-%s-%d-%d", spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort)

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
			// GroupID strategy, so any tool reading the PacketConfig
			// directly (parsers, replays, custom harnesses) sees the
			// same group the worker would stamp via computeHashKey.
			// The worker overwrites this at worker.go:325 with the
			// flowIdx-resolved gID, so for "inc"/"pattern"/"rand"
			// strategies with flow_count > 1 the pre-write value is a
			// placeholder (it stays at the flowIdx=0 evaluation until
			// the worker stamp). When spec.GroupID is nil the worker
			// falls back to the unordered 4-tuple hash, so we leave
			// Metadata nil and let the worker own it.
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

// planSessions drives the multi-session shape (D-FTP-1): one independent
// TCP connection per FTPSession — own 4-tuple (SrcPort override), own
// sequence spaces, own handshake/banner/teardown — running its transactions
// in order. Data channels mount at {parent}:sub-{tx-idx} (per-transaction
// index replaces the old hardcoded sub-0 collision), and each transaction's
// data-channel port derivation scans only its own commands' PASV/PORT
// signaling (per-transaction isolation, T-FTP-4).
func (p *Planner) planSessions(ctx context.Context, configChan chan<- core.PacketConfig, spec core.FlowSpec, ftpConfig *core.FTPConfig, now time.Time) {
	for _, sess := range ftpConfig.Sessions {
		// Per-session TCP state (isolated from other sessions AND from the
		// legacy single-control path).
		sessSpec := spec
		if sess.SrcPort != 0 {
			sessSpec.SrcPort = sess.SrcPort
		}
		// Session-level dynamic variants (D-FTP-2): resolved at the flow
		// index; static non-zero wins, dynamic fills the gap.
		if sess.SrcPortDyn != nil && sess.SrcPort == 0 {
			if v := core.ResolvePortValue(sess.SrcPortDyn, spec.FlowIndex); v != 0 {
				sessSpec.SrcPort = v
			}
		}
		banner := sess.Banner
		if sess.BannerDyn != nil && banner == "" {
			if v := core.ResolveStringValue(sess.BannerDyn, spec.FlowIndex); v != "" {
				banner = v
			}
		}
		flowID := fmt.Sprintf("%s-%s-%d-%d", sessSpec.SrcIP, sessSpec.DstIP, sessSpec.SrcPort, sessSpec.DstPort)

		effectiveTTL := spec.TTL
		if effectiveTTL == 0 {
			effectiveTTL = DefaultTTL
		}
		mss := uint16(DefaultMSS)
		if spec.TCP != nil && spec.TCP.MSS > 0 {
			mss = spec.TCP.MSS
		}
		synOpts := synOptions(mss)

		packetIndex := uint64(0)
		ipID := uint16(rand.Uint32())
		nextIPID := func() uint16 {
			id := ipID
			ipID++
			return id
		}
		// spec.TCP.InitialSeq pins the FIRST session's clientSeq; later
		// sessions get fresh random ISNs (same ISN twice would read as a
		// TCP retransmission to DPI).
		clientSeq := uint32(0)
		if spec.TCP != nil {
			clientSeq = spec.TCP.InitialSeq
		}
		if clientSeq == 0 {
			clientSeq = rand.Uint32()
		}
		serverSeq := rand.Uint32()
		winSize := uint16(65535)

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
				l4.TCPOptions = synOpts
			}
			var meta map[string]interface{}
			if spec.GroupID != nil && spec.GroupID.Strategy != "" {
				if g := core.FlowGroupIDValue(spec.GroupID, 0); g != "" {
					meta = map[string]interface{}{"group_id": g}
				}
			}
			configChan <- core.PacketConfig{
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
			packetIndex++
		}

		emitData := func(direction, srcMAC, dstMAC, srcIP, dstIP string, srcPort, dstPort uint16, senderSeq, peerSeq uint32, payload []byte) (newSenderSeq uint32) {
			for _, seg := range segmentByMSS(payload, int(mss)) {
				emit(direction, srcMAC, dstMAC, srcIP, dstIP, srcPort, dstPort, senderSeq, peerSeq, 0x18, seg)
				senderSeq += uint32(len(seg))
			}
			return senderSeq
		}

		// --- handshake ---
		emit("up", spec.SrcMAC, spec.DstMAC, sessSpec.SrcIP, sessSpec.DstIP, sessSpec.SrcPort, sessSpec.DstPort, clientSeq, 0, 0x02, nil)
		clientSeq++
		emit("down", spec.DstMAC, spec.SrcMAC, sessSpec.DstIP, sessSpec.SrcIP, sessSpec.DstPort, sessSpec.SrcPort, serverSeq, clientSeq, 0x12, nil)
		serverSeq++
		emit("up", spec.SrcMAC, spec.DstMAC, sessSpec.SrcIP, sessSpec.DstIP, sessSpec.SrcPort, sessSpec.DstPort, clientSeq, serverSeq, 0x10, nil)

		// --- session banner ---
		if banner != "" {
			payload := []byte(banner + "\r\n")
			serverSeq = emitData("down", spec.DstMAC, spec.SrcMAC, sessSpec.DstIP, sessSpec.SrcIP, sessSpec.DstPort, sessSpec.SrcPort, serverSeq, clientSeq, payload)
		}

		// --- transactions in order ---
		for txIdx, rawTx := range sess.Transactions {
			// Per-transaction dynamic resolution (D-FTP-2): static transaction
			// passes through untouched (zero-copy); a dynamic one is resolved
			// against spec.FlowIndex. Signal scans below see the RESOLVED text,
			// so PASV/PORT derivation stays correct automatically.
			tx := rawTx
			if hasDynFields(sess) {
				tx = resolveTx(rawTx, spec.FlowIndex)
			}
			for _, cmd := range tx.Commands {
				if cmd.Cmd != "" {
					payload := []byte(cmd.Cmd + "\r\n")
					clientSeq = emitData("up", spec.SrcMAC, spec.DstMAC, sessSpec.SrcIP, sessSpec.DstIP, sessSpec.SrcPort, sessSpec.DstPort, clientSeq, serverSeq, payload)
				}
				if cmd.Response != "" {
					payload := []byte(cmd.Response + "\r\n")
					serverSeq = emitData("down", spec.DstMAC, spec.SrcMAC, sessSpec.DstIP, sessSpec.SrcIP, sessSpec.DstPort, sessSpec.SrcPort, serverSeq, clientSeq, payload)
				}
			}
			if txHasDataChannel(tx) {
				p.emitTxDataChannel(ctx, configChan, tx, sessSpec, flowID, now, &packetIndex, nextIPID, mss, txIdx)
			}
		}

		// --- teardown (FIN-ACK, ACK, FIN-ACK, ACK) ---
		emit("up", spec.SrcMAC, spec.DstMAC, sessSpec.SrcIP, sessSpec.DstIP, sessSpec.SrcPort, sessSpec.DstPort, clientSeq, serverSeq, 0x11, nil)
		clientSeq++
		emit("down", spec.DstMAC, spec.SrcMAC, sessSpec.DstIP, sessSpec.SrcIP, sessSpec.DstPort, sessSpec.SrcPort, serverSeq, clientSeq, 0x10, nil)
		emit("down", spec.DstMAC, spec.SrcMAC, sessSpec.DstIP, sessSpec.SrcIP, sessSpec.DstPort, sessSpec.SrcPort, serverSeq, clientSeq, 0x11, nil)
		serverSeq++
		emit("up", spec.SrcMAC, spec.DstMAC, sessSpec.SrcIP, sessSpec.DstIP, sessSpec.SrcPort, sessSpec.DstPort, clientSeq, serverSeq, 0x10, nil)
	}
}

// txHasDataChannel reports whether any command in the transaction flags the
// data channel AND the transaction carries one (mirrors the legacy
// cmd.EmitDataChannel && dc != nil gate).
// hasDynFields reports whether any dynamic variant exists in the session
// tree (D-FTP-2). Cheap pre-scan: when false, resolveTx returns the
// original transaction with zero allocations and planSessions keeps the
// phase-1 hot path unchanged.
func hasDynFields(sess core.FTPSession) bool {
	if sess.SrcPortDyn != nil || sess.BannerDyn != nil {
		return true
	}
	for _, tx := range sess.Transactions {
		if tx.DataChannel != nil && tx.DataChannel.PayloadDyn != nil {
			return true
		}
		for _, cmd := range tx.Commands {
			if cmd.CmdDyn != nil || cmd.ResponseDyn != nil {
				return true
			}
		}
	}
	return false
}

// resolveTx materializes a flow-index-resolved copy of the transaction:
// command cmd/response and data-channel payload replace their static
// counterparts only when the static field is empty and the dynamic variant
// resolves non-empty. Static values always win (zero semantic change);
// dynamic fields are read-only pointers (never written back).
func resolveTx(tx core.FTPTransaction, i int) core.FTPTransaction {
	if tx.DataChannel != nil && tx.DataChannel.PayloadDyn != nil && tx.DataChannel.Payload == "" {
		if v := core.ResolveStringValue(tx.DataChannel.PayloadDyn, i); v != "" {
			dc := *tx.DataChannel
			dc.Payload = v
			tx.DataChannel = &dc
		}
	}
	// CRITICAL: tx.Commands is the shared slice from ftpConfig.Sessions —
	// the worker reuses the same spec.FTP tree for every flow. Mutating a
	// command in place would corrupt other flows (flow i's resolved text
	// would flow into flow j) and race under -race. Copy the slice first,
	// but only when any dynamic variant actually exists in it.
	hasCmdDyn := false
	for _, cmd := range tx.Commands {
		if cmd.CmdDyn != nil || cmd.ResponseDyn != nil {
			hasCmdDyn = true
			break
		}
	}
	cmds := tx.Commands
	if hasCmdDyn {
		cmds = append([]core.FTPCommand(nil), tx.Commands...)
	}
	for ci := range cmds {
		cmd := &cmds[ci]
		if cmd.CmdDyn != nil && cmd.Cmd == "" {
			if v := core.ResolveStringValue(cmd.CmdDyn, i); v != "" {
				cmd.Cmd = v
			}
		}
		if cmd.ResponseDyn != nil && cmd.Response == "" {
			if v := core.ResolveStringValue(cmd.ResponseDyn, i); v != "" {
				cmd.Response = v
			}
		}
	}
	tx.Commands = cmds
	return tx
}

func txHasDataChannel(tx core.FTPTransaction) bool {
	if tx.DataChannel == nil {
		return false
	}
	for _, cmd := range tx.Commands {
		if cmd.EmitDataChannel {
			return true
		}
	}
	return false
}

// emitTxDataChannel is the per-transaction variant of emitFTPDataChannel:
// identical port derivation (explicit > signaling > fallback) but the
// signaling scan is scoped to THIS transaction's commands (D-FTP-1 T-FTP-4)
// and the sub-flow mounts at sub-{txIdx}.
func (p *Planner) emitTxDataChannel(
	ctx context.Context,
	configChan chan<- core.PacketConfig,
	tx core.FTPTransaction,
	spec core.FlowSpec,
	parentFlowID string,
	now time.Time,
	packetIndex *uint64,
	nextIPID func() uint16,
	parentMSS uint16,
	txIdx int,
) {
	dc := tx.DataChannel
	mode := dc.Mode
	if mode == "" {
		mode = "passive"
	}
	isActive := strings.EqualFold(mode, "active")

	// Per-transaction signaling scope (T-FTP-4): scan only this
	// transaction's command/response pairs for the advertised data port.
	signalingDataPort := scanTxForDataPort(tx.Commands, isActive)

	clientDataPort := dc.SrcPort
	serverDataPort := dc.DstPort

	if isActive {
		if serverDataPort == 0 {
			serverDataPort = 20
		}
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
		if clientDataPort == 0 {
			if spec.SrcPort == 65535 {
				clientDataPort = 1024
			} else {
				clientDataPort = spec.SrcPort + 1
			}
		}
		if serverDataPort == 0 {
			if signalingDataPort != 0 {
				serverDataPort = signalingDataPort
			} else {
				serverDataPort = 50000
			}
		}
	}

	mss := dc.MSS
	if mss == 0 {
		mss = parentMSS
	}

	var payloadBytes []byte
	if dc.FileSource != nil {
		pc := core.PayloadCacheFrom(ctx)
		if pc == nil {
			return
		}
		payloadBytes, _ = pc.GetOrLoad(ctx, *dc.FileSource)
	} else if dc.PayloadB64 != "" {
		payloadBytes, _ = base64.StdEncoding.DecodeString(dc.PayloadB64)
	} else {
		payloadBytes = []byte(dc.Payload)
	}

	if dc.AbortAfterBytes > 0 && dc.AbortAfterBytes < len(payloadBytes) {
		payloadBytes = payloadBytes[:dc.AbortAfterBytes]
	}

	var subPayload string
	var subPayloadB64 string
	if len(payloadBytes) > 0 {
		if core.IsText(payloadBytes) {
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
		GroupID:         spec.GroupID,
	}
	core.EmitSubFlow(configChan, txIdx, sub, spec, parentFlowID, now, packetIndex, nextIPID)
}

// scanTxForDataPort scans ONE transaction's command/response pairs for the
// advertised data port (PORT/EPRT command for active, 227 PASV / 229 EPSV
// response for passive). Mirrors scanCommandsForDataPort's last-wins semantics.
func scanTxForDataPort(commands []core.FTPCommand, isActive bool) uint16 {
	var port uint16
	if isActive {
		for i := 0; i < len(commands); i++ {
			if p := parsePORTPort(commands[i].Cmd); p != 0 {
				port = p
			}
			// D-FTP-4 (RFC 2428 §4): EPRT 与 PORT 同序 last-wins——同一事务
			// 先后通告时后者赢（与现网"后通告覆盖"一致）。
			if p := parseEPRTPort(commands[i].Cmd); p != 0 {
				port = p
			}
		}
	} else {
		for i := 0; i < len(commands); i++ {
			if p := parsePASVPort(commands[i].Response); p != 0 {
				port = p
			}
			// D-FTP-4 (RFC 2428 §3): EPSV 与 227 同序 last-wins。
			if p := parseEPSVPort(commands[i].Response); p != 0 {
				port = p
			}
		}
	}
	return port
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
//
//	"227 Entering Passive Mode (h1,h2,h3,h4,p1,p2)"
//
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
//
//	"PORT h1,h2,h3,h4,p1,p2"
//
// The client tells the server "I'm listening on IP h1.h2.h3.h4 port p1*256+p2".
// Per RFC 959 §5.3.1 FTP commands are case-insensitive — the regex uses
// (?i) so "port", "Port", "PORT" all parse. The (?m) flag makes ^ match
// the start of each line (mirroring pasvPortRe's (?im)) so a multi-line
// command string (e.g. "USER ...\r\nPORT 10,0,0,1,78,17") parses the PORT
// line regardless of which line it's on. Today callers pass single-line
// commands, but the (?m) flag future-proofs against callers that join
// commands with CRLF.
var portCmdRe = regexp.MustCompile(`(?im)^PORT\s+(\d+),(\d+),(\d+),(\d+),(\d+),(\d+)`)

// epsvPortRe matches a 229 EPSV response line per RFC 2428 §3:
//
//	"229 Entering Extended Passive Mode (|||port|)"
//
// Only the port is advertised (the address is the control connection's).
// 口径与 parsePASVPort 同款：字面空格（RFC 959 §5.4 分隔符）、首元组 wins、
// 溢出拒绝。非 229 行（227 PASV 等）不匹配。
var epsvPortRe = regexp.MustCompile(`(?im)^229 [^\n]*?\(\|\|\|(\d+)\|\)`)

// parseEPSVPort scans a server response string for a 229 EPSV port triple
// and returns the advertised data-port. Returns 0 if not found or if the
// port doesn't parse as an integer in [0, 65535].
// Example: "229 Entering Extended Passive Mode (|||50010|)" -> 50010.
func parseEPSVPort(response string) uint16 {
	m := epsvPortRe.FindStringSubmatch(response)
	if m == nil {
		return 0
	}
	p, err := strconv.Atoi(m[1])
	if err != nil {
		return 0
	}
	if p < 0 || p > 65535 {
		return 0
	}
	return uint16(p)
}

// eprtCmdRe matches an EPRT command per RFC 2428 §4:
//
//	"EPRT |af|addr|port|"
//
// af=2 is IPv6 (implemented); af=1 (IPv4 over EPRT) is a documented C-class
// gap (D-FTP-4: 现网只用 PORT 传 v4) and returns 0. The addr segment is
// passed through unchecked (opaque to port derivation); only the port
// segment is validated. Case-insensitive per RFC 959 §5.3.1 (multiline
// future-proofing mirrors portCmdRe).
var eprtCmdRe = regexp.MustCompile(`(?im)^EPRT\s+\|(\d+)\|([^|]*)\|(\d+)\|`)

// parseEPRTPort scans a client command for an EPRT triple and returns the
// advertised data-port. Returns 0 if not an EPRT line, af != 2, segments
// missing, or the port doesn't parse as an integer in [0, 65535].
// Example: "EPRT |2|2001:db8::1|50011|" -> 50011.
func parseEPRTPort(cmd string) uint16 {
	m := eprtCmdRe.FindStringSubmatch(cmd)
	if m == nil {
		return 0
	}
	if m[1] != "2" {
		return 0
	}
	p, err := strconv.Atoi(m[3])
	if err != nil {
		return 0
	}
	if p < 0 || p > 65535 {
		return 0
	}
	return uint16(p)
}

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
			// D-FTP-4 (RFC 2428 §4): 老形状遗留路径同步新增 EPRT（与
			// scanTxForDataPort 同序，两处调用点语义一致）。
			if p := parseEPRTPort(commands[i].Cmd); p != 0 {
				port = p
			}
		}
	} else {
		for i := 0; i <= upToIdx; i++ {
			if p := parsePASVPort(commands[i].Response); p != 0 {
				port = p
			}
			// D-FTP-4 (RFC 2428 §3): 老形状遗留路径同步新增 EPSV。
			if p := parseEPSVPort(commands[i].Response); p != 0 {
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
//
//  1. Explicit user override (dc.SrcPort / dc.DstPort).
//
//  2. Parsed from signaling (PASV 227 response for passive; PORT command
//     for active) — this is what makes the data-channel 4-tuple match what
//     the control channel actually advertised.
//
//  3. Hardcoded fallback (server port 20 for active; ephemeral
//     control_src_port+1 for the client's side; 50000 when no PASV response
//     in dialog).
//
//     - active mode (PORT): server connects from port 20 to client's data-port.
//     SubFlowSpec.ServerInitiated=true so SYN goes server→client.
//     - passive mode (PASV): client connects from an ephemeral port to
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
	// that forgot core.WithPayloadCache, or a controller path that doesn't
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
		pc := core.PayloadCacheFrom(ctx)
		if pc == nil {
			return
		}
		payloadBytes, _ = pc.GetOrLoad(ctx, *dc.FileSource)
	} else if dc.PayloadB64 != "" {
		payloadBytes, _ = base64.StdEncoding.DecodeString(dc.PayloadB64)
	} else {
		payloadBytes = []byte(dc.Payload)
	}

	// ABOR (RFC 959 §4.1.4): when AbortAfterBytes > 0, truncate the payload
	// to the first N bytes. This models a transfer interrupted mid-stream -
	// the data channel sends a prefix of the file then tears down, while the
	// control channel carries the ABOR command + 426/226 responses. A value
	// >= len(payloadBytes) is a no-op (no truncation past the end).
	if dc.AbortAfterBytes > 0 && dc.AbortAfterBytes < len(payloadBytes) {
		payloadBytes = payloadBytes[:dc.AbortAfterBytes]
	}

	var subPayload string
	var subPayloadB64 string
	if len(payloadBytes) > 0 {
		// Prefer the text field when the bytes are valid UTF-8 and contain
		// no NUL bytes (a heuristic for "this is text"). Otherwise encode
		// as base64 so binary payloads round-trip exactly. This mirrors
		// how a user would write the same bytes inline.
		if core.IsText(payloadBytes) {
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
		// Pass the parent's GroupID so EmitSubFlow pre-writes
		// Metadata["group_id"] for the sub-flow packets. We assign the
		// SAME pointer (not a copy) so resolveSubFlowGroupID's first
		// branch (sub.GroupID non-nil) wins and returns the parent's
		// evaluated gID — equivalent to inheriting, just via the override
		// path. nil parent -> nil sub.GroupID -> both branches of
		// resolveSubFlowGroupID return "" -> no Metadata write, matching
		// pre-fix behavior.
		GroupID: spec.GroupID,
	}
	core.EmitSubFlow(configChan, 0, sub, spec, parentFlowID, now, packetIndex, nextIPID)
}

// (Removed local isText helper — moved to core.IsText in Task 12.
// All five planners (ftp, sip, sctp, http, icmp) now share the single
// core.IsText definition.)
