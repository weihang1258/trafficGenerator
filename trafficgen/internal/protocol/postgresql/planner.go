// Package postgresql implements the PostgreSQL wire protocol v3 (and v3.1
// with Pipeline Mode support) planner.
//
// PostgreSQL is a session-level protocol: a single TCP connection on port
// 5432 carries StartupMessage → authentication → ready → operations →
// Terminate. The planner emits:
//
//  1. TCP 3-way handshake (SYN, SYN-ACK, ACK) with MSS/WinScale/SACK
//     options, mirroring the FTP/HTTP/SIP/POP3 control-channel pattern.
//     Skipped when PostgreSQLConfig.EmitHandshake = false.
//  2. StartupMessage (no type byte, just 4-byte length) with protocol
//     version + parameter pairs (key\0val\0...).
//  3. Authentication frames depending on AuthMethod:
//     - "trust": server sends AuthenticationOk directly.
//     - "cleartext": server requests plaintext password, client replies.
//     - "md5": server requests MD5 password (4-byte salt), client replies
//       with md5(md5(password + username) || salt) hex form.
//     - "scram-sha-256": 4-step SASL exchange with stubbed crypto.
//     - "gss" / "sspi": opaque byte placeholder + AuthOk.
//  4. ParameterStatus* (S) + BackendKeyData (K) + ReadyForQuery (Z, 'I').
//  5. Each PGOperation: client request (PSH-ACK up) + server response
//     (PSH-ACK down). Supports query / parse / bind / describe / execute /
//     sync / close / flush / copy-from / copy-to / listen / unlisten /
//     replication-identify / replication-start / terminate / function-call.
//  6. TCP 4-way teardown (FIN-ACK, ACK, FIN-ACK, ACK), unless
//     PostgreSQLConfig.EmitTeardown = false.
//
// All messages use the v3 general format: 1-byte type tag + 4-byte big-endian
// length (length INCLUDES itself but NOT the type byte) + payload. The
// StartupMessage is the only exception - it has no type byte, just a
// 4-byte length. ErrorResponse / NoticeResponse fields are 1-byte type +
// C-string value, terminated by a single \0 byte.
//
// The planner models byte-level format faithfully so Wireshark's PostgreSQL
// dissector can parse the resulting packets. Real PostgreSQL servers will
// reject SCRAM/MD5/GSS handshakes (the planner does NOT implement real
// cryptography - it emits correctly-shaped bytes matching protocol field
// layout). For traffic-generation purposes this is acceptable: the goal is
// "wire-format correct", not "session authenticated".
//
// The planner does NOT enforce PG state-machine transitions. The user is
// responsible for providing a logically valid dialog. This matches the
// trafficgen contract: synthesize test packets, not a real PG server.
package postgresql

import (
	"context"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/rand"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
)

const (
	// DefaultTTL mirrors internal/protocol/tcp.DefaultTTL and
	// internal/protocol/pop3.DefaultTTL (64). Standard IP TTL.
	DefaultTTL = 64

	// DefaultMSS mirrors internal/protocol/tcp.DefaultMSS (1460).
	DefaultMSS = 1460

	// MinMSS per RFC 879.
	MinMSS = 536

	// DefaultPort is the well-known PostgreSQL port per RFC 765.
	DefaultPort = 5432

	// ProtocolV3 is the default PostgreSQL protocol version (v3.0).
	ProtocolV3 = 0x00030000

	// ProtocolV3Pipeline is v3.1 with Pipeline Mode support.
	ProtocolV3Pipeline = 0x00030001

	// DefaultRowCount is the default RowDescription row count for SELECT
	// queries that produce a result set. Real SELECT results vary; we
	// emit a single synthetic DataRow by default.
	DefaultRowCount = 1

	// DefaultWALDataSize bytes per XLogData frame in replication-start.
	DefaultWALDataSize = 64
)

// ASCII byte constants for message type tags. PostgreSQL uses ASCII
// letters for regular messages and digits '1'/'2'/'3' for sub-protocol
// responses. The compiler enforces uint8 size.
const (
	typeAuth           byte = 'R' // 0x52, Authentication (sub-typed by int32)
	typeParameter      byte = 'S' // 0x53, ParameterStatus
	typeBackendKeyData byte = 'K' // 0x4B, BackendKeyData
	typeReadyForQuery  byte = 'Z' // 0x5A, ReadyForQuery
	typeDataRow        byte = 'D' // 0x44, DataRow
	typeRowDesc        byte = 'T' // 0x54, RowDescription
	typeCmdComplete    byte = 'C' // 0x43, CommandComplete
	typeEmptyQuery     byte = 'I' // 0x49, EmptyQueryResponse
	typeNotice         byte = 'N' // 0x4E, NoticeResponse
	typeError          byte = 'E' // 0x45, ErrorResponse
	typeNotification   byte = 'A' // 0x41, NotificationResponse

	typeParseComplete      byte = '1' // 0x31
	typeBindComplete       byte = '2' // 0x32
	typeCloseComplete      byte = '3' // 0x33
	typeParameterDesc      byte = 't' // 0x74
	typeNoData             byte = 'n' // 0x6E
	typePortalSuspended    byte = 's' // 0x73
	typePortalBindComplete byte = 'v' // 0x76
	typeCopyIn             byte = 'B' // 0x42, CopyInResponse
	typeCopyOut            byte = 'H' // 0x48, CopyOutResponse
	typeCopyBoth           byte = 'W' // 0x57, CopyBothResponse (walsender)
	typeCopyData           byte = 'd' // 0x64, CopyData
	typeCopyDone           byte = 'c' // 0x63, CopyDone
	typeCopyFail           byte = 'f' // 0x66, CopyFail
	typeFuncCallResp       byte = 'V' // 0x56, FunctionCallResponse

	// Frontend message types:
	typeQuery       byte = 'Q' // 0x51
	typeParse       byte = 'P' // 0x50
	typeBind        byte = 'B' // 0x42 (front-side; same letter as CopyInResponse)
	typeDescribe    byte = 'D' // 0x44 (front-side; same letter as DataRow)
	typeExecute     byte = 'E' // 0x45 (front-side; same letter as ErrorResponse)
	typeClose       byte = 'C' // 0x43 (front-side; same letter as CommandComplete)
	typeFlush       byte = 'H' // 0x48 (front-side; same letter as CopyOutResponse)
	typeSync        byte = 'S' // 0x53 (front-side; same letter as ParameterStatus)
	typeTerminate   byte = 'X' // 0x58
	typeFunction    byte = 'F' // 0x46
	typePassword    byte = 'p' // 0x70, used by PasswordMessage AND
	                             // SASLInitialResponse AND SASLResponse per
	                             // PostgreSQL frontend protocol (all 3 use 'p').
	typeSASL        byte = 'p' // alias for typePassword (frontend SASL)

	// Authentication sub-types (int32 discriminator after type 'R').
	authOk            int32 = 0
	authKerberosV5    int32 = 2
	authCleartext     int32 = 3
	authMD5           int32 = 5
	authGSS           int32 = 7
	authGSSContinue   int32 = 8
	authSSPI          int32 = 9
	authSASL          int32 = 10
	authSASLContinue  int32 = 11
	authSASLFinal     int32 = 12

	// ReadyForQuery status bytes.
	rfqIdle    byte = 'I' // not in transaction
	rfqInTrans byte = 'T' // in transaction
	rfqFailed  byte = 'E' // in failed transaction

	// Describe/Close mode discriminator.
	modeStatement byte = 's' // 'statement' (lowercase 's' = byte 0x73)
	modePortal    byte = 'p' // 'portal'    (lowercase 'p' = byte 0x70)

	// WAL sub-types inside CopyData byte 0.
	walSubXLogData         byte = 'w'
	walSubPrimaryKeepalive byte = 'k'
)

// Common PostgreSQL type OIDs (used by RowDescription fields).
const (
	oidBool    int32 = 16
	oidBytea   int32 = 17
	oidInt8    int32 = 20
	oidInt4    int32 = 23
	oidText    int32 = 25
	oidFloat8  int32 = 701
	oidNumeric int32 = 1700
	oidUUID    int32 = 2950
)

// emitFunc is a closure type for emit().
type emitFunc func(direction, srcMAC, dstMAC, srcIP, dstIP string, srcPort, dstPort uint16, seq, ack uint32, flags uint8, payload []byte)

// emitDataFunc is the MSS-segmented variant of emitFunc.
type emitDataFunc func(direction, srcMAC, dstMAC, srcIP, dstIP string, srcPort, dstPort uint16, senderSeq, peerSeq uint32, payload []byte) uint32

// runState carries the mutable per-Plan state (counters, ISNs, etc.).
// Created in Plan() and passed through runFlow / runAuth / runOperation.
//
// clientSeq / serverSeq are deliberately NOT stored here: they are threaded
// as function parameters and return values through runFlow -> runAuth ->
// runOperation. Go closures capture variables by reference, so the
// closure-based sendUp/sendDown helpers inside each sub-function always see
// the latest value of their enclosing function's local seq variables. This
// mirrors the pop3 / telnet planner pattern.
type runState struct {
	spec   core.FlowSpec
	cfg    *core.PostgreSQLConfig
	now_   time.Time
	pktIdx uint64
	ipID   uint16
	ttl    uint8
}

// Planner implements the PostgreSQL protocol planner.
type Planner struct{}

// NewPlanner creates a new PostgreSQL planner.
func NewPlanner() *Planner { return &Planner{} }

// Name returns the protocol name. Used by the registry to look up the
// planner by the "postgresql" string in FlowSpec JSON tags and
// Task.Protocol.
func (p *Planner) Name() string { return "postgresql" }

// Validate validates a PostgreSQL flow spec. Read-only: never modifies
// spec. Per validate_conventions.md §1.1, default-value filling happens
// in Plan(), not here.
func (p *Planner) Validate(spec core.FlowSpec) error {
	// If PostgreSQL is nil, the caller asked for a different protocol.
	// Validate is a no-op so the registry can probe planners without
	// pulling in their config.
	if spec.PostgreSQL == nil {
		return nil
	}

	// IP validity (read-only; "" = use default filled by Plan).
	if spec.SrcIP != "" {
		if net.ParseIP(spec.SrcIP) == nil {
			return fmt.Errorf("postgresql: SrcIP %q is not a valid IP address", spec.SrcIP)
		}
	}
	if spec.DstIP != "" {
		if net.ParseIP(spec.DstIP) == nil {
			return fmt.Errorf("postgresql: DstIP %q is not a valid IP address", spec.DstIP)
		}
	}

	// MSS is a TCP transport parameter; lives on TCPConfig. 0 = default.
	if spec.TCP != nil && spec.TCP.MSS > 0 {
		if spec.TCP.MSS < MinMSS {
			return fmt.Errorf("postgresql: MSS %d too small (min %d per RFC 879)", spec.TCP.MSS, MinMSS)
		}
	}

	// ProtocolVersion sanity (only 3.0 and 3.1 are supported).
	if spec.PostgreSQL.ProtocolVersion != 0 &&
		spec.PostgreSQL.ProtocolVersion != ProtocolV3 &&
		spec.PostgreSQL.ProtocolVersion != ProtocolV3Pipeline {
		return fmt.Errorf("postgresql: ProtocolVersion 0x%08X unsupported (only 0x%08X and 0x%08X)", spec.PostgreSQL.ProtocolVersion, ProtocolV3, ProtocolV3Pipeline)
	}

	// AuthMethod whitelist (case-insensitive).
	if am := spec.PostgreSQL.AuthMethod; am != "" {
		switch strings.ToLower(am) {
		case "trust", "cleartext", "md5", "scram-sha-256", "gss", "sspi":
			// ok
		default:
			return fmt.Errorf("postgresql: AuthMethod %q unsupported (use trust/cleartext/md5/scram-sha-256/gss/sspi)", am)
		}
	}

	// MD5Salt must be exactly 4 bytes when provided (otherwise planner
	// falls back to the default).
	if salt := spec.PostgreSQL.MD5Salt; len(salt) != 0 && len(salt) != 4 {
		return fmt.Errorf("postgresql: MD5Salt must be exactly 4 bytes (got %d)", len(salt))
	}

	return nil
}

// fillDefaults applies per-Plan defaults on top of the user's
// PostgreSQLConfig. The output is a freshly-allocated map where the
// planner can mutate freely without surprising the caller (per
// validate_conventions.md §1.3).
func fillDefaults(in *core.PostgreSQLConfig) *core.PostgreSQLConfig {
	out := *in
	if out.ProtocolVersion == 0 {
		out.ProtocolVersion = ProtocolV3
	}
	if out.StartupParams == nil {
		out.StartupParams = map[string]string{
			"user":            "postgres",
			"database":        "postgres",
			"client_encoding": "UTF8",
		}
	}
	if out.AuthMethod == "" {
		out.AuthMethod = "trust"
	} else {
		out.AuthMethod = strings.ToLower(out.AuthMethod)
	}
	if out.Username == "" {
		if u, ok := out.StartupParams["user"]; ok && u != "" {
			out.Username = u
		} else {
			out.Username = "postgres"
		}
	}
	if out.Password == "" {
		out.Password = "testpass"
	}
	if out.RowCount <= 0 {
		out.RowCount = DefaultRowCount
	}
	if out.WALDataSize <= 0 {
		out.WALDataSize = DefaultWALDataSize
	}
	// EmitHandshake / EmitTeardown default true (nil pointer = use default).
	if out.EmitHandshake == nil {
		t := true
		out.EmitHandshake = &t
	}
	if out.EmitTeardown == nil {
		t := true
		out.EmitTeardown = &t
	}
	return &out
}

// Plan generates packet configs for a PostgreSQL flow. Returns a channel
// that yields PacketConfig values in wire order. The channel is closed
// when generation completes or when ctx is cancelled.
func (p *Planner) Plan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) {
	if err := p.Validate(spec); err != nil {
		return nil, err
	}

	// If PostgreSQL is nil, the caller asked for a different protocol.
	// Return an empty channel so the engine can move on without
	// double-emitting packets.
	emitCfg := spec.PostgreSQL != nil

	configChan := make(chan core.PacketConfig, 256)

	go func() {
		defer close(configChan)
		if !emitCfg {
			return
		}

		cfg := fillDefaults(spec.PostgreSQL)
		state := &runState{
			spec: spec,
			cfg:  cfg,
			now_: time.Now(),
			ipID: uint16(rand.Uint32()),
			ttl:  spec.TTL,
		}
		if state.ttl == 0 {
			state.ttl = DefaultTTL
		}

		// emit writes one packet to configChan. Pre-writes
		// Metadata["group_id"] when spec carries a GroupID strategy,
		// mirroring the pop3 pattern.
		emit := func(direction, srcMAC, dstMAC, srcIP, dstIP string, srcPort, dstPort uint16, seq, ack uint32, flags uint8, payload []byte) {
			l3 := core.L3Base(srcIP, dstIP, 6, state.ttl, state.nextIPID(), spec)
			l4 := core.L4Config{
				Protocol:   "tcp",
				SrcPort:    srcPort,
				DstPort:    dstPort,
				Seq:        seq,
				Ack:        ack,
				Flags:      flags,
				WindowSize: 65535,
			}
			if flags == 0x02 || flags == 0x12 {
				l4.TCPOptions = state.synOptions()
			}
			var meta map[string]interface{}
			if spec.GroupID != nil && spec.GroupID.Strategy != "" {
				if g := core.FlowGroupIDValue(spec.GroupID, 0); g != "" {
					meta = map[string]interface{}{"group_id": g}
				}
			}
			configChan <- core.PacketConfig{
				FlowID:      fmt.Sprintf("%s-%s-%d-%d", spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort),
				PacketIndex: state.nextPktIdx(),
				Direction:   direction,
				Timestamp:   state.now_,
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
		}

		state.runFlow(emit)
		_ = ctx
	}()

	return configChan, nil
}

// runFlow orchestrates the PG state machine: handshake → StartupMessage
// → auth → ParameterStatus* → BackendKeyData → ReadyForQuery →
// Operations → terminate.
func (s *runState) runFlow(emit emitFunc) {
	cfg := s.cfg
	spec := s.spec

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

	emitData := func(direction, srcMAC, dstMAC, srcIP, dstIP string, srcPort, dstPort uint16, senderSeq, peerSeq uint32, payload []byte) uint32 {
		for _, seg := range s.segmentByMSS(payload) {
			emit(direction, srcMAC, dstMAC, srcIP, dstIP, srcPort, dstPort, senderSeq, peerSeq, 0x18, seg)
			senderSeq += uint32(len(seg))
		}
		return senderSeq
	}

	// 1. TCP handshake.
	if *cfg.EmitHandshake {
		emit("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, 0, 0x02, nil)
		clientSeq++
		emit("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, 0x12, nil)
		serverSeq++
		emit("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, 0x10, nil)
	}

	// 2. StartupMessage (client → server, untagged).
	startup := encodeStartup(cfg.ProtocolVersion, cfg.StartupParams)
	clientSeq = emitData("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, startup)

	// 3. Authentication exchange.
	clientSeq, serverSeq = s.runAuth(emit, clientSeq, serverSeq, emitData)

	// 4. ParameterStatus* (server → client, deterministic order so tests
	//    can assert specific parameter names).
	paramOrder := []struct{ name, val string }{
		{"server_encoding", "UTF8"},
		{"client_encoding", "UTF8"},
		{"DateStyle", "ISO, MDY"},
		{"TimeZone", "UTC"},
		{"integer_datetimes", "on"},
		{"standard_conforming_strings", "on"},
		{"application_name", "trafficgen"},
	}
	for _, p := range paramOrder {
		serverSeq = emitData("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, encodeParameterStatus(p.name, p.val))
	}

	// 5. BackendKeyData (K) — pid + secret (deterministic for tests).
	serverSeq = emitData("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, encodeBackendKeyData(12345, 67890))

	// 6. ReadyForQuery (Z, 'I').
	serverSeq = emitData("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, encodeReadyForQuery(rfqIdle))

	// 7. Operations.
	currentStatus := rfqIdle
	for i := range cfg.Operations {
		clientSeq, serverSeq, currentStatus = s.runOperation(emit, clientSeq, serverSeq, currentStatus, &cfg.Operations[i], emitData)
	}

	// 8. TCP teardown.
	if *cfg.EmitTeardown {
		emit("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, 0x11, nil)
		clientSeq++
		emit("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, 0x10, nil)
		emit("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, 0x11, nil)
		serverSeq++
		emit("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, 0x10, nil)
	}
}

// runAuth emits the auth-method-specific exchange and returns updated
// client/server sequence numbers.
func (s *runState) runAuth(emit emitFunc, clientSeq, serverSeq uint32, emitData emitDataFunc) (uint32, uint32) {
	cfg := s.cfg
	spec := s.spec

	sendDown := func(payload []byte) uint32 {
		serverSeq = emitData("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, payload)
		return serverSeq
	}
	sendUp := func(payload []byte) uint32 {
		clientSeq = emitData("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, payload)
		return clientSeq
	}

	switch cfg.AuthMethod {
	case "trust":
		serverSeq = sendDown(encodeAuthOk())
	case "cleartext":
		serverSeq = sendDown(encodeAuthRequest(authCleartext))
		clientSeq = sendUp(encodePassword(cfg.Password))
		serverSeq = sendDown(encodeAuthOk())
	case "md5":
		salt := s.md5SaltOrDefault()
		serverSeq = sendDown(encodeAuthMD5(salt))
		hash := md5Hex(cfg.Username, cfg.Password, salt)
		clientSeq = sendUp(encodePassword("md5" + hash))
		serverSeq = sendDown(encodeAuthOk())
	case "scram-sha-256":
		serverSeq = sendDown(encodeAuthSASL([]string{"SCRAM-SHA-256"}))

		clientNonce := randomScramNonce()
		first := "n,,n=" + cfg.Username + ",r=" + clientNonce
		clientSeq = sendUp(encodeSASLInitialResponse("SCRAM-SHA-256", first))

		serverNonce := randomScramNonce()
		serverFirst := "r=" + clientNonce + serverNonce + ",s=" + randomBase64Salt() + ",i=4096"
		serverSeq = sendDown(encodeAuthSASLContinue([]byte(serverFirst)))

		clientFinal := "c=biws,r=" + clientNonce + serverNonce + ",p=" + randomBase64(32)
		clientSeq = sendUp(encodeSASLResponse(clientFinal))

		serverFinal := "v=" + randomBase64(32)
		serverSeq = sendDown(encodeAuthSASLFinal([]byte(serverFinal)))
		serverSeq = sendDown(encodeAuthOk())
	case "gss":
		serverSeq = sendDown(encodeAuthRequest(authGSS))
		clientSeq = sendUp(encodePassword("opaque-gss-token"))
		serverSeq = sendDown(encodeAuthOk())
	case "sspi":
		serverSeq = sendDown(encodeAuthRequest(authSSPI))
		clientSeq = sendUp(encodePassword("opaque-sspi-token"))
		serverSeq = sendDown(encodeAuthOk())
	default:
		// Unknown method: degrade to trust (planner is best-effort).
		serverSeq = sendDown(encodeAuthOk())
	}
	return clientSeq, serverSeq
}

// runOperation emits frames for one PGOperation, updating sequence
// numbers and transaction status.
func (s *runState) runOperation(emit emitFunc, clientSeq, serverSeq uint32, currentStatus byte, op *core.PGOperation, emitData emitDataFunc) (uint32, uint32, byte) {
	cfg := s.cfg
	spec := s.spec

	sendDown := func(payload []byte) uint32 {
		serverSeq = emitData("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, payload)
		return serverSeq
	}
	sendUp := func(payload []byte) uint32 {
		clientSeq = emitData("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, payload)
		return clientSeq
	}

	if op.EmitAsServer {
		switch op.Kind {
		case "notification":
			serverSeq = sendDown(encodeNotificationResponse(12345, op.NotifyChannel, op.NotifyPayload))
		case "xlog-data":
			serverSeq = sendDown(encodeCopyData(encodeXLogData(12345, 0, 0, fillWal(cfg.WALDataSize))))
		case "keepalive":
			serverSeq = sendDown(encodeCopyData(encodePrimaryKeepalive(0, 0, 0)))
		}
		return clientSeq, serverSeq, currentStatus
	}

	switch op.Kind {
	case "query":
		clientSeq = sendUp(encodeQuery(op.SQL))
		serverSeq, currentStatus = s.runSimpleQuery(sendDown, serverSeq, op.SQL, currentStatus)
	case "parse":
		clientSeq = sendUp(encodeParse(op.Statement, op.SQL, s.paramOIDs(op.ParamCount)))
		serverSeq = sendDown(encodeParseComplete())
	case "bind":
		clientSeq = sendUp(encodeBind(op.Portal, op.Statement, s.bindParamFmts(op.ParamCount), s.bindParamValues(op.ParamValues), nil))
		serverSeq = sendDown(encodeBindComplete())
	case "describe":
		mode, name := descModeName(op)
		clientSeq = sendUp(encodeDescribe(mode, name))
		// planner emits RowDescription by default; user can model NoData
		// by setting ParamCount=0 (would emit n in a future refinement).
		serverSeq = sendDown(encodeRowDescription(s.rowDescFields(1)))
	case "execute":
		clientSeq = sendUp(encodeExecute(op.Portal, op.MaxRows))
		for i := 0; i < cfg.RowCount; i++ {
			serverSeq = sendDown(encodeDataRow(s.syntheticDataRowColumns(1)))
		}
		if op.MaxRows > 0 && int32(cfg.RowCount) > op.MaxRows {
			serverSeq = sendDown(encodePortalSuspended())
		}
		serverSeq = sendDown(encodeCommandComplete(fmt.Sprintf("SELECT %d", cfg.RowCount)))
	case "sync":
		clientSeq = sendUp(encodeSync())
		serverSeq = sendDown(encodeReadyForQuery(currentStatus))
	case "close":
		mode, name := descModeName(op)
		clientSeq = sendUp(encodeClose(mode, name))
		serverSeq = sendDown(encodeCloseComplete())
	case "flush":
		clientSeq = sendUp(encodeFlush())
		serverSeq = sendDown(encodeReadyForQuery(currentStatus))
	case "copy-from":
		clientSeq = sendUp(encodeQuery("COPY t FROM STDIN"))
		cols := []int16{0, 0}
		serverSeq = sendDown(encodeCopyInResponse(0, cols))
		if len(op.CopyData) > 0 {
			var buf strings.Builder
			for _, row := range op.CopyData {
				buf.WriteString(row)
			}
			clientSeq = sendUp(encodeCopyData([]byte(buf.String())))
		}
		clientSeq = sendUp(encodeCopyDone())
		serverSeq = sendDown(encodeCommandComplete(fmt.Sprintf("COPY %d", len(op.CopyData))))
		serverSeq = sendDown(encodeReadyForQuery(currentStatus))
	case "copy-to":
		clientSeq = sendUp(encodeQuery("COPY t TO STDOUT"))
		cols := []int16{0, 0}
		serverSeq = sendDown(encodeCopyOutResponse(0, cols))
		if len(op.CopyData) > 0 {
			var buf strings.Builder
			for _, row := range op.CopyData {
				buf.WriteString(row)
			}
			serverSeq = sendDown(encodeCopyData([]byte(buf.String())))
		}
		serverSeq = sendDown(encodeCommandComplete(fmt.Sprintf("COPY %d", len(op.CopyData))))
		serverSeq = sendDown(encodeReadyForQuery(currentStatus))
	case "listen":
		sql := "LISTEN " + op.Channel
		clientSeq = sendUp(encodeQuery(sql))
		serverSeq = sendDown(encodeCommandComplete("LISTEN"))
		serverSeq = sendDown(encodeReadyForQuery(currentStatus))
		if cfg.NotificationPayload != "" || op.NotifyPayload != "" {
			payload := cfg.NotificationPayload
			if op.NotifyPayload != "" {
				payload = op.NotifyPayload
			}
			channel := op.Channel
			if op.NotifyChannel != "" {
				channel = op.NotifyChannel
			}
			serverSeq = sendDown(encodeNotificationResponse(12345, channel, payload))
		}
	case "unlisten":
		sql := "UNLISTEN " + op.Channel
		if op.Channel == "" {
			sql = "UNLISTEN *"
		}
		clientSeq = sendUp(encodeQuery(sql))
		serverSeq = sendDown(encodeCommandComplete("UNLISTEN"))
		serverSeq = sendDown(encodeReadyForQuery(currentStatus))
	case "replication-identify":
		clientSeq = sendUp(encodeQuery("IDENTIFY_SYSTEM"))
		serverSeq = sendDown(encodeRowDescription([]core.PGField{
			{Name: "systemid", TypeOID: oidText, TypeLen: -1, FormatCode: 0},
		}))
		serverSeq = sendDown(encodeDataRow([][]byte{[]byte("trafficgen")}))
		serverSeq = sendDown(encodeCommandComplete("SELECT 1"))
		serverSeq = sendDown(encodeReadyForQuery(currentStatus))
	case "replication-start":
		kind := orDefault(op.ReplicationKind, "physical")
		kindUpper := strings.ToUpper(kind)
		sql := "START_REPLICATION SLOT \"" + op.ReplicationSlot + "\" " + kindUpper + " " + op.ReplicationLSN
		clientSeq = sendUp(encodeQuery(sql))
		cols := []int16{0, 0}
		serverSeq = sendDown(encodeCopyBothResponse(1, cols))
		serverSeq = sendDown(encodeCopyData(encodeXLogData(12345, 0, 0, fillWal(cfg.WALDataSize))))
		serverSeq = sendDown(encodeCopyData(encodePrimaryKeepalive(0, 0, 0)))
	case "terminate":
		clientSeq = sendUp(encodeTerminate())
	case "function-call":
		clientSeq = sendUp(encodeFunctionCall(1244, []int16{0}, op.ParamValues, 0))
		serverSeq = sendDown(encodeFunctionCallResponse([]byte{0, 0, 0, 0}))
	default:
		// Unknown kind: emit Sync + ReadyForQuery to keep channel
		// bounded.
		clientSeq = sendUp(encodeSync())
		serverSeq = sendDown(encodeReadyForQuery(currentStatus))
	}
	return clientSeq, serverSeq, currentStatus
}

// descModeName returns the mode byte (s/p) and name string for a
// describe / close operation. Defaults to "statement" with empty name.
func descModeName(op *core.PGOperation) (byte, string) {
	if strings.EqualFold(op.Mode, "portal") {
		return modePortal, op.Portal
	}
	return modeStatement, op.Statement
}

// runSimpleQuery models a Simple Query response set: T (optional) +
// D* (optional) + C + Z.
func (s *runState) runSimpleQuery(sendDown func([]byte) uint32, serverSeq uint32, sql string, currentStatus byte) (uint32, byte) {
	cfg := s.cfg
	trimmed := strings.TrimSpace(sql)
	if trimmed == "" {
		serverSeq = sendDown(encodeEmptyQueryResponse())
		serverSeq = sendDown(encodeReadyForQuery(currentStatus))
		return serverSeq, currentStatus
	}

	upper := strings.ToUpper(trimmed)
	switch {
	case strings.HasPrefix(upper, "BEGIN"), strings.HasPrefix(upper, "START TRANSACTION"):
		serverSeq = sendDown(encodeCommandComplete("BEGIN"))
		serverSeq = sendDown(encodeReadyForQuery(rfqInTrans))
		return serverSeq, rfqInTrans
	case upper == "COMMIT", upper == "END":
		serverSeq = sendDown(encodeCommandComplete("COMMIT"))
		serverSeq = sendDown(encodeReadyForQuery(rfqIdle))
		return serverSeq, rfqIdle
	case upper == "ROLLBACK", strings.HasPrefix(upper, "ROLLBACK "):
		serverSeq = sendDown(encodeCommandComplete("ROLLBACK"))
		serverSeq = sendDown(encodeReadyForQuery(rfqIdle))
		return serverSeq, rfqIdle
	case strings.HasPrefix(upper, "SELECT"):
		ncols := strings.Count(trimmed, ",") + 1
		serverSeq = sendDown(encodeRowDescription(s.rowDescFields(ncols)))
		for i := 0; i < cfg.RowCount; i++ {
			serverSeq = sendDown(encodeDataRow(s.syntheticDataRowColumns(ncols)))
		}
		serverSeq = sendDown(encodeCommandComplete(fmt.Sprintf("SELECT %d", cfg.RowCount)))
		serverSeq = sendDown(encodeReadyForQuery(rfqIdle))
		return serverSeq, rfqIdle
	case strings.HasPrefix(upper, "LISTEN"), strings.HasPrefix(upper, "UNLISTEN"):
		tag := "LISTEN"
		if strings.HasPrefix(upper, "UNLISTEN") {
			tag = "UNLISTEN"
		}
		serverSeq = sendDown(encodeCommandComplete(tag))
		serverSeq = sendDown(encodeReadyForQuery(rfqIdle))
		return serverSeq, rfqIdle
	}

	serverSeq = sendDown(encodeCommandComplete("OK"))
	serverSeq = sendDown(encodeReadyForQuery(currentStatus))
	return serverSeq, currentStatus
}

// --- runState helpers ---

func (s *runState) nextIPID() uint16 {
	id := s.ipID
	s.ipID++
	return id
}

func (s *runState) nextPktIdx() uint64 {
	idx := s.pktIdx
	s.pktIdx++
	return idx
}

func (s *runState) synOptions() []core.TCPOption {
	mss := uint16(DefaultMSS)
	return []core.TCPOption{
		{Kind: core.TCPOptMSS, Data: []byte{byte(mss >> 8), byte(mss)}},
		{Kind: core.TCPOptWinScale, Data: []byte{0x07}},
		{Kind: core.TCPOptSACKPermit},
	}
}

// segmentByMSS splits payload into chunks of at most spec.TCP.MSS bytes.
// A nil/empty payload returns a single empty chunk (matches the
// pre-segmentation behavior where an empty body still produced one
// packet).
func (s *runState) segmentByMSS(payload []byte) [][]byte {
	mss := DefaultMSS
	if s.spec.TCP != nil && s.spec.TCP.MSS > 0 {
		mss = int(s.spec.TCP.MSS)
	}
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

func (s *runState) md5SaltOrDefault() []byte {
	if len(s.cfg.MD5Salt) == 4 {
		out := make([]byte, 4)
		copy(out, s.cfg.MD5Salt)
		return out
	}
	return []byte{0x12, 0x34, 0x56, 0x78}
}

func (s *runState) rowDescFields(n int) []core.PGField {
	fields := make([]core.PGField, n)
	for i := 0; i < n; i++ {
		oid := oidInt4
		if v, ok := s.cfg.ColumnTypes[i+1]; ok {
			oid = v
		}
		fields[i] = core.PGField{
			Name:       fmt.Sprintf("col%d", i+1),
			TableOID:   0,
			Column:     int16(i + 1),
			TypeOID:    oid,
			TypeLen:    -1,
			TypeMod:    -1,
			FormatCode: 0,
		}
	}
	return fields
}

func (s *runState) syntheticDataRowColumns(n int) [][]byte {
	cols := make([][]byte, n)
	for i := 0; i < n; i++ {
		oid := oidInt4
		if v, ok := s.cfg.ColumnTypes[i+1]; ok {
			oid = v
		}
		switch oid {
		case oidBool:
			cols[i] = []byte{0x01}
		case oidInt8, oidFloat8:
			var buf [8]byte
			binary.BigEndian.PutUint64(buf[:], uint64(42))
			cols[i] = buf[:]
		default: // int4, numeric, and others fall back to 4-byte big-endian 42
			var buf [4]byte
			binary.BigEndian.PutUint32(buf[:], uint32(42))
			cols[i] = buf[:]
		}
	}
	return cols
}

func (s *runState) paramOIDs(n int) []int32 {
	out := make([]int32, n)
	for i := 0; i < n; i++ {
		if v, ok := s.cfg.ColumnTypes[i+1]; ok {
			out[i] = v
		} else {
			out[i] = oidInt4
		}
	}
	return out
}

func (s *runState) bindParamFmts(n int) []int16 {
	out := make([]int16, n)
	for i := range out {
		out[i] = 1
	}
	return out
}

func (s *runState) bindParamValues(values []string) [][]byte {
	out := make([][]byte, len(values))
	for i, v := range values {
		out[i] = []byte(v)
	}
	return out
}

// --- encoding helpers (per design_postgresql.md §7.3) ---

func encodePGMessage(typeTag byte, payload []byte) []byte {
	out := make([]byte, 5+len(payload))
	out[0] = typeTag
	binary.BigEndian.PutUint32(out[1:5], uint32(4+len(payload)))
	copy(out[5:], payload)
	return out
}

func encodeCString(s string) []byte {
	out := make([]byte, len(s)+1)
	copy(out, s)
	return out
}

func encodeInt16(n int16) []byte {
	var buf [2]byte
	binary.BigEndian.PutUint16(buf[:], uint16(n))
	return buf[:]
}

func encodeInt32(n int32) []byte {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], uint32(n))
	return buf[:]
}

func encodeInt64(n int64) []byte {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(n))
	return buf[:]
}

// StartupMessage (no type byte).
func encodeStartup(protocolVersion int32, params map[string]string) []byte {
	if params == nil {
		params = map[string]string{}
	}
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys) // deterministic
	payload := make([]byte, 4)
	binary.BigEndian.PutUint32(payload[0:4], uint32(protocolVersion))
	for _, k := range keys {
		payload = append(payload, []byte(k)...)
		payload = append(payload, 0)
		payload = append(payload, []byte(params[k])...)
		payload = append(payload, 0)
	}
	payload = append(payload, 0) // terminator
	length := uint32(4 + len(payload))
	out := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(out[0:4], length)
	copy(out[4:], payload)
	return out
}

func encodeAuthRequest(subType int32) []byte {
	payload := make([]byte, 4)
	binary.BigEndian.PutUint32(payload[0:4], uint32(subType))
	return encodePGMessage(typeAuth, payload)
}

func encodeAuthOk() []byte {
	return encodeAuthRequest(authOk)
}

func encodeAuthMD5(salt []byte) []byte {
	payload := make([]byte, 4+4)
	binary.BigEndian.PutUint32(payload[0:4], uint32(authMD5))
	copy(payload[4:], salt[:4])
	return encodePGMessage(typeAuth, payload)
}

func encodeAuthSASL(mechanisms []string) []byte {
	payload := encodeInt32(authSASL)
	for _, m := range mechanisms {
		payload = append(payload, []byte(m)...)
		payload = append(payload, 0)
	}
	payload = append(payload, 0) // terminator
	return encodePGMessage(typeAuth, payload)
}

func encodeAuthSASLContinue(serverFirst []byte) []byte {
	payload := encodeInt32(authSASLContinue)
	payload = append(payload, serverFirst...)
	return encodePGMessage(typeAuth, payload)
}

func encodeAuthSASLFinal(serverFinal []byte) []byte {
	payload := encodeInt32(authSASLFinal)
	payload = append(payload, serverFinal...)
	return encodePGMessage(typeAuth, payload)
}

func encodeSASLInitialResponse(mechanism, clientFirst string) []byte {
	payload := append([]byte(mechanism), 0)
	payload = append(payload, encodeInt32(int32(len(clientFirst)))...)
	payload = append(payload, []byte(clientFirst)...)
	return encodePGMessage(typeSASL, payload)
}

func encodeSASLResponse(clientFinal string) []byte {
	payload := encodeInt32(int32(len(clientFinal)))
	payload = append(payload, []byte(clientFinal)...)
	return encodePGMessage(typeSASL, payload)
}

func encodeParameterStatus(name, val string) []byte {
	payload := append([]byte(name), 0)
	payload = append(payload, []byte(val)...)
	payload = append(payload, 0)
	return encodePGMessage(typeParameter, payload)
}

func encodeBackendKeyData(pid, secret int32) []byte {
	payload := make([]byte, 8)
	binary.BigEndian.PutUint32(payload[0:4], uint32(pid))
	binary.BigEndian.PutUint32(payload[4:8], uint32(secret))
	return encodePGMessage(typeBackendKeyData, payload)
}

func encodeReadyForQuery(status byte) []byte {
	return encodePGMessage(typeReadyForQuery, []byte{status})
}

func encodeDataRow(cols [][]byte) []byte {
	bodyLen := 2
	for _, col := range cols {
		bodyLen += 4 + len(col)
	}
	payload := make([]byte, bodyLen)
	binary.BigEndian.PutUint16(payload[0:2], uint16(len(cols)))
	offset := 2
	for _, col := range cols {
		binary.BigEndian.PutUint32(payload[offset:offset+4], uint32(len(col)))
		offset += 4
		copy(payload[offset:], col)
		offset += len(col)
	}
	return encodePGMessage(typeDataRow, payload)
}

func encodeCommandComplete(tag string) []byte {
	return encodePGMessage(typeCmdComplete, encodeCString(tag))
}

func encodeRowDescription(fields []core.PGField) []byte {
	bodyLen := 2
	for _, f := range fields {
		bodyLen += len(f.Name) + 1 // null-terminated name
		bodyLen += 4 + 2 + 4 + 2 + 4 + 2
	}
	payload := make([]byte, bodyLen)
	binary.BigEndian.PutUint16(payload[0:2], uint16(len(fields)))
	offset := 2
	for _, f := range fields {
		copy(payload[offset:], f.Name)
		offset += len(f.Name)
		payload[offset] = 0
		offset++
		binary.BigEndian.PutUint32(payload[offset:offset+4], uint32(f.TableOID))
		offset += 4
		binary.BigEndian.PutUint16(payload[offset:offset+2], uint16(f.Column))
		offset += 2
		binary.BigEndian.PutUint32(payload[offset:offset+4], uint32(f.TypeOID))
		offset += 4
		binary.BigEndian.PutUint16(payload[offset:offset+2], uint16(f.TypeLen))
		offset += 2
		binary.BigEndian.PutUint32(payload[offset:offset+4], uint32(f.TypeMod))
		offset += 4
		binary.BigEndian.PutUint16(payload[offset:offset+2], uint16(f.FormatCode))
		offset += 2
	}
	return encodePGMessage(typeRowDesc, payload)
}

func encodeEmptyQueryResponse() []byte {
	return encodePGMessage(typeEmptyQuery, nil)
}

func encodeErrorResponse(fields []core.PGErrorField) []byte {
	var payload []byte
	for _, f := range fields {
		payload = append(payload, f.Type)
		payload = append(payload, []byte(f.Value)...)
		payload = append(payload, 0)
	}
	payload = append(payload, 0) // terminator
	return encodePGMessage(typeError, payload)
}

func encodeNoticeResponse(fields []core.PGErrorField) []byte {
	var payload []byte
	for _, f := range fields {
		payload = append(payload, f.Type)
		payload = append(payload, []byte(f.Value)...)
		payload = append(payload, 0)
	}
	payload = append(payload, 0)
	return encodePGMessage(typeNotice, payload)
}

func encodeNotificationResponse(pid int32, channel, payload string) []byte {
	body := encodeInt32(pid)
	body = append(body, []byte(channel)...)
	body = append(body, 0)
	body = append(body, []byte(payload)...)
	body = append(body, 0)
	return encodePGMessage(typeNotification, body)
}

func encodeCopyInResponse(format byte, cols []int16) []byte {
	body := []byte{format}
	body = append(body, encodeInt16(int16(len(cols)))...)
	for _, c := range cols {
		body = append(body, encodeInt16(c)...)
	}
	return encodePGMessage(typeCopyIn, body)
}

func encodeCopyOutResponse(format byte, cols []int16) []byte {
	body := []byte{format}
	body = append(body, encodeInt16(int16(len(cols)))...)
	for _, c := range cols {
		body = append(body, encodeInt16(c)...)
	}
	return encodePGMessage(typeCopyOut, body)
}

func encodeCopyBothResponse(format byte, cols []int16) []byte {
	body := []byte{format}
	body = append(body, encodeInt16(int16(len(cols)))...)
	for _, c := range cols {
		body = append(body, encodeInt16(c)...)
	}
	return encodePGMessage(typeCopyBoth, body)
}

func encodeCopyData(data []byte) []byte {
	return encodePGMessage(typeCopyData, data)
}

func encodeCopyDone() []byte {
	return encodePGMessage(typeCopyDone, nil)
}

func encodeCopyFail(msg string) []byte {
	return encodePGMessage(typeCopyFail, encodeCString(msg))
}

func encodeParse(stmt, sql string, paramTypes []int32) []byte {
	body := append([]byte(stmt), 0)
	body = append(body, []byte(sql)...)
	body = append(body, 0)
	body = append(body, encodeInt16(int16(len(paramTypes)))...)
	for _, t := range paramTypes {
		body = append(body, encodeInt32(t)...)
	}
	return encodePGMessage(typeParse, body)
}

func encodeBind(portal, stmt string, fmtCodes []int16, values [][]byte, resultFmts []int16) []byte {
	body := append([]byte(portal), 0)
	body = append(body, []byte(stmt)...)
	body = append(body, 0)
	body = append(body, encodeInt16(int16(len(fmtCodes)))...)
	for _, f := range fmtCodes {
		body = append(body, encodeInt16(f)...)
	}
	body = append(body, encodeInt16(int16(len(values)))...)
	for _, v := range values {
		body = append(body, encodeInt32(int32(len(v)))...)
		body = append(body, v...)
	}
	body = append(body, encodeInt16(int16(len(resultFmts)))...)
	for _, f := range resultFmts {
		body = append(body, encodeInt16(f)...)
	}
	return encodePGMessage(typeBind, body)
}

func encodeDescribe(mode byte, name string) []byte {
	body := []byte{mode}
	body = append(body, []byte(name)...)
	body = append(body, 0)
	return encodePGMessage(typeDescribe, body)
}

func encodeExecute(portal string, maxRows int32) []byte {
	body := append([]byte(portal), 0)
	body = append(body, encodeInt32(maxRows)...)
	return encodePGMessage(typeExecute, body)
}

func encodeSync() []byte {
	return encodePGMessage(typeSync, nil)
}

func encodeClose(mode byte, name string) []byte {
	body := []byte{mode}
	body = append(body, []byte(name)...)
	body = append(body, 0)
	return encodePGMessage(typeClose, body)
}

func encodeFlush() []byte {
	return encodePGMessage(typeFlush, nil)
}

func encodeTerminate() []byte {
	return encodePGMessage(typeTerminate, nil)
}

func encodePassword(pwd string) []byte {
	return encodePGMessage(typePassword, encodeCString(pwd))
}

func encodeParseComplete() []byte {
	return encodePGMessage(typeParseComplete, nil)
}

func encodeBindComplete() []byte {
	return encodePGMessage(typeBindComplete, nil)
}

func encodeCloseComplete() []byte {
	return encodePGMessage(typeCloseComplete, nil)
}

func encodeNoData() []byte {
	return encodePGMessage(typeNoData, nil)
}

func encodeParameterDescription(types []int32) []byte {
	body := encodeInt16(int16(len(types)))
	for _, t := range types {
		body = append(body, encodeInt32(t)...)
	}
	return encodePGMessage(typeParameterDesc, body)
}

func encodePortalSuspended() []byte {
	return encodePGMessage(typePortalSuspended, nil)
}

func encodePortalBindComplete() []byte {
	return encodePGMessage(typePortalBindComplete, nil)
}

func encodeQuery(sql string) []byte {
	return encodePGMessage(typeQuery, encodeCString(sql))
}

func encodeFunctionCall(oid int32, fmtCodes []int16, args []string, resultFmt int16) []byte {
	body := encodeInt32(oid)
	body = append(body, encodeInt16(int16(len(fmtCodes)))...)
	for _, f := range fmtCodes {
		body = append(body, encodeInt16(f)...)
	}
	body = append(body, encodeInt16(int16(len(args)))...)
	for _, a := range args {
		body = append(body, encodeInt32(int32(len(a)))...)
		body = append(body, []byte(a)...)
	}
	body = append(body, encodeInt16(resultFmt)...)
	return encodePGMessage(typeFunction, body)
}

func encodeFunctionCallResponse(result []byte) []byte {
	body := encodeInt32(int32(len(result)))
	body = append(body, result...)
	return encodePGMessage(typeFuncCallResp, body)
}

func encodeXLogData(startLSN, endLSN, sendTime int64, wal []byte) []byte {
	body := []byte{walSubXLogData}
	body = append(body, encodeInt64(startLSN)...)
	body = append(body, encodeInt64(endLSN)...)
	body = append(body, encodeInt64(sendTime)...)
	body = append(body, wal...)
	return body
}

func encodePrimaryKeepalive(endLSN, sendTime int64, reply byte) []byte {
	body := []byte{walSubPrimaryKeepalive}
	body = append(body, encodeInt64(endLSN)...)
	body = append(body, encodeInt64(sendTime)...)
	body = append(body, reply)
	return body
}

// md5Hex computes md5(md5(password + username) + salt) and returns the
// lowercase hex form (PostgreSQL MD5Password docs).
func md5Hex(user, password string, salt []byte) string {
	inner := md5.Sum([]byte(password + user))
	combined := append([]byte(hex.EncodeToString(inner[:])), salt...)
	outer := md5.Sum(combined)
	return hex.EncodeToString(outer[:])
}

// --- random helpers (used by SCRAM + replication flows) ---

func randomScramNonce() string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 18)
	for i := range b {
		b[i] = alphabet[rand.Intn(len(alphabet))]
	}
	return string(b)
}

func randomBase64(n int) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	b := make([]byte, n)
	for i := range b {
		b[i] = alphabet[rand.Intn(len(alphabet))]
	}
	return string(b)
}

func randomBase64Salt() string {
	return randomBase64(16)
}

// fillWal returns N bytes of synthetic WAL data. Real WAL bytes are page
// headers + transaction records; the planner does not synthesize valid
// WAL because Wireshark doesn't need it.
func fillWal(n int) []byte {
	if n <= 0 {
		n = DefaultWALDataSize
	}
	out := make([]byte, n)
	for i := range out {
		out[i] = byte(i & 0xff)
	}
	return out
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}
