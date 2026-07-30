// Package mysql implements the MySQL Client/Server Protocol (MySQL 客户端/服务器协议)
// planner per the official MySQL 8.0+ protocol specification.
//
// MySQL is a session-level protocol: a single TCP connection on port 3306
// (the well-known MySQL port) carries a sequence of binary request/response
// packets. Each packet is framed by a 4-byte header:
//
//	+----------+----------+----------+----------+
//	| Length (3 bytes LE)         | Seq (1)  |
//	+-----------------------------+----------+
//	| Body (Length bytes)                     |
//	+-----------------------------------------+
//
// The planner emits:
//
//  1. TCP 3-way handshake (SYN/SYN-ACK/ACK) with MSS/WinScale/SACK options
//     when TCP.Handshake is true. Mirrors FTP/HTTP/SIP/POP3 control-channel.
//  2. Server Greeting (down, seq=0): 0x0a protocol + version + thread_id +
//     auth_plugin_data_part1(8) + filler + capability_lower(2) +
//     charset(1) + status_flags(2) + capability_upper(2) + auth_data_length(1)
//     + reserved(10 zeros) + auth_plugin_data_part2(13) + auth_plugin_name\0.
//  3. Client Handshake Response (up, seq=1): capability_flags(4) +
//     max_packet_size(4) + charset(1) + reserved(23) + username\0 +
//     auth_response(lenenc) + (database\0) + auth_plugin\0.
//  4. Server Auth OK (down, seq=2) OR Auth More Data (0x04 → triggers RSA/
//     plaintext fallback for caching_sha2_password cache miss) OR Auth
//     Switch Request (0xfe → client responds with new plugin algorithm).
//  5. Each MySQLCommand: client command (up, body = 4-byte header +
//     opcode + body bytes) + matching server response (down). Reply modes
//     cover "ok" / "ok-insert" / "err" / "err-perm" / "result-set" /
//     "binary-result" / "raw". Each individual packet's payload is
//     framed with the 4-byte header; when the framed packet exceeds MSS,
//     each PSH-ACK segment carries a chunk of that packet's body, advancing
//     the sender's sequence by the segment length (TCP layer is opaque to
//     MySQL framing — MySQL's own seq resets per-command on top of TCP).
//  6. TCP 4-way teardown (FIN-ACK/ACK/FIN-ACK/ACK) when TCP.Termination.
//
// The planner does NOT enforce MySQL state-machine transitions. The user
// is responsible for providing a coherent dialog (handshake complete before
// commands, statement prepared before execute, etc.). This matches the
// trafficgen contract: synthesize test packets, not a real MySQL client.
//
// IPv6 / multicast MAC / VLAN behavior follows the unified convention at
// /tmp/l7_planner_design/multicast_ipv6_vlan.md. MySQL is "transparent" for
// IP version (works over IPv4 or IPv6); it is unicast-only.
//
// KNOWN LIMITATIONS (per design_mysql.md §8):
//   - RSA-encrypted password bytes (sha256_password / caching_sha2_password
//     cache-miss path) are emitted as a planner-computed placeholder; the
//     user can override via MySQLCommand.ReplyBytes when "raw" mode is
//     used. Real RSA encryption requires a server PEM public key.
//   - Multi-result-set (CLIENT_MULTI_RESULTS) is NOT auto-decoded by the
//     planner; the user composes the multi-result reply in ReplyBytes when
//     "raw" mode is used.
//   - COM_BINLOG_DUMP / COM_TABLE_DUMP / COM_REGISTER_SLAVE / LOAD DATA
//     LOCAL INFILE / X Protocol are explicitly out of scope.
package mysql

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math"
	"math/rand"
	"net"
	"strings"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
)

const (
	// DefaultTTL mirrors internal/protocol/pop3.DefaultTTL and
	// internal/protocol/ftp.DefaultTTL (64). Standard IP TTL for forwarded
	// traffic; matches Linux/macOS defaults.
	DefaultTTL = 64

	// DefaultMSS mirrors internal/protocol/pop3.DefaultMSS and
	// internal/protocol/ftp.DefaultMSS (1460). RFC 879 floor is 536.
	DefaultMSS = 1460

	// MinMSS per RFC 879 (IP+TCP header 20+20+536 = 576-byte minimum packet).
	MinMSS = 536

	// DefaultPort is the well-known MySQL port per the protocol overview.
	DefaultPort = 3306

	// DefaultServerVersion is what an empty ServerVersion expands to.
	// "8.0.36" is a plausible MySQL 8.0.x release.
	DefaultServerVersion = "8.0.36"

	// DefaultAuthPlugin is the SHA1-based auth plugin supported by every
	// MySQL client since the dawn of the protocol.
	DefaultAuthPlugin = "mysql_native_password"

	// DefaultUsername is the canonical MySQL super-user.
	DefaultUsername = "root"

	// DefaultMaxPacketSize per the protocol is 16 MB (0x01000000).
	DefaultMaxPacketSize uint32 = 0x01000000

	// DefaultCharsetServer is the connection character_set_client value
	// common in 8.0 servers (utf8 / utf8_general_ci).
	DefaultCharsetServer uint8 = 0x21

	// MySQL proto version (first byte of Greeting), fixed at 0x0a.
	protocolVersion10 uint8 = 0x0a

	// Auth plugin data total bytes (8 part1 + 13 part2 [+ null terminator
	// already counted in part2] = 21). The handshake's auth_data_length
	// byte = 21 per §2.10.
	authDataTotalLen = 21

	// DefaultScrambleLen is the expected scramble total length per the
	// MySQL handshake protocol: 8 + 12 = 20 bytes.
	DefaultScrambleLen = 20

	// scramblePart1Len / scramblePart2Len mirror the standard
	// "auth_plugin_data" split. MySQL sends Part 1 (8 bytes) immediately
	// after thread_id, and Part 2 (12 bytes + null) at the end of the
	// Greeting — total 21 bytes on the wire including the null terminator
	// on Part 2.
	scramblePart1Len = 8
	scramblePart2Len = 12

	// MaxPacketBytes is the largest 3-byte length-encoded value
	// (2^24 - 1 = 16 777 215).
	MaxPacketBytes = (1 << 24) - 1

	// packetHeaderLen is the MySQL packet header length: 3-byte length
	// + 1-byte sequence ID.
	packetHeaderLen = 4
)

// designCapabilityFlags is the default 32-bit capability flag set per
// design_mysql.md §2.6:
//
//	CLIENT_LONG_PASSWORD                     0x0001
//	CLIENT_PROTOCOL_41 (FOUND_ROWS in spec)  0x0002 (use 0x0004 from §2.6)
//	CLIENT_LONG_FLAG                         0x0004
//	CLIENT_TRANSACTIONS                      0x0200
//	CLIENT_SECURE_CONNECTION                 0x0800
//	CLIENT_MULTI_STATEMENTS                  0x2000
//	CLIENT_PLUGIN_AUTH                       0x8000
//	CLIENT_PLUGIN_AUTH_CLIENT_SUPPLIED_DATA  0x00080000
//
// Lower 16 bits = 0xa005 (test case §1.2.6.1); Upper 16 bits = 0x0008.
const designCapabilityFlags uint32 = 0x0008a005

// SERVER_STATUS_* bits used by the OK Packet status_flags field.
const (
	serverStatusInTrans    uint16 = 0x0001
	serverStatusAutocommit uint16 = 0x0002
)

// MySQL column type constants (enum_field_types) per MySQL protocol.
// Only the subset needed for binary protocol value encoding is enumerated.
const (
	mysqlTypeDecimal    uint8 = 0x00
	mysqlTypeTiny       uint8 = 0x01
	mysqlTypeShort      uint8 = 0x02
	mysqlTypeLong       uint8 = 0x03
	mysqlTypeFloat      uint8 = 0x04
	mysqlTypeDouble     uint8 = 0x05
	mysqlTypeNull       uint8 = 0x06
	mysqlTypeTimestamp  uint8 = 0x07
	mysqlTypeLongLong   uint8 = 0x08
	mysqlTypeInt24      uint8 = 0x09
	mysqlTypeDate       uint8 = 0x0a
	mysqlTypeTime       uint8 = 0x0b
	mysqlTypeDatetime   uint8 = 0x0c
	mysqlTypeYear       uint8 = 0x0d
	mysqlTypeVarchar    uint8 = 0x0f
	mysqlTypeBit        uint8 = 0x10
	mysqlTypeJSON       uint8 = 0xf5
	mysqlTypeNewDecimal uint8 = 0xf6
	mysqlTypeEnum       uint8 = 0xf7
	mysqlTypeSet        uint8 = 0xf8
	mysqlTypeTinyBlob   uint8 = 0xf9
	mysqlTypeMediumBlob uint8 = 0xfa
	mysqlTypeLongBlob   uint8 = 0xfb
	mysqlTypeBlob       uint8 = 0xfc
	mysqlTypeVarString  uint8 = 0xfd
	mysqlTypeString     uint8 = 0xfe
	mysqlTypeGeometry   uint8 = 0xff
)

// bitOffsetBinaryResult is the NULL-bitmap bit offset for binary
// protocol result rows (per MySQL protocol).
const bitOffsetBinaryResult = 2

// nullBitInBinaryResult reports whether the bitmap byte for a (numCols,
// bitPos) pair needs to be allocated. bitPos uses the binary result
// offset (2) per MySQL protocol.
func nullBitInBinaryResult(numCols int) int {
	if numCols == 0 {
		return 0
	}
	return (numCols + 7 + bitOffsetBinaryResult) / 8
}

// capConnectWithDB is the CLIENT_CONNECT_WITH_DB bit (0x08). When
// enabled, the client may send a database name in the Handshake
// Response.
const capConnectWithDB uint32 = 0x00000008

// capPluginAuthClientSuppliedData is the CLIENT_PLUGIN_AUTH bit's
// "client supplied data" companion (0x80000). When set the client may
// include auth_plugin_name in the Handshake Response.
const capPluginAuthClientSuppliedData uint32 = 0x00080000

// Planner implements the MySQL protocol planner.
type Planner struct{}

// NewPlanner creates a new MySQL planner.
func NewPlanner() *Planner { return &Planner{} }

// Name returns the protocol name.
func (p *Planner) Name() string { return "mysql" }

// Validate validates a MySQL flow spec. Read-only: never modifies spec.
// Per validate_conventions.md §1.1 contract, default-value filling
// happens in Plan(), not here.
func (p *Planner) Validate(spec core.FlowSpec) error {
	// IP validity.
	if spec.SrcIP != "" {
		if net.ParseIP(spec.SrcIP) == nil {
			return fmt.Errorf("mysql: SrcIP %q is not a valid IP address", spec.SrcIP)
		}
	}
	if spec.DstIP != "" {
		if net.ParseIP(spec.DstIP) == nil {
			return fmt.Errorf("mysql: DstIP %q is not a valid IP address", spec.DstIP)
		}
	}

	// MSS sanity check (RFC 879 floor 536).
	if spec.TCP != nil && spec.TCP.MSS > 0 {
		if spec.TCP.MSS < MinMSS {
			return fmt.Errorf("mysql: MSS %d too small (min %d per RFC 879)", spec.TCP.MSS, MinMSS)
		}
	}

	if spec.MySQL == nil {
		return nil
	}

	// CharacterSet is 1 byte.
	if spec.MySQL.CharacterSet > 255 {
		return fmt.Errorf("mysql: CharacterSet %d out of range [0, 255]", spec.MySQL.CharacterSet)
	}

	// AuthPlugin must be one of the three known values (or empty for
	// default). User-facing typo protection.
	if ap := spec.MySQL.AuthPlugin; ap != "" {
		switch ap {
		case "mysql_native_password", "caching_sha2_password", "sha256_password":
			// known
		default:
			return fmt.Errorf("mysql: AuthPlugin %q not recognized (want mysql_native_password | caching_sha2_password | sha256_password)", ap)
		}
	}

	// Scramble must be 20 bytes when explicitly set.
	if len(spec.MySQL.Scramble) > 0 && len(spec.MySQL.Scramble) != DefaultScrambleLen {
		return fmt.Errorf("mysql: Scramble length %d invalid (want %d bytes when set)", len(spec.MySQL.Scramble), DefaultScrambleLen)
	}

	// MaxPacketSize upper bound (24-bit packet length field).
	if spec.MySQL.MaxPacketSize > 0 && spec.MySQL.MaxPacketSize > MaxPacketBytes {
		return fmt.Errorf("mysql: MaxPacketSize %d exceeds 3-byte length field max (%d)", spec.MySQL.MaxPacketSize, MaxPacketBytes)
	}

	// Per-command structural checks.
	for i, cmd := range spec.MySQL.Commands {
		if !isKnownOpCode(cmd.Opcode) {
			return fmt.Errorf("mysql: Commands[%d].Opcode 0x%02x not a known COM_* opcode", i, cmd.Opcode)
		}
		switch cmd.BodyEncoding {
		case "", "text", "hex", "base64":
			// ok
		default:
			return fmt.Errorf("mysql: Commands[%d].BodyEncoding %q not recognized", i, cmd.BodyEncoding)
		}
		switch cmd.ReplyEncoding {
		case "", "text", "hex", "base64":
			// ok
		default:
			return fmt.Errorf("mysql: Commands[%d].ReplyEncoding %q not recognized", i, cmd.ReplyEncoding)
		}
		switch cmd.ReplyMode {
		case "", "ok", "ok-insert", "ok-custom", "err", "err-perm", "err-custom", "result-set", "binary-result", "prepare-ok", "no-reply", "raw":
			// ok
		default:
			return fmt.Errorf("mysql: Commands[%d].ReplyMode %q not recognized", i, cmd.ReplyMode)
		}
		// COM_STMT_EXECUTE requires StmtID.
		if cmd.Opcode == 0x1b && cmd.StmtID == 0 {
			return fmt.Errorf("mysql: Commands[%d] is COM_STMT_EXECUTE but StmtID == 0", i)
		}
	}

	return nil
}

// isKnownOpCode returns true for COM_* opcodes (0x01..0x20). We are
// permissive: protocol errors are the server's concern, not the planner's.
func isKnownOpCode(op uint8) bool {
	return op >= 0x01 && op <= 0x20
}

// Plan generates packet configs for a MySQL flow.
//
// Wire layout per §6.3 of design_mysql.md:
//  1. (optional) TCP handshake
//  2. Server Greeting (down, seq 0)
//  3. (unless ServerBypassAuth) Client Handshake Response (up, seq 1)
//  4. (unless ServerBypassAuth) Server Auth OK (down, seq 2)
//  5. For each MySQLCommand: up (command packet) + down (reply packets
//     framed per reply mode); each MySQL packet's payload is segmented
//     by MSS at the TCP layer.
//  6. (optional) TCP 4-way teardown.
func (p *Planner) Plan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) {
	if err := p.Validate(spec); err != nil {
		return nil, err
	}

	configChan := make(chan core.PacketConfig, 256)

	go func() {
		defer close(configChan)

		flowID := fmt.Sprintf("%s-%s-%d-%d", spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort)

		mc := spec.MySQL
		if mc == nil {
			mc = &core.MySQLConfig{}
		}

		effectiveTTL := spec.TTL
		if effectiveTTL == 0 {
			effectiveTTL = DefaultTTL
		}

		// MSS resolution: 0 -> DefaultMSS (1460).
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

		// emit writes one packet to configChan. Pre-writes
		// Metadata["group_id"] when spec carries a GroupID strategy.
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

		// emitMySQLDown / emitMySQLUp segment an application-layer MySQL
		// packet across multiple PSH-ACK segments bounded by MSS. Each
		// segment carries len(seg) bytes; the sender's TCP seq advances
		// by that length.
		emitMySQLDown := func(payload []byte) {
			for _, seg := range segmentByMSS(payload, int(mss)) {
				emit("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, 0x18, seg)
				serverSeq += uint32(len(seg))
			}
		}
		emitMySQLUp := func(payload []byte) {
			for _, seg := range segmentByMSS(payload, int(mss)) {
				emit("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, 0x18, seg)
				clientSeq += uint32(len(seg))
			}
		}

		// handshakeEnabled / terminationEnabled follow the TCP convention.
		handshakeEnabled := true
		terminationEnabled := true
		if spec.TCP != nil {
			handshakeEnabled = spec.TCP.Handshake
			terminationEnabled = spec.TCP.Termination
		}

		// --- 1. TCP 3-way handshake ---
		if handshakeEnabled {
			emit("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, 0, 0x02, nil)
			clientSeq++
			emit("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, 0x12, nil)
			serverSeq++
			emit("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, 0x10, nil)
		}

		// --- 2. Server Greeting (down, seq=0) ---
		greetingPayload := encodeGreetingPayload(mc)
		emitMySQLDown(framePacket(0, greetingPayload))

		// --- 3+4. Client Handshake Response + Server Auth OK ---
		if !mc.ServerBypassAuth {
			responsePayload := encodeHandshakeResponsePayload(mc)
			emitMySQLUp(framePacket(1, responsePayload))

			// Server auth reply: standard OK by default. The planner picks
			// the simplest valid outcome; users wanting more elaborate flows
			// write their own reply with ReplyBytes (raw mode) or wrap the
			// planner in the controller for alternate auth paths.
			authReplyPayload := encodeServerAuthOKPayload(mc)
			emitMySQLDown(framePacket(2, authReplyPayload))
		}

		// --- 5. Each MySQLCommand ---
		for _, cmd := range mc.Commands {
			// Client command (up): 4-byte header + opcode + body. When
			// the opcode is COM_STMT_EXECUTE (0x1b) and Body is empty,
			// the planner auto-encodes the request from StmtID +
			// StmtFlags + IterationCount + StmtParams.
			var cmdPacket []byte
			if cmd.Opcode == 0x1b && cmd.Body == "" && cmd.StmtID != 0 {
				cmdPacket = encodeStmtExecuteRequest(cmd)
			} else {
				bodyBytes, _ := decodeUserBytes(cmd.Body, cmd.BodyEncoding)
				cmdPacket = make([]byte, 0, 1+len(bodyBytes))
				cmdPacket = append(cmdPacket, cmd.Opcode)
				cmdPacket = append(cmdPacket, bodyBytes...)
			}
			emitMySQLUp(framePacket(0, cmdPacket))

			// Server reply (down): one or more MySQL packets framed at
			// the application layer. Reply mode drives the body composition.
			replySeq := uint8(1)
			replies := buildReplyPackets(cmd, mc)
			for _, rp := range replies {
				emitMySQLDown(framePacket(replySeq, rp))
				replySeq++
			}
		}

		// --- 6. TCP 4-way teardown ---
		if terminationEnabled {
			emit("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, 0x11, nil)
			clientSeq++
			emit("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, 0x10, nil)
			emit("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, 0x11, nil)
			serverSeq++
			emit("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, 0x10, nil)
		}
	}()

	return configChan, nil
}

// ----------------------------------------------------------------------------
// Greeting / Handshake / Auth packet encoders.
//
// All return the BODY (no 4-byte header); callers frame and emit.
// ----------------------------------------------------------------------------

// encodeGreetingPayload returns the body of the Server Greeting packet
// (the planner prepends the 4-byte packet header + seq 0). The layout
// follows design_mysql.md §2.2 / Oracle's protocol_overview page.
func encodeGreetingPayload(mc *core.MySQLConfig) []byte {
	var b strings.Builder
	b.Grow(96)

	// 0. protocol_version (1): fixed 0x0a.
	b.WriteByte(protocolVersion10)

	// 1. server_version (null-terminated).
	ver := mc.ServerVersion
	if ver == "" {
		ver = DefaultServerVersion
	}
	b.WriteString(ver)
	b.WriteByte(0x00)

	// 2. thread_id (4 LE). 0 → 1 (plan-computed default; deterministic).
	tid := mc.ThreadID
	if tid == 0 {
		tid = 1
	}
	b.Write(encodeLEUint32(tid))

	// 3. auth_plugin_data_part1 (8).
	scramble := normalizedScramble(mc.Scramble)
	b.Write(scramble[:scramblePart1Len])

	// 4. filler (1).
	b.WriteByte(0x00)

	// 5+6. capability_flags lower 2 bytes + character_set + status_flags
	// + capability_flags upper 2 bytes. Build the 4-byte LE capability
	// mask from the design defaults, OR'd with the user override.
	caps := effectiveCapabilityFlags(mc)
	b.Write(encodeLEUint16(uint16(caps & 0xffff)))

	// 6. character_set (1). 0 → utf8 default.
	cs := mc.CharacterSet
	if cs == 0 {
		cs = DefaultCharsetServer
	}
	b.WriteByte(cs)

	// 7. status_flags (2 LE).
	b.Write(encodeLEUint16(serverStatusAutocommit))

	// 8. capability_flags upper 2 bytes (2 LE).
	b.Write(encodeLEUint16(uint16((caps >> 16) & 0xffff)))

	// 9. auth_data_length (1) — at least 21 per spec; we emit 21.
	b.WriteByte(authDataTotalLen)

	// 10. reserved (10 zeros).
	b.Write(make([]byte, 10))

	// 11. auth_plugin_data_part2 (13 bytes = 12 scramble + null terminator).
	part2 := scramble[scramblePart1Len : scramblePart1Len+scramblePart2Len]
	b.Write(part2)
	b.WriteByte(0x00) // null terminator

	// 12. auth_plugin_name (null-terminated).
	plugin := mc.AuthPlugin
	if plugin == "" {
		plugin = DefaultAuthPlugin
	}
	b.WriteString(plugin)
	b.WriteByte(0x00)

	return []byte(b.String())
}

// encodeHandshakeResponsePayload returns the Client Handshake Response
// body (the planner prepends the 4-byte packet header + seq 1) per
// design §2.3.
func encodeHandshakeResponsePayload(mc *core.MySQLConfig) []byte {
	caps := effectiveCapabilityFlags(mc)

	maxPkt := mc.MaxPacketSize
	if maxPkt == 0 {
		maxPkt = DefaultMaxPacketSize
	}

	cs := mc.CharacterSet
	if cs == 0 {
		cs = DefaultCharsetServer
	}

	username := mc.Username
	if username == "" {
		username = DefaultUsername
	}

	plugin := mc.AuthPlugin
	if plugin == "" {
		plugin = DefaultAuthPlugin
	}

	scramble := normalizedScramble(mc.Scramble)
	authData := computeAuthResponse(plugin, []byte(mc.Password), scramble)

	buf := make([]byte, 0, 64+len(username))
	buf = append(buf, encodeLEUint32(caps)...)
	buf = append(buf, encodeLEUint32(maxPkt)...)
	buf = append(buf, cs)
	buf = append(buf, make([]byte, 23)...) // reserved 23 zeros
	buf = append(buf, []byte(username)...)
	buf = append(buf, 0x00)
	buf = append(buf, encodeLenencBytes(authData)...)
	// database (null-terminated) — emitted only when CLIENT_CONNECT_WITH_DB.
	if (caps & capConnectWithDB) != 0 && mc.Database != "" {
		buf = append(buf, []byte(mc.Database)...)
		buf = append(buf, 0x00)
	}
	// auth_plugin_name (null-terminated) — emitted only when CLIENT_PLUGIN_AUTH bit set.
	// We always emit when capPluginAuthClientSuppliedData (0x80000) is in caps
	// since that bit is in designCapabilityFlags by default.
	if (caps & capPluginAuthClientSuppliedData) != 0 {
		buf = append(buf, []byte(plugin)...)
		buf = append(buf, 0x00)
	}
	return buf
}

// encodeServerAuthOKPayload returns the server OK body (the planner
// prepends the 4-byte packet header + seq 2). Default is the standard
// OK packet: 0x00 + affected_rows(0) + last_insert_id(0) + status_flags
// (AUTOCOMMIT) + warnings(0) → 7 bytes total.
func encodeServerAuthOKPayload(mc *core.MySQLConfig) []byte {
	return encodeOKPacketAuto(0, 0, serverStatusAutocommit, 0)
}

// effectiveCapabilityFlags returns the 32-bit capability bitmask the
// planner uses for both Greeting and Handshake Response. Starts from
// designCapabilityFlags, overlays the user's override (when set), and
// OR's in CLIENT_CONNECT_WITH_DB when Database is non-empty.
func effectiveCapabilityFlags(mc *core.MySQLConfig) uint32 {
	caps := designCapabilityFlags
	if mc.CapabilityFlags != 0 {
		caps = mc.CapabilityFlags
	}
	if mc.Database != "" {
		caps |= capConnectWithDB
	}
	return caps
}

// normalizedScramble returns a 20-byte scramble (Part 1 + Part 2). The
// planner-computed default is deterministic (always the same 20 bytes
// for reproducible tests); user-provided scrambles shorter than 20
// bytes are zero-padded; user-provided 20-byte scrambles are used as-is.
func normalizedScramble(user []byte) []byte {
	if len(user) == 0 {
		return defaultScramble()
	}
	if len(user) == DefaultScrambleLen {
		return user
	}
	out := make([]byte, DefaultScrambleLen)
	copy(out, user)
	return out
}

// ----------------------------------------------------------------------------
// Length-Encoded Integer / String / OK / ERR / EOF / Capability encoders.
// ----------------------------------------------------------------------------

// encodeLEUint16 returns 2-byte little-endian.
func encodeLEUint16(n uint16) []byte {
	return []byte{byte(n & 0xff), byte((n >> 8) & 0xff)}
}

// encodeLEUint32 returns 4-byte little-endian.
func encodeLEUint32(n uint32) []byte {
	return []byte{byte(n & 0xff), byte((n >> 8) & 0xff), byte((n >> 16) & 0xff), byte((n >> 24) & 0xff)}
}

// encodeLEUint24 returns the 3-byte little-endian length field used in
// every MySQL packet header. Range: 0..2^24-1.
func encodeLEUint24(n uint32) []byte {
	if n > MaxPacketBytes {
		n = MaxPacketBytes
	}
	return []byte{byte(n & 0xff), byte((n >> 8) & 0xff), byte((n >> 16) & 0xff)}
}

// encodeLenencInt encodes a non-negative integer in MySQL's
// length-encoded integer format per design §2.8:
//
//	0..250          → 1 byte direct
//	251..2^16-1     → 0xfc + 2 bytes LE (3 bytes total)
//	2^16..2^24-1    → 0xfd + 3 bytes LE (4 bytes total)
//	> 2^24          → 0xfe + 8 bytes LE (9 bytes total)
//
// The special value 0xfb is RESERVED for SQL NULL; this encoder does
// NOT treat n=0xfb specially — callers that want the NULL marker
// should write 0xfb directly.
func encodeLenencInt(n uint64) []byte {
	switch {
	case n <= 250:
		return []byte{byte(n)}
	case n <= 0xffff:
		return []byte{0xfc, byte(n & 0xff), byte((n >> 8) & 0xff)}
	case n <= 0xffffff:
		return []byte{0xfd, byte(n & 0xff), byte((n >> 8) & 0xff), byte((n >> 16) & 0xff)}
	default:
		return []byte{
			0xfe,
			byte(n), byte(n >> 8), byte(n >> 16), byte(n >> 24),
			byte(n >> 32), byte(n >> 40), byte(n >> 48), byte(n >> 56),
		}
	}
}

// encodeLenencBytes writes a length-encoded string: lenenc-int length
// + raw bytes. Empty slice → 0x00 (length = 0).
func encodeLenencBytes(b []byte) []byte {
	out := encodeLenencInt(uint64(len(b)))
	return append(out, b...)
}

// encodeLenencString is an alias for encodeLenencBytes (kept for
// readability at call sites).
func encodeLenencString(s string) []byte {
	return encodeLenencBytes([]byte(s))
}

// encodeNullBitmap emits a (colCount+7)/8 byte bitmap; per-column
// isNull flags set the bit (1 = NULL). Bit ordering follows design §2.9:
// bit i (0..7) of byte k covers column (k*8 + i). Returns nil when
// colCount == 0 (server doesn't send a bitmap when there are no columns).
func encodeNullBitmap(colCount int, isNull []bool) []byte {
	if colCount <= 0 {
		return nil
	}
	byteLen := (colCount + 7) / 8
	out := make([]byte, byteLen)
	for i := 0; i < colCount && i < len(isNull); i++ {
		if isNull[i] {
			out[i/8] |= 1 << uint(i%8)
		}
	}
	return out
}

// encodeOKPacket emits the body of an OK packet per design §2.6.1.
//
//	0x00 (OK marker) | affected_rows (lenenc) | last_insert_id (lenenc) |
//	status_flags (2 LE) | warnings (2 LE) | (optional) info (lenenc-string)
func encodeOKPacket(affected, lastId uint64, status, warnings uint16, extended bool, info string) []byte {
	buf := make([]byte, 0, 16)
	buf = append(buf, 0x00)
	buf = append(buf, encodeLenencInt(affected)...)
	buf = append(buf, encodeLenencInt(lastId)...)
	buf = append(buf, encodeLEUint16(status)...)
	buf = append(buf, encodeLEUint16(warnings)...)
	if extended && info != "" {
		buf = append(buf, encodeLenencString(info)...)
	}
	return buf
}

// encodeOKPacketAuto is encodeOKPacket with extended=false (no info).
// Helper used by reply-mode "ok" / "ok-insert" paths.
func encodeOKPacketAuto(affected, lastId uint64, status, warnings uint16) []byte {
	return encodeOKPacket(affected, lastId, status, warnings, false, "")
}

// encodeERRPacket emits the body of an ERR packet per design §2.6.2.
//
//	0xff (ERR marker) | error_code (2 LE) | sql_state_marker (1, '#') |
//	sql_state (5 ASCII) | error_message (UTF-8)
func encodeERRPacket(errorCode uint16, sqlState, message string) []byte {
	if len(sqlState) != 5 {
		if sqlState == "" {
			sqlState = "HY000"
		}
		if len(sqlState) > 5 {
			sqlState = sqlState[:5]
		} else {
			sqlState = sqlState + strings.Repeat(" ", 5-len(sqlState))
		}
	}
	buf := make([]byte, 0, 8+len(message))
	buf = append(buf, 0xff)
	buf = append(buf, encodeLEUint16(errorCode)...)
	buf = append(buf, 0x23) // '#'
	buf = append(buf, []byte(sqlState)...)
	buf = append(buf, []byte(message)...)
	return buf
}

// encodeEOFPacket emits the body of an EOF packet per design §2.6.3.
//
//	0xfe (EOF marker) | warnings (2 LE) | status_flags (2 LE)
func encodeEOFPacket(warnings, status uint16) []byte {
	buf := make([]byte, 5)
	buf[0] = 0xfe
	copy(buf[1:3], encodeLEUint16(warnings))
	copy(buf[3:5], encodeLEUint16(status))
	return buf
}

// encodeColDefPacket emits the body of a column definition packet per
// design §2.7. catalog/schema/table/org_table/name/org_name are
// length-encoded strings; the 0x0c byte separates names from type
// metadata.
func encodeColDefPacket(col core.MySQLColDef) []byte {
	buf := make([]byte, 0, 64)
	buf = append(buf, encodeLenencString(col.Catalog)...)
	buf = append(buf, encodeLenencString(col.Schema)...)
	buf = append(buf, encodeLenencString(col.Table)...)
	buf = append(buf, encodeLenencString(col.OrgTable)...)
	buf = append(buf, encodeLenencString(col.Name)...)
	buf = append(buf, encodeLenencString(col.OrgName)...)
	buf = append(buf, 0x0c) // fixed separator
	buf = append(buf, encodeLEUint16(col.Charset)...)
	buf = append(buf, encodeLEUint32(col.Length)...)
	buf = append(buf, col.Type)
	buf = append(buf, encodeLEUint16(col.Flags)...)
	buf = append(buf, col.Decimals)
	buf = append(buf, 0x00, 0x00) // filler (2)
	return buf
}

// encodeRowPacket emits the body of a row packet for SELECT-style
// result sets: null_bitmap(colCount) + lenenc-string per value.
func encodeRowPacket(row core.MySQLRow, colCount int) []byte {
	buf := make([]byte, 0, 8)
	if colCount > 0 {
		if bmp := encodeNullBitmap(colCount, row.IsNull); bmp != nil {
			buf = append(buf, bmp...)
		}
	}
	for i := 0; i < colCount && i < len(row.Values); i++ {
		if i < len(row.IsNull) && row.IsNull[i] {
			buf = append(buf, 0xfb) // SQL NULL
			continue
		}
		valBytes := decodeUserBytesOrEmpty(row.Values[i], row.ValueEncoding)
		buf = append(buf, encodeLenencBytes(valBytes)...)
	}
	return buf
}

// framePacket wraps a body with the 4-byte MySQL packet header
// (3-byte LE length + 1-byte sequence ID). Returns header+body.
func framePacket(seq uint8, body []byte) []byte {
	hdr := make([]byte, packetHeaderLen)
	copy(hdr[:3], encodeLEUint24(uint32(len(body))))
	hdr[3] = seq
	out := make([]byte, 0, packetHeaderLen+len(body))
	out = append(out, hdr...)
	out = append(out, body...)
	return out
}

// ----------------------------------------------------------------------------
// Auth response computation.
//
// mysql_native_password:
//
//	HASH1   = SHA1(password)
//	HASH2   = SHA1(HASH1)
//	stage2  = SHA1(scramble + HASH2)
//	resp    = HASH1 XOR stage2
//
// caching_sha2_password fast path:
//
//	xor_stage = SHA256(password) XOR SHA256(scramble + SHA256(SHA256(password)))
//	resp      = xor_stage
//
// sha256_password / unknown / caching_sha2_password cache miss:
//
//	planner emits a fixed placeholder (32 bytes). Real RSA encryption
//	requires server PEM public key; users wanting the real flow provide
//	ReplyBytes (raw mode on the first command) or wrap the planner in
//	the controller for alternate auth paths.
// ----------------------------------------------------------------------------

// computeAuthResponse returns the auth response bytes for the configured
// plugin. See header comment for the algorithm.
func computeAuthResponse(plugin string, password, scramble []byte) []byte {
	switch plugin {
	case "mysql_native_password":
		return mysqlNativePassword(password, scramble)
	case "caching_sha2_password":
		return cachingSHA2PasswordFast(password, scramble)
	default:
		// sha256_password and any unknown plugin: emit a planner-
		// computed placeholder.
		return placeholderRSA(len(password) > 0)
	}
}

// mysqlNativePassword returns the 20-byte mysql_native_password response.
//
// Per the MySQL 4.1+ native_password plugin (MySQL source sql/auth/password.c
// Scramble / hash_password_algorithm):
//
//	HASH1 = SHA1(password)
//	HASH2 = SHA1(HASH1)
//	stage2 = SHA1(scramble + HASH2)
//	response = HASH1 XOR stage2
//
// The response IS the XOR value directly — there is NO final SHA1 over the
// XOR. An earlier version of this function applied an extra `SHA1(xor)`,
// producing an incorrect 20-byte digest that no real MySQL server would
// accept.
func mysqlNativePassword(password, scramble []byte) []byte {
	if len(password) == 0 {
		return make([]byte, 20)
	}
	sha1P := sha1.Sum(password)          // HASH1 = SHA1(password)
	sha1Sha1P := sha1.Sum(sha1P[:])      // HASH2 = SHA1(HASH1)
	buf := append([]byte{}, scramble...)
	buf = append(buf, sha1Sha1P[:]...)   // scramble + HASH2
	sha1Step := sha1.Sum(buf)            // SHA1(scramble + HASH2)
	xor := make([]byte, 20)
	for i := 0; i < 20; i++ {
		xor[i] = sha1P[i] ^ sha1Step[i] // HASH1 XOR SHA1(scramble + HASH2)
	}
	return xor
}

// cachingSHA2PasswordFast returns the 32-byte caching_sha2_password
// fast-path response.
//
// SHA256(password) XOR SHA256(scramble + SHA256(SHA256(password))).
func cachingSHA2PasswordFast(password, scramble []byte) []byte {
	if len(password) == 0 {
		return make([]byte, 32)
	}
	sha256P := sha256.Sum256(password)
	sha256Sha256P := sha256.Sum256(sha256P[:])
	buf := append([]byte{}, scramble...)
	buf = append(buf, sha256Sha256P[:]...)
	sha256Step := sha256.Sum256(buf)
	xor := make([]byte, 32)
	for i := 0; i < 32; i++ {
		xor[i] = sha256P[i] ^ sha256Step[i]
	}
	return xor[:]
}

// placeholderRSA returns a deterministic 32-byte placeholder for the
// sha256_password / caching_sha2_password cache-miss auth reply.
// Real RSA encryption is intentionally NOT computed here (would need
// the server PEM public key).
func placeholderRSA(hasPassword bool) []byte {
	if !hasPassword {
		return make([]byte, 32)
	}
	tag := []byte("RSA_PLACEHOLDER_PADDING_PADDING_PADD")[:32]
	return tag
}

// ----------------------------------------------------------------------------
// Reply packet composition per ReplyMode.
// ----------------------------------------------------------------------------

// encodePrepareOKPacket emits the body of a COM_STMT_PREPARE_OK packet
// per MySQL protocol:
//
//	0x00 (status) | stmt_id (4 LE) | num_columns (2 LE) |
//	num_params (2 LE) | reserved (1) | warning_count (2 LE)
func encodePrepareOKPacket(stmtID uint32, numColumns, numParams, warnings uint16) []byte {
	buf := make([]byte, 0, 12)
	buf = append(buf, 0x00) // status
	buf = append(buf, encodeLEUint32(stmtID)...)
	buf = append(buf, encodeLEUint16(numColumns)...)
	buf = append(buf, encodeLEUint16(numParams)...)
	buf = append(buf, 0x00) // reserved
	buf = append(buf, encodeLEUint16(warnings)...)
	return buf
}

// encodeBinaryValue emits a single value for COM_STMT_EXECUTE binary
// protocol rows. The type byte determines the encoding (see MySQL
// Binary Protocol Value spec). The val string is decoded per encoding
// ("text" default, "hex", "base64"); for integer types it is parsed
// as a decimal integer, for float/double as a float64, for string
// types it is emitted as a length-encoded string.
//
// SQL NULL values are NOT emitted here - the caller marks them in the
// NULL bitmap and skips them entirely.
func encodeBinaryValue(typ uint8, unsigned bool, val, encoding string) []byte {
	if encoding == "" {
		encoding = "text"
	}
	// Parse the value bytes (raw bytes for string/integer types).
	rawBytes, _ := decodeUserBytes(val, encoding)
	// Build the 2-byte parameter type (low byte = type, MSB of high byte = unsigned).
	_ = unsigned // Reserved for param-type encoding; values here are direct.

	switch typ {
	case mysqlTypeTiny:
		v := parseUint64FromBytes(rawBytes, 0)
		return []byte{byte(v & 0xff)}
	case mysqlTypeShort, mysqlTypeYear:
		v := parseUint64FromBytes(rawBytes, 0)
		return encodeLEUint16(uint16(v & 0xffff))
	case mysqlTypeLong, mysqlTypeInt24:
		v := parseUint64FromBytes(rawBytes, 0)
		return encodeLEUint32(uint32(v & 0xffffffff))
	case mysqlTypeLongLong:
		v := parseUint64FromBytes(rawBytes, 0)
		return encodeLEUint64(v)
	case mysqlTypeFloat:
		f := parseFloatFromBytes(rawBytes, 0)
		return encodeLEUint32(math.Float32bits(float32(f)))
	case mysqlTypeDouble:
		f := parseFloatFromBytes(rawBytes, 0)
		return encodeLEUint64(math.Float64bits(f))
	default:
		// String / blob / json / decimal / date types: lenenc-string.
		return encodeLenencBytes(rawBytes)
	}
}

// encodeLEUint64 returns 8-byte little-endian.
func encodeLEUint64(n uint64) []byte {
	return []byte{
		byte(n), byte(n >> 8), byte(n >> 16), byte(n >> 24),
		byte(n >> 32), byte(n >> 40), byte(n >> 48), byte(n >> 56),
	}
}

// parseUint64FromBytes decodes a decimal integer from raw bytes. If
// raw is empty, returns def. Uses strings.TrimSpace for robustness.
func parseUint64FromBytes(raw []byte, def uint64) uint64 {
	if len(raw) == 0 {
		return def
	}
	v, err := parseUint64String(string(raw))
	if err != nil {
		return def
	}
	return v
}

// parseUint64String parses a decimal or hex/0x-prefixed integer.
func parseUint64String(s string) (uint64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty")
	}
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		return parseHexUint64(s[2:])
	}
	return parseDecUint64(s)
}

// parseDecUint64 parses a decimal uint64 from string.
func parseDecUint64(s string) (uint64, error) {
	var n uint64
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("bad digit %q", c)
		}
		n = n*10 + uint64(c-'0')
	}
	return n, nil
}

// parseHexUint64 parses a hex uint64 from string.
func parseHexUint64(s string) (uint64, error) {
	var n uint64
	for _, c := range s {
		var d uint64
		switch {
		case c >= '0' && c <= '9':
			d = uint64(c - '0')
		case c >= 'a' && c <= 'f':
			d = uint64(c-'a') + 10
		case c >= 'A' && c <= 'F':
			d = uint64(c-'A') + 10
		default:
			return 0, fmt.Errorf("bad hex digit %q", c)
		}
		n = n*16 + d
	}
	return n, nil
}

// parseFloatFromBytes decodes a float64 from decimal text bytes.
func parseFloatFromBytes(raw []byte, def float64) float64 {
	if len(raw) == 0 {
		return def
	}
	f, err := parseFloatString(string(raw))
	if err != nil {
		return def
	}
	return f
}

// parseFloatString parses a float64 from string (decimal point allowed).
func parseFloatString(s string) (float64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty")
	}
	// Integer promotion path avoids importing strconv; the integer
	// parser handles "0", "10", etc. and the slow path handles decimals.
	if !strings.ContainsAny(s, ".eE") {
		v, err := parseDecUint64(s)
		if err != nil {
			return 0, err
		}
		return float64(v), nil
	}
	// Fallback: convert manually. The MySQL planner is single-threaded
	// so the cost of a manual parser is acceptable; we avoid strconv.
	return parseFloatManual(s)
}

// parseFloatManual parses a decimal float64 manually (no strconv import).
func parseFloatManual(s string) (float64, error) {
	neg := false
	if len(s) > 0 && s[0] == '-' {
		neg = true
		s = s[1:]
	}
	dot := strings.Index(s, ".")
	intPart, decPart := s, ""
	if dot >= 0 {
		intPart = s[:dot]
		decPart = s[dot+1:]
	}
	var intVal uint64
	for _, c := range intPart {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("bad int digit %q", c)
		}
		intVal = intVal*10 + uint64(c-'0')
	}
	var decVal uint64
	var decPow float64 = 1
	for _, c := range decPart {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("bad dec digit %q", c)
		}
		decVal = decVal*10 + uint64(c-'0')
		decPow *= 10
	}
	v := float64(intVal) + float64(decVal)/decPow
	if neg {
		v = -v
	}
	return v, nil
}

// encodeBinaryRowPacket emits the body of a binary protocol result
// row: 0x00 header + NULL bitmap (offset 2) + values per column type.
// Returns nil if the number of columns doesn't match colDefs.
//
// The colDefs parameter is used to look up each value's type. The
// row.Values are decoded per row.ValueEncoding (or "text" default);
// for integer/float types the text is parsed as a decimal number, for
// string/blob types the raw bytes are emitted as a length-encoded
// string.
//
// IsNull[i] = true causes column i to be marked NULL in the bitmap
// (no value bytes emitted for that column).
func encodeBinaryRowPacket(row core.MySQLRow, colDefs []core.MySQLColDef) []byte {
	numCols := len(colDefs)
	bitmapLen := nullBitInBinaryResult(numCols)
	bitmap := make([]byte, bitmapLen)
	values := make([][]byte, numCols)

	// First pass: compute NULL bitmap + encode each value.
	for i := 0; i < numCols; i++ {
		isNull := i < len(row.IsNull) && row.IsNull[i]
		// A value of exactly "\xfb" also means NULL (lenenc convention).
		if !isNull && i < len(row.Values) && row.Values[i] == "\xfb" {
			isNull = true
		}
		if isNull {
			bytePos := (i + bitOffsetBinaryResult) / 8
			bitPos := uint((i + bitOffsetBinaryResult) % 8)
			bitmap[bytePos] |= 1 << bitPos
			continue
		}
		if i >= len(row.Values) {
			// No value provided: emit SQL NULL.
			bytePos := (i + bitOffsetBinaryResult) / 8
			bitPos := uint((i + bitOffsetBinaryResult) % 8)
			bitmap[bytePos] |= 1 << bitPos
			continue
		}
		var typ uint8 = mysqlTypeString // default
		var unsigned bool
		if i < len(colDefs) {
			typ = colDefs[i].Type
			unsigned = colDefs[i].Flags&0x20 != 0 // UNSIGNED_FLAG
		}
		valEnc := row.ValueEncoding
		if valEnc == "" {
			valEnc = "text"
		}
		values[i] = encodeBinaryValue(typ, unsigned, row.Values[i], valEnc)
	}

	// Second pass: concatenate (0x00 header + bitmap + values).
	var buf []byte
	buf = append(buf, 0x00)
	buf = append(buf, bitmap...)
	for _, v := range values {
		buf = append(buf, v...)
	}
	return buf
}

// encodeStmtExecuteRequest builds the COM_STMT_EXECUTE request body
// from StmtID + StmtFlags + IterationCount + StmtParams. Per MySQL
// protocol the body layout is:
//
//	0x17 (opcode) | stmt_id (4 LE) | flags (1) | iteration_count (4 LE) |
//	[parameter_count (lenenc)] | null_bitmap | new_params_bind_flag |
//	[per-param type (2 bytes) + value]
//
// The parameter_count lenenc field is only emitted when the
// CLIENT_QUERY_ATTRIBUTES capability is set; trafficgen does not set
// that capability, so the planner omits parameter_count and emits
// the null bitmap + new_params_bind_flag + types + values directly.
//
// The null bitmap uses bit_offset=0 (COM_STMT_EXECUTE convention). The
// new_params_bind_flag is always 1 (re-bind). Each parameter's 2-byte
// type field is low byte = enum_field_type, MSB of high byte = unsigned.
func encodeStmtExecuteRequest(cmd core.MySQLCommand) []byte {
	params := cmd.StmtParams
	numParams := len(params)

	// null bitmap: (num_params + 7) / 8 bytes, bit_offset=0.
	bitmapLen := (numParams + 7) / 8
	bitmap := make([]byte, bitmapLen)
	values := make([][]byte, numParams)
	types := make([][]byte, numParams)

	for i, p := range params {
		// Emit the 2-byte type for ALL parameters (including NULL ones)
		// when new_params_bind_flag=1. The null bitmap controls whether
		// value bytes follow; the type is always present.
		typByte := p.Type
		unsignedBit := uint8(0)
		if p.Unsigned {
			unsignedBit = 0x80
		}
		types[i] = []byte{typByte, unsignedBit}

		if p.IsNull {
			bitmap[i/8] |= 1 << uint(i%8)
			continue
		}
		valEnc := p.ValueEncoding
		if valEnc == "" {
			valEnc = "text"
		}
		values[i] = encodeBinaryValue(p.Type, p.Unsigned, p.Value, valEnc)
	}

	iterCount := cmd.IterationCount
	if iterCount == 0 {
		iterCount = 1
	}

	buf := make([]byte, 0, 9+bitmapLen+1+2*numParams)
	buf = append(buf, 0x1b) // COM_STMT_EXECUTE opcode
	buf = append(buf, encodeLEUint32(cmd.StmtID)...)
	buf = append(buf, cmd.StmtFlags)
	buf = append(buf, encodeLEUint32(iterCount)...)
	if numParams > 0 {
		buf = append(buf, bitmap...)
		buf = append(buf, 0x01) // new_params_bind_flag = 1
		for _, t := range types {
			buf = append(buf, t...)
		}
		for _, v := range values {
			buf = append(buf, v...)
		}
	}
	return buf
}

// buildReplyPackets returns the application-layer bodies (without the
// 4-byte packet header) for the command's reply. Each element becomes
// one MySQL packet after framing.
//
// For "raw" mode, the user provides the raw reply bytes (the literal
// concatenation of all down packet BODIES in order). The planner slices
// them into MaxPacketSize-sized packets — NOT into MSS-sized TCP
// segments; the latter happens at emit time via segmentByMSS.
func buildReplyPackets(cmd core.MySQLCommand, mc *core.MySQLConfig) [][]byte {
	switch cmd.ReplyMode {
	case "", "ok":
		status := cmd.StatusFlags
		if status == 0 {
			status = serverStatusAutocommit
		}
		return [][]byte{encodeOKPacket(0, 0, status, 0, cmd.EmitOkExtended, "")}
	case "ok-insert":
		status := cmd.StatusFlags
		if status == 0 {
			status = serverStatusAutocommit
		}
		return [][]byte{encodeOKPacket(1, 42, status, 0, cmd.EmitOkExtended, "")}
	case "ok-custom":
		status := cmd.StatusFlags
		if status == 0 {
			status = serverStatusAutocommit
		}
		warnings := cmd.Warnings
		return [][]byte{encodeOKPacket(cmd.AffectedRows, cmd.LastInsertID, status, warnings, cmd.EmitOkExtended, "")}
	case "err":
		return [][]byte{encodeERRPacket(1064, "HY000", "You have an error in your SQL syntax")}
	case "err-perm":
		return [][]byte{encodeERRPacket(1044, "42000", "Access denied for user")}
	case "err-custom":
		sqlState := cmd.ErrSQLState
		if sqlState == "" {
			sqlState = "HY000"
		}
		msg := cmd.ErrMessage
		if msg == "" {
			msg = "Unknown error"
		}
		return [][]byte{encodeERRPacket(cmd.ErrCode, sqlState, msg)}
	case "result-set":
		// column_count + col_defs + EOF + rows + EOF.
		out := make([][]byte, 0, 2+len(cmd.ColDefs)+len(cmd.Rows))
		colCount := len(cmd.ColDefs)
		out = append(out, encodeLenencInt(uint64(colCount)))
		for _, cd := range cmd.ColDefs {
			out = append(out, encodeColDefPacket(cd))
		}
		status := cmd.StatusFlags
		if status == 0 {
			status = serverStatusAutocommit
		}
		out = append(out, encodeEOFPacket(0, status))
		for _, r := range cmd.Rows {
			out = append(out, encodeRowPacket(r, colCount))
		}
		out = append(out, encodeEOFPacket(0, status))
		return out
	case "binary-result":
		// COM_STMT_EXECUTE response: column_count + col_defs + EOF +
		// binary rows + EOF. Each binary row is 0x00 header + NULL
		// bitmap (offset 2) + typed values per column.
		out := make([][]byte, 0, 2+len(cmd.ColDefs)+len(cmd.Rows))
		colCount := len(cmd.ColDefs)
		out = append(out, encodeLenencInt(uint64(colCount)))
		for _, cd := range cmd.ColDefs {
			out = append(out, encodeColDefPacket(cd))
		}
		status := cmd.StatusFlags
		if status == 0 {
			status = serverStatusAutocommit
		}
		out = append(out, encodeEOFPacket(0, status))
		for _, r := range cmd.Rows {
			out = append(out, encodeBinaryRowPacket(r, cmd.ColDefs))
		}
		out = append(out, encodeEOFPacket(0, status))
		return out
	case "prepare-ok":
		// COM_STMT_PREPARE_OK + param col defs + EOF + col defs + EOF.
		numCols := uint16(len(cmd.ColDefs))
		numParams := uint16(len(cmd.Params))
		out := make([][]byte, 0, 2+numParams+numCols+1)
		out = append(out, encodePrepareOKPacket(cmd.StmtID, numCols, numParams, cmd.WarningCount))
		for _, p := range cmd.Params {
			out = append(out, encodeColDefPacket(p))
		}
		if numParams > 0 {
			out = append(out, encodeEOFPacket(0, serverStatusAutocommit))
		}
		for _, c := range cmd.ColDefs {
			out = append(out, encodeColDefPacket(c))
		}
		if numCols > 0 {
			out = append(out, encodeEOFPacket(0, serverStatusAutocommit))
		}
		return out
	case "no-reply":
		// COM_QUIT / COM_STMT_CLOSE / COM_STMT_RESET: no server reply.
		return nil
	case "raw":
		rawBytes, err := decodeUserBytes(cmd.ReplyBytes, cmd.ReplyEncoding)
		if err != nil || len(rawBytes) == 0 {
			return [][]byte{encodeOKPacket(0, 0, serverStatusAutocommit, 0, false, "")}
		}
		maxPkt := int(DefaultMaxPacketSize)
		if mc.MaxPacketSize > 0 {
			maxPkt = int(mc.MaxPacketSize)
		}
		if maxPkt > MaxPacketBytes {
			maxPkt = MaxPacketBytes
		}
		out := make([][]byte, 0, (len(rawBytes)+maxPkt-1)/maxPkt)
		for len(rawBytes) > 0 {
			n := len(rawBytes)
			if n > maxPkt {
				n = maxPkt
			}
			out = append(out, rawBytes[:n])
			rawBytes = rawBytes[n:]
		}
		return out
	default:
		return [][]byte{encodeOKPacket(0, 0, serverStatusAutocommit, 0, false, "")}
	}
}

// ----------------------------------------------------------------------------
// User-input byte decode helpers.
// ----------------------------------------------------------------------------

// decodeUserBytes turns a user-supplied string field (Body,
// ReplyBytes, Row.Value) into raw bytes. Empty input → nil.
func decodeUserBytes(s, encoding string) ([]byte, error) {
	if s == "" {
		return nil, nil
	}
	switch encoding {
	case "", "text":
		return []byte(s), nil
	case "hex":
		return hex.DecodeString(s)
	case "base64":
		return base64.StdEncoding.DecodeString(s)
	default:
		return nil, fmt.Errorf("unknown encoding %q", encoding)
	}
}

// decodeUserBytesOrEmpty is the no-error variant used inside row-packet
// encoding where a malformed encoding falls back to an empty value
// rather than crashing the planner.
func decodeUserBytesOrEmpty(s, encoding string) []byte {
	b, err := decodeUserBytes(s, encoding)
	if err != nil {
		return nil
	}
	return b
}

// defaultScramble returns a deterministic 20-byte scramble so that
// tests are reproducible.
func defaultScramble() []byte {
	return []byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
		0x11, 0x12, 0x13, 0x14,
	}
}

// ----------------------------------------------------------------------------
// Generic helpers duplicated from other L7 planners (avoids import cycle).
// ----------------------------------------------------------------------------

// segmentByMSS splits payload into chunks of at most mss bytes. Returns
// a single empty chunk when payload is nil/empty.
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

// synOptions builds TCP options for SYN packets: MSS, Window Scale,
// SACK-Permitted.
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
