// Package redis implements the Redis (RESP2/RESP3) protocol planner.
//
// Redis (REmote DIctionary Server, 远程字典服务器) is a session-level
// key-value store running over a single TCP connection on port 6379. The
// wire protocol is RESP (REdis Serialization Protocol, Redis 序列化协议):
// clients send commands as RESP arrays of bulk strings; servers reply with
// typed RESP frames (Simple String, Error, Integer, Bulk String, Array in
// RESP2; plus Null, Boolean, Double, Big Number, Blob Error, Verbatim
// String, Map, Set, Push, Attribute in RESP3).
//
// The planner emits:
//
//  1. TCP 3-way handshake (SYN, SYN-ACK, ACK) with MSS/WinScale/SACK
//     options, mirroring the FTP/HTTP/SIP/POP3/Telnet control-channel
//     pattern. Conditional on TCPConfig.Handshake (default true when TCP
//     is nil).
//  2. Optional RESP3 HELLO 3 [AUTH u p] bootstrap (when Version=3 and
//     SkipHello=false), or RESP2 AUTH u p (when Version=2 and
//     Password!="").
//  3. Optional SELECT n (when SelectDB >= 0).
//  4. Optional CLIENT SETNAME <name> (when ClientName != "").
//  5. Optional SUBSCRIBE c1 c2 ... / PSUBSCRIBE p1 p2 ... (when
//     SubscribeTo / SubscribePatterns non-empty), each followed by the
//     matching server confirmation frames.
//  6. Each user RedisCommand: client command frame (PSH-ACK up) + paired
//     server reply frame (PSH-ACK down). In Pipeline mode (PipelineSize>1),
//     N consecutive commands are emitted before their N replies.
//  7. Optional PUBLISH frames from PublishMessages.
//  8. TCP 4-way teardown (FIN-ACK, ACK, FIN-ACK, ACK), or a single RST
//     when TCPConfig.RST=true. Conditional on TCPConfig.Termination.
//
// The planner does NOT enforce Redis state-machine transitions (MULTI/
// EXEC ordering, SUBSCRIBED command subset, WATCH/UNWATCH). The user is
// responsible for providing a syntactically valid dialog. This matches the
// trafficgen contract: synthesize test packets, not a real Redis server.
//
// IPv6 / multicast MAC / VLAN behavior follows the unified convention.
// Redis is transparent for IP version (works over IPv4 or IPv6).
package redis

import (
	"context"
	"encoding/base64"
	"fmt"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
)

const (
	// DefaultTTL mirrors internal/protocol/tcp.DefaultTTL (64).
	DefaultTTL = 64

	// DefaultMSS mirrors internal/protocol/tcp.DefaultMSS (1460). RFC 879
	// floor is 536; 1460 is the Ethernet-friendly value used by Linux.
	DefaultMSS = 1460

	// MinMSS per RFC 879 (IP+TCP header 20+20+536 = 576-byte minimum
	// packet). Smaller values produce malformed SYNs.
	MinMSS = 536

	// DefaultPort is the well-known Redis port (6379).
	DefaultPort = 6379
)

// TCP flag bits (RFC 9293 §3.1).
const (
	flagSYN = 0x02
	flagSYNACK = 0x12
	flagACK = 0x10
	flagPSHACK = 0x18
	flagFINACK = 0x11
	flagRSTACK = 0x14
)

// Planner implements the Redis protocol planner.
type Planner struct{}

// NewPlanner creates a new Redis planner.
func NewPlanner() *Planner { return &Planner{} }

// Name returns the protocol name used by the registry.
func (p *Planner) Name() string { return "redis" }

// Validate validates a Redis flow spec. Read-only: never modifies spec.
// Per the validate_conventions.md §1.1 contract, default-value filling
// happens in Plan(), not here.
func (p *Planner) Validate(spec core.FlowSpec) error {
	if spec.SrcIP != "" && net.ParseIP(spec.SrcIP) == nil {
		return fmt.Errorf("redis: SrcIP %q is not a valid IP address", spec.SrcIP)
	}
	if spec.DstIP != "" && net.ParseIP(spec.DstIP) == nil {
		return fmt.Errorf("redis: DstIP %q is not a valid IP address", spec.DstIP)
	}
	if spec.TCP != nil && spec.TCP.MSS > 0 && spec.TCP.MSS < MinMSS {
		return fmt.Errorf("redis: TCP.MSS %d too small (min %d per RFC 879)", spec.TCP.MSS, MinMSS)
	}
	if spec.Redis == nil {
		return nil
	}
	r := spec.Redis
	if r.Version != 0 && r.Version != 2 && r.Version != 3 {
		return fmt.Errorf("redis: Version %d invalid (must be 2 or 3)", r.Version)
	}
	if r.SelectDB < -1 || r.SelectDB > 15 {
		return fmt.Errorf("redis: SelectDB %d out of range [-1,15]", r.SelectDB)
	}
	if r.PipelineSize < 0 {
		return fmt.Errorf("redis: PipelineSize %d cannot be negative", r.PipelineSize)
	}
	for i, c := range r.Commands {
		if len(c.Args) == 0 && len(c.ArgsBase64) == 0 && c.Channel == "" {
			return fmt.Errorf("redis: Commands[%d] has no arguments (need Args, ArgsBase64, or Channel)", i)
		}
		for j, s := range c.ArgsBase64 {
			if _, err := base64.StdEncoding.DecodeString(s); err != nil {
				return fmt.Errorf("redis: Commands[%d].ArgsBase64[%d]: %w", i, j, err)
			}
		}
		// Every user command must produce a reply: either an explicit
		// Reply string or an AutoReply mode. Empty Reply + empty/none
		// AutoReply is an error (per testcases §2.8.4 and design §7.1
		// "none: Reply must be provided; planner errors out").
		if c.Reply == "" && (c.AutoReply == "" || c.AutoReply == core.RedisAutoReplyNone) {
			return fmt.Errorf("redis: Commands[%d] has no Reply and no AutoReply (set one or both)", i)
		}
		if c.Reply != "" {
			if err := validateRESPFrame(c.Reply); err != nil {
				return fmt.Errorf("redis: Commands[%d].Reply: %w", i, err)
			}
		}
		if c.Reply == "" && c.AutoReply != "" && c.AutoReply != core.RedisAutoReplyNone && !validAutoReply(c.AutoReply) {
			return fmt.Errorf("redis: Commands[%d].AutoReply %q invalid", i, c.AutoReply)
		}
	}
	for i, pub := range r.PublishMessages {
		if pub.MessageB64 != "" {
			if _, err := base64.StdEncoding.DecodeString(pub.MessageB64); err != nil {
				return fmt.Errorf("redis: PublishMessages[%d].MessageB64: %w", i, err)
			}
		}
	}
	return nil
}

// validReplyPrefix returns true when b is a valid RESP type prefix byte
// (RESP2: + - : $ *; RESP3: _ # , ( ! = % ~ > |).
func validReplyPrefix(b byte) bool {
	return strings.ContainsRune("+-:$*_#,(!=%~>|", rune(b))
}

// validAutoReply returns true when v is a recognized AutoReply mode.
func validAutoReply(v string) bool {
	switch v {
	case core.RedisAutoReplyNone, core.RedisAutoReplyOK, core.RedisAutoReplyQueued,
		core.RedisAutoReplyPong, core.RedisAutoReplyNilBulk, core.RedisAutoReplyNilArr,
		core.RedisAutoReplyEmpty:
		return true
	}
	if strings.HasPrefix(v, "integer-") {
		_, err := strconv.ParseInt(strings.TrimPrefix(v, "integer-"), 10, 64)
		return err == nil
	}
	return false
}

// validateRESPFrame checks that reply is a structurally valid RESP frame:
//   - First byte is a valid RESP type prefix.
//   - Frame ends with \r\n.
//   - For length-prefixed types ($, *, !, =, %, ~, >, |), the length line
//     is a valid integer (or -1 for $ and *).
//
// This catches the testcases §4.3.2 malformed replies (GARBAGE, $abc\r\n,
// $3\r\nfoo without trailing CRLF).
func validateRESPFrame(reply string) error {
	if len(reply) == 0 {
		return fmt.Errorf("empty reply")
	}
	if !validReplyPrefix(reply[0]) {
		return fmt.Errorf("invalid RESP prefix %q (must be one of + - : $ * _ # , ( ! = %% ~ > |)", reply[0])
	}
	if len(reply) < 2 || reply[len(reply)-1] != '\n' || reply[len(reply)-2] != '\r' {
		return fmt.Errorf("reply must end with \\r\\n")
	}
	// For length-prefixed types, validate the length line is a valid integer.
	switch reply[0] {
	case '$', '*', '!', '=', '%', '~', '>', '|':
		// Find the first \r\n after the prefix byte; the bytes between
		// are the length/count and must parse as int64 (or -1).
		end := strings.IndexByte(reply, '\r')
		if end < 0 || end+1 >= len(reply) || reply[end+1] != '\n' {
			return fmt.Errorf("length line missing CRLF")
		}
		lenStr := reply[1:end]
		if _, err := strconv.ParseInt(lenStr, 10, 64); err != nil {
			return fmt.Errorf("length %q is not a valid integer: %w", lenStr, err)
		}
	}
	return nil
}

// Plan generates packet configs for a Redis flow. Returns a channel that
// yields PacketConfig values in wire order. The channel is closed when
// generation completes or when ctx is cancelled.
func (p *Planner) Plan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) {
	if err := p.Validate(spec); err != nil {
		return nil, err
	}

	out := make(chan core.PacketConfig, 256)

	go func() {
		defer close(out)

		r := spec.Redis
		if r == nil {
			r = &core.RedisConfig{SelectDB: -1}
		}

		// Default command list when user provides none (per task spec).
		commands := r.Commands
		if len(commands) == 0 && len(r.SubscribeTo) == 0 && len(r.SubscribePatterns) == 0 && len(r.PublishMessages) == 0 {
			commands = defaultCommands()
		}

		// Effective defaults applied here (not in Validate) so spec stays
		// untouched per validate_conventions.md §1.3.
		effectiveTTL := spec.TTL
		if effectiveTTL == 0 {
			effectiveTTL = DefaultTTL
		}
		mss := uint16(DefaultMSS)
		if spec.TCP != nil && spec.TCP.MSS > 0 {
			mss = spec.TCP.MSS
		}
		windowSize := uint16(65535)
		if spec.TCP != nil && spec.TCP.WindowSize > 0 {
			windowSize = spec.TCP.WindowSize
		}
		handshake, termination := true, true
		if spec.TCP != nil {
			handshake = spec.TCP.Handshake
			termination = spec.TCP.Termination
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
		ipID := uint16(rand.Uint32())
		packetIndex := uint64(0)
		now := time.Now()

		flowID := fmt.Sprintf("%s-%s-%d-%d", spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort)

		// emit sends one packet in the given direction. Returns false
		// when ctx is cancelled (caller should return to close channel).
		emit := func(direction, smac, dmac, sip, dip string, sport, dport uint16, seq, ack uint32, flags uint8, payload []byte) bool {
			l4 := core.L4Config{
				Protocol:   "tcp",
				SrcPort:    sport,
				DstPort:    dport,
				Seq:        seq,
				Ack:        ack,
				Flags:      flags,
				WindowSize: windowSize,
			}
			if flags == flagSYN || flags == flagSYNACK {
				l4.TCPOptions = synOptions(mss)
			}
			cfg := core.PacketConfig{
				FlowID:      flowID,
				PacketIndex: packetIndex,
				Direction:   direction,
				Timestamp:   now,
				L2: core.L2Config{
					SrcMAC:    smac,
					DstMAC:    dmac,
					EtherType: core.EtherTypeFor(spec.SrcIP),
				},
				L3:      core.L3Base(sip, dip, 6, effectiveTTL, ipID, spec),
				L4:      l4,
				Payload: payload,
			}
			if spec.GroupID != nil && spec.GroupID.Strategy != "" {
				if g := core.FlowGroupIDValue(spec.GroupID, 0); g != "" {
					cfg.Metadata = map[string]interface{}{"group_id": g}
				}
			}
			select {
			case out <- cfg:
				packetIndex++
				ipID++
				return true
			case <-ctx.Done():
				return false
			}
		}

		// emitData segments payload by MSS and emits each chunk as a
		// PSH-ACK in the given direction, advancing the sender's seq.
		emitData := func(up bool, payload []byte) bool {
			for _, seg := range segmentByMSS(payload, int(mss)) {
				if up {
					if !emit("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, flagPSHACK, seg) {
						return false
					}
					clientSeq += uint32(len(seg))
				} else {
					if !emit("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, flagPSHACK, seg) {
						return false
					}
					serverSeq += uint32(len(seg))
				}
			}
			return true
		}

		// emitPair emits a command (up) and its reply (down). When reply
		// is empty, only the command is emitted (used for subscribe where
		// confirmations are emitted separately).
		emitPair := func(args [][]byte, reply []byte) bool {
			if !emitData(true, encodeRESPArray(args)) {
				return false
			}
			if len(reply) == 0 {
				return true
			}
			return emitData(false, reply)
		}

		// --- TCP handshake ---
		if handshake {
			if !emit("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, 0, flagSYN, nil) {
				return
			}
			clientSeq++
			if !emit("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, flagSYNACK, nil) {
				return
			}
			serverSeq++
			if !emit("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, flagACK, nil) {
				return
			}
		}

		// --- RESP3 HELLO / RESP2 AUTH bootstrap ---
		version := r.Version
		if version == 0 {
			version = 2
		}
		if version == 3 && !r.SkipHello {
			args := [][]byte{[]byte("HELLO"), []byte("3")}
			if r.Password != "" {
				args = append(args, []byte("AUTH"))
				if r.Username != "" {
					args = append(args, []byte(r.Username))
				}
				args = append(args, []byte(r.Password))
			}
			if !emitPair(args, []byte("%0\r\n")) {
				return
			}
		} else if version == 2 && r.Password != "" {
			args := [][]byte{[]byte("AUTH")}
			if r.Username != "" {
				args = append(args, []byte(r.Username))
			}
			args = append(args, []byte(r.Password))
			if !emitPair(args, []byte("+OK\r\n")) {
				return
			}
		}

		// --- SELECT n ---
		if r.SelectDB >= 0 {
			if !emitPair(bytesArgs("SELECT", strconv.Itoa(r.SelectDB)), []byte("+OK\r\n")) {
				return
			}
		}

		// --- CLIENT SETNAME ---
		if r.ClientName != "" {
			if !emitPair(bytesArgs("CLIENT", "SETNAME", r.ClientName), []byte("+OK\r\n")) {
				return
			}
		}

		// --- SUBSCRIBE / PSUBSCRIBE ---
		if len(r.SubscribeTo) > 0 {
			args := append([]string{"SUBSCRIBE"}, r.SubscribeTo...)
			if !emitData(true, encodeRESPArray(bytesArgs(args...))) {
				return
			}
			for i, ch := range r.SubscribeTo {
				if !emitData(false, encodeSubConfirm("subscribe", ch, i+1)) {
					return
				}
			}
		}
		if len(r.SubscribePatterns) > 0 {
			args := append([]string{"PSUBSCRIBE"}, r.SubscribePatterns...)
			if !emitData(true, encodeRESPArray(bytesArgs(args...))) {
				return
			}
			for i, pat := range r.SubscribePatterns {
				if !emitData(false, encodeSubConfirm("psubscribe", pat, i+1)) {
					return
				}
			}
		}

		// --- User commands (with optional pipelining) ---
		pipeline := r.PipelineSize
		if pipeline < 1 {
			pipeline = 1
		}
		for start := 0; start < len(commands); start += pipeline {
			end := start + pipeline
			if end > len(commands) {
				end = len(commands)
			}
			batch := commands[start:end]
			replies := make([][]byte, 0, len(batch))

			// Emit all commands in the batch first (up direction).
			for _, c := range batch {
				args, err := commandArgs(c)
				if err != nil {
					return
				}
				if !emitData(true, encodeRESPArray(args)) {
					return
				}
				reply := resolveReply(c)
				if c.EmitAsPush && len(reply) > 0 && reply[0] != '>' {
					reply = encodeRESP3Push([][]byte{reply})
				}
				replies = append(replies, reply)
			}

			// Emit all replies in the batch (down direction).
			for _, reply := range replies {
				if len(reply) > 0 {
					if !emitData(false, reply) {
						return
					}
				}
			}
		}

		// --- PUBLISH messages ---
		for _, pub := range r.PublishMessages {
			msg := []byte(pub.Message)
			if pub.MessageB64 != "" {
				msg, _ = base64.StdEncoding.DecodeString(pub.MessageB64)
			}
			if !emitPair([][]byte{[]byte("PUBLISH"), []byte(pub.Channel), msg}, []byte(":1\r\n")) {
				return
			}
		}

		// --- RST or TCP teardown ---
		if spec.TCP != nil && spec.TCP.RST {
			emit("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, flagRSTACK, nil)
			return
		}
		if termination {
			if !emit("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, flagFINACK, nil) {
				return
			}
			clientSeq++
			if !emit("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, flagACK, nil) {
				return
			}
			if !emit("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, flagFINACK, nil) {
				return
			}
			serverSeq++
			emit("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, flagACK, nil)
		}
	}()

	return out, nil
}

// defaultCommands returns a minimal command list (single PING) used when
// the user provides no Commands, Subscribe, or Publish config. This
// ensures the planner always emits at least one command/reply pair.
func defaultCommands() []core.RedisCommand {
	return []core.RedisCommand{
		{Args: []string{"PING"}, AutoReply: core.RedisAutoReplyPong},
	}
}

// commandArgs resolves a RedisCommand to its [][]byte argument list. Args
// (strings) come first, then ArgsBase64 (decoded). When both are empty and
// Channel is set, Channel is used as a single-element command (convenience
// for simple commands like PING).
func commandArgs(c core.RedisCommand) ([][]byte, error) {
	out := make([][]byte, 0, len(c.Args)+len(c.ArgsBase64)+1)
	for _, s := range c.Args {
		out = append(out, []byte(s))
	}
	for _, s := range c.ArgsBase64 {
		b, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	if len(out) == 0 && c.Channel != "" {
		out = append(out, []byte(c.Channel))
	}
	return out, nil
}

// bytesArgs converts string args to [][]byte.
func bytesArgs(args ...string) [][]byte {
	out := make([][]byte, len(args))
	for i, s := range args {
		out[i] = []byte(s)
	}
	return out
}

// resolveReply returns the reply bytes for a command: the explicit Reply
// if set, otherwise the auto-derived reply from AutoReply mode. Returns
// nil when neither is set (should not happen after Validate, but defensive).
func resolveReply(c core.RedisCommand) []byte {
	if c.Reply != "" {
		return []byte(c.Reply)
	}
	return autoReplyBytes(c.AutoReply)
}

// --- RESP2 encoders ---

// encodeRESPArray serializes args as a RESP array of bulk strings:
// *<argc>\r\n$<len>\r\n<data>\r\n...
func encodeRESPArray(args [][]byte) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "*%d\r\n", len(args))
	for _, a := range args {
		fmt.Fprintf(&b, "$%d\r\n", len(a))
		b.Write(a)
		b.WriteString("\r\n")
	}
	return []byte(b.String())
}

// encodeRESPBulk serializes v as a RESP bulk string: $<len>\r\n<v>\r\n.
func encodeRESPBulk(v []byte) []byte {
	return []byte(fmt.Sprintf("$%d\r\n%s\r\n", len(v), v))
}

// encodeRESPNull returns a RESP2 NIL bulk string: $-1\r\n.
func encodeRESPNull() []byte { return []byte("$-1\r\n") }

// encodeRESPInteger returns a RESP integer: :<n>\r\n.
func encodeRESPInteger(n int64) []byte {
	return []byte(fmt.Sprintf(":%d\r\n", n))
}

// encodeRESPSimpleString returns a RESP simple string: +<s>\r\n.
func encodeRESPSimpleString(v string) []byte {
	return []byte("+" + v + "\r\n")
}

// encodeRESPError returns a RESP error: -<msg>\r\n.
func encodeRESPError(msg string) []byte {
	return []byte("-" + msg + "\r\n")
}

// --- RESP3 encoders ---

// encodeRESP3Null returns a RESP3 null: _\r\n.
func encodeRESP3Null() []byte { return []byte("_\r\n") }

// encodeRESP3Boolean returns a RESP3 boolean: #t\r\n or #f\r\n.
func encodeRESP3Boolean(v bool) []byte {
	if v {
		return []byte("#t\r\n")
	}
	return []byte("#f\r\n")
}

// encodeRESP3Map returns a RESP3 map: %<n>\r\n<entries>...
// entries must have an even number of elements (key-value pairs).
func encodeRESP3Map(entries [][]byte) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "%%%d\r\n", len(entries)/2)
	for _, e := range entries {
		b.Write(e)
	}
	return []byte(b.String())
}

// encodeRESP3Set returns a RESP3 set: ~<n>\r\n<entries>...
func encodeRESP3Set(entries [][]byte) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "~%d\r\n", len(entries))
	for _, e := range entries {
		b.Write(e)
	}
	return []byte(b.String())
}

// encodeRESP3Push returns a RESP3 push frame: ><n>\r\n<entries>...
func encodeRESP3Push(entries [][]byte) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, ">%d\r\n", len(entries))
	for _, e := range entries {
		b.Write(e)
	}
	return []byte(b.String())
}

// encodeSubConfirm encodes a subscribe/psubscribe/unsubscribe confirmation
// frame: *3\r\n$<lenKind>\r\n<kind>\r\n$<lenCh>\r\n<ch>\r\n:<count>\r\n.
// The count is an integer (RESP :), not a bulk string, per the Redis
// pub/sub protocol (testcases §2.7.1.1).
func encodeSubConfirm(kind, channel string, count int) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "*3\r\n$%d\r\n%s\r\n$%d\r\n%s\r\n:%d\r\n", len(kind), kind, len(channel), channel, count)
	return []byte(b.String())
}

// autoReplyBytes maps an AutoReply mode to its RESP frame bytes. Returns
// nil for "none" or unrecognized modes (no reply emitted).
func autoReplyBytes(mode string) []byte {
	switch mode {
	case core.RedisAutoReplyOK:
		return []byte("+OK\r\n")
	case core.RedisAutoReplyQueued:
		return []byte("+QUEUED\r\n")
	case core.RedisAutoReplyPong:
		return []byte("+PONG\r\n")
	case core.RedisAutoReplyNilBulk:
		return []byte("$-1\r\n")
	case core.RedisAutoReplyNilArr:
		return []byte("*-1\r\n")
	case core.RedisAutoReplyEmpty:
		return []byte("*0\r\n")
	}
	if strings.HasPrefix(mode, "integer-") {
		n, err := strconv.ParseInt(strings.TrimPrefix(mode, "integer-"), 10, 64)
		if err == nil {
			return encodeRESPInteger(n)
		}
	}
	return nil
}

// segmentByMSS splits payload into chunks of at most mss bytes. The last
// chunk may be smaller. A nil/empty payload returns a single empty chunk
// so the caller emits one PSH-ACK segment. Mirrors http/ftp/pop3/telnet
// segmentByMSS - duplicated to avoid an import cycle.
func segmentByMSS(payload []byte, mss int) [][]byte {
	if mss <= 0 {
		return [][]byte{payload}
	}
	if len(payload) == 0 {
		return [][]byte{{}}
	}
	out := make([][]byte, 0, (len(payload)+mss-1)/mss)
	for len(payload) > 0 {
		n := len(payload)
		if n > mss {
			n = mss
		}
		out = append(out, payload[:n])
		payload = payload[n:]
	}
	return out
}

// synOptions builds TCP options for SYN packets: MSS, Window Scale, and
// SACK-Permitted. Mirrors http/ftp/pop3/telnet synOptions.
func synOptions(mss uint16) []core.TCPOption {
	if mss == 0 {
		mss = DefaultMSS
	}
	return []core.TCPOption{
		{Kind: core.TCPOptMSS, Data: []byte{byte(mss >> 8), byte(mss)}},
		{Kind: core.TCPOptWinScale, Data: []byte{0x07}},
		{Kind: core.TCPOptSACKPermit},
	}
}
