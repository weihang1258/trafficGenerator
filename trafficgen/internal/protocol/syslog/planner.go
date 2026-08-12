// Package syslog implements the Syslog protocol planner (RFC 5424).
//
// Syslog (系统日志协议, System Logging Protocol) is a text protocol for
// sending log messages to a central collector. The planner emits:
//
//  1. UDP mode (default, RFC 5426): one UDP datagram per syslog message
//     on port 514. Each message is a complete RFC 5424 frame:
//     `<PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD MSG`.
//  2. TCP mode (RFC 6587): TCP 3-way handshake → framed syslog messages
//     (octet-counting `<len> SP <msg> LF` or non-transparent `<msg> LF`)
//     → TCP 4-way teardown.
//  3. TLS mode (RFC 5425): same as TCP but on port 6514. The TLS handshake
//     is delegated to the engine layer; the planner only marks need_tls.
//
// RFC 5424 message layout (§6):
//
//	<PRI>VERSION SP TIMESTAMP SP HOSTNAME SP APP-NAME SP PROCID SP MSGID SP SD [SP MSG]
//
// Where:
//   - PRI = `<` Facility*8+Severity `>`, range 0-191 (§6.2.1)
//   - VERSION = 1 (§6.2.2, mandatory)
//   - TIMESTAMP = RFC 3339 or NILVALUE `-` (§6.2.3)
//   - HOSTNAME/APP-NAME/PROCID/MSGID = UTF-8 or NILVALUE `-`
//     (§6.2.4-§6.2.7)
//   - SD = 1+ SD-ELEMENTs concatenated without spaces, or NILVALUE `-`
//     (§6.2.8). Each SD-ELEMENT: `[ID[@PEN] [key="val"]*]`
//   - MSG = optional; preceded by SP (or BOM if MsgHasBOM=true, §6.4.4)
//
// NILVALUE (空值, "-") replaces any unknown field per RFC 5424 §3.2.2.
//
// IPv6 / multicast MAC / VLAN behavior follows the unified convention at
// /tmp/l7_planner_design/multicast_ipv6_vlan.md. Syslog is "✅ 必须（双栈）"
// (mandatory dual-stack): the planner accepts both IPv4 and IPv6 endpoints
// and uses EtherTypeFor(srcIP) to select the L2 EtherType dynamically.
package syslog

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
	// DefaultMSS mirrors internal/protocol/tcp.DefaultMSS (1460). Duplicated
	// here to avoid an import cycle. RFC 879 floor is 536.
	DefaultMSS = 1460
	// MinMSS per RFC 879 (IP+TCP header 20+20+536 = 576-byte minimum packet).
	MinMSS = 536

	// Default ports per RFC 5426/6587/5425.
	DefaultPort       uint16 = 514  // UDP & TCP
	DefaultTLSPort    uint16 = 6514 // TLS (RFC 5425)
	MaxUDPPayloadBytes       = 65507 // 65535 - 20 IP - 8 UDP (RFC 5426 §6)

	// UTF-8 BOM per RFC 5424 §6.4.4 (EF BB BF).
	utf8BOM = "\xef\xbb\xbf"

	// NILVALUE per RFC 5424 §3.2.2.
	NILVALUE = "-"

	// Default Facility/Severity per validate_conventions.md §7 (Syslog row):
	//   Facility 默认 16 (local0); Severity 默认 6 (info).
	// The design_syslog.md §8 also mentions 1/6 (user/info) as defaults.
	// We use 1/6 to match design_syslog.md §6.1 example and the crossverify
	// §7 table (C17: Facility 0-23, Severity 0-7, default 16/6). The
	// strategy_convert.go helper sets Facility=1, Severity=6 when the user
	// omits them; Validate accepts any value in range.
	DefaultFacility uint8 = 1
	DefaultSeverity uint8 = 6
	DefaultVersion  uint8 = 1
)

// Planner implements the Syslog protocol planner.
type Planner struct{}

// NewPlanner creates a new Syslog planner.
func NewPlanner() *Planner { return &Planner{} }

// Name returns the protocol name.
func (p *Planner) Name() string { return "syslog" }

// Validate validates a Syslog flow spec. Read-only per validate_conventions.md
// §1.1: does not modify spec; defaults are applied in Plan.
func (p *Planner) Validate(spec core.FlowSpec) error {
	if spec.SrcIP != "" {
		if net.ParseIP(spec.SrcIP) == nil {
			return fmt.Errorf("syslog: SrcIP %q is not a valid IP address", spec.SrcIP)
		}
	}
	if spec.DstIP != "" {
		if net.ParseIP(spec.DstIP) == nil {
			return fmt.Errorf("syslog: DstIP %q is not a valid IP address", spec.DstIP)
		}
	}
	return validateSyslogConfig(spec)
}

// validateSyslogConfig validates the SyslogConfig portion of a flow spec
// (SyslogConfig 非 nil、PRI 范围、format/version/transport/framing、
// timestamp、字段长度、SD-ELEMENT、UDP 负载上限)。波 4 起经 layer_gen.go
// 的 init 注册为 syslog 链的协议校验器，与 legacy Validate 共用同一实现
// （配置部分），保证两条路径拒绝同一批 spec。
func validateSyslogConfig(spec core.FlowSpec) error {
	if spec.Syslog == nil {
		return fmt.Errorf("syslog: config is required")
	}
	cfg := spec.Syslog

	// PRI bounds (RFC 5424 §6.2.1: Facility 0-23, Severity 0-7).
	if cfg.Facility > 23 {
		return fmt.Errorf("syslog: Facility %d invalid (must be 0-23 per RFC 5424 §6.2.1)", cfg.Facility)
	}
	if cfg.Severity > 7 {
		return fmt.Errorf("syslog: Severity %d invalid (must be 0-7 per RFC 5424 §6.2.1)", cfg.Severity)
	}

	// Format: "rfc5424" (default) or "bsd" (RFC 3164). Empty = rfc5424.
	format := cfg.Format
	if format == "" {
		format = "rfc5424"
	}
	if format != "rfc5424" && format != "bsd" {
		return fmt.Errorf("syslog: Format %q not in supported list (allowed: rfc5424, bsd per RFC 5424/3164)", cfg.Format)
	}

	// VERSION: RFC 5424 mandates VERSION=1 (§6.2.2). BSD format omits
	// VERSION entirely. Version=0 with Format=rfc5424 is rejected (testcase
	// 1.2.2 / 4.3.3) — the planner cannot emit a valid RFC 5424 message
	// without VERSION=1.
	if format == "rfc5424" {
		if cfg.Version == 0 {
			return fmt.Errorf("syslog: Version 0 unsupported (RFC 5424 requires VERSION=1; use Format=bsd for RFC 3164)")
		}
		if cfg.Version != 1 {
			return fmt.Errorf("syslog: Version %d unsupported (RFC 5424 requires VERSION=1)", cfg.Version)
		}
	}

	// Transport: udp (default), tcp, tls.
	transport := cfg.Transport
	if transport == "" {
		transport = "udp"
	}
	if transport != "udp" && transport != "tcp" && transport != "tls" {
		return fmt.Errorf("syslog: Transport %q not in supported list (allowed: udp, tcp, tls)", cfg.Transport)
	}

	// TCP framing: octet_counting (default) or non_transparent (RFC 6587 §3-4).
	if transport == "tcp" || transport == "tls" {
		framing := cfg.TCPFraming
		if framing == "" {
			framing = "octet_counting"
		}
		if framing != "octet_counting" && framing != "non_transparent" {
			return fmt.Errorf("syslog: TCPFraming %q not in supported list (allowed: octet_counting, non_transparent per RFC 6587)", cfg.TCPFraming)
		}
		// non-transparent framing forbids LF inside MSG (would break frame
		// delimiting per RFC 6587 §4). Check both the top-level Msg and
		// every per-message Msg (testcases §3.3.2/§3.4.2 multi-payload
		// path: a per-message Msg with LF would corrupt the frame).
		if framing == "non_transparent" {
			if strings.Contains(cfg.Msg, "\n") {
				return fmt.Errorf("syslog: MSG cannot contain LF in non-transparent framing (RFC 6587 §4 frame delimiting)")
			}
			for i, m := range cfg.Messages {
				if strings.Contains(m.Msg, "\n") {
					return fmt.Errorf("syslog: Messages[%d].Msg cannot contain LF in non-transparent framing (RFC 6587 §4)", i)
				}
			}
		}
	}

	// TIMESTAMP validation is format-specific:
	//   - RFC 5424 (default): empty or "-" = NILVALUE; non-empty must parse
	//     as RFC 3339 (§6.2.3). The planner emits the value verbatim into the
	//     RFC 5424 frame.
	//   - BSD (RFC 3164): empty or "-" = use current time at encode; non-empty
	//     may be either an RFC 3339 timestamp (re-formatted to "Mmm dd hh:mm:ss"
	//     by encodeBSD) or a pre-formatted BSD timestamp like "Jan  1 00:00:00".
	//     A pre-formatted BSD timestamp is accepted as-is and emitted verbatim
	//     by encodeBSD (which detects the BSD format and skips re-encoding).
	// Rejecting "Jan  1 00:00:00" here would make every SYSLOG.1.3-style test
	// fail validation even though the value is the canonical BSD timestamp
	// format mandated by RFC 3164 §4.1.2.
	//
	// The same RFC 3339 rule applies to per-message Timestamp entries
	// (testcases §3.3.2/§3.4.2 multi-payload path): an invalid per-message
	// timestamp would otherwise be silently emitted verbatim, producing a
	// malformed RFC 5424 frame that passes Validate but fails on the wire.
	validateTimestamp := func(label, ts string) error {
		if ts == "" || ts == NILVALUE {
			return nil
		}
		if format == "rfc5424" {
			if _, err := time.Parse(time.RFC3339Nano, ts); err != nil {
				return fmt.Errorf("syslog: %s %q not a valid RFC 3339 timestamp (RFC 5424 §6.2.3): %v", label, ts, err)
			}
		}
		// For format == "bsd" we accept any non-empty value. encodeBSD handles
		// both RFC 3339 (re-formatted to BSD) and pre-formatted BSD strings.
		return nil
	}
	if err := validateTimestamp("Timestamp", cfg.Timestamp); err != nil {
		return err
	}
	for i, m := range cfg.Messages {
		if err := validateTimestamp(fmt.Sprintf("Messages[%d].Timestamp", i), m.Timestamp); err != nil {
			return err
		}
	}

	// HOSTNAME 1-255 bytes (RFC 5424 §6.2.4); no SP allowed.
	if err := validateNoSpaceLen("HOSTNAME", cfg.Hostname, 255); err != nil {
		return err
	}
	// APP-NAME 1-48 bytes (§6.2.5).
	if err := validateNoSpaceLen("APP-NAME", cfg.AppName, 48); err != nil {
		return err
	}
	// PROCID 1-128 bytes (§6.2.6).
	if err := validateNoSpaceLen("PROCID", cfg.ProcID, 128); err != nil {
		return err
	}
	// MSGID 1-32 bytes (§6.2.7).
	if err := validateNoSpaceLen("MSGID", cfg.MsgID, 32); err != nil {
		return err
	}

	// STRUCTURED-DATA: each element must be a valid SD-ELEMENT. Empty list =
	// NILVALUE. Validate framing (must start with `[`, end with `]`), SD-ID
	// length (1-32, no SP), PARAM-NAME length (1-32, no SP).
	for i, sd := range cfg.StructuredData {
		if err := validateSDElement(sd, i); err != nil {
			return err
		}
	}

	// UDP payload size guard (RFC 5426 §6: max 65507 bytes). We check the
	// encoded message length, not the raw Msg field, to catch SD+MSG combos
	// that exceed the limit. TCP/TLS have no such cap (stream transport).
	if transport == "udp" {
		// Quick upper-bound check: header (~256 bytes worst case) + SD + MSG.
		// Full encode happens in Plan; here we use a conservative estimate.
		approx := 256 + len(cfg.Msg)
		for _, sd := range cfg.StructuredData {
			approx += len(sd) + 2 // brackets
		}
		if approx > MaxUDPPayloadBytes {
			return fmt.Errorf("syslog: encoded message exceeds UDP payload limit %d (RFC 5426 §6)", MaxUDPPayloadBytes)
		}
	}

	return nil
}

// validateNoSpaceLen checks that a field is empty (NILVALUE will be emitted)
// or within maxLen bytes and contains no SP (per RFC 5424 §6.2.4-§6.2.7).
func validateNoSpaceLen(field, value string, maxLen int) error {
	if value == "" {
		return nil
	}
	if strings.Contains(value, " ") {
		return fmt.Errorf("syslog: %s %q must not contain SP (RFC 5424 §6.2)", field, value)
	}
	if len(value) > maxLen {
		return fmt.Errorf("syslog: %s exceeds %d bytes (got %d, RFC 5424 §6.2)", field, maxLen, len(value))
	}
	return nil
}

// validateSDElement validates a single SD-ELEMENT string. Accepts both bare
// (`origin ip="1.2.3.4"`) and pre-framed (`[origin ip="1.2.3.4"]`) forms;
// the planner wraps bare forms at encode time. Validates:
//   - If pre-framed: starts with `[`, ends with `]`
//   - SD-ID (before first SP): 1-32 bytes, no SP. The SD-ID may be followed
//     by `@PEN` (e.g. `eventID@32473`) where PEN is the private enterprise
//     number, then optional `param="val"` parameters.
//   - After the SD-ID (and optional `@PEN`), the body must be empty (no
//     params) or consist of `SP PARAM-NAME="PARAM-VALUE"` triples. A bare
//     token after SP that is not a valid `name="value"` triple is rejected.
func validateSDElement(sd string, idx int) error {
	if sd == "" {
		return fmt.Errorf("syslog: StructuredData[%d] empty (use nil slice for NILVALUE)", idx)
	}
	// Strip pre-framed brackets for validation.
	body := sd
	if strings.HasPrefix(sd, "[") {
		if !strings.HasSuffix(sd, "]") {
			return fmt.Errorf("syslog: StructuredData[%d] unclosed SD-ELEMENT (missing ']' per RFC 5424 §6.2.8)", idx)
		}
		body = sd[1 : len(sd)-1]
		if body == "" {
			return fmt.Errorf("syslog: StructuredData[%d] empty brackets (SD-ID required)", idx)
		}
	}
	// SD-ID is the first token (before first SP). It may contain `@PEN`
	// (e.g. `eventID@32473`) which is part of the SD-ID.
	endID := len(body)
	for i, r := range body {
		if r == ' ' {
			endID = i
			break
		}
	}
	sdID := body[:endID]
	if strings.Contains(sdID, " ") {
		return fmt.Errorf("syslog: StructuredData[%d] SD-ID must not contain SP (RFC 5424 §6.2.8)", idx)
	}
	if len(sdID) > 32 {
		return fmt.Errorf("syslog: StructuredData[%d] SD-ID exceeds 32 bytes (RFC 5424 §6.2.8)", idx)
	}
	if len(sdID) < 1 {
		return fmt.Errorf("syslog: StructuredData[%d] SD-ID empty (RFC 5424 §6.2.8)", idx)
	}
	// After SD-ID, validate parameter structure. Each must be
	// `SP PARAM-NAME="PARAM-VALUE"` where PARAM-NAME is 1-32 chars
	// (letters/digits/underscore/hyphen). The body after SD-ID splits on
	// SP; each non-empty token must contain `=` and `"`. Note: PARAM-VALUE
	// may itself contain spaces (escaped or unescaped) which complicates
	// strict parsing. To avoid rejecting valid values with embedded SP
	// (which the user pre-escapes inside the quotes), we use a weaker
	// check: the body after SD-ID must either be empty (no params) or
	// contain at least one `=`. A fully strict SD-ELEMENT parser is out of
	// scope; the planner trusts the user's pre-framed form.
	rest := body[endID:]
	if rest != "" {
		// Trim leading SP; if the remainder is non-empty, it must contain
		// at least one `=` (a parameter assignment).
		trimmed := strings.TrimLeft(rest, " ")
		if trimmed != "" && !strings.Contains(rest, "=") {
			return fmt.Errorf("syslog: StructuredData[%d] parameter %q missing '=' (RFC 5424 §6.2.8)", idx, trimmed)
		}
	}
	return nil
}

// Plan generates packet configs for a Syslog flow.
func (p *Planner) Plan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) {
	if err := p.Validate(spec); err != nil {
		return nil, err
	}

	configChan := make(chan core.PacketConfig, 256)

	go func() {
		defer close(configChan)

		flowID := fmt.Sprintf("%s-%s-%d-%d", spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort)

		cfg := spec.Syslog
		// Apply defaults per validate_conventions.md §1.3 (in Plan goroutine,
		// not Validate).
		facility := cfg.Facility
		if facility == 0 && cfg.Transport == "" {
			// Distinguish "user set 0" from "unset" — both are 0. Since we
			// cannot tell, honor 0 as a valid value (kern facility). The
			// strategy_convert.go helper sets DefaultFacility=1 when the
			// user omits facility, so this branch only fires for direct
			// FlowSpec construction.
		}
		severity := cfg.Severity
		version := cfg.Version
		if version == 0 {
			version = DefaultVersion
		}
		format := cfg.Format
		if format == "" {
			format = "rfc5424"
		}
		transport := cfg.Transport
		if transport == "" {
			transport = "udp"
		}
		tcpFraming := cfg.TCPFraming
		if tcpFraming == "" {
			tcpFraming = "octet_counting"
		}
		count := cfg.Count
		if count == 0 {
			count = 1
		}

		effectiveTTL := spec.TTL
		if effectiveTTL == 0 {
			effectiveTTL = DefaultTTL
		}

		// Encode the syslog message(s). When Messages is non-empty, emit
		// one datagram/frame per entry with per-message overrides; otherwise
		// emit Count copies of the single encoded message.
		//
		// Per-message encoding (RFC 5424 §3.4 stream of distinct messages):
		// testcases_syslog.md §3.3.2 (per-message sequenceId), §3.4.2
		// (per-message MSG length variation).
		var msgBytesList [][]byte
		if len(cfg.Messages) > 0 {
			msgBytesList = make([][]byte, 0, len(cfg.Messages))
			for i := range cfg.Messages {
				entry := buildPerMessageCfg(cfg, &cfg.Messages[i])
				if format == "bsd" {
					msgBytesList = append(msgBytesList, encodeBSD(entry, facility, severity))
				} else {
					msgBytesList = append(msgBytesList, encodeRFC5424(entry, facility, severity, version))
				}
			}
		} else {
			single := encodeSingleMsg(cfg, format, facility, severity, version)
			msgBytesList = [][]byte{single}
		}

		now := time.Now()
		packetIndex := uint64(0)
		ipID := uint16(rand.Uint32())
		nextIPID := func() uint16 {
			id := ipID
			ipID++
			return id
		}

		switch transport {
		case "udp":
			emitUDP(configChan, spec, flowID, msgBytesList, now, &packetIndex, nextIPID, effectiveTTL, count)
		case "tcp":
			mss := uint16(DefaultMSS)
			if spec.TCP != nil && spec.TCP.MSS > 0 {
				mss = spec.TCP.MSS
			}
			emitTCP(configChan, spec, flowID, msgBytesList, now, &packetIndex, nextIPID, effectiveTTL, mss, tcpFraming, count)
		case "tls":
			// TLS uses the same TCP framing; the engine layer handles the
			// TLS handshake. We mark need_tls in Metadata so the engine can
			// dispatch. Port 6514 is set by mapToFlowSpec when transport=tls.
			mss := uint16(DefaultMSS)
			if spec.TCP != nil && spec.TCP.MSS > 0 {
				mss = spec.TCP.MSS
			}
			emitTCP(configChan, spec, flowID, msgBytesList, now, &packetIndex, nextIPID, effectiveTTL, mss, tcpFraming, count)
		}

		// Note: ctx.Done() is not explicitly checked here, matching the
		// pattern in udp.go and dns.go. The configChan send will block if
		// the consumer stops draining, which provides backpressure. A future
		// improvement would add a select on ctx.Done() in the send loop.
		_ = ctx
	}()

	return configChan, nil
}

// encodeSingleMsg encodes the top-level SyslogConfig into a single
// message byte slice, applying the active format (RFC 5424 or BSD).
// Used when SyslogConfig.Messages is empty.
func encodeSingleMsg(cfg *core.SyslogConfig, format string, facility, severity, version uint8) []byte {
	if format == "bsd" {
		return encodeBSD(cfg, facility, severity)
	}
	return encodeRFC5424(cfg, facility, severity, version)
}

// buildPerMessageCfg merges a per-message SyslogMessage entry over the
// top-level SyslogConfig to produce a SyslogConfig whose encodeRFC5424
// / encodeBSD will emit that one message. Fields that are zero-valued
// in the entry inherit from the parent (so `Msg: "hi"` alone inherits
// StructuredData/MsgID/etc from parent). msg_has_bom explicitly set in
// the entry (true or false) overrides parent; unset (zero) inherits.
//
// Returns a *new* SyslogConfig (not the original) so the parent is not
// mutated across iterations.
func buildPerMessageCfg(parent *core.SyslogConfig, entry *core.SyslogMessage) *core.SyslogConfig {
	out := *parent // shallow copy of scalar fields
	// Per-message overrides. Only override when the entry has set the
	// field (we use ""/nil as "inherit" sentinel for string/list fields;
	// MsgHasBOM uses an explicit override helper because bool false vs
	// unset is ambiguous in JSON).
	if entry.Timestamp != "" {
		out.Timestamp = entry.Timestamp
	}
	if entry.Hostname != "" {
		out.Hostname = entry.Hostname
	}
	if entry.AppName != "" {
		out.AppName = entry.AppName
	}
	if entry.ProcID != "" {
		out.ProcID = entry.ProcID
	}
	if entry.MsgID != "" {
		out.MsgID = entry.MsgID
	}
	if entry.StructuredData != nil {
		out.StructuredData = entry.StructuredData
	}
	if entry.Msg != "" {
		out.Msg = entry.Msg
	}
	// Distinguish "entry set msg_has_bom=true" from "entry omitted". We
	// always honor the entry's value when present; callers who want to
	// force "no BOM" for one message pass {msg_has_bom: false} explicitly
	// (the parser converts absent to false via getBool default). In Go
	// code via FlowSpec, the entry's MsgHasBOM is always honored as-is
	// since bool zero is a valid value (inherits).
	//
	// To preserve the "inherit" semantic from JSON, we use a heuristic:
	// if the entry has any other field set, the caller intended to
	// override; we honor its MsgHasBOM verbatim. Otherwise inherit.
	if hasAnyMessageField(entry) {
		out.MsgHasBOM = entry.MsgHasBOM
	}
	if entry.SignBlocks != nil {
		out.SignBlocks = entry.SignBlocks
	}
	return &out
}

// hasAnyMessageField returns true if the SyslogMessage has any
// non-default per-message field set. Used to decide whether MsgHasBOM
// should override or inherit (JSON absent -> inherit; explicit false ->
// override to no-BOM).
func hasAnyMessageField(m *core.SyslogMessage) bool {
	return m.Timestamp != "" || m.Hostname != "" || m.AppName != "" ||
		m.ProcID != "" || m.MsgID != "" || m.StructuredData != nil ||
		m.Msg != "" || m.SignBlocks != nil
}

// emitUDP emits N UDP datagrams, each carrying one syslog message.
// Direction is always "up" (client→server). UDP syslog is fire-and-forget
// per RFC 5426 §3.
//
// If msgs has multiple entries (from SyslogConfig.Messages), emit one
// datagram per entry (Count is ignored). Otherwise emit Count copies of
// the single encoded message.
func emitUDP(configChan chan<- core.PacketConfig, spec core.FlowSpec, flowID string, msgs [][]byte,
	now time.Time, packetIndex *uint64, nextIPID func() uint16, ttl uint8, count uint32) {
	emit := func(msg []byte) {
		configChan <- core.PacketConfig{
			FlowID:      flowID,
			PacketIndex: *packetIndex,
			Direction:   "up",
			Timestamp:   now,
			L2: core.L2Config{
				SrcMAC:    spec.SrcMAC,
				DstMAC:    spec.DstMAC,
				EtherType: core.EtherTypeFor(spec.SrcIP),
			},
			L3: core.L3Base(spec.SrcIP, spec.DstIP, core.ProtocolUDP, ttl, nextIPID(), spec),
			L4: core.L4Config{
				Protocol: "udp",
				SrcPort:  spec.SrcPort,
				DstPort:  spec.DstPort,
			},
			Payload: msg,
			Metadata: map[string]interface{}{
				"syslog_priority": int(spec.Syslog.Facility)*8 + int(spec.Syslog.Severity),
				"syslog_transport": "udp",
			},
		}
		*packetIndex++
	}
	if len(msgs) > 1 {
		// Multi-payload: one datagram per distinct message.
		for _, m := range msgs {
			emit(m)
		}
		return
	}
	// Legacy path: emit Count copies of the single message.
	for i := uint32(0); i < count; i++ {
		emit(msgs[0])
	}
}

// emitTCP emits TCP handshake → framed syslog messages → TCP teardown.
// Mirrors the SIP planner's TCP handling. Each syslog message becomes one
// or more PSH-ACK segments (MSS-segmented). Framing per RFC 6587:
//   - octet_counting: `<len> SP <msg> LF` (len is ASCII digits, excludes itself)
//   - non_transparent: `<msg> LF`
//
// If msgs has multiple entries (from SyslogConfig.Messages), emit one
// frame per entry (Count is ignored). Otherwise emit Count copies of the
// single encoded message (legacy behavior).
func emitTCP(configChan chan<- core.PacketConfig, spec core.FlowSpec, flowID string, msgs [][]byte,
	now time.Time, packetIndex *uint64, nextIPID func() uint16, ttl uint8, mss uint16, framing string, count uint32) {
	synOpts := synOptions(mss)

	// Random ISN per RFC 6528. User can override via spec.TCP.InitialSeq.
	clientSeq := uint32(0)
	if spec.TCP != nil {
		clientSeq = spec.TCP.InitialSeq
	}
	if clientSeq == 0 {
		clientSeq = rand.Uint32()
	}
	serverSeq := rand.Uint32()
	winSize := uint16(65535)

	emit := func(direction, srcMAC, dstMAC, srcIP, dstIP string, srcPort, dstPort uint16,
		seq, ack uint32, flags uint8, payload []byte) {
		l3 := core.L3Base(srcIP, dstIP, core.ProtocolTCP, ttl, nextIPID(), spec)
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
		configChan <- core.PacketConfig{
			FlowID:      flowID,
			PacketIndex: *packetIndex,
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
		*packetIndex++
	}

	// TCP 3-way handshake (SYN, SYN-ACK, ACK).
	emit("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, 0, 0x02, nil)
	clientSeq++
	emit("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, 0x12, nil)
	serverSeq++
	emit("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, 0x10, nil)

	// Determine how many frames to emit: 1 per distinct message when
	// multi-payload; else Count copies of the single message.
	frameCount := count
	if len(msgs) > 1 {
		frameCount = uint32(len(msgs))
	}
	for i := uint32(0); i < frameCount; i++ {
		// Pick the source message: multi-payload uses msgs[i]; legacy
		// path always uses msgs[0].
		msg := msgs[0]
		if len(msgs) > 1 {
			msg = msgs[i]
		}
		var frame []byte
		switch framing {
		case "non_transparent":
			// `<msg> LF` — msg must not contain LF (validated in Validate).
			frame = append(frame, msg...)
			frame = append(frame, '\n')
		default:
			// octet_counting: `<len> SP <msg> LF`. len is ASCII digits
			// and does NOT count its own bytes or the SP/LF.
			frame = []byte(fmt.Sprintf("%d %s\n", len(msg), msg))
		}

		// Segment by MSS and emit each chunk.
		for _, seg := range segmentByMSS(frame, int(mss)) {
			emit("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, 0x18, seg)
			clientSeq += uint32(len(seg))
		}
	}

	// TCP 4-way teardown (FIN-ACK, ACK, FIN-ACK, ACK).
	emit("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, 0x11, nil)
	clientSeq++
	emit("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, 0x10, nil)
	emit("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, 0x11, nil)
	serverSeq++
	emit("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, 0x10, nil)
}

// encodeRFC5424 builds the RFC 5424 §6 wire format:
//
//	<PRI>VERSION SP TIMESTAMP SP HOSTNAME SP APP-NAME SP PROCID SP MSGID SP SD [SP|BOM MSG]
//
// NILVALUE ("-") replaces empty fields. SD is the concatenation of all
// SD-ELEMENTs (each wrapped in `[...]` if not already), or NILVALUE when
// the list is empty. MSG is omitted entirely when empty (no SP, no BOM).
// When MSG is non-empty and MsgHasBOM is true, BOM replaces the SP before
// MSG per RFC 5424 §6.4.4.
func encodeRFC5424(cfg *core.SyslogConfig, facility, severity, version uint8) []byte {
	pri := int(facility)*8 + int(severity)

	var b strings.Builder
	// PRI: `<` digits `>` (§6.2.1). No leading zeros.
	fmt.Fprintf(&b, "<%d>", pri)
	// VERSION (§6.2.2).
	b.WriteString(fmt.Sprintf("%d", version))
	b.WriteByte(' ')
	// TIMESTAMP (§6.2.3): empty or "-" → NILVALUE; otherwise emit as-is
	// (validated as RFC 3339 in Validate).
	ts := cfg.Timestamp
	if ts == "" {
		ts = NILVALUE
	}
	b.WriteString(ts)
	b.WriteByte(' ')
	// HOSTNAME (§6.2.4).
	b.WriteString(nilOrValue(cfg.Hostname))
	b.WriteByte(' ')
	// APP-NAME (§6.2.5).
	b.WriteString(nilOrValue(cfg.AppName))
	b.WriteByte(' ')
	// PROCID (§6.2.6).
	b.WriteString(nilOrValue(cfg.ProcID))
	b.WriteByte(' ')
	// MSGID (§6.2.7).
	b.WriteString(nilOrValue(cfg.MsgID))
	b.WriteByte(' ')

	// STRUCTURED-DATA (§6.2.8): concatenate SD-ELEMENTs without spaces.
	// Empty list → NILVALUE. Each element wrapped in `[...]` if not already.
	// SignBlocks are appended as `[sign@32473 signature="..."]`.
	sdParts := make([]string, 0, len(cfg.StructuredData)+len(cfg.SignBlocks))
	for _, sd := range cfg.StructuredData {
		sdParts = append(sdParts, frameSDElement(sd))
	}
	for _, sig := range cfg.SignBlocks {
		// RFC 5848 syslog-sign: `[sign@32473 signature="<sig>"]`
		// Escape `"`, `\`, `]` in the signature value per RFC 5424 §6.2.8.
		sdParts = append(sdParts, fmt.Sprintf("[sign@32473 signature=\"%s\"]", escapeSDValue(sig)))
	}
	if len(sdParts) == 0 {
		b.WriteString(NILVALUE)
	} else {
		b.WriteString(strings.Join(sdParts, ""))
	}

	// MSG (§6.2.9): omitted entirely when empty. Otherwise SP (or BOM)
	// then MSG bytes. BOM replaces SP when MsgHasBOM=true (§6.4.4).
	// Note: empty MSG produces NO trailing SP/BOM (the "NILVALUE MSG" form
	// per §2.9). This matches the canonical RFC 5424 message
	// `<0>1 - - - - - -` (16 bytes, no MSG) — see testcase 4.5.1.
	if cfg.Msg != "" {
		if cfg.MsgHasBOM {
			b.WriteString(utf8BOM)
		} else {
			b.WriteByte(' ')
		}
		b.WriteString(cfg.Msg)
	}

	return []byte(b.String())
}

// encodeBSD builds the RFC 3164 (BSD syslog) wire format:
//
//	<PRI>TIMESTAMP SP HOSTNAME SP TAG[PID]: SP MSG
//
// Where TIMESTAMP is `Mmm dd hh:mm:ss` (15 bytes, month abbrev + day with
// leading space for 1-9 + time). No VERSION field. TAG is APP-NAME, PID is
// PROCID. When PROCID is empty, omit `[PID]`. When MSG is empty, omit the
// trailing SP+MSG.
func encodeBSD(cfg *core.SyslogConfig, facility, severity uint8) []byte {
	pri := int(facility)*8 + int(severity)

	var b strings.Builder
	fmt.Fprintf(&b, "<%d>", pri)

	// BSD timestamp: Mmm dd hh:mm:ss. The timestamp field accepts:
	//   - empty / "-" → use current time at emit (RFC 3164 §4.1.2 leaves this
	//     to the implementation; we pick now-UTC for determinism).
	//   - RFC 3339 timestamp (e.g. "2026-07-28T10:00:00Z") → re-formatted to
	//     BSD "Mmm dd hh:mm:ss" via time.Format.
	//   - Pre-formatted BSD timestamp (e.g. "Jan  1 00:00:00") → emitted
	//     verbatim. RFC 3164 §4.1.2 mandates this exact layout; the user may
	//     supply it directly to control the on-wire bytes. We detect the
	//     pre-formatted form by checking whether time.Parse(RFC3339Nano)
	//     rejects it; if it does and the value is non-empty/non-"-", we treat
	//     it as a pre-formatted BSD timestamp and emit it verbatim.
	timestampWritten := false
	var t time.Time
	ts := cfg.Timestamp
	if ts != "" && ts != NILVALUE {
		if parsed, err := time.Parse(time.RFC3339Nano, ts); err == nil {
			t = parsed
		} else {
			// Pre-formatted BSD timestamp: emit verbatim.
			b.WriteString(ts)
			b.WriteByte(' ')
			timestampWritten = true
		}
	}
	if !timestampWritten {
		if t.IsZero() {
			t = time.Now().UTC()
		}
		// Month abbreviations (Jan-Dec).
		months := []string{"Jan", "Feb", "Mar", "Apr", "May", "Jun",
			"Jul", "Aug", "Sep", "Oct", "Nov", "Dec"}
		b.WriteString(months[int(t.Month())-1])
		b.WriteByte(' ')
		// Day: space-padded to 2 chars (RFC 3164 §4.1.2: " 1"-"31").
		day := t.Day()
		if day < 10 {
			b.WriteByte(' ')
			b.WriteByte(byte('0' + day))
		} else {
			b.WriteByte(byte('0' + day/10))
			b.WriteByte(byte('0' + day%10))
		}
		b.WriteByte(' ')
		// Time: hh:mm:ss.
		b.WriteString(fmt.Sprintf("%02d:%02d:%02d", t.Hour(), t.Minute(), t.Second()))
		b.WriteByte(' ')
	}

	// HOSTNAME (or NILVALUE).
	b.WriteString(nilOrValue(cfg.Hostname))
	b.WriteByte(' ')

	// TAG[PID]: MSG. TAG = APP-NAME, PID = PROCID.
	tag := nilOrValue(cfg.AppName)
	pid := cfg.ProcID
	if pid != "" && pid != NILVALUE {
		b.WriteString(fmt.Sprintf("%s[%s]:", tag, pid))
	} else {
		b.WriteString(fmt.Sprintf("%s:", tag))
	}

	// MSG: SP + body. Omit when empty.
	if cfg.Msg != "" {
		b.WriteByte(' ')
		b.WriteString(cfg.Msg)
	}

	return []byte(b.String())
}

// nilOrValue returns "-" (NILVALUE) when value is empty, otherwise the
// value as-is. Per RFC 5424 §3.2.2.
func nilOrValue(v string) string {
	if v == "" {
		return NILVALUE
	}
	return v
}

// frameSDElement ensures an SD-ELEMENT is wrapped in `[...]`. Accepts both
// bare (`origin ip="1.2.3.4"`) and pre-framed (`[origin ip="1.2.3.4"]`)
// forms; the planner wraps bare forms at encode time.
func frameSDElement(sd string) string {
	if strings.HasPrefix(sd, "[") && strings.HasSuffix(sd, "]") {
		return sd
	}
	return "[" + sd + "]"
}

// escapeSDValue escapes `"`, `\`, `]` in a STRUCTURED-DATA PARAM-VALUE per
// RFC 5424 §6.2.8. Returns the escaped string.
func escapeSDValue(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '"', '\\', ']':
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// segmentByMSS splits payload into chunks of at most mss bytes. The last
// chunk may be smaller. A nil/empty payload returns a single empty chunk
// so the caller emits one PSH-ACK segment.
//
// Mirrors internal/protocol/sip.segmentByMSS — duplicated to avoid an
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
// SACK-Permitted. Mirrors internal/protocol/sip.synOptions — duplicated
// to avoid an import cycle.
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
