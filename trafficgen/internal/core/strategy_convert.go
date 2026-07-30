package core

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/trafficgen/trafficgen/internal/storage"
	"github.com/trafficgen/trafficgen/pkg/filesystem"
)

// Default field values applied by mapToFlowSpec when the user did not
// provide a value. Per the "user > default > none" rule, explicit user
// values (including 0 for numeric fields where 0 is a valid choice) MUST
// be honored -- defaults only fill in gaps.
const (
	// DefaultSrcMAC / DefaultDstMAC: locally-administered IEEE 802 MACs
	// (02: prefix) so trafficgen packets are visually distinct from real
	// hosts on the wire. Filter: ether src 02:00:00:00:00:00/16
	DefaultSrcMAC = "02:00:00:00:00:01"
	DefaultDstMAC = "02:00:00:00:00:02"

	// DefaultSrcIP / DefaultDstIP: 10.0.0.1 / 20.0.0.1 -- different /24
	// subnets so DPI/firewall tests see a routed (inter-subnet) flow rather
	// than a switched (intra-subnet) one. Formerly 192.0.2.1/192.0.2.2 (RFC
	// 5737 TEST-NET-1, same /24) which made src and dst DPI land in the same
	// subnet and defeated cross-subnet test scenarios.
	// These are SYNTHETIC test IPs (not assigned to any real NIC) -- per
	// trafficgen's "fake packets for testing" contract, they must not match
	// system NIC addresses. Users running real-traffic tests override with
	// actual routable IPs.
	DefaultSrcIP = "10.0.0.1"
	DefaultDstIP = "20.0.0.1"

	// DefaultSrcPort: high non-privileged port (>1024) typical of client
	// ephemeral ports. Multi-flow scenarios should use batch tuples to
	// vary src_port per flow.
	DefaultSrcPort = 12345

	// DefaultDstPort: 80 (HTTP) is the most common test target for TCP/UDP.
	// Protocol-specific defaults (DNS=53) still override this in their
	// switch cases.
	DefaultDstPort = 80

	// DefaultDSCP: CS1 (Class Selector 1, 0x08=8). Visible in the IP TOS
	// byte as 0x20 (0x08<<2). CS1 is RFC 4594 "less than best-effort" --
	// background traffic class that does NOT compete with business traffic
	// for the default (BE) queue. Marks every trafficgen IP packet so it
	// can be filtered out of noisy captures:
	//   tcpdump 'ip[1] & 0xfc == 0x20'
	// User can override with dscp=0 for plain best-effort, or dscp=0x2E
	// for EF (legacy behavior, affects business traffic).
	DefaultDSCP = 0x08

	// DefaultIPFlags: DF=1 (Don't Fragment). Matches modern OS TCP defaults
	// (Linux/macOS/Windows set DF=1 for TCP PMTU discovery). User can
	// override with flags=0 to allow fragmentation.
	DefaultIPFlags = 0x02 // IPFlagDF
)

// StrategyModelToTask converts a StrategyModel + TaskModel into a core.Task for the engine.
// Each strategy produces one engine task with a composite ID "{taskID}-{strategyID}".
// ifaceOverride, when non-empty, overrides the interface name (resolved from port_group by caller).
func StrategyModelToTask(taskModel *storage.TaskModel, strategy *storage.StrategyModel, ifaceOverride string) (*Task, error) {
	// Output config from task model — parsed first because replay and synth
	// branches both need it.
	var outputCfg struct {
		PortGroupID string `json:"port_group_id"`
		PcapPath    string `json:"pcap_path"`
	}
	json.Unmarshal([]byte(taskModel.OutputConfig), &outputCfg)

	outputMode := "pcap"
	iface := ""
	pcapFile := outputCfg.PcapPath
	if taskModel.OutputType == "port_group" {
		outputMode = "interface"
		pcapFile = ""
		iface = ifaceOverride
	} else if outputCfg.PcapPath != "" {
		pcapFile = outputCfg.PcapPath
	}

	// Task-level flow control: parsed into typed fields for the engine to
	// consume as an aggregate ceiling (parent rate bucket / shared flow
	// counter / parent context deadline). Unlike the legacy behaviour, this
	// does NOT overwrite spec.BPS/Count/Duration — the strategy-level limits
	// remain in spec and the task-level value caps the aggregate on top.
	var taskFC struct {
		Type  string  `json:"type"`
		Value float64 `json:"value"`
	}
	if taskModel.FlowControl != "" {
		json.Unmarshal([]byte(taskModel.FlowControl), &taskFC)
	}

	// Replay branch: no protocol planner, no mapToFlowSpec. The raw strategy
	// Config is passed as Replay JSON for the replay planner to interpret.
	if strategy.Mode == "replay" {
		task := &Task{
			ID:           fmt.Sprintf("%s-%s", taskModel.ID, strategy.ID),
			Name:         strategy.Name,
			Mode:         "replay",
			Replay:       json.RawMessage(strategy.Config),
			ClassID:      fmt.Sprintf("%s-%s", taskModel.ID, strategy.ID),
			ParentTaskID: taskModel.ID,
			Interface:    iface,
			OutputMode:   outputMode,
			PcapFile:     pcapFile,
			TaskFCType:   taskFC.Type,
			TaskFCValue:  taskFC.Value,
			UserID:       taskModel.UserID,
		}
		// bps mode: extract speed.bps into Spec.BPS so the engine creates a
		// per-strategy child rate-limiter bucket for this task (same as synth).
		var rs struct {
			Speed struct {
				Mode string `json:"mode"`
				BPS  string `json:"bps"`
			} `json:"speed"`
		}
		if json.Unmarshal([]byte(strategy.Config), &rs) == nil && rs.Speed.Mode == "bps" {
			task.Spec.BPS = rs.Speed.BPS
		}
		return task, nil
	}

	var cfg map[string]interface{}
	if err := json.Unmarshal([]byte(strategy.Config), &cfg); err != nil {
		return nil, fmt.Errorf("invalid strategy config JSON: %w", err)
	}

	spec := mapToFlowSpec(cfg, strategy.Protocol)

	// Flow control from strategy
	var fc struct {
		Type  string  `json:"type"`
		Value float64 `json:"value"`
	}
	if strategy.FlowControl != "" {
		json.Unmarshal([]byte(strategy.FlowControl), &fc)
	}
	switch fc.Type {
	case "bps":
		spec.BPS = formatBPS(fc.Value)
	case "flows":
		spec.Count = int(fc.Value)
	case "time":
		spec.Duration = int(fc.Value)
	}

	return &Task{
		ID:           fmt.Sprintf("%s-%s", taskModel.ID, strategy.ID),
		Name:         strategy.Name,
		Protocol:     strategy.Protocol,
		Spec:         spec,
		ClassID:      fmt.Sprintf("%s-%s", taskModel.ID, strategy.ID),
		ParentTaskID: taskModel.ID,
		Interface:    iface,
		OutputMode:   outputMode,
		PcapFile:     pcapFile,
		TaskFCType:   taskFC.Type,
		TaskFCValue:  taskFC.Value,
	}, nil
}

// mapToFlowSpec builds a FlowSpec from a config map and protocol name. It
// populates L2/L3/L4 and protocol-specific fields. It does NOT set BPS/Count/
// Duration (those come from flow control and are the caller's responsibility).
// Shared by StrategyModelToTask (single-protocol tasks) and the mixed-traffic
// batch path (TrafficClass.Config).
//
// Defaulting follows the unified rule (user > default > none): when a field
// is absent from cfg, the corresponding Default* constant fills in. Numeric
// fields where 0 is a valid user choice (DSCP=best-effort, IPFlags=no-DF) use
// hasKey to distinguish "absent" from "explicitly 0".
//
// Backward compatibility: several fields were renamed to remove ambiguity —
// "flags" -> "ip_flags" (was ambiguous with TCP flags), "content_encoding"
// -> "response_content_encoding" (sounded global but only affects response),
// "response" -> "is_response" (UDP/DNS, was ambiguous with FTP response
// bodies). The new name is preferred when present; the legacy name is read
// as fallback so existing DB rows keep working.
func mapToFlowSpec(cfg map[string]interface{}, protocol string) FlowSpec {
	spec := FlowSpec{
		SrcIP:      defaultString(cfg, "src_ip", DefaultSrcIP),
		DstIP:      defaultString(cfg, "dst_ip", DefaultDstIP),
		SrcPort:    defaultPort(cfg, "src_port", DefaultSrcPort),
		DstPort:    defaultPort(cfg, "dst_port", DefaultDstPort),
		SrcMAC:     defaultMAC(cfg, "src_mac", DefaultSrcMAC),
		DstMAC:     defaultMAC(cfg, "dst_mac", DefaultDstMAC),
		TTL:        uint8(getIntDefault(cfg, "ttl", 64)),
		TOS:        uint8(getInt(cfg, "tos")),
		DSCP:       defaultDSCP(cfg),
		ECN:        uint8(getInt(cfg, "ecn")),
		IPFlags:    defaultIPFlags(cfg),
		FragOffset: uint16(getInt(cfg, "frag_offset")),
		Payload:    []byte(getString(cfg, "payload")),
	}

	// VLAN
	if vlanID := getUint16(cfg, "vlan_id"); vlanID > 0 {
		spec.VLAN = &VLAN{
			ID:       vlanID,
			Priority: uint8(getInt(cfg, "vlan_priority")),
		}
	}

	// Universal TCP sub-config: applies to any TCP-based protocol
	// (tcp/http/ftp/sip). Must run before the protocol-specific switch so
	// the switch only handles protocol-specific fields (HTTP/FTP/SIP/...).
	// Before this, cfg["tcp"] was only read inside case "tcp", leaving
	// spec.TCP nil for http/ftp/sip -- a regression from the MSS relocation
	// that silently dropped MSS/InitialSeq/Handshake/Termination for those
	// protocols.
	if sub, ok := cfg["tcp"].(map[string]interface{}); ok {
		spec.TCP = &TCPConfig{
			Handshake:   getBool(sub, "handshake", true),
			Termination: getBool(sub, "termination", true),
			RST:         getBool(sub, "rst", false),
			MSS:         getUint16(sub, "mss"),
			WindowSize:  getUint16(sub, "window_size"),
			InitialSeq:  getUint32(sub, "initial_seq"),
		}
	}

	// Protocol-specific config
	switch protocol {
	case "tcp":
		// TCP sub-config already read above; nothing protocol-specific to add.
	case "udp":
		if sub, ok := cfg["udp"].(map[string]interface{}); ok {
			spec.UDP = &UDPConfig{
				IsResponse:      getBoolWithFallback(sub, "is_response", "response", false),
				DisableChecksum: getBool(sub, "disable_checksum", false),
			}
		}
	case "http":
		if sub, ok := cfg["http"].(map[string]interface{}); ok {
			// Backward compat: pre-rename strategies stored request headers
			// under the "headers" key. Prefer the new "request_headers" key
			// when present; fall back to legacy key so existing DB rows do
			// not silently lose user-configured headers.
			reqHeaders := getStringMap(sub, "request_headers")
			if len(reqHeaders) == 0 {
				reqHeaders = getStringMap(sub, "headers")
			}
			spec.HTTP = &HTTPConfig{
				Method:                  getStringDefault(sub, "method", "GET"),
				URI:                     getStringDefault(sub, "uri", "/"),
				Version:                 getString(sub, "version"),
				RequestHeaders:          reqHeaders,
				Body:                    getString(sub, "body"),
				BodyB64:                 getString(sub, "body_b64"),
				KeepAlive:               getBool(sub, "keep_alive", false),
				Transactions:            getInt(sub, "transactions"),
				ThinkTime:               getInt(sub, "think_time"),
				ResponseHeaders:         getStringMap(sub, "response_headers"),
				ResponseBody:            getString(sub, "response_body"),
				ResponseBodyB64:         getString(sub, "response_body_b64"),
				ResponseStatusCode:      getInt(sub, "response_status_code"),
				ResponseStatusText:      getString(sub, "response_status_text"),
				ResponseContentEncoding: getStringWithFallback(sub, "response_content_encoding", "content_encoding"),
				RequestContentEncoding:  getString(sub, "request_content_encoding"),
			}
		}
		// HTTP defaults to port 80, same as DefaultDstPort. No override
		// needed here -- mapToFlowSpec's defaultPort call already set it.
	case "dns":
		if sub, ok := cfg["dns"].(map[string]interface{}); ok {
			spec.DNS = &DNSConfig{
				Domain:         getString(sub, "domain"),
				QueryType:      uint16(getIntDefault(sub, "query_type", 1)),
				IsResponse:     getBoolWithFallback(sub, "is_response", "response", false),
				ResponseIP:     getString(sub, "response_ip"),
				TxID:           uint16(getInt(sub, "txid")),
				EDNS0Enabled:   getBool(sub, "edns0_enabled", false),
				UDPPayloadSize: uint16(getIntDefault(sub, "udp_payload_size", 4096)),
				DnssecOK:       getBool(sub, "dnssec_ok", false),
			}
		}
		// DNS overrides the generic port-80 default with its own 53.
		if _, ok := cfg["dst_port"]; !ok || cfg["dst_port"] == nil {
			spec.DstPort = 53
		}
	case "icmp":
		if sub, ok := cfg["icmp"].(map[string]interface{}); ok {
			spec.ICMP = &ICMPConfig{
				Type:       uint8(getIntDefault(sub, "type", 8)),
				Code:       uint8(getIntDefault(sub, "code", 0)),
				Identifier: uint16(getInt(sub, "identifier")),
				Sequence:   uint16(getIntDefault(sub, "sequence", 1)),
				Data:       []byte(getStringDefault(sub, "data", "ping")),
				Pattern:    parseICMPPattern(sub["pattern"]),
			}
		}
	case "arp":
		if sub, ok := cfg["arp"].(map[string]interface{}); ok {
			spec.ARP = &ARPConfig{
				Operation: uint16(getIntDefault(sub, "operation", 1)),
				TargetMAC: getString(sub, "target_mac"),
				TargetIP:  getString(sub, "target_ip"),
			}
		}
	case "ftp":
		if sub, ok := cfg["ftp"].(map[string]interface{}); ok {
			spec.FTP = &FTPConfig{
				Banner:      getString(sub, "banner"),
				Commands:    parseFTPCommands(sub["commands"]),
				DataChannel: parseFTPDataChannel(sub["data_channel"]),
			}
		}
		// FTP defaults to port 21 (control channel). Only override when
		// the user did not specify a dst_port — matches the DNS override
		// pattern.
		if _, ok := cfg["dst_port"]; !ok || cfg["dst_port"] == nil {
			spec.DstPort = 21
		}
	case "sip":
		if sub, ok := cfg["sip"].(map[string]interface{}); ok {
			spec.SIP = &SIPConfig{
				Dialog: parseSIPDialog(sub["dialog"]),
				Media:  parseSIPMedia(sub["media"]),
			}
		}
		// SIP defaults to port 5060 (signaling). Only override when the
		// user did not specify a dst_port — matches DNS/FTP pattern.
		if _, ok := cfg["dst_port"]; !ok || cfg["dst_port"] == nil {
			spec.DstPort = 5060
		}
	case "sctp":
		if sub, ok := cfg["sctp"].(map[string]interface{}); ok {
			spec.SCTP = &SCTPConfig{
				VerificationTag: getUint32(sub, "verification_tag"),
				InitiateTag:     getUint32(sub, "initiate_tag"),
				Chunks:          parseSCTPChunks(sub["chunks"]),
				Heartbeats:      parseSCTPHeartbeats(sub["heartbeats"]),
				Abort:           getBool(sub, "abort", false),
			}
		}
		// SCTP has no universal default port (common ports: 38412 for NGAP,
		// 2905 for M3UA, 9 for discard). Unlike HTTP/FTP/SIP, the user must
		// specify dst_port; otherwise mapToFlowSpec's generic default of
		// DefaultDstPort (80) is left in place — which is almost never what
		// an SCTP test wants. We do not silently override 80 → 38412.
	case "icmpv6":
		if sub, ok := cfg["icmpv6"].(map[string]interface{}); ok {
			spec.ICMPv6 = &ICMPv6Config{
				Type:       uint8(getIntDefault(sub, "type", 128)),
				Code:       uint8(getIntDefault(sub, "code", 0)),
				Identifier: uint16(getInt(sub, "identifier")),
				Sequence:   uint16(getIntDefault(sub, "sequence", 1)),
				Data:       []byte(getStringDefault(sub, "data", "ping")),
				Pattern:    parseICMPv6Pattern(sub["pattern"]),
				FileSource: parseFileSource(sub),
			}
		}
		// ICMPv6 does not use ports (it is a Layer 3 protocol like ICMP).
		// Clear src_port/dst_port to 0 so the L4 header — which is never
		// emitted for ICMP — does not carry stale values that confuse
		// packet inspection. ICMPv6 packets over the wire carry no L4.
		spec.SrcPort = 0
		spec.DstPort = 0
	// --- Phase 3 L7 protocols. Each case is a placeholder the protocol's
	// implementer fills in. The default branch only sets spec.<Proto> to a
	// zero-valued pointer when the cfg sub-map is present, so mapToFlowSpec
	// round-trips (JSON unmarshal test) work before the implementer adds
	// real field parsing. Implementer replaces the body with real parsing.
	case "dhcp":
		if sub, ok := cfg["dhcp"].(map[string]interface{}); ok {
			spec.DHCP = parseDHCPConfig(sub)
		}
		if _, ok := cfg["dst_port"]; !ok || cfg["dst_port"] == nil {
			spec.DstPort = 67
		}
	case "dhcpv6":
		if sub, ok := cfg["dhcpv6"].(map[string]interface{}); ok {
			spec.DHCPv6 = parseDHCPv6Config(sub)
		}
		if _, ok := cfg["dst_port"]; !ok || cfg["dst_port"] == nil {
			spec.DstPort = 547
		}
	case "grpc":
		if sub, ok := cfg["grpc"].(map[string]interface{}); ok {
			spec.GRPC = parseGRPCConfig(sub)
		}
		if _, ok := cfg["dst_port"]; !ok || cfg["dst_port"] == nil {
			spec.DstPort = 8604
		}
	case "ike":
		if sub, ok := cfg["ike"].(map[string]interface{}); ok {
			spec.IKE = parseIKEConfig(sub)
		}
		if _, ok := cfg["dst_port"]; !ok || cfg["dst_port"] == nil {
			spec.DstPort = 500
		}
	case "ike_nat_t":
		if sub, ok := cfg["ike_nat_t"].(map[string]interface{}); ok {
			spec.IKENATT = parseIKENATTConfig(sub)
		}
		if _, ok := cfg["dst_port"]; !ok || cfg["dst_port"] == nil {
			spec.DstPort = 4500
		}
	case "imap":
		if sub, ok := cfg["imap"].(map[string]interface{}); ok {
			spec.IMAP = parseIMAPConfig(sub)
		}
		if _, ok := cfg["dst_port"]; !ok || cfg["dst_port"] == nil {
			spec.DstPort = 143
		}
	case "l2tp":
		if sub, ok := cfg["l2tp"].(map[string]interface{}); ok {
			spec.L2TP = parseL2TPConfig(sub)
		}
		if _, ok := cfg["dst_port"]; !ok || cfg["dst_port"] == nil {
			spec.DstPort = 1701
		}
	case "mdns":
		if sub, ok := cfg["mdns"].(map[string]interface{}); ok {
			spec.MDNS = parseMDNSConfig(sub)
		}
		if _, ok := cfg["dst_port"]; !ok || cfg["dst_port"] == nil {
			spec.DstPort = 5353
		}
	case "mysql":
		if sub, ok := cfg["mysql"].(map[string]interface{}); ok {
			spec.MySQL = parseMySQLConfig(sub)
		}
		if _, ok := cfg["dst_port"]; !ok || cfg["dst_port"] == nil {
			spec.DstPort = 3306
		}
	case "ntp":
		if sub, ok := cfg["ntp"].(map[string]interface{}); ok {
			spec.NTP = &NTPConfig{
				LeapIndicator:  uint8(getIntDefault(sub, "leap_indicator", 0)),
				Version:        uint8(getIntDefault(sub, "version", 4)),
				Mode:           uint8(getIntDefault(sub, "mode", 3)),
				Stratum:        uint8(getIntDefault(sub, "stratum", 0)),
				Poll:           int8(getIntDefault(sub, "poll", 6)),
				Precision:      int8(getIntDefault(sub, "precision", -6)),
				RootDelay:      getFloatDefault(sub, "root_delay", 0),
				RootDispersion: getFloatDefault(sub, "root_dispersion", 0),
				ReferenceID:    getUint32(sub, "reference_id"),
				RefTimestamp:   getTime(sub, "ref_timestamp"),
				OriginTS:       getTime(sub, "origin_ts"),
				ReceiveTS:      getTime(sub, "receive_ts"),
				TransmitTS:     getTime(sub, "transmit_ts"),
				KeyID:          getUint32(sub, "key_id"),
				MAC:            getByteSlice(sub, "mac"),
				Extensions:     parseNTPExtensions(sub["extensions"]),
				IsResponse:     getBool(sub, "is_response", false),
				PollInterval:   getInt(sub, "poll_interval"),
				RepeatCount:    getInt(sub, "repeat_count"),
				Sequence:       uint16(getIntDefault(sub, "sequence", 0)),
				Implementation: uint8(getIntDefault(sub, "implementation", 0)),
				RequestCode:    uint8(getIntDefault(sub, "request_code", 0)),
				AssociationID:  uint16(getIntDefault(sub, "association_id", 0)),
				Offset:         uint16(getIntDefault(sub, "offset", 0)),
				Error:          getBool(sub, "error", false),
				More:           getBool(sub, "more", false),
				StatusWord:     uint16(getInt(sub, "status_word")),
				ControlData:    getByteSlice(sub, "control_data"),
			}
		}
		if _, ok := cfg["dst_port"]; !ok || cfg["dst_port"] == nil {
			spec.DstPort = 123
		}
	case "openvpn":
		if sub, ok := cfg["openvpn"].(map[string]interface{}); ok {
			spec.OpenVPN = parseOpenVPNConfig(sub)
		}
		if _, ok := cfg["dst_port"]; !ok || cfg["dst_port"] == nil {
			spec.DstPort = 1194
		}
	case "postgresql":
		if sub, ok := cfg["postgresql"].(map[string]interface{}); ok {
			spec.PostgreSQL = parsePostgreSQLConfig(sub)
		}
		if _, ok := cfg["dst_port"]; !ok || cfg["dst_port"] == nil {
			spec.DstPort = 5432
		}
	case "pop3":
		if sub, ok := cfg["pop3"].(map[string]interface{}); ok {
			spec.POP3 = &POP3Config{
				Banner:   getString(sub, "banner"),
				Commands: parsePOP3Commands(sub["commands"]),
				Mailbox:  parsePOP3Mailbox(sub["mailbox"]),
			}
		}
		// POP3 defaults to port 110 per RFC 1939 §6. Only override when
		// the user did not specify a dst_port - matches the DNS/FTP/SIP
		// override pattern.
		if _, ok := cfg["dst_port"]; !ok || cfg["dst_port"] == nil {
			spec.DstPort = 110
		}
	case "rdp":
		if sub, ok := cfg["rdp"].(map[string]interface{}); ok {
			spec.RDP = parseRDPConfig(sub)
		}
		if _, ok := cfg["dst_port"]; !ok || cfg["dst_port"] == nil {
			spec.DstPort = 3389
		}
	case "redis":
		if sub, ok := cfg["redis"].(map[string]interface{}); ok {
			spec.Redis = parseRedisConfig(sub)
		}
		if _, ok := cfg["dst_port"]; !ok || cfg["dst_port"] == nil {
			spec.DstPort = 6379
		}
	case "shadowsocks":
		if sub, ok := cfg["shadowsocks"].(map[string]interface{}); ok {
			spec.Shadowsocks = parseShadowsocksConfig(sub)
		}
		// shadowsocks has no canonical port; user must specify.
	case "smtp":
		if sub, ok := cfg["smtp"].(map[string]interface{}); ok {
			spec.SMTP = &SMTPConfig{
				Banner: getString(sub, "banner"),
				Dialog: parseSMTPDialog(sub["dialog"]),
			}
		}
		// SMTP defaults to port 25 (RFC 5321 §3.1). Only override when
		// the user did not specify a dst_port - matches the DNS/FTP
		// pattern. Submission (587) and SMTPS (465) are also valid but
		// the user must set dst_port explicitly for those.
		if _, ok := cfg["dst_port"]; !ok || cfg["dst_port"] == nil {
			spec.DstPort = 25
		}
	case "snmp":
		if sub, ok := cfg["snmp"].(map[string]interface{}); ok {
			spec.SNMP = &SNMPConfig{
				Version:                   uint8(getIntDefault(sub, "version", 1)),
				Community:                 getStringDefault(sub, "community", "public"),
				UserName:                  getString(sub, "user_name"),
				AuthProtocol:              getString(sub, "auth_protocol"),
				AuthPassword:              getString(sub, "auth_password"),
				PrivProtocol:              getString(sub, "priv_protocol"),
				PrivPassword:              getString(sub, "priv_password"),
				AuthoritativeEngineID:     getString(sub, "authoritative_engine_id"),
				AuthoritativeEngineBoots:  getUint32(sub, "authoritative_engine_boots"),
				AuthoritativeEngineTime:   getUint32(sub, "authoritative_engine_time"),
				PDUType:                   uint8(getIntDefault(sub, "pdu_type", 0)),
				RequestID:                 getUint32(sub, "request_id"),
				NonRepeaters:              uint8(getInt(sub, "non_repeaters")),
				MaxRepetitions:            uint8(getIntDefault(sub, "max_repetitions", 1)),
				VarBinds:                  parseSNMPVarBinds(sub["var_binds"]),
				IsResponse:                getBool(sub, "is_response", false),
				ResponseError:             uint8(getInt(sub, "response_error")),
				ResponseErrorIndex:        uint8(getInt(sub, "response_error_index")),
				ResponseValues:            parseSNMPVarBinds(sub["response_values"]),
				PollInterval:              getInt(sub, "poll_interval"),
				RepeatCount:               getInt(sub, "repeat_count"),
				EngineIDOverride:          getString(sub, "engine_id_override"),
				MaxSize:                   getUint32(sub, "max_size"),
				ContextName:               getString(sub, "context_name"),
			}
		}
		// SNMP defaults to port 161 (query) or 162 (trap/inform). Only
		// override when user did not specify dst_port - matches DNS/FTP
		// pattern. The planner chooses 161 vs 162 based on PDUType when
		// dst_port is absent here; if the user set dst_port explicitly,
		// their value wins.
		if _, ok := cfg["dst_port"]; !ok || cfg["dst_port"] == nil {
			spec.DstPort = 161
		}
	case "ssdp":
		if sub, ok := cfg["ssdp"].(map[string]interface{}); ok {
			spec.SSDP = parseSSDPConfig(sub)
		}
		if _, ok := cfg["dst_port"]; !ok || cfg["dst_port"] == nil {
			spec.DstPort = 1900
		}
	case "ssh":
		if sub, ok := cfg["ssh"].(map[string]interface{}); ok {
			spec.SSH = parseSSHConfig(sub)
		}
		if _, ok := cfg["dst_port"]; !ok || cfg["dst_port"] == nil {
			spec.DstPort = 22
		}
	case "syslog":
		if sub, ok := cfg["syslog"].(map[string]interface{}); ok {
			spec.Syslog = &SyslogConfig{
				Facility:       uint8(getIntDefault(sub, "facility", 1)),
				Severity:       uint8(getIntDefault(sub, "severity", 6)),
				Version:        uint8(getIntDefault(sub, "version", 1)),
				Timestamp:      getString(sub, "timestamp"),
				Hostname:       getString(sub, "hostname"),
				AppName:        getString(sub, "app_name"),
				ProcID:         getString(sub, "proc_id"),
				MsgID:          getString(sub, "msg_id"),
				StructuredData: parseSyslogStructuredData(sub["structured_data"]),
				Msg:            getString(sub, "msg"),
				MsgHasBOM:      getBool(sub, "msg_has_bom", false),
				Format:         getStringDefault(sub, "format", "rfc5424"),
				Transport:      getStringDefault(sub, "transport", "udp"),
				TCPFraming:     getStringDefault(sub, "tcp_framing", "octet_counting"),
				Count:          uint32(getIntDefault(sub, "count", 1)),
				SignBlocks:     parseSyslogSignBlocks(sub["sign_blocks"]),
			}
		}
		// Default port depends on transport: udp/tcp=514, tls=6514.
		// Only override when the user did not specify a dst_port.
		if _, ok := cfg["dst_port"]; !ok || cfg["dst_port"] == nil {
			transport := "udp"
			if sub, ok := cfg["syslog"].(map[string]interface{}); ok {
				if t, ok := sub["transport"].(string); ok && t != "" {
					transport = t
				}
			}
			if transport == "tls" {
				spec.DstPort = 6514
			} else {
				spec.DstPort = 514
			}
		}
	case "telnet":
		if sub, ok := cfg["telnet"].(map[string]interface{}); ok {
			spec.Telnet = &TelnetConfig{
				Banner:       getString(sub, "banner"),
				Dialog:       parseTelnetDialog(sub["dialog"]),
				TerminalType: getString(sub, "terminal_type"),
				WindowCols:   getUint16(sub, "window_cols"),
				WindowRows:   getUint16(sub, "window_rows"),
				FileSource:    parseFileSource(sub),
			}
		}
		// Telnet defaults to port 23 (RFC 854). Only override when the
		// user did not specify a dst_port — matches the DNS/FTP override
		// pattern.
		if _, ok := cfg["dst_port"]; !ok || cfg["dst_port"] == nil {
			spec.DstPort = 23
		}
	case "tls":
		if sub, ok := cfg["tls"].(map[string]interface{}); ok {
			spec.TLS = parseTLSConfig(sub)
		}
		if _, ok := cfg["dst_port"]; !ok || cfg["dst_port"] == nil {
			spec.DstPort = 443
		}
	case "vmess":
		if sub, ok := cfg["vmess"].(map[string]interface{}); ok {
			spec.Vmess = parseVmessConfig(sub)
		}
		// vmess has no canonical port; user must specify.
	case "wireguard":
		if sub, ok := cfg["wireguard"].(map[string]interface{}); ok {
			spec.WireGuard = parseWireGuardConfig(sub)
		}
		if _, ok := cfg["dst_port"]; !ok || cfg["dst_port"] == nil {
			spec.DstPort = 51820
		}
	}

	// GroupID: optional strategy for cross-flow ordering. When cfg has
	// "group_id" as a map, unmarshal into StrategyConfig; absent = nil
	// (fall back to 4-tuple hash).
	if gCfg, ok := cfg["group_id"].(map[string]interface{}); ok && gCfg != nil {
		if raw, err := json.Marshal(gCfg); err == nil {
			var g StrategyConfig
			if err := json.Unmarshal(raw, &g); err == nil {
				spec.GroupID = &g
			}
		}
	}

	// InitialSeq backward compat: pre-rename strategies stored this at the
	// top-level cfg. After the rename it lives inside the "tcp" sub-map. We
	// prefer spec.TCP.InitialSeq (set above from the tcp sub-map) and fall
	// back to the top-level "initial_seq" key when TCP is nil or its
	// InitialSeq is 0. This preserves reproducible-ISN configs that still
	// use the legacy top-level location.
	//
	// When creating a new TCPConfig here (no "tcp" sub-map was present),
	// Handshake/Termination default to true so HTTP/FTP/SIP flows still
	// get a proper handshake/teardown -- without this, the zero-value false
	// would skip the SYN handshake and FIN teardown, breaking the flow.
	if v, ok := cfg["initial_seq"]; ok && v != nil {
		legacy := getUint32(cfg, "initial_seq")
		if spec.TCP == nil {
			spec.TCP = &TCPConfig{
				Handshake:   true,
				Termination: true,
				InitialSeq:  legacy,
			}
		} else if spec.TCP.InitialSeq == 0 {
			spec.TCP.InitialSeq = legacy
		}
	}

	// PadMinFrame: optional Ethernet padding toggle. nil (absent) = default
	// ON; explicit true = ON; explicit false = OFF. Presence-checked so
	// user false (don't pad) is honored rather than replaced with the
	// default true.
	if v, ok := cfg["pad_min_frame"]; ok && v != nil {
		if b, ok := v.(bool); ok {
			spec.PadMinFrame = &b
		}
	}

	// SubFlows: generic multi-flow binding (FTP data channel, SIP RTP,
	// SCTP multi-homing). Parsed protocol-independently so any planner
	// can emit sub-flows without its own map[]-decoder. Absent = no
	// sub-flows (the default for every protocol unless the user sets it
	// or the planner injects one internally, e.g. FTP's DataChannel).
	//
	// Two-stage decode: first unmarshal into a typed slice (decodes
	// numeric/most fields), and if that fails fall back to nil. We
	// tolerate individual field decode errors (e.g. Payload field
	// receiving a non-base64 string into []byte) by using a json.RawMessage
	// intermediate and then re-decoding field by field, so one bad field
	// doesn't drop the whole sub-flow.
	if sCfg, ok := cfg["sub_flows"]; ok && sCfg != nil {
		if raw, err := json.Marshal(sCfg); err == nil {
			var subs []SubFlowSpec
			if err := json.Unmarshal(raw, &subs); err == nil {
				spec.SubFlows = subs
			} else {
				// Fallback: decode each entry individually. A sub-flow with
				// an un-decodable field (e.g. Payload that isn't valid base64)
				// still gets its other fields populated; bad fields are left
				// at their zero value.
				var raws []json.RawMessage
				if err := json.Unmarshal(raw, &raws); err == nil {
					for _, r := range raws {
						var sub SubFlowSpec
						_ = json.Unmarshal(r, &sub)
						spec.SubFlows = append(spec.SubFlows, sub)
					}
				}
			}
		}
	}

	// FileSource (protocol-agnostic): parsed unconditionally so any
	// protocol can carry a file_source. Planners that don't consume it
	// simply ignore the field. Per-protocol FileSource fields (set below)
	// take precedence over this top-level one.
	spec.FileSource = parseFileSource(cfg)

	// Per-protocol FileSource overrides. Each lives inside its protocol's
	// sub-map under the "file_source" key. We only set the field when the
	// sub-map is present (parseFileSource returns nil for absent/empty
	// sources, so existing configs that don't use file_source stay
	// zero-value and don't serialize).
	if spec.FTP != nil && spec.FTP.DataChannel != nil {
		if dcFS := parseFileSource(getMap(cfg, "ftp", "data_channel")); dcFS != nil {
			spec.FTP.DataChannel.FileSource = dcFS
		}
	}
	if spec.SIP != nil && spec.SIP.Media != nil {
		if mFS := parseFileSource(getMap(cfg, "sip", "media")); mFS != nil {
			spec.SIP.Media.FileSource = mFS
		}
	}
	if spec.HTTP != nil {
		if hFS := parseFileSource(getMap(cfg, "http")); hFS != nil {
			spec.HTTP.FileSource = hFS
		}
	}
	if spec.ICMP != nil {
		if iFS := parseFileSource(getMap(cfg, "icmp")); iFS != nil {
			spec.ICMP.FileSource = iFS
		}
	}
	if spec.ICMPv6 != nil {
		if i6FS := parseFileSource(getMap(cfg, "icmpv6")); i6FS != nil {
			spec.ICMPv6.FileSource = i6FS
		}
	}
	// SCTP chunks: FileSource parsing is handled inside parseSCTPChunks
	// itself (each chunk is constructed there with its FileSource assigned
	// from the chunk map's "file_source" key). The earlier dispatch loop
	// here walked cfg["sctp"]["chunks"][i] and indexed into
	// spec.SCTP.Chunks[i] — but parseSCTPChunks filters non-map entries,
	// so len(parsed) < len(raw) whenever any entry was a non-map. The
	// length-safety check failed and silently dropped ALL chunk
	// FileSources, including valid ones at aligned indices. Pushing the
	// parse into parseSCTPChunks eliminates the index-aliasing bug.

	// Validate all FileSource instances surfaced above. parseFileSource
	// returns nil for absent/empty sources, so nil-check first. A Validate
	// failure is a user-facing input error and fails the task loudly —
	// silent acceptance of, e.g., Fill.Bytes=-1 would panic make([]byte, n)
	// deep in the planner and produce a confusing stack trace.
	if err := spec.FileSource.Validate(); err != nil {
		spec.ValidationErrors = append(spec.ValidationErrors, err.Error())
	}
	if spec.FTP != nil && spec.FTP.DataChannel != nil {
		if err := spec.FTP.DataChannel.FileSource.Validate(); err != nil {
			spec.ValidationErrors = append(spec.ValidationErrors, err.Error())
		}
	}
	if spec.SIP != nil && spec.SIP.Media != nil {
		if err := spec.SIP.Media.FileSource.Validate(); err != nil {
			spec.ValidationErrors = append(spec.ValidationErrors, err.Error())
		}
	}
	if spec.HTTP != nil {
		if err := spec.HTTP.FileSource.Validate(); err != nil {
			spec.ValidationErrors = append(spec.ValidationErrors, err.Error())
		}
	}
	if spec.ICMP != nil {
		if err := spec.ICMP.FileSource.Validate(); err != nil {
			spec.ValidationErrors = append(spec.ValidationErrors, err.Error())
		}
	}
	if spec.ICMPv6 != nil {
		if err := spec.ICMPv6.FileSource.Validate(); err != nil {
			spec.ValidationErrors = append(spec.ValidationErrors, err.Error())
		}
	}
	if spec.SCTP != nil {
		for i := range spec.SCTP.Chunks {
			if err := spec.SCTP.Chunks[i].FileSource.Validate(); err != nil {
				spec.ValidationErrors = append(spec.ValidationErrors, err.Error())
			}
		}
	}

	return spec
}

// MapToFlowSpec is the exported wrapper around mapToFlowSpec. It exists so
// external test packages (core_test) can exercise the parser without
// duplicating the dispatch logic. Production code continues to call
// mapToFlowSpec directly.
func MapToFlowSpec(cfg map[string]interface{}, protocol string) FlowSpec {
	return mapToFlowSpec(cfg, protocol)
}

// parseFileSource extracts a *FileSource from cfg["file_source"] (a map).
// Returns nil when absent, not a map, or all fields zero — so a config
// without a file_source serializes as nil (no null in JSON output thanks
// to omitempty on the field tags).
//
// The four source kinds (File, Literal, Fill, Random) are parsed
// independently; at most one is expected to be set, but we don't enforce
// that here (priority resolution happens at consume time in PayloadCache).
//
// Numeric coercion: JSON decode produces float64 for numbers (and
// json.Number when UseNumber is set); test map literals produce int. We
// delegate to the package-level toInt (defined in shard_router.go) which
// handles float64/int/int64/string so the parser works identically in
// production and in tests.
func parseFileSource(cfg map[string]interface{}) *filesystem.FileSource {
	src, ok := cfg["file_source"].(map[string]interface{})
	if !ok {
		return nil
	}
	fs := &filesystem.FileSource{}
	if v, ok := src["file"].(string); ok {
		fs.File = v
	}
	if v, ok := src["literal"].(string); ok {
		fs.Literal = v
	}
	if fill, ok := src["fill"].(map[string]interface{}); ok {
		fs.Fill = &filesystem.Fill{
			Byte:  byte(toInt(fill["byte"])),
			Bytes: toInt(fill["bytes"]),
		}
	}
	if r, ok := src["random"].(map[string]interface{}); ok {
		fs.Random = &filesystem.Random{
			MinBytes: toInt(r["min_bytes"]),
			MaxBytes: toInt(r["max_bytes"]),
			Seed:     int64(toInt(r["seed"])),
		}
	}
	// If all fields are zero, treat as nil. This prevents a non-nil pointer
	// to a zero-value FileSource from being serialized as "file_source": {}
	// and from confusing planners that test `if spec.FileSource != nil`.
	if fs.File == "" && fs.Literal == "" && fs.Fill == nil && fs.Random == nil {
		return nil
	}
	return fs
}

// parseFileSourceField reads a "file_source" sub-map from the given map and
// delegates to parseFileSource for the actual field parsing. Used when the
// caller already has the protocol-specific sub-map (e.g. inside an IMAP
// command entry) rather than the top-level cfg.
func parseFileSourceField(m map[string]interface{}) *filesystem.FileSource {
	src, ok := m["file_source"].(map[string]interface{})
	if !ok {
		return nil
	}
	fs := &filesystem.FileSource{}
	if v, ok := src["file"].(string); ok {
		fs.File = v
	}
	if v, ok := src["literal"].(string); ok {
		fs.Literal = v
	}
	if fill, ok := src["fill"].(map[string]interface{}); ok {
		fs.Fill = &filesystem.Fill{
			Byte:  byte(toInt(fill["byte"])),
			Bytes: toInt(fill["bytes"]),
		}
	}
	if r, ok := src["random"].(map[string]interface{}); ok {
		fs.Random = &filesystem.Random{
			MinBytes: toInt(r["min_bytes"]),
			MaxBytes: toInt(r["max_bytes"]),
			Seed:     int64(toInt(r["seed"])),
		}
	}
	if fs.File == "" && fs.Literal == "" && fs.Fill == nil && fs.Random == nil {
		return nil
	}
	return fs
}

// getMap walks cfg through a chain of keys, returning the nested map at the
// end of the chain or nil if any intermediate is missing or not a map. It
// never panics on missing keys or nil maps.
func getMap(cfg map[string]interface{}, keys ...string) map[string]interface{} {
	var cur map[string]interface{} = cfg
	for _, k := range keys {
		if cur == nil {
			return nil
		}
		next, ok := cur[k].(map[string]interface{})
		if !ok {
			return nil
		}
		cur = next
	}
	return cur
}

func formatBPS(val float64) string {
	switch {
	case val >= 1e9:
		return fmt.Sprintf("%.0fG", val/1e9)
	case val >= 1e6:
		return fmt.Sprintf("%.0fM", val/1e6)
	case val >= 1e3:
		return fmt.Sprintf("%.0fk", val/1e3)
	default:
		return fmt.Sprintf("%.0f", val)
	}
}

// parseICMPPattern converts the JSON-decoded "pattern" value (an array of
// step objects) into a []ICMPStep. Returns nil for absent/non-array input
// so the planner falls back to the single-ping path. Each step inherits
// Type/Code defaults from the parent config when absent (Type=8, Code=0);
// Sequence defaults to step index+1 when 0 (per RFC 792 ping session
// semantics: Identifier groups, Sequence increments per ping).
func parseICMPPattern(v interface{}) []ICMPStep {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]ICMPStep, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		typ := uint8(getIntDefault(m, "type", 8))
		code := uint8(getIntDefault(m, "code", 0))
		seq := uint16(getInt(m, "sequence"))
		if seq == 0 {
			seq = uint16(len(out) + 1)
		}
		data := []byte(getStringDefault(m, "data", "ping"))
		out = append(out, ICMPStep{
			Type:     typ,
			Code:     code,
			Sequence: seq,
			Data:     data,
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// parseFTPCommands converts the JSON-decoded "commands" value (an array
// of {cmd, response} objects) into a []FTPCommand. Returns nil for
// absent/non-array input — the planner then emits only TCP handshake +
// teardown (an empty FTP session, which is a valid degenerate test).
func parseFTPCommands(v interface{}) []FTPCommand {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]FTPCommand, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		out = append(out, FTPCommand{
			Cmd:             getString(m, "cmd"),
			Response:        getString(m, "response"),
			EmitDataChannel: getBool(m, "emit_data_channel", false),
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// parsePOP3Commands converts the JSON-decoded "commands" value (an array
// of {cmd, response, multiline, emit_mail_drop, msg_num} objects) into a
// []POP3Command. Returns nil for absent/non-array input - the planner then
// emits only TCP handshake + teardown (an empty POP3 session, which is a
// valid degenerate test). Mirrors parseFTPCommands.
func parsePOP3Commands(v interface{}) []POP3Command {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]POP3Command, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		out = append(out, POP3Command{
			Cmd:          getString(m, "cmd"),
			Response:     getString(m, "response"),
			Multiline:    getBool(m, "multiline", false),
			EmitMailDrop: getBool(m, "emit_mail_drop", false),
			MsgNum:       getUint32(m, "msg_num"),
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// parsePOP3Mailbox converts the JSON-decoded "mailbox" sub-map into a
// *POP3Mailbox. Returns nil for absent/non-map input - the planner then
// cannot synthesize RETR responses (EmitMailDrop=true commands will fail
// Validate). Mirrors parseFTPDataChannel.
func parsePOP3Mailbox(v interface{}) *POP3Mailbox {
	m, ok := v.(map[string]interface{})
	if !ok || m == nil {
		return nil
	}
	mb := &POP3Mailbox{}
	if msgs, ok := m["messages"].([]interface{}); ok {
		for _, item := range msgs {
			mi, ok := item.(map[string]interface{})
			if !ok {
				continue
			}
			msg := POP3Message{
				UID:  getString(mi, "uid"),
				Body: getString(mi, "body"),
				Size: getUint32(mi, "size"),
			}
			if headers, ok := mi["headers"].([]interface{}); ok {
				for _, h := range headers {
					if s, ok := h.(string); ok {
						msg.Headers = append(msg.Headers, s)
					}
				}
			}
			mb.Messages = append(mb.Messages, msg)
		}
	}
	if len(mb.Messages) == 0 {
		return nil
	}
	return mb
}

// parseSMTPDialog converts the JSON-decoded "dialog" value (an array of
// {cmd, response, direction} objects) into a []SMTPCommand. Returns nil
// for absent/non-array input - the planner then emits a default SMTP
// session per design_smtp.md §6.6. Mirrors parsePOP3Commands.
func parseSMTPDialog(v interface{}) []SMTPCommand {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]SMTPCommand, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		out = append(out, SMTPCommand{
			Cmd:       getString(m, "cmd"),
			Response:  getString(m, "response"),
			Direction: getString(m, "direction"),
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// parseFTPDataChannel converts the JSON-decoded "data_channel" sub-map
// into an *FTPDataChannel. Returns nil for absent/non-map input — the
// planner then emits only the control channel (the default for backward
// compatibility with pre-data-channel specs).
func parseFTPDataChannel(v interface{}) *FTPDataChannel {
	m, ok := v.(map[string]interface{})
	if !ok || m == nil {
		return nil
	}
	dc := &FTPDataChannel{
		Mode:       getString(m, "mode"),
		SrcPort:    getUint16(m, "src_port"),
		DstPort:    getUint16(m, "dst_port"),
		Direction:  getString(m, "direction"),
		Payload:    getString(m, "payload"),
		PayloadB64: getString(m, "payload_b64"),
		MSS:        getUint16(m, "mss"),
	}
	// Defaults: Mode="passive", Direction="down" — matches the most
	// common FTP test shape (PASV + RETR download). Zero-value check
	// leaves room for the planner to derive ports.
	if dc.Mode == "" {
		dc.Mode = "passive"
	}
	if dc.Direction == "" {
		dc.Direction = "down"
	}
	return dc
}

// parseSSHConfig converts the JSON-decoded "ssh" sub-map into an *SSHConfig.
// Returns nil for absent/non-map input. Empty string fields are left empty so
// the planner can apply its own defaults.
func parseSSHConfig(m map[string]interface{}) *SSHConfig {
	if m == nil {
		return nil
	}
	return &SSHConfig{
		ServerVersion:         getString(m, "server_version"),
		ClientVersion:         getString(m, "client_version"),
		KexAlgorithms:         getString(m, "kex_algorithms"),
		HostKeyAlgorithms:     getString(m, "host_key_algorithms"),
		EncryptionAlgorithms:  getString(m, "encryption_algorithms"),
		MACAlgorithms:         getString(m, "mac_algorithms"),
		CompressionAlgorithms: getString(m, "compression_algorithms"),
		KEX:                   getString(m, "kex"),
		AuthMethods:           parseSSHMessages(m["auth_methods"]),
		ExtInfo:               getBool(m, "ext_info", false),
		Channels:              parseChannelEntries(m["channels"]),
		RekeyAfter:            getUint32(m, "rekey_after"),
		DisconnectOnClose:     getBool(m, "disconnect_on_close", false),
	}
}

// parseSSHMessages converts the JSON-decoded "auth_methods" array into a
// []SSHMessage. Returns nil for absent/non-array input.
func parseSSHMessages(v interface{}) []SSHMessage {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]SSHMessage, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		msg := SSHMessage{
			Type:                       getString(m, "type"),
			Direction:                  getString(m, "direction"),
			ServiceName:                getString(m, "service_name"),
			MethodName:                 getString(m, "method_name"),
			Username:                   getString(m, "username"),
			Password:                   getString(m, "password"),
			HasPasswordChange:          getBool(m, "has_password_change", false),
			NewPassword:                getString(m, "new_password"),
			PublicKeyAlgorithm:         getString(m, "public_key_algorithm"),
			PublicKeyBlob:              getByteSlice(m, "public_key_blob"),
			HasSignature:               getBool(m, "has_signature", false),
			Signature:                  getByteSlice(m, "signature"),
			Submethods:                 getString(m, "submethods"),
			Prompt:                     getString(m, "prompt"),
			Response:                   getString(m, "response"),
			AuthMethodsThatCanContinue: getString(m, "auth_methods_that_can_continue"),
			PartialSuccess:             getBool(m, "partial_success", false),
			Banner:                     getString(m, "banner"),
			LanguageTag:                getString(m, "language_tag"),
			Name:                       getString(m, "name"),
			Instruction:                getString(m, "instruction"),
			PromptCount:                getUint32(m, "prompt_count"),
			Prompts:                    getString(m, "prompts"),
			Echo:                       getBool(m, "echo", false),
			NumResponses:               getUint32(m, "num_responses"),
			Responses:                  getString(m, "responses"),
			ReasonCode:                 getUint32(m, "reason_code"),
			Description:                getString(m, "description"),
			ReceiveSeq:                 getUint32(m, "receive_seq"),
			AlwaysDisplay:              getBool(m, "always_display", false),
			Message:                    getString(m, "message"),
			Data:                       getByteSlice(m, "data"),
		}
		out = append(out, msg)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// parseChannelEntries converts the JSON-decoded "channels" array into a
// []ChannelEntry. Returns nil for absent/non-array input.
func parseChannelEntries(v interface{}) []ChannelEntry {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]ChannelEntry, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		entry := ChannelEntry{
			Type:              getString(m, "type"),
			Direction:         getString(m, "direction"),
			SenderChannel:     getUint32(m, "sender_channel"),
			RecipientChannel:  getUint32(m, "recipient_channel"),
			ChannelType:       getString(m, "channel_type"),
			InitialWindowSize: getUint32(m, "initial_window_size"),
			MaximumPacketSize: getUint32(m, "maximum_packet_size"),
			DestHost:          getString(m, "dest_host"),
			DestPort:          getUint32(m, "dest_port"),
			OriginatorIP:      getString(m, "originator_ip"),
			OriginatorPort:    getUint32(m, "originator_port"),
			RequestType:       getString(m, "request_type"),
			WantReply:         getBool(m, "want_reply", false),
			Term:              getString(m, "term"),
			WidthChars:        getUint32(m, "width_chars"),
			HeightRows:        getUint32(m, "height_rows"),
			WidthPixels:       getUint32(m, "width_pixels"),
			HeightPixels:      getUint32(m, "height_pixels"),
			TTYModes:          getByteSlice(m, "tty_modes"),
			Command:           getString(m, "command"),
			EnvVarName:        getString(m, "env_var_name"),
			EnvVarValue:       getString(m, "env_var_value"),
			SubsystemName:     getString(m, "subsystem_name"),
			SignalName:        getString(m, "signal_name"),
			ExitStatus:        getUint32(m, "exit_status"),
			Data:              getByteSlice(m, "data"),
			DataTypeCode:      getUint32(m, "data_type_code"),
			BytesToAdd:        getUint32(m, "bytes_to_add"),
			OpenReasonCode:    getUint32(m, "open_reason_code"),
			OpenReasonText:    getString(m, "open_reason_text"),
			GlobalRequestName: getString(m, "global_request_name"),
			Address:           getString(m, "address"),
			Port:              getUint32(m, "port"),
			X11AuthProtocol:   getString(m, "x11_auth_protocol"),
			X11AuthCookie:     getByteSlice(m, "x11_auth_cookie"),
			X11ScreenNumber:   getUint32(m, "x11_screen_number"),
			SingleConnection:  getBool(m, "single_connection", false),
		}
		out = append(out, entry)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// parseDHCPConfig converts the JSON-decoded "dhcp" sub-map into a
// *DHCPConfig. Returns nil for absent/non-map input. Each field maps to a
// DHCPConfig struct field; per-message overrides live inside parseDHCPMessages.
// Default field inheritance (DefaultClientIP, DefaultLeaseTime, etc.) is
// applied by the planner at emit time when message-level overrides are empty.
func parseDHCPConfig(m map[string]interface{}) *DHCPConfig {
	if m == nil {
		return nil
	}
	cfg := &DHCPConfig{
		Role:               getString(m, "role"),
		Xid:                 getUint32(m, "xid"),
		Messages:            parseDHCPMessages(m["messages"]),
		ClientMAC:           getString(m, "client_mac"),
		HType:               uint8(getInt(m, "h_type")),
		HLen:                uint8(getInt(m, "h_len")),
		BroadcastFlag:       getBool(m, "broadcast_flag", false),
		Secs:                getUint16(m, "secs"),
		Sname:               getString(m, "sname"),
		File:                getString(m, "file"),
		DefaultClientIP:     getString(m, "default_client_ip"),
		DefaultYourIP:       getString(m, "default_your_ip"),
		DefaultServerIP:     getString(m, "default_server_ip"),
		DefaultRelayAgentIP: getString(m, "default_relay_agent_ip"),
		DefaultServerIdentifier: getString(m, "default_server_identifier"),
		DefaultLeaseTime:    getUint32(m, "default_lease_time"),
		DefaultT1:           getUint32(m, "default_t1"),
		DefaultT2:           getUint32(m, "default_t2"),
		DefaultSubnetMask:   getString(m, "default_subnet_mask"),
		DefaultRouters:      getStringSlice(m, "default_routers"),
		DefaultDNS:          getStringSlice(m, "default_dns"),
		DefaultDomainName:   getString(m, "default_domain_name"),
		DefaultHostname:     getString(m, "default_hostname"),
		DefaultDomainSearch: getStringSlice(m, "default_domain_search"),
		DefaultClientID:     getByteSlice(m, "default_client_id"),
		DefaultRequestedIP:  getString(m, "default_requested_ip"),
		DefaultParamRequestList: getUint8Slice(m, "default_param_request_list"),
		DefaultVendorClass:  getString(m, "default_vendor_class"),
		DefaultRelayAgentInfo: getByteSlice(m, "default_relay_agent_info"),
	}
	return cfg
}

// parseDHCPMessages converts the "messages" array into []DHCPMessage. Each
// message carries MessageType + per-message overrides; empty fields inherit
// from DHCPConfig defaults at emit time.
func parseDHCPMessages(v interface{}) []DHCPMessage {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]DHCPMessage, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		msg := DHCPMessage{
			Type:              uint8(getInt(m, "type")),
			Direction:         getString(m, "direction"),
			ClientIP:          getString(m, "client_ip"),
			YourIP:            getString(m, "your_ip"),
			ServerIP:          getString(m, "server_ip"),
			RelayAgentIP:      getString(m, "relay_agent_ip"),
			Hops:              uint8(getInt(m, "hops")),
			ServerIdentifier:  getString(m, "server_identifier"),
			LeaseTime:         getUint32(m, "lease_time"),
			T1:                getUint32(m, "t1"),
			T2:                getUint32(m, "t2"),
			SubnetMask:        getString(m, "subnet_mask"),
			Routers:           getStringSlice(m, "routers"),
			DNS:               getStringSlice(m, "dns"),
			DomainName:        getString(m, "domain_name"),
			Hostname:          getString(m, "hostname"),
			DomainSearch:      getStringSlice(m, "domain_search"),
			ClientID:          getByteSlice(m, "client_id"),
			RequestedIP:       getString(m, "requested_ip"),
			ParamRequestList:  getUint8Slice(m, "param_request_list"),
			VendorClass:       getString(m, "vendor_class"),
			RelayAgentInfo:    getByteSlice(m, "relay_agent_info"),
			ExtraOptions:      parseDHCPOptions(m["extra_options"]),
			Broadcast:         getBoolPtr(m, "broadcast"),
		}
		out = append(out, msg)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// parseDHCPOptions converts the "extra_options" array into []DHCPOption.
func parseDHCPOptions(v interface{}) []DHCPOption {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]DHCPOption, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		out = append(out, DHCPOption{
			Code: uint8(getInt(m, "code")),
			Data: getByteSlice(m, "data"),
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// parseDHCPv6Config converts the JSON-decoded "dhcpv6" sub-map into a
// *DHCPv6Config. Returns nil for absent/non-map input.
func parseDHCPv6Config(m map[string]interface{}) *DHCPv6Config {
	if m == nil {
		return nil
	}
	cfg := &DHCPv6Config{
		Messages:     parseDHCPv6Messages(m["messages"]),
		ClientDUID:    parseDUID(m["client_duid"]),
		ServerDUID:    parseDUID(m["server_duid"]),
		RelayConfig:   parseDHCPv6RelayConfig(m["relay_config"]),
	}
	return cfg
}

// parseDHCPv6Messages converts the "messages" array into []DHCPv6Message.
func parseDHCPv6Messages(v interface{}) []DHCPv6Message {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]DHCPv6Message, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		var txID [3]byte
		if t := getByteSlice(m, "transaction_id"); len(t) >= 3 {
			copy(txID[:], t[:3])
		}
		msg := DHCPv6Message{
			MsgType:        uint8(getInt(m, "msg_type")),
			TransactionID:  txID,
			Direction:      getString(m, "direction"),
			Options:        parseDHCPv6Options(m["options"]),
			RelayFields:    parseDHCPv6RelayFields(m["relay_fields"]),
		}
		out = append(out, msg)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// parseDUID converts a DUID sub-map into *DUID.
func parseDUID(v interface{}) *DUID {
	m, ok := v.(map[string]interface{})
	if !ok || m == nil {
		return nil
	}
	return &DUID{
		Type:            uint8(getInt(m, "type")),
		HardwareType:    getUint16(m, "hardware_type"),
		Time:            getUint32(m, "time"),
		EnterpriseNum:   getUint32(m, "enterprise_num"),
		VendorSpecific:  getByteSlice(m, "vendor_specific"),
		LinkLayerAddr:   getString(m, "link_layer_addr"),
	}
}

// parseDHCPv6Options converts an array of {code, data} into []DHCPv6Option.
func parseDHCPv6Options(v interface{}) []DHCPv6Option {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]DHCPv6Option, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		out = append(out, DHCPv6Option{
			Code: getUint16(m, "code"),
			Data: getByteSlice(m, "data"),
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// parseDHCPv6RelayFields converts a relay_fields sub-map into *RelayFields.
func parseDHCPv6RelayFields(v interface{}) *RelayFields {
	m, ok := v.(map[string]interface{})
	if !ok || m == nil {
		return nil
	}
	return &RelayFields{
		HopCount:     uint8(getInt(m, "hop_count")),
		LinkAddress:  getString(m, "link_address"),
		PeerAddress:  getString(m, "peer_address"),
	}
}

// parseDHCPv6RelayConfig converts a relay_config sub-map into *RelayConfig.
func parseDHCPv6RelayConfig(v interface{}) *RelayConfig {
	m, ok := v.(map[string]interface{})
	if !ok || m == nil {
		return nil
	}
	return &RelayConfig{
		RelayIP:           getString(m, "relay_ip"),
		RelayMAC:          getString(m, "relay_mac"),
		HopCount:          uint8(getInt(m, "hop_count")),
		InterfaceID:       getByteSlice(m, "interface_id"),
		IncludeClientMAC:  getBool(m, "include_client_mac", false),
	}
}

// parseGRPCConfig converts the JSON-decoded "grpc" sub-map into a
// *GRPCConfig. Returns nil for absent/non-map input. Request/Response
// messages accept both raw-bytes arrays ([][]byte) and base64 strings
// ([]string); the planner decodes base64 at Plan time.
func parseGRPCConfig(m map[string]interface{}) *GRPCConfig {
	if m == nil {
		return nil
	}
	cfg := &GRPCConfig{
		Service:               getString(m, "service"),
		Method:                getString(m, "method"),
		Authority:             getString(m, "authority"),
		Scheme:                getString(m, "scheme"),
		CallType:              getString(m, "call_type"),
		RequestMessages:       getByteSlices(m, "request_messages"),
		RequestMessagesB64:    getStringSlice(m, "request_messages_b64"),
		ResponseMessages:      getByteSlices(m, "response_messages"),
		ResponseMessagesB64:   getStringSlice(m, "response_messages_b64"),
		ResponseStatus:        getInt(m, "response_status"),
		ResponseMessage:       getString(m, "response_message"),
		Timeout:               getString(m, "timeout"),
		Encoding:              getString(m, "encoding"),
		AcceptEncoding:        getString(m, "accept_encoding"),
		Metadata:              getStringMap(m, "metadata"),
		UserAgent:             getString(m, "user_agent"),
		MaxFrameSize:          getUint32(m, "max_frame_size"),
		InitialWindow:         getUint32(m, "initial_window"),
		MaxConcurrentStreams:   getUint32(m, "max_concurrent_streams"),
		HeaderTableSize:       getUint32(m, "header_table_size"),
		Pings:                 parseGRPCPingConfig(m["pings"]),
		CancelAfter:           getInt(m, "cancel_after"),
		GoAwayAfter:           getBool(m, "go_away_after", false),
		Calls:                 parseGRPCCalls(m["calls"]),
		FileSource:            parseFileSourceField(m),
	}
	return cfg
}

// parseGRPCPingConfig converts the "pings" sub-map into *GRPCPingConfig.
func parseGRPCPingConfig(v interface{}) *GRPCPingConfig {
	m, ok := v.(map[string]interface{})
	if !ok || m == nil {
		return nil
	}
	var opaque [8]byte
	if b := getByteSlice(m, "opaque_data"); len(b) >= 8 {
		copy(opaque[:], b[:8])
	}
	return &GRPCPingConfig{
		IntervalMs:  getInt(m, "interval_ms"),
		Count:        getInt(m, "count"),
		OpaqueData:   opaque,
	}
}

// parseGRPCCalls converts the "calls" array into []GRPCCall.
func parseGRPCCalls(v interface{}) []GRPCCall {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]GRPCCall, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		out = append(out, GRPCCall{
			Service:          getString(m, "service"),
			Method:           getString(m, "method"),
			CallType:         getString(m, "call_type"),
			RequestMessages:  getByteSlices(m, "request_messages"),
			ResponseMessages: getByteSlices(m, "response_messages"),
			ResponseStatus:   getInt(m, "response_status"),
			ResponseMessage:  getString(m, "response_message"),
			Metadata:         getStringMap(m, "metadata"),
			Timeout:          getString(m, "timeout"),
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// parseIKEConfig converts the JSON-decoded "ike" sub-map into *IKEConfig.
func parseIKEConfig(m map[string]interface{}) *IKEConfig {
	if m == nil {
		return nil
	}
	cfg := &IKEConfig{
		VersionMajor:            uint8(getIntDefault(m, "version_major", 2)),
		VersionMinor:            uint8(getIntDefault(m, "version_minor", 0)),
		InitiatorSPI:            getUint64(m, "initiator_spi"),
		ResponderSPI:            getUint64(m, "responder_spi"),
		StartMessageID:          getUint32(m, "start_message_id"),
		Role:                    getString(m, "role"),
		Strict:                  getBool(m, "strict", false),
		FaultInjection:          getBool(m, "fault_injection", false),
		Messages:                parseIKEMessages(m["messages"]),
		Scenario:                getString(m, "scenario"),
		DefaultProposal:         parseIKEProposal(m["default_proposal"]),
		DefaultDHGroup:          getUint16(m, "default_dh_group"),
		DefaultNonceSize:        getUint16(m, "default_nonce_size"),
		DefaultAuthMethod:       uint8(getInt(m, "default_auth_method")),
		AllowNullAuth:           getBool(m, "allow_null_auth", false),
		EAPOnly:                 getBool(m, "eap_only", false),
		FragmentationSupported:  getBool(m, "fragmentation_supported", false),
		FragmentThreshold:       getUint16(m, "fragment_threshold"),
		ChildSAs:                parseIKEChildSAs(m["child_sas"]),
		DPDCount:                getInt(m, "dpd_count"),
		RetransmitCount:         getInt(m, "retransmit_count"),
		EncryptMode:             getString(m, "encrypt_mode"),
		OpaqueKeySeed:           getUint64(m, "opaque_key_seed"),
	}
	return cfg
}

// parseIKEMessages converts the "messages" array into []IKEMessage.
func parseIKEMessages(v interface{}) []IKEMessage {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]IKEMessage, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		msg := IKEMessage{
			Direction:              getString(m, "direction"),
			ExchangeType:            uint8(getInt(m, "exchange_type")),
			IsResponse:              getBool(m, "is_response", false),
			FromOriginalInitiator:  getBool(m, "from_original_initiator", false),
			HigherVersionSupported: getBool(m, "higher_version_supported", false),
			MessageID:              getUint32Ptr(m, "message_id"),
			InitiatorSPI:           getUint64Ptr(m, "initiator_spi"),
			ResponderSPI:           getUint64Ptr(m, "responder_spi"),
			Payloads:               parseIKEPayloads(m["payloads"]),
			Encrypted:              parseIKEEncryptedBody(m["encrypted"]),
			Retransmit:             getInt(m, "retransmit"),
			DelayMillis:            getInt(m, "delay_ms"),
			RawLengthOverride:      getUint32Ptr(m, "raw_length_override"),
			RawNextPayloadOverride: getUint8Ptr(m, "raw_next_payload_override"),
			RawFlagsOverride:       getUint8Ptr(m, "raw_flags_override"),
		}
		out = append(out, msg)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// parseIKEPayloads converts the "payloads" array into []IKEPayload.
func parseIKEPayloads(v interface{}) []IKEPayload {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]IKEPayload, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		pl := IKEPayload{
			Type:                     uint8(getInt(m, "type")),
			Critical:                 getBool(m, "critical", false),
			SA:                       parseIKESA(m["sa"]),
			KE:                       parseIKEKE(m["ke"]),
			ID:                       parseIKEIdentity(m["id"]),
			Certificate:              parseIKECertificate(m["certificate"]),
			CertificateRequest:       parseIKECertificateRequest(m["certificate_request"]),
			Auth:                     parseIKEAuth(m["auth"]),
			Nonce:                    getByteSlice(m, "nonce"),
			Notify:                   parseIKENotify(m["notify"]),
			Delete:                   parseIKEDelete(m["delete"]),
			VendorID:                 getByteSlice(m, "vendor_id"),
			TrafficSelectors:         parseIKETrafficSelectors(m["traffic_selectors"]),
			Config:                   parseIKEConfiguration(m["config"]),
			EAP:                      parseIKEEAP(m["eap"]),
			Fragment:                 parseIKEFragment(m["fragment"]),
			Raw:                      getByteSlice(m, "raw"),
			RawLengthOverride:        getUint16Ptr(m, "raw_length_override"),
			RawNextPayloadOverride:   getUint8Ptr(m, "raw_next_payload_override"),
		}
		out = append(out, pl)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func parseIKEProposal(v interface{}) *IKEProposal {
	m, ok := v.(map[string]interface{})
	if !ok || m == nil {
		return nil
	}
	return &IKEProposal{
		Number:     uint8(getInt(m, "number")),
		ProtocolID: uint8(getInt(m, "protocol_id")),
		SPI:        getByteSlice(m, "spi"),
		Transforms: parseIKETransforms(m["transforms"]),
	}
}

func parseIKETransforms(v interface{}) []IKETransform {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]IKETransform, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		out = append(out, IKETransform{
			Type:            uint8(getInt(m, "type")),
			ID:              getUint16(m, "id"),
			KeyLengthBits:   getUint16(m, "key_length_bits"),
			RawAttributes:   getByteSlice(m, "raw_attributes"),
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func parseIKESA(v interface{}) *IKESA {
	m, ok := v.(map[string]interface{})
	if !ok || m == nil {
		return nil
	}
	return &IKESA{
		Proposals: parseIKEProposals(m["proposals"]),
	}
}

func parseIKEProposals(v interface{}) []IKEProposal {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]IKEProposal, 0, len(arr))
	for _, item := range arr {
		if p := parseIKEProposal(item); p != nil {
			out = append(out, *p)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func parseIKEKE(v interface{}) *IKEKE {
	m, ok := v.(map[string]interface{})
	if !ok || m == nil {
		return nil
	}
	return &IKEKE{
		DHGroup:  getUint16(m, "dh_group"),
		KeyData:  getByteSlice(m, "key_data"),
	}
}

func parseIKEIdentity(v interface{}) *IKEIdentity {
	m, ok := v.(map[string]interface{})
	if !ok || m == nil {
		return nil
	}
	return &IKEIdentity{
		IDType: uint8(getInt(m, "id_type")),
		Data:   getByteSlice(m, "data"),
	}
}

func parseIKECertificate(v interface{}) *IKECertificate {
	m, ok := v.(map[string]interface{})
	if !ok || m == nil {
		return nil
	}
	return &IKECertificate{
		Encoding: uint8(getInt(m, "encoding")),
		Data:     getByteSlice(m, "data"),
	}
}

func parseIKECertificateRequest(v interface{}) *IKECertificateRequest {
	m, ok := v.(map[string]interface{})
	if !ok || m == nil {
		return nil
	}
	return &IKECertificateRequest{
		Encoding: uint8(getInt(m, "encoding")),
		CAs:      getByteSlices(m, "cas"),
	}
}

func parseIKEAuth(v interface{}) *IKEAuth {
	m, ok := v.(map[string]interface{})
	if !ok || m == nil {
		return nil
	}
	return &IKEAuth{
		Method: uint8(getInt(m, "method")),
		Data:   getByteSlice(m, "data"),
	}
}

func parseIKENotify(v interface{}) *IKENotify {
	m, ok := v.(map[string]interface{})
	if !ok || m == nil {
		return nil
	}
	return &IKENotify{
		ProtocolID:  uint8(getInt(m, "protocol_id")),
		SPI:         getByteSlice(m, "spi"),
		MessageType: getUint16(m, "message_type"),
		Data:        getByteSlice(m, "data"),
	}
}

func parseIKEDelete(v interface{}) *IKEDelete {
	m, ok := v.(map[string]interface{})
	if !ok || m == nil {
		return nil
	}
	return &IKEDelete{
		ProtocolID: uint8(getInt(m, "protocol_id")),
		SPISize:    uint8(getInt(m, "spi_size")),
		SPIs:       getByteSlices(m, "spis"),
	}
}

func parseIKETrafficSelectors(v interface{}) []IKETrafficSelector {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]IKETrafficSelector, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		out = append(out, IKETrafficSelector{
			TSType:        uint8(getInt(m, "ts_type")),
			IPProtocolID:  uint8(getInt(m, "ip_protocol_id")),
			StartPort:     getUint16(m, "start_port"),
			EndPort:       getUint16(m, "end_port"),
			StartAddress:  getByteSlice(m, "start_address"),
			EndAddress:    getByteSlice(m, "end_address"),
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func parseIKEConfiguration(v interface{}) *IKEConfiguration {
	m, ok := v.(map[string]interface{})
	if !ok || m == nil {
		return nil
	}
	return &IKEConfiguration{
		CFGType:    uint8(getInt(m, "cfg_type")),
		Attributes: parseIKEConfigAttributes(m["attributes"]),
	}
}

func parseIKEConfigAttributes(v interface{}) []IKEConfigAttribute {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]IKEConfigAttribute, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		out = append(out, IKEConfigAttribute{
			Type:  getUint16(m, "type"),
			Value: getByteSlice(m, "value"),
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func parseIKEEAP(v interface{}) *IKEEAP {
	m, ok := v.(map[string]interface{})
	if !ok || m == nil {
		return nil
	}
	return &IKEEAP{
		Code:        uint8(getInt(m, "code")),
		Identifier:  uint8(getInt(m, "identifier")),
		Type:        getUint8Ptr(m, "type"),
		Data:        getByteSlice(m, "data"),
	}
}

func parseIKEEncryptedBody(v interface{}) *IKEEncryptedBody {
	m, ok := v.(map[string]interface{})
	if !ok || m == nil {
		return nil
	}
	return &IKEEncryptedBody{
		InnerPayloads: parseIKEPayloads(m["inner_payloads"]),
		OpaqueData:    getByteSlice(m, "opaque_data"),
		IVLength:      getUint16(m, "iv_length"),
		ICVLength:     getUint16(m, "icv_length"),
		PadTo:         getUint16(m, "pad_to"),
	}
}

func parseIKEFragment(v interface{}) *IKEFragment {
	m, ok := v.(map[string]interface{})
	if !ok || m == nil {
		return nil
	}
	return &IKEFragment{
		FragmentNumber: getUint16(m, "fragment_number"),
		TotalFragments: getUint16(m, "total_fragments"),
		Data:           getByteSlice(m, "data"),
	}
}

func parseIKEChildSAs(v interface{}) []IKEChildSA {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]IKEChildSA, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		out = append(out, IKEChildSA{
			Proposal:     parseIKEProposal(m["proposal"]),
			TSi:          parseIKETrafficSelectors(m["ts_i"]),
			TSr:          parseIKETrafficSelectors(m["ts_r"]),
			EmitSubFlow:  getBool(m, "emit_sub_flow", false),
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// parseIKENATTConfig converts the JSON-decoded "ike_nat_t" sub-map into
// *IKENATTConfig. Returns nil for absent/non-map input.
func parseIKENATTConfig(m map[string]interface{}) *IKENATTConfig {
	if m == nil {
		return nil
	}
	cfg := &IKENATTConfig{
		InitiatorSPI:         getUint64(m, "initiator_spi"),
		ResponderSPI:         getUint64(m, "responder_spi"),
		NATDetection:         getBool(m, "nat_detection", false),
		NATDetectedOnSource:  getBool(m, "nat_detected_on_source", false),
		NATDetectedOnDest:    getBool(m, "nat_detected_on_dest", false),
		PortFloat:            getBool(m, "port_float", false),
		UDPEncapESP:          getBool(m, "udp_encap_esp", false),
		Keepalive:            parseNATKeepaliveConfig(m["keepalive"]),
		Retransmit:           parseRetransmitConfig(m["retransmit"]),
		Dialog:               parseIKENATTMessages(m["dialog"]),
		ChildSA:              parseESPChildSAConfig(m["child_sa"]),
	}
	return cfg
}

func parseNATKeepaliveConfig(v interface{}) *NATKeepaliveConfig {
	m, ok := v.(map[string]interface{})
	if !ok || m == nil {
		return nil
	}
	return &NATKeepaliveConfig{
		Interval:  getInt(m, "interval"),
		Count:     getInt(m, "count"),
		Direction: getString(m, "direction"),
	}
}

func parseRetransmitConfig(v interface{}) *RetransmitConfig {
	m, ok := v.(map[string]interface{})
	if !ok || m == nil {
		return nil
	}
	return &RetransmitConfig{
		Timeout:        getInt(m, "timeout"),
		MaxRetransmits: getInt(m, "max_retransmits"),
		Backoff:        getFloatDefault(m, "backoff", 0),
	}
}

func parseIKENATTMessages(v interface{}) []IKENATTMessage {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]IKENATTMessage, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		out = append(out, IKENATTMessage{
			Direction:    getString(m, "direction"),
			ExchangeType: uint8(getInt(m, "exchange_type")),
			MessageID:    getUint32(m, "message_id"),
			Payloads:     parseIKENATTPayloads(m["payloads"]),
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func parseIKENATTPayloads(v interface{}) []IKENATTPayload {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]IKENATTPayload, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		out = append(out, IKENATTPayload{
			Type:    uint8(getInt(m, "type")),
			SA:      parseIKESA(m["sa"]),
			KE:      parseIKEKE(m["ke"]),
			Nonce:   getByteSlice(m, "nonce"),
			Notify:  parseNotifyPayload(m["notify"]),
			Raw:     getByteSlice(m, "raw"),
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func parseNotifyPayload(v interface{}) *NotifyPayload {
	m, ok := v.(map[string]interface{})
	if !ok || m == nil {
		return nil
	}
	return &NotifyPayload{
		ProtocolID:       uint8(getInt(m, "protocol_id")),
		SPISize:          uint8(getInt(m, "spi_size")),
		NotifyMsgType:    getUint16(m, "notify_msg_type"),
		NotificationData: getByteSlice(m, "notification_data"),
	}
}

func parseESPChildSAConfig(v interface{}) *ESPChildSAConfig {
	m, ok := v.(map[string]interface{})
	if !ok || m == nil {
		return nil
	}
	return &ESPChildSAConfig{
		SPIout:      getUint32(m, "spi_out"),
		SPIin:       getUint32(m, "spi_in"),
		ESPDataSize: getInt(m, "esp_data_size"),
		ESPCount:    getInt(m, "esp_count"),
		Algorithm:   getString(m, "algorithm"),
		Mode:        getString(m, "mode"),
	}
}

// parseIMAPConfig converts the JSON-decoded "imap" sub-map into *IMAPConfig.
func parseIMAPConfig(m map[string]interface{}) *IMAPConfig {
	if m == nil {
		return nil
	}
	cfg := &IMAPConfig{
		Banner:              getString(m, "banner"),
		Commands:            parseIMAPCommands(m["commands"]),
		IDLE:                parseIMAPIDLE(m["idle"]),
		PipelinedCommands:   getBool(m, "pipelined_commands", false),
		AllowUTF8Mailbox:    getBool(m, "allow_utf8_mailbox", false),
	}
	return cfg
}

func parseIMAPCommands(v interface{}) []IMAPCommand {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]IMAPCommand, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		cmd := IMAPCommand{
			Tag:                   getString(m, "tag"),
			Cmd:                   getString(m, "cmd"),
			Responses:             getStringSlice(m, "responses"),
			LiteralBody:           getString(m, "literal_body"),
			LiteralBodyB64:        getString(m, "literal_body_b64"),
			FileSource:            parseFileSourceField(m),
			EmitIDLE:              getBool(m, "emit_idle", false),
			CancelAfterResponses:  getInt(m, "cancel_after_responses"),
			UIDCacheInvalidation:  getBool(m, "uid_cache_invalidation", false),
		}
		out = append(out, cmd)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func parseIMAPIDLE(v interface{}) *IMAPIDLE {
	m, ok := v.(map[string]interface{})
	if !ok || m == nil {
		return nil
	}
	return &IMAPIDLE{
		PushResponses:         getStringSlice(m, "push_responses"),
		DoneTag:               getString(m, "done_tag"),
		DoneResponse:          getString(m, "done_response"),
		ServerTimeoutBehavior: getString(m, "server_timeout_behavior"),
	}
}

// parseL2TPConfig converts the JSON-decoded "l2tp" sub-map into *L2TPConfig.
func parseL2TPConfig(m map[string]interface{}) *L2TPConfig {
	if m == nil {
		return nil
	}
	cfg := &L2TPConfig{
		Version:           uint8(getInt(m, "version")),
		Role:              getString(m, "role"),
		LocalTunnelID:     getUint16(m, "local_tunnel_id"),
		PeerTunnelID:      getUint16(m, "peer_tunnel_id"),
		LocalSessionID:    getUint16(m, "local_session_id"),
		PeerSessionID:     getUint16(m, "peer_session_id"),
		LocalSessionID32:  getUint32(m, "local_session_id_32"),
		PeerSessionID32:   getUint32(m, "peer_session_id_32"),
		HostName:          getString(m, "host_name"),
		VendorName:        getString(m, "vendor_name"),
		FirmwareRev:       getUint16(m, "firmware_rev"),
		FramingCaps:       getUint32(m, "framing_caps"),
		BearerCaps:        getUint32(m, "bearer_caps"),
		ReceiveWindowSize: getUint16(m, "receive_window_size"),
		InitialNs:         getUint16(m, "initial_ns"),
		TieBreaker:        getUint64(m, "tie_breaker"),
		ProtocolVersion:   getUint16(m, "protocol_version"),
		Cookie:            getByteSlice(m, "cookie"),
		Scenarios:         parseL2TPSteps(m["scenarios"]),
		HelloInterval:     getInt(m, "hello_interval"),
		PPPFrames:         parseL2TPPPPFrames(m["ppp_frames"]),
		CustomAVPs:        parseL2TPAVPs(m["custom_avps"]),
		ResultCode:        getUint16(m, "result_code"),
		ErrorCode:         getUint16(m, "error_code"),
		ErrorMessage:      getString(m, "error_message"),
	}
	return cfg
}

func parseL2TPSteps(v interface{}) []L2TPStep {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]L2TPStep, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		out = append(out, L2TPStep{
			Type:               getString(m, "type"),
			Direction:          getString(m, "direction"),
			AVPs:               parseL2TPAVPs(m["avps"]),
			TunnelIDOverride:   getUint16Ptr(m, "tunnel_id_override"),
			SessionIDOverride:  getUint16Ptr(m, "session_id_override"),
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func parseL2TPAVPs(v interface{}) []L2TPAVP {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]L2TPAVP, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		out = append(out, L2TPAVP{
			Mandatory: getBool(m, "mandatory", false),
			Hidden:    getBool(m, "hidden", false),
			VendorID:  getUint16(m, "vendor_id"),
			AttrType:  getUint16(m, "attr_type"),
			Value:     getByteSlice(m, "value"),
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func parseL2TPPPPFrames(v interface{}) []L2TPPPPFrame {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]L2TPPPPFrame, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		out = append(out, L2TPPPPFrame{
			Protocol:    getUint16(m, "protocol"),
			Data:        getByteSlice(m, "data"),
			Direction:   getString(m, "direction"),
			L2PPPHeader: getBool(m, "l2_ppp_header", false),
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// parseMDNSConfig converts the JSON-decoded "mdns" sub-map into *MDNSConfig.
func parseMDNSConfig(m map[string]interface{}) *MDNSConfig {
	if m == nil {
		return nil
	}
	cfg := &MDNSConfig{
		Mode:               getString(m, "mode"),
		Questions:           parseMDNSQuestions(m["questions"]),
		Answers:             parseMDNSResourceRecords(m["answers"]),
		Authorities:         parseMDNSResourceRecords(m["authorities"]),
		Additionals:         parseMDNSResourceRecords(m["additionals"]),
		ProbingRepeat:       getInt(m, "probing_repeat"),
		ProbingInterval:     getInt(m, "probing_interval"),
		ProbingJitterMax:    getInt(m, "probing_jitter_max"),
		ProbingJitterSeed:   int64(getInt(m, "probing_jitter_seed")),
		AnnouncingRepeat:    getInt(m, "announcing_repeat"),
		AnnouncingInterval:  getInt(m, "announcing_interval"),
		ResponseDelay:       getInt(m, "response_delay"),
		MulticastGroup:      getString(m, "multicast_group"),
		ForceUnicastResponse: getBool(m, "force_unicast_response", false),
		CacheFlush:          getBoolPtr(m, "cache_flush"),
		DefaultTTL:          getUint32(m, "default_ttl"),
		TC:                  getBool(m, "tc", false),
	}
	return cfg
}

func parseMDNSQuestions(v interface{}) []MDNSQuestion {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]MDNSQuestion, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		out = append(out, MDNSQuestion{
			Name:  getString(m, "name"),
			Type:  getUint16(m, "type"),
			Class: getUint16(m, "class"),
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func parseMDNSResourceRecords(v interface{}) []MDNSResourceRecord {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]MDNSResourceRecord, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		out = append(out, MDNSResourceRecord{
			Name:         getString(m, "name"),
			Type:         getUint16(m, "type"),
			Class:        getUint16(m, "class"),
			TTL:          getUint32(m, "ttl"),
			IPAddress:    getString(m, "ip_address"),
			DomainName:   getString(m, "domain_name"),
			Priority:     getUint16(m, "priority"),
			Weight:       getUint16(m, "weight"),
			Port:         getUint16(m, "port"),
			Target:       getString(m, "target"),
			TXTEntries:   getStringSlice(m, "txt_entries"),
			NSECNextName: getString(m, "nsec_next_name"),
			NSECTypes:    getUint16Slice(m, "nsec_types"),
			RawRDATA:     getByteSlice(m, "raw_rdata"),
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// parseMySQLConfig converts the JSON-decoded "mysql" sub-map into *MySQLConfig.
func parseMySQLConfig(m map[string]interface{}) *MySQLConfig {
	if m == nil {
		return nil
	}
	cfg := &MySQLConfig{
		ServerVersion:    getString(m, "server_version"),
		ThreadID:          getUint32(m, "thread_id"),
		AuthPlugin:        getString(m, "auth_plugin"),
		Username:          getString(m, "username"),
		Password:          getString(m, "password"),
		Scramble:          getByteSlice(m, "scramble"),
		Database:          getString(m, "database"),
		CapabilityFlags:   getUint32(m, "capability_flags"),
		MaxPacketSize:     getUint32(m, "max_packet_size"),
		CharacterSet:      uint8(getInt(m, "character_set")),
		Commands:          parseMySQLCommands(m["commands"]),
		ServerBypassAuth:  getBool(m, "server_bypass_auth", false),
	}
	return cfg
}

func parseMySQLCommands(v interface{}) []MySQLCommand {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]MySQLCommand, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		cmd := MySQLCommand{
			Opcode:           uint8(getInt(m, "opcode")),
			Body:             getString(m, "body"),
			BodyEncoding:     getString(m, "body_encoding"),
			ReplyMode:        getString(m, "reply_mode"),
			ReplyBytes:       getString(m, "reply_bytes"),
			ReplyEncoding:    getString(m, "reply_encoding"),
			ColDefs:          parseMySQLColDefs(m["col_defs"]),
			Rows:             parseMySQLRows(m["rows"]),
			StmtID:           getUint32(m, "stmt_id"),
			IterationCount:   getUint32(m, "iteration_count"),
			EmitOkExtended:   getBool(m, "emit_ok_extended", false),
		}
		out = append(out, cmd)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func parseMySQLColDefs(v interface{}) []MySQLColDef {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]MySQLColDef, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		out = append(out, MySQLColDef{
			Catalog:   getString(m, "catalog"),
			Schema:    getString(m, "schema"),
			Table:     getString(m, "table"),
			OrgTable:  getString(m, "org_table"),
			Name:      getString(m, "name"),
			OrgName:   getString(m, "org_name"),
			Charset:   getUint16(m, "charset"),
			Length:    getUint32(m, "length"),
			Type:      uint8(getInt(m, "type")),
			Flags:     getUint16(m, "flags"),
			Decimals:  uint8(getInt(m, "decimals")),
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func parseMySQLRows(v interface{}) []MySQLRow {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]MySQLRow, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		row := MySQLRow{
			Values:        getStringSlice(m, "values"),
			ValueEncoding: getString(m, "value_encoding"),
		}
		// is_null is a parallel bool array
		if nulls, ok := m["is_null"].([]interface{}); ok {
			for _, n := range nulls {
				if b, ok := n.(bool); ok {
					row.IsNull = append(row.IsNull, b)
				}
			}
		}
		out = append(out, row)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// parseOpenVPNConfig converts the JSON-decoded "openvpn" sub-map into *OpenVPNConfig.
func parseOpenVPNConfig(m map[string]interface{}) *OpenVPNConfig {
	if m == nil {
		return nil
	}
	cfg := &OpenVPNConfig{
		Proto:                   getString(m, "proto"),
		Version:                 getString(m, "version"),
		KeyID:                   uint8(getInt(m, "key_id")),
		SessionID:               getUint64(m, "session_id"),
		TLSAuth:                 getBool(m, "tls_auth", false),
		TLSCrypt:                getBool(m, "tls_crypt", false),
		TLSCryptV2:              getBool(m, "tls_crypt_v2", false),
		DataCipher:              getString(m, "data_cipher"),
		NCPDisable:              getBool(m, "ncp_disable", false),
		TLSVersion:              getString(m, "tls_version"),
		TLSRole:                 getString(m, "tls_role"),
		SNI:                     getString(m, "sni"),
		Mssfix:                  getUint16(m, "mssfix"),
		TLSAuthHMAC:             getByteSlice(m, "tls_auth_hmac"),
		TLSCryptWrappedKey:      getByteSlice(m, "tls_crypt_wrapped_key"),
		DataPayload:             getByteSlice(m, "data_payload"),
		DataPacketCount:         getInt(m, "data_packet_count"),
		PerformSoftReset:       getBool(m, "perform_soft_reset", false),
		StaticKeyMode:          getBool(m, "static_key_mode", false),
		KeyDirection:           uint8(getInt(m, "key_direction")),
		StaticKey:              getByteSlice(m, "static_key"),
		AuthUserPass:           getBool(m, "auth_user_pass", false),
		AuthUser:               getString(m, "auth_user"),
		AuthPass:               getString(m, "auth_pass"),
		AuthAlg:                 getString(m, "auth_alg"),
		FragmentSize:           getUint16(m, "fragment_size"),
		KeepalivePingInterval:  getUint16(m, "keepalive_ping"),
		KeepalivePingRestart:   getUint16(m, "keepalive_ping_restart"),
		ExitNotifyCount:        uint8(getInt(m, "exit_notify_count")),
		ExitNotifyInterval:     getUint16(m, "exit_notify_interval"),
		TunMTU:                 getUint16(m, "tun_mtu"),
	}
	return cfg
}

// parsePostgreSQLConfig converts the JSON-decoded "postgresql" sub-map into
// *PostgreSQLConfig.
func parsePostgreSQLConfig(m map[string]interface{}) *PostgreSQLConfig {
	if m == nil {
		return nil
	}
	// ColumnTypes has int->int32 map; we need to fetch values from JSON map
	var colTypes map[int]int32
	if v, ok := m["column_types"].(map[string]interface{}); ok && len(v) > 0 {
		colTypes = make(map[int]int32, len(v))
		for k, val := range v {
			var idx int
			if _, err := fmt.Sscanf(k, "%d", &idx); err != nil {
				continue
			}
			switch n := val.(type) {
			case float64:
				colTypes[idx] = int32(n)
			case json.Number:
				if j, err := n.Int64(); err == nil {
					colTypes[idx] = int32(j)
				}
			}
		}
	}
	cfg := &PostgreSQLConfig{
		ProtocolVersion:      int32(getInt(m, "protocol_version")),
		StartupParams:        getStringMap(m, "startup_params"),
		AuthMethod:           getString(m, "auth_method"),
		Username:             getString(m, "username"),
		Password:             getString(m, "password"),
		MD5Salt:              getByteSlice(m, "md5_salt"),
		Operations:           parsePGOperations(m["operations"]),
		Pipeline:             getBool(m, "pipeline", false),
		RowCount:             getInt(m, "row_count"),
		ColumnTypes:          colTypes,
		NotificationPayload:  getString(m, "notification_payload"),
		WALDataSize:          getInt(m, "wal_data_size"),
		EmitHandshake:        getBoolPtr(m, "emit_handshake"),
		EmitTeardown:         getBoolPtr(m, "emit_teardown"),
	}
	return cfg
}

func parsePGOperations(v interface{}) []PGOperation {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]PGOperation, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		op := PGOperation{
			Kind:              getString(m, "kind"),
			SQL:               getString(m, "sql"),
			Statement:         getString(m, "statement"),
			Portal:            getString(m, "portal"),
			Mode:              getString(m, "mode"),
			MaxRows:           int32(getInt(m, "max_rows")),
			ParamCount:        getInt(m, "param_count"),
			ParamValues:       getStringSlice(m, "param_values"),
			Channel:           getString(m, "channel"),
			CopyData:          getStringSlice(m, "copy_data"),
			ReplicationSlot:   getString(m, "replication_slot"),
			ReplicationLSN:    getString(m, "replication_lsn"),
			ReplicationKind:   getString(m, "replication_kind"),
			EmitAsServer:      getBool(m, "emit_as_server", false),
			NotifyChannel:     getString(m, "notify_channel"),
			NotifyPayload:     getString(m, "notify_payload"),
			FunctionOID:       int32(getInt(m, "function_oid")),
			ResultFormatCode:  int16(getInt(m, "result_format_code")),
		}
		// ArgumentFormatCodes is int16 slice
		if arr, ok := m["argument_format_codes"].([]interface{}); ok {
			for _, c := range arr {
				switch n := c.(type) {
				case float64:
					op.ArgumentFormatCodes = append(op.ArgumentFormatCodes, int16(n))
				case json.Number:
					if j, err := n.Int64(); err == nil {
						op.ArgumentFormatCodes = append(op.ArgumentFormatCodes, int16(j))
					}
				}
			}
		}
		out = append(out, op)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// parseRDPConfig converts the JSON-decoded "rdp" sub-map into *RDPConfig.
func parseRDPConfig(m map[string]interface{}) *RDPConfig {
	if m == nil {
		return nil
	}
	cfg := &RDPConfig{
		SecurityLayer:            getString(m, "security_layer"),
		RequestedProtocols:       getUint32(m, "requested_protocols"),
		RestrictedAdmin:          getBool(m, "restricted_admin", false),
		RedirectedAuth:           getBool(m, "redirected_auth", false),
		Cookie:                   getString(m, "cookie"),
		ClientName:               getString(m, "client_name"),
		ClientBuild:              getUint32(m, "client_build"),
		KeyboardLayout:           getUint32(m, "keyboard_layout"),
		KeyboardType:             getUint32(m, "keyboard_type"),
		KeyboardSubType:          getUint32(m, "keyboard_sub_type"),
		KeyboardFunctionKey:      getUint32(m, "keyboard_function_key"),
		DesktopWidth:             getUint16(m, "desktop_width"),
		DesktopHeight:            getUint16(m, "desktop_height"),
		ColorDepth:               getUint16(m, "color_depth"),
		HighColorDepth:           getUint16(m, "high_color_depth"),
		SupportedColorDepths:     getUint16(m, "supported_color_depths"),
		ConnectionType:           uint8(getInt(m, "connection_type")),
		ServerSelectedProtocol:   getUint32(m, "server_selected_protocol"),
		EncryptionMethods:        getUint32(m, "encryption_methods"),
		ExtEncryptionMethods:     getUint32(m, "ext_encryption_methods"),
		Domain:                   getString(m, "domain"),
		UserName:                 getString(m, "user_name"),
		Password:                 getString(m, "password"),
		AlternateShell:           getString(m, "alternate_shell"),
		WorkingDir:               getString(m, "working_dir"),
		Channels:                 parseRDPChannels(m["channels"]),
		AutoLogon:                getBool(m, "auto_logon", false),
		InfoUnicode:              getBool(m, "info_unicode", false),
		InfoLogonNotify:          getBool(m, "info_logon_notify", false),
		InfoCompression:          getBool(m, "info_compression", false),
		CodePage:                 getUint32(m, "code_page"),
		Flags2:                   getUint16(m, "flags2"),
		SkipMCSChannelJoin:       getBool(m, "skip_mcs_channel_join", false),
		SkipSecurityExchange:     getBool(m, "skip_security_exchange", false),
		SkipLicense:              getBool(m, "skip_license", false),
		SkipCapability:           getBool(m, "skip_capability", false),
		ForceRDPVersion:          getUint32(m, "force_rdp_version"),
		EncryptionLevel:          getUint32(m, "encryption_level"),
		EncryptionMethod:         getUint32(m, "encryption_method"),
		ServerRandom:             getByteSlice(m, "server_random"),
		ServerCertVersion:        getUint32(m, "server_cert_version"),
		SecurityExchangeRSAKeyBytes: getInt(m, "security_exchange_rsa_key_bytes"),
		DataEvents:               parseRDPDataEvents(m["data_events"]),
		ServerResponses:          parseRDPServerResponses(m["server_responses"]),
	}
	return cfg
}

func parseRDPChannels(v interface{}) []RDPChannel {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]RDPChannel, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		out = append(out, RDPChannel{
			Name:    getString(m, "name"),
			Options: getUint32(m, "options"),
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func parseRDPDataEvents(v interface{}) []RDPDataEvent {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]RDPDataEvent, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		ev := RDPDataEvent{
			Type:       getString(m, "type"),
			Channel:    getString(m, "channel"),
			Direction:  getString(m, "direction"),
			Payload:    getByteSlice(m, "payload"),
			PayloadB64: getString(m, "payload_b64"),
		}
		// Decode base64 payload if provided
		if ev.Payload == nil && ev.PayloadB64 != "" {
			if b, err := decodeBase64(ev.PayloadB64); err == nil {
				ev.Payload = b
			}
		}
		out = append(out, ev)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func parseRDPServerResponses(v interface{}) []RDPServerResponse {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]RDPServerResponse, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		out = append(out, RDPServerResponse{
			Type:    getString(m, "type"),
			Payload: getByteSlice(m, "payload"),
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// parseRedisConfig converts the JSON-decoded "redis" sub-map into *RedisConfig.
func parseRedisConfig(m map[string]interface{}) *RedisConfig {
	if m == nil {
		return nil
	}
	cfg := &RedisConfig{
		Version:           getInt(m, "version"),
		SkipHello:         getBool(m, "skip_hello", false),
		Username:          getString(m, "username"),
		Password:          getString(m, "password"),
		SelectDB:          getInt(m, "select_db"),
		ClientName:        getString(m, "client_name"),
		Commands:          parseRedisCommands(m["commands"]),
		SubscribeTo:       getStringSlice(m, "subscribe_to"),
		SubscribePatterns: getStringSlice(m, "subscribe_patterns"),
		PublishMessages:   parseRedisPublish(m["publish_messages"]),
		PipelineSize:      getInt(m, "pipeline_size"),
	}
	return cfg
}

func parseRedisCommands(v interface{}) []RedisCommand {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]RedisCommand, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		out = append(out, RedisCommand{
			Args:        getStringSlice(m, "args"),
			ArgsBase64:  getStringSlice(m, "args_base64"),
			Reply:       getString(m, "reply"),
			AutoReply:   getString(m, "auto_reply"),
			EmitAsPush:  getBool(m, "emit_as_push", false),
			Channel:     getString(m, "channel"),
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func parseRedisPublish(v interface{}) []RedisPublish {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]RedisPublish, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		out = append(out, RedisPublish{
			Channel:    getString(m, "channel"),
			Message:    getString(m, "message"),
			MessageB64: getString(m, "message_b64"),
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// parseShadowsocksConfig converts the JSON-decoded "shadowsocks" sub-map
// into *ShadowsocksConfig.
func parseShadowsocksConfig(m map[string]interface{}) *ShadowsocksConfig {
	if m == nil {
		return nil
	}
	cfg := &ShadowsocksConfig{
		Mode:                getString(m, "mode"),
		Cipher:              getString(m, "cipher"),
		SOCKS5Handshake:     getBool(m, "socks5_handshake", false),
		SOCKS5AuthMethod:   getString(m, "socks5_auth_method"),
		SOCKS5Username:     getString(m, "socks5_username"),
		SOCKS5Password:     getString(m, "socks5_password"),
		SOCKS5Cmd:          getString(m, "socks5_cmd"),
		SOCKS5DstAddr:      getString(m, "socks5_dst_addr"),
		SOCKS5DstPort:      getUint16(m, "socks5_dst_port"),
		SOCKS5BNDAddr:      getString(m, "socks5_bnd_addr"),
		SOCKS5BNDPort:      getUint16(m, "socks5_bnd_port"),
		Chunks:              getInt(m, "chunks"),
		ChunkPayloadSize:   getInt(m, "chunk_payload_size"),
		Obfuscation:        getString(m, "obfuscation"),
		ObfMethod:          getString(m, "obf_method"),
		ObfHeaders:          getStringMap(m, "obf_headers"),
		PayloadBytesFormat:  getString(m, "payload_bytes_format"),
		FRAG:                uint8(getInt(m, "frag")),
		FileSource:          parseFileSourceField(m),
	}
	return cfg
}

// parseSSDPConfig converts the JSON-decoded "ssdp" sub-map into *SSDPConfig.
func parseSSDPConfig(m map[string]interface{}) *SSDPConfig {
	if m == nil {
		return nil
	}
	cfg := &SSDPConfig{
		MessageType:          getString(m, "message_type"),
		SearchTarget:         getString(m, "search_target"),
		USN:                  getString(m, "usn"),
		Location:             getString(m, "location"),
		Server:               getString(m, "server"),
		MaxAge:               getInt(m, "max_age"),
		MX:                   getInt(m, "mx"),
		BootID:               getUint32(m, "boot_id"),
		ConfigID:             getUint32(m, "config_id"),
		NextBootID:           getUint32(m, "next_boot_id"),
		SearchPort:           getUint16(m, "search_port"),
		ResponseCount:        getInt(m, "response_count"),
		ResponseDelayMinMs:   getInt(m, "response_delay_min_ms"),
		ResponseDelayMaxMs:   getInt(m, "response_delay_max_ms"),
		RepeatCount:          getInt(m, "repeat_count"),
		Date:                 getString(m, "date"),
		MulticastGroup:       getString(m, "multicast_group"),
		OmitExt:              getBool(m, "omit_ext", false),
		Body:                 getString(m, "body"),
		EmitContentLength:    getBool(m, "emit_content_length", false),
		RepeatIntervalMs:     getInt(m, "repeat_interval_ms"),
	}
	return cfg
}

// parseTLSConfig converts the JSON-decoded "tls" sub-map into *TLSConfig.
func parseTLSConfig(m map[string]interface{}) *TLSConfig {
	if m == nil {
		return nil
	}
	cfg := &TLSConfig{
		Version:             getString(m, "version"),
		Role:                getString(m, "role"),
		SNI:                 getString(m, "sni"),
		ALPN:                getStringSlice(m, "alpn"),
		CipherSuites:        getUint16Slice(m, "cipher_suites"),
		SupportedGroups:     getUint16Slice(m, "supported_groups"),
		SignatureAlgorithms: getUint16Slice(m, "signature_algorithms"),
		ClientCertificate:   parseX509Ref(m["client_certificate"]),
		ServerCertificate:   parseX509Ref(m["server_certificate"]),
		PSKs:                parsePSKIdentities(m["psks"]),
		AllowEarlyData:      getBool(m, "allow_early_data", false),
		AlertPath:           parseAlertStep(m["alert_path"]),
		OCSPStapling:        getBool(m, "ocsp_stapling", false),
	}
	return cfg
}

func parseX509Ref(v interface{}) *X509Ref {
	m, ok := v.(map[string]interface{})
	if !ok || m == nil {
		return nil
	}
	return &X509Ref{
		Subject:    getString(m, "subject"),
		San:        getStringSlice(m, "san"),
		NotBefore:  int64(getInt(m, "not_before")),
		NotAfter:   int64(getInt(m, "not_after")),
		KeyType:    getString(m, "key_type"),
		FileSource: parseFileSourceField(m),
	}
}

func parsePSKIdentities(v interface{}) []PSKIdentity {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]PSKIdentity, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		out = append(out, PSKIdentity{
			Identity:        getByteSlice(m, "identity"),
			ObfuscatedAge:   getUint32(m, "obfuscated_age"),
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func parseAlertStep(v interface{}) *AlertStep {
	m, ok := v.(map[string]interface{})
	if !ok || m == nil {
		return nil
	}
	return &AlertStep{
		After:       getString(m, "after"),
		Description: uint8(getInt(m, "description")),
		Level:       uint8(getInt(m, "level")),
	}
}

// parseVmessConfig converts the JSON-decoded "vmess" sub-map into *VmessConfig.
func parseVmessConfig(m map[string]interface{}) *VmessConfig {
	if m == nil {
		return nil
	}
	cfg := &VmessConfig{
		UUID:             getString(m, "uuid"),
		AlterID:          getUint16(m, "alter_id"),
		Encryption:       getString(m, "encryption"),
		Command:          uint8(getInt(m, "command")),
		AddressType:      uint8(getInt(m, "address_type")),
		Address:          getString(m, "address"),
		Port:             getUint16(m, "port"),
		HeaderPadLen:     uint8(getInt(m, "header_pad_len")),
		Payload:          getByteSlice(m, "payload"),
		ResponsePayload:  getByteSlice(m, "response_payload"),
		FileSource:       parseFileSourceField(m),
		Heartbeat:        getBool(m, "heartbeat", false),
		HeartbeatCount:   getInt(m, "heartbeat_count"),
		MuxStreams:       parseVmessMuxStreams(m["mux_streams"]),
	}
	return cfg
}

func parseVmessMuxStreams(v interface{}) []VmessMuxStream {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]VmessMuxStream, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		out = append(out, VmessMuxStream{
			SessionID:   getUint16(m, "session_id"),
			Frames:      parseVmessMuxFrames(m["frames"]),
			TargetAddr:  getString(m, "target_addr"),
			TargetPort:  getUint16(m, "target_port"),
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func parseVmessMuxFrames(v interface{}) []VmessMuxFrame {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]VmessMuxFrame, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		out = append(out, VmessMuxFrame{
			Status:  uint8(getInt(m, "status")),
			Payload: getByteSlice(m, "payload"),
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// parseWireGuardConfig converts the JSON-decoded "wireguard" sub-map into
// *WireGuardConfig.
func parseWireGuardConfig(m map[string]interface{}) *WireGuardConfig {
	if m == nil {
		return nil
	}
	cfg := &WireGuardConfig{
		Role:                    getString(m, "role"),
		LocalStaticPubKey:       getByteSlice(m, "local_static_pub_key"),
		PeerStaticPubKey:        getByteSlice(m, "peer_static_pub_key"),
		LocalEphemeralPubKey:   getByteSlice(m, "local_ephemeral_pub_key"),
		SenderIndex:             getUint32(m, "sender_index"),
		PSK:                     getByteSlice(m, "psk"),
		Cookie:                  getByteSlice(m, "cookie"),
		InitialCounter:          getUint64(m, "initial_counter"),
		RekeyAfter:              getUint64(m, "rekey_after"),
		RekeyAfterTime:          getInt(m, "rekey_after_time"),
		KeepaliveInterval:       getInt(m, "keepalive_interval"),
		CookieReplyThreshold:    getInt(m, "cookie_reply_threshold"),
		TransportPayloads:       getByteSlices(m, "transport_payloads"),
		FileSource:              parseFileSourceField(m),
		Direction:               getString(m, "direction"),
	}
	return cfg
}

// parseTelnetDialog converts the JSON-decoded "dialog" array into a
// []TelnetEvent. Returns nil for absent/non-array input - the planner then
// falls back to its built-in defaultDialog() (a minimal login shape per
// design_telnet.md §6.6).
//
// Each event carries Type (data/will/wont/do/dont/sb/ttype_send/ttype_is/
// naws/ip/dm/nop/ayt/brk/ao/ec/el/ga/synch), Direction ("up"/"down", empty
// defaults to "up" in the planner), and type-specific fields (Option/Data/
// DataB64/SubData/SubDataB64/Value/Cols/Rows). SubData may be a JSON array
// of byte integers or a string (raw bytes).
func parseTelnetDialog(v interface{}) []TelnetEvent {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]TelnetEvent, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		ev := TelnetEvent{
			Type:       getString(m, "type"),
			Direction:  getString(m, "direction"),
			Option:     uint8(getInt(m, "option")),
			Data:       getString(m, "data"),
			DataB64:    getString(m, "data_b64"),
			SubData:    parseByteSlice(m["sub_data"]),
			SubDataB64: getString(m, "sub_data_b64"),
			Value:      getString(m, "value"),
			Cols:       getUint16(m, "cols"),
			Rows:       getUint16(m, "rows"),
		}
		out = append(out, ev)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// parseByteSlice converts a JSON-decoded value into a []byte. Accepts a
// JSON array of integers (each 0-255) or a string (raw bytes). Returns nil
// for absent/non-array/non-string input. Mirrors the SCTP chunk data
// parseSNMPVarBinds converts the JSON-decoded "var_binds" or "response_values"
// value (an array of {name, type, value, str_value} objects) into a
// []SNMPVarBind. Returns nil for absent/non-array input - the planner then
// emits a PDU with an empty varbind list (valid for Trap/Inform, where the
// planner synthesises sysUpTime + snmpTrapOID; rejected by Validate for
// Get/GetNext/Set/GetBulk).
//
// Type is the BER tag (0x05 NULL / 0x02 INTEGER / 0x04 OCTET STRING / 0x06 OID
// / 0x40 IpAddress / 0x41 Counter32 / 0x42 Gauge32 / 0x43 TimeTicks / 0x46
// Counter64 / 0x80 noSuchObject / 0x81 noSuchInstance / 0x82 EndOfMibView).
// Value is the raw bytes of the value body (without tag/length); for NULL and
// exception types it is empty. StrValue, when set on an OCTET STRING varbind,
// is encoded as the UTF-8 bytes of the string (convenience for DisplayString).
func parseSNMPVarBinds(v interface{}) []SNMPVarBind {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]SNMPVarBind, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		vb := SNMPVarBind{
			Name:     getString(m, "name"),
			Type:     uint8(getInt(m, "type")),
			Value:    parseByteSlice(m["value"]),
			StrValue: getString(m, "str_value"),
		}
		// When Type is OCTET STRING (0x04) and Value is empty but StrValue
		// is set, copy StrValue into Value so the encoder emits the string
		// bytes. This is the DisplayString convenience path.
		if vb.Type == 0x04 && len(vb.Value) == 0 && vb.StrValue != "" {
			vb.Value = []byte(vb.StrValue)
		}
		out = append(out, vb)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// parsing pattern.
func parseByteSlice(v interface{}) []byte {
	switch d := v.(type) {
	case string:
		return []byte(d)
	case []interface{}:
		out := make([]byte, 0, len(d))
		for _, b := range d {
			if n, ok := b.(float64); ok {
				out = append(out, byte(int(n)))
			}
		}
		if len(out) == 0 {
			return nil
		}
		return out
	}
	return nil
}

// parseSIPDialog converts the JSON-decoded "dialog" value into a
// []SIPMessage. Returns nil for absent/non-array input - the planner then
// emits only TCP handshake + teardown (an empty SIP session, which is a
// valid degenerate test).
//
// Each message may carry Method+URI (request) or StatusCode+StatusText
// (response). Direction is "up" or "down"; when empty, the planner infers
// it from Method/StatusCode (Method set -> up request; StatusCode set ->
// down response). Headers is a list of "Name: Value" strings; the planner
// auto-appends Content-Length when Body is non-empty. Body is the optional
// message body (e.g. SDP).
func parseSIPDialog(v interface{}) []SIPMessage {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]SIPMessage, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		msg := SIPMessage{
			Method:     getString(m, "method"),
			URI:        getString(m, "uri"),
			StatusCode: getInt(m, "status_code"),
			StatusText: getString(m, "status_text"),
			Direction:  getString(m, "direction"),
			Body:       getString(m, "body"),
			EmitMedia:  getBool(m, "emit_media", false),
		}
		if headers, ok := m["headers"].([]interface{}); ok {
			for _, h := range headers {
				if s, ok := h.(string); ok {
					msg.Headers = append(msg.Headers, s)
				}
			}
		}
		out = append(out, msg)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// parseSIPMedia converts the JSON-decoded "media" sub-map into a *SIPMedia.
// Returns nil for absent/non-map input — the planner then emits only
// signaling (backward compat with pre-media specs).
func parseSIPMedia(v interface{}) *SIPMedia {
	m, ok := v.(map[string]interface{})
	if !ok || m == nil {
		return nil
	}
	return &SIPMedia{
		SrcPort:     getUint16(m, "src_port"),
		DstPort:     getUint16(m, "dst_port"),
		Frames:      getInt(m, "frames"),
		PayloadType: uint8(getInt(m, "payload_type")),
		SampleRate:  uint32(getInt(m, "sample_rate")),
		FrameSize:   getInt(m, "frame_size"),
	}
}

// Each chunk carries TSN/SID/SSN/PPID/Data/Direction. TSN 0 = planner
// auto-increments per direction. Direction "up" = client→server, "down"
// = server→client; empty defaults to "up".
func parseSCTPChunks(v interface{}) []SCTPChunk {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]SCTPChunk, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		var data []byte
		switch d := m["data"].(type) {
		case string:
			data = []byte(d)
		case []interface{}:
			data = make([]byte, 0, len(d))
			for _, b := range d {
				if n, ok := b.(float64); ok {
					data = append(data, byte(int(n)))
				}
			}
		}
		chunk := SCTPChunk{
			TSN:        getUint32(m, "tsn"),
			SID:        getUint16(m, "sid"),
			SSN:        getUint16(m, "ssn"),
			PPID:       getUint32(m, "ppid"),
			Data:       data,
			Direction:  getString(m, "direction"),
			FileSource: parseFileSource(m),
		}
		out = append(out, chunk)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// parseSCTPHeartbeats converts the JSON-decoded "heartbeats" value into an
// *SCTPHeartbeatConfig. Returns nil for absent/non-map input so the planner
// skips heartbeat emission. Count 0 = 1 pair default. AltPath is optional
// — nil means primary-path heartbeats (still useful for liveness).
func parseSCTPHeartbeats(v interface{}) *SCTPHeartbeatConfig {
	m, ok := v.(map[string]interface{})
	if !ok || m == nil {
		return nil
	}
	hb := &SCTPHeartbeatConfig{
		Count: getInt(m, "count"),
	}
	if alt, ok := m["alt_path"].(map[string]interface{}); ok && alt != nil {
		hb.AltPath = &SCTPAltPath{
			SrcIP:  getString(alt, "alt_src_ip"),
			DstIP:  getString(alt, "alt_dst_ip"),
			SrcMAC: getString(alt, "alt_src_mac"),
			DstMAC: getString(alt, "alt_dst_mac"),
		}
	}
	return hb
}

// parseICMPv6Pattern converts the JSON-decoded "pattern" value (an array of
// step objects) into a []ICMPv6Step. Returns nil for absent/non-array input
// so the planner falls back to the single-ping path. Each step inherits
// Type/Code defaults from the parent config when absent (Type=128, Code=0);
// Sequence defaults to step index+1 when 0 (per RFC 4443 ping session
// semantics: Identifier groups, Sequence increments per ping).
func parseICMPv6Pattern(v interface{}) []ICMPv6Step {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]ICMPv6Step, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		typ := uint8(getIntDefault(m, "type", 128))
		code := uint8(getIntDefault(m, "code", 0))
		seq := uint16(getInt(m, "sequence"))
		if seq == 0 {
			seq = uint16(len(out) + 1)
		}
		data := []byte(getStringDefault(m, "data", "ping"))
		out = append(out, ICMPv6Step{
			Type:     typ,
			Code:     code,
			Sequence: seq,
			Data:     data,
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// JSON helper functions with sensible defaults

// parseSyslogStructuredData converts the JSON-decoded "structured_data" field
// into a []string. Accepts both a list of strings (preferred, each entry is
// a pre-framed SD-ELEMENT like `[origin ip="1.2.3.4"]` or a bare body like
// `origin ip="1.2.3.4"`) and a list of maps with `id` + `parameters` keys
// (structured form). Returns nil for absent/non-list input.
func parseSyslogStructuredData(v interface{}) []string {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, item := range arr {
		switch s := item.(type) {
		case string:
			if s != "" {
				out = append(out, s)
			}
		case map[string]interface{}:
			// Structured form: {id: "origin", parameters: {ip: "1.2.3.4"}}
			id, _ := item.(map[string]interface{})["id"].(string)
			if id == "" {
				continue
			}
			params, _ := item.(map[string]interface{})["parameters"].(map[string]interface{})
			var b strings.Builder
			b.WriteByte('[')
			b.WriteString(id)
			for k, v := range params {
				vs, _ := v.(string)
				b.WriteString(` `)
				b.WriteString(k)
				b.WriteString(`="`)
				b.WriteString(escapeSDValue(vs))
				b.WriteString(`"`)
			}
			b.WriteByte(']')
			out = append(out, b.String())
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// parseSyslogSignBlocks converts the JSON-decoded "sign_blocks" field into
// a []string. Accepts a list of strings (each is a base64 signature value).
// Returns nil for absent/non-list input.
func parseSyslogSignBlocks(v interface{}) []string {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, item := range arr {
		if s, ok := item.(string); ok && s != "" {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
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

func getString(m map[string]interface{}, key string) string {
	v, _ := m[key].(string)
	return v
}

func getStringDefault(m map[string]interface{}, key, def string) string {
	if v, ok := m[key].(string); ok && v != "" {
		return v
	}
	return def
}

func getUint16(m map[string]interface{}, key string) uint16 {
	switch v := m[key].(type) {
	case float64:
		return uint16(v)
	case json.Number:
		n, _ := v.Int64()
		return uint16(n)
	default:
		return 0
	}
}

func getUint32(m map[string]interface{}, key string) uint32 {
	switch v := m[key].(type) {
	case float64:
		return uint32(v)
	case json.Number:
		n, _ := v.Int64()
		return uint32(n)
	default:
		return 0
	}
}

// getUint64 reads a uint64 from the map. Supports float64 (JSON decode) and
// json.Number (UseNumber path); missing key returns 0. Used by IKE SPI fields.
func getUint64(m map[string]interface{}, key string) uint64 {
	switch v := m[key].(type) {
	case float64:
		return uint64(v)
	case json.Number:
		n, _ := v.Int64()
		return uint64(n)
	case int:
		return uint64(v)
	case int64:
		return uint64(v)
	default:
		return 0
	}
}

func getInt(m map[string]interface{}, key string) int {
	switch v := m[key].(type) {
	case float64:
		return int(v)
	case json.Number:
		n, _ := v.Int64()
		return int(n)
	default:
		return 0
	}
}

func getIntDefault(m map[string]interface{}, key string, def int) int {
	v := getInt(m, key)
	if v == 0 {
		return def
	}
	return v
}

// defaultDSCP returns the user-provided DSCP value when the "dscp" key is
// present in cfg AND non-nil (even if 0 = best-effort), and DefaultDSCP when
// the key is absent or explicitly null. The presence + nil check is required
// because:
//   - DSCP=0 is a valid user choice (clean best-effort traffic with no
//     trafficgen marker), which the older getIntDefault helper would silently
//     override with the default.
//   - JSON null (cfg["dscp"]=nil) should be treated as "not set", not as
//     "explicitly 0" -- otherwise a config like {"dscp": null} silently
//     disables the trafficgen marker.
func defaultDSCP(cfg map[string]interface{}) uint8 {
	if v, ok := cfg["dscp"]; ok && v != nil {
		return uint8(getInt(cfg, "dscp"))
	}
	return DefaultDSCP
}

// defaultIPFlags returns the user-provided IP flags when the "ip_flags" key
// is present in cfg AND non-nil (even if 0 = allow fragmentation), and
// DefaultIPFlags (DF=1) when the key is absent or null. Same presence + nil
// check rationale as defaultDSCP: flags=0 is a valid user choice.
//
// Backward compat: pre-rename strategies used the key "flags". We prefer
// "ip_flags" when present and fall back to "flags" so existing DB rows keep
// working. The "flags" key is ambiguous on a FlowSpec (TCP flags vs IP flags)
// — the rename makes the intent unambiguous.
func defaultIPFlags(cfg map[string]interface{}) uint8 {
	if v, ok := cfg["ip_flags"]; ok && v != nil {
		return uint8(getInt(cfg, "ip_flags"))
	}
	if v, ok := cfg["flags"]; ok && v != nil {
		return uint8(getInt(cfg, "flags"))
	}
	return DefaultIPFlags
}

// defaultMAC returns the user-provided MAC when the "key" field is present
// AND non-empty (allowing explicit "" to produce an all-zero MAC on the wire
// for ARP probe scenarios), and def when absent or null. The presence check
// is required because empty string is a legitimate user value (zero MAC),
// which getStringDefault would silently replace with the default.
func defaultMAC(cfg map[string]interface{}, key, def string) string {
	if v, ok := cfg[key]; ok && v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return def
}

// defaultString returns the user-provided string when the "key" field is
// present AND non-nil (even if ""), and def when absent or null. Same
// presence + nil rationale as defaultMAC: empty string is a legitimate
// user value (e.g., empty domain for DNS wildcard, empty URI for root).
func defaultString(cfg map[string]interface{}, key, def string) string {
	if v, ok := cfg[key]; ok && v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return def
}

// defaultPort returns the user-provided port when the "port_key" field is
// present AND non-nil (even if 0), and def when absent or null. Port 0 is a
// valid user choice (let OS pick ephemeral port), which getUint16 would
// silently override with the default. Same presence-check pattern as
// defaultDSCP.
func defaultPort(cfg map[string]interface{}, key string, def uint16) uint16 {
	if v, ok := cfg[key]; ok && v != nil {
		return getUint16(cfg, key)
	}
	return def
}

func getBool(m map[string]interface{}, key string, def bool) bool {
	if v, ok := m[key].(bool); ok {
		return v
	}
	return def
}

// getBoolWithFallback reads a bool from preferredKey, falling back to
// legacyKey when preferredKey is absent. Used for renamed bool fields
// (e.g. "is_response" replacing "response" on UDP/DNS) so existing DB
// rows keep working.
func getBoolWithFallback(m map[string]interface{}, preferredKey, legacyKey string, def bool) bool {
	if v, ok := m[preferredKey].(bool); ok {
		return v
	}
	if v, ok := m[legacyKey].(bool); ok {
		return v
	}
	return def
}

// getStringWithFallback reads a string from preferredKey, falling back to
// legacyKey when preferredKey is absent. Used for renamed string fields
// (e.g. "response_content_encoding" replacing "content_encoding") so
// existing DB rows keep working.
func getStringWithFallback(m map[string]interface{}, preferredKey, legacyKey string) string {
	if v, ok := m[preferredKey].(string); ok {
		return v
	}
	if v, ok := m[legacyKey].(string); ok {
		return v
	}
	return ""
}

func getStringMap(m map[string]interface{}, key string) map[string]string {
	result := make(map[string]string)
	if sub, ok := m[key].(map[string]interface{}); ok {
		for k, v := range sub {
			if s, ok := v.(string); ok {
				result[k] = s
			}
		}
	}
	return result
}

// getFloatDefault returns the float64 value for key when present and non-nil
// (0.0 is a valid user value for RootDelay/RootDispersion), and def when the
// key is absent or null. Mirrors the presence-check pattern of defaultDSCP
// /defaultIPFlags so explicit 0 is honored rather than silently replaced.
func getFloatDefault(m map[string]interface{}, key string, def float64) float64 {
	if v, ok := m[key]; ok && v != nil {
		switch f := v.(type) {
		case float64:
			return f
		case int:
			return float64(f)
		case int64:
			return float64(f)
		case json.Number:
			n, err := f.Float64()
			if err == nil {
				return n
			}
		}
	}
	return def
}

// getTime parses an RFC 3339 timestamp string into time.Time. Empty string,
// missing key, or null returns the zero time.Time (which the NTP planner
// treats as "not set" and emits as 0). Parse errors also return the zero
// time -- mapToFlowSpec collects parse errors elsewhere; here we want a
// best-effort conversion so the planner can still emit a packet.
func getTime(m map[string]interface{}, key string) time.Time {
	v, ok := m[key]
	if !ok || v == nil {
		return time.Time{}
	}
	s, ok := v.(string)
	if !ok || s == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}
	}
	return t
}

// getByteSlice converts a JSON-decoded value into []byte. Accepts a string
// (taken as raw bytes) or an array of numbers (each byte 0-255). nil/missing
// returns nil so the planner skips the field entirely.
func getByteSlice(m map[string]interface{}, key string) []byte {
	v, ok := m[key]
	if !ok || v == nil {
		return nil
	}
	switch b := v.(type) {
	case string:
		return []byte(b)
	case []interface{}:
		out := make([]byte, 0, len(b))
		for _, n := range b {
			if f, ok := n.(float64); ok {
				out = append(out, byte(int(f)))
			}
		}
		return out
	}
	return nil
}

// parseNTPExtensions converts the JSON-decoded "extensions" value (an array
// of {type, value} objects) into a []NTPExt. Returns nil for absent/non-array
// input so the planner skips extension emission. Each extension's Value may
// be a string (raw bytes) or a number array (each byte 0-255); the planner
// 0-pads to a 4-byte boundary before emitting.
// Pointer-typed helpers for fields where the zero value is meaningful
// (e.g. *bool, *uint32). These return nil when the key is absent, so the
// planner can distinguish "user did not set" from "user set to 0/false".
// Used by IKE MessageID/InitiatorSPI/ResponderSPI, PostgreSQL
// EmitHandshake/EmitTeardown, MDNS CacheFlush, etc.

func getBoolPtr(m map[string]interface{}, key string) *bool {
	v, ok := m[key]
	if !ok || v == nil {
		return nil
	}
	if b, ok := v.(bool); ok {
		return &b
	}
	return nil
}

func getUint8Ptr(m map[string]interface{}, key string) *uint8 {
	v, ok := m[key]
	if !ok || v == nil {
		return nil
	}
	switch n := v.(type) {
	case float64:
		u := uint8(n)
		return &u
	case json.Number:
		i, err := n.Int64()
		if err != nil {
			return nil
		}
		u := uint8(i)
		return &u
	}
	return nil
}

func getUint16Ptr(m map[string]interface{}, key string) *uint16 {
	v, ok := m[key]
	if !ok || v == nil {
		return nil
	}
	switch n := v.(type) {
	case float64:
		u := uint16(n)
		return &u
	case json.Number:
		i, err := n.Int64()
		if err != nil {
			return nil
		}
		u := uint16(i)
		return &u
	}
	return nil
}

func getUint32Ptr(m map[string]interface{}, key string) *uint32 {
	v, ok := m[key]
	if !ok || v == nil {
		return nil
	}
	switch n := v.(type) {
	case float64:
		u := uint32(n)
		return &u
	case json.Number:
		i, err := n.Int64()
		if err != nil {
			return nil
		}
		u := uint32(i)
		return &u
	}
	return nil
}

func getUint64Ptr(m map[string]interface{}, key string) *uint64 {
	v, ok := m[key]
	if !ok || v == nil {
		return nil
	}
	switch n := v.(type) {
	case float64:
		u := uint64(n)
		return &u
	case json.Number:
		i, err := n.Int64()
		if err != nil {
			return nil
		}
		u := uint64(i)
		return &u
	}
	return nil
}

func getInt32Ptr(m map[string]interface{}, key string) *int32 {
	v, ok := m[key]
	if !ok || v == nil {
		return nil
	}
	switch n := v.(type) {
	case float64:
		i := int32(n)
		return &i
	case json.Number:
		j, err := n.Int64()
		if err != nil {
			return nil
		}
		i := int32(j)
		return &i
	}
	return nil
}

// getUint16Slice reads a JSON array of numbers into a []uint16.
func getUint16Slice(m map[string]interface{}, key string) []uint16 {
	arr, ok := m[key].([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]uint16, 0, len(arr))
	for _, item := range arr {
		switch n := item.(type) {
		case float64:
			out = append(out, uint16(n))
		case json.Number:
			if i, err := n.Int64(); err == nil {
				out = append(out, uint16(i))
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// getUint8Slice reads a JSON array of numbers into a []uint8.
func getUint8Slice(m map[string]interface{}, key string) []uint8 {
	arr, ok := m[key].([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]uint8, 0, len(arr))
	for _, item := range arr {
		switch n := item.(type) {
		case float64:
			out = append(out, uint8(n))
		case json.Number:
			if i, err := n.Int64(); err == nil {
				out = append(out, uint8(i))
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// getStringSlice reads a JSON array of strings into a []string.
func getStringSlice(m map[string]interface{}, key string) []string {
	arr, ok := m[key].([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, item := range arr {
		if s, ok := item.(string); ok && s != "" {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// getByteSlices reads a JSON array of byte-array/string entries into a [][]byte.
// Each entry may be a string (raw bytes) or an array of integers (0-255).
func getByteSlices(m map[string]interface{}, key string) [][]byte {
	arr, ok := m[key].([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([][]byte, 0, len(arr))
	for _, item := range arr {
		b := parseByteSlice(item)
		if b != nil {
			out = append(out, b)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// getInt32MapKeysValues reads a map[int]int32 (used by PostgreSQL ColumnTypes).
func getInt32MapValues(m map[string]interface{}, key string) map[int]int32 {
	sub, ok := m[key].(map[string]interface{})
	if !ok || len(sub) == 0 {
		return nil
	}
	out := make(map[int]int32, len(sub))
	for k, v := range sub {
		// JSON keys are strings; parse to int
		var idx int
		if _, err := fmt.Sscanf(k, "%d", &idx); err != nil {
			continue
		}
		switch n := v.(type) {
		case float64:
			out[idx] = int32(n)
		case json.Number:
			if j, err := n.Int64(); err == nil {
				out[idx] = int32(j)
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// decodeBase64 decodes a standard base64-encoded string. Used by RDP
// payload_b64 / shadowsocks / IKE raw fields. Returns nil on error (the
// caller treats nil as "no payload set" which is the correct fallback).
func decodeBase64(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

func parseNTPExtensions(v interface{}) []NTPExt {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]NTPExt, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		ext := NTPExt{
			Type:  uint16(getInt(m, "type")),
			Value: getByteSlice(m, "value"),
		}
		out = append(out, ext)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
