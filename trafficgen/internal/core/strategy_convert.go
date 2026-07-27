package core

import (
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
				Domain:     getString(sub, "domain"),
				QueryType:  uint16(getIntDefault(sub, "query_type", 1)),
				IsResponse: getBoolWithFallback(sub, "is_response", "response", false),
				ResponseIP: getString(sub, "response_ip"),
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
		if _, ok := cfg["dhcp"].(map[string]interface{}); ok {
			spec.DHCP = &DHCPConfig{}
		}
		if _, ok := cfg["dst_port"]; !ok || cfg["dst_port"] == nil {
			spec.DstPort = 67
		}
	case "dhcpv6":
		if _, ok := cfg["dhcpv6"].(map[string]interface{}); ok {
			spec.DHCPv6 = &DHCPv6Config{}
		}
		if _, ok := cfg["dst_port"]; !ok || cfg["dst_port"] == nil {
			spec.DstPort = 547
		}
	case "grpc":
		if _, ok := cfg["grpc"].(map[string]interface{}); ok {
			spec.GRPC = &GRPCConfig{}
		}
		if _, ok := cfg["dst_port"]; !ok || cfg["dst_port"] == nil {
			spec.DstPort = 8604
		}
	case "ike":
		if _, ok := cfg["ike"].(map[string]interface{}); ok {
			spec.IKE = &IKEConfig{}
		}
		if _, ok := cfg["dst_port"]; !ok || cfg["dst_port"] == nil {
			spec.DstPort = 500
		}
	case "ike_nat_t":
		if _, ok := cfg["ike_nat_t"].(map[string]interface{}); ok {
			spec.IKENATT = &IKENATTConfig{}
		}
		if _, ok := cfg["dst_port"]; !ok || cfg["dst_port"] == nil {
			spec.DstPort = 4500
		}
	case "imap":
		if _, ok := cfg["imap"].(map[string]interface{}); ok {
			spec.IMAP = &IMAPConfig{}
		}
		if _, ok := cfg["dst_port"]; !ok || cfg["dst_port"] == nil {
			spec.DstPort = 143
		}
	case "l2tp":
		if _, ok := cfg["l2tp"].(map[string]interface{}); ok {
			spec.L2TP = &L2TPConfig{}
		}
		if _, ok := cfg["dst_port"]; !ok || cfg["dst_port"] == nil {
			spec.DstPort = 1701
		}
	case "mdns":
		if _, ok := cfg["mdns"].(map[string]interface{}); ok {
			spec.MDNS = &MDNSConfig{}
		}
		if _, ok := cfg["dst_port"]; !ok || cfg["dst_port"] == nil {
			spec.DstPort = 5353
		}
	case "mysql":
		if _, ok := cfg["mysql"].(map[string]interface{}); ok {
			spec.MySQL = &MySQLConfig{}
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
				Sequence:       uint8(getIntDefault(sub, "sequence", 0)),
				Implementation: uint8(getIntDefault(sub, "implementation", 0)),
				RequestCode:    uint8(getIntDefault(sub, "request_code", 0)),
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
		if _, ok := cfg["openvpn"].(map[string]interface{}); ok {
			spec.OpenVPN = &OpenVPNConfig{}
		}
		if _, ok := cfg["dst_port"]; !ok || cfg["dst_port"] == nil {
			spec.DstPort = 1194
		}
	case "postgresql":
		if _, ok := cfg["postgresql"].(map[string]interface{}); ok {
			spec.PostgreSQL = &PostgreSQLConfig{}
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
		if _, ok := cfg["rdp"].(map[string]interface{}); ok {
			spec.RDP = &RDPConfig{}
		}
		if _, ok := cfg["dst_port"]; !ok || cfg["dst_port"] == nil {
			spec.DstPort = 3389
		}
	case "redis":
		if _, ok := cfg["redis"].(map[string]interface{}); ok {
			spec.Redis = &RedisConfig{}
		}
		if _, ok := cfg["dst_port"]; !ok || cfg["dst_port"] == nil {
			spec.DstPort = 6379
		}
	case "shadowsocks":
		if _, ok := cfg["shadowsocks"].(map[string]interface{}); ok {
			spec.Shadowsocks = &ShadowsocksConfig{}
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
		if _, ok := cfg["ssdp"].(map[string]interface{}); ok {
			spec.SSDP = &SSDPConfig{}
		}
		if _, ok := cfg["dst_port"]; !ok || cfg["dst_port"] == nil {
			spec.DstPort = 1900
		}
	case "ssh":
		if _, ok := cfg["ssh"].(map[string]interface{}); ok {
			spec.SSH = &SSHConfig{}
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
		if _, ok := cfg["tls"].(map[string]interface{}); ok {
			spec.TLS = &TLSConfig{}
		}
		if _, ok := cfg["dst_port"]; !ok || cfg["dst_port"] == nil {
			spec.DstPort = 443
		}
	case "vmess":
		if _, ok := cfg["vmess"].(map[string]interface{}); ok {
			spec.Vmess = &VmessConfig{}
		}
		// vmess has no canonical port; user must specify.
	case "wireguard":
		if _, ok := cfg["wireguard"].(map[string]interface{}); ok {
			spec.WireGuard = &WireGuardConfig{}
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
