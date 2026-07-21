package core

import (
	"encoding/json"
	"fmt"

	"github.com/trafficgen/trafficgen/internal/storage"
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

	// DefaultSrcIP / DefaultDstIP: TEST-NET-1 (RFC 5737) addresses reserved
	// for documentation/testing. Public routers drop these, so trafficgen
	// packets never leak into real networks. Users running real-traffic
	// tests override with actual routable IPs.
	DefaultSrcIP = "192.0.2.1"
	DefaultDstIP = "192.0.2.2"

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
// fields where 0 is a valid user choice (DSCP=best-effort, Flags=no-DF) use
// hasKey to distinguish "absent" from "explicitly 0".
func mapToFlowSpec(cfg map[string]interface{}, protocol string) FlowSpec {
	spec := FlowSpec{
		SrcIP:   defaultString(cfg, "src_ip", DefaultSrcIP),
		DstIP:   defaultString(cfg, "dst_ip", DefaultDstIP),
		SrcPort: defaultPort(cfg, "src_port", DefaultSrcPort),
		DstPort: defaultPort(cfg, "dst_port", DefaultDstPort),
		SrcMAC:  defaultMAC(cfg, "src_mac", DefaultSrcMAC),
		DstMAC:  defaultMAC(cfg, "dst_mac", DefaultDstMAC),
		TTL:     uint8(getIntDefault(cfg, "ttl", 64)),
		TOS:     uint8(getInt(cfg, "tos")),
		DSCP:       defaultDSCP(cfg),
		ECN:        uint8(getInt(cfg, "ecn")),
		Flags:      defaultIPFlags(cfg),
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

	// Protocol-specific config
	switch protocol {
	case "tcp":
		if sub, ok := cfg["tcp"].(map[string]interface{}); ok {
			spec.TCP = &TCPConfig{
				Handshake:   getBool(sub, "handshake", true),
				Termination: getBool(sub, "termination", true),
				MSS:         getUint16(sub, "mss"),
				WindowSize:  getUint16(sub, "window_size"),
			}
		}
	case "udp":
		if sub, ok := cfg["udp"].(map[string]interface{}); ok {
			spec.UDP = &UDPConfig{
				Response: getBool(sub, "response", false),
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
				Method:            getStringDefault(sub, "method", "GET"),
				URI:               getStringDefault(sub, "uri", "/"),
				Version:           getString(sub, "version"),
				RequestHeaders:    reqHeaders,
				Body:              getString(sub, "body"),
				KeepAlive:         getBool(sub, "keep_alive", false),
				Transactions:      getInt(sub, "transactions"),
				ThinkTime:         getInt(sub, "think_time"),
				ResponseHeaders:    getStringMap(sub, "response_headers"),
				ResponseBody:       getString(sub, "response_body"),
				ResponseStatusCode: getInt(sub, "response_status_code"),
				ResponseStatusText: getString(sub, "response_status_text"),
				ContentEncoding:    getString(sub, "content_encoding"),
				MSS:                getUint16(sub, "mss"),
			}
		}
		// HTTP defaults to port 80, same as DefaultDstPort. No override
		// needed here -- mapToFlowSpec's defaultPort call already set it.
	case "dns":
		if sub, ok := cfg["dns"].(map[string]interface{}); ok {
			spec.DNS = &DNSConfig{
				Domain:     getString(sub, "domain"),
				QueryType:  uint16(getIntDefault(sub, "query_type", 1)),
				Response:   getBool(sub, "response", false),
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
				Banner:   getString(sub, "banner"),
				Commands: parseFTPCommands(sub["commands"]),
				MSS:      getUint16(sub, "mss"),
			}
		}
		// FTP defaults to port 21 (control channel). Only override when
		// the user did not specify a dst_port — matches the DNS override
		// pattern.
		if _, ok := cfg["dst_port"]; !ok || cfg["dst_port"] == nil {
			spec.DstPort = 21
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

	// InitialSeq: optional TCP initial sequence number override. 0 = random
	// (default). Non-zero fixes client ISN for reproducible tests. Without
	// this, user JSON "initial_seq" is silently dropped and always random.
	if v, ok := cfg["initial_seq"]; ok && v != nil {
		spec.InitialSeq = uint32(getInt(cfg, "initial_seq"))
	}

	return spec
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
			Cmd:      getString(m, "cmd"),
			Response: getString(m, "response"),
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// JSON helper functions with sensible defaults

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

// defaultIPFlags returns the user-provided IP flags when the "flags" key is
// present in cfg AND non-nil (even if 0 = allow fragmentation), and
// DefaultIPFlags (DF=1) when the key is absent or null. Same presence + nil
// check rationale as defaultDSCP: flags=0 is a valid user choice.
func defaultIPFlags(cfg map[string]interface{}) uint8 {
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