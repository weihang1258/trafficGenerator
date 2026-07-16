package core

import (
	"encoding/json"
	"fmt"

	"github.com/trafficgen/trafficgen/internal/storage"
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
func mapToFlowSpec(cfg map[string]interface{}, protocol string) FlowSpec {
	spec := FlowSpec{
		SrcIP:   getString(cfg, "src_ip"),
		DstIP:   getString(cfg, "dst_ip"),
		SrcPort: getUint16(cfg, "src_port"),
		DstPort: getUint16(cfg, "dst_port"),
		SrcMAC:  getString(cfg, "src_mac"),
		DstMAC:  getString(cfg, "dst_mac"),
		TTL:     uint8(getIntDefault(cfg, "ttl", 64)),
		TOS:     uint8(getInt(cfg, "tos")),
		DSCP:       uint8(getInt(cfg, "dscp")),
		ECN:        uint8(getInt(cfg, "ecn")),
		Flags:      uint8(getInt(cfg, "flags")),
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
			spec.HTTP = &HTTPConfig{
				Method:       getStringDefault(sub, "method", "GET"),
				URI:          getStringDefault(sub, "uri", "/"),
				Headers:      getStringMap(sub, "headers"),
				Body:         getString(sub, "body"),
				KeepAlive:    getBool(sub, "keep_alive", false),
				Transactions: getInt(sub, "transactions"),
				ThinkTime:    getInt(sub, "think_time"),
			}
		}
		if spec.DstPort == 0 {
			spec.DstPort = 80
		}
	case "dns":
		if sub, ok := cfg["dns"].(map[string]interface{}); ok {
			spec.DNS = &DNSConfig{
				Domain:     getString(sub, "domain"),
				QueryType:  uint16(getIntDefault(sub, "query_type", 1)),
				Response:   getBool(sub, "response", false),
				ResponseIP: getString(sub, "response_ip"),
			}
		}
		if spec.DstPort == 0 {
			spec.DstPort = 53
		}
	case "icmp":
		if sub, ok := cfg["icmp"].(map[string]interface{}); ok {
			spec.ICMP = &ICMPConfig{
				Type:     uint8(getIntDefault(sub, "type", 8)),
				Code:     uint8(getIntDefault(sub, "code", 0)),
				Sequence: uint16(getIntDefault(sub, "sequence", 1)),
				Data:     []byte(getStringDefault(sub, "data", "ping")),
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