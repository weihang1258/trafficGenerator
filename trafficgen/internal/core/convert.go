package core

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
)

// generateTaskID generates a unique task ID.
func generateTaskID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return "task-" + hex.EncodeToString(b)
}

// APIRequestToTask converts an API request to an internal Task.
func APIRequestToTask(name, description, protocol string, spec FlowSpec, iface string) Task {
	return Task{
		ID:          generateTaskID(),
		Name:        name,
		Description: description,
		Protocol:    protocol,
		Spec:        spec,
		Interface:   iface,
	}
}

// TaskToAPIResponse converts a Task and TaskStatus to API response format.
func TaskToAPIResponse(task Task, status TaskStatus) map[string]interface{} {
	return map[string]interface{}{
		"id":          task.ID,
		"name":        task.Name,
		"description": task.Description,
		"protocol":    task.Protocol,
		"status":      status.Status,
		"progress":    status.Progress,
		"stats":       status.Stats,
		"created_at":  status.CreatedAt.Unix(),
		"started_at":  status.StartedAt.Unix(),
	}
}

// ParseMAC parses a MAC address string.
func ParseMAC(mac string) (net.HardwareAddr, error) {
	return net.ParseMAC(mac)
}

// ParseIP parses an IP address string.
func ParseIP(ip string) (net.IP, error) {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return nil, fmt.Errorf("invalid IP address: %s", ip)
	}
	return parsed, nil
}

// ParseBPS parses a BPS string like "200k", "1M", "1g".
func ParseBPS(bps string) (int64, error) {
	if bps == "" {
		return 0, nil
	}

	multiplier := int64(1)
	last := bps[len(bps)-1]

	switch last {
	case 'k', 'K':
		multiplier = 1000
		bps = bps[:len(bps)-1]
	case 'm', 'M':
		multiplier = 1000 * 1000
		bps = bps[:len(bps)-1]
	case 'g', 'G':
		multiplier = 1000 * 1000 * 1000
		bps = bps[:len(bps)-1]
	}

	value, err := strconv.ParseInt(bps, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid BPS value: %s", bps)
	}

	return value * multiplier, nil
}

// FlowSpecToPacketConfigs converts a FlowSpec to a channel of PacketConfigs.
// This is implemented by protocol-specific planners.
type FlowSpecToPacketConfigsFunc func(spec FlowSpec) (<-chan PacketConfig, error)

// ValidateTask validates a Task.
func ValidateTask(task Task) error {
	if task.Name == "" {
		return fmt.Errorf("task name is required")
	}

	// Mixed-traffic (batch) tasks validate each class instead of a single spec.
	if task.Batch != nil {
		return ValidateBatchSpec(*task.Batch)
	}

	// Replay tasks validate the ReplaySpec JSON instead of protocol/spec.
	// The pcap's own protocols populate the wire bytes, so Protocol/Spec are
	// informational and not validated here.
	if task.Mode == "replay" || len(task.Replay) > 0 {
		return ValidateReplaySpec(task.Replay)
	}

	if !IsAllowedProtocol(task.Protocol) {
		return fmt.Errorf("invalid protocol: %s", task.Protocol)
	}

	if err := ValidateFlowSpec(task.Spec); err != nil {
		return fmt.Errorf("invalid spec: %w", err)
	}

	return nil
}

// ValidateBatchSpec validates a mixed-traffic batch specification.
func ValidateBatchSpec(batch BatchSpec) error {
	if len(batch.Classes) == 0 {
		return fmt.Errorf("batch must contain at least one traffic class")
	}
	seenIDs := make(map[string]bool)
	for i, c := range batch.Classes {
		if c.ID == "" {
			return fmt.Errorf("class[%d]: id is required", i)
		}
		if seenIDs[c.ID] {
			return fmt.Errorf("class[%d] %s: duplicate class id (ids must be unique within a batch)", i, c.ID)
		}
		seenIDs[c.ID] = true
		if !IsAllowedProtocol(c.Type) {
			return fmt.Errorf("class[%d] %s: invalid type %s", i, c.ID, c.Type)
		}
		// Replay classes don't use FlowCount/FlowSpec -- they replay a pcap
		// asset's packets via the replay planner. Validate the replay spec itself.
		if c.Type == "replay" {
			if len(c.Replay) == 0 {
				return fmt.Errorf("class[%d] %s: replay class missing 'replay' spec", i, c.ID)
			}
			if err := ValidateReplaySpec(c.Replay); err != nil {
				return fmt.Errorf("class[%d] %s: %w", i, c.ID, err)
			}
			continue
		}
		if c.FlowCount <= 0 {
			return fmt.Errorf("class[%d] %s: flow_count must be > 0", i, c.ID)
		}
		// Validate raw DSCP/ECN/VLAN ranges BEFORE mapToFlowSpec truncates them
		// to uint8/uint16. Without this, dscp=256 silently wraps to 0 (valid).
		if err := ValidateConfigRanges(c.Config); err != nil {
			return fmt.Errorf("class[%d] %s: %w", i, c.ID, err)
		}
		// Validate per-protocol sub-config fields (tcp.mss, icmp.type, etc.)
		// that also truncate silently through uint16/uint8.
		if err := ValidateProtocolSubConfigs(c.Config, c.Type); err != nil {
			return fmt.Errorf("class[%d] %s: %w", i, c.ID, err)
		}
		// Step 1（全协议扁平删除）：batch 类顶层四元组/count 同判死——
		// 与 strategy create/update 同口径（core.CheckProtoFlat 单一真相，
		// schema 包 import core，反向复用成环故此处调 core 导出函数）。
		if msg := CheckProtoFlat(c.Type, c.Config); msg != "" {
			return fmt.Errorf("class[%d] %s: %s", i, c.ID, msg)
		}
		// D-FTP-3 (CORE_MEMORY §1): layers 与顶层扁平四元组混用拒绝——
		// 与 strategy create/update 同口径（schema.checkLayerFlatConflict），
		// 此处重复 6 行检查而非复用（schema 包 import core，反向复用成环）。
		if _, hasLayers := c.Config["layers"]; hasLayers {
			for _, k := range []string{"src_ip", "dst_ip", "src_port", "dst_port"} {
				if v, ok := c.Config[k]; ok && v != nil {
					return fmt.Errorf("class[%d] %s: config mixes layers with flat four-tuple field %s (use ip.src/ip.dst for addresses, tcp/udp src_port/dst_port for ports)", i, c.ID, k)
				}
			}
		}
		// Validate the class's spec fields (DSCP/ECN/VLAN/MSS ranges, IP format).
		if err := ValidateFlowSpec(mapToFlowSpec(c.Config, c.Type)); err != nil {
			return fmt.Errorf("class[%d] %s: %w", i, c.ID, err)
		}
	}
	return nil
}

// ValidateReplaySpec validates a replay spec JSON (§16.4): speed mode,
// direction, checksum_mode, and that required fields are present. Catches
// submission-time errors (e.g. bogus speed mode silently falling back to max,
// dual without interface2) before the task runs and fails silently.
//
// Speed modes are reduced to original|multiplier|bps|"" (unrestricted). pps and
// max were dropped: max folds to empty (unrestricted) and pps is removed (replay
// rate is either timestamp-paced or byte-paced). bps requires a parseable bps
// value (validated via ParseBPS so a typo like "2xx" is caught at submit time,
// not when the engine first builds the token bucket).
func ValidateReplaySpec(specJSON json.RawMessage) error {
	var spec struct {
		PcapAssetID string `json:"pcap_asset_id"`
		Loop        *int   `json:"loop,omitempty"`
		Speed       struct {
			Mode       string  `json:"mode"`
			Multiplier float64 `json:"multiplier"`
			BPS        string  `json:"bps"`
		} `json:"speed"`
		Direction    string `json:"direction"`
		ChecksumMode string `json:"checksum_mode"`
	}
	if err := json.Unmarshal(specJSON, &spec); err != nil {
		return fmt.Errorf("invalid replay spec JSON: %w", err)
	}
	// 负 loop 在 strategy create 时即拒（此前要到 task start 的 Plan 才报），
	// 与 P1-13 的 planner 侧拒绝同一文案。
	if spec.Loop != nil && *spec.Loop < 0 {
		return fmt.Errorf("loop must be >= 0 (0 = infinite, omit for a single pass), got %d", *spec.Loop)
	}
	if spec.PcapAssetID == "" {
		return fmt.Errorf("replay spec missing pcap_asset_id")
	}
	switch spec.Speed.Mode {
	case "original", "multiplier", "bps", "":
		// valid
	default:
		return fmt.Errorf("invalid speed mode %q (want original|multiplier|bps)", spec.Speed.Mode)
	}
	// M4: multiplier <= 0 is invalid. Without this, NewPacer silently falls
	// back to 1.0 (pacing.go:31) so a typo like multiplier:0 or multiplier:-1
	// replays at original speed instead of erroring. 0 and negative are
	// nonsensical for a speed multiplier (0 = freeze, negative = reverse time)
	// and almost always typos or miscalculations, not intent.
	if spec.Speed.Mode == "multiplier" && spec.Speed.Multiplier <= 0 {
		return fmt.Errorf("multiplier mode requires multiplier > 0 (got %v)", spec.Speed.Multiplier)
	}
	if spec.Speed.Mode == "bps" {
		if spec.Speed.BPS == "" {
			return fmt.Errorf("bps mode requires a bps value")
		}
		if _, err := ParseBPS(spec.Speed.BPS); err != nil {
			return fmt.Errorf("bps mode invalid bps value %q: %w", spec.Speed.BPS, err)
		}
	}
	switch spec.Direction {
	case "single", "dual", "":
		// valid
	default:
		return fmt.Errorf("invalid direction %q (want single|dual)", spec.Direction)
	}
	switch spec.ChecksumMode {
	case "recompute", "preserve", "":
		// valid
	default:
		return fmt.Errorf("invalid checksum_mode %q (want recompute|preserve)", spec.ChecksumMode)
	}
	return nil
}
