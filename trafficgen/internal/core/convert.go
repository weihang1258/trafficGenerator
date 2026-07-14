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

	validProtocols := map[string]bool{
		"tcp":  true,
		"udp":  true,
		"http": true,
		"dns":  true,
		"icmp": true,
		"arp":  true,
	}

	if !validProtocols[task.Protocol] {
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
	validProtocols := map[string]bool{
		"tcp": true, "udp": true, "http": true, "dns": true, "icmp": true, "arp": true,
		"replay": true,
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
		if !validProtocols[c.Type] {
			return fmt.Errorf("class[%d] %s: invalid type %s", i, c.ID, c.Type)
		}
		// Replay classes don't use FlowCount/FlowSpec -- they replay a pcap
		// asset's packets via the replay planner. Validate the replay spec itself.
		if c.Type == "replay" {
			if len(c.Replay) == 0 {
				return fmt.Errorf("class[%d] %s: replay class missing 'replay' spec", i, c.ID)
			}
			if err := validateReplaySpec(c.Replay); err != nil {
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
		// Validate the class's spec fields (DSCP/ECN/VLAN/MSS ranges, IP format).
		if err := ValidateFlowSpec(mapToFlowSpec(c.Config, c.Type)); err != nil {
			return fmt.Errorf("class[%d] %s: %w", i, c.ID, err)
		}
	}
	return nil
}

// validateReplaySpec validates a replay spec JSON (§16.4): speed mode,
// direction, checksum_mode, and that required fields are present. Catches
// submission-time errors (e.g. bogus speed mode silently falling back to max,
// dual without interface2) before the task runs and fails silently.
func validateReplaySpec(specJSON json.RawMessage) error {
	var spec struct {
		PcapAssetID string `json:"pcap_asset_id"`
		Speed       struct {
			Mode       string  `json:"mode"`
			Multiplier float64 `json:"multiplier"`
			BPS        string  `json:"bps"`
			PPS        float64 `json:"pps"`
		} `json:"speed"`
		Direction    string `json:"direction"`
		ChecksumMode string `json:"checksum_mode"`
	}
	if err := json.Unmarshal(specJSON, &spec); err != nil {
		return fmt.Errorf("invalid replay spec JSON: %w", err)
	}
	if spec.PcapAssetID == "" {
		return fmt.Errorf("replay spec missing pcap_asset_id")
	}
	switch spec.Speed.Mode {
	case "original", "multiplier", "bps", "pps", "max", "":
		// valid
	default:
		return fmt.Errorf("invalid speed mode %q (want original|multiplier|bps|pps|max)", spec.Speed.Mode)
	}
	if spec.Speed.Mode == "bps" && spec.Speed.BPS == "" {
		return fmt.Errorf("bps mode requires a bps value")
	}
	if spec.Speed.Mode == "pps" && spec.Speed.PPS <= 0 {
		return fmt.Errorf("pps mode requires pps > 0")
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
