package core

import (
	"crypto/rand"
	"encoding/hex"
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
	}
	for i, c := range batch.Classes {
		if c.ID == "" {
			return fmt.Errorf("class[%d]: id is required", i)
		}
		if !validProtocols[c.Type] {
			return fmt.Errorf("class[%d] %s: invalid type %s", i, c.ID, c.Type)
		}
		if c.FlowCount <= 0 {
			return fmt.Errorf("class[%d] %s: flow_count must be > 0", i, c.ID)
		}
		// Validate the class's spec fields (DSCP/ECN/VLAN/MSS ranges, IP format).
		if err := ValidateFlowSpec(mapToFlowSpec(c.Config, c.Type)); err != nil {
			return fmt.Errorf("class[%d] %s: %w", i, c.ID, err)
		}
	}
	return nil
}
