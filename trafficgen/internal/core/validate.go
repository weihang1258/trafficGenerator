package core

import "fmt"

// ValidateFlowSpec validates a FlowSpec. Empty/zero values mean "use default"
// and are accepted; only genuinely invalid values (out-of-range, malformed)
// are rejected. IP/MAC format is checked when present.
func ValidateFlowSpec(spec FlowSpec) error {
	// IP addresses
	if spec.SrcIP != "" {
		if _, err := ParseIP(spec.SrcIP); err != nil {
			return fmt.Errorf("invalid src_ip: %w", err)
		}
	}
	if spec.DstIP != "" {
		if _, err := ParseIP(spec.DstIP); err != nil {
			return fmt.Errorf("invalid dst_ip: %w", err)
		}
	}

	// MAC addresses
	if spec.SrcMAC != "" {
		if _, err := ParseMAC(spec.SrcMAC); err != nil {
			return fmt.Errorf("invalid src_mac: %w", err)
		}
	}
	if spec.DstMAC != "" {
		if _, err := ParseMAC(spec.DstMAC); err != nil {
			return fmt.Errorf("invalid dst_mac: %w", err)
		}
	}

	// VLAN: ID 0 = no VLAN; valid range 0-4095. Priority 0-7.
	if spec.VLAN != nil {
		if spec.VLAN.ID > 4095 {
			return fmt.Errorf("vlan_id %d invalid (must be 0-4095)", spec.VLAN.ID)
		}
		if spec.VLAN.Priority > 7 {
			return fmt.Errorf("vlan_priority %d invalid (must be 0-7)", spec.VLAN.Priority)
		}
	}

	// DSCP is 6 bits (0-63); ECN is 2 bits (0-3). 0 is valid (best-effort / no ECN).
	if spec.DSCP > 63 {
		return fmt.Errorf("dscp %d invalid (must be 0-63)", spec.DSCP)
	}
	if spec.ECN > 3 {
		return fmt.Errorf("ecn %d invalid (must be 0-3)", spec.ECN)
	}

	// MSS: 0 = use default. When set, must be at least 536 (IP minimum MTU
	// minus headers) to produce viable TCP segments.
	if spec.TCP != nil && spec.TCP.MSS > 0 && spec.TCP.MSS < 536 {
		return fmt.Errorf("mss %d too small (must be 0 or >= 536)", spec.TCP.MSS)
	}

	return nil
}
