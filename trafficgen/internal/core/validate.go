package core

import (
	"fmt"
	"strings"

	"go.uber.org/zap"
)

// ValidateConfigRanges checks DSCP/ECN/VLAN/Flags/FragOffset/TTL/TOS/Port values in
// the raw config map before mapToFlowSpec truncates them to uint8/uint16.
// Without this, an out-of-range value like dscp=256 silently wraps to 0
// (valid) because uint8(256)==0, and negative values wrap to large unsigned
// values. getInt returns the untruncated int, so both upper- and lower-bound
// violations are caught here.
func ValidateConfigRanges(cfg map[string]interface{}) error {
	if d := getInt(cfg, "dscp"); d < 0 || d > 63 {
		return fmt.Errorf("dscp %d invalid (must be 0-63)", d)
	}
	if e := getInt(cfg, "ecn"); e < 0 || e > 3 {
		return fmt.Errorf("ecn %d invalid (must be 0-3)", e)
	}
	if v := getInt(cfg, "vlan_id"); v < 0 || v > 4095 {
		return fmt.Errorf("vlan_id %d invalid (must be 0-4095)", v)
	}
	if p := getInt(cfg, "vlan_priority"); p < 0 || p > 7 {
		return fmt.Errorf("vlan_priority %d invalid (must be 0-7)", p)
	}
	// IP flags: 3-bit field (reserved|DF|MF). Valid 0-7; reserved bit (0x04)
	// should be 0 but is masked by the builder, so only range-check here.
	// Backward compat: "ip_flags" is the preferred key; "flags" is the legacy
	// key (ambiguous with TCP flags) read as fallback by defaultIPFlags.
	if f := getIntWithFallback(cfg, "ip_flags", "flags"); f < 0 || f > 7 {
		return fmt.Errorf("ip_flags %d invalid (must be 0-7)", f)
	}
	// Fragment offset: 13-bit field (0-8191), in 8-byte units.
	if fo := getInt(cfg, "frag_offset"); fo < 0 || fo > 8191 {
		return fmt.Errorf("frag_offset %d invalid (must be 0-8191)", fo)
	}
	// TTL/TOS: 8-bit fields (0-255). 0 means "use default"; >255 silently wraps.
	if ttl := getInt(cfg, "ttl"); ttl < 0 || ttl > 255 {
		return fmt.Errorf("ttl %d invalid (must be 0-255)", ttl)
	}
	if tos := getInt(cfg, "tos"); tos < 0 || tos > 255 {
		return fmt.Errorf("tos %d invalid (must be 0-255)", tos)
	}
	// src_port/dst_port: 16-bit fields (0-65535). getUint16 truncates 65536 to 0
	// and -1 to 65535, the same silent-wrap class of bug as the uint8 fields above.
	if p := getInt(cfg, "src_port"); p < 0 || p > 65535 {
		return fmt.Errorf("src_port %d invalid (must be 0-65535)", p)
	}
	if p := getInt(cfg, "dst_port"); p < 0 || p > 65535 {
		return fmt.Errorf("dst_port %d invalid (must be 0-65535)", p)
	}
	return nil
}

// ValidateProtocolSubConfigs checks per-protocol sub-config fields (tcp.mss,
// tcp.window_size, dns.query_type, icmp.type/code/sequence, arp.operation)
// for truncation wraparound before mapToFlowSpec casts to uint16/uint8.
// These fields live in nested sub-maps (cfg["tcp"], etc.) that are invisible
// to ValidateConfigRanges's flat getInt lookups.
func ValidateProtocolSubConfigs(cfg map[string]interface{}, protocol string) error {
	switch protocol {
	case "tcp":
		if sub, ok := cfg["tcp"].(map[string]interface{}); ok {
			if m := getInt(sub, "mss"); m < 0 || m > 65535 {
				return fmt.Errorf("tcp.mss %d invalid (must be 0-65535)", m)
			}
			if w := getInt(sub, "window_size"); w < 0 || w > 65535 {
				return fmt.Errorf("tcp.window_size %d invalid (must be 0-65535)", w)
			}
			if s := getInt(sub, "initial_seq"); s < 0 {
				return fmt.Errorf("tcp.initial_seq %d invalid (must be >= 0)", s)
			}
		}
	case "dns":
		if sub, ok := cfg["dns"].(map[string]interface{}); ok {
			if q := getInt(sub, "query_type"); q < 0 || q > 65535 {
				return fmt.Errorf("dns.query_type %d invalid (must be 0-65535)", q)
			}
		}
	case "icmp":
		if sub, ok := cfg["icmp"].(map[string]interface{}); ok {
			if t := getInt(sub, "type"); t < 0 || t > 255 {
				return fmt.Errorf("icmp.type %d invalid (must be 0-255)", t)
			}
			if c := getInt(sub, "code"); c < 0 || c > 255 {
				return fmt.Errorf("icmp.code %d invalid (must be 0-255)", c)
			}
			if s := getInt(sub, "sequence"); s < 0 || s > 65535 {
				return fmt.Errorf("icmp.sequence %d invalid (must be 0-65535)", s)
			}
		}
	case "arp":
		if sub, ok := cfg["arp"].(map[string]interface{}); ok {
			if o := getInt(sub, "operation"); o < 0 || o > 65535 {
				return fmt.Errorf("arp.operation %d invalid (must be 0-65535)", o)
			}
		}
	case "http", "ftp", "sip", "amqp":
		// HTTP/FTP/SIP run over TCP (SIP also over UDP). MSS for payload
		// segmentation is governed by tcp.mss — validate here so users
		// can't smuggle out-of-range values past validation (the tcp case
		// only fires when protocol=="tcp", which http/ftp/sip never reach).
		if err := validateTCPMSS(cfg); err != nil {
			return err
		}
	case "sctp":
		if sub, ok := cfg["sctp"].(map[string]interface{}); ok {
			if t := getInt(sub, "verification_tag"); t < 0 {
				return fmt.Errorf("sctp.verification_tag %d invalid (must be >= 0)", t)
			}
			if t := getInt(sub, "initiate_tag"); t < 0 {
				return fmt.Errorf("sctp.initiate_tag %d invalid (must be >= 0)", t)
			}
			if s := getInt(sub, "sid"); s < 0 || s > 65535 {
				return fmt.Errorf("sctp.sid %d invalid (must be 0-65535)", s)
			}
			if s := getInt(sub, "ssn"); s < 0 || s > 65535 {
				return fmt.Errorf("sctp.ssn %d invalid (must be 0-65535)", s)
			}
		}
	case "icmpv6":
		if sub, ok := cfg["icmpv6"].(map[string]interface{}); ok {
			if t := getInt(sub, "type"); t < 0 || t > 255 {
				return fmt.Errorf("icmpv6.type %d invalid (must be 0-255)", t)
			}
			if c := getInt(sub, "code"); c < 0 || c > 255 {
				return fmt.Errorf("icmpv6.code %d invalid (must be 0-255)", c)
			}
			if s := getInt(sub, "sequence"); s < 0 || s > 65535 {
				return fmt.Errorf("icmpv6.sequence %d invalid (must be 0-65535)", s)
			}
		}
	case "dnp3":
		// DNP3 IIN is a uint16 field; parseDNP3Config's getUint16 silently
		// truncates out-of-range values (0x10000 -> 0), so an out-of-range
		// config would pass validation and complete the task with the wrong
		// IIN on the wire (design §7.6.2 T55). Reject before conversion.
		sub, hasDNP3 := cfg["dnp3"].(map[string]interface{})
		if !hasDNP3 {
			return nil
		}
		if i := getInt(sub, "iin"); i < 0 || i > 65535 {
			return fmt.Errorf("dnp3.iin %d invalid (must be 0-65535)", i)
		}
	case "tftp":
		// TFTP fields: most cross-protocol / inter-field checks (V20 mutex,
		// V9 ErrorAfterBlock constraints, V12 ServerTIDChange mutex) require
		// the parsed FlowSpec and are enforced by tftp.Planner.Validate at
		// plan time. This layer catches the simple per-field range / enum
		// violations that would otherwise reach plan() and hang the task.
		sub, hasTFTP := cfg["tftp"].(map[string]interface{})
		if !hasTFTP {
			return nil
		}
		if v, ok := sub["mode"].(string); ok && v != "" {
			lo := strings.ToLower(strings.TrimSpace(v))
			if lo != "read" && lo != "write" {
				return fmt.Errorf("tftp.mode %q invalid (must be read or write)", v)
			}
		}
		if v, ok := sub["transfer_mode"].(string); ok && v != "" {
			lo := strings.ToLower(strings.TrimSpace(v))
			if lo == "mail" {
				return fmt.Errorf("tftp.transfer_mode %q is deprecated and unsupported", v)
			}
			if lo != "netascii" && lo != "octet" {
				return fmt.Errorf("tftp.transfer_mode %q invalid (must be netascii or octet)", v)
			}
		}
		if v, ok := sub["error_side"].(string); ok && v != "" {
			lo := strings.ToLower(strings.TrimSpace(v))
			if lo != "server" && lo != "client" {
				return fmt.Errorf("tftp.error_side %q invalid (must be server or client)", v)
			}
		}
		if b := getInt(sub, "blksize"); b != 0 && (b < 8 || b > 65464) {
			return fmt.Errorf("tftp.blksize %d out of range (8-65464)", b)
		}
		if t := getInt(sub, "timeout"); t != 0 && (t < 1 || t > 255) {
			return fmt.Errorf("tftp.timeout %d out of range (1-255)", t)
		}
		if w := getInt(sub, "windowsize"); w != 0 && (w < 1 || w > 65535) {
			return fmt.Errorf("tftp.windowsize %d out of range (1-65535)", w)
		}
		if e := getInt(sub, "error_code"); e < 0 || e > 8 {
			return fmt.Errorf("tftp.error_code %d out of range (0-8)", e)
		}
		if s := getInt(sub, "server_tid"); s != 0 && s < 1024 {
			return fmt.Errorf("tftp.server_tid %d in well-known range (<1024)", s)
		}
	case "enip":
		// ENIP EPATH 字段：class_id 是 uint16、instance_id 是 uint32 编码
		// （设计 §7.3 T-104/T-105）。转换层 getUint16/getUint32 会静默截断
		// 超范围值（0x10000→0、0x100000000→0），截断后无法按字段编码，
		// 必须在转换前拒绝。commands 是数组，这里逐项检查 raw map。
		sub, hasENIP := cfg["enip"].(map[string]interface{})
		if !hasENIP {
			return nil
		}
		if cmds, ok := sub["commands"].([]interface{}); ok {
			for i, item := range cmds {
				cmd, ok := item.(map[string]interface{})
				if !ok {
					continue
				}
				if c := getInt(cmd, "class_id"); c < 0 || c > 65535 {
					return fmt.Errorf("enip.commands[%d].class_id out of range: %d (must be 0-65535)", i, c)
				}
				if in := getInt(cmd, "instance_id"); in < 0 || in > 4294967295 {
					return fmt.Errorf("enip.commands[%d].instance_id out of range: %d (must be 0-4294967295)", i, in)
				}
			}
		}
		// EPATH 字段也出现在 sub_requests 数组（Multiple_Service_Packet），
		// 转换层 parseENIPSubRequests 同样用 getUint16/getUint32 静默截断，
		// 必须一并检查。
		if srs, ok := sub["sub_requests"].([]interface{}); ok {
			for j, item := range srs {
				sr, ok := item.(map[string]interface{})
				if !ok {
					continue
				}
				if c := getInt(sr, "class_id"); c < 0 || c > 65535 {
					return fmt.Errorf("enip.sub_requests[%d].class_id out of range: %d (must be 0-65535)", j, c)
				}
				if in := getInt(sr, "instance_id"); in < 0 || in > 4294967295 {
					return fmt.Errorf("enip.sub_requests[%d].instance_id out of range: %d (must be 0-4294967295)", j, in)
				}
			}
		}
	}
	return nil
}

// validateTCPMSS validates tcp.mss in cfg when present. Shared by the
// http/ftp/sip cases since they all run over TCP and use tcp.mss for
// payload segmentation. Returns nil when tcp sub-config is absent (the
// planner falls back to its default MSS).
func validateTCPMSS(cfg map[string]interface{}) error {
	sub, ok := cfg["tcp"].(map[string]interface{})
	if !ok {
		return nil
	}
	if m := getInt(sub, "mss"); m < 0 || m > 65535 {
		return fmt.Errorf("tcp.mss %d invalid (must be 0-65535)", m)
	}
	return nil
}

func getIntWithFallback(m map[string]interface{}, preferredKey, legacyKey string) int {
	if v, ok := m[preferredKey]; ok && v != nil {
		return getInt(m, preferredKey)
	}
	return getInt(m, legacyKey)
}

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
		// 802.1Q VLAN ID 0 is a "priority tag" frame: the tag carries only
		// the priority bits and the VID is 0, meaning "this frame belongs to
		// no VLAN". Users who write `vlan: {id: 0, priority: 5}` almost
		// always intend a real VLAN and are surprised when the resulting
		// frame is treated as priority-only by switches. Warn (not error)
		// because priority-tagged frames are a valid 802.1Q construct.
		if spec.VLAN.ID == 0 {
			zap.L().Warn("VLAN ID=0 is priority-tag (802.1Q), not a real VLAN",
				zap.String("note", "set vlan.id >= 1 for a real VLAN"),
			)
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
