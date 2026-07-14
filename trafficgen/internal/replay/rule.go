package replay

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/pcapparser"
	"github.com/trafficgen/trafficgen/internal/storage"
)

// matchRule reports whether a FlowMatcher matches a flow, bidirectionally
// (§16.4): the matcher's src/dst may match the flow's src/dst in EITHER
// direction. Empty/zero matcher fields are wildcards. SrcIP/DstIP support
// CIDR notation (e.g. "10.0.0.0/8") in addition to exact match.
func matchRule(m FlowMatcher, flow storage.FlowModel) bool {
	if m.Protocol != "" && flow.L4Protocol != m.Protocol {
		return false
	}
	// Bidirectional: src/dst may be swapped.
	srcIPMatch := m.SrcIP == "" || ipMatch(m.SrcIP, flow.SrcIP) || ipMatch(m.SrcIP, flow.DstIP)
	dstIPMatch := m.DstIP == "" || ipMatch(m.DstIP, flow.DstIP) || ipMatch(m.DstIP, flow.SrcIP)
	srcPortMatch := m.SrcPort == 0 || m.SrcPort == flow.SrcPort || m.SrcPort == flow.DstPort
	dstPortMatch := m.DstPort == 0 || m.DstPort == flow.DstPort || m.DstPort == flow.SrcPort
	// If both src and dst are set, they must match as a pair (either direction),
	// not cross-matched independently. This avoids matching (A->B) matcher to a
	// (A->C) flow when only A is set.
	if m.SrcIP != "" && m.DstIP != "" {
		pair1 := ipMatch(m.SrcIP, flow.SrcIP) && ipMatch(m.DstIP, flow.DstIP)
		pair2 := ipMatch(m.SrcIP, flow.DstIP) && ipMatch(m.DstIP, flow.SrcIP)
		if !pair1 && !pair2 {
			return false
		}
	} else if !srcIPMatch || !dstIPMatch {
		return false
	}
	if m.SrcPort != 0 && m.DstPort != 0 {
		pair1 := m.SrcPort == flow.SrcPort && m.DstPort == flow.DstPort
		pair2 := m.SrcPort == flow.DstPort && m.DstPort == flow.SrcPort
		if !pair1 && !pair2 {
			return false
		}
	} else if !srcPortMatch || !dstPortMatch {
		return false
	}
	return true
}

// ipMatch reports whether a pattern matches an IP string. The pattern may be
// an exact IP ("10.0.0.1") or a CIDR ("10.0.0.0/8").
func ipMatch(pattern, ipStr string) bool {
	if pattern == ipStr {
		return true
	}
	_, cidr, err := net.ParseCIDR(pattern)
	if err != nil {
		return false
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	return cidr.Contains(ip)
}

// fieldSpec describes how to patch a logical field: its offset in the layout,
// the layer (for checksum scope), and the byte width.
type fieldSpec struct {
	offset int
	layer  string
	width  int
}

// fieldSpecFor resolves a target field name to its layout offset + layer + width.
// Returns ok=false for unsupported targets (caller validates against the
// flow's protocol -- e.g. don't patch ports on an ARP flow).
// Returns a conflictKey for conflict detection: fields that share the same byte
// (e.g. dscp and ecn both map to the TOS byte) use the same conflictKey so
// setting both via two rules triggers a conflict (they must be set via a single
// TOS value or the user must choose one or the other).
func fieldSpecFor(layout pcapparser.OffsetLayout, target string) (fieldSpec, bool) {
	switch target {
	case "src_ip":
		return fieldSpec{layout.SrcIP, "l3", 4}, true
	case "dst_ip":
		return fieldSpec{layout.DstIP, "l3", 4}, true
	case "src_port":
		return fieldSpec{layout.SrcPort, "l4", 2}, true
	case "dst_port":
		return fieldSpec{layout.DstPort, "l4", 2}, true
	case "src_mac":
		return fieldSpec{layout.SrcMAC, "l2", 6}, true
	case "dst_mac":
		return fieldSpec{layout.DstMAC, "l2", 6}, true
	case "ttl":
		return fieldSpec{layout.TTL, "l3", 1}, true
	case "dscp":
		return fieldSpec{layout.DSCPECN, "l3", 1}, true
	case "ecn":
		return fieldSpec{layout.DSCPECN, "l3", 1}, true
	case "ip_id":
		return fieldSpec{layout.IPID, "l3", 2}, true
	case "seq":
		return fieldSpec{layout.Seq, "l4", 4}, true
	case "ack":
		return fieldSpec{layout.Ack, "l4", 4}, true
	case "window":
		return fieldSpec{layout.Window, "l4", 2}, true
	case "tcp_flags":
		return fieldSpec{layout.TCPFlags, "l4", 1}, true
	}
	return fieldSpec{}, false
}

// encodeValue encodes a string value into bytes for the given target field.
func encodeValue(target, value string) ([]byte, error) {
	switch target {
	case "src_ip", "dst_ip", "src_mac", "dst_mac":
		ip := net.ParseIP(value)
		if target == "src_mac" || target == "dst_mac" {
			hw, err := net.ParseMAC(value)
			if err != nil {
				return nil, fmt.Errorf("invalid MAC %q: %w", value, err)
			}
			return hw, nil
		}
		if ip == nil {
			return nil, fmt.Errorf("invalid IP %q", value)
		}
		if v4 := ip.To4(); v4 != nil {
			return v4, nil
		}
		return nil, fmt.Errorf("IPv6 not supported in v1: %q", value)
	case "src_port", "dst_port", "window", "ip_id":
		port, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			return nil, fmt.Errorf("invalid port %q: %w", value, err)
		}
		b := make([]byte, 2)
		binary.BigEndian.PutUint16(b, uint16(port))
		return b, nil
	case "ttl", "tcp_flags":
		v, err := strconv.ParseUint(value, 10, 8)
		if err != nil {
			return nil, fmt.Errorf("invalid byte %q: %w", value, err)
		}
		return []byte{byte(v)}, nil
	case "dscp":
		v, err := strconv.ParseUint(value, 10, 8)
		if err != nil {
			return nil, fmt.Errorf("invalid dscp %q: %w", value, err)
		}
		return []byte{byte(v) << 2}, nil // DSCP is the high 6 bits of TOS
	case "ecn":
		v, err := strconv.ParseUint(value, 10, 8)
		if err != nil {
			return nil, fmt.Errorf("invalid ecn %q: %w", value, err)
		}
		return []byte{byte(v) & 0x03}, nil // ECN is the low 2 bits of TOS
	case "seq", "ack":
		v, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid u32 %q: %w", value, err)
		}
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, uint32(v))
		return b, nil
	}
	return nil, fmt.Errorf("unsupported target %q", target)
}

// resolveStrategyValue resolves a core.StrategyConfig to a single string value
// for a flow-level patch. v1 supports "fixed" (and "list" first element) for
// rules; inc/random are used by FlowScaling (R8) for per-clone variation.
func resolveStrategyValue(sc core.StrategyConfig) (string, error) {
	switch sc.Strategy {
	case "fixed":
		if sc.Value == nil {
			return "", fmt.Errorf("fixed strategy missing value")
		}
		return fmt.Sprintf("%v", sc.Value), nil
	case "list":
		if len(sc.List) > 0 {
			return sc.List[0], nil
		}
		return "", fmt.Errorf("list strategy empty")
	default:
		return "", fmt.Errorf("strategy %q not supported for flow-level rules (use FlowScaling for inc/random)", sc.Strategy)
	}
}

// computeFlowPatches matches rules against a flow's ORIGINAL values and
// generates flow-level patches (mapping + field), with conflict detection (§7).
// Endpoint patches are per-packet (direction-dependent) and are generated by
// the planner via endpointPatch. Returns the patches and matched rule count.
//
// Conflict detection keys on the byte offset (not field name), so fields that
// share the same byte (e.g. dscp + ecn both on the TOS byte) are caught.
func computeFlowPatches(flow storage.FlowModel, layout pcapparser.OffsetLayout, rules []RewriteRule) ([]Patch, error) {
	var patches []Patch
	fieldSeen := map[string][]byte{} // field -> bytes (conflict detection)
	offsetSeen := map[int]string{}   // offset -> first field name for overlap detection
	for _, rule := range rules {
		if !matchRule(rule.Match, flow) {
			continue
		}
		rp, err := genFlowPatches(rule, flow, layout)
		if err != nil {
			return nil, fmt.Errorf("rule kind %q: %w", rule.Kind, err)
		}
		for _, p := range rp {
			// Byte-offset conflict detection: two rules touching the same byte
			// must be compatible. DSCP and ECN are special: they share the TOS
			// byte and should be merged (DSCP<<2 | ECN&0x03). All other
			// overlapping offsets are a conflict.
			if firstName, ok := offsetSeen[p.Offset]; ok {
				if firstName == p.Field {
					// Same field: check value equality (idempotent).
					existing := fieldSeen[p.Field]
					if !bytesEqual(existing, p.Bytes) {
						return nil, fmt.Errorf("conflict: field %s set to both %x and %x", p.Field, existing, p.Bytes)
					}
					continue
				}
				// Different fields, same offset. Check for DSCP+ECN merge.
				if (firstName == "dscp" && p.Field == "ecn") || (firstName == "ecn" && p.Field == "dscp") {
					// Merge: already have the first field's bytes, patch with
					// the second field's bits. ECN is low 2 bits, DSCP is high 6.
					existing := fieldSeen[firstName]
					merged := make([]byte, 1)
					if firstName == "dscp" {
						merged[0] = existing[0] | (p.Bytes[0] & 0x03) // existing DSCP + new ECN
					} else {
						merged[0] = (p.Bytes[0] & 0xFC) | (existing[0] & 0x03) // new DSCP + existing ECN
					}
					// Replace the existing patch with the merged value.
					for i := range patches {
						if patches[i].Offset == p.Offset {
							patches[i].Bytes = merged
							break
						}
					}
					fieldSeen[p.Field] = p.Bytes
					continue
				}
				return nil, fmt.Errorf("conflict: offset %d (fields %s and %s) would overlap", p.Offset, firstName, p.Field)
			}
			fieldSeen[p.Field] = p.Bytes
			offsetSeen[p.Offset] = p.Field
			patches = append(patches, p)
		}
	}
	return patches, nil
}

// applyIPMap applies an ipmap mapping table to a flow's src/dst IP (§6). Both
// exact-match ("10.0.0.1" -> "11.0.0.1") and CIDR network-segment translation
// ("10.0.0.0/8" -> "192.168.0.0/16", preserving the host offset within the
// subnet) are supported. Returns flow-level patches for src_ip/dst_ip.
func applyIPMap(mapping map[string]string, flow storage.FlowModel, layout pcapparser.OffsetLayout) ([]Patch, error) {
	var patches []Patch
	if layout.SrcIP >= 0 {
		if newVal, ok := lookupIPMap(mapping, flow.SrcIP); ok {
			enc, err := encodeValue("src_ip", newVal)
			if err != nil {
				return nil, fmt.Errorf("ipmap src %q: %w", newVal, err)
			}
			patches = append(patches, Patch{Field: "src_ip", Offset: layout.SrcIP, Bytes: enc, Layer: "l3"})
		}
	}
	if layout.DstIP >= 0 {
		if newVal, ok := lookupIPMap(mapping, flow.DstIP); ok {
			enc, err := encodeValue("dst_ip", newVal)
			if err != nil {
				return nil, fmt.Errorf("ipmap dst %q: %w", newVal, err)
			}
			patches = append(patches, Patch{Field: "dst_ip", Offset: layout.DstIP, Bytes: enc, Layer: "l3"})
		}
	}
	return patches, nil
}

// lookupIPMap resolves an IP through the mapping table. Returns (newIP, true) if
// a mapping applies. Keys may be exact IPs or CIDRs; CIDR keys translate the IP
// into the target subnet preserving the host offset (§6 "网段平移保偏移").
func lookupIPMap(mapping map[string]string, ipStr string) (string, bool) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "", false
	}
	// First try exact match (fast path).
	if newVal, ok := mapping[ipStr]; ok {
		return newVal, true
	}
	// CIDR keys: find the most specific matching network and translate.
	var bestMask int = -1
	var bestNew string
	found := false
	for k, v := range mapping {
		_, cidr, err := net.ParseCIDR(k)
		if err != nil {
			continue
		}
		if !cidr.Contains(ip) {
			continue
		}
		ones, _ := cidr.Mask.Size()
		if ones > bestMask {
			bestMask = ones
			bestNew = translateCIDR(ip, cidr, v)
			found = true
		}
	}
	return bestNew, found
}

// translateCIDR maps an IP from the source CIDR to the target CIDR, preserving
// the host offset within the subnet (§6 "网段平移保偏移"). E.g.
// 10.0.0.5 in 10.0.0.0/8 -> 192.168.0.0/16 yields 192.168.0.5.
func translateCIDR(ip net.IP, srcCIDR *net.IPNet, targetSpec string) string {
	_, dstCIDR, err := net.ParseCIDR(targetSpec)
	if err != nil {
		// target is a single IP, not a CIDR -- use it directly (exact translation).
		if v := net.ParseIP(targetSpec); v != nil {
			return v.String()
		}
		return targetSpec
	}
	// v1 is IPv4-only (IPv6 address rewrite is v2). Work on 4-byte form.
	v4 := ip.To4()
	if v4 == nil {
		if v := net.ParseIP(targetSpec); v != nil {
			return v.String()
		}
		return targetSpec
	}
	srcOnes, _ := srcCIDR.Mask.Size()
	dstOnes, _ := dstCIDR.Mask.Size()
	// Host offset of ip within srcCIDR (low srcHostBits bits).
	srcHostBits := 32 - srcOnes
	hostOffset := ipToUint(v4) & maskLowBits(srcHostBits)
	// If the target subnet is smaller, restrict the offset to its host bits.
	dstHostBits := 32 - dstOnes
	if dstHostBits < srcHostBits {
		hostOffset = hostOffset & maskLowBits(dstHostBits)
	}
	dstBase := ipToUint(dstCIDR.IP.To4())
	newIP := dstBase | hostOffset
	return uintToIP4(newIP).String()
}

// ipToUint converts a 4-byte IPv4 to a uint32.
func ipToUint(ip net.IP) uint32 {
	v4 := ip.To4()
	if v4 == nil {
		return 0
	}
	return uint32(v4[0])<<24 | uint32(v4[1])<<16 | uint32(v4[2])<<8 | uint32(v4[3])
}

// uintToIP4 converts a uint32 to a 4-byte IPv4.
func uintToIP4(v uint32) net.IP {
	return net.IPv4(byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

// maskLowBits returns a uint32 with the low n bits set.
func maskLowBits(n int) uint32 {
	if n <= 0 {
		return 0
	}
	if n >= 32 {
		return 0xFFFFFFFF
	}
	return (1 << uint(n)) - 1
}

// genFlowPatches generates the flow-level patches for one matched rule.
func genFlowPatches(rule RewriteRule, flow storage.FlowModel, layout pcapparser.OffsetLayout) ([]Patch, error) {
	switch rule.Kind {
	case "ipmap":
		return applyIPMap(rule.Mapping, flow, layout)
	case "portmap":
		var patches []Patch
		srcStr := strconv.Itoa(int(flow.SrcPort))
		dstStr := strconv.Itoa(int(flow.DstPort))
		if newVal, ok := rule.Mapping[srcStr]; ok && layout.SrcPort >= 0 {
			enc, err := encodeValue("src_port", newVal)
			if err != nil {
				return nil, fmt.Errorf("portmap src %q: %w", newVal, err)
			}
			patches = append(patches, Patch{Field: "src_port", Offset: layout.SrcPort, Bytes: enc, Layer: "l4"})
		}
		if newVal, ok := rule.Mapping[dstStr]; ok && layout.DstPort >= 0 {
			enc, err := encodeValue("dst_port", newVal)
			if err != nil {
				return nil, fmt.Errorf("portmap dst %q: %w", newVal, err)
			}
			patches = append(patches, Patch{Field: "dst_port", Offset: layout.DstPort, Bytes: enc, Layer: "l4"})
		}
		return patches, nil
	case "macmap":
		// MACs aren't in FlowModel; macmap is per-packet (planner reads MACs
		// from raw bytes). Return no flow-level patches.
		return nil, nil
	case "field":
		return genFieldPatches(rule, layout)
	case "endpoint":
		// Endpoint is per-packet (direction-dependent); no flow-level patches.
		return nil, nil
	}
	return nil, fmt.Errorf("unknown rule kind %q", rule.Kind)
}

// genFieldPatches generates a patch for a "field" rule at the target's offset.
// Rules with apply:offset return no flow-level patch -- they are handled
// per-packet by the planner (the original value varies per packet, so the delta
// must be added to each packet's original value, §6).
func genFieldPatches(rule RewriteRule, layout pcapparser.OffsetLayout) ([]Patch, error) {
	if rule.Apply == "offset" {
		// Validated + collected by the planner; no flow-level patch here.
		return nil, nil
	}
	spec, ok := fieldSpecFor(layout, rule.Target)
	if !ok {
		return nil, fmt.Errorf("unsupported target %q", rule.Target)
	}
	if spec.offset < 0 {
		return nil, fmt.Errorf("target %q absent in this flow's layout", rule.Target)
	}
	valStr, err := resolveStrategyValue(rule.Strategy)
	if err != nil {
		return nil, err
	}
	enc, err := encodeValue(rule.Target, valStr)
	if err != nil {
		return nil, err
	}
	return []Patch{{Field: rule.Target, Offset: spec.offset, Bytes: enc, Layer: spec.layer}}, nil
}

// resolveOffsetDelta resolves an apply:offset rule's strategy to a uint32 delta.
// Used by the planner for per-packet offset patches (seq/ack/ip_id, §6).
func resolveOffsetDelta(rule RewriteRule) (uint32, error) {
	valStr, err := resolveStrategyValue(rule.Strategy)
	if err != nil {
		return 0, err
	}
	v, err := strconv.ParseUint(valStr, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("offset delta %q: %w", valStr, err)
	}
	return uint32(v), nil
}

// endpointPatch generates a per-packet endpoint patch (§6): for client_ip,
// c2s patches src_ip (client is src), s2c patches dst_ip (client is dst).
// server_ip is the reverse.
func endpointPatch(dir, target string, newVal net.IP, layout pcapparser.OffsetLayout) (Patch, error) {
	var offset int
	switch target {
	case "client_ip":
		if dir == "c2s" {
			offset = layout.SrcIP
		} else {
			offset = layout.DstIP
		}
	case "server_ip":
		if dir == "c2s" {
			offset = layout.DstIP
		} else {
			offset = layout.SrcIP
		}
	case "client_port":
		if dir == "c2s" {
			offset = layout.SrcPort
		} else {
			offset = layout.DstPort
		}
	case "server_port":
		if dir == "c2s" {
			offset = layout.DstPort
		} else {
			offset = layout.SrcPort
		}
	default:
		return Patch{}, fmt.Errorf("unsupported endpoint target %q", target)
	}
	if offset < 0 {
		return Patch{}, fmt.Errorf("endpoint %q offset absent", target)
	}
	v4 := newVal.To4()
	if v4 == nil {
		return Patch{}, fmt.Errorf("endpoint IP not IPv4: %v", newVal)
	}
	width := 4
	if strings.HasSuffix(target, "_port") {
		width = 2
	}
	bytes := v4
	if width == 2 {
		// Port value: newVal is actually a port encoded as an IP -- handle via
		// the caller passing a proper port. For v1, endpoint ports use a
		// separate path; here we only handle IP endpoints.
		return Patch{}, fmt.Errorf("endpoint port patching not supported via IP path")
	}
	return Patch{Field: target, Offset: offset, Bytes: bytes, Layer: "l3"}, nil
}

// resolveStrategyConfigValue and strategyValueProvider removed: strategy
// resolution uses core.StrategyConfig directly via resolveStrategyValue.

// bytesEqual compares two byte slices.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
