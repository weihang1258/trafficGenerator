package replay

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"strconv"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/pcapparser"
)

// generateClones produces N clones with per-clone replacement values resolved
// from the FlowScaling strategy configs (§16.8). Each clone gets a consistent
// set of IP/port/MAC values (one value per field per clone) + a seq offset.
func generateClones(fs *FlowScaling) ([]Clone, error) {
	if fs == nil || fs.Count <= 0 {
		return nil, nil
	}
	clones := make([]Clone, fs.Count)
	for k := 0; k < fs.Count; k++ {
		srcIP, err := resolveCloneStr(fs.SrcIP, k, true)
		if err != nil {
			return nil, fmt.Errorf("clone %d src_ip: %w", k, err)
		}
		dstIP, err := resolveCloneStr(fs.DstIP, k, true)
		if err != nil {
			return nil, fmt.Errorf("clone %d dst_ip: %w", k, err)
		}
		srcPort, err := resolveClonePort(fs.SrcPort, k)
		if err != nil {
			return nil, fmt.Errorf("clone %d src_port: %w", k, err)
		}
		dstPort, err := resolveClonePort(fs.DstPort, k)
		if err != nil {
			return nil, fmt.Errorf("clone %d dst_port: %w", k, err)
		}
		srcMAC, _ := resolveCloneStr(fs.SrcMAC, k, false)
		dstMAC, _ := resolveCloneStr(fs.DstMAC, k, false)
		seqOff, err := resolveCloneSeq(fs.SeqOffset, k)
		if err != nil {
			return nil, fmt.Errorf("clone %d seq_offset: %w", k, err)
		}
		clones[k] = Clone{
			Index: k, SrcIP: srcIP, DstIP: dstIP, SrcPort: srcPort, DstPort: dstPort,
			SrcMAC: srcMAC, DstMAC: dstMAC, SeqOffset: seqOff,
		}
	}
	return clones, nil
}

// resolveCloneStr resolves a StrategyConfig to a string value for clone k.
// isIP hints that inc should increment the IP's 4-byte value.
func resolveCloneStr(sc core.StrategyConfig, k int, isIP bool) (string, error) {
	switch sc.Strategy {
	case "", "fixed":
		if sc.Value == nil {
			return "", nil // field not configured -> no patch
		}
		return fmt.Sprintf("%v", sc.Value), nil
	case "inc":
		if len(sc.Range) < 2 {
			return "", fmt.Errorf("inc strategy needs range")
		}
		start := fmt.Sprintf("%v", sc.Range[0])
		step := sc.Step
		if step == 0 {
			step = 1
		}
		if isIP {
			return incIP(start, k*step)
		}
		// Numeric inc (port/mac-as-number).
		n, err := strconv.ParseInt(start, 10, 64)
		if err != nil {
			return start, nil // non-numeric: return start unchanged
		}
		return strconv.FormatInt(n+int64(k*step), 10), nil
	case "random":
		if len(sc.Range) < 2 {
			return "", fmt.Errorf("random strategy needs range")
		}
		lo := fmt.Sprintf("%v", sc.Range[0])
		hi := fmt.Sprintf("%v", sc.Range[1])
		return randomInRange(lo, hi, sc.Seed, k, isIP)
	case "list":
		if len(sc.List) == 0 {
			return "", fmt.Errorf("list strategy empty")
		}
		return sc.List[k%len(sc.List)], nil
	}
	return "", fmt.Errorf("unsupported strategy %q", sc.Strategy)
}

// resolveClonePort resolves a port strategy for clone k.
func resolveClonePort(sc core.StrategyConfig, k int) (uint16, error) {
	s, err := resolveCloneStr(sc, k, false)
	if err != nil || s == "" {
		return 0, err
	}
	n, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return 0, fmt.Errorf("port %q: %w", s, err)
	}
	return uint16(n), nil
}

// resolveCloneSeq resolves a seq offset strategy for clone k.
func resolveCloneSeq(sc core.StrategyConfig, k int) (uint32, error) {
	if sc.Strategy == "" || sc.Strategy == "fixed" {
		if sc.Value == nil {
			return 0, nil
		}
		v, err := strconv.ParseUint(fmt.Sprintf("%v", sc.Value), 10, 32)
		return uint32(v), err
	}
	s, err := resolveCloneStr(sc, k, false)
	if err != nil || s == "" {
		return 0, err
	}
	v, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("seq %q: %w", s, err)
	}
	return uint32(v), nil
}

// incIP increments an IPv4 address by n (treating it as a 32-bit number).
func incIP(ipStr string, n int) (string, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "", fmt.Errorf("invalid IP %q", ipStr)
	}
	v4 := ip.To4()
	if v4 == nil {
		return "", fmt.Errorf("not IPv4: %q", ipStr)
	}
	val := binary.BigEndian.Uint32(v4)
	val += uint32(n)
	out := make([]byte, 4)
	binary.BigEndian.PutUint32(out, val)
	return net.IP(out).String(), nil
}

// randomInRange returns a random value in [lo, hi] for clone k, using a seed.
// For IPs, picks a random IP in the range; for numbers, a random int.
func randomInRange(lo, hi string, seed int64, k int, isIP bool) (string, error) {
	if isIP {
		loIP := net.ParseIP(lo).To4()
		hiIP := net.ParseIP(hi).To4()
		if loIP == nil || hiIP == nil {
			return "", fmt.Errorf("invalid IP range %q..%q", lo, hi)
		}
		loV := binary.BigEndian.Uint32(loIP)
		hiV := binary.BigEndian.Uint32(hiIP)
		if hiV < loV {
			loV, hiV = hiV, loV
		}
		r := newRand(seed, k)
		val := loV + uint32(r.Int63n(int64(hiV-loV+1)))
		out := make([]byte, 4)
		binary.BigEndian.PutUint32(out, val)
		return net.IP(out).String(), nil
	}
	loN, err := strconv.ParseInt(lo, 10, 64)
	if err != nil {
		return "", fmt.Errorf("invalid range lo %q", lo)
	}
	hiN, err := strconv.ParseInt(hi, 10, 64)
	if err != nil {
		return "", fmt.Errorf("invalid range hi %q", hi)
	}
	if hiN < loN {
		loN, hiN = hiN, loN
	}
	r := newRand(seed, k)
	val := loN + r.Int63n(hiN-loN+1)
	return strconv.FormatInt(val, 10), nil
}

// newRand creates a deterministic rand source from a seed + clone index.
func newRand(seed int64, k int) *rand.Rand {
	if seed == 0 {
		seed = 1
	}
	return rand.New(rand.NewSource(seed + int64(k)))
}

// clonePatches generates the per-clone patches (IP/port/MAC) for a clone.
// Seq offset is handled separately (per-packet, since origSeq varies).
func clonePatches(c Clone, layout pcapparser.OffsetLayout) []Patch {
	var patches []Patch
	if c.SrcIP != "" && layout.SrcIP >= 0 {
		if b, err := encodeValue("src_ip", c.SrcIP); err == nil {
			patches = append(patches, Patch{Field: "src_ip", Offset: layout.SrcIP, Bytes: b, Layer: "l3"})
		}
	}
	if c.DstIP != "" && layout.DstIP >= 0 {
		if b, err := encodeValue("dst_ip", c.DstIP); err == nil {
			patches = append(patches, Patch{Field: "dst_ip", Offset: layout.DstIP, Bytes: b, Layer: "l3"})
		}
	}
	if c.SrcPort != 0 && layout.SrcPort >= 0 {
		b := make([]byte, 2)
		binary.BigEndian.PutUint16(b, c.SrcPort)
		patches = append(patches, Patch{Field: "src_port", Offset: layout.SrcPort, Bytes: b, Layer: "l4"})
	}
	if c.DstPort != 0 && layout.DstPort >= 0 {
		b := make([]byte, 2)
		binary.BigEndian.PutUint16(b, c.DstPort)
		patches = append(patches, Patch{Field: "dst_port", Offset: layout.DstPort, Bytes: b, Layer: "l4"})
	}
	if c.SrcMAC != "" && layout.SrcMAC >= 0 {
		if b, err := encodeValue("src_mac", c.SrcMAC); err == nil {
			patches = append(patches, Patch{Field: "src_mac", Offset: layout.SrcMAC, Bytes: b, Layer: "l2"})
		}
	}
	if c.DstMAC != "" && layout.DstMAC >= 0 {
		if b, err := encodeValue("dst_mac", c.DstMAC); err == nil {
			patches = append(patches, Patch{Field: "dst_mac", Offset: layout.DstMAC, Bytes: b, Layer: "l2"})
		}
	}
	return patches
}

// seqOffsetPatch generates a seq patch for a packet: origSeq + clone.SeqOffset.
// origSeq is read from the packet's raw bytes at layout.Seq.
func seqOffsetPatch(raw []byte, clone Clone, layout pcapparser.OffsetLayout) (Patch, bool) {
	if clone.SeqOffset == 0 || layout.Seq < 0 || layout.Seq+4 > len(raw) {
		return Patch{}, false
	}
	origSeq := binary.BigEndian.Uint32(raw[layout.Seq : layout.Seq+4])
	newSeq := origSeq + clone.SeqOffset
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, newSeq)
	return Patch{Field: "seq", Offset: layout.Seq, Bytes: b, Layer: "l4"}, true
}

// checkFlowScalingConflict verifies FlowScaling (vary) doesn't collide with a
// field/endpoint rule (set) on the same field (§16.6). Mapping rules are
// allowed (substitution coexists with clone variation).
func checkFlowScalingConflict(fs *FlowScaling, rules []RewriteRule) error {
	if fs == nil {
		return nil
	}
	// Fields varied by FlowScaling (strategy set).
	varied := map[string]bool{}
	if fs.SrcIP.Strategy != "" {
		varied["src_ip"] = true
	}
	if fs.DstIP.Strategy != "" {
		varied["dst_ip"] = true
	}
	if fs.SrcPort.Strategy != "" {
		varied["src_port"] = true
	}
	if fs.DstPort.Strategy != "" {
		varied["dst_port"] = true
	}
	if fs.SrcMAC.Strategy != "" {
		varied["src_mac"] = true
	}
	if fs.DstMAC.Strategy != "" {
		varied["dst_mac"] = true
	}
	// Endpoint targets map to src/dst fields.
	endpointField := map[string]string{
		"client_ip": "src_ip", "server_ip": "dst_ip",
		"client_port": "src_port", "server_port": "dst_port",
	}
	for _, rule := range rules {
		if rule.Kind == "field" && varied[rule.Target] {
			return fmt.Errorf("conflict: FlowScaling varies %s but a field rule sets it", rule.Target)
		}
		if rule.Kind == "endpoint" {
			if f, ok := endpointField[rule.Target]; ok && varied[f] {
				return fmt.Errorf("conflict: FlowScaling varies %s but an endpoint rule sets %s", f, rule.Target)
			}
		}
	}
	return nil
}
