package core

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"strconv"
	"strings"
)

// Layer-dynamic allowlist (D-FTP-3 §4): only these layer fields accept a
// dynamic object. Anything else seeing an object is rejected by ValidateLayers
// ("field X does not support dynamic"); parseLayerDyn only READS allowlisted
// fields so a non-allowlisted object never reaches resolution (defense in
// depth — ValidateLayers is authoritative).
var layerDynAllowlist = map[string]map[string]bool{
	"ip":  {"src": true, "dst": true, "ttl": true},
	"tcp": {"src_port": true, "dst_port": true},
	"udp": {"src_port": true, "dst_port": true},
	"eth": {"src_mac": true, "dst_mac": true},
}

// parseLayerDyn extracts per-flow dynamic strategies from a decoded layers
// array ([]any of single-key {layer: config} maps). Object values on
// allowlisted fields become *StrategyConfig; malformed objects produce
// "layers[i](name).field: ..." errors for spec.ValidationErrors. Returns
// (nil, nil) when no dynamic object is present.
func parseLayerDyn(layersVal interface{}) (*LayerDynValues, []string) {
	arr, ok := layersVal.([]interface{})
	if !ok {
		return nil, nil
	}
	out := &LayerDynValues{}
	var errs []string
	set := func(where, lname, field string, dst **StrategyConfig, v interface{}) {
		m, ok := v.(map[string]interface{})
		if !ok {
			return // scalar or absent: not dynamic
		}
		raw, err := json.Marshal(m)
		if err != nil {
			errs = append(errs, where+": invalid object")
			return
		}
		var sc StrategyConfig
		if err := json.Unmarshal(raw, &sc); err != nil {
			errs = append(errs, where+": invalid object")
			return
		}
		if msg := checkDynShape(where, lname, field, &sc); msg != "" {
			errs = append(errs, msg)
			return
		}
		*dst = &sc
	}
	for i, item := range arr {
		layer, _ := item.(map[string]interface{})
		if layer == nil {
			continue
		}
		for lname, allowed := range layerDynAllowlist {
			sub, _ := layer[lname].(map[string]interface{})
			if sub == nil {
				continue
			}
			for f := range allowed {
				v, ok := sub[f]
				if !ok || v == nil {
					continue
				}
				where := fmt.Sprintf("layers[%d](%s).%s", i, lname, f)
				switch lname {
				case "ip":
					switch f {
					case "src":
						set(where, lname, f, &out.IP.Src, v)
					case "dst":
						set(where, lname, f, &out.IP.Dst, v)
					case "ttl":
						set(where, lname, f, &out.IP.TTL, v)
					}
				case "tcp":
					if f == "src_port" {
						set(where, lname, f, &out.TCP.SrcPort, v)
					} else {
						set(where, lname, f, &out.TCP.DstPort, v)
					}
				case "udp":
					if f == "src_port" {
						set(where, lname, f, &out.UDP.SrcPort, v)
					} else {
						set(where, lname, f, &out.UDP.DstPort, v)
					}
				case "eth":
					if f == "src_mac" {
						set(where, lname, f, &out.Eth.SrcMAC, v)
					} else {
						set(where, lname, f, &out.Eth.DstMAC, v)
					}
				}
			}
		}
	}
	if !out.HasAny() && len(errs) == 0 {
		return nil, nil
	}
	if !out.HasAny() {
		return nil, errs
	}
	return out, errs
}

// checkDynShape validates one dynamic object (same rules as FTP
// validateDynFields + MAC/TTL allowlist): unknown strategy, bad range,
// empty list, bad pattern, pattern on IP/port/MAC/TTL. Range/list endpoints
// must parse in the field's type (IP/MAC/port/TTL) — unparseable endpoints
// are loud errors here, never silent empty resolutions downstream.
func checkDynShape(where, lname, field string, s *StrategyConfig) string {
	switch s.Strategy {
	case "fixed", "":
		return ""
	case "inc", "rand":
		if len(s.Range) != 2 {
			return fmt.Sprintf("%s: %s strategy requires a 2-element range", where, s.Strategy)
		}
		if msg := checkDynEndpoints(where, lname, field, s.Range); msg != "" {
			return msg
		}
		a, b := dynIntEnds(s.Range)
		if a > b {
			return fmt.Sprintf("%s: %s range start must not exceed end", where, s.Strategy)
		}
		return ""
	case "list":
		if len(s.List) == 0 {
			return fmt.Sprintf("%s: list strategy requires a non-empty list", where)
		}
		vals := make([]interface{}, len(s.List))
		for i, v := range s.List {
			vals[i] = v
		}
		if msg := checkDynEndpoints(where, lname, field, vals); msg != "" {
			return msg
		}
		return ""
	case "pattern":
		// Pattern is only meaningful for string-ish fields resolved via
		// genStringValue. IP/port/MAC/TTL use typed algorithms that have no
		// pattern case — reject here so the failure is loud, not a silent
		// empty resolution.
		return fmt.Sprintf("%s: pattern strategy is not supported for layer address/port fields", where)
	default:
		return fmt.Sprintf("%s: unknown dynamic strategy %q", where, s.Strategy)
	}
}

// dynIntEnds mirrors core.toInt for range endpoint comparison.
func dynIntEnds(r []interface{}) (int, int) {
	toI := func(v interface{}) int {
		switch x := v.(type) {
		case float64:
			return int(x)
		case int:
			return x
		case int64:
			return int(x)
		case string:
			n, _ := strconv.Atoi(x)
			return n
		}
		return 0
	}
	return toI(r[0]), toI(r[1])
}

// checkDynEndpoints verifies range/list endpoints parse in the field type.
func checkDynEndpoints(where, lname, field string, vals []interface{}) string {
	isIP := lname == "ip" && field != "ttl"
	isMAC := lname == "eth"
	isPort := (lname == "tcp" || lname == "udp")
	isTTL := lname == "ip" && field == "ttl"
	for _, v := range vals {
		switch {
		case isIP:
			str, _ := v.(string)
			if !validIPv4(str) {
				return fmt.Sprintf("%s: invalid IP endpoint %q", where, fmt.Sprint(v))
			}
		case isMAC:
			if _, ok := parseMAC(v); !ok {
				return fmt.Sprintf("%s: invalid MAC endpoint %q", where, fmt.Sprint(v))
			}
		case isPort:
			if toPort(v) == 0 && fmt.Sprint(v) != "0" {
				// toPort returns 0 for both "0" and garbage; only garbage is an error.
				return fmt.Sprintf("%s: invalid port endpoint %q", where, fmt.Sprint(v))
			}
		case isTTL:
			n := toInt(v)
			if n < 0 || n > 255 {
				return fmt.Sprintf("%s: invalid ttl endpoint %q", where, fmt.Sprint(v))
			}
		}
	}
	// MAC order check for inc/rand is done at resolve time (low-byte order);
	// cross-OUI ranges resolve empty (no-op). Keep loud-shape vs quiet-resolve
	// split: shape guarantees parseability, resolve guarantees bounds.
	return ""
}

// validIPv4 reports whether s is a parseable dotted IPv4 address.
func validIPv4(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || n > 255 {
			return false
		}
	}
	return true
}

// genMAC resolves a MAC StrategyConfig at flow index i (D-FTP-3 §4):
// fixed/list as-is; inc/rand advance the low 3 bytes with OUI (high 3 bytes)
// preserved and wrap; pattern unsupported (rejected by checkDynShape).
func genMAC(s StrategyConfig, index int) string {
	switch s.Strategy {
	case "fixed", "":
		if v, ok := s.Value.(string); ok {
			return v
		}
		return ""
	case "list":
		if len(s.List) == 0 {
			return ""
		}
		return s.List[index%len(s.List)]
	case "inc", "rand":
		if len(s.Range) != 2 {
			return ""
		}
		start, ok1 := parseMAC(s.Range[0])
		end, ok2 := parseMAC(s.Range[1])
		if !ok1 || !ok2 {
			return ""
		}
		startLo := start & 0xFFFFFF
		endLo := end & 0xFFFFFF
		if endLo < startLo {
			return ""
		}
		oui := start & 0xFF0000000000
		count := endLo - startLo + 1
		var off uint64
		if s.Strategy == "inc" {
			step := s.Step
			if step <= 0 {
				step = 1
			}
			off = uint64((index * step) % int(count))
		} else {
			r := rand.New(rand.NewSource(s.Seed + int64(index)))
			off = uint64(r.Int63n(int64(count)))
		}
		return formatMAC(oui | ((startLo + off) & 0xFFFFFF))
	default:
		return ""
	}
}

// parseMAC parses "xx:xx:xx:xx:xx:xx" to a uint64.
func parseMAC(v interface{}) (uint64, bool) {
	str, _ := v.(string)
	parts := strings.Split(str, ":")
	if len(parts) != 6 {
		return 0, false
	}
	var n uint64
	for _, p := range parts {
		b, err := strconv.ParseUint(p, 16, 8)
		if err != nil {
			return 0, false
		}
		n = n<<8 | b
	}
	return n, true
}

// formatMAC formats a uint64 as "xx:xx:xx:xx:xx:xx".
func formatMAC(n uint64) string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
		(n>>40)&0xFF, (n>>32)&0xFF, (n>>24)&0xFF,
		(n>>16)&0xFF, (n>>8)&0xFF, n&0xFF)
}

// genSmallInt resolves a small-integer StrategyConfig (TTL) at flow index i:
// fixed/list/inc/rand clamped to [min,max]; pattern unsupported.
func genSmallInt(s StrategyConfig, index int, min, max int) int {
	switch s.Strategy {
	case "fixed", "":
		return toInt(s.Value)
	case "list":
		if len(s.List) == 0 {
			return min
		}
		return toInt(s.List[index%len(s.List)])
	case "inc", "rand":
		if len(s.Range) != 2 {
			return min
		}
		start, end := toInt(s.Range[0]), toInt(s.Range[1])
		if end < start {
			return min
		}
		count := end - start + 1
		var v int
		if s.Strategy == "inc" {
			step := s.Step
			if step <= 0 {
				step = 1
			}
			v = start + (index*step)%count
		} else {
			r := rand.New(rand.NewSource(s.Seed + int64(index)))
			v = start + r.Intn(count)
		}
		if v < min {
			return min
		}
		if v > max {
			return max
		}
		return v
	default:
		return min
	}
}

// resolveLayerTuple applies parsed layer dynamics at flow index i onto the
// per-flow spec copy (D-FTP-3 §3). Non-zero resolutions win; zero/empty is a
// no-op preserving the static/default chain. Read-only on LayerDyn.
func resolveLayerTuple(spec *FlowSpec, i int) {
	ld := spec.LayerDyn
	if ld == nil {
		return
	}
	if ld.IP.Src != nil {
		if v := ResolveIPValue(ld.IP.Src, i); v != "" {
			spec.SrcIP = v
		}
	}
	if ld.IP.Dst != nil {
		if v := ResolveIPValue(ld.IP.Dst, i); v != "" {
			spec.DstIP = v
		}
	}
	if ld.IP.TTL != nil {
		if v := genSmallInt(*ld.IP.TTL, i, 0, 255); v != 0 {
			spec.TTL = uint8(v)
		}
	}
	if ld.TCP.SrcPort != nil {
		if v := ResolvePortValue(ld.TCP.SrcPort, i); v != 0 {
			spec.SrcPort = v
		}
	}
	if ld.TCP.DstPort != nil {
		if v := ResolvePortValue(ld.TCP.DstPort, i); v != 0 {
			spec.DstPort = v
		}
	}
	if ld.UDP.SrcPort != nil {
		if v := ResolvePortValue(ld.UDP.SrcPort, i); v != 0 {
			spec.SrcPort = v
		}
	}
	if ld.UDP.DstPort != nil {
		if v := ResolvePortValue(ld.UDP.DstPort, i); v != 0 {
			spec.DstPort = v
		}
	}
	if ld.Eth.SrcMAC != nil {
		if v := genMAC(*ld.Eth.SrcMAC, i); v != "" {
			spec.SrcMAC = v
		}
	}
	if ld.Eth.DstMAC != nil {
		if v := genMAC(*ld.Eth.DstMAC, i); v != "" {
			spec.DstMAC = v
		}
	}
}

// CheckLayerDynShape validates a decoded dynamic object for a layer field
// (exported for layers.checkLayerDynObjects; single truth with parseLayerDyn's
// checkDynShape). Returns "" when valid, else a human message prefixed with
// "lname.field: " (caller strips it and re-anchors to layers[i](name).field).
func CheckLayerDynShape(lname, field string, m map[string]interface{}) string {
	raw, err := json.Marshal(m)
	if err != nil {
		return "invalid object"
	}
	var sc StrategyConfig
	if err := json.Unmarshal(raw, &sc); err != nil {
		return "invalid object"
	}
	return checkDynShape(lname+"."+field, lname, field, &sc)
}

// LayerDynAllowlisted reports whether a layer field accepts dynamic objects
// (D-FTP-3 §4 allowlist; single truth shared by core parse and layers validate).
func LayerDynAllowlisted(lname, field string) bool {
	allowed, ok := layerDynAllowlist[lname]
	return ok && allowed[field]
}
