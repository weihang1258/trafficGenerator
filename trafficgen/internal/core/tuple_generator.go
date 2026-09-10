package core

import (
	"fmt"
	"math/rand"
	"strconv"
	"strings"
)

// TupleGenerator produces 4-tuples (srcIP, dstIP, srcPort, dstPort) from a
// TupleConfig. It is type-aware: IP fields use 4-byte arithmetic (with octet
// carry and wrap), port fields use integer arithmetic. Generation is a pure
// function of the index, so the same index always yields the same value
// (reproducible), independent of call order.
type TupleGenerator struct {
	tc TupleConfig
}

// NewTupleGenerator creates a generator from a TupleConfig.
func NewTupleGenerator(tc TupleConfig) *TupleGenerator {
	return &TupleGenerator{tc: tc}
}

// Next returns the 4-tuple for the given flow index.
func (g *TupleGenerator) Next(index int) (srcIP, dstIP string, srcPort, dstPort uint16) {
	srcIP = genIP(g.tc.SrcIP, index)
	dstIP = genIP(g.tc.DstIP, index)
	srcPort = genPort(g.tc.SrcPort, index)
	dstPort = genPort(g.tc.DstPort, index)
	return
}

// genIP generates an IPv4 string for the given index per the strategy.
func genIP(s StrategyConfig, index int) string {
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
	case "inc":
		if len(s.Range) < 2 {
			return ""
		}
		start, ok1 := ipToU32(asString(s.Range[0]))
		end, ok2 := ipToU32(asString(s.Range[1]))
		if !ok1 || !ok2 || end < start {
			return ""
		}
		count := end - start + 1
		step := s.Step
		if step <= 0 {
			step = 1
		}
		offset := uint32((index * step) % int(count))
		return u32ToIP(start + offset)
	case "rand":
		if len(s.Range) < 2 {
			return ""
		}
		start, ok1 := ipToU32(asString(s.Range[0]))
		end, ok2 := ipToU32(asString(s.Range[1]))
		if !ok1 || !ok2 || end < start {
			return ""
		}
		r := rand.New(rand.NewSource(s.Seed + int64(index)))
		return u32ToIP(start + uint32(r.Int63n(int64(end-start+1))))
	default:
		return ""
	}
}

// genPort generates a port for the given index per the strategy.
func genPort(s StrategyConfig, index int) uint16 {
	switch s.Strategy {
	case "fixed", "":
		return toPort(s.Value)
	case "list":
		if len(s.List) == 0 {
			return 0
		}
		return toPort(s.List[index%len(s.List)])
	case "inc":
		if len(s.Range) < 2 {
			return 0
		}
		start := int(toPort(s.Range[0]))
		end := int(toPort(s.Range[1]))
		if end < start {
			return 0
		}
		count := end - start + 1
		step := s.Step
		if step <= 0 {
			step = 1
		}
		return uint16(start + (index*step)%count)
	case "rand":
		if len(s.Range) < 2 {
			return 0
		}
		start := int(toPort(s.Range[0]))
		end := int(toPort(s.Range[1]))
		if end < start {
			return 0
		}
		r := rand.New(rand.NewSource(s.Seed + int64(index)))
		return uint16(start + r.Intn(end-start+1))
	default:
		return 0
	}
}

// ipToU32 parses a dotted IPv4 string to a uint32.
func ipToU32(ip string) (uint32, bool) {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return 0, false
	}
	var v uint32
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || n > 255 {
			return 0, false
		}
		v = v<<8 | uint32(n)
	}
	return v, true
}

// u32ToIP formats a uint32 as a dotted IPv4 string.
func u32ToIP(v uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", (v>>24)&0xFF, (v>>16)&0xFF, (v>>8)&0xFF, v&0xFF)
}

// toPort converts an interface{} (float64/int/string) to a uint16 port.
func toPort(v interface{}) uint16 {
	switch x := v.(type) {
	case float64:
		return uint16(x)
	case int:
		return uint16(x)
	case string:
		n, _ := strconv.Atoi(x)
		return uint16(n)
	}
	return 0
}

// asString renders an interface{} (typically from JSON) as a string.
func asString(v interface{}) string {
	switch x := v.(type) {
	case string:
		return x
	case float64:
		return strconv.Itoa(int(x))
	}
	return fmt.Sprintf("%v", v)
}

// ResolveIPValue evaluates a StrategyConfig at flow index i as an IPv4
// string (fixed/list/inc/rand — same algorithms as genIP). nil/empty/invalid
// strategy returns "" (callers treat as "no value"). Exported so protocol
// planners (FTP sessions, D-FTP-2) resolve dynamic fields through the same
// core implementation instead of re-implementing it.
func ResolveIPValue(s *StrategyConfig, i int) string {
	if s == nil {
		return ""
	}
	return genIP(*s, i)
}

// ResolvePortValue evaluates a StrategyConfig at flow index i as a uint16
// port (fixed/list/inc/rand). nil/empty/invalid returns 0 (caller's
// "absent/inherit" sentinel, matching session SrcPort semantics).
func ResolvePortValue(s *StrategyConfig, i int) uint16 {
	if s == nil {
		return 0
	}
	return genPort(*s, i)
}

// ResolveStringValue evaluates a StrategyConfig at flow index i as a string
// (all five strategies via genStringValue, pattern {n} included).
// nil/empty/invalid returns "".
func ResolveStringValue(s *StrategyConfig, i int) string {
	if s == nil {
		return ""
	}
	return genStringValue(*s, i)
}
