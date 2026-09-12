package core

import (
	"fmt"
	"math/rand"
	"net"
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

// genIP generates an IP string for the given index per the strategy
// (D-FTP-4 双栈：IPv4 走既有 32 位整型路径零改动；IPv6 走 128 位路径，
// 递增跨段进位/回绕/rand/轮转口径与 IPv4 同构；两端异族返回 "").
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
		if isIPv6Endpoint(s.Range[0]) || isIPv6Endpoint(s.Range[1]) {
			return genIP6Inc(s, index)
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
		if isIPv6Endpoint(s.Range[0]) || isIPv6Endpoint(s.Range[1]) {
			return genIP6Rand(s, index)
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

// isIPv6Endpoint reports whether v is an IPv6 literal (parsed by net.ParseIP
// and not IPv4-mapped). Strings that parse as IPv4 return false; garbage
// returns false (callers fall through to the IPv4 path which rejects it).
func isIPv6Endpoint(v interface{}) bool {
	str, ok := v.(string)
	if !ok {
		return false
	}
	ip := net.ParseIP(str)
	return ip != nil && ip.To4() == nil
}

// ip6ToU128 parses an IPv6 literal into 16 big-endian bytes.
func ip6ToU128(s string) ([16]byte, bool) {
	var out [16]byte
	ip := net.ParseIP(s)
	if ip == nil || ip.To4() != nil {
		return out, false
	}
	copy(out[:], ip.To16())
	return out, true
}

// u128ToIP formats 16 big-endian bytes as the canonical IPv6 string
// (net.IP.String: RFC 5952 :: compression, lowercase).
func u128ToIP(b [16]byte) string {
	return net.IP(b[:]).String()
}

// u128Cmp compares two 128-bit big-endian values (-1/0/+1).
func u128Cmp(a, b [16]byte) int {
	for i := 0; i < 16; i++ {
		if a[i] != b[i] {
			if a[i] < b[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}

// u128Add adds off (mod 2^128) to b.
func u128Add(b [16]byte, off uint64) [16]byte {
	carry := off
	for i := 15; i >= 0 && carry > 0; i-- {
		sum := uint64(b[i]) + (carry & 0xFF)
		b[i] = byte(sum)
		carry = (carry >> 8) + (sum >> 8)
	}
	return b
}

// u128Diff returns end-start (requires end >= start).
func u128Diff(start, end [16]byte) uint64 {
	var borrow uint64
	var diff [16]byte
	for i := 15; i >= 0; i-- {
		d := int64(end[i]) - int64(start[i]) - int64(borrow)
		if d < 0 {
			d += 256
			borrow = 1
		} else {
			borrow = 0
		}
		diff[i] = byte(d)
	}
	var v uint64
	for i := 8; i < 16; i++ {
		v = v<<8 | uint64(diff[i])
	}
	return v
}

// genIP6Inc resolves IPv6 inc at flow index i. Mixed-family or unparseable
// endpoints return "" (callers treat as "no value"; shape-level rejection of
// mixed families is owned by checkDynEndpoints in layer_dyn.go).
func genIP6Inc(s StrategyConfig, index int) string {
	start, ok1 := ip6ToU128(asString(s.Range[0]))
	end, ok2 := ip6ToU128(asString(s.Range[1]))
	if !ok1 || !ok2 || u128Cmp(end, start) < 0 {
		return ""
	}
	span := u128Diff(start, end) + 1
	step := s.Step
	if step <= 0 {
		step = 1
	}
	off := uint64(index*step) % span
	return u128ToIP(u128Add(start, off))
}

// genIP6Rand resolves IPv6 rand at flow index i (seed+i, reproducible).
// Large spans (>2^64) keep the high 64 bits and randomize the low 64.
func genIP6Rand(s StrategyConfig, index int) string {
	start, ok1 := ip6ToU128(asString(s.Range[0]))
	end, ok2 := ip6ToU128(asString(s.Range[1]))
	if !ok1 || !ok2 || u128Cmp(end, start) < 0 {
		return ""
	}
	r := rand.New(rand.NewSource(s.Seed + int64(index)))
	span := u128Diff(start, end) + 1
	off := uint64(r.Int63n(int64(span)))
	return u128ToIP(u128Add(start, off))
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
