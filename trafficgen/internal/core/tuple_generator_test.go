package core

import (
	"testing"
)

// ipToUint32 converts an IPv4 string to a uint32 for assertions.
func ipToUint32(t *testing.T, ip string) uint32 {
	t.Helper()
	parts := splitIP(ip)
	if len(parts) != 4 {
		t.Fatalf("invalid ipv4: %s", ip)
	}
	var v uint32
	for _, p := range parts {
		v = v<<8 | uint32(p)
	}
	return v
}

func splitIP(ip string) []byte {
	var parts []byte
	cur := 0
	for i := 0; i < len(ip); i++ {
		if ip[i] == '.' {
			parts = append(parts, byte(cur))
			cur = 0
		} else {
			cur = cur*10 + int(ip[i]-'0')
		}
	}
	parts = append(parts, byte(cur))
	return parts
}

func TestTupleGenerator_IncIP(t *testing.T) {
	tc := TupleConfig{
		SrcIP:   StrategyConfig{Strategy: "inc", Range: []interface{}{"10.0.0.1", "10.0.0.5"}, Step: 1},
		DstIP:   StrategyConfig{Strategy: "fixed", Value: "192.168.1.1"},
		SrcPort: StrategyConfig{Strategy: "fixed", Value: float64(1000)},
		DstPort: StrategyConfig{Strategy: "fixed", Value: float64(80)},
	}
	g := NewTupleGenerator(tc)

	want := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5"}
	for i, w := range want {
		srcIP, dstIP, srcPort, dstPort := g.Next(i)
		if srcIP != w {
			t.Errorf("Next(%d) srcIP = %s, want %s", i, srcIP, w)
		}
		if dstIP != "192.168.1.1" {
			t.Errorf("Next(%d) dstIP = %s, want 192.168.1.1", i, dstIP)
		}
		if srcPort != 1000 || dstPort != 80 {
			t.Errorf("Next(%d) ports = %d/%d, want 1000/80", i, srcPort, dstPort)
		}
	}
	// Index 5 wraps back to start (range exhausted).
	srcIP, _, _, _ := g.Next(5)
	if srcIP != "10.0.0.1" {
		t.Errorf("Next(5) srcIP = %s, want wrap to 10.0.0.1", srcIP)
	}
}

func TestTupleGenerator_RandPortReproducible(t *testing.T) {
	tc := TupleConfig{
		SrcIP:   StrategyConfig{Strategy: "fixed", Value: "10.0.0.1"},
		DstIP:   StrategyConfig{Strategy: "fixed", Value: "10.0.0.2"},
		SrcPort: StrategyConfig{Strategy: "rand", Range: []interface{}{float64(1024), float64(65535)}, Seed: 42},
		DstPort: StrategyConfig{Strategy: "fixed", Value: float64(80)},
	}
	g1 := NewTupleGenerator(tc)
	g2 := NewTupleGenerator(tc)
	for i := 0; i < 5; i++ {
		_, _, s1, _ := g1.Next(i)
		_, _, s2, _ := g2.Next(i)
		if s1 != s2 {
			t.Errorf("rand not reproducible at %d: %d vs %d", i, s1, s2)
		}
		if s1 < 1024 || s1 > 65535 {
			t.Errorf("rand port out of range: %d", s1)
		}
	}
}

func TestTupleGenerator_ListPort(t *testing.T) {
	tc := TupleConfig{
		SrcIP:   StrategyConfig{Strategy: "fixed", Value: "10.0.0.1"},
		DstIP:   StrategyConfig{Strategy: "fixed", Value: "10.0.0.2"},
		SrcPort: StrategyConfig{Strategy: "fixed", Value: float64(5000)},
		DstPort: StrategyConfig{Strategy: "list", List: []string{"80", "443", "8080"}},
	}
	g := NewTupleGenerator(tc)
	want := []uint16{80, 443, 8080, 80, 443}
	for i, w := range want {
		_, _, _, dport := g.Next(i)
		if dport != w {
			t.Errorf("Next(%d) dport = %d, want %d", i, dport, w)
		}
	}
}

func TestTupleGenerator_IPIncrementAcrossOctet(t *testing.T) {
	// 10.0.0.254 -> 10.0.0.255 -> 10.0.1.0 (carry across octet)
	tc := TupleConfig{
		SrcIP:   StrategyConfig{Strategy: "inc", Range: []interface{}{"10.0.0.254", "10.0.1.2"}, Step: 1},
		DstIP:   StrategyConfig{Strategy: "fixed", Value: "1.1.1.1"},
		SrcPort: StrategyConfig{Strategy: "fixed", Value: float64(1)},
		DstPort: StrategyConfig{Strategy: "fixed", Value: float64(1)},
	}
	g := NewTupleGenerator(tc)
	_, _, _, _ = g.Next(0) // 10.0.0.254
	srcIP, _, _, _ := g.Next(1)
	if srcIP != "10.0.0.255" {
		t.Errorf("Next(1) = %s, want 10.0.0.255", srcIP)
	}
	srcIP, _, _, _ = g.Next(2)
	if srcIP != "10.0.1.0" {
		t.Errorf("Next(2) = %s, want 10.0.1.0 (carry)", srcIP)
	}
}
