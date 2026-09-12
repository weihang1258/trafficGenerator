package core

import (
	"testing"
)

// D-FTP-4 T-FTP-18 failing-first：genIP 双栈——IPv6 inc/rand/list/fixed。
// 现状 genIP 纯 IPv4（ipToU32），v6 端点返回 ""（探针 TestZZIPv6Probe 实测）。
func TestGenIP_IPv6Inc(t *testing.T) {
	s := StrategyConfig{Strategy: "inc", Range: []interface{}{"2001:db8::1", "2001:db8::3"}}
	want := []string{"2001:db8::1", "2001:db8::2", "2001:db8::3"}
	for i, w := range want {
		if got := genIP(s, i); got != w {
			t.Errorf("genIP inc v6 i=%d = %q, want %q", i, got, w)
		}
	}
	if got := genIP(s, 3); got != "2001:db8::1" {
		t.Errorf("genIP inc v6 wraparound i=3 = %q, want 2001:db8::1", got)
	}
}

func TestGenIP_IPv6IncCarry(t *testing.T) {
	s := StrategyConfig{Strategy: "inc", Range: []interface{}{"2001:db8::ffff", "2001:db8::1:1"}}
	if got := genIP(s, 0); got != "2001:db8::ffff" {
		t.Errorf("i=0 = %q", got)
	}
	if got := genIP(s, 1); got != "2001:db8::1:0" {
		t.Errorf("carry i=1 = %q, want 2001:db8::1:0", got)
	}
}

func TestGenIP_IPv6RandReproducible(t *testing.T) {
	s := StrategyConfig{Strategy: "rand", Range: []interface{}{"2001:db8::1", "2001:db8::9"}, Seed: 7}
	a := []string{genIP(s, 0), genIP(s, 1), genIP(s, 2)}
	b := []string{genIP(s, 0), genIP(s, 1), genIP(s, 2)}
	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("not reproducible at %d: %q vs %q", i, a[i], b[i])
		}
		if a[i] == "" {
			t.Fatalf("empty value at %d", i)
		}
	}
}

func TestGenIP_IPv6ListFixed(t *testing.T) {
	l := StrategyConfig{Strategy: "list", List: []string{"2001:db8::a", "2001:db8::b"}}
	for i, w := range []string{"2001:db8::a", "2001:db8::b", "2001:db8::a"} {
		if got := genIP(l, i); got != w {
			t.Errorf("list i=%d = %q, want %q", i, got, w)
		}
	}
	f := StrategyConfig{Strategy: "fixed", Value: "2001:db8::99"}
	if got := genIP(f, 0); got != "2001:db8::99" {
		t.Errorf("fixed = %q", got)
	}
}

func TestValidIP_MixedFamily_Rejected(t *testing.T) {
	// D-FTP-4 T-FTP-18 错误期望：混族 range 走形状拒绝（400/任务 error）。
	spec := mapToFlowSpec(map[string]any{"layers": []any{
		map[string]any{"ip": map[string]any{
			"src": map[string]any{"strategy": "inc", "range": []any{"10.0.0.1", "2001:db8::9"}},
		}},
	}}, "tcp")
	found := false
	for _, e := range spec.ValidationErrors {
		if containsSub(e, "must not mix") {
			found = true
		}
	}
	if !found {
		t.Fatalf("want ValidationErrors naming mixed families, got %v", spec.ValidationErrors)
	}
}

func TestGenIP_IPv6EndBeforeStart_Rejected(t *testing.T) {
	// end<start（128 位比较）→ 形状拒绝，不是静默空值。
	spec := mapToFlowSpec(map[string]any{"layers": []any{
		map[string]any{"ip": map[string]any{
			"src": map[string]any{"strategy": "inc", "range": []any{"2001:db8::9", "2001:db8::1"}},
		}},
	}}, "tcp")
	found := false
	for _, e := range spec.ValidationErrors {
		if containsSub(e, "must not exceed end") {
			found = true
		}
	}
	if !found {
		t.Fatalf("want range-order rejection, got %v", spec.ValidationErrors)
	}
}
