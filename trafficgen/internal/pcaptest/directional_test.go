package pcaptest

import "testing"

func TestDirectionalSourcesIncludesIPv6(t *testing.T) {
	got := mergeDirectionalSources([]string{"10.0.0.1", ""}, []string{"", "2001:db8::1"})
	want := map[string]bool{"10.0.0.1": true, "2001:db8::1": true}
	if len(got) != len(want) {
		t.Fatalf("merged source count = %d, want %d: %#v", len(got), len(want), got)
	}
	for v := range want {
		if !got[v] {
			t.Errorf("merged sources missing %q: %#v", v, got)
		}
	}
}
