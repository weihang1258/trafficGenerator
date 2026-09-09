package schema

import "testing"

func TestSemanticMatchesHandlerMessages(t *testing.T) {
	cases := []struct {
		name     string
		mode     string
		protocol string
		config   map[string]any
		fc       *FlowControl
		wantSub  string
	}{
		{
			name:     "bad ip format",
			mode:     "synth",
			protocol: "tcp",
			config:   map[string]any{"src_ip": "999.1.1.1"},
			wantSub:  "invalid IP format: src_ip",
		},
		{
			name:     "bad mac format",
			mode:     "synth",
			protocol: "tcp",
			config:   map[string]any{"src_mac": "zz"},
			wantSub:  "invalid MAC format: src_mac",
		},
		{
			name:     "range violation",
			mode:     "synth",
			protocol: "tcp",
			config:   map[string]any{"dscp": float64(64)},
			wantSub:  "dscp 64 invalid",
		},
		{
			name:     "unknown protocol",
			mode:     "synth",
			protocol: "nope",
			config:   map[string]any{},
			wantSub:  "invalid or missing protocol",
		},
		{
			name:     "tftp tid collision",
			mode:     "synth",
			protocol: "tftp",
			config:   map[string]any{"tftp": map[string]any{"server_tid": float64(5000)}},
			fc:       &FlowControl{Type: "flows", Value: 2},
			wantSub:  "server_tid 5000 conflicts",
		},
		{
			name:     "replay bad speed",
			mode:     "replay",
			protocol: "",
			config:   map[string]any{"pcap_asset_id": "x", "speed": map[string]any{"mode": "nope"}},
			wantSub:  "invalid speed mode",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, errs := ValidateStrategy(tc.mode, tc.protocol, tc.config, tc.fc)
			if len(errs) == 0 {
				t.Fatalf("want errors, got clean")
			}
			found := false
			for _, e := range errs {
				if contains(e.Message, tc.wantSub) {
					found = true
				}
			}
			if !found {
				t.Fatalf("want error containing %q, got %v", tc.wantSub, errs)
			}
		})
	}
}

func TestSemanticLayersInference(t *testing.T) {
	proto, errs := ValidateStrategy("synth", "", map[string]any{
		"layers": []any{map[string]any{"ip": map[string]any{}}, map[string]any{"tcp": map[string]any{}}, map[string]any{"http": map[string]any{}}},
	}, nil)
	if len(errs) != 0 {
		t.Fatalf("want clean layers inference, got %v", errs)
	}
	if proto == "" {
		t.Fatalf("want inferred protocol, got empty")
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}
