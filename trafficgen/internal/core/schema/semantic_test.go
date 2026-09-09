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
		{
			name:     "replay empty direction/checksum accepted",
			mode:     "replay",
			protocol: "",
			config:   map[string]any{"pcap_asset_id": "x", "direction": "", "checksum_mode": ""},
			wantSub:  "",
		},
		{
			name:     "replay bad direction",
			mode:     "replay",
			protocol: "",
			config:   map[string]any{"pcap_asset_id": "x", "direction": "sideways"},
			wantSub:  "invalid direction",
		},
		{
			name:     "replay bad checksum",
			mode:     "replay",
			protocol: "",
			config:   map[string]any{"pcap_asset_id": "x", "checksum_mode": "mangle"},
			wantSub:  "invalid checksum_mode",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, errs := ValidateStrategy(tc.mode, tc.protocol, tc.config, tc.fc)
			if tc.wantSub == "" {
				if len(errs) != 0 {
					t.Fatalf("want clean, got %v", errs)
				}
				return
			}
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

func TestTaskShape(t *testing.T) {
	good := map[string]any{
		"name": "t1", "strategy_ids": []any{"s1"},
		"output_type": "pcap", "output_config": map[string]any{"pcap_path": "x.pcap"},
	}
	if errs := ValidateTaskShape(good); len(errs) != 0 {
		t.Fatalf("want clean, got %v", errs)
	}
	bad := []struct {
		name string
		doc  map[string]any
	}{
		{"no ids nor batch", map[string]any{"name": "t", "output_type": "pcap", "output_config": map[string]any{"pcap_path": "x"}}},
		{"both ids and batch", map[string]any{"name": "t", "strategy_ids": []any{"s"}, "batch": map[string]any{"classes": []any{}}, "output_type": "pcap", "output_config": map[string]any{"pcap_path": "x"}}},
		{"empty ids", map[string]any{"name": "t", "strategy_ids": []any{}, "output_type": "pcap", "output_config": map[string]any{"pcap_path": "x"}}},
		{"pg missing id", map[string]any{"name": "t", "strategy_ids": []any{"s"}, "output_type": "port_group", "output_config": map[string]any{}}},
		{"pcap missing path", map[string]any{"name": "t", "strategy_ids": []any{"s"}, "output_type": "pcap", "output_config": map[string]any{}}},
		{"bad fc", map[string]any{"name": "t", "strategy_ids": []any{"s"}, "output_type": "pcap", "output_config": map[string]any{"pcap_path": "x"}, "flow_control": map[string]any{"type": "cps", "value": 1}}},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			if errs := ValidateTaskShape(tc.doc); len(errs) == 0 {
				t.Fatalf("want errors, got clean")
			}
		})
	}
}

func TestBatchShape(t *testing.T) {
	good := map[string]any{
		"classes": []any{map[string]any{"id": "c1", "type": "tcp", "flow_count": 1, "config": map[string]any{}}},
	}
	if errs := ValidateBatchShape(good); len(errs) != 0 {
		t.Fatalf("want clean, got %v", errs)
	}
	bad := []struct {
		name string
		doc  map[string]any
	}{
		{"no classes", map[string]any{}},
		{"synth no count", map[string]any{"classes": []any{map[string]any{"id": "c", "type": "tcp", "config": map[string]any{}}}}},
		{"replay no spec", map[string]any{"classes": []any{map[string]any{"id": "c", "type": "replay"}}}},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			if errs := ValidateBatchShape(tc.doc); len(errs) == 0 {
				t.Fatalf("want errors, got clean")
			}
		})
	}
}

func TestTaskCreateEntry(t *testing.T) {
	doc := map[string]any{
		"name": "t1", "strategy_ids": []any{"s1"},
		"output_type": "pcap", "output_config": map[string]any{"pcap_path": "x.pcap"},
		"flow_control": map[string]any{"type": "bps", "value": float64(100)},
	}
	strats := []StrategyView{{Name: "r1", Mode: "replay", SpeedMode: "original"}}
	errs := ValidateTaskCreate(doc, strats)
	if len(errs) == 0 {
		t.Fatalf("want replay+bps conflict, got clean")
	}
	if got := errs.Error(); !contains(got, "cannot combine with bps") {
		t.Fatalf("want conflict text, got %v", errs)
	}
	doc2 := map[string]any{
		"name": "t1", "strategy_ids": []any{"s1"},
		"output_type": "pcap", "output_config": map[string]any{"pcap_path": "x.pcap"},
		"flow_control": map[string]any{"type": "xyz", "value": float64(1)},
	}
	if errs := ValidateTaskCreate(doc2, nil); len(errs) == 0 {
		t.Fatalf("want fc type error, got clean")
	} else if got := errs.Error(); !contains(got, "invalid flow_control type") {
		t.Fatalf("want historic fc text, got %v", errs)
	}
}
