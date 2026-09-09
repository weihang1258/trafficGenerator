package schema

import (
	"encoding/json"
	"testing"
)

func mustDoc(t *testing.T, doc string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(doc), &m); err != nil {
		t.Fatalf("bad test doc: %v", err)
	}
	return m
}

func validStrategyDoc() map[string]any {
	return map[string]any{
		"name": "s1", "mode": "synth", "protocol": "tcp",
		"config": map[string]any{},
	}
}

func TestLoads(t *testing.T) {
	if err := load(); err != nil {
		t.Fatalf("load: %v", err)
	}
}

func TestValidMinimal(t *testing.T) {
	if errs := ValidateStrategyShape(validStrategyDoc()); len(errs) != 0 {
		t.Fatalf("want clean, got %v", errs)
	}
}

func TestInvalidCases(t *testing.T) {
	cases := []struct {
		name string
		doc  string
	}{
		{"missing_name", `{"mode":"synth","protocol":"tcp","config":{}}`},
		{"bad_mode", `{"name":"s","mode":"nope","protocol":"tcp","config":{}}`},
		{"bad_fc_type", `{"name":"s","mode":"synth","protocol":"tcp","config":{},"flow_control":{"type":"cps","value":1}}`},
		{"nonpositive_fc", `{"name":"s","mode":"synth","protocol":"tcp","config":{},"flow_control":{"type":"flows","value":0}}`},
		{"replay_fc_bps", `{"name":"s","mode":"replay","config":{"pcap_asset_id":"x"},"flow_control":{"type":"bps","value":1}}`},
		{"replay_with_layers", `{"name":"s","mode":"replay","config":{"pcap_asset_id":"x","layers":[{"tcp":{}}]}}`},
		{"replay_no_asset", `{"name":"s","mode":"replay","config":{}}`},
		{"bad_dscp", `{"name":"s","mode":"synth","protocol":"tcp","config":{"dscp":64}}`},
		{"bad_src_port", `{"name":"s","mode":"synth","protocol":"tcp","config":{"src_port":70000}}`},
		{"bad_mac", `{"name":"s","mode":"synth","protocol":"tcp","config":{"src_mac":"zz"}}`},
		{"bad_tftp_mode", `{"name":"s","mode":"synth","protocol":"tftp","config":{"tftp":{"mode":"nope"}}}`},
		{"bad_server_tid", `{"name":"s","mode":"synth","protocol":"tftp","config":{"tftp":{"server_tid":100}}}`},
		{"multiplier_no_value", `{"name":"s","mode":"replay","config":{"pcap_asset_id":"x","speed":{"mode":"multiplier"}}}`},
		{"bad_inc_no_range", `{"name":"s","mode":"synth","protocol":"tcp","config":{"group_id":{"strategy":"inc"}}}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			errs := ValidateStrategyShape(mustDoc(t, tc.doc))
			if len(errs) == 0 {
				t.Fatalf("want errors, got clean")
			}
			t.Logf("errors: %v", errs)
		})
	}
}

func TestValidDynamicAndReplay(t *testing.T) {
	docs := []string{
		`{"name":"s","mode":"synth","protocol":"tcp","config":{"group_id":{"strategy":"inc","range":[1,10]}}}`,
		`{"name":"s","mode":"replay","config":{"pcap_asset_id":"x","speed":{"mode":"multiplier","multiplier":2}}}`,
		`{"name":"s","mode":"synth","protocol":"tcp","config":{"layers":[{"ip":{}},{"tcp":{}}]}}`,
	}
	for i, d := range docs {
		if errs := ValidateStrategyShape(mustDoc(t, d)); len(errs) != 0 {
			t.Fatalf("doc %d: want clean, got %v", i, errs)
		}
	}
}
