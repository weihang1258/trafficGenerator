package schema

import (
	"encoding/json"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core/layers"
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

func TestDescriptionsCoverMCPFields(t *testing.T) {
	m, err := DescriptionMap("v1/strategy.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"/properties/config", "/properties/flow_control", "/properties/mode"} {
		if _, ok := m[p]; !ok {
			t.Fatalf("missing doc path %s", p)
		}
	}
	dm, err := DescriptionMap("v1/defs.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"/$defs/flow_control", "/$defs/output_config", "/$defs/dynamic_value"} {
		if _, ok := dm[p]; !ok {
			t.Fatalf("missing defs path %s", p)
		}
	}
	tm, err := DescriptionMap("v1/task.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := tm["/properties/strategy_ids"]; !ok {
		t.Fatalf("missing task strategy_ids doc")
	}
}

func TestLayersGeneratedMatchesRegistry(t *testing.T) {
	layersMap, err := LayersGenerated()
	if err != nil {
		t.Fatal(err)
	}
	reg := layers.DefaultRegistry()
	if len(layersMap) != len(reg.List()) {
		t.Fatalf("generated dump has %d layers, registry has %d; regenerate via go run ./internal/core/layers/schemagen",
			len(layersMap), len(reg.List()))
	}
	for _, name := range reg.List() {
		s, ok := reg.Get(name)
		if !ok {
			continue
		}
		raw, ok := layersMap[name]
		if !ok {
			t.Fatalf("registry layer %q missing from generated dump; regenerate", name)
			continue
		}
		entry, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("dump entry %q is not an object", name)
			continue
		}
		if entry["category"] != s.Category.String() {
			t.Errorf("layer %q category: dump=%v registry=%v; regenerate", name, entry["category"], s.Category.String())
		}
		fields, _ := entry["fields"].(map[string]any)
		if len(fields) != len(s.Fields) {
			t.Errorf("layer %q fields: dump=%d registry=%d; regenerate", name, len(fields), len(s.Fields))
			continue
		}
		for fname, f := range s.Fields {
			fr, ok := fields[fname]
			if !ok {
				t.Errorf("layer %q field %q missing from dump; regenerate", name, fname)
				continue
			}
			fm, ok := fr.(map[string]any)
			if !ok {
				t.Errorf("layer %q field %q dump entry not an object", name, fname)
				continue
			}
			if fm["type"] != f.Type {
				t.Errorf("layer %q field %q type: dump=%v registry=%v; regenerate", name, fname, fm["type"], f.Type)
			}
			// min/max 同步（D-MEGACO-1 修轮 U3：注册表 Min/Max 变更未重跑
			// schemagen 曾致 megaco version 下界丢失而本测试保持绿）。
			// JSON 数值反序列化为 float64，与注册表 int64 按数值比对。
			cmpBound := func(key string, want int64) {
				raw, ok := fm[key]
				if want == 0 {
					if ok && raw != nil {
						t.Errorf("layer %q field %q %s: dump=%v registry=unbounded; regenerate", name, fname, key, raw)
					}
					return
				}
				v, isNum := raw.(float64)
				if !isNum || int64(v) != want {
					t.Errorf("layer %q field %q %s: dump=%v registry=%d; regenerate", name, fname, key, raw, want)
				}
			}
			cmpBound("min", f.Min)
			cmpBound("max", f.Max)
		}
	}
}

func TestLayersShape(t *testing.T) {
	good := []any{map[string]any{"ip": map[string]any{}}, map[string]any{"tcp": map[string]any{}}}
	if errs := ValidateLayersShape(good); len(errs) != 0 {
		t.Fatalf("want clean, got %v", errs)
	}
	for _, bad := range []any{
		[]any{},
		[]any{map[string]any{"ip": map[string]any{}, "tcp": map[string]any{}}},
		[]any{"ip"},
	} {
		if errs := ValidateLayersShape(bad); len(errs) == 0 {
			t.Fatalf("want errors for %v, got clean", bad)
		}
	}
}
