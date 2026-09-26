package core

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

// P4 red-first: every stored smb sub-map must round-trip through the
// layer-chain decoder identically to the flat truth (parseSMBConfig).
// P5 layers shape: business config lives in spec_json.layers[].smb
// (top-level smb is dead — presence guard rejects it).
func TestTranslateSMBConfigMatchesFlat(t *testing.T) {
	raw, err := os.ReadFile("../..//test/protocol_pcap/cases/smb.json")
	if err != nil {
		// allow run from either module root or package dir
		raw, err = os.ReadFile("../../test/protocol_pcap/cases/smb.json")
		if err != nil {
			t.Skip("cases file not found")
		}
	}
	var cases []map[string]any
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		sj, _ := c["spec_json"].(map[string]any)
		var sm map[string]any
		if lys, ok := sj["layers"].([]any); ok {
			for _, e := range lys {
				if em, ok := e.(map[string]any); ok {
					if s, ok := em["smb"].(map[string]any); ok {
						sm = s
					}
				}
			}
		}
		if sm == nil {
			t.Errorf("%s: no layers[].smb found", c["id"])
			continue
		}
		got, err := TranslateSMBConfigFromMap(sm)
		if err != nil {
			t.Errorf("%s: layer decode: %v", c["id"], err)
			continue
		}
		want := parseSMBConfig(sm)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s: mismatch layer vs flat decode", c["id"])
		}
	}
}
