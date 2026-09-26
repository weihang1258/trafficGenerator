package core

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

// P4 red-first: every stored smb sub-map must round-trip through the
// layer-chain decoder identically to the flat truth (parseSMBConfig).
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
		sm := c["spec_json"].(map[string]any)["smb"].(map[string]any)
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
