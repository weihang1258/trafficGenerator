package replay

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestReplaySpec_JSONRoundTrip verifies the §16.14 config examples parse into
// ReplaySpec correctly (schema matches the documented examples).
func TestReplaySpec_JSONRoundTrip(t *testing.T) {
	cases := []struct {
		name    string
		json    string
		check   func(*ReplaySpec, *testing.T)
	}{
		{
			name: "scenario A pure replay",
			json: `{"pcap_asset_id":"pcap_abc123","speed":{"mode":"original"},"direction":"single","loop":1}`,
			check: func(s *ReplaySpec, t *testing.T) {
				if s.PcapAssetID != "pcap_abc123" || s.Speed.Mode != "original" || s.Direction != "single" || s.Loop == nil || *s.Loop != 1 {
					t.Errorf("scenario A parsed wrong: %+v", s)
				}
			},
		},
		{
			name: "scenario B ipmap",
			json: `{"pcap_asset_id":"pcap_abc123","speed":{"mode":"multiplier","multiplier":1.0},"direction":"single","rewrites":[{"kind":"ipmap","mapping":{"1.0.0.1":"11.0.0.1"}}]}`,
			check: func(s *ReplaySpec, t *testing.T) {
				if len(s.Rewrites) != 1 || s.Rewrites[0].Kind != "ipmap" {
					t.Errorf("scenario B rewrites wrong: %+v", s.Rewrites)
				}
				if s.Rewrites[0].Mapping["1.0.0.1"] != "11.0.0.1" {
					t.Errorf("ipmap mapping wrong: %v", s.Rewrites[0].Mapping)
				}
			},
		},
		{
			name: "scenario C flow scaling",
			json: `{"pcap_asset_id":"pcap_abc123","speed":{"mode":"bps","bps":"500k"},"direction":"single","flow_scaling":{"count":100,"src_ip":{"strategy":"inc","range":["11.0.0.1","11.0.0.100"],"step":1},"dst_ip":{"strategy":"fixed","value":"22.0.0.1"},"seq_offset":{"strategy":"random","range":[0,4294967295],"seed":42},"interleave":"stack"}}`,
			check: func(s *ReplaySpec, t *testing.T) {
				if s.FlowScaling == nil || s.FlowScaling.Count != 100 {
					t.Errorf("flow_scaling wrong: %+v", s.FlowScaling)
				}
				if s.FlowScaling.SrcIP.Strategy != "inc" {
					t.Errorf("src_ip strategy wrong: %+v", s.FlowScaling.SrcIP)
				}
			},
		},
		{
			name: "scenario D endpoint",
			json: `{"pcap_asset_id":"pcap_abc123","speed":{"mode":"original"},"direction":"single","rewrites":[{"match":{"protocol":"tcp","src_ip":"1.0.0.1","src_port":1000,"dst_ip":"2.0.0.1","dst_port":21},"kind":"endpoint","target":"client_ip","apply":"set","strategy":{"strategy":"fixed","value":"11.0.0.1"}}]}`,
			check: func(s *ReplaySpec, t *testing.T) {
				if len(s.Rewrites) != 1 || s.Rewrites[0].Target != "client_ip" {
					t.Errorf("endpoint rewrite wrong: %+v", s.Rewrites)
				}
				if s.Rewrites[0].Match.SrcPort != 1000 {
					t.Errorf("matcher src_port wrong: %d", s.Rewrites[0].Match.SrcPort)
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var s ReplaySpec
			if err := json.Unmarshal([]byte(tc.json), &s); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			tc.check(&s, t)
			// Re-marshal and ensure no loss of essential fields.
			out, err := json.Marshal(&s)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if !strings.Contains(string(out), "pcap_abc123") {
				t.Errorf("re-marshal lost asset id: %s", out)
			}
		})
	}
}

// TestPatch_Struct verifies the Patch struct carries the fields the rewriter needs.
func TestPatch_Struct(t *testing.T) {
	p := Patch{Field: "src_ip", Offset: 26, Bytes: []byte{11, 0, 0, 1}, Layer: "l3"}
	out, _ := json.Marshal(&p)
	if !strings.Contains(string(out), "src_ip") || !strings.Contains(string(out), "l3") {
		t.Errorf("Patch marshal lost fields: %s", out)
	}
}
