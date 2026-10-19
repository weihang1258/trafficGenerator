package mcp

import (
	"encoding/json"
	"testing"
)

// R7：MCP 输出面 PascalCase→snake_case 键归一（storage 模型直出键）。
func TestSnakeCaseKeys(t *testing.T) {
	in := map[string]interface{}{
		"ID": "a1", "Name": "x.pcap", "PacketCount": float64(5),
		"UserID": "u1", "CreatedAt": "t", "PcapAssetID": "p1", "FirstTsUs": float64(1),
		"Nested":        []interface{}{map[string]interface{}{"FlowCount": float64(2)}},
		"already_snake": 1,
	}
	out := snakeCaseKeys(in)
	b, _ := json.Marshal(out)
	want := `"id":"a1"`
	if !jsonContains(string(b), want) {
		t.Errorf("ID key missing: %s", b)
	}
	for _, want := range []string{`"name"`, `"packet_count"`, `"user_id"`, `"created_at"`, `"pcap_asset_id"`, `"first_ts_us"`, `"flow_count"`, `"already_snake"`} {
		if !jsonContains(string(b), want) {
			t.Errorf("key %s missing in %s", want, b)
		}
	}
	for _, bad := range []string{"PacketCount", "UserID", "PcapAssetID"} {
		if jsonContains(string(b), `"`+bad+`"`) {
			t.Errorf("PascalCase key %s survived: %s", bad, b)
		}
	}
}

func jsonContains(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool { return indexOf(s, sub) >= 0 })()
}
func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
