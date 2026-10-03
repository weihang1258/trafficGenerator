package layers_test

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	_ "github.com/trafficgen/trafficgen/internal/protocol/tds" // init 注册 tds 终结层生成器+校验器
)

// D-TDS-1 P4 链级测试：①层条目→Payload 翻译端到端（[ip,tcp,tds] 出包，
// 握手 3 + 数据 6 + 挥手 4 = 13）/②presence 与顶层游离键判死（CheckProtoFlat
// tds 分支）/③udp 载体拒（TransportOn=[tcp]）/④用例文件收官自查（非负例
// 顶层键 ⊆ {layers,flow_control,output}）。

func tJSON(t *testing.T, layersArr []interface{}) json.RawMessage {
	t.Helper()
	out, err := json.Marshal(layersArr)
	if err != nil {
		t.Fatalf("marshal layers: %v", err)
	}
	return out
}

func tLayers(tdsCfg map[string]interface{}) []interface{} {
	return []interface{}{
		map[string]interface{}{"ip": map[string]interface{}{"src": "10.0.0.1", "dst": "20.0.0.1"}},
		map[string]interface{}{"tcp": map[string]interface{}{"src_port": 54321, "dst_port": 1433}},
		map[string]interface{}{"tds": tdsCfg},
	}
}

func tMinSessions() map[string]interface{} {
	return map[string]interface{}{
		"sessions": []interface{}{
			map[string]interface{}{
				"id": "s1",
				"requests": []interface{}{
					map[string]interface{}{"type": "attention"},
				},
			},
		},
	}
}

func tPlan(t *testing.T, layersArr []interface{}) []core.PacketConfig {
	t.Helper()
	p, err := layers.BuildLayersPlanner("tds", tJSON(t, layersArr))
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v", err)
	}
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 54321, DstPort: 1433}
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var pkts []core.PacketConfig
	for c := range ch {
		pkts = append(pkts, c)
	}
	return pkts
}

// ①层条目→Payload 翻译端到端：最小 attention 会话 13 包，首包 SYN。
func TestTDSChain_LayerToPayloadPlan(t *testing.T) {
	pkts := tPlan(t, tLayers(tMinSessions()))
	if len(pkts) != 13 {
		t.Fatalf("got %d packets, want 13 (handshake 3 + data 6 + teardown 4)", len(pkts))
	}
	if pkts[0].L4.Flags != 0x02 {
		t.Fatalf("packet 0 flags = 0x%02x, want SYN 0x02", pkts[0].L4.Flags)
	}
}

// ②presence 与顶层游离键判死。
func TestTDSChain_PresenceAndStrayTopLevelKeys(t *testing.T) {
	cfg := map[string]interface{}{
		"layers": tLayers(map[string]interface{}{}),
		"tds":    map[string]interface{}{},
	}
	if msg := core.CheckProtoFlat("tds", cfg); msg == "" {
		t.Fatal("CheckProtoFlat(tds, {layers, tds:{}}) = \"\", want top-level tds presence rejection")
	} else if !strings.Contains(msg, "rejects a top-level tds sub-config") {
		t.Fatalf("CheckProtoFlat msg = %q", msg)
	}
	for _, k := range []string{"src_ip", "dst_ip", "src_port", "dst_port", "count"} {
		bad := map[string]interface{}{"layers": cfg["layers"], k: 1}
		if msg := core.CheckProtoFlat("tds", bad); msg == "" {
			t.Fatalf("CheckProtoFlat(tds, {layers, %s}) = \"\", want flat-field rejection", k)
		}
	}
}

// ③udp 载体拒（TransportOn=[tcp]，complete.go tcp-only 专用锚词）。
func TestTDSChain_UDPCarrierRejected(t *testing.T) {
	arr := []interface{}{
		map[string]interface{}{"ip": map[string]interface{}{"src": "10.0.0.1", "dst": "20.0.0.1"}},
		map[string]interface{}{"udp": map[string]interface{}{"src_port": 54321, "dst_port": 1433}},
		map[string]interface{}{"tds": tMinSessions()},
	}
	_, err := layers.BuildLayersPlanner("tds", tJSON(t, arr))
	if err == nil {
		t.Fatal("BuildLayersPlanner([ip,udp,tds]) = nil, want carrier rejection")
	}
	if !strings.Contains(err.Error(), "carrier") {
		t.Fatalf("carrier error = %q, want anchor \"carrier\"", err.Error())
	}
}

// ④用例文件收官自查：134 例（105 正 + 29 负 = 26 V-TDS + presence 1 + 游离键 2）；
// 非负例顶层键 ⊆ 白名单；presence/游离键负例在案。
func TestTDSChain_CaseFileAudit(t *testing.T) {
	raw, err := os.ReadFile("../../../test/protocol_pcap/cases/tds.json")
	if err != nil {
		t.Fatalf("read cases: %v", err)
	}
	var cases []map[string]interface{}
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatalf("parse cases: %v", err)
	}
	if len(cases) != 134 {
		t.Fatalf("want 134 cases (105 pos + 29 neg), got %d", len(cases))
	}
	allowed := map[string]bool{"layers": true, "flow_control": true, "output": true}
	presence := false
	for _, c := range cases {
		id, _ := c["id"].(string)
		sj, _ := c["spec_json"].(map[string]interface{})
		if sj == nil {
			t.Fatalf("%s: spec_json missing", id)
		}
		exp, _ := c["expect"].(map[string]interface{})
		neg := exp != nil && exp["expect_error"] == true
		if !neg {
			for k := range sj {
				if !allowed[k] {
					t.Fatalf("%s: non-negative top-level key %q (want ⊆ layers/flow_control/output)", id, k)
				}
			}
		}
		if _, hasTDS := sj["tds"]; hasTDS {
			if !neg {
				t.Fatalf("%s: top-level tds on non-negative case", id)
			}
			presence = true
		}
	}
	if !presence {
		t.Fatal("want 1 presence negative (layers + top-level tds), found none")
	}
}
