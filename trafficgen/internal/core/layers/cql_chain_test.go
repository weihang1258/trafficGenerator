package layers_test

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	_ "github.com/trafficgen/trafficgen/internal/protocol/cql" // init 注册 cql 终结层生成器+校验器
)

// D-CQL-1 P4 链级测试（M5 清单，tds_chain_test.go 范本）：
// ①层条目→spec.CQL 翻译端到端（[ip,tcp,cql] 出包 9）；
// ②presence 与顶层游离键判死（CheckProtoFlat cql 分支）；
// ③udp 载体拒 / 缺 tcp 载体拒（BuildLayersPlanner 预检，锚词 carrier）；
// ④用例文件收官自查（非负例顶层键 ⊆ {layers,flow_control,output}）。

func cqlJSON(t *testing.T, layersArr []interface{}) json.RawMessage {
	t.Helper()
	out, err := json.Marshal(layersArr)
	if err != nil {
		t.Fatalf("marshal layers: %v", err)
	}
	return out
}

func cqlLayers(cqlCfg map[string]interface{}) []interface{} {
	return []interface{}{
		map[string]interface{}{"ip": map[string]interface{}{"src": "10.0.0.1", "dst": "20.0.0.1"}},
		map[string]interface{}{"tcp": map[string]interface{}{"src_port": 12345, "dst_port": 9042}},
		map[string]interface{}{"cql": cqlCfg},
	}
}

func cqlMinEvents() map[string]interface{} {
	return map[string]interface{}{
		"wire_profile": "cql_v4",
		"events": []interface{}{
			map[string]interface{}{"kind": "startup", "direction": "c2s",
				"options": map[string]interface{}{"CQL_VERSION": "3.0.0"}},
			map[string]interface{}{"kind": "ready", "direction": "s2c"},
		},
	}
}

func cqlPlan(t *testing.T, layersArr []interface{}) []core.PacketConfig {
	t.Helper()
	p, err := layers.BuildLayersPlanner("cql", cqlJSON(t, layersArr))
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v", err)
	}
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345, DstPort: 9042}
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

// ①层条目→spec.CQL 翻译端到端：最小 startup/ready 会话 9 包，首包 SYN，
// 应用帧落在层内配置声明的 9042 端口。
func TestCQLChain_LayerToSpecPlan(t *testing.T) {
	pkts := cqlPlan(t, cqlLayers(cqlMinEvents()))
	if len(pkts) != 9 {
		t.Fatalf("got %d packets, want 9 (handshake 3 + 2 events + teardown 4)", len(pkts))
	}
	if pkts[0].L4.Flags != 0x02 {
		t.Fatalf("packet 0 flags = 0x%02x, want SYN 0x02", pkts[0].L4.Flags)
	}
	if pkts[3].L4.DstPort != 9042 {
		t.Fatalf("packet 3 dst_port = %d, want 9042", pkts[3].L4.DstPort)
	}
	want := "0400000001000000160001000b43514c5f56455253494f4e0005332e302e30"
	if got := hexOf(pkts[3].Payload); got != want {
		t.Fatalf("STARTUP frame = %s, want %s", got, want)
	}
}

// ②presence 与顶层游离键判死（CheckProtoFlat cql 分支）。
func TestCQLChain_PresenceAndStrayTopLevelKeys(t *testing.T) {
	cfg := map[string]interface{}{
		"layers": cqlLayers(map[string]interface{}{}),
		"cql":    map[string]interface{}{},
	}
	if msg := core.CheckProtoFlat("cql", cfg); msg == "" {
		t.Fatal(`CheckProtoFlat(cql, {layers, cql:{}}) = "", want top-level cql presence rejection`)
	} else if !strings.Contains(msg, "rejects a top-level cql sub-config") {
		t.Fatalf("CheckProtoFlat msg = %q", msg)
	}
	for _, k := range []string{"src_ip", "dst_ip", "src_port", "dst_port", "count"} {
		bad := map[string]interface{}{"layers": cfg["layers"], k: 1}
		if msg := core.CheckProtoFlat("cql", bad); msg == "" {
			t.Fatalf("CheckProtoFlat(cql, {layers, %s}) = \"\", want flat-field rejection", k)
		}
	}
}

// ③载体：链夹 udp 拒、缺 tcp 拒（BuildLayersPlanner 预检，锚词 carrier）。
func TestCQLChain_CarrierRejected(t *testing.T) {
	udpArr := []interface{}{
		map[string]interface{}{"ip": map[string]interface{}{"src": "10.0.0.1", "dst": "20.0.0.1"}},
		map[string]interface{}{"udp": map[string]interface{}{"src_port": 12345, "dst_port": 9042}},
		map[string]interface{}{"cql": cqlMinEvents()},
	}
	_, err := layers.BuildLayersPlanner("cql", cqlJSON(t, udpArr))
	if err == nil {
		t.Fatal("BuildLayersPlanner([ip,udp,cql]) = nil, want carrier rejection")
	}
	if !strings.Contains(err.Error(), "carrier") {
		t.Fatalf("udp carrier error = %q, want anchor \"carrier\"", err.Error())
	}
	// 缺 tcp：DependsOn tcp 会自动补全，故必须由预检拦（否则被补全掩盖）。
	noTCP := []interface{}{
		map[string]interface{}{"ip": map[string]interface{}{"src": "10.0.0.1", "dst": "20.0.0.1"}},
		map[string]interface{}{"cql": cqlMinEvents()},
	}
	if _, err := layers.BuildLayersPlanner("cql", cqlJSON(t, noTCP)); err == nil {
		t.Fatal("BuildLayersPlanner([ip,cql]) = nil, want missing-carrier rejection")
	} else if !strings.Contains(err.Error(), "carrier") {
		t.Fatalf("missing carrier error = %q, want anchor \"carrier\"", err.Error())
	}
}

// ④用例文件收官自查：30 例（15 正 + 15 负）；非负例顶层键 ⊆ 白名单；
// presence/游离键负例在案。
func TestCQLChain_CaseFileAudit(t *testing.T) {
	raw, err := os.ReadFile("../../../test/protocol_pcap/cases/cql.json")
	if err != nil {
		t.Fatalf("read cases: %v", err)
	}
	var cases []map[string]interface{}
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatalf("parse cases: %v", err)
	}
	if len(cases) != 30 {
		t.Fatalf("want 30 cases (15 pos + 15 neg), got %d", len(cases))
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
		if _, hasCQL := sj["cql"]; hasCQL {
			if !neg {
				t.Fatalf("%s: top-level cql on non-negative case", id)
			}
			presence = true
		}
	}
	if !presence {
		t.Fatal("want 1 presence negative (layers + top-level cql), found none")
	}
}

// ⑤FieldContract 缺省：层内不写 dst_port 时由契约补 9042（用户显式优先）。
func TestCQLChain_FieldContractPortDefault(t *testing.T) {
	lj := json.RawMessage(`[{"ip":{"src":"10.0.0.1","dst":"20.0.0.1"}},{"tcp":{"src_port":12345}},{"cql":{"wire_profile":"cql_v4","events":[{"kind":"options","direction":"c2s"}]}}]`)
	p, err := layers.BuildLayersPlanner("cql", lj)
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v", err)
	}
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345}
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	n, up := 0, 0
	for pk := range ch {
		if pk.Direction == "up" && pk.L4.DstPort == 9042 {
			up++
		}
		n++
	}
	if n != 8 {
		t.Fatalf("packets = %d, want 8 (handshake 3 + 1 event + teardown 4)", n)
	}
	if up == 0 {
		t.Fatal("no up packet with DstPort=9042 (FieldContract default must apply)")
	}
}

func hexOf(b []byte) string {
	const hexDigits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, x := range b {
		out = append(out, hexDigits[x>>4], hexDigits[x&0x0f])
	}
	return string(out)
}
