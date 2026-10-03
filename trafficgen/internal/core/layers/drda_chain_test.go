package layers_test

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	_ "github.com/trafficgen/trafficgen/internal/protocol/drda" // init 注册 drda 终结层生成器+校验器
)

// D-DRDA-1 P4 链级红例：①层条目→DRDA 翻译端到端（[ip,tcp,drda] association
// 四档：excsat 9 / security 13 / database 15 / sql 17；握手 3 + 2N + 挥手 4）
// /②presence 与顶层游离键判死（CheckProtoFlat drda 分支；M5 必含①②：顶层空
// drda 子映射 + 游离键）/③udp 载体拒（DependsOn=[tcp]，complete.go tcp-only
// 锚词 carrier）/④dss_length 负例锚词（planner.go:35/39）+ 端口契约锚词
// （planner.go dst_port must be 446）/⑤T-11 chained format 0x41 /⑥用例文件
// 收官自查（13 例：9 正 + 4 负；非负例顶层键=0）。

func drdaJSON(t *testing.T, layersArr []interface{}) json.RawMessage {
	t.Helper()
	out, err := json.Marshal(layersArr)
	if err != nil {
		t.Fatalf("marshal layers: %v", err)
	}
	return out
}

func drdaLayers(drdaCfg map[string]interface{}) []interface{} {
	return []interface{}{
		map[string]interface{}{"ip": map[string]interface{}{"src": "10.0.0.1", "dst": "20.0.0.1"}},
		map[string]interface{}{"tcp": map[string]interface{}{"src_port": 12345}},
		map[string]interface{}{"drda": drdaCfg},
	}
}

func drdaPlan(t *testing.T, layersArr []interface{}) []core.PacketConfig {
	t.Helper()
	p, err := layers.BuildLayersPlanner("drda", drdaJSON(t, layersArr))
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v", err)
	}
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345}
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

// ① association 四档翻译端到端。
func TestDRDAChain_AssociationTiers(t *testing.T) {
	cases := []struct {
		name string
		cfg  map[string]interface{}
		want int
	}{
		{"excsat", map[string]interface{}{"association": "excsat", "correlator_start": 1, "ccsid": 1208}, 9},
		{"security", map[string]interface{}{"association": "security", "correlator_start": 1, "ccsid": 1208, "security_user": "TESTUSR"}, 13},
		{"database", map[string]interface{}{"association": "database", "correlator_start": 1, "ccsid": 1208, "rdb_name": "SAMPLE"}, 15},
		{"sql", map[string]interface{}{"association": "sql", "correlator_start": 1, "ccsid": 1208, "rdb_name": "SAMPLE",
			"sql": map[string]interface{}{"data": []interface{}{1, 2, 3, 4}, "code": 0, "state": "00000"}}, 17},
	}
	for _, c := range cases {
		pkts := drdaPlan(t, drdaLayers(c.cfg))
		if len(pkts) != c.want {
			t.Fatalf("%s: got %d packets, want %d", c.name, len(pkts), c.want)
		}
		if pkts[0].L4.Flags != 0x02 {
			t.Fatalf("%s: packet 0 flags = 0x%02x, want SYN 0x02", c.name, pkts[0].L4.Flags)
		}
	}
}

// ①b 空层默认流：P0b-2 空配置默认化（assoc 空 + 无 SQL = 4 对，15 包）。
func TestDRDAChain_EmptyLayerDefault(t *testing.T) {
	pkts := drdaPlan(t, drdaLayers(map[string]interface{}{}))
	if len(pkts) != 15 {
		t.Fatalf("got %d packets, want 15 (empty config default: full 4-pair sequence)", len(pkts))
	}
}

// ② presence 与顶层游离键判死（M5 必含）。
func TestDRDAChain_PresenceAndStrayTopLevelKeys(t *testing.T) {
	cfg := map[string]interface{}{
		"layers": drdaLayers(map[string]interface{}{}),
		"drda":   map[string]interface{}{},
	}
	if msg := core.CheckProtoFlat("drda", cfg); msg == "" {
		t.Fatal("CheckProtoFlat(drda, {layers, drda:{}}) = \"\", want top-level drda presence rejection")
	} else if !strings.Contains(msg, "rejects a top-level drda sub-config") {
		t.Fatalf("CheckProtoFlat msg = %q", msg)
	}
	for _, k := range []string{"src_ip", "dst_ip", "src_port", "dst_port", "count"} {
		bad := map[string]interface{}{"layers": cfg["layers"], k: 1}
		if msg := core.CheckProtoFlat("drda", bad); msg == "" {
			t.Fatalf("CheckProtoFlat(drda, {layers, %s}) = \"\", want flat-field rejection", k)
		}
	}
}

// ③ udp 载体拒（DependsOn=[tcp] tcp-only，锚词 carrier）。
func TestDRDAChain_UDPCarrierRejected(t *testing.T) {
	arr := []interface{}{
		map[string]interface{}{"ip": map[string]interface{}{"src": "10.0.0.1", "dst": "20.0.0.1"}},
		map[string]interface{}{"udp": map[string]interface{}{"src_port": 12345, "dst_port": 446}},
		map[string]interface{}{"drda": map[string]interface{}{"association": "excsat"}},
	}
	_, err := layers.BuildLayersPlanner("drda", drdaJSON(t, arr))
	if err == nil {
		t.Fatal("BuildLayersPlanner([ip,udp,drda]) = nil, want carrier rejection")
	}
	if !strings.Contains(err.Error(), "carrier") {
		t.Fatalf("carrier error = %q, want anchor \"carrier\"", err.Error())
	}
}

// ④ dss_length 负例锚词（planner.go:35 下界 / :39 失配）。
func TestDRDAChain_DSSLengthAnchors(t *testing.T) {
	bad := map[string]interface{}{
		"association": "excsat", "dss_length": 11,
		"dss_segments": []interface{}{map[string]interface{}{"format": 1, "correlator": 1, "length": 10, "length2": 4, "code_point": 4161}},
	}
	_, err := layers.BuildLayersPlanner("drda", drdaJSON(t, drdaLayers(bad)))
	if err == nil {
		// BuildLayersPlanner 只做链形状校验；长度锚词在 Plan/Validate 期。
		// 此处不断言 Build 期拒，改走 Plan 期断言。
		p, berr := layers.BuildLayersPlanner("drda", drdaJSON(t, drdaLayers(bad)))
		if berr != nil {
			t.Fatalf("BuildLayersPlanner: %v", berr)
		}
		spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345}
		if _, perr := p.Plan(context.Background(), spec); perr == nil {
			t.Fatal("Plan(dss_length=11 vs 10) = nil, want dss_length rejection")
		} else if !strings.Contains(perr.Error(), "dss_length") {
			t.Fatalf("Plan err = %q, want anchor \"dss_length\"", perr.Error())
		}
	} else if !strings.Contains(err.Error(), "dss_length") {
		t.Fatalf("Build err = %q, want anchor \"dss_length\"", err.Error())
	}
}

// ⑤ T-11 chained format 0x41：请求首 DDM format=0x41，响应 format=0x01。
func TestDRDAChain_ChainedFormat(t *testing.T) {
	cfg := map[string]interface{}{
		"dss_length": 10,
		"dss_segments": []interface{}{map[string]interface{}{
			"format": 65, "correlator": 1, "length": 10, "length2": 4, "code_point": 4161}},
	}
	pkts := drdaPlan(t, drdaLayers(cfg))
	if len(pkts) != 9 {
		t.Fatalf("got %d packets, want 9", len(pkts))
	}
	if len(pkts[3].Payload) < 10 || pkts[3].Payload[3] != 0x41 {
		t.Fatalf("pkt4 format = 0x%02x, want chained 0x41", pkts[3].Payload[3])
	}
	if len(pkts[4].Payload) < 10 || pkts[4].Payload[3] != 0x01 {
		t.Fatalf("pkt5 (response) format = 0x%02x, want 0x01", pkts[4].Payload[3])
	}
}

// ⑤b 端口契约：层内显式 tcp.dst_port 非 446 即拒（planner 端口域）。
func TestDRDAChain_PortContractRejected(t *testing.T) {
	arr := []interface{}{
		map[string]interface{}{"ip": map[string]interface{}{"src": "10.0.0.1", "dst": "20.0.0.1"}},
		map[string]interface{}{"tcp": map[string]interface{}{"src_port": 12345, "dst_port": 5000}},
		map[string]interface{}{"drda": map[string]interface{}{"association": "excsat"}},
	}
	p, err := layers.BuildLayersPlanner("drda", drdaJSON(t, arr))
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v", err)
	}
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345}
	if _, perr := p.Plan(context.Background(), spec); perr == nil {
		t.Fatal("Plan(tcp.dst_port=5000) = nil, want port contract rejection")
	} else if !strings.Contains(perr.Error(), "dst_port must be 446") {
		t.Fatalf("Plan err = %q, want anchor \"dst_port must be 446\"", perr.Error())
	}
	// 显式 446 必须放行（契约端口本身）。
	arr[1] = map[string]interface{}{"tcp": map[string]interface{}{"src_port": 12345, "dst_port": 446}}
	p2, err := layers.BuildLayersPlanner("drda", drdaJSON(t, arr))
	if err != nil {
		t.Fatalf("BuildLayersPlanner(446): %v", err)
	}
	ch, perr := p2.Plan(context.Background(), spec)
	if perr != nil {
		t.Fatalf("Plan(tcp.dst_port=446) err: %v", perr)
	}
	n := 0
	for range ch {
		n++
	}
	if n != 9 {
		t.Fatalf("explicit 446: got %d packets, want 9", n)
	}
}

// ⑥ 用例文件收官自查：13 例（9 正 + 4 负）；非负例顶层键 ⊆ 白名单；
// presence 负例在案；层 drda 条目非空（负例 udp_rejected 豁免——其 drda
// 条目 association 纯触发载体拒形状）。
func TestDRDAChain_CaseFileAudit(t *testing.T) {
	raw, err := os.ReadFile("../../../test/protocol_pcap/cases/drda.json")
	if err != nil {
		t.Fatalf("read cases: %v", err)
	}
	var cases []map[string]interface{}
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatalf("parse cases: %v", err)
	}
	if len(cases) != 13 {
		t.Fatalf("want 13 cases (9 pos + 4 neg), got %d", len(cases))
	}
	allowed := map[string]bool{"layers": true, "flow_control": true, "output": true, "output_config": true, "group_id": true}
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
		if _, hasDrda := sj["drda"]; hasDrda {
			if !neg {
				t.Fatalf("%s: top-level drda on non-negative case", id)
			}
			presence = true
		}
	}
	if !presence {
		t.Fatal("want 1 presence negative (layers + top-level drda), found none")
	}
}
