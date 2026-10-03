package layers_test

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	_ "github.com/trafficgen/trafficgen/internal/protocol/cflow" // init 注册 cflow 终结层生成器+校验器
)

// D-CFLOW-1 P4 链级测试：①层条目→spec.CFlow 翻译端到端（[ip,udp,cflow]
// 出包 1，v9/IPFIX 双 profile）/②presence 与顶层游离键判死（CheckProtoFlat
// cflow 分支）/③G-CFLOW-4 载体锚词面（tcp 载体 / 缺 udp 载体，own-protocol
// 块，不复用 planner 端口守卫锚词）/④端口域回填（IPFIX 层写 4739 不被
// 缺省 2055 顶掉）/⑤用例文件收官自查（非负例顶层键 ⊆ {layers}）。

func cJSON(t *testing.T, v interface{}) json.RawMessage {
	t.Helper()
	out, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return out
}

func cV9Cfg() map[string]interface{} {
	return map[string]interface{}{
		"profile":   "netflow_v9_rfc3954",
		"source_id": 7,
		"templates": []interface{}{
			map[string]interface{}{
				"template_id": 256,
				"fields": []interface{}{
					map[string]interface{}{"element_id": 8, "length": 4},
					map[string]interface{}{"element_id": 12, "length": 4},
				},
			},
		},
		"records": []interface{}{
			map[string]interface{}{
				"template_id": 256,
				"record":      map[string]interface{}{"srcaddr": "10.43.1.1", "dstaddr": "10.43.1.2"},
			},
		},
	}
}

func cLayers(udpLayer, cflowCfg map[string]interface{}) []interface{} {
	return []interface{}{
		map[string]interface{}{"ip": map[string]interface{}{"src": "192.0.2.10", "dst": "198.51.100.10"}},
		map[string]interface{}{"udp": udpLayer},
		map[string]interface{}{"cflow": cflowCfg},
	}
}

func cPlan(t *testing.T, layersArr []interface{}) []core.PacketConfig {
	t.Helper()
	p, err := layers.BuildLayersPlanner("cflow", cJSON(t, layersArr))
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v", err)
	}
	ch, err := p.Plan(context.Background(), core.FlowSpec{SrcIP: "192.0.2.10", DstIP: "198.51.100.10", SrcPort: 40000, DstPort: 2055})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var pkts []core.PacketConfig
	for c := range ch {
		pkts = append(pkts, c)
	}
	return pkts
}

// ①层条目→spec.CFlow 翻译端到端：v9 一包（UDP payload 起 offset 42 = 20B
// header + Template FlowSet + Data FlowSet），IPFIX 同（offset 42 = 16B header）。
func TestCFlowChain_LayerToSpecPlan(t *testing.T) {
	pkts := cPlan(t, cLayers(map[string]interface{}{"src_port": 40000, "dst_port": 2055}, cV9Cfg()))
	if len(pkts) != 1 {
		t.Fatalf("v9: got %d packets, want 1", len(pkts))
	}
	p := pkts[0].Payload
	if len(p) < 20 || p[0] != 0x00 || p[1] != 0x09 {
		t.Fatalf("v9 payload version = % x, want 00 09 prefix (len %d)", p[:2], len(p))
	}
	if got := uint16(p[2])<<8 | uint16(p[3]); got != 2 {
		t.Fatalf("v9 count = %d, want 2 (1 template + 1 data record)", got)
	}

	ipfix := map[string]interface{}{
		"profile":               "ipfix_rfc7011",
		"observation_domain_id": 43,
		"templates": []interface{}{
			map[string]interface{}{
				"template_id": 256,
				"fields": []interface{}{
					map[string]interface{}{"element_id": 8, "length": 4},
				},
			},
		},
		"records": []interface{}{
			map[string]interface{}{
				"template_id": 256,
				"record":      map[string]interface{}{"sourceIPv4Address": "10.43.8.1"},
			},
		},
	}
	pkts = cPlan(t, cLayers(map[string]interface{}{"src_port": 40000, "dst_port": 4739}, ipfix))
	if len(pkts) != 1 {
		t.Fatalf("ipfix: got %d packets, want 1", len(pkts))
	}
	p = pkts[0].Payload
	if len(p) < 16 || p[0] != 0x00 || p[1] != 0x0a {
		t.Fatalf("ipfix payload version = % x, want 00 0a prefix (len %d)", p[:2], len(p))
	}
	if got := uint16(p[2])<<8 | uint16(p[3]); int(got) != len(p) {
		t.Fatalf("ipfix length = %d, want full message length %d", got, len(p))
	}
	if got := uint32(p[12])<<24 | uint32(p[13])<<16 | uint32(p[14])<<8 | uint32(p[15]); got != 43 {
		t.Fatalf("ipfix OD id = %d, want 43", got)
	}
}

// ②presence 与顶层游离键判死。
func TestCFlowChain_PresenceAndStrayTopLevelKeys(t *testing.T) {
	cfg := map[string]interface{}{
		"layers": cLayers(map[string]interface{}{"src_port": 40000, "dst_port": 2055}, cV9Cfg()),
		"cflow":  map[string]interface{}{},
	}
	if msg := core.CheckProtoFlat("cflow", cfg); msg == "" {
		t.Fatal("CheckProtoFlat(cflow, {layers, cflow:{}}) = \"\", want top-level cflow presence rejection")
	} else if !strings.Contains(msg, "rejects a top-level cflow sub-config") {
		t.Fatalf("CheckProtoFlat msg = %q", msg)
	}
	for _, k := range []string{"src_ip", "dst_ip", "src_port", "dst_port", "count"} {
		bad := map[string]interface{}{"layers": cfg["layers"], k: 1}
		if msg := core.CheckProtoFlat("cflow", bad); msg == "" {
			t.Fatalf("CheckProtoFlat(cflow, {layers, %s}) = \"\", want flat-field rejection", k)
		}
	}
}

// ③G-CFLOW-4 载体锚词面：链夹 tcp → "tcp carrier is not supported …(carrier)"
// （registry TransportOn=["udp"] 驱动，own-protocol 块，非 planner 端口守卫）；
// 缺 udp → "missing udp carrier …(carrier)"。两者都与 planner.go 的
// "requires udp port 2055" 端口守卫锚词不同源。
func TestCFlowChain_CarrierAnchors(t *testing.T) {
	tcpChain := []interface{}{
		map[string]interface{}{"ip": map[string]interface{}{"src": "10.0.0.1", "dst": "20.0.0.1"}},
		map[string]interface{}{"tcp": map[string]interface{}{"src_port": 40000, "dst_port": 2055}},
		map[string]interface{}{"cflow": cV9Cfg()},
	}
	_, err := layers.BuildLayersPlanner("cflow", cJSON(t, tcpChain))
	if err == nil {
		t.Fatal("BuildLayersPlanner([ip,tcp,cflow]) = nil, want carrier rejection")
	}
	if !strings.Contains(err.Error(), "tcp carrier is not supported") || !strings.Contains(err.Error(), "carrier") {
		t.Fatalf("tcp carrier error = %q, want own-protocol carrier anchor", err.Error())
	}

	noUDP := []interface{}{
		map[string]interface{}{"ip": map[string]interface{}{"src": "10.0.0.1", "dst": "20.0.0.1"}},
		map[string]interface{}{"cflow": cV9Cfg()},
	}
	_, err = layers.BuildLayersPlanner("cflow", cJSON(t, noUDP))
	if err == nil {
		t.Fatal("BuildLayersPlanner([ip,cflow]) = nil, want missing-carrier rejection")
	}
	if !strings.Contains(err.Error(), "missing udp carrier") {
		t.Fatalf("missing carrier error = %q, want \"missing udp carrier\"", err.Error())
	}
}

// ④端口域回填：IPFIX 层显式 4739 不被 spec 缺省 2055 顶掉（validator 按
// 层值判域）；v9 层写 4739 → planner 端口守卫拒（锚词 udp）；IPFIX 链
// 缺省 udp.dst_port → profile 感知缺省 4739（设计 §2 端口表；base 期
// spec.CFlow 尚 nil，只有 2055 会误判）。
func TestCFlowChain_PortDomainBackfill(t *testing.T) {
	ipfix := func() map[string]interface{} {
		return map[string]interface{}{
			"profile":               "ipfix_rfc7011",
			"observation_domain_id": 43,
			"templates": []interface{}{
				map[string]interface{}{
					"template_id": 256,
					"fields":      []interface{}{map[string]interface{}{"element_id": 8, "length": 4}},
				},
			},
			"records": []interface{}{
				map[string]interface{}{
					"template_id": 256,
					"record":      map[string]interface{}{"sourceIPv4Address": "10.43.8.1"},
				},
			},
		}
	}
	p, err := layers.BuildLayersPlanner("cflow", cJSON(t, cLayers(map[string]interface{}{"src_port": 40000, "dst_port": 4739}, ipfix())))
	if err != nil {
		t.Fatalf("BuildLayersPlanner(ipfix 4739): %v", err)
	}
	// Plan 以 spec 缺省 2055 进入：层值 4739 必须回填，否则 validator 拒。
	if _, err := p.Plan(context.Background(), core.FlowSpec{SrcIP: "192.0.2.10", DstIP: "198.51.100.10", SrcPort: 40000, DstPort: 2055}); err != nil {
		t.Fatalf("Plan(ipfix layer port 4739): %v", err)
	}

	p, err = layers.BuildLayersPlanner("cflow", cJSON(t, cLayers(map[string]interface{}{"src_port": 43005, "dst_port": 4739}, cV9Cfg())))
	if err != nil {
		t.Fatalf("BuildLayersPlanner(v9 on 4739): %v", err)
	}
	_, err = p.Plan(context.Background(), core.FlowSpec{SrcIP: "192.0.2.35", DstIP: "198.51.100.35", SrcPort: 43005, DstPort: 2055})
	if err == nil {
		t.Fatal("Plan(v9 profile on layer port 4739) = nil, want port-domain rejection")
	}
	if !strings.Contains(err.Error(), "2055") {
		t.Fatalf("port-domain error = %q, want anchor naming 2055", err.Error())
	}

	// IPFIX 链 udp 层不写 dst_port → 缺省按 profile 解析成 4739 而非 2055。
	p, err = layers.BuildLayersPlanner("cflow", cJSON(t, cLayers(map[string]interface{}{"src_port": 40000}, ipfix())))
	if err != nil {
		t.Fatalf("BuildLayersPlanner(ipfix, no layer port): %v", err)
	}
	ch, err := p.Plan(context.Background(), core.FlowSpec{SrcIP: "192.0.2.10", DstIP: "198.51.100.10", SrcPort: 40000, DstPort: 2055})
	if err != nil {
		t.Fatalf("Plan(ipfix, no layer port): %v", err)
	}
	n := 0
	for pkt := range ch {
		n++
		if pkt.L4.DstPort != 4739 {
			t.Fatalf("ipfix default dst_port = %d, want 4739 (profile-aware default)", pkt.L4.DstPort)
		}
	}
	if n != 1 {
		t.Fatalf("ipfix default-port case: got %d packets, want 1", n)
	}
}

// ⑤用例文件收官自查：27 例（15 正 + 12 负）；非负例顶层键 ⊆ {layers}；
// presence/载体/游离键负例在案。
func TestCFlowChain_CaseFileAudit(t *testing.T) {
	raw, err := os.ReadFile("../../../test/protocol_pcap/cases/cflow.json")
	if err != nil {
		t.Fatalf("read cases: %v", err)
	}
	var cases []map[string]interface{}
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatalf("parse cases: %v", err)
	}
	if len(cases) != 27 {
		t.Fatalf("want 27 cases (15 pos + 12 neg), got %d", len(cases))
	}
	allowed := map[string]bool{"layers": true}
	wantNeg := map[string]bool{
		"cflow_neg_presence_top_level_cflow": false,
		"cflow_neg_carrier_tcp":              false,
		"cflow_neg_carrier_no_udp":           false,
		"cflow_neg_flat_count":               false,
		"cflow_neg_unknown_layer_field":      false,
	}
	pos := 0
	for _, c := range cases {
		id, _ := c["id"].(string)
		sj, _ := c["spec_json"].(map[string]interface{})
		if sj == nil {
			t.Fatalf("%s: spec_json missing", id)
		}
		exp, _ := c["expect"].(map[string]interface{})
		neg := exp != nil && exp["expect_error"] == true
		if !neg {
			pos++
			for k := range sj {
				if !allowed[k] {
					t.Fatalf("%s: non-negative top-level key %q (want ⊆ layers)", id, k)
				}
			}
		}
		if _, tracked := wantNeg[id]; tracked {
			if !neg {
				t.Fatalf("%s: want negative case, got positive", id)
			}
			wantNeg[id] = true
		}
	}
	if pos != 15 {
		t.Fatalf("want 15 positive cases, got %d", pos)
	}
	for id, seen := range wantNeg {
		if !seen {
			t.Fatalf("red case %s missing from cases file", id)
		}
	}
}
