package layers_test

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	"github.com/trafficgen/trafficgen/internal/core/schema"
	_ "github.com/trafficgen/trafficgen/internal/protocol/tns" // init 注册 tns 终结层生成器+校验器
)

// D-TNS-1 P4 链级测试（drda_chain_test.go 同构）。覆盖：
//  ① 层条目→spec.TNS 翻译端到端（[ip,tcp,tns] S1 四事件 11 包；tns 头 type
//    字节 type 在 payload[4]，长度/端口由 FieldContract 补 1521）；
//  ② presence 与顶层游离键判死（CheckProtoFlat tns 分支；M5 必含①②：顶层
//    空 tns 子映射 + 游离键 src_mac 走 schema 语义门）；
//  ③ udp 载体拒（DependsOn=[tcp] → complete.go tcp-only 锚词 carrier）；
//  ④ G-TNS-3：sessions[1..n] 全量校验在 Protected 边界拒绝（旧实现只校验
//    Sessions[0]，坏 type 逃到生成期）；
//  ⑤ G-TNS-8：状态机跳步/终态与 direction 白名单锚词；
//  ⑥ 死字段判死（G-TNS-4 payload_profile / G-TNS-11 reconnect 严格解码）；
//  ⑦ 用例文件收官自查（17 例：8 正 + 9 负；非负例顶层键 ⊆ 白名单）。

func tnsJSON(t *testing.T, layersArr []interface{}) json.RawMessage {
	t.Helper()
	out, err := json.Marshal(layersArr)
	if err != nil {
		t.Fatalf("marshal layers: %v", err)
	}
	return out
}

func tnsLayers(tnsCfg map[string]interface{}) []interface{} {
	return []interface{}{
		map[string]interface{}{"ip": map[string]interface{}{"src": "10.0.0.1", "dst": "20.0.0.1"}},
		map[string]interface{}{"tcp": map[string]interface{}{"src_port": 12345}},
		map[string]interface{}{"tns": tnsCfg},
	}
}

func tnsPlan(t *testing.T, layersArr []interface{}) []core.PacketConfig {
	t.Helper()
	p, err := layers.BuildLayersPlanner("tns", tnsJSON(t, layersArr))
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v", err)
	}
	ch, err := p.Plan(context.Background(), core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var pkts []core.PacketConfig
	for c := range ch {
		pkts = append(pkts, c)
	}
	return pkts
}

// ① S1 翻译端到端：CONNECT/ACCEPT/DATA/DATA → 11 包（3 握手 + 4 事件 + 4 挥手），
// 目的端口由 FieldContract 补 1521，事件包 type/length 字节按设计 §3.2 落线。
func TestTNSChain_LayerToSpecPlan(t *testing.T) {
	pkts := tnsPlan(t, tnsLayers(map[string]interface{}{
		"events": []interface{}{
			map[string]interface{}{"type": "CONNECT", "direction": "c2s"},
			map[string]interface{}{"type": "ACCEPT", "direction": "s2c"},
			map[string]interface{}{"type": "DATA", "direction": "c2s", "data_flags": 0},
			map[string]interface{}{"type": "DATA", "direction": "s2c", "data_flags": 0},
		},
	}))
	if len(pkts) != 11 {
		t.Fatalf("got %d packets, want 11 (3 handshake + 4 events + 4 teardown)", len(pkts))
	}
	if pkts[0].L4.Flags != 0x02 {
		t.Fatalf("packet 1 flags = 0x%02x, want SYN 0x02", pkts[0].L4.Flags)
	}
	if pkts[0].L4.DstPort != 1521 {
		t.Fatalf("packet 1 dst port = %d, want 1521 (FieldContract)", pkts[0].L4.DstPort)
	}
	want := []struct {
		idx    int
		typ    byte
		length uint16
	}{
		{3, 0x01, 106}, // CONNECT body 98
		{4, 0x02, 28},  // ACCEPT body 20
		{5, 0x06, 10},  // DATA: 8 + data_flags 2 + 0 payload
		{6, 0x06, 10},
	}
	for _, w := range want {
		p := pkts[w.idx]
		if len(p.Payload) != int(w.length) {
			t.Fatalf("packet %d payload len = %d, want %d", w.idx+1, len(p.Payload), w.length)
		}
		if p.Payload[4] != w.typ {
			t.Fatalf("packet %d type = 0x%02x, want 0x%02x", w.idx+1, p.Payload[4], w.typ)
		}
		if got := uint16(p.Payload[0])<<8 | uint16(p.Payload[1]); got != w.length {
			t.Fatalf("packet %d length field = %d, want %d", w.idx+1, got, w.length)
		}
	}
	// 方向：CONNECT 上行 / ACCEPT 下行（evUp 语义）。
	if pkts[3].Direction != "up" || pkts[4].Direction != "down" {
		t.Fatalf("directions = %q/%q, want up/down", pkts[3].Direction, pkts[4].Direction)
	}
}

// ①b 空层 {} 走 P0b-2 缺省流：一条 DATA 事件 → 8 包（设计 §4.3 派生表 +
// testcase §3.11 tns_session_null_default；bgp 空层=缺省事件流同款）。
// 对照：显式 events: [] 是"零事件"配置 → validator 判死（nil/非 nil 二态）。
func TestTNSChain_EmptyLayerDefaultFlow(t *testing.T) {
	pkts := tnsPlan(t, tnsLayers(map[string]interface{}{}))
	if len(pkts) != 8 {
		t.Fatalf("got %d packets, want 8 (3 handshake + 1 default DATA + 4 teardown)", len(pkts))
	}
	data := pkts[3]
	if len(data.Payload) != 10 || data.Payload[4] != 0x06 {
		t.Fatalf("default event payload = %v (type %v), want DATA 10B (type 0x06)",
			data.Payload, func() interface{} {
				if len(data.Payload) > 4 {
					return data.Payload[4]
				}
				return nil
			}())
	}
	if got := uint16(data.Payload[0])<<8 | uint16(data.Payload[1]); got != 10 {
		t.Fatalf("default DATA length field = %d, want 10", got)
	}
	if data.L4.DstPort != 1521 {
		t.Fatalf("default flow dst port = %d, want 1521 (FieldContract)", data.L4.DstPort)
	}

	// 显式空 events 必须判死（与"缺键"区分）。
	raw := tnsJSON(t, tnsLayers(map[string]interface{}{"events": []interface{}{}}))
	p, err := layers.BuildLayersPlanner("tns", raw)
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v", err)
	}
	if _, perr := p.Plan(context.Background(), core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345}); perr == nil {
		t.Fatal("Plan(events: []) = nil, want at least one event rejection")
	} else if !strings.Contains(perr.Error(), "at least one event") {
		t.Fatalf("Plan err = %q, want anchor \"at least one event\"", perr.Error())
	}
}

// ② presence 与顶层游离键判死（M5 必含）。
func TestTNSChain_PresenceAndStrayTopLevelKeys(t *testing.T) {
	cfg := map[string]interface{}{
		"layers": tnsLayers(map[string]interface{}{
			"events": []interface{}{map[string]interface{}{"type": "CONNECT", "direction": "c2s"}},
		}),
		"tns": map[string]interface{}{},
	}
	if msg := core.CheckProtoFlat("tns", cfg); msg == "" {
		t.Fatal("CheckProtoFlat(tns, {layers, tns:{}}) = \"\", want top-level tns presence rejection")
	} else if !strings.Contains(msg, "no longer accepts a top-level tns sub-config") {
		t.Fatalf("CheckProtoFlat msg = %q", msg)
	}
	for _, k := range []string{"src_ip", "dst_ip", "src_port", "dst_port", "count"} {
		bad := map[string]interface{}{"layers": cfg["layers"], k: 1}
		if msg := core.CheckProtoFlat("tns", bad); msg == "" {
			t.Fatalf("CheckProtoFlat(tns, {layers, %s}) = \"\", want flat-field rejection", k)
		}
	}
	// MAC 类游离键走 schema 语义门（checkLayerFlatConflict 六键，M5②）。
	_, errs := schema.ValidateStrategy("synth", "tns", map[string]any{
		"layers":  cfg["layers"],
		"src_mac": "02:00:00:00:00:01",
	}, nil)
	found := false
	for _, e := range errs {
		if strings.Contains(e.Error(), "src_mac") {
			found = true
		}
	}
	if !found {
		t.Fatalf("schema must reject top-level src_mac alongside layers, errs=%v", errs)
	}
}

// ③ udp 载体拒（DependsOn=[tcp] tcp-only，锚词 carrier）。
func TestTNSChain_UDPCarrierRejected(t *testing.T) {
	arr := []interface{}{
		map[string]interface{}{"ip": map[string]interface{}{"src": "10.0.0.1", "dst": "20.0.0.1"}},
		map[string]interface{}{"udp": map[string]interface{}{"src_port": 12345, "dst_port": 1521}},
		map[string]interface{}{"tns": map[string]interface{}{
			"events": []interface{}{map[string]interface{}{"type": "CONNECT", "direction": "c2s"}},
		}},
	}
	_, err := layers.BuildLayersPlanner("tns", tnsJSON(t, arr))
	if err == nil {
		t.Fatal("BuildLayersPlanner([ip,udp,tns]) = nil, want carrier rejection")
	}
	if !strings.Contains(err.Error(), "carrier") || !strings.Contains(err.Error(), "tcp") {
		t.Fatalf("carrier error = %q, want anchors \"carrier\" + \"tcp\"", err.Error())
	}
}

// ④ G-TNS-3：sessions[1..n] 全量校验——坏 type 在 Sessions[1] 也必须在
// validator 边界拒绝（旧实现只校验 Sessions[0]，坏事件逃到生成期）。
func TestTNSChain_SessionsBeyondFirstValidated(t *testing.T) {
	arr := tnsLayers(map[string]interface{}{
		"sessions": []interface{}{
			map[string]interface{}{"src_port": 41234, "events": []interface{}{
				map[string]interface{}{"type": "CONNECT", "direction": "c2s"},
				map[string]interface{}{"type": "ACCEPT", "direction": "s2c"},
			}},
			map[string]interface{}{"src_port": 41235, "events": []interface{}{
				map[string]interface{}{"type": 127},
			}},
		},
	})
	p, err := layers.BuildLayersPlanner("tns", tnsJSON(t, arr))
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v", err)
	}
	if _, perr := p.Plan(context.Background(), core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345}); perr == nil {
		t.Fatal("Plan(sessions[1].type=127) = nil, want unknown packet type rejection")
	} else if !strings.Contains(perr.Error(), "unknown packet type") {
		t.Fatalf("Plan err = %q, want anchor \"unknown packet type\"", perr.Error())
	}
	// 合法双会话放行：18 包（2 × (3 + 2 + 4)），各自独立握手挥手。
	pkts := tnsPlan(t, tnsLayers(map[string]interface{}{
		"sessions": []interface{}{
			map[string]interface{}{"src_port": 41234, "events": []interface{}{
				map[string]interface{}{"type": "CONNECT", "direction": "c2s"},
				map[string]interface{}{"type": "ACCEPT", "direction": "s2c"},
			}},
			map[string]interface{}{"src_port": 41235, "events": []interface{}{
				map[string]interface{}{"type": "CONNECT", "direction": "c2s"},
				map[string]interface{}{"type": "ACCEPT", "direction": "s2c"},
			}},
		},
	}))
	if len(pkts) != 18 {
		t.Fatalf("got %d packets, want 18 (2 sessions × 9)", len(pkts))
	}
	seen := map[uint16]bool{}
	for _, p := range pkts {
		if p.Direction == "up" && p.L4.Flags == 0x02 {
			seen[p.L4.SrcPort] = true
		}
	}
	if !seen[41234] || !seen[41235] {
		t.Fatalf("handshake src ports = %v, want both 41234 and 41235", seen)
	}
}

// ⑤ G-TNS-8 状态机与 direction 白名单锚词（链路径）。
func TestTNSChain_StateMachineAndDirectionAnchors(t *testing.T) {
	skip := tnsLayers(map[string]interface{}{
		"events": []interface{}{
			map[string]interface{}{"type": "CONNECT", "direction": "c2s"},
			map[string]interface{}{"type": "DATA", "direction": "s2c"},
		},
	})
	p, err := layers.BuildLayersPlanner("tns", tnsJSON(t, skip))
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v", err)
	}
	if _, perr := p.Plan(context.Background(), core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345}); perr == nil {
		t.Fatal("Plan(DATA before ACCEPT) = nil, want state violation")
	} else if !strings.Contains(perr.Error(), "state violation") {
		t.Fatalf("Plan err = %q, want anchor \"state violation\"", perr.Error())
	}

	badDir := tnsLayers(map[string]interface{}{
		"events": []interface{}{map[string]interface{}{"type": "CONNECT", "direction": "sideways"}},
	})
	p2, err := layers.BuildLayersPlanner("tns", tnsJSON(t, badDir))
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v", err)
	}
	if _, perr := p2.Plan(context.Background(), core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345}); perr == nil {
		t.Fatal("Plan(direction=sideways) = nil, want unknown direction rejection")
	} else if !strings.Contains(perr.Error(), "direction") {
		t.Fatalf("Plan err = %q, want anchor \"direction\"", perr.Error())
	}
}

// ⑤b type 双形同锚词：字符串形（"BOGUS"）与数值形（127）在链路径都被拒，
// 锚词同为 eventType 的 "unknown packet type"（设计 §3.12 双承载形）。
func TestTNSChain_UnknownTypeBothForms(t *testing.T) {
	for _, bad := range []interface{}{"BOGUS", 127} {
		arr := tnsLayers(map[string]interface{}{
			"events": []interface{}{map[string]interface{}{"type": bad, "direction": "c2s"}},
		})
		p, err := layers.BuildLayersPlanner("tns", tnsJSON(t, arr))
		if err != nil {
			t.Fatalf("BuildLayersPlanner(%v): %v", bad, err)
		}
		if _, perr := p.Plan(context.Background(), core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345}); perr == nil {
			t.Fatalf("Plan(type=%v) = nil, want unknown packet type rejection", bad)
		} else if !strings.Contains(perr.Error(), "unknown packet type") {
			t.Fatalf("Plan(type=%v) err = %q, want anchor \"unknown packet type\"", bad, perr.Error())
		}
	}
}

// ⑥ 死字段判死：G-TNS-4 payload_profile（事件级）与 G-TNS-11 reconnect
// （配置级）——层内写任一即拒（严格解码 / V9 unknown field），不再"配上不生效"。
func TestTNSChain_DeadFieldsRejected(t *testing.T) {
	prof := tnsLayers(map[string]interface{}{
		"events": []interface{}{map[string]interface{}{"type": "CONNECT", "direction": "c2s", "payload_profile": "connect_basic"}},
	})
	p, err := layers.BuildLayersPlanner("tns", tnsJSON(t, prof))
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v", err)
	}
	if _, perr := p.Plan(context.Background(), core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345}); perr == nil {
		t.Fatal("Plan(payload_profile) = nil, want unknown field rejection")
	} else if !strings.Contains(perr.Error(), "payload_profile") {
		t.Fatalf("Plan err = %q, want anchor \"payload_profile\"", perr.Error())
	}

	reconn := tnsLayers(map[string]interface{}{
		"events":    []interface{}{map[string]interface{}{"type": "CONNECT", "direction": "c2s"}},
		"reconnect": false,
	})
	if _, err := layers.BuildLayersPlanner("tns", tnsJSON(t, reconn)); err == nil {
		t.Fatal("BuildLayersPlanner(reconnect) = nil, want unknown field rejection")
	} else if !strings.Contains(err.Error(), "reconnect") {
		t.Fatalf("build err = %q, want anchor \"reconnect\"", err.Error())
	}
}

// ⑦ 用例文件收官自查：17 例（8 正 + 9 负）；非负例顶层键 ⊆ {layers,
// flow_control, output}（收官自查行「非负例顶层键=0」）；presence 与游离键
// 负例在案；负例 expect 键集严格 = {expect_error, error_contains}。
func TestTNSChain_CaseFileAudit(t *testing.T) {
	raw, err := os.ReadFile("../../../test/protocol_pcap/cases/tns.json")
	if err != nil {
		t.Fatalf("read cases: %v", err)
	}
	var cases []map[string]interface{}
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatalf("parse cases: %v", err)
	}
	if len(cases) != 17 {
		t.Fatalf("want 17 cases (8 pos + 9 neg), got %d", len(cases))
	}
	allowed := map[string]bool{"layers": true, "flow_control": true, "output": true}
	presence, stray := false, false
	pos, neg := 0, 0
	for _, c := range cases {
		id, _ := c["id"].(string)
		sj, _ := c["spec_json"].(map[string]interface{})
		if sj == nil {
			t.Fatalf("%s: spec_json missing", id)
		}
		exp, _ := c["expect"].(map[string]interface{})
		isNeg := exp != nil && exp["expect_error"] == true
		if isNeg {
			neg++
			if len(exp) != 2 || exp["error_contains"] == nil || exp["error_contains"] == "" {
				t.Fatalf("%s: negative expect keys = %v, want exactly {expect_error, error_contains}", id, exp)
			}
		} else {
			pos++
			for k := range sj {
				if !allowed[k] {
					t.Fatalf("%s: non-negative top-level key %q (want ⊆ layers/flow_control/output)", id, k)
				}
			}
		}
		if _, has := sj["tns"]; has {
			if !isNeg {
				t.Fatalf("%s: top-level tns on non-negative case", id)
			}
			presence = true
		}
		if _, has := sj["src_mac"]; has {
			if !isNeg {
				t.Fatalf("%s: top-level src_mac on non-negative case", id)
			}
			stray = true
		}
		// 断言通道诚实性：tns.* 字段断言只允许设计 §3.1 的 dissector 字段名。
		if fields, ok := exp["fields"].([]interface{}); ok {
			for _, fi := range fields {
				fm, _ := fi.(map[string]interface{})
				f, _ := fm["field"].(string)
				if !strings.HasPrefix(f, "tns.") {
					continue
				}
				switch f {
				case "tns.type", "tns.length", "tns.reserved_byte",
					"tns.packet_checksum", "tns.header_checksum", "tns.data_flag":
				default:
					t.Fatalf("%s: unverified tns field assertion %q", id, f)
				}
			}
		}
	}
	if pos != 8 || neg != 9 {
		t.Fatalf("want 8 pos + 9 neg, got %d pos + %d neg", pos, neg)
	}
	if !presence {
		t.Fatal("want presence negative (layers + top-level tns), found none")
	}
	if !stray {
		t.Fatal("want stray top-level key negative (layers + src_mac), found none")
	}
}
