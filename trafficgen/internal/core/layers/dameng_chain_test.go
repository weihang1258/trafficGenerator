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
	_ "github.com/trafficgen/trafficgen/internal/protocol/dameng" // init 注册 dameng 终结层生成器+校验器
)

// D-DAMENG-1 P4 链级红例（enip_chain_test 同构）。覆盖：
//  ① 层 config 翻译生效（G-DM-2）——[ip,tcp,dameng] 最小 connect 例出 8 包；
//  ② 严格解码未知层键拒（G-DM-2 V9，锚词 unknown field）；
//  ③ presence 负例形状（M5 清单①）：层链 + 顶层空 dameng 子映射并存判死；
//  ④ 白名单外游离键判死（M5 清单②，1.11–1.13）：CheckProtoFlat 五键 +
//     schema 语义门 MAC 键；
//  ⑤ 负例带锚词（M5 清单③）：每例断言 error_contains 命中代码锚词；
//  ⑥ 收官自查行（M5 清单④）：用例文件全例「非负例顶层键=0」。

const (
	dCli   = "10.0.0.1"
	dSrv   = "20.0.0.1"
	dSport = 12345
	dDport = 5236
)

func damengLayers(cfg map[string]interface{}) []interface{} {
	return []interface{}{
		map[string]interface{}{"ip": map[string]interface{}{"src": dCli, "dst": dSrv}},
		map[string]interface{}{"tcp": map[string]interface{}{"src_port": dSport}},
		map[string]interface{}{"dameng": cfg},
	}
}

func minDamengCfg() map[string]interface{} {
	return map[string]interface{}{
		"wire_profile": "dm8_profile_pending",
		"events": []interface{}{
			map[string]interface{}{"kind": "connect", "direction": "c2s", "profile": "connect_default"},
		},
	}
}

func planDamengAt(t *testing.T, layersArr []interface{}) ([]core.PacketConfig, error) {
	t.Helper()
	raw, _ := json.Marshal(layersArr)
	p, err := layers.BuildLayersPlanner("dameng", raw)
	if err != nil {
		return nil, err
	}
	cp, ok := p.(*layers.ChainPlanner)
	if !ok {
		t.Fatalf("planner is %T, want *layers.ChainPlanner", p)
	}
	spec := core.FlowSpec{SrcIP: dCli, DstIP: dSrv, SrcPort: dSport}
	fin, err := cp.ValidateSpec(spec)
	if err != nil {
		return nil, err
	}
	ch, err := cp.Plan(context.Background(), fin)
	if err != nil {
		return nil, err
	}
	var pkts []core.PacketConfig
	for c := range ch {
		pkts = append(pkts, c)
	}
	return pkts, nil
}

// ①层条目→Payload 翻译端到端：最小单 connect 例 8 包（握手 3 + 数据 1 + 挥手 4），首包 SYN。
func TestDamengChain_LayerToPayloadPlan(t *testing.T) {
	pkts, err := planDamengAt(t, damengLayers(minDamengCfg()))
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(pkts) != 8 {
		t.Fatalf("got %d packets, want 8 (handshake 3 + data 1 + teardown 4)", len(pkts))
	}
	if pkts[0].L4.Flags != 0x02 {
		t.Fatalf("packet 0 flags = 0x%02x, want SYN 0x02", pkts[0].L4.Flags)
	}
}

// ②严格解码未知层键拒（V9 前置探针：registry 补 Fields 之前恒 unknown field）。
func TestDamengChain_StrictDecodeUnknownLayerKey(t *testing.T) {
	cfg := minDamengCfg()
	cfg["bogus_key"] = 1
	_, err := planDamengAt(t, damengLayers(cfg))
	if err == nil {
		t.Fatal("want unknown-field rejection, got nil")
	}
	if !strings.Contains(err.Error(), "bogus_key") {
		t.Fatalf("err %q does not name the unknown key", err.Error())
	}
}

// ③ presence 负例形状（M5 清单①）：层链 + 顶层空 dameng 子映射并存 = 判死。
func TestDamengChain_PresenceRejected(t *testing.T) {
	cfg := map[string]interface{}{
		"layers": damengLayers(minDamengCfg()),
		"dameng": map[string]interface{}{},
	}
	msg := core.CheckProtoFlat("dameng", cfg)
	if msg == "" {
		t.Fatal("CheckProtoFlat(dameng, {layers, dameng:{}}) = \"\", want presence rejection")
	}
	if !strings.Contains(msg, "rejects a top-level dameng sub-config") {
		t.Fatalf("CheckProtoFlat msg = %q", msg)
	}
}

// ④ 白名单外游离键判死（M5 清单②，1.11–1.13）：四元组五键 + MAC 键。
func TestDamengChain_StrayTopLevelKeysRejected(t *testing.T) {
	layersArr := damengLayers(minDamengCfg())
	for _, k := range []string{"src_ip", "dst_ip", "src_port", "dst_port", "count"} {
		bad := map[string]interface{}{"layers": layersArr, k: 1}
		msg := core.CheckProtoFlat("dameng", bad)
		if msg == "" {
			t.Fatalf("CheckProtoFlat(dameng, {layers, %s}) = \"\", want rejection", k)
		}
		if !strings.Contains(msg, k) {
			t.Fatalf("CheckProtoFlat msg for %s = %q (must name the key)", k, msg)
		}
	}
	// MAC 类走 schema 语义门（checkLayerFlatConflict 六键）。
	_, errs := schema.ValidateStrategy("synth", "dameng", map[string]any{
		"layers":  layersArr,
		"src_mac": "aa:bb:cc:dd:ee:01",
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

// ⑤ 契约面锚词与代码一致：负例 error_contains 必须非空且 expect 键集合严格。
//（M5 清单③：一切负例带锚词，逐例可回溯）。
func TestDamengChain_NegativeAnchorsPresentInCode(t *testing.T) {
	raw, err := os.ReadFile("../../../test/protocol_pcap/cases/dameng.json")
	if err != nil {
		t.Fatalf("read cases: %v", err)
	}
	var cases []map[string]interface{}
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatalf("parse cases: %v", err)
	}
	if len(cases) == 0 {
		t.Fatal("empty case file")
	}
	for _, c := range cases {
		id, _ := c["id"].(string)
		exp, _ := c["expect"].(map[string]interface{})
		if exp == nil {
			t.Fatalf("%s: expect missing", id)
		}
		if _, isNeg := exp["expect_error"]; !isNeg {
			continue
		}
		ec, _ := exp["error_contains"].(string)
		if ec == "" {
			t.Fatalf("%s: negative case without error_contains", id)
		}
		// 负例 expect 键集合严格 {expect_error, error_contains}（+notes 注释键）。
		for k := range exp {
			if k != "expect_error" && k != "error_contains" && k != "notes" {
				t.Fatalf("%s: unexpected negative expect key %q", id, k)
			}
		}
	}
}

// ⑥ 收官自查行（M5 清单④）：非负例顶层键 = 0（白名单只有结构性键）。
func TestDamengChain_CaseFileTopLevelWhitelist(t *testing.T) {
	raw, err := os.ReadFile("../../../test/protocol_pcap/cases/dameng.json")
	if err != nil {
		t.Fatalf("read cases: %v", err)
	}
	var cases []map[string]interface{}
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatalf("parse cases: %v", err)
	}
	// group_id 例外：它是框架任务层键(同 shard 调度语义)，非协议旧键——语料内 h323_port_dyn/smb_tpos167 同形。
	allowed := map[string]bool{"layers": true, "flow_control": true, "output": true, "output_config": true, "group_id": true}
	stray := map[string]bool{}
	for _, c := range cases {
		id, _ := c["id"].(string)
		sj, _ := c["spec_json"].(map[string]interface{})
		if sj == nil {
			t.Fatalf("%s: spec_json missing", id)
		}
		exp, _ := c["expect"].(map[string]interface{})
		if _, isNeg := exp["expect_error"]; isNeg {
			continue
		}
		for k := range sj {
			if !allowed[k] {
				stray[k+" ("+id+")"] = true
			}
		}
	}
	if len(stray) > 0 {
		var names []string
		for k := range stray {
			names = append(names, k)
		}
		t.Fatalf("positive cases carry stray top-level keys (非负例顶层键必须 = 0): %v", names)
	}
}
