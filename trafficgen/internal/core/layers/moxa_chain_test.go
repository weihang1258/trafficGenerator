package layers_test

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	_ "github.com/trafficgen/trafficgen/internal/protocol/moxa" // init 注册 moxa 终结层生成器+校验器
)

// D-MOXA-1 G-MOXA-1 P4 链级测试（rtmfp/drda_chain_test.go 同构）：
// ①层条目→spec.MOXA 翻译端到端（[ip,tcp,moxa] 出 3+N+4 包 + 缺省端口）
// ②空层 config 走 P0b-2 默认流（stream 缺键 vs 显式 [] 二态）
// ③presence 与顶层游离键判死（CheckProtoFlat moxa 分支）
// ④载体拒绝：夹 udp 载体（carrier）
// ⑤载体违例：层内 tcp.handshake=false 必须仍被拒（层链形状下 spec.TCP 回填）
// ⑥严格解码（stream[] 元素内层未知键拒，bgp 范式）
// ⑦用例文件收官自查（23 例：11 正 + 12 负；非负例顶层键 ⊆ 白名单）

const (
	moxaCli = "10.0.0.1"
	moxaSrv = "20.0.0.1"
)

func moxaJSON(t *testing.T, layersArr []interface{}) json.RawMessage {
	t.Helper()
	out, err := json.Marshal(layersArr)
	if err != nil {
		t.Fatalf("marshal layers: %v", err)
	}
	return out
}

func moxaLayers(moxaCfg map[string]interface{}, tcpCfg map[string]interface{}) []interface{} {
	if tcpCfg == nil {
		tcpCfg = map[string]interface{}{"dst_port": 4800}
	}
	return []interface{}{
		map[string]interface{}{"ip": map[string]interface{}{"src": moxaCli, "dst": moxaSrv}},
		map[string]interface{}{"tcp": tcpCfg},
		map[string]interface{}{"moxa": moxaCfg},
	}
}

func moxaPlan(t *testing.T, layersArr []interface{}) ([]core.PacketConfig, error) {
	t.Helper()
	p, err := layers.BuildLayersPlanner("moxa", moxaJSON(t, layersArr))
	if err != nil {
		return nil, err
	}
	ch, err := p.Plan(context.Background(), core.FlowSpec{SrcIP: moxaCli, DstIP: moxaSrv})
	if err != nil {
		return nil, err
	}
	var pkts []core.PacketConfig
	for c := range ch {
		pkts = append(pkts, c)
	}
	return pkts, nil
}

// ①层条目→spec.MOXA 翻译端到端：纯 layers 形（无顶层 moxa 子映射）出 8 包
// = 3 握手 + 1 数据 + 4 挥手；数据帧 payload = "hello"，端口 4800。
func TestMOXAChain_LayerToSpecPlan(t *testing.T) {
	pkts, err := moxaPlan(t, moxaLayers(map[string]interface{}{
		"stream": []interface{}{map[string]interface{}{"payload": "hello"}},
	}, nil))
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(pkts) != 8 {
		t.Fatalf("got %d packets, want 8 (3 handshake + 1 data + 4 teardown)", len(pkts))
	}
	if got := string(pkts[3].Payload); got != "hello" {
		t.Fatalf("packet 4 payload = %q, want hello", got)
	}
	if pkts[3].L4.DstPort != 4800 {
		t.Fatalf("packet 4 dst port = %d, want 4800", pkts[3].L4.DstPort)
	}
	// 缺省端口补齐：tcp 层不写 dst_port 也落 4800（validateSpecBase 缺省）。
	pkts2, err := moxaPlan(t, moxaLayers(map[string]interface{}{
		"stream": []interface{}{map[string]interface{}{"payload": "hello"}},
	}, map[string]interface{}{}))
	if err != nil {
		t.Fatalf("Plan (default port): %v", err)
	}
	if pkts2[3].L4.DstPort != 4800 {
		t.Fatalf("default dst port = %d, want 4800", pkts2[3].L4.DstPort)
	}
}

// ③presence 与顶层游离键判死（§12-P2 清单①③）。
func TestMOXAChain_PresenceAndStrayTopLevelKeys(t *testing.T) {
	layersArr := moxaLayers(map[string]interface{}{}, nil)
	cfg := map[string]interface{}{
		"layers": layersArr,
		"moxa":   map[string]interface{}{},
	}
	if msg := core.CheckProtoFlat("moxa", cfg); msg == "" {
		t.Fatal("CheckProtoFlat(moxa, {layers, moxa:{}}) = \"\", want presence rejection")
	} else if !strings.Contains(msg, "no longer accepts a top-level moxa sub-config") {
		t.Fatalf("CheckProtoFlat msg = %q", msg)
	}
	// 层链形状（无顶层 moxa 子映射）不触发。
	if msg := core.CheckProtoFlat("moxa", map[string]interface{}{"layers": layersArr}); msg != "" {
		t.Fatalf("layers-only shape must not trigger, got %q", msg)
	}
	// 白名单外游离顶层键判死（rtmfp 先例锚词逐字）。
	for _, k := range []string{"src_ip", "dst_ip", "src_port", "dst_port", "count"} {
		bad := map[string]interface{}{"layers": layersArr, k: 1}
		if msg := core.CheckProtoFlat("moxa", bad); !strings.Contains(msg, "no longer accepts flat config field "+k) {
			t.Fatalf("CheckProtoFlat(moxa, {layers, %s}) = %q", k, msg)
		}
	}
}

// ④载体拒绝：moxa 只走 tcp（DependsOn=[tcp] ⟹ tcp-only），夹 udp 载体判死。
func TestMOXAChain_CarrierRejected(t *testing.T) {
	_, err := layers.BuildLayersPlanner("moxa", moxaJSON(t, []interface{}{
		map[string]interface{}{"ip": map[string]interface{}{"src": moxaCli, "dst": moxaSrv}},
		map[string]interface{}{"udp": map[string]interface{}{"dst_port": 4800}},
		map[string]interface{}{"moxa": map[string]interface{}{}},
	}))
	if err == nil || !strings.Contains(err.Error(), "carrier") {
		t.Fatalf("udp carrier error = %v, want anchor \"carrier\"", err)
	}
}

// ⑤载体违例（G-MOXA-1 回填面）：tcp 层的 handshake=false 是链形状下的载体
// 真相（顶层 tcp 子映射已被 CheckProtoFlat 判死），必须回填 spec.TCP 才能让
// moxa 校验器的 "tcp.handshake must be true" 分支有执法对象——不回填则
// N-4 在层链形状下被旁路（负例假通过）。
func TestMOXAChain_HandshakeFalseRejected(t *testing.T) {
	_, err := moxaPlan(t, moxaLayers(map[string]interface{}{
		"stream": []interface{}{map[string]interface{}{"payload": "hello"}},
	}, map[string]interface{}{"dst_port": 4800, "handshake": false}))
	if err == nil || !strings.Contains(err.Error(), "tcp.handshake must be true") {
		t.Fatalf("handshake=false error = %v, want anchor \"tcp.handshake must be true\"", err)
	}
}

// ②空层 config（{"moxa":{}}）走 P0b-2 缺省流：stream 缺键 → 单块 "hello"
// （设计 §5 自动派生规则①：`stream` 缺省 → 单块 up "hello"，planner.Plan +
// layer_gen.Generate 双默认）。显式 `stream: []` 是另一态，必须仍拒（N-1
// 执法对象）——二者不可混同（bgp events 缺键/显式 [] 二态同款）。
func TestMOXAChain_EmptyLayerDefaultsToHello(t *testing.T) {
	pkts, err := moxaPlan(t, moxaLayers(map[string]interface{}{}, nil))
	if err != nil {
		t.Fatalf("empty layer config must default to a hello flow, got %v", err)
	}
	if len(pkts) != 8 {
		t.Fatalf("got %d packets, want 8 (default hello flow)", len(pkts))
	}
	if got := string(pkts[3].Payload); got != "hello" {
		t.Fatalf("default payload = %q, want hello", got)
	}
	// 显式空 stream 仍拒（N-1 锚词）。
	_, err = moxaPlan(t, moxaLayers(map[string]interface{}{
		"stream": []interface{}{},
	}, nil))
	if err == nil || !strings.Contains(err.Error(), "moxa: empty stream block or payload required") {
		t.Fatalf("explicit empty stream error = %v, want N-1 anchor", err)
	}
}

// ⑥严格解码（bgp 范式）：层 config 的未知键必须拒，含 stream[] 元素内层
// 未知键（宽容 Unmarshal 会把 typo 静默丢弃成默认流——CLAUDE.md 点名的
// "静默丢弃"反模式）。
func TestMOXAChain_StrictDecode(t *testing.T) {
	// 元素内层未知键：`paylod`（payload 拼错）不得被静默忽略。
	_, err := moxaPlan(t, moxaLayers(map[string]interface{}{
		"stream": []interface{}{map[string]interface{}{"paylod": "hello"}},
	}, nil))
	if err == nil {
		t.Fatal("stream[] element unknown key must be rejected, got silent default flow")
	}
	if !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("element unknown key error = %v, want anchor \"unknown field\"", err)
	}
	// 顶层层键未知由 V9 拒（ValidateLayers 前置，锚词同上）。
	_, err = moxaPlan(t, moxaLayers(map[string]interface{}{"bogus": 1}, nil))
	if err == nil || !strings.Contains(err.Error(), `unknown field "bogus"`) {
		t.Fatalf("layer unknown key error = %v, want anchor \"unknown field\"", err)
	}
}

// ⑦用例文件收官自查：23 例（11 正 + 12 负 = 9 协议负例 + 3 §12-P2 链级红例；
// M-1 后补落 6 条 A′ 例 + 1 条 block_over 对偶）；
// 非负例顶层键 ⊆ {layers, flow_control, strategy_fc}；presence/游离键红例在案；
// 负例 expect 键集严格 = {expect_error, error_contains}；断言无 moxa.* 字段；
// 多流例（flows>1）的层链必须带动态对象（否则 MCP 静态复制门 400——离线
// executor 不跑 schema 门，此处离线自查补位）。
func TestMOXAChain_CaseFileAudit(t *testing.T) {
	raw, err := os.ReadFile("../../../test/protocol_pcap/cases/moxa.json")
	if err != nil {
		t.Fatalf("read cases: %v", err)
	}
	var cases []map[string]interface{}
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatalf("parse cases: %v", err)
	}
	if len(cases) != 23 {
		t.Fatalf("want 23 cases (11 pos + 12 neg), got %d", len(cases))
	}
	allowed := map[string]bool{"layers": true, "flow_control": true, "strategy_fc": true}
	presence, stray, carrier := false, false, false
	pos, neg := 0, 0
	for _, c := range cases {
		id, _ := c["id"].(string)
		sj, _ := c["spec_json"].(map[string]interface{})
		if sj == nil {
			t.Fatalf("%s: spec_json missing", id)
		}
		exp, _ := c["expect"].(map[string]interface{})
		isNeg := exp != nil && exp["expect_error"] == true
		anchor, _ := exp["error_contains"].(string)
		if isNeg {
			neg++
			if len(exp) != 2 || exp["error_contains"] == nil {
				t.Fatalf("%s: negative expect keys = %v, want exactly {expect_error, error_contains}", id, exp)
			}
			switch {
			case strings.Contains(anchor, "top-level moxa sub-config"):
				presence = true
			case strings.Contains(anchor, "flat config field"):
				stray = true
			case strings.Contains(anchor, "carrier"):
				carrier = true
			}
		} else {
			pos++
			for k := range sj {
				if !allowed[k] {
					t.Fatalf("%s: non-negative top-level key %q (want ⊆ layers/flow_control/strategy_fc)", id, k)
				}
			}
			if _, has := sj["moxa"]; has {
				t.Fatalf("%s: top-level moxa on non-negative case", id)
			}
		}
		// 全例：layers 必须存在且末层是 moxa（纯层链形，无顶层旧键）。
		arr, _ := sj["layers"].([]interface{})
		if len(arr) == 0 {
			t.Fatalf("%s: layers missing/empty", id)
		}
		last, _ := arr[len(arr)-1].(map[string]interface{})
		if _, ok := last["moxa"]; !ok {
			t.Fatalf("%s: last layer is not moxa (%v)", id, last)
		}
		// 断言通道诚实性：无 dissector（tshark 3.6.14 moxa.* 零字段），
		// 任何用例都不得写 moxa.* 字段。
		if fields, ok := exp["fields"].([]interface{}); ok {
			for _, f := range fields {
				fm, _ := f.(map[string]interface{})
				if s, _ := fm["field"].(string); strings.HasPrefix(s, "moxa.") {
					t.Fatalf("%s: moxa.* field assertion %q (no dissector)", id, s)
				}
			}
		}
		// 多流例（flows>1）静态复制门自查（MCP 侧 schema 门，离线 executor
		// 不跑——此处补位防离线绿/MCP 红的分歧）：层链必须带动态对象
		// （allowlist 四元组字段的 strategy map），否则 flows>1 会 400。
		if !isNeg {
			if fc, ok := sj["flow_control"].(map[string]interface{}); ok {
				if flows, ok := fc["flows"].(float64); ok && flows > 1 {
					if !hasDynObject(sj) {
						t.Fatalf("%s: flows=%v with a fully static layer chain — the MCP static-copy gate rejects it (write a dynamic object on ip.src/ip.dst or tcp src_port/dst_port)", id, flows)
					}
				}
			}
		}
	}
	if pos != 11 || neg != 12 {
		t.Fatalf("want 11 pos + 12 neg, got %d pos + %d neg", pos, neg)
	}
	if !presence || !stray || !carrier {
		t.Fatalf("chain red cases missing: presence=%v stray=%v carrier=%v", presence, stray, carrier)
	}
}

// hasDynObject reports whether any layer config carries a dynamic object
// (a map with a "strategy" key) — the escape hatch the static-copy gate
// requires when flows > 1.
func hasDynObject(sj map[string]interface{}) bool {
	arr, _ := sj["layers"].([]interface{})
	for _, item := range arr {
		layer, _ := item.(map[string]interface{})
		for _, sub := range layer {
			subMap, _ := sub.(map[string]interface{})
			for _, v := range subMap {
				if m, ok := v.(map[string]interface{}); ok {
					if _, looksDyn := m["strategy"]; looksDyn {
						return true
					}
				}
			}
		}
	}
	return false
}
