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
	_ "github.com/trafficgen/trafficgen/internal/protocol/stratum" // init 注册 stratum 终结层生成器+校验器
)

// D-STRATUM-1 P4 链级测试（cflow/bgp/dameng 先例同构）：
// ①层条目→spec.Stratum 翻译端到端（[ip,tcp,stratum] 出包 9；空层 {} 缺省基线
// 同 9——G-ST-1 首要缺口：无 translate case 时层内配置到不了 spec.Stratum）；
// ②presence 判死（M5 清单①：layers + 顶层 stratum 空子映射并存）+ 白名单外
// 游离键（M5 清单②，src_mac）+ 扁平四键（G-ST-1 去向面）；
// ③载体拒绝（G-ST-6：缺 tcp / 夹 udp / 混合地址族——链面自然守卫，非
// planner 注入文案）；④严格解码（层内未知键 + session/event 嵌套未知键）；
// ⑤G-ST-2 事件 3 键接线（configure 的 extensions/version_rolling_mask/
// min_bit_count 上线；stratum 级 termination 死键判死）；⑥G-ST-3 非默认端口
// 4444 显式合法 + 缺省 3333 由 FieldContract 补齐；⑦用例文件收官自查
// （40 例；非负例顶层键 = {layers, flow_control}——G-ST-1 自查行「=0」）。

const (
	stCli   = "192.0.2.75"
	stSrv   = "198.51.100.75"
	stCli6  = "2001:db8::75"
	stSrv6  = "2001:db8::100:75"
	stSport = 4075
)

// stLayers builds [ip,tcp,stratum] with the given stratum cfg.
func stLayers(stratumCfg, tcpCfg map[string]interface{}) []interface{} {
	if tcpCfg == nil {
		tcpCfg = map[string]interface{}{"src_port": stSport, "dst_port": 3333}
	}
	if stratumCfg == nil {
		stratumCfg = map[string]interface{}{}
	}
	return []interface{}{
		map[string]interface{}{"ip": map[string]interface{}{"src": stCli, "dst": stSrv}},
		map[string]interface{}{"tcp": tcpCfg},
		map[string]interface{}{"stratum": stratumCfg},
	}
}

func stJSON(t *testing.T, layersArr []interface{}) []byte {
	t.Helper()
	out, err := json.Marshal(layersArr)
	if err != nil {
		t.Fatalf("marshal layers: %v", err)
	}
	return out
}

// stPlan drives the chain through BuildLayersPlanner + Plan (the production
// path: worker → ChainPlanner → translateTerminalConfig → generator).
func stPlan(t *testing.T, layersArr []interface{}, spec core.FlowSpec) ([]core.PacketConfig, error) {
	t.Helper()
	p, err := layers.BuildLayersPlanner("stratum", stJSON(t, layersArr))
	if err != nil {
		return nil, err
	}
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		return nil, err
	}
	var pkts []core.PacketConfig
	for c := range ch {
		pkts = append(pkts, c)
	}
	return pkts, nil
}

func stSpec() core.FlowSpec {
	return core.FlowSpec{SrcIP: stCli, DstIP: stSrv, SrcPort: stSport, DstPort: 3333}
}

// stSubSession is the baseline subscribe-only session (fixture 会话 1 值).
func stSubSession(srcPort int) map[string]interface{} {
	return map[string]interface{}{
		"src_port": srcPort,
		"events": []interface{}{
			map[string]interface{}{"kind": "subscribe", "id": 1,
				"user_agent": "MinerName/1.0.0", "extranonce1": "ea02567c", "extranonce2_size": 4},
		},
	}
}

// ① 层条目→spec.Stratum 翻译端到端：9 包 = 3 握手 + subscribe 请求/响应 2 行
// + 4 挥手；行字节 = 设计 §3.3 钉死值（66B 请求 / 114B 响应）。空层 {} 走
// 生成器缺省基线（layer_gen.go:48-54），同 9 包。
func TestStratumChain_TranslateReachesSpec(t *testing.T) {
	wantReq := `{"id":1,"method":"mining.subscribe","params":["MinerName/1.0.0"]}` + "\n"
	wantResp := `{"id":1,"result":[[["mining.set_difficulty","7f1a2b3c"],["mining.notify","9d8e7f6a"]],"ea02567c",4],"error":null}` + "\n"
	for _, tc := range []struct {
		name string
		cfg  map[string]interface{}
	}{
		{"explicit sessions", map[string]interface{}{"sessions": []interface{}{stSubSession(stSport)}}},
		{"empty layer (default baseline)", map[string]interface{}{}},
	} {
		pkts, err := stPlan(t, stLayers(tc.cfg, nil), stSpec())
		if err != nil {
			t.Fatalf("%s: Plan: %v", tc.name, err)
		}
		if len(pkts) != 9 {
			t.Fatalf("%s: want 9 packets, got %d", tc.name, len(pkts))
		}
		if got := string(pkts[3].Payload); got != wantReq {
			t.Fatalf("%s: subscribe request mismatch:\n got %q\nwant %q", tc.name, got, wantReq)
		}
		if len(pkts[3].Payload) != 66 {
			t.Fatalf("%s: subscribe request length = %d, want 66", tc.name, len(pkts[3].Payload))
		}
		if got := string(pkts[4].Payload); got != wantResp {
			t.Fatalf("%s: subscribe response mismatch:\n got %q\nwant %q", tc.name, got, wantResp)
		}
		if len(pkts[4].Payload) != 114 {
			t.Fatalf("%s: subscribe response length = %d, want 114", tc.name, len(pkts[4].Payload))
		}
		if pkts[3].L4.DstPort != 3333 {
			t.Fatalf("%s: up dst port = %d, want 3333", tc.name, pkts[3].L4.DstPort)
		}
	}
}

// ①b 翻译确实落进 spec.Stratum（非 P0b 缺省流兜底）：给一个非缺省会话（两
// 行事件）应产出 11 包而非缺省 9 包——若 translate case 缺席，层 config 到
// 不了 spec.Stratum，生成器只出缺省基线订阅流。
func TestStratumChain_NonDefaultConfigNotSwallowed(t *testing.T) {
	cfg := map[string]interface{}{"sessions": []interface{}{
		map[string]interface{}{"src_port": stSport, "events": []interface{}{
			map[string]interface{}{"kind": "subscribe", "id": 1, "user_agent": "MinerName/1.0.0",
				"extranonce1": "ea02567c", "extranonce2_size": 4},
			map[string]interface{}{"kind": "extranonce_subscribe", "id": 2},
		}},
	}}
	pkts, err := stPlan(t, stLayers(cfg, nil), stSpec())
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	// 3 握手 + 4 行（subscribe 对 + extranonce_subscribe 对）+ 4 挥手 = 11。
	if len(pkts) != 11 {
		t.Fatalf("want 11 packets (layer config must reach spec.Stratum, not the default baseline), got %d", len(pkts))
	}
	wantExt := `{"id":2,"method":"mining.extranonce.subscribe","params":[]}` + "\n"
	if got := string(pkts[5].Payload); got != wantExt {
		t.Fatalf("extranonce.subscribe request mismatch:\n got %q\nwant %q", got, wantExt)
	}
}

// ② presence 判死（M5 清单①：层链 + 顶层空子映射并存 = 判死形状，空 map
// 也死）+ 白名单外游离键（M5 清单②：src_mac）+ 扁平四键（G-ST-1 去向面）。
func TestStratumChain_PresenceAndStrayTopLevelKeys(t *testing.T) {
	cfg := map[string]interface{}{
		"layers":  stLayers(nil, nil),
		"stratum": map[string]interface{}{},
	}
	if msg := core.CheckProtoFlat("stratum", cfg); msg == "" {
		t.Fatal(`CheckProtoFlat(stratum, {layers, stratum:{}}) = "", want presence rejection`)
	} else if !strings.Contains(msg, "no longer accepts a top-level stratum sub-config") {
		t.Fatalf("CheckProtoFlat msg = %q", msg)
	}
	for _, k := range []string{"src_ip", "dst_ip", "src_port", "dst_port", "count"} {
		bad := map[string]interface{}{"layers": cfg["layers"], k: 1}
		if msg := core.CheckProtoFlat("stratum", bad); msg == "" {
			t.Fatalf("CheckProtoFlat(stratum, {layers, %s}) = \"\", want flat-field rejection", k)
		}
	}
	// M5 清单②：白名单外游离键（1.11–1.13）由 schema 层通用门判死。
	_, errs := schema.ValidateStrategy("synth", "stratum", map[string]any{
		"layers":  cfg["layers"],
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

// ③ 载体拒绝（G-ST-6：链面自然守卫，非 planner wire_fault 注入文案）：
// 缺 tcp → "missing tcp carrier …(carrier)"；夹 udp → "udp carrier is not
// supported …(carrier)"；混合地址族 → "mixed address family …(family)"。
func TestStratumChain_CarrierShapes(t *testing.T) {
	// 缺 tcp 载体（DependsOn 自动补全前拦，裸 stratum 层不被补全掩盖）。
	_, err := layers.BuildLayersPlanner("stratum", stJSON(t, []interface{}{
		map[string]interface{}{"ip": map[string]interface{}{"src": stCli, "dst": stSrv}},
		map[string]interface{}{"stratum": map[string]interface{}{}},
	}))
	if err == nil || !strings.Contains(err.Error(), "missing tcp carrier") ||
		!strings.Contains(err.Error(), "carrier") {
		t.Fatalf("missing tcp err = %v, want \"missing tcp carrier …(carrier)\"", err)
	}
	// udp 混入。
	_, err = layers.BuildLayersPlanner("stratum", stJSON(t, []interface{}{
		map[string]interface{}{"ip": map[string]interface{}{"src": stCli, "dst": stSrv}},
		map[string]interface{}{"udp": map[string]interface{}{"src_port": stSport, "dst_port": 3333}},
		map[string]interface{}{"stratum": map[string]interface{}{}},
	}))
	if err == nil || !strings.Contains(err.Error(), "udp carrier is not supported") {
		t.Fatalf("udp mix err = %v, want \"udp carrier is not supported\"", err)
	}
	// 混合地址族。
	_, err = layers.BuildLayersPlanner("stratum", stJSON(t, []interface{}{
		map[string]interface{}{"ip": map[string]interface{}{"src": stCli, "dst": stSrv6}},
		map[string]interface{}{"tcp": map[string]interface{}{"src_port": stSport, "dst_port": 3333}},
		map[string]interface{}{"stratum": map[string]interface{}{}},
	}))
	if err == nil || !strings.Contains(err.Error(), "mixed address family") {
		t.Fatalf("mixed family err = %v, want \"mixed address family\"", err)
	}
}

// ④ 严格解码：层内未知键（config 级）+ session/event 嵌套未知键（Decoder
// DisallowUnknownFields 递归）必须计 ValidationErrors 走任务错误——置空
// 配置会被 validator 直通成默认流假成功（edp/bacnet 同款）。
func TestStratumChain_StrictDecode(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  map[string]interface{}
		want string
	}{
		{"config-level unknown key", map[string]interface{}{"bogus_cfg_key": 1}, "bogus_cfg_key"},
		{"session-level unknown key", map[string]interface{}{"sessions": []interface{}{
			map[string]interface{}{"src_port": stSport, "bogus_sess_key": 1,
				"events": []interface{}{map[string]interface{}{"kind": "subscribe", "id": 1}}},
		}}, "bogus_sess_key"},
		{"event-level unknown key", map[string]interface{}{"sessions": []interface{}{
			map[string]interface{}{"src_port": stSport, "events": []interface{}{
				map[string]interface{}{"kind": "subscribe", "id": 1, "bogus_ev_key": 1},
			}},
		}}, "bogus_ev_key"},
		// G-ST-2：stratum 级 termination 是死键（struct 无此键，终止行为由
		// tcp 层 rst:true 承载——契约 §2.3），严格门按未知键拒。
		{"stratum-level termination (dead key)", map[string]interface{}{"termination": "rst"}, "termination"},
	} {
		_, err := stPlan(t, stLayers(tc.cfg, nil), stSpec())
		if err == nil {
			t.Fatalf("%s: want rejection, got nil", tc.name)
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s: want %q in %v", tc.name, tc.want, err)
		}
	}
	// 宽容值必须通过（非默认端口 + 显式会话）。
	if _, err := stPlan(t, stLayers(map[string]interface{}{"sessions": []interface{}{stSubSession(stSport)}}, nil), stSpec()); err != nil {
		t.Fatalf("valid config must plan: %v", err)
	}
}

// ⑤ G-ST-2 事件键接线：configure 事件的 extensions/version_rolling_mask/
// min_bit_count 三键上线（旧版静默丢弃，线字节恒由缺省 FixtureCfgParams
// 产出）。掩码值改 `0000ffff` + 计数 8 → 请求行 params 映射随值变。
func TestStratumChain_ConfigureEventKeys(t *testing.T) {
	cfg := map[string]interface{}{"sessions": []interface{}{
		map[string]interface{}{"src_port": stSport, "events": []interface{}{
			map[string]interface{}{"kind": "configure", "id": 5,
				"extensions":           []interface{}{"version-rolling"},
				"version_rolling_mask": "0000ffff", "min_bit_count": 8},
			map[string]interface{}{"kind": "subscribe", "id": 1, "user_agent": "MinerName/1.0.0",
				"extranonce1": "ea02567c", "extranonce2_size": 4},
		}},
	}}
	pkts, err := stPlan(t, stLayers(cfg, nil), stSpec())
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	// 3 握手 + configure 对 + subscribe 对 + 4 挥手 = 11。
	if len(pkts) != 11 {
		t.Fatalf("want 11 packets, got %d", len(pkts))
	}
	req := string(pkts[3].Payload)
	wantReq := `{"id":5,"method":"mining.configure","params":[["version-rolling"],{"version-rolling.mask":"0000ffff","version-rolling.min-bit-count":8}]}` + "\n"
	if req != wantReq {
		t.Fatalf("configure request mismatch (event keys must reach the wire):\n got %q\nwant %q", req, wantReq)
	}
	// 缺省（无三键）时仍走钉死 fixture 字面量——139B 行长不变。
	pkts, err = stPlan(t, stLayers(map[string]interface{}{"sessions": []interface{}{
		map[string]interface{}{"src_port": stSport, "events": []interface{}{
			map[string]interface{}{"kind": "configure", "id": 5},
			map[string]interface{}{"kind": "subscribe", "id": 1},
		}},
	}}, nil), stSpec())
	if err != nil {
		t.Fatalf("Plan default configure: %v", err)
	}
	if got := len(pkts[3].Payload); got != 139 {
		t.Fatalf("default configure request length = %d, want 139 (pinned fixture)", got)
	}
}

// ⑥ G-ST-3 端口域：链内显式非默认端口 4444 合法（行字节与基线一致——端口
// 不进 stratum 行）；tcp 层不写 dst_port 时由 FieldContract 补 3333。
func TestStratumChain_PortDomain(t *testing.T) {
	pkts, err := stPlan(t, stLayers(nil, map[string]interface{}{"src_port": stSport, "dst_port": 4444}), stSpec())
	if err != nil {
		t.Fatalf("explicit 4444 must be legal: %v", err)
	}
	if len(pkts) != 9 {
		t.Fatalf("want 9 packets, got %d", len(pkts))
	}
	if pkts[3].L4.DstPort != 4444 {
		t.Fatalf("up dst port = %d, want 4444", pkts[3].L4.DstPort)
	}
	// 层内端口不进 stratum 行：与基线行字节逐字相同。
	wantReq := `{"id":1,"method":"mining.subscribe","params":["MinerName/1.0.0"]}` + "\n"
	if got := string(pkts[3].Payload); got != wantReq {
		t.Fatalf("line bytes must not carry the port: %q", got)
	}
	// 不写 dst_port → FieldContract 3333 补齐。
	pkts, err = stPlan(t, stLayers(nil, map[string]interface{}{"src_port": stSport}), stSpec())
	if err != nil {
		t.Fatalf("FieldContract default: %v", err)
	}
	if pkts[3].L4.DstPort != 3333 {
		t.Fatalf("FieldContract dst port = %d, want 3333", pkts[3].L4.DstPort)
	}
}

// ⑦ IPv6 载体：同一 fixture 同包数（地址族同住 ip 层，不新增层）。
func TestStratumChain_IPv6(t *testing.T) {
	arr := []interface{}{
		map[string]interface{}{"ip": map[string]interface{}{"src": stCli6, "dst": stSrv6}},
		map[string]interface{}{"tcp": map[string]interface{}{"src_port": stSport, "dst_port": 3333}},
		map[string]interface{}{"stratum": map[string]interface{}{"sessions": []interface{}{stSubSession(stSport)}}},
	}
	pkts, err := stPlan(t, arr, core.FlowSpec{SrcIP: stCli6, DstIP: stSrv6, SrcPort: stSport, DstPort: 3333})
	if err != nil {
		t.Fatalf("IPv6 Plan: %v", err)
	}
	if len(pkts) != 9 {
		t.Fatalf("want 9 packets, got %d", len(pkts))
	}
	if pkts[3].L3.SrcIP != stCli6 || pkts[3].L3.DstIP != stSrv6 {
		t.Fatalf("addrs %s -> %s, want %s -> %s", pkts[3].L3.SrcIP, pkts[3].L3.DstIP, stCli6, stSrv6)
	}
	if got := string(pkts[3].Payload); !strings.HasPrefix(got, `{"id":1,"method":"mining.subscribe"`) {
		t.Fatalf("IPv6 line bytes must match the v4 fixture: %q", got)
	}
}

// ⑧ 用例文件收官自查（G-ST-1「非负例顶层键 = 0」）：40 例（29 正 + 11 负）；
// 非负例顶层键 = {layers, flow_control}（4 扁平键与顶层 stratum 子映射已清零）；
// 负例 expect 键集严格 = {expect_error, error_contains}。
func TestStratumChain_CaseFileAudit(t *testing.T) {
	raw, err := os.ReadFile("../../../test/protocol_pcap/cases/stratum.json")
	if err != nil {
		t.Fatalf("read cases: %v", err)
	}
	var cases []map[string]interface{}
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatalf("parse cases: %v", err)
	}
	if len(cases) != 40 {
		t.Fatalf("want 40 cases (29 pos + 11 neg), got %d", len(cases))
	}
	pos, neg := 0, 0
	allowedPos := map[string]bool{"layers": true, "flow_control": true}
	for _, c := range cases {
		id, _ := c["id"].(string)
		sj, _ := c["spec_json"].(map[string]interface{})
		if sj == nil {
			t.Fatalf("%s: spec_json missing", id)
		}
		exp, _ := c["expect"].(map[string]interface{})
		if exp == nil {
			t.Fatalf("%s: expect missing", id)
		}
		isNeg := exp["expect_error"] == true
		if isNeg {
			neg++
			for k := range exp {
				if k != "expect_error" && k != "error_contains" {
					t.Fatalf("%s: negative expect key %q (want strictly {expect_error, error_contains})", id, k)
				}
			}
			continue
		}
		pos++
		for k := range sj {
			if !allowedPos[k] {
				t.Fatalf("%s: non-negative top-level key %q (want ⊆ {layers, flow_control})", id, k)
			}
		}
		if _, ok := exp["packet_count"]; !ok {
			t.Fatalf("%s: positive case without packet_count", id)
		}
		// 业务配置必须在层内：stratum 层条目带 sessions（或空层缺省基线）。
		found := false
		ls, _ := sj["layers"].([]interface{})
		for _, item := range ls {
			l, _ := item.(map[string]interface{})
			if _, ok := l["stratum"]; ok {
				found = true
			}
		}
		if !found {
			t.Fatalf("%s: no stratum layer entry in the chain", id)
		}
	}
	if pos != 29 || neg != 11 {
		t.Fatalf("want 29 pos + 11 neg, got %d pos + %d neg", pos, neg)
	}
}
