package layers_test

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	_ "github.com/trafficgen/trafficgen/internal/protocol/ethmining" // init 注册 ethmining 终结层生成器+校验器
)

// D-ETHMINING-1 P4 链级红例（rtmfp_chain_test/xmrmining_chain_test 同构）：
// ①层条目→spec.ETHMining 翻译端到端（[ip,tcp,ethmining] 出包；空配置层走
// P0b 缺省基线会话）/②presence 与顶层游离键判死（CheckProtoFlat ethmining
// 分支，M5 清单①②）/③载体拒绝（udp 夹链 / 缺 tcp 报 carrier 锚词；ip 层混合
// 地址族走通用 same-version 门报 "same IP version"，M5 清单③）/④wire_fault
// 经层内注入生效（§7 行 31 通道）/⑤非默认端口 3353 显式合法（设计 §2）/
// ⑥IPv6 独立 fixture /⑦多会话展开 /⑧用例文件收官自查（37 例 = 22 正 + 15
// 负；非负例顶层键 = 0）。

const (
	emCli   = "192.0.2.73"
	emSrv   = "198.51.100.73"
	emCli6  = "2001:db8::73"
	emSrv6  = "2001:db8::100:73"
	emSport = 4073
	emPort  = 4444
)

// emLayers builds the [ip,tcp,ethmining] chain with the given ethmining cfg.
func emLayers(emCfg, tcpCfg map[string]interface{}) []interface{} {
	if tcpCfg == nil {
		tcpCfg = map[string]interface{}{"src_port": emSport, "dst_port": emPort}
	}
	return []interface{}{
		map[string]interface{}{"ip": map[string]interface{}{"src": emCli, "dst": emSrv}},
		map[string]interface{}{"tcp": tcpCfg},
		map[string]interface{}{"ethmining": emCfg},
	}
}

func emJSON(t *testing.T, layersArr []interface{}) json.RawMessage {
	t.Helper()
	out, err := json.Marshal(layersArr)
	if err != nil {
		t.Fatalf("marshal layers: %v", err)
	}
	return out
}

func emPlan(t *testing.T, layersArr []interface{}) ([]core.PacketConfig, error) {
	t.Helper()
	p, err := layers.BuildLayersPlanner("ethmining", emJSON(t, layersArr))
	if err != nil {
		return nil, err
	}
	spec := core.FlowSpec{SrcIP: emCli, DstIP: emSrv, SrcPort: emSport, DstPort: emPort}
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

func emDrive(t *testing.T, emCfg map[string]interface{}) []core.PacketConfig {
	t.Helper()
	pkts, err := emPlan(t, emLayers(emCfg, nil))
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	return pkts
}

func emDriveErr(t *testing.T, emCfg map[string]interface{}) error {
	t.Helper()
	_, err := emPlan(t, emLayers(emCfg, nil))
	return err
}

// emSubscribeEv 是基线订阅事件（fixture 常量，testcase §3）。
func emSubscribeEv() map[string]interface{} {
	return map[string]interface{}{
		"kind": "subscribe", "id": 1,
		"user_agent": "MinerName/1.0.0", "protocol": "EthereumStratum/1.0.0",
		"subscription_id": "ae6812eb4cd7735a302a8a9dd95cf71f", "extranonce": "080c",
	}
}

// ①层条目→spec.ETHMining 翻译端到端：单事件 subscribe = 请求 + 自动应答响应
// 两行；3 握手 + 2 行 + 4 挥手 = 9 包（设计 §6/用例 1 packet_count）。
// 行字节钉死（设计 §3.11：请求 90B、响应 117B；紧凑 JSON + 单 LF）。
func TestEthminingChain_LayerToSpecPlan(t *testing.T) {
	pkts := emDrive(t, map[string]interface{}{
		"sessions": []interface{}{map[string]interface{}{
			"events": []interface{}{emSubscribeEv()},
		}},
	})
	if len(pkts) != 9 {
		t.Fatalf("want 9 packets (3 handshake + 2 lines + 4 teardown), got %d", len(pkts))
	}
	req := string(pkts[3].Payload)
	wantReq := `{"id":1,"method":"mining.subscribe","params":["MinerName/1.0.0","EthereumStratum/1.0.0"]}` + "\n"
	if req != wantReq {
		t.Fatalf("subscribe request mismatch:\n got %q\nwant %q", req, wantReq)
	}
	if len(req) != 90 {
		t.Fatalf("subscribe request length = %d, want 90 (设计 §3.11 公式 53+len(id)+len(ua)+len(proto)+1)", len(req))
	}
	resp := string(pkts[4].Payload)
	wantResp := `{"id":1,"result":[["mining.notify","ae6812eb4cd7735a302a8a9dd95cf71f","EthereumStratum/1.0.0"],"080c"],"error":null}` + "\n"
	if resp != wantResp {
		t.Fatalf("subscribe response mismatch:\n got %q\nwant %q", resp, wantResp)
	}
	if len(resp) != 117 {
		t.Fatalf("subscribe response length = %d, want 117 (2B extranonce)", len(resp))
	}
	// 载体与端口（设计 §2：4444 经 FieldContract 补齐；缺省 tcp.dst_port 时
	// flat 兼容面 4444 注入，通用默认 80 不得漏上线）。
	if pkts[3].L4.SrcPort != emSport || pkts[3].L4.DstPort != emPort {
		t.Fatalf("packet 3 L4 = %d->%d, want %d->%d", pkts[3].L4.SrcPort, pkts[3].L4.DstPort, emSport, emPort)
	}
	if pkts[4].L4.SrcPort != emPort || pkts[4].L4.DstPort != emSport {
		t.Fatalf("packet 4 L4 = %d->%d, want swapped (src %d / dst %d)", pkts[4].L4.SrcPort, pkts[4].L4.DstPort, emPort, emSport)
	}
}

// ①b 空配置层（bare {"ethmining":{}}）= P0b 缺省基线会话（subscribe + 响应，
// 9 包；生成器 layer_gen.go:48-54 缺省流）。端口由 FieldContract 4444 补齐。
func TestEthminingChain_EmptyConfigBaseline(t *testing.T) {
	pkts := emDrive(t, map[string]interface{}{})
	if len(pkts) != 9 {
		t.Fatalf("empty config: want 9 packets (default subscribe baseline), got %d", len(pkts))
	}
	if got := string(pkts[3].Payload); !strings.HasPrefix(got, `{"id":1,"method":"mining.subscribe"`) {
		t.Fatalf("empty config baseline must emit default subscribe, got %q", got)
	}
	if pkts[3].L4.DstPort != emPort {
		t.Fatalf("empty config dst port = %d, want %d (FieldContract)", pkts[3].L4.DstPort, emPort)
	}
}

// ①c 层 config 缺省 tcp.dst_port → flat 兼容面 4444 注入（bgp 179 同款；
// 通用默认 80 漏上线是 bgp P4 修轮 1 的实测缺陷面）。
// M1（gen-review）：原实现用 emPlan，而 emPlan 把 DstPort 硬编码成 emPort
// （helper 第 70 行 `DstPort: emPort`）→ 断言恒真，根本没走缺省路径，是空断言。
// 改为 spec.DstPort=0 直接交给规划器，只有 FieldContract/链缺省能补 4444，
// 通用默认 80 若漏上线即在此红。
func TestEthminingChain_DefaultPortNotHTTPDefault(t *testing.T) {
	layersArr := emLayers(map[string]interface{}{}, map[string]interface{}{"src_port": emSport})
	p, err := layers.BuildLayersPlanner("ethmining", emJSON(t, layersArr))
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v", err)
	}
	ch, err := p.Plan(context.Background(), core.FlowSpec{
		SrcIP: emCli, DstIP: emSrv, SrcPort: emSport, DstPort: 0,
	})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var pkts []core.PacketConfig
	for c := range ch {
		pkts = append(pkts, c)
	}
	if len(pkts) < 4 {
		t.Fatalf("want >=4 packets, got %d", len(pkts))
	}
	if pkts[3].L4.DstPort != emPort {
		t.Fatalf("dst port = %d, want %d (ethmining default, not the universal 80)", pkts[3].L4.DstPort, emPort)
	}
}

// ②presence 与顶层游离键判死（CheckProtoFlat ethmining 分支；空 map 也死
// ——M5 清单①②；同时经 mapToFlowSpec 落 ValidationErrors = 存量行启动真相）。
func TestEthminingChain_PresenceAndStrayTopLevelKeys(t *testing.T) {
	cfg := map[string]interface{}{
		"layers":    emLayers(map[string]interface{}{}, nil),
		"ethmining": map[string]interface{}{},
	}
	msg := core.CheckProtoFlat("ethmining", cfg)
	if msg == "" {
		t.Fatal("CheckProtoFlat(ethmining, {layers, ethmining:{}}) = \"\", want presence rejection")
	}
	if !strings.Contains(msg, "no longer accepts a top-level ethmining sub-config") {
		t.Fatalf("CheckProtoFlat msg = %q", msg)
	}
	spec := core.MapToFlowSpec(cfg, "ethmining")
	joined := strings.Join(spec.ValidationErrors, "; ")
	if !strings.Contains(joined, "no longer accepts a top-level ethmining sub-config") {
		t.Fatalf("presence must be wired into ValidationErrors (存量行启动执法), got %q", joined)
	}
	// 白名单外游离键（flat 五键）逐键判死。
	for _, k := range []string{"src_ip", "dst_ip", "src_port", "dst_port", "count"} {
		bad := map[string]interface{}{"layers": cfg["layers"], k: 1}
		if got := core.CheckProtoFlat("ethmining", bad); !strings.Contains(got, "no longer accepts flat config field "+k) {
			t.Fatalf("CheckProtoFlat(ethmining, {layers, %s}) = %q, want flat-field rejection", k, got)
		}
	}
}

// ③载体拒绝（M5 清单③）：udp 夹链拒 / 缺 tcp 拒（预检在 DependsOn 自动
// 补全前拦，裸 ethmining 层不被补全掩盖）；ip 层混合地址族走通用
// same-version 门（validateSpecBase 一处一面，task-time 报 "same IP version"）。
func TestEthminingChain_CarrierRejected(t *testing.T) {
	// udp 载体（真链形）。
	_, err := layers.BuildLayersPlanner("ethmining", emJSON(t, []interface{}{
		map[string]interface{}{"ip": map[string]interface{}{"src": emCli, "dst": emSrv}},
		map[string]interface{}{"udp": map[string]interface{}{"src_port": emSport, "dst_port": emPort}},
		map[string]interface{}{"ethmining": map[string]interface{}{}},
	}))
	if err == nil || !strings.Contains(err.Error(), "carrier") {
		t.Fatalf("udp carrier err = %v, want anchor \"carrier\"", err)
	}
	if !strings.Contains(err.Error(), "tcp only") {
		t.Fatalf("udp carrier err = %v, want \"rides tcp only\"", err)
	}
	// 缺 tcp 载体。
	_, err = layers.BuildLayersPlanner("ethmining", emJSON(t, []interface{}{
		map[string]interface{}{"ip": map[string]interface{}{"src": emCli, "dst": emSrv}},
		map[string]interface{}{"ethmining": map[string]interface{}{}},
	}))
	if err == nil || !strings.Contains(err.Error(), "missing tcp carrier") {
		t.Fatalf("missing tcp err = %v, want anchor \"missing tcp carrier\"", err)
	}
	// ip 层混合地址族（通用 same-version 门，validateSpecBase 一处一面；
	// 预检只报 carrier 锚词，混族在 Plan 期报 "must be same IP version"）。
	mixedLayers := []interface{}{
		map[string]interface{}{"ip": map[string]interface{}{"src": emCli, "dst": emSrv6}},
		map[string]interface{}{"tcp": map[string]interface{}{"src_port": emSport, "dst_port": emPort}},
		map[string]interface{}{"ethmining": map[string]interface{}{}},
	}
	if _, err := layers.BuildLayersPlanner("ethmining", emJSON(t, mixedLayers)); err != nil {
		t.Fatalf("mixed family: build err = %v, want nil (carrier precheck passes; family gate is task-time)", err)
	}
	// spec 经 mapToFlowSpec 取层内地址（ip 层是链形状的四元组真相）。
	mixedSpec := core.MapToFlowSpec(map[string]interface{}{"layers": mixedLayers}, "ethmining")
	mp, err := layers.BuildLayersPlanner("ethmining", emJSON(t, mixedLayers))
	if err != nil {
		t.Fatalf("mixed family build: %v", err)
	}
	ch, err := mp.Plan(context.Background(), mixedSpec)
	if err == nil {
		n := 0
		for range ch {
			n++
		}
		t.Fatalf("mixed family: Plan err = nil (%d packets), want rejection", n)
	}
	if !strings.Contains(err.Error(), "same IP version") {
		t.Fatalf("mixed family err = %v, want anchor \"same IP version\"", err)
	}
}

// ④wire_fault 经层内注入生效（§7 行 31 通道；合法链形下注入面是唯一触发源）。
// 未知 kind 拒（10 值枚举外）；合法 kind 带各自锚词拒。
func TestEthminingChain_WireFaultInjection(t *testing.T) {
	err := emDriveErr(t, map[string]interface{}{
		"wire_fault": "not_a_known_kind",
		"sessions":   []interface{}{},
	})
	if err == nil || !strings.Contains(err.Error(), "unknown wire_fault kind") {
		t.Fatalf("unknown wire_fault should be rejected, got %v", err)
	}
	for kind, anchor := range map[string]string{
		"json": "json", "framing": "framing", "method": "method", "params": "params",
		"hex": "hex", "state": "state", "id": "id", "job": "job",
		"carrier": "carrier", "propagation": "propagat",
	} {
		err := emDriveErr(t, map[string]interface{}{"wire_fault": kind, "sessions": []interface{}{}})
		if err == nil {
			t.Fatalf("wire_fault %q: expected rejection", kind)
		}
		if !strings.Contains(err.Error(), anchor) {
			t.Fatalf("wire_fault %q: want anchor %q in %v", kind, anchor, err)
		}
	}
	// 非法 hex_prefix 值拒（层 config 键值域，非 wire_fault）。
	err = emDriveErr(t, map[string]interface{}{"hex_prefix": "0X"})
	if err == nil || !strings.Contains(err.Error(), "hex_prefix") {
		t.Fatalf("hex_prefix=0X err = %v, want rejection", err)
	}
	// 层内未知键同步拒（V9 未知字段面；schema 四键之外即拒）。
	_, err = emPlan(t, emLayers(map[string]interface{}{"bogus_key": 1}, nil))
	if err == nil || !strings.Contains(err.Error(), `unknown field "bogus_key"`) {
		t.Fatalf("bogus_key err = %v", err)
	}
}

// ⑤非默认端口 3353 显式合法（设计 §2：端口不进 stratum 行内容，行字节与基线
// 逐字节一致；planner 不得静默改写）。
func TestEthminingChain_CustomPort(t *testing.T) {
	pkts, err := emPlan(t, emLayers(map[string]interface{}{
		"sessions": []interface{}{map[string]interface{}{
			"events": []interface{}{emSubscribeEv()},
		}},
	}, map[string]interface{}{"src_port": emSport, "dst_port": 3353}))
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(pkts) != 9 {
		t.Fatalf("want 9 packets, got %d", len(pkts))
	}
	if pkts[3].L4.DstPort != 3353 || pkts[4].L4.SrcPort != 3353 {
		t.Fatalf("custom port not honored: up dst=%d / down src=%d", pkts[3].L4.DstPort, pkts[4].L4.SrcPort)
	}
	// 行字节与基线一致（端口不进行内容）。
	want := `{"id":1,"method":"mining.subscribe","params":["MinerName/1.0.0","EthereumStratum/1.0.0"]}` + "\n"
	if got := string(pkts[3].Payload); got != want {
		t.Fatalf("line bytes must be port-independent:\n got %q\nwant %q", got, want)
	}
}

// ⑥IPv6 独立 fixture：同逻辑行字节、外层地址族只换 ip 层。
func TestEthminingChain_IPv6(t *testing.T) {
	arr := []interface{}{
		map[string]interface{}{"ip": map[string]interface{}{"src": emCli6, "dst": emSrv6}},
		map[string]interface{}{"tcp": map[string]interface{}{"src_port": emSport, "dst_port": emPort}},
		map[string]interface{}{"ethmining": map[string]interface{}{
			"sessions": []interface{}{map[string]interface{}{
				"events": []interface{}{emSubscribeEv()},
			}},
		}},
	}
	p, err := layers.BuildLayersPlanner("ethmining", emJSON(t, arr))
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	spec := core.FlowSpec{SrcIP: emCli6, DstIP: emSrv6, SrcPort: emSport, DstPort: emPort}
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	n := 0
	for c := range ch {
		if n == 0 && (c.L3.SrcIP != emCli6 || c.L3.DstIP != emSrv6) {
			t.Fatalf("addrs %s -> %s, want %s -> %s", c.L3.SrcIP, c.L3.DstIP, emCli6, emSrv6)
		}
		n++
	}
	if n != 9 {
		t.Fatalf("want 9 packets, got %d", n)
	}
}

// ⑦多会话展开（设计 §5：sessions[] 按序整块回放，各会话四元组/状态互不串用）。
// 双会话各 subscribe = 9 + 9 = 18 包；两 src_port distinct。
func TestEthminingChain_MultiSession(t *testing.T) {
	pkts := emDrive(t, map[string]interface{}{
		"sessions": []interface{}{
			map[string]interface{}{"src_port": 4073, "events": []interface{}{emSubscribeEv()}},
			map[string]interface{}{"src_port": 4074, "events": []interface{}{emSubscribeEv()}},
		},
	})
	if len(pkts) != 18 {
		t.Fatalf("want 18 packets (two 9-packet sessions), got %d", len(pkts))
	}
	seen := map[uint16]bool{}
	for _, p := range pkts {
		if p.Direction == "up" && p.L4.DstPort == emPort {
			seen[p.L4.SrcPort] = true
		}
	}
	if !seen[4073] || !seen[4074] {
		t.Fatalf("session src ports must be distinct per session, got %v", seen)
	}
}

// ⑧用例文件收官自查（testcase §7/§8）：37 例 = 22 正 + 15 负；非负例顶层键 = 0
// （仅 layers）；负例 expect 键集严格 = {expect_error, error_contains}；
// presence/游离/载体红例在案；断言无 ethmining.*/stratum.* 字段（无 dissector）。
func TestEthminingChain_CaseFileAudit(t *testing.T) {
	raw, err := os.ReadFile("../../../test/protocol_pcap/cases/ethmining.json")
	if err != nil {
		t.Fatalf("read cases: %v", err)
	}
	var cases []map[string]interface{}
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatalf("parse cases: %v", err)
	}
	if len(cases) != 37 {
		t.Fatalf("want 37 cases (22 pos + 15 neg), got %d", len(cases))
	}
	allowed := map[string]bool{"layers": true, "flow_control": true, "output": true}
	presence, stray, carrierUDP, carrierMissing, mixedFam := false, false, false, false, false
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
			if len(exp) != 2 || exp["error_contains"] == nil {
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
		if _, has := sj["ethmining"]; has {
			if !isNeg {
				t.Fatalf("%s: top-level ethmining on non-negative case", id)
			}
			presence = true
		}
		if _, has := sj["src_ip"]; has {
			if !isNeg {
				t.Fatalf("%s: top-level src_ip on non-negative case", id)
			}
			stray = true
		}
		// 断言通道诚实性：无 ethmining.*/stratum.* 字段（tshark 无 dissector）。
		if fields, ok := exp["fields"].([]interface{}); ok {
			for _, fi := range fields {
				fm, _ := fi.(map[string]interface{})
				f, _ := fm["field"].(string)
				if strings.HasPrefix(f, "ethmining.") || strings.HasPrefix(f, "stratum.") {
					t.Fatalf("%s: field assertion %q (no dissector; use tcp.payload/frames hex)", id, f)
				}
			}
		}
		switch id {
		case "ethmining_neg_carrier_udp":
			carrierUDP = true
		case "ethmining_neg_carrier_missing_tcp":
			carrierMissing = true
		case "ethmining_neg_carrier_mixed_family":
			mixedFam = true
		}
	}
	if pos != 22 || neg != 15 {
		t.Fatalf("want 22 pos + 15 neg, got %d pos + %d neg", pos, neg)
	}
	if !presence {
		t.Fatal("want presence negative (layers + top-level ethmining), found none")
	}
	if !stray {
		t.Fatal("want stray top-level key negative (layers + src_ip), found none")
	}
	if !carrierUDP || !carrierMissing || !mixedFam {
		t.Fatalf("want all three carrier negatives (udp/missing/mixed), got udp=%v missing=%v mixed=%v",
			carrierUDP, carrierMissing, mixedFam)
	}
}
