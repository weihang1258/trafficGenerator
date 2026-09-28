package layers_test

// D-ISIS-1 P4 链级测试：[eth→isis] L2-only 链（goose/sv/arp 族对称）。
// 覆盖：①层条目→spec.ISIS 翻译端到端（L2-only 直发：EtherType 0x8870、
// L3 清空、LLC padding）；②presence 判死 + 顶层游离键；③载体拒（V7b
// carrier）；④用例文件收官自查（27 例 = 13 正 + 14 负；非负例顶层键 ⊆
// {layers}；负例 expect 键集严格二键；M5 红例在案）。
//
// 数量键偏离登记（P4 实测，igmp 先例）：design §12.1 去向表把数量键映射为
// 兄弟键 `flow_control`（`{"flows": packet_count}`）。实测框架语义：
// ①isis 的包数由层内 `events` 事件数决定（单流内逐事件 Emit），`flows` 是
// 流数（worker 每流调一次 Plan）——`flows=4` 会产 16 包而非 4 包；
// ②`spec_json` 内的 `flow_control` 不被任何代码读取（死配置），用例级唯一
// 被 runner 消费的流控键是 `strategy_fc`（nfs/enip/tftp/smb/igmp 先例）。
// 故 27 例均不写流控键：单 PDU 例 packet_count=1、#12 四事件=4、#13 双事件=2，
// 与 design §2 的 packet_count 序列逐值一致（包数由事件数决定）。

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	_ "github.com/trafficgen/trafficgen/internal/protocol/isis" // init 注册 isis 终结层生成器+校验器
)

const (
	isisSrcMAC = "02:00:00:00:10:01"
	// 存量 #1（LLC L1 LAN IIH）逐值 fixture——与 cases/isis.json 同源。
	isisIIHL1 = `{
		"wire_profile": "iso10589_llc",
		"level": "l1",
		"pdu_type": "lan_hello",
		"system_id": "0102.0304.0506",
		"holding_timer": 30,
		"priority": 100,
		"lan_id": "01020304050601",
		"tlvs": [{"type": 1, "value_hex": "03 49 00 01"}]
	}`
)

func isisLayers(t *testing.T, isisCfg string) []interface{} {
	t.Helper()
	return []interface{}{
		map[string]interface{}{"eth": map[string]interface{}{"src_mac": isisSrcMAC}},
		map[string]interface{}{"isis": mustJSONMap(t, isisCfg)},
	}
}

// isisPlannerFromSpecJSON 复刻产线路径（StrategyModelToTask + 引擎）：
// 整份 spec_json（layers 在位）→ MapToFlowSpec（eth.src_mac 经
// extractLayerMACs 回填 spec.SrcMAC）→ BuildLayersPlanner → Plan。
// 与离线链套件（layer_chain_suite_test.go 先删 layers 再 MapToFlowSpec，
// eth MAC 不参与）刻意区分：本测试钉的是产线真相。
func isisPlannerFromSpecJSON(t *testing.T, isisCfg string) (*layers.ChainPlanner, core.FlowSpec) {
	t.Helper()
	full := map[string]interface{}{"layers": isisLayers(t, isisCfg)}
	raw, err := json.Marshal(full)
	if err != nil {
		t.Fatalf("marshal spec_json: %v", err)
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("reparse spec_json: %v", err)
	}
	layersRaw, _ := json.Marshal(parsed["layers"])
	spec := core.MapToFlowSpec(parsed, "isis")
	p, err := layers.BuildLayersPlanner("isis", layersRaw)
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v", err)
	}
	cp, ok := p.(*layers.ChainPlanner)
	if !ok {
		t.Fatalf("BuildLayersPlanner returned %T, want *layers.ChainPlanner", p)
	}
	return cp, spec
}

func isisPlanner(t *testing.T, isisCfg string) (*layers.ChainPlanner, core.FlowSpec) {
	t.Helper()
	p := layers.NewChainPlannerFromChain("isis", []layers.Layer{
		{Name: "eth", Config: map[string]interface{}{"src_mac": isisSrcMAC}},
		{Name: "isis", Config: mustJSONMap(t, isisCfg)},
	})
	validated, err := p.ValidateSpec(core.FlowSpec{})
	if err != nil {
		t.Fatalf("ValidateSpec: %v", err)
	}
	return p, validated
}

// ①层条目→spec.ISIS 翻译端到端：L2-only 直发（EtherType 0x8870 强制、L3
// 清空、LLC 载体 + 802.3 最小载荷 padding 46B），PDU 前缀逐字节 = builder
// 单测 TestBuildLANIIHL1 的公共头 + 固定字段。
func TestISISChain_LayerToSpecPlan(t *testing.T) {
	p, spec := isisPlannerFromSpecJSON(t, isisIIHL1)
	if spec.SrcMAC != isisSrcMAC {
		t.Fatalf("eth.src_mac must reach spec.SrcMAC on the production path, got %q", spec.SrcMAC)
	}
	// 翻译发生在 Plan → ValidateSpec → translateTerminalConfig（产线同序）；
	// 直接对 ValidateSpec 结果断言 spec.ISIS 内容。
	validated, err := p.ValidateSpec(spec)
	if err != nil {
		t.Fatalf("ValidateSpec: %v", err)
	}
	if validated.ISIS == nil {
		t.Fatal("translate must populate spec.ISIS from the isis layer config")
	}
	if validated.ISIS.SystemID != "0102.0304.0506" || validated.ISIS.HoldingTimer != 30 ||
		validated.ISIS.Priority != 100 || validated.ISIS.WireProfile != "iso10589_llc" {
		t.Fatalf("layer config not translated: %+v", validated.ISIS)
	}
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var pkts []core.PacketConfig
	for pkt := range ch {
		pkts = append(pkts, pkt)
	}
	if len(pkts) != 1 {
		t.Fatalf("packets=%d, want 1 (single lan_hello PDU)", len(pkts))
	}
	pkt := pkts[0]
	if pkt.L2.EtherType != core.EtherTypeISIS {
		t.Fatalf("EtherType=%#x, want %#x (L2-only 直发强制)", pkt.L2.EtherType, core.EtherTypeISIS)
	}
	if pkt.L2.SrcMAC != isisSrcMAC {
		t.Fatalf("SrcMAC=%q, want eth layer value %q", pkt.L2.SrcMAC, isisSrcMAC)
	}
	if pkt.L3.Protocol != 0 || pkt.L3.SrcIP != "" {
		t.Fatalf("L2-only chain must clear L3, got %+v", pkt.L3)
	}
	if pkt.L4.Protocol != "isis" {
		t.Fatalf("L4.Protocol=%q, want isis", pkt.L4.Protocol)
	}
	if pkt.L2.LLC == nil {
		t.Fatal("iso10589_llc profile must set L2.LLC (802.3 length + fe fe 03)")
	}
	if pkt.L2.LLC.DSAP != 0xfe || pkt.L2.LLC.SSAP != 0xfe || pkt.L2.LLC.Control != 0x03 {
		t.Fatalf("LLC header=%+v, want fe/fe/03", *pkt.L2.LLC)
	}
	// PDU 33B（8 公共头 + 19 IIH 固定 + 6 TLV 1）补齐 802.3 最小载荷 46B。
	if len(pkt.Payload) != 46 {
		t.Fatalf("payload=%d bytes, want 46 (33B PDU padded to LLC min 46)", len(pkt.Payload))
	}
	want := []byte{0x83, 0x1b, 0x01, 0x06, 0x0f, 0x01, 0x00, 0x00, 0x01}
	if got := pkt.Payload[:len(want)]; string(got) != string(want) {
		t.Fatalf("PDU prefix=% x, want % x", got, want)
	}
	for i := 33; i < len(pkt.Payload); i++ {
		if pkt.Payload[i] != 0 {
			t.Fatalf("padding byte %d = %#x, want 0", i, pkt.Payload[i])
		}
	}
}

// ①b EtherType profile：LLC 头前置进 payload（layer_gen.go 双 profile 语义），
// 不设 L2.LLC（802.3 length 分支跳过）。
func TestISISChain_EtherTypeProfile(t *testing.T) {
	p, spec := isisPlanner(t, `{
		"wire_profile": "iso10589_ethertype",
		"level": "l2",
		"pdu_type": "lan_hello",
		"system_id": "0a0b.0c0d.0e0f",
		"holding_timer": 45,
		"priority": 64,
		"lan_id": "0a0b0c0d0e0f02",
		"tlvs": [{"type": 1, "value_hex": "03 49 00 02"}]
	}`)
	if spec.ISIS.WireProfile != "iso10589_ethertype" {
		t.Fatalf("wire_profile=%q", spec.ISIS.WireProfile)
	}
	ch, err := p.Plan(context.Background(), core.FlowSpec{})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var pkts []core.PacketConfig
	for pkt := range ch {
		pkts = append(pkts, pkt)
	}
	if len(pkts) != 1 {
		t.Fatalf("packets=%d, want 1", len(pkts))
	}
	pkt := pkts[0]
	if pkt.L2.LLC != nil {
		t.Fatalf("ethertype profile must not set L2.LLC, got %+v", *pkt.L2.LLC)
	}
	if len(pkt.Payload) != 36 {
		t.Fatalf("payload=%d, want 36 (LLC 3B prefix + 33B PDU, no padding)", len(pkt.Payload))
	}
	want := []byte{0xfe, 0xfe, 0x03, 0x83, 0x1b, 0x01, 0x06, 0x10}
	if got := pkt.Payload[:len(want)]; string(got) != string(want) {
		t.Fatalf("payload prefix=% x, want % x (LLC prepended, L2 IIH type 0x10)", got, want)
	}
}

// ②presence 判死 + 顶层游离键（CheckProtoFlat；空 map 也死，M5①②）。
func TestISISChain_PresenceAndStrayTopLevelKeys(t *testing.T) {
	cfg := map[string]interface{}{
		"layers": isisLayers(t, isisIIHL1),
		"isis":   map[string]interface{}{},
	}
	msg := core.CheckProtoFlat("isis", cfg)
	if msg == "" {
		t.Fatal(`CheckProtoFlat(isis, {layers, isis:{}}) = "", want top-level isis presence rejection`)
	}
	if !strings.Contains(msg, "no longer accepts a top-level isis sub-config") {
		t.Fatalf("presence anchor mismatch: %q", msg)
	}
	for _, k := range []string{"src_ip", "dst_ip", "src_port", "dst_port", "count"} {
		bad := map[string]interface{}{"layers": cfg["layers"], k: 1}
		if m := core.CheckProtoFlat("isis", bad); m == "" {
			t.Fatalf("CheckProtoFlat(isis, {layers, %s}) = \"\", want flat-field rejection", k)
		} else if !strings.Contains(m, "no longer accepts flat config field "+k) {
			t.Fatalf("flat anchor mismatch for %s: %q", k, m)
		}
	}
	// 顶层 src_mac/dst_mac 与 layers 并存：checkLayerFlatConflict 家族文案
	// （schema 层 create-time 400；此处锁文案含键名）。
	if m := core.CheckProtoFlat("isis", map[string]interface{}{
		"layers": cfg["layers"], "src_mac": isisSrcMAC,
	}); m != "" {
		t.Fatalf("CheckProtoFlat 不负责 src_mac（由 checkLayerFlatConflict 承接），got %q", m)
	}
}

// ③载体拒（V7b：L2 终结层不得有 ip/transport 载体；锚词 carrier）。
func TestISISChain_CarrierRejected(t *testing.T) {
	for _, tc := range []struct {
		name  string
		chain string
	}{
		{"ip carrier", `[{"ip":{}},{"isis":{}}]`},
		{"tcp carrier", `[{"eth":{}},{"tcp":{}},{"isis":{}}]`},
		{"udp carrier", `[{"eth":{}},{"udp":{}},{"isis":{}}]`},
	} {
		_, err := layers.BuildLayersPlanner("isis", json.RawMessage(tc.chain))
		if err == nil {
			t.Fatalf("%s: BuildLayersPlanner(%s) = nil, want carrier rejection", tc.name, tc.chain)
		}
		if !strings.Contains(err.Error(), "carrier") {
			t.Fatalf("%s: error = %q, want anchor \"carrier\"", tc.name, err.Error())
		}
	}
}

// ⑤L2-only 默认面（D-ISIS-1，arp/goose/sv 同族）：isis 无 IP/端口语义，
// mapToFlowSpec 不得填假默认（10.0.0.1/20.0.0.1/12345/80）——isL2OnlyProtocol
// 同列后 spec 面诚实（空 IP/0 端口），HasExplicitSrcPort 恒真使 worker 跳过
// 多流端口递增（否则 N 流会各带一个假 src_port）。
func TestISISChain_L2OnlySpecDefaults(t *testing.T) {
	spec := core.MapToFlowSpec(map[string]interface{}{}, "isis")
	if spec.SrcIP != "" || spec.DstIP != "" {
		t.Fatalf("isis is L2-only: spec IP must stay empty, got %q/%q", spec.SrcIP, spec.DstIP)
	}
	if spec.SrcPort != 0 || spec.DstPort != 0 {
		t.Fatalf("isis is L2-only: spec ports must stay 0, got %d/%d", spec.SrcPort, spec.DstPort)
	}
	if !spec.HasExplicitSrcPort {
		t.Fatal("isis is L2-only: HasExplicitSrcPort must be true (worker must skip the per-flow port auto-increment)")
	}
	// 显式写的 IP/端口仍被透传（诚实拒绝由终结层/链校验承担，此处不静默吞）。
	explicit := core.MapToFlowSpec(map[string]interface{}{"src_ip": "192.0.2.1"}, "isis")
	if explicit.SrcIP != "192.0.2.1" {
		t.Fatalf("explicit src_ip must pass through, got %q", explicit.SrcIP)
	}
}

// ④用例文件收官自查：28 例（13 正 + 15 负）；非负例顶层键 ⊆ {layers}；
// 负例 expect 键集严格 = {expect_error, error_contains}；presence/游离键/
// 载体三类红例在案；每例 layers 恒 2 条目且 isis 条目非空。
func TestISISChain_CaseFileAudit(t *testing.T) {
	raw, err := os.ReadFile("../../../test/protocol_pcap/cases/isis.json")
	if err != nil {
		t.Fatalf("read cases: %v", err)
	}
	var cases []map[string]interface{}
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatalf("parse cases: %v", err)
	}
	if len(cases) != 28 {
		t.Fatalf("want 28 cases (13 pos + 15 neg), got %d", len(cases))
	}
	pos, neg := 0, 0
	presence, stray, carrier := false, false, false
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
		layersArr, _ := sj["layers"].([]interface{})
		if isNeg {
			neg++
			if len(exp) != 2 || exp["error_contains"] == nil {
				t.Fatalf("%s: negative expect keys = %v, want exactly {expect_error, error_contains}", id, exp)
			}
			switch ec, _ := exp["error_contains"].(string); {
			case strings.Contains(ec, "top-level isis sub-config"):
				presence = true
			case strings.Contains(ec, "flat config field"):
				stray = true
			case strings.Contains(ec, "carrier"):
				carrier = true
			}
			// 负例：判死形状（presence 例顶层留空 isis；游离例顶层留 flat 键）
			// 或纯层链（V7b/planner 拒）二者其一，不得两者皆非。
			if _, hasLayers := sj["layers"]; !hasLayers {
				t.Fatalf("%s: negative case must still carry the layers chain (rejection trigger lives in the chain)", id)
			}
			continue
		}
		pos++
		for k := range sj {
			if k != "layers" {
				t.Fatalf("%s: non-negative top-level key %q (want only layers)", id, k)
			}
		}
		// 纯 L2 链 [eth, isis]，isis 条目非空（业务键全量迁入）。
		if len(layersArr) != 2 {
			t.Fatalf("%s: layers has %d entries, want 2 ([eth, isis])", id, len(layersArr))
		}
		ethEntry, _ := layersArr[0].(map[string]interface{})
		isisEntry, _ := layersArr[1].(map[string]interface{})
		if _, ok := ethEntry["eth"]; !ok {
			t.Fatalf("%s: layers[0] is not eth", id)
		}
		sub, _ := isisEntry["isis"].(map[string]interface{})
		if sub == nil || len(sub) == 0 {
			t.Fatalf("%s: layers[1].isis is empty (business keys must move into the layer)", id)
		}
	}
	if pos != 13 || neg != 15 {
		t.Fatalf("want 13 pos + 15 neg, got %d pos + %d neg", pos, neg)
	}
	if !presence {
		t.Fatal("want presence negative (layers + top-level empty isis), found none")
	}
	if !stray {
		t.Fatal("want stray top-level key negative (layers + flat field), found none")
	}
	if !carrier {
		t.Fatal("want carrier negative ([ip,isis] V7b), found none")
	}
}
