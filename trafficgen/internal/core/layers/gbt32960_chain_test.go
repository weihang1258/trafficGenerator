package layers_test

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	_ "github.com/trafficgen/trafficgen/internal/protocol/gbt32960" // init 注册 gbt32960 终结层生成器+校验器
)

// D-GBT32960 P4 链级测试（tds_chain_test.go 同构 M5 五件套）：
// ①层条目→事件流端到端（[tcp,gbt32960] 出包：握手 3 + 登入/登出 4 业务
// + 挥手 4 = 11）/②presence 与顶层游离键判死（CheckProtoFlat gbt32960 分支）
// /③udp 载体拒（TransportOn=[tcp]，complete.go tcp-only 锚词）/④层 config
// 翻译端到端（layers[].gbt32960 的 vin/时间进 wire 字节，非 flat 通道）
// /⑤用例文件收官自查（非负例顶层键 ⊆ {layers,flow_control,output,group_id}）。

func gJSON(t *testing.T, layersArr []interface{}) json.RawMessage {
	t.Helper()
	out, err := json.Marshal(layersArr)
	if err != nil {
		t.Fatalf("marshal layers: %v", err)
	}
	return out
}

// gMinCfg 最小可校验 vehicle 配置（V4/V7/V30/V31/V35 全过）。
func gMinCfg() map[string]interface{} {
	return map[string]interface{}{
		"role":                            "vehicle",
		"vin":                             "LXXXXXXXXXXXXXXX1",
		"sim":                             "13800138000",
		"login_time":                      "2026-08-03T14:30:00+08:00",
		"login_serial_number":             1,
		"rechargeable_subsys_count":       1,
		"rechargeable_subsys_code_length": 1,
		"rechargeable_subsys_codes":       []interface{}{"00"},
	}
}

func gLayers(cfg map[string]interface{}) []interface{} {
	return []interface{}{
		map[string]interface{}{"tcp": map[string]interface{}{}},
		map[string]interface{}{"gbt32960": cfg},
	}
}

func gPlan(t *testing.T, layersArr []interface{}) []core.PacketConfig {
	t.Helper()
	p, err := layers.BuildLayersPlanner("gbt32960", gJSON(t, layersArr))
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v", err)
	}
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345, DstPort: 10020}
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

// ①层条目→事件流端到端：最小 vehicle 流（无 reports）握手 3 + 业务 4 +
// 挥手 4 = 11 包，首包 SYN，第 4 包 PSH-ACK 载荷以起始符 23 23 01 FE 开头。
func TestGBT32960Chain_LayerToEventPlan(t *testing.T) {
	pkts := gPlan(t, gLayers(gMinCfg()))
	if len(pkts) != 11 {
		t.Fatalf("got %d packets, want 11 (handshake 3 + login/ack 2 + logout/ack 2 + teardown 4)", len(pkts))
	}
	if pkts[0].L4.Flags != 0x02 {
		t.Fatalf("packet 0 flags = 0x%02x, want SYN 0x02", pkts[0].L4.Flags)
	}
	p4 := pkts[3].Payload
	if len(p4) < 25 || p4[0] != 0x23 || p4[1] != 0x23 || p4[2] != 0x01 || p4[3] != 0xFE {
		t.Fatalf("packet 3 payload head = % X, want 23 23 01 FE ...", p4[:min(8, len(p4))])
	}
	// 登入报文总长 = 25 + 31 = 56（n=1,m=1）。
	if len(p4) != 56 {
		t.Fatalf("login message length = %d, want 56 (25 header + 31 data)", len(p4))
	}
}

// ②presence 与顶层游离键判死。
func TestGBT32960Chain_PresenceAndStrayTopLevelKeys(t *testing.T) {
	cfg := map[string]interface{}{
		"layers":   gLayers(gMinCfg()),
		"gbt32960": map[string]interface{}{},
	}
	if msg := core.CheckProtoFlat("gbt32960", cfg); msg == "" {
		t.Fatal("CheckProtoFlat(gbt32960, {layers, gbt32960:{}}) = \"\", want top-level gbt32960 presence rejection")
	} else if !strings.Contains(msg, "no longer accepts a top-level gbt32960 sub-config") {
		t.Fatalf("CheckProtoFlat msg = %q", msg)
	}
	for _, k := range []string{"src_ip", "dst_ip", "src_port", "dst_port", "count"} {
		bad := map[string]interface{}{"layers": cfg["layers"], k: 1}
		if msg := core.CheckProtoFlat("gbt32960", bad); msg == "" {
			t.Fatalf("CheckProtoFlat(gbt32960, {layers, %s}) = \"\", want flat-field rejection", k)
		}
	}
}

// ③udp 载体拒（TransportOn=[tcp]，complete.go tcp-only 专用锚词）。
func TestGBT32960Chain_UDPCarrierRejected(t *testing.T) {
	arr := []interface{}{
		map[string]interface{}{"ip": map[string]interface{}{"src": "10.0.0.1", "dst": "20.0.0.1"}},
		map[string]interface{}{"udp": map[string]interface{}{"src_port": 12345, "dst_port": 10020}},
		map[string]interface{}{"gbt32960": gMinCfg()},
	}
	_, err := layers.BuildLayersPlanner("gbt32960", gJSON(t, arr))
	if err == nil {
		t.Fatal("BuildLayersPlanner([ip,udp,gbt32960]) = nil, want carrier rejection")
	}
	if !strings.Contains(err.Error(), "carrier") {
		t.Fatalf("carrier error = %q, want anchor \"carrier\"", err.Error())
	}
}

// ④层 config 翻译端到端：vin/登录时间从 layers[].gbt32960 进 wire 字节
// （translateTerminalConfig case gbt32960 → spec.GBT32960 → FlowMeta）。
// 断言登入报文含 VIN ASCII 与 BCD 时间；空层 config 走 validator 首命中
// V4（不静默缺省流）。
func TestGBT32960Chain_LayerConfigTranslated(t *testing.T) {
	pkts := gPlan(t, gLayers(gMinCfg()))
	p4 := pkts[3].Payload
	wantVIN := []byte("LXXXXXXXXXXXXXXX1")
	if len(p4) < 24 || string(p4[4:21]) != string(wantVIN) {
		t.Fatalf("login VIN field = %q, want %q", p4[4:21], wantVIN)
	}
	wantBCD := []byte{0x26, 0x08, 0x03, 0x14, 0x30, 0x00}
	if string(p4[24:30]) != string(wantBCD) {
		t.Fatalf("login time BCD = % X, want % X", p4[24:30], wantBCD)
	}

	// 空层 config：validator 同步拒（V4 VIN 必需），不静默产出缺省流。
	p, err := layers.BuildLayersPlanner("gbt32960", gJSON(t, gLayers(map[string]interface{}{})))
	if err != nil {
		return // 构建期拒绝亦可
	}
	if _, err := p.Plan(context.Background(), core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345, DstPort: 10020}); err == nil {
		t.Fatal("empty gbt32960 layer config: Plan = nil error, want V4 rejection")
	}
}

// ⑤用例文件收官自查：116 例（70 正 + 46 负 = 43 validator/presence/stray
// + A′ 8 补例）；非负例顶层键 ⊆ 白名单；presence 与游离键负例在案。
// presence 负例形状唯一性：顶层 gbt32960 只允许出现在带 presence 锚词的
// 负例上（t071/t103 的顶层 tcp 是 MSS 通道，非 presence 面）。
func TestGBT32960Chain_CaseFileAudit(t *testing.T) {
	raw, err := os.ReadFile("../../../test/protocol_pcap/cases/gbt32960.json")
	if err != nil {
		t.Fatalf("read cases: %v", err)
	}
	var cases []map[string]interface{}
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatalf("parse cases: %v", err)
	}
	if len(cases) != 116 {
		t.Fatalf("want 116 cases (70 pos + 46 neg), got %d", len(cases))
	}
	allowed := map[string]bool{"layers": true, "flow_control": true, "output": true, "group_id": true}
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
					t.Fatalf("%s: non-negative top-level key %q (want ⊆ layers/flow_control/output/group_id)", id, k)
				}
			}
		}
		if _, has := sj["gbt32960"]; has {
			if !neg {
				t.Fatalf("%s: top-level gbt32960 on non-negative case", id)
			}
			presence = true
		}
	}
	if !presence {
		t.Fatal("want 1 presence negative (layers + top-level gbt32960), found none")
	}
}
