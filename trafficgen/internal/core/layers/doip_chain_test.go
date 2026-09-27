package layers_test

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	_ "github.com/trafficgen/trafficgen/internal/protocol/doip" // init 注册 doip 终结层生成器+校验器
)

// D-DOIP-1 P4 链级红例（tftp_chain_test 同构）。契约：
// docs/protocol-designs/05-doip-design.md（v2.0.1 旧版 §2/§8 值域）+
// /tmp/pipe/57-doip/05-doip-testcase.md（T-DOIP 41 ID，§2–§4）。族划分：
//  ①层链 + 顶层 doip 空子映射并存判死（M5 清单①，presence 形状，G-DOIP-5）
//  ②白名单外游离键判死（M5 清单②，src_ip 等五键）
//  ③层翻译：层 config → spec.DoIP（十三键经 ParseDoIPConfigFromMap 复用
//    扁平解析单一真相；oem_specific 原文字节/user_data hex 双语义）
//  ④层内业务键经链路全周期（激活 0x0005/0x0006 字节钉 + SA/TA 一致性）
//  ⑤dst 端口缺省 13400（FieldContract 通用补齐；层内不写 → 默认）
//  ⑥UDP 三阶段判死（discovery/entity_status/power_mode 链上不可达）
//  ⑦用例文件收官自查（M5 清单④：非负例顶层键=0 + 三方一致）
//
// 契约 fixture：Tester 10.0.0.1 / ECU 20.0.0.1 / Tester 端口 12345 /
// Tester 地址 0x0E80 / ECU 逻辑地址 0x0001。

func doipChainJSON(t *testing.T, layersArr []interface{}) json.RawMessage {
	t.Helper()
	out, err := json.Marshal(layersArr)
	if err != nil {
		t.Fatalf("marshal layers: %v", err)
	}
	return out
}

func doipChain(ipCfg, tcpCfg, doipCfg map[string]interface{}) []interface{} {
	return []interface{}{
		map[string]interface{}{"ip": ipCfg},
		map[string]interface{}{"tcp": tcpCfg},
		map[string]interface{}{"doip": doipCfg},
	}
}

func doipBaseIP() map[string]interface{} {
	return map[string]interface{}{"src": "10.0.0.1", "dst": "20.0.0.1"}
}

func doipBaseTCP() map[string]interface{} {
	return map[string]interface{}{"src_port": 12345}
}

func doipBaseActivation() map[string]interface{} {
	return map[string]interface{}{
		"tester_address":  0x0E80,
		"logical_address": 0x0001,
		"activation": map[string]interface{}{
			"direction": "up", "activation_type": 0, "response_code": 16,
		},
	}
}

func doipPlan(t *testing.T, layersArr []interface{}) []core.PacketConfig {
	t.Helper()
	p, err := layers.BuildLayersPlanner("doip", doipChainJSON(t, layersArr))
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v", err)
	}
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345, DstPort: 13400}
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

// ①presence：层链 + 顶层 doip 空子映射并存判死（G-DOIP-5）。
func TestDoIPChain_PresenceTopLevelDoIP(t *testing.T) {
	arr := doipChain(doipBaseIP(), doipBaseTCP(), map[string]interface{}{})
	cfg := map[string]interface{}{
		"layers": arr,
		"doip":   map[string]interface{}{},
	}
	msg := core.CheckProtoFlat("doip", cfg)
	if msg == "" {
		t.Fatal("CheckProtoFlat(doip, {layers, doip:{}}) = \"\", want top-level doip presence rejection")
	}
	if !strings.Contains(msg, "no longer accepts a top-level doip sub-config") {
		t.Fatalf("CheckProtoFlat msg = %q, want anchor %q", msg, "no longer accepts a top-level doip sub-config")
	}
}

// ②游离键：顶层 src_ip/dst_ip/src_port/dst_port/count 任一即判死。
func TestDoIPChain_StrayFlatFields(t *testing.T) {
	arr := doipChain(doipBaseIP(), doipBaseTCP(), doipBaseActivation())
	var layersRaw []interface{}
	raw, _ := json.Marshal(arr)
	_ = json.Unmarshal(raw, &layersRaw)
	for _, k := range []string{"src_ip", "dst_ip", "src_port", "dst_port", "count"} {
		bad := map[string]interface{}{"layers": layersRaw, k: 1}
		if msg := core.CheckProtoFlat("doip", bad); msg == "" {
			t.Fatalf("CheckProtoFlat(doip, {layers, %s}) = \"\", want flat-field rejection", k)
		} else if !strings.Contains(msg, "no longer accepts flat config field "+k) {
			t.Fatalf("CheckProtoFlat msg = %q, want flat-field anchor for %s", msg, k)
		}
	}
}

// ③层翻译：层 config 十三键 → spec.DoIP（oem_specific 原文字节 +
// user_data 经 UDS 结构；翻译后 validator 放行，Plan 出包）。
func TestDoIPChain_LayerTranslateActivation(t *testing.T) {
	pkts := doipPlan(t, doipChain(doipBaseIP(), doipBaseTCP(), doipBaseActivation()))
	if len(pkts) < 5 {
		t.Fatalf("got %d packets, want >= 5 (handshake 3 + activation 2)", len(pkts))
	}
	if pkts[0].L4.Flags != 0x02 {
		t.Fatalf("packet 0 flags = 0x%02x, want SYN 0x02", pkts[0].L4.Flags)
	}
	// 0x0005 首字节：PV=0x02 InvPV=0xFD type=0x0005 len=7。
	found05 := false
	for _, p := range pkts {
		if len(p.Payload) >= 15 && p.Payload[0] == 0x02 && p.Payload[1] == 0xFD &&
			p.Payload[2] == 0x00 && p.Payload[3] == 0x05 {
			found05 = true
			if p.Payload[7] != 0x07 {
				t.Fatalf("0x0005 PayloadLength = %d, want 7", p.Payload[7])
			}
			break
		}
	}
	if !found05 {
		t.Fatal("no 0x0005 activation frame found in chain output")
	}
}

func doipPlanErr(t *testing.T, layersArr []interface{}) error {
	t.Helper()
	p, err := layers.BuildLayersPlanner("doip", doipChainJSON(t, layersArr))
	if err != nil {
		return err
	}
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345, DstPort: 13400}
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		return err
	}
	for range ch {
	}
	return nil
}

// ④锚词负例：值域拒绝走真实 validator 文案（与 T-DOIP #25–#41 同锚；
// Plan 期同步报错，非空流）。
func TestDoIPChain_ValueAnchors(t *testing.T) {
	for _, tc := range []struct {
		name string
		mut  func(map[string]interface{})
		want string
	}{
		{"activation_type_reserved", func(m map[string]interface{}) {
			m["activation"] = map[string]interface{}{"activation_type": 0x02, "response_code": 16}
		}, "ActivationType must be 0x00, 0x01, or 0xE0-0xFF"},
		{"response_code_reserved", func(m map[string]interface{}) {
			m["activation"] = map[string]interface{}{"response_code": 0x12}
		}, "ResponseCode must be 0x00-0x07, 0x10, or 0x11"},
		{"messages_without_activation", func(m map[string]interface{}) {
			delete(m, "activation")
			m["messages"] = []interface{}{map[string]interface{}{"direction": "up"}}
		}, "Messages require Activation"},
		{"ack_code_reserved", func(m map[string]interface{}) {
			m["activation"] = map[string]interface{}{"response_code": 16}
			m["messages"] = []interface{}{map[string]interface{}{"direction": "up", "ack_code": 0x01}}
		}, "AckCode must be 0x00"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := doipBaseActivation()
			tc.mut(cfg)
			err := doipPlanErr(t, doipChain(doipBaseIP(), doipBaseTCP(), cfg))
			if err == nil {
				t.Fatalf("%s: Plan = nil, want anchor %q", tc.name, tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("%s: error = %q, want anchor %q", tc.name, err.Error(), tc.want)
			}
		})
	}
}

// ⑤UDP 三阶段判死（G-DOIP-2）：discovery/entity_status/power_mode 任一
// 非空即拒，锚词与生成器 layer_gen.go:63-69 逐字一致。
func TestDoIPChain_UDPPhasesRejected(t *testing.T) {
	for _, tc := range []struct {
		name string
		key  string
	}{
		{"discovery", "discovery"},
		{"entity_status", "entity_status"},
		{"power_mode", "power_mode"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := doipBaseActivation()
			cfg[tc.key] = map[string]interface{}{"direction": "up"}
			err := doipPlanErr(t, doipChain(doipBaseIP(), doipBaseTCP(), cfg))
			if err == nil {
				t.Fatalf("%s: Plan = nil, want (%s) rejection", tc.name, tc.key)
			}
			if !strings.Contains(err.Error(), tc.key) || !strings.Contains(err.Error(), "not supported") {
				t.Fatalf("%s: error = %q, want anchor %q + not supported", tc.name, err.Error(), tc.key)
			}
		})
	}
}

// ⑥udp 载体拒（TransportOn=[tcp]，complete.go tcp-only 专用锚词）。
func TestDoIPChain_UDPCarrierRejected(t *testing.T) {
	arr := []interface{}{
		map[string]interface{}{"ip": doipBaseIP()},
		map[string]interface{}{"udp": map[string]interface{}{"src_port": 12345, "dst_port": 13400}},
		map[string]interface{}{"doip": doipBaseActivation()},
	}
	_, err := layers.BuildLayersPlanner("doip", doipChainJSON(t, arr))
	if err == nil {
		t.Fatal("BuildLayersPlanner([ip,udp,doip]) = nil, want carrier rejection")
	}
	if !strings.Contains(err.Error(), "carrier") {
		t.Fatalf("carrier error = %q, want anchor \"carrier\"", err.Error())
	}
}

// ⑦用例文件收官自查：非负例顶层键 ⊆ 白名单；presence/游离键负例在案。
func TestDoIPChain_CaseFileAudit(t *testing.T) {
	raw, err := os.ReadFile("../../../test/protocol_pcap/cases/doip.json")
	if err != nil {
		t.Fatalf("read cases: %v", err)
	}
	var cases []map[string]interface{}
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatalf("parse cases: %v", err)
	}
	allowed := map[string]bool{"layers": true, "flow_control": true, "output": true, "output_config": true, "group_id": true}
	ids := map[string]bool{}
	for _, c := range cases {
		id, _ := c["id"].(string)
		ids[id] = true
		sj, _ := c["spec_json"].(map[string]interface{})
		if sj == nil {
			t.Fatalf("%s: spec_json missing", id)
		}
		exp, _ := c["expect"].(map[string]interface{})
		neg := exp != nil && exp["expect_error"] == true
		if !neg {
			for k := range sj {
				if !allowed[k] {
					t.Fatalf("%s: non-negative top-level key %q (want ⊆ layers/flow_control/output/output_config/group_id)", id, k)
				}
			}
		}
		if _, hasDoIP := sj["doip"]; hasDoIP {
			if !neg {
				t.Fatalf("%s: top-level doip on non-negative case", id)
			}
		}
	}
	for _, want := range []string{"doip_neg_presence", "doip_neg_stray_src_ip", "doip_neg_stray_count"} {
		if !ids[want] {
			t.Fatalf("want case %s in file, missing", want)
		}
	}
}

// ⑧端口契约：tcp 层不写 dst_port 时缺省补齐 13400（FieldContract 驱动，
// enip :44818 同款）；层内显式写则尊重用户值。
func TestDoIPChain_DefaultDstPort(t *testing.T) {
	pkts := doipPlan(t, doipChain(doipBaseIP(), doipBaseTCP(), doipBaseActivation()))
	if len(pkts) == 0 {
		t.Fatal("no packets")
	}
	for _, p := range pkts {
		if p.Direction == "up" && p.L4.DstPort != 13400 {
			t.Fatalf("up packet DstPort = %d, want FieldContract default 13400", p.L4.DstPort)
		}
	}
	// 显式端口优先。
	explicit := doipChain(doipBaseIP(),
		map[string]interface{}{"src_port": 12345, "dst_port": 13401},
		doipBaseActivation())
	pkts2 := doipPlan(t, explicit)
	for _, p := range pkts2 {
		if p.Direction == "up" && p.L4.DstPort != 13401 {
			t.Fatalf("explicit dst_port: up packet DstPort = %d, want 13401", p.L4.DstPort)
		}
	}
}

// ⑨V1 最小兼容子集：PV=0x01 时 0x0005/0x0006 无 OEM，长度 7/9。
func TestDoIPChain_V1Minimal(t *testing.T) {
	cfg := map[string]interface{}{
		"tester_address":   0x0E80,
		"logical_address":  0x0001,
		"protocol_version": 0x01,
		"activation":       map[string]interface{}{"response_code": 16},
	}
	pkts := doipPlan(t, doipChain(doipBaseIP(), doipBaseTCP(), cfg))
	var saw05, saw06 bool
	for _, p := range pkts {
		if len(p.Payload) < 8 || p.Payload[0] != 0x01 || p.Payload[1] != 0xFE {
			continue
		}
		switch {
		case p.Payload[2] == 0x00 && p.Payload[3] == 0x05:
			saw05 = true
			if p.Payload[7] != 7 {
				t.Fatalf("V1 0x0005 PayloadLength = %d, want 7", p.Payload[7])
			}
		case p.Payload[2] == 0x00 && p.Payload[3] == 0x06:
			saw06 = true
			if p.Payload[7] != 9 {
				t.Fatalf("V1 0x0006 PayloadLength = %d, want 9", p.Payload[7])
			}
		}
	}
	if !saw05 || !saw06 {
		t.Fatalf("V1 chain missing 0x0005/0x0006 (saw05=%v saw06=%v)", saw05, saw06)
	}
}
