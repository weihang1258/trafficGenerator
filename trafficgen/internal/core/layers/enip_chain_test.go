package layers_test

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	"github.com/trafficgen/trafficgen/internal/core/schema"
	_ "github.com/trafficgen/trafficgen/internal/protocol/enip" // init 注册 enip 终结层生成器+校验器
)

// D-ENIP-1 P4 链级红例（kerberos_chain_test 同构）。覆盖：
//  ① G-ENIP-3 层内业务键（commands/transport/scenario 等）翻译生效——
//    registry 补 Fields 之前恒 "unknown field"；
//  ② presence 负例形状（M5 清单①）：层链 + 顶层空 enip 子映射并存判死；
//  ③ 白名单外游离键判死（M5 清单②，1.11–1.13）：CheckProtoFlat 五键 +
//    schema 语义门 MAC 键；
//  ④ 负例带锚词（M5 清单③）：每例断言 error_contains 命中代码锚词；
//  ⑤ 收官自查行（M5 清单④）：用例文件全例「非负例顶层键=0」。
//
// 契约 fixture：客户端 10.0.0.1 / 服务端 20.0.0.1 / 44818（与 cases 同值，
// 便于逐字节对齐 legacy 期望）。

const (
	eCli   = "10.0.0.1"
	eSrv   = "20.0.0.1"
	eSport = 12345
	eDport = 44818
)

func enipLayers(cfg map[string]interface{}) []interface{} {
	return []interface{}{
		map[string]interface{}{"ip": map[string]interface{}{"src": eCli, "dst": eSrv}},
		map[string]interface{}{"tcp": map[string]interface{}{"src_port": eSport, "dst_port": eDport}},
		map[string]interface{}{"enip": cfg},
	}
}

func planEnipAt(t *testing.T, layersArr []interface{}) ([]core.PacketConfig, error) {
	t.Helper()
	raw, _ := json.Marshal(layersArr)
	p, err := layers.BuildLayersPlanner("enip", raw)
	if err != nil {
		return nil, err
	}
	spec := core.FlowSpec{SrcIP: eCli, DstIP: eSrv, SrcPort: eSport, DstPort: eDport}
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

func driveE(t *testing.T, cfg map[string]interface{}) []core.PacketConfig {
	t.Helper()
	pkts, err := planEnipAt(t, enipLayers(cfg))
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	return pkts
}

func driveEErr(t *testing.T, cfg map[string]interface{}) error {
	t.Helper()
	_, err := planEnipAt(t, enipLayers(cfg))
	return err
}

// eMsgHex renders the ENIP message bytes of packet idx (= the TCP segment
// payload the tcp layer generator hands up; Plan returns PacketConfigs,
// not assembled Ethernet frames).
func eMsgHex(t *testing.T, pkts []core.PacketConfig, idx int) string {
	t.Helper()
	if idx >= len(pkts) {
		t.Fatalf("packet %d out of range (have %d)", idx, len(pkts))
	}
	return strings.ToUpper(hex.EncodeToString(pkts[idx].Payload))
}

// ① 层内键翻译：commands 住 enip 层，NOP 单命令 = 4 TCP 段 + 握手/挥手。
func TestENIPChain_LayerConfigTranslated(t *testing.T) {
	pkts := driveE(t, map[string]interface{}{
		"transport": "tcp",
		"commands": []interface{}{
			map[string]interface{}{"command": 0, "session_handle": 305419896,
				"payload": []interface{}{222, 173, 190, 239}},
		},
	})
	if len(pkts) != 8 {
		t.Fatalf("want 8 packets (3 handshake + 1 ENIP + 4 teardown), got %d", len(pkts))
	}
	// 第 4 包 = ENIP NOP：24B 头 + 4B payload DE AD BE EF。
	want := "000004007856341200000000000000000000000000000000DEADBEEF"
	if got := eMsgHex(t, pkts, 3); got != want {
		t.Fatalf("ENIP message bytes:\n got %s\nwant %s", got, want)
	}
}

// ② sendrrdata/response 双命令：from_response 会话句柄回写经层内键生效。
func TestENIPChain_RegisterSessionThenSendRRData(t *testing.T) {
	pkts := driveE(t, map[string]interface{}{
		"transport": "tcp",
		"commands": []interface{}{
			map[string]interface{}{"command": 101, "protocol_version": 1, "option_flag": 0,
				"direction": "up"},
			map[string]interface{}{"command": 101, "protocol_version": 1, "option_flag": 0,
				"direction": "down", "session_handle": 305419896, "status": 0},
			map[string]interface{}{"command": 111, "cip_service": 14, "class_id": 1,
				"instance_id": 1, "attribute_id": 1,
				"from_response_field": "session_handle", "source_command_index": 1},
		},
	})
	// 3 命令 → 8 + 2 = 10 包（握手 3 + 命令 3 + down + 挥手 4）。
	if len(pkts) != 10 {
		t.Fatalf("want 10 packets, got %d", len(pkts))
	}
	// 命令 3（SendRRData）的 ENIP 头 offset 4 起 4B = 回写的 SessionHandle。
	msg := eMsgHex(t, pkts, 5)
	if !strings.HasPrefix(msg, "6F00") {
		t.Fatalf("packet 5 is not SendRRData: %s", msg[:8])
	}
	if got := msg[8:16]; got != "78563412" {
		t.Fatalf("SessionHandle not backfilled from response: %s (want 78563412)", got)
	}
}

// ③ 未支持面显式拒绝（不静默缩水）——三条生成器守卫锚词。
func TestENIPChain_UnsupportedShapesRejected(t *testing.T) {
	cases := []struct {
		name string
		cfg  map[string]interface{}
		want string
	}{
		{"io_data", map[string]interface{}{
			"transport": "tcp",
			"commands":  []interface{}{map[string]interface{}{"command": 0}},
			"io_data":   map[string]interface{}{"o2t_connection_id": 1, "frame_count": 1},
		}, "io_data"},
		{"transport_udp", map[string]interface{}{
			"transport": "udp",
			"commands":  []interface{}{map[string]interface{}{"command": 0}},
		}, "transport \"udp\""},
		{"multi_session", map[string]interface{}{
			"transport":     "tcp",
			"session_count": 2,
			"commands":      []interface{}{map[string]interface{}{"command": 0}},
		}, "multi-unit expansion"},
		{"multi_flow", map[string]interface{}{
			"transport":  "tcp",
			"flow_count": 2,
			"commands":   []interface{}{map[string]interface{}{"command": 0}},
		}, "multi-unit expansion"},
	}
	for _, tc := range cases {
		err := driveEErr(t, tc.cfg)
		if err == nil {
			t.Fatalf("%s: want rejection, got nil", tc.name)
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s: err %q does not contain %q", tc.name, err.Error(), tc.want)
		}
	}
}

// ④ 未知命令码 = 校验期禁止（T-081 锚词），且必须同步报错（非空流）。
func TestENIPChain_UnknownCommandRejected(t *testing.T) {
	err := driveEErr(t, map[string]interface{}{
		"transport": "tcp",
		"commands":  []interface{}{map[string]interface{}{"command": 4660}},
	})
	if err == nil || !strings.Contains(err.Error(), "unknown command 0x1234") {
		t.Fatalf("want 'unknown command 0x1234', got %v", err)
	}
}

// ⑤ 严格解码：层 config 未知键拒（kerberos/ntlm/sstp 同款 DisallowUnknownFields）。
func TestENIPChain_StrictDecodeUnknownLayerKey(t *testing.T) {
	err := driveEErr(t, map[string]interface{}{
		"transport": "tcp",
		"commands":  []interface{}{map[string]interface{}{"command": 0}},
		"bogus_key": 1,
	})
	if err == nil {
		t.Fatal("want unknown-field rejection, got nil")
	}
	if !strings.Contains(err.Error(), "bogus_key") {
		t.Fatalf("err %q does not name the unknown key", err.Error())
	}
}

// ⑥ presence 负例形状（M5 清单①）：层链 + 顶层空 enip 子映射并存 = 判死。
func TestENIPChain_PresenceRejected(t *testing.T) {
	cfg := map[string]interface{}{
		"layers": enipLayers(map[string]interface{}{
			"transport": "tcp",
			"commands":  []interface{}{map[string]interface{}{"command": 0}},
		}),
		"enip": map[string]interface{}{},
	}
	msg := core.CheckProtoFlat("enip", cfg)
	if msg == "" {
		t.Fatal("CheckProtoFlat(enip, {layers, enip:{}}) = \"\", want presence rejection")
	}
	if !strings.Contains(msg, "no longer accepts a top-level enip sub-config") {
		t.Fatalf("CheckProtoFlat msg = %q", msg)
	}
}

// ⑦ 白名单外游离键判死（M5 清单②，1.11–1.13）：四元组五键 + MAC 二键。
func TestENIPChain_StrayTopLevelKeysRejected(t *testing.T) {
	layersArr := enipLayers(map[string]interface{}{
		"transport": "tcp",
		"commands":  []interface{}{map[string]interface{}{"command": 0}},
	})
	for _, k := range []string{"src_ip", "dst_ip", "src_port", "dst_port", "count"} {
		bad := map[string]interface{}{"layers": layersArr, k: 1}
		msg := core.CheckProtoFlat("enip", bad)
		if msg == "" {
			t.Fatalf("CheckProtoFlat(enip, {layers, %s}) = \"\", want rejection", k)
		}
		if !strings.Contains(msg, k) {
			t.Fatalf("CheckProtoFlat msg for %s = %q (must name the key)", k, msg)
		}
	}
	// MAC 类走 schema 语义门（checkLayerFlatConflict 六键）。
	_, errs := schema.ValidateStrategy("synth", "enip", map[string]any{
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

// ⑧ 契约面锚词与代码一致：负例 error_contains 必须命中代码锚词集
//（M5 清单③：一切负例带锚词，逐例可回溯）。
func TestENIPChain_NegativeAnchorsPresentInCode(t *testing.T) {
	raw, err := os.ReadFile("../../../test/protocol_pcap/cases/enip.json")
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

// ⑨ 收官自查行（M5 清单④）：非负例顶层键 = 0（白名单只有结构性键）。
func TestENIPChain_CaseFileTopLevelWhitelist(t *testing.T) {
	raw, err := os.ReadFile("../../../test/protocol_pcap/cases/enip.json")
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
