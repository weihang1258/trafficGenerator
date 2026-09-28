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
	_ "github.com/trafficgen/trafficgen/internal/protocol/iec104" // init 注册 iec104 终结层生成器+校验器
)

// D-IEC104-1 P4 链级红例（drda_chain_test / bgp_chain_test 同构）。覆盖：
//  ① G-IEC104-9：层条目 layers[].iec104 翻译端到端（事件序 + 双向序号 +
//    包数公式 3+E+4；缺省路 events 缺席 vs 显式 []）；
//  ② M5-1 presence 判死形状（层链 + 顶层空 iec104 子映射并存）；
//  ③ M5-2 顶层游离键判死（CheckProtoFlat 五键 + schema 语义门 MAC 键）；
//  ④ M5-3 载体拒绝（DependsOn=[tcp]，complete.go tcp-only 锚词 carrier）；
//  ⑤ G-IEC104-2 幽灵键裁决（role/startdt/stopdt/repeat 层内即拒）；
//  ⑥ G-IEC104-8 value 越界拒（负值/>65535，锚词 value）；
//  ⑦ 4 锚词逐字命中（planner.go kind/type_id/max_apdu_length/IOA）；
//  ⑧ 用例文件收官自查（21 例 = 12 正 + 9 负；非负例顶层键=0）。

const (
	iCli   = "10.104.0.1"
	iSrv   = "10.104.0.2"
	iSport = 31001
	iDport = 2404
)

func iec104JSON(t *testing.T, layersArr []interface{}) json.RawMessage {
	t.Helper()
	out, err := json.Marshal(layersArr)
	if err != nil {
		t.Fatalf("marshal layers: %v", err)
	}
	return out
}

func iec104Layers(cfg map[string]interface{}) []interface{} {
	return []interface{}{
		map[string]interface{}{"ip": map[string]interface{}{"src": iCli, "dst": iSrv}},
		map[string]interface{}{"tcp": map[string]interface{}{"src_port": iSport}},
		map[string]interface{}{"iec104": cfg},
	}
}

// iec104Plan runs the production chain path (BuildLayersPlanner → ValidateSpec
// → Plan) so the test exercises the same translation + validator order the
// engine uses. errors are returned, not fatal, for the negative cases.
func iec104Plan(t *testing.T, layersArr []interface{}) ([]core.PacketConfig, error) {
	t.Helper()
	p, err := layers.BuildLayersPlanner("iec104", iec104JSON(t, layersArr))
	if err != nil {
		return nil, err
	}
	cp, ok := p.(*layers.ChainPlanner)
	if !ok {
		t.Fatalf("planner type = %T, want *layers.ChainPlanner", p)
	}
	spec := core.FlowSpec{SrcIP: iCli, DstIP: iSrv, SrcPort: iSport}
	v, err := cp.ValidateSpec(spec)
	if err != nil {
		return nil, err
	}
	ch, err := cp.Plan(context.Background(), v)
	if err != nil {
		return nil, err
	}
	var pkts []core.PacketConfig
	for c := range ch {
		pkts = append(pkts, c)
	}
	return pkts, nil
}

// uFrameSequence is the §3.3 six-control-word U sequence (startdt/testfr/stopdt).
func uFrameSequence() []interface{} {
	kinds := []string{"startdt_act", "startdt_con", "testfr_act", "testfr_con", "stopdt_act", "stopdt_con"}
	dirs := []string{"up", "down", "up", "down", "up", "down"}
	evs := make([]interface{}, 0, len(kinds))
	for i := range kinds {
		evs = append(evs, map[string]interface{}{"direction": dirs[i], "kind": kinds[i]})
	}
	return evs
}

// ① 事件序端到端：3 握手 + E 事件 + 4 挥手（设计 §6 包数公式）。
func TestIEC104Chain_EventSequenceTranslated(t *testing.T) {
	cases := []struct {
		name string
		evs  []interface{}
		want int
	}{
		{"u_six_frames", uFrameSequence(), 13},
		{"single_event", uFrameSequence()[:1], 8},
	}
	for _, c := range cases {
		pkts, err := iec104Plan(t, iec104Layers(map[string]interface{}{
			"common_address": 1, "events": c.evs,
		}))
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if len(pkts) != c.want {
			t.Fatalf("%s: got %d packets, want %d (3 + %d events + 4)", c.name, len(pkts), c.want, len(c.evs))
		}
		if pkts[0].L4.Flags != 0x02 {
			t.Fatalf("%s: packet 0 flags = 0x%02x, want SYN 0x02", c.name, pkts[0].L4.Flags)
		}
	}
	// U 六帧逐字节（设计 §3.3 表；offset 54 = Eth14+IPv4 20+TCP 20）。
	pkts, err := iec104Plan(t, iec104Layers(map[string]interface{}{
		"common_address": 1, "events": uFrameSequence(),
	}))
	if err != nil {
		t.Fatalf("u frames: %v", err)
	}
	want := []string{
		"680407000000", "68040b000000", "680443000000",
		"680483000000", "680413000000", "680423000000",
	}
	for i, w := range want {
		got := pkts[3+i].Payload
		if len(got) != 6 {
			t.Fatalf("U frame %d: len=%d, want 6", i, len(got))
		}
		if h := hexString(got); h != w {
			t.Fatalf("U frame %d = %s, want %s", i, h, w)
		}
	}
}

// ①b 双向序号：up/down 各自 N(S) 从 0 递增，I 帧只消耗本方向序号。
func TestIEC104Chain_BidirectionalSequence(t *testing.T) {
	evs := []interface{}{
		map[string]interface{}{"direction": "up", "kind": "startdt_act"},
		map[string]interface{}{"direction": "down", "kind": "startdt_con"},
		map[string]interface{}{"direction": "up", "kind": "i", "type_id": 1, "cause": 3, "ioa": 1, "siq": 1},
		map[string]interface{}{"direction": "down", "kind": "i", "type_id": 1, "cause": 20, "ioa": 2, "siq": 1},
		map[string]interface{}{"direction": "up", "kind": "s", "rx": 1},
	}
	pkts, err := iec104Plan(t, iec104Layers(map[string]interface{}{"common_address": 1, "events": evs}))
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(pkts) != 12 {
		t.Fatalf("got %d packets, want 12 (3 + 5 + 4)", len(pkts))
	}
	// up I 帧（索引 5）：N(S)=0 → 控制域 C[0..1] = 00 00。
	if got := pkts[5].Payload[2:4]; got[0] != 0x00 || got[1] != 0x00 {
		t.Fatalf("up I frame N(S) = % x, want 00 00 (first up I)", got)
	}
	// down I 帧（索引 6）：down 方向 N(S) 也从 0 起 → 控制域 C[0..1] = 00 00。
	if got := pkts[6].Payload[2:4]; got[0] != 0x00 || got[1] != 0x00 {
		t.Fatalf("down I frame N(S) = % x, want 00 00 (down sequence is independent)", got)
	}
	// up S 帧（索引 7）：C = 01 00 + (rx<<1) 小端 = 01 00 02 00。
	if h := hexString(pkts[7].Payload); h != "680401000200" {
		t.Fatalf("S frame = %s, want 680401000200", h)
	}
}

// ①c events 缺席 → 缺省路（STARTDT 对 + 默认 M_SP，每命令上下行各一份）；
// 显式 [] 在 layer_gen 同走 len==0 分支，故两者包数一致（presence 语义由
// 层 config 保留 nil/[] 之别，生成器侧等价）。
func TestIEC104Chain_EventsAbsentVsEmpty(t *testing.T) {
	absent, err := iec104Plan(t, iec104Layers(map[string]interface{}{"common_address": 1}))
	if err != nil {
		t.Fatalf("Plan(absent): %v", err)
	}
	empty, err := iec104Plan(t, iec104Layers(map[string]interface{}{"common_address": 1, "events": []interface{}{}}))
	if err != nil {
		t.Fatalf("Plan(empty): %v", err)
	}
	if len(absent) != 11 || len(empty) != 11 {
		t.Fatalf("absent=%d empty=%d packets, want 11 each (3 + STARTDT pair + 2 default M_SP + 4)", len(absent), len(empty))
	}
	// 缺省路首发为 STARTDT act。
	if h := hexString(absent[3].Payload); h != "680407000000" {
		t.Fatalf("default path pkt4 = %s, want STARTDT act 680407000000", h)
	}
}

// ② M5-1 presence 与 ③ M5-2 顶层游离键判死。
func TestIEC104Chain_PresenceAndStrayTopLevelKeys(t *testing.T) {
	cfg := map[string]interface{}{
		"layers": iec104Layers(map[string]interface{}{}),
		"iec104": map[string]interface{}{},
	}
	msg := core.CheckProtoFlat("iec104", cfg)
	if msg == "" {
		t.Fatal("CheckProtoFlat(iec104, {layers, iec104:{}}) = \"\", want top-level iec104 presence rejection")
	}
	if !strings.Contains(msg, "top-level iec104 sub-config") {
		t.Fatalf("CheckProtoFlat msg = %q", msg)
	}
	for _, k := range []string{"src_ip", "dst_ip", "src_port", "dst_port", "count"} {
		bad := map[string]interface{}{"layers": iec104Layers(map[string]interface{}{}), k: 1}
		m := core.CheckProtoFlat("iec104", bad)
		if m == "" {
			t.Fatalf("CheckProtoFlat(iec104, {layers, %s}) = \"\", want flat-field rejection", k)
		}
		if !strings.Contains(m, k) {
			t.Fatalf("CheckProtoFlat msg for %s = %q (must name the key)", k, m)
		}
	}
	// MAC 类走 schema 语义门（checkLayerFlatConflict 六键）。
	_, errs := schema.ValidateStrategy("synth", "iec104", map[string]any{
		"layers":  iec104Layers(map[string]interface{}{}),
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

// ④a 端口契约（设计 §1 不变式 1）：层内显式 tcp.dst_port 非 2404 即拒
// （planner 端口域；0=未写走 FieldContract 2404 缺省）。
func TestIEC104Chain_PortContractRejected(t *testing.T) {
	arr := []interface{}{
		map[string]interface{}{"ip": map[string]interface{}{"src": iCli, "dst": iSrv}},
		map[string]interface{}{"tcp": map[string]interface{}{"src_port": iSport, "dst_port": 5000}},
		map[string]interface{}{"iec104": map[string]interface{}{"common_address": 1, "events": []interface{}{}}},
	}
	_, err := iec104Plan(t, arr)
	if err == nil {
		t.Fatal("Plan(tcp.dst_port=5000) = nil, want port contract rejection")
	}
	if !strings.Contains(err.Error(), "dst_port must be 2404") {
		t.Fatalf("Plan err = %q, want anchor \"dst_port must be 2404\"", err.Error())
	}
	// 显式 2404 必须放行（契约端口本身）。
	arr[1] = map[string]interface{}{"tcp": map[string]interface{}{"src_port": iSport, "dst_port": 2404}}
	pkts, err := iec104Plan(t, arr)
	if err != nil {
		t.Fatalf("Plan(tcp.dst_port=2404) err: %v", err)
	}
	if len(pkts) != 11 {
		t.Fatalf("explicit 2404: got %d packets, want 11", len(pkts))
	}
}

// ④b FieldContract 缺省路径（回归守卫）：层内 tcp 不写 dst_port 时，链形状
// 必须走契约 2404 缺省而非通用 80——MapToFlowSpec 的 iec104 case 缺
// setDefaultDstPort(2404) 时 spec.DstPort 停在 80，被端口契约守卫误杀
// （P4 自审实证的回归；drda 446 / enip 44818 同款缺省）。
func TestIEC104Chain_DefaultPortFromContract(t *testing.T) {
	arr := []interface{}{
		map[string]interface{}{"ip": map[string]interface{}{"src": iCli, "dst": iSrv}},
		map[string]interface{}{"tcp": map[string]interface{}{"src_port": iSport}},
		map[string]interface{}{"iec104": map[string]interface{}{"common_address": 1, "events": []interface{}{}}},
	}
	// 复刻离线套件路径：spec 先经 MapToFlowSpec（会把 DstPort 填成通用缺省）。
	spec := core.MapToFlowSpec(map[string]interface{}{}, "iec104")
	if spec.DstPort != iDport {
		t.Fatalf("MapToFlowSpec DstPort = %d, want %d (iec104 case must default the contract port)", spec.DstPort, iDport)
	}
	p, err := layers.BuildLayersPlanner("iec104", iec104JSON(t, arr))
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v", err)
	}
	cp := p.(*layers.ChainPlanner)
	v, err := cp.ValidateSpec(spec)
	if err != nil {
		t.Fatalf("ValidateSpec(no explicit dst_port): %v (FieldContract 缺省路径被端口守卫误杀)", err)
	}
	ch, err := cp.Plan(context.Background(), v)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	n := 0
	for range ch {
		n++
	}
	if n != 11 {
		t.Fatalf("got %d packets, want 11", n)
	}
}

// ④ M5-3 载体拒绝：udp 载体（DependsOn tcp，complete.go tcp-only 锚词）。
func TestIEC104Chain_UDPCarrierRejected(t *testing.T) {
	arr := []interface{}{
		map[string]interface{}{"ip": map[string]interface{}{"src": iCli, "dst": iSrv}},
		map[string]interface{}{"udp": map[string]interface{}{"dst_port": iDport}},
		map[string]interface{}{"iec104": map[string]interface{}{"events": []interface{}{}}},
	}
	_, err := layers.BuildLayersPlanner("iec104", iec104JSON(t, arr))
	if err == nil {
		t.Fatal("BuildLayersPlanner([ip,udp,iec104]) = nil, want carrier rejection")
	}
	if !strings.Contains(err.Error(), "carrier") {
		t.Fatalf("carrier error = %q, want anchor \"carrier\"", err.Error())
	}
}

// ⑤ G-IEC104-2 幽灵键裁决：role/startdt/stopdt/repeat 已从层注册表删除，
// 层内出现即拒（V9 unknown field；空 map presence 语义不受影响）。
func TestIEC104Chain_GhostKeysRejected(t *testing.T) {
	for _, k := range []string{"role", "startdt", "stopdt", "repeat"} {
		_, err := layers.BuildLayersPlanner("iec104", iec104JSON(t,
			iec104Layers(map[string]interface{}{k: true})))
		if err == nil {
			t.Fatalf("layer key %q accepted, want unknown-field rejection (G-IEC104-2 裁决=删除)", k)
		}
		if !strings.Contains(err.Error(), k) {
			t.Fatalf("layer key %q err = %q, want the key named", k, err.Error())
		}
	}
	// 事件内幽灵键同理（事件级严格解码 DisallowUnknownFields 在翻译期承接
	// ——BuildLayersPlanner 的 V9 只走层顶层标量，嵌套 events 元素由
	// translateTerminalConfig 的严格解码拒）。
	for _, k := range []string{"control", "repeat"} {
		_, perr := iec104Plan(t, iec104Layers(map[string]interface{}{
			"events": []interface{}{map[string]interface{}{
				"direction": "up", "kind": "i", "type_id": 1, "cause": 3, "ioa": 1, k: true}},
		}))
		if perr == nil {
			t.Fatalf("event key %q accepted end-to-end, want rejection", k)
		}
		if !strings.Contains(perr.Error(), k) {
			t.Fatalf("event key %q plan err = %q, want the key named", k, perr.Error())
		}
	}
}

// ⑥ G-IEC104-8 value 越界拒（负值回绕 / >65535 丢高位都是静默错字节）。
func TestIEC104Chain_ValueOutOfRangeRejected(t *testing.T) {
	for _, v := range []int{-1, 65536} {
		_, err := iec104Plan(t, iec104Layers(map[string]interface{}{
			"common_address": 1,
			"events": []interface{}{map[string]interface{}{
				"direction": "up", "kind": "i", "type_id": 9, "cause": 3, "ioa": 1, "value": v}},
		}))
		if err == nil {
			t.Fatalf("value=%d accepted, want rejection", v)
		}
		if !strings.Contains(err.Error(), "value") {
			t.Fatalf("value=%d err = %q, want anchor \"value\"", v, err.Error())
		}
	}
	// 边界两侧放行。
	for _, v := range []int{0, 65535} {
		pkts, err := iec104Plan(t, iec104Layers(map[string]interface{}{
			"common_address": 1,
			"events": []interface{}{map[string]interface{}{
				"direction": "up", "kind": "i", "type_id": 9, "cause": 3, "ioa": 1, "value": v}},
		}))
		if err != nil {
			t.Fatalf("value=%d rejected: %v (0..65535 legal)", v, err)
		}
		if len(pkts) != 8 {
			t.Fatalf("value=%d: got %d packets, want 8 (3 + 1 + 4)", v, len(pkts))
		}
	}
}

// ⑦ 四锚词逐字命中（planner.go:31/35/46/41；负例的 error_contains 单一真相）。
func TestIEC104Chain_NegativeAnchors(t *testing.T) {
	cases := []struct {
		name string
		cfg  map[string]interface{}
		evs  []interface{}
		want string
	}{
		{
			name: "invalid_kind", want: "control",
			evs: []interface{}{map[string]interface{}{"direction": "up", "kind": "u"}},
		},
		{
			name: "unknown_type_id", want: "unknown type_id",
			evs: []interface{}{map[string]interface{}{"direction": "up", "kind": "i", "type_id": 250, "cause": 6, "ioa": 1}},
		},
		{
			name: "ioa_overflow", want: "IOA",
			evs: []interface{}{map[string]interface{}{"direction": "up", "kind": "i", "type_id": 45, "cause": 6, "ioa": 16777216, "value": 1}},
		},
		{
			name: "apdu_too_long", want: "APDU too long",
			cfg: map[string]interface{}{"max_apdu_length": 254},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := map[string]interface{}{"common_address": 1}
			for k, v := range c.cfg {
				cfg[k] = v
			}
			if c.evs != nil {
				cfg["events"] = c.evs
			}
			_, err := iec104Plan(t, iec104Layers(cfg))
			if err == nil {
				t.Fatalf("no error, want anchor %q", c.want)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %q, want anchor %q", err.Error(), c.want)
			}
		})
	}
}

// ⑧ 用例文件收官自查（M5 清单④）：20 例（12 正 + 8 负）；非负例顶层键 ⊆
// 白名单（layers/flow_control）；presence 判死形状在案。
func TestIEC104Chain_CaseFileAudit(t *testing.T) {
	raw, err := os.ReadFile("../../../test/protocol_pcap/cases/iec104.json")
	if err != nil {
		t.Fatalf("read cases: %v", err)
	}
	var cases []map[string]interface{}
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatalf("parse cases: %v", err)
	}
	if len(cases) != 21 {
		t.Fatalf("want 21 cases (12 pos + 9 neg), got %d", len(cases))
	}
	allowed := map[string]bool{"layers": true, "flow_control": true, "output": true, "output_config": true, "group_id": true}
	neg, pos := 0, 0
	presence := false
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
			// 负例 expect 严格两键（§4 契约）。
			if len(exp) != 2 || exp["error_contains"] == nil {
				t.Fatalf("%s: negative expect keys = %v, want exactly {expect_error, error_contains}", id, exp)
			}
			if _, hasIE := sj["iec104"]; hasIE {
				presence = true
			}
			continue
		}
		pos++
		for k := range sj {
			if !allowed[k] {
				t.Fatalf("%s: non-negative top-level key %q (want ⊆ layers/flow_control)", id, k)
			}
		}
		if _, hasIE := sj["iec104"]; hasIE {
			t.Fatalf("%s: top-level iec104 on non-negative case", id)
		}
	}
	if pos != 12 || neg != 9 {
		t.Fatalf("pos=%d neg=%d, want 12 pos + 9 neg", pos, neg)
	}
	if !presence {
		t.Fatal("want 1 presence negative (layers + top-level iec104), found none")
	}
}

func hexString(b []byte) string {
	const hexDigits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, hexDigits[c>>4], hexDigits[c&0x0f])
	}
	return string(out)
}
