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
	_ "github.com/trafficgen/trafficgen/internal/protocol/mongodb" // init 注册 mongodb 终结层生成器+校验器
)

// D-MONGODB-1（#87）P4 链级红例（dameng/drda_chain_test 同构）。覆盖：
//  ① 层 config 翻译生效（G-MONGO-1）——[ip,tcp,mongodb] 双消息查询响应对出
//     9 包且第 4/5 包载荷 = 契约 §3.3 的头字节（修前层 config 静默丢弃 →
//     P0b-2 缺省流 1 条消息，包数 8）；
//  ② 端口契约（G-MONGO-1 同批）——层内不写 dst_port 时上包目的端口 = 27017
//     （修前 mapToFlowSpec 通用缺省 80 泄漏，spec.DstPort≠0 使 DstPort switch
//     与通用 FieldContract 块都不生效 → 线上端口 80）；
//  ③ 严格解码未知层键拒（V9，锚词 unknown field）；
//  ④ 空层 {} 不静默缺省（层链下显式空配置 → validator 报缺消息）；
//  ⑤ presence 负例形状（M5 清单①）：层链 + 顶层空 mongodb 子映射并存判死；
//  ⑥ 白名单外游离键判死（M5 清单②，1.11–1.13）：CheckProtoFlat 五键；
//  ⑦ 载体：链夹 udp 拒（DependsOn tcp 自动补全 → 通用 transport duplicated，
//     锚词 tcp）；
//  ⑧ 数字坏 opcode 同步拒（G-MONGO-3）——修前 Validate 放行、Generate 期
//     buildMessage 报错被 drive 吞成空流（假成功）；
//  ⑨ responseTo 配对守卫（G-MONGO-3）：孤儿响应拒；
//  ⑩ BSON 确定性（G-MONGO-2）：同配置两次构建字节完全一致；
//  ⑪ 用例文件收官自查（M5 清单④：非负例顶层键=0 + 链形 [ip,tcp,mongodb] +
//     负例带锚词 + presence 负例在案）。

const (
	mgCli   = "10.0.0.1"
	mgSrv   = "20.0.0.1"
	mgCli6  = "2001:db8::1"
	mgSrv6  = "2001:db8::2"
	mgSport = 12345
)

func mgLayers(mongoCfg map[string]interface{}) []interface{} {
	return []interface{}{
		map[string]interface{}{"ip": map[string]interface{}{"src": mgCli, "dst": mgSrv}},
		map[string]interface{}{"tcp": map[string]interface{}{"src_port": mgSport}},
		map[string]interface{}{"mongodb": mongoCfg},
	}
}

func mgQueryReplyMsgs() []interface{} {
	return []interface{}{
		map[string]interface{}{"request_id": 100, "response_to": 0, "opcode": "OP_QUERY",
			"namespace": "test.users", "flags": 0, "skip": 0, "return_count": 1,
			"query": map[string]interface{}{"x": 1}},
		map[string]interface{}{"request_id": 101, "response_to": 100, "opcode": "OP_REPLY",
			"flags": 0, "cursor_id": 0, "starting_from": 0, "returned": 1,
			"documents": []interface{}{map[string]interface{}{"x": 1}}},
	}
}

func mgPlan(t *testing.T, layersArr []interface{}, src, dst string, sport uint16) ([]core.PacketConfig, error) {
	t.Helper()
	raw, err := json.Marshal(layersArr)
	if err != nil {
		t.Fatalf("marshal layers: %v", err)
	}
	p, err := layers.BuildLayersPlanner("mongodb", raw)
	if err != nil {
		return nil, err
	}
	spec := core.FlowSpec{SrcIP: src, DstIP: dst, SrcPort: sport}
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

func mgDrive(t *testing.T, mongoCfg map[string]interface{}) []core.PacketConfig {
	t.Helper()
	pkts, err := mgPlan(t, mgLayers(mongoCfg), mgCli, mgSrv, mgSport)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	return pkts
}

func mgDriveErr(t *testing.T, mongoCfg map[string]interface{}) error {
	t.Helper()
	_, err := mgPlan(t, mgLayers(mongoCfg), mgCli, mgSrv, mgSport)
	return err
}

// ① 层 config 翻译生效：双消息查询响应 = 3 握手 + 2 消息 + 4 挥手 = 9 包，
// 第 4/5 包载荷头 = 契约 §3.3 canonical 字节（修前层 config 静默丢弃 → 8 包）。
func TestMongoDBChain_LayerConfigTranslated(t *testing.T) {
	pkts := mgDrive(t, map[string]interface{}{"messages": mgQueryReplyMsgs()})
	if len(pkts) != 9 {
		t.Fatalf("got %d packets, want 9 (handshake 3 + 2 messages + teardown 4)", len(pkts))
	}
	if pkts[0].L4.Flags != 0x02 {
		t.Fatalf("packet 0 flags = 0x%02x, want SYN 0x02", pkts[0].L4.Flags)
	}
	// 数据包序号 3 = OP_QUERY，4 = OP_REPLY（0-based；1-based 包 4/5）。
	wantQuery := "330000006400000000000000d4070000"
	if got := hex.EncodeToString(pkts[3].Payload[:16]); got != wantQuery {
		t.Fatalf("OP_QUERY header = %s, want %s", got, wantQuery)
	}
	wantReply := "30000000650000006400000001000000"
	if got := hex.EncodeToString(pkts[4].Payload[:16]); got != wantReply {
		t.Fatalf("OP_REPLY header = %s, want %s", got, wantReply)
	}
}

// ② 端口契约：层内不写 dst_port，上包目的端口 = 27017。
//
// 必须走 mapToFlowSpec（服务端/suite 的真实路径）——直接 Plan 一个零值 spec
// 时 DstPort==0，通用 FieldContract 块照样补 27017，修前也是绿的（假通过）。
// 真 bug 是 mapToFlowSpec 把通用缺省 80 写进 spec.DstPort，使 DstPort switch
// 与 FieldContract 块**双双失效**，线上端口变 80。
// 链路径端口缺省的三条独立供给（gen-review m1 实证，逐条变异验证）：
//   ① registry FieldContract "tcp.dst_port":"27017"（链路径权威）
//   ② validateSpecBase 的 DstPort switch（chain_planner.go，冗余兜底）
//   ③ mapToFlowSpec 的 setDefaultDstPort(27017)（flat 兼容路径）
// 变异结论：关②仍绿（①兜住）；关①+②则 "destination port is required"。
// 故 PortContractDefault（经 MapToFlowSpec）与下例都无法区分①/②——下例钉的是
// **行为**（spec 无端口提示时链上仍出 27017），不是某一条 code path；②的注释
// 声称「mapToFlowSpec 已把通用缺省 80 写进 spec」与实测（27017）不符，已勘误。
func TestMongoDBChain_PortDefaultWithoutSpecHint(t *testing.T) {
	layersArr := mgLayers(map[string]interface{}{"messages": mgQueryReplyMsgs()})
	raw, _ := json.Marshal(layersArr)
	p, err := layers.BuildLayersPlanner("mongodb", raw)
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v", err)
	}
	ch, err := p.Plan(context.Background(), core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345, DstPort: 0,
	})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	up := 0
	for pk := range ch {
		if len(pk.Payload) == 0 || pk.Direction != "up" {
			continue
		}
		up++
		if pk.L4.DstPort != 27017 {
			t.Fatalf("up packet DstPort = %d, want 27017 (universal default 80 must not leak)", pk.L4.DstPort)
		}
	}
	if up == 0 {
		t.Fatal("no up data packets produced")
	}
}

// 设计 §2.1 明文：「无强制等于校验——显式写非 27017 被尊重、不拒绝」。
// 层值优先（applySpecToChain）必须压过所有缺省点（①②③）。这条是 27017 三处
// 缺省逻辑真正的风险面：任一处写成无条件赋值即在此红。
func TestMongoDBChain_ExplicitNonDefaultPortRespected(t *testing.T) {
	layersArr := []interface{}{
		map[string]interface{}{"ip": map[string]interface{}{"src": "10.0.0.1", "dst": "20.0.0.1"}},
		map[string]interface{}{"tcp": map[string]interface{}{"src_port": 12345, "dst_port": 9999}},
		map[string]interface{}{"mongodb": map[string]interface{}{"messages": mgQueryReplyMsgs()}},
	}
	raw, _ := json.Marshal(layersArr)
	p, err := layers.BuildLayersPlanner("mongodb", raw)
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v", err)
	}
	spec := core.MapToFlowSpec(map[string]interface{}{"layers": layersArr}, "mongodb")
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	for pk := range ch {
		if len(pk.Payload) == 0 || pk.Direction != "up" {
			continue
		}
		if pk.L4.DstPort != 9999 {
			t.Fatalf("up packet DstPort = %d, want 9999 (explicit layer value must win, design §2.1)", pk.L4.DstPort)
		}
		return
	}
	t.Fatal("no up data packet")
}

func TestMongoDBChain_PortContractDefault(t *testing.T) {
	layersArr := mgLayers(map[string]interface{}{"messages": mgQueryReplyMsgs()})
	cfg := map[string]interface{}{"layers": layersArr}
	spec := core.MapToFlowSpec(cfg, "mongodb")
	raw, _ := json.Marshal(layersArr)
	p, err := layers.BuildLayersPlanner("mongodb", raw)
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v", err)
	}
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	up, data := 0, 0
	for pk := range ch {
		if len(pk.Payload) == 0 {
			continue
		}
		data++
		if pk.Direction == "up" {
			if pk.L4.DstPort != 27017 {
				t.Fatalf("up packet DstPort = %d, want 27017 (universal default 80 must not leak)", pk.L4.DstPort)
			}
			up++
		} else if pk.L4.SrcPort != 27017 {
			t.Fatalf("down packet SrcPort = %d, want 27017", pk.L4.SrcPort)
		}
	}
	if data != 2 || up != 1 {
		t.Fatalf("data packets = %d (up %d), want 2 (up 1: OP_QUERY up / OP_REPLY down)", data, up)
	}
	// 显式非 27017 被尊重（设计 §2.1 无强制等于校验）：层值优先落线。
	arr2 := []interface{}{
		map[string]interface{}{"ip": map[string]interface{}{"src": mgCli, "dst": mgSrv}},
		map[string]interface{}{"tcp": map[string]interface{}{"src_port": mgSport, "dst_port": 37017}},
		map[string]interface{}{"mongodb": map[string]interface{}{"messages": mgQueryReplyMsgs()}},
	}
	pkts2, err := mgPlan(t, arr2, mgCli, mgSrv, mgSport)
	if err != nil {
		t.Fatalf("explicit port Plan: %v", err)
	}
	found := false
	for _, p := range pkts2 {
		if p.Direction == "up" && len(p.Payload) > 0 && p.L4.DstPort == 37017 {
			found = true
		}
	}
	if !found {
		t.Fatal("explicit tcp.dst_port=37017 not honored (no up packet on 37017)")
	}
}

// ③ 严格解码未知层键拒（V9 未知字段面）。
func TestMongoDBChain_UnknownLayerKeyReject(t *testing.T) {
	err := mgDriveErr(t, map[string]interface{}{
		"messages": mgQueryReplyMsgs(), "bogus_key": 1,
	})
	if err == nil || !strings.Contains(err.Error(), `unknown field "bogus_key"`) {
		t.Fatalf("bogus_key err = %v", err)
	}
}

// ④ 空层 {}：层链下显式空配置不静默走 P0b 缺省流（报缺消息）。
func TestMongoDBChain_EmptyLayerRejected(t *testing.T) {
	err := mgDriveErr(t, map[string]interface{}{})
	if err == nil || !strings.Contains(err.Error(), "at least one message or session required") {
		t.Fatalf("empty layer err = %v", err)
	}
}

// ⑤ presence 负例形状（M5 清单①）：层链 + 顶层空 mongodb 子映射并存 = 判死。
func TestMongoDBChain_PresenceRejected(t *testing.T) {
	cfg := map[string]interface{}{
		"layers":  mgLayers(map[string]interface{}{"messages": mgQueryReplyMsgs()}),
		"mongodb": map[string]interface{}{},
	}
	msg := core.CheckProtoFlat("mongodb", cfg)
	if msg == "" {
		t.Fatal("CheckProtoFlat(mongodb, {layers, mongodb:{}}) = \"\", want presence rejection")
	}
	if !strings.Contains(msg, "rejects a top-level mongodb sub-config") {
		t.Fatalf("CheckProtoFlat msg = %q", msg)
	}
}

// ⑥ 白名单外游离键判死（M5 清单②，1.11–1.13）：CheckProtoFlat 五键。
func TestMongoDBChain_StrayTopLevelKeysRejected(t *testing.T) {
	for _, k := range []string{"src_ip", "dst_ip", "src_port", "dst_port", "count"} {
		bad := map[string]interface{}{
			"layers": mgLayers(map[string]interface{}{"messages": mgQueryReplyMsgs()}),
			k:        1,
		}
		if msg := core.CheckProtoFlat("mongodb", bad); msg == "" {
			t.Fatalf("CheckProtoFlat(mongodb, {layers, %s}) = \"\", want flat-field rejection", k)
		}
	}
}

// ⑦ 载体：链夹 udp 拒（DependsOn tcp 自动补全 → 通用 transport duplicated，
// 锚词含 tcp）。
func TestMongoDBChain_UDPCarrierRejected(t *testing.T) {
	arr := []interface{}{
		map[string]interface{}{"ip": map[string]interface{}{"src": mgCli, "dst": mgSrv}},
		map[string]interface{}{"udp": map[string]interface{}{"src_port": mgSport}},
		map[string]interface{}{"mongodb": map[string]interface{}{"messages": mgQueryReplyMsgs()}},
	}
	raw, _ := json.Marshal(arr)
	if _, err := layers.BuildLayersPlanner("mongodb", raw); err == nil {
		t.Fatal("BuildLayersPlanner([ip,udp,mongodb]) = nil, want carrier rejection")
	} else if !strings.Contains(err.Error(), "tcp") {
		t.Fatalf("carrier error = %q, want anchor \"tcp\"", err.Error())
	}
}

// ⑧ 数字坏 opcode 同步拒（G-MONGO-3）：修前 Validate 放行 → Generate 期
// buildMessage 报错被 drive 吞成空流（0 包"完成"= 假成功）。
func TestMongoDBChain_NumericOpcodeRejected(t *testing.T) {
	for _, op := range []interface{}{2013, 2003, 2012, float64(2147483647)} {
		err := mgDriveErr(t, map[string]interface{}{"messages": []interface{}{
			map[string]interface{}{"request_id": 1, "opcode": op},
		}})
		if err == nil || !strings.Contains(err.Error(), "unknown opcode") {
			t.Fatalf("opcode %v err = %v, want unknown opcode", op, err)
		}
	}
	// 字符串路径同锚词（对照：修前已拒，非新增能力）。
	err := mgDriveErr(t, map[string]interface{}{"messages": []interface{}{
		map[string]interface{}{"request_id": 1, "opcode": "BOGUS"},
	}})
	if err == nil || !strings.Contains(err.Error(), "unknown opcode") {
		t.Fatalf("string BOGUS err = %v", err)
	}
}

// ⑨ responseTo 配对守卫（G-MONGO-3，设计 §4.2/§10.4）：孤儿响应 / 请求带
// responseTo 均拒，锚词 responseTo。
func TestMongoDBChain_PairingGuard(t *testing.T) {
	orphan := map[string]interface{}{"messages": []interface{}{
		map[string]interface{}{"request_id": 101, "response_to": 100, "opcode": "OP_REPLY", "returned": 1},
	}}
	if err := mgDriveErr(t, orphan); err == nil || !strings.Contains(err.Error(), "responseTo") {
		t.Fatalf("orphan reply err = %v, want anchor responseTo", err)
	}
	badReq := map[string]interface{}{"messages": []interface{}{
		map[string]interface{}{"request_id": 1, "response_to": 9, "opcode": "OP_QUERY", "namespace": "t.u"},
	}}
	if err := mgDriveErr(t, badReq); err == nil || !strings.Contains(err.Error(), "responseTo") {
		t.Fatalf("request with responseTo err = %v, want anchor responseTo", err)
	}
	// 合法配对必须放行（守卫不是"凡 OP_REPLY 都拒"）。
	if _, err := mgPlan(t, mgLayers(map[string]interface{}{"messages": mgQueryReplyMsgs()}), mgCli, mgSrv, mgSport); err != nil {
		t.Fatalf("valid pair rejected: %v", err)
	}
}

// ⑩ BSON 确定性（G-MONGO-2）：多键文档/多元素数组两次构建字节完全一致
// （修前 range map 随机序）。同一进程内重复构建即可暴露（Go map 遍历序
// 每轮不同）。
func TestMongoDBChain_BSONDeterministic(t *testing.T) {
	cfg := map[string]interface{}{"messages": []interface{}{
		map[string]interface{}{"request_id": 700, "opcode": "OP_INSERT", "namespace": "test.users",
			"documents": []interface{}{
				map[string]interface{}{"zeta": 1, "alpha": 2, "mid": 3, "beta": 4, "gamma": 5},
			}},
	}}
	first := mgDrive(t, cfg)
	for round := 0; round < 8; round++ {
		again := mgDrive(t, cfg)
		if len(again) != len(first) {
			t.Fatalf("round %d packet count %d != %d", round, len(again), len(first))
		}
		for i := range first {
			if hex.EncodeToString(first[i].Payload) != hex.EncodeToString(again[i].Payload) {
				t.Fatalf("round %d packet %d payload differs:\n  %s\n  %s",
					round, i, hex.EncodeToString(first[i].Payload), hex.EncodeToString(again[i].Payload))
			}
		}
	}
}

// ⑪ IPv6：同包数 + 首包 EtherType 0x86DD。
func TestMongoDBChain_IPv6Carrier(t *testing.T) {
	arr := []interface{}{
		map[string]interface{}{"ip": map[string]interface{}{"src": mgCli6, "dst": mgSrv6}},
		map[string]interface{}{"tcp": map[string]interface{}{"src_port": mgSport}},
		map[string]interface{}{"mongodb": map[string]interface{}{"messages": mgQueryReplyMsgs()}},
	}
	pkts, err := mgPlan(t, arr, mgCli6, mgSrv6, mgSport)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(pkts) != 9 {
		t.Fatalf("want 9 packets, got %d", len(pkts))
	}
	if pkts[0].L2.EtherType != 0x86DD {
		t.Fatalf("ethertype 0x%04x, want 0x86DD", pkts[0].L2.EtherType)
	}
}

// ⑫ 用例文件收官自查（M5 清单④）：31 例（18 正 + 13 负）；非负例顶层键 ⊆
// 白名单；非负例链形 = [ip,tcp,mongodb]；presence 负例在案；负例 expect 键集
// 严格两键。
func TestMongoDBChain_CaseFileAudit(t *testing.T) {
	raw, err := os.ReadFile("../../../test/protocol_pcap/cases/mongodb.json")
	if err != nil {
		t.Fatalf("read cases: %v", err)
	}
	var cases []map[string]interface{}
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatalf("parse cases: %v", err)
	}
	if len(cases) != 31 {
		t.Fatalf("want 31 cases (18 pos + 13 neg), got %d", len(cases))
	}
	allowed := map[string]bool{"layers": true, "flow_control": true, "output": true,
		"output_config": true, "group_id": true}
	presence := false
	nNeg := 0
	for _, c := range cases {
		id, _ := c["id"].(string)
		sj, _ := c["spec_json"].(map[string]interface{})
		if sj == nil {
			t.Fatalf("%s: spec_json missing", id)
		}
		exp, _ := c["expect"].(map[string]interface{})
		neg := exp != nil && exp["expect_error"] == true
		if neg {
			nNeg++
			// 负例 expect 键集严格 = {expect_error, error_contains}。
			if len(exp) != 2 || exp["error_contains"] == nil || exp["error_contains"] == "" {
				t.Fatalf("%s: negative expect must be exactly {expect_error, error_contains}, got %v", id, exp)
			}
			continue
		}
		for k := range sj {
			if !allowed[k] {
				t.Fatalf("%s: non-negative top-level key %q (want ⊆ layers/flow_control/output)", id, k)
			}
		}
		lays, _ := sj["layers"].([]interface{})
		if len(lays) != 3 {
			t.Fatalf("%s: want 3 layers [ip,tcp,mongodb], got %d", id, len(lays))
		}
		for i, want := range []string{"ip", "tcp", "mongodb"} {
			m, _ := lays[i].(map[string]interface{})
			if m == nil || len(m) != 1 {
				t.Fatalf("%s: layer %d shape", id, i)
			}
			for k := range m {
				if k != want {
					t.Fatalf("%s: layer %d = %q, want %q", id, i, k, want)
				}
			}
		}
	}
	if nNeg != 13 {
		t.Fatalf("want 13 negatives, got %d", nNeg)
	}
	if _, hasMongo := cases[0]["spec_json"].(map[string]interface{})["mongodb"]; hasMongo {
		t.Fatal("case 0: top-level mongodb on non-negative case")
	}
	for _, c := range cases {
		if c["id"] == "mongodb_neg_presence_top_level_mongodb" {
			sj := c["spec_json"].(map[string]interface{})
			if _, ok := sj["mongodb"]; ok {
				presence = true
			}
		}
	}
	if !presence {
		t.Fatal("want 1 presence negative (layers + top-level mongodb), found none")
	}
}
