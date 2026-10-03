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
	_ "github.com/trafficgen/trafficgen/internal/protocol/amqp" // init 注册 amqp 终结层生成器+校验器
)

// D-AMQP-1 P4 链级红例（ntlm/ocsp_chain_test 同构）：①空配置基线（P0b-2
// 缺省档一条 protocol header）/②protocol header 8 字节固定布局（AMQP
// 0-9-1 §4.2：41 4d 51 50 00 00 09 01）/③METHOD frame 布局（type=1、
// channel、size、CE）/④HEARTBEAT 固定 8 字节（08 00 00 00 00 00 00 ce）/
// ⑤CONTENT 序列（publish→HEADER→BODY，BodySize 自动累加）/⑥载体形状
// （缺 tcp/夹 udp/混合地址族，锚词 carrier/family）/⑦严格解码（未知键拒）/
// ⑧多连接隔离（双 protocol header，G-AMQP-2 注记）/⑨IPv6（offset 74，
// 应用 bytes 不变）/⑩presence 与顶层游离键判死（1.11–1.13）/⑪用例文件
// 收官自查（非负例顶层键=0 + 三方一致）。
// 契约 fixture：客户端 10.0.0.1 / 服务端 20.0.0.1 / TCP 12345→5672。

const (
	aCli   = "10.0.0.1"
	aSrv   = "20.0.0.1"
	aCli6  = "2001:db8::1"
	aSrv6  = "2001:db8::2"
	aSport = 12345
	aPort  = 5672
)

// aProtoHeader 是 8 字节 AMQP 0-9-1 protocol header（builder.go:14
// ProtocolHeader = "AMQP\x00\x00\x09\x01"）。
const aProtoHeader = "414D515000000901"

// aHeartbeat 是固定 8 字节 HEARTBEAT frame（builder.go:116-118：
// type=8、channel=0、size=0、end=CE）。
const aHeartbeat = "08000000000000CE"

func aJSON(t *testing.T, layersArr []interface{}) json.RawMessage {
	t.Helper()
	out, _ := json.Marshal(layersArr)
	return out
}

func aIP(cfg map[string]interface{}) []interface{} {
	return []interface{}{
		map[string]interface{}{"ip": map[string]interface{}{"src": aCli, "dst": aSrv}},
		map[string]interface{}{"tcp": map[string]interface{}{"src_port": aSport, "dst_port": aPort}},
		map[string]interface{}{"amqp": cfg},
	}
}

func aIP6(cfg map[string]interface{}) []interface{} {
	return []interface{}{
		map[string]interface{}{"ip": map[string]interface{}{"src": aCli6, "dst": aSrv6}},
		map[string]interface{}{"tcp": map[string]interface{}{"src_port": aSport, "dst_port": aPort}},
		map[string]interface{}{"amqp": cfg},
	}
}

func aHdrEv() map[string]interface{} {
	return map[string]interface{}{"kind": "protocol_header", "direction": "c2s"}
}

func aMethod(dir string, class, method int, ch int) map[string]interface{} {
	return map[string]interface{}{"kind": "method", "direction": dir,
		"class_id": class, "method_id": method, "channel": ch}
}

// aHandshake 返回六步 connection 握手事件（start/start-ok/tune/tune-ok/
// open/open-ok，方向逐方法钉死，planner.go:239-283）。
func aHandshake() []interface{} {
	return []interface{}{
		aHdrEv(),
		aMethod("s2c", 10, 10, 0), aMethod("c2s", 10, 11, 0),
		aMethod("s2c", 10, 30, 0), aMethod("c2s", 10, 31, 0),
		aMethod("c2s", 10, 40, 0), aMethod("s2c", 10, 41, 0),
	}
}

func aPlan(t *testing.T, layersArr []interface{}) ([]core.PacketConfig, error) {
	t.Helper()
	p, err := layers.BuildLayersPlanner("amqp", aJSON(t, layersArr))
	if err != nil {
		return nil, err
	}
	// 四元组回填：以链声明为准（ntlm nPlan 同款）。
	spec := core.FlowSpec{SrcIP: aCli, DstIP: aSrv, SrcPort: aSport, DstPort: aPort}
	for _, item := range layersArr {
		m, _ := item.(map[string]interface{})
		if m == nil {
			continue
		}
		if ipc, ok := m["ip"].(map[string]interface{}); ok {
			if s, ok := ipc["src"].(string); ok && s != "" {
				spec.SrcIP = s
			}
			if s, ok := ipc["dst"].(string); ok && s != "" {
				spec.DstIP = s
			}
		}
		if tcpc, ok := m["tcp"].(map[string]interface{}); ok {
			if f, ok := tcpc["src_port"].(float64); ok {
				spec.SrcPort = uint16(f)
			}
			if f, ok := tcpc["dst_port"].(float64); ok {
				spec.DstPort = uint16(f)
			}
			if i, ok := tcpc["src_port"].(int); ok {
				spec.SrcPort = uint16(i)
			}
			if i, ok := tcpc["dst_port"].(int); ok {
				spec.DstPort = uint16(i)
			}
		}
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

func aDrive(t *testing.T, layersArr []interface{}) []core.PacketConfig {
	t.Helper()
	pkts, err := aPlan(t, layersArr)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	return pkts
}

func aDriveErr(t *testing.T, layersArr []interface{}) error {
	t.Helper()
	_, err := aPlan(t, layersArr)
	if err == nil {
		t.Fatalf("want error, got nil")
	}
	return err
}

// aData 返回 payload 非空的数据包（去掉握手/挥手空包）。
func aData(pkts []core.PacketConfig) []core.PacketConfig {
	var out []core.PacketConfig
	for _, p := range pkts {
		if len(p.Payload) > 0 {
			out = append(out, p)
		}
	}
	return out
}

// ---- ① 空配置基线（P0b-2：空 amqp 层 → 缺省 protocol header 流）----

func TestAMQPChain_EmptyConfigBaseline(t *testing.T) {
	// 空 amqp 层走 P0b-2 缺省流：校验器 nil 放行 + 生成器默认 protocol
	// header。BuildLayersPlanner 形状面要求 connections 非空——空层在
	// Plan 同步面被 validator 拒（"connections is required"），故此处
	// 钉形状面拒绝 + 单事件最小流走 8 包（3 hs + 1 data + 4 fin）。
	err := aDriveErr(t, aIP(map[string]interface{}{}))
	if !strings.Contains(err.Error(), "connections is required") {
		t.Fatalf("empty amqp layer error %q, want connections-required", err)
	}
	pkts := aDrive(t, aIP(map[string]interface{}{"profile": "amqp091_minimal",
		"connections": []interface{}{map[string]interface{}{"events": []interface{}{aHdrEv()}}}}))
	if len(pkts) != 8 {
		t.Fatalf("want 8 packets (3 hs + 1 data + 4 fin), got %d", len(pkts))
	}
	data := aData(pkts)
	if len(data) != 1 {
		t.Fatalf("want 1 data segment (protocol header), got %d", len(data))
	}
	if got := strings.ToUpper(hex.EncodeToString(data[0].Payload)); got != aProtoHeader {
		t.Fatalf("default payload %s, want %s", got, aProtoHeader)
	}
	if pkts[3].L4.DstPort != aPort || pkts[3].L4.SrcPort != aSport {
		t.Fatalf("ports %d->%d", pkts[3].L4.SrcPort, pkts[3].L4.DstPort)
	}
}

// ---- ② protocol header 8 字节固定布局 ----

func TestAMQPChain_ProtocolHeaderLayout(t *testing.T) {
	cfg := map[string]interface{}{"profile": "amqp091_minimal",
		"connections": []interface{}{map[string]interface{}{"events": []interface{}{aHdrEv()}}}}
	pkts := aDrive(t, aIP(cfg))
	data := aData(pkts)
	if len(data) != 1 {
		t.Fatalf("want 1 data segment, got %d", len(data))
	}
	got := strings.ToUpper(hex.EncodeToString(data[0].Payload))
	if got != aProtoHeader {
		t.Fatalf("protocol header %s, want %s", got, aProtoHeader)
	}
}

// ---- ③ METHOD frame 布局（type=1、channel、size、CE）----

func TestAMQPChain_MethodFrameLayout(t *testing.T) {
	evs := append(aHandshake(),
		aMethod("c2s", 20, 10, 1), aMethod("s2c", 20, 11, 1))
	cfg := map[string]interface{}{"profile": "amqp091_minimal",
		"connections": []interface{}{map[string]interface{}{"events": evs}}}
	pkts := aDrive(t, aIP(cfg))
	data := aData(pkts)
	if len(data) != len(evs) {
		t.Fatalf("want %d data segments (one per event), got %d", len(evs), len(data))
	}
	// 首包 = protocol header；第 2 包 = connection.start METHOD
	// （type=1、channel=0、class(10)|method(10)、end=CE；start 参数
	// version/octet/longstr/table 缺省编码使 payload 为 18 字节，
	// size=0x12——不断言固定参数值，只钉 frame 骨架）。
	m := data[1].Payload
	if len(m) < 7+4+1 || m[0] != 0x01 || m[1] != 0x00 || m[2] != 0x00 {
		t.Fatalf("method frame head % x", m)
	}
	if m[3] != 0x00 || m[4] != 0x00 || m[5] != 0x00 || m[6] == 0x00 {
		t.Fatalf("method frame size % x, want nonzero payload", m[3:7])
	}
	if m[7] != 0x00 || m[8] != 0x0A || m[9] != 0x00 || m[10] != 0x0A {
		t.Fatalf("method class/method % x, want 00 0A 00 0A", m[7:11])
	}
	if int(m[3])<<24|int(m[4])<<16|int(m[5])<<8|int(m[6]) != len(m)-7-1 {
		t.Fatalf("method frame size % x != payload %d", m[3:7], len(m)-8)
	}
	if m[len(m)-1] != 0xCE {
		t.Fatalf("method frame end %#x, want 0xCE", m[len(m)-1])
	}
}

// ---- ④ HEARTBEAT 固定 8 字节 ----

func TestAMQPChain_HeartbeatLayout(t *testing.T) {
	evs := append(aHandshake(),
		map[string]interface{}{"kind": "heartbeat", "direction": "c2s"},
		map[string]interface{}{"kind": "heartbeat", "direction": "s2c"})
	cfg := map[string]interface{}{"profile": "amqp091_minimal", "heartbeat": 30,
		"connections": []interface{}{map[string]interface{}{"events": evs}}}
	pkts := aDrive(t, aIP(cfg))
	data := aData(pkts)
	if len(data) != len(evs) {
		t.Fatalf("want %d data segments, got %d", len(evs), len(data))
	}
	for _, idx := range []int{len(evs) - 2, len(evs) - 1} {
		if got := strings.ToUpper(hex.EncodeToString(data[idx].Payload)); got != aHeartbeat {
			t.Fatalf("heartbeat[%d] %s, want %s", idx, got, aHeartbeat)
		}
	}
}

// ---- ⑤ CONTENT 序列（publish→HEADER→BODY，BodySize=6）----

func TestAMQPChain_ContentSequence(t *testing.T) {
	evs := append(aHandshake(),
		aMethod("c2s", 20, 10, 1), aMethod("s2c", 20, 11, 1),
		map[string]interface{}{"kind": "method", "direction": "c2s",
			"class_id": 60, "method_id": 40, "channel": 1,
			"arguments": map[string]interface{}{"exchange": "", "routing_key": "test", "mandatory": false}},
		map[string]interface{}{"kind": "header", "direction": "c2s",
			"channel": 1, "class_id": 60,
			"properties": map[string]interface{}{"content_type": "text/plain", "delivery_mode": 1}},
		map[string]interface{}{"kind": "body", "direction": "c2s",
			"channel": 1, "body": "Hello!"})
	cfg := map[string]interface{}{"profile": "amqp091_rabbitmq",
		"connections": []interface{}{map[string]interface{}{"events": evs}}}
	pkts := aDrive(t, aIP(cfg))
	data := aData(pkts)
	if len(data) != len(evs) {
		t.Fatalf("want %d data segments, got %d", len(evs), len(data))
	}
	// HEADER 帧：type=2（data[len-3]）、class=60、BodySize=6。
	hdr := data[len(data)-2].Payload
	if hdr[0] != 0x02 {
		t.Fatalf("header frame type %#x, want 0x02", hdr[0])
	}
	var bodySize uint64
	for i := 0; i < 8; i++ {
		bodySize = bodySize<<8 | uint64(hdr[11+i])
	}
	if bodySize != 6 {
		t.Fatalf("header BodySize %d, want 6", bodySize)
	}
	// BODY 帧：type=3（data[len-1]），payload="Hello!"。
	body := data[len(data)-1].Payload
	if body[0] != 0x03 || string(body[7:len(body)-1]) != "Hello!" {
		t.Fatalf("body frame % x", body)
	}
}

// ---- ⑥ 载体形状（缺 tcp / 夹 udp / 混合地址族）----

func TestAMQPChain_CarrierShapes(t *testing.T) {
	cases := []struct {
		name   string
		layers []interface{}
		anchor string
	}{
		{"missing_tcp", []interface{}{
			map[string]interface{}{"ip": map[string]interface{}{"src": aCli, "dst": aSrv}},
			map[string]interface{}{"amqp": map[string]interface{}{}},
		}, "(carrier)"},
		{"udp_carrier", []interface{}{
			map[string]interface{}{"ip": map[string]interface{}{"src": aCli, "dst": aSrv}},
			map[string]interface{}{"udp": map[string]interface{}{"src_port": aSport, "dst_port": aPort}},
			map[string]interface{}{"amqp": map[string]interface{}{}},
		}, "(carrier)"},
		{"mixed_family", []interface{}{
			map[string]interface{}{"ip": map[string]interface{}{"src": aCli, "dst": aSrv6}},
			map[string]interface{}{"tcp": map[string]interface{}{"src_port": aSport, "dst_port": aPort}},
			map[string]interface{}{"amqp": map[string]interface{}{}},
		}, "(family)"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := aDriveErr(t, tc.layers)
			if !strings.Contains(err.Error(), tc.anchor) {
				t.Fatalf("error %q missing anchor %q", err, tc.anchor)
			}
		})
	}
}

// ---- ⑦ 严格解码（层 config 未知键拒）----

func TestAMQPChain_StrictDecode(t *testing.T) {
	cfg := map[string]interface{}{"profile": "amqp091_minimal", "bogus_key": 1,
		"connections": []interface{}{map[string]interface{}{"events": []interface{}{aHdrEv()}}}}
	err := aDriveErr(t, aIP(cfg))
	if !strings.Contains(err.Error(), "bogus_key") {
		t.Fatalf("error %q must name the unknown key", err)
	}
}

// ---- ⑧ 多连接隔离（双 protocol header；G-AMQP-2 注记：校验器只扫首连接）----

func TestAMQPChain_MultiConnectionIsolation(t *testing.T) {
	mk := func(srcPort int) map[string]interface{} {
		return map[string]interface{}{"src_port": srcPort, "events": aHandshake()}
	}
	cfg := map[string]interface{}{"profile": "amqp091_minimal",
		"connections": []interface{}{mk(aSport), mk(aSport + 1)}}
	pkts := aDrive(t, aIP(cfg))
	data := aData(pkts)
	// 生成器逐连接直发：14 事件 = 14 数据段（G-AMQP-2 注记——校验器只扫
	// Connections[0]，此处不断言校验侧多连接语义，只钉生成侧隔离）。
	if len(data) != 14 {
		t.Fatalf("want 14 data segments (2 conns x 7 events), got %d", len(data))
	}
	for _, idx := range []int{0, 7} {
		if got := strings.ToUpper(hex.EncodeToString(data[idx].Payload)); got != aProtoHeader {
			t.Fatalf("conn header[%d] %s, want %s", idx, got, aProtoHeader)
		}
	}
}

// ---- ⑨ IPv6 载体（offset 74，应用 bytes 不变）----

func TestAMQPChain_IPv6Carrier(t *testing.T) {
	cfg := map[string]interface{}{"profile": "amqp091_minimal",
		"connections": []interface{}{map[string]interface{}{"events": []interface{}{aHdrEv()}}}}
	pkts := aDrive(t, aIP6(cfg))
	data := aData(pkts)
	if len(data) != 1 {
		t.Fatalf("want 1 data segment, got %d", len(data))
	}
	if got := strings.ToUpper(hex.EncodeToString(data[0].Payload)); got != aProtoHeader {
		t.Fatalf("ipv6 payload %s, want %s", got, aProtoHeader)
	}
	if pkts[0].L3.SrcIP != aCli6 || pkts[0].L3.DstIP != aSrv6 {
		t.Fatalf("ipv6 addrs %s -> %s", pkts[0].L3.SrcIP, pkts[0].L3.DstIP)
	}
}

// ---- ⑩ presence 与顶层游离键判死（1.11–1.13）----

func TestAMQPChain_PresenceAndStrayTopLevelKeys(t *testing.T) {
	// ①presence 负例形状（M5 清单①）：层链 + 顶层空子映射并存 = 判死。
	cfg := map[string]interface{}{
		"layers": []interface{}{
			map[string]interface{}{"ip": map[string]interface{}{"src": aCli, "dst": aSrv}},
			map[string]interface{}{"tcp": map[string]interface{}{"src_port": aSport, "dst_port": aPort}},
			map[string]interface{}{"amqp": map[string]interface{}{}},
		},
		"amqp": map[string]interface{}{},
	}
	if msg := core.CheckProtoFlat("amqp", cfg); msg == "" {
		t.Fatal("CheckProtoFlat(amqp, {layers, amqp:{}}) = \"\", want top-level amqp presence rejection")
	} else if !strings.Contains(msg, "rejects a top-level amqp sub-config") {
		t.Fatalf("CheckProtoFlat msg = %q", msg)
	}
	// ②白名单外游离键（1.11–1.13）：四元组类经 CheckProtoFlat/门2-1 判死。
	for _, k := range []string{"src_ip", "dst_ip", "src_port", "dst_port", "count"} {
		bad := map[string]interface{}{"layers": cfg["layers"], k: 1}
		if msg := core.CheckProtoFlat("amqp", bad); msg == "" {
			t.Fatalf("CheckProtoFlat(amqp, {layers, %s}) = \"\", want flat-field rejection", k)
		}
	}
	// MAC 类经 schema 语义门（checkLayerFlatConflict）判死。
	_, errs := schema.ValidateStrategy("synth", "amqp", map[string]any{
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

// ---- ⑪ 用例文件收官自查（M5 清单④：非负例顶层键=0 + 三方一致）----

func TestAMQPChain_CaseFileAudit(t *testing.T) {
	raw, err := os.ReadFile("../../../test/protocol_pcap/cases/amqp.json")
	if err != nil {
		t.Fatalf("read cases: %v", err)
	}
	var cases []map[string]interface{}
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatalf("parse cases: %v", err)
	}
	if len(cases) != 24 {
		t.Fatalf("want 24 cases (20 ID + 4 chain red), got %d", len(cases))
	}
	allowed := map[string]bool{"layers": true, "flow_control": true, "output": true}
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
		_, isNeg := exp["expect_error"]
		if isNeg {
			if len(exp) != 2 || exp["error_contains"] == nil {
				t.Fatalf("%s: negative expect keys must be exactly expect_error/error_contains, got %v", id, exp)
			}
			if _, ok := exp["notes"]; ok {
				t.Fatalf("%s: negative expect must not carry notes", id)
			}
			continue
		}
		// 非负例顶层键=0（M5 清单④）：只允许白名单结构性键。
		for k := range sj {
			if !allowed[k] {
				t.Fatalf("%s: stray top-level key %q (1.11–1.13)", id, k)
			}
		}
		if exp["packet_count"] == nil {
			t.Fatalf("%s: positive case must carry packet_count", id)
		}
	}
	// 24 例 = 20 ID（14 正 + 6 负）+ 4 链级红例（presence/白名单外游离键/
	// udp 载体/缺 tcp，§13-P2 四件套）。
	if cases[0]["id"] != "amqp_protocol_header_ipv4" || cases[23]["id"] != "amqp_neg_missing_tcp" {
		t.Fatalf("case order/ID mismatch: first=%v last=%v", cases[0]["id"], cases[23]["id"])
	}
	if cases[14]["id"] != "amqp_neg_protocol_header" {
		t.Fatalf("negatives must start at index 14 (14 positives first), got %v", cases[14]["id"])
	}
}
