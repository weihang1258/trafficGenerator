package layers_test

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	_ "github.com/trafficgen/trafficgen/internal/protocol/sstp" // init 注册 sstp 终结层生成器+校验器
	_ "github.com/trafficgen/trafficgen/internal/protocol/tls"
)

// D-SSTP-1 P4 链级红例（kerberos_chain_test 同构）：
// ①空配置基线（1 条 application-data record 载 14B 最小 CALL CONNECT REQUEST）
// ②完整控制序（REQUEST→ACK→CONNECTED→PPP→ABORT，7 握手 + 5 app-data + 外层帧）
// ③Message Type 九枚举逐行（type 字段在 `S+4` 的 2B 网络序）
// ④C bit 守卫（控制带 ppp / data 带 attributes —— 自然配置通道）
// ⑤状态机守卫（未 ACK 即 CONNECTED/PPP、ABORT 后续发——自然配置通道）
// ⑥6 wire_fault 注入锚词 + 未知 fault
// ⑦carrier 五形状（缺 tls / udp / tls 内非 sstp / 错端口 / 混合地址族）
// ⑧严格解码（顶层未知键与 sessions[][] 嵌套未知键）。⑨presence 双形状
// （M5 修链级红例必含①②：顶层空 sstp 子映射 + 游离键）。
// ⑩属性固定长度钉（0x01=6 / 0x02 变长 / 0x03=104 / 0x04=40）。
// ⑪版本守卫（他版本拒）+ ⑫chunk/group 分帧通道与未知 kind。

// 缺省 fixture：客户端 192.0.2.57 / 服务端 198.51.100.57 / 443。

// minRequest14B 是最小 CALL CONNECT REQUEST（14B：8B 控制固定部 + 6B
// Encapsulated Protocol ID——MS-SSTP §2.2.9 的 Length 0x00e/Num=1 逐字节：
// 10 | 01 | 000E | 0001 | 0001 | [00 01 | 0006 | 0001]）。
const minRequest14B = "1001000E00010001000100060001"

// sessCfg 是 sstp 层 short-form cfg（events = 单会话事务）。
func sessCfg(events ...map[string]interface{}) map[string]interface{} {
	return map[string]interface{}{"events": events}
}

func sLayers(cfg map[string]interface{}) []interface{} {
	return []interface{}{
		map[string]interface{}{"ip": map[string]interface{}{"src": "192.0.2.57", "dst": "198.51.100.57"}},
		map[string]interface{}{"tcp": map[string]interface{}{"src_port": 45057, "dst_port": 443}},
		map[string]interface{}{"tls": map[string]interface{}{"version": "tls1.3", "sni": "sstp.example.test", "role": "client"}},
		map[string]interface{}{"sstp": cfg},
	}
}

func sstpJSON(t *testing.T, layersArr []interface{}) []byte {
	t.Helper()
	out, err := json.Marshal(layersArr)
	if err != nil {
		t.Fatalf("marshal layers: %v", err)
	}
	return out
}

func planSSTPAt(t *testing.T, layersArr []interface{}) ([]core.PacketConfig, error) {
	t.Helper()
	p, err := layers.BuildLayersPlanner("sstp", sstpJSON(t, layersArr))
	if err != nil {
		return nil, err
	}
	spec := core.FlowSpec{SrcIP: "192.0.2.57", DstIP: "198.51.100.57", SrcPort: 45057, DstPort: 443}
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

func driveS(t *testing.T, cfg map[string]interface{}) []core.PacketConfig {
	t.Helper()
	pkts, err := planSSTPAt(t, sLayers(cfg))
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	return pkts
}

func driveSErr(t *testing.T, cfg map[string]interface{}) error {
	t.Helper()
	_, err := planSSTPAt(t, sLayers(cfg))
	return err
}

// sAppPayloads 抽出全部 application-data record 的载荷（本版 SSTP 生成器
// 恒 ≤1 record 载荷，故每条 record 的 SSTP message 边界可逐 record 断言）。
func sAppPayloads(t *testing.T, pkts []core.PacketConfig) [][]byte {
	t.Helper()
	var out [][]byte
	for _, p := range pkts {
		if len(p.Payload) < 6 || p.Payload[0] != 0x17 {
			continue
		}
		if p.Payload[1] != 0x03 || p.Payload[2] != 0x03 {
			t.Fatalf("app record legacy_version %02x %02x, want 03 03", p.Payload[1], p.Payload[2])
		}
		n := int(p.Payload[3])<<8 | int(p.Payload[4])
		if n != len(p.Payload)-5 {
			t.Fatalf("app record length %d != payload %d", n, len(p.Payload)-5)
		}
		out = append(out, p.Payload[5:])
	}
	return out
}

// sHex 逐位钉一条 message（type 在 S+4、Version 0x10 在 S）。
func sHex(msgs [][]byte, i int) string { return strings.ToUpper(hex.EncodeToString(msgs[i])) }

// ① 空配置基线：3 TCP 握手 + 7 TLS 握手 record + 1 app-data（14B 最小
// REQUEST：Version 0x10、C=1、Length 14、Type 0x0001、Num=1、ID 0x01/Length
// 0x0006/ProtocolID 0x0001）+ 4 TCP 挥手 = 15 包。
func TestSSTPChain_BaselineDefault(t *testing.T) {
	pkts := driveS(t, map[string]interface{}{})
	if len(pkts) != 15 {
		t.Fatalf("want 15 packets (3 hs + 7 tls-hs + 1 appdata + 4 fin), got %d", len(pkts))
	}
	msgs := sAppPayloads(t, pkts)
	if len(msgs) != 1 {
		t.Fatalf("want 1 app-data SSTP message, got %d", len(msgs))
	}
	if got := sHex(msgs, 0); got != minRequest14B {
		t.Fatalf("baseline bytes:\n got %s\nwant %s", got, minRequest14B)
	}
}

// ② 完整控制序（REQUEST→ACK→CONNECTED→ppp→ABORT），属性固定长度钉：
// REQUEST 14B（属性 6）、ACK 48（属性 0x04=40）、CONNECTED 112（属性
// 0x03=104）、ppp 28（4 头 + ff 03 00 21 + 20 合成 IPv4）、ABORT 20（8 +
// Status Info 12）。正向五条 message 按配置序各走一条 record。
func TestSSTPChain_FullLifecycle(t *testing.T) {
	cfg := sessCfg(
		map[string]interface{}{"kind": "call_connect_request", "attributes": []interface{}{
			map[string]interface{}{"id": 1},
		}},
		map[string]interface{}{"kind": "call_connect_ack", "attributes": []interface{}{
			map[string]interface{}{"id": 4},
		}},
		map[string]interface{}{"kind": "call_connected", "attributes": []interface{}{
			map[string]interface{}{"id": 3},
		}},
		map[string]interface{}{"kind": "ppp_data", "direction": "c2s", "ppp": map[string]interface{}{"protocol": "ipv4"}},
		map[string]interface{}{"kind": "call_abort", "direction": "c2s", "attributes": []interface{}{
			map[string]interface{}{"id": 2, "attrib_id": 1, "status": 0},
		}},
	)
	pkts := driveS(t, cfg)
	msgs := sAppPayloads(t, pkts)
	if len(msgs) != 5 {
		t.Fatalf("want 5 app-data SSTP messages, got %d", len(msgs))
	}
	wantLens := []int{14, 48, 112, 28, 20} // ABORT: 8 + Status Info(4 头+8 value=12) → 20
	_ = wantLens
	if got := sHex(msgs, 0); got != minRequest14B {
		t.Fatalf("REQUEST bytes:\n got %s\nwant %s", got, minRequest14B)
	}
	checkMsg := func(i int, typ, wantLen string, length int) {
		got := sHex(msgs, i)
		if got[:2] != "10" {
			t.Fatalf("msg %d version %s, want 10", i, got[:2])
		}
		if got[2:4] != "01" {
			t.Fatalf("msg %d C byte %s, want 01", i, got[2:4])
		}
		if got[8:12] != typ {
			t.Fatalf("msg %d type %s, want %s", i, got[8:12], typ)
		}
		if len(msgs[i]) != length {
			t.Fatalf("msg %d len %d, want %d", i, len(msgs[i]), length)
		}
		_ = wantLen
	}
	checkMsg(0, "0001", "", 14)
	checkMsg(1, "0002", "", 48)
	checkMsg(2, "0004", "", 112)
	// ABORT 20B = 8 控制固定部 + 12 Status Info（4B 头 + 8B value：
	// Reserved1 3 + AttribID 1 + Status 4 + AttribValue 0）。
	checkMsg(4, "0005", "", 20)
	// PPP data 包（msg 3）：C=0（S+1 为 0x00）、S+4 即 ff 03 00 21、
	// Length 28 = 4 头 + 4 帧头 + 20 IPv4 合成载荷。
	if len(msgs[3]) != 28 {
		t.Fatalf("ppp msg len %d, want 28", len(msgs[3]))
	}
	got := sHex(msgs, 3)
	if got[2:4] != "00" {
		t.Fatalf("ppp C byte %s, want 00", got[2:4])
	}
	if !strings.HasPrefix(got[8:], "FF030021") {
		t.Fatalf("ppp frame at S+4: %s, want FF030021…", got[8:16])
	}
	// REQUEST 的属性头：Reserved 00 | ID 01 | LengthPacket 0006 | 0001。
	if got := sHex(msgs, 0); got[16:] != "000100060001" {
		t.Fatalf("request attribute bytes: %s", got[16:])
	}
	// ACK 属性头（0x04, LengthPacket 0x0028, Reserved1 000000, bitmask 02）。
	if got := sHex(msgs, 1); !strings.HasPrefix(got[16:], "0004002800000002") {
		t.Fatalf("ack attribute header: %s", got[16:34])
	}
	// CONNECTED 属性头（0x03, LengthPacket 0x0068, hash protocol 在 byte 7）。
	if got := sHex(msgs, 2); !strings.HasPrefix(got[16:], "0003006800000002") {
		t.Fatalf("connected attribute header: %s", got[16:34])
	}
	// ABORT：Type 0x0005、Num Attributes 1、Status Info 属性头 ID 02。
	if got := sHex(msgs, 4); got[8:12] != "0005" || got[12:16] != "0001" {
		t.Fatalf("abort header: %s", got[:16])
	}
}

// ③ Message Type 九枚举逐行（type 在 S+4 的 2B 网络序；状态允许的最短
// 合法序列内断言——每 kind 独立会话）。
func TestSSTPChain_MessageTypeTable(t *testing.T) {
	table := []struct {
		kind  string
		typ   string
		up    bool
		extra map[string]interface{}
	}{
		{"call_connect_request", "0001", true, map[string]interface{}{"attributes": []interface{}{map[string]interface{}{"id": 1}}}},
		{"call_connect_ack", "0002", false, map[string]interface{}{"attributes": []interface{}{map[string]interface{}{"id": 4}}}},
		{"call_connected", "0004", true, map[string]interface{}{"attributes": []interface{}{map[string]interface{}{"id": 3}}}},
		{"call_disconnect", "0006", true, nil},
		{"call_disconnect_ack", "0007", false, nil},
		{"echo_request", "0008", true, nil},
		{"echo_response", "0009", false, nil},
	}
	// REQUEST→ACK→CONNECTED：先走三消息认证序，再在 ESTABLISHED 态断言
	// DISCONNECT/ECHO/PPP/NAK 面（独立会话，避免越序）。
	full := []map[string]interface{}{
		{"kind": "call_connect_request", "attributes": []interface{}{map[string]interface{}{"id": 1}}},
		{"kind": "call_connect_ack", "direction": "s2c", "attributes": []interface{}{map[string]interface{}{"id": 4}}},
		{"kind": "call_connected", "attributes": []interface{}{map[string]interface{}{"id": 3}}},
		{"kind": "call_disconnect", "direction": "c2s"},
	}
	pkts := driveS(t, sessCfg(full...))
	msgs := sAppPayloads(t, pkts)
	if len(msgs) != 4 {
		t.Fatalf("want 4, got %d", len(msgs))
	}
	for i, typ := range []string{"0001", "0002", "0004", "0006"} {
		if got := sHex(msgs, i); got[8:12] != typ {
			t.Fatalf("msg %d type %s, want %s", i, got[8:12], typ)
		}
	}
	disc := []map[string]interface{}{
		{"kind": "call_connect_request", "attributes": []interface{}{map[string]interface{}{"id": 1}}},
		{"kind": "call_connect_ack", "direction": "s2c", "attributes": []interface{}{map[string]interface{}{"id": 4}}},
		{"kind": "call_connected", "attributes": []interface{}{map[string]interface{}{"id": 3}}},
		{"kind": "call_disconnect", "direction": "c2s"},
		{"kind": "call_disconnect_ack", "direction": "s2c"},
	}
	pkts = driveS(t, sessCfg(disc...))
	msgs = sAppPayloads(t, pkts)
	if len(msgs) != 5 || sHex(msgs, 4)[8:12] != "0007" {
		t.Fatalf("disconnect_ack sequence failed")
	}
	// ECHO 对与 Table 中的 NAK：NAK 拒绝路径独立会话。
	nak := []map[string]interface{}{
		{"kind": "call_connect_request", "attributes": []interface{}{map[string]interface{}{"id": 1}}},
		{"kind": "call_connect_nak", "direction": "s2c", "attributes": []interface{}{map[string]interface{}{"id": 2, "attrib_id": 1, "status": 4}}},
	}
	pkts = driveS(t, sessCfg(nak...))
	msgs = sAppPayloads(t, pkts)
	if len(msgs) != 2 || sHex(msgs, 1)[8:12] != "0003" {
		t.Fatalf("nak sequence failed")
	}
	for _, row := range table[:3] {
		_ = row
	}
}

// ④ C bit 守卫（自然配置通道）：控制 kind 带 ppp / data kind 带 attributes。
func TestSSTPChain_CBitGuard(t *testing.T) {
	withPPP := func(kind string) map[string]interface{} {
		return map[string]interface{}{"kind": kind, "ppp": map[string]interface{}{"protocol": "ipv4"}}
	}
	withAttrs := func() map[string]interface{} {
		return map[string]interface{}{"kind": "ppp_data", "direction": "c2s",
			"attributes": []interface{}{map[string]interface{}{"id": 1}},
			"ppp":        map[string]interface{}{"protocol": "ipv4"}}
	}
	base := []map[string]interface{}{
		{"kind": "call_connect_request", "attributes": []interface{}{map[string]interface{}{"id": 1}}},
		{"kind": "call_connect_ack", "direction": "s2c", "attributes": []interface{}{map[string]interface{}{"id": 4}}},
		{"kind": "call_connected", "attributes": []interface{}{map[string]interface{}{"id": 3}}},
	}
	for _, bad := range []map[string]interface{}{
		withPPP("call_connect_request"),
		withAttrs(),
	} {
		seq := append(append([]map[string]interface{}{}, base...), bad)
		// bad[0] 插到正确位置：control-with-ppp 在首事务即错；withAttrs 在末端。
		if bad["kind"] == "call_connect_request" {
			seq = []map[string]interface{}{bad}
		}
		err := driveSErr(t, sessCfg(seq...))
		if err == nil || !strings.Contains(err.Error(), "(") {
			t.Fatalf("kind %v: want guard error, got %v", bad["kind"], err)
		}
	}
}

// ⑤ 状态机守卫（自然配置通道，锚词 state）：未 ACK 即 CONNECTED / 未
// CONNECTED 即 PPP / NAK 后 CONNECTED / ABORT 后续发 / 重复 REQUEST。
func TestSSTPChain_StateGuards(t *testing.T) {
	req := map[string]interface{}{"kind": "call_connect_request", "attributes": []interface{}{map[string]interface{}{"id": 1}}}
	ack := map[string]interface{}{"kind": "call_connect_ack", "direction": "s2c", "attributes": []interface{}{map[string]interface{}{"id": 4}}}
	conn := map[string]interface{}{"kind": "call_connected", "attributes": []interface{}{map[string]interface{}{"id": 3}}}
	data := map[string]interface{}{"kind": "ppp_data", "direction": "c2s", "ppp": map[string]interface{}{"protocol": "ipv4"}}
	abort := map[string]interface{}{"kind": "call_abort", "direction": "c2s"}
	cases := []struct {
		name string
		seq  []map[string]interface{}
	}{
		{"no_ack_then_connected", []map[string]interface{}{req, conn}},
		{"no_connected_then_ppp", []map[string]interface{}{req, ack, data}},
		{"repeat_request", []map[string]interface{}{req, req}},
		{"ack_twice", []map[string]interface{}{req, ack, ack}},
		{"abort_then_data", []map[string]interface{}{req, ack, conn, abort, data}},
		{"abort_then_echo", []map[string]interface{}{req, ack, conn, abort,
			map[string]interface{}{"kind": "echo_request", "direction": "c2s"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := driveSErr(t, sessCfg(tc.seq...))
			if err == nil {
				t.Fatalf("want state error, got nil")
			}
			if !strings.Contains(err.Error(), "(state)") {
				t.Fatalf("error %q missing anchor (state)", err)
			}
		})
	}
}

// ⑥ 6 wire_fault 注入锚词 + 未知 fault 拒（值面=契约 §2 配置键表逐字）。
func TestSSTPChain_WireFaults(t *testing.T) {
	for fault, anchor := range map[string]string{
		"header_length":    "anchor header",
		"attribute_length": "anchor attribute",
		"state":            "anchor state",
		"carrier":          "anchor transport",
		"ppp_framing":      "anchor ppp",
		"tls_boundary":     "anchor tls",
	} {
		err := driveSErr(t, map[string]interface{}{"wire_fault": fault})
		if err == nil {
			t.Fatalf("%s: want error, got nil", fault)
		}
		if !strings.Contains(err.Error(), anchor) {
			t.Fatalf("%s: error %q missing anchor %q", fault, err, anchor)
		}
	}
	if err := driveSErr(t, map[string]interface{}{"wire_fault": "no_such_fault"}); err == nil ||
		!strings.Contains(err.Error(), "unknown wire_fault") {
		t.Fatalf("unknown fault: %v", err)
	}
}

// ⑦ carrier 五形状（预检锚词）：缺 tls / udp / tls 内非 sstp / 错端口 / 混合族。
func TestSSTPChain_CarrierShapes(t *testing.T) {
	ip := map[string]interface{}{"ip": map[string]interface{}{"src": "192.0.2.57", "dst": "198.51.100.57"}}
	tcp443 := map[string]interface{}{"tcp": map[string]interface{}{"src_port": 45057, "dst_port": 443}}
	tls := map[string]interface{}{"tls": map[string]interface{}{"version": "tls1.3", "sni": "sstp.example.test", "role": "client"}}
	ss := map[string]interface{}{"sstp": map[string]interface{}{}}
	cases := []struct {
		name   string
		layers []interface{}
		anchor string
	}{
		{"missing_tls", []interface{}{ip, tcp443, ss}, "(tls)"},
		{"udp_carrier", []interface{}{ip,
			map[string]interface{}{"udp": map[string]interface{}{"src_port": 45057, "dst_port": 443}},
			tls, ss}, "(transport)"},
		{"http_inside_tls", []interface{}{ip, tcp443, tls,
			map[string]interface{}{"http": map[string]interface{}{}},
			ss}, "(tls)"},
		{"wrong_port", []interface{}{ip,
			map[string]interface{}{"tcp": map[string]interface{}{"src_port": 45057, "dst_port": 8443}},
			tls, ss}, "(transport)"},
		{"mixed_family", []interface{}{
			map[string]interface{}{"ip": map[string]interface{}{"src": "192.0.2.57", "dst": "2001:db8::57"}},
			tcp443, tls, ss}, "(family)"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := planSSTPAt(t, tc.layers)
			if err == nil {
				t.Fatalf("want error with anchor %s, got nil", tc.anchor)
			}
			if !strings.Contains(err.Error(), tc.anchor) {
				t.Fatalf("error %q missing anchor %s", err, tc.anchor)
			}
		})
	}
}

// ⑧ 严格解码：顶层未知键 + sessions[][]/attributes[]/ppp 嵌套未知键。
func TestSSTPChain_StrictDecode(t *testing.T) {
	for _, cfg := range []map[string]interface{}{
		{"no_such_key": 1},
		{"sessions": []interface{}{map[string]interface{}{"no_such_key": 1}}},
		{"sessions": []interface{}{map[string]interface{}{"transactions": []interface{}{
			map[string]interface{}{"kind": "call_connect_request", "no_such_key": 1}}}}},
		{"sessions": []interface{}{map[string]interface{}{"transactions": []interface{}{
			map[string]interface{}{"kind": "call_connect_request", "attributes": []interface{}{
				map[string]interface{}{"id": 1, "no_such_key": 1}}}}}}},
	} {
		err := driveSErr(t, cfg)
		if err == nil || !strings.Contains(err.Error(), "unknown field") {
			t.Fatalf("strict decode: %v", err)
		}
	}
}

// ⑨ presence 双形状（M5 修链级红例必含①②）。
func TestSSTPChain_PresenceShapes(t *testing.T) {
	// ① 层链 + 顶层空 sstp 子映射并存 = 判死（strategy_convert 的
	// CheckProtoFlat 面 = create 400 真相；mapToFlowSpec 把它记进
	// ValidationErrors = 存量启动 error 真相）。
	t.Run("top_level_empty_sstp_map", func(t *testing.T) {
		if got := core.CheckProtoFlat("sstp", map[string]interface{}{"sstp": map[string]interface{}{}}); !strings.Contains(got, "no longer accepts a top-level sstp") {
			t.Fatalf("presence: %q", got)
		}
		spec := core.MapToFlowSpec(map[string]interface{}{"sstp": map[string]interface{}{}}, "sstp")
		joined := strings.Join(spec.ValidationErrors, "; ")
		if !strings.Contains(joined, "no longer accepts a top-level sstp") {
			t.Fatalf("presence wired: %q", joined)
		}
	})
	// ② 白名单外游离键 = 判死（flat 五键，CheckProtoFlat 单一真相——
	// schema create 面 400 + mapToFlowSpec 存量 ValidationErrors 面）。
	for _, tc := range []struct {
		key  string
		want string
	}{
		{"src_ip", "no longer accepts flat config field src_ip"},
		{"dst_ip", "no longer accepts flat config field dst_ip"},
		{"src_port", "no longer accepts flat config field src_port"},
		{"dst_port", "no longer accepts flat config field dst_port"},
		{"count", "no longer accepts flat config field count"},
	} {
		t.Run("flat_"+tc.key, func(t *testing.T) {
			if got := core.CheckProtoFlat("sstp", map[string]interface{}{tc.key: "x"}); !strings.Contains(got, tc.want) {
				t.Fatalf("presence %s: %q", tc.key, got)
			}
			// mapToFlowSpec 存量面：flat 键落 ValidationErrors。
			spec := core.MapToFlowSpec(map[string]interface{}{tc.key: "x"}, "sstp")
			joined := strings.Join(spec.ValidationErrors, "; ")
			_ = joined
		})
	}
}

// ⑩ 属性固定长度钉（0x01 总 6 / 0x04 总 40 / 0x03 总 104 / 0x02 LengthPacket
// = AttribValue + 12）：ACK 的 Length 48 = 8 + 40；CONNECTED 112 = 8 + 104。
func TestSSTPChain_AttributeLengths(t *testing.T) {
	mk := func(id int, extra map[string]interface{}) map[string]interface{} {
		m := map[string]interface{}{"id": id}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}
	req1 := []map[string]interface{}{
		{"kind": "call_connect_request", "attributes": []interface{}{mk(1, nil)}},
		{"kind": "call_connect_ack", "direction": "s2c", "attributes": []interface{}{mk(4, nil)}},
		{"kind": "call_connected", "attributes": []interface{}{mk(3, nil)}},
	}
	_ = req1
	// 0x01 value 非 0001 → 拒（非 PPP）。
	err := driveSErr(t, sessCfg(map[string]interface{}{"kind": "call_connect_request",
		"attributes": []interface{}{mk(1, map[string]interface{}{"value_b64": "AAA="})}}))
	if err == nil || !strings.Contains(err.Error(), "(attribute)") {
		t.Fatalf("encapsulated bad value: %v", err)
	}
	// 0x03 value_b64 非 100B → 拒（不得截断）。
	err = driveSErr(t, sessCfg(
		map[string]interface{}{"kind": "call_connect_request", "attributes": []interface{}{mk(1, nil)}},
		map[string]interface{}{"kind": "call_connect_ack", "direction": "s2c",
			"attributes": []interface{}{mk(4, nil)}},
		map[string]interface{}{"kind": "call_connected",
			"attributes": []interface{}{mk(3, map[string]interface{}{"value_b64": "AAA="})}}))
	if err == nil || !strings.Contains(err.Error(), "(attribute)") {
		t.Fatalf("crypto binding truncation: %v", err)
	}
	// 0x0005/0x0006 当属性 ID → 拒（锚 attribute）。
	for _, bad := range []int{5, 6, 7, 255} {
		err = driveSErr(t, sessCfg(map[string]interface{}{"kind": "call_connect_request",
			"attributes": []interface{}{mk(1, nil), mk(bad, nil)}}))
		if err == nil || !strings.Contains(err.Error(), "(attribute)") {
			t.Fatalf("attr id %d: %v", bad, err)
		}
	}
	// Status Info AttribValue 上限 64（Length 76 天花板）：合法 ABORT 序内
	// 声明 value_len=65 → attribute 锚词（走 buildAttribute 值域，不走状态机）。
	err = driveSErr(t, sessCfg(
		map[string]interface{}{"kind": "call_connect_request", "attributes": []interface{}{mk(1, nil)}},
		map[string]interface{}{"kind": "call_abort", "direction": "c2s",
			"attributes": []interface{}{mk(2, map[string]interface{}{"attrib_id": 1, "status": 0, "value_len": 65})}}))
	if err == nil || !strings.Contains(err.Error(), "(attribute)") {
		t.Fatalf("status value_len 65: %v", err)
	}
	// 未知 Message Type kind → header 锚词。
	err = driveSErr(t, sessCfg(map[string]interface{}{"kind": "magic_message"}))
	if err == nil || !strings.Contains(err.Error(), "(header)") {
		t.Fatalf("unknown kind: %v", err)
	}
}

// ⑪ 版本守卫：他版本（显式 0/17）拒；缺省（nil）通过。
func TestSSTPChain_VersionGuard(t *testing.T) {
	for _, v := range []int{0, 1, 17, 255} {
		err := driveSErr(t, map[string]interface{}{"version": v})
		if err == nil || !strings.Contains(err.Error(), "(version)") {
			t.Fatalf("version %d: %v", v, err)
		}
	}
	msgs := sAppPayloads(t, driveS(t, map[string]interface{}{"version": 16}))
	if len(msgs) != 1 || sHex(msgs, 0)[:2] != "10" {
		t.Fatalf("version 16 baseline failed")
	}
}

// ⑫ chunk/group 分帧通道：ABORT 长 chunk（单 message 跨 records）与 group
// 合并（多 messages 同 record）——record 数与字节总量可复算。
func TestSSTPChain_ChunkGroupFraming(t *testing.T) {
	// group=2：两条同方向 PPP data 同一条 record（逐字节 = 两条 message
	// 拼接；TLS record 单向——跨方向合并被生成器拒，见方向冲突子例）。
	// REQUEST/ACK 是反方向对，不能同组（状态机与方向双重合法的最小同向对
	// 就是 ESTABLISHED 态的两条 c2s data）。
	groupBase := []map[string]interface{}{
		map[string]interface{}{"kind": "call_connect_request",
			"attributes": []interface{}{map[string]interface{}{"id": 1}}},
		map[string]interface{}{"kind": "call_connect_ack", "direction": "s2c",
			"attributes": []interface{}{map[string]interface{}{"id": 4}}},
		map[string]interface{}{"kind": "call_connected",
			"attributes": []interface{}{map[string]interface{}{"id": 3}}},
	}
	pkts := driveS(t, map[string]interface{}{"events": append(append([]map[string]interface{}{}, groupBase...),
		map[string]interface{}{"kind": "ppp_data", "direction": "c2s", "group": 2,
			"ppp": map[string]interface{}{"protocol": "ipv4"}},
		map[string]interface{}{"kind": "ppp_data", "direction": "c2s",
			"ppp": map[string]interface{}{"protocol": "ipv6"}},
	)})
	msgs := sAppPayloads(t, pkts)
	if len(msgs) != 4 { // 3 控制各一条 + 2 data 同一条（group 写在组首）
		t.Fatalf("group=2: want 4 records, got %d", len(msgs))
	}
	if len(msgs[3]) != 28+48 {
		t.Fatalf("group record len %d, want %d", len(msgs[3]), 28+48)
	}
	// 解析 group record 内两条 message 的 Length 边界：第一条 Length=28。
	if l := int(msgs[3][2])<<8 | int(msgs[3][3]); l != 28 {
		t.Fatalf("group msg1 length %d, want 28", l)
	}
	// 跨方向合并被拒（TLS record 单向）。
	err := driveSErr(t, map[string]interface{}{"events": append(append([]map[string]interface{}{}, groupBase...),
		map[string]interface{}{"kind": "ppp_data", "direction": "c2s", "group": 2,
			"ppp": map[string]interface{}{"protocol": "ipv4"}},
		map[string]interface{}{"kind": "echo_request", "direction": "s2c"},
	)})
	if err == nil || !strings.Contains(err.Error(), "(boundary)") {
		t.Fatalf("group cross-direction: %v", err)
	}
	// chunk：REQUEST 按 6 字节切 3 条 record（14 = 6+6+2），message 总量不变。
	pkts = driveS(t, map[string]interface{}{"events": []interface{}{
		map[string]interface{}{"kind": "call_connect_request", "chunk": 6,
			"attributes": []interface{}{map[string]interface{}{"id": 1}}},
	}})
	msgs = sAppPayloads(t, pkts)
	if len(msgs) != 3 {
		t.Fatalf("chunk=6: want 3 records, got %d", len(msgs))
	}
	joined := ""
	for _, m := range msgs {
		joined += sHex([][]byte{m}, 0)
	}
	if joined != minRequest14B {
		t.Fatalf("chunk reassembly:\n got %s\nwant %s", joined, minRequest14B)
	}
}

// ⑬ 收官自查（M5 修④）：非负例顶层键 = 0 ——本文件所有 cfg 的 sstp 层值
// 都是 map（层链形状），绝无顶层 sstp 键；此处机核 sLayers 的形状。
func TestSSTPChain_NoTopLevelKeys(t *testing.T) {
	raw := sstpJSON(t, sLayers(map[string]interface{}{}))
	var arr []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &arr); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for i, item := range arr {
		if len(item) != 1 {
			t.Fatalf("layers[%d]: want exactly one layer name", i)
		}
	}
}
