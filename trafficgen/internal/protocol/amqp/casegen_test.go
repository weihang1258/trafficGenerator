// Package amqp — casegen 一次性用例生成器（D-AMQP-1 P4）。
//
// 24 例（14 正 + 6 负 + 4 链级红例），按用例文档 §2 权威序 + 契约 §13-P2
// 四件套。正例帧断言取自全链真实回放（BuildLayersPlanner→Plan，与套件
// 同路径——单权威，无重复编码）：frames 只钉 protocol header / heartbeat
// 等可复算前缀（testcase §1）；fields 逐包断言取自旧 JSON（先跑后钉在
// P5 lane suite 落盘 pcap + tshark 双通道校准，包号以实测为准）。
//
// TCP 算术（实测）：3 握手 + N 数据段（每事件一段；body 分段按 splitBody
// 增段）+ 4 挥手。单事件 header-only → 8；7 事件握手 → 14；publish 12
// 事件 → 19；多连接 14 事件同流直发 → 21。
package amqp

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
)

type afld struct {
	Packet   int
	Field    string
	Value    string
	Same     int
	Nonzero  bool
	Distinct []string
	Exclude  []string
}

func (f afld) m() map[string]interface{} {
	m := map[string]interface{}{"packet": f.Packet, "field": f.Field}
	if f.Value != "" {
		m["value"] = f.Value
	}
	if f.Same > 0 {
		m["same_as_packet"] = f.Same
	}
	if f.Nonzero {
		m["nonzero"] = true
	}
	if len(f.Distinct) > 0 {
		m["distinct_values"] = f.Distinct
	}
	if len(f.Exclude) > 0 {
		m["distinct_exclude"] = f.Exclude
	}
	return m
}

type afr struct {
	Packet int
	Offset int
	Hex    string
}

func (f afr) m() map[string]interface{} {
	m := map[string]interface{}{"packet": f.Packet, "hex": f.Hex}
	if f.Offset != 0 {
		m["offset"] = f.Offset
	}
	return m
}

type aposCase struct {
	id      string
	summary string
	layers  []interface{}
	count   int
	fields  []afld
	frames  []afr
	notes   []string
}

type anegCase struct {
	id      string
	summary string
	layers  []interface{}
	anchor  string
	notes   []string
	// extra 顶层附加键（presence/游离键红例：与 layers 并存的判死形状；
	// smtp/fins 同构——spec_json 顶层必须真实携带该键，suite 才能走到拒绝路径）。
	extra map[string]interface{}
}

const (
	aCli   = "10.0.0.1"
	aSrv   = "20.0.0.1"
	aCli6  = "2001:db8::1"
	aSrv6  = "2001:db8::2"
	aSprt  = 12345
	aSprt2 = 12346
	aPort  = 5672
)

func aipL(src, dst string) map[string]interface{} {
	return map[string]interface{}{"ip": map[string]interface{}{"src": src, "dst": dst}}
}
func atcpL(sp, dp int) map[string]interface{} {
	return map[string]interface{}{"tcp": map[string]interface{}{"src_port": sp, "dst_port": dp}}
}
func aamqpL(cfg map[string]interface{}) map[string]interface{} {
	return map[string]interface{}{"amqp": cfg}
}

// aChain 返回 [ip,tcp,amqp] 链（IPv4）。
func aChain(cfg map[string]interface{}) []interface{} {
	return []interface{}{aipL(aCli, aSrv), atcpL(aSprt, aPort), aamqpL(cfg)}
}

// aChain6 返回 IPv6 链（offset 74）。
func aChain6(cfg map[string]interface{}) []interface{} {
	return []interface{}{aipL(aCli6, aSrv6), atcpL(aSprt, aPort), aamqpL(cfg)}
}

func ahdrEv() map[string]interface{} {
	return map[string]interface{}{"kind": "protocol_header", "direction": "c2s"}
}
func amethod(dir string, class, method, ch int, extra map[string]interface{}) map[string]interface{} {
	m := map[string]interface{}{"kind": "method", "direction": dir,
		"class_id": class, "method_id": method, "channel": ch}
	for k, v := range extra {
		m[k] = v
	}
	return m
}

// aHandshakeEvents 返回六步 connection 握手事件（不含 protocol header）。
func aHandshakeEvents() []interface{} {
	return []interface{}{
		amethod("s2c", 10, 10, 0, nil), amethod("c2s", 10, 11, 0, nil),
		amethod("s2c", 10, 30, 0, nil), amethod("c2s", 10, 31, 0, nil),
		amethod("c2s", 10, 40, 0, nil), amethod("s2c", 10, 41, 0, nil),
	}
}

// aFullHandshake 返回 protocol header + 六步握手完整事件序。
func aFullHandshake() []interface{} {
	return append([]interface{}{ahdrEv()}, aHandshakeEvents()...)
}

func aWithChannelOpen(evs []interface{}, ch int) []interface{} {
	return append(evs,
		amethod("c2s", 20, 10, ch, nil), amethod("s2c", 20, 11, ch, nil))
}

// planAChain 全链回放（与套件同路径）。
func planAChain(t *testing.T, layersArr []interface{}) []core.PacketConfig {
	t.Helper()
	raw, err := json.Marshal(layersArr)
	if err != nil {
		t.Fatal(err)
	}
	p, err := layers.BuildLayersPlanner("amqp", raw)
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v", err)
	}
	spec := core.FlowSpec{SrcIP: aCli, DstIP: aSrv, SrcPort: aSprt, DstPort: aPort}
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
	}
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

// wholeFrame 钉某包整段 payload（offset 起）。
func wholeFrame(t *testing.T, pkts []core.PacketConfig, idx, base int) afr {
	t.Helper()
	if idx > len(pkts) {
		t.Fatalf("frame %d out of range (%d packets)", idx, len(pkts))
	}
	payload := pkts[idx-1].Payload
	if len(payload) == 0 {
		t.Fatalf("frame %d has empty payload", idx)
	}
	return afr{Packet: idx, Offset: base, Hex: strings.ToUpper(hex.EncodeToString(payload))}
}

// ============================================================
//  24 例生成（14 正 + 6 负 + 4 链级红例）
// ============================================================

func TestGenerateAMQPCases(t *testing.T) {
	var positives []aposCase
	var negatives []anegCase

	add := func(id, summary string, layersArr []interface{}, count int, fields []afld, frames []afr, notes ...string) {
		pkts := planAChain(t, layersArr)
		if len(pkts) != count {
			t.Fatalf("%s: rendered %d packets, pinned %d", id, len(pkts), count)
		}
		positives = append(positives, aposCase{id: id, summary: summary, layers: layersArr,
			count: count, fields: fields, frames: frames, notes: notes})
	}

	// ① amqp_protocol_header_ipv4（旧 min 4 → 实测 8）：1 事件。
	{
		cfg := map[string]interface{}{"profile": "amqp091_minimal",
			"connections": []interface{}{map[string]interface{}{"events": []interface{}{ahdrEv()}}}}
		pkts := planAChain(t, aChain(cfg))
		add("amqp_protocol_header_ipv4",
			"AMQP 0-9-1 8-byte protocol header over TCP/IPv4, port 5672",
			aChain(cfg), 8,
			[]afld{{4, "tcp.dstport", "5672", 0, false, nil, nil}},
			[]afr{wholeFrame(t, pkts, 4, 54)},
			"旧 min_packets=4（只数握手 3+1）；实测 8（3 握手 + 1 数据 + 4 挥手）")
	}

	// ② amqp_connection_handshake（旧 10 → 实测 14）：7 事件。
	{
		cfg := map[string]interface{}{"profile": "amqp091_minimal",
			"connections": []interface{}{map[string]interface{}{"events": aFullHandshake()}}}
		add("amqp_connection_handshake",
			"Full connection handshake: protocol header -> start/start-ok/tune/tune-ok/open/open-ok",
			aChain(cfg), 14,
			[]afld{
				{5, "amqp.method.class", "10", 0, false, nil, nil},
				{5, "amqp.method.method", "10", 0, false, nil, nil},
				{6, "amqp.method.class", "10", 0, false, nil, nil},
				{6, "amqp.method.method", "11", 0, false, nil, nil},
				{7, "amqp.method.class", "10", 0, false, nil, nil},
				{7, "amqp.method.method", "30", 0, false, nil, nil},
				{8, "amqp.method.class", "10", 0, false, nil, nil},
				{8, "amqp.method.method", "31", 0, false, nil, nil},
				{9, "amqp.method.class", "10", 0, false, nil, nil},
				{9, "amqp.method.method", "40", 0, false, nil, nil},
				{10, "amqp.method.class", "10", 0, false, nil, nil},
				{10, "amqp.method.method", "41", 0, false, nil, nil},
			},
			[]afr{{Packet: 4, Offset: 54, Hex: "41 4D 51 50 00 00 09 01"}},
			"旧 min_packets=10；实测 14（3+7+4）；packet 5-10 逐包不断言跨包合并")
	}

	// ③ amqp_channel_open_close（旧 16 → 实测 20）：13 事件。
	{
		evs := append(aFullHandshake(),
			amethod("c2s", 20, 10, 1, nil), amethod("s2c", 20, 11, 1, nil),
			amethod("c2s", 20, 40, 1, nil), amethod("s2c", 20, 41, 1, nil),
			amethod("c2s", 10, 50, 0, nil), amethod("s2c", 10, 51, 0, nil))
		cfg := map[string]interface{}{"profile": "amqp091_minimal",
			"connections": []interface{}{map[string]interface{}{"events": evs}}}
		add("amqp_channel_open_close",
			"channel 1 open/close 全序 + connection close",
			aChain(cfg), 20,
			[]afld{
				{11, "amqp.method.class", "20", 0, false, nil, nil},
				{11, "amqp.method.method", "10", 0, false, nil, nil},
				{11, "amqp.channel", "1", 0, false, nil, nil},
				{12, "amqp.method.class", "20", 0, false, nil, nil},
				{12, "amqp.method.method", "11", 0, false, nil, nil},
				{12, "amqp.channel", "1", 0, false, nil, nil},
				{15, "amqp.method.class", "10", 0, false, nil, nil},
				{15, "amqp.method.method", "50", 0, false, nil, nil},
				{16, "amqp.method.class", "10", 0, false, nil, nil},
				{16, "amqp.method.method", "51", 0, false, nil, nil},
			},
			[]afr{{Packet: 4, Offset: 54, Hex: "41 4D 51 50 00 00 09 01"}},
			"旧 min_packets=16；实测 20（3+13+4）")
	}

	// ④ amqp_heartbeat（旧 12 → 实测 16）：9 事件。
	{
		evs := append(aFullHandshake(),
			map[string]interface{}{"kind": "heartbeat", "direction": "c2s"},
			map[string]interface{}{"kind": "heartbeat", "direction": "s2c"})
		cfg := map[string]interface{}{"profile": "amqp091_minimal", "heartbeat": 30,
			"connections": []interface{}{map[string]interface{}{"events": evs}}}
		pkts := planAChain(t, aChain(cfg))
		add("amqp_heartbeat",
			"HEARTBEAT type 8/channel 0/size 0 双向双包",
			aChain(cfg), 16,
			[]afld{
				{11, "amqp.type", "8", 0, false, nil, nil},
				{11, "amqp.channel", "0", 0, false, nil, nil},
				{11, "amqp.length", "0", 0, false, nil, nil},
				{12, "amqp.type", "8", 0, false, nil, nil},
				{12, "amqp.channel", "0", 0, false, nil, nil},
				{12, "amqp.length", "0", 0, false, nil, nil},
			},
			[]afr{
				{Packet: 4, Offset: 54, Hex: "41 4D 51 50 00 00 09 01"},
				wholeFrame(t, pkts, 11, 54),
			},
			"旧 min_packets=12；实测 16（3+9+4）")
	}

	// ⑤ amqp_exchange_queue_declare（旧 16 → 实测 20）：13 事件。
	{
		evs := append(aWithChannelOpen(aFullHandshake(), 1),
			amethod("c2s", 40, 10, 1, map[string]interface{}{"arguments": map[string]interface{}{
				"exchange": "amq.direct", "type": "direct", "passive": false, "durable": false, "auto_delete": false}}),
			amethod("s2c", 40, 11, 1, nil),
			amethod("c2s", 50, 10, 1, map[string]interface{}{"arguments": map[string]interface{}{
				"queue": "q1", "durable": false, "exclusive": false, "auto_delete": false}}),
			amethod("s2c", 50, 11, 1, nil))
		cfg := map[string]interface{}{"profile": "amqp091_rabbitmq",
			"connections": []interface{}{map[string]interface{}{"events": evs}}}
		add("amqp_exchange_queue_declare",
			"exchange/queue declare 参数和响应",
			aChain(cfg), 20,
			[]afld{
				{13, "amqp.method.class", "40", 0, false, nil, nil},
				{13, "amqp.method.method", "10", 0, false, nil, nil},
				{13, "amqp.channel", "1", 0, false, nil, nil},
				{15, "amqp.method.class", "50", 0, false, nil, nil},
				{15, "amqp.method.method", "10", 0, false, nil, nil},
				{16, "amqp.method.class", "50", 0, false, nil, nil},
				{16, "amqp.method.method", "11", 0, false, nil, nil},
			},
			[]afr{{Packet: 4, Offset: 54, Hex: "41 4D 51 50 00 00 09 01"}},
			"旧 min_packets=16；实测 20（3+13+4）")
	}

	// ⑥ amqp_basic_publish（旧 15 → 实测 19）：12 事件。
	{
		evs := append(aWithChannelOpen(aFullHandshake(), 1),
			amethod("c2s", 60, 40, 1, map[string]interface{}{"arguments": map[string]interface{}{
				"exchange": "", "routing_key": "test", "mandatory": false}}),
			map[string]interface{}{"kind": "header", "direction": "c2s",
				"channel": 1, "class_id": 60,
				"properties": map[string]interface{}{"content_type": "text/plain", "delivery_mode": 1}},
			map[string]interface{}{"kind": "body", "direction": "c2s", "channel": 1, "body": "Hello!"})
		cfg := map[string]interface{}{"profile": "amqp091_rabbitmq",
			"connections": []interface{}{map[string]interface{}{"events": evs}}}
		add("amqp_basic_publish",
			"publish→HEADER→BODY、BodySize=6",
			aChain(cfg), 19,
			[]afld{
				{13, "amqp.method.class", "60", 0, false, nil, nil},
				{13, "amqp.method.method", "40", 0, false, nil, nil},
				{14, "amqp.type", "2", 0, false, nil, nil},
				{14, "amqp.header.class", "60", 0, false, nil, nil},
				{14, "amqp.header.body-size", "6", 0, false, nil, nil},
				{15, "amqp.type", "3", 0, false, nil, nil},
				{15, "amqp.channel", "1", 0, false, nil, nil},
			},
			[]afr{{Packet: 4, Offset: 54, Hex: "41 4D 51 50 00 00 09 01"}},
			"旧 min_packets=15；实测 19（3+12+4）；BodySize 由生成器自动累加")
	}

	// ⑦ amqp_basic_body_segmentation（旧 16 → 实测 20）：12 事件 + 200B
	// body 按 frame_max=128 拆 2 BODY 段 → 13 数据段。
	{
		body200 := strings.Repeat("X", 200)
		evs := append(aWithChannelOpen(aFullHandshake(), 1),
			amethod("c2s", 60, 40, 1, map[string]interface{}{"arguments": map[string]interface{}{
				"exchange": "", "routing_key": "seg"}}),
			map[string]interface{}{"kind": "header", "direction": "c2s",
				"channel": 1, "class_id": 60,
				"properties": map[string]interface{}{"content_type": "application/octet-stream"}},
			map[string]interface{}{"kind": "body", "direction": "c2s", "channel": 1, "body": body200})
		cfg := map[string]interface{}{"profile": "amqp091_rabbitmq", "frame_max": 128,
			"connections": []interface{}{map[string]interface{}{"events": evs}}}
		add("amqp_basic_body_segmentation",
			"200B body frame_max=128 多 BODY 拆分",
			aChain(cfg), 20,
			[]afld{
				{14, "amqp.header.body-size", "200", 0, false, nil, nil},
				{15, "amqp.type", "3", 0, false, nil, nil},
				{16, "amqp.type", "3", 0, false, nil, nil},
			},
			[]afr{{Packet: 4, Offset: 54, Hex: "41 4D 51 50 00 00 09 01"}},
			"旧 min_packets=16；实测 20（3+13+4，body 拆 2 段）；单帧线上长 7+Size+1≤frame_max")
	}

	// ⑧ amqp_basic_consume_deliver_ack（旧 18 → 实测 22）：15 事件。
	{
		evs := append(aWithChannelOpen(aFullHandshake(), 1),
			amethod("c2s", 60, 20, 1, map[string]interface{}{"arguments": map[string]interface{}{
				"queue": "q1", "consumer_tag": "ctag1"}}),
			amethod("s2c", 60, 21, 1, nil),
			amethod("s2c", 60, 60, 1, map[string]interface{}{"arguments": map[string]interface{}{
				"consumer_tag": "ctag1", "delivery_tag": 1, "redelivered": false, "exchange": "", "routing_key": "test"}}),
			map[string]interface{}{"kind": "header", "direction": "s2c",
				"channel": 1, "class_id": 60,
				"properties": map[string]interface{}{"content_type": "text/plain"}},
			map[string]interface{}{"kind": "body", "direction": "s2c", "channel": 1, "body": "data"},
			amethod("c2s", 60, 80, 1, map[string]interface{}{"arguments": map[string]interface{}{
				"delivery_tag": 1, "multiple": false}}))
		cfg := map[string]interface{}{"profile": "amqp091_rabbitmq",
			"connections": []interface{}{map[string]interface{}{"events": evs}}}
		add("amqp_basic_consume_deliver_ack",
			"consume→deliver→HEADER→BODY→ack 关联",
			aChain(cfg), 22,
			[]afld{
				{15, "amqp.method.class", "60", 0, false, nil, nil},
				{15, "amqp.method.method", "60", 0, false, nil, nil},
				{18, "amqp.method.class", "60", 0, false, nil, nil},
				{18, "amqp.method.method", "80", 0, false, nil, nil},
			},
			[]afr{{Packet: 4, Offset: 54, Hex: "41 4D 51 50 00 00 09 01"}},
			"旧 min_packets=18；实测 22（3+15+4）；同 channel 同 tag 关联")
	}

	// ⑨ amqp_basic_get_empty（旧 14 → 实测 18）：11 事件。
	{
		evs := append(aWithChannelOpen(aFullHandshake(), 1),
			amethod("c2s", 60, 70, 1, map[string]interface{}{"arguments": map[string]interface{}{"queue": "q1"}}),
			amethod("s2c", 60, 72, 1, nil))
		cfg := map[string]interface{}{"profile": "amqp091_rabbitmq",
			"connections": []interface{}{map[string]interface{}{"events": evs}}}
		add("amqp_basic_get_empty",
			"basic.get(70) 与显式 get-empty(72)",
			aChain(cfg), 18,
			[]afld{
				{13, "amqp.method.class", "60", 0, false, nil, nil},
				{13, "amqp.method.method", "70", 0, false, nil, nil},
				{14, "amqp.method.class", "60", 0, false, nil, nil},
				{14, "amqp.method.method", "72", 0, false, nil, nil},
			},
			[]afr{{Packet: 4, Offset: 54, Hex: "41 4D 51 50 00 00 09 01"}},
			"旧 min_packets=14；实测 18（3+11+4）；不自动生成 HEADER/BODY")
	}

	// ⑩ amqp_confirm_transaction（旧 18 → 实测 22）：15 事件（tx 六方法）。
	{
		evs := append(aWithChannelOpen(aFullHandshake(), 1),
			amethod("c2s", 90, 10, 1, nil), amethod("s2c", 90, 11, 1, nil),
			amethod("c2s", 90, 20, 1, nil), amethod("s2c", 90, 21, 1, nil),
			amethod("c2s", 90, 30, 1, nil), amethod("s2c", 90, 31, 1, nil))
		cfg := map[string]interface{}{"profile": "amqp091_rabbitmq",
			"connections": []interface{}{map[string]interface{}{"events": evs}}}
		add("amqp_confirm_transaction",
			"tx.select/commit/rollback 六方法（class 90）",
			aChain(cfg), 22,
			[]afld{
				{13, "amqp.method.class", "90", 0, false, nil, nil},
				{13, "amqp.method.method", "10", 0, false, nil, nil},
				{15, "amqp.method.class", "90", 0, false, nil, nil},
				{15, "amqp.method.method", "20", 0, false, nil, nil},
				{17, "amqp.method.class", "90", 0, false, nil, nil},
				{17, "amqp.method.method", "30", 0, false, nil, nil},
			},
			[]afr{{Packet: 4, Offset: 54, Hex: "41 4D 51 50 00 00 09 01"}},
			"旧 min_packets=18；实测 22（3+15+4）；confirm.select（85/10）→ A′ T-21")
	}

	// ⑪ amqp_keepalive_multi_channel（旧 17 → 实测 21）：14 事件。
	{
		evs := append(aFullHandshake(),
			amethod("c2s", 20, 10, 1, nil), amethod("s2c", 20, 11, 1, nil),
			amethod("c2s", 20, 10, 2, nil), amethod("s2c", 20, 11, 2, nil),
			map[string]interface{}{"kind": "heartbeat", "direction": "c2s"},
			amethod("c2s", 60, 40, 1, map[string]interface{}{"arguments": map[string]interface{}{
				"exchange": "", "routing_key": "k1"}}),
			amethod("c2s", 60, 40, 2, map[string]interface{}{"arguments": map[string]interface{}{
				"exchange": "", "routing_key": "k2"}}))
		cfg := map[string]interface{}{"profile": "amqp091_rabbitmq", "heartbeat": 30,
			"connections": []interface{}{map[string]interface{}{"events": evs}}}
		add("amqp_keepalive_multi_channel",
			"双 channel + heartbeat 隔离",
			aChain(cfg), 21,
			[]afld{
				{15, "amqp.type", "8", 0, false, nil, nil},
				{16, "amqp.method.class", "60", 0, false, nil, nil},
				{16, "amqp.channel", "1", 0, false, nil, nil},
				{17, "amqp.method.class", "60", 0, false, nil, nil},
				{17, "amqp.channel", "2", 0, false, nil, nil},
			},
			[]afr{{Packet: 4, Offset: 54, Hex: "41 4D 51 50 00 00 09 01"}},
			"旧 min_packets=17；实测 21（3+14+4）")
	}

	// ⑫ amqp_multi_connection（旧 17 → 实测 21）：双连接各 7 事件同流直发。
	{
		mk := func(sp int) map[string]interface{} {
			return map[string]interface{}{"src_port": sp, "events": aFullHandshake()}
		}
		cfg := map[string]interface{}{"profile": "amqp091_minimal",
			"connections": []interface{}{mk(aSprt), mk(aSprt2)}}
		pkts := planAChain(t, aChain(cfg))
		add("amqp_multi_connection",
			"Two independent TCP connections with separate protocol header and handshake",
			aChain(cfg), 21,
			[]afld{
				{4, "tcp.dstport", "5672", 0, false, nil, nil},
			},
			[]afr{
				{Packet: 4, Offset: 54, Hex: "41 4D 51 50 00 00 09 01"},
				wholeFrame(t, pkts, 11, 54),
			},
			"旧 min_packets=17；实测 21（3+14+4，双连接同流直发）；G-AMQP-2 注记：校验器只扫首连接")
	}

	// ⑬ amqp_ipv6（旧 4 → 实测 8）：1 事件，offset 74。
	{
		cfg := map[string]interface{}{"profile": "amqp091_minimal",
			"connections": []interface{}{map[string]interface{}{"events": []interface{}{ahdrEv()}}}}
		add("amqp_ipv6",
			"AMQP 0-9-1 protocol header over TCP/IPv6, application bytes unchanged",
			aChain6(cfg), 8,
			[]afld{
				{4, "ipv6.nxt", "6", 0, false, nil, nil},
				{4, "tcp.dstport", "5672", 0, false, nil, nil},
			},
			[]afr{{Packet: 4, Offset: 74, Hex: "41 4D 51 50 00 00 09 01"}},
			"旧 min_packets=4；实测 8；应用 bytes 与 IPv4 一致")
	}

	// ⑭ amqp_frame_boundary（旧 16 → 实测 20）：13 事件。
	{
		evs := append(aWithChannelOpen(aFullHandshake(), 1),
			map[string]interface{}{"kind": "heartbeat", "direction": "c2s"},
			amethod("c2s", 60, 40, 1, map[string]interface{}{"arguments": map[string]interface{}{
				"exchange": "", "routing_key": "boundary"}}),
			map[string]interface{}{"kind": "header", "direction": "c2s",
				"channel": 1, "class_id": 60, "properties": map[string]interface{}{}},
			map[string]interface{}{"kind": "heartbeat", "direction": "s2c"})
		cfg := map[string]interface{}{"profile": "amqp091_minimal", "frame_max": 4096,
			"connections": []interface{}{map[string]interface{}{"events": evs}}}
		pkts := planAChain(t, aChain(cfg))
		add("amqp_frame_boundary",
			"frame_max=4096 + 空 properties header + heartbeat 混排",
			aChain(cfg), 20,
			[]afld{
				{13, "amqp.type", "8", 0, false, nil, nil},
				{13, "amqp.channel", "0", 0, false, nil, nil},
				{16, "amqp.type", "8", 0, false, nil, nil},
				{16, "amqp.channel", "0", 0, false, nil, nil},
			},
			[]afr{
				{Packet: 4, Offset: 54, Hex: "41 4D 51 50 00 00 09 01"},
				wholeFrame(t, pkts, 11, 54),
			},
			"旧 min_packets=16；实测 20（3+13+4）")
	}

	// ============================================================
	//  负例（6 例）+ 链级红例（4 例）
	// ============================================================

	addNeg := func(id, summary string, layersArr []interface{}, anchor string, notes ...string) {
		// 失败测试先行：负例形状必须在 Plan/Build 同步面被拒。
		p, err := layers.BuildLayersPlanner("amqp", mustJSON(t, layersArr))
		if err == nil {
			raw, _ := json.Marshal(layersArr)
			_ = raw
			spec := core.FlowSpec{SrcIP: aCli, DstIP: aSrv, SrcPort: aSprt, DstPort: aPort}
			if _, perr := p.Plan(context.Background(), spec); perr == nil {
				t.Fatalf("%s: negative shape accepted, want rejection with anchor %q", id, anchor)
			} else if !strings.Contains(perr.Error(), anchor) {
				t.Fatalf("%s: rejection %q missing anchor %q", id, perr, anchor)
			}
		} else if !strings.Contains(err.Error(), anchor) {
			t.Fatalf("%s: build rejection %q missing anchor %q", id, err, anchor)
		}
		negatives = append(negatives, anegCase{id: id, summary: summary, layers: layersArr, anchor: anchor, notes: notes})
	}

	// ⑮ protocol_version 注入（planner.go:435 `protocol version mismatch`）。
	addNeg("amqp_neg_protocol_header",
		"wire_fault protocol_version 注入",
		aChain(map[string]interface{}{"profile": "amqp091_minimal", "wire_fault": "protocol_version",
			"connections": []interface{}{map[string]interface{}{"events": []interface{}{ahdrEv()}}}}),
		"protocol")
	// ⑯ bad_frame_type 注入（planner.go:437 `bad frame type`）。
	addNeg("amqp_neg_frame_encoding",
		"wire_fault bad_frame_type 注入",
		aChain(map[string]interface{}{"profile": "amqp091_minimal", "wire_fault": "bad_frame_type",
			"connections": []interface{}{map[string]interface{}{"events": []interface{}{
				ahdrEv(),
				amethod("s2c", 10, 10, 0, nil), amethod("c2s", 10, 11, 0, nil)}}}}),
		"frame")
	// ⑰ handshake_state 注入（planner.go:443 `handshake state violation`）。
	addNeg("amqp_neg_handshake_state",
		"wire_fault handshake_state 注入 + open-before-tune-ok 事件序",
		aChain(map[string]interface{}{"profile": "amqp091_minimal", "wire_fault": "handshake_state",
			"connections": []interface{}{map[string]interface{}{"events": []interface{}{
				ahdrEv(), amethod("c2s", 10, 40, 0, nil)}}}}),
		"handshake")
	// ⑱ channel 自然守卫（planner.go:306 `unopened channel`）。
	neg18evs := append(aFullHandshake(), amethod("c2s", 60, 40, 0, nil))
	addNeg("amqp_neg_channel_state",
		"channel 0 上 basic.publish（自然守卫）",
		aChain(map[string]interface{}{"profile": "amqp091_minimal",
			"connections": []interface{}{map[string]interface{}{"events": neg18evs}}}),
		"channel")
	// ⑲ body 自然守卫（planner.go:425 `body size mismatch`）。
	neg19evs := append(aWithChannelOpen(aFullHandshake(), 1),
		amethod("c2s", 60, 40, 1, nil),
		map[string]interface{}{"kind": "header", "direction": "c2s",
			"channel": 1, "class_id": 60, "body_size_override": 100},
		map[string]interface{}{"kind": "body", "direction": "c2s", "channel": 1, "body": "short"})
	addNeg("amqp_neg_content_length",
		"body_size_override=100 vs body=5（自然守卫）",
		aChain(map[string]interface{}{"profile": "amqp091_minimal",
			"connections": []interface{}{map[string]interface{}{"events": neg19evs}}}),
		"body")
	// ⑳ session_reference 注入（planner.go:449 `session reference violation`）。
	addNeg("amqp_neg_session_reference",
		"wire_fault session_reference 注入",
		aChain(map[string]interface{}{"profile": "amqp091_minimal", "wire_fault": "session_reference",
			"connections": []interface{}{map[string]interface{}{"events": aFullHandshake()}}}),
		"session")
	// ㉑ presence 红例（M5 清单①）：层链 + 顶层空子映射并存 = 判死。
	// 顶层 amqp 空映射走 CheckProtoFlat presence 面（fins/smtp 同构）——
	// layers 数组本身保持合法三层，判死发生在策略 shape 门（400），此处
	// 先验 shape 门再落盘（BuildLayersPlanner 只见 layers 面）。
	pres21cfg := map[string]interface{}{"profile": "amqp091_minimal",
		"connections": []interface{}{map[string]interface{}{"events": []interface{}{ahdrEv()}}}}
	pres21shape := map[string]interface{}{"layers": aChain(pres21cfg),
		"amqp": map[string]interface{}{}}
	if _, errs := schema.ValidateStrategy("synth", "amqp", pres21shape, nil); len(errs) == 0 {
		t.Fatalf("amqp_neg_presence_top_submap: shape gate accepted, want presence rejection")
	} else {
		found := false
		for _, e := range errs {
			if strings.Contains(e.Error(), "presence") || strings.Contains(e.Error(), "top-level amqp") {
				found = true
			}
		}
		if !found {
			t.Fatalf("amqp_neg_presence_top_submap: shape errs %v missing presence anchor", errs)
		}
	}
	negatives = append(negatives, anegCase{id: "amqp_neg_presence_top_submap",
		summary: "层链+顶层空 amqp 子映射并存判死（presence 负例形状）",
		layers:  aChain(pres21cfg),
		anchor:  "no longer accepts a top-level amqp sub-config",
		extra:   map[string]interface{}{"amqp": map[string]interface{}{}}})
	// ㉒ 白名单外游离键红例（M5 清单②：1.11–1.13）。
	// 顶层 src_ip + layers 并存走 CheckProtoFlat 四元组面（fins/smtp 同构
	// presence 形）——shape 门 400，锚词 "no longer accepts ... src_ip"。
	stray22cfg := map[string]interface{}{"profile": "amqp091_minimal",
		"connections": []interface{}{map[string]interface{}{"events": []interface{}{ahdrEv()}}}}
	stray22shape := map[string]interface{}{"layers": aChain(stray22cfg), "src_ip": aCli}
	if _, errs := schema.ValidateStrategy("synth", "amqp", stray22shape, nil); len(errs) == 0 {
		t.Fatalf("amqp_neg_stray_top_key: shape gate accepted, want flat rejection")
	} else {
		found := false
		for _, e := range errs {
			if strings.Contains(e.Error(), "src_ip") {
				found = true
			}
		}
		if !found {
			t.Fatalf("amqp_neg_stray_top_key: shape errs %v missing src_ip anchor", errs)
		}
	}
	negatives = append(negatives, anegCase{id: "amqp_neg_stray_top_key",
		summary: "顶层游离键 src_ip 判死（白名单外）",
		layers:  aChain(stray22cfg),
		anchor:  "no longer accepts flat config field src_ip",
		extra:   map[string]interface{}{"src_ip": aCli}})
	// ㉓ udp 载体红例（M5 清单；carrier 锚词，§13-P2）。
	addNeg("amqp_neg_udp_carrier",
		"链中夹 udp 层判死（单 TCP 载体）",
		[]interface{}{aipL(aCli, aSrv),
			map[string]interface{}{"udp": map[string]interface{}{"src_port": aSprt, "dst_port": aPort}},
			aamqpL(map[string]interface{}{"profile": "amqp091_minimal",
				"connections": []interface{}{map[string]interface{}{"events": []interface{}{ahdrEv()}}}})},
		"carrier")
	// ㉔ 缺 tcp 红例（M5 清单；carrier 锚词，§13-P2）。
	addNeg("amqp_neg_missing_tcp",
		"链缺 tcp 直连判死（[ip,amqp]）",
		[]interface{}{aipL(aCli, aSrv),
			aamqpL(map[string]interface{}{"profile": "amqp091_minimal",
				"connections": []interface{}{map[string]interface{}{"events": []interface{}{ahdrEv()}}}})},
		"carrier")

	// ---- 写入（套件同构扁平数组：spec_json/expect）----
	type outCase struct {
		ID      string                 `json:"id"`
		Proto   string                 `json:"proto"`
		Summary string                 `json:"summary"`
		Spec    map[string]interface{} `json:"spec_json"`
		Expect  map[string]interface{} `json:"expect"`
	}
	var out []outCase
	for _, pc := range positives {
		fields := make([]interface{}, 0, len(pc.fields))
		for _, f := range pc.fields {
			fields = append(fields, f.m())
		}
		frames := make([]interface{}, 0, len(pc.frames))
		for _, f := range pc.frames {
			frames = append(frames, f.m())
		}
		expect := map[string]interface{}{
			"packet_count": pc.count,
			"fields":       fields,
			"frames":       frames,
		}
		if len(pc.notes) > 0 {
			expect["notes"] = pc.notes
		}
		out = append(out, outCase{ID: pc.id, Proto: "amqp", Summary: pc.summary,
			Spec: map[string]interface{}{"layers": pc.layers}, Expect: expect})
	}
	for _, nc := range negatives {
		expect := map[string]interface{}{
			"expect_error":   true,
			"error_contains": nc.anchor,
		}
		if len(nc.notes) > 0 {
			expect["notes"] = nc.notes
		}
		spec := map[string]interface{}{"layers": nc.layers}
		for k, v := range nc.extra {
			spec[k] = v
		}
		out = append(out, outCase{ID: nc.id, Proto: "amqp", Summary: nc.summary,
			Spec:   spec,
			Expect: expect})
	}
	if len(out) != 24 {
		t.Fatalf("want 24 cases, built %d", len(out))
	}
	if len(positives) != 14 || len(negatives) != 10 {
		t.Fatalf("want 14 positive + 10 negative, got %d + %d", len(positives), len(negatives))
	}
	b, err := json.MarshalIndent(out, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	path := "../../../test/protocol_pcap/cases/amqp.json"
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %d cases (%d pos + %d neg)", len(out), len(positives), len(negatives))
}

func mustJSON(t *testing.T, layersArr []interface{}) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(layersArr)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
