package mqtt

// MQTT terminal-layer generator tests (P4a)。MQTTGenerator 复用 build* 纯
// 函数产事件——事件序列与 legacy Plan 的数据帧（flags=0x18 PSH-ACK，握手/
// 挥手过滤后）在方向/字节上逐帧一致（CONNECT → CONNACK → 订阅 → 消息 →
// ping → will → DISCONNECT，ConnectAckCode==0 门控）；链级测试通过
// ChainPlanner 驱动 [ip→tcp→mqtt] 完整链路验证握手→数据→挥手与 legacy
// 数据帧字节一致、seq 连续。默认化（Version=0→4、Disconnect=nil→true、
// 空 ClientID→自动生成+强制 CleanSession、PacketID 流内从 1 自动分配、
// 空 Subscriptions/Messages 跳过对应阶段）与 legacy Plan 对齐，测试覆盖
// 默认值与显式值两路径。

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// mustPlan runs the legacy planner and returns all PacketConfigs in order.
func mustPlan(t *testing.T, p *Planner, spec core.FlowSpec) []core.PacketConfig {
	t.Helper()
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan returned error: %v", err)
	}
	var out []core.PacketConfig
	for c := range ch {
		out = append(out, c)
	}
	return out
}

// tcpPackets returns the TCP packet configs in wire order.
func tcpPackets(cfgs []core.PacketConfig) []core.PacketConfig {
	var out []core.PacketConfig
	for _, c := range cfgs {
		if c.L4.Protocol == "tcp" {
			out = append(out, c)
		}
	}
	return out
}

// mqttSpec returns a base MQTT spec with a deterministic ISN (initialSeq=0 →
// 不设 spec.TCP，链上 tcp 层随机 ISN) 和一个覆盖订阅/消息/遗嘱/心跳/断开
// 的完整配置。值拷贝 cfg：事件生成与 legacy 对比各持独立实例。
func mqttSpec(initialSeq uint32) core.FlowSpec {
	cfg := &core.MQTTConfig{
		Version:  4,
		ClientID: "layer-gen-test",
		Subscriptions: []core.MQTTSubscribe{
			{PacketID: 0, Filters: []core.MQTTTopicFilter{{Filter: "sensor/#", QoS: 1}}},
		},
		Messages: []core.MQTTMessage{
			{Topic: "sensor/temp", Payload: "21.5", QoS: 1, PacketID: 0},
			{Topic: "sensor/hum", Payload: "60", QoS: 2, PacketID: 0},
			{Topic: "log/msg", Payload: "hi", QoS: 0, PacketID: 0},
		},
		Will:              &core.MQTTWill{Topic: "client/gone", Payload: "offline", QoS: 1},
		PingAfterMessages: true,
	}
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1",
		SrcPort: 36164, DstPort: 1883,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		MQTT: cfg,
	}
	if initialSeq != 0 {
		spec.TCP = &core.TCPConfig{InitialSeq: initialSeq}
	}
	return spec
}

// collectEvents drives MQTTGenerator.Generate and collects the emitted
// message events in order. 值拷贝 cfg：事件生成与 legacy 对比各持独立实例。
func collectEvents(t *testing.T, spec core.FlowSpec) []layers.MessageEvent {
	t.Helper()
	var events []layers.MessageEvent
	gen := &MQTTGenerator{}
	meta := layers.FlowMeta{
		SrcIP:   spec.SrcIP,
		DstIP:   spec.DstIP,
		SrcPort: spec.SrcPort,
		DstPort: spec.DstPort,
	}
	if spec.MQTT != nil {
		c2 := *spec.MQTT
		meta.MQTT = &c2
	}
	req := &layers.GenRequest{
		Meta: meta,
		EmitMsg: func(ev layers.MessageEvent) error {
			events = append(events, ev)
			return nil
		},
	}
	if err := gen.Generate(context.Background(), req); err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}
	return events
}

// legacyDataFrames runs the legacy planner and returns the MQTT data frames
// (skip TCP handshake/teardown)。数据帧 flags=0x18 PSH-ACK
// （emitSessionFlow emitData），与事件一一对应。
func legacyDataFrames(t *testing.T, spec core.FlowSpec) []core.PacketConfig {
	t.Helper()
	spec2 := spec
	if spec.MQTT != nil {
		c2 := *spec.MQTT
		spec2.MQTT = &c2
	}
	var out []core.PacketConfig
	for _, c := range tcpPackets(mustPlan(t, &Planner{}, spec2)) {
		if c.L4.Flags == 0x18 { // data frame
			out = append(out, c)
		}
	}
	return out
}

// maskAutoClientID masks the auto-generated ClientID bytes in a CONNECT
// payload。clientIDCounter 是包级原子计数器，事件生成与 legacy 对比各消耗
// 一个计数值（后缀不同）——空 ClientID 场景的字节对比须先掩码该字段
// （modbus SharedTIDSpace 同款先例：共享计数器的字段不做逐字节对比）。
// 非 CONNECT 包与显式 ClientID 场景不做掩码（保持严格字节对比）。
func maskAutoClientID(p []byte) []byte {
	out := append([]byte(nil), p...)
	if len(out) > 2 && out[0]&0xF0 == 0x10 && out[0]&0x0F == 0 { // CONNECT
		vbiLen := 1
		for i := 1; i < 5 && i < len(out); i++ {
			if out[i]&0x80 != 0 {
				vbiLen++
			} else {
				break
			}
		}
		// payload 起点 = 固定头(1+vbiLen) + 可变头(name len 2 + name 4 +
		// level 1 + flags 1 + keepalive 2 = 10)；ClientID 长度前缀紧随其后。
		off := 1 + vbiLen + 10
		if off+2 <= len(out) {
			l := int(out[off])<<8 | int(out[off+1])
			if off+2+l <= len(out) {
				for i := 0; i < l; i++ {
					out[off+2+i] = 0x20 // space
				}
			}
		}
	}
	return out
}

// assertEventsMatchLegacy 逐帧断言事件方向与字节与 legacy 数据帧一致。
// 空 ClientID 场景先掩码自动生成的 ClientID（共享计数器跨运行后缀不同），
// 其余字段（含 CONNECT flags 的强制 CleanSession 位）仍严格对比。
func assertEventsMatchLegacy(t *testing.T, spec core.FlowSpec, events []layers.MessageEvent) {
	t.Helper()
	legacy := legacyDataFrames(t, spec)
	if len(events) != len(legacy) {
		t.Fatalf("events = %d, legacy data frames = %d", len(events), len(legacy))
	}
	autoID := spec.MQTT != nil && spec.MQTT.ClientID == ""
	for i, ev := range events {
		pc := legacy[i]
		if (ev.Up && pc.Direction != "up") || (!ev.Up && pc.Direction != "down") {
			t.Errorf("event[%d] Up=%v, legacy Direction=%s", i, ev.Up, pc.Direction)
		}
		evBytes, legacyBytes := ev.Bytes, pc.Payload
		if autoID {
			evBytes = maskAutoClientID(evBytes)
			legacyBytes = maskAutoClientID(legacyBytes)
		}
		if !bytes.Equal(evBytes, legacyBytes) {
			t.Errorf("event[%d] payload = % X, legacy = % X", i, evBytes, legacyBytes)
		}
	}
}

// TestLayerGen_EventsMatchLegacyPlan 字节级对比：事件序列与 legacy 数据帧在
// 方向/payload 上逐帧一致。覆盖核心场景矩阵（默认化/多消息含 QoS0/1/2/
// 关键字段变体/负向字段）。
func TestLayerGen_EventsMatchLegacyPlan(t *testing.T) {
	cases := []struct {
		name string
		cfg  *core.MQTTConfig
	}{
		// 默认化路径：MQTTConfig{}（Version=0→4、Disconnect=nil→true、
		// 空 ClientID → 自动生成 + 强制 CleanSession、KeepAlive nil →
		// builder 默认 60、空 Subscriptions/Messages/Will → 跳过对应阶段）。
		{"default config (connect/connack/disconnect only)", &core.MQTTConfig{}},
		{"empty client id auto-generated", &core.MQTTConfig{
			Version: 4, ClientID: "",
			Messages: []core.MQTTMessage{{Topic: "t", Payload: "p", QoS: 0}},
		}},
		{"multi-message QoS 0/1/2 mixed", &core.MQTTConfig{
			Version:  4,
			ClientID: "c1",
			Messages: []core.MQTTMessage{
				{Topic: "t0", Payload: "a", QoS: 0},
				{Topic: "t1", Payload: "b", QoS: 1, PacketID: 100},
				{Topic: "t2", Payload: "c", QoS: 2, PacketID: 7},
			},
		}},
		{"down-direction publish", &core.MQTTConfig{
			Version:  4,
			ClientID: "c1",
			Messages: []core.MQTTMessage{
				{Topic: "t", Payload: "p", QoS: 1, PacketID: 5, Direction: "down"},
			},
		}},
		{"subscriptions multi-filter", &core.MQTTConfig{
			Version:  4,
			ClientID: "c1",
			Subscriptions: []core.MQTTSubscribe{
				{PacketID: 0, Filters: []core.MQTTTopicFilter{
					{Filter: "a/#", QoS: 2}, {Filter: "b/+", QoS: 0},
				}},
				{PacketID: 0, Filters: []core.MQTTTopicFilter{{Filter: "c", QoS: 1}}},
			},
		}},
		{"connect ack reject skips everything after connack", &core.MQTTConfig{
			Version: 4, ClientID: "bad", ConnectAckCode: 5,
			Subscriptions: []core.MQTTSubscribe{
				{PacketID: 0, Filters: []core.MQTTTopicFilter{{Filter: "s/#", QoS: 1}}},
			},
			Messages: []core.MQTTMessage{{Topic: "t", Payload: "p", QoS: 1}},
			Will:     &core.MQTTWill{Topic: "w", Payload: "gone", QoS: 0},
		}},
		{"no disconnect emits will publish", &core.MQTTConfig{
			Version:  4,
			ClientID: "c1",
			Disconnect: boolPtr(false),
			Will:       &core.MQTTWill{Topic: "client/gone", Payload: "offline", QoS: 1},
		}},
		{"will qos2", &core.MQTTConfig{
			Version:    4,
			ClientID:   "c1",
			Disconnect: boolPtr(false),
			Will:       &core.MQTTWill{Topic: "w", Payload: "p", QoS: 2},
		}},
		{"ping after messages", &core.MQTTConfig{
			Version:          4,
			ClientID:         "c1",
			PingAfterMessages: true,
		}},
		{"v5 disconnect reason", &core.MQTTConfig{
			Version:          5,
			ClientID:         "c1",
			DisconnectReason: intPtr(141), // 0x8D keep alive timeout
		}},
		{"v5 connect properties + connack properties", &core.MQTTConfig{
			Version:  5,
			ClientID: "c1",
			Properties: []core.MQTTProperty{
				{Identifier: 0x22, Format: "uint16", Value: "10"}, // Topic Alias Maximum
			},
			ConnackProperties: []core.MQTTProperty{
				{Identifier: 0x24, Format: "byte", Value: "1"}, // Maximum QoS
			},
		}},
		{"v5 message with properties", &core.MQTTConfig{
			Version:  5,
			ClientID: "c1",
			Messages: []core.MQTTMessage{
				{Topic: "t", Payload: "p", QoS: 1, PacketID: 3,
					Properties: []core.MQTTProperty{
						{Identifier: 0x26, Format: "stringpair", Value: "k\x00v"}, // User Property
					}},
			},
		}},
		{"explicit keepalive and clean_session false", &core.MQTTConfig{
			Version: 4, ClientID: "c1",
			KeepAlive:   intPtr(30),
			CleanSession: boolPtr(false),
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec := mqttSpec(0)
			c2 := *tc.cfg
			spec.MQTT = &c2
			events := collectEvents(t, spec)
			assertEventsMatchLegacy(t, spec, events)
		})
	}
}

// TestLayerGen_EventPacketTypes 独立校验事件序列形状（不依赖 legacy 对比）：
// 完整配置（订阅 + QoS0/1/2 消息 + ping + disconnect）下逐事件的 MQTT 包
// 类型字节（固定头高 4 位）与方向；PacketID 自动分配（subscriptions →
// messages → will 共享计数器，从 1 递增，QoS0 无 PacketID 不消耗）。
func TestLayerGen_EventPacketTypes(t *testing.T) {
	cfg := &core.MQTTConfig{
		Version:  4,
		ClientID: "shape-test",
		Subscriptions: []core.MQTTSubscribe{
			{PacketID: 0, Filters: []core.MQTTTopicFilter{{Filter: "s/#", QoS: 1}}},
		},
		Messages: []core.MQTTMessage{
			{Topic: "t1", Payload: "a", QoS: 0},
			{Topic: "t2", Payload: "b", QoS: 1},
		},
		PingAfterMessages: true,
	}
	spec := mqttSpec(0)
	c2 := *cfg
	spec.MQTT = &c2
	events := collectEvents(t, spec)
	// 期望形状：CONNECT(up) CONNACK(down) SUBSCRIBE(up) SUBACK(down)
	// PUBLISH0(up) PUBLISH1(up) PUBACK(down) PINGREQ(up) PINGRESP(down)
	// DISCONNECT(up)。
	want := []struct {
		up  bool
		typ byte
	}{
		{true, 0x10}, {false, 0x20}, // CONNECT / CONNACK
		{true, 0x80}, {false, 0x90}, // SUBSCRIBE / SUBACK
		{true, 0x30}, {true, 0x30}, {false, 0x40}, // PUBLISH0, PUBLISH1, PUBACK
		{true, 0xC0}, {false, 0xD0}, // PINGREQ / PINGRESP
		{true, 0xE0}, // DISCONNECT
	}
	if len(events) != len(want) {
		t.Fatalf("events = %d, want %d", len(events), len(want))
	}
	for i, w := range want {
		if events[i].Up != w.up {
			t.Errorf("event[%d] Up=%v, want %v", i, events[i].Up, w.up)
		}
		if got := events[i].Bytes[0] & 0xF0; got != w.typ {
			t.Errorf("event[%d] packet type = 0x%02x, want 0x%02x", i, got, w.typ)
		}
	}
	// PacketID 自动分配：SUBSCRIBE PacketID=1；PUBLISH1 (QoS1) PacketID=2；
	// QoS0 消息不消耗。SUBSCRIBE 帧 layout：固定头 2 + 可变头 PacketID 2 +
	// payload。
	if id := binary.BigEndian.Uint16(events[2].Bytes[2:4]); id != 1 {
		t.Errorf("SUBSCRIBE packet_id = %d, want 1 (auto from 1)", id)
	}
	// PUBLISH1 帧：固定头（2，QoS1 时含 2 字节 packetID 于可变头）。
	// PUBLISH QoS1 layout：固定头 + 主题长度 2 + 主题 + packetID 2 + payload；
	// 事件[4] = PUBLISH0（QoS0，无 packetID）；事件[5] = PUBLISH1（QoS1）。
	// 主题 "t1"（2 字节）→ packetID 偏移 = 2 + 2 + 2 = 6。
	p1 := events[5].Bytes
	off := 2 + 2 + 2 // fixed hdr + topic len + topic
	if p1[0]&0xF0 != 0x30 {
		t.Fatalf("event[5] is not a PUBLISH: 0x%02x", p1[0])
	}
	id := binary.BigEndian.Uint16(p1[off : off+2])
	if id != 2 {
		t.Errorf("PUBLISH1 packet_id = %d, want 2 (next after subscription)", id)
	}
	// PUBACK 携带同一 packetID（off 同 PUBLISH QoS1 的 packetID 位置）。
	puback := events[6].Bytes
	if len(puback) < 4 {
		t.Fatalf("PUBACK too short: % X", puback)
	}
	if id := binary.BigEndian.Uint16(puback[2:4]); id != 2 {
		t.Errorf("PUBACK packet_id = %d, want 2 (matches PUBLISH1)", id)
	}
}

// TestLayerGen_ChainPlannerBytes 链级字节验证：ChainPlanner 驱动
// [ip→tcp→mqtt] 完整链路，数据帧与 legacy 逐字节一致。挥手为 TCPGenerator
// 标准 4 包（FIN|ACK up → ACK down → FIN|ACK down → ACK up）——legacy
// mqtt.go 是 3 包挥手（FIN up → FIN down → ACK up，emitSessionFlow
// 1191-1203），层模型意图的文档化分歧（modbus/dnp3/doip 链测试同款断言
// 形状）。数据帧方向与 legacy 一致。
func TestLayerGen_ChainPlannerBytes(t *testing.T) {
	spec := mqttSpec(1000) // 确定性 ISN
	// 完整配置的包序列：握手 3 + 数据帧 14（CONNECT、CONNACK、SUBSCRIBE、
	// SUBACK、PUBLISH QoS1、PUBACK、PUBLISH QoS2、PUBREC、PUBREL、PUBCOMP、
	// PUBLISH QoS0、PINGREQ、PINGRESP、DISCONNECT）+ 挥手 4 = 21。
	planner := layers.NewChainPlannerFromChain("mqtt", []layers.Layer{
		{Name: "ip"},
		{Name: "tcp"},
		{Name: "mqtt"},
	})
	ch, err := planner.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("ChainPlanner Plan: %v", err)
	}
	var pkts []core.PacketConfig
	for p := range ch {
		pkts = append(pkts, p)
	}
	if len(pkts) != 21 {
		t.Fatalf("got %d packets, want 21 (handshake 3 + data 14 + teardown 4)", len(pkts))
	}
	// 握手：SYN(up) → SYN-ACK(down) → ACK(up)；数据 14 帧；挥手 4 包。
	wantFlags := []uint8{0x02, 0x12, 0x10,
		0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18,
		0x11, 0x10, 0x11, 0x10}
	wantDir := []string{"up", "down", "up",
		"up", "down", "up", "down", "up", "down", "up", "down", "up", "down", "up", "up", "down", "up",
		"up", "down", "down", "up"}
	for i, wf := range wantFlags {
		if pkts[i].L4.Flags != wf {
			t.Errorf("packet %d flags = 0x%02x, want 0x%02x", i, pkts[i].L4.Flags, wf)
		}
		if pkts[i].Direction != wantDir[i] {
			t.Errorf("packet %d direction = %s, want %s", i, pkts[i].Direction, wantDir[i])
		}
	}
	// 数据帧方向/字节与 legacy 逐帧一致（legacy 数据帧恒 0x18 PSH-ACK 且
	// 与事件一一对应——链上 tcp 层将事件直落数据段，帧形状等价；方向断言
	// 覆盖"交换方向/错位包序"的静默错误）。
	legacy := legacyDataFrames(t, spec)
	if len(legacy) != 14 {
		t.Fatalf("legacy data frames = %d, want 14", len(legacy))
	}
	for i, l := range legacy {
		seg := pkts[3+i]
		if !bytes.Equal(seg.Payload, l.Payload) {
			t.Errorf("data frame %d payload = % X, legacy = % X", i, seg.Payload, l.Payload)
		}
		if seg.Direction != l.Direction {
			t.Errorf("data frame %d direction = %s, legacy = %s", i, seg.Direction, l.Direction)
		}
	}
	// down 数据帧端口交换（legacy 同款：down 帧源端口 = DstPort 1883）。
	if pkts[4].L4.SrcPort != 1883 || pkts[4].L4.DstPort != 36164 {
		t.Errorf("down data frame ports = %d/%d, want 1883/36164", pkts[4].L4.SrcPort, pkts[4].L4.DstPort)
	}
	// 挥手 seq 连续性（seq 只按同侧负载推进——up 侧只累加 up 帧长度）：
	// FIN|ACK(up) pkts[17] 继承最后 up 数据帧（pkts[16] = DISCONNECT up）
	// 尾部 seq；FIN|ACK(down) pkts[19] 继承最后 down 数据帧（pkts[15] =
	// PINGRESP down）尾部 seq。
	if pkts[17].L4.Seq != pkts[16].L4.Seq+uint32(len(pkts[16].Payload)) {
		t.Errorf("FIN(up) seq = %d, want up data tail %d", pkts[17].L4.Seq, pkts[16].L4.Seq+uint32(len(pkts[16].Payload)))
	}
	if pkts[19].L4.Seq != pkts[15].L4.Seq+uint32(len(pkts[15].Payload)) {
		t.Errorf("FIN(down) seq = %d, want down data tail %d", pkts[19].L4.Seq, pkts[15].L4.Seq+uint32(len(pkts[15].Payload)))
	}
}

// TestLayerGen_ChainPlannerRejectSkipsData 链级 CONNACK 拒绝：ConnectAckCode
// != 0 → 数据帧只有 CONNECT + CONNACK（订阅/消息/ping/will/disconnect 全
// 跳过）——与 legacy 8 包（握手 3 + 2 + 挥手 3）等价；链上挥手 4 包 → 9。
func TestLayerGen_ChainPlannerRejectSkipsData(t *testing.T) {
	spec := mqttSpec(1000)
	spec.MQTT.ConnectAckCode = 5
	planner := layers.NewChainPlannerFromChain("mqtt", []layers.Layer{
		{Name: "ip"},
		{Name: "tcp"},
		{Name: "mqtt"},
	})
	ch, err := planner.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("ChainPlanner Plan: %v", err)
	}
	var pkts []core.PacketConfig
	for p := range ch {
		pkts = append(pkts, p)
	}
	// 9 = 握手 3 + 数据 2（CONNECT/CONNACK）+ 挥手 4（链上 TCPGenerator
	// 4 包，legacy 为 3 包挥手）。
	if len(pkts) != 9 {
		t.Fatalf("got %d packets, want 9 (handshake 3 + connect/connack 2 + teardown 4)", len(pkts))
	}
	// 数据帧只有 2：CONNECT(up) CONNACK(down)；无任何 PUBLISH/PINGREQ/
	// DISCONNECT（legacy 同款语义）。
	legacy := legacyDataFrames(t, spec)
	if len(legacy) != 2 {
		t.Fatalf("legacy data frames = %d, want 2", len(legacy))
	}
	for i, l := range legacy {
		if !bytes.Equal(pkts[3+i].Payload, l.Payload) {
			t.Errorf("data frame %d payload = % X, legacy = % X", i, pkts[3+i].Payload, l.Payload)
		}
	}
	if pkts[3].Payload[0]&0xF0 != 0x10 || pkts[4].Payload[0]&0xF0 != 0x20 {
		t.Errorf("data frames = 0x%02x/0x%02x, want CONNECT(0x10)/CONNACK(0x20)",
			pkts[3].Payload[0]&0xF0, pkts[4].Payload[0]&0xF0)
	}
}

// TestLayerGen_ChainPlannerDstPortDefault 目的端口默认：spec.DstPort=0 →
// 1883（validateSpecBase mqtt 分支，legacy Plan 同款默认）。
func TestLayerGen_ChainPlannerDstPortDefault(t *testing.T) {
	spec := mqttSpec(1000)
	spec.DstPort = 0
	planner := layers.NewChainPlannerFromChain("mqtt", []layers.Layer{
		{Name: "ip"},
		{Name: "tcp"},
		{Name: "mqtt"},
	})
	ch, err := planner.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("ChainPlanner Plan: %v", err)
	}
	var pkts []core.PacketConfig
	for p := range ch {
		pkts = append(pkts, p)
	}
	if len(pkts) == 0 {
		t.Fatal("no packets")
	}
	if pkts[0].L4.DstPort != 1883 {
		t.Errorf("SYN dst_port = %d, want 1883 (default)", pkts[0].L4.DstPort)
	}
}

// TestLayerGen_NilEmitMsg EmitMsg 未接线即报错（不能静默丢事件）。
func TestLayerGen_NilEmitMsg(t *testing.T) {
	gen := &MQTTGenerator{}
	req := &layers.GenRequest{Meta: layers.FlowMeta{MQTT: &core.MQTTConfig{}}}
	if err := gen.Generate(context.Background(), req); err == nil {
		t.Fatal("Generate with nil EmitMsg returned nil, want error")
	}
}

// TestLayerGen_NoConfig 无 MQTT 配置即报错（不产任何事件）。
func TestLayerGen_NoConfig(t *testing.T) {
	gen := &MQTTGenerator{}
	var events []layers.MessageEvent
	req := &layers.GenRequest{
		Meta: layers.FlowMeta{},
		EmitMsg: func(ev layers.MessageEvent) error {
			events = append(events, ev)
			return nil
		},
	}
	if err := gen.Generate(context.Background(), req); err == nil {
		t.Fatal("Generate with no config returned nil, want error")
	}
	if len(events) != 0 {
		t.Fatalf("emitted %d events on invalid config, want 0", len(events))
	}
}

// TestLayerGen_MultiStreamRejected 多流展开拒绝（enip/dnp3/modbus 同款
// 纪律）：Sessions 非空 → 生成器级显式报错（0 事件，包数缩水的静默单流是
// 禁止语义）；链级经 validator 在 Plan 期同步拒绝。
func TestLayerGen_MultiStreamRejected(t *testing.T) {
	cfg := &core.MQTTConfig{
		Version:  4,
		ClientID: "c1",
		Sessions: []core.MQTTSession{
			{ClientID: "s1"},
			{ClientID: "s2"},
		},
	}
	// 生成器级：显式错误 + 0 事件。
	gen := &MQTTGenerator{}
	var events []layers.MessageEvent
	c2 := *cfg
	req := &layers.GenRequest{
		Meta: layers.FlowMeta{MQTT: &c2},
		EmitMsg: func(ev layers.MessageEvent) error {
			events = append(events, ev)
			return nil
		},
	}
	err := gen.Generate(context.Background(), req)
	if err == nil || !strings.Contains(err.Error(), "not supported on a tcp-layer chain") {
		t.Fatalf("Generate error = %v, want multi-stream rejection", err)
	}
	if len(events) != 0 {
		t.Fatalf("emitted %d events on multi-stream config, want 0", len(events))
	}
	// 链级：validator 同步拒绝（Plan 报错，非空流）。
	spec := mqttSpec(0)
	spec.MQTT.Sessions = cfg.Sessions
	planner := layers.NewChainPlannerFromChain("mqtt", []layers.Layer{
		{Name: "ip"},
		{Name: "tcp"},
		{Name: "mqtt"},
	})
	if _, err := planner.Plan(context.Background(), spec); err == nil {
		t.Fatal("ChainPlanner Plan with multi-stream returned nil, want error")
	}
}

// TestLayerGen_ChainPlannerRejectsInvalidSpec 链级负向：非法 spec 经
// ChainPlanner 校验拒绝（validator 触发，planner 名必须为 "mqtt"）。
// 覆盖 legacy Validate 的主要检查：非法版本、QoS 越界、无效 direction、
// 空订阅过滤器、v4 携带 properties、密码无用户名、无效 ConnectAckCode。
func TestLayerGen_ChainPlannerRejectsInvalidSpec(t *testing.T) {
	planner := layers.NewChainPlannerFromChain("mqtt", []layers.Layer{
		{Name: "ip"},
		{Name: "tcp"},
		{Name: "mqtt"},
	})
	// 非法版本（仅允许 4/5）。
	spec := mqttSpec(0)
	spec.MQTT.Version = 3
	if _, err := planner.Plan(context.Background(), spec); err == nil || !strings.Contains(err.Error(), "invalid version") {
		t.Fatalf("Plan with version=3 error = %v, want invalid version", err)
	}
	// QoS=3 越界。
	spec = mqttSpec(0)
	spec.MQTT.Messages = []core.MQTTMessage{{Topic: "t", Payload: "p", QoS: 3}}
	if _, err := planner.Plan(context.Background(), spec); err == nil || !strings.Contains(err.Error(), "invalid message qos") {
		t.Fatalf("Plan with QoS=3 error = %v, want invalid qos", err)
	}
	// 无效 direction。
	spec = mqttSpec(0)
	spec.MQTT.Messages = []core.MQTTMessage{{Topic: "t", Payload: "p", QoS: 0, Direction: "sideways"}}
	if _, err := planner.Plan(context.Background(), spec); err == nil || !strings.Contains(err.Error(), "invalid message direction") {
		t.Fatalf("Plan with direction=sideways error = %v, want invalid direction", err)
	}
	// 空订阅过滤器。
	spec = mqttSpec(0)
	spec.MQTT.Subscriptions = []core.MQTTSubscribe{{PacketID: 0, Filters: nil}}
	if _, err := planner.Plan(context.Background(), spec); err == nil || !strings.Contains(err.Error(), "filters cannot be empty") {
		t.Fatalf("Plan with empty subscription filters error = %v, want filters cannot be empty", err)
	}
	// v4 携带 properties（5.0 only）。
	spec = mqttSpec(0)
	spec.MQTT.Properties = []core.MQTTProperty{{Identifier: 0x22, Format: "uint16", Value: "10"}}
	if _, err := planner.Plan(context.Background(), spec); err == nil || !strings.Contains(err.Error(), "5.0 only") {
		t.Fatalf("Plan with v4 properties error = %v, want 5.0 only", err)
	}
	// 密码无用户名（3.1.1）。
	spec = mqttSpec(0)
	spec.MQTT.Username = ""
	spec.MQTT.Password = "secret"
	if _, err := planner.Plan(context.Background(), spec); err == nil || !strings.Contains(err.Error(), "username required when password is set") {
		t.Fatalf("Plan with password-only error = %v, want username required", err)
	}
	// 无效 ConnectAckCode（5 超出 3.1.1 合法域 0-5 的边界——3.1.1 合法 0-5，
	// 用 6）。
	spec = mqttSpec(0)
	spec.MQTT.ConnectAckCode = 6
	if _, err := planner.Plan(context.Background(), spec); err == nil {
		t.Fatalf("Plan with connect_ack_code=6 error = nil, want invalid code (v4 allowed 0-5)")
	}
	// v4 disconnect_reason（5.0 only）。
	spec = mqttSpec(0)
	spec.MQTT.DisconnectReason = intPtr(141)
	if _, err := planner.Plan(context.Background(), spec); err == nil || !strings.Contains(err.Error(), "5.0 only") {
		t.Fatalf("Plan with v4 disconnect_reason error = %v, want 5.0 only", err)
	}
}

// TestLayerGen_EmitMsgErrorPropagates emit 错误向上传播（不能吞）。
func TestLayerGen_EmitMsgErrorPropagates(t *testing.T) {
	gen := &MQTTGenerator{}
	sentinel := errors.New("emit failed")
	c2 := *mqttSpec(0).MQTT
	req := &layers.GenRequest{
		Meta: layers.FlowMeta{MQTT: &c2},
		EmitMsg: func(ev layers.MessageEvent) error {
			return sentinel
		},
	}
	if err := gen.Generate(context.Background(), req); !errors.Is(err, sentinel) {
		t.Fatalf("Generate error = %v, want sentinel", err)
	}
}

// TestLayerGen_CancelMidSequence 取消后停止产事件（精确计数）：默认配置产 2
// 事件（CONNECT+CONNACK），第 2 个事件后取消 → 返回 context 错误且只发出
// 2 事件（订阅阶段前）。
func TestLayerGen_CancelMidSequence(t *testing.T) {
	gen := &MQTTGenerator{}
	ctx, cancel := context.WithCancel(context.Background())
	var mu sync.Mutex
	var events []layers.MessageEvent
	cancelled := false
	c2 := *mqttSpec(0).MQTT
	req := &layers.GenRequest{
		Meta: layers.FlowMeta{MQTT: &c2},
		EmitMsg: func(ev layers.MessageEvent) error {
			mu.Lock()
			events = append(events, ev)
			n := len(events)
			mu.Unlock()
			if n == 2 { // 第 2 个事件后取消（CONNECT+CONNACK 完成，订阅前）
				cancel()
				cancelled = true
			}
			return nil
		},
	}
	err := gen.Generate(ctx, req)
	if !cancelled {
		t.Fatal("test did not reach cancel point")
	}
	if err == nil {
		t.Fatal("Generate after cancel returned nil, want context error")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(events) != 2 {
		t.Fatalf("emitted %d events, want exactly 2 (cancelled mid-sequence)", len(events))
	}
}
