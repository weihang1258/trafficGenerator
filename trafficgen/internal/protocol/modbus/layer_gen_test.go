package modbus

// MODBUS terminal-layer generator tests (P4a)。MODBUSGenerator 复用
// buildRequestPDU/buildResponsePDU/BuildMBAPFrame 纯函数产事件——事件序列
// 与 legacy Plan 的数据帧（flags=0x18 PSH-ACK，握手/挥手过滤后）在方向/字节
// 上逐帧一致（MBAP 头 TID/单元号/长度 + PDU）；链级测试通过 ChainPlanner
// 驱动 [ip→tcp→modbus] 完整链路验证握手→数据→挥手与 legacy 数据帧字节
// 一致、seq 连续。默认化（事务注入 FC=0x03 / unitID=1 / masterCount=1 /
// flowCount=1）与响应抑制（no_response / Force Listen Only / 广播抑制）与
// legacy Plan 对齐，测试覆盖默认值与显式值两路径。

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

// modbusSpec returns a base Modbus spec with a deterministic ISN and 3
// transactions（0x03 read + 0x06 write + 0x10 write multiple，覆盖读/写/多写
// 三类 PDU 形状）。initialSeq=0 → 不设 spec.TCP（链上 tcp 层随机 ISN）。
func modbusSpec(initialSeq uint32) core.FlowSpec {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1",
		SrcPort: 20000, DstPort: 502,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		MODBUS: &core.MODBUSConfig{
			Transactions: []core.MODBUSOperation{
				{FunctionCode: 0x03, StartingAddress: 0x0000, Quantity: 2},
				{FunctionCode: 0x06, StartingAddress: 0x0001, WriteValue: 0x1234},
				{FunctionCode: 0x10, StartingAddress: 0x0002, Quantity: 2,
					Values: []byte{0xAB, 0xCD, 0xEF, 0x01}},
			},
		},
	}
	if initialSeq != 0 {
		spec.TCP = &core.TCPConfig{InitialSeq: initialSeq}
	}
	return spec
}

// collectEvents drives MODBUSGenerator.Generate and collects the emitted
// message events in order. 值拷贝 cfg：事件生成与 legacy 对比各持独立实例。
func collectEvents(t *testing.T, spec core.FlowSpec) []layers.MessageEvent {
	t.Helper()
	var events []layers.MessageEvent
	gen := &MODBUSGenerator{}
	meta := layers.FlowMeta{
		SrcIP:   spec.SrcIP,
		DstIP:   spec.DstIP,
		SrcPort: spec.SrcPort,
		DstPort: spec.DstPort,
	}
	if spec.MODBUS != nil {
		c2 := *spec.MODBUS
		meta.MODBUS = &c2
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

// legacyDataFrames runs the legacy planner and returns the Modbus data
// frames (skip TCP handshake/teardown)。数据帧 flags=0x18 PSH-ACK
// （modbus.go planFlow 555-571），与事件一一对应。
func legacyDataFrames(t *testing.T, spec core.FlowSpec) []core.PacketConfig {
	t.Helper()
	spec2 := spec
	if spec.MODBUS != nil {
		c2 := *spec.MODBUS
		spec2.MODBUS = &c2
	}
	var out []core.PacketConfig
	for _, c := range tcpPackets(mustPlan(t, &Planner{}, spec2)) {
		if c.L4.Flags == 0x18 { // data frame
			out = append(out, c)
		}
	}
	return out
}

// assertEventsMatchLegacy 逐帧断言事件方向与字节与 legacy 数据帧一致。
func assertEventsMatchLegacy(t *testing.T, spec core.FlowSpec, events []layers.MessageEvent) {
	t.Helper()
	legacy := legacyDataFrames(t, spec)
	if len(events) != len(legacy) {
		t.Fatalf("events = %d, legacy data frames = %d", len(events), len(legacy))
	}
	for i, ev := range events {
		pc := legacy[i]
		if (ev.Up && pc.Direction != "up") || (!ev.Up && pc.Direction != "down") {
			t.Errorf("event[%d] Up=%v, legacy Direction=%s", i, ev.Up, pc.Direction)
		}
		if !bytes.Equal(ev.Bytes, pc.Payload) {
			t.Errorf("event[%d] payload = % X, legacy = % X", i, ev.Bytes, pc.Payload)
		}
	}
}

// TestLayerGen_EventsMatchLegacyPlan 字节级对比：事件序列与 legacy 数据帧在
// 方向/payload 上逐帧一致。覆盖核心场景矩阵（默认/多事务/异常/显式响应/
// 响应抑制/广播/空事务）。
func TestLayerGen_EventsMatchLegacyPlan(t *testing.T) {
	cases := []struct {
		name string
		cfg  *core.MODBUSConfig
	}{
		// 默认化路径：MODBUSConfig{}（Transactions=nil → 注入 FC=0x03 事务、
		// UnitID=nil → 1、MasterCount/FlowCount=0 → 1）。nil MODBUS 是生成器
		// 错误（TestLayerGen_NoConfig），非默认化路径。
		{"default config (injected FC=0x03)", &core.MODBUSConfig{}},
		{"multi-transaction", &core.MODBUSConfig{Transactions: []core.MODBUSOperation{
			{FunctionCode: 0x03, StartingAddress: 0x0000, Quantity: 2},
			{FunctionCode: 0x06, StartingAddress: 0x0001, WriteValue: 0x1234},
			{FunctionCode: 0x10, StartingAddress: 0x0002, Quantity: 2,
				Values: []byte{0xAB, 0xCD, 0xEF, 0x01}},
		}}},
		{"exception response", &core.MODBUSConfig{Transactions: []core.MODBUSOperation{
			{FunctionCode: 0x03, StartingAddress: 0x0000, Quantity: 1},
			{FunctionCode: 0x03, StartingAddress: 0x0000, Quantity: 1,
				ExceptionCode: 0x02},
		}}},
		{"response values override", &core.MODBUSConfig{Transactions: []core.MODBUSOperation{
			{FunctionCode: 0x03, StartingAddress: 0x0000, Quantity: 2,
				ResponseValues: []byte{0x04, 0xAA, 0xBB, 0xCC, 0xDD}},
		}}},
		{"response mode no_response", &core.MODBUSConfig{Transactions: []core.MODBUSOperation{
			{FunctionCode: 0x03, StartingAddress: 0x0000, Quantity: 1,
				ResponseMode: "no_response"},
		}}},
		{"force listen only", &core.MODBUSConfig{Transactions: []core.MODBUSOperation{
			{FunctionCode: 0x08, SubFunction: 0x0004, Values: []byte{0x00, 0x00}},
		}}},
		{"broadcast suppressed", &core.MODBUSConfig{
			UnitID:            u8ptr(0),
			SuppressBroadcast: true,
			Transactions: []core.MODBUSOperation{
				{FunctionCode: 0x06, StartingAddress: 0x0000, WriteValue: 0x1234},
			},
		}},
		{"broadcast not suppressed", &core.MODBUSConfig{
			UnitID: u8ptr(0),
			Transactions: []core.MODBUSOperation{
				{FunctionCode: 0x06, StartingAddress: 0x0000, WriteValue: 0x1234},
			},
		}},
		{"explicit empty transactions (handshake+teardown only)", &core.MODBUSConfig{
			Transactions: []core.MODBUSOperation{},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec := modbusSpec(0)
			c2 := *tc.cfg
			spec.MODBUS = &c2
			events := collectEvents(t, spec)
			assertEventsMatchLegacy(t, spec, events)
		})
	}
}

// TestLayerGen_MBAPByteLayout 独立校验 MBAP 头布局（不依赖 legacy 对比）：
// TID（offset 0-1）、ProtocolID=0x0000（2-3）、Length=1+len(PDU)（4-5）、
// UnitID（6）。事件[0]=request up、事件[1]=response down 共享同一 TID
// （§2.3 事务匹配语义）；TID 流内从 0 递增。
func TestLayerGen_MBAPByteLayout(t *testing.T) {
	spec := modbusSpec(0)
	spec.MODBUS.UnitID = u8ptr(0x11) // 显式单元号验证进 MBAP 头
	events := collectEvents(t, spec)
	if len(events) != 6 {
		t.Fatalf("events = %d, want 6 (3 transactions × req+resp)", len(events))
	}
	for i := 0; i < 3; i++ {
		req := events[2*i].Bytes
		if !events[2*i].Up || events[2*i+1].Up {
			t.Errorf("transaction %d directions = %v/%v, want up/down", i, events[2*i].Up, events[2*i+1].Up)
		}
		if binary.BigEndian.Uint16(req[0:2]) != uint16(i) {
			t.Errorf("req %d TID = %d, want %d (per-flow from 0)", i, binary.BigEndian.Uint16(req[0:2]), i)
		}
		resp := events[2*i+1].Bytes
		if binary.BigEndian.Uint16(resp[0:2]) != uint16(i) {
			t.Errorf("resp %d TID = %d, want %d (shared with req)", i, binary.BigEndian.Uint16(resp[0:2]), i)
		}
		for j, ev := range []layers.MessageEvent{events[2*i], events[2*i+1]} {
			if got := binary.BigEndian.Uint16(ev.Bytes[2:4]); got != 0 {
				t.Errorf("event %d proto ID = 0x%04x, want 0x0000", j, got)
			}
			if len(ev.Bytes) < 7 {
				t.Fatalf("event %d shorter than MBAP header", j)
			}
			if got := binary.BigEndian.Uint16(ev.Bytes[4:6]); got != uint16(1+len(ev.Bytes)-MBAPHeaderLen) {
				t.Errorf("event %d length field = %d, want 1+len(PDU)=%d", j, got, 1+len(ev.Bytes)-MBAPHeaderLen)
			}
			if ev.Bytes[6] != 0x11 {
				t.Errorf("event %d unit ID = 0x%02x, want 0x11", j, ev.Bytes[6])
			}
		}
	}
	// 首个事务 req PDU = 0x03 + addr 0x0000 + qty 0x0002。
	if got := events[0].Bytes[7]; got != 0x03 {
		t.Errorf("req[0] PDU FC = 0x%02x, want 0x03", got)
	}
}

// TestLayerGen_SharedTIDSpace 全局 TID：SharedTIDSpace=true 时 TID 经
// nextGlobalTID 原子递增（legacy 跨流共享计数器；链拒绝多流后为全局单流
// 仍 +1）。记录调用前全局计数，断言首个 TID 为旧值（连续）、req/resp 共享。
func TestLayerGen_SharedTIDSpace(t *testing.T) {
	spec := modbusSpec(0)
	spec.MODBUS.SharedTIDSpace = true
	before := globalTIDCounter
	events := collectEvents(t, spec)
	if len(events) != 6 {
		t.Fatalf("events = %d, want 6", len(events))
	}
	wantTID := uint16(before)
	for i := 0; i < 3; i++ {
		if got := binary.BigEndian.Uint16(events[2*i].Bytes[0:2]); got != wantTID {
			t.Errorf("req %d TID = %d, want %d (global counter from pre-call value)", i, got, wantTID)
		}
		if got := binary.BigEndian.Uint16(events[2*i+1].Bytes[0:2]); got != wantTID {
			t.Errorf("resp %d TID = %d, want %d (shared with req)", i, got, wantTID)
		}
		wantTID++
	}
}

// TestLayerGen_ChainPlannerBytes 链级字节验证：ChainPlanner 驱动
// [ip→tcp→modbus] 完整链路（握手 3 + 数据 6 + 挥手 4 = 13 包），数据帧与
// legacy 逐字节一致。挥手为 TCPGenerator 标准 4 包（FIN|ACK up → ACK down
// → FIN|ACK down → ACK up，generator.go:874-943）——legacy modbus.go 是 3
// 包挥手（FIN up → FIN down → ACK up，planFlow 575-596），层模型意图的
// 文档化分歧（gbt32960/dnp3/doip 链测试同款断言形状）。数据帧方向与
// legacy 一致（up 请求/down 响应），FIN(up) 继承最后 up 数据帧尾部 seq。
func TestLayerGen_ChainPlannerBytes(t *testing.T) {
	spec := modbusSpec(1000) // 确定性 ISN
	planner := layers.NewChainPlannerFromChain("modbus", []layers.Layer{
		{Name: "ip"},
		{Name: "tcp"},
		{Name: "modbus"},
	})
	ch, err := planner.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("ChainPlanner Plan: %v", err)
	}
	var pkts []core.PacketConfig
	for p := range ch {
		pkts = append(pkts, p)
	}
	// 3 事务 × (req up + resp down) = 6 数据帧。
	if len(pkts) != 13 {
		t.Fatalf("got %d packets, want 13 (handshake 3 + data 6 + teardown 4)", len(pkts))
	}
	// 握手：SYN(up) → SYN-ACK(down) → ACK(up)；数据 6 帧；挥手 4 包。
	// 方向模式独立断言（up/down 错位时 flags 序列同构，仅方向能暴露）。
	wantFlags := []uint8{0x02, 0x12, 0x10, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x11, 0x10, 0x11, 0x10}
	wantDir := []string{"up", "down", "up",
		"up", "down", "up", "down", "up", "down",
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
	// 覆盖"交换方向/错位 TID"的静默错误）。
	legacy := legacyDataFrames(t, spec)
	if len(legacy) != 6 {
		t.Fatalf("legacy data frames = %d, want 6", len(legacy))
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
	// down 数据帧端口交换（legacy 同款：down 帧源端口 = DstPort 502）。
	if pkts[4].L4.SrcPort != 502 || pkts[4].L4.DstPort != 20000 {
		t.Errorf("down data frame ports = %d/%d, want 502/20000", pkts[4].L4.SrcPort, pkts[4].L4.DstPort)
	}
	// 挥手 seq 连续性（seq 只按同侧负载推进——up 侧只累加 up 帧长度）：
	// FIN|ACK(up) pkts[9] 继承最后 up 数据帧尾部 seq（pkts[7] = 第三事务
	// req up，seq 1025 + 17 = 1042）；FIN|ACK(down) pkts[11] 继承最后 down
	// 数据帧尾部 seq（pkts[8] = 第三事务 resp down，seq 3251898584 + 12 =
	// 3251898596）。
	if pkts[9].L4.Seq != pkts[7].L4.Seq+uint32(len(pkts[7].Payload)) {
		t.Errorf("FIN(up) seq = %d, want up data tail %d", pkts[9].L4.Seq, pkts[7].L4.Seq+uint32(len(pkts[7].Payload)))
	}
	if pkts[11].L4.Seq != pkts[8].L4.Seq+uint32(len(pkts[8].Payload)) {
		t.Errorf("FIN(down) seq = %d, want down data tail %d", pkts[11].L4.Seq, pkts[8].L4.Seq+uint32(len(pkts[8].Payload)))
	}
}

// TestLayerGen_ChainPlannerSuppressed 链级抑制：no_response 事务（0x03 正常 +
// 0x08/0x0004 只 up）→ 数据帧 3（1 请求/响应对 + 1 只请求），FIN(up) seq
// 推进 3 段（不含被抑制的 down 段）。
func TestLayerGen_ChainPlannerSuppressed(t *testing.T) {
	spec := modbusSpec(1000)
	spec.MODBUS.Transactions = []core.MODBUSOperation{
		{FunctionCode: 0x03, StartingAddress: 0x0000, Quantity: 1},
		{FunctionCode: 0x08, SubFunction: 0x0004, Values: []byte{0x00, 0x00}},
	}
	planner := layers.NewChainPlannerFromChain("modbus", []layers.Layer{
		{Name: "ip"},
		{Name: "tcp"},
		{Name: "modbus"},
	})
	ch, err := planner.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("ChainPlanner Plan: %v", err)
	}
	var pkts []core.PacketConfig
	for p := range ch {
		pkts = append(pkts, p)
	}
	// 数据帧 3：req1 up、resp1 down、req2 up（TID 1 无响应，被 Force Listen
	// Only 抑制）。总包数 = 3 + 3 + 4 = 10。
	if len(pkts) != 10 {
		t.Fatalf("got %d packets, want 10 (handshake 3 + data 3 + teardown 4)", len(pkts))
	}
	wantDir := []string{"up", "down", "up"}
	for i, wd := range wantDir {
		if pkts[3+i].L4.Flags != 0x18 || pkts[3+i].Direction != wd {
			t.Errorf("data frame %d = flags 0x%02x dir %s, want 0x18/%s",
				i, pkts[3+i].L4.Flags, pkts[3+i].Direction, wd)
		}
	}
	// 与 legacy 字节级一致（suppressed 路径同款）。
	legacy := legacyDataFrames(t, spec)
	if len(legacy) != 3 {
		t.Fatalf("legacy data frames = %d, want 3", len(legacy))
	}
	for i, l := range legacy {
		if !bytes.Equal(pkts[3+i].Payload, l.Payload) {
			t.Errorf("data frame %d payload = % X, legacy = % X", i, pkts[3+i].Payload, l.Payload)
		}
	}
	// 事务 2 是 Force Listen Only（0x08/0x0004）：只 up、无响应——up 侧 seq
	// 只按本侧已发字节推进（resp1 的 11 字节不参与 up 计数：1013 = 1001+12）。
	if pkts[5].L4.Seq != pkts[3].L4.Seq+uint32(len(pkts[3].Payload)) {
		t.Errorf("req2 seq = %d, want %d (req1 bytes)", pkts[5].L4.Seq, pkts[3].L4.Seq+uint32(len(pkts[3].Payload)))
	}
	// FIN(up) pkts[6] 继承最后 up 数据帧（pkts[5] req2）尾部 seq。
	if pkts[6].L4.Seq != pkts[5].L4.Seq+uint32(len(pkts[5].Payload)) {
		t.Errorf("FIN(up) seq = %d, want %d (req2 tail)", pkts[6].L4.Seq, pkts[5].L4.Seq+uint32(len(pkts[5].Payload)))
	}
}

// TestLayerGen_ChainPlannerEmptyTransactions 链级空事务：显式空数组 →
// 只握手 + 挥手（0 数据帧，legacy 同款）。
func TestLayerGen_ChainPlannerEmptyTransactions(t *testing.T) {
	spec := modbusSpec(1000)
	spec.MODBUS.Transactions = []core.MODBUSOperation{}
	planner := layers.NewChainPlannerFromChain("modbus", []layers.Layer{
		{Name: "ip"},
		{Name: "tcp"},
		{Name: "modbus"},
	})
	ch, err := planner.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("ChainPlanner Plan: %v", err)
	}
	var pkts []core.PacketConfig
	for p := range ch {
		pkts = append(pkts, p)
	}
	if len(pkts) != 7 {
		t.Fatalf("got %d packets, want 7 (handshake 3 + teardown 4)", len(pkts))
	}
	for _, p := range pkts {
		if p.L4.Flags == 0x18 {
			t.Fatalf("unexpected data frame (empty transactions): % X", p.Payload)
		}
	}
}

// TestLayerGen_ChainPlannerDstPortDefault 目的端口默认：spec.DstPort=0 →
// 502（validateSpecBase modbus 分支，legacy Plan 同款默认）。
func TestLayerGen_ChainPlannerDstPortDefault(t *testing.T) {
	spec := modbusSpec(1000)
	spec.DstPort = 0
	planner := layers.NewChainPlannerFromChain("modbus", []layers.Layer{
		{Name: "ip"},
		{Name: "tcp"},
		{Name: "modbus"},
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
	if pkts[0].L4.DstPort != 502 {
		t.Errorf("SYN dst_port = %d, want 502 (default)", pkts[0].L4.DstPort)
	}
}

// TestLayerGen_NilEmitMsg EmitMsg 未接线即报错（不能静默丢事件）。
func TestLayerGen_NilEmitMsg(t *testing.T) {
	gen := &MODBUSGenerator{}
	req := &layers.GenRequest{Meta: layers.FlowMeta{MODBUS: &core.MODBUSConfig{}}}
	if err := gen.Generate(context.Background(), req); err == nil {
		t.Fatal("Generate with nil EmitMsg returned nil, want error")
	}
}

// TestLayerGen_NoConfig 无 MODBUS 配置即报错（不产任何事件）。
func TestLayerGen_NoConfig(t *testing.T) {
	gen := &MODBUSGenerator{}
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

// TestLayerGen_MultiStreamRejected 多流展开拒绝（enip/dnp3 同款纪律）：
// MasterCount>1 / FlowCount>1 生成器级显式报错（0 事件，包数缩水的静默
// 单流是禁止语义）；链级经 validator 在 Plan 期同步拒绝。
func TestLayerGen_MultiStreamRejected(t *testing.T) {
	for name, mutate := range map[string]func(*core.MODBUSConfig){
		"master_count>1": func(c *core.MODBUSConfig) { c.MasterCount = 2 },
		"flow_count>1":   func(c *core.MODBUSConfig) { c.FlowCount = 3 },
	} {
		t.Run(name, func(t *testing.T) {
			c := &core.MODBUSConfig{}
			mutate(c)
			// 生成器级：显式错误 + 0 事件。
			gen := &MODBUSGenerator{}
			var events []layers.MessageEvent
			c2 := *c
			req := &layers.GenRequest{
				Meta: layers.FlowMeta{MODBUS: &c2},
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
			spec := modbusSpec(0)
			spec.MODBUS.MasterCount = c.MasterCount
			spec.MODBUS.FlowCount = c.FlowCount
			planner := layers.NewChainPlannerFromChain("modbus", []layers.Layer{
				{Name: "ip"},
				{Name: "tcp"},
				{Name: "modbus"},
			})
			if _, err := planner.Plan(context.Background(), spec); err == nil {
				t.Fatal("ChainPlanner Plan with multi-stream returned nil, want error")
			}
		})
	}
}

// TestLayerGen_ChainPlannerRejectsInvalidSpec 链级负向：非法 spec 经
// ChainPlanner 校验拒绝（validator 触发，planner 名必须为 "modbus"）。
// 覆盖 legacy Validate 的 4 类检查：UnitID 保留范围、master_count 范围、
// 非法功能码、非法异常码。
func TestLayerGen_ChainPlannerRejectsInvalidSpec(t *testing.T) {
	planner := layers.NewChainPlannerFromChain("modbus", []layers.Layer{
		{Name: "ip"},
		{Name: "tcp"},
		{Name: "modbus"},
	})
	// UnitID=248 保留（V-001）。
	spec := modbusSpec(0)
	spec.MODBUS.UnitID = u8ptr(248)
	if _, err := planner.Plan(context.Background(), spec); err == nil || !strings.Contains(err.Error(), "reserved") {
		t.Fatalf("Plan with unit_id=248 error = %v, want reserved", err)
	}
	// master_count 超出 0-1000 范围。
	spec = modbusSpec(0)
	spec.MODBUS.MasterCount = -1
	if _, err := planner.Plan(context.Background(), spec); err == nil || !strings.Contains(err.Error(), "master_count") {
		t.Fatalf("Plan with master_count=-1 error = %v, want master_count range", err)
	}
	// 非法功能码：FC=0x7F 不在 supportedFCs 且无异常码 → unsupported（带
	// 异常码是 V-103 豁免路径，合法，不在此测；FC=0x99 因高位已置位报的
	// 是 high-bit 错，与本断言不符）。
	spec = modbusSpec(0)
	spec.MODBUS.Transactions = []core.MODBUSOperation{{FunctionCode: 0x7F}}
	if _, err := planner.Plan(context.Background(), spec); err == nil || !strings.Contains(err.Error(), "unsupported function code") {
		t.Fatalf("Plan with FC=0x7F error = %v, want unsupported function code", err)
	}
	// 非法异常码（0x09 不在 exceptionCodes）。
	spec = modbusSpec(0)
	spec.MODBUS.Transactions = []core.MODBUSOperation{
		{FunctionCode: 0x03, Quantity: 1, ExceptionCode: 0x09},
	}
	if _, err := planner.Plan(context.Background(), spec); err == nil || !strings.Contains(err.Error(), "invalid exception code") {
		t.Fatalf("Plan with exception_code=0x09 error = %v, want invalid exception code", err)
	}
}

// TestLayerGen_EmitMsgErrorPropagates emit 错误向上传播（不能吞）。
func TestLayerGen_EmitMsgErrorPropagates(t *testing.T) {
	gen := &MODBUSGenerator{}
	sentinel := errors.New("emit failed")
	c2 := *modbusSpec(0).MODBUS
	req := &layers.GenRequest{
		Meta: layers.FlowMeta{MODBUS: &c2},
		EmitMsg: func(ev layers.MessageEvent) error {
			return sentinel
		},
	}
	if err := gen.Generate(context.Background(), req); !errors.Is(err, sentinel) {
		t.Fatalf("Generate error = %v, want sentinel", err)
	}
}

// TestLayerGen_CancelMidSequence 取消后停止产事件（精确计数）：默认配置
// 产 2 事件（req+resp），第 2 个事件后取消 → 返回 context 错误且只发出
// 2 事件。
func TestLayerGen_CancelMidSequence(t *testing.T) {
	gen := &MODBUSGenerator{}
	ctx, cancel := context.WithCancel(context.Background())
	var mu sync.Mutex
	var events []layers.MessageEvent
	cancelled := false
	c2 := *modbusSpec(0).MODBUS
	req := &layers.GenRequest{
		Meta: layers.FlowMeta{MODBUS: &c2},
		EmitMsg: func(ev layers.MessageEvent) error {
			mu.Lock()
			events = append(events, ev)
			n := len(events)
			mu.Unlock()
			if n == 2 { // 第 2 个事件后取消（req+resp 完成，第 2 事务前）
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
