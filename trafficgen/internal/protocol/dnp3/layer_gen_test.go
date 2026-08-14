package dnp3

// DNP3 terminal-layer generator tests (P4a)。DNP3Generator 逐帧复用
// scenarioFrames 纯函数产事件——事件序列与 legacy planFlow 的数据帧
// （handshake/teardown 过滤后）在方向/字节上逐帧一致；链级测试通过
// ChainPlanner 驱动 [ip→tcp→dnp3] 完整链路验证握手→数据→挥手与 legacy
// 数据帧字节一致。

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// basicSpec builds a valid DNP3 flow spec (master, tcp, read_class0)。
// 值拷贝 cfg：scenarioFrames 有副作用（fcbToggle 翻转 c.LinkFCB），
// 事件生成与 legacy 对比必须各持独立实例，否则第二次观察错位。
// 注意：浅拷贝隔离 struct 标量（LinkFCB 等），slice 字段（Objects[].Points）
// 仍共享——当前测试不在对比间修改 objects，够用。
func basicSpec(cfg *core.DNP3Config) core.FlowSpec {
	if cfg == nil {
		cfg = &core.DNP3Config{}
	}
	cp := *cfg
	return core.FlowSpec{
		SrcIP:   "192.168.1.1",
		DstIP:   "192.168.1.2",
		SrcPort: 12345,
		DstPort: 20000,
		SrcMAC:  "aa:bb:cc:dd:ee:ff",
		DstMAC:  "11:22:33:44:55:66",
		DNP3:    &cp,
	}
}

// collectEvents drives DNP3Generator.Generate and collects the emitted
// message events in order.
func collectEvents(t *testing.T, spec core.FlowSpec) []layers.MessageEvent {
	t.Helper()
	var events []layers.MessageEvent
	gen := &DNP3Generator{}
	meta := layers.FlowMeta{
		SrcIP:   spec.SrcIP,
		DstIP:   spec.DstIP,
		SrcPort: spec.SrcPort,
		DstPort: spec.DstPort,
	}
	// 值拷贝：scenarioFrames 有副作用（fcbToggle 翻转 c.LinkFCB，scenario.go:36），
	// 生成器会原地翻转 meta 里的配置；legacy 对比必须看到未翻转的初始状态。
	if spec.DNP3 != nil {
		c2 := *spec.DNP3
		meta.DNP3 = &c2
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

// legacyDataFrames runs the legacy planner and returns the DNP3 data frames
// (skip TCP handshake/teardown)。数据帧 flags=0x18 PSH-ACK（dnp3.go:139），
// 与事件一一对应。
func legacyDataFrames(t *testing.T, spec core.FlowSpec) []core.PacketConfig {
	t.Helper()
	// 值拷贝：scenarioFrames 有副作用（fcbToggle 翻转 c.LinkFCB），必须从
	// 未翻转的初始状态起跑，与事件生成（collectEvents 同款拷贝）对齐。
	spec2 := spec
	if spec.DNP3 != nil {
		c2 := *spec.DNP3
		spec2.DNP3 = &c2
	}
	ch, err := (&Planner{}).Plan(context.Background(), spec2)
	if err != nil {
		t.Fatalf("legacy Plan: %v", err)
	}
	var out []core.PacketConfig
	for c := range ch {
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
// 方向/payload 上逐帧一致。覆盖核心场景矩阵（每个 scenario 至少一例）。
func TestLayerGen_EventsMatchLegacyPlan(t *testing.T) {
	cases := []struct {
		name string
		cfg  *core.DNP3Config
	}{
		{"read_class0 default objects", &core.DNP3Config{Scenario: "read_class0"}},
		{"read_class123", &core.DNP3Config{Scenario: "read_class123"}},
		{"select_operate", &core.DNP3Config{Scenario: "select_operate", Objects: []core.DNP3Object{{ObjectType: 12, Variation: 1, Qualifier: 0, IndexRange: [2]uint16{5, 5}, Points: []core.DNP3Point{{Value: 3}}}}}},
		{"direct_operate", &core.DNP3Config{Scenario: "direct_operate", Objects: []core.DNP3Object{{ObjectType: 12, Variation: 1, Qualifier: 0, IndexRange: [2]uint16{5, 5}, Points: []core.DNP3Point{{Value: 3}}}}}},
		{"write_single", &core.DNP3Config{Scenario: "write_single", Objects: []core.DNP3Object{{ObjectType: 20, Variation: 1, Qualifier: 1, IndexRange: [2]uint16{0, 0}, Points: []core.DNP3Point{{Value: 42}}}}}},
		{"delay_measurement", &core.DNP3Config{Scenario: "delay_measurement"}},
		{"cold_restart", &core.DNP3Config{Scenario: "cold_restart"}},
		{"enable_unsolicited", &core.DNP3Config{Scenario: "enable_unsolicited"}},
		{"assign_class", &core.DNP3Config{Scenario: "assign_class"}},
		{"unsolicited outstation", &core.DNP3Config{Scenario: "unsolicited", LinkType: "outstation"}},
		{"respond outstation", &core.DNP3Config{Scenario: "respond", LinkType: "outstation", Objects: []core.DNP3Object{{ObjectType: 30, Variation: 1, Qualifier: 0, IndexRange: [2]uint16{0, 5}}}}},
		{"multi_object_response", &core.DNP3Config{Scenario: "multi_object_response", LinkType: "outstation", Objects: []core.DNP3Object{{ObjectType: 30, Variation: 1, Qualifier: 0, IndexRange: [2]uint16{0, 2}}}}},
		{"empty scenario custom func", &core.DNP3Config{AppFunc: "delay_measurement"}},
		{"no-ack direct operate", &core.DNP3Config{AppFuncCode: AppDirectOperateNoAck, Objects: []core.DNP3Object{{ObjectType: 12, Variation: 1, Qualifier: 0, IndexRange: [2]uint16{1, 1}, Points: []core.DNP3Point{{Value: 3}}}}}},
		{"custom link_fc", &core.DNP3Config{Scenario: "reset_link", LinkFC: LinkNACK}},
		{"link_fcb toggling", &core.DNP3Config{Scenario: "select_operate", LinkFCB: 1}},
		{"malformed crc", &core.DNP3Config{Scenario: "read_class0", MalformedCRC: true}},
		{"malformed length", &core.DNP3Config{Scenario: "read_class0", MalformedLength: func() *uint8 { v := uint8(4); return &v }()}},
		{"iin bits", &core.DNP3Config{Scenario: "read_class0", LinkType: "outstation", IINClass1: true, IINNeedTime: true, IINObjectUnknown: true}},
		{"broadcast no confirm", &core.DNP3Config{Scenario: "read_class0", DstAddr: 0xFFFF}},
		{"explicit addresses", &core.DNP3Config{Scenario: "read_class0", SrcAddr: 10, DstAddr: 20}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec := basicSpec(tc.cfg)
			events := collectEvents(t, spec)
			assertEventsMatchLegacy(t, spec, events)
		})
	}
}

// TestLayerGen_LinkFrameBytes 链路层帧字节断言：reset_link 首帧 = 5 64 05
// C0 00 04 01 00 + CRC（legacy 测试同款断言，验证复用帧构造未漂移）。
func TestLayerGen_LinkFrameBytes(t *testing.T) {
	events := collectEvents(t, basicSpec(&core.DNP3Config{Scenario: "reset_link"}))
	if len(events) != 2 {
		t.Fatalf("got %d events, want 2 (reset up + reset down)", len(events))
	}
	if !events[0].Up {
		t.Errorf("reset request event 0 = down, want up")
	}
	// 全帧断言：10 字节链路头（05 64 len ctrl dst src）+ 4 字节用户数据
	// （全零，legacy padApp 保证 Length>=6）+ 2 字节 CRC。
	want := []byte{0x05, 0x64, 6, 0xC0, 0, 4, 1, 0, 0x87, 0x64, 0, 0, 0, 0, 0xFF, 0xFF}
	if len(events[0].Bytes) != 16 {
		t.Fatalf("reset frame length = %d, want 16 (10 header + 4 user data + 2 CRC)", len(events[0].Bytes))
	}
	if !bytes.Equal(events[0].Bytes, want) {
		t.Errorf("reset frame = % X, want % X", events[0].Bytes, want)
	}
	if events[1].Up {
		t.Errorf("reset response event = up, want down")
	}
}

// TestLayerGen_DirectionAlternation 交换类 scenario 的方向模式：
// up/down/up/down/down/up（reset 2 帧 + request + ack + respond + ack）。
func TestLayerGen_DirectionAlternation(t *testing.T) {
	events := collectEvents(t, basicSpec(&core.DNP3Config{Scenario: "read_class0"}))
	if len(events) != 6 {
		t.Fatalf("got %d events, want 6 (reset up/down + request + ack + respond + ack)", len(events))
	}
	want := []bool{true, false, true, false, false, true}
	for i, up := range want {
		if events[i].Up != up {
			t.Errorf("event %d Up=%v, want %v", i, events[i].Up, up)
		}
	}
}

// TestLayerGen_UnsolicitedFrameUp 非请求类 scenario（unsolicited）方向：
// 帧 up（outstation 主动上报）→ 确认 down。
func TestLayerGen_UnsolicitedFrameUp(t *testing.T) {
	events := collectEvents(t, basicSpec(&core.DNP3Config{Scenario: "unsolicited", LinkType: "outstation"}))
	if len(events) != 2 {
		t.Fatalf("got %d events, want 2 (unsolicited + confirm)", len(events))
	}
	if !events[0].Up {
		t.Errorf("unsolicited event 0 = down, want up (outstation initiates)")
	}
	if events[1].Up {
		t.Errorf("confirm event 1 = up, want down")
	}
}

// TestLayerGen_NilEmitMsg EmitMsg 未接线即报错（不能静默丢事件）。
func TestLayerGen_NilEmitMsg(t *testing.T) {
	gen := &DNP3Generator{}
	req := &layers.GenRequest{Meta: layers.FlowMeta{DNP3: &core.DNP3Config{}}}
	if err := gen.Generate(context.Background(), req); err == nil {
		t.Fatal("Generate with nil EmitMsg returned nil, want error")
	}
}

// TestLayerGen_NoConfig 无 DNP3 配置即报错。
func TestLayerGen_NoConfig(t *testing.T) {
	gen := &DNP3Generator{}
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

// TestLayerGen_UDPRejected transport=udp 显式拒绝（链无 UDP 混合流，
// 事件模式不产 UDP 前导字节帧）。
func TestLayerGen_UDPRejected(t *testing.T) {
	gen := &DNP3Generator{}
	req := &layers.GenRequest{
		Meta: layers.FlowMeta{DNP3: &core.DNP3Config{Transport: "udp"}},
		EmitMsg: func(ev layers.MessageEvent) error {
			return nil
		},
	}
	if err := gen.Generate(context.Background(), req); err == nil {
		t.Fatal("Generate with transport=udp returned nil, want error")
	}
}

// TestLayerGen_MultiOutstationRejected multi_outstation 多流展开显式拒绝
// （每条 outstation 是独立 flow，事件模式单流）。
func TestLayerGen_MultiOutstationRejected(t *testing.T) {
	gen := &DNP3Generator{}
	req := &layers.GenRequest{
		Meta: layers.FlowMeta{DNP3: &core.DNP3Config{MultiOutstation: &core.DNP3MultiOutstation{
			OutstationCount: 2, OutstationIPStart: "10.0.0.10", SrcPortStart: 20000,
		}}},
		EmitMsg: func(ev layers.MessageEvent) error {
			return nil
		},
	}
	if err := gen.Generate(context.Background(), req); err == nil {
		t.Fatal("Generate with multi_outstation returned nil, want error")
	}
}

// TestLayerGen_InvalidScenario 非法 scenario 报错（scenarioFrames 透传）。
func TestLayerGen_InvalidScenario(t *testing.T) {
	gen := &DNP3Generator{}
	req := &layers.GenRequest{
		Meta: layers.FlowMeta{DNP3: &core.DNP3Config{Scenario: "bogus"}},
		EmitMsg: func(ev layers.MessageEvent) error {
			return nil
		},
	}
	if err := gen.Generate(context.Background(), req); err == nil || !strings.Contains(err.Error(), "unsupported scenario") {
		t.Fatalf("Generate error = %v, want unsupported scenario error", err)
	}
}

// TestLayerGen_EmitMsgErrorPropagates emit 错误向上传播（不能吞）。
func TestLayerGen_EmitMsgErrorPropagates(t *testing.T) {
	gen := &DNP3Generator{}
	sentinel := errors.New("emit failed")
	req := &layers.GenRequest{
		Meta: layers.FlowMeta{DNP3: &core.DNP3Config{Scenario: "read_class0"}},
		EmitMsg: func(ev layers.MessageEvent) error {
			return sentinel
		},
	}
	if err := gen.Generate(context.Background(), req); !errors.Is(err, sentinel) {
		t.Fatalf("Generate error = %v, want sentinel", err)
	}
}

// TestLayerGen_CancelMidSequence 取消后停止产事件（精确计数）。
func TestLayerGen_CancelMidSequence(t *testing.T) {
	gen := &DNP3Generator{}
	ctx, cancel := context.WithCancel(context.Background())
	var mu sync.Mutex
	var events []layers.MessageEvent
	cancelled := false
	req := &layers.GenRequest{
		Meta: layers.FlowMeta{DNP3: &core.DNP3Config{Scenario: "read_class0"}},
		EmitMsg: func(ev layers.MessageEvent) error {
			mu.Lock()
			events = append(events, ev)
			n := len(events)
			mu.Unlock()
			if n == 2 { // 第 2 个事件后取消（reset 交换完成）
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

// TestLayerGen_ChainPlannerBytes 链级字节验证：ChainPlanner 驱动 [ip→tcp→dnp3]
// 完整链路（握手 3 + 数据 6 + 挥手 4 = 13 包），数据帧与 legacy 逐字节一致，
// 挥手为 TCPGenerator 标准 4 包（http 波 2 同款语义）。
func TestLayerGen_ChainPlannerBytes(t *testing.T) {
	cfg := &core.DNP3Config{Scenario: "read_class0"}
	spec := basicSpec(cfg)
	planner := layers.NewChainPlannerFromChain("dnp3", []layers.Layer{
		{Name: "ip"},
		{Name: "tcp"},
		{Name: "dnp3"},
	})
	ch, err := planner.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("ChainPlanner Plan: %v", err)
	}
	var pkts []core.PacketConfig
	for p := range ch {
		pkts = append(pkts, p)
	}
	if len(pkts) != 13 {
		t.Fatalf("got %d packets, want 13 (handshake 3 + data 6 + teardown 4)", len(pkts))
	}
	// 握手：SYN(up) → SYN-ACK(down) → ACK(up)；数据 6 帧；挥手 4 包。
	// 方向模式独立断言（up/down 错位时 flags 序列同构，仅方向能暴露）。
	wantFlags := []uint8{0x02, 0x12, 0x10, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x11, 0x10, 0x11, 0x10}
	wantDir := []string{"up", "down", "up", "up", "down", "up", "down", "down", "up", "up", "down", "down", "up"}
	for i, wf := range wantFlags {
		if pkts[i].L4.Flags != wf {
			t.Errorf("packet %d flags = 0x%02x, want 0x%02x", i, pkts[i].L4.Flags, wf)
		}
		if pkts[i].Direction != wantDir[i] {
			t.Errorf("packet %d direction = %s, want %s", i, pkts[i].Direction, wantDir[i])
		}
	}
	// 数据帧与 legacy 逐字节一致（方向 + payload）。legacy 用原始 cfg 的
	// 独立拷贝（链驱动会经 scenarioFrames 翻转 spec.DNP3 的 LinkFCB）。
	legacy := legacyDataFrames(t, basicSpec(cfg))
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
	// down 数据帧端口交换（legacy 同款：down 帧源端口 = DstPort）。
	if pkts[4].L4.SrcPort != 20000 || pkts[4].L4.DstPort != 12345 {
		t.Errorf("down data frame ports = %d/%d, want 20000/12345", pkts[4].L4.SrcPort, pkts[4].L4.DstPort)
	}
	// 挥手 seq 连续性：FIN(up) 继承最后 up 数据帧尾部 seq（ack up =
	// pkts[8]）；FIN(down) 继承最后 down 数据帧尾部 seq（respond down =
	// pkts[7]）。
	if pkts[9].L4.Seq != pkts[8].L4.Seq+uint32(len(pkts[8].Payload)) {
		t.Errorf("FIN(up) seq = %d, want up data tail %d", pkts[9].L4.Seq, pkts[8].L4.Seq+uint32(len(pkts[8].Payload)))
	}
	if pkts[11].L4.Seq != pkts[7].L4.Seq+uint32(len(pkts[7].Payload)) {
		t.Errorf("FIN(down) seq = %d, want down data tail %d", pkts[11].L4.Seq, pkts[7].L4.Seq+uint32(len(pkts[7].Payload)))
	}
}

// TestLayerGen_ChainPlannerTCPConfig 链级 cfg.Handshake/Termination 校准：
// 显式 false → tcp 层生成器不产握手/挥手（仅 6 数据帧）。
func TestLayerGen_ChainPlannerTCPConfig(t *testing.T) {
	f := false
	spec := basicSpec(&core.DNP3Config{Scenario: "read_class0", Handshake: &f, Termination: &f})
	planner := layers.NewChainPlannerFromChain("dnp3", []layers.Layer{
		{Name: "ip"},
		{Name: "tcp"},
		{Name: "dnp3"},
	})
	ch, err := planner.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("ChainPlanner Plan: %v", err)
	}
	var pkts []core.PacketConfig
	for p := range ch {
		pkts = append(pkts, p)
	}
	if len(pkts) != 6 {
		t.Fatalf("got %d packets, want 6 (no handshake/teardown)", len(pkts))
	}
	for i, p := range pkts {
		if p.L4.Flags != 0x18 {
			t.Errorf("packet %d flags = 0x%02x, want 0x18 (data only)", i, p.L4.Flags)
		}
	}
}

// TestLayerGen_ChainPlannerRejectsInvalidSpec 链级负向：非法 spec 经
// ChainPlanner 校验拒绝（validator 触发，planner 名必须为 "dnp3"）。
func TestLayerGen_ChainPlannerRejectsInvalidSpec(t *testing.T) {
	cfg := &core.DNP3Config{Scenario: "read_class0", AppSeq: 20} // AppSeq > 15
	spec := basicSpec(cfg)
	planner := layers.NewChainPlannerFromChain("dnp3", []layers.Layer{
		{Name: "ip"},
		{Name: "tcp"},
		{Name: "dnp3"},
	})
	_, err := planner.Plan(context.Background(), spec)
	if err == nil {
		t.Fatal("ChainPlanner Plan with invalid AppSeq returned nil, want error")
	}
}
