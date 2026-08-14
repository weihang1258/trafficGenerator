package gbt32960

// GBT32960 terminal-layer generator tests (P4a)。GBT32960Generator 复用
// buildVehicleMessages/buildPlatformMessages 状态机产事件——事件序列与
// legacy Plan 的数据帧（flags=0x18 PSH-ACK，握手/挥手过滤后）在方向/字节
// 上逐消息一致；链级测试通过 ChainPlanner 驱动 [ip→tcp→gbt32960] 完整
// 链路验证握手→数据→挥手与 legacy 数据帧字节一致。默认化（role/vinPad/
// serial/subsys/enc）与 BCC 注入行为与 legacy Plan 对齐，测试覆盖默认值
// 与显式值两路径。

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

// vehicleCfg returns a base vehicle config with deterministic times.
func vehicleCfg() *GBT32960Config {
	return &GBT32960Config{
		Role:                         "vehicle",
		VIN:                          "LXXXXXXXXXXXXXXX1",
		SIM:                          "13800138000",
		LoginSerialNumber:            1,
		LoginTime:                    "2026-08-03T14:30:00+08:00",
		RechargeableSubsysCount:      1,
		RechargeableSubsysCodeLength: 1,
		RechargeableSubsysCodes:      []string{"00"},
	}
}

// collectEvents drives GBT32960Generator.Generate and collects the emitted
// message events in order. 值拷贝 cfg：事件生成与 legacy 对比各持独立实例
// （build* 纯函数不原地改配置，拷贝为防御性惯例）。
func collectEvents(t *testing.T, spec core.FlowSpec) []layers.MessageEvent {
	t.Helper()
	var events []layers.MessageEvent
	gen := &GBT32960Generator{}
	meta := layers.FlowMeta{
		SrcIP:   spec.SrcIP,
		DstIP:   spec.DstIP,
		SrcPort: spec.SrcPort,
		DstPort: spec.DstPort,
	}
	if spec.GBT32960 != nil {
		c2 := *spec.GBT32960
		meta.GBT32960 = &c2
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

// legacyDataFrames runs the legacy planner and returns the GBT32960 data
// frames (skip TCP handshake/teardown)。数据帧 flags=0x18 PSH-ACK
// （gbt32960.go:716-731），与事件一一对应。
func legacyDataFrames(t *testing.T, spec core.FlowSpec) []core.PacketConfig {
	t.Helper()
	spec2 := spec
	if spec.GBT32960 != nil {
		c2 := *spec.GBT32960
		spec2.GBT32960 = &c2
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
// 方向/payload 上逐消息一致。覆盖核心场景矩阵（vehicle/platform 状态机各
// 阶段 + BCC 注入）。显式时间保证确定性（reportTimes/logoutTime 默认推导
// 自 LoginTime，配置时间全显式时字节固定）。
func TestLayerGen_EventsMatchLegacyPlan(t *testing.T) {
	cases := []struct {
		name string
		cfg  *GBT32960Config
	}{
		{"vehicle default", vehicleCfg()},
		{"vehicle + reports", func() *GBT32960Config {
			c := vehicleCfg()
			c.Reports = []GBT32960Report{
				{Time: "2026-08-03T14:31:00+08:00"},
				{Time: "2026-08-03T14:31:30+08:00"},
			}
			return c
		}()},
		{"vehicle + reissue", func() *GBT32960Config {
			c := vehicleCfg()
			c.ReissueReports = []GBT32960Report{
				{Time: "2026-08-03T14:29:00+08:00"}, // 补报历史时间
			}
			return c
		}()},
		{"vehicle + remote control", func() *GBT32960Config {
			c := vehicleCfg()
			c.Reports = []GBT32960Report{{Time: "2026-08-03T14:31:00+08:00"}}
			c.RemoteControl = &GBT32960RemoteControl{
				ControlType: 1, Params: "00", ResponseFlags: "01",
			}
			return c
		}()},
		{"platform", &GBT32960Config{
			Role: "platform", PlatformID: "100000LVE00000000",
		}},
		{"platform + heartbeat", &GBT32960Config{
			Role: "platform", PlatformID: "100000LVE00000000",
			HeartbeatCount: 2,
			PlatformLogin: &GBT32960PlatformLogin{
				User: "platform01", Password: "pwd1234567890abcdef",
			},
		}},
		{"bcc injection index 0", func() *GBT32960Config {
			c := vehicleCfg()
			c.InjectBCCError = true
			c.BCCErrorIndex = 0
			return c
		}()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec := gbtSpec(0)
			c2 := *tc.cfg
			spec.GBT32960 = &c2
			events := collectEvents(t, spec)
			assertEventsMatchLegacy(t, spec, events)
		})
	}
}

// TestLayerGen_EventsMatchLegacyDefaults 默认化路径（legacy gbt32960.go:
// 545-600 同款）：role 空 → vehicle、LogoutSerialNumber 0 → 继承
// loginSerial、enc 空 → 01。LoginSerialNumber 0 / subsys 0 的默认化在
// legacy 不可达（V7/V30/V35 在 Validate 拒绝显式 0），不在此覆盖。
// 默认化只影响字节内容，不影响消息个数；与 legacy 对比即可验证。
func TestLayerGen_EventsMatchLegacyDefaults(t *testing.T) {
	c := vehicleCfg()
	c.Role = ""
	c.LogoutSerialNumber = 0
	c.EncryptRule = ""
	spec := gbtSpec(0)
	c2 := *c
	spec.GBT32960 = &c2
	events := collectEvents(t, spec)
	assertEventsMatchLegacy(t, spec, events)
	// 登录消息字节级抽查：enc 默认 0x01（encryptRuleByte 空 → EncNone）。
	// Wire 布局：start_flag(2) | cmd(1) | resp(1) | VIN(17) | enc(1) |
	// data_len(2) | data | BCC —— enc 在 offset 21。
	if len(events[0].Bytes) < 22 {
		t.Fatalf("login event too short")
	}
	if events[0].Bytes[21] != EncNone {
		t.Errorf("login enc byte = 0x%02x, want 0x01 (default)", events[0].Bytes[21])
	}
}

// TestLayerGen_BCCFlip 独立校验 BCC 注入生效（不依赖 legacy 对比）：
// events[0] 的 BCC 与独立 XOR 计算值差 0x01（覆盖 T-GBT-003 在事件层的
// 同款断言）。
func TestLayerGen_BCCFlip(t *testing.T) {
	spec := gbtSpec(0)
	spec.GBT32960.InjectBCCError = true
	spec.GBT32960.BCCErrorIndex = 0
	events := collectEvents(t, spec)
	if len(events) == 0 {
		t.Fatal("no events emitted")
	}
	msg := events[0].Bytes
	var correct byte
	for i := 2; i < len(msg)-1; i++ {
		correct ^= msg[i]
	}
	if got := msg[len(msg)-1]; got != correct^0x01 {
		t.Errorf("injected BCC = 0x%02x, want 0x%02x (correct ^ 0x01)", got, correct^0x01)
	}
	if !events[0].Up {
		t.Errorf("event 0 Up = false, want true (0x01 login is uplink)")
	}
}

// TestLayerGen_ChainPlannerBytes 链级字节验证：ChainPlanner 驱动
// [ip→tcp→gbt32960] 完整链路（握手 3 + 数据 4 + 挥手 4 = 11 包），数据帧
// 与 legacy 逐字节一致。挥手为 TCPGenerator 标准 4 包（FIN|ACK up → ACK
// down → FIN|ACK down → ACK up，generator.go:874-943）——legacy gbt32960
// 是 3 包挥手（FIN up → FIN down → ACK up，gbt32960.go:754-762），层模型
// 意图的文档化分歧（与 dnp3/doip 链测试同款断言形状）。
func TestLayerGen_ChainPlannerBytes(t *testing.T) {
	spec := gbtSpec(1000) // 确定性 ISN
	planner := layers.NewChainPlannerFromChain("gbt32960", []layers.Layer{
		{Name: "ip"},
		{Name: "tcp"},
		{Name: "gbt32960"},
	})
	ch, err := planner.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("ChainPlanner Plan: %v", err)
	}
	var pkts []core.PacketConfig
	for p := range ch {
		pkts = append(pkts, p)
	}
	// vehicle default：4 条消息（0x01 up + 0x0C down + 0x04 up + 0x0C down）。
	if len(pkts) != 11 {
		t.Fatalf("got %d packets, want 11 (handshake 3 + data 4 + teardown 4)", len(pkts))
	}
	// 握手：SYN(up) → SYN-ACK(down) → ACK(up)；数据 4 帧；挥手 4 包。
	// 方向模式独立断言（up/down 错位时 flags 序列同构，仅方向能暴露）。
	wantFlags := []uint8{0x02, 0x12, 0x10, 0x18, 0x18, 0x18, 0x18, 0x11, 0x10, 0x11, 0x10}
	wantDir := []string{"up", "down", "up", "up", "down", "up", "down", "up", "down", "down", "up"}
	for i, wf := range wantFlags {
		if pkts[i].L4.Flags != wf {
			t.Errorf("packet %d flags = 0x%02x, want 0x%02x", i, pkts[i].L4.Flags, wf)
		}
		if pkts[i].Direction != wantDir[i] {
			t.Errorf("packet %d direction = %s, want %s", i, pkts[i].Direction, wantDir[i])
		}
	}
	// 数据帧与 legacy 逐字节一致（方向 + payload）。
	legacy := legacyDataFrames(t, spec)
	if len(legacy) != 4 {
		t.Fatalf("legacy data frames = %d, want 4", len(legacy))
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
	// down 数据帧端口交换（legacy 同款：down 帧源端口 = DstPort 10020）。
	if pkts[4].L4.SrcPort != 10020 || pkts[4].L4.DstPort != 20000 {
		t.Errorf("down data frame ports = %d/%d, want 10020/20000", pkts[4].L4.SrcPort, pkts[4].L4.DstPort)
	}
	// 挥手 seq 连续性：FIN(up) 继承最后 up 数据帧尾部 seq（pkts[5] =
	// 0x04 logout up）；FIN(down) 继承最后 down 数据帧尾部 seq（pkts[6] =
	// 0x0C ack down）。
	if pkts[7].L4.Seq != pkts[5].L4.Seq+uint32(len(pkts[5].Payload)) {
		t.Errorf("FIN(up) seq = %d, want up data tail %d", pkts[7].L4.Seq, pkts[5].L4.Seq+uint32(len(pkts[5].Payload)))
	}
	if pkts[9].L4.Seq != pkts[6].L4.Seq+uint32(len(pkts[6].Payload)) {
		t.Errorf("FIN(down) seq = %d, want down data tail %d", pkts[9].L4.Seq, pkts[6].L4.Seq+uint32(len(pkts[6].Payload)))
	}
}

// TestLayerGen_ChainPlannerDstPortDefault 目的端口默认：spec.DstPort=0 →
// 10020（GB/T 32960.3-2016 平台监听端口；validateSpecBase gbt32960 分支，
// strategy_convert mapToFlowSpec 同款默认）。
func TestLayerGen_ChainPlannerDstPortDefault(t *testing.T) {
	spec := gbtSpec(1000)
	spec.DstPort = 0
	planner := layers.NewChainPlannerFromChain("gbt32960", []layers.Layer{
		{Name: "ip"},
		{Name: "tcp"},
		{Name: "gbt32960"},
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
	if pkts[0].L4.DstPort != 10020 {
		t.Errorf("SYN dst_port = %d, want 10020 (default)", pkts[0].L4.DstPort)
	}
}

// TestLayerGen_NilEmitMsg EmitMsg 未接线即报错（不能静默丢事件）。
func TestLayerGen_NilEmitMsg(t *testing.T) {
	gen := &GBT32960Generator{}
	req := &layers.GenRequest{Meta: layers.FlowMeta{GBT32960: vehicleCfg()}}
	if err := gen.Generate(context.Background(), req); err == nil {
		t.Fatal("Generate with nil EmitMsg returned nil, want error")
	}
}

// TestLayerGen_NoConfig 无 GBT32960 配置即报错（不产任何事件）。
func TestLayerGen_NoConfig(t *testing.T) {
	gen := &GBT32960Generator{}
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

// TestLayerGen_BCCIndexOutOfRange BCC 注入索引越界：生成器在 build/emit
// 任何消息**之前**同步报错（0 事件）；链级经 validator（legacy Validate
// V23/V24 同款）在 Plan 时同步拒绝——两者都不能静默产出 BCC 未注入的
// 正常流。
func TestLayerGen_BCCIndexOutOfRange(t *testing.T) {
	spec := gbtSpec(0)
	spec.GBT32960.InjectBCCError = true
	spec.GBT32960.BCCErrorIndex = 999
	// 生成器级：显式错误 + 0 事件。
	gen := &GBT32960Generator{}
	var events []layers.MessageEvent
	c2 := *spec.GBT32960
	req := &layers.GenRequest{
		Meta: layers.FlowMeta{GBT32960: &c2},
		EmitMsg: func(ev layers.MessageEvent) error {
			events = append(events, ev)
			return nil
		},
	}
	err := gen.Generate(context.Background(), req)
	if err == nil || !strings.Contains(err.Error(), "exceeds message count") {
		t.Fatalf("Generate error = %v, want exceeds message count", err)
	}
	if len(events) != 0 {
		t.Fatalf("emitted %d events on invalid BCC index, want 0 (bounds checked before any emit)", len(events))
	}
	// 链级：validator 同步拒绝（Plan 报错，非空流）。
	planner := layers.NewChainPlannerFromChain("gbt32960", []layers.Layer{
		{Name: "ip"},
		{Name: "tcp"},
		{Name: "gbt32960"},
	})
	if _, err := planner.Plan(context.Background(), spec); err == nil {
		t.Fatal("ChainPlanner Plan with out-of-range BCCErrorIndex returned nil, want error")
	}
}

// TestLayerGen_ChainPlannerRejectsInvalidSpec 链级负向：非法 spec 经
// ChainPlanner 校验拒绝（validator 触发，planner 名必须为 "gbt32960"）。
func TestLayerGen_ChainPlannerRejectsInvalidSpec(t *testing.T) {
	planner := layers.NewChainPlannerFromChain("gbt32960", []layers.Layer{
		{Name: "ip"},
		{Name: "tcp"},
		{Name: "gbt32960"},
	})
	spec := gbtSpec(1000)
	spec.GBT32960.Role = "bogus"
	if _, err := planner.Plan(context.Background(), spec); err == nil || !strings.Contains(err.Error(), "invalid Role") {
		t.Fatalf("Plan with invalid role error = %v, want invalid Role", err)
	}
	spec = gbtSpec(1000)
	spec.GBT32960.VIN = "LXXXXXXXXXXXXXXXO" // I/O/Q 不允许（V3b）
	if _, err := planner.Plan(context.Background(), spec); err == nil || !strings.Contains(err.Error(), "invalid char") {
		t.Fatalf("Plan with invalid VIN error = %v, want invalid char", err)
	}
}

// TestLayerGen_EmitMsgErrorPropagates emit 错误向上传播（不能吞）。
func TestLayerGen_EmitMsgErrorPropagates(t *testing.T) {
	gen := &GBT32960Generator{}
	sentinel := errors.New("emit failed")
	c2 := *vehicleCfg()
	req := &layers.GenRequest{
		Meta: layers.FlowMeta{GBT32960: &c2},
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
	gen := &GBT32960Generator{}
	ctx, cancel := context.WithCancel(context.Background())
	var mu sync.Mutex
	var events []layers.MessageEvent
	cancelled := false
	c2 := *vehicleCfg()
	req := &layers.GenRequest{
		Meta: layers.FlowMeta{GBT32960: &c2},
		EmitMsg: func(ev layers.MessageEvent) error {
			mu.Lock()
			events = append(events, ev)
			n := len(events)
			mu.Unlock()
			if n == 2 { // 第 2 个事件后取消（0x01 login + 0x0C ack 完成）
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
