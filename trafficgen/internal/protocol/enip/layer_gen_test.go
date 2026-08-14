package enip

// ENIP terminal-layer generator tests (P4a)。ENIPGenerator 逐命令复用
// buildENIPPacket 产数据事件——事件序列与 legacy planUnit 的命令段在
// 方向/字节上逐命令一致（TCP 字段 seq/flags 由 tcp 层生成器负责，不比）；
// 链级测试通过 ChainPlanner 驱动 [ip→tcp→enip] 完整链路验证握手→数据→
// 挥手与 legacy 数据段字节一致。

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// collectEvents drives ENIPGenerator.Generate and collects the emitted
// message events in order.
func collectEvents(t *testing.T, spec core.FlowSpec) []layers.MessageEvent {
	t.Helper()
	var events []layers.MessageEvent
	gen := &ENIPGenerator{}
	req := &layers.GenRequest{
		Meta: layers.FlowMeta{
			SrcIP:   spec.SrcIP,
			DstIP:   spec.DstIP,
			SrcPort: spec.SrcPort,
			DstPort: spec.DstPort,
			ENIP:    spec.ENIP,
		},
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

// legacyCommandPackets runs the legacy planner and returns only the TCP
// command segments (skips UDP I/O frames, which the generator rejects).
func legacyCommandPackets(t *testing.T, spec core.FlowSpec) []core.PacketConfig {
	t.Helper()
	ch, err := (&Planner{}).Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("legacy Plan: %v", err)
	}
	var out []core.PacketConfig
	for c := range ch {
		if c.L4.Protocol == "tcp" {
			out = append(out, c)
		}
	}
	return out
}

// assertEventsMatchLegacy 逐命令断言事件方向与字节与 legacy 命令段一致。
func assertEventsMatchLegacy(t *testing.T, spec core.FlowSpec, events []layers.MessageEvent) {
	t.Helper()
	legacy := legacyCommandPackets(t, spec)
	if len(events) != len(legacy) {
		t.Fatalf("events = %d, legacy commands = %d", len(events), len(legacy))
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

// TestLayerGen_EventsMatchLegacyPlan 字节级对比：事件序列与 legacy
// planUnit 命令段在方向/payload 上逐命令一致。
func TestLayerGen_EventsMatchLegacyPlan(t *testing.T) {
	cases := []struct {
		name string
		cfg  *core.ENIPConfig
	}{
		{"nop keepalive", &core.ENIPConfig{Commands: []core.ENIPCommand{
			{Command: CmdNop, SessionHandle: 0x12345678},
		}}},
		{"register session request+response", &core.ENIPConfig{Commands: []core.ENIPCommand{
			{Command: CmdRegisterSession, ProtocolVersion: 1},
			{Command: CmdRegisterSession, Direction: "down", SessionHandle: 0x11223344, ProtocolVersion: 1},
		}}},
		{"sendrrdata get attribute single", &core.ENIPConfig{Commands: []core.ENIPCommand{
			{Command: CmdSendRRData, CIPService: CIPGetAttributeSingle, ClassID: 0x04, InstanceID: 1, AttributeID: 3},
		}}},
		{"forward open request", &core.ENIPConfig{Commands: []core.ENIPCommand{
			{Command: CmdSendRRData, CIPService: CIPForwardOpen, ConnSerialNum: 1, OrigVendorID: 2, OrigSerialNum: 3, O2TRPI: 4, T2ORPI: 5},
		}}},
		{"mixed multi-command", &core.ENIPConfig{Commands: []core.ENIPCommand{
			{Command: CmdRegisterSession, ProtocolVersion: 1},
			{Command: CmdRegisterSession, Direction: "down", SessionHandle: 0x11223344, ProtocolVersion: 1},
			{Command: CmdSendRRData, CIPService: CIPGetAttributeSingle, ClassID: 0x04, InstanceID: 1, AttributeID: 3},
			{Command: CmdUnRegisterSession, SessionHandle: 0x11223344},
		}}},
		{"down direction only", &core.ENIPConfig{Commands: []core.ENIPCommand{
			{Command: CmdListIdentity, Direction: "down"},
		}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec := basicSpec()
			spec.ENIP = tc.cfg
			events := collectEvents(t, spec)
			assertEventsMatchLegacy(t, spec, events)
		})
	}
}

// TestLayerGen_RegisterSessionHandleCarryover 状态机专项：RegisterSession
// 响应的 SessionHandle 回写为后续命令默认（legacy planUnit enip.go:730-736
// 同款语义），NOP 保活使用该句柄。
func TestLayerGen_RegisterSessionHandleCarryover(t *testing.T) {
	cfg := &core.ENIPConfig{Commands: []core.ENIPCommand{
		{Command: CmdRegisterSession, ProtocolVersion: 1},
		{Command: CmdRegisterSession, Direction: "down", SessionHandle: 0xABCD1234, ProtocolVersion: 1},
		{Command: CmdNop}, // SessionHandle 0 → 用回写的 0xABCD1234
	}}
	spec := basicSpec()
	spec.ENIP = cfg
	events := collectEvents(t, spec)
	if len(events) != 3 {
		t.Fatalf("events = %d, want 3", len(events))
	}
	got := binaryLe32(events[2].Bytes[4:8])
	if got != 0xABCD1234 {
		t.Errorf("NOP session handle = %#x, want 0xABCD1234 (carryover from RegisterSession response)", got)
	}
	assertEventsMatchLegacy(t, spec, events)
}

// TestLayerGen_FromResponseInjection H-2 专项：SendUnitData 经 from_response
// 从 SendRRData 响应提取 o2t_connection_id 注入 Connection Address item
// （legacy planUnit enip.go:705-727 同款）。
func TestLayerGen_FromResponseInjection(t *testing.T) {
	// 响应 payload = MR 头(4B: reply 0xD4/GeneralStatus 0/AddStatusSize 0) +
	// CIP body（O2T/T2O/ConnSerial）+ 填充，总长 ≥ 30B 使完整报文 ≥ 54B
	// （extractFromResponse 的 bodyStart+10 前置）。
	resp := make([]byte, 40)
	resp[0] = 0xD4
	resp[4] = 0x11 // O2T ID 低字节
	resp[5] = 0x22
	resp[6] = 0x33
	resp[7] = 0x44 // O2T = 0x44332211
	cfg := &core.ENIPConfig{Commands: []core.ENIPCommand{
		{Command: CmdSendRRData, Direction: "down", SessionHandle: 0x1111, Payload: resp},
		{Command: CmdSendUnitData, FromResponseField: "o2t_connection_id", SourceCommandIndex: 0,
			CPFItems: []core.CPFItem{
				{TypeID: TypeIDConnectionAddress, Length: 4, Data: []byte{0, 0, 0, 0}},
				{TypeID: TypeIDConnectedData, Length: 2, Data: []byte{0, 0}},
			}},
	}}
	spec := basicSpec()
	spec.ENIP = cfg
	events := collectEvents(t, spec)
	if len(events) != 2 {
		t.Fatalf("events = %d, want 2", len(events))
	}
	// SendUnitData 报文 = 24B 头 + SendRRData payload（6 前缀 + 2 count +
	// item1 头 4 + item1 数据 4 + item2 头 4 + item2 数据）。
	// Connection Address item 数据在 offset 36。
	got := binaryLe32(events[1].Bytes[36:40])
	if got != 0x44332211 {
		t.Errorf("SendUnitData conn id = %#x, want 0x44332211 (from_response injection)", got)
	}
	assertEventsMatchLegacy(t, spec, events)
}

// binaryLe32 reads a little-endian uint32.
func binaryLe32(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

// TestLayerGen_IODataRejected 负向：IOData（UDP I/O 帧）在 tcp 层链上无
// 表达载体，必须显式报错（不能静默丢帧）。
func TestLayerGen_IODataRejected(t *testing.T) {
	cfg := &core.ENIPConfig{
		Commands: []core.ENIPCommand{{Command: CmdNop, SessionHandle: 1}},
		IOData:   &core.ENIPIOData{FrameCount: 1, O2TConnectionID: 1, Payload: []byte("x")},
	}
	spec := basicSpec()
	spec.ENIP = cfg
	gen := &ENIPGenerator{}
	req := &layers.GenRequest{
		Meta: layers.FlowMeta{
			SrcIP: spec.SrcIP, DstIP: spec.DstIP,
			SrcPort: spec.SrcPort, DstPort: spec.DstPort,
			ENIP: cfg,
		},
		EmitMsg: func(ev layers.MessageEvent) error { return nil },
	}
	err := gen.Generate(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for io_data on tcp chain, got nil")
	}
	if !strings.Contains(err.Error(), "io_data") {
		t.Errorf("error = %q, want io_data-rejection message", err.Error())
	}
}

// TestLayerGen_NoCommands 负向：空命令列表必须显式报错（不能静默产 0 事件）。
func TestLayerGen_NoCommands(t *testing.T) {
	cfg := &core.ENIPConfig{}
	spec := basicSpec()
	spec.ENIP = cfg
	gen := &ENIPGenerator{}
	req := &layers.GenRequest{
		Meta: layers.FlowMeta{
			SrcIP: spec.SrcIP, DstIP: spec.DstIP,
			SrcPort: spec.SrcPort, DstPort: spec.DstPort,
			ENIP: cfg,
		},
		EmitMsg: func(ev layers.MessageEvent) error { return nil },
	}
	err := gen.Generate(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for empty commands, got nil")
	}
}

// TestLayerGen_UDPTransportRejected 负向：transport="udp"（legacy 合法，
// 命令发为 UDP 数据报）在 tcp 层链上无表达载体——显式拒绝，不能静默改发
// TCP 段（review HIGH-1a）。
func TestLayerGen_UDPTransportRejected(t *testing.T) {
	cfg := &core.ENIPConfig{
		Transport: "udp",
		Commands:  []core.ENIPCommand{{Command: CmdNop, SessionHandle: 1}},
	}
	spec := basicSpec()
	spec.ENIP = cfg
	gen := &ENIPGenerator{}
	req := &layers.GenRequest{
		Meta: layers.FlowMeta{
			SrcIP: spec.SrcIP, DstIP: spec.DstIP,
			SrcPort: spec.SrcPort, DstPort: spec.DstPort,
			ENIP: cfg,
		},
		EmitMsg: func(ev layers.MessageEvent) error { return nil },
	}
	err := gen.Generate(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for transport udp on tcp chain, got nil")
	}
	if !strings.Contains(err.Error(), "udp") {
		t.Errorf("error = %q, want transport-udp rejection message", err.Error())
	}
}

// TestLayerGen_MultiUnitRejected 负向：session_count/flow_count > 1（legacy
// 多单元展开，T-162/169/177）在链上无等价物——显式拒绝，不能静默单遍产
// 1 单元（review HIGH-1b）。
func TestLayerGen_MultiUnitRejected(t *testing.T) {
	cfg := &core.ENIPConfig{
		SessionCount: 2, // 多单元展开
		Commands:     []core.ENIPCommand{{Command: CmdNop, SessionHandle: 1}},
	}
	spec := basicSpec()
	spec.ENIP = cfg
	gen := &ENIPGenerator{}
	req := &layers.GenRequest{
		Meta: layers.FlowMeta{
			SrcIP: spec.SrcIP, DstIP: spec.DstIP,
			SrcPort: spec.SrcPort, DstPort: spec.DstPort,
			ENIP: cfg,
		},
		EmitMsg: func(ev layers.MessageEvent) error { return nil },
	}
	err := gen.Generate(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for session_count>1 on chain, got nil")
	}
	if !strings.Contains(err.Error(), "session_count") {
		t.Errorf("error = %q, want session_count rejection message", err.Error())
	}
}

// TestLayerGen_FromResponseSessionHandle H-2 专项：from_response 的
// session_handle 字段必须与 legacy 同款注入（review MEDIUM-3 修复）。
// extractFromResponse 对 session_handle 读响应 24B 头的 offset 4-8
// （enip.go:953-954）——即 down 命令自身的 SessionHandle。
func TestLayerGen_FromResponseSessionHandle(t *testing.T) {
	resp := make([]byte, 24)
	resp[0] = 0xD4 // reply
	cfg := &core.ENIPConfig{Commands: []core.ENIPCommand{
		{Command: CmdListIdentity, Direction: "down", SessionHandle: 0x11223344, Payload: resp},
		{Command: CmdNop, FromResponseField: "session_handle", SourceCommandIndex: 0},
	}}
	spec := basicSpec()
	spec.ENIP = cfg
	events := collectEvents(t, spec)
	if len(events) != 2 {
		t.Fatalf("events = %d, want 2", len(events))
	}
	got := binaryLe32(events[1].Bytes[4:8])
	if got != 0x11223344 {
		t.Errorf("NOP session handle = %#x, want 0x11223344 (from_response session_handle)", got)
	}
	assertEventsMatchLegacy(t, spec, events)
}

// TestLayerGen_UpRegisterSessionHandleCarryover 状态机专项：up 方向
// RegisterSession 带显式句柄时 legacy 同样回写（sessionHandle==0 条件，
// enip.go:730-736）——生成器必须同款（review HIGH-2 修复）。
func TestLayerGen_UpRegisterSessionHandleCarryover(t *testing.T) {
	cfg := &core.ENIPConfig{Commands: []core.ENIPCommand{
		// up 请求显式带句柄：legacy 回写为后续默认（会话已存在场景）。
		{Command: CmdRegisterSession, ProtocolVersion: 1, SessionHandle: 0xCAFEBABE},
		{Command: CmdNop}, // 用回写的 0xCAFEBABE
	}}
	spec := basicSpec()
	spec.ENIP = cfg
	events := collectEvents(t, spec)
	if len(events) != 2 {
		t.Fatalf("events = %d, want 2", len(events))
	}
	got := binaryLe32(events[1].Bytes[4:8])
	if got != 0xCAFEBABE {
		t.Errorf("NOP session handle = %#x, want 0xCAFEBABE (up RegisterSession carryover)", got)
	}
	assertEventsMatchLegacy(t, spec, events)
}

// TestLayerGen_SenderContextPtrPriority R43 专项：SenderContextPtr（用户显式
// 强制，含 0）优先级最高——生成器传参不影响（buildENIPPacket 内统一处理，
// enip.go:1087-1090；review MEDIUM-4 确认共享逻辑）。断言与 legacy 字节一致。
func TestLayerGen_SenderContextPtrPriority(t *testing.T) {
	zero := uint64(0)
	five := uint64(5)
	cases := []struct {
		name string
		ptr  *uint64
		val  uint64
		want uint64
	}{
		{"ptr zero forces zero", &zero, 0, 0},
		{"ptr five beats counter", &five, 0, 5},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &core.ENIPConfig{Commands: []core.ENIPCommand{
				{Command: CmdSendRRData, CIPService: CIPGetAttributeSingle,
					ClassID: 0x04, InstanceID: 1, AttributeID: 3,
					SenderContextPtr: tc.ptr, SenderContext: tc.val},
			}}
			spec := basicSpec()
			spec.ENIP = cfg
			events := collectEvents(t, spec)
			if len(events) != 1 {
				t.Fatalf("events = %d, want 1", len(events))
			}
			// SenderContext 是 24B ENIP 头 offset 12-20 的 8B LE。
			var got uint64
			for i := 0; i < 8; i++ {
				got |= uint64(events[0].Bytes[12+i]) << (8 * i)
			}
			if got != tc.want {
				t.Errorf("SenderContext = %d, want %d", got, tc.want)
			}
			assertEventsMatchLegacy(t, spec, events)
		})
	}
}

// TestLayerGen_ChainRejectsInvalidSpec 负向：未知 command 的 spec 经链上
// 协议级校验器（RegisterLayerValidator → enip Validate）拒绝——错误由
// Plan 返回，不静默吞成空流（生成器本身只做防御性检查；完整校验属
// LayerValidator 职责，直接调 Generate 不会触发）。
func TestLayerGen_ChainRejectsInvalidSpec(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP:   "10.0.0.1",
		DstIP:   "10.0.0.2",
		SrcPort: 49152,
		DstPort: DefaultPort,
		ENIP: &core.ENIPConfig{
			Commands: []core.ENIPCommand{{Command: 0xFFFF}}, // 未知 command → Validate 必拒
		},
	}
	chain := []layers.Layer{{Name: "ip"}, {Name: "tcp"}, {Name: "enip"}}
	// planner 名必须是 "enip"：protocolValidator 按 p.name 查注册表（生产
	// 路径 worker 用协议名构造 planner，测试同款）。
	p := layers.NewChainPlannerFromChain("enip", chain)
	_, err := p.Plan(context.Background(), spec)
	if err == nil {
		t.Fatal("expected validation error for unknown command, got nil")
	}
	if !strings.Contains(err.Error(), "unknown command") {
		t.Errorf("error = %q, want unknown-command message", err.Error())
	}
}

// TestLayerGen_NilConfig 负向：ENIP 配置缺失必须显式报错。
func TestLayerGen_NilConfig(t *testing.T) {
	gen := &ENIPGenerator{}
	req := &layers.GenRequest{
		Meta: layers.FlowMeta{
			SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
			SrcPort: 49152, DstPort: 44818,
		},
		EmitMsg: func(ev layers.MessageEvent) error { return nil },
	}
	err := gen.Generate(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for nil ENIP config, got nil")
	}
	if !strings.Contains(err.Error(), "ENIP config is nil") {
		t.Errorf("error = %q, want nil-config message", err.Error())
	}
}

// TestLayerGen_NilEmitMsg 负向：EmitMsg 未接线必须显式报错。
func TestLayerGen_NilEmitMsg(t *testing.T) {
	gen := &ENIPGenerator{}
	req := &layers.GenRequest{
		Meta: layers.FlowMeta{
			SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
			SrcPort: 49152, DstPort: 44818,
			ENIP: &core.ENIPConfig{Commands: []core.ENIPCommand{{Command: CmdNop}}},
		},
	}
	err := gen.Generate(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for nil EmitMsg, got nil")
	}
}

// TestLayerGen_EmitMsgCancelBlocks 负向：EmitMsg 阻塞时（传输层停止消费
// 事件流）ctx 取消必须解除阻塞并返回取消错误。
func TestLayerGen_EmitMsgCancelBlocks(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cfg := &core.ENIPConfig{Commands: []core.ENIPCommand{
		{Command: CmdRegisterSession, ProtocolVersion: 1},
		{Command: CmdRegisterSession, Direction: "down", SessionHandle: 1, ProtocolVersion: 1},
	}}
	gen := &ENIPGenerator{}
	req := &layers.GenRequest{
		Meta: layers.FlowMeta{
			SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
			SrcPort: 49152, DstPort: 44818,
			ENIP: cfg,
		},
		EmitMsg: func(ev layers.MessageEvent) error {
			<-ctx.Done() // 永不消费：模拟传输层已退出
			return nil
		},
	}
	done := make(chan error, 1)
	go func() {
		done <- gen.Generate(ctx, req)
	}()
	select {
	case err := <-done:
		t.Fatalf("Generate returned before cancel: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Generate error = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Generate hung after cancel (EmitMsg not context-aware)")
	}
}

// TestLayerGen_EmitMsgErrorPropagates 负向：EmitMsg 返回错误必须终止生成
// 并原样传播。
func TestLayerGen_EmitMsgErrorPropagates(t *testing.T) {
	cfg := &core.ENIPConfig{Commands: []core.ENIPCommand{
		{Command: CmdRegisterSession, ProtocolVersion: 1},
		{Command: CmdRegisterSession, Direction: "down", SessionHandle: 1, ProtocolVersion: 1},
	}}
	gen := &ENIPGenerator{}
	wantErr := errors.New("transport failed")
	req := &layers.GenRequest{
		Meta: layers.FlowMeta{
			SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
			SrcPort: 49152, DstPort: 44818,
			ENIP: cfg,
		},
		EmitMsg: func(ev layers.MessageEvent) error { return wantErr },
	}
	err := gen.Generate(context.Background(), req)
	if !errors.Is(err, wantErr) {
		t.Fatalf("Generate error = %v, want %v", err, wantErr)
	}
}

// TestLayerGen_CancelMidSequence 负向：ctx 取消必须终止生成，事件数精确
// 停在取消点（emitMsg 开头 ctx 检查是确定性的，cancel 后不再发送）。
func TestLayerGen_CancelMidSequence(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cfg := &core.ENIPConfig{Commands: []core.ENIPCommand{
		{Command: CmdRegisterSession, ProtocolVersion: 1},
		{Command: CmdRegisterSession, Direction: "down", SessionHandle: 1, ProtocolVersion: 1},
		{Command: CmdSendRRData, CIPService: CIPGetAttributeSingle, ClassID: 0x04, InstanceID: 1, AttributeID: 3},
		{Command: CmdUnRegisterSession, SessionHandle: 1},
	}}
	gen := &ENIPGenerator{}
	var mu sync.Mutex
	count := 0
	req := &layers.GenRequest{
		Meta: layers.FlowMeta{
			SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
			SrcPort: 49152, DstPort: 44818,
			ENIP: cfg,
		},
		EmitMsg: func(ev layers.MessageEvent) error {
			mu.Lock()
			count++
			n := count
			mu.Unlock()
			if n == 2 {
				cancel()
			}
			return nil
		},
	}
	err := gen.Generate(ctx, req)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Generate error = %v, want context.Canceled", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if count != 2 {
		t.Errorf("emitted %d events, want exactly 2 (cancel at event 2; cancel 后不得继续发)", count)
	}
}

// TestLayerGen_ChainPlannerBytes 端到端：ChainPlanner 驱动 [ip→tcp→enip]
// 链。tcp 层生成器全权处理 TCP 语义（握手 3 包 → 数据段（MSS 分段，段间
// 无独立 ACK）→ 挥手 4 包）；数据段字节与 legacy 命令段逐字节一致。
func TestLayerGen_ChainPlannerBytes(t *testing.T) {
	cfg := &core.ENIPConfig{Commands: []core.ENIPCommand{
		{Command: CmdRegisterSession, ProtocolVersion: 1},
		{Command: CmdRegisterSession, Direction: "down", SessionHandle: 0x11223344, ProtocolVersion: 1},
		{Command: CmdSendRRData, CIPService: CIPGetAttributeSingle, ClassID: 0x04, InstanceID: 1, AttributeID: 3},
	}}
	spec := core.FlowSpec{
		SrcIP:   "10.0.0.100",
		DstIP:   "10.0.0.1",
		SrcPort: 49152,
		DstPort: DefaultPort,
		SrcMAC:  "aa:bb:cc:dd:ee:ff",
		DstMAC:  "11:22:33:44:55:66",
		IPFlags: core.IPFlagDF,
		TTL:     128,
		VLAN:    &core.VLAN{ID: 100},
		ENIP:    cfg,
	}
	chain := []layers.Layer{{Name: "ip"}, {Name: "tcp"}, {Name: "enip"}}
	p := layers.NewChainPlannerFromChain("test-enip", chain)
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("chain Plan: %v", err)
	}
	got := drain(ch)

	// 包序：SYN → SYN-ACK → ACK → 3 数据段 → FIN → ACK → FIN → ACK。
	if len(got) != 3+3+4 {
		t.Fatalf("chain packets = %d, want 10 (3 handshake + 3 data + 4 teardown)", len(got))
	}
	flagAt := func(i int) uint8 { return got[i].L4.Flags }
	wantFlags := []uint8{0x02, 0x12, 0x10, 0x18, 0x18, 0x18, 0x11, 0x10, 0x11, 0x10}
	for i, f := range wantFlags {
		if flagAt(i) != f {
			t.Errorf("packet[%d] flags = %#x, want %#x", i, flagAt(i), f)
		}
	}
	// 握手 seq 推进：SYN seq=clientSeq，SYN-ACK ack=clientSeq+1，ACK seq=clientSeq+1。
	clientSeq := got[0].L4.Seq
	if got[1].L4.Ack != clientSeq+1 {
		t.Errorf("SYN-ACK ack = %d, want %d (clientSeq+1)", got[1].L4.Ack, clientSeq+1)
	}
	if got[2].L4.Seq != clientSeq+1 {
		t.Errorf("ACK seq = %d, want %d (clientSeq+1)", got[2].L4.Seq, clientSeq+1)
	}

	// 数据段（0x18）与 legacy 命令段逐字节一致。
	legacy := legacyCommandPackets(t, spec)
	if len(legacy) != 3 {
		t.Fatalf("legacy commands = %d, want 3", len(legacy))
	}
	dataIdx := 0
	for i := 3; i < 6; i++ {
		if !bytes.Equal(got[i].Payload, legacy[dataIdx].Payload) {
			t.Errorf("data[%d] payload = % X, legacy = % X", dataIdx, got[i].Payload, legacy[dataIdx].Payload)
		}
		// 数据段方向与 legacy 一致。
		wantUp := legacy[dataIdx].Direction == "up"
		if (got[i].Direction == "up") != wantUp {
			t.Errorf("data[%d] direction = %s, legacy = %s", dataIdx, got[i].Direction, legacy[dataIdx].Direction)
		}
		// down 段端口交换。
		if !wantUp {
			if got[i].L4.SrcPort != DefaultPort || got[i].L4.DstPort != 49152 {
				t.Errorf("data[%d] down ports = %d->%d, want %d->%d",
					dataIdx, got[i].L4.SrcPort, got[i].L4.DstPort, DefaultPort, 49152)
			}
		}
		dataIdx++
	}

	// flow 级字段回填（LOW-2 同款）：DF/VLAN/TTL/IPID 必须实际落到链输出。
	for i := range got {
		if got[i].L3.Protocol != core.ProtocolTCP {
			t.Errorf("packet[%d] L3.Protocol = %d, want TCP", i, got[i].L3.Protocol)
		}
		if got[i].L3.Flags&core.IPFlagDF == 0 {
			t.Errorf("packet[%d] L3.Flags = %#x, want DF (%#x)", i, got[i].L3.Flags, core.IPFlagDF)
		}
		if got[i].L2.VLAN.ID != uint16(100) {
			t.Errorf("packet[%d] VLAN.ID = %d, want 100", i, got[i].L2.VLAN.ID)
		}
		if got[i].L3.TTL != 128 {
			t.Errorf("packet[%d] TTL = %d, want 128 (spec.TTL)", i, got[i].L3.TTL)
		}
		if i > 0 && got[i].L3.IPID <= got[i-1].L3.IPID {
			t.Errorf("packet[%d] IPID = %d, want strictly greater than previous %d",
				i, got[i].L3.IPID, got[i-1].L3.IPID)
		}
	}
}
