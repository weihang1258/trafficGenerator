package a2a

// A2A terminal-layer generator tests (P4a)。A2AGenerator 逐任务复用 legacy
// 纯函数产数据事件——事件序列与 legacy planUnit 的数据段在方向/字节上
// 逐任务一致（TCP 字段 seq/flags 由 tcp 层生成器负责，不比）；链级测试
// 通过 ChainPlanner 驱动 [ip→tcp→a2a] 完整链路验证握手→数据→挥手与
// legacy 数据段字节一致。

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// validA2AConfig builds a minimal valid A2A config (1 message/send task)。
func validA2AConfig() *A2AConfig {
	return &A2AConfig{
		BaseURL: "https://agent.example.com/a2a",
		AgentCard: &A2AAgentCard{
			Name:               "test-agent",
			Description:        "Test agent",
			URL:                "https://agent.example.com/a2a",
			Version:            "1.0.0",
			ProtocolVersion:    "0.3.0",
			Capabilities:       &A2AAgentCapabilities{},
			Skills:             []A2AAgentSkill{{ID: "skill-1", Name: "test", Description: "test", Tags: []string{"test"}}},
			DefaultInputModes:  []string{"text"},
			DefaultOutputModes: []string{"text"},
		},
		Tasks: []A2ATask{
			{
				Method: MethodMessageSend,
				Message: A2AMessage{
					Role:      "user",
					Parts:     []A2APart{{Kind: "text", Text: "hello"}},
					MessageID: "m-001",
					Kind:      DefaultMessageKind,
				},
				RequestID: json.RawMessage(`"req-001"`),
				Response: A2ATaskResponse{
					Result: json.RawMessage(`{"kind":"task","id":"task-001","contextId":"ctx-001","status":{"state":"completed"}}`),
				},
			},
		},
	}
}

// basicSpec builds the flow spec carrying cfg as A2AConfig JSON in Payload
// (strategy_convert.go a2a case 同款)。
func basicSpec(cfg *A2AConfig) core.FlowSpec {
	b, _ := json.Marshal(cfg)
	return core.FlowSpec{
		SrcIP:   "192.168.1.1",
		DstIP:   "192.168.1.2",
		SrcPort: 12345,
		DstPort: 443,
		SrcMAC:  "aa:bb:cc:dd:ee:ff",
		DstMAC:  "11:22:33:44:55:66",
		Payload: b,
	}
}

// collectEvents drives A2AGenerator.Generate and collects the emitted
// message events in order.
func collectEvents(t *testing.T, spec core.FlowSpec) []layers.MessageEvent {
	t.Helper()
	var events []layers.MessageEvent
	gen := &A2AGenerator{}
	req := &layers.GenRequest{
		Meta: layers.FlowMeta{
			SrcIP:   spec.SrcIP,
			DstIP:   spec.DstIP,
			SrcPort: spec.SrcPort,
			DstPort: spec.DstPort,
			Payload: spec.Payload,
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

// legacyDataPackets runs the legacy planner and returns the data segments
// (skip handshake/teardown/standalone-ACK control packets)。lazy ACKPolicy
// 下 legacy 无独立 ACK，数据段序列与事件序列一一对应。
func legacyDataPackets(t *testing.T, spec core.FlowSpec) []core.PacketConfig {
	t.Helper()
	ch, err := (&Planner{}).Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("legacy Plan: %v", err)
	}
	var out []core.PacketConfig
	for c := range ch {
		if c.L4.Flags == 0x18 { // PSH-ACK data segment
			out = append(out, c)
		}
	}
	return out
}

// assertEventsMatchLegacyData 逐任务断言事件方向与字节与 legacy 数据段一致
// （lazy ACKPolicy 下 legacy 每任务只有 request/response 两个数据段）。
func assertEventsMatchLegacyData(t *testing.T, spec core.FlowSpec, events []layers.MessageEvent) {
	t.Helper()
	legacy := legacyDataPackets(t, spec)
	if len(events) != len(legacy) {
		t.Fatalf("events = %d, legacy data segments = %d", len(events), len(legacy))
	}
	for i, ev := range events {
		pc := legacy[i]
		if (ev.Up && pc.Direction != "up") || (!ev.Up && pc.Direction != "down") {
			t.Errorf("event[%d] Up=%v, legacy Direction=%s", i, ev.Up, pc.Direction)
		}
		if !bytes.Equal(ev.Bytes, pc.Payload) {
			t.Errorf("event[%d] payload = %q, legacy = %q", i, string(ev.Bytes), string(pc.Payload))
		}
	}
}

// TestLayerGen_EventsMatchLegacyPlan 字节级对比：事件序列与 legacy 数据段在
// 方向/payload 上逐任务一致（lazy ACKPolicy = legacy 无独立 ACK，可比）。
func TestLayerGen_EventsMatchLegacyPlan(t *testing.T) {
	cases := []struct {
		name string
		cfg  *A2AConfig
	}{
		{"single message/send", validA2AConfig()},
		{"agent card discovery", func() *A2AConfig {
			cfg := validA2AConfig()
			cfg.Discover = true
			return cfg
		}()},
		{"multiple tasks", func() *A2AConfig {
			cfg := validA2AConfig()
			cfg.Tasks = append(cfg.Tasks, A2ATask{
				Method: MethodTasksGet,
				TaskID: "task-002",
				RequestID: json.RawMessage(`"req-002"`),
				Response: A2ATaskResponse{
					Result: json.RawMessage(`{"kind":"task","id":"task-002","contextId":"ctx-001","status":{"state":"completed"}}`),
				},
			})
			return cfg
		}()},
		{"sse streaming", func() *A2AConfig {
			cfg := validA2AConfig()
			cfg.Tasks[0].Method = MethodMessageStream // V8: 仅 message/stream 等可 Streaming
			cfg.Tasks[0].Streaming = true
			cfg.Tasks[0].SSEEvents = []A2ASSEEvent{
				{Kind: "task", Task: &A2ATaskObject{
					ID: "task-001", ContextID: "ctx-001",
					Status: A2ATaskStatus{State: "working"},
				}},
				{Kind: "status-update", StatusUpdate: &A2ATaskStatusUpdateEvent{
					TaskID: "task-001", ContextID: "ctx-001", Kind: "status-update",
					Status: A2ATaskStatus{State: "completed"}, Final: true,
				}},
			}
			return cfg
		}()},
		{"jsonrpc error response", func() *A2AConfig {
			cfg := validA2AConfig()
			cfg.Tasks[0].Response = A2ATaskResponse{
				Error: &A2AError{Code: -32601, Message: "method not found"},
			}
			return cfg
		}()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec := basicSpec(tc.cfg)
			spec.TCP = &core.TCPConfig{}
			events := collectEvents(t, spec)
			assertEventsMatchLegacyData(t, spec, events)
		})
	}
}

// TestLayerGen_AgentCardDiscoveryOrdering 事件顺序断言：Agent Card GET 在
// task POST 之前，方向 up/down 交替。
func TestLayerGen_AgentCardDiscoveryOrdering(t *testing.T) {
	cfg := validA2AConfig()
	cfg.Discover = true
	events := collectEvents(t, basicSpec(cfg))
	// GET (up) → 200 (down) → POST (up) → 200 (down)
	if len(events) != 4 {
		t.Fatalf("got %d events, want 4 (agent card + task)", len(events))
	}
	if !events[0].Up || !strings.Contains(string(events[0].Bytes), "GET /.well-known/agent.json") {
		t.Errorf("event 0 = %v, want up GET agent card: %q", events[0].Up, string(events[0].Bytes))
	}
	if events[1].Up || !strings.Contains(string(events[1].Bytes), "HTTP/1.1 200") {
		t.Errorf("event 1 = %v, want down 200: %q", events[1].Up, string(events[1].Bytes))
	}
	if !events[2].Up || !strings.Contains(string(events[2].Bytes), "POST /a2a") {
		t.Errorf("event 2 = %v, want up POST: %q", events[2].Up, string(events[2].Bytes))
	}
	if events[3].Up {
		t.Errorf("event 3 = up, want down 200")
	}
}

// TestLayerGen_LastTaskConnectionClose 最后 task 且 termination=true 时
// Connection: close（legacy a2a.go:593-595 同款）。
func TestLayerGen_LastTaskConnectionClose(t *testing.T) {
	cfg := validA2AConfig()
	events := collectEvents(t, basicSpec(cfg))
	if !strings.Contains(string(events[0].Bytes), "Connection: close\r\n") {
		t.Errorf("last task request missing Connection: close: %q", string(events[0].Bytes))
	}
}

// TestLayerGen_TerminationFalseKeepsKeepAlive termination=false 时最后 task
// 保持 keep-alive（legacy a2a.go:593-595 同款）。
func TestLayerGen_TerminationFalseKeepsKeepAlive(t *testing.T) {
	cfg := validA2AConfig()
	f := false
	cfg.TCP.Termination = &f
	events := collectEvents(t, basicSpec(cfg))
	if !strings.Contains(string(events[0].Bytes), "Connection: keep-alive\r\n") {
		t.Errorf("last task request should keep keep-alive when termination=false: %q", string(events[0].Bytes))
	}
}

// TestLayerGen_SSEChunkedFraming Streaming=true 时响应为 chunked 帧
// （legacy a2a.go:611 同款，Transfer-Encoding + 16 进制长度 + 结束 chunk）。
func TestLayerGen_SSEChunkedFraming(t *testing.T) {
	cfg := validA2AConfig()
	cfg.Tasks[0].Method = MethodMessageStream
	cfg.Tasks[0].Streaming = true
	cfg.Tasks[0].SSEEvents = []A2ASSEEvent{
		{Kind: "task", Task: &A2ATaskObject{
			ID: "task-001", ContextID: "ctx-001",
			Status: A2ATaskStatus{State: "completed"},
		}},
	}
	events := collectEvents(t, basicSpec(cfg))
	resp := string(events[1].Bytes)
	if !strings.Contains(resp, "Content-Type: text/event-stream") {
		t.Errorf("SSE response missing event-stream content type: %q", resp)
	}
	if !strings.Contains(resp, "Transfer-Encoding: chunked") {
		t.Errorf("SSE response missing chunked transfer encoding: %q", resp)
	}
	if !strings.Contains(resp, "0\r\n\r\n") {
		t.Errorf("SSE response missing terminating chunk: %q", resp)
	}
	if !strings.Contains(resp, "data: ") {
		t.Errorf("SSE response missing data: lines: %q", resp)
	}
}

// TestLayerGen_JSONRPCErrorResponse Error 响应携带 jsonrpc/error/id
// （legacy a2a.go:615-636 同款）。
func TestLayerGen_JSONRPCErrorResponse(t *testing.T) {
	cfg := validA2AConfig()
	cfg.Tasks[0].Response = A2ATaskResponse{
		Error: &A2AError{Code: -32601, Message: "method not found", Data: json.RawMessage(`{"hint":"typo"}`)},
	}
	events := collectEvents(t, basicSpec(cfg))
	resp := string(events[1].Bytes)
	if !strings.Contains(resp, `"jsonrpc":"2.0"`) || !strings.Contains(resp, `"error":`) ||
		!strings.Contains(resp, `-32601`) || !strings.Contains(resp, `"hint":"typo"`) ||
		!strings.Contains(resp, `"id":"req-001"`) {
		t.Errorf("error response malformed: %q", resp)
	}
}

// TestLayerGen_NilEmitMsg EmitMsg 未接线即报错（不能静默丢事件）。
func TestLayerGen_NilEmitMsg(t *testing.T) {
	gen := &A2AGenerator{}
	req := &layers.GenRequest{Meta: layers.FlowMeta{Payload: basicSpec(validA2AConfig()).Payload}}
	if err := gen.Generate(context.Background(), req); err == nil {
		t.Fatal("Generate with nil EmitMsg returned nil, want error")
	}
}

// TestLayerGen_NoPayload 无 Payload 配置即报错。
func TestLayerGen_NoPayload(t *testing.T) {
	gen := &A2AGenerator{}
	var events []layers.MessageEvent
	req := &layers.GenRequest{
		Meta: layers.FlowMeta{},
		EmitMsg: func(ev layers.MessageEvent) error {
			events = append(events, ev)
			return nil
		},
	}
	if err := gen.Generate(context.Background(), req); err == nil {
		t.Fatal("Generate with no Payload returned nil, want error")
	}
	if len(events) != 0 {
		t.Fatalf("emitted %d events on invalid config, want 0", len(events))
	}
}

// TestLayerGen_InvalidJSON 非法 Payload JSON 即报错。
func TestLayerGen_InvalidJSON(t *testing.T) {
	gen := &A2AGenerator{}
	req := &layers.GenRequest{
		Meta: layers.FlowMeta{Payload: []byte("{not json")},
		EmitMsg: func(ev layers.MessageEvent) error {
			return nil
		},
	}
	if err := gen.Generate(context.Background(), req); err == nil {
		t.Fatal("Generate with invalid config JSON returned nil, want error")
	}
}

// TestLayerGen_NoTasks 空任务序列显式拒绝（事件模式下无事件 = 链上只剩
// TCP 空连接，不能静默产空连接）。
func TestLayerGen_NoTasks(t *testing.T) {
	cfg := validA2AConfig()
	cfg.Tasks = nil
	gen := &A2AGenerator{}
	req := &layers.GenRequest{
		Meta: layers.FlowMeta{Payload: basicSpec(cfg).Payload},
		EmitMsg: func(ev layers.MessageEvent) error {
			return nil
		},
	}
	if err := gen.Generate(context.Background(), req); err == nil {
		t.Fatal("Generate with no tasks returned nil, want error")
	}
}

// TestLayerGen_EmitMsgErrorPropagates emit 错误向上传播（不能吞）。
func TestLayerGen_EmitMsgErrorPropagates(t *testing.T) {
	gen := &A2AGenerator{}
	sentinel := errors.New("emit failed")
	req := &layers.GenRequest{
		Meta: layers.FlowMeta{Payload: basicSpec(validA2AConfig()).Payload},
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
	cfg := validA2AConfig()
	cfg.Tasks = append(cfg.Tasks, cfg.Tasks[0]) // 2 tasks
	gen := &A2AGenerator{}
	ctx, cancel := context.WithCancel(context.Background())
	var mu sync.Mutex
	var events []layers.MessageEvent
	cancelled := false
	req := &layers.GenRequest{
		Meta: layers.FlowMeta{Payload: basicSpec(cfg).Payload},
		EmitMsg: func(ev layers.MessageEvent) error {
			mu.Lock()
			events = append(events, ev)
			n := len(events)
			mu.Unlock()
			if n == 2 { // 第 2 个事件后取消（首个 task 完成）
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
		t.Fatalf("emitted %d events, want exactly 2 (cancelled before task 2)", len(events))
	}
}

// TestLayerGen_ChainPlannerBytes 链级字节验证：ChainPlanner 驱动 [ip→tcp→a2a]
// 完整链路（握手 3 + 数据 2 + 挥手 4 = 9 包），数据段与 legacy 逐字节一致，
// 挥手为 TCPGenerator 标准 4 包（http 波 2 同款语义）。
func TestLayerGen_ChainPlannerBytes(t *testing.T) {
	cfg := validA2AConfig()
	cfg.TCP.ACKPolicy = "lazy" // legacy 无独立 ACK，数据段可比
	spec := basicSpec(cfg)
	planner := layers.NewChainPlannerFromChain("a2a", []layers.Layer{
		{Name: "ip"},
		{Name: "tcp"},
		{Name: "a2a"},
	})
	ch, err := planner.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("ChainPlanner Plan: %v", err)
	}
	var pkts []core.PacketConfig
	for p := range ch {
		pkts = append(pkts, p)
	}
	if len(pkts) != 9 {
		t.Fatalf("got %d packets, want 9 (handshake 3 + data 2 + teardown 4)", len(pkts))
	}
	// 握手：SYN(up) → SYN-ACK(down) → ACK(up)
	wantFlags := []uint8{0x02, 0x12, 0x10, 0x18, 0x18, 0x11, 0x10, 0x11, 0x10}
	wantDir := []string{"up", "down", "up", "up", "down", "up", "down", "down", "up"}
	for i, wf := range wantFlags {
		if pkts[i].L4.Flags != wf {
			t.Errorf("packet %d flags = 0x%02x, want 0x%02x", i, pkts[i].L4.Flags, wf)
		}
		if pkts[i].Direction != wantDir[i] {
			t.Errorf("packet %d direction = %s, want %s", i, pkts[i].Direction, wantDir[i])
		}
	}
	// 数据段与 legacy 逐字节一致（方向 + payload）。
	legacy := legacyDataPackets(t, spec)
	if len(legacy) != 2 {
		t.Fatalf("legacy data segments = %d, want 2", len(legacy))
	}
	for i, l := range legacy {
		seg := pkts[3+i]
		if !bytes.Equal(seg.Payload, l.Payload) {
			t.Errorf("data packet %d payload = %q, legacy = %q", i, string(seg.Payload), string(l.Payload))
		}
		if seg.Direction != l.Direction {
			t.Errorf("data packet %d direction = %s, legacy = %s", i, seg.Direction, l.Direction)
		}
	}
	// down 数据段端口交换（legacy 同款：down 帧源端口 = DstPort）。
	if pkts[4].L4.SrcPort != 443 || pkts[4].L4.DstPort != 12345 {
		t.Errorf("down data segment ports = %d/%d, want 443/12345", pkts[4].L4.SrcPort, pkts[4].L4.DstPort)
	}
	// 挥手 seq 连续性：FIN(up) 继承 up 数据段尾部 seq（TCPGenerator
	// fin1.Seq = clientSeq 已推进）；FIN(down) 继承 down 数据段尾部 seq
	// （fin2.Seq = serverSeq 已推进）。
	if pkts[5].L4.Seq != pkts[3].L4.Seq+uint32(len(pkts[3].Payload)) {
		t.Errorf("FIN(up) seq = %d, want up data tail %d", pkts[5].L4.Seq, pkts[3].L4.Seq+uint32(len(pkts[3].Payload)))
	}
	if pkts[7].L4.Seq != pkts[4].L4.Seq+uint32(len(pkts[4].Payload)) {
		t.Errorf("FIN(down) seq = %d, want down data tail %d", pkts[7].L4.Seq, pkts[4].L4.Seq+uint32(len(pkts[4].Payload)))
	}
}

// TestLayerGen_ChainPlannerTCPConfig 链级 cfg.TCP 校准：MSS/InitialSeq/
// Handshake/Termination 经 LayerValidator 进 spec.TCP → tcp 层生成器执行。
func TestLayerGen_ChainPlannerTCPConfig(t *testing.T) {
	cfg := validA2AConfig()
	handshake, termination := false, false
	cfg.TCP = A2ATCP{
		Handshake:   &handshake,
		Termination: &termination,
		InitialSeq:  0x11223344,
		MSS:         1400,
	}
	spec := basicSpec(cfg)
	planner := layers.NewChainPlannerFromChain("a2a", []layers.Layer{
		{Name: "ip"},
		{Name: "tcp"},
		{Name: "a2a"},
	})
	ch, err := planner.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("ChainPlanner Plan: %v", err)
	}
	var pkts []core.PacketConfig
	for p := range ch {
		pkts = append(pkts, p)
	}
	// 无握手无挥手：仅 2 数据段。
	if len(pkts) != 2 {
		t.Fatalf("got %d packets, want 2 (no handshake/teardown)", len(pkts))
	}
	// 数据段 seq = InitialSeq+1（握手省略但 seq 仍从 InitialSeq 起，SYN 的
	// +1 消费被跳过——TCPGenerator 数据段用当前 clientSeq 直接发包）。
	if pkts[0].L4.Seq != 0x11223344 {
		t.Errorf("data packet 0 seq = %d, want InitialSeq 0x11223344", pkts[0].L4.Seq)
	}
	// MSS 1400 且请求 > 1400 字节时 tcp 层按 1400 分段（SegmentMSS 事件级
	// 处理；此测试请求体小不触发分段，断言由链级分段专项覆盖）。
	reqLen := len(pkts[0].Payload)
	if reqLen > 1400 {
		t.Errorf("data packet 0 len = %d > MSS 1400 (tcp layer did not segment)", reqLen)
	}
}

// TestLayerGen_ChainPlannerSegmentByMSS 链级 MSS 分段专项：任务消息体超过
// MSS 1400 时 tcp 层把请求事件切成多段（每段 0x18，up 连续 seq，段间无
// 独立 ACK），响应下行为单段（小体）。字节仍与 legacy 分段一致。
func TestLayerGen_ChainPlannerSegmentByMSS(t *testing.T) {
	cfg := validA2AConfig()
	cfg.TCP.MSS = 1400
	cfg.Tasks[0].Message.Parts = []A2APart{
		{Kind: "text", Text: strings.Repeat("x", 3500)},
	}
	spec := basicSpec(cfg)
	planner := layers.NewChainPlannerFromChain("a2a", []layers.Layer{
		{Name: "ip"},
		{Name: "tcp"},
		{Name: "a2a"},
	})
	ch, err := planner.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("ChainPlanner Plan: %v", err)
	}
	var pkts []core.PacketConfig
	for p := range ch {
		pkts = append(pkts, p)
	}
	// 握手 3 + 请求 3 段 + 响应 1 + 挥手 4 = 11 包。
	if len(pkts) != 11 {
		t.Fatalf("got %d packets, want 11 (handshake 3 + req 3 segments + resp 1 + teardown 4)", len(pkts))
	}
	var reqLen int
	for i := 3; i <= 5; i++ {
		p := pkts[i]
		if p.Direction != "up" || p.L4.Flags != 0x18 {
			t.Errorf("segment %d direction/flags = %s/0x%02x, want up/0x18", i, p.Direction, p.L4.Flags)
		}
		if len(p.Payload) > 1400 {
			t.Errorf("segment %d len = %d > MSS 1400", i, len(p.Payload))
		}
		if i > 3 {
			if p.L4.Seq != pkts[i-1].L4.Seq+uint32(len(pkts[i-1].Payload)) {
				t.Errorf("segment %d seq = %d, want %d (previous tail)",
					i, p.L4.Seq, pkts[i-1].L4.Seq+uint32(len(pkts[i-1].Payload)))
			}
		}
		reqLen += len(p.Payload)
	}
	// 请求 = HTTP 头 + 3500 字节体 > 2×MSS → 恰好 3 段。
	if reqLen <= 2*1400 {
		t.Errorf("segmented request bytes = %d, want > %d (must split into 3 segments)", reqLen, 2*1400)
	}
	// 段间无独立 ACK：3 段连续 up，中间无 down。
	for i := 3; i < 6; i++ {
		if pkts[i].Direction != "up" {
			t.Errorf("segment index %d = %s, want up (no inter-segment ACK)", i, pkts[i].Direction)
		}
	}
	// 与 legacy 分段一致：请求 3 段 + 响应 1 段（legacy 数据段数相同）。
	legacy := legacyDataPackets(t, spec)
	if len(legacy) != 4 {
		t.Fatalf("legacy data segments = %d, want 4 (3 request segments + 1 response)", len(legacy))
	}
	chainReqLen := 0
	for i := 3; i <= 5; i++ {
		chainReqLen += len(pkts[i].Payload)
	}
	var legacyReqLen int
	for _, l := range legacy[:3] {
		legacyReqLen += len(l.Payload)
	}
	if chainReqLen != legacyReqLen {
		t.Errorf("chained request bytes = %d, legacy = %d", chainReqLen, legacyReqLen)
	}
	// 段内字节前缀一致（前 2 段逐字节等于 legacy 前 2 段）。
	for i := 0; i < 2; i++ {
		if !bytes.Equal(pkts[3+i].Payload, legacy[i].Payload) {
			t.Errorf("segment %d payload mismatch vs legacy", i)
		}
	}
	// 响应段：链 pkts[6] == legacy[3]。
	if !bytes.Equal(pkts[6].Payload, legacy[3].Payload) {
		t.Errorf("response segment payload mismatch vs legacy")
	}
}

// TestLayerGen_ChainPlannerRejectsInvalidSpec 链级负向：非法 spec 经
// ChainPlanner 校验拒绝（validator 触发，planner 名必须为 "a2a"）。
func TestLayerGen_ChainPlannerRejectsInvalidSpec(t *testing.T) {
	cfg := validA2AConfig()
	cfg.Tasks[0].Method = "bogus/method" // 非法 method
	spec := basicSpec(cfg)
	planner := layers.NewChainPlannerFromChain("a2a", []layers.Layer{
		{Name: "ip"},
		{Name: "tcp"},
		{Name: "a2a"},
	})
	_, err := planner.Plan(context.Background(), spec)
	if err == nil {
		t.Fatal("ChainPlanner Plan with invalid method returned nil, want error")
	}
}
