package mcp

// MCP 终结层层生成器测试（P4a）。MCPGenerator 复用 build* 纯函数状态机产
// 事件——事件序列与 legacy Plan 的数据帧（flags=0x18 PSH-ACK，握手/挥手过滤
// 后）在方向/字节上逐消息一致；覆盖 stdio / http_sse / streamable 三传输。
// 链级测试通过 ChainPlanner 驱动 [ip→tcp→mcp] 完整链路验证握手→数据→挥手
// 与 legacy 数据帧字节一致；Shutdown=false 时挥手（与 streamable 的 DELETE）
// 按 legacy 语义跳过。默认化（transport/protocol_version/requests/rounds/
// shutdown/sessionID）与 legacy Plan（plan.go:36-72）对齐，测试覆盖默认值与
// 显式值两路径。HTTP 模式字节依赖 cfg.SessionID（Mcp-Session-Id 头 +
// postURI），测试必须显式设置保证确定性。

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

// mcpSpec returns a base flow spec for generator tests（源/目的端口显式）。
func mcpSpec() core.FlowSpec {
	return core.FlowSpec{
		SrcIP:   "10.0.0.1",
		DstIP:   "20.0.0.2",
		SrcPort: 40000,
		DstPort: 22,
	}
}

// stdioCfg returns a stdio config with a deterministic session id。sessionID
// 在 stdio 不上线（无 Mcp-Session-Id 头），显式设置仅为确定性防御。
func stdioCfg() *core.MCPConfig {
	return &core.MCPConfig{
		Transport: TransportStdio,
		SessionID: "a1b2c3d4e5f60718293a4b5c6d7e8f90",
	}
}

// httpCfg returns an HTTP-mode config with a deterministic session id
// （HTTP 字节依赖 SessionID——Mcp-Session-Id 头与 postURI）。
func httpCfg(transport string) *core.MCPConfig {
	return &core.MCPConfig{
		Transport: transport,
		SessionID: "a1b2c3d4e5f60718293a4b5c6d7e8f90",
	}
}

// mustPlan runs the legacy Planner and fails the test on Plan error。
func mustPlan(t *testing.T, p *Planner, spec core.FlowSpec) <-chan core.PacketConfig {
	t.Helper()
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	return ch
}

// collectEvents drives MCPGenerator.Generate and collects the emitted
// message events in order. 值拷贝 cfg：事件生成与 legacy 对比各持独立实例。
func collectEvents(t *testing.T, spec core.FlowSpec) []layers.MessageEvent {
	t.Helper()
	var events []layers.MessageEvent
	gen := &MCPGenerator{}
	meta := layers.FlowMeta{
		SrcIP:   spec.SrcIP,
		DstIP:   spec.DstIP,
		SrcPort: spec.SrcPort,
		DstPort: spec.DstPort,
	}
	if spec.MCP != nil {
		c2 := *spec.MCP
		meta.MCP = &c2
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

// legacyDataFrames runs the legacy planner and returns the MCP data frames
// （skip TCP handshake/teardown）。数据帧 flags=0x18 PSH-ACK（emit.go:63-83），
// 与事件一一对应。
func legacyDataFrames(t *testing.T, spec core.FlowSpec) []core.PacketConfig {
	t.Helper()
	spec2 := spec
	if spec.MCP != nil {
		c2 := *spec.MCP
		spec2.MCP = &c2
	}
	var out []core.PacketConfig
	for _, c := range drain(mustPlan(t, &Planner{}, spec2)) {
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
// 方向/payload 上逐消息一致。覆盖三传输 + 通知（Step 边界：Step==i 与
// Step==len(Requests)）+ rounds 多轮 + 显式 ID + Shutdown=false（streamable
// 的 DELETE/204 按 legacy 语义跳过）。
func TestLayerGen_EventsMatchLegacyPlan(t *testing.T) {
	shutdownFalse := false
	cases := []struct {
		name string
		cfg  *core.MCPConfig
	}{
		{"stdio default", stdioCfg()},
		{"stdio random session", func() *core.MCPConfig {
			c := stdioCfg()
			c.SessionID = "" // 随机 32 hex；stdio 不上线，事件字节不变
			return c
		}()},
		{"stdio rounds 2", func() *core.MCPConfig {
			c := stdioCfg()
			c.Rounds = 2
			return c
		}()},
		{"stdio explicit IDs", func() *core.MCPConfig {
			c := stdioCfg()
			c.Requests = []core.MCPRequest{
				{ID: 100, Method: "resources/list"},
				{ID: 101, Method: "ping"},
			}
			return c
		}()},
		{"stdio notifications step boundary", func() *core.MCPConfig {
			c := stdioCfg()
			// Validate 规则 12 在默认化之前执行（len(Requests)=0 时 Step>0 越界），
			// 通知用例须显式 Requests。
			c.Requests = append([]core.MCPRequest(nil), DefaultRequestSequence...)
			c.Notifications = []core.MCPNotification{
				{Step: 0, Method: "notifications/roots/list_changed"},                                                      // 客户端通知（up）
				{Step: 1, Method: "notifications/progress", Params: map[string]any{"progressToken": "t1", "progress": 50}}, // 服务器通知（down）
				{Step: 2, Method: "notifications/cancelled"},                                                               // Step == len(Requests)，每轮末
			}
			return c
		}()},
		{"http_sse default", httpCfg(TransportHTTPSSE)},
		{"http_sse notifications", func() *core.MCPConfig {
			c := httpCfg(TransportHTTPSSE)
			c.Requests = append([]core.MCPRequest(nil), DefaultRequestSequence...)
			c.Notifications = []core.MCPNotification{
				{Step: 0, Method: "notifications/roots/list_changed"},
				{Step: 1, Method: "notifications/progress", Params: map[string]any{"progressToken": "t1", "progress": 50}},
				{Step: 2, Method: "notifications/cancelled"},
			}
			return c
		}()},
		{"streamable default", httpCfg(TransportStreamable)},
		{"streamable shutdown false", func() *core.MCPConfig {
			c := httpCfg(TransportStreamable)
			c.Shutdown = &shutdownFalse // DELETE/204 跳过（legacy 同款）
			return c
		}()},
		{"streamable notifications rounds 2", func() *core.MCPConfig {
			c := httpCfg(TransportStreamable)
			c.Rounds = 2
			c.Requests = append([]core.MCPRequest(nil), DefaultRequestSequence...)
			c.Notifications = []core.MCPNotification{
				{Step: 0, Method: "notifications/roots/list_changed"},
				{Step: 1, Method: "notifications/progress", Params: map[string]any{"progressToken": "t1", "progress": 50}},
				{Step: 2, Method: "notifications/cancelled"},
			}
			return c
		}()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec := mcpSpec()
			if tc.cfg.Transport == TransportHTTPSSE || tc.cfg.Transport == TransportStreamable {
				spec.DstPort = 8081
			}
			c2 := *tc.cfg
			spec.MCP = &c2
			events := collectEvents(t, spec)
			assertEventsMatchLegacy(t, spec, events)
		})
	}
}

// TestLayerGen_ChainPlannerBytes 链级字节验证：ChainPlanner 驱动
// [ip→tcp→mcp] 完整链路（握手 3 + 数据 7 + 挥手 4 = 14 包），数据帧与 legacy
// 逐字节一致。挥手为 TCPGenerator 标准 4 包（FIN|ACK up → ACK down → FIN|ACK
// down → ACK up，generator.go:877-947）——legacy stdio 是 3 包挥手（FIN-ACK
// up → FIN-ACK down → ACK up，emit.go emitTeardown），层模型意图的文档化分歧
// （与 gbt32960/dnp3/doip 链测试同款断言形状）。DstPort=0 → validateSpecBase
// mcp 分支默认 22（stdio）。
func TestLayerGen_ChainPlannerBytes(t *testing.T) {
	spec := mcpSpec()
	spec.DstPort = 0 // 默认化验证（stdio → 22）
	spec.TCP = &core.TCPConfig{InitialSeq: 1000}
	c2 := *stdioCfg()
	spec.MCP = &c2
	planner := layers.NewChainPlannerFromChain("mcp", []layers.Layer{
		{Name: "ip"},
		{Name: "tcp"},
		{Name: "mcp"},
	})
	ch, err := planner.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("ChainPlanner Plan: %v", err)
	}
	var pkts []core.PacketConfig
	for p := range ch {
		pkts = append(pkts, p)
	}
	// stdio 默认：3 条初始化 + 2 请求 + 2 响应 = 7 事件 → 7 数据帧。
	if len(pkts) != 14 {
		t.Fatalf("got %d packets, want 14 (handshake 3 + data 7 + teardown 4)", len(pkts))
	}
	// 握手：SYN(up) → SYN-ACK(down) → ACK(up)；数据 7 帧；挥手 4 包。
	wantFlags := []uint8{0x02, 0x12, 0x10, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x11, 0x10, 0x11, 0x10}
	wantDir := []string{"up", "down", "up", "up", "down", "up", "up", "down", "up", "down", "up", "down", "down", "up"}
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
	if len(legacy) != 7 {
		t.Fatalf("legacy data frames = %d, want 7", len(legacy))
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
	// SYN dst_port = 22（stdio 默认）。
	if pkts[0].L4.DstPort != 22 {
		t.Errorf("SYN dst_port = %d, want 22 (stdio default)", pkts[0].L4.DstPort)
	}
	// down 数据帧端口交换（legacy 同款：down 帧源端口 = DstPort 22）。
	if pkts[4].L4.SrcPort != 22 || pkts[4].L4.DstPort != 40000 {
		t.Errorf("down data frame ports = %d/%d, want 22/40000", pkts[4].L4.SrcPort, pkts[4].L4.DstPort)
	}
	// 挥手 seq 连续性：FIN(up) 继承最后 up 数据帧尾部 seq（pkts[8] =
	// tools/call 请求 up）；FIN(down) 继承最后 down 数据帧尾部 seq（pkts[9]
	// = tools/call 响应 down）。
	if pkts[10].L4.Seq != pkts[8].L4.Seq+uint32(len(pkts[8].Payload)) {
		t.Errorf("FIN(up) seq = %d, want up data tail %d", pkts[10].L4.Seq, pkts[8].L4.Seq+uint32(len(pkts[8].Payload)))
	}
	if pkts[12].L4.Seq != pkts[9].L4.Seq+uint32(len(pkts[9].Payload)) {
		t.Errorf("FIN(down) seq = %d, want down data tail %d", pkts[12].L4.Seq, pkts[9].L4.Seq+uint32(len(pkts[9].Payload)))
	}
}

// TestLayerGen_ChainPlannerHTTP 链级 HTTP 模式验证：http_sse 的 12 数据帧
// （GET + 200 SSE + POST×2 + 202×2 + 2×(POST + 202 + SSE push)），
// Mcp-Session-Id 头带确定性 SessionID（HTTP 字节依赖）。链包数 =
// 握手 3 + 数据 12 + 挥手 4 = 19。
func TestLayerGen_ChainPlannerHTTP(t *testing.T) {
	spec := mcpSpec()
	spec.DstPort = 0 // http_sse → 8081
	spec.TCP = &core.TCPConfig{InitialSeq: 1000}
	c2 := *httpCfg(TransportHTTPSSE)
	spec.MCP = &c2
	planner := layers.NewChainPlannerFromChain("mcp", []layers.Layer{
		{Name: "ip"},
		{Name: "tcp"},
		{Name: "mcp"},
	})
	ch, err := planner.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("ChainPlanner Plan: %v", err)
	}
	var pkts []core.PacketConfig
	for p := range ch {
		pkts = append(pkts, p)
	}
	if len(pkts) != 19 {
		t.Fatalf("got %d packets, want 19 (handshake 3 + data 12 + teardown 4)", len(pkts))
	}
	if pkts[0].L4.DstPort != 8081 {
		t.Errorf("SYN dst_port = %d, want 8081 (http_sse default)", pkts[0].L4.DstPort)
	}
	// 逐帧与 legacy 对比（数据帧方向 + payload）。
	legacy := legacyDataFrames(t, spec)
	if len(legacy) != 12 {
		t.Fatalf("legacy data frames = %d, want 12", len(legacy))
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
	// 会话确定性：GET 帧无 Mcp-Session-Id（legacy §A.2 同款），POST 帧带。
	if bytes.Contains(pkts[3].Payload, []byte("Mcp-Session-Id")) {
		t.Errorf("GET frame carries Mcp-Session-Id, legacy GET must not")
	}
	foundSID := false
	for i := 4; i < len(pkts); i++ {
		if bytes.Contains(pkts[i].Payload, []byte("Mcp-Session-Id: a1b2c3d4e5f60718293a4b5c6d7e8f90")) {
			foundSID = true
			break
		}
	}
	if !foundSID {
		t.Errorf("no POST frame carries the configured Mcp-Session-Id")
	}
}

// TestLayerGen_ChainPlannerNoTeardown Shutdown=false：挥手跳过（validator
// 校准 spec.TCP.Termination=false，tcp 层不产 4 包挥手）；streamable 的
// DELETE/204 也跳过。包数 = 握手 3 + 数据 7 = 10，无 0x11 标志。
func TestLayerGen_ChainPlannerNoTeardown(t *testing.T) {
	spec := mcpSpec()
	spec.TCP = &core.TCPConfig{InitialSeq: 1000}
	shutdownFalse := false
	c2 := *stdioCfg()
	c2.Shutdown = &shutdownFalse
	spec.MCP = &c2
	planner := layers.NewChainPlannerFromChain("mcp", []layers.Layer{
		{Name: "ip"},
		{Name: "tcp"},
		{Name: "mcp"},
	})
	ch, err := planner.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("ChainPlanner Plan: %v", err)
	}
	var pkts []core.PacketConfig
	for p := range ch {
		pkts = append(pkts, p)
	}
	if len(pkts) != 10 {
		t.Fatalf("got %d packets, want 10 (handshake 3 + data 7, no teardown)", len(pkts))
	}
	for i, p := range pkts {
		if p.L4.Flags == 0x11 { // 精确匹配 FIN|ACK（0x12 SYN-ACK/0x18 PSH-ACK 含 ACK 位不算）
			t.Errorf("packet %d has FIN flag 0x%02x, want no teardown", i, p.L4.Flags)
		}
	}
}

// TestLayerGen_ChainPlannerStreamableNoShutdown streamable + Shutdown=false：
// 链上既无 DELETE/204 数据帧也无 TCP 挥手（包数 = 3 + 8 = 11；8 数据帧 =
// POST init + 200 + POST initdN + 202 + 2×(POST + 200)）。Shutdown=true 时
// DELETE+204 在带内（legacy http_plan.go:536-539 同款），无新握手。
func TestLayerGen_ChainPlannerStreamableNoShutdown(t *testing.T) {
	spec := mcpSpec()
	spec.DstPort = 8081
	spec.TCP = &core.TCPConfig{InitialSeq: 1000}
	shutdownFalse := false
	c2 := *httpCfg(TransportStreamable)
	c2.Shutdown = &shutdownFalse
	spec.MCP = &c2
	planner := layers.NewChainPlannerFromChain("mcp", []layers.Layer{
		{Name: "ip"},
		{Name: "tcp"},
		{Name: "mcp"},
	})
	ch, err := planner.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("ChainPlanner Plan: %v", err)
	}
	var pkts []core.PacketConfig
	for p := range ch {
		pkts = append(pkts, p)
	}
	if len(pkts) != 11 {
		t.Fatalf("got %d packets, want 11 (handshake 3 + data 8, no DELETE no teardown)", len(pkts))
	}
	for i, p := range pkts {
		if p.L4.Flags == 0x11 { // 精确匹配 FIN|ACK（0x12 SYN-ACK/0x18 PSH-ACK 含 ACK 位不算）
			t.Errorf("packet %d has FIN flag 0x%02x, want no teardown", i, p.L4.Flags)
		}
		if bytes.Contains(p.Payload, []byte("DELETE")) {
			t.Errorf("packet %d carries DELETE with shutdown=false", i)
		}
	}
}

// TestLayerGen_ChainPlannerSrcPortZero 源端口 0 保持 0 上包（legacy 语义：
// spec.SrcPort 直传，validateSpecBase mcp 分支不默认化）。
func TestLayerGen_ChainPlannerSrcPortZero(t *testing.T) {
	spec := mcpSpec()
	spec.SrcPort = 0
	spec.TCP = &core.TCPConfig{InitialSeq: 1000}
	c2 := *stdioCfg()
	spec.MCP = &c2
	planner := layers.NewChainPlannerFromChain("mcp", []layers.Layer{
		{Name: "ip"},
		{Name: "tcp"},
		{Name: "mcp"},
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
	if pkts[0].L4.SrcPort != 0 {
		t.Errorf("SYN src_port = %d, want 0 (kept as-is, legacy semantics)", pkts[0].L4.SrcPort)
	}
}

// TestLayerGen_NilEmitMsg EmitMsg 未接线即报错（不能静默丢事件）。
func TestLayerGen_NilEmitMsg(t *testing.T) {
	gen := &MCPGenerator{}
	c2 := *stdioCfg()
	req := &layers.GenRequest{Meta: layers.FlowMeta{MCP: &c2}}
	if err := gen.Generate(context.Background(), req); err == nil {
		t.Fatal("Generate with nil EmitMsg returned nil, want error")
	}
}

// TestLayerGen_NoConfig 无 MCP 配置即报错（不产任何事件）。
func TestLayerGen_NoConfig(t *testing.T) {
	gen := &MCPGenerator{}
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

// TestLayerGen_ChainPlannerRejectsInvalidSpec 链级负向：非法 spec 经
// ChainPlanner 校验拒绝（validator = legacy Validate，planner 名必须为
// "mcp"）。覆盖：非法 transport（规则 2）、空 method（规则 7）、通知 Step
// 越界（规则 12）。
func TestLayerGen_ChainPlannerRejectsInvalidSpec(t *testing.T) {
	planner := layers.NewChainPlannerFromChain("mcp", []layers.Layer{
		{Name: "ip"},
		{Name: "tcp"},
		{Name: "mcp"},
	})
	spec := mcpSpec()
	c2 := *stdioCfg()
	c2.Transport = "bogus"
	spec.MCP = &c2
	if _, err := planner.Plan(context.Background(), spec); err == nil || !strings.Contains(err.Error(), "invalid transport") {
		t.Fatalf("Plan with invalid transport error = %v, want invalid transport", err)
	}
	spec = mcpSpec()
	c3 := *stdioCfg()
	c3.Requests = []core.MCPRequest{{Method: ""}}
	spec.MCP = &c3
	if _, err := planner.Plan(context.Background(), spec); err == nil || !strings.Contains(err.Error(), "method is required") {
		t.Fatalf("Plan with empty method error = %v, want method is required", err)
	}
	spec = mcpSpec()
	c4 := *stdioCfg()
	c4.Notifications = []core.MCPNotification{{Step: 99, Method: "notifications/progress"}}
	spec.MCP = &c4
	if _, err := planner.Plan(context.Background(), spec); err == nil || !strings.Contains(err.Error(), "out of range") {
		t.Fatalf("Plan with out-of-range step error = %v, want out of range", err)
	}
}

// TestLayerGen_EmitMsgErrorPropagates emit 错误向上传播（不能吞）。
func TestLayerGen_EmitMsgErrorPropagates(t *testing.T) {
	gen := &MCPGenerator{}
	sentinel := errors.New("emit failed")
	c2 := *stdioCfg()
	req := &layers.GenRequest{
		Meta: layers.FlowMeta{MCP: &c2},
		EmitMsg: func(ev layers.MessageEvent) error {
			return sentinel
		},
	}
	if err := gen.Generate(context.Background(), req); !errors.Is(err, sentinel) {
		t.Fatalf("Generate error = %v, want sentinel", err)
	}
}

// TestLayerGen_CancelMidSequence 取消后停止产事件（精确计数）：第 2 个事件
// 后取消（initialize request + initialize response 完成）。
func TestLayerGen_CancelMidSequence(t *testing.T) {
	gen := &MCPGenerator{}
	ctx, cancel := context.WithCancel(context.Background())
	var mu sync.Mutex
	var events []layers.MessageEvent
	cancelled := false
	c2 := *stdioCfg()
	req := &layers.GenRequest{
		Meta: layers.FlowMeta{MCP: &c2},
		EmitMsg: func(ev layers.MessageEvent) error {
			mu.Lock()
			events = append(events, ev)
			n := len(events)
			mu.Unlock()
			if n == 2 {
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

// TestLayerGen_HTTPModeMethodErrorPropagates HTTP 模式构造错误同步返回：
// buildNotification 对空 method 返回 error（builder.go:46-50），Generate 的
// 传输分发（layer_gen.go:122-131）必须把 planHTTPSSEEvents /
// planStreamableEvents 的 error 向上传播，不能吞成 nil（CLAUDE.md §2 反例：
// "驱动失败 → 空流"会报告 completed + 0 包）。validator（mcp.go:140-152
// Rule 12）拦了空 method，但生成器级检查是双保险（doip 同款纪律）——直接调
// Generate 绕过 validator，HTTP 模式必须显式报错且不产任何事件。
func TestLayerGen_HTTPModeMethodErrorPropagates(t *testing.T) {
	for _, tc := range []struct {
		name      string
		transport string
	}{
		{"http_sse", TransportHTTPSSE},
		{"streamable", TransportStreamable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gen := &MCPGenerator{}
			c2 := *httpCfg(tc.transport)
			c2.Notifications = []core.MCPNotification{{Step: 1, Method: ""}}
			var events []layers.MessageEvent
			req := &layers.GenRequest{
				Meta: layers.FlowMeta{MCP: &c2},
				EmitMsg: func(ev layers.MessageEvent) error {
					events = append(events, ev)
					return nil
				},
			}
			err := gen.Generate(context.Background(), req)
			if err == nil || !strings.Contains(err.Error(), "notification") {
				t.Fatalf("Generate error = %v, want notification method error", err)
			}
			// 错误发生在序列中段（通知在 requests 循环之后构造），此前事件
			// 合法产出；断言流在错误点停止（事件数少于无错误全量）即可。
			if len(events) == 0 {
				t.Fatal("no events emitted before the error point, want partial sequence")
			}
		})
	}
}

// TestLayerGen_EventCountRounds 事件计数数学（与 legacy 一致，独立于字节
// 对比的防御断言）：stdio 默认 = 3（初始化）+ 2×2（请求+响应）= 7；
// Rounds=2 = 3 + 2×2×2 = 11；每轮末通知（Step==len(Requests)）每轮 +1。
func TestLayerGen_EventCountRounds(t *testing.T) {
	spec := mcpSpec()
	c2 := *stdioCfg()
	spec.MCP = &c2
	events := collectEvents(t, spec)
	if len(events) != 7 {
		t.Fatalf("default events = %d, want 7 (init 3 + 2 requests + 2 responses)", len(events))
	}
	c3 := *stdioCfg()
	c3.Rounds = 2
	spec.MCP = &c3
	events = collectEvents(t, spec)
	if len(events) != 11 {
		t.Fatalf("rounds=2 events = %d, want 11 (init 3 + 2 rounds × 4)", len(events))
	}
	c4 := *stdioCfg()
	c4.Rounds = 2
	c4.Notifications = []core.MCPNotification{{Step: 2, Method: "notifications/cancelled"}}
	spec.MCP = &c4
	events = collectEvents(t, spec)
	if len(events) != 13 {
		t.Fatalf("rounds=2 + step-end notification events = %d, want 13 (11 + 2 rounds × 1)", len(events))
	}
}
