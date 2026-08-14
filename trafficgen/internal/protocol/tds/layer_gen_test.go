package tds

// TDS terminal-layer generator tests (P4a)。TDSGenerator 复用 legacy 纯函数
// 产事件——事件序列与 legacy Plan 的数据帧（flags=0x18 PSH-ACK，握手/挥手
// 过滤后）在方向/字节上逐帧一致（PRELOGIN → PRELOGIN response → Login7 →
// Login response → sessions → Attention，Login.Error 门控跳过会话；down
// 报文按 PacketSize 应用层分片，T-148）。链级测试通过 ChainPlanner 驱动
// [ip→tcp→tds] 完整链路验证握手→数据→挥手与 legacy 数据帧字节一致、
// seq 连续、端口默认。默认化（Payload 空 → 默认配置（无会话）、presence-
// checked 显式空字符串、dstPort 0→1433、srcPort 0 保持）与 legacy Plan
// 对齐。

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// layerErrSpec builds an ErrorSpec with the common fields (state=1, class
// 11..25 per V-TDS-060；登录错误注入用 class 14)。
func layerErrSpec(number int32, class byte, msg string) *ErrorSpec {
	state := byte(1)
	cl := class
	return &ErrorSpec{Number: number, State: &state, Class: &cl, Message: msg}
}

// layerCfg returns a config with the planner-applied defaults (applyDefaults
// + 默认会话 s1：一条 SQL Batch request)。
func layerCfg() *TDSConfig {
	cfg := &TDSConfig{}
	applyDefaults(cfg, nil)
	cfg.Sessions = []SessionSpec{{
		ID: "s1",
		Requests: []RequestSpec{{
			Type: RequestSQLBatch,
			Sql:  &SqlBatchSpec{Statements: []StatementSpec{{Text: "select 'foo' as 'bar'"}}},
		}},
	}}
	return cfg
}

// layerSpec marshals cfg into spec.Payload and returns the base flow spec
// （strategy_convert.go tds case 同款：flat 键 tds 子 map 序列化进 Payload）。
func layerSpec(cfg *TDSConfig) core.FlowSpec {
	raw, _ := json.Marshal(cfg)
	return core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1",
		SrcPort: 50000, DstPort: DefaultPort,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		Payload: raw,
	}
}

// layerSpecRaw wraps a raw JSON payload into a flow spec（presence-check
// 测试用——layerSpec 经 struct 序列化会丢空字段，omitempty 直接删掉显式
// 空值；raw JSON 才保留 "app_name":"" 键）。
func layerSpecRaw(raw string) core.FlowSpec {
	spec := layerSpec(&TDSConfig{})
	spec.Payload = []byte(raw)
	return spec
}

// collectEvents drives TDSGenerator.Generate and collects the emitted message
// events in order.
func collectEvents(t *testing.T, spec core.FlowSpec) []layers.MessageEvent {
	t.Helper()
	var events []layers.MessageEvent
	gen := &TDSGenerator{}
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

// legacyDataFrames runs the legacy planner and returns the TDS data frames
// (skip TCP handshake/teardown)。数据帧 flags=0x18 PSH-ACK（tds.go
// emitData），与事件一一对应。
func legacyDataFrames(t *testing.T, spec core.FlowSpec) []core.PacketConfig {
	t.Helper()
	ch, err := (&Planner{}).Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("legacy Plan: %v", err)
	}
	var out []core.PacketConfig
	for c := range ch {
		if c.L4.Protocol == "tcp" && c.L4.Flags == 0x18 { // data frame
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
// 方向/payload 上逐帧一致。覆盖核心场景矩阵（默认配置/显式 config/
// Login.Error 注入/MARS 多会话/混合请求类型）。
func TestLayerGen_EventsMatchLegacyPlan(t *testing.T) {
	cases := []struct {
		name string
		cfg  *TDSConfig
	}{
		// 默认化路径：空 Payload（生成器空 Payload = 默认配置 + 默认会话，
		// 与 legacy configFromSpec 空 Payload 语义一致）。
		{"empty payload (defaults)", nil},
		// 显式 config：版本/PacketSize/AppName 等字段 + 默认会话。
		{"explicit fields", func() *TDSConfig {
			cfg := layerCfg()
			cfg.Version = TDSVersion73B
			cfg.PacketSize = 2048
			cfg.EncryptMode = EncryptRequired
			cfg.AppName = "layer-test"
			cfg.UserName = "alice"
			cfg.Password = "s3cret"
			return cfg
		}()},
		// Login.Error 注入：跳过全部会话（T-147）。
		{"login error skips sessions", func() *TDSConfig {
			cfg := layerCfg()
			cfg.Login = &LoginSpec{Error: layerErrSpec(18456, 14, "Login failed for user 'sa'.")}
			return cfg
		}()},
		// MARS 多会话：spid=0x0042 + OutstandingRequestCount=len(Sessions)。
		{"mars multi-session", func() *TDSConfig {
			cfg := layerCfg()
			cfg.MarsEnabled = true
			cfg.Sessions = []SessionSpec{
				{ID: "a", Requests: []RequestSpec{{Type: RequestSQLBatch,
					Sql: &SqlBatchSpec{Statements: []StatementSpec{{Text: "select 1"}}}}}},
				{ID: "b", Requests: []RequestSpec{{Type: RequestRPC,
					Rpc: &RpcSpec{ProcID: uint16Ptr(10)}}}},
			}
			return cfg
		}()},
		// SQLBatch/RPC/TransMgr/Attention 混合请求。
		{"mixed request types", func() *TDSConfig {
			cfg := layerCfg()
			cfg.Sessions = []SessionSpec{{
				ID: "mixed",
				Requests: []RequestSpec{
					{Type: RequestSQLBatch,
						Sql: &SqlBatchSpec{Statements: []StatementSpec{
							{Text: "select 1"},
							{Text: "set nocount on"},
						}}},
					{Type: RequestRPC,
						Rpc: &RpcSpec{ProcName: "sp_who", Params: []ParamSpec{
							{Name: "@p1", Type: "int", Value: stringPtr("42")},
						}}},
					{Type: RequestTransMgr,
						TransMgr: &TransMgrSpec{RequestType: TMBeginXact}},
					{Type: RequestAttention},
				},
			}}
			return cfg
		}()},
		// 多会话（MARS）+ transaction_id：事务描述符带出（请求 ALL_HEADERS）。
		{"mars sessions with transaction ids", func() *TDSConfig {
			cfg := layerCfg()
			cfg.MarsEnabled = true
			cfg.Sessions = []SessionSpec{
				{ID: "txa", TransactionID: 7, Requests: []RequestSpec{{
					Type: RequestTransMgr, TransMgr: &TransMgrSpec{RequestType: TMBeginXact}}}},
				{ID: "txb", TransactionID: 9, Requests: []RequestSpec{{
					Type: RequestSQLBatch,
					Sql:  &SqlBatchSpec{Statements: []StatementSpec{{Text: "BEGIN TRAN"}}}}}},
			}
			return cfg
		}()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var spec core.FlowSpec
			if tc.cfg == nil {
				// 空 Payload = 默认配置但**无会话**（configFromSpec 不注入
				// 会话；legacy 空 Payload 直喂会挂 V-TDS-003）。事件侧空
				// Payload 只产 4 帧（PRELOGIN 对 + LOGIN7 对，会话循环零次）。
				// legacy 侧改用"仅含该会话、其余字段全默认"的 payload——与空
				// Payload 的 applyDefaults 结果逐字节相同，会话前 4 帧可比。
				probe := layerCfg()
				evSpec := layerSpec(&TDSConfig{})
				evSpec.Payload = nil // 真正空 Payload（json.Marshal 产出 "{}"）
				events := collectEvents(t, evSpec)
				legacy := legacyDataFrames(t, layerSpec(probe))
				if len(events) != 4 {
					t.Fatalf("empty-payload events = %d, want 4 (no sessions)", len(events))
				}
				if len(legacy) < 4 {
					t.Fatalf("legacy data frames = %d, want >= 4", len(legacy))
				}
				for i := 0; i < 4; i++ {
					ev := events[i]
					pc := legacy[i]
					if (ev.Up && pc.Direction != "up") || (!ev.Up && pc.Direction != "down") {
						t.Errorf("event[%d] Up=%v, legacy Direction=%s", i, ev.Up, pc.Direction)
					}
					if !bytes.Equal(ev.Bytes, pc.Payload) {
						t.Errorf("event[%d] payload = % X, legacy = % X", i, ev.Bytes, pc.Payload)
					}
				}
				return
			}
			spec = layerSpec(tc.cfg)
			events := collectEvents(t, spec)
			assertEventsMatchLegacy(t, spec, events)
		})
	}
}

// TestLayerGen_EventSequence 独立校验事件序列形状（不依赖 legacy 对比）：
// 默认配置下的逐事件方向、TDS 报文类型（header[0]）。每帧头长字段
// （bytes[2:4] BE）与实际长度一致。
func TestLayerGen_EventSequence(t *testing.T) {
	events := collectEvents(t, layerSpec(layerCfg()))
	// 期望形状（legacy tds.go 数据帧序列）：
	//   PRELOGIN(up 0x12) → PRELOGIN response(down 0x04) → Login7(up 0x10)
	//   → Login response(down 0x04) → SQLBatch(up 0x01) → SQLBatch response
	//   (down 0x04)。
	want := []struct {
		up   bool
		typ  byte
		desc string
	}{
		{true, TypePreLogin, "PRELOGIN"},
		{false, TypeTabularResult, "PRELOGIN response"},
		{true, TypeLogin7, "LOGIN7"},
		{false, TypeTabularResult, "Login response"},
		{true, TypeSQLBatch, "SQL Batch"},
		{false, TypeTabularResult, "SQL Batch response"},
	}
	if len(events) != len(want) {
		t.Fatalf("events = %d, want %d", len(events), len(want))
	}
	for i, w := range want {
		if events[i].Up != w.up {
			t.Errorf("event[%d] (%s) Up=%v, want %v", i, w.desc, events[i].Up, w.up)
		}
		if len(events[i].Bytes) < 8 {
			t.Fatalf("event[%d] (%s) too short: % X", i, w.desc, events[i].Bytes)
		}
		if events[i].Bytes[0] != w.typ {
			t.Errorf("event[%d] (%s) msg type = 0x%02x, want 0x%02x", i, w.desc, events[i].Bytes[0], w.typ)
		}
	}
	// 报文头长度字段（bytes[2:4] BE）与实际长度一致。
	for i, ev := range events {
		if n := int(binary.BigEndian.Uint16(ev.Bytes[2:4])); n != len(ev.Bytes) {
			t.Errorf("event[%d] header length = %d, actual = %d", i, n, len(ev.Bytes))
		}
	}
}

// TestLayerGen_PacketSizeSplitting PacketSize 分片触发（T-148）：长响应
// （登录失败 ERROR 注入，消息 > 512-8 payload）被 BuildTableResponsePackets
// 拆成多片——每片是合法 TDS 报文（头长=实际长、type=0x04、除末片外
// Status=0x00、末片 StatusEOM）。Login.Error 注入下会话被跳过，所以分片
// 只发生在登录响应（Login.Error 时 session 响应不存在——这正是最简洁的
// 触发路径）。小 PacketSize (512) 下 PRELOGIN 响应保持单片；请求侧
// （PRELOGIN/LOGIN7）不参与分片。
func TestLayerGen_PacketSizeSplitting(t *testing.T) {
	cfg := layerCfg()
	cfg.PacketSize = 512
	cfg.Login = &LoginSpec{Error: layerErrSpec(18456, 14, strings.Repeat("long login failure ", 40))}
	events := collectEvents(t, layerSpec(cfg))
	var down [][]byte
	for _, ev := range events {
		if !ev.Up {
			down = append(down, ev.Bytes)
		}
	}
	if len(down) < 3 {
		t.Fatalf("down events = %d, want >= 3 (split login response)", len(down))
	}
	// 事件 0,1 = PRELOGIN 对；事件 2 = Login7（up）；down[0] = PRELOGIN
	// response（单片，< 512），down[1:] = 登录响应片序列。逐片校验契约：
	// 头长=实际长、type=0x04、中间片（Status=0x00）必须占满 payload
	// （len=512），说明分片按 packetSize 切。
	split := false
	for i, pkt := range down {
		if n := int(binary.BigEndian.Uint16(pkt[2:4])); n != len(pkt) {
			t.Errorf("down[%d] header length = %d, actual = %d", i, n, len(pkt))
		}
		if pkt[0] != TypeTabularResult {
			t.Errorf("down[%d] msg type = 0x%02x, want 0x04", i, pkt[0])
		}
		if len(pkt) == 512 {
			split = true
		}
		if pkt[1] == 0x00 && len(pkt) != 512 {
			t.Errorf("down[%d] intermediate fragment len = %d, want 512 (full payload)", i, len(pkt))
		}
	}
	if !split {
		t.Errorf("no down packet hit the %d-byte packet size boundary", cfg.PacketSize)
	}
}

// TestLayerGen_LoginErrorSkipsSessions Login.Error 注入后事件序列 = 握手前
// 阶段（PRELOGIN/PRELOGIN response/Login7/Login response）——无任何会话
// 请求/响应事件（T-147）。
func TestLayerGen_LoginErrorSkipsSessions(t *testing.T) {
	cfg := layerCfg()
	cfg.Login = &LoginSpec{Error: layerErrSpec(18456, 14, "Login failed for user 'sa'.")}
	events := collectEvents(t, layerSpec(cfg))
	if len(events) != 4 {
		t.Fatalf("events = %d, want 4 (PRELOGIN pair + LOGIN7 pair, sessions skipped)", len(events))
	}
	// 会话前共 4 事件；事件 3 = Login response（down, 0x04），必须携带
	// ERROR token (0xAA)。
	if events[3].Up || events[3].Bytes[0] != TypeTabularResult {
		t.Fatalf("event[3] = Up=%v type=0x%02x, want down 0x04 (Login response)", events[3].Up, events[3].Bytes[0])
	}
	if !bytes.Contains(events[3].Bytes, []byte{TokenError}) {
		t.Errorf("Login response missing ERROR token: % X", events[3].Bytes)
	}
	// 无任何会话请求事件（SQLBatch/RPC/TransMgr/Attention）。
	for i, ev := range events {
		if ev.Up {
			switch ev.Bytes[0] {
			case TypeSQLBatch, TypeRPC, TypeTransMgrReq, TypeAttention:
				t.Errorf("event[%d] session request emitted after login failure", i)
			}
		}
	}
}

// TestLayerGen_MARSSpidAndOutstanding MARS 语义：PRELOGIN 携带 PLMARS option
// 数据 0x01（option 表 token 0x04 + 数据区 0x01——恒在、值区分）；请求
// SPID=0x0042（header[4:6] BE）；请求 ALL_HEADERS 的 OutstandingRequestCount
// = len(Sessions)（body[18:22] LE，AllHeaders 单头布局：TotalLen[0:4] +
// HeaderLen[4:8] + Type[8:10] + txnDesc[10:18] + outstanding[18:22]）。
// 非 MARS 时 PRELOGIN 数据 0x00、SPID=0、outstanding=1（AutoCommit 固定）。
// 注意 BuildLogin7 把 SPID 硬编码为 0（builder_packet.go:297），MARS SPID
// 只作用于请求帧。
func TestLayerGen_MARSSpidAndOutstanding(t *testing.T) {
	cfg := layerCfg()
	cfg.MarsEnabled = true
	cfg.Sessions = []SessionSpec{
		{ID: "a", Requests: []RequestSpec{{Type: RequestSQLBatch,
			Sql: &SqlBatchSpec{Statements: []StatementSpec{{Text: "select 1"}}}}}},
		{ID: "b", Requests: []RequestSpec{{Type: RequestRPC,
			Rpc: &RpcSpec{ProcID: uint16Ptr(10)}}}},
	}
	events := collectEvents(t, layerSpec(cfg))
	// PRELOGIN(up)：option 表 token 0x04 恒在，数据区 0x01（MARS on）。
	if events[0].Bytes[0] != TypePreLogin {
		t.Fatalf("event[0] = 0x%02x, want PRELOGIN", events[0].Bytes[0])
	}
	if !preloginHasMARS(events[0].Bytes, true) {
		t.Errorf("PRELOGIN missing MARS option data 0x01: % X", events[0].Bytes)
	}
	// LOGIN7 与请求 SPID：请求帧 0x0042。
	upCount := 0
	for i, ev := range events {
		if !ev.Up || len(ev.Bytes) < 8 {
			continue
		}
		switch ev.Bytes[0] {
		case TypeSQLBatch, TypeRPC:
			upCount++
			if spid := binary.BigEndian.Uint16(ev.Bytes[4:6]); spid != 0x0042 {
				t.Errorf("event[%d] spid = 0x%04x, want 0x0042 (MARS)", i, spid)
			}
			body := ev.Bytes[8:]
			if len(body) < 22 {
				t.Fatalf("request too short for ALL_HEADERS: % X", ev.Bytes)
			}
			if got := binary.LittleEndian.Uint32(body[18:22]); got != 2 {
				t.Errorf("event[%d] outstanding = %d, want 2 (len(Sessions))", i, got)
			}
			if hd := binary.LittleEndian.Uint32(body[4:8]); hd != 18 {
				t.Errorf("event[%d] ALL_HEADERS header_len = %d, want 18", i, hd)
			}
			if tl := binary.LittleEndian.Uint32(body[0:4]); tl != 22 {
				t.Errorf("event[%d] ALL_HEADERS total_len = %d, want 22", i, tl)
			}
		}
	}
	if upCount != 2 {
		t.Fatalf("up requests = %d, want 2 (SQLBatch + RPC)", upCount)
	}
	// 非 MARS：PRELOGIN 数据 0x00、SPID=0、outstanding=1。
	nonMars := collectEvents(t, layerSpec(layerCfg()))
	if !preloginHasMARS(nonMars[0].Bytes, false) {
		t.Errorf("non-MARS PRELOGIN missing MARS option data 0x00: % X", nonMars[0].Bytes)
	}
	for _, ev := range nonMars {
		if ev.Up && ev.Bytes[0] == TypeSQLBatch {
			if spid := binary.BigEndian.Uint16(ev.Bytes[4:6]); spid != 0 {
				t.Errorf("non-MARS SQL Batch spid = 0x%04x, want 0", spid)
			}
			body := ev.Bytes[8:]
			if len(body) < 22 {
				t.Fatalf("non-MARS request too short for ALL_HEADERS: % X", ev.Bytes)
			}
			if got := binary.LittleEndian.Uint32(body[18:22]); got != 1 {
				t.Errorf("non-MARS SQL Batch outstanding = %d, want 1 (AutoCommit)", got)
			}
		}
	}
}

// preloginHasMARS 解析 PRELOGIN option 表：token 0x04 (PLMARS) 的 data 区
// 是否等于 want（0x01 = MARS on，0x00 = off）。option 表条目 5B
// （token + offset 2B BE + len 2B BE），0xFF 终止，数据区在表后。
func preloginHasMARS(pkt []byte, want bool) bool {
	body := pkt[8:]
	pos := 0
	for pos+5 <= len(body) {
		if body[pos] == 0xFF {
			return false
		}
		if body[pos] == PLMARS {
			off := int(binary.BigEndian.Uint16(body[pos+1 : pos+3]))
			l := int(binary.BigEndian.Uint16(body[pos+3 : pos+5]))
			if off+l > len(body) {
				return false
			}
			on := l >= 1 && body[off] == 0x01
			return on == want
		}
		pos += 5
	}
	return false
}

// TestLayerGen_ChainPlannerBytes 链级字节验证：ChainPlanner 驱动
// [ip→tcp→tds] 完整链路，数据帧与 legacy 逐字节一致。挥手为 TCPGenerator
// 标准 4 包（FIN|ACK up → ACK down → FIN|ACK down → ACK up）——legacy
// tds.go 是 2 包挥手（FIN-ACK up → FIN-ACK down，tds.go:539-542），层模型
// 意图的文档化分歧（mqtt/modbus/dnp3/doip 链测试同款断言形状）。
func TestLayerGen_ChainPlannerBytes(t *testing.T) {
	cfg := layerCfg()
	spec := layerSpec(cfg)
	spec.TCP = &core.TCPConfig{InitialSeq: 1000} // 确定性 ISN
	planner := layers.NewChainPlannerFromChain("tds", []layers.Layer{
		{Name: "ip"},
		{Name: "tcp"},
		{Name: "tds"},
	})
	ch, err := planner.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("ChainPlanner Plan: %v", err)
	}
	var pkts []core.PacketConfig
	for p := range ch {
		pkts = append(pkts, p)
	}
	// 默认配置：握手 3 + 数据 6（PRELOGIN、PRELOGIN response、LOGIN7、
	// Login response、SQLBatch、SQLBatch response）+ 挥手 4 = 13。
	if len(pkts) != 13 {
		t.Fatalf("got %d packets, want 13 (handshake 3 + data 6 + teardown 4)", len(pkts))
	}
	wantFlags := []uint8{0x02, 0x12, 0x10,
		0x18, 0x18, 0x18, 0x18, 0x18, 0x18,
		0x11, 0x10, 0x11, 0x10}
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
	// 数据帧方向/字节与 legacy 逐帧一致（legacy 数据帧恒 0x18 PSH-ACK 且与
	// 事件一一对应——链上 tcp 层将事件直落数据段，帧形状等价）。
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
	// down 数据帧端口交换（legacy 同款：down 帧源端口 = DstPort 1433）。
	if pkts[4].L4.SrcPort != 1433 || pkts[4].L4.DstPort != 50000 {
		t.Errorf("down data frame ports = %d/%d, want 1433/50000", pkts[4].L4.SrcPort, pkts[4].L4.DstPort)
	}
	// 挥手 seq 连续性（seq 只按同侧负载推进）：FIN|ACK(up) pkts[9] 继承最后
	// up 数据帧（pkts[7] = SQLBatch up）尾部 seq；FIN|ACK(down) pkts[11]
	// 继承最后 down 数据帧（pkts[8] = SQLBatch response down）尾部 seq
	// （pkts[10] 是 FIN(up) 的 ACK 回执，空负载不推进 serverSeq）。
	if pkts[9].L4.Seq != pkts[7].L4.Seq+uint32(len(pkts[7].Payload)) {
		t.Errorf("FIN(up) seq = %d, want up data tail %d", pkts[9].L4.Seq, pkts[7].L4.Seq+uint32(len(pkts[7].Payload)))
	}
	if pkts[11].L4.Seq != pkts[8].L4.Seq+uint32(len(pkts[8].Payload)) {
		t.Errorf("FIN(down) seq = %d, want down data tail %d", pkts[11].L4.Seq, pkts[8].L4.Seq+uint32(len(pkts[8].Payload)))
	}
}

// TestLayerGen_ChainPlannerLoginError 链级 Login.Error：数据帧只有 4
// （PRELOGIN 对 + LOGIN7 对，无会话），挥手 4 包 → 11 包；Login response
// 携带 ERROR token。
func TestLayerGen_ChainPlannerLoginError(t *testing.T) {
	cfg := layerCfg()
	cfg.Login = &LoginSpec{Error: layerErrSpec(18456, 14, "Login failed for user 'sa'.")}
	spec := layerSpec(cfg)
	spec.TCP = &core.TCPConfig{InitialSeq: 1000}
	planner := layers.NewChainPlannerFromChain("tds", []layers.Layer{
		{Name: "ip"},
		{Name: "tcp"},
		{Name: "tds"},
	})
	ch, err := planner.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("ChainPlanner Plan: %v", err)
	}
	var pkts []core.PacketConfig
	for p := range ch {
		pkts = append(pkts, p)
	}
	// 11 = 握手 3 + 数据 4 + 挥手 4。
	if len(pkts) != 11 {
		t.Fatalf("got %d packets, want 11 (handshake 3 + login 4 + teardown 4)", len(pkts))
	}
	// 数据帧只有 4：PRELOGIN(up) PRELOGIN response(down) LOGIN7(up)
	// Login response(down)；无任何 SQLBatch/RPC/TransMgr/Attention 请求。
	for i := 3; i < 7; i++ {
		if pkts[i].Direction == "up" && len(pkts[i].Payload) > 0 {
			switch pkts[i].Payload[0] {
			case TypeSQLBatch, TypeRPC, TypeTransMgrReq, TypeAttention:
				t.Fatalf("packet %d session request emitted after login failure", i)
			}
		}
	}
	if !bytes.Contains(pkts[6].Payload, []byte{TokenError}) {
		t.Errorf("login response missing ERROR token: % X", pkts[6].Payload)
	}
}

// TestLayerGen_ChainPlannerDstPortDefault 目的端口默认：spec.DstPort=0 →
// 1433（validateSpecBase tds 分支，legacy Plan 同款默认）。
func TestLayerGen_ChainPlannerDstPortDefault(t *testing.T) {
	spec := layerSpec(layerCfg())
	spec.DstPort = 0
	planner := layers.NewChainPlannerFromChain("tds", []layers.Layer{
		{Name: "ip"},
		{Name: "tcp"},
		{Name: "tds"},
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
	if pkts[0].L4.DstPort != 1433 {
		t.Errorf("SYN dst_port = %d, want 1433 (default)", pkts[0].L4.DstPort)
	}
}

// TestLayerGen_ChainPlannerSrcPortZero srcPort 0 保持 0：legacy Plan 用
// spec.SrcPort 原值（0 也上包），validateSpecBase tds 分支不默认化。
func TestLayerGen_ChainPlannerSrcPortZero(t *testing.T) {
	spec := layerSpec(layerCfg())
	spec.SrcPort = 0
	planner := layers.NewChainPlannerFromChain("tds", []layers.Layer{
		{Name: "ip"},
		{Name: "tcp"},
		{Name: "tds"},
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
		t.Errorf("SYN src_port = %d, want 0 (kept as-is)", pkts[0].L4.SrcPort)
	}
}

// TestLayerGen_ChainPlannerRejectsInvalidSpec 链级负向：非法 spec 经
// ChainPlanner 校验拒绝（validator 触发）。覆盖 legacy Validate 的主要
// 检查：非法版本、PacketSize 越界、无会话、多会话未开 MARS、SQL Batch 无
// sql、ProcName+ProcID 互斥、登录错误 class < 11、非法 Payload JSON。
func TestLayerGen_ChainPlannerRejectsInvalidSpec(t *testing.T) {
	planner := layers.NewChainPlannerFromChain("tds", []layers.Layer{
		{Name: "ip"},
		{Name: "tcp"},
		{Name: "tds"},
	})
	// 非法版本。
	cfg := layerCfg()
	cfg.Version = TDSVersion(0x1234)
	spec := layerSpec(cfg)
	if _, err := planner.Plan(context.Background(), spec); err == nil || !strings.Contains(err.Error(), "invalid version") {
		t.Fatalf("Plan with bad version error = %v, want invalid version", err)
	}
	// PacketSize 越界（< 512）。
	cfg = layerCfg()
	cfg.PacketSize = 100
	spec = layerSpec(cfg)
	if _, err := planner.Plan(context.Background(), spec); err == nil || !strings.Contains(err.Error(), "invalid packet_size") {
		t.Fatalf("Plan with packet_size=100 error = %v, want invalid packet_size", err)
	}
	// 无会话（V-TDS-003）。
	cfg = layerCfg()
	cfg.Sessions = nil
	spec = layerSpec(cfg)
	if _, err := planner.Plan(context.Background(), spec); err == nil || !strings.Contains(err.Error(), "at least one session") {
		t.Fatalf("Plan with no sessions error = %v, want at least one session", err)
	}
	// 多会话未开 MARS（V-TDS-038）。
	cfg = layerCfg()
	cfg.Sessions = []SessionSpec{
		{ID: "a", Requests: []RequestSpec{{Type: RequestSQLBatch,
			Sql: &SqlBatchSpec{Statements: []StatementSpec{{Text: "select 1"}}}}}},
		{ID: "b", Requests: []RequestSpec{{Type: RequestSQLBatch,
			Sql: &SqlBatchSpec{Statements: []StatementSpec{{Text: "select 2"}}}}}},
	}
	spec = layerSpec(cfg)
	if _, err := planner.Plan(context.Background(), spec); err == nil || !strings.Contains(err.Error(), "mars=true") {
		t.Fatalf("Plan with multi-session non-mars error = %v, want mars=true", err)
	}
	// SQL Batch 缺 sql（V-TDS-006）。
	cfg = layerCfg()
	cfg.Sessions = []SessionSpec{{ID: "s", Requests: []RequestSpec{{Type: RequestSQLBatch}}}}
	spec = layerSpec(cfg)
	if _, err := planner.Plan(context.Background(), spec); err == nil || !strings.Contains(err.Error(), "sql missing") {
		t.Fatalf("Plan with sql_batch missing sql error = %v, want sql missing", err)
	}
	// ProcName + ProcID 互斥（V-TDS-024）。
	cfg = layerCfg()
	cfg.Sessions = []SessionSpec{{ID: "s", Requests: []RequestSpec{{
		Type: RequestRPC,
		Rpc:  &RpcSpec{ProcName: "sp_who", ProcID: uint16Ptr(10)},
	}}}}
	spec = layerSpec(cfg)
	if _, err := planner.Plan(context.Background(), spec); err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("Plan with proc_name+proc_id error = %v, want mutually exclusive", err)
	}
	// 登录错误 class < 11（V-TDS-060）。
	cfg = layerCfg()
	cfg.Login = &LoginSpec{Error: layerErrSpec(1, 5, "info-ish")}
	spec = layerSpec(cfg)
	if _, err := planner.Plan(context.Background(), spec); err == nil || !strings.Contains(err.Error(), "class") {
		t.Fatalf("Plan with login error class=5 error = %v, want class rejection", err)
	}
	// 非法 Payload JSON（configFromSpec 拒绝，validator 路径）。
	spec = layerSpec(layerCfg())
	spec.Payload = []byte("{not json")
	if _, err := planner.Plan(context.Background(), spec); err == nil || !strings.Contains(err.Error(), "invalid config JSON") {
		t.Fatalf("Plan with invalid payload JSON error = %v, want invalid config JSON", err)
	}
}

// TestLayerGen_NilEmitMsg EmitMsg 未接线即报错（不能静默丢事件）。
func TestLayerGen_NilEmitMsg(t *testing.T) {
	gen := &TDSGenerator{}
	req := &layers.GenRequest{Meta: layers.FlowMeta{Payload: layerSpec(layerCfg()).Payload}}
	if err := gen.Generate(context.Background(), req); err == nil {
		t.Fatal("Generate with nil EmitMsg returned nil, want error")
	}
}

// TestLayerGen_InvalidJSON 非法 Payload JSON 即报错（不产任何事件）。
func TestLayerGen_InvalidJSON(t *testing.T) {
	gen := &TDSGenerator{}
	var events []layers.MessageEvent
	req := &layers.GenRequest{
		Meta: layers.FlowMeta{Payload: []byte("{not json")},
		EmitMsg: func(ev layers.MessageEvent) error {
			events = append(events, ev)
			return nil
		},
	}
	if err := gen.Generate(context.Background(), req); err == nil {
		t.Fatal("Generate with invalid config JSON returned nil, want error")
	}
	if len(events) != 0 {
		t.Fatalf("emitted %d events on invalid config, want 0", len(events))
	}
}

// TestLayerGen_EmitMsgErrorPropagates emit 错误向上传播（不能吞）。
func TestLayerGen_EmitMsgErrorPropagates(t *testing.T) {
	gen := &TDSGenerator{}
	sentinel := errors.New("emit failed")
	req := &layers.GenRequest{
		Meta: layers.FlowMeta{Payload: layerSpec(layerCfg()).Payload},
		EmitMsg: func(ev layers.MessageEvent) error {
			return sentinel
		},
	}
	if err := gen.Generate(context.Background(), req); !errors.Is(err, sentinel) {
		t.Fatalf("Generate error = %v, want sentinel", err)
	}
}

// TestLayerGen_CancelMidSequence 取消后停止产事件（精确计数）：PRELOGIN 对 +
// LOGIN7 对共 4 事件，第 4 个事件后取消 → 返回 context 错误且只发出 4
// 事件（会话阶段前）。
func TestLayerGen_CancelMidSequence(t *testing.T) {
	gen := &TDSGenerator{}
	ctx, cancel := context.WithCancel(context.Background())
	var mu sync.Mutex
	var events []layers.MessageEvent
	cancelled := false
	req := &layers.GenRequest{
		Meta: layers.FlowMeta{Payload: layerSpec(layerCfg()).Payload},
		EmitMsg: func(ev layers.MessageEvent) error {
			mu.Lock()
			events = append(events, ev)
			n := len(events)
			mu.Unlock()
			if n == 4 { // 第 4 个事件后取消（Login response 完成，会话前）
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
	if len(events) != 4 {
		t.Fatalf("emitted %d events, want exactly 4 (cancelled before sessions)", len(events))
	}
}

// TestLayerGen_EmptyStringsPresenceCheck T-026 类 presence-check：显式空
// 字符串保留——raw JSON 里显式 "app_name":"" 与 "password":"" 时，生成器
// 产出的 LOGIN7 cchAppName=0 且 cchPassword=0（BuildLogin7 的
// obfuscatePassword 对空串产 0 字节）；applyDefaults 不覆盖 present 键。
func TestLayerGen_EmptyStringsPresenceCheck(t *testing.T) {
	raw := `{"app_name":"","password":"","sessions":[{"id":"s1","requests":[
		{"type":"sql_batch","sql":{"statements":[{"text":"select 1"}]}}]}]}`
	events := collectEvents(t, layerSpecRaw(raw))
	if len(events) != 6 {
		t.Fatalf("events = %d, want 6", len(events))
	}
	login := events[2].Bytes
	if login[0] != TypeLogin7 {
		t.Fatalf("event[2] = 0x%02x, want LOGIN7", login[0])
	}
	// LOGIN7 offset 表从 body 偏移 36 起（固定头 36B），9 对 (ib,cch) 各 4B
	// LE；第 3 对 = Password（index 2），第 4 对 = AppName（index 3）。
	// 显式空 → cch=0。
	off := func(idx int) (ib, cch uint16) {
		base := 36 + idx*4
		return binary.LittleEndian.Uint16(login[8+base : 8+base+2]),
			binary.LittleEndian.Uint16(login[8+base+2 : 8+base+4])
	}
	if _, cch := off(2); cch != 0 {
		t.Errorf("LOGIN7 cchPassword = %d, want 0 (explicit empty password preserved)", cch)
	}
	if _, cch := off(3); cch != 0 {
		t.Errorf("LOGIN7 cchAppName = %d, want 0 (explicit empty app_name preserved)", cch)
	}
	// 对照：显式非空密码 → cchPassword > 0。
	cfg := layerCfg()
	cfg.Password = "s3cret"
	events2 := collectEvents(t, layerSpec(cfg))
	l2 := events2[2].Bytes
	base := 36 + 2*4
	if cch := binary.LittleEndian.Uint16(l2[8+base+2 : 8+base+4]); cch == 0 {
		t.Error("LOGIN7 cchPassword = 0 with non-empty password, want > 0")
	}
}

// uint16Ptr / stringPtr are small helpers for pointer fields.
func uint16Ptr(v uint16) *uint16 { return &v }
func stringPtr(s string) *string { return &s }
