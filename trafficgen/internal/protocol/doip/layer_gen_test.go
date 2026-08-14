package doip

// DoIP terminal-layer generator tests (P4a)。DoIPGenerator 阶段逐报文复用
// build* 纯函数产事件——事件序列与 legacy Plan 的数据帧（TCP 握手/挥手
// 过滤后）在方向/字节上逐帧一致；链级测试通过 ChainPlanner 驱动
// [ip→tcp→doip] 完整链路验证握手→数据→挥手与 legacy 数据帧字节一致。

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

// basicSpec builds a valid DoIP flow spec (activation + one diagnostic
// message, tcp)。DoIPConfig 无 TCP 状态字段，生成器只读不改（无需深拷贝；
// 保留值语义以防未来扩展引入副作用）。
func basicSpec(cfg *core.DoIPConfig) core.FlowSpec {
	if cfg == nil {
		cfg = &core.DoIPConfig{}
	}
	return core.FlowSpec{
		SrcIP:   "192.168.1.1",
		DstIP:   "192.168.1.2",
		SrcPort: 12345,
		DstPort: 13400,
		SrcMAC:  "aa:bb:cc:dd:ee:ff",
		DstMAC:  "11:22:33:44:55:66",
		DoIP:    cfg,
	}
}

// basicActivation is the common activation+message config used by most
// tests (tester 0x0E80, ecu 0x0001, one 0x8001 diagnostic)。
func basicActivation() *core.DoIPConfig {
	return &core.DoIPConfig{
		Activation: &core.DoIPActivation{
			Direction:      "up",
			ActivationType: 0x00,
			ResponseCode:   0x10,
		},
		Messages: []core.DoIPMessage{{
			Direction: "up",
			UserData:  []byte{0x22, 0xF1, 0x90, 0x01},
		}},
	}
}

// collectEvents drives DoIPGenerator.Generate and collects the emitted
// message events in order.
func collectEvents(t *testing.T, spec core.FlowSpec) []layers.MessageEvent {
	t.Helper()
	var events []layers.MessageEvent
	gen := &DoIPGenerator{}
	meta := layers.FlowMeta{
		SrcIP:   spec.SrcIP,
		DstIP:   spec.DstIP,
		SrcPort: spec.SrcPort,
		DstPort: spec.DstPort,
		DoIP:    spec.DoIP,
		TCP:     spec.TCP,
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

// legacyDataFrames runs the legacy planner and returns the DoIP data frames
// (skip TCP handshake/teardown)。数据帧 flags=0x18 PSH-ACK（emitDoIP tcp
// 分支，doip.go:402-404），与事件一一对应。
func legacyDataFrames(t *testing.T, spec core.FlowSpec) []core.PacketConfig {
	t.Helper()
	ch, err := (&Planner{}).Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("legacy Plan: %v", err)
	}
	var out []core.PacketConfig
	for c := range ch {
		if c.L4.Flags == 0x18 {
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
// 方向/payload 上逐帧一致。覆盖核心场景矩阵（每个阶段至少一例）。
func TestLayerGen_EventsMatchLegacyPlan(t *testing.T) {
	ack := byte(0x00)
	nack := byte(0x02)
	cases := []struct {
		name    string
		cfg     *core.DoIPConfig
		wantDir []bool // 非 nil = divergence 用例（仅断言方向，不对比 legacy）
	}{
		{"activation only", &core.DoIPConfig{
			Activation: &core.DoIPActivation{ResponseCode: 0x10},
		}, nil},
		{"activation + message up", basicActivation(), nil},
		// Activation.Direction="down"：生成器尊重字段（请求 down/响应 up），
		// 与 legacy 硬编码方向分歧（divergence，layer_gen.go 头注释）——
		// 生成器行为断言用 wantDir 而非 legacy 对比。
		{"activation direction down", &core.DoIPConfig{
			Activation: &core.DoIPActivation{Direction: "down", ResponseCode: 0x10},
		}, []bool{false, true}},
		{"message down", &core.DoIPConfig{
			Activation: &core.DoIPActivation{ResponseCode: 0x10},
			Messages: []core.DoIPMessage{{
				Direction: "down",
				UserData:  []byte{0x62, 0xF1, 0x90, 0x01},
			}},
		}, nil},
		{"message with explicit SA/TA", &core.DoIPConfig{
			Activation:   &core.DoIPActivation{ResponseCode: 0x10},
			LogicalAddress: 0x1001,
			Messages: []core.DoIPMessage{{
				SourceAddress: 0x0E80,
				TargetAddress: 0x1001,
				UserData:      []byte{0x22, 0xF1, 0x90, 0x01},
			}},
		}, nil},
		{"nack instead of ack", &core.DoIPConfig{
			Activation: &core.DoIPActivation{ResponseCode: 0x10},
			Messages: []core.DoIPMessage{{
				UserData: []byte{0x22, 0xF1, 0x90, 0x01},
				NackCode: &nack,
			}},
		}, nil},
		{"confirmation required", &core.DoIPConfig{
			Activation: &core.DoIPActivation{
				ResponseCode: 0x11, ConfirmationRequired: true,
			},
		}, nil},
		{"confirmation required + message", &core.DoIPConfig{
			Activation: &core.DoIPActivation{
				ResponseCode: 0x11, ConfirmationRequired: true,
			},
			Messages: []core.DoIPMessage{{UserData: []byte{0x22, 0xF1, 0x90}}},
		}, nil},
		{"oem specific data", &core.DoIPConfig{
			Activation: &core.DoIPActivation{
				ResponseCode: 0x10, OEMSpecific: []byte{0xDE, 0xAD, 0xBE, 0xEF},
			},
		}, nil},
		{"uds structured message", &core.DoIPConfig{
			Activation: &core.DoIPActivation{ResponseCode: 0x10},
			Messages: []core.DoIPMessage{{
				UDS: &core.DoIPUDS{ServiceID: 0x22, Data: []byte{0x90, 0x01}},
			}},
		}, nil},
		{"uds positive response", &core.DoIPConfig{
			Activation: &core.DoIPActivation{ResponseCode: 0x10},
			Messages: []core.DoIPMessage{{
				UDS: &core.DoIPUDS{ServiceID: 0x22, IsResponse: true, Data: []byte{0x90, 0x01}},
			}},
		}, nil},
		{"multiple messages", &core.DoIPConfig{
			Activation: &core.DoIPActivation{ResponseCode: 0x10},
			Messages: []core.DoIPMessage{
				{UserData: []byte{0x10, 0x03}},
				{UserData: []byte{0x22, 0xF1, 0x90}},
				{Direction: "down", UserData: []byte{0x62, 0xF1, 0x90}},
			},
		}, nil},
		{"alive check request", &core.DoIPConfig{
			Activation: &core.DoIPActivation{ResponseCode: 0x10},
			AliveCheck: &core.DoIPAliveCheck{Direction: "down"},
		}, nil},
		{"alive check response", &core.DoIPConfig{
			Activation: &core.DoIPActivation{ResponseCode: 0x10},
			AliveCheck: &core.DoIPAliveCheck{Direction: "up"},
		}, nil},
		{"generic nack", &core.DoIPConfig{
			GenericNack: &core.DoIPGenericNack{NackCode: 0x02},
		}, nil},
		{"alive check + generic nack", &core.DoIPConfig{
			Activation: &core.DoIPActivation{ResponseCode: 0x10},
			AliveCheck: &core.DoIPAliveCheck{Direction: "down"},
			GenericNack: &core.DoIPGenericNack{NackCode: 0x00},
		}, nil},
		// 0x7F 负响应优先于 SID 序列化（serializeUDS doip.go:960-962）。
		{"uds negative response", &core.DoIPConfig{
			Activation: &core.DoIPActivation{ResponseCode: 0x10},
			Messages: []core.DoIPMessage{{
				UDS: &core.DoIPUDS{ServiceID: 0x22, NegativeResponseCode: 0x31},
			}},
		}, nil},
		// HasSubFunction=true 显式输出 SubFunction 字节（0x22 默认无）。
		{"uds explicit subfunction", &core.DoIPConfig{
			Activation: &core.DoIPActivation{ResponseCode: 0x10},
			Messages: []core.DoIPMessage{{
				UDS: &core.DoIPUDS{
					ServiceID: 0x27, SubFunction: 0x01,
					HasSubFunction: func() *bool { v := true; return &v }(),
				},
			}},
		}, nil},
		{"uds write data by identifier", &core.DoIPConfig{
			Activation: &core.DoIPActivation{ResponseCode: 0x10},
			Messages: []core.DoIPMessage{{
				UDS: &core.DoIPUDS{ServiceID: 0x2E, DID: []byte{0xF1, 0x90}, Data: []byte{0xAA, 0xBB}},
			}},
		}, nil},
		{"uds request download", &core.DoIPConfig{
			Activation: &core.DoIPActivation{ResponseCode: 0x10},
			Messages: []core.DoIPMessage{{
				UDS: &core.DoIPUDS{ServiceID: 0x34, AddressAndLength: []byte{0x01, 0x00, 0x10, 0x00, 0x10, 0x00, 0x00, 0x00}},
			}},
		}, nil},
		{"protocol version 1", &core.DoIPConfig{
			ProtocolVersion: 0x01,
			Activation:      &core.DoIPActivation{ResponseCode: 0x10},
		}, nil},
		{"custom addresses", &core.DoIPConfig{
			TesterAddress: 0x0E00, LogicalAddress: 0x0200,
			Activation: &core.DoIPActivation{ResponseCode: 0x10},
		}, nil},
		{"ack explicit zero", &core.DoIPConfig{
			Activation: &core.DoIPActivation{ResponseCode: 0x10},
			Messages: []core.DoIPMessage{{
				UserData: []byte{0x22, 0xF1, 0x90, 0x01},
				AckCode:  ack,
			}},
		}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec := basicSpec(tc.cfg)
			events := collectEvents(t, spec)
			if tc.wantDir != nil {
				// divergence 用例：生成器行为断言（不进 legacy 对比）。
				if len(events) != len(tc.wantDir) {
					t.Fatalf("events = %d, want %d", len(events), len(tc.wantDir))
				}
				for i, up := range tc.wantDir {
					if events[i].Up != up {
						t.Errorf("event %d Up=%v, want %v", i, events[i].Up, up)
					}
				}
				return
			}
			assertEventsMatchLegacy(t, spec, events)
		})
	}
}

// TestLayerGen_AliveCheckCustomSA 生成器级：AliveCheck.SourceAddress 覆盖
// 0x0008 响应 payload 的 SA（默认 testerAddr，doip.go:757-760 同款）。
// 注：链级 Validate 拒绝 SA != TesterAddress（doip.go:210-211），该分支在
// 链上不可达——生成器级直测锁定行为（与 legacy emit 逻辑逐字节一致）。
func TestLayerGen_AliveCheckCustomSA(t *testing.T) {
	events := collectEvents(t, basicSpec(&core.DoIPConfig{
		Activation: &core.DoIPActivation{ResponseCode: 0x10},
		AliveCheck: &core.DoIPAliveCheck{Direction: "up", SourceAddress: 0x1234},
	}))
	// activation req + resp + alive response = 3 事件。
	if len(events) != 3 {
		t.Fatalf("got %d events, want 3", len(events))
	}
	ev := events[2]
	if !ev.Up {
		t.Errorf("alive response = down, want up")
	}
	want := []byte{0x02, 0xFD, 0x00, 0x08, 0x00, 0x00, 0x00, 0x02, 0x12, 0x34}
	if !bytes.Equal(ev.Bytes, want) {
		t.Errorf("alive response = % X, want % X", ev.Bytes, want)
	}
}

// TestLayerGen_ActivationFrameBytes 完整帧字节断言：0x0005 Routing
// Activation Request 事件 = 8 字节 DoIP 头 + 7 字节 payload（SA + type +
// reserved 4 字节 0x00，buildRoutingActivationRequest 复用未漂移——
// u32BE(0) 的 Reserved ISO 是 4 字节 0x00 非 0xFF）。
func TestLayerGen_ActivationFrameBytes(t *testing.T) {
	events := collectEvents(t, basicSpec(&core.DoIPConfig{
		Activation: &core.DoIPActivation{ActivationType: 0x00, ResponseCode: 0x10},
	}))
	if len(events) != 2 {
		t.Fatalf("got %d events, want 2 (request + response)", len(events))
	}
	if !events[0].Up {
		t.Errorf("activation request event 0 = down, want up")
	}
	want := []byte{0x02, 0xFD, 0x00, 0x05, 0x00, 0x00, 0x00, 0x07,
		0x0E, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00}
	if len(events[0].Bytes) != 15 {
		t.Fatalf("activation request length = %d, want 15 (8 header + 7 payload)", len(events[0].Bytes))
	}
	if !bytes.Equal(events[0].Bytes, want) {
		t.Errorf("activation request = % X, want % X", events[0].Bytes, want)
	}
	if events[1].Up {
		t.Errorf("activation response event 1 = up, want down")
	}
	wantResp := []byte{0x02, 0xFD, 0x00, 0x06, 0x00, 0x00, 0x00, 0x09,
		0x0E, 0x80, 0x00, 0x01, 0x10, 0x00, 0x00, 0x00, 0x00}
	if !bytes.Equal(events[1].Bytes, wantResp) {
		t.Errorf("activation response = % X, want % X", events[1].Bytes, wantResp)
	}
}

// TestLayerGen_DirectionAlternation 事件方向模式：activation up/down →
// message up → ack down（0x8002 接收侧相反方向回）。
func TestLayerGen_DirectionAlternation(t *testing.T) {
	events := collectEvents(t, basicSpec(basicActivation()))
	if len(events) != 4 {
		t.Fatalf("got %d events, want 4 (act req + act resp + diag + ack)", len(events))
	}
	want := []bool{true, false, true, false}
	for i, up := range want {
		if events[i].Up != up {
			t.Errorf("event %d Up=%v, want %v", i, events[i].Up, up)
		}
	}
}

// TestLayerGen_MessageDownAckUp down 方向 message 的 ack 方向反转验证。
func TestLayerGen_MessageDownAckUp(t *testing.T) {
	events := collectEvents(t, basicSpec(&core.DoIPConfig{
		Activation: &core.DoIPActivation{ResponseCode: 0x10},
		Messages: []core.DoIPMessage{{
			Direction: "down",
			UserData:  []byte{0x62, 0xF1, 0x90, 0x01},
		}},
	}))
	if len(events) != 4 {
		t.Fatalf("got %d events, want 4 (act req + act resp + diag down + ack up)", len(events))
	}
	if events[2].Up {
		t.Errorf("diagnostic event 2 = up, want down")
	}
	if !events[3].Up {
		t.Errorf("ack event 3 = down, want up (ack in opposite direction)")
	}
}

// TestLayerGen_TransferDataSegmentation 0x36 TransferData 协议级分段专项：
// MSS=800 → 每块 758 字节（MSS-40-2），BlockSeq 递增；块首字节 = 0x36 SID
// + 当前块序号。与 legacy 相同配置逐帧字节一致。
func TestLayerGen_TransferDataSegmentation(t *testing.T) {
	data := make([]byte, 2000)
	for i := range data {
		data[i] = byte(i)
	}
	cfg := &core.DoIPConfig{
		Activation: &core.DoIPActivation{ResponseCode: 0x10},
		Messages: []core.DoIPMessage{{
			UDS: &core.DoIPUDS{
				ServiceID:           0x36,
				BlockSequenceCounter: 0x01,
				TransferData:         data,
			},
		}},
	}
	spec := basicSpec(cfg)
	spec.TCP = &core.TCPConfig{MSS: 800}
	events := collectEvents(t, spec)
	// 3 块（758+758+484），每块 0x8001 + 0x8002。
	if len(events) != 2+6 {
		t.Fatalf("got %d events, want 8 (2 activation + 6 segmented)", len(events))
	}
	// 块序号断言：0x8001 帧 payload[12] = 0x36 SID，payload[13] = blockSeq。
	for i := 0; i < 3; i++ {
		diag := events[2+2*i]
		// 8 头 + 4 地址 + 2（SID+blockSeq）= 14 偏移。
		if diag.Bytes[12] != 0x36 {
			t.Errorf("segment %d SID = 0x%02X, want 0x36", i, diag.Bytes[12])
		}
		if diag.Bytes[13] != 0x01+uint8(i) {
			t.Errorf("segment %d blockSeq = 0x%02X, want 0x%02X", i, diag.Bytes[13], 0x01+uint8(i))
		}
	}
	// 与 legacy 对比（同配置同 MSS）。
	legacy := legacyDataFrames(t, spec)
	if len(legacy) != 8 {
		t.Fatalf("legacy data frames = %d, want 8", len(legacy))
	}
	for i, ev := range events {
		if !bytes.Equal(ev.Bytes, legacy[i].Payload) {
			t.Errorf("event[%d] = % X, legacy = % X", i, ev.Bytes, legacy[i].Payload)
		}
	}
}

// TestLayerGen_TransferDataExactBoundary 分段边界：len==MSS-40 不触发分段
// （单帧），MSS-40+1 触发（两帧）。与 legacy 相同配置逐帧一致。
func TestLayerGen_TransferDataExactBoundary(t *testing.T) {
	mss := 800
	// 边界 = MSS-40：序列化 userData = 1(SID)+1(blockSeq)+758 = 760 = MSS-40，
	// 不触发分段（条件 > 非 >=）。
	cfg := &core.DoIPConfig{
		Activation: &core.DoIPActivation{ResponseCode: 0x10},
		Messages: []core.DoIPMessage{{
			UDS: &core.DoIPUDS{
				ServiceID:           0x36,
				BlockSequenceCounter: 0x00,
				TransferData:         make([]byte, mss-40-2),
			},
		}},
	}
	spec := basicSpec(cfg)
	spec.TCP = &core.TCPConfig{MSS: uint16(mss)}
	events := collectEvents(t, spec)
	// 2 activation + 1 diag + 1 ack = 4。
	if len(events) != 4 {
		t.Fatalf("exact-boundary events = %d, want 4 (no segmentation)", len(events))
	}
	legacy := legacyDataFrames(t, spec)
	if len(legacy) != 4 {
		t.Fatalf("legacy exact-boundary frames = %d, want 4", len(legacy))
	}
	// 边界+1：1(SID)+1(blockSeq)+759 = 761 > 760 → 两帧（757+2）。
	cfg2 := &core.DoIPConfig{
		Activation: &core.DoIPActivation{ResponseCode: 0x10},
		Messages: []core.DoIPMessage{{
			UDS: &core.DoIPUDS{
				ServiceID:           0x36,
				BlockSequenceCounter: 0x00,
				TransferData:         make([]byte, mss-40-1),
			},
		}},
	}
	spec2 := basicSpec(cfg2)
	spec2.TCP = &core.TCPConfig{MSS: uint16(mss)}
	events2 := collectEvents(t, spec2)
	if len(events2) != 2+4 {
		t.Fatalf("over-boundary events = %d, want 6 (2 activation + 2 diag + 2 ack)", len(events2))
	}
	legacy2 := legacyDataFrames(t, spec2)
	if len(legacy2) != 6 {
		t.Fatalf("legacy over-boundary frames = %d, want 6", len(legacy2))
	}
	for i, ev := range events2 {
		if !bytes.Equal(ev.Bytes, legacy2[i].Payload) {
			t.Errorf("event[%d] = % X, legacy = % X", i, ev.Bytes, legacy2[i].Payload)
		}
	}
}

// TestLayerGen_TransferDataPositiveResponse 0x76（IsResponse）分段路径：
// SID 首字节 = 0x76（serializeUDS SID|0x40）。
func TestLayerGen_TransferDataPositiveResponse(t *testing.T) {
	data := make([]byte, 2000)
	cfg := &core.DoIPConfig{
		Activation: &core.DoIPActivation{ResponseCode: 0x10},
		Messages: []core.DoIPMessage{{
			Direction: "down",
			UDS: &core.DoIPUDS{
				ServiceID:           0x36,
				IsResponse:          true,
				BlockSequenceCounter: 0x00,
				TransferData:         data,
			},
		}},
	}
	spec := basicSpec(cfg)
	spec.TCP = &core.TCPConfig{MSS: 800}
	events := collectEvents(t, spec)
	// 3 块（758+758+484）+ ack 3 + activation 2 = 8。
	if len(events) != 8 {
		t.Fatalf("got %d events, want 8", len(events))
	}
	for i := 0; i < 3; i++ {
		diag := events[2+2*i]
		if diag.Bytes[12] != 0x76 {
			t.Errorf("segment %d SID = 0x%02X, want 0x76 (positive response)", i, diag.Bytes[12])
		}
	}
	// 与 legacy 对比（方向/字节）。
	legacy := legacyDataFrames(t, spec)
	if len(legacy) != 8 {
		t.Fatalf("legacy data frames = %d, want 8", len(legacy))
	}
	for i, ev := range events {
		if (ev.Up && legacy[i].Direction != "up") || (!ev.Up && legacy[i].Direction != "down") {
			t.Errorf("event[%d] Up=%v, legacy Direction=%s", i, ev.Up, legacy[i].Direction)
		}
		if !bytes.Equal(ev.Bytes, legacy[i].Payload) {
			t.Errorf("event[%d] = % X, legacy = % X", i, ev.Bytes, legacy[i].Payload)
		}
	}
}

// TestLayerGen_TransferDataBelowMSS 小数据不触发分段（单帧 0x8001+ack）。
func TestLayerGen_TransferDataBelowMSS(t *testing.T) {
	cfg := &core.DoIPConfig{
		Activation: &core.DoIPActivation{ResponseCode: 0x10},
		Messages: []core.DoIPMessage{{
			UDS: &core.DoIPUDS{
				ServiceID:           0x36,
				BlockSequenceCounter: 0x00,
				TransferData:         []byte{0x01, 0x02, 0x03},
			},
		}},
	}
	events := collectEvents(t, basicSpec(cfg))
	if len(events) != 4 {
		t.Fatalf("got %d events, want 4 (2 activation + 1 diag + 1 ack)", len(events))
	}
}

// TestLayerGen_NilEmitMsg EmitMsg 未接线即报错（不能静默丢事件）。
func TestLayerGen_NilEmitMsg(t *testing.T) {
	gen := &DoIPGenerator{}
	req := &layers.GenRequest{Meta: layers.FlowMeta{DoIP: &core.DoIPConfig{}}}
	if err := gen.Generate(context.Background(), req); err == nil {
		t.Fatal("Generate with nil EmitMsg returned nil, want error")
	}
}

// TestLayerGen_NoConfig 无 DoIP 配置即报错。
func TestLayerGen_NoConfig(t *testing.T) {
	gen := &DoIPGenerator{}
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

// TestLayerGen_UDPPhasesRejected UDP 阶段（Discovery/EntityStatus/PowerMode）
// 显式拒绝（链无 UDP 混合流，事件模式只走 tcp 载体）。
func TestLayerGen_UDPPhasesRejected(t *testing.T) {
	phases := []struct {
		name string
		cfg  *core.DoIPConfig
	}{
		{"discovery", &core.DoIPConfig{Discovery: &core.DoIPDiscovery{RequestType: 0x0001}}},
		{"entity status", &core.DoIPConfig{EntityStatus: &core.DoIPEntityStatus{}}},
		{"power mode", &core.DoIPConfig{PowerMode: &core.DoIPPowerMode{}}},
	}
	for _, tc := range phases {
		t.Run(tc.name, func(t *testing.T) {
			gen := &DoIPGenerator{}
			var events []layers.MessageEvent
			req := &layers.GenRequest{
				Meta: layers.FlowMeta{DoIP: tc.cfg},
				EmitMsg: func(ev layers.MessageEvent) error {
					events = append(events, ev)
					return nil
				},
			}
			if err := gen.Generate(context.Background(), req); err == nil {
				t.Fatalf("Generate with %s returned nil, want error", tc.name)
			}
			// 拒绝前不产任何事件（UDP 阶段检查在生成首事件之前）。
			if len(events) != 0 {
				t.Fatalf("%s: emitted %d events, want 0 before rejection", tc.name, len(events))
			}
		})
	}
}

// TestLayerGen_ActivationFailedRejected 激活失败（ResponseCode 0x00-0x07，
// 或 0x11 无确认）显式拒绝（legacy 走 FIN 提前终止，链上由 tcp 层接管）。
func TestLayerGen_ActivationFailedRejected(t *testing.T) {
	codes := []struct {
		name    string
		cfg     *core.DoIPConfig
		wantErr string
	}{
		{"denied 0x05", &core.DoIPConfig{
			Activation: &core.DoIPActivation{ResponseCode: 0x05},
		}, "activation failed"},
		{"denied 0x00", &core.DoIPConfig{
			Activation: &core.DoIPActivation{ResponseCode: 0x00},
		}, "activation failed"},
		{"denied 0x07", &core.DoIPConfig{
			Activation: &core.DoIPActivation{ResponseCode: 0x07},
		}, "activation failed"},
		{"confirmation without required", &core.DoIPConfig{
			Activation: &core.DoIPActivation{ResponseCode: 0x11},
		}, "activation failed"},
	}
	for _, tc := range codes {
		t.Run(tc.name, func(t *testing.T) {
			gen := &DoIPGenerator{}
			var events []layers.MessageEvent
			req := &layers.GenRequest{
				Meta: layers.FlowMeta{DoIP: tc.cfg},
				EmitMsg: func(ev layers.MessageEvent) error {
					events = append(events, ev)
					return nil
				},
			}
			err := gen.Generate(context.Background(), req)
			if err == nil {
				t.Fatal("Generate with failed activation returned nil, want error")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %v, want containing %q", err, tc.wantErr)
			}
			// 失败后不产任何事件（第一对 req/resp 之后立即报错）。
			if len(events) != 2 {
				t.Fatalf("emitted %d events, want 2 (request+response before rejection)", len(events))
			}
		})
	}
}

// TestLayerGen_MessagesWithoutActivationRejected 双保险：Messages 无
// Activation 拒绝（legacy Validate 同款）。
func TestLayerGen_MessagesWithoutActivationRejected(t *testing.T) {
	gen := &DoIPGenerator{}
	req := &layers.GenRequest{
		Meta: layers.FlowMeta{DoIP: &core.DoIPConfig{
			Messages: []core.DoIPMessage{{UserData: []byte{0x22}}},
		}},
		EmitMsg: func(ev layers.MessageEvent) error {
			return nil
		},
	}
	if err := gen.Generate(context.Background(), req); err == nil {
		t.Fatal("Generate with messages but no activation returned nil, want error")
	}
}

// TestLayerGen_EmitMsgErrorPropagates emit 错误向上传播（不能吞）。
func TestLayerGen_EmitMsgErrorPropagates(t *testing.T) {
	gen := &DoIPGenerator{}
	sentinel := errors.New("emit failed")
	req := &layers.GenRequest{
		Meta: layers.FlowMeta{DoIP: basicActivation()},
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
	gen := &DoIPGenerator{}
	ctx, cancel := context.WithCancel(context.Background())
	var mu sync.Mutex
	var events []layers.MessageEvent
	cancelled := false
	req := &layers.GenRequest{
		Meta: layers.FlowMeta{DoIP: basicActivation()},
		EmitMsg: func(ev layers.MessageEvent) error {
			mu.Lock()
			events = append(events, ev)
			n := len(events)
			mu.Unlock()
			if n == 2 { // 第 2 个事件后取消（activation 交换完成）
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

// TestLayerGen_ChainPlannerBytes 链级字节验证：ChainPlanner 驱动
// [ip→tcp→doip] 完整链路（握手 3 + 数据 4 + 挥手 4 = 11 包），数据帧与
// legacy 逐字节一致，挥手为 TCPGenerator 标准 4 包（http 波 2 同款语义）。
func TestLayerGen_ChainPlannerBytes(t *testing.T) {
	spec := basicSpec(basicActivation())
	planner := layers.NewChainPlannerFromChain("doip", []layers.Layer{
		{Name: "ip"},
		{Name: "tcp"},
		{Name: "doip"},
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
		t.Fatalf("got %d packets, want 11 (handshake 3 + data 4 + teardown 4)", len(pkts))
	}
	// 握手：SYN(up) → SYN-ACK(down) → ACK(up)；数据 4 帧；挥手 4 包。
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
	// down 数据帧端口交换（legacy 同款：down 帧源端口 = 13400）。
	if pkts[4].L4.SrcPort != 13400 || pkts[4].L4.DstPort != 12345 {
		t.Errorf("down data frame ports = %d/%d, want 13400/12345", pkts[4].L4.SrcPort, pkts[4].L4.DstPort)
	}
	// down ack 帧端口交换（legacy 同款：ack 反向方向，down ack 源端口 =
	// 13400——所有 down 帧统一交换）。
	if pkts[6].L4.SrcPort != 13400 || pkts[6].L4.DstPort != 12345 {
		t.Errorf("down ack frame ports = %d/%d, want 13400/12345", pkts[6].L4.SrcPort, pkts[6].L4.DstPort)
	}
	// 握手 SYN 携带 MSS 选项（tcp 层 synOptions，MSS=1460 默认）。
	opt := pkts[0].L4.TCPOptions
	var mssOpt []byte
	for _, o := range opt {
		if o.Kind == core.TCPOptMSS {
			mssOpt = o.Data
		}
	}
	if len(mssOpt) != 2 || uint16(mssOpt[0])<<8|uint16(mssOpt[1]) != 1460 {
		t.Errorf("SYN MSS option = % X, want 05 B4 (1460)", mssOpt)
	}
	// 挥手 seq 连续性：FIN(up) 继承最后 up 数据帧尾部 seq（diag up =
	// pkts[5]）；FIN(down) 继承最后 down 数据帧尾部 seq（ack down =
	// pkts[6]）。
	if pkts[7].L4.Seq != pkts[5].L4.Seq+uint32(len(pkts[5].Payload)) {
		t.Errorf("FIN(up) seq = %d, want up data tail %d", pkts[7].L4.Seq, pkts[5].L4.Seq+uint32(len(pkts[5].Payload)))
	}
	if pkts[9].L4.Seq != pkts[6].L4.Seq+uint32(len(pkts[6].Payload)) {
		t.Errorf("FIN(down) seq = %d, want down data tail %d", pkts[9].L4.Seq, pkts[6].L4.Seq+uint32(len(pkts[6].Payload)))
	}
}

// TestLayerGen_ChainPlannerNoActivation 链级校准：Activation==nil 时
// validator 关掉 tcp 层握手/挥手（legacy 同款：无 activation 无 TCP 阶段）——
// 仅 GenericNack 数据帧，无 SYN/FIN。
func TestLayerGen_ChainPlannerNoActivation(t *testing.T) {
	spec := basicSpec(&core.DoIPConfig{
		GenericNack: &core.DoIPGenericNack{NackCode: 0x02},
	})
	planner := layers.NewChainPlannerFromChain("doip", []layers.Layer{
		{Name: "ip"},
		{Name: "tcp"},
		{Name: "doip"},
	})
	ch, err := planner.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("ChainPlanner Plan: %v", err)
	}
	var pkts []core.PacketConfig
	for p := range ch {
		pkts = append(pkts, p)
	}
	if len(pkts) != 1 {
		t.Fatalf("got %d packets, want 1 (generic nack only, no handshake/teardown)", len(pkts))
	}
	if pkts[0].L4.Flags != 0x18 || pkts[0].Direction != "down" {
		t.Errorf("packet 0 flags/dir = 0x%02x/%s, want 0x18/down", pkts[0].L4.Flags, pkts[0].Direction)
	}
	// 与 legacy 对比（legacy 无 activation 时同样只产 GenericNack 数据帧）。
	legacy := legacyDataFrames(t, spec)
	if len(legacy) != 1 {
		t.Fatalf("legacy data frames = %d, want 1", len(legacy))
	}
	if !bytes.Equal(pkts[0].Payload, legacy[0].Payload) {
		t.Errorf("payload = % X, legacy = % X", pkts[0].Payload, legacy[0].Payload)
	}
}

// TestLayerGen_ChainPlannerTransferData 链级 0x36 分段：MSS 走链上默认
// （spec.TCP=nil → tcp 层 DefaultMSS 1460），数据帧数与 legacy 一致
// （1418+1418+164 三块 + 2 activation + 3 ack）。
func TestLayerGen_ChainPlannerTransferData(t *testing.T) {
	data := make([]byte, 3000)
	for i := range data {
		data[i] = byte(i)
	}
	spec := basicSpec(&core.DoIPConfig{
		Activation: &core.DoIPActivation{ResponseCode: 0x10},
		Messages: []core.DoIPMessage{{
			UDS: &core.DoIPUDS{
				ServiceID:           0x36,
				BlockSequenceCounter: 0x00,
				TransferData:         data,
			},
		}},
	})
	planner := layers.NewChainPlannerFromChain("doip", []layers.Layer{
		{Name: "ip"},
		{Name: "tcp"},
		{Name: "doip"},
	})
	ch, err := planner.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("ChainPlanner Plan: %v", err)
	}
	var pkts []core.PacketConfig
	for p := range ch {
		pkts = append(pkts, p)
	}
	// 3 块（1418+1418+164）+ activation 2 + ack 3 → 数据 8；握手 3 + 挥手 4。
	if len(pkts) != 15 {
		t.Fatalf("got %d packets, want 15 (handshake 3 + data 8 + teardown 4)", len(pkts))
	}
	// 与 legacy 相同配置对比数据帧。
	legacy := legacyDataFrames(t, spec)
	if len(legacy) != 8 {
		t.Fatalf("legacy data frames = %d, want 8", len(legacy))
	}
	for i, l := range legacy {
		seg := pkts[3+i]
		if !bytes.Equal(seg.Payload, l.Payload) {
			t.Errorf("data frame %d payload = % X, legacy = % X", i, seg.Payload, l.Payload)
		}
	}
}

// TestLayerGen_ChainPlannerExplicitTCPFlags 链级 spec.TCP 显式开关（dnp3
// 同款测试）：handshake=false/termination=false → 仅数据事件，无 SYN/FIN。
// 注：Activation!=nil 时 validator 不改 spec.TCP（尊重显式 false）。
func TestLayerGen_ChainPlannerExplicitTCPFlags(t *testing.T) {
	f := false
	spec := basicSpec(basicActivation())
	spec.TCP = &core.TCPConfig{Handshake: f, Termination: f}
	planner := layers.NewChainPlannerFromChain("doip", []layers.Layer{
		{Name: "ip"},
		{Name: "tcp"},
		{Name: "doip"},
	})
	ch, err := planner.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("ChainPlanner Plan: %v", err)
	}
	var pkts []core.PacketConfig
	for p := range ch {
		pkts = append(pkts, p)
	}
	// 4 数据帧（2 activation + 1 diag + 1 ack），无握手/挥手。
	if len(pkts) != 4 {
		t.Fatalf("got %d packets, want 4 (data only, no handshake/teardown)", len(pkts))
	}
	for i, p := range pkts {
		if p.L4.Flags != 0x18 {
			t.Errorf("packet %d flags = 0x%02x, want 0x18 (data only)", i, p.L4.Flags)
		}
	}
}

// TestLayerGen_ChainPlannerRejectsInvalidSpec 链级负向矩阵：非法 spec 经
// ChainPlanner 校验拒绝（validator 触发，planner 名必须为 "doip"）。
// 覆盖 Validate 的主要拒绝行（ActivationType/ResponseCode/NackCode/UDS
// SID/NRC/GenericNack/MSS/Messages-require-Activation）；协议校验行全套在
// doip_extra_test.go 直测，此处验证"经链同样拦截"。
func TestLayerGen_ChainPlannerRejectsInvalidSpec(t *testing.T) {
	mutate := func(f func(*core.DoIPConfig)) *core.DoIPConfig {
		cfg := basicActivation()
		f(cfg)
		return cfg
	}
	cases := []struct {
		name string
		cfg  *core.DoIPConfig
	}{
		{"nack code 0x09 (must be 0x02-0x08)", mutate(func(c *core.DoIPConfig) {
			c.Messages = append(c.Messages, core.DoIPMessage{
				UserData: []byte{0x22}, NackCode: func() *uint8 { v := uint8(0x09); return &v }(),
			})
		})},
		{"activation type 0x02 (only 0x00/0x01/0xE0-0xFF)", mutate(func(c *core.DoIPConfig) {
			c.Activation.ActivationType = 0x02
		})},
		{"response code 0x0A (only 0x00-0x07/0x10/0x11)", mutate(func(c *core.DoIPConfig) {
			c.Activation.ResponseCode = 0x0A
		})},
		{"uds sid 0x62 request (unsupported)", mutate(func(c *core.DoIPConfig) {
			c.Messages = []core.DoIPMessage{{UDS: &core.DoIPUDS{ServiceID: 0x62}}}
		})},
		{"uds nrc 0x80 (must be 0x01-0x7F)", mutate(func(c *core.DoIPConfig) {
			c.Messages = []core.DoIPMessage{{
				UDS: &core.DoIPUDS{ServiceID: 0x22, NegativeResponseCode: 0x80},
			}}
		})},
		{"generic nack code 0x09 (must be 0x00-0x04)", mutate(func(c *core.DoIPConfig) {
			c.GenericNack = &core.DoIPGenericNack{NackCode: 0x09}
		})},
		// 链级拒绝（validator 链专用行，legacy 合法但链上无表达载体）：
		// UDP 阶段与激活失败。生成器同样显式拒绝（双保险）。
		{"discovery udp phase (chain)", &core.DoIPConfig{Discovery: &core.DoIPDiscovery{RequestType: 0x0001}}},
		{"entity status udp phase (chain)", &core.DoIPConfig{EntityStatus: &core.DoIPEntityStatus{}}},
		{"power mode udp phase (chain)", &core.DoIPConfig{PowerMode: &core.DoIPPowerMode{}}},
		{"activation denied 0x05 (chain)", mutate(func(c *core.DoIPConfig) {
			c.Activation.ResponseCode = 0x05
		})},
		{"activation denied 0x00 (chain)", mutate(func(c *core.DoIPConfig) {
			c.Activation.ResponseCode = 0x00
		})},
		{"confirmation missing 0x11 (chain)", mutate(func(c *core.DoIPConfig) {
			c.Activation.ResponseCode = 0x11
			c.Activation.ConfirmationRequired = false
		})},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec := basicSpec(tc.cfg)
			planner := layers.NewChainPlannerFromChain("doip", []layers.Layer{
				{Name: "ip"},
				{Name: "tcp"},
				{Name: "doip"},
			})
			if _, err := planner.Plan(context.Background(), spec); err == nil {
				t.Fatalf("ChainPlanner Plan with invalid %s returned nil, want error", tc.name)
			}
		})
	}
	// MSS < MinMSS 拒绝（spec.TCP.MSS 显式超小）。
	t.Run("mss below min", func(t *testing.T) {
		spec := basicSpec(basicActivation())
		spec.TCP = &core.TCPConfig{MSS: 100}
		planner := layers.NewChainPlannerFromChain("doip", []layers.Layer{
			{Name: "ip"},
			{Name: "tcp"},
			{Name: "doip"},
		})
		if _, err := planner.Plan(context.Background(), spec); err == nil {
			t.Fatal("ChainPlanner Plan with MSS=100 returned nil, want error")
		}
	})
	// Messages 无 Activation 拒绝（validator 行，直测见
	// TestValidate_MessagesRequireActivation）。
	t.Run("messages without activation", func(t *testing.T) {
		spec := basicSpec(&core.DoIPConfig{
			Messages: []core.DoIPMessage{{UserData: []byte{0x22}}},
		})
		planner := layers.NewChainPlannerFromChain("doip", []layers.Layer{
			{Name: "ip"},
			{Name: "tcp"},
			{Name: "doip"},
		})
		if _, err := planner.Plan(context.Background(), spec); err == nil {
			t.Fatal("ChainPlanner Plan with messages but no activation returned nil, want error")
		}
	})
}

// TestLayerGen_ChainPlannerTerminalRejectNoHang 生成中途拒绝（UDP 阶段、
// 激活失败）经完整链驱动时 Plan 返回错误且不挂死（review Agent 1 MAJOR
// 的验证面）：终结层错误路径下，tcp 层在事件流关闭时进入挥手正常退出。
func TestLayerGen_ChainPlannerTerminalRejectNoHang(t *testing.T) {
	rejects := []struct {
		name string
		cfg  *core.DoIPConfig
	}{
		{"discovery udp phase", &core.DoIPConfig{Discovery: &core.DoIPDiscovery{RequestType: 0x0001}}},
		{"activation denied", &core.DoIPConfig{
			Activation: &core.DoIPActivation{ResponseCode: 0x05},
		}},
		{"confirmation missing", &core.DoIPConfig{
			Activation: &core.DoIPActivation{ResponseCode: 0x11},
		}},
	}
	for _, tc := range rejects {
		t.Run(tc.name, func(t *testing.T) {
			spec := basicSpec(tc.cfg)
			planner := layers.NewChainPlannerFromChain("doip", []layers.Layer{
				{Name: "ip"},
				{Name: "tcp"},
				{Name: "doip"},
			})
			done := make(chan error, 1)
			go func() {
				_, err := planner.Plan(context.Background(), spec)
				done <- err
			}()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("Plan with terminal rejection returned nil, want error")
				}
				if !strings.Contains(err.Error(), "not supported") && !strings.Contains(err.Error(), "activation failed") {
					t.Fatalf("Plan error = %v, want rejection error", err)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("Plan hung: terminal rejection did not propagate (transport stuck)")
			}
		})
	}
}