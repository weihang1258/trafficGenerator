package moxa

import (
	"context"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

func TestValidateAcceptsEmptyConfig(t *testing.T) {
	// P0b-2：空配置默认化并产默认流（stream "hello"）。
	p := Planner{}
	if err := p.Validate(core.FlowSpec{}); err != nil {
		t.Fatalf("empty config Validate err=%v, want nil (default flow)", err)
	}
}

func TestValidateRejectsEmptyStream(t *testing.T) {
	p := Planner{}
	spec := core.FlowSpec{MOXA: &core.MOXAConfig{}}
	if err := p.Validate(spec); err == nil || !strings.Contains(err.Error(), "empty stream block") {
		t.Fatalf("err=%v want empty stream", err)
	}
	// 空数组
	spec.MOXA.Stream = []core.MOXAStreamBlock{}
	if err := p.Validate(spec); err == nil || !strings.Contains(err.Error(), "empty stream block") {
		t.Fatalf("err=%v want empty stream", err)
	}
}

func TestValidateRejectsEmptyPayload(t *testing.T) {
	p := Planner{}
	// 双空
	spec := core.FlowSpec{MOXA: &core.MOXAConfig{
		Stream: []core.MOXAStreamBlock{{Payload: "", PayloadB64: ""}},
	}}
	if err := p.Validate(spec); err == nil || !strings.Contains(err.Error(), "empty stream block") {
		t.Fatalf("err=%v want empty stream", err)
	}
}

func TestValidateRejectsOversizePayload(t *testing.T) {
	p := Planner{}
	data := make([]byte, 2049)
	for i := range data {
		data[i] = 'A'
	}
	spec := core.FlowSpec{MOXA: &core.MOXAConfig{
		Stream: []core.MOXAStreamBlock{{Payload: string(data)}},
	}}
	if err := p.Validate(spec); err == nil || !strings.Contains(err.Error(), "exceeds max") {
		t.Fatalf("err=%v want exceeds max", err)
	}
}

func TestValidateRejectsBadB64(t *testing.T) {
	p := Planner{}
	spec := core.FlowSpec{MOXA: &core.MOXAConfig{
		Stream: []core.MOXAStreamBlock{{PayloadB64: "%%%"}},
	}}
	if err := p.Validate(spec); err == nil || !strings.Contains(err.Error(), "invalid payload_b64") {
		t.Fatalf("err=%v want invalid payload_b64", err)
	}
}

func TestValidateRejectsBadDirection(t *testing.T) {
	p := Planner{}
	spec := core.FlowSpec{MOXA: &core.MOXAConfig{
		Stream: []core.MOXAStreamBlock{{Direction: "sideways", Payload: "hello"}},
	}}
	if err := p.Validate(spec); err == nil || !strings.Contains(err.Error(), "invalid direction") {
		t.Fatalf("err=%v want invalid direction", err)
	}
}

func TestValidateRejectsSessionsOverOne(t *testing.T) {
	p := Planner{}
	spec := core.FlowSpec{MOXA: &core.MOXAConfig{
		Sessions: 3,
		Stream:   []core.MOXAStreamBlock{{Payload: "hello"}},
	}}
	if err := p.Validate(spec); err == nil || !strings.Contains(err.Error(), "sessions=3>1 not supported") {
		t.Fatalf("err=%v want sessions>1", err)
	}
}

func TestValidateRejectsHandshakeFalse(t *testing.T) {
	p := Planner{}
	spec := core.FlowSpec{
		MOXA: &core.MOXAConfig{Stream: []core.MOXAStreamBlock{{Payload: "hello"}}},
		TCP:  &core.TCPConfig{Handshake: false},
	}
	if err := p.Validate(spec); err == nil || !strings.Contains(err.Error(), "tcp.handshake must be true") {
		t.Fatalf("err=%v want handshake must be true", err)
	}
}

func TestValidateRejectsConfigPacket(t *testing.T) {
	p := Planner{}
	// 探针 5a 5a 5a (ZZZ base64)
	spec := core.FlowSpec{MOXA: &core.MOXAConfig{
		Stream: []core.MOXAStreamBlock{{Payload: "ZZZ"}},
	}}
	if err := p.Validate(spec); err == nil || !strings.Contains(err.Error(), "config-packet bytes in stream") {
		t.Fatalf("err=%v want config-packet rejection", err)
	}
}

func TestValidateRejectsEmptyBlock(t *testing.T) {
	p := Planner{}
	// b64 解码后为空
	spec := core.FlowSpec{MOXA: &core.MOXAConfig{
		Stream: []core.MOXAStreamBlock{{PayloadB64: ""}},
	}}
	if err := p.Validate(spec); err == nil || !strings.Contains(err.Error(), "empty stream block") {
		t.Fatalf("err=%v want empty stream", err)
	}
}

func TestValidateAcceptsValidConfig(t *testing.T) {
	p := Planner{}
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1",
		MOXA: &core.MOXAConfig{Stream: []core.MOXAStreamBlock{{Payload: "hello"}}},
	}
	if err := p.Validate(spec); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateAcceptsB64Payload(t *testing.T) {
	p := Planner{}
	spec := core.FlowSpec{
		MOXA: &core.MOXAConfig{Stream: []core.MOXAStreamBlock{{PayloadB64: "aGFoYQ=="}}},
	}
	if err := p.Validate(spec); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateAcceptsDownDirection(t *testing.T) {
	p := Planner{}
	spec := core.FlowSpec{
		MOXA: &core.MOXAConfig{Stream: []core.MOXAStreamBlock{{Direction: "down", Payload: "response"}}},
	}
	if err := p.Validate(spec); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRejectsIPVersionMismatch(t *testing.T) {
	p := Planner{}
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "2001:db8::2",
		MOXA: &core.MOXAConfig{Stream: []core.MOXAStreamBlock{{Payload: "hello"}}},
	}
	if err := p.Validate(spec); err == nil || !strings.Contains(err.Error(), "same IP version") {
		t.Fatalf("err=%v want IP version mismatch", err)
	}
}

// S1: 单向上行，单块 "hello" → 8 包（3 握手 + 1 数据 + 4 挥手）
func TestPlanSingleUp(t *testing.T) {
	ch, err := (Planner{}).Plan(context.Background(), core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 40000, DstPort: 4800,
		MOXA: &core.MOXAConfig{Stream: []core.MOXAStreamBlock{{Payload: "hello"}}},
		TCP:  &core.TCPConfig{Handshake: true, Termination: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	var packets []core.PacketConfig
	for p := range ch {
		packets = append(packets, p)
	}
	if len(packets) != 8 {
		t.Fatalf("packets=%d want 8 (3 handshake + 1 data + 4 teardown)", len(packets))
	}
	// 包4: 数据段，payload="hello"
	if string(packets[3].Payload) != "hello" {
		t.Fatalf("data payload=%q want hello", string(packets[3].Payload))
	}
	if packets[3].Direction != "up" {
		t.Fatalf("data direction=%q want up", packets[3].Direction)
	}
	// 握手
	if packets[0].L4.Flags != 0x02 {
		t.Fatalf("packet0 flags=0x%x want SYN", packets[0].L4.Flags)
	}
	if packets[1].L4.Flags != 0x12 {
		t.Fatalf("packet1 flags=0x%x want SYN-ACK", packets[1].L4.Flags)
	}
	// 挥手尾4包
	if packets[4].L4.Flags != 0x11 {
		t.Fatalf("packet4 flags=0x%x want FIN-ACK", packets[4].L4.Flags)
	}
}

// S2: 超 MSS 分段，2000B → 2 段（1460+540）
func TestPlanMultiSegment(t *testing.T) {
	payload := make([]byte, 2000)
	for i := range payload {
		payload[i] = 'A'
	}
	ch, err := (Planner{}).Plan(context.Background(), core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 40000, DstPort: 4800,
		MOXA: &core.MOXAConfig{Stream: []core.MOXAStreamBlock{{Payload: string(payload)}}},
		TCP:  &core.TCPConfig{Handshake: true, Termination: true, MSS: 1460},
	})
	if err != nil {
		t.Fatal(err)
	}
	var packets []core.PacketConfig
	for p := range ch {
		packets = append(packets, p)
	}
	if len(packets) != 9 {
		t.Fatalf("packets=%d want 9 (3 handshake + 2 data + 4 teardown)", len(packets))
	}
	// 两段数据
	if len(packets[3].Payload) != 1460 {
		t.Fatalf("segment1 len=%d want 1460", len(packets[3].Payload))
	}
	if len(packets[4].Payload) != 540 {
		t.Fatalf("segment2 len=%d want 540", len(packets[4].Payload))
	}
	if packets[3].Payload[0] != 'A' || packets[4].Payload[0] != 'A' {
		t.Fatalf("segment data not 'A'")
	}
}

// S3: 双向流，WR/RT 交替
func TestPlanBidirectional(t *testing.T) {
	ch, err := (Planner{}).Plan(context.Background(), core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 40000, DstPort: 4800,
		MOXA: &core.MOXAConfig{
			Stream: []core.MOXAStreamBlock{
				{Direction: "up", Payload: "WR"},
				{Direction: "down", Payload: "RT"},
				{Direction: "up", Payload: "WR"},
				{Direction: "down", Payload: "RT"},
			},
		},
		TCP: &core.TCPConfig{Handshake: true, Termination: true, MSS: 536},
	})
	if err != nil {
		t.Fatal(err)
	}
	var packets []core.PacketConfig
	for p := range ch {
		packets = append(packets, p)
	}
	if len(packets) != 11 {
		t.Fatalf("packets=%d want 11 (3 handshake + 4 data + 4 teardown)", len(packets))
	}
	// 数据包验证
	checks := []struct {
		idx int
		dir string
		pay string
	}{
		{3, "up", "WR"},
		{4, "down", "RT"},
		{5, "up", "WR"},
		{6, "down", "RT"},
	}
	for _, c := range checks {
		if packets[c.idx].Direction != c.dir {
			t.Fatalf("packet%d direction=%q want %q", c.idx, packets[c.idx].Direction, c.dir)
		}
		if string(packets[c.idx].Payload) != c.pay {
			t.Fatalf("packet%d payload=%q want %q", c.idx, string(packets[c.idx].Payload), c.pay)
		}
	}
	// down 段 src_port=4800（服务器端口对换）
	if packets[4].L4.SrcPort != 4800 {
		t.Fatalf("down packet src_port=%d want 4800", packets[4].L4.SrcPort)
	}
}

// S5: 二进制 payload（payload_b64）
func TestPlanBinaryPayload(t *testing.T) {
	ch, err := (Planner{}).Plan(context.Background(), core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 40000, DstPort: 4800,
		MOXA: &core.MOXAConfig{Stream: []core.MOXAStreamBlock{{PayloadB64: "aGFoYQ=="}}},
		TCP:  &core.TCPConfig{Handshake: true, Termination: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	var packets []core.PacketConfig
	for p := range ch {
		packets = append(packets, p)
	}
	if len(packets) != 8 {
		t.Fatalf("packets=%d want 8", len(packets))
	}
	if string(packets[3].Payload) != "haha" {
		t.Fatalf("data payload=%q want haha", string(packets[3].Payload))
	}
}

// S6: IPv6 载体
func TestPlanIPv6(t *testing.T) {
	ch, err := (Planner{}).Plan(context.Background(), core.FlowSpec{
		SrcIP: "2001:db8::1", DstIP: "2001:db8::2", SrcPort: 40000, DstPort: 4800,
		MOXA: &core.MOXAConfig{Stream: []core.MOXAStreamBlock{{Payload: "hello"}}},
		TCP:  &core.TCPConfig{Handshake: true, Termination: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	var packets []core.PacketConfig
	for p := range ch {
		packets = append(packets, p)
	}
	if len(packets) != 8 {
		t.Fatalf("packets=%d want 8", len(packets))
	}
	if string(packets[3].Payload) != "hello" {
		t.Fatalf("data payload=%q want hello", string(packets[3].Payload))
	}
	if packets[3].L3.SrcIP != "2001:db8::1" {
		t.Fatalf("src=%q want 2001:db8::1", packets[3].L3.SrcIP)
	}
}

// 层生成器: 注册检查
func TestLayerGeneratorRegistered(t *testing.T) {
	g, err := layers.NewLayerGenerator("moxa")
	if err != nil {
		t.Fatal(err)
	}
	if g.Name() != "moxa" {
		t.Fatalf("name=%q", g.Name())
	}
}

// 层生成器: S1 事件流
func TestLayerGeneratorSingleUp(t *testing.T) {
	var events []layers.MessageEvent
	err := (&MOXAGenerator{}).Generate(context.Background(), &layers.GenRequest{
		Meta: layers.FlowMeta{MOXA: &core.MOXAConfig{Stream: []core.MOXAStreamBlock{{Payload: "hello"}}}},
		EmitMsg: func(ev layers.MessageEvent) error {
			events = append(events, ev)
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("events=%d want 1", len(events))
	}
	if !events[0].Up {
		t.Fatal("event Up=false want true")
	}
	if string(events[0].Bytes) != "hello" {
		t.Fatalf("event bytes=%q want hello", string(events[0].Bytes))
	}
}

// 层生成器: S3 双向事件流
func TestLayerGeneratorBidirectional(t *testing.T) {
	var events []layers.MessageEvent
	err := (&MOXAGenerator{}).Generate(context.Background(), &layers.GenRequest{
		Meta: layers.FlowMeta{MOXA: &core.MOXAConfig{
			Stream: []core.MOXAStreamBlock{
				{Direction: "up", Payload: "WR"},
				{Direction: "down", Payload: "RT"},
			},
		}},
		EmitMsg: func(ev layers.MessageEvent) error {
			events = append(events, ev)
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 {
		t.Fatalf("events=%d want 2", len(events))
	}
	if !events[0].Up || string(events[0].Bytes) != "WR" {
		t.Fatalf("event0 Up=%v bytes=%q want true,WR", events[0].Up, string(events[0].Bytes))
	}
	if events[1].Up || string(events[1].Bytes) != "RT" {
		t.Fatalf("event1 Up=%v bytes=%q want false,RT", events[1].Up, string(events[1].Bytes))
	}
}

// 层生成器: S5 b64 事件
func TestLayerGeneratorBinaryPayload(t *testing.T) {
	var events []layers.MessageEvent
	err := (&MOXAGenerator{}).Generate(context.Background(), &layers.GenRequest{
		Meta: layers.FlowMeta{MOXA: &core.MOXAConfig{Stream: []core.MOXAStreamBlock{{PayloadB64: "aGFoYQ=="}}}},
		EmitMsg: func(ev layers.MessageEvent) error {
			events = append(events, ev)
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("events=%d want 1", len(events))
	}
	if string(events[0].Bytes) != "haha" {
		t.Fatalf("event bytes=%q want haha", string(events[0].Bytes))
	}
}

// 层生成器: 空 stream 走缺省 "hello"
func TestLayerGeneratorDefaultStream(t *testing.T) {
	var events []layers.MessageEvent
	err := (&MOXAGenerator{}).Generate(context.Background(), &layers.GenRequest{
		Meta: layers.FlowMeta{MOXA: &core.MOXAConfig{}},
		EmitMsg: func(ev layers.MessageEvent) error {
			events = append(events, ev)
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("events=%d want 1", len(events))
	}
	if string(events[0].Bytes) != "hello" {
		t.Fatalf("event bytes=%q want hello", string(events[0].Bytes))
	}
}

// 层生成器: 拒绝空 payload
func TestLayerGeneratorRejectsEmptyPayload(t *testing.T) {
	err := (&MOXAGenerator{}).Generate(context.Background(), &layers.GenRequest{
		Meta:    layers.FlowMeta{MOXA: &core.MOXAConfig{Stream: []core.MOXAStreamBlock{{Payload: ""}}}},
		EmitMsg: func(ev layers.MessageEvent) error { return nil },
	})
	if err == nil || !strings.Contains(err.Error(), "empty stream block") {
		t.Fatalf("err=%v want empty stream block", err)
	}
}

// 层生成器: 拒绝超长 payload
func TestLayerGeneratorRejectsOversize(t *testing.T) {
	data := make([]byte, 2049)
	for i := range data {
		data[i] = 'A'
	}
	err := (&MOXAGenerator{}).Generate(context.Background(), &layers.GenRequest{
		Meta:    layers.FlowMeta{MOXA: &core.MOXAConfig{Stream: []core.MOXAStreamBlock{{Payload: string(data)}}}},
		EmitMsg: func(ev layers.MessageEvent) error { return nil },
	})
	if err == nil || !strings.Contains(err.Error(), "exceeds max") {
		t.Fatalf("err=%v want exceeds max", err)
	}
}

// 层生成器: 拒绝非法方向
func TestLayerGeneratorRejectsBadDirection(t *testing.T) {
	err := (&MOXAGenerator{}).Generate(context.Background(), &layers.GenRequest{
		Meta:    layers.FlowMeta{MOXA: &core.MOXAConfig{Stream: []core.MOXAStreamBlock{{Direction: "sideways", Payload: "hello"}}}},
		EmitMsg: func(ev layers.MessageEvent) error { return nil },
	})
	if err == nil || !strings.Contains(err.Error(), "invalid direction") {
		t.Fatalf("err=%v want invalid direction", err)
	}
}

// 层生成器: 拒绝探针 5a5a5a
func TestLayerGeneratorRejectsConfigPacket(t *testing.T) {
	err := (&MOXAGenerator{}).Generate(context.Background(), &layers.GenRequest{
		Meta:    layers.FlowMeta{MOXA: &core.MOXAConfig{Stream: []core.MOXAStreamBlock{{Payload: "ZZZ"}}}},
		EmitMsg: func(ev layers.MessageEvent) error { return nil },
	})
	if err == nil || !strings.Contains(err.Error(), "config-packet bytes in stream") {
		t.Fatalf("err=%v want config-packet rejection", err)
	}
}

// 层生成器: 拒绝 sessions>1
func TestLayerGeneratorRejectsSessionsOverOne(t *testing.T) {
	err := (&MOXAGenerator{}).Generate(context.Background(), &layers.GenRequest{
		Meta:    layers.FlowMeta{MOXA: &core.MOXAConfig{Sessions: 3, Stream: []core.MOXAStreamBlock{{Payload: "hello"}}}},
		EmitMsg: func(ev layers.MessageEvent) error { return nil },
	})
	if err == nil || !strings.Contains(err.Error(), "sessions=3>1 not supported") {
		t.Fatalf("err=%v want sessions>1 rejection", err)
	}
}

// 层生成器: 拒绝非法 b64
func TestLayerGeneratorRejectsBadB64(t *testing.T) {
	err := (&MOXAGenerator{}).Generate(context.Background(), &layers.GenRequest{
		Meta:    layers.FlowMeta{MOXA: &core.MOXAConfig{Stream: []core.MOXAStreamBlock{{PayloadB64: "%%%"}}}},
		EmitMsg: func(ev layers.MessageEvent) error { return nil },
	})
	if err == nil || !strings.Contains(err.Error(), "invalid payload_b64") {
		t.Fatalf("err=%v want invalid payload_b64", err)
	}
}

// 层生成器: EmitMsg nil 返回错误
func TestLayerGeneratorNilEmitMsg(t *testing.T) {
	err := (&MOXAGenerator{}).Generate(context.Background(), &layers.GenRequest{
		Meta: layers.FlowMeta{MOXA: &core.MOXAConfig{Stream: []core.MOXAStreamBlock{{Payload: "hello"}}}},
	})
	if err == nil || !strings.Contains(err.Error(), "EmitMsg is nil") {
		t.Fatalf("err=%v want EmitMsg is nil", err)
	}
}

// 层生成器: MOXA config nil 返回错误
func TestLayerGeneratorNilConfig(t *testing.T) {
	// P0b-2：空 config 默认化并产默认流（stream "hello"）。
	var events []layers.MessageEvent
	err := (&MOXAGenerator{}).Generate(context.Background(), &layers.GenRequest{
		Meta:    layers.FlowMeta{},
		EmitMsg: func(ev layers.MessageEvent) error { events = append(events, ev); return nil },
	})
	if err != nil {
		t.Fatalf("empty config Generate err: %v", err)
	}
	if len(events) == 0 {
		t.Fatal("empty config generated 0 events")
	}
}
func TestEmptyConfigProducesDefaultFlow(t *testing.T) {
	// P0b-2：空 config 默认化（stream "hello"），Plan/Generate 均产默认流。
	ch, err := (&Planner{}).Plan(context.Background(), core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 1234, DstPort: 4800})
	if err != nil {
		t.Fatalf("empty config Plan err: %v", err)
	}
	n := 0
	for range ch {
		n++
	}
	if n == 0 {
		t.Fatal("empty config produced 0 packets")
	}

	var events []layers.MessageEvent
	err = (&MOXAGenerator{}).Generate(context.Background(), &layers.GenRequest{
		Meta:    layers.FlowMeta{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 1234, DstPort: 4800},
		EmitMsg: func(ev layers.MessageEvent) error { events = append(events, ev); return nil },
	})
	if err != nil {
		t.Fatalf("empty config Generate err: %v", err)
	}
	if len(events) == 0 {
		t.Fatal("empty config generated 0 events")
	}
}
