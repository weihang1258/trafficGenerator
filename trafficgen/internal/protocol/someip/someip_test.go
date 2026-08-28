package someip

import (
	"context"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

func TestBuildMessageHeaderAndLength(t *testing.T) {
	// S1: REQUEST with 4-byte payload de ad be ef
	msg := buildMessage(0x1234, 0x0001, 0x0001, 0x0001, 1, 1, MTRequest, 0, []byte{0xde, 0xad, 0xbe, 0xef})
	if len(msg) != 20 {
		t.Fatalf("msg len=%d want 20", len(msg))
	}
	// header: service id
	if binary.BigEndian.Uint16(msg[0:2]) != 0x1234 {
		t.Fatalf("service id=%x", binary.BigEndian.Uint16(msg[0:2]))
	}
	if binary.BigEndian.Uint16(msg[2:4]) != 0x0001 {
		t.Fatalf("method id=%x", binary.BigEndian.Uint16(msg[2:4]))
	}
	// Length = 8 + 4 = 12 (0x0c), design §2.2/§3.2.2
	if got := binary.BigEndian.Uint32(msg[4:8]); got != 12 {
		t.Fatalf("length=%d want 12", got)
	}
	if binary.BigEndian.Uint16(msg[8:10]) != 0x0001 {
		t.Fatalf("client id=%x", binary.BigEndian.Uint16(msg[8:10]))
	}
	// Request ID = Client 0x0001 + Session 0x0001
	if got := binary.BigEndian.Uint32(msg[8:12]); got != 0x00010001 {
		t.Fatalf("request id=%08x want 00010001", got)
	}
	if msg[12] != 1 || msg[13] != 1 {
		t.Fatalf("protocol/interface ver=%d/%d", msg[12], msg[13])
	}
	if msg[14] != 0x00 || msg[15] != 0x00 {
		t.Fatalf("msg type/return=%02x/%02x", msg[14], msg[15])
	}
	if string(msg[16:20]) != string([]byte{0xde, 0xad, 0xbe, 0xef}) {
		t.Fatalf("payload=%x", msg[16:20])
	}
	// canonical hex: 12 34 00 01 00 00 00 0c 00 01 00 01 01 01 00 00 de ad be ef
	want := "123400010000000c0001000101010000deadbeef"
	if hex(msg) != want {
		t.Fatalf("hex=%s want %s", hex(msg), want)
	}
}

func TestBuildMessageEmptyPayloadLength8(t *testing.T) {
	// S1 变体：空载荷 Length=8
	msg := buildMessage(0x1234, 0x0001, 0x0001, 0x0001, 1, 1, MTRequest, 0, nil)
	if got := binary.BigEndian.Uint32(msg[4:8]); got != 8 {
		t.Fatalf("length=%d want 8", got)
	}
}

func TestValidateRejectsServiceIDZero(t *testing.T) {
	// V1
	err := (Planner{}).Validate(core.FlowSpec{SOMEIP: &core.SOMEIPConfig{ServiceID: 0, MethodID: 1}})
	if err == nil || !strings.Contains(err.Error(), "service_id must be nonzero") {
		t.Fatalf("err=%v want service_id must be nonzero", err)
	}
}

func TestValidateRejectsNonIncrementingSession(t *testing.T) {
	// V2: session_start 非 0 而 session_inc=0（Session ID 不递增）必须被拒。
	err := (Planner{}).Validate(core.FlowSpec{SOMEIP: &core.SOMEIPConfig{
		ServiceID: 0x1234, MethodID: 1, SessionStart: 1, SessionInc: 0,
	}})
	if err == nil || !strings.Contains(err.Error(), "invalid session_id") {
		t.Fatalf("err=%v want invalid session_id", err)
	}
	// 默认单消息（两者都未设 -> 0,0，由 Plan 默认化为 1/1）必须通过。
	err = (Planner{}).Validate(core.FlowSpec{SOMEIP: &core.SOMEIPConfig{
		ServiceID: 0x1234, MethodID: 1, MessageType: "request",
	}})
	if err != nil {
		t.Fatalf("default session (0,0) should be valid, got %v", err)
	}
}

func TestValidateRejectsInvalidMessageType(t *testing.T) {
	// V3: message_type=5 不在枚举
	err := (Planner{}).Validate(core.FlowSpec{SOMEIP: &core.SOMEIPConfig{
		ServiceID: 0x1234, MethodID: 1, MessageType: "bogus",
	}})
	if err == nil || !strings.Contains(err.Error(), "invalid message_type") {
		t.Fatalf("err=%v want invalid message_type", err)
	}
}

func TestValidateRejectsInvalidProtocolVersion(t *testing.T) {
	// V4
	err := (Planner{}).Validate(core.FlowSpec{SOMEIP: &core.SOMEIPConfig{
		ServiceID: 0x1234, MethodID: 1, ProtocolVersion: 2,
	}})
	if err == nil || !strings.Contains(err.Error(), "protocol_version") {
		t.Fatalf("err=%v want protocol_version", err)
	}
}

func TestValidateRejectsTPSegmentSizeZero(t *testing.T) {
	// V5: tp.segment_size=0
	err := (Planner{}).Validate(core.FlowSpec{SOMEIP: &core.SOMEIPConfig{
		ServiceID: 0x1234, MethodID: 1,
		TP: &core.SOMEIPTPConfig{Enabled: true, SegmentSize: 0},
	}})
	if err == nil || !strings.Contains(err.Error(), "tp") {
		t.Fatalf("err=%v want tp", err)
	}
}

func TestValidateRejectsBadSDType(t *testing.T) {
	err := (Planner{}).Validate(core.FlowSpec{SOMEIP: &core.SOMEIPConfig{
		SD: &core.SOMEIPSDConfig{Type: "bogus"},
	}})
	if err == nil || !strings.Contains(err.Error(), "sd.type") {
		t.Fatalf("err=%v want sd.type", err)
	}
}

func TestValidateAcceptsDefaultConfig(t *testing.T) {
	err := (Planner{}).Validate(core.FlowSpec{SOMEIP: &core.SOMEIPConfig{ServiceID: 0x1234}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPlanRejectsInvalidConfig(t *testing.T) {
	// validator 与 Plan 同拒
	_, err := (Planner{}).Plan(context.Background(), core.FlowSpec{
		SOMEIP: &core.SOMEIPConfig{ServiceID: 0},
	})
	if err == nil || !strings.Contains(err.Error(), "service_id must be nonzero") {
		t.Fatalf("err=%v want service_id must be nonzero", err)
	}
}

func TestPlanSingleRequestResponse(t *testing.T) {
	// S1: REQUEST → autoResponse RESPONSE，2 包
	ch, err := (Planner{}).Plan(context.Background(), core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345, DstPort: 30490,
		SOMEIP: &core.SOMEIPConfig{
			ServiceID: 0x1234, MethodID: 0x0001, ClientID: 0x0001,
			MessageType: "request", AutoResponse: boolPtr(true),
			Payload: []byte{0xde, 0xad, 0xbe, 0xef},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	var pkts []core.PacketConfig
	for p := range ch {
		pkts = append(pkts, p)
	}
	if len(pkts) != 2 {
		t.Fatalf("packets=%d want 2", len(pkts))
	}
	if pkts[0].Direction != "up" || pkts[1].Direction != "down" {
		t.Fatalf("directions=%q/%q", pkts[0].Direction, pkts[1].Direction)
	}
	if pkts[0].L4.SrcPort != 12345 || pkts[0].L4.DstPort != 30490 {
		t.Fatalf("pkt0 ports=%d/%d", pkts[0].L4.SrcPort, pkts[0].L4.DstPort)
	}
	if pkts[1].L4.SrcPort != 30490 {
		t.Fatalf("pkt1 srcport=%d want 30490 (down 方向端口对换)", pkts[1].L4.SrcPort)
	}
	// request msg type 0x00, response 0x80
	if pkts[0].Payload[14] != 0x00 {
		t.Fatalf("pkt0 type=%02x", pkts[0].Payload[14])
	}
	if pkts[1].Payload[14] != 0x80 {
		t.Fatalf("pkt1 type=%02x", pkts[1].Payload[14])
	}
	// session id 配对
	if binary.BigEndian.Uint16(pkts[0].Payload[10:12]) != binary.BigEndian.Uint16(pkts[1].Payload[10:12]) {
		t.Fatalf("session id mismatch")
	}
}

func TestPlanNoReturnSinglePacket(t *testing.T) {
	// S3: REQUEST_NO_RETURN → 1 包
	ch, err := (Planner{}).Plan(context.Background(), core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345, DstPort: 30490,
		SOMEIP: &core.SOMEIPConfig{
			ServiceID: 0x1234, MethodID: 0x0001, ClientID: 0x0001,
			MessageType: "request_no_return",
			Payload:     []byte{0xde, 0xad, 0xbe, 0xef},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	var pkts []core.PacketConfig
	for p := range ch {
		pkts = append(pkts, p)
	}
	if len(pkts) != 1 {
		t.Fatalf("packets=%d want 1", len(pkts))
	}
	if pkts[0].Payload[14] != 0x01 {
		t.Fatalf("type=%02x want 0x01", pkts[0].Payload[14])
	}
}

func TestPlanErrorResponse(t *testing.T) {
	// S4: REQUEST → ERROR(0x81) RC=0x01
	ch, err := (Planner{}).Plan(context.Background(), core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345, DstPort: 30490,
		SOMEIP: &core.SOMEIPConfig{
			ServiceID: 0x1234, MethodID: 0x0001, ClientID: 0x0001,
			AutoResponse: boolPtr(true),
			Events: []core.SOMEIPEvent{
				{MessageType: "request", Payload: []byte{0xde, 0xad, 0xbe, 0xef}},
				{Direction: "down", MessageType: "error", ReturnCode: 0x01, Payload: []byte{0}},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	var pkts []core.PacketConfig
	for p := range ch {
		pkts = append(pkts, p)
	}
	if len(pkts) != 3 {
		t.Fatalf("packets=%d want 3 (REQUEST + auto RESPONSE + explicit ERROR)", len(pkts))
	}
	if pkts[0].Payload[14] != 0x00 {
		t.Fatalf("pkt0 type=%02x want 0x00", pkts[0].Payload[14])
	}
	if pkts[1].Payload[14] != 0x80 {
		t.Fatalf("pkt1 type=%02x want 0x80 (auto RESPONSE)", pkts[1].Payload[14])
	}
	if pkts[2].Payload[14] != 0x81 {
		t.Fatalf("pkt2 type=%02x want 0x81", pkts[2].Payload[14])
	}
	if pkts[2].Payload[15] != 0x01 {
		t.Fatalf("pkt2 returncode=%02x want 0x01", pkts[2].Payload[15])
	}
}

func TestPlanMultiSession(t *testing.T) {
	// S2: 两次方法调用 SessionID=1,2 各自配对
	ch, err := (Planner{}).Plan(context.Background(), core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345, DstPort: 30490,
		SOMEIP: &core.SOMEIPConfig{
			ServiceID: 0x1234, MethodID: 0x0001, ClientID: 0x0001,
			SessionStart: 1, SessionInc: 1, AutoResponse: boolPtr(true),
			Events: []core.SOMEIPEvent{
				{Payload: []byte{1, 2, 3, 4}},
				{Payload: []byte{5, 6, 7, 8}},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	var pkts []core.PacketConfig
	for p := range ch {
		pkts = append(pkts, p)
	}
	if len(pkts) != 4 {
		t.Fatalf("packets=%d want 4", len(pkts))
	}
	sess := func(i int) uint16 { return binary.BigEndian.Uint16(pkts[i].Payload[10:12]) }
	if sess(0) != 1 || sess(2) != 2 {
		t.Fatalf("session ids=%d,%d want 1,2", sess(0), sess(2))
	}
	if sess(1) != sess(0) || sess(3) != sess(2) {
		t.Fatalf("session mismatch resp=%d,%d req=%d,%d", sess(1), sess(3), sess(0), sess(2))
	}
}

func TestPlanMultiMethodEvent(t *testing.T) {
	// S7: 方法 A/B REQUEST→RESPONSE + 事件 NOTIFICATION
	ch, err := (Planner{}).Plan(context.Background(), core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345, DstPort: 30490,
		SOMEIP: &core.SOMEIPConfig{
			ServiceID: 0x1234, ClientID: 0x0001, AutoResponse: boolPtr(true),
			Events: []core.SOMEIPEvent{
				{MethodID: 1, MessageType: "request", Payload: []byte{1}},
				{MethodID: 2, MessageType: "request", Payload: []byte{2}},
				{MethodID: 0x8001, MessageType: "event", Direction: "down", Payload: []byte{9, 9}},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	var pkts []core.PacketConfig
	for p := range ch {
		pkts = append(pkts, p)
	}
	if len(pkts) != 5 {
		t.Fatalf("packets=%d want 5", len(pkts))
	}
	// 包5 事件：method 0x8001, type 0x02, down
	if binary.BigEndian.Uint16(pkts[4].Payload[2:4]) != 0x8001 {
		t.Fatalf("pkt5 method=%x", binary.BigEndian.Uint16(pkts[4].Payload[2:4]))
	}
	if pkts[4].Payload[14] != 0x02 {
		t.Fatalf("pkt5 type=%02x want 0x02", pkts[4].Payload[14])
	}
	if pkts[4].Direction != "down" {
		t.Fatalf("pkt5 direction=%q want down", pkts[4].Direction)
	}
}

func TestLayerGeneratorEvents(t *testing.T) {
	// 层生成器：REQUEST→RESPONSE 2 事件
	var events []layers.MessageEvent
	err := (&SOMEIPGenerator{}).Generate(context.Background(), &layers.GenRequest{
		Meta: layers.FlowMeta{SOMEIP: &core.SOMEIPConfig{
			ServiceID: 0x1234, MethodID: 0x0001, ClientID: 0x0001,
			MessageType: "request", AutoResponse: boolPtr(true),
			Payload: []byte{0xde, 0xad, 0xbe, 0xef},
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
	if !events[0].Up || events[1].Up {
		t.Fatalf("up=%v/%v want true/false", events[0].Up, events[1].Up)
	}
	if events[0].Bytes[14] != 0x00 {
		t.Fatalf("event0 type=%02x", events[0].Bytes[14])
	}
	if events[1].Bytes[14] != 0x80 {
		t.Fatalf("event1 type=%02x", events[1].Bytes[14])
	}
}

func TestLayerGeneratorSDMessage(t *testing.T) {
	// S5: FindService → OfferService，SD outer service 0xFFFF, method 0x8100
	gen := &SOMEIPGenerator{}
	var events []layers.MessageEvent
	err := gen.Generate(context.Background(), &layers.GenRequest{
		Meta: layers.FlowMeta{SOMEIP: &core.SOMEIPConfig{
			MethodID: 0x8100, MessageType: "event",
			SD: &core.SOMEIPSDConfig{
				Type: "find", ServiceID: 0x1234, InstanceID: 1,
				MajorVersion: 1, TTL: 0xFFFFFF,
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
		t.Fatalf("events=%d want 2 (find + offer)", len(events))
	}
	// outer service/method/type
	if binary.BigEndian.Uint16(events[0].Bytes[0:2]) != 0xFFFF {
		t.Fatalf("sd service=%x", binary.BigEndian.Uint16(events[0].Bytes[0:2]))
	}
	if binary.BigEndian.Uint16(events[0].Bytes[2:4]) != 0x8100 {
		t.Fatalf("sd method=%x", binary.BigEndian.Uint16(events[0].Bytes[2:4]))
	}
	if events[0].Bytes[14] != 0x02 {
		t.Fatalf("sd type=%02x want 0x02", events[0].Bytes[14])
	}
	// entry type at offset 16+8+0 = 24
	if events[0].Bytes[24] != 0x00 {
		t.Fatalf("entry type=%02x want 0x00", events[0].Bytes[24])
	}
	if events[1].Bytes[24] != 0x01 {
		t.Fatalf("offer entry type=%02x want 0x01", events[1].Bytes[24])
	}
	// entries length = 16
	if got := binary.BigEndian.Uint32(events[0].Bytes[20:24]); got != 16 {
		t.Fatalf("entries length=%d want 16", got)
	}
	// serviceid at entry[4:6] = 0x1234, instanceid at [6:8] = 0x0001
	if binary.BigEndian.Uint16(events[0].Bytes[28:30]) != 0x1234 {
		t.Fatalf("entry serviceid=%x", binary.BigEndian.Uint16(events[0].Bytes[28:30]))
	}
	// ttl 0xFFFFFF at entry[9:12]; entry starts at 24, so [33:36]
	if events[0].Bytes[33] != 0xFF || events[0].Bytes[34] != 0xFF || events[0].Bytes[35] != 0xFF {
		t.Fatalf("find ttl=%02x%02x%02x", events[0].Bytes[33], events[0].Bytes[34], events[0].Bytes[35])
	}
}

func TestLayerGeneratorSDWithOption(t *testing.T) {
	// OfferService with IPv4 Endpoint Option (S5 包2)
	gen := &SOMEIPGenerator{}
	var events []layers.MessageEvent
	err := gen.Generate(context.Background(), &layers.GenRequest{
		Meta: layers.FlowMeta{SOMEIP: &core.SOMEIPConfig{
			MethodID: 0x8100, MessageType: "event",
			SD: &core.SOMEIPSDConfig{
				Type: "offer", ServiceID: 0x1234, InstanceID: 1,
				MajorVersion: 1, MinorVersion: 0, TTL: 3,
				Options: []core.SOMEIPOption{
					{Type: 1, IP: "20.0.0.200", Port: 30490, Proto: "udp"},
				},
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
	if len(events) != 1 {
		t.Fatalf("events=%d want 1 (offer 单发)", len(events))
	}
	msg := events[0].Bytes
	// someip length = 8 + 8(SD头) + 16(entry) + 4(options_len) + 12(option) = 48 (0x30)
	if got := binary.BigEndian.Uint32(msg[4:8]); got != 48 {
		t.Fatalf("length=%d want 48", got)
	}
	// options length at 40:44 = 12
	if got := binary.BigEndian.Uint32(msg[40:44]); got != 12 {
		t.Fatalf("options length=%d want 12", got)
	}
	// option at 44: Length(2BE)=0009 first, then Type=0x04, then Reserved(1)
	if binary.BigEndian.Uint16(msg[44:46]) != 9 {
		t.Fatalf("option length=%d want 9", binary.BigEndian.Uint16(msg[44:46]))
	}
	if msg[46] != 0x04 {
		t.Fatalf("option type=%02x want 0x04 (IPv4 Endpoint wire)", msg[46])
	}
	// addr 20.0.0.200 at 48-51
	if msg[48] != 20 || msg[49] != 0 || msg[50] != 0 || msg[51] != 200 {
		t.Fatalf("option addr=%d.%d.%d.%d", msg[48], msg[49], msg[50], msg[51])
	}
	// proto=17 (0x11) at 52, port=30490 (0x771a) at 53:55
	if msg[53] != 0x11 {
		t.Fatalf("option proto=%02x", msg[53])
	}
	if binary.BigEndian.Uint16(msg[54:56]) != 30490 {
		t.Fatalf("option port=%d", binary.BigEndian.Uint16(msg[54:56]))
	}
}

func TestPlanTPSegmentation(t *testing.T) {
	// S8: 2560B payload segment_size=1408 → 2 段 (1408+1152), 16 对齐
	pl := make([]byte, 2560)
	for i := range pl {
		pl[i] = byte(i % 256)
	}
	ch, err := (Planner{}).Plan(context.Background(), core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345, DstPort: 30490,
		SOMEIP: &core.SOMEIPConfig{
			ServiceID: 0x1234, MethodID: 0x0001, ClientID: 0x0001,
			MessageType: "request", Payload: pl,
			TP: &core.SOMEIPTPConfig{Enabled: true, SegmentSize: 1408, PayloadLength: 2560},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	var pkts []core.PacketConfig
	for p := range ch {
		pkts = append(pkts, p)
	}
	if len(pkts) != 2 {
		t.Fatalf("packets=%d want 2", len(pkts))
	}
	// 首段：type=0x20 (TP_REQUEST), TP header 4B: offset=0, more=1 (raw 0x00000001)
	if pkts[0].Payload[14] != 0x20 {
		t.Fatalf("pkt0 type=%02x want 0x20", pkts[0].Payload[14])
	}
	if got := binary.BigEndian.Uint32(pkts[0].Payload[16:20]); got != 0x00000001 {
		t.Fatalf("pkt0 tp header=%08x want 00000001 (offset 0 + more)", got)
	}
	// 首段 data len = 1408 (16B header + 4B TP header + 1408 data)
	if len(pkts[0].Payload)-20 != 1408 {
		t.Fatalf("pkt0 seg data len=%d want 1408", len(pkts[0].Payload)-20)
	}
	// 末段：type=0x20, TP header raw=1408 (more=0 → 0x00000580)
	if got := binary.BigEndian.Uint32(pkts[1].Payload[16:20]); got != 1408 {
		t.Fatalf("pkt1 tp header=%08x want %08x (offset 1408, more=0)", got, 1408)
	}
	if got := binary.BigEndian.Uint32(pkts[1].Payload[4:8]); got != 8+4+1152 {
		t.Fatalf("pkt1 length=%d want %d", got, 8+4+1152)
	}
	if len(pkts[1].Payload)-20 != 1152 {
		t.Fatalf("pkt1 seg data len=%d want 1152", len(pkts[1].Payload)-20)
	}
}

func TestLayerGeneratorRegistered(t *testing.T) {
	g, err := layers.NewLayerGenerator("someip")
	if err != nil {
		t.Fatal(err)
	}
	if g.Name() != "someip" {
		t.Fatalf("name=%q", g.Name())
	}
}

func boolPtr(b bool) *bool { return &b }

func hex(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = digits[v>>4]
		out[i*2+1] = digits[v&0xf]
	}
	return string(out)
}
func TestEmptyConfigProducesDefaultFlow(t *testing.T) {
	// P0b-2：空 config（nil SOMEIP）默认化（service 0x1234 REQUEST +
	// auto RESPONSE），Validate/Plan/Generate 均产默认流。
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 40000, DstPort: 30490}
	p := Planner{}
	if err := p.Validate(spec); err != nil {
		t.Fatalf("empty config Validate err: %v", err)
	}
	ch, err := p.Plan(context.Background(), spec)
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
	err = (&SOMEIPGenerator{}).Generate(context.Background(), &layers.GenRequest{
		Meta:    layers.FlowMeta{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 40000, DstPort: 30490},
		EmitMsg: func(ev layers.MessageEvent) error { events = append(events, ev); return nil },
	})
	if err != nil {
		t.Fatalf("empty config Generate err: %v", err)
	}
	if len(events) == 0 {
		t.Fatal("empty config generated 0 events")
	}
}
