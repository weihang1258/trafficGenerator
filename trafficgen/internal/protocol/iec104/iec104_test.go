package iec104

import (
	"context"
	"encoding/hex"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

func TestBuildStartDTMatchesTemplate(t *testing.T) {
	got, err := BuildUFrame(UStartDTAct)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(got) != "680407000000" {
		t.Fatalf("startdt = %x", got)
	}
}

func TestBuildInformationAndSupervisoryFrames(t *testing.T) {
	cfg := &IEC104Config{TypeID: TypeMSpNa, Cause: 3, CommonAddress: 1, InformationObjectAddress: 100, Value: 42}
	info, err := BuildInformation(cfg, 2, 4)
	if err != nil {
		t.Fatal(err)
	}
	if len(info) < 12 || info[0] != 0x68 || info[2] != 0x04 || info[3] != 0x00 {
		t.Fatalf("info = %x", info)
	}
	s, err := BuildSFrame(4)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(s) != "680401000800" {
		t.Fatalf("s = %x", s)
	}
}

func TestBuildSupervisoryFrameEncodesReceiveSequence(t *testing.T) {
	got, err := BuildSFrame(4)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(got) != "680401000800" {
		t.Fatalf("s = %x, want 680401000800", got)
	}
}

func TestInformationFrameUsesDistinctSequenceNumbers(t *testing.T) {
	cfg := &IEC104Config{TypeID: TypeMSpNa, Cause: 3, CommonAddress: 1, InformationObjectAddress: 1, Value: 1}
	got, err := BuildInformation(cfg, 2, 4)
	if err != nil {
		t.Fatal(err)
	}
	if got[2] != 0x04 || got[3] != 0x00 || got[4] != 0x08 || got[5] != 0x00 {
		t.Fatalf("control = %x, want 04000800", got[2:6])
	}
}
func TestSupportedInformationTypesEncodeExpectedPayloads(t *testing.T) {
	cases := []struct {
		typeID  uint8
		bodyLen int
	}{
		{TypeMSpNa, 1}, {TypeMMeNa, 3}, {TypeMSpTb, 8}, {TypeMMeTd, 10}, {TypeCScNa, 1}, {TypeCDcTa, 8},
	}
	for _, tc := range cases {
		got, err := BuildInformation(&IEC104Config{TypeID: tc.typeID, Cause: 3}, 0, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 6+6+3+tc.bodyLen {
			t.Fatalf("type=%d len=%d want=%d", tc.typeID, len(got), 15+tc.bodyLen)
		}
	}
}
func TestIEC104TypeIDsMatchStandard(t *testing.T) {
	if TypeMMeTd != 34 {
		t.Fatalf("M_ME_TD_1 type=%d, want 34", TypeMMeTd)
	}
}

func TestBuildInformationEncodesIEC104TypeSpecificFields(t *testing.T) {
	tests := []struct {
		name string
		cfg  *IEC104Config
		want string
	}{
		{
			name: "double point",
			cfg:  &IEC104Config{TypeID: TypeMDpNa, Cause: 3, CommonAddress: 1, InformationObjectAddress: 2, Value: 2, DIQ: 0x82},
			want: "680e0000000003010300010002000082",
		},
		{
			name: "interrogation",
			cfg:  &IEC104Config{TypeID: TypeCICNa, Cause: 6, CommonAddress: 7, InformationObjectAddress: 0, QOI: 20},
			want: "680e0000000064010600070000000014",
		},
		{
			name: "single command select",
			cfg:  &IEC104Config{TypeID: TypeCScNa, Cause: 6, CommonAddress: 5, InformationObjectAddress: 22, Value: 1, Select: true},
			want: "680e000000002d010600050016000081",
		},
		{
			name: "timed measurement",
			cfg:  &IEC104Config{TypeID: TypeMMeTd, Cause: 3, CommonAddress: 3, InformationObjectAddress: 17, Value: 100, QDS: 0, Time: "2026-08-18T12:34:56.789Z"},
			want: "681700000000220103000300110000640000d5dd220c12481a",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := BuildInformation(tc.cfg, 0, 0)
			if err != nil {
				t.Fatal(err)
			}
			if hex.EncodeToString(got) != tc.want {
				t.Fatalf("frame=%x want=%s", got, tc.want)
			}
		})
	}
}

func TestBuildInformationRejectsInvalidCP56Time(t *testing.T) {
	_, err := BuildInformation(&IEC104Config{TypeID: TypeMMeTd, Cause: 3, Time: "not-a-time"}, 0, 0)
	if err == nil || !contains(err.Error(), "time") {
		t.Fatalf("err=%v, want invalid time error", err)
	}
}
func TestPlannerRejectsInvalidIEC104Events(t *testing.T) {
	cases := []struct {
		name string
		cfg  *IEC104Config
		want string
	}{
		{
			name: "unknown event kind",
			cfg:  &IEC104Config{Events: []IEC104Event{{Kind: "u", Direction: "up"}}},
			want: "control",
		},
		{
			name: "unknown event type",
			cfg:  &IEC104Config{Events: []IEC104Event{{Kind: "i", TypeID: 250, Cause: 6}}},
			want: "unknown type_id",
		},
		{
			name: "event ioa overflow",
			cfg:  &IEC104Config{Events: []IEC104Event{{Kind: "i", TypeID: TypeCScNa, Cause: 6, IOA: 0x1000000}}},
			want: "IOA",
		},
		{
			name: "apdu limit",
			cfg:  &IEC104Config{MaxAPDULength: 254, Events: []IEC104Event{{Kind: "i", TypeID: TypeMSpNa, Cause: 6}}},
			want: "APDU too long",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := (Planner{}).Validate(core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345, DstPort: 2404, IEC104: tc.cfg})
			if err == nil || !contains(err.Error(), tc.want) {
				t.Fatalf("err=%v want=%s", err, tc.want)
			}
		})
	}
}

func TestPlannerRejectsInvalidIEC104Config(t *testing.T) {
	cases := []struct {
		name string
		cfg  *IEC104Config
		want string
	}{
		{"transport", &IEC104Config{Transport: "udp"}, "udp"},
		{"type", &IEC104Config{TypeID: 0xff}, "type"},
		{"cause", &IEC104Config{TypeID: TypeMSpNa, Cause: 0}, "cause"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := (Planner{}).Validate(core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345, DstPort: 2404, IEC104: tc.cfg})
			if err == nil || !contains(err.Error(), tc.want) {
				t.Fatalf("err=%v want=%s", err, tc.want)
			}
		})
	}
}

func TestPlannerAndLayerGeneratorEmitIEC104Events(t *testing.T) {
	cfg := &IEC104Config{Commands: []IEC104Command{{TypeID: TypeMSpNa, Cause: 3, CommonAddress: 1, InformationObjectAddress: 100, Value: 42}}}
	ch, err := (Planner{}).Plan(context.Background(), core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345, DstPort: 2404, IEC104: cfg})
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for range ch {
		count++
	}
	if count < 3 {
		t.Fatalf("packets=%d", count)
	}
	var events []layers.MessageEvent
	err = (&IEC104Generator{}).Generate(context.Background(), &layers.GenRequest{Meta: layers.FlowMeta{IEC104: cfg}, EmitMsg: func(ev layers.MessageEvent) error { events = append(events, ev); return nil }})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) < 3 || !events[0].Up || events[1].Up {
		t.Fatalf("events=%#v", events)
	}
}

func TestGeneratorAdvancesInformationFrameSequenceNumbers(t *testing.T) {
	cfg := &IEC104Config{Events: []IEC104Event{
		{Direction: "up", Kind: "i", TypeID: TypeMSpNa, Cause: 3, IOA: 1, SIQ: 1},
		{Direction: "up", Kind: "i", TypeID: TypeMSpNa, Cause: 3, IOA: 2, SIQ: 0},
		{Direction: "down", Kind: "i", TypeID: TypeMSpNa, Cause: 20, IOA: 3, SIQ: 1},
	}}
	var events []layers.MessageEvent
	if err := (&IEC104Generator{}).Generate(context.Background(), &layers.GenRequest{
		Meta:    layers.FlowMeta{IEC104: cfg},
		EmitMsg: func(ev layers.MessageEvent) error { events = append(events, ev); return nil },
	}); err != nil {
		t.Fatal(err)
	}
	if len(events) != 3 {
		t.Fatalf("events=%d want=3", len(events))
	}
	for i, want := range []string{"00000000", "02000000", "00000400"} {
		got := hex.EncodeToString(events[i].Bytes[2:6])
		if got != want {
			t.Fatalf("event %d control=%s want=%s", i, got, want)
		}
	}
}
func TestGeneratorHonorsConfiguredUAndSAndEventSequence(t *testing.T) {
	cfg := &IEC104Config{Events: []IEC104Event{
		{Direction: "up", Kind: "startdt_act"},
		{Direction: "down", Kind: "startdt_con"},
		{Direction: "up", Kind: "testfr_act"},
		{Direction: "down", Kind: "testfr_con"},
		{Direction: "up", Kind: "s", RX: 1},
	}}
	var events []layers.MessageEvent
	if err := (&IEC104Generator{}).Generate(context.Background(), &layers.GenRequest{
		Meta:    layers.FlowMeta{IEC104: cfg},
		EmitMsg: func(ev layers.MessageEvent) error { events = append(events, ev); return nil },
	}); err != nil {
		t.Fatal(err)
	}
	if len(events) != len(cfg.Events) {
		t.Fatalf("events=%d want=%d", len(events), len(cfg.Events))
	}
	if events[3].Up {
		t.Fatalf("testfr con direction=%v", events[3].Up)
	}
	if hex.EncodeToString(events[4].Bytes) != "680401000200" {
		t.Fatalf("s frame=%x", events[4].Bytes)
	}
}

func TestIEC104LayerRegistryAndFlowMeta(t *testing.T) {
	if _, ok := layers.DefaultRegistry().Get("iec104"); !ok {
		t.Fatal("iec104 layer is not registered")
	}
	cfg := &IEC104Config{TypeID: TypeMSpNa, Cause: 3}
	if (&layers.FlowMeta{IEC104: cfg}).IEC104 != cfg {
		t.Fatal("iec104 config was not carried in FlowMeta")
	}
}

func TestPlannerEmptyConfigProducesDefaultFlow(t *testing.T) {
	// P0b-2：空配置（IEC104 nil）→ Plan 默认化并产默认流。
	ch, err := (Planner{}).Plan(context.Background(), core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 1234})
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for range ch {
		count++
	}
	if count < 3 {
		t.Fatalf("packets=%d want >=3", count)
	}
}

func TestGeneratorEmptyConfigProducesDefaultFlow(t *testing.T) {
	// P0b-2：空配置（IEC104 nil）→ Generate 默认化并产默认流。
	var events []layers.MessageEvent
	err := (&IEC104Generator{}).Generate(context.Background(), &layers.GenRequest{
		Meta:    layers.FlowMeta{},
		EmitMsg: func(ev layers.MessageEvent) error { events = append(events, ev); return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) < 4 {
		t.Fatalf("events=%d want >=4", len(events))
	}
}

// G-IEC104-8（P4 必办，失败测试先行）：value 是 16-bit 信息体（NVA/DCO/SCO
// 单字节取低 8 位），builder 走 `uint16(cfg.Value)` 截断——负值静默回绕、
// >65535 静默丢高位，两者都产出"看起来合法"的字节。Validate 必须显式拒收，
// 使负例走 task error 终态（零假成功）而不是静默错字节。
func TestPlannerRejectsOutOfRangeValue(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value int32
	}{
		{"negative", -1},
		{"overflow", 65536},
		{"far_overflow", 1 << 20},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &IEC104Config{Events: []IEC104Event{{
				Direction: "up", Kind: "i", TypeID: TypeMMeNa, Cause: 3, IOA: 1, Value: tc.value,
			}}}
			err := (Planner{}).Validate(core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345, DstPort: 2404, IEC104: cfg})
			if err == nil {
				t.Fatalf("value=%d accepted, want rejection (16-bit information element)", tc.value)
			}
			if !contains(err.Error(), "value") {
				t.Fatalf("value=%d err=%q, want anchor \"value\"", tc.value, err.Error())
			}
		})
	}
	// 边界两侧必须放行：0 与 65535 都是合法 16-bit 值。
	for _, v := range []int32{0, 65535} {
		cfg := &IEC104Config{Events: []IEC104Event{{
			Direction: "up", Kind: "i", TypeID: TypeMMeNa, Cause: 3, IOA: 1, Value: v,
		}}}
		if err := (Planner{}).Validate(core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345, DstPort: 2404, IEC104: cfg}); err != nil {
			t.Fatalf("value=%d rejected: %v (0..65535 are legal)", v, err)
		}
	}
}

// G-IEC104-8 同面：顶层单对象快捷键 value 同域（commands 路同 builder）。
func TestPlannerRejectsOutOfRangeTopLevelValue(t *testing.T) {
	cfg := &IEC104Config{TypeID: TypeMMeNa, Cause: 3, InformationObjectAddress: 1, Value: 70000}
	if err := (Planner{}).Validate(core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345, DstPort: 2404, IEC104: cfg}); err == nil {
		t.Fatal("top-level value=70000 accepted, want rejection")
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
