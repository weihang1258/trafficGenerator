package jtt905

// D-JTT905-1 P4 单测面：金向量（SmallChi/JT905 README 0x0200 组包例，
// 上游 Assert 钉死，含 7D02/7D01 双转义形）逐字节核算、信封+头钉
// （DataLength=纯体长）、体形钉、解析负路径、ValidateConfig 锚、编排面。

import (
	"context"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/protocol/jtcommon"
)

// SmallChi/JT905 README 组包例（0x0200 位置信息汇报，上游 Assert.Equal 通过）。
const goldenWireHex = "7E02000023103456789012007D02000000010000000200BA7F0E07E4F11C" +
	"003C002110152110100104000000640202007D01347E"

// 锚1：金向量反转义+XOR 复算+头核算（DataLength=35 纯体长/ISU BCD/MsgNum 含 7E 转义位）。
func TestGoldenVector(t *testing.T) {
	wire := jtcommon.MustParseHex(goldenWireHex)
	pf, err := ParseFrame(wire)
	if err != nil {
		t.Fatalf("ParseFrame: %v", err)
	}
	if pf.MsgID != 0x0200 {
		t.Fatalf("MsgID %04x, want 0200", pf.MsgID)
	}
	if pf.DataLength != 35 || len(pf.Body) != 35 {
		t.Fatalf("DataLength %d body %d, want 35/35（纯体长语义）", pf.DataLength, len(pf.Body))
	}
	if pf.ISUId != "103456789012" {
		t.Fatalf("ISUId %q, want 103456789012", pf.ISUId)
	}
	if pf.MsgNum != 0x007E {
		t.Fatalf("MsgNum %04x, want 007e（线上 7D02 反转义）", pf.MsgNum)
	}
	// 体内容锚：报警=1 状态=2 纬=12222222 经=132444444 速=60 方向=0 时间=211015211010。
	want := "000000010000000200ba7f0e07e4f11c003c00211015211010"
	if got := hexl(pf.Body[:25]); got != want {
		t.Fatalf("position base: got %s want %s", got, want)
	}
}

// 锚2：builder 复现金向量（typed 位置块 → 逐字节）。
func TestBuildFrame_GoldenVector(t *testing.T) {
	pos, err := buildPosition(&JTT905Position{
		AlarmFlag: 1, StatusFlag: 2,
		Lat: 12222222, Lng: 132444444, Speed: 60, Direction: 0,
		Time: "211015211010",
	})
	if err != nil {
		t.Fatalf("buildPosition: %v", err)
	}
	attaches := jtcommon.MustParseHex("0104000000640202007d")
	body := append(append([]byte{}, pos...), attaches...)
	isuBCD, _ := jtcommon.BCDEncode("103456789012")
	frame, err := buildSimpleFrame(0x0200, body, isuBCD, 126)
	if err != nil {
		t.Fatalf("buildSimpleFrame: %v", err)
	}
	got := hexl(frame)
	if !strings.EqualFold(got, goldenWireHex) {
		t.Fatalf("golden mismatch:\n got %s\nwant %s", got, goldenWireHex)
	}
}

// 信封+头钉：DataLength=纯体长（无版本位）。
func TestDataLengthPureSemantics(t *testing.T) {
	body := buildGeneralResponseBody(5, 0x8300, 1)
	frame, err := buildSimpleFrame(MsgISUGeneralResponse, body, mustBCD(t, "103456789012"), 7)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	pf, err := ParseFrame(frame)
	if err != nil {
		t.Fatalf("ParseFrame: %v", err)
	}
	if pf.DataLength != 5 || len(pf.Body) != 5 {
		t.Fatalf("DataLength %d body %d, want 5/5（纯体长，无版本/加密位）", pf.DataLength, len(pf.Body))
	}
	if pf.MsgID != MsgISUGeneralResponse || pf.MsgNum != 7 {
		t.Fatalf("header: %04x sn=%d", pf.MsgID, pf.MsgNum)
	}
	rsn, rid, result, err := pf.GeneralRespBody()
	if err != nil || rsn != 5 || rid != 0x8300 || result != 1 {
		t.Fatalf("resp body: %d/%d/%d err=%v", rsn, rid, result, err)
	}
}

// 体形钉：0x0B03/0x0B04 宽度与字段序。
func TestBodyShapes(t *testing.T) {
	cfg := &JTT905Config{
		ISUId:              "103456789012",
		BusinessLicense:    "BL-001",
		QualificationCode:  "QC-0001",
		PlateNo:            "A12345",
		OnDutyPowerOnTime:  "202408030800",
		OnDutyPowerOffTime: "202408031600",
		TaximeterKValue:    "0512",
		OnDutyMileage:      "001250",
		TotalMileage:       "00125000",
		TotalOperations:    12,
		SignType:           1,
		Position:           &JTT905Position{Time: "240803080000"},
	}
	in, err := buildCheckInBody(cfg)
	if err != nil {
		t.Fatalf("checkin: %v", err)
	}
	if len(in) != PositionLen+baseCheckInLen {
		t.Fatalf("checkin body %d, want %d (25 位置+47 基础)", len(in), PositionLen+baseCheckInLen)
	}
	out, err := buildCheckOutBody(cfg)
	if err != nil {
		t.Fatalf("checkout: %v", err)
	}
	if len(out) != PositionLen+91 {
		t.Fatalf("checkout body %d, want %d (25 位置+91 基础)", len(out), PositionLen+91)
	}
}

// 解析负路径：XOR 破坏/DataLength 自洽。
func TestParseFrame_Negative(t *testing.T) {
	frame, err := buildSimpleFrame(MsgHeartbeat, nil, mustBCD(t, "103456789012"), 1)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	bad := append([]byte(nil), frame...)
	bad[len(bad)-2] ^= 0xFF
	if _, err := ParseFrame(bad); err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("want checksum mismatch, got %v", err)
	}
	// DataLength 篡改（补回正确 XOR，仅剩 DataLength-vs-体 自洽错）。
	bad2 := append([]byte(nil), frame...)
	bad2[4] = 0x01 // DataLength 0→1（心跳体为空）
	var cs byte
	for _, b := range bad2[1 : len(bad2)-2] {
		cs ^= b
	}
	bad2[len(bad2)-2] = cs
	if _, err := ParseFrame(bad2); err == nil || !strings.Contains(err.Error(), "DataLength") {
		t.Fatalf("want DataLength error, got %v", err)
	}
}

// ValidateConfig 锚（T-10…13 同源锚词）。
func TestValidateConfig_Anchors(t *testing.T) {
	cases := []struct {
		name string
		cfg  *JTT905Config
		want string
	}{
		{"isu 11 位", &JTT905Config{ISUId: "12345678901"}, `ISUId "12345678901" must be 12 digits`},
		{"isu 非数字", &JTT905Config{ISUId: "12345678901a"}, "contains non-digit"},
		{"plate 7 ASCII", &JTT905Config{ISUId: "103456789012", PlateNo: "A123456"}, "PlateNo length 7 > 6"},
		{"license 超宽", &JTT905Config{ISUId: "103456789012", BusinessLicense: strings.Repeat("a", 17)}, "BusinessLicense length 17 > 16"},
		{"result=3", &JTT905Config{ISUId: "103456789012", Procedures: []JTT905Procedure{{Type: ProcCenterGeneralResponse, Result: 3}}}, "Result 3 > 2"},
		{"未知类型", &JTT905Config{ISUId: "103456789012", Procedures: []JTT905Procedure{{Type: "vehicle_register"}}}, "unknown procedure type"},
		{"K值位数错", &JTT905Config{ISUId: "103456789012", TaximeterKValue: "123"}, `TaximeterKValue "123" must be 4 digits`},
		// L1 红例：等长非数字串必须在校验层拒（原缺口=漏到 BCDEncode 才以他锚词失败）。
		{"K值非数字", &JTT905Config{ISUId: "103456789012", TaximeterKValue: "12a4"}, `TaximeterKValue "12a4" contains non-digit`},
		{"uptime 非数字", &JTT905Config{ISUId: "103456789012", OnDutyPowerOnTime: "20240803080a"}, "contains non-digit"},
		{"uptime 位数错", &JTT905Config{ISUId: "103456789012", OnDutyPowerOnTime: "20240803"}, "OnDutyPowerOnTime \"20240803\" must be 12 digits"},
		{"nil", nil, "nil config"},
	}
	for _, c := range cases {
		err := ValidateConfig(c.cfg)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Fatalf("%s: want %q, got %v", c.name, c.want, err)
		}
	}
	if err := ValidateConfig(DefaultJTT905Config()); err != nil {
		t.Fatalf("default config must validate: %v", err)
	}
}

// 编排面：自动会话 签到→应答→心跳→应答→签退→应答 = 6 消息 + 3+3 = 12 帧；
// 双计数器/应答自动绑定最近上行。
func TestPlanWithConfig_AutoSession(t *testing.T) {
	cfg := &JTT905Config{
		ISUId:     "103456789012",
		InitialSN: 100,
	}
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcMAC: "02:00:00:00:00:01", DstMAC: "02:00:00:00:00:02"}
	ch, err := NewPlanner().PlanWithConfig(context.Background(), spec, cfg)
	if err != nil {
		t.Fatalf("PlanWithConfig: %v", err)
	}
	var ids []uint16
	var snsDown []uint16
	n := 0
	for pkt := range ch {
		n++
		if len(pkt.Payload) > 0 && pkt.Payload[0] == jtcommon.FrameDelimiter {
			pf, err := ParseFrame(pkt.Payload)
			if err != nil {
				t.Fatalf("parse frame %d: %v", n, err)
			}
			ids = append(ids, pf.MsgID)
			if pkt.Direction == "down" {
				snsDown = append(snsDown, pf.MsgNum)
			}
		}
	}
	if n != 12 {
		t.Fatalf("packets %d, want 12 (3+6+3)", n)
	}
	want := []uint16{0x0B03, 0x8001, 0x0002, 0x8001, 0x0B04, 0x8001}
	if len(ids) != len(want) {
		t.Fatalf("frames %d, want 6", len(ids))
	}
	for i := range want {
		if ids[i] != want[i] {
			t.Fatalf("msg %d: %04x, want %04x", i, ids[i], want[i])
		}
	}
	// 中心侧应答 SN 从 PlatformInitialSN=0 递增。
	for i, sn := range snsDown {
		if sn != uint16(i) {
			t.Fatalf("down SN %d at %d, want %d", sn, i, i)
		}
	}
}

// 负路径：Plan 硬错 + ValidateConfig 直达。
func TestPlanWithConfig_Negative(t *testing.T) {
	if _, err := NewPlanner().PlanWithConfig(context.Background(), core.FlowSpec{}, &JTT905Config{ISUId: "12345"}); err == nil {
		t.Fatal("want error for short ISUId")
	}
	if _, err := NewPlanner().Plan(context.Background(), core.FlowSpec{}); err == nil {
		t.Fatal("Plan must hard-error")
	}
}

func mustBCD(t *testing.T, s string) []byte {
	t.Helper()
	b, err := jtcommon.BCDEncode(s)
	if err != nil {
		t.Fatalf("BCD: %v", err)
	}
	return b
}

func hexl(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, x := range b {
		out = append(out, digits[x>>4], digits[x&0xF])
	}
	return string(out)
}
