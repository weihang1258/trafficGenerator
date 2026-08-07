package jtt905

import (
	"bytes"
	"context"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/protocol/jtcommon"
)

// mustPlan collects all PacketConfig from PlanWithConfig.
func mustPlan(t *testing.T, spec core.FlowSpec, cfg *JTT905Config) []core.PacketConfig {
	t.Helper()
	p := NewPlanner()
	ch, err := p.PlanWithConfig(context.Background(), spec, cfg)
	if err != nil {
		t.Fatalf("PlanWithConfig error: %v", err)
	}
	var out []core.PacketConfig
	for pc := range ch {
		out = append(out, pc)
	}
	return out
}

// findFrames returns all JTT905 frames parsed from payloads.
func findFrames(packets []core.PacketConfig) []*ParsedFrame {
	var out []*ParsedFrame
	for _, p := range packets {
		if len(p.Payload) < 14 {
			continue
		}
		if p.Payload[0] != jtcommon.FrameDelimiter {
			continue
		}
		pf, err := ParseFrame(p.Payload)
		if err != nil {
			continue
		}
		out = append(out, pf)
	}
	return out
}

// TestCheckInSuccess (C-01) verifies 0x1001 hex matches design §7C.8.
func TestCheckInSuccess(t *testing.T) {
	cfg := &JTT905Config{
		Phone:          "013800138000",
		Version:        jtcommon.Version2019,
		DriverId:       "11012345678901234567",
		DriverName:     "张三",
		LicensePlate:   "京A12345",
		LicenseColor:   LicenseColorBlue,
		VehicleModel:   "BJ-TAXI",
		LoadCapacity:   4,
		OnTime:         "240803080000",
		OffTime:        "240803160000",
		Mileage:        250000,
		Income:         50000,
		PassengerCount: 12,
		InitialSN:      0,
		Procedures:     []JTT905Procedure{{Type: ProcCheckIn}},
	}
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 50000, DstPort: 10700}
	packets := mustPlan(t, spec, cfg)
	frames := findFrames(packets)
	if len(frames) == 0 {
		t.Fatalf("no frames")
	}
	pf := frames[0]
	if pf.MsgID != MsgCheckIn {
		t.Fatalf("MsgID = 0x%04x, want 0x1001", pf.MsgID)
	}
	if pf.MsgSN != 0 {
		t.Fatalf("MsgSN = %d, want 0 (first = InitialSN)", pf.MsgSN)
	}
	if pf.BodyLen != 82 {
		t.Fatalf("BodyLen = %d, want 82", pf.BodyLen)
	}
	// MsgBodyProps = 0x0852 (BodyLength=82, Version=2019 bits10-12=010).
	if pf.MsgBodyProps != 0x0852 {
		t.Fatalf("MsgBodyProps = 0x%04x, want 0x0852", pf.MsgBodyProps)
	}
	if pf.Phone != "013800138000" {
		t.Fatalf("Phone = %q", pf.Phone)
	}
	cb, err := ParseCheckInBody(pf.Body)
	if err != nil {
		t.Fatalf("ParseCheckInBody: %v", err)
	}
	if cb.DriverId != "11012345678901234567" {
		t.Fatalf("DriverId = %q", cb.DriverId)
	}
	if cb.DriverName != "张三" {
		t.Fatalf("DriverName = %q, want 张三", cb.DriverName)
	}
	if cb.LicensePlate != "京A12345" {
		t.Fatalf("LicensePlate = %q", cb.LicensePlate)
	}
	if cb.LicenseColor != LicenseColorBlue {
		t.Fatalf("LicenseColor = %d", cb.LicenseColor)
	}
	if cb.OnTime != "240803080000" {
		t.Fatalf("OnTime = %q", cb.OnTime)
	}
	if cb.VehicleModel != "BJ-TAXI" {
		t.Fatalf("VehicleModel = %q", cb.VehicleModel)
	}
	if cb.LoadCapacity != 4 {
		t.Fatalf("LoadCapacity = %d", cb.LoadCapacity)
	}
}

// TestHeartbeatBasic (C-05) verifies 0x0002 has an empty body and
// MsgBodyProps=0x0800 (design §7C.8 C-33).
func TestHeartbeatBasic(t *testing.T) {
	cfg := &JTT905Config{
		Phone:       "013800138000",
		Version:     jtcommon.Version2019,
		DriverId:    "11012345678901234567",
		InitialSN:   1,
		Procedures:  []JTT905Procedure{{Type: ProcHeartbeat}},
	}
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 50000, DstPort: 10700}
	packets := mustPlan(t, spec, cfg)
	frames := findFrames(packets)
	if len(frames) == 0 {
		t.Fatalf("no frames")
	}
	pf := frames[0]
	if pf.MsgID != MsgHeartbeat {
		t.Fatalf("MsgID = 0x%04x, want 0x0002", pf.MsgID)
	}
	if len(pf.Body) != 0 {
		t.Fatalf("heartbeat body length %d, want 0", len(pf.Body))
	}
	if pf.MsgBodyProps != 0x0800 {
		t.Fatalf("MsgBodyProps = 0x%04x, want 0x0800 (BodyLength=0, Version=2019)", pf.MsgBodyProps)
	}
	if pf.MsgSN != 1 {
		t.Fatalf("MsgSN = %d, want 1", pf.MsgSN)
	}
}

// TestAutoProcedures (C-32) verifies the auto-generated session:
// check-in → response → (heartbeat → response)×3 → check-out → response.
func TestAutoProcedures(t *testing.T) {
	cfg := DefaultJTT905Config()
	cfg.HeartbeatCount = 3
	cfg.Procedures = nil
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 50000, DstPort: 10700}
	packets := mustPlan(t, spec, cfg)
	frames := findFrames(packets)
	// Messages: 1 (check-in) + 1 (resp) + 3*2 (hb+resp) + 1 (check-out)
	// + 1 (resp) = 10.
	if len(frames) != 10 {
		t.Fatalf("got %d frames, want 10", len(frames))
	}
	wantIDs := []uint16{
		MsgCheckIn,
		MsgCenterGeneralResp,
		MsgHeartbeat,
		MsgCenterGeneralResp,
		MsgHeartbeat,
		MsgCenterGeneralResp,
		MsgHeartbeat,
		MsgCenterGeneralResp,
		MsgCheckOut,
		MsgCenterGeneralResp,
	}
	for i, id := range wantIDs {
		if frames[i].MsgID != id {
			t.Fatalf("frame %d MsgID = 0x%04x, want 0x%04x", i, frames[i].MsgID, id)
		}
	}
	// ISU-side MsgSN: check-in=0, hb1=1, hb2=2, hb3=3, check-out=4 (C-09).
	wantSNs := []uint16{0, 0, 1, 1, 2, 2, 3, 3, 4, 4}
	for i, sn := range wantSNs {
		if frames[i].MsgSN != sn {
			t.Fatalf("frame %d MsgSN = %d, want %d", i, frames[i].MsgSN, sn)
		}
	}
	// Platform-side MsgSN: 5 responses, SNs = 0,1,2,3,4 (C-34).
	wantPlatSNs := []uint16{0, 1, 2, 3, 4}
	var platSNs []uint16
	for _, f := range frames {
		if f.MsgID == MsgCenterGeneralResp {
			platSNs = append(platSNs, f.MsgSN)
		}
	}
	if len(platSNs) != len(wantPlatSNs) {
		t.Fatalf("got %d platform responses, want %d", len(platSNs), len(wantPlatSNs))
	}
	for i, sn := range wantPlatSNs {
		if platSNs[i] != sn {
			t.Fatalf("platform response %d MsgSN = %d, want %d", i, platSNs[i], sn)
		}
	}
}

// TestHeartbeatZeroCount (C-07) verifies HeartbeatCount=0 → check-in
// directly followed by check-out.
func TestHeartbeatZeroCount(t *testing.T) {
	cfg := DefaultJTT905Config()
	cfg.HeartbeatCount = 0
	cfg.Procedures = nil
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 50000, DstPort: 10700}
	packets := mustPlan(t, spec, cfg)
	frames := findFrames(packets)
	// check-in + response + check-out + response = 4.
	if len(frames) != 4 {
		t.Fatalf("got %d frames, want 4", len(frames))
	}
	if frames[0].MsgID != MsgCheckIn {
		t.Fatalf("frame 0 = 0x%04x, want 0x1001", frames[0].MsgID)
	}
	if frames[2].MsgID != MsgCheckOut {
		t.Fatalf("frame 2 = 0x%04x, want 0x1002 (no heartbeats)", frames[2].MsgID)
	}
}

// TestCheckOutSuccess (C-10) verifies 0x1002 fields.
func TestCheckOutSuccess(t *testing.T) {
	cfg := &JTT905Config{
		Phone:          "013800138000",
		Version:        jtcommon.Version2019,
		DriverId:       "11012345678901234567",
		DriverName:     "张三",
		LicensePlate:   "京A12345",
		LicenseColor:   LicenseColorBlue,
		OffTime:        "240803160000",
		Mileage:        250000,
		Income:         50000,
		PassengerCount: 12,
		InitialSN:      6,
		Procedures:     []JTT905Procedure{{Type: ProcCheckOut}},
	}
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 50000, DstPort: 10700}
	packets := mustPlan(t, spec, cfg)
	frames := findFrames(packets)
	if len(frames) == 0 {
		t.Fatalf("no frames")
	}
	pf := frames[0]
	if pf.MsgID != MsgCheckOut {
		t.Fatalf("MsgID = 0x%04x, want 0x1002", pf.MsgID)
	}
	if pf.MsgSN != 6 {
		t.Fatalf("MsgSN = %d, want 6", pf.MsgSN)
	}
	if pf.BodyLen != 74 {
		t.Fatalf("BodyLen = %d, want 74", pf.BodyLen)
	}
	if pf.MsgBodyProps != 0x084a {
		t.Fatalf("MsgBodyProps = 0x%04x, want 0x084a", pf.MsgBodyProps)
	}
	cb, err := ParseCheckOutBody(pf.Body)
	if err != nil {
		t.Fatalf("ParseCheckOutBody: %v", err)
	}
	if cb.OffTime != "240803160000" {
		t.Fatalf("OffTime = %q", cb.OffTime)
	}
	if cb.Mileage != 250000 {
		t.Fatalf("Mileage = %d, want 250000", cb.Mileage)
	}
	if cb.Income != 50000 {
		t.Fatalf("Income = %d, want 50000", cb.Income)
	}
	if cb.PassengerCount != 12 {
		t.Fatalf("PassengerCount = %d, want 12", cb.PassengerCount)
	}
}

// TestCenterGeneralResponse (C-19/C-20/C-37) verifies 0x8001 body is
// 5 bytes with MsgBodyProps=0x0805 (Version=2019) and no Phone.
func TestCenterGeneralResponse(t *testing.T) {
	for _, result := range []uint8{0, 1, 2, 3} {
		body := buildGeneralResponseBody(2, MsgHeartbeat, result)
		if len(body) != 5 {
			t.Fatalf("Result=%d: body length %d, want 5", result, len(body))
		}
		rb, err := ParseGeneralResponseBody(body)
		if err != nil {
			t.Fatalf("Result=%d parse: %v", result, err)
		}
		if rb.ResponseSN != 2 || rb.ResponseMsgID != MsgHeartbeat || rb.Result != result {
			t.Fatalf("Result=%d: parsed (%d,0x%04x,%d)", result, rb.ResponseSN, rb.ResponseMsgID, rb.Result)
		}
	}
	// MsgBodyProps for a 5-byte body + Version=2019 = 0x0805 (C-37).
	props, _ := jtcommon.EncodeMsgBodyProps(5, jtcommon.Version2019, 0, 0)
	if props != 0x0805 {
		t.Fatalf("props = 0x%04x, want 0x0805", props)
	}
}

// TestISUGeneralResponseValues (C-14..C-17) verifies 0x0001 Result
// 0/1/2/3 each produce a 5-byte body.
func TestISUGeneralResponseValues(t *testing.T) {
	for _, result := range []uint8{0, 1, 2, 3} {
		body := buildGeneralResponseBody(1, MsgTextDown, result)
		if len(body) != 5 {
			t.Fatalf("Result=%d: body length %d, want 5", result, len(body))
		}
	}
}

// TestValidateBadACK (C-18) verifies ACKFlag=99 is rejected.
func TestValidateBadACK(t *testing.T) {
	cfg := DefaultJTT905Config()
	cfg.Procedures = []JTT905Procedure{{Type: ProcISUGeneralResponse, ACKFlag: 99}}
	if err := ValidateConfig(cfg); err == nil {
		t.Fatalf("ACKFlag=99 expected rejection")
	}
}

// TestValidateBadPhone (C-23) rejects non-12-digit Phone.
func TestValidateBadPhone(t *testing.T) {
	cfg := DefaultJTT905Config()
	cfg.Phone = "123"
	if err := ValidateConfig(cfg); err == nil {
		t.Fatalf("short Phone expected rejection")
	}
}

// TestValidateBadDriverId (C-24) rejects non-20-char DriverId.
func TestValidateBadDriverId(t *testing.T) {
	cfg := DefaultJTT905Config()
	cfg.DriverId = "short"
	if err := ValidateConfig(cfg); err == nil {
		t.Fatalf("short DriverId expected rejection")
	}
}

// TestValidateBadDriverName (C-25) rejects DriverName > 16 GBK bytes.
func TestValidateBadDriverName(t *testing.T) {
	cfg := DefaultJTT905Config()
	cfg.DriverName = "一二三四五六七八九十一二三四五六七" // 17 chars = 34 GBK bytes
	if err := ValidateConfig(cfg); err == nil {
		t.Fatalf("long DriverName expected rejection")
	}
}

// TestValidateBadOnTime (C-26) rejects malformed OnTime.
func TestValidateBadOnTime(t *testing.T) {
	cfg := DefaultJTT905Config()
	cfg.OnTime = "24-08-03"
	if err := ValidateConfig(cfg); err == nil {
		t.Fatalf("bad OnTime expected rejection")
	}
}

// TestValidateNegativeHeartbeatCount (C-27) rejects HeartbeatCount < 0.
func TestValidateNegativeHeartbeatCount(t *testing.T) {
	cfg := DefaultJTT905Config()
	cfg.HeartbeatCount = -1
	if err := ValidateConfig(cfg); err == nil {
		t.Fatalf("HeartbeatCount=-1 expected rejection")
	}
}

// TestHeartbeatIntervalZero (C-28) allows HeartbeatInterval=0.
func TestHeartbeatIntervalZero(t *testing.T) {
	cfg := DefaultJTT905Config()
	cfg.HeartbeatInterval = 0
	if err := ValidateConfig(cfg); err != nil {
		t.Fatalf("HeartbeatInterval=0 expected acceptance, got %v", err)
	}
}

// TestMsgSNWraparound (C-29) verifies InitialSN=65535 wraps to 0.
func TestMsgSNWraparound(t *testing.T) {
	cfg := &JTT905Config{
		Phone:       "013800138000",
		Version:     jtcommon.Version2019,
		DriverId:    "11012345678901234567",
		InitialSN:   65535,
		Procedures: []JTT905Procedure{
			{Type: ProcHeartbeat},
			{Type: ProcHeartbeat},
		},
	}
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 50000, DstPort: 10700}
	packets := mustPlan(t, spec, cfg)
	frames := findFrames(packets)
	if len(frames) != 2 {
		t.Fatalf("got %d frames, want 2", len(frames))
	}
	if frames[0].MsgSN != 65535 {
		t.Fatalf("frame 0 SN = %d, want 65535", frames[0].MsgSN)
	}
	if frames[1].MsgSN != 0 {
		t.Fatalf("frame 1 SN = %d, want 0 (wraparound)", frames[1].MsgSN)
	}
}

// TestEscapeInPlate (C-30) verifies 0x7e in GBK plate is escaped.
// GBK encoding of characters never produces 0x7e (GBK lead bytes are
// 0x81-0xFE, trail bytes 0x40-0xFE excluding 0x7F) — the adversarial
// case here is a body byte equal to 0x7e, which the escape layer must
// still handle. We use an ASCII payload with 0x7e in it.
func TestEscapeInPlate(t *testing.T) {
	// Build a frame with a body containing 0x7e via a synthetic message.
	phoneBCD, _ := jtcommon.BCDEncode("013800138000")
	props, _ := jtcommon.EncodeMsgBodyProps(1, jtcommon.Version2019, 0, 0)
	body := []byte{0x7e}
	frame := buildSimpleFrame(MsgHeartbeat, props, phoneBCD, 1, body)
	inner := frame[1 : len(frame)-1]
	if bytes.Contains(inner, []byte{0x7e}) {
		t.Fatalf("raw 0x7e found in escaped frame: %x", inner)
	}
	if !bytes.Contains(inner, []byte{0x7d, 0x02}) {
		t.Fatalf("escaped 0x7e not found: %x", inner)
	}
	// Round-trip.
	pf, err := ParseFrame(frame)
	if err != nil {
		t.Fatalf("ParseFrame: %v", err)
	}
	if len(pf.Body) != 1 || pf.Body[0] != 0x7e {
		t.Fatalf("body = %x", pf.Body)
	}
}

// TestFullLifecycleE2E (C-31) verifies check-in → heartbeat×3 →
// check-out full flow.
func TestFullLifecycleE2E(t *testing.T) {
	cfg := DefaultJTT905Config()
	cfg.HeartbeatCount = 3
	cfg.Procedures = nil
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 50000, DstPort: 10700}
	packets := mustPlan(t, spec, cfg)
	frames := findFrames(packets)
	wantIDs := []uint16{
		MsgCheckIn, MsgCenterGeneralResp,
		MsgHeartbeat, MsgCenterGeneralResp,
		MsgHeartbeat, MsgCenterGeneralResp,
		MsgHeartbeat, MsgCenterGeneralResp,
		MsgCheckOut, MsgCenterGeneralResp,
	}
	if len(frames) != len(wantIDs) {
		t.Fatalf("got %d frames, want %d", len(frames), len(wantIDs))
	}
	for i, id := range wantIDs {
		if frames[i].MsgID != id {
			t.Fatalf("frame %d = 0x%04x, want 0x%04x", i, frames[i].MsgID, id)
		}
	}
}

// TestMultiISUIndependent (C-21) verifies 2 ISUs get distinct flowIDs.
func TestMultiISUIndependent(t *testing.T) {
	cfg1 := DefaultJTT905Config()
	cfg1.Phone = "013800138000"
	cfg1.HeartbeatCount = 2
	cfg1.Procedures = nil
	cfg2 := DefaultJTT905Config()
	cfg2.Phone = "013800138001"
	cfg2.HeartbeatCount = 2
	cfg2.Procedures = nil
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 50000, DstPort: 10700}
	p1 := mustPlan(t, spec, cfg1)
	p2 := mustPlan(t, spec, cfg2)
	if p1[0].FlowID == p2[0].FlowID {
		t.Fatalf("flowIDs should differ: %s", p1[0].FlowID)
	}
	if p1[0].FlowID != "jtt905-013800138000-0" {
		t.Fatalf("flowID = %q", p1[0].FlowID)
	}
	// MsgSN independence: both start at 0.
	f1 := findFrames(p1)
	f2 := findFrames(p2)
	if f1[0].MsgSN != 0 || f2[0].MsgSN != 0 {
		t.Fatalf("independent counters broken: %d vs %d", f1[0].MsgSN, f2[0].MsgSN)
	}
}

// TestPlatformMsgSNIndependentFromInitialSN (C-34) verifies the platform
// counter starts at PlatformInitialSN, not InitialSN.
func TestPlatformMsgSNIndependentFromInitialSN(t *testing.T) {
	cfg := &JTT905Config{
		Phone:             "013800138000",
		Version:           jtcommon.Version2019,
		DriverId:          "11012345678901234567",
		OnTime:            "240803080000", // required by buildCheckInBody (BCD time)
		InitialSN:         5, // ISU-side
		PlatformInitialSN: 0, // platform-side
		Procedures: []JTT905Procedure{
			{Type: ProcCheckIn},
			{Type: ProcCenterGeneralResponse, ACKFlag: ACKSuccess},
			{Type: ProcCenterGeneralResponse, ACKFlag: ACKSuccess},
		},
	}
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 50000, DstPort: 10700}
	packets := mustPlan(t, spec, cfg)
	frames := findFrames(packets)
	// ISU: check-in SN=5. Platform: responses SN=0, then 1.
	if frames[0].MsgSN != 5 {
		t.Fatalf("ISU check-in SN = %d, want 5", frames[0].MsgSN)
	}
	if frames[1].MsgSN != 0 {
		t.Fatalf("first platform response SN = %d, want 0", frames[1].MsgSN)
	}
	if frames[2].MsgSN != 1 {
		t.Fatalf("second platform response SN = %d, want 1", frames[2].MsgSN)
	}
}

// TestProceduresNonEmptyCustom (C-38) verifies an explicit procedure list
// is honored exactly (no auto heartbeats inserted).
func TestProceduresNonEmptyCustom(t *testing.T) {
	cfg := &JTT905Config{
		Phone:          "013800138000",
		Version:        jtcommon.Version2019,
		DriverId:       "11012345678901234567",
		OnTime:         "240803080000", // required by buildCheckInBody
		OffTime:        "240803160000", // required by buildCheckOutBody
		InitialSN:      0,
		Procedures: []JTT905Procedure{
			{Type: ProcCheckIn},
			{Type: ProcHeartbeat},
			{Type: ProcHeartbeat},
			{Type: ProcCheckOut},
		},
	}
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 50000, DstPort: 10700}
	packets := mustPlan(t, spec, cfg)
	frames := findFrames(packets)
	wantIDs := []uint16{MsgCheckIn, MsgHeartbeat, MsgHeartbeat, MsgCheckOut}
	if len(frames) != len(wantIDs) {
		t.Fatalf("got %d frames, want %d (no auto-completion)", len(frames), len(wantIDs))
	}
	for i, id := range wantIDs {
		if frames[i].MsgID != id {
			t.Fatalf("frame %d = 0x%04x, want 0x%04x", i, frames[i].MsgID, id)
		}
	}
}

// TestPadRightSpaceFields (C-36) verifies DriverName/VehicleModel/
// LicensePlate are 0x20-padded (not 0x00).
func TestPadRightSpaceFields(t *testing.T) {
	cfg := &JTT905Config{
		Phone:        "013800138000",
		Version:      jtcommon.Version2019,
		DriverId:     "11012345678901234567",
		DriverName:   "张三",
		LicensePlate: "京A12345",
		LicenseColor: LicenseColorBlue,
		VehicleModel: "BJ-TAXI",
		LoadCapacity: 4,
		OnTime:       "240803080000",
		InitialSN:    0,
		Procedures:   []JTT905Procedure{{Type: ProcCheckIn}},
	}
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 50000, DstPort: 10700}
	packets := mustPlan(t, spec, cfg)
	frames := findFrames(packets)
	if len(frames) == 0 {
		t.Fatalf("no frames")
	}
	body := frames[0].Body
	// DriverName field: bytes 20-35 (16 bytes).
	// GBK 张三 = 4 bytes (d5 c5 c8 fd) + 12 spaces.
	if !bytes.Equal(body[20:24], []byte{0xd5, 0xc5, 0xc8, 0xfd}) {
		t.Fatalf("DriverName GBK = %x", body[20:24])
	}
	for i := 24; i < 36; i++ {
		if body[i] != 0x20 {
			t.Fatalf("DriverName pad byte %d = 0x%02x, want 0x20", i, body[i])
		}
	}
	// LicensePlate field: bytes 36-56 (21 bytes).
	// GBK 京A12345 = 8 bytes + 13 spaces.
	if !bytes.Equal(body[36:44], []byte{0xbe, 0xa9, 'A', '1', '2', '3', '4', '5'}) {
		t.Fatalf("LicensePlate GBK = %x", body[36:44])
	}
	for i := 44; i < 57; i++ {
		if body[i] != 0x20 {
			t.Fatalf("LicensePlate pad byte %d = 0x%02x, want 0x20", i, body[i])
		}
	}
	// VehicleModel field: bytes 64-79 (16 bytes).
	// "BJ-TAXI" = 7 bytes + 9 spaces.
	if !bytes.Equal(body[64:71], []byte("BJ-TAXI")) {
		t.Fatalf("VehicleModel = %q", body[64:71])
	}
	for i := 71; i < 80; i++ {
		if body[i] != 0x20 {
			t.Fatalf("VehicleModel pad byte %d = 0x%02x, want 0x20", i, body[i])
		}
	}
}

// TestCheckInEmptyPlate (C-03) verifies LicensePlate="" → 21 spaces.
func TestCheckInEmptyPlate(t *testing.T) {
	cfg := &JTT905Config{
		Phone:        "013800138000",
		Version:      jtcommon.Version2019,
		DriverId:     "11012345678901234567",
		DriverName:   "张三",
		LicenseColor: LicenseColorBlue,
		VehicleModel: "BJ-TAXI",
		LoadCapacity: 4,
		OnTime:       "240803080000",
		InitialSN:    0,
		Procedures:   []JTT905Procedure{{Type: ProcCheckIn}},
	}
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 50000, DstPort: 10700}
	packets := mustPlan(t, spec, cfg)
	frames := findFrames(packets)
	if len(frames) == 0 {
		t.Fatalf("no frames")
	}
	for i := 36; i < 57; i++ {
		if frames[0].Body[i] != 0x20 {
			t.Fatalf("empty plate byte %d = 0x%02x, want 0x20", i, frames[0].Body[i])
		}
	}
}
