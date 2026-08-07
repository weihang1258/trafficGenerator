package jt809

import (
	"context"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/protocol/jt808"
	"github.com/trafficgen/trafficgen/internal/protocol/jtcommon"
)

// mustPlan collects all PacketConfig from PlanWithConfig.
func mustPlan(t *testing.T, spec core.FlowSpec, cfg *JT809Config) []core.PacketConfig {
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

// findFrames returns all JT809 frames (payloads starting with a valid
// MsgLength prefix) with their parsed MsgID.
func findFrames(packets []core.PacketConfig) []*ParsedFrame {
	var out []*ParsedFrame
	for _, p := range packets {
		if len(p.Payload) < HeaderLen {
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

// TestMainLoginSuccess (B-01) verifies 0x1001 hex matches design §7B.13.
func TestMainLoginSuccess(t *testing.T) {
	cfg := &JT809Config{
		GNSSCenterId: 291,
		UserName:     "TEST",
		Password:     "0000000000",
		VersionFlag:  2,
		EncryptFlag:  1,
		EncryptKey:   0xDEADBEEF,
		InitialSN:    0,
		Procedures:   []JT809Procedure{{Type: ProcMainLogin}},
	}
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 50000, DstPort: 8812}
	packets := mustPlan(t, spec, cfg)
	frames := findFrames(packets)
	if len(frames) == 0 {
		t.Fatalf("no JT809 frames emitted")
	}
	pf := frames[0]
	if pf.MsgID != MsgMainLogin {
		t.Fatalf("MsgID = 0x%04x, want 0x1001", pf.MsgID)
	}
	if pf.MsgSN != 0 {
		t.Fatalf("MsgSN = %d, want 0 (first message = InitialSN)", pf.MsgSN)
	}
	if pf.MsgLength != 32+25 {
		t.Fatalf("MsgLength = %d, want 57 (32 header + 25 body)", pf.MsgLength)
	}
	if pf.VehicleColor != 0 {
		t.Fatalf("VehicleColor = %d, want 0 (non-vehicle message)", pf.VehicleColor)
	}
	if pf.VehiclePlate != "" {
		t.Fatalf("VehiclePlate = %q, want empty (21 spaces)", pf.VehiclePlate)
	}
	lb, err := ParseLoginBody(pf.Body)
	if err != nil {
		t.Fatalf("ParseLoginBody: %v", err)
	}
	if lb.UserName != "TEST" {
		t.Fatalf("UserName = %q, want TEST", lb.UserName)
	}
	if lb.Password != "0000000000" {
		t.Fatalf("Password = %q, want 0000000000", lb.Password)
	}
	if lb.GNSSCenterId != 291 {
		t.Fatalf("GNSSCenterId = %d, want 291", lb.GNSSCenterId)
	}
	if lb.VersionFlag != 2 {
		t.Fatalf("VersionFlag = %d, want 2", lb.VersionFlag)
	}
	if lb.EncryptFlag != 1 {
		t.Fatalf("EncryptFlag = %d, want 1", lb.EncryptFlag)
	}
	if lb.EncryptKey != 0xDEADBEEF {
		t.Fatalf("EncryptKey = 0x%08x, want 0xDEADBEEF", lb.EncryptKey)
	}
	// Hex verification (design §7B.13) — compare the first JT809 frame
	// (the first non-SYN packet payload).
	wantHex := "00000039" + "00000000" + "1001" + "00" +
		"202020202020202020202020202020202020202020" +
		"5445535400" + "30303030303030303030" +
		"00000123" + "02" + "01" + "deadbeef"
	var framePayload []byte
	for _, p := range packets {
		if len(p.Payload) >= HeaderLen {
			framePayload = p.Payload
			break
		}
	}
	if framePayload == nil {
		t.Fatalf("no JT809 frame payload found")
	}
	if !jtcommon.HexEqual(framePayload, wantHex) {
		t.Fatalf("0x1001 hex mismatch:\n want %s\n got  %s", wantHex, hexOf(framePayload))
	}
}

// TestMainLoginResponses (B-02/B-03/B-04/B-05) verifies the login
// response Result values.
func TestMainLoginResponses(t *testing.T) {
	cases := []struct {
		result uint8
		valid  bool
	}{
		{0, true},
		{1, true},
		{2, true},
		{3, true},
		{4, true},
		{5, false},
		{99, false},
	}
	for _, tc := range cases {
		cfg := &JT809Config{
			GNSSCenterId: 291,
			LoginResult:  tc.result,
			Procedures:   []JT809Procedure{{Type: ProcMainLoginResponse}},
		}
		err := ValidateConfig(cfg)
		if tc.valid && err != nil {
			t.Fatalf("Result=%d: expected valid, got %v", tc.result, err)
		}
		if !tc.valid && err == nil {
			t.Fatalf("Result=%d: expected rejection", tc.result)
		}
	}
}

// TestMainLogout (B-06) verifies 0x1003 has an empty body.
func TestMainLogout(t *testing.T) {
	cfg := &JT809Config{
		GNSSCenterId: 291,
		InitialSN:    1,
		Procedures:   []JT809Procedure{{Type: ProcMainLogout}},
	}
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 50000, DstPort: 8812}
	packets := mustPlan(t, spec, cfg)
	frames := findFrames(packets)
	if len(frames) == 0 {
		t.Fatalf("no frames")
	}
	pf := frames[0]
	if pf.MsgID != MsgMainLogout {
		t.Fatalf("MsgID = 0x%04x", pf.MsgID)
	}
	if len(pf.Body) != 0 {
		t.Fatalf("0x1003 body length %d, want 0", len(pf.Body))
	}
	if pf.MsgLength != 32 {
		t.Fatalf("MsgLength = %d, want 32 (header only)", pf.MsgLength)
	}
}

// TestDisconnectReasons (B-07/B-08/B-50) verifies ReasonCode 0/1/2 valid,
// 99 invalid.
func TestDisconnectReasons(t *testing.T) {
	for _, rc := range []uint8{0, 1, 2} {
		cfg := &JT809Config{
			GNSSCenterId: 291,
			Procedures:   []JT809Procedure{{Type: ProcMainDisconnectNotice, DisconnectReason: rc}},
		}
		if err := ValidateConfig(cfg); err != nil {
			t.Fatalf("ReasonCode=%d: %v", rc, err)
		}
		// Build the body directly.
		body := buildDisconnectNoticeBody(rc, 291)
		if len(body) != 5 {
			t.Fatalf("ReasonCode=%d: body length %d, want 5", rc, len(body))
		}
	}
	// 99 rejected.
	cfg := &JT809Config{
		GNSSCenterId: 291,
		Procedures:   []JT809Procedure{{Type: ProcMainDisconnectNotice, DisconnectReason: 99}},
	}
	if err := ValidateConfig(cfg); err == nil {
		t.Fatalf("ReasonCode=99 expected rejection")
	}
}

// TestVehicleRegister (B-09) verifies the 0x1200 container with
// SubMsgId=0x01, SubLength=38, and MsgLength=73 (design §7B.13 J-4.01).
func TestVehicleRegister(t *testing.T) {
	cfg := &JT809Config{
		GNSSCenterId: 291,
		VehicleColor: VehicleColorBlue,
		VehiclePlate: "京A12345",
		InitialSN:    1,
		Procedures:   []JT809Procedure{{Type: ProcVehicleRegister}},
	}
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 50000, DstPort: 8812}
	packets := mustPlan(t, spec, cfg)
	frames := findFrames(packets)
	if len(frames) == 0 {
		t.Fatalf("no frames")
	}
	pf := frames[0]
	if pf.MsgID != MsgVehicleDynamic {
		t.Fatalf("MsgID = 0x%04x, want 0x1200", pf.MsgID)
	}
	if pf.MsgSN != 1 {
		t.Fatalf("MsgSN = %d, want 1", pf.MsgSN)
	}
	if pf.MsgLength != 32+1+2+38 {
		t.Fatalf("MsgLength = %d, want 73 (32+1+2+38)", pf.MsgLength)
	}
	if pf.VehicleColor != VehicleColorBlue {
		t.Fatalf("VehicleColor = %d, want 1", pf.VehicleColor)
	}
	if pf.VehiclePlate != "京A12345" {
		t.Fatalf("VehiclePlate = %q, want 京A12345", pf.VehiclePlate)
	}
	cb, err := ParseContainerBody(pf.Body)
	if err != nil {
		t.Fatalf("ParseContainerBody: %v", err)
	}
	if cb.SubMsgId != SubVehicleRegister {
		t.Fatalf("SubMsgId = 0x%02x, want 0x01", cb.SubMsgId)
	}
	if cb.SubLen != 38 {
		t.Fatalf("SubLen = %d, want 38", cb.SubLen)
	}
	// SubBody: TerminalPhone BCD(6) + ManufacturerId(5) + TerminalModel(20)
	// + TerminalId(7).
	if len(cb.SubBody) != 38 {
		t.Fatalf("SubBody length %d, want 38", len(cb.SubBody))
	}
	if !jtcommon.HexEqual(cb.SubBody[:6], "013800138000") {
		t.Fatalf("TerminalPhone BCD = %x, want 013800138000", cb.SubBody[:6])
	}
	if !jtcommon.HexEqual(cb.SubBody[6:11], "5445535400") {
		t.Fatalf("ManufacturerId = %x, want TEST\\0", cb.SubBody[6:11])
	}
}

// TestRealtimeLocation (B-11/B-55) verifies 0x1202 SubBody = JT808 0x0200
// layout (28 bytes) with SubLength=28, MsgLength=63 (J-4.02).
func TestRealtimeLocation(t *testing.T) {
	cfg := &JT809Config{
		GNSSCenterId: 291,
		VehicleColor: VehicleColorBlue,
		VehiclePlate: "京A12345",
		InitialSN:    2,
		Procedures: []JT809Procedure{{
			Type: ProcRealtimeLocation,
			LocationData: &jt808.JT808Location{
				AlarmFlag:  1,
				StatusFlag: 1,
				Latitude:   39900000,
				Longitude:  116400000,
				Altitude:   50,
				Speed:      600,
				Direction:  180,
				Time:       "240803120000",
			},
		}},
	}
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 50000, DstPort: 8812}
	packets := mustPlan(t, spec, cfg)
	frames := findFrames(packets)
	if len(frames) == 0 {
		t.Fatalf("no frames")
	}
	pf := frames[0]
	if pf.MsgLength != 32+1+2+28 {
		t.Fatalf("MsgLength = %d, want 63 (32+1+2+28)", pf.MsgLength)
	}
	cb, err := ParseContainerBody(pf.Body)
	if err != nil {
		t.Fatalf("ParseContainerBody: %v", err)
	}
	if cb.SubMsgId != SubRealtimeLocation {
		t.Fatalf("SubMsgId = 0x%02x, want 0x02", cb.SubMsgId)
	}
	if cb.SubLen != 28 {
		t.Fatalf("SubLen = %d, want 28", cb.SubLen)
	}
	// Verify the location fields match the input values (big-endian).
	// Latitude=39900000 → 0x0260D360 (39.9 deg, Beijing).
	// Longitude=116400000 → 0x06F01F80 (116.4 deg).
	// The design doc §7A.14 HexDump shows 0263B560/06E60C80 which are
	// typos (those hex values decode to 40088928/115739776, not matching
	// the stated 39.9e6/116.4e6). The implementation correctly encodes
	// the input uint32 values in big-endian.
	want := "00000001" + "00000001" + "0260d360" + "06f01f80" +
		"0032" + "0258" + "00b4" + "240803120000"
	if !jtcommon.HexEqual(cb.SubBody, want) {
		t.Fatalf("0x1202 SubBody mismatch:\n want %s\n got  %s", want, hexOf(cb.SubBody))
	}
}

// TestHistoryLocation (B-14/B-15) verifies the 0x1203 container.
func TestHistoryLocation(t *testing.T) {
	// TimeRange(12 BCD) + 3 location bodies.
	timeRange, _ := jtcommon.BCDEncode("240803000000")
	subBody := append([]byte{}, timeRange...)
	loc := &jt808.JT808Location{Latitude: 39900000, Longitude: 116400000, Time: "240803120000"}
	locBody, _ := jt808.BuildLocationBody(loc)
	for i := 0; i < 3; i++ {
		subBody = append(subBody, locBody...)
	}
	cfg := &JT809Config{
		GNSSCenterId: 291,
		VehicleColor: VehicleColorBlue,
		VehiclePlate: "京A12345",
		InitialSN:    3,
		Procedures: []JT809Procedure{{
			Type:    ProcHistoryLocation,
			SubBody: subBody,
		}},
	}
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 50000, DstPort: 8812}
	packets := mustPlan(t, spec, cfg)
	frames := findFrames(packets)
	if len(frames) == 0 {
		t.Fatalf("no frames")
	}
	cb, err := ParseContainerBody(frames[0].Body)
	if err != nil {
		t.Fatalf("ParseContainerBody: %v", err)
	}
	if cb.SubMsgId != SubHistoryLocation {
		t.Fatalf("SubMsgId = 0x%02x", cb.SubMsgId)
	}
	// 6 (TimeRange) + 3*28 = 90.
	if len(cb.SubBody) != 90 {
		t.Fatalf("SubBody length %d, want 90", len(cb.SubBody))
	}
}

// TestAlarm (B-16/B-17) verifies 0x1208 alarm SubBody.
func TestAlarm(t *testing.T) {
	cfg := &JT809Config{
		GNSSCenterId: 291,
		VehicleColor: VehicleColorBlue,
		VehiclePlate: "京A12345",
		InitialSN:    4,
		Procedures: []JT809Procedure{{
			Type:       ProcAlarm,
			AlarmFlag:  0x00000001,
			PulseSpeed: 600,
			LocationData: &jt808.JT808Location{
				Latitude: 39900000, Longitude: 116400000, Time: "240803120000",
			},
		}},
	}
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 50000, DstPort: 8812}
	packets := mustPlan(t, spec, cfg)
	frames := findFrames(packets)
	if len(frames) == 0 {
		t.Fatalf("no frames")
	}
	cb, err := ParseContainerBody(frames[0].Body)
	if err != nil {
		t.Fatalf("ParseContainerBody: %v", err)
	}
	if cb.SubMsgId != SubAlarm {
		t.Fatalf("SubMsgId = 0x%02x, want 0x08", cb.SubMsgId)
	}
	if !jtcommon.HexEqual(cb.SubBody[:4], "00000001") {
		t.Fatalf("AlarmFlag = %x", cb.SubBody[:4])
	}
	if !jtcommon.HexEqual(cb.SubBody[4:6], "0258") {
		t.Fatalf("PulseSpeed = %x, want 0258", cb.SubBody[4:6])
	}
}

// TestAlarmWithAttachment (B-18/B-19/B-20/B-21) verifies 0x1400 body.
func TestAlarmWithAttachment(t *testing.T) {
	// (a) FileType=1, FileUrl non-empty.
	body, err := buildAlarmWithAttachmentBody(0x00000002, "240803120000", []byte("test alarm"), FileTypeImage, "http://example.com/alarm/001.jpg")
	if err != nil {
		t.Fatalf("buildAlarmWithAttachmentBody: %v", err)
	}
	if !jtcommon.HexEqual(body[:4], "00000002") {
		t.Fatalf("AlarmFlag mismatch")
	}
	if !jtcommon.HexEqual(body[4:10], "240803120000") {
		t.Fatalf("AlarmTime mismatch")
	}
	// FileType is at offset 4+6+len(alarmInfo)=10+10=20.
	if body[20] != FileTypeImage {
		t.Fatalf("FileType = %d, want 1", body[20])
	}
	url := string(body[21:])
	if url != "http://example.com/alarm/001.jpg" {
		t.Fatalf("FileUrl = %q", url)
	}

	// (b) FileType=0, FileUrl empty → body ends right after FileType.
	body2, err := buildAlarmWithAttachmentBody(0, "240803120000", nil, FileTypeNone, "")
	if err != nil {
		t.Fatalf("buildAlarmWithAttachmentBody: %v", err)
	}
	if len(body2) != 4+6+1 {
		t.Fatalf("FileType=0 body length %d, want 11", len(body2))
	}

	// (d) Chinese URL. The URL is GBK-encoded in the body, so decode
	// it back to UTF-8 for comparison.
	body3, err := buildAlarmWithAttachmentBody(0, "240803120000", nil, FileTypeImage, "报警图片001.jpg")
	if err != nil {
		t.Fatalf("Chinese URL: %v", err)
	}
	url3Bytes := body3[11:]
	url3, err := jtcommon.GBKDecode(url3Bytes)
	if err != nil {
		t.Fatalf("Chinese URL GBK decode: %v", err)
	}
	if url3 != "报警图片001.jpg" {
		t.Fatalf("Chinese URL roundtrip = %q", url3)
	}

	// (e) 129 Chinese chars = 258 GBK bytes > 256 → reject.
	longURL := ""
	for i := 0; i < 129; i++ {
		longURL += "报"
	}
	if _, err := buildAlarmWithAttachmentBody(0, "240803120000", nil, FileTypeImage, longURL); err == nil {
		t.Fatalf("FileUrl 258 GBK bytes expected rejection")
	}
	// (c) 128 Chinese chars = 256 GBK bytes → accept.
	okURL := ""
	for i := 0; i < 128; i++ {
		okURL += "报"
	}
	if _, err := buildAlarmWithAttachmentBody(0, "240803120000", nil, FileTypeImage, okURL); err != nil {
		t.Fatalf("FileUrl 256 GBK bytes expected acceptance, got %v", err)
	}
}

// TestSlaveLinkIndependentMsgSN (B-24b) verifies main and slave links
// use independent MsgSN counters. Also verifies that 0x1002 (main-link
// response) uses the platformMainMsgSN counter (starting at
// PlatformInitialSN=0), NOT the mainMsgSN counter.
func TestSlaveLinkIndependentMsgSN(t *testing.T) {
	cfg := &JT809Config{
		GNSSCenterId:       291,
		InitialSN:          0,
		PlatformInitialSN:  0,
		SlaveLinkEnabled:   true,
		Procedures: []JT809Procedure{
			{Type: ProcMainLogin},             // main SN=0 (mainMsgSN)
			{Type: ProcMainLoginResponse},     // main SN=0 (platformMainMsgSN, independent)
			{Type: ProcSlaveConnect, Link: LinkSlave}, // slave SN=0 (slaveMsgSN, independent)
		},
	}
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 50000, DstPort: 8812}
	packets := mustPlan(t, spec, cfg)
	frames := findFrames(packets)
	if len(frames) != 3 {
		t.Fatalf("got %d frames, want 3", len(frames))
	}
	if frames[0].MsgID != MsgMainLogin || frames[0].MsgSN != 0 {
		t.Fatalf("frame 0: 0x%04x SN=%d", frames[0].MsgID, frames[0].MsgSN)
	}
	// 0x1002 uses platformMainMsgSN (independent of mainMsgSN).
	if frames[1].MsgID != MsgMainLoginResponse || frames[1].MsgSN != 0 {
		t.Fatalf("frame 1: 0x%04x SN=%d, want 0x1002 SN=0 (platformMainMsgSN)", frames[1].MsgID, frames[1].MsgSN)
	}
	// 0x9001 uses slaveMsgSN (independent counter, restarts at InitialSN=0).
	if frames[2].MsgID != MsgSlaveConnect || frames[2].MsgSN != 0 {
		t.Fatalf("frame 2: 0x%04x SN=%d, want 0x9001 SN=0 (independent counter)", frames[2].MsgID, frames[2].MsgSN)
	}
}

// TestSlaveLinkSecondTCP verifies that when a slave-link procedure is
// present, the planner opens a SECOND TCP 4-tuple (port 8813 on the lower
// side), distinct from the main link's port 8812. The check walks all
// emitted PacketConfig entries and asserts:
//   - main-link packets use spec.SrcPort / spec.DstPort (50000/8812).
//   - slave-link packets (flowID matches slaveFlowID) use port 8813 on
//     the lower side (either src or dst, depending on direction).
//   - the slave 4-tuple is opened with a SYN before any slave data and
//     closed with FINs after.
//
// 修复点：jt809 旧实现把 slave 消息路由到 slaveFlowID 但复用主链路 4-元组，
// 导致 Wireshark 只看到一条 TCP，与 JT/T 809-2019 §5.2 不符。新实现显式开
// 启第二条 TCP (port 8813)，并由 SlaveLinkEnabled 或 存在 slave 流程自动触发。
func TestSlaveLinkSecondTCP(t *testing.T) {
	cfg := &JT809Config{
		GNSSCenterId: 291,
		InitialSN:    0,
		Procedures: []JT809Procedure{
			{Type: ProcMainLogin},                       // main only
			{Type: ProcSlaveConnect, Link: LinkSlave},   // opens slave link
		},
	}
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 50000, DstPort: 8812}
	packets := mustPlan(t, spec, cfg)

	// Collect TCP packets by flowID + flags. This lets us verify that
	// the slave flowID carries a SYN, SYN+ACK, ACK, and a FIN (handshake
	// + teardown).
	type tcpSig struct {
		flowID  string
		srcPort uint16
		dstPort uint16
		flags   uint8
	}
	var sigs []tcpSig
	for _, p := range packets {
		if p.L4.Protocol != "tcp" {
			continue
		}
		sigs = append(sigs, tcpSig{
			flowID:  p.FlowID,
			srcPort: p.L4.SrcPort,
			dstPort: p.L4.DstPort,
			flags:   p.L4.Flags,
		})
	}

	// 1) Main flowID must carry a SYN on its own 4-tuple (50000→8812).
	sawMainSYN := false
	for _, s := range sigs {
		if s.flowID == "jt809-main-291-0" && s.flags == 0x02 && s.srcPort == 50000 && s.dstPort == 8812 {
			sawMainSYN = true
			break
		}
	}
	if !sawMainSYN {
		t.Fatalf("main link SYN on (50000,8812) not found")
	}

	// 2) Slave flowID must carry a SYN, and the destination port MUST be 8813.
	sawSlaveSYN := false
	for _, s := range sigs {
		if s.flowID == "jt809-slave-291-0" && s.flags == 0x02 && s.dstPort == SlaveLinkPort {
			sawSlaveSYN = true
			break
		}
	}
	if !sawSlaveSYN {
		t.Fatalf("slave link SYN on (... → 8813) not found; slave TCP not opened")
	}

	// 3) Slave flowID must carry a SYN+ACK (flag 0x12) and a final ACK (0x10).
	hasSlaveSYNACK, hasSlaveFIN := false, false
	for _, s := range sigs {
		if s.flowID != "jt809-slave-291-0" {
			continue
		}
		if s.flags == 0x12 {
			hasSlaveSYNACK = true
		}
		if s.flags == 0x11 {
			hasSlaveFIN = true
		}
	}
	if !hasSlaveSYNACK {
		t.Fatalf("slave link SYN+ACK (0x12) not found")
	}
	if !hasSlaveFIN {
		t.Fatalf("slave link FIN (0x11) not found in teardown")
	}

	// 4) The slave 0x9001 frame itself must be carried on port 8813 on the
	// lower side (down direction: upper→lower, dstPort=8813). Search all
	// TCP packets for one whose payload begins with a valid JT809 header
	// and whose flowID is the slave flow.
	frames := findFrames(packets)
	var sawSlaveFrame bool
	for _, f := range frames {
		if f.MsgID == MsgSlaveConnect {
			sawSlaveFrame = true
			break
		}
	}
	if !sawSlaveFrame {
		t.Fatalf("0x9001 slave connect frame not emitted")
	}
	for _, p := range packets {
		if p.L4.Protocol != "tcp" {
			continue
		}
		if len(p.Payload) >= HeaderLen && p.FlowID == "jt809-slave-291-0" {
			// The slave frame rides on the slave link; direction is "down"
			// (upper→lower) when SlaveConnect is emitted by ProcSlaveConnect.
			if p.L4.DstPort != SlaveLinkPort {
				t.Fatalf("slave link frame on port %d, want %d", p.L4.DstPort, SlaveLinkPort)
			}
			break
		}
	}
}

// TestMsgsnWraparound32bit (B-27) verifies 32-bit wrap: FFFFFFFE → FF → 0 → 1.
func TestMsgsnWraparound32bit(t *testing.T) {
	cfg := &JT809Config{
		GNSSCenterId: 291,
		InitialSN:    0xFFFFFFFE,
		Procedures: []JT809Procedure{
			{Type: ProcMainLogin},
			{Type: ProcMainLogout},
			{Type: ProcMainLogout},
			{Type: ProcMainLogout},
		},
	}
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 50000, DstPort: 8812}
	packets := mustPlan(t, spec, cfg)
	frames := findFrames(packets)
	want := []uint32{0xFFFFFFFE, 0xFFFFFFFF, 0, 1}
	if len(frames) != len(want) {
		t.Fatalf("got %d frames, want %d", len(frames), len(want))
	}
	for i := range want {
		if frames[i].MsgSN != want[i] {
			t.Fatalf("frame %d SN = 0x%08x, want 0x%08x", i, frames[i].MsgSN, want[i])
		}
	}
}

// TestVehiclePlatePadding (B-30/B-56) verifies 21-byte space padding.
func TestVehiclePlatePadding(t *testing.T) {
	body := make([]byte, 0, 64)
	body = append(body, 0x01) // sub msg id
	hdr, err := buildHeader(0, MsgVehicleDynamic, VehicleColorBlue, "京A12345", body)
	if err != nil {
		t.Fatalf("buildHeader: %v", err)
	}
	// Header bytes: MsgLength(4) MsgSN(4) MsgId(2) VehicleColor(1) Plate(21).
	plate := hdr[11:32]
	if len(plate) != 21 {
		t.Fatalf("plate length %d, want 21", len(plate))
	}
	// First 8 bytes = GBK 京A12345.
	if !jtcommon.HexEqual(plate[:8], "bea9413132333435") {
		t.Fatalf("plate head = %x", plate[:8])
	}
	// Remaining 13 = 0x20 spaces.
	for i := 8; i < 21; i++ {
		if plate[i] != 0x20 {
			t.Fatalf("plate byte %d = 0x%02x, want 0x20", i, plate[i])
		}
	}
	// Empty plate → 21 spaces.
	hdr2, err := buildHeader(0, MsgVehicleDynamic, VehicleColorBlue, "", body)
	if err != nil {
		t.Fatalf("buildHeader empty plate: %v", err)
	}
	for i := 11; i < 32; i++ {
		if hdr2[i] != 0x20 {
			t.Fatalf("empty plate byte %d = 0x%02x, want 0x20", i, hdr2[i])
		}
	}
}

// TestNoEscapeInJT809 (B-36) verifies 0x7e in the body is NOT escaped.
func TestNoEscapeInJT809(t *testing.T) {
	body := []byte{0x7e, 0x7d, 0x01, 0x02}
	frame, err := buildFrame(0, MsgMainLogin, 0, "", body)
	if err != nil {
		t.Fatalf("buildFrame: %v", err)
	}
	// The body bytes must appear verbatim in the frame.
	for i, b := range body {
		if frame[HeaderLen+i] != b {
			t.Fatalf("byte %d = 0x%02x, want 0x%02x (no escape)", HeaderLen+i, frame[HeaderLen+i], b)
		}
	}
}

// TestMsgLengthCorrect (B-35) verifies exact MsgLength values.
func TestMsgLengthCorrect(t *testing.T) {
	cases := []struct {
		name string
		cfg  *JT809Config
		want uint32
	}{
		{"main_login", &JT809Config{GNSSCenterId: 291, Procedures: []JT809Procedure{{Type: ProcMainLogin}}}, 57},
		{"main_login_response", &JT809Config{GNSSCenterId: 291, Procedures: []JT809Procedure{{Type: ProcMainLoginResponse}}}, 37},
		{"main_logout", &JT809Config{GNSSCenterId: 291, Procedures: []JT809Procedure{{Type: ProcMainLogout}}}, 32},
	}
	for _, tc := range cases {
		spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 50000, DstPort: 8812}
		packets := mustPlan(t, spec, tc.cfg)
		frames := findFrames(packets)
		if len(frames) == 0 {
			t.Fatalf("%s: no frames", tc.name)
		}
		if frames[0].MsgLength != tc.want {
			t.Fatalf("%s: MsgLength = %d, want %d", tc.name, frames[0].MsgLength, tc.want)
		}
	}
}

// TestValidate (B-32/B-33/B-34) verifies UserName/Password/VersionFlag.
func TestValidate(t *testing.T) {
	// UserName > 5 → reject.
	cfg := &JT809Config{GNSSCenterId: 291, UserName: "123456"}
	if err := ValidateConfig(cfg); err == nil {
		t.Fatalf("UserName length 6 expected rejection")
	}
	// UserName short → accept (right-padded with 0x00).
	cfg2 := &JT809Config{GNSSCenterId: 291, UserName: "AB"}
	if err := ValidateConfig(cfg2); err != nil {
		t.Fatalf("UserName short expected acceptance, got %v", err)
	}
	// Password > 10 → reject.
	cfg3 := &JT809Config{GNSSCenterId: 291, Password: "12345678901"}
	if err := ValidateConfig(cfg3); err == nil {
		t.Fatalf("Password length 11 expected rejection")
	}
	// VersionFlag=3 → reject.
	cfg4 := &JT809Config{GNSSCenterId: 291, VersionFlag: 3}
	if err := ValidateConfig(cfg4); err == nil {
		t.Fatalf("VersionFlag=3 expected rejection")
	}
	// GNSSCenterId > 999999999 → reject.
	cfg5 := &JT809Config{GNSSCenterId: 1000000000}
	if err := ValidateConfig(cfg5); err == nil {
		t.Fatalf("GNSSCenterId=1e9 expected rejection")
	}
}

// TestDefaultUserName verifies GNSSCenterId=291 → "00291" (design §4B.1).
func TestDefaultUserName(t *testing.T) {
	if got := defaultUserName(291); got != "00291" {
		t.Fatalf("defaultUserName(291) = %q, want 00291", got)
	}
	if got := defaultUserName(123456789); got != "56789" {
		t.Fatalf("defaultUserName(123456789) = %q, want 56789", got)
	}
}

// TestSubMsg1204AlarmAttachment (B-39/B-51) verifies the 0x1204 SubBody
// field order: AlarmFlag(4)+AlarmTime(6)+AlarmInfo(var)+FileType(1)+
// FileSize(4)+FileUrl(var).
func TestSubMsg1204AlarmAttachment(t *testing.T) {
	sub, err := buildAlarmAttachmentSubBody(0x00000001, "240803120000", []byte("alarm-detail"), FileTypeImage, 2048, "http://example.com/a.jpg")
	if err != nil {
		t.Fatalf("buildAlarmAttachmentSubBody: %v", err)
	}
	if !jtcommon.HexEqual(sub[:4], "00000001") {
		t.Fatalf("AlarmFlag mismatch")
	}
	if !jtcommon.HexEqual(sub[4:10], "240803120000") {
		t.Fatalf("AlarmTime mismatch")
	}
	// alarmInfo = 12 bytes, so FileType at offset 10+12=22.
	if sub[22] != FileTypeImage {
		t.Fatalf("FileType = %d, want 1", sub[22])
	}
	// FileSize at offset 23-26.
	if !jtcommon.HexEqual(sub[23:27], "00000800") {
		t.Fatalf("FileSize = %x, want 00000800", sub[23:27])
	}
	// FileType=0 → FileSize=0.
	sub2, err := buildAlarmAttachmentSubBody(0, "240803120000", nil, FileTypeNone, 0, "")
	if err != nil {
		t.Fatalf("buildAlarmAttachmentSubBody: %v", err)
	}
	if !jtcommon.HexEqual(sub2[10:14], "00000000") {
		t.Fatalf("FileType=0 FileSize = %x, want 0", sub2[10:14])
	}
}

// TestSubMsg1205Direction (B-40) verifies 0x1205 SubBody layout.
func TestSubMsg1205Direction(t *testing.T) {
	phoneBCD := jtcommon.MustBCD("013800138000")
	sub := buildVehicleDirectionSubBody(phoneBCD, 90)
	if len(sub) != 8 {
		t.Fatalf("SubBody length %d, want 8", len(sub))
	}
	if !jtcommon.HexEqual(sub[:6], "013800138000") {
		t.Fatalf("TerminalPhone mismatch")
	}
	if !jtcommon.HexEqual(sub[6:8], "005a") {
		t.Fatalf("Direction mismatch: %x", sub[6:8])
	}
}

// TestSubMsg1209EventReport (B-43) verifies 0x1209 SubBody layout.
func TestSubMsg1209EventReport(t *testing.T) {
	phoneBCD := jtcommon.MustBCD("013800138000")
	sub, err := buildEventReportSubBody(phoneBCD, 7, "240803120000")
	if err != nil {
		t.Fatalf("buildEventReportSubBody: %v", err)
	}
	if len(sub) != 14 {
		t.Fatalf("SubBody length %d, want 14", len(sub))
	}
	if !jtcommon.HexEqual(sub[6:8], "0007") {
		t.Fatalf("EventId mismatch")
	}
	if !jtcommon.HexEqual(sub[8:14], "240803120000") {
		t.Fatalf("EventTime mismatch")
	}
}

// TestSubMsg120ALogout (B-44) verifies 0x120A SubBody = TerminalPhone only.
func TestSubMsg120ALogout(t *testing.T) {
	phoneBCD := jtcommon.MustBCD("013800138000")
	sub := buildVehicleLogoutSubBody(phoneBCD)
	if len(sub) != 6 {
		t.Fatalf("SubBody length %d, want 6", len(sub))
	}
	if !jtcommon.HexEqual(sub, "013800138000") {
		t.Fatalf("TerminalPhone mismatch")
	}
}

// TestContainer1300 (B-45) verifies the 0x1300 container body layout.
func TestContainer1300(t *testing.T) {
	subBody := []byte{0x01, 0x02, 0x03, 0x04}
	body := buildContainerBody(SubQueryVehicle, subBody)
	if len(body) != 3+4 {
		t.Fatalf("body length %d, want 7", len(body))
	}
	if body[0] != SubQueryVehicle {
		t.Fatalf("SubMsgId = 0x%02x", body[0])
	}
	cb, err := ParseContainerBody(body)
	if err != nil {
		t.Fatalf("ParseContainerBody: %v", err)
	}
	if cb.SubMsgId != SubQueryVehicle || cb.SubLen != 4 {
		t.Fatalf("parsed: SubMsgId=0x%02x SubLen=%d", cb.SubMsgId, cb.SubLen)
	}
}

// TestEncryptPlaceholder (B-31) verifies EncryptFlag=1 + EncryptKey
// emits the fields unchanged.
func TestEncryptPlaceholder(t *testing.T) {
	cfg := &JT809Config{
		GNSSCenterId: 291,
		UserName:     "TEST",
		Password:     "0000000000",
		VersionFlag:  2,
		EncryptFlag:  1,
		EncryptKey:   0xDEADBEEF,
		InitialSN:    0,
		Procedures:   []JT809Procedure{{Type: ProcMainLogin}},
	}
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 50000, DstPort: 8812}
	packets := mustPlan(t, spec, cfg)
	frames := findFrames(packets)
	if len(frames) == 0 {
		t.Fatalf("no frames")
	}
	lb, _ := ParseLoginBody(frames[0].Body)
	if lb.EncryptFlag != 1 {
		t.Fatalf("EncryptFlag = %d, want 1", lb.EncryptFlag)
	}
	if lb.EncryptKey != 0xDEADBEEF {
		t.Fatalf("EncryptKey = 0x%08x", lb.EncryptKey)
	}
}

// TestFlowIDStable (B-54) verifies flowID templates.
func TestFlowIDStable(t *testing.T) {
	cfg := &JT809Config{
		GNSSCenterId: 291,
		InitialSN:    7,
		Procedures: []JT809Procedure{
			{Type: ProcMainLogin},
			{Type: ProcSlaveConnect, Link: LinkSlave},
		},
	}
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 50000, DstPort: 8812}
	packets := mustPlan(t, spec, cfg)
	if len(packets) == 0 {
		t.Fatalf("no packets")
	}
	// Main flow: "jt809-main-291-7". The first data packet after the
	// handshake carries a JT809 frame with flowID "jt809-main-291-7".
	sawMain := false
	sawSlave := false
	for _, p := range packets {
		if p.FlowID == "jt809-main-291-7" {
			sawMain = true
		}
		if p.FlowID == "jt809-slave-291-7" {
			sawSlave = true
		}
	}
	if !sawMain {
		t.Fatalf("main flowID jt809-main-291-7 not found")
	}
	if !sawSlave {
		t.Fatalf("slave flowID jt809-slave-291-7 not found")
	}
}

// hexOf returns the hex string of a byte slice.
func hexOf(b []byte) string {
	const hexChars = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, by := range b {
		out = append(out, hexChars[by>>4], hexChars[by&0x0f])
	}
	return string(out)
}
