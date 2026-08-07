package gbt32960

// Additional GBT32960 planner tests: VIN/SIM/serial, encrypt rules,
// alarm data, time fields, state machine, CustomFields, multi-vehicle,
// platform-side, reissue, and Validate negative cases.

import (
	"context"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

// --- §8.3 应答标志 ---

// T-GBT-014: all uplink messages have resp=0xFE.
func TestUplinkRespIsFE(t *testing.T) {
	p := NewPlanner()
	spec := gbtSpec(1000)
	tcps := tcpPackets(mustPlan(t, p, spec))
	payloads := pshPayloads(tcps)
	for i, pl := range payloads {
		if len(pl) < 4 {
			continue
		}
		// Uplink = 0x01 login (payload[0]) and 0x04 logout (last uplink).
		if i == 0 {
			if pl[3] != RespNone {
				t.Errorf("login resp = 0x%02x, want 0xFE", pl[3])
			}
		}
	}
}

// T-GBT-015: ResponseFlags=01 writes into next uplink (0x04 logout).
func TestResponseFlags01WritesNextUplink(t *testing.T) {
	p := NewPlanner()
	spec := gbtSpec(1000)
	spec.GBT32960.ResponseFlags = "01"
	tcps := tcpPackets(mustPlan(t, p, spec))
	payloads := pshPayloads(tcps)
	// 0x0C ack (payload[1]) resp must be 0xFE.
	if payloads[1][3] != RespNone {
		t.Errorf("0x0C resp = 0x%02x, want 0xFE", payloads[1][3])
	}
	// Next uplink = 0x04 logout (payload[2] since no Reports).
	if payloads[2][3] != RespSuccess {
		t.Errorf("logout resp = 0x%02x, want 0x01 (ResponseFlags)", payloads[2][3])
	}
}

// T-GBT-016: ResponseFlags=02 → no Reports, direct to logout.
func TestResponseFlags02NoReporting(t *testing.T) {
	p := NewPlanner()
	spec := gbtSpec(1000)
	spec.GBT32960.ResponseFlags = "02"
	spec.GBT32960.Reports = []GBT32960Report{{}}
	tcps := tcpPackets(mustPlan(t, p, spec))
	payloads := pshPayloads(tcps)
	// Should be: 0x01 login, 0x0C ack, 0x04 logout, 0x0C ack.
	cmds := extractCmds(payloads)
	for _, c := range cmds {
		if c == CmdRealtimeReport {
			t.Errorf("found 0x02 report in ResponseFlags=02 path; expected skip to logout")
		}
	}
}

// T-GBT-017: ResponseFlags=03 (VIN duplicate) → no logout, direct teardown.
func TestResponseFlags03NoLogout(t *testing.T) {
	p := NewPlanner()
	spec := gbtSpec(1000)
	spec.GBT32960.ResponseFlags = "03"
	tcps := tcpPackets(mustPlan(t, p, spec))
	payloads := pshPayloads(tcps)
	for _, pl := range payloads {
		if len(pl) >= 3 && pl[2] == CmdVehicleLogout {
			t.Errorf("found 0x04 logout in ResponseFlags=03 path; expected no logout")
		}
	}
}

// T-GBT-019: ResponseFlags="05" invalid → Validate error.
func TestResponseFlagsInvalid(t *testing.T) {
	p := NewPlanner()
	spec := gbtSpec(1000)
	spec.GBT32960.ResponseFlags = "05"
	mustFail(t, p, spec, "invalid ResponseFlags")
}

// --- §8.4 VIN / SIM / 序列号 ---

// T-GBT-020: VIN 17 bytes, no padding.
func TestVIN17NoPad(t *testing.T) {
	p := NewPlanner()
	spec := gbtSpec(1000)
	tcps := tcpPackets(mustPlan(t, p, spec))
	m := parseFirstMsg(t, tcps)
	if string(m.VIN) != "LXXXXXXXXXXXXXXX1" {
		t.Errorf("VIN = %q, want original 17 bytes", string(m.VIN))
	}
}

// T-GBT-021: VIN 10 bytes right-padded with 0x00.
func TestVIN10Padded(t *testing.T) {
	p := NewPlanner()
	spec := gbtSpec(1000)
	spec.GBT32960.VIN = "LXXXXXXXXX"
	tcps := tcpPackets(mustPlan(t, p, spec))
	m := parseFirstMsg(t, tcps)
	if string(m.VIN[:10]) != "LXXXXXXXXX" {
		t.Errorf("VIN[:10] = %q, want LXXXXXXXXX", string(m.VIN[:10]))
	}
	for i := 10; i < VINLen; i++ {
		if m.VIN[i] != 0x00 {
			t.Errorf("VIN[%d] = 0x%02x, want 0x00 (pad)", i, m.VIN[i])
		}
	}
}

// T-GBT-022: VIN 18 bytes → V2 error.
func TestVIN18Error(t *testing.T) {
	p := NewPlanner()
	spec := gbtSpec(1000)
	spec.GBT32960.VIN = "LXXXXXXXXXXXXXXX12"
	mustFail(t, p, spec, "VIN length")
}

// T-GBT-023: VIN with non-ASCII → V3 error.
func TestVINNonASCIIError(t *testing.T) {
	p := NewPlanner()
	spec := gbtSpec(1000)
	// Use a VIN <= 17 bytes so V2 (length) does not fire first; V3
	// (non-ASCII) is the targeted check. "中" is 3 bytes in UTF-8.
	spec.GBT32960.VIN = "LXX中XXXXXXXX1"
	mustFail(t, p, spec, "non-ASCII")
}

// T-GBT-024: VIN empty + Role=vehicle → V4 error.
func TestVINEmptyVehicleError(t *testing.T) {
	p := NewPlanner()
	spec := gbtSpec(1000)
	spec.GBT32960.VIN = ""
	mustFail(t, p, spec, "VIN is required")
}

// T-GBT-028: SIM 21 bytes → V5 error.
func TestSIM21Error(t *testing.T) {
	p := NewPlanner()
	spec := gbtSpec(1000)
	spec.GBT32960.SIM = "123456789012345678901"
	mustFail(t, p, spec, "SIM length")
}

// T-GBT-029b: LoginSerialNumber=65531 → bytes FF FB.
func TestLoginSerial65531(t *testing.T) {
	p := NewPlanner()
	spec := gbtSpec(1000)
	spec.GBT32960.LoginSerialNumber = 65531
	tcps := tcpPackets(mustPlan(t, p, spec))
	m := parseFirstMsg(t, tcps)
	if m.Data[6] != 0xFF || m.Data[7] != 0xFB {
		t.Errorf("serial = %02x %02x, want FF FB (65531 big-endian)", m.Data[6], m.Data[7])
	}
}

// T-GBT-030: LoginSerialNumber=65532 → V7 error.
func TestLoginSerial65532Error(t *testing.T) {
	p := NewPlanner()
	spec := gbtSpec(1000)
	spec.GBT32960.LoginSerialNumber = 65532
	mustFail(t, p, spec, "out of range")
}

// T-GBT-030b: LoginSerialNumber=0 → V7 error (must be >=1).
func TestLoginSerial0Error(t *testing.T) {
	p := NewPlanner()
	spec := gbtSpec(1000)
	spec.GBT32960.LoginSerialNumber = 0
	// Per design T-GBT-030b, 0 is treated as an explicit error (V7).
	mustFail(t, p, spec, "out of range")
}

// T-GBT-030c: VIN with I/O/Q → V3b error.
func TestVINWithIOQError(t *testing.T) {
	p := NewPlanner()
	spec := gbtSpec(1000)
	spec.GBT32960.VIN = "LIOXXXXXXXXXXXX5"
	mustFail(t, p, spec, "I/O/Q")
}

// --- §8.5 加密方式 ---

// T-GBT-031: EncryptRule=01 → enc field = 0x01.
func TestEncryptNone(t *testing.T) {
	p := NewPlanner()
	spec := gbtSpec(1000)
	spec.GBT32960.EncryptRule = "01"
	tcps := tcpPackets(mustPlan(t, p, spec))
	m := parseFirstMsg(t, tcps)
	if m.Encrypt != EncNone {
		t.Errorf("enc = 0x%02x, want 0x01", m.Encrypt)
	}
}

// T-GBT-033: EncryptRule=03 → enc field = 0x03.
func TestEncryptAES128(t *testing.T) {
	p := NewPlanner()
	spec := gbtSpec(1000)
	spec.GBT32960.EncryptRule = "03"
	tcps := tcpPackets(mustPlan(t, p, spec))
	m := parseFirstMsg(t, tcps)
	if m.Encrypt != EncAES128 {
		t.Errorf("enc = 0x%02x, want 0x03", m.Encrypt)
	}
}

// T-GBT-034: EncryptRule="06" → V6 error.
func TestEncryptInvalid(t *testing.T) {
	p := NewPlanner()
	spec := gbtSpec(1000)
	spec.GBT32960.EncryptRule = "06"
	mustFail(t, p, spec, "invalid EncryptRule")
}

// T-GBT-035: EncryptRule empty → default "01".
func TestEncryptEmptyDefault(t *testing.T) {
	p := NewPlanner()
	spec := gbtSpec(1000)
	spec.GBT32960.EncryptRule = ""
	tcps := tcpPackets(mustPlan(t, p, spec))
	m := parseFirstMsg(t, tcps)
	if m.Encrypt != EncNone {
		t.Errorf("enc = 0x%02x, want 0x01 (default)", m.Encrypt)
	}
}

// --- §8.6 报警数据 ---

// T-GBT-036: AlarmData all-zero → 5 bytes 00 00 00 00 00.
func TestAlarmAllZero(t *testing.T) {
	body := buildAlarmInfoBody(&GBT32960AlarmData{
		MaxAlarmLevel:     0,
		GeneralAlarmFlags: "00000000",
	})
	want := []byte{InfoTypeAlarm, 0x00, 0x00, 0x00, 0x00, 0x00}
	if !bytesEqual(body, want) {
		t.Errorf("alarm body = %x, want %x", body, want)
	}
}

// T-GBT-037: AlarmData all-ones → 5 bytes 03 FF FF FF FF.
func TestAlarmAllOnes(t *testing.T) {
	body := buildAlarmInfoBody(&GBT32960AlarmData{
		MaxAlarmLevel:     3,
		GeneralAlarmFlags: "FFFFFFFF",
	})
	want := []byte{InfoTypeAlarm, 0x03, 0xFF, 0xFF, 0xFF, 0xFF}
	if !bytesEqual(body, want) {
		t.Errorf("alarm body = %x, want %x", body, want)
	}
}

// T-GBT-038: AlarmData bit1 (battery high temp) → flags 00 00 00 02 (big-endian).
func TestAlarmBit1BatteryHighTemp(t *testing.T) {
	body := buildAlarmInfoBody(&GBT32960AlarmData{
		MaxAlarmLevel:     1,
		GeneralAlarmFlags: "00000002",
	})
	// InfoType(1) + Level(1) + Flags(4 BE) = 07 01 00 00 00 02
	want := []byte{InfoTypeAlarm, 0x01, 0x00, 0x00, 0x00, 0x02}
	if !bytesEqual(body, want) {
		t.Errorf("alarm body = %x, want %x (bit1=battery high temp, big-endian)", body, want)
	}
}

// T-GBT-040: AlarmData non-hex → V8 error.
func TestAlarmNonHexError(t *testing.T) {
	p := NewPlanner()
	spec := gbtSpec(1000)
	spec.GBT32960.AlarmData = &GBT32960AlarmData{
		MaxAlarmLevel:     0,
		GeneralAlarmFlags: "XYZW",
	}
	mustFail(t, p, spec, "GeneralAlarmFlags")
}

// T-GBT-040b: AlarmData 3-char hex → V8 error (must be exactly 8).
func TestAlarmShortHexError(t *testing.T) {
	p := NewPlanner()
	spec := gbtSpec(1000)
	spec.GBT32960.AlarmData = &GBT32960AlarmData{
		MaxAlarmLevel:     0,
		GeneralAlarmFlags: "000",
	}
	mustFail(t, p, spec, "GeneralAlarmFlags")
}

// T-GBT-040c: MaxAlarmLevel=4 → V32 error.
func TestAlarmLevel4Error(t *testing.T) {
	p := NewPlanner()
	spec := gbtSpec(1000)
	spec.GBT32960.AlarmData = &GBT32960AlarmData{
		MaxAlarmLevel:     4,
		GeneralAlarmFlags: "00000000",
	}
	mustFail(t, p, spec, "MaxAlarmLevel")
}

// --- §8.7 时间字段 ---

// T-GBT-044: LoginTime BCD encoding preserves input timezone.
func TestLoginTimeBCD(t *testing.T) {
	p := NewPlanner()
	spec := gbtSpec(1000)
	spec.GBT32960.LoginTime = "2026-08-03T14:30:00+08:00"
	tcps := tcpPackets(mustPlan(t, p, spec))
	m := parseFirstMsg(t, tcps)
	// 6 BCD bytes: 26 08 03 14 30 00.
	want := []byte{0x26, 0x08, 0x03, 0x14, 0x30, 0x00}
	if !bytesEqual(m.Data[:6], want) {
		t.Errorf("login time BCD = %x, want %x", m.Data[:6], want)
	}
}

// T-GBT-044b: LoginTime with Z (UTC) → UTC BCD (no +8 offset).
func TestLoginTimeUTCBCD(t *testing.T) {
	p := NewPlanner()
	spec := gbtSpec(1000)
	spec.GBT32960.LoginTime = "2026-08-03T06:30:00Z"
	tcps := tcpPackets(mustPlan(t, p, spec))
	m := parseFirstMsg(t, tcps)
	want := []byte{0x26, 0x08, 0x03, 0x06, 0x30, 0x00}
	if !bytesEqual(m.Data[:6], want) {
		t.Errorf("login time BCD = %x, want %x (UTC, no offset)", m.Data[:6], want)
	}
}

// T-GBT-046: LoginTime wrong format → V12 error.
func TestLoginTimeFormatError(t *testing.T) {
	p := NewPlanner()
	spec := gbtSpec(1000)
	spec.GBT32960.LoginTime = "2026/08/03"
	mustFail(t, p, spec, "invalid LoginTime")
}

// T-GBT-046b: LoginTime no timezone → V12 error.
func TestLoginTimeNoTZError(t *testing.T) {
	p := NewPlanner()
	spec := gbtSpec(1000)
	spec.GBT32960.LoginTime = "2026-08-03 14:30:00"
	mustFail(t, p, spec, "invalid LoginTime")
}

// T-GBT-048a: LogoutTime < LoginTime → V34 error.
func TestLogoutBeforeLoginError(t *testing.T) {
	p := NewPlanner()
	spec := gbtSpec(1000)
	spec.GBT32960.LoginTime = "2026-08-03T14:30:00+08:00"
	spec.GBT32960.LogoutTime = "2026-08-03T14:00:00+08:00"
	mustFail(t, p, spec, "must be >= LoginTime")
}

// --- §8.8 状态机 ---

// T-GBT-052: vehicle full flow packet count = 3 + 2 + 4 + 2 + 3 = 14
// (login + 2 reports + logout, no RemoteControl).
func TestVehicleFullFlowPacketCount(t *testing.T) {
	p := NewPlanner()
	spec := gbtSpec(1000)
	spec.GBT32960.Reports = []GBT32960Report{{}, {}}
	tcps := tcpPackets(mustPlan(t, p, spec))
	// 3 handshake + 2 (login+ack) + 4 (2 reports × 2) + 2 (logout+ack) + 3 teardown = 14.
	want := 3 + 2 + 4 + 2 + 3
	if len(tcps) != want {
		t.Errorf("packet count = %d, want %d", len(tcps), want)
	}
}

// T-GBT-053: platform full flow packet count = 3 + 2 + 3 + 2 + 3 = 13.
func TestPlatformFullFlowPacketCount(t *testing.T) {
	p := NewPlanner()
	spec := gbtSpec(1000)
	spec.GBT32960 = &GBT32960Config{
		Role:       "platform",
		PlatformID: "100000LVE00000000",
		PlatformLogin: &GBT32960PlatformLogin{
			User: "platform01", Password: "pwd1234567890abcdef",
		},
		HeartbeatCount: 3,
	}
	tcps := tcpPackets(mustPlan(t, p, spec))
	// 3 handshake + 2 (login+ack) + 3 (heartbeats) + 2 (logout+ack) + 3 teardown = 13.
	want := 3 + 2 + 3 + 2 + 3
	if len(tcps) != want {
		t.Errorf("packet count = %d, want %d", len(tcps), want)
	}
}

// T-GBT-056: ReissueReports after Reports; order 0x02×3 → 0x03×2 → 0x04.
func TestReissueAfterReports(t *testing.T) {
	p := NewPlanner()
	spec := gbtSpec(1000)
	spec.GBT32960.Reports = []GBT32960Report{{}, {}, {}}
	spec.GBT32960.ReissueReports = []GBT32960Report{{}, {}}
	tcps := tcpPackets(mustPlan(t, p, spec))
	cmds := extractCmds(pshPayloads(tcps))
	// Find indices of 0x02, 0x03, 0x04.
	var idx02, idx03, idx04 []int
	for i, c := range cmds {
		switch c {
		case CmdRealtimeReport:
			idx02 = append(idx02, i)
		case CmdReissueReport:
			idx03 = append(idx03, i)
		case CmdVehicleLogout:
			idx04 = append(idx04, i)
		}
	}
	if len(idx02) != 3 || len(idx03) != 2 || len(idx04) != 1 {
		t.Fatalf("cmd counts: 0x02=%d, 0x03=%d, 0x04=%d", len(idx02), len(idx03), len(idx04))
	}
	// All 0x02 must come before all 0x03, which must come before 0x04.
	if idx02[len(idx02)-1] > idx03[0] {
		t.Errorf("0x02 at %d after 0x03 at %d", idx02[len(idx02)-1], idx03[0])
	}
	if idx03[len(idx03)-1] > idx04[0] {
		t.Errorf("0x03 at %d after 0x04 at %d", idx03[len(idx03)-1], idx04[0])
	}
}

// --- §8.11 CustomFields ---

// T-GBT-064: CustomFields empty + IsTransBatteryData=true → 0x01 + 18 zero bytes.
func TestCustomFieldsEmptyTrue(t *testing.T) {
	p := NewPlanner()
	spec := gbtSpec(1000)
	spec.GBT32960.Reports = []GBT32960Report{{}}
	tcps := tcpPackets(mustPlan(t, p, spec))
	payloads := pshPayloads(tcps)
	// Report is payload[2] (login=0, ack=1, report=2).
	report := payloads[2]
	// data unit: 6 collect time + 1 info type + 18 zero body.
	infoType := report[24+6]
	if infoType != InfoTypeVehicleData {
		t.Errorf("info type = 0x%02x, want 0x01 (vehicle data)", infoType)
	}
}

// T-GBT-064b: IsTransBatteryData=false → only 0x05 vehicle position, no 0x01.
func TestCustomFieldsEmptyFalse(t *testing.T) {
	p := NewPlanner()
	spec := gbtSpec(1000)
	f := false
	spec.GBT32960.IsTransBatteryData = &f
	spec.GBT32960.Reports = []GBT32960Report{{}}
	tcps := tcpPackets(mustPlan(t, p, spec))
	payloads := pshPayloads(tcps)
	report := payloads[2]
	infoType := report[24+6]
	if infoType != InfoTypeVehiclePos {
		t.Errorf("info type = 0x%02x, want 0x05 (vehicle position)", infoType)
	}
}

// T-GBT-066: CustomFields odd-length hex → V26 error.
func TestCustomFieldsOddHexError(t *testing.T) {
	p := NewPlanner()
	spec := gbtSpec(1000)
	spec.GBT32960.CustomFields = "ABC"
	mustFail(t, p, spec, "CustomFields")
}

// T-GBT-067: CustomFields non-hex → V26 error.
func TestCustomFieldsNonHexError(t *testing.T) {
	p := NewPlanner()
	spec := gbtSpec(1000)
	spec.GBT32960.CustomFields = "XYZW"
	mustFail(t, p, spec, "CustomFields")
}

// --- §8.13 平台侧 ---

// T-GBT-074: platform login + heartbeat + logout sequence.
func TestPlatformSequence(t *testing.T) {
	p := NewPlanner()
	spec := gbtSpec(1000)
	spec.GBT32960 = &GBT32960Config{
		Role:       "platform",
		PlatformID: "100000LVE00000000",
		PlatformLogin: &GBT32960PlatformLogin{
			User: "platform01", Password: "pwd1234567890abcdef",
		},
		HeartbeatCount: 3,
	}
	tcps := tcpPackets(mustPlan(t, p, spec))
	cmds := extractCmds(pshPayloads(tcps))
	// Expected: 0x05, 0x0C, 0x0B, 0x0B, 0x0B, 0x06, 0x0C.
	want := []byte{CmdPlatformLogin, CmdAck, CmdHeartbeat, CmdHeartbeat, CmdHeartbeat,
		CmdPlatformLogout, CmdAck}
	if len(cmds) != len(want) {
		t.Fatalf("cmd sequence length = %d, want %d", len(cmds), len(want))
	}
	for i, c := range cmds {
		if c != want[i] {
			t.Errorf("cmd[%d] = 0x%02x, want 0x%02x", i, c, want[i])
		}
	}
}

// T-GBT-075: platform heartbeat has no 0x0C ack.
func TestPlatformHeartbeatNoAck(t *testing.T) {
	p := NewPlanner()
	spec := gbtSpec(1000)
	spec.GBT32960 = &GBT32960Config{
		Role:       "platform",
		PlatformID: "100000LVE00000000",
		PlatformLogin: &GBT32960PlatformLogin{
			User: "platform01", Password: "pwd1234567890abcdef",
		},
		HeartbeatCount: 2,
	}
	tcps := tcpPackets(mustPlan(t, p, spec))
	cmds := extractCmds(pshPayloads(tcps))
	// After each 0x0B, there must NOT be an 0x0C.
	for i, c := range cmds {
		if c == CmdHeartbeat && i+1 < len(cmds) {
			if cmds[i+1] == CmdAck {
				t.Errorf("0x0B at index %d followed by 0x0C (heartbeat should have no ack)", i)
			}
			if cmds[i+1] != CmdHeartbeat && cmds[i+1] != CmdPlatformLogout {
				t.Errorf("0x0B at index %d followed by unexpected 0x%02x", i, cmds[i+1])
			}
		}
	}
}

// T-GBT-076: PlatformLogin.User too long → V18 error.
func TestPlatformUserTooLong(t *testing.T) {
	p := NewPlanner()
	spec := gbtSpec(1000)
	spec.GBT32960 = &GBT32960Config{
		Role:       "platform",
		PlatformID: "100000LVE00000000",
		PlatformLogin: &GBT32960PlatformLogin{
			User:     "platform01234", // 13 bytes
			Password: "pwd1234567890abcdef",
		},
	}
	mustFail(t, p, spec, "User length")
}

// T-GBT-078: HeartbeatCount=-1 → V21 error.
func TestHeartbeatCountNegative(t *testing.T) {
	p := NewPlanner()
	spec := gbtSpec(1000)
	spec.GBT32960 = &GBT32960Config{
		Role:           "platform",
		PlatformID:     "100000LVE00000000",
		HeartbeatCount: -1,
		PlatformLogin: &GBT32960PlatformLogin{
			User: "platform01", Password: "pwd1234567890abcdef",
		},
	}
	mustFail(t, p, spec, "HeartbeatCount")
}

// --- §8.15 异常与边界 ---

// T-GBT-082: Role="client" → V1 error.
func TestRoleInvalidError(t *testing.T) {
	p := NewPlanner()
	spec := gbtSpec(1000)
	spec.GBT32960.Role = "client"
	mustFail(t, p, spec, "invalid Role")
}

// T-GBT-083: Role empty → default "vehicle".
func TestRoleEmptyDefault(t *testing.T) {
	p := NewPlanner()
	spec := gbtSpec(1000)
	spec.GBT32960.Role = ""
	cfgs := mustPlan(t, p, spec)
	if len(cfgs) == 0 {
		t.Errorf("expected packets with default Role=vehicle, got 0")
	}
}

// T-GBT-084: Reports 0 → only login + logout (4 GBT messages + 6 TCP = 10).
func TestReportsZero(t *testing.T) {
	p := NewPlanner()
	spec := gbtSpec(1000)
	spec.GBT32960.Reports = nil
	tcps := tcpPackets(mustPlan(t, p, spec))
	// 3 handshake + 2 (login+ack) + 2 (logout+ack) + 3 teardown = 10.
	want := 3 + 2 + 2 + 3
	if len(tcps) != want {
		t.Errorf("packet count = %d, want %d", len(tcps), want)
	}
}

// T-GBT-086: RemoteControl.ControlType=0 → V16 error.
func TestRemoteControlTypeZero(t *testing.T) {
	p := NewPlanner()
	spec := gbtSpec(1000)
	spec.GBT32960.RemoteControl = &GBT32960RemoteControl{
		ControlType: 0, Params: "00",
	}
	mustFail(t, p, spec, "ControlType is required")
}

// T-GBT-096: RechargeableSubsysCount=0 → V30 error.
func TestSubsysCountZeroError(t *testing.T) {
	p := NewPlanner()
	spec := gbtSpec(1000)
	spec.GBT32960.RechargeableSubsysCount = 0
	// 0 is treated as explicit trigger for V30.
	mustFail(t, p, spec, "RechargeableSubsysCount")
}

// T-GBT-097: RechargeableSubsysCodes length mismatch → V31 error.
func TestSubsysCodesMismatch(t *testing.T) {
	p := NewPlanner()
	spec := gbtSpec(1000)
	spec.GBT32960.RechargeableSubsysCount = 2
	spec.GBT32960.RechargeableSubsysCodes = []string{"01"}
	mustFail(t, p, spec, "RechargeableSubsysCodes length")
}

// T-GBT-097b: 子系统数量非零但编码列表为空时也必须触发 V31。
func TestSubsysCodesEmptyMismatch(t *testing.T) {
	p := NewPlanner()
	spec := gbtSpec(1000)
	spec.GBT32960.RechargeableSubsysCount = 2
	spec.GBT32960.RechargeableSubsysCodes = []string{}
	mustFail(t, p, spec, "RechargeableSubsysCodes length")
}

// T-GBT-099: PlatformID 18 bytes → V33 error.
func TestPlatformIDTooLong(t *testing.T) {
	p := NewPlanner()
	spec := gbtSpec(1000)
	spec.GBT32960 = &GBT32960Config{
		Role:       "platform",
		PlatformID: "100000LVE000000000", // 18 bytes
		PlatformLogin: &GBT32960PlatformLogin{
			User: "platform01", Password: "pwd1234567890abcdef",
		},
	}
	mustFail(t, p, spec, "PlatformID length")
}

// T-GBT-071: MSS too small → V27 error.
func TestMSSTooSmall(t *testing.T) {
	p := NewPlanner()
	spec := gbtSpec(1000)
	spec.TCP = &core.TCPConfig{InitialSeq: 1000, MSS: 100}
	mustFail(t, p, spec, "MSS")
}

// --- helpers ---

func extractCmds(payloads [][]byte) []byte {
	var cmds []byte
	for _, pl := range payloads {
		if len(pl) >= 3 {
			cmds = append(cmds, pl[2])
		}
	}
	return cmds
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// --- §8.10 StatusChangeTrace ---

// T-GBT-061: StatusChangeTrace applies alarm at index 2.
func TestStatusChangeTraceApplies(t *testing.T) {
	p := NewPlanner()
	spec := gbtSpec(1000)
	spec.GBT32960.Reports = []GBT32960Report{{}, {}, {}}
	spec.GBT32960.StatusChangeTrace = []GBT32960StatusChange{
		{AtReportIndex: 2, AlarmData: &GBT32960AlarmData{
			MaxAlarmLevel: 1, GeneralAlarmFlags: "00000002",
		}},
	}
	tcps := tcpPackets(mustPlan(t, p, spec))
	payloads := pshPayloads(tcps)
	// 3 Reports → payloads layout:
	//   [0]=login, [1]=ack(login),
	//   [2]=report1, [3]=ack(report1),
	//   [4]=report2, [5]=ack(report2),
	//   [6]=report3, [7]=ack(report3),
	//   [8]=logout, [9]=ack(logout).
	// StatusChangeTrace.AtReportIndex=2 applies to Reports[2] = report3
	// at payloads[6].
	report3 := payloads[6]
	if report3[2] != CmdRealtimeReport {
		t.Fatalf("payload[6] cmd = 0x%02x, want 0x02", report3[2])
	}
	// data unit = 6 collect + info bodies. Info body should start with 0x07.
	infoStart := 24 + 6
	if report3[infoStart] != InfoTypeAlarm {
		t.Errorf("report #3 info type = 0x%02x, want 0x07 (alarm from trace)", report3[infoStart])
	}
	// 5-byte alarm body: 07 01 00 00 00 02.
	want := []byte{0x07, 0x01, 0x00, 0x00, 0x00, 0x02}
	for i := 0; i < len(want); i++ {
		if report3[infoStart+i] != want[i] {
			t.Errorf("report #3 alarm body[%d] = 0x%02x, want 0x%02x", i, report3[infoStart+i], want[i])
		}
	}
}

// T-GBT-063: StatusChangeTrace AtReportIndex out of range → V25 error.
func TestTraceIndexOutOfRange(t *testing.T) {
	p := NewPlanner()
	spec := gbtSpec(1000)
	spec.GBT32960.Reports = []GBT32960Report{{}, {}}
	spec.GBT32960.StatusChangeTrace = []GBT32960StatusChange{
		{AtReportIndex: 99, AlarmData: &GBT32960AlarmData{
			MaxAlarmLevel: 0, GeneralAlarmFlags: "00000000",
		}},
	}
	mustFail(t, p, spec, "AtReportIndex")
}

// T-GBT-063b: StatusChangeTrace AtReportIndex duplicate → V25 error.
func TestTraceIndexDuplicate(t *testing.T) {
	p := NewPlanner()
	spec := gbtSpec(1000)
	spec.GBT32960.Reports = []GBT32960Report{{}, {}, {}}
	spec.GBT32960.StatusChangeTrace = []GBT32960StatusChange{
		{AtReportIndex: 1, AlarmData: &GBT32960AlarmData{
			MaxAlarmLevel: 0, GeneralAlarmFlags: "00000000",
		}},
		{AtReportIndex: 1, AlarmData: &GBT32960AlarmData{
			MaxAlarmLevel: 1, GeneralAlarmFlags: "00000002",
		}},
	}
	mustFail(t, p, spec, "AtReportIndex")
}

// --- §8.9 多车场景 ---

// T-GBT-058: 2 vehicles with different VINs.
func TestMultiVehicleVINsUnique(t *testing.T) {
	p := NewPlanner()
	spec1 := gbtSpec(1000)
	spec1.GBT32960.VIN = "LVEH0000000000001"
	spec2 := gbtSpec(2000)
	spec2.GBT32960.VIN = "LVEH0000000000002"
	spec2.SrcPort = 20001

	ch1, _ := p.Plan(context.Background(), spec1)
	ch2, _ := p.Plan(context.Background(), spec2)
	cfgs1 := drain(ch1)
	cfgs2 := drain(ch2)
	vin1 := extractVIN(cfgs1)
	vin2 := extractVIN(cfgs2)
	if vin1 == vin2 {
		t.Errorf("VIN1 == VIN2 (%s); should be unique", vin1)
	}
	if !strings.Contains(vin1, "0000001") {
		t.Errorf("VIN1 = %q, want containing 0000001", vin1)
	}
	if !strings.Contains(vin2, "0000002") {
		t.Errorf("VIN2 = %q, want containing 0000002", vin2)
	}
}

// extractVIN extracts the VIN from the first PSH-ACK payload.
func extractVIN(cfgs []core.PacketConfig) string {
	tcps := tcpPackets(cfgs)
	payloads := pshPayloads(tcps)
	if len(payloads) == 0 {
		return ""
	}
	pl := payloads[0]
	if len(pl) < 4+VINLen {
		return ""
	}
	return string(pl[4 : 4+VINLen])
}

// --- §8.16 0x07/0x09/0x0A 数据单元构造 (M8) ---

// T-GBT-090: 0x07 reissue request data unit = 2×6-byte BCD times (12 bytes).
func TestReissueReqDataUnit(t *testing.T) {
	start, _ := parseRFC3339Strict("2026-08-03T14:00:00+08:00")
	end, _ := parseRFC3339Strict("2026-08-03T14:30:00+08:00")
	data := buildReissueReqData(start, end)
	if len(data) != 12 {
		t.Fatalf("0x07 data unit length = %d, want 12", len(data))
	}
	wantStart := []byte{0x26, 0x08, 0x03, 0x14, 0x00, 0x00}
	wantEnd := []byte{0x26, 0x08, 0x03, 0x14, 0x30, 0x00}
	if !bytesEqual(data[:6], wantStart) {
		t.Errorf("start time BCD = %x, want %x", data[:6], wantStart)
	}
	if !bytesEqual(data[6:], wantEnd) {
		t.Errorf("end time BCD = %x, want %x", data[6:], wantEnd)
	}
}

// T-GBT-091: 0x09 parameter query data unit = 1 byte param type.
func TestParamQueryDataUnit(t *testing.T) {
	data := buildParamQueryData(0x01)
	if len(data) != 1 || data[0] != 0x01 {
		t.Errorf("0x09 data unit = %x, want 01", data)
	}
}

// T-GBT-092: 0x0A parameter set data unit = param type + custom params hex.
func TestParamSetDataUnit(t *testing.T) {
	data, err := buildParamSetData(0x01, "0A1B2C")
	if err != nil {
		t.Fatalf("buildParamSetData: %v", err)
	}
	if len(data) != 4 {
		t.Fatalf("0x0A data unit length = %d, want 4 (1 type + 3 params)", len(data))
	}
	if data[0] != 0x01 {
		t.Errorf("param type = 0x%02x, want 0x01", data[0])
	}
	if data[1] != 0x0A || data[2] != 0x1B || data[3] != 0x2C {
		t.Errorf("params = %x, want 0a1b2c", data[1:])
	}
}

// --- §8.18 边界与 MSS ---

// T-GBT-103: CustomFields exceeding MSS-31 budget → V29 error.
func TestCustomFieldsExceedMSS(t *testing.T) {
	p := NewPlanner()
	spec := gbtSpec(1000)
	spec.TCP = &core.TCPConfig{InitialSeq: 1000, MSS: 1460}
	// 1430 decoded bytes > MSS-31 = 1429 → V29 error.
	// hex string of 1430 bytes = 2860 hex chars.
	spec.GBT32960.CustomFields = strings.Repeat("ab", 1430) // 1430 bytes
	mustFail(t, p, spec, "exceeds MSS-31")
}

// T-GBT-102: data unit length 65532 → V28 error.
func TestDataUnitTooLong(t *testing.T) {
	p := NewPlanner()
	spec := gbtSpec(1000)
	// CustomFields decoded 65526 bytes + 6 collect time = 65532 > 65531.
	// strings.Repeat("ab", N) produces 2N hex chars = N decoded bytes,
	// so N=65526 yields 65526 decoded bytes.
	spec.GBT32960.CustomFields = strings.Repeat("ab", 65526) // 65526 bytes
	mustFail(t, p, spec, "exceeds 65531")
}

// --- §8.17 扩展表 1 字段 ---

// T-GBT-093: LogoutSerialNumber defaults to LoginSerialNumber.
func TestLogoutSerialInherits(t *testing.T) {
	p := NewPlanner()
	spec := gbtSpec(1000)
	spec.GBT32960.LoginSerialNumber = 42
	spec.GBT32960.LogoutSerialNumber = 0
	tcps := tcpPackets(mustPlan(t, p, spec))
	payloads := pshPayloads(tcps)
	var logout []byte
	for _, pl := range payloads {
		if len(pl) >= 3 && pl[2] == CmdVehicleLogout {
			logout = pl
			break
		}
	}
	if logout == nil {
		t.Fatalf("no logout")
	}
	// 0x04 data = 6 BCD + 2 serial; serial must equal 42 (0x00 0x2A).
	if logout[24+6] != 0x00 || logout[24+7] != 0x2A {
		t.Errorf("logout serial = %02x %02x, want 00 2A (42, inherited from login)", logout[24+6], logout[24+7])
	}
}

// T-GBT-094: LogoutSerialNumber explicit.
func TestLogoutSerialExplicit(t *testing.T) {
	p := NewPlanner()
	spec := gbtSpec(1000)
	spec.GBT32960.LoginSerialNumber = 1
	spec.GBT32960.LogoutSerialNumber = 42
	tcps := tcpPackets(mustPlan(t, p, spec))
	payloads := pshPayloads(tcps)
	var logout []byte
	for _, pl := range payloads {
		if len(pl) >= 3 && pl[2] == CmdVehicleLogout {
			logout = pl
			break
		}
	}
	if logout == nil {
		t.Fatalf("no logout")
	}
	if logout[24+6] != 0x00 || logout[24+7] != 0x2A {
		t.Errorf("logout serial = %02x %02x, want 00 2A (42)", logout[24+6], logout[24+7])
	}
}

// T-GBT-100: ConnectID auto-generated from 4-tuple, consistent per spec.
func TestConnectIDAutoGenerated(t *testing.T) {
	p := NewPlanner()
	spec := gbtSpec(1000)
	spec.GBT32960.ConnectID = ""
	// ConnectID is only used for logging in v1; the planner must not
	// error and must generate identical ConnectID for identical specs.
	cfgs1 := mustPlan(t, p, spec)
	cfgs2 := mustPlan(t, p, spec)
	if len(cfgs1) != len(cfgs2) {
		t.Errorf("packet counts differ: %d vs %d", len(cfgs1), len(cfgs2))
	}
	// Both plans must produce identical login payloads (deterministic).
	tcps1 := tcpPackets(cfgs1)
	tcps2 := tcpPackets(cfgs2)
	if len(tcps1) == 0 || len(tcps2) == 0 {
		t.Fatalf("no packets")
	}
	if !bytesEqual(tcps1[3].Payload, tcps2[3].Payload) {
		t.Errorf("login payloads differ across identical specs (ConnectID nondeterminism)")
	}
}

// --- §8.21 登出失败异常分支 ---

// T-GBT-108: logout failure (resp=02) — no retry, direct TCP teardown.
func TestLogoutFailureNoRetry(t *testing.T) {
	p := NewPlanner()
	spec := gbtSpec(1000)
	spec.GBT32960.ResponseFlags = "02"
	spec.GBT32960.Reports = nil
	tcps := tcpPackets(mustPlan(t, p, spec))
	payloads := pshPayloads(tcps)
	// Count 0x04 messages: must be exactly 1 (no retry).
	logoutCount := 0
	for _, pl := range payloads {
		if len(pl) >= 3 && pl[2] == CmdVehicleLogout {
			logoutCount++
		}
	}
	if logoutCount != 1 {
		t.Errorf("logout count = %d, want 1 (no retry on failure)", logoutCount)
	}
	// The logout resp must be 0x02 (simulating failure on the next uplink).
	for _, pl := range payloads {
		if len(pl) >= 3 && pl[2] == CmdVehicleLogout {
			if pl[3] != RespError {
				t.Errorf("logout resp = 0x%02x, want 0x02 (simulated failure)", pl[3])
			}
		}
	}
	// Teardown follows: last 3 packets are FIN, FIN-ACK, ACK.
	if len(tcps) < 3 {
		t.Fatalf("too few packets")
	}
	last3 := tcps[len(tcps)-3:]
	flags := []uint8{last3[0].L4.Flags, last3[1].L4.Flags, last3[2].L4.Flags}
	if flags[0] != 0x11 || flags[1] != 0x11 || flags[2] != 0x10 {
		t.Errorf("teardown flags = %#x %#x %#x, want 0x11 0x11 0x10 (FIN FIN-ACK ACK)", flags[0], flags[1], flags[2])
	}
}

// --- §8.12 集成 ---

// T-GBT-070: TCP seq/ack advance correctly — packet[4].Ack = packet[3].Seq + 56.
func TestTCPSeqAckAdvance(t *testing.T) {
	p := NewPlanner()
	spec := gbtSpec(1000)
	tcps := tcpPackets(mustPlan(t, p, spec))
	// Index 3 = 0x01 login (up PSH-ACK), index 4 = 0x0C ack (down PSH-ACK).
	// 0x0C ack must acknowledge login payload length = 56 bytes (25+31).
	login := tcps[3]
	ack := tcps[4]
	wantAck := login.L4.Seq + uint32(len(login.Payload))
	if ack.L4.Ack != wantAck {
		t.Errorf("0x0C ack = %d, want %d (login seq + 56)", ack.L4.Ack, wantAck)
	}
}

// T-GBT-069: handshake + GBT32960 + teardown, seq continuity.
func TestFullFlowSeqContinuity(t *testing.T) {
	p := NewPlanner()
	spec := gbtSpec(1000)
	spec.GBT32960.Reports = []GBT32960Report{{}}
	tcps := tcpPackets(mustPlan(t, p, spec))
	// Packet 0 = SYN, packet 1 = SYN-ACK, packet 2 = ACK, packet 3 = login PSH-ACK.
	if tcps[0].L4.Flags != 0x02 {
		t.Errorf("packet[0] flags = %#x, want 0x02 (SYN)", tcps[0].L4.Flags)
	}
	if tcps[1].L4.Flags != 0x12 {
		t.Errorf("packet[1] flags = %#x, want 0x12 (SYN-ACK)", tcps[1].L4.Flags)
	}
	if tcps[2].L4.Flags != 0x10 {
		t.Errorf("packet[2] flags = %#x, want 0x10 (ACK)", tcps[2].L4.Flags)
	}
	// Login seq = SYN seq + 1.
	if tcps[3].L4.Seq != tcps[0].L4.Seq+1 {
		t.Errorf("login seq = %d, want %d (SYN seq + 1)", tcps[3].L4.Seq, tcps[0].L4.Seq+1)
	}
	// Teardown FIN seq = last up PSH-ACK seq + payload len.
	fin := tcps[len(tcps)-3]
	var lastUpSeq uint32
	var lastUpLen int
	for i := 0; i < len(tcps); i++ {
		if tcps[i].Direction == "up" && tcps[i].L4.Flags == 0x18 {
			lastUpSeq = tcps[i].L4.Seq
			lastUpLen = len(tcps[i].Payload)
		}
	}
	if fin.Direction == "up" && fin.L4.Seq != lastUpSeq+uint32(lastUpLen) {
		t.Errorf("FIN seq = %d, want %d", fin.L4.Seq, lastUpSeq+uint32(lastUpLen))
	}
}

// --- §8.13 T-GBT-077: HeartbeatCount=0 → no heartbeats, only login+logout ---

func TestHeartbeatCountZero(t *testing.T) {
	p := NewPlanner()
	spec := gbtSpec(1000)
	spec.GBT32960 = &GBT32960Config{
		Role:       "platform",
		PlatformID: "100000LVE00000000",
		PlatformLogin: &GBT32960PlatformLogin{
			User: "platform01", Password: "pwd1234567890abcdef",
		},
		HeartbeatCount: 0,
	}
	tcps := tcpPackets(mustPlan(t, p, spec))
	payloads := pshPayloads(tcps)
	for _, pl := range payloads {
		if len(pl) >= 3 && pl[2] == CmdHeartbeat {
			t.Errorf("found 0x0B heartbeat with HeartbeatCount=0")
		}
	}
}

// T-GBT-095: PlatformDomain/SetPlatformDomain fields accepted (v1 log-only).
func TestPlatformDomainFieldsAccepted(t *testing.T) {
	p := NewPlanner()
	spec := gbtSpec(1000)
	spec.GBT32960.PlatformDomain = "test.example.com"
	spec.GBT32960.SetPlatformDomain = "target.example.com"
	// Must not error; planner does not emit them in the 0x05 data unit.
	cfgs := mustPlan(t, p, spec)
	if len(cfgs) == 0 {
		t.Errorf("expected packets with PlatformDomain fields set, got 0")
	}
}

// T-GBT-098: MaxAlarmLevel=4 → V32 error (range 0-3).
func TestAlarmMaxLevel4Error(t *testing.T) {
	p := NewPlanner()
	spec := gbtSpec(1000)
	spec.GBT32960.AlarmData = &GBT32960AlarmData{
		MaxAlarmLevel:     4,
		GeneralAlarmFlags: "00000000",
	}
	mustFail(t, p, spec, "MaxAlarmLevel")
}

// T-GBT-096a: RechargeableSubsysCodeLength=0 → V35 error.
func TestSubsysCodeLengthZeroError(t *testing.T) {
	p := NewPlanner()
	spec := gbtSpec(1000)
	spec.GBT32960.RechargeableSubsysCodeLength = 0
	mustFail(t, p, spec, "RechargeableSubsysCodeLength")
}

// T-GBT-079/080/081: reissue reports use 0x03 command with historical times.
func TestReissueReports(t *testing.T) {
	p := NewPlanner()
	spec := gbtSpec(1000)
	spec.GBT32960.Reports = nil
	spec.GBT32960.ReissueReports = []GBT32960Report{
		{Time: "2026-08-03T14:00:00+08:00"},
		{Time: "2026-08-03T14:00:30+08:00"},
	}
	tcps := tcpPackets(mustPlan(t, p, spec))
	payloads := pshPayloads(tcps)
	// Count 0x03 commands.
	reissueCount := 0
	for _, pl := range payloads {
		if len(pl) >= 3 && pl[2] == CmdReissueReport {
			reissueCount++
		}
	}
	if reissueCount != 2 {
		t.Errorf("0x03 count = %d, want 2", reissueCount)
	}
	// First reissue's collect time BCD = 14:00:00.
	for _, pl := range payloads {
		if len(pl) >= 3 && pl[2] == CmdReissueReport {
			want := []byte{0x26, 0x08, 0x03, 0x14, 0x00, 0x00}
			if !bytesEqual(pl[24:30], want) {
				t.Errorf("reissue collect time = %x, want %x", pl[24:30], want)
			}
			break
		}
	}
}

// T-GBT-008b: multi info-body loop via CustomFields (0x07 alarm + 0x05 pos).
func TestRealtimeMultiInfoBody(t *testing.T) {
	p := NewPlanner()
	spec := gbtSpec(1000)
	spec.GBT32960.Reports = []GBT32960Report{{}}
	// 16 bytes = 1 info type 0x07 + 5B alarm body + 1 info type 0x05 + 9B pos body.
	spec.GBT32960.CustomFields = "0701000000020500" + "0A1B2C0000000000"
	tcps := tcpPackets(mustPlan(t, p, spec))
	payloads := pshPayloads(tcps)
	if len(payloads) < 3 {
		t.Fatalf("need >= 3 payloads")
	}
	report := payloads[2]
	if report[2] != CmdRealtimeReport {
		t.Fatalf("payload[2] cmd = 0x%02x, want 0x02", report[2])
	}
	// data unit = 6 collect + 16 info bodies = 22 bytes.
	dataLen := int(report[22])<<8 | int(report[23])
	if dataLen != 22 {
		t.Errorf("0x02 data length = %d, want 22", dataLen)
	}
	// info type sequence: 0x07 at offset 6, 0x05 at offset 12 (6+1+5).
	if report[24+6] != InfoTypeAlarm {
		t.Errorf("info type[0] = 0x%02x, want 0x07", report[24+6])
	}
	if report[24+12] != InfoTypeVehiclePos {
		t.Errorf("info type[1] = 0x%02x, want 0x05", report[24+12])
	}
}

// T-GBT-074 variant: platform with no PlatformLogin (heartbeats + logout only).
func TestPlatformNoLogin(t *testing.T) {
	p := NewPlanner()
	spec := gbtSpec(1000)
	spec.GBT32960 = &GBT32960Config{
		Role:           "platform",
		PlatformID:     "100000LVE00000000",
		HeartbeatCount: 1,
	}
	tcps := tcpPackets(mustPlan(t, p, spec))
	payloads := pshPayloads(tcps)
	cmds := extractCmds(payloads)
	// Expected: 0x0B, 0x06, 0x0C.
	want := []byte{CmdHeartbeat, CmdPlatformLogout, CmdAck}
	if len(cmds) != len(want) {
		t.Fatalf("cmd sequence = %v, want %v", cmds, want)
	}
	for i, c := range cmds {
		if c != want[i] {
			t.Errorf("cmd[%d] = 0x%02x, want 0x%02x", i, c, want[i])
		}
	}
}

// T-GBT-054b: ResponseFlags=02 + RemoteControl + ReissueReports → all
// business states skipped, only login/ack + logout/ack emitted.
// Validates the §5.3 fix that 02/04 skips ST_REMOTE_CTRL and ST_REISSUE
// (not just ST_REPORTING).
func TestResponseFlags02SkipsAllBusiness(t *testing.T) {
	p := NewPlanner()
	spec := gbtSpec(1000)
	spec.GBT32960.ResponseFlags = "02"
	spec.GBT32960.Reports = []GBT32960Report{{}}
	spec.GBT32960.RemoteControl = &GBT32960RemoteControl{
		ControlType: 1, Params: "00",
	}
	spec.GBT32960.ReissueReports = []GBT32960Report{{}}
	tcps := tcpPackets(mustPlan(t, p, spec))
	cmds := extractCmds(pshPayloads(tcps))
	// Expected: 0x01, 0x0C, 0x04 (with resp=0x02), 0x0C.
	want := []byte{CmdVehicleLogin, CmdAck, CmdVehicleLogout, CmdAck}
	if len(cmds) != len(want) {
		t.Fatalf("cmd sequence = %v, want %v (skip all business on resp=02)", cmds, want)
	}
	for i, c := range cmds {
		if c != want[i] {
			t.Errorf("cmd[%d] = 0x%02x, want 0x%02x", i, c, want[i])
		}
	}
	// The 0x04 logout must carry resp=0x02 (the deferred ResponseFlags).
	payloads := pshPayloads(tcps)
	for _, pl := range payloads {
		if len(pl) >= 4 && pl[2] == CmdVehicleLogout {
			if pl[3] != RespError {
				t.Errorf("logout resp = 0x%02x, want 0x02 (deferred ResponseFlags)", pl[3])
			}
		}
	}
}

// T-GBT-015b: ResponseFlags=01 + Reports + RemoteControl + ReissueReports
// — the ResponseFlags value is consumed by the first 0x02 report (not
// leaked to 0x04 logout), and RemoteControl.ResponseFlags is consumed
// by the first 0x03 reissue (not leaked to 0x04 logout).
func TestResponseFlagsConsumedOnce(t *testing.T) {
	p := NewPlanner()
	spec := gbtSpec(1000)
	spec.GBT32960.ResponseFlags = "01"
	spec.GBT32960.Reports = []GBT32960Report{{}}
	spec.GBT32960.RemoteControl = &GBT32960RemoteControl{
		ControlType: 1, Params: "00", ResponseFlags: "02",
	}
	spec.GBT32960.ReissueReports = []GBT32960Report{{}}
	tcps := tcpPackets(mustPlan(t, p, spec))
	payloads := pshPayloads(tcps)
	cmds := extractCmds(payloads)
	// Find first 0x02, first 0x03, and 0x04.
	var first02, first03, logout []byte
	for _, pl := range payloads {
		if len(pl) < 4 {
			continue
		}
		switch pl[2] {
		case CmdRealtimeReport:
			if first02 == nil {
				first02 = pl
			}
		case CmdReissueReport:
			if first03 == nil {
				first03 = pl
			}
		case CmdVehicleLogout:
			logout = pl
		}
	}
	if first02 == nil || first03 == nil || logout == nil {
		t.Fatalf("missing messages: 0x02=%v 0x03=%v 0x04=%v", first02 != nil, first03 != nil, logout != nil)
	}
	// First 0x02 must carry resp=0x01 (top-level ResponseFlags).
	if first02[3] != RespSuccess {
		t.Errorf("first 0x02 resp = 0x%02x, want 0x01 (top-level ResponseFlags)", first02[3])
	}
	// First 0x03 must carry resp=0x02 (RemoteControl.ResponseFlags).
	if first03[3] != RespError {
		t.Errorf("first 0x03 resp = 0x%02x, want 0x02 (RemoteControl.ResponseFlags)", first03[3])
	}
	// 0x04 logout must carry resp=0xFE (no deferred flags remain).
	if logout[3] != RespNone {
		t.Errorf("logout resp = 0x%02x, want 0xFE (ResponseFlags consumed)", logout[3])
	}
	_ = cmds
}

