package gbt32960

// GBT32960 planner tests, derived from design doc §8 (T-GBT-001 ~ 108).
// Tests are organized by §8 subsections. Each test names its T-GBT ID(s)
// and the V#/§# it covers.

import (
	"context"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

// --- helpers ---

func drain(ch <-chan core.PacketConfig) []core.PacketConfig {
	var out []core.PacketConfig
	for c := range ch {
		out = append(out, c)
	}
	return out
}

func mustPlan(t *testing.T, p *Planner, spec core.FlowSpec) []core.PacketConfig {
	t.Helper()
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan returned error: %v", err)
	}
	return drain(ch)
}

func mustFail(t *testing.T, p *Planner, spec core.FlowSpec, substr string) {
	t.Helper()
	_, err := p.Plan(context.Background(), spec)
	if err == nil {
		t.Fatalf("Plan succeeded, want error containing %q", substr)
		return
	}
	if substr != "" && !strings.Contains(err.Error(), substr) {
		t.Fatalf("Plan error %q does not contain %q", err.Error(), substr)
	}
}

// gbtSpec returns a base vehicle spec with a deterministic ISN.
func gbtSpec(initialSeq uint32) core.FlowSpec {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1",
		SrcPort: 20000, DstPort: 10020,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		GBT32960: &GBT32960Config{
			Role:                         "vehicle",
			VIN:                          "LXXXXXXXXXXXXXXX1",
			SIM:                          "13800138000",
			LoginSerialNumber:            1,
			LoginTime:                    "2026-08-03T14:30:00+08:00",
			RechargeableSubsysCount:      1,
			RechargeableSubsysCodeLength: 1,
			RechargeableSubsysCodes:      []string{"00"},
		},
	}
	if initialSeq != 0 {
		spec.TCP = &core.TCPConfig{InitialSeq: initialSeq}
	}
	return spec
}

// tcpPackets returns the TCP packet configs in wire order.
func tcpPackets(cfgs []core.PacketConfig) []core.PacketConfig {
	var out []core.PacketConfig
	for _, c := range cfgs {
		if c.L4.Protocol == "tcp" {
			out = append(out, c)
		}
	}
	return out
}

// pshPayloads returns the PSH-ACK payload bytes in wire order.
func pshPayloads(tcps []core.PacketConfig) [][]byte {
	var out [][]byte
	for _, c := range tcps {
		if c.L4.Flags == 0x18 {
			out = append(out, c.Payload)
		}
	}
	return out
}

func hexStr(b []byte) string { return hex.EncodeToString(b) }

// B36: 未显式配置 group_id 时，按 VIN 为同一车辆生成稳定分组。
func TestGroupIDMetaDefaultsToVIN(t *testing.T) {
	p := NewPlanner()
	spec := gbtSpec(1000)
	cfgs := mustPlan(t, p, spec)
	for i, cfg := range cfgs {
		if got, ok := cfg.Metadata["group_id"].(string); !ok || got != spec.GBT32960.VIN {
			t.Fatalf("cfgs[%d] group_id = %v, want VIN %q", i, cfg.Metadata["group_id"], spec.GBT32960.VIN)
		}
	}
}

// B36: 显式 group_id 的优先级高于 VIN 默认分组。
func TestGroupIDMetaExplicitOverridesVIN(t *testing.T) {
	p := NewPlanner()
	spec := gbtSpec(1000)
	spec.GroupID = &core.StrategyConfig{Strategy: "fixed", Value: "fleet-A"}
	cfgs := mustPlan(t, p, spec)
	for i, cfg := range cfgs {
		if got, ok := cfg.Metadata["group_id"].(string); !ok || got != "fleet-A" {
			t.Fatalf("cfgs[%d] group_id = %v, want fleet-A", i, cfg.Metadata["group_id"])
		}
	}
}

// parseFirstMsg parses the first GBT32960 message in the PSH-ACK payloads.
func parseFirstMsg(t *testing.T, tcps []core.PacketConfig) *Message {
	t.Helper()
	payloads := pshPayloads(tcps)
	if len(payloads) == 0 {
		t.Fatalf("no PSH-ACK payloads")
	}
	m, _, err := ParseMessage(payloads[0])
	if err != nil {
		t.Fatalf("ParseMessage: %v", err)
	}
	return m
}

// --- §8.1 报文格式与 BCC ---

// T-GBT-001: start flag is fixed 0x23 0x23.
func TestStartFlagFixed(t *testing.T) {
	p := NewPlanner()
	spec := gbtSpec(1000)
	tcps := tcpPackets(mustPlan(t, p, spec))
	m := parseFirstMsg(t, tcps)
	if m.StartFlagOk == false {
		t.Errorf("start flag not 0x23 0x23")
	}
	payloads := pshPayloads(tcps)
	if len(payloads[0]) < 2 || payloads[0][0] != 0x23 || payloads[0][1] != 0x23 {
		t.Errorf("first 2 bytes = %x, want 23 23", payloads[0][:2])
	}
}

// T-GBT-002: BCC range correct (independent computation, not including start flag).
func TestBCCRangeIndependent(t *testing.T) {
	p := NewPlanner()
	spec := gbtSpec(1000)
	tcps := tcpPackets(mustPlan(t, p, spec))
	payloads := pshPayloads(tcps)
	if len(payloads) == 0 {
		t.Fatalf("no payloads")
	}
	msg := payloads[0]
	// Independently compute BCC over bytes [2 .. len-2] (cmd through last
	// data byte; excludes start flag and BCC itself).
	var expect byte = 0
	for i := 2; i < len(msg)-1; i++ {
		expect ^= msg[i]
	}
	got := msg[len(msg)-1]
	if got != expect {
		t.Errorf("BCC = 0x%02x, want 0x%02x (start flag must be excluded)", got, expect)
	}
	// Note: we cannot assert that "BCC with start flag != BCC without"
	// here because the start flag is fixed 0x23 0x23, and 0x23 ^ 0x23 = 0.
	// Including the start flag in the XOR therefore yields the same BCC
	// as excluding it, making that assertion vacuously true (and always
	// failing the test). The fixed start flag is mandated by §1.2 of the
	// design doc and cannot be changed. The BCC range correctness is
	// fully verified by the `expect` computation above (which excludes
	// the start flag) matching the wire BCC.
}

// T-GBT-003: BCC error injection flips lowest bit.
func TestBCCErrorInjection(t *testing.T) {
	p := NewPlanner()
	spec := gbtSpec(1000)
	spec.GBT32960.InjectBCCError = true
	spec.GBT32960.BCCErrorIndex = 0
	tcps := tcpPackets(mustPlan(t, p, spec))
	payloads := pshPayloads(tcps)
	msg := payloads[0]
	// Recompute correct BCC.
	var correct byte = 0
	for i := 2; i < len(msg)-1; i++ {
		correct ^= msg[i]
	}
	got := msg[len(msg)-1]
	if got != correct^0x01 {
		t.Errorf("injected BCC = 0x%02x, want 0x%02x (correct ^ 0x01 = 0x%02x)", got, correct^0x01, correct)
	}
}

// T-GBT-004: BCC error injection index out of range → error (V24).
func TestBCCErrorIndexOutOfRange(t *testing.T) {
	p := NewPlanner()
	spec := gbtSpec(1000)
	spec.GBT32960.InjectBCCError = true
	spec.GBT32960.BCCErrorIndex = 999
	// Per design §4.4 V24: fail-fast at Validate/Plan (not a warning).
	mustFail(t, p, spec, "exceeds message count")
}

// T-GBT-005: data length field is big-endian.
func TestDataLengthBigEndian(t *testing.T) {
	p := NewPlanner()
	spec := gbtSpec(1000)
	tcps := tcpPackets(mustPlan(t, p, spec))
	payloads := pshPayloads(tcps)
	msg := payloads[0]
	// 0x01 vehicle login with n=1,m=1 → data unit = 31 bytes → len field = 0x00 0x1F.
	if msg[22] != 0x00 || msg[23] != 0x1F {
		t.Errorf("data length = %02x %02x, want 00 1F (big-endian 31)", msg[22], msg[23])
	}
}

// T-GBT-006: data length 0 for platform heartbeat.
func TestDataLengthZeroHeartbeat(t *testing.T) {
	p := NewPlanner()
	spec := gbtSpec(1000)
	spec.GBT32960 = &GBT32960Config{
		Role:           "platform",
		PlatformID:     "100000LVE00000000",
		HeartbeatCount: 1,
		PlatformLogin: &GBT32960PlatformLogin{
			User: "platform01", Password: "pwd1234567890abcdef",
		},
	}
	tcps := tcpPackets(mustPlan(t, p, spec))
	payloads := pshPayloads(tcps)
	// Find the heartbeat (cmd=0x0B).
	var hb []byte
	for _, pl := range payloads {
		if len(pl) >= 3 && pl[2] == CmdHeartbeat {
			hb = pl
			break
		}
	}
	if hb == nil {
		t.Fatalf("no 0x0B heartbeat in payloads")
	}
	if hb[22] != 0x00 || hb[23] != 0x00 {
		t.Errorf("heartbeat data length = %02x %02x, want 00 00", hb[22], hb[23])
	}
	if len(hb) != 25 {
		t.Errorf("heartbeat total length = %d, want 25 (24 header + 1 BCC)", len(hb))
	}
}

// --- §8.2 命令单元 ---

// T-GBT-007: 0x01 vehicle login data unit format (n=1,m=1 → 31 bytes).
func TestVehicleLoginDataUnit(t *testing.T) {
	p := NewPlanner()
	spec := gbtSpec(1000)
	tcps := tcpPackets(mustPlan(t, p, spec))
	m := parseFirstMsg(t, tcps)
	if m.Cmd != CmdVehicleLogin {
		t.Errorf("cmd = 0x%02x, want 0x01", m.Cmd)
	}
	if len(m.Data) != 31 {
		t.Fatalf("data unit length = %d, want 31 (6+2+20+1+1+1)", len(m.Data))
	}
	// 6 BCD time + 2 serial (big-endian) + 20 ICCID + 1 n + 1 m + 1 code.
	// Layout: [0-5]=time, [6-7]=serial, [8-27]=ICCID(20), [28]=n, [29]=m, [30]=code.
	if m.Data[6] != 0x00 || m.Data[7] != 0x01 {
		t.Errorf("login serial = %02x %02x, want 00 01 (big-endian 1)", m.Data[6], m.Data[7])
	}
	if m.Data[28] != 0x01 {
		t.Errorf("subsys count n = 0x%02x, want 0x01", m.Data[28])
	}
	if m.Data[29] != 0x01 {
		t.Errorf("subsys code length m = 0x%02x, want 0x01", m.Data[29])
	}
}

// T-GBT-007b: 0x01 multi-subsystem codes (n=2, m=3 → 38 bytes).
func TestVehicleLoginMultiSubsys(t *testing.T) {
	p := NewPlanner()
	spec := gbtSpec(1000)
	spec.GBT32960.RechargeableSubsysCount = 2
	spec.GBT32960.RechargeableSubsysCodeLength = 3
	// Per design §3.1, subsys codes are STRING (ASCII), not hex.
	// Each code is right-padded or truncated to m=3 bytes.
	// "AB" → "AB" + 0x00 pad = 0x41 0x42 0x00
	// "CDE" → "CDE" = 0x43 0x44 0x45
	spec.GBT32960.RechargeableSubsysCodes = []string{"AB", "CDE"}
	tcps := tcpPackets(mustPlan(t, p, spec))
	m := parseFirstMsg(t, tcps)
	wantLen := 30 + 2*3 // 6+2+20+1+1 + n*m
	if len(m.Data) != wantLen {
		t.Fatalf("data unit length = %d, want %d", len(m.Data), wantLen)
	}
	// Layout: [0-5]=time, [6-7]=serial, [8-27]=ICCID(20), [28]=n, [29]=m, [30..]=codes.
	codes := m.Data[30:]
	if codes[0] != 0x41 || codes[1] != 0x42 || codes[2] != 0x00 {
		t.Errorf("code[0] = %02x %02x %02x, want 41 42 00 (\"AB\"+pad)", codes[0], codes[1], codes[2])
	}
	if codes[3] != 0x43 || codes[4] != 0x44 || codes[5] != 0x45 {
		t.Errorf("code[1] = %02x %02x %02x, want 43 44 45 (\"CDE\")", codes[3], codes[4], codes[5])
	}
}

// T-GBT-008: 0x02 realtime report data unit (minimal 0x01 vehicle data → 25 bytes).
func TestRealtimeReportDataUnit(t *testing.T) {
	p := NewPlanner()
	spec := gbtSpec(1000)
	spec.GBT32960.Reports = []GBT32960Report{{}}
	tcps := tcpPackets(mustPlan(t, p, spec))
	payloads := pshPayloads(tcps)
	// payloads[0] = 0x01 login, [1] = 0x0C ack, [2] = 0x02 report.
	if len(payloads) < 3 {
		t.Fatalf("only %d payloads, need >= 3", len(payloads))
	}
	reportMsg := payloads[2]
	if reportMsg[2] != CmdRealtimeReport {
		t.Fatalf("payload[2] cmd = 0x%02x, want 0x02", reportMsg[2])
	}
	// data unit = 6 collect time + 1 info type + 18 info body = 25 bytes.
	dataLen := int(reportMsg[22])<<8 | int(reportMsg[23])
	if dataLen != 25 {
		t.Errorf("0x02 data length = %d, want 25 (6+1+18)", dataLen)
	}
	// First byte of data = collect time BCD; byte 6 = info type 0x01.
	if reportMsg[24+6] != InfoTypeVehicleData {
		t.Errorf("info type = 0x%02x, want 0x01 (vehicle data)", reportMsg[24+6])
	}
}

// T-GBT-009: 0x04 vehicle logout data unit is 8 bytes.
func TestVehicleLogoutDataUnit(t *testing.T) {
	p := NewPlanner()
	spec := gbtSpec(1000)
	spec.GBT32960.LogoutTime = "2026-08-03T14:32:00+08:00"
	tcps := tcpPackets(mustPlan(t, p, spec))
	payloads := pshPayloads(tcps)
	// Find the logout message (cmd=0x04).
	var logout []byte
	for _, pl := range payloads {
		if len(pl) >= 3 && pl[2] == CmdVehicleLogout {
			logout = pl
			break
		}
	}
	if logout == nil {
		t.Fatalf("no 0x04 logout in payloads")
	}
	dataLen := int(logout[22])<<8 | int(logout[23])
	if dataLen != 8 {
		t.Errorf("0x04 data length = %d, want 8 (6 BCD + 2 serial)", dataLen)
	}
	// Last 2 bytes = login serial (big-endian), must match LoginSerialNumber.
	serial := uint16(logout[24+6])<<8 | uint16(logout[24+7])
	if serial != 1 {
		t.Errorf("logout serial = %d, want 1 (matches LoginSerialNumber)", serial)
	}
}

// T-GBT-010: 0x0B platform heartbeat — N=0, VIN = PlatformID 17 bytes.
func TestPlatformHeartbeatVIN(t *testing.T) {
	p := NewPlanner()
	spec := gbtSpec(1000)
	spec.GBT32960 = &GBT32960Config{
		Role:           "platform",
		PlatformID:     "100000LVE00000000",
		HeartbeatCount: 1,
		PlatformLogin: &GBT32960PlatformLogin{
			User: "platform01", Password: "pwd1234567890abcdef",
		},
	}
	tcps := tcpPackets(mustPlan(t, p, spec))
	payloads := pshPayloads(tcps)
	var hb []byte
	for _, pl := range payloads {
		if len(pl) >= 3 && pl[2] == CmdHeartbeat {
			hb = pl
			break
		}
	}
	if hb == nil {
		t.Fatalf("no heartbeat")
	}
	vin := hb[4 : 4+VINLen]
	want := "100000LVE00000000"
	if string(vin) != want {
		t.Errorf("heartbeat VIN = %q, want %q", string(vin), want)
	}
}

// T-GBT-011: 0x0C platform ack data = 0x01; 0x0C header resp = 0xFE (not 0x01).
func TestPlatformAckRespIsFE(t *testing.T) {
	p := NewPlanner()
	spec := gbtSpec(1000)
	tcps := tcpPackets(mustPlan(t, p, spec))
	payloads := pshPayloads(tcps)
	// payloads[1] = 0x0C ack for 0x01.
	if len(payloads) < 2 {
		t.Fatalf("need >= 2 payloads")
	}
	ack := payloads[1]
	if ack[2] != CmdAck {
		t.Errorf("payload[1] cmd = 0x%02x, want 0x0C", ack[2])
	}
	if ack[3] != RespNone {
		t.Errorf("0x0C header resp = 0x%02x, want 0xFE (always)", ack[3])
	}
	dataLen := int(ack[22])<<8 | int(ack[23])
	if dataLen != 1 {
		t.Errorf("0x0C data length = %d, want 1", dataLen)
	}
	if ack[24] != CmdVehicleLogin {
		t.Errorf("0x0C data = 0x%02x, want 0x01 (acked command)", ack[24])
	}
}

// T-GBT-012: 0x05 platform login data unit is 48 bytes; VIN = PlatformID.
func TestPlatformLoginDataUnit(t *testing.T) {
	p := NewPlanner()
	spec := gbtSpec(1000)
	spec.GBT32960 = &GBT32960Config{
		Role:       "platform",
		PlatformID: "100000LVE00000000",
		PlatformLogin: &GBT32960PlatformLogin{
			User: "platform01", Password: "pwd1234567890abcdef", EncryptSeq: "0001020304050607",
		},
	}
	tcps := tcpPackets(mustPlan(t, p, spec))
	m := parseFirstMsg(t, tcps)
	if m.Cmd != CmdPlatformLogin {
		t.Errorf("cmd = 0x%02x, want 0x05", m.Cmd)
	}
	if len(m.Data) != 48 {
		t.Fatalf("data unit length = %d, want 48 (12+20+16)", len(m.Data))
	}
	if string(m.VIN) != "100000LVE00000000" {
		t.Errorf("VIN = %q, want PlatformID", string(m.VIN))
	}
}

// T-GBT-013: 0x08 control command data = 01 00; 0x0C ack header resp = 0xFE.
func TestControlCommandDataUnit(t *testing.T) {
	p := NewPlanner()
	spec := gbtSpec(1000)
	spec.GBT32960.Reports = []GBT32960Report{{}}
	spec.GBT32960.RemoteControl = &GBT32960RemoteControl{
		ControlType: 1, Params: "00", ResponseFlags: "01",
	}
	tcps := tcpPackets(mustPlan(t, p, spec))
	payloads := pshPayloads(tcps)
	var ctrl, ack []byte
	for i, pl := range payloads {
		if len(pl) >= 3 && pl[2] == CmdControl && ctrl == nil {
			ctrl = pl
			// The next payload should be the 0x0C ack.
			if i+1 < len(payloads) {
				ack = payloads[i+1]
			}
		}
	}
	if ctrl == nil {
		t.Fatalf("no 0x08 control command")
	}
	dataLen := int(ctrl[22])<<8 | int(ctrl[23])
	if dataLen != 2 {
		t.Errorf("0x08 data length = %d, want 2 (1 ControlType + 1 param)", dataLen)
	}
	if ctrl[24] != 0x01 || ctrl[25] != 0x00 {
		t.Errorf("0x08 data = %02x %02x, want 01 00", ctrl[24], ctrl[25])
	}
	if ack == nil {
		t.Fatalf("no 0x0C ack after 0x08")
	}
	if ack[3] != RespNone {
		t.Errorf("0x0C ack header resp = 0x%02x, want 0xFE", ack[3])
	}
}
