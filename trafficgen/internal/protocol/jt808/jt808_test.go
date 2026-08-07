package jt808

import (
	"bytes"
	"context"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/protocol/jtcommon"
)

// mustPlan collects all PacketConfig from PlanWithConfig, failing on error.
func mustPlan(t *testing.T, spec core.FlowSpec, cfg *JT808Config) []core.PacketConfig {
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

// extractPayloads returns the L4 payload of every packet.
func extractPayloads(packets []core.PacketConfig) [][]byte {
	out := make([][]byte, 0, len(packets))
	for _, p := range packets {
		out = append(out, p.Payload)
	}
	return out
}

// TestRegisterSuccess (A-01) verifies 0x0100 register frame hex matches
// design §7A.14 byte-for-byte. Uses the reference config: Phone=012345678901,
// LicenseColor=1, LicensePlate="京A12345", Version=2011 (so MsgBodyProps
// matches the 0x002d in the design — Version=2019 would shift bits 10-12).
func TestRegisterSuccess(t *testing.T) {
	cfg := &JT808Config{
		Phone:          "012345678901",
		Version:        jtcommon.Version2011,
		LicenseColor:   LicenseColorBlue,
		LicensePlate:   "京A12345",
		ProvinceId:     11,
		CityId:         0,
		ManufacturerId: "TEST",
		TerminalModel:  "TG-DEMO",
		TerminalId:     "0000001",
		InitialSN:      1,
		Procedures:     []JT808Procedure{{Type: ProcRegister}},
	}
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 50000, DstPort: 7611}
	packets := mustPlan(t, spec, cfg)
	// Find the JT808 frame (payload starts with 0x7e, length > 14).
	var frame []byte
	for _, p := range packets {
		if len(p.Payload) > 0 && p.Payload[0] == jtcommon.FrameDelimiter {
			frame = p.Payload
			break
		}
	}
	if frame == nil {
		t.Fatalf("no JT808 frame emitted")
	}
	// Expected from design §7A.14 (Version=2011 → MsgBodyProps=0x002d):
	//   7e 0100 002d 012345678901 0001
	//   000b 0000 5445535400 54472d44454d4f+13*0x20 30303030303031
	//   01 bea9413132333435 XX 7e
	wantHex := "7e" + "0100" + "002d" + "012345678901" + "0001" +
		"000b" + "0000" + "5445535400" +
		"54472d44454d4f" + "20202020202020202020202020" + // 13 spaces (TG-DEMO is 7 chars, 20-7=13)
		"30303030303031" + "01" + "bea9413132333435"
	// Compute expected checksum: XOR of all bytes from MsgId to body end.
	headerAndBody := jtcommon.MustParseHex(
		"0100" + "002d" + "012345678901" + "0001" +
			"000b" + "0000" + "5445535400" +
			"54472d44454d4f" + "20202020202020202020202020" +
			"30303030303031" + "01" + "bea9413132333435")
	wantCS := jtcommon.XORChecksum(headerAndBody)
	wantHex += csHex(wantCS) + "7e"
	if !jtcommon.HexEqual(frame, wantHex) {
		t.Fatalf("register frame mismatch:\n want %s\n got  %s", wantHex, hexStr(frame))
	}
	// Parse it back.
	pf, err := ParseFrame(frame)
	if err != nil {
		t.Fatalf("ParseFrame error: %v", err)
	}
	if pf.MsgID != MsgTerminalRegister {
		t.Fatalf("MsgID = 0x%04x, want 0x%04x", pf.MsgID, MsgTerminalRegister)
	}
	if pf.MsgSN != 1 {
		t.Fatalf("MsgSN = %d, want 1", pf.MsgSN)
	}
	if pf.Phone != "012345678901" {
		t.Fatalf("Phone = %q, want 012345678901", pf.Phone)
	}
	if pf.BodyLen != 45 {
		t.Fatalf("BodyLen = %d, want 45", pf.BodyLen)
	}
	rb, err := ParseRegisterBody(pf.Body)
	if err != nil {
		t.Fatalf("ParseRegisterBody error: %v", err)
	}
	if rb.ProvinceId != 11 {
		t.Fatalf("ProvinceId = %d, want 11", rb.ProvinceId)
	}
	if rb.ManufacturerId != "TEST" {
		t.Fatalf("ManufacturerId = %q, want TEST", rb.ManufacturerId)
	}
	if rb.TerminalModel != "TG-DEMO" {
		t.Fatalf("TerminalModel = %q, want TG-DEMO", rb.TerminalModel)
	}
	if rb.TerminalId != "0000001" {
		t.Fatalf("TerminalId = %q, want 0000001", rb.TerminalId)
	}
	if rb.LicenseColor != LicenseColorBlue {
		t.Fatalf("LicenseColor = %d, want 1", rb.LicenseColor)
	}
	if rb.LicensePlate != "京A12345" {
		t.Fatalf("LicensePlate = %q, want 京A12345", rb.LicensePlate)
	}
}

// TestRegisterNoPlate (A-03) verifies LicenseColor=0 + LicensePlate=""
// produces a body without the plate field.
func TestRegisterNoPlate(t *testing.T) {
	cfg := &JT808Config{
		Phone:          "012345678901",
		Version:        jtcommon.Version2019,
		LicenseColor:   LicenseColorNone,
		ManufacturerId: "TEST",
		TerminalModel:  "TG-DEMO",
		TerminalId:     "0000001",
		InitialSN:      1,
		Procedures:     []JT808Procedure{{Type: ProcRegister}},
	}
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 50000, DstPort: 7611}
	packets := mustPlan(t, spec, cfg)
	for _, p := range packets {
		if len(p.Payload) > 0 && p.Payload[0] == jtcommon.FrameDelimiter {
			pf, err := ParseFrame(p.Payload)
			if err != nil {
				t.Fatalf("ParseFrame: %v", err)
			}
			// Body = 2+2+5+20+7+1 = 37 bytes (no plate).
			if pf.BodyLen != 37 {
				t.Fatalf("BodyLen = %d, want 37 (no plate)", pf.BodyLen)
			}
			rb, _ := ParseRegisterBody(pf.Body)
			if rb.LicenseColor != 0 {
				t.Fatalf("LicenseColor = %d, want 0", rb.LicenseColor)
			}
			if rb.LicensePlate != "" {
				t.Fatalf("LicensePlate = %q, want empty", rb.LicensePlate)
			}
			return
		}
	}
	t.Fatalf("no JT808 frame emitted")
}

// TestValidateBadPhone (A-31) rejects Phone != 12 digits.
func TestValidateBadPhone(t *testing.T) {
	cases := []string{"123", "12345678901", "1234567890123", "12ab56789012"}
	for _, phone := range cases {
		cfg := DefaultJT808Config()
		cfg.Phone = phone
		if err := ValidateConfig(cfg); err == nil {
			t.Fatalf("Phone %q expected rejection", phone)
		}
	}
}

// TestValidateBadVersion (A-32) rejects unknown version strings.
func TestValidateBadVersion(t *testing.T) {
	cfg := DefaultJT808Config()
	cfg.Version = "2099"
	if err := ValidateConfig(cfg); err == nil {
		t.Fatalf("Version=2099 expected rejection")
	}
}

// TestValidateColorPlateMismatch (A-33) rejects LicenseColor=0 + non-empty
// LicensePlate.
func TestValidateColorPlateMismatch(t *testing.T) {
	cfg := DefaultJT808Config()
	cfg.LicenseColor = LicenseColorNone
	cfg.LicensePlate = "京A12345"
	if err := ValidateConfig(cfg); err == nil {
		t.Fatalf("color/plate mismatch expected rejection")
	}
}

// TestValidateBadLicenseColor (A-44) rejects LicenseColor=6.
func TestValidateBadLicenseColor(t *testing.T) {
	cfg := DefaultJT808Config()
	cfg.LicenseColor = 6
	if err := ValidateConfig(cfg); err == nil {
		t.Fatalf("LicenseColor=6 expected rejection")
	}
}

// TestValidateBadDirection (A-45) rejects Direction >= 360.
func TestValidateBadDirection(t *testing.T) {
	cfg := DefaultJT808Config()
	cfg.Procedures = []JT808Procedure{{
		Type: ProcLocationReport,
		LocationData: &JT808Location{Direction: 360, Time: "240803120000"},
	}}
	if err := ValidateConfig(cfg); err == nil {
		t.Fatalf("Direction=360 expected rejection")
	}
}

// TestValidateBadLatitude (A-46) rejects Latitude > 90000000.
func TestValidateBadLatitude(t *testing.T) {
	cfg := DefaultJT808Config()
	cfg.Procedures = []JT808Procedure{{
		Type: ProcLocationReport,
		LocationData: &JT808Location{Latitude: 90000001, Time: "240803120000"},
	}}
	if err := ValidateConfig(cfg); err == nil {
		t.Fatalf("Latitude=90000001 expected rejection")
	}
}

// TestValidateBadTimeFormat (A-47) rejects Time != "YYMMDDhhmmss".
func TestValidateBadTimeFormat(t *testing.T) {
	// ValidateConfig does not check Time format; buildLocationBody does.
	// So this test exercises the builder path.
	loc := &JT808Location{Time: "24-08-03"}
	if _, err := buildLocationBody(loc); err == nil {
		t.Fatalf("Time=24-08-03 expected rejection in buildLocationBody")
	}
}

// TestACKFlagRejected (A-40) verifies ACKFlag=99 is rejected, ACKFlag=3
// (not supported) is accepted.
func TestACKFlagRejected(t *testing.T) {
	cfg := DefaultJT808Config()
	cfg.Procedures = []JT808Procedure{{
		Type:    ProcPlatformGeneralResponse,
		ACKFlag: 99,
	}}
	if err := ValidateConfig(cfg); err == nil {
		t.Fatalf("ACKFlag=99 expected rejection")
	}
	// ACKFlag=3 is valid.
	cfg.Procedures[0].ACKFlag = ACKNotSupported
	if err := ValidateConfig(cfg); err != nil {
		t.Fatalf("ACKFlag=3 expected acceptance, got %v", err)
	}
}

// TestVersionBits (A-34/A-35/A-36) verifies MsgBodyProps bit10-12 for
// 2011/2013/2019.
func TestVersionBits(t *testing.T) {
	cases := []struct {
		version string
		want    uint16
	}{
		{jtcommon.Version2011, 0x0000},
		{jtcommon.Version2013, 0x0400},
		{jtcommon.Version2019, 0x0800},
	}
	for _, tc := range cases {
		got, err := jtcommon.EncodeMsgBodyProps(0, tc.version, 0, 0)
		if err != nil {
			t.Fatalf("EncodeMsgBodyProps(%s): %v", tc.version, err)
		}
		if got != tc.want {
			t.Fatalf("Version=%s: props=0x%04x, want 0x%04x", tc.version, got, tc.want)
		}
	}
}

// TestEncryptFlagSet (A-37) verifies EncryptFlag=1 sets bit15 without
// altering the body bytes.
func TestEncryptFlagSet(t *testing.T) {
	loc := &JT808Location{
		AlarmFlag: 1, StatusFlag: 1,
		Latitude: 39900000, Longitude: 116400000,
		Altitude: 50, Speed: 600, Direction: 180,
		Time: "240803120000",
	}
	body, err := buildLocationBody(loc)
	if err != nil {
		t.Fatalf("buildLocationBody: %v", err)
	}
	propsPlain, _ := jtcommon.EncodeMsgBodyProps(len(body), jtcommon.Version2019, 0, 0)
	propsEnc, _ := jtcommon.EncodeMsgBodyProps(len(body), jtcommon.Version2019, 0, 1)
	if propsEnc&0x8000 != 0x8000 {
		t.Fatalf("EncryptFlag=1 did not set bit15: 0x%04x", propsEnc)
	}
	if propsPlain&0x8000 != 0 {
		t.Fatalf("EncryptFlag=0 unexpectedly set bit15: 0x%04x", propsPlain)
	}
	if propsEnc&0x7FFF != propsPlain&0x7FFF {
		t.Fatalf("encrypt flag altered lower 15 bits: plain=0x%04x enc=0x%04x", propsPlain, propsEnc)
	}
}

// TestEscapeInBody (A-23/A-24) verifies bytes 0x7e / 0x7d in the body are
// escaped on the wire.
func TestEscapeInBody(t *testing.T) {
	// AuthCode with 0x7e and 0x7d bytes: encode a body whose bytes include
	// those values. AuthCode is GBK-encoded; "AB~CD" has '~' = 0x7e (ASCII).
	cfg := &JT808Config{
		Phone:          "012345678901",
		Version:        jtcommon.Version2019,
		ManufacturerId: "TEST",
		TerminalModel:  "TG-DEMO",
		TerminalId:     "0000001",
		AuthCode:       "AB~CD", // contains 0x7e
		IMEI:           "012345678901234",
		SoftwareVersion: "TG-V1.0.0",
		InitialSN:      1,
		Procedures:     []JT808Procedure{{Type: ProcAuth}},
	}
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 50000, DstPort: 7611}
	packets := mustPlan(t, spec, cfg)
	for _, p := range packets {
		if len(p.Payload) > 0 && p.Payload[0] == jtcommon.FrameDelimiter {
			// Verify the wire bytes between delimiters contain 0x7d 0x02
			// (escaped 0x7e) and NOT a raw 0x7e (except the delimiters).
			inner := p.Payload[1 : len(p.Payload)-1]
			if bytes.Contains(inner, []byte{0x7e}) {
				t.Fatalf("raw 0x7e found in escaped body: %x", inner)
			}
			if !bytes.Contains(inner, []byte{0x7d, 0x02}) {
				t.Fatalf("escaped 0x7e (0x7d 0x02) not found: %x", inner)
			}
			// Parse and verify roundtrip.
			pf, err := ParseFrame(p.Payload)
			if err != nil {
				t.Fatalf("ParseFrame: %v", err)
			}
			if pf.MsgID != MsgTerminalAuth {
				t.Fatalf("MsgID = 0x%04x, want 0x0102", pf.MsgID)
			}
			return
		}
	}
	t.Fatalf("no JT808 frame emitted")
}

// TestXORChecksumRange (A-26/A-50) verifies the checksum includes the body.
// The 0x0100 register frame's checksum = XOR of all 57 bytes
// (12 header + 45 body).
func TestXORChecksumRange(t *testing.T) {
	cfg := &JT808Config{
		Phone:          "012345678901",
		Version:        jtcommon.Version2011,
		LicenseColor:   LicenseColorBlue,
		LicensePlate:   "京A12345",
		ProvinceId:     11,
		ManufacturerId: "TEST",
		TerminalModel:  "TG-DEMO",
		TerminalId:     "0000001",
		InitialSN:      1,
		Procedures:     []JT808Procedure{{Type: ProcRegister}},
	}
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 50000, DstPort: 7611}
	packets := mustPlan(t, spec, cfg)
	for _, p := range packets {
		if len(p.Payload) > 0 && p.Payload[0] == jtcommon.FrameDelimiter {
			pf, err := ParseFrame(p.Payload)
			if err != nil {
				t.Fatalf("ParseFrame: %v", err)
			}
			// Manually compute XOR of header+body (12 + 45 = 57 bytes).
			hdrAndBody := append([]byte{}, p.Payload[1:len(p.Payload)-1]...) // before unescape
			decoded, _ := jtcommon.Unescape(hdrAndBody)
			// Drop the checksum byte (last byte).
			decoded = decoded[:len(decoded)-1]
			expected := jtcommon.XORChecksum(decoded)
			if pf.Checksum != expected {
				t.Fatalf("checksum 0x%02x != expected 0x%02x", pf.Checksum, expected)
			}
			if len(decoded) != 57 {
				t.Fatalf("header+body length %d != 57", len(decoded))
			}
			return
		}
	}
}

// TestMsgSNWraparound (A-27) verifies SN wraps from 65534 → 65535 → 0 → 1.
func TestMsgSNWraparound(t *testing.T) {
	cfg := &JT808Config{
		Phone:          "012345678901",
		Version:        jtcommon.Version2019,
		LicenseColor:   LicenseColorBlue,
		LicensePlate:   "京A12345",
		ProvinceId:     11,
		ManufacturerId: "TEST",
		TerminalModel:  "TG-DEMO",
		TerminalId:     "0000001",
		InitialSN:      65534,
		Procedures: []JT808Procedure{
			{Type: ProcCancel},
			{Type: ProcCancel},
			{Type: ProcCancel},
			{Type: ProcCancel},
		},
	}
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 50000, DstPort: 7611}
	packets := mustPlan(t, spec, cfg)
	var sns []uint16
	for _, p := range packets {
		if len(p.Payload) > 0 && p.Payload[0] == jtcommon.FrameDelimiter {
			pf, err := ParseFrame(p.Payload)
			if err != nil {
				t.Fatalf("ParseFrame: %v", err)
			}
			if pf.MsgID == MsgTerminalCancel {
				sns = append(sns, pf.MsgSN)
			}
		}
	}
	want := []uint16{65534, 65535, 0, 1}
	if len(sns) != len(want) {
		t.Fatalf("got %d SNs, want %d", len(sns), len(want))
	}
	for i := range want {
		if sns[i] != want[i] {
			t.Fatalf("SN[%d] = %d, want %d", i, sns[i], want[i])
		}
	}
}

// TestLocationReportBasic (A-08) verifies 0x0200 hex matches design §7A.14.
func TestLocationReportBasic(t *testing.T) {
	cfg := &JT808Config{
		Phone:       "012345678901",
		Version:     jtcommon.Version2011,
		InitialSN:   3,
		Procedures: []JT808Procedure{{
			Type: ProcLocationReport,
			LocationData: &JT808Location{
				AlarmFlag:  1,
				StatusFlag: 1,
				Latitude:   39900000, // 39.9 deg (Beijing)
				Longitude:  116400000, // 116.4 deg
				Altitude:   50,
				Speed:      600,
				Direction:  180,
				Time:       "240803120000",
			},
		}},
	}
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 50000, DstPort: 7611}
	packets := mustPlan(t, spec, cfg)
	for _, p := range packets {
		if len(p.Payload) > 0 && p.Payload[0] == jtcommon.FrameDelimiter {
			pf, err := ParseFrame(p.Payload)
			if err != nil {
				t.Fatalf("ParseFrame: %v", err)
			}
			if pf.MsgID != MsgLocationReport {
				continue
			}
			if pf.MsgSN != 3 {
				t.Fatalf("MsgSN = %d, want 3", pf.MsgSN)
			}
			if pf.BodyLen != 28 {
				t.Fatalf("BodyLen = %d, want 28", pf.BodyLen)
			}
			lb, err := ParseLocationBody(pf.Body)
			if err != nil {
				t.Fatalf("ParseLocationBody: %v", err)
			}
			if lb.AlarmFlag != 1 {
				t.Fatalf("AlarmFlag = %d", lb.AlarmFlag)
			}
			if lb.Latitude != 39900000 {
				t.Fatalf("Latitude = %d", lb.Latitude)
			}
			if lb.Longitude != 116400000 {
				t.Fatalf("Longitude = %d", lb.Longitude)
			}
			if lb.Speed != 600 {
				t.Fatalf("Speed = %d", lb.Speed)
			}
			if lb.Direction != 180 {
				t.Fatalf("Direction = %d", lb.Direction)
			}
			if lb.Time != "240803120000" {
				t.Fatalf("Time = %q", lb.Time)
			}
			return
		}
	}
	t.Fatalf("no 0x0200 frame emitted")
}

// TestLocationReportWithExtras (A-11) verifies TLV extras are appended.
func TestLocationReportWithExtras(t *testing.T) {
	cfg := &JT808Config{
		Phone:     "012345678901",
		Version:   jtcommon.Version2019,
		InitialSN: 1,
		Procedures: []JT808Procedure{{
			Type: ProcLocationReport,
			LocationData: &JT808Location{
				Latitude:  39900000,
				Longitude: 116400000,
				Time:      "240803120000",
				ExtraItems: []JT808Extra{
					{Type: 0x01, Value: []byte{0x00, 0x01, 0x86, 0xA0}}, // mileage 100000m
					{Type: 0x02, Value: []byte{0x00, 0xC8}},             // fuel 200
				},
			},
		}},
	}
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 50000, DstPort: 7611}
	packets := mustPlan(t, spec, cfg)
	for _, p := range packets {
		if len(p.Payload) > 0 && p.Payload[0] == jtcommon.FrameDelimiter {
			pf, err := ParseFrame(p.Payload)
			if err != nil {
				t.Fatalf("ParseFrame: %v", err)
			}
			if pf.MsgID != MsgLocationReport {
				continue
			}
			lb, _ := ParseLocationBody(pf.Body)
			if len(lb.ExtraItems) != 2 {
				t.Fatalf("extras = %d, want 2", len(lb.ExtraItems))
			}
			if lb.ExtraItems[0].Type != 0x01 {
				t.Fatalf("extras[0].Type = 0x%02x", lb.ExtraItems[0].Type)
			}
			if !bytes.Equal(lb.ExtraItems[0].Value, []byte{0x00, 0x01, 0x86, 0xA0}) {
				t.Fatalf("extras[0].Value = %x", lb.ExtraItems[0].Value)
			}
			return
		}
	}
	t.Fatalf("no 0x0200 frame emitted")
}

// TestStatusFlagBitMerge (A-43) verifies ACC + DoorStatus OR-merge into
// StatusFlag: ACC=bit0, DoorStatus=bit1 → StatusFlag = 0x03.
func TestStatusFlagBitMerge(t *testing.T) {
	acc := true
	door := true
	loc := &JT808Location{
		StatusFlag: 0,
		ACC:        &acc,
		DoorStatus: &door,
		Time:       "240803120000",
	}
	body, err := buildLocationBody(loc)
	if err != nil {
		t.Fatalf("buildLocationBody: %v", err)
	}
	// StatusFlag is at body[4..7] (big-endian, after AlarmFlag at [0..3]).
	status := uint32(body[4])<<24 | uint32(body[5])<<16 | uint32(body[6])<<8 | uint32(body[7])
	if status != 0x00000003 {
		t.Fatalf("StatusFlag = 0x%08x, want 0x00000003", status)
	}
}

// TestFragmentedMessage (A-28a/A-28b) verifies a 1100-byte body is split
// into 2 fragments and the reassembled body matches the original.
func TestFragmentedMessage(t *testing.T) {
	body := make([]byte, 1100)
	for i := range body {
		body[i] = byte(i % 256)
	}
	phoneBCD, _ := jtcommon.BCDEncode("012345678901")
	props, _ := jtcommon.EncodeMsgBodyProps(0, jtcommon.Version2019, 0, 0)
	frames := buildFragmentedFrames(MsgTextDown, props, phoneBCD, 42, body, jtcommon.MaxBodyLength)
	if len(frames) != 2 {
		t.Fatalf("got %d frames, want 2", len(frames))
	}
	// Parse both frames and verify PackageNum/PackageTotal.
	var reassembled []byte
	for i, fr := range frames {
		pf, err := ParseFrame(fr)
		if err != nil {
			t.Fatalf("frame %d ParseFrame: %v", i, err)
		}
		if pf.PackageFlag != 1 {
			t.Fatalf("frame %d PackageFlag = %d, want 1", i, pf.PackageFlag)
		}
		if pf.PackageTotal != 2 {
			t.Fatalf("frame %d PackageTotal = %d, want 2", i, pf.PackageTotal)
		}
		if pf.PackageNum != uint16(i+1) {
			t.Fatalf("frame %d PackageNum = %d, want %d", i, pf.PackageNum, i+1)
		}
		if pf.MsgSN != 42 {
			t.Fatalf("frame %d MsgSN = %d, want 42 (shared)", i, pf.MsgSN)
		}
		reassembled = append(reassembled, pf.Body...)
	}
	if !bytes.Equal(reassembled, body) {
		t.Fatalf("reassembled body does not match original")
	}
}

// TestGeneralResponseDirection (A-52/A-53) verifies the two general
// response types map to the correct MsgId and direction.
func TestGeneralResponseDirection(t *testing.T) {
	cfg := &JT808Config{
		Phone:     "012345678901",
		Version:   jtcommon.Version2019,
		InitialSN: 1,
		Procedures: []JT808Procedure{
			{Type: ProcRegister},
			{Type: ProcPlatformGeneralResponse, ACKFlag: ACKSuccess, ResponseSN: 1, ResponseMsgId: MsgTerminalRegister},
			{Type: ProcTerminalGeneralResponse, ACKFlag: ACKSuccess, ResponseSN: 1, ResponseMsgId: MsgSetTerminalParams},
		},
	}
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 50000, DstPort: 7611}
	packets := mustPlan(t, spec, cfg)
	var saw8001, saw0001 bool
	for _, p := range packets {
		if len(p.Payload) > 0 && p.Payload[0] == jtcommon.FrameDelimiter {
			pf, err := ParseFrame(p.Payload)
			if err != nil {
				continue
			}
			if pf.MsgID == MsgPlatformGeneralResponse {
				saw8001 = true
			}
			if pf.MsgID == MsgTerminalGeneralResponse {
				saw0001 = true
			}
		}
	}
	if !saw8001 {
		t.Fatalf("0x8001 platform_general_response not emitted")
	}
	if !saw0001 {
		t.Fatalf("0x0001 terminal_general_response not emitted")
	}
}

// TestRegistrationResultValues (A-02/A-48) verifies Result 1-4 each
// produces a 3-byte body (no AuthCode).
func TestRegistrationResultValues(t *testing.T) {
	for _, result := range []uint8{1, 2, 3, 4} {
		body, err := buildRegistrationResponseBody(1, result, "")
		if err != nil {
			t.Fatalf("result %d: %v", result, err)
		}
		if len(body) != 3 {
			t.Fatalf("result %d: body length %d, want 3 (no AuthCode)", result, len(body))
		}
		rb, err := ParseRegistrationResponseBody(body)
		if err != nil {
			t.Fatalf("result %d parse: %v", result, err)
		}
		if rb.Result != result {
			t.Fatalf("result %d: parsed Result = %d", result, rb.Result)
		}
		if rb.AuthCode != "" {
			t.Fatalf("result %d: AuthCode = %q, want empty", result, rb.AuthCode)
		}
	}
}

// TestGeneralResponseResult23 (A-49) verifies Result 2/3 each produce a
// 5-byte body.
func TestGeneralResponseResult23(t *testing.T) {
	for _, result := range []uint8{2, 3} {
		body := buildGeneralResponseBody(1, MsgLocationReport, result)
		if len(body) != 5 {
			t.Fatalf("result %d: body length %d, want 5", result, len(body))
		}
		rb, err := ParseGeneralResponseBody(body)
		if err != nil {
			t.Fatalf("result %d parse: %v", result, err)
		}
		if rb.Result != result {
			t.Fatalf("result %d: parsed Result = %d", result, rb.Result)
		}
	}
}

// TestBCDPhoneEncoding (A-39) verifies Phone="000000000001" → 6 bytes
// 0x00 0x00 0x00 0x00 0x00 0x01 (big-endian BCD).
func TestBCDPhoneEncoding(t *testing.T) {
	b, err := jtcommon.BCDEncode("000000000001")
	if err != nil {
		t.Fatalf("BCDEncode: %v", err)
	}
	want := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x01}
	if !bytes.Equal(b, want) {
		t.Fatalf("BCD: want %x, got %x", want, b)
	}
}

// TestPlatformMsgSNIndependent (A-54/A-55) verifies the platform-side
// MsgSN counter starts at PlatformInitialSN and is independent of the
// terminal-side InitialSN.
func TestPlatformMsgSNIndependent(t *testing.T) {
	cfg := &JT808Config{
		Phone:            "012345678901",
		Version:          jtcommon.Version2019,
		InitialSN:        5,    // terminal-side starts at 5
		PlatformInitialSN: 0,   // platform-side starts at 0
		LicenseColor:     LicenseColorBlue,
		LicensePlate:     "京A12345",
		ProvinceId:       11,
		AuthCode:         "ABCDEF1234567890", // required for ProcAuth (design §7A.2 H-07)
		Procedures: []JT808Procedure{
			{Type: ProcRegister},                                                       // SN=5 (up)
			{Type: ProcPlatformGeneralResponse, ACKFlag: ACKSuccess, ResponseSN: 5, ResponseMsgId: MsgTerminalRegister}, // SN=0 (down)
			{Type: ProcAuth},                                                           // SN=6 (up)
			{Type: ProcPlatformGeneralResponse, ACKFlag: ACKSuccess, ResponseSN: 6, ResponseMsgId: MsgTerminalAuth},     // SN=1 (down)
		},
	}
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 50000, DstPort: 7611}
	packets := mustPlan(t, spec, cfg)
	var platformSNs []uint16
	for _, p := range packets {
		if len(p.Payload) > 0 && p.Payload[0] == jtcommon.FrameDelimiter {
			pf, err := ParseFrame(p.Payload)
			if err != nil {
				continue
			}
			if pf.MsgID == MsgPlatformGeneralResponse {
				platformSNs = append(platformSNs, pf.MsgSN)
			}
		}
	}
	want := []uint16{0, 1}
	if len(platformSNs) != len(want) {
		t.Fatalf("platform SNs = %v, want %v", platformSNs, want)
	}
	for i := range want {
		if platformSNs[i] != want[i] {
			t.Fatalf("platformSN[%d] = %d, want %d", i, platformSNs[i], want[i])
		}
	}
}

// TestFullLifecycleE2E (A-38) verifies register→auth→location×3→cancel
// produces all expected message types.
func TestFullLifecycleE2E(t *testing.T) {
	cfg := DefaultJT808Config()
	cfg.Procedures = []JT808Procedure{
		{Type: ProcRegister},
		{Type: ProcPlatformGeneralResponse, ACKFlag: ACKSuccess, ResponseMsgId: MsgTerminalRegister, ResponseSN: 0},
		{Type: ProcAuth},
		{Type: ProcPlatformGeneralResponse, ACKFlag: ACKSuccess, ResponseMsgId: MsgTerminalAuth, ResponseSN: 1},
		{Type: ProcLocationReport, LocationData: &JT808Location{Latitude: 39900000, Longitude: 116400000, Time: "240803120000"}},
		{Type: ProcLocationReport, LocationData: &JT808Location{Latitude: 39900001, Longitude: 116400001, Time: "240803120100"}},
		{Type: ProcLocationReport, LocationData: &JT808Location{Latitude: 39900002, Longitude: 116400002, Time: "240803120200"}},
		{Type: ProcCancel},
	}
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 50000, DstPort: 7611}
	packets := mustPlan(t, spec, cfg)
	wantMsgIDs := []uint16{
		MsgTerminalRegister,
		MsgPlatformGeneralResponse,
		MsgTerminalAuth,
		MsgPlatformGeneralResponse,
		MsgLocationReport,
		MsgLocationReport,
		MsgLocationReport,
		MsgTerminalCancel,
	}
	var gotMsgIDs []uint16
	for _, p := range packets {
		if len(p.Payload) > 0 && p.Payload[0] == jtcommon.FrameDelimiter {
			pf, err := ParseFrame(p.Payload)
			if err != nil {
				continue
			}
			gotMsgIDs = append(gotMsgIDs, pf.MsgID)
		}
	}
	if len(gotMsgIDs) != len(wantMsgIDs) {
		t.Fatalf("got %d messages, want %d (got IDs %v, want %v)", len(gotMsgIDs), len(wantMsgIDs), gotMsgIDs, wantMsgIDs)
	}
	for i := range wantMsgIDs {
		if gotMsgIDs[i] != wantMsgIDs[i] {
			t.Fatalf("msg[%d] = 0x%04x, want 0x%04x", i, gotMsgIDs[i], wantMsgIDs[i])
		}
	}
}

// TestFlowIDStable (A-56) verifies flowID is "jt808-{Phone}-{InitialSN}"
// and is set in Config phase (not dependent on src_port).
func TestFlowIDStable(t *testing.T) {
	cfg1 := DefaultJT808Config()
	cfg1.Phone = "012345678901"
	cfg1.InitialSN = 5
	cfg2 := DefaultJT808Config()
	cfg2.Phone = "012345678902"
	cfg2.InitialSN = 5
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 50000, DstPort: 7611}
	p1 := mustPlan(t, spec, cfg1)
	p2 := mustPlan(t, spec, cfg2)
	if len(p1) == 0 || len(p2) == 0 {
		t.Fatalf("no packets emitted")
	}
	if p1[0].FlowID == p2[0].FlowID {
		t.Fatalf("flowIDs should differ for different Phones: %s", p1[0].FlowID)
	}
	if p1[0].FlowID != "jt808-012345678901-5" {
		t.Fatalf("flowID = %q, want jt808-012345678901-5", p1[0].FlowID)
	}
}

// TestEscapeMsgBodyPropsLowByte7d (A-57) verifies that a MsgBodyProps
// with low byte 0x7d is escaped on the wire.
func TestEscapeMsgBodyPropsLowByte7d(t *testing.T) {
	// BodyLength=125 (0x7d), Version=2011 → props = 0x007d.
	body := make([]byte, 125)
	for i := range body {
		body[i] = 0xAA // avoid 0x7e/0x7d in body to isolate the test
	}
	phoneBCD, _ := jtcommon.BCDEncode("012345678901")
	props, err := jtcommon.EncodeMsgBodyProps(125, jtcommon.Version2011, 0, 0)
	if err != nil {
		t.Fatalf("EncodeMsgBodyProps: %v", err)
	}
	if props != 0x007d {
		t.Fatalf("props = 0x%04x, want 0x007d", props)
	}
	frame := buildSimpleFrame(MsgTerminalCancel, props, phoneBCD, 1, body)
	// The wire bytes must contain 0x7d 0x01 (escaped 0x7d) from props low byte.
	inner := frame[1 : len(frame)-1]
	if !bytes.Contains(inner, []byte{0x7d, 0x01}) {
		t.Fatalf("escaped 0x7d (0x7d 0x01) not found in wire: %x", inner)
	}
	// And must NOT contain a raw 0x7d followed by anything other than 0x01/0x02.
	// ParseFrame must succeed (proving unescape is consistent).
	pf, err := ParseFrame(frame)
	if err != nil {
		t.Fatalf("ParseFrame: %v", err)
	}
	if pf.MsgBodyProps != 0x007d {
		t.Fatalf("parsed props = 0x%04x, want 0x007d", pf.MsgBodyProps)
	}
}

// TestVersion2019BitsHex (A-59) verifies Version=2019 + BodyLength=5
// yields MsgBodyProps=0x0805 (hex bytes 08 05).
func TestVersion2019BitsHex(t *testing.T) {
	props, err := jtcommon.EncodeMsgBodyProps(5, jtcommon.Version2019, 0, 0)
	if err != nil {
		t.Fatalf("EncodeMsgBodyProps: %v", err)
	}
	if props != 0x0805 {
		t.Fatalf("props = 0x%04x, want 0x0805", props)
	}
}

// csHex returns the hex string of a single byte.
func csHex(b byte) string {
	const hexChars = "0123456789abcdef"
	return string([]byte{hexChars[b>>4], hexChars[b&0x0f]})
}

// hexStr returns the hex representation of a byte slice (no spaces).
func hexStr(b []byte) string {
	const hexChars = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, by := range b {
		out = append(out, hexChars[by>>4], hexChars[by&0x0f])
	}
	return string(out)
}
