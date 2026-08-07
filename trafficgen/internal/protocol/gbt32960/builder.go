package gbt32960

import (
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

// bccXOR computes BCC over buf, which MUST be the packet bytes from
// the command unit (offset 2) through the last data-unit byte
// (offset 24+N-1). buf MUST NOT include the start flag (offset 0-1)
// nor the BCC byte itself (design §2.4).
func bccXOR(buf []byte) byte {
	var sum byte = 0
	for _, b := range buf {
		sum ^= b
	}
	return sum
}

// buildMessage assembles a complete GBT32960 wire message (design §6.3):
//
//	start_flag(2B) | cmd(1B) | resp(1B) | VIN(17B) | enc(1B) |
//	data_len(2B BE) | data(N) | BCC(1B)
//
// BCC covers bytes [2 .. 24+N-1] (cmd through last data byte), i.e.
// buf[2:] of the start-flag-prefixed buffer. The start flag and the
// BCC byte itself are excluded.
func buildMessage(cmd, resp byte, vin []byte, enc byte, data []byte) []byte {
	if len(vin) != VINLen {
		// Defensive: callers are expected to pre-pad VIN to 17 bytes.
		padded := make([]byte, VINLen)
		copy(padded, vin)
		vin = padded
	}
	buf := make([]byte, 0, HeaderLen+BCCLen+len(data))
	buf = append(buf, StartFlag0, StartFlag1)                   // start flag (NOT in BCC range)
	buf = append(buf, cmd, resp)                                // command + response
	buf = append(buf, vin...)                                   // VIN (17 bytes)
	buf = append(buf, enc)                                      // encrypt rule
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(data))) // data length (BE)
	buf = append(buf, data...)                                  // data unit
	bcc := bccXOR(buf[2:])                                      // from cmd (offset 2) through last data byte
	buf = append(buf, bcc)
	return buf
}

// flipBCCBit flips the lowest bit of the BCC byte of a fully-built
// message (used for §7.15 data-integrity tests). The BCC byte is the
// last byte of msg.
func flipBCCBit(msg []byte) ([]byte, error) {
	if len(msg) < HeaderLen+BCCLen {
		return nil, fmt.Errorf("gbt32960: message too short (%d bytes) to flip BCC", len(msg))
	}
	out := make([]byte, len(msg))
	copy(out, msg)
	out[len(out)-1] ^= 0x01
	return out, nil
}

// encodeBCDTime encodes a time.Time as 6-byte BCD `YYMMDDHHMMSS` in
// the SAME timezone as the input (design §4.5). Year is truncated to
// 2 digits (2026 → 0x26). time.Time preserves the input location from
// RFC3339 parsing (time.Parse keeps the offset), so encoding uses the
// input timezone directly — no conversion is performed.
func encodeBCDTime(t time.Time) []byte {
	y := t.Year() % 100
	return []byte{
		decToBCD(y),
		decToBCD(int(t.Month())),
		decToBCD(t.Day()),
		decToBCD(t.Hour()),
		decToBCD(t.Minute()),
		decToBCD(t.Second()),
	}
}

// decToBCD converts an integer to its BCD byte (e.g. 26 → 0x26).
// Values outside 0-99 wrap (defensive; callers should validate ranges).
func decToBCD(v int) byte {
	v = v % 100
	if v < 0 {
		v += 100
	}
	return byte((v/10)<<4 | (v % 10))
}

// padASCII right-pads s with padByte to length n. If len(s) > n, s is
// truncated to n bytes (caller should validate upstream to avoid
// silent truncation — see V2/V5).
func padASCII(s string, n int, padByte byte) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = padByte
	}
	copy(out, []byte(s))
	return out
}

// encodeVIN encodes the VIN field to 17 bytes using padByte (default
// 0x00). Callers must validate VIN charset/length BEFORE calling this
// (see V2/V3/V3b/V4).
func encodeVIN(vin string, padByte byte) []byte {
	return padASCII(vin, VINLen, padByte)
}

// encodeSIM encodes the SIM/ICCID field to 20 bytes, right-padded
// with 0x00 (design §3.1).
func encodeSIM(sim string) []byte {
	return padASCII(sim, SIMLen, 0x00)
}

// encodeRechargeableSubsysCodes concatenates n subsystem codes, each
// right-padded or truncated to m bytes (design §3.1).
func encodeRechargeableSubsysCodes(codes []string, n, m int) []byte {
	out := make([]byte, 0, n*m)
	for i := 0; i < n; i++ {
		var code string
		if i < len(codes) {
			code = codes[i]
		}
		out = append(out, padASCII(code, m, 0x00)...)
	}
	return out
}

// buildLoginData builds the 0x01 vehicle login data unit (design §3.1):
//
//	login_time(6 BCD) | serial(2 BE) | ICCID(20) | n(1) | m(1) | codes(n*m)
func buildLoginData(loginTime time.Time, serial uint16, sim string, n, m int, codes []string) []byte {
	data := make([]byte, 0, LoginDataBase+n*m)
	data = append(data, encodeBCDTime(loginTime)...)
	data = binary.BigEndian.AppendUint16(data, serial)
	data = append(data, encodeSIM(sim)...)
	data = append(data, byte(n), byte(m))
	data = append(data, encodeRechargeableSubsysCodes(codes, n, m)...)
	return data
}

// buildLogoutData builds the 0x04 vehicle logout data unit (design §3.4):
//
//	logout_time(6 BCD) | login_serial(2 BE)
//
// Total 8 bytes. logoutSerial MUST equal the session's LoginSerialNumber.
func buildLogoutData(logoutTime time.Time, logoutSerial uint16) []byte {
	data := make([]byte, 0, LogoutDataLen)
	data = append(data, encodeBCDTime(logoutTime)...)
	data = binary.BigEndian.AppendUint16(data, logoutSerial)
	return data
}

// buildRealtimeData builds the 0x02/0x03 data unit (design §3.2):
//
//	collect_time(6 BCD) | (info_type(1) + info_body(L))*
//
// The info-body loop is provided by infoBodies (already-assembled bytes
// for the "info type + info body" repeated sequence). When infoBodies is
// empty, buildDefaultInfoBodies is used to emit a minimal valid body.
func buildRealtimeData(collectTime time.Time, infoBodies []byte) []byte {
	data := make([]byte, 0, RealtimeDataBase+len(infoBodies))
	data = append(data, encodeBCDTime(collectTime)...)
	data = append(data, infoBodies...)
	return data
}

// buildDefaultInfoBodies returns the minimal valid info-body loop when
// the user provides no CustomFields (design §3.2.3):
//   - IsTransBatteryData=true (default): info type 0x01 + 18 zero bytes
//   - IsTransBatteryData=false: info type 0x05 + 9 zero bytes
//
// When alarmData is non-nil, an info type 0x07 alarm body (5 bytes) is
// prepended.
func buildDefaultInfoBodies(isTransBattery bool, alarmData *GBT32960AlarmData) []byte {
	var out []byte
	if alarmData != nil {
		out = append(out, buildAlarmInfoBody(alarmData)...)
	}
	if isTransBattery {
		out = append(out, InfoTypeVehicleData)
		out = append(out, make([]byte, VehicleDataBodyLen)...)
	} else {
		out = append(out, InfoTypeVehiclePos)
		out = append(out, make([]byte, VehiclePosBodyLen)...)
	}
	return out
}

// buildAlarmInfoBody builds the info-type 0x07 alarm info body (5 bytes):
//
//	max_level(1) | general_flags(4 big-endian)
func buildAlarmInfoBody(a *GBT32960AlarmData) []byte {
	flags, _ := parseAlarmFlags(a.GeneralAlarmFlags)
	return []byte{
		InfoTypeAlarm,
		a.MaxAlarmLevel,
		byte(flags >> 24),
		byte(flags >> 16),
		byte(flags >> 8),
		byte(flags),
	}
}

// buildPlatformLoginData builds the 0x05 platform login data unit (design
// §3.5): user(12) | password(20) | encrypt_seq(16). Total 48 bytes.
func buildPlatformLoginData(pl *GBT32960PlatformLogin) []byte {
	data := make([]byte, 0, PlatformLoginDataLen)
	data = append(data, padASCII(pl.User, 12, 0x00)...)
	data = append(data, padASCII(pl.Password, 20, 0x00)...)
	data = append(data, padASCII(pl.EncryptSeq, 16, 0x00)...)
	return data
}

// buildControlData builds the 0x08 control command data unit (design §3.8):
//
//	control_type(1) | params(hex-decoded bytes)
func buildControlData(rc *GBT32960RemoteControl) ([]byte, error) {
	params, err := decodeHex(rc.Params)
	if err != nil {
		return nil, fmt.Errorf("gbt32960: RemoteControl.Params: %w", err)
	}
	data := make([]byte, 0, 1+len(params))
	data = append(data, rc.ControlType)
	data = append(data, params...)
	return data, nil
}

// buildAckData builds the 0x0C platform acknowledgement data unit
// (design §3.12): 1 byte = the command unit being acknowledged. The
// 0x0C header resp field is always 0xFE (set by the caller).
func buildAckData(ackedCmd byte) []byte {
	return []byte{ackedCmd}
}

// buildReissueReqData builds the 0x07 reissue request data unit
// (design §3.7): start_time(6 BCD) | end_time(6 BCD). Total 12 bytes.
func buildReissueReqData(start, end time.Time) []byte {
	data := make([]byte, 0, 12)
	data = append(data, encodeBCDTime(start)...)
	data = append(data, encodeBCDTime(end)...)
	return data
}

// buildParamQueryData builds the 0x09 parameter query data unit
// (design §3.9): param_type(1).
func buildParamQueryData(paramType byte) []byte {
	return []byte{paramType}
}

// buildParamSetData builds the 0x0A parameter set data unit (design §3.10):
//
//	param_type(1) | params(hex-decoded bytes)
func buildParamSetData(paramType byte, paramsHex string) ([]byte, error) {
	params, err := decodeHex(paramsHex)
	if err != nil {
		return nil, fmt.Errorf("gbt32960: ParamSet params: %w", err)
	}
	data := make([]byte, 0, 1+len(params))
	data = append(data, paramType)
	data = append(data, params...)
	return data, nil
}

// parseAlarmFlags parses the 8-hex-char GeneralAlarmFlags into a uint32
// (big-endian). Returns error if not exactly 8 hex chars or exceeds
// 32-bit range (V8/V9).
func parseAlarmFlags(s string) (uint32, error) {
	s = strings.TrimSpace(s)
	if len(s) != 8 {
		return 0, fmt.Errorf("gbt32960: invalid GeneralAlarmFlags %q (expect 8 hex chars)", s)
	}
	var v uint64
	for i := 0; i < 8; i++ {
		c := s[i]
		var d uint64
		switch {
		case c >= '0' && c <= '9':
			d = uint64(c - '0')
		case c >= 'a' && c <= 'f':
			d = uint64(c-'a') + 10
		case c >= 'A' && c <= 'F':
			d = uint64(c-'A') + 10
		default:
			return 0, fmt.Errorf("gbt32960: invalid GeneralAlarmFlags %q (non-hex char %q)", s, c)
		}
		v = (v << 4) | d
	}
	if v > 0xFFFFFFFF {
		return 0, fmt.Errorf("gbt32960: GeneralAlarmFlags %q exceeds 32-bit range", s)
	}
	return uint32(v), nil
}

// decodeHex decodes an even-length hex string into bytes.
// Returns error for odd-length or non-hex input (V26).
func decodeHex(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	if len(s)%2 != 0 {
		return nil, fmt.Errorf("gbt32960: invalid hex %q (odd length)", s)
	}
	out := make([]byte, len(s)/2)
	for i := 0; i < len(s); i += 2 {
		hi, ok1 := hexNibble(s[i])
		lo, ok2 := hexNibble(s[i+1])
		if !ok1 || !ok2 {
			return nil, fmt.Errorf("gbt32960: invalid hex %q (non-hex char at offset %d)", s, i)
		}
		out[i/2] = hi<<4 | lo
	}
	return out, nil
}

func hexNibble(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}
