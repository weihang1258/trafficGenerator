package jt808

import (
	"encoding/binary"
	"fmt"

	"github.com/trafficgen/trafficgen/internal/protocol/jtcommon"
)

// buildHeader constructs the JT808 message header (12 or 16 bytes).
// When packageFlag is true, the 4-byte PackageNum/PackageTotal is appended
// (design §3A.1, §3A.2).
//
// The returned header is the bytes BEFORE escape and BEFORE checksum —
// the caller must append the body, then XOR-checksum the whole
// (header+body), then escape, then wrap with 0x7e.
func buildHeader(msgID uint16, props uint16, phoneBCD []byte, msgSN uint16, packageFlag bool, pkgNum, pkgTotal uint16) []byte {
	h := make([]byte, 0, HeaderLenPkg)
	h = binary.BigEndian.AppendUint16(h, msgID)
	h = binary.BigEndian.AppendUint16(h, props)
	h = append(h, phoneBCD...)
	h = binary.BigEndian.AppendUint16(h, msgSN)
	if packageFlag {
		// JT/T 808 §5.4.2 消息体封装项：消息总包数 WORD(+12) 在前、包数据
		// 序号 WORD(+14) 在后（隔离复审 F1 勘误——legacy 发反序）。
		h = binary.BigEndian.AppendUint16(h, pkgTotal)
		h = binary.BigEndian.AppendUint16(h, pkgNum)
	}
	return h
}

// buildFrame assembles a complete JT808 frame from header+body bytes:
// computes the XOR checksum, appends it, escapes the whole, then wraps
// with 0x7e delimiters (design §3A.3, §3A.4).
//
// Input: headerAndBody = header (12 or 16B) + body (0..1023B), no checksum.
// Output: 0x7e + escaped(header+body+checksum) + 0x7e.
func buildFrame(headerAndBody []byte) []byte {
	cs := jtcommon.XORChecksum(headerAndBody)
	withCS := append(append([]byte{}, headerAndBody...), cs)
	escaped := jtcommon.Escape(withCS)
	out := make([]byte, 0, len(escaped)+2)
	out = append(out, jtcommon.FrameDelimiter)
	out = append(out, escaped...)
	out = append(out, jtcommon.FrameDelimiter)
	return out
}

// buildRegisterBody constructs the 0x0100 terminal registration body
// (design §4A.1, §7A.14):
//
//	ProvinceId(2 BE) + CityId(2 BE) + ManufacturerId(5 ASCII, 0x00-padded)
//	+ TerminalModel(20, 0x20-padded) + TerminalId(7, 0x00-padded)
//	+ LicenseColor(1) + LicensePlate(GBK, variable, no length prefix)
func buildRegisterBody(cfg *JT808Config) ([]byte, error) {
	if cfg == nil {
		return nil, fmt.Errorf("jt808: nil config")
	}
	body := make([]byte, 0, 2+2+5+20+7+1+8)
	body = binary.BigEndian.AppendUint16(body, cfg.ProvinceId)
	body = binary.BigEndian.AppendUint16(body, cfg.CityId)
	mid := jtcommon.PadRightZeroASCII(cfg.ManufacturerId, ManufacturerIDLen)
	body = append(body, mid...)
	tm := jtcommon.PadRightSpace(cfg.TerminalModel, TerminalModelLen)
	body = append(body, tm...)
	tid := jtcommon.PadRightZeroASCII(cfg.TerminalId, TerminalIDLen)
	body = append(body, tid...)
	body = append(body, cfg.LicenseColor)
	if cfg.LicenseColor != LicenseColorNone {
		plate, err := jtcommon.GBKEncode(cfg.LicensePlate)
		if err != nil {
			return nil, fmt.Errorf("jt808: LicensePlate GBK encode: %w", err)
		}
		body = append(body, plate...)
	}
	return body, nil
}

// buildAuthBody constructs the 0x0102 terminal authentication body
// (design §4A.2):
//
//	AuthCode(variable GBK, 1-16B) + IMEI(15 ASCII) + SoftwareVersion(20B)
func buildAuthBody(cfg *JT808Config, authCode, imei, sw string) ([]byte, error) {
	auth, err := jtcommon.GBKEncode(authCode)
	if err != nil {
		return nil, fmt.Errorf("jt808: AuthCode GBK encode: %w", err)
	}
	if len(auth) == 0 {
		return nil, fmt.Errorf("jt808: AuthCode is empty (design §5A.1 H-07)")
	}
	if len(auth) > AuthCodeMaxLen {
		return nil, fmt.Errorf("jt808: AuthCode GBK length %d > %d", len(auth), AuthCodeMaxLen)
	}
	body := make([]byte, 0, len(auth)+IMEILen+SoftwareVersionLen)
	body = append(body, auth...)
	if len(imei) > IMEILen {
		imei = imei[:IMEILen]
	}
	imeiBytes := jtcommon.PadRightZeroASCII(imei, IMEILen)
	body = append(body, imeiBytes...)
	if len(sw) > SoftwareVersionLen {
		sw = sw[:SoftwareVersionLen]
	}
	swBytes := jtcommon.PadRightZeroASCII(sw, SoftwareVersionLen)
	body = append(body, swBytes...)
	return body, nil
}

// buildLocationBody constructs the 0x0200 location body (design §4A.3).
// It applies the bit-level convenience fields (ACC/DoorStatus/OilCircuit/
// RunStatus) by OR-merging them into StatusFlag before encoding.
func buildLocationBody(loc *JT808Location) ([]byte, error) {
	return BuildLocationBody(loc)
}

// BuildLocationBody is the exported wrapper around buildLocationBody,
// exposed so the jt809 package can reuse the identical 0x0200 body layout
// for its 0x1202 realtime-location SubBody (design §4B.5, §11.3 — package
// reuse, no implementation drift).
func BuildLocationBody(loc *JT808Location) ([]byte, error) {
	if loc == nil {
		return nil, fmt.Errorf("jt808: nil LocationData")
	}
	status := loc.StatusFlag
	if loc.ACC != nil && *loc.ACC {
		status |= 0x00000001
	}
	if loc.RunStatus != nil && *loc.RunStatus {
		status |= 0x00000001
	}
	if loc.DoorStatus != nil && *loc.DoorStatus {
		status |= 0x00000002
	}
	if loc.OilCircuit != nil && *loc.OilCircuit {
		status |= 0x00000004
	}
	timeBCD, err := jtcommon.EncodeTimeBCD(loc.Time)
	if err != nil {
		return nil, fmt.Errorf("jt808: Time BCD: %w", err)
	}
	body := make([]byte, 0, 28)
	body = binary.BigEndian.AppendUint32(body, loc.AlarmFlag)
	body = binary.BigEndian.AppendUint32(body, status)
	body = binary.BigEndian.AppendUint32(body, loc.Latitude)
	body = binary.BigEndian.AppendUint32(body, loc.Longitude)
	body = binary.BigEndian.AppendUint16(body, loc.Altitude)
	body = binary.BigEndian.AppendUint16(body, loc.Speed)
	body = binary.BigEndian.AppendUint16(body, loc.Direction)
	body = append(body, timeBCD...)
	for _, ex := range loc.ExtraItems {
		body = append(body, ex.Type)
		body = append(body, byte(len(ex.Value)))
		body = append(body, ex.Value...)
	}
	return body, nil
}

// buildGeneralResponseBody constructs the 0x8001 / 0x0001 general response
// body (design §4A.7): ResponseSN(2) + ResponseMsgId(2) + Result(1).
// Phone is NOT included (it's in the header).
func buildGeneralResponseBody(responseSN, responseMsgID uint16, result uint8) []byte {
	body := make([]byte, 0, GeneralResponseLen)
	body = binary.BigEndian.AppendUint16(body, responseSN)
	body = binary.BigEndian.AppendUint16(body, responseMsgID)
	body = append(body, result)
	return body
}

// buildRegistrationResponseBody constructs the 0x8100 registration
// response body (design §4A.8):
//
//	ResponseSN(2) + Result(1) [+ AuthCode(variable GBK) when result=0]
func buildRegistrationResponseBody(responseSN uint16, result uint8, authCode string) ([]byte, error) {
	body := make([]byte, 0, 3+AuthCodeMaxLen)
	body = binary.BigEndian.AppendUint16(body, responseSN)
	body = append(body, result)
	if result == RegResultSuccess {
		auth, err := jtcommon.GBKEncode(authCode)
		if err != nil {
			return nil, fmt.Errorf("jt808: AuthCode GBK: %w", err)
		}
		if len(auth) > AuthCodeMaxLen {
			return nil, fmt.Errorf("jt808: AuthCode GBK length %d > %d", len(auth), AuthCodeMaxLen)
		}
		body = append(body, auth...)
	}
	return body, nil
}

// buildLocationQueryResponseBody constructs the 0x0201 location query
// response body (design §4A.4):
//
//	QuerySN(2 BE) + LocationBody (same as 0x0200)
func buildLocationQueryResponseBody(querySN uint16, loc *JT808Location) ([]byte, error) {
	locBody, err := buildLocationBody(loc)
	if err != nil {
		return nil, err
	}
	body := make([]byte, 0, 2+len(locBody))
	body = binary.BigEndian.AppendUint16(body, querySN)
	body = append(body, locBody...)
	return body, nil
}

// buildPropertyResponseBody constructs the 0x0107 terminal property
// response body (design §4A.6, 17 fields).
func buildPropertyResponseBody(p *JT808Property) ([]byte, error) {
	if p == nil {
		return nil, fmt.Errorf("jt808: nil PropertyData")
	}
	body := make([]byte, 0, 64)
	body = append(body, p.DeviceType)
	body = append(body, jtcommon.PadRightZeroASCII(p.ManufacturerId, ManufacturerIDLen)...)
	body = append(body, jtcommon.PadRightSpace(p.TerminalModel, TerminalModelLen)...)
	body = append(body, jtcommon.PadRightZeroASCII(p.TerminalId, TerminalIDLen)...)
	body = append(body, jtcommon.PadRightZeroASCII(p.IccId, 10)...)
	body = append(body, jtcommon.PadRightZeroASCII(p.Imei, IMEILen)...)
	body = append(body, jtcommon.PadRightZeroASCII(p.SoftwareVersion, SoftwareVersionLen)...)
	body = append(body, p.GnssModule)
	body = append(body, p.CommModule)
	body = binary.BigEndian.AppendUint16(body, p.ProvinceId)
	body = binary.BigEndian.AppendUint16(body, p.CityId)
	body = binary.BigEndian.AppendUint16(body, p.CountyId)
	body = binary.BigEndian.AppendUint16(body, p.TownId)
	body = append(body, p.Operator)
	apn, err := jtcommon.GBKEncode(p.APN)
	if err != nil {
		return nil, fmt.Errorf("jt808: APN GBK: %w", err)
	}
	if len(apn) > 32 {
		apn = apn[:32] // design §8A A-17e: truncate with warning
	}
	body = append(body, apn...)
	hwv, err := jtcommon.GBKEncode(p.HardwareVersion)
	if err != nil {
		return nil, fmt.Errorf("jt808: HardwareVersion GBK: %w", err)
	}
	body = append(body, hwv...)
	body = binary.BigEndian.AppendUint16(body, p.MaxSpeed)
	return body, nil
}

// buildSetParamsBody constructs the 0x8103 set-params body（JT/T 808 §7.9：
// 消息体=参数总数 BYTE + Σ[参数ID DWORD + 参数长度 BYTE + 参数值]；
// 隔离复审 F2 勘误——legacy 缺总数前导且 ID 线上 1 字节）.
func buildSetParamsBody(params []JT808Param) ([]byte, error) {
	if len(params) > 255 {
		return nil, fmt.Errorf("jt808: too many params %d (total byte is uint8)", len(params))
	}
	body := make([]byte, 0, 1+len(params)*8)
	body = append(body, byte(len(params)))
	for _, p := range params {
		body = binary.BigEndian.AppendUint32(body, p.Id)
		body = append(body, byte(len(p.Value)))
		if len(p.Value) > 255 {
			return nil, fmt.Errorf("jt808: param 0x%x value %d bytes > 255 (length byte is uint8)", p.Id, len(p.Value))
		}
		body = append(body, p.Value...)
	}
	return body, nil
}

// buildTextDownBody constructs the 0x8300 text-down body (design §4A.9):
//
//	TextFlag(1) + Text(GBK, variable)
//
// When the encoded text exceeds MaxBodyLength-1, it is truncated and the
// caller is responsible for logging a warning (design §8A A-22).
func buildTextDownBody(textFlag uint8, text string) ([]byte, error) {
	enc, err := jtcommon.GBKEncode(text)
	if err != nil {
		return nil, fmt.Errorf("jt808: Text GBK: %w", err)
	}
	maxTextLen := jtcommon.MaxBodyLength - 1
	if len(enc) > maxTextLen {
		enc = enc[:maxTextLen]
	}
	body := make([]byte, 0, 1+len(enc))
	body = append(body, textFlag)
	body = append(body, enc...)
	return body, nil
}

// buildFragmentedFrames splits an over-long body into multiple JT808 frames
// (design §3A.2 bit14=1, §7A.12 (e)). Each fragment carries 4 bytes of
// package info (PackageNum + PackageTotal) after the standard 12-byte
// header. All fragments share the same MsgSN (design §3A.2 M-07). Each
// fragment's checksum is computed independently (including the package
// info bytes).
//
// The baseProps passed in carries the version + encrypt flag bits; the
// body-length field (low 10 bits) is recomputed per-fragment from the
// chunk length, and the package flag (bit 14) is forced to 1.
//
// maxBodyLen is the per-fragment body limit (typically jtcommon.MaxBodyLength).
// Returns one frame per fragment, each wrapped with 0x7e delimiters.
func buildFragmentedFrames(msgID uint16, baseProps uint16, phoneBCD []byte, msgSN uint16, body []byte, maxBodyLen int) [][]byte {
	if maxBodyLen <= 0 {
		maxBodyLen = jtcommon.MaxBodyLength
	}
	total := (len(body) + maxBodyLen - 1) / maxBodyLen
	if total == 0 {
		total = 1
	}
	frames := make([][]byte, 0, total)
	for i := 0; i < total; i++ {
		start := i * maxBodyLen
		end := start + maxBodyLen
		if end > len(body) {
			end = len(body)
		}
		chunk := body[start:end]
		pkgNum := uint16(i + 1)
		pkgTotal := uint16(total)
		// Recompute props: keep version (bits 10-12) + encrypt (bit 15)
		// from baseProps; set body length to chunk length; force bit 14.
		chunkProps := (baseProps & 0x1C00) | uint16(len(chunk)&0x3FF) | (1 << 14)
		if baseProps&0x8000 != 0 {
			chunkProps |= 0x8000
		}
		hdr := buildHeader(msgID, chunkProps, phoneBCD, msgSN, true, pkgNum, pkgTotal)
		hdrAndBody := append(hdr, chunk...)
		frame := buildFrame(hdrAndBody)
		frames = append(frames, frame)
	}
	return frames
}

// buildSimpleFrame is the convenience wrapper for the common case: a
// non-fragmented message with the given header fields and body.
func buildSimpleFrame(msgID uint16, props uint16, phoneBCD []byte, msgSN uint16, body []byte) []byte {
	hdr := buildHeader(msgID, props, phoneBCD, msgSN, false, 0, 0)
	hdrAndBody := append(hdr, body...)
	return buildFrame(hdrAndBody)
}
