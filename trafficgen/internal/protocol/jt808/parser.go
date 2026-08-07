package jt808

import (
	"encoding/binary"
	"fmt"

	"github.com/trafficgen/trafficgen/internal/protocol/jtcommon"
)

// ParsedFrame holds the decoded fields of one JT808 frame.
type ParsedFrame struct {
	MsgID         uint16
	MsgBodyProps  uint16
	BodyLen       int
	Version       string
	PackageFlag   uint8
	EncryptFlag   uint8
	PhoneBCD      []byte // 6 bytes
	Phone         string // 12-digit string
	MsgSN         uint16
	PackageNum    uint16 // 0 when not fragmented
	PackageTotal  uint16 // 0 when not fragmented
	Body          []byte
	Checksum      byte
}

// ParseFrame decodes one JT808 frame from raw bytes (including the leading
// and trailing 0x7e delimiters). It reverses escape, splits the header /
// body / checksum, and verifies the XOR checksum (design §3A.3, §3A.4).
//
// Returns an error when:
//   - the input is shorter than 14 bytes (delim + 12B header + checksum + delim)
//   - the leading/trailing delimiter is not 0x7e
//   - Unescape fails (illegal 0x7d sequence)
//   - the body length implied by MsgBodyProps disagrees with the actual
//     remaining bytes
//   - the XOR checksum does not match
func ParseFrame(raw []byte) (*ParsedFrame, error) {
	if len(raw) < 14 {
		return nil, fmt.Errorf("jt808: frame too short (%d bytes)", len(raw))
	}
	if raw[0] != jtcommon.FrameDelimiter {
		return nil, fmt.Errorf("jt808: leading byte 0x%02x != 0x7e", raw[0])
	}
	if raw[len(raw)-1] != jtcommon.FrameDelimiter {
		return nil, fmt.Errorf("jt808: trailing byte 0x%02x != 0x7e", raw[len(raw)-1])
	}
	middle := raw[1 : len(raw)-1]
	decoded, err := jtcommon.Unescape(middle)
	if err != nil {
		return nil, fmt.Errorf("jt808: unescape: %w", err)
	}
	if len(decoded) < HeaderLen+1 {
		return nil, fmt.Errorf("jt808: decoded frame too short (%d bytes)", len(decoded))
	}
	p := &ParsedFrame{}
	p.MsgID = binary.BigEndian.Uint16(decoded[0:2])
	p.MsgBodyProps = binary.BigEndian.Uint16(decoded[2:4])
	p.BodyLen, p.Version, p.PackageFlag, p.EncryptFlag = jtcommon.DecodeMsgBodyProps(p.MsgBodyProps)
	p.PhoneBCD = make([]byte, PhoneLen)
	copy(p.PhoneBCD, decoded[4:10])
	p.Phone = jtcommon.BCDDecode(p.PhoneBCD)
	p.MsgSN = binary.BigEndian.Uint16(decoded[10:12])
	hdrLen := HeaderLen
	if p.PackageFlag == 1 {
		if len(decoded) < HeaderLen+PackageInfoLen+1 {
			return nil, fmt.Errorf("jt808: fragmented frame too short")
		}
		p.PackageNum = binary.BigEndian.Uint16(decoded[12:14])
		p.PackageTotal = binary.BigEndian.Uint16(decoded[14:16])
		hdrLen = HeaderLenPkg
	}
	// Body + checksum = remaining bytes after header.
	if len(decoded) < hdrLen+p.BodyLen+ChecksumLen {
		return nil, fmt.Errorf("jt808: body length %d exceeds remaining %d bytes",
			p.BodyLen, len(decoded)-hdrLen-1)
	}
	p.Body = make([]byte, p.BodyLen)
	copy(p.Body, decoded[hdrLen:hdrLen+p.BodyLen])
	p.Checksum = decoded[hdrLen+p.BodyLen]
	// Verify checksum: XOR of bytes[0 .. hdrLen+bodyLen-1].
	expected := jtcommon.XORChecksum(decoded[:hdrLen+p.BodyLen])
	if p.Checksum != expected {
		return nil, fmt.Errorf("jt808: checksum mismatch (got 0x%02x, want 0x%02x)",
			p.Checksum, expected)
	}
	return p, nil
}

// ParseRegisterBody decodes a 0x0100 terminal registration body (design §4A.1).
// Returns the decoded fields. LicensePlate is the GBK-decoded string when
// LicenseColor != 0, else empty.
type RegisterBody struct {
	ProvinceId    uint16
	CityId        uint16
	ManufacturerId string // 5 ASCII bytes (trailing 0x00 stripped)
	TerminalModel  string // 20 bytes (trailing 0x20 stripped)
	TerminalId     string // 7 bytes (trailing 0x00 stripped)
	LicenseColor   uint8
	LicensePlate   string
}

func ParseRegisterBody(body []byte) (*RegisterBody, error) {
	fixedLen := ProvinceIDLen + CityIDLen + ManufacturerIDLen + TerminalModelLen + TerminalIDLen + LicenseColorLen
	if len(body) < fixedLen {
		return nil, fmt.Errorf("jt808: 0x0100 body length %d < %d", len(body), fixedLen)
	}
	r := &RegisterBody{}
	r.ProvinceId = binary.BigEndian.Uint16(body[0:2])
	r.CityId = binary.BigEndian.Uint16(body[2:4])
	r.ManufacturerId = stripTrailingZero(string(body[4:9]))
	r.TerminalModel = stripTrailingSpace(string(body[9:29]))
	r.TerminalId = stripTrailingZero(string(body[29:36]))
	r.LicenseColor = body[36]
	if r.LicenseColor != LicenseColorNone {
		plateBytes := body[37:]
		plate, err := jtcommon.GBKDecode(plateBytes)
		if err != nil {
			return nil, fmt.Errorf("jt808: LicensePlate GBK decode: %w", err)
		}
		r.LicensePlate = plate
	}
	return r, nil
}

// ParseLocationBody decodes a 0x0200 location body (design §4A.3).
type LocationBody struct {
	AlarmFlag  uint32
	StatusFlag uint32
	Latitude   uint32
	Longitude  uint32
	Altitude   uint16
	Speed      uint16
	Direction  uint16
	TimeBCD    []byte // 6 bytes
	Time       string // "YYMMDDhhmmss"
	ExtraItems []JT808Extra
}

func ParseLocationBody(body []byte) (*LocationBody, error) {
	fixedLen := AlarmFlagLen + StatusFlagLen + LatitudeLen + LongitudeLen + AltitudeLen + SpeedLen + DirectionLen + TimeLen
	if len(body) < fixedLen {
		return nil, fmt.Errorf("jt808: 0x0200 body length %d < %d", len(body), fixedLen)
	}
	l := &LocationBody{}
	l.AlarmFlag = binary.BigEndian.Uint32(body[0:4])
	l.StatusFlag = binary.BigEndian.Uint32(body[4:8])
	l.Latitude = binary.BigEndian.Uint32(body[8:12])
	l.Longitude = binary.BigEndian.Uint32(body[12:16])
	l.Altitude = binary.BigEndian.Uint16(body[16:18])
	l.Speed = binary.BigEndian.Uint16(body[18:20])
	l.Direction = binary.BigEndian.Uint16(body[20:22])
	l.TimeBCD = make([]byte, TimeLen)
	copy(l.TimeBCD, body[22:28])
	l.Time = jtcommon.BCDDecode(l.TimeBCD)
	// Parse extra TLV items from offset 28 onward.
	off := fixedLen
	for off+2 <= len(body) {
		ex := JT808Extra{Type: body[off]}
		ex.Length = body[off+1]
		if off+2+int(ex.Length) > len(body) {
			return nil, fmt.Errorf("jt808: extra item length %d exceeds remaining bytes", ex.Length)
		}
		ex.Value = make([]byte, ex.Length)
		copy(ex.Value, body[off+2:off+2+int(ex.Length)])
		l.ExtraItems = append(l.ExtraItems, ex)
		off += 2 + int(ex.Length)
	}
	return l, nil
}

// ParseGeneralResponseBody decodes a 0x8001 / 0x0001 general response body
// (design §4A.7): ResponseSN(2) + ResponseMsgId(2) + Result(1) = 5 bytes.
type GeneralResponseBody struct {
	ResponseSN    uint16
	ResponseMsgID uint16
	Result        uint8
}

func ParseGeneralResponseBody(body []byte) (*GeneralResponseBody, error) {
	if len(body) != GeneralResponseLen {
		return nil, fmt.Errorf("jt808: general response body length %d != %d", len(body), GeneralResponseLen)
	}
	r := &GeneralResponseBody{}
	r.ResponseSN = binary.BigEndian.Uint16(body[0:2])
	r.ResponseMsgID = binary.BigEndian.Uint16(body[2:4])
	r.Result = body[4]
	return r, nil
}

// ParseRegistrationResponseBody decodes a 0x8100 registration response body
// (design §4A.8).
type RegistrationResponseBody struct {
	ResponseSN uint16
	Result     uint8
	AuthCode   string // empty when Result != 0
}

func ParseRegistrationResponseBody(body []byte) (*RegistrationResponseBody, error) {
	if len(body) < RegistrationRespFixed {
		return nil, fmt.Errorf("jt808: 0x8100 body length %d < %d", len(body), RegistrationRespFixed)
	}
	r := &RegistrationResponseBody{}
	r.ResponseSN = binary.BigEndian.Uint16(body[0:2])
	r.Result = body[2]
	if r.Result == RegResultSuccess && len(body) > RegistrationRespFixed {
		auth, err := jtcommon.GBKDecode(body[3:])
		if err != nil {
			return nil, fmt.Errorf("jt808: 0x8100 AuthCode GBK: %w", err)
		}
		r.AuthCode = auth
	}
	return r, nil
}

// stripTrailingZero removes trailing 0x00 bytes from a fixed-width ASCII
// field (e.g. ManufacturerId "TEST\0" → "TEST").
func stripTrailingZero(s string) string {
	for len(s) > 0 && s[len(s)-1] == 0x00 {
		s = s[:len(s)-1]
	}
	return s
}

// stripTrailingSpace removes trailing 0x20 bytes from a fixed-width ASCII
// field (e.g. TerminalModel "TG-DEMO             " → "TG-DEMO").
func stripTrailingSpace(s string) string {
	for len(s) > 0 && s[len(s)-1] == 0x20 {
		s = s[:len(s)-1]
	}
	return s
}
