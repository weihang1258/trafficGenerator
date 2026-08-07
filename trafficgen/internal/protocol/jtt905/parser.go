package jtt905

import (
	"encoding/binary"
	"fmt"

	"github.com/trafficgen/trafficgen/internal/protocol/jtcommon"
)

// ParsedFrame holds the decoded fields of one JTT905 frame.
type ParsedFrame struct {
	MsgID        uint16
	MsgBodyProps uint16
	BodyLen      int
	Version      string
	PackageFlag  uint8
	EncryptFlag  uint8
	PhoneBCD     []byte // 6 bytes
	Phone        string // 12-digit string
	MsgSN        uint16
	PackageNum   uint16 // 0 when not fragmented
	PackageTotal uint16 // 0 when not fragmented
	Body         []byte
	Checksum     byte
}

// ParseFrame decodes one JTT905 frame (same format as JT808: 0x7e
// delimiters + escape + XOR checksum). See jt808.ParseFrame for the
// equivalent semantics; this mirrors it with the JTT905 header constants.
func ParseFrame(raw []byte) (*ParsedFrame, error) {
	if len(raw) < 14 {
		return nil, fmt.Errorf("jtt905: frame too short (%d bytes)", len(raw))
	}
	if raw[0] != jtcommon.FrameDelimiter {
		return nil, fmt.Errorf("jtt905: leading byte 0x%02x != 0x7e", raw[0])
	}
	if raw[len(raw)-1] != jtcommon.FrameDelimiter {
		return nil, fmt.Errorf("jtt905: trailing byte 0x%02x != 0x7e", raw[len(raw)-1])
	}
	middle := raw[1 : len(raw)-1]
	decoded, err := jtcommon.Unescape(middle)
	if err != nil {
		return nil, fmt.Errorf("jtt905: unescape: %w", err)
	}
	if len(decoded) < 12+1 {
		return nil, fmt.Errorf("jtt905: decoded frame too short (%d bytes)", len(decoded))
	}
	p := &ParsedFrame{}
	p.MsgID = binary.BigEndian.Uint16(decoded[0:2])
	p.MsgBodyProps = binary.BigEndian.Uint16(decoded[2:4])
	p.BodyLen, p.Version, p.PackageFlag, p.EncryptFlag = jtcommon.DecodeMsgBodyProps(p.MsgBodyProps)
	p.PhoneBCD = make([]byte, 6)
	copy(p.PhoneBCD, decoded[4:10])
	p.Phone = jtcommon.BCDDecode(p.PhoneBCD)
	p.MsgSN = binary.BigEndian.Uint16(decoded[10:12])
	hdrLen := 12
	if p.PackageFlag == 1 {
		if len(decoded) < 12+4+1 {
			return nil, fmt.Errorf("jtt905: fragmented frame too short")
		}
		p.PackageNum = binary.BigEndian.Uint16(decoded[12:14])
		p.PackageTotal = binary.BigEndian.Uint16(decoded[14:16])
		hdrLen = 16
	}
	if len(decoded) < hdrLen+p.BodyLen+1 {
		return nil, fmt.Errorf("jtt905: body length %d exceeds remaining %d bytes",
			p.BodyLen, len(decoded)-hdrLen-1)
	}
	p.Body = make([]byte, p.BodyLen)
	copy(p.Body, decoded[hdrLen:hdrLen+p.BodyLen])
	p.Checksum = decoded[hdrLen+p.BodyLen]
	expected := jtcommon.XORChecksum(decoded[:hdrLen+p.BodyLen])
	if p.Checksum != expected {
		return nil, fmt.Errorf("jtt905: checksum mismatch (got 0x%02x, want 0x%02x)",
			p.Checksum, expected)
	}
	return p, nil
}

// ParseCheckInBody decodes a 0x1001 check-in body (design §4C.2).
type CheckInBody struct {
	DriverId     string // trailing 0x20 stripped
	DriverName   string // GBK-decoded, trailing 0x20 stripped
	LicensePlate string // GBK-decoded, trailing 0x20 stripped
	LicenseColor uint8
	OnTime       string // "YYMMDDhhmmss"
	VehicleModel string // trailing 0x20 stripped
	LoadCapacity uint16
}

func ParseCheckInBody(body []byte) (*CheckInBody, error) {
	fixedLen := DriverIdLen + DriverNameLen + LicensePlateLen + LicenseColorLen + OnTimeLen + VehicleModelLen + LoadCapacityLen
	if len(body) != fixedLen {
		return nil, fmt.Errorf("jtt905: 0x1001 body length %d != %d", len(body), fixedLen)
	}
	c := &CheckInBody{}
	c.DriverId = stripTrailingSpace(string(body[0:20]))
	dn, err := jtcommon.GBKDecode(stripTrailingSpaceBytes(body[20:36]))
	if err != nil {
		return nil, fmt.Errorf("jtt905: DriverName GBK: %w", err)
	}
	c.DriverName = dn
	plate, err := jtcommon.GBKDecode(stripTrailingSpaceBytes(body[36:57]))
	if err != nil {
		return nil, fmt.Errorf("jtt905: LicensePlate GBK: %w", err)
	}
	c.LicensePlate = plate
	c.LicenseColor = body[57]
	c.OnTime = jtcommon.BCDDecode(body[58:64])
	c.VehicleModel = stripTrailingSpace(string(body[64:80]))
	c.LoadCapacity = binary.BigEndian.Uint16(body[80:82])
	return c, nil
}

// ParseCheckOutBody decodes a 0x1002 check-out body (design §4C.3).
type CheckOutBody struct {
	DriverId       string
	DriverName     string
	LicensePlate   string
	LicenseColor   uint8
	OffTime        string
	Mileage        uint32
	Income         uint32
	PassengerCount uint16
}

func ParseCheckOutBody(body []byte) (*CheckOutBody, error) {
	fixedLen := DriverIdLen + DriverNameLen + LicensePlateLen + LicenseColorLen + OffTimeLen + MileageLen + IncomeLen + PassengerCountLen
	if len(body) != fixedLen {
		return nil, fmt.Errorf("jtt905: 0x1002 body length %d != %d", len(body), fixedLen)
	}
	c := &CheckOutBody{}
	c.DriverId = stripTrailingSpace(string(body[0:20]))
	dn, err := jtcommon.GBKDecode(stripTrailingSpaceBytes(body[20:36]))
	if err != nil {
		return nil, fmt.Errorf("jtt905: DriverName GBK: %w", err)
	}
	c.DriverName = dn
	plate, err := jtcommon.GBKDecode(stripTrailingSpaceBytes(body[36:57]))
	if err != nil {
		return nil, fmt.Errorf("jtt905: LicensePlate GBK: %w", err)
	}
	c.LicensePlate = plate
	c.LicenseColor = body[57]
	c.OffTime = jtcommon.BCDDecode(body[58:64])
	c.Mileage = binary.BigEndian.Uint32(body[64:68])
	c.Income = binary.BigEndian.Uint32(body[68:72])
	c.PassengerCount = binary.BigEndian.Uint16(body[72:74])
	return c, nil
}

// ParseGeneralResponseBody decodes a 0x8001 / 0x0001 general response
// body (design §4C.4): 5 bytes, no Phone.
type GeneralResponseBody struct {
	ResponseSN    uint16
	ResponseMsgID uint16
	Result        uint8
}

func ParseGeneralResponseBody(body []byte) (*GeneralResponseBody, error) {
	if len(body) != GeneralResponseLen {
		return nil, fmt.Errorf("jtt905: general response body length %d != %d", len(body), GeneralResponseLen)
	}
	r := &GeneralResponseBody{}
	r.ResponseSN = binary.BigEndian.Uint16(body[0:2])
	r.ResponseMsgID = binary.BigEndian.Uint16(body[2:4])
	r.Result = body[4]
	return r, nil
}

// stripTrailingSpace removes trailing 0x20 bytes from a string.
func stripTrailingSpace(s string) string {
	for len(s) > 0 && s[len(s)-1] == 0x20 {
		s = s[:len(s)-1]
	}
	return s
}

// stripTrailingSpaceBytes removes trailing 0x20 bytes from a byte slice.
func stripTrailingSpaceBytes(b []byte) []byte {
	for len(b) > 0 && b[len(b)-1] == 0x20 {
		b = b[:len(b)-1]
	}
	return b
}
