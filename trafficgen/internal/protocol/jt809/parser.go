package jt809

import (
	"encoding/binary"
	"fmt"

	"github.com/trafficgen/trafficgen/internal/protocol/jtcommon"
)

// ParsedFrame holds the decoded fields of one JT809 message.
type ParsedFrame struct {
	MsgLength    uint32
	MsgSN        uint32
	MsgID        uint16
	VehicleColor uint8
	VehiclePlate string // GBK-decoded, trailing 0x20 stripped
	Body         []byte
}

// ParseFrame decodes one JT809 message from raw bytes. JT809 has no
// delimiters, no escape, and no checksum (design §1, §3B) — the parser
// simply splits the 32-byte header from the body using MsgLength.
//
// Returns an error when the input is shorter than 32 bytes or when
// MsgLength disagrees with the actual input length.
func ParseFrame(raw []byte) (*ParsedFrame, error) {
	if len(raw) < HeaderLen {
		return nil, fmt.Errorf("jt809: frame too short (%d bytes < %d)", len(raw), HeaderLen)
	}
	p := &ParsedFrame{}
	p.MsgLength = binary.BigEndian.Uint32(raw[0:4])
	p.MsgSN = binary.BigEndian.Uint32(raw[4:8])
	p.MsgID = binary.BigEndian.Uint16(raw[8:10])
	p.VehicleColor = raw[10]
	plateBytes := make([]byte, VehiclePlateLen)
	copy(plateBytes, raw[11:32])
	// Strip trailing 0x20 (space) before GBK decoding for a clean string.
	trimmed := stripTrailingSpaceBytes(plateBytes)
	if len(trimmed) > 0 {
		plate, err := jtcommon.GBKDecode(trimmed)
		if err != nil {
			return nil, fmt.Errorf("jt809: VehiclePlate GBK decode: %w", err)
		}
		p.VehiclePlate = plate
	}
	if int(p.MsgLength) != len(raw) {
		return nil, fmt.Errorf("jt809: MsgLength %d != actual length %d", p.MsgLength, len(raw))
	}
	p.Body = make([]byte, len(raw)-HeaderLen)
	copy(p.Body, raw[HeaderLen:])
	return p, nil
}

// ParseLoginBody decodes a 0x1001 / 0x9001 login body (design §4B.1).
type LoginBody struct {
	UserName     string // 5 ASCII, trailing 0x00 stripped
	Password     string // 10 ASCII, trailing 0x00 stripped
	GNSSCenterId uint32
	VersionFlag  uint8
	EncryptFlag  uint8
	EncryptKey   uint32
}

func ParseLoginBody(body []byte) (*LoginBody, error) {
	if len(body) != LoginBodyLen {
		return nil, fmt.Errorf("jt809: login body length %d != %d", len(body), LoginBodyLen)
	}
	l := &LoginBody{}
	l.UserName = string(stripTrailingZeroBytes(body[0:5]))
	l.Password = string(stripTrailingZeroBytes(body[5:15]))
	l.GNSSCenterId = binary.BigEndian.Uint32(body[15:19])
	l.VersionFlag = body[19]
	l.EncryptFlag = body[20]
	l.EncryptKey = binary.BigEndian.Uint32(body[21:25])
	return l, nil
}

// ParseLoginRespBody decodes a 0x1002 / 0x9002 login response body.
type LoginRespBody struct {
	Result       uint8
	GNSSCenterId uint32
}

func ParseLoginRespBody(body []byte) (*LoginRespBody, error) {
	if len(body) != LoginRespBodyLen {
		return nil, fmt.Errorf("jt809: login resp body length %d != %d", len(body), LoginRespBodyLen)
	}
	r := &LoginRespBody{}
	r.Result = body[0]
	r.GNSSCenterId = binary.BigEndian.Uint32(body[1:5])
	return r, nil
}

// ParseContainerBody decodes a 0x1200/0x1300/0x1500/0x1600/0x9100/0x9600
// container body (design §4B.5): SubMsgId(1) + SubLength(2) + SubBody.
type ContainerBody struct {
	SubMsgId uint8
	SubLen   uint16
	SubBody  []byte
}

func ParseContainerBody(body []byte) (*ContainerBody, error) {
	if len(body) < 3 {
		return nil, fmt.Errorf("jt809: container body too short (%d bytes)", len(body))
	}
	c := &ContainerBody{}
	c.SubMsgId = body[0]
	c.SubLen = binary.BigEndian.Uint16(body[1:3])
	if int(c.SubLen) != len(body)-3 {
		return nil, fmt.Errorf("jt809: SubLength %d != actual SubBody length %d", c.SubLen, len(body)-3)
	}
	c.SubBody = make([]byte, c.SubLen)
	copy(c.SubBody, body[3:])
	return c, nil
}

// stripTrailingSpaceBytes removes trailing 0x20 bytes.
func stripTrailingSpaceBytes(b []byte) []byte {
	for len(b) > 0 && b[len(b)-1] == 0x20 {
		b = b[:len(b)-1]
	}
	return b
}

// stripTrailingZeroBytes removes trailing 0x00 bytes.
func stripTrailingZeroBytes(b []byte) []byte {
	for len(b) > 0 && b[len(b)-1] == 0x00 {
		b = b[:len(b)-1]
	}
	return b
}
