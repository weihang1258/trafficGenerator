package jtt905

import (
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/trafficgen/trafficgen/internal/protocol/jtcommon"
)

// ParsedFrame is a decoded JTT905 frame（解析与 builder 严格对称；
// 金向量 0x0200 例为外部权威锚）。
type ParsedFrame struct {
	MsgID      uint16
	DataLength uint16 // 纯消息体长度（裁定1）
	ISUId      string // BCD 解码 12 位
	MsgNum     uint16
	Body       []byte
}

// ParseFrame decodes one wire frame: delimiters → unescape → XOR 复算 →
// 头字段。体长自洽（DataLength==len(Body)）随解包断言。
func ParseFrame(wire []byte) (*ParsedFrame, error) {
	if len(wire) < HeaderLen+ChecksumLen+2 {
		return nil, fmt.Errorf("jtt905: frame too short: %d", len(wire))
	}
	if wire[0] != jtcommon.FrameDelimiter || wire[len(wire)-1] != jtcommon.FrameDelimiter {
		return nil, fmt.Errorf("jtt905: bad delimiters %02x %02x", wire[0], wire[len(wire)-1])
	}
	content, err := jtcommon.Unescape(wire[1 : len(wire)-1])
	if err != nil {
		return nil, fmt.Errorf("jtt905: unescape: %w", err)
	}
	if len(content) < HeaderLen+ChecksumLen {
		return nil, fmt.Errorf("jtt905: content %d < header %d + checksum", len(content), HeaderLen+ChecksumLen)
	}
	wantCS := jtcommon.XORChecksum(content[:len(content)-1])
	if wantCS != content[len(content)-1] {
		return nil, fmt.Errorf("jtt905: XOR checksum mismatch got %02x want %02x", wantCS, content[len(content)-1])
	}
	f := &ParsedFrame{}
	f.MsgID = binary.BigEndian.Uint16(content[0:2])
	f.DataLength = binary.BigEndian.Uint16(content[2:4])
	f.ISUId = jtcommon.BCDDecode(content[4:10])
	f.MsgNum = binary.BigEndian.Uint16(content[10:12])
	f.Body = append([]byte(nil), content[HeaderLen:len(content)-ChecksumLen]...)
	if int(f.DataLength) != len(f.Body) {
		return nil, fmt.Errorf("jtt905: DataLength %d != body length %d", f.DataLength, len(f.Body))
	}
	return f, nil
}

// GeneralRespBody decodes 0x0001/0x8001: ReplySN(2)+ReplyMsgId(2)+Result(1)。
func (f *ParsedFrame) GeneralRespBody() (replySN, replyMsgID uint16, result uint8, err error) {
	if len(f.Body) != GeneralRespLen {
		return 0, 0, 0, fmt.Errorf("jtt905: 0x%04x body %d bytes, want %d", f.MsgID, len(f.Body), GeneralRespLen)
	}
	return binary.BigEndian.Uint16(f.Body), binary.BigEndian.Uint16(f.Body[2:4]), f.Body[4], nil
}

// CheckInBody decodes 0x0B03（Position 可选，体首 25B 判定与库同口径）。
func (f *ParsedFrame) CheckInBody() (license, qual, plate, uptime string, err error) {
	b := f.Body
	if len(b) >= PositionLen && len(b) != baseCheckInLen {
		b = b[PositionLen:] // 带位置形态
	}
	if len(b) != baseCheckInLen {
		return "", "", "", "", fmt.Errorf("jtt905: 0x0B03 body %d bytes, want %d (±25 position)", len(f.Body), baseCheckInLen)
	}
	license = strings.TrimRight(string(b[0:LicenseLen]), "\x00")
	qual = strings.TrimRight(string(b[LicenseLen:LicenseLen+QualCodeLen]), "\x00")
	plate = strings.TrimRight(string(b[LicenseLen+QualCodeLen:LicenseLen+QualCodeLen+PlateLen]), "\x00")
	uptime = jtcommon.BCDDecode(b[LicenseLen+QualCodeLen+PlateLen:])
	return
}

// baseCheckInLen = 16+19+6+6（无 Position 形）。
const baseCheckInLen = LicenseLen + QualCodeLen + PlateLen + TimeLen
