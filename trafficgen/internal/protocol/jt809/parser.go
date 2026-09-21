package jt809

import (
	"encoding/binary"
	"fmt"

	"github.com/trafficgen/trafficgen/internal/protocol/jtcommon"
)

// ParsedFrame is a decoded JT809 frame（解析与 builder 严格对称——CLAUDE.md
// 改码先自审面；负路径供单测/链级校验锚）。
type ParsedFrame struct {
	MsgLength    uint32 // 整帧总长（勘误1）
	MsgSN        uint32
	MsgID        uint16
	GNSSCenterId uint32
	Version      []byte // 3B
	EncryptFlag  uint8
	EncryptKey   uint32
	TimeSec      uint64 // 仅 2019
	Body         []byte // 反转义后的体
}

// ParseFrame decodes one wire frame: delimiters → unescape → MsgLength
// 自洽 → CRC 复算 → 头字段。versionFlag selects the header layout (22B/30B)，
// 与 builder 同源规则（lib 以 config.Version 选头长，同口径）。
func ParseFrame(wire []byte, versionFlag uint8) (*ParsedFrame, error) {
	if len(wire) < FixedFrameLegacy {
		return nil, fmt.Errorf("jt809: frame too short: %d", len(wire))
	}
	if wire[0] != FlagBegin || wire[len(wire)-1] != FlagEnd {
		return nil, fmt.Errorf("jt809: bad delimiters %02x %02x", wire[0], wire[len(wire)-1])
	}
	content := jtcommon.Unescape809(wire[1 : len(wire)-1])
	headerLen := HeaderLenLegacy
	if versionFlag == 2 {
		headerLen = HeaderLen2019
	}
	if len(content) < headerLen+CRCLen {
		return nil, fmt.Errorf("jt809: content %d < header %d + CRC", len(content), headerLen)
	}
	f := &ParsedFrame{}
	f.MsgLength = binary.BigEndian.Uint32(content[0:4])
	// 整帧语义（勘误1）按未转义口径：5B+content+CRC… content 已含 CRC，
	// 故 = len(content)+2 个标识位。转义帧的 wire 长更大，不可比。
	if int(f.MsgLength) != len(content)+2 {
		return nil, fmt.Errorf("jt809: MsgLength %d != unescaped frame length %d", f.MsgLength, len(content)+2)
	}
	wantCRC := binary.BigEndian.Uint16(content[len(content)-2:])
	gotCRC := jtcommon.CRC809(content[:len(content)-2])
	if gotCRC != wantCRC {
		return nil, fmt.Errorf("jt809: CRC mismatch got %04x want %04x", gotCRC, wantCRC)
	}
	f.MsgSN = binary.BigEndian.Uint32(content[4:8])
	f.MsgID = binary.BigEndian.Uint16(content[8:10])
	f.GNSSCenterId = binary.BigEndian.Uint32(content[10:14])
	f.Version = append([]byte(nil), content[14:17]...)
	f.EncryptFlag = content[17]
	f.EncryptKey = binary.BigEndian.Uint32(content[18:22])
	body := content[headerLen : len(content)-CRCLen]
	if versionFlag == 2 {
		f.TimeSec = binary.BigEndian.Uint64(content[22:30])
	}
	f.Body = append([]byte(nil), body...)
	return f, nil
}

// LoginBody decodes 0x1001 (version-conditional per 勘误4: 46B/50B).
func (f *ParsedFrame) LoginBody() (userId uint32, password string, gnss uint32, ip string, port uint16, err error) {
	need := 4 + PasswordLen + DownLinkIPLen + 2 // 46B（2011/2013）
	if len(f.Body) != need && len(f.Body) != need+4 {
		// 形判定先行（隔离复审 M1：中间带 47-49B 必须报错不越界切片）。
		return 0, "", 0, "", 0, fmt.Errorf("jt809: 0x1001 body %d bytes, want 46 or 50", len(f.Body))
	}
	off := 0
	userId = binary.BigEndian.Uint32(f.Body[off:])
	off += 4
	password = trimPad(f.Body[off : off+PasswordLen])
	off += PasswordLen
	if len(f.Body) == need+4 { // 2019 形 50B
		gnss = binary.BigEndian.Uint32(f.Body[off:])
		off += 4
	}
	ip = trimPad(f.Body[off : off+DownLinkIPLen])
	off += DownLinkIPLen
	port = binary.BigEndian.Uint16(f.Body[off:])
	return
}

// RespBody decodes 0x1002: Result(1)+VerifyCode(4).
func (f *ParsedFrame) RespBody() (result uint8, verifyCode uint32, err error) {
	if len(f.Body) != 5 {
		return 0, 0, fmt.Errorf("jt809: 0x%04x body %d bytes, want 5", f.MsgID, len(f.Body))
	}
	return f.Body[0], binary.BigEndian.Uint32(f.Body[1:5]), nil
}

// VerifyCodeBody decodes 0x9001: VerifyCode(4).
func (f *ParsedFrame) VerifyCodeBody() (uint32, error) {
	if len(f.Body) != 4 {
		return 0, fmt.Errorf("jt809: 0x9001 body %d bytes, want 4", len(f.Body))
	}
	return binary.BigEndian.Uint32(f.Body), nil
}

// LogoutBody decodes 0x1003/0x9003: UserId(4)+Password(8).
func (f *ParsedFrame) LogoutBody() (userId uint32, password string, err error) {
	if len(f.Body) != 12 {
		return 0, "", fmt.Errorf("jt809: 0x%04x body %d bytes, want 12", f.MsgID, len(f.Body))
	}
	return binary.BigEndian.Uint32(f.Body), trimPad(f.Body[4:12]), nil
}

// trimPad strips trailing 0x00 pad bytes（与 builder padRight 对称）.
func trimPad(b []byte) string {
	for len(b) > 0 && b[len(b)-1] == 0x00 {
		b = b[:len(b)-1]
	}
	return string(b)
}

// CodeBody decodes 0x1007/0x1008/0x9007/0x9008: 1 byte.
func (f *ParsedFrame) CodeBody() (uint8, error) {
	if len(f.Body) != 1 {
		return 0, fmt.Errorf("jt809: 0x%04x body %d bytes, want 1", f.MsgID, len(f.Body))
	}
	return f.Body[0], nil
}

// EmptyBody asserts an empty body (0x1004/0x1005/0x1006/0x9004/0x9005/0x9006).
func (f *ParsedFrame) EmptyBody() error {
	if len(f.Body) != 0 {
		return fmt.Errorf("jt809: 0x%04x body %d bytes, want 0", f.MsgID, len(f.Body))
	}
	return nil
}
