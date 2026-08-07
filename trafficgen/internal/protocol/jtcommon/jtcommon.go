// Package jtcommon provides shared helpers for the JT/T 808, JT/T 809,
// and JT/T 905 vehicle-networking protocols (中华人民共和国交通部车联网
// 标准族). The helpers cover escape/unescape (转义), XOR checksum (字节异或
// 校验), BCD encoding (BCD 编码), GBK encoding (GBK 编码), message-body
// property packing (消息体属性打包), and time BCD (时间 BCD) conversion.
//
// Reference: design doc 02-03-04-jt808-jt809-jtt905-design.md v1.1.4-patch.
package jtcommon

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/text/encoding/simplifiedchinese"
)

// FrameDelimiter (起始/结束符) is the 0x7e marker wrapping JT808/JTT905
// frames. JT809 does NOT use delimiters.
const FrameDelimiter byte = 0x7e

// EscapeMarker (转义标记) is the 0x7d byte prefixing escaped sequences.
const EscapeMarker byte = 0x7d

// MaxBodyLength (消息体最大长度) is the 10-bit body length field limit
// (JT/T 808-2019 §4.2.2). Messages longer than this must be fragmented
// (PackageFlag=1, design §3A.2).
const MaxBodyLength = 1023

// Version flag values for MsgBodyProps bits 10-12 (design §3A.2).
const (
	Version2011 = "2011" // bit10-12 = 000
	Version2013 = "2013" // bit10-12 = 001
	Version2019 = "2019" // bit10-12 = 010
)

// VersionFlag numeric values (used by JT809 VersionFlag uint8 field).
const (
	VersionFlag2011 uint8 = 0
	VersionFlag2013 uint8 = 1
	VersionFlag2019 uint8 = 2
)

// ErrInvalidEscape is returned by Unescape when the input contains an
// illegal 0x7d followed by a byte other than 0x01/0x02 (design §3A.3).
var ErrInvalidEscape = errors.New("jtcommon: invalid escape sequence")

// ErrInvalidBCD is returned when a BCD input is not the expected length
// or contains non-digit characters.
var ErrInvalidBCD = errors.New("jtcommon: invalid BCD input")

// ErrInvalidVersion is returned when a version string is not 2011/2013/2019.
var ErrInvalidVersion = errors.New("jtcommon: invalid version (must be 2011, 2013, or 2019)")

// Escape applies JT808/JTT905 escape rules (design §3A.3):
//
//	0x7e -> 0x7d 0x02
//	0x7d -> 0x7d 0x01
//
// Used after checksum computation, before wrapping with 0x7e delimiters.
// The caller passes the bytes between the delimiters (i.e. the header +
// body + checksum, NOT including the leading/trailing 0x7e).
func Escape(raw []byte) []byte {
	out := make([]byte, 0, len(raw)+4)
	for _, b := range raw {
		switch b {
		case 0x7e:
			out = append(out, 0x7d, 0x02)
		case 0x7d:
			out = append(out, 0x7d, 0x01)
		default:
			out = append(out, b)
		}
	}
	return out
}

// Unescape reverses Escape. Returns ErrInvalidEscape when a 0x7d byte is
// followed by anything other than 0x01 or 0x02 (design §3A.3, A-41).
// The caller passes the bytes between the delimiters (NOT including the
// leading/trailing 0x7e).
func Unescape(escaped []byte) ([]byte, error) {
	out := make([]byte, 0, len(escaped))
	for i := 0; i < len(escaped); i++ {
		b := escaped[i]
		if b == 0x7d {
			if i+1 >= len(escaped) {
				return nil, fmt.Errorf("%w: 0x7d at end of input", ErrInvalidEscape)
			}
			nb := escaped[i+1]
			switch nb {
			case 0x01:
				out = append(out, 0x7d)
			case 0x02:
				out = append(out, 0x7e)
			default:
				return nil, fmt.Errorf("%w: 0x7d followed by 0x%02x", ErrInvalidEscape, nb)
			}
			i++ // consume the trailing byte
			continue
		}
		out = append(out, b)
	}
	return out, nil
}

// XORChecksum computes the XOR of all bytes in buf (design §3A.4). The
// caller MUST pass the bytes from MsgId's first byte to the body's last
// byte (i.e. header + [package info] + body), excluding the leading 0x7e,
// trailing 0x7e, and the checksum byte itself.
func XORChecksum(buf []byte) byte {
	var cs byte
	for _, b := range buf {
		cs ^= b
	}
	return cs
}

// XORChecksumGBK is a named wrapper around XORChecksum for payload bytes
// already encoded as GBK (e.g. GBK LicensePlate, DriverName, FileUrl).
// It is defined here (not inlined) so jtcommon tests can assert that it
// equals XORChecksum on identical input bytes (D-02 covers this).
//
// Per design §11.1: this function makes the GBK-byte checksum scope
// explicit so callers cannot accidentally pass UTF-8 strings to a
// byte-level XOR. The bytes are XOR'd identically to XORChecksum.
func XORChecksumGBK(payload []byte) byte {
	return XORChecksum(payload)
}

// BCDEncode encodes a digit string into packed BCD (big-endian BCD, design
// §3A.1). Each output byte holds two digits (high nibble first). The input
// length MUST equal 2*n for some n (n >= 1, i.e. length >= 2); otherwise
// ErrInvalidBCD is returned. Non-digit characters are rejected.
//
// 空字符串 (length 0) 不属于合法的 BCD 输入，必须返回 error。这条规则覆盖
// 用户未提供电话号码 / IMEI / IMSI 等场景，避免下游写入零长度 BCD 字段
// 后被对端平台判定为非法帧。
//
// Example: "012345678901" → [0x01, 0x23, 0x45, 0x67, 0x89, 0x01].
func BCDEncode(s string) ([]byte, error) {
	if len(s) == 0 {
		return nil, fmt.Errorf("%w: empty string", ErrInvalidBCD)
	}
	if len(s)%2 != 0 {
		return nil, fmt.Errorf("%w: length %d is not even", ErrInvalidBCD, len(s))
	}
	out := make([]byte, len(s)/2)
	for i := 0; i < len(s); i += 2 {
		hi, err := bcdDigit(s[i])
		if err != nil {
			return nil, err
		}
		lo, err := bcdDigit(s[i+1])
		if err != nil {
			return nil, err
		}
		out[i/2] = (hi << 4) | lo
	}
	return out, nil
}

// BCDDecode decodes packed BCD bytes into a digit string. The output has
// 2*len(b) digits. Bytes with nibbles > 9 produce '?' for those nibbles
// (callers should treat this as a parse error at a higher layer).
func BCDDecode(b []byte) string {
	var sb strings.Builder
	sb.Grow(len(b) * 2)
	for _, by := range b {
		hi := by >> 4
		lo := by & 0x0f
		sb.WriteByte(bcdNibbleToChar(hi))
		sb.WriteByte(bcdNibbleToChar(lo))
	}
	return sb.String()
}

func bcdDigit(c byte) (byte, error) {
	if c < '0' || c > '9' {
		return 0, fmt.Errorf("%w: non-digit 0x%02x", ErrInvalidBCD, c)
	}
	return c - '0', nil
}

func bcdNibbleToChar(n byte) byte {
	if n < 10 {
		return '0' + n
	}
	return '?'
}

// EncodeMsgBodyProps packs the JT808/JTT905 message body properties field
// (big-endian 16-bit, design §3A.2):
//
//	bits 0-9:   body length (0-1023)
//	bits 10-12: version flag (0=2011, 1=2013, 2=2019)
//	bit 13:     reserved (0)
//	bit 14:     package flag (0/1)
//	bit 15:     encrypt flag (0/1)
//
// Returns ErrInvalidVersion for unknown version strings, or an error if
// bodyLen exceeds MaxBodyLength.
func EncodeMsgBodyProps(bodyLen int, version string, pkgFlag, encFlag uint8) (uint16, error) {
	if bodyLen < 0 || bodyLen > MaxBodyLength {
		return 0, fmt.Errorf("jtcommon: body length %d out of range [0,%d]", bodyLen, MaxBodyLength)
	}
	vf, err := ParseVersionFlag(version)
	if err != nil {
		return 0, err
	}
	if pkgFlag > 1 || encFlag > 1 {
		return 0, fmt.Errorf("jtcommon: pkgFlag/encFlag must be 0 or 1 (got %d/%d)", pkgFlag, encFlag)
	}
	props := uint16(bodyLen & 0x3FF)
	props |= uint16(vf) << 10
	props |= uint16(pkgFlag&0x01) << 14
	props |= uint16(encFlag&0x01) << 15
	return props, nil
}

// DecodeMsgBodyProps unpacks the properties into body length, version
// string, package flag, and encrypt flag.
func DecodeMsgBodyProps(props uint16) (bodyLen int, version string, pkgFlag, encFlag uint8) {
	bodyLen = int(props & 0x03FF)
	vf := uint8((props >> 10) & 0x07)
	version = FormatVersionFlag(vf)
	pkgFlag = uint8((props >> 14) & 0x01)
	encFlag = uint8((props >> 15) & 0x01)
	return
}

// ParseVersionFlag converts "2011"/"2013"/"2019" to 0/1/2 (design §3A.2).
// Empty string defaults to "2019".
func ParseVersionFlag(v string) (uint8, error) {
	switch v {
	case "", Version2019:
		return 2, nil
	case Version2011:
		return 0, nil
	case Version2013:
		return 1, nil
	}
	return 0, fmt.Errorf("%w: %q", ErrInvalidVersion, v)
}

// FormatVersionFlag converts 0/1/2 to "2011"/"2013"/"2019". Unknown
// values return "2019".
func FormatVersionFlag(v uint8) string {
	switch v {
	case 0:
		return Version2011
	case 1:
		return Version2013
	case 2:
		return Version2019
	}
	return Version2019
}

// GBKEncode encodes a UTF-8 string to GBK bytes (design §11.1). Uses
// golang.org/x/text/encoding/simplifiedchinese.GBK. Pure-ASCII inputs
// pass through unchanged (each byte < 0x80).
func GBKEncode(s string) ([]byte, error) {
	if !utf8.ValidString(s) {
		return nil, fmt.Errorf("jtcommon: invalid UTF-8 string")
	}
	enc := simplifiedchinese.GBK.NewEncoder()
	return enc.Bytes([]byte(s))
}

// GBKDecode decodes GBK bytes back to UTF-8.
func GBKDecode(b []byte) (string, error) {
	dec := simplifiedchinese.GBK.NewDecoder()
	out, err := dec.Bytes(b)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// PadRight pads s with 0x20 (ASCII space) to width bytes (design §11.1).
// Used for JT809's 21-byte VehiclePlate and JTT905's 16-byte DriverName /
// VehicleModel / LicensePlate fields, which require LEFT-aligned 0x20 fill
// (NOT 0x00). If s is longer than width, it is truncated.
//
// IMPORTANT: For GBK fields like VehiclePlate/DriverName, callers MUST
// first GBK-encode the string (so multi-byte chars become byte sequences)
// and then pass the encoded bytes' length. The helper PadRightSpaceGBK
// handles that two-step; PadRightSpace here operates on raw string bytes
// (use it for ASCII-only fields like JT808 TerminalModel).
func PadRightSpace(s string, width int) []byte {
	out := make([]byte, width)
	for i := range out {
		out[i] = 0x20
	}
	n := copy(out, []byte(s))
	if n > width {
		n = width
	}
	_ = n
	return out
}

// PadRightSpaceGBK GBK-encodes s and right-pads with 0x20 (ASCII space)
// to totalBytes. Returns an error if the encoded value exceeds the width.
// Used for JT809 VehiclePlate (21B) and JTT905 DriverName (16B) /
// VehicleModel (16B) / LicensePlate (21B).
//
// Per design §11.1, this is distinct from PadRightGBK which pads with
// 0x00. The 0x20 padding is mandated by JT/T 809-2019 §5.2 and JT/T
// 905-2014 §4.2; using 0x00 causes the receiving platform to reject
// the frame as "invalid plate / driver name".
func PadRightSpaceGBK(s string, totalBytes int) ([]byte, error) {
	encoded, err := GBKEncode(s)
	if err != nil {
		return nil, err
	}
	if len(encoded) > totalBytes {
		return nil, fmt.Errorf("jtcommon: GBK-encoded length %d exceeds %d", len(encoded), totalBytes)
	}
	out := make([]byte, totalBytes)
	for i := range out {
		out[i] = 0x20
	}
	copy(out, encoded)
	return out, nil
}

// PadRightGBK encodes s as GBK and right-pads the encoded bytes with 0x00
// until totalBytes. It returns an error if the encoded value exceeds the
// width (design §11.1).
//
// IMPORTANT: JT809 VehiclePlate and JTT905 DriverName/VehicleModel/
// LicensePlate fields require 0x20 (space) fill, NOT 0x00 — for those,
// use PadRightSpaceGBK. PadRightGBK is appropriate only for byte fields
// that genuinely want zero-padding (e.g. fixed-length numeric fields
// that allow zero as a legitimate "absent" value, or JT809 UserName /
// Password ASCII fields).
func PadRightGBK(s string, totalBytes int) ([]byte, error) {
	encoded, err := GBKEncode(s)
	if err != nil {
		return nil, err
	}
	if len(encoded) > totalBytes {
		return nil, fmt.Errorf("jtcommon: GBK-encoded length %d exceeds %d", len(encoded), totalBytes)
	}
	out := make([]byte, totalBytes)
	copy(out, encoded)
	return out, nil
}

// PadRightZeroASCII right-pads an ASCII string with 0x00 bytes to width.
// Used for JT809 UserName (5B) / Password (10B) and JT808 ManufacturerId
// (5B) / TerminalId (7B) — these are ASCII fields padded with 0x00 when
// the user-supplied value is shorter than the fixed width.
func PadRightZeroASCII(s string, width int) []byte {
	out := make([]byte, width)
	copy(out, []byte(s))
	return out
}

// EncodeTimeBCD encodes a "YYMMDDhhmmss" string into 6-byte BCD (design
// §11.1). The input MUST be exactly 12 digits. The 2-digit year is taken
// as-is (the standard does not define a century pivot; callers should
// pass the year they intend to encode). Time is Beijing time (UTC+8).
//
// Validation: length 12, all digits, month 01-12, day 01-31, hour 00-23,
// minute 00-59, second 00-60 (leap-second tolerant). Year 00-99 allowed.
func EncodeTimeBCD(s string) ([]byte, error) {
	if len(s) != 12 {
		return nil, fmt.Errorf("jtcommon: time BCD length %d != 12", len(s))
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return nil, fmt.Errorf("jtcommon: time BCD non-digit at %d", i)
		}
	}
	month, _ := strconv.Atoi(s[2:4])
	day, _ := strconv.Atoi(s[4:6])
	hh, _ := strconv.Atoi(s[6:8])
	mm, _ := strconv.Atoi(s[8:10])
	ss, _ := strconv.Atoi(s[10:12])
	if month < 1 || month > 12 {
		return nil, fmt.Errorf("jtcommon: month %d out of range", month)
	}
	if day < 1 || day > 31 {
		return nil, fmt.Errorf("jtcommon: day %d out of range", day)
	}
	if hh > 23 {
		return nil, fmt.Errorf("jtcommon: hour %d out of range", hh)
	}
	if mm > 59 {
		return nil, fmt.Errorf("jtcommon: minute %d out of range", mm)
	}
	if ss > 60 {
		return nil, fmt.Errorf("jtcommon: second %d out of range", ss)
	}
	return BCDEncode(s)
}

// ParseTimeBCD parses a 6-byte BCD "YYMMDDhhmmss" into time.Time. The
// year is interpreted as 2000+YY (so "24" → 2024). Location is set to
// Beijing time (UTC+8) per design §4A.3.
func ParseTimeBCD(b []byte) (time.Time, error) {
	if len(b) != 6 {
		return time.Time{}, fmt.Errorf("jtcommon: time BCD length %d != 6", len(b))
	}
	s := BCDDecode(b)
	if len(s) != 12 {
		return time.Time{}, fmt.Errorf("jtcommon: decoded BCD length %d != 12", len(s))
	}
	// Reject nibbles that decoded to '?'.
	for i := 0; i < 12; i++ {
		if s[i] == '?' {
			return time.Time{}, fmt.Errorf("jtcommon: invalid BCD nibble in time")
		}
	}
	year, _ := strconv.Atoi(s[0:2])
	month, _ := strconv.Atoi(s[2:4])
	day, _ := strconv.Atoi(s[4:6])
	hh, _ := strconv.Atoi(s[6:8])
	mm, _ := strconv.Atoi(s[8:10])
	ss, _ := strconv.Atoi(s[10:12])
	loc, err := time.LoadLocation("Asia/Shanghai")
	if err != nil {
		loc = time.FixedZone("CST", 8*3600)
	}
	t := time.Date(2000+year, time.Month(month), day, hh, mm, ss, 0, loc)
	return t, nil
}

// MustParseHex parses a hex string (no spaces) into []byte. Panics on
// error. For test-only use (design §11.4).
func MustParseHex(s string) []byte {
	b, err := hexDecode(s)
	if err != nil {
		panic(err)
	}
	return b
}

// HexEqual compares a []byte to a hex string (no spaces). Returns true
// when the decoded hex matches the byte slice exactly (design §11.4).
func HexEqual(b []byte, hexStr string) bool {
	expected, err := hexDecode(hexStr)
	if err != nil {
		return false
	}
	if len(b) != len(expected) {
		return false
	}
	for i := range b {
		if b[i] != expected[i] {
			return false
		}
	}
	return true
}

// MustBCD encodes a 12-digit string to BCD, panicking on error. Test-only.
func MustBCD(s string) []byte {
	b, err := BCDEncode(s)
	if err != nil {
		panic(err)
	}
	return b
}

// hexDecode decodes a hex string (no spaces, case-insensitive) to bytes.
// Mirrors encoding/hex.DecodeString but is local to avoid an extra import.
func hexDecode(s string) ([]byte, error) {
	if len(s)%2 != 0 {
		return nil, fmt.Errorf("jtcommon: odd hex length %d", len(s))
	}
	out := make([]byte, len(s)/2)
	for i := 0; i < len(s); i += 2 {
		hi, err := hexNibble(s[i])
		if err != nil {
			return nil, err
		}
		lo, err := hexNibble(s[i+1])
		if err != nil {
			return nil, err
		}
		out[i/2] = (hi << 4) | lo
	}
	return out, nil
}

func hexNibble(c byte) (byte, error) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', nil
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, nil
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, nil
	}
	return 0, fmt.Errorf("jtcommon: invalid hex char 0x%02x", c)
}

// PutUint16BE writes a big-endian uint16 into b[0:2].
func PutUint16BE(b []byte, v uint16) {
	binary.BigEndian.PutUint16(b, v)
}

// PutUint32BE writes a big-endian uint32 into b[0:4].
func PutUint32BE(b []byte, v uint32) {
	binary.BigEndian.PutUint32(b, v)
}
