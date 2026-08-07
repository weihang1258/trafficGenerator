package jtcommon

import (
	"bytes"
	"errors"
	"testing"
)

// TestEscapeRoundtrip (D-01) verifies Escape then Unescape restores the
// original bytes, covering a mix of 0x7e / 0x7d / ordinary bytes.
func TestEscapeRoundtrip(t *testing.T) {
	cases := []struct {
		name string
		raw  []byte
	}{
		{"empty", []byte{}},
		{"no_escape", []byte{0x01, 0x02, 0x03, 0xff}},
		{"single_7e", []byte{0x7e}},
		{"single_7d", []byte{0x7d}},
		{"mixed", []byte{0x7e, 0x01, 0x7d, 0x02, 0x7e, 0x7d}},
		{"consecutive_7e_7d", []byte{0x7e, 0x7d, 0x7e, 0x7d}},
		{"long", bytes.Repeat([]byte{0x7e, 0x7d, 0x01}, 50)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			escaped := Escape(tc.raw)
			// Verify no 0x7e survives in escaped form (must be 0x7d 0x02).
			for _, b := range escaped {
				if b == 0x7e {
					t.Fatalf("escaped output contains raw 0x7e: %x", escaped)
				}
			}
			round, err := Unescape(escaped)
			if err != nil {
				t.Fatalf("Unescape error: %v", err)
			}
			if !bytes.Equal(round, tc.raw) {
				t.Fatalf("roundtrip mismatch:\n in:  %x\n out: %x", tc.raw, round)
			}
		})
	}
}

// TestEscapeKnownVector verifies the exact escaped byte sequence.
func TestEscapeKnownVector(t *testing.T) {
	raw := []byte{0x7e, 0x7d, 0x01}
	escaped := Escape(raw)
	want := []byte{0x7d, 0x02, 0x7d, 0x01, 0x01}
	if !bytes.Equal(escaped, want) {
		t.Fatalf("Escape mismatch:\n want %x\n got  %x", want, escaped)
	}
}

// TestUnescapeInvalidSequence (D-10) verifies that 0x7d followed by
// anything other than 0x01/0x02 returns ErrInvalidEscape.
func TestUnescapeInvalidSequence(t *testing.T) {
	cases := [][]byte{
		{0x7d, 0x03}, // illegal
		{0x7d, 0x00}, // illegal
		{0x7d, 0xff}, // illegal
		{0x01, 0x7d}, // 0x7d at end (no trailing byte)
	}
	for i, in := range cases {
		_, err := Unescape(in)
		if err == nil {
			t.Fatalf("case %d: expected error, got nil (input %x)", i, in)
		}
	}
}

// TestXORChecksumKnownVector (D-02) verifies the XOR checksum of a known
// JT808 0x0100 header+body byte sequence matches the expected value.
func TestXORChecksumKnownVector(t *testing.T) {
	// From design §7A.14: 0x0100 register frame header (12B) + body (45B).
	// Header: 01 00 00 2d 01 23 45 67 89 01 00 01
	// Body (45B): 00 0b 00 00 54 45 53 54 00 54 47 2d 44 45 4d 4f 20 20 20 20
	//             20 20 20 20 20 20 20 20 20 30 30 30 30 30 30 31 01 be a9 41
	//             31 32 33 34 35
	// All bytes XOR'd → expected checksum byte.
	in := MustParseHex(
		"0100002d" + "012345678901" + "0001" +
			"000b" + "0000" + "5445535400" + "54472d44454d4f" +
			"20202020202020202020202020" + "30303030303031" +
			"01" + "bea9413132333435")
	if len(in) != 57 {
		t.Fatalf("test vector length %d != 57", len(in))
	}
	cs := XORChecksum(in)
	// Compute expected by hand: XOR all 57 bytes.
	var expected byte
	for _, b := range in {
		expected ^= b
	}
	if cs != expected {
		t.Fatalf("XORChecksum mismatch: want 0x%02x, got 0x%02x", expected, cs)
	}
	// XORChecksumGBK must produce the same result on identical bytes.
	if got := XORChecksumGBK(in); got != expected {
		t.Fatalf("XORChecksumGBK mismatch: want 0x%02x, got 0x%02x", expected, got)
	}
}

// TestBCDEncodeDecodeRoundtrip (D-03) verifies 12-digit ↔ 6-byte BCD.
func TestBCDEncodeDecodeRoundtrip(t *testing.T) {
	cases := []string{
		"012345678901",
		"000000000000", // D-13
		"999999999999", // D-14
		"013000000001", // D-15 leading zero
	}
	for _, s := range cases {
		b, err := BCDEncode(s)
		if err != nil {
			t.Fatalf("BCDEncode(%s) error: %v", s, err)
		}
		if len(b) != 6 {
			t.Fatalf("BCDEncode(%s) length %d != 6", s, len(b))
		}
		got := BCDDecode(b)
		if got != s {
			t.Fatalf("BCDDecode mismatch: want %s, got %s", s, got)
		}
	}
}

// TestBCDEncodeAllZeros (D-13) verifies "000000000000" → 6 bytes of 0x00.
func TestBCDEncodeAllZeros(t *testing.T) {
	b, err := BCDEncode("000000000000")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	for i, by := range b {
		if by != 0x00 {
			t.Fatalf("byte %d = 0x%02x, want 0x00", i, by)
		}
	}
}

// TestBCDEncodeAllNines (D-14) verifies "999999999999" → 6 bytes of 0x99.
func TestBCDEncodeAllNines(t *testing.T) {
	b, err := BCDEncode("999999999999")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	for i, by := range b {
		if by != 0x99 {
			t.Fatalf("byte %d = 0x%02x, want 0x99", i, by)
		}
	}
}

// TestBCDEncodeLeadingZero (D-15) verifies "013000000001" preserves leading
// zero: 0x01 0x30 0x00 0x00 0x00 0x01.
func TestBCDEncodeLeadingZero(t *testing.T) {
	b, err := BCDEncode("013000000001")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	want := []byte{0x01, 0x30, 0x00, 0x00, 0x00, 0x01}
	if !bytes.Equal(b, want) {
		t.Fatalf("BCD mismatch: want %x, got %x", want, b)
	}
}

// TestBCDEncodeInvalid rejects odd-length and non-digit inputs.
func TestBCDEncodeInvalid(t *testing.T) {
	cases := []string{
		"",     // empty string (length 0)
		"123",  // odd length 3
		"12ab56789012", // non-digit 'ab'
		"12345678901a", // non-digit '1a'
	}
	for _, s := range cases {
		_, err := BCDEncode(s)
		if err == nil {
			t.Fatalf("BCDEncode(%q) expected error, got nil", s)
		}
	}
}

// TestBCDEncodeEmptyString verifies that BCDEncode("") returns an error
// (not an empty byte slice). 空字符串是 BCD 非法输入之一，下游 (jt808/jt809/
// jtt905) 在写入电话号码 / IMEI / IMSI 等字段时若传入空串会生成零长度 BCD，
// 被对端平台判定为非法帧。修复点：jtcommon.BCDEncode 显式拦截 length 0。
func TestBCDEncodeEmptyString(t *testing.T) {
	b, err := BCDEncode("")
	if err == nil {
		t.Fatalf("BCDEncode(\"\") expected error, got nil (output=%x)", b)
	}
	if !errors.Is(err, ErrInvalidBCD) {
		t.Fatalf("BCDEncode(\"\") error = %v, want wraps ErrInvalidBCD", err)
	}
	if b != nil {
		t.Fatalf("BCDEncode(\"\") output = %x, want nil", b)
	}
}

// TestEncodeMsgBodyPropsAllVersions (D-04) verifies the bit layout for
// 2011/2013/2019 + encrypt + package + max length.
func TestEncodeMsgBodyPropsAllVersions(t *testing.T) {
	cases := []struct {
		bodyLen int
		version string
		pkg     uint8
		enc     uint8
		want    uint16
	}{
		{0, "2011", 0, 0, 0x0000},
		{0, "2013", 0, 0, 0x0400},
		{0, "2019", 0, 0, 0x0800},
		{5, "2019", 0, 0, 0x0805}, // body 5B + version 2019 (vf<<10 = 0x0800)
		{82, "2019", 0, 0, 0x0852},
		{1023, "2019", 0, 0, 0x0BFF},
		{45, "2011", 0, 0, 0x002d}, // 0x0100 body 45B
		{125, "2011", 0, 0, 0x007d}, // A-57 low-byte 0x7d test
		{100, "2019", 1, 0, 0x4864}, // package flag set
		{100, "2019", 0, 1, 0x8864}, // encrypt flag set
		{100, "2019", 1, 1, 0xC864}, // both flags
	}
	for _, tc := range cases {
		got, err := EncodeMsgBodyProps(tc.bodyLen, tc.version, tc.pkg, tc.enc)
		if err != nil {
			t.Fatalf("EncodeMsgBodyProps(%d,%s,%d,%d) error: %v",
				tc.bodyLen, tc.version, tc.pkg, tc.enc, err)
		}
		if got != tc.want {
			t.Fatalf("EncodeMsgBodyProps(%d,%s,%d,%d) = 0x%04x, want 0x%04x",
				tc.bodyLen, tc.version, tc.pkg, tc.enc, got, tc.want)
		}
		// Round-trip decode.
		bl, v, pf, ef := DecodeMsgBodyProps(got)
		if bl != tc.bodyLen || v != tc.version || pf != tc.pkg || ef != tc.enc {
			t.Fatalf("DecodeMsgBodyProps(0x%04x) = (%d,%s,%d,%d), want (%d,%s,%d,%d)",
				got, bl, v, pf, ef, tc.bodyLen, tc.version, tc.pkg, tc.enc)
		}
	}
}

// TestEncodeMsgBodyPropsErrors verifies out-of-range body length and
// unknown version strings are rejected.
func TestEncodeMsgBodyPropsErrors(t *testing.T) {
	if _, err := EncodeMsgBodyProps(-1, "2019", 0, 0); err == nil {
		t.Fatalf("negative body length expected error")
	}
	if _, err := EncodeMsgBodyProps(1024, "2019", 0, 0); err == nil {
		t.Fatalf("body length > 1023 expected error")
	}
	if _, err := EncodeMsgBodyProps(10, "2099", 0, 0); err == nil {
		t.Fatalf("unknown version expected error")
	}
	if _, err := EncodeMsgBodyProps(10, "2019", 2, 0); err == nil {
		t.Fatalf("pkgFlag=2 expected error")
	}
}

// TestGBKChineseRoundtrip (D-05) verifies "京A12345" ↔ GBK bytes.
func TestGBKChineseRoundtrip(t *testing.T) {
	encoded, err := GBKEncode("京A12345")
	if err != nil {
		t.Fatalf("GBKEncode error: %v", err)
	}
	// "京" in GBK is 0xBE 0xA9; "A12345" is 6 ASCII bytes.
	want := []byte{0xbe, 0xa9, 'A', '1', '2', '3', '4', '5'}
	if !bytes.Equal(encoded, want) {
		t.Fatalf("GBK encode mismatch: want %x, got %x", want, encoded)
	}
	decoded, err := GBKDecode(encoded)
	if err != nil {
		t.Fatalf("GBKDecode error: %v", err)
	}
	if decoded != "京A12345" {
		t.Fatalf("GBK decode mismatch: want %q, got %q", "京A12345", decoded)
	}
}

// TestGBKPureASCII (D-11) verifies pure-ASCII strings encode to all
// bytes < 0x80.
func TestGBKPureASCII(t *testing.T) {
	encoded, err := GBKEncode("ABC123")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	for i, b := range encoded {
		if b >= 0x80 {
			t.Fatalf("byte %d = 0x%02x >= 0x80", i, b)
		}
	}
	decoded, err := GBKDecode(encoded)
	if err != nil {
		t.Fatalf("GBKDecode error: %v", err)
	}
	if decoded != "ABC123" {
		t.Fatalf("roundtrip mismatch: want %q, got %q", "ABC123", decoded)
	}
}

// TestGBKPureChinese (D-12) verifies "张三" encodes to the expected GBK
// bytes (0xD5 0xC5 0xC8 0xFD).
func TestGBKPureChinese(t *testing.T) {
	encoded, err := GBKEncode("张三")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	want := []byte{0xd5, 0xc5, 0xc8, 0xfd}
	if !bytes.Equal(encoded, want) {
		t.Fatalf("GBK encode mismatch: want %x, got %x", want, encoded)
	}
}

// TestPadRightGBKExact (D-06) verifies that PadRightGBK does not pad
// when the encoded length equals the target width.
func TestPadRightGBKExact(t *testing.T) {
	out, err := PadRightGBK("ABC", 3)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	want := []byte{'A', 'B', 'C'}
	if !bytes.Equal(out, want) {
		t.Fatalf("mismatch: want %x, got %x", want, out)
	}
}

// TestPadRightGBKShort (D-07) verifies that PadRightGBK pads short GBK
// strings with 0x00 to the target width.
func TestPadRightGBKShort(t *testing.T) {
	out, err := PadRightGBK("AB", 5)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	want := []byte{'A', 'B', 0x00, 0x00, 0x00}
	if !bytes.Equal(out, want) {
		t.Fatalf("mismatch: want %x, got %x", want, out)
	}
}

// TestPadRightSpaceGBK verifies that PadRightSpaceGBK pads with 0x20.
func TestPadRightSpaceGBK(t *testing.T) {
	out, err := PadRightSpaceGBK("京A12345", 21)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(out) != 21 {
		t.Fatalf("length %d != 21", len(out))
	}
	// First 8 bytes = GBK encoded "京A12345".
	wantHead := []byte{0xbe, 0xa9, 'A', '1', '2', '3', '4', '5'}
	if !bytes.Equal(out[:8], wantHead) {
		t.Fatalf("head mismatch: want %x, got %x", wantHead, out[:8])
	}
	// Remaining 13 bytes must be 0x20 (space), NOT 0x00.
	for i := 8; i < 21; i++ {
		if out[i] != 0x20 {
			t.Fatalf("byte %d = 0x%02x, want 0x20 (space)", i, out[i])
		}
	}
}

// TestPadRightSpaceASCII verifies ASCII space padding.
func TestPadRightSpaceASCII(t *testing.T) {
	out := PadRightSpace("TG-DEMO", 20)
	if len(out) != 20 {
		t.Fatalf("length %d != 20", len(out))
	}
	wantHead := []byte("TG-DEMO")
	if !bytes.Equal(out[:7], wantHead) {
		t.Fatalf("head mismatch: want %x, got %x", wantHead, out[:7])
	}
	for i := 7; i < 20; i++ {
		if out[i] != 0x20 {
			t.Fatalf("byte %d = 0x%02x, want 0x20", i, out[i])
		}
	}
}

// TestPadRightZeroASCII verifies 0x00 padding for ASCII fields.
func TestPadRightZeroASCII(t *testing.T) {
	out := PadRightZeroASCII("TEST", 5)
	want := []byte{'T', 'E', 'S', 'T', 0x00}
	if !bytes.Equal(out, want) {
		t.Fatalf("mismatch: want %x, got %x", want, out)
	}
}

// TestTimeBCDRoundtrip (D-08) verifies "240803120000" ↔ 6-byte BCD.
func TestTimeBCDRoundtrip(t *testing.T) {
	b, err := EncodeTimeBCD("240803120000")
	if err != nil {
		t.Fatalf("EncodeTimeBCD error: %v", err)
	}
	want := []byte{0x24, 0x08, 0x03, 0x12, 0x00, 0x00}
	if !bytes.Equal(b, want) {
		t.Fatalf("mismatch: want %x, got %x", want, b)
	}
	t2, err := ParseTimeBCD(b)
	if err != nil {
		t.Fatalf("ParseTimeBCD error: %v", err)
	}
	// Year 24 → 2024.
	if t2.Year() != 2024 {
		t.Fatalf("year = %d, want 2024", t2.Year())
	}
	if int(t2.Month()) != 8 {
		t.Fatalf("month = %d, want 8", int(t2.Month()))
	}
	if t2.Day() != 3 {
		t.Fatalf("day = %d, want 3", t2.Day())
	}
	if t2.Hour() != 12 {
		t.Fatalf("hour = %d, want 12", t2.Hour())
	}
}

// TestTimeBCDInvalid (D-09) rejects malformed time strings.
func TestTimeBCDInvalid(t *testing.T) {
	cases := []string{
		"",
		"24080312000",    // 11 digits
		"2408031200000",  // 13 digits
		"24-08-03 12:00", // non-digit
		"241303120000",   // month 13
		"240832120000",   // day 32
		"240803250000",   // hour 25
		"240803126000",   // minute 60
		"240803120061",   // second 61
	}
	for _, s := range cases {
		_, err := EncodeTimeBCD(s)
		if err == nil {
			t.Fatalf("EncodeTimeBCD(%q) expected error", s)
		}
	}
}

// TestMustParseHex verifies the test helper.
func TestMustParseHex(t *testing.T) {
	got := MustParseHex("010203ff")
	want := []byte{0x01, 0x02, 0x03, 0xff}
	if !bytes.Equal(got, want) {
		t.Fatalf("mismatch: want %x, got %x", want, got)
	}
}

// TestHexEqual verifies the test helper.
func TestHexEqual(t *testing.T) {
	if !HexEqual([]byte{0x01, 0x02}, "0102") {
		t.Fatalf("HexEqual should return true")
	}
	if HexEqual([]byte{0x01, 0x02}, "0103") {
		t.Fatalf("HexEqual should return false")
	}
	if HexEqual([]byte{0x01}, "0102") {
		t.Fatalf("HexEqual should return false (length mismatch)")
	}
}

// TestMustBCD verifies the test helper.
func TestMustBCD(t *testing.T) {
	got := MustBCD("012345678901")
	want := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0x01}
	if !bytes.Equal(got, want) {
		t.Fatalf("mismatch: want %x, got %x", want, got)
	}
}
