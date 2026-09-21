package jtcommon

// D-JT809-1 裁定2 金向量：SmallChi/JT809 自带单测 0x1001 主链登录例逐字节
// 程序化转录（上游 Assert.Equal 钉死，为库权威）。锚定三件事：
//   1) CRC809 = CRC-16 poly 0x1021 init 0xFFFF，对未转义 头+体 计算（不含
//      CRC 自身与首尾标识）——对齐库 WriteCRC16（Written.Slice(1)）。
//   2) MsgLength 语义 = 整帧总长（5B+头+体+CRC+5D）——对齐库
//      WriteInt32Return(位置+3)，非"头+体"字面读法。
//   3) 转义四规则单遍扫描（库 WriteEncode：CRC 之后对标识间整体转义）。
// 注：库 README 组包例（0x9400）经核算 MsgLength=146 与 帧长149/内容147/
// 内容去CRC 145 互斥，手拼不可靠，弃用作锚（D-JT809-1 P4 勘误）。

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

// SmallChi JT809_0x1001PackageTest.Test1 期望 hex，逐字节原样（无转义字节）。
const goldenWireHex = "5B000000480000008510010133EFB8010000000000270F0133EFB8" +
	"32303138303932303132372E302E302E31" +
	"0000000000000000000000000000000000000000000000" +
	"03296A915D"

func goldenWire(t *testing.T) []byte {
	t.Helper()
	wire, err := hex.DecodeString(goldenWireHex)
	if err != nil {
		t.Fatalf("golden hex: %v", err)
	}
	return wire
}

// 锚1：CRC 对 头+体（去 5B/5D/CRC）计算 = 线上 CRC（BE）。
func TestCRC809_GoldenVector(t *testing.T) {
	wire := goldenWire(t)
	content := wire[1 : len(wire)-1] // 头+体+CRC
	wantCRC := binary.BigEndian.Uint16(content[len(content)-2:])
	gotCRC := CRC809(content[:len(content)-2])
	if gotCRC != wantCRC {
		t.Fatalf("CRC809 = %04x, want %04x (SmallChi 0x1001 金向量)", gotCRC, wantCRC)
	}
}

// 锚2：MsgLength = 整帧总长（含 5B/5D 与 CRC），库语义非"头+体"。
func TestMsgLength_FullFrameSemantics(t *testing.T) {
	wire := goldenWire(t)
	msgLen := binary.BigEndian.Uint32(wire[1:5])
	if int(msgLen) != len(wire) {
		t.Fatalf("MsgLength=%d, 帧总长=%d：必须整帧长语义（库 WriteInt32Return(+3)）", msgLen, len(wire))
	}
}

// 锚3：转义四规则 + 单遍（转义产物不复扫——5A 01 原文序列只转义首个 5A）。
func TestEscape809_Rules(t *testing.T) {
	cases := []struct {
		in, want []byte
	}{
		{[]byte{0x5B}, []byte{0x5A, 0x01}},
		{[]byte{0x5A}, []byte{0x5A, 0x02}},
		{[]byte{0x5D}, []byte{0x5E, 0x01}},
		{[]byte{0x5E}, []byte{0x5E, 0x02}},
		// 单遍：0x5B 0x5A 0x01 → 5A01 5A02 01（产物 5A 01 不再转义）
		{[]byte{0x5B, 0x5A, 0x01}, []byte{0x5A, 0x01, 0x5A, 0x02, 0x01}},
		{[]byte{0xAA, 0x00}, []byte{0xAA, 0x00}}, // 普通字节原样
	}
	for i, c := range cases {
		got := Escape809(c.in)
		if !bytes.Equal(got, c.want) {
			t.Fatalf("case %d Escape(% x) = % x, want % x", i, c.in, got, c.want)
		}
	}
}

// 锚3补：反转义回程 + 原文无特殊字节恒等。
func TestUnescape809_Roundtrip(t *testing.T) {
	raw := []byte{0x01, 0x5B, 0x5A, 0x5D, 0x5E, 0x5A, 0x01, 0x5E, 0x02, 0xFF}
	esc := Escape809(raw)
	if bytes.Equal(esc, raw) {
		t.Fatal("escape must change buffer containing special bytes")
	}
	back := Unescape809(esc)
	if !bytes.Equal(back, raw) {
		t.Fatalf("roundtrip: got % x, want % x", back, raw)
	}
	plain := []byte{0x00, 0x11, 0x22}
	if got := Unescape809(Escape809(plain)); !bytes.Equal(got, plain) {
		t.Fatalf("plain roundtrip: % x", got)
	}
	// 孤立 5A/5E（后随非 01/02）按原样透传（宽松口径，与库 Decode 容错一致）。
	lone := []byte{0x5A, 0xFF, 0x5E, 0x00}
	if got := Unescape809(lone); !bytes.Equal(got, lone) {
		t.Fatalf("lone 5A/5E passthrough: % x", got)
	}
}
