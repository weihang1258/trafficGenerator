// Package ocsp — OCSP（RFC 6960/RFC 8954）ASN.1 DER 编码原语。
//
// 全部 definite-length（X.690 §10：短形 <128 用 1B，长形 0x81/0x82 前缀 +
// 大端长度；§11：最短形式、INTEGER 最短补码、DEFAULT 值不编码）。tag 字节
// = class(2b)|constructed(1b)|number(5b)：
//
//	universal primitive 0x00+/constructed 0x20；context primitive 0x80+num；
//	context constructed 0xA0+num（EXPLICIT wrapper 与 IMPLICIT 构造型同形）。
//
// 载体无关：本文件只产 DER 字节，分帧（HTTP body / 裸 TCP）在 builder.go。
package ocsp

// DER class/constructed bits。
const (
	flagConstructed byte = 0x20
	classContext    byte = 0x80
	octetTag        byte = 0x04
	intTag          byte = 0x02
	seqTag          byte = 0x30
)

// derLen renders a definite-length（短形 <128；长形 0x8N + N 字节 BE——
// X.690 §10.1 最短形）。
func derLen(n int) []byte {
	switch {
	case n < 0x80:
		return []byte{byte(n)}
	case n <= 0xFF:
		return []byte{0x81, byte(n)}
	case n <= 0xFFFF:
		return []byte{0x82, byte(n >> 8), byte(n)}
	default:
		return []byte{0x83, byte(n >> 16), byte(n >> 8), byte(n)}
	}
}

// tlv wraps content with tag+length（一切 DER 元素的原语）。
func tlv(tag byte, content []byte) []byte {
	out := make([]byte, 0, 1+len(content)+4)
	out = append(out, tag)
	out = append(out, derLen(len(content))...)
	return append(out, content...)
}

// derSeq renders a universal SEQUENCE（0x30）。
func derSeq(parts ...[]byte) []byte {
	var content []byte
	for _, p := range parts {
		content = append(content, p...)
	}
	return tlv(seqTag, content)
}

// derOctet renders an OCTET STRING（0x04——issuer hashes/signature/blob 面）。
func derOctet(b []byte) []byte { return tlv(octetTag, b) }

// derInteger renders a non-negative INTEGER（最短二补码：0 = 00；正数首字节
// 高位为 1 时补 00 前缀——X.690 §8.3.2；serialNumber 非负，契约 §3）。
func derInteger(v int) []byte {
	if v <= 0 {
		return tlv(intTag, []byte{0})
	}
	var b []byte
	for x := v; x > 0; x >>= 8 {
		b = append([]byte{byte(x)}, b...)
	}
	if b[0]&0x80 != 0 {
		b = append([]byte{0}, b...)
	}
	return tlv(intTag, b)
}

// derEnum renders an ENUMERATED（0x0A——responseStatus，X.690 §8.4 取值域
// 同 INTEGER 的最短编码）。
func derEnum(v int) []byte { return tlv(0x0A, derInteger(v)[2:]) }

// derBitString renders a BIT STRING（0x03）：unused-bits 前导 1B + 数据。
func derBitString(data []byte, unused byte) []byte {
	content := make([]byte, 0, len(data)+1)
	content = append(content, unused)
	content = append(content, data...)
	return tlv(0x03, content)
}

// derGeneralizedTime renders GeneralizedTime（0x18，"YYYYMMDDHHMMSSZ"——
// RFC 5280 §4.1.2.5.2，producedAt/thisUpdate/nextUpdate，契约 §4）。
func derGeneralizedTime(s string) []byte { return tlv(0x18, []byte(s)) }

// derUTCTime renders UTCTime（0x17，"YYMMDDHHMMSSZ"——X.509 证书 validity
// fixture 面）。
func derUTCTime(s string) []byte { return tlv(0x17, []byte(s)) }

// derPrintable 是 DirectoryString PrintableString 面（证书 DN CN fixture）。
func derPrintable(s string) []byte { return tlv(0x13, []byte(s)) }

// derCtxExplicit renders [num] EXPLICIT（context constructed 0xA0+num——
// wrapper 长度只覆盖自身内容，契约 §3）。
func derCtxExplicit(num byte, content []byte) []byte {
	return tlv(classContext|flagConstructed|num, content)
}

// derCtxImplicitPrim renders [num] IMPLICIT 基本类型（context primitive
// 0x80+num——CertStatus good[0]/unknown[2]、GeneralName rfc822Name [1]）。
func derCtxImplicitPrim(num byte, content []byte) []byte {
	return tlv(classContext|num, content)
}

// derCtxImplicitCons renders [num] IMPLICIT 构造型（0xA0+num——CertStatus
// revoked [1] IMPLICIT RevokedInfo：内容 = RevokedInfo 的 SEQUENCE 内容，
// 不带内层 0x30，契约 §4）。
func derCtxImplicitCons(num byte, content []byte) []byte {
	return tlv(classContext|flagConstructed|num, content)
}
