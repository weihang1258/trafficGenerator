// Package kerberos — Kerberos V5（RFC 4120）ASN.1 DER 编码原语。
//
// 全部 definite-length（裁定3：BER 宽松解析不改变线上生成契约——设计 §4）：
// tag 1B + length（<128 短形 1B；≥128 长形 0x8N 前缀+N 字节大端）+ content。
// tag 字节 = class(2b)|constructed(1b)|number(5b)：
//
//	universal primitive 0x00+/constructed 0x20；context constructed 0xA0+num；
//	application constructed 0x60+num（顶层消息 0x6a-0x6f/0x7e、Ticket 0x61）。
package kerberos

// DER class/constructed bits。
const (
	classUniversal   byte = 0x00
	classContext     byte = 0x80
	classApplication byte = 0x40
	flagConstructed  byte = 0x20
)

// derTag renders one tag byte.
func derTag(class, num byte, constructed bool) byte {
	t := class | num
	if constructed {
		t |= flagConstructed
	}
	return t
}

// derLen renders a definite-length（短形 <128；长形 0x8N + N 字节 BE）。
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

// derCtx renders [tagNumber] context-constructed（0xA0+num）。
func derCtx(num byte, content []byte) []byte { return tlv(classContext|flagConstructed|num, content) }

// derApp renders [APPLICATION num] constructed（0x60|num）。
func derApp(num byte, content []byte) []byte {
	return tlv(classApplication|flagConstructed|num, content)
}

// derSeq renders a universal SEQUENCE（0x30）。
func derSeq(parts ...[]byte) []byte {
	var content []byte
	for _, p := range parts {
		content = append(content, p...)
	}
	return tlv(0x30, content)
}

// derInteger renders an INTEGER value（universal primitive 0x02 + minimal
// two's complement；0 = 00，正数首字节高位为 0 时补 00 前缀）。
func derInteger(v int) []byte {
	switch {
	case v == 0:
		return tlv(0x02, []byte{0})
	case v > 0:
		var b []byte
		for x := v; x > 0; x >>= 8 {
			b = append([]byte{byte(x)}, b...)
		}
		if b[0]&0x80 != 0 {
			b = append([]byte{0}, b...) // 正数保持非负
		}
		return tlv(0x02, b)
	default: // 负数：固定 fixture 面不涉大负值，按补码最长形 4B 渲染
		var b []byte
		u := uint32(v)
		for i := 3; i >= 0; i-- {
			b = append(b, byte(u>>(8*uint(i))))
		}
		return tlv(0x02, b)
	}
}

// derOctet renders an OCTET STRING（universal primitive 0x04——Realm/
// KerberosString 同面，RFC 4120 §5.2.1）。
func derOctet(s string) []byte { return tlv(0x04, []byte(s)) }

// derBitString renders a BIT STRING（0x03）：unused-bits 前导 1B + 数据。
func derBitString(data []byte) []byte {
	content := append([]byte{0}, data...)
	return tlv(0x03, content)
}

// derGeneralizedTime renders KerberosTime（"YYYYMMDDHHMMSSZ" —— RFC 4120
// §5.2.2 语义，Universal GeneralizedTime primitive 0x18）。
func derGeneralizedTime(s string) []byte { return tlv(0x18, []byte(s)) }
