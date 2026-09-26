// Package spnego — SPNEGO（RFC 4178，Simple and Protected GSS-API
// Negotiation）DER 编码原语（D-SPNEGO-1 #47）。
//
// 权威：design §10.3/§10.7/§12 DER 逐结构表（RFC 4178 §4.2–§4.2.2 +
// Appendix A / RFC 2478 §3.2.1 / RFC 2743 §3.1 / X.690）。全
// definite-length 恒定（X.690——indefinite/非最短形→负例 #16）。
//
// 本文件只产 DER 字节，不管载体（HTTP base64 包装 / 裸 TCP 直发归
// builder.go 成帧）。
package spnego

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// ---- DER 原语（X.690；ntlm derLen/tlv 口径同款，spnego 侧独立副本）----

// derLen 编 definite-length 长度字节：短形 <0x80 / 长形 0x81（单字节）/
// 0x82（双字节，init 大包档）。>0xFFFF = 协议外（见大包守卫）。
func derLen(n int) []byte {
	switch {
	case n < 0x80:
		return []byte{byte(n)}
	case n <= 0xFF:
		return []byte{0x81, byte(n)}
	default:
		return []byte{0x82, byte(n >> 8), byte(n)}
	}
}

// tlv 是 tag + definite-length + content（显式 [n] wrapper 与 universal
// 结构共用——§10.8 裁定2 ①：[n] 内层 universal tag 原样保留）。
func tlv(tag byte, content []byte) []byte {
	out := make([]byte, 0, 3+len(content))
	out = append(out, tag)
	out = append(out, derLen(len(content))...)
	return append(out, content...)
}

// ---- OID（契约 §4：四个 DER 值逐字节钉，§10.7 附带实测/tshark OID 名库互证）----

// oidDER 是机制 OID 的 TLV 全字节（含 tag/len）：
// Kerberos V5（7 arc 组，9B value）/ msKrb5（arc 48018 双字节展开
// `82 F7 12`，与 Kerberos 的 `86 F7 12` 仅首字节差）/ NTLM（含 `82 37`
// 双字节 arc）/ SPNEGO（外层专用，不进 supportedMech）。
var oidDER = map[string][]byte{
	"1.2.840.113554.1.2.2":    {0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x12, 0x01, 0x02, 0x02},       // Kerberos V5（"KRB5 - Kerberos 5"）
	"1.2.840.48018.1.2.2":     {0x06, 0x09, 0x2A, 0x86, 0x48, 0x82, 0xF7, 0x12, 0x01, 0x02, 0x02},       // msKrb5（"MS KRB5 - Microsoft Kerberos 5"）
	"1.3.6.1.4.1.311.2.2.10":  {0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0A}, // NTLM（"NTLMSSP - Microsoft NTLM"）
	"1.3.6.1.5.5.2":           {0x06, 0x06, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x02},                          // SPNEGO（外层专用）
}

// Alias 是 OID 文本别名（契约 §2 oid_alias 行：别名不可改写线上 OID——
// 解析即规范形，线上恒为数字 OID DER）。
var oidAlias = map[string]string{
	"kerberos": "1.2.840.113554.1.2.2",
	"krb5":     "1.2.840.113554.1.2.2",
	"mskrb5":   "1.2.840.48018.1.2.2",
	"ms-krb5":  "1.2.840.48018.1.2.2",
	"ntlm":     "1.3.6.1.4.1.311.2.2.10",
	"spnego":   "1.3.6.1.5.5.2",
}

// resolveOID 文本→规范 OID 再→ DER bytes（未知=机制错，#18 通道）。
func resolveOID(text string) ([]byte, error) {
	t := strings.TrimSpace(text)
	if t == "" {
		return nil, fmt.Errorf("spnego: empty mechanism OID (oid)")
	}
	if canon, ok := oidAlias[strings.ToLower(t)]; ok {
		t = canon
	}
	if der, ok := oidDER[t]; ok {
		return der, nil
	}
	return nil, fmt.Errorf("spnego: unknown mechanism OID %q (oid)", text)
}

// ---- reqFlags（契约 §3 reqFlags 行：RFC 4178 §4.2.1 位定义，DER 截尾零位）----

// contextFlagsContent 编掩码为 BIT STRING 的**内容**字节（未用位数 + 值
// 字节）。线形钉死 `03 02 00 C0`（§12 dissector 兼容约束逐字：`reqFlags=
// `A1{03 02 00 C0}``，§10.7 M-shape-1 实测干净解出 reqFlags=c0 +
// delegFlag/mutualFlag=1）。
//
// 截尾按 §12 锚在**字节**级（4 字节大端去**前导**零字节 + 未用位数 0）；
// RFC 4178 §4.2.1 的"截尾零位"（位级，`C0`→未用 6）会产出 `03 02 06 C0`，
// 与实测锚不符——锚优先（P5 先跑后钉时按落盘 pcap 复核）。
func contextFlagsContent(mask uint32) []byte {
	if mask == 0 {
		return []byte{0x00} // 空位串（未用位数 0、零值字节）
	}
	raw := []byte{byte(mask >> 24), byte(mask >> 16), byte(mask >> 8), byte(mask)}
	for len(raw) > 1 && raw[0] == 0 {
		raw = raw[1:]
	}
	return append([]byte{0x00}, raw...)
}

// ---- OCTET STRING / GeneralString / ENUMERATED ----

// octetString 编原始字节为 OCTET STRING TLV。
func octetString(b []byte) []byte { return tlv(0x04, b) }

// generalString 编 ASCII 提示名为 GeneralString TLV（tag 0x1B；negHints
// [0] 面）。
func generalString(s string) []byte { return tlv(0x1B, []byte(s)) }

// enumerated 编小整数为 ENUMERATED TLV（negState/negResult 面）。
func enumerated(v int) []byte { return tlv(0x0A, []byte{byte(v)}) }

// ---- fixtured opaque 负载（裁定5：无解密证据，线上为确定性占位字节）----

const fixtureByte = 0xA5 // opaque token/MIC fixture 占位字节（ntlm 同款口径）

// fixtureOpaque 产 n 字节确定性 opaque 负载。
func fixtureOpaque(n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = fixtureByte
	}
	return out
}

// hexBytes 解 hex fixture（hint_address 原始字节面）。
func hexBytes(s, what string) ([]byte, error) {
	raw, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("spnego: %s hex %q is not valid hex (%v) (length)", what, s, err)
	}
	return raw, nil
}
