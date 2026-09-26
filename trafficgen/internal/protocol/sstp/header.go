// Package sstp — SSTP（Secure Socket Tunneling Protocol，MS-SSTP）终结层。
//
// Register* functions run at init() time (in builder.go), wiring the sstp
// layer into the chain planner and generator factory. The side-effect import
// _ "…/protocol/sstp" activates this registration.
//
// 层链 [ip → tcp → tls → sstp]（DependsOn ["tls"]；FieldContract
// tcp.dst_port=443——tshark tls dissector 自动解码依赖）。sstp 不产包：
// 它产出 SSTP message 事件流，经 tls 变换器包成 application-data record，
// 再由 tcp 层按 MSS 成段（契约 §5：TLS record/TCP segment 边界 ≠ SSTP
// Length 边界）。
//
// 本文件是 header/属性编码原语（唯一字节权威）：Version 0x10 恒定、
// C bit、Reserved4+Length12 网络序（Length 覆盖整包，含 4B common header）、
// Message Type 9 枚举、Attribute ID 0x01–0x04、LengthPacket 含 4B 属性头。
package sstp

import (
	"encoding/binary"
	"fmt"
)

// SSTP 线格式常量（MS-SSTP §2.2）。
const (
	// versionByte 是 Version 字段唯一合法值：高 4 bits MAJOR=1、低 4 bits
	// MINOR=0（MS-SSTP §2.2.1）。他版本拒（契约 §12-1 单版本协议）。
	versionByte = 0x10
	// maxLength12 是 R(4)+Length(12) 的 12-bit 上限：Length 覆盖整包，含
	// 4-byte common header（MS-SSTP §2.2.1/§2.2.2）。
	maxLength12 = 0x0FFF
	// commonHeaderLen / controlFixedLen 是 4-byte common header 与"无属性
	// 控制包"的 8-byte 固定部（4B common + Message Type 2B + Num Attributes 2B）。
	commonHeaderLen = 4
	controlFixedLen = 8
	// attributeHeaderLen 是属性头固定 4 bytes（Reserved(1) + Attribute ID(1)
	// + R(4)+LengthPacket(12)）；LengthPacket 含这 4 bytes。
	attributeHeaderLen = 4
)

// Message Type 9 枚举（MS-SSTP §2.2.2 全表；未知值拒）。
const (
	msgCallConnectRequest = 0x0001
	msgCallConnectAck     = 0x0002
	msgCallConnectNak     = 0x0003
	msgCallConnected      = 0x0004
	msgCallAbort          = 0x0005
	msgCallDisconnect     = 0x0006
	msgCallDisconnectAck  = 0x0007
	msgEchoRequest        = 0x0008
	msgEchoResponse       = 0x0009
)

// Attribute ID 4 枚举（MS-SSTP §2.2.5–§2.2.8）。0x0005/0x0006 是 Message
// Type 值，不是属性 ID（契约 §4 末段）。
const (
	attrEncapsulatedProtocolID = 0x01
	attrStatusInfo             = 0x02
	attrCryptoBinding          = 0x03
	attrCryptoBindingRequest   = 0x04
)

// kindTable 是 kind→(Message Type, 是否控制包) 权威映射（MS-SSTP §2.2.2/
// §2.2.3 九控制消息 + C=0 数据包）：C bit 由 kind 派生，故"C bit↔Message
// Type 一致性"在生成侧恒成立，配置面的不一致（控制 kind 带 ppp / data
// kind 带 attributes）由守卫拒（planner.go）。
var kindTable = map[string]struct {
	msgType uint16
	control bool
}{
	"call_connect_request": {msgCallConnectRequest, true},
	"call_connect_ack":     {msgCallConnectAck, true},
	"call_connect_nak":     {msgCallConnectNak, true},
	"call_connected":       {msgCallConnected, true},
	"call_abort":           {msgCallAbort, true},
	"call_disconnect":      {msgCallDisconnect, true},
	"call_disconnect_ack":  {msgCallDisconnectAck, true},
	"echo_request":         {msgEchoRequest, true},
	"echo_response":        {msgEchoResponse, true},
	"ppp_data":             {0, false},
}

// 属性固定/区间长度（MS-SSTP §2.2.5–§2.2.8）：
//   - 0x01 Encapsulated Protocol ID：Length=0x006（value 2B Protocol ID）
//   - 0x02 Status Info：Length = AttribValue + 12（Reserved1 3B + AttribID 1B
//     + Status 4B + AttribValue nB），AttribValue ≤ 64 → Length ∈ [12, 76]
//   - 0x03 Crypto Binding：Length=0x068（104，SHA-256 profile；SHA-1 用
//     Padding 补足同长——不得截断）
//   - 0x04 Crypto Binding Request：Length=0x028（40，含 hash bitmask + 32B nonce）
const (
	encapsulatedProtocolIDLen = 6
	statusInfoMinLen          = 12
	statusInfoMaxLen          = 76
	cryptoBindingLen          = 104
	cryptoBindingRequestLen   = 40
	// nonceLen 是 Crypto Binding / Binding Request 的 32-byte nonce。
	nonceLen = 32
)

// LengthPacket 打包：R(4 bits) 保留置 0 + Length(12 bits) 网络序（MS-SSTP
// §2.2.1–§2.2.8 每个长度字段都是这一形状）。超 12 bits 拒——绝不静默截断。
func putLength12(dst []byte, n int) error {
	if n < 0 || n > maxLength12 {
		return fmt.Errorf("sstp: length %d out of range (R(4)+Length(12) field, max %d)", n, maxLength12)
	}
	binary.BigEndian.PutUint16(dst, uint16(n)&maxLength12)
	return nil
}

// encodeControlPacket 组一条控制包：4B common header（Version 0x10 | Reserved7
// +C=1 | R4+Length12）+ Message Type(2) + Num Attributes(2) + attributes。
// Length 覆盖整包（含 4B 头）——契约 §3/§4 恒定。
func encodeControlPacket(msgType uint16, attributes [][]byte) ([]byte, error) {
	total := controlFixedLen
	for _, a := range attributes {
		total += len(a)
	}
	out := make([]byte, controlFixedLen, total)
	out[0] = versionByte
	out[1] = 0x01 // Reserved(7)=0 + C=1（控制包）
	if err := putLength12(out[2:4], total); err != nil {
		return nil, err
	}
	binary.BigEndian.PutUint16(out[4:6], msgType)
	binary.BigEndian.PutUint16(out[6:8], uint16(len(attributes))) // Num Attributes ↔ 实数由 verifyControlPacket 回读复核
	for _, a := range attributes {
		out = append(out, a...)
	}
	if err := verifyControlPacket(out, msgType, len(attributes)); err != nil {
		return nil, err
	}
	return out, nil
}

// encodeDataPacket 组一条 C=0 数据包：4B common header（C=0）+ PPP frame。
// C=0 时 S+4 即 PPP 帧起点（`ff 03`，契约 §3 表 + RFC 1661）——不写
// Message Type/Num Attributes（契约 §3："C=0 时此处直接是 PPP data"）。
func encodeDataPacket(pppFrame []byte) ([]byte, error) {
	total := commonHeaderLen + len(pppFrame)
	out := make([]byte, commonHeaderLen, total)
	out[0] = versionByte
	out[1] = 0x00 // Reserved(7)=0 + C=0（数据包）
	if err := putLength12(out[2:4], total); err != nil {
		return nil, err
	}
	out = append(out, pppFrame...)
	return out, nil
}

// verifyControlPacket 回读自产控制包（双算复核，不是解析器）：
// Length == len(packet)、C bit == 1、Num Attributes == 属性实数、每个属性头
// 的 Reserved==0 / ID ∈ {0x01..0x04} / LengthPacket ∈ [4, 剩余] 且逐项累加
// 恰好铺满 (Length - 8)。任何一条不成立都是内部编码错（绝不产出结构自相
// 矛盾的控制包——契约 §17 错误分支②Length↔内容/Num↔实数守卫）。
func verifyControlPacket(pkt []byte, msgType uint16, numAttrs int) error {
	if len(pkt) < controlFixedLen {
		return fmt.Errorf("sstp: control packet %d bytes is shorter than the 8-byte control header (header)", len(pkt))
	}
	if pkt[0] != versionByte {
		return fmt.Errorf("sstp: control packet version 0x%02x, want 0x%02x (header)", pkt[0], versionByte)
	}
	if pkt[1]&0x01 != 0x01 {
		return fmt.Errorf("sstp: control packet C bit is 0 (header)")
	}
	if got := int(binary.BigEndian.Uint16(pkt[2:4]) & maxLength12); got != len(pkt) {
		return fmt.Errorf("sstp: packet Length %d does not cover the %d-byte packet (length)", got, len(pkt))
	}
	if got := int(binary.BigEndian.Uint16(pkt[4:6])); got != int(msgType) {
		return fmt.Errorf("sstp: packet Message Type 0x%04x, want 0x%04x (header)", got, msgType)
	}
	if got := int(binary.BigEndian.Uint16(pkt[6:8])); got != numAttrs {
		return fmt.Errorf("sstp: Num Attributes %d does not match the %d encoded attributes (attribute)", got, numAttrs)
	}
	off, seen := controlFixedLen, 0
	for off < len(pkt) {
		if off+attributeHeaderLen > len(pkt) {
			return fmt.Errorf("sstp: attribute header truncated at offset %d (attribute)", off)
		}
		if pkt[off] != 0 {
			return fmt.Errorf("sstp: attribute Reserved byte 0x%02x is not zero (attribute)", pkt[off])
		}
		id := pkt[off+1]
		if id < attrEncapsulatedProtocolID || id > attrCryptoBindingRequest {
			return fmt.Errorf("sstp: attribute ID 0x%02x is not a valid attribute ID (0x01..0x04) (attribute)", id)
		}
		alen := int(binary.BigEndian.Uint16(pkt[off+2:off+4]) & maxLength12)
		if alen < attributeHeaderLen || off+alen > len(pkt) {
			return fmt.Errorf("sstp: attribute LengthPacket %d out of range at offset %d (length)", alen, off)
		}
		off += alen
		seen++
	}
	if seen != numAttrs {
		return fmt.Errorf("sstp: parsed %d attributes but Num Attributes says %d (attribute)", seen, numAttrs)
	}
	return nil
}

// encodeAttribute 组一条属性：Reserved(1)=0 | Attribute ID(1) | R(4)+
// LengthPacket(12)（含 4B 属性头）| Value。
func encodeAttribute(id byte, value []byte) ([]byte, error) {
	total := attributeHeaderLen + len(value)
	out := make([]byte, attributeHeaderLen, total)
	out[0] = 0 // Reserved 发送时为 0
	out[1] = id
	if err := putLength12(out[2:4], total); err != nil {
		return nil, err
	}
	return append(out, value...), nil
}

// —— 属性 value 编码（MS-SSTP §2.2.5–§2.2.8）——

// encapsulatedProtocolIDValue 是 Encapsulated Protocol ID 的 value：2 bytes
// Protocol ID，本版唯一合法值 0x0001（SSTP_ENCAPSULATED_PROTOCOL_PPP）。
func encapsulatedProtocolIDValue() []byte { return []byte{0x00, 0x01} }

// statusInfoValue 是 Status Info 的 value：Reserved1(3, 零) + AttribID(1) +
// Status(4) + AttribValue(n)。
func statusInfoValue(attrID byte, status uint32, attribValue []byte) []byte {
	out := make([]byte, 0, 8+len(attribValue))
	out = append(out, 0x00, 0x00, 0x00, attrID)
	var st [4]byte
	binary.BigEndian.PutUint32(st[:], status)
	out = append(out, st[:]...)
	return append(out, attribValue...)
}

// cryptoBindingValue 是 Crypto Binding 的 value（SHA-256 profile）：
// Reserved1(3) + Hash Protocol(1) + Nonce(32) + Cert Hash(32) + Compound
// MAC(32) = 100 bytes（+4B 头 = 104，MS-SSTP §2.2.7 的 MUST 0x068）。
// 密文/摘要面 opaque：确定性填充，不伪造密码学语义（契约 §2 证据红线）。
func cryptoBindingValue(hashProtocol byte, nonce, certHash, compoundMAC []byte) []byte {
	out := make([]byte, 0, cryptoBindingLen-attributeHeaderLen)
	out = append(out, 0x00, 0x00, 0x00, hashProtocol)
	out = append(out, nonce...)
	out = append(out, certHash...)
	return append(out, compoundMAC...)
}

// cryptoBindingRequestValue 是 Crypto Binding Request 的 value：
// Reserved1(3) + Hash Protocol Bitmask(1) + Nonce(32) = 36 bytes（+4B 头
// = 40，MS-SSTP §2.2.6 的 MUST 0x028）。
func cryptoBindingRequestValue(bitmask byte, nonce []byte) []byte {
	out := make([]byte, 0, cryptoBindingRequestLen-attributeHeaderLen)
	out = append(out, 0x00, 0x00, 0x00, bitmask)
	return append(out, nonce...)
}

// —— PPP 帧编码（RFC 1661；契约 §7）——

// PPP protocol 字段枚举（RFC 1661 / RFC 1700）：IPv4 0x0021 / IPv6 0x0057；
// MPPE 加密的 information 用 0x00FD（RFC 3078 压缩加密数据报）。
const (
	pppProtocolIPv4 = 0x0021
	pppProtocolIPv6 = 0x0057
	pppProtocolMPPE = 0x00FD
)

// encodePPPFrame 组 PPP 帧：Address 0xff | Control 0x03 | Protocol(2) |
// Information（默认 uncompressed framing——契约 §7 正例固定断言 ff 03；
// 压缩形必须显式声明，本版只承认 uncompressed）。
//
// MPPE（RFC 3078）只改变 information 的加密表示：帧结构、protocol 语义与
// SSTP Length 均不变（契约 §7），故此处与明文同路，只由调用方换 protocol。
func encodePPPFrame(protocol uint16, info []byte) []byte {
	out := make([]byte, 0, 4+len(info))
	out = append(out, 0xFF, 0x03)
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], protocol)
	out = append(out, pb[:]...)
	return append(out, info...)
}

// encodeCompressedPPPFrame 组 address/control-compressed 帧（缺 ff 03）：
// 负例面——契约 §7"若 profile 显式启用 address/control/protocol compression，
// 必须单独声明并更新断言，不能隐式切换"，本版无该 profile，出现即拒。
func encodeCompressedPPPFrame(protocol uint16, info []byte) []byte {
	out := make([]byte, 0, 2+len(info))
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], protocol)
	out = append(out, pb[:]...)
	return append(out, info...)
}
