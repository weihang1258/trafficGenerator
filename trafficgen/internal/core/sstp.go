package core

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// SSTP（D-SSTP-1 #48，契约 57-sstp v1.1.0）配置类型。字段名对齐契约 §2 键表：
// version / events / sessions / attributes / ppp / mppe / wire_fault。
//
// 层链 [ip → tcp → tls → sstp]：sstp 是终结层，SSTP message 经 tls 层
// application-data 透传（多 messages 同 record / 单 message 跨 records 按
// SSTP Length 切分，MS-SSTP §2.2.2——record/segment 边界 ≠ message 边界）。
// 目的端口 443（FieldContract，tls 底座同契约）。
//
// 线格式权威：MS-SSTP §2.2（common header 4B：Version 0x10 | Reserved7+C |
// R4+Length12 网络序，Length 覆盖整包含 4B 头；控制包追加 Message Type(2)
// + Num Attributes(2)；属性头 4B：Reserved(1) | Attribute ID(1) |
// R(4)+LengthPacket(12)，LengthPacket 含 4B 属性头）。PPP framing 权威
// RFC 1661（C=0 data 包 S+4 即 `ff 03`）；MPPE 边界权威 RFC 3078（只改
// information 加密表示，不改 Length/protocol 语义）。
//
// 证据红线（契约 §1/§9/§16）：无解密密钥的 PCAP 只能断言 TCP/TLS 载体
// （tls.record.*）+ 方向 + 长度，不得声称看见 SSTP/PPP 明文；sstp.*/ppp.*
// 字段仅在解密 fixture 可用。

// SSTPConfig is the flow's sstp terminal-layer configuration.
type SSTPConfig struct {
	// Version is the SSTP version byte（本版正例固定 0x10=16；他版本拒）。
	// 指针三态：nil = 缺省 0x10（显式 0 不是"用缺省"——0 非法版本，拒）。
	Version *int `json:"version,omitempty"`
	// Events is the single-connection short form（同 sessions 的 transactions；
	// 与 sessions 并存时 sessions 优先——两处各写一半按双权威拒）。
	Events []SSTPEvent `json:"events,omitempty"`
	// Sessions is the ordered connection list（会话间状态/TLS session/属性
	// 全隔离——契约 §6；同一 flow 内的会话共享一条 TLS 载体，多连接并行
	// 由 flow_control.flows>1 表达，契约 §8）。
	Sessions []SSTPSession `json:"sessions,omitempty"`
	// WireFault injects one negative-path fault（6 值枚举，契约 §2/§11
	// 逐字：header_length/attribute_length/state/carrier/ppp_framing/
	// tls_boundary）。非线上字段。
	WireFault string `json:"wire_fault,omitempty"`
}

// SSTPSession is one SSTP connection: 独立 ID、独立 TLS session、独立事务序
// （契约 §6："连接 ID、transaction 状态和属性不能跨 TLS connection 复用"）。
type SSTPSession struct {
	// ID names the session（错误锚点；跨会话不得重复）。
	ID string `json:"id,omitempty"`
	// TLSSession is the session's TLS carrier identity（每个连接独立 TLS
	// session；跨会话重复 = 跨连接引用，拒）。
	TLSSession string `json:"tls_session,omitempty"`
	// Transactions is the session's ordered transaction list（每事务 = 一条
	// 完整 SSTP message；控制消息与 PPP 数据帧同类不同 kind）。
	Transactions []SSTPEvent `json:"transactions,omitempty"`
}

// SSTPEvent is one SSTP transaction/message（契约 §17 数据结构：Transaction
// {id, kind, attributes[], ppp}）。SSTP 一个事务恰好产出一条 message，故
// 事务与线上事件一一对应，不再单独维护第二套事件结构。
type SSTPEvent struct {
	// ID names the transaction（错误锚点；空 = 以序号定位）。
	ID string `json:"id,omitempty"`
	// Kind is the message kind：call_connect_request 0x0001 /
	// call_connect_ack 0x0002 / call_connect_nak 0x0003 / call_connected
	// 0x0004 / call_abort 0x0005 / call_disconnect 0x0006 /
	// call_disconnect_ack 0x0007 / echo_request 0x0008 / echo_response
	// 0x0009 / ppp_data（C=0 data 包）。未知 kind 拒（契约 §3 九枚举）。
	Kind string `json:"kind"`
	// Direction is "c2s" (client→server) or "s2c"（空 = 按 kind 派生唯一
	// 合法方向；ppp_data/echo/abort 无缺省方向，必须显式声明）。
	Direction string `json:"direction,omitempty"`
	// Expect declares the transaction's 成功分支（契约 §16.1 样例字段）：
	// ack/nak/connected/ppp/echo/abort/disconnect——声明值必须与下一条事务
	// 的 kind 相符，否则拒（state/sequence）。
	Expect string `json:"expect,omitempty"`
	// Attributes is the ordered attribute list（控制消息专用；C=0 数据包
	// 携带属性 = C bit↔Message Type 不一致，拒）。
	Attributes []AttributeEntry `json:"attributes,omitempty"`
	// PPP is the C=0 data packet's PPP frame（仅 ppp_data；控制消息携带
	// = C bit 不一致，拒）。
	PPP *PPPEntry `json:"ppp,omitempty"`
	// Chunk splits this message into TLS records of at most Chunk bytes
	// （单 message 跨 records；0 = 不切分）。
	Chunk int `json:"chunk,omitempty"`
	// Group merges this message with the following Group-1 messages into one
	// TLS record（多 messages 同 record；0/1 = 不合并）。
	Group int `json:"group,omitempty"`
}

// AttributeEntry is one SSTP control attribute（契约 §4 属性表）。
type AttributeEntry struct {
	// ID is the Attribute ID（0x01 Encapsulated Protocol ID / 0x02 Status
	// Info / 0x03 Crypto Binding / 0x04 Crypto Binding Request）。Message
	// Type 值 0x0005/0x0006 不是属性 ID，出现即拒。
	ID int `json:"id"`
	// ValueB64 overrides the full attribute value（std base64；opaque fixture
	// 逃生口）。声明时长度必须命中该属性 ID 的固定/区间长度，否则拒。
	ValueB64 string `json:"value_b64,omitempty"`
	// AttrID is the Status Info reported attribute ID（0x00..0x04）。
	AttrID *int `json:"attrib_id,omitempty"`
	// Status is the Status Info status code（MS-SSTP §2.2.8：0x00..0x0b）。
	Status *uint32 `json:"status,omitempty"`
	// ValueLen is the Status Info AttribValue length（0..64）。
	ValueLen int `json:"value_len,omitempty"`
	// HashProtocol selects the Crypto Binding hash（1=SHA1 / 2=SHA256）。
	HashProtocol *int `json:"hash_protocol,omitempty"`
	// HashBitmask is the Crypto Binding Request hash bitmask（bit0=SHA1,
	// bit1=SHA256；非零）。
	HashBitmask *int `json:"hash_bitmask,omitempty"`
	// NonceB64 overrides the 32-byte nonce（std base64；空 = 确定性填充）。
	NonceB64 string `json:"nonce_b64,omitempty"`
}

// PPPEntry is the C=0 data packet's PPP frame（RFC 1661；契约 §7）。
type PPPEntry struct {
	// Protocol selects the PPP protocol field：ipv4 (0x0021) / ipv6 (0x0057)。
	// 不由 outer IP 地址族推导（契约 §7）。
	Protocol string `json:"protocol"`
	// PayloadB64 is the PPP information（std base64；空 = 按 PayloadLen 合成）。
	PayloadB64 string `json:"payload_b64,omitempty"`
	// PayloadLen is the synthesized information length（缺省 20；显式 0 =
	// 零长 information，profile 允许——契约 §8）。
	PayloadLen int `json:"payload_len,omitempty"`
	// Framing declares the PPP framing profile：""/"uncompressed" = ff 03 +
	// protocol（契约 §7 正例）；"none" = 缺 address/control 字段（负例）。
	Framing string `json:"framing,omitempty"`
	// MPPE marks the information as MPPE-encrypted（RFC 3078）：协议字段
	// 0x00FD，载荷 opaque，只改表示不改 Length/protocol 语义（契约 §7）。
	MPPE bool `json:"mppe,omitempty"`
}

// UnmarshalJSON strict-decodes the sstp layer config（未知键拒绝；
// DisallowUnknownFields 递归作用于 sessions[]/transactions[] 嵌套结构——
// kerberos/dtls 同款严格面）。
func (c *SSTPConfig) UnmarshalJSON(b []byte) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	type alias SSTPConfig
	var a alias
	if err := dec.Decode(&a); err != nil {
		return err
	}
	*c = SSTPConfig(a)
	return nil
}

// 6 wire_fault 值（契约 §2 配置键表逐字；锚词=契约 §11 目标词——逐值单
// 锚词。负例 ID 后缀与 wire_fault 值不同名是设计既定，§10 表）。
const (
	SSTPWireFaultHeaderLength    = "header_length"    // common/control header 长度错
	SSTPWireFaultAttributeLength = "attribute_length" // 属性头/LengthPacket 长度错
	SSTPWireFaultState           = "state"            // 越序/ABORT 后续发/跨连接引用
	SSTPWireFaultCarrier         = "carrier"          // 载体错（缺 TLS/UDP/错端口）
	SSTPWireFaultPPPFraming      = "ppp_framing"      // PPP ff 03/protocol/长度错
	SSTPWireFaultTLSBoundary     = "tls_boundary"     // TLS record 截断/越出 TLS/跨连接拼接
)

// DescribeSSTPWireFault returns the row's 主锚词（error_contains 断言；契约
// §11 逐行目标词——单锚词表是唯一权威）。
func DescribeSSTPWireFault(kind string) (string, error) {
	anchors := map[string]string{
		SSTPWireFaultHeaderLength:    "header",
		SSTPWireFaultAttributeLength: "attribute",
		SSTPWireFaultState:           "state",
		SSTPWireFaultCarrier:         "transport",
		SSTPWireFaultPPPFraming:      "ppp",
		SSTPWireFaultTLSBoundary:     "tls",
	}
	a, ok := anchors[kind]
	if !ok {
		return "", fmt.Errorf("sstp: unknown wire_fault kind %q", kind)
	}
	return a, nil
}
