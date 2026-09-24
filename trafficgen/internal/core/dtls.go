package core

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// DTLS（D-DTLS-1 #43，契约 58-dtls v1.0.0）配置类型。
// 字段名对齐契约 §2：sessions[] 事件编排会话（每事件 = 一条 DTLS record
// = 一 UDP datagram——UDP 无连接，bacnet 同族），多会话按序整块回放，
// 会话间 epoch/sequence/cookie 状态全隔离（设计 §9）。
// 链形 [ip→udp→dtls]：UDP/4433（tshark dtls dissector 自动解码依赖）。
//
// 全协议大端（§4 记录头/§6 握手头 24-bit 字段均网络序；dcerpc LE 勿串）：
// ContentType(1) Version(2) Epoch(2) Sequence48(6) Length(2)。
// 版本：1.0=`feff`、1.2=`fefd`（RFC 6347 §4.1；feff/fefd 自洽守卫）。
// 加密 epoch 后 payload 全 opaque（设计 §8——不断言明文，key log 另立项）。

// DTLSConfig is the flow's dtls terminal-layer configuration.
type DTLSConfig struct {
	// Sessions is the ordered session list（会话间按序整块回放；四元组/
	// epoch/seq/cookie 状态不跨会话串用——设计 §9）.
	Sessions []DTLSSession `json:"sessions,omitempty"`
	// WireFault injects one negative-path fault（6 值枚举，设计 §10 与
	// 用例 §4/§5 三方同序）.
	WireFault string `json:"wire_fault,omitempty"`
}

// DTLSSession is one event-orchestration session：端点覆盖 + 版本缺省 +
// 有序事件列。会话身份 = SrcIP/SrcPort 覆盖（空/0 = 流缺省）。
type DTLSSession struct {
	// SrcIP overrides the session's source IP（多会话双客户端；空 = 流
	// 缺省。仅 up 方向直落——down 方向留空走链层交换，bacnet 先例）.
	SrcIP string `json:"src_ip,omitempty"`
	// SrcPort overrides the session's UDP source port (0 = 流缺省).
	SrcPort uint16 `json:"src_port,omitempty"`
	// DstPort overrides the session's destination port (0 = 继承链级缺省
	// 4433 via FieldContract；validator 守会话间一致性).
	DstPort uint16 `json:"dst_port,omitempty"`
	// Version is the session's record version default ("1.0"|"1.2"；空 =
	// "1.2"。事件级 Version 覆盖).
	Version string `json:"version,omitempty"`
	// Events is the session's ordered event list；每事件一 datagram.
	Events []DTLSEvent `json:"events,omitempty"`
}

// DTLSEvent is one DTLS record（事件）：kind 决定 content type 与 body
// 形态；Up 显式声明方向（datagram 协议无请求/应答派生规则）。
type DTLSEvent struct {
	// Kind: handshake|ccs|alert|appdata（content type 22/20/21/23；
	// 未知 kind 拒）.
	Kind string `json:"kind"`
	// Up declares the direction (true=client→server).
	Up bool `json:"up,omitempty"`
	// Version overrides the record version for this event ("1.0"|"1.2"；
	// 空 = 会话缺省).
	Version string `json:"version,omitempty"`
	// Epoch declares the record's epoch（指针区分"声明 0"与缺省；
	// 缺省沿会话当前 epoch。epoch 回退=自然守卫拒）.
	Epoch *int `json:"epoch,omitempty"`
	// Seq declares the record's 48-bit sequence number（指针：声明采纳
	// 并推进 walker；缺省按 (epoch,方向) 计数器递增起 0。回退/重复=
	// 自然守卫拒——重传不复用 record seq，RFC 6347 §4.1）.
	Seq *int `json:"seq,omitempty"`

	// Handshake carries the handshake message（kind=handshake 时必填；
	// content type 恒 22）.
	Handshake *DTLSHandshake `json:"handshake,omitempty"`
	// AlertLevel/AlertDesc are the plaintext alert fields（kind=alert 且
	// 明文时；各 0-255。加密 alert 走 CiphertextLen，只断言外层）.
	AlertLevel *int `json:"alert_level,omitempty"`
	AlertDesc  *int `json:"alert_desc,omitempty"`
	// Payload is the plaintext body hex（kind=appdata 明文 fixture；
	// kind=ccs 缺省自动 "01"——RFC 6347 CCS 单字节）.
	Payload string `json:"payload,omitempty"`
	// CiphertextLen declares an opaque encrypted payload length
	// （加密 epoch 边界——payload 确定性填充，不伪造密文语义）.
	CiphertextLen int `json:"ciphertext_len,omitempty"`
}

// DTLSHandshake is the 12-byte handshake message header + fragment body
// （RFC 6347 §4.2.6：type/len24/msg_seq/off24/fraglen24 全网络序）。
type DTLSHandshake struct {
	// Type: 1=client_hello、2=server_hello、3=hello_verify_request 等
	// （0-255 值域）.
	Type int `json:"type"`
	// MsgSeq declares the handshake message_seq（指针：缺省沿会话计数器
	// 递增起 0；重传复用同 msg_seq 合法——分片声明面）.
	MsgSeq *int `json:"message_seq,omitempty"`
	// Length is the full message body length（24-bit；分片时 > 本片）.
	Length *int `json:"length,omitempty"`
	// FragOffset/FragLen declare this fragment's place in the full body
	// （24-bit；缺省 offset=0、fraglen=len(body)。offset+fraglen>length
	// =越界自然守卫拒）.
	FragOffset int  `json:"fragment_offset,omitempty"`
	FragLen    *int `json:"fragment_length,omitempty"`
	// Body is the fragment body hex（本片 payload；opaque fixture）.
	Body string `json:"body,omitempty"`
	// Cookie carries the HVR/CH-cookie bytes（hex；type=3 时自动组
	// body=server_version(2)+cookie_len(1)+cookie——RFC 6347 §4.2.1；
	// 长度前缀=实际字节，不硬编码运行期随机值）.
	Cookie string `json:"cookie,omitempty"`
}

// UnmarshalJSON strict-decodes the dtls layer config（未知键拒绝；
// dcerpc 同款三级严格面）。
func (c *DTLSConfig) UnmarshalJSON(b []byte) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	type alias DTLSConfig
	var a alias
	if err := dec.Decode(&a); err != nil {
		return err
	}
	*c = DTLSConfig(a)
	return nil
}

// 6 wire_fault 值（设计 §10 表；锚词=testcase §4 目标词——逐值单锚词）。
const (
	DTLSWireFaultRecordLength     = "record_length"     // Length≠实际 datagram 字节
	DTLSWireFaultVersionEpoch     = "version_epoch"     // 非法版本
	DTLSWireFaultSequenceOverflow = "sequence_overflow" // seq 超 48-bit
	DTLSWireFaultFragmentBounds   = "fragment_bounds"   // 分片越界/重叠
	DTLSWireFaultCookieState      = "cookie_state"      // cookie 长度/状态错
	DTLSWireFaultCarrierUDP       = "carrier_udp"       // 载体错（tcp/缺 udp）
)

// DescribeDTLSWireFault returns the row's 主锚词（error_contains 断言）。
func DescribeDTLSWireFault(kind string) (string, error) {
	anchors := map[string]string{
		DTLSWireFaultRecordLength:     "record",
		DTLSWireFaultVersionEpoch:     "version",
		DTLSWireFaultSequenceOverflow: "sequence",
		DTLSWireFaultFragmentBounds:   "fragment",
		DTLSWireFaultCookieState:      "cookie",
		DTLSWireFaultCarrierUDP:       "udp",
	}
	a, ok := anchors[kind]
	if !ok {
		return "", fmt.Errorf("dtls: unknown wire_fault kind %q", kind)
	}
	return a, nil
}
