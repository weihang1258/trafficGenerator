package core

import (
	"fmt"
)

// SPNEGO（D-SPNEGO-1 #47，契约 61-spnego v1.5.0）配置类型。
//
// 字段名对齐契约 §2 键表：`profile`/`negotiation`/`mech_types`/`supported_mech`/
// `neg_result`/`req_flags`/`neg_hints`/`mech_token`/`response_token`/
// `mech_list_mic`/`wire_fault`/`sessions` 全部住 spnego 层内（顶层同名子映射=
// 旧扁平形，CheckProtoFlat 判死）；数量走顶层 `flow_control`。
//
// 双 profile 自封帧（裁定1）：`tcp`（缺省档）= 裸 TCP stream 直发整 DER；
// `http` = TCP/80 HTTP 401/`WWW-Authenticate: Negotiate` ↔
// `Authorization: Negotiate`，token 为 base64 包装（DER 字节不变）。
// 内层机制 token 一律 opaque（裁定5）：只生成确定性 fixture 字节，不解读、
// 不伪造 Kerberos/KRB5/NTLM 内部字段。

// SPNEGOConfig is the flow's spnego terminal-layer configuration.
type SPNEGOConfig struct {
	// Profile 是必填语义配置：http | tcp。空 = 缺省档 tcp（裸 spnego 层不
	// 静默 0 包——bacnet/dtls/kerberos/ntlm 空配置缺省家族同款）；profile
	// 永不按 dst_port 推导（契约 §2）。
	Profile string `json:"profile,omitempty"`
	// Negotiation: init_resp（缺省档）| init_targ（RFC 2478 旧式互操作）|
	// 空（显式事件序列；响应事件用 kind targ 表达）。
	Negotiation string `json:"negotiation,omitempty"`
	// MechTypes 是按线上 DER 顺序保留的机制 OID 文本列表（序=线上序；禁
	// 排序/重编码——MIC 输入依赖，契约 §4/§5）。
	MechTypes []string `json:"mech_types,omitempty"`
	// SupportedMech 是 acceptor 选择的机制 OID，必须 ∈ 原始 mech_types
	// （降级守卫，契约 §5）。
	SupportedMech string `json:"supported_mech,omitempty"`
	// NegResult: resp 档 0..3（accept-completed/accept-incomplete/reject/
	// request-mic，RFC 4178 §4.2.2）；targ 档 0..2（RFC 2478 §3.2.1 三值）。
	NegResult *int `json:"neg_result,omitempty"`
	// ReqFlags 是 [1] ContextFlags 位掩码（RFC 4178 §4.2.1 bit0..bit6）；
	// DER 须截去尾随零位（不得期待恒 32 位）。0/缺席 = 不发该字段。
	ReqFlags *uint32 `json:"req_flags,omitempty"`
	// NegHints 只走 dissector 形（carry: dissector，NegTokenInit [3] 槽；
	// 裁定2）；与 RFC 形 mech_list_mic 同槽互斥。
	NegHints *SPNEGONegHints `json:"neg_hints,omitempty"`
	// MechToken 是 InitialContextToken/negTokenInit 的 [2] OCTET STRING
	// 外壳（opaque fixture）。
	MechToken *SPNEGOToken `json:"mech_token,omitempty"`
	// ResponseToken 是 negTokenResp/negTokenTarg 的 [2] OCTET STRING 外壳。
	ResponseToken *SPNEGOToken `json:"response_token,omitempty"`
	// MechListMIC 覆盖原始 DER mechTypes 的完整性校验；线位 = NegTokenInit/
	// NegTokenResp [3]（RFC 4178 形；裁定2）。
	MechListMIC *SPNEGOMIC `json:"mech_list_mic,omitempty"`
	// Sessions 是有序会话列表；每会话独立协商状态、候选列表、选定 OID、
	// MIC 输入 bytes（契约 §5）。
	Sessions []SPNEGOSession `json:"sessions,omitempty"`
	// WireFault 仅负例故障注入口（6 值枚举，契约 §2/§12 与用例 §4 三方同序）。
	WireFault string `json:"wire_fault,omitempty"`
}

// SPNEGONegHints 是 dissector 形 NegHints 的声明（G-SPNEGO-1：RFC 原文无
// 该结构，证据=dissector 拆解级；两字段长度独立计算，契约 §3）。
type SPNEGONegHints struct {
	// Carry: none（缺省=不发）| dissector（NegTokenInit [3] 槽）。
	Carry string `json:"carry,omitempty"`
	// HintName → [0] GeneralString（tag 0x1B）。
	HintName string `json:"hint_name,omitempty"`
	// HintAddress → [1] OCTET STRING（原始字节）。
	HintAddress string `json:"hint_address,omitempty"`
}

// SPNEGOToken 是不透明机制 token 外壳声明（裁定5：无解密证据，内层语义
// 不可断言）。Len 指针三态：缺席 = 缺省 fixture 长度；显式 0 = 零长占位
// （空 OCTET STRING）；显式 n = n 字节确定性 fixture。
type SPNEGOToken struct {
	Opaque *bool `json:"opaque,omitempty"`
	Len    *int  `json:"len,omitempty"`
}

// SPNEGOMIC 是 mechListMIC 声明：验证输入 = 原始 DER mechTypes bytes
// （不含 [0] wrapper，RFC 4178 §5）；layout 本版唯一档 rfc4178。
type SPNEGOMIC struct {
	Layout string `json:"layout,omitempty"`
	Opaque *bool  `json:"opaque,omitempty"`
	Len    *int   `json:"len,omitempty"`
}

// SPNEGOSession 是一个协商会话：独立候选列表/选定 OID + 有序事件列。
// 端点覆盖（src_ip/dst_port）在 TCP 单载体下被判死——一个流 = 一个连接
// 四元组（kerberos udp 面先例的 tcp 侧同款，planner 守卫）。
type SPNEGOSession struct {
	ID string `json:"id,omitempty"`
	// SrcIP/DstPort 是端点覆盖声明（TCP 载体下拒——流身份=连接四元组）。
	SrcIP   string `json:"src_ip,omitempty"`
	DstPort *int   `json:"dst_port,omitempty"`
	// MechTypes/SupportedMech/NegResult 是会话级覆盖（会话独立候选列表、
	// 选定 OID 与协商结果；缺席=取配置级档）。#8 三 OID 变体与 #13 会话
	// 隔离靠此表达。
	MechTypes     []string      `json:"mech_types,omitempty"`
	SupportedMech string        `json:"supported_mech,omitempty"`
	NegResult     *int          `json:"neg_result,omitempty"`
	Events        []SPNEGOEvent `json:"events,omitempty"`
}

// SPNEGOEvent 是一条协商消息事件（每 event = 一条完整 negotiationToken
// 消息 = 一 TCP payload 单元 / 一 HTTP 认证 header 值）。kind 枚举：
// init（negTokenInit，up）| resp（negTokenResp，down）| targ（negTokenTarg
// 旧式，down）| mic（补 mechListMIC 的 negTokenInit，up）|
// challenge（HTTP 401 + 裸 `WWW-Authenticate: Negotiate`，down）|
// http_success（HTTP 200，down）。方向缺省按 kind 派生，可显式覆盖。
type SPNEGOEvent struct {
	Kind string `json:"kind"`
	Up   *bool  `json:"up,omitempty"`
	// NegResult 覆盖该事件的协商进展值（#12 四值枚举逐值覆盖）。
	NegResult *int `json:"neg_result,omitempty"`
}

// UnmarshalJSON strict-decodes the spnego layer config（未知键拒绝；
// kerberos/dtls/ntlm 同款递归严格面——嵌套结构各自实现）。
func (c *SPNEGOConfig) UnmarshalJSON(b []byte) error {
	type alias SPNEGOConfig
	var a alias
	if err := strictUnmarshalJSON(b, &a); err != nil {
		return err
	}
	*c = SPNEGOConfig(a)
	return nil
}

// UnmarshalJSON strict-decodes the neg_hints block.
func (h *SPNEGONegHints) UnmarshalJSON(b []byte) error {
	type alias SPNEGONegHints
	var a alias
	if err := strictUnmarshalJSON(b, &a); err != nil {
		return err
	}
	*h = SPNEGONegHints(a)
	return nil
}

// UnmarshalJSON strict-decodes a token shell block.
func (t *SPNEGOToken) UnmarshalJSON(b []byte) error {
	type alias SPNEGOToken
	var a alias
	if err := strictUnmarshalJSON(b, &a); err != nil {
		return err
	}
	*t = SPNEGOToken(a)
	return nil
}

// UnmarshalJSON strict-decodes the mech_list_mic block.
func (m *SPNEGOMIC) UnmarshalJSON(b []byte) error {
	type alias SPNEGOMIC
	var a alias
	if err := strictUnmarshalJSON(b, &a); err != nil {
		return err
	}
	*m = SPNEGOMIC(a)
	return nil
}

// UnmarshalJSON strict-decodes one session.
func (s *SPNEGOSession) UnmarshalJSON(b []byte) error {
	type alias SPNEGOSession
	var a alias
	if err := strictUnmarshalJSON(b, &a); err != nil {
		return err
	}
	*s = SPNEGOSession(a)
	return nil
}

// UnmarshalJSON strict-decodes one event.
func (e *SPNEGOEvent) UnmarshalJSON(b []byte) error {
	type alias SPNEGOEvent
	var a alias
	if err := strictUnmarshalJSON(b, &a); err != nil {
		return err
	}
	*e = SPNEGOEvent(a)
	return nil
}

// 6 wire_fault 值（契约 §2 键表逐字；锚词=testcase §4 目标词——逐值单锚词）。
const (
	SPNEGOWireFaultDERTruncated = "der_truncated" // tag/length/子 TLV 截断
	SPNEGOWireFaultDERLength    = "der_length"    // 长形式溢出/父长度不符/非最短
	SPNEGOWireFaultChoice       = "choice"        // 未知 choice / tag class / 三形混用
	SPNEGOWireFaultMechOID      = "mech_oid"      // OID 编码或选定机制绑定错误
	SPNEGOWireFaultMIC          = "mic"           // MIC 缺失/不匹配/列表改写
	SPNEGOWireFaultCarrier      = "carrier"       // HTTP/TCP profile/载体错
)

// DescribeSPNEGOWireFault returns the value's 主锚词（error_contains 断言）。
func DescribeSPNEGOWireFault(kind string) (string, error) {
	anchors := map[string]string{
		SPNEGOWireFaultDERTruncated: "der",
		SPNEGOWireFaultDERLength:    "length",
		SPNEGOWireFaultChoice:       "choice",
		SPNEGOWireFaultMechOID:      "oid",
		SPNEGOWireFaultMIC:          "mic",
		SPNEGOWireFaultCarrier:      "carrier",
	}
	a, ok := anchors[kind]
	if !ok {
		return "", fmt.Errorf("spnego: unknown wire_fault kind %q", kind)
	}
	return a, nil
}
