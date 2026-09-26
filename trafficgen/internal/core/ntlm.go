package core

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// NTLM（D-NTLM-1 #45，契约 60-ntlm v2.0.0）配置类型。
//
// 字段名对齐契约 §2 键表：`profile`/`version`/`outer`/`flags`/`target_info`/
// `ntlmv2_response`/`mic`/`encrypted_random_session_key` 全部住 ntlm 层内
// （顶层同名子映射=旧扁平形，CheckProtoFlat 判死）；数量走顶层 `flow_control`。
//
// 双 profile 自封帧（裁定 N1）：`smb2` = TCP/445 SMB2 SESSION_SETUP
// SecurityBuffer 承载 NTLMSSP token；`http-negotiate` = TCP/80 HTTP
// 401/`WWW-Authenticate: Negotiate` ↔ `Authorization: Negotiate`，token 为
// base64 编码。`outer=none|spnego` 决定是否加 SPNEGO（RFC 4178）外层。
//
// 密钥面纪律（设计 §7）：proof/MIC/EncryptedRandomSessionKey 在无授权密钥时
// 一律为确定性 opaque 占位（fixtureFill），只断言长度/边界，不伪造密码学值。

// NTLMConfig is the flow's ntlm terminal-layer configuration.
type NTLMConfig struct {
	// Profile 是必填语义配置：smb2 | http-negotiate。空 = 缺省档 smb2
	// （裸 {"ntlm":{}} 层不静默 0 包——bacnet/dtls/kerberos 空配置缺省家族
	// 同款）；profile 永不按 dst_port 推导（设计 §2）。
	Profile string `json:"profile,omitempty"`
	// Version 本版正例唯一档 ntlmv2（NTLMv1/LM 方言面=缺口 G-NTLM-6，
	// 明确不支持）。
	Version string `json:"version,omitempty"`
	// Outer: none | spnego（缺省 none）。
	Outer string `json:"outer,omitempty"`
	// Flags 三消息共用的 32-bit flags 集（Type 1/2/3 交集一致）。
	Flags *NTLMFlags `json:"flags,omitempty"`
	// TargetInfo Type 2 TargetInfo security buffer 的 AV_PAIR 序列声明。
	TargetInfo *NTLMTargetInfo `json:"target_info,omitempty"`
	// Type3 是 Type 3 NT response/blob 的形态声明（RV/HRV/TS/CC/AV/EOL）。
	Type3 *NTLMType3Config `json:"ntlmv2_response,omitempty"`
	// MIC 声明 Type 3 是否带 16-byte MIC（缺省 false=不出现）。
	MIC *bool `json:"mic,omitempty"`
	// SessionKeyLen 是 Type 3 EncryptedRandomSessionKey 的 security buffer
	// 长度（0=空，值 opaque 不可断言）。
	SessionKeyLen int `json:"encrypted_random_session_key,omitempty"`
	// Sessions 是有序会话列表；每会话独立事件序列（NEGOTIATE→CHALLENGE→
	// AUTHENTICATE）、独立 ServerChallenge/client challenge（§9）。
	Sessions []NTLMSession `json:"sessions,omitempty"`
	// WireFault 仅负例故障注入口（6 值枚举，设计 §2/§10 三方同序）。
	WireFault string `json:"wire_fault,omitempty"`
}

// NTLMFlags 是 NEGOTIATE flags 集（指针三态：缺席=缺省档、显式 false=关闭、
// 显式 true=置位）。bit 值见契约 §6（MS-NLMP §2.2.2.1）。
type NTLMFlags struct {
	Unicode                 *bool `json:"unicode,omitempty"`                   // 0x00000001（UTF-16LE 编码；关闭=OEM）
	RequestTarget           *bool `json:"request_target,omitempty"`            // 0x00000004
	NTLM                    *bool `json:"ntlm,omitempty"`                      // 0x00000200
	AlwaysSign              *bool `json:"always_sign,omitempty"`               // 0x00008000
	TargetTypeDomain        *bool `json:"target_type_domain,omitempty"`        // 0x00010000
	ExtendedSessionSecurity *bool `json:"extended_session_security,omitempty"` // 0x00080000（NTLMv2 必需）
	TargetInfo              *bool `json:"target_info,omitempty"`               // 0x00800000
	Version                 *bool `json:"version,omitempty"`                   // 0x02000000（置位才有 8-byte Version 字段）
	Sign                    *bool `json:"sign,omitempty"`                      // 0x00000010
	KeyExch                 *bool `json:"key_exch,omitempty"`                  // 0x40000000
	Negotiate128            *bool `json:"negotiate_128,omitempty"`             // 0x20000000
	Negotiate56             *bool `json:"negotiate_56,omitempty"`              // 0x80000000
}

// NTLMTargetInfo 声明 Type 2 的 TargetInfo AV_PAIR 序列（契约 §6）。
// 已知 AvId：1 NbComputerName / 2 NbDomainName / 3 DnsComputerName /
// 4 DnsDomainName / 5 DnsTreeName / 6 AvFlags / 7 Timestamp /
// 9 TargetName；未知项经 Extra 按 MS-NLMP 扩展保留。
type NTLMTargetInfo struct {
	NbComputerName  string       `json:"nb_computer_name,omitempty"`
	NbDomainName    string       `json:"nb_domain_name,omitempty"`
	DnsComputerName string       `json:"dns_computer_name,omitempty"`
	DnsDomainName   string       `json:"dns_domain_name,omitempty"`
	DnsTreeName     string       `json:"dns_tree_name,omitempty"`
	TargetName      string       `json:"target_name,omitempty"`
	Timestamp       string       `json:"timestamp,omitempty"` // "auto"（缺省，按会话确定性派生）| 16-hex fixture 钉
	AvFlags         *uint32      `json:"av_flags,omitempty"`
	Extra           []NTLMAVPair `json:"extra,omitempty"`  // 未知 AvId 保留项（扩展面）
	NoEOL           bool         `json:"no_eol,omitempty"` // 缺 MsvAvEOL 收尾（自然守卫负例面）
}

// NTLMAVPair 是一项 AV_PAIR：AvId(2) | AvLen(2) | Value(AvLen)（little-endian，
// AvLen 只计 value、不含 4-byte AV header——契约 §6）。
type NTLMAVPair struct {
	ID       uint16 `json:"id"`
	Text     string `json:"text,omitempty"`      // UTF-16LE 文本（AvLen = 2*len）
	ValueHex string `json:"value_hex,omitempty"` // 原始 value 字节（与 Text 二选一）
}

// NTLMType3Config 声明 Type 3 的 NT response 形态（NTLMv2 blob，契约 §7）。
type NTLMType3Config struct {
	LMResponseLen     int          `json:"lm_response_len,omitempty"`     // 0=空 LM response（NTLMv2 档）
	ResponseVersion   *int         `json:"response_version,omitempty"`    // blob RespType，缺省 1
	HiResponseVersion *int         `json:"hi_response_version,omitempty"` // blob HiRespType，缺省 1
	Timestamp         string       `json:"timestamp,omitempty"`           // "auto"|16-hex（blob TimeStamp）
	ClientChallenge   string       `json:"client_challenge,omitempty"`    // "auto"|16-hex（blob ChallengeFromClient）
	AVPairs           []NTLMAVPair `json:"av_pairs,omitempty"`            // blob 内 AV 序列（EOL 自动收尾）
	NoEOL             bool         `json:"no_eol,omitempty"`              // 缺 MsvAvEOL（自然守卫负例面）
	MaxLenPad         int          `json:"max_len_pad,omitempty"`         // 非空字段 MaxLen = Len + pad（缓存语义形）
}

// NTLMSession 是一个认证会话：身份（domain/user/workstation）+ 有序事件列。
type NTLMSession struct {
	ID          string `json:"id,omitempty"`
	Domain      string `json:"domain,omitempty"`
	User        string `json:"user,omitempty"`
	Workstation string `json:"workstation,omitempty"`
	// TargetName 是 Type 2 TargetNameFields 的值（UTF-16LE/OEM 按 flag）。
	TargetName string `json:"target_name,omitempty"`
	// ServerChallenge: "auto"（缺省，按流四元组+会话序号确定性派生）| 16-hex。
	ServerChallenge string      `json:"server_challenge,omitempty"`
	Events          []NTLMEvent `json:"events,omitempty"`
}

// NTLMEvent 是一个载体事件：kind 决定 NTLMSSP 消息与载体状态码。
// kind 枚举：negotiate（Type 1，up）| challenge（Type 2，down，
// STATUS_MORE_PROCESSING_REQUIRED）| authenticate（Type 3，up）|
// session_setup_success（STATUS_SUCCESS，down）| session_setup_failure
// （STATUS_LOGON_FAILURE，down）| challenge_401（401 + WWW-Authenticate:
// Negotiate，down）| http_success（2xx，down）| http_unauthorized（401 最终
// 拒绝，down）。方向缺省按 kind 派生，可显式覆盖（多流双向面）。
type NTLMEvent struct {
	Kind string `json:"kind"`
	Up   *bool  `json:"up,omitempty"`
	// Version 覆盖 NEGOTIATE_VERSION 置位（#4 两档：声明/不声明）。
	Version *bool `json:"version,omitempty"`
	// MIC 覆盖 Type 3 MIC 出现（#8）。
	MIC *bool `json:"mic,omitempty"`
	// SessionKeyLen 覆盖 Type 3 EncryptedRandomSessionKey 长度（#8）。
	SessionKeyLen *int `json:"session_key_len,omitempty"`
}

// UnmarshalJSON strict-decodes the ntlm layer config（未知键拒绝；
// kerberos/dtls 同款递归严格面——嵌套结构各自实现）。
func (c *NTLMConfig) UnmarshalJSON(b []byte) error {
	type alias NTLMConfig
	var a alias
	if err := strictUnmarshalJSON(b, &a); err != nil {
		return err
	}
	*c = NTLMConfig(a)
	return nil
}

// UnmarshalJSON strict-decodes the flags block.
func (f *NTLMFlags) UnmarshalJSON(b []byte) error {
	type alias NTLMFlags
	var a alias
	if err := strictUnmarshalJSON(b, &a); err != nil {
		return err
	}
	*f = NTLMFlags(a)
	return nil
}

// UnmarshalJSON strict-decodes the target_info block.
func (t *NTLMTargetInfo) UnmarshalJSON(b []byte) error {
	type alias NTLMTargetInfo
	var a alias
	if err := strictUnmarshalJSON(b, &a); err != nil {
		return err
	}
	*t = NTLMTargetInfo(a)
	return nil
}

// UnmarshalJSON strict-decodes the ntlmv2_response block.
func (t *NTLMType3Config) UnmarshalJSON(b []byte) error {
	type alias NTLMType3Config
	var a alias
	if err := strictUnmarshalJSON(b, &a); err != nil {
		return err
	}
	*t = NTLMType3Config(a)
	return nil
}

// UnmarshalJSON strict-decodes one session.
func (s *NTLMSession) UnmarshalJSON(b []byte) error {
	type alias NTLMSession
	var a alias
	if err := strictUnmarshalJSON(b, &a); err != nil {
		return err
	}
	*s = NTLMSession(a)
	return nil
}

// UnmarshalJSON strict-decodes one event.
func (e *NTLMEvent) UnmarshalJSON(b []byte) error {
	type alias NTLMEvent
	var a alias
	if err := strictUnmarshalJSON(b, &a); err != nil {
		return err
	}
	*e = NTLMEvent(a)
	return nil
}

// UnmarshalJSON strict-decodes one AV pair.
func (p *NTLMAVPair) UnmarshalJSON(b []byte) error {
	type alias NTLMAVPair
	var a alias
	if err := strictUnmarshalJSON(b, &a); err != nil {
		return err
	}
	*p = NTLMAVPair(a)
	return nil
}

// strictUnmarshalJSON is the shared recursive strict-decode primitive.
func strictUnmarshalJSON(b []byte, v interface{}) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

// 6 wire_fault 值（设计 §2 键表逐字；锚词=testcase §4 目标词——逐值单锚词）。
const (
	NTLMWireFaultMessageLength   = "message_length"    // 通用头/固定字段截断
	NTLMWireFaultSecurityBuffer  = "security_buffer"   // Len/MaxLen/编码/承载不合法
	NTLMWireFaultOffsetOverflow  = "offset_overflow"   // offset 越界/溢出/重叠
	NTLMWireFaultFlagsTargetInfo = "flags_target_info" // flags 交集/TargetInfo 协商不一致
	NTLMWireFaultBlobAVPairs     = "blob_av_pairs"     // NTLMv2 response/blob/AV_PAIR 不合法
	NTLMWireFaultCarrierProfile  = "carrier_profile"   // SMB/HTTP/SPNEGO/载体 profile 错
)

// DescribeNTLMWireFault returns the value's 主锚词（error_contains 断言）。
func DescribeNTLMWireFault(kind string) (string, error) {
	anchors := map[string]string{
		NTLMWireFaultMessageLength:   "message",
		NTLMWireFaultSecurityBuffer:  "buffer",
		NTLMWireFaultOffsetOverflow:  "offset",
		NTLMWireFaultFlagsTargetInfo: "flags",
		NTLMWireFaultBlobAVPairs:     "blob",
		NTLMWireFaultCarrierProfile:  "carrier",
	}
	a, ok := anchors[kind]
	if !ok {
		return "", fmt.Errorf("ntlm: unknown wire_fault kind %q", kind)
	}
	return a, nil
}
