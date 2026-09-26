package core

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// OCSP（D-OCSP-1 #46，契约 62-ocsp v1.1.0）配置类型。
//
// 字段名对齐契约 §12.1 目标形状：层链 [ip→tcp→(http)→ocsp]，地址只住
// ip 层、端口只住 tcp 层、数量走 flow_control；业务键全量迁入 ocsp 层。
// 双 profile（契约 §11.4 裁定1）：DependsOn ["tcp"] + OptionalOn ["http"] +
// TransportOn ["tcp"]——裸 TCP profile 走 [ip,tcp,ocsp]，HTTP profile 由用户
// 显式写 http 层启用 [ip,tcp,http,ocsp]。
//
// 编码权威：ASN.1 DER definite-length（X.690 §10—11：最短 length、最短
// INTEGER、DEFAULT 值不编码——契约 §3/§4）。签名/证书取证面 opaque（无
// 私钥不宣称验证成功——契约 §1/§4）。
//
// 语义边界：OCSPRequest/OCSPResponse 的所有结构面（CertID/批量 requestList/
// nonce 双层 OCTET STRING/optionalSignature/BasicOCSPResponse/SingleResponse
// 三态/时间窗）结构化可见；signature/cert/issuer-hash 的**值**为确定性
// fixture（不伪造真实密码学语义）。

// OCSPProfile* 是 profile 取值（契约 §2 配置键表逐字）。
const (
	OCSPProfileHTTPPost = "http-post" // HTTP POST，Content-Type application/ocsp-request/response
	OCSPProfileHTTPGet  = "http-get"  // RFC 5019 轻量 profile：DER base64url（无 padding）入 URI
	OCSPProfileTCP      = "tcp"       // 裸 TCP stream：整 DER 直发，无私有长度前缀
)

// OCSP 哈希算法与证书状态取值（契约 §2/§3/§4）。
const (
	OCSPHashSHA1   = "sha1"   // RFC 6960 CertID.hashAlgorithm（OID 1.3.14.3.2.26，20B）
	OCSPHashSHA256 = "sha256" // RFC 8954 CertID.hashAlgorithm（OID 2.16.840.1.101.3.4.2.1，32B）

	OCSPStatusGood    = "good"    // CertStatus [0] IMPLICIT NULL
	OCSPStatusRevoked = "revoked" // CertStatus [1] IMPLICIT RevokedInfo
	OCSPStatusUnknown = "unknown" // CertStatus [2] IMPLICIT NULL
)

// OCSPExpect* 是 responseStatus 取值名（RFC 6960 §4.2.1；4 未用保留——
// 契约 §10.1 行 5）。
const (
	OCSPExpectSuccessful    = "successful"     // 0
	OCSPExpectMalformed     = "malformed"      // 1 malformedRequest
	OCSPExpectInternalError = "internal_error" // 2
	OCSPExpectTryLater      = "try_later"      // 3
	OCSPExpectSigRequired   = "sig_required"   // 5
	OCSPExpectUnauthorized  = "unauthorized"   // 6
)

// OCSPConfig is the flow's ocsp terminal-layer configuration.
type OCSPConfig struct {
	// Profile: http-post（缺省）/http-get/tcp（契约 §2）。链上无 http 层时
	// 缺省回退 tcp（双 profile 可达性——§11.4 裁定1）。
	Profile string `json:"profile,omitempty"`
	// HashAlgorithm: sha1（缺省）/sha256，决定 CertID.hashAlgorithm OID 与
	// issuer hash 长度绑定（RFC 8954 §2；契约 §3）。
	HashAlgorithm string `json:"hash_algorithm,omitempty"`
	// RequestCount 是 requestList 项数（批量形，缺省 1）。request.certs
	// 非空时以它为准，二者冲突判死（批量项不匹配守卫）。
	RequestCount int `json:"request_count,omitempty"`
	// Nonce 是请求/响应 nonce 扩展（OID 1.3.6.1.5.5.7.48.1.2）。
	Nonce *OCSPNonce `json:"nonce,omitempty"`
	// CertStatus: good（缺省）/revoked/unknown——单响应状态缺省值。
	CertStatus string `json:"cert_status,omitempty"`
	// SignedRequest 启用 requestorName [1] + optionalSignature [0]。
	SignedRequest bool `json:"signed_request,omitempty"`
	// SignatureAlgorithm 覆盖签名算法名（缺省按 hash_algorithm 派生）；
	// 未知值判死（signature/algorithm 锚词——契约 §4）。
	SignatureAlgorithm string `json:"signature_algorithm,omitempty"`
	// Version 非 nil 时显式编码 version [0] EXPLICIT（v1 DEFAULT 按 DER
	// §11.5 恒省略；显式形属 fixture 逃生口——契约 §10.3 版本变体）。
	Version *int `json:"version,omitempty"`
	// Certs 在 optionalSignature/BasicOCSPResponse 内嵌 X.509 certificate
	// fixture（结构可见、值 opaque——契约 §1/§4）。
	Certs bool `json:"certs,omitempty"`
	// ResponseExtensions/SingleExtensions 在 ResponseData [1] 与
	// SingleResponse [1] 槽内编码 Extensions（契约 §4/用例 §3.11）。
	ResponseExtensions bool `json:"response_extensions,omitempty"`
	SingleExtensions   bool `json:"single_extensions,omitempty"`
	// ResponderID 覆盖 ResponderID CHOICE 形：""/bykey（缺省，byKey [2]
	// KeyHash）或 byname（byName [1] Name——目录名 RDNSequence）。
	ResponderID string `json:"responder_id,omitempty"`
	// ProducedAt/ThisUpdate/NextUpdate 是 GeneralizedTime fixture 覆盖
	// （缺省见 builder 常量；next_update "none" = 缺省 Optional 字段，
	// 契约 §3 时间窗变体）。
	ProducedAt string `json:"produced_at,omitempty"`
	ThisUpdate string `json:"this_update,omitempty"`
	NextUpdate string `json:"next_update,omitempty"`
	// Sessions 是有序会话列表：每会话独立四元组 + 事务序列（会话间
	// CertID/nonce/响应/重组缓存状态全隔离——契约 §6）。
	Sessions []OCSPSession `json:"sessions,omitempty"`
	// WireFault 仅负例注入口（6 值枚举，契约 §2 与用例 §4 三方同序）。
	WireFault string `json:"wire_fault,omitempty"`
}

// OCSPNonce 是 nonce 扩展配置（双层 OCTET STRING：extnValue 外层 OCTET
// STRING 内再包 DER OCTET STRING，长度逐层计算——契约 §2/§5）。
type OCSPNonce struct {
	// Enabled 启用 nonce 扩展（请求 requestExtensions [2] + 响应
	// responseExtensions [1]，两侧同值——契约 §5 same_as）。
	Enabled bool `json:"enabled,omitempty"`
	// Value 是 nonce 字节 hex fixture（1..32B，RFC 8954 §4 上限）；空 =
	// 按 Seed+会话/事务序号确定性派生（§12.12 rand 策略可复现面）。
	Value string `json:"value,omitempty"`
	// Seed 是派生根（非零使非 fixture 面可复现）。
	Seed *int `json:"seed,omitempty"`
	// Opaque 声明值不透明（契约 §2 形态键；值本身不参与断言）。
	Opaque bool `json:"opaque,omitempty"`
}

// OCSPSession 是一个 OCSP 会话：四元组覆盖 + 有序事务（每事务 = 一次
// request→response 交换，可含 keep-alive 复用——契约 §12.3）。
type OCSPSession struct {
	// ID 是会话标识（fixture 面；事务 id 同）。
	ID string `json:"id,omitempty"`
	// Profile 覆盖层 profile（会话级；与链上 http 层有无必须一致）。
	Profile string `json:"profile,omitempty"`
	// SrcIP overrides the session's source IP（多会话双客户端；空 = 流
	// 缺省。up 直落，down 留空走链层交换——bacnet/dtls 先例）。
	SrcIP string `json:"src_ip,omitempty"`
	// SrcPort overrides the session's source port（0 = 流缺省）。会话
	// 端口变化即独立 TCP 连接（tcp 层 connKey 语义）。
	SrcPort uint16 `json:"src_port,omitempty"`
	// DstPort overrides the session's destination port（0 = 继承链级缺省
	// 80 via FieldContract；validator 守会话间一致性）。裸 TCP profile
	// 惯用 8080（fixture 显式写，不依赖补齐——§13 §8.7）。
	DstPort      uint16            `json:"dst_port,omitempty"`
	Transactions []OCSPTransaction `json:"transactions,omitempty"`
}

// OCSPTransaction 是一个 OCSP 事务（request→response 交换）。
type OCSPTransaction struct {
	ID string `json:"id,omitempty"`
	// Request 声明 requestList（缺省 = request_count 项 auto serial）。
	Request *OCSPRequestSpec `json:"request,omitempty"`
	// ExpectStatus 是 responseStatus 取值名（缺省 successful）；非成功
	// 响应无 responseBytes（RFC 6960 §4.2.1——不得伪造成功响应）。
	ExpectStatus string `json:"expect_status,omitempty"`
	// CertStatus 覆盖单响应状态（批量三态见 Request.Certs[].Status）。
	CertStatus string `json:"cert_status,omitempty"`
}

// OCSPRequestSpec 是事务的请求面声明。
type OCSPRequestSpec struct {
	// Certs 是 requestList 逐项 CertID（顺序保留，不静默去重/重排——
	// 契约 §2）。空 = 按 request_count 生成 auto serial 项。
	Certs []OCSPCertEntry `json:"certs,omitempty"`
}

// OCSPCertEntry 是一个 CertID 声明项。
type OCSPCertEntry struct {
	// Serial 是证书序列号：""/"auto" = 确定性递增 fixture（0x10000000+i）；
	// 或十进制 / 0x 前缀十六进制字面量（最短 INTEGER 编码——契约 §3）。
	Serial string `json:"serial,omitempty"`
	// Status 是该证书的响应状态（缺省继承层 cert_status）。
	Status string `json:"status,omitempty"`
	// HashAlgorithm 覆盖该 CertID 的算法（缺省继承层 hash_algorithm）。
	HashAlgorithm string `json:"hash_algorithm,omitempty"`
	// IssuerNameHash/IssuerKeyHash 是 hex fixture（长度必须等于算法 digest
	// 长度，否则算法↔长度绑定守卫判死——契约 §2/§3）。空 = fixture 缺省。
	IssuerNameHash string `json:"issuer_name_hash,omitempty"`
	IssuerKeyHash  string `json:"issuer_key_hash,omitempty"`
	// NextUpdate ""（缺省，按层 fixture）/ "none"（省略 Optional 字段）/
	// GeneralizedTime 字面量（契约 §3 nextUpdate 可选 [0] EXPLICIT）。
	NextUpdate string `json:"next_update,omitempty"`
	// RevocationReason 是 revoked 状态的 CRLReason（缺省 1=keyCompromise）。
	RevocationReason *int `json:"revocation_reason,omitempty"`
}

// UnmarshalJSON strict-decodes the ocsp layer config（未知键拒绝；
// kerberos/dtls 同款递归严格面——会话/事务/证书项为值切片，同一 decoder
// 逐层拒绝未知键）。
func (c *OCSPConfig) UnmarshalJSON(b []byte) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	type alias OCSPConfig
	var a alias
	if err := dec.Decode(&a); err != nil {
		return err
	}
	*c = OCSPConfig(a)
	return nil
}

// 6 wire_fault 值（契约 §2 配置键表逐字；锚词=用例 §4 目标词——逐值
// 单锚词；负例 ID 后缀与 wire_fault 值不同名是设计既定——§7 表）。
const (
	OCSPWireFaultDERTruncated = "der_truncated"    // DER 父/子 TLV 截断
	OCSPWireFaultCertIDHash   = "certid_hash"      // 算法↔hash 长度/CertID tag/serial 错
	OCSPWireFaultReqResp      = "request_response" // 响应 CertID/批量项/状态/nonce 与请求不匹配
	OCSPWireFaultNonce        = "nonce"            // nonce 嵌套/重复/缺失/长度/关联错
	OCSPWireFaultSignature    = "signature"        // signatureAlgorithm/signature/certs 结构错
	OCSPWireFaultCarrier      = "carrier"          // HTTP method/content type/status、TCP stream、端口、地址族错
)

// DescribeOCSPWireFault returns the row's 主锚词（error_contains 断言）。
func DescribeOCSPWireFault(kind string) (string, error) {
	anchors := map[string]string{
		OCSPWireFaultDERTruncated: "der",
		OCSPWireFaultCertIDHash:   "hash",
		OCSPWireFaultReqResp:      "match",
		OCSPWireFaultNonce:        "nonce",
		OCSPWireFaultSignature:    "algorithm",
		OCSPWireFaultCarrier:      "carrier",
	}
	a, ok := anchors[kind]
	if !ok {
		return "", fmt.Errorf("ocsp: unknown wire_fault kind %q", kind)
	}
	return a, nil
}
