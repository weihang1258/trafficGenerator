// Package ocsp — OCSP（RFC 6960 / RFC 8954）终结层。
//
// 链形（契约 §11.4 裁定1）：DependsOn ["tcp"] + OptionalOn ["http"] +
// TransportOn ["tcp"]——裸 TCP profile 走 [ip,tcp,ocsp]（整 DER 直发）；
// HTTP profile 由用户显式写 http 层启用 [ip,tcp,http,ocsp]（POST body /
// RFC 5019 GET base64url URI）。
//
// **http 层分工（gbt/mmse 同族透传）**：HTTP profile 下本层每事务产「完整
// HTTP POST/GET 请求帧」+「完整 HTTP 200/503 响应帧」（RFC 6960 A.1），http
// 层原样转发；裸 TCP profile 下产「整 DER 消息」两条事件直发。分工点：
// HTTP 语法（请求行/状态行/头/Content-Length/503/Retry-After）由本层按
// A.1 钉死后借道 http 层传输，OCSP 语义（DER/算法/CertID/nonce/状态/时间）
// 全归本层。
//
// 编码权威：X.690 DER definite-length（最短 length、最短 INTEGER、DEFAULT
// 值不编码）。签名/证书/issuer hash 的**值**为确定性 fixture（无 key 不
// 宣称验证成功——契约 §1/§4）。
package ocsp

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// ---- OID（DER TLV 原文；契约 §3/§4/§5）----

var (
	oidSHA1        = []byte{0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A}                         // 1.3.14.3.2.26（RFC 6960 CertID）
	oidSHA256      = []byte{0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01} // 2.16.840.1.101.3.4.2.1（RFC 8954）
	oidSHA1RSA     = []byte{0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x05} // sha1WithRSAEncryption
	oidSHA256RSA   = []byte{0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B} // sha256WithRSAEncryption
	oidECDSASHA256 = []byte{0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02}       // ecdsa-with-SHA256（1.2.840.10045.4.3.2）
	oidRSAPubKey   = []byte{0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01} // rsaEncryption（证书 fixture SPKI）
	oidNonce       = []byte{0x06, 0x09, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x02} // 1.3.6.1.5.5.7.48.1.2（RFC 6960 §4.4.1）
	oidBasic       = []byte{0x06, 0x09, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01} // 1.3.6.1.5.5.7.48.1.1（id-pkix-ocsp-basic）
	oidCommonName  = []byte{0x06, 0x03, 0x55, 0x04, 0x03}                                     // 2.5.4.3（证书 fixture DN）
)

// fixture 缺省（契约 §2 形态；确定性、无随机源）。
const (
	fixtureSerialBase   = 0x10000000 // auto serial 基：base + si*0x100 + ti*0x10 + ei
	fixtureNameHashFill = 0x11       // issuerNameHash fixture 填充（无 issuer 证书时不伪造真哈希）
	fixtureKeyHashFill  = 0x22       // issuerKeyHash fixture 填充
	fixtureResponderKey = 0x33       // ResponderID byKey [2] KeyHash fixture
	fixtureSignatureLen = 64         // signature BIT STRING 数据长度（opaque）
	fixtureSignatureVal = 0x77       // signature 确定性填充（不伪造真实签名值）
	fixtureCertSigVal   = 0x99       // 证书 fixture signatureValue 填充
	fixtureNonceLen     = 16         // 派生 nonce 长度（RFC 8954 §4 允许 1..32）
	fixtureNonceSeed    = 0x0C5F     // nonce 派生根（非零使可复现）
	fixtureProducedAt   = "20260926120000Z"
	fixtureThisUpdate   = "20260926120000Z"
	fixtureNextUpdate   = "20260927120000Z"
	fixtureRevokedAt    = "20260920100000Z"
	fixtureResponderCN  = "OCSP Responder CA"
	fixtureRequestor    = "ocsp-requester@example.test"
	maxRequestListItems = 256 // requestList 项数上界（生成器策略）
)

// nonceMaxLen 是 nonce 字节上界（RFC 8954 §4：responder 须接受 1..32 字节；
// 本生成器按此上界守卫——超界 = nonce/length 锚词负例，契约 §5）。
const nonceMaxLen = 32

// expectCodes 是 responseStatus 取值名→数值（RFC 6960 §4.2.1；4 未用保留，
// 契约 §10.1 行 5）。
var expectCodes = map[string]int{
	core.OCSPExpectSuccessful:    0,
	core.OCSPExpectMalformed:     1,
	core.OCSPExpectInternalError: 2,
	core.OCSPExpectTryLater:      3,
	core.OCSPExpectSigRequired:   5,
	core.OCSPExpectUnauthorized:  6,
}

// hashLens 是算法→digest 长度（CertID issuer hash 绑定面，契约 §3）。
var hashLens = map[string]int{core.OCSPHashSHA1: 20, core.OCSPHashSHA256: 32}

// sigAlgs 是签名算法名→OID（结构可见面；无 key 不宣称验证成功，契约 §4）。
var sigAlgs = map[string][]byte{
	"sha1-rsa":     oidSHA1RSA,
	"sha256-rsa":   oidSHA256RSA,
	"sha256-ecdsa": oidECDSASHA256,
	"sha1":         oidSHA1,
	"sha256":       oidSHA256,
}

// ---- 渲染计划（解析 + 守卫唯一权威：planner 校验与 generator 生成同路径）----

// entryPlan 是一个 CertID 的已解析渲染参数。
type entryPlan struct {
	serial     int
	status     string
	hashAlg    string // 有效算法名（算法↔hash 长度绑定面）
	nameHash   []byte
	keyHash    []byte
	nextUpdate string // "" = 省略 Optional 字段
	revReason  int
}

// txPlan 是一个事务的已解析渲染计划。
type txPlan struct {
	sessIdx    int
	txIdx      int
	profile    string
	hashAlg    string // 层算法（签名算法缺省派生面）
	entries    []entryPlan
	nonce      []byte // 请求/响应同值（nil = 无 nonce 扩展）
	expect     int    // responseStatus 数值
	signed     bool
	sigAlg     []byte
	withCert   bool
	responder  string // bykey（缺省）/byname
	version    *int
	respExts   bool
	singleExts bool
	producedAt string
	thisUpdate string
}

// resolvePlan 把一个事务解析为完整渲染计划（含全部守卫）。校验与生成
// 共用本函数——不做第二套规则（kerberos 同判）。hasHTTP 声明链上是否
// 存在 http 层（profile 缺省面）。
func resolvePlan(cfg *core.OCSPConfig, hasHTTP bool, sess *core.OCSPSession, si, ti int) (*txPlan, error) {
	tx := &sess.Transactions[ti]

	profile := sess.Profile
	if profile == "" {
		profile = cfg.Profile
	}
	if profile == "" {
		if hasHTTP {
			profile = core.OCSPProfileHTTPPost
		} else {
			profile = core.OCSPProfileTCP
		}
	}
	switch profile {
	case core.OCSPProfileHTTPPost, core.OCSPProfileHTTPGet, core.OCSPProfileTCP:
	default:
		return nil, fmt.Errorf("ocsp: sessions[%d].transactions[%d]: unknown profile %q (profile)", si, ti, profile)
	}

	hashAlg := cfg.HashAlgorithm
	if hashAlg == "" {
		hashAlg = core.OCSPHashSHA1
	}
	if _, ok := hashLens[hashAlg]; !ok {
		return nil, fmt.Errorf("ocsp: unsupported hash_algorithm %q (hash)", hashAlg)
	}

	p := &txPlan{sessIdx: si, txIdx: ti, profile: profile, hashAlg: hashAlg, signed: cfg.SignedRequest}

	// responseStatus（缺省 successful；非成功响应不得带 responseBytes——
	// RFC 6960 §4.2.1）。
	expectName := tx.ExpectStatus
	if expectName == "" {
		expectName = core.OCSPExpectSuccessful
	}
	code, ok := expectCodes[expectName]
	if !ok {
		return nil, fmt.Errorf("ocsp: sessions[%d].transactions[%d]: unknown expect_status %q (response)", si, ti, expectName)
	}
	p.expect = code

	// requestList：显式 certs[] 保序；否则 request_count 项 auto serial。
	var entries []core.OCSPCertEntry
	if tx.Request != nil && len(tx.Request.Certs) > 0 {
		if cfg.RequestCount != 0 && cfg.RequestCount != len(tx.Request.Certs) {
			return nil, fmt.Errorf("ocsp: sessions[%d].transactions[%d]: request_count %d does not match request.certs length %d (match)",
				si, ti, cfg.RequestCount, len(tx.Request.Certs))
		}
		entries = tx.Request.Certs
	} else {
		n := cfg.RequestCount
		if n <= 0 {
			n = 1
		}
		if n > maxRequestListItems {
			return nil, fmt.Errorf("ocsp: request_count %d out of range 1..%d (count)", n, maxRequestListItems)
		}
		entries = make([]core.OCSPCertEntry, n)
	}

	for ei := range entries {
		ep, err := resolveEntry(cfg, tx, &entries[ei], si, ti, ei)
		if err != nil {
			return nil, err
		}
		p.entries = append(p.entries, *ep)
	}

	// nonce：请求 requestExtensions [2] 与响应 responseExtensions [1] 同值
	// （same_as 断言面，契约 §5）。
	if cfg.Nonce != nil && cfg.Nonce.Enabled {
		nb, err := resolveNonce(cfg.Nonce, si, ti)
		if err != nil {
			return nil, err
		}
		p.nonce = nb
	}

	// 签名算法（optionalSignature 与 BasicOCSPResponse 的 signatureAlgorithm）。
	sigName := cfg.SignatureAlgorithm
	if sigName == "" {
		if hashAlg == core.OCSPHashSHA256 {
			sigName = "sha256-rsa"
		} else {
			sigName = "sha1-rsa"
		}
	}
	sigOID, ok := sigAlgs[sigName]
	if !ok {
		return nil, fmt.Errorf("ocsp: unknown signature_algorithm %q (algorithm)", sigName)
	}
	p.sigAlg = sigOID
	p.withCert = cfg.Certs

	p.responder = cfg.ResponderID
	if p.responder == "" {
		p.responder = "bykey"
	}
	if p.responder != "bykey" && p.responder != "byname" {
		return nil, fmt.Errorf("ocsp: unknown responder_id %q (responder)", p.responder)
	}
	p.version = cfg.Version
	if p.version != nil && *p.version == 0 {
		// v1 是 DEFAULT：X.690 §11.5 禁止编码等于默认值的分量——显式
		// A0 03 02 01 00 属非规范形，恒省略（schema 默认 0 也必须走此归一，
		// 否则层 config 默认值会把 canonical DER 变成 BER 宽松形）。
		p.version = nil
	}
	p.respExts = cfg.ResponseExtensions
	p.singleExts = cfg.SingleExtensions
	p.producedAt = orDefault(cfg.ProducedAt, fixtureProducedAt)
	p.thisUpdate = orDefault(cfg.ThisUpdate, fixtureThisUpdate)
	return p, nil
}

// orDefault 返回值或 fixture 缺省。
func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

// resolveEntry 解析一个 CertID 项：serial/状态/算法↔hash 长度绑定/hash
// fixture 长度（算法↔长度绑定守卫=自然面负例通道，契约 §3/§7）。
func resolveEntry(cfg *core.OCSPConfig, tx *core.OCSPTransaction, e *core.OCSPCertEntry, si, ti, ei int) (*entryPlan, error) {
	alg := e.HashAlgorithm
	if alg == "" {
		alg = cfg.HashAlgorithm
	}
	if alg == "" {
		alg = core.OCSPHashSHA1
	}
	hlen, ok := hashLens[alg]
	if !ok {
		return nil, fmt.Errorf("ocsp: sessions[%d].transactions[%d].request.certs[%d]: unsupported hash_algorithm %q (hash)", si, ti, ei, alg)
	}

	status := e.Status
	if status == "" {
		status = tx.CertStatus
	}
	if status == "" {
		status = cfg.CertStatus
	}
	if status == "" {
		status = core.OCSPStatusGood
	}
	switch status {
	case core.OCSPStatusGood, core.OCSPStatusRevoked, core.OCSPStatusUnknown:
	default:
		return nil, fmt.Errorf("ocsp: sessions[%d].transactions[%d].request.certs[%d]: unknown cert_status %q (status)", si, ti, ei, status)
	}

	ep := &entryPlan{status: status, hashAlg: alg, revReason: 1} // 1 = keyCompromise（RFC 5280 CRLReason）

	serial, err := parseSerial(e.Serial, si, ti, ei)
	if err != nil {
		return nil, err
	}
	ep.serial = serial

	nameHash, err := entryHash(e.IssuerNameHash, fixtureNameHashFill, hlen, si, ti, ei, "issuer_name_hash")
	if err != nil {
		return nil, err
	}
	keyHash, err := entryHash(e.IssuerKeyHash, fixtureKeyHashFill, hlen, si, ti, ei, "issuer_key_hash")
	if err != nil {
		return nil, err
	}
	ep.nameHash, ep.keyHash = nameHash, keyHash

	// nextUpdate："" = 层 fixture 缺省；"none" = 省略 Optional 字段。
	nxt := e.NextUpdate
	if nxt == "" {
		nxt = cfg.NextUpdate
	}
	switch nxt {
	case "none":
		ep.nextUpdate = ""
	case "":
		ep.nextUpdate = fixtureNextUpdate
	default:
		ep.nextUpdate = nxt
	}

	if e.RevocationReason != nil {
		ep.revReason = *e.RevocationReason
	}
	return ep, nil
}

// parseSerial 解析序列号：""/"auto" = 确定性递增 fixture；0x 前缀十六进制
// 或十进制字面量（最短 INTEGER 编码由 derInteger 保证——契约 §3）。
func parseSerial(s string, si, ti, ei int) (int, error) {
	switch s {
	case "", "auto":
		return fixtureSerialBase + si*0x100 + ti*0x10 + ei, nil
	}
	base := 10
	digits := s
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		base, digits = 16, s[2:]
	}
	v, err := strconv.ParseInt(digits, base, 64)
	if err != nil || v < 0 {
		return 0, fmt.Errorf("ocsp: sessions[%d].transactions[%d].request.certs[%d]: invalid serial %q (serial)", si, ti, ei, s)
	}
	return int(v), nil
}

// entryHash 解析 hex fixture 或按填充字节生成，长度绑定算法 digest 长度。
func entryHash(hexStr string, fillByte byte, hlen int, si, ti, ei int, what string) ([]byte, error) {
	if hexStr == "" {
		return fillBytes(fillByte, hlen), nil
	}
	b, err := hex.DecodeString(strings.ToLower(hexStr))
	if err != nil {
		return nil, fmt.Errorf("ocsp: sessions[%d].transactions[%d].request.certs[%d]: %s is not valid hex (hash)", si, ti, ei, what)
	}
	if len(b) != hlen {
		return nil, fmt.Errorf("ocsp: sessions[%d].transactions[%d].request.certs[%d]: certid hash length mismatch: %s is %d bytes but hash_algorithm requires %d (hash)",
			si, ti, ei, what, len(b), hlen)
	}
	return b, nil
}

// resolveNonce 解析 nonce 字节：hex fixture 或按 seed+会话/事务序号确定性
// 派生（§12.12 rand 策略可复现面；不同会话 distinct）。
func resolveNonce(n *core.OCSPNonce, si, ti int) ([]byte, error) {
	if n.Value != "" {
		b, err := hex.DecodeString(strings.ToLower(n.Value))
		if err != nil {
			return nil, fmt.Errorf("ocsp: nonce value %q is not valid hex (nonce)", n.Value)
		}
		if len(b) == 0 || len(b) > nonceMaxLen {
			return nil, fmt.Errorf("ocsp: nonce value is %d bytes; nonce length must be 1..%d bytes (nonce)", len(b), nonceMaxLen)
		}
		return b, nil
	}
	seed := fixtureNonceSeed
	if n.Seed != nil {
		seed = *n.Seed
	}
	// LCG 派生（确定性；非密码学随机——Opaque 语义，不断言随机质量）。
	s := uint32(seed)*2654435761 + uint32(si*131+ti*17+1)*40503
	out := make([]byte, fixtureNonceLen)
	for i := range out {
		s = s*1664525 + 1013904223
		out[i] = byte(s >> 24)
	}
	return out, nil
}

// ---- DER 渲染（RFC 6960 §4.1/§4.2 结构逐层）----

// algorithmIdentifier 渲染 AlgorithmIdentifier：SHA-1 带 NULL 参数，
// SHA-256 参数缺省（RFC 8954 §2——SHA-256 无参数）。
func algorithmIdentifier(oid []byte, nullParam bool) []byte {
	if nullParam {
		return derSeq(oid, tlv(0x05, nil))
	}
	return derSeq(oid)
}

// hashOID 返回算法 OID（调用方已校验算法合法）。
func hashOID(alg string) []byte {
	if alg == core.OCSPHashSHA256 {
		return oidSHA256
	}
	return oidSHA1
}

// renderCertID 渲染 CertID ::= SEQUENCE{ hashAlgorithm, issuerNameHash,
// issuerKeyHash, serialNumber }（契约 §3）。
func renderCertID(ep *entryPlan) []byte {
	return derSeq(
		algorithmIdentifier(hashOID(ep.hashAlg), ep.hashAlg == core.OCSPHashSHA1),
		derOctet(ep.nameHash),
		derOctet(ep.keyHash),
		derInteger(ep.serial),
	)
}

// extensions 渲染 Extensions ::= SEQUENCE OF Extension，仅 nonce 一型
// （extnValue 双层 OCTET STRING：外层包内层 DER 全字节，长度逐层计算——
// 契约 §2/§5；critical DEFAULT FALSE 按 DER §11.5 不编码）。
func extensions(nonce []byte) []byte {
	inner := derOctet(nonce)
	return derSeq(derSeq(oidNonce, derOctet(inner)))
}

// renderRequest 渲染 OCSPRequest（契约 §3）：
//
//	SEQUENCE{ tbsRequest TBSRequest, optionalSignature [0] EXPLICIT OPTIONAL }
func renderRequest(p *txPlan) []byte {
	var reqList []byte
	for i := range p.entries {
		reqList = append(reqList, derSeq(renderCertID(&p.entries[i]))...)
	}

	tbs := []byte{}
	if p.version != nil {
		tbs = append(tbs, derCtxExplicit(0, derInteger(*p.version))...)
	}
	if p.signed {
		// requestorName [1] EXPLICIT GeneralName，取 rfc822Name [1] IA5String。
		tbs = append(tbs, derCtxExplicit(1, derCtxImplicitPrim(1, []byte(fixtureRequestor)))...)
	}
	tbs = append(tbs, derSeq(reqList)...)
	if p.nonce != nil {
		tbs = append(tbs, derCtxExplicit(2, extensions(p.nonce))...)
	}

	parts := [][]byte{derSeq(tbs)}
	if p.signed {
		parts = append(parts, derCtxExplicit(0, renderSignature(p.sigAlg, p.withCert)))
	}
	return derSeq(parts...)
}

// renderSignature 渲染 Signature ::= SEQUENCE{ signatureAlgorithm,
// signature BIT STRING, certs [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL }
// （无 key 不宣称验证成功——signature/cert 值 opaque fixture，契约 §4）。
func renderSignature(sigAlg []byte, withCert bool) []byte {
	parts := [][]byte{
		derSeq(sigAlg),
		derBitString(fillBytes(fixtureSignatureVal, fixtureSignatureLen), 0),
	}
	if withCert {
		parts = append(parts, derCtxExplicit(0, derSeq(fixtureCertificate())))
	}
	return derSeq(parts...)
}

// renderResponse 渲染 OCSPResponse（契约 §4）：
//
//	SEQUENCE{ responseStatus ENUMERATED, responseBytes [0] EXPLICIT OPTIONAL }
//
// 非 successful 状态不带 responseBytes（RFC 6960 §4.2.1）。
func renderResponse(p *txPlan) []byte {
	parts := [][]byte{derEnum(p.expect)}
	if p.expect == 0 {
		parts = append(parts, derCtxExplicit(0, derSeq(oidBasic, derOctet(renderBasicResponse(p)))))
	}
	return derSeq(parts...)
}

// renderBasicResponse 渲染 BasicOCSPResponse ::= SEQUENCE{ tbsResponseData,
// signatureAlgorithm, signature, certs [0] EXPLICIT OPTIONAL }（契约 §4）。
func renderBasicResponse(p *txPlan) []byte {
	parts := [][]byte{
		renderResponseData(p),
		derSeq(p.sigAlg),
		derBitString(fillBytes(fixtureSignatureVal, fixtureSignatureLen), 0),
	}
	if p.withCert {
		parts = append(parts, derCtxExplicit(0, derSeq(fixtureCertificate())))
	}
	return derSeq(parts...)
}

// renderResponseData 渲染 ResponseData ::= SEQUENCE{ responderID, producedAt,
// responses SEQUENCE OF SingleResponse, responseExtensions [1] EXPLICIT
// OPTIONAL }（version DEFAULT v1 按 DER §11.5 恒省略；契约 §4）。
func renderResponseData(p *txPlan) []byte {
	var srs []byte
	for i := range p.entries {
		srs = append(srs, renderSingleResponse(p, &p.entries[i])...)
	}
	parts := [][]byte{
		renderResponderID(p.responder),
		derGeneralizedTime(p.producedAt),
		derSeq(srs),
	}
	if p.respExts && p.nonce != nil {
		parts = append(parts, derCtxExplicit(1, extensions(p.nonce)))
	}
	return derSeq(parts...)
}

// renderResponderID 渲染 ResponderID CHOICE：byKey [2] KeyHash（默认）或
// byName [1] Name。RFC 6960 ASN.1 模块是 EXPLICIT TAGS——KeyHash 是 OCTET
// STRING，[2] 必须显式包一层（a2 16 04 14 …），不能 IMPLICIT 原语化
// （82 14 会让 tshark OCSP dissector 在 responderID 后中止解析——P5 实证）。
func renderResponderID(kind string) []byte {
	if kind == "byname" {
		return derCtxExplicit(1, directoryName(fixtureResponderCN))
	}
	return derCtxExplicit(2, derOctet(fillBytes(fixtureResponderKey, 20)))
}

// renderSingleResponse 渲染 SingleResponse ::= SEQUENCE{ certID, certStatus,
// thisUpdate, nextUpdate [0] EXPLICIT OPTIONAL, singleExtensions [1] EXPLICIT
// OPTIONAL }（契约 §4）。
func renderSingleResponse(p *txPlan, ep *entryPlan) []byte {
	parts := [][]byte{
		renderCertID(ep),
		renderCertStatus(ep),
		derGeneralizedTime(p.thisUpdate),
	}
	if ep.nextUpdate != "" {
		parts = append(parts, derCtxExplicit(0, derGeneralizedTime(ep.nextUpdate)))
	}
	if p.singleExts && p.nonce != nil {
		parts = append(parts, derCtxExplicit(1, extensions(p.nonce)))
	}
	return derSeq(parts...)
}

// renderCertStatus 渲染 CertStatus CHOICE（IMPLICIT，非字符串——契约 §4）：
// good [0] IMPLICIT NULL / revoked [1] IMPLICIT RevokedInfo / unknown [2]。
func renderCertStatus(ep *entryPlan) []byte {
	switch ep.status {
	case core.OCSPStatusRevoked:
		revoked := derGeneralizedTime(fixtureRevokedAt)
		revoked = append(revoked, derCtxExplicit(0, derEnum(ep.revReason))...)
		return derCtxImplicitCons(1, revoked)
	case core.OCSPStatusUnknown:
		return derCtxImplicitPrim(2, nil)
	default:
		return derCtxImplicitPrim(0, nil)
	}
}

// directoryName 渲染 Name（RDNSequence → 单 RDN 单属性 CN，X.509 fixture）。
func directoryName(cn string) []byte {
	return derSeq(tlv(0x31, derSeq(oidCommonName, derPrintable(cn))))
}

// fixtureCertificate 渲染证书 fixture（X.509 v3 结构完整、签名值 opaque；
// 私钥不存在故不宣称可信——契约 §1/§4）。
func fixtureCertificate() []byte {
	spki := derSeq(
		algorithmIdentifier(oidRSAPubKey, true),
		derBitString(derSeq(derInteger(0xC0FFEE01), derInteger(65537)), 0),
	)
	tbs := derSeq(
		derCtxExplicit(0, derInteger(2)), // version v3
		derInteger(0x1234567890),
		algorithmIdentifier(oidSHA256RSA, false),
		directoryName(fixtureResponderCN),
		derSeq(derUTCTime("260101000000Z"), derUTCTime("270101000000Z")),
		directoryName(fixtureResponderCN),
		spki,
	)
	return derSeq(
		tbs,
		algorithmIdentifier(oidSHA256RSA, false),
		derBitString(fillBytes(fixtureCertSigVal, fixtureSignatureLen), 0),
	)
}

// fillBytes 构造 n 字节确定性填充。
func fillBytes(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

// ---- 双 profile 线帧（契约 §5；gbt/mmse 同族——HTTP profile 产完整 HTTP
// 帧，http 层原样转发；裸 TCP profile 产整 DER 直发）----

// frame 是一条完整线消息：方向 + 完整字节（HTTP profile = 完整 HTTP 帧，
// 裸 TCP profile = 整 DER 消息）。
type frame struct {
	up    bool
	bytes []byte
}

// OCSP HTTP 帧常量（RFC 6960 Appendix A.1）。
const (
	mtOCSPRequest  = "application/ocsp-request"
	mtOCSPResponse = "application/ocsp-response"
	retryAfterSecs = "120" // 503 重试间隔（RFC 6960 §4.2.1 重试语义 fixture）
)

// httpPostFrame 渲染 A.1 POST 请求帧：请求行 + Host + Content-Type +
// Content-Length + Connection: close + DER body（头序与值域按 P5 实测钉死）。
func httpPostFrame(host string, der []byte) []byte {
	head := fmt.Sprintf("POST / HTTP/1.1\r\nHost: %s\r\nContent-Type: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n",
		host, mtOCSPRequest, len(der))
	return append([]byte(head), der...)
}

// httpGetFrame 渲染 A.1 GET 请求帧：URI = / + base64url(DER)（无 padding），
// 无 body 无 Content-* 头。
func httpGetFrame(host, uri string) []byte {
	return []byte(fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", uri, host))
}

// httpResponseFrame 渲染响应帧：statusLine = "200 OK" / "503 Service
// Unavailable"；retryAfter 非空时插 Retry-After 头（503 语义）。
func httpResponseFrame(statusLine, retryAfter string, der []byte) []byte {
	head := fmt.Sprintf("HTTP/1.1 %s\r\nContent-Type: %s\r\nContent-Length: %d\r\n", statusLine, mtOCSPResponse, len(der))
	if retryAfter != "" {
		head += "Retry-After: " + retryAfter + "\r\n"
	}
	head += "Connection: close\r\n\r\n"
	return append([]byte(head), der...)
}

// requestPayload 渲染请求线帧（HTTP POST / RFC 5019 GET / 裸 TCP 整 DER）。
func requestPayload(p *txPlan, host string) frame {
	req := renderRequest(p)
	switch p.profile {
	case core.OCSPProfileHTTPGet:
		return frame{up: true, bytes: httpGetFrame(host, GETURI(req))}
	case core.OCSPProfileHTTPPost:
		return frame{up: true, bytes: httpPostFrame(host, req)}
	default: // tcp
		return frame{up: true, bytes: req}
	}
}

// responsePayload 渲染响应线帧：tryLater(3) 期望 HTTP 503 + Retry-After
// （RFC 6960 §4.2.1 重试语义）；其余状态 HTTP 200。
func responsePayload(p *txPlan) frame {
	resp := renderResponse(p)
	switch p.profile {
	case core.OCSPProfileHTTPGet, core.OCSPProfileHTTPPost:
		if p.expect == 3 {
			return frame{up: false, bytes: httpResponseFrame("503 Service Unavailable", retryAfterSecs, resp)}
		}
		return frame{up: false, bytes: httpResponseFrame("200 OK", "", resp)}
	default: // tcp
		return frame{up: false, bytes: resp}
	}
}

// GETURI 渲染 RFC 5019 GET 请求 URI（base64url 无 padding——契约 §5；
// base64.RawURLEncoding 收编）。
func GETURI(der []byte) string {
	return "/" + base64.RawURLEncoding.EncodeToString(der)
}

// ---- 会话/事务渲染（casegen 钉帧、链级红例与 Generate 共用单权威）----

// sessionPlan 是已解析的会话渲染序（逐事务 request→response 交替）。
type sessionPlan struct {
	sessIdx int
	session core.OCSPSession
	plans   []*txPlan
}

// resolveSessions 解析全部会话（cfg 无会话时给一条基线事务——裸
// {"ocsp":{}} 链不静默 0 包；用例恒显式声明 sessions）。
func resolveSessions(cfg *core.OCSPConfig, hasHTTP bool) ([]*sessionPlan, error) {
	sessions := cfg.Sessions
	if len(sessions) == 0 {
		sessions = []core.OCSPSession{{ID: "baseline", Transactions: []core.OCSPTransaction{{ID: "t1"}}}}
	}
	out := make([]*sessionPlan, 0, len(sessions))
	for si := range sessions {
		sp := &sessionPlan{sessIdx: si, session: sessions[si]}
		for ti := range sp.session.Transactions {
			p, err := resolvePlan(cfg, hasHTTP, &sp.session, si, ti)
			if err != nil {
				return nil, err
			}
			sp.plans = append(sp.plans, p)
		}
		out = append(out, sp)
	}
	return out, nil
}

// buildTxFrames 渲染一个会话的全部线帧（[事务][request,response]）。
func buildTxFrames(sp *sessionPlan, host string) [][]frame {
	var out [][]frame
	for _, p := range sp.plans {
		out = append(out, []frame{requestPayload(p, host), responsePayload(p)})
	}
	return out
}

// ---- 生成器（链驱动入口）----

// OCSPGenerator is the terminal-layer generator for ocsp chains.
type OCSPGenerator struct{}

func (g *OCSPGenerator) Name() string { return "ocsp" }

// GenEvents/EmitEvent mark the event-generator face（edp/mmse 同款——nil 会
// 令 ChainPlanner 不接事件通道并静默 0 包）。
func (g *OCSPGenerator) GenEvents() layers.EventGenerator { return g }
func (g *OCSPGenerator) EmitEvent(layers.MessageEvent) error {
	return fmt.Errorf("ocsp generator: EmitEvent is not wired; events flow through GenRequest.EmitMsg only")
}

// hasHTTPCarrier 报告链上是否存在 http 层（profile 缺省与一致性面）。
func hasHTTPCarrier(chain []layers.Layer) bool {
	for _, l := range chain {
		if l.Name == "http" {
			return true
		}
	}
	return false
}

func (g *OCSPGenerator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req == nil {
		return fmt.Errorf("ocsp generator: request is nil")
	}
	if req.EmitMsg == nil {
		return fmt.Errorf("ocsp generator: EmitMsg is nil")
	}
	cfg := req.Meta.OCSP
	if cfg == nil {
		cfg = &core.OCSPConfig{}
	}
	if err := (&Planner{}).Validate(core.FlowSpec{OCSP: cfg}); err != nil {
		return err
	}
	hasHTTP := hasHTTPCarrier(req.Chain)

	plans, err := resolveSessions(cfg, hasHTTP)
	if err != nil {
		return err
	}
	// 会话端点覆盖（kerberos/dtls 同款）：up 直落 SrcIP/SrcPort；down 会话
	// 声明 SrcIP 时显式路由 服务端(=流 dst)→客户端（多会话双客户端应答
	// 回对端）。会话 SrcPort 变化即独立 TCP 连接（tcp 层 connKey 语义）。
	// HTTP profile：本层已产完整 HTTP 帧（gbt/mmse 同族），http 层原样
	// 转发；裸 TCP：整 DER 直发。Host 头取流目的 IP（A.1 fixture）。
	host := req.Meta.DstIP
	for _, sp := range plans {
		txFrames := buildTxFrames(sp, host)
		for _, fr := range txFrames {
			for _, f := range fr {
				ev := layers.MessageEvent{Up: f.up, Bytes: f.bytes}
				if f.up {
					if sp.session.SrcIP != "" {
						ev.SrcIP = sp.session.SrcIP
					}
					if sp.session.SrcPort != 0 {
						ev.SrcPort = sp.session.SrcPort
					}
				} else if sp.session.SrcIP != "" {
					ev.SrcIP = req.Meta.DstIP
					ev.DstIP = sp.session.SrcIP
					ev.OverrideDstIP = true
				}
				if sp.session.DstPort != 0 {
					ev.DstPort = sp.session.DstPort
				}
				select {
				case <-ctx.Done():
					return ctx.Err()
				default:
				}
				if err := req.EmitMsg(ev); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// init registers the generator + validator（edp/mmse 同款接线）。
func init() {
	layers.RegisterLayerGenerator("ocsp", func() (layers.LayerGenerator, error) { return &OCSPGenerator{}, nil })
	layers.RegisterLayerValidator("ocsp", func(spec *core.FlowSpec) error { return (&Planner{}).Validate(*spec) })
}
