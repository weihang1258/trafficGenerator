# OCSP（在线证书状态协议，Online Certificate Status Protocol）设计契约

> 版本：v1.0.0（设计阶段）  
> 日期：2026-08-20  
> 状态：仅设计与 PCAP（抓包文件）用例契约；`ocsp` 层尚未注册，不修改 Go（编程语言）实现，不宣称当前 suite（测试套件）可运行。  
> 配套文件：`docs/protocol-designs/62-ocsp-testcase.md`、`trafficgen/test/protocol_pcap/cases/ocsp.json`  
> 规范基线：RFC 6960（OCSP）、RFC 8954（SHA-256 CertID）、RFC 5019（轻量 HTTP profile）、RFC 5280（PKIX）、ITU-T X.690（DER，唯一编码规则）。

## 1. 范围、证据等级和未注册边界

本设计定义 RFC 6960 OCSPRequest/OCSPResponse 的 DER（可区分编码规则，Distinguished Encoding Rules）外层、`CertID`、批量 `requestList`、nonce 扩展、签名请求、`BasicOCSPResponse`、`SingleResponse`、证书状态和时间窗口。覆盖 HTTP POST/GET 与裸 TCP stream（字节流）载体、IPv4/IPv6、多会话/多流、PCAP/NIC（网卡）一致性。HTTP 是 OCSP 常用传输 profile（档案）；OCSP 不定义独立 TCP record length，裸 TCP 必须按完整 DER TLV（标签-长度-值）重组，不能自创长度字段。

没有签名私钥、证书链或动态 nonce fixture（固定样本）时，只断言 DER tag/length、`CertID` 算法与 hash 长度、请求/响应方向、HTTP 状态、responseStatus 和不透明 signature bytes；不得伪造签名值、nonce、证书序列号，或声称密码学签名已验证。动态字段用 `presence`、`nonzero`、`distinct`、`same_as_packet` 断言。

当前仓库没有注册 `ocsp` layer、planner（规划器）、validator（校验器）或生成器。`cases/ocsp.json` 只保留一个 `ocsp_neg_unregistered` 注册前置占位，必须 `expect_error=true` 且 `error_contains="unknown layer"`；占位不计入下文 20 个语义 ID。注册前拒绝、0 包或空 PCAP 不是 OCSP 行为通过。

## 2. 推荐配置、层链和载体 profile

推荐 HTTP 层链为 `[ip, tcp, http, ocsp]` 或 `[ipv6, tcp, http, ocsp]`；裸 TCP 为 `[ip, tcp, ocsp]` 或 IPv6 对应链。层链是实现集成契约，不表示当前注册：

```json
{
  "layers": [{"ip": {}}, {"tcp": {}}, {"http": {}}, {"ocsp": {}}],
  "src_ip": "192.0.2.62", "dst_ip": "198.51.100.62",
  "src_port": 42062, "dst_port": 80,
  "ocsp": {
    "profile": "http-post", "hash_algorithm": "sha256",
    "request_count": 1, "nonce": {"enabled": true, "opaque": true},
    "cert_status": "good", "signed_request": false
  }
}
```

| 配置键 | 约束 |
|---|---|
| `profile` | `http-post`、`http-get` 或 `tcp`。POST 使用 `application/ocsp-request`/`application/ocsp-response`；GET 按 RFC 5019 将 DER 请求 base64url 编码到 URI。 |
| `transport`/端口 | 仅 TCP；明文 HTTP 端口 80，HTTPS 443 只能在明确解密 fixture 中断言 HTTP/DER。OCSP 不以 UDP 作为本契约载体。 |
| `request_list` | 一个 `tbsRequest` 含一个或多个 Request；顺序保留，不静默去重或重排。 |
| `hash_algorithm` | `CertID.hashAlgorithm` 的完整 AlgorithmIdentifier（算法标识符），OID 与参数 DER 自洽；支持 RFC 6960 SHA-1 和 RFC 8954 SHA-256。 |
| `issuer_name_hash`/`issuer_key_hash` | OCTET STRING，长度等于 digest（摘要）长度；无 issuer 证书时只断言存在、长度和 nonzero。 |
| `serial_number` | 非负、最短 DER INTEGER（整数）；动态值仅 presence/nonzero/same_as。 |
| `cert_status` | `good`、`revoked`、`unknown`，三种 context-specific tag/内容边界必须区分。 |
| `this_update`/`next_update` | GeneralizedTime；`nextUpdate` 可选，存在时是 `[0]` EXPLICIT wrapper（显式包装），且不早于 `thisUpdate`。 |
| `nonce` | OID `1.3.6.1.5.5.7.48.1.2`；`extnValue` 外层 OCTET STRING 内再包 DER OCTET STRING，长度逐层计算。 |
| `signed_request`/`signature` | 可选 `optionalSignature`；算法、BIT STRING 和 certs 结构可见，无私钥不宣称验证成功。 |
| `session_id`/`flow_count` | 每会话独立 nonce、requestList、response matching（响应匹配）、重试和 DER 重组缓存。 |
| `wire_fault` | 仅负例注入口：`der_truncated`、`certid_hash`、`request_response`、`nonce`、`signature`、`carrier`。 |

## 3. OCSPRequest 和 CertID DER

```text
OCSPRequest ::= SEQUENCE {
  tbsRequest        TBSRequest,
  optionalSignature [0] EXPLICIT Signature OPTIONAL }
TBSRequest ::= SEQUENCE {
  version [0] EXPLICIT Version DEFAULT v1,
  requestorName [1] EXPLICIT GeneralName OPTIONAL,
  requestList SEQUENCE OF Request,
  requestExtensions [2] EXPLICIT Extensions OPTIONAL }
Request ::= SEQUENCE {
  reqCert CertID,
  singleRequestExtensions [0] EXPLICIT Extensions OPTIONAL }
CertID ::= SEQUENCE {
  hashAlgorithm AlgorithmIdentifier,
  issuerNameHash OCTET STRING,
  issuerKeyHash OCTET STRING,
  serialNumber CertificateSerialNumber }
```

`requestList` 至少一项。父 SEQUENCE 长度必须覆盖全部子 TLV；explicit wrapper 长度只覆盖自身内容。DER 使用 definite length（确定长度）、最短 INTEGER 和最短合法 length；禁止 indefinite length（不定长）、非最短长度、错误 tag class、父长度越界、重复不可重复字段。长度按编码 bytes 计算，不用 Unicode、Base64 或 URI 字符数替代。

SHA-1 OID 为 `1.3.14.3.2.26`，issuerNameHash/issuerKeyHash 通常各 20 bytes；RFC 8954 SHA-256 OID 为 `2.16.840.1.101.3.4.2.1`，对应各 32 bytes。SHA-256 CertID 不得误判为 SHA-1，也不能仅凭长度猜算法；AlgorithmIdentifier 的 NULL 参数约束按 fixture 保持一致。`issuerNameHash` 对 issuer Name DER 编码摘要，`issuerKeyHash` 对 subjectPublicKey BIT STRING 内容（不含 unused-bits 字节）摘要；无证书证据时不声称哈希真实匹配。

`serialNumber` 是证书序列号 ASN.1 INTEGER，不是十进制字符串或固定宽度 blob。明确 0 不能被默认值覆盖；真实序列号、hash、nonce 只能用动态断言。

## 4. OCSPResponse、BasicOCSPResponse 和 SingleResponse

```text
OCSPResponse ::= SEQUENCE {
  responseStatus ENUMERATED,
  responseBytes [0] EXPLICIT ResponseBytes OPTIONAL }
ResponseBytes ::= SEQUENCE {
  responseType OBJECT IDENTIFIER,
  response OCTET STRING }
BasicOCSPResponse ::= SEQUENCE {
  tbsResponseData ResponseData,
  signatureAlgorithm AlgorithmIdentifier,
  signature BIT STRING,
  certs [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL }
ResponseData ::= SEQUENCE {
  version [0] EXPLICIT Version DEFAULT v1,
  responderID ResponderID,
  producedAt GeneralizedTime,
  responses SEQUENCE OF SingleResponse,
  responseExtensions [1] EXPLICIT Extensions OPTIONAL }
SingleResponse ::= SEQUENCE {
  certID CertID,
  certStatus CertStatus,
  thisUpdate GeneralizedTime,
  nextUpdate [0] EXPLICIT GeneralizedTime OPTIONAL,
  singleExtensions [1] EXPLICIT Extensions OPTIONAL }
CertStatus ::= CHOICE {
  good [0] IMPLICIT NULL,
  revoked [1] IMPLICIT RevokedInfo,
  unknown [2] IMPLICIT NULL }
```

`responseStatus=successful(0)` 必须伴随 `responseBytes`，通常 `responseType=id-pkix-ocsp-basic`（`1.3.6.1.5.5.7.48.1.1`），其 OCTET STRING payload 再解码为 BasicOCSPResponse；非成功 `malformedRequest(1)`、`internalError(2)`、`tryLater(3)`、`sigRequired(5)`、`unauthorized(6)` 不得伪造成功响应。`ResponderID` 只能是 byName `[1]` 或 byKey `[2]`，不可互换。

每个 SingleResponse 的 CertID 必须逐项匹配请求；`good`/`revoked`/`unknown` 是 IMPLICIT choice，不是字符串。`revoked` 的 revocationTime 必须存在，可选 reason/invalidityDate 按声明 wrapper 编码。`producedAt`、`thisUpdate`、`nextUpdate` 是 GeneralizedTime；验证器区分格式成功和 freshness（新鲜度），过期或时间倒置不得静默标为有效。

签名覆盖 DER 编码的 `ResponseData`，不是 HTTP body、Base64 文本或 response OCTET STRING 外层。`signatureAlgorithm` OID、BIT STRING unused-bits、长度和 certs wrapper 可观察；无 key evidence（密钥证据）不声称签名有效、证书可信或 delegated responder 授权。

## 5. 扩展、nonce 和 HTTP/TCP

Nonce 扩展 OID 为 `1.3.6.1.5.5.7.48.1.2`；`critical` 默认 false，`extnValue` 是包含 nonce DER OCTET STRING 的 OCTET STRING。请求/响应 nonce 应 `same_as_packet`，不同 session 应 distinct；错误嵌套、重复、缺失或长度不一致进入负例。请求签名 `optionalSignature [0]` 内含 AlgorithmIdentifier、BIT STRING 和可选 certs，不能因 HTTP POST 自动插入。

HTTP POST body 是 DER OCSPRequest，`Content-Length` 等于 DER bytes，response body 是 DER OCSPResponse；status 200 不等于 OCSP successful。HTTP GET 的 path segment 是无 `=` padding（填充）的 base64url 请求 DER，URL 字符数不等于 DER 长度。HTTP keep-alive 按 Content-Length/chunked framing（分块封装）分隔事务；`tryLater`/503 和重传可观察但不得静默成功。

裸 TCP 没有 OCSP 私有长度前缀；TCP stream 重组后按 DER 父长度解析，可 segment 切分/合并，两个完整消息粘连时逐个解析，不能跨 stream 拼接。无 VLAN/IP/TCP options 时 payload 参考 offset（偏移）为 IPv4 `14+20+20=54`、IPv6 `14+40+20=74`；固定 offset 仅适用于明确 fixture。HTTPS 443 未解密只能断言 TCP/TLS carrier（载体）。

## 6. IPv4/IPv6、多会话、多流与边界

IPv4/IPv6 是独立 fixture，分别断言 `ip.proto=6` 或 `ipv6.nxt=6`、地址族、TCP checksum、端口和 HTTP/DER carrier。每 session 独立四元组、requestList、CertID、nonce、response status、签名上下文、时间窗口和重组缓存；多会话可共享端口但不得共享动态 nonce、response bytes 或 HTTP 事务状态。

至少覆盖：单/批量 Request、SHA-1/SHA-256、serial 最短编码、DER 短/长 length、空可选字段、三种 certStatus、this/next update、成功/非成功 responseStatus、nonce 双层 OCTET STRING、签名/证书 opaque（不透明）、HTTP POST/GET、TCP 分段/粘连、keep-alive、重试、IPv4/IPv6 和 PCAP/NIC。

## 7. 错误处理、PCAP/NIC 证据和完成定义

负例必须在 planner/validator 失败并传播为 task error，不能输出成功 PCAP、`completed/0 packet` 或只有 TCP/HTTP 外壳的假成功。负例执行期 `expect` 只能包含 `expect_error` 与 `error_contains`。

| ID | 故障输入 | 目标 `error_contains` |
|---|---|---|
| `ocsp_neg_der_truncated` | OCSPRequest/Response、BasicOCSPResponse 或子 TLV 截断 | `der`、`response` 或 `length` |
| `ocsp_neg_certid_hash_length` | 算法 OID 与 hash 长度不匹配、CertID tag 或 serial 错误 | `certid`、`hash` 或 `algorithm` |
| `ocsp_neg_request_response_mismatch` | response CertID、批量项、状态或 nonce 与请求不匹配 | `match`、`certid` 或 `nonce` |
| `ocsp_neg_nonce_extension` | nonce 错误嵌套、重复、缺失或请求响应不相等 | `nonce` 或 `extension` |
| `ocsp_neg_signature` | signatureAlgorithm/signature/certs 结构错误或伪造成功签名 | `signature`、`algorithm` 或 `responder` |
| `ocsp_neg_carrier_profile` | HTTP method/content type/status、TCP stream、端口或 IP family 错误 | `carrier`、`http`、`tcp` 或 `profile` |

PCAP 正例断言 HTTP/TCP carrier、方向、端口、DER tag/length、CertID OID/hash 长度、request/response matching、状态和时间结构。动态 nonce、serial、hash、signature、时间用 presence/nonzero/distinct/same_as；没有 key 证据不声称签名验证。NIC 过滤器 HTTP 推荐 `tcp port 80 or tcp port 443`，裸 TCP 按实际端口，并记录 checksum offload（校验和卸载）边界。

实现完成定义：注册 `ocsp` layer；逐字节验证 RFC 6960/8954 Request/Response、CertID、批量项、nonce、signed request、BasicOCSPResponse、SingleResponse 状态/时间/扩展、HTTP GET/POST 与裸 TCP framing；planner→worker→HTTP/TCP output 完整传播正负结果；-race（竞态检测）和集成测试覆盖多会话、keep-alive、重试、TCP 重组和 IPv4/IPv6；无 key evidence 不声称动态签名有效。

## 8. 20 个语义场景和 packet_count 映射

共 20 个唯一语义 ID：14 个正例和 6 个负例；顺序必须与 `62-ocsp-testcase.md` §2 及注册后的 `ocsp.json` 完全一致。当前 JSON 只有不计数的注册前置占位。

| # | ID | 类型 | 覆盖 | 约定 packet_count |
|---:|---|---|---|---:|
| 1 | `ocsp_http_ipv4_request_response` | 正 | HTTP POST/IPv4、DER 请求响应和 content type | 8 |
| 2 | `ocsp_http_ipv6_request_response` | 正 | HTTP POST/IPv6、独立地址族和响应 | 8 |
| 3 | `ocsp_tcp_record_framing` | 正 | 裸 TCP DER stream 分段/合并，无私有长度前缀 | 8 |
| 4 | `ocsp_request_certid_sha1` | 正 | RFC 6960 SHA-1 CertID、issuer hashes、serial | 6 |
| 5 | `ocsp_request_certid_sha256_rfc8954` | 正 | RFC 8954 SHA-256 CertID 与算法/长度绑定 | 6 |
| 6 | `ocsp_batch_multi_request` | 正 | 多项 requestList、顺序和逐项响应匹配 | 8 |
| 7 | `ocsp_nonce_extension` | 正 | nonce 扩展、双层 DER 包装和跨消息关联 | 6 |
| 8 | `ocsp_signed_request` | 正 | requestorName、optionalSignature、算法/证书结构 | 8 |
| 9 | `ocsp_basic_response_status` | 正 | responseStatus、ResponseBytes、BasicOCSPResponse | 8 |
| 10 | `ocsp_single_response_statuses` | 正 | good/revoked/unknown、SingleResponse CertID 绑定 | 8 |
| 11 | `ocsp_response_signature_extensions` | 正 | signatureAlgorithm/signature/certs 和扩展 | 8 |
| 12 | `ocsp_time_validity_windows` | 正 | producedAt/thisUpdate/nextUpdate、freshness | 6 |
| 13 | `ocsp_multi_session_stream` | 正 | HTTP keep-alive、多 TCP stream、状态隔离 | 16 |
| 14 | `ocsp_pcap_nic_consistency` | 正 | PCAP/NIC carrier、方向、DER/CertID 外层一致 | 12 |
| 15 | `ocsp_neg_der_truncated` | 负 | DER tag/length/TLV 截断 | — |
| 16 | `ocsp_neg_certid_hash_length` | 负 | 算法与 hash 长度/CertID/serial 错误 | — |
| 17 | `ocsp_neg_request_response_mismatch` | 负 | CertID、批量项、状态或 nonce 不匹配 | — |
| 18 | `ocsp_neg_nonce_extension` | 负 | nonce 扩展缺失、重复、错误嵌套或不相等 | — |
| 19 | `ocsp_neg_signature` | 负 | 签名结构、算法、Responder 授权错误 | — |
| 20 | `ocsp_neg_carrier_profile` | 负 | HTTP/TCP profile、端口、method/content type 错误 | — |

三方契约必须保持本文 §8、`62-ocsp-testcase.md` §2、注册后的 `ocsp.json` 同一组 20 个 ID、同一顺序、14 正例+6 负例；当前 JSON 另有一个不计数的 `ocsp_neg_unregistered`，且唯一预期为 `unknown layer`。

## 9. 修订记录

- v1.0.0（2026-08-20）：建立 14 个 RFC 6960/8954 正例和 6 个严格负例，覆盖 HTTP/TCP profile、OCSPRequest/Response DER、CertID、批量请求、nonce、签名/扩展、BasicOCSPResponse、SingleResponse、时间窗口、IPv4/IPv6、多会话/多流、PCAP/NIC 和错误传播；不修改 Go 实现。
