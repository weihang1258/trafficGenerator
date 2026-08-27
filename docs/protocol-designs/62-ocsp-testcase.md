# OCSP（在线证书状态协议，Online Certificate Status Protocol）测试用例契约

> 版本：v1.0.0（设计阶段）  
> 日期：2026-08-20  
> 配套设计：`docs/protocol-designs/62-ocsp-design.md`  
> 机器契约：`trafficgen/test/protocol_pcap/cases/ocsp.json`  
> 状态：`ocsp` 层尚未注册；本文定义实现后的 PCAP（抓包文件）/NIC（网卡）断言，不宣称当前 suite（测试套件）可运行。

## 1. 测试原则和未注册边界

用例从设计 §2–§8 逐项派生，共 20 个唯一语义 ID：14 个正例和 6 个负例。当前 JSON 只保留一个不计入语义覆盖的注册前置占位 `ocsp_neg_unregistered`，其 `expect` 必须 `expect_error=true`、`error_contains="unknown layer"`；注册后移除占位，再按本文 §2 顺序加入 20 个语义用例。

OCSP carrier（载体）为 HTTP POST、RFC 5019 GET 或裸 TCP stream（字节流）；HTTPS/TCP 443 未解密时只能观察 TCP/TLS。无私钥、issuer 证书链或签名验证上下文时，PCAP/NIC 只可断言 DER（可区分编码）tag/length、CertID、status、签名/证书边界和 nonce 存在；不能声称签名有效、证书可信或动态 serial/nonce/signature 具有特定值。运行期动态字段使用 `presence`、`nonzero`、`same_as_packet`、`distinct` 和长度断言。

## 2. 原子用例索引

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
| 18 | `ocsp_neg_nonce_extension` | 负 | nonce 缺失、重复、错误嵌套或不相等 | — |
| 19 | `ocsp_neg_signature` | 负 | 签名结构、算法、Responder 授权错误 | — |
| 20 | `ocsp_neg_carrier_profile` | 负 | HTTP/TCP profile、端口、method/content type 错误 | — |

## 3. 正例逐项断言契约

1. **`ocsp_http_ipv4_request_response`**：建立 IPv4/TCP/80，断言 SYN/SYN-ACK、HTTP POST、`Content-Type: application/ocsp-request`、响应 `application/ocsp-response`，请求为 DER OCSPRequest，响应 `responseStatus=successful`、Basic OID 和 SingleResponse 外层，`packet_count=8`。
2. **`ocsp_http_ipv6_request_response`**：独立 IPv6/TCP/80 fixture，断言 `ipv6.nxt=6`、地址族、HTTP POST 与 DER 外层/Basic OID，IPv6 地址不能从 IPv4 fixture 继承，`packet_count=8`。
3. **`ocsp_tcp_record_framing`**：裸 IPv4/IPv6 TCP stream 携带 OCSPRequest/OCSPResponse，断言重组后的父 DER 长度、两个粘连消息按长度分离，TCP segment 边界不当作 OCSP 字段，`packet_count=8`。
4. **`ocsp_request_certid_sha1`**：断言 SHA-1 AlgorithmIdentifier OID/参数边界、issuerNameHash/issuerKeyHash 各 20 bytes 和 serial INTEGER 最短正编码；动态 serial 使用 presence/nonzero，`packet_count=6`。
5. **`ocsp_request_certid_sha256_rfc8954`**：断言 RFC 8954 SHA-256 OID、两项 32-byte hash 和算法/长度绑定，不能误判为 SHA-1，`packet_count=6`。
6. **`ocsp_batch_multi_request`**：单一 requestList 至少两项 CertID，断言线上顺序、逐项 response matching 和各项状态，不能静默去重/重排，`packet_count=8`。
7. **`ocsp_nonce_extension`**：断言 nonce OID `1.3.6.1.5.5.7.48.1.2`、extnValue 与内部 DER OCTET STRING 双层长度，响应 nonce `same_as_packet`，不同 session `distinct`/nonzero，`packet_count=6`。
8. **`ocsp_signed_request`**：断言 requestorName wrapper、optionalSignature、signatureAlgorithm、BIT STRING unused-bits/长度和可选 certs；无私钥不宣称验证成功，`packet_count=8`。
9. **`ocsp_basic_response_status`**：断言 responseStatus 与 responseBytes 组合；successful 必须有 Basic OID `1.3.6.1.5.5.7.48.1.1`，非成功状态可无 responseBytes，`packet_count=8`。
10. **`ocsp_single_response_statuses`**：至少独立 good `[0]`、revoked `[1]`/RevokedInfo、unknown `[2]`，断言 tags/长度、thisUpdate 和可选 nextUpdate，不将文本 status 当 tag，`packet_count=8`。
11. **`ocsp_response_signature_extensions`**：断言 Basic signatureAlgorithm/signature/certs、ResponseData `[1]` 与 SingleResponse `[1]` extensions；动态 signature/cert bytes 只 presence/nonzero/length，`packet_count=8`。
12. **`ocsp_time_validity_windows`**：断言 producedAt/thisUpdate/nextUpdate GeneralizedTime 和 freshness 边界；`nextUpdate` 不早于 thisUpdate，运行期时钟不硬编码，`packet_count=6`。
13. **`ocsp_multi_session_stream`**：至少两个 HTTP keep-alive 请求和两个裸 TCP streams/会话并行；断言 CertID、nonce、响应、重组缓存和时间窗口隔离，不假设跨流包序，`packet_count=16`。
14. **`ocsp_pcap_nic_consistency`**：同一明文 HTTP 或裸 TCP fixture 分别输出 PCAP 并在 NIC 捕获；断言 TCP carrier、方向、80/443/实际端口、HTTP method/header（明文时）、DER 外层、Basic OID 和 status 一致。过滤器推荐 `tcp port 80 or tcp port 443`，`packet_count=12`。

无解密/私钥/issuer 证书链时，不添加“signature valid”、证书可信、serial 属于某证书、issuer hash 匹配、nonce 随机质量或签名者身份断言。若 tshark（抓包解析器）无 `ocsp.*` 字段，使用通用 `tcp`/`http`/`tls` 和稳定 raw frames；不自创字段名。

## 4. 负例契约

每个负例必须在 planner/validator 失败并传播为 task error；不能产生成功 PCAP、`completed/0 packet` 或只有 TCP/HTTP 外壳的假成功。执行期 `expect` 键集合严格为 `{"expect_error", "error_contains"}`：

| ID | 故障输入 | 目标 `error_contains` |
|---|---|---|
| `ocsp_neg_der_truncated` | DER tag/length/TLV、HTTP body 或 TCP stream 在父/子结构中截断 | `der`、`response` 或 `length` |
| `ocsp_neg_certid_hash_length` | 算法 OID 与 hash 长度不匹配、CertID tag 或 serial 错误 | `certid`、`hash` 或 `algorithm` |
| `ocsp_neg_request_response_mismatch` | response CertID、批量项、状态或 nonce 与请求不匹配 | `match`、`certid` 或 `nonce` |
| `ocsp_neg_nonce_extension` | nonce OID、双层 OCTET STRING、长度或请求响应关联错误 | `nonce`、`extension` 或 `length` |
| `ocsp_neg_signature` | signatureAlgorithm/signature/certs 结构错误或伪造成功签名 | `signature`、`algorithm` 或 `responder` |
| `ocsp_neg_carrier_profile` | POST/GET/HTTPS/TCP 混用、错误端口、Content-Type/URI/body 边界错误 | `carrier`、`http`、`tcp` 或 `profile` |

合法的动态 serial/nonce/signature、SHA-1/SHA-256、三种 certStatus、非成功 responseStatus、长形式 length、HTTP keep-alive、503/tryLater、TCP segmentation 和 HTTPS opaque carrier 由正例覆盖，不能误报为负例。错误传播必须保留原始原因，不能用通用“0 packets”替代验证错误。

## 5. 三方一致性和静态检查

1. 设计 §8 的 20 个 ID、本文 §2、注册后的 JSON 和审计必须保持同一组 ID、同一顺序：14 正例 + 6 负例；当前 JSON 另有一个 `ocsp_neg_unregistered` 占位。
2. 未来 14 个正例均有 `packet_count`/`min_packets`、carrier、方向和稳定 DER/HTTP 字段；6 个负例的 `expect` 只能有 `expect_error`、`error_contains`。当前未注册 JSON 只验证 placeholder（占位）结构。
3. `OCSPRequest` 的 `tbsRequest/requestList/CertID` 与 `OCSPResponse/BasicOCSPResponse/SingleResponse` 父子 DER length、context tags、AlgorithmIdentifier 和 responseStatus 必须按实际编码断言。
4. HTTP POST body 是 DER bytes；RFC 5019 GET path 是 base64url 包装；HTTP Content-Length/URI 长度不替代 DER length。裸 TCP 先重组 stream，不自创 record header。
5. `good/revoked/unknown` 分别使用 `[0]`/`[1]`/`[2]` CertStatus tag；`thisUpdate` 必需，`nextUpdate` 是 `[0]` EXPLICIT 可选字段。
6. nonce 使用 OID `1.3.6.1.5.5.7.48.1.2` 和双层 OCTET STRING；请求/响应 same-as、不同会话 distinct；签名/证书/serial 动态字段只用 presence/nonzero/same_as/length。
7. IPv4/IPv6、多会话和 keep-alive 断言以流内状态为准，不依赖全局交织包序；未解密 HTTPS 不断言 HTTP/OCSP 明文。
8. `python3 -m json.tool trafficgen/test/protocol_pcap/cases/ocsp.json` 应成功；当前数组只能含 `ocsp_neg_unregistered`，且 `proto=ocsp`、`expect_error=true`、`error_contains` 精确为 `unknown layer`。

## 6. 实现后执行建议

注册 `ocsp` layer 后，先检查 JSON parser、ID 顺序、正负 expect 键集合、DER offsets/length、CertID hash、certStatus tags、nonce 双层扩展和 HTTP GET/POST carrier，再运行 1–14 的 PCAP/NIC 正例和 15–20 的错误传播。若环境没有 OCSP dissector，使用通用 HTTP/TCP/TLS 字段与 raw frames；不能将唯一 placeholder 运行结果报告为 OCSP suite 通过。

## 7. 修订记录

- v1.0.0（2026-08-20）：建立 14 个 RFC 6960/8954 正例和 6 个严格负例，覆盖 HTTP POST/GET、TCP/HTTP 80/443、OCSPRequest/OCSPResponse/BasicOCSPResponse/SingleResponse、CertID、三种 certStatus、nonce、签名/证书 opaque 边界、DER 长度、keep-alive/重试、IPv4/IPv6、PCAP/NIC 和错误传播；不修改 Go 实现。
