# OCSP（在线证书状态协议，Online Certificate Status Protocol）测试用例契约

> 版本：v1.1.1（P1–P3 产物 + P4–P6 交付回写）  
> 日期：2026-09-25（v1.1.1 回写 2026-09-27）  
> 配套设计：`docs/protocol-designs/62-ocsp-design.md` v1.1.1（P1 矩阵 §10/三路对照 §11/门1表 §12/D-OCSP-1 §13）  
> 机器契约：`trafficgen/test/protocol_pcap/cases/ocsp.json`  
> 状态：**P4–P6 已完成**（D-OCSP-1 已验收，2026-09-27）——`ocsp` 层已注册并入链；本文 §2 的 20 ID（14 正 + 6 负）与 `ocsp.json` 已对账，历史 suite 20/20 全绿证据见 §7；后续代码变更须重新跑全量。

## 1. 测试原则和未注册边界

用例从设计 §2–§8 逐项派生，共 20 个唯一语义 ID：14 个正例和 6 个负例。当前 JSON 已包含并按本文 §2 顺序对账这 20 个目标用例；实现注册和真实套件验收已有历史证据，后续改动须以最新执行结果为准，不以文档迁移本身替代运行验证。

OCSP carrier（载体）为 HTTP POST、RFC 5019 GET 或裸 TCP stream（字节流）；HTTPS/TCP 443 未解密时只能观察 TCP/TLS。无私钥、issuer 证书链或签名验证上下文时，PCAP/NIC 只可断言 DER（可区分编码）tag/length、CertID、status、签名/证书边界和 nonce 存在；不能声称签名有效、证书可信或动态 serial/nonce/signature 具有特定值。运行期动态字段使用 `presence`、`nonzero`、`same_as_packet`、`distinct` 和长度断言。

### 1.1 T1–T6 测试点清单（先行）

| 编号 | 测试点 | OCSP 落点 |
|---|---|---|
| T1 | 三源回指：规范、设计、现网行为分别可追溯 | RFC 6960/8954/5019/5280/X.690 → design §10–§14 → 本文 §2–§4 与 `ocsp.json` |
| T2 | 先列测试点再落原子用例，覆盖 carrier、DER、CertID、状态、扩展、时间、多流和错误传播 | 本文 §2 索引、§3 正例、§4 负例 |
| T3 | 原子粒度：每例只验证一个可区分行为面；批量、会话和跨消息关联单独成例 | #3–#14 按行为拆分；负例 #15–#20 按故障锚点拆分 |
| T4 | 正常、失败、边界三类均有机器契约和稳定断言 | 正常/边界 #1–#14；失败 #15–#20；动态值只用 presence/nonzero/same_as/distinct/length |
| T5 | §3.15 固定动作：同流多轮、非正常结束、长保活逐项落地或立项 | #13 覆盖同流多轮与长保活；#9 覆盖非成功状态；主动 abort 立项 G-OCSP-1 |
| T6 | 存量用例逐例去向：合入、等价覆盖或作废必须有原因 | 20 个现行 ID 全部合入本轮 LayerChain 契约；无作废项、无遗留旧占位 |

## 2. 原子用例索引

| # | ID | 类型 | 覆盖 | 约定 packet_count |
|---:|---|---|---|---:|
| 1 | `ocsp_http_ipv4_request_response` | 正 | HTTP POST/IPv4、DER 请求响应和 content type | 9 |
| 2 | `ocsp_http_ipv6_request_response` | 正 | HTTP POST/IPv6、独立地址族和响应 | 9 |
| 3 | `ocsp_tcp_record_framing` | 正 | 裸 TCP DER stream 分段/合并，无私有长度前缀 | 10 |
| 4 | `ocsp_request_certid_sha1` | 正 | RFC 6960 SHA-1 CertID、issuer hashes、serial | 9 |
| 5 | `ocsp_request_certid_sha256_rfc8954` | 正 | RFC 8954 SHA-256 CertID 与算法/长度绑定 | 9 |
| 6 | `ocsp_batch_multi_request` | 正 | 多项 requestList、顺序和逐项响应匹配 | 9 |
| 7 | `ocsp_nonce_extension` | 正 | nonce 扩展、双层 DER 包装和跨消息关联 | 9 |
| 8 | `ocsp_signed_request` | 正 | requestorName、optionalSignature、算法/证书结构 | 9 |
| 9 | `ocsp_basic_response_status` | 正 | responseStatus、ResponseBytes、BasicOCSPResponse | 9 |
| 10 | `ocsp_single_response_statuses` | 正 | good/revoked/unknown、SingleResponse CertID 绑定 | 9 |
| 11 | `ocsp_response_signature_extensions` | 正 | signatureAlgorithm/signature/certs 和扩展 | 9 |
| 12 | `ocsp_time_validity_windows` | 正 | producedAt/thisUpdate/nextUpdate、freshness | 9 |
| 13 | `ocsp_multi_session_stream` | 正 | HTTP keep-alive、多 TCP stream、状态隔离 | 22 |
| 14 | `ocsp_pcap_nic_consistency` | 正 | PCAP/NIC carrier、方向、DER/CertID 外层一致 | 18 |
| 15 | `ocsp_neg_der_truncated` | 负 | DER tag/length/TLV 截断 | — |
| 16 | `ocsp_neg_certid_hash_length` | 负 | 算法与 hash 长度/CertID/serial 错误 | — |
| 17 | `ocsp_neg_request_response_mismatch` | 负 | CertID、批量项、状态或 nonce 不匹配 | — |
| 18 | `ocsp_neg_nonce_extension` | 负 | nonce 缺失、重复、错误嵌套或不相等 | — |
| 19 | `ocsp_neg_signature` | 负 | 签名结构、算法、Responder 授权错误 | — |
| 20 | `ocsp_neg_carrier_profile` | 负 | HTTP/TCP profile、端口、method/content type 错误 | — |

## 3. 正例逐项断言契约

1. **`ocsp_http_ipv4_request_response`**：建立 IPv4/TCP/80，断言 SYN/SYN-ACK、HTTP POST、`Content-Type: application/ocsp-request`、响应 `application/ocsp-response`，请求为 DER OCSPRequest，响应 `responseStatus=successful`、Basic OID 和 SingleResponse 外层，`packet_count=9`。
2. **`ocsp_http_ipv6_request_response`**：独立 IPv6/TCP/80 fixture，断言 `ipv6.nxt=6`、地址族、HTTP POST 与 DER 外层/Basic OID，IPv6 地址不能从 IPv4 fixture 继承，`packet_count=9`。
3. **`ocsp_tcp_record_framing`**：裸 IPv4/IPv6 TCP stream 携带 OCSPRequest/OCSPResponse，断言重组后的父 DER 长度、两个粘连消息按长度分离，TCP segment 边界不当作 OCSP 字段，`packet_count=10`。
4. **`ocsp_request_certid_sha1`**：断言 SHA-1 AlgorithmIdentifier OID/参数边界、issuerNameHash/issuerKeyHash 各 20 bytes 和 serial INTEGER 最短正编码；动态 serial 使用 presence/nonzero，`packet_count=9`。
5. **`ocsp_request_certid_sha256_rfc8954`**：断言 RFC 8954 SHA-256 OID、两项 32-byte hash 和算法/长度绑定，不能误判为 SHA-1，`packet_count=9`。
6. **`ocsp_batch_multi_request`**：单一 requestList 至少两项 CertID，断言线上顺序、逐项 response matching 和各项状态，不能静默去重/重排，`packet_count=9`。
7. **`ocsp_nonce_extension`**：断言 nonce OID `1.3.6.1.5.5.7.48.1.2`、extnValue 与内部 DER OCTET STRING 双层长度，响应 nonce `same_as_packet`，不同 session `distinct`/nonzero，`packet_count=9`。
8. **`ocsp_signed_request`**：断言 requestorName wrapper、optionalSignature、signatureAlgorithm、BIT STRING unused-bits/长度和可选 certs；无私钥不宣称验证成功，`packet_count=9`。
9. **`ocsp_basic_response_status`**：断言 responseStatus 与 responseBytes 组合；successful 必须有 Basic OID `1.3.6.1.5.5.7.48.1.1`，非成功状态可无 responseBytes，`packet_count=9`。
10. **`ocsp_single_response_statuses`**：至少独立 good `[0]`、revoked `[1]`/RevokedInfo、unknown `[2]`，断言 tags/长度、thisUpdate 和可选 nextUpdate，不将文本 status 当 tag，`packet_count=9`。
11. **`ocsp_response_signature_extensions`**：断言 Basic signatureAlgorithm/signature/certs、ResponseData `[1]` 与 SingleResponse `[1]` extensions；动态 signature/cert bytes 只 presence/nonzero/length，`packet_count=9`。
12. **`ocsp_time_validity_windows`**：断言 producedAt/thisUpdate/nextUpdate GeneralizedTime 和 freshness 边界；`nextUpdate` 不早于 thisUpdate，运行期时钟不硬编码，`packet_count=9`。
13. **`ocsp_multi_session_stream`**：至少两个 HTTP keep-alive 请求和两个裸 TCP streams/会话并行；断言 CertID、nonce、响应、重组缓存和时间窗口隔离，不假设跨流包序，`packet_count=22`。
14. **`ocsp_pcap_nic_consistency`**：同一明文 HTTP 或裸 TCP fixture 分别输出 PCAP 并在 NIC 捕获；断言 TCP carrier、方向、80/443/实际端口、HTTP method/header（明文时）、DER 外层、Basic OID 和 status 一致。过滤器推荐 `tcp port 80 or tcp port 443`，`packet_count=18`。

无解密/私钥/issuer 证书链时，不添加“signature valid”、证书可信、serial 属于某证书、issuer hash 匹配、nonce 随机质量或签名者身份断言。tshark（抓包解析器）`ocsp.*` 字段以 §8.6 所列 53 个为准；缺失时退化通用 `tcp`/`http`/`tls` 和稳定 raw frames；不自创字段名。

## 4. 负例契约

每个负例必须在 planner/validator 失败并传播为 task error；不能产生成功 PCAP、`completed/0 packet` 或只有 TCP/HTTP 外壳的假成功。执行期 `expect` 键集合严格为 `{"expect_error", "error_contains"}`，不携带说明性字段；说明、来源和守卫归本文设计/测试契约正文。

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

1. 设计 §8 的 20 个 ID、本文 §2、`ocsp.json` 和审计必须保持同一组 ID、同一顺序：14 正例 + 6 负例；当前 JSON 已完成该对账。
2. 14 个正例均有 `packet_count`、carrier、方向和稳定 DER/HTTP 字段；6 个负例的 `expect` 严格只含 `expect_error`、`error_contains`，说明性内容不进入机器契约。
3. `OCSPRequest` 的 `tbsRequest/requestList/CertID` 与 `OCSPResponse/BasicOCSPResponse/SingleResponse` 父子 DER length、context tags、AlgorithmIdentifier 和 responseStatus 必须按实际编码断言。
4. HTTP POST body 是 DER bytes；RFC 5019 GET path 是 base64url 包装；HTTP Content-Length/URI 长度不替代 DER length。裸 TCP 先重组 stream，不自创 record header。
5. `good/revoked/unknown` 分别使用 `[0]`/`[1]`/`[2]` CertStatus tag；`thisUpdate` 必需，`nextUpdate` 是 `[0]` EXPLICIT 可选字段。
6. nonce 使用 OID `1.3.6.1.5.5.7.48.1.2` 和双层 OCTET STRING；请求/响应 same-as、不同会话 distinct；签名/证书/serial 动态字段只用 presence/nonzero/same_as/length。
7. IPv4/IPv6、多会话和 keep-alive 断言以流内状态为准，不依赖全局交织包序；未解密 HTTPS 不断言 HTTP/OCSP 明文。
8. `python3 -m json.tool trafficgen/test/protocol_pcap/cases/ocsp.json` 应成功；数组包含 §2 的 20 个 ID，正例 14 个、负例 6 个，且正例 spec_json 顶层仅含层链/允许的结构性键。

## 6. 实现后执行建议

注册 `ocsp` layer 后，先检查 JSON parser、ID 顺序、正负 expect 键集合、DER offsets/length、CertID hash、certStatus tags、nonce 双层扩展和 HTTP GET/POST carrier，再运行 1–14 的 PCAP/NIC 正例和 15–20 的错误传播。历史 suite 已有 20/20 证据；后续改动必须重跑全量，不能将历史结果冒充当前运行。

## 7. 修订记录

- v1.1.1（2026-09-27）：P4–P6 交付回写与本文入版（原 v1.1.0 未曾入仓，随关单补提交）。交付事实=实现 `31ae72e` / 集成 `ed131c5` / 关单 `d971856`；§2 的 20 ID 即交付集（14 正 + 6 负），断言通道与 packet_count 映射按 §3/§4 原契约执行：suite 20/20 全绿、`coverage_gate` 54/54、`verify.py` 104 点 0 失败；248 表落 `docs/protocol-designs/248/46-ocsp-248-table.md`。
- v1.1.0（2026-09-25）：P3 产物。新增 §8 P3 固定动作（§3.15 三项逐项一例或立项 + A′/B′ 两分类表 + 9.52 对账两行与清单出处声明 + 3.14 豁免边界审计 + 三源回指行 + 断言契约核对结论）。20 ID 断言契约（§2–§4）原样保留，已核对与 design §8 一致（14 正+6 负、同序）。
- v1.0.0（2026-08-20）：建立 14 个 RFC 6960/8954 正例和 6 个严格负例，覆盖 HTTP POST/GET、TCP/HTTP 80/443、OCSPRequest/OCSPResponse/BasicOCSPResponse/SingleResponse、CertID、三种 certStatus、nonce、签名/证书 opaque 边界、DER 长度、keep-alive/重试、IPv4/IPv6、PCAP/NIC 和错误传播；不修改 Go 实现。

## 8. P3 固定动作（CORE_MEMORY §3.15/§9.52/§9.14/覆盖审计要求面）

### 8.1 §3.15 三项逐项一例或立项（无例无项即缺口）

| # | 三项 | 本协议对照 | 用例/立项 |
|---|---|---|---|
| ① | 同连接/同流内的多轮操作 | HTTP keep-alive 同连接多事务（t1 单查→t2 批量）；裸 TCP 同 stream 多消息 | 已覆：#13（含 t1→t2 序列） |
| ② | 非正常结束 | tryLater 中断分支；revoked 判定即“吊销”终止分支；malformed 拒收 | 已覆半程：#9（非成功 status）+#13（tryLater→重试/中断）；服务端主动 abort（FIN/RST  mid-transaction）→立项 G-OCSP-1（含） |
| ③ | 长保活 | keep-alive 空闲复用多事务 | 已覆：#13 |

无空项。②的服务端主动 abort 面进 B′（G-OCSP-1），不删用例。

### 8.2 A′/B′ 两分类表（要求面反推：数据/业务/现网/多流四类审计）

A′（现有引擎可构建→20 ID 内已覆或 P4 fixture 可建）：

| 面 | 要求点 | 去向 |
|---|---|---|
| 数据 | CertID 双算法/serial 边界/DER 短长形/三 certStatus/时间窗/nonce 双层/签名 opaque | #4/#5/#7/#8/#10/#11/#12 已覆 |
| 业务 | 单查/批量顺序保持/request→response 匹配/tryLater 重试/keep-alive 多事务 | #1/#6/#9/#13 已覆 |
| 现网 | POST 基线/GET 形态/HTTPS opaque/200+content-type | #1/#9/#14 已覆 |
| 多流 | keep-alive 并发会话/裸 TCP 双 stream/IPv4+IPv6 | #3/#13 已覆 |

B′（引擎结构缺口→D-OCSP-1“明确不解决+迁入计划”，见 design §14 缺口立项）：G-OCSP-1（服务端主动错误语义 internalError/sigRequired 主动面+abort）、G-OCSP-2（openssl 回环抓包核对，确认方式已写清）、G-OCSP-3（代理转发形 fixture）。

### 8.3 9.52 对账两行 + 清单出处声明

- 清单出处声明：本清单来源=规范/官方文档反推（RFC 6960 §4.1/§4.2/§4.3 + RFC 8954 §2 + RFC 5019 §3/§5 + RFC 5280 + X.690），非引擎能力面反推。
- 对账两行：规范逻辑点总数=42（design §10.2 矩阵 30 格 + §10.3 变体 12 行）；用例覆盖数=34 点（矩阵 22 格 + 变体 12 行，#13 内 tryLater→重试事务 P4 显式加），B′ 立项覆盖 8 点（G-OCSP-1；G-OCSP-2/3 为确认项/迁入项不计覆盖点），合计 42 无遗漏。反查 20/20 绿≠覆盖全，此对账为覆盖审计有效口径。

### 8.4 3.14 豁免边界审计

`sessions[]` 显式声明不豁免（本协议有长连接 HTTP keep-alive + 多会话，sessions[] 必写，design §12.3 会话表 s1/s2/s3）。多流并发（#13 双会话交错）与单包多载荷（#6 批量 requestList≥2，多 question 形）各至少一例——两项均有，无豁免逃逸。

### 8.5 三源回指行

RFC 6960（请求/响应/传输/错误码）+ RFC 8954（SHA-256 CertID）+ RFC 5019（GET/cache）+ RFC 5280（PKIX）+ X.690（DER）→ D-OCSP-1（design §13）→ `test/protocol_pcap/cases/ocsp.json`（20 例）。ID 权威=本文 §2（14 正+6 负）；对账 20=14+6。

### 8.6 断言契约核对结论（与 design §8 一致）

本文 §2 的 20 ID 与 design §8 逐 ID、逐序、逐类型核对一致（14 正 #1–#14 + 6 负 #15–#20，顺序相同，JSON 实际 `packet_count` 为 9/9/10/9/9/9/9/9/9/9/9/9/22/18）。存量审计（9.14）：20 个 cases 均为本轮层链目标形，未发现额外旧占位；负例机器契约仅保留两个执行键；修订记录的 suite 证据保留为历史记录，后续改动须重新校准包数和断言。
