# OCSP（在线证书状态协议，Online Certificate Status Protocol）设计契约

> 版本：v1.1.1（P1–P3 产物 + P4–P6 交付回写；v1.1.0 = P1–P3 产物）  
> 日期：2026-09-25（v1.1.1 回写 2026-09-27）  
> 状态：**P4–P6 已完成（D-OCSP-1 已验收，2026-09-27）**——`ocsp` 层已注册并入链（`http` 作事件变换器，`DependsOn ["tcp"] + OptionalOn ["http"]`，FieldContract `tcp.dst_port=80`，裸 TCP 8080 fixture 显式写端口）；`cases/ocsp.json` 20 例（14 正 + 6 负）全绿；实现/集成/关单证据见 §9 v1.1.1。本文 §1 的状态边界仅用于说明无效配置不能冒充协议行为通过。  
> 配套文件：`docs/protocol-designs/62-ocsp-testcase.md`、`trafficgen/test/protocol_pcap/cases/ocsp.json`  
> 规范基线：RFC 6960（OCSP）、RFC 8954（SHA-256 CertID）、RFC 5019（轻量 HTTP profile）、RFC 5280（PKIX）、ITU-T X.690（DER，唯一编码规则）。

## 1. 范围、证据等级和未注册边界

本设计定义 RFC 6960 OCSPRequest/OCSPResponse 的 DER（可区分编码规则，Distinguished Encoding Rules）外层、`CertID`、批量 `requestList`、nonce 扩展、签名请求、`BasicOCSPResponse`、`SingleResponse`、证书状态和时间窗口。覆盖 HTTP POST/GET 与裸 TCP stream（字节流）载体、IPv4/IPv6、多会话/多流、PCAP/NIC（网卡）一致性。HTTP 是 OCSP 常用传输 profile（档案）；OCSP 不定义独立 TCP record length，裸 TCP 必须按完整 DER TLV（标签-长度-值）重组，不能自创长度字段。

没有签名私钥、证书链或动态 nonce fixture（固定样本）时，只断言 DER tag/length、`CertID` 算法与 hash 长度、请求/响应方向、HTTP 状态、responseStatus 和不透明 signature bytes；不得伪造签名值、nonce、证书序列号，或声称密码学签名已验证。动态字段用 `presence`、`nonzero`、`distinct`、`same_as_packet` 断言。

当前实现已注册 `ocsp` layer、planner、validator 和生成器；`cases/ocsp.json` 已包含 20 个语义用例（14 正 + 6 负）。注册前拒绝、0 包或空 PCAP 不是 OCSP 行为通过。

## 2. 推荐配置、层链和载体 profile

推荐 HTTP 层链为 `[ip, tcp, http, ocsp]` 或 `[ipv6, tcp, http, ocsp]`；裸 TCP 为 `[ip, tcp, ocsp]` 或 IPv6 对应链。层链是实现集成契约，不表示当前注册。地址只住 `ip`/`ipv6` 层（`src`/`dst`），端口只住 `tcp` 层（`src_port`/`dst_port`），数量只走 `flow_control`；顶层只允许 `layers`/`flow_control`/`output`：

```json
{
  "layers": [
    {"ip": {"src": "192.0.2.62", "dst": "198.51.100.62"}},
    {"tcp": {"src_port": 42062, "dst_port": 80}},
    {"http": {}},
    {"ocsp": {
      "profile": "http-post", "hash_algorithm": "sha256",
      "request_count": 1, "nonce": {"enabled": true, "opaque": true},
      "cert_status": "good", "signed_request": false
    }}
  ],
  "flow_control": {"flows": 1}
}
```

裸 TCP profile 链形（无 `http` 层，走完整 DER TLV 重组，无私有长度前缀）：

```json
{
  "layers": [
    {"ip": {"src": "192.0.2.62", "dst": "198.51.100.62"}},
    {"tcp": {"src_port": 42062, "dst_port": 8080}},
    {"ocsp": {"profile": "tcp", "hash_algorithm": "sha256", "request_count": 1}}
  ],
  "flow_control": {"flows": 1}
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
| `sessions`/`flow_control` | 每会话独立 nonce、requestList、response matching（响应匹配）、重试和 DER 重组缓存；数量只走 `flow_control.flows`。 |
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

共 20 个唯一语义 ID：14 个正例和 6 个负例；顺序与本文 §8、`testcase.md` §2 及 `ocsp.json` 完全一致。三方契约见 §5。

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
| 18 | `ocsp_neg_nonce_extension` | 负 | nonce 扩展缺失、重复、错误嵌套或不相等 | — |
| 19 | `ocsp_neg_signature` | 负 | 签名结构、算法、Responder 授权错误 | — |
| 20 | `ocsp_neg_carrier_profile` | 负 | HTTP/TCP profile、端口、method/content type 错误 | — |

三方契约必须保持本文 §8、`testcase.md` §2、`ocsp.json` 同一组 20 个 ID、同一顺序、14 正例+6 负例；当前文档阶段的 cases 已满足该对账。

## 9. 修订记录

- v1.1.1（2026-09-27）：P4–P6 交付回写与本文入版（原 v1.1.0 仅存 /tmp/stale-docs-backup，未曾入仓——本版随关单补提交）。交付事实：实现 `31ae72e`、集成 merge `ed131c5`（schemagen 125→126）、P6 关单 `d971856`；P6 隔离终审「通过，无修轮点」（0C/0M/0m/3 注记）；门 1–3 全绿（门3 三条点到行；9.53 最复杂例 #13 = 7 点/4 维达标）；suite 20/20（canonical 复跑 + pcap 落盘）、`coverage_gate` 54/54、`verify.py` 104 点 0 失败、`-race` 绿；248 条款比对表落 `docs/protocol-designs/248/46-ocsp-248-table.md`；live 库 ocsp 行清空（strategies 14 + tasks 42，删前报数→备份 `backup-ocsp-purge-20260927-010017.db`→删→总量 1840/9481 对账，跨协议引用零）。缺口：G-OCSP-1/2/3 维持 open（§15）。
- v1.1.0（2026-09-25）：P1–P3 产物。新增 §10 P1 八项规范矩阵、§11 三路对照与候选方案对比、§12 门1 §1–§14 十四行对照表（含 §1/§3/§12 强制展开与目标形状 spec_json 样例）、§13 D-OCSP-1 P2 代码设计草稿、§14 P3 测试对接清单。修复 §2 示例顶层旧扁平键（`src_ip/src_port/dst_ip/dst_port` 四键迁入 `ip`/`tcp` 层，数量走 `flow_control`）。
- v1.0.0（2026-08-20）：建立 14 个 RFC 6960/8954 正例和 6 个严格负例，覆盖 HTTP/TCP profile、OCSPRequest/Response DER、CertID、批量请求、nonce、签名/扩展、BasicOCSPResponse、SingleResponse、时间窗口、IPv4/IPv6、多会话/多流、PCAP/NIC 和错误传播；不修改 Go 实现。

## 10. P1 规范矩阵（CORE_MEMORY §4 八项：规范要求→业务场景→代码现状→缺口）

> 深度口径（§4.19–4.22）：矩阵三张子表——①命令×响应码矩阵（§10.2）②数据形态变体表（§10.3）③商业行为→用例映射表（§11.2）。条目三选一：已实现 / 明确不支持 / 不适用 + 对应用例号；无遗漏留白。

### 10.1 八项规范矩阵

| # | 规范要求（RFC 条款） | 业务场景 | 代码现状 | 缺口 |
|---|---|---|---|---|
| 1 | 连接模型：OCSP over HTTP（POST/GET），请求→响应短事务；HTTP keep-alive 可复用连接发多事务（RFC 6960 §4.3；RFC 5019 §3；本契约 §5） | 浏览器/客户端向 OCSP responder 查证书状态；压测多事务长保活 | `ocsp` layer/planner/validator/生成器已注册；HTTP 层提供 TCP 事件能力；20 个目标层链 cases 已落盘 | 已实现；由 #1/#2/#13/#14 覆盖，真实 suite 证据见修订记录 |
| 2 | 命令消息表：OCSPRequest（tbsRequest/version/requestorName/requestList/requestExtensions/optionalSignature）→ OCSPResponse（responseStatus + 可选 responseBytes→BasicOCSPResponse→ResponseData→SingleResponse[]）（RFC 6960 §4.1/§4.2；本契约 §3/§4） | 单/批量证书状态查询；签名请求；三种 certStatus 区分 | 结构化声明式回放与断言契约已落实现并由 20 个 cases 驱动 | 已实现；#1/#4–#11 覆盖，负例由 planner/validator 拒绝 |
| 3 | 状态机：请求发送→响应接收→nonce/CertID 匹配→状态/时间判定；非 successful responseStatus 不得当成功用；`tryLater(3)` 可重试（RFC 6960 §4.3；本契约 §4） | 客户端状态判定；tryLater 重试；错误码分支 | 无 | 事务序列事件序（request→response→match→判定）；重试/失败分支见门1 §3 五件套；错误码枚举全覆盖见 §10.2 |
| 4 | 字段表：CertID（hashAlgorithm OID+参数/issuerNameHash/issuerKeyHash/serialNumber 最短 INTEGER）、nonce 双层 OCTET STRING、GeneralizedTime（producedAt/thisUpdate/可选 nextUpdate [0] EXPLICIT）、CertStatus 三 choice tag、ResponderID byName[1]/byKey[2]、DER definite-length 最短 length（RFC 6960 §4.1/§4.2；RFC 8954 §2；X.690；本契约 §3–§5） | 跨 CA 互操作；哈希算法迁移 SHA-1→SHA-256；时间 freshness 判定 | DER 原语、算法绑定、时间/status/nonce 结构已在 `internal/protocol/ocsp/{der,builder,planner}.go` 实现 | 已实现；#4/#5/#7/#10/#12 与负例 #15/#16/#18 覆盖 |
| 5 | 错误处理：responseStatus 7 取值（0 successful/1 malformedRequest/2 internalError/3 tryLater/5 sigRequired/6 unauthorized；4 未用保留）；DER 非法（截断/长度越界/tag 错/非最短形/indefinite）；请求响应不匹配（CertID/批量项/nonce/状态）；签名结构错；carrier/profile 错（RFC 6960 §4.2.1；本契约 §7） | 服务端拒识；网络损坏；重放/错配；未授权 responder | `planner.go` 已提供 wire_fault 与自然守卫；错误锚词由 6 个负例断言 | 已实现；#15–#20 覆盖，服务端主动错误面仍列 G-OCSP-1 迁入计划 |
| 6 | 超时活性：HTTP 层超时/重试；`tryLater`+HTTP 503 可重试；长保活 keep-alive 空闲复用；裸 TCP stream 重组超时（RFC 6960 §4.3；RFC 5019 §5；本契约 §5/§6） | 高峰 responder 过载重试；长连接复用；弱网重组 | keep-alive、重组与错误传播已实现并被 #13 覆盖 | 已实现；#13 含 tryLater→重试与多会话隔离 |
| 7 | NAT/代理：HTTP 明文经代理转发（绝对 URI/Host 头）；HTTPS 443 经 CONNECT 隧道（未解密只能断言 TCP/TLS carrier）；裸 TCP 无代理语义（RFC 5019 §3；本契约 §5） | 企业网代理后 OCSP 查询；HTTPS-OCSP 隧道 | HTTPS opaque 与裸 TCP 已有目标形；代理行为仍为 G-OCSP-3 缺口，未以未实现冒充通过 | G-OCSP-3：抓 RFC 5019 §3 + 代理包，确认后补 fixture |
| 8 | 版本方言：v1 DEFAULT（[0] EXPLICIT 可缺省）/v2 显式；SHA-1（RFC 6960）→ SHA-256（RFC 8954）算法迁移；RFC 5019 轻量 profile（GET base64url 无 padding/可缓存）；BasicOCSPResponse 为 responseType `1.3.6.1.5.5.7.48.1.1`（RFC 6960 §4；RFC 8954 §2；RFC 5019；本契约 §2–§4） | 老客户端 SHA-1 兼容；移动端轻量 GET；v2 扩展 | 双算法、GET/POST、版本形态已进入实现与 cases；未知 responseType 保持未断言 | 已实现；#4/#5/#14 覆盖，未知保留值不冒充支持 |

### 10.2 子表①：命令×响应码矩阵（逐格已覆/缺失）

| 请求面 \ 响应面 | successful(0)+Basic | malformed(1) | internalError(2) | tryLater(3)+重试 | sigRequired(5) | unauthorized(6) |
|---|---|---|---|---|---|---|
| POST 单 Request | 已覆 #1/#4/#5 | 缺口→负例 #15 覆盖（DER 截断触发侧） | 缺口 B′：服务端 500 行为待 P4 fixture（见 §14 缺口立项 G-OCSP-1） | 正例 #13 keep-alive 序列含 tryLater→重试分支 | 缺口→负例 #19 部分（伪造签名拒）；服务端主动 sigRequired 待 G-OCSP-1 | 缺口→负例 #19（Responder 授权错） |
| POST 批量 requestList | 已覆 #6 | #15 同上 | G-OCSP-1 | #13 | #19 | #19 |
| GET（RFC 5019） | 已覆（#14 carrier 一致含 GET 形；#3 同链） | #15 | G-OCSP-1 | G-OCSP-1（GET 缓存+tryLater 交织） | #19 | #19 |
| 裸 TCP stream | 已覆 #3 | #15 | G-OCSP-1 | G-OCSP-1 | #19 | #19 |
| signed request | 已覆 #8 | #15 | G-OCSP-1 | G-OCSP-1 | 已覆 #8（结构面）+#19 | #19 |

注：30 格中 22 格由 20 ID 覆盖（含 signed×sigRequired 客户端触发面 1 格部分覆盖）；8 格走 B′ 立项 G-OCSP-1（internalError 服务端主动面×5、GET/裸 TCP/signed 的 tryLater 交织×3）。客户端 tryLater→重试事务由 #13 keep-alive 序列显式带（P4 fixture 加该事务，先跑后钉）。

### 10.3 子表②：数据形态变体表（协议相关全部形态逐项）

| 变体维度 | 形态 | 对应用例 | 备注 |
|---|---|---|---|
| 地址族×载体 | IPv4/HTTP POST、IPv6/HTTP POST、IPv4/裸 TCP、IPv6/裸 TCP | #1/#2/#3/#14 | 四格满格（§9.24 对称） |
| hash 算法 | SHA-1（20B×2）、SHA-256（32B×2） | #4/#5 | 算法↔长度绑定校验；仅凭长度猜算法=拒 |
| serialNumber | 正常值/显式 0/长整数最短形/高位 1 加 0x00 | #4（扩展断言） | 0 不被缺省覆盖（契约 §3） |
| DER length | 短形（<128）/长形（0x81/0x82）/父长度覆盖全部子 TLV | #4–#8 frames 钉 | indefinite/非最短形→负例 #15 |
| CertStatus | good[0]/revoked[1]+RevokedInfo/unknown[2] | #10 | IMPLICIT choice tag 面，非字符串 |
| 时间 | producedAt/thisUpdate 必需、nextUpdate 可选 [0] EXPLICIT、缺 nextUpdate 形、过期/倒置形 | #12 | 过期≠静默有效；时钟不硬编码 |
| nonce | 有 nonce 双层/same_as、无 nonce 请求、nonce 不等 | #7 + 负例 #18 | 双层长度逐层算 |
| 签名 | 无签名/optionalSignature+certs/仅算法错 | #8 + 负例 #19 | 无 key 不宣称验证成功 |
| responseStatus | successful+Basic/5 非成功取值 | #9 + 负例 #19 | 4 未用保留：不断言 |
| HTTP 形态 | POST/GET base64url 无 padding/keep-alive 多事务/chunked 分隔/503 | #1/#13/#14 | Content-Length=DER bytes |
| TCP 形态 | 分段/合并/粘连双消息/跨 stream 不拼接 | #3/#13 | 无私有长度前缀 |
| 版本 | v1 缺省/v2 显式 | #8（requestorName 侧带出） | 缺省≠缺字段 |

## 11. 三路对照与候选方案对比（CORE_MEMORY §4.12–4.18）

### 11.1 三路对照

①规范原文：RFC 6960（OCSP 全流程：§4.1 请求/§4.2 响应/§4.3 传输语义/§4.2.1 responseStatus 7 取值）、RFC 8954（SHA-256 CertID，OID `2.16.840.1.101.3.4.2.1`）、RFC 5019（轻量 profile：GET base64url 无 padding、缓存语义）、RFC 5280（PKIX 证书/扩展语义：ResponderID、GeneralizedTime）、X.690（DER definite-length/最短形）。
②现网行为：浏览器（Chrome/Firefox CRLite/OCSP 装订 stapling 优先，直连 responder 降级）+ CA responder（DigiCert/Let's Encrypt：POST `application/ocsp-request`→200 `application/ocsp-response`，GET 缓存友好）+ `openssl ocsp`（`-issuer/-cert/-url` 发 POST，`-nonce` 加扩展；抓包形态=HTTP POST + DER body，Content-Length=DER bytes）——出处确认方式：P4 前抓 `openssl ocsp -issuer chain.pem -cert cert.pem -url http://127.0.0.1:80 -nonce` 回环包核对 POST 头序与 DER 外层（立项 G-OCSP-2）。
③开源实现思路：wireshark `packet-ocsp.c`（本机 tshark 53 个 ocsp.* 字段已实证：`ocsp.responseStatus`/`ocsp.issuerNameHash`/`ocsp.issuerKeyHash`/`ocsp.serialNumber`/`ocsp.ReOcspNonce`/`ocsp.certStatus` 等，字段语义借鉴不搬码）+ `openssl crypto/ocsp`（请求构建/nonce 加解语义借鉴）。

三路结论一致：POST short-transaction + DER definite-length + nonce 双层 OCTET STRING + 三 certStatus tag 面；取舍：现网 stapling/TLS 装订属 TLS 载体行为不入本契约（HTTPS 未解密只断言 carrier）；UDP 不做本契约载体（三路均无 OCSP-over-UDP 形态）。

### 11.2 子表③：商业行为→用例映射表（§4.16）

| 商业行为（产品+版本+出处） | 用例编号 | 无映射项+确认方式 |
|---|---|---|
| openssl ocsp POST 查询（openssl 3.x `-issuer/-cert/-url/-nonce`） | #1/#4/#5/#7（POST+CertID+nonce） | — |
| CA responder GET 缓存查询（RFC 5019；Let's Encrypt GET 形态） | #14（含 GET 形 carrier 一致） | GET+tryLater 交织→G-OCSP-1 确认（查 RFC 5019 §5 缓存节+抓包） |
| 浏览器 stapling 降级直连（Chrome/Firefox） | #1（直连 POST 形） | stapling 本体属 TLS 面→不适用（本契约声明） |
| DigiCert/LE responder 200+`application/ocsp-response` | #1/#9 | — |
| responder 过载 tryLater/503 重试 | #13（含重试分支） | 服务端主动 internalError→G-OCSP-1（抓 `openssl ocsp_responder` 过载行为） |
| 企业代理转发（绝对 URI/Host） | 缺口→G-OCSP-3（P4 fixture 构建，查 RFC 5019 §3 + 代理抓包） | 待确认，见缺口立项 |

### 11.3 候选方案对比（§4.17）

| 方案 | 走法（含借鉴来源） | 优 | 劣 | 性能/复杂度/兼容性 | 结论 |
|---|---|---|---|---|---|
| A 结构化声明式回放 | realm/hash/serial/nonce/status/时间外层结构化 + 签名密文 opaque fixture（kerberos #44 D-KERBEROS-1 同族：EncryptedData 外壳结构化+内层 opaque） | 与已收官族同构（接线/builder/planner/casegen 可复用范式）；无 key 不伪造密码学语义 | 服务端错误语义（internalError 主动面）需 B′ 立项 | O(n) 流式渲染；复杂度低；兼容 SHA-1/256 双算法 | **采用** |
| B 完整 ASN.1 schema 编译器 | 通用 DER schema 驱动编解码（借鉴 openssl asn1t 思路） | 通用性强 | 超 fixture 范围；签名内层本就不可断言；引入编译器复杂度 | 复杂度高；性能无 Fixture 优势 | 不选 |
| C 生 hex 回放 | 整消息 body hex 覆盖（kerberos events[].body 逃生口同款思路） | 最简单 | 字段不可结构化断言；动态面全失；算法迁移即死 | 动态零分 | 仅作负例/特殊形逃生口，不做主方案 |

### 11.4 裁定（双 profile 依赖建模结论）

**裁定1：双 profile 依赖建模选 A——`DependsOn ["tcp"] + OptionalOn ["http"] + TransportOn ["tcp"]`**（本节 A/B 指依赖建模二选一，与 §11.3 候选方案 A/B/C 无关。）**

先证（`trafficgen/internal/core/layers/registry.go` 实测）：
- 全仓库无 `DependsOn` 双值先例：dns/nfs/megaco/kerberos/someip 等双载体全是 `DependsOn` 单值（默认载体）+ `TransportOn` 双值（dns :135-136；nfs :1001-1002；kerberos :771）。
- `TransportOn` 全是 L4（udp/tcp 二值组合或单值）；`http` 是终端/变换层，从未进过 `TransportOn`——原草稿 `TransportOn ["http","tcp"]` 无先例，废止。
- http 族先例（mmse `DependsOn ["http"]`，http_flv/hls/hds 同款）：补全恒供给 http+tcp，缺 http 链不可达（mmse `carrier_no_http` 书面豁免）——只适用于纯 HTTP 形态，不适用本协议双 profile。
- 双载体覆盖机制先例：“用户显式写另一载体层覆盖（补全时替代）”（dns/nfs 注释）+ 链载体↔配置 transport 结构性一致校验（chain_planner.go nfs 块，载体与 transport 不一致同步拒）。
- `OptionalOn` 语义（schema.go:93-98）：可选底座，系统永不自动插入，只有用户显式写才启用（http 层 `OptionalOn ["tls"]` 同款模式，registry.go:103）——正是 HTTP profile 需要的“默认无 http、写了才有”。

二选一：
- A）`DependsOn ["tcp"] + OptionalOn ["http"] + TransportOn ["tcp"]`：裸 TCP profile 默认可达（`[ip,tcp,ocsp]`）；HTTP profile 用户显式写 `http` 层即启用（`[ip,tcp,http,ocsp]`，§12.1 样例）；profile↔http 层有无一致性（http profile 要求 http 层在链、tcp profile 要求不在）由 planner 结构性校验（nfs 同款），不一致同步拒。
- B）`DependsOn ["http"]` 默认 + 裸 TCP 为例外放行：mmse 先证说明 `DependsOn ["http"]` 使无 http 链天然不可达，B 须为引擎开“缺依赖放行”新机制，全仓库无先例。

结论选 A：`OptionalOn` + 单载体 `TransportOn` + 结构性校验全有先例；`TransportOn` 保持 L4 纯度；双 profile 对称可达；http 层变换器分工（http_flv 同款：HTTP 语义归 http 层，OCSP 语义归 ocsp 层）不变。本契约 §10.1 行 1、门1 §5/§13 行、§13 接线件、§13-P2 §8.7 冲突点依赖写法均已统一为本结论。

**框架实装确认（2026-09-25，commit `0c355be`）**：本裁定写作时 `OptionalOn` 在链校验中**零消费点**——`complete.go` 的 `dependedOn` 只查 `DependsOn`，故 A 方案声明的 `[ip,tcp,http,ocsp]` 链当时实际会被判第二个终结层拒绝（与 `[ip,tcp,http,dns]` 同格）。主线程随后修复：`dependedOn` 现为 `contains(s.DependsOn, name) || contains(s.OptionalOn, name)`，可选底座一并计入底座关系。回归证据：`internal/core/layers/optional_on_chain_test.go` 正反两例 + 既有 T18/T18b 语义不变，`go test ./internal/core/layers/ -count=1` 全绿；真实注册表实测 `ip → tcp → http → X` 与 `ip → tcp → X` 双链均可达。存量零影响（修复前全仓库 `OptionalOn` 取值仅 `tls`/`eth`，无终结层声明 `http`）。**A 方案自本次修复起名副其实，双 profile 无需新机制。**

## 12. 门1 §1–§14 十四行对照表（CORE_MEMORY §15.1–15.3）

| § | 本协议怎么满足 | 证据 |
|---|---|---|
| §1 层链唯一真相 | 顶层只含 `layers`/允许的结构性键；地址在 `ip`/`ipv6`，端口在 `tcp`，OCSP 业务字段在终结层，数量走 `flow_control`；目标形状 spec_json 见 §12.1；20 个 cases 已完成迁移 | 本契约 §2、§12.1；`ocsp.json` 全量顶层扫描 |
| §2 策略/任务 | 策略=单 OCSP 流量模板（自带 flow_control flows/bps/time）；任务=多策略合跑+总量封顶；框架语义未动 | 本契约 §1/§13-P2 |
| §3 五件套 | 见 §12.3 强制展开：双 profile 会话表/事务序列/关联 nonce same_as/插入位置/时间线；单流协议不豁免（多事务+keep-alive 在例） | 本契约 §12.3 + 用例 #13 |
| §4 查规范 | RFC 6960/8954/5019/5280 + X.690 + 现网（openssl/browser-CA）+ tshark ocsp 53 字段；P1 矩阵 8 行+三子表 | 本契约 §10/§11 |
| §5 依赖与错误 | DependsOn ["tcp"]+OptionalOn ["http"]（§11.4 裁定1；http 层已注册）；wire_fault 6 值=§2 键表逐字（der_truncated/certid_hash/request_response/nonce/signature/carrier）+自然守卫+profile↔http 层有无结构性校验；失败返回 task error（零假成功） | 本契约 §2/§7 + §13-P2 错误分支 |
| §6 性能 | 声明式回放族：O(n) 流式渲染无全量聚合；pcap/NIC 双路验收；吞吐/并发/内存目标待 P4 基准后定（诚实待确认，不写承诺数字）；六类场景清单见 §13-P2 | §13-P2 性能设计与验收 |
| §7 三份文档 | 62-ocsp-{design,testcase}.md v1.1.0（ID 权威=testcase §2）+ D-OCSP-1（本契约 §13 草稿，门1 获批=定稿）+ T-OCSP（testcase §8 草稿）+ generated schema（P4 重跑） | 修订记录 |
| §8 设计先行 | 本条目 P1–P3 先于 P4 实现；门1 获批= D-OCSP-1 定稿=开工门 | 提交序 |
| §9 测试三源 | 三源=RFC 条款+D-OCSP-1+tshark ocsp.* 字段（53 已实证）+现网 openssl/CA 行为；20 ID 正负对账；三源回指行见 testcase §8 | T-OCSP（testcase §8） |
| §10 评审闭环 | 每阶段对抗自重审（结论见 p123 报告）+ 收官隔离复审 + 修轮；红先绿后 | 本轮文档自审报告 |
| §11 白话 | 每阶段白话一句先行 | 汇报 |
| §12 动态清单 | 见 §12.12 强制展开：四元组=ip/tcp 层（五策略全支持）；业务字段逐个列开/不开+理由；序号算法位置诚实“待 P4 定” | 本契约 §12.12 |
| §13 schema 派生 | 层链 schema 行（`DependsOn ["tcp"]+OptionalOn ["http"]+TransportOn ["tcp"]`，§11.4 裁定1；FieldContract tcp.dst_port=80）为设计契约；生成表更新与重跑归代码阶段 | 本契约 §11.4 + §13-P2 接线件 |
| §14 真实流程 | 代码阶段按 suite 三步（MCP 建任务→引擎生成→tshark 校字段）执行全量；断言数值以真实 pcap 钉死；不得照旧手算 | 用例 §1/§6 |

### 12.1 §1 强制展开：旧键去向 + 完整 spec_json 样例

旧键清单（`src_ip/dst_ip/src_port/dst_port/count` + 本协议顶层子映射 `ocsp`）：

| 旧键 | 去向 |
|---|---|
| `src_ip` | → `layers[i].ip.src`（`192.0.2.62`） |
| `dst_ip` | → `layers[i].ip.dst`（`198.51.100.62`） |
| `src_port` | → `layers[i].tcp.src_port`（`42062`） |
| `dst_port` | → `layers[i].tcp.dst_port`（`80`，http profile；裸 TCP 例用 `8080`） |
| `count`（若有） | → 删除，走 `flow_control.flows` |
| 顶层 `ocsp` 子映射 | → `layers[]` 中 `{"ocsp": {...}}` 条目（业务键全量迁入，零残留） |

完整 HTTP POST 样例（目标形状，顶层键仅 `layers`+`flow_control`）：

```json
{
  "layers": [
    {"ip": {"src": "192.0.2.62", "dst": "198.51.100.62"}},
    {"tcp": {"src_port": 42062, "dst_port": 80}},
    {"http": {"method": "POST", "uri": "/", "headers": {"Content-Type": "application/ocsp-request"}, "keep_alive": false}},
    {"ocsp": {"profile": "http-post", "hash_algorithm": "sha256", "request_count": 1, "nonce": {"enabled": true, "opaque": true}, "cert_status": "good", "signed_request": false, "sessions": [{"id": "s1", "transactions": [{"id": "t1", "request": {"certs": [{"serial": "auto"}]}, "expect_status": "successful"}]}]}}
  ],
  "flow_control": {"flows": 1}
}
```

### 12.3 §3 强制展开：五件套（双 profile）

会话表（HTTP POST/GET 与裸 TCP 双 profile）：

| 会话 | profile | 四元组 | 生命周期 |
|---|---|---|---|
| s1 | http-post | ip.src/dst + tcp.42062→80 | TCP 握手→POST request→response→match→判定→挥手 |
| s2 | http-get（RFC 5019） | 同 s1 族，独立 src_port | GET base64url URI→response→match→判定 |
| s3 | tcp（裸） | tcp.42062→8080 | 建连→DER stream 发→重组→逐消息解析→判定 |

事务序列（request→response，单事务四件事 §3.4–3.7）：

| 事务 | 前置条件 | 触发动作 | 成功分支 | 失败分支 |
|---|---|---|---|---|
| t1 单查 | s1 已建连 | POST OCSPRequest（1 CertID） | response successful→nonce/CertID same_as→good/revoked/unknown 判定 | responseStatus 非成功→按码分支（tryLater 重试/其余中断）；DER 非法→task error |
| t2 批量 | t1 成功（同会话 keep-alive） | POST requestList≥2 | 逐项 response matching，顺序保持 | 任一项不匹配→中断会话+task error |
| t3 GET | s2 已建连 | GET base64url DER | 同 t1 判定 | URI 非法→carrier 负例 |
| t4 裸 TCP | s3 stream 就绪 | 发完整 DER TLV | 重组后父长度解析→判定 | 截断→der 负例；粘连→逐个解析 |

关联关系：请求/响应经 CertID（逐项）+ nonce `same_as_packet` 关联（三件事 §3.9：归属会话 sN、归属事务 tM、由 nonce 扩展 + CertID 双字段决定）；被关联方无独立副流（单通道协议，无 `driven_by` 派生流——与 CWMP 范本差异点诚实声明）。
插入位置：终结层——HTTP profile 经 http 层 body 透传（request=POST body，response=response body）；裸 TCP 经 tcp payload 直传（接收端按 DER 父长度重组）。
时间线：顺序（t1→t2 同连接 keep-alive 串行；s1/s2/s3 会话间并发交错，多会话输出不假设全局包序，只断言流内状态）。

### 12.12 §12 强制展开：动态字段清单

| 字段 | 住处 | 开策略 | 理由 |
|---|---|---|---|
| `src`（src_ip） | ip 层 | fixed；多流由每 session 显式 `src_ip` 覆盖 | §12.2 四元组锚点；动态地址池不在 OCSP 生成器内重复实现 |
| `dst`（dst_ip） | ip 层 | fixed；responder 地址由 fixture 钉死 | 多目标地址另立项，不暗示自动变化 |
| `src_port` | tcp 层 | fixed；OCSP 会话可显式覆盖，未写时由 tcp 层缺省 | 端口由承载层统一管理；OCSP 不另起顶层端口算法 |
| `dst_port` | tcp 层 | fixed（80/8080/443 由 profile/fixture 约束） | tshark 自动解码约束；裸 TCP 8080 fixture 显式写端口 |
| `serial_number` | ocsp 层 | `auto` 确定性递增；也支持十进制/0x 字面量 | builder 按会话/事务/CertID 索引生成 |
| `nonce` | ocsp 层 | fixed hex 或 seed 派生；same_as response、跨会话 distinct | 无 seed 时固定 fixture 派生，非密码学随机 |
| `issuer hashes` | ocsp 层 | fixed fixture；不开放动态 | 无 issuer 证书证据时真实匹配不可算 |
| `cert_status` | ocsp 层 | fixed；正例逐例覆盖 good/revoked/unknown | 三态由单事务声明，不静默轮转 |
| `responseStatus` | ocsp 层 | fixed/由事务结果决定；4 保留值不生成 | 错误码负例与 G-OCSP-1 分开 |
| `hash_algorithm` | ocsp 层 | fixed（sha1/sha256） | 算法与 hash 长度绑定 |
| `request_count` | ocsp 层 | fixed/由 `request.certs` 项数推导 | 批量项数必须与 requestList 一致 |

序号算法代码位置：`trafficgen/internal/protocol/ocsp/builder.go:322-328` 的 `parseSerial`；`"auto"` 按 `fixtureSerialBase + si*0x100 + ti*0x10 + ei` 确定性生成，索引分别为会话、事务和 CertID 项。nonce 解析位置为 `builder.go:359`；具体动态算法由该实现与测试契约共同锁定。

### 12-P2 presence 负例形状（链级红例必含①）

层链 + 顶层空子映射并存 = 判死负例（presence 负例形状，非残留）：`{"layers":[...],"ocsp":{}}`（顶层空 `ocsp:{}` 与层链并存）应由 planner/validator 拒绝，`error_contains` 含 `presence` 或顶层键锚词。当前 20 个目标用例中无该形；代码阶段必须新增或在套件中补链级红例。

## 13. D-OCSP-1 P2 代码设计草稿（CORE_MEMORY §8 八要素；门1 获批=定稿）

> 体裁：文件清单/接口签名/数据结构/主流程/错误分支/性能设计与验收/回滚方式。http 层作为常用传输依赖必须声明；DER 编码权威与 nonce 双层 OCTET STRING 长度规则点名。

**文件清单（新建 5 + 接线 9）**：

| 文件 | 职责 |
|---|---|
| internal/core/ocsp.go（NEW） | OCSPConfig/Session/Transaction/CertEntry 结构 + 严格 UnmarshalJSON（递归 DisallowUnknownFields）+ 6 wire_fault 常量与 DescribeOCSPWireFault 锚词表 |
| internal/protocol/ocsp/der.go（NEW） | DER 编码原语：tag 字节、长度短形（<128）/长形（0x81/0x82）、INTEGER 最短形、OCTET STRING、GeneralizedTime、SEQUENCE、上下文构造型——全 definite-length（X.690）；**nonce 双层 OCTET STRING 长度逐层计算**（外层包内层 DER 全字节） |
| internal/protocol/ocsp/builder.go（NEW） | 请求/响应 builder（CertID/批量 requestList/nonce/optionalSignature/BasicOCSPResponse/SingleResponse 三态/时间窗）+ 双 profile 分帧（HTTP 经 http 层 body 透传；裸 TCP 整 DER 直发，接收按父长度重组）+ ocspWalker 会话状态单权威 + init() 注册 generator/validator |
| internal/protocol/ocsp/planner.go（NEW） | validateSpec/validateSession（walk renderEvent 同路径单权威）+ validateWireFault + 算法↔hash 长度绑定守卫 + CertID↔响应一致性守卫 + presence/白名单预检 |
| internal/protocol/ocsp/casegen_test.go（NEW） | 一次性生成器：20 例（14 正+6 负）契约计数逐例 add()，落 test/protocol_pcap/cases/ocsp.json |
| 接线件 | types.go `OCSP *OCSPConfig`；FlowMeta.OCSP；translate `case "ocsp"` + Meta 直传；strategy_convert `case "ocsp"` + setDefaultDstPort 80；registry 行 DependsOn ["tcp"]+OptionalOn ["http"]+TransportOn ["tcp"]（§11.4 裁定1）+FieldContract tcp.dst_port=80；validate_layers 预检（缺 tcp 载体/profile↔http 层有无不一致/混合地址族/顶层旧键拒）；main.go 空白导入 + NewChainPlanner("ocsp")；protocols.go 白名单 + protocols_test 同步；schemagen 重跑 |
| tools/coverage_gate.py | check_ocsp（准入接线/关键件/守卫/用例面四段） |

**接口签名**（示意，P4 落码钉死）：`GenerateOCSPRequest(cfg) []byte` / `GenerateOCSPResponse(cfg) []byte` / `ValidateOCSPSpec(spec) error` / `DescribeOCSPWireFault(fault string) string`。
**数据结构**：Session{id, profile, transactions[]}；Transaction{id, request CertEntry[], expect_status, nonce}；CertEntry{hash_alg, issuer_hashes, serial, status}。
**主流程**：validateSpec→逐会话 walker→逐事务 render（request DER→http body/tcp payload；response DER→匹配 nonce/CertID）→EmitMsg→worker→pcap/NIC。
**错误分支（§5.2）**：①wire_fault 6 值注入拒（锚词进断言）；②自然守卫：算法↔长度不绑定/CertID 不一致/nonce 不等/DER 长度形非法/tag 错/顶层旧键-presence 并存；③validate_layers 预检：缺 http/tcp 载体、双 profile 并存、混合地址族。全部传播为 task error，零假成功。
**依赖声明（§5.1）**：依赖 `http` 层（POST/GET 语义、Content-Length/chunked、keep-alive/transactions）或 `tcp` 层（裸 stream）；依赖 DER definite-length 编码权威（X.690）；无外部密钥/证书依赖（opaque 面）。
**性能设计与验收（§6.1–6.8）**：O(n) 流式——逐事务渲染直发 EmitMsg 无全量聚合；确定性内存（无按包增长结构）；无锁无 sleep（事件驱动）；pcap 路实测 + NIC 路注记（过滤器 `tcp port 80 or tcp port 443`）；回归口径=ocsp.json 全量 suite 耗时 ±10%；六类场景（基线/目标规模/压力上限/长运行时/并发交错/背压）P5 跑测覆盖；边界诚实声明：吞吐/并发/内存目标数字待 P4 基准后定（§6.5，不写承诺）。
**与现有逻辑冲突点（§8.7）**：http 层在 ocsp 链中作事件变换器（body 透传 DER，不解析 OCSP 语义——http_flv 同款分工）；registry `DependsOn ["tcp"]+OptionalOn ["http"]`（§11.4 裁定1）：http 层用户显式写才供给/放行；profile↔http 层有无一致性校验（http profile 要求 http 层在链、tcp profile 要求不在，nfs 链载体↔transport 同款结构性校验，不一致同步拒）；FieldContract tcp.dst_port=80 与裸 TCP 8080 fixture 共存（fixture 显式写端口，不依赖补齐）；schemagen 重跑层数 123→124（kerberos 项后递增）。
**回滚方式（§8.8）**：全量 revert 新建文件 + 接线件回退（git revert 提交序）；registry/schemagen 生成文件随提交对齐回退；无数据迁移面。

## 14. P3 测试对接清单（T-OCSP 草稿输入；正文落 testcase 文件）

- §3.15 三项：①同连接多轮操作→#13 keep-alive 多事务（已覆）；②非正常结束→tryLater 中断+revoked 判定分支（#9/#13 已覆半程，服务端主动 abort 面→G-OCSP-1）；③长保活→#13（已覆）。逐项一例或立项，无空项。
- A′/B′ 两分类表：见 testcase §8（A′=引擎可构建→20 ID 内已覆；B′=引擎结构缺口→G-OCSP-1/2/3 进 D-条目“明确不解决+迁入计划”）。
- 9.52 对账两行：见 testcase §8（规范逻辑点总数 vs 用例覆盖数 + 清单出处声明）。
- 3.14 豁免边界审计：见 testcase §8（sessions[] 豁免≠多流豁免：多流并发 #13 + 单包多载荷批量 #6 各一例，无豁免逃逸）。
- 三源回指行：见 testcase §8。
- 断言通道：fields 用 `ocsp.*`（53 字段已实证：responseStatus/issuerNameHash/issuerKeyHash/serialNumber/ReOcspNonce/certStatus 等）+ 载体 `http.*`/`tcp.dstport`/`ip.proto`/`ipv6.nxt`；DER 顶层/长度走 frames hex 钉；动态 nonce/serial/signature/时间用 presence/nonzero/distinct/same_as。

## 15. 缺口立项清单（有缺口写“缺口立项”，不许空着）

| 立项号 | 缺口 | 确认方式（三选一） | 去向 |
|---|---|---|---|
| G-OCSP-1 | 服务端主动错误语义：internalError(2)/sigRequired(5) 服务端主动面、服务端 mid-transaction abort（FIN/RST）、GET+tryLater 缓存交织 | 查 RFC 6960 §4.2.1 + 抓 `openssl ocsp_responder` 过载行为包 | B′→D-OCSP-1“明确不解决+迁入计划”（P4 fixture 可构建性待定） |
| G-OCSP-2 | 现网抓包核对：`openssl ocsp -issuer/-cert/-url/-nonce` 回环 POST 头序与 DER 外层 | 抓回环包（问谁：无，抓包即确认） | P4 前置确认项，不挡开工 |
| G-OCSP-3 | 企业代理转发形（绝对 URI/Host 头）fixture | 查 RFC 5019 §3 + 代理抓包 | B′→D-OCSP-1 迁入计划 |
