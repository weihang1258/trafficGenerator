# SPNEGO（简单和受保护的 GSS-API 协商，Simple and Protected GSS-API Negotiation）测试用例契约

> 版本：v1.0.0（设计阶段）  
> 日期：2026-08-20  
> 配套设计：`docs/protocol-designs/61-spnego-design.md`  
> 机器契约：`trafficgen/test/protocol_pcap/cases/spnego.json`  
> 状态：`spnego` 层尚未注册；本文定义实现后的 PCAP（抓包文件）/NIC（网卡）断言，不宣称当前 suite（测试套件）可运行。

## 1. 测试原则和未注册边界

用例从设计 §2–§9 逐项派生，共 20 个唯一语义 ID：14 个正例和 6 个负例。当前 JSON 只保留一个不计入语义覆盖的注册前置占位 `spnego_neg_unregistered`，其 `expect` 必须为 `expect_error=true`、`error_contains="unknown layer"`；注册后移除占位，再按本文 §2 顺序加入 20 个语义用例。

SPNEGO carrier（载体）为 HTTP `Negotiate` 或裸 TCP stream（字节流）。无机制解密证据时，PCAP/NIC 只可断言 TCP/HTTP 方向、端口、header、GSS-API InitialContextToken、DER（可区分编码规则）tag/length、OID 和 OCTET STRING 长度；不可声称看见 Kerberos/KRB5/msKrb5/NTLM token 内部字段。动态 token、MIC、nonce、ticket 使用 `presence`、`nonzero`、`same_as_packet`，不能硬编码运行期随机值。

## 2. 原子用例索引

| # | ID | 类型 | 覆盖 | 约定 packet_count |
|---:|---|---|---|---:|
| 1 | `spnego_http_ipv4_init` | 正 | HTTP Negotiate/IPv4、InitialContextToken 与 negTokenInit | 12 |
| 2 | `spnego_http_ipv6_init` | 正 | HTTP Negotiate/IPv6、独立地址族与 token | 12 |
| 3 | `spnego_tcp_ipv4_init` | 正 | 裸 TCP/IPv4 DER stream 重组与 init | 10 |
| 4 | `spnego_tcp_ipv6_init` | 正 | 裸 TCP/IPv6 DER stream 重组与 init | 10 |
| 5 | `spnego_neg_token_init_hints` | 正 | mechTypes、reqFlags、negHints、mechToken 可选字段 | 12 |
| 6 | `spnego_neg_token_resp_selection` | 正 | negTokenResp、negResult、supportedMech、responseToken | 12 |
| 7 | `spnego_neg_token_targ_legacy` | 正 | negTokenTarg 旧式 tag/字段顺序互操作 | 10 |
| 8 | `spnego_mech_oid_variants` | 正 | Kerberos/KRB5/msKrb5 OID 及 OCTET STRING 包装 | 14 |
| 9 | `spnego_mech_token_opaque` | 正 | 未解密机制 token 的存在、长度、重传相等边界 | 10 |
| 10 | `spnego_mechlist_mic` | 正 | 原始 DER mechTypes、MIC 存在/验证与重算边界 | 14 |
| 11 | `spnego_der_canonical_boundaries` | 正 | explicit wrapper、短/长 length 与编码边界 | 12 |
| 12 | `spnego_downgrade_prevention` | 正 | offered/selected OID 约束、reject/incomplete/accept 状态 | 12 |
| 13 | `spnego_multi_session_stream` | 正 | HTTP keep-alive、多 TCP stream、多会话状态隔离 | 24 |
| 14 | `spnego_pcap_nic_consistency` | 正 | PCAP/NIC carrier、方向、DER/OID 外层证据一致 | 16 |
| 15 | `spnego_neg_der_truncated` | 负 | DER tag/length/TLV/token 截断 | — |
| 16 | `spnego_neg_der_length_overflow` | 负 | 长度溢出、父子长度不一致、非最短编码 | — |
| 17 | `spnego_neg_invalid_token_choice` | 负 | choice/tag class/结构混用错误 | — |
| 18 | `spnego_neg_mech_oid_selection` | 负 | OID 编码或选定机制绑定错误 | — |
| 19 | `spnego_neg_mic_downgrade` | 负 | MIC/list 改写、缺失或降级选择 | — |
| 20 | `spnego_neg_carrier_profile` | 负 | HTTP/TCP profile、端口、stream 边界错误 | — |

## 3. 正例逐项断言契约

1. **`spnego_http_ipv4_init`**：建立 IPv4 TCP/HTTP 认证交换，断言 TCP SYN/SYN-ACK、HTTP `401` 与 `WWW-Authenticate: Negotiate`、后续 `Authorization: Negotiate`，InitialContextToken 外层 `0x60`、SPNEGO OID 存在及 negTokenInit tag/length，`packet_count=12`；不可断言机制 token 内字段。
2. **`spnego_http_ipv6_init`**：独立 IPv6 TCP/HTTP fixture，断言 `ipv6.nxt=6`、地址族、HTTP Negotiate 方向与 DER 外层，`packet_count=12`；IPv6 地址不能由 IPv4 fixture 继承。
3. **`spnego_tcp_ipv4_init`**：裸 IPv4 TCP stream 携带跨 segment 的 InitialContextToken/negTokenInit；按重组 stream 断言 `ip.proto=6`、DER 父长度与 SPNEGO OID，`packet_count=10`；TCP segment 边界不当作 token 边界。
4. **`spnego_tcp_ipv6_init`**：裸 IPv6 TCP stream 携带同类 token，断言 `ipv6.nxt=6`、IPv6 checksum 与 token 重组，`packet_count=10`；不得把 IPv6 outer 地址当机制字段。
5. **`spnego_neg_token_init_hints`**：断言 negTokenInit 的 `[0] mechTypes` 为有序 OID SEQUENCE、可选 `[1] reqFlags`、`negHints` name/address 的独立长度、`[2] mechToken` OCTET STRING；动态 token 仅 nonzero，`packet_count=12`。
6. **`spnego_neg_token_resp_selection`**：服务端 negTokenResp 含 `[0] negResult`、`[1] supportedMech`（必须来自 offered list）和可选 `[2] responseToken`；断言字段 tag/DER length/方向与 `accept_incomplete` 或 `accept_completed` 状态，`packet_count=12`。
7. **`spnego_neg_token_targ_legacy`**：显式声明旧式 negTokenTarg profile，断言其 `[0] supportedMech`、`[1] responseToken`、`[2] negResult`、可选 `[3] mechListMIC` 的 tag/顺序，不误解析为 negTokenResp，`packet_count=10`。
8. **`spnego_mech_oid_variants`**：至少三个独立交换使用 Kerberos `1.2.840.113554.1.2.2`、Microsoft KRB5 `1.2.840.48018.1.2.2`、NTLM `1.3.6.1.4.1.311.2.2.10`；断言 OID DER bytes 及 selectedMech 与列表绑定，机制 token 只断言包装存在/长度，`packet_count=14`。
9. **`spnego_mech_token_opaque`**：跨多个 TCP/HTTP 消息携带不透明 mechToken/responseToken，断言 context wrapper、OCTET STRING length 与 nonzero；重传 token 使用 same-as 断言，不解析 token 内部，`packet_count=10`。
10. **`spnego_mechlist_mic`**：断言 mechListMIC wrapper `[3]`、MIC OCTET STRING 存在、验证输入为原始 DER mechTypes；列表未改变时可 completed，动态 MIC 使用 nonzero/same-as，`packet_count=14`。
11. **`spnego_der_canonical_boundaries`**：覆盖空可选字段、单/多 OID、DER 短形式和长形式 length、父子 TLV 紧邻及 token 跨 TCP segment；断言最短合法 length、父长度包含全部子项，`packet_count=12`。
12. **`spnego_downgrade_prevention`**：覆盖 `accept_incomplete`→继续、`request_mic`→MIC、`reject`→终止和合法 `accept_completed`；selectedMech 始终来自原始 offered list，列表改变时要求 MIC/失败，`packet_count=12`。
13. **`spnego_multi_session_stream`**：至少两个 HTTP keep-alive 请求和两个裸 TCP stream/会话并行；断言各自 OID 列表、token buffer、MIC、状态和 TCP四元组隔离，端口可共享但动态 token 不串用，`packet_count=24`，不假设跨流全局顺序。
14. **`spnego_pcap_nic_consistency`**：同一 fixture 分别写 PCAP 并在 NIC 捕获；断言 TCP carrier、方向、端口、HTTP header 或 DER 外层、OID、token 长度一致，`packet_count=16`；HTTP 过滤器为 `tcp port 80 or tcp port 443`，裸 TCP 按实际端口。

无解密/授权密钥时，上述正例不得添加 Kerberos AP-REQ、KRB-ERROR、ticket、nonce、session key 或 NTLM proof 字段断言。若 tshark（抓包解析器）无 `spnego.*` 字段，使用通用 `tcp`/`http` 和稳定 raw frames（原始帧）；不自创字段名。

## 4. 负例契约

每个负例必须在 planner/validator 失败并传播为 task error；不能产生成功 PCAP、`completed/0 packet` 或只有 TCP/HTTP 外壳的假成功。执行期 `expect` 键集合严格为 `{"expect_error", "error_contains"}`：

| ID | 故障输入 | 目标 `error_contains` |
|---|---|---|
| `spnego_neg_der_truncated` | tag/length/子 TLV 或 OCTET STRING 在 stream 中截断 | `der`、`token` 或 `length` |
| `spnego_neg_der_length_overflow` | 长形式溢出、父长度不足/超出、非最短 DER length | `length` 或 `der` |
| `spnego_neg_invalid_token_choice` | 未知 choice、错误 tag class 或 init/resp/targ 混用 | `choice`、`token` 或 `tag` |
| `spnego_neg_mech_oid_selection` | 非法/未提供 OID、OID DER 失配或 selected mech 绑定错误 | `oid`、`mechanism` 或 `selection` |
| `spnego_neg_mic_downgrade` | MIC 缺失/不匹配、列表改写或选择未提供机制 | `mic`、`downgrade` 或 `mechanism` |
| `spnego_neg_carrier_profile` | HTTP scheme/header 方向错误、非 TCP、跨 stream 拼接或裸明文 | `carrier`、`http`、`tcp` 或 `profile` |

合法的空可选字段、长形式 length、`accept_incomplete`/`reject`、OID 别名差异、HTTP keep-alive 和 TCP 分段由正例覆盖，不能误报为负例。错误传播须保留原始原因，不能以通用“0 packets”替代验证错误。

## 5. 三方一致性和静态检查

1. 设计 §9、本文 §2、注册后的 JSON 和审计必须保持同一 20 个语义 ID、同一顺序；14 正例 + 6 负例，当前 JSON 另有一个 `spnego_neg_unregistered` 占位。
2. 未来 14 个正例均有 `packet_count`/`min_packets`、方向和稳定 carrier/DER/OID 字段；6 个负例的 `expect` 只能有 `expect_error`、`error_contains`。当前未注册 JSON 只验证 placeholder（占位）结构。
3. InitialContextToken 的 `0x60`、SPNEGO OID `1.3.6.1.5.5.2`、context-specific tags、父子 DER length 和 OID bytes 必须按实际编码断言；HTTP base64 长度不代替 DER 长度。
4. TCP profile 必须先重组 stream 再解析 DER；TCP segment 起点、IPv4 54/IPv6 74 参考 offset 仅适用于无 options fixture。HTTP profile 只在 header/token 可观察时断言 carrier。
5. 未解密 mechToken/responseToken/MIC 使用 presence/nonzero/same_as；不得伪造 Kerberos/KRB5/msKrb5/NTLM 内部字段。
6. 多会话/多流断言使用四元组、OID/token distinct 或 same-as，不能依赖交织流的全局包序。
7. 运行 `python3 -m json.tool trafficgen/test/protocol_pcap/cases/spnego.json` 应成功；当前数组只能含 `spnego_neg_unregistered`，且 `proto=spnego`、`expect_error=true`、`error_contains` 精确为 `unknown layer`。

## 6. 实现后执行建议

注册 `spnego` layer 后，先检查 JSON parser、ID 顺序、正负 expect 键集合、DER offsets 和 tshark 字段注册，再运行 1–14 的 PCAP/NIC 正例和 15–20 的错误传播。若环境没有 `spnego.*` dissector，使用通用 carrier 字段和 raw frames；不能将唯一 placeholder 运行结果报告为 SPNEGO suite 通过。

## 7. 修订记录

- v1.0.0（2026-08-20）：建立 14 个 SPNEGO RFC 4178 正例和 6 个严格负例，覆盖三种 negotiation token、negHints、Kerberos/KRB5/msKrb5 OID 包装、DER 边界、MIC、降级防护、HTTP/TCP carrier、IPv4/IPv6、多会话/多流、PCAP/NIC 和错误传播；不修改 Go 实现。
