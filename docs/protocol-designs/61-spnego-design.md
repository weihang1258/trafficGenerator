# SPNEGO（简单和受保护的 GSS-API 协商，Simple and Protected GSS-API Negotiation）设计契约

> 版本：v1.0.0（设计阶段）  
> 日期：2026-08-20  
> 状态：仅设计与 PCAP（抓包文件）用例契约；`spnego` 层尚未注册，不修改 Go（编程语言）实现，不宣称当前 suite（测试套件）可运行。  
> 配套文件：`docs/protocol-designs/61-spnego-testcase.md`、`trafficgen/test/protocol_pcap/cases/spnego.json`  
> 规范基线：RFC 4178（SPNEGO）、RFC 2743（GSS-API）、RFC 4121（Kerberos GSS-API）、ITU-T X.690（DER，唯一编码规则）。

## 1. 范围、证据等级和未注册边界

本设计定义 RFC 4178 的协商令牌（token）：`negTokenInit`、`negTokenResp` 和兼容 RFC 2478 的 `negTokenTarg`，包括机制类型 OID（对象标识符，Object Identifier）、`negHints`、`mechToken` 包装、`mechListMIC`（机制列表消息完整性校验）和协商结果。覆盖 HTTP `Negotiate`（协商认证）与裸 TCP 字节流两个 carrier（载体）profile（档案），以及 IPv4/IPv6、多会话/多流隔离。

SPNEGO 只负责选择 GSS-API 机制，不解码或伪造机制 token 的内部字段。Kerberos、KRB5、Microsoft KRB5（msKrb5）等 OID 后的 OCTET STRING 视为不透明 bytes；没有解密密钥、协商上下文或明确 fixture（固定样本）时，不能声称观察到票据、nonce、session key（会话密钥）、NTLM proof 等内层值。动态 OID/token 使用 presence（存在）、nonzero（非全零）、same_as（跨包相等）断言。

当前仓库没有注册 `spnego` layer、planner（规划器）、validator（校验器）或生成器。`cases/spnego.json` 只保留一个 `spnego_neg_unregistered` 注册前置占位，必须为 `expect_error=true` 且 `error_contains="unknown layer"`；占位不计入下文 20 个语义 ID。注册前拒绝、0 包或空 PCAP 不是 SPNEGO 行为通过。

## 2. 推荐配置、层链和 carrier profile

推荐的裸 TCP 层链为 `[ip, tcp, spnego]` 或 `[ipv6, tcp, spnego]`；HTTP profile 为 `[ip, tcp, http, spnego]` 或其 IPv6 变体。层链只是实现集成契约，不表示当前注册：

```json
{
  "layers": [{"ip": {}}, {"tcp": {}}, {"spnego": {}}],
  "src_ip": "192.0.2.61",
  "dst_ip": "198.51.100.61",
  "src_port": 45061,
  "dst_port": 445,
  "spnego": {
    "profile": "tcp",
    "negotiation": "init_resp",
    "mech_types": [
      "1.2.840.113554.1.2.2",
      "1.2.840.48018.1.2.2",
      "1.3.6.1.4.1.311.2.2.10"
    ],
    "mech_token": {"opaque": true},
    "mech_list_mic": {"opaque": true}
  }
}
```

| 配置键 | 约束 |
|---|---|
| `profile` | `http` 或 `tcp`。HTTP 认证头是 carrier；裸 TCP 不自创 RFC 外层长度字段。 |
| `mech_types` | 按线上 DER（可区分编码规则，Distinguished Encoding Rules）顺序保留 OID；选择的 `supportedMech` 必须来自该列表。 |
| `negotiation` | `init_resp`、`init_targ` 或显式事件序列；不能跳过必要的协商状态。 |
| `neg_hints` | 可选的 hint name/target name；只在 `negTokenInit` 中按 profile 声明出现，长度必须匹配。 |
| `mech_token`/`response_token` | 机制 OID 对应的 OCTET STRING；只校验 tag/length/存在性/不透明字节，不解读内层。 |
| `mech_list_mic` | 覆盖 DER 编码的原始 `mechTypes` 列表；算法和密钥由选定机制 profile 提供，不能把 MIC 当作任意 token。 |
| `oid_alias` | `Kerberos` OID `1.2.840.113554.1.2.2`、Microsoft KRB5 OID `1.2.840.48018.1.2.2` 等必须按实际字节区分；别名不可改写线上 OID。 |
| `session_id`/`flow_count` | 每会话独立协商状态、DER token 重组、MIC 上下文和关闭状态；多流不得共享 token。 |
| `wire_fault` | 仅负例注入口：`der_truncated`、`der_length`、`choice`、`mech_oid`、`mic`、`carrier`；不是合法线上字段。 |

HTTP profile 的客户端请求使用 `Authorization: Negotiate <base64-token>`，服务端挑战使用 `WWW-Authenticate: Negotiate [base64-token]`；HTTP header 的 base64（基于 64 个字符的二进制编码）只是传输包装，不改变 DER 字节。PCAP 未解码或未授权解码时只能断言 HTTP header 存在、方向、状态码和 token 长度，不能把任意 base64 内容解释为明文机制字段。TCP profile 中 SPNEGO token 是 TCP stream（字节流）里的 DER TLV；TCP segment 边界不是 token 边界，验证器必须重组 stream 后按 DER length 取 token。

## 3. SPNEGO 外层和 DER 逐层编码

初始 GSS-API `InitialContextToken` 的可观察结构为：

```text
APPLICATION 0 (0x60) {
  MechType OID 1.3.6.1.5.5.2,
  [0] EXPLICIT negotiationToken
}
```

`negotiationToken` 为：

```text
NegotiationToken ::= CHOICE {
  negTokenInit [0] NegTokenInit,
  negTokenResp [1] NegTokenResp
}
```

`negTokenTarg` 是互操作 profile 允许的旧式目标响应结构；若实现把它作为显式选择，必须保持其字段 tag 与 `negTokenResp` 不混淆。所有 SEQUENCE/SET/EXPLICIT wrapper（显式包装）都使用 DER definite length（确定长度）；长度短形式为 1 byte，长形式的首字节高位为 1、低 7 bits 为后续长度字节数。DER 禁止 indefinite length（不定长）、非最短整数/长度编码、错误 tag class 或超出父容器的子 TLV。

| 结构 | 规范字段及 context-specific tag | 线格式约束 |
|---|---|---|
| `NegTokenInit` | `mechTypes [0]`、`reqFlags [1]`、`mechToken [2]`、`mechListMIC [3]`、扩展字段（若 profile 允许） | 每项是显式 `[n]` wrapper；`mechTypes` 内为 SEQUENCE OF OID；`mechToken`/MIC 的 OCTET STRING length 必须与 payload 相等。 |
| `NegTokenResp` | `negResult [0]`、`supportedMech [1]`、`responseToken [2]`、`mechListMIC [3]` | `negResult` 为 ENUMERATED；`supportedMech` 是单个 OID；字段可选但至少须有可解释的协商进展。 |
| `NegTokenTarg` | `supportedMech [0]`、`responseToken [1]`、`negResult [2]`、`mechListMIC [3]` | RFC 2478 旧式字段顺序/tag 与 `NegTokenResp` 不可互换；profile 必须显式声明。 |
| `negHints` | `NegHints ::= SEQUENCE { hintName [0] GeneralString OPTIONAL, hintAddress [1] OCTET STRING OPTIONAL }` | 仅允许在声明的扩展/实现 profile 中出现；GeneralString 和 OCTET STRING 的长度独立计算，不把 hint 当 OID。 |

字段可选不等于任意顺序：同一结构内应按 RFC 4178 的 DER canonical order（规范顺序）发送；未知扩展只能在 profile 明确允许时保留。父 SEQUENCE 长度必须覆盖所有子 TLV，子 wrapper 的长度只覆盖自身内容，不包含外层 tag/length。

## 4. 机制 OID 和 token 包装

机制类型是 ASN.1 OID 的 DER 编码，不是可变字符串。至少覆盖以下互操作值，并在 fixture 中保持区分：

| 名称 | OID 文本 | 语义边界 |
|---|---|---|
| Kerberos V5 | `1.2.840.113554.1.2.2` | 常用 Kerberos GSS-API 机制；OID 后的 token 不解密。 |
| Microsoft KRB5（msKrb5） | `1.2.840.48018.1.2.2` | Microsoft 变体 OID；不能与上行 OID 按名称合并。 |
| NTLM | `1.3.6.1.4.1.311.2.2.10` | 仅作为可选机制列表/响应 token 的 OID；NTLM 内层由独立协议契约负责。 |
| SPNEGO | `1.3.6.1.5.5.2` | 仅用于 GSS-API InitialContextToken 外层，不可作为 selectedMech 冒充已选机制。 |

`NegTokenInit.mechToken [2]` 与 `NegTokenResp.responseToken [2]` 都是 context-specific wrapper 内的 OCTET STRING；旧式 `NegTokenTarg.responseToken` 使用 tag `[1]`。wrapper 内 token 的第一个字节可能是机制自有 tag，但不得仅凭字节猜测 Kerberos AP-REQ、KRB5 或 NTLM message。token length 允许为零仅在 profile 明确允许空占位时；正常机制交换必须存在且 nonzero。跨包同一 token 的重传可用 `same_as_packet` 断言，动态 ticket/nonce/MIC bytes 只能用 presence/nonzero。

## 5. 协商状态、negHints、降级和结果

推荐状态序列为：

1. initiator 发送 `negTokenInit`，列出有序 `mechTypes`，可带 `reqFlags`、`negHints` 和初始 `mechToken`；
2. acceptor 发送 `negTokenResp` 或声明的 `negTokenTarg`，给出 `negResult`、来自列表的 `supportedMech`，以及可选 response token；
3. 机制双方交换后续 response token，必要时携带 `mechListMIC`；
4. `negResult=accept_completed` 才能进入已选机制的应用数据；`accept_incomplete` 只能继续协商；`reject` 必须终止协商并报告明确错误；`request_mic` 表示 acceptor 要求 initiator 提供 `mechListMIC`，不能视为结束或成功。

`negHints` 是提示，不是授权结果；hint name/address 不能覆盖 `mechTypes` 选择，也不能把 HTTP host 或 TCP 地址自动当作 hint。降级防护要求：`supportedMech` 必须出现在 initiator 原始列表；acceptor 不得静默删除更强机制后选择未提供 OID；若机制列表改变，双方必须重新计算/验证 MIC；MIC 缺失或不匹配时不得把协商结果标为 completed。实现需要记录原始 DER `mechTypes` bytes，不能对 OID 排序或重编码后再验证 MIC。

每个 session 维护独立的状态、候选列表、选定 OID、MIC 输入 bytes、token 重组缓冲和结果；重传同一 message 不得推进状态两次。多个 TCP stream 可以交织，但不能跨 stream 拼接 DER token；HTTP keep-alive 上的不同认证请求也必须按连接/认证上下文隔离。

## 6. HTTP Negotiate 与 TCP profile

### 6.1 HTTP Negotiate

请求方向为 `Authorization: Negotiate <token>`，挑战方向为 `401` 与 `WWW-Authenticate: Negotiate [token]`；成功响应由 HTTP profile 声明，SPNEGO `negResult` 仍需在 token/解码 fixture 中自洽。header 折行、base64 缺 padding、空 token、重复 scheme 和错误方向属于 carrier/DER 负例，不得仅因 HTTP 请求建立就报告协商成功。HTTP keep-alive 的多请求应复用 TCP 但不复用不相关 session 的候选机制或 MIC。

### 6.2 裸 TCP

TCP 三次握手、FIN/RST 和 segment sequence 是 carrier 证据。SPNEGO 没有 RFC 定义的独立 TCP record length；实现可以用 stream parser 按 DER TLV 重组，但不得把本地 framing 字段伪装为 SPNEGO 字段。跨 segment 的 token 必须在完整父 TLV 收齐后解析；截断、父长度超出 stream、两个 token 粘连后错误合并均应报告错误。

无 TCP options、无 VLAN、IPv4 的 TCP payload 参考起点为 Ethernet 14 + IPv4 20 + TCP 20 = 54；IPv6 为 14 + 40 + 20 = 74。TCP options 会移动 payload，故这些 offset 仅适用于明确 fixture，不可把固定 offset 当普遍 SPNEGO 字段位置。

## 7. IPv4/IPv6、多会话、多流和边界

outer IPv4 与 IPv6 是独立 fixture 维度，分别断言 `ip.proto=6` 或 `ipv6.nxt=6`、地址族和 TCP checksum；不能由 OID 或 DER 内容推导地址族。每个 session 至少独立维护 TCP四元组、候选 OID 列表、negHints、token buffer、MIC 输入和状态。多会话可共享目标端口，但不得共享动态 token、状态或重组缓存。HTTP 多请求和 TCP 多流只要求每流内部顺序，不假设跨流全局包序。

边界必须覆盖空可选字段、单/多 OID、OID 长 arc、DER 短/长形式 length、token 分段、父/子长度临界值、重复可选字段、合法 reject/incomplete、空 hint（若 profile 允许）和多次 MIC。明确 0 值不能被默认值覆盖；DER 长度计算使用编码后的 bytes，不使用 Unicode 字符数或 base64 文本长度。

## 8. 错误处理、PCAP/NIC 证据和实现完成定义

负例必须在 planner/validator 处失败并传播为 task error，不能输出成功 PCAP、`completed/0 packet` 或只剩 TCP/HTTP 外壳的假成功。负例执行期 `expect` 只能包含 `expect_error` 与 `error_contains`。

| ID | 故障输入 | 目标 `error_contains` |
|---|---|---|
| `spnego_neg_der_truncated` | tag/length/子 TLV 或 OCTET STRING 在 stream/datagram 中截断 | `der`、`token` 或 `length` |
| `spnego_neg_der_length_overflow` | 长度长形式溢出、父长度不足/超出、非最短 DER length | `length` 或 `der` |
| `spnego_neg_invalid_token_choice` | 未知 NegotiationToken choice、错误 tag class 或把 init/resp/targ 混用 | `choice`、`token` 或 `tag` |
| `spnego_neg_mech_oid_selection` | 非法/未提供 OID、OID DER 失配或 selected mech 与 token 不对应 | `oid`、`mechanism` 或 `selection` |
| `spnego_neg_mic_downgrade` | MIC 缺失/不匹配、列表被改写或降级选择未提供机制 | `mic`、`downgrade` 或 `mechanism` |
| `spnego_neg_carrier_profile` | HTTP scheme/header 方向错误、非 TCP、跨 stream 拼接或裸明文冒充 profile | `carrier`、`http`、`tcp` 或 `profile` |

PCAP 正例必须断言 TCP/HTTP carrier、方向、端口、握手/终止、DER raw frame（原始帧）稳定前缀、父长度和 OID bytes。无机制解密证据时只能观察 SPNEGO 外层、OID、OCTET STRING 长度和不透明 token；不能断言 Kerberos/KRB5/msKrb5 token 内部字段。NIC 模式记录接口、过滤器（HTTP profile 推荐 `tcp port 80 or tcp port 443`，TCP profile 按实际端口）和 checksum offload（校验和卸载）边界。

实现完成定义：注册 `spnego` layer；逐字节验证 InitialContextToken、三种 negotiation token、DER explicit tags/length、OID 与 mech token 绑定、negHints、MIC 输入/验证、降级阻断和两类 carrier；planner→worker→TCP/HTTP output 完整路径传播正负结果；-race（竞态检测）和集成测试覆盖多会话 token buffer、乱序/重传与连接关闭；无解密证据不声称看到机制内层。

## 9. 20 个语义场景和 packet_count 映射

共 20 个唯一语义 ID：14 个正例、6 个负例；顺序必须与 `61-spnego-testcase.md` §2 及注册后的 `spnego.json` 完全一致。当前 JSON 只有不计数的注册前置占位。

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
| 11 | `spnego_der_canonical_boundaries` | 正 | explicit wrapper、短/长 length 与 DER 编码边界 | 12 |
| 12 | `spnego_downgrade_prevention` | 正 | offered/selected OID 约束、reject/incomplete/accept 状态 | 12 |
| 13 | `spnego_multi_session_stream` | 正 | HTTP keep-alive、多 TCP stream、多会话状态隔离 | 24 |
| 14 | `spnego_pcap_nic_consistency` | 正 | PCAP/NIC carrier、方向、DER/OID 外层证据一致 | 16 |
| 15 | `spnego_neg_der_truncated` | 负 | DER tag/length/TLV/token 截断 | — |
| 16 | `spnego_neg_der_length_overflow` | 负 | 长度溢出、父子长度不一致、非最短编码 | — |
| 17 | `spnego_neg_invalid_token_choice` | 负 | choice/tag class/结构混用错误 | — |
| 18 | `spnego_neg_mech_oid_selection` | 负 | OID 编码或选定机制绑定错误 | — |
| 19 | `spnego_neg_mic_downgrade` | 负 | MIC/list 改写、缺失或降级选择 | — |
| 20 | `spnego_neg_carrier_profile` | 负 | HTTP/TCP profile、端口、stream 边界错误 | — |

三方契约必须保持本文 §9、`61-spnego-testcase.md` §2、未来 `spnego.json` 同一组 20 个 ID、同一顺序、14 正例+6 负例；当前 JSON 另有一个不计数的 `spnego_neg_unregistered`，且唯一预期为 `unknown layer`。

## 10. 修订记录

- v1.0.0（2026-08-20）：建立 14 个 SPNEGO RFC 4178 正例和 6 个严格负例，覆盖三种 negotiation token、negHints、Kerberos/KRB5/msKrb5 OID 包装、DER 边界、MIC、降级防护、HTTP/TCP carrier、IPv4/IPv6、多会话/多流、PCAP/NIC 和错误传播；不修改 Go 实现。
