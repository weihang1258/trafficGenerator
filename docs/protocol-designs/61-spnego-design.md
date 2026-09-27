# SPNEGO（简单和受保护的 GSS-API 协商，Simple and Protected GSS-API Negotiation）设计契约

> 版本：v1.5.0（P4–P6 落地回写；v1.4.0 = P1–P3 完整产物，含 dissector 模板实测复校 + OptionalOn 可达性证据 + 断言通道勘正）  
> 日期：2026-09-27  
> 状态：**P4–P6 已交付（v1.5.0 回写口径）**：`spnego` 终结层已注册（`registry.go`：`DependsOn ["tcp"]` + `OptionalOn ["http"]` + `TransportOn ["tcp"]` + FieldContract `tcp.dst_port=445`），层链翻译/严格解码/presence 判死/双 profile 生成器与校验器全部接线；`cases/spnego.json` 为 20 个语义用例（14 正 + 6 负），注册前置占位 `spnego_neg_unregistered` 已移除；lane suite 20/20 绿（P6 修轮后复跑，实测包数见 §9 表后注）。P1 期状态（模型口径保留）：八项规范矩阵（§10）+ 三子表 + 三路对照与候选方案对比（§10.4/§10.5）+ 门1 §1–§14 十四行表（§11，§1/§3/§12 强制展开）+ P2 D-SPNEGO-1 代码设计（§12，含 §10.6 裁定的依赖建模）+ P3 对接清单与缺口立项（§13/§14）已落盘；P4 落码按门1 获批版 D-SPNEGO-1 执行。v1.4.0 复校项（全部本机 tshark 3.6.14 + `text2pcap` 重跑实证）：①§10.6 补 **OptionalOn 可达性证据**（框架提交 `0c355be` 已使 `OptionalOn` 参与终结层底座判定，`[ip,tcp,http,spnego]` 今日可达）；②§10.7 M-shape-1 的 `[n]` 包装写法勘正（原记多套一层 `[0]`，实测该形 malformed）；③§9 勘误⑦再勘正（空 `mechTypes` 合法最短形=`A0 02 30 00`，v1.3.0 记的 `A0 04 30 02 A0 00` 实测 malformed）；④§10.3 DER length 行改为实测两档（短形 32B / 长形 268B）；⑤断言通道勘正（裸 TCP 无 `-V` OID 行、`decode_as` 合法目标数 **317**）；⑥`spnego.krb5.*` 子面细分口径（15 + `spnego.krb5_oid` 1）。v1.3.0 追加 §10.7 dissector（解析器）编码模板实测矩阵 + §10.8 裁定2（wire shape / mechListMIC 布局）；§10.4/§11/§13 的 `spnego.*` 字段计数按 `awk -F'\t' '$3 ~ /^spnego\./'` 精确口径为 **41**（§9 勘误⑥）。v1.0.0 §2 的顶层扁平示例已按层链唯一真相改写为纯 layers 形（§2 与 §11.1 样例）。  
> 配套文件：`docs/protocol-designs/61-spnego-testcase.md`、`trafficgen/test/protocol_pcap/cases/spnego.json`  
> 规范基线：RFC 4178（SPNEGO，§4.2/§4.2.1/§4.2.2/§5/Appendix A）、RFC 2743（GSS-API §3.1 InitialContextToken；**ContextFlags 定义不在本 RFC**，见 RFC 4178 §4.2.1）、RFC 4121（Kerberos GSS-API 机制，**opaque 边界参考**）、RFC 2478（§3.2.1 negTokenTarg 旧式互操作）、RFC 4559（§1/§4.1/§4.2 HTTP Negotiate）、ITU-T X.690（DER definite-length，设计决策级参考）。  
> **层链唯一真相**：本契约全文示例只有纯 `layers` 形（裸 TCP `[ip,tcp,spnego]` / HTTP `[ip,tcp,http,spnego]`），地址只住 ip/ipv6、端口只住 tcp、数量只走 `flow_control`；v1.0.0 §2 的顶层扁平键示例已作废（§11.1 去向表）。  
> **内层 mech token 边界**：Kerberos/msKrb5/NTLM token 一律 opaque（只校验 tag/length/存在性/跨包相等），不解码内层字段（§10 矩阵行行重申 + 裁定5）。  
> **与 #45 ntlm 关系**：仅文档级交叉引用（`60-ntlm-design.md:61` `outer=spnego` / `:203` / `:219`），不写代码依赖。

## 1. 范围、证据等级和未注册边界

本设计定义 RFC 4178 的协商令牌（token）：`negTokenInit`、`negTokenResp` 和兼容 RFC 2478 的 `negTokenTarg`，包括机制类型 OID（对象标识符，Object Identifier）、`negHints`、`mechToken` 包装、`mechListMIC`（机制列表消息完整性校验）和协商结果。覆盖 HTTP `Negotiate`（协商认证）与裸 TCP 字节流两个 carrier（载体）profile（档案），以及 IPv4/IPv6、多会话/多流隔离。

SPNEGO 只负责选择 GSS-API 机制，不解码或伪造机制 token 的内部字段。Kerberos、KRB5、Microsoft KRB5（msKrb5）等 OID 后的 OCTET STRING 视为不透明 bytes；没有解密密钥、协商上下文或明确 fixture（固定样本）时，不能声称观察到票据、nonce、session key（会话密钥）、NTLM proof 等内层值。动态 OID/token 使用 presence（存在）、nonzero（非全零）、same_as（跨包相等）断言。

**P4–P6 交付实况（v1.5.0；P1 期边界已收口）**：`spnego` layer/planner/validator/生成器均已注册（`registry.go` spnego 行 + `internal/protocol/spnego/` 五件套 + `internal/core/strategy_convert.go`/`chain_planner.go`/`validate_layers.go` 三处本地块）；`cases/spnego.json` = 20 个语义用例（14 正 + 6 负，顺序=本文 §9=testcase §2），注册前置占位 `spnego_neg_unregistered` 已移除（三源回指见 testcase §8.5）。**P1 期边界（历史口径，保留备查）**：注册前该层在 `registry`/`protocols.go` 零命中，`cases/spnego.json` 只保留 `spnego_neg_unregistered` 占位（`expect_error=true`、`error_contains="unknown layer"`），占位不计入 20 个语义 ID；注册前拒绝、0 包或空 PCAP 不构成 SPNEGO 行为通过。

## 2. 推荐配置、层链和 carrier profile

推荐的裸 TCP 层链为 `[ip, tcp, spnego]` 或 `[ipv6, tcp, spnego]`；HTTP profile 为 `[ip, tcp, http, spnego]` 或其 IPv6 变体。层链是实现集成契约，不表示当前注册。地址只住 `ip`/`ipv6` 层（`src`/`dst`），端口只住 `tcp` 层（`src_port`/`dst_port`），数量只走 `flow_control`；顶层只允许 `layers`/`flow_control`/`output`。v1.0.0 §2 曾给出 `src_ip`/`dst_ip`/`src_port`/`dst_port` 顶层扁平键的示例，现已作废，下样例为唯一合法形状（裸 TCP 链形）：

```json
{
  "layers": [
    {"ip": {"src": "192.0.2.61", "dst": "198.51.100.61"}},
    {"tcp": {"src_port": 45061, "dst_port": 445}},
    {"spnego": {
      "profile": "tcp",
      "negotiation": "init_resp",
      "mech_types": [
        "1.2.840.113554.1.2.2",
        "1.2.840.48018.1.2.2",
        "1.3.6.1.4.1.311.2.2.10"
      ],
      "mech_token": {"opaque": true},
      "mech_list_mic": {"opaque": true}
    }}
  ],
  "flow_control": {"flows": 1}
}
```

HTTP profile 链形（经 http 层透传 Negotiate token）：

```json
{
  "layers": [
    {"ip": {"src": "192.0.2.61", "dst": "198.51.100.61"}},
    {"tcp": {"src_port": 45062, "dst_port": 80}},
    {"http": {"method": "GET", "uri": "/", "keep_alive": true}},
    {"spnego": {
      "profile": "http",
      "negotiation": "init_resp",
      "mech_types": [
        "1.2.840.113554.1.2.2",
        "1.2.840.48018.1.2.2"
      ],
      "mech_token": {"opaque": true},
      "mech_list_mic": {"opaque": true}
    }}
  ],
  "flow_control": {"flows": 1}
}
```

| 配置键 | 约束 |
|---|---|
| `profile` | `http` 或 `tcp`。HTTP 认证头是 carrier；裸 TCP 不自创 RFC 外层长度字段。 |
| `mech_types` | 按线上 DER（可区分编码规则，Distinguished Encoding Rules）顺序保留 OID；选择的 `supportedMech` 必须来自该列表。 |
| `negotiation` | `init_resp`、`init_targ` 或显式事件序列；不能跳过必要的协商状态。 |
| `neg_hints` | 可选的 hint name/target name，只走 dissector 形（`carry: dissector`，NegTokenInit `[3]` 槽；§10.7/裁定2），长度必须匹配；与 RFC 形 `mech_list_mic` 同槽互斥，同消息同时声明=planner 拒。 |
| `mech_token`/`response_token` | 机制 OID 对应的 OCTET STRING；只校验 tag/length/存在性/不透明字节，不解读内层。 |
| `mech_list_mic` | 覆盖 DER 编码的原始 `mechTypes` 列表；算法和密钥由选定机制 profile 提供，不能把 MIC 当作任意 token。线位 = NegTokenInit/NegTokenResp `[3]`（RFC 4178 形；裁定2）。 |
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
| `NegTokenTarg` | `negResult [0]`、`supportedMech [1]`、`responseToken [2]`、`mechListMIC [3]` | RFC 2478 §3.2.1 旧式；**字段序/tag 与 `NegTokenResp` 同构**（差异在 CHOICE 值 [1] 与 ENUMERATED 取值集合：targ 三值、无 request_mic(3)）；v1.0.0 本表原记 `supportedMech [0]/responseToken [1]/negResult [2]` 系误记，已勘误（§10.3 H1 行）。profile 必须显式声明。 |
| `negHints` | `NegHints ::= SEQUENCE { hintName [0] GeneralString OPTIONAL, hintAddress [1] OCTET STRING OPTIONAL }` | 仅允许在声明的扩展/实现 profile 中出现；GeneralString 和 OCTET STRING 的长度独立计算，不把 hint 当 OID。 |

字段可选不等于任意顺序：同一结构内应按 RFC 4178 的 DER canonical order（规范顺序）发送；未知扩展只能在 profile 明确允许时保留。父 SEQUENCE 长度必须覆盖所有子 TLV，子 wrapper 的长度只覆盖自身内容，不包含外层 tag/length。

## 4. 机制 OID 和 token 包装

机制类型是 ASN.1 OID 的 DER 编码，不是可变字符串。至少覆盖以下互操作值，并在 fixture 中保持区分：

| 名称 | OID 文本 | DER bytes（实测，含 tag/len；5.5 节级） | 语义边界 |
|---|---|---|---|
| Kerberos V5 | `1.2.840.113554.1.2.2` | `06 09 2A 86 48 86 F7 12 01 02 02`（tshark OID 名库实测 "KRB5 - Kerberos 5"） | 常用 Kerberos GSS-API 机制；OID 后的 token 不解密。 |
| Microsoft KRB5（msKrb5） | `1.2.840.48018.1.2.2` | `06 09 2A 86 48 82 F7 12 01 02 02`（"MS KRB5 - Microsoft Kerberos 5"） | Microsoft 变体 OID；不能与上行 OID 按名称合并。 |
| NTLM | `1.3.6.1.4.1.311.2.2.10` | `06 0A 2B 06 01 04 01 82 37 02 02 0A`（"NTLMSSP - Microsoft NTLM Security Support Provider"） | 仅作为可选机制列表/响应 token 的 OID；NTLM 内层由独立协议契约负责。 |
| SPNEGO | `1.3.6.1.5.5.2` | `06 06 2B 06 01 05 05 02` | 仅用于 GSS-API InitialContextToken 外层，不可作为 selectedMech 冒充已选机制。 |

`NegTokenInit.mechToken [2]` 与 `NegTokenResp.responseToken [2]` 都是 context-specific wrapper 内的 OCTET STRING；旧式 `NegTokenTarg.responseToken` 同样使用 tag `[2]`（RFC 2478 §3.2.1，v1.0.0 原记 `[1]` 系误记，已勘误——§10.3 H1 行）。wrapper 内 token 的第一个字节可能是机制自有 tag，但不得仅凭字节猜测 Kerberos AP-REQ、KRB5 或 NTLM message。token length 允许为零仅在 profile 明确允许空占位时；正常机制交换必须存在且 nonzero。跨包同一 token 的重传可用 `same_as_packet` 断言，动态 ticket/nonce/MIC bytes 只能用 presence/nonzero。

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

边界必须覆盖空可选字段、单/多 OID、DER 短/长形式 length、token 分段、父/子长度临界值、重复可选字段、合法 reject/incomplete、空 hint（若 profile 允许）和多次 MIC（「OID 长 arc」变体已删——无 RFC 依据，§10.3）。明确 0 值不能被默认值覆盖；DER 长度计算使用编码后的 bytes，不使用 Unicode 字符数或 base64 文本长度。

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

共 20 个唯一语义 ID：14 个正例、6 个负例；顺序必须与 `61-spnego-testcase.md` §2 及 `spnego.json` 完全一致。**交付实况（v1.5.0）**：JSON 已按本文 §2 目标形状落盘 20 例，占位 `spnego_neg_unregistered` 已移除（P1 期该 JSON 只有不计数的注册前置占位）。

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
| 13 | `spnego_multi_session_stream` | 正 | 多流 × 多会话 × 异常分支：两条四元组独立裸 TCP stream（45061/45062→445，`flow_control.flows=2` + `tcp.src_port` 动态对象），每流 s1(krb+msKrb5→accept_completed)/s2(NTLM→reject 异常终止)，候选列表/选定机制/状态不串用 | 24 → **22（实测）** |
| 14 | `spnego_pcap_nic_consistency` | 正 | PCAP/NIC carrier、方向、DER/OID 外层证据一致 | 16 |
| 15 | `spnego_neg_der_truncated` | 负 | DER tag/length/TLV/token 截断 | — |
| 16 | `spnego_neg_der_length_overflow` | 负 | 长度溢出、父子长度不一致、非最短编码 | — |
| 17 | `spnego_neg_invalid_token_choice` | 负 | choice/tag class/结构混用错误 | — |
| 18 | `spnego_neg_mech_oid_selection` | 负 | OID 编码或选定机制绑定错误 | — |
| 19 | `spnego_neg_mic_downgrade` | 负 | MIC/list 改写、缺失或降级选择 | — |
| 20 | `spnego_neg_carrier_profile` | 负 | HTTP/TCP profile、端口、stream 边界错误 | — |

三方契约必须保持本文 §9、`61-spnego-testcase.md` §2、`spnego.json` 同一组 20 个 ID、同一顺序、14 正例+6 负例（v1.5.0 实测：三处逐 ID 同序 ✓；P1 期 JSON 另有不计数占位 `spnego_neg_unregistered`，已随注册移除）。

**表内 `约定 packet_count` 与实测的偏离（先跑后钉，v1.5.0 落盘实测）**：正例实测 = **11/11/9/9/11/11/9/9/9/10/9/9/22/11**（第 1–14 项，出处 `trafficgen/test/protocol_pcap/cases/spnego.json` 的 `expect.packet_count`，由 lane suite 对落盘 pcap 逐例校验）。约定值系 P1 设计意图值，实现期一律按落盘 pcap 实测校准：实测 14 例全部满足 `packet_count = 3（三次握手）+ 事件数 + 4（FIN 挥手）`，故 2 事件例=9、3 事件例=10、4 事件例=11；#13 为单流 11 × 2 流 = **22**（约定 24 已作废）。

**v1.0.0 正文勘误汇总（P1 三路对照实证；v1.1.0 起以本清单为准，v1.3.0 追加 ⑤–⑧，v1.4.0 追加 ⑨–⑫ 复校项）**：①§3 表 `NegTokenTarg` 字段序误记 `supportedMech [0]`/`responseToken [1]`/`negResult [2]`/`mechListMIC [3]`——RFC 2478 §3.2.1 权威（本机 `rfc2478.txt` 第 413-421 行原文实测）为 `negResult [0]`（ENUMERATED，OPTIONAL）/`supportedMech [1]`/`responseToken [2]`/`mechListMIC [3]`，与 RFC 4178 §4.2.2 `NegTokenResp` 字段序同构（差异在 ENUMERATED 取值集合：targ 三值/无 request-mic(3)）（§10.3 H1 行）；②§7 边界清单"OID 长 arc"无 RFC 依据（本协议 OID 域无 ≥128 展开面）——删去该变体（§10.3）；③§5"结果判定"旧口径已按 §10.3"HTTP carrier 成功面"行修正（RFC 4559 §4.2 原文"Any returned code other than a success 2xx code represents an authentication error"，200 可携带末段 token）；④`NegHints` 命名与字段降级为 dissector 本地拆解级证据（§10.1 行 4 + §10.3 negHints 行 + G-SPNEGO-1）；⑤**`reqFlags` 的 ContextFlags 定义出处勘误**：ASN.1 定义在 **RFC 4178 §4.2.1**（本机 `rfc4178.txt` 第 415-422 行原文实测），v1.2.0 误记"RFC 2743 §3.12"——实测 RFC 2743 **无 §3.12 节**（该 RFC §3 只有 §3.1 Mechanism-Independent Token Format 与 §3.2 Exported Name Object Format），其 §2.1 只给 `deleg_req_flag` 等 BOOLEAN 形参；且 RFC 4178 §4.2.1 明确"DER requires that all trailing zero bits be truncated … Implementations should not expect to receive exactly 32 bits"；⑥**`spnego.*` 字段计数口径勘误**：精确值 **41**（`awk -F'\t' '$3 ~ /^spnego\./'`；`grep -c spnego` = 43 含 2 个协议行）；v1.2.0 的 38 来自默认空白分隔 `awk '{print $3}'`，把 3 个 label 含空格的行（`spnego.krb5_oid`/`spnego.decrypted_keytype`/`spnego.unknown_header`）错列漏计；⑦**"空 mechTypes 占位形"字节勘误（v1.4.0 复校后口径）**：v1.2.0 §10.3 记 `0xA0 0x03 0xA0 0x01 0x00` 为"negTokenInit 空 mechTypes 占位形"——实测该形 malformed（`BER Error: SET OF expected but class:CONTEXT(2) Constructed tag:0 was unexpected`）；**合法最短空表形 = `A0 02 30 00`**（`[0]` 内即 `SEQUENCE OF` 空表本体；`spnego.mechTypes` 读回 `0`、Malformed=0）；v1.3.0 曾把该形记作 `A0 04 30 02 A0 00`（二次误记，该形实测 malformed），本次一并作废；⑧**OID value 长度勘误**：v1.2.0 §10.3 记"长度 7 字节为最短形 value"——四值实测为 Kerberos V5 9B / msKrb5 9B / NTLM 10B / SPNEGO 6B（§10.7 附带实测表）；⑨**（v1.4.0 复校）M-shape-1 的 `[n]` 包装写法勘正**：v1.3.0 §10.7 记 `A0 { 30 { A0{30{OIDs}}, … } }`（`mechTypes` 外多套一层 `[0]`）——实测该形被 dissector 判 malformed（`BER Error: Wrong field in SEQUENCE OF: expected class:UNIVERSAL(0) tag:6(OBJECT IDENTIFIER) but found class:CONTEXT(2) tag:0`），`spnego.MechType` 空；合法形=**`[0]` 只包一层、其内容即 `SEQUENCE OF OID` 本体**（`A0{30{OID…}}`，RFC 4178 Appendix A `MechTypeList ::= SEQUENCE OF MechType` 直译）；⑩**（v1.4.0 复校）勘误⑦的"再勘正"项**：即上条⑦内所述 v1.3.0 中间值 `A0 04 30 02 A0 00` 作废，正式口径=`A0 02 30 00`；⑪**（v1.4.0 复校）断言通道勘正**：裸 TCP carrier 的 `tshark -V` **不出现** `OID: 1.3.6.1.5.5.2` 行（445 栈止于 `nbss` 的 `Continuation data:` 原始 hex；随机高端口栈止于 `tcp`），故裸 TCP 的唯一结构证据=该原始 hex 本身（frames hex + offset 54/74）；`tcp.port` 的合法 `decode_as` 目标实测 **317** 个（v1.3.0 记 313，非精确口径），其中仅 `ber`/`kerberos` 对本协议有意义；⑫**（v1.4.0 复校）`spnego.krb5.*` 细分口径**：`spnego.krb5.*` 15 项 + `spnego.krb5_oid` 1 项（后者不含 `krb5.` 段）= 16 项子面；`spnego.ContextFlags.*` 7 + 本体 18 = 41 ✓。

## 9.1 修订记录（v1.0.0–v1.4.0；编号沿 v1.0.0 正文，不重编以免扰动交叉引用）

- v1.5.0（2026-09-27）：**P4–P6 落地回写**。①**P4 交付**：`spnego` 终结层注册（`registry.go`（`DependsOn ["tcp"]` + `OptionalOn ["http"]` + `TransportOn ["tcp"]` + FieldContract `tcp.dst_port=445`）+ 层链翻译/严格解码（`internal/core/spnego.go` 6 级 `strictUnmarshalJSON` 调用点：Config/NegHints/Token/MIC/Session/Event）/`CheckProtoFlat` 顶层 `spnego` 子映射 presence 判死/双 profile 生成器与校验器；RFC 4178 DER 三 token（init/resp/targ）+ `negHints [3]` + `mechListMIC` 逐字节实现。②**P5 交付**：`cases/spnego.json` 20 例（14 正 + 6 负）去扁平完成，占位移除；lane suite 20/20。③**C1（P6 打回修复）形状落地**：#13 `spnego_multi_session_stream` 由"单 HTTP 连接双会话（15 包）"重做为**多流 × 多会话 × 异常分支**——`flow_control.flows=2` + `tcp.src_port` 动态对象 → 两条四元组独立裸 TCP stream（45061/45062→445），每流 s1(krb+mskrb→accept_completed)/s2(NTLM→reject 异常终止)；断言 2 点 → 11 点（5 fields 含跨流 `distinct_values=[45061,45062]` + 6 frames 逐包钉候选列表/negState），实测 22 包（约定 24 作废，§9 表后注）。④**C2 订正**：casegen 该例 summary 原写"s1(HTTP/80) + s2(裸 TCP/445) 并行"与 spec 实况矛盾，已改回实况；偏离（契约 §3-13 字面"同一用例内 HTTP keep-alive 双事务 与 裸 TCP 双 stream 并存"受 one-strategy-one-chain 约束不可表达）登记于 p4-report §7；双载体覆盖改由跨用例承担（#1/#2 HTTP、#3/#4 裸 TCP）。⑤**m1 补钉**：#8 `spnego_mech_oid_variants` 补包 5 resp 帧钉（`supportedMech=NTLM` 会话级选定绑定）。⑥**验收**：lane suite 20/20（P6 修轮后复跑）、`coverage_gate.py spnego` 84/84、`pipe_gate spnego` 静态四项绿、chain/单测 `-race` 绿、casegen 幂等。⑦**缺口维持 open**：G-SPNEGO-1（现网证据升级）/G-SPNEGO-2（服务端主动错误语义，B′）/G-SPNEGO-3（dissector 形↔RFC 形长期一致性）——见 §14；T-21（dissector 形 negHints 字段断言补例）维持"不入 20 ID 契约"。⑧正文同步：§1 注册边界收口、§9 计数与清单、§11.3 会话表/时间线（§11.1 去向表与 §10.1 行 1、§12 的 P1 期现状取证按历史口径保留）。
- v1.4.0（2026-09-25）：P1 实测复校（本机 tshark 3.6.14 + `text2pcap` 逐形重跑）。①§10.6 补 **OptionalOn 可达性证据**：框架提交 `0c355be`（`fix(layers): OptionalOn 计入链路底座关系（终结层豁免）`）已使 `complete.go:418` 的 `dependedOn` 同时认 `OptionalOn`，`[ip,tcp,http,spnego]` **今日可达**（`go test ./internal/core/layers/ -run TestValidateChain_OptionalOnBaseSatisfiesTerminalExemption -count=1` 实测 ok）——v1.2.0/v1.3.0 隐含的"HTTP profile 依赖框架扩展"口径作废；②§10.7 M-shape-1 `[n]` 包装写法勘正（勘误⑨）+ M-shape-3/4/5 补实测细节（`hintAddress` 取值、裸 TCP `-V` 无 OID 行、随机高端口栈止于 `tcp`）；③§9 勘误⑦再勘正（合法空 `mechTypes`=`A0 02 30 00`，勘误⑩；§10.3「NegotiationToken choice」行内残留的 v1.3.0 中间值 `A0 04 30 02 A0 00` 同步勘正，p123 报告缺口 G1）+ 新增 ⑪ 断言通道 / ⑫ `spnego.krb5.*` 细分；④§10.3 DER length 行改实测两档（短形 32B/长形 268B）；⑤§10.4 ① 补 RFC 4559 §4.1、RFC 2743 无 ContextFlags 的原文级结论；⑥§12 DER 权威表 `reqFlags` 注行勘正（RFC 4178 §4.2.1）。
- v1.3.0（2026-09-25）：P1 第③路深挖——§10.7 dissector 编码模板实测矩阵（5 形）+ §10.8 裁定2（wire shape/`mechListMIC`×`negHints` 双形互斥）；§9 勘误汇总扩至 8 条（新增 ⑤`reqFlags` 定义出处=RFC 4178 §4.2.1、⑥`spnego.*` 精确计数 41、⑦空 mechTypes 占位形字节、⑧OID value 长度）；§10.2 逐格重数（35 格）与 §10.3 新增两行（dissector 形 vs RFC 形、断言通道）修正 v1.2.0 算术；补 §11.2 子表③商业行为→用例映射表（§4.16，8 行）；§12 追加 wire shape/dissector 兼容约束；§13/§14 口径同步。（**注**：本条 ⑦ 的字节值与 §10.7 M-shape-1 包装写法已被 v1.4.0 复校作废，以 v1.4.0 为准。）
- v1.2.0（2026-09-25）：P1–P3 完整产物。新增 §10 P1 八项规范矩阵 + 三子表（命令/事件×协商进展矩阵、数据形态变体表、P1 三路对照 §10.4、候选方案对比 §10.5、裁定1 依赖建模 §10.6）；§11 门1 §1–§14 十四行表（§1/§3/§12 强制展开 + 目标形状 spec_json 样例 + presence 负例形状）；§12 D-SPNEGO-1 P2 代码设计（文件清单/接口签名/数据结构/主流程/错误分支/性能设计与验收/回滚方式 + DER 逐结构权威表）；§13 P3 对接清单；§14 缺口立项（G-SPNEGO-1/2）。v1.0.0 正文四处勘误落 §9 后勘误汇总。
- v1.1.0（2026-09-25）：§2 顶层扁平示例改写为纯 layers 形（裸 TCP/HTTP 双 profile 样例）；规范基线补 RFC 2478/4559。
- v1.0.0（2026-08-20）：建立 14 个 SPNEGO RFC 4178 正例和 6 个严格负例，覆盖三种 negotiation token、negHints、Kerberos/KRB5/msKrb5 OID 包装、DER 边界、MIC、降级防护、HTTP/TCP carrier、IPv4/IPv6、多会话/多流、PCAP/NIC 和错误传播；不修改 Go 实现。

## 10. P1 规范矩阵（CORE_MEMORY §4 八项：规范要求→业务场景→代码现状→缺口）

> 深度口径（§4.19–4.22）：矩阵三张子表——①命令×negotiation 进展矩阵（§10.2）②数据形态变体表（§10.3）③商业行为→用例映射表（§11.2）。条目三选一：已实现 / 明确不支持 / 不适用 + 对应用例号；无遗漏留白。
> **内层 mech token 边界（本设计铁律，逐矩阵行重申）**：Kerberos / msKrb5 / NTLM OID 之后的 OCTET STRING 一律 opaque（不透明字节）——只校验 tag/length/存在性/跨包相等；任何内层字段（ticket、nonce、session key、NTLM proof、AP-REQ tag）**不解码、不断言、不伪造**。本仓库 `cases/spnego.json` 为纯 SPNEGO 空间，与 `#45 ntlm` 仅文档级交叉引用（§11.2 映射表 + 本节行 8 注记），**不写代码依赖**。

### 10.1 八项规范矩阵

| # | 规范要求（RFC 条款+本契约节） | 业务场景 | 代码现状 | 缺口 |
|---|---|---|---|---|
| 1 | 连接模型：SPNEGO 是**非独立协议**——协商 token 寄居载体（HTTP `Negotiate` 认证事务 / 裸 TCP 字节流）；无自有连接、无自有端口；TCP 上 token 边界=DERNegotiationTuple 边界不等于 segment 边界（RFC 4178 §5；RFC 4559 §1/§4.2；RFC 2743 §3.1；本契约 §2/§6） | IIS/AD 域内 HTTP 认证；SMB/445 会话建立协商阶段；企业代理链 | **【P1 期实测基线；P4 已收口→本文 §9.1 v1.5.0 ①】** 未注册：registry/schema/protocols.go 全无 `spnego` 行（实测零命中）；`http` 层已注册（registry.go:101-104，`DependsOn ["tcp"]`+`OptionalOn ["tls"]`+`TransformEvents:true`）；`tcp` 层已注册；占位 1 例 `spnego_neg_unregistered` 仍为旧扁平形（顶层 `src_ip/dst_ip/src_port/dst_port` 四键） | 全量新建：`spnego` 终结层（裁定1：`DependsOn ["tcp"] + OptionalOn ["http"] + TransportOn ["tcp"]`）；双 profile 会话/事务编排；占位随注册移除并按 §2 层链形改写 |
| 2 | 命令消息表：`NegotiationToken ::= CHOICE { negTokenInit [0] NegTokenInit, negTokenResp [1] NegTokenResp }`；`NegTokenInit ::= SEQUENCE { mechTypes [0] MechTypeList, reqFlags [1] ContextFlags OPTIONAL, mechToken [2] OCTET STRING OPTIONAL, mechListMIC [3] OCTET STRING OPTIONAL, ... }`；`NegTokenResp` 字段序 [0..3]（RFC 4178 §4.2/§4.2.1/§4.2.2 与 Appendix A 一致）；旧式 `NegTokenTarg ::= SEQUENCE { negResult [0] ENUMERATED {accept_completed(0), accept_incomplete(1), reject(2)} OPTIONAL, supportedMech [1], responseToken [2], mechListMIC [3] }`（RFC 2478 §3.2.1） | 双机制列表协商；协商进展三态；旧式互操作 | 无 | DER builder（tag+长度短/长形+值）+ 三结构声明式构建；H1 字段序勘误注记（§10.3）随 builder 钉死；命令×进展矩阵见 §10.2 |
| 3 | 状态机：initiator `negTokenInit`（有序 mechTypes）→ acceptor `negTokenResp`（`negState` ∈ {accept-completed(0), accept-incomplete(1), reject(2), request-mic(3)}）；`accept-completed` 前不得进入已验证应用数据；`request-mic` ⇒ initiator 补 `mechListMIC` 续协商（RFC 4178 §4.2.2/§5）；降级防护：`supportedMech` 必须 ∈ initiator 原始 mechTypes（§5 Processing of mechListMIC） | 域认证三步（401 挑战→令牌→200）；协商失败终止 | 无 | 声明式事件序（协商进展状态机）；状态不跨 session 复用；降级/拒接分支见门1 §3 五件套；每状态迁移至少一例（§10.2 逐格） |
| 4 | 字段表：`MechType ::= OBJECT IDENTIFIER`；`MechTypeList ::= SEQUENCE OF MechType`（RFC 4178 Appendix A `DEFINITIONS EXPLICIT TAGS` 模块）；`InitialContextToken` = `[APPLICATION 0] IMPLICIT SEQUENCE { thisMech MechType, innerContextToken ANY DEFINED BY thisMech }`（RFC 2743 §3.1 原文，本机 `rfc2743.txt` 第 4624 行起实测）；SPNEGO 伪机制 OID `1.3.6.1.5.5.2`（RFC 4178 §4.2 注册值）；`negHints` 两字段（**「NegHints」RFC 4178/2478 原文皆无此结构**——`spnego.hintName`(FT_STRING)/`spnego.hintAddress`(FT_BYTES)/`spnego.negHints_element` 三字段在本机 3.6.14 `tshark -G fields` 实测存在，且 §10.7 M-shape-3 实测其可拆解形=NegTokenInit `[3]` 槽内 `SEQUENCE { [0] GeneralString, [1] OCTET STRING }`，与 RFC 4178 把 `[3]` 定义为 `mechListMIC` **冲突**）→ 证据等级=dissector 本地拆解级，RFC 原文级确认=G-SPNEGO-1 | 跨厂商互操作；OID 别名区分；提示名带出 | 无 | DER 编码原语（OID 编码/短长形 length/上下文构造型 definite-length 恒定；`[n]` 全程显式包装=内层带 universal tag，§10.8 裁定2）；OID bytes 实测表+变体全枚举见 §10.3/§10.7 |
| 5 | 错误处理：unknown/changed mechTypes 时 acceptor MUST 回 `reject`；MIC 仅校验机制列表完整性——**不认证对端、不得因 MIC 失败判定凭证被盗**（RFC 4178 §4.2.2/§5）；DER 非法（截断/非最短 length/indefinite/tag class 错/父长度越界）；choice 混用；`supportedMech` 不在列表（降级）；carrier/profiel 错（RFC 4559 §4.2；X.690；本契约 §8） | 服务端拒识；网络损坏；降级攻击；profile 误用 | 无 | 6 负例 + `wire_fault` 值面=§2 键表逐字（`der_truncated`/`der_length`/`choice`/`mech_oid`/`mic`/`carrier`）；自然守卫（DER 长度形非法/tag 不匹配/choice 越界/降级） |
| 6 | 超时活性：SPNEGO 无自有超时/保活/重传语义（RFC 4178 无此章）；保活与空闲复用走载体——HTTP keep-alive（同连接多认证事务）、TCP 连接生命周期（RFC 4559 §4.2；本契约 §6） | 长连接多请求复用；弱网 token 跨 segment 重组 | 无（http 层 keep_alive/transactions 字段已注册可用；tcp 握手/挥手由框架生成） | keep-alive 多事务例（=§3.15 第三项）+ 跨 segment 重组 fixture；超时值走载体现有语义，不自创 SPNEGO 超时字段 |
| 7 | NAT/代理：SPNEGO 无自有 NAT 遍历（与 FTP/媒体协议不同，无 PORT/PASV 类衍生连接）；HTTP `Negotiate` 经代理转发时只影响 HTTP 层语义（绝对 URI/Host），token 字节不变；裸 TCP 无代理语义；NTLM 场景下代理是**信道绑定语义输入**（EPA/CBT），非 SPNEGO 结构（RFC 4559 §1/§4.2；本契约 §6） | 企业代理后的域认证；443 隧道 | 无 | 正例覆盖：明文 HTTP 经代理形（Host/绝对 URI fixture 钉）一例或立项；跨 NAT 无 SPNEGO 语义=不适用（显式声明，不用"待确认"逃逸） |
| 8 | 版本方言：单版本无协商版本号；方言全在机制 OID 面——Kerberos V5 `1.2.840.113554.1.2.2` / Microsoft KRB5 `1.2.840.48018.1.2.2` / NTLM `1.3.6.1.4.1.311.2.2.10`（RFC 4178 §4.2 注册值；msKrb5/NTLM OID 出处=Wireshark dissector 源码值 + **我们的现网行为**（非"已确认"级）——登记待抓包确认 G-SPNEGO-1）；旧式 `negTokenTarg`（RFC 2478）与 `negTokenResp`（RFC 4178 §4.2.2）**字段序/tag 实为同构**（详见 §10.3 H1 勘误）；`mechListMIC` RFC 4559 扩展 `1.3.6.1.4.1.311.2.2.30`（本 RFC 外，外部证据级，同上立项） | 老/新客户端兼容；别名 OID 区分 | 无 | 三 OID 变体例（#8）+ 旧式 targ 兼容例（#7）+ msKrb5 别名与列表别名区分；**跨引用注记**：`#45 ntlm` 的 `outer=spnego`（60-ntlm-design.md:61）是 NTLM 层视角的本协议外层声明，其 ID 9 `ntlm_spnego_outer_separation`（60-ntlm-design.md:219）/ ID 20 `ntlm_neg_carrier_profile`（:203）由 NTLM 车道交付，本协议**不写代码依赖**、不重复覆盖 |

### 10.2 子表①：命令/事件×协商进展矩阵（逐格已覆/缺失）

行=线上事件（initiator→acceptor 方向面），列=acceptor 回复的 `negState` 四值（RFC 4178 §4.2.2 全枚举）+ 无回复面：

| 事件 \ 回复 | accept-completed(0) | accept-incomplete(1) | reject(2) | request-mic(3) | 无回复/中止 |
|---|---|---|---|---|---|
| `negTokenInit`（单 OID） | 已覆 #1/#2/#3/#4（IPv4/IPv6×HTTP/TCP 基线） | 缺口→正例 #12（`accept_incomplete` 后继续） | 正例 #12（合法 reject 终止） | 已覆 #10（request-mic→补 MIC） | 缺口 B′→G-SPNEGO-2（服务端中止面） |
| `negTokenInit`（多 OID 有序列表） | 已覆 #5（mechTypes 序保持） | 缺 → G-SPNEGO-2（多步 incomplete 交织，与 #12/#13 状态面重叠） | 缺口→负例 #19（列表改写/降级选择） | 已覆 #10 | G-SPNEGO-2 |
| `negTokenInit`+`reqFlags`/`negHints`/`mechToken` | 已覆 #5 | 缺口 B′→G-SPNEGO-2 | 缺口 B′→G-SPNEGO-2 | 缺口 B′→G-SPNEGO-2 | G-SPNEGO-2 |
| `negTokenResp`（initiator 侧后续） | 已覆 #6（`supportedMech`+`responseToken`） | G-SPNEGO-2 | G-SPNEGO-2 | 缺口 B′→G-SPNEGO-2（双向 request-mic 不对称面） | G-SPNEGO-2 |
| `negTokenTarg`（RFC 2478 旧式） | 已覆 #7（旧式字段序/tag 不误解析） | G-SPNEGO-2 | G-SPNEGO-2 | 缺口 B′→G-SPNEGO-2（旧式无 request-mic 值，语义边界待确认） | G-SPNEGO-2 |
| `mechListMIC`（验证输入=原始 DER mechTypes） | 已覆 #10 | G-SPNEGO-2 | 已覆 #19（MIC 不匹配拒） | G-SPNEGO-2 | 缺口 B′→G-SPNEGO-2（MIC 后静默中止） |
| 跨 segment/粘连 token（TCP profile） | 已覆 #3/#13 | 缺口→负例 #15（截断）/ #16（粘连/父长越界） | 缺口→负例 #17（choice 混用） | G-SPNEGO-2 | 缺口→负例 #20（stream 边界错） |

注（诚实口径）：矩阵按**结构轴**排（事件形状 × 进展语义），不按"客户端/服务端角色轴"——本引擎两侧皆可生成（声明式回放族，bacnet/dcerpc 同判），角色由事件方向字段表达。**逐格机械重数（v1.3.0 修正 v1.2.0 的"42 格"与"14+6+22"两处算术；本节计数由逐格分类脚本产出，可复核）**：表体 7 行 × 5 列 = **35 格**，三类——**已覆 10 格**（R1c1←#1/#2/#3/#4、R1c4←#10、R2c1←#5、R2c4←#10、R3c1←#5、R4c1←#6、R5c1←#7、R6c1←#10、R6c3←#19、R7c1←#3/#13）；**已覆（缺口→用例通道）6 格**（R1c2/R1c3←#12、R2c3←#19、R7c2←#15/#16、R7c3←#17、R7c5←#20）；**B′ 立项 G-SPNEGO-2 承载 19 格**（R1c5、R2c2/c5、R3c2/c3/c4/c5、R4c2/c3/c4/c5、R5c2/c3/c4/c5、R6c2/c4/c5、R7c4）；R2c4 的 request-mic 与 R4c4 的 initiator 侧 request-mic 分别为已覆（#10）与 B′ 立项（双向不对称）。10 + 6 + 19 = 35，**逐格有结论、无空格**。

### 10.3 子表②：数据形态变体表（协议相关全部形态逐项）

| 变体维度 | 形态 | 对应用例 | 备注 |
|---|---|---|---|
| 地址族×profile | IPv4/HTTP、IPv6/HTTP、IPv4/裸 TCP、IPv6/裸 TCP | #1/#2/#3/#4 | 四格满格（§9.24 对称）：IPv4 `ip.proto=6`、IPv6 `ipv6.nxt=6`，offset 54/74 两档 |
| OID | Kerberos V5（7 arc，域 1.2.840）/ msKrb5（域 1.2.840.48018，**其 arc 48018 需 base-128 双字节展开 `82 F7 12`、与 Kerberos 的 `86 F7 12` 仅首字节差**）/ NTLM（域 1.3.6.1.4.1.311，含 `82 37` 双字节 arc）/ SPNEGO（1.3.6.1.5.5.2，仅外层不进 supportedMech） | #8 | OID DER bytes 逐字节钉；**实测修正（v1.2.0 数字勘误）**：value 长度应为——Kerberos V5 = **9 字节**（`06 09 2A 86 48 86 F7 12 01 02 02`，v1.2.0 误记"7 字节"）、msKrb5 = 9 字节（`06 09 2A 86 48 82 F7 12 01 02 02`）、NTLM = **10 字节**（`06 0A 2B 06 01 04 01 82 37 02 02 0A`）、SPNEGO = 6 字节（`06 06 2B 06 01 05 05 02`）；四值均与 tshark 3.6.14 OID 名库互证（§10.7 附带实测）。v1.0.0 正文"OID 长 arc"变体无 RFC 依据（无 ≥128 的整 arc 面）→ **勘误：删去该变体**，保留单/多 OID 两形 |
| DER length | 短形（<128）/长形（0x81 单字节/0x82 两字节）；父长度覆盖全部子 TLV | #11 | **实测两档（v1.4.0 复校）**：TCP profile 三 OID + 200B mechToken 的 InitialContextToken 总长 **268B**、外层长度字节 `0x82`（长形两字节），内层 NegTokenInit SEQUENCE 长 **129B**（`0x81` 单字节长形）；negTokenResp 小结构（negResult+supportedMech）总长 **32B**、外层 `0x1e`（短形）——短/长两形均有真实 fixture 承载；indefinite/非最短形→负例 #16 |
| NegotiationToken choice | negTokenInit `0xA0` / negTokenResp `0xA1` / negTokenTarg 旧式（同 `0xA1` 选择枝） | #1/#6/#7 | 实测：negTokenInit 外层 `0x60 { OID, 0xA0 … }`、内层 NegTokenInit 以 `0x30` 起（§10.7 M-shape-1/2 实测）；`0xA1` 起者被 dissector 归入 negTokenTarg 模板（resp 面字段 `spnego.negResult`/`supportedMech`/`responseToken` 实测填充）。**v1.2.0 行内"negTokenInit 线首字节 `0xA0 0x03 0xA0 0x01 0x00`（空 mechTypes 占位形）"系误记**——该 5 字节既非合法 NegTokenInit（实测报 `Sequence expected but class:CONTEXT(2) …`），合法空 mechTypes 占位形应为 `A0 02 30 00`（§9 勘误⑦ 复校后正式口径，见勘误⑩；v1.3.0 中间值 `A0 04 30 02 A0 00` 实测 malformed，已作废）；未知 choice→负例 #17 |
| **H1 字段序勘误（v1.0.0 正文误）** | v1.0.0 §3 表"`NegTokenTarg`: `supportedMech [0]`、`responseToken [1]`、`negResult [2]`、`mechListMIC [3]`"**系误记**——RFC 2478 §3.2.1 权威：`negResult [0]`（ENUMERATED，OPTIONAL）、`supportedMech [1]`、`responseToken [2]`、`mechListMIC [3]`，与 RFC 4178 §4.2.2 `NegTokenResp` 字段序**同构**（差异在 ENUMERATED 取值集合：targ 三值/无 request_mic(3)）。三结构 tag 面实为"同形不同 choice" | #7 + §4 行 | 本勘误由 P1 三路对照实证得出（RFC 2478 原文 + 本机 dissector 字段面），v1.1.0 起以本节为准；v1.0.0 §3 原表作废 |
| mechToken/responseToken 外壳 | `[2]` context wrapper 内 OCTET STRING；零长占位/非零两类；跨包重传 | #9 | 实测口径：零长=空包装占位形；重传 same_as_packet；内层 bytes 一律 opaque |
| mechListMIC | RFC 4178 §4.2.1：`[3] OCTET STRING`；request-mic(3) 触发后携带；验证输入=**原始 DER mechTypes**（RFC 4178 §5 原文"the input message is the DER encoding of the value of type MechTypeList … NOT the DER encoding of the type \"[0] MechTypeList\""，Appendix D 补证 `A0 nn` 不计入） | #10 | **dissector 布局冲突（§10.7 M-shape-4 实测）**：本机 tshark 3.6.14 把 NegTokenInit 的 `[3]` 槽按 negHints 拆解、`mechListMIC` 字段只认 `[4]`；RFC 形 `A3{04}` 会报 `BER Error: Sequence expected …` 且 `spnego.mechListMIC` 为空 → 本设计以 RFC 形生成、该字段断言改走 frames hex（裁定2） |
| negHints | `SEQUENCE { hintName [0] GeneralString, hintAddress [1] OCTET STRING }`，两长度独立 | #5 | **证据等级=dissector 拆解级**（RFC 4178/2478 原文无 NegHints 结构，G-SPNEGO-1）：本机实测可拆解形=NegTokenInit `[3]` 槽内 `SEQUENCE { [0] GeneralString, [1] OCTET STRING }`（§10.7 M-shape-3 干净解出 `spnego.hintName`/`spnego.hintAddress`）；`spnego.hintName` FT_STRING / `spnego.hintAddress` FT_BYTES 两字段实证；与 RFC `[3]=mechListMIC` 冲突 ⇒ fixture 二者不可同形共存（裁定2） |
| reqFlags | `[1]` ContextFlags：**ASN.1 定义在 RFC 4178 §4.2.1**（`ContextFlags ::= BIT STRING { delegFlag(0), mutualFlag(1), replayFlag(2), sequenceFlag(3), anonFlag(4), confFlag(5), integFlag(6) } (SIZE (32))`；v1.2.0 误记"RFC 2743 §3.12"——实测原文该节无 ContextFlags 定义，G-勘误见 §9 勘误⑥）；RFC 4178 同时规定"initiator SHOULD omit / acceptor MUST ignore"且 **DER 须截去尾随零位**（不得期待恒 32 位） | #5 | 实测：dissector 按位展开 `spnego.ContextFlags.*` 七布尔（`tshark -G fields` 实测 7 行，§10.7 M-shape-2 位串 `03 02 00 C0` → `spnego.reqFlags=c0` + `delegFlag=1`/`mutualFlag=1`）；本设计只作结构覆盖面（不建行为面，RFC 明示可省略） |
| HTTP carrier | `Authorization: Negotiate <base64>` / `WWW-Authenticate: Negotiate [base64]` + 401 挑战；base64 缺 padding/折行/空 token | #1/#13 | 实测口径：base64 长度 ≠ DER 长度（先 base64 解码再量 DER）；GSSAPI 机制 OID 方进 `Authorization: Negotiate`（RFC 4559 §4.2） |
| HTTP 成功面 | SPNEGO 无自有成功码，RFC 4559 只对 SPNEGO 机制定义 200/401 两侧（客户端可用 HTTP 200 表示成功）；**本设计选"结果显式配置"**（fixture 声明，省 B′ 立项） | #6 | RFC 4559 §4.2 权威；自填"机制定义其他状态码"面=不适用（显式声明，不用"待确认"逃逸） |
| TCP 形态 | 分段/合并/粘连双 token/跨 stream 不拼接 | #3/#11/#13 | 无私有长度前缀（不把本地 framing 伪装 SPNEGO 字段）；重组按 DER 父长度 |
| 版本方言 | 三机制 OID 别名 + 旧式 targ + 无版本号单版本 | #7/#8 | 单版本=不适用（无版本协商字段）；方言全在 OID/结构面 |
| **dissector 形 vs RFC 形（v1.3.0 新增实测行）** | NegTokenInit `[3]` 槽二义：RFC=`mechListMIC`(OCTET STRING) / dissector=`negHints`(SEQUENCE)；`mechListMIC` 在 dissector 侧住 `[4]` | 裁定2（§10.8）+ #5/#10 断言通道 | 两形不可同包共存；本设计默认 RFC 形，dissector 形登记为 P4 可选 fixture 变体（A′） |
| **断言通道（v1.3.0 新增实测行；v1.4.0 勘正）** | HTTP carrier：`http → gss-api → spnego`（实测 `-V` Protocols in frame 原文 `eth:ethertype:ip:tcp:http:gss-api:spnego`，无需 decode_as）；裸 TCP carrier：无 decode_as 目标（实测 `tshark -d tcp.port==445,gss-api`/`,spnego` 均被拒，合法 tcp.port decode_as 目标实测 **317** 个里只有 `ber` 与 `kerberos`） | #1/#2（HTTP）+ #3/#4/#14（裸 TCP 走 frames hex） | **decode_as 对 spnego 用例是负收益**：实测加 `-d tcp.port==80,ber` 会把协议栈压成 `ber` 单层、`spnego.*` 字段全空 ⇒ 用例不得声明 decode_as（§10.7 M-shape-5）。**勘正**：裸 TCP carrier 的 `tshark -V` 实测**没有** `OID: 1.3.6.1.5.5.2` 行（445 栈止于 `nbss` 的 `Continuation data:` 原始 hex；随机高端口栈止于 `tcp`）⇒ 裸 TCP 的唯一结构证据=该原始 hex 本身（即 frames hex + offset） |
### 10.4 P1 三路对照与候选方案对比（CORE_MEMORY §4.12–4.18）

**①规范原文**（本机 RFC 原文实测行号，v1.4.0 补）：RFC 4178（§4.2 CHOICE/InitialContextToken 与 SPNEGO OID 1.3.6.1.5.5.2（`rfc4178.txt:384`）；§4.2.1 NegTokenInit + **ContextFlags 位定义**（`rfc4178.txt:408/415-422`）；§4.2.2 NegTokenResp negState 四值（`rfc4178.txt:470-482`）；§5 mechListMIC 处理与降级防护（输入消息口径 `rfc4178.txt:571-574`）；Appendix A 模块 `DEFINITIONS EXPLICIT TAGS`（`rfc4178.txt:852`））、RFC 2743（§3.1 InitialContextToken 语法=本设计 APPLICATION 0 外层依据，`rfc2743.txt:4624-4634`；**该 RFC 无 ContextFlags 定义**，全文 `grep ContextFlags` 零命中）、RFC 4121（Kerberos GSS-API 机制——**仅作 opaque 边界参考，不实现其 token 结构**）、RFC 2478（§3.2.1 NegTokenTarg 旧式，互操作；`rfc2478.txt:413-421`）、RFC 4559（§1/§4.1 `WWW-Authenticate`/§4.2 `Authorization` + 2xx/401 语义；原文 `rfc4559.txt:155-157`（重试语义）/`:178-181`（非 2xx=认证错误））、X.690（DER definite-length/最短形/字节序；**X.690 是设计决策级参考，非用例级依据——无本协议专属编码断言用例**）。

**②现网行为**（Windows/AD + Samba/impacket 抓包形态）：IIS/AD 域内 HTTP：匿名请求→`401 WWW-Authenticate: Negotiate`→客户端 `Authorization: Negotiate <base64(InitialContextToken+negTokenInit)>`→服务端 `WWW-Authenticate: Negotiate <base64(negTokenResp)>`→200（或 `accept-incomplete` 续一轮）；SMB/445：Session Setup 内嵌 SPNEGO（`negTokenInit` → `negTokenResp`+NTLMSSP 或 Kerberos AP-REQ）——**SPNEGO 作为 SMB2 内部结构而非独立协议**；Samba 客户端 `negprot` 面同形；impacket `smbclient.py`/`spnego.py` 构 OID 列表首项恒 Kerberos V5、次项 msKrb5。出处确认方式：本机回环抓 `curl --negotiate -u : http://127.0.0.1:8080/` 或无域环境退化用 impacket 脚本抓回环包核对（**立项 G-SPNEGO-1**：三 OID 别名/NegHints 结构/RFC 4559 扩展 OID `1.3.6.1.4.1.311.2.2.30` 的"已确认现网"级证据）。

**③开源实现思路**：wireshark `epan/dissectors/packet-spnego.c`（本机 tshark 3.6.14 实测 `spnego.*` 字段 **41** 个，精确口径 `tshark -G fields | awk -F'\t' '$3 ~ /^spnego\./' | wc -l` = 41；同命令 `grep -c spnego` = 43 = 41 + 2 个协议行（`P\tSimple Protected Negotiation\tspnego`、`P\tSPNEGO-KRB5\tspnego-krb5`）——v1.2.0 记的 38 是默认空白分隔 `awk '{print $3}'` 把 3 个含空格 label 的行错列所致（§9 勘误⑥）。字段面：`negTokenInit_element`/`negTokenTarg_element`/`mechTypes`/`MechType`/`supportedMech`/`negResult`/`mechToken`/`responseToken`/`mechListMIC`/`reqFlags`/`negHints_element`/`hintName`/`hintAddress`/`thisMech`/`innerContextToken_element` + `ContextFlags.*` 七布尔 + `spnego.krb5.*` 16 项 wrap token 子面（`blob`/`krb5_oid`/`tok_id`/`sgn_alg`/`seal_alg`/`snd_seq`/`sgn_cksum`/`confounder`/`filler`/`cfx_flags`/`send_by_acceptor`/`sealed`/`acceptor_subkey`/`cfx_ec`/`cfx_rrc`/`cfx_seq`）+ `wraptoken`/`decrypted_keytype`/`unknown_header`；**实测差异（记录在案）**：dissector 无 `spnego.negTokenResp_element`（`[1]` 选择枝与 negTokenTarg 共用一套 ASN.1 拆解模板，实测协议栈里显示为 `spnego`/`spnego-krb5`，`-T fields` 里 resp 面落在 `spnego.negTokenTarg_element` 与 `spnego.negResult`）；`spnego.negResult` 字段名沿用 RFC 2478 词、RFC 4178 §4.2.2 正名为 `negState`）；只借鉴字段语义与拆解思路，不搬码；另有 IANA GSS-API 机制 OID 注册表（Kerberos V5/msKrb5/NTLM 三值出处，§10.7 表已逐字节实测比对 tshark 自带的 OID 名库）。

**三路结论一致性**：三路在"CHOICE 两层结构（外层 `0x60` InitialContextToken + 内层 `[0]/[1]` choice）、negState 四值、MIC 只保列表完整性、HTTP 双 header 语义"四点完全一致。取舍：①**内层机制 token 三路皆不可断言**（无解密证据）→ 本设计全线 opaque；②现网 SMB/445 嵌入形**不进本协议契约**（SPNEGO 有 SMB 兄弟载体但本设计只声明 HTTP 与裸 TCP 两 profile；SMB 载体由 `#45 ntlm` 的 `outer=spnego` 面表达，文档级交叉引用）——若 P4 后要加 SMB carrier 须另开 D-条目修订；③`NegHints`/`mechListMIC` 扩展 OID 两处证据未到"RFC 原文"级 → 按 §5.5 标"待确认"+ 确认方式（G-SPNEGO-1），不写死混入实现。

### 10.5 候选方案对比（§4.17）

| 方案 | 走法（含借鉴来源） | 优 | 劣 | 性能/复杂度/兼容性 | 结论 |
|---|---|---|---|---|---|
| A 结构化声明式回放 | mechTypes/negState/supportedMech/MIC 外层结构化 + 内层 token opaque fixture（kerberos #44 D-KERBEROS-1 同族：外壳结构化+密文 opaque） | 与已收官族同构（接线/builder/planner/casegen 范式可复用）；不外泄机制内层语义 | 服务端主动态需 B′ 立项（G-SPNEGO-2） | O(n) 流式渲染；复杂度低；三 OID 与旧式 targ 兼容 | **采用** |
| B 完整 ASN.1 编译器 | 通用 DER schema 驱动编解码（借鉴 openssl asn1t 思路） | 通用性强 | 超 fixture 范围；内层本就不可断言；编译器复杂度 | 复杂度高；无 fixture 收益 | 不选 |
| C 生 hex 回放 | 整 token hex 覆盖（kerberos `events[].body` 逃生口同款） | 最简单 | 字段不可结构化断言；动态面全失；OID 变体即死 | 动态零分 | 仅作负例/特殊形逃生口，不做主方案 |

### 10.6 裁定1：双 profile 依赖建模——`DependsOn ["tcp"] + OptionalOn ["http"] + TransportOn ["tcp"]`

**先证（`trafficgen/internal/core/layers/registry.go` 实测）**：
- **全仓库无 `DependsOn` 双值先例**：实测 `grep -c 'DependsOn: *\[\]string{"[^"]*", "'` = **0**；双载体家族（dns registry.go:135-137、nfs registry.go:1000、megaco registry.go:662、kerberos registry.go:769-771、someip registry.go:611）全是 `DependsOn` 单值（默认载体）+ `TransportOn` 双值。
- **`TransportOn` 全是 L4**：实测 `grep -c 'TransportOn:.*http'` = **0**——`http` 是终端/变换层，从未进过 `TransportOn`。本设计据此**只放 L4 值**（`["tcp"]`）。
- http 族先例：http_flv registry.go:464-465 `DependsOn ["http"]`、mmse registry.go:708-711 同款——补全恒供给 http+tcp，**缺 http 链不可达**；只适用纯 HTTP 形态，不适用本协议双 profile。
- 双载体覆盖机制先例：`TransportOn` 注释（registry.go:136"用户显式写 tcp 层覆盖（补全时替代）"）+ 链载体↔配置 profile 结构性一致校验（nfs/kerberos 同款）。
- `OptionalOn` 语义（schema.go:93-96）：可选底座，**系统永不自动插入，只有用户显式写才启用**（http 层 `OptionalOn ["tls"]` registry.go:103 同款)——正是"HTTP profile 默认关闭、写了才有"所需。

**OptionalOn 可达性证据（v1.4.0 复校；框架提交 `0c355be` 已修）**：`complete.go` 的终结层底座判定 `dependedOn`（`complete.go:412-425`）现同时认 `DependsOn` 与 `OptionalOn`（`complete.go:418` 原文 `(contains(s.DependsOn, name) || contains(s.OptionalOn, name))`，注释 `complete.go:406-411` 逐字点名"@ocsp-spnego-ntlm 双 profile：X 声明 DependsOn ["tcp"]+OptionalOn ["http"] 时，显式写了 http 的链 [ip,tcp,http,X] 中 http 是 X 的底座而非第二个终结层"）。**结论：`[ip,tcp,http,spnego]` 今日可达**——`http` 被计为 `spnego` 的可选底座，不再触发 `layers: terminal layer "http" duplicated`。直接实证（可复跑）：

```bash
cd trafficgen && go test ./internal/core/layers/ -run TestValidateChain_OptionalOnBaseSatisfiesTerminalExemption -count=1   # ok
cd trafficgen && go test ./internal/core/layers/ -count=1                                                                  # ok（12.5s 全量）
```

红例/反例（`internal/core/layers/optional_on_chain_test.go:21`/`:44`）：正例构造 `xproto`（`DependsOn ["tcp"]` + `OptionalOn ["http"]`）链 `[ip,tcp,http,xproto]` 断言 `CompleteChain` 合法且链形 `ip → tcp → http → xproto`；反例 `yproto`（无 `OptionalOn`）挂 `http` 之后仍判 duplicated——**T18 的 `[ip,tcp,http,dns]` 判死语义未被放宽**。存量零影响（提交说明逐字）：现有 `OptionalOn` 值只有 `tls`/`eth`，且 `tls` 是 `CategoryTunnel`（非终结层）、`eth` 是 L2——无终结层声明 `http` 先例，故判定不变。

**与本协议的关系**：裁定1 A 方案（`OptionalOn ["http"]`）**不再需要框架扩展**，`§11` 门1 §5/§13 行、§12 接线件按本证据写"今日可达"；`[ip,tcp,http,spnego]` 与 `[ip,tcp,spnego]` 双 profile 均可达，零新机制。**跨引用注记**：兄弟车道 `60-ntlm-design.md:353`/`:497`（G-NTLM-2）与 `62-ocsp-design.md` 记的"`OptionalOn` 不参与 V2 豁免 → `[ip,tcp,http,X]` 判死"结论**已被 `0c355be` 作废**（该结论在提交前为真）；本契约按修后实测收口，兄弟契约的同一问题由各自车道更新。

**二选一结论**：
- **A（采用）** `DependsOn ["tcp"] + OptionalOn ["http"] + TransportOn ["tcp"]`：裸 TCP profile 默认可达（`[ip,tcp,spnego]`）；HTTP profile 用户显式写 `http` 层即启用（`[ip,tcp,http,spnego]`，§2 样例；**可达性证据见上段**）；profile↔http 层有无一致性由 planner 结构性校验（http profile 要求 http 层在链、tcp profile 要求不在），不一致同步拒。**零新机制**。
- B（不选） `DependsOn ["http"]` 默认 + 裸 TCP 例外放行：已有范式先证 http_flv/mmse `DependsOn ["http"]` 使无 http 链天然不可达，B 须为引擎开"缺依赖放行"新机制，全仓库无先例。

**为何不写 `DependsOn ["udp"]`（误写检查）**：SPNEGO 无 UDP carrier（RFC 4178 无 UDP 语义；现网亦无）——`DependsOn`/`TransportOn` 只出现 `tcp` 值，**udp 零值**（区别于 kerberos 的 udp+tcp 双载体；§12 把此列成守卫）。

**TransportOn 纯 L4 声明**：`TransportOn ["tcp"]` 单值；`http` 走 `OptionalOn` 不进 `TransportOn`（实测 0 先例，理由如上）。本契约 §2 键表、门1 §5/§13 行、§12 接线件均引用本裁定。

### 10.7 dissector（解析器）编码模板实测矩阵（第③路深挖；P4 builder 硬约束；2026-09-25 本机 tshark 3.6.14 实测）

方法（可复现）：Python 以 DER 手工构造候选 wire，经 `text2pcap -T 80,45062 -4 198.51.100.61,192.0.2.61 -q - -`（或 `-T 45061,445`）打单元帧，`tshark -r - -T fields -e spnego.*` + `tshark -r - -V`（含 Malformed 专家信息）逐形读回；HTTP carrier 用 `WWW-Authenticate: Negotiate <b64>`（response，server→client）与 `Authorization: Negotiate <b64>`（request，client→server）两方向各验一次。

| # | wire 形（构造） | tshark 读回 | 裁定 |
|---|---|---|---|
| M-shape-1 | `0x60 { OID(S), A0 { 30 { A0{30{OIDs}}, A1{03 02 00 C0}, A2{04 token} } } }`（NegTokenInit 全字段：mechTypes/reqFlags/mechToken，`[n]` 各带内层 universal tag；**`mechTypes` 的 `[0]` 只包一层，其内容即 `SEQUENCE OF OID` 本体**——v1.3.0 原记 `A0{30{A0{30{OIDs}}}}` 多套一层，实测 malformed，§9 勘误⑨） | **干净**；协议栈 `http:gss-api:spnego`；`spnego.negTokenInit_element`=1、`spnego.mechTypes`=3、`spnego.MechType`=三个 OID 文本（逗号连接）、`spnego.reqFlags`=c0、`spnego.ContextFlags.delegFlag`/`mutualFlag`=1/1、`spnego.mechToken`=hex 逐字节等同 | **采用**：P4 builder 的 wire shape（裁定2 ①）；单 OID 形实测读回 `mechTypes=1` + `MechType=1.2.840.113554.1.2.2` + `reqFlags=c0` + `mechToken=deadbeef`，malformed=0 |
| M-shape-2 | 同上但 `reqFlags` 位串写成 `A1{30{03 02 00 C0}}`（多一层 SEQUENCE） | Malformed：`BER Error: BitString expected but class:UNIVERSAL(0) Constructed tag:16 was unexpected` | 反证：`[n]` 必须是**显式包装 + 内层 universal tag 原样**，不得再套 SEQUENCE |
| M-shape-3 | `negHints` 放 NegTokenInit `[3]`：`A3 { 30 { A0{1B hintName}, A1{04 hintAddress} } }`（`hintName`=`hint.example`，`hintAddress`=`C0000201`） | **干净**；`spnego.negHints_element`=1、`spnego.hintName`=`hint.example`、`spnego.hintAddress`=`c0000201`，malformed=0 | **冲突记录**：dissector 把 `[3]` 当 negHints；RFC 4178 §4.2.1 该位是 mechListMIC ⇒ 两形互斥（裁定2 ②） |
| M-shape-4 | RFC 形 `mechListMIC`：`A3 { 04 MIC… }`（§4.2.1 直译） | Malformed：`BER Error: Sequence expected but class:UNIVERSAL(0) Primitive tag:4 was unexpected`；`spnego.mechListMIC` **空**。而把同一 OCTET STRING 放 `A4 { 04 … }` 时 `spnego.mechListMIC` 填充、无 Malformed | dissector 的 `mechListMIC` 槽是 `[4]`（RFC 未定义）⇒ RFC 形生成的包在 tshark 侧该字段不可断言 → 断言走 frames hex（裁定2 ③） |
| M-shape-5 | 断言通道口径：HTTP carrier 默认 / 裸 TCP carrier（dst 445 与随机高端口）默认 / 加 `-d tcp.port==…,ber` / 试 `-d tcp.port==445,gss-api` 与 `,spnego` | HTTP carrier：栈 `eth:ethertype:ip:tcp:http:gss-api:spnego`（`-V` 的 Protocols in frame 原文；resp 面另可跟出 `spnego-krb5` 子拆解）；裸 TCP 445：栈 `eth:ethertype:ip:tcp:nbss`，**无 `spnego.*` 字段、无 Malformed、`-V` 里也没有 `OID: 1.3.6.1.5.5.2` 行**（只有 nbss `Continuation data:` 原始 hex）；裸 TCP 随机高端口：栈止于 `tcp`、payload 无任何 dissect；`-d …,ber`：栈被压成单层 `ber`、`spnego.*` 全空（**decode_as 是负收益**）；`gss-api`/`spnego` 不在 tcp.port 的合法 decode_as 目标内（实测 **317** 个合法目标，报错原文 \"Protocol \\\"spnego\\\" isn't valid for layer type \\\"tcp.port\\\"\"） | **采用**：HTTP carrier 走字段通道；裸 TCP carrier 走 frames hex；**全用例禁用 `decode_as`**（裁定2 ④） |

**附带实测（同批，写入 §4 OID 表依据）**：四个 OID 的 DER 逐字节与 tshark 自带 OID 名库互证——`1.3.6.1.5.5.2`=`06 06 2B 06 01 05 05 02`；`1.2.840.113554.1.2.2`=`06 09 2A 86 48 86 F7 12 01 02 02`（tshark 名 \"KRB5 - Kerberos 5\"）；`1.2.840.48018.1.2.2`=`06 09 2A 86 48 82 F7 12 01 02 02`（\"MS KRB5 - Microsoft Kerberos 5\"）；`1.3.6.1.4.1.311.2.2.10`=`06 0A 2B 06 01 04 01 82 37 02 02 0A`（\"NTLMSSP - Microsoft NTLM Security Support Provider\"）。四个值的**首弧对编码**（`40*X+Y`）与 base-128 变长弧均逐一核对。

### 10.8 裁定2：wire shape 与 `mechListMIC`/`negHints` 双形互斥

**先证**（§10.7 五形实测）：①`[n]` 显式包装 + 内层 universal tag 是 tshark 干净拆解的唯一形；②`[3]` 槽在 dissector 侧是 negHints、在 RFC 4178 §4.2.1 是 mechListMIC，`mechListMIC` 的 dissector 槽是 `[4]`；③HTTP carrier 自动可达 spnego 拆解、裸 TCP carrier 不可达（字段与 `-V` OID 行皆无），`decode_as` 只会压栈。

**二选一**：
- **A（采用）单 wire 真相 = RFC 形**：builder 一律产出 RFC 4178 形（`[3]`=mechListMIC(OCTET STRING)）；`negHints` 作为**可选 fixture 变体**由显式开关启用（启用时该消息不携带 RFC 形 MIC，二者互斥，planner 拒绝同消息同时声明）；断言通道按 carrier 分流（HTTP=字段，裸 TCP=frames hex）。代价：#10 的 MIC 字节只能 hex 断言（字段通道对 RFC 形天然不可用）；收益：线上真相唯一、与 RFC 4178 §4.2.1/§5 及 IANA 注册一致，不产出 RFC 外结构。
- B（不选）dissector 形为出厂默认（`[4]`=MIC、`[3]`=negHints）：tshark 字段面好看，但线上 token 含 RFC 未定义标签位，跨厂商互操作面失真——与 §10.4 取舍①（RFC 为准）冲突。

**结论**：采用 A。`neg_hints.carry ∈ {none(默认), dissector}` 与 `mech_list_mic.layout ∈ {rfc4178(默认)}` 进 D-SPNEGO-1 数据结构（§12）；用例侧 #5 覆盖 `dissector` 形（断言 `spnego.hintName`/`hintAddress`），#10 覆盖 RFC 形（frames hex 断言 MIC 字节与父长度），两例互斥形各自独立、不得同包共存。


## 11. 门1 §1–§14 十四行对照表（CORE_MEMORY §15.1–15.3）

| § | 本协议怎么满足 | 证据 |
|---|---|---|
| §1 层链唯一真相 | 见 §11.1 强制展开：旧键 `src_ip/dst_ip/src_port/dst_port` 四键迁入 `ip`/`tcp` 层；`spnego` 顶层子映射迁入 `layers[]` spnego 条目；数量走 `flow_control`；目标形状 spec_json 样例见 §11.1；占位 `cases/spnego.json`（当前旧扁平形 `layers`+无 ip/tcp 内地址 + 顶层四键）随注册改写；非负例顶层键=0（presence 负例见 §11-P2） | 本契约 §2（目标形状）+ §11.1 样例；占位实测 `topkeys=['dst_ip','dst_port','layers','src_ip','src_port']` |
| §2 策略/任务 | 策略=单 SPNEGO 流量模板（自带 `flow_control` flows/bps/time）；任务=多策略合跑+总量封顶；框架语义未动 | 本契约 §1/§12 |
| §3 五件套 | 见 §11.3 强制展开：双 profile 会话表/事务序列/关联关系/插入位置/时间线；**无长连接豁免**（SPNEGO 无自有连接，多事务与 keep-alive 全在载体面） | 本契约 §11.3 + 用例 #13 |
| §4 查规范 | RFC 4178（§4.2/§4.2.1/§4.2.2/§5/Appendix A/Appendix D，本机 RFC 原文实测）+ RFC 2743 §3.1（InitialContextToken 原文）+ RFC 4121（opaque 边界参考）+ RFC 2478 §3.2.1 + RFC 4559 §1/§4.2 + X.690 + 现网（Windows/AD HTTP 401→Authorization：Negotiate 两轮、Samba/impacket OID 列表）+ tshark `spnego.*` **41** 字段实测 + §10.7 dissector 编码模板实测矩阵；P1 矩阵 8 行+三子表（§10.1–§10.3）+ 三路对照（§10.4）+ 裁定1/裁定2（§10.6/§10.8） | 本契约 §10 |
| §5 依赖与错误 | §10.6 裁定1：`DependsOn ["tcp"] + OptionalOn ["http"] + TransportOn ["tcp"]`（无 DependsOn 双值先例实测=0；TransportOn 无 http 先例实测=0；**OptionalOn 可达性证据见 §10.6 中段——框架 `0c355be` 后 `[ip,tcp,http,spnego]` 今日可达，`go test ./internal/core/layers/ -run TestValidateChain_OptionalOnBaseSatisfiesTerminalExemption -count=1` 实测 ok**）；`wire_fault` 6 值=§2 键表逐字（`der_truncated`/`der_length`/`choice`/`mech_oid`/`mic`/`carrier`）+ 自然守卫 + profile↔http 层有无结构性校验；失败返回 task error（零假成功） | 本契约 §2/§8 + §12 错误分支 |
| §6 性能 | 声明式回放族：O(n) 流式渲染无全量聚合；pcap/NIC 双路验收；吞吐/并发/内存目标待 P4 基准后定（§6.5 诚实待确认，不写承诺数字）；六类场景清单见 §12 | §12 性能设计与验收 |
| §7 三份文档 | 61-spnego-design.md v1.4.0 + 61-spnego-testcase.md v1.2.0（ID 权威=testcase §2）+ D-SPNEGO-1（本契约 §12 草稿，门1 获批=定稿）+ T-SPNEGO（testcase §8 草稿）+ generated schema（P4 重跑） | 修订记录 |
| §8 设计先行 | 本条目 P1–P3 先于 P4 实现；门1 获批=D-SPNEGO-1 定稿=开工门 | 提交序 |
| §9 测试三源 | 三源=RFC 条款（§4 行列示各条+节号，逐条原文实测）+ D-SPNEGO-1 + tshark `spnego.*` **41** 字段已实证（精确口径 `tshark -G fields \| awk -F'\t' '$3 ~ /^spnego\./' \| wc -l`；`grep -c spnego`=43 含 2 协议行）+ §10.7 模板实测（两形不可共存、decode_as 负收益）+ 现网 Windows/AD 形态（未确认级→G-SPNEGO-1）；20 ID 正负对账 | T-SPNEGO（testcase §8） |
| §10 评审闭环 | 每阶段对抗自重审（结论见 p123 报告）+ 收官隔离复审 + 修轮；红先绿后 | /tmp/pipe/47-spnego/p123-report.md |
| §11 白话 | 每阶段白话一句先行 | 汇报 |
| §12 动态清单 | 见 §11.12 强制展开：四元组=ip/tcp 层（五策略全支持）；业务字段逐个列开/不开+理由；序号算法位置诚实"待 P4 定"（不编行号，§5.7） | 本契约 §11.12 |
| §13 schema 派生 | registry spnego 行（§10.6 裁定1；FieldContract `tcp.dst_port`=445 单值=裸 TCP 档缺省，HTTP 档 80 由 http 层 FieldContract 供给；两档 fixture 显式写端口时均不生效）→ schemagen 重跑；struct 标签字面量锁 | §12 接线件 |
| §14 真实流程 | suite 经 MCP 建任务→引擎生成→tshark `spnego.*` 字段 + frames hex 双通道；先跑后钉；pcap 落 `/tmp/mcp-pcaps/spnego/` | 用例 §1/§6 |

### 11.1 §1 强制展开：旧键去向 + 完整 spec_json 样例

旧键清单（`src_ip`/`dst_ip`/`src_port`/`dst_port`/`count` + 本协议顶层子映射 `spnego`）：

| 旧键 | 去向 |
|---|---|
| `src_ip` | → `layers[i].ip.src`（`192.0.2.61`） |
| `dst_ip` | → `layers[i].ip.dst`（`198.51.100.61`） |
| `src_port` | → `layers[i].tcp.src_port`（`45061`，裸 TCP profile；HTTP profile `45062`） |
| `dst_port` | → `layers[i].tcp.dst_port`（裸 TCP profile 用 `445`——**445 是 SMB/SPNEGO 惯用端口，本协议裸 TCP fixture 沿用**；HTTP profile 用 `80`——tshark `http` dissector 自动解码依赖） |
| `count`（若有） | → 删除，走 `flow_control.flows` |
| 顶层 `spnego` 子映射 | → `layers[]` 中 `{"spnego": {...}}` 条目（业务键全量迁入，零残留） |

**存量占位 `spnego_neg_unregistered` 去扁平改写清单（逐键；P1/P2 期口径，P4 注册时已按此执行并整体移除占位——现 `cases/spnego.json` 为 20 语义例，§9.1 v1.5.0 ②）**：实测当前 `spec_json` 顶层键 = `['dst_ip','dst_port','layers','src_ip','src_port']`，`layers` = `[{"tcp":{}},{"spnego":{}}]`（**无 `ip` 层**——旧扁平形把地址放在顶层）。逐键去向：

| 现状 | 去向（注册时改写） |
|---|---|
| 顶层 `src_ip`=`192.0.2.61` / `dst_ip`=`198.51.100.61` | 删除顶层键；新增 `{"ip": {"src": "192.0.2.61", "dst": "198.51.100.61"}}` 作为 `layers[0]`（补 `ip` 层是本次改写的**结构性新增**，非仅挪值） |
| 顶层 `src_port`=`45061` / `dst_port`=`445` | 删除顶层键；写进既有 `layers[1].tcp` 条目（`{"tcp": {"src_port": 45061, "dst_port": 445}}`） |
| 顶层 `layers` 内 `{"spnego":{}}` 空条目 | 按 §2/§11.1 样例填 `profile`/`negotiation`/`mech_types`/`mech_token` 等业务键（或随占位整体移除，由 20 个语义用例替代——`spnego_neg_unregistered` 本身**不计入 20 ID**，注册后删除） |
| `count` | 本占位无此键；若任何存量例有，→ 删除并走 `flow_control.flows` |

改写后必须满足：非负例顶层键 = 0（仅 `layers`/`flow_control`/`output` 家族）；`expect` 键集合为 `{expect_error, error_contains}` 或正例的字段断言集。

完整裸 TCP 样例（目标形状，顶层键仅 `layers`+`flow_control`；v1.0.0 §2 的 `[ip,tcp,spnego]`+顶层四键混用形已作废）：

```json
{
  "layers": [
    {"ip": {"src": "192.0.2.61", "dst": "198.51.100.61"}},
    {"tcp": {"src_port": 45061, "dst_port": 445}},
    {"spnego": {
      "profile": "tcp",
      "negotiation": "init_resp",
      "mech_types": ["1.2.840.113554.1.2.2", "1.2.840.48018.1.2.2", "1.3.6.1.4.1.311.2.2.10"],
      "mech_token": {"opaque": true},
      "mech_list_mic": {"opaque": true}
    }}
  ],
  "flow_control": {"flows": 1}
}
```

HTTP profile 样例（`http` 层显式写才启用，§10.6 裁定1）：

```json
{
  "layers": [
    {"ip": {"src": "192.0.2.61", "dst": "198.51.100.61"}},
    {"tcp": {"src_port": 45062, "dst_port": 80}},
    {"http": {"method": "GET", "uri": "/", "keep_alive": true}},
    {"spnego": {
      "profile": "http",
      "negotiation": "init_resp",
      "mech_types": ["1.2.840.113554.1.2.2", "1.2.840.48018.1.2.2"],
      "mech_token": {"opaque": true}
    }}
  ],
  "flow_control": {"flows": 1}
}
```

### 11.2 子表③：商业行为→用例映射表（CORE_MEMORY §4.16；缺此表按 §4.22 记缺口）

| # | 商业行为（产品+行为） | 出处 | 对应用例 | 状态 |
|---|---|---|---|---|
| 1 | IIS/AD 域内 HTTP：匿名请求 → `401 WWW-Authenticate: Negotiate` → 客户端 `Authorization: Negotiate <b64>` → 服务端 `WWW-Authenticate: Negotiate <b64>` → 200 | 现网通用形态（RFC 4559 §4.2 原文与之同构："Upon receipt of the response containing a \"WWW-Authenticate\" header … the client is expected to retry the HTTP request, passing a HTTP \"Authorization\" header line."） | #1（IPv4 全链）/ #2（IPv6）/ #6（resp 结构）/ #13（keep-alive 多事务） | 已映射；**现网抓包级确认** → G-SPNEGO-1（确认方式已写清：回环抓包） |
| 2 | Windows 域内 SMB2/445 Session Setup（SPNEGO 内嵌 security blob；Kerberos 优先、NTLM 兜底） | 现网通用形态 | **不进本契约**（本设计只声明 HTTP 与裸 TCP 两 profile）：由 `#45 ntlm` 的 `outer=spnego` 面表达（`60-ntlm-design.md:61` 字段行 / `:203` ID 20 / `:219` ID 9） | 明确不支持（显式声明，不用"待确认"逃逸）；文档级交叉引用，不写代码依赖 |
| 3 | Samba 客户端 `negprot`/session setup 同形（含 `--negotiate` 类客户端） | 现网通用形态 | 同 #2 处置；OID 列表序（Kerberos 优先）由 #8 覆盖 | 明确不支持（载体面同上） |
| 4 | impacket `smbclient.py`/`spnego.py`：OID 列表首项 Kerberos V5、次项 msKrb5 | 开源实现（impacket，出处=其 spnego/smb 模块常量） | #8（三 OID 变体与列表序） | 已映射；抓包核对 → G-SPNEGO-1 |
| 5 | Linux `curl --negotiate -u :` 对 HTTP 服务 | 现网通用形态 | #1（HTTP carrier 两方向）+ #3/#4（裸 TCP 形另测） | 已映射；`Negotiate` 头 base64 与 DER 关系由 #1 断言 |
| 6 | 遗留客户端走 RFC 2478 旧式 `negTokenTarg`（Windows/Legacy 互操作） | RFC 2478 §3.2.1（原文实测） | #7（旧式字段序/tag 不误解析） | 已映射 |
| 7 | 企业代理链（HTTP 代理转发 `Negotiate`、绝对 URI/Host 语义） | 现网形态 | #1 的 fixture 形可承载，但**代理专属形（绝对 URI + 407 `Proxy-Authenticate`）** | 缺口立项 G-SPNEGO-2（B′，迁入计划=确认后进 §10.2 空白格） |
| 8 | EPA/CBT（NTLM over SPNEGO 的信道绑定扩展） | 现网形态（Windows 扩展） | 不适用：属**机制内层语义**（NTLM 层），本设计内层一律 opaque（裁定5） | 明确不支持（显式声明） |

注：本表 8 行的"出处"列严格按 §4.13 三选一（官方文档/抓包/管理面）标注；凡记"现网通用形态"但未落抓包证据的，一律挂 G-SPNEGO-1 且不写死进实现（§5.5）。


### 11.3 §3 强制展开：五件套（双 profile）

会话表：

| 会话 | profile | 四元组 | 生命周期 |
|---|---|---|---|
| s1 | http | `ip.src/dst` + `tcp.45062→80` | TCP 握手 → 匿名请求 → 401 `WWW-Authenticate: Negotiate` → `Authorization: Negotiate`(init) → `WWW-Authenticate: Negotiate`(resp) → 200 → 挥手 |
| s2 | tcp（裸） | `tcp.45061→445` | 建连 → DER stream 发 init → resp → （可选 MIC 续） → 挥手 |

**交付口径（v1.5.0，C2 订正）**：#13 落盘形状 = **两条裸 TCP stream（`flow_control.flows=2` + `tcp.src_port` 动态对象，45061/45062→445）× 每流 s1/s2 两会话**（s1=配置级候选 [krb5, msKrb5]→`accept_completed(0)`；s2=会话级覆盖 NTLM→`reject(2)` 异常终止），单流 11 包 × 2 = **22 包**。上表 s1(http)/s2(裸 TCP) 的"同一用例内双载体并行"**不可表达**——引擎约束 one strategy = one chain（`planner.go:36-43` 明确拒会话端点覆盖），故双载体覆盖改由**跨用例**承担：#1/#2（HTTP profile）、#3/#4（裸 TCP profile）；本表 s1/s2 的双 profile 语义在实现中体现为**同一 spnego 层配置对两载体的可用性**，非同一 fixture 内并存。P6 审打回项 C1/C2 的处置与证据见 `/tmp/pipe/47-spnego/p6-fix-report.md`。

事务序列（`init_resp` 双消息 + 可选 MIC 第三消息；单事务四件事 §3.4–3.7）：

| 事务 | 前置条件 | 触发动作 | 成功分支 | 失败分支 |
|---|---|---|---|---|
| t1 init | s1 建连 + 401 挑战已收 | 发 `negTokenInit`（有序 mechTypes/reqFlags/negHints/mechToken） | acceptor 回 `negTokenResp`（`negState`∈四值） | 结构非法/DER 非法 → task error（#15–#17 通道） |
| t2 resp 判定 | t1 init 已发 | 收 `negTokenResp`：`negResult`/`supportedMech`/`responseToken` | `supportedMech` ∈ 原始列表 + `accept_completed` → 进入已完成态 | `supportedMech` ∉ 列表 / 列表被改写 → 降级拒（#19 通道）；`reject` → 终止并报明确错误 |
| t3 MIC 续 | t2 得 `request_mic`(3) | initiator 补 `mechListMIC`（验证输入=**原始 DER mechTypes**） | MIC 匹配 → `accept_completed` | MIC 缺失/不匹配 → 不得标 completed（#19 通道） |
| t4 旧式 targ | profile 显式声明 RFC 2478 | 收 `negTokenTarg`（`negResult`/`supportedMech`/`responseToken`） | 字段序/tag [0..3] 按 RFC 2478 §3.2.1 解析，不误当 `negTokenResp` | 字段序混用 → choice/tag 负例（#17 通道） |

关联关系（§3.8–3.10 三件事）：本协议**无控制流驱动数据流**（无 `driven_by` 派生流），但有**同会话内请求-响应关联**：归属会话 sN、归属事务 tM、由 `supportedMech`（必须 ∈ initiator 原始 mechTypes 且与 `mechToken`/`responseToken` OID 绑定）+ `mechListMIC` 输入（原始 `mechTypes` DER bytes）双字段决定——与 CWMP 范本差异点诚实声明：SPNEGO 无副流派生，`sessions[]` 承载"每会话独立状态/候选列表/选定 OID/MIC 输入/token 重组缓冲"（本契约 §5）。

插入位置：终结层——HTTP profile 经 http 层 header 承载（`Authorization`/`WWW-Authenticate`，base64 包装，DER 字节不变）；裸 TCP 经 tcp payload 直传（接收端按 DER 父长度重组，segment 边界≠token 边界）。

时间线：**顺序**——同会话内 t1→t2→(t3) 严格消息序（每步依赖前一步结果）；会话间（交付形=两条独立 stream）并发但输出不假设全局包序，只断言流内状态（**实测调度**：按流顺序发射——flow0=包 1–11、flow1=包 12–22；套件按四元组聚合断言，不依赖全局包序）；无"长传输分片让位"面（无数据流）；控制可中插动作=无（SPNEGO 无 ABOR/STAT 类动作）。§3.12 的调度方式在本协议落点为"按事务序逐消息推进"。

### 11.12 §12 强制展开：动态字段清单

| 字段 | 住处 | 开策略 | 理由 |
|---|---|---|---|
| `src`（src_ip） | ip 层 | fixed/inc/rand/list/pattern 全开 | §12.2 四元组必备；多会话并发锚点 |
| `dst`（dst_ip） | ip 层 | fixed（多地址待 P4 立项） | 目标服务端地址 fixture 钉死；多目标另立项 |
| `src_port` | tcp 层 | 全开 + 未写动态保底 `12345+i` | §12.2/§2.8 |
| `dst_port` | tcp 层 | fixed（445 裸 TCP / 80 HTTP 两档 fixture） | tshark 自动解码约束（445→smb/smb2、80→http）；动态端口例顶层 `decode_as` 另议 |
| `mech_types`（OID 列表） | spnego 层 | list（三种 OID 轮转/别名区分） | 互操作 OID 面需全枚举；列表顺序影响 MIC 输入，按序轮转 |
| `mech_token`（内层 token 外壳） | spnego 层 | 不开（opaque fixture 钉死字节） | 无解密证据，动态**无意义**（内层语义不可断言）——诚实声明而非漏项 |
| `mech_list_mic` | spnego 层 | 不开（opaque fixture 钉死） | MIC 需与"原始 mechTypes"绑定验证；动态会破坏可复现验证面 |
| `neg_hints`（hintName/hintAddress） | spnego 层 | 不开（fixture 两值钉死） | 提示语义无列表可轮转；长度独立计算面按固定值覆盖 |
| `negResult`/`negState` | spnego 层 | list（accept_completed(0)/accept_incomplete(1)/reject(2)/request_mic(3) 四值枚举） | 协商进展全枚举；每值至少一例（§10.2 列面） |
| `supportedMech` | spnego 层 | list（来自 mech_types 列表示例） | 必须 ∈ 原始列表（降级防护面）；非法值走负例 |

序号算法代码位置：**待 P4 定**（D-SPNEGO-1 定稿后 builder/planner 落码时钉死文件+行号；此处不编行号——§5.7）。

### 11-P2 presence 负例形状（链级红例必含①）

层链+顶层空子映射并存=判死负例（presence 负例形状，非残留）：`{"layers":[{"ip":{}},{"tcp":{}},{"spnego":{}}],"spnego":{}}`（顶层空 `spnego:{}` 与层链并存）必须 planner/validator 拒，`error_contains` 含 `presence` 或顶层键锚词；P4 链级红例必含此形。白名单外游离键（如顶层 `src_mac`/`ttl`）判死负例见 §12。**另注**：`TransportOn ["tcp"]` 单值 + SPNEGO 无 UDP 语义 → 链中夹 `udp` 层（`[ip,udp,spnego]`）判死负例（`carrier` 锚词）；此形与 kerberos 双载体区别点须在链级红例中钉死。 **wire shape（裁定2）**：用例**不得声明 `decode_as`**——实测 `tshark -d tcp.port==80,ber` 把协议栈压成 `ber` 单层、`spnego.*` 字段全空（§10.7 M-shape-5），HTTP carrier 默认栈已是 `http→gss-api→spnego`；裸 TCP carrier 无 `gss-api`/`spnego` decode_as 目标（实测被拒；合法 tcp.port decode_as 目标实测 **317** 个中仅 `ber`/`kerberos` 可用），其断言走 frames hex（`tshark -V` 在裸 TCP 下**无** `OID: 1.3.6.1.5.5.2` 行，勘误⑪）。

## 12. D-SPNEGO-1 P2 代码设计草稿（CORE_MEMORY §8 八要素；门1 获批=定稿）

> 体裁：文件清单/接口签名/数据结构/主流程/错误分支/性能设计与验收/回滚方式。依赖建模沿 §10.6 裁定1；DER 编码权威逐结构点名（RFC 4178 §4.2–§4.2.2 + Appendix A / RFC 2478 §3.2.1 / RFC 2743 §3.1 / X.690）；内层 mech token 一律 opaque（裁定5）。

**文件清单（新建 5 + 接线 9）**：

| 文件 | 职责 |
|---|---|
| internal/core/spnego.go（NEW） | SPNEGOConfig/Session/Event 结构 + 严格 UnmarshalJSON（递归 DisallowUnknownFields，dtls/kerberos 同款三级）+ 6 `wire_fault` 常量（值面=§2 键表逐字：`der_truncated`/`der_length`/`choice`/`mech_oid`/`mic`/`carrier`）+ DescribeSPNEGOWireFault 锚词表 |
| internal/protocol/spnego/der.go（NEW） | DER 编码原语：tag 字节（class\|constructed\|num）、长度短形（<128）/长形（0x81/0x82）、OBJECT IDENTIFIER（首字节 40*X+Y + base-128 变长 arc）、OCTET STRING、GeneralString、ENUMERATED、SEQUENCE、上下文构造型 [n]（0xA0/n）、APPLICATION 0（0x60）——全 definite-length 恒定（X.690） |
| internal/protocol/spnego/builder.go（NEW） | 三结构 builder：`InitialContextToken`（0x60{OID 1.3.6.1.5.5.2,[0] EXPlicit negotiationToken}）+ `NegTokenInit`（mechTypes[0]/reqFlags[1]/mechToken[2]/mechListMIC[3]）+ `NegTokenResp`（negState[0]/supportedMech[1]/responseToken[2]/mechListMIC[3]，RFC 4178 §4.2.1/§4.2.2）+ `NegTokenTarg`（同构字段序，RFC 2478 §3.2.1，§10.3 H1 勘误后权威）+ 双 profile 承载（HTTP 经 http 层 header base64 包装；裸 TCP 整 DER 直发）+ spnegoWalker 会话状态单权威（候选列表/选定 OID/MIC 输入 bytes/重组缓冲）+ init() 注册 generator/validator |
| internal/protocol/spnego/planner.go（NEW） | validateSpec/validateSession（walk renderEvent 同路径单权威）+ validateWireFault + 降级守卫（supportedMech ∈ 原始 mechTypes）+ profile↔http 层有无结构性校验 + 会话 dst_port 冲突守卫 + presence/白名单预检 |
| internal/protocol/spnego/casegen_test.go（NEW） | 一次性生成器：20 例（14 正+6 负）契约计数逐例 add()，落 test/protocol_pcap/cases/spnego.json |
| 接线件 | types.go `SPNEGO *SPNEGOConfig`；FlowMeta.SPNEGO；translate `case "spnego"` + **Meta 字面量 `SPNEGO: spec.SPNEGO` 直传**（固定检查点——dcerpc/dtls/kerberos 三犯处，链级红例必钉）；strategy_convert `case "spnego"` + setDefaultDstPort 445（裸 TCP 档；HTTP profile 由 http 层 FieldContract=80 供给，两档并存、fixture 显式写端口时均不生效）；registry 行 §10.6 裁定1（`DependsOn ["tcp"]` + `OptionalOn ["http"]` + `TransportOn ["tcp"]`）+ FieldContract `tcp.dst_port`=445；validate_layers 预检（缺 tcp 载体 / profile↔http 层有无不一致 / 链夹 udp / 混合地址族 / 顶层旧键-presence 并存拒）；main.go 空白导入 + NewChainPlanner("spnego")；protocols.go 白名单 + protocols_test 同步；schemagen 重跑 |
| tools/coverage_gate.py | check_spnego（准入接线/关键件/守卫/用例面四段） |

**DER 逐结构权威（P4 逐字节对照此表；内层 token 不在表内=不可断言面）**：

```
InitialContextToken ::= [APPLICATION 0] IMPLICIT SEQUENCE (线首字节 0x60) {
  thisMech          MechType,                     -- OID 1.3.6.1.5.5.2（RFC 4178 §4.2 注册值）
  innerContextToken [0] EXPLICIT negotiationToken -- 线首 0xA0
}  ← 语法权威 RFC 2743 §3.1；本机 dissector spnego.thisMech/spnego.innerContextToken_element 实证
negotiationToken ::= CHOICE {
  negTokenInit [0] NegTokenInit,   -- 0xA0
  negTokenResp [1] NegTokenResp }  -- 0xA1（RFC 4178 §4.2 CHOICE；RFC 2478 targ 为旧式第三形）
NegTokenInit ::= SEQUENCE {        -- RFC 4178 §4.2.1 与 Appendix A 一致
  mechTypes   [0] MechTypeList,    -- SEQUENCE OF MechType；序=线上序，禁排序/重编码（MIC 输入依赖）
  reqFlags    [1] ContextFlags OPTIONAL,       -- 定义在 RFC 4178 §4.2.1（非 RFC 2743；DER 截尾零位）
  mechToken   [2] OCTET STRING OPTIONAL,       -- 内层机制 token=opaque（裁定5）
  mechListMIC [3] OCTET STRING OPTIONAL }
NegTokenResp ::= SEQUENCE {        -- RFC 4178 §4.2.2（正名 negState，非 RFC 2478 的 negResult）
  negState      [0] ENUMERATED { accept-completed(0), accept-incomplete(1), reject(2), request-mic(3) },
  supportedMech [1] MechType OPTIONAL,         -- 必须 ∈ 原始 mechTypes（降级守卫）
  responseToken [2] OCTET STRING OPTIONAL,     -- 内层 opaque
  mechListMIC   [3] OCTET STRING OPTIONAL }
NegTokenTarg ::= SEQUENCE {        -- RFC 2478 §3.2.1 旧式（字段序与 NegTokenResp 同构；ENUMERATED 三值无 request-mic）
  negResult     [0] ENUMERATED { accept_completed(0), accept_incomplete(1), reject(2) } OPTIONAL,
  supportedMech [1] MechType OPTIONAL, responseToken [2] OCTET STRING OPTIONAL,
  mechListMIC   [3] OCTET STRING OPTIONAL }
mechListMIC 输入 = 初始消息 MechTypeList 的 DER 原始字节（不含 [0] wrapper，RFC 4178 §5）
mechListMIC 线位 = NegTokenInit/NegTokenResp 的 [3]（RFC 4178 §4.2.1/§4.2.2 原文；tshark 3.6.14 该槽读作 negHints、其 mechListMIC 字段住 [4] —— §10.7 M-shape-4 实测冲突，裁定2 采 RFC 形）
上下文标签均 context-class constructed（0xA0+tagno）；长度全 definite-length（短形 <0x80 / 长形 0x81-0x82）
OID 编码：首字节 = 40*arc0+arc1，后续 arc 基 128 变长；Kerberos V5 / msKrb5 / NTLM 三值 DER bytes 逐字节钉
```

**数据结构**：`SPNEGOConfig{profile("http"|"tcp"), negotiation("init_resp"|"init_targ"|显式事件序), mech_types[]OID, supported_mech, neg_result(0..3 或旧式 0..2), req_flags{bitmask, 尾零截断=DER 默认}, neg_hints{carry("none"|"dissector"), hint_name, hint_address}, mech_token{opaque,len?}, mech_list_mic{layout("rfc4178"), opaque}, wire_fault, sessions[]}`；`Session{id, src_ip/src_port/dst_port 端点覆盖, events[]}`（会话间状态隔离）；`Event{kind(init|resp|targ), direction(up|down), ...}`（每 event = 一条完整 negotiationToken 消息 = 一 TCP payload 单元 / 一 HTTP 认证 header 值）。

**接口签名**（示意，P4 落码钉死）：`GenerateInitialContextToken(cfg) []byte` / `GenerateNegTokenInit(cfg) []byte` / `GenerateNegTokenResp(cfg) []byte` / `GenerateNegTokenTarg(cfg) []byte` / `ValidateSPNEGOSpec(spec) error` / `DescribeSPNEGOWireFault(fault string) string`。

**主流程**：validateSpec → 逐会话 walker → 逐 event render（InitialContextToken/negTokenInit → 裸 TCP payload 或 HTTP `Authorization` header base64；negTokenResp/negTokenTarg → 反方向）→ EmitMsg → worker → pcap/NIC。

**错误分支（§5.2）**：①`wire_fault` 6 值注入拒（锚词进断言，值面=§2 键表逐字）；②自然守卫：DER 长度形非法（indefinite/非最短）/ tag 不匹配 / choice 越界 / `supportedMech` ∉ 原始列表（降级）/ MIC 输入被改写 / 会话 dst_port 冲突 / profile↔http 层不一致 / 链夹 udp / 顶层旧键-presence 并存 / **同消息同时声明 `neg_hints.carry=dissector` 与 `mech_list_mic`（`[3]` 槽二义冲突，裁定2）**；③validate_layers 预检同步拒（缺 tcp 载体等）。全部传播为 task error，零假成功。

**依赖声明（§5.1）**：依赖 `tcp` 层（唯一载体，`TransportOn ["tcp"]`）；HTTP profile 依赖 `http` 层**显式写入**（`OptionalOn ["http"]`，无 http 层即裸 TCP profile）；依赖 DER definite-length 编码权威（X.690）；无外部密钥/票据依赖（内层 opaque 面，裁定5）。**不含 `udp` 依赖**（SPNEGO 无 UDP 语义，§10.6 误写检查）。

**为何不写 `DependsOn ["udp"]`（误写检查）**：SPNEGO 无 UDP carrier（RFC 4178 无 UDP 语义；现网亦无）——`DependsOn`/`TransportOn` 只出现 `tcp` 值，**udp 零值**（区别于 kerberos 的 udp+tcp 双载体；§11-P2 把此列成守卫）。

**TransportOn 只放 L4 值**：`TransportOn ["tcp"]` 单值；`http` 走 `OptionalOn` 不进 `TransportOn`（实测全仓库 `TransportOn:.*http` = 0，见 §10.6 先证）。本契约 §2 键表、门1 §5/§13 行、本 §12 接线件均引用本结论。

**性能设计与验收（§6.1–6.8）**：O(n) 流式——逐 event 渲染直发 EmitMsg 无全量聚合；确定性内存（无按包增长结构）；无锁无 sleep（事件驱动）；pcap 路实测 + NIC 路注记（过滤器 HTTP profile `tcp port 80 or tcp port 443`，裸 TCP profile 按实际端口 445）；回归口径=spnego.json 全量 suite 耗时 ±10%；六类场景（基线/目标规模/压力上限/长运行时/并发交错/背压）P5 跑测覆盖；边界诚实声明：吞吐/并发/内存目标数字待 P4 基准后定（§6.5，不写承诺）。

**dissector 兼容约束（裁定2，P4 builder 硬约束；v1.4.0 补实测 hex 锚）**：①`[n]` 一律显式包装（内层保留 universal tag）；`mechTypes`=`A0{30{OIDs}}`（单 OID 实测锚 `a0 0d 30 0b 06 09 2a 86 48 86 f7 12 01 02 02`）、`supportedMech`=`A1{06…}`、`negState`=`A0{0A vv}`、`reqFlags`=`A1{03 02 00 C0}`、`mechToken`/`responseToken`=`A2{04 …}`、`mechListMIC`(RFC 形)=`A3{04 …}` —— §10.7 M-shape-1 实测干净解出（单 OID 全字段形实测 DER `602906062b0601050502a01f301da00d300b06092a864886f712010202a104030200c0a2060404deadbeef`，读回 `mechTypes=1`/`MechType=1.2.840.113554.1.2.2`/`reqFlags=c0`/`delegFlag=1`/`mutualFlag=1`/`mechToken=deadbeef`，Malformed=0）；②NegTokenInit `[3]` 槽二义（RFC=mechListMIC / dissector=negHints）、`mechListMIC` 在 dissector 侧住 `[4]` —— builder 由 fixture 开关 `neg_hints.carry`（`none`|`dissector`）决定是否占用该槽，默认 `none`(RFC 形)；③用例禁 `decode_as`（§12 末段）。

**与现有逻辑冲突点（§8.7）**：http 层在 spnego 链中作 header 承载/变换器（`TransformEvents:true`，http_flv 同款分工：HTTP 语义归 http 层、认证 header 注入与 base64 包装归 spnego 层）；registry `OptionalOn ["http"]` 用户显式写才供给；`tcp.dst_port` 双层契约（spnego 445 / http 80）fixture 显式写端口时均不生效；schemagen 重跑层数按注册时点递增（**P2 期实测**：`schemas/v1/generated/layers.generated.json` = 123 层、`spnego` 零命中；**P4 交付后** 该文件含 spnego 行、层数随注册递增，`TestLayersGeneratedMatchesRegistry` 绿）。

**回滚方式（§8.8）**：全量 revert 新建文件 + 接线件回退（git revert 提交序）；registry/schemagen 生成文件随提交对齐回退；无数据迁移面。

## 13. P3 测试对接清单与缺口立项（T-SPNEGO 草稿输入；正文落 testcase 文件）

- §3.15 三项：①同连接/同流多轮操作→#13（HTTP keep-alive 多事务 + 双裸 TCP stream）+ #1/#6/#10 单轮基线，已覆；②非正常结束→`reject(2)`/`accept-incomplete(1)`/DER 截断/choice 混用/MIC 拒（#12/#15/#16/#17/#19，已覆）；服务端主动中止面→G-SPNEGO-2；③长保活→#13（已覆）。逐项一例或立项，无空项（明细见 testcase §8.1）。
- A′/B′ 两分类表：见 testcase §8.2（A′=引擎可构建→20 ID 内已覆 + A′ 补例建议 T-21（唯一一条，见 testcase §8.2；#45 ntlm 的 T-21/T-22 为同族先例）；B′=引擎结构缺口→G-SPNEGO-1/2/3 进 D-条目"明确不解决+迁入计划"）。
- 9.52 对账两行：见 testcase §8.3（清单出处声明 + 对账两行）。**v1.3.0 修正口径（可复核）**：**规范逻辑点总数 = 58** = §10.1 八项 8 行 + §10.2 事件×进展矩阵 35 格 + §10.3 数据形态变体表 15 行；**用例覆盖数 = 38** = §10.1 行 1–6、8 共 7 行 + 矩阵 16 格（已覆 10 + 缺口→用例通道 6）+ 变体 15 行；**B′/立项 = 20** = §10.1 行 7（代理专属形）1 + 矩阵 19 格（G-SPNEGO-2）。38 + 20 = 58 ✓。**工具/断言面 5 点**（§10.7 五形）单列，不计入规范总数——它们映射到 testcase §3.1 断言通道分流表（实现面约束，非用例覆盖点）。v1.2.0 的"42 格 + 变体 14 行 = 56 点 / 覆盖 34 + 立项 22"为双重算术失真，逐格重数见 §10.2 注。
- 3.14 豁免边界审计：见 testcase §8.4（本协议无自有连接但**不主张任何豁免**：多流并发 #13 + #14 已覆；单包多载荷=显式不适用（SPNEGO 一条消息=一条 negotiationToken）——三结论齐全，无豁免逃逸）。
- 三源回指行：见 testcase §8.5（第三源"已确认现网行为"当前=未确认级，挂 G-SPNEGO-1）。
- 断言通道：fields 用 `spnego.*`（**41** 字段已实证，精确口径 `tshark -G fields | awk -F'\t' '$3 ~ /^spnego\./' | wc -l`；细分 `spnego.krb5.*` 15 + `spnego.krb5_oid` 1 + `spnego.ContextFlags.*` 7 + 本体 18：negTokenInit_element/negTokenTarg_element/MechType/mechTypes/reqFlags/mechToken/mechListMIC/hintName/hintAddress/negHints_element/negResult/supportedMech/responseToken/thisMech/innerContextToken_element/wraptoken/decrypted_keytype/unknown_header；**v1.4.0 勘正**：裸 TCP carrier 无字段通道**也无 `-V` OID 行**，只能 frames hex；全用例禁 `decode_as`，合法目标实测 **317**）

## 14. 缺口立项清单（有缺口写"缺口立项"，不许空着）

| 立项号 | 缺口 | 确认方式（三选一） | 去向 |
|---|---|---|---|
| G-SPNEGO-1 | 现网证据升级：三机制 OID 别名的"已确认现网"级证据（msKrb5 `1.2.840.48018.1.2.2`/NTLM `1.3.6.1.4.1.311.2.2.10` 目前只到 dissector 源码值级）；`NegHints` 结构名与字段（RFC 4178 原文无此定义，现为 dissector 本地拆解级）；`mechListMIC` RFC 4559 扩展 OID `1.3.6.1.4.1.311.2.2.30` | 抓包（本机回环 `curl --negotiate` 或无域环境用 impacket 脚本抓回环包核对三 OID 列表与 hint 形态）| P4 前置确认项，不挡开工；确认前相关条目按 §5.5"待确认"不写死 |
| G-SPNEGO-3 | dissector 形↔RFC 形长期一致性：tshark 3.6.14 用 `[3]`=negHints / `[4]`=mechListMIC（§10.7 M-shape-3/4 实测）与 RFC 4178 §4.2.1/§4.2.2 相反；若上游 wireshark 改回 RFC 形（或新增 `spnego.negTokenResp_element`），本协议 #5/#10 的字段断言通道需重校准 | 查 wireshark 上游 release notes / `packet-spnego.c` 变更（问谁：无，查源码+复跑本机 §10.7 复现脚本即确认） | P4 后跟踪项，不挡开工；跟踪前按 §10.8 裁定2 A 方案执行（RFC 形生成 + 通道分流） |
| G-SPNEGO-2 | 服务端主动错误语义：`accept-incomplete` 多步交织（>2 轮协商）、双向 `request-mic` 不对称面（initiator 侧 resp 携带）、旧式 `negTokenTarg` 的扩展值面、MIC 后静默中止、服务端 mid-transaction 中止（FIN/RST）、HTTP 代理转发形（绝对 URI + 407 `Proxy-Authenticate` 专属形，§11.2 行 7） | 查 RFC 4178 §5 原文 + RFC 4559 §4.2 + 抓 Samba/IIS 交互包（问谁：无，抓包即确认） | B′→D-SPNEGO-1"明确不解决+迁入计划"（P4 fixture 可构建性待定；确认后进 §10.2 矩阵空白格） |

**P4–P6 交付后缺口状态（v1.5.0）**：**三项全部维持 open**——G-SPNEGO-1（现网证据升级；P4 已按"确认前不写死"执行，实现只用 dissector 实测级证据）、G-SPNEGO-2（B′ 服务端主动错误语义；20 ID 未覆盖，维持迁入计划）、G-SPNEGO-3（dissector 形↔RFC 形长期一致性；P4 按 §10.8 裁定2 A 方案执行，未见上游变更）。另：T-21（dissector 形 negHints 字段断言补例）维持"不入 20 ID 契约"裁定（testcase §8.2），未随交付并入。
