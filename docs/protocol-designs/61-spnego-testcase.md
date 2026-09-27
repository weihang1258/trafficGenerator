# SPNEGO（简单和受保护的 GSS-API 协商，Simple and Protected GSS-API Negotiation）测试用例契约

> 版本：v1.3.0（P4–P6 落地回写：交付实况 + #13 形状订正；v1.2.0 = P3 完整产物 + 断言通道实测复校）  
> 日期：2026-09-27  
> 配套设计：`docs/protocol-designs/61-spnego-design.md`（v1.4.0）  
> 机器契约：`trafficgen/test/protocol_pcap/cases/spnego.json`  
> 状态：**P4–P6 已交付**：`spnego` 层已注册，`cases/spnego.json` = 20 个语义用例（14 正 + 6 负，占位移除），lane suite 20/20 绿（P6 修轮后复跑）。本文既定的 PCAP（抓包文件）/NIC（网卡）断言现已全部可运行并被套件执行。P1–P3 期口径（保留备查）：v1.1.0 追加 §8 P3 固定动作（§3.15 三项 / A′B′ 两分类 / 9.52 对账两行 + 出处声明 / 3.14 豁免边界审计 / 三源回指 / 断言契约核对），并将 §3 项 7 的 `NegTokenTarg` 字段序按 RFC 2478 §3.2.1 原文勘误（与 design §10.3 H1 行一致）。v1.2.0 复校断言通道：裸 TCP 的 `tshark -V` 无 `OID: 1.3.6.1.5.5.2` 行（唯一证据=frames hex），`decode_as` 合法目标数 **317**；HTTP profile 链形可达性按 design v1.4.0 §10.6 证据（框架 `0c355be`）。

## 1. 测试原则和未注册边界

用例从设计 §2–§9 逐项派生，共 20 个唯一语义 ID：14 个正例和 6 个负例。**交付实况（v1.3.0）**：`cases/spnego.json` 已按本文 §2 顺序落盘 20 个语义用例，注册前置占位 `spnego_neg_unregistered` 已移除（P1–P3 期该 JSON 只保留一个不计入语义覆盖的占位，`expect_error=true`、`error_contains="unknown layer"`）。

SPNEGO carrier（载体）为 HTTP `Negotiate` 或裸 TCP stream（字节流）。**断言通道（design §10.7 实测口径；v1.2.0 勘正）**：HTTP carrier 由 tshark 默认协议栈 `http→gss-api→spnego` 自动拆解（无需 `decode_as`，加 `decode_as` 反而把栈压成 `ber` 单层、`spnego.*` 全空）；裸 TCP carrier 无 `gss-api`/`spnego` decode_as 目标（实测被拒），其结构证据走 frames hex（offset 54/74 的原始 DER hex）——**`tshark -V` 在裸 TCP 下不出现 `OID: 1.3.6.1.5.5.2` 行**（445 栈止于 `nbss` 的 `Continuation data:` 原始 hex、随机高端口栈止于 `tcp`），v1.1.0 记的"`-V` 的 OID 行"手段作废；**全用例禁止声明 `decode_as`**。无机制解密证据时，PCAP/NIC 只可断言 TCP/HTTP 方向、端口、header、GSS-API InitialContextToken、DER（可区分编码规则）tag/length、OID 和 OCTET STRING 长度；不可声称看见 Kerberos/KRB5/msKrb5/NTLM token 内部字段。动态 token、MIC、nonce、ticket 使用 `presence`、`nonzero`、`same_as_packet`，不能硬编码运行期随机值。

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
| 13 | `spnego_multi_session_stream` | 正 | 多流 × 多会话 × 异常分支：两条四元组独立裸 TCP stream（flows=2 + 动态 src_port）、每流 s1(krb+msKrb5→accept)/s2(NTLM→reject) 会话状态不串用 | 24 → **22（实测）** |
| 14 | `spnego_pcap_nic_consistency` | 正 | PCAP/NIC carrier、方向、DER/OID 外层证据一致 | 16 |
| 15 | `spnego_neg_der_truncated` | 负 | DER tag/length/TLV/token 截断 | — |
| 16 | `spnego_neg_der_length_overflow` | 负 | 长度溢出、父子长度不一致、非最短编码 | — |
| 17 | `spnego_neg_invalid_token_choice` | 负 | choice/tag class/结构混用错误 | — |
| 18 | `spnego_neg_mech_oid_selection` | 负 | OID 编码或选定机制绑定错误 | — |
| 19 | `spnego_neg_mic_downgrade` | 负 | MIC/list 改写、缺失或降级选择 | — |
| 20 | `spnego_neg_carrier_profile` | 负 | HTTP/TCP profile、端口、stream 边界错误 | — |

**`约定 packet_count` 与实测偏离（先跑后钉，v1.3.0 落盘实测；design §9 表后注同口径）**：正例实测 = **11/11/9/9/11/11/9/9/9/10/9/9/22/11**（第 1–14 项，出处 `cases/spnego.json` 的 `expect.packet_count`，逐例对落盘 pcap 校验）；14 例全部满足 `3（三次握手）+ 事件数 + 4（FIN 挥手）`；#13 = 单流 11 × 2 流 = 22（约定 24 作废）。负例不计包数（`expect` 只有 `expect_error`/`error_contains`）。

## 3. 正例逐项断言契约

1. **`spnego_http_ipv4_init`**：建立 IPv4 TCP/HTTP 认证交换，断言 TCP SYN/SYN-ACK、HTTP `401` 与 `WWW-Authenticate: Negotiate`、后续 `Authorization: Negotiate`，InitialContextToken 外层 `0x60`、SPNEGO OID 存在及 negTokenInit tag/length，`packet_count=12`；不可断言机制 token 内字段。
2. **`spnego_http_ipv6_init`**：独立 IPv6 TCP/HTTP fixture，断言 `ipv6.nxt=6`、地址族、HTTP Negotiate 方向与 DER 外层，`packet_count=12`；IPv6 地址不能由 IPv4 fixture 继承。
3. **`spnego_tcp_ipv4_init`**：裸 IPv4 TCP stream 携带跨 segment 的 InitialContextToken/negTokenInit；按重组 stream 断言 `ip.proto=6`、DER 父长度与 SPNEGO OID，`packet_count=10`；TCP segment 边界不当作 token 边界。**通道**：裸 TCP carrier 无 spnego 字段通道（design §10.7 M-shape-5 实测），结构证据=frames hex（payload 起点 54 的原始 DER hex，含 `0x60` 外层与 OID `06 06 2B 06 01 05 05 02`；`-V` 无 OID 行，v1.2.0 勘正）。
4. **`spnego_tcp_ipv6_init`**：裸 IPv6 TCP stream 携带同类 token，断言 `ipv6.nxt=6`、IPv6 checksum 与 token 重组，`packet_count=10`；不得把 IPv6 outer 地址当机制字段。**通道**同项 3（frames hex，payload 起点 74）。
5. **`spnego_neg_token_init_hints`**：断言 negTokenInit 的 `[0] mechTypes` 为有序 OID SEQUENCE、可选 `[1] reqFlags`（BIT STRING，DER 须截尾零位；字段面 `spnego.reqFlags` + `spnego.ContextFlags.*` 七布尔）、`negHints` name/address 的独立长度、`[2] mechToken` OCTET STRING；**`negHints` 线位按 design §10.8 裁定2 只走 dissector 形（NegTokenInit `[3]` 内 `SEQUENCE { [0] GeneralString, [1] OCTET STRING }`，字段面 `spnego.negHints_element`/`hintName`/`hintAddress` 实测干净解出），该 fixture 不得同时携带 RFC 形 `mechListMIC`（同槽二义，planner 拒绝）**；动态 token 仅 nonzero，`packet_count=12`。
6. **`spnego_neg_token_resp_selection`**：服务端 negTokenResp 含 `[0] negResult`（RFC 4178 §4.2.2 正名 `negState`）、`[1] supportedMech`（必须来自 offered list）和可选 `[2] responseToken`；断言字段 tag/DER length/方向与 `accept_incomplete(1)` 或 `accept_completed(0)` 状态，`packet_count=12`。**实测**：tshark 3.6.14 无 `spnego.negTokenResp_element`，`[1]` 选择枝统一显示为 `spnego.negTokenTarg_element`；resp 面可用字段=`spnego.negResult`/`spnego.supportedMech`/`spnego.responseToken`（三字段实测填充；不用 dissector 未提供的字段名）。
7. **`spnego_neg_token_targ_legacy`**：显式声明旧式 negTokenTarg profile，断言其 `[0] negResult`（ENUMERATED 三值 accept_completed(0)/accept_incomplete(1)/reject(2)）、`[1] supportedMech`、`[2] responseToken`、`[3] mechListMIC` 的 tag/顺序（RFC 2478 §3.2.1 原文；**v1.0.0 本项记 `[0] supportedMech`/`[1] responseToken`/`[2] negResult` 系误记，随 design §10.3 H1 行勘误**），不误解析为 negTokenResp（tshark 3.6.14 对 `[1]` 选择枝统一显示为 `spnego.negTokenTarg_element`），`packet_count=10`。
8. **`spnego_mech_oid_variants`**：至少三个独立交换使用 Kerberos `1.2.840.113554.1.2.2`、Microsoft KRB5 `1.2.840.48018.1.2.2`、NTLM `1.3.6.1.4.1.311.2.2.10`；断言 OID DER bytes 及 selectedMech 与列表绑定，机制 token 只断言包装存在/长度，`packet_count=14`。
9. **`spnego_mech_token_opaque`**：跨多个 TCP/HTTP 消息携带不透明 mechToken/responseToken，断言 context wrapper、OCTET STRING length 与 nonzero；重传 token 使用 same-as 断言，不解析 token 内部，`packet_count=10`。
10. **`spnego_mechlist_mic`**：断言 mechListMIC wrapper `[3]`（RFC 4178 §4.2.1 形）、MIC OCTET STRING 存在、验证输入为原始 DER mechTypes（不含 `[0]` wrapper，RFC 4178 §5 原文 + Appendix D）；列表未改变时可 completed，动态 MIC 使用 nonzero/same-as，`packet_count=14`。**断言通道（design §10.7 M-shape-4 实测）**：tshark 3.6.14 把 RFC 形的 `[3]` 槽读作 negHints（`spnego.mechListMIC` 字段只认 `[4]`，RFC 未定义），故本用例 MIC 结构断言走 **frames hex**（`A3`+len+`04`+len），字段面只用于 `spnego.mechTypes` 与 `spnego.negResult`。
11. **`spnego_der_canonical_boundaries`**：覆盖空可选字段、单/多 OID、DER 短形式和长形式 length、父子 TLV 紧邻及 token 跨 TCP segment；断言最短合法 length、父长度包含全部子项，`packet_count=12`。
12. **`spnego_downgrade_prevention`**：覆盖 `accept_incomplete`→继续、`request_mic`→MIC、`reject`→终止和合法 `accept_completed`；selectedMech 始终来自原始 offered list，列表改变时要求 MIC/失败，`packet_count=12`。
13. **`spnego_multi_session_stream`**（**v1.3.0 交付口径；C2 订正**）：**多流 × 多会话 × 异常分支**三类交织于一例——`flow_control.flows=2` + `tcp.src_port` 动态对象（`{inc,[45061,45070],step 1}`）→ 两条四元组独立的裸 TCP stream（45061/45062→445），每流两个会话：s1=配置级候选 [Kerberos, msKrb5] → `accept_completed(0)`；s2=会话级覆盖 NTLM 单候选 → `reject(2)` 异常终止。断言（5 fields + 6 frames = 11 点）：`tcp.dstport=445`、流内首包 srcport、第二流首包 srcport=45062、`ip.proto=6`、**`tcp.srcport` 跨流 `distinct_values=[45061,45062]`（`distinct_exclude=[445]`，恰两条客户端流=四元组隔离）**；帧钉包 4/5/6/7（流 1 s1 init 双候选 → s1 resp `negState=0`+supportedMech=krb5 → s2 init NTLM 单候选 → s2 resp `negState=2`）与包 15/18（流 2 同结构、四元组独立）。`packet_count=22`（实测），不假设跨流全局顺序。**通道**：裸 TCP 无 `spnego.*` 字段通道（§3.1 实测：445 栈止于 `nbss`、`decode_as` 被拒），故隔离差异按 frames hex 逐包钉（每包钉死候选列表/negState/选定机制字节）。**契约偏离登记**：本项原写"两个 HTTP keep-alive 请求和两个裸 TCP stream/会话并行（`packet_count=24`）"——同一用例内双载体并存受引擎 one strategy = one chain 约束不可表达（`planner.go:36-43` 拒会话端点覆盖），双载体覆盖改由跨用例承担（#1/#2 HTTP、#3/#4 裸 TCP）；见 design §11.3 交付口径段与 `/tmp/pipe/47-spnego/p6-fix-report.md`。
14. **`spnego_pcap_nic_consistency`**：同一 fixture 分别写 PCAP 并在 NIC 捕获；断言 TCP carrier、方向、端口、HTTP header 或 DER 外层、OID、token 长度一致，`packet_count=16`；HTTP 过滤器为 `tcp port 80 or tcp port 443`，裸 TCP 按实际端口。

无解密/授权密钥时，上述正例不得添加 Kerberos AP-REQ、KRB-ERROR、ticket、nonce、session key 或 NTLM proof 字段断言。若 tshark（抓包解析器）无 `spnego.*` 字段，使用通用 `tcp`/`http` 和稳定 raw frames（原始帧）；不自创字段名。


## 3.1 断言通道分流表（design §10.7 实测口径；全用例禁 `decode_as`）

| carrier | 通道 | 可用字段/手段 | 不可用（实测） |
|---|---|---|---|
| HTTP（`WWW-Authenticate` / `Authorization`） | tshark 默认协议栈 `http→gss-api→spnego` 自动拆解 | `spnego.thisMech`/`negTokenInit_element`/`mechTypes`/`MechType`/`reqFlags`/`ContextFlags.*`（七）/`mechToken`/`negTokenTarg_element`/`negResult`/`supportedMech`/`responseToken`/`negHints_element`/`hintName`/`hintAddress` + `http.response.code`/`http.authorization`/`http.www_authenticate`/`tcp.dstport` | `spnego.mechListMIC`（RFC 形不填充）、`spnego.negTokenResp_element`（dissector 无此字段，实测 0 命中） |
| 裸 TCP（445 / 任意端口） | frames hex（payload 起点 54/74 的原始 DER hex） | `ip.proto`/`ipv6.nxt`/`tcp.dstport`；payload 起点 54（IPv4）/ 74（IPv6）的 DER hex（含 `0x60` 外层、SPNEGO OID `06 06 2B 06 01 05 05 02`、内层 `0xA0`/`0xA1` choice 与父长度） | `spnego.*` 全部（实测 445 栈止于 `nbss`，字段与 Malformed 皆无）；**`tshark -V` 的 `OID: 1.3.6.1.5.5.2` 行亦不存在**（实测 445 只有 nbss `Continuation data:` 原始 hex、随机高端口栈止于 `tcp`）——v1.1.0 该格记此行为可用手段，v1.2.0 勘正 |
| 任何 carrier | — | — | `decode_as`：`tshark -d tcp.port==…,spnego` / `,gss-api` 均被拒（`Protocol "…" isn't valid for layer type "tcp.port"`；合法目标实测 **317** 个里仅 `ber`/`kerberos`）；加 `-d …,ber` 反把栈压成单层 `ber`、`spnego.*` 全空 |

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

1. 设计 §9、本文 §2、`cases/spnego.json` 和审计必须保持同一 20 个语义 ID、同一顺序；14 正例 + 6 负例（**v1.3.0 实测三处逐 ID 同序 ✓**；P1–P3 期 JSON 另有 `spnego_neg_unregistered` 占位，已随注册移除）。
2. 14 个正例均已带 `packet_count`、方向和稳定 carrier/DER/OID 断言（字段或 frames 二通道，实测分流见 §8.2）；6 个负例的 `expect` 只有 `expect_error`、`error_contains`——**交付后（v1.3.0）实测全部合规**（P1–P3 期未注册 JSON 只验证占位结构）。
3. InitialContextToken 的 `0x60`、SPNEGO OID `1.3.6.1.5.5.2`、context-specific tags、父子 DER length 和 OID bytes 必须按实际编码断言；HTTP base64 长度不代替 DER 长度。
4. TCP profile 必须先重组 stream 再解析 DER；TCP segment 起点、IPv4 54/IPv6 74 参考 offset 仅适用于无 options fixture。HTTP profile 只在 header/token 可观察时断言 carrier。
5. 未解密 mechToken/responseToken/MIC 使用 presence/nonzero/same_as；不得伪造 Kerberos/KRB5/msKrb5/NTLM 内部字段。
6. 多会话/多流断言使用四元组、OID/token distinct 或 same-as，不能依赖交织流的全局包序。
7. 运行 `python3 -m json.tool trafficgen/test/protocol_pcap/cases/spnego.json` 应成功；**交付实况（v1.3.0）**：数组含 20 个语义用例（14 正 + 6 负）且不含注册前置占位；负例 `expect` 键集严格 = `{expect_error, error_contains}`（P1–P3 期该数组只含 `spnego_neg_unregistered`）。

## 6. 实现后执行建议

**交付实况（v1.3.0）**：P4 注册后已按本条执行——JSON parser（`python3 -m json.tool` + 链级 audit 单测）、ID 顺序（三源回指 §8.5）、正负 expect 键集合（coverage_gate 84/84 项反查）、DER offsets（frames hex 起点 54/74）与 tshark 字段注册（§3.1 实测口径）逐项核过，1–14 正例与 15–20 负例经 lane suite 全绿；NIC 半按 design §13 注记降级（PCAP 半执行）。环境无 `spnego.*` dissector 时按 §3.1 用通用 carrier 字段与 raw frames；placeholder 运行结果不得报告为 SPNEGO suite 通过（占位已移除，此纪律仍适用于任何未来的注册前置占位）。

## 7. 修订记录

- v1.3.0（2026-09-27）：**P4–P6 落地回写**（对照 09-tds-design.md v3.1.1 格式）。①**交付**：`spnego` 层注册、`cases/spnego.json` 20 例（14 正 + 6 负）去扁平完成、占位移除、lane suite 20/20（P6 修轮后复跑）；②**C1 形状落地**：#13 重做为多流 × 多会话 × 异常分支（flows=2 + 动态 src_port → 两条四元组独立裸 TCP stream；每流 s1 accept / s2 reject），断言 2 点 → 11 点（5 fields + 6 frames），实测 22 包（§2 表后注 + §3 项 13）；③**C2 订正**：§3 项 13 原"两个 HTTP keep-alive 请求和两个裸 TCP stream/会话并行（24 包）"与可表达形状不符，按交付口径改写并附偏离登记（one strategy = one chain；双载体改由跨用例 #1/#2/#3/#4 承担）；④**m1 补钉**：#8 补包 5 resp 帧钉（supportedMech=NTLM 会话级选定）；⑤**通道订正**：#13 由字段通道改为 frames hex（裸 TCP 无 `spnego.*`，§3.1 律），§8.2 断言通道行同步；⑥**缺口维持 open**：G-SPNEGO-1/2/3（design §14）；T-21 维持不入 20 ID 契约。
- v1.2.0（2026-09-25）：实测复校（本机 tshark 3.6.14 + `text2pcap`）。①§1/§3 项 3/§3.1 的裸 TCP 断言手段勘正——`tshark -V` 在裸 TCP 下**无** `OID: 1.3.6.1.5.5.2` 行，唯一结构证据=frames hex（原始 DER hex，含 `0x60`/OID/choice/父长度）；②§3.1 合法 `decode_as` 目标数勘正 313→**317**；③与 design v1.4.0 的 OptionalOn 可达性证据（框架 `0c355be`）口径同步——本文件不含"不可达"断言，无需改写。
- v1.1.0（2026-09-25）：P3 完整产物。新增 §8 固定动作（§3.15 三项 / A′B′ 两分类 / 9.52 对账两行 + 出处声明 / 3.14 豁免边界审计 / 三源回指 / 断言契约核对）；新增 §3.1 断言通道分流表（design §10.7 五形实测口径，全用例禁 `decode_as`）；§3 项 7 `NegTokenTarg` 字段序按 RFC 2478 §3.2.1 原文勘误（v1.0.0 记 `[0] supportedMech`/`[1] responseToken`/`[2] negResult` 有误）、项 3/4/5/6/10/13 补通道口径；§1 补通道纪律。
- v1.0.0（2026-08-20）：建立 14 个 SPNEGO RFC 4178 正例和 6 个严格负例，覆盖三种 negotiation token、negHints、Kerberos/KRB5/msKrb5 OID 包装、DER 边界、MIC、降级防护、HTTP/TCP carrier、IPv4/IPv6、多会话/多流、PCAP/NIC 和错误传播；不修改 Go 实现。

## 8. P3 固定动作（CORE_MEMORY §3.15 / §9.52 / §9.14 / 覆盖审计要求面）

### 8.1 §3.15 三项逐项一例或立项（无例无项即缺口）

| # | 三项 | 本协议对照 | 用例/立项 |
|---|---|---|---|
| ① | 同连接/同流内的多轮操作 | HTTP：同一 TCP 连接上 匿名请求 → `401`+`WWW-Authenticate: Negotiate` → `Authorization: Negotiate`(init) → `WWW-Authenticate: Negotiate`(resp) → 200，keep-alive 下再来一轮；裸 TCP：同一 stream 内 init → resp →（可选 MIC 第三消息） | 已覆：HTTP 面 #1/#2（单连接双 header 往返）+ #6/#10；**多流多会面 #13（交付形=两条裸 TCP stream × 每流 s1/s2 两会话，22 包）**；单轮基线 #1/#6/#10 |
| ② | 非正常结束 | 合法 `reject(2)` 终止（#12）、`accept-incomplete(1)` 后中止（#12）、DER 截断/父长越界/choice 混用（#15/#16/#17）、MIC/列表改写拒（#19）；**载体会话中断形**（服务端 mid-negotiation 主动 FIN/RST、HTTP 代理 `407 Proxy-Authenticate`、resp 后无后续静默丢弃） | 前半已覆（#12/#15/#16/#17/#19）；后半 → **B′ 立项 G-SPNEGO-2**（不删用例，迁入计划见 design §14） |
| ③ | 长保活 | HTTP keep-alive 同连接多认证事务（多轮 401/Authorization）；裸 TCP 长生命周期连接上的多轮协商与重组 | 已覆：#13（交付形=两条裸 TCP stream × 每流 s1/s2 两会话，22 包，实测；HTTP keep-alive 多事务面由 #1/#2 的 keep-alive 连接承载） |

无空项。

### 8.2 A′/B′ 两分类表（要求面反推：数据/业务/现网/多流/地址族/断言通道六类）

A′（引擎可构建 → 20 ID 内已覆；**唯一 A′ 补例建议 = T-21**（dissector 形 negHints 的字段断言面），它超出 20 ID 契约，**并入与否由主线程定**，不影响 §2 的 20 ID 权威口径；#45 ntlm 的 T-21/T-22 为同族先例）：

| 面 | 要求点 | 去向 |
|---|---|---|
| 数据 | mechTypes 单/多 OID 与列表序；四 OID DER bytes；DER 短/长 length；choice 三形（init/resp/targ）；mechToken 零长占位/非零/跨包重传；MIC 输入=原始 mechTypes bytes；reqFlags 位串（含 DER 尾零截断）；negHints 两字段独立长度；空可选字段 | #5/#8/#9/#10/#11 已覆；非法形 → 负例 #15–#19 |
| 业务 | 协商状态机四值（accept-completed/accept-incomplete/reject/request-mic）× 旧式三值；降级守卫（supportedMech ∈ 原始列表）；request-mic → 补 MIC；多轮 keep-alive 事务 | #6/#7/#10/#12/#13 已覆；**>2 轮 incomplete 交织 / 双向 request-mic 不对称** → B′（G-SPNEGO-2） |
| 现网 | Windows/AD HTTP 两轮（401→Authorization→200）；Samba/impacket OID 列表序（Kerberos 优先、msKrb5 次之）；Linux `curl --negotiate` | #1/#2（HTTP 两方向）/ #6 / #8 已覆；**抓包级确认 → B′ 治理项 G-SPNEGO-1**（确认方式已写清：回环抓包）；SMB/445 内嵌形 → 明确不支持（design §11.2 行 2，交 #45 ntlm 文档级交叉引用） |
| 多流 | 双裸 TCP stream 会话隔离（OID 列表/token buffer/MIC/状态/四元组不串用；交付形 2 四元组 × 每流 2 会话）；PCAP 与 NIC 双路一致 | #13 已覆（22 包实测）；#14 覆盖双路一致 |
| 地址族 | IPv4/HTTP、IPv6/HTTP、IPv4/裸 TCP、IPv6/裸 TCP 四格（§9.24 对称，不许一族代表另一族） | #1/#2/#3/#4 已覆（无缺格） |
| 断言通道（v1.1.0 新增面；v1.2.0 勘正） | HTTP carrier 字段通道（含 dissector 形 negHints）；裸 TCP frames hex（`-V` 无 OID 行）；RFC 形 mechListMIC 只能 hex 断言 | **实测分流（v1.3.0 按 cases/spnego.json 逐例清点）**：#1/#2/#5/#6/#14 走字段（HTTP profile，`spnego.*` 填充）；#3/#4/#7/#8/#9/#10/#11/#12/#13 走 hex（裸 TCP profile，frames 帧钉，含 #13 的多流隔离 6 处帧钉）；**dissector 形 negHints 断言面 → A′ 补例建议 T-21**（design §10.8 裁定2 的 dissector 形，落 `spnego.hintName`/`hintAddress` 两字段；实测两字段在 canonical 形下干净解出） |

B′（引擎结构缺口 → D-SPNEGO-1「明确不解决 + 迁入计划」，见 design §14）：

- **G-SPNEGO-2**（服务端主动错误语义：多步 incomplete 交织、双向 request-mic 不对称、旧式 targ 扩展值、MIC 后静默中止、mid-transaction FIN/RST、HTTP 代理 407 专属形）——覆盖 §10.2 矩阵 19 格 + 八项行 7。
- **G-SPNEGO-1**（现网证据升级：三 OID 别名的"已确认现网"级证据、NegHints 结构名、RFC 4559 扩展 OID `1.3.6.1.4.1.311.2.2.30`）——P4 前置确认项，不挡开工；确认前按 §5.5 不写死。
- **G-SPNEGO-3**（dissector 形↔RFC 形长期一致性：tshark 3.6.14 的 `[3]`=negHints / `[4]`=mechListMIC 与 RFC 4178 相反；上游变更时 #5/#10 字段通道需重校准）——P4 后跟踪项，跟踪前按 design §10.8 裁定2 A 方案执行。

### 8.3 9.52 对账两行 + 清单出处声明

- **清单出处声明**：本清单来源 = **规范/官方文档反推**（RFC 4178 §4.2/§4.2.1/§4.2.2/§5/Appendix A/Appendix D；RFC 2478 §3.2.1；RFC 2743 §3.1；RFC 4559 §1/§4.2；ITU-T X.690），**非**引擎能力面反推。引擎侧只作现状取证：`spnego` 在 `registry.go`/`protocols.go` 零命中（`protocols_test.go:105` 列在 negativeOnly）、`cases/spnego.json` 仅 1 例占位（旧扁平形五顶层键）、`tshark -G fields` 实测 `spnego.*` 41 字段、design §10.7 五形 dissector 实测。
- **对账两行（v1.2.0 口径，可复核）**：**规范逻辑点总数 = 58**（八项矩阵 8 行 + design §10.2 事件×进展矩阵 35 格 + design §10.3 数据形态变体表 15 行）；**用例覆盖数 = 38**（八项行 1–6、8 共 7 行 + 矩阵 16 格〔已覆 10 + 缺口→用例通道 6〕+ 变体 15 行，全部由 20 个语义 ID 承载）；**B′/立项 = 20**（八项行 7 代理专属形 1 + 矩阵 19 格 → G-SPNEGO-2）。38 + 20 = 58 ✓ 无遗漏。**工具/断言面 5 点**（design §10.7 五形：wire shape/位串包装/negHints 槽/mechListMIC 槽/断言通道）单列，不计入规范总数——映射到本文 §3.1 分流表，属实现面约束。**v1.4.0 复校不改计数**：勘误⑨–⑫（wire 包装写法、空表字节、断言通道手段、krb5 子面口径）全在实现面/工具面，未增删 §10 任何行/格。
- **粒度声明（防误读）**：按 design §10 的行/格粒度计数（八项按行、矩阵按格、变体按行），每行只计 1 点；行内子面缺口另登 design §14，**不折进 58 点、也不冒充覆盖**；§10.7 五形（工具/断言面）单列不进 58。**反查 20/20 绿 ≠ 覆盖全**——反查只证明清单内的点有例，本对账才证明清单本身全（§9.52 原文）。

### 8.4 3.14 豁免边界审计

- 本协议**无自有连接**（token 寄居 HTTP 事务/裸 TCP 字节流），是最典型的"无长连接协议"——但 §3.14 明示"豁免 `sessions[]` 不等于豁免多流覆盖"。本文**不主张任何豁免**：`sessions[]` 由 design §11.3 会话表（s1 HTTP / s2 裸 TCP）显式声明，且 #13 覆盖会话隔离与并发。
- **多流并发**：已覆 #13（交付形=两条四元组独立裸 TCP stream × 每流 s1/s2 两会话，含候选列表/选定机制/状态/四元组隔离，帧级逐包钉）+ #14（PCAP/NIC 双路）。**契约偏离**：原"HTTP keep-alive 事务 与 裸 TCP stream 同一用例并行"受 one strategy = one chain 约束不可表达，双载体覆盖改由跨用例承担（#1/#2 HTTP、#3/#4 裸 TCP），见 §3 项 13 偏离登记。
- **单包多载荷**：SPNEGO 无"一包多载荷"形态（一个 negotiationToken = 一条消息；`mechTypes` 内多 OID 属单载荷内的子结构，由 #5/#8 覆盖）→ 显式记 **不适用**（design §10.3 变体表"TCP 形态"行），不是豁免逃逸。
- 结论：多流、单包多载荷、多轮事务三项各有结论，无逃逸。

### 8.5 三源回指行

RFC 4178（协商 token 结构与降级/MIC 语义）+ RFC 2478 §3.2.1（旧式 `negTokenTarg`）+ RFC 2743 §3.1（`InitialContextToken` 语法）+ RFC 4559 §1/§4.2（HTTP `Negotiate` 双 header 与 2xx 语义）+ X.690（DER definite-length）→ **D-SPNEGO-1**（design §12）→ `trafficgen/test/protocol_pcap/cases/spnego.json`（20 例）。第三源"已确认的现网行为"当前为**未确认级**（design §10.4 ②），挂 G-SPNEGO-1 且按 §5.5 不写死进实现。ID 权威 = 本文 §2（14 正 + 6 负）。

### 8.6 断言契约核对结论（与 design §9/§10.7/§12 一致）

1. **20 ID 契约核对**：本文 §2 与 design §9 逐 ID、逐序、逐类型一致——14 正例 + 6 负例（`expect` 只有 `expect_error`/`error_contains`），顺序同为 #1–#20。`packet_count` 约定值（12/12/10/10/12/12/10/14/10/14/12/12/24/16）为 P1 设计意图值，交付实测 = **11/11/9/9/11/11/9/9/9/10/9/9/22/11**（先跑后钉，§2 表后注）；#13 约定 24 已作废改 22。
2. **存量审计（§9.14）**：**交付后（v1.3.0）** `cases/spnego.json` = 20 个语义用例（14 正 + 6 负），占位已整体移除、旧扁平形期望值未搬运。P1–P3 期实测（保留备查）：仅 1 例占位 `spnego_neg_unregistered`（`proto=spnego`、`expect_error=true`、`error_contains="unknown layer"`、`spec_json` 顶层键 = `layers`+`src_ip`/`dst_ip`/`src_port`/`dst_port`，`layers`=`[{"tcp":{}},{"spnego":{}}]` 无 `ip` 层——旧扁平形），按 design §11.1 去向表改写。
3. **断言通道核对**：`spnego.*` **41** 字段已实证（精确口径 `tshark -G fields | awk -F'\t' '$3 ~ /^spnego\./' | wc -l`；`grep -c spnego`=43 = 41 + 2 协议行；细分 `spnego.krb5.*` 15 + `spnego.krb5_oid` 1 + `spnego.ContextFlags.*` 7 + 本体 18）；分流规则见 §3.1；**全用例禁 `decode_as`**（实测负收益）。字段名一律取自实测注册表，不自创（design §13 同款纪律）。
4. **勘误同步**：本文 §3 项 7 的 `NegTokenTarg` 字段序已与 design §10.3 H1 行对齐（RFC 2478 §3.2.1 原文实测）。
5. **packet_count 纪律**：§2 的约定值随注册后**先跑后钉**（§9.31/§14.6），以落盘 pcap 实测校准，不照抄本文约定值。

