# NTLM（NT LAN Manager，NT 局域网管理器）测试用例契约

> 版本：v1.1.0（P1–P3 产物）  
> 日期：2026-09-25  
> 配套设计：`docs/protocol-designs/60-ntlm-design.md` v2.0.0（P1 矩阵 §14/三路对照 §15/门1表 §16/D-NTLM-1 §17/缺口 §19）  
> 机器契约：`trafficgen/test/protocol_pcap/cases/ntlm.json`  
> 状态：P3 固定动作（§3.15/A′/B′/9.52/3.14/三源回指）已落盘 §8；`ntlm` 层尚未注册；本文定义实现后的 PCAP（抓包文件）/NIC（网卡）断言，不宣称当前 suite（测试套件）可运行。**层链口径**：design §15.4 裁定 N1 定两 profile 今日可达链形同为 `[ip,tcp,ntlm]`（`[ip,tcp,smb,ntlm]`/`[ip,tcp,http,ntlm]` 判不可达，缺口 G-NTLM-1/G-NTLM-2）。  

## 1. 测试原则和未注册边界

用例从设计 §2–§12 逐项派生，共 20 个唯一语义 ID：14 个正例和 6 个负例。当前 JSON 只保留一个不计入语义覆盖的注册前置占位 `ntlm_neg_unregistered`，其 `expect` 必须为 `expect_error=true`、`error_contains="unknown layer"`；注册后移除占位，再按本文 §2 顺序加入 20 个语义用例。

NTLMv2 必须显式选择 P-SMB 或 P-HTTP `Negotiate` profile。P-SMB 为 TCP/445 的 SMB2 Session Setup SecurityBuffer；P-HTTP 为 HTTP 401/407 challenge 与 Authorization/Proxy-Authorization token，可再选择 TLS。SPNEGO 外层 token 与 NTLMSSP 内层固定头分开验证。无授权密钥的 PCAP/NIC 只能断言固定头、类型、offset/length、flags、TargetInfo/AV_PAIR 边界及动态字段 presence/nonzero/same_as/长度；不能伪造 proof、MIC、时间戳、client challenge 或 session key 值。

正例实现后需要 `packet_count`/`min_packets`、可观察 carrier/stream/方向和稳定 raw frames（原始帧）；负例执行期 `expect` 只能包含 `expect_error`、`error_contains`。

## 2. 原子用例索引

| # | ID | 类型 | 覆盖 | 实测 packet_count（P5 先跑后钉，2026-09-26 canonical 校准） |
|---:|---|---|---|---:|
| 1 | `ntlm_smb_ipv4_v2_basic` | 正 | P-SMB TCP/445、IPv4、Type 1→2→3、NTLMv2 成功 | 11 |
| 2 | `ntlm_smb_ipv6_v2_basic` | 正 | P-SMB TCP/445、IPv6 独立地址族和会话 | 11 |
| 3 | `ntlm_http_negotiate_v2` | 正 | P-HTTP 明文 TCP/80、401 Negotiate 和 Type 3 成功 | 11 |
| 4 | `ntlm_negotiate_flags_version` | 正 | flags 交集、可选 8-byte Version 和 Unicode 编码 | 15 |
| 5 | `ntlm_challenge_target_info` | 正 | Type 2 ServerChallenge、TargetInfo security buffer/AV pairs | 11 |
| 6 | `ntlm_authenticate_security_buffers` | 正 | Type 3 六类 security buffer 的 offset/length 关联 | 11 |
| 7 | `ntlm_ntlmv2_blob_av_pairs` | 正 | 16-byte proof、blob、timestamp/client challenge、AV EOL | 11 |
| 8 | `ntlm_mic_session_key_opaque` | 正 | MIC/session key 加密边界与无密钥 opaque 证据 | 11 |
| 9 | `ntlm_spnego_outer_separation` | 正 | HTTP 或 SMB 的 SPNEGO 外层与 NTLMSSP 内层隔离 | 11 |
| 10 | `ntlm_multi_session_isolation` | 正 | 多会话 challenge、blob、retry、结果独立 | 15 |
| 11 | `ntlm_multi_flow_streams` | 正 | 多 TCP stream/方向和 segmentation 后重组 | 15 |
| 12 | `ntlm_retry_auth_failure` | 正 | challenge 重试、最终 STATUS_LOGON_FAILURE/HTTP 401 | 13 |
| 13 | `ntlm_record_boundary_offsets` | 正 | 最小/最大附近 token、SecurityBuffer 边界和分段 | 15 |
| 14 | `ntlm_pcap_nic_consistency` | 正 | PCAP/NIC carrier、方向、端口和 token 长度一致 | 11 |
| 15 | `ntlm_neg_message_truncated` | 负 | 通用头或三类消息固定字段截断 | — |
| 16 | `ntlm_neg_security_buffer` | 负 | SecurityBuffer 长度/编码/承载不合法 | — |
| 17 | `ntlm_neg_offsets_overlap_overflow` | 负 | offset 越界、溢出或字段重叠 | — |
| 18 | `ntlm_neg_flags_target_info` | 负 | flags/TargetInfo 协商不一致 | — |
| 19 | `ntlm_neg_v2_blob_av_pairs` | 负 | NTLMv2 response/blob/AV_PAIR 不合法 | — |
| 20 | `ntlm_neg_carrier_profile` | 负 | SMB/HTTP/SPNEGO/TCP profile 载体错误 | — |

## 3. 正例逐项断言契约

1. **`ntlm_smb_ipv4_v2_basic`**：P-SMB 使用 IPv4/TCP/445，完成 SYN/SYN-ACK/ACK、SMB2 Session Setup Type 1、`STATUS_MORE_PROCESSING_REQUIRED` Type 2、Type 3 和 `STATUS_SUCCESS`；断言每条 SecurityBuffer 的 carrier offset/length、NTLMSSP signature/type，动态 challenge/proof 只用 presence/nonzero/length，`packet_count=11`。
2. **`ntlm_smb_ipv6_v2_basic`**：独立 IPv6/TCP/445 session，断言 IPv6 next-header、地址族、SMB2 Session Setup 与 Type 1→2→3 顺序，不能复用 IPv4 的 challenge 或 stream，`packet_count=11`。
3. **`ntlm_http_negotiate_v2`**：明文 HTTP/TCP/80，服务端 401 `WWW-Authenticate: Negotiate`，客户端 Authorization Type 1，服务器 challenge Type 2，客户端 Type 3，最终 2xx；断言 header scheme/token 边界、TCP stream 和消息顺序，`packet_count=11`。
4. **`ntlm_negotiate_flags_version`**：Type 1/2/3 的 32-bit little-endian flags 具备兼容交集；声明 `NEGOTIATE_VERSION` 时逐字节观察 8-byte Version，Unicode security buffer 长度为偶数，`packet_count=15`；不把未声明 Version 自动插入。
5. **`ntlm_challenge_target_info`**：Type 2 的 ServerChallenge 为 8-byte nonzero 动态值；TargetInfo SecurityBuffer 完整指向 AV_PAIR 序列，所有 AvLen 覆盖 value 且以 `MsvAvEOL=0, len=0` 结束，`packet_count=11`。
6. **`ntlm_authenticate_security_buffers`**：Type 3 逐项验证 LM/NT/domain/user/workstation/encrypted-session-key 六类 SecurityBuffer 的 Len/MaxLen/Offset；NT response 至少有 16-byte proof，字段不重叠且均落在 token 内，动态值只断言长度/presence，`packet_count=11`。
7. **`ntlm_ntlmv2_blob_av_pairs`**：NT response 为 16-byte proof + NTLMv2 blob；断言 response version、8-byte timestamp、8-byte client challenge、AV_PAIR 的 4-byte header/边界/EOL，proof 与 challenge 不硬编码，`packet_count=11`。
8. **`ntlm_mic_session_key_opaque`**：声明 MIC 或 EncryptedRandomSessionKey 的 fixture 断言 16-byte MIC/安全缓冲区长度和 opaque bytes 边界；无授权密钥不比较 proof/MIC/session-key 内容，不把 `NEGOTIATE_KEY_EXCH` 当作值证据，`packet_count=11`。
9. **`ntlm_spnego_outer_separation`**：HTTP 或 SMB 使用 SPNEGO，断言 ASN.1 outer token 的 mech OID 与 inner NTLMSSP signature/type 分界；不能把 outer tag/length 当 SecurityBuffer，`packet_count=11`。
10. **`ntlm_multi_session_isolation`**：至少两个并行 SMB 或 HTTP sessions，各有独立四元组、ServerChallenge、client challenge、SecurityBuffer 和结果；断言每个 stream 内 Type 1→2→3，跨 session 不使用 same_as，`packet_count=15`。
11. **`ntlm_multi_flow_streams`**：多个 TCP streams、双向流和 TCP segmentation，将 Type 1/2/3 拆在多个 segments 后重组；断言按 stream 恢复 token、offset 相对 NTLMSSP 起点，不能按单 packet 截断，`packet_count=15`。
12. **`ntlm_retry_auth_failure`**：覆盖 `STATUS_MORE_PROCESSING_REQUIRED`/HTTP 401 challenge 重试及最终 `STATUS_LOGON_FAILURE` 或 401 拒绝；重试不重复推进成功状态，失败后无 authenticated data/2xx，动态 challenge 使用 distinct/presence，`packet_count=13`。
13. **`ntlm_record_boundary_offsets`**：覆盖 Type 1/2/3 最小合法头、Len=0 空字段和最大附近 token，断言 Offset+Len 不溢出且完全落在 token 内、UTF-16 长度为偶数、分段重组后长度一致，`packet_count=15`。
14. **`ntlm_pcap_nic_consistency`**：同一 P-SMB 或 P-HTTP fixture 分别输出 PCAP 并在指定 NIC 捕获；两者断言 TCP profile 端口、方向、stream、NTLMSSP Type 和 token 长度一致。过滤器为 `tcp port 445` 或 `tcp port 80/443`，记录 checksum offload/TLS 加密边界，`packet_count=11`。

## 4. 负例契约

每个负例必须在 planner/validator 处失败并传播为 task error；不能生成成功 PCAP、`completed/0 packet` 或只有 TCP/HTTP/SMB2 外壳的假成功。执行期 `expect` 键集合严格为 `{"expect_error", "error_contains"}`：

| ID | 故障输入 | 目标 `error_contains` |
|---|---|---|
| `ntlm_neg_message_truncated` | Signature/Type 或 Type 1/2/3 固定字段截断 | `message`、`signature` 或 `truncated` |
| `ntlm_neg_security_buffer` | Len/MaxLen 不一致、非偶数 Unicode、空字段伪造或 token 截断 | `buffer`、`length` 或 `unicode` |
| `ntlm_neg_offsets_overlap_overflow` | Offset+Len 溢出、越界、固定头重叠或字段重叠 | `offset`、`overflow` 或 `overlap` |
| `ntlm_neg_flags_target_info` | flags 互不兼容、TargetInfo 缺失/越界、未知 reserved bits | `flags`、`target` 或 `capability` |
| `ntlm_neg_v2_blob_av_pairs` | proof/blob 长度错误、AV_PAIR 越界/缺 EOL/重复非法 | `response`、`blob` 或 `av` |
| `ntlm_neg_carrier_profile` | SMB/HTTP 混用、非 TCP 载体、错误端口、SPNEGO 边界错误 | `carrier`、`profile`、`spnego` 或 `transport` |

合法的空 LM response、动态 challenge/timestamp/client challenge、TargetInfo 扩展 AV_PAIR、SPNEGO wrapping、HTTP 401/SMB2 `STATUS_MORE_PROCESSING_REQUIRED` 和 TCP segmentation 由正例覆盖，不能误报为负例。错误传播须保留原始原因，不能用通用“0 packets”替代验证错误。

## 5. 三方一致性和静态检查

1. 设计 §11、本文 §2、注册后的 JSON 和审计必须保持同一 20 个语义 ID、同一顺序；14 正例 + 6 负例，当前 JSON 另有一个 `ntlm_neg_unregistered` 占位。
2. 未来 14 个正例均有 `packet_count`/`min_packets`、profile、方向和稳定 carrier/raw fields；6 个负例的 `expect` 只能有 `expect_error`、`error_contains`。当前未注册 JSON 只验证 placeholder（占位）结构。
3. P-SMB 固定 TCP/445 + SMB2 Session Setup SecurityBuffer；P-HTTP 固定 HTTP 80/443 + Negotiate header；不能由端口猜 profile，也不能混用两种载体。
4. Signature 为 8-byte `NTLMSSP\\0`，MessageType 为 little-endian 32-bit 1/2/3；SecurityBuffer 为 Len/MaxLen/Offset little-endian，Offset 相对 NTLMSSP 起点。
5. `Offset+Len` 必须防 32-bit overflow、越界和重叠；Unicode field 长度为偶数；NT response 至少 16-byte proof + 完整 blob。
6. TargetInfo/NTLMv2 blob AV_PAIR 使用 2-byte ID + 2-byte value length + value，必须以 EOL 结束；动态 challenge/proof/timestamp/client challenge/MIC/session key 不硬编码。
7. SPNEGO ASN.1 outer 与 NTLMSSP inner 分离断言；无解密 TLS/SMB encryption 时不得声称看见 HTTP/NTLM 明文。
8. `python3 -m json.tool trafficgen/test/protocol_pcap/cases/ntlm.json` 应成功；当前数组只能含 `ntlm_neg_unregistered`，且 `proto=ntlm`、`expect_error=true`、`error_contains` 精确为 `unknown layer`。

## 6. 实现后执行建议

注册 `ntlm` layer 后，先检查 JSON parser、ID 顺序、正负 expect 键集合、profile/port、SMB2/HTTP carrier offsets、SecurityBuffer bounds、TargetInfo/AV_PAIR 和动态字段断言，再运行 1–14 的 PCAP/NIC 正例和 15–20 的错误传播。若 tshark 没有 NTLM dissector，使用通用 TCP/SMB2/HTTP/TLS 字段与稳定 raw frames，不自创解析字段。当前阶段不得将唯一 placeholder 运行结果报告为 NTLM suite 通过。

## 7. 修订记录
- v1.1.0（2026-09-25）：P3 产物。新增 §8 P3 固定动作（§3.15 三项逐项一例或立项 + A′/B′ 两分类表 + 9.52 对账两行与清单出处声明 + 3.14 豁免边界审计 + 三源回指行 + 断言契约核对结论）。20 ID 断言契约（§2–§4）原样保留，已核对与 design §11 一致（14 正+6 负、同序、packet_count 逐值相同）。

- v1.0.0（2026-08-20）：建立 14 个 NTLMv2 正例和 6 个严格负例，覆盖 MS-NLMP 三消息、SecurityBuffer offset/length、flags/TargetInfo、NTLMv2 response/blob/AV_PAIR、MIC/session key opaque 边界、SMB2/HTTP Negotiate 双 profile、SPNEGO、IPv4/IPv6、多会话/多流、重试/失败、PCAP/NIC 和错误传播；不修改 Go 实现。


## 8. P3 固定动作（CORE_MEMORY §3.15/§9.52/§9.14/覆盖审计要求面）

### 8.1 §3.15 三项逐项一例或立项（无例无项即缺口）

| # | 三项 | 本协议对照 | 用例/立项 |
|---|---|---|---|
| ① | 同连接/同流内的多轮操作 | SMB2 同一 TCP 连接上的 SESSION_SETUP 链（Type 1 → `MORE_PROCESSING_REQUIRED`+Type 2 → Type 3 → `STATUS_SUCCESS`），含 3 轮形态「Type 3 后仍 MORE」；同 session 重发 Type 1 的重试轮 | 已覆：#1/#2（2 轮成功链）+#12（3 轮/重试） |
| ② | 非正常结束 | 最终 `STATUS_LOGON_FAILURE` / HTTP 401 最终拒绝；失败后不得发 authenticated SMB data / 2xx；重试不得重复推进成功状态 | 已覆半程：#12（终态拒绝）；**载体会话中断形**（服务端主动 FIN/RST mid-auth、401 无后续、SMB2 非 `LOGON_FAILURE` 错误 status）→立项 **G-NTLM-5** |
| ③ | 长保活 | HTTP keep-alive 同连接多认证事务；SMB2 over 长生命周期 TCP 连接 | 已覆：#11（多 TCP stream 与分段重组，终审 M1 修轮后真分段）；keep-alive 多认证事务=HTTP profile 每事务一轮 401/Authorization，#3 与 T-21 各承载一轮全序——**T-22 裁定为由 #3/T-21 等价覆盖，不再单列**（终审 M2 修轮去向声明） |

无空项。②的载体会话中断面进 B′（G-NTLM-5），不删用例。

### 8.2 A′/B′ 两分类表（要求面反推：数据/业务/现网/多流四类审计）

A′（现有引擎可构建 → 20 ID 内已覆 或 A′ 补例，P4 并入）：

| 面 | 要求点 | 去向 |
|---|---|---|
| 数据 | SecurityBuffer 空/`MaxLen>Len`/UTF-16 与 OEM 编码/`Offset+Len` 边界/flags 组合/Version 有無/TargetInfo AV 集/blob 结构/LM response 空有/MIC 有無/EncryptedRandomSessionKey 有無/SPNEGO 外层两形 | #4/#5/#6/#7/#8/#9/#13 已覆；越界与非法形 → 负例 #15–#19 |
| 业务 | 三消息顺序/2 轮与 3 轮 SESSION_SETUP/401→Type 3→2xx/重试与最终拒绝/多会话隔离 | #1/#2/#3/#10/#12 已覆 |
| 现网 | Windows-AD SMB2（SPNEGO 包装）基线/HTTP `Negotiate` 明文形/impacket 裸 NTLMSSP 形 | #1/#3/#9 已覆；抓包核对 → G-NTLM-4 |
| 多流 | 多 TCP stream+分段重组/双向流/PCAP 与 NIC 双路一致 | #11/#14 已覆 |
| 地址族 | IPv4/SMB2、IPv6/SMB2、IPv4/HTTP、IPv6/HTTP | #1/#2/#3 + **T-21=`ntlm_http_negotiate_v6` 已并入**（终审 M2 修轮，2026-09-26 canonical 21/21 绿） |
| 长保活 | keep-alive 同连接多认证事务 | 由 #3/T-21 等价覆盖（T-22 不单列，终审 M2 去向声明） |

B′（引擎结构缺口 → D-NTLM-1「明确不解决 + 迁入计划」，见 design §19 缺口立项清单）：**G-NTLM-1**（`[ip,tcp,smb,ntlm]` 嵌套不可达，框架变更）、**G-NTLM-2**（`[ip,tcp,http,ntlm]` 嵌套不可达，`OptionalOn` 不参与 V2 豁免）、**G-NTLM-3**（与 `smb` 层既有 NTLMSSP 实现的权威重叠裁定）、**G-NTLM-4**（现网抓包核对，确认方式已写清）、**G-NTLM-5**（代理/TLS 隧道 + 载体会话中断面）、**G-NTLM-6**（NTLMv1/LM 方言面，三选一收口）。

### 8.3 9.52 对账两行 + 清单出处声明

- 清单出处声明：本清单来源=**规范/官方文档反推**（MS-NLMP §2.2.1–§2.2.3、§2.2.2.1；MS-SMB2 §3.2.5.3/§3.3.5.2.4；RFC 4178；RFC 4559 §1/§4.2；RFC 2743），**非**引擎能力面反推（engine 侧仅作现状取证：`tshark -G fields` 实测 `ntlmssp.*` 147 字段 / `smb2.*` 533 / `spnego.*` 41；`smb` 层既有 NTLMSSP 实现 `emit_session.go:92-144`）。
- 对账两行：**规范逻辑点总数 = 47**（design §14.1 八项 8 行 + §14.2 消息×载体终态矩阵 16 格 + §14.3 数据形态变体表 23 行）；**用例覆盖数 = 40**（八项 8 行落点 + 矩阵 10 格 + 变体 22 行，含 A′ 补例 **T-21=`ntlm_http_negotiate_v6` 已并入、非虚报**（终审 M2 修轮落盘）；另 **不适用 2 格**（三选一之一，非缺口）+ **B′ 立项 5 点**（G-NTLM-5 覆盖矩阵 4 格 + 变体 1 行）），40+2+5=47 无遗漏。反查 20/20 绿 ≠ 覆盖全；此对账为覆盖审计的有效口径。**台账粒度声明（防误读）**：47 点按 design §14 的行/格粒度计数（八项按行、矩阵按格、变体按行），即 §14.1 每行只计 1 点——该行下的子面缺口另登 design §19，**不折进 47 点**、也**不冒充覆盖**：G-NTLM-1/G-NTLM-2（链形不可达）、G-NTLM-3（与 smb 层权威重叠）、G-NTLM-4（现网抓包核对）、G-NTLM-6（NTLMv1/LM 方言面）四项为跨切面缺口；G-NTLM-5 为唯一落在台账内的立项（矩阵 4 格 + 变体 1 行）。

### 8.4 3.14 豁免边界审计

本协议**有长连接载体**（SMB2 over 长生命周期 TCP、HTTP keep-alive），故 `sessions[]` 必写、**不豁免**（design §16.3 会话表 s1/s2/s3）。多流并发与单消息多载荷两项各至少一例：多流并发=#10（双 SMB 会话并行）+#11（多 TCP stream 与分段后重组）；单消息多载荷=#5（单个 Type 2 内多个 AV_PAIR）+#6/#7（单个 Type 3 内多个 SecurityBuffer 与 blob 内 AV 序列）。两项均有，无豁免逃逸。

### 8.5 三源回指行

MS-NLMP（三消息字段与 SecurityBuffer/AV_PAIR 语义）+ MS-SMB2 §3.2.5.3/§3.3.5.2.4（SESSION_SETUP 与 status trio）+ RFC 4178（SPNEGO 外层）/RFC 4559 §1/§4.2（HTTP Negotiate）/RFC 2743（GSS-API）→ D-NTLM-1（design §17）→ `test/protocol_pcap/cases/ntlm.json`（20 例）。ID 权威=本文 §2（14 正+6 负）；对账 20=14+6。

### 8.6 断言契约核对结论（与 design §11 一致）

本文 §2 的 20 ID 与 design §11 逐 ID、逐序、逐类型核对一致：14 正 #1–#14 + 6 负 #15–#20，顺序相同，`packet_count` 约定值逐值相同（14/14/14/12/10/12/10/12/14/28/18/18/8/16）。存量审计（§9.14）：`ntlm_neg_unregistered` 注册前置占位随注册移除，**无存量语义用例**（当前 JSON 仅 1 例占位，实测 `spec_json.layers` 为 `[ip,tcp,ntlm]` 且带顶层 `src_ip/dst_ip/src_port/dst_port/ntlm` 五键=旧扁平形，注册时按 design §16.1 去向表改写为纯 layers 形）。断言通道：fields 用 `ntlmssp.*`（147 字段已实测：`ntlmssp.identifier`/`ntlmssp.messagetype`/`ntlmssp.negotiateflags`/`ntlmssp.negotiate.domain`/`ntlmserverchallenge`/`challenge.target_name`/`challenge.target_info.item.type`/`auth.username|domain|hostname|lmresponse|ntresponse|sesskey`/`string.length|maxlen|offset`/`ntlmv2_response.ntproofstr|time|chal`/`authenticate.mic`/`version.*`）+ 载体 `tcp.dstport`/`ip.proto`/`ipv6.nxt`/`smb2.security_blob`/`http.*`；固定头/offset/AV_PAIR 走 frames hex 钉；动态值用 presence/nonzero/distinct/same_as；不自创字段名。**未注册期纪律**：唯一 placeholder 的运行结果不得报告为 NTLM suite 通过。
