# NTLM（NT LAN Manager，NT 局域网管理器）测试用例契约

> 版本：v1.0.0（设计阶段）  
> 日期：2026-08-20  
> 配套设计：`docs/protocol-designs/60-ntlm-design.md`  
> 机器契约：`trafficgen/test/protocol_pcap/cases/ntlm.json`  
> 状态：`ntlm` 层尚未注册；本文定义实现后的 PCAP（抓包文件）/NIC（网卡）断言，不宣称当前 suite（测试套件）可运行。

## 1. 测试原则和未注册边界

用例从设计 §2–§12 逐项派生，共 20 个唯一语义 ID：14 个正例和 6 个负例。当前 JSON 只保留一个不计入语义覆盖的注册前置占位 `ntlm_neg_unregistered`，其 `expect` 必须为 `expect_error=true`、`error_contains="unknown layer"`；注册后移除占位，再按本文 §2 顺序加入 20 个语义用例。

NTLMv2 必须显式选择 P-SMB 或 P-HTTP `Negotiate` profile。P-SMB 为 TCP/445 的 SMB2 Session Setup SecurityBuffer；P-HTTP 为 HTTP 401/407 challenge 与 Authorization/Proxy-Authorization token，可再选择 TLS。SPNEGO 外层 token 与 NTLMSSP 内层固定头分开验证。无授权密钥的 PCAP/NIC 只能断言固定头、类型、offset/length、flags、TargetInfo/AV_PAIR 边界及动态字段 presence/nonzero/same_as/长度；不能伪造 proof、MIC、时间戳、client challenge 或 session key 值。

正例实现后需要 `packet_count`/`min_packets`、可观察 carrier/stream/方向和稳定 raw frames（原始帧）；负例执行期 `expect` 只能包含 `expect_error`、`error_contains`。

## 2. 原子用例索引

| # | ID | 类型 | 覆盖 | 约定 packet_count |
|---:|---|---|---|---:|
| 1 | `ntlm_smb_ipv4_v2_basic` | 正 | P-SMB TCP/445、IPv4、Type 1→2→3、NTLMv2 成功 | 14 |
| 2 | `ntlm_smb_ipv6_v2_basic` | 正 | P-SMB TCP/445、IPv6 独立地址族和会话 | 14 |
| 3 | `ntlm_http_negotiate_v2` | 正 | P-HTTP 明文 TCP/80、401 Negotiate 和 Type 3 成功 | 14 |
| 4 | `ntlm_negotiate_flags_version` | 正 | flags 交集、可选 8-byte Version 和 Unicode 编码 | 12 |
| 5 | `ntlm_challenge_target_info` | 正 | Type 2 ServerChallenge、TargetInfo security buffer/AV pairs | 10 |
| 6 | `ntlm_authenticate_security_buffers` | 正 | Type 3 六类 security buffer 的 offset/length 关联 | 12 |
| 7 | `ntlm_ntlmv2_blob_av_pairs` | 正 | 16-byte proof、blob、timestamp/client challenge、AV EOL | 10 |
| 8 | `ntlm_mic_session_key_opaque` | 正 | MIC/session key 加密边界与无密钥 opaque 证据 | 12 |
| 9 | `ntlm_spnego_outer_separation` | 正 | HTTP 或 SMB 的 SPNEGO 外层与 NTLMSSP 内层隔离 | 14 |
| 10 | `ntlm_multi_session_isolation` | 正 | 多会话 challenge、blob、retry、结果独立 | 28 |
| 11 | `ntlm_multi_flow_streams` | 正 | 多 TCP stream/方向和 segmentation 后重组 | 18 |
| 12 | `ntlm_retry_auth_failure` | 正 | challenge 重试、最终 STATUS_LOGON_FAILURE/HTTP 401 | 18 |
| 13 | `ntlm_record_boundary_offsets` | 正 | 最小/最大附近 token、SecurityBuffer 边界和分段 | 8 |
| 14 | `ntlm_pcap_nic_consistency` | 正 | PCAP/NIC carrier、方向、端口和 token 长度一致 | 16 |
| 15 | `ntlm_neg_message_truncated` | 负 | 通用头或三类消息固定字段截断 | — |
| 16 | `ntlm_neg_security_buffer` | 负 | SecurityBuffer 长度/编码/承载不合法 | — |
| 17 | `ntlm_neg_offsets_overlap_overflow` | 负 | offset 越界、溢出或字段重叠 | — |
| 18 | `ntlm_neg_flags_target_info` | 负 | flags/TargetInfo 协商不一致 | — |
| 19 | `ntlm_neg_v2_blob_av_pairs` | 负 | NTLMv2 response/blob/AV_PAIR 不合法 | — |
| 20 | `ntlm_neg_carrier_profile` | 负 | SMB/HTTP/SPNEGO/TCP profile 载体错误 | — |

## 3. 正例逐项断言契约

1. **`ntlm_smb_ipv4_v2_basic`**：P-SMB 使用 IPv4/TCP/445，完成 SYN/SYN-ACK/ACK、SMB2 Session Setup Type 1、`STATUS_MORE_PROCESSING_REQUIRED` Type 2、Type 3 和 `STATUS_SUCCESS`；断言每条 SecurityBuffer 的 carrier offset/length、NTLMSSP signature/type，动态 challenge/proof 只用 presence/nonzero/length，`packet_count=14`。
2. **`ntlm_smb_ipv6_v2_basic`**：独立 IPv6/TCP/445 session，断言 IPv6 next-header、地址族、SMB2 Session Setup 与 Type 1→2→3 顺序，不能复用 IPv4 的 challenge 或 stream，`packet_count=14`。
3. **`ntlm_http_negotiate_v2`**：明文 HTTP/TCP/80，服务端 401 `WWW-Authenticate: Negotiate`，客户端 Authorization Type 1，服务器 challenge Type 2，客户端 Type 3，最终 2xx；断言 header scheme/token 边界、TCP stream 和消息顺序，`packet_count=14`。
4. **`ntlm_negotiate_flags_version`**：Type 1/2/3 的 32-bit little-endian flags 具备兼容交集；声明 `NEGOTIATE_VERSION` 时逐字节观察 8-byte Version，Unicode security buffer 长度为偶数，`packet_count=12`；不把未声明 Version 自动插入。
5. **`ntlm_challenge_target_info`**：Type 2 的 ServerChallenge 为 8-byte nonzero 动态值；TargetInfo SecurityBuffer 完整指向 AV_PAIR 序列，所有 AvLen 覆盖 value 且以 `MsvAvEOL=0, len=0` 结束，`packet_count=10`。
6. **`ntlm_authenticate_security_buffers`**：Type 3 逐项验证 LM/NT/domain/user/workstation/encrypted-session-key 六类 SecurityBuffer 的 Len/MaxLen/Offset；NT response 至少有 16-byte proof，字段不重叠且均落在 token 内，动态值只断言长度/presence，`packet_count=12`。
7. **`ntlm_ntlmv2_blob_av_pairs`**：NT response 为 16-byte proof + NTLMv2 blob；断言 response version、8-byte timestamp、8-byte client challenge、AV_PAIR 的 4-byte header/边界/EOL，proof 与 challenge 不硬编码，`packet_count=10`。
8. **`ntlm_mic_session_key_opaque`**：声明 MIC 或 EncryptedRandomSessionKey 的 fixture 断言 16-byte MIC/安全缓冲区长度和 opaque bytes 边界；无授权密钥不比较 proof/MIC/session-key 内容，不把 `NEGOTIATE_KEY_EXCH` 当作值证据，`packet_count=12`。
9. **`ntlm_spnego_outer_separation`**：HTTP 或 SMB 使用 SPNEGO，断言 ASN.1 outer token 的 mech OID 与 inner NTLMSSP signature/type 分界；不能把 outer tag/length 当 SecurityBuffer，`packet_count=14`。
10. **`ntlm_multi_session_isolation`**：至少两个并行 SMB 或 HTTP sessions，各有独立四元组、ServerChallenge、client challenge、SecurityBuffer 和结果；断言每个 stream 内 Type 1→2→3，跨 session 不使用 same_as，`packet_count=28`。
11. **`ntlm_multi_flow_streams`**：多个 TCP streams、双向流和 TCP segmentation，将 Type 1/2/3 拆在多个 segments 后重组；断言按 stream 恢复 token、offset 相对 NTLMSSP 起点，不能按单 packet 截断，`packet_count=18`。
12. **`ntlm_retry_auth_failure`**：覆盖 `STATUS_MORE_PROCESSING_REQUIRED`/HTTP 401 challenge 重试及最终 `STATUS_LOGON_FAILURE` 或 401 拒绝；重试不重复推进成功状态，失败后无 authenticated data/2xx，动态 challenge 使用 distinct/presence，`packet_count=18`。
13. **`ntlm_record_boundary_offsets`**：覆盖 Type 1/2/3 最小合法头、Len=0 空字段和最大附近 token，断言 Offset+Len 不溢出且完全落在 token 内、UTF-16 长度为偶数、分段重组后长度一致，`packet_count=8`。
14. **`ntlm_pcap_nic_consistency`**：同一 P-SMB 或 P-HTTP fixture 分别输出 PCAP 并在指定 NIC 捕获；两者断言 TCP profile 端口、方向、stream、NTLMSSP Type 和 token 长度一致。过滤器为 `tcp port 445` 或 `tcp port 80/443`，记录 checksum offload/TLS 加密边界，`packet_count=16`。

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

- v1.0.0（2026-08-20）：建立 14 个 NTLMv2 正例和 6 个严格负例，覆盖 MS-NLMP 三消息、SecurityBuffer offset/length、flags/TargetInfo、NTLMv2 response/blob/AV_PAIR、MIC/session key opaque 边界、SMB2/HTTP Negotiate 双 profile、SPNEGO、IPv4/IPv6、多会话/多流、重试/失败、PCAP/NIC 和错误传播；不修改 Go 实现。
