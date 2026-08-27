# NTLM（NT LAN Manager，NT 局域网管理器）设计契约

> 版本：v1.0.0（设计阶段）  
> 日期：2026-08-20  
> 状态：仅设计与 PCAP（抓包文件）用例契约；`ntlm` 层尚未注册，不修改 Go（编程语言）实现，不宣称当前 suite（测试套件）可运行。  
> 配套文件：`docs/protocol-designs/60-ntlm-testcase.md`、`trafficgen/test/protocol_pcap/cases/ntlm.json`  
> 规范基线：MS-NLMP（NT LAN Manager Protocol）、MS-SMB2 §3.2.5.3 Session Setup、RFC 4178（SPNEGO，简单且受保护的协商机制）、RFC 4559（HTTP Negotiate）、RFC 2743（GSS-API）及 RFC 791/8200/793（IPv4/IPv6/TCP）。

## 1. 范围、profile（载体配置）和证据等级

本版定义 NTLMv2 的三消息认证交换：`NEGOTIATE_MESSAGE`（Type 1）、`CHALLENGE_MESSAGE`（Type 2）和 `AUTHENTICATE_MESSAGE`（Type 3），以及它们在 SMB2 Session Setup 或 HTTP `Negotiate` 中的载体边界。正例必须显式选择一个 profile，不能把两种载体拼成一个会话：

- **P-SMB**：SMB2 直接运行在 TCP/445 上；NTLMSSP token（令牌）位于 SMB2 `SESSION_SETUP` 的 SecurityBuffer。P-SMB 不生成 TCP/139 NetBIOS Session Service，也不把 SMB2 header 当成 NTLMSSP header。
- **P-HTTP**：HTTP/1.1 `401 WWW-Authenticate: Negotiate` → `Authorization: Negotiate <token>`，或服务器 `407 Proxy-Authenticate` → `Proxy-Authorization`。载体可以是明文 TCP/80，或 HTTPS TCP/443；选择 TLS（传输层安全）时，未解密 PCAP/NIC（网卡）只能观察 TCP/TLS，不能声称看见 HTTP 或 NTLM token。

HTTP 的 `Negotiate` token 可能是 SPNEGO 外层，SPNEGO 内部再选择 NTLMSSP；本设计不把 SPNEGO `negTokenInit/negTokenResp` 的 ASN.1（抽象语法标记）字段误判成 NTLMSSP 固定头。P-SMB 也可能使用 SPNEGO 包装，但必须由 fixture（固定样本）声明 `outer=spnego`；裸 NTLMSSP 与 SPNEGO 的边界分别验证。

当前仓库没有注册 `ntlm` layer、planner（规划器）、validator（校验器）或生成器。`cases/ntlm.json` 只保留一个 `ntlm_neg_unregistered` 注册前置占位，必须为 `expect_error=true` 且 `error_contains="unknown layer"`；占位不计入下文 20 个语义 ID。注册前的拒绝、0 包或空 PCAP 不是 NTLM 行为通过。

## 2. 推荐配置和层链

推荐链按载体选择：P-SMB 为 `[ip, tcp, ntlm]`，P-HTTP 为 `[ip, tcp, http, ntlm]`；IPv6 将 `ip` 替换为 `ipv6`。`ntlm.profile` 是必填语义配置，不允许由目标端口猜测：

```json
{
  "layers": [{"ip": {}}, {"tcp": {}}, {"ntlm": {}}],
  "src_ip": "192.0.2.60",
  "dst_ip": "198.51.100.60",
  "src_port": 45600,
  "dst_port": 445,
  "ntlm": {
    "profile": "smb2",
    "version": "ntlmv2",
    "outer": "none",
    "events": ["negotiate", "challenge", "authenticate", "session_setup_success"]
  }
}
```

| 配置键 | 约束 |
|---|---|
| `profile` | `smb2` 或 `http-negotiate`，决定外层 framing（成帧）和状态机；不能为空，不能混用。 |
| `outer` | `none` 或 `spnego`；SPNEGO 外层必须独立编码，不能把其 token 长度当 NTLM SecurityBuffer 长度。 |
| `src_ip`/`dst_ip`、端口 | P-SMB 目的端口为 445；P-HTTP 为 80/443（代理模式可为显式代理端口）；IPv4/IPv6 为独立 fixture。 |
| `version` | 本版正例为 NTLMv2 应用语义；NTLMSSP Version 字段只有声明 `NEGOTIATE_VERSION` 时出现，8 bytes，不能因版本名自动伪造。 |
| `messages`/`events` | 必须按 NEGOTIATE→CHALLENGE→AUTHENTICATE；HTTP 401/407 challenge 和 SMB2 Session Setup status 是载体事件，不替代三条 NTLM 消息。 |
| `flags` | Type 1/2/3 的 flags 必须协商一致；仅断言声明且可复核的 bits，不把未声明的 reserved bits 当能力。 |
| `target_info` | Type 2 的 security buffer 指向 AV_PAIR 序列；长度和 offset 必须覆盖实际 bytes。 |
| `ntlmv2_response` | Type 3 NT response 为 16-byte proof 加 blob；proof、时间戳、client challenge、session key 都是动态/密钥相关字段。 |
| `mic`/`encrypted_random_session_key` | 可选 MIC 为 16 bytes；EncryptedRandomSessionKey 长度由 SecurityBuffer 声明。无授权密钥不得生成或断言其值。 |
| `flow_count`/`session_id` | 每个认证会话独立 challenge、client challenge、message offsets、retry 和状态；不能跨流共享。 |
| `wire_fault` | 仅负例故障注入口：`message_length`、`security_buffer`、`offset_overflow`、`flags_target_info`、`blob_av_pairs`、`carrier_profile`。不是线上字段。 |

## 3. 载体边界和可观察偏移

NTLMSSP token 的固定起点必须由载体解析得到，不能固定假定为 IP 或 TCP payload 起点：

| profile | 线边界 | NTLMSSP 起点规则 |
|---|---|---|
| P-SMB | TCP/445 → SMB2 header（64 bytes）→ SessionSetup SecurityBuffer | `smb2.SessionSetup.SecurityBufferOffset/Length` 指向 SMB2 message；NTLMSSP signature 从该 buffer 起点开始。 |
| P-HTTP 明文 | TCP/80 → HTTP request/response headers → `Negotiate` token | token 是 base64（基于 64 个字符的编码）解码后的完整 NTLMSSP 或 SPNEGO bytes；HTTP header folding/重复 header 不可改变 token 边界。 |
| P-HTTP TLS | TCP/443 → TLS records → HTTP headers（需解密） | 未提供 key log（密钥日志）时只能断言 TCP/TLS carrier、方向和长度，不得断言 HTTP/NTLM 字段。 |

无 VLAN、IPv4 options、TCP options 时，TCP payload 参考起点为 Ethernet 14 + IPv4 20 + TCP 20 = 54；IPv6 参考起点为 14 + 40 + 20 = 74。该偏移仅是 carrier 参考，不是 NTLMSSP 起点。TCP segmentation（分段）可拆开任意 NTLM 消息，验证器必须先按载体长度重组 TCP stream（字节流），再解析 SecurityBuffer 和 NTLMSSP；不得按单个 TCP packet 截断。

P-SMB 的 SMB2 `SESSION_SETUP` SecurityBuffer 必须完整落在 SMB2 message 内；P-HTTP 的 `Negotiate` token 必须完整落在对应 HTTP header value 内。HTTP 401/407 challenge 与 SMB2 `STATUS_MORE_PROCESSING_REQUIRED` 是成功协商中的中间状态，不应误报为 NTLM 失败。

## 4. NTLMSSP 通用头和消息类型

每条 NTLMSSP message 从 `N` 开始，固定前缀为：

```text
Signature(8) = "NTLMSSP\\0" | MessageType(4, little-endian)
```

`MessageType` 为 1、2、3，字段宽度是 32-bit little-endian（小端）。Signature、Type 和后续 offsets 都相对于当前 NTLMSSP message 起点，不相对于 TCP packet、SMB2 message 或 HTTP header 起点。任何少于 12 bytes 的 token、错误 signature、未知 type 必须失败。

### 4.1 NEGOTIATE_MESSAGE（Type 1）

| 相对 offset | 宽度 | 字段 | 约束 |
|---:|---:|---|---|
| 0 | 8 | Signature | 固定 `NTLMSSP\\0`。 |
| 8 | 4 | MessageType | `01 00 00 00`。 |
| 12 | 4 | NegotiateFlags | little-endian；flags 需与后续 Type 2/3 能力交集一致。 |
| 16 | 8 | DomainNameFields | Len/MaxLen/Offset，通常可为零；若非零必须落在线上 payload。 |
| 24 | 8 | WorkstationFields | Len/MaxLen/Offset，通常可为零；若非零必须落在线上 payload。 |
| 32 | 8 | Version（可选） | 仅 `NEGOTIATE_VERSION` 置位时存在；版本字段不能跨 message 猜测。 |
| 40+ | n | Payload | Domain/Workstation 等 security buffer 指向的 bytes。 |

### 4.2 CHALLENGE_MESSAGE（Type 2）

| 相对 offset | 宽度 | 字段 | 约束 |
|---:|---:|---|---|
| 0 | 8 | Signature | 固定签名。 |
| 8 | 4 | MessageType | `02 00 00 00`。 |
| 12 | 8 | TargetNameFields | Len/MaxLen/Offset；可为空，但非空必须在 message 内。 |
| 20 | 4 | NegotiateFlags | ServerChallenge 与 Type 1 协商 flags；不能静默加入不支持能力。 |
| 24 | 8 | ServerChallenge | 8-byte 动态 nonce（随机数）；只能 `nonzero`，不得硬编码。 |
| 32 | 8 | Reserved | 必须为零或按 profile 明确保留，不得承载伪造 proof。 |
| 40 | 8 | TargetInfoFields | AV_PAIR bytes 的 Len/MaxLen/Offset；启用 NTLMv2 时通常非空。 |
| 48 | 8 | Version（可选） | `NEGOTIATE_VERSION` 置位时为 8 bytes。 |
| 56+ | n | Payload | TargetName 与 TargetInfo 的实际 bytes，顺序由 offsets 决定。 |

### 4.3 AUTHENTICATE_MESSAGE（Type 3）

| 相对 offset | 宽度 | 字段 | 约束 |
|---:|---:|---|---|
| 0 | 8 | Signature | 固定签名。 |
| 8 | 4 | MessageType | `03 00 00 00`。 |
| 12 | 8 | LmChallengeResponseFields | LM response security buffer；NTLMv2 profile 可声明 zero length，不得冒充 NT response。 |
| 20 | 8 | NtChallengeResponseFields | NT response security buffer；NTLMv2 至少 16-byte proof + blob。 |
| 28 | 8 | DomainNameFields | UTF-16LE（小端 Unicode）或按 Unicode flag 的编码；长度按 bytes。 |
| 36 | 8 | UserNameFields | 用户名 bytes；不含隐式 NUL。 |
| 44 | 8 | WorkstationFields | 工作站 bytes。 |
| 52 | 8 | EncryptedRandomSessionKeyFields | 可选加密随机会话密钥；无密钥只断言长度/边界。 |
| 60 | 4 | NegotiateFlags | 与 Type 2 兼容，不能改变已协商安全能力。 |
| 64 | 8 | Version（可选） | 仅 `NEGOTIATE_VERSION` 时出现。 |
| 72 | 16 | MIC（可选） | `NEGOTIATE_SIGN`/profile 声明时出现；值由密钥计算，不能猜测。 |
| 88+ | n | Payload | 上述 security buffers 的实际值，按 Offset/Length 读取。 |

实现可以省略可选 Version/MIC，但省略必须与 flags/profile 一致。Type 3 的 NT response 是认证证据，不得把固定样本 proof 复制到随机 challenge 会话。

## 5. Security Buffer（安全缓冲区）和 offset/length 规则

每个 security buffer 是 8 bytes：`Len(2) | MaxLen(2) | Offset(4)`，均为 little-endian。Len 是实际字节数，MaxLen 不得小于 Len，Offset 是相对 NTLMSSP message 起点的字节偏移。实现必须满足：

1. `Offset + Len` 不溢出 32-bit，且完全不超过 token 长度；Offset 不得落入固定 header 中间或落到另一个 message。
2. 空字段必须 `Len=0`；其 Offset 可为 0 或按实现约定，但验证器不应以空字段 offset 推导 payload。
3. 非空字段的 bytes 必须恰好可读；UTF-16 字段长度为偶数；NT response 的 Len 至少覆盖 16-byte proof 和完整 blob。
4. 不同字段允许按 profile 声明相邻或非相邻，但任意重叠、整数回绕、Offset 指向 token 外、Len 与承载长度不一致都必须失败。Padding 只能是显式 payload，不可被默默跳过。
5. 计算时使用宽整数并在边界检查后再切片；不得先把 32-bit offset 加长度截断成 16-bit/32-bit 后继续。

固定 header 的最小长度分别为 Type 1（至少 32 bytes，含可选字段按 flags）、Type 2（至少 48 bytes，含 TargetInfo 描述）、Type 3（至少 64 bytes；含可选字段时按 flags）。最小长度不是允许越界的默认值，实际 security buffer 仍必须在完整 token 内。

## 6. Flags、Version 和 TargetInfo

常见可观察 flags 包括 `NEGOTIATE_UNICODE=0x00000001`、`REQUEST_TARGET=0x00000004`、`NEGOTIATE_NTLM=0x00000200`、`NEGOTIATE_ALWAYS_SIGN=0x00008000`、`TARGET_TYPE_DOMAIN=0x00010000`、`NEGOTIATE_EXTENDED_SESSIONSECURITY=0x00080000`、`NEGOTIATE_TARGET_INFO=0x00800000`、`NEGOTIATE_VERSION=0x02000000`、`NEGOTIATE_128=0x20000000`、`NEGOTIATE_KEY_EXCH=0x40000000` 和 `NEGOTIATE_56=0x80000000`。flags 作为 little-endian 32-bit 集合编码；reserved/未知 bits 必须由 profile 明确，否则负例拒绝。

NTLMv2 需要 Type 2 TargetInfo security buffer 中的 AV_PAIR（属性值对）序列。每项为 `AvId(2) | AvLen(2) | Value(AvLen)`，little-endian；序列必须以 `MsvAvEOL=0x0000, AvLen=0` 结束。常见 `MsvAvNbComputerName=1`、`MsvAvNbDomainName=2`、`MsvAvDnsComputerName=3`、`MsvAvDnsDomainName=4`、`MsvAvDnsTreeName=5`、`MsvAvTimestamp=7`、`MsvAvFlags=6`、`MsvAvTargetName=9` 可按 fixture 声明。`AvLen` 只计 Value，不含 4-byte AV header；未知项可按 MS-NLMP 扩展保留，但不能越界或伪造 EOL。

ServerChallenge、MsvAvTimestamp、client challenge、Version、session key 等运行期值使用 presence、nonzero、same_as 或长度断言；不能把随机 nonce 或时间戳写成固定常量。

## 7. NTLMv2 response/blob、MIC 和 session key 边界

Type 3 `NtChallengeResponse` 的 NTLMv2 response 结构为：

```text
Proof(16) | ResponseVersion(1) | HiResponseVersion(1) | Reserved(2)
| TimeStamp(8) | ClientChallenge(8) | Reserved2(4) | AV_PAIR... | EOL(4)
```

Proof 是 HMAC-MD5（基于 HMAC 的 MD5 摘要）结果，验证依赖 NT hash/NTLMv2 key、ServerChallenge 和 blob；没有获授权的测试密钥时，PCAP/NIC 只能断言 proof 存在、长度为 16、不是全零（若 fixture 要求），不能伪造或验证 proof 值。Blob 的 timestamp 与 client challenge 是动态字段；AV_PAIR 必须按 §6 的 4-byte header/长度规则解析，最后有 EOL，且整个 blob 不得超过 NtChallengeResponse 的 Len。

MIC（Message Integrity Code，消息完整性码）为可选 16-byte 字段，计算输入涉及 Type 1、Type 2、Type 3（MIC 位置置零）和 exported session key（导出会话密钥）。无授权密钥不可生成 proof/MIC；有 key log 或受控 fixture 时，也只在明确记录算法、key 来源和解密条件后断言。`EncryptedRandomSessionKey` 是密钥相关的 opaque（不透明） bytes，必须通过 security buffer 边界观察，不能因为 `NEGOTIATE_KEY_EXCH` 就填入伪造值。

SMB signing/session key 派生、HTTP TLS 保护、SMB3 encryption 和 SPNEGO integrity 都不等于 NTLMv2 proof 本身。未解密 PCAP 的可见范围只到 carrier、token 长度、固定 headers、动态字段长度和 nonzero/presence；不可将解析器推测当作 proof/session key 证据。

## 8. SPNEGO 外层隔离

SPNEGO 外层使用 ASN.1 DER（区分编码规则）token，典型 HTTP `Negotiate` 值可能是 `negTokenInit`/`negTokenResp`，内部 `mechTypes`/`supportedMech` 选择 NTLM OID（对象标识符）`1.3.6.1.4.1.311.2.2.10`。NTLMSSP signature 只能在 SPNEGO 的 `mechToken`/`responseToken` 内部起点断言；不能把 ASN.1 tag/length 当作 NTLM Type 或 security buffer。

P-SMB 直接 NTLM 与 SPNEGO 包装分别计为不同 fixture；P-HTTP 的 `WWW-Authenticate`/`Authorization` header scheme 必须与 profile 一致。SPNEGO token 截断、内层 NTLM 截断或 OID 与 NTLM payload 不匹配应通过载体/outer 负例失败。

## 9. 会话状态、重试、失败和多流

基本状态为 `Initial → NegotiateSent → ChallengeReceived → AuthenticateSent → Accepted/Rejected`。P-SMB 中 Type 1/Type 3 位于连续 Session Setup request，Type 2 位于 `STATUS_MORE_PROCESSING_REQUIRED` response；成功后为 `STATUS_SUCCESS`。P-HTTP 中 Type 1 request 触发 401/407，Type 2 challenge 后的 Type 3 request 才能得到 2xx；401/407 的重复 challenge 不得推进为成功。

重试可以重新发送同一个 Type 1 或服务器 challenge，但必须明确是同一 session 的 retry；新 session 必须拥有独立 ServerChallenge、client challenge、security buffer 和状态。认证失败（STATUS_LOGON_FAILURE、HTTP 401/407 最终拒绝）必须传播 task error 或 rejected 终态，不能 `completed/0 packet`；失败后不能继续发送 authenticated SMB data/HTTP 2xx。

多会话可以共享目标端口但必须以 TCP 四元组或显式 `session_id` 隔离。多流/多 worker（工作进程）输出不保证全局包顺序，只保证每条 TCP stream 内重组后消息顺序和每个 session 的 challenge-response 关联一致。

## 10. 边界、异常和错误传播

至少覆盖：Type 1/2/3 最小头、可选 Version/MIC、空与非空 security buffer、Offset=0/最大附近、Len=0/最大附近、UTF-16 奇数长度、TargetInfo 多 AV_PAIR、EOL、NTLMv2 blob 的 proof/timestamp/client challenge、动态 challenge、SMB2 status、HTTP 401/407、SPNEGO 外层、IPv4/IPv6、TCP segmentation、重试和失败。

负例必须在 planner/validator 处失败并传播为 task error，不能输出成功 PCAP、`completed/0 packet` 或只剩 TCP/HTTP/SMB2 外壳的假成功。负例执行期 `expect` 只能包含 `expect_error` 与 `error_contains`。

| ID | 故障输入 | 目标 `error_contains` |
|---|---|---|
| `ntlm_neg_message_truncated` | Signature/Type 或 Type 1/2/3 固定字段截断 | `message`、`signature` 或 `truncated` |
| `ntlm_neg_security_buffer` | Len/MaxLen 不一致、非偶数 Unicode、空字段伪造或 token 截断 | `buffer`、`length` 或 `unicode` |
| `ntlm_neg_offsets_overlap_overflow` | Offset+Len 溢出、越界、固定头重叠或字段重叠 | `offset`、`overflow` 或 `overlap` |
| `ntlm_neg_flags_target_info` | flags 互不兼容、TargetInfo 缺失/越界、未知 reserved bits | `flags`、`target` 或 `capability` |
| `ntlm_neg_v2_blob_av_pairs` | proof/blob 长度错误、AV_PAIR 越界/缺 EOL/重复非法 | `response`、`blob` 或 `av` |
| `ntlm_neg_carrier_profile` | SMB/HTTP 混用、非 TCP 载体、错误端口、SPNEGO 边界错误 | `carrier`、`profile`、`spnego` 或 `transport` |

## 11. 20 个语义场景和 packet_count 映射

共 20 个唯一语义 ID：14 个正例、6 个负例；顺序必须与 `60-ntlm-testcase.md` §2 及未来注册后的 `ntlm.json` 完全一致。当前 JSON 只有不计数的注册前置占位。

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

## 12. PCAP/NIC 观察与实现完成定义

实现注册后先检查 `tshark -G fields | grep -E '\\t(ntlmssp|smb2|http|spnego)\\.'`。若环境没有 NTLM dissector（解析器），使用通用 `tcp.port`、`smb2`/`http`/`tls`、稳定 raw frames 和 token 长度/offset；不自创 `ntlm.*` 字段。明文 SMB/HTTP fixture 可对 signature、Type、固定 little-endian fields 和 security buffer bytes 断言；动态 challenge、timestamp、client challenge、proof、MIC、session key 只用 presence/nonzero/same_as/length。

PCAP 正例必须断言 profile、TCP 端口、方向、TCP stream、NTLMSSP signature/Type、载体 SecurityBuffer 或 HTTP scheme；P-SMB 还断言 SMB2 Session Setup status，P-HTTP 还断言 401/407→最终状态。P-HTTP/TLS 与 SMB3 encryption 未解密时只能断言 TLS/SMB carrier，不得声称看到 token。NIC 模式必须记录接口和过滤器 `tcp port 445` 或 `tcp port 80/443`，说明 checksum offload 与 TLS/SMB encryption 观察边界。

完成定义：注册 `ntlm` layer；逐字段验证三消息固定布局、little-endian security buffer、32-bit offset overflow、flags/TargetInfo、NTLMv2 blob/AV_PAIR、SPNEGO separation 和 SMB/HTTP 双 profile；planner→worker→TCP output 完整路径能传播正负结果；-race 和集成测试覆盖多会话/多流、重试/失败；未授权密钥下没有伪造 proof、MIC 或 session key。

三方契约必须保持本文 §11、`60-ntlm-testcase.md` §2、未来 `ntlm.json` 同一组 20 个语义 ID、同一顺序、14 正例+6 负例；当前 JSON 另有一个不计数的 `ntlm_neg_unregistered`，且唯一预期为 `unknown layer`。

## 13. 修订记录

- v1.0.0（2026-08-20）：建立 14 个 NTLMv2 正例和 6 个严格负例，覆盖 MS-NLMP 三消息、SecurityBuffer offset/length、flags/TargetInfo、NTLMv2 response/blob/AV_PAIR、MIC/session key opaque 边界、SMB2/HTTP Negotiate 双 profile、SPNEGO、IPv4/IPv6、多会话/多流、重试/失败、PCAP/NIC 和错误传播；不修改 Go 实现。
