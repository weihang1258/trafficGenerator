# NTLM（NT LAN Manager，NT 局域网管理器）设计契约

> 版本：v2.0.0（P1–P3 产物）  
> 日期：2026-09-25  
> 状态：P1 规范矩阵（§14）+ 三路对照与候选方案对比（§15）+ 门1 §1–§14 十四行表（§16，含 §1/§3/§12 强制展开）+ P2 D-NTLM-1 代码设计（§17）+ P3 对接清单与缺口立项（§18/§19）已落盘；`ntlm` 层尚未注册，不修改 Go（编程语言）实现，不宣称当前 suite（测试套件）可运行。**层链裁定 N1（框架修 0c355be 后更新）**：P-SMB 链形 `[ip,tcp,ntlm]`；P-HTTP 链形 `[ip,tcp,http,ntlm]`（`OptionalOn ["http"]` 底座豁免已由 `complete.go` 实装，2026-09-25 commit 0c355be）。v1.0.0 §2 顶层扁平示例作废；`[ip,tcp,smb,ntlm]` 仍判不可达（G-NTLM-1）。P4 落码前 D-NTLM-1 以门1 获批版为准。  
> 配套文件：`docs/protocol-designs/60-ntlm-testcase.md`、`trafficgen/test/protocol_pcap/cases/ntlm.json`  
> 规范基线：MS-NLMP（NT LAN Manager Protocol）、MS-SMB2 §3.2.5.3 Session Setup、RFC 4178（SPNEGO，简单且受保护的协商机制）、RFC 4559（HTTP Negotiate）、RFC 2743（GSS-API）及 RFC 791/8200/793（IPv4/IPv6/TCP）。

## 1. 范围、profile（载体配置）和证据等级

本版定义 NTLMv2 的三消息认证交换：`NEGOTIATE_MESSAGE`（Type 1）、`CHALLENGE_MESSAGE`（Type 2）和 `AUTHENTICATE_MESSAGE`（Type 3），以及它们在 SMB2 Session Setup 或 HTTP `Negotiate` 中的载体边界。正例必须显式选择一个 profile，不能把两种载体拼成一个会话：

- **P-SMB**：SMB2 直接运行在 TCP/445 上；NTLMSSP token（令牌）位于 SMB2 `SESSION_SETUP` 的 SecurityBuffer。P-SMB 不生成 TCP/139 NetBIOS Session Service，也不把 SMB2 header 当成 NTLMSSP header。
- **P-HTTP**：HTTP/1.1 `401 WWW-Authenticate: Negotiate` → `Authorization: Negotiate <token>`，或服务器 `407 Proxy-Authenticate` → `Proxy-Authorization`。载体可以是明文 TCP/80，或 HTTPS TCP/443；选择 TLS（传输层安全）时，未解密 PCAP/NIC（网卡）只能观察 TCP/TLS，不能声称看见 HTTP 或 NTLM token。

HTTP 的 `Negotiate` token 可能是 SPNEGO 外层，SPNEGO 内部再选择 NTLMSSP；本设计不把 SPNEGO `negTokenInit/negTokenResp` 的 ASN.1（抽象语法标记）字段误判成 NTLMSSP 固定头。P-SMB 也可能使用 SPNEGO 包装，但必须由 fixture（固定样本）声明 `outer=spnego`；裸 NTLMSSP 与 SPNEGO 的边界分别验证。

当前仓库没有注册 `ntlm` layer、planner（规划器）、validator（校验器）或生成器。`cases/ntlm.json` 只保留一个 `ntlm_neg_unregistered` 注册前置占位，必须为 `expect_error=true` 且 `error_contains="unknown layer"`；占位不计入下文 20 个语义 ID。注册前的拒绝、0 包或空 PCAP 不是 NTLM 行为通过。

## 2. 推荐配置和层链

`ntlm.profile` 是必填语义配置，不允许由目标端口猜测。目标形状一律为纯 layers 形：地址只住 `ip` 层（`src`/`dst`；IPv6 地址族同住 `ip` 层——仓库无 `ipv6` 层，kerberos 先例，裁定 N5），端口只住 `tcp` 层（`src_port`/`dst_port`），数量只走 `flow_control`；顶层只允许 `layers`（+ `flow_control` 家族 / `output`），任何业务/承载键出现在顶层即违规（1.11–1.13）。v1.0.0 §2 曾给出 `src_ip`/`dst_ip`/`src_port`/`dst_port`/`ntlm` 顶层扁平键的示例，现已作废，下样例为唯一合法形状。

两个 profile 的**可达链形**（IPv6 地址族同住 `ip` 层，裁定 N5）：**P-SMB `[ip, tcp, ntlm]`**（NTLMSSP 三消息落 `tcp` payload，SMB2 成帧由 `ntlm` 层按 `profile` 自封）；**P-HTTP `[ip, tcp, http, ntlm]`**（`http` 作可选底座，`OptionalOn ["http"]` 豁免已由框架 commit `0c355be` 实装——`complete.go` 终结层计数把 `OptionalOn` 计入底座关系）。裁定 N1 全文与证据见 §15.4。v1.0.0 的 `[ip,tcp,smb,ntlm]` 仍判**结构性不可达**（smb 无 `TransformEvents`、无层依赖它）——缺口 G-NTLM-1 见 §15.4/§19，不许当成「已规划形状」写进实现。

```json
{
  "layers": [
    {"ip": {"src": "192.0.2.60", "dst": "198.51.100.60"}},
    {"tcp": {"src_port": 45600, "dst_port": 445}},
    {"ntlm": {
      "profile": "smb2",
      "version": "ntlmv2",
      "outer": "none",
      "sessions": [{"id": "s1", "events": ["negotiate", "challenge", "authenticate", "session_setup_success"]}]
    }}
  ],
  "flow_control": {"flows": 1}
}
```

```json
{
  "layers": [
    {"ip": {"src": "192.0.2.60", "dst": "198.51.100.60"}},
    {"tcp": {"src_port": 45601, "dst_port": 80}},
    {"ntlm": {
      "profile": "http-negotiate",
      "version": "ntlmv2",
      "outer": "none",
      "sessions": [{"id": "s2", "events": ["negotiate", "challenge_401", "authenticate", "http_success"]}]
    }}
  ],
  "flow_control": {"flows": 1}
}
```

| 配置键 | 约束 |
|---|---|
| `profile`（住 `ntlm` 层内） | `smb2` 或 `http-negotiate`，决定载体成帧（SMB2 SESSION_SETUP / HTTP 401+Negotiate）和状态机；不能为空，不能混用，不能由端口推导。 |
| `outer`（住 `ntlm` 层内） | `none` 或 `spnego`；SPNEGO 外层必须独立编码，不能把其 token 长度当 NTLM SecurityBuffer 长度。 |
| 地址/端口（住 `ip`/`tcp` 层内） | `smb2` 目的端口 445（NetBIOS 139 本契约不生成，§1）；`http-negotiate` 80/443（代理模式可为显式代理端口）；IPv4/IPv6 为独立 fixture。 |
| `version`（住 `ntlm` 层内） | 本版正例为 NTLMv2 应用语义；NTLMSSP Version 字段只有声明 `NEGOTIATE_VERSION` 时出现，8 bytes，不能因版本名自动伪造。 |
| `sessions[]`/`events[]`（住 `ntlm` 层内） | 多会话用 `sessions[]` 显式声明（3.1），每会话独立 ID/四元组/生命周期（3.2）；会话内事件必须按 NEGOTIATE→CHALLENGE→AUTHENTICATE；HTTP 401/407 challenge 和 SMB2 Session Setup status 是载体事件，不替代三条 NTLM 消息。 |
| `flags`（住 `ntlm` 层内） | Type 1/2/3 的 flags 必须协商一致；仅断言声明且可复核的 bits，不把未声明的 reserved bits 当能力。 |
| `target_info`（住 `ntlm` 层内） | Type 2 的 security buffer 指向 AV_PAIR 序列；长度和 offset 必须覆盖实际 bytes。 |
| `ntlmv2_response`（住 `ntlm` 层内） | Type 3 NT response 为 16-byte proof 加 blob；proof、时间戳、client challenge、session key 都是动态/密钥相关字段。 |
| `mic`/`encrypted_random_session_key`（住 `ntlm` 层内） | 可选 MIC 为 16 bytes；EncryptedRandomSessionKey 长度由 SecurityBuffer 声明。无授权密钥不得生成或断言其值。 |
| `flow_control`（顶层家族） | 策略数量/速率封包（`flows`/`bps`/`time`）；`spec` 本身不管数量（2.6）。 |
| `wire_fault`（住 `ntlm` 层内） | 仅负例故障注入口：`message_length`、`security_buffer`、`offset_overflow`、`flags_target_info`、`blob_av_pairs`、`carrier_profile`。不是线上字段。 |

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

## 11. 21 个语义场景和 packet_count 映射

共 21 个唯一语义 ID：15 个正例、6 个负例；顺序必须与 `60-ntlm-testcase.md` §2 及注册后的 `ntlm.json` 完全一致。注册前置占位 `ntlm_neg_unregistered` 已随注册移除。

| # | ID | 类型 | 覆盖 | packet_count（P5 实测回修） |
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
| 11 | `ntlm_multi_flow_streams` | 正 | 多 TCP stream/方向和 segmentation 后重组 | 17 |
| 12 | `ntlm_retry_auth_failure` | 正 | challenge 重试、最终 STATUS_LOGON_FAILURE/HTTP 401 | 13 |
| 13 | `ntlm_record_boundary_offsets` | 正 | 最小/最大附近 token、SecurityBuffer 边界和分段 | 15 |
| 14 | `ntlm_pcap_nic_consistency` | 正 | PCAP/NIC carrier、方向、端口和 token 长度一致 | 11 |
| 15 | `ntlm_http_negotiate_v6` | 正 | IPv6×HTTP 格（地址族对称补齐，A′ 补例 T-21） | 11 |
| 16 | `ntlm_neg_message_truncated` | 负 | 通用头或三类消息固定字段截断 | — |
| 17 | `ntlm_neg_security_buffer` | 负 | SecurityBuffer 长度/编码/承载不合法 | — |
| 18 | `ntlm_neg_offsets_overlap_overflow` | 负 | offset 越界、溢出或字段重叠 | — |
| 19 | `ntlm_neg_flags_target_info` | 负 | flags/TargetInfo 协商不一致 | — |
| 20 | `ntlm_neg_v2_blob_av_pairs` | 负 | NTLMv2 response/blob/AV_PAIR 不合法 | — |
| 21 | `ntlm_neg_carrier_profile` | 负 | SMB/HTTP/SPNEGO/TCP profile 载体错误 | — |

## 12. PCAP/NIC 观察与实现完成定义

实现注册后先检查 `tshark -G fields | grep -E '\\t(ntlmssp|smb2|http|spnego)\\.'`。若环境没有 NTLM dissector（解析器），使用通用 `tcp.port`、`smb2`/`http`/`tls`、稳定 raw frames 和 token 长度/offset；不自创 `ntlm.*` 字段。明文 SMB/HTTP fixture 可对 signature、Type、固定 little-endian fields 和 security buffer bytes 断言；动态 challenge、timestamp、client challenge、proof、MIC、session key 只用 presence/nonzero/same_as/length。

PCAP 正例必须断言 profile、TCP 端口、方向、TCP stream、NTLMSSP signature/Type、载体 SecurityBuffer 或 HTTP scheme；P-SMB 还断言 SMB2 Session Setup status，P-HTTP 还断言 401/407→最终状态。P-HTTP/TLS 与 SMB3 encryption 未解密时只能断言 TLS/SMB carrier，不得声称看到 token。NIC 模式必须记录接口和过滤器 `tcp port 445` 或 `tcp port 80/443`，说明 checksum offload 与 TLS/SMB encryption 观察边界。

完成定义：注册 `ntlm` layer；逐字段验证三消息固定布局、little-endian security buffer、32-bit offset overflow、flags/TargetInfo、NTLMv2 blob/AV_PAIR、SPNEGO separation 和 SMB/HTTP 双 profile；planner→worker→TCP output 完整路径能传播正负结果；-race 和集成测试覆盖多会话/多流、重试/失败；未授权密钥下没有伪造 proof、MIC 或 session key。

三方契约必须保持本文 §11、`60-ntlm-testcase.md` §2、`ntlm.json` 同一组 21 个语义 ID、同一顺序、15 正例+6 负例。

## 13. 修订记录

- v1.0.0（2026-08-20）：建立 14 个 NTLMv2 正例和 6 个严格负例，覆盖 MS-NLMP 三消息、SecurityBuffer offset/length、flags/TargetInfo、NTLMv2 response/blob/AV_PAIR、MIC/session key opaque 边界、SMB2/HTTP Negotiate 双 profile、SPNEGO、IPv4/IPv6、多会话/多流、重试/失败、PCAP/NIC 和错误传播；不修改 Go 实现。


## 14. P1 规范矩阵（CORE_MEMORY §4 八项：规范要求→业务场景→代码现状→缺口）

> 深度口径（§4.19–4.22）：矩阵三张子表——①消息×载体终态矩阵（§14.2）②数据形态变体表（§14.3）③商业行为→用例映射表（§15.2）。条目三选一：已实现 / 明确不支持 / 不适用 + 对应用例号；无遗漏留白。

### 14.1 八项规范矩阵

| # | 规范要求（规范条款） | 业务场景 | 代码现状 | 缺口 |
|---|---|---|---|---|
| 1 | 连接模型：NTLM 是**非独立连接协议**——NTLMSSP 三消息寄居载体，无自有连接、无自有端口；SMB2 直接跑在 TCP/445 的 SESSION_SETUP request/response（MS-SMB2 §3.2.5.3、§3.3.5.2.4），或 HTTP 401/407 `WWW-Authenticate: Negotiate` → `Authorization: Negotiate`（RFC 4559 §1/§4.2）；TCP 上 NTLMSSP 边界=NTLMSSP message 边界≠segment 边界（本契约 §3） | AD 域内 SMB2 文件访问认证；IIS/Negotiate Web 认证；企业代理链下的认证压测 | 未注册：registry.go / schema / protocols.go / `generated/layers.generated.json`（123 层）实测零 `ntlm` 命中；`tcp` 层已注册可承载；**`smb` 层已注册且已内建 NTLMSSP blob 生成**（`internal/protocol/smb/emit_session.go:92-144`，`auth_mechanism` 枚举含 ntlm：`internal/protocol/smb/constants.go:127`，默认 ntlm：`internal/protocol/smb/validate.go:226`）——存在权威重叠，见 §15.3 方案 B | 全量新建 `ntlm` 终结层（裁定 N1：`DependsOn ["tcp"] + OptionalOn ["http"] + TransportOn ["tcp"]`）；双 profile 自封帧；层嵌套 `[ip,tcp,smb,ntlm]` 判不可达→G-NTLM-1；P-HTTP 链 `[ip,tcp,http,ntlm]` 经 `OptionalOn` 底座豁免可达（0c355be）；与 smb 层权威裁定→G-NTLM-3；占位随注册移除 |
| 2 | 命令/消息表：`NEGOTIATE_MESSAGE`(Type 1)/`CHALLENGE_MESSAGE`(Type 2)/`AUTHENTICATE_MESSAGE`(Type 3) 固定头 + security buffer 负载（MS-NLMP §2.2.1.1/§2.2.1.2/§2.2.2.1/§2.2.2.2/§2.2.2.3）；载体事件：SMB2 SESSION_SETUP status trio 与 HTTP 401/407→2xx（MS-SMB2 §3.3.5.2.4；RFC 4559 §4.2） | 单次认证三消息交换；SPNEGO 包装形；2 轮/3 轮 SESSION_SETUP | 无 | 结构化声明式回放（三消息 builder + opaque 密钥面 fixture 钉死）；消息×载体终态矩阵见 §14.2，每格对应用例或立项 |
| 3 | 状态机：`Initial → NegotiateSent → ChallengeReceived → AuthenticateSent → Accepted/Rejected`；重试=同 session 重发 Type 1 或服务器重发 challenge，新 session 必须独立 challenge/client challenge/状态；认证失败必须传播 task error 或 rejected 终态（本契约 §9；MS-SMB2 §3.3.5.2.4；RFC 4559 §4.2） | 认证重试；失败不得静默成功（不许 `completed/0 packet`） | 无 | 会话内事件序 + 每会话独立状态；失败/重试分支见 §16.3；错误传播零假成功见 §17 错误分支 |
| 4 | 字段表：固定前缀 `Signature(8)="NTLMSSP\0" + MessageType(4, LE)`；SecurityBuffer = `Len(2)\|MaxLen(2)\|Offset(4)` 全 little-endian、Offset 相对 NTLMSSP 起点；Type 1/2/3 逐字段（§4.1–§4.3）；AV_PAIR=`AvId(2)\|AvLen(2)\|Value(AvLen)` 以 `MsvAvEOL=0` 结束；Version 8B；MIC 16B；NTLMv2 blob（§7）（MS-NLMP §2.2.1–§2.2.3、§2.2.2.1；本契约 §4–§7） | 跨 Windows/Samba/impacket 互操作；Unicode 与 OEM 编码；Version/MIC 可选面 | 无 | 字段变体全枚举见 §14.3；`Offset+Len` 32-bit 溢出/越界/重叠守卫；空字段与最大附近边界 |
| 5 | 错误处理：token <12B / 错误 signature / 未知 type；SecurityBuffer `Len>MaxLen`、offset 越界、UTF-16 奇数长度、字段重叠、32-bit 溢出；flags 不兼容/未知 reserved bits；TargetInfo 缺 `MsvAvEOL`/`AvLen` 越界；NTLMv2 blob 长度错；载体与 profile 不符（MS-NLMP §2.2.1.1/§2.2.2.1；MS-SMB2 §3.3.5.2.4；本契约 §5/§10） | 畸形 token 拒识；载体混用；伪造 challenge 会话 | 无 | 6 负例（§10 表）+ `wire_fault` 6 值=§2 键表逐字；自然守卫（长度/offset/编码/flags/EOL）+ 载体↔profile 一致性预检（smb 的 `transport` 一致性校验同款） |
| 6 | 超时与活性：NTLM 自身无超时/保活/重传语义（不经网络握手）；活性由载体承担——TCP 握手/seq-ack/挥手与 SMB2 keepalive（MS-SMB2 §3.3.5.2.1）、HTTP keep-alive；重传语义属 TCP；重试=同 session 重发（本契约 §9） | 长保活载体内多轮认证；弱网 TCP 分段 | 无（载体 `tcp`/`http` 层已有握手/保活/分段语义） | TCP 分段切分/合并 fixture（#11）+ 同 session 重试（#12）+ keep-alive 多事务→A′ 补例 T-22；载体会话中断形（服务端主动 FIN/RST mid-auth）→G-NTLM-5 |
| 7 | NAT/代理/被动模式：SMB2 直连 445（139 NetBIOS Session Service 本契约不生成）；HTTP Negotiate 明文 80，或 HTTPS 443 经 CONNECT 隧道（未解密 PCAP/NIC 只能断言 TCP/TLS carrier，不得声称看见 HTTP/NTLM 明文）（RFC 4559 §4.2；本契约 §1/§3 表） | 企业网代理后的 Negotiate 认证；SMB3 encryption 与 HTTPS 的不透明边界 | 无 | 明文双 profile 正例（#1/#3）+ HTTPS opaque carrier 例；代理形（绝对 URI/Host）与 CONNECT 隧道→G-NTLM-5 |
| 8 | 版本/方言：NTLMv2（本版正例，`NEGOTIATE_EXTENDED_SESSIONSECURITY` 下的 NTLMv2 response/blob）vs NTLMv1（LM/NT response 形态）；NTLMSSP Version 字段仅 `NEGOTIATE_VERSION` 置位时存在（8B）；NTLMv1/LM 默认禁用（Windows 7/Server 2008 R2 起默认拒 NTLMv1）；Samba/impacket 方言（MS-NLMP §2.2.1.2.2/§2.2.2.2；本契约 §6/§7） | 老客户端 NTLMv1 兼容性面；Version 字段有无两形 | 无 | NTLMv2 正例为主（#4/#7/#8）；NTLMv1/LM response 与方言面三选一收口→G-NTLM-6（明确不支持 或 立项） |

### 14.2 子表①：消息×载体终态矩阵（逐格已覆/缺失/不适用）

> **适配声明**：NTLM 无自有响应码（§4.22 的「命令×响应码矩阵」原型是请求命令×响应码）。NTLM 的等价物是**NTLMSSP 消息 × 载体终态**（SMB2 status / HTTP status），故本表按该等价口径建表，逐格给结论，不留白。

| 请求面 \ 载体终态 | `STATUS_MORE_PROCESSING_REQUIRED`+Type 2 / `401\|407`+Type 2 | `STATUS_SUCCESS` / `2xx` | `STATUS_LOGON_FAILURE` / `401` 最终拒 | 无响应（中断/超时） |
|---|---|---|---|---|
| SMB2 SESSION_SETUP req（Type 1） | 已覆 #1/#2（+3 轮 #12） | 不适用（本契约 NTLM 最小 2 轮，Type 1 不直接成功） | 已覆 #12 | 立项 G-NTLM-5 |
| SMB2 SESSION_SETUP req（Type 3） | 已覆 #12（3 轮：Type 3 后仍 MORE） | 已覆 #1/#2 | 已覆 #12 | 立项 G-NTLM-5 |
| HTTP req（Type 1） | 已覆 #3 | 不适用 | 已覆 #12 | 立项 G-NTLM-5 |
| HTTP req（Type 3） | 已覆 #12（重复 challenge 不推进成功） | 已覆 #3 | 已覆 #12 | 立项 G-NTLM-5 |

注：16 格中 10 格由 20 ID 覆盖，2 格「不适用」（三选一之一，非缺口），4 格走 B′ 立项 G-NTLM-5（载体会话中断/无响应面）。

### 14.3 子表②：数据形态变体表（协议相关全部形态逐项）

| # | 变体维度 | 形态 | 对应用例 | 备注 |
|---:|---|---|---|---|
| 1 | 地址族×profile | IPv4/`smb2` | #1 | |
| 2 | 地址族×profile | IPv6/`smb2` | #2 | 独立 IPv6 fixture，不复用 IPv4 challenge/stream |
| 3 | 地址族×profile | IPv4/`http-negotiate` | #3 | 明文 TCP/80 |
| 4 | 地址族×profile | IPv6/`http-negotiate` | **T-21 已并入**（`ntlm_http_negotiate_v6`，终审 M2 修轮） | 原 20 ID 缺 IPv6+HTTP 格；P6 修轮落盘，21/21 绿 |
| 5 | SecurityBuffer | Len=0 空字段 与 非空字段并存 | #6/#13 | 空字段 Offset 不作 payload 推导（§5 规则 2） |
| 6 | SecurityBuffer | `MaxLen > Len` 形（缓存语义） | #13 | MaxLen 不得小于 Len；不得按 MaxLen 读线上 bytes |
| 7 | 编码 | `NEGOTIATE_UNICODE` 置位（UTF-16LE，偶数字节长度）/ 关闭（OEM） | #4 | 奇数长度→负例 #16 |
| 8 | flags | 必需交集 / `EXTENDED_SESSIONSECURITY` / `TARGET_INFO` / `KEY_EXCH` / `128`/`56` 组合 | #4/#5/#8 | Type 1/2/3 交集一致 |
| 9 | flags | reserved/未知 bits 置位 | 负例 #18 | 不把未声明 bit 当能力 |
| 10 | Version | `NEGOTIATE_VERSION` 置位（8B 逐字节）/ 未置位（缺席） | #4 | 不因版本名自动插入 |
| 11 | TargetInfo AV_PAIR 集 | NbComputerName/NbDomainName/Dns*/Timestamp/Flags/TargetName/未知项/EOL | #5/#7 | `AvLen` 只计 Value，不含 4B AV header |
| 12 | TargetInfo 边界 | 缺 `MsvAvEOL` / `AvLen` 越界 / 重复非法项 | 负例 #19 | |
| 13 | NTLMv2 blob 结构 | `Proof(16)\|RV(1)\|HRV(1)\|Reserved(2)\|TS(8)\|CC(8)\|Reserved2(4)\|AV…\|EOL(4)` | #7 | proof 无授权密钥不断言值 |
| 14 | LM response | Len=0（NTLMv2 profile）与非空两形 | #6 | 不得冒充 NT response |
| 15 | MIC | 声明出现（16B）/ 不出现 | #8 | 计算输入涉密钥，不猜测值 |
| 16 | EncryptedRandomSessionKey | 声明出现 / 不出现 | #8 | 长度由 SecurityBuffer 声明 |
| 17 | SPNEGO 外层 | `outer=none`（裸 NTLMSSP）/ `outer=spnego`（ASN.1 外层+OID `1.3.6.1.4.1.311.2.2.10`） | #9 | 不能把 ASN.1 tag/length 当 Type/SecurityBuffer |
| 18 | offset 边界 | Offset=0 / 最大附近 / 字段重叠 / `Offset+Len` 32-bit 回绕 | #13 + 负例 #17 | 宽整数+边界检查后再切片（§5 规则 5） |
| 19 | TCP 分段 | 单消息跨 segment 切分 / 多消息合并于单 segment，重组后解析 | #11 | 不按单 packet 截断 |
| 20 | 多会话/多流 | `smb2` 双会话并行 / `http-negotiate` 多会话 keep-alive | #10/#11 | 四元组或显式 `session_id` 隔离 |
| 21 | 载体失败与重试 | `MORE_PROCESSING_REQUIRED`/401 重试、最终 `LOGON_FAILURE`/401 拒绝 | #12 | 失败后不发 authenticated data/2xx |
| 22 | PCAP/NIC | 同 fixture 双路输出，carrier/方向/端口/token 长度一致 | #14 | 过滤器 `tcp port 445` / `tcp port 80`（或 443） |
| 23 | 载体会话中断形 | 服务端主动 FIN/RST mid-auth、HTTP 401 无后续 | 立项 G-NTLM-5 | 20 ID 未覆（#12 只到终态拒绝，不含「无终态」） |

## 15. 三路对照与候选方案对比（CORE_MEMORY §4.12–4.18）

### 15.1 三路对照

①**规范原文**：MS-NLMP（`NEGOTIATE_MESSAGE`/`CHALLENGE_MESSAGE`/`AUTHENTICATE_MESSAGE` 逐字段与 SecurityBuffer `Len|MaxLen|Offset` little-endian 语义，§2.2.1–§2.2.3；AV_PAIR `AvId|AvLen|Value` 与 `MsvAvEOL`，§2.2.2.1）、MS-SMB2（§3.2.5.3 SESSION_SETUP 请求、§3.3.5.2.4 响应与 status trio）、RFC 4178（SPNEGO `negTokenInit`/`negTokenResp` 与 NTLM OID `1.3.6.1.4.1.311.2.2.10`）、RFC 4559（HTTP Negotiate 401/407 流程）、RFC 2743（GSS-API）。NTLM 无 RFC，以 MS-NLMP/MS-SMB2 官方规范为准（§4.10）。

②**现网行为**（定「真跑成什么样」，逐条给产品+出处）：
- **Windows/AD（SMB2）**：客户端 SMB2 SESSION_SETUP 的 SecurityBuffer 默认承载 **SPNEGO 包装**的 NTLMSSP（非裸 NTLMSSP），即 `outer=spnego` 是现网 SMB2 主形态；会话状态机走 `STATUS_MORE_PROCESSING_REQUIRED`→`STATUS_SUCCESS`（MS-SMB2 §3.2.5.3/§3.3.5.2.4 定义该 trio）。确认方式：G-NTLM-4（回环抓 Windows 客户端 / 更新 MS-SMB2 章节核对）。
- **NTLMv2 为现网默认**：Windows 7/Server 2008 R2 起 NTLMv1/LM 默认不再发送（微软 LMCompatibilityLevel 默认档位），故本契约正例取 NTLMv2；NTLMv1 面入 G-NTLM-6。确认方式：查微软官方 LMCompatibilityLevel 文档 + 抓包（G-NTLM-4）。
- **Samba**：`smbd` 的 SMB2 SESSION_SETUP 同为 SPNEGO 包装、支持 NTLMv2。确认方式：抓本机/容器 Samba 3 会话（G-NTLM-4）。
- **impacket**：`impacket.smb3`/`smbclient` 走 SMB2+NTLMv2；`ntlmrelayx` 以 NTLMSSP 直接中继。确认方式：读其源码结构体 + 抓包（G-NTLM-4）；仅借鉴行为，不搬运受限代码（§4.14）。
- **HTTP Negotiate**：IIS/Kerberos/NTLM 双支持时先发 `WWW-Authenticate: Negotiate`，浏览器回 `Authorization: Negotiate <base64>`；`curl --ntlm` 走同形。确认方式：抓 IIS 或 `curl --ntlm` 回环（G-NTLM-4）。

③**开源实现思路**：wireshark 的 `epan/dissectors/packet-ntlmssp.c`（本机 tshark 3.6.14 **实测 147 个 `ntlmssp.*` 字段**——具名清单与计数口径见 §12；关键锚：`ntlmssp.identifier`/`ntlmssp.messagetype`/`ntlmssp.negotiateflags`/`ntlmssp.negotiate.domain`/`ntlmssp.ntlmserverchallenge`/`ntlmssp.challenge.target_name`/`ntlmssp.challenge.target_info.item.type`/`ntlmssp.auth.username|domain|hostname|lmresponse|ntresponse|sesskey`/`ntlmssp.string.length|maxlen|offset`/`ntlmssp.ntlmv2_response.ntproofstr|time|chal`/`ntlmssp.authenticate.mic`/`ntlmssp.version.*`），其「SecurityBuffer 三元组驱动、按 Offset 相对 message 起点切片」的解析思路即本契约 §5 的权威；另有 SMB2/SPNEGO 侧的 `smb2.security_blob`（533 个 `smb2.*` 字段）与 `spnego.*`（41 个字段）可作载体侧交叉校验。**只借鉴思路，不搬码**（§4.14）。

三路结论一致：三消息 + SecurityBuffer 三元组 + little-endian 固定头 + 载体状态机（MORE_PROCESSING_REQUIRED/401 → SUCCESS/2xx）；**不一致点**：规范允许裸 NTLMSSP（`outer=none`），而现网 Windows/Samba 默认走 SPNEGO 包装——取舍按 §4.15「以规范为底线、以现网为准绳」：本契约 `outer` 为**必选声明**、两种形态分别为独立 fixture（#1 表 `outer` 行、#9），不把现网默认当成唯一合法形。

### 15.2 子表③：商业行为→用例映射表（§4.16）

| 商业行为（产品/版本+出处） | 用例编号 | 无映射项 + 确认方式 |
|---|---|---|
| Windows/AD SMB2 认证（SPNEGO 包装 NTLMSSP，status trio） | #1/#2/#9 | 抓包核对同形 → G-NTLM-4（抓 Windows 客户端或更新 MS-SMB2 章节） |
| Samba `smbd` SMB2 会话（NTLMv2，SPNEGO） | #1（+ #9） | 抓 Samba 3 会话 → G-NTLM-4 |
| impacket `smb3`/`ntlmrelayx`（NTLMSSP 直发/中继） | #9（`outer=none` 裸形） | 读源码+抓包 → G-NTLM-4 |
| IIS/浏览器 HTTP `Negotiate`（401 → Authorization → 2xx） | #3/#9 | 抓 IIS 或 `curl --ntlm` 回环 → G-NTLM-4 |
| 企业代理后的 Negotiate 认证（绝对 URI/Host、HTTPS CONNECT） | 缺口 | → G-NTLM-5（查 RFC 4559 §4.2 + 代理抓包） |
| NTLMv1 老客户端兼容（默认禁用，LM response） | 缺口 | → G-NTLM-6（查微软 LMCompatibilityLevel 文档，三选一收口） |

### 15.3 候选方案对比（§4.17）

| 方案 | 走法（含借鉴来源） | 优 | 劣 | 性能/复杂度/兼容性 | 结论 |
|---|---|---|---|---|---|
| A 结构化声明式回放（自封帧） | `ntlm` 层内按 profile 自封 SMB2 SESSION_SETUP / HTTP 401+Negotiate，三消息 builder 结构化 + proof/MIC/session key opaque（kerberos #44 D-KERBEROS-1 同族：外壳结构化+密钥面 opaque；多载体协议 dns/someip 同族：`DependsOn` 单载体 + 自封帧） | 与已收官族同构（接线/builder/planner/casegen 范式可复用）；双 profile 对称可达；零新引擎机制；无密钥不伪造密码学语义 | SMB2/HTTP 成帧语义在 `ntlm` 层内重述，与 `smb` 层存在权威重叠（须裁定，G-NTLM-3） | O(n) 流式渲染；复杂度低；兼容 NTLMv2 与 SPNEGO 两形态 | **采用** |
| B 复用 `smb` 层的 NTLMSSP 实现 | 直接用既有 `smb` 层（`auth_mechanism=ntlm` + `auth_rounds=2\|3`，`emit_session.go:92-144` 已产 Type 1/2/3 blob），`ntlm` 不注册 | 零新代码；已内建 SMB2 成帧与 status trio | 不能注册独立 `ntlm` 层 → 本契约 20 ID 与 `ntlm.json` 无落点；HTTP profile 完全不可达；双头权威（两个协议名管同一线上语义） | 复杂度最低但契约表达力不足 | 不选为层链方案；**其 SMB2 成帧语义作 P-SMB 参考实现**（§17 冲突点） |
| C 仅发 SPNEGO 外层 | 只生成 ASN.1 外层，内层 NTLMSSP 交给别的机制 | 与 #47 spnego 职责划分干净 | 违反本契约 §8：内层 NTLMSSP signature/Type/SecurityBuffer 逐字段不可断言 → 20 ID 之 #4–#8 全失 | 表达力骤降 | 不选（#47 已明确其内层 opaque，本契约的内层正是其 opaque 面之内容） |
| D 整消息 hex 回放 | 三消息 body 整段 hex 覆盖（kerberos `events[].body` 逃生口同款） | 最简单 | 字段不可结构化断言；offset/flags/AV_PAIR 面全失；动态面全失 | 动态零分 | 仅作负例/特殊形逃生口，不做主方案 |

### 15.4 裁定 N1：依赖建模与载体链形（逐条先证，二选一后给结论）

**先证 1（`smb` 层不能作 `ntlm` 的外层底座）**：`[ip,tcp,smb,ntlm]` 结构性不可达。证据链：
- `smb` 注册为 `CategoryTerminal` 且**未**标记 `TransformEvents`（`internal/core/layers/registry.go:1028-1030`）；全仓库 `TransformEvents: true` 只有 `http` 一处（`registry.go:104`）。
- 终结层唯一性（V2）在 `complete.go:416-433`：终结层计数 >1 即 `layers: terminal layer %q duplicated`；唯一豁免是 `schema.TransformEvents && i < len(chain)-1 && dependedOn(i, l.Name)`（`complete.go:423`），而 `dependedOn` 要求**链中另一层**的 `DependsOn` 含该层名（`complete.go:405-415`）。
- 全仓库**无任何层 `DependsOn` 含 `"smb"`**（实测：`registry.go` 中 `smb` 仅出现在它自己的注册行 1028），故 `dependedOn(smb)=false`，`smb`+`ntlm` 两个终结层 → 判死。
- 唯一先例 `[ip→tcp→http→http_flv]` 成立的条件是 `http` 带 `TransformEvents:true`（`registry.go:104`）+ `HTTPGenerator` 实现 `TransformEvents()`（`internal/protocol/http/layer_gen.go:35`）+ `http_flv.DependsOn ["http"]`（`registry.go:464-465`）；且 `assertEventWiring`（`chain_planner_chain.go:243-253`）要求夹层生成器实现 `EventTransformer`——smb 生成器无此实现。现有测试同时钉死两个方向：`validate_layers_test.go:65-69`（T18b，`[ip,tcp,http,http_flv]` 合法）与 `:48-60`（T18，`[{"s7":{}},{"ip":{}},{"s7":{}}]` 与 `[ip,tcp,http,dns]` 均判 `duplicated`）。
- **结论**：`[ip,tcp,smb,ntlm]` 要成立须动跨协议框架（`registry.go` 给 smb 加 `TransformEvents`、smb 生成器实现 `EventTransformer`、并新增 smb 变换器模式把 ntlm 事件包进 SESSION_SETUP）→ 缺口 **G-NTLM-1**（上报主线程，车道不得自改框架）。

**先证 2（`http` 作 `ntlm` 的外层底座——框架修 0c355be 后可达）**：`[ip,tcp,http,ntlm]` 于 2026-09-25 起可达。
- 原判死理由（已失效）：`OptionalOn` 当时不参与 V2 豁免——`complete.go` 的 `dependedOn` 只查 `s.DependsOn`，故 `DependsOn ["tcp"] + OptionalOn ["http"]` 的层在 `[ip,tcp,http,ntlm]` 中仍被计为第二个终结层。
- 现状（实测）：commit `0c355be` 把 `OptionalOn` 一并计入底座关系——`dependedOn` 现为 `contains(s.DependsOn, name) || contains(s.OptionalOn, name)`（`complete.go` 该闭包内），使显式写了可选底座的链可达。回归证据：`optional_on_chain_test.go` 两例（正例 `[ip,tcp,http,X]` 合法、反例无 `OptionalOn` 仍判 `duplicated`）+ 既有 T18/T18b 语义不变，`go test ./internal/core/layers/ -count=1` 全绿。
- 存量零影响：修复前全仓库 `OptionalOn` 取值只有 `tls`/`eth`（隧道/L2 底座），无终结层声明 `http`，终结层计数判定对既有 123 协议不变。
- **结论**：`OptionalOn ["http"]` 声明 + `[ip,tcp,http,ntlm]` 链形**今日可达**，与 #46 ocsp、#47 spnego 同写法跨协议一致；原缺口 **G-NTLM-2 关闭**（框架已实装，见 §19）。

**二选一（今日可达链形）**：
- **A（采用）** `DependsOn ["tcp"] + OptionalOn ["http"] + TransportOn ["tcp"]`；**P-SMB 可达链形 `[ip,tcp,ntlm]`、P-HTTP 可达链形 `[ip,tcp,http,ntlm]`**（IPv6 地址族同住 `ip` 层，裁定 N5）。`http` 层显式写了才启用（系统不自动插入），SMB2 成帧由 `ntlm` 层内按 `profile` 自封。`TransportOn` 保持 L4 纯度（实测全仓库 `TransportOn:.*http` = 0；取值仅 `tcp`/`udp` 组合）。
- B（不选） `DependsOn ["http"]` 默认 + P-SMB 例外放行：http 族先例（`gbt`/`mmse`）证明 `DependsOn ["http"]` 使「无 http 链」天然不可达，B 须为引擎开「缺依赖放行」新机制且与 P-SMB 语义冲突，全仓库无先例。

**`DependsOn` 单值 / `TransportOn` 纯 L4 声明**：`DependsOn` 只写单值 `["tcp"]`（实测全仓库 `DependsOn` 双值 = 0 处）；`TransportOn ["tcp"]` 单值、**udp 零值**（NTLM 无 UDP 语义）——链中夹 `udp`（`[ip,udp,ntlm]`）判死负例，锚词 `transport`/`carrier`。本契约 §2 键表、门1 §5/§13 行、§17 接线件均引用本裁定。

## 16. 门1 §1–§14 十四行对照表（CORE_MEMORY §15.1–15.3）

| § | 本协议怎么满足 | 证据 |
|---|---|---|
| §1 层链唯一真相 | 见 §16.1 强制展开：旧键 `src_ip/dst_ip/src_port/dst_port` 四键迁入 `ip`/`tcp` 层；顶层 `ntlm` 子映射迁入 `layers[]` ntlm 条目；数量走 `flow_control`；目标形状 spec_json 样例见 §16.1；占位（旧扁平形）随注册移除；非负例顶层键=0（presence 负例见 §16-P2） | 本契约 §2 + §16.1；占位 `cases/ntlm.json`（当前旧扁平形） |
| §2 策略/任务 | 策略=单 NTLM 流量模板（自带 `flow_control` flows/bps/time）；任务=多策略合跑+总量封顶；框架语义未动 | 本契约 §2/§17 |
| §3 五件套 | 见 §16.3 强制展开：双 profile 会话表/事务序列/关联关系/插入位置/时间线；**有长连接载体不豁免**（多会话 + 多事务在例） | 本契约 §16.3 + 用例 #10/#11/#12 |
| §4 查规范 | MS-NLMP + MS-SMB2 §3.2.5.3/§3.3.5.2.4 + RFC 4178 + RFC 4559 + RFC 2743；现网（Windows/AD、Samba、impacket、IIS/curl）；tshark `ntlmssp.*` **147 字段实测**；P1 矩阵 8 行 + 三子表 | 本契约 §14/§15 |
| §5 依赖与错误 | 裁定 N1：`DependsOn ["tcp"] + OptionalOn ["http"] + TransportOn ["tcp"]`（单值/L4 纯）；`wire_fault` 6 值=§2 键表逐字；自然守卫 + 载体↔profile 一致性预检；失败返回 task error（零假成功） | 本契约 §2/§10 + §15.4 + §17 错误分支 |
| §6 性能 | 声明式回放族：O(n) 流式渲染无全量聚合；pcap/NIC 双路验收；吞吐/并发/内存目标待 P4 基准后定（诚实待确认，不写承诺数字，§6.5）；六类场景清单见 §17 | §17 性能设计与验收 |
| §7 三份文档 | 60-ntlm-{design,testcase}.md v2.0.0/v1.1.0（ID 权威=testcase §2）+ D-NTLM-1（本契约 §17 草稿，门1 获批=定稿）+ T-NTLM（testcase §8）+ generated schema（P4 重跑） | 修订记录 |
| §8 设计先行 | 本条目 P1–P3 先于 P4 实现；门1 获批 = D-NTLM-1 定稿 = 开工门 | 提交序 |
| §9 测试三源 | 三源=MS-NLMP/MS-SMB2/RFC 条款 + D-NTLM-1 + tshark `ntlmssp.*` 字段（147 实测）+ 现网 Windows/Samba/impacket 行为；20 ID 正负对账；三源回指行见 testcase §8 | T-NTLM（testcase §8） |
| §10 评审闭环 | 每阶段对抗自重审（结论见 p123 报告）+收官隔离复审+修轮；红先绿后 | /tmp/pipe/45-ntlm/p123-report.md |
| §11 白话 | 每阶段白话一句先行 | 汇报 |
| §12 动态清单 | 见 §16.12 强制展开：四元组=ip/tcp 层（五策略全支持）；业务字段逐个列开/不开+理由；序号算法位置诚实「待 P4 定」 | 本契约 §16.12 |
| §13 schema 派生 | registry ntlm 行（裁定 N1）→ schemagen 重跑（层数 123→124）；struct 标签字面量锁；`allowedProtocols`（`internal/core/protocols.go`）在注册时同增，实测当前 `ntlm` 零命中 | §17 接线件 |
| §14 真实流程 | suite 经 MCP 建任务→引擎生成→tshark `ntlmssp.*`（147 字段）+ frames hex 双通道；先跑后钉；pcap 落 `/tmp/mcp-pcaps/ntlm/` | 用例 §1/§6 |

### 16.1 §1 强制展开：旧键去向 + 完整 spec_json 样例

旧键清单（`src_ip/dst_ip/src_port/dst_port/count` + 本协议顶层子映射 `ntlm`）：

| 旧键 | 去向 |
|---|---|
| `src_ip` | → `layers[i].ip.src`（`192.0.2.60`） |
| `dst_ip` | → `layers[i].ip.dst`（`198.51.100.60`） |
| `src_port` | → `layers[i].tcp.src_port`（`45600`） |
| `dst_port` | → `layers[i].tcp.dst_port`（`smb2` 用 445；`http-negotiate` 用 80/443） |
| `count`（若有） | → 删除，走 `flow_control.flows` |
| 顶层 `ntlm` 子映射 | → `layers[]` 中 `{"ntlm": {...}}` 条目（业务键全量迁入，零残留） |
| 顶层 `smb` / `http` 子映射（若出现） | → **判死负例**（1.11–1.13 白名单外游离键）：`smb` 的 SMB2 成帧归 `ntlm.profile=smb2` 自封，`http` 的 header 语义归 `ntlm.profile=http-negotiate` 自封，二者都不作为顶层键，也不作为链上层（裁定 N1，§15.4） |

完整 P-SMB 样例（目标形状，顶层键仅 `layers`+`flow_control`）：

```json
{
  "layers": [
    {"ip": {"src": "192.0.2.60", "dst": "198.51.100.60"}},
    {"tcp": {"src_port": 45600, "dst_port": 445}},
    {"ntlm": {"profile": "smb2", "version": "ntlmv2", "outer": "spnego", "flags": {"extended_session_security": true, "target_info": true, "key_exch": true}, "target_info": {"nb_computer_name": "DC01", "nb_domain_name": "EXAMPLE", "timestamp": "auto"}, "sessions": [{"id": "s1", "events": ["negotiate", "challenge", "authenticate", "session_setup_success"]}]}}
  ],
  "flow_control": {"flows": 1}
}
```

### 16.3 §3 强制展开：五件套（双 profile）

会话表：

| 会话 | profile | 四元组 | 生命周期 |
|---|---|---|---|
| s1 | `smb2` | ip.src/dst + tcp.45600→445 | TCP 握手 → SESSION_SETUP(Type 1) → MORE+Type 2 → SESSION_SETUP(Type 3) → SUCCESS → 挥手 |
| s2 | `smb2`（独立会话） | 单 TCP 连接双 SessionId（实现口径：SMB2 单连接多 SessionId 复用为现网常态；终审 m2 回修——链级红例 ntlm_chain_test.go:795 同连接实证） | 独立 ServerChallenge/client challenge/SecurityBuffer，不与 s1 共享 |
| s3 | `http-negotiate` | ip.src/dst + tcp.45601→80 | 建连 → req(Type 1) → 401 `WWW-Authenticate: Negotiate` → req(Type 3) → 2xx |

事务序列（单事务四件事 §3.4–3.7）：

| 事务 | 前置条件 | 触发动作 | 成功分支 | 失败分支 |
|---|---|---|---|---|
| t1 SMB2 认证 | s1 已建连（TCP 握手完成） | 发 SESSION_SETUP request（SecurityBuffer=Type 1 或 SPNEGO 外层） | 收 MORE_PROCESSING_REQUIRED+Type 2 → 发 Type 3 → 收 SUCCESS | 收 LOGON_FAILURE → 终止会话+task error（不发 authenticated data） |
| t2 SMB2 第 2 会话 | s2 已建连 | 同 t1（独立 challenge） | 同 t1，且与 s1 的 challenge/proof 不 `same_as` | 同 t1，只终止 s2 |
| t3 HTTP 认证 | s3 已建连 | 发带 `Authorization: Negotiate` 的请求 | 401+Type 2 → 发 Type 3 → 2xx | 最终 401 → 终止会话+task error；重复 401 不推进成功 |
| t4 重试 | t1/t3 收到 challenge 后（同 session） | 重发同一 Type 1 或等服务器重发 challenge | 重新走 t1/t3 成功分支，状态不重复推进 | 连续失败 → task error |

关联关系（§3.8–3.10）：一个认证会话关联一条 TCP stream（无独立派生数据/媒体流，故无 `driven_by` 派生流——与 CWMP 范本差异点诚实声明）；请求/响应关联三件事=归属会话 `sN`、归属事务 `tM`、由 `ServerChallenge`（Type 2）+ `client challenge`（Type 3 blob）+ 载体 status 三字段决定。多会话可共享目标端口但必须按 TCP 四元组或显式 `session_id` 隔离（#10）。
插入位置：终结层——`smb2` profile 的 token 落在 TCP payload 内的 SMB2 SESSION_SETUP SecurityBuffer（`ntlm` 层自封），`http-negotiate` profile 落在 TCP payload 内的 HTTP header value（`ntlm` 层自封）；**无链上中间层**（裁定 N1）。
时间线：会话内顺序（Type 1→2→3 严格有序）；跨会话并发交错（s1/s2/s3 可交错，多流/多 worker 不保证全局包序，只断言**每条 TCP stream 内重组后**的消息顺序与每个 session 的 challenge-response 关联一致，§9）。

### 16.12 §12 强制展开：动态字段清单

| 字段 | 住处 | 开策略 | 理由 |
|---|---|---|---|
| `src`（src_ip） | ip 层 | fixed/inc/rand/list/pattern 全开 | §12.2 四元组必备；多流并发锚点 |
| `dst`（dst_ip） | ip 层 | fixed（多目标地址待 P4 立项） | 目标 server 地址 fixture 钉死 |
| `src_port` | tcp 层 | 全开 + 未写动态保底 `12345+i` | §12.2/§2.8 |
| `dst_port` | tcp 层 | fixed（445 / 80 / 443 三档 fixture） | tshark 自动解码约束；动态端口例顶层 `decode_as` 另议 |
| `session_id` | ntlm 层 | inc（按流递增） | 多会话隔离锚点（#10） |
| `ServerChallenge`（Type 2 8B nonce） | ntlm 层 | rand（seed+序号可复现）/fixed fixture | 断言 `nonzero`/`distinct_values`；**不得硬编码**（§6） |
| `client challenge`（Type 3 blob 8B） | ntlm 层 | rand（seed+序号可复现） | 每 session distinct；会话内与 blob 关联 |
| `timestamp`（blob 8B）/ `MsvAvTimestamp` | ntlm 层 | rand（可复现）或 fixture 钉死 | 运行期时间不进硬编码常量（§6/§7） |
| `proof`（16B HMAC-MD5）/ `MIC`（16B） | ntlm 层 | 不开（无授权密钥） | 无密钥不生成不断言其值（§7）；有 key log 时另立 fixture |
| `EncryptedRandomSessionKey` | ntlm 层 | 不开（opaque） | 长度由 SecurityBuffer 声明，值不可断言（§7） |
| `flags` | ntlm 层 | list（预置合法组合集） | 声明且可复核的 bits；reserved 置位入负例 |
| `target_info` AV_PAIR 集 | ntlm 层 | list（AV 组合轮转） | 多 AV 形态覆盖（#5/#7）；序号算法位置待 P4 定 |
| `version`（NTLMSSP 8B Version） | ntlm 层 | fixed（声明/不声明两档 fixture） | 仅 `NEGOTIATE_VERSION` 置位时存在（§6） |
| `outer` | ntlm 层 | fixed（none / spnego 两档 fixture） | 外层形态是 fixture 维度不是动态维度 |
| `profile` | ntlm 层 | fixed（smb2 / http-negotiate 两档） | 载体档案不可按流变化（业务语义约束） |

序号算法代码位置：**待 P4 定**（D-NTLM-1 定稿后 builder/planner 落码时钉死文件行号；此处不编行号——§5.7）。

### 16-P2 presence 负例形状（链级红例必含①）

层链+顶层空子映射并存=判死负例（presence 负例形状，非残留）：`{"layers":[{"ip":{}},{"tcp":{}},{"ntlm":{}}],"ntlm":{}}`（顶层空 `ntlm:{}` 与层链并存）必须被 planner/validator 拒，`error_contains` 含 `presence` 或顶层键锚词；P4 链级红例必含此形。白名单外游离键（如顶层 `src_mac`/`ttl`/`smb`/`http` 子映射）判死负例见 §17。

## 17. D-NTLM-1 P2 代码设计草稿（CORE_MEMORY §8 八要素；门1 获批=定稿）

> 体裁：文件清单/接口签名/数据结构/主流程/错误分支/性能设计与验收/回滚方式。依赖建模沿 §15.4 裁定 N1；`http` 层作为**声明的可选底座**（`OptionalOn ["http"]`）必须声明，链形 `[ip,tcp,http,ntlm]` 经框架 0c355be 已可达；`smb` 层的既有 NTLMSSP 实现（`emit_session.go:92-144`）为 P-SMB 参考权威，冲突点单列。

**文件清单（新建 4 + 接线 10）**：

| 文件 | 职责 |
|---|---|
| internal/core/ntlm.go（NEW） | NTLMConfig/Session/Event/Flags/TargetInfo 结构 + 严格 UnmarshalJSON（递归 DisallowUnknownFields）+ 6 wire_fault 常量与 DescribeNTLMWireFault 锚词表（kerberos.go/dtls.go 同范式） |
| internal/protocol/ntlm/builder.go（NEW） | 三消息 builder（固定头 + SecurityBuffer `Len\|MaxLen\|Offset` 三元组 + flags 位域 + AV_PAIR 序列 + 可选 Version/MIC + NTLMv2 blob）+ 双 profile 成帧（`smb2`：SMB2 header(64B)+SESSION_SETUP body+SecurityBuffer；`http-negotiate`：请求行/状态行+`WWW-Authenticate`/`Authorization` 头+base64）+ SPNEGO 外层（`none`/`spnego` 独立编码）+ ntlmWalker 会话状态单权威 + init() 注册 generator/validator |
| internal/protocol/ntlm/planner.go（NEW） | validateSpec/validateSession（walk renderEvent 同路径单权威）+ validateWireFault + 结构守卫（`Offset+Len` 32-bit 溢出/越界/重叠、UTF-16 偶数长度、`Len<=MaxLen`、flags 交集一致、AV_PAIR 的 `AvLen` 覆盖与 `MsvAvEOL` 收尾、blob 不超 NtChallengeResponse.Len）+ presence/白名单预检 |
| internal/protocol/ntlm/casegen_test.go（NEW） | 一次性生成器：21 例（15 正+6 负）契约计数逐例 add()，落 test/protocol_pcap/cases/ntlm.json |
| 接线件 | types.go `NTLM *NTLMConfig`（对照 `DTLS/Kerberos` 字段 :1818-1819）；FlowMeta.NTLM；translate `case "ntlm"` + **Meta 字面量 `NTLM: spec.NTLM` 直传**（固定检查点——dcerpc/dtls/kerberos 三犯处，链级红例必钉）；strategy_convert `case "ntlm"` + 端口默认（`smb2`→445、`http-negotiate`→80；`setDefaultDstPort` 在 `strategy_convert_helpers.go:41`，按 profile 分支或走 `chain_planner.go` 的 `setDefaultDstPort` 同款 switch——smb 现成写法 `chain_planner.go:1119-1128`）；registry 行（裁定 N1）+ 无 FieldContract（端口按 profile 两档，`FieldContract` 常量形不适用，同 smb 无 FieldContract 先例 `registry.go:1028-1030`）；validate_layers 预检（缺 tcp 载体 / 链夹 udp / 混合地址族 / 顶层旧键-presence 并存拒 / profile↔外层层有无不一致拒）；`internal/core/protocols.go` allowedProtocols 增 `"ntlm"`（实测当前零命中，与 `_neg_unregistered` 用例的注册前置严格同步）；`cmd/server/main.go` 空白导入 + `NewChainPlanner("ntlm")`；`internal/core/layer_dyn.go` 动态字段接线（§16.12 清单）；schemagen 重跑（层数 123→124） |
| tools/coverage_gate.py | check_ntlm（准入接线/关键件/守卫/用例面四段）+ 分发表增 `"ntlm": check_ntlm`（现表在 `:3045`，kerberos/dtls 为最新两项） |

**接口签名**（示意，P4 落码钉死）：`GenerateNTLMMessage(cfg, msgType) []byte` / `FrameSMB2SessionSetup(cfg, token) []byte` / `FrameHTTPNegotiate(cfg, token, status) []byte` / `WrapSPNEGO(token) []byte` / `ValidateNTLMSpec(spec) error` / `DescribeNTLMWireFault(fault string) string`。
**数据结构**：Session{id, profile, events[], flags, target_info, outer}；Event{kind(negotiate|challenge|authenticate|session_setup_success|challenge_401|http_success)}；Flags{extended_session_security, target_info, key_exch, version, unicode, ...}；TargetInfo{av_pairs[]}。
**主流程**：validateSpec → 逐会话 walker → 逐事件 render（Type 1/2/3 构造 → profile 成帧 → EmitMsg）→ worker → tcp 分段/握手 → pcap/NIC。
**错误分支（§5.2）**：①`wire_fault` 6 值注入拒（锚词进断言）；②自然守卫：`Offset+Len` 溢出/越界/重叠、`Len>MaxLen`、UTF-16 奇数长度、flags 交集不一致、AV_PAIR 缺 EOL/`AvLen` 越界、blob 超界、token<12B/错误 signature/未知 type；③`validate_layers` 预检：缺 tcp 载体、链夹 udp、混合地址族、presence 并存、profile↔外层层不一致。全部传播为 task error，零假成功（禁止 `completed/0 packet`）。
**依赖声明（§5.1）**：依赖 `tcp` 层（唯一载体，`TransportOn ["tcp"]`；握手/seq-ack/挥手/MSS 分段由 tcp 层管）；**`http` 层作可选底座依赖声明**（`OptionalOn ["http"]`，用户显式写才供给；链形生效经框架 0c355be 实装，见裁定 N1）；依赖 TCP stream 重组（消息可跨 segment）；无外部密钥依赖（proof/MIC/session key opaque）。**不含 `udp` 依赖**。
**性能设计与验收（§6.1–6.8）**：O(n) 流式——逐事件渲染直发 EmitMsg，无全量聚合（与 legacy 生成器同形）；确定性内存（无按包增长结构）；无休眠/无锁（事件驱动，速率由既有 pacer 统一）；pcap 路实测 + NIC 路注记（过滤器 `tcp port 445` / `tcp port 80 or tcp port 443`，说明 checksum offload 与 TLS/SMB encryption 观察边界）；回归口径=`ntlm.json` 全量 suite 耗时与同族协议（kerberos/dtls）同量级；六类场景（基线/目标规模/压力上限/长运行时/并发交错/背压）P5 跑测覆盖；**边界诚实声明**：吞吐/并发/内存目标数字待 P4 基准后定（§6.5，不写承诺）。
**与现有逻辑冲突点（§8.7）**：①**权威重叠**——`smb` 层已内建 NTLMSSP Type 1/2/3 blob 生成（`internal/protocol/smb/emit_session.go:92-101`（`buildNTLMSSPNegotiateBlob`/`buildNTLMSSPAuthBlob`）、`:144`（`buildNTLMSSPChallengeBlob`）、`:130`（非末轮 → `StatusMoreProcessingRequired`）、`:110`（`buildGSSAPIBlob("ntlm")` SPNEGO 形）），`ntlm` 层的 P-SMB 自封帧与之语义同域；**P4 落码前必须裁定复用/独立/边界（禁止双头权威）**→G-NTLM-3（参考：`smb` 的 `auth_rounds` 限 2|3 轮、`internal/protocol/smb/validate.go:70-72`；`security_blob` 为用户 GSS-API 透传口，`internal/core/types.go:10001-10003`）；②`http` 层在 spnego/ocsp 兄弟契约中被写作 `OptionalOn ["http"]` + 链形 `[ip,tcp,http,X]`，与本仓库 V2 校验冲突（§15.4 先证 2）——本契约按实测收口为 `[ip,tcp,ntlm]`，兄弟契约的同一问题已上报主线程；③`FieldContract` 常量形不适用于双端口 profile（无 FieldContract，端口默认走 planner switch）；④schemagen 重跑层数 123→124，`allowedProtocols` 与 `_neg_unregistered` 占位必须同批翻转（否则占位由「unknown layer」变「invalid or missing protocol」，负例锚词漂移）。
**回滚方式（§8.8）**：全量 revert 新建文件 + 接线件回退（git revert 提交序）；registry/schemagen 生成文件与 `allowedProtocols` 随提交对齐回退；`cases/ntlm.json` 恢复 `ntlm_neg_unregistered` 单占位；无数据迁移面。

## 18. P3 测试对接清单（T-NTLM 草稿输入；正文落 testcase 文件）

- §3.15 三项：①同连接/同流内多轮操作→#1/#2/#12（SMB2 同 TCP 连接 Type 1→2→3，含 3 轮「Type 3 后仍 MORE」）；②非正常结束→#12（最终 `LOGON_FAILURE`/401 拒，失败后不发 authenticated data）；载体会话中断形（服务端主动 FIN/RST mid-auth）→G-NTLM-5；③长保活→#11（分段/多流）+ A′ 补例 T-22（keep-alive 多认证事务）。逐项一例或立项，无空项。
- A′/B′ 两分类表：见 testcase §8.2（A′ 四类要求面→21 ID 落点（含已并入的 T-21）；B′=G-NTLM-1…6 进 D-NTLM-1「明确不解决+迁入计划」）。
- 9.52 对账两行：见 testcase §8.3（规范逻辑点总数 47 = §14.1 八项 8 行 + §14.2 矩阵 16 格 + §14.3 变体 23 行；用例覆盖数 40 + 不适用 2 + 台账内立项 5 = 47；清单出处=规范/官方文档反推）。台账粒度=行/格粒度，子面缺口（G-NTLM-1/2/3/4/6）另登 §19、不折进 47 点也不冒充覆盖。
- 3.14 豁免边界审计：见 testcase §8.4（有长连接载体 → `sessions[]` 不豁免；多流并发 #10/#11 + 单消息多载荷 #5/#7 各至少一例）。
- 三源回指行：见 testcase §8.5。
- 断言通道：fields 用 `ntlmssp.*`（**147 字段已实测**：`ntlmssp.identifier`/`ntlmssp.messagetype`/`ntlmssp.negotiateflags`/`ntlmssp.negotiate.domain`/`ntlmserverchallenge`/`challenge.target_name`/`challenge.target_info.item.type`/`auth.username|domain|hostname|lmresponse|ntresponse|sesskey`/`string.length|maxlen|offset`/`ntlmv2_response.ntproofstr|time|chal`/`authenticate.mic`/`version.*`）+ 载体 `tcp.dstport`/`ip.proto`/`ipv6.nxt`/`smb2.security_blob`/`http.*`；固定头/offset/AV_PAIR/frames 走 frames hex 钉；动态值用 presence/nonzero/distinct/same_as；不自创字段名。

## 19. 缺口立项清单（有缺口写「缺口立项」，不许空着）

| 立项号 | 缺口 | 确认方式（三选一：查文档/抓包/问人） | 去向 |
|---|---|---|---|
| G-NTLM-1 | `[ip,tcp,smb,ntlm]` 原生层嵌套不可达（`smb` 无 `TransformEvents`、无层依赖它、生成器无 `EventTransformer`）——须动跨协议框架 | 读 `registry.go:1028-1030` + `complete.go:405-435` + `chain_planner_chain.go:243-253`（三处行号实测） | **上报主线程**（跨协议框架文件，车道不得自改）；P4 走裁定 N1 的可达链形，本项不挡开工 |
| ~~G-NTLM-2~~（**已关闭**） | ~~`[ip,tcp,http,ntlm]` 不可达（`OptionalOn` 不参与 V2 豁免）~~ → 框架 commit `0c355be` 已把 `OptionalOn` 计入 `dependedOn`（`complete.go`），链形可达 | 回归证据：`optional_on_chain_test.go` 正反两例 + T18/T18b 语义不变，`go test ./internal/core/layers/ -count=1` 全绿 | **已关闭**（2026-09-25 主线程框架修复；原「上报主线程」已处置） |
| G-NTLM-3 | `ntlm` 层 P-SMB 自封帧 与 `smb` 层既有 NTLMSSP 实现（`emit_session.go:92-144`）的权威重叠裁定（复用/独立/边界） | 读两侧实现（`internal/protocol/smb/emit_session.go:92-144`、`internal/protocol/smb/validate.go:57-72`、`internal/core/types.go:9988-10003`）+ 抓包比对线上字节 | D-NTLM-1「明确不解决 + 迁入计划」；**P4 落码前必裁定**（禁双头） |
| G-NTLM-4 | 现网抓包核对：Windows/AD/Samba 的 SMB2 SESSION_SETUP SPNEGO 包装形态、status trio 与轮数；impacket 直发形；IIS/`curl --ntlm` 的 HTTP Negotiate 头序 | 抓回环/真实客户端包（问谁：无，抓包即确认） | P4 前置确认项，不挡开工 |
| G-NTLM-5 | 代理/隧道与载体异常面：HTTP 代理（绝对 URI/Host）+ HTTPS 443 经 CONNECT 隧道（opaque）；载体会话中断（服务端主动 FIN/RST mid-auth、401 无后续、SMB2 非 `LOGON_FAILURE` 错误 status） | 查 RFC 4559 §4.2 + 抓代理/中断场景包 | B′→D-NTLM-1「明确不解决 + 迁入计划」（覆盖 §14.2 四格 + §14.3 行 23） |
| G-NTLM-6 | NTLMv1/LM response 方言面（规范定义了 NTLMv1/LM 形态，现网默认禁用） | 查微软 LMCompatibilityLevel 官方文档 + 抓老客户端包（三选一收口后写结论） | **三选一收口**：已实现 / 明确不支持 / 不适用 + 理由（§4.19 不留白）；D-NTLM-1 迁入计划 |
