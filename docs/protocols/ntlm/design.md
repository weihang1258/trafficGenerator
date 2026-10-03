# NTLM 设计契约（文档轨）

> 版本：v1.2.0（2026-09-30）  
> 范围：D1–D8；只维护设计契约与迁移后的测试形状，不改 Go 实现。  
> 规范：MS-NLMP §2.2.1–§2.2.3、MS-SMB2 §3.2.5.3/§3.3.5.2.4、RFC 4178、RFC 4559 §1/§4.2、RFC 2743、RFC 791/8200/9293。  
> 机器契约：`trafficgen/test/protocol_pcap/cases/ntlm.json`。当前实现是否已通过 suite 以实际运行结果为准，本文不把 JSON 静态形状冒充运行通过。

## D1 范围、证据与边界

NTLM 是寄居在 TCP 承载上的 NTLMSSP 三消息认证：NEGOTIATE（Type 1）、CHALLENGE（Type 2）、AUTHENTICATE（Type 3）。本契约覆盖 NTLMv2、SMB2 Session Setup（TCP/445）和 HTTP Negotiate（TCP/80；443 仅允许声明不透明 TLS carrier），以及裸 NTLMSSP/SPNEGO 两种外层。

覆盖固定头、little-endian flags、SecurityBuffer（Len/MaxLen/Offset）、TargetInfo/AV_PAIR、NTLMv2 blob、可选 Version/MIC/session-key 边界、状态/重试/拒绝、IPv4/IPv6、分段、多会话和 PCAP/NIC 观察。无授权密钥时 proof、MIC、timestamp、client challenge、session key 只断言 presence、长度、nonzero、distinct 或 same_as，不断言其值。

不承诺 NTLMv1/LM 方言、代理/CONNECT 隧道、中途 FIN/RST、SMB3 加密或 HTTPS 明文解密；这些属于 G-NTLM-5/G-NTLM-6 缺口，不得写成已覆盖。

## D2 严格层链与配置权威

地址只在 `ip`，端口只在 `tcp`，NTLM 业务字段只在 `ntlm`，数量只在顶层 `flow_control`。顶层只允许 `layers`、`flow_control` 家族和 `output`；禁止顶层 `src_ip`、`dst_ip`、`src_port`、`dst_port`、`count`、`ntlm`、`smb`、`http` 游离映射。`profile` 显式值选择 `smb2` 或 `http-negotiate`；省略时实现按缺省档生成最小 SMB2 NEGOTIATE，不由目标端口推导。

两种目标链形：

- P-SMB：`[ip,tcp,ntlm]`，`ntlm.profile=smb2`，目的端口 445；SMB2 Session Setup 外壳由 NTLM profile 负责。
- P-HTTP：`[ip,tcp,http,ntlm]`，`ntlm.profile=http-negotiate`，目的端口 80（443 仅 opaque）；`http` 是显式可选底座，不自动补入。

`[ip,tcp,smb,ntlm]` 结构不可达，登记为 G-NTLM-1；不得把它写成正例。IPv6 地址仍住 `ip.src`/`ip.dst`。

```json
{
  "layers": [
    {"ip": {"src": "192.0.2.60", "dst": "198.51.100.60"}},
    {"tcp": {"src_port": 45600, "dst_port": 445}},
    {"ntlm": {"profile": "smb2", "version": "ntlmv2", "outer": "spnego", "sessions": [{"id": "s1", "events": [{"kind": "negotiate"}, {"kind": "challenge"}, {"kind": "authenticate"}, {"kind": "session_setup_success"}]}]}}
  ],
  "flow_control": {"flows": 1}
}
```

## D3 线格式、边界与偏移

NTLMSSP 起点由承载解析得到，不由 IP/TCP packet 偏移猜测。通用头为 `NTLMSSP\0`（8 bytes）+ MessageType（4-byte little-endian，值 1/2/3）。SecurityBuffer 为 `Len(2)|MaxLen(2)|Offset(4)`，Offset 相对 NTLMSSP 起点；`Len<=MaxLen`，`Offset+Len` 不溢出且完全在 token 内，字段不得重叠。Unicode 字段长度必须为偶数。

Type 2 的 ServerChallenge 为 8 bytes；TargetInfo 每项是 `AvId(2)|AvLen(2)|Value`，最终必须有 `MsvAvEOL=0, AvLen=0`。Type 3 NTLMv2 response 至少包含 16-byte proof 和完整 blob：response version、timestamp、client challenge、AV_PAIR/EOL。Version 仅在协商 flags 声明时有 8 bytes；MIC 为 16 bytes。

SMB2 的 token 位于 Session Setup SecurityBuffer；HTTP 的 token 位于 `Negotiate` header（base64 解码后再看 NTLMSSP）；TLS 未解密时只观察 TCP/TLS carrier。TCP segmentation 必须先按 stream 重组再解析 token。

## D4 状态、会话与业务序列

单会话状态为 `Initial → NegotiateSent → ChallengeReceived → AuthenticateSent → Accepted/Rejected`。SMB2 中间状态为 `STATUS_MORE_PROCESSING_REQUIRED`，成功为 `STATUS_SUCCESS`；HTTP 中间状态为 401/407，成功为 2xx。重复 challenge 是同一 session 的 retry，不得静默推进成功；最终失败必须传播 task error 或 rejected 终态，失败后不得发送 authenticated data/2xx。

`sessions[]` 显式声明每个会话；会话有独立 id、四元组、生命周期和 challenge。多会话/多流可交错，但每条 TCP stream 重组后的消息顺序必须保持 Type 1→2→3。NTLM 无独立派生数据流，故不伪造 `driven_by`。

## D5 规范要求→用例→代码现状→缺口矩阵

| 要求 | 用例落点 | 当前代码/缺口结论 |
|---|---|---|
| 三消息与 SMB2/HTTP 载体 | #1–#3、#9、#12、#15 | JSON 已声明；生成/验证实际行为仍以实现审计为准 |
| SecurityBuffer、flags、Version、AV_PAIR、blob | #4–#8、#13、负例 #16–#20 | JSON 已声明；非法输入需 planner/validator 拒绝 |
| IPv4/IPv6 × SMB/HTTP | #1/#2/#3/#15 | 四格均有例，地址族不互相代表 |
| 多会话、多流、分段、重试 | #10–#12 | 已有语义例；必须按 stream/session 断言 |
| PCAP/NIC 一致性 | #14 | PCAP 与授权 NIC 双路验收，记录 offload 边界 |
| 代理/隧道、中断、NTLMv1/LM | G-NTLM-5/G-NTLM-6 | 明确不解决，不能从现有正例推断覆盖 |

## D6 错误处理与缺口计划

六类负例必须在 planner/validator 失败并保留锚词，禁止成功 PCAP、`completed/0 packet` 或只输出 TCP/HTTP/SMB2 外壳：截断（message/signature）、SecurityBuffer（buffer/length/unicode）、offset 溢出/重叠（offset/overflow/overlap）、flags/TargetInfo（flags/target/capability）、blob/AV_PAIR（response/blob/av）、载体 profile（carrier/profile/spnego/transport）。

| 缺口 | 计划 |
|---|---|
| G-NTLM-1：`smb` 与 `ntlm` 双终结层不可达 | 主线程评估跨层变换；本次只用 `[ip,tcp,ntlm]` |
| G-NTLM-3：`smb` 既有 NTLMSSP 与独立 ntlm 权威重叠 | P4 落码前裁定复用/边界，禁止双头权威 |
| G-NTLM-4：Windows/AD、Samba、impacket、IIS/curl 现网核对 | 授权回环抓包后逐条映射，不以猜测代替证据 |
| G-NTLM-5：代理、CONNECT、TLS opaque、载体中断 | 查 RFC 4559 并抓授权场景后另立 cases |
| G-NTLM-6：NTLMv1/LM 方言 | 查 MS-NLMP 与微软策略并三选一收口 |
| 性能基线 | 实现后测基线、目标规模、压力、长跑、交错、背压六类；当前不承诺数字 |

## D7 性能、输出与验收

目标路径应按 session/event 流式生成，不聚合全部 token；使用既有有界队列、缓冲和统一限速，不新增无界缓存。验收分两路：PCAP 校验 carrier、方向、stream、字段、raw bytes、长度和偏移；NIC 使用 `tcp port 445` 或 `tcp port 80/443`，记录接口、checksum offload、TLS/SMB encryption 不透明边界。吞吐、并发、内存和丢包预算待实现后实测。

## D8 接口、文件与回滚边界

实现阶段应补齐 NTLM 层 schema、严格配置解码、三消息 builder、双 profile 成帧、状态 walker、planner/validator、生成器和 suite 接线；接口至少覆盖消息构造、SMB2/HTTP framing、SPNEGO wrapping、spec validation 和 wire-fault 描述。所有错误从 planner/worker 传播到 task error。

回滚只撤销 NTLM 注册、实现、生成文件和 cases 迁移，恢复前一版本机器契约；不修改其他协议或跨协议框架。本文与 testcase 先于实现定稿。

## 21 个语义 ID（与 JSON 顺序一致）

正例 15 个：`ntlm_smb_ipv4_v2_basic`、`ntlm_smb_ipv6_v2_basic`、`ntlm_http_negotiate_v2`、`ntlm_negotiate_flags_version`、`ntlm_challenge_target_info`、`ntlm_authenticate_security_buffers`、`ntlm_ntlmv2_blob_av_pairs`、`ntlm_mic_session_key_opaque`、`ntlm_spnego_outer_separation`、`ntlm_multi_session_isolation`、`ntlm_multi_flow_streams`、`ntlm_retry_auth_failure`、`ntlm_record_boundary_offsets`、`ntlm_pcap_nic_consistency`、`ntlm_http_negotiate_v6`。

负例 6 个：`ntlm_neg_message_truncated`、`ntlm_neg_security_buffer`、`ntlm_neg_offsets_overlap_overflow`、`ntlm_neg_flags_target_info`、`ntlm_neg_v2_blob_av_pairs`、`ntlm_neg_carrier_profile`。

本版自审：两轮。第一轮核对 D1–D8、层链唯一真相、缺口和 21 个 ID；第二轮核对示例顶层白名单、错误锚词、未宣称运行通过，末轮干净。

## 静态闭环对账（D1–D8 / C1–C6）

| ID | 设计要求 | 当前结论与证据 |
|---|---|---|
| D1 | 范围、规范依据、证据边界 | NTLMv2、MS-NLMP/MS-SMB2、RFC 4178/4559/2743 已列明；现网抓包与未实现方言不伪造，G-NTLM-4/6 保留。 |
| D2 | 严格层链唯一配置真相 | 所有机器用例为 `[ip,tcp,ntlm]`；地址、端口、业务分别归层；P-HTTP `[ip,tcp,http,ntlm]` 是显式可选底座目标形，不向当前 cases 机械添加空层。 |
| D3 | 固定头、SecurityBuffer、偏移边界 | Type 1/2/3、little-endian 三元组、AV_PAIR/EOL、32-bit 溢出/重叠与 UTF-16 偶数约束均有设计条目，并由正负 ID 对应。 |
| D4 | 状态、会话、重试、多流 | `sessions[]` 与事件顺序明确；#10/#11 覆盖隔离/分段，#12 覆盖重试与最终拒绝；无响应/中断进 G-NTLM-5。 |
| D5 | 规范→业务→代码→缺口矩阵 | §D5 与 §D6 已逐面列出；NTLM layer、planner、validator 和生成器已存在，但本轮不以静态文件冒充 suite 运行通过。 |
| D6 | 错误处理与迁入计划 | 六类负例锚词与 `wire_fault` 对应；G-NTLM-1/3/4/5/6 写明确认方式和迁入去向。 |
| D7 | 性能、PCAP/NIC 验收 | 流式 O(n)、有界队列、PCAP/NIC 双路和六类性能场景已定义；无实测数字不作承诺，C6 待真实流程。 |
| D8 | 接口、文件、回滚边界 | builder/planner/接线文件、错误传播及回滚范围均已列出；本次仅改文档与机器用例，不改 Go/schema。 |

## C1–C6 与 T1–T6 交叉核对

| ID | 静态核对 | 结论 |
|---|---|---|
| C1/T1 | JSON 语法、21 个唯一 ID、数量与顺序 | 21/21 可解析且唯一；15 正 + 6 负，与 §11 和 testcase §T2 同序。 |
| C2/T2 | 层链、顶层白名单、地址/端口归属 | 21/21 为 `[ip,tcp,ntlm]`；正例顶层旧键零残留，地址仅 `ip`，端口仅 `tcp`。 |
| C3/T3 | 正例字段、帧、packet_count | 15/15 正例均有 `fields`、`frames`、`packet_count`；序列为 11/11/11/15/11/11/11/11/11/15/17/13/15/11/11。 |
| C4/T4 | 负例双键与锚词 | 6/6 负例 `expect` 严格只有 `expect_error`、`error_contains`；message/buffer/offset/flags/blob/carrier 六类锚词有落点。 |
| C5/T5 | 组合场景与缺口 | 多会话、多流、重试和状态面有例；代理/中断、现网核对、NTLMv1/LM 不从正例推断，登记 G 缺口及迁入计划。 |
| C6/T6 | 真实流程与运行边界 | 本轮完成 JSON/tool、diff-check 静态门；未运行 suite/MCP/NIC，不宣称 PCAP/NIC 全绿。 |

### 闭环自审

第一轮逐条回查 D1–D8、T1–T6、C1–C6、21 个 ID、层链和 G 缺口；第二轮复核 packet_count、正负 expect 键集合、锚词、代码现状引用和未运行边界，末轮干净。

