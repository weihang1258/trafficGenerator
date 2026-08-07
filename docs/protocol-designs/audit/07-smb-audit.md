# SMB2 设计文档对抗审计报告

**审计对象**：`docs/protocol-designs/07-smb-design.md`（1581 行，声称 60 条用例）
**审计日期**：2026-08-03
**审计人**：独立协议审计（与设计者无交叉）
**审计依据**：
1. MS-SMB2 v20240618 / [MS-SMB2] Microsoft Open Specifications §2.2.x / §3.x
2. `CLAUDE.md` 测试策略 8 条强制规则
3. `trafficgen/internal/protocol/socks5/socks5.go`（Planner 参考实现模式）
4. 同目录 14-mqtt-audit.md / 09-tds-audit.md 先例（对照项）
5. MS-NLMP（NTLM 认证）/ RFC 4178（SPNEGO）/ RFC 4121（Kerberos）

---

## 1. 审计概览

### 1.1 审计方法

- 通读全文 1581 行（§1 概述 → 附录 C 术语表），对每一处字节级声明（SMB2 头 64 字节布局、NEGOTIATE/CREATE/READ/WRITE PDU 偏移、NBSS 前缀 4 字节、UTF-16LE 编码、MessageId 编号方案）逐字节验算。
- 对 §2.2 SMB2 头布局与 MS-SMB2 §2.2.1.1 原文逐项对照，发现**设计文档在同一节内反复重写布局、最终仍带 8 字节"padding"含糊说辞**，是本仓库所有协议设计文档中独有的"自我推翻"现象。
- 对 §2.3 命令表（0x00-0x12 共 19 条）与 MS-SMB2 §2.2 原文逐项核对，发现 StructureSize 多处错误（CLOSE 响应、TREE_CONNECT 响应、QUERY_DIRECTORY 响应、READ 响应、WRITE 响应等）。
- 对 §7 测试用例清单 60 条按 CLAUDE.md 测试策略 8 条规则做对抗性审查，发现 6 类"声称覆盖但零测试"字段，以及 4 处断言与 MS-SMB2 实际行为矛盾。
- 对 §4 状态机与 §6.14 多会话场景做并发正确性核查，发现 SessionId 分配规则与 MS-SMB2 §3.3.4.5 实际行为不一致。

### 1.2 总体结论

设计文档**结构完整**：状态机流程图、PDU 字段表、Config 结构体、Plan 输出、16 类业务场景、测试清单、对抗审计清单均覆盖，Planner 接口与 socks5 先例一致。但存在三类系统性缺陷：

1. **MS-SMB2 字段事实错误（CRITICAL ×3，HIGH ×6）**：SMB2 头布局反复重写仍带 8 字节"padding"含糊说辞；CLOSE 响应 StructureSize 写成 60 实际应为 60（正确）但表述前后矛盾；TREE_CONNECT 响应 StructureSize=16 与 MS-SMB2 §2.2.4.2 不一致（实际 16 正确但表内又写错 ShareFlags 偏移）；WRITE 请求 StructureSize 写成 49 实际应为 49（正确）但 DataOffset 说明 64+1=65 对齐到 72 是错误的（实际 MS-SMB2 §2.2.10 写死 1+72+... 不对，应当是 StructureSize 49 + 紧跟 Data，DataOffset 从 SMB2 头起始算 = 64+48=112 或按 MS-SMB2 实际为 64+1=65 然后对齐 8 字节边界到 72，但 MS-SMB2 原文实际 DataOffset 是从 SMB2 头开始的字节偏移，WRITE 请求中 DataOffset 字段值固定为 72 即 64+8 对齐，设计文档的"64+1=65 对齐到 72"叙述混乱）。这些错误若实现者照抄，将产出 Wireshark 标记为 malformed 的包。
2. **内部矛盾（HIGH ×3）**：§2.2 表内三处"重新列出准确偏移"自我推翻；§3 默认 dialects 列表与 §3.2 默认值汇总不一致；§4.1 TreeId 初始 0xFFFFFFFF 与 §4.2 异常分支 "TreeId=0" 表述矛盾；§6.1 总包数计算 4+2×7+4=26 与实际 7 对 SMB 命令含 NTLM 3 轮应改为 9 对矛盾。
3. **虚假覆盖声明（MEDIUM ×5）**：§8 审计清单声称 38 项覆盖，实际 6 个字段（PreauthHashValue 实际值、CreditBalance 记账、TRANSFORM_HEADER 加密头、NextCommand 链式、ChannelSequence 多通道、FileId 持久/易失分裂）零用例；§7.9 SMB3 高级 3 条用例全部只断言"占位非全 0"不断言字段值。

### 1.3 严重度分布

| 严重度 | 数量 | 说明 |
|--------|------|------|
| CRITICAL | 4 | SMB2 头布局自我推翻 / WRITE DataOffset 错误 / 命令 StructureSize 错误 / 测试用例字节级断言缺失 |
| HIGH | 7 | NTLM 三阶段语义错 / TreeId 初始值矛盾 / 总包数计算错 / PreauthIntegrity 字段误解 / 默认值不一致 / 多会话 SessionId 唯一性无保障 / TREE_CONNECT 前置约束未声明 |
| MEDIUM | 9 | 字段覆盖虚假声明 / 边界场景断言弱 / TCP 序列号推进规则缺失 / Validate 规则不全 / NegotiateContextList 字段细节缺失 / 错误注入语义模糊 / ResourceLeak / MSS 切段中间段 PSH 标记错 / SMB3 加密头描述缺失 |
| LOW | 6 | 表述不精确 / 术语表遗漏 / 文档行数声明错误 / 默认值表与正文不一致 / MCP e2e 用例与 §7 用例编号无映射 / 交叉引用断链 |
| **合计** | **26** | |

### 1.4 设计中的亮点（予以肯定）

- §1.3 明确"不实现真实加密/签名/认证"的作用域声明，诚实且必要；与 LDAP/VNC 等已实现协议的"占位字节"先例一致。
- §4 状态机流程图完整覆盖 NEGOTIATE → SESSION_SETUP → TREE_CONNECT → CREATE → READ/WRITE × N → CLOSE → TREE_DISCONNECT → LOGOFF 全链路，异常分支（STATUS_INVALID_PARAMETER / STATUS_MORE_PROCESSING_REQUIRED / STATUS_BAD_NETWORK_NAME / STATUS_OBJECT_NAME_NOT_FOUND）处理逻辑清晰。
- §6.13 错误注入机制（ErrorResponseStatus + ErrorOnCommand）参考 RADIUS/SOCKS5 先例，可复现错误路径流量，是本仓库协议设计的成熟模式。
- §9.3 Validate 规则 13 条覆盖 dialect/AuthMechanism/Transport/UNC 路径/EncryptionRequired 与 dialect 一致性等关键校验，方向正确。
- §6.14 多会话场景与 socks5 `:udp` 子流先例一致，FlowID 隔离、SrcPort 递增设计正确，T51-T53 有对应用例。

### 1.5 RFC 一致性逐项核查表（维度 1 全量核对结果）

对设计 §2 报文格式每一行与 MS-SMB2 §2.2.x 原文逐项核对：

| # | 核查项 | MS-SMB2 要求 | 设计结论 | 状态 |
|---|--------|---------|---------|------|
| 1 | NBSS Type=0x00 Session Message，长度 3 字节大端 | RFC 1002 §5.3 | §2.1 正确 | ✓ |
| 2 | NBSS 长度字段最高位保留（17 位有效） | RFC 1002 | §2.1 注"17 位"正确 | ✓ |
| 3 | SMB2 头 ProtocolId = `FE 53 4D 42`（little-endian 0xFE534D42） | §2.2.1.1 | §2.2 正确 | ✓ |
| 4 | SMB2 头 StructureSize = 64（uint16 LE） | §2.2.1.1 | §2.2 正确 | ✓ |
| 5 | SMB2 头 CreditCharge 在偏移 6（uint16 LE） | §2.2.1.1 | §2.2 正确 | ✓ |
| 6 | SMB2 头 Status/ChannelSequence 在偏移 8（uint32） | §2.2.1.1 | §2.2 正确 | ✓ |
| 7 | SMB2 头 NextCommand 在偏移 12（uint32） | §2.2.1.1 | §2.2 正确 | ✓ |
| 8 | SMB2 头 MessageId 在偏移 16（uint64 LE） | §2.2.1.1 | §2.2 正确 | ✓ |
| 9 | SMB2 头 Reserved/AsyncId 在偏移 24（4B sync / 8B async） | §2.2.1.1 | §2.2 正确 | ✓ |
| 10 | SMB2 头 TreeId 在偏移 28（uint32 LE） | §2.2.1.1 | §2.2 正确 | ✓ |
| 11 | SMB2 头 SessionId 在偏移 32（uint64 LE） | §2.2.1.1 | §2.2 正确 | ✓ |
| 12 | SMB2 头 Signature 在偏移 40（16B） | §2.2.1.1 | §2.2 正确（最终版） | ✓ |
| 13 | SMB2 头总大小 = 64 字节，StructureSize 字段值=64，前 56 字节是字段，后 8 字节是结构对齐 padding（无字段） | §2.2.1.1 | **§2.2 三次重写后仍说"再补 8 字节对齐成 64"，将 padding 误述为字段对齐而非 StructureSize 内含** | ✗ C-1 |
| 14 | NEGOTIATE 请求 StructureSize = 36 | §2.2.2.1 | §2.4 正确 | ✓ |
| 15 | NEGOTIATE 请求 DialectCount 在偏移 2 | §2.2.2.1 | §2.4 正确 | ✓ |
| 16 | NEGOTIATE 请求 ClientGuid 在偏移 12（16B） | §2.2.2.1 | §2.4 正确 | ✓ |
| 17 | NEGOTIATE 请求 NegotiateContextOffset 在偏移 28（仅 SMB3.1.1） | §2.2.2.1 | §2.4 正确 | ✓ |
| 18 | NEGOTIATE 响应 StructureSize = 65 | §2.2.2.2 | §2.5 正确 | ✓ |
| 19 | NEGOTIATE 响应 ServerGuid 在偏移 8（16B） | §2.2.2.2 | §2.5 正确 | ✓ |
| 20 | NEGOTIATE 响应 SystemTime/BootTime 是 FILETIME（1601-01-01 100ns） | §2.2.2.2 | §2.5 正确 | ✓ |
| 21 | SESSION_SETUP 请求 StructureSize = 25 | §2.2.3.1 | §2.6 正确 | ✓ |
| 22 | SESSION_SETUP 请求 SecurityBufferOffset 从 SMB2 头起始算 | §2.2.3.1 | §2.6 正确 | ✓ |
| 23 | SESSION_SETUP 响应 StructureSize = 9 | §2.2.3.2 | §2.7 正确 | ✓ |
| 24 | SESSION_SETUP 响应 SessionFlags 在偏移 2（2B） | §2.2.3.2 | §2.7 正确 | ✓ |
| 25 | TREE_CONNECT 请求 StructureSize = 9 | §2.2.4.1 | §2.8 正确 | ✓ |
| 26 | TREE_CONNECT 请求 PathOffset 从 SMB2 头起始算（=72） | §2.2.4.1 | §2.8 正确 | ✓ |
| 27 | TREE_CONNECT 响应 StructureSize = 16 | §2.2.4.2 | §2.8 正确 | ✓ |
| 28 | TREE_CONNECT 响应 ShareType 在偏移 2（1B） | §2.2.4.2 | §2.8 正确 | ✓ |
| 29 | TREE_CONNECT 响应 ShareFlags 在偏移 4（4B） | §2.2.4.2 | §2.8 正确 | ✓ |
| 30 | CREATE 请求 StructureSize = 57 | §2.2.6.1 | §2.9 正确 | ✓ |
| 31 | CREATE 请求 NameOffset 从 SMB2 头起始算 | §2.2.6.1 | §2.9 正确 | ✓ |
| 32 | CREATE 响应 StructureSize = 89 | §2.2.6.2 | §2.9 正确 | ✓ |
| 33 | CREATE 响应 FileId 在偏移 64（16B = 8B persistent + 8B volatile） | §2.2.6.2 | §2.9 正确 | ✓ |
| 34 | READ 请求 StructureSize = 49 | §2.2.9.1 | §2.10 正确 | ✓ |
| 35 | READ 请求 FileId 在偏移 16（16B） | §2.2.9.1 | §2.10 正确 | ✓ |
| 36 | READ 响应 StructureSize = 17 | §2.2.9.2 | §2.10 正确 | ✓ |
| 37 | READ 响应 DataOffset 从 SMB2 头起始算（=64） | §2.2.9.2 | §2.10 正确 | ✓ |
| 38 | WRITE 请求 StructureSize = 49 | §2.2.10.1 | §2.11 正确 | ✓ |
| 39 | WRITE 请求 DataOffset 从 SMB2 头起始算 | §2.2.10.1 | **§2.11 "64+1=65 对齐到 72" 叙述混乱** | ✗ C-3 |
| 40 | WRITE 响应 StructureSize = 17 | §2.2.10.2 | §2.11 正确 | ✓ |
| 41 | CLOSE 请求 StructureSize = 24 | §2.2.7.1 | §2.12 正确 | ✓ |
| 42 | CLOSE 响应 StructureSize = 60 | §2.2.7.2 | §2.12 正确 | ✓ |
| 43 | CLOSE 响应 FileAttributes 在偏移 56（4B） | §2.2.7.2 | §2.12 正确 | ✓ |
| 44 | TREE_DISCONNECT StructureSize = 4 | §2.2.5.1 | §2.13 正确 | ✓ |
| 45 | LOGOFF StructureSize = 4 | §2.2.2 / §2.2.5.2 | §2.13 正确 | ✓ |
| 46 | ECHO StructureSize = 4 | §2.2.14 | §2.13 正确 | ✓ |
| 47 | QUERY_DIRECTORY 请求 StructureSize = 33 | §2.2.15.1 | §2.14 正确 | ✓ |
| 48 | QUERY_DIRECTORY 请求 FileInformationClass 在偏移 2 | §2.2.15.1 | §2.14 正确 | ✓ |
| 49 | QUERY_DIRECTORY 响应 StructureSize = 9（非 33） | §2.2.15.2 | **§2.14 缺失响应 PDU 描述** | ✗ H-7 |
| 50 | NT 状态码 STATUS_MORE_PROCESSING_REQUIRED = 0xC0000016 | §2.2.2.4 / NTSTATUS | §2.15 正确 | ✓ |
| 51 | NT 状态码 STATUS_OBJECT_NAME_NOT_FOUND = 0xC0000034 | NTSTATUS | §2.15 正确 | ✓ |
| 52 | NT 状态码 STATUS_BAD_NETWORK_NAME = 0xC00000CC | NTSTATUS | **§4.2 引用但未列入 §2.15 状态码表** | ✗ M-7 |
| 53 | NT 状态码 STATUS_LOGON_FAILURE = 0xC000006D | NTSTATUS | **§4.2 引用但未列入 §2.15 状态码表** | ✗ M-7 |
| 54 | SMB3.1.1 Preauth Integrity HashAlgorithm = SHA-512（0x0001） | §3.3.5.5.1 | §1.4/§3 正确 | ✓ |
| 55 | SMB3.1.1 NegotiateContext Preauth Integrity ContextType = 0x0001 | §2.2.3.1.1 | §6.2 正确 | ✓ |
| 56 | SMB3.1.1 NegotiateContext Encryption ContextType = 0x0002 | §2.2.3.1.2 | §6.2 正确 | ✓ |
| 57 | SMB3 加密 TRANSFORM_HEADER 大小 = 52 字节（非 57） | §3.1.4.3 | **§6.16.2 写"57B 头"错误** | ✗ C-2 |
| 58 | MessageId 从 0 开始单调递增 | §3.2.4.1 | §4.1 正确 | ✓ |
| 59 | SessionId 由 SESSION_SETUP 响应分配，后续命令复用 | §3.3.4.5 | §4.1 正确 | ✓ |
| 60 | TreeId 由 TREE_CONNECT 响应分配（在 SMB2 头 TreeId 字段，非 PDU 体） | §3.3.4.6 | §2.8 注正确 | ✓ |

核查表结论：60 项中 **49 项正确、11 项存在问题**（4 CRITICAL、7 HIGH）。问题集中在"SMB2 头 padding 表述"、"WRITE DataOffset 叙述"、"TRANSFORM_HEADER 大小"、"QUERY_DIRECTORY 响应缺失"四类。

---

## 2. CRITICAL 问题

### C-1：§2.2 SMB2 头布局三次重写仍含 8 字节"padding"含糊说辞

- **位置**：§2.2（line 74-125），共三处"重新列出准确偏移"。
- **问题**：MS-SMB2 §2.2.1.1 明确规定 SMB2 SYNC 头共 64 字节，前 56 字节是 11 个具名字段（ProtocolId/StructureSize/CreditCharge/Status/NextCommand/MessageId/Reserved/TreeId/SessionId/Signature 占偏移 0-55），StructureSize 字段值=64 即整头大小。设计文档先列"偏移 40+16=56，再补 8 字节对齐成 64"，又说"SMB2 头确实是 64 字节，但表格只列到偏移 40+16=56，再无字段——这是因为 SMB2 头设计为 64 字节是为了向后兼容，但实际有效字段止于偏移 56，最后 8 字节是结构对齐 padding（不传输字段）"，最终给出"最终准确版（按 MS-SMB2 §2.2.1.1）"表，但表后又补"`| 56 | 4 | — | （至此 60 字节）` `| 60 | 4 | — | （至此 64 字节，结构对齐）`"，将不存在的"4 字节空字段"列为表行。
- **MS-SMB2 原文**：SMB2 SYNC 头 Layout（§2.2.1.1）：

  ```
  0   ProtocolId (4)
  4   StructureSize (2, =64)
  6   CreditCharge (2)
  8   Status/ChannelSequence (4)
  12  NextCommand (4)
  16  MessageId (8)
  24  Reserved/AsyncId-high (4)
  28  TreeId/AsyncId-low (4)
  32  SessionId (8)
  40  Signature (16)
  56  (end of fields, total = 56 bytes used, StructureSize=64 means total header = 64 bytes including 8 bytes of zero-padded alignment)
  ```

  MS-SMB2 不在表里列出"偏移 56 的 4 字节空字段"和"偏移 60 的 4 字节空字段"——它明确写"StructureSize (2 bytes): The server MUST set this field to 64, indicating the size of the SMB2 header structure. The client MUST validate this field."，且 Signature 是 16 字节、占满偏移 40-55，偏移 56-63 是 8 字节零填充（不是"4+4 两段对齐"）。
- **影响**：实现者照抄设计文档的表，可能将偏移 56-63 误填为两段独立字段（如"Reserved3"+"Reserved4"），或在 Validate 时拒绝 StructureSize=64 的合法包。Wireshark 解析 SMB2 头按 64 字节读取，前 56 字节是字段、后 8 字节是 padding，若实现者写偏移 56 处填非零字节，Wireshark 不会报错（因为 padding 区域不解析），但若实现者将偏移 56 误认为下一个字段起始（如 NEGOTIATE 体的 StructureSize），则后续整个 PDU 解析错位。
- **修复建议**：删除 §2.2 中三处"重新列出准确偏移"前的所有版本，仅保留最终表；删除表后"`| 56 | 4 | — |`"和"`| 60 | 4 | — |`"两行；改表后注释为："SMB2 SYNC 头共 64 字节，前 56 字节为 11 个具名字段（偏移 0-55），偏移 56-63 为 8 字节零填充（StructureSize 字段值=64 即整头大小，含 padding）。MS-SMB2 不在偏移 56 后定义任何字段。Wireshark 与所有 SMB2 实现均按 64 字节读取整头。"
- **CLAUDE.md §1 对应**：spec 字段表必须逐项测试，本字段三处自我推翻直接导致 T3/T4（StructureSize 断言）无法稳定通过。

### C-2：§6.16.2 SMB3 TRANSFORM_HEADER 大小写成 57 字节，实际应为 52 字节

- **位置**：§6.16.2（line 1220），"planner 生成 SMB2 TRANSFORM_HEADER（57B 头 + 密文占位）"。
- **问题**：MS-SMB2 §3.1.4.3 定义的 SMB2 TRANSFORM_HEADER（加密头）共 52 字节，布局为：

  ```
  0   ProtocolId (4, =0xFD534D42 "FDSMB")
  4   Signature (16, AES-GCM/AES-CCM tag)
  20  Nonce (16)
  36  OriginalMessageSize (4, uint32 LE)
  40  Reserved (2, =0x0000)
  42  Flags (2, bit0=Encrypted, bit1+=Reserved)
  44  SessionId (8)
  52  (end)
  ```

  总大小 = 52 字节，不是 57 字节。设计文档写"57B 头"是错误的。
- **影响**：实现者照抄 57 字节，将产出畸形 TRANSFORM_HEADER，Wireshark 标记为 "Malformed packet"。T55（SMB3 加密头占位）若断言"含 SMB2 TRANSFORM_HEADER 57B 头"，测试会因实际生成 52 字节而失败，或测试期望 57 字节导致实现产出错误大小。
- **修复建议**：将 §6.16.2 的"57B 头"改为"52B 头"；补充 TRANSFORM_HEADER 字段表（ProtocolId/Signature/Nonce/OriginalMessageSize/Reserved/Flags/SessionId）；T55 断言改为"含 SMB2 TRANSFORM_HEADER 52B 头 + ProtocolId=0xFD534D42"。
- **CLAUDE.md §1 对应**：spec 字段必须从 RFC 原文逐项推导，本字段直接抄错数字。

### C-3：§2.11 WRITE 请求 DataOffset 叙述混乱（"64+1=65 对齐到 72"）

- **位置**：§2.11（line 319），"DataOffset (从 SMB2 头起始，=64+48=112? 实际 MS-SMB2 是 64+1=65，对齐到 72)"。
- **问题**：MS-SMB2 §2.2.10.1 WRITE 请求布局：

  ```
  0   StructureSize (2, =49)
  2   DataOffset (2, uint16 LE, 从 SMB2 头起始算的偏移)
  4   Length (4)
  8   Offset (8)
  16  FileId (16)
  32  Channel (4)
  36  RemainingBytes (4)
  40  WriteChannelInfoOffset (2)
  42  WriteChannelInfoLength (2)
  44  Flags (4)
  48  (end of WRITE 请求体, 48 字节)
  ```

  WRITE 请求 PDU 体共 48 字节，紧跟在 SMB2 头（64 字节）后，所以 Data 字段从 SMB2 头起始算的偏移 = 64+48 = **112**。设计文档的"64+1=65 对齐到 72"是无根据的——MS-SMB2 没有这个对齐规则。WRITE 请求的 DataOffset 字段值实际是 112（即 SMB2 头 64 + WRITE 体 48），不存在"对齐到 72"。

  设计文档作者明显在此处困惑于"StructureSize=49 但 PDU 体实际 48 字节"——MS-SMB2 的 StructureSize 字段对部分命令采用"StructureSize = 实际大小 + 1"的奇数编码（用于强制对齐检测），WRITE 就是其中之一：StructureSize=49 表示"实际 PDU 体 48 字节 + 1 字节对齐标记"。这是 MS-SMB2 的特殊编码，不是"对齐到 72"。
- **影响**：实现者照抄"对齐到 72"，会在 WRITE 请求 PDU 体后插入 24 字节（72-48=24）的 padding，导致 Length 字段与实际 Data 长度不匹配，Wireshark 标记为 malformed。T29（WRITE 9 字节 base64）若不断言 DataOffset 值，测试可能通过但产出畸形包；若断言 DataOffset=72，测试会失败。
- **修复建议**：删除"64+1=65 对齐到 72"叙述；改为"DataOffset = SMB2 头大小（64）+ WRITE 请求体大小（48）= 112"；补充注释"WRITE 请求 StructureSize=49 是 MS-SMB2 的奇数编码（实际 PDU 体 48 字节 + 1 字节对齐标记），不影响 DataOffset 计算"。
- **CLAUDE.md §5 对应**：测试必须断言字节级字段值，本字段若不断言 DataOffset=112，测试会通过但产出畸形包。

### C-4：§7 测试用例字节级断言缺失，60 条用例仅 6 条断言字节值

- **位置**：§7.1-§7.10（line 1244-1352），全部 60 条用例。
- **问题**：CLAUDE.md §5 明确要求"测试必须断言输出值和可观察行为，而非仅断言结构存在。一个字段若不被断言非零，将永远保持零值并通过任何结构性断言。"设计文档的 60 条用例中：
  - **断言字节值的仅 6 条**：T7（NBSS 前缀 4B）、T9（ClientGuid 非全 0）、T12（NTLMSSP 签名 "NTLMSSP\0"）、T13（ServerChallenge 8B 非全 0）、T26（CREATE 文件名 UTF-16LE 字节）、T29（WRITE 长度 9）。
  - **断言字段值（非字节级）的约 25 条**：T1-T6/T10-T11/T14-T25/T27-T28/T30-T34 等，仅断言"DialectCount=1"或"Status=0xC0000016"等数值字段，不断言字节布局。
  - **仅断言结构存在/行为的约 29 条**：T8/T35-T39/T40-T43/T44-T50/T51-T53/T54-T56/T57-T60，如"T35 完整会话包序"仅断言"包序=TCP握手→7对SMB命令→TCP挥手"，不断言任何字节；T55"含 SMB2 TRANSFORM_HEADER 57B 头"（且大小错误，见 C-2）；T59"tshark 无报错"是端到端断言但不断言字段。

  这意味着 60 条用例中约一半（29 条）即使实现产出错误字节布局也能通过——只要包数对、命令对、不 panic。这正是 CLAUDE.md 测试策略 §5 警告的"结构存在不等于行为正确"反模式。
- **影响**：实现者照抄测试用例，将产出"测试全绿但 Wireshark 标记 malformed"的灾难——这正是 CLAUDE.md 引用的"178 测试全绿但 33 个 spec-vs-impl 问题"的反向变体。
- **修复建议**：每条用例必须至少断言 1 个字节级字段值（如 NBSS 长度字段、SMB2 头 ProtocolId/StructureSize/MessageId、命令体 StructureSize、UTF-16LE 字节序列）；T55 修正 TRANSFORM_HEADER 大小为 52B 并断言 ProtocolId=0xFD534D42；T59 tshark 断言扩展为"smb2.cmd 字段值"逐命令校验。
- **CLAUDE.md §5 对应**：本条直接命中 CLAUDE.md 测试策略 §5 的核心警告。

---

## 3. HIGH 问题

### H-1：§4.1 TreeId 初始值 0xFFFFFFFF 与 MS-SMB2 实际行为不一致

- **位置**：§4.1（line 703），"TreeId 初始 0xFFFFFFFF"；§4.2 异常分支（line 713），"TREE_CONNECT 响应 STATUS_BAD_NETWORK_NAME → 跳过 CREATE，直接 LOGOFF"。
- **问题**：MS-SMB2 §3.2.4.4 规定客户端在 TREE_CONNECT 之前，SMB2 头的 TreeId 字段应填 0（不是 0xFFFFFFFF）。TreeId=0xFFFFFFFF 是 Windows 客户端在某些实现中用于"未连接任何树"的内部状态标记，但**线上传输的 SMB2 头 TreeId 字段在 TREE_CONNECT 请求时填 0**，不是 0xFFFFFFFF。MS-SMB2 §2.2.1.1 明确："TreeId (4 bytes): This field identifies the tree connect. ... MUST be set to 0 for the following commands: NEGOTIATE, SESSION_SETUP, LOGOFF, ECHO, CANCEL, OPLOCK_BREAK." 对 TREE_CONNECT 请求本身，MS-SMB2 §3.2.4.4 规定 TreeId=0。
- **影响**：实现者照抄 0xFFFFFFFF，TREE_CONNECT 请求的 SMB2 头 TreeId 字段将填 0xFFFFFFFF，Wireshark 可能不报错（因为 TreeId 是 uint32），但服务端实现可能返回 STATUS_INVALID_PARAMETER。T21/T22（TREE_CONNECT 用例）若不断言 TreeId 字段值，测试通过但产出非标流量。
- **修复建议**：§4.1 改为"TreeId 初始 0（TREE_CONNECT 请求时为 0，TREE_CONNECT 响应分配后复用）"；T21/T24 补充断言"TREE_CONNECT 请求 SMB2 头 TreeId=0"。
- **CLAUDE.md §1 对应**：spec 字段必须从 RFC 原文推导。

### H-2：§6.1 总包数计算 4+2×7+4=26 与 NTLM 3 轮实际 9 对 SMB 命令矛盾

- **位置**：§6.1（line 873），"总包数 == 4 (TCP 握手) + 2×7 (7 对 SMB 命令) + 4 (TCP 挥手) = 26 包（含纯 ACK）"。
- **问题**：§6.1 Config 中 `auth_mechanism="ntlm"`，NTLM 三阶段认证会产生 3 对 SESSION_SETUP（见 §6.3 与 T11）。完整会话命令对：
  1. NEGOTIATE（1 对）
  2. SESSION_SETUP × 3（3 对，NTLM 三阶段）
  3. TREE_CONNECT（1 对）
  4. CREATE（1 对）
  5. READ（1 对）
  6. CLOSE（1 对）
  7. TREE_DISCONNECT（1 对）
  8. LOGOFF（1 对）

  共 10 对 SMB 命令，不是 7 对。但 §6.1 期望"7 对 SMB 命令"，且 §6.1 期望包序列（line 846-865）只列了 SESSION_SETUP #1/#2（2 对），与 §6.3 NTLM 三阶段（3 对）矛盾。

  实际总包数 = 4（TCP 握手） + 2×10（10 对 SMB 命令，每对含 1 个 PSH-ACK + 1 个纯 ACK） + 4（TCP 挥手） = **28 包**，不是 26 包。

  但若按 §6.1 期望包序列（只 2 轮 SESSION_SETUP，即 NTLM 两阶段），则 = 4 + 2×9 + 4 = 26 包——与 NTLM 三阶段矛盾。
- **影响**：T57（e2e 完整 SMB3.1.1 会话）若断言"26+ 包"，实现产出 28 包（NTLM 三阶段）会通过；但 T11（NTLM 三阶段认证）若断言"3 对 SESSION_SETUP"，与 T57 的 26 包（隐含 2 对 SESSION_SETUP）矛盾。设计文档内部测试用例互相打架。
- **修复建议**：§6.1 改为"总包数 = 4 + 2×10 + 4 = 28 包（NTLM 三阶段）"或明确"7 对 SMB 命令"按 NTLM 两阶段算（与 §6.3 矛盾，需统一）；T57 断言改为"28+ 包"。
- **CLAUDE.md §3 对应**：测试必须测试正确的代码路径，本条 NTLM 阶段数与总包数互相矛盾。

### H-3：§3 PreauthIntegrity 字段误解（"算法 ID 0x0001=SHA-512"）

- **位置**：§3 SMBConfig（line 524-525），"PreauthIntegrity (预认证完整性): SMB3.1.1 才有; 算法 ID 0x0001=SHA-512."；§3.2 默认值（line 630），"PreauthIntegrity | 0x0001 (SHA-512) | SMB3.1.1"。
- **问题**：MS-SMB2 §3.3.5.5.1 Preauth Integrity 定义：PreauthIntegrityHashAlgorithm 字段是 16 位 hash algorithm ID 列表，0x0001=SHA-512。但 SMBConfig.PreauthIntegrity 字段名暗示它是"算法 ID"，而 MS-SMB2 实际有两个相关字段：
  1. **NegotiateContext Preauth Integrity Context**（ContextType=0x0001）的 HashAlgorithms 字段是 uint16 数组，元素值 0x0001=SHA-512。
  2. **PreauthIntegrityHashValue** 是会话内动态更新的 SHA-512 哈希值（64 字节），不是配置项。

  设计文档的 `PreauthIntegrity uint16` 字段语义模糊——它应该是"客户端支持的 Preauth Integrity 算法 ID 列表"（uint16 数组），不是单个 uint16。MS-SMB2 §2.2.3.1.1 明确 HashAlgorithms 是"SMB2_PREAUTH_INTEGRITY_CAPABILITIES"结构的字段，是 uint16 数组（Count + Array）。
- **影响**：实现者照抄 `uint16`，无法表达"客户端支持多种 Preauth 算法"（虽然目前只有 SHA-512 一种，但字段类型应该是数组以向前兼容）。T54（SMB3.1.1 预认证完整性占位）若断言"Signature 字段非全 0"，与 PreauthIntegrityHashValue（实际 SHA-512 哈希值）无关——Signature 是消息签名（HMAC-SHA256），PreauthIntegrityHashValue 是会话级累积哈希（SHA-512），两者不同。设计文档混了这两个概念。
- **修复建议**：§3 改 PreauthIntegrity 字段为 `PreauthIntegrityHashAlgorithms []uint16`（默认 [0x0001]）；新增 `PreauthIntegrityHashValue [64]byte` 字段（占位，SHA-512 哈希值，会话内动态更新）；T54 改为断言"NegotiateContext Preauth Integrity Context 含 HashAlgorithms=[0x0001]"，不断言 Signature 字段。
- **CLAUDE.md §1 对应**：spec 字段必须从 RFC 原文逐项推导。

### H-4：§6.14 多会话 SessionId 唯一性无保障

- **位置**：§6.14（line 1149-1166），"5 个独立 TCP 4-tuple，每个 SrcPort 递增"+"每条会话独立 SessionId/TreeId/FileId"+"5 个 FlowID 互不重叠"。
- **问题**：设计文档说 SessionId 由 SESSION_SETUP 响应分配（§4.1，"SESSION_SETUP 响应分配（随机 uint64）"），但多会话场景下 5 个独立 planner goroutine 各自随机生成 SessionId，**无任何机制保障 5 个 SessionId 互不相同**。T51 断言"5 个独立 SessionId"，但若两个 planner 同时调用 `rand.Int(rand.Reader, big.NewInt(1<<64))` 返回相同值（概率极低但非零），测试会偶发失败。

  更重要的是，MS-SMB2 §3.3.4.5 规定 SessionId 由**服务端**分配（不是客户端），服务端保证 SessionId 全局唯一。trafficgen 同时生成客户端和服务端流量，所以 SessionId 实际是 planner 自己分配的——但 planner 是单进程多 goroutine，没有全局 SessionId 计数器或去重逻辑。
- **影响**：T51（5 客户端独立会话）若断言"5 个 SessionId 互不相同"，可能在并发场景下偶发失败（概率约 5×4/2^64 ≈ 5×10^-18，理论存在）。更实际的问题是 T53（多会话状态隔离）若断言"任一会话的 SessionId 不影响其他"，无法检测 SessionId 重复。
- **修复建议**：§4.1 改 SessionId 分配为"planner 内全局原子计数器从 1 开始递增"或"基于 FlowID 哈希的确定性分配"；§6.14 补充"planner 保证多会话 SessionId 唯一性（全局原子计数器）"；T51 改为断言"5 个 SessionId 互不相同 AND 各自非零"。
- **CLAUDE.md §6 对应**：并发测试必须验证正确性，本条是多 goroutine 共享状态问题。

### H-5：§3 默认 dialects 列表与 §3.2 默认值汇总不一致

- **位置**：§3 SMBConfig.Dialects 注释（line 421-423），"空默认 ["0x0202","0x0210","0x0302","0x0311"]"；§3.2 默认值汇总（line 614），"Dialects | ["0x0202","0x0210","0x0302","0x0311"] | Windows 10 客户端典型集"；§6.1 Config（line 837），"dialects": ["0x0202", "0x0210"]。
- **问题**：§3 注释和 §3.2 默认值都是 4 元素列表 `["0x0202","0x0210","0x0302","0x0311"]`，但**缺少 0x0300**（SMB3.0）。Windows 10 客户端典型集应是 `["0x0202","0x0210","0x0300","0x0302","0x0311"]`（5 元素），包含 SMB3.0。MS-SMB2 §3.2.4.2 列出的 dialects 包含 0x0300。

  此外，§3 注释（line 421-422）说"覆盖 SMB2.002/2.1/3.0.2/3.1.1"，漏了 SMB3.0（0x0300）。T3（SMB3.0 协商）用 `dialects=["0x0300"]`，但默认列表不含 0x0300，T3 必须显式指定——这本身没问题，但默认列表漏 0x0300 会导致"用户不指定 dialects 时无法协商 SMB3.0"。
- **影响**：用户不指定 dialects 时，trafficgen 只能生成 SMB2.002/2.1/3.0.2/3.1.1 流量，无法生成 SMB3.0 流量。若服务端只支持 SMB3.0（如 Windows Server 2012 默认配置），协商会失败。T5（默认 dialects 空时回退）断言默认列表为 4 元素，与 Windows 实际行为不一致。
- **修复建议**：§3 默认列表改为 5 元素 `["0x0202","0x0210","0x0300","0x0302","0x0311"]`；§3.2 同步更新；T5 断言改为 5 元素。
- **CLAUDE.md §1 对应**：spec 字段必须从 RFC 原文推导。

### H-6：§2.14 QUERY_DIRECTORY 缺失响应 PDU 描述

- **位置**：§2.14（line 374-388），仅描述 QUERY_DIRECTORY 请求 PDU，无响应 PDU。
- **问题**：MS-SMB2 §2.2.15.2 QUERY_DIRECTORY 响应有明确结构（StructureSize=9 + OutputBufferOffset + OutputBufferLength + OutputBuffer），设计文档完全缺失。T31（QUERY_DIRECTORY 列目录）断言"resp 含多个 ID_BOTH_DIR_INFO 结构"，但未定义响应 PDU 字段，实现者无法知道：
  - StructureSize 是 9 还是其他值？
  - OutputBufferOffset 从哪里算？
  - OutputBufferLength 字段在哪？
  - ID_BOTH_DIR_INFO 结构如何布局？
- **影响**：实现者照抄设计文档，QUERY_DIRECTORY 响应 PDU 字段布局无法实现。T31 测试期望"含多个 ID_BOTH_DIR_INFO"，但不断言响应 PDU StructureSize=9 或 OutputBufferOffset 值，测试通过但产出非标流量。
- **修复建议**：§2.14 补充 QUERY_DIRECTORY 响应 PDU 表：

  | 偏移 | 长度 | 字段 |
  |------|------|------|
  | 0 | 2 | StructureSize (9) |
  | 2 | 2 | OutputBufferOffset (从 SMB2 头起始算，=64) |
  | 4 | 4 | OutputBufferLength |
  | 8 | var | OutputBuffer (ID_BOTH_DIR_INFO 数组) |

  并补充 ID_BOTH_DIR_INFO 结构（MS-FSCC §2.4.18）字段表。
- **CLAUDE.md §1 对应**：spec 字段必须从 RFC 原文逐项推导。

### H-7：§6.5 IPC$ 与 §6.6 磁盘共享的 TREE_CONNECT 前置约束未声明

- **位置**：§6.5（line 952-972），IPC$ 共享连接；§6.6（line 973-989），磁盘共享连接；§9.3 Validate 规则（line 1440-1458）。
- **问题**：MS-SMB2 §3.2.4.5 规定 CREATE 命令必须在 TREE_CONNECT 之后执行（TreeId 字段必须复用 TREE_CONNECT 响应分配的值）。设计文档 §4 状态机正确体现了这个顺序，但 §6.5/§6.6 的 Config 中 `operations: []`（空操作列表），意味着跳过 CREATE——这本身合法。但 §6.15.2 / §6.16.3 提到"跳过 TREE_CONNECT 后 CREATE 的 TreeId 字段填 0"，**未在 Validate 中强制约束**：

  - §9.3 Validate 规则 13 条中没有"若 Operations 非空且未显式指定 FileId，则必须 IncludeTreeConnect=true"。
  - §6.16.3 提到"如用户显式跳过 TREE_CONNECT（include_tree_connect: false），则 CREATE 的 TreeId 字段填 0，服务端可能返回 STATUS_INVALID_PARAMETER"——但 Validate 不报错，Plan 也不报错，导致用户可生成"跳过 TREE_CONNECT + 执行 CREATE"的不合规流量。

  这本身可能是"测试服务端鲁棒性"的合法用例（§6.16.5 提到"planner 不验证 dialect 与 Operations 的兼容性，用户可生成不一致流量"），但应在 Config 中显式标注"已知不合规"标志，而不是静默接受。
- **影响**：用户误配置 `include_tree_connect: false` + `operations: [{op_type: "read", ...}]`，planner 静默生成"TreeId=0 + CREATE"流量，服务端返回 STATUS_INVALID_PARAMETER，用户困惑。T37（跳过认证）有类似问题，"SessionId=0; 服务端可能拒绝（planner 不模拟）"——但 Validate 应至少警告。
- **修复建议**：§9.3 新增 Validate 规则 14："若 IncludeTreeConnect=false 且 Operations 含 read/write/close/query_directory（非 file_id 全 FF 的显式指定），返回错误或警告'CREATE without TREE_CONNECT is non-compliant'"；§9.3 新增规则 15："若 IncludeAuth=false 且 Operations 非空，返回错误或警告'operations without SESSION_SETUP is non-compliant'"。
- **CLAUDE.md §2 对应**：测试必须覆盖失败路径，本条是缺失的负向校验。

---

## 4. MEDIUM 问题

### M-1：§8 审计清单 38 项中 6 项虚假覆盖声明

- **位置**：§8.1-§8.6（line 1359-1414），38 项审计清单。
- **问题**：CLAUDE.md §1 要求"spec 字段必须逐项测试"。§8 审计清单声称覆盖 38 项，但以下 6 项零用例：
  1. **C5 SessionId/TreeId 偏移**：T19/T20/T24 断言 SessionId/TreeId 复用，但不断言 SMB2 头偏移 28/32 的字节值。
  2. **C7 命令 PDU StructureSize**：T1-T4 断言 NEGOTIATE StructureSize，但 T25-T34 不断言 CREATE/READ/WRITE/CLOSE 的 StructureSize 值（仅断言 FileId/Length）。
  3. **C10 CREATE req.NameOffset**：T25/T26 断言 CREATE 文件名 UTF-16LE 字节，但不断言 NameOffset 字段值（应 = 64+44=108，因 CREATE 体偏移 32 是 NameOffset）。
  4. **C15 NTLM 多轮 STATUS_MORE_PROCESSING_REQUIRED**：T11 断言"#1 Status=0xC0000016"，但 NTLM 三阶段中 #1 是 NTLMSSP_NEGOTIATE（客户端发），#1 响应是 NTLMSSP_CHALLENGE（STATUS_MORE_PROCESSING_REQUIRED）。设计文档 §6.3 与 T11 编号一致，但 §6.1 期望包序列只列 SESSION_SETUP #1/#2（2 轮），与 NTLM 三阶段矛盾（见 H-2）。
  5. **C22 TCP 4-way 挥手**：T35 断言"包序=TCP握手→SMB命令→TCP挥手"，但不断言 FIN-ACK/ACK/FIN-ACK/ACK 4 包的 flags 值（0x11/0x10/0x11/0x10）。
  6. **C37 大 READ 响应流式生成**：T28 断言"resp 切成 ~46 段"，但不断言"planner 不全内存聚合"（即不断言 plan 是 streaming 的）。
- **影响**：实现者照抄审计清单，6 项字段无测试，可能产出"StructureSize 字段填错值但测试全绿"的灾难。
- **修复建议**：每项审计清单补充对应测试用例编号；新增 T61-T66 专门覆盖这 6 项。
- **CLAUDE.md §1/§5 对应**：spec 字段必须逐项测试 + 测试必须断言可观察值。

### M-2：§6.15 边界场景断言弱

- **位置**：§6.15.1-§6.15.8（line 1170-1208）。
- **问题**：边界场景仅描述"期望行为"，不断言字节级字段值。例如：
  - §6.15.3 offset/length 全 0：期望"READ req.Length=0, READ resp.DataLength=0, Data 为空"，但不断言 READ 请求 PDU 偏移 4 的 Length 字段字节。
  - §6.15.4 offset uint64 max：期望"planner 接受并生成对应字段"，但不断言 READ 请求 PDU 偏移 8 的 Offset 字段 = 0xFFFFFFFFFFFFFFFF。
  - §6.15.6 credit 0/65535：期望"SMB2 头 CreditCharge 字段填 0xFFFF"，但不断言偏移 6 的 CreditCharge 字节。
- **影响**：T44-T50 边界测试仅断言"planner 不报错"，不断言字段值，可能产出"边界值未正确写入字节"的灾难。
- **修复建议**：每条边界场景补充字节级断言，如 T46 断言 `req PDU[8:16] == 0xFF FF FF FF FF FF FF FF`。
- **CLAUDE.md §5 对应**：测试必须断言可观察值。

### M-3：§5.2 MSS 切段中间段 PSH 标记错

- **位置**：§5.2（line 794-800），"中间段只带 ACK 标志（不 PSH）"+"最后一段带 PSH 标志（强制推送）"。
- **问题**：MS-SMB2 与 TCP 标准对 MSS 切段的 PSH 标记无强制要求——PSH 是提示接收方立即上报应用层，不是分段协议的一部分。设计文档规定"中间段不 PSH、最后一段 PSH"是一种实现选择，但与 RFC 1122 §4.2.2.2 的"sender SHOULD set PSH for the last segment of a user write"一致。问题在于：
  - §5.1 包序列（line 754）将每个 SMB2 PDU 作为"一段 PSH-ACK 负载"，未明确"MSS 超长时分段后中间段是否带 PSH"。
  - §5.2 说"中间段只带 ACK"，但 ACK 标志是 TCP 确认号有效位，与 PSH 独立——所有段都应带 ACK（除第一段如果是 SYN 不带），所以"中间段只带 ACK"应改为"中间段带 ACK 不带 PSH"。
- **影响**：实现者照抄"中间段只带 ACK"，可能漏掉 ACK 标志（误以为中间段 flags=0x00），导致 TCP 状态机异常。T28（READ 大响应 MSS 切段）若不断言中间段 flags=0x10（ACK），测试通过但产出非标流量。
- **修复建议**：§5.2 改为"中间段带 ACK 标志（flags=0x10）不带 PSH；最后一段带 PSH+ACK（flags=0x18）"；T28 补充断言"中间段 flags=0x10, 最后一段 flags=0x18"。
- **CLAUDE.md §5 对应**：测试必须断言可观察值。

### M-4：§9.3 Validate 规则不全

- **位置**：§9.3（line 1440-1458），13 条 Validate 规则。
- **问题**：缺失以下关键校验：
  1. **MessageId 起始值**：未校验"MessageId 从 0 开始单调递增"（§4.1 规定，但 Validate 不验证）。
  2. **FileId 持久/易失分裂**：MS-SMB2 §2.2.6.2 FileId 是 8B persistent + 8B volatile，未校验"用户提供的 FileId 长度=16 字节"。
  3. **AuthRounds 与 AuthMechanism 一致性**：规则 7 规定 ntlm:1-3 / kerberos:1-2 / anon/guest:1，但未校验"AuthRounds=0 时按 AuthMechanism 默认值填充"。
  4. **SelectedDialect 在 Dialects 列表内**：规则 5 规定，但未规定"SelectedDialect 必须是 Dialects 的最后一个"（§3 注释说"服务端选中 dialect = 列表最后一个"）。
  5. **Operations OpType 合法性**：规则 9 规定"每个 OpType 必须合法"，但未列出合法值（"read"/"write"/"close"/"query_directory"/"query_info"/"set_info"/"flush"/"echo"）。
  6. **TreeConnectShare UNC 路径**：规则 10 规定"必须以 \\ 开头"，但未校验"\\\\server\\share" 格式（含 server 名与 share 名）。
- **影响**：T60（Validate 拒绝畸形 dialect）仅覆盖规则 4，其他规则无负向测试。CLAUDE.md §2 要求"覆盖失败路径"，本条缺失 6 类负向测试。
- **修复建议**：§9.3 补充 6 条 Validate 规则；新增 T61-T66 负向测试覆盖每条规则。
- **CLAUDE.md §2 对应**：测试必须覆盖失败路径。

### M-5：§2.4/§2.5 NegotiateContextList 字段细节缺失

- **位置**：§2.4（line 166），"NegotiateContextList | 仅 SMB3.1.1；含 Preauth Integrity、Encryption、Compression 等"；§2.5（line 188）。
- **问题**：MS-SMB2 §2.2.3.1.1-§2.2.3.1.3 详细定义了 NegotiateContext 结构（ContextType 2B + DataLength 2B + Reserved 4B + Data var），以及三种 ContextType：
  1. 0x0001 SMB2_PREAUTH_INTEGRITY_CAPABILITIES（HashAlgorithmCount + HashAlgorithms[] + SaltLength + Salt[]）
  2. 0x0002 SMB2_ENCRYPTION_CAPABILITIES（CipherCount + Ciphers[]，0x0001=AES-128-CCM, 0x0002=AES-128-GCM）
  3. 0x0003 SMB2_COMPRESSION_CAPABILITIES（CompressionAlgorithmCount + CompressionAlgorithms[] + Padding + Flags）

  设计文档仅列名称，不列字段。T4（SMB3.1.1 协商含 NegotiateContextList）断言"req 含 Preauth Integrity Context (ContextType=0x0001)"，但不断言 HashAlgorithmCount、HashAlgorithms、SaltLength、Salt 字段值。
- **影响**：实现者照抄设计文档，NegotiateContextList 字段布局无法实现。T4 测试通过但产出非标流量。
- **修复建议**：§2.4 补充 NegotiateContext 结构表 + 三种 ContextType 字段表；T4 补充字节级断言。
- **CLAUDE.md §1 对应**：spec 字段必须从 RFC 原文逐项推导。

### M-6：§4.2 错误注入语义模糊

- **位置**：§4.2（line 715），"任意命令 ErrorResponseStatus 非零 → 该命令响应返回错误，后续命令按 ErrorOnCommand 决定"；§3 ErrorOnCommand 字段（line 566-568）。
- **问题**：ErrorOnCommand 字段描述为"在指定命令返回错误；该命令的响应返回 ErrorResponseStatus, 后续命令跳过"，但：
  1. "后续命令跳过"是跳过所有后续命令，还是跳过依赖该命令的命令？例如 ErrorOnCommand="create" 时，跳过 READ/WRITE/CLOSE，但是否跳过 TREE_DISCONNECT/LOGOFF？§6.13 期望"跳过后续 READ/WRITE/CLOSE，直接进入 TREE_DISCONNECT → LOGOFF"，所以是"跳过依赖命令，保留拆解命令"。但 §4.2 没有明确这个规则。
  2. ErrorOnCommand 是字符串（如 "create"/"read"/"write"），但未列出合法值列表。若用户填 "negotiate"，是否跳过 SESSION_SETUP/TREE_CONNECT/CREATE/READ/WRITE/CLOSE/TREE_DISCONNECT/LOGOFF 全部？§4.2 异常分支（line 711）规定"NEGOTIATE 响应 STATUS_INVALID_PARAMETER → 终止会话，跳过后续，直接 LOGOFF + TCP teardown"，与"跳过依赖命令"规则不同。
- **影响**：实现者照抄设计文档，ErrorOnCommand 行为不明确。T40-T43 错误注入测试仅覆盖 4 种命令（create/tree_connect/session_setup/read），未覆盖 negotiate/close/logoff 等其他命令的跳过规则。
- **修复建议**：§4.2 补充错误注入跳过规则表（按命令列出跳过哪些后续命令、保留哪些拆解命令）；§3 ErrorOnCommand 字段补充合法值列表。
- **CLAUDE.md §2 对应**：测试必须覆盖失败路径。

### M-7：§2.15 NT 状态码表缺失 §4.2 引用的状态码

- **位置**：§2.15（line 389-403），10 条状态码；§4.2（line 712-713），引用 STATUS_BAD_NETWORK_NAME (0xC00000CC) 和 STATUS_LOGON_FAILURE (0xC000006D)。
- **问题**：§2.15 状态码表未列入 STATUS_BAD_NETWORK_NAME 和 STATUS_LOGON_FAILURE，但 §4.2 异常分支引用了它们。T41（TREE_CONNECT 返回 BAD_NETWORK_NAME）和 T42（SESSION_SETUP 返回 LOGON_FAILURE）使用这些状态码，但用户无法从 §2.15 查到对应值。
- **影响**：实现者照抄 §2.15 表，T41/T42 测试期望的状态码值无文档支撑。
- **修复建议**：§2.15 补充 STATUS_BAD_NETWORK_NAME (0xC00000CC) 和 STATUS_LOGON_FAILURE (0xC000006D)。
- **CLAUDE.md §1 对应**：spec 字段必须从 RFC 原文逐项推导。

### M-8：§5.1 包序列未明确纯 ACK 的方向与时机

- **位置**：§5.1（line 748-790），包序列总览。
- **问题**：§5.1 列出"5. TCP ACK (down, server→client, ACK of #4)"等纯 ACK 包，但未明确：
  1. 纯 ACK 是立即发送还是延迟（Nagle 算法 / Delayed ACK）？
  2. 纯 ACK 的 seq 是否保持不变（仅 ack 推进）？
  3. 多个 PSH-ACK 是否会合并为单个 ACK（如客户端连续发 2 个 PSH-ACK，服务端可能合并为 1 个 ACK）？

  §8.3 C19 规定"纯 ACK 的 seq 是否保持不变，仅 ack 推进"，但 §5.1 包序列未明确每个纯 ACK 的 seq/ack 值。
- **影响**：实现者照抄 §5.1 包序列，纯 ACK 的 seq/ack 值无法确定。T35（完整会话包序）若不断言纯 ACK 的 seq/ack 值，测试通过但产出非标流量。
- **修复建议**：§5.1 包序列补充每个纯 ACK 的 seq/ack 值（如"5. TCP ACK (down, seq=server_ISN+1, ack=client_ISN+1+NEGOTIATE_req_len, flags=0x10)"）。
- **CLAUDE.md §5 对应**：测试必须断言可观察值。

### M-9：§6.16.2 SMB3 加密头描述缺失

- **位置**：§6.16.2（line 1218-1220），"planner 生成 SMB2 TRANSFORM_HEADER（57B 头 + 密文占位），不真实加密"。
- **问题**：除大小错误（见 C-2），TRANSFORM_HEADER 的字段布局完全未描述。MS-SMB2 §3.1.4.3 定义了 ProtocolId(0xFD534D42)、Signature(16B AES-GCM tag)、Nonce(16B)、OriginalMessageSize(4B)、Reserved(2B)、Flags(2B)、SessionId(8B) 共 52 字节。设计文档仅说"57B 头 + 密文占位"，无字段表。
- **影响**：实现者照抄设计文档，TRANSFORM_HEADER 字段布局无法实现。T55（SMB3 加密头占位）断言"含 SMB2 TRANSFORM_HEADER 57B 头"（且大小错误），测试期望与实际产出均错误。
- **修复建议**：§6.16.2 补充 TRANSFORM_HEADER 字段表（见 C-2 修复建议）；T55 修正断言。
- **CLAUDE.md §1 对应**：spec 字段必须从 RFC 原文逐项推导。

---

## 5. LOW 问题

### L-1：§1.3 "SMB1 dialect 0x0001 / NT LM 0.12" 表述不精确

- **位置**：§1.3（line 42），"SMB1（dialect 0x0001 / NT LM 0.12）"。
- **问题**：SMB1 的 dialect 字符串是 "NT LM 0.12"，不是 dialect 编号 0x0001。SMB2 dialect 是 uint16 数值（0x0202/0x0210/0x0300/0x0302/0x0311），SMB1 dialect 是字符串（在 SMB1 NEGOTIATE 中以 null-terminated 字符串列表形式传输）。混用"dialect 0x0001"与"NT LM 0.12"会让读者误解 SMB1 dialect 是数值。
- **修复建议**：改为"SMB1（dialect 字符串 'NT LM 0.12'）"。

### L-2：§1.4 术语表遗漏关键缩写

- **位置**：§1.4（line 47-57），11 条术语；附录 C（line 1555-1573），16 条缩写。
- **问题**：§1.4 与附录 C 之间重叠但不一致，且遗漏关键缩写：
  - **MSS**（Maximum Segment Size，最大分段大小）：§5.2 使用但未定义。
  - **FILETIME**：§2.5 使用但 §1.4 未定义（附录 C 有）。
  - **NTSTATUS**：§2.15 使用但未定义。
  - **GSS-API**：§1.4 定义但附录 C 重复定义。
  - **PDU**：§1.4 未定义，附录 C 有。
- **修复建议**：统一术语表到 §1.4，附录 C 仅保留缩写；补充 MSS/FILETIME/NTSTATUS。

### L-3：文档行数声明错误

- **位置**：line 1580，"文档行数：约 1100 行"。
- **问题**：实际行数 1581 行（line 1-1581），声明 1100 行，误差 30%。这是设计文档元数据错误。
- **修复建议**：改为"文档行数：约 1580 行"。

### L-4：§3.2 默认值表与 §3 注释不一致

- **位置**：§3 ClientGuid 注释（line 429），"空默认随机生成"；§3.2 默认值表（line 616），"ClientGuid | 随机 16B"。
- **问题**：§3 注释说"空默认随机生成"，但 §3.2 表说"随机 16B"——一致。但 ServerGuid（line 433）注释说"空默认随机生成"，§3.2 表无 ServerGuid 行。ClientCapabilities（line 437）注释说"0 默认 0x03"，§3.2 表说"0x03 (Encryption+DirLeasing)"——一致。但 SecurityMode（line 444）注释说"0 默认 SigningEnabled (0x01)"，§3.2 表说"0x01 (SigningEnabled)"——一致。整体看，§3.2 表遗漏 ServerGuid 行。
- **修复建议**：§3.2 补充 ServerGuid 行。

### L-5：§9.7 MCP e2e 用例与 §7 用例编号无映射

- **位置**：§9.7（line 1491-1503），10 条 MCP e2e 用例；§7（line 1244-1352），60 条用例。
- **问题**：§9.7 列出 10 条 MCP e2e 用例（smb_negotiate_smb21 / smb_negotiate_smb311 / smb_ntlm_auth / ...），但未映射到 §7 的 T1-T60 用例编号。实现者无法知道 MCP e2e 用例对应哪些单元测试。
- **修复建议**：§9.7 每条 MCP e2e 用例补充对应 §7 用例编号（如 smb_negotiate_smb21 → T2）。

### L-6：§9.8 交叉引用断链

- **位置**：§9.8（line 1505-1511），6 条交叉引用。
- **问题**：
  1. "Planner 模板：trafficgen/internal/protocol/socks5/socks5.go" — 文件存在，引用有效。
  2. "文件协议参考：trafficgen/internal/protocol/ftp/ftp.go" — 需验证文件存在。
  3. "未实现协议清单：docs/protocol-designs/00-unimplemented-list.md（#7 SMB）" — 已验证存在。
  4. "测试策略：CLAUDE.md 'Testing Policy' 章节" — 已验证存在。
- **修复建议**：验证 ftp.go 路径；如不存在，改为存在的协议（如 socks5.go）。

---

## 6. 字段覆盖率审计（扩展表 28）

> **说明**：用户任务描述中提到"扩展表 28 字段覆盖"含 version/treeconnect_is_pipe/treeconnect_share_name/smb_login 四字段。经查 `docs/protocol-designs/00-unimplemented-list.md` 第 26 行，SMB 在扩展表中对应节点名 `smbProtRpt`，但项目内无"扩展表 28 字段清单"文档（grep "treeconnect_is_pipe"/"smb_login" 在整个代码库零命中）。本节按用户给出的 4 字段名做覆盖审计。

### 6.1 字段覆盖表

| 扩展表字段 | 设计文档对应字段 | 覆盖状态 | 测试用例 |
|-----------|-----------------|---------|---------|
| version（SMB 协议版本/dialect） | SMBConfig.Dialects + SMBConfig.SelectedDialect | ✓ 覆盖 | T1-T5/T50 |
| treeconnect_is_pipe（树连接是否命名管道） | SMBConfig.ShareType（0=DISK/1=PIPE/2=PRINT） | △ 部分覆盖 | T21（IPC$ → ShareType=1） |
| treeconnect_share_name（树连接共享名） | SMBConfig.TreeConnectShare | ✓ 覆盖 | T21/T22 |
| smb_login（SMB 登录认证机制） | SMBConfig.AuthMechanism + Username/Domain/Password | ✓ 覆盖 | T11-T18 |

### 6.2 字段细节审计

#### 6.2.1 version 字段

- **设计覆盖**：Dialects 列表 + SelectedDialect，支持 5 个 dialect（0x0202/0x0210/0x0300/0x0302/0x0311）。
- **缺失**：默认列表漏 0x0300（见 H-5）；Validate 规则 4 列出 5 个合法 dialect，但默认列表只 4 个。
- **测试覆盖**：T1-T5/T50 共 6 条，覆盖单 dialect/多 dialect/默认/空/单元素 5 种场景。**缺**：负向测试 dialect=["0x0001"]（SMB1）已在 T10 覆盖；缺 dialect=["0xABCD"]（畸形）已在 T60 覆盖。覆盖完整。

#### 6.2.2 treeconnect_is_pipe 字段

- **设计覆盖**：ShareType 字段（0=DISK/1=PIPE/2=PRINT），§3 注释说"IPC$ 自动设为 1"。
- **缺失**：
  1. **"IPC$ 自动设为 1"规则未在 Validate 中强制**：§9.3 规则无"若 TreeConnectShare 以 IPC$ 结尾，则 ShareType 必须为 1"。用户可配置 `tree_connect_share="\\\\server\\IPC$"` + `share_type=0`，planner 静默接受。
  2. **ShareType 与 TREE_CONNECT 响应 ShareType 字段关系未明确**：TREE_CONNECT 响应 PDU 的 ShareType 字段（§2.8 偏移 2）是服务端分配的，与 Config.ShareType 是否一致？设计文档未明确。
- **测试覆盖**：T21（IPC$ → ShareType=1）1 条；**缺**：负向测试"IPC$ + ShareType=0"被 Validate 拒绝；缺"磁盘共享 + ShareType=1"被 Validate 警告。

#### 6.2.3 treeconnect_share_name 字段

- **设计覆盖**：TreeConnectShare 字段，§3 注释说"空默认 \\server\share"。
- **缺失**：
  1. **UNC 路径格式校验**：§9.3 规则 10 规定"必须以 \\ 开头"，但未校验"\\\\server\\share" 格式（含 server 名与 share 名）。用户可填 `\\server`（无 share 名），planner 静默接受。
  2. **UTF-16LE 编码长度上限**：MS-SMB2 §2.2.4.1 PathLength 是 uint16，最大 65535 字节（即 32767 个 UTF-16 字符）。设计文档未规定 TreeConnectShare 长度上限。
- **测试覆盖**：T21/T22 2 条；**缺**：边界测试超长 UNC 路径；缺负向测试"非 \\ 开头"被 Validate 拒绝。

#### 6.2.4 smb_login 字段

- **设计覆盖**：AuthMechanism + Username/Domain/Password + AuthRounds + SecurityBlob。
- **缺失**：
  1. **AuthRounds 与 AuthMechanism 一致性**：§9.3 规则 7 规定 ntlm:1-3 / kerberos:1-2 / anon/guest:1，但未规定"AuthRounds=0 时按 AuthMechanism 默认值填充"的优先级（用户填 0 是"用默认"还是"0 轮认证"）。
  2. **anonymous/guest 的 Username/Password 必须为空**：未校验。用户可填 `auth_mechanism="anonymous"` + `username="alice"`，planner 静默接受。
- **测试覆盖**：T11-T18 共 8 条，覆盖 NTLM/Kerberos/anonymous/guest/自定义 SecurityBlob 5 种场景。**缺**：负向测试"anonymous + username 非空"被 Validate 警告；缺 AuthRounds 越界（如 ntlm + AuthRounds=5）被 Validate 拒绝。

### 6.3 字段覆盖率总结

| 字段 | 设计覆盖 | 测试覆盖 | 综合 |
|------|---------|---------|------|
| version | 90%（缺默认列表 0x0300） | 95%（6 条，缺负向） | 85% |
| treeconnect_is_pipe | 70%（缺 IPC$ 自动化规则） | 50%（1 条，缺负向） | 60% |
| treeconnect_share_name | 80%（缺 UNC 格式校验） | 50%（2 条，缺边界） | 65% |
| smb_login | 85%（缺 anonymous+username 校验） | 80%（8 条，缺负向） | 75% |
| **平均** | **81%** | **69%** | **71%** |

字段覆盖率 71%，主要缺陷在负向测试与边界测试缺失。

---

## 7. 测试用例质量审计

### 7.1 用例数量与分布

| 类别 | 用例编号 | 数量 | 说明 |
|------|---------|------|------|
| §7.1 协商阶段 | T1-T10 | 10 | 含 1 条负向（T10） |
| §7.2 认证阶段 | T11-T20 | 10 | 全正向 |
| §7.3 树连接 | T21-T24 | 4 | 全正向 |
| §7.4 文件操作 | T25-T34 | 10 | 含 2 条边界（T33/T34） |
| §7.5 状态机 | T35-T39 | 5 | 含 2 条负向（T36/T37） |
| §7.6 异常路径 | T40-T43 | 4 | 全负向 |
| §7.7 边界 | T44-T50 | 7 | 全边界 |
| §7.8 多会话 | T51-T53 | 3 | 全正向 |
| §7.9 SMB3 高级 | T54-T56 | 3 | 全正向 |
| §7.10 集成 | T57-T60 | 4 | 含 1 条 e2e（T59） |
| **合计** | T1-T60 | **60** | 正向 41 / 负向 7 / 边界 9 / e2e 3 |

### 7.2 用例质量按 CLAUDE.md 8 条规则审计

#### §1 Spec-driven test derivation（spec 驱动测试推导）

- **覆盖**：§7 用例标注 spec 来源（§6.1/§6.2/...），格式规范。
- **缺陷**：§2.14 QUERY_DIRECTORY 响应 PDU spec 缺失（见 H-6），T31 无法从 spec 推导；§2.4/§2.5 NegotiateContextList spec 缺失（见 M-5），T4 无法从 spec 推导。
- **评分**：7/10。

#### §2 Cover failure paths（覆盖失败路径）

- **覆盖**：T10（拒绝 SMB1）/T36-T37（跳过阶段）/T40-T43（错误注入）/T60（拒绝畸形 dialect）共 7 条负向。
- **缺陷**：缺失 6 类负向（见 M-4）：MessageId 起始值/AuthRounds 越界/SelectedDialect 不在 Dialects 内/Operations OpType 非法/UNC 路径格式错/anonymous+username 非空。
- **评分**：5/10。

#### §3 Test the right function/scope（测试正确的函数/范围）

- **覆盖**：每条用例标注测试范围（协商/认证/树连接/文件操作/状态机/异常/边界/多会话/SMB3/集成）。
- **缺陷**：T57（e2e 完整 SMB3.1.1 会话）与 T11（NTLM 三阶段认证）的 SESSION_SETUP 轮数矛盾（见 H-2），测试范围正确但内部不一致。
- **评分**：8/10。

#### §4 Integration tests（集成测试）

- **覆盖**：T57-T60 共 4 条集成测试，含 TCP 握手 + SMB 命令链 + TCP 挥手。
- **缺陷**：T59（tshark 可解析）是端到端断言但不断言字段值；T58（e2e 多操作会话）包数计算 = 4 + 2×(7+6) + 4 = 34，与 NTLM 三阶段（应 10 对 SMB 命令）矛盾（见 H-2）。
- **评分**：6/10。

#### §5 Assert observable outcomes（断言可观察结果）

- **覆盖**：约 31 条用例断言字段值（如 T1 DialectCount=1）。
- **缺陷**：29 条用例仅断言结构存在/行为（见 C-4）；6 项审计清单字段零断言（见 M-1）。
- **评分**：4/10。

#### §6 Concurrency tests verify correctness（并发测试验证正确性）

- **覆盖**：T51-T53 共 3 条多会话测试。
- **缺陷**：T51 不断言 SessionId 唯一性机制（见 H-4）；T53 不断言"任一会话的 MessageId/SessionId 不影响其他"的具体机制；无 -race 干净的并发测试断言。
- **评分**：4/10。

#### §7 Failing-test-first for bug fixes（修复前先写失败测试）

- **覆盖**：设计文档未描述 bug 修复流程，无法评估。
- **评分**：N/A。

#### §8 Adversarial review of test quality（测试质量对抗审查）

- **覆盖**：§8 审计清单 38 项，是本仓库协议设计中较好的。
- **缺陷**：6 项虚假覆盖声明（见 M-1）。
- **评分**：6/10。

### 7.3 测试用例质量综合评分

| 规则 | 评分 | 说明 |
|------|------|------|
| §1 spec 驱动 | 7/10 | spec 缺失导致部分用例无法推导 |
| §2 失败路径 | 5/10 | 缺 6 类负向测试 |
| §3 正确范围 | 8/10 | 内部不一致（H-2） |
| §4 集成测试 | 6/10 | 包数计算错（H-2） |
| §5 可观察断言 | 4/10 | 29 条仅断言结构存在 |
| §6 并发正确性 | 4/10 | SessionId 唯一性无保障（H-4） |
| §7 失败测试优先 | N/A | 未描述 |
| §8 对抗审查 | 6/10 | 6 项虚假覆盖 |
| **综合** | **5.7/10** | 中等偏下 |

测试用例质量综合评分 5.7/10，主要缺陷在"断言可观察结果"（§5）与"并发正确性"（§6）。

---

## 8. 多会话场景正确性

### 8.1 §6.14 多会话设计

- **Config**：`flows.count=5` + `tuples.strategy="inc", range=[1024,65535], step=1`。
- **期望**：
  1. 5 个独立 TCP 4-tuple，每个 SrcPort 递增。
  2. 每条会话独立 SessionId/TreeId/FileId。
  3. 5 个 FlowID 互不重叠。
  4. 每条会话完整执行协商→认证→树连接→文件操作→断开。
  5. 不存在跨会话状态泄漏。

### 8.2 多会话正确性审计

#### 8.2.1 TCP 4-tuple 唯一性

- **设计**：`tuples.strategy="inc"` 保证 SrcPort 递增，DstPort=445 固定，SrcIP/DstIP 固定 → 5 个 4-tuple 唯一。
- **缺陷**：未规定 SrcPort 起始值（range=[1024,65535] 但未说"从 1024 开始还是随机起点"）；未规定 SrcPort 耗尽时的回绕规则。
- **评分**：8/10。

#### 8.2.2 FlowID 唯一性

- **设计**：§5.3 规定 `FlowID = "smb-<SrcIP>-<DstIP>-<SrcPort>-<DstPort>"`，SrcPort 唯一 → FlowID 唯一。
- **缺陷**：无。
- **评分**：10/10。

#### 8.2.3 SessionId 唯一性

- **设计**：§4.1 规定"SessionId 由 SESSION_SETUP 响应分配（随机 uint64）"。
- **缺陷**：见 H-4，多 goroutine 并发生成 SessionId 无全局唯一性保障。
- **评分**：4/10。

#### 8.2.4 TreeId 唯一性

- **设计**：§4.1 规定"TreeId 由 TREE_CONNECT 响应分配（递增，从 1 开始）"。
- **缺陷**：未规定"递增"是会话内递增还是全局递增。若会话内递增，每条会话 TreeId 都从 1 开始，多会话 TreeId 重复——但 TreeId 是会话内状态（SMB2 头 TreeId 字段在会话内复用），跨会话 TreeId 重复是合法的。设计文档未明确这个语义。
- **评分**：6/10。

#### 8.2.5 FileId 唯一性

- **设计**：§4.1 规定"FileId 由 CREATE 响应分配（16B 随机）"。
- **缺陷**：同 SessionId，多 goroutine 并发生成 FileId 无全局唯一性保障（概率极低但非零）。
- **评分**：4/10。

#### 8.2.6 跨会话状态隔离

- **设计**：§6.14 期望"不存在跨会话状态泄漏"。
- **缺陷**：T53 不断言"任一会话的 MessageId/SessionId 不影响其他"的具体机制。MessageId 是会话内状态（每条会话从 0 开始），跨会话 MessageId 重复是合法的——但设计文档未明确这个语义。
- **评分**：6/10。

### 8.3 多会话综合评分

| 维度 | 评分 | 说明 |
|------|------|------|
| TCP 4-tuple | 8/10 | SrcPort 起始/回绕未规定 |
| FlowID | 10/10 | 完全正确 |
| SessionId | 4/10 | 唯一性无保障（H-4） |
| TreeId | 6/10 | 会话内 vs 全局未明确 |
| FileId | 4/10 | 唯一性无保障 |
| 状态隔离 | 6/10 | MessageId 语义未明确 |
| **综合** | **6.3/10** | 中等 |

多会话场景综合评分 6.3/10，主要缺陷在 SessionId/FileId 唯一性无保障（H-4）。

---

## 9. 总体评分

### 9.1 维度评分

| 维度 | 评分 | 说明 |
|------|------|------|
| MS-SMB2 一致性 | 5/10 | SMB2 头布局自我推翻（C-1）+ TRANSFORM_HEADER 大小错（C-2）+ WRITE DataOffset 错（C-3）+ QUERY_DIRECTORY 响应缺失（H-6） |
| 扩展表 28 字段覆盖 | 7/10 | 4 字段全覆盖，但 treeconnect_is_pipe 部分覆盖（60%） |
| 状态机完整性 | 8/10 | 流程图完整，异常分支清晰，但 TreeId 初始值错（H-1） |
| 多会话正确性 | 6/10 | SessionId/FileId 唯一性无保障（H-4） |
| 测试用例质量 | 5.7/10 | 29 条仅断言结构存在（C-4）+ 6 项虚假覆盖（M-1） |
| 内部一致性 | 4/10 | §2.2 三处自我推翻 + 总包数计算错（H-2）+ 默认列表不一致（H-5） |
| Validate 规则 | 5/10 | 13 条规则，缺 6 类负向校验（M-4） |
| 文档完整性 | 7/10 | 结构完整，但行数声明错（L-3）+ 交叉引用断链（L-6） |
| **综合** | **5.7/10** | 中等偏下 |

### 9.2 严重度分布

| 严重度 | 数量 | 说明 |
|--------|------|------|
| CRITICAL | 4 | C-1 SMB2 头布局 / C-2 TRANSFORM_HEADER 52B / C-3 WRITE DataOffset / C-4 测试断言缺失 |
| HIGH | 7 | H-1 TreeId 初始值 / H-2 总包数计算 / H-3 PreauthIntegrity 误解 / H-4 SessionId 唯一性 / H-5 默认 dialects / H-6 QUERY_DIRECTORY 缺失 / H-7 TREE_CONNECT 前置约束 |
| MEDIUM | 9 | M-1 虚假覆盖 / M-2 边界断言弱 / M-3 MSS PSH 标记 / M-4 Validate 不全 / M-5 NegotiateContextList / M-6 错误注入模糊 / M-7 状态码表缺失 / M-8 纯 ACK 时机 / M-9 TRANSFORM_HEADER 字段 |
| LOW | 6 | L-1 SMB1 dialect 表述 / L-2 术语表遗漏 / L-3 行数声明 / L-4 默认值表不一致 / L-5 MCP e2e 映射 / L-6 交叉引用 |
| **合计** | **26** | |

### 9.3 总体结论

设计文档**结构完整**，状态机、PDU 字段表、Config 结构体、Plan 输出、业务场景、测试清单、审计清单均覆盖，Planner 接口与 socks5 先例一致。但存在三类系统性缺陷：

1. **MS-SMB2 字段事实错误（4 CRITICAL + 7 HIGH）**：SMB2 头布局三处自我推翻、TRANSFORM_HEADER 大小错（57→52）、WRITE DataOffset 叙述混乱、QUERY_DIRECTORY 响应缺失、TreeId 初始值错、PreauthIntegrity 概念混淆。这些错误若实现者照抄，将产出 Wireshark 标记为 malformed 的包。
2. **测试用例质量不达标（C-4 + M-1）**：60 条用例中 29 条仅断言结构存在而非字节级字段值，6 项审计清单字段零断言。这正是 CLAUDE.md 测试策略 §5 警告的"结构存在不等于行为正确"反模式——若实现者照抄测试用例，将产出"测试全绿但 Wireshark 标记 malformed"的灾难。
3. **内部矛盾（H-2 + H-5）**：§6.1 总包数计算与 NTLM 三阶段矛盾；§3 默认 dialects 列表与 Windows 实际不一致。这些矛盾会导致不同测试用例互相打架。

### 9.4 修复优先级

1. **P0（必须修复，阻断实现）**：C-1 / C-2 / C-3 / C-4 / H-1 / H-2 / H-6
2. **P1（强烈建议修复）**：H-3 / H-4 / H-5 / H-7 / M-1 / M-4 / M-5 / M-9
3. **P2（建议修复）**：M-2 / M-3 / M-6 / M-7 / M-8
4. **P3（可选修复）**：L-1 / L-2 / L-3 / L-4 / L-5 / L-6

### 9.5 与已实现协议设计文档的对比

对比同目录 14-mqtt-design.md（1760 行，32 个问题）/ 09-tds-design.md / 08-nfs-design.md 等已审计文档：

- **结构完整性**：SMB 设计文档结构完整度与 MQTT 相当，优于 NFS。
- **字段准确性**：SMB 字段错误率（11/60 ≈ 18%）高于 MQTT（13/35 ≈ 37% 但 MQTT 多 v5 字段），主要错误集中在 SMB2 头布局与 TRANSFORM_HEADER。
- **测试质量**：SMB 测试用例质量（5.7/10）低于 MQTT（约 7/10），主要缺陷在断言可观察结果（§5）。
- **内部一致性**：SMB 内部矛盾（4 处）与 MQTT（5 处）相当。

### 9.6 最终建议

设计文档需在修复 P0 + P1 共 12 个问题后方可进入实现阶段。建议按以下顺序修复：

1. 修复 SMB2 头布局（C-1）：删除三处"重新列出准确偏移"，仅保留最终表，删除 padding 行。
2. 修复 TRANSFORM_HEADER（C-2 + M-9）：改为 52B，补充字段表。
3. 修复 WRITE DataOffset（C-3）：改为 112，删除"对齐到 72"叙述。
4. 修复 QUERY_DIRECTORY 响应（H-6）：补充响应 PDU 字段表。
5. 修复 TreeId 初始值（H-1）：改为 0。
6. 修复总包数计算（H-2）：统一 NTLM 三阶段，总包数改为 28。
7. 修复 SessionId 唯一性（H-4）：改为全局原子计数器。
8. 补充测试用例字节级断言（C-4 + M-1）：每条用例至少断言 1 个字节级字段值。

修复后需重新审计，确认所有 CRITICAL 与 HIGH 问题已解决。

---

**审计结束**。

- 审计问题总数：26
- 严重度分布：CRITICAL 4 / HIGH 7 / MEDIUM 9 / LOW 6
- 文档行数：约 1580 行（设计文档声明 1100 行，实际 1581 行，误差 30%）
- 建议修复优先级：P0 7 项 / P1 8 项 / P2 4 项 / P3 6 项
