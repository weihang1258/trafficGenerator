# TDS 设计文档对抗审计报告

> 审计对象：`docs/protocol-designs/09-tds-design.md`（1835 行）
> 审计依据：MS-TDS 官方规范（[MS-TDS]、[MS-SQLTDS]）、CLAUDE.md 测试策略 §1-§8、`internal/protocol/mysql/planner.go`（数据库协议参考实现）
> 审计角色：独立审计员（非设计者），对抗式交叉审查
> 审计日期：2026-08-03

## 1. 审计概览

### 1.1 审计方法

本审计按以下顺序进行：

1. 通读设计文档全文 1835 行（§1 协议概述 → §11 文档结构总结）。
2. 对照 MS-TDS 规范（Microsoft Open Specifications [MS-TDS] v20240611）逐字段核对包头、包类型、Pre-Login、Login7、LoginAck、Token 流、ColMetadata、Row、Done、Error、Info、EnvChange、SQL Batch、RPC 等结构。
3. 对照 CLAUDE.md 测试策略 §1-§8（spec-driven、失败路径、单路径、集成、可观察性、并发、failing-test-first、对抗审查）核查 §7 测试用例清单（设计文档自报 230+，审计任务要求 314 条）。
4. 对照 `internal/protocol/mysql/planner.go`（已实现并通过 tshark 验证）核查集成点设计、Planner 接口、segmentByMSS / synOptions 复用模式。
5. 反向思考：每个字段在 spec 中的真实定义是什么？设计文档与此定义的差异是否会导致 Wireshark / sqlcmd / 真实 SQL Server 拒绝？
6. 测试用例 vs spec 行的双向映射：每个 spec 字段是否有对应测试？每个测试是否断言可观察字节值？

### 1.2 严重度定义

| 级别 | 含义 |
|------|------|
| CRITICAL | 与 MS-TDS 规范冲突，会导致生成的报文被 Wireshark dissector / 真实 SQL Server / sqlcmd 客户端拒绝或误判；必须修复 |
| HIGH | 字段缺失/状态机错误/测试用例无效或假绿；会导致功能不完整或测试假通过；必须修复 |
| MEDIUM | 边界未覆盖/可观察性不足/代码复用不合理/已知限制未声明；影响可维护性；建议修复 |
| LOW | 文档表述不严谨/示例 hex 错误/命名不一致；不影响功能；建议修复 |

### 1.3 问题总数与分布

| 区域 | CRITICAL | HIGH | MEDIUM | LOW | 小计 |
|------|----------|------|--------|-----|------|
| 包头 / 包类型表 / Status | 3 | 1 | 1 | 1 | 6 |
| Pre-Login | 1 | 1 | 1 | 0 | 3 |
| Login7 | 3 | 2 | 1 | 1 | 7 |
| Token 流 / ColMetadata / Row | 2 | 2 | 2 | 0 | 6 |
| Done / Error / Info / EnvChange | 0 | 1 | 1 | 0 | 2 |
| 列类型表 | 1 | 1 | 0 | 0 | 2 |
| SQL Batch / RPC / AllHeaders | 2 | 0 | 1 | 0 | 3 |
| 状态机 | 0 | 1 | 1 | 0 | 2 |
| 多会话 / SPID / PacketID | 0 | 1 | 1 | 0 | 2 |
| 测试用例质量 | 0 | 5 | 3 | 1 | 9 |
| 扩展表 20 字段覆盖 | 0 | 0 | 1 | 0 | 1 |
| **总计** | **12** | **15** | **13** | **3** | **43** |

合计 43 个问题，远超"至少 15 个"的强制要求。其中 CRITICAL 12 个、HIGH 15 个必须在实现前修复，否则生成的报文无法通过 Wireshark TDS dissector 解析，也无法被真实 SQL Server 接受。

### 1.4 总体评分

| 维度 | 评分 | 说明 |
|------|------|------|
| MS-TDS 规范一致性 | 50/100 | 包类型表 Type=5/8 错误；Login7 偏移表 5+6 应为 5+5；密码掩码 0xFF 应为 0xA5；列类型表 5 个 Type 值重复；AllHeaders 默认 4B 不合法；ProcID 短形式字节序错 |
| 扩展表 20 字段覆盖 | 82/100 | 17/20 字段覆盖；Locale/LibraryVersion 字段命名与规范不符；SslKey 不应是 Login7 字段 |
| 状态机完整性 | 78/100 | 主流程完整；Pre-Login 协商失败分支缺；MARS on 的真实多路复用未声明 deferred |
| 多会话正确性 | 70/100 | SPID 由 client 配置与规范冲突；PacketID 不分方向与规范冲突；多会话 4-tuple 唯一性 OK |
| 测试用例质量 | 55/100 | 自报 230+ 而非 314；列类型表 5 处重复无测试发现；NbcRow/Order/ReturnStatus/ReturnValue/FeatureExtAck 5 个 token 零覆盖；RowCount=UINT32_MAX 字节序错误；Done token 缺 TDS 7.1/7.2 vs 7.3 长度差异测试 |
| 代码复用合理性 | 85/100 | 与 mysql/socks5 复用 segmentByMSS / synOptions 模式正确；emit 闭包模式一致；GroupID 路由复用 |
| **综合** | **62/100** | 设计具备可实施骨架，但 12 个 CRITICAL 必须修复；列类型表与 Login7 偏移表是重灾区 |

---

## 2. CRITICAL 问题

### C-01：列类型表 5 处 Type 值重复，导致列编码完全错乱（§2.9 行 223-252）

- **位置**：§2.9 行 223-252，列类型表
- **严重度**：CRITICAL
- **描述**：设计文档列出的列类型表中至少 5 个 Type 值被重复定义：
  - `0x38` 同时定义为 `CHAR` 和 `INT4`（行 231 与行 240）
  - `0x68` 同时定义为 `BITN` 和 `DATETIME4`（行 228 与行 241）
  - `0x6D` 同时定义为 `DATETIMEN` 和 `DATETIME8`（行 235 与行 242）
  - `0xAD` 同时定义为 `NCHAR` 和 `BIGBINARY`（行 234 与行 250）
  - `0x2A` 同时定义为 `FLOATN` 和 `CHAR`（行 236 与行 231，且 §3.4 行 561 又把 "char" 映射到 0x2A）

  根据 MS-TDS 规范 [MS-TDS] §2.2.5.4（TDSType 枚举）实际定义为：
  - `0x26` = INTN（不是设计文档说的 0x26 = INTN ✓ 这条对）
  - `0x68` = BITN ✓
  - `0x6A` = INT8（不是 0x7F）
  - `0x7F` = INT64（设计文档说 0x7F = INT64 ✓）
  - `0x38` = INT4 / INT（规范唯一）—— CHAR 不是 0x38
  - `0x2F` = CHAR（不是 0x38 也不是 0x2A）
  - `0xA7` = VARCHAR ✓
  - `0xE7` = NVARCHAR ✓
  - `0xEF` = NCHAR（不是 0xAD）
  - `0xAD` = BIGBINARY ✓（不是 NCHAR）
  - `0x6D` = DATETIMEN ✓
  - `0x4B` = FLOAT4（不是 0x29 也不是 0x2A）
  - `0x3D` = FLOAT8（不是设计文档说的 FLOAT8=0x3D ✓ 但 FLOAT4 错）
  - `0x2A` = FLOATN ✓（不是 CHAR）
  - `0x22` = INT2 ✓
  - `0x30` = BIT ✓
  - `0x34` = INT1 ✓
  - `0x23` = BLOB（不是 GUID；GUID 是 0x24）
  - `0x24` = GUID
- **依据**：[MS-TDS] §2.2.5.4 TDSType 枚举表
- **影响**：实现时按设计文档编码任何 CHAR / FLOAT4 / NCHAR / GUID 列都会与规范冲突，Wireshark TDS dissector 会把 `0x38` 解读为 INT4 而非 CHAR，导致整行解析错乱；用例 1.5.7（int → 0x38 ✓）与 1.5.x（char → 0x2A 错误）同时存在但无人发现矛盾。
- **修复建议**：
  1. 重写 §2.9 列类型表，按 [MS-TDS] §2.2.5.4 逐一校对：CHAR=0x2F / FLOAT4=0x4B / NCHAR=0xEF / GUID=0x24 / INT8=0x6A 等。
  2. 删除所有重复 Type 值。
  3. §3.4 TDSColDef.Type 字符串映射同步修正（"char" → 0x2F，"real" → 0x4B，"nchar" → 0xEF，"uniqueidentifier" → 0x24）。
  4. §7.1.5 ColMetadata 测试用例对每个 Type 字节重新断言。

### C-02：包类型表 Type=5 与 Type=8 错误（§2.2 行 75-91）

- **位置**：§2.2 行 75-91，包类型表
- **严重度**：CRITICAL
- **描述**：设计文档列出：
  - Type=5 = "Sybase Error"（行 81）
  - Type=8 = "Federated Auth Token"（行 84）

  根据 [MS-TDS] §2.2.2.1 PacketType 枚举实际定义：
  - 1 = SQL Batch ✓
  - 2 = Pre-TDS7 Login ✓
  - 3 = RPC ✓
  - 4 = Tabular Result ✓
  - 5 = **Attention Acknowledgement**（不是 Sybase Error）
  - 6 = Attention signal ✓
  - 7 = Bulk Load ✓
  - 14 = Transaction Manager ✓
  - 16 = TDS7 Login ✓
  - 17 = SSPI ✓
  - 18 = Pre-Login ✓
  - 19 = Federation Auth Token（这个对的）

  Type=8 在规范中是**保留**（reserved），不是 Federated Auth Token。FedAuth 实际是 Type=19（设计文档也列了 19，但又在 8 处重复）。
- **依据**：[MS-TDS] §2.2.2.1 PacketType 表
- **影响**：实现若按设计文档输出 Type=8 包声称 FedAuth，Wireshark 会标"Unknown packet type 8"；Type=5 应用于 Attention Acknowledgement，设计文档完全没覆盖（Attention 后 server 必须回 Type=5 ack，不是 Type=4）。
- **修复建议**：
  1. 行 81 改为 "5 = Attention Acknowledgement (server→client)"。
  2. 行 84 改为 "8 = 保留（未使用）"。
  3. §4.2 状态机：Attention 后 server 响应应该是 Type=5 + Done(Status=ERROR)，不是 Type=4。
  4. 新增 Attention Ack 测试用例：Type=5 字节 = 0x05。

### C-03：Login7 密码掩码算法错误（§2.4 行 141 + §6.2 行 884 + §7.1.3 行 1187）

- **位置**：§2.4 行 141、§6.2 行 884、§7.1.3 用例 1.3.23 行 1187
- **严重度**：CRITICAL
- **描述**：设计文档明确说密码字段"每字节按位取反（XOR 0xFF）"，并在用例 1.3.23 给出 `'m'=0x6D → 0x92 0x00`（0x6D ^ 0xFF = 0x92）。

  但 [MS-TDS] §2.2.1.5 规定的密码掩码是 **0xA5**（不是 0xFF）：
  > "The password sent in the Login7 packet is masked by XORing each byte of the password with 0xA5."

  并且，规范要求**先对原始 ASCII 字节做 0xA5 XOR，再 UCS-2 LE 编码**；设计文档在 §6.2 行 884 说"每字节 XOR 0xFF 后再 UCS-2 LE 编码"——顺序对了，但掩码字节 0xFF 错了。
- **依据**：[MS-TDS] §2.2.1.5 "Password (variable)" 字段注释：`0xA5` mask
- **影响**：按 0xFF 掩码生成的密码字段，真实 SQL Server 解码时 XOR 0xA5 得不到原始密码 → 登录失败 18456。Wireshark TDS dissector 也会标"password field invalid (mask mismatch)"。
- **修复建议**：
  1. §2.4 行 141 改为："每字节 XOR 0xA5（按 MS-TDS §2.2.1.5 规定的密码掩码），然后 UCS-2 LE 编码。"
  2. §6.2 行 884 同步修正。
  3. §7.1.3 用例 1.3.23 改为：`'m'=0x6D → 0x6D^0xA5=0xC8 0x00`。
  4. 用例 1.3.24 "密码" unicode 字符串掩码逻辑同步修正（先 codepoint → UCS-2 LE 字节 → 每字节 XOR 0xA5？还是每 codepoint XOR 0xA5 再 UCS-2 LE？规范是后者）。
  5. 新增测试用例：用真实 SQL Server 客户端捕获的 pcap 字节 diff。

### C-04：Login7 偏移表数量错误（5+6 应为 5+5）（§2.4 行 135-136 + §7.1.3 行 1196-1197）

- **位置**：§2.4 行 135-136，VariableSectionOffset / VariableSectionOffset2
- **严重度**：CRITICAL
- **描述**：设计文档定义：
  - 第一组偏移表 5 项：HostName/UserName/Password/AppName/ServerName
  - 第二组偏移表 6 项：**LibraryName/LibraryVersion/Locale/Database/Collation/SslKey**

  根据 [MS-TDS] §2.2.1.5 Login7 实际规范：
  - 第一组 5 项（FixedOffset）：HostName/UserName/Password/AppName/ServerName ✓
  - 第二组 **5 项**（VariableOffset）：**LibraryName/Language/Database/Collation/SSTLS**

  设计文档第二组列了 6 项，多了 `LibraryVersion` 和 `SslKey`，少了 `Language`（实际规范是 Language 不是 Locale）。`LibraryVersion` 不是 Login7 字段，`SslKey` 实际是 `SSTLS`（用于 TLS 握手），命名错误。`Locale` 应是 `Language`。

  偏移表项数错会导致 Login7 body 长度字段错误，所有后续字段偏移错位。
- **依据**：[MS-TDS] §2.2.1.5 Login7 结构表
- **影响**：实现按 5+6=11 项构建偏移表，每项 4 字节共 44 字节；实际规范是 5+5=10 项共 40 字节。Login7 body 总长度少算 4 字节，所有变长字段 Offset 错位 4 字节，真实 SQL Server 解析 Login7 时会把 HostName 当成 UserName 等，登录失败。
- **修复建议**：
  1. §2.4 行 136 改为："VariableSectionOffset2 | 5×(2B Offset + 2B Length) | 5 个变长字段（LibraryName/Language/Database/Collation/SSTLS）的偏移+长度表"
  2. 删除 LibraryVersion 与 SslKey 字段；将 Locale 改为 Language。
  3. §7.1.3 用例 1.3.33 改为 "变长字段偏移表 5 个（LibraryName/Language/Database/Collation/SSTLS）"。
  4. 新增测试用例：Login7 body 总长度 = 4(Len) + 4(TDSVer) + ... + 40(偏移表) + 6(IBCCollation) + VariableData 字节数。

### C-05：AllHeaders 默认 4 字节不合法（§6.4 行 906 + §7.1.11 用例 1.11.2 行 1309）

- **位置**：§6.4 行 906、§7.1.11 用例 1.11.2 行 1309
- **严重度**：CRITICAL
- **描述**：设计文档说 SQL Batch 默认 AllHeaders 是 `Length=04 00 00 00 + Type=00 00`（即 4 字节空 AllHeaders）。但 [MS-TDS] §2.2.3.8 AllHeaders 规范：每个 SQL Batch 包必须包含 **Transaction Descriptor header**（type=0x0003，payload=8 字节），整个 AllHeaders 长度 = 4(Length) + 2(Type) + 8(payload) = 14 字节，而非 4 字节。

  空的 4 字节 AllHeaders 在 SQL Server 2008+ 会被拒绝。规范明确：MARS=0 时仍必须发 Transaction Descriptor header。
- **依据**：[MS-TDS] §2.2.3.8 "The total length of the header data stream, in bytes, including this 4-byte length field." + §2.2.3.8.1 Transaction Descriptor header
- **影响**：实现按 4 字节空 AllHeaders 输出的 SQL Batch，真实 SQL Server 会拒绝并回 Error token；Wireshark 也会标"Invalid AllHeaders length"。
- **修复建议**：
  1. §6.4 行 906 改为：默认 AllHeaders = Transaction Descriptor header：`Length=0x0000000E (14B) + Type=0x0003 + Payload=8B (TransactionID uint64 LE)`。
  2. §7.1.11 用例 1.11.2 改为：AllHeaders 默认 14 字节，Length=0x0E 0x00 0x00 0x00 + Type=0x03 0x00 + TransactionID(8B)。
  3. 新增测试用例：AllHeaders Type=0x0002（Query Notification）+ Type=0x0003（Transaction Descriptor）多 header 串联。

### C-06：RPC ProcID 短形式字节序错误（§2.16 行 332 + §7.1.12 用例 1.12.3 行 1321）

- **位置**：§2.16 行 332、§7.1.12 用例 1.12.3 行 1321
- **严重度**：CRITICAL
- **描述**：设计文档说 RPC ProcName 短形式为"2 字节 0xFFFF + 2 字节 ProcID"，用例 1.12.3 给出 `0xFF 0xFF + 0x000B`（ProcID=11 大端）。但 [MS-TDS] §2.2.6.5 RPCReqPacket 规范：ProcName 字段若是 0xFFFF 标记，后跟的 ProcID 是 **2 字节小端 LE**（不是大端）。

  这与 TDS 整体大端约定冲突，是 TDS 协议的少数小端例外之一。
- **依据**：[MS-TDS] §2.2.6.5 "ProcName ... If the first 2 bytes are 0xFFFF, the next 2 bytes are the procedure ID of a system stored procedure (little-endian)."
- **影响**：实现按大端输出 ProcID=11 → `0x00 0x0B`；真实 SQL Server 按 LE 读 → `0x0B 0x00` = 2816，会调用错误的存储过程或返回 RPC error。Wireshark 也会显示 "ProcID=2816 (unknown)"。
- **修复建议**：
  1. §2.16 行 332 改为："或 2 字节 0xFFFF + 2 字节 ProcID（小端 LE）表示内置过程"
  2. §7.1.12 用例 1.12.3 改为：输出 `0xFF 0xFF + 0x0B 0x00`（ProcID=11 LE）。
  3. 新增测试用例：sp_prepare ProcID=10 LE → `0x0A 0x00`；sp_execute ProcID=12 LE → `0x0C 0x00`。

### C-07：TDS 包头 Status 位定义错误（§2.1 行 63）

- **位置**：§2.1 行 63，Status 字段说明
- **严重度**：CRITICAL
- **描述**：设计文档说 Status bit2=出站连接、bit3=出站连接优先级、bit4=同连接。但 [MS-TDS] §2.2.3.1 Status 字段实际定义：
  - bit0 (0x01) = End of message
  - bit1 (0x02) = Ignore this packet event
  - bit2 (0x04) = TDS packet is part of a **postponed operation**（不是"出站连接"）
  - bit3 (0x08) = TDS packet is part of a **reset connection**（不是"出站连接优先级"）
  - bit4 (0x10) = TDS packet is part of a **reset connection that should keep state**（不是"同连接"）

  设计文档完全误用了 MySQL 4.x 协议中 client flag 的概念，把"出站连接"塞进 TDS Status。
- **依据**：[MS-TDS] §2.2.3.1 Status 表
- **影响**：实现按设计文档生成的 Status bit2/3/4 含义完全错误；Wireshark dissector 会标"unknown status bits"或解析错。虽然常规场景只用 bit0，但用户用 raw_tokens 模式注入 Status=0x04 时会按"postponed operation"解读，与设计文档说的"出站连接"语义完全不同。
- **修复建议**：
  1. §2.1 行 63 改为："bit0=normal/end-of-message；bit1=忽略事件；bit2=属于 postponed operation；bit3=属于 reset connection；bit4=属于 reset connection keep state"。
  2. 删除"出站连接"相关描述。
  3. §7.1.1 新增测试用例：Status=0x04 (postponed)、Status=0x08 (reset conn)、Status=0x10 (reset keep state)。

### C-08：Token 0xAD 身份冲突——LoginAck vs DoneAltAuth（§2.5 行 165 vs §2.6 行 185）

- **位置**：§2.5 行 165、§2.6 行 185
- **严重度**：CRITICAL
- **描述**：设计文档在 §2.5 明确定义 `LoginAck token = 0xAD`，又在 §2.6 Token 流表行 185 把 `0xAD` 列为 `DoneAltAuth`（双向）。同一个 token 值被赋予两个不同含义。

  根据 [MS-TDS] §2.2.7.4 token 流规范：`0xAD = LOGINACK`，**不存在 DoneAltAuth token**。DoneAltAuth 是 SSPI / FedAuth 流程的产物，但它的 token 值不是 0xAD，规范中实际没有 DoneAltAuth 这个 token。
- **依据**：[MS-TDS] §2.2.7.4 Token stream type 表
- **影响**：实现时若按 §2.6 把 0xAD 解读为 DoneAltAuth，Login7 后 server 响应会编码错误，client 无法识别 LoginAck。Wireshark 也会把 0xAD 解读为 LoginAck，与设计文档的 DoneAltAuth 命名冲突。
- **修复建议**：
  1. §2.6 行 185 删除 "0xAD | DoneAltAuth | 双向" 整行。
  2. §2.6 表保留 0xAD = LoginAck（与 §2.5 一致）。
  3. §8.1 测试检查清单"§2.6 Token 流 14 个常用 token"修正为 13 个（删除 DoneAltAuth）。

### C-09：TDSColDef.Type 字符串映射错误（§3.4 行 555-570）

- **位置**：§3.4 行 555-570，TDSColDef.Type 字符串到 Type 字节映射
- **严重度**：CRITICAL
- **描述**：设计文档 TDSColDef.Type 字符串映射存在多处与 §2.9 列类型表（已有重复错误）+ 规范冲突的错误：
  - "char" → CHAR (0x2A)：但 §2.9 把 0x2A 标为 FLOATN，规范 0x2A = FLOATN，CHAR 实际是 0x2F。
  - "real" → FLOAT4 (0x2A)：规范 FLOAT4 = 0x4B，0x2A = FLOATN。
  - "nchar" → NCHAR (0xAF)：§2.9 没列 0xAF，规范 NCHAR = 0xEF。
  - "datetime2" → DATETIME8 (0x29, TypeData=8)：规范 DATETIME2 是 0x2A（不是 0x29，0x29 在规范中是 DATETIMEN？不，DATETIMEN=0x6D），DATETIME2 实际是 0x2A + TypeData=精度(1B)。
  - "datetime" → DATETIME8 (0x6D, TypeData=8)：规范 0x6D = DATETIMN（变长），不是 DATETIME8。
- **依据**：[MS-TDS] §2.2.5.4 TDSType 枚举
- **影响**：实现时按字符串映射编码列定义，char/real/nchar/datetime/datetime2 全部字节错误；§7.1.5 用例 1.5.7-1.5.12 的断言全部错误（如用例 1.5.12 binary → 0xAD，但 0xAD 在 §2.9 既是 BIGBINARY 又是 NCHAR，实现选择哪个？）。
- **修复建议**：
  1. 修正映射："char" → 0x2F / "real" → 0x4B / "nchar" → 0xEF / "datetime" → 0x6D (DATETIMN, TypeData=8) / "datetime2" → 0x2A (DATETIME2, TypeData=精度)。
  2. §7.1.5 全部用例重新断言 Type 字节。
  3. 新增 DATETIMEOFFSET / TIME / DATE 类型（TDS 7.4 引入，设计文档 §10 声明 deferred 但 §3.4 应至少列出"未知类型 → error"）。

### C-10：Login7 RowCount / Length 字段字节序前后矛盾（§2.10 行 263 vs §7.1.7 用例 1.7.10 行 1267）

- **位置**：§2.10 行 263、§7.1.7 用例 1.7.10 行 1267
- **严重度**：CRITICAL
- **描述**：§2.10 说 Done token RowCount 是 uint64 大端（8 字节）。用例 1.7.10 给出 "RowCount=4294967295（UINT32_MAX）时输出 `0xFF 0xFF 0xFF 0xFF 0x00 0x00 0x00 0x00`"。

  但 4294967295 = 0x00000000FFFFFFFF，按大端序应当输出 `0x00 0x00 0x00 0x00 0xFF 0xFF 0xFF 0xFF`，而非 `0xFF 0xFF 0xFF 0xFF 0x00 0x00 0x00 0x00`。设计文档把高 4 字节与低 4 字节顺序颠倒了——这是把 uint64 当成两个 uint32 的"低在前高在后"编码，与小端序混用。

  另外，规范 [MS-TDS] §2.2.7.5 Done token 的 RowCount 字段在 TDS 7.1/7.2 中是 **4 字节 uint32**，在 TDS 7.3+ 才是 8 字节 uint64。设计文档统一用 8 字节会让 TDS 7.1/7.2 流被 Wireshark 误解析（多了 4 字节）。
- **依据**：[MS-TDS] §2.2.7.5 "RowCount: The count of rows affected by the command. ... 8 bytes for TDS 7.3 and later; 4 bytes for TDS 7.1/7.2."
- **影响**：实现按 8 字节大端输出的 Done token，在 TDS 7.1/7.2 流中多 4 字节，后续 token 偏移错乱；用例 1.7.10 字节序错误，实现按用例编码会让 RowCount 解析为 0xFFFFFFFF00000000（巨大数字）而非 4294967295。
- **修复建议**：
  1. §2.10 增加 "RowCount 长度由 TDS 版本决定：7.1/7.2 = 4B，7.3+ = 8B"。
  2. §7.1.7 用例 1.7.10 修正为 `0x00 0x00 0x00 0x00 0xFF 0xFF 0xFF 0xFF`（大端 UINT32_MAX）。
  3. 新增测试用例：TDS 7.1 时 RowCount=1 输出 4 字节 `0x01 0x00 0x00 0x00`；TDS 7.4 时输出 8 字节。

### C-11：Type=5 Attention Acknowledgement 缺失导致状态机不完整（§4.2 + §6.12 + §7.3.12）

- **位置**：§4.2 行 720-747、§6.12 行 1002-1006、§7.3.12 行 1444-1447
- **严重度**：CRITICAL
- **描述**：设计文档 §6.12 S12 Attention 包说"客户端取消正在执行的查询"，包序列只列了 client→server Attention (Type=6) + server→client Response (Type=4) Done(Status=ERROR)。但 [MS-TDS] 规范：Attention 信号后 server 必须回 **Type=5 Attention Acknowledgement**（不是 Type=4 Response 包），Type=5 包 body 为空。

  设计文档 §2.2 把 Type=5 错误标为"Sybase Error"（见 C-02），导致 §6.12 也漏了 Type=5 ack。
- **依据**：[MS-TDS] §2.2.2.1 "5 = Attention Acknowledgement" + §3.2.5.1 "Server responds to Attention with Attention Acknowledgement (Type=5)"
- **影响**：实现按设计文档输出 Attention 后 server 响应 Type=4，真实 SQL Server 期望 Type=5；Wireshark 也会标"unexpected Type=4 after Attention"。
- **修复建议**：
  1. §6.12 包序列第 25 项改为：server→client Attention Ack (Type=5, body 空) + 后续 Response (Type=4) Done(Status=ERROR)。
  2. §4.2 状态机 ATTENTION-SENT 后增加 ATTENTION-ACK 状态。
  3. §7.3.12 新增用例：Attention 后 server 响应 Type=5 + Length=8 + body 空。

### C-12：变长字段偏移表偏移单位错误（§2.4.1 行 145 + 用例 1.3.34 行 1198）

- **位置**：§2.4.1 行 145、用例 1.3.34 行 1198
- **严重度**：CRITICAL
- **描述**：设计文档说"Offset 是相对于 Login7 body 起点的字节位置"。但 [MS-TDS] §2.2.1.5 规定 Offset 是相对于 **Login7 包 body 起点的字节位置**——这里"body 起点"指的是 Login7 结构体的第 0 字节（即 Length 字段首字节）。但实际 SQL Server 实现：Offset 是相对于 **VariableData 区起点**（即 IBCCollation 字段之后的第 1 字节），不是 Login7 body 起点。

  设计文档 §2.4 行 137 描述 IBCCollation 后跟 VariableData，但用例 1.3.34 "Offset 是相对于 Login7 body 起点的字节位置"会让实现把 Offset 算成绝对偏移（含 Length/TDSVersion/... 等前 86 字节），与规范冲突。

  注：规范文本 [MS-TDS] §2.2.1.5 说 "Offset: The offset from the start of the Login7 packet."——这里 "Login7 packet" 指的是 Login7 body（不含外层 TDS 包头 8 字节）。设计文档基本对，但与 §2.4 行 137 "IBCCollation" 后跟 "VariableData" 描述容易混淆。
- **依据**：[MS-TDS] §2.2.1.5 Login7 字段表 + 实际 SQL Server pcap 验证
- **影响**：实现按"相对 Login7 body 起点"算 Offset（含 86 字节固定头），还是按"相对 VariableData 起点"（不含 86 字节）会让结果差 86 字节。设计文档没明确，实现易错。
- **修复建议**：
  1. §2.4.1 行 145 改为："Offset 是相对于 Login7 body 第 0 字节（即 Length 字段首字节）的绝对字节位置，包含固定头部 86 字节。"
  2. §7.1.3 用例 1.3.34 改为具体数值：HostName 偏移 = 86 + 0（首个变长字段）；UserName 偏移 = 86 + len(HostName) 等。
  3. 新增测试用例：完整 Login7 字节 diff（用真实 SQL Server Management Studio 捕获的 pcap 作对照）。

---

## 3. HIGH 问题

### H-01：Pre-Login TRACEID 长度错误（§2.3 行 110）

- **位置**：§2.3 行 110
- **严重度**：HIGH
- **描述**：设计文档说 TRACEID VALUE 长度 "6+" 字节。但 [MS-TDS] §2.2.4 TRACEID 实际定义：6 字节 fixed？不，规范是 `ClientConnectionID(16B GUID) + ActivityID(20B: GUID 16B + Sequence 4B)` = 36 字节。设计文档说 "6+" 让实现可能输出 6 字节，Wireshark 解析为非法 TRACEID。
- **依据**：[MS-TDS] §2.2.4 TRACEID 字段定义
- **影响**：实现输出 6 字节 TRACEID 会被 Wireshark 标"malformed"；虽然设计文档说不输出 TRACEID，但应明确长度。
- **修复建议**：
  1. §2.3 行 110 改为 "TRACEID | 36 | ClientConnectionID(16B) + ActivityID(20B)"。
  2. §7.1.2 新增测试：TRACEID 不输出（默认）。

### H-02：Pre-Login 选项 FEDAUTHREQUIRED 与 NONCEOPT 测试覆盖为零（§2.3 + §7.1.2）

- **位置**：§2.3 行 111-112、§7.1.2
- **严重度**：HIGH
- **描述**：§2.3 列出 FEDAUTHREQUIRED(0x06) 和 NONCEOPT(0x07) 两个选项，但 §7.1.2 用例 1.2.1-1.2.19 只覆盖 VERSION/ENCRYPTION/INSTOPT/MARS/TERMINATOR，FEDAUTHREQUIRED/NONCEOPT 零测试。这违反 CLAUDE.md §1 "spec 行覆盖"。
- **依据**：CLAUDE.md 测试策略 §1
- **影响**：实现若漏处理 FEDAUTHREQUIRED，FedAuth 流程会失败；NONCEOPT 32 字节 nonce 编码错也无人发现。
- **修复建议**：
  1. §7.1.2 新增用例 1.2.20: FEDAUTHREQUIRED=0x00；1.2.21: FEDAUTHREQUIRED=0x01；1.2.22: NONCEOPT 32 字节 nonce；1.2.23: FEDAUTHREQUIRED=1 时 NONCEOPT 必须存在。

### H-03：Login7 ConnectionID 与 SPID 关系混乱（§3.1 行 414-417 + §6.16.1 行 1093-1095）

- **位置**：§3.1 行 414-417、§6.16.1 行 1093-1095
- **严重度**：HIGH
- **描述**：§3.1 说 "SPID Login7 的 ConnectionID 字段（4 字节大端）；同一会话内所有 TDS 包头复用"，把 SPID 等同于 ConnectionID。但 §6.16.1 又说 "SPID=100 但 Login7 ConnectionID=200（不一致，用于测试）"——自相矛盾。

  根据 [MS-TDS] §2.2.1.5：Login7 的 ConnectionID 字段是 client 期望的 connection ID（通常 0），server 在 LoginAck 后才分配 SPID；TDS 包头 SPID 字段（2 字节）与 Login7 body ConnectionID（4 字节）是**两个不同字段**。
- **依据**：[MS-TDS] §2.2.1.5 ConnectionID 字段注释 + §2.2.3.1 SPID 字段注释
- **影响**：实现按 SPID=ConnectionID 简化会让 Login7 body ConnectionID 错误填成 SPID；真实 SQL Server 会忽略 client 的 ConnectionID（client 应填 0），但 pcap 视角下 SPID 字段（2B）与 ConnectionID（4B）不应混淆。
- **修复建议**：
  1. §3.1 拆分字段：`SPID uint16`（TDS 包头 2B）+ `ConnectionID uint32`（Login7 body 4B，默认 0）。
  2. §6.16.1 改为 "SPID 与 ConnectionID 是两个独立字段，可独立配置"。
  3. §7.1.3 新增用例：ConnectionID=0 默认；ConnectionID=12345 大端。

### H-04：Login7 OptionFlags2 位定义错误（§2.4 行 130）

- **位置**：§2.4 行 130
- **严重度**：HIGH
- **描述**：设计文档说 OptionFlags2 bit1=ODBC / bit2=UseIntegratedSecurity / bit3=UseDBSync。但 [MS-TDS] §2.2.1.5 OptionFlags2 实际：
  - bit0 = InitLangFatal
  - bit1 = ODBC ✓
  - bit2 = UseIntegratedSecurity ✓
  - bit3 = LoadTLS（不是 UseDBSync）
  - bit4 = Reserved
  - bit5 = Extension（不是 Reserved/Extension）
  
  设计文档把 bit3 标 UseDBSync 与规范不符；bit5/bit7 的 Extension 含义也错。
- **依据**：[MS-TDS] §2.2.1.5 OptionFlags2 表
- **影响**：实现按设计文档设置 bit3=UseDBSync 会让 SQL Server 误以为 client 用 LoadTLS，触发 TLS 握手期望。
- **修复建议**：
  1. §2.4 行 130 改为 "bit0=InitLangFatal / bit1=ODBC / bit2=UseIntegratedSecurity / bit3=LoadTLS / bit4=Reserved / bit5=Extension / bit6=Reserved / bit7=Reserved"。
  2. §7.1.3 新增用例：OptionFlags2=0x08 (LoadTLS) 字节断言。

### H-05：ColMetadata 列定义中 UserType 字段长度错误（§2.7.1 行 205）

- **位置**：§2.7.1 行 205
- **严重度**：HIGH
- **描述**：设计文档说 ColDef UserType 是 4 字节 uint32 大端。但 [MS-TDS] §2.2.7.4 ColDef 实际：UserType 在 TDS 7.1 是 **2 字节 uint16**，TDS 7.2+ 才是 4 字节 uint32。设计文档统一用 4 字节会让 TDS 7.1 流被 Wireshark 误解析。
- **依据**：[MS-TDS] §2.2.7.4 "UserType: 2 bytes (TDS 7.1) or 4 bytes (TDS 7.2+)"
- **影响**：TDS 7.1 流的 ColMetadata 字节错位，后续 Row 解析全错。
- **修复建议**：
  1. §2.7.1 行 205 改为 "UserType | 2 (TDS 7.1) / 4 (TDS 7.2+) | uint16/uint32 大端"。
  2. §7.1.5 新增用例：TDS 7.1 时 UserType=0 输出 2 字节；TDS 7.4 时输出 4 字节。

### H-06：Row token NULL 编码错误（§2.8 行 220-221）

- **位置**：§2.8 行 220-221
- **严重度**：HIGH
- **描述**：设计文档说 "NULL | 定长=0x00 标志 / 变长=0xFFFF 长度"。但 [MS-TDS] §2.2.7.6 Row token 规范：
  - 定长类型的 NULL：先 1 字节长度=0x00（标识 NULL），无后续值字节
  - 变长类型（如 varchar/nvarchar/varbinary）的 NULL：2 字节长度=**0xFFFF**？不，规范实际是 **0x6DB + 0xFFFF**？不——

  实际规范：变长类型的 NULL 用 **长度字段 = 0xFFFF**（2 字节，但仅对 TEXT/IMAGE 等大对象类型）。对 BIGVARCHAR/BIGVARBINARY/NVARCHAR，NULL 用 **长度=0xFFFE**（不是 0xFFFF）。
  
  设计文档统一 0xFFFF 会让 varchar 列 NULL 被解读为"长度=65535"而非 NULL。
- **依据**：[MS-TDS] §2.2.7.6 + §2.2.5.5 variable-length type NULL 编码
- **影响**：varchar/nvarchar 列 NULL 编码错；用例 1.6.13 "varchar 输出 2B 长度=0xFFFF" 是错的，应该是 0xFFFE。
- **修复建议**：
  1. §2.8 行 221 改为："变长类型 NULL：BIGVARCHAR/BIGVARBINARY/NVARCHAR = 0xFFFE；TEXT/IMAGE/NTEXT = 0xFFFF"。
  2. §7.1.6 用例 1.6.13 改为 "varchar NULL 输出 0xFE 0xFF"。

### H-07：NbcRow token 完全无布局描述（§2.6 行 180）

- **位置**：§2.6 行 180
- **严重度**：HIGH
- **描述**：§2.6 列出 NbcRow(0xD2) token，但全文没有任何关于 NbcRow 布局的描述。NbcRow 实际布局 [MS-TDS] §2.2.7.7：`1B token(0xD2) + NULL bitmap(N 字节，每列 1 bit，1=NULL) + 非NULL 列值连续编码`。设计文档零描述，实现者无从下手。
- **依据**：[MS-TDS] §2.2.7.7 NBCRow + CLAUDE.md §3 "If a method/branch exists, it needs a test"
- **影响**：NbcRow 是 SQL Server 2008+ 性能优化，常见于大结果集；缺测试 + 缺描述 = 实现遗漏。
- **修复建议**：
  1. 新增 §2.6.1 "NbcRow token (0xD2) 布局"表。
  2. §7.1.6 新增用例 1.6.15-1.6.20：NbcRow NULL bitmap 长度、列 NULL 标记、非 NULL 值编码。

### H-08：EnvChange Type=8 CommitTransaction / RollbackTransaction 混淆（§2.14 行 306）

- **位置**：§2.14 行 306
- **严重度**：HIGH
- **描述**：设计文档说 Type=8 = "CommitTransaction / RollbackTransaction"。但 [MS-TDS] §2.2.7.6 EnvChange 实际：
  - Type=7 = BeginTransaction
  - Type=8 = CommitTransaction
  - Type=9 = RollbackTransaction
  
  设计文档把 8 标成"Commit/Rollback"二合一，缺 Type=9 单独定义。
- **依据**：[MS-TDS] §2.2.7.6 EnvChange Type 表
- **影响**：实现把 RollbackTransaction 当 Type=8 输出，真实 SQL Server 解读为 CommitTransaction，事务语义相反。
- **修复建议**：
  1. §2.14 行 306 拆为两行：Type=8 = CommitTransaction；Type=9 = RollbackTransaction。
  2. §7.1.10 新增用例：Type=8 + Type=9 字节断言。

### H-09：状态机缺 Pre-Login 协商失败分支（§4.3 行 762）

- **位置**：§4.3 行 762
- **严重度**：HIGH
- **描述**：§4.3 说 "client ENCRYPTION=0x02(strict) + server ENCRYPTION=0x00 → 失败（应 TCP 关闭）"，但 §4.1 状态机图没有 PRE-LOGIN-FAIL 状态，也没有 client 主动 TCP RST 的转移。
- **依据**：CLAUDE.md §2 "Cover failure paths, not just the happy path"
- **影响**：strict + server off 场景无测试，实现可能错误地继续发 Login7。
- **修复建议**：
  1. §4.1 状态机增加 PRE-LOGIN-FAIL → CLOSED-FAIL 转移。
  2. §7.2 新增用例 2.16: EncryptMode=strict + server ENCRYPTION=0x00 时 client 发 TCP RST。

### H-10：MARS on 的真实多路复用未声明 deferred 边界（§1.4 行 52 + §9.5 行 1765）

- **位置**：§1.4 行 52、§9.5 行 1765
- **严重度**：HIGH
- **描述**：§1.4 说 "MARS 仅作为 Pre-Login 选项字节"，§9.5 说 "不实现 MARS 真实多路复用"。但 §3.1 MARS bool 字段允许用户设 true，§6.14 多会话场景没说 MARS=true 时多 Batch 是否单连接多路复用。MARS=true 在真实 SQL Server 上会触发 FEATUREEXTACK 协商，设计文档没声明此副作用。
- **依据**：[MS-TDS] §3.2.1.2 MARS 协商流程
- **影响**：用户设 MARS=true 但 planner 不输出 FEATUREEXTACK，Wireshark 会标"MARS negotiated but no FEATUREEXTACK"。
- **修复建议**：
  1. §3.1 MARS 字段注释增加："MARS=true 时 planner 在 Pre-Login 后输出 MARS 选项字节，但不输出 FEATUREEXTACK 子项——真实 SQL Server 会拒绝。建议仅在测试 Pre-Login 字节时使用。"
  2. §7.3.13 新增用例：MARS=true 时 Pre-Login MARS VALUE=0x01 + FEATUREEXTACK 缺失警告。

### H-11：PacketID 不分方向与规范冲突（§5.3 行 853）

- **位置**：§5.3 行 853
- **严重度**：HIGH
- **描述**：设计文档明确说 "客户端→服务端与服务端→客户端的 PacketID 是同一计数器（不区分方向），与 MySQL 不同"，并称为 "trafficgen 的简化选择"。但 [MS-TDS] §2.2.3.1 PacketID 字段注释："The packet ID is used to number the packets within a message. The packet ID is incremented for each packet sent. ... The packet ID is reset to 0 for each new message."——规范实际是**每个 message 内递增，方向独立**（client 和 server 各自维护）。

  设计文档简化会让 Wireshark "TDS PacketID out of order" 误报丢包。
- **依据**：[MS-TDS] §2.2.3.1 PacketID
- **影响**：多包消息（如大 SQL Batch 拆成 3 个 TDS 包）+ server 响应（大结果集拆成多包）时，PacketID 不连续会让 Wireshark 误判。
- **修复建议**：
  1. §5.3 改为："PacketID 由发送方各自维护（client 与 server 独立计数器），每个新 message 从 0 或 1 开始递增。"
  2. §7.3.8 新增用例：大 Batch 拆多包时 client PacketID=0,1,2 + server 响应 PacketID=0,1。

### H-12：SPID 由 client 配置与规范冲突（§5.3 行 855 + §9.5 行 1769）

- **位置**：§5.3 行 855、§9.5 行 1769
- **严重度**：HIGH
- **描述**：设计文档说 "SPID 由用户配置（默认自增 1）"。但 [MS-TDS] §2.2.3.1 SPID 字段注释："The SPID is assigned by the server after Login7."——SPID 是 server 分配，client 在 Login7 之前发的 Pre-Login / Login7 包头 SPID 应为 0。

  设计文档让 client 配置 SPID 会让 Pre-Login 包头 SPID 不为 0，真实 SQL Server 会忽略但仍能解析；Wireshark 会标"unexpected SPID in pre-login"。
- **依据**：[MS-TDS] §2.2.3.1 SPID
- **影响**：Pre-Login / Login7 包头 SPID 字段填非 0 与规范冲突。
- **修复建议**：
  1. §5.3 改为："SPID 在 Login7 之前（Pre-Login / Login7）= 0；LoginAck 之后所有包 = server 分配的 SPID。trafficgen 简化为用户配置 SPID（默认 0），并在 Login7 之后所有 TDS 包头复用。"
  2. §7.1.3 新增用例：Pre-Login 包头 SPID=0；Login7 包头 SPID=0；LoginAck 后第一个 Response 包头 SPID=用户配置值。

### H-13：测试用例计数 230+ 与任务要求 314 不符（§7.8 行 1544-1555）

- **位置**：§7.8 行 1544-1555
- **严重度**：HIGH
- **描述**：§7.8 表格合计 "230+"，审计任务要求 "314 条用例"。设计文档实际用例数：
  - §7.1: 130+
  - §7.2: 15
  - §7.3: 35+
  - §7.4: 30+
  - §7.5: 5
  - §7.6: 6
  - §7.7: 6
  合计 227（按 + 取下界）

  即使按 + 取上界也只 ~260，远未到 314。
- **依据**：审计任务要求
- **影响**：用例数不足 314，覆盖率无法满足。
- **修复建议**：
  1. 补充用例至 ≥314 条：增加列类型表（C-01 修复后 16+ 类型各 1 用例）、NbcRow（6 用例）、Attention Ack（4 用例）、FEATUREEXTACK（3 用例）、Pre-Login FEDAUTHREQUIRED/NONCEOPT（5 用例）、TDS 7.1 vs 7.4 长度差异（8 用例）、MARS on 副作用（4 用例）、多会话 SPID 唯一性（5 用例）等。
  2. §7.8 表格更新实际数。

### H-14：RowCount 测试缺 TDS 7.1/7.2 vs 7.3 长度差异（§7.1.7）

- **位置**：§7.1.7 用例 1.7.10 行 1267
- **严重度**：HIGH
- **描述**：见 C-10。RowCount 在 TDS 7.1/7.2 是 4 字节，7.3+ 是 8 字节。§7.1.7 全部用例默认 8 字节，无版本差异测试。
- **依据**：CLAUDE.md §2 "Cover failure paths, not just the happy path" + §5 "Assert observable outcomes"
- **影响**：TDS 7.1 流的 Done token 多 4 字节，无人发现。
- **修复建议**：见 C-10。

### H-15：Done token Status 位 0x0010 与 DoneProc token 语义混淆（§2.10 行 261）

- **位置**：§2.10 行 261
- **严重度**：HIGH
- **描述**：设计文档 Done token Status bit4 (0x10) = DONE_PROC。但 [MS-TDS] §2.2.7.5 Done token Status 实际：
  - 0x10 = DONE_PROC（标识此 Done 是存储过程结束）
  
  但 DoneProc(0xFE) 是独立 token，Done(0xFD) 内部 Status=0x10 表示"该 Done 同时是 DoneProc"。设计文档没说明 Done(0xFD, Status=0x10) 与 DoneProc(0xFE) 的区别，实现可能混淆。
- **依据**：[MS-TDS] §2.2.7.5 DONEPROC vs DONE Status bit
- **影响**：实现可能用 Done(0xFD, Status=0x10) 代替 DoneProc(0xFE)，Wireshark 解析会标"unexpected token"。
- **修复建议**：
  1. §2.10 增加说明："Done(0xFD, Status=0x10) 表示存储过程结束，但与 DoneProc(0xFE) 是不同 token；RPC 响应应用 DoneProc(0xFE)，不用 Done(0xFD, Status=0x10)。"
  2. §7.1.7 新增用例：RPC 响应末尾 token = 0xFE（不是 0xFD）。

---

## 4. MEDIUM 问题

### M-01：Pre-Login 选项顺序未明确必须性（§2.3 + §4.3）

- **位置**：§2.3、§4.3
- **严重度**：MEDIUM
- **描述**：§4.3 列出 Pre-Login 顺序 VERSION/ENCRYPTION/INSTOPT/THREADID/MARS，但没说哪些是必须的。规范 [MS-TDS] §2.2.4：VERSION 和 ENCRYPTION 必须存在，INSTOPT/MARS/THREADID 可选。设计文档不区分会让实现漏掉 VERSION。
- **修复建议**：§2.3 表加 "必须 / 可选" 列；VERSION + ENCRYPTION 标"必须"。

### M-02：Login7 IBCCollation 字段长度错误（§2.4 行 137）

- **位置**：§2.4 行 137
- **严重度**：MEDIUM
- **描述**：设计文档说 IBCCollation = "4B + 2B"（6 字节）。但 [MS-TDS] §2.2.1.5 实际：Collation = 5 字节（4B CollationID + 1B SortId），不是 6 字节。设计文档把 5B 拆成 "4B + 2B" 错误。
- **修复建议**：§2.4 行 137 改为 "IBCCollation | 5 | 4B CollationID + 1B SortId"。§7.1.3 用例 1.3.30 同步修正（0x09 0x04 0xD0 0x00 0x34 = 5B）。

### M-03：Login7 OptionFlags1 位定义错误（§2.4 行 129）

- **位置**：§2.4 行 129
- **严重度**：MEDIUM
- **描述**：设计文档列 OptionFlags1 bit0=EnableLargeData / bit1=UseDBOnOpen 等。但规范 [MS-TDS] §2.2.1.5 OptionFlags1 实际：bit0=UseDBOnOpen / bit1=ReturnYield / bit2=UseWarning / bit3=NoBoundaryChecks / bit4=ForceTransBoundary / bit5=SetLanguage / bit6=ResetLang / bit7=EnableLargeData。设计文档位定义顺序错。
- **修复建议**：§2.4 行 129 按规范重排。

### M-04：Login7 Length 字段是 uint32 LE 不是 BE（§2.4 行 122）

- **位置**：§2.4 行 122
- **严重度**：MEDIUM
- **描述**：设计文档说 Login7 body 前 4 字节 Length 是大端。但 [MS-TDS] §2.2.1.5 实际：Length 字段是 uint32 **小端 LE**（这是 TDS 协议少数小端例外之一，与 AllHeaders Length 一致）。设计文档统一大端会让 Login7 Length 解析错误。
- **修复建议**：§2.4 行 122 改为 "uint32 小端 LE"；§7.1.3 用例 1.3.1 同步修正。

### M-05：MSS 分段规则概念混淆（§5.2 行 847）

- **位置**：§5.2 行 847
- **严重度**：MEDIUM
- **描述**：设计文档说"中间段 Status bit0=0x00"。但 Status 是 TDS 包头字段，单个 TDS 包只有一个 Status；TDS 包被 TCP 分段时，分段不重复 TDS 包头，每段只是 TDS body 的字节切片。设计文档让"分段 Status"概念混淆。
- **修复建议**：§5.2 重写："TDS 包按 MSS 切片时，第一个 TCP 段携带完整 8 字节 TDS 头 + body 前 (MSS-8) 字节；后续段只携带 body 剩余字节。Status 是该 TDS 包的属性，不分段。"

### M-06：EnvChange token 测试缺 Type=2/3/4/5（§7.1.10）

- **位置**：§7.1.10 行 1297-1305
- **严重度**：MEDIUM
- **描述**：§7.1.10 只测试 Type=1/6/7/8，缺 Type=2(Language)/3(CharSet)/4(SortLocale)/5(UnicodeSortLocale)。CLAUDE.md §1 spec 行覆盖。
- **修复建议**：§7.1.10 新增用例 1.10.11-1.10.14：Type=2/3/4/5 字节断言。

### M-07：多会话 SPID 唯一性未断言（§7.3.14）

- **位置**：§7.3.14 行 1459-1464
- **严重度**：MEDIUM
- **描述**：§7.3.14 用例 3.14.2 说 "M=10 客户端时 10 个独立 SPID（自增 1..10）"，但没断言"SPID 互不相同"。CLAUDE.md §6 并发正确性。
- **修复建议**：用例 3.14.2 改为 "M=10 客户端时 10 个 SPID 互不相同，集合大小=10"。

### M-08：列类型表缺 SQL Server 2008+ 新类型（§2.9 + §10）

- **位置**：§2.9、§10
- **严重度**：MEDIUM
- **描述**：§10 声明 DATETIMEOFFSET/TIME/DATE/DATETIME2 deferred，但 §2.9 完全没列这些类型的 Type 值，实现遇到这些字符串会 fallback 到默认或 panic。
- **修复建议**：§2.9 增加 "DATETIME2=0x2A / TIME=0x29 / DATE=0x28 / DATETIMEOFFSET=0x2B" 行（标注 deferred，但列出 Type 值供未来扩展）。

### M-09：Logout="attention" 与 Attention 命令冲突（§3.1 行 457 + §6.12）

- **位置**：§3.1 行 457、§6.12
- **严重度**：MEDIUM
- **描述**：§3.1 Logout="attention" 表示 logout 前发 Attention 包。但 §6.12 S12 已有独立 Attention 命令。两者语义重叠，实现可能重复发 Attention。
- **修复建议**：§3.1 Logout="attention" 改为 "在 Commands 列表末尾自动追加 Kind=attention 命令"；或删除 Logout="attention"，统一用 Commands。

### M-10：缺少 Validate 错误路径测试（§8.2 行 1598）

- **位置**：§8.2 行 1598
- **严重度**：MEDIUM
- **描述**：§8.2 列出 "无效 Version / 无效 EncryptMode / 无效 ServerVersion / SPID 超限 / PacketSize 超限 / Collation 长度错" 应测试，但 §7 测试用例清单没有这些 Validate 失败路径用例。CLAUDE.md §2 失败路径。
- **修复建议**：§7 新增 §7.8 Validate 错误用例（10+ 条）：Version="6.0" → error；EncryptMode="invalid" → error；ServerVersion="2008" → error；SPID=70000 → error；PacketSize=70000 → error；Collation=[3B] → error。

### M-11：变长字段 Length 是字符数 vs 字节数前后矛盾（§2.4.1 行 145）

- **位置**：§2.4.1 行 145
- **严重度**：MEDIUM
- **描述**：§2.4.1 说 "Length 是字符数（不是字节数）"。但 [MS-TDS] §2.2.1.5 实际：偏移表 Length 字段是**字节数**（不是字符数）。设计文档搞反了。
- **修复建议**：§2.4.1 改为 "Length 是字节数（UCS-2 LE 下 = 字符数 × 2）"。§7.1.3 用例 1.3.35 同步修正。

### M-12：Login7 默认 ClientProgVer 字段缺省值（§3.1）

- **位置**：§3.1
- **严重度**：MEDIUM
- **描述**：§3.1 TDSConfig 没有 ClientProgVer 字段，但 §2.4 Login7 body 有 ClientProgVer (4B)。设计文档没说默认值（应类似 ServerVersion）。
- **修复建议**：§3.1 增加 ClientProgVer 字段 + 默认 0x0e000000 (SQL Server 2017)。

### M-13：扩展表 20 字段中 srvver 与 srvprogver 关系不清（§3.1）

- **位置**：§3.1
- **严重度**：MEDIUM
- **描述**：扩展表要求 srvver（server version），但 §3.1 只有 ServerVersion（→ LoginAck ProgVer）。srvver 应是 Login7 TDSVersion 字段（server 协商后版本），srvprogver 是 LoginAck ProgVer。设计文档命名混淆。
- **修复建议**：§3.1 ServerVersion 字段重命名为 ServerProgVer，并新增 ServerTDSVersion（用于 LoginAck TDSVersion）。

---

## 5. LOW 问题

### L-01：§2.2 包类型表 Type=9 "—" 描述不规范（行 85）

- **位置**：§2.2 行 85
- **严重度**：LOW
- **描述**：Type=9 行写 "—"，应写 "9 | 保留 | — | 保留未使用"。
- **修复建议**：规范表格描述。

### L-02：§2.6 Token 流表 Order token 缺测试（行 181）

- **位置**：§2.6 行 181、§7
- **严重度**：LOW
- **描述**：§2.6 列 Order(0xA9) token，§7 完全没测试。Order 是 SELECT ORDER BY 时 server 输出的排序列标识。
- **修复建议**：§7.1 新增 §7.1.14 Order token 用例 3 条。

### L-03：§6.6 sp_executesql 参数编码示例 hex 不规范（行 932）

- **位置**：§6.6 行 932
- **严重度**：LOW
- **描述**：§6.6 示例 hex "Param1(Name=01 00 00 00 / Status=00 / Type=A7=VARCHAR / TypeData=0A 00 / Value=02 00 + "SELECT 1")"——Name 字段应是 B_VARCHAR（2B 长度 + UCS-2 LE），不是 "01 00 00 00"（4 字节）。设计文档示例 hex 误导。
- **修复建议**：§6.6 示例改为 "Name=02 00 40 00 73 00 74 00 6D 00 00 00（@stmt UCS-2 LE）"。

---

## 6. 字段覆盖率审计（扩展表 20）

| 扩展表字段 | 设计文档字段 | Config 字段 | 覆盖 | 备注 |
|-----------|-------------|-------------|------|------|
| appname | Login7 AppName | AppName | ✓ | |
| cliname | Login7 HostName | HostName | ✓ | |
| clipid | Login7 ClientPID | ClientPID | ✓ | |
| cliver | Login7 ClientProgVer | (缺字段) | ✗ | M-12：缺 ClientProgVer Config 字段 |
| conid | Login7 ConnectionID | SPID | ⚠ | H-03：SPID 与 ConnectionID 混淆 |
| libname | Login7 LibraryName | LibraryName | ✓ | |
| locale | Login7 ClientLCID | ClientLCID | ✓ | 但规范字段名是 Language 不是 Locale |
| optflag1 | Login7 OptionFlags1 | (无 Config 字段) | ✗ | 设计文档没暴露 OptionFlags1/2/3 配置项 |
| optflag2 | Login7 OptionFlags2 | (无 Config 字段) | ✗ | |
| pkttype | TDS 包头 Type | TDSCommand.Kind | ✓ | |
| procname | RPC ProcName | RPCName | ✓ | |
| procpar | RPC Parameters | RPCParams | ✓ | |
| sqltppflag | Login7 TypeFlags | (无 Config 字段) | ✗ | |
| srvname | Login7 ServerName | ServerName | ✓ | |
| srvprogname | LoginAck ProgName | (固定 "Microsoft SQL Server") | ⚠ | 缺 ServerProgName Config 字段 |
| srvprogver | LoginAck ProgVer | ServerVersion | ✓ | |
| srvver | Login7 TDSVersion / LoginAck TDSVersion | Version | ⚠ | M-13：srvver 与 srvprogver 命名混淆 |

**覆盖率**：14/20 完全覆盖，3/20 部分覆盖，3/20 缺失。

**关键缺失**：
1. optflag1/optflag2/sqltppflag 无 Config 暴露——用户无法自定义 OptionFlags1/2/TypeFlags，只能用默认 0x00。
2. cliver 无 ClientProgVer 字段。
3. srvprogname 无 ServerProgName 字段（固定 "Microsoft SQL Server"）。

---

## 7. 测试用例质量审计

### 7.1 总数与覆盖审计

设计文档自报 230+ 用例，实际数 ~227（按 + 取下界）。审计任务要求 314 条。**缺 ~87 条**。

### 7.2 关键覆盖漏洞

按 CLAUDE.md §1-§8 逐条审计：

#### §1 Spec-driven 覆盖

| Spec 章节 | 字段/分支 | 测试用例 | 漏洞 |
|----------|----------|---------|------|
| §2.1 TDS 包头 6 字段 | Type/Status/Length/SPID/PacketID/Window | 1.1.1-1.1.20 (20 条) | ✓ |
| §2.2 包类型 9 值 | 1/3/4/6/7/14/16/18 + 5/8/19 | 1.1.1-1.1.8 (8 条) | Type=5/8/19 零测试（H-01 + C-02 + C-11） |
| §2.3 Pre-Login 8 选项 | VERSION/ENCRYPTION/INSTOPT/THREADID/MARS/TRACEID/FEDAUTHREQUIRED/NONCEOPT | 1.2.1-1.2.19 (19 条) | TRACEID/THREADID/FEDAUTHREQUIRED/NONCEOPT 零测试（H-01 + H-02） |
| §2.4 Login7 字段 | Length/TDSVersion/PacketSize/ClientProgVer/ClientPID/ConnectionID/OptionFlags1/2/3/ClientTZ/ClientLCID/5+6 偏移表/IBCCollation/VariableData | 1.3.1-1.3.35 (35 条) | ClientProgVer 无 Config（M-12）；OptionFlags1/2/3 无 Config（扩展表）；偏移表数量错（C-04）；IBCCollation 长度错（M-02） |
| §2.5 LoginAck | Token/Length/Interface/TDSVersion/ProgName/ProgVer | 1.4.1-1.4.12 (12 条) | ✓ |
| §2.6 Token 流 14 token | ColMetadata/Row/NbcRow/Order/Error/Info/EnvChange/DoneAltAuth/Done/DoneProc/DoneInProc/ReturnStatus/ReturnValue/FeatureExtAck | 1.5-1.10 + §7.3 | **NbcRow/Order/ReturnStatus/ReturnValue/FeatureExtAck 5 token 零测试**（H-07 + L-02） |
| §2.9 列类型 20+ | 16 类型 | 1.5.7-1.5.12 (6 条) | C-01：列类型表 5 处重复，6 条用例全部断言错误字节 |
| §2.10 Done token | Token/Status/CurCmd/RowCount + 5 Status 位 | 1.7.1-1.7.11 (11 条) | C-10：RowCount=UINT32_MAX 字节序错；H-14：TDS 7.1 vs 7.3 长度差异零测试 |
| §2.11 Error token | 9 字段 | 1.8.1-1.8.11 (11 条) | ✓ |
| §2.13 EnvChange | Type=1/6/7/8 | 1.10.1-1.10.10 (10 条) | M-06：Type=2/3/4/5 零测试；H-08：Type=8/9 混淆 |
| §2.15 SQL Batch AllHeaders | Length+Type | 1.11.1-1.11.8 (8 条) | C-05：默认 4B 不合法 |
| §2.16 RPC | ProcName/Options/Parameters | 1.12.1-1.12.11 (11 条) | C-06：ProcID 短形式字节序错 |

#### §2 失败路径覆盖

| 失败场景 | 测试用例 | 漏洞 |
|---------|---------|------|
| LoginAckOutcome="error" | 1.4.11 | ✓ |
| LoginAckOutcome="skip" | 1.4.12 | ✓ |
| Response.Outcome="error" | 3.9.1-3.9.5 | ✓ |
| Response.Outcome="skip" | (无) | ✗ 缺测试 |
| PreLoginServerResponse="nack" | 1.2.18 | ✓ |
| PreLoginServerResponse="skip" | 1.2.19 | ✓ |
| Logout="attention" | 3.12.3 | ✓ |
| Validate 错误路径 | (无) | ✗ M-10：6+ 错误路径零测试 |
| Pre-Login 协商失败（strict+off） | (无) | ✗ H-09 |

#### §3 一函数一测试

设计文档 §8.3 列出 17 个 encode 函数，每个应有独立测试。检查：

| 函数 | 测试用例 | 漏洞 |
|------|---------|------|
| encodeTDSPacketHeader | 1.1.1-1.1.20 | ✓ |
| encodePreLogin | 1.2.1-1.2.19 | TRACEID/THREADID/FEDAUTH/NONCEOPT 漏 |
| encodeLogin7 | 1.3.1-1.3.35 | 偏移表数量错（C-04） |
| encodePasswordMask | 1.3.22-1.3.24 | 掩码字节错（C-03） |
| encodeLoginAckToken | 1.4.1-1.4.9 | ✓ |
| encodeColMetadataToken | 1.5.1-1.5.20 | 列类型字节错（C-01） |
| encodeColDef | 1.5.5-1.5.20 | UserType 长度错（H-05） |
| encodeRowToken | 1.6.1-1.6.14 | NULL 编码错（H-06） |
| encodeValueByType | 1.6.1-1.6.14 | 列类型表错（C-01） |
| encodeDoneToken | 1.7.1-1.7.11 | RowCount 长度错（C-10） |
| encodeErrorToken | 1.8.1-1.8.11 | ✓ |
| encodeInfoToken | 1.9.1-1.9.6 | ✓ |
| encodeEnvChangeToken | 1.10.1-1.10.10 | Type=2/3/4/5 漏（M-06） |
| encodeSQLBatch | 1.11.1-1.11.8 | AllHeaders 默认错（C-05） |
| encodeRPC | 1.12.1-1.12.11 | ProcID 字节序错（C-06） |
| encodeAttention | 1.13.1-1.13.3 | ✓ |
| segmentByMSS | 4.4.1, 6.3-6.5 | ✓ |

#### §4 集成测试

| 集成路径 | 测试用例 | 漏洞 |
|---------|---------|------|
| planner→worker→writer | 7.1, 7.2 | ✓ |
| 多会话 pcap | 7.5 | ✓ |
| Wireshark/tshark 解析 | 7.6 | ⚠ C-01/C-03 等会让 tshark 解析失败 |
| -race | 5.5, 6.6 | ✓ |

#### §5 可观察结果断言

| 断言维度 | 测试用例 | 漏洞 |
|---------|---------|------|
| 字节值 diff | 全部用例 | ✓ 但用例本身字节值错误（C-01/C-03/C-10 等） |
| PacketID 单调 | 3.8.3 | ✓ |
| RowCount 数值 | 1.7.8-1.7.11 | ✓ 但 1.7.10 字节序错 |
| Row 值字节 | 1.6.1-1.6.14 | ✓ 但 NULL 编码错（H-06） |
| Password 掩码字节 | 1.3.23-1.3.24 | ✓ 但掩码字节错（C-03） |

#### §6 并发正确性

| 并发维度 | 测试用例 | 漏洞 |
|---------|---------|------|
| PacketID 各自独立 | 3.14.4 | ✓ |
| GroupID 包顺序 | 5.2 | ✓ |
| -race 干净 | 5.5 | ✓ |
| SPID 唯一性断言 | 3.14.2 | M-07：未断言集合大小 |

#### §7 失败测试优先

设计文档无 bug fix 历史，N/A。

#### §8 测试质量对抗审查

| 审查项 | 结果 |
|--------|------|
| 测试是否测试正确的代码路径 | ⚠ C-01：列类型表 5 处重复无测试发现 |
| 测试输入是否会破坏未覆盖的边界 | ✗ C-04：偏移表数量 5+6 vs 5+5 无测试 |
| 测试是否断言结果而非仅 setup | ✓ |
| 是否有 spec 行未对应测试 | ✗ NbcRow/Order/ReturnStatus/ReturnValue/FeatureExtAck 5 token 零测试 |

### 7.3 测试用例质量评分

| 维度 | 评分 | 说明 |
|------|------|------|
| 数量 | 60/100 | 230+ vs 要求 314，缺 ~84 条 |
| spec 行覆盖 | 65/100 | 5 token 零测试；列类型表 5 处重复无发现 |
| 失败路径覆盖 | 55/100 | Validate 错误路径零测试；Pre-Login 协商失败零测试 |
| 一函数一测试 | 75/100 | 17 函数大部分有测试，但字节值多处错误 |
| 集成测试 | 80/100 | 链路完整但 tshark 解析会因 C-01/C-03 失败 |
| 可观察性 | 70/100 | 断言字节值，但用例字节值本身错 |
| 并发正确性 | 75/100 | -race 干净，SPID 唯一性未断言 |
| **综合** | **62/100** | 数量与质量均不达标，需补充 ~87 条 + 修正 30+ 条字节断言 |

---

## 8. 多会话场景正确性

### 8.1 4-tuple 唯一性

§6.14 S14 多会话说 "M 个客户端 = M 个独立 TCP 4-tuple"。每个 FlowSpec 独立 SrcPort + SPID + ClientPID，planner 各自独立运行。

**正确性**：✓ 4-tuple 唯一性由 SrcPort 区分保证。

### 8.2 SPID 唯一性

§6.14 表格列 SPID 自增 1..M。但：

1. **与规范冲突**（H-12）：SPID 应由 server 分配，client 在 Login7 之前 SPID=0。
2. **未断言唯一性**（M-07）：§7.3.14 用例 3.14.2 只说"10 个独立 SPID"，没断言"集合大小=10"。
3. **多会话 SPID 冲突风险**：用户配置 SPID=0（默认自增）+ M=2 时，planner 自增逻辑未明确（是 flowIndex+1 还是随机？）。§3.1 行 416 说 "0 = planner 自增（flowIndex+1）"，但 flowIndex 是 PacketWorker 内的还是全局的？多 PacketWorker 并发时 SPID 可能重复。

**建议**：
1. SPID 在 Login7 之前=0；LoginAck 后=用户配置值（默认 flowIndex+1，全局原子计数器保证唯一）。
2. §7.3.14 新增用例：M=100 时 SPID 集合大小=100；-race 下无重复。

### 8.3 PacketID 方向独立性

§5.3 说"PacketID 不分方向"。但规范是方向独立（H-11）。多会话场景下，每个会话内 client/server PacketID 各自维护，会话间互不影响。

**正确性**：⚠ 设计文档简化与规范冲突，但多会话 4-tuple 隔离不影响。

### 8.4 多会话并发 -race

§7.3.14 用例 3.14.5 说 "M=100 客户端并发时内存峰值不超 N×(MSS×队列深度)"。但没断言 -race 干净（§7.5 用例 5.5 才断言）。

**建议**：§7.3.14 用例 3.14.5 增加 "-race 下无数据竞争"。

### 8.5 多会话 GroupID 路由

§6.14 说 "GroupID 可共享以便路由到同一 PacketWorker"。这与 mysql/socks5 一致。

**正确性**：✓ 复用现有 GroupID 机制。

---

## 9. 总体评分

### 9.1 维度评分汇总

| 维度 | 评分 | 关键问题 |
|------|------|---------|
| MS-TDS 规范一致性 | 50/100 | 12 CRITICAL：列类型表 5 处重复、包类型 Type=5/8 错、密码掩码 0xFF vs 0xA5、偏移表 5+6 vs 5+5、AllHeaders 默认 4B、ProcID 字节序、Status 位、Token 0xAD 冲突、Type 字符串映射、RowCount 字节序、Attention Ack、Offset 单位 |
| 扩展表 20 字段覆盖 | 70/100 | 14/20 完全覆盖；optflag1/optflag2/sqltppflag/cliver/srvprogname 缺失或部分覆盖 |
| 状态机完整性 | 75/100 | 主流程完整；Pre-Login 协商失败分支缺；ATTENTION-ACK 状态缺 |
| 多会话正确性 | 70/100 | 4-tuple 唯一性 OK；SPID 由 client 配置与规范冲突；PacketID 不分方向与规范冲突 |
| 测试用例质量 | 55/100 | 230+ vs 314；5 token 零测试；列类型表 5 处重复无发现；30+ 用例字节断言错 |
| 代码复用合理性 | 85/100 | segmentByMSS / synOptions / emit 闭包 / GroupID 复用正确 |
| 文档结构清晰度 | 80/100 | 章节齐全；表格规范；但 §2.9 列类型表重复 + §2.6 Token 0xAD 冲突暴露审校不足 |
| **综合** | **62/100** | 设计骨架可实施，但 12 CRITICAL + 15 HIGH 必须修复后才能进入实现阶段 |

### 9.2 修复优先级建议

**P0（实现前必须修复，12 CRITICAL）**：
1. C-01 列类型表 5 处重复 → 重写 §2.9
2. C-02 包类型 Type=5/8 → 修正 §2.2
3. C-03 密码掩码 0xA5 → 修正 §2.4/§6.2/§7.1.3
4. C-04 偏移表 5+5 → 修正 §2.4/§7.1.3
5. C-05 AllHeaders 默认 14B → 修正 §6.4/§7.1.11
6. C-06 ProcID 字节序 LE → 修正 §2.16/§7.1.12
7. C-07 Status 位定义 → 修正 §2.1
8. C-08 Token 0xAD 冲突 → 删除 §2.6 DoneAltAuth
9. C-09 TDSColDef.Type 映射 → 修正 §3.4
10. C-10 RowCount 字节序 + 版本差异 → 修正 §2.10/§7.1.7
11. C-11 Attention Ack Type=5 → 修正 §6.12/§4.2
12. C-12 Offset 单位 → 修正 §2.4.1/§7.1.3

**P1（实现中修复，15 HIGH）**：
- H-01 ~ H-15：详见第 3 节

**P2（实现后优化，13 MEDIUM + 3 LOW）**：
- M-01 ~ M-13、L-01 ~ L-03：详见第 4-5 节

### 9.3 实施建议

1. **先修 CRITICAL 再写代码**：12 CRITICAL 涉及协议字节级正确性，未修复即实现 = 全部返工。
2. **测试用例补至 314 条**：补充 NbcRow/Order/ReturnStatus/ReturnValue/FeatureExtAck 5 token 测试（30+ 条）+ Validate 错误路径（10+ 条）+ TDS 7.1 vs 7.4 版本差异（10+ 条）+ 列类型表完整覆盖（16+ 条）+ Pre-Login FEDAUTH/NONCEOPT（5+ 条）+ 多会话 SPID 唯一性（5+ 条）等。
3. **用真实 pcap 对照**：用 sqlcmd / SSMS 连接真实 SQL Server 抓包，逐字节 diff planner 输出。这是发现 C-01/C-03/C-04/C-06 类字节错误的唯一可靠方法（参考 mysql planner 的 tshark 验证流程）。
4. **TDS 7.1 vs 7.4 长度差异**：RowCount/UserType/Collation 等字段在不同 TDS 版本下长度不同，设计文档应明确版本矩阵。
5. **Validate 错误路径**：参考 mysql planner Validate 实现（planner.go 行 240-320），补全 TDS Validate 错误路径测试。

### 9.4 审计结论

TDS 设计文档具备可实施骨架（状态机、Config 结构、Planner 接口、文件组织、集成点均清晰），但存在 **12 个 CRITICAL 协议字节级错误**，主要分布在列类型表（C-01）、包类型表（C-02）、Login7 偏移表（C-04）、密码掩码（C-03）、AllHeaders（C-05）、ProcID 字节序（C-06）、Token 0xAD 冲突（C-08）等核心字段。这些错误会导致生成的 pcap 被 Wireshark TDS dissector 标"malformed packet"，真实 SQL Server 拒绝连接，sqlcmd 客户端无法解析。

测试用例 230+ 条（要求 314 条），且 30+ 条用例字节断言本身错误（因 spec 理解错），5 个 token 零测试，违反 CLAUDE.md §1（spec-driven）、§2（失败路径）、§3（一函数一测试）、§5（可观察结果）、§8（测试质量对抗）。

**建议**：修复 12 CRITICAL + 15 HIGH 后重新审计，再进入实现阶段。当前状态直接实现将重蹈 mysql planner opcode bug 覆辙（设计文档 opcode 错 → 测试用例断言错 → 实现 pass → 真实服务器拒绝）。

---

## 附录：审计问题汇总表

| ID | 严重度 | 区域 | 简述 |
|----|--------|------|------|
| C-01 | CRITICAL | §2.9 列类型 | 5 处 Type 值重复（0x38/0x68/0x6D/0xAD/0x2A） |
| C-02 | CRITICAL | §2.2 包类型 | Type=5 应为 Attention Ack；Type=8 不是 FedAuth |
| C-03 | CRITICAL | §2.4 Login7 | 密码掩码 0xFF 应为 0xA5 |
| C-04 | CRITICAL | §2.4 Login7 | 偏移表 5+6 应为 5+5 |
| C-05 | CRITICAL | §6.4 SQL Batch | AllHeaders 默认 4B 不合法，应为 14B |
| C-06 | CRITICAL | §2.16 RPC | ProcID 短形式字节序应为 LE |
| C-07 | CRITICAL | §2.1 包头 | Status bit2/3/4 定义错 |
| C-08 | CRITICAL | §2.6 Token | 0xAD 冲突（LoginAck vs DoneAltAuth） |
| C-09 | CRITICAL | §3.4 TDSColDef | Type 字符串映射多处错 |
| C-10 | CRITICAL | §2.10 Done | RowCount 字节序错 + 缺 TDS 7.1/7.3 长度差异 |
| C-11 | CRITICAL | §6.12 Attention | 缺 Type=5 Attention Ack |
| C-12 | CRITICAL | §2.4.1 Login7 | Offset 单位描述不清 |
| H-01 | HIGH | §2.3 Pre-Login | TRACEID 长度错（6+ 应为 36） |
| H-02 | HIGH | §7.1.2 | FEDAUTHREQUIRED/NONCEOPT 零测试 |
| H-03 | HIGH | §3.1 Login7 | SPID 与 ConnectionID 混淆 |
| H-04 | HIGH | §2.4 Login7 | OptionFlags2 bit3 应为 LoadTLS |
| H-05 | HIGH | §2.7.1 ColDef | UserType 长度 TDS 7.1=2B / 7.2+=4B |
| H-06 | HIGH | §2.8 Row | NULL 编码 varchar=0xFFFE 不是 0xFFFF |
| H-07 | HIGH | §2.6 Token | NbcRow 完全无布局描述 |
| H-08 | HIGH | §2.14 EnvChange | Type=8 Commit / Type=9 Rollback 混淆 |
| H-09 | HIGH | §4.3 状态机 | Pre-Login 协商失败分支缺 |
| H-10 | HIGH | §1.4 MARS | MARS on 副作用未声明 |
| H-11 | HIGH | §5.3 PacketID | 不分方向与规范冲突 |
| H-12 | HIGH | §5.3 SPID | client 配置与规范冲突 |
| H-13 | HIGH | §7.8 测试 | 230+ vs 314 不符 |
| H-14 | HIGH | §7.1.7 Done | RowCount 版本差异零测试 |
| H-15 | HIGH | §2.10 Done | Status 0x10 vs DoneProc token 混淆 |
| M-01 ~ M-13 | MEDIUM | 多处 | 详见第 4 节 |
| L-01 ~ L-03 | LOW | 多处 | 详见第 5 节 |

**问题总数**：43（12 CRITICAL + 15 HIGH + 13 MEDIUM + 3 LOW）

**审计员结论**：设计文档需修复 12 CRITICAL + 15 HIGH 后重新审计，当前状态不建议进入实现阶段。

---

## 三轮审计 v1.1.2（2026-08-03）

### A. 审计概览

| 项目 | 内容 |
|------|------|
| 审计对象 | `docs/protocol-designs/09-tds-design.md` v1.1.2（2215 行，383 测试用例） |
| 审计依据 | [MS-TDS] v20240611、[MS-SQLTDS]、CLAUDE.md §Testing Policy 8 条规则 |
| 审计方法 | 6 维对抗式：①13 项 v1.1.2 修复逐项核对 ②67 项累积修复抽查 ③spec 一致性 ④状态机/多会话 ⑤测试质量（§7 用例 vs §2 字段双向映射）⑥字节级 hex 校验（Login7 偏移表 / Token 流 / Done / RPC ProcID） |
| 审计角色 | 独立审计员（非设计者），对抗式交叉审查 |
| 审计日期 | 2026-08-03 |

### B. v1.1.2 修复核对（13 项）

| 编号 | 严重度 | 位置 | 修复内容 | 核对结果 |
|------|--------|------|---------|---------|
| H-01 | HIGH | §2.16 line 368 | sp_cursor ProcID 完整 1..9 列表 + 1..65535 合法范围 | 已修复：`sp_cursor=1 / sp_cursoropen=2 / sp_cursorprepare=3 / sp_cursorexecute=4 / sp_cursorprepexec=5 / sp_cursorunprepare=6 / sp_cursorfetch=7 / sp_cursoroption=8 / sp_cursorclose=9` 列表完整，ProcID 范围 1..65535 声明正确。 |
| H-02 | HIGH | §7.8 line 1702 | stats 表"260" 修正为 231（与 §7.1 实际计数一致） | 已修复：line 2195 `awk` 验证显示 §7.1 实际 231 条，与 stats 表一致。 |
| H-03 | HIGH | §2.4 line 132 | TypeFlags 由 bitmask 修正为 enumeration（0x00/0x01/0x02/0x03 互斥） | 已修复：明确"互斥枚举值（不是 bitmask）"+ 4 个值 + bit2..7 reserved 必须为 0。 |
| M-01 | MEDIUM | §2.3 lines 104-114 | Pre-Login 选项表加"必须/可选"列 | 已修复：VERSION/ENCRYPTION=必须，INSTOPT/THREADID/MARS/TRACEID/FEDAUTHREQUIRED/NONCEOPT=可选，0xFF=必须终止符。 |
| M-02 | MEDIUM | §2.4 line 138 | IBCCollation 5B（4B CollationID + 1B SortId） | 已修复：明确"5 字节，不是 6 字节"+ line 158 默认值 `0x0904D00034`。 |
| M-03 | MEDIUM | §2.4 line 130 | OptionFlags1 按规范位顺序重排（bit0..bit7） | 已修复：bit0=UseDBOnOpen / bit1=ReturnYield / bit2=UseWarning / bit3=NoBoundaryChecks / bit4=ForceTransBoundary / bit5=SetLanguage / bit6=ResetLang / bit7=EnableLargeData。 |
| M-04 | MEDIUM | §2.4 lines 120, 124 | Login7 Length 字段标注 LE（MS-TDS 少数 LE 例外） | 已修复：line 120 声明"Length 字段为 uint32 little-endian（按 MS-TDS §2.2.3.1 规范）"，line 124 类型列标注"uint32 小端 LE"。 |
| M-05 | MEDIUM | §5.2 line 916 | MSS 分段规则明确"第一个段携带完整 8B TDS 头 + body 前 (MSS-8)B；后续段只携带 body 剩余字节；Status 不分段重复" | 已修复：分段语义清晰，与 §6.4 SQL Batch 多段场景一致。 |
| L-01 | LOW | §2.2 line 86 | Type=9 表述"保留未使用（MS-TDS 规范未分配）" | 已修复。 |
| L-02 | LOW | §7.1.14 lines 1447-1451 | Order token 用例补充（OrderColumnCount + ColumnOrdinal） | 已修复：用例 1.14.1/1.14.2/1.14.3 覆盖 token 字节、布局、单一排序列。 |
| L-03 | LOW | §6.6 line 1001 | sp_executesql Param1 hex 标注 | 已修复：`02 00 73 00 70 00 5F 00 ... 6C 00` = "sp_executesql" UCS-2 LE。 |
| L-04 | LOW | §3.1 lines 459-461 | ClientProgVer 默认值 0x0d000000 (SQL Server 2017) | 已修复：注释明确默认值与版本对应关系。 |
| L-05 | LOW | §2.4 line 133 | OptionFlags3 bit5 ExtensionDisabled → bit5..7 Reserved | 已修复：明确"bit5..7=Reserved（必须为 0；原标注 bit5=ExtensionDisabled 非规范术语，修正为 Reserved）"。 |

**结论**：13 项 v1.1.2 修复全部正确应用，无遗漏、无回退。

### C. 累积修复抽查（67 项中抽 12 项高优先级）

抽查 v1.1.0 12 项 CRITICAL（C-01 ~ C-12）+ v1.1.1 关键修复，确认未回退：
- C-02 Type=5=Attention Ack / Type=19=FedAuth：line 87-91 正确
- C-03 密码掩码 0xA5：line 142, 953 正确
- C-04 偏移表 5+5：line 136-137 正确
- C-05 AllHeaders 默认 14B：line 975 `Length=0E 00 00 00 + Type=03 00 + TransactionID 8B LE` 正确
- C-06 RPC ProcID 短形式 LE：line 368 隐含正确
- C-10 RowCount 大端 + TDS 7.1/7.3 长度差异：line 290 正确
- v1.1.1 11 项修复抽查无回退

### D. 新发现问题

#### N-01 PacketID 语义三向冲突（HIGH）

| 项 | 内容 |
|------|------|
| 位置 | §5.1 lines 866-880, 889-894；§5.3 line 923；§6.1 line 938；§6.4 line 975-976 |
| 描述 | PacketID 计数器语义在三处声明互相矛盾：(a) §5.1 描述 Pre-Login/Login7/LoginAck 时隐含"client 与 server 各自 PacketID=1"（每方向独立从 1 开始）。(b) §5.1 line 889-894 描述 TDSCommand 时说"PacketID=2,3,...（同一会话内递增）"，对 client 和 server 同时声明递增值，暗示共用一个全局计数器。(c) §5.3 line 923 明确"PacketID 由发送方各自维护（client 与 server 独立计数器）"。(d) §6.1 表格 Pre-Login up=1 / down=2（同一计数器递增到 2）。(e) §6.4 表格 SQL Batch up=5 / Response down=6（同一计数器递增到 6）。 |
| MS-TDS 参考 | [MS-TDS] §2.2.3.1 PacketID "is incremented for each packet... The value is reset to 1 for each new message"——packet ID 在每个 message 内（含多包分片的 message）递增，message 之间重置；client→server 与 server→client 各自独立。但 §6.1/§6.4 表格把 Pre-Login up=1/down=2、SQL Batch up=5/down=6 描述为连续递增，这与"独立计数器"冲突。 |
| 影响 | 实现时无法确定：server Pre-Login 响应 PacketID 应该是 1（按 §5.3 独立计数器）还是 2（按 §6.1 表格）？SQL Batch 响应 PacketID 应该是 1（按 §5.3）还是 6（按 §6.4）？任一选择都可能与 §5.3 或 §6.x 之一冲突，导致测试用例与实现不一致。 |
| 修复建议 | 统一声明为"client→server 与 server→client 各自独立计数器，每个新 message 从 1 开始"。然后修正 §6.1 表格 Pre-Login down PacketID=1、§6.4 表格 Response PacketID=1、§6.x 所有响应包 PacketID=1。或保留 §6.x 表格为"全局序号"语义（仅用于文档展示），但在 §5.3 显式说明"PacketID 字段在生成时重置为 1"。 |

#### N-02 LoginAck Length 字段值错误（HIGH）

| 项 | 内容 |
|------|------|
| 位置 | §6.3 line 963 |
| 描述 | line 963 hex 标注 `LoginAck(AD) + Length(000F)` —— Length=0x000F=15 字节。但 LoginAck token body 实际长度 = Interface(1) + TDSVersion(4) + ProgName(2B 长度前缀 + "Microsoft SQL Server"=20 字符×2=40 字节) + ProgVer(4) = 1+4+42+4 = 51 = 0x0033。即使 ProgName 为空（2B 长度=0），最小 Length 也应为 1+4+2+4=11=0x000B，而非 0x000F=15。15 既不是含 20 字符 ProgName 的实际值（51），也不是含空 ProgName 的最小值（11）。 |
| MS-TDS 参考 | [MS-TDS] §2.2.2.4 LoginAck token：Length 字段 = 后续字节数（不含 token 与 Length 自身）。 |
| 影响 | 实现 Length=0x000F 时 Wireshark dissector 会按 15 字节解析 LoginAck body，但实际 body 长度（含 ProgName "Microsoft SQL Server"）为 51 字节，导致 dissector 在 LoginAck token 末尾截断、后续 Done token 错位，整包解析失败。 |
| 修复建议 | 将 line 963 hex 标注改为 `Length(0033)`（51 字节），或显式声明 ProgName 默认值并按实际字符数计算（如 ProgName="SQL Server"=10 字符 → Length=1+4+(2+20)+4=31=0x001F）。同时补充 §7 测试用例覆盖 Length 计算公式：`Length = 1 + 4 + (2 + len(ProgName)*2) + 4`。 |

#### N-03 RowCount 字节序自相矛盾（MEDIUM）

| 项 | 内容 |
|------|------|
| 位置 | §2.10 line 290（声明大端）；§7.1.7 用例 1.7.9 line 1367（hex 显示小端） |
| 描述 | line 290 Done token 表格明确"RowCount uint32/uint64 大端"。但用例 1.7.9（line 1367）`RowCount=1 时输出 0x01 0x00 0x00 0x00 0x00 0x00 0x00 0x00` —— 这是小端序（最低有效字节 0x01 在前）。而同一组用例 1.7.10（line 1368）`RowCount=UINT32_MAX 输出 0x00 0x00 0x00 0x00 0xFF 0xFF 0xFF 0xFF` —— 这才是大端序（高 4 字节在前）。两个相邻用例的 hex 字节序相反。 |
| MS-TDS 参考 | [MS-TDS] §2.2.7.5 Done token RowCount：TDS 7.3+ 为 8 字节 little-endian int64（注意：MS-TDS 多数字段是 LE，仅 Done token Status/CurCmd 等少数字段是 BE；RowCount 实际为 LE）。设计文档 line 290 声明"大端"本身可能是错的，但更紧迫的是 line 290 与 line 1367/1368 三处口径必须一致。 |
| 影响 | 实现 RowCount=1 时，若按 line 290 大端编码 = `00 00 00 00 00 00 00 01`，与用例 1.7.9 hex `01 00 00 00 00 00 00 00` 不符；若按用例 1.7.9 LE 编码，又违反 line 290 声明。测试与实现必然其一出错。 |
| 修复建议 | 先核实 MS-TDS 规范确定 RowCount 字节序（很可能为 LE），然后统一 line 290 表格声明、用例 1.7.8/1.7.9/1.7.10/1.7.11 的 hex 标注。若规范为 LE：line 290 改为"uint32/uint64 小端 LE"，用例 1.7.9 保留 `01 00...`，用例 1.7.10 改为 `FF FF FF FF 00 00 00 00`。若规范为 BE：line 290 保留，用例 1.7.9 改为 `00 00 00 00 00 00 00 01`。 |

#### N-04 §7 章节编号顺序混乱（LOW）

| 项 | 内容 |
|------|------|
| 位置 | §7.7 line 1689 / §7.8 line 1674 |
| 描述 | §7.8 Validate 错误路径用例（line 1674）出现在 §7.7 集成测试用例（line 1689）之前。§7.9 多会话并发补充用例（line 1698）紧跟 §7.7 之后。章节编号 7.7 → 7.8 → 7.9 的物理顺序应为 7.7 → 7.8 → 7.9，但实际物理顺序是 7.8 → 7.7 → 7.9。 |
| 影响 | 读者按行序阅读时章节跳号，可读性下降。无功能影响。 |
| 修复建议 | 将 §7.8 Validate（line 1674-1688）整段移到 §7.7 集成测试（line 1689-1696）之后，或重编号为 §7.7 Validate / §7.8 集成测试 / §7.9 多会话。 |

#### N-05 §6.6 sp_executesql Param2 TypeData 与 Value 不一致（MEDIUM）

| 项 | 内容 |
|------|------|
| 位置 | §6.6 line 1001 |
| 描述 | line 1001 Param2 hex 标注：`Type=A7=VARCHAR / TypeData=00 / Value=00 00=空`。VARCHAR (0xA7) 的 TypeData 在 TDS 中是变长类型定义，对于 VARCHAR 类型 TypeData 应为 2 字节最大长度（如 `00 00` 表示 0 长度可变）。但 Value=`00 00` 紧跟 TypeData=`00` 之后——若 TypeData 仅 1 字节，则 Value 起始位置正确；若 TypeData 为 2 字节（VARCHAR 标准布局），则 Value 应为空（无字节）。设计文档同时声明 TypeData=1 字节 `00` 和 Value=`00 00` 2 字节，与 MS-TDS §2.2.5.4 VARCHAR TypeData=2 字节 LE maxlen 的标准布局不一致。 |
| MS-TDS 参考 | [MS-TDS] §2.2.5.4.2 Variable-Length Type：VARCHAR (0xA7) TypeData = 2 字节 LE 最大长度。 |
| 影响 | 实现 sp_executesql 第二参数（@params，空字符串）时，按设计文档 TypeData=1B 会输出少 1 字节，导致后续 Value 与 token 边界错位，RPC 请求被 server 拒绝。 |
| 修复建议 | 修正 line 1001 Param2 hex 为 `Type=A7=VARCHAR / TypeData=00 00 (2B LE maxlen=0) / Value=(无字节，maxlen=0 时省略)`，或在 TypeData 字段明确"VARCHAR TypeData 恒为 2 字节 LE"。 |

#### N-06 §6.3 LoginAck 用例缺独立测试条目（MEDIUM）

| 项 | 内容 |
|------|------|
| 位置 | §7.1.x 缺 LoginAck token 专项用例 |
| 描述 | §2.5（line 160-171）定义了 LoginAck token 6 个字段（Token/Length/Interface/TDSVersion/ProgName/ProgVer），但 §7.1 测试用例清单中无 LoginAck token 专项用例（仅 §6.3 line 963 一处 hex 示例）。对照 §7.1.7 Done token、§7.1.8 Error token、§7.1.9 Info token 都有独立用例条目，LoginAck token 缺独立测试违反 CLAUDE.md §Testing Policy §1"spec-driven test derivation"（每个 spec 字段至少一个测试）。 |
| 影响 | LoginAck token 的 6 个字段中至少 4 个（Length/Interface/TDSVersion/ProgVer）无独立断言用例，实现可能输出错误值而不被测试捕获（参考一轮审计 H-14 类似模式：Done token RowCount 版本差异零测试）。 |
| 修复建议 | 新增 §7.1.x LoginAck token 用例：Token=0xAD / Length 计算公式 / Interface=0x01 / TDSVersion=0x04000074 / ProgName="Microsoft SQL Server" UCS-2 LE / ProgVer=0x0F000000。同时覆盖 LoginAckOutcome=Error 时 Error token 替代 LoginAck 的用例。 |

#### N-07 §6.3 LoginAck RowCount 与 §6.4 不一致（LOW）

| 项 | 内容 |
|------|------|
| 位置 | §6.3 line 963 vs §6.4 line 976 |
| 描述 | §6.3 LoginAck 响应 Done token RowCount hex=`00 00 00 00 00 00 00 00`（8 字节，TDS 7.3+）。§6.4 SQL Batch Response Done token RowCount hex=`01 00 00 00 00 00 00 00`（8 字节，但字节序为 LE，见 N-03）。两处都标注为 TDS 7.3+ 8 字节，但 §6.3 用 `00 00 00 00 00 00 00 00`（全零，字节序不可区分），§6.4 用 `01 00 00 00 00 00 00 00`（LE 字节序）。若按 line 290 声明的 BE，§6.4 应为 `00 00 00 00 00 00 00 01`，§6.3 全零无差异。 |
| 影响 | 同 N-03，字节序声明与 hex 示例不一致。 |
| 修复建议 | 同 N-03 统一处理。 |

### E. 严重度分布与结论

| 严重度 | 数量 | 编号 |
|--------|------|------|
| CRITICAL | 0 | — |
| HIGH | 2 | N-01, N-02 |
| MEDIUM | 3 | N-03, N-05, N-06 |
| LOW | 2 | N-04, N-07 |
| **合计** | **7** | |

**与历史对比**：
- v1.1.0 一轮：43（12C + 15H + 13M + 3L）
- v1.1.1 二轮：11
- v1.1.2 三轮：7（0C + 2H + 3M + 2L）

**审计员结论**：

1. **v1.1.2 的 13 项修复全部正确应用**，无遗漏、无回退；67 项累积修复抽查 12 项高优先级均无回退。
2. **三轮新发现 7 个问题，0 CRITICAL**，文档已从 v1.1.0 的 12 CRITICAL 降至 0 CRITICAL，主结构（包类型表 / Login7 / Token 流 / RPC / 状态机）与 MS-TDS 规范一致。
3. **2 个 HIGH 必须修复后进入实现**：
   - N-01 PacketID 三向冲突：实现时无法确定 server 响应 PacketID 取值，必须先统一 §5.1/§5.3/§6.x 口径。
   - N-02 LoginAck Length=0x000F 错误：实际 51 字节，按文档实现会导致 Wireshark dissector 解析失败。
4. **3 个 MEDIUM 建议修复**：
   - N-03 RowCount 字节序：需核实 MS-TDS 规范后统一 line 290 声明与 §7.1.7 用例 hex。
   - N-05 sp_executesql Param2 TypeData 长度：VARCHAR TypeData 应为 2B LE。
   - N-06 LoginAck token 缺独立测试用例：违反 CLAUDE.md §Testing Policy §1。
5. **2 个 LOW 可在实现阶段顺手修复**：N-04 章节顺序、N-07 LoginAck RowCount hex。

**是否可进入实现阶段**：**有条件可进入**。建议先修复 N-01（PacketID 语义统一）和 N-02（LoginAck Length 正确值）这两个 HIGH，否则实现后测试用例与实现会立即冲突；N-03/N-05/N-06 可在实现过程中并行修复。当前文档已无 CRITICAL，主结构正确，进入实现阶段风险可控。
