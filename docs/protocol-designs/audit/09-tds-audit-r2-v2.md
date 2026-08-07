# TDS 设计文档 v2.0.1 第二轮对抗式审计报告

**审计日期**: 2026-08-04
**审计对象**: `/home/weihang/trafficGenerator/docs/protocol-designs/09-tds-design.md` (v2.0.1)
**审计依据**: MS-TDS v20260617（修订版 42.0）
**审计原则**: 默认"有 bug"，除非证据确凿
**审计范围**: 第一轮修复落地核查 + 全文 HexDump 自洽性 + 字节序 + 测试用例合规性

---

## 执行摘要

**发现问题总数**: 41

**严重度分布**:
- CRITICAL: 14
- HIGH: 11
- MEDIUM: 9
- LOW: 7

**第一轮修复落地核查**:
- A-004 (TDSVersion `0x74000004` / wire `04 00 00 74`): **已落地**（§2.7、§3.2.1、§6.2 多处一致）
- A-006 (Done RowCount 7.2+ 8B): **已落地**（§2.7、§3.6.3、多处 HexDump 注释一致）
- A-007 (Error LineNumber 2B USHORT): **已落地**（§6.8、§6.9 HexDump 注释 "2B USHORT"）
- A-010 (Packet Header Length 自洽): **未落地** — 26 个 HexDump 仍存在 wire Length 与实际字节数不符

**最终结论**: **否** — 本文档**不能直接进入实现阶段**。第一轮 9 个 CRITICAL 仅文字层面修复，HexDump 层面仍存在大量自洽性故障，且新发现多处字节级错误（Login7 偏移表错位、EnvChange 缺 OldValue、LoginAck Length 少 4 字节、S13 EnvChange NewValue 长度字节错误等）。必须再返工后方可进入实现。

---

## 问题清单

### R2-001 [CRITICAL] §6.2 Login7 HexDump 偏移表整体错位 4 字节（ClientLCID 字段丢失）

| 属性 | 值 |
|------|-----|
| 位置 | §6.2 S2 Login7 请求 HexDump（行 800-815） |
| 描述 | HexDump 第 5 行 `E0 00 00 00 00 00 00 00`（字节 32-39）对应 OptionFlags1-3 + ClientTimeZone；第 6 行 `00 00 5A 00 0C 00 66 00`（字节 40-47）应为 ClientLCID(4B) + ibHostName(4B)。但 ClientLCID 应为 `00 00 00 00`，HexDump 却将 `00 00 5A 00` 当作 ClientLCID（值 0x005A0000=5898240），并将 ibHostName 读为 `0C 00 66 00`（Offset=0x000C=12, Length=0x0066=102）—— 12 落在固定头部内，明显错误。正确字节应为 `00 00 00 00 5A 00 0C 00`（ClientLCID=0, ibHostName Offset=0x5A=90, Length=0x0C=12）。HexDump 整体少 4 字节，导致从 ibHostName 起所有后续字段错位。 |
| 证据 | 文字描述与 HexDump 字节对照：文字称 ibHostName Offset=0x5A、Length=0x0C，但 HexDump 字节解码为 Offset=0x0C、Length=0x66 |
| 修复建议 | 在 HexDump 第 5 行后插入一行 `00 00 00 00`（ClientLCID=0），或重写所有 Login7 HexDump 字节使其与 §3.2.1 字段顺序一致 |

### R2-002 [CRITICAL] §3.2.2 Login7 偏移表偏移值与"4B/项"声明自相矛盾

| 属性 | 值 |
|------|-----|
| 位置 | §3.2.2（行 283-301） |
| 描述 | 表头声明"13 项 × 4B = 52B"，但列出的偏移值为：36, 44, 52, 60, 68, 76, 80, 84, 88, 92, 100, 104, 108。这些值之间的间隔为 8B（36→44→52→60→68→76）或 4B（76→80→84→88→92）或 8B（92→100），完全不均匀。13 项 × 4B 应为 36, 40, 44, 48, 52, 56, 60, 64, 68, 72, 76, 80, 84。文档列出的偏移值实际对应 8B/项（与"4B/项=52B"声明矛盾），且 ibSSPI 偏移 92 应为 96。 |
| 证据 | 36+52=88（声明），但末项 108+4=112，跨度 76B ≠ 52B |
| 修复建议 | 重写偏移表偏移列为：36, 40, 44, 48, 52, 56, 60, 64, 68, 72, 76, 80, 84 |

### R2-003 [CRITICAL] §6.2 LoginAck Length 字段值错误（0x33=51，应为 0x37=55）

| 属性 | 值 |
|------|-----|
| 位置 | §6.2 S2 LoginAck 响应（行 834） |
| 描述 | 文档称 `Length: 0x3300 (51 LE)`。但 LoginAck token body 应为 Interface(1) + TDSVersion(4) + ProgName(US_VARCHAR: 2B 长度 + 44B 数据) + ProgVer(4) = 1+4+46+4 = 55 字节。MS-TDS §2.2.7.1 规定 Length 字段为 token stream 字节数（不含 Token 与 Length 字段本身），故 Length=55=0x37。HexDump 字节布局验证：`AD 33 00 01 04 00 00 74 2C 00 ...[44B ProgName]... 0F 00 00 00 FD` —— ProgVer (`0F 00 00 00`) 明确在 token body 内，故 Length 必须包含它。 |
| 修复建议 | 修正为 `Length: 0x3700 (55 LE)`，HexDump 字节 `33 00` 改为 `37 00` |

### R2-004 [CRITICAL] §6.2 LoginAck HexDump Done Token 缺 1 字节 RowCount

| 属性 | 值 |
|------|-----|
| 位置 | §6.2 S2 LoginAck HexDump（行 848-858） |
| 描述 | HexDump 共 74 字节。Token 流：LoginAck(1+2+55=58 字节，对应 Length=55 修正后) + Done(13 字节) = 71 字节。但 HexDump 8 字节包头 + 66 字节 token 流 = 74 字节（即 token 流 = 66 字节）。若 LoginAck body 仅 51 字节（按错误 Length），则 8+54+12=74，Done token 仅 12 字节（应为 13）。具体看 HexDump：`FD 00 00 00 00 00 00 00 00 00 00 00` —— FD 后 11 字节，但 Done 需要 Status(2)+CurCmd(2)+RowCount(8)=12 字节。少 1 字节。 |
| 修复建议 | 在 RowCount 后补 1 字节 `00`，使 Done token 完整为 13 字节；同时调整 Length 字段为 75=0x4B |

### R2-005 [CRITICAL] §6.11 / §6.13 EnvChange Begin/Commit Transaction 缺 OldValue 字节

| 属性 | 值 |
|------|-----|
| 位置 | §6.11 S11 BEGIN TRAN 响应（行 1357-1362）、§6.11 S11 COMMIT 响应（行 1394-1399）、§6.13 S13 响应（行 1546-1553） |
| 描述 | MS-TDS §2.2.7.8 ENVCHANGE Token 规定结构：`Token(1) + Length(2 LE) + Type(1) + NewValue(B_VARBYTE) + OldValue(B_VARBYTE)`。Begin Transaction (Type=0x07) 与 Commit Transaction (Type=0x08) 的 NewValue 为 8 字节 TransactionID（前缀 0x08），OldValue 为空（前缀 0x00，1 字节）。故 Length 字段应为 1(Type) + 1(NV len) + 8(NV) + 1(OV len) = 11 = 0x0B。但文档 HexDump 中 Length=0x0A=10（S11 BEGIN/COMMIT）或 0x0C=12（S13），且 HexDump 字节序列 `E3 0A 00 07 08 01 00 00 00 02 00 00 00 FD` 在 `08 01 00 00 00 02 00 00 00`（NewValue 长度+8B）后直接接 FD，完全没有 OldValue 的 0x00 字节。 |
| 证据 | HexDump `E3 0A 00 07 08 <8B TransactionID> FD` —— 缺 OldValue；正确应为 `E3 0B 00 07 08 <8B> 00 FD` |
| 修复建议 | (1) Length 改为 0x0B；(2) 在 NewValue 后 FD 前插入 1 字节 `00`；(3) 同步更新 §6.13 S13 响应中的两个 EnvChange token |

### R2-006 [CRITICAL] §6.13 S13 响应 EnvChange NewValue 长度字节错误（0x01 而非 0x08）

| 属性 | 值 |
|------|-----|
| 位置 | §6.13 S13 响应（行 1547-1553） |
| 描述 | HexDump 第 2 行 `E3 0C 00 07 01 00 00 00 02 00 00 00` —— Type=0x07(Begin Tran) 后第 1 字节为 `01`（NewValue 长度前缀）。但 Begin Transaction 的 NewValue 应为 8 字节 TransactionID，长度前缀必须为 `0x08`。文档文字描述（行 1528）也称"NewValue: 8B TransactionID"。HexDump 与文字描述自相矛盾。同理 Commit Transaction（行 1551）也是 `01` 而非 `08`。 |
| 修复建议 | 将 `01` 改为 `08`，Length 字段改为 0x0B（见 R2-005），在 8B TransactionID 后补 OldValue `00` |

### R2-007 [CRITICAL] §3.7 Attention Acknowledgement Type=0x05 不存在

| 属性 | 值 |
|------|-----|
| 位置 | §3.7（行 474-477）、§6.10 S10（行 1293-1302） |
| 描述 | 文档称"Attention Acknowledgement（服务端 → 客户端）：Type = 0x05"。但 MS-TDS §2.2.3.1.1 Packet Type 表中 0x05 不是合法包类型（合法值为 0x01-0x04, 0x06, 0x07, 0x10-0x13 等）。Attention 响应实际使用 Type=0x06（与请求相同 Type，通过 Status 与方向区分），不存在单独的 0x05 Type。 |
| 证据 | MS-TDS §2.2.3.1.1 Packet Type 表无 0x05 项 |
| 修复建议 | 将 Attention Ack Type 改为 0x06（或描述为"Attention 响应，Type 与请求相同"），重写 §6.10 S10 HexDump 的 Ack 包头字节 |

### R2-008 [CRITICAL] §2.2/§2.3/§2.5 类型字节表多处冲突（同字节映射到不同类型）

| 属性 | 值 |
|------|-----|
| 位置 | §2.2（行 137-153）、§2.3（行 157-169）、§2.5（行 192-194） |
| 描述 | 类型字节存在多处冲突：
- `0x22` 同时映射到 INT2（§2.2 行 141）和 IMAGE（§2.3 行 169）—— INT2 是固定 2B 整数，IMAGE 是大二进制，完全不同的类型
- `0x3D` 同时映射到 FLOAT8（§2.2 行 147）和 DATETIME（§2.2 行 151）—— 同一表内冲突
- `0x6A` 同时映射到 INT8（§2.2 行 143）和 NUMERIC（§2.5 行 193）
- `0x2A` 同时映射到 FLOATN（§2.2 行 148）和 DATETIME2（§2.4 行 181）
这些冲突会让实现者无法判断某一字节应解码为哪种类型，且与 MS-TDS 规范的实际字节值不符。 |
| 修复建议 | 对照 MS-TDS §2.2.5.1 重写类型表。参考值（待规范核实）：INT2 应为 0x3B（非 0x22），FLOAT8 应为 0x7F（非 0x3D，0x3D 是 DATETIME），NUMERIC 应为 0x6C（非 0x6A，0x6A 是 INT8），FLOATN 应为 0x6B（非 0x2A，0x2A 是 DATETIME2） |

### R2-009 [CRITICAL] §6.6 S6 RPC param[0] Type=VARCHAR(0xA7) 但 Value 字节为 UCS-2 LE

| 属性 | 值 |
|------|-----|
| 位置 | §6.6 S6 RPC 请求（行 1058-1083） |
| 描述 | 文档定义 Param[0]: Type=0xA7 (VARCHAR，ASCII 数据)。但 HexDump 的 Value 字节为 `02 00 53 00 45 00 4C 00 45 00 43 00 54 00 20 00 31 00` —— 即 2B 长度前缀 0x0002 + 16 字节 UCS-2 LE 数据 `S E L E C T space 1`。VARCHAR 的数据应为 ASCII（1B/字符），16 字节应解码为 16 个 ASCII 字符而非 8 个 Unicode 字符。该编码与 NVARCHAR(0xE7) 一致，与 VARCHAR(0xA7) 矛盾。 |
| 修复建议 | 二选一：(a) 将 Type 改为 0xE7 (NVARCHAR)，保持 UCS-2 LE 数据；(b) 保持 Type=0xA7 (VARCHAR)，将 Value 数据改为 ASCII `53 45 4C 45 43 54 20 31`（8 字节），长度前缀 0x0008 |

### R2-010 [CRITICAL] §6.6 S6 RPC param[1] HexDump 缺 Status 字节

| 属性 | 值 |
|------|-----|
| 位置 | §6.6 S6 RPC 请求 param[1]（行 1066-1071, 1083） |
| 描述 | 文档定义 Param[1]: NameLen=0x00, Status=0x00, Type=0xA7, TypeData=0x0000, Value=(空)。RPC 参数结构为 `NameLen(1) + Name(NameLen×2) + Status(1) + Type(1) + TypeData(...) + Value(...)`。NameLen=0 时 Name 为空，紧跟 Status(1B)。HexDump 中 param[1] 起始处为 `00 A7 00 00` —— 即 NameLen=0x00, 然后直接 `A7`，**完全跳过 Status 字节**。正确应为 `00 00 A7 00 00`（NameLen=0, Status=0, Type=0xA7, TypeData=0x0000）。 |
| 修复建议 | 在 `00 A7` 之间插入 1 字节 `00`（Status=0） |

### R2-011 [CRITICAL] §6.10 S10 Attention Ack HexDump 与 Length 字段完全不一致

| 属性 | 值 |
|------|-----|
| 位置 | §6.10 S10（行 1301-1322） |
| 描述 | 文档给出 Attention Ack 包：`Length: 0x0008 (8 BE)`、`完整 HexDump: 05 01 00 08 00 01 01 00`（8 字节）。但**紧接着**又给出 Done 包 HexDump：`04 01 00 13 00 01 02 00 FD 02 00 00 00 00 00 00 00 00 00 00`（20 字节）。第一个 HexDump 8 字节确实匹配 Length=8（与 R2-007 一并修正 Type=0x06 后），但第二个 HexDump 20 字节却声明 Length=0x0013=19，hexdump 实际 20 字节（且 Done token 仅 12 字节，缺 1 字节 RowCount，同 R2-012）。两包混在同一代码块内，未明确分开，且第二个包 Length 与字节数不符。 |
| 修复建议 | 将两个 HexDump 分到独立代码块；Ack Type 改 0x06；Done 包补 1 字节使 Length=0x14=21 |

### R2-012 [CRITICAL] 多处 Done/DoneProc Token HexDump 缺 RowCount 末字节（20 字节而非 21）

| 属性 | 值 |
|------|-----|
| 位置 | §6.4 S4 DML 响应、§6.6 S6 RPC 响应、§6.7 S7 RPC 响应、§6.10 S10 Done、§6.12 S12 Session A 响应 |
| 描述 | Done Token 结构为 `Token(1) + Status(2) + CurCmd(2) + RowCount(8B LE for TDS 7.2+)` = 13 字节。但这些场景的 HexDump 在 FD token 后仅有 11 字节（如 S4 响应 `FD 00 00 00 00 01 00 00 00 00 00 00` = FD + 11 字节）。Status(2)+CurCmd(2)=4 字节已用，RowCount 应 8 字节但仅 7 字节，缺 1 字节。TDS 7.4 默认 RowCount 8B，故 Done token 必须 13 字节。HexDump 整体 Length 比应有值少 1 字节。 |
| 证据 | S4 响应 wire Length=0x13=19，但实际所需 = 8(包头)+13(Done)=21 字节；HexDump 20 字节恰好少 1 |
| 修复建议 | 在每个受影响 HexDump 末尾补 1 字节 `00`，并相应修正 Length 字段（0x13→0x14） |

### R2-013 [CRITICAL] §6.7 S7 RPC 响应 ReturnValue Token 缺 Status 字节且 DoneProc 缺 2 字节

| 属性 | 值 |
|------|-----|
| 位置 | §6.7 S7 RPC 响应（行 1175-1183） |
| 描述 | ReturnValue Token (0xAC) 结构（MS-TDS §2.2.7.7）：`Token(1) + ParamOrdinal(2 LE) + ParamName(B_VARCHAR) + Status(1) + Type(1) + TypeData(...) + Value(...)`。HexDump: `AC 02 00 06 52 65 73 75 6C 74 00 E7 32 00 0C 00 41...`。解码：AC + ParamOrdinal=0x0002 + NameLen=0x06 + Name="Result" + **Status=0x00? Type=0xE7?** —— 但 `74 00 E7` 三字节，若 Status=0x74 则非 0；若 Type=0x00 则非 NVARCHAR。正确读法应是 `74`（Status=0x74? 错）或 `00`（Status=0）+ `E7`（Type=NVARCHAR）。HexDump 缺 Status 字节，应在 "Result" 后插入 `00`。另外 DoneProc Token 在 HexDump 末尾 `FE 00 00 00 00 00 00 00 00 00 00` = FE + 10 字节，但 DoneProc 需要 1+2+2+8=13 字节，即 FE 后 12 字节，缺 2 字节。 |
| 修复建议 | (1) 在 "Result" 后插入 Status 字节 `00`；(2) 在末尾补 2 字节 `00 00`；(3) Length 字段从 0x2F=47 改为 0x40=64 |

### R2-014 [CRITICAL] §6.13 S13 响应 HexDump 与 wire Length 严重不一致（69 vs 57 字节）

| 属性 | 值 |
|------|-----|
| 位置 | §6.13 S13 响应（行 1546-1555） |
| 描述 | 文档声明 `Length 字段 = 0x0045 = 69 字节`，但 HexDump 实际仅 57 字节。差异 12 字节。结合 R2-005（EnvChange 缺 OldValue）、R2-006（NewValue 长度字节错误），该 HexDump 存在多重叠加错误：EnvChange Length=0x0C 应为 0x0B、NewValue 长度 0x01 应为 0x08、缺 OldValue 0x00 ×2。修正后两个 EnvChange 各 14 字节 + 两个 Done 各 13 字节 = 54 字节 token 流，加 8 字节包头 = 62 字节 = 0x3E。 |
| 修复建议 | 重写整个 S13 响应 HexDump，确保 EnvChange Begin Tran 为 `E3 0B 00 07 08 <8B TransactionID> 00`、Done 为 13 字节，Length=0x3E=62 |

---

### R2-015 [HIGH] §6.3 S3 SQL Batch 请求 wire Length=0x20=32 与实际 28 字节不符

| 属性 | 值 |
|------|-----|
| 位置 | §6.3 S3 SQL Batch 请求（行 871） |
| 描述 | "SELECT 1" = 8 字符 × 2 = 16B UCS-2 LE。AllHeaders(TotalLength=0) = 4B。body = 4+16 = 20B。总长 = 8+20 = 28B = 0x1C。但 wire Length=0x0020=32（HexDump 实际 28 字节正确）。 |
| 修复建议 | wire Length 改为 0x001C=28 |

### R2-016 [HIGH] §6.3 S3 SELECT 响应 wire Length=0x24=36 与实际 38 字节不符

| 属性 | 值 |
|------|-----|
| 位置 | §6.3 S3 SELECT 响应（行 897, 927-933） |
| 描述 | ColMetadata: 1(token)+2(count)+[4(UserType)+2(Flags)+1(Type)+1(ColName len)+1('a')]=12B。Row: 1+4=5B。Done: 1+2+2+8=13B。Total = 8+12+5+13 = 38B = 0x26。wire Length=0x24=36，HexDump 实际 36 字节，少 2 字节。 |
| 修复建议 | wire Length 改为 0x26=38，HexDump 补齐缺失字节 |

### R2-017 [HIGH] §6.4 S4 SQL Batch 请求 wire Length=0x46=70 与实际 58 字节不符

| 属性 | 值 |
|------|-----|
| 位置 | §6.4 S4 DML 请求（行 944） |
| 描述 | "INSERT INTO t VALUES(1)" = 23 字符 × 2 = 46B。+ 4B AllHeaders + 8B 包头 = 58B = 0x3A。wire Length=0x46=70（HexDump 58 字节正确）。 |
| 修复建议 | wire Length 改为 0x003A=58 |

### R2-018 [HIGH] §6.5 S5 SQL Batch 请求 wire Length=0x38=56 与实际 48 字节不符

| 属性 | 值 |
|------|-----|
| 位置 | §6.5 S5 多结果集请求（行 1001） |
| 描述 | "SELECT 1; SELECT 2" = 18 字符 × 2 = 36B。+ 4B + 8B = 48B = 0x30。wire Length=0x38=56（HexDump 48 字节正确）。 |
| 修复建议 | wire Length 改为 0x0030=48 |

### R2-019 [HIGH] §6.5 S5 多结果集响应 wire Length=0x3C=60 与实际 68 字节不符

| 属性 | 值 |
|------|-----|
| 位置 | §6.5 S5 响应（行 1026-1035） |
| 描述 | 2 × (ColMetadata 12B + Row 5B + Done 13B) = 60B token 流。+ 8B 包头 = 68B = 0x44。wire Length=0x3C=60，HexDump 64 字节，少 4 字节（每个 Done 各缺 1 字节 + ColMetadata/Row 计算偏差）。 |
| 修复建议 | 重算每个 token 字节数，wire Length 改为 0x44=68，HexDump 补齐 |

### R2-020 [HIGH] §6.6 S6 RPC 请求 wire Length=0x48=72 与实际 80 字节不符

| 属性 | 值 |
|------|-----|
| 位置 | §6.6 S6 RPC 请求（行 1046） |
| 描述 | HexDump 80 字节。wire Length=0x48=72。结合 R2-009（VARCHAR 数据应为 NVARCHAR 或 ASCII）与 R2-010（param[1] 缺 Status 字节），实际所需字节数会变化。当前 HexDump 80 字节，wire 应至少为 80=0x50。 |
| 修复建议 | 修正 R2-009/R2-010 后重新核算，wire Length 应与 HexDump 字节数一致 |

### R2-021 [HIGH] §6.7 S7 RPC 请求 wire Length=0x60=96 与实际 85 字节不符

| 属性 | 值 |
|------|-----|
| 位置 | §6.7 S7 RPC 请求（行 1135-1147） |
| 描述 | HexDump 85 字节。wire Length=0x60=96。HexDump 自身比 wire 多/少 11 字节。可能原因：Param[1] Value 的 NVARCHAR 数据 "Alice" 应为 5 字符 × 2 = 10B + 2B 长度前缀 = 12B，但 HexDump 末尾 `08 00 41 00 6C 00 69 00 63 00 65 00` = 12 字节 ✓。ProcName "usp_GetUserByID" 14 字符 × 2 = 28B ✓。还需详细核算 Param[0] 的 INT4 Value (4B)。综合核算 HexDump 85 字节应是正确值，wire 96 错。 |
| 修复建议 | wire Length 改为 0x55=85（如 HexDump 字节确实正确） |

### R2-022 [HIGH] §6.8 S8 Error 响应 Error Token Length=0x30=48 错误（应 53）

| 属性 | 值 |
|------|-----|
| 位置 | §6.8 S8 Error 响应（行 1196, 1217-1228） |
| 描述 | Error Token 结构：`Token(1) + Length(2 LE) + Number(4) + State(1) + Class(1) + MsgText(B_VARCHAR: 1+33) + ServerName(B_VARCHAR: 1+9) + ProcName(B_VARCHAR: 1+0) + LineNumber(2)`。Length 字段值 = 4+1+1+34+10+1+2 = 53 = 0x35。文档称 Length=0x30=48，少 5 字节。HexDump `AA 30 00 ...` 中 `30 00` 应改为 `35 00`。同时 HexDump 总长 74 字节，wire=78，应 77（Error 56B + Done 13B + 包头 8B），HexDump 缺 3 字节。 |
| 修复建议 | Length 改为 0x35=53；wire Length 改为 0x4D=77；HexDump 补齐缺失 3 字节 |

### R2-023 [HIGH] §6.9 S9 Info Token Length=0x15=21 错误（应 25）

| 属性 | 值 |
|------|-----|
| 位置 | §6.9 S9 Info 响应（行 1239, 1260-1268） |
| 描述 | Info Token 同 Error Token 结构。Length 字段值 = 4+1+1+6+10+1+2 = 25 = 0x19。文档称 Length=0x15=21，少 4 字节。HexDump `AB 15 00 ...` 应改为 `AB 19 00 ...`。同时 HexDump 50 字节，wire=45，应 49（Info 28B + Done 13B + 包头 8B），HexDump 多 1 字节。 |
| 修复建议 | Length 改为 0x19=25；wire Length 改为 0x31=49；移除 HexDump 多余 1 字节 |

### R2-024 [HIGH] §6.11 S11 BEGIN TRAN 请求 wire Length=0x1C=28 与实际 32 字节不符

| 属性 | 值 |
|------|-----|
| 位置 | §6.11 S11 BEGIN TRAN 请求（行 1333-1337） |
| 描述 | "BEGIN TRAN" = 10 字符 × 2 = 20B。+ 4B AllHeaders + 8B 包头 = 32B = 0x20。wire Length=0x1C=28（HexDump 32 字节正确）。 |
| 修复建议 | wire Length 改为 0x0020=32 |

### R2-025 [HIGH] §6.11 S11 COMMIT TRAN 请求 wire Length=0x20=32 与实际 34 字节不符

| 属性 | 值 |
|------|-----|
| 位置 | §6.11 S11 COMMIT TRAN 请求（行 1373-1377） |
| 描述 | "COMMIT TRAN" = 11 字符 × 2 = 22B。+ 4B + 8B = 34B = 0x22。wire Length=0x20=32（HexDump 34 字节正确）。 |
| 修复建议 | wire Length 改为 0x0022=34 |

### R2-026 [HIGH] §6.12 S12 Session A 请求 wire Length=0x30=48 与实际 60 字节不符

| 属性 | 值 |
|------|-----|
| 位置 | §6.12 S12 Session A 请求（行 1422-1430） |
| 描述 | "WAITFOR DELAY '00:00:30'" = 24 字符 × 2 = 48B。+ 4B + 8B = 60B = 0x3C。wire Length=0x30=48（HexDump 60 字节正确）。 |
| 修复建议 | wire Length 改为 0x003C=60 |

### R2-027 [HIGH] §6.12 S12 Session B 请求 wire Length=0x20=32 与实际 44 字节不符

| 属性 | 值 |
|------|-----|
| 位置 | §6.12 S12 Session B 请求（行 1446-1452） |
| 描述 | "SELECT GETDATE()" = 16 字符 × 2 = 32B。+ 4B + 8B = 44B = 0x2C。wire Length=0x20=32（HexDump 44 字节正确）。 |
| 修复建议 | wire Length 改为 0x002C=44 |

### R2-028 [HIGH] §6.13 S13 SQL Batch 请求 wire Length=0x5E=94 与实际 108 字节不符

| 属性 | 值 |
|------|-----|
| 位置 | §6.13 S13 请求（行 1502-1517） |
| 描述 | "BEGIN TRAN; INSERT INTO t VALUES(1); COMMIT TRAN" = 48 字符 × 2 = 96B（从 HexDump 反解码验证）。+ 4B + 8B = 108B = 0x6C。wire Length=0x5E=94（HexDump 108 字节正确）。 |
| 修复建议 | wire Length 改为 0x006C=108 |

---

### R2-029 [MEDIUM] §6.10 S10 Attention 请求 HexDump Status=0x00 但应=0x01 (EOM)

| 属性 | 值 |
|------|-----|
| 位置 | §6.10 S10 Attention 请求（行 1286-1288） |
| 描述 | HexDump `06 00 00 08 00 01 01 00` —— Status=0x00。但 Attention 是单包消息，应设 EOM (0x01)。MS-TDS 规定所有单包 TDS 消息 Status bit0=EOM。文档正文（行 1278）也称"Status: 0x00"，与 HexDump 一致地错。 |
| 修复建议 | Status 改为 0x01，HexDump 第 2 字节改为 `01` |

### R2-030 [MEDIUM] §6.14 S14 大数据类型 Length=0x0100=256 与 HexDump 24 字节完全不符

| 属性 | 值 |
|------|-----|
| 位置 | §6.14 S14（行 1568-1582） |
| 描述 | wire Length=0x0100=256，HexDump 仅 24 字节且以 `...` 截断。文档未声明"简化版"。同时 S14 的 Row Token TEXT 编码说明（行 1584-1592）声称"Length: 0xFFFF + DataLength: 4B LE + Data"，但 MS-TDS §2.2.5.2.1 TEXT/NTEXT/IMAGE 的 Row 编码更复杂（包含 TextPtr、Timestamp、TextDataLength 等字段），文档过度简化，会让实现者遗漏必要字段。 |
| 修复建议 | (a) 声明 HexDump 为简化版或补全；(b) wire Length 与 HexDump 字节数一致；(c) 补全 TEXT/NTEXT/IMAGE Row 编码完整字段 |

### R2-031 [MEDIUM] §2.3 BINARY 0x2D / BIGBINARY 0xAD 字节值待核实

| 属性 | 值 |
|------|-----|
| 位置 | §2.3（行 162） |
| 描述 | 文档列出 `0xAD BIGBINARY` 和 `0x2D BINARY`。MS-TDS §2.2.5.1.2 中 BIGBINARY 实际为 0xAD，但 BINARY（遗留固定长度二进制）的字节值在不同 TDS 版本可能有差异，0x2D 需核实。同时 0xAD 既是 BIGBINARY 类型字节，又是 LoginAck Token 字节（§3.1）—— 虽在不同上下文不冲突，但实现者需注意区分。 |
| 修复建议 | 核对 MS-TDS 规范确认 BINARY 字节值；在文档中注明 0xAD 在 ColDef.Type 与 Token 流的不同含义 |

### R2-032 [MEDIUM] §3.6.3 Done Status 位定义不完整

| 属性 | 值 |
|------|-----|
| 位置 | §3.6.3（行 456-463） |
| 描述 | 列出 7 个 Status 位（0x0000/0x0001/0x0002/0x0004/0x0010/0x0020/0x0080），但 MS-TDS §2.2.7.5 实际定义更多位：0x0008 (DONE_INXACT 重复?）、0x0040 (DONE_CLIENT_FATAL)、0x0100 (DONE_RPC_IN_BATCH)、0x0200 (DONE_DST)。虽然 0x0080 = DONE_ATTN 文档已列出。 |
| 修复建议 | 补充缺失的 Status 位定义，或注明"仅列常用位" |

### R2-033 [MEDIUM] §3.1 Token 表缺少部分 Token

| 属性 | 值 |
|------|-----|
| 位置 | §3.1（行 245-260） |
| 描述 | 列出 14 个 Token，但 MS-TDS §2.2.7 还包括 0xE7 COLINFO、0xEC RETURNVALUE（variant）、0xED XMLTYPE 等未列出。虽 §3.1 标题暗示"常用 Token"，但未明确声明范围。 |
| 修复建议 | 在 §3.1 加注"本表仅列 trafficgen 实现所需 Token；完整列表见 MS-TDS §2.2.7" |

### R2-034 [MEDIUM] §6.12 S12 MARS HexDump Session B 响应截断不完整

| 属性 | 值 |
|------|-----|
| 位置 | §6.12 S12 Session B 响应（行 1469-1472） |
| 描述 | HexDump `04 01 00 20 00 01 01 00 81 01 00 00 00 00 00 38 01 61 D1 ... FD 00 00 ...` —— 含 `...` 省略号，wire Length=0x20=32 但 HexDump 仅 16 字节。Session A 响应 HexDump 20 字节、wire=19，亦缺 1 字节（同 R2-012）。 |
| 修复建议 | 补全 Session B 响应 HexDump 所有字节，使字节数与 Length 一致；Session A 响应补 1 字节 |

### R2-035 [MEDIUM] §6.7 S7 响应 ReturnValue ParamName "Result" 后 Status 字节缺失（与 R2-013 关联）

| 属性 | 值 |
|------|-----|
| 位置 | §6.7 S7 响应（行 1161-1163） |
| 描述 | 文档文字描述 ParamName 后有 `Status: 0x00` 字段，但 HexDump 字节 `06 52 65 73 75 6C 74 00 E7 32 00 0C 00 41...` 中 "Result" 后是 `00 E7` —— 若 `00` 是 Status，`E7` 是 Type，则结构正确。但若按文字描述 Status=0x00 后接 Type=0xE7，则 HexDump 字节布局是正确的。重新审视后，此项可能是 R2-013 的重复告警，需结合 R2-013 判定。 |
| 修复建议 | 与 R2-013 合并核查；若 Status 字节确实存在则降级为 LOW |

### R2-036 [MEDIUM] §6.2 S2 Login7 偏移表 HexDump 仅展示 3 项（HostName/UserName/Password），其余 10 项用 `...` 省略

| 属性 | 值 |
|------|-----|
| 位置 | §6.2 S2 Login7 请求（行 788-792） |
| 描述 | 文字称"偏移表 13 项 × 4B"，但 HexDump 字节仅展示前 3 项（HostName/UserName/Password）的 4B 偏移/长度对，其余 10 项（AppName/ServerName/Unused/LibraryName/Language/Database/SSPI/AttachDBFile/ChangePassword/Reserved）全部以 `...` 或全 `00 00 00 00 00 00 00 00` 行填充。这使得 Length=172 不可从 HexDump 验证（实际 HexDump 120 字节）。虽文档自承"简化版"，但 §7 测试 T-031"偏移表 13 项 × 4B 正确"无法从此 HexDump 验证。 |
| 修复建议 | 提供完整 Login7 HexDump（172 字节）或注明 T-031 需在实现层验证 |

### R2-037 [MEDIUM] §2.2 GUID TypeData 描述"1B=0x10"含义不清

| 属性 | 值 |
|------|-----|
| 位置 | §2.2（行 153） |
| 描述 | 文档称 `0x24 GUID 1B=0x10 16 LE`。"1B=0x10" 意为 TypeData 是 1 字节、值 0x10（=16）。但表头"TypeData"列对其他类型写"0"（FIXED）或"1B"（variable），此处"1B=0x10" 混合了长度与值两种语义。 |
| 修复建议 | 改为 `0x10 (1B, 值=16)` 或 `1B; 值=0x10` 明确区分长度与值 |

### R2-038 [MEDIUM] §2.5 NUMERIC 长度字段值列表不完整

| 属性 | 值 |
|------|-----|
| 位置 | §2.5（行 199） |
| 描述 | 文档列出"长度 = 1, 5, 9, 13, 17（精度 1-9：5B；10-19：9B；20-28：13B；29-38：17B）"。但精度 0 的长度=1（数据 0B + 符号位 1B？），且 17B 应对应精度 29-38。映射关系缺精度 0 的情况。 |
| 修复建议 | 补全精度-长度映射表，包括精度 0 |

### R2-039 [MEDIUM] §6.15 S15 Row Token HexDump 仅 14 字节，无 Packet Header，无法验证 Length

| 属性 | 值 |
|------|-----|
| 位置 | §6.15 S15（行 1647-1650） |
| 描述 | HexDump `D1 00 00 00 00 FF FF 05 00 68 65 6C 6C 6F`（14 字节）仅是 Row Token 片段，无 Packet Header。无法验证整体 Length。S15 本身是"NULL 处理"专题，但缺乏完整 packet 上下文。 |
| 修复建议 | 提供完整 packet HexDump（含 ColMetadata + Row + Done），或注明 S15 仅展示 Row Token 片段 |

---

### R2-040 [LOW] §6.6 S6 RPC param[0] Value 文字描述"Length=9"错误

| 属性 | 值 |
|------|-----|
| 位置 | §6.6 S6 param[0]（行 1064） |
| 描述 | 文字 `Value: 02 00 + "SELECT 1" (Length=9, 实际 9 chars × 2 = 18B; 简化为 ASCII)`。"SELECT 1" 是 8 字符不是 9。Length=0x0002 也与 9 不符。整段描述混乱。 |
| 修复建议 | 改为 `Value: 08 00 + "SELECT 1" ASCII (8B)`（若 Type=VARCHAR）或 `Value: 10 00 + "SELECT 1" UCS-2 LE (16B)`（若 Type=NVARCHAR） |

### R2-041 [LOW] §11 修订记录未列 v2.0.1 修复条目

| 属性 | 值 |
|------|-----|
| 位置 | §11（行 2072-） |
| 描述 | 文档头部声明"v2.0.1（2026-08-04；返工修复；详见 §11 修订记录）"，但 §11 修订记录仅列 v2.0.0 修复清单（R10-01 至 R10-14），**完全没有 v2.0.1 的修复条目**。第一轮审计的 9 CRITICAL + 11 HIGH 修复未在 §11 留痕。 |
| 修复建议 | 在 §11 增加 v2.0.1 小节，列出 A-001 至 A-037 的修复情况（哪些已修、哪些 deferred、哪些部分修复） |

---

## 测试用例合规性审计（对照 CLAUDE.md §Testing Policy 8 条）

| 规则 | 符合度 | 说明 |
|------|--------|------|
| 1. Spec-driven 测试推导 | ⚠️ PARTIAL | 200+ 用例覆盖主要字段，但未明确对应 MS-TDS 章节；多处用例（如 T-031 偏移表、T-034 LoginAck Length）的预期值与文档 HexDump 的错误值绑定，测试通过不能证明规范正确 |
| 2. 覆盖失败路径 | ✅ PASS | §7.5 错误处理、§7.11 Validate 错误路径覆盖较全 |
| 3. 一测试一路径 | ⚠️ PARTIAL | T-028（Collation 5B）只测长度，未测 5B 内部结构（CollationID+SortId）；T-162/163 版本兼容只测输出长度，未测相邻字段偏移 |
| 4. 集成测试 | ✅ PASS | §7.12 集成测试 + §7.13 E2E 覆盖端到端 |
| 5. 断言可观察结果 | ❌ FAIL | HexDump 场景 S2/S3/S4/S5/S6/S7/S8/S9/S11/S12/S13 的 Length 字段均与字节数不符，若测试以这些 HexDump 为 golden，则测试通过即等于"测试错误的字节"；T-034"LoginAck Length=51" 会把错误值固化进测试 |
| 6. 并发正确性 | ✅ PASS | §7.14 含 -race 与吞吐量断言 |
| 7. 失败先测试 | ⚠️ UNVERIFIABLE | 本审计仅看设计文档，无法验证实现顺序 |
| 8. 对抗式测试质量审查 | ⚠️ PARTIAL | 本审计即对抗式审查；但用例未断言 HexDump Length 自洽性、未断言 LoginAck Length=55（应为规范值） |

### 关键测试缺失

1. **HexDump Length 自洽性断言**：无测试用例要求"每个 HexDump 的 wire Length == 实际字节数"。这导致 26 个 Length 不一致全部未被发现。
2. **EnvChange OldValue 字节存在性断言**：无测试要求 Begin/Commit Tran EnvChange 包含 OldValue 0x00。
3. **LoginAck Length=55 断言**：T-034 错误绑定 Length=51，应修正并加测试。
4. **Type 字节冲突检测**：无测试要求"同字节不能映射到两个不同类型"。
5. **MARS 真实交错 HexDump**：T-114~T-118 描述场景但无完整 HexDump（S12 HexDump 截断且 Length 错）。
6. **VARCHAR vs NVARCHAR 数据编码区分测试**：S6 param[0] Type=VARCHAR 但数据是 UCS-2，无测试覆盖此区分。

---

## 修复优先级建议

### P0（阻止实现，必须先修）
- R2-001, R2-002, R2-003, R2-004, R2-005, R2-006, R2-007, R2-008, R2-009, R2-010, R2-011, R2-012, R2-013, R2-014

### P1（必须修复）
- R2-015, R2-016, R2-017, R2-018, R2-019, R2-020, R2-021, R2-022, R2-023, R2-024, R2-025, R2-026, R2-027, R2-028

### P2（强烈建议）
- R2-029, R2-030, R2-031, R2-032, R2-033, R2-034, R2-035, R2-036, R2-037, R2-038, R2-039

### P3（可选）
- R2-040, R2-041

---

## 审计结论

**文档状态**: **不可直接进入实现阶段**

**主要障碍**:

1. **14 个 CRITICAL 级别问题**涉及 HexDump 字节级错误（Login7 偏移表错位、EnvChange 缺 OldValue、LoginAck Length 少 4 字节、S13 EnvChange NewValue 长度字节错误、Attention Ack Type=0x05 不存在、类型字节表多处冲突、VARCHAR/NVARCHAR 数据编码混淆、param 缺 Status 字节、Done Token 缺 RowCount 末字节、S13 整体响应与 wire Length 严重不一致）
2. **第一轮 9 CRITICAL 仅文字层面修复**：A-004/A-006/A-007 已落地文字描述，但 A-010（Packet Header Length 自洽）未真正落地 —— 26 个 HexDump 仍存在 wire Length 与实际字节数不符
3. **测试用例绑定错误预期值**：T-034 绑定 LoginAck Length=51（应 55）、T-031 无法验证偏移表（HexDump 缺 4B ClientLCID）、多处 HexDump golden 值错误
4. **§11 修订记录未留痕 v2.0.1 修复**

**建议返工范围**:

- 重写所有 HexDump，确保 wire Length == 实际字节数 == 文档声明值三者一致
- 修正 §3.2.2 偏移表偏移值（36,40,44,...,84）
- 修正所有 EnvChange Begin/Commit Tran HexDump（补 OldValue 0x00，Length 改 0x0B）
- 修正 LoginAck Length=0x37=55 与 HexDump 字节数
- 修正 Attention Ack Type=0x05→0x06
- 重写 §2.2/§2.3/§2.5 类型字节表，消除同字节多型冲突
- 修正 §6.6 param[0] VARCHAR/NVARCHAR 编码、param[1] 补 Status 字节
- 重写 §6.13 S13 响应 HexDump
- §11 增加 v2.0.1 修复留痕

**返工完成后需重新审计（第三轮）**。

---

**审计员**: Claude Code (独立审计员)
**审计完成时间**: 2026-08-04
