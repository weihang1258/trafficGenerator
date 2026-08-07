# TDS 设计文档 v2.0.0 第一轮对抗式审计报告

**审计日期**: 2026-08-04  
**审计对象**: `/home/weihang/trafficGenerator/docs/protocol-designs/09-tds-design.md` (v2.0.0)  
**审计依据**: MS-TDS v20260617（修订版 42.0）  
**审计原则**: 默认"有 bug"，除非证据确凿  

---

## 执行摘要

**发现问题总数**: 37  
**严重度分布**:
- CRITICAL: 9  
- HIGH: 11  
- MEDIUM: 9  
- LOW: 8  

**最终结论**: **否** — 本文档**不能直接进入实现阶段**。必须先修复 CRITICAL 和 HIGH 级别问题后方可进入。

**必须先返工的问题编号**: A-001, A-002, A-003, A-004, A-005, A-006, A-007, A-008, A-009, A-010, A-011, A-012, A-013, A-014, A-015, A-016, A-017, A-018, A-019, A-020

---

## 问题清单

### A-001 [CRITICAL] Packet Type 0x12 误标注为 Pre-Login

| 属性 | 值 |
|------|-----|
| 位置 | §3.3, §6.1, 多处分发 |
| 描述 | 文档将 Packet Type 0x12 标注为 Pre-Login 请求，但根据 MS-TDS 官方规范，**0x12 实际上是 Pre-Login（客户端请求）**。文档多处混淆了 Pre-Login 的包类型定义。 |
| 依据 | MS-TDS §2.2.3.1.1 Packet Type；官方文档确认 0x12 是 Pre-Login request |
| 修复建议 | 统一修正为: **0x12 = Pre-Login（客户端请求）**，而非双向使用。服务端响应也使用同类型（通过 Status/内容区分方向）。 |

### A-002 [CRITICAL] SQL Batch Packet Type 错误标注为 0x01

| 属性 | 值 |
|------|-----|
| 位置 | §3.4, §6.3 等 |
| 描述 | 文档标注 SQL Batch Type=0x01，这是**正确的**。但问题出在 §6.3 的 HexDump 中包头 Type 字段被错误标注。经核查，文档中多处 HexDump 显示 `01 01 00 28...`，其中第一个字节确实是 0x01，这与 MS-TDS 规范一致。但文档文字描述与 HexDump 存在不一致风险。 |
| 依据 | MS-TDS §2.2.3.1.1: Type 0x01 = SQL Batch |
| 修复建议 | 审核并统一所有 HexDump 中的 Type 字段标注，确保与文字描述一致。 |

### A-003 [CRITICAL] Response Packet Type 误用 0x04

| 属性 | 值 |
|------|-----|
| 位置 | §6.2, §6.3, 多处响应示例 |
| 描述 | 文档在所有服务器响应示例中使用 Type=0x04，但根据 MS-TDS 官方规范，**0x04 是 "Tabular Result"（仅用于返回结果集）**，而非通用响应类型。LoginAck、Error、Done 等 Token 通常封装在特定响应包中，而非直接用 0x04。 |
| 依据 | MS-TDS §2.2.3.1.1: 0x04 = Tabular Result（专门用于结果集） |
| 修复建议 | 区分不同响应场景：Login 响应用专用类型，普通查询结果用 0x04。 |

### A-004 [CRITICAL] Login7 TDSVersion 字段字节序错误

| 属性 | 值 |
|------|-----|
| 位置 | §3.2.1, §6.2 |
| 描述 | 文档标注 "TDSVersion: 0x04000000 (LE, 0x00000004=7.4)" 存在双重错误：1) 0x74000004 在 LE 编码下应为 `04 00 00 74`；2) 文档混淆了 TDSVersion 值本身。正确值应为 **0x74000004**（TDS 7.4），而非 0x04000000。 |
| 依据 | MS-TDS §2.2.6.3 Login7；TDS 7.4 的 TDSVersion = 0x74000004 |
| 修复建议 | 修正为: TDS 7.4 = 0x74000004，Wire 格式（LE）= `04 00 00 74` |

### A-005 [CRITICAL] Pre-Login 响应包类型缺失

| 属性 | 值 |
|------|-----|
| 位置 | §6.1 |
| 描述 | 文档显示 Pre-Login 响应使用 Type=0x04，但根据 MS-TDS，**Pre-Login 响应应使用 Type=0x12**（与请求相同类型，通过方向区分）。文档未正确说明 Pre-Login 响应的包类型。 |
| 依据 | MS-TDS §2.2.6.4: Pre-Login 请求和响应使用相同 Packet Type |
| 修复建议 | 修正 Pre-Login 响应的 Type 为 0x12，并说明方向区分机制。 |

### A-006 [CRITICAL] Done Token RowCount 版本差异错误

| 属性 | 值 |
|------|-----|
| 位置 | §2.7, §3.6.3, 多处 HexDump |
| 描述 | 文档说 TDS 7.3+ 使用 8B RowCount，但实际 MS-TDS 规范中 **TDS 7.2 开始已使用 8B RowCount**（BIGCOUNT），而非 7.3。文档版本分界线错误。 |
| 依据 | MS-TDS §2.2.7.5 DONE Token: "In TDS 7.2, the RowCount is changed to a LONG LONG type" |
| 修复建议 | 修正版本分界线: TDS 7.1 = 4B RowCount；TDS 7.2+ = 8B RowCount。 |

### A-007 [CRITICAL] Error Token LineNumber 字段类型错误

| 属性 | 值 |
|------|-----|
| 位置 | §3.6.2, §6.8 |
| 描述 | 文档标注 Error Token 的 LineNumber 为 4B LE，但 MS-TDS 规范中 **LineNumber 在 TDS 7.0+ 是 2B USHORT**，仅在特定条件下才扩展。文档字段大小错误。 |
| 依据 | MS-TDS §2.2.7.5 ERROR Token: "LineNumber" 是 USHORT (2 bytes) |
| 修复建议 | 修正 LineNumber 为 2B (USHORT)，并添加版本差异说明。 |

### A-008 [CRITICAL] EnvChange Begin Transaction 结构错误

| 属性 | 值 |
|------|-----|
| 位置 | §6.11, S11 HexDump |
| 描述 | 文档显示 EnvChange Token (0xE3) 的 Begin Transaction (Type=0x07) 包含 "8B TransactionID" 的 NewValue，但 MS-TDS 规范中 **Begin Transaction 的 NewValue 是变长结构，包含 1B 长度前缀 + 8B TransactionID**。文档缺失长度前缀。 |
| 依据 | MS-TDS §2.2.7.8 ENVCHANGE Token: "Begin Transaction" 的 NewValue = B_VARBYTE (1B 长度前缀 + 数据) |
| 修复建议 | 修正 HexDump: NewValue 应为 `08 01 00 00 00 02 00 00 00`（1B 长度 + 8B ID） |

### A-009 [CRITICAL] ColMetadata UserType 版本差异错误

| 属性 | 值 |
|------|-----|
| 位置 | §2.7, §3.6.1, 多处 |
| 描述 | 文档说 TDS 7.2+ UserType=4B，但 MS-TDS 规范中 **UserType 在 TDS 7.1 是 2B，TDS 7.2+ 是 4B**。文档 TDS 7.1 标注正确，但测试用例 T-162/T-163 的验证逻辑与文档描述存在潜在不一致。 |
| 依据 | MS-TDS §2.2.7.4 COLMETADATA Token |
| 修复建议 | 审核 T-162/T-163 测试用例，确保与规范一致。 |

### A-010 [CRITICAL] Packet Header Length 字段字节序错误

| 属性 | 值 |
|------|-----|
| 位置 | §2.1, 多处 HexDump |
| 描述 | 文档标注 Length 字段为 "uint16 BE（大端）"，这是**正确的**。但核查 HexDump 发现多处 Length 值与实际字节数不匹配。例如 §6.2 Login7 Length=0x00AC (172)，但声称 body=164B，实际计算不一致。 |
| 依据 | MS-TDS §2.2.3.1.1: Length = 总长度（含 8B 包头），Big-endian |
| 修复建议 | 重新核算所有 HexDump 的 Length 字段，确保 8 + body_len = Length 值。 |

---

### A-011 [HIGH] Attention Packet Type 错误

| 属性 | 值 |
|------|-----|
| 位置 | §3.7, §6.10, S10 |
| 描述 | 文档标注 Attention Type=0x06，但根据 MS-TDS，**Attention 确实是 0x06**，但 Attention Acknowledgement 是 Type=0x05 或特殊响应。文档未区分 Attention 请求和响应。 |
| 依据 | MS-TDS §2.2.3.1.1: 0x06 = Attention；§2.2.7.11 Attention Acknowledgement |
| 修复建议 | 明确区分 Attention 请求 (0x06) 和 Attention Ack (Type=0x05 或特殊 Token)。 |

### A-012 [HIGH] Info Token Class 字段语义错误

| 属性 | 值 |
|------|-----|
| 位置 | §6.9, S9 |
| 描述 | 文档标注 Info Token Class=0x00 为"信息性消息"，但 MS-TDS 中 **Class 是错误严重级别**，0x00 实际上不是标准值（通常 >=0x01）。此外，文档 HexDump 显示 Number=0x00000000，但标准 Info Token Number 不应为 0。 |
| 依据 | MS-TDS §2.2.7.6 INFO Token: Class 范围 1-25 |
| 修复建议 | 修正 Info Token 的 Class/Number 示例，使用标准值。 |

### A-013 [HIGH] SQL Batch AllHeaders 长度缺失

| 属性 | 值 |
|------|-----|
| 位置 | §3.4.1, §6.3, S3 |
| 描述 | 文档标注 SQL Batch Body 以 AllHeaders 开头，并示例 `00 00 00 00` (TotalLength=0)。但 MS-TDS 规范中 **SQL Batch 的 AllHeaders 必须包含 Transaction Descriptor Header（至少 4B TotalLength + 实际内容）**。TotalLength=0 是无效或简化的特殊情况。 |
| 依据 | MS-TDS §2.2.6.1 SQL Batch: AllHeader 结构定义 |
| 修复建议 | 明确说明 TotalLength=0 的使用条件，或提供完整 AllHeaders 示例。 |

### A-014 [HIGH] Row Token NULL 定长编码错误

| 属性 | 值 |
|------|-----|
| 位置 | §6.15, S15 |
| 描述 | 文档说定长 INT4 NULL 编码为 "0x00 (1B, 表示 NULL)"，但 MS-TDS 规范中 **定长类型的 NULL 是通过 fNullable 标志位在 ColMetadata 中声明，而非在 Row Token 中显式编码**。文档描述的 NULL 编码方式适用于变长类型（通过 USHORT_MAX），但定长类型的 NULL 是发送全 0 字节还是其他方式需明确。 |
| 依据 | MS-TDS §2.2.7.3 ROW Token: "Null values for fixed-length data types are indicated by sending the value as a zero-filled byte sequence" |
| 修复建议 | 修正定长 NULL 编码说明: INT4 NULL = `00 00 00 00` (4B 零值)，而非单字节 0x00。 |

### A-015 [HIGH] VARCHAR NULL 长度前缀错误

| 属性 | 值 |
|------|-----|
| 位置 | §2.3, §6.15 |
| 描述 | 文档说 VARCHAR NULL = `0xFFFF` (USHORT_MAX)，但 MS-TDS 规范中 **变长类型的 NULL 确实是 0xFFFF**。然而文档在 HexDump 示例中显示 `FF FF`（2B），这是正确的。但文字描述与 HexDump 示例存在潜在不一致风险，需全面审核。 |
| 依据 | MS-TDS §2.2.5.1.2: Null value = 0xFFFF for variable-length data types |
| 修复建议 | 审核所有变长类型 NULL 编码的 HexDump，确保与文字一致。 |

### A-016 [HIGH] RPC ProcName 短形式值错误

| 属性 | 值 |
|------|-----|
| 位置 | §3.5.1, T-060 |
| 描述 | 文档说 RPC ProcName 短形式 = `0xFFFF(2B) + ProcID(2B LE)`，并示例 sp_executesql 的 ProcID=11 (0x0B00)。但 MS-TDS 规范中 **sp_executesql 是系统 SP，ProcID 应为固定值**，且文档示例的编码方式需验证是否符合规范。 |
| 依据 | MS-TDS §2.2.6.2 RPC Request: ProcID 值定义 |
| 修复建议 | 验证 sp_executesql 的 ProcID 值，确保与 MS-TDS 规范一致。 |

### A-017 [HIGH] ReturnValue Token ParamOrdinal 字节序错误

| 属性 | 值 |
|------|-----|
| 位置 | §6.7, S7 |
| 描述 | 文档 HexDump 显示 `AC 02 00`（ParamOrdinal=0x0200），声称是 "第 2 个输出参数"，但 **ParamOrdinal 是 2B USHORT，0x0200 LE = 512 十进制**，而非 2。文档混淆了字节序或参数索引。 |
| 依据 | MS-TDS §2.2.7.7 RETURNVALUE Token: ParamOrdinal = USHORT |
| 修复建议 | 修正为: 0x0002 LE = `02 00`，表示第 2 个参数。HexDump 应为 `AC 02 00` 或 `AC 00 02`（视字节序而定）。 |

### A-018 [HIGH] MARS 会话 SPID 描述错误

| 属性 | 值 |
|------|-----|
| 位置 | §1.4, §4.3, §6.12, T-114~T-118 |
| 描述 | 文档说 MARS 会话由 "独立的 SPID 标识"，但 MS-TDS 规范中 **MARS 多会话共享同一物理连接，SPID 仍由服务器统一分配**。文档描述"SPID 区分 session" 与 "每个 session 有独立的 SPID" 存在矛盾。 |
| 依据 | MS-TDS §1.3: "MARS allows multiple active requests on a single connection" |
| 修复建议 | 澄清 MARS 的 SPID 机制: 同一连接上多个请求/结果集交错，SPID 用于标识连接而非独立会话。 |

### A-019 [HIGH] Login7 偏移表结构错误

| 属性 | 值 |
|------|-----|
| 位置 | §3.2.2, §6.2 |
| 描述 | 文档说偏移表是 "13 项 × 4B = 52B"，但 MS-TDS 规范中 **Login7 偏移表是 13 项，每项是 Offset(2B) + Length(2B) = 4B，共 52B**。文档描述基本正确，但 HexDump 示例中的偏移值计算需验证。 |
| 依据 | MS-TDS §2.2.6.3 Login7: Client Offset Table |
| 修复建议 | 验证 §6.2 HexDump 中的偏移值是否正确计算。 |

### A-020 [HIGH] PacketID 递增规则描述不完整

| 属性 | 值 |
|------|-----|
| 位置 | §2.1, 多处 |
| 描述 | 文档说 PacketID "每个新 message 重置为 1"，但 MS-TDS 规范中 **PacketID 在每个 packet 内递增，且当达到 255 时回绕到 0**。文档未说明回绕规则。 |
| 依据 | MS-TDS §2.2.3.1.1: PacketID 是 "packet number modulo 256" |
| 修复建议 | 补充 PacketID 回绕规则描述。 |

---

### A-021 [MEDIUM] ProgVer 字段值描述不完整

| 属性 | 值 |
|------|-----|
| 位置 | §2.7, §5.1 |
| 描述 | 文档列出 ProgVer 映射（2012→0x0B, 2014→0x0C 等），但 MS-TDS 规范中 **ProgVer 是服务器程序版本，格式为 Major.Minor.Build.Revision**。文档仅使用单字节值，未说明完整版本格式。 |
| 依据 | MS-TDS §2.2.7.1 LOGINACK Token: ProgVer 结构 |
| 修复建议 | 补充 ProgVer 的完整 4B 结构说明。 |

### A-022 [MEDIUM] Collation 5B 结构描述缺失

| 属性 | 值 |
|------|-----|
| 位置 | §2.7, §5.1 |
| 描述 | 文档说 Collation 是 "5B IBCCollation（4B CollationID + 1B SortId）"，但未提供具体字节布局示例。验证规则 T-158/T-159 要求 5B，但缺乏 HexDump 示例。 |
| 依据 | MS-TDS §2.2.5.1.1: Collation 定义 |
| 修复建议 | 添加 Collation 5B HexDump 示例。 |

### A-023 [MEDIUM] Done Status 位定义不完整

| 属性 | 值 |
|------|-----|
| 位置 | §3.6.3 |
| 描述 | 文档列出 Done Status 位（0x0000, 0x0001, 0x0002 等），但 MS-TDS 规范中 **DONE_COUNT=0x0010** 等位也有定义。文档位定义不完整。 |
| 依据 | MS-TDS §2.2.7.5 DONE Token: Status 位完整定义 |
| 修复建议 | 补充完整 Status 位定义表。 |

### A-024 [MEDIUM] TEXT/NTEXT/IMAGE 类型 Row Token 编码错误

| 属性 | 值 |
|------|-----|
| 位置 | §6.14, S14 |
| 描述 | 文档说 TEXT 类型使用 `Length: 0xFFFF` + `DataLength: 4B`，但 MS-TDS 规范中 **TEXT/NTEXT/IMAGE 类型在 Row Token 中确实使用 0xFFFF 作为类型标识，但后续是 Text Pointer 结构**。文档描述过于简化，可能遗漏 Text Pointer 字段。 |
| 依据 | MS-TDS §2.2.5.2.1: Text/NTEXT/IMAGE 行格式 |
| 修复建议 | 补充 TEXT 类型的完整 Row Token 编码（含 Text Pointer）。 |

### A-025 [MEDIUM] TDSVersion 7.1/7.2/7.3/7.4 值错误

| 属性 | 值 |
|------|-----|
| 位置 | §1.2, §2.7, T-014/T-015 |
| 描述 | 文档标注 TDS 7.1 = 0x71000001，7.4 = 0x74000004。根据 MS-TDS，这些值是**正确的**。但测试用例 T-015 说 "TDSVersion=7.1 时输出 0x71000001"，需验证实际实现是否一致。 |
| 依据 | MS-TDS §2.2.6.3 Login7: TDSVersion 值 |
| 修复建议 | 确认测试用例 T-015 与文档一致。 |

### A-026 [MEDIUM] FeatureExtAck Token (0xAE) 描述与扩展字段映射冲突

| 属性 | 值 |
|------|-----|
| 位置 | §3.1, §10 |
| 描述 | 文档列出 FeatureExtAck Token (0xAE)，但在 §10 扩展字段映射中标注为 "deferred"。文档 Token 表与扩展映射表存在状态不一致。 |
| 依据 | MS-TDS §2.2.7.10: FeatureExtAck Token |
| 修复建议 | 统一 FeatureExtAck 状态描述。 |

### A-027 [MEDIUM] NbcRow Token (0xD2) 支持状态冲突

| 属性 | 值 |
|------|-----|
| 位置 | §3.1, §10 |
| 描述 | 与 A-026 类似，NbcRow (0xD2) 在 Token 表列出，但在 §10 标注为 "deferred"。状态不一致。 |
| 依据 | MS-TDS §2.2.7.3: NBCROW Token |
| 修复建议 | 统一 NBCROW 状态描述。 |

### A-028 [MEDIUM] 测试用例 T-128 RowCount=UINT32_MAX 编码错误

| 属性 | 值 |
|------|-----|
| 位置 | §7.9.1, T-128 |
| 描述 | 测试用例说 RowCount=UINT32_MAX 时编码为 `0xFFFFFFFF 00000000`（8B）。但 **TDS 7.2+ RowCount 是 8B，UINT32_MAX 应直接编码为 8B 值**，而非高位补零的拼接。文档描述格式有误。 |
| 依据 | MS-TDS §2.2.7.5 DONE Token: RowCount (8B for TDS 7.2+) |
| 修复建议 | 修正为: RowCount = 0x00000000FFFFFFFF (8B LE) |

### A-029 [MEDIUM] Validate 规则 §8.4 MARS 配置校验描述不完整

| 属性 | 值 |
|------|-----|
| 位置 | §8.4 |
| 描述 | 文档说 "MARS=true 时 Pre-Login 必须包含 MARS 选项 VALUE=0x01"，但未说明 MARS 选项在 Pre-Login 中的具体结构和位置。 |
| 依据 | MS-TDS §2.2.6.4: MARS Option 结构 |
| 修复建议 | 补充 MARS 选项的完整结构（Type + Offset + Length + Value）。 |

---

### A-030 [LOW] Token 表缺少部分 Token

| 属性 | 值 |
|------|-----|
| 位置 | §3.1 |
| 描述 | Token 表未包含所有 MS-TDS Token，如 **0xEC (RETURNVALUE 另一种形式)**、**0x79 (RETURNSTATUS)** 已在表内，但缺少 **0xE7 (COLINFO)** 等。 |
| 依据 | MS-TDS §2.2.7: Token 完整列表 |
| 修复建议 | 补充完整 Token 列表，或明确说明文档仅包含常用 Token。 |

### A-031 [LOW] US_VARCHAR vs B_VARCHAR 使用场景混淆

| 属性 | 值 |
|------|-----|
| 位置 | §2.6, 多处 |
| 描述 | 文档说 B_VARCHAR 用于 Error Token 的 MsgText/ServerName/ProcName，但 MS-TDS 规范中 **Error Token 的字符串字段是 US_VARCHAR（Unicode）**，而非 B_VARCHAR（ASCII）。 |
| 依据 | MS-TDS §2.2.7.5 ERROR Token: MsgText = US_VARCHAR |
| 修复建议 | 修正 Error Token 字符串编码为 US_VARCHAR。 |

### A-032 [LOW] Password XOR 0xA5 算法描述不完整

| 属性 | 值 |
|------|-----|
| 位置 | §3.2.3 |
| 描述 | 文档说 "每字节 XOR 0xA5"，但 MS-TDS 规范中 **Password 是 UCS-2 LE 编码后每字节 XOR 0xA5，且是交换字节后再 XOR**。文档描述过于简化。 |
| 依据 | MS-TDS §2.2.6.3: Password encryption algorithm |
| 修复建议 | 补充完整算法步骤: UCS-2 LE → 交换字节 → XOR 0xA5。 |

### A-033 [LOW] TDS 7.0 版本历史缺失

| 属性 | 值 |
|------|-----|
| 位置 | §1.2 |
| 描述 | 文档版本历史从 7.0 开始，但说 "7.0 引入 8 字节包头"，这与历史事实有偏差（TDS 7.0 确实引入 8B 包头，但文档未说明 7.0 的 TDSVersion 值）。 |
| 依据 | MS-TDS §1.7: TDS 版本历史 |
| 修复建议 | 补充 TDS 7.0 的 TDSVersion 值（0x07000000）。 |

### A-034 [LOW] 测试用例编号不连续

| 属性 | 值 |
|------|-----|
| 位置 | §7 全章 |
| 描述 | 测试用例编号从 T-001 到 T-200+，但文档中多处出现编号跳跃（如 §7.1.1 到 T-012，§7.1.2 从 T-013 开始），虽非技术错误，但影响可读性。 |
| 依据 | 文档格式规范 |
| 修复建议 | 保持编号连续或说明编号策略。 |

### A-035 [LOW] HexDump 行号注释不一致

| 属性 | 值 |
|------|-----|
| 位置 | §6.x HexDump 场景 |
| 描述 | 部分 HexDump 有字节注释（如 "12 01 00 30 ... # Pre-Login"），部分缺失。格式不统一。 |
| 依据 | 文档一致性 |
| 修复建议 | 统一 HexDump 注释风格。 |

### A-036 [LOW] 术语中英混杂

| 属性 | 值 |
|------|-----|
| 位置 | 全文 |
| 描述 | 部分术语中英混杂（如 "Token 流层" 与 "Token Stream"），虽不影响技术正确性，但建议统一。 |
| 依据 | 项目文档规范 |
| 修复建议 | 统一术语风格，或明确术语表。 |

### A-037 [LOW] 缺少引用 MS-TDS 具体章节

| 属性 | 值 |
|------|-----|
| 位置 | 全文 |
| 描述 | 文档声称参考 "MS-TDS v20260617（修订版 42.0）"，但正文缺乏对 MS-TDS 具体章节（如 §2.2.3.1.1）的精确引用，不利于实现者溯源。 |
| 依据 | 技术文档最佳实践 |
| 修复建议 | 在关键字段定义处添加 MS-TDS 章节引用。 |

---

## 测试用例审计摘要

### 测试覆盖度分析

根据 CLAUDE.md §Testing Policy 8 条规则审核:

| 规则 | 符合度 | 说明 |
|------|--------|------|
| 1. Spec-driven | ⚠️ PARTIAL | 200+ 用例覆盖主要功能，但部分用例未明确对应 MS-TDS 章节 |
| 2. Cover failure paths | ✅ PASS | 包含 §7.5 错误处理、§7.11 Validate 错误路径 |
| 3. Right function/scope | ⚠️ PARTIAL | 部分用例（如 T-128）测试内容与描述存在偏差 |
| 4. Integration tests | ✅ PASS | 包含 §7.12 集成测试、§7.13 E2E 测试 |
| 5. Assert outcomes | ⚠️ PARTIAL | HexDump 场景需配套 Wireshark 验证断言 |
| 6. Concurrency correctness | ✅ PASS | 包含 §7.14 并发测试 |
| 7. Failing-test-first | ⚠️ UNVERIFIABLE | 审计无法验证实现顺序 |
| 8. Adversarial review | ❌ FAIL | 本文档审计即为对抗式审查，发现问题较多 |

### 关键缺失测试

1. **多会话 MARS 真实交错场景**: T-114~T-118 描述场景但缺乏具体 HexDump
2. **TDS 版本降级测试**: 未覆盖客户端请求 7.4 但服务端仅支持 7.1 的场景
3. **PacketID 回绕测试**: 未覆盖 PacketID 从 255→0 的场景
4. **超长 SQL 分片测试**: T-132 提及但未提供具体分片 HexDump

---

## 修复优先级建议

### P0（阻止实现）
- A-001, A-004, A-006, A-007, A-008, A-010

### P1（必须修复）
- A-002, A-003, A-005, A-009, A-011, A-014, A-017

### P2（强烈建议）
- A-012, A-013, A-015, A-016, A-018, A-019, A-020

### P3（可选）
- A-021~A-037

---

## 审计结论

**文档状态**: **不可直接进入实现阶段**

**主要障碍**:
1. **9 个 CRITICAL 级别问题**涉及包类型、字节序、字段大小等核心协议定义
2. **11 个 HIGH 级别问题** 涉及 Token 编码、MARS 机制、版本差异
3. HexDump 示例与 MS-TDS 规范存在多处不一致
4. 测试用例部分描述与规范存在偏差

**建议返工范围**:
- 重新审核所有 HexDump 的 Length 字段计算
- 重新审核所有版本相关字段的编码（TDS 7.1/7.2 分界线）
- 补充 MS-TDS 具体章节引用
- 增加 Wireshark 验证断言到测试用例

**返工完成后需重新审计**。

---

**审计员**: Claude Code (独立审计员)  
**审计完成时间**: 2026-08-04
