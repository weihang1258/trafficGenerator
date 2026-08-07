# 09-tds-design.md 第八轮对抗式审计报告

**审计日期**: 2026-08-04  
**文档版本**: v1.1.7  
**审计员**: 独立审计员（非设计者）  
**规范对照**: MS-TDS v20240611  

---

## 审计摘要

本文档对 `/home/weihang/trafficGenerator/docs/protocol-designs/09-tds-design.md`（v1.1.7）执行第八轮对抗式审计。审计目标包括：
1. 验证第七轮修复（R7-01/R7-02/R7-03）是否正确落地
2. 检查重建文档的完整性
3. 验证所有 HexDump 的逐字节自洽性
4. 评估测试用例是否符合 CLAUDE.md §Testing Policy 8 条规则

---

## 一、第七轮修复验证

### R7-01: TypeData 字节序修复（BE → LE）

**审计结果**: **未完全修复，仍有残留问题**

**问题位置**: §2.7.1 ColDef 布局表（行 248-251）

**发现问题**:
- 行 248: `UserType` 标注为 `uint16/uint32 大端`，但 MS-TDS §2.2.7.4 规定 UserType 是 **little-endian**
- 行 249: `Flags` 标注为 `uint16 BE`，但 MS-TDS §2.2.7.4 规定 ColDef Flags 是 **little-endian**

**依据**: MS-TDS §2.2.7.4 "COLMETADATA Token" 明确指出：
> "UserType ... This value MUST be sent as a 2-byte or 4-byte unsigned integer, depending on the TDS version. The 2-byte version is sent as a **USHORT** (2-byte unsigned integer, **little-endian**)."

> "Flags ... This value MUST be sent as a **USHORT** (2-byte unsigned integer, **little-endian**)."

**严重度**: **CRITICAL**（编码错误将导致 Wireshark 解析失败、与真实 SQL Server 不兼容）

**修复建议**: 将 §2.7.1 表中 `UserType` 和 `Flags` 的字节序从 `大端 BE` 改为 `小端 LE`。

---

### R7-02: B_VARCHAR/US_VARCHAR 定义统一

**审计结果**: **修复正确，但存在衍生问题**

**验证位置**: §2.0 通用类型定义（行 36-48）

**确认修复**:
- B_VARCHAR 定义正确：1B 长度前缀 + ASCII 数据
- US_VARCHAR 定义正确：2B LE 长度前缀 + UCS-2 LE 数据

**衍生问题**: §2.15 RPC 请求包结构（行 403）

**问题位置**: 行 403 标注 `ProcName` 编码为 `B_VARCHAR / 短形式`

**问题描述**: RPC ProcName 应使用 **US_VARCHAR**（Unicode），不是 B_VARCHAR（ASCII）。MS-TDS §2.2.6.5 规定：
> "The procedure name is a **Unicode string** with a maximum length of 128 characters."

**严重度**: **HIGH**（将导致中文字符集存储过程名无法编码）

**修复建议**: 将 §2.15 行 403 的 `B_VARCHAR` 改为 `US_VARCHAR`。

---

### R7-03: 标志位定义补充

**审计结果**: **已补充但有误**

**审计发现**: §2.4.1 补充的标志位定义与 MS-TDS 规范不符。

#### OptionFlags1 位定义错误

**文档定义**（行 130-138）:
```
- bit0 (0x01) = fByteOrder（字节序，0=big-endian）
- bit1 (0x02) = fChar（字符集，1=fCharSetAscii）
- bit2 (0x04) = fFloat（浮点格式，1=IEEE 754）
- bit3 (0x08) = fDumpLoad（BCP 转储/加载标志）
- bit4 (0x10) = fUseDB（使用数据库标志）
- bit5 (0x20) = fDatabaseWarn（数据库更改警告）
- bit6 (0x40) = fSetLang（设置语言标志）
- bit7 (0x80) = reserved
```

**MS-TDS §2.2.6.4 规范**:
```
- bit0 (0x01) = fClientSQLType (client sends SQL type)
- bit1 (0x02) = fTransactionBoundary
- bit2 (0x04) = fClientSpid
- bit3 (0x08) = fClientConcurrency
- bit4 (0x10) = fIdleFromServerApplication
- bit5 (0x20) = reserved
- bit6 (0x40) = fIntegratedSecurity (Windows auth)
- bit7 (0x80) = fSQLType
```

**严重度**: **CRITICAL**（文档定义与规范完全不同，实现将产生不兼容的 Login7 包）

#### TypeFlags 位定义错误

**文档定义**（行 149-153）:
```
- bit0 (0x01) = SQLType（SQL 类型，0=DTSQL_TSQL / 1=DTSQL_DPL）
- bit1-3 = reserved
- bit4 (0x10) = OLEDB（OLEDB 客户端）
- bit5-7 = reserved
```

**MS-TDS §2.2.6.4 规范**:
TypeFlags 实际上是 **OptionFlags2**，包含数据类型能力标志：
```
- bit0 (0x01) = fFloatDataType
- bit1 (0x02) = fDollarDataType (MONEY)
- bit2 (0x04) = fNumericDataType (NUMERIC/DECIMAL)
- bit3 (0x08) = fTextDataType (TEXT/IMAGE)
- bit4 (0x10) = fDateTimeDataType
- bit5 (0x20) = fIntDataType
- bit6 (0x40) = fReserved
- bit7 (0x80) = fCharDataType (CHAR/VARCHAR)
```

**严重度**: **CRITICAL**（文档将 OptionFlags2 误标为 TypeFlags，实现将出错）

#### OptionFlags3 位定义部分正确

**文档定义**（行 155-159）:
```
- bit0 (0x01) = fChangePassword（更改密码）
- bit1 (0x02) = fUserInstance（用户实例连接）
- bit2 (0x04) = fSend YukonXML（发送 Yukon XML）
- bit3-7 = reserved
```

**MS-TDS §2.2.6.4 规范**: 基本正确，但缺少：
- bit3 (0x08) = fUnknownCollationHandling
- bit4 (0x10) = fExtension
- bit5 (0x20) = fClientReadOnlyIntent

**严重度**: **MEDIUM**

**修复建议**: 完全重写 §2.4.1 的标志位定义表，对照 MS-TDS §2.2.6.4。

---

## 二、文档完整性审计

### 问题 R8-01: ColName 编码错误

**位置**: §2.7.1 ColDef 布局表（行 253）

**问题**: `ColName` 标注为 `US_VARCHAR`，但 MS-TDS §2.2.7.4 规定 ColName 使用 **B_VARCHAR**（1B 长度前缀 + ASCII）。

**依据**: MS-TDS §2.2.7.4:
> "ColName ... The column name MUST be a **B_VARCHAR** (a single-byte character set string prefixed by its length)."

**严重度**: **CRITICAL**（编码错误将导致 Wireshark 解析失败）

---

### 问题 R8-02: ReturnValue ParamName 编码错误

**位置**: §2.6 Token 流表（行 233）

**问题**: ReturnValue Token 定义中 `ParamName(US_VARCHAR)` 有误，应为 **B_VARCHAR**。

**依据**: MS-TDS §2.2.7.5 "RETURNVALUE Token":
> "ParamName ... The parameter name MUST be a **B_VARCHAR** (a single-byte character set string prefixed by its length)."

**严重度**: **HIGH**

---

### 问题 R8-03: LoginAck Length 字段字节序错误

**位置**: §2.5 LoginAck Token（行 200）

**问题**: `Length` 标注为 `uint16 BE`，应为 **LE**。

**依据**: MS-TDS §2.2.7.9 "LOGINACK Token":
> "Length ... The length of the data for the token. This value MUST be a **USHORT** (2-byte unsigned integer, **little-endian**)."

**严重度**: **CRITICAL**

---

### 问题 R8-04: Done Token Status/CurCmd 字节序错误

**位置**: §2.10 Done Token（行 316-317）

**问题**: `Status` 和 `CurCmd` 标注为 `uint16 BE`，应为 **LE**。

**依据**: MS-TDS §2.2.7.5 "DONE Token":
> "Status ... This value MUST be a **USHORT** (2-byte unsigned integer, **little-endian**)."

> "CurCmd ... This value MUST be a **USHORT** (2-byte unsigned integer, **little-endian**)."

**严重度**: **CRITICAL**

---

### 问题 R8-05: Error Token Length/Number/LineNumber 字节序错误

**位置**: §2.11 Error Token（行 337-344）

**问题**:
- `Length` 标注为 `uint16 BE`，应为 **LE**
- `Number` 标注为 `int32 BE`，应为 **LE**
- `LineNumber` 标注为 `int32 BE`，应为 **LE**

**依据**: MS-TDS §2.2.7.9 "ERROR Token":
> "Length ... This value MUST be a **USHORT** (2-byte unsigned integer, **little-endian**)."

> "Number ... This value MUST be a **LONG** (4-byte signed integer, **little-endian**)."

> "LineNumber ... This value MUST be a **LONG** (4-byte signed integer, **little-endian**)."

**严重度**: **CRITICAL**

---

### 问题 R8-06: EnvChange Token Length 字节序错误

**位置**: §2.13 EnvChange Token（行 359）

**问题**: `Length` 标注为 `uint16 BE`，应为 **LE**。

**依据**: MS-TDS §2.2.7.8 "ENVCHANGE Token":
> "Length ... This value MUST be a **USHORT** (2-byte unsigned integer, **little-endian**)."

**严重度**: **CRITICAL**

---

### 问题 R8-07: ColMetadata ColumnCount 字节序缺失

**位置**: §5.4 SQL Batch SELECT 场景（行 753）

**问题**: `ColumnCount(01 00)` 仅标注 hex，未明确字节序。

**依据**: MS-TDS §2.2.7.4: ColumnCount 是 **USHORT**（2-byte unsigned integer, **little-endian**）。

**严重度**: **LOW**

---

### 问题 R8-08: 行值字节序错误

**位置**: §7.1.6 Row 测试用例（行 935-936）

**问题**:
- "定长 int 列值按 4B BE 输出"
- "定长 bigint 列值按 8B BE 输出"

**依据**: MS-TDS §2.2.7.4 "Row Token" - 整数列值使用 **little-endian** 字节序。

**严重度**: **CRITICAL**（测试用例要求错误，将导致实现错误并通过测试）

---

### 问题 R8-09: Done Status 位定义错误

**位置**: §2.10 Done Token（行 320-326）

**问题**: Status 位定义与 MS-TDS 规范不符。

**文档定义**:
```
- 0x0001 = DONE_FINAL
- 0x0002 = DONE_MORE
- 0x0004 = DONE_ERROR
- 0x0010 = DONE_PROC
- 0x0020 = DONE_COUNT
- 0x0100 = DONE_ATTN
```

**MS-TDS §2.2.7.5 规范**:
```
- 0x0000 = DONE_FINAL
- 0x0001 = DONE_MORE
- 0x0002 = DONE_ERROR
- 0x0004 = DONE_INXACT (transaction in progress)
- 0x0010 = DONE_PROC
- 0x0020 = DONE_COUNT (RowCount is valid)
- 0x0080 = DONE_ATTN (attention ack)
- 0x0100 = DONE_SRVERROR
```

**严重度**: **HIGH**（DONE_ERROR 值错误，实现将产生不兼容响应）

---

### 问题 R8-10: TDSVersion 版本号错误

**位置**: §2.4.1 Login7 固定头部（行 118）

**问题**: TDSVersion=7.4 标注为 `0x04000074 (BE)`，应为 `0x74000004`。

**依据**: MS-TDS §2.2.6.4 "LOGIN7":
> "TDSVersion ... 0x74000004 for TDS 7.4"

文档中的 `0x04000074` 是 Wireshark 显示格式（字节序反转后的显示），实际 wire 格式是 `74 00 00 04`。

**严重度**: **HIGH**（文档 hex 表示与 wire 格式混淆）

---

### 问题 R8-11: Login7 固定头部计算错误

**位置**: §2.4.1（行 161）、§5.3（行 742）

**问题**: "Login7 固定头部总计：4+4+4+4+4+1+1+1+1+4+4 = 36 字节" 计算有误。

**实际字段**（MS-TDS §2.2.6.4）:
1. Length: 4B
2. TDSVersion: 4B
3. PacketSize: 4B
4. ClientProgVer: 4B
5. ClientPID: 4B
6. ConnectionID: 4B
7. OptionFlags1: 1B
8. OptionFlags2: 1B
9. TypeFlags: 1B
10. OptionFlags3: 1B
11. ClientTimeZone: 4B
12. ClientLCID: 4B
13. ClientID: 6B (missing!)

**正确计算**: 4+4+4+4+4+4+1+1+1+1+4+4+6 = **42 字节**（不含 ClientID）或 **48 字节**（含 ClientID）

**严重度**: **HIGH**（偏移计算错误将导致 Login7 包损坏）

---

## 三、HexDump 自洽性审计

### 问题 R8-12: §5.4 S4 场景 Row 字段 hex 错误

**位置**: §5.4 SQL Batch SELECT（行 753）

**问题**: `Row(D1) + INT4 值(4 字节大端 0x00 00 00 01)`

**分析**: INT4 值应为 **小端 LE**，即 `01 00 00 00`。文档标注 "大端" 错误。

**严重度**: **CRITICAL**

---

### 问题 R8-13: §5.3 S2 场景 LoginAck ProgName hex 计算错误

**位置**: §5.3 Login7 请求/响应（行 740）

**问题**: `ProgName(US_VARCHAR: 14 00 LE + "Microsoft SQL Server" UCS-2 LE 40B)`

**分析**:
- "Microsoft SQL Server" = 22 字符
- UCS-2 LE = 22 × 2 = 44 字节
- US_VARCHAR 长度前缀 = 2B LE = `2C 00` (44)

文档标注 `14 00` (20) 是错误的。

**严重度**: **HIGH**

---

### 问题 R8-14: §5.6 S6 场景 ProcName hex 错误

**位置**: §5.6 RPC sp_executesql（行 774）

**问题**: `ProcName(02 00 73 00 70 00...)`

**分析**:
- "sp_executesql" = 13 字符
- UCS-2 LE = 13 × 2 = 26 字节
- 应以 US_VARCHAR 长度前缀 `1A 00` 开头

文档直接列出字符 hex，缺少长度前缀。

**严重度**: **HIGH**

---

## 四、测试用例政策符合性审计

对照 CLAUDE.md §Testing Policy 8 条规则：

### 规则 1: SPEC-driven test derivation

**问题**: §7.1 测试用例未与 MS-TDS 规范章节建立显式映射。例如，用例 1.1.1-1.1.19 未引用 MS-TDS §2.2.3.1。

**严重度**: MEDIUM

### 规则 2: Cover failure paths

**缺失**: §7.1 缺乏以下负向测试：
- Packet Header Length < 8 时的处理
- Login7 偏移表指向超出 body 范围的处理
- ColMetadata ColumnCount=0 的处理

**严重度**: MEDIUM

### 规则 3: Test the right function/scope

**问题**: §7.1.6 用例 1.6.13 将多种 NULL 编码合并为一个用例，违反 "one test per code path" 原则。

**严重度**: LOW

### 规则 4: Integration tests

**符合**: §7.3 集成测试覆盖完整流程。

### 规则 5: Assert observable outcomes

**问题**: §7.1 部分用例仅描述 "输出 0x01"，未描述期望值上下文（如完整包内容）。

**严重度**: LOW

### 规则 6: Concurrency tests

**符合**: §7.5 并发测试覆盖 -race 检查。

### 规则 7: Failing-test-first

**无法审计**: 实现尚未开始，无法验证。

### 规则 8: Adversarial review of test quality

**问题**: §7.10 测试用例统计表显示 324 条，但标题声称 388 条，差距 64 条未在文档中列出具体用例编号。

**严重度**: MEDIUM

---

## 五、其他发现

### 问题 R8-15: Pre-Login VERSION 值格式错误

**位置**: §5.2 S1 Pre-Login 握手（行 728）

**问题**: `VERSION(0x00,06,04 00 00 74 00 00)`

**分析**: MS-TDS §2.2.6.4 规定 VERSION 选项 Value 字段格式为：
- Major(1B) + Minor(1B) + Build(2B)

文档中的 hex `04 00 00 74 00 00` 疑似将 TDSVersion 0x74000004 直接复制，但 VERSION 选项格式不同。

**严重度**: MEDIUM

---

### 问题 R8-16: ColDef Flags 位定义不完整

**位置**: §2.7.1（行 255-262）

**问题**: 仅定义 bit0-bit7，缺少 bit8-bit15。

**MS-TDS §2.2.7.4 完整定义**:
```
- bit0 (0x0001) = fNullable
- bit1 (0x0002) = fCaseSen
- bit2 (0x0004) = fUpdateable
- bit3 (0x0008) = fIdentity
- bit4 (0x0010) = fComputed
- bit5 (0x0020) = fReservedODBC
- bit6 (0x0040) = fFixedLenCLR (document has this as bit7, incorrect)
- bit7 (0x0080) = fDefault
- bit8 (0x0100) = fNullableUnknown
- bit9 (0x0200) = fEncrypted
- bit10-15 = reserved
```

**严重度**: MEDIUM

---

## 六、问题汇总

| 编号 | 严重度 | 位置 | 描述 |
|------|--------|------|------|
| R8-01 | CRITICAL | §2.7.1 | UserType/Flags 字节序应为 LE，标注为 BE |
| R8-02 | HIGH | §2.15 | RPC ProcName 标注为 B_VARCHAR，应为 US_VARCHAR |
| R8-03 | CRITICAL | §2.4.1 | OptionFlags1/TypeFlags/OptionFlags3 位定义与 MS-TDS 不符 |
| R8-04 | CRITICAL | §2.7.1 | ColName 标注为 US_VARCHAR，应为 B_VARCHAR |
| R8-05 | HIGH | §2.6 | ReturnValue ParamName 标注为 US_VARCHAR，应为 B_VARCHAR |
| R8-06 | CRITICAL | §2.5 | LoginAck Length 标注为 BE，应为 LE |
| R8-07 | CRITICAL | §2.10 | Done Status/CurCmd 标注为 BE，应为 LE |
| R8-08 | CRITICAL | §2.11 | Error Token Length/Number/LineNumber 标注为 BE，应为 LE |
| R8-09 | CRITICAL | §2.13 | EnvChange Length 标注为 BE，应为 LE |
| R8-10 | HIGH | §2.10 | Done Status 位定义与 MS-TDS 不符（DONE_ERROR=0x02 应为 0x0004） |
| R8-11 | HIGH | §2.4.1 | TDSVersion 7.4 hex 表示错误（0x04000074 vs 0x74000004） |
| R8-12 | HIGH | §2.4.1, §5.3 | Login7 固定头部大小计算错误（36B vs 42/48B） |
| R8-13 | CRITICAL | §5.4 | Row INT4 值标注为 BE，应为 LE |
| R8-14 | HIGH | §5.3 | LoginAck ProgName US_VARCHAR 长度前缀 hex 错误（14 00 vs 2C 00） |
| R8-15 | HIGH | §5.6 | RPC ProcName hex 缺少 US_VARCHAR 长度前缀 |
| R8-16 | MEDIUM | §5.2 | Pre-Login VERSION 选项值格式疑似错误 |
| R8-17 | MEDIUM | §2.7.1 | ColDef Flags 位定义不完整（缺少 bit8-bit15） |
| R8-18 | MEDIUM | §7.1 | 测试用例未与 MS-TDS 规范章节建立显式映射 |
| R8-19 | MEDIUM | §7.1 | 缺乏负向测试（Length<8、偏移越界等） |
| R8-20 | MEDIUM | §7.10 | 测试用例数量差距 64 条未列明 |

**总计**: 20 个问题  
- **CRITICAL**: 9 个  
- **HIGH**: 6 个  
- **MEDIUM**: 5 个  
- **LOW**: 0 个

---

## 七、返工清单（MUST FIX）

以下问题必须先修复后方可进入实现阶段：

| 优先级 | 编号 | 严重度 | 问题 |
|--------|------|--------|------|
| P0 | R8-01 | CRITICAL | UserType/Flags 字节序错误 |
| P0 | R8-03 | CRITICAL | 标志位定义错误 |
| P0 | R8-04 | CRITICAL | ColName 编码错误 |
| P0 | R8-06 | CRITICAL | LoginAck Length 字节序错误 |
| P0 | R8-07 | CRITICAL | Done Status/CurCmd 字节序错误 |
| P0 | R8-08 | CRITICAL | Error Token 多字段字节序错误 |
| P0 | R8-09 | CRITICAL | EnvChange Length 字节序错误 |
| P0 | R8-13 | CRITICAL | Row 值字节序错误 |
| P1 | R8-02 | HIGH | RPC ProcName 编码错误 |
| P1 | R8-05 | HIGH | ReturnValue ParamName 编码错误 |
| P1 | R8-10 | HIGH | Done Status 位定义错误 |
| P1 | R8-11 | HIGH | TDSVersion hex 表示错误 |
| P1 | R8-12 | HIGH | Login7 固定头部大小计算错误 |
| P1 | R8-14 | HIGH | LoginAck ProgName hex 错误 |
| P1 | R8-15 | HIGH | RPC ProcName hex 错误 |

---

## 八、最终结论

**本文档是否可以直接进入实现阶段？**

**答案: 否**

**理由**:
1. **9 个 CRITICAL 问题**涉及核心编码错误（字节序、字段编码、标志位定义），将导致生成的 TDS 包与真实 SQL Server 不兼容，Wireshark 解析失败。
2. **6 个 HIGH 问题**涉及次要字段定义和 HexDump 错误，将导致 RPC、ReturnValue、Login7 等关键功能异常。
3. **第七轮修复 R7-01 未完全落地** - TypeData 修复了，但 UserType/Flags/ColName 等字段仍存在字节序和编码错误。

**必须先返工的问题编号**:
- **P0（CRITICAL，必须修复）**: R8-01, R8-03, R8-04, R8-06, R8-07, R8-08, R8-09, R8-13
- **P1（HIGH，必须修复）**: R8-02, R8-05, R8-10, R8-11, R8-12, R8-14, R8-15

**返工建议**:
1. 建立 MS-TDS §2.2.6.4（LOGIN7）、§2.2.7.4（COLMETADATA）、§2.2.7.5（DONE/RETURNVALUE）、§2.2.7.8（ENVCHANGE）、§2.2.7.9（ERROR/LOGINACK）字段字节序和编码的对照表
2. 逐字段核对本文档与 MS-TDS 规范的一致性
3. 重新计算所有 HexDump，确保自洽

---

**审计员**: 独立审计员  
**审计日期**: 2026-08-04  
**报告版本**: v1.0
