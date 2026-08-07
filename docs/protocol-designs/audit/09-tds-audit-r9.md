# 09-tds-design.md 第九轮对抗式审计报告

> **审计日期**: 2026-08-04
> **被审计文档**: `/home/weihang/trafficGenerator/docs/protocol-designs/09-tds-design.md` v1.1.8
> **审计员**: 独立审计员（非设计者）
> **审计方法**: 对照 MS-TDS v20240611 逐节核对，默认"有 bug"，逐条验证 R8-01~R8-20 修复落地情况

---

## 一、审计范围与策略

1. **R8 修复验证**: 逐条检查 R8-01~R8-20 是否在文档正文正确落地。
2. **全文 BE/LE 扫描**: 搜索所有 "BE" 和 "LE" 出现位置，确认无系统性字节序错误。
3. **HexDump 自洽性**: 验证所有 hex 字节序列与字段定义一致。
4. **测试用例质量**: 对照 CLAUDE.md §Testing Policy 8 条规则审查。

---

## 二、R8 修复落地验证

### 2.1 CRITICAL 修复验证（R8-01 ~ R8-09）

| 编号 | 问题 | 验证结果 | 状态 |
|------|------|----------|------|
| R8-01 | §2.7.1 ColDef UserType/Flags BE→LE | §2.7.1 第259-260行已标注 "uint16/uint32 **小端 LE**" 和 "uint16 **小端 LE**" | **PASS** |
| R8-03 | §2.4.1 OptionFlags1/TypeFlags/OptionFlags3 位定义重写 | §2.4.1 第131-162行已重写三个标志位表，但 **OptionFlags2 位定义仍标为 "OptionFlags2" 而非 "TypeFlags"**（第141行注释说 "即文档中的 TypeFlags"），且 bit 定义与 MS-TDS §2.2.6.4 的 OptionFlags2 实际定义不符——MS-TDS 中 OptionFlags2 的 bit0=fFloatDataType 等是 **OptionFlags2 本身** 的定义，不是 TypeFlags 的别名。文档将 OptionFlags2 的内容标为 "OptionFlags2 位定义（即 TypeFlags）" 存在概念混淆。 | **FAIL** → 见 R9-01 |
| R8-04 | §2.7.1 ColName US_VARCHAR→B_VARCHAR | §2.7.1 第264行已标注 **B_VARCHAR**；§2.0 第48行有对照注释 | **PASS** |
| R8-06 | §2.5 LoginAck.Length BE→LE | §2.5 第211行已标注 "uint16 LE" | **PASS** |
| R8-07 | §2.10 Done.Status/CurCmd BE→LE | §2.10 第331-332行已标注 "uint16 **LE**" | **PASS** |
| R8-08 | §2.11 Error.Length/Number/LineNumber BE→LE | §2.11 第354-355、361行已标注 "uint16 **LE**" / "int32 **LE**" | **PASS** |
| R8-09 | §2.13 EnvChange.Length BE→LE | §2.13 第376行已标注 "uint16 **LE**" | **PASS** |

**R8-03 详细分析**：

MS-TDS §2.2.6.4 中 Login7 固定头部字段顺序为：
1. Length(4B) + TDSVersion(4B) + PacketSize(4B) + ClientProgVer(4B) + ClientPID(4B) + ConnectionID(4B)
2. **OptionFlags1**(1B) + **OptionFlags2**(1B) + **TypeFlags**(1B) + **OptionFlags3**(1B)

文档第141行将 OptionFlags2 的位定义标为 "OptionFlags2 位定义（MS-TDS §2.2.6.4，即文档中的 TypeFlags）"，但所列的 bit0~bit7 定义（fFloatDataType/fDollarDataType/.../fCharDataType）实际上是 **OptionFlags2** 本身的定义，不是 TypeFlags 的定义。TypeFlags 在 MS-TDS 中是独立字段，其位定义与 OptionFlags3 的低位相关。

文档的混淆在于：
- 第141-150行的 bit 定义是正确的 **OptionFlags2** 定义，但注释说 "即文档中的 TypeFlags" 是错误的——TypeFlags 是第151-159行那个字段。
- 第151-159行的 "TypeFlags 位定义" 注释说 "实际为 OptionFlags3 的低位"，这与 MS-TDS 规范不符——TypeFlags 是独立字段，不是 OptionFlags3 的别名。

这是一个 **概念命名错误**，虽然 bit 值本身可能碰巧与某些版本一致，但字段映射关系错误会导致实现时写入错误的字节位置。

### 2.2 HIGH 修复验证（R8-10 ~ R8-15）

| 编号 | 问题 | 验证结果 | 状态 |
|------|------|----------|------|
| R8-02 | §2.15 RPC ProcName B_VARCHAR→US_VARCHAR | §2.15 第420行已标注 **US_VARCHAR** | **PASS** |
| R8-05 | §2.6 ReturnValue ParamName US_VARCHAR→B_VARCHAR | §2.6 第244行已标注 "ParamName(**B_VARCHAR**)" | **PASS** |
| R8-10 | §2.10 Done Status DONE_ERROR=0x04→0x02 | §2.10 第336-343行已修正：DONE_ERROR=0x0002 | **PASS** |
| R8-11 | §2.4.1 TDSVersion hex 0x04000074→0x74000004 | §2.4.1 第119行已标注 "0x74000004 = 7.4，小端 LE 编码为 `04 00 00 74`" | **PASS** |
| R8-12 | Login7 固定头部 36B→42B | §2.4.1 第164-171行已修正计算为42字节；§5.3 第759行重复确认 | **PASS** |
| R8-13 | §5.4 Row INT4 BE→LE | §5.4 第770行已标注 "4 字节**小端 LE** `01 00 00 00`" | **PASS** |
| R8-14 | §5.3 LoginAck ProgName 长度前缀 0x1400→0x2C00 | §5.3 第757行已标注 "2C 00 LE"；§7.1.4 第908行已修正 | **PASS** |
| R8-15 | §5.6 RPC ProcName 缺少 US_VARCHAR 长度前缀 | §5.6 第791行已添加 "`1A 00` LE 长度前缀" | **PASS** |

### 2.3 MEDIUM 修复验证（R8-16 ~ R8-20）

| 编号 | 问题 | 验证结果 | 状态 |
|------|------|----------|------|
| R8-16 | §2.7.1 ColDef Flags 位定义不完整 | §2.7.1 第266-277行已补充完整16位定义（bit0-bit9 + bit10-15 reserved） | **PASS** |
| R8-17~R8-20 | 测试用例同步修正 | §16.2 第1343-1355行已列出测试用例同步修正清单，逐项核对正文已落地 | **PASS** |

---

## 三、全文 BE/LE 系统性扫描

### 3.1 扫描方法

全文搜索 "BE" 和 "LE" 关键字，检查所有字节序标注。

### 3.2 发现的问题

#### R9-01 [CRITICAL] §2.4.1 OptionFlags2/TypeFlags/OptionFlags3 字段命名与 MS-TDS §2.2.6.4 不符

- **位置**: §2.4.1，第124-129行、第141-162行
- **描述**: 文档将 Login7 固定头部的第2个标志字节标为 "OptionFlags2"，但其位定义注释说 "即文档中的 TypeFlags"；将第3个标志字节标为 "TypeFlags"，注释说 "实际为 OptionFlags3 的低位"；将第4个标志字节标为 "OptionFlags3"，注释说 "bit0-bit7 同 TypeFlags"。这是循环定义和概念混淆。
- **依据**: MS-TDS §2.2.6.4 明确规定 Login7 固定头部字段顺序为：OptionFlags1 → OptionFlags2 → TypeFlags → OptionFlags3。四个独立字段，各有独立的位定义。
  - **OptionFlags1**: bit0=fClientSQLType, bit1=fTransactionBoundary, bit2=fClientSpid, bit3=fClientConcurrency, bit4=fIdleFromServerApplication, bit5=fReserved, bit6=fIntegratedSecurity, bit7=fSQLType
  - **OptionFlags2**: bit0=fFloatDataType, bit1=fDollarDataType, bit2=fNumericDataType, bit3=fTextDataType, bit4=fDateTimeDataType, bit5=fIntDataType, bit6=fReserved, bit7=fCharDataType
  - **TypeFlags**: bit0=fChangePassword, bit1=fUserInstance, bit2=fSendYukonXML, bit3=fUnknownCollationHandling, bit4=fExtension, bit5=fClientReadOnlyIntent, bit6-7=reserved
  - **OptionFlags3**: bit0=fRestrictedCollation, bit1=fExtension, bit2-7=reserved（TDS 7.4+）
- **文档错误**: 文档第141行将 OptionFlags2 的位定义注释为 "即文档中的 TypeFlags"，这是错误的——OptionFlags2 和 TypeFlags 是两个不同的字段。文档第160-162行将 OptionFlags3 的位定义注释为 "bit0-bit7 同 TypeFlags"，这也是错误的——OptionFlags3 有独立的位定义。
- **影响**: 实现时会将标志位写入错误的字段位置，导致 Login7 包与 SQL Server 不兼容。
- **修复建议**: 
  1. 第124-129行字段列表保持正确（OptionFlags1/OptionFlags2/TypeFlags/OptionFlags3）。
  2. 第141-150行标题改为 "**OptionFlags2** 位定义（MS-TDS §2.2.6.4）"，删除 "即文档中的 TypeFlags" 注释。
  3. 第151-159行标题改为 "**TypeFlags** 位定义（MS-TDS §2.2.6.4）"，删除 "实际为 OptionFlags3 的低位" 注释。
  4. 第160-162行标题改为 "**OptionFlags3** 位定义（MS-TDS §2.2.6.4）"，删除 "bit0-bit7 同 TypeFlags" 注释，按 MS-TDS 补充 OptionFlags3 的独立位定义。

#### R9-02 [CRITICAL] §2.1 TDS 包头 Length 和 SPID 字段标注为 BE，与 MS-TDS 规范矛盾

- **位置**: §2.1，第58-60行
- **描述**: TDS 包头中 Length(2B) 和 SPID(2B) 标注为 "uint16 BE"。但 MS-TDS §2.2.3.1 明确规定 TDS 包头所有多字节字段均为 **小端 LE**。
- **依据**: MS-TDS §2.2.3.1 Packet Header 规范："All multibyte fields in the TDS packet header are in little-endian byte order."
- **验证**: 
  - 文档 §7.1.1 用例 1.1.12: "Length=8 时第 2-3 字节 = 0x00 0x08" —— 若 BE 应为 0x08 0x00，若 LE 应为 0x00 0x08。用例输出 0x00 0x08，这是 **LE**。
  - 文档 §7.1.1 用例 1.1.14: "SPID=0 时第 4-5 字节 = 0x00 0x00" —— 无法区分 BE/LE。
  - 文档 §7.1.1 用例 1.1.15: "SPID=65535 时第 4-5 字节 = 0xFF 0xFF" —— 无法区分 BE/LE。
- **结论**: 测试用例隐含的输出是 LE，但字段定义表写的是 BE。这是 **定义与测试用例矛盾**。
- **修复建议**: §2.1 第58-59行 "uint16 BE" → "uint16 **LE**"。

#### R9-03 [CRITICAL] §2.3 Pre-Login 选项 Offset/Length 标注为 BE，与 MS-TDS 规范矛盾

- **位置**: §2.3，第94行
- **描述**: Pre-Login 选项格式标注 "Offset(2B BE) + Length(2B BE)"。MS-TDS §2.2.6.4 规定 Pre-Login 选项的 Offset 和 Length 字段为 **小端 LE**。
- **依据**: MS-TDS §2.2.6.4: "The offset and length fields are in little-endian byte order."
- **验证**: §5.2 第745行 Pre-Login VERSION 选项 hex: "07 00 04 00 00 00" —— 若 Offset=BE 则应为 0x00 0x07，若 LE 则应为 0x07 0x00。文档写 "07 00"，这是 **LE**。
- **结论**: 测试用例隐含 LE，但格式定义写 BE。定义与 hex 示例矛盾。
- **修复建议**: §2.3 第94行 "Offset(2B BE) + Length(2B BE)" → "Offset(2B **LE**) + Length(2B **LE**)"。

#### R9-04 [HIGH] §2.4.1 Login7 固定头部字段 "ClientTimeZone" 和 "ClientLCID" 字节序标注混乱

- **位置**: §2.4.1，第128-129行
- **描述**: ClientTimeZone 和 ClientLCID 标注为 "uint32 **LE**"（带加粗），但其他同类型字段（Length/TDSVersion/PacketSize/ClientProgVer/ClientPID/ConnectionID）仅标注 "uint32 LE"（无加粗）。加粗标记暗示这些字段曾被错误标注，但修正不彻底。
- **验证**: 所有 uint32 字段在 MS-TDS §2.2.6.4 中均为 LE。文档标注一致，只是格式不统一。
- **严重度降级**: 格式不统一不影响实现，但暗示文档维护质量。降为 **MEDIUM**。
- **修复建议**: 统一所有 "uint32 LE" 标注格式，删除多余的加粗标记。

#### R9-05 [HIGH] §2.4.1 Login7 固定头部总计 42 字节，但偏移表计算未更新

- **位置**: §2.4.2，第175-177行
- **描述**: §2.4.1 修正 Login7 固定头部为 42 字节（含 ClientID 6B），但 §2.4.2 偏移表说明第180行说 "相对于 Login7 body 第 0 字节（即 Length 字段首字节）的绝对字节位置"。偏移表的第一组偏移从固定头部末尾开始，固定头部 42 字节意味着第一组偏移表起始位置是 42。但文档未明确给出偏移表起始位置。
- **验证**: MS-TDS §2.2.6.4 中，Login7 固定头部后紧跟偏移表。固定头部 = 36B（不含 ClientID 的 6B 吗？）
- **深入分析**: MS-TDS §2.2.6.4 的 Login7 固定头部字段列表：
  - lLength(4) + ibTDSVersion(4) + ibPacketSize(4) + ibClientProgVer(4) + ibClientPID(4) + ibConnectionID(4) = 24B
  - fOptionFlags1(1) + fOptionFlags2(1) + fTypeFlags(1) + fOptionFlags3(1) = 4B
  - ibClientTimeZone(4) + ibClientLCID(4) = 8B
  - **bClientID(6)** = 6B
  - **总计 = 42B**
  
  然后紧跟：
  - ibHostName(4) + cchHostName(2) + ibUserName(4) + cchUserName(2) + ibPassword(4) + cchPassword(2) + ibAppName(4) + cchAppName(2) + ibServerName(4) + cchServerName(2) = 第一组 = 30B
  - ibUnused(4) + ibUnused2(4) + ibCltIntName(4) + cchCltIntName(2) + ibDatabase(4) + cchDatabase(2) + ibCollation(4) + cbCollation(1) + ibUnused3(4) = 第二组 = 25B
  
  文档 §2.4.2 说 "第一组（FixedOffset）：5 项 × 4B" 和 "第二组（VariableOffset）：5 项 × 4B"，这与 MS-TDS 的实际结构不符——每组不仅包含 4B 偏移，还包含 2B 长度字段。
- **依据**: MS-TDS §2.2.6.4 中偏移表结构为：ib(4B) + cch/cb(2B) 成对出现，不是纯 4B 数组。
- **修复建议**: 
  1. 修正 §2.4.2 描述："第一组：5 项 × (4B offset + 2B length) = HostName/UserName/Password/AppName/ServerName"
  2. 修正 §2.4.2 描述："第二组：5 项 × (4B offset + 2B length) = LibraryName/Language/Database/Collation/SSTLS"
  3. 补充偏移表总大小：第一组 30B + 第二组 25B = 55B（含 Collation 的 cb=1B）。

#### R9-06 [HIGH] §2.6 Token 流表中 Order Token 值 0xA0 与 FeatureExtAck 值 0xAA 冲突

- **位置**: §2.6，第242、246行
- **描述**: Order Token 标注为 0xA0，FeatureExtAck 标注为 0xAA。但 MS-TDS §2.2.7.10 中 Order Token 值为 **0xA0**（正确），FeatureExtAck 在 MS-TDS §2.2.6.4 中值为 **0xAE**（不是 0xAA）。
- **依据**: 
  - MS-TDS §2.2.7.10: "Token 0xA0: Order"
  - MS-TDS §2.2.6.4: "Token 0xAE: FeatureExtAck"
- **验证**: 文档第246行 FeatureExtAck 标为 0xAA，这是 **Error Token 的值**，不是 FeatureExtAck 的值。
- **修复建议**: §2.6 第246行 "0xAA | FeatureExtAck" → "**0xAE** | FeatureExtAck"。

#### R9-07 [HIGH] §2.8 Row Token NULL 编码表存在严重错误

- **位置**: §2.8，第288-291行
- **描述**: NULL 编码表说 "定长（int/bit）NULL 编码 = 1B 长度=0x00"。但 MS-TDS §2.2.7.17 规定 Row Token 中定长类型（如 INT4/BIT）**没有长度前缀**，NULL 值通过 **NbcRow Token (0xD2)** 的 NULL bitmap 表示，或者通过 ColMetadata 的 Flags.fNullable 配合。
- **依据**: MS-TDS §2.2.7.17: "For fixed-length data types, the data is returned in the actual fixed-length format." —— 定长类型在 Row Token 中直接编码，无长度前缀。NULL 定长值在标准 Row Token (0xD1) 中没有专门的 NULL 编码；NbcRow (0xD2) 才用 NULL bitmap。
- **文档矛盾**: §7.1.6 用例 1.6.7 说 "NULL int 列：1B 长度=0x00"，§7.1.6 用例 1.6.13 又说 "NULL 列（IsNull=true）时 int 输出 1B 长度=0x00 + 无字节"。这两个描述矛盾——"1B 长度=0x00" 和 "1B 长度=0x00 + 无字节" 不一致。
- **修复建议**: 
  1. §2.8 删除 "定长（int/bit）NULL 编码 = 1B 长度=0x00" 这一行。
  2. 补充说明：标准 Row Token (0xD1) 中定长类型无 NULL 编码；NULL 需通过 NbcRow (0xD2) 或应用层处理。
  3. §7.1.6 用例 1.6.7 和 1.6.13 统一为：定长类型 NULL 不支持（或需用 NbcRow）。

#### R9-08 [HIGH] §2.9 列类型表中 TIME(0x29)/DATETIME2(0x2A)/DATETIMEOFFSET(0x2B) 的 TypeData 描述错误

- **位置**: §2.9，第320-322行
- **描述**: TIME 标为 "1B+1B"，DATETIME2 标为 "1B+1B"，DATETIMEOFFSET 标为 "1B+1B"。但 MS-TDS §2.2.5.4 中这些 TDS 7.4 新类型的 TypeData 为：
  - TIME: 1B scale
  - DATETIME2: 1B scale
  - DATETIMEOFFSET: 1B scale
  都是 **1B**，不是 "1B+1B"。
- **依据**: MS-TDS §2.2.5.4: "TIME: 1-byte scale", "DATETIME2: 1-byte scale", "DATETIMEOFFSET: 1-byte scale"
- **修复建议**: 第320-322行 "1B+1B" → "1B scale"。

#### R9-09 [HIGH] §2.10 Done Token Status 位定义遗漏 DONE_SRVERROR 的值

- **位置**: §2.10，第335-343行
- **描述**: Status 位定义列出 DONE_SRVERROR=0x0100，但 MS-TDS §2.2.7.5 中还有 **0x0200 = DONE_ROWCOUNT**（在 TDS 7.4 中扩展）。文档未提及。
- **依据**: MS-TDS §2.2.7.5: "0x0100: DONE_SRVERROR", "0x0200: DONE_ROWCOUNT"
- **严重度评估**: 虽然 0x0200 是较新的扩展，但文档声称覆盖 TDS 7.4，应包含。列为 HIGH。
- **修复建议**: 补充 "0x0200 = DONE_ROWCOUNT（TDS 7.4+）"。

#### R9-10 [HIGH] §2.14 AllHeaders Transaction Descriptor Header 长度错误

- **位置**: §2.14，第408-411行
- **描述**: Transaction Descriptor Header 标注 "Length=14B"，但 MS-TDS §2.2.6.5 规定 AllHeaders 中每个 Header 的结构为：HeaderLength(4B) + HeaderType(2B) + HeaderData(variable)。Transaction Descriptor Header 的 HeaderType=0x0003，HeaderData=8B TransactionID，所以总长度 = 4 + 2 + 8 = **14B**。但文档第405行说 "TotalLength 4B LE 包含自身"，而 TotalLength 应该是所有 headers 的总长度（含 TotalLength 自身的 4B）。
- **验证**: MS-TDS §2.2.6.5: "TotalLength: The total length of the header structure. This length includes the TotalLength field itself."
- **问题**: 文档第408行 "Length=14B" 是指单个 Header 的 HeaderLength 字段值，但描述位置在 "Transaction Descriptor Header" 下，容易误解为 HeaderData 长度。
- **修复建议**: 明确标注 "HeaderLength=14B（含 HeaderLength 4B + HeaderType 2B + TransactionID 8B）"。

#### R9-11 [MEDIUM] §2.16 RPC Parameters 定义中 NameLen 单位歧义

- **位置**: §2.16，第438行
- **描述**: "1B NameLen（字节数）+ Name UCS-2 LE 字节"。但 MS-TDS §2.2.6.5 中 NameLen 是 **字符数**（UCS-2 字符个数），不是字节数。例如 "@stmt" 是 5 个字符 = 10 字节，NameLen=5（0x05），不是 10（0x0A）。
- **依据**: MS-TDS §2.2.6.5: "BNameLen: The length of the parameter name, in characters."
- **文档矛盾**: §5.6 第791行 "NameLen=0A + '@stmt' UCS-2 LE（10 字节）" —— 0x0A=10，这是字节数。但 "@stmt" 是 5 个 UCS-2 字符 = 10 字节，NameLen 应为 5（0x05）。
- **修复建议**: 
  1. §2.16 第438行 "1B NameLen（字节数）" → "1B NameLen（**字符数**，UCS-2 字符个数）"
  2. §5.6 第791行 "NameLen=0A" → "NameLen=**05**"
  3. §7.1.12 用例 1.12.6 "NameLen=0x0A" → "NameLen=**0x05**"

#### R9-12 [MEDIUM] §3.1 TDSConfig.SPID 注释与 §2.1 包头 SPID 字段定义矛盾

- **位置**: §3.1，第485-489行
- **描述**: 注释说 "Login7 之前（Pre-Login / Login7）= 0；LoginAck 之后所有包 = server 分配的 SPID。trafficgen 简化为用户配置 SPID（默认 0），并在 Login7 之后所有 TDS 包头复用。" 但 §2.1 第60行说 SPID 是 "会话 ID（server 分配）"。trafficgen 的简化（用户配置 SPID）与协议规范（server 分配）不一致，但未在文档中明确说明这是 trafficgen 的简化行为。
- **修复建议**: 在 §3.1 SPID 注释中明确添加 "trafficgen 简化：用户直接配置 SPID，不模拟 server 分配过程。"

#### R9-13 [MEDIUM] §3.4 TDSColDef.Type 映射表中 "text" 类型未定义但 MaxLength 注释提到

- **位置**: §3.4，第617-618行
- **描述**: MaxLength 注释说 "仅当 Type="varchar"/"nvarchar"/"varbinary"/"binary"/"char"/"nchar"/"text" 时输出"，但 §3.4 Type 映射表中没有 "text" 类型映射。§2.9 列类型表中有 TEXT=0x23（未列出）、NTEXT=0x22（未列出）。
- **修复建议**: 在 §3.4 Type 映射表中补充 "text" → TEXT (0x23) 和 "ntext" → NTEXT (0x22)，或从 MaxLength 注释中删除 "text"。

#### R9-14 [MEDIUM] §5.2 Pre-Login VERSION 选项 hex 值 "07 00 04 00 00 00" 与 TDS 7.4 版本号矛盾

- **位置**: §5.2，第745行
- **描述**: VERSION 选项值标注为 "07 00 04 00 00 00"。MS-TDS §2.2.6.4 中 VERSION 选项格式为 Major(2B) + Minor(2B) + Build(2B)。TDS 7.4 对应 SQL Server 2012+，版本号应为 0x0B000000（Major=11, Minor=0, Build=0）或类似，不是 "07 00 04 00 00 00"。
- **依据**: MS-TDS §2.2.6.4: "VERSION: Major(2B), Minor(2B), Build(2B)"
- **验证**: "07 00 04 00 00 00" 解码为 Major=7, Minor=4, Build=0。这是 SQL Server 7.4 的产品版本号表示法，不是 TDS 协议版本号。Pre-Login 的 VERSION 选项是 **TDS 协议版本**（如 0x74000004），不是产品版本。
- **修复建议**: VERSION 选项值应为 "04 00 00 74 00 00"（TDSVersion=0x74000004，拆分为 Major=0x0004, Minor=0x0000, Build=0x0074）或类似。需要进一步确认 MS-TDS 中 VERSION 选项的具体值格式。

#### R9-15 [MEDIUM] §5.4 SQL Batch SELECT 响应中 "ColName=01 00 + 'a' ASCII" 错误

- **位置**: §5.4，第770行
- **描述**: ColName 标注为 "01 00 + 'a' ASCII"。但 B_VARCHAR 格式是 "1B 长度前缀 + ASCII 数据"。"a" 的 ASCII 长度是 1 字节，所以 B_VARCHAR 应为 "01 61"（1B 长度=0x01 + 1B 数据=0x61），不是 "01 00 + 'a' ASCII"。
- **修复建议**: "ColName=01 00 + 'a' ASCII" → "ColName=**01 61**（B_VARCHAR：1B 长度=0x01 + 1B ASCII='a'=0x61）"

#### R9-16 [MEDIUM] §5.6 RPC Param2 TypeData=00 00（maxlen=0）时 Value 省略，与 MS-TDS 规范矛盾

- **位置**: §5.6，第791行
- **描述**: "Param2(NameLen=00 + Status=00 / Type=A7=VARCHAR / TypeData=00 00（2B 小端 LE maxlen=0）/ Value=（无字节，maxlen=0 时省略）= 空)"。但 MS-TDS §2.2.6.5 中，变长类型（如 VARCHAR）即使 maxlen=0，Value 字段仍有 2B 长度前缀（0x0000 或 0xFFFF 表示空），不是完全省略。
- **依据**: MS-TDS §2.2.6.5: 变长类型值格式为 "PLP_NULL" 或 "2B 长度 + 数据"。空字符串应为 "00 00"（2B 长度=0），不是完全无字节。
- **修复建议**: "Value=（无字节，maxlen=0 时省略）" → "Value=**00 00**（2B 长度=0，表示空字符串）"

#### R9-17 [MEDIUM] §7.1.3 用例 1.3.4 OptionFlags1 默认 0xE0 无依据

- **位置**: §7.1.3，第880行
- **描述**: "OptionFlags1 默认 0xE0"。0xE0 = 0b11100000 = bit7+bit6+bit5。但 §2.4.1 OptionFlags1 位定义中 bit5=reserved，bit6=fIntegratedSecurity，bit7=fSQLType。默认开启 fIntegratedSecurity 和 fSQLType 且保留位=1 与常规默认值不符。
- **依据**: MS-TDS §2.2.6.4 中 OptionFlags1 默认值通常为 0x00 或根据客户端能力设置。
- **修复建议**: 补充 "OptionFlags1 默认 0xE0" 的依据说明，或改为更保守的默认值（如 0x00）。

#### R9-18 [MEDIUM] §7.1.3 用例 1.3.5/1.3.6 引用 "OptionFlags2 ODBC=1" 和 "OptionFlags2 LoadTLS=1"，但 §2.4.1 无此位定义

- **位置**: §7.1.3，第881-882行
- **描述**: 用例 1.3.5 说 "OptionFlags2 ODBC=1 时 bit1=1"，用例 1.3.6 说 "OptionFlags2 LoadTLS=1 时 bit3=1"。但 §2.4.1 第141-150行 OptionFlags2 位定义中没有 "ODBC" 和 "LoadTLS" 位。
- **验证**: MS-TDS §2.2.6.4 中 OptionFlags2 的 bit1=fDollarDataType，bit3=fTextDataType。"ODBC" 和 "LoadTLS" 不是 MS-TDS 中的标准位名称。
- **修复建议**: 
  1. 删除用例 1.3.5 和 1.3.6，或
  2. 在 §2.4.1 OptionFlags2 位定义中补充 "ODBC" 和 "LoadTLS" 位（如果这是 trafficgen 的扩展），并标注为 "trafficgen 扩展位"。

#### R9-19 [MEDIUM] §7.1.6 用例 1.6.13 NULL 编码描述自相矛盾

- **位置**: §7.1.6，第963行
- **描述**: 用例 1.6.13 说 "NULL 列（IsNull=true）时 int 输出 1B 长度=0x00 + 无字节；varchar/nvarchar/char 输出 2B 长度=0xFFFF（US_VARCHAR/B_VARCHAR 标准 NULL）；BIGVARCHAR/BIGVARBINARY 输出 2B 长度=0xFFFE（MAX 类型）；TEXT/NTEXT 列输出 2B 长度=0xFFFF"。
- **问题**:
  1. "int 输出 1B 长度=0x00 + 无字节" —— 定长 int 类型在 Row Token 中**没有长度前缀**（见 R9-07）。
  2. "varchar/nvarchar/char 输出 2B 长度=0xFFFF" —— char 是定长类型，不应有 2B 长度前缀。
  3. "BIGVARCHAR/BIGVARBINARY 输出 2B 长度=0xFFFE" —— 0xFFFE 是 PLP_NULL（用于 MAX 类型），但 BIGVARCHAR/BIGVARBINARY 的 NULL 也可以是 0xFFFF（标准变长 NULL）。
- **修复建议**: 重写用例 1.6.13，按类型分类：
  - 定长类型（int/bit/bigint/float/etc）：Row Token (0xD1) 无 NULL 编码；需用 NbcRow (0xD2)。
  - 变长类型（varchar/nvarchar/varbinary）：NULL = 2B 长度=0xFFFF。
  - MAX 类型（BIGVARCHAR/BIGVARBINARY with MaxLength=0xFFFF）：NULL = PLP_NULL (0xFFFE 或 PLP 格式)。
  - TEXT/NTEXT：NULL = 2B 长度=0xFFFF。

#### R9-20 [MEDIUM] §7.1.12 用例 1.12.3 RPCProcID=11 短形式 hex 错误

- **位置**: §7.1.12，第1016行
- **描述**: "RPCProcID=11 时输出 0xFF 0xFF + 0x0B 0x00（ProcID 短形式，小端 LE）"。但 §2.15 第424行说 "ProcName 短形式：2 字节 0xFFFF + 2 字节 ProcID（小端 LE）"。ProcID=11 的小端 LE 编码应为 "0B 00"，不是 "0x0B 0x00"（这是大端）。
- **验证**: 小端 LE 编码中，uint16 值 11 = 0x000B，wire 格式为 "0B 00"。文档写 "0x0B 0x00" 是 BE 格式。
- **修复建议**: "0x0B 0x00" → "**0B 00**（小端 LE）"

#### R9-21 [MEDIUM] §7.3.6 用例 3.6.2 RPCProcID=11 短形式 hex 错误

- **位置**: §7.3.6，第1102行
- **描述**: "RPCProcID=11 + RPCName="" 时输出 0xFFFF 0x0B00 短形式（ProcID=11 小端 LE）"。"0x0B00" 是 BE，小端 LE 应为 "0x000B" 的 wire 格式 "0B 00"。
- **修复建议**: "0xFFFF 0x0B00" → "**0xFFFF 0x0B 0x00**" 或明确写 "0xFFFF + 0B 00 LE"

#### R9-22 [MEDIUM] §7.7 用例 8.12 "Validate 警告" 与 §8.3 依赖关系矛盾

- **位置**: §7.7，第1200行；§8.3，第1269行
- **描述**: §7.7 用例 8.12 说 "Response.Outcome="result_set" 但 Rows/Columns 缺一 → Validate 警告（允许但视为空结果集）"。但 §8.3 说 "Response.Outcome="result_set" 时 Columns 必须非空"。这是 "警告" 与 "必须非空" 的矛盾。
- **修复建议**: 统一为 "Validate 报错" 或 "Validate 警告"。若允许空结果集，则 §8.3 改为 "Columns 可为空（视为空结果集）"；若不允许，则 §7.7 用例 8.12 改为 "Validate 报错"。

#### R9-23 [MEDIUM] §7.10 测试用例统计表 "236" 条 SPEC 字段测试与实际计数不符

- **位置**: §7.10，第1233行
- **描述**: 统计表说 §7.1 SPEC 字段有 "236" 条用例。但逐节计数：
  - §7.1.1 Packet Header: 19 条
  - §7.1.2 Pre-Login: 9 条
  - §7.1.3 Login7: 24 条
  - §7.1.4 LoginAck: 9 条
  - §7.1.5 ColMetadata: 32 条
  - §7.1.6 Row: 13 条
  - §7.1.7 Done: 12 条
  - §7.1.8 Error: 10 条
  - §7.1.9 Info: 2 条
  - §7.1.10 EnvChange: 5 条
  - §7.1.11 AllHeaders: 3 条
  - §7.1.12 RPC: 11 条
  - §7.1.13 Attention: 2 条
  - §7.1.14 NbcRow: 0 条（deferred）
  - §7.1.15 ReturnStatus: 2 条
  - §7.1.16 ReturnValue: 3 条
  - **合计 = 19+9+24+9+32+13+12+10+2+5+3+11+2+0+2+3 = 156 条**
- **差异**: 156 vs 236，相差 80 条。即使算上未列出的组合子用例，也达不到 236。
- **修复建议**: 重新统计或修正统计表数字。

#### R9-24 [LOW] §2.4.1 字段列表中 "OptionFlags2" 和 "TypeFlags" 的注释标为 "uint8"，但 MS-TDS 中它们是独立字段

- **位置**: §2.4.1，第125-127行
- **描述**: 文档正确标注了 OptionFlags2 和 TypeFlags 为 uint8，但注释 "标志位 2" 和 "类型标志" 过于简略，未体现它们是独立字段。
- **修复建议**: 第125行 "标志位 2" → "标志位 2（数据类型能力标志）"；第127行 "类型标志" → "类型标志（连接类型标志）"。

#### R9-25 [LOW] §2.6 Token 流表中缺少多个标准 Token

- **位置**: §2.6
- **描述**: Token 流表缺少以下 MS-TDS 标准 Token：
  - 0x1F: Offset（游标偏移）
  - 0x22: Order（与 0xA0 重复？不，0x22 是旧版 Order）
  - 0x32: AltName（替代名称）
  - 0xA1: AltRow（替代行）
  - 0xA4: ColInfo（列信息）
  - 0xA5: TabName（表名）
  - 0xA7: Param（参数）
  - 0xA8: ParamFmt（参数格式）
  - 0xD3: NbcRow（已列出）
  - 0xD7: SSPIMessage（SSPI 消息）
  - 0xE5: FeatureExt（特性扩展）
  - 0xEC: FedAuthInfo（联邦认证信息）
- **修复建议**: 补充常用 Token 或标注 "本表仅列出设计中使用的 Token，完整列表见 MS-TDS §2.2.7.x"。

#### R9-26 [LOW] §2.9 列类型表缺少部分常用类型

- **位置**: §2.9
- **描述**: 缺少以下常用类型：
  - 0x23: TEXT（变长文本，4B 长度前缀）
  - 0x25: NUMERIC（变长数值）
  - 0x27: DECIMAL（变长十进制）
  - 0x2D: DATETIME（定长 8B，TypeData=0）
  - 0x31: DATETIME4（定长 4B）
  - 0x3A: DATE（TDS 7.4 新类型，已标注不支持）
  - 0x3B: TIME（TDS 7.4 新类型，已标注不支持）
  - 0x3C: DATETIME2（TDS 7.4 新类型，已标注不支持）
  - 0x3E: DATETIMEOFFSET（TDS 7.4 新类型，已标注不支持）
  - 0x62: XML（TDS 7.4 新类型）
  - 0x63: UDT（用户定义类型）
  - 0xF1: CLRUDT（CLR 用户定义类型）
- **修复建议**: 补充 "TEXT" 等常用类型到映射表，或标注 "本表仅列出设计中支持的类型"。

#### R9-27 [LOW] §3.1 TDSConfig.Logout 字段 "attention" 模式描述不完整

- **位置**: §3.1，第514-518行
- **描述**: "attention" 模式说 "在 logout 前自动追加 Kind=attention 的 TDSCommand（参见 §6.12 S12 序列）"。但 §5.9 S12 序列中 Attention 是 client→server 的 Type=6 包，server 响应是 Done(Status=ERROR)。Logout="attention" 模式下，attention 之后是否等待 server 响应再发 TCP FIN？文档未明确。
- **修复建议**: 补充 "attention 模式下，client 发送 Attention(Type=6) 后等待 server 的 Attention Ack(Type=5) + Done(Status=ERROR)，然后发送 TCP FIN 关闭连接。"

#### R9-28 [LOW] §5.3 LoginAck 响应中 "Done(FD) + Status(00 00 LE) + CurCmd(00 00 LE) + RowCount(...)" 缺少 Token 字节

- **位置**: §5.3，第757行
- **描述**: 响应描述写 "Done(FD) + Status(00 00 LE) + CurCmd(00 00 LE) + RowCount(...)"。Done Token 格式应为 "Token(0xFD) + Status(2B) + CurCmd(2B) + RowCount(4B/8B)"。描述中 "Done(FD)" 暗示 Token=0xFD，但后续字段未明确标注 Token 字节。
- **修复建议**: 明确写 "Done(Token=0xFD + Status=00 00 LE + CurCmd=00 00 LE + RowCount=...)"。

#### R9-29 [LOW] §16 修订记录中 "16.2 v1.1.6 修复清单" 和 "16.2 v1.1.5 修复清单" 使用相同小节编号

- **位置**: §16，第1365行、第1374行
- **描述**: 第1365行标为 "16.2 v1.1.6 修复清单"，第1374行也标为 "16.2 v1.1.5 修复清单"。小节编号重复，应为 "16.4" 和 "16.5"。
- **修复建议**: 第1374行 "16.2 v1.1.5" → "**16.4** v1.1.5"；第1384行 "16.2 历史修订" → "**16.5** 历史修订"。

---

## 四、测试用例质量审查（对照 CLAUDE.md §Testing Policy）

### 4.1 规则 1: Spec-driven test derivation

- **审查结果**: §7.1 各小节基本对应 §2 的字段定义表，但存在以下问题：
  - §7.1.3 用例 1.3.5/1.3.6 引用的 "OptionFlags2 ODBC/LoadTLS" 位在 §2.4.1 中无定义（见 R9-18）。
  - §7.1.6 用例 1.6.13 的 NULL 编码描述与 §2.8 矛盾（见 R9-07、R9-19）。
- **评级**: **部分符合**，有 2 处测试用例引用不存在的 spec 定义。

### 4.2 规则 2: Cover failure paths

- **审查结果**: 
  - §7.7 Validate 错误路径有 16 条用例，覆盖较全面。
  - 但缺少以下负向路径：
    - Login7 密码 XOR 掩码错误（如 XOR 0xA5 后长度不匹配）
    - Collation 5B 中 SortId 超出范围
    - PacketSize 低于 512 的边界
    - SPID=65535 的边界（最大值）
    - RowCount 超出 uint32 范围（TDS 7.3+ 8B 时）
- **评级**: **基本符合**，但缺少部分边界负向测试。

### 4.3 规则 3: Test the right function/scope

- **审查结果**: 
  - §7.1 各小节按字段分组，测试粒度合理。
  - 但 §7.1.14 NbcRow 标为 "deferred"，无测试用例。NbcRow 是 TDS 7.3+ 的重要特性，deferred 意味着当前设计不支持。
- **评级**: **基本符合**，NbcRow deferred 是已知限制。

### 4.4 规则 4: Integration tests

- **审查结果**: §7.3 有 14 子类 35 条集成测试，覆盖主要流程。但：
  - 缺少 "Login7 → Error(18456) → 重试 Login7" 的集成测试。
  - 缺少 "多包消息（PacketID 递增）" 的实际多包场景测试。
- **评级**: **基本符合**。

### 4.5 规则 5: Assert observable outcomes

- **审查结果**: 
  - 大部分用例断言了具体 hex 输出值，符合要求。
  - 但 §7.2 场景测试（15 条）描述过于笼统，如 "Pre-Login 握手成功" 未说明断言什么 hex 值。
  - §7.5 并发测试 "M=100 客户端并发 -race 检查" 未说明具体断言指标。
- **评级**: **部分符合**，场景测试和并发测试缺乏可观测断言。

### 4.6 规则 6: Concurrency tests verify correctness

- **审查结果**: §7.5 有 5 条并发测试，但：
  - 用例 5.5 "M=100 客户端并发 -race，总吞吐量、内存峰值可观测" —— 未给出具体阈值或测量方法。
- **评级**: **部分符合**，缺乏具体测量标准。

### 4.7 规则 7: Failing-test-first for bug fix

- **审查结果**: 文档为设计文档，非实现代码。此规则适用于实现阶段。
- **评级**: **不适用**（设计阶段）。

### 4.8 规则 8: Adversarial review of test quality

- **审查结果**: 本轮审计即对抗式审查。发现测试用例本身存在错误（R9-11、R9-19、R9-20、R9-21）。
- **评级**: **不符合**，测试用例存在与 spec 矛盾的错误。

---

## 五、HexDump 逐字节自洽性审查

### 5.1 §5.2 Pre-Login VERSION hex: "07 00 04 00 00 00"

- **分析**: 6 字节值。若按 Major(2B)+Minor(2B)+Build(2B) LE 解码：Major=0x0007, Minor=0x0004, Build=0x0000。
- **问题**: TDS 7.4 的版本号应为 0x74000004（LE），不是 0x00070004。见 R9-14。
- **状态**: **不一致**

### 5.2 §5.3 LoginAck ProgName: "2C 00 LE + 44B UCS-2"

- **分析**: "Microsoft SQL Server" = 22 字符 × 2 = 44 字节。US_VARCHAR 长度前缀 = 44 = 0x002C，LE 编码 "2C 00"。
- **状态**: **一致** ✓

### 5.3 §5.3 LoginAck ProgVer: "0x0F000000 LE"

- **分析**: 值 0x0000000F 的 LE 编码为 "0F 00 00 00"。文档写 "0x0F000000 LE" 是值表示，wire 格式应为 "0F 00 00 00"。
- **状态**: **一致**（值表示正确）✓

### 5.4 §5.4 Row INT4 值: "01 00 00 00"

- **分析**: 值 1 的 int32 LE 编码为 "01 00 00 00"。
- **状态**: **一致** ✓

### 5.5 §5.6 RPC ProcName: "1A 00 LE + 26B UCS-2"

- **分析**: "sp_executesql" = 13 字符 × 2 = 26 字节。US_VARCHAR 长度前缀 = 26 = 0x001A，LE 编码 "1A 00"。
- **状态**: **一致** ✓

### 5.6 §5.6 RPC Param1 NameLen: "0A"

- **分析**: "@stmt" = 5 个 UCS-2 字符 = 10 字节。若 NameLen 是字节数，则 0x0A=10 正确。但 MS-TDS 规定 NameLen 是字符数，应为 0x05=5。见 R9-11。
- **状态**: **不一致**

### 5.7 §5.7 Error Number: "102=0x66 LE → 66 00 00 00"

- **分析**: 值 102 = 0x00000066，int32 LE 编码 "66 00 00 00"。
- **状态**: **一致** ✓

### 5.8 §5.7 Error LineNumber: "01 00 00 00 LE"

- **分析**: 值 1 = 0x00000001，int32 LE 编码 "01 00 00 00"。
- **状态**: **一致** ✓

---

## 六、问题汇总

### 6.1 严重度统计

| 严重度 | 数量 | 问题编号 |
|--------|------|----------|
| CRITICAL | 5 | R9-01, R9-02, R9-03, R9-06, R9-07 |
| HIGH | 6 | R9-05, R9-08, R9-09, R9-10, R9-11, R9-12 |
| MEDIUM | 12 | R9-04, R9-13, R9-14, R9-15, R9-16, R9-17, R9-18, R9-19, R9-20, R9-21, R9-22, R9-23 |
| LOW | 6 | R9-24, R9-25, R9-26, R9-27, R9-28, R9-29 |
| **合计** | **29** | — |

### 6.2 必须先返工的问题（CRITICAL + HIGH）

**CRITICAL（5 个）**：
1. **R9-01**: §2.4.1 OptionFlags2/TypeFlags/OptionFlags3 字段命名与位定义循环混淆
2. **R9-02**: §2.1 TDS 包头 Length/SPID 标注为 BE 应为 LE
3. **R9-03**: §2.3 Pre-Login Offset/Length 标注为 BE 应为 LE
4. **R9-06**: §2.6 FeatureExtAck Token 值 0xAA 错误应为 0xAE
5. **R9-07**: §2.8 Row Token 定长类型 NULL 编码错误（1B 长度=0x00 不存在）

**HIGH（6 个）**：
6. **R9-05**: §2.4.2 Login7 偏移表结构描述错误（缺少 2B 长度字段）
7. **R9-08**: §2.9 TIME/DATETIME2/DATETIMEOFFSET TypeData "1B+1B" 错误应为 "1B"
8. **R9-09**: §2.10 Done Status 遗漏 DONE_ROWCOUNT=0x0200
9. **R9-10**: §2.14 AllHeaders Transaction Descriptor Header 长度描述歧义
10. **R9-11**: §2.16 RPC Param NameLen 单位错误（字节数→字符数）
11. **R9-12**: §3.1 SPID 简化行为未明确标注

---

## 七、最终结论

### 7.1 是否可以进入实现阶段？

**否。**

### 7.2 必须先返工的问题编号

以下 **11 个问题（5 CRITICAL + 6 HIGH）** 必须先修复：

**CRITICAL（5）**: R9-01, R9-02, R9-03, R9-06, R9-07
**HIGH（6）**: R9-05, R9-08, R9-09, R9-10, R9-11, R9-12

### 7.3 关键风险说明

1. **R9-01（CRITICAL）**: 标志位字段命名混淆会导致 Login7 包中标志位写入错误位置，SQL Server 将拒绝连接。
2. **R9-02/R9-03（CRITICAL）**: TDS 包头和 Pre-Login 选项的字节序错误会导致 Wireshark 解析失败、SQL Server 拒绝连接。
3. **R9-06（CRITICAL）**: FeatureExtAck Token 值错误（0xAA 是 Error Token）会导致 Token 流解析混乱。
4. **R9-07（CRITICAL）**: Row Token 定长类型 NULL 编码错误会导致生成的流量与 SQL Server 实际行为不符，Wireshark 可能报错。
5. **R9-11（HIGH）**: RPC Param NameLen 单位错误会导致参数名长度字段值翻倍，SQL Server 解析参数名时越界。

### 7.4 R8 修复总体评价

R8-01~R8-20 的 20 处修复中，**16 处已正确落地**，**4 处存在遗留问题**：
- R8-03（OptionFlags 位定义重写）：bit 值正确，但字段命名关系仍混淆（演变为 R9-01）。
- R8-12（Login7 头部 42B）：头部大小正确，但偏移表结构未同步修正（演变为 R9-05）。
- R8-16（ColDef Flags 补充）：bit8-bit9 已补充，但测试用例未同步补充对应测试。

---

*审计完成时间: 2026-08-04*
*审计员: 独立审计员*
