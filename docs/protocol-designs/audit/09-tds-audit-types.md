# TDS 设计文档 v3.0.0 审计报告 — 数据类型/包结构/跨节一致性/版本兼容性

> **审计维度**：数据类型与编码、包结构、跨节一致性、版本兼容性
> **审计对象**：`/home/weihang/trafficGenerator/docs/protocol-designs/09-tds-design.md` (v3.0.0, 2323 行)
> **规范基准**：MS-TDS v20260617（修订版 42.0）
> **审计方法**：逐字段与规范对照，逐字检查跨节一致性，不修改文档、不运行 go build/test
> **审计日期**：2026-08-04

---

## 一、问题汇总

| 严重度 | 数量 | 标识 |
|--------|------|------|
| CRITICAL | 6 | C1-C6 |
| HIGH | 5 | H1-H5 |
| MEDIUM | 6 | M1-M6 |
| LOW | 3 | L1-L3 |
| **合计** | **20** | |

---

## 二、CRITICAL 问题（必须修复）

### C1：COLMETADATA Flags 位掩码值全面错误

- **位置**：§3.7 第 547 行
- **描述**：`fSparseColumnSet`/`fEncrypted`/`usReserved3`/`fFixedLenCLRType`/`fHidden`/`fKey`/`fNullableUnknown` 的值与 MS-TDS §2.2.7.4 Flags 定义（LSB 序）矛盾。

| 字段 | 设计文档值 | 规范实际值（LSB 序） | 规范依据 |
|------|-----------|---------------------|-----------|
| fFixedLenCLRType | 0x1000 (bit 12) | 0x0100 (bit 8) | MS-TDS §2.2.7.4 Flags 规则 |
| FRESERVEDBIT | 未提及 | bit 9 (7.4 版本) | 同上 |
| fSparseColumnSet | 0x200 (bit 9) | 0x0400 (bit 10) | 同上 |
| fEncrypted | 0x400 (bit 10) | 0x0800 (bit 11) | 同上 |
| usReserved3 | 0x800 (bit 11) | 0x1000 (bit 12) | 同上 |
| fHidden | 0x20000 (17 位) | 0x2000 (bit 13) | 同上 |
| fKey | 0x40000 (17 位) | 0x4000 (bit 14) | 同上 |
| fNullableUnknown | 0x80000 (17 位) | 0x8000 (bit 15) | 同上 |

- **影响**：Flags 共 16 位（规范明确：`Flags` 参数始终为 16 位）。设计文档将 fFixedLenCLRType 从 bit 8 错误移到 bit 12，进而导致后续所有位的分配全部偏移。此外，fHidden/fKey/fNullableUnknown 的取值 0x20000/0x40000/0x80000 已超出 16 位范围（0xFFFF），属于无法实现的位编码。
- **修复**：按规范 LSB 序重排所有位值：fFixedLenCLRType=0x0100（bit 8）、FRESERVEDBIT（bit 9）、fSparseColumnSet=0x0400（bit 10）、fEncrypted=0x0800（bit 11）、usReserved3=0x1000（bit 12）、fHidden=0x2000（bit 13）、fKey=0x4000（bit 14）、fNullableUnknown=0x8000（bit 15）。

**状态**：错误


### C2：Attention Ack Type 为未使用值 0x05（与规范冲突）

- **位置**：§3.15 第 704 行
- **描述**：设计文档称 "Attention Ack Type=0x05（包头 Type 5 标记 Attention 确认消息类型；服务器对 Attention 的实际确认载体是 DONE_ATTN）"。规范 MS-TDS §2.2.3.1.1 Type 表明确标注 "5 Unused" 且消息表显示 "Attention Acknowledgement Server 4"。服务器对 Attention 的确认通过 Type=0x04 包中的 DONE Token（DONE_ATTN 位）承载，不存在独立的 Type=0x05 包类型。
- **修复**：删除 "Attention Ack Type=0x05" 的声明及相关注释，明确 Attention 确认在 Type=0x04 包中以 DONE_ATTN 位承载。

**状态**：错误


### C3：RPC STATUSFLAGS fEncrypted 位号错误

- **位置**：§3.4 第 483 行
- **描述**：设计文档描述 "StatusFlags; 1B：fByRefValue(bit0) + fDefaultValue(bit1) + 保留 + fEncrypted(bit4)"。规范 MS-TDS §2.2.6.6 StatusFlags：
  ```
  fByRefValue BIT
  fDefaultValue BIT
  1FRESERVEDBIT
  fEncrypted BIT
  4FRESERVEDBIT
  ```
  因此 fEncrypted 在 bit3（1 个保留位之后），而非 bit4。bit2 是保留位，bit3 是 fEncrypted。
- **修复**：将 fEncrypted 位号从 bit4 改为 bit3。

**状态**：错误


### C4：LOGINACK ProgName 类型声明错误（US_VARCHAR → B_VARCHAR）

- **位置**：§3.12 第 660 行、§2.3 第 202 行
- **描述**：
  1. §3.12 第 660 行："ProgName 用 **US_VARCHAR**（2B 长度 + UCS-2 LE）"
  2. §2.3 第 202 行："LoginAck.ProgName 用 US_VARCHAR"
  3. 规范 MS-TDS §2.2.7.14 定义：`ProgName = B_VARCHAR`（**1B** 长度 + UCS-2 LE）
  4. S2 HexDump 第 1087 行 `16 4D 00 69 00 ...` — 0x16（=22）为 1 字节长度前缀，确认为 B_VARCHAR
  5. T-035 断言 "ProgName(1+44)" — 明确使用 1 字节长度，与设计文档自身的测试用例矛盾
  6. 官方规范示例 4.4 XML：`<B_VARCHAR><BYTELEN><BYTE>16</BYTE></BYTELEN>...` — 确认为 B_VARCHAR
- **修复**：§3.12 和 §2.3 中 "US_VARCHAR" 改为 "B_VARCHAR（1B 长度 + UCS-2 LE）"。

**状态**：错误


### C5：LOGINACK TDSVersion wire 字节序标注错误

- **位置**：§3.12 第 659 行
- **描述**：设计文档标注 "7.4=`0x74000004`（wire LE `04 00 00 74`）"。规范示例 4.2（LOGIN7 第 7107 行）和 4.4（LOGINACK 第 8013 行）表明 TDSVersion 字段在 wire 上实际为 BE（大端）：
  - LOGIN7 TDS 7.2: wire `02 00 09 72`（BE 解释 = 0x02000972 = 客户端→服务器值）
  - LOGINACK TDS 7.2: wire `72 09 00 02`（BE 解释 = 0x72090002 = 服务器→客户端值）
  - 两个值互为字节反转，表明该字段为 BE
  - 据此，LOGINACK TDS 7.4 的 wire 应为 `74 00 00 04`，而非 `04 00 00 74`
  - 设计文档 S2 LOGIN7 TDS 7.2 wire 为 `02 00 09 72`（HexDump 第 1043 行），S2 LOGINACK TDS 7.2 wire 为 `72 09 00 02`（HexDump 第 1087 行），两者均与规范示例一致
- **修复**：
  1. §3.12 将标注从 "wire LE `04 00 00 74`" 改为 "wire `74 00 00 04`"
  2. T-016 将 "wire=`04 00 00 74`" 改为 "wire=`74 00 00 04`"（仅针对 LOGINACK，LOGIN7 的 `04 00 00 74` 保留不变）

**状态**：错误


### C6：DONEINPROC 状态表错误包含 DONE_FINAL

- **位置**：§3.9 第 586 行
- **描述**：设计文档 Status 位表第 1 行 "DONE_FINAL | 0x00 | 请求中最后的 DONE | ✓ | ✓ | ✓" 暗示 DONE_FINAL 对 DONEINPROC 也有效。规范 MS-TDS §2.2.7.7 DONEINPROC Status 位列表（仅 DONE_MORE 0x1 / DONE_ERROR 0x2 / DONE_INXACT 0x4 / DONE_COUNT 0x10 / DONE_SRVERROR 0x100）中**不含** DONE_FINAL(0x00)。DONEINPROC 必须后跟另一个 DONEPROC 或 DONEINPROC（规范注释），因此它本身不可能为 "final"。
- **修复**：DONE_FINAL 行中 DONEINPROC 列的 ✓ 改为 —。DONE_FINAL 仅适用于 DONE 和 DONEPROC。

**状态**：错误


## 三、HIGH 问题（应当修复）

### H1：LOGIN7 OffsetLength 表大小描述错误（94 字节 → 58 字节）

- **位置**：§3.2 第 426 行、T-030 第 1830 行
- **描述**：设计文档声明 "OffsetLength（偏移表）：固定 94 字节"。根据规范 MS-TDS §2.2.6.4 OffsetLength 规则（仅包含 ibHostName...cbSSPILong），TDS 7.2+ 的表实际大小为 58 字节（13 对 × 4B + ClientID 6B = 58B），TDS 7.0/7.1 为 50 字节。ibHostName = 0x5E = 94 是**从 LOGIN7 结构起始到 Data 区的偏移量**（=36 字节固定 Header + 58 字节 OffsetLength 表），而非 OffsetLength 表本身的大小。
- **修复**：
  1. §3.2："OffsetLength（偏移表）：固定 94 字节" → "OffsetLength（偏移表）：TDS 7.2+ 为 58 字节，TDS 7.0/7.1 为 50 字节；ibHostName 指向 Data 区，其值 94（= 固定 Header 36 字节 + OffsetLength 58 字节）"
  2. T-030："OffsetLength 94B" → "OffsetLength 58B"

**状态**：错误


### H2：TDS 版本表 §1.2 将 NBCROW 标注为 TDS 7.3.A 支持（实际仅 7.3.B+）

- **位置**：§1.2 第 39 行
- **描述**：设计文档表为 "7.3.A / 7.3.B | SQL Server 2008 / 2008 R2 | NbcRow(0xD2)、稀疏列、TVP..."。规范脚注 `*SQL Server 2008 TDS version 0x03000A73 does not include support for NBCROW and fSparseColumnSet.` 明确 SQL Server 2008 (7.3.A) **不支持** NBCROW 和 fSparseColumnSet。仅 7.3.B 支持。
- **修复**：将 §1.2 表中 "NbcRow(0xD2)、稀疏列" 从 7.3.A 行移除，或拆分为两行标注。§10.1 矩阵已正确标注 NbcRow = 7.3.B+（无需修改），但 §1.2 表需同步。

**状态**：错误


### H3：TDS 8.0 版本行不存在于规范中

- **位置**：§1.2 第 41 行
- **描述**：设计文档表含 "8.0 | SQL Server 2022+ | 强制 TLS（ALPN 'tds/8.0'），本文档不覆盖"。规范 MS-TDS v20260617 版本表（脚注 17）将 SQL Server 2022/2025 标注为 TDS 版本 **7.4**（0x04000074），规范中未定义 TDS 8.0。该行无可靠引用来源。
- **修复**：删除 TDS 8.0 行，或标注其为 "其它文档引用，非 MS-TDS 规范定义"。

**状态**：错误


### H4：§1.7 约定中 B_VARCHAR 说明与规范冲突

- **位置**：§1.7 第 120 行
- **描述**：设计文档定义 "B_VARCHAR = 1B 长度 + UCS-2 LE 字符（长度单位=Unicode 字符数）"。规范 MS-TDS §2.2.5.2.2 定义 `B_VARCHAR = BYTELEN *CHAR`，注释 "Note that the lengths of B_VARCHAR and US_VARCHAR are given in Unicode characters." 即长度单位为 Unicode 字符数，**CHAR = UNICODECHAR = 2BYTE**（规范 §2.2.5.1 定义）。设计文档正确描述了长度语义，但“1B 长度” 的表述隐含单字节长度，应更精确地说明为 "BYTELEN（1 字节，值为 Unicode 字符数）"。此处与规范无直接矛盾，但表述可完善。
- **修复**：无需实质修改，但建议在 B_VARCHAR 定义中补充："BYTELEN 值为 Unicode 字符数（非字节数）"。

**状态**：不精确


### H5：§2.4.3 变长类型 NULL 规则表述矛盾

- **位置**：§2.4.3 第 278 行
- **描述**：设计文档 "变长 NULL：BYTELEN/USHORTLEN 类型 = 长度 0x00（GEN_NULL）；VARCHAR/BINARY 类（BIG* 等）= 0xFFFF（2B CHARBIN_NULL）"。规范 MS-TDS §2.2.5.2.3：
  - 2 字节 CHARBIN_NULL（0xFFFF）用于 BIGCHARTYPE, BIGVARCHARTYPE, NCHARTYPE, NVARCHARTYPE, BIGBINARYTYPE, BIGVARBINARYTYPE（均属 USHORTLEN_TYPE）
  - 4 字节 CHARBIN_NULL（0xFFFFFFFF）用于 TEXTTYPE, NTEXTTYPE, IMAGETYPE（均属 LONGLEN_TYPE）
  - GEN_NULL（0x00）适用于所有其它类型（包括 BYTELEN_TYPE 中的字符类型如 VARCHARTYPE、BINARYTYPE 等）
  - 设计文档 "BYTELEN/USHORTLEN 类型 = 0x00" 与 "BIG* 等 = 0xFFFF" 存在逻辑矛盾——BIG* 类型本就属于 USHORTLEN_TYPE，不应同时满足两个条件
- **修复**：重写为三段式："非 char/binary 类型的 BYTELEN/USHORTLEN 变长类型 NULL=0x00（GEN_NULL）；USHORTLEN char/binary 类型（BIG* 系列）NULL=0xFFFF；LONGLEN 类型（TEXT/NTEXT/IMAGE）NULL=0xFFFFFFFF。"

**状态**：矛盾


## 四、MEDIUM 问题（建议修复）

### M1：ENVCHANGE Type 16 (Transaction Manager Address) 遗漏

- **位置**：§3.10 第 607-627 行 Type 表
- **描述**：ENVCHANGE 类型表中 Type 16 (Transaction Manager Address) 缺失。规范 MS-TDS §2.2.7.9 列出了 Type 16，作为 TM_GET_DTC_ADDRESS 响应发送。
- **修复**：添加 "16 | Transaction Manager Address | B_VARBYTE | %x00" 一行。

**状态**：遗漏


### M2：§3.10 ENVCHANGE 类型 7 OldValue 编码错误

- **位置**：§3.10 第 614 行
- **描述**：设计文档表中 Type 7 (SQL Collation) 的 "OldValue" 列未明确标注为 B_VARBYTE。规范 MS-TDS §2.2.7.9 Type 表：Type 7 OLDVALUE = B_VARBYTE, NEWVALUE = B_VARBYTE。设计文档 HexDump 示例第 1059 行 `E3 08 00 07 05 09 04 D0 00 34 00` — OldValue 的 `00` = B_VARBYTE 长度 0（空 B_VARBYTE），实际上表项未明确显示 OldValue 类型。
- **修复**：在 Type 7 行明确标注 "OldValue: B_VARBYTE（空时为 0x00）"。

**状态**：不精确


### M3：§3.5 TransMgrReq 隔离级别 OLDVALUE 与规范轻微差异

- **位置**：§3.5 第 508 行
- **描述**：设计文档 "隔离级别: 0x00=无变化" 与规范 "0x00 No isolation level change requested. Use current." 含义一致，但翻译不同。不会导致实现错误，但应统一措辞。
- **修复**：建议改为 "0x00=使用当前不改变" 以与规范注释对齐。

**状态**：不精确


### M4：TDS 7.3.A / 7.3.B TDSVersion 服务器格式在 §3.12 中遗漏

- **位置**：§3.12 第 659 行
- **描述**：设计文档仅列出了 7.1 / 7.2 / 7.4 的服务器→客户端 TDSVersion。7.3.A 的 `0x730A0003` 和 7.3.B 的 `0x730B0003` 未列出。规范脚注 72 完整列出了所有版本的对应关系。
- **修复**：补充 7.3.A: `0x730A0003`，7.3.B: `0x730B0003` 的服务器格式。

**状态**：遗漏


### M5：§2.5 ALL_HEADERS 中 NotifyId 和 SSBDeployment 表述歧义

- **位置**：§2.5 第 348 行
- **描述**：设计文档描述 "NotifyId(USHORT+Unicode) + SSBDeployment(USHORT+Unicode)"。规范 MS-TDS §2.2.5.3.1：`NotifyId = USHORT UNICODESTREAM`，`SSBDeployment = USHORT UNICODESTREAM`。其中 `USHORT` 为 **UNICODESTREAM 的字节长度**，不是字符数。"USHORT+Unicode" 的表述可能误导读者理解为 "2B 长度前缀"（正确）或 "USHORT id + Unicode 名称"（歧义）。
- **修复**：改为 "NotifyId(2B LE 长度 + UNICODESTREAM 数据) + SSBDeployment(2B LE 长度 + UNICODESTREAM 数据) + [NotifyTimeout(4B LE)]"。

**状态**：歧义


### M6：§3.2 偏移表 TDS 7.4 前 ibExtension 未明确替代 ibUnused

- **位置**：§3.2 第 435 行
- **描述**：设计文档 "ibExtension / cbExtension | 2B+2B | TDS 7.4 fExtension=1 时有效"。规范 MS-TDS §2.2.6.4 OffsetLength 规则使用 `(ibUnused / ibExtension)` 形式，表明它们是物理上相同的字节位置，语义随版本变化。设计文档声称 "TDS 7.4 fExtension=1 时有效" 可能令人误解——字节始终存在，仅当 fExtension=1 时引用 FeatureExt。前几个版本中该位置是 ibUnused/cbUnused。
- **修复**：补充说明："TDS 7.3 及以下：这些字节为 ibUnused/cbUnused（预留）；TDS 7.4：当 fExtension=1 时，这些字节引用 FeatureExt 数据偏移"。

**状态**：不精确


## 五、LOW 问题（可选的改进）

### L1：§3.7 TableName 字段 PartName 版本标注不完整

- **位置**：§3.7 第 552 行
- **描述**：设计文档 "TableName（NumParts(1B) + PartName*(US_VARCHAR)）仅在 text/ntext/image 列出现"。规范 MS-TDS §2.2.7.4：`NumParts = BYTE`（TDS 7.2 引入），`PartName = US_VARCHAR`（TDS 7.2 引入），`TableName = US_VARCHAR`（TDS 7.2 中移除 = 遗留形式）。TDS 7.1 中 TableName 为单一的 US_VARCHAR。设计文档未区分版本差异。
- **修复**：补充 "TDS 7.2+ 为多段格式；TDS 7.1 为单一的 US_VARCHAR"。

**状态**：不完整


### L2：§3.8 ROW Token TextPointer/Timestamp 说明可更精确

- **位置**：§3.8 第 562 行
- **描述**："TextPointer = B_VARBYTE（16B 文本指针）+ Timestamp(8B)，仅 text/ntext/image 列需要；NULL 实例不得带 TextPointer/Timestamp" — 正确。但建议补充 "Timestamp 为 8BYTE（固定 8 字节），非可选" 以避免混淆。
- **修复**：可补充 "TextPointer = B_VARBYTE + 固定 8B Timestamp"。

**状态**：建议


### L3：§2.4.6 datetime 编码 "自 1900-01-01" 中 1753 边界可补充说明

- **位置**：§2.4.6 第 329 行
- **描述**："datetime | 4B 有符号天数（自 1900-01-01，负数可表示 1753 起）" — 规范 MS-TDS §2.2.5.5.1.8 允许负数到 1753 年 1 月 1 日。正确。但设计文档没有明确能表示的最早日期（1753-01-01 = 53690 天前 ≈ -53690）。
- **修复**：可补充 "最早可表示 1753-01-01"。

**状态**：建议


## 六、已验证正确的重要内容

以下项目经与规范逐项核对，确认无误：

1. **TYPE_INFO 结构**（§2.4.5 第 300-316 行）：FIXEDLENTYPE/VARLENTYPE/PARTLENTYPE 规则与 COLLATION/PRECISION/SCALE/USHORTMAXLEN 规则完全正确。

2. **PLP 编码**（§2.4.4 第 284-297 行）：PLP_NULL/UNKNOWN_PLP_LEN/PLP_CHUNK/PLP_TERMINATOR 与规范 MS-TDS §2.2.5.2.3 完全一致。

3. **定长/变长类型 token 值**（§2.4.2/2.4.3 第 214-271 行）：全部 42 个类型 token 值与规范 §2.2.5.4.2/§2.2.5.4.3 一致。

4. **日期时间新类型长度**（§2.4.3 第 244-247 行）：DATENTYPE/TIMENTYPE/DATETIME2NTYPE/DATETIMEOFFSETNTYPE 的 SCALE→长度映射与规范精确一致。

5. **COLLATION 5B 编码**（§2.4.5 第 317 行）：LCID(20bit) + ColFlags(8bit LSB) + Version(4bit) + SortId(1B) = 40bit = 5B。正确。

6. **ALL_HEADERS HeaderType 值**（§2.5 第 346-350 行）：Query Notifications=0x0000, Transaction Descriptor=0x0002, Trace Activity=0x0003。与规范 MS-TDS §2.2.5.3 一致。

7. **DONE Status 位表**（§3.9 第 584-593 行）：除 C6 外，其余位值与应用范围全部正确。

8. **ENVCHANGE Type 8/9/10 事务编码**（§3.10 第 615-617 行）：NewValue/OldValue 的 B_VARBYTE 编码与 ULONGLONG TransactionID 完全正确。

9. **ERROR/INFO LineNumber 版本宽度**（§3.11 第 645 行）：TDS 7.1=2B USHORT，TDS 7.2+=4B LONG。与规范一致。

10. **RPC ProcName ≤ 1046 字节**（§3.4 第 472 行）、**ProcID 短形式 0xFFFF**（§3.4 第 473 行）、**BatchFlag/NoExecFlag**（§3.4 第 476-477 行）

11. **返回值编码**（§2.4.6 第 321-333 行）：整数 LE、money ×10^4、decimal 符号+整数、datetime 1/300 秒等全部正确。

12. **NULL 编码**（§2.4.3 第 276-280 行）：除 H5 矛盾表述外，基本逻辑正确（PLP_NULL=8B 0xFF...FF, LONGLEN=4B 0xFFFFFFFF, USHORTLEN char/binary=2B 0xFFFF）。

13. **PRELOGIN 选项表**（§3.1 第 389-398 行）：VERSION/ENCRYPTION/INSTOPT/THREADID/MARS/TRACEID/FEDAUTHREQUIRED/NONCEOPT/TERMINATOR 全部 token 值与规范 §2.2.6.5 一致。

14. **LOGIN7 固定字段**（§3.2 第 413-424 行）：Length/TDSVersion/PacketSize/ClientProgVer/ClientPID/ConnectionID/OptionFlags 全部与规范一致。

15. **SQLBatch、RPCReqBatch 结构**（§3.3-§3.4）：与规范 §2.2.6.7 和 §2.2.6.6 一致。

16. **S15 NULL 处理的 HexDump**（§6 S15）：定长 NULL=类型宽度全 0、变长 NULL=0xFFFF、MAX NULL=8B PLP_NULL 全部正确体现。

---

## 七、结论

**类型/结构/一致性维度审计结论：未通过**

必须修复的 CRITICAL 问题（C1-C6，共 6 项）涉及：
- Flags 位掩码（C1：会导致所有含 Flag 的列编码/解码错误）
- Attention 确认包类型（C2：错误引用不存在的 Type=0x05）
- RPC StatusFlags fEncrypted 位号（C3）
- LOGINACK ProgName 类型（C4：US_VARCHAR→B_VARCHAR）
- LOGINACK TDSVersion wire 字节序（C5：LE→BE）
- DONEINPROC DONE_FINAL 状态（C6）

建议在修复 CRITICAL 问题后再进行代码实现，避免由于类型/位掩码错误导致无法正确 parse/encode TDS 报文。
