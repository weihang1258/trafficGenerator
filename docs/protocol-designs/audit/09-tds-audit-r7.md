# 09-tds-design.md 第七轮对抗式审计报告

**审计日期**: 2026-08-04
**文档版本**: v1.1.6（审计时版本）
**审计员**: 独立审计员（非设计者）
**文档总行数**: 1291 行
**规范引用**: MS-TDS v20240611

---

## 执行摘要

### 第六轮修复验证结果

| 编号 | 严重度 | 修复状态 | 验证结果 |
|------|--------|----------|----------|
| R6-01 | MEDIUM | §5.8 RowCount(0) 格式不一致 | **已修复** - §5.8 S10 现已使用 `RowCount(00 00 00 00 00 00 00 00)` 完整 hex 表示，并保留版本分支注释 |
| R6-02 | HIGH | §2.6 Token 表 FeatureExtAck/Error 冲突说明 | **已修复** - Error Token 行添加 "Token 流上下文" 注释；FeatureExtAck 行添加 "Pre-Login 响应上下文" 注释，并显式说明同值 0xAA 通过消息类型区分 |
| R6-03 | LOW | §5.4 Row 字段长度前缀说明 | **已修复** - S4 场景 Row 字段已补充 "无长度前缀，定长直接编码" 说明 |
| R6-04 | LOW | §7.10 统计表差异说明 | **已修复** - 表格下方已添加注释，说明 388 vs 324 条差异来源（deferred 小节未编号 + 组合子用例合并计数） |

**结论**: 第六轮 4 处修复已全部正确落地。

---

## 本轮审计发现汇总

### 问题统计

| 严重度 | 数量 |
|--------|------|
| CRITICAL | 0 |
| HIGH | 1 |
| MEDIUM | 3 |
| LOW | 3 |
| **总计** | **7** |

---

## 详细问题清单

### R7-01: §2.9 TypeData 字节序标注错误 [MEDIUM]

**位置**: §2.9 列类型表、§3.5 TDSRPCParam、§5.6 S6 RPC 场景、§7.1 测试用例

**问题描述**:
文档在多处将 TypeData（ColDef/Param 的最大长度字段）标注为 "2B BE"（2 字节大端），但实际 hex 值显示为小端编码。

**证据**:
- §2.9 列类型表: `0xA6 | BIGVARCHAR | 2B BE | 变长字符串`
- §3.5 TDSRPCParam 注释: `// 字节序 2B BE（与 ColDef 一致，见 §2.1 通则）`
- §5.6 S6: `TypeData=0A 00（2B 大端 BE maxlen=10）`
- §7.1.12 用例 1.12.10: `TypeData=0x000A（2B 大端 BE MaxLength）`

**分析**:
Hex 值 `0A 00` 表示数值 10 时：
- 若为大端（BE）：`00 0A` = 2560
- 若为小端（LE）：`0A 00` = 10

文档标注为 "BE" 但 hex 值 `0A 00` 实际对应小端编码。此错误贯穿多个章节。

**依据**: MS-TDS §2.2.5.4 规定 ColDef 的 TypeData 为 USHORT（2 字节小端）。

**修复建议**:
1. §2.9 列类型表中所有 "2B BE" 改为 "2B LE"
2. §3.5 注释 "2B BE" 改为 "2B LE"
3. §5.6 S6 "2B 大端 BE" 改为 "2B 小端 LE"
4. §7.1.12 用例 1.12.10 "2B 大端 BE" 改为 "2B 小端 LE"

---

### R7-02: B_VARCHAR 类型缺乏统一定义且用法矛盾 [MEDIUM]

**位置**: 全文多处使用 B_VARCHAR/US_VARCHAR 的字段

**问题描述**:
文档在多处使用 B_VARCHAR 类型但未提供统一定义，且实际用法与 MS-TDS 规范不符，文档内部也存在矛盾。

**具体矛盾点**:

| 位置 | B_VARCHAR 定义/用法 |
|------|---------------------|
| §2.13 EnvChange | `B_VARCHAR（2B BE 长度 + ASCII 字节）` |
| §7.1.4 用例 1.4.5 | `B_VARCHAR（2B 长度前缀 + 40B UCS-2 LE 数据）`（ProgName） |
| §7.1.5 用例 1.5.13 | `B_VARCHAR（2B LE 长度 + UCS-2 LE）`（ColName） |
| §7.1.8 用例 1.8.7 | `B_VARCHAR（2B BE 长度 + ASCII）`（MsgText） |
| §7.1.12 用例 1.12.1 | `B_VARCHAR（2B BE 长度 + UCS-2 LE）`（ProcName） |

**问题分析**:
1. **文档内部矛盾**: B_VARCHAR 被定义为有时使用 2B BE、有时使用 2B LE 长度前缀；有时使用 ASCII、有时使用 UCS-2 LE 数据
2. **与 MS-TDS 不符**: 根据 MS-TDS §2.2.5.4，B_VARCHAR 应为 `1-byte 长度前缀 + ASCII 数据`；US_VARCHAR 应为 `2-byte 长度前缀（LE）+ UCS-2 LE 数据`
3. **实际使用情况**:
   - ProgName (LoginAck) 实际使用 US_VARCHAR（2B LE + UCS-2 LE），但文档标记为 B_VARCHAR
   - ColName (ColDef) 实际使用 US_VARCHAR（2B LE + UCS-2 LE），但文档标记为 B_VARCHAR
   - MsgText (Error Token) 实际使用 B_VARCHAR（1B + ASCII），但文档描述为 2B BE 长度

**依据**:
- MS-TDS §2.2.5.4: B_VARCHAR = BYTE Length + ASCII chars
- MS-TDS §2.2.5.4: US_VARCHAR = USHORT Length (LE) + UCS-2 LE chars

**修复建议**:
1. 在 §2 开头添加 "通用类型定义" 小节，明确定义：
   - `B_VARCHAR`: 1-byte 长度前缀 + ASCII 数据
   - `US_VARCHAR`: 2-byte 小端长度前缀 + UCS-2 LE 数据
2. 修正所有字段类型标记：
   - ProgName (LoginAck): B_VARCHAR → US_VARCHAR
   - ColName (ColDef): B_VARCHAR → US_VARCHAR
3. 修正 §2.13 EnvChange 中的 B_VARCHAR 定义（若用于 Database/Language 等应为 B_VARCHAR 1B + ASCII，但文档说 2B BE）

---

### R7-03: OptionFlags1/OptionFlags3/TypeFlags/ColDef.Flags 位定义缺失 [MEDIUM]

**位置**: §2.4.1 Login7 固定头部、§2.7.1 ColDef 布局

**问题描述**:
文档仅提供了 OptionFlags2 的位定义（§2.4.1），但 OptionFlags1、OptionFlags3、TypeFlags 和 ColDef.Flags 的位定义完全缺失。

**缺失内容**:
| 字段 | 当前状态 | 默认值 | 问题 |
|------|----------|--------|------|
| OptionFlags1 | 仅标注 "标志位 1" | 0xE0（§7.1.3 用例 1.3.4） | 无位定义说明 |
| OptionFlags3 | 仅标注 "标志位 3" | 0x00（§7.1.3 用例 1.3.8） | 无位定义说明 |
| TypeFlags | 仅标注 "类型标志" | 0x00（§7.1.3 用例 1.3.7） | 无位定义说明 |
| ColDef.Flags | 仅标注 "列标志" | — | 无位定义说明 |

**依据**:
- MS-TDS §2.2.6.4 定义了 OptionFlags1/2/3 的各位含义
- MS-TDS §2.2.7.4 定义了 ColDef Flags 的各位含义

**修复建议**:
1. 在 §2.4.1 添加 OptionFlags1 位定义（bit0-bit7）
2. 在 §2.4.1 添加 OptionFlags3 位定义（bit0-bit7）
3. 在 §2.4.1 添加 TypeFlags 位定义（bit0-bit3）
4. 在 §2.7.1 添加 ColDef.Flags 位定义（如 fNullable、fCaseSen 等）

---

### R7-04: §5.4 S4 场景 ColName hex 值含义不明 [LOW]

**位置**: §5.4 S4 SQL Batch SELECT，第 703 行

**问题描述**:
S4 场景响应中的 ColName 字段显示为 `ColName=02 00 00 00`，但未说明该列名的实际含义。

**分析**:
- `02 00` = 长度 2（LE）
- `00 00` = UCS-2 LE 字符 0x0000（NUL）

对于 `SELECT 1` 查询，SQL Server 通常返回自动生成的列名（如空字符串或 "(No column name)"）。Hex 值 `02 00 00 00` 表示一个 1 字符的列名，字符值为 0x0000（NUL），这与典型 SQL Server 行为不符。实际应为空字符串（长度=0：`00 00`）或有意义的列名。

**修复建议**:
补充说明该列名的语义，或修正为更合理的示例值（如 `ColName=00 00` 表示空列名，或 `ColName=02 00 3F 00` 表示 "?" 作为列名）。

---

### R7-05: §5.8 Info 场景 Number/State/Class/LineNumber 格式不一致 [LOW]

**位置**: §5.8 S10 Info 响应，第 749 行

**问题描述**:
§5.8 Info 场景中的数字字段格式与其他场景不一致：
- §5.7 S9 Error: `Number(102=0x00000066)`、`State(01)`、`Class(0F=15)`、`LineNumber(01 00 00 00)`
- §5.8 S10 Info: `Number(0)`、`State(1)`、`Class(0)`、`LineNumber(1)`

Info 场景使用十进制简写而非 hex 字节表示，与 Error 场景的详细 hex 表示不一致。

**修复建议**:
将 §5.8 S10 的字段表示统一为 hex 格式：
- `Number(00 00 00 00)`
- `State(01)`
- `Class(00)`
- `LineNumber(01 00 00 00)`

---

### R7-06: 测试用例统计表计数方法不透明 [LOW]

**位置**: §7.10 测试用例统计表

**问题描述**:
虽然 R6-04 添加了注释说明 388 vs 324 的差异，但注释中的 "各小节中未单独列出的组合/边界子用例（如 §7.1.6 用例 1.6.13 含 5 种子情况按 1 条计）" 缺乏具体枚举，实现阶段难以验证。

**修复建议**:
1. 在 §7.10 添加详细的 "测试用例编号映射表"，列出所有 388 条用例的编号、位置和简要描述
2. 或提供脚本/工具用于自动统计和验证

---

### R7-07: §2.4.1 Login7 固定头部大小缺乏依据 [LOW]

**位置**: §2.4.1、§5.3

**问题描述**:
文档声明 Login7 固定头部为 86 字节，但未提供字段分解说明。按 §2.4.1 列出的字段（Length 到 ClientLCID）计算为 36 字节，与 86 字节差距较大。

**分析**:
MS-TDS §2.2.6.4 定义的 Login7 结构包含：
- 基础字段（lLength 到 ulClientLCID）：36 字节
- 偏移表（cb/cch 对）：40 字节
- 其他字段：可能包含 ClientID(6B) 等

文档将 "固定头部" 定义为 86 字节，但未明确包含哪些字段，可能导致实现时计算偏移错误。

**修复建议**:
在 §2.4.1 添加 Login7 固定头部的字段分解表，明确 86 字节的组成部分。

---

## 章节完整性检查

### 关键章节存在性检查

| 章节 | 状态 | 备注 |
|------|------|------|
| §1 协议概述 | 存在 | 完整 |
| §2 数据类型与字段定义 | 存在 | **缺少通用类型定义小节**（B_VARCHAR/US_VARCHAR 正式定义） |
| §3 配置与类型定义 | 存在 | 6 个结构体完整 |
| §4 消息结构与状态机 | 存在 | 状态机图完整 |
| §5 包序列 | 存在 | S1-S12 场景完整 |
| §6 场景表格 | 存在 | 引用 §5 |
| §7 测试用例 | 存在 | 用例完整 |
| §8 Validate 规则 | 存在 | 规则表完整 |
| §9 错误处理 | 存在 | 错误码表完整 |
| §10 扩展字段映射 | 存在 | 延期类型表完整 |
| §16 修订记录 | 存在 | v1.1.6 修订记录完整 |

**缺失**: §2 缺少 "通用类型定义" 小节，导致 B_VARCHAR/US_VARCHAR 用法混乱。

---

## HexDump 自洽性检查

### 逐字节格式一致性

| 检查项 | 状态 | 备注 |
|--------|------|------|
| TDS 包头字段 | 一致 | Type/Status/Length/SPID/PacketID/Window 格式统一 |
| Login7 固定头部 | **存疑** | 86 字节定义缺乏分解说明 |
| ColDef 字段顺序 | 一致 | UserType→Flags→Type→TypeData→Collation→ColName |
| RowCount 版本分支 | 已修复 | 所有场景已添加 TDS 7.3+ vs 7.1/7.2 分支注释 |
| RPC Param Name | 已修复 | 1B NameLen 格式统一 |
| Token 值冲突 | 已修复 | 0xAA 上下文区分已添加 |
| TypeData 字节序 | **错误** | 文档标注 "BE" 但实际应为 "LE" |
| B_VARCHAR 编码 | **矛盾** | 不同章节定义不一致 |
| ColName hex 值 | **存疑** | S4 场景 02 00 00 00 含义不明 |
| Info 数字字段 | **不一致** | 使用十进制而非 hex |

---

## 测试用例质量审查

### CLAUDE.md Testing Policy 符合性检查

| 规则 | 符合性 | 备注 |
|------|--------|------|
| 规则 1: Spec-driven test derivation | 符合 | 用例与 SPEC 字段对应 |
| 规则 2: Cover failure paths | 符合 | §7.7 Validate 错误路径已覆盖 |
| 规则 3: Test the right function/scope | **部分符合** | TypeData 字节序错误导致测试用例 1.5.16/1.5.20/1.12.10 可能测试错误编码 |
| 规则 4: Integration tests | 符合 | §7.3 集成测试完整 |
| 规则 5: Assert observable outcomes | 基本符合 | Hex 断言为主，但部分 hex 值含义需澄清 |
| 规则 6: Concurrency tests verify correctness | 符合 | §7.5 并发测试包含 -race |
| 规则 7: Failing-test-first for bug fix | 无法验证 | 文档阶段不涉及 |
| 规则 8: Adversarial review of test quality | 进行中 | 本审计执行 |

**测试用例风险点**:
- 用例 1.5.16、1.5.20、1.12.10 涉及 TypeData 字节序，若实现按文档 "BE" 标注编码，将导致 wire 格式错误

---

## 最终结论

### 修复验证结论

**第六轮 4 处修复已全部正确落地**:
- R6-01 (MEDIUM): §5.8 RowCount 格式已统一为完整 hex
- R6-02 (HIGH): §2.6 FeatureExtAck/Error Token 上下文区分已添加
- R6-03 (LOW): §5.4 Row 字段长度前缀说明已补充
- R6-04 (LOW): §7.10 统计表差异注释已添加

### 本轮审计结论

**本文档是否可以直接进入实现阶段：否**

**必须先返工的问题**:

| 优先级 | 问题 | 严重度 |
|--------|------|--------|
| P1 | R7-01 TypeData 字节序标注错误（BE→LE） | MEDIUM |
| P2 | R7-02 B_VARCHAR 类型定义缺失与用法矛盾 | MEDIUM |
| P3 | R7-03 OptionFlags1/3/TypeFlags/Flags 位定义缺失 | MEDIUM |

**理由**:
1. **R7-01 是编码错误**: TypeData 字节序标注为 "BE" 但实际应为 "LE"，将导致实现生成的 wire 格式与 MS-TDS 不兼容
2. **R7-02 是设计缺陷**: B_VARCHAR/US_VARCHAR 缺乏统一定义，不同章节用法矛盾，实现者无法确定正确编码
3. **R7-03 是文档不完整**: 关键标志位缺乏定义，实现者无法正确设置这些字段

**可在实现阶段同步修复**:
- R7-04 (LOW): S4 ColName hex 含义
- R7-05 (LOW): Info 场景数字字段格式
- R7-06 (LOW): 测试用例统计方法透明化
- R7-07 (LOW): Login7 固定头部大小说明

---

## 附录: 问题优先级排序（全量）

| 优先级 | 问题 | 严重度 | 修复建议 |
|--------|------|--------|----------|
| P1 | R7-01 TypeData 字节序错误 | MEDIUM | 全文 "2B BE" → "2B LE" |
| P2 | R7-02 B_VARCHAR 定义缺失 | MEDIUM | 添加通用类型定义小节 |
| P3 | R7-03 标志位定义缺失 | MEDIUM | 添加位定义表 |
| P4 | R7-04 S4 ColName 含义 | LOW | 补充列名说明或修正 hex |
| P5 | R7-05 Info 字段格式 | LOW | 统一为 hex 表示 |
| P6 | R7-06 用例计数透明化 | LOW | 添加编号映射表 |
| P7 | R7-07 Login7 头部说明 | LOW | 添加字段分解表 |

---

*审计报告完成*
