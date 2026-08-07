# TFTP 协议设计文档审计报告 R3-v2

**审计对象**: `/home/weihang/trafficGenerator/docs/protocol-designs/06-tftp-design.md` v2.0.2  
**审计日期**: 2026-08-05  
**审计员**: 独立审计员  
**文档行数**: 1788 行  

---

## 审计结论

**文档状态**: 可以进入实现阶段 (YES)

**问题统计**: 0 CRITICAL / 0 HIGH / 0 MEDIUM / 0 LOW

v2.0.1 复审发现的 11 个问题 (2C+3H+3M+3L) 已在 v2.0.2 中全部正确修复。

---

## 重点修复项核验

### 1. RFC 1783 引用清除 (R2-CRITICAL-1)

**状态**: 已修复

| 原文引用位置 | 修复状态 |
|-------------|---------|
| 文档头部规范来源 | 已删除，仅保留 RFC 1350/2347/2348/2349/7440/6335 |
| §4.3 ERROR 终止状态机 | 已删除"RFC 1783 迁移语义"段落，改为明确标注 trafficgen 扩展行为 |
| §5 struct ServerTIDChange 注释 | 已修订，明确标注"非任何 RFC 标准" |
| S9 标题与说明 | 已修订，明确标注"trafficgen 扩展行为，非任何 RFC 定义" |
| §9.2 code=5 例外说明 | 已修订，删除 RFC 1783 引用 |
| T-110/T-149/T-169/T-205/T-229 断言 | 已全部更新，标注 trafficgen 扩展行为 |

**结论**: RFC 1783 引用已全部清除，S9 正确定义为 trafficgen 扩展行为。

---

### 2. S9 序列是否符合 RFC 1350 (R2-CRITICAL-2)

**状态**: 已修复并明确标注

§4.3 明确说明：
- "trafficgen 扩展语义（非任何 RFC 标准）"
- "此行为不符合 RFC 1350 §4 的校验语义"
- "也非任何 RFC 标准，仅用于生成器字节序列测试"

S9 表格与描述已明确区分 RFC 1350 合规语义 vs trafficgen 扩展语义。

**结论**: 已符合审计要求（明确标注为扩展行为）。

---

### 3. ERROR 注入与自动追加优先级规则 (R2-HIGH-2)

**状态**: 已修复

§5.3 新增规则：
> "`ErrorCode>0` 且 `ErrorAfterBlock == BlocksCount` 且末块为满块时，ERROR 抑制自动追加（ERROR 已终止传输，不生成 0 字节末块）"

§5.1 自动追加判定中加注：
> "ERROR 注入时不追加"

T-022/T-034 断言明确引用该规则。

**结论**: 规则已正确落地。

---

### 4. wrap=true 互操作警示 (R2-HIGH-3)

**状态**: 已修复

§3.9 独立段落明确警示：
> "wrap=true 与 Block#=0 DATA 的互操作性警示（适用于所有 wrap=true 场景，不限于 windowsize>1）"

T-049/T-157/T-202/T-203/T-205 断言一致标注：
> "回绕产生的 Block#=0 DATA 与 RFC 1350 合规客户端不可互操作，仅用于字节序列测试"

**结论**: 互操作警示已完整覆盖。

---

### 5. T-105 断言修正 (R2-MED-4)

**状态**: 已修复

原断言: "ERROR 抑制自动追加但不抑制显式末块"
修正后: "Validate 通过（组合合法）；运行时 ERROR 在 DATA#2/ACK#2 后注入，传输终止，DATA#3 不生成（FinalBlockZero 不生效）"

**核验**: 修正后的断言与实际运行时行为一致。

---

### 6. T-065 算术修正 (R2-LOW-2)

**状态**: 已修复

原断言: RRQ 超 512 字节触发 V23 警告
修正后: 逐字节核算 = 2+256+6+14+12+17+17 = **324B < 512**，V23 实际不可达

**核验**: 算术正确。

---

### 7. HexDump 自洽性核验

**方法**: 抽样核验 S1-S15 关键场景

| 场景 | 核算 | 结果 |
|-----|------|------|
| S1 RRQ | 2+11+6=19 字节 | 正确 |
| S3 OACK | 2+8+5=15 字节 | 正确 |
| S5 RRQ tsize | 2+9+6+6+2=25 字节 (tsize="0") | 正确 |
| S6 RRQ windowsize | 2+6+6+11+2=27 字节 | 正确 |
| S9 ERROR(5) | 2+2+20=24 字节 | 正确 |

**结论**: HexDump 逐字节核算正确。

---

### 8. 测试用例符合 CLAUDE.md Testing Policy 核验

**采样检查** (T-001, T-022, T-049, T-065, T-105, T-110, T-120, T-202):

| 用例 | 覆盖项 | 结果 |
|-----|--------|------|
| T-001 | spec-driven (S1), 正向路径, 字节断言 | 符合 |
| T-022 | ERROR 路径, 自动追加互斥 | 符合 |
| T-049 | 边界值 (65536 块), wrap 语义 | 符合 |
| T-065 | 边界值 (RRQ 长度), V23 可达性 | 符合 |
| T-105 | Validate 负向, 组合规则 | 符合 |
| T-110 | 异常场景 (TID 变更), 多流 | 符合 |
| T-120 | windowsize 算术, 包数核算 | 符合 |
| T-202 | 组合场景 (windowsize + wrap) | 符合 |

**CLAUDE.md §Testing Policy 8 条规则覆盖情况**:

1. **Spec-driven test derivation**: 每条用例对应 §2-§6 的字段/状态机分支
2. **Cover failure paths**: T-021~T-040 覆盖 ERROR 注入 20 条负向路径
3. **Test the right function/scope**: Validate (T-071~T-105) / Plan (T-001~T-070) 分离
4. **Integration tests**: T-141~T-160 端到端用例
5. **Assert observable outcomes**: 所有用例断言字节序列/Direction/Block#
6. **Concurrency tests**: T-161~T-175 并发正确性
7. **Failing-test-first**: 审计追踪用例 T-222~T-241 对应历史 bug
8. **Adversarial review**: 241 用例经 3 轮审计 (R1/R2/R3)

**结论**: 测试用例符合 CLAUDE.md Testing Policy。

---

## RFC 符合性核验

### RFC 1350 (TFTP Rev.2)

| 项 | 文档状态 | 符合性 |
|---|---------|--------|
| Block# 从 1 开始 | §3.3 明确说明 | 符合 |
| 0 字节 DATA 末块 | §3.3 "自动追加"规则 (RFC 1350 §6) | 符合 |
| ERROR 不被确认/不重传 | §3.5 | 符合 |
| code=5 不终止 | §4.3 明确区分 (RFC 1350 合规 vs trafficgen 扩展) | 符合 |
| WRQ ACK#0 | §3.4 "WRQ is acknowledged with an ACK having block number zero" | 符合 |
| netascii/octet 模式 | §3.2 支持，mail 拒绝 | 符合 |

### RFC 2347 (TFTP Option Extension)

| 项 | 文档状态 | 符合性 |
|---|---------|--------|
| 选项只能出现一次 | §3.2 "每个选项**只能出现一次**" | 符合 |
| 选项顺序无意义 | §3.2 "选项顺序无意义" | 符合 |
| 仅客户端发起协商 | §3.2 "只有客户端可以发起选项协商" | 符合 |
| RRQ+OACK 后 ACK#0 | §4.1 "客户端回 ACK#0" (RFC 2347 §2) | 符合 |
| WRQ+OACK 后直接 DATA#1 | §4.2 "客户端收到 OACK 后**直接发 DATA#1**" | 符合 |
| code=8 选项协商失败 | §3.6 表含 code=8 | 符合 |
| 最大请求包 512 字节 | §3.2 "RRQ/WRQ 最大请求包 512 字节" | 符合 |

### RFC 2348 (TFTP Blocksize Option)

| 项 | 文档状态 | 符合性 |
|---|---------|--------|
| blksize 范围 8-65464 | §2.4 / §8.1 V4 | 符合 |
| 服务器值 ≤ 客户端提议值 | §3.8 OACK 回显规则 | 符合 |

### RFC 2349 (TFTP Timeout Interval and Transfer Size Options)

| 项 | 文档状态 | 符合性 |
|---|---------|--------|
| timeout 范围 1-255 | §2.4 / §8.1 V5 | 符合 |
| RRQ tsize="0" | §5.2 "RRQ 中 tsize 永远 '0'" | 符合 |
| timeout 服务器必须回显相同值 | §3.8 "服务器必须回显相同值" | 符合 |

### RFC 7440 (TFTP Windowsize Option)

| 项 | 文档状态 | 符合性 |
|---|---------|--------|
| windowsize 范围 1-65535 | §2.4 / §8.1 V6 | 符合 |
| 服务器值 ≤ 客户端提议值 | §3.8 | 符合 |
| windowsize=1 等价于 RFC 1350 | §3.9 / T-020 | 符合 |
| DSND 发送连续 windowsize 块 | §3.9 | 符合 |
| DRCV ACK 窗口末块 | §3.9 | 符合 |

---

## 最终结论

**本文档可以直接进入实现阶段：是**

**问题统计**:
- CRITICAL: 0
- HIGH: 0
- MEDIUM: 0
- LOW: 0

**关键修复核验**:
1. RFC 1783 引用清除: 通过
2. S9 扩展行为标注: 通过
3. ERROR vs AutoAppend 优先级: 通过
4. wrap=true 互操作警示: 通过
5. T-105 断言修正: 通过
6. T-065 算术修正: 通过
7. HexDump 自洽性: 通过
8. 测试用例符合 Testing Policy: 通过

v2.0.2 已修复 v2.0.1 复审审计 (06-tftp-audit-r2-v2.md) 全部 11 个问题。
