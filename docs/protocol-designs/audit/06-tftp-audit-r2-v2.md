# TFTP 设计文档复审审计报告（v2.0.1，第二轮）

**审计对象**：`/home/weihang/trafficGenerator/docs/protocol-designs/06-tftp-design.md`（v2.0.1，约 1732 行）
**审计依据**：RFC 1350（TFTP Rev.2）、RFC 2347（选项扩展）、RFC 2348（blksize）、RFC 2349（timeout/tsize）、RFC 7440（windowsize）、RFC 1783（实际为 TFTP Blocksize Option，**非** TID 变更机制）、RFC 6335（端口范围）、CLAUDE.md §Testing Policy 8 条规则
**审计方法**：交叉对抗——逐节对照 RFC 原文尝试反驳设计正确性，默认"有 bug"；逐字节核算全部 HexDump；测试用例按 CLAUDE.md 8 条规则逐条审核；核实 v2.0.0 复审 17 项修复是否正确落地
**审计员**：独立审计员（v2.0.1 复审，与 v2.0.0 复审员不同）
**审计日期**：2026-08-05

---

## 1. 审计概览

### 1.1 v2.0.0 复审 17 项修复落地核对

v2.0.1 声明修复了 v2.0.0 复审（`06-tftp-audit-r1-v2.md`）发现的全部 17 个问题（3 CRITICAL + 5 HIGH + 6 MEDIUM + 3 LOW）。逐项核对：

| v2.0.0 复审问题 | v2.0.1 修复 | 结论 |
|----------------|-------------|------|
| R1-CRITICAL-1（S9 TID 变更语义） | 引入 RFC 1783 迁移语义 | **未修复**——RFC 1783 实际是 "TFTP Blocksize Option"，**不**含 TID 变更机制。详见本次 R2-CRITICAL-1 |
| R1-CRITICAL-2（ErrorCode=0 语义统一） | §5 struct/§5.1/§5.3/§5.4/§8.1 V9/§9.2/T-227~T-228 六处对齐 | 部分修复——内部一致性达成，但语义选择"ErrorCode=0 + ErrorAfterBlock=0 不注入"在 omitempty 下与"未设置"不可区分，属可接受权衡。**已修复** |
| R1-CRITICAL-3（AutoAppendFinalBlock 改为"末块满块即追加"） | §5.1 规则改为"末块 Data 长度 == BlkSize 即追加"，与 tsize 解耦 | **已修复**——S3/S4/S6/S9/S10 等场景与 T-053/T-062 等用例联动修订，自洽 |
| R1-HIGH-1（§5.4 表 "Unknown transfer ID" 21→20） | §5.4 表改为 20；T-027 同步 | **已修复** |
| R1-HIGH-2（S9 第 7 行注释矛盾） | 改为 RFC 1783 迁移语义注释 | 随 R2-CRITICAL-1 重新评估——注释本身已自洽，但 RFC 引用错误 |
| R1-HIGH-3（T-202 次窗口 464→4465） | T-202 改为 4465 | **已修复** |
| R1-HIGH-4（RFC 7440 末窗口与 S6 冲突） | S6 改为 15 包（含自动追加）；T-009/T-145 同步 | **已修复** |
| R1-HIGH-5（T-120 9→10 包） | T-120 改为 10 包 | **已修复** |
| R1-MED-1（§5.4 表 9 行字节数全修正） | 12/15/17/33/23/20/20/13/28 | **已修复**（逐字节核算通过） |
| R1-MED-2（§9.3 双 `\0` 矛盾） | 删除矛盾表述；明确空 ErrMsg 无法通过字段表达 | **已修复** |
| R1-MED-3（T-019 blocks_count=3→2） | T-019 改为 blocks_count=2 | **已修复** |
| R1-MED-4（wrap 与 windowsize 交互规则） | §3.9 新增交互规则；T-203 断言明确 | **已修复** |
| R1-MED-5（S6 行 858 与 §5.1 矛盾消除） | 随 R1-CRITICAL-3 处理 | **已修复** |
| R1-MED-7（T-065 超限子用例） | 改为 filename=255 + 全 4 选项 | **已修复** |
| R1-LOW-4（S13c/T-048 末块满块自动追加注明） | S13c/T-048 加注 | **已修复** |
| R1-LOW-5（§2.4 错误消息 netascii 注） | §2.4 加注 | **已修复** |
| R1-LOW-6（T-163 断言依赖 FlowID 构成） | T-163 加注 | **已修复** |

**小结**：17 项中 16 项已正确落地，但 **R1-CRITICAL-1 的修复基于错误的 RFC 引用**（RFC 1783 实际是 Blocksize Option，不是 TID 变更机制），导致 S9 的整个语义基础崩塌。这是本次复审发现的最严重问题。

### 1.2 v2.0.1 新发现问题汇总

| 严重度 | 数量 | 关键问题 |
|--------|------|----------|
| CRITICAL | 2 | RFC 1783 引用错误（S9 整个语义基础崩塌）；S9 序列本身不符合任何已知 RFC 的 TID 迁移流程 |
| HIGH | 3 | §4.3 两种语义区分仍依赖错误 RFC；T-022 ERROR 优先于自动追加的判定规则未在 §5.3 明确；§3.9 wrap+windowsize 的 Block#=0 DATA 与 RFC 1350 "DATA Block# 恒 ≥1" 冲突的互操作性风险未充分警示 |
| MEDIUM | 3 | S9 自动追加包数核算说明口径不一（10 包 vs 12 包并存）；§9.4 半标准流表格中 "ErrorCode 注入于末块后" 表述模糊；T-105 断言与实际运行时行为相反 |
| LOW | 3 | §1.1 最大文件大小近似值精度；T-065 子用例算术错误（V23 实际不可触发）；§11 修订记录撤回说明可简化 |
| **总计** | **11** | — |

（另：§5.4 表 code=0 "Not defined" 字节数 12 经核算正确，列入 §4 核实记录，不构成问题。）

### 1.3 总体评级

**不合格（不可直接进入实现阶段）**。v2.0.1 在内部一致性上较 v2.0.0 有显著进步（16/17 项修复正确落地，§5.4 字节数全表修正，自动追加规则统一），但 **R1-CRITICAL-1 的修复引用了错误的 RFC**——RFC 1783 的标题是 "TFTP Blocksize Option"（RFC 2348 的前身），其内容**完全不包含** TID 变更机制。S9 场景的整个语义基础（"RFC 1783 §3 TID 迁移"）是虚构的。这意味着：

1. S9 场景的 ERROR(5) 发向新 TID 后继续传输的行为，**没有任何 RFC 依据**。
2. §4.3 中"RFC 1350 校验语义 vs RFC 1783 迁移语义"的二分法是错误的——只有 RFC 1350 一种语义（向错误源回 ERROR(5) 后丢弃该包、继续原 TID 传输）。
3. T-110/T-149/T-169/T-205/T-229 等用例期望"ERROR(5) 后继续向新 TID 传输"，违反 RFC 1350 §4。

必须在 §4.3/S9/§5 ServerTIDChange 字段注释中删除对 RFC 1783 的引用，并重新定义 S9 的语义（推荐：明确标注为"trafficgen 扩展行为，非任何 RFC 定义"或改为符合 RFC 1350 的"NAT/中间件 TID 重写导致的 TID 漂移"场景）。

---

## 2. CRITICAL 问题

### R2-CRITICAL-1：RFC 1783 引用错误——S9 TID 迁移语义的整个基础是虚构的

**位置**：文档头部规范来源（行 3）、§4.3（行 354-355）、§5 ServerTIDChange 注释（行 526-533）、S9（行 964-997）、§11 修订记录（行 1626）

**描述**：v2.0.1 为修复 R1-CRITICAL-1，将 S9 的语义基础从"RFC 1350 校验语义"改为"RFC 1783 §3 TID 迁移语义"。文档多处明确引用 RFC 1783 作为 TID 变更机制的依据：

- 行 3：`RFC 1783（TFTP Options Negotiation 的前身——定义 TID 变更（transfer identifier change）机制的 Informational RFC）`
- 行 354：`TID 迁移语义（RFC 1783 §3，Informational）`
- 行 527：`语义为 RFC 1783 TID 迁移（非 RFC 1350 校验语义）`
- 行 964：`S9 TID 变更（ERROR code=5 不终止传输 — RFC 1783 TID 迁移语义）`
- 行 978：`本场景模拟 RFC 1783 §3 的 TID change 机制（Informational）`

**问题**：**RFC 1783 的实际标题是 "TFTP Blocksize Option"**（作者 G. Malkin 和 A. Harkin，1995 年 3 月），是 RFC 2348（TFTP Blocksize Option）的前身。其内容**仅**讨论 blksize 选项协商，**完全不包含**任何 TID 变更、transfer identifier change、ERROR code 5 或 Unknown transfer ID 的内容。RFC 1783 的章节结构为：

1. Status of this Memo
2. Abstract（介绍 blksize 选项）
3. Blocksize Option Specification（blksize 协商规则）
4. Proof of Concept（性能测试）
5. Security Considerations
6. References（引用 RFC 1350 和 RFC 1782）
7. Authors' Addresses

经 WebFetch 核实 RFC 1783 原文（https://www.rfc-editor.org/rfc/rfc1783.txt）：
> "Title: TFTP Blocksize Option... None of these appear anywhere in the document. There is no mention of TID change, transfer identifier change, ERROR code 5, or 'Unknown transfer ID.'"

**这意味着**：
1. S9 场景的"RFC 1783 §3 TID 迁移语义"是**虚构的引用**——RFC 1783 §3 实际是 "Blocksize Option Specification"，讨论的是 blksize 选项，不是 TID 变更。
2. §4.3 中"RFC 1350 校验语义 vs RFC 1783 迁移语义"的二分法不成立——只有 RFC 1350 一种 TID 校验语义。
3. S9 包序列（ERROR(5) 发向新 TID 后继续向新 TID 传输）**不符合任何已知 RFC**。
4. v2.0.0 复审 R1-CRITICAL-1 的修复建议（方案 A：引用 RFC 1783）基于对 RFC 1783 内容的误解，v2.0.1 采纳了该建议但未核实 RFC 原文。

**TID 变更机制的实际情况**：TFTP 的 TID 变更（NAT 重写导致的源端口漂移）在现实网络中确实存在，但**没有任何 RFC 定义"服务器主动切换 TID"的机制**。RFC 1350 §4 只定义了"收到源 TID 不匹配的包时向错误源回 ERROR(5) 并继续原传输"的校验语义。某些 TFTP 实现（如 tftp-hpa）在检测到对端 TID 变化时会发送 ERROR(5) 并**接受**新 TID，但这属于实现扩展行为，非 RFC 标准。

**依据**：RFC 1783 原文（标题 "TFTP Blocksize Option"，内容仅涉 blksize）；RFC 1350 §4（TID 校验语义）；文档自身对 RFC 1783 的多处引用（行 3/354/527/964/978）。

**修复建议**（必选其一）：

- **方案 A（推荐）**：删除全部 RFC 1783 引用，明确标注 S9 为"trafficgen 扩展行为，模拟 NAT/中间件导致的 TID 漂移场景，非任何 RFC 定义"。具体改动：
  - 行 3 规范来源：删除 `RFC 1783（...TID 变更机制...）`，改为 `（无 RFC 依据，trafficgen 扩展场景）` 或完全不列。
  - §4.3（行 354-355）：删除"RFC 1783 §3 TID 迁移语义"段落，改为"trafficgen 扩展语义：模拟 NAT/中间件 TID 漂移。ERROR(5) 发向新 TID 表示'包源 TID 与约定不符'，随后接受新 TID 继续。此行为非 RFC 1350 校验语义（RFC 1350 下 ERROR(5) 后丢弃该包、继续旧 TID），也非任何 RFC 标准，仅用于生成器字节序列测试。"
  - §5 ServerTIDChange 注释（行 526-533）：删除"RFC 1783 TID 迁移"表述，改为"trafficgen 扩展（非 RFC 标准）"。
  - S9 标题与说明（行 964-978）：删除"RFC 1783"引用，改为"trafficgen 扩展 TID 漂移场景"。
  - §11 修订记录（行 1626）：R1-CRITICAL-1 修复要点改为"引入 trafficgen 扩展 TID 漂移语义（非 RFC 标准）"。
  - T-110/T-229 等用例断言中"RFC 1783 迁移语义"表述同步修改。

- **方案 B**：将 S9 改为符合 RFC 1350 校验语义的场景——服务器 TID 不变，模拟"第三方主机"向客户端发送伪造的 TFTP 包（源 TID 不匹配），客户端向该第三方回 ERROR(5) 并继续原传输。但此场景与 `ServerTIDChange` 字段语义不符（字段名暗示服务器主动切换），需重命名字段。

- **方案 C**：若坚持"服务器主动切换 TID"场景，必须明确标注"此行为违反 RFC 1350 §4（RFC 1350 下客户端应丢弃新 TID 的包并继续等待旧 TID）"，并将 S9 移入"互操作负向测试"分类（类似 §9.4 半标准流）。T-110/T-229 等用例断言需明确"该流与 RFC 1350 合规客户端不可互操作"。

**无论选哪个方案，必须删除对 RFC 1783 的全部引用**——RFC 1783 是 Blocksize Option，与 TID 无关。

### R2-CRITICAL-2：S9 包序列不符合任何已知 RFC 的 TID 迁移流程

**位置**：S9 包序列表（行 982-995）

**描述**：S9 期望的包序列为：
```
6. DATA#3（down, 61000 → C）          服务器主动切换到新 TID
7. ERROR(5)（up, C → 61000）          客户端向新 TID 发，表示"尚未完成迁移"
8. ACK#3（up, C → 61000）             客户端接受新 TID，继续以新 TID 应答
9. DATA#4（down, 61000 → C）
10. ACK#4（up, C → 61000）
```

**问题**：
1. **不符合 RFC 1350 校验语义**：RFC 1350 §4 明确"收到源 TID 不匹配的包应**丢弃该包**并继续原传输"——客户端收到 61000 的 DATA#3 后应丢弃，不回 ACK#3，继续等待 60000 的 DATA#3。S9 第 8 行 ACK#3 发给 61000 违反此规则。
2. **不符合任何 RFC 的迁移流程**：由于 R2-CRITICAL-1（RFC 1783 不含 TID 迁移），S9 序列无 RFC 依据。
3. **逻辑不自洽**：第 7 行 ERROR(5) 的语义是"包源 TID 与约定不符"（约定为 60000），但第 8 行立即向 61000 发 ACK#3——等于客户端在收到 ERROR 后立即改变"约定 TID"为 61000，ERROR(5) 的"拒绝"语义失去意义。真实 TFTP 客户端（如 tftp-hpa）的 TID 漂移处理通常是：检测到新 TID 后直接更新会话 TID（不先发 ERROR 再更新），或发 ERROR 后**等待对方重发**才接受。
4. **缺少"服务器重发 DATA#3"步骤**：若 ERROR(5) 表示"我不认 61000"，符合逻辑的后续是服务器重发 DATA#3（用 61000），客户端再次检测……直到客户端实现决定接受。S9 直接从 ERROR(5) 跳到 ACK#3，缺少重发环节。

**依据**：RFC 1350 §4（TID 校验语义）；逻辑一致性。

**修复建议**：随 R2-CRITICAL-1 一并处理。若采用方案 A（trafficgen 扩展），S9 序列可保持现状但必须明确标注"非 RFC 互操作流，仅用于生成器字节序列测试"。若采用方案 B，S9 序列需重写。若采用方案 C，S9 需移入负向测试。

---

## 3. HIGH 问题

### R2-HIGH-1：§4.3 两种语义区分仍依赖错误的 RFC 1783 引用

**位置**：§4.3（行 354-355）

**描述**：§4.3 明确区分两种语义：
> "TID 迁移语义（RFC 1783 §3，Informational）：RFC 1350 未定义'服务器中途主动更换 TID'的行为；RFC 1783 定义了 TID change（传输标识变更）机制……"

**问题**：随 R2-CRITICAL-1——RFC 1783 不含 TID change 机制，§4.3 的"两种语义"二分法不成立。实际只有 RFC 1350 一种语义（向错误源回 ERROR(5) 后丢弃该包、继续原 TID 传输）。`ServerTIDChange=true` 走的"RFC 1783 迁移语义"是虚构的。

**依据**：RFC 1783 原文（Blocksize Option，无 TID 内容）。

**修复建议**：随 R2-CRITICAL-1 一并处理。删除"RFC 1783 迁移语义"表述，改为"trafficgen 扩展语义"或"非 RFC 标准行为"。

### R2-HIGH-2：T-022 "ERROR 优先于自动追加"判定规则未在 §5.3 明确

**位置**：T-022（行 1194）、§5.3（行 595-608）

**描述**：T-022 输入 `mode=read, blocks_count=3, data_payload_pattern=0xAA, error_code=2, error_after_block=3, error_side=server`，期望 "RRQ → DATA/ACK×3 → ERROR(2)（8 包）"，断言 "ERROR 于 ACK#3 后；ERROR 优先于自动追加（无 0 字节末块）"。

**问题**：
1. T-022 的 blocks_count=3，BlkSize=512（默认），3×512=1536。末块 #3 是满块（512B），按 §5.1 自动追加规则应追加 DATA#4(0B)。但 T-022 期望 8 包 = 1(RRQ) + 3×2(DATA/ACK) + 1(ERROR) = 8，**不含自动追加的 DATA#4(0B)/ACK#4**。
2. T-034（行 1206）更明确："error_code=1, error_after_block=3, blocks_count=3, client_tsize=1536... RRQ → DATA/ACK×3 → ERROR(1)（8 包），ERROR 优先：3×512=1536=TSize 但 ERROR 抑制自动追加"。
3. **§5.3 未明确此规则**：§5.3 列出了 ErrorCode 与 BlocksCount/ErrorAfterBlock 的组合规则，但**未提及 ERROR 注入与自动追加的优先级**。实现者读 §5.3 无法推断"ERROR 抑制自动追加"。
4. §9.4（行 1545）表格中有一行 "ErrorCode 注入于末块后 | ERROR 抑制自动追加（ERROR 已终止传输）"，但这在 §9.4"半标准流生成"章节下，属于负向测试分类，而非 §5.3 的正向规则。

**依据**：CLAUDE.md §Testing Policy 第 1 条（spec 必须无歧义）；§5.3 字段互斥规则表未覆盖 ERROR vs AutoAppend 优先级。

**修复建议**：§5.3 新增一条规则："ErrorCode>0 注入时，若 ErrorAfterBlock == BlocksCount 且末块为满块，ERROR 抑制自动追加（ERROR 已终止传输，不再生成 0 字节末块）。" 同步在 §5.1 自动追加判定规则中加注"ERROR 注入时不追加"。

### R2-HIGH-3：§3.9 wrap+windowsize 的 Block#=0 DATA 与 RFC 1350 冲突的互操作性风险未充分警示

**位置**：§3.9（行 270）

**描述**：§3.9 行 270 已加注："DATA 中 Block#=0 只在回绕后出现（发送序 i 为 65536 的倍数时 `i mod 65536 = 0`）；RFC 1350 中 DATA 的 Block# 恒 ≥1（0 只出现在 ACK 中），回绕产生 Block#=0 的 DATA 属 trafficgen 生成器回绕语义（S13d/T-049/T-157），不承诺与真实实现互操作。"

**问题**：
1. 该注已警示互操作性风险，但**警示强度不足**——Block#=0 的 DATA 在 RFC 1350 合规接收方眼中会被误判为"ACK#0"（opcode 3 vs 4 区分，但某些实现可能基于 Block#=0 做特殊处理）。
2. T-049/T-157/T-203/T-205 等用例期望生成 Block#=0 的 DATA，但未在用例断言中明确"此 DATA 与 RFC 1350 合规客户端不可互操作"。
3. §3.9 行 269 已说明"该组合（windowsize>1 + wrap=true）在真实 TFTP 中无互操作性保证"，但**单独的 wrap=true（无 windowsize）**也有同样的 Block#=0 DATA 问题，§3.9 未单独警示。

**依据**：RFC 1350 §4（DATA Block# 从 1 开始）；文档 §3.9。

**修复建议**：
1. §3.9 行 270 的警示移至独立段落，适用于所有 wrap=true 场景（不仅限 windowsize>1）。
2. T-049/T-157/T-202/T-203/T-205 用例断言中明确"回绕产生的 Block#=0 DATA 与 RFC 1350 合规客户端不可互操作，仅用于字节序列测试"。

---

## 4. MEDIUM 问题

### R2-MED-1：S9 自动追加包数核算说明口径不一

**位置**：S9 表注（行 994-995）、T-110（行 1297）

**描述**：S9 表注（行 994-995）写："S9 序列聚焦 TID 迁移流程，未列出末块满块后的自动追加 DATA#5(0B)/ACK#5（实际生成时会追加，T-110/T-149 的断言以'10 包迁移序列 + 自动追加 2 包 = 12 包'为准；本表 10 包为迁移流程的核心包）。"

T-110（行 1297）写："10 包迁移序列（见 S9 表）+ 自动追加 DATA#5(0B)/ACK#5 = 12 包"。

**问题**：
1. S9 输入 `blocks_count=4, data_payload_pattern=0xAA`，BlkSize=512（默认），4×512=2048。末块 #4 是满块 → 自动追加 DATA#5(0B)。
2. S9 表列出 10 包（含 DATA#4/ACK#4），自动追加后应为 12 包。S9 表注与 T-110 一致（10+2=12）。
3. **但 T-149（行 1346）写 "PCAP 12 包"**，与 T-110 一致。**核算通过**。
4. **口径问题**：S9 表本身标"期望包序列（10 包）"，但实际生成 12 包。读者读 S9 时容易误以为最终输出是 10 包。S9 表注虽已说明，但"10 包"与"12 包"并存仍可能造成实现者困惑。

**依据**：文档内部一致性。

**修复建议**：S9 表标题改为"期望包序列（10 包迁移核心 + 2 包自动追加 = 12 包）"，或在表内直接列出 DATA#5(0B)/ACK#5 两行（标注"自动追加"）。

### R2-MED-2：§5.4 表 code=0 "Not defined" 字节数需核实

**位置**：§5.4（行 620）

**描述**：§5.4 表 code=0 "Not defined" 字节数（含 `\0`）标注为 12。

**核算**："Not defined" 是 11 个字符（N-o-t-空-d-e-f-i-n-e-d），+1 个 `\0` = 12 字节。**核算通过**。

但 T-134（行 1326）"ERROR 字节精确（默认映射）" 输入 `error_code=1, error_msg=""`，期望 `00 05 00 01 46 69 6c 65 20 6e 6f 74 20 66 6f 75 6e 64 00`（19B：2+2+15）。**"File not found" = 14 字符 + 1 = 15 字节**，核算通过。

**结论**：§5.4 表字节数全部正确（12/15/17/33/23/20/20/13/28）。本条不构成问题，记录为核实通过。

### R2-MED-3：§9.4 半标准流表格 "ErrorCode 注入于末块后" 表述模糊

**位置**：§9.4（行 1545）

**描述**：§9.4 表格最后一行：
> | ErrorCode 注入于末块后 | ERROR 抑制自动追加（ERROR 已终止传输） |

**问题**："ErrorCode 注入于末块后"表述模糊——是指 ErrorAfterBlock == BlocksCount（末块后注入），还是 ErrorAfterBlock > BlocksCount（越界）？后者会被 Validate 拒绝（V9）。应明确为"ErrorAfterBlock == BlocksCount 时"。

**依据**：CLAUDE.md §Testing Policy 第 1 条（spec 无歧义）。

**修复建议**：§9.4 表格该行改为 "ErrorAfterBlock == BlocksCount（末块后注入 ERROR）| ERROR 抑制自动追加（ERROR 已终止传输，不再生成 0 字节末块）"。

### R2-MED-4：T-105 "ERROR 抑制自动追加但不抑制显式末块"语义需明确

**位置**：T-105（行 1287）

**描述**：T-105 输入 `error_after_block=2, final_block_zero=true, blocks_count=3`，期望"通过（ERROR 抑制自动追加但不抑制显式末块；ERROR 先发则无末块）"。

**问题**：
1. T-105 是 Validate 用例（期望通过），但其断言"ERROR 先发则无末块"涉及运行时行为，不是 Validate 检查项。Validate 阶段无法判断"ERROR 先发还是末块先发"。
2. error_after_block=2, blocks_count=3, final_block_zero=true：若 ERROR 在 DATA#2 后注入，则传输在 ERROR 处终止，**不会生成 DATA#3（显式末块）**——因为 ERROR 终止传输。若 ERROR 在 DATA#3 后注入（error_after_block=3），则 DATA#3 已生成（0 字节末块），ERROR 在其后。T-105 的 error_after_block=2 < blocks_count=3，所以 ERROR 在 DATA#2 后，DATA#3 不会生成。
3. "ERROR 抑制自动追加但不抑制显式末块"表述与实际行为相反——error_after_block=2 时既不生成自动追加块，也不生成显式末块（DATA#3），因为 ERROR 已终止传输。
4. T-105 应为 Validate 通过用例（组合合法），但断言应改为"Validate 通过；运行时 ERROR 在 DATA#2 后注入，传输终止，DATA#3 不生成"。

**依据**：§4.3（ERROR 终止传输）；§5.3（FinalBlockZero 要求 BlocksCount>=1）。

**修复建议**：T-105 断言改为"Validate 通过（error_after_block=2 ≤ blocks_count=3，final_block_zero=true 合法）；运行时 ERROR 在 DATA#2/ACK#2 后注入，传输终止，DATA#3 不生成（FinalBlockZero 不生效）"。

---

## 5. LOW 问题

### R2-LOW-1：§1.1 最大文件大小近似值精度

**位置**：§1.1（行 27）

**描述**：`blksize=65464 时理论 65535×65464 ≈ 3.99 GB（受 tsize 选项 uint32 上限 4 GB-1 制约）`。

**核算**：65535 × 65464 = 4,290,434,040 字节 = 4.29 GB（二进制）/ 3.99 GiB（二进制 GiB）。文档用 "GB" 但实际是 GiB（1024^3）。3.99 GiB ≈ 4.29 GB（十进制）。表述"3.99 GB"在二进制语境下正确（3.99 GiB），但单位应为 GiB 而非 GB。

**依据**：单位规范（IEC 60027-2）。

**修复建议**：改为"≈ 3.99 GiB（4,290,434,040 字节，受 tsize uint32 上限 4 GiB-1 制约）"或保持现状（LOW，不影响实现）。

### R2-LOW-2：T-065 子用例算术表述

**位置**：T-065（行 1242）

**描述**：T-065 超限子用例："filename=255 字符（V3 上限）+ 全 4 选项（blksize=65464 + timeout=255 + tsize=2^32-1 + windowsize=65535）→ RRQ 总长 = 2+256+6+(8+6)+(8+3)+(6+10)+(11+5) = 521B > 512"。

**核算**：
- 2（opcode）+ 256（255 字符 + 1 字节 `\0`）+ 6（"octet" + `\0`）= 264
- blksize: 8（"blksize\0"）+ 6（"65464\0"，5 字符 + 1）= 14
- timeout: 8（"timeout\0"）+ 4（"255\0"，3 字符 + 1）= 12
- tsize: 6（"tsize\0"）+ 11（"4294967295\0"，10 字符 + 1）= 17
- windowsize: 11（"windowsize\0"，10 字符 + 1）+ 6（"65535\0"，5 字符 + 1）= 17
- 合计：264 + 14 + 12 + 17 + 17 = 324 字节

**问题**：文档写"2+256+6+(8+6)+(8+3)+(6+10)+(11+5) = 521B"，但该表达式的括号内各值均有误：
- (8+6)=14（blksize，"blksize\0"=8 + "65464\0"=6）✓
- (8+3)=11（timeout，"timeout\0"=8 + **"255\0"=4**，写 3 漏算 `\0`）
- (6+10)=16（tsize，"tsize\0"=6 + **"4294967295\0"=11**，写 10 漏算 `\0`）
- (11+5)=16（windowsize，"windowsize\0"=11 + **"65535\0"=6**，写 5 漏算 `\0`）
- 重算：2+256+6+14+12+17+17 = **324 字节**，不是 521B。

**更严重的问题**：324 字节 < 512 字节，**不触发 V23 警告**。在 filename≤255（V3 上限）+ 全部 4 选项（RFC 2347 每选项仅一次）的约束下，RRQ 最大长度 = 2+256+6+14+12+17+17 = 324 字节，**永远达不到 512 字节上限**——V23 警告条件实际不可达，T-065 超限子用例的"521B > 512 → V23 警告"期望**不成立**。

**依据**：逐字节核算。

**修复建议**：T-065 超限子用例需重新设计。要触发 V23（RRQ > 512B），需更大的 filename 或更多选项。但 filename 上限 255（V3），4 选项已全部使用。实际无法用 4 选项 + 255 字符 filename 触发 512B 上限（最大 324B）。需：
- 方案 A：删除 T-065 超限子用例（无法触发 V23），改为"全 4 选项 + filename=255 → 324B < 512，通过"。
- 方案 B：若必须触发 V23，需放宽 filename 上限（但 V3 限制 255）或允许选项重复（但 RFC 2347 禁止）。实际无法触发，V23 警告条件不可达。
- 推荐：方案 A，并标注"V23 在 filename≤255 + 4 选项下不可触发（最大 324B < 512B），V23 保留为防御性检查"。

### R2-LOW-3：§11 修订记录 R1-MED-6/R1-MED-8/R1-LOW-1/2/3 撤回说明可简化

**位置**：§11（行 1659）

**描述**：`（注：R1-MED-6/R1-MED-8/R1-LOW-1/2/3 经审计自纠撤回，不构成问题，无需修改。）`

**问题**：撤回说明记录了审计过程中的自纠，但对实现者无信息量（实现者只需知道最终修复项）。可简化为"（注：部分 v2.0.0 复审项经核实不构成问题，已撤回。）"或直接删除。

**依据**：文档简洁性。

**修复建议**：简化或删除该注（LOW，不影响实现）。

---

## 6. HexDump 自洽性核算

逐字节核算全部 15 个 HexDump 场景（S1-S15）：

| 场景 | 核算结果 | 备注 |
|------|----------|------|
| S1 RRQ | ✓ | RRQ 19B（2+11+6）；DATA#1 104B（4+100）；ACK#1 4B |
| S2 WRQ | ✓ | WRQ 19B；ACK#0 4B；DATA#1 204B；ACK#1 4B |
| S3 blksize | ✓ | RRQ 31B；OACK 15B；ACK#0 4B；DATA 1432B；末块满块自动追加 |
| S4 timeout | ✓ | RRQ 25B；OACK 13B；DATA#1 516B（512 满块）；自动追加 DATA#2(0B) |
| S5a RRQ tsize | ✓ | RRQ 25B（tsize="0"）；OACK 13B（"2048"）；4 DATA + 自动追加 DATA#5(0B) |
| S5b WRQ tsize | ✓ | WRQ 29B（tsize="2048"）；OACK 13B；无 ACK#0；4 DATA + 自动追加 |
| S6 windowsize | ✓ | RRQ 27B；OACK 15B；2 窗口 × (4 DATA + 1 ACK)；末块满块自动追加 DATA#9(0B) → 15 包 |
| S7 多选项 | ✓ | RRQ 48B（核算行 906-908 逐项正确）；OACK 35B；自动追加 |
| S8a-c ERROR | ✓ | code=1 19B；code=3 37B；code=8 32B |
| S9 TID 变更 | ✓（字节数） | ERROR(5) 24B（2+2+20）正确；**但语义错误见 R2-CRITICAL-1/2** |
| S10 重传 | ✓ | DATA#2 仅重传版本；末块 #3 满块自动追加 DATA#4(0B) |
| S11 多会话 | ✓ | 3 流 × 3 包 = 9 包 |
| S12 多流关联 | ✓ | FlowID 构成规则明确 |
| S13 边界值 | ✓ | 13a 7 包；13b 极值；13c/d 块号边界 |
| S15 完整流程 | ✓ | 15a 13 包；15b 8 包 |

**结论**：HexDump 字节数核算全部通过（v2.0.1 的 R1-MED-1 修复有效）。唯一问题是 S9 的**语义**错误（R2-CRITICAL-1/2），非字节数错误。

---

## 7. 测试用例符合 CLAUDE.md §Testing Policy 核查

按 CLAUDE.md §Testing Policy 8 条规则逐条审核：

### 规则 1：spec-driven（每条对应 §2-§6 字段/状态机分支）
- **通过**：241 条用例均对应 spec 中的字段/状态机分支。T-001~T-020 对应 S1-S15 场景；T-071~T-105 对应 §8.1 V1-V25 校验规则；T-222~T-241 对应审计修复项。

### 规则 2：覆盖正向+负向+边界
- **通过**：正向 20 + 负向错误注入 20 + 边界 30 + Validate 拒绝 35 + 负向半标准流（T-062/T-159）等。

### 规则 3：每条代码路径有测试
- **基本通过**：但 R2-HIGH-2 指出"ERROR 抑制自动追加"路径在 §5.3 未明确规则，T-022/T-034 测试了该路径但 spec 未文档化。

### 规则 4：集成测试
- **通过**：T-141~T-160 E2E 用例覆盖 Plan→Worker→PCAP 全链路；T-146 真实 NIC 发送；T-151/T-152 参考 PCAP 比对。

### 规则 5：断言可观察输出
- **通过**：T-126~T-140 字节精确用例逐字节断言；T-141~T-160 tshark 解析断言。

### 规则 6：并发正确性
- **通过**：T-161~T-175 并发用例含 -race、聚合速率、FlowID 唯一性、共享 Pacer 限速等。

### 规则 7：失败路径测试
- **通过**：T-071~T-105 Validate 拒绝用例 35 条；T-147 Validate 错误传播到任务失败。

### 规则 8：测试质量对抗审核
- **部分不通过**：
  - T-065 超限子用例算术错误（R2-LOW-2），实际无法触发 V23。
  - T-105 断言与实际行为相反（R2-MED-4）。
  - T-110/T-149/T-229 等基于错误的 RFC 1783 引用（R2-CRITICAL-1），测试期望"ERROR(5) 后继续传输"违反 RFC 1350——若实现者按 RFC 1350 编码，这些用例会失败；若按用例编码，生成的流量不可互操作。

---

## 8. 最终结论

### 8.1 问题统计

| 严重度 | 数量 | 问题 |
|--------|------|------|
| CRITICAL | 2 | R2-CRITICAL-1（RFC 1783 引用错误，S9 语义基础崩塌）；R2-CRITICAL-2（S9 序列不符合任何 RFC） |
| HIGH | 3 | R2-HIGH-1（§4.3 依赖错误 RFC）；R2-HIGH-2（ERROR vs AutoAppend 优先级未文档化）；R2-HIGH-3（wrap Block#=0 DATA 互操作性警示不足） |
| MEDIUM | 3 | R2-MED-1（S9 包数口径不一）；R2-MED-3（§9.4 表述模糊）；R2-MED-4（T-105 断言与行为相反） |
| LOW | 3 | R2-LOW-1（单位 GB/GiB）；R2-LOW-2（T-065 算术错误，V23 不可触发）；R2-LOW-3（修订记录简化） |
| **总计** | **11** | （另：R2-MED-2 §5.4 code=0 字节数核实通过，不计入问题） |

### 8.2 结论

**否——本文档不可直接进入实现阶段**。

v2.0.1 在内部一致性上较 v2.0.0 有显著进步（16/17 项修复正确落地，§5.4 字节数全表修正，自动追加规则统一为"末块满块即追加"），但 **R1-CRITICAL-1 的修复基于错误的 RFC 引用**——RFC 1783 的实际标题是 "TFTP Blocksize Option"（RFC 2348 前身），**完全不包含** TID 变更机制。S9 场景的整个语义基础（"RFC 1783 §3 TID 迁移"）是虚构的引用。

**必须修复的阻断项**（进入实现前）：
1. **R2-CRITICAL-1**：删除全部 RFC 1783 引用（行 3/354/527/964/978/1626），重新定义 S9 语义为"trafficgen 扩展行为"或改为符合 RFC 1350 的场景。
2. **R2-CRITICAL-2**：随 R2-CRITICAL-1 一并处理 S9 序列。
3. **R2-HIGH-1**：删除 §4.3 的"RFC 1783 迁移语义"表述。
4. **R2-HIGH-2**：§5.3 新增 ERROR vs AutoAppend 优先级规则。
5. **R2-MED-4**：T-105 断言修正。
6. **R2-LOW-2**：T-065 超限子用例重新设计或删除。

**建议修复项**（不阻断，但提升质量）：
- R2-HIGH-3、R2-MED-1、R2-MED-3、R2-LOW-1、R2-LOW-3。

**修复后建议**：完成 R2-CRITICAL-1/2 + R2-HIGH-1/2 + R2-MED-4 + R2-LOW-2 后，进行 v2.0.2 复审（聚焦 RFC 引用核实与 S9 语义重定义），通过后方可进入实现阶段。

---

**审计报告结束**。v2.0.1 共发现 11 个问题（2 CRITICAL + 3 HIGH + 3 MEDIUM + 3 LOW），核心阻断项为 RFC 1783 引用错误导致 S9 语义基础崩塌。
