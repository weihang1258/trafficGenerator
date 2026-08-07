# RIP 设计文档第五轮对抗审计报告

**审计日期**：2026-08-04
**审计员**：独立审计员（非设计者）
**文档版本**：v1.1.4（2026-08-03）
**文档行数**：1316 行
**基础测试用例数**：73 条

---

## 执行摘要

本文档执行第五轮对抗审计，重点检查第四轮审计的 13 处修复是否正确落地、是否引入新的不一致，以及 RFC 合规性、HexDump 自洽性、测试用例质量和跨节一致性。

**审计结论**：**否** — 文档存在 7 处问题需返工后方可进入实现阶段。

| 严重度 | 数量 | 编号 |
|--------|------|------|
| CRITICAL | 0 | — |
| HIGH | 2 | R-5.01, R-5.02 |
| MEDIUM | 4 | R-5.03, R-5.04, R-5.05, R-5.06 |
| LOW | 1 | R-5.07 |

---

## 发现详情

### R-5.01 [HIGH] §2.8.2 后续包 Payload 公式与 T-POS-31 描述矛盾

**位置**：§2.8.2 MD5 认证（行 127-138）、T-POS-31（行 763）

**问题描述**：

§2.8.2 给出的后续包公式为：
```
后续包 Payload = 4 + 20×N + 4 + AuthDataLen = 24 + 20N + AuthDataLen
```

该公式包含 `+ 4 + AuthDataLen`（trailer header + digest），暗示后续包也包含认证 trailer。

但 T-POS-31 断言要点描述为：
> "第 2 包无认证 + 1 路由，认证 trailer 仅按首包规则追加"

"仅按首包规则追加" 暗示 trailer 仅存在于首包，后续包无 trailer。

**矛盾分析**：
- 公式说后续包有 trailer（`+ 4 + AuthDataLen`）
- 测试描述说后续包无 trailer（"仅首包"）

两者矛盾，实现者无法确定后续包是否应包含 trailer。

**RFC 依据**：
RFC 4822 §2.1 规定 authentication trailer 包含 Authentication Data，用于验证整个消息。若后续包无 auth entry，则无法计算 trailer，不应包含 trailer。

**修复建议**：
1. 明确后续包行为：若采用"仅首包认证"策略，则后续包 Payload = 4 + 20×N（无 trailer）；若采用"每包独立认证"策略，则每包都应有 auth entry + trailer。
2. 修正 §2.8.2 公式或 T-POS-31 描述，使其一致。

---

### R-5.02 [HIGH] §2.5 Auth Data Len 字段引用章节错误

**位置**：§2.5 Auth Data Len 字段说明（行 78）

**问题描述**：

文档原文：
> "Auth Data Len | 摘要长度。RFC 4822 §2.5：默认 16（MD5 输出）..."

但 RFC 4822 §2.5 是 "RIPv2 Security Association"，与 Auth Data Len 字段无关。Auth Data Len 字段实际定义在 RFC 4822 §2.1。

**RFC 依据**：
RFC 4822 §2.1 字段定义表：
> "Auth Data Len: An unsigned 8-bit field that contains the length in octets of the trailing Authentication Data field."

**修复建议**：
将 "RFC 4822 §2.5" 改为 "RFC 4822 §2.1"。

---

### R-5.03 [MEDIUM] R-4.01 修复引入术语不一致："offset" vs "total length"

**位置**：§2.5 RIPv2 Packet Length 字段说明（行 76）

**问题描述**：

R-4.01 修复将字段语义从"指向 trailer header 起始位置的偏移"改为"regular RIPv2 packet 的总长度"。

但 RFC 4822 §2.1 原文为：
> "RIPv2 Packet Length: An unsigned 16-bit **offset** from the start of the RIPv2 header to the end of the regular RIPv2 packet..."

RFC 使用术语 "offset"（偏移），文档使用 "total length"（总长度）。虽然数值上两者等价（因 RIP 头从偏移 0 开始），但术语与 RFC 不符，且 R-4.01 修复引入了新的不一致。

**修复建议**：
将描述改为：
> "RFC 4822 §2.1 定义的 16-bit offset，表示从 RIP 头起始到 regular RIPv2 packet 结束的字节数（数值上等于 regular packet 总长度）"

---

### R-5.04 [MEDIUM] T-POS-9/T-POS-25 缺少 MD5 认证 entry 关键字段的字节级断言

**位置**：T-POS-9（行 747）、T-POS-25（行 763）

**问题描述**：

T-POS-9 和 T-POS-25 仅断言了 Auth Type（Payload[6:8]）和 trailer header（Payload[44:48]），但缺少以下关键字段的字节级断言：

| 字段 | 期望位置 | 期望值（示例） |
|------|----------|----------------|
| RIPv2 Packet Length | Payload[8:10] | 00 44（=44） |
| Key ID | Payload[10] | 01（=1） |
| Auth Data Len | Payload[11] | 10（=16）或 14（=20） |
| Sequence Number | Payload[12:16] | 00 00 30 39（=12345） |
| MustBeZero | Payload[16:24] | 00 00 00 00 00 00 00 00 |

**CLAUDE.md §Testing Policy §5 依据**：
> "Tests must assert output values and observable behavior... A field that is never populated stays at its zero value and passes any structural assertion."

缺少上述字段的断言意味着实现者可能未正确填充这些字段，而测试仍会通过。

**修复建议**：
为 T-POS-9 和 T-POS-25 增加上述字段的字节级断言。

---

### R-5.05 [MEDIUM] T-POS-1 缺少 request entry 完整字段断言

**位置**：T-POS-1（行 738）

**问题描述**：

T-POS-1 仅断言了 Payload[20:24]=00 00 00 10（Metric=16），但未覆盖以下字段：
- RouteTag（Payload[6:10]）应为 00 00
- IP（Payload[10:14]）应为 00 00 00 00
- Mask（Payload[14:18]）应为 00 00 00 00
- NextHop（Payload[18:22]）应为 00 00 00 00

虽然 §6.1 提供了完整 hex dump，但测试用例表未将其纳入断言，不符合 CLAUDE.md §Testing Policy §5 的"assert observable outcomes"要求。

**修复建议**：
T-POS-1 增加完整 entry 字段断言：
> Payload[6:10]=00 00 00 00, Payload[10:14]=00 00 00 00, Payload[14:18]=00 00 00 00, Payload[18:22]=00 00 00 00

---

### R-5.06 [MEDIUM] §2.8.2 后续包公式变量 N 未定义

**位置**：§2.8.2 MD5 认证（行 138）

**问题描述**：

文档原文：
> "后续包 Payload = 4 + 20×N + 4 + AuthDataLen = 24 + 20N + AuthDataLen"

变量 N 未明确定义。读者需自行推断 N 表示"后续包中的 route entry 数量"。

**修复建议**：
将公式改为：
> "后续包 Payload = 4 + 20×M + 4 + AuthDataLen，其中 M = 后续包中的 route entry 数（M ≤ 25）"

---

### R-5.07 [LOW] §2.5 末段 RFC 4822 章节引用错误

**位置**：§2.5 末段（行 90）

**问题描述**：

文档原文：
> "RFC 4822 §2.5：默认 16（MD5 输出），但允许其他算法..."

同 R-5.02，Auth Data Len 字段定义在 §2.1，不是 §2.5。

**修复建议**：
将 "RFC 4822 §2.5" 改为 "RFC 4822 §2.1"。

---

## 第四轮修复验证

| 修复 ID | 严重度 | 验证结果 | 说明 |
|---------|--------|----------|------|
| R-4.01 | CRITICAL | ⚠️ 引入新问题 | 术语从 "offset" 改为 "total length"，与 RFC 原术语不符（见 R-5.03） |
| R-4.02 | CRITICAL | ✅ 已正确落地 | Payload 长度公式已拆分为无认证/MD5 认证两节，数值正确 |
| R-4.03 | HIGH | ✅ 已正确落地 | Auth Type=0x0003（entry）与 Type=0x0001（trailer）已明确区分 |
| R-4.04 | HIGH | ✅ 已正确落地 | request_full 同向四元组定义已明确 |
| R-4.05 | HIGH | ✅ 已正确落地 | RIPng Version=1 解释已注明需结合 UDP 521/IPv6 |
| R-4.06 | MEDIUM | ✅ 已正确落地 | v1 Metric 偏移描述已修正 |
| R-4.07 | MEDIUM | ✅ 已正确落地 | Routes 优先级描述已补全 |
| R-4.08 | MEDIUM | ✅ 已正确落地 | Payload 524B/528B 断言已补全 |
| R-4.09 | MEDIUM | ✅ 已正确落地 | request_full 输入优先级表已补全 |
| R-4.10 | MEDIUM | ✅ 已正确落地 | T-POS-1b 变体已拆分 |
| R-4.11 | LOW | ✅ 已正确落地 | 统计数字已统一 |
| R-4.12 | LOW | ✅ 已正确落地 | RFC 引用已修正 |
| R-4.13 | LOW | ✅ 已正确落地 | 历史 RFC 引用已修正 |

**总结**：12/13 修复已正确落地，1/13（R-4.01）引入新的术语不一致。

---

## RFC 合规性检查

| RFC 章节 | 检查项 | 状态 | 说明 |
|----------|--------|------|------|
| RFC 1058 §3.1 | v1 RTE 布局 | ✅ | AFI(2)+Zero(2)+IP(4)+Zero(4)+Zero(4)+Metric(4)=20B |
| RFC 2453 §3.1.1 | v2 RTE 布局 | ✅ | AFI(2)+RouteTag(2)+IP(4)+Mask(4)+NextHop(4)+Metric(4)=20B |
| RFC 2080 §2.1 | RIPng RTE 布局 | ✅ | Prefix(16)+RouteTag(2)+PrefixLen(1)+Metric(1)=20B |
| RFC 2453 §3.9.1 | Request 全量 entry | ✅ | AFI=0x0000, Metric=16 |
| RFC 4822 §2.1 | MD5 auth entry 布局 | ✅ | AFI=0xFFFF+AuthType(2)+PacketLen(2)+KeyID(1)+AuthDataLen(1)+SeqNum(4)+Zero(8)=20B |
| RFC 4822 §2.1 | Trailer header | ✅ | 0xFFFF 0x0001（4B）+ Digest（AuthDataLen B）|
| RFC 2453 §4.5 | v2 组播地址 | ✅ | 224.0.0.9 |
| RFC 2080 §2.5 | RIPng 组播地址 | ✅ | FF02::9 |
| RFC 2453 §3.6 | Response 源端口 | ✅ | 520（文档注明多路由器场景非标）|
| RFC 2080 §2.1 | RIPng 端口 | ✅ | 521 |

---

## 测试用例质量检查（CLAUDE.md §Testing Policy）

| 规则 | 检查项 | 状态 | 说明 |
|------|--------|------|------|
| §1 Spec-driven | 测试与 spec 章节映射 | ✅ | §7.1 提供 spec 章节映射表 |
| §2 负向覆盖 | 失败路径测试 | ✅ | 17 条负向用例（T-ERR 系列）|
| §3 单路径单测 | 每场景至少 1 条用例 | ✅ | 每个 Scenario 均有覆盖 |
| §4 集成测试 | 端到端测试 | ✅ | T-POS-26, T-POS-27, T-POS-28 |
| §5 可观测量 | 字节级/字段级断言 | ⚠️ | T-POS-9, T-POS-25, T-POS-1 缺少关键字段断言（见 R-5.04, R-5.05）|
| §6 并发验证 | 多路由器吞吐量 | ✅ | T-POS-28 断言总发包数 |
| §7 Failing-test-first | Bug fix 先写失败测试 | N/A | 新增协议，无历史 bug |
| §8 测试质量审查 | 对抗审计 | ✅ | 本文档执行 |

---

## HexDump 自洽性检查

| HexDump | 位置 | 状态 | 说明 |
|---------|------|------|------|
| §6.1 Request entry | 行 436 | ✅ | `00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 10` 正确（AFI=0, Metric=16） |
| §6.4 v1 Response | 行 481 | ✅ | Metric=1 在偏移 20-23 正确 |
| §6.8 MD5 首包 | 行 557-562 | ✅ | PacketLength=44, trailer 在偏移 44-47 正确 |
| T-POS-9 断言 | 行 747 | ⚠️ | 缺少 PacketLength、KeyID、AuthDataLen、SeqNum、MustBeZero 断言 |
| T-POS-25 断言 | 行 763 | ⚠️ | 同 T-POS-9，且 AuthDataLen=20 时应为 00 14 |

---

## 跨节一致性检查

| 字段 | 位置 1 | 位置 2 | 状态 | 说明 |
|------|--------|--------|------|------|
| v1/v2 Metric | §2.2: 4 字节 | §2.3: 4 字节 | ✅ | 一致 |
| RIPng Metric | §2.6: 1 字节 | — | ✅ | 与 v1/v2 区分正确 |
| RIPv2 Packet Length | §2.5: "总长度" | RFC: "offset" | ⚠️ | 术语不一致（见 R-5.03） |
| 后续包 trailer | §2.8.2: 有 | T-POS-31: 无 | ❌ | 矛盾（见 R-5.01） |
| Auth Data Len 引用 | §2.5: §2.5 | — | ❌ | 应为 §2.1（见 R-5.02） |

---

## 最终结论

**本文档可以直接进入实现阶段吗？否。**

必须先返工的问题编号：
1. **R-5.01** [HIGH]：§2.8.2 后续包 Payload 公式与 T-POS-31 描述矛盾
2. **R-5.02** [HIGH]：§2.5 Auth Data Len 字段引用章节错误

建议一并修复的问题（非阻塞，但推荐修复）：
3. **R-5.03** [MEDIUM]：RIPv2 Packet Length 术语与 RFC 不符
4. **R-5.04** [MEDIUM]：T-POS-9/T-POS-25 缺少关键字段断言
5. **R-5.05** [MEDIUM]：T-POS-1 缺少完整字段断言
6. **R-5.06** [MEDIUM]：§2.8.2 公式变量 N 未定义
7. **R-5.07** [LOW]：§2.5 末段 RFC 章节引用错误

---

## 附录：第四轮修复验证详细说明

### R-4.01 修复验证

**修复内容**：Packet Length 字段从 "offset to trailer header" 改为 "regular RIPv2 packet 总长度"

**问题**：RFC 4822 §2.1 原文使用 "offset" 术语，文档使用 "total length" 术语。虽然数值相同（`4 + 20×entry_count`），但术语与 RFC 不符。

**建议**：保留 "total length" 作为中文解释，但增加 RFC 原术语 "offset" 的引用，例如：
> "RFC 4822 §2.1 定义的 RIPv2 Packet Length 字段（原文称 'offset'，中文解释为正则 RIPv2 包总长度）"

---

*报告完成*
