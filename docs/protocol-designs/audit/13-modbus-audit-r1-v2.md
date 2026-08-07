# MODBUS 设计文档复审审计报告（v2.0.0）

**审计对象**：`docs/protocol-designs/13-modbus-design.md`（v2.0.0，1548 行，140 用例）
**审计依据**：
- Modbus.org MB-ASYM-TCP（MODBUS Application Protocol Specification V1.1b3）
- MODICON PI-MBUS-300（Modbus Protocol Reference Guide）
- CLAUDE.md §Testing Policy 8 条规则
- `audit/13-modbus-audit-deep.md`（v1.1 深度审计，14 项问题，v2.0.0 声称全部修复）

**审计人**：独立审计 agent（非 v2.0.0 设计者）
**审计日期**：2026-08-05
**审计方式**：逐节对照规范核对 + HexDump 逐字节核算 + 测试用例与规范/文档交叉验证

---

## 1. 审计概览

本次为 v2.0.0 复审（v1.1 深度审计见 `audit/13-modbus-audit-deep.md`，14 项问题：2 CRITICAL + 4 HIGH + 5 MEDIUM + 3 LOW）。v2.0.0 声称全部修复。本报告验证修复效果，并对 15 个 HexDump 场景逐字节核算、对 140 条用例逐条交叉验证，发现 **20 项新问题**（7 CRITICAL + 3 HIGH + 6 MEDIUM + 4 LOW），其中多数为 v2.0.0 重构时新引入的算术/结构错误。

### 1.1 问题汇总

| 严重度 | 数量 | 编号 |
|--------|------|------|
| CRITICAL | 7 | R1-C1 ~ R1-C7 |
| HIGH | 3 | R1-H1 ~ R1-H3 |
| MEDIUM | 6 | R1-M1 ~ R1-M6 |
| LOW | 4 | R1-L1 ~ R1-L4 |
| **合计** | **20** | |

### 1.2 最终结论

**不可以直接进入实现阶段**。必须先返工修复：

- **R1-C1 ~ R1-C4**：S8/S9/S10/S13 四个 HexDump 场景的 MBAP Length 字段值算术错误（4 处），直接违反 §1.4 不变式 2 与 §2.6 长度约束，若照抄实现将产生 Wireshark 无法识别的报文；
- **R1-C5**：FC 0x14 响应 item 漏 Byte Count 字段（v1.1 深度审计未覆盖的结构错误，v2 仍残留）；
- **R1-C6**：FC 0x16 掩码写公式错误（恒为 0xFFFF），wire 格式虽为 echo 不受影响，但语义描述错误将误导实现；
- **R1-C7**：T-018 FC 0x0C 响应 Byte Count=8 与后续 10 字节自相矛盾。

另需修复 R1-H1（§8.1 支持集/高位规则与 S14 豁免矛盾）、R1-H2（FC 0x05 WriteValue 接受 0/1 与 Validate 只接受 0xFF00/0x0000 矛盾）、R1-H3（FC 0x17 WriteAddress 回退公式依赖被忽略的 Quantity）。

---

## 2. CRITICAL 问题

### R1-C1：S8（§6.8）响应 MBAP Length 字段错误 + 总字节数标注错误

**位置**：§6.8，第 830-836 行。

**问题**：S8（Report Server ID，FC=0x11）响应：

```
00 06  00 00  00 06  01  11  03  01  FF  AA BB
```

实际核算：
- MBAP 头 = `00 06 00 00 00 06 01`：TID=6, PID=0, **Length=0x0006=6**, Unit=1
- PDU = `11 03 01 FF AA BB` = **6 字节**（FC + ByteCount + SlaveID + RunInd + Additional）
- 按 §1.4 不变式 2：Length = Unit ID(1) + PDU 长度(6) = **7 = 0x0007**

文档写 `00 06`（Length=6），且解释"Length=6 = 1(Unit) + 1(FC) + 1(ByteCount) + 1(SlaveID) + 1(RunInd) + 2(Additional)"——**该公式自身相加 = 7**，结论却写 6，属算术错误。字节序列与解释自相矛盾。

**连带错误**：同节标题"响应（14 字节…）"——实际 7 MBAP + 6 PDU = **13 字节**。

**依据**：MODBUS Application Protocol Specification V1.1b3 §2.1（MBAP Length = Unit Identifier + PDU）。

**修复建议**：字节序列改为 `00 06 00 00 00 07 01 11 03 01 FF AA BB`（Length=7），标题改为"13 字节"，解释改为"Length=7 = 1+1+1+1+1+2"。

---

### R1-C2：S9（§6.9）请求 MBAP Length 字段错误 + T-085 同错

**位置**：§6.9 第 840-845 行；§7.8 T-085 第 1101 行。

**问题**：S9（Read/Write Multiple Registers，FC=0x17，ReadQty=10, WriteQty=3）请求：

```
00 07  00 00  00 12  01  17  00 00  00 0A  00 14  00 03  06  11 11  22 22  33 33
```

实际核算：
- PDU = FC(1) + ReadAddr(2) + ReadQty(2) + WriteAddr(2) + WriteQty(2) + WriteBC(1) + 3 寄存器值(6) = **16 字节**
- Length = Unit ID(1) + 16 = **17 = 0x0011**

文档字节序列写 `00 12`（Length=18），解释"Length=18 = 0x12 = 1+1+2+2+2+2+1+6"——**公式自身相加 = 17**，结论写 18。字节序列与解释均错。

**连带错误**：T-085（§7.8）"Length=0x0012=18（请求，1+1+2+2+2+2+1+6）"——同一错误。

**对照**：同节响应 `00 07 00 00 00 17 01 17 14 <20 字节>` Length=0x0017=23 核算正确（1+1+1+20=23），说明本错误仅在请求侧。

**依据**：MB-ASYM-TCP §2.1；§2.6 本设计自身的长度公式。

**修复建议**：S9 请求 Length 改为 `00 11`（17），解释改为"Length=17 = 1+1+2+2+2+2+1+6"；T-085 同步改为 0x0011=17。

---

### R1-C3：S10（§6.10）MBAP Length 字段错误

**位置**：§6.10，第 856-861 行。

**问题**：S10（Mask Write Register，FC=0x16）请求/响应（echo）：

```
00 08  00 00  00 07  01  16  00 00  FF FF  00 00
```

实际核算：
- PDU = FC(1) + Addr(2) + AND(2) + OR(2) = **7 字节**
- Length = Unit ID(1) + 7 = **8 = 0x0008**

文档字节序列写 `00 07`（Length=7），解释"Length=7 = 1+1+2+2+2"——**公式自身相加 = 8**，结论写 7。字节序列与解释均错。

**依据**：MB-ASYM-TCP §2.1。

**修复建议**：Length 改为 `00 08`（8），解释改为"Length=8 = 1+1+2+2+2"。

---

### R1-C4：S13（§6.13）响应 MBAP Length 字段错误

**位置**：§6.13，第 917-922 行。

**问题**：S13（FC=0x03 读 125 寄存器，最大量边界）响应：

```
00 09  00 00  00 FA  01  03  FA  <250 字节寄存器值>
```

实际核算：
- PDU = FC(1) + ByteCount(1) + 250 寄存器值 = **252 字节**
- Length = Unit ID(1) + 252 = **253 = 0x00FD**

文档字节序列写 `00 FA`（Length=250），解释"Length=250 = 0xFA = 1+1+1+250"——**公式自身相加 = 253**，结论写 250。字节序列与解释均错。

**注意**：本场景是"最大量"边界用例（quantity=125 是 FC 0x03 上限），Length=253 恰好逼近 §2.6 声明的 PDU 上限 253/Length 上限 254，是验证长度边界的**核心场景**，数值错误将直接掩盖长度溢出类 bug。

**依据**：MB-ASYM-TCP §2.1；§2.6 本设计自身的长度约束。

**修复建议**：Length 改为 `00 FD`（253），解释改为"Length=253 = 0xFD = 1+1+1+250"；并同步核算"MBAP+PDU 总长 259 < 260"结论仍成立。

---

### R1-C5：FC 0x14 响应 item 漏 Byte Count 字段（§3.3.12 + T-020 + T-115 三处）

**位置**：§3.3.12 第 341-345 行；§7.2 T-020 第 1006 行；§7.13 T-115 第 1156 行。

**问题**：v1.1 深度审计修复了 FC 0x15 请求 item 漏 Record Data（M2-CRIT-1），但 **FC 0x14 响应 item 漏 Byte Count 的结构错误未被发现并残留到 v2.0.0**。

依据 MODICON PI-MBUS-300 §6.13（Read File Record）与 MB-ASYM-TCP §6.12，FC 0x14 **响应** item 格式为：

| 字节 | 字段 |
|------|------|
| 0 | Reference Type = 0x06 |
| 1 | **Byte Count = Record Length × 2** |
| 2.. | Record Data（Record Length × 2 字节） |

文档 §3.3.12 响应表写"每项：Reference Type(1)=0x06 + Record Data(Record Length * 2 字节)"——**漏了 item 内 Byte Count 字段**。

**连带错误**：
- T-020 预期响应 `14 05 06 1234 5678`（ByteCount=5）——按规范应含 item 内 Byte Count=0x04：`14 06 06 04 1234 5678`（ByteCount=6）；
- T-115 预期响应 `14 05 06 1234 5678`（ByteCount=5=1+4）——同样缺 item 内 Byte Count。

**影响**：照此实现，Wireshark Modbus 解析器无法识别 FC 0x14 响应（item 字段错位，后续 Record Data 被误读），且 §8.4"FC 0x14 | 1 + Σ(item 长度)"的长度校验公式也无法自洽。

**依据**：PI-MBUS-300 §6.13；MB-ASYM-TCP §6.12（响应 item 含 Byte Count 字段）。

**修复建议**：§3.3.12 响应表 item 增加"Byte Count(1) = Record Length × 2"字段；T-020/T-115 响应改为 `14 06 06 04 1234 5678`（ByteCount=6，item 内 ByteCount=4）；§8.4 的"1 + Σ(item 长度)"中 item 长度 = 2 + Record Length × 2。

---

### R1-C6：FC 0x16 掩码写公式错误（恒为 0xFFFF）

**位置**：§3.3.14，第 383 行。

**问题**：文档公式：

> 新寄存器值 = (当前值 AND AND_Mask) OR (0xFFFF AND NOT AND_Mask) OR OR_Mask

依据 MB-ASYM-TCP §6.16（Mask Write Register）与 PI-MBUS-300 §6.14，正确公式为：

```
Result = (Current Contents AND And_Mask) OR (Or_Mask AND (NOT And_Mask))
```

文档公式展开后 = (Cur AND A) OR (~A) OR O = (Cur OR ~A) OR O——其中 (Cur AND A) OR ~A = Cur OR ~A（吸收律），结果包含 **~A 的全部 1 位**，与 OR_Mask 取值无关，且当 A ≠ 0xFFFF 时结果恒非 0 的高位全 1，**在多数掩码组合下恒等于 0xFFFF**。

正确公式中 ~A 的位只在与 Or_Mask 相与（O AND ~A）后才置位，二者语义完全不同。

**为什么测试没抓住**：T-116/T-117/T-118 全部只断言请求/响应 echo 字节序列（`16 0000 FFFF 0000` 等），**没有任何用例验证公式的算术结果**。这是 CLAUDE.md §Testing Policy 规则 5（断言可观察输出，而非仅结构）的典型反例——echo 格式正确掩盖了语义公式错误。

**依据**：MB-ASYM-TCP §6.16。

**修复建议**：公式改为 `(当前值 AND AND_Mask) OR (OR_Mask AND NOT AND_Mask)`；新增用例验证掩码组合的算术结果（如 A=0x00FF, O=0x0001，Cur=0x1234 → 0x0034）。若设计不模拟寄存器状态（仅 wire 透传），则删除该公式或明确标注"仅为协议语义参考，实现不执行"。

---

### R1-C7：T-018（§7.2）FC 0x0C 响应 Byte Count 与后续字节数矛盾

**位置**：§7.2 T-018 第 1004 行；对照 §3.3.8 第 258-267 行。

**问题**：T-018 预期响应：

```
0C 08 0000 0064 000A 01 02 03 04
```

按 §3.3.8 的响应表：FC(1) + ByteCount(1) + Status(2) + EventCount(2) + MessageCount(2) + Events(N)：
- ByteCount 之后的字节 = Status(2) + EventCount(2) + MessageCount(2) + Events(4) = **10 字节**
- Byte Count 应 = **10 = 0x0A**

文档写 ByteCount=0x08=8，与后续 10 字节矛盾（若 Wireshark 按 BC=8 解析将把 Events 截断 2 字节）。

**连带错误**：§8.4 第 1304 行"FC 0x0C | 1 + 4 + N"——ResponseValues（FC 之后的字节）= ByteCount(1) + Status(2) + EventCount(2) + MessageCount(2) + Events(N) = **7 + N**，文档写 1+4+N（漏 MessageCount 2 字节），应为 "1 + 6 + N"。

**另注意**：T-018 的 EventCount=100 而 Events 仅 4 字节——规范中 Events 字段长度为事件数（Event Count 值），文档未定义"事件数 ≠ Events 字节数"的语义（模拟用途可接受，但需明确 Events 长度是 N 而非 EventCount 值）。

**依据**：MB-ASYM-TCP §6.8（Get Comm Event Log 响应）。

**修复建议**：T-018 响应 ByteCount 改为 0x0A（10）：`0C 0A 0000 0064 000A 01 02 03 04`；§8.4 改为 "1 + 6 + N"；并明确 Events 长度定义（N 字节，与 EventCount 字段值解耦）。

---

## 3. HIGH 问题

### R1-H1：§8.1 支持集/高位规则与 S14 豁免矛盾，豁免优先级未定义且无测试

**位置**：§8.1 第 1260-1261 行；§6.14 S14 第 924-940 行；§7.5 T-053/T-063 第 1054/1064 行。

**问题**：存在三条相互矛盾的规则：

1. §8.1："FunctionCode 必须在支持集 {0x01-0x08, 0x0B, 0x0C, 0x0F-0x11, 0x14-0x18, 0x2B} 内"——FC=0x99 不在支持集；
2. §5.2 注释 + T-063："FunctionCode 高位（0x80）不能设"——**FC=0x99 的 bit7=1**；
3. S14 注："FC 0x99 不在支持集中，但 `ExceptionCode != 0` 时 Validate 接受"。

S14 的豁免要求"非法 FC + 异常码 → 通过"，但 T-063 的高位检查（0x83 → 拒绝）在字面上与 0x99（同样 bit7=1）冲突。文档未定义豁免的适用条件与优先级（是"支持集外且异常码非零 → 豁免高位检查"，还是仅"支持集内非法值 + 异常码"？）。

**测试缺口**：T-053 只测"FC=0x99 + ExceptionCode=0 → 拒绝"；**没有任何用例测"FC=0x99 + ExceptionCode=0x01 → 通过"这一 S14 声明路径**，也没有用例覆盖 T-025 的 FC=0x41（同样是支持集外的 FC）。若实现按 T-063 高位检查先行，S14/T-025 全部失效且无测试发现。

**依据**：CLAUDE.md §Testing Policy 规则 2（覆盖失败路径）、规则 5（断言可观察输出）。

**修复建议**：在 §8.1 明确豁免规则，如"FC 不在支持集且 ExceptionCode≠0 时，跳过支持集与高位检查，按用户字节透传请求，响应为 FC|0x80 + ExceptionCode"；新增用例 T-053b（FC=0x99 + ExcCode=0x01 → 通过，响应 `19 01`）与 T-025b（FC=0x41 + ExcCode=0x01 → 通过）。

---

### R1-H2：FC 0x05 WriteValue 接受 0/1 与 Validate 只接受 0xFF00/0x0000 矛盾

**位置**：§5.2 第 606-609 行；§8.2 第 1274 行。

**问题**：§5.2 注释：

> For 0x05, the planner accepts 0/1 or 0xFF00/0x0000 directly. Empty defaults to 0 (OFF / 0x0000).

但 §8.2 Validate 规则："0x05 | WriteValue | 0xFF00 或 0x0000（其他值需配 ExceptionCode）"。若用户填 WriteValue=1（布尔 ON），§5.2 说接受（转换为 0xFF00），§8.2 说拒绝（1 既不是 0xFF00 也不是 0x0000）。

**测试缺口**：T-009（0xFF00）与 T-010（0）分别测了两端，**没有任何用例测 WriteValue=1 的转换路径**，也未定义"0/1 → 0xFF00/0x0000"的转换规则归属（Validate 时转换还是 Plan 时转换）。

**依据**：CLAUDE.md §Testing Policy 规则 3（每个分支需要测试）。

**修复建议**：统一语义——§8.2 明确"WriteValue ∈ {0, 1, 0xFF00, 0x0000}，0/1 由 planner 映射为 0x0000/0xFF00"；新增 T-009b（WriteValue=1 → PDU `05 0064 FF00`）。

---

### R1-H3：FC 0x17 WriteAddress 回退公式依赖被忽略的 Quantity

**位置**：§5.2 第 617 行；对照第 585 行。

**问题**：§5.2 注释：

> When zero, falls back to StartingAddress for read and **StartingAddress+Quantity for write**.

但同结构体 Quantity 注释（第 585 行）明确："0x17: IGNORED (use ReadQuantity / WriteQuantity)"。WriteAddress 的回退公式使用了一个被声明为 IGNORED 的字段——公式不可执行（Quantity=0 时 WriteAddress 回退到 StartingAddress 本身，语义错误）。

**影响**：实现者只能猜测回退公式应为 `StartingAddress + WriteQuantity` 或 `StartingAddress + ReadQuantity`；T-014 显式设置了 WriteAddr=20，未覆盖回退路径。

**依据**：CLAUDE.md §Testing Policy 规则 1（spec 驱动的测试推导，每个字段需可执行语义）。

**修复建议**：公式改为"WriteAddress 回退到 StartingAddress + WriteQuantity"（与 T-014 的显式值语义一致），或删除回退机制强制显式设置；新增用例覆盖回退路径（WriteAddr=0, WriteQty=3, StartingAddress=0 → WriteAddr=3）。

---

## 4. MEDIUM 问题

### R1-M1：FC 0x14/0x15 请求 item 的配置与校验机制未定义

**位置**：§5.2 Values 第 599 行；§7.13 T-111~T-114；§8.2 第 1283 行。

**问题**：ModbusTransaction 结构体**没有 File Number / Record Number / Record Length 字段**，T-020/T-111~T-114 却用"File=1, Record=0, RecLen=2"参数描述用例。这些值只能通过 Values 字节数组透传（§5.2 仅写"0x14/0x15: file record item data"）。但文档未定义：

- planner 如何从 Values 推导 FC 0x14/0x15 请求的 Byte Count（= len(Values)？需明确）；
- §8.2"FC=0x14 固定 7 字节；FC=0x15 = 7+2×RecordLength"的 item 长度校验如何执行——planner 需解析 Values 中每个 item 的 Record Length 字段（偏移 5-6）才能校验，此解析规则未定义；
- 多 item 时（T-112/T-114）item 边界如何划分（按 7 字节固定步长？按 RecLen 动态步长？）。

**依据**：CLAUDE.md §Testing Policy 规则 1（错误处理表行必须有对应测试与可执行语义）。

**修复建议**：在 §5.2 明确"FC 0x14/0x15 的请求 item 由 Values 透传，Byte Count = len(Values)，Validate 按 item 结构解析（FC 0x14 每 7 字节一个 item；FC 0x15 每 item 按偏移 5-6 的 RecLen 动态步进）并校验总长"；新增 T-112b（2 items 中一个 RecLen 异常 → 拒绝）负向用例。

---

### R1-M2：FC 0x0F Values 长度负向用例缺失

**位置**：§8.2 第 1276 行；§7.5。

**问题**：§8.2 有 FC 0x0F 的校验规则"values length must be ⌈Quantity/8⌉"，但 §7.5 负向用例中**只有 T-052 测了 FC 0x10 的 values 长度**（"values length must be Quantity*2"），FC 0x0F 与 FC 0x17（"values length must be WriteQuantity*2"，§8.2 第 1281 行）的长度校验均无负向用例。符合 CLAUDE.md 列出的反模式"错误处理表 10 行只测 1 行"。

**依据**：CLAUDE.md §Testing Policy 规则 2（负向路径）。

**修复建议**：新增用例：FC=0x0F qty=8 Values=2 字节 → 拒绝；FC=0x17 WriteQty=3 Values=5 字节 → 拒绝。

---

### R1-M3：§8.3 语义非法值 + ExceptionCode∈{0x04..0x0B} 组合未定义

**位置**：§8.3 第 1287-1292 行。

**问题**：§8.3 规则表只定义"语义非法值 + ExceptionCode∈{0x01,0x02,0x03} → 合法"，未定义 ExceptionCode∈{0x04,0x05,0x06,0x07,0x08,0x0A,0x0B} 配语义非法值的组合（如 Quantity=0 + ExceptionCode=0x04 Slave Device Failure）。T-061/T-103/T-105 全部只用 0x03。实现者将猜测该组合行为。

**修复建议**：明确"任意合法异常码（0x01-0x08, 0x0A, 0x0B）均可背书语义非法值"或限定子集；新增一条异常码边界用例（如 Quantity=0 + ExceptionCode=0x07）。

---

### R1-M4：UnitID=0（广播）+ ExceptionCode 非零 / 读功能码组合未定义

**位置**：§4.4 第 503-506 行；§5.1 SuppressBroadcast 注释。

**问题**：规范中广播（Unit ID=0）仅对写功能码有效（master 广播写，slave 不响应；读+广播在规范中未定义，实际 slave 会异常响应）。文档未定义：
- UnitID=0 + 读功能码（FC=0x01-0x04 等）是否允许（Validate 层面）；
- UnitID=0 + ExceptionCode≠0 时响应是否也抑制（SuppressBroadcast 是否同时抑制异常响应）。

T-037/T-038/T-072/T-140 全部用写功能码测广播，未覆盖读功能码广播与异常广播。

**依据**：MB-ASYM-TCP §"Broadcast"（广播语义仅适用于写功能码）。

**修复建议**：Validate 增加"广播 + 读功能码拒绝"或文档明确允许并说明理由；明确 SuppressBroadcast 对异常响应的作用范围；新增对应用例。

---

### R1-M5：§10.3 声称 gopacket `layers.ModbusTCP` 完全支持，声明过强

**位置**：§10.3 第 1427-1428 行。

**问题**：文档称"trafficgen pcap 解析器需识别 Modbus 层——已由 gopacket 内置 layers.ModbusTCP 提供，无需新写解析器"。gopacket 的 ModbusTCP 解析仅覆盖基础字段（TID/PID/Length/Unit/FC），对 FC 0x14/0x15 的 item 内字段、FC 0x2B MEI 子字段等**不保证逐字段解析**，T-076/T-077 声称的"Wireshark 识别 Byte Count / Slave ID / Record Data 字段"验证的是 Wireshark（tshark）而非 gopacket。若验证工具用 gopacket，断言将落空。

**修复建议**：明确"gopacket 仅提供层识别与基础字段，FC 特定字段验证以 tshark 为准"，并在 §7.7 注明验证工具链。

---

### R1-M6：FC 0x2B SubFunction（uint16）→ MEI Type（1 字节）截断规则未定义

**位置**：§5.2 SubFunction 第 624-629 行；§3.3.17 第 444-451 行。

**问题**：SubFunction 是 uint16（FC 0x08 需 0x0000-0x0018），FC 0x2B 的 MEI Type 是 PDU 中 1 字节（0x0D/0x0E）。SubFunction=0x000D → MEI Type=0x0D 的截断/转换规则未说明（低字节截取？），且 FC 0x2B 时 SubFunction 高字节（如 0x010D）的行为未定义。

**修复建议**：明确"FC 0x2B 时取 SubFunction 低字节作为 MEI Type，高字节必须为 0，否则 Validate 拒绝"；新增负向用例（SubFunction=0x010D → 拒绝）。

---

## 5. LOW 问题

### R1-L1：S1（§6.1）残留草稿注释

**位置**：§6.1 第 700-701 行。

**问题**：请求序列首行残留草稿"`00 00 00 00 00 06 01 03... 不对, 应为 FC=01`"——设计文档混入工作草稿，应删除。

---

### R1-L2：S1 响应总字节数标注错误

**位置**：§6.1 第 713 行。

**问题**："响应（slave→master，TCP payload，6+4=10 字节）"——MBAP 头是 **7 字节**（§3.1），不是 6。应为 7+4=11 字节。字节序列 `00 00 00 00 00 05 01 01 02 03 01` 实际 11 字节，与标注矛盾。

---

### R1-L3：S5/S8/S14 总字节数标注错误

**位置**：§6.5 第 776 行；§6.8 第 823 行；§6.14 第 926 行。

**问题**：
- S5 请求标注"16 字节"——实际 17 字节（7 MBAP + 10 PDU）；
- S8 请求标注"10 字节"——实际 8 字节（7 + 1）；
- S14 请求标注"10 字节"——实际 8 字节（7 + 1）。

三个场景的 Length 字段值均正确（S5=0x0B ✓、S8=0x02 ✓、S14=0x02 ✓），仅总字节数标注错。

---

### R1-L4：测试用例重复与对照矩阵映射错误

**位置**：§7.4 vs §7.11；§7.12 vs §7.5；§7.20。

**问题**：
- T-040/T-041 与 T-098/T-099 内容完全重复（Transaction ID 回绕 65537/65538 事务）；T-042 与 T-100 重复（多 slave 同流）；T-102/T-103 与 T-049/T-062 重复（quantity=0）。140 条核心用例中至少 6 条重复，实际独立用例约 134；
- §7.20 对照矩阵"§6.11 多事务序列 | T-096~T-100, T-136~T-140"——§6.11 实际是 HexDump 场景 S11（多会话），不是"多事务序列"（§4.2）；T-096~T-100 应对应 §4.2；"§9 错误处理 | T-049~T-066"——T-049~T-066 是 §7.5 负向用例（属 §8 Validate 规则），不是 §9。

**修复建议**：删除重复用例或注明"与 T-xxx 等价"；修正矩阵映射（T-096~T-100 → §4.2；T-049~T-066 → §8）。

---

## 6. v2.0.0 修复验证结论

| 深度审计 ID | 严重度 | v2.0.0 修复状态 | 本次复核 |
|------------|--------|----------------|---------|
| M2-CRIT-1（FC 0x15 漏 Record Data） | CRITICAL | §3.3.13 + T-021/T-077/T-113/T-114 | **已修复**，但同族结构错误转移到 FC 0x14 响应（R1-C5） |
| M2-CRIT-2（FC 0x11 漏 Byte Count） | CRITICAL | §3.3.11 + T-019/T-076 | **已修复**（§3.3.11 响应含 Byte Count，S8 的 ByteCount=3 核算正确） |
| M2-HIGH-1（UnitID omitempty） | HIGH | *uint8 + T-094 | **已修复**（§5.1 类型与 T-094 断言一致） |
| M2-HIGH-2（FC 0x0B/0x0C 未规格化） | HIGH | §3.3.7/§3.3.8 + T-017/T-018 | **基本修复**，但 T-018 引入 Byte Count=8 错误（R1-C7） |
| M2-HIGH-3（10 FC 无正向用例） | HIGH | T-015~T-024 | **已修复**（但 T-020/T-023 依赖 R1-C5/R1-C7 的修正） |
| M2-HIGH-4（异常码 0x07 缺失） | HIGH | §2.5 + T-031/T-054 | **已修复**（0x07 在表内，0x09 拒绝，T-025~T-034 覆盖全表） |
| M2-MED-1（S1 位数据矛盾） | MEDIUM | 改为 `01 01 00` | **已修复**（§6.1 与 §5.3 默认值规则一致） |
| M2-MED-2（FC 0x17 字段规则） | MEDIUM | Quantity=IGNORED + T-065/T-066 | **基本修复**，但 WriteAddress 回退公式依赖 Quantity（R1-H3） |
| M2-MED-3（FC 0x18 FIFO ≤31） | MEDIUM | §3.3.16 + T-048/T-059/T-120/T-121 | **已修复** |
| M2-MED-4（nil vs []） | MEDIUM | §5.3 + T-091/T-092 | **已修复** |
| M2-MED-5（互斥规则） | MEDIUM | §5.3/§8.1 + T-060 | **已修复** |
| M2-LOW-1（位序术语） | LOW | §2.2 改写 | **已修复** |
| M2-LOW-2（FC 0x08 表述） | LOW | §3.3.6 + T-126~T-130 | **已修复** |
| M2-LOW-3（TID 回绕参数） | LOW | T-041 改 65538 | **已修复** |

**总体判断**：14 项旧问题中 12 项真正修复、2 项修复不彻底（M2-HIGH-2 引入新错误 R1-C7；M2-MED-2 残留 R1-H3）；v2.0.0 重构新增 18 项问题（7 CRITICAL + 3 HIGH + 6 MEDIUM + 2 LOW），其中 4 项 CRITICAL（R1-C1~C4）集中在 HexDump 场景的 Length 字段算术错误——深度审计报告核查过 S1/S2 但未逐字节核算 S8/S9/S10/S13。

---

## 7. 重点检查项核对清单

| 检查项 | 结论 | 说明 |
|--------|------|------|
| 1. MBAP 头部（TID 2B BE + PID 2B BE + Len 2B BE + Unit 1B） | 通过 | §3.1 正确；但 S8/S9/S10/S13 的 Length **值**算错（R1-C1~C4） |
| 2. Length = Unit ID + PDU | 定义正确 | §1.4/§2.6/§3.1 一致；HexDump 多处执行错误 |
| 3. FC 枚举完整（0x01-0x2B） | 通过 | §1.3 与 §8.1 支持集一致，19 个 FC 全规格化 |
| 4. FC 0x15 请求 item 含 Record Data | 通过（已修复） | §3.3.13 正确；但 FC 0x14 响应漏 item Byte Count（R1-C5） |
| 5. FC 0x11 响应含 Byte Count | 通过（已修复） | §3.3.11 + S8 + T-019 自洽 |
| 6. 异常码完整（01-0B 含 0x07） | 通过（已修复） | §2.5 十码齐全，T-025~T-034 全覆盖 |
| 7. UnitID=0 广播 *uint8 | 通过（已修复） | §5.1 + T-094；广播+读 FC 组合未定义（R1-M4） |
| 8. Register 值 2B BE | 通过 | §2.4/§3.3.2/各 HexDump 一致 |
| 9. 多会话/多流 TID 复用 | 通过 | S11/S12 + T-131~T-135；回绕时跨流 TID 重复未讨论（设计选择，可接受） |
| 10. HexDump 自洽性 | **失败** | R1-C1~C4（Length 值）、R1-C7（ByteCount）、R1-L1~L3（总字节数） |
| 11. 测试用例符合 Testing Policy | **部分失败** | R1-C6 公式错误无测试捕获；R1-H1/H2 声明路径无测试；R1-M2 负向缺失；6 条重复用例 |

---

## 8. 修复优先级建议

1. **立即修复（CRITICAL，7 项）**：R1-C1~C4 四个 Length 值、R1-C5 FC 0x14 响应 item、R1-C6 FC 0x16 公式、R1-C7 T-018 ByteCount。
2. **实现前必须明确（HIGH，3 项）**：R1-H1 豁免规则优先级、R1-H2 WriteValue 0/1 映射、R1-H3 WriteAddress 回退公式。
3. **实现时补充（MEDIUM，6 项）**：R1-M1~M6 的机制定义与用例补充。
4. **顺手清理（LOW，4 项）**：R1-L1~L4 的草稿残留、字节数标注、重复用例、矩阵映射。

修复后应重新逐字节核算全部 15 个 HexDump 场景（建议实现时以 tshark 实测为最终裁判，§10.3 已有此约定）。
