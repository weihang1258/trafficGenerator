# MODBUS 设计文档深度对抗审计报告

**审计对象**：`docs/protocol-designs/13-modbus-design.md`（v1.1，1292 行，60 用例）
**审计依据**：
- Modbus.org MB-ASYM-TCP（MODBUS Application Protocol Specification V1.1b3）
- MODICON PI-MBUS-300（Modbus Protocol Reference Guide）
- RFC 879（TCP MSS）
- CLAUDE.md §Testing Policy 8 条规则
- `audit/10-13-rip-modbus-enip-audit.md`（v1.0 审计结果，本次 v1.1 二次审计）

**审计人**：独立审计 agent（非 v1.1 设计者）
**审计日期**：2026-08-04

---

## 1. 审计概览

本次为 v1.1 二次审计（首次审计见 `audit/10-13-rip-modbus-enip-audit.md` §3，2026-08-03 发现 10 项问题：3 CRITICAL + 3 HIGH + 3 MEDIUM + 1 LOW，全部在 v1.1 修复并追加 10 用例 T51-T60）。本报告重点关注 v1.1 修复后是否引入新 bug 以及首次审计未覆盖的盲区。

### 1.1 问题汇总

| 严重度 | 数量 | 编号 |
|--------|------|------|
| CRITICAL | 2 | M2-CRIT-1, M2-CRIT-2 |
| HIGH | 4 | M2-HIGH-1, M2-HIGH-2, M2-HIGH-3, M2-HIGH-4 |
| MEDIUM | 5 | M2-MED-1, M2-MED-2, M2-MED-3, M2-MED-4, M2-MED-5 |
| LOW | 3 | M2-LOW-1, M2-LOW-2, M2-LOW-3 |
| **合计** | **14** | |

### 1.2 最终结论

**不可以直接进入实现阶段**。必须先返工修复 M2-CRIT-1（FC 0x15 请求结构错误）、M2-CRIT-2（FC 0x11 响应格式错误）、M2-HIGH-1（UnitID omitempty 冲突）、M2-HIGH-2（FC 0x0B/0x0C 声称但未规格化）、M2-HIGH-3（10 个 FC 无正向用例）、M2-HIGH-4（异常码 0x07 缺失）。详见 §11。

---

## 2. CRITICAL 问题

### M2-CRIT-1：§2.3.11 写文件记录 FC=0x15 请求结构错误（漏 Record Data 字段）

**位置**：§2.3.11，第 217-225 行。

**问题**：设计文档将 FC 0x14（读文件记录）与 FC 0x15（写文件记录）的请求格式合并描述：

```
请求：
| 字节 | 字段 | 说明 |
| 0 | FC | 0x14 / 0x15 |
| 1 | Byte Count | 后续总字节数 |
| 2.. | Item(s) | 每项 7 字节：Reference Type(1)=6 + File Number(2) + Record Number(2) + Record Length(2) |
```

但 FC 0x14 和 FC 0x15 的请求 item 结构**完全不同**：

| FC | Item 头部 | Item 数据 | 总长 |
|----|----------|----------|------|
| 0x14 (Read) | 7B（Reference Type + File Number + Record Number + Record Length） | 无 | 7B |
| 0x15 (Write) | 7B（同上） | **2×Record Length 字节 Record Data** | **7 + 2×Record Length** |

依据 MODICON PI-MBUS-300 §6.14（Write File Record）：每个 sub-request 必须包含 Reference Type(1) + File Number(2) + Record Number(2) + Record Length(2) + Record Data(2×Record Length)。设计文档说"每项 7 字节"对 FC 0x15 是**直接 wire-format 错误**——漏掉 Record Data 会导致：
- Byte Count 与实际 item 总长不匹配（计算结果比实际少 2×Record Length 字节）
- PLC 拒绝处理或 Wireshark 解析异常
- 实施者按"7 字节"实现则永远无法写文件记录数据

**依据**：MODBUS Application Protocol Specification V1.1b3 §6.15（FC 0x15 Write File Record）—— "Each sub-request shall be defined as: Reference Type (1 byte, fixed 0x06), File Number (2 bytes), Record Number (2 bytes), Record Length (2 bytes), Record Data (2×Record Length bytes)."

**修复建议**：
- §2.3.11 拆分为两个独立的请求格式表
- FC 0x15 item 格式改为"Reference Type(1) + File Number(2) + Record Number(2) + Record Length(2) + Record Data(2×Record Length)"
- 附录 B 增加 §2.3.11 FC=0x15 的测试映射（当前无单测）

---

### M2-CRIT-2：§2.3.10 FC 0x11 报告从站 ID 响应格式错误（漏 Byte Count 字段）

**位置**：§2.3.10，第 215 行。

**问题**：

```
响应：1 字节 FC=0x11 + 1 字节 Slave ID + 1 字节 Run Indicator Status (0x00=OFF, 0xFF=ON) + 可变特定数据。
```

依据 Modbus.org MB-ASYM-TCP §6.11，FC 0x11 响应格式应为：

| 字节 | 字段 |
|------|------|
| 0 | FC = 0x11 |
| **1** | **Byte Count（后续字节数 = Slave ID + Run Indicator + Additional Data 之和）** |
| 2 | Slave ID |
| 3 | Run Indicator Status |
| 4.. | Additional Data |

设计文档漏掉 Byte Count 字段是**wire-format 错误**——Wireshark Modbus 解析器依赖 Byte Count 定位后续字段起始位置，缺失会导致字段全部错位（Slave ID 误读为 Byte Count 等）。

**典型响应字节序列示例**（依 Modbus 规范）：
```
11 02 11 00   <- FC=0x11, Byte Count=0x02, Slave ID=0x11, Run Indicator=0x00
11 0C 01 FF "Schneider XYZ" 00   <- FC=0x11, Byte Count=0x0C, Slave ID=0x01, Run Indicator=0xFF, Additional Data=10B, Run Indicator(2nd?)=0x00
```

**依据**：Modbus.org MB-ASYM-TCP §6.11（Report Slave ID）响应 PDU 第 2 字段明确定义为 Byte Count（1 byte, number of data bytes following）。

**修复建议**：
- §2.3.10 响应格式改为"FC(1) + Byte Count(1) + Slave ID(1) + Run Indicator(1) + Additional Data(N)"
- Byte Count 含义明确为"Slave ID + Run Indicator + Additional Data 之和的字节数"
- 附录 B 增加 FC 0x11 单测（当前无任何测试）

---

## 3. HIGH 问题

### M2-HIGH-1：§3.1 ModbusConfig.UnitID 用 uint8+omitempty 导致广播（UnitID=0）功能不可用

**位置**：§3.1 第 337 行；§3.4 第 470-471 行；§6.13.5 第 802-805 行；T28/T29 第 898-899 行。

**问题**：

```go
UnitID uint8 `json:"unit_id,omitempty"`
```

`omitempty` 在 Go 中对 uint8 类型表现为：值为 0 时省略。但 Modbus 规范中 Unit ID = 0 是合法值（广播地址，Modbus.org MB-ASYM-TCP §4.1 Protocol Documentation 明确"Unit Identifier 0 = broadcast"）。

设计文档 §3.4 默认值规则表：

| 字段 | 空值 | 默认 |
| UnitID | 0 | 1（0 = 广播，需 SuppressBroadcast 显式控制） |

该规则意味着无论用户是否显式设置 `unit_id: 0`，Planner 都会把 0 改写为 1。但 Go 中 uint8 + omitempty 的语义是：**无法区分** "字段未设" 与 "字段设为 0"（两者都解析为 0）。后果：

1. 用户设置 `{"unit_id": 0}`（意图广播）→ Planner 改写为 1 → 广播功能**完全不可用**
2. 用户省略 `unit_id` → 解析为 0 → Planner 改写为 1 → 默认值 1 生效
3. T28（"Unit ID=0 广播，SuppressBroadcast=false"）、T29（"Unit ID=0 广播抑制"）两个测试用例**无法通过任何 JSON 输入触发**

§6.13.5 章节"Unit ID=0（广播）— 默认仍发响应包"描述的是期望行为，但实际代码层面无法实现此行为。

**依据**：
- Go encoding/json 规范：omitempty 对数值类型在值为零值时省略
- Modbus.org MB-ASYM-TCP §4.1：Unit ID 0 是合法广播标识

**修复建议**（任选其一）：
- **方案 A（推荐）**：UnitID 类型改为 `*uint8`，nil 表示未设置（默认 1），0 表示显式广播
- **方案 B**：保留 uint8 但删除默认 0→1 规则，0 = 广播（如未设置则上游 mapToFlowSpec 在创建默认 config 时填 1）
- **方案 C**：增加伴生字段 `UnitIDSet bool` 显式标记是否用户设置
- §3.4 默认值表同步修改

---

### M2-HIGH-2：§1.3 声称覆盖 FC 0x0B/0x0C 但 §2.3 完全未规格化

**位置**：§1.3 第 31-32 行；§2.3（通篇）；§7 测试用例（通篇）。

**问题**：

§1.3 明确声明：
> 功能码覆盖：0x01-0x06, 0x07, 0x08, **0x0B, 0x0C**, 0x0F, 0x10, 0x11, 0x14, 0x15, 0x16, 0x17, 0x18, 0x2B（含 0x80 异常响应）

但 §2.3 共 14 个子节（2.3.1 至 2.3.14），**没有任何子节描述 FC 0x0B 或 0x0C**。具体规格：

| FC | 功能名 | §2.3 描述 |
|----|--------|-----------|
| 0x0B | Get Comm Event Counter（取通信事件计数）| ❌ 缺失 |
| 0x0C | Get Comm Event Log（取通信事件日志）| ❌ 缺失 |

后果：
- §2.3 规格表数量（14 个）与 §1.3 声称（17 个 FC + 0x80 异常）不一致
- 实施者无 PDU 格式可遵循，只能从外部 RFC/规范查找
- §7 测试用例 60 条全部跳过 FC 0x0B/0x0C（无任何 Txx 引用）
- 附录 B "spec 章节与用例对照矩阵"也未列出这两个 FC

**依据**：
- Modbus.org MB-ASYM-TCP §6.5（FC 0x0B）、§6.6（FC 0x0C）
- CLAUDE.md Testing Policy §1："§X 要求行为 Y → 需测试"——规格声明但无规格也无测试

**修复建议**：
- §2.3 增加 §2.3.x（FC 0x0B）、§2.3.x+1（FC 0x0C）两个完整 PDU 表格
- 或从 §1.3 声称范围中**删除** 0x0B/0x0C（标注"v1 不支持"）
- §7 增加至少各 1 条正向测试用例
- 附录 B 同步更新对照矩阵

---

### M2-HIGH-3：§7 测试用例严重漏覆盖——10 个 FC 描述在 §2.3 但无正向用例

**位置**：§7.1-§7.4（第 857-918 行）；附录 B 第 1203-1228 行。

**问题**：CLAUDE.md Testing Policy §1（"spec 驱动，§X 要求行为 Y → 至少 1 测试"）与 §3（"一路径一测试"）明确要求"每个规格声明必须有测试"。

但 §2.3 描述的 17 个 FC 中，以下 FC **无任何正向用例**：

| FC | 功能 | §2.3 描述 | §7 正向用例 | §7 验证用例 |
|----|------|----------|------------|------------|
| 0x07 | Read Exception Status | §2.3.8 | ❌ 无 | ❌ 无 |
| 0x08 | Diagnostics | §2.3.9 | ❌ 无 | ❌ 无 |
| 0x0B | Get Comm Event Counter | ❌ 未描述 | ❌ 无 | ❌ 无（M2-HIGH-2） |
| 0x0C | Get Comm Event Log | ❌ 未描述 | ❌ 无 | ❌ 无（M2-HIGH-2） |
| 0x11 | Report Slave ID | §2.3.10 | ❌ 无 | ❌ 无 |
| 0x14 | Read File Record | §2.3.11 | ❌ 无 | ❌ 无 |
| 0x15 | Write File Record | §2.3.11 | ❌ 无 | ❌ 无（M2-CRIT-1） |
| 0x16 | Mask Write Register | §2.3.12 | ❌ 无 | ❌ 无 |
| 0x18 | Read FIFO Queue | §2.3.13 | ❌ 无 | ❌ 无 |
| 0x2B | Encapsulated Interface Transport | §2.3.14 | ❌ 无 | 仅 T56/T57 Validate 拒绝测试 |

附录 B 自认：
> FC=0x16/0x18 在 v1 仅 §2 描述覆盖，单测待 v1.2 补齐（非本次审计范围）。

但 v1.1 修订记录声称"修复 10 项（3 CRITICAL + 3 HIGH + 3 MEDIUM + 1 LOW）"，并未承诺补齐这些 FC 的正向用例。这意味着：
- 实施者按规格实现 FC 0x07/0x08/0x11/0x14/0x15/0x16/0x18/0x2B 后**无任何测试验证**
- CLAUDE.md Testing Policy §8（"adversarial review of test quality"）要求每个规格声明必须有测试
- v1.2 推迟但当前 v1.1 已声明"可进入实现"

**依据**：CLAUDE.md Testing Policy §1 + §3 + §8。

**修复建议**：
- §7.1 增加正向用例：
  - T61：FC=0x07 读异常状态（请求 1B，响应 `07 FF` 或 `07 00`）
  - T62：FC=0x08 诊断 Return Query Data（请求 `08 0000 AABB`，响应回显）
  - T63：FC=0x11 报告从站 ID（请求 1B，响应 `11 03 11 FF 00` 含 Byte Count）
  - T64：FC=0x14 读文件记录（请求含 1 个 item，响应含 Record Data）
  - T65：FC=0x15 写文件记录（请求含 1 个 item + Record Data，响应回显）
  - T66：FC=0x16 掩码写寄存器（请求 `16 0000 FFFF 0000`，响应回显）
  - T67：FC=0x18 读 FIFO 队列（请求 `18 0000`，响应含 Byte Count + FIFO Count + Values）
  - T68：FC=0x2B Read Device Identification（请求 `2B 0E 01 00`，响应含 Read Device ID）
- 附录 B 同步更新对照矩阵

---

### M2-HIGH-4：§2.4 + §3.2 + T41 异常码表漏 0x07 Negative Acknowledge

**位置**：§2.4 第 287-299 行；§3.2 第 435 行；T41 第 916 行。

**问题**：

Modbus 规范定义的异常码为：

| 码 | 名称 |
|----|------|
| 0x01 | Illegal Function |
| 0x02 | Illegal Data Address |
| 0x03 | Illegal Data Value |
| 0x04 | Slave Device Failure |
| 0x05 | Acknowledge |
| 0x06 | Slave Device Busy |
| **0x07** | **Negative Acknowledge**（否定确认）|
| 0x08 | Memory Parity Error |
| 0x0A | Gateway Path Unavailable |
| 0x0B | Gateway Target No Response |

（注：0x09 故意保留空缺，规范无此码）

§2.4 异常码表从 0x06 **直接跳到 0x08**，漏 0x07。§3.2 ExceptionCode 注释"Valid values: 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x08, 0x0A, 0x0B"——同样漏 0x07。T41 期望 ExceptionCode=0x07 被拒绝：

```
T41 | 异常码非法 | ExceptionCode=0x07 | "invalid exception code 0x07"
```

但 0x07 是 Modbus 规范定义的合法异常码。设计文档错误地将合法码视为非法。

依据：Modbus.org MB-ASYM-TCP §7 "Exception Response" 明确定义 0x07 = Negative Acknowledge（"Server cannot perform the programming functions; client should request diagnostic or error information from server"）。

**修复建议**：
- §2.4 异常码表增加 0x07 Negative Acknowledge 行
- §3.2 ExceptionCode 注释增加 0x07
- T41 改为正向用例或改为测试 0x09（真正非法）的拒绝行为

---

## 4. MEDIUM 问题

### M2-MED-1：§6.1.1 单线圈读响应示例 `01 01 01` 与 §3.4 默认值规则矛盾

**位置**：§6.1.1 第 591-593 行；§3.4 第 478-479 行。

**问题**：

§6.1.1 示例：
```
请求 PDU：`01 0000 0001`
响应 PDU：`01 01 01`（byte count=1，1 字节位数据）
```

§3.4 默认值规则表：
```
读响应寄存器值（auto-derived） | nil | 全 0（zeros of correct length）
```

若 qty=1 且未设 ResponseValues，Byte Count=1，1 字节位数据应为 0x00（全 0），但 §6.1.1 示例是 0x01。两者矛盾。

附录 B 修正记录（v1.1）声称"M-CRIT-3 复核"已修复 T01 显式标 ResponseValues=[0x00]，但 §6.1.1 的示例 `01 01 01` **未被修正**——若读者按 §6.1.1 示例推导 wire format，会得到错误的位数据 0x01。

**依据**：CLAUDE.md Testing Policy §8（"adversarial review of test quality"）——文档内部示例应与默认规则一致。

**修复建议**：
- §6.1.1 响应 PDU 改为 `01 01 00`（位数据=0x00=所有线圈 OFF）
- 或明确标注"此示例设 ResponseValues=[0x01, 0x00]，故位数据为 0x00"

---

### M2-MED-2：§3.2 FC 0x17 时 Quantity 与 ReadQuantity/WriteQuantity 字段使用规则未定义

**位置**：§3.2 第 380-390 行（Quantity）、第 416-422 行（ReadQuantity/WriteQuantity）；§7 T14 第 874 行。

**问题**：

§3.2 Quantity 字段注释：
```
Quantity (数量): ... FC-specific bounds:
  0x17 read: 1-125
  0x17 write: 1-121
```

但 §3.2 同时定义独立字段：
```go
ReadQuantity  uint16 `json:"read_quantity,omitempty"`
WriteQuantity uint16 `json:"write_quantity,omitempty"`
```

后果：
1. FC 0x17 时 Quantity 与 ReadQuantity/WriteQuantity 哪个生效未定义
2. ReadQuantity/WriteQuantity 默认值未说明（omitempty → 0 时如何处理？Quantity=0 会被 Validate 拒绝）
3. T14 同时使用 ReadQty 与 WriteQty，但 §3.2 字段描述未明示用户应填哪个
4. 实施者可能误用 Quantity（而非 ReadQuantity）导致 FC 0x17 写数量错误

**依据**：
- Modbus.org MB-ASYM-TCP §6.17（FC 0x17 Read/Write Multiple Registers）请求 PDU 含**两个独立 quantity 字段**（Read Quantity + Write Quantity），与 Quantity 无关
- 内部一致性原则

**修复建议**：
- §3.2 Quantity 字段对 FC 0x17 的描述改为："FC 0x17 时忽略本字段，使用 ReadQuantity/WriteQuantity"
- §3.2 ReadQuantity/WriteQuantity 注释默认值规则："未设置时 Validate 报错（quantity 必须显式）"
- T14 字段名保持 `ReadQty`/`WriteQty`（与 json tag 一致）

---

### M2-MED-3：§2.3.13 FC 0x18 读 FIFO 队列上限未声明

**位置**：§2.3.13 第 250-266 行；§3.2 第 386-387 行。

**问题**：

依据 MODBUS Application Protocol Specification V1.1b3 §6.18（Read FIFO Queue）：
> The maximum number of registers that can be read from the FIFO is 31.
> If the FIFO count exceeds 31, an exception response with exception code 04 (Slave Device Failure) is sent.

设计文档 §2.3.13 描述 FC 0x18 响应格式但**未声明 31 寄存器上限**。后果：
- 用户设置 ResponseValues 含 FIFO Count = 50 时，planner 不会警告
- 生成的 wire format 与真实 Modbus 设备不兼容
- §3.2 Quantity 字段对 FC 0x18 说"ignored (FIFO queue length is response-driven)"——但长度上限不可忽略

**修复建议**：
- §2.3.13 响应表增加 "FIFO Count ≤ 31，否则异常响应 04"
- §3.2 Quantity 字段对 FC 0x18 改为"ignored，但 ResponseValues 中 FIFO Count 必须 ≤ 31，否则 Validate 拒绝"
- 新增测试用例 T69（FC=0x18 FIFO Count=32 → Validate 拒绝）

---

### M2-MED-4：§3.4 Transactions=nil vs Transactions=[] 行为冲突未澄清

**位置**：§3.1 第 340-345 行；§3.4 第 472 行；T34 第 904 行；T35 第 905 行。

**问题**：

§3.1 ModbusTransaction 注释：
> Empty list = the planner emits only TCP handshake + teardown (useful for connection-probe tests)

§3.4 默认值规则表：
> Transactions | nil/空 | 单个默认事务（FC=0x03 读保持寄存器，addr=0, qty=1）

两者**直接矛盾**：
- §3.1 说空列表 = 仅握手+挥手
- §3.4 说 nil/空 = 默认 1 事务

测试用例 T34（"仅有握手+挥手 | Transactions=[] | 仅 TCP 握手 + 挥手"）与 T35（"默认配置 | 全空 ModbusConfig | 默认 1 事务"）**两套相反的行为各有一条用例**。

实施者必须理解"nil 切片（JSON 字段缺失）" vs "空切片（JSON `"transactions": []`）"的 Go 语义差异才能正确实现。但文档未明确说明这一区分规则。

**依据**：Go encoding/json 规范——`omitempty` 对 slice 在 `len()==0` 时省略，故缺失与空数组都解析为 `nil`；但显式 `"transactions": []` 解析为 `len()==0` 的非 nil 切片。

**修复建议**：
- §3.1 + §3.4 明确规则：
  - `Transactions == nil`（JSON 字段缺失）→ 添加 1 个默认事务
  - `len(Transactions) == 0 && Transactions != nil`（JSON `"transactions": []`）→ 仅握手+挥手
- §3.4 表分两行：
  ```
  | Transactions（nil，JSON 字段缺失）| nil | 1 个默认事务 |
  | Transactions（[]，显式空数组）| [] | 仅 TCP 握手+挥手 |
  ```

---

### M2-MED-5：§3.2 ExceptionCode 与 ResponseValues 同时设置时行为未定义

**位置**：§3.2 第 432-446 行。

**问题**：

§3.2 ExceptionCode 注释：
> when non-zero, the planner emits an exception response (FC|0x80 + this code) instead of a normal response

§3.2 ResponseValues 注释：
> when non-nil, overrides the planner's auto-derived response payload (the bytes after FC in the response PDU, including byte count for read functions)

若两者同时非零/非空，行为未定义。可能的三种实现：
1. ExceptionCode 优先 → 异常响应，ResponseValues 被忽略
2. ResponseValues 优先 → 自定义响应，异常码被忽略
3. Validate 拒绝 → "ExceptionCode 与 ResponseValues 互斥"

实施者只能猜测，导致实现不一致。

**修复建议**：
- §3.2 增加明确规则："ExceptionCode 非零时 ResponseValues 必须为 nil（互斥）；Validate 在两者同时设置时拒绝并报错 'exception_code and response_values are mutually exclusive'"
- 或 ExceptionCode 优先：ResponseValues 在异常响应时被忽略，文档明示

---

## 5. LOW 问题

### M2-LOW-1：§6.1.2 + §6.7.2 "位数据字节序 = little-endian" 术语与 Modbus 规范标准术语不符

**位置**：§2.3.1 第 89 行；§6.1.2 第 599 行；§6.7.2 第 674 行。

**问题**：

设计文档用"字节序 = little-endian（低地址字节先），字节内位序 = LSB-first"描述 FC 0x01/0x02/0x0F 的位数据布局。但 Modbus 规范原文为：

> The LSB of the first data byte contains the output addressed in the query. The other outputs follow toward the high order end of this byte, and from 'low order to high order' in subsequent bytes.

规范未使用 "little-endian" 一词——"little-endian" 在计算机科学中专指多字节标量的字节序（如 uint32 的高低字节排列），用于位打包数据是**非标准术语**，可能误导：
- 实施者按 little-endian 实现多字节标量（如寄存器值），与规范要求 big-endian 矛盾
- 文档自身对"位数据字节序"与"寄存器值字节序"使用不同的 endian 描述

**依据**：
- Modbus.org MB-ASYM-TCP §6.1、§6.2、§6.11、§6.15：寄存器值统一为 big-endian；位数据按"LSB-first within byte, subsequent bytes from low to high address"
- 计算机体系结构常识

**修复建议**：
- §2.3.1 改为："字节传输顺序：低地址字节先；字节内位序：bit0（LSB）= starting_address+0，后续位序向字节高位递增"
- 删除 "little-endian" 术语，统一改为"低地址优先（low-address-first）"

---

### M2-LOW-2：§2.3.9 诊断 FC=0x08 响应"多数为回显"表述不精确

**位置**：§2.3.9 第 210 行。

**问题**：

§2.3.9 响应描述："与请求相同（多数子功能为回显）"。

但 MODBUS Application Protocol Specification V1.1b3 §6.8 定义诊断子功能响应：
- 子功能 0x0000（Return Query Data）：回显
- 子功能 0x0001（Restart Communications）：响应含"清除所有事件计数器"数据（0x0001 或 0xFF00 + 子功能码）
- 子功能 0x0002-0x0004：不返回诊断寄存器/进入 Listen Only 模式
- 子功能 0x000A-0x0010：返回计数器值（不一定是回显数据）

"多数为回显" 不够精确——不同子功能响应格式差异较大。

**修复建议**：
- 改为："响应格式因子功能而异；常见回显类子功能 0x0000、0x000A-0x0010 的响应 = 请求 PDU 前 4 字节（FC + Sub-Function）+ 数据"

---

### M2-LOW-3：T55 Transaction ID 回绕精确点用例参数 65537 事务与断言 65538 事务矛盾

**位置**：§7.7 第 945 行（T55）；§6.13.8 第 815-822 行。

**问题**：

T55 参数列：
> T55 | Transaction ID 回绕精确点 | **65537 事务** | 第 65536 个事务 TID=65535，第 65537 个事务 TID=0，第 65538 个事务 TID=1

参数 65537 事务意味着生成 65537 个事务，但断言涉及第 65538 个事务。要验证第 65538 个 TID=1，需要生成至少 65538 个事务。

**依据**：逻辑自洽性。

**修复建议**：
- T55 参数列改为 "65538 事务" 或将断言改为"第 65537 个事务 TID=0"（去除 65538 断言）

---

## 6. v1.0 旧问题 v1.1 修复复核

### 6.1 M-CRIT-1（附录 A.1 Length 计算混乱）→ v1.1 修复确认 ✅

v1.0 附录 A.1 含 "00 07" + "先写错再修正" 自相矛盾段落。v1.1 删除该段落，改为：
```
00 17  -- Length = 23 = 0x17 (Unit ID + FC + Byte Count + 10 registers = 1+1+1+20)
```
算式 1+1+1+20=23 与结论 0x17=23 一致。T52 断言此字节序列。**已彻底修复**。

### 6.2 M-CRIT-2（位打包字节序 T02 仅断言 byte count）→ v1.1 修复确认 ✅

v1.0 §2.3.1 位打包描述模糊，§6.1.2 示例"quantity=10 → byte count=2"无位数据值。v1.1 §2.3.1 显式声明"字节序 little-endian，字节内位序 LSB-first"（术语见 M2-LOW-1），§6.1.2 示例改为 `01 02 03 01`，T02 增加 ResponseValues=[0x02, 0x03, 0x01]，新增 T51。**字节序描述与示例已修复**（术语精度见 M2-LOW-1）。

### 6.3 M-CRIT-3（T01/T05 默认值矛盾）→ v1.1 修复确认 ⚠️ 部分修复

v1.0 T01 默认响应 `01 01 01 00` 与默认零规则矛盾。v1.1 T01 显式 ResponseValues=[0x00]，T05 显式 ResponseValues=[0x12, 0x34]。但 §6.1.1 文本示例仍为 `01 01 01`（见 M2-MED-1）。**测试用例已修复，文本示例残留矛盾**。

### 6.4 M-HIGH-1（Direction 字段语义不清）→ v1.1 修复确认 ✅

v1.0 §3.2 称"informational only" 但 §3.4 暗示强制处理。v1.1 Direction 标记 DEPRECATED，§3.2 注释明确"planner 忽略 Direction"，§3.4 表标注"已废弃字段"，T58 验证。**已修复**。

### 6.5 M-HIGH-2（WriteValue/Quantity 非法处理不一致）→ v1.1 修复确认 ✅

v1.0 §6.5.3 与 §6.10.3 对"非法值"处理不一致。v1.1 §6.5.3 改写为统一规则表（语义非法无 ExceptionCode → 拒绝；配 ExceptionCode → 合法），新增 T53/T54。**已修复**。

### 6.6 M-HIGH-3（Transaction ID off-by-one）→ v1.1 修复确认 ✅

v1.0 §3.2 说"第 N 个 = N-1" 但 §6.11.3 说"65536 事务从 0 到 65535 后回绕"。v1.1 统一为 `TID = (N-1) mod 65536`，T31/T55 修复。**已修复**（T55 参数自洽性见 M2-LOW-3）。

### 6.7 M-MED-1（T31 继承错误）→ v1.1 修复确认 ✅

T31 同步修复为"第 65536 个 TID=65535，第 65537 个 TID=0"，新增 T55。**已修复**。

### 6.8 M-MED-2（FC 0x2B SubFunction 默认值）→ v1.1 修复确认 ✅

v1.0 §3.2 FC 0x2B SubFunction 默认值未声明。v1.1 §3.2 注释"FC=0x2B 时 SubFunction 必须 0x0D 或 0x0E，否则 Validate 拒绝"，新增 T56/T57。**已修复**。

### 6.9 M-MED-3（位打包字节序未声明）→ v1.1 修复确认 ✅

v1.0 §6.7.2 示例 `0F 0000 000A 02 03 01` 位数据含义不清。v1.1 §2.3.1 显式声明字节序与位序，新增 T59。**已修复**（术语精度见 M2-LOW-1）。

### 6.10 M-LOW-1（T17 vs T33 冗余）→ v1.1 修复确认 ✅

v1.0 T17（2 master）与 T33（8×5）冗余。v1.1 T17 改为"最小并发边界"、T33 保留"压力"，明确分工。**已修复**。

### 6.11 v1.1 复核总结

v1.0 的 10 项问题全部修复。但 v1.1 修复过程中未触及本次审计发现的新问题（M2-CRIT-1、M2-CRIT-2、M2-HIGH-1~4、M2-MED-1~5、M2-LOW-1~3），且 §6.1.1 文本示例残留旧矛盾（M2-MED-1）。

---

## 7. §2.3 逐 FC 规格审计对照

| FC | 功能 | §2.3 描述 | 规范匹配 | 单测覆盖 | 发现 |
|----|------|----------|----------|----------|------|
| 0x01 | Read Coils | §2.3.1 | ✅ | T01-T03, T51 | M2-LOW-1 术语 |
| 0x02 | Read Discrete Inputs | §2.3.1 | ✅ | T04 | — |
| 0x03 | Read Holding Registers | §2.3.2 | ✅ | T05-T07, T15, T16, T52 | — |
| 0x04 | Read Input Registers | §2.3.2 | ✅ | T08 | — |
| 0x05 | Write Single Coil | §2.3.3 | ✅ | T09, T10, T53, T54 | — |
| 0x06 | Write Single Register | §2.3.4 | ✅ | T11 | — |
| 0x07 | Read Exception Status | §2.3.8 | ✅ | ❌ 无 | M2-HIGH-3 |
| 0x08 | Diagnostics | §2.3.9 | ⚠️ "多数回显"不精确 | ❌ 无 | M2-HIGH-3, M2-LOW-2 |
| 0x0B | Get Comm Event Counter | ❌ 未描述 | — | ❌ 无 | M2-HIGH-2 |
| 0x0C | Get Comm Event Log | ❌ 未描述 | — | ❌ 无 | M2-HIGH-2 |
| 0x0F | Write Multiple Coils | §2.3.5 | ✅ | T12, T59 | M2-LOW-1 术语 |
| 0x10 | Write Multiple Registers | §2.3.6 | ✅ | T13 | — |
| 0x11 | Report Slave ID | §2.3.10 | ❌ 漏 Byte Count | ❌ 无 | **M2-CRIT-2** |
| 0x14 | Read File Record | §2.3.11 | ✅ | ❌ 无 | M2-HIGH-3 |
| 0x15 | Write File Record | §2.3.11 | ❌ 漏 Record Data | ❌ 无 | **M2-CRIT-1** |
| 0x16 | Mask Write Register | §2.3.12 | ✅ | ❌ 无 | M2-HIGH-3 |
| 0x17 | Read/Write Multiple Regs | §2.3.7 | ⚠️ Quantity 字段冲突 | T14 | M2-MED-2 |
| 0x18 | Read FIFO Queue | §2.3.13 | ⚠️ 缺 31 上限 | ❌ 无 | M2-MED-3 |
| 0x2B | Encapsulated Interface Transport | §2.3.14 | ✅ | T56, T57（仅 Validate） | M2-HIGH-3 |

---

## 8. 测试用例覆盖率审计

### 8.1 路径覆盖（CLAUDE.md Testing Policy §3）

| 类别 | 路径 | 用例 | 覆盖 |
|------|------|------|------|
| 正向 | 10 个 FC 的正常读写 | T01-T14, T61-T68（建议补）| 4/14 FC（仅 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x0F, 0x10, 0x17） |
| 异常 | 9 个异常码 | T18-T25 | 8/9 异常码（缺 0x07，见 M2-HIGH-4） |
| 边界 | 数量上下限/地址边界/Unit ID 边界 | T26-T35 | ✅ |
| 负向 | Validate 拒绝 | T36-T43 | 8 条 |
| 集成 | e2e | T44-T47 | 4 条 |
| Wire-format | tshark 验证 | T48-T50 | 3 条 |
| 追加 | v1.1 补充 | T51-T60 | 10 条 |
| **合计** | — | — | **60 条** |

### 8.2 业务场景覆盖（CLAUDE.md Testing Policy §2）

| 场景 | 用例 | 覆盖 |
|------|------|------|
| 读写线圈 | T01-T03, T12, T51, T59 | ✅ |
| 读写寄存器 | T05-T07, T11, T13, T14 | ✅ |
| 异常响应 | T18-T25, T53 | ⚠️ 缺 0x07 |
| 广播 Unit ID=0 | T28, T29 | ⚠️ M2-HIGH-1 不可用 |
| 多事务序列 | T15, T16, T31, T55 | ✅ |
| 多会话并发 | T17, T33, T47 | ✅ |
| Transaction ID 回绕 | T31, T55 | ⚠️ T55 参数矛盾 |

---

## 9. 扩展表字段覆盖率审计

扩展表 21 个 MODBUS 适用字段（v1.1 修订记录自述）：

| 字段 | v1.1 声明覆盖 | 实际可用 | 发现 |
|------|--------------|----------|------|
| protoid | ✅ | ✅ | — |
| len | ✅ | ✅ | — |
| func | ✅ | ✅ | — |
| excp | ✅ | ⚠️ 缺 0x07 | M2-HIGH-4 |
| transid | ✅ | ✅ | — |
| unitid | ✅ | ❌ omitempty 冲突 | **M2-HIGH-1** |
| regcount | ✅ | ✅ | — |
| starting_address | ✅ | ✅ | — |
| write_value | ✅ | ✅ | — |
| values | ✅ | ✅ | — |
| mask_and/mask_or | ✅ | ⚠️ 无单测 | M2-HIGH-3 |
| read_address/write_address | ✅ | ⚠️ 与 StartingAddress 规则不清 | M2-MED-2 |
| read_quantity/write_quantity | ✅ | ⚠️ 与 Quantity 冲突未定义 | M2-MED-2 |
| sub_function | ✅ | ✅ | — |
| response_values | ✅ | ⚠️ 与 ExceptionCode 互斥未定义 | M2-MED-5 |
| suppress_broadcast | ✅ | ⚠️ 依赖 UnitID=0 | M2-HIGH-1 |
| direction | ✅ | ✅（已废弃）| — |

合计 21 字段中，**1 字段不可用**（unitid，M2-HIGH-1），**5 字段语义不明**（excp/M2-HIGH-4、mask_and/M2-HIGH-3、read/write_address & quantity/M2-MED-2、response_values/M2-MED-5、suppress_broadcast/M2-HIGH-1）。

---

## 10. HexDump 自洽性审计

附录 A（1149-1200 行）三个示例逐字节验证：

### A.1 单事务读保持寄存器

**请求**：12 字节 = 7(MBAP) + 5(PDU)
```
00 00  00 00  00 06  01  03  00 00  00 0A
TID=0  PID=0  Len=6 Unit=1 FC=3 Addr=0 Qty=10
```
Length = 1+1+2+2 = 6 ✅

**响应**：29 字节 = 7(MBAP) + 1(FC) + 1(ByteCount) + 20(寄存器值)
```
00 00  00 00  00 17  01  03  14  + 20 bytes
TID=0  PID=0  Len=23 Unit=1 FC=3 BC=20
```
Length = 1+1+1+20 = 23 ✅

### A.2 异常响应

**请求**：12 字节
```
00 00 00 00 00 06 01 03 FF FF 00 0A
```
Length = 1+1+2+2 = 6 ✅

**响应**：9 字节
```
00 00 00 00 00 03 01 83 02
```
Length = 1(Unit) + 1(FC) + 1(ExceptionCode) = 3 ✅
FC = 0x03|0x80 = 0x83 ✅

### A.3 多事务序列（3 事务）

逐包验证 Length 字段：

| # | MBAP + PDU | Length 字段 | 算式 | 一致 |
|---|-----------|------------|------|------|
| 1 | `0000 0000 0006 01 03 0000 000A` | 0x0006 | 1+1+2+2=6 | ✅ |
| 2 | `0000 0000 0017 01 03 14 <20B>` | 0x0017 | 1+1+1+20=23 | ✅ |
| 3 | `0001 0000 0006 01 06 0014 1234` | 0x0006 | 1+1+2+2=6 | ✅ |
| 4 | `0001 0000 0006 01 06 0014 1234` | 0x0006 | 1+1+2+2=6 | ✅ |
| 5 | `0002 0000 0006 01 03 0014 0001` | 0x0006 | 1+1+2+2=6 | ✅ |
| 6 | `0002 0000 0005 01 03 02 1234` | 0x0005 | 1+1+1+2=5 | ✅ |

Transaction ID 序列：0, 0, 1, 1, 2, 2（请求/响应共享 TID）✅

**附录 A 全部 HexDump 自洽** ✅

---

## 11. 最终结论

### 11.1 是否可直接进入实现阶段

**不可以**。

必须先返工修复以下 6 项问题：

1. **M2-CRIT-1**：§2.3.11 FC 0x15 请求 item 结构必须改为"7B 头部 + Record Data"
2. **M2-CRIT-2**：§2.3.10 FC 0x11 响应必须增加 Byte Count 字段
3. **M2-HIGH-1**：UnitID 必须用 `*uint8` 或其他机制解决 omitempty 与广播值 0 的冲突
4. **M2-HIGH-2**：FC 0x0B/0x0C 必须补充 §2.3 规格或在 §1.3 移除声称
5. **M2-HIGH-3**：§2.3 描述的 10 个 FC（0x07/0x08/0x11/0x14/0x15/0x16/0x18/0x2B）必须各有至少 1 条正向用例
6. **M2-HIGH-4**：异常码 0x07 必须加入 §2.4 + §3.2 + Validate 合法集

### 11.2 建议返工优先级

| 优先级 | 问题 | 原因 |
|--------|------|------|
| P0 | M2-CRIT-1, M2-CRIT-2 | wire-format 错误，Wireshark 解析失败 |
| P0 | M2-HIGH-1 | 广播功能完全不可用，核心业务场景缺失 |
| P1 | M2-HIGH-3 | 60% 的 FC 描述无任何测试，违反 Testing Policy §1+§3 |
| P1 | M2-HIGH-2 | §1.3 声称但 §2.3 缺失，文档自相矛盾 |
| P1 | M2-HIGH-4 | 异常码规则错误，影响 1/9 异常场景 |
| P2 | M2-MED-1~5 | 实现歧义但不立即导致 wire 错误 |
| P3 | M2-LOW-1~3 | 文档精度/术语/测试参数微调 |

### 11.3 测试用例目标值

当前 60 条，建议补齐后目标 ≥ 72 条：
- T61-T68：8 条 FC 正向用例（0x07, 0x08, 0x11, 0x14, 0x15, 0x16, 0x18, 0x2B）
- T69：FC 0x18 FIFO Count=32 拒绝
- T70：异常码 0x07 合法
- T71：ExceptionCode + ResponseValues 互斥
- T72：Transactions=nil vs [] 行为分支

---

## 12. 审计来源

- Modbus.org MODBUS Application Protocol Specification V1.1b3（MB-ASYM-TCP）
- MODICON PI-MBUS-300 Rev. J（Modbus Protocol Reference Guide，June 1996）
- CLAUDE.md §Testing Policy 8 条规则
- `audit/10-13-rip-modbus-enip-audit.md` §3（v1.0 审计基线）
- §1.3 修订记录 v1.1（本次审计的二次审计基线）

---

**审计完成时间**：2026-08-04T12:07Z
**审计总耗时**：约 90 分钟
**审计覆盖**：全 1292 行设计文档 + 60 条测试用例 + 全部附录 A/B/C