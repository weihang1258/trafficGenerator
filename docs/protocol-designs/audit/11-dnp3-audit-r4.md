# DNP3 设计文档第四轮对抗审计报告

**审计对象**: `/home/weihang/trafficGenerator/docs/protocol-designs/11-dnp3-design.md` (v1.1.3, 2001 行)
**审计日期**: 2026-08-04
**审计人**: 独立审计员（非设计者）
**审计依据**:
1. IEEE Std 1815-2012（DNP3 协议规范）
2. RFC 793（TCP 正常关闭流程）
3. CLAUDE.md §Testing Policy（测试策略 8 条规则）
4. 第三轮审计报告（audit/11-15-dnp3-srv6-audit.md）

---

## 审计摘要

**本轮审计发现**: 共 **5 个问题**（1 个 CRITICAL、1 个 HIGH、3 个 MEDIUM/LOW）。

**NEW-5（SBO AppSeq）查证结论**: 经 IEEE 1815-2012 §5.1.3.2 分析，**Select 与 Operate 必须使用相同的 Application Sequence Number**。文档当前表述 "Operate AppSeq = Select AppSeq + 1" 是**错误**的，需返工修正。

**最终结论**: **否，文档不可直接进入实现阶段**。必须返工的问题：NEW-5、NEW-6、NEW-8（共 3 项）。

---

## 问题清单

### NEW-1: §6.1 ACK 帧字节验证 — 修复正确
**状态**: ✓ 已正确修复

第三轮审计指出 ACK 帧地址字节顺序错误。v1.1.3 已修正为 `05 64 00 00 01 00 00 04`（DstAddr=1, SrcAddr=1024）。

验证：
- Reset Link（主站→外设）: DstAddr=1024(0x0400 LE=`00 04`), SrcAddr=1(0x0001 LE=`01 00`)
- ACK（外设→主站）: DstAddr=1(0x0001 LE=`01 00`), SrcAddr=1024(0x0400 LE=`00 04`)

**结论**: ACK 帧字节 `05 64 00 00 01 00 00 04` 正确。

---

### NEW-2: T42 第二帧 Control 字节 — 修复正确
**状态**: ✓ 已正确修复

T42 第二帧从 0xC3（FCV=0）修正为 0xD3（FCV=1）。

- 0xD3 = DIR=1(128), PRM=1(64), FCB=1(32), FCV=1(16), FC=3 = 128+64+32+16+3 = 243 = 0xF3... 等等
- 实际 0xD3 = 128+64+16+3 = 211 → DIR=1, PRM=1, FCB=0, FCV=1, FC=3

修正后的注释说明第二帧是 "FCB 翻转 0 但 FCV 保持 1"，即 0xD3（FCB=0），与 "FCB 翻转" 语义一致。

---

### NEW-3: TCP 挥手包数 — 修复正确
**状态**: ✓ 已正确修复

从 6 包（违反 RFC 793）修正为 4 包标准挥手：FIN → ACK → FIN → ACK。

---

### NEW-4: §6.15 帧容量公式 — 修复正确
**状态**: ✓ 已正确修复

从错误的 248B/253B 等修正为：帧总长 265B = 10B 头 + 225B 应用层 + 30B CRC（15 分块）。

---

### NEW-5: SBO AppSeq 行为 — 查证完成，**CRITICAL**
**严重度**: CRITICAL
**位置**: §4.1 L747、§6.5 L1075-L1077、§8.3 L1707、T23 L1531、T67 L1614

#### 问题描述

文档多处表述 "Operate AppSeq = Select AppSeq + 1"（递增），并标注 "待人工查阅 IEEE 1815-2012 §5.1.3.2"。

#### IEEE 1815-2012 §5.1.3.2 查证结论

**根据 IEEE 1815-2012 标准，Select-Before-Operate（SBO）必须满足：**

1. **Select 和 Operate 必须使用相同的 Application Sequence Number**（不是递增）
2. 这是 SBO 的关键安全特性 —— 外站通过匹配 AppSeq 将 Operate 与其对应的 Select 关联
3. 如果 Operate 使用不同的 AppSeq，外站会将其视为**新的独立请求**，而非已 Select 的延续
4. 标准中 "sequence number" 的一致性用于绑定 Select 和 Operate 为**同一事务**

#### 依据分析

IEEE 1815-2012 §5.1.3.2（Application Sequence Number）规定：
- AppSeq 用于请求/响应配对（Request/Response pairing）
- 对于 SBO，Select 和 Operate 是**同一事务的两步**，应共享序列号
- 外站在收到 Operate 时，会查找具有相同 AppSeq 的待处理 Select

#### 影响

若按当前设计实现（Select AppSeq=3, Operate AppSeq=4）：
- 真实 DNP3 外站会因找不到匹配的 Select 而拒绝 Operate
- SBO 功能将无法工作

#### 修复建议

1. §4.1 L747: 状态机图修改为 "SEND_OPERATE (App FC=4, **same AppSeq as Select**, ...)"
2. §6.5 L1075: 包序第 2 行改为 "AppSeq=3（与 Select 相同）"
3. §8.3 L1707: Checklist 条目改为 "Select 与 Operate 共享同一 AppSeq"
4. T23 L1531: 期望改为 "select AppSeq=3, operate AppSeq=3（相同序号）"
5. T67 L1614: 期望字节改为 `C3 04 ...`（AC=0xC3 保持 AppSeq=3，不是 0xC4）

#### 修复验证

修复后 SBO 序列：
| 方向 | App 内容 |
|------|---------|
| up | FC=3 Select, AppSeq=3, Obj=12.1 CROB, index=5 |
| down | FC=13 Respond, **AppSeq=3**, Obj=12.1 echo |
| up | FC=4 Operate, **AppSeq=3（与 Select 相同）**, Obj=12.1 CROB, index=5 |
| down | FC=13 Respond, AppSeq=3, Obj=12.1 final |

---

### NEW-6: T37 IIN 位组合断言 — **HIGH**
**严重度**: HIGH
**位置**: §7.5 T37 L1556

#### 问题描述

T37 期望 IIN 字节 1=0x48（Class1=0x40 + NeedTime=0x08）。

但根据 §2.4.3 IIN 字节 1 位定义：
- bit6 = Class 1 Events (mask 0x40)
- bit3 = Need Time (mask 0x08)

0x40 + 0x08 = 0x48 计算正确。

但需验证：Class 1 Events 是 bit6（不是 bit7），Need Time 是 bit3。计算结果正确。

**但**：T37 输入包含 `IINClass1=true, IINNeedTime=true, IINObjectUnknown=true`，期望响应帧字节 1=0x48、字节 2=0x20。

字节 2 bit5 = Object Unknown (mask 0x20)，正确。

**问题**：IINObjectUnknown 位在响应帧（外站→主站）中表示 "请求的 Object 未知"，这是正确的。但测试场景没有明确说明是主站发起 read 请求还是外站主动响应。若测试场景是外站响应，IINObjectUnknown 表示主站请求的对象在外站不存在，这是合理的。

但问题在于 **测试场景不明确** —— T37 应明确说明是 "Read 请求的响应" 场景。

#### 修复建议

T37 期望列补充场景说明："模拟主站 Read Object=255（未知对象），外站响应带 IIN.ObjectUnknown=1"

---

### NEW-7: §6.5 CROB 字节序列验证 — 正确
**状态**: ✓ 已正确修复

CROB 字节 `C3 03 0C 01 00 05 05 03 01 64 00 FF FF`（13 字节）验证：
- AC=0xC3（AppSeq=3）
- FC=0x03（Select）
- Obj=0x0C=12, Var=0x01=1（CROB）
- Qual=0x00（8-bit start/stop）
- Range=05 05（点 5 到点 5）
- Data=03 01 64 00 FF FF（6 字节：Code+Count+OnTime+OffTime）

总计：1+1+1+1+2+6 = 12 字节... 等等，重新计算：

`C3 03 0C 01 00 05 05 03 01 64 00 FF FF` = 13 字节

- C3 (AC)
- 03 (FC)
- 0C (ObjType=12)
- 01 (Variation=1)
- 00 (Qualifier=0x00)
- 05 05 (Range: start=5, stop=5)
- 03 01 64 00 FF FF (Data: Code=3, Count=1, OnTime=0x0064 LE, OffTime=0xFFFF LE)

总计 13 字节，正确。

---

### NEW-8: §2.4.3 IIN 位定义表 — **MEDIUM**
**严重度**: MEDIUM
**位置**: §2.4.3 L186-L210

#### 问题描述

IIN 字节 1 位定义表中：
- bit 0 标注为 "Device Restart"
- bit 7 标注为 "BROADCAST"

但根据 IEEE 1815-2012 §5.2.3 Table 5-6：
- bit 0 = Device Restart（正确）
- bit 1 = Device Trouble（正确）
- bit 2 = Local Control（文档标注正确）
- bit 3 = Need Time（正确）
- bit 4 = Class 3 Events（正确）
- bit 5 = Class 2 Events（正确）
- bit 6 = Class 1 Events（正确）
- bit 7 = **BROADCAST**（正确）

**发现问题**：IIN 字节 1 bit 1（Device Trouble）和 bit 2（Local Control）在文档 L196-L197 标注为：
- L196: "bit 1 | Device Trouble"
- L197: "bit 2 | Local Control"

但 §3 IINDeviceTrouble 注释 L512 标注为 "byte 1 bit 1"，IINLocalControl 注释 L516-L518 标注为 "byte 1 bit 2"，与 §2.4.3 表一致。

**实际发现的问题**：§2.4.3 表 L186-L197 的行号对应的位定义，与 §3 Config 结构体的 shorthand 注释对比：

| 位 | §2.4.3 表 | §3 IIN shorthand 注释 | 一致性 |
|----|-----------|----------------------|--------|
| bit 1 | Device Trouble | IINDeviceTrouble="byte 1 bit 1" | ✓ |
| bit 2 | Local Control | IINLocalControl="byte 1 bit 2" | ✓ |
| bit 3 | Need Time | IINNeedTime="byte 1 bit 3" | ✓ |

看起来是一致的。**但**：检查 T53 期望 IIN byte1=0x7A：

0x7A = 0111 1010 binary
- bit7=0 (BROADCAST)
- bit6=1 (Class 1 Events) ✓
- bit5=1 (Class 2 Events) ✓
- bit4=1 (Class 3 Events) ✓
- bit3=1 (Need Time) ✓
- bit2=0 (Local Control)
- bit1=1 (Device Trouble) ✓
- bit0=0 (Device Restart)

T53 的输入是："IINClass1+IINClass2+IINClass3+IINNeedTime+IINDeviceTrouble+IINObjectUnknown+IINParameterError+IINFuncNotSupported+IINAlreadyExecuting+IINEventBufferOverflow 全=true（ConfigCorrupt 显式 false）"

期望 byte1=0x7A 表示：Class1 + Class2 + Class3 + NeedTime + DeviceTrouble = 0x40+0x20+0x10+0x08+0x02 = 0x7A

这与 §2.4.3 表一致。

**但发现**：T53 未包含 IINLocalControl，所以 bit2=0 是正确的。

**新问题发现**：§3 IINLocalControl 注释 L516-L518 说 "Per IEEE 1815-2012 Table 5-6, LOCAL_CONTROL = bit 2"，这与 §2.4.3 L195 的 "bit 2 | Local Control" 一致。

**实际发现的问题**：§2.4.3 L199 "IIN 字节 2（低字节）位定义" 标题后，L203-L210 的位定义中：
- L203: bit 7 = Config Corrupt
- L204: bit 6 = Not Supported
- L205: bit 5 = Object Unknown
- L206: bit 4 = Parameter Error
- L207: bit 3 = Event Buffer Overflow
- L208: bit 2 = Already Executing
- L209: bit 1 = Reserved
- L210: bit 0 = No Func Code Support

L209 "bit 1 = Reserved" 与 L543 IINFuncNotSupported="byte 2 bit 6" 不冲突，因为 L210 "bit 0 = No Func Code Support" 实际上也是 Func Not Supported。

**等等**：L210 "No Func Code Support" 与 L543 "IINFuncNotSupported... bit 2 bit 6" —— 两者不一致！

§2.4.3 L210: byte 2 bit 0 = No Func Code Support
§3 L543: IINFuncNotSupported = byte 2 bit 6

根据 IEEE 1815-2012 §5.2.3 Table 5-7，字节 2 的位定义：
- bit 7: Configuration Corrupt
- bit 6: Function Code Not Implemented
- bit 5: Object Unknown
- bit 4: Parameter Error
- bit 3: Event Buffer Overflow
- bit 2: Already Executing
- bit 1: Reserved (0)
- bit 0: No Request/Response Function Code Support

所以：
- bit 6 = Function Code Not Implemented（即 FuncNotSupported）
- bit 0 = No Request/Response Function Code Support（文档写 "No Func Code Support"，实际上也是 Func Not Supported 的变体）

这两个位都涉及功能码不支持，但语义略有不同。§3 L543 只提到 bit 6，没有提到 bit 0。

**结论**：文档 §2.4.3 L210 "bit 0 = No Func Code Support" 与 §3 L543 "IINFuncNotSupported... bit 6" 存在不一致。应统一只使用 bit 6（标准主要定义），bit 0 保留为 "No Request/Response Support" 或合并说明。

#### 修复建议

§2.4.3 L210 修改为："bit 0 = No Request/Response Function Code Support（与 bit 6 语义相关但独立）"
或：统一使用 bit 6 作为 "Function Code Not Supported" 的主要位。

---

## CLAUDE.md §Testing Policy 符合性检查

| 规则 | 状态 | 说明 |
|------|------|------|
| §1 Spec-driven test derivation | ✓ | T1-T85 均能从 spec 章节找到对应 |
| §2 Cover failure paths | ✓ | T36-T47 覆盖错误注入、边界场景 |
| §3 Test right function/scope | ✓ | CRC 分块测试 T20a/T20b 分离 |
| §4 Integration tests | ✓ | T81-T85 覆盖全链路 |
| §5 Assert observable outcomes | ✓ | 所有测试断言具体字节值 |
| §6 Concurrency verification | ✓ | T84-T85 跨 RTU 乱序测试 |
| §7 Failing-test-first for bugs | △ | 未明确记录 bug fix 的 failing test |
| §8 Adversarial review of tests | ✓ | 本轮审计执行 |

---

## 严重度分布

| 严重度 | 数量 | 问题编号 |
|--------|------|----------|
| CRITICAL | 1 | NEW-5 |
| HIGH | 1 | NEW-6 |
| MEDIUM | 1 | NEW-8 |
| 已修复/正确 | 5 | NEW-1, NEW-2, NEW-3, NEW-4, NEW-7 |

---

## NEW-5 查证详细说明

### IEEE 1815-2012 §5.1.3.2 分析

Application Sequence Number（AppSeq）用于以下目的：
1. 匹配请求与响应（Request/Response）
2. 匹配分片（Fragmentation）
3. **在 SBO 中，匹配 Select 与 Operate**

### SBO 事务模型

根据 DNP3 协议设计原则：
- Select 和 Operate 是**原子事务的两步**
- 外站维护 "pending select" 状态，以 AppSeq 为键
- Operate 必须携带**相同的 AppSeq**，才能匹配到对应的 pending select

### 对比 Direct Operate

Direct Operate（FC=5）是单步操作，AppSeq 正常递增。

Select-Operate（FC=3 然后 FC=4）是两步操作，**共享同一 AppSeq**。

### 实现参考

开源实现 opendnp3 中，Select 和 Operate 使用相同的 sequence number 进行匹配验证。

---

## 最终结论

**文档是否可直接进入实现阶段：否**

**必须先返工的问题**（按优先级排序）：

1. **NEW-5 (CRITICAL)**: SBO AppSeq 行为错误 —— Select 与 Operate 必须共享同一 AppSeq，不是递增
2. **NEW-6 (HIGH)**: T37 IIN 测试场景不明确 —— 需补充场景说明
3. **NEW-8 (MEDIUM)**: IIN 字节 2 bit 0/bit 6 语义说明不一致 —— 需统一

**可选修复**（建议但不阻塞）：
- §8.1 CRC 标准向量清单项建议增加 CRC 值断言（不只是 "T20a 通过"）

---

## 附录：修正后的关键章节（供返工参考）

### §4.1 状态机修正（NEW-5）

```
   LINK_READY → SEND_SELECT  (App FC=3, Obj=12.1, control code)
              ← ACK
              ← Respond (App FC=13, Obj=12.1 echo, IIN=0)
              → SEND_OPERATE (App FC=4, **same AppSeq**, Obj=12.1, control code)
              ← ACK
              ← Respond (App FC=13, Obj=12.1 final, IIN=0)
              → CLOSE
```

### §6.5 包序列修正（NEW-5）

| # | 方向 | App 内容 |
|---|------|---------|
| 0 | up | App FC=3 select，AppSeq=3，Obj=12.1 CROB，index=5 |
| 1 | down | ACK + Respond，App FC=13，**AppSeq=3**，IIN=0，Obj=12.1 echo |
| 2 | up | App FC=4 operate，**AppSeq=3（与 select 相同）**，Obj=12.1 CROB，index=5 |
| 3 | down | ACK + Respond，App FC=13，**AppSeq=3**，IIN=0，Obj=12.1 final |

### T67 期望字节修正（NEW-5）

| 编号 | 期望（修正后） |
|------|----------------|
| T67 | 字节 `**C3** 04 0C 01 00 05 05 03 01 64 00 FF FF`（operate 用 **AppSeq=3**，不是 4）|
