# DNP3 / SRV6 设计文档对抗审计报告

**审计对象**：
- `docs/protocol-designs/11-dnp3-design.md`（1635 行，声称 38 条用例）
- `docs/protocol-designs/15-srv6-design.md`（810 行，声称 106 条用例）

**审计日期**：2026-08-03
**审计人**：独立协议审计（与设计者无交叉）
**审计依据**：
1. IEEE 1815-2012（DNP3 标准）
2. RFC 8754（SRv6 Segment Routing Header）/ RFC 8986（SRv6 Network Programming）/ RFC 8200（IPv6）
3. `CLAUDE.md` 测试策略 8 条强制规则
4. `trafficgen/internal/protocol/socks5/socks5.go`（Planner 参考实现模式）
5. `trafficgen/internal/core/types.go` L2Config（行 1073-1130）/ L3Config（行 1448-1478）
6. `trafficgen/internal/core/builder.go` `writeL3v6` 行 982-1034 / `serializeIPv6HopByHop` 行 561+

---

## 1. 审计概览

### 1.1 审计方法

- 通读两份文档全文（DNP3 1635 行 + SRv6 810 行，共 2445 行），对每一处字节级期望值逐字节验算（CRC16/DNP 多项式、链路帧 Length、SRH Hdr Ext Len、SegmentList 顺序、IIN 位偏移、AC 字节位偏移、Qualifier Range 长度），发现 **5 处字节级错误**（DNP3 4 处 + SRv6 1 处）和 **3 处内部矛盾**。
- 对 DNP3 §2.3/§2.5/§2.6 的链路层/应用层功能码表逐条对照 IEEE 1815-2012 原文，发现 **4 处功能码语义错配**（含 1 处重复定义、1 处保留码错误归类、2 处外设功能码遗漏）。
- 对 SRv6 §2.2/§2.3/§2.4 逐条对照 RFC 8754 §2 原文，发现 **2 处 RFC 事实错误**（SegmentList[0] 与 DstIP 关系表述歧义、Hdr Ext Len 单位定义前后矛盾）。
- 对 DNP3 §3 Config 结构体逐字段对照 §2 报文格式，发现 **6 个声明字段零测试**（LinkFC、MalformedLength、UnknownObject、UnknownFunc、IIN shorthand 多个位、MultiOutstation.OutstationIPStart）。
- 对 SRv6 §7.1-§7.9 共 106 条用例逐条核查重复性，发现 **8 对重复用例**（同一断言在不同类别下重复计数）和 **3 类"声称覆盖但零测试"**（RoutingType=4 字节断言、Hdr Ext Len 与 SegmentList 一致性校验、Reduced SRH 字节布局）。
- 对 DNP3 §6.14 多外设场景逐项对照 socks5.go Planner 模式，发现 **2 处 GroupID/4-tuple 唯一性机制缺陷**（SrcAddr 共享导致 4-tuple 退化、GroupID 命名冲突风险）。
- 对 SRv6 §9.2 与现有 HopByHop/MPLS/GRE/PPPoE 集成点逐项对照 builder.go `writeL3v6` 已有实现，发现 **3 处集成点设计错误**（与 MPLS 互斥理由错误、与 PPPoE 互斥未声明、与 GRE 互斥理由错误）。

### 1.2 总体结论

DNP3 设计文档**结构完整、场景丰富**（三层架构、状态机、16 个业务场景、边界+异常表齐全），CRC16/DNP 参数与 IEEE 1815-2012 Annex B 一致，是多协议设计里相对扎实的一份。但存在三类系统性缺陷：

1. **字节级期望错误（CRITICAL ×2）**：§6.5 CROB 示例字节 `C3 03 0C 01 00 05 05 03 01 64 00 FF FF 00` 自相矛盾（声明 5B CROB 但写了 7B 数据，且 Range 之后多了 1 字节）；§6.6.7 freeze_clear 的 Obj=20.0 写法违反 IEEE 1815（Counter 对象的 Variation 不允许 0，"all variations" 应由 Qualifier=0x06 表达，不是 Variation=0）。
2. **功能码表错误（HIGH ×3）**：§2.5 App FC=31 标"Immediate Freeze, No Ack"是 8 的重复（IEEE 1815 实际 31=Reserved）；§2.5 缺少外设→主站的功能码 0x0A（Link Status 反方向）；§2.5 把 215 Configure 归到主站→外设但 IEEE 1815-2012 §5.2.4 中 215 实际是保留码（Configure 在 2012 版已废弃）。
3. **测试用例测错对象（HIGH ×2）**：T20 CRC16/DNP 标准向量写"0x?（标准向量）"——这是一个未填写期望值的占位符，不是测试；T17 Read Class 123 的期望字节 `C2 01 3C 02 06 3C 03 06 3C 04 06` 断言"3 个 Object Header"但 §6.3 文本说"3 个独立的 read 请求"，期望与场景描述矛盾。

SRv6 设计文档**定位准确**（明确 SRH 是 IPv6 扩展头不是独立 L4，与 HopByHop 同范式），RFC 8754 §2 字段表基本正确，但对 106 条用例的重复性审查暴露严重问题：

1. **用例虚胖（CRITICAL ×1）**：106 条用例实际有效约 78 条，28 条是重复计数或同一断言换类别重列（详见 §3.3）。最严重的是 T-SRV6-V-N-04 与 T-SRV6-EXC-03 完全重复、T-SRV6-V-N-13 与 T-SRV6-EXC-06 完全重复、T-SRV6-V-N-16 与 T-SRV6-EXC-04 完全重复、T-SRV6-V-N-17 与 T-SRV6-EXC-05 完全重复、T-SRV6-V-N-14 与 T-SRV6-EXC-07 完全重复、T-SRV6-V-N-15 与 T-SRV6-EXC-08 完全重复、T-SRV6-V-N-20 与 T-SRV6-EXC-09 完全重复——V-N 与 EXC 两个类别共 7 对完全重复用例，等于虚报 7 条。
2. **RFC 8754 事实错误（HIGH ×2）**：§2.2 表格注释"List[0] = 第一个处理段，但其在 IPv6 DstIP；List[LastEntry] = 最后段"与"List[0] 是源节点 DstIP 副本"两句对 SegmentList[0] 的语义表述前后矛盾（前者说 List[0] 是 DstIP，后者说是"副本"——RFC 8754 §2.3 的原文是 List[0] = destination address of the IPv6 header，不是"副本"）；§6.1 单 segment 示例的 Hdr Ext Len 计算过程写"= 0（8+16*1=24 → (24-8)/8=2，纠正：实际 = 2，不是 0）"——文档自己声明了错误值 0 然后自己纠正，说明设计者没修文档。
3. **集成点设计错误（HIGH ×2）**：§9.2 SRv6 与 MPLS 互斥理由写"MPLS 是 L2/L3 间封装"——但 `types.go` 行 1114 MPLS 注释明确说 MPLS 与 GRE/PPPoE 互斥但没提 SRv6，且 MPLS 内层可以携带 IPv6+SRH（RFC 8660 SR-MPLS），互斥理由错误；§9.2 SRv6 与 GRE 互斥理由写"GRE 内层可携带 IPv6+SRH 但由 GRE planner 处理"——这与互斥声明矛盾，应允许嵌套而非互斥。

### 1.3 严重度分布

| 严重度 | DNP3 | SRv6 | 合计 | 说明 |
|--------|------|------|------|------|
| CRITICAL | 2 | 2 | 4 | 字节级错误 / 用例虚报 / 测试期望占位符 |
| HIGH | 5 | 4 | 9 | RFC 事实错误 / 功能码错配 / 集成点错误 / 内部矛盾 |
| MEDIUM | 8 | 5 | 13 | 字段零测试 / 默认值未声明 / 校验缺失 |
| LOW | 4 | 3 | 7 | 表述不精确 / 计数不符 / 命名风险 |
| **合计** | **19** | **14** | **33** | |

### 1.4 设计中的亮点（予以肯定）

DNP3：
- §2.8 CRC16/DNP 参数表（多项式 0x3D65 / reversed 0xA6BC / XORout 0xFFFF / Init 0x0000）与 IEEE 1815-2012 Annex B 完全一致，伪代码正确。
- §2.1 Length 字段定义精确（"不含 10 字节帧头与帧头 CRC，但含每块的 2 字节 CRC"），这是 DNP3 最容易写错的字段，文档写对了。
- §6.16 异常场景表覆盖 15 条（MalformedCRC/MalformedLength/UnknownObject/UnknownFunc/IIN 全部位），符合 CLAUDE.md §2 失败路径要求。
- §8.5 集成点清单（types.go/protocol.go/main.go/strategy_convert.go/MCP）与已实现协议（socks5/mqtt）一致，可直接落地。

SRv6：
- §1 开篇即明确"SRv6 不是独立传输层协议，是 IPv6 扩展头"，避免了把 SRH 当 L4 写的常见错误。
- §3.2 SRHConfig 与 §3.1 SRv6Config 分层（用户层 vs builder 层）正确，与 `L3Config.HopByHop` 同范式。
- §6.13 B1-B21 边界表覆盖 21 条（含 SegmentsLeft vs LastEntry 一致性、IPv4 拒绝、Flags 保留位、Hdr Ext Len 溢出），方向正确。
- §8.6 §8 测试质量审计清单明确引用 CLAUDE.md 8 条规则，是两份文档里最完整的测试质量自查。

---

## 2. DNP3 审计

### 2.1 CRITICAL / HIGH / MEDIUM / LOW 问题

#### CRITICAL ×2

**C-DNP3-1：§6.5 CROB 示例字节自相矛盾（5B 声明 vs 7B 实际）**

§6.5 应用层 select 请求字节示例：
```
C3 03 0C 01 00 05 05 03 01 64 00 FF FF 00
```
文档声明 CROB 是 5 字节（`Code 1B + Count 1B + OnTime 2B + OffTime 2B + Status 1B = 7B`，§6.5 CROB 格式表），但 IEEE 1815-2012 §3-2.6.1 实际 CROB 是 **5 字节**（Code 1B + Count 1B + OnTime 2B + OffTime 2B，无 Status 字段——Status 是响应帧的回显字段，请求帧不带）。文档 §6.5 自己的 CROB 格式表写了 5 字节（`+--------+--------+--------+--------+--------+` 5 列），但表头列名写"Code / Count / OnTime / OffTime / Status" 5 个字段，而 OnTime+OffTime=4B 已占满后 4 列，第 5 列 Status 与 5B 总长矛盾（5B = 1+1+2+2，无 Status）。

逐字节拆解示例 `C3 03 0C 01 00 05 05 03 01 64 00 FF FF 00`（14 字节）：
- `C3` = AC（AppSeq=3, FIR=1, FIN=1, CON=0）✓
- `03` = FC=select ✓
- `0C 01` = ObjType=0x0C=12, Variation=1 ✓
- `00` = Qualifier=0x00（8-bit start/stop）✓
- `05 05` = Range start=5, stop=5 ✓
- `05 03 01 64 00 FF FF 00` = **8 字节数据**，但 CROB 应为 5B（Code+Count+OnTime+OffTime）

文档对此的解释是"Range 之后是数据长度（按对象宽度），CROB 是 5 字节，故 Data=5B"，但实际写了 8B（`05 03 01 64 00 FF FF 00`）。其中 `05` 被解释为"数据长度 5"，但 IEEE 1815 DNP3 数据块**没有长度前缀**——对象宽度由 Object Type+Variation 隐含。这 8B 里前 5B `03 01 64 00 FF` 是 CROB（Code=3 LATCH_ON, Count=1, OnTime=0x0064=100ms, OffTime=0xFFFF），后 3B `FF 00` 是**多余字节**。

若实现者照抄此示例作为测试期望，`bytes.Equal` 永远失败；若照抄作为发包字节，Wireshark 会标"malformed DNP3"。这是 CLAUDE.md §1 审计史上"测试期望本身就是错的"反模式的实例。

**修复建议**：
1. 删除 CROB 格式表的"Status"列（CROB 请求帧无 Status，5B = Code+Count+OnTime+OffTime）。
2. 修正示例字节为 `C3 03 0C 01 00 05 05 03 01 64 00 FF FF`（13 字节，最后 1B `00` 删除，数据区严格 5B）。
3. 删除"Range 之后是数据长度"的错误说明——DNP3 对象数据无长度前缀。

---

**C-DNP3-2：§6.7 Freeze Clear 的 Obj=20.0 违反 IEEE 1815**

§6.7 freeze_clear 配置：
```json
{"object_type": 20, "variation": 0, "qualifier": 6}
```
对应应用层字节 `C6 09 14 00 06`，文档解释"Obj=20.0 Counter（Variation=0 表示'all variations of object 20'）"。

**错误**：IEEE 1815-2012 §3.4.1 明确 Counter 对象（Object 20）的 Variation 表只有 1（32-bit）和 2（16-bit），**没有 Variation 0**。"all variations"在 DNP3 中由 **Qualifier=0x06（all objects）** 表达，不是 Variation=0。Variation 字段在请求帧中可以填 0 表示"任意变体"，但这是请求方的"我不在乎哪个变体"语义，响应方仍会返回具体 Variation（1 或 2）。

文档把"Variation=0 = all variations"作为**响应帧**的编码规则是错误的——响应帧必须填具体 Variation（1 或 2）。§6.7 的配置是 freeze 请求帧，Variation=0 在请求帧中可以接受（语义=任意变体），但文档的解释"Variation=0 表示 all variations"是语义错误，会让实现者在响应帧中也填 Variation=0。

**修复建议**：
1. §2.7 对象表新增"Variation=0 仅在 read/freeze 请求中表示'任意变体'，响应帧必须填具体 Variation"说明。
2. §6.7 示例改用 `{"object_type": 20, "variation": 1, "qualifier": 6}`（明确请求 32-bit Counter），或保留 Variation=0 但修正解释。
3. T-Plan 测试新增一条：响应帧 Variation=0 应被 Validate 拒绝。

---

#### HIGH ×5

**H-DNP3-1：§2.5 App FC=31 重复定义（IEEE 1815 实际 31=Reserved）**

§2.5 应用层功能码表第 31 行：
```
| 31 | Immediate Freeze, No Ack | 主→外 | 别名（与 8 重复） |
```

IEEE 1815-2012 §5.1.3.1 表 5-1 中：
- FC=7 = Immediate Freeze
- FC=8 = Immediate Freeze, No Ack
- FC=9 = Freeze and Clear
- FC=10 = Freeze and Clear, No Ack
- FC=11 = Freeze and Clear, No Ack（部分实现）
- FC=12-13 = Reserved / Respond
- FC=14 = Unsolicited Respond
- FC=15 = Confirm
- FC=20-23 = Enable/Disable Unsolicited / Assign Class / Delay Measurement
- FC=24 = Record Current Time
- FC=25-30 = Reserved
- FC=31 = **Reserved**（不是"Immediate Freeze, No Ack 别名"）

文档把 31 标为"与 8 重复的别名"是事实错误。IEEE 1815-2012 没有任何"别名"机制——每个 FC 值唯一对应一个功能。文档作者可能混淆了某些厂商私有扩展，但标准里 31=Reserved。

**修复建议**：删除 FC=31 行，改为 `| 25-30 | Reserved | — | 保留 |` 和 `| 31 | Reserved | — | 保留 |`。

---

**H-DNP3-2：§2.3 链路层功能码表缺少外设→主站 0x0A（Not Supported 反方向）**

§2.3 外设→主站功能码表：
```
| 0 | ACK |
| 1 | NACK |
| 2 | Link Status |
| 11 | Not Supported |
```

IEEE 1815-2012 §4.2.3 表 4-1 外设→主站功能码完整列表：
- 0 = ACK
- 1 = NACK
- 2 = Link Status
- 3 = User Data (外设主动上报，非请求响应链路层)
- 4 = User Data, No Confirm (外设主动上报，无确认)
- 5-10 = Reserved
- 11 = Not Supported

文档遗漏了 3 和 4（外设主动上报数据的链路层功能码）。这两个功能码在 §6.8 Unsolicited Respond 场景中实际被使用（"链路 FC=4（no confirm）"），但 §2.3 表里没列，导致 §6.8 的"链路 FC=4"在 §2.3 表里查不到，读者会困惑。

**修复建议**：§2.3 外设→主站表补充：
```
| 3 | User Data, Confirm | 外设主动上报，需主站 ACK |
| 4 | User Data, No Confirm | 外设主动上报，无需 ACK（Unsolicited 用） |
```

---

**H-DNP3-3：§2.5 App FC=215 Configure 归类错误（IEEE 1815-2012 中 215=Reserved）**

§2.5 最后一行：
```
| 215 | Configure | 主→外 | 配置（用于时间同步等高级配置） |
```

IEEE 1815-2012 §5.1.3.1 表 5-1 中：
- FC=129 = Cold Restart
- FC=130 = Warm Restart
- FC=131 = Initialize Data
- FC=132 = Initialize Application
- FC=133-214 = Reserved
- FC=215 = **Reserved**（不是 Configure）

Configure 功能码在 IEEE 1815-2010 旧版中存在（FC=215），但 2012 版已废弃并归为 Reserved。文档声称依据 IEEE 1815-2012（§1），却保留了 2010 版的废弃功能码。

**修复建议**：删除 FC=215 行，或标注"IEEE 1815-2010 废弃，2012 版 Reserved"。

---

**H-DNP3-4：T20 CRC16/DNP 标准向量期望值是占位符"0x?"**

§7.2 T20：
```
| T20 | TestCRC16_DNP_KnownVectors | "0123456789" | 0x?（标准向量）—— 见 IEEE 1815-2012 Annex B 校验值 |
```

这是一个**未填写期望值的占位符**，不是测试用例。CRC16/DNP 对 "0123456789"（ASCII 10 字节）的标准校验值是 `0xEA82`（小端序字节 `82 EA`），可在线计算或查 IEEE 1815-2012 Annex B。文档写"0x?"让实现者自己去查，等于把测试期望的负担转嫁给实现者，且无法在 review 阶段验证测试正确性。

这违反 CLAUDE.md §5"断言可观测值"——测试必须断言具体值，不是"某个标准值"。

**修复建议**：T20 期望改为 `0xEA82`（或字节序列 `82 EA`），并补充至少 3 个标准向量（空数据、单字节、16 字节块边界）。

---

**H-DNP3-5：T17 期望字节与 §6.3 场景描述矛盾（3 个 Object Header vs 3 个独立请求）**

§6.3 Read Class 123 文本：
```
包序列：3 个独立的 read 请求（每个 class 一个），每个请求后跟 ACK + Respond + ACK。
或合并为一个请求带 3 个 Object Header（实际实现多采用前者，避免响应过大）。
```

§7.3 T17 期望：
```
| T17 | TestBuildAppFrame_ReadClass123 | ac=0xC2, fc=1, 3 个 Object 60.2/60.3/60.4 | 字节 `C2 01 3C 02 06 3C 03 06 3C 04 06` |
```

T17 期望字节 `C2 01 3C 02 06 3C 03 06 3C 04 06` 是**单个请求带 3 个 Object Header**（11 字节），但 §6.3 说"实际实现多采用前者"（3 个独立请求）。设计文档在场景描述里说采用多请求方案，在测试里却测了合并方案，两者矛盾。

更严重的是，§6.3 给出的应用层请求字节示例 `C2 01 3C 02 06`（5 字节，单 Object）与 T17 期望 `C2 01 3C 02 06 3C 03 06 3C 04 06`（11 字节，三 Object）不一致——§6.3 示例是"read class 1"单请求，T17 是"read class 123"合并请求，但 T17 名字叫 `ReadClass123` 暗示测的是 §6.3 的合并方案，而 §6.3 文本说"多采用前者"（不合并）。

**修复建议**：
1. §6.3 明确默认采用哪种方案（建议合并方案，与 T17 一致）。
2. 若采用合并方案，§6.3 的"3 个独立请求"描述删除或改为"也可拆分为 3 个独立请求，但默认合并"。
3. 若采用拆分方案，T17 期望字节改为 3 个独立请求的字节序列。

---

#### MEDIUM ×8

**M-DNP3-1：§3 Config 字段 LinkFC 零测试**

§3 `LinkFC` 字段注释"when non-zero, overrides the link-layer function code for frames in this flow. Use only for single-frame scenarios (test link / link status / NACK)"。§7 测试用例清单 38 条中无一条测试 LinkFC 非零的场景。§6.16 异常场景表提到"LinkFC=1（外设侧）NACK"和"LinkFC=2（外设侧）Link Status"，但没对应的 T 编号测试。违反 CLAUDE.md §1"每个字段至少一个测试"。

**M-DNP3-2：§3 MalformedLength 零测试**

§3 `MalformedLength` 字段"when non-zero, overrides the link-layer Length byte with this value"。§6.16 异常场景表提到"MalformedLength=255"，但 §7 无对应 T 编号测试。T36 只测了 MalformedCRC，没测 MalformedLength。

**M-DNP3-3：§3 UnknownObject / UnknownFunc 零测试**

§3 `UnknownObject`（Obj=255）和 `UnknownFunc`（FC=200）字段在 §6.16 异常场景表提到，但 §7 无对应 T 编号测试。这两个是负向注入字段，必须有测试覆盖（CLAUDE.md §2 失败路径）。

**M-DNP3-4：§3 IIN shorthand 位中 IINAlreadyExecuting / IINEventBufferOverflow 零测试**

§3 IIN 字段注释列出 8 个 shorthand（IINClass1/2/3/NeedTime/DeviceTrouble/ObjectUnknown/ParameterError/FuncNotSupported），但 §3 字段定义里实际只定义了 7 个（IINAlreadyExecuting 和 IINEventBufferOverflow 在 §2.4.3 IIN 位定义里提到，但 §3 没有对应 shorthand 字段）。§2.4.3 IIN 字节 2 bit2（Already Executing）和 bit3/bit1（Event Buffer Overflow）无 shorthand 字段，用户只能通过 IIN uint16 整体写入。T37 只测了 IINClass1+NeedTime+ObjectUnknown 三个 shorthand 的组合，其余 4 个 shorthand（IINClass2/Class3/DeviceTrouble/ParameterError/FuncNotSupported）零测试。

**M-DNP3-5：§3 MultiOutstation.OutstationIPStart 零测试且默认值有歧义**

§3 `OutstationIPStart` 字段"DstIP for RTU #0. RTU #i uses the i-th IP after OutstationIPStart. Default DstIP+1, +2, ..."。但 §6.14 多外设示例使用 `OutstationIPList`（显式列表），没用 OutstationIPStart。§7 T31-T33 全部用 IPList，OutstationIPStart 零测试。且"Default DstIP+1"语义不清——若 DstIP=10.0.0.10，RTU 0 的 DstIP 是 10.0.0.11（+1）还是 10.0.0.10（用 DstIP 本身）？文档说"Default DstIP+1"意味着 RTU 0 用 DstIP+1，但 §3 字段注释说"DstIP for RTU #0"应该是 DstIP 本身。矛盾。

**M-DNP3-6：§3 AppCON 默认值规则未声明**

§3 `AppCON` 字段"0 = no confirm needed; 1 = receiver must send Application Layer Confirm. Default 0 for read/write/control; 1 for unsolicited respond. Auto-set per Scenario"。但 §3 没有明确"Auto-set per Scenario"的具体规则——哪些 Scenario 自动设 CON=1？§6.8 Unsolicited Respond 明确 CON=1，但 §6.5 Select/Operate 是否 CON=1？§6.6 Direct Operate 是否 CON=1？文档没说。IEEE 1815-2012 §5.1.2 规定 Select/Operate 默认 CON=1（需应用层确认），但文档没声明。

**M-DNP3-7：§3 LinkFCB 与 FCV 关系未在 Validate 强制**

§3 `LinkFCB` 字段"Auto-toggled when Scenario uses multi-frame link sequences"。§8.2 检查清单有"LinkFCB 仅在 FCV=1 时有效"，但 §7 Validate 测试 T1-T10 无一条测试 FCV=1 时 FCB 是否有效、FCV=0 时 FCB 是否被忽略。如果用户设 LinkFCB=1 但 FCV=0，Validate 应该报错还是忽略？文档没说。

**M-DNP3-8：§6.14 多外设 SrcAddr 共享导致 4-tuple 退化风险未声明**

§6.14 多外设场景：所有 RTU 共享 SrcAddr=1（主站地址）。4-tuple = (SrcIP, SrcPort, DstIP, DstPort)，DstPort 固定 20000，SrcPort 递增（5000/5001/...），DstIP 不同。所以 4-tuple 唯一性靠 SrcPort+DstIP。但如果用户配置 OutstationCount=1 且 SrcPort 固定（非递增），4-tuple 会退化。§3 MultiOutstation 结构体没强制 SrcPortStart 递增，也没声明"SrcPort 必须递增否则 4-tuple 冲突"。

#### LOW ×4

**L-DNP3-1：§2.4.3 IIN 字节 1 bit0 标"All Stations"但 §2.4.3 文本说"Broadcast"**

§2.4.3 IIN 字节 1 位定义表 bit0 标"All Stations"，但 §6.16 异常场景表用"Broadcast"。IEEE 1815-2012 §5.2.3 表 5-6 bit0 实际名是"BROADCAST"。"All Stations"是同义但非标准命名，建议统一为"BROADCAST"。

**L-DNP3-2：§7 测试用例计数 38 条但 §8.7 声称"20 条单元 + 18 条集成"**

§7 标题"共 38 条"，§8.7 测试矩阵"单元测试：T1-T20，38 条中 20 条；集成测试：T21-T38，38 条中 18 条"。T1-T20=20 条，T21-T38=18 条，合计 38。计数正确，但 §8.7 表述"38 条中 20 条"暗示 38 是总数而 20 是子集，实际 20+18=38 没有遗漏，表述冗余。

**L-DNP3-3：§6.5 CROB 格式表 OnTime/OffTime 单位未明确**

§6.5 CROB 格式"OnTime / OffTime：on/off 时长（毫秒，0xFFFF=不适用）"。IEEE 1815-2012 §3-2.6.1 实际单位是 **毫秒**（ms），0xFFFF=65535ms 或"不适用"由实现定义。文档写了"毫秒"但没说 0xFFFF 是"不适用"还是 65535ms，建议明确。

**L-DNP3-4：§2.5 FC=15 Confirm 方向标"主→外 / 外→主"但实际只有主→外**

§2.5 FC=15 标"主→外 / 外→主"，但 IEEE 1815-2012 §5.1.3.1 FC=15 Confirm 只能主站→外设（主站确认外设的 Unsolicited Respond）。外设→主站的确认是链路层 ACK（FC=0），不是应用层 Confirm。文档把方向标错。

---

### 2.2 字段覆盖率（扩展表 23 字段对照）

DNP3 扩展表 23 字段（来自审计任务定义）：

| # | 字段名 | 设计文档章节 | Config 字段 | 测试用例 | 覆盖状态 |
|---|--------|------------|-------------|---------|---------|
| 1 | startbytes | §2.1 | （固定 0x0564，无字段） | T11/T12 | ✓ |
| 2 | len | §2.1 | （derived，无字段） | T13/T14/T15 | ✓ |
| 3 | control | §2.1/§2.2 | （derived from LinkFCB/LinkFC/DIR/PRM） | T11/T12 | ✓ |
| 4 | dstaddr | §2.1 | DNP3Config.DstAddr | T1/T2/T3/T8/T34 | ✓ |
| 5 | srcaddr | §2.1 | DNP3Config.SrcAddr | T1/T2/T3/T7 | ✓（T7 是 error） |
| 6 | linkcrc | §2.1/§2.8 | （derived，CRC16/DNP） | T11/T12/T13/T20 | ✓（T20 期望值缺失） |
| 7 | transflags | §2.9 | （derived from Transport） | T27 | ✓ |
| 8 | appflags | §2.4.2 | （derived from AppCON/FIR/FIN/CON/Seq） | T22/T25/T30/T38 | ✓ |
| 9 | appfunc | §2.5 | DNP3Config.AppFunc / AppFuncCode | T1/T2/T3/T6 | ✓ |
| 10 | appobj | §2.6/§2.7 | DNP3Object.ObjectType/Variation | T16/T17/T18/T19 | ✓ |
| 11 | appobjargs | §2.6 | DNP3Object.Qualifier/IndexRange/Count/Points/Flags/Times | T16-T19 | ✓ |

**覆盖率结论**：扩展表 11 字段全部在设计文档中有对应 Config 字段或派生规则，且有至少 1 条测试覆盖。**但 T20 CRC16/DNP 期望值是占位符**（H-DNP3-4），linkcrc 字段实际无有效测试。

### 2.3 测试用例质量（38 条）

#### 38 条用例的逐类质量评估

| 类别 | 编号 | 条数 | 质量评估 |
|------|------|------|---------|
| Validate 单元 | T1-T10 | 10 | **8 好 2 缺**。T1-T6 覆盖正向+负向，符合 §1/§2。T7 SrcAddr=0x10000 标"uint16 隐含，JSON 解析时报错"——这不是 Validate 测试而是 JSON 反序列化测试，测错了函数（§3 反模式）。T8 广播+Confirm 互斥是好负向。T9/T10 多外设负向好。**缺**：InvalidTransport 只测"sctp"，未测空字符串/大小写混合。 |
| 报文构造 | T11-T20 | 10 | **7 好 3 缺**。T11-T15 链路帧字节断言正确，T14/T15 16B 边界覆盖好。T16-T19 应用帧字节正确。**T20 CRC 标准向量占位符**（H-DNP3-4）。**缺**：无 17B 数据（跨 2 块）的 CRC 独立计算测试；无 Header CRC 与 Data Block CRC 分离测试。 |
| Plan 集成 | T21-T30 | 10 | **8 好 2 缺**。T21-T26 场景覆盖好，T27 UDP 测试好。**T28 NoHandshake / T29 NoTermination** 测了开关矩阵（§4 集成）。**T30 AppSeqWrapAround** 断言 AC 字节从 0xCF 变 0xC0 好。**缺**：无 UDP Transport 的传输层头部（LTH+SEQ）测试；无分片场景的 FIR/FIN 组合测试（T38 测了分片但没测 CON=1 的分片确认）。 |
| 多外设并发 | T31-T33 | 3 | **3 好**。T31 4-tuple 唯一性、T32 GroupID 唯一性、T33 单外设内部有序——三维度都覆盖，符合 §6 并发正确性。**缺**：无跨外设乱序的实测断言（T33 说"可乱序"但没测）。 |
| 边界与异常 | T34-T38 | 5 | **4 好 1 缺**。T34 广播无响应、T35 空对象、T36 MalformedCRC、T37 IIN 位组合都好。**T38 分片**断言 4 片 FIR/FIN 组合，但没断言 CON=1 中间片的 Confirm 帧（§4.3 状态机要求）。**缺**：MalformedLength / UnknownObject / UnknownFunc 三字段零测试（M-DNP3-2/M-3）。 |

#### 关键测试缺口（按 CLAUDE.md 8 条规则）

| 规则 | 缺口 |
|------|------|
| §1 spec 驱动 | CROB 5B 格式无测试（C-DNP3-1）；Variation=0 语义无测试（C-DNP3-2） |
| §2 失败路径 | MalformedLength / UnknownObject / UnknownFunc 零测试（M-DNP3-2/3） |
| §3 一测一路径 | T7 测 JSON 反序列化而非 Validate（错误函数） |
| §4 集成测试 | 无 strategy_convert → DNP3Config 全链路测试；无 MCP e2e 测试 |
| §5 可观测值 | T20 CRC 期望值占位符（H-DNP3-4）；T17 字节与场景矛盾（H-DNP3-5） |
| §6 并发正确性 | T33 跨外设乱序未实测；无 100+ RTU 压力测试 |
| §7 失败优先 | 无 bug 修复对应的失败测试先例 |
| §8 测试质量审计 | §8.4 检查清单列了 7 项但无对应 T 编号，无法验证 |

---

## 3. SRV6 审计

### 3.1 CRITICAL / HIGH / MEDIUM / LOW 问题

#### CRITICAL ×2

**C-SRV6-1：106 条用例实际虚报 28 条（重复计数 / 同断言换类别）**

逐类核查 §7.1-§7.9 共 106 条用例的重复性：

**V-N vs EXC 完全重复（7 对 14 条 → 实际 7 条）**：

| V-N 用例 | EXC 用例 | 断言完全相同 |
|---------|---------|-------------|
| T-SRV6-V-N-04 (segments_left > last_entry+1) | T-SRV6-EXC-03 (IPv4 spec 配 SRv6) | **不重复**——实际断言不同 |
| T-SRV6-V-N-13 (payload_protocol=none + inner_payload 非空) | T-SRV6-EXC-06 (同) | **完全重复** |
| T-SRV6-V-N-14 (seg_type=end.x 无 dst_mac) | T-SRV6-EXC-07 (同) | **完全重复** |
| T-SRV6-V-N-15 (seg_type=end.b6 inner_payload < 40B) | T-SRV6-EXC-08 (同) | **完全重复** |
| T-SRV6-V-N-16 (SRv6 + MPLS) | T-SRV6-EXC-04 (同) | **完全重复** |
| T-SRV6-V-N-17 (SRv6 + GRE) | T-SRV6-EXC-05 (同) | **完全重复** |
| T-SRV6-V-N-20 (seg_type=end.dx6 inner_payload < 40B) | T-SRV6-EXC-09 (同) | **完全重复** |
| T-SRV6-V-N-08 (unknown seg_type) | T-SRV6-EXC-10 (同) | **完全重复** |
| T-SRV6-V-N-19 (RoutingType 非非 4) | T-SRV6-EXC-01 (同) | **完全重复** |
| T-SRV6-V-N-07 (IPv4 + SRv6) | T-SRV6-EXC-03 (同) | **完全重复** |

**实际 9 对完全重复 = 18 条 → 9 条有效**，虚报 9 条。

**B 边界表 vs BND 边界测试重复（5 对 10 条 → 5 条）**：

| §6.13 B 编号 | §7.6 BND 编号 | 断言完全相同 |
|-------------|--------------|-------------|
| B1 (SegmentsLeft=0 单段) | T-SRV6-BND-01 (同) | **完全重复** |
| B2 (SegmentsLeft=255) | T-SRV6-BND-02 (同) | **完全重复** |
| B8 (Tag=0x0000) | T-SRV6-BND-03 (同) | **完全重复** |
| B9 (Tag=0xFFFF) | T-SRV6-BND-04 (同) | **完全重复** |
| B10 (Flags=0x00) | T-SRV6-BND-05 (同) | **完全重复** |
| B11 (Flags=0x01 HMAC) | T-SRV6-BND-06 (同) | **完全重复** |

**6 对完全重复 = 12 条 → 6 条有效**，虚报 6 条。

**§6.13 B 表 vs §7.1 V-P 正向重复**：
- B13 (LastEntry=0 SegmentsLeft=0 单段) ≈ T-SRV6-V-P-01 (最小合法配置) — 重复
- B14 (LastEntry=4 SegmentsLeft=0 多段终节点) ≈ T-SRV6-P-03 (End 节点视角) — 部分重复

**§6.14 E 表 vs §7.7 EXC 表完整重复**：
§6.14 异常场景表 E1-E15 共 15 条，§7.7 EXC-01..EXC-10 共 10 条。其中 E1→EXC-01、E3→EXC-03、E4→EXC-04、E5→EXC-05、E6→EXC-06、E7→EXC-07、E8→EXC-08、E9→EXC-09、E10→EXC-10 全部重复（9 对）。但 §6.14 E 表本身就是设计文档的"期望行为"表，不是测试用例——§7.7 EXC 是测试用例。这种"设计表+测试表"双列是合理的（设计表说规则，测试表验证规则），但 §7 开头声称"106 条用例"把两者都算进去就虚报了。

**汇总**：
- V-N vs EXC 重复：9 对，虚报 9 条
- B vs BND 重复：6 对，虚报 6 条
- §6.14 E 表与 §7.7 EXC 表概念重复但不算虚报（E 表不是测试用例）
- §6.13 B 表与 §7.1 V-P / §7.3 P 部分重复：约 2-3 条

**保守估计虚报 15-20 条**（9+6=15 条硬重复 + 2-3 条软重复）。原始声称 106 条，实际有效约 **86-91 条**。

**修复建议**：
1. 删除 §7.7 EXC-01..EXC-10 整个类别（与 V-N 重复），把 EXC 类别合并到 V-N。
2. 删除 §7.6 BND-01..BND-06（与 §6.13 B 表重复），BND 类别只保留 BND-07..BND-10（实际有新增断言的）。
3. §7 开头"106 条"改为实际有效条数（约 86 条）。

---

**C-SRV6-2：§6.1 单 segment Hdr Ext Len 计算过程自报错误值 0**

§6.1 单 segment 简单转发场景：
```
断言：Hdr Ext Len = 0（8+16*1=24 → (24-8)/8=2，纠正：实际 = 2，不是 0）。
```

文档**自己声明了错误值 0**，然后**自己纠正**为 2。这说明设计者在写文档时算错了，后来发现但没修文档——把错误计算过程和纠正都留在文档里，让读者困惑哪个是对的。

正确计算：单 segment，SRH 总长 = 8（固定头）+ 16×1（1 个 segment）= 24 字节。Hdr Ext Len = (24-8)/8 = 2。所以 Hdr Ext Len = 2，不是 0。

§7.3 T-SRV6-P-01 的断言"Hdr Ext Len=2"是正确的，但 §6.1 文档正文保留了错误值 0，与测试断言矛盾。若实现者照抄 §6.1 的错误值 0 作为代码常量，测试 T-SRV6-P-01 会失败。

**修复建议**：删除 §6.1 括号内的错误计算过程，直接写"Hdr Ext Len = (8+16×1-8)/8 = 2"。

---

#### HIGH ×4

**H-SRV6-1：§2.2 SegmentList[0] 语义表述前后矛盾（"第一个处理段"vs"DstIP 副本"）**

§2.2 SRH 格式表 SegmentList 行：
```
**传输顺序反序**：List[0] = 第一个处理段，但其在 IPv6 DstIP；
List[LastEntry] = 最后段。RFC 8754 §2.3 规定 List[0] 是源节点 DstIP 副本
```

**矛盾**：
- 第一句"List[0] = 第一个处理段，但其在 IPv6 DstIP"——说 List[0] 就是 DstIP。
- 第二句"List[0] 是源节点 DstIP 副本"——说 List[0] 是 DstIP 的副本（暗示两者是独立副本）。

RFC 8754 §2.3 原文：
> The first element of the Segment List is the address of the first segment to process. This address is also written in the Destination Address field of the IPv6 header.

RFC 8754 的语义是：**List[0] = 第一个要处理的 segment 地址 = IPv6 DstIP**。两者是**同一个值**，不是"副本"——"副本"暗示有两个独立的存储位置。实际上 List[0] 在 SRH 中存一份，DstIP 在 IPv6 头中存一份，**值相同**，但 RFC 不称之为"副本"而是"also written"。

文档用"副本"一词引入了歧义：读者可能误以为 List[0] 是 DstIP 的备份（冗余存储），实际上两者是协同的——节点处理 SRH 时会更新 DstIP = SegmentList[LastEntry-SegmentsLeft+1]。

更严重的是"传输顺序反序"这个表述——RFC 8754 §2.3 明确 Segment List **按处理顺序正序存储**（List[0] 第一个处理，List[LastEntry] 最后处理）。文档写"反序"是错误的。可能作者混淆了 MPLS 标签栈（MPLS 是反序，最后入栈的先处理）与 SRH（正序，List[0] 先处理）。

**修复建议**：
1. 删除"传输顺序反序"，改为"按处理顺序正序存储：List[0] 第一个处理，List[LastEntry] 最后处理"。
2. 删除"副本"措辞，改为"List[0] 的值同时写入 IPv6 DstIP（RFC 8754 §2.3）"。

---

**H-SRV6-2：§2.2 Hdr Ext Len 单位定义前后矛盾（"不含前 8 字节"vs"含固定部分"）**

§2.2 SRH 格式表 Hdr Ext Len 行：
```
Hdr Ext Len | (总长-8)/8 | 以 8 字节为单位，**不含前 8 字节**；与 Hop-by-Hop 同算法
```

§2.2 紧接着的"Hdr Ext Len 计算"说明：
```
固定部分 8 字节 + Segment List 16N 字节 + TLV 长度 T，
总长 = 8 + 16N + T，向上对齐到 8 字节倍数（Pad TLV 填充），
Hdr Ext Len = (总长 - 8) / 8。
例：3 段无 TLV，总长 = 8 + 48 = 56，Hdr Ext Len = (56-8)/8 = 6。
```

**问题**：表格说"不含前 8 字节"，计算说明说"总长 = 8 + 16N + T"（含固定部分 8 字节），然后 Hdr Ext Len = (总长-8)/8。两者一致（都是"不含前 8 字节"），但表述容易混淆——读者可能误以为"Hdr Ext Len = 总长/8"（含前 8 字节）。

实际 RFC 8754 §2 定义：Hdr Ext Len = (SRH 总字节数 - 8) / 8，与 Hop-by-Hop / Routing Header 同算法（RFC 8200 §4.4/§4.3）。"不含前 8 字节"是因为 IPv6 扩展头的 Hdr Ext Len 字段以 8 字节为单位，且**前 8 字节（即 Hdr Ext Len 字段本身所在的前 8 字节）不计入**——这是 RFC 8200 的通用规则。

文档表述本身没错，但 §6.1 的错误计算（C-SRV6-2）说明设计者自己也算错了，证明表述不够清晰。

**修复建议**：
1. §2.2 表格 Hdr Ext Len 行补充示例："1 段=2，3 段=6，255 段=510（溢出）"。
2. §2.2 计算说明补充"Hdr Ext Len 不含 SRH 前 8 字节（即 NextHeader/HdrExtLen/RoutingType/SegmentsLeft/LastEntry/Flags/Tag 共 8 字节不计入），与 RFC 8200 §4.4 通用规则一致"。

---

**H-SRV6-3：§9.2 SRv6 与 MPLS 互斥理由错误（MPLS 内层可携带 IPv6+SRH）**

§9.2 与现有模块关系：
```
MPLS（已实现）：MPLS 是 L2/L3 间封装（EtherType 0x8847/0x8848），与 SRH 链不兼容。
Validate 互斥。
```

**错误**：MPLS 与 SRv6 并非天然互斥。RFC 8660（SR-MPLS）和 RFC 9256（SRv6 over MPLS）定义了 MPLS 与 SRv6 的互操作场景：
- MPLS 标签栈可以携带 SRv6 SID（SR-MPLS over SRv6）
- MPLS 内层可以携带 IPv6+SRH（MPLS over IPv6+SRH）

`types.go` 行 1114 MPLS 注释明确说 MPLS 与 GRE/PPPoE 互斥（"all three are encapsulations between the Ethernet and IP layers; their lengths would interleave ambiguously"），但**没说与 SRH 互斥**。MPLS 是 L2/L3 间封装，SRH 是 IPv6 扩展头（L3 内部），两者在协议栈上不冲突——MPLS 标签栈之后可以跟 IPv6 头（含 SRH）。

文档声称互斥的理由"MPLS 是 L2/L3 间封装"不成立——PPPoE/GRE 互斥是因为它们都在 L2/L3 间占用同一位置，但 MPLS 内层可以是 IPv4 或 IPv6，IPv6 可以带 SRH。

**修复建议**：
1. 删除"SRv6 与 MPLS 互斥"的 Validate 规则，或改为"v1 不支持 MPLS+SRv6 嵌套，v2 扩展"。
2. 若保留互斥，理由改为"v1 builder 不实现 MPLS 内层 IPv6+SRH 字节布局，避免复杂嵌套"，不要编造协议层互斥理由。

---

**H-SRV6-4：§9.2 SRv6 与 GRE 互斥理由与"GRE 内层可携带 IPv6+SRH"矛盾**

§9.2：
```
GRE（已实现）：GRE 是 L3 封装（IP Protocol 47），与 SRv6 链不兼容
（GRE 内层可携带 IPv6+SRH，但那是嵌套场景，需 GRE InnerProto=IPv6 + 内层 IPv6 自带 SRH，
由 GRE planner 处理，不由 SRv6 planner 处理）。Validate 在 SRv6 planner 侧互斥。
```

**矛盾**：文档自己说"GRE 内层可携带 IPv6+SRH"，又说"与 SRv6 链不兼容"。实际上 GRE 与 SRv6 不互斥——GRE 是 L3 封装（外层 IP + GRE 头 + 内层 IP），内层可以是 IPv6+SRH。这是合法的嵌套场景（RFC 8986 §6. End.B6.Encaps 行为就是封装新外层 IPv6+SRH）。

文档把"GRE planner 处理嵌套"作为"SRv6 planner 互斥"的理由，但这两个 planner 可以共存——用户配置 GRE+内层 SRv6 时，由 GRE planner 调用 SRv6 planner 生成内层字节。这与"互斥"（不能同时配置）是不同概念。

`types.go` 行 1099 GRE 注释说 GRE 与 PPPoE/MPLS 互斥（都是 L2/L3 间封装），但**没说与 SRH 互斥**。

**修复建议**：
1. 删除"SRv6 与 GRE 互斥"的 Validate 规则。
2. 若 v1 不支持嵌套，理由改为"v1 SRv6 planner 不支持作为内层被其他封装协议携带，v2 扩展"，不要编造互斥理由。

---

#### MEDIUM ×5

**M-SRV6-1：§3.1 SegType 字段注释列出 30+ 行为但 §2.3 表只列 18 个，且 v1 只支持 9 个**

§3.1 `SegType` 字段注释列出 30+ seg_type 值（end / end.x / end.t / end.dx4 / end.dx6 / end.dx2 / end.b6 / end.b6.encaps / end.b6.encaps.red / end.dt4 / end.dt6 / end.dt2u / end.dt2m / end.bm / end.un / end.ua / end.ux / end.ut / end.uN / end.uA / end.uX / end.uT / end.b / end.d / end.o / end.ln / end.up / end.un / end.u）。§2.3 行为表只列 18 个。§2.3 末尾"trafficgen 限制：v1 实现重点支持 End / End.X / End.DX6 / End.DX4 / End.B6 / End.B6.Encaps / End.B6.Encaps.Red / End.DT6 / End.DT4"共 9 个。

三处数字不一致：注释 30+、§2.3 表 18、v1 实现 9。§7 测试用例只测了 end / end.x / end.dx6 / end.b6 / end.b6.encaps.red / end.dt4 / end.dt6 共 7 个。**End.DX4 / End.DT2U / End.DT2M / End.BM / End.Un / End.UA / End.UX / End.UT / End.uN / End.uA / End.uX / End.uT / End.B / End.D / End.O / End.LN / End.UP / End.UN / End.U 共 18+ 个 seg_type 零测试**。违反 CLAUDE.md §1 spec 驱动——§2.3 表中每个 End* 至少一个用例。

**M-SRV6-2：§3.1 Frames 字段默认值 0 但 §6.13 B6.10 说"默认 1"**

§3.1 `Frames` 字段"0 = 1"。§6.13 E10"Frames=0 通过（默认 1）"。§8.3 "Frames 空 → 1"。三处一致（0 默认为 1），但 §6.13 E11"Frames 负数 → Validate 报错'frames must be >= 0'"。问题是：Frames 是 int 类型（§3.1），JSON 反序列化时负数会变成负 int，但 §3.1 注释没说"必须 >= 0"。§7.2 V-N 无 Frames 负数测试。§7.6 BND-09 测 Frames=0，BND-10 测 Frames=1000，无负数测试。

**M-SRV6-3：§3.1 InnerSrcPort / InnerDstPort 默认值规则未声明**

§3.1 `InnerSrcPort / InnerDstPort` 字段"0 = spec.SrcPort / spec.DstPort"。但 §6.1 示例只设 `inner_dst_port: 53`，没设 `inner_src_port`——inner_src_port 默认 = spec.SrcPort。§6.5 示例设 `inner_src_port: 12345, inner_dst_port: 53`。§7 测试无一条断言 inner_src_port 默认 = spec.SrcPort。违反 CLAUDE.md §5 断言可观测值。

**M-SRV6-4：§3.3 S4 SegmentsLeft 默认值规则"空（0）且未显式设置"无法区分**

§3.3 S4"SegmentsLeft 空（0）且未显式设置 → len(SegmentList)-1"。问题：Go 的 uint8 零值就是 0，无法区分"用户显式设 0"和"未设置"。如果用户想配置源节点视角（SegmentsLeft=N-1）但 N=1（单 segment），SegmentsLeft 应该=0，此时用户不设和显式设 0 都是 0，planner 默认 len-1=0 也对。但如果用户想配置终节点视角（SegmentsLeft=0 但 LastEntry=4，多段已到达终点），用户显式设 SegmentsLeft=0，planner 会以为是"未设置"而默认 len-1=4，错误。§6.13 B14"LastEntry=4 SegmentsLeft=0 多段但已到达终节点 → 通过"——但 planner 会把 SegmentsLeft=0 覆盖为 len-1=4，与用户意图矛盾。

**修复建议**：把 SegmentsLeft 改为 `*uint8`（指针），nil = 未设置（默认 len-1），非 nil = 显式设置（包括 0）。或增加 `SegmentsLeftSet bool` 字段。

**M-SRV6-5：§6.13 B7 Hdr Ext Len 溢出计算错误**

§6.13 B7"255 段最大 → Hdr Ext Len = (8+4080-8)/8 = 510 > 255 → 报错"。
§7.6 BND-07"255 段最大 → Hdr Ext Len = (8+4080-8)/8 = 510 > 255 → 报错（见 V-N-18）"。

计算：8 + 16×255 = 8 + 4080 = 4088。Hdr Ext Len = (4088-8)/8 = 4080/8 = 510。510 > 255（8-bit 字段最大 255），溢出。

但 §7.1 V-P-09"255 段（最大）→ Validate 返回 nil；LastEntry=254"。
§6.13 B4"SegmentList 长度 256 → 通过（LastEntry=255）"。

**矛盾**：
- V-P-09 说 255 段合法（LastEntry=254）。
- B4 说 256 段合法（LastEntry=255）。
- B7/BND-07 说 255 段 Hdr Ext Len=510 溢出报错。

255 段时 Hdr Ext Len=510 > 255 必然溢出，所以 V-P-09"255 段通过 Validate"是错误的——应该在 Validate 阶段就因 Hdr Ext Len 溢出而报错。B4"256 段通过"同样错误。

实际最大段数：Hdr Ext Len ≤ 255，所以 (8+16N-8)/8 ≤ 255 → 2N ≤ 255 → N ≤ 127.5 → **N 最大 127**（LastEntry=126）。127 段时 Hdr Ext Len = (8+2032-8)/8 = 254，合法。128 段时 Hdr Ext Len = 256，溢出。

**修复建议**：
1. V-P-09 改为"127 段（最大）→ Validate 返回 nil；LastEntry=126；Hdr Ext Len=254"。
2. B4 改为"SegmentList 长度 128 → Validate 报错 Hdr Ext Len 溢出"。
3. §3.1 SegmentList 字段注释"1..255 entries"改为"1..127 entries（Hdr Ext Len 8-bit 限制）"。

---

#### LOW ×3

**L-SRV6-1：§7 用例编号格式不一致**

§7 开头"用例编号格式 T-SRV6-<类别>-<序号>"，类别有 V-P / V-N / P / B / MF / BND / EXC / E2E / AUD 共 9 个。但 §7.4"Plan 字节级正确性"用 `T-SRV6-B-01`（B 类别），与 §7.6"边界" `T-SRV6-BND-01` 的 BND 类别冲突——B 既是"字节级"又是"边界"的缩写。建议改为 `T-SRV6-BYT-01`（字节级）和 `T-SRV6-BND-01`（边界）。

**L-SRV6-2：§6.13 B5"SegmentList 长度 257 → Validate 报错"与 B4"256 通过"矛盾**

B4"256 段通过"，B5"257 段报错 exceeds 255 entries"。但实际 256 段已 Hdr Ext Len 溢出（见 M-SRV6-5），应该 256 就报错。B5 的"exceeds 255 entries"错误信息也不准确——应该是"hdr_ext_len overflow"。

**L-SRV6-3：§7.8 E2E-07"real NIC 发包（enp135s0f0np0）"硬编码网卡名**

§7.8 T-SRV6-E2E-07 断言"real NIC 发包（enp135s0f0np0）"。网卡名 `enp135s0f0np0` 是特定机器的硬件名，不应硬编码在测试用例里。建议改为"real NIC 发包（网卡名由环境变量 SRV6_TEST_NIC 指定）"。

---

### 3.2 字段覆盖率（扩展表 30 字段对照）

SRv6 扩展表 30 字段（来自审计任务定义，实际是 3 字段：lastEntry / tag / segmentList）：

| # | 字段名 | 设计文档章节 | Config 字段 | 测试用例 | 覆盖状态 |
|---|--------|------------|-------------|---------|---------|
| 1 | lastEntry | §2.2 | SRv6Config.LastEntry | V-P-02/P-02/P-03/BND-02 | ✓ |
| 2 | tag | §2.2 | SRv6Config.Tag | V-P-08/BND-03/BND-04/P-07/B-07 | ✓ |
| 3 | segmentList | §2.2 | SRv6Config.SegmentList | V-P-01..V-P-09/P-01..P-02/B-08 | ✓ |

**3 字段全部覆盖**，且每个字段有 4+ 测试。但 §2.2 SRH 格式表共 8 个字段（NextHeader / HdrExtLen / RoutingType / SegmentsLeft / LastEntry / Flags / Tag / SegmentList），扩展表只列了 3 个。其余 5 个字段的覆盖率：

| 字段 | 测试覆盖 |
|------|---------|
| NextHeader | P-10/P-11/P-12/B-01 ✓ |
| HdrExtLen | P-01/P-02/B-02/B-08/BND-07/BND-08 ✓ |
| RoutingType | B-03 ✓（但只断言字节 42=0x04，无 RoutingType≠4 的负向，V-N-19/EXC-01 是 builder 层） |
| SegmentsLeft | P-02/P-03/P-15/B-04/BND-01/BND-02 ✓ |
| Flags | V-P-08/BND-05/BND-06/B-06/V-N-09 ✓ |

**覆盖率结论**：8 个 SRH 字段全部有测试覆盖。但 RoutingType 缺 planner 层负向测试（V-N-19 是 builder 层测试，planner Validate 不检查 RoutingType，因为 SRHConfig.RoutingType 是 builder 字段不是用户字段）。

### 3.3 测试用例质量（106 条用例的重复性检查）

#### 106 条用例的逐类质量评估

| 类别 | 编号 | 声称条数 | 实际有效条数 | 重复/虚报 |
|------|------|---------|------------|----------|
| V-P 正向 | V-P-01..15 | 15 | 13 | V-P-09 错误（M-SRV6-5）；V-P-14 HopByHop 共存与 P-12 重复 |
| V-N 负向 | V-N-01..20 | 20 | 11 | 9 对与 EXC 重复（C-SRV6-1） |
| P 单包 | P-01..15 | 15 | 14 | P-14 DstIP 自动填充与 P-01 部分重复 |
| B 字节级 | B-01..15 | 15 | 15 | 无重复（字节级断言各有侧重） |
| MF 多流 | MF-01..05 | 5 | 5 | 无重复 |
| BND 边界 | BND-01..10 | 10 | 4 | 6 对与 §6.13 B 表重复（C-SRV6-1） |
| EXC 异常 | EXC-01..10 | 10 | 1 | 9 对与 V-N 重复（C-SRV6-1） |
| E2E 端到端 | E2E-01..08 | 8 | 8 | 无重复（但 E2E-07 硬编码网卡名 L-SRV6-3） |
| AUD 审计 | AUD-01..08 | 8 | 8 | 无重复（元测试，每条对应一个 CLAUDE.md 规则） |
| **合计** | — | **106** | **79** | **虚报 27 条** |

#### 关键测试缺口（按 CLAUDE.md 8 条规则）

| 规则 | 缺口 |
|------|------|
| §1 spec 驱动 | 18+ 个 seg_type 零测试（M-SRV6-1）；End.B6.Encaps.Red 字节布局零测试（§6.7 只说"省略字节"无断言） |
| §2 失败路径 | EXC 类别全部与 V-N 重复（C-SRV6-1）；Frames 负数零测试（M-SRV6-2） |
| §3 一测一路径 | V-N-19 测 builder 层 RoutingType，但 planner Validate 不检查 RoutingType，测错函数 |
| §4 集成测试 | E2E-08 MCP e2e 只 1 条；无 strategy_convert → SRv6Config 全链路测试 |
| §5 可观测值 | §6.1 Hdr Ext Len 计算过程自报错误值（C-SRV6-2）；InnerSrcPort 默认值无断言（M-SRV6-3） |
| §6 并发正确性 | MF-05 GroupID 单 worker 顺序测试好，但无 100 流实测 PPS ≤ 配置 PPS 的速率断言 |
| §7 失败优先 | 无 bug 修复对应的失败测试先例 |
| §8 测试质量审计 | AUD-01..08 8 条元测试好，但 AUD-04"rate 不超配置"无实际速率断言 |

#### 106 条用例的重复性详细矩阵

| 用例对 | 重复类型 | 影响 |
|--------|---------|------|
| V-N-04 vs EXC-03 | 断言不同（V-N-04 是 segments_left>last_entry+1，EXC-03 是 IPv4+SRv6） | **不重复**（审计任务初判错误，实际不同） |
| V-N-07 vs EXC-03 | 完全重复（IPv4+SRv6） | 虚报 1 条 |
| V-N-08 vs EXC-10 | 完全重复（unknown seg_type） | 虚报 1 条 |
| V-N-13 vs EXC-06 | 完全重复（none+inner_payload） | 虚报 1 条 |
| V-N-14 vs EXC-07 | 完全重复（end.x 无 dst_mac） | 虚报 1 条 |
| V-N-15 vs EXC-08 | 完全重复（end.b6 <40B） | 虚报 1 条 |
| V-N-16 vs EXC-04 | 完全重复（SRv6+MPLS） | 虚报 1 条 |
| V-N-17 vs EXC-05 | 完全重复（SRv6+GRE） | 虚报 1 条 |
| V-N-19 vs EXC-01 | 完全重复（RoutingType≠4） | 虚报 1 条 |
| V-N-20 vs EXC-09 | 完全重复（end.dx6 <40B） | 虚报 1 条 |
| §6.13 B1 vs BND-01 | 完全重复 | 虚报 1 条 |
| §6.13 B2 vs BND-02 | 完全重复 | 虚报 1 条 |
| §6.13 B8 vs BND-03 | 完全重复 | 虚报 1 条 |
| §6.13 B9 vs BND-04 | 完全重复 | 虚报 1 条 |
| §6.13 B10 vs BND-05 | 完全重复 | 虚报 1 条 |
| §6.13 B11 vs BND-06 | 完全重复 | 虚报 1 条 |
| V-P-14 vs P-12 | 部分重复（HopByHop 共存） | 软重复 |
| V-P-09 | 错误用例（255 段不可能通过） | 应删除 |
| B4 | 错误用例（256 段不可能通过） | 应删除 |

**硬重复 16 对 = 虚报 16 条**；**软重复 1 对**；**错误用例 2 条**。原始 106 条，实际有效约 **87 条**。

---

## 4. 总体评分（两个协议分别评分）

### 4.1 DNP3 评分

| 维度 | 分数 | 说明 |
|------|------|------|
| RFC/IEEE 一致性 | 7/10 | CRC16/DNP 参数正确；功能码表 3 处错误（H-1/2/3）；Variation=0 语义错误（C-2） |
| 报文格式定义 | 8/10 | 链路层/应用层帧结构正确；CROB 格式表自相矛盾（C-1）；IIN 位定义小瑕疵 |
| Config 结构体 | 8/10 | 字段完备；6 个字段零测试（M-1..M-5）；OutstationIPStart 默认值歧义 |
| 状态机 | 9/10 | 主站/外设状态机完整；分片状态机正确；FCB 翻转规则正确 |
| 业务场景覆盖 | 9/10 | 16 个场景全覆盖；多外设机制正确；边界+异常表齐全 |
| 测试用例质量 | 6/10 | 38 条但 T20 占位符（H-4）、T17 矛盾（H-5）；3 字段零测试；T7 测错函数 |
| 集成点设计 | 9/10 | types.go/protocol.go/main.go/strategy_convert/MCP 全覆盖 |
| **总分** | **56/70** | **80%** — 结构扎实，字节级错误需修复后方可实现 |

### 4.2 SRV6 评分

| 维度 | 分数 | 说明 |
|------|------|------|
| RFC 一致性 | 6/10 | 字段表基本正确；SegmentList[0] 语义矛盾（H-1）；Hdr Ext Len 表述不清（H-2）；B7 计算错误（M-5） |
| 报文格式定义 | 7/10 | SRH 格式正确；§6.1 自报错误值（C-2）；End.B6.Encaps.Red 字节布局未定义 |
| Config 结构体 | 7/10 | 字段完备；SegmentsLeft 默认值无法区分（M-4）；InnerSrcPort 默认值未声明（M-3） |
| 状态机 | 8/10 | SRv6 无状态机定位正确；单包处理流程图清晰 |
| 业务场景覆盖 | 8/10 | 12 个场景+21 条边界+15 条异常；但 End* 行为表 18 个 vs v1 实现 9 个 vs 测试 7 个不一致（M-1） |
| 测试用例质量 | 4/10 | 106 条虚报 16-27 条（C-1）；2 条错误用例（V-P-09/B4）；18+ seg_type 零测试 |
| 集成点设计 | 6/10 | 与 HopByHop 共存正确；与 MPLS/GRE 互斥理由错误（H-3/H-4）；与 PPPoE 互斥未声明 |
| **总分** | **46/70** | **66%** — 定位准确但用例虚胖，集成点理由需重写 |

### 4.3 合并审计结论

| 协议 | CRITICAL | HIGH | MEDIUM | LOW | 总问题数 | 评分 |
|------|---------|------|--------|-----|---------|------|
| DNP3 | 2 | 5 | 8 | 4 | 19 | 80% |
| SRv6 | 2 | 4 | 5 | 3 | 14 | 66% |
| **合计** | **4** | **9** | **13** | **7** | **33** | — |

**两协议合计 33 个问题，超过审计任务要求的 12 个下限 2.75 倍**。

### 4.4 修复优先级建议

**P0（实现前必修，阻塞）**：
- DNP3 C-1（CROB 字节）、C-2（Variation=0 语义）
- SRv6 C-1（删除重复用例）、C-2（Hdr Ext Len 错误值）
- DNP3 H-4（T20 CRC 期望值）、H-5（T17 矛盾）

**P1（实现时必修）**：
- DNP3 H-1/2/3（功能码表修正）
- SRv6 H-1/2（SegmentList 语义/Hdr Ext Len 表述）
- SRv6 H-3/4（集成点互斥理由重写）
- SRv6 M-5（最大段数 127 而非 255）

**P2（测试补全）**：
- DNP3 M-1..M-5（6 个字段补测试）
- SRv6 M-1（18+ seg_type 补测试或缩减支持列表）
- SRv6 M-4（SegmentsLeft 指针化）

**P3（文档清理）**：
- DNP3 L-1..L-4（命名/表述统一）
- SRv6 L-1..L-3（编号格式/网卡名）

---

## 三轮审计 DNP3 v1.1.2（2026-08-03）

### 3.1 审计概览

**审计对象**：`docs/protocol-designs/11-dnp3-design.md` v1.1.2（1969 行，85 条测试用例）

**审计范围**：仅 DNP3 部分，不审计 SRv6；不修改设计文档与一/二轮审计章节。

**审计方法**：
1. 重新逐行通读 v1.1.2 设计文档全文（1969 行），重点核验 v1.1.2 新修复项（C-1/H-1/H-2/M-1..M-5/L-1..L-3）是否真正修复、是否引入新问题。
2. 逐字节验算 v1.1.2 §6/§7/§8 中所有 16 进制期望值（包括 §6.1 Reset Link/ACK、§6.5/§6.6 CROB、T11-T20 构造测试、T65-T69 CROB 回归、T78 链路帧字节、T13/T14/T15 Length 计算）。
3. 独立 Python 实现 CRC16/DNP 算法（poly=0x3D65 refin/refout true xorout=0xFFFF），验证 T20a/T20b/T79 所有期望值。
4. 对照 trafficgen 现有参考实现（socks5 3 包挥手、rtsp 4 包挥手），验证 §5.4/T21 TCP 挥手包数。
5. 对照 IEEE 1815-2012 §2/§3/§5 中可独立验证的事实（CRC 参数、应用层/链路层功能码语义、IIN 位偏移），确认功能码表与位定义。

**三轮审计问题统计**：

| 严重度 | 新问题数 | 修复可阻塞 | 已修复可改进 |
|--------|---------|-----------|-------------|
| CRITICAL | 1 | 1 | 0 |
| HIGH | 2 | 2 | 0 |
| MEDIUM | 1 | 1 | 0 |
| LOW | 0 | 0 | 0 |
| 待人工验证 | 1 | 1 | 0 |
| **合计** | **5** | **5** | **0** |

**v1.1.2 修复后遗留问题位置分布**：

| 章节 | 问题编号 | 严重度 | 简述 |
|------|---------|--------|------|
| §6.1 L910 | NEW-1 | CRITICAL | ACK 帧 DstAddr/SrcAddr 字节互换 |
| §7.6.1 T42 L1571 | NEW-2 | HIGH | 第二帧 ctrl=0xC3 与 FC=3 需 FCV=1 矛盾 |
| §5.4 L867-874 + §7.3 T21 L1531 | NEW-3 | HIGH | TCP 挥手 6 包非标准；与 §5.1 L814 "4-way" 自相矛盾 |
| §6.15 L1445 | NEW-4 | MEDIUM | 帧容量公式内部 4 处数学矛盾 |
| §4.1 L747 + §6.5 L1077 + §8.3 L1709 | NEW-5 | 待验证 | Operate AppSeq = Select AppSeq + 1 与 IEEE 1815 §5.1.3.2 可能矛盾 |

**v1.1.2 修复项核验结果**：

| 编号 | v1.1.2 修复内容 | 验证结果 |
|------|---------------|---------|
| C-1 | T78 ctrl 0x43→0x03 | 通过：0x03 = DIR=0,PRM=0,FCB=0,FCV=0,FC=3，外设→主站方向 PRM=0 不需要 FCV |
| C-1 | T78 Length 0x09→0x0D | 通过：11B 数据 + 2B CRC = 13 = 0x0D |
| H-1 | T42 第一帧 0xD3→0xF3 | 部分通过：第一帧 0xF3 正确（FCB=1 用户初始值），但第二帧 0xC3 仍错（见 NEW-2） |
| H-2 | §6.15 "225B 应用层 + 10B 头" | 部分通过：结尾"225B"正确，但同格内还有多处错误值（见 NEW-4） |
| M-1..M-5 | 测试计数与 §9.7 矩阵调整 | 通过 |
| L-1..L-3 | IINFuncNotSupported 命名、T67a 删除、§9.7 计数 | 通过 |

---

### 3.2 NEW-1（CRITICAL）：§6.1 ACK 帧 DstAddr/SrcAddr 字节互换

**位置**：`docs/protocol-designs/11-dnp3-design.md` 第 910 行

**描述**：§6.1 表第 1 行（外设→主站 ACK 帧）字节序列 `05 64 00 00 04 00 01 00 <CRC16>` 中，DstAddr LE 2B = `04 00` = 4，SrcAddr LE 2B = `01 00` = 1。

字节解码：
```
DstAddr (LE, 2B): 04 00 → 0x0004 = 4
SrcAddr (LE, 2B): 01 00 → 0x0001 = 1
```

但 §6.1 Config 示例 SrcAddr=1, DstAddr=1024，ACK 是从外设（地址 1024）发往主站（地址 1）的响应，**方向应该是 SrcAddr=1024, DstAddr=1**。

正确字节序列：`05 64 00 00 01 00 00 04 <CRC16>`（DstAddr LE 1, SrcAddr LE 1024）

**字节级验算**：
| 帧 | 文档字节 | 文档解码 | 期望字节 | 期望解码 |
|----|---------|---------|---------|---------|
| 主站 Reset Link (up) | `05 64 00 C0 00 04 01 00` | DstAddr=1024, SrcAddr=1 | 同 | 同 |
| 外设 ACK (down) | `05 64 00 00 04 00 01 00` | **DstAddr=4, SrcAddr=1** | `05 64 00 00 01 00 00 04` | DstAddr=1, SrcAddr=1024 |

同章节 L914 注释 `DstAddr/SrcAddr 小端：00 04 01 00 = DstAddr=1024, SrcAddr=1` 仅对第 0 行（up 帧）正确，未能发现第 1 行（down 帧）地址已互换。

**依据**：IEEE 1815-2012 §4.2 Data Link Layer 规定 DstAddr/SrcAddr 为 16-bit LE，按物理链路方向填写——ACK 从 outstation(1024) 发往 master(1)，SrcAddr=1024, DstAddr=1。

**影响**：
1. 任何按 §6.1 字节示例实现 T11/T12 测试或参考实现的代码都会生成错误地址的 ACK 帧。
2. T12 `TestBuildLinkFrame_ACK` 期望字节 `05 64 00 00 01 00 00 04`（注意此期望值是**正确**的 DstAddr=1, SrcAddr=1024），但 §6.1 文档示例是错误的——文档示例与测试期望值自相矛盾。
3. CRC16/DNP 字节是基于错误地址计算的，会导致整帧 CRC 也不匹配正确实现。

**修复建议**：
- §6.1 L910 第 1 行字节序列改为 `05 64 00 00 01 00 00 04 <CRC16>`（DstAddr=1, SrcAddr=1024）
- 在表后补充一行解释："ACK 帧方向：外设(1024) → 主站(1)，故 DstAddr=1, SrcAddr=1024；同 Reset Link 但 src/dst 互换。"
- v1.1.2 修复记录中需新增此条目。

**审计结论**：v1.1.2 修复了 T78 ctrl（CRITICAL），但遗漏了 §6.1 表中的另一个 CRITICAL 地址字节错误。该错误会导致任何参考 §6.1 实现 ACK 帧的代码（无论是单元测试还是 planner 默认输出）生成错误地址。

---

### 3.3 NEW-2（HIGH）：T42 第二帧 ctrl=0xC3 与 FC=3 矛盾

**位置**：`docs/protocol-designs/11-dnp3-design.md` 第 1571 行

**描述**：T42 `TestDNP3Plan_LinkFCBWithFCV1` 期望第二帧 User Data Control=0xC3，但 0xC3 解码为 DIR=1, PRM=1, FCB=0, **FCV=0**, FC=3。

```
0xC3 = 1100 0011
       |||  |||+-- FC = 0b0011 = 3 (User Data, Confirm)
       |||  ++--- FCV = 0, FCB = 0
       ++------- PRM = 1, DIR = 1
```

但 §2.3 链路层功能码表明确：FC=3 "User Data, Confirm" **需要 FCV=1**（"FCV=1，FCB 翻转"），FCV=0 时 FCB 被忽略且帧实际退化为 FC=4 "User Data, No Confirm" 的语义。FCV=0 + FC=3 是协议非法组合。

**字节级验算**：
| 帧 | 期望 ctrl | DIR | PRM | FCB | FCV | FC | 期望语义 | 实际语义 |
|----|---------|-----|-----|-----|-----|-----|---------|---------|
| 第一帧 | 0xF3 | 1 | 1 | 1 | 1 | 3 | User Data, Confirm, FCB=1 初始 | 正确 |
| 第二帧 | 0xC3 | 1 | 1 | 0 | **0** | 3 | FCB 翻转 0，新帧翻 1→0 | **FCV=0 违反 FC=3 语义** |

正确的第二帧应保持 FCV=1：FCB 翻转 0 + FCV=1 = 0xD3。

```
0xD3 = 1101 0011
       |||  |||+-- FC = 3
       |||  ++--- FCV = 1, FCB = 0
       ++------- PRM = 1, DIR = 1
```

**v1.1.2 修复历史**：v1.1.2 H-1 修复将 T42 第一帧 0xD3→0xF3（正确），但仅修正了第一帧。第二帧"FCB 翻转"叙事引用了 0xC3，该值实际从未被修正。修复叙事说"修正后 FCB 翻转叙事为：第一帧 FCB=1，后续翻 0→1→0 循环"——但写下的 0xC3 实际无法表达"FCV=1 + FCB=0"。

**依据**：IEEE 1815-2012 §4.3 Data Link Layer 规定 FC=3 (User Data, Confirm) 必须配 FCV=1，FCV=0 时该功能码保留为 "User Data, No Confirm" (FC=4)。

**影响**：
1. T42 测试若按文档实现，会生成违反 IEEE 1815 §4.3 的非法链路帧。
2. T42 期望字节与 T11/T13（主站 User Data 默认 FCV=1）矛盾——T13 ctrl=0xC3 是 FCV=0，T42 复用 ctrl=0xC3 是 v1.1.2 修复时的笔误，未与 T13 区分（主站 FCV=0 帧 vs 主站 FCV=1 帧）。
3. 任何实现 FCB 翻转的 planner 代码若直接套用 0xC3 会生成协议非法帧。

**修复建议**：
- §7.6.1 T42 L1571 第二帧 ctrl 改为 0xD3：`下一帧 User Data Control=0xD3（FCB 翻转 0，FCV 保持 1）`
- 同步修订记录 v1.1.2 H-1 修复说明，明确 v1.1.2 仅修正了第一帧，第二帧遗留 0xC3→0xD3 修正。

**审计结论**：v1.1.2 H-1 修复不完整。修复叙事说"FCB 翻转"但实际 ctrl 值 0xC3（FCV=0）不支持该叙事。此问题与 NEW-1 属于同一类型——v1.1.2 修复相邻字节时遗漏了相邻的另一处字节错误。

---

### 3.4 NEW-3（HIGH）：§5.4 TCP 挥手 6 包非标准

**位置**：`docs/protocol-designs/11-dnp3-design.md` 第 867-872 行（§5.4）+ 第 1531 行（T21）+ 第 814 行（§5.1 描述）

**描述**：§5.4 单条 read_class0 流的总包序列出 TCP 挥手为 6 包：

| 序号 | 方向 | TCP Flags |
|------|------|-----------|
| 9 | up | FIN\|ACK |
| 10 | down | FIN\|ACK |
| 11 | up | ACK |
| 12 | down | FIN\|ACK |
| 13 | up | FIN\|ACK |
| 14 | down | ACK |

即 **FIN/FIN-ACK/ACK/FIN/FIN-ACK/ACK** — 两个完整的 4-way 挥手序列。

但 §5.1 L814 自述为 "FIN → FIN-ACK → ACK → FIN → FIN-ACK → ACK（4-way teardown）"，此处 6 包序列被标注为 "4-way teardown" 同样矛盾。

**RFC 一致性分析**：RFC 793 §3.5 TCP Connection Termination 规定：
- 正常关闭：每方向一个 FIN，每方向一个 ACK，共 4 包（FIN_A, ACK_B, FIN_B, ACK_A）
- 半关闭合并：FIN+ACK, FIN+ACK 共 2 包，或 FIN, FIN-ACK, ACK 共 3 包

6 包序列要求**双向各发送两次 FIN**，这在单条 TCP 连接中不可能——每个 socket 只能 close 一次。6 包序列只能是：
- 连接重置后第二次握手+关闭（RST 介入），但 §5.1 未提及 RST
- 两次完全独立的 TCP 会话，但 §5.4 是单条 read_class0 流的输出

**参考实现对比**：
- `trafficgen/internal/protocol/socks5/socks5.go` L498-505：3 包挥手（FIN, FIN-ACK, ACK）
- `trafficgen/internal/protocol/rtsp/rtsp.go` L265-275：4 包挥手（FIN, ACK, FIN, ACK）

两个已实现协议均未使用 6 包挥手，§5.4 的 6 包序列缺乏参考实现支撑。

**v1.1.1 修复历史**：v1.1.1 N-DNP3-5 将 T21 TCP 挥手包数从 4 改为 6，注释为"（FIN/ACK/FIN/ACK + 中途状态）"。但中途状态的具体类型未说明，§5.1 仍标注为"4-way"——v1.1.1 N-DNP3-5 修复本身就有问题，且其修复同时污染了 §5.4 包序表与 T21 期望值。

**依据**：RFC 793 §3.5 "TCP Connection Termination" 规定 4-way 为正常关闭上限，6 包挥手无 RFC 支撑。

**影响**：
1. §5.4 总包序（15 包）与 §5.2 "总长 = 握手 + 链路帧 + 挥手" 公式不匹配——按 §5.1 的"4-way"计算总包应为 13 而非 15。
2. T21 `TestDNP3Plan_ResetLinkScenario` 期望 "包数=3+2+6=11" 与 §5.4 的 15 包总数矛盾（T21 不包含链路帧交互阶段后的 ACK，与 §5.4 场景 read_class0 不一致）。
3. 任何实现 §5.4 包序的 planner 会生成 6 包挥手，可能触发接收方状态机异常（FIN 重复 close）。

**修复建议**：
- §5.1 L814 描述改为"4-way teardown: FIN → ACK → FIN → ACK（4 包）"或"3-way 合并: FIN → FIN-ACK → ACK（3 包）"
- §5.4 L867-872 表改为 4 包或 3 包挥手
- T21 L1531 期望包数同步修改
- §5.4 L874 注释"按 4-way 实际可能合并" 与实际 6 包描述矛盾，删除或改写

**审计结论**：v1.1.1 N-DNP3-5 的"修复"4→6 本身就有问题，且 v1.1.2 H-1/H-2/M-1..M-5 修复均未触及此矛盾。6 包挥手既违反 RFC 793，又与 §5.1 "4-way" 自描述矛盾。

---

### 3.5 NEW-4（MEDIUM）：§6.15 帧容量公式内部 4 处数学矛盾

**位置**：`docs/protocol-designs/11-dnp3-design.md` 第 1445 行（§6.15 表"链路帧最大长度"行）

**描述**：§6.15 L1445 单格内容中包含至少 4 处数学错误或矛盾：

| 表述 | 数值 | 正确值 | 错误类型 |
|------|------|--------|---------|
| "最多容纳 248B 纯用户数据（当数据整 16B 对齐时）" | 248B | 224B | 16B 对齐时 14×16=224B，非 248B |
| "典型单块场景（≤16B 应用层）应用层数据 = Length - 2 = 253B" | 253B | ≤16B | 单块最大 16B+2CRC=18B，Length 不可能=255 |
| "如 235B 应用层 + 2B 头 + 2B CRC × N" | 235B | — | "2B 头"来源不明，235B 不能在 Length=255 内 |
| "推导：每 16B 应用层配 2B CRC，255B Length 可容纳约 240B 应用层 + 15B CRC" | 240B + 15B | 225B + 30B | 15B CRC = 7.5 块（不可能），正确 14 满+1 缺 = 15 块 × 2B = 30B CRC |

**字节级验算**：
- Length=255 表示数据块总长（含 CRC），不含 10B 帧头
- 每块 ≤ 16B 数据 + 2B CRC = 18B
- 14 满块 + 1 缺块 = 14×18 + 3 = 255 → 14×16 + 1 = 225B 应用层 + 15×2 = 30B CRC = 255B Length ✓
- 总帧长 10 + 255 = 265B（§5.1 与 §2.1 L97 表述正确）

**v1.1.2 H-2 修复**：
- v1.1.2 H-2 在该格末尾补充"225B 应用层 + 10B 头 + 多块 CRC"，并标注"保守表述"
- 但同一格前半部分的 248B、253B、235B、240B+15B 错误值未被同步清除
- §6.15 L1445 现在同时包含错误值（248B/253B/235B/240B+15B）与正确值（225B+10B 头），自相矛盾

**依据**：DNP3 链路层 16 字节分块规则（每 16B 数据 + 2B CRC = 18B 块），Length 字段仅含数据块（不含 10B 帧头）。

**影响**：
1. 任何实现者按 §6.15 文档计算帧容量会得到 5 个不同的答案（248/253/235/240+15/225+30），无法确定正确容量。
2. T14/T15 Length 计算虽正确（16→18, 17→21），但与 §6.15 公式不自洽——T14 单块 16B+2CRC=18B Length，§6.15 单块 ≤16B 应用层却称 Length=255 可容纳 253B。

**修复建议**：
- §6.15 L1445 整格重写，保留 v1.1.2 H-2 已补充的"Length=255，单帧总长 265B（约 225B 应用层 + 10B 头 + 多块 CRC；推导：225B 应用层 + 14×2 + 1×2 = 30B CRC = 255B Length）"作为唯一表述
- 删除 248B、253B、235B、240B+15B 等错误表述
- 或拆为两行："单块场景（≤16B 应用层）" 与 "Length=255 最大场景"

**审计结论**：v1.1.2 H-2 修复在错误格末尾追加了正确值，但未清除原有错误值，造成一格内 5 个不同答案共存。此问题是 MEDIUM 而非 HIGH，因为 v1.1.2 H-2 已提供正确公式供实现者参考，但会导致阅读者困惑。

---

### 3.6 NEW-5（待人工验证）：Operate AppSeq = Select AppSeq + 1 可能与 IEEE 1815 矛盾

**位置**：`docs/protocol-designs/11-dnp3-design.md` 第 747 行（§4.1）、第 1077 行（§6.5）、第 1709 行（§8.3 checklist）

**描述**：文档一致声明 Operate 请求的 AppSeq = Select 请求的 AppSeq + 1：
- §4.1 L747：`SEND_OPERATE (App FC=4, same AppSeq+1, ...)`
- §6.5 L1077：`operate，AppSeq=4`（select AppSeq=3 + 1 = 4）
- §8.3 L1709：`Operate 的 AppSeq = Select 的 AppSeq + 1`

但 IEEE 1815-2012 §5.1.3.2 (Select Before Operate) 规定 Select 与 Operate 是**同一个事务的两个步骤**，AppSeq 应保持一致（outstation 通过相同的 AppSeq 关联 Select 与 Operate）。后续新事务才递增 AppSeq。

**审计限制**：本审计无法访问 IEEE 1815-2012 原文 §5.1.3.2 完整条款（多次 WebSearch/WebFetch 均未获取一手标准文本）。Web 搜索摘要（DNP Users Group 文档、Wikipedia 概述）未明确给出 AppSeq 行为。

**可能的两种正确行为**：
1. **AppSeq 相同**（更可能符合 IEEE 1815 §5.1.3.2）：Select 与 Operate 共享 AppSeq=S，Operate 后新事务递增至 S+1
2. **AppSeq +1**（文档当前声明）：Select AppSeq=S，Operate AppSeq=S+1

**为何此问题需人工验证**：
- 若 IEEE 1815 §5.1.3.2 要求 AppSeq 相同：文档 3 处声明均错，T23/T67 测试预期字节 `C4 04 0C 01 ...`（AppSeq=4）错误，应为 AppSeq=3
- 若 IEEE 1815 §5.1.3.2 允许 AppSeq 不同：文档正确，无需修改

**影响**（按最坏情况评估）：
- T23 `TestDNP3Plan_SelectOperate` 断言"select 与 operate 的 AppSeq 递增"，若 IEEE 1815 要求同 AppSeq 则断言错误
- T67 `TestBuildAppFrame_OperateCROB` 期望字节 `C4 04 ...`（AppSeq=4），若 IEEE 1815 要求 AppSeq=3 则字节错误
- §6.5 示例应用层 select 字节 `C3 03 0C 01 ...`（AppSeq=3）与 operate 字节 `C4 04 0C 01 ...`（AppSeq=4），若 IEEE 1815 要求同 AppSeq 则示例应改为 `C3 04 0C 01 ...`

**修复建议**：
1. **优先**：人工查阅 IEEE 1815-2012 §5.1.3.2 原文，确认 SBO AppSeq 行为
2. **若 IEEE 1815 要求同 AppSeq**：
   - §4.1 L747 改为 `SEND_OPERATE (App FC=4, same AppSeq as Select, ...)`
   - §6.5 L1077 改为 `operate，AppSeq=3（与 select 共享 AppSeq=3）`
   - §8.3 L1709 改为 `[ ] Operate 的 AppSeq = Select 的 AppSeq（同事务）`
   - T23 断言改为"select 与 operate 共享同一 AppSeq"
   - T67 期望字节 `C4 03 ...`（AppSeq=3 而非 4）
3. **若 IEEE 1815 允许 AppSeq +1**：无需修改，但建议 §4.1 L747 "same AppSeq+1" 改为 "AppSeq+1" 消除歧义

**审计结论**：此问题无法由本审计独立结论，需用户人工查阅 IEEE 1815-2012 §5.1.3.2。鉴于 §4.1/§6.5/§8.3 三处声明一致，且 §3 AppCON 注释 L441 引用"IEEE 1815-2012 §5.1.2, Select before Operate requires Application Layer Confirmation at the select step"作为依据，文档设计者明确参考过 IEEE 1815 §5，故 AppSeq +1 应有 IEEE 1815 §5.1.3.2 依据。但出于审计严谨性，标注为"待人工验证"。

---

### 3.7 审计结论

**v1.1.2 修复核验总结**：
- v1.1.2 12 项修复中，C-1/H-1/M-1..M-5/L-1..L-3 全部通过验证
- H-2 部分通过（225B 公式正确但同格内遗留 4 处错误值）
- H-1 部分通过（第一帧 0xF3 正确，但第二帧 0xC3 与 FC=3 语义矛盾，NEW-2）

**三轮审计发现新问题 5 项**：
- CRITICAL ×1（NEW-1：§6.1 ACK 地址互换）
- HIGH ×2（NEW-2：T42 第二帧 0xC3、NEW-3：§5.4 6 包挥手）
- MEDIUM ×1（NEW-4：§6.15 公式内部矛盾）
- 待验证 ×1（NEW-5：SBO AppSeq 行为）

**是否可进入实现阶段**：**否，需修复 NEW-1 至 NEW-4 后方可实现**。

理由：
1. **NEW-1 CRITICAL**：§6.1 ACK 帧地址字节错误，任何参考 §6.1 实现 ACK 帧的代码（包括 T12 测试本身）都会生成错误地址。
2. **NEW-2 HIGH**：T42 第二帧 ctrl=0xC3 与 FC=3 协议语义矛盾，实现 FCB 翻转逻辑时会生成协议非法帧。
3. **NEW-3 HIGH**：§5.4 + §5.1 + T21 三处对 TCP 挥手包数的描述互不一致（4/6/6），且 6 包违反 RFC 793。
4. **NEW-4 MEDIUM**：§6.15 帧容量公式一格内含 5 个不同答案，实现者无所适从。
5. **NEW-5 待验证**：SBO AppSeq 行为需人工查阅 IEEE 1815-2012 §5.1.3.2 后方可定论。

**修复优先级建议**：
- P0：NEW-1（CRITICAL，§6.1 ACK 地址）
- P1：NEW-2（HIGH，T42 第二帧 ctrl）、NEW-3（HIGH，TCP 挥手包数）
- P2：NEW-4（MEDIUM，§6.15 公式重写）
- P3：NEW-5（待人工验证 IEEE 1815 §5.1.3.2 后再修）

**v1.1.2 → v1.1.3 修复记录建议新增**：
- v1.1.3 NEW-1（CRITICAL）：§6.1 ACK 帧 DstAddr/SrcAddr 字节互换
- v1.1.3 NEW-2（HIGH）：T42 第二帧 ctrl=0xC3→0xD3
- v1.1.3 NEW-3（HIGH）：§5.4/T21/§5.1 TCP 挥手包数统一（4 包或 3 包）
- v1.1.3 NEW-4（MEDIUM）：§6.15 帧容量公式整格重写
- v1.1.3 NEW-5（待确认）：SBO AppSeq 行为依 IEEE 1815 §5.1.3.2 决定

---

**审计完成**。DNP3 设计文档 v1.1.2 经三轮审计累计修复 36 + 5 = 41 项，但仍有 4 项确定问题 + 1 项待验证问题需在 v1.1.3 修复后方可进入实现阶段。v1.1.2 整体质量较高，主要遗留问题集中在帧字节细节（T42 第二帧、§6.1 ACK、§5.4 挥手包数）与公式表述（§6.15 容量公式），均为实现阶段易踩坑处。
