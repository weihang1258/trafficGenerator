# MODBUS TCP 协议设计与测试用例（v2.0.4）

协议编号：扩展表 13（modbusProtRpt）
规范来源：Modbus.org MB-ASYM-TCP（MODBUS Application Protocol Specification V1.1b3）/ MODICON PI-MBUS-300 Rev. J（Modbus Protocol Reference Guide）
默认端口：502（TCP）
传输层：TCP（IPv4/IPv6 皆可，单播与广播）
设计日期：2026-08-03（v1 初稿）／2026-08-05（v2.0.0 重写）／2026-08-05（v2.0.1/v2.0.2 复审修订）／2026-08-05（v2.0.3 R3 复审修订）／2026-08-05（v2.0.4 R4 复审修订）
文档版本：**v2.0.4**

> v2.0.2 为基于官方规范（MB-ASYM-TCP V1.1b3 / PI-MBUS-300 Rev. J）与三轮对抗审计报告（`audit/13-modbus-audit-deep.md` 14 项、`audit/13-modbus-audit-r1-v2.md` 20 项、`audit/13-modbus-audit-r2-v2.md` 14 项，合计 48 项全部修复）的全量重写：功能码/异常码/PDU 结构按规范逐字段核对，15 个 HexDump 场景逐字节核算，测试用例 205 条，覆盖全部 19 个功能码。修订明细见 §11。
> v2.0.3 为 R3 复审修订（`audit/13-modbus-audit-r3-v2.md` 7 项：1 CRITICAL + 2 HIGH + 2 MEDIUM + 2 LOW），修复 FC 0x14 响应 item 字段语义（C-1）、FC 0x08 子功能上限（H-1）、FC 0x15 请求 item 缺 Byte Count（C-2）、FC 0x0C 字段顺序核对（H-2）、FC 0x11 示例自洽（M-2）、MEI Type 0x0E 标注（M-1）、豁免路径请求语义（L-1）与版本时间线（L-2）。详见 §11.4。
> v2.0.4 为 R4 复审修订（`audit/13-modbus-audit-r4-v2.md` 12 项：1 CRITICAL + 4 HIGH + 3 MEDIUM + 4 LOW），依据本机 tshark 3.6.14 实测 12 种 wire 形态交叉核实：**回退 R3 两处方向性错误**——FC 0x15 请求 item 首字节是 Reference Type=0x06 而非 Byte Count（R3-C2 错误，规范形式 `15 0B 06 ...` tshark 正常解析、`15 0C 0B 06 ...` 被标记 Malformed）；MEI Type 0x0D=**CANopen（CiA 309）**、0x0E=**Read Device Identification**（请求与响应同用 0x0E，R3-M1 的"0x0D=请求/0x0E=响应侧"系对规范表 42 的误读）。另修复 FC 0x11 响应多余 Byte Count 字段（H-2，tshark 实测无此字段）、§8.3 背书区间列歧义（H-3）、FC 0x18 长度自洽未定义（H-4）与 3 MEDIUM + 4 LOW 问题。详见 §11.5。
> 版本时间线说明：v2.0.0 全量重写与 v2.0.1/v2.0.2 复审修订同日（2026-08-05）完成，v2.0.1 为中间版本未独立成文（修复内容并入 §11.3 描述），v2.0.0 之后 §4-§11 在 v2.0.2 重建（修复 L-2）。

---

## §1. 协议概述

### §1.1 定位

Modbus TCP（莫迪总线 TCP，工业控制事实标准）是 Modbus 协议（Modicon 公司 1979 年提出，现由 Modbus Organization 维护）在 TCP/IP 之上的实现。客户端（client/master，主站）向服务端（server/slave，从站）发起事务（transaction，事务），每个事务由一条请求 PDU（Protocol Data Unit，协议数据单元）与一条响应 PDU 组成。Modbus 是无状态请求-响应协议，不维护会话层状态机——事务之间相互独立，唯一的会话状态是 TCP 连接本身。

规范依据：Modbus.org MB-ASYM-TCP（MODBUS Application Protocol Specification V1.1b3，TCP/IP 上的 Modbus 应用协议）；历史参考 MODICON PI-MBUS-300 Rev. J（Modbus Protocol Reference Guide，串行链路帧格式与功能码定义，1996）。TCP 传输通用约定遵循 RFC 793（Transmission Control Protocol）。

### §1.2 与已有协议的关系

- 与 MySQL 类似，Modbus TCP 是"单 TCP 连接 + 多请求/响应"的会话型协议。本设计沿用 MySQL planner 的"事务序列"模型，每个事务 = 一个上行请求 + 一个下行响应，帧定界由 MBAP（Modbus Application Protocol Header，Modbus 应用协议头）的 Length 字段承担。
- 与 SOCKS5 不同，Modbus 没有握手/认证阶段，TCP 三次握手完成即可发送第一个请求。
- 与 RTSP 不同，事务顺序由配置数组显式指定，不存在对话式（dialog）模式。
- 与 GRE/MPLS/PPPoE 互斥：L2 配置不能同时承载 Modbus PDU（`L2Config` 只能选其一）。
- 与 TLS 互斥：Modbus Security = Modbus over TLS，端口 802，超出本设计范围。

### §1.3 功能码覆盖范围（完整枚举）

| FC | 名称（中文） | FC | 名称（中文） |
|----|-------------|----|-------------|
| 0x01 | Read Coils（读线圈） | 0x10 | Write Multiple Registers（写多寄存器） |
| 0x02 | Read Discrete Inputs（读离散输入） | 0x11 | Report Server ID（报告服务器 ID） |
| 0x03 | Read Holding Registers（读保持寄存器） | 0x14 | Read File Records（读文件记录） |
| 0x04 | Read Input Registers（读输入寄存器） | 0x15 | Write File Records（写文件记录） |
| 0x05 | Write Single Coil（写单线圈） | 0x16 | Mask Write Register（掩码写寄存器） |
| 0x06 | Write Single Register（写单寄存器） | 0x17 | Read/Write Multiple Registers（读写多寄存器） |
| 0x07 | Read Exception Status（读异常状态） | 0x18 | Read FIFO Queue（读 FIFO 队列） |
| 0x08 | Diagnostic（诊断） | 0x2B | Encapsulated Interface Transport（封装接口传输，MEI） |
| 0x0B | Get Comm Event Counter（取通信事件计数） | 0x80+ | 异常响应（Exception Response，FC 高位 + 异常码） |
| 0x0C | Get Comm Event Log（取通信事件日志） | — | — |
| 0x0F | Write Multiple Coils（写多线圈） | — | — |

支持集（Validate 合法集）：`{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x0B, 0x0C, 0x0F, 0x10, 0x11, 0x14, 0x15, 0x16, 0x17, 0x18, 0x2B}`，共 19 个功能码。0x09/0x0A/0x0D/0x0E/0x12/0x13/0x19-0x2A 等保留码不在支持集。

**豁免规则（修复 R1-H1）**：`FunctionCode` 不在支持集（如 0x41、0x99）时，若 `ExceptionCode != 0`，Validate **豁免**支持集与高位检查，请求 PDU 按用户配置逐字节透传（无数据时仅 FC 一字节），响应 PDU = `FC|0x80 + ExceptionCode`。该豁免用于模拟"slave 对未知功能码回异常"的真实场景（规范 §7：client 发出的功能码不在 slave 支持集内时，slave 回 Illegal Function）。豁免仅在 `ExceptionCode != 0` 时生效；`ExceptionCode == 0` 时非法 FC 一律拒绝。**豁免不适用于支持集内的合法 FC**（支持集内 FC 仍禁止设高位）。

### §1.4 设计目标

- wire-format 正确：MBAP 头 7 字节 + PDU，可被 Wireshark/tshark Modbus 解析器逐字段识别（§7.7 以 tshark 为最终裁判）。
- 功能码覆盖：§1.3 全部 19 个功能码 + 0x80 异常响应，每个功能码至少 1 条正向用例（修复 M2-HIGH-2/M2-HIGH-3）。
- 多事务序列：单 TCP 流承载 N 个事务，Transaction ID 单调递增（可回绕）。
- 多会话/多流关联：M 个 master 并发，每个独立 4-tuple（独立 TCP 流）；Transaction ID 默认流内唯一，跨流可并发复用（`SharedTIDSpace=true` 时多流共享连续 TID 空间，见 S11/S12）。
- 异常响应：通过 `exception_code` 字段触发 `FC | 0x80` 响应；10 个合法异常码全支持（含 0x07，修复 M2-HIGH-4）。
- 广播：Unit ID=0 为广播（仅写功能码合法，修复 R1-M4）；默认仍发镜像响应包（traffic-mirror 用途），`SuppressBroadcast=true` 时省略。
- 边界覆盖：quantity=0/最大值、starting_address=0/65535、Unit ID 0/247、Transaction ID 回绕、MBAP+PDU 总长 260 字节上限。
- 不实现：Modbus RTU（串行链路）、Modbus over UDP、Modbus Security（TLS/802）、网关多跳路由模拟（gateway 异常仅生成响应码 0x0A/0x0B，不模拟路由）、CANopen MEI 封装（MEI Type 0x0D=CANopen General，CiA 309 扩展，V1.1b3 未定义，本设计不实现，修复 R4-H1）。

### §1.5 不变式（Invariants）

1. MBAP 头 Protocol ID 恒为 0x0000（Modbus 协议标识）。
2. **Length 字段 = Unit ID(1) + PDU 长度（含功能码）**，big-endian。Length ≠ PDU 长度本身（常见错误点）。
3. PDU 最小 1 字节（功能码），最大 253 字节；MBAP+PDU 总长 ≤ 260 字节，单条 TCP 段可承载（默认 MSS 1460）。
4. 异常响应功能码 = 原功能码 | 0x80（不是替换为 0x80）；异常响应 PDU = 功能码(1) + 异常码(1)。
5. 同一事务的请求与响应共享 Transaction ID；事务间 Transaction ID 按 `TID = (N-1) mod 65536` 递增（第 1 个事务 TID=0，第 65536 个 TID=65535，第 65537 个 TID=0 回绕）。
6. 读位数据（FC 0x01/0x02）响应 byte count = ⌈quantity/8⌉；读寄存器（FC 0x03/0x04/0x17）响应 byte count = quantity×2。
7. 写单线圈合法值仅 0xFF00（ON）/0x0000（OFF）；本设计另接受 0/1 由 planner 映射（修复 R1-H2）。
8. 寄存器值均为 2 字节 big-endian（含 FC 0x0B/0x0C 的 Status/EventCount/MessageCount、FC 0x18 的 Byte Count/FIFO Count）。
9. FC 0x14 响应 item 含 File Response Length 字段（= 1 + 2 × Record Length，含 RefType 在内的记录数据字节数，修复 R3-C1）；FC 0x15 请求 item **不含 Byte Count 字段**，首字节即 Reference Type=0x06，item = RefType(1) + File Number(2) + Record Number(2) + Record Length(2) + Record Data(2×RL)，item 总长 = 7 + 2 × Record Length，外层 Byte Count = Σ(7+2×RL)（修复 R4-C1：R3-C2 补 item 内 Byte Count 的方向错误，tshark 实测 `15 0C 0B 06 ...` 被标记 Malformed、规范形式 `15 0B 06 ...` 正常解析）；FC 0x11 响应**无 Byte Count 字段**，首字节即 Slave ID（修复 R4-H2：v2.0.0 起的 M2-CRIT-2 与 R3-M2 两轮修复均未发现，tshark 实测 `11 04 01 FF AA BB` 显示原始 Data 无 Byte Count 字段）。
10. FC 0x18 读 FIFO 的 FIFO Count ≤ 31（规范上限，超出回异常码 0x04；本设计 Validate 拒绝，修复 M2-MED-3）。
11. 广播（Unit ID=0）仅对**纯写功能码**（FC 0x05/0x06/0x0F/0x10/0x15/0x16）合法；广播 + 读功能码（含 FC 0x17 读写混合）Validate 拒绝（修复 R1-M4；全部读类 FC 的拒绝路径见 T-094~T-095l，修复 R4-M3）。

---

## §2. 数据类型与编码

### §2.1 整数编码

| 类型 | 字节数 | 字节序 | 说明 |
|------|--------|--------|------|
| Transaction ID | 2 | big-endian | MBAP 字段，master 分配，slave 原样回传 |
| Protocol ID | 2 | big-endian | 恒 0x0000 |
| Length | 2 | big-endian | 后续字节数（Unit ID + PDU） |
| Unit ID | 1 | — | 0-247（248-255 保留），0=广播 |
| Function Code | 1 | — | 0x01-0x7F 正常；0x80+ 异常 |
| Starting Address | 2 | big-endian | 0x0000-0xFFFF |
| Quantity | 2 | big-endian | 数量，FC 特定上限 |
| Register Value | 2 | big-endian | 每个寄存器 2 字节 |
| Byte Count | 1 | — | 后续数据字节数（例外：FC 0x18 的 Byte Count 为 2 字节，见 §3.3.16） |
| Exception Code | 1 | — | 异常码，见 §2.5 |

### §2.2 位打包规则（FC 0x01/0x02/0x0F）

依据 Modbus 规范 §6.1：

> The LSB of the first data byte contains the output addressed in the query.
> The other outputs follow toward the high order end of this byte, and
> from 'low order to high order' in subsequent bytes.

- **字节传输顺序**：低地址字节先（low-address-first），即按地址升序传输承载字节。
- **字节内位序**：bit0（LSB，最低有效位）= starting_address+0，后续位序向字节高位递增。
- **末字节补零**：若 quantity 不是 8 的倍数，最后字节的高位（bitN..bit7）补 0，其中 N = (Quantity mod 8)。
- 例：quantity=10，第 1 字节承载 bit0-7，第 2 字节承载 bit8-9（bit10-15 补 0）。

注：本规范避免使用"little-endian / big-endian"术语描述位数据布局，统一采用"低地址字节先 + 字节内 LSB 优先"，与寄存器值的"big-endian"明确区分（修复 M2-LOW-1）。

### §2.3 写单线圈值（FC 0x05）

| 值 | 含义 |
|----|------|
| 0xFF00 | ON（闭合） |
| 0x0000 | OFF（断开） |

其他值（如 0x1234、0x0100）语义非法；除非配 `ExceptionCode`（任意合法异常码，见 §8.3），否则 Validate 拒绝。本设计另接受布尔 0/1 由 planner 在 Plan 阶段映射（0→0x0000，1→0xFF00，修复 R1-H2）。

### §2.4 寄存器值

每个寄存器（register，16 位）值为 2 字节 big-endian。多寄存器读写时按地址升序连续传输，无字节间填充。

### §2.5 异常码表（完整）

依据 Modbus 规范 §7 "Exception Response"：

| 码 | 名称 | 说明 |
|----|------|------|
| 0x01 | Illegal Function（非法功能） | 不支持的功能码 |
| 0x02 | Illegal Data Address（非法数据地址） | 地址越界 |
| 0x03 | Illegal Data Value（非法数据值） | 数量/值非法（如 quantity=0） |
| 0x04 | Slave Device Failure（从站设备故障） | 从站内部故障（含 FC 0x18 FIFO > 31） |
| 0x05 | Acknowledge（确认） | 已接受，需长时间处理 |
| 0x06 | Slave Device Busy（从站忙） | 从站忙，请重试 |
| 0x07 | Negative Acknowledge（否定确认） | 从站无法执行编程功能；客户端应请求诊断或错误信息（**合法码，v1.1 曾误删，v2.0.0 恢复**） |
| 0x08 | Memory Parity Error（内存奇偶校验错） | 内存奇偶校验错 |
| 0x0A | Gateway Path Unavailable（网关路径不可用） | 网关路径不可用 |
| 0x0B | Gateway Target Device Failed to Respond（网关目标设备无响应） | 网关目标无响应 |

合法异常码集合（Validate 接受）：`{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x0A, 0x0B}`，共 10 个。0x00 在配置层视为"未设置异常"（即正常响应语义），**不报错**（V-122，修复 R4-L3 澄清与异常响应无关）；0x09、0x0C-0xFF 一律拒绝。注：0x09 在规范中保留空缺（reserved），不是合法异常码。

### §2.6 长度字段约束

- Length 字段 = Unit ID(1) + PDU 长度 = 1 + PDU 长度。
- PDU 最大 253 字节，故 Length 最大 254（0x00FE）。
- 整个 Modbus TCP 报文（MBAP+PDU）最大 260 字节，可由单条 TCP 段承载（默认 MSS 1460）。
- 多寄存器/多线圈数量上限由 PDU 长度反推：写多寄存器 quantity≤123，写多线圈 quantity≤1968。

### §2.7 数量上限汇总（规范 §6 各 FC）

| FC | 字段 | 最小 | 最大 | 依据（MB-ASYM-TCP） |
|----|------|------|------|---------------------|
| 0x01/0x02 | Quantity of Coils/Inputs | 1 | 2000 | §6.1/§6.2（0x07D0） |
| 0x03/0x04 | Quantity of Registers | 1 | 125 | §6.3/§6.4（0x7D） |
| 0x0F | Quantity of Outputs | 1 | 1968 | §6.11（0x7B0） |
| 0x10 | Quantity of Registers | 1 | 123 | §6.12（0x7B） |
| 0x17 | Read Quantity | 1 | 125 | §6.17 |
| 0x17 | Write Quantity | 1 | 121 | §6.17（写值 2×121=242 字节） |
| 0x18 | FIFO Count（响应） | 0 | 31 | §6.18（超出回异常码 0x04；值字节数必须=2×FIFO Count，自洽校验 V-119，修复 R4-H4） |
| 0x0B/0x0C | Event Count / Message Count | 0 | 65535 | §6.5/§6.6（uint16 全域） |

---

## §3. 消息结构

### §3.1 MBAP 头（Modbus Application Protocol Header，7 字节）

| 偏移 | 长度 | 字段 | 说明 |
|------|------|------|------|
| 0 | 2 | Transaction ID | 事务标识符，big-endian，master 分配，slave 原样回传 |
| 2 | 2 | Protocol ID | 协议标识符，恒 0x0000（Modbus） |
| 4 | 2 | Length | **后续字节数（Unit ID + PDU）**，big-endian |
| 6 | 1 | Unit ID | 从站标识符，0-247（248-255 保留），0=广播 |

### §3.2 PDU 通用格式

| 偏移 | 长度 | 字段 | 说明 |
|------|------|------|------|
| 0 | 1 | Function Code | 功能码 0x01-0x7F；0x80+ 为异常响应 |
| 1 | 可变 | Data | 功能码特定数据 |

### §3.3 各 Function Code 的 PDU 格式（逐字段对照 MB-ASYM-TCP §6.1-§6.21）

#### §3.3.1 读线圈 FC=0x01 / 读离散输入 FC=0x02

请求（规范 §6.1/§6.2）：

| 字节 | 字段 | 说明 |
|------|------|------|
| 0 | FC | 0x01 / 0x02 |
| 1-2 | Starting Address | 起始地址 0x0000-0xFFFF，big-endian |
| 3-4 | Quantity of Coils/Inputs | 数量 1-2000（0x01-0x07D0），big-endian |

正常响应：

| 字节 | 字段 | 说明 |
|------|------|------|
| 0 | FC | 0x01 / 0x02 |
| 1 | Byte Count | = ⌈Quantity/8⌉ |
| 2.. | Coil/Input Status | 位打包，按 §2.2 规则：低地址字节先 + 字节内 LSB 优先 |

#### §3.3.2 读保持寄存器 FC=0x03 / 读输入寄存器 FC=0x04

请求（规范 §6.3/§6.4）：

| 字节 | 字段 | 说明 |
|------|------|------|
| 0 | FC | 0x03 / 0x04 |
| 1-2 | Starting Address | 0x0000-0xFFFF |
| 3-4 | Quantity of Registers | 1-125（0x01-0x7D） |

正常响应：

| 字节 | 字段 | 说明 |
|------|------|------|
| 0 | FC | 0x03 / 0x04 |
| 1 | Byte Count | = Quantity * 2 |
| 2.. | Register Values | 每个寄存器 2 字节 big-endian |

#### §3.3.3 写单线圈 FC=0x05

请求（规范 §6.5）：

| 字节 | 字段 | 说明 |
|------|------|------|
| 0 | FC | 0x05 |
| 1-2 | Output Address | 0x0000-0xFFFF |
| 3-4 | Output Value | 0xFF00=ON，0x0000=OFF（其他值语义非法，见 §2.3） |

正常响应：与请求逐字节相同（echo）。

#### §3.3.4 写单寄存器 FC=0x06

请求（规范 §6.6）：

| 字节 | 字段 | 说明 |
|------|------|------|
| 0 | FC | 0x06 |
| 1-2 | Register Address | 0x0000-0xFFFF |
| 3-4 | Register Value | 0x0000-0xFFFF |

正常响应：与请求逐字节相同（echo）。

#### §3.3.5 读异常状态 FC=0x07

请求（规范 §6.7）：仅 1 字节 FC=0x07，无数据。

响应：

| 字节 | 字段 | 说明 |
|------|------|------|
| 0 | FC | 0x07 |
| 1 | Exception Status | 8 位离散输入打包，bit0=异常状态第 0 位 |

#### §3.3.6 诊断 FC=0x08

请求（规范 §6.8）：

| 字节 | 字段 | 说明 |
|------|------|------|
| 0 | FC | 0x08 |
| 1-2 | Sub-Function | 子功能码 0x0000-0x0015（**上限 0x0015，修复 R3-H1；0x0005-0x0009 保留**） |
| 3.. | Data Field | 子功能特定数据（通常 2 字节） |

响应：响应格式因子功能而异（修复 M2-LOW-2 的"多数为回显"不精确表述）：

| 子功能 | 名称 | 响应 |
|--------|------|------|
| 0x0000 | Return Query Data（返回查询数据） | 与请求逐字节相同（回显） |
| 0x0001 | Restart Communications（重启通信） | 响应含清除事件计数器数据（0x0000 或 0xFF00 + 子功能码） |
| 0x0002/0x0003 | Return Diagnostic Register / Change ASCII Input Delimiter | 回显 |
| 0x0004 | Force Listen Only Mode（强制只听模式） | 无响应（从站进入只听模式） |
| 0x0005-0x0009 | （保留，reserved） | Validate 拒绝（V-117） |
| 0x000A-0x0015 | 计数器类子功能（Clear Counters and Diagnostic Register 至 Return IOP Overrun Count 等，含 0x0014=Clear Overrun Counter and Flag、0x0015=Get/Clear Modbus Plus Statistics） | 返回计数器值（不一定是回显） |
| 0x0014 | Clear Overrun Counter and Flag（清溢出计数器与标志） | 返回计数器值（不一定是回显） |
| 0x0015 | Get/Clear Modbus Plus Statistics（获取/清空 Modbus Plus 统计） | 返回 Modbus Plus 统计（不一定是回显） |
| 0x0016-0xFFFF | （保留/未定义） | Validate 拒绝（V-117） |

> 注（修复 R4-M1）：**0x0015 在 Wireshark 3.6 的值表未收录**——tshark 3.6.14 实测子功能 0x0014 → "Clear Overrun Counter and Flag (20)" 正常识别，0x0015 → "Unknown (21)"。本设计按规范 §6.8 仍将 0x0015 列为合法子功能（V-117 允许），但 tshark 集成用例（T-181~T-200）**不覆盖 0x0015**（§9.5 工具链弱化声明）；如需 wire 级验证 0x0015 报文，须使用更高版本 tshark 或自写解析器。

本设计 v2 默认实现 0x0000 回显模式，其他子功能由用户通过 `ResponseValues` 显式注入。

#### §3.3.7 取通信事件计数器 FC=0x0B（Get Comm Event Counter）

请求（规范 §6.5 of V1.1b3）：仅 1 字节 FC=0x0B，无数据。

响应（**Status 为 2 字节**）：

| 字节 | 字段 | 说明 |
|------|------|------|
| 0 | FC | 0x0B |
| 1-2 | Status | big-endian；0xFFFF = 事件计数有效（ready），0x0000 = 无效（busy） |
| 3-4 | Event Count | 事件计数，big-endian，0-65535 |

#### §3.3.8 取通信事件日志 FC=0x0C（Get Comm Event Log）

请求（规范 §6.6）：仅 1 字节 FC=0x0C，无数据。

响应（**修复 R1-C7：Byte Count 必须 = 6 + N**）：

| 字节 | 字段 | 说明 |
|------|------|------|
| 0 | FC | 0x0C |
| 1 | Byte Count | = 后续字节数 = Status(2) + EventCount(2) + MessageCount(2) + Events(N) = **6 + N** |
| 2-3 | Status | big-endian；0xFFFF = 有效，0x0000 = 无效 |
| 4-5 | Event Count | 事件计数，big-endian |
| 6-7 | Message Count | 报文计数，big-endian |
| 8.. | Events | 事件字节序列，每个事件 1 字节；**N 由 Events 配置决定，与 EventCount 字段值解耦**（模拟用途） |

> 字段顺序依据 MB-ASYM-TCP §6.6 表 10（Status → Event Count → Message Count；v2.0.0-§3.3.8 曾将 EventCount/MessageCount 对调，修复 R3-H2）。

#### §3.3.9 写多线圈 FC=0x0F

请求（规范 §6.11）：

| 字节 | 字段 | 说明 |
|------|------|------|
| 0 | FC | 0x0F |
| 1-2 | Starting Address | 0x0000-0xFFFF |
| 3-4 | Quantity of Outputs | 1-1968（0x01-0x7B0） |
| 5 | Byte Count | = ⌈Quantity/8⌉ |
| 6.. | Outputs Value | 位打包，按 §2.2 规则 |

正常响应：

| 字节 | 字段 | 说明 |
|------|------|------|
| 0 | FC | 0x0F |
| 1-2 | Starting Address | 回显请求起始地址 |
| 3-4 | Quantity of Outputs | 回显请求数量 |

#### §3.3.10 写多寄存器 FC=0x10

请求（规范 §6.12）：

| 字节 | 字段 | 说明 |
|------|------|------|
| 0 | FC | 0x10 |
| 1-2 | Starting Address | 0x0000-0xFFFF |
| 3-4 | Quantity of Registers | 1-123（0x01-0x7B） |
| 5 | Byte Count | = Quantity * 2 |
| 6.. | Registers Value | 每个寄存器 2 字节 big-endian |

正常响应：

| 字节 | 字段 | 说明 |
|------|------|------|
| 0 | FC | 0x10 |
| 1-2 | Starting Address | 回显 |
| 3-4 | Quantity of Registers | 回显 |

#### §3.3.11 报告从站 ID FC=0x11（Report Server ID）

请求（规范 §6.11 of V1.1b3 / PI-MBUS-300 §6.11）：仅 1 字节 FC=0x11。

响应（**修复 R4-H2：无 Byte Count 字段，首字节即 Slave ID**；MB-ASYM-TCP §6.11 / PI-MBUS-300 中 FC 0x11 响应的字段顺序为 Slave ID + Run Indicator + Additional Data，无首字节 Byte Count——Byte Count 仅存在于 Modbus RTU 的 FC 0x11 响应，Modbus TCP 的 FC 0x11 响应直接以 Slave ID 开始；tshark 3.6.14 实测 `11 04 01 FF AA BB` 显示 "Data: 0401ffaabb" 无 Byte Count 字段；pymodbus `ReportSlaveIdResponse` 编码同样无 Byte Count。v2.0.0 起 M2-CRIT-2 与 R3-M2 两轮修复均未发现此问题）：

| 字节 | 字段 | 说明 |
|------|------|------|
| 0 | FC | 0x11 |
| 1 | Slave ID | 从站标识（设备特定） |
| 2 | Run Indicator Status | 0x00=OFF（停止运行），0xFF=ON（运行中） |
| 3.. | Additional Data | 设备特定附加数据（可空，此时响应 PDU 仅 3 字节） |

典型响应字节序列示例：
```
11 01 FF              <- Slave ID=0x01, Run Indicator=0xFF（无 Additional）
11 01 FF AA BB        <- Slave ID=0x01, Run Indicator=0xFF, Additional=AA BB（2 字节）
```
核算：第二行共 6 字节 = FC(1) + Slave ID(1) + Run Indicator(1) + Additional(2)；PDU=5 字节，MBAP Length = 1(Unit) + 5 = 6（0x0006）。

#### §3.3.12 读文件记录 FC=0x14（Read File Records）

请求（规范 §6.14 / PI-MBUS-300 §6.13）：

| 字节 | 字段 | 说明 |
|------|------|------|
| 0 | FC | 0x14 |
| 1 | Byte Count | 后续总字节数 = Σ(item 7 字节) |
| 2.. | Item(s) | 每项固定 **7 字节**：Reference Type(1)=0x06 + File Number(2) + Record Number(2) + Record Length(2) |

响应（**修复 R3-C1：item 首字节为 File Response Length，非 Byte Count；字段语义修正**）：

| 字节 | 字段 | 说明 |
|------|------|------|
| 0 | FC | 0x14 |
| 1 | Byte Count | 后续总字节数 = Σ(item 长度) |
| 2.. | Item(s) | 每项（依据 MB-ASYM-TCP §6.14 表 31 / PI-MBUS-300 §6.13；与 pymodbus `ReadFileRecordResponse.encode` 一致）：**File Response Length(1) = 1 + 2 × Record Length**（含 RefType 在内的记录数据总字节数，**不是 Byte Count，更不是 Record Length × 2**）+ Reference Type(1)=0x06 + Record Data(Record Length * 2 字节)；每项总长 = 1 + 1 + 2 × Record Length = 2 + 2 × Record Length 字节；**item 内不含 File Number/Record Number** |

> 依据：MB-ASYM-TCP §6.14 表 31，响应 item 字段为 **File Response Length(1) + Reference Type(1) + Record Data(2×RL)**。File Response Length 计数**包含 Reference Type 自身的 1 字节**，即 = 1 + 2 × Record Length（如 RL=2 时 Length=5=0x05，而不是 4=0x04）；item 内不存在"Byte Count = Record Length × 2"字段（v2.0.0-§3.3.12 曾误设，修复 R3-C1）。

#### §3.3.13 写文件记录 FC=0x15（Write File Records）

请求（规范 §6.15 / PI-MBUS-300 §6.14；**修复 R4-C1：item 内无 Byte Count 字段，首字节即 Reference Type=0x06；R3-C2 补 item 内 Byte Count 的方向错误已回退**）：

| 字节 | 字段 | 说明 |
|------|------|------|
| 0 | FC | 0x15 |
| 1 | Byte Count | 后续总字节数 = Σ(item 长度) |
| 2.. | Item(s) | 每项结构为（依据 MB-ASYM-TCP §6.15 表 35 / PI-MBUS-300 §6.14，与 pymodbus `WriteFileRecordRequest.encode` 一致）：**Reference Type(1)=0x06 + File Number(2) + Record Number(2) + Record Length(2) + Record Data(2 × Record Length 字节)**；item 首字节直接是 Reference Type，**不是 Byte Count** |

每个 item 总长 = 7 + 2 × Record Length 字节，**按各 item 的 Record Length（偏移 5-6）动态步进**（修复 R4-C1，恢复 v2.0.2 的 R1-M1 步进规则）。

> 依据（修复 R4-C1）：MB-ASYM-TCP §6.15 表 35，请求 item 首字段为 **Reference Type** 而非 Byte Count。tshark 3.6.14 实测：规范形式 `15 0B 06 0001 0000 0002 1234 5678`（外层 Byte Count=0x0B=11）→ **正常解析**（Byte Count=11、Reference Type=6、File Number=1、Record Number=0、Word Count=2、Data）；v2.0.3 形式 `15 0C 0B 06 0001 0000 0002 1234 5678`（多出 item 内首字节 0x0B）→ **标记 Malformed**（外层 Byte Count=12 后被当成 Reference Type=0x0B、Reference Number=0x060001、Word Count=0x0000）。pymodbus dev `WriteFileRecordRequest.encode` 为 `packet += struct.pack(">BHHH", 0x06, file, rec, len)` 直接写 Reference Type=0x06，外层 `total_length = sum(7+2×RL)`——item 内无 Byte Count 字段。

响应：与请求逐字节相同（echo，含完整 Record Data）。

典型请求示例（1 个 item，File=1, Record=0, Record Length=2, Record Data=0x1234 0x5678）：
```
15 0B 06 0001 0000 0002 1234 5678
   ^^ -- 外层 Byte Count=0x0B=11 = item 总长（7+2×2，修复 R4-C1）
      ^ -- Reference Type=0x06（item 首字节，无 item 内 Byte Count）
        ^^^^ -- File Number=1
              ^^^^ -- Record Number=0
                    ^^^^ -- Record Length=2
                          ^^^^ ^^^^ -- Record Data (2×2=4 bytes)
```
核算：PDU = FC(1) + 外层 BC(1) + item(11) = 13 字节；MBAP Length = 1(Unit) + 13 = 14（0x000E）。item 11 字节 = RefType(1) + File(2) + Record(2) + RecLen(2) + Data(4) ✓，外层 BC=11 = 7+2×2 与 item 总长自洽 ✓（修复 R4-C1：v2.0.3 的 item 12 字节、Length=15 形态被 tshark 判 Malformed）。

#### §3.3.14 掩码写寄存器 FC=0x16（Mask Write Register）

请求（规范 §6.16）：

| 字节 | 字段 | 说明 |
|------|------|------|
| 0 | FC | 0x16 |
| 1-2 | Reference Address | 0x0000-0xFFFF |
| 3-4 | AND Mask | 0x0000-0xFFFF |
| 5-6 | OR Mask | 0x0000-0xFFFF |

**协议语义公式（修复 R1-C6）**：

```
Result = (Current Contents AND AND_Mask) OR (OR_Mask AND (NOT AND_Mask))
```

注：上式为协议语义参考（依据 MB-ASYM-TCP §6.16 / PI-MBUS-300 §6.14）。本设计的 wire 行为是请求/响应逐字节 echo，**不模拟寄存器状态**，实现不执行该公式。例：A=0x00FF, O=0x0001, Cur=0x1234 → (0x1234 AND 0x00FF) | (0x0001 AND ~0x00FF) = 0x0034 | 0x0000 = 0x0034。

响应：与请求逐字节相同（echo）。

#### §3.3.15 读/写多寄存器 FC=0x17（Read/Write Multiple Registers）

请求（规范 §6.17）：

| 字节 | 字段 | 说明 |
|------|------|------|
| 0 | FC | 0x17 |
| 1-2 | Read Starting Address | 0x0000-0xFFFF |
| 3-4 | Quantity to Read | 1-125（0x01-0x7D） |
| 5-6 | Write Starting Address | 0x0000-0xFFFF |
| 7-8 | Quantity to Write | 1-121（0x01-0x79） |
| 9 | Write Byte Count | = Quantity to Write * 2 |
| 10.. | Write Registers Value | 每个寄存器 2 字节 big-endian |

正常响应：

| 字节 | 字段 | 说明 |
|------|------|------|
| 0 | FC | 0x17 |
| 1 | Byte Count | = Quantity to Read * 2 |
| 2.. | Read Registers Value | 每个寄存器 2 字节 big-endian |

注：FC 0x17 时配置使用独立的 `ReadQuantity` / `WriteQuantity` 字段，忽略通用 `Quantity` 字段（见 §5.2 字段说明，修复 M2-MED-2）。

#### §3.3.16 读 FIFO 队列 FC=0x18（Read FIFO Queue）

请求（规范 §6.18）：

| 字节 | 字段 | 说明 |
|------|------|------|
| 0 | FC | 0x18 |
| 1-2 | FIFO Pointer Address | 0x0000-0xFFFF |

响应（**注意 Byte Count 为 2 字节，与其余 FC 不同**；FIFO Count ≤ 31，修复 M2-MED-3）：

| 字节 | 字段 | 说明 |
|------|------|------|
| 0 | FC | 0x18 |
| 1-2 | Byte Count | = 后续字节数 = FIFO Count(2) + Value Registers(2N) = **2 + 2N**，big-endian |
| 3-4 | FIFO Count | 寄存器数 N，big-endian；**N ≤ 31**，否则触发异常响应 0x04（本设计 Validate 拒绝） |
| 5.. | FIFO Value Register(s) | N*2 字节，每个寄存器 2 字节 big-endian |

约束（修复 R4-H4）：若 `ResponseValues` 中 FIFO Count（RV 偏移 2-3）> 31，Validate 拒绝（V-119）；且 **FIFO Count 与 RV 中值字节数必须自洽**——值字节数必须 = 2 × FIFO Count，否则 Validate 拒绝 `response_values length must match FIFO count`（RV 中 Byte Count 字段由 planner 按 2 + 2×FIFO Count 重新计算，用户无需、也不应手工维护）。

#### §3.3.17 封装接口传输 FC=0x2B（Encapsulated Interface Transport / MEI）

请求（规范 §6.21）：

| 字节 | 字段 | 说明 |
|------|------|------|
| 0 | FC | 0x2B |
| 1 | MEI Type | 0x0E=Read Device Identification（读设备标识，请求与响应**同用 0x0E**）；0x0D=**CANopen General（CiA 309）**，本设计不实现；其他值拒绝 |
| 2.. | MEI Specific Data | 子类型特定 |

**MEI Type 编码规则（修复 R1-M6）**：配置层 `SubFunction` 为 uint16（FC 0x08 需 0x0000-0x0015 全宽，修复 R3-H1）；FC 0x2B 时取 **SubFunction 低字节**作为 MEI Type，**高字节必须为 0**（SubFunction=0x000E → MEI=0x0E；SubFunction=0x010E → Validate 拒绝"FC 0x2B 时 SubFunction 高字节必须为 0"）。

> MEI Type 语义（修复 R4-H1，回退 R3-M1 的错误标注）：规范 §6.21 表 42 的 MEI Type 值是 **per FC 2B sub-function 的请求值**——MEI Type 0x0D=**CANopen General（CiA 309）**、0x0E=**Read Device Identification**，两者都是请求侧 MEI Type，不存在"0x0D=请求、0x0E=响应侧"的区分（Read Device Identification 的响应与请求使用同一个 MEI Type 0x0E）。tshark 3.6.14 实测：`2B 0D 01 00` → "MEI type: **CANopen Request/Response (13)**"；`2B 0E 01 00` → "MEI type: **Read Device Identification (14)**"。v2.0.3 的"0x0E 仅作响应侧 MEI Type 接受"系对表 42 的根本性误读，已回退。

Read Device Identification（MEI Type=0x0E）请求：

| 字节 | 字段 | 说明 |
|------|------|------|
| 0 | FC | 0x2B |
| 1 | MEI Type | 0x0E |
| 2 | Read Device ID Code | 0x01=Basic, 0x02=Regular, 0x03=Extended, 0x04=Specific |
| 3 | Object ID | 起始对象 ID（Basic 时为 0x00） |

响应（修复 M2-HIGH-3 的完整规格化）：

| 字节 | 字段 | 说明 |
|------|------|------|
| 0 | FC | 0x2B |
| 1 | MEI Type | 0x0E（与请求同值） |
| 2 | Read Device ID Code | 回显请求值 |
| 3 | Conformity Level | 0x01/0x02/0x03 = Basic/Regular/Extended；0x81/0x82/0x83 = 对应级别 + Private |
| 4 | More Follows | 0x00 = 无后续对象，0xFF = 还有 |
| 5 | Next Object ID | 下一对象 ID（More Follows=0 时置 0x00） |
| 6 | Number of Objects | 本响应中的对象数 |
| 7.. | Object(s) | 每个：Object ID(1) + Object Length(1) + Object Value(Object Length) |

### §3.4 异常响应格式（规范 §7）

| 字节 | 字段 | 说明 |
|------|------|------|
| 0 | Function Code | 原功能码 \| 0x80 |
| 1 | Exception Code | 见 §2.5 异常码表 |

异常响应 PDU 恒 2 字节；MBAP 头的 Length = 1（Unit ID）+ 1（FC）+ 1（Exception Code）= 3。用户不可直接设置高位置位的 FunctionCode（0x80-0xFF 一律拒绝，除非走 §1.3 豁免路径）。

---

## §4. 状态机

### §4.1 事务状态机（Transaction，请求→响应→异常）

Modbus 是无状态请求-响应协议（stateless，无状态）：slave 不维护跨事务的会话状态，每个事务（transaction，事务 = 一次请求 + 一次响应）独立处理。planner（规划器，负责把配置展开为报文序列的组件）在**单条 TCP 流**上串行推进事务，事务之间无状态依赖，唯一的流状态是 TCP 连接本身。

```
                        +----------------+
                        |  Idle（空闲）   |
                        +----------------+
                              |
                              | 生成请求 PDU（FC + Data）
                              v
   +----------------+    +----------------+
   |  TxSent（请求已发）|-> |  AwaitReply    |
   |（仅发送，无响应）  |   |  （等待响应）    |
   +----------------+    +----------------+
   （广播+Suppress    |         |            |
     Broadcast=true    |         | 响应到达    | 超时（仅响应时间戳策略）
   或只听模式 0x0004） |         v            v
                        |   +----------------+    +----------------+
                        |   |  RxOk（正常响应）|    |  RxTimeout     |
                        |   +----------------+    +----------------+
                        |         |                    |
                        |         |                    |
                        |         v                    |
                        |   +----------------+         |
                        +-> |  Exception     |<--------+
                            |  （异常响应）    |
                            +----------------+
                              |
                              v
                        +----------------+
                        |  事务结束        |
                        |  TID = (N-1)    |
                        |  mod 65536      |
                        +----------------+
```

**状态迁移规则**：

| 当前状态 | 事件 | 下一状态 | 说明 |
|----------|------|----------|------|
| Idle | planner 取下一事务配置 | TxSent | 生成请求 PDU，计算 MBAP Length |
| TxSent | 配置 `ResponseMode=no_response`（或无响应语义场景） | 事务结束 | 不等待响应（诊断子功能 0x0004 Force Listen Only、广播+SuppressBroadcast=true） |
| TxSent | 配置 `ExceptionCode != 0` | Exception | 响应 PDU = `FC\|0x80 + ExceptionCode`（见 §3.4） |
| TxSent | 响应到达且 FC 正常 | RxOk | 响应 PDU 按 §3.3 各 FC 构造 |
| AwaitReply | 超时（若启用响应时间戳策略） | RxTimeout | 标记事务超时，继续下一事务（不重传） |

**关键设计点（修复 R2-H2）**：
1. `ResponseValues`（响应值，显式注入响应 PDU 的字节序列）只作用于响应 PDU，与请求 PDU（由 `Values` 决定）**完全独立、无任何交互路径**——不存在"ResponseValues 试图覆盖请求"的配置形态，该错误消息不可达（T-064/T-108 已删除）。
2. `ExceptionCode` 与 `ResponseValues` 互斥：两者同时非零/非空时 Validate 拒绝（`exception_code and response_values are mutually exclusive`，见 §8.1 V-017）。
3. 事务之间无重传、无滑动窗口：请求发出后不模拟 slave 的 ACK 时序，响应包与请求包在 TCP 流上按"请求 1 → 响应 1 → 请求 2 → 响应 2"的顺序排列（traffic-mirror 模型，traffic-mirror 即把响应包镜像生成以便抓包验证）。
4. **ExceptionCode 的请求侧语义（修复 R3-L1）**：支持集内合法 FC 配 `ExceptionCode != 0` 时，**请求 PDU 仍按该 FC 正常构造**（与无 ExceptionCode 时完全相同，包括 `Values` 透传、外层 Byte Count 等），**仅响应 PDU 被替换为异常 PDU（`FC|0x80 + ExceptionCode`）**；该语义对 §1.3 豁免路径（FC 不在支持集）不适用——豁免路径下请求按用户字节逐字节透传。T-031~T-040 的异常用例均应额外断言请求 PDU 正常构造（如 T-032 断言请求 PDU=`03 0000 0001`）。

### §4.2 多事务序列状态机（TID 分配）

单 TCP 流承载 N 个事务时，Transaction ID（事务标识符）分配规则：

```
TID = (N-1) mod 65536        // 第 1 个事务 TID=0
                             // 第 65536 个事务 TID=65535
                             // 第 65537 个事务 TID=0（回绕，wrap-around）
```

| 属性 | 规则 |
|------|------|
| 请求/响应共享 TID | 同一事务的请求与响应使用相同 TID |
| 事务间 TID 单调递增 | 每事务 +1，按上公式回绕 |
| 流内唯一性 | 单流内 TID 在回绕前唯一 |
| 跨流复用 | 不同 TCP 流（不同 4-tuple）的 TID 空间独立，可并发复用相同 TID 值 |
| SharedTIDSpace=true | 多流共享一个连续 TID 空间，TID 跨流全局递增（见 S11/S12） |

**广播特殊规则（修复 R1-M4，§4.4 细化为三条）**：
- 广播（Unit ID=0）仅对纯写功能码（FC 0x05/0x06/0x0F/0x10/0x15/0x16）合法；广播 + 读功能码（含 FC 0x17 读写混合）Validate 拒绝。
- 广播时 slave 不回正常响应；本设计默认仍生成镜像响应包（traffic-mirror 用途），`SuppressBroadcast=true` 时省略。
- `SuppressBroadcast=true` 同时抑制异常响应包：广播 + `ExceptionCode != 0` 时，若 SuppressBroadcast=true 则不生成任何响应包（异常响应也属于响应，一并抑制）。

### §4.3 TCP 连接状态机

| 阶段 | 动作 | 报文 |
|------|------|------|
| TCP 三次握手 | SYN → SYN+ACK → ACK | 由 TCP 层完成（planner 不干预） |
| 请求/响应阶段 | 依序发送 N 个事务（每事务：请求包 + 响应包） | 所有 Modbus TCP 报文 |
| TCP 挥手 | FIN → ACK → FIN → ACK | 由 TCP 层完成 |

与 SOCKS5 不同，Modbus 没有握手/认证阶段——TCP 三次握手完成后即可发送第一个请求。`Transactions == nil`（JSON 字段缺失）→ planner 注入 1 个默认事务（FC=0x03 读保持寄存器，addr=0, qty=1）；`Transactions` 为显式空数组 `[]` → 仅 TCP 握手 + 挥手（连接探测场景，见 §5.3 默认值规则）。

### §4.4 广播语义（Unit ID=0）

依据 MB-ASYM-TCP "Broadcast"：Unit ID=0 为广播地址，slave 处理请求但不回正常响应。本设计三细则（修复 R1-M4）：

1. **广播 + 读功能码 → Validate 拒绝**：仅纯写功能码（FC 0x05/0x06/0x0F/0x10/0x15/0x16）可广播；广播 + 读功能码（FC 0x01-0x04/0x07/0x08/0x0B/0x0C/0x11/0x14/0x17/0x18/0x2B，含 FC 0x17 读写混合）拒绝，错误消息 `broadcast (unit_id=0) is only valid for write function codes`。全部读类 FC 的广播拒绝路径由参数化用例 T-094~T-095l 覆盖（修复 R4-M3）。
2. **默认仍发镜像响应包**：广播事务在 master 侧仍生成响应包（traffic-mirror 用途，便于抓包验证），`SuppressBroadcast=true` 时省略。
3. **SuppressBroadcast 作用域含异常响应**：广播 + `ExceptionCode != 0` + `SuppressBroadcast=true` → 不生成任何响应包（含异常响应）；`SuppressBroadcast=false` 时异常响应包照常生成。

### §4.5 响应推导规则（planner 自动构造）

planner 按 FC 自动构造响应 PDU 结构（ResponseValues 非空时覆盖"FC 之后的字节"，见 §5.2）：

| FC | 响应 PDU 自动构造规则（ResponseValues 为空时） |
|----|------|
| 0x01/0x02 | FC + Byte Count=⌈qty/8⌉ + 位数据（默认全 0） |
| 0x03/0x04 | FC + Byte Count=qty×2 + 寄存器值（默认全 0） |
| 0x05/0x06 | 与请求逐字节相同（echo） |
| 0x07 | FC + Exception Status（默认 0x00） |
| 0x08 | 回显请求 PDU（子功能 0x0000 Return Query Data 语义） |
| 0x0B | FC + Status(2) + Event Count(2)（默认 Status=0xFFFF, EventCount=0） |
| 0x0C | FC + Byte Count=6+N + Status(2) + EventCount(2) + MessageCount(2) + Events(N)（字段顺序依规范 §6.6 表 10，修复 R3-H2 核对） |
| 0x0F/0x10 | FC + Starting Address(2) + Quantity(2)（回显请求地址与数量） |
| 0x11 | FC + Slave ID(1) + Run Indicator(1) + Additional(N)（无 Byte Count 字段，修复 R4-H2） |
| 0x14 | FC + Byte Count + items（每 item：File Response Length(1) = 1+2×RL + RefType(1)=0x06 + Record Data(2×RL)，修复 R3-C1） |
| 0x15 | 与请求逐字节相同（echo，含完整 Record Data；item 无 item 内 Byte Count，修复 R4-C1） |
| 0x16 | 与请求逐字节相同（echo） |
| 0x17 | FC + Byte Count=ReadQty×2 + 读寄存器值（默认全 0） |
| 0x18 | FC + Byte Count(2)=2+2N + FIFO Count(2) + Values(2N)（FIFO Count 与值字节数必须自洽：值字节数 = 2×FIFO Count，修复 R4-H4） |
| 0x2B | FC + MEI Type(0x0E) + Read Device ID Code + Conformity Level + More Follows + Next Object ID + Object Count + Object(s)（见 §3.3.17 响应表，修复 R4-H1） |

---

## §5. 配置类型定义（Go struct）

### §5.1 MODBUSConfig 顶层结构

```go
// MODBUSConfig 是 Modbus TCP 协议的顶层配置。
type MODBUSConfig struct {
    // UnitID 是从站标识符（Unit Identifier，Unit ID）。
    // *uint8：nil = 未设置（默认 1）；0 = 广播（合法值，修复 M2-HIGH-1）。
    // 不能用 uint8+omitempty——Go 中 uint8 零值 0 会被 omitempty 省略，
    // 无法区分"字段未设"与"显式设为 0（广播）"。
    UnitID *uint8 `json:"unit_id"`

    // SuppressBroadcast 抑制广播响应包。
    // true 时 UnitID=0 的事务不生成镜像响应包（含异常响应包，见 §4.4）。
    SuppressBroadcast bool `json:"suppress_broadcast"`

    // Transactions 是事务序列（按顺序执行）。
    // nil（JSON 字段缺失）→ planner 注入 1 个默认事务（FC=0x03, addr=0, qty=1）；
    // 显式空数组 [] → 仅 TCP 握手 + 挥手（连接探测，修复 M2-MED-4）。
    Transactions []MODBUSOperation `json:"transactions"`

    // 多会话/多流参数（修复 M2-LOW-1 的术语区分）。
    MasterCount int `json:"master_count"` // 并发 master（client）数，默认 1；每个 master 独立 4-tuple（独立 TCP 流）
    FlowCount   int `json:"flow_count"`   // 每 master 的并发流数，默认 1

    // SharedTIDSpace 共享 TID 空间：true 时所有流共享连续 TID 空间（跨流全局递增）。
    SharedTIDSpace bool `json:"shared_tid_space"`

    // 广播 + 写功能码时 ResponseValues 仍只作用于响应 PDU（见 §5.2）。
}
```

**设计原则**（对齐 §1.4）：
1. 零值可用：`MODBUSConfig{}`（全空）→ 1 个默认事务（FC=0x03 读保持寄存器），可直接生成 wire 报文。
2. `UnitID` 用 `*uint8`：nil→默认 1；显式 0→广播（修复 M2-HIGH-1 的 omitempty 冲突）。
3. 字节序由 builder（构造器，负责把配置序列化为 wire 字节的组件）处理：用户填写 host-endian 值，builder 负责序列化为 big-endian。

### §5.2 MODBUSOperation 结构

```go
// MODBUSOperation 描述单个 Modbus 事务（一个请求 + 一个响应）。
type MODBUSOperation struct {
    // FunctionCode 功能码，支持集见 §1.3（19 个合法 FC）。
    // 不在支持集时若 ExceptionCode != 0 走 §1.3 豁免路径（逐字节透传，响应 FC|0x80 + 异常码）。
    FunctionCode uint8 `json:"function_code"`

    // ExceptionCode 异常码（见 §2.5）。
    // 非零时响应 PDU = FC|0x80 + ExceptionCode，忽略正常响应构造。
    // 与 ResponseValues 互斥（V-017）。
    // 注意：FC 0x99 等 bit7 已置位的 FC，FC|0x80 幂等（结果仍为原值，见 §6.14 S14）。
    ExceptionCode uint8 `json:"exception_code"`

    // StartingAddress 起始地址（FC 0x01-0x06/0x0F/0x10/0x11-0x18 通用）。
    // FC 0x17 时作为 Read Starting Address（见 ReadAddress）。
    StartingAddress uint16 `json:"starting_address"`

    // Quantity 数量（FC 特定上限，见 §2.7）。
    // FC 0x17 时 IGNORED（使用 ReadQuantity/WriteQuantity，修复 M2-MED-2）。
    Quantity uint16 `json:"quantity"`

    // ReadAddress/WriteAddress FC 0x17 专用（读写起始地址）。
    // WriteAddress=0 时回退到 StartingAddress + WriteQuantity（uint16 模运算回绕，修复 R1-H3/R2-M6）。
    ReadAddress  uint16 `json:"read_address"`
    WriteAddress uint16 `json:"write_address"`

    // ReadQuantity/WriteQuantity FC 0x17 专用（读/写数量）。
    // 未设置（0）时 Validate 报错（quantity must be explicit for FC 0x17）。
    ReadQuantity  uint16 `json:"read_quantity"`
    WriteQuantity uint16 `json:"write_quantity"`

    // WriteValue 写单值（FC 0x05/0x06）。
    // FC 0x05：接受 0/1（布尔，planner 在 Plan 阶段映射为 0x0000/0xFF00）或 0xFF00/0x0000。
    // 其他值（如 0x1234）语义非法，除非配 ExceptionCode（任意合法异常码背书）。
    WriteValue uint16 `json:"write_value"`

    // Values 请求数据字段（FC 之后的请求字节，透传）：
    //   FC 0x0F：位打包线圈值，长度必须 = ⌈Quantity/8⌉
    //   FC 0x10/0x17：寄存器值，长度必须 = Quantity*2 / WriteQuantity*2
    //   FC 0x14/0x15：文件记录 item 原样透传；外层 Byte Count = len(Values)
    //     （FC 0x14 请求每 7 字节一个 item：RefType+File+Record+RecLen；FC 0x15 每 item 首字节直接是 Reference Type=0x06，
    //      item = RefType(1)+File(2)+Record(2)+RecLen(2)+Data(2×RL)，总长 7+2×RL，Record Length 位于偏移 5-6，动态步进；
    //      item 内无 Byte Count 字段，修复 R4-C1（回退 R3-C2 的 8+2×RL））
    //     FC 0x14 响应 item 结构见 §3.3.12：File Response Length(1) + RefType(1) + Record Data（修复 R3-C1）
    //   FC 0x2B：MEI 特定数据（Read Device ID Code + Object ID 等）
    //   FC 0x08：诊断子功能数据字段
    //   FC 0x0B/0x0C/0x07/0x11/0x18 等无数据请求 FC 忽略本字段
    Values []byte `json:"values"`

    // ResponseValues 响应数据字段（响应 PDU 中 FC 之后的字节，透传）。
    // 非空时覆盖 planner 的自动响应构造（§4.5）；只作用于响应 PDU，与 Values 完全独立。
    // 与 ExceptionCode 互斥（V-017）。
    ResponseValues []byte `json:"response_values"`

    // SubFunction 子功能（uint16 全宽，修复 R1-M6）：
    //   FC 0x08：诊断子功能 0x0000-0x0015（0x0005-0x0009 保留，0x0014/0x0015 合法，上限 0x0015 修复 R3-H1）
    //   FC 0x2B：取低字节作为 MEI Type（0x0E=Read Device Identification，请求与响应同用 0x0E；0x0D=CANopen General 不实现，修复 R4-H1），
    //     高字节必须为 0（SubFunction=0x010E → Validate 拒绝）
    SubFunction uint16 `json:"sub_function"`

    // MaskAnd/MaskOr FC 0x16 掩码写寄存器专用（AND Mask / OR Mask）。
    MaskAnd uint16 `json:"mask_and"`
    MaskOr  uint16 `json:"mask_or"`

    // ResponseMode 响应模式：
    //   normal（默认）——生成响应包
    //   no_response——不生成响应包（诊断子功能 0x0004 Force Listen Only、广播+SuppressBroadcast 语义）
    ResponseMode string `json:"response_mode"`

    // Direction 已废弃（DEPRECATED，v1.1 起 planner 忽略本字段）。
    Direction string `json:"direction"`

    // SourceAddress/ReadFileItems 等 FC 0x14/0x15 语义字段不单独建模，
    // 由 Values/ResponseValues 字节透传（见 §3.3.12/§3.3.13）。
}
```

**字段使用规则（按 FC）**：

| FC | 使用的字段 | 忽略的字段 |
|----|-----------|-----------|
| 0x01/0x02 | StartingAddress, Quantity | 其余 |
| 0x03/0x04 | StartingAddress, Quantity | 其余 |
| 0x05 | StartingAddress, WriteValue | Quantity |
| 0x06 | StartingAddress, WriteValue | Quantity |
| 0x07 | —（无数据请求） | 全部 |
| 0x08 | SubFunction, Values | 其余 |
| 0x0B/0x0C | —（无数据请求） | 全部 |
| 0x0F | StartingAddress, Quantity, Values | 其余 |
| 0x10 | StartingAddress, Quantity, Values | 其余 |
| 0x11 | —（无数据请求） | 全部 |
| 0x14 | Values（item 透传） | StartingAddress/Quantity |
| 0x15 | Values（item 透传） | StartingAddress/Quantity |
| 0x16 | StartingAddress, MaskAnd, MaskOr | Quantity |
| 0x17 | ReadAddress/StartingAddress, ReadQuantity, WriteAddress, WriteQuantity, Values | **Quantity（IGNORED）** |
| 0x18 | StartingAddress（FIFO Pointer Address） | 其余 |
| 0x2B | SubFunction（低字节→MEI Type）, Values | 其余 |

### §5.3 默认值规则

| 字段 | 空值 | 默认 | 说明 |
|------|------|------|------|
| UnitID | nil | 1 | 0 = 广播（需显式设置，`*uint8` 区分，修复 M2-HIGH-1） |
| SuppressBroadcast | false | false | 默认发广播镜像响应包 |
| Transactions（nil，JSON 字段缺失） | nil | 1 个默认事务 | FC=0x03 读保持寄存器，addr=0, qty=1（修复 M2-MED-4） |
| Transactions（[]，显式空数组） | [] | 仅 TCP 握手+挥手 | 连接探测场景（修复 M2-MED-4） |
| MasterCount | 0 | 1 | 并发 master 数 |
| FlowCount | 0 | 1 | 每 master 流数 |
| SharedTIDSpace | false | false | 默认流内独立 TID 空间 |
| FunctionCode | 0 | 拒绝 | 无默认，必须显式（0 不在支持集） |
| ExceptionCode | 0 | 0 | 0 = 正常响应 |
| StartingAddress | 0 | 0 | 合法（0x0000） |
| Quantity | 0 | 按 FC 拒绝 | FC 0x01-0x04/0x0F/0x10 的 quantity=0 非法（V-006） |
| ReadQuantity/WriteQuantity | 0 | 拒绝 | FC 0x17 必须显式（V-009） |
| WriteValue | 0 | 0（OFF / 0x0000） | FC 0x05 时 0 = OFF |
| SubFunction | 0 | FC 0x2B 时拒绝 | FC 0x2B 必须显式 0x000E（Read Device Identification；0x000D=CANopen General 不实现，修复 R4-H1）（V-013） |
| MaskAnd/MaskOr | 0 | 0 | FC 0x16 合法（0x0000 AND/OR 掩码） |
| ResponseMode | "" | normal | no_response 需显式 |

**位数据默认值规则（修复 M2-MED-1）**：读响应寄存器值（auto-derived，自动推导）默认全 0（zeros of correct length，长度正确的全零字节）。例如 FC 0x01 qty=1 未设 ResponseValues → 响应 PDU `01 01 00`（Byte Count=1，位数据=0x00=所有线圈 OFF）。

---

## §6. 包序列场景（HexDump S1-S15）

### §6.1 场景索引

| # | 场景 | FC | 请求 PDU | 响应 PDU | 关键验证点 |
|---|------|----|---------|---------|-----------|
| S1 | 读线圈 | 0x01 | 5B | 4B | 位打包（qty=10 → Byte Count=2） |
| S2 | 读保持寄存器 | 0x03 | 5B | 8B | 寄存器值 2B BE |
| S3 | 写单线圈 | 0x05 | 5B | 5B（echo） | 0xFF00/0x0000 |
| S4 | 写多寄存器 | 0x10 | 10B | 5B | Byte Count=qty×2 |
| S5 | 写多线圈 | 0x0F | 8B | 5B | 位打包 + Byte Count=⌈qty/8⌉ |
| S6 | 写单寄存器 | 0x06 | 5B | 5B（echo） | 单寄存器值 |
| S7 | 诊断（Return Query Data） | 0x08 | 5B | 5B（echo） | 子功能 0x0000 |
| S8 | 报告从站 ID | 0x11 | 1B | 5B | 响应无 Byte Count，首字节即 Slave ID（修复 R4-H2） |
| S9 | 读写多寄存器 | 0x17 | 16B | 22B | ReadQty/WriteQty 独立字段（修复 R1-C2） |
| S10 | 掩码写寄存器 | 0x16 | 7B | 7B（echo） | AND/OR Mask（修复 R1-C3） |
| S11 | 多会话（2 master） | 0x03 | 5B×2 | 4B×2 | 独立 4-tuple，TID 各自从 0 |
| S12 | 多流（SharedTIDSpace=true） | 0x03 | 5B×2 | 4B×2 | 共享 TID 空间全局递增 |
| S13 | 最大量边界（qty=125） | 0x03 | 5B | 252B | Length=253=0x00FD（修复 R1-C4） |
| S14 | 豁免路径（FC=0x99） | 0x99 | 1B | 2B | `99 01`（0x99\|0x80=0x99，修复 R2-C1） |
| S15 | 多事务序列（3 事务） | 0x01/0x03/0x06 | — | — | TID 递增 0→1→2 |

**Length 核算公式（每场景必验）**：`MBAP Length = 1(Unit ID) + PDU 字节数`（big-endian）。以下所有场景的 Length 均按此公式逐字节核算。

---

### §6.2 S1：读线圈（FC=0x01，qty=10）

**目的**：验证位打包规则（§2.2）与读线圈响应结构。

**配置**：`FunctionCode=0x01, StartingAddress=0x0000, Quantity=10, ResponseValues=[0x03, 0x01]`（10 个线圈：bit0-1 ON，bit2-7 OFF，第 2 字节 bit8 ON）。

**请求（master→slave，TCP payload，7+5=12 字节）**：

```
00 00  00 00  00 06  01  01  00 00  00 0A
├─TID─┤ ├─PID─┤ ├─Len─┤ ├U┤ ├FC┤ ├─addr─┤ ├qty─┤
```
- Transaction ID=0（第 1 个事务），Protocol ID=0x0000，Unit ID=1
- **Length=0x0006 = 1(Unit) + 1(FC) + 2(addr) + 2(qty) = 6** ✓
- PDU=`01 00 00 00 0A`=5 字节

**响应（slave→master，TCP payload，7+4=11 字节）**：

```
00 00  00 00  00 05  01  01  02  03 01
├─TID─┤ ├─PID─┤ ├─Len─┤ ├U┤ ├FC┤ ├BC┤ ├─data─┤
```
- **Length=0x0005 = 1(Unit) + 1(FC) + 1(BC) + 2(位数据) = 5** ✓
- Byte Count=0x02 = ⌈10/8⌉=2 ✓
- 位数据 `03 01`：第 1 字节 bit0-1=1（线圈 0、1 ON），bit2-7=0；第 2 字节 bit0=1（线圈 8 ON），bit1-7=0（补零）✓ 符合 §2.2 低地址字节先 + 字节内 LSB 优先

**验证**：Length=6/5 自洽；Byte Count=⌈qty/8⌉=2；位打包正确。✓

---

### §6.3 S2：读保持寄存器（FC=0x03，qty=3）

**目的**：验证寄存器值 2 字节 big-endian 与响应 Byte Count=qty×2。

**配置**：`FunctionCode=0x03, StartingAddress=0x0000, Quantity=3, ResponseValues=[0x12,0x34, 0x56,0x78, 0x9A,0xBC]`。

**请求（7+5=12 字节）**：

```
00 00  00 00  00 06  01  03  00 00  00 03
```
- **Length=0x0006 = 1+1+2+2 = 6** ✓（PDU=5B）

**响应（7+8=15 字节）**：

```
00 00  00 00  00 09  01  03  06  12 34  56 78  9A BC
```
- **Length=0x0009 = 1(Unit) + 1(FC) + 1(BC) + 6(寄存器值) = 9** ✓
- Byte Count=0x06 = 3×2 ✓
- 寄存器值 2 字节 BE：0x1234、0x5678、0x9ABC ✓

**验证**：Length=9 自洽；Byte Count=qty×2=6；寄存器值 BE。✓

---

### §6.4 S3：写单线圈（FC=0x05）

**目的**：验证写单线圈合法值 0xFF00/0x0000 与 echo 响应。

**配置**：`FunctionCode=0x05, StartingAddress=0x0064, WriteValue=1`（布尔 1，planner Plan 阶段映射为 0xFF00，修复 R1-H2）。

**请求（7+5=12 字节）**：

```
00 00  00 00  00 06  01  05  00 64  FF 00
```
- **Length=0x0006 = 1+1+2+2 = 6** ✓（PDU=5B）
- WriteValue=1 → 0xFF00（ON）✓

**响应（7+5=12 字节，与请求逐字节相同）**：

```
00 00  00 00  00 06  01  05  00 64  FF 00
```
- **Length=0x0006 = 6** ✓（echo）

**验证**：WriteValue 布尔映射；echo 响应；Length 自洽。✓

---

### §6.5 S4：写多寄存器（FC=0x10，qty=2）

**目的**：验证写多寄存器请求 Byte Count=qty×2 与响应回显地址/数量。

**配置**：`FunctionCode=0x10, StartingAddress=0x0014, Quantity=2, Values=[0x11,0x11, 0x22,0x22]`。

**请求（7+10=17 字节）**：

```
00 01  00 00  00 0B  01  10  00 14  00 02  04  11 11  22 22
├TID=1┤ ├PID─┤ ├─Len─┤ ├U┤ ├FC┤ ├─addr─┤ ├qty──┤ ├BC┤ ├─values─┤
```
- Transaction ID=1（第 2 个事务，演示 TID 递增）
- **Length=0x000B = 1+1+2+2+1+4 = 11** ✓（PDU=10B）
- Byte Count=0x04 = 2×2 ✓

**响应（7+5=12 字节）**：

```
00 01  00 00  00 06  01  10  00 14  00 02
```
- **Length=0x0006 = 1+1+2+2 = 6** ✓（PDU=5B）
- Starting Address=0x0014 回显、Quantity=2 回显 ✓

**验证**：Length=11/6 自洽；请求 Byte Count=4；响应回显地址与数量。✓

---

### §6.6 S5：写多线圈（FC=0x0F，qty=10）

**目的**：验证写多线圈位打包 + 请求 Byte Count=⌈qty/8⌉。

**配置**：`FunctionCode=0x0F, StartingAddress=0x0000, Quantity=10, Values=[0x03, 0x01]`。

**请求（7+8=15 字节）**：

```
00 02  00 00  00 09  01  0F  00 00  00 0A  02  03 01
```
- **Length=0x0009 = 1+1+2+2+1+2 = 9** ✓（PDU=8B）
- Byte Count=0x02 = ⌈10/8⌉=2 ✓
- 位数据 `03 01`：与 S1 相同的位打包布局（线圈 0-1 ON、线圈 8 ON）✓

**响应（7+5=12 字节）**：

```
00 02  00 00  00 06  01  0F  00 00  00 0A
```
- **Length=0x0006 = 1+1+2+2 = 6** ✓
- Starting Address / Quantity 回显 ✓

**验证**：Length=9/6 自洽；请求 Byte Count=⌈10/8⌉=2；位打包正确。✓

---

### §6.7 S6：写单寄存器（FC=0x06）

**目的**：验证写单寄存器 echo 响应。

**配置**：`FunctionCode=0x06, StartingAddress=0x0014, WriteValue=0x1234`。

**请求（7+5=12 字节）**：

```
00 03  00 00  00 06  01  06  00 14  12 34
```
- **Length=0x0006 = 1+1+2+2 = 6** ✓

**响应（7+5=12 字节，echo）**：

```
00 03  00 00  00 06  01  06  00 14  12 34
```
- **Length=0x0006 = 6** ✓

**验证**：Length 自洽；echo 响应。✓

---

### §6.8 S7：诊断（FC=0x08，Return Query Data 子功能 0x0000）

**目的**：验证诊断子功能 0x0000 的回显语义（修复 M2-LOW-2）。

**配置**：`FunctionCode=0x08, SubFunction=0x0000, Values=[0xAA, 0xBB]`。

**请求（7+5=12 字节）**：

```
00 04  00 00  00 06  01  08  00 00  AA BB
├TID=4┤ ├─PID─┤ ├─Len─┤ ├U┤ ├FC┤ ├─subfun─┤ ├─data─┤
```
- **Length=0x0006 = 1+1+2+2 = 6** ✓（PDU=5B）
- Sub-Function=0x0000（Return Query Data），Data Field=0xAABB

**响应（7+5=12 字节，回显请求 PDU）**：

```
00 04  00 00  00 06  01  08  00 00  AA BB
```
- **Length=0x0006 = 6** ✓
- 子功能 0x0000 语义：响应与请求逐字节相同（回显）✓

**验证**：Length 自洽；Return Query Data 回显语义。✓

---

### §6.9 S8：报告从站 ID（FC=0x11）

**目的**：验证响应无 Byte Count 字段、首字节即 Slave ID（修复 R4-H2；v2.0.0 起的 M2-CRIT-2 与 R3-M2 两轮修复均误加 Byte Count 字段，tshark 3.6.14 实测 `11 04 01 FF AA BB` 显示 "Data: 0401ffaabb" 无 Byte Count 字段）。

**配置**：`FunctionCode=0x11, ResponseValues=[0x01, 0xFF, 0xAA, 0xBB]`（Slave ID=0x01, Run Indicator=0xFF, Additional=2 字节）。

**请求（7+1=8 字节）**：

```
00 05  00 00  00 02  01  11
```
- **Length=0x0002 = 1(Unit) + 1(FC) = 2** ✓（PDU=1B，仅 FC）

**响应（7+5=12 字节）**：

```
00 05  00 00  00 06  01  11  01  FF  AA BB
├TID=5┤ ├─PID─┤ ├─Len─┤ ├U┤ ├FC┤ ├SI┤ ├RI─┤ ├─Additional─┤
```
- **Length=0x0006 = 1(Unit) + 1(FC) + 1(Slave ID) + 1(Run Indicator) + 2(Additional) = 6** ✓（PDU=5B）
- Slave ID=0x01、Run Indicator=0xFF、Additional=AA BB；**无 Byte Count 字段**（修复 R4-H2：v2.0.3 的 `11 04 01 FF AA BB` 中 0x04 实为 Slave ID 而非 Byte Count）

**验证**：Length=6=1+5；总字节数 12（修复 R4-H2：v2.0.3 曾标注 13）；响应无 Byte Count 字段。✓

---

### §6.10 S9：读写多寄存器（FC=0x17，ReadQty=10, WriteQty=3）

**目的**：验证 FC 0x17 双数量字段（ReadQuantity/WriteQuantity 独立，忽略 Quantity，修复 M2-MED-2）与 Length 核算（修复 R1-C2）。

**配置**：`FunctionCode=0x17, StartingAddress=0x0000（Read Address）, ReadQuantity=10, WriteAddress=0x0014, WriteQuantity=3, Values=[0x11,0x11, 0x22,0x22, 0x33,0x33]`。

**请求（7+16=23 字节）**：

```
00 06  00 00  00 11  01  17  00 00  00 0A  00 14  00 03  06  11 11  22 22  33 33
├TID=6┤ ├─PID─┤ ├─Len─┤ ├U┤ ├FC┤ ├ReadA─┤ ├ReadQ─┤ ├WrAddr┤ ├WrQty─┤ ├BC┤ ├──values──┤
```
- **Length=0x0011 = 1(Unit) + 1(FC) + 2(ReadAddr) + 2(ReadQty) + 2(WriteAddr) + 2(WriteQty) + 1(WriteBC) + 6(寄存器值) = 17** ✓（PDU=16B，修复 R1-C2：v2.0.0 曾误写 0x0012=18）
- Write Byte Count=0x06 = 3×2 ✓

**响应（7+22=29 字节）**：

```
00 06  00 00  00 17  01  17  14  00 01  00 02  00 03  00 04  00 05  00 06  00 07  00 08  00 09  00 0A
```
- **Length=0x0017 = 1(Unit) + 1(FC) + 1(BC) + 20(读寄存器值) = 23** ✓（PDU=22B）
- Byte Count=0x14 = 10×2 = 20 ✓
- 读寄存器值：0x0001-0x000A 共 10 个寄存器 ✓

**验证**：请求 Length=17（修复 R1-C2）；响应 Length=23；双数量字段独立生效。✓

---

### §6.11 S10：掩码写寄存器（FC=0x16）

**目的**：验证 AND/OR Mask 请求结构（修复 R1-C3 的 Length 值）。

**配置**：`FunctionCode=0x16, StartingAddress=0x0000, MaskAnd=0xFFFF, MaskOr=0x0000`。

**请求（7+7=14 字节）**：

```
00 07  00 00  00 08  01  16  00 00  FF FF  00 00
├TID=7┤ ├─PID─┤ ├─Len─┤ ├U┤ ├FC┤ ├─addr─┤ ├─AND──┤ ├─OR───┤
```
- **Length=0x0008 = 1(Unit) + 1(FC) + 2(addr) + 2(AND) + 2(OR) = 8** ✓（PDU=7B，修复 R1-C3：v2.0.0 曾误写 0x0007=7）

**响应（7+7=14 字节，echo）**：

```
00 07  00 00  00 08  01  16  00 00  FF FF  00 00
```
- **Length=0x0008 = 8** ✓

**验证**：Length=8=1+7（修复 R1-C3）；echo 响应；协议语义公式（Cur AND A）OR (O AND ~A) 仅为语义参考，wire 行为是 echo（§3.3.14）。✓

---

### §6.12 S11：多会话（2 个并发 master）

**目的**：验证多会话（多 master）场景——每个 master 独立 4-tuple（独立 TCP 流），TID 空间各自独立从 0 开始（修复 M2-HIGH-1 的 TID 语义）。

**配置**：`MasterCount=2, SharedTIDSpace=false`，每 master 1 个事务（FC=0x03 读 1 寄存器）。

**master 1 流（4-tuple A，TID 从 0 开始）**：

```
请求：00 00  00 00  00 06  01  03  00 00  00 01     Length=6 = 1+1+2+2 ✓
响应：00 00  00 00  00 05  01  03  02  12 34        Length=5 = 1+1+1+2 ✓
```

**master 2 流（4-tuple B，TID 从 0 开始）**：

```
请求：00 00  00 00  00 06  01  03  00 00  00 01     Length=6 ✓
响应：00 00  00 00  00 05  01  03  02  56 78        Length=5 ✓
```

**验证**：
- 两个 master 的 TCP 流 4-tuple 不同（SrcPort 由流分配器分配，互不相等）✓
- 两流 TID 各自从 0 开始，**可并发复用相同 TID 值**（流内唯一，跨流复用）✓
- 响应寄存器值不同（0x1234 vs 0x5678，由各自 ResponseValues 决定）✓

---

### §6.13 S12：多流共享 TID 空间（SharedTIDSpace=true）

**目的**：验证 `SharedTIDSpace=true` 时多流共享连续 TID 空间，TID 跨流全局递增（§4.2）。

**配置**：`MasterCount=2, SharedTIDSpace=true`，每 master 1 个事务（FC=0x03 读 1 寄存器）。

**流 1 请求（TID=0）**：

```
请求：00 00  00 00  00 06  01  03  00 00  00 01     Length=6 ✓
响应：00 00  00 00  00 05  01  03  02  12 34        Length=5 ✓
```

**流 2 请求（TID=1，全局递增）**：

```
请求：00 01  00 00  00 06  01  03  00 00  00 01     Length=6 ✓
响应：00 01  00 00  00 05  01  03  02  56 78        Length=5 ✓
```

**验证**：SharedTIDSpace=true 时跨流 TID 连续（流 1 TID=0 → 流 2 TID=1），整个多流集合内 TID 唯一（区别于 S11 的跨流复用）；回绕规则仍按 `TID = (N-1) mod 65536` 全局应用。✓

---

### §6.14 S13：最大量边界（FC=0x03，qty=125）

**目的**：验证 FC 0x03 最大量边界（quantity=125 是规范上限），MBAP Length=253 逼近 Length 上限 254（修复 R1-C4 的 Length 值；R2-M3 的边界语义）。

**配置**：`FunctionCode=0x03, StartingAddress=0x0000, Quantity=125`（ResponseValues 缺省 → 全 0）。

**请求（7+5=12 字节）**：

```
00 08  00 00  00 06  01  03  00 00  00 7D
```
- **Length=0x0006 = 1+1+2+2 = 6** ✓
- Quantity=0x007D=125（FC 0x03 规范上限）✓

**响应（7+252=259 字节）**：

```
00 08  00 00  00 FD  01  03  FA  <250 字节寄存器值（全 0）>
```
- **Length=0x00FD = 1(Unit) + 1(FC) + 1(Byte Count) + 250(寄存器值) = 253** ✓（PDU=252B，修复 R1-C4：v2.0.0 曾误写 0x00FA=250）
- Byte Count=0xFA=250 = 125×2 ✓
- PDU=252 ≤ 253（PDU 上限）合法；Length=253 ≤ 254（Length 上限）合法；MBAP+PDU 总长 259 < 260 ✓

**边界语义（修复 R2-M3）**：PDU=252 恰好是 FC 0x03 能达到的最大值（qty=125 上限）；PDU=253 理论上由其他 FC 可达（如 FC 0x14 长文件记录），本场景验证 252→253 的跳变合法且为上限值。**PDU=253 合法 / PDU=254 非法**的边界断言见 T-007（补充断言）。

**验证**：Length=253=0x00FD（修复 R1-C4）；总长 259<260；qty=125 上限合法。✓

---

### §6.15 S14：豁免路径（FC=0x99 + ExceptionCode=0x01）

**目的**：验证 §1.3 豁免规则——FC 不在支持集（0x99）+ ExceptionCode≠0 → 请求按用户字节透传，响应 = FC|0x80 + ExceptionCode（修复 R1-H1/R2-C1）。

**配置**：`FunctionCode=0x99, ExceptionCode=0x01`。

**请求（7+1=8 字节）**：

```
00 09  00 00  00 02  01  99
```
- **Length=0x0002 = 1(Unit) + 1(FC) = 2** ✓（PDU=1B，仅 FC，无数据时逐字节透传）

**响应（7+2=9 字节）**：

```
00 09  00 00  00 03  01  99  01
├TID=9┤ ├─PID─┤ ├─Len─┤ ├U┤ ├FC┤ ├EXC─┤
```
- **Length=0x0003 = 1(Unit) + 1(FC) + 1(Exception Code) = 3** ✓（PDU=2B）
- **功能码 = 0x99 | 0x80 = 0x99**（0x99 的 bit7 已置位，OR 幂等不变；**不是 0x19**，修复 R2-C1：v2.0.1 曾误写 `19 01`）
- 对照：T-025 的 FC=0x41 | 0x80 = 0xC1（0x41 bit7 未置位，正常叠加）——两例自洽 ✓

**验证**：豁免路径生效；异常响应功能码 = 原码|0x80 幂等语义（bit7 已置位时结果等于原码）；Length=3。✓

---

### §6.16 S15：多事务序列（3 事务，TID 递增）

**目的**：验证单 TCP 流多事务序列：TID 单调递增（第 N 个事务 TID=N-1），请求/响应共享 TID（§4.2）。

**配置**：`Transactions=[{FC=0x01, addr=0, qty=10}, {FC=0x03, addr=0, qty=1}, {FC=0x06, addr=0x0014, value=0x1234}]`。

**事务 1（TID=0）— FC 0x01 读线圈**：

```
请求：00 00  00 00  00 06  01  01  00 00  00 0A     Length=6 = 1+1+2+2 ✓
响应：00 00  00 00  00 05  01  01  02  03 01        Length=5 = 1+1+1+2 ✓
```

**事务 2（TID=1）— FC 0x03 读保持寄存器**：

```
请求：00 01  00 00  00 06  01  03  00 00  00 01     Length=6 ✓
响应：00 01  00 00  00 05  01  03  02  12 34        Length=5 ✓
```

**事务 3（TID=2）— FC 0x06 写单寄存器**：

```
请求：00 02  00 00  00 06  01  06  00 14  12 34     Length=6 ✓
响应：00 02  00 00  00 06  01  06  00 14  12 34     Length=6 ✓（echo）
```

**验证**：
- TID 序列：0, 0, 1, 1, 2, 2（请求/响应共享 TID，事务间 +1）✓
- 全部 Length 自洽（6/5/6/5/6/6）✓
- 事务按配置数组顺序串行执行，无状态依赖（Modbus 无状态特性）✓
- 回绕验证（65536/65537/65538 事务的 TID 0/1/2）见 T-040/T-098 ✓

---

## §7. 测试用例（T-001 ~ T-205 + R4 追加 13 条）

### §7.1 测试用例分组

| 分组 | 编号范围 | 数量 | 说明 |
|------|----------|------|------|
| 正向（成功路径） | T-001 ~ T-080 | 80 | 19 个 FC 全覆盖 + 多场景 |
| 负向（Validate 拒绝） | T-081 ~ T-120 | 40 | 非法配置被 Validate 拒绝 |
| 边界 | T-121 ~ T-160 | 40 | 数量上下限/地址边界/Unit ID/TID 回绕 |
| 多会话/多流 | T-161 ~ T-180 | 20 | 并发与 TID 共享 |
| 集成（wire-format） | T-181 ~ T-200 | 20 | tshark 解析验证（§7.7 以 tshark 为最终裁判） |
| 修订追加（v2.0.2） | T-201 ~ T-205 | 5 | R2 复审修复验证 |
| 修订追加（v2.0.4） | T-095b~T-095l/T-117b/T-119b | 13 | R4 复审修复验证（广播负向参数化 11 条 + MEI 0x000F 拒绝 + FC 0x18 长度自洽，修复 R4-M3/R4-H1/R4-H4） |
| **合计** | — | **218** | |

---

### §7.2 正向用例（T-001 ~ T-080）

| # | 名称 | 输入 | 期望输出 | 断言点 |
|---|------|------|----------|--------|
| T-001 | FC=0x01 读线圈基础 | FC=0x01, addr=0, qty=10, RV=[0x03,0x01] | 请求 `01 0000 000A`，响应 `01 02 03 01` | bytes PDU 匹配 |
| T-002 | FC=0x01 位打包 qty=8 | qty=8, RV=[0xFF] | Byte Count=1, 位数据=0xFF | bytes[1]=0x01, bytes[2]=0xFF |
| T-003 | FC=0x01 qty=2000 上限 | qty=2000 | Byte Count=250 | Byte Count=0xFA |
| T-004 | FC=0x02 读离散输入 | FC=0x02, addr=0, qty=1, RV=[0x01] | 请求 `02 0000 0001`，响应 `02 01 01` | bytes 匹配 |
| T-005 | FC=0x03 读保持寄存器基础 | FC=0x03, addr=0, qty=3, RV=[0x12,0x34,...] | 请求 `03 0000 0003`，响应 `03 06 1234 5678 9ABC` | bytes 匹配 |
| T-006 | FC=0x03 默认全 0 响应 | qty=2, RV 缺省 | 响应 `03 04 0000 0000` | 位数据=0x00 |
| T-007 | FC=0x03 qty=125 上限（含 Length 边界断言） | qty=125, RV 缺省 | 响应 Byte Count=0xFA=250, **Length=0x00FD=253, PDU=252B（合法上限，修复 R2-M3）** | Length 字段=0x00FD |
| T-008 | FC=0x04 读输入寄存器 | FC=0x04, addr=0, qty=1, RV=[0xAB,0xCD] | 请求 `04 0000 0001`，响应 `04 02 ABCD` | bytes 匹配 |
| T-009 | FC=0x05 写单线圈 ON | addr=0x0064, WriteValue=0xFF00 | 请求 `05 0064 FF00` | bytes=`FF 00` |
| T-010 | FC=0x05 写单线圈 OFF | addr=0x0064, WriteValue=0x0000 | 请求 `05 0064 0000` | bytes=`00 00` |
| T-011 | FC=0x05 WriteValue=1 布尔映射 | WriteValue=1 | 请求 `05 0064 FF00`（planner 映射 1→0xFF00，修复 R1-H2） | bytes=`FF 00` |
| T-012 | FC=0x05 WriteValue=0 布尔映射 | WriteValue=0 | 请求 `05 0064 0000`（0→0x0000） | bytes=`00 00` |
| T-013 | FC=0x05 echo 响应 | 同 T-009 | 响应与请求逐字节相同 | response == request |
| T-014 | FC=0x06 写单寄存器 | addr=0x0014, WriteValue=0x1234 | 请求 `06 0014 1234` | bytes 匹配 |
| T-015 | FC=0x06 echo 响应 | 同 T-014 | 响应回显 | response == request |
| T-016 | FC=0x07 读异常状态 | FC=0x07, RV=[0xFF] | 请求 `07`，响应 `07 FF` | PDU 长度=1（请求）, 2（响应） |
| T-017 | FC=0x07 异常状态全 0 | RV 缺省 | 响应 `07 00` | bytes[1]=0x00 |
| T-018 | FC=0x08 诊断 Return Query Data | SubFunction=0x0000, Values=[0xAA,0xBB] | 请求 `08 0000 AABB`，响应回显（修复 M2-LOW-2） | response PDU == request PDU |
| T-019 | FC=0x11 报告从站 ID（修复 R4-H2：删除 Byte Count 字段，首字节即 Slave ID） | RV=[0x01,0xFF,0xAA,0xBB]（SlaveID=0x01, RunInd=0xFF, Additional=AA BB） | 请求 `11`，响应 `11 01 FF AA BB`（无 Byte Count，首字节 Slave ID=0x01，修复 R4-H2） | bytes PDU=`11 01 FF AA BB`, Length=6 |
| T-020 | FC=0x14 读文件记录（修复 R3-C1：File Response Length 语义） | 1 item: File=1, Record=0, RecLen=2; RV=[0x06,0x05,0x06,0x12,0x34,0x56,0x78]（外层 Byte Count=0x06 + item 6 字节，ResponseValues 含外层 BC，见 §8.4 表头） | 请求 `14 06 06 0001 0000 0002`（Byte Count=6=1×item7B），响应 `14 06 05 06 1234 5678`（外层 Byte Count=6，item=File Response Length=0x05=1+2×2 + RefType=0x06 + Record Data=4B） | bytes PDU=`14 06 05 06 1234 5678` |
| T-021 | FC=0x15 写文件记录（修复 R4-C1：回退 R3-C2，item 首字节为 Reference Type 而非 Byte Count） | 1 item: File=1, Record=0, RecLen=2, Data=0x1234 0x5678; Values=`0B 06 0001 0000 0002 1234 5678`（外层 Byte Count=0x0B=11=7+2×2=item 总长，item 首字节=Reference Type=0x06） | 请求 `15 0B 06 0001 0000 0002 1234 5678`（PDU=13 字节、MBAP Length=14=0x000E，修复 R4-C1），响应 echo | bytes PDU=`15 0B 06 ...`（tshark 无 Malformed，修复 R4-C1） |
| T-022 | FC=0x15 多 item | 2 items, RecLen=1+1（item 总长各 7+2×1=9 字节，首字节均为 Reference Type=0x06，修复 R4-C1） | 请求 PDU 含两 item（外层 Byte Count=9+9=18=0x12） | 步进按 RecLen 动态（修复 R1-M1/R4-C1） |
| T-023 | FC=0x16 掩码写寄存器 | addr=0, MaskAnd=0xFFFF, MaskOr=0x0000 | 请求 `16 0000 FFFF 0000`（Length=8=1+7，修复 R1-C3） | Length=0x0008 |
| T-024 | FC=0x16 公式语义（文档级） | A=0x00FF, O=0x0001, Cur=0x1234 | 公式 (Cur AND A) OR (O AND ~A) = 0x0034（修复 R1-C6，§3.3.14 明确"实现不执行该公式"，此处仅文档验证） | 公式手算=0x0034 |
| T-025 | FC=0x2B Read Device Identification 完整响应（修复 R4-H1：MEI Type 0x0E，0x0D 为 CANopen 不实现） | MEI=0x0E, Code=0x01, Conformity=0x01, More=0x00, Next=0x00, Count=1, Obj={ID=0x00, Len=4, Val="ABCD"} | 请求 `2B 0E 01 00`，响应 `2B 0E 01 01 00 00 01 00 04 41 42 43 44`（请求与响应同用 MEI Type 0x0E，修复 R4-H1） | bytes PDU 匹配完整结构 |
| T-026 | FC=0x2B MEI Type=0x0D 拒绝（修复 R4-H1：0x0D=CANopen General，CiA 309，本设计不实现） | SubFunction=0x000D（0x0D=CANopen，非 Read Device Identification） | Validate 拒绝（0x0D 不再是合法 MEI Type，修复 R4-H1；v2.0.3 曾误认"0x0D=请求"并接受，实际生成 Wireshark 视为 CANopen 的报文） | error 含 "FC 0x2B sub_function must be 0x000E" |
| T-027 | FC=0x17 读写多寄存器 | ReadAddr=0, ReadQty=10, WriteAddr=0x0014, WriteQty=3, Values=6B | 请求 `17 0000 000A 0014 0003 06 ...`（Length=17=1+16，修复 R1-C2） | Length=0x0011 |
| T-028 | FC=0x17 响应 Byte Count=ReadQty×2 | ReadQty=10 | 响应 BC=0x14=20 | bytes[1]=0x14 |
| T-029 | FC=0x18 读 FIFO 队列 | addr=0, RV=[0x00,0x02, 0x00,0x01, 0x00,0x02]（FIFO Count=2, Values=0x0001 0x0002） | 请求 `18 0000`，响应 `18 0006 0002 0001 0002`（Byte Count 2B=0x0006, FIFO Count=0x0002） | bytes PDU 匹配 |
| T-030 | FC=0x18 FIFO Count=31 上限 | RV 含 31 个寄存器 | FIFO Count=0x001F | FIFO Count=31（修复 M2-MED-3） |
| T-031 | FC=0x01 异常响应 0x01 | ExceptionCode=0x01 | 响应 `81 01` | FC=0x01\|0x80=0x81 |
| T-032 | FC=0x03 异常响应 0x02（修复 R3-L1：请求 PDU 正常构造） | ExceptionCode=0x02, addr=0, qty=1 | 请求 `03 0000 0001`（支持集内 FC 配 ExceptionCode 时请求 PDU 仍按 FC 0x03 正常构造，修复 R3-L1），响应 `83 02` | 请求 PDU=`03 0000 0001`，响应 FC=0x03\|0x80=0x83 |
| T-033 | FC=0x05 异常响应 0x03 | ExceptionCode=0x03 | 响应 `85 03` | FC=0x05\|0x80=0x85 |
| T-034 | FC=0x10 异常响应 0x04 | ExceptionCode=0x04 | 响应 `90 04` | FC=0x10\|0x80=0x90 |
| T-035 | 异常码 0x05 Acknowledge | ExceptionCode=0x05 | 响应 `XX 05` | exc_code=0x05 |
| T-036 | 异常码 0x06 Slave Busy | ExceptionCode=0x06 | 响应 `XX 06` | exc_code=0x06 |
| T-037 | 异常码 0x07 Negative Acknowledge（修复 M2-HIGH-4） | ExceptionCode=0x07 | 响应 `XX 07` | exc_code=0x07（合法码） |
| T-038 | 异常码 0x08 Memory Parity | ExceptionCode=0x08 | 响应 `XX 08` | exc_code=0x08 |
| T-039 | 异常码 0x0A Gateway Path | ExceptionCode=0x0A | 响应 `XX 0A` | exc_code=0x0A |
| T-040 | 异常码 0x0B Gateway Target | ExceptionCode=0x0B | 响应 `XX 0B` | exc_code=0x0B |
| T-041 | Transaction ID 第 1 个 = 0 | 1 个事务 | TID=0x0000 | bytes TID=0 |
| T-042 | Transaction ID 第 2 个 = 1 | 2 个事务 | 第 2 个 TID=0x0001 | bytes TID=1 |
| T-043 | Transaction ID 回绕 65537 事务 | 65537 事务 | 第 65536 个 TID=0xFFFF，第 65537 个 TID=0x0000 | TID 序列正确 |
| T-044 | Transaction ID 回绕 65538 事务（修复 M2-LOW-3） | 65538 事务 | 第 65537 个 TID=0，第 65538 个 TID=1 | 第 65538 个 TID=0x0001 |
| T-045 | Unit ID=1 默认 | UnitID=nil | Unit ID=1 | bytes Unit=0x01 |
| T-046 | Unit ID=247 上限 | UnitID=247 | Unit ID=0xF7 | bytes Unit=0xF7 |
| T-047 | Unit ID=0 广播（修复 M2-HIGH-1） | UnitID=0（*uint8 显式 0）, FC=0x05 写功能码 | Unit ID=0 | bytes Unit=0x00 |
| T-048 | Unit ID=0 广播镜像响应 | UnitID=0, FC=0x05, SuppressBroadcast=false | 生成响应包（traffic-mirror） | response 包存在 |
| T-049 | Unit ID=0 广播抑制响应 | UnitID=0, FC=0x05, SuppressBroadcast=true | 不生成响应包 | response 包不存在 |
| T-050 | Unit ID=0 广播 + 异常响应抑制（修复 R1-M4） | UnitID=0, FC=0x05, ExcCode=0x04, SuppressBroadcast=true | 不生成异常响应包 | response 包不存在 |
| T-051 | FC=0x01 位打包字节内 LSB | qty=10, RV=[0x01,0x00] | 第 1 字节 bit0=1，其余 OFF | bytes[2]=0x01 |
| T-052 | FC=0x10 写多寄存器基础 | FC=0x10, addr=0, qty=2, Values=[0x11,0x11,0x22,0x22] | 请求 `10 0000 0002 04 1111 2222` | Byte Count=0x04 |
| T-053 | FC=0x0F 写多线圈基础 | FC=0x0F, addr=0, qty=10, Values=[0x03,0x01] | 请求 `0F 0000 000A 02 03 01` | Byte Count=0x02 |
| T-054 | FC=0x0B 取通信事件计数器 | RV=[0xFF,0xFF, 0x00,0x64]（Status=0xFFFF, EventCount=100） | 请求 `0B`，响应 `0B FFFF 0064`（修复 M2-HIGH-2） | bytes PDU=`0B FFFF 0064` |
| T-055 | FC=0x0C 取通信事件日志（修复 R3-H2：字段顺序规范化） | RV=[0x0A, 0xFF,0xFF, 0x00,0x64, 0x00,0x0A, 0x01,0x02,0x03,0x04]（BC=10, Status=0xFFFF, EventCount=100=0x0064, MessageCount=10=0x000A, Events=4B） | 请求 `0C`，响应 `0C 0A FFFF 0064 000A 01 02 03 04`（Byte Count=0x0A=10=2+2+2+4；字段顺序 Status→EventCount→MessageCount，修复 R3-H2） | bytes[1]=0x0A |
| T-056 | FC=0x0C Events 长度与 EventCount 解耦 | EventCount=100, Events=4B | Events 长度=4（与 EventCount 值解耦） | Events 字段=4B |
| T-057 | FC=0x14 多 item | 2 items, RecLen=2+2 | 请求 PDU 含 2 item | Byte Count=14=2×7 |
| T-058 | FC=0x15 echo 含 Record Data | 1 item, RecLen=2 | 响应 PDU 含完整 Record Data | response == request |
| T-059 | FC=0x16 echo 响应 | 同 T-023 | 响应回显 | response == request |
| T-060 | FC=0x17 WriteAddress 显式 | ReadAddr=0, ReadQty=10, WriteAddr=20, WriteQty=3 | 请求含 WriteAddr=0x0014 | bytes WriteAddr=0x0014 |
| T-061 | FC=0x17 默认全 0 响应 | ReadQty=2, RV 缺省 | 响应 `17 04 0000 0000` | bytes 数据=全 0 |
| T-062 | FC=0x18 FIFO Count=0 | RV=[0x00,0x00, 0x00,0x00]（BC=2, FIFO Count=0） | 响应 `18 0002 0000`（值字节数=0=2×0，自洽，修复 R4-H4） | FIFO Count=0 |
| T-063 | FC=0x08 子功能 0x0001 Restart Communications | SubFunction=0x0001, Values=[0xFF,0x00] | 请求 `08 0001 FF00` | SubFunction=0x0001 |
| T-064 | FC=0x08 子功能 0x0013 合法（修复 R3-H1 改注） | SubFunction=0x0013 | 请求 `08 0013 ...` | SubFunction=0x0013（接受） |
| T-065 | FC=0x2B Conformity Level=0x81 | Conformity=0x81（Basic + Private） | 响应 Conformity=0x81 | bytes Conformity=0x81 |
| T-066 | FC=0x2B More Follows=0xFF | More Follows=0xFF | 响应 More Follows=0xFF | bytes More Follows=0xFF |
| T-067 | FC=0x2B 多对象 | Count=3, 3 个 Obj | 响应含 3 个 Object 三元组 | Object Count=3 |
| T-068 | FC=0x2B Next Object ID | More Follows=0xFF, Next=0x05 | 响应 Next Object ID=0x05 | bytes Next=0x05 |
| T-069 | FC=0x05 写单线圈 ON 响应 echo | WriteValue=0xFF00 | 响应 `05 0064 FF00` | response==request |
| T-070 | FC=0x06 WriteValue 边界 0xFFFF | WriteValue=0xFFFF | 请求 `06 XXXX FFFF` | bytes value=`FF FF` |
| T-071 | FC=0x03 Starting Address 边界 0xFFFF | addr=0xFFFF | 请求 `03 FFFF 0001` | bytes addr=`FF FF` |
| T-072 | FC=0x01 Starting Address 边界 0x0000 | addr=0x0000 | 请求 `01 0000 0001` | bytes addr=`00 00` |
| T-073 | Unit ID=128 中值 | UnitID=128 | Unit ID=0x80 | bytes Unit=0x80 |
| T-074 | Transactions=nil 默认 1 事务 | Transactions 字段缺失 | 1 个 FC=0x03 默认事务 | 1 个请求包 |
| T-075 | Transactions=[] 仅握手+挥手 | Transactions 显式空数组 | 仅 TCP 握手 + 挥手 | 0 个 Modbus 请求包 |
| T-076 | Direction 字段已废弃 | Direction="up" | planner 忽略 Direction | 行为同未设 |
| T-077 | ResponseMode=normal 默认 | ResponseMode 缺省 | 生成响应包 | response 包存在 |
| T-078 | ResponseMode=no_response | ResponseMode="no_response" | 不生成响应包 | response 包不存在 |
| T-079 | FC=0x17 Quantity 字段被忽略 | FC=0x17, Quantity=999, ReadQty=10, WriteQty=3 | Quantity 不影响报文 | 报文同 T-027 |
| T-080 | FC=0x11 Additional Data 可空（修复 R4-H2） | RV=[0x01, 0xFF]（SlaveID=1, RunInd=0xFF, 无 Additional） | 响应 `11 01 FF`（无 Byte Count，首字节 Slave ID=0x01） | bytes PDU=`11 01 FF` |

### §7.3 负向用例（T-081 ~ T-120，验证 Validate 拒绝）

| # | 名称 | 输入 | 期望 | 断言点 |
|---|------|------|------|--------|
| T-081 | FC 不在支持集 + ExcCode=0 | FC=0x99, ExcCode=0 | Validate 拒绝 | error 含 "unsupported function code 0x99" |
| T-082 | FC 高位已置位 | FC=0x83（支持集内 FC + 0x80） | Validate 拒绝 | error 含 "function code high bit must not be set" |
| T-083 | FC=0x09 不支持 | FC=0x09 | Validate 拒绝 | error 含 "unsupported function code" |
| T-084 | FC=0x0A 不支持 | FC=0x0A | Validate 拒绝 | error 含 "unsupported function code" |
| T-085 | FC=0x0D 不支持 | FC=0x0D | Validate 拒绝 | error 含 "unsupported function code" |
| T-086 | FC=0x12 保留码 | FC=0x12 | Validate 拒绝 | error 含 "unsupported function code" |
| T-087 | FC=0x13 保留码 | FC=0x13 | Validate 拒绝 | error 含 "unsupported function code" |
| T-088 | FC=0x19-0x2A 范围 | FC=0x20 | Validate 拒绝 | error 含 "unsupported function code" |
| T-089 | 异常码 0x00 视为未设置（修复 R4-L3：归入正向语义并澄清与 §2.5 的关系） | ExcCode=0x00（与正常响应无区别） | 接受（0x00 在配置层视为"未设置异常"，V-122 允许，**不报错**；与异常响应无关，§2.5 已同步澄清，修复 R4-L3） | 不报错 |
| T-090 | 异常码 0x09 非法 | ExcCode=0x09 | Validate 拒绝 | error 含 "invalid exception code 0x09" |
| T-091 | 异常码 0x0C 非法 | ExcCode=0x0C | Validate 拒绝 | error 含 "invalid exception code" |
| T-092 | 异常码 0xFF 非法 | ExcCode=0xFF | Validate 拒绝 | error 含 "invalid exception code" |
| T-093 | ExcCode 与 ResponseValues 互斥 | ExcCode=0x01, RV=[0x00] | Validate 拒绝 | error 含 "exception_code and response_values are mutually exclusive" |
| T-094 | UnitID=0 广播 + 读功能码 | UnitID=0, FC=0x01（读） | Validate 拒绝 | error 含 "broadcast (unit_id=0) is only valid for write function codes"（修复 R1-M4） |
| T-095 | UnitID=0 广播 + FC=0x17 读写混合 | UnitID=0, FC=0x17 | Validate 拒绝 | error 含 "broadcast" |
| T-095b | 广播 + FC=0x02 读离散输入拒绝 | UnitID=0, FC=0x02 | Validate 拒绝 | error 含 "broadcast" |
| T-095c | 广播 + FC=0x03 读保持寄存器拒绝 | UnitID=0, FC=0x03 | Validate 拒绝 | error 含 "broadcast" |
| T-095d | 广播 + FC=0x04 读输入寄存器拒绝 | UnitID=0, FC=0x04 | Validate 拒绝 | error 含 "broadcast" |
| T-095e | 广播 + FC=0x07 读异常状态拒绝 | UnitID=0, FC=0x07 | Validate 拒绝 | error 含 "broadcast" |
| T-095f | 广播 + FC=0x08 诊断拒绝 | UnitID=0, FC=0x08 | Validate 拒绝 | error 含 "broadcast" |
| T-095g | 广播 + FC=0x0B 取事件计数拒绝 | UnitID=0, FC=0x0B | Validate 拒绝 | error 含 "broadcast" |
| T-095h | 广播 + FC=0x0C 取事件日志拒绝 | UnitID=0, FC=0x0C | Validate 拒绝 | error 含 "broadcast" |
| T-095i | 广播 + FC=0x11 报告 ID 拒绝 | UnitID=0, FC=0x11 | Validate 拒绝 | error 含 "broadcast" |
| T-095j | 广播 + FC=0x14 读文件记录拒绝 | UnitID=0, FC=0x14 | Validate 拒绝 | error 含 "broadcast" |
| T-095k | 广播 + FC=0x18 读 FIFO 拒绝 | UnitID=0, FC=0x18 | Validate 拒绝 | error 含 "broadcast" |
| T-095l | 广播 + FC=0x2B MEI 拒绝 | UnitID=0, FC=0x2B | Validate 拒绝 | error 含 "broadcast" |
| T-096 | UnitID=248 保留 | UnitID=248 | Validate 拒绝 | error 含 "unit_id 248 is reserved" |
| T-097 | UnitID=255 保留 | UnitID=255 | Validate 拒绝 | error 含 "unit_id 255 is reserved" |
| T-098 | FC=0x01 qty=0 | FC=0x01, qty=0 | Validate 拒绝 | error 含 "quantity must be 1-2000" |
| T-099 | FC=0x01 qty=2001 超上限 | FC=0x01, qty=2001 | Validate 拒绝 | error 含 "quantity must be 1-2000" |
| T-100 | FC=0x03 qty=0 | FC=0x03, qty=0 | Validate 拒绝 | error 含 "quantity must be 1-125" |
| T-101 | FC=0x03 qty=126 超上限 | FC=0x03, qty=126 | Validate 拒绝 | error 含 "quantity must be 1-125" |
| T-102 | FC=0x0F qty=1969 超上限 | FC=0x0F, qty=1969 | Validate 拒绝 | error 含 "quantity must be 1-1968" |
| T-103 | FC=0x10 qty=124 超上限 | FC=0x10, qty=124 | Validate 拒绝 | error 含 "quantity must be 1-123" |
| T-104 | FC=0x17 ReadQty=0 | FC=0x17, ReadQty=0 | Validate 拒绝 | error 含 "read_quantity must be explicit" |
| T-105 | FC=0x17 WriteQty=0 | FC=0x17, WriteQty=0 | Validate 拒绝 | error 含 "write_quantity must be explicit" |
| T-106 | FC=0x17 ReadQty=126 | FC=0x17, ReadQty=126 | Validate 拒绝 | error 含 "read_quantity must be 1-125" |
| T-107 | FC=0x17 WriteQty=122 | FC=0x17, WriteQty=122 | Validate 拒绝 | error 含 "write_quantity must be 1-121" |
| T-108 | FC=0x0F Values 长度不匹配 | FC=0x0F, qty=8, Values=2B（应=1B） | Validate 拒绝 | error 含 "values length must be ceil(quantity/8)"（修复 R1-M2） |
| T-109 | FC=0x10 Values 长度不匹配 | FC=0x10, qty=2, Values=3B（应=4B） | Validate 拒绝 | error 含 "values length must be quantity*2" |
| T-110 | FC=0x17 Values 长度不匹配 | FC=0x17, WriteQty=3, Values=5B（应=6B） | Validate 拒绝 | error 含 "values length must be write_quantity*2"（修复 R1-M2） |
| T-111 | FC=0x05 WriteValue 语义非法 | FC=0x05, WriteValue=0x1234, ExcCode=0 | Validate 拒绝 | error 含 "write_value must be 0/1/0xFF00/0x0000 or set exception_code" |
| T-112 | FC=0x18 FIFO Count=32 超上限 | FC=0x18, RV 含 FIFO Count=32 | Validate 拒绝 | error 含 "FIFO count exceeds 31"（修复 M2-MED-3） |
| T-113 | FC=0x08 SubFunction=0x0016 超上限（修复 R3-H1） | FC=0x08, SubFunction=0x0016 | Validate 拒绝 | error 含 "sub_function must be 0x0000-0x0015" |
| T-114 | FC=0x08 SubFunction=0x0005 保留 | FC=0x08, SubFunction=0x0005 | Validate 拒绝 | error 含 "sub_function 0x0005-0x0009 reserved" |
| T-115 | FC=0x2B SubFunction 高字节非 0 | FC=0x2B, SubFunction=0x010E | Validate 拒绝 | error 含 "FC 0x2B sub_function high byte must be 0"（修复 R1-M6） |
| T-116 | FC=0x2B SubFunction=0x00（无 MEI Type） | FC=0x2B, SubFunction=0x0000 | Validate 拒绝 | error 含 "FC 0x2B sub_function must be 0x000E" |
| T-117 | FC=0x2B SubFunction=0x000D（CANopen，不实现） | FC=0x2B, SubFunction=0x000D | Validate 拒绝 | error 含 "FC 0x2B sub_function must be 0x000E"（修复 R4-H1：0x0D=CANopen General，CiA 309，不再接受） |
| T-117b | FC=0x2B SubFunction=0x000F（非 0x0E） | FC=0x2B, SubFunction=0x000F | Validate 拒绝 | error 含 "FC 0x2B sub_function must be 0x000E" |
| T-118 | FC=0x14 item Record Length=0 | FC=0x14, item RecLen=0 | Validate 拒绝 | error 含 "record length must be >= 1"（修复 R2-M5） |
| T-119 | FC=0x15 item 步进异常 | FC=0x15, 2 items 中第二个 item 起始位置与 RecLen 步进不一致（item 总长=7+2×RL，修复 R4-C1） | Validate 拒绝 | error 含 "item length mismatch"（修复 R1-M1） |
| T-119b | FC=0x18 FIFO Count 与值字节数不自洽 | FC=0x18, RV 中 FIFO Count=2 但值仅 2 字节（应 4 字节） | Validate 拒绝 | error 含 "response_values length must match FIFO count"（修复 R4-H4） |
| T-120 | Protocol ID 非 0（wire 层） | 手工构造 PID=0x0001 | builder 拒绝 | error 含 "protocol_id must be 0x0000" |

### §7.4 边界用例（T-121 ~ T-160）

| # | 名称 | 输入 | 期望 | 断言点 |
|---|------|------|------|--------|
| T-121 | FC=0x01 qty=1 最小 | qty=1 | Byte Count=1 | bytes BC=0x01 |
| T-122 | FC=0x01 qty=2000 最大 | qty=2000 | Byte Count=250 | bytes BC=0xFA |
| T-123 | FC=0x03 qty=1 最小 | qty=1 | Byte Count=2 | bytes BC=0x02 |
| T-124 | FC=0x03 qty=125 最大（含 PDU 边界断言） | qty=125 | Byte Count=250, **Length=253, PDU=252B 合法上限** | Length=0x00FD（修复 R2-M3） |
| T-125 | FC=0x0F qty=1 最小 | qty=1 | Byte Count=1 | bytes BC=0x01 |
| T-126 | FC=0x0F qty=1968 最大 | qty=1968 | Byte Count=246 | bytes BC=0xF6 |
| T-127 | FC=0x10 qty=1 最小 | qty=1 | Byte Count=2 | bytes BC=0x02 |
| T-128 | FC=0x10 qty=123 最大 | qty=123 | Byte Count=246, PDU=252B（与 FC 0x03 同界） | bytes BC=0xF6 |
| T-129 | FC=0x17 ReadQty=125 最大 | ReadQty=125 | 响应 Byte Count=250 | bytes BC=0xFA |
| T-130 | FC=0x17 WriteQty=121 最大 | WriteQty=121 | 请求 WriteBC=242 | bytes WriteBC=0xF2 |
| T-131 | FC=0x18 FIFO Count=0 最小 | FIFO Count=0 | 响应 `18 0002 0000`（值字节数=0=2×0，自洽，修复 R4-H4） | FIFO Count=0 |
| T-132 | FC=0x18 FIFO Count=31 最大 | FIFO Count=31 | 响应含 31 寄存器值 | FIFO Count=0x1F |
| T-133 | StartingAddress=0x0000 最小 | addr=0 | bytes addr=`00 00` | bytes 匹配 |
| T-134 | StartingAddress=0xFFFF 最大 | addr=0xFFFF | bytes addr=`FF FF` | bytes 匹配 |
| T-135 | UnitID=0 广播最小 | UnitID=0 | bytes Unit=0x00 | bytes 匹配 |
| T-136 | UnitID=247 最大合法 | UnitID=247 | bytes Unit=0xF7 | bytes 匹配 |
| T-137 | Transaction ID 回绕精确点 | 65538 事务 | 第 65537 个 TID=0，第 65538 个 TID=1 | TID 序列（修复 M2-LOW-3） |
| T-138 | Transaction ID=0 第 1 个 | 1 事务 | TID=0x0000 | bytes TID=0 |
| T-139 | Transaction ID=0xFFFF 第 65536 个 | 65536 事务 | 第 65536 个 TID=0xFFFF | bytes TID=0xFFFF |
| T-140 | SharedTIDSpace 跨流全局递增 | MasterCount=2, SharedTIDSpace=true | 流 1 TID=0, 流 2 TID=1 | 跨流 TID 连续 |
| T-141 | 跨流 TID 复用（SharedTIDSpace=false） | MasterCount=2, SharedTIDSpace=false | 流 1 TID=0, 流 2 TID=0 | 跨流 TID 复用 |
| T-142 | WriteValue=0x0000 边界 | FC=0x05, WriteValue=0x0000 | 请求 `05 XXXX 0000` | bytes value=`00 00` |
| T-143 | WriteValue=0xFF00 边界 | FC=0x05, WriteValue=0xFF00 | 请求 `05 XXXX FF00` | bytes value=`FF 00` |
| T-144 | WriteValue=0xFFFF FC=0x06 | FC=0x06, WriteValue=0xFFFF | 请求 `06 XXXX FFFF` | bytes value=`FF FF` |
| T-145 | MaskAnd=0x0000 边界 | FC=0x16, MaskAnd=0x0000 | bytes AND=`00 00` | bytes 匹配 |
| T-146 | MaskAnd=0xFFFF 边界 | FC=0x16, MaskAnd=0xFFFF | bytes AND=`FF FF` | bytes 匹配 |
| T-147 | MaskOr=0x0000 边界 | FC=0x16, MaskOr=0x0000 | bytes OR=`00 00` | bytes 匹配 |
| T-148 | MaskOr=0xFFFF 边界 | FC=0x16, MaskOr=0xFFFF | bytes OR=`FF FF` | bytes 匹配 |
| T-149 | SubFunction=0x0000 最小 | FC=0x08, SubFunction=0x0000 | bytes sub=`00 00` | bytes 匹配 |
| T-150 | SubFunction=0x0015 最大合法（修复 R3-H1；注：0x0015 在 Wireshark 3.6 值表未收录，tshark 显示 Unknown，集成用例不覆盖，修复 R4-M1） | FC=0x08, SubFunction=0x0015 | bytes sub=`00 15` | bytes 匹配 |
| T-151 | FC=0x2B Conformity Level=0x01 Basic | Conformity=0x01 | bytes Conformity=0x01 | bytes 匹配 |
| T-152 | FC=0x2B Conformity Level=0x03 Extended | Conformity=0x03 | bytes Conformity=0x03 | bytes 匹配 |
| T-153 | FC=0x2B Conformity Level=0x83 Extended+Private | Conformity=0x83 | bytes Conformity=0x83 | bytes 匹配 |
| T-154 | FC=0x2B Object Length=0 | Obj Len=0 | Object 无 Value | Obj 仅 ID+Len=2B |
| T-155 | FC=0x2B Object Length=255 | Obj Len=255 | Object Value 255B | bytes Obj Len=0xFF |
| T-156 | FC=0x17 WriteAddress 回退 StartingAddress+WriteQuantity | WriteAddr=0, StartingAddress=0, WriteQty=3 | WriteAddr 回退=0+3=3（修复 R1-H3） | bytes WriteAddr=0x0003 |
| T-157 | FC=0x17 WriteAddress 回退 uint16 回绕 | WriteAddr=0, StartingAddress=0xFFFF, WriteQty=3 | WriteAddr 回退=(0xFFFF+3) mod 65536=0x0002（修复 R2-M6） | bytes WriteAddr=0x0002 |
| T-158 | PDU=253 边界（FC 0x10 qty=123） | FC=0x10, qty=123 | PDU=252B（合法上限）, Length=253 | Length=0x00FD |
| T-159 | MBAP+PDU 总长 259 边界 | FC=0x03, qty=125 | 总长=259 < 260 | total=259 |
| T-160 | ExceptionCode=0x0B 最大合法 | ExcCode=0x0B | bytes exc=0x0B | bytes 匹配 |

### §7.5 多会话/多流用例（T-161 ~ T-180）

| # | 名称 | 输入 | 期望 | 断言点 |
|---|------|------|------|--------|
| T-161 | 2 并发 master | MasterCount=2 | 2 个独立 TCP 流 | SrcPort 不同 |
| T-162 | 8 并发 master | MasterCount=8 | 8 个独立 TCP 流 | 8 个不同 4-tuple |
| T-163 | 2 master TID 独立 | MasterCount=2, SharedTIDSpace=false | 流 1 TID=0, 流 2 TID=0（跨流复用） | 两流 TID 相同 |
| T-164 | 2 master SharedTIDSpace=true | MasterCount=2, SharedTIDSpace=true | 流 1 TID=0, 流 2 TID=1（跨流递增） | 两流 TID 连续 |
| T-165 | 100 master 压力 | MasterCount=100 | 100 个独立 TCP 流 | 100 个不同 4-tuple |
| T-166 | 多 master 独立事务序列 | MasterCount=2, 每 master 3 事务 | 每 master TID 序列 0,1,2 | 流内 TID 递增 |
| T-167 | 多 master 响应不交叉 | MasterCount=2 | 每 master 响应配对其请求 | TID 配对正确 |
| T-168 | 多 master TCP FIN 独立 | MasterCount=2 | 每流独立 FIN | 2 个 FIN 包 |
| T-169 | 多 master from_response 隔离 | MasterCount=2 | 每 master 独立流状态 | 不交叉引用 |
| T-170 | FlowCount=2 同 master 多流 | MasterCount=1, FlowCount=2 | 2 个独立 TCP 流 | 2 个不同 SrcPort |
| T-171 | FlowCount=8 | MasterCount=1, FlowCount=8 | 8 个独立流 | 8 个不同 4-tuple |
| T-172 | MasterCount×FlowCount 笛卡尔积 | MasterCount=2, FlowCount=3 | 6 个独立流 | 6 个不同 4-tuple |
| T-173 | SharedTIDSpace 跨流全局递增 | MasterCount=2, FlowCount=2, SharedTIDSpace=true | 4 流共享 TID 空间 | 4 流 TID 连续 0,1,2,3 |
| T-174 | SharedTIDSpace 回绕 | SharedTIDSpace=true, 总事务数=65537 | 第 65537 个 TID=0 | TID 回绕正确 |
| T-175 | 多流 TCP 三次握手独立 | MasterCount=2 | 每流独立 SYN/SYN+ACK/ACK | 2 个 SYN 包 |
| T-176 | 多流事务顺序保持 | MasterCount=2, 每 master 5 事务 | 每流事务按序 | 流内顺序正确 |
| T-177 | 广播跨多 master | MasterCount=2, UnitID=0, FC=0x05 | 2 流都广播 | 2 个广播包 |
| T-178 | 多 master 异常响应独立 | MasterCount=2, ExcCode=0x01 | 每流独立异常响应 | 2 个异常响应包 |
| T-179 | SharedTIDSpace=false 跨流 TID 复用 | MasterCount=3, SharedTIDSpace=false | 3 流 TID 都从 0 开始 | 3 流 TID=0 |
| T-180 | 多流并发时序 | MasterCount=2, 每 master 3 事务 | 6 事务全部完成 | 6 请求+6 响应 |

### §7.6 集成用例（T-181 ~ T-200，wire-format 验证）

> 验证工具链（修复 R1-M5）：tshark 为最终裁判（§7.7）。gopacket 的 `layers.ModbusTCP` 仅提供层识别与基础字段（TID/PID/Length/Unit/FC），FC 特定字段（如 FC 0x14 item 内 File Response Length、FC 0x2B MEI 子字段、FC 0x18 Byte Count 2B）**不保证逐字段解析**——FC 特定字段验证以 tshark 为准。

| # | 名称 | 输入 | 期望 | 断言点 |
|---|------|------|------|--------|
| T-181 | tshark 解析 FC=0x01 | 生成 FC=0x01 包 | tshark 识别为 Modbus read coils | tshark output 含 "Read Coils" |
| T-182 | tshark 解析 FC=0x03 | 生成 FC=0x03 包 | tshark 识别为 Read Holding Registers | tshark output 含 "Read Holding Registers" |
| T-183 | tshark 解析 FC=0x05 | 生成 FC=0x05 包 | tshark 识别 Write Single Coil | tshark output 含 "Write Single Coil" |
| T-184 | tshark 解析 FC=0x10 | 生成 FC=0x10 包 | tshark 识别 Write Multiple Registers | tshark output 含 "Write Multiple Registers" |
| T-185 | tshark 解析 FC=0x11 | 生成 FC=0x11 包（响应 `11 01 FF AA BB`） | tshark 识别 Report Server ID 且显示原始 Data（无 Byte Count 字段，修复 R4-H2） | tshark output 含 "Report Server ID" 且 **不含** "Byte Count"；Data 字段与 `01ffaabb` 匹配 |
| T-186 | tshark 解析 FC=0x14 | 生成 FC=0x14 包（响应 `14 06 05 06 1234 5678`） | tshark 识别 Read File Records 且 item 含 File Response Length 字段（修复 R3-C1） | tshark output 含 "Read File Records" + File Response Length 值=0x05（=1+2×RL，字段级断言，修复 R4-M2） |
| T-187 | tshark 解析 FC=0x15 | 生成 FC=0x15 包（请求 `15 0B 06 0001 0000 0002 1234 5678`） | tshark 识别 Write File Records 且**无 Malformed**、item 含 Reference Type=6/File Number=1/Record Number=0/Word Count=2/Data（修复 R4-C1） | tshark output 含 "Write File Records"，不含 "Malformed"；Reference Type 字段=6（字段级断言，修复 R4-M2） |
| T-188 | tshark 解析 FC=0x17 | 生成 FC=0x17 包 | tshark 识别 Read/Write Multiple Registers | tshark output 含 "Read/Write Multiple" |
| T-189 | tshark 解析 FC=0x18 | 生成 FC=0x18 包 | tshark 识别 Read FIFO Queue 且 Byte Count 2B | tshark output 含 "Read FIFO Queue" |
| T-190 | tshark 解析 FC=0x2B 完整响应结构 | 生成 FC=0x2B 响应含 Conformity/More/Next/Count/Objects | tshark 识别所有字段（修复 R2-C2） | tshark output 含 "Encapsulated Interface Transport" + "Conformity Level" + "More Follows" + "Object" |
| T-191 | tshark 解析异常响应 | 生成 ExcCode=0x02 异常响应 | tshark 识别 Exception Response | tshark output 含 "Exception" + exc_code=0x02 |
| T-192 | tshark MBAP Length 字段 | 任意包 | tshark Length 与实际 PDU 长度一致 | length 匹配 |
| T-193 | tshark Transaction ID 字段 | 多事务序列 | tshark 显示 TID 递增 | TID 序列正确 |
| T-194 | tshark Unit ID 字段 | UnitID=247 | tshark 显示 Unit=247 | unit 匹配 |
| T-195 | tshark 字节序 BE | 任意寄存器值 | tshark 显示 BE 字节序 | 寄存器值 BE 解析正确 |
| T-196 | tshark 位打包 | FC=0x01 qty=10 | tshark 显示位数据布局 | 位数据解析正确 |
| T-197 | tshark FC=0x16 echo | FC=0x16 请求/响应 | tshark 显示 echo 响应 | 请求/响应字节相同 |
| T-198 | tshark 广播包 | UnitID=0 | tshark 显示 Unit=0（broadcast） | tshark output 含 "broadcast" |
| T-199 | tshark 完整会话 | 多事务序列 | tshark 识别整个序列 | 序列完整 |
| T-200 | tshark 多 master | MasterCount=2 | tshark 识别 2 个独立 TCP 流 | 2 个独立流 |

### §7.7 修订追加用例（T-201 ~ T-205，v2.0.2 复审修复验证）

| # | 名称 | 输入 | 期望 | 断言点 | 修复 ID |
|---|------|------|------|--------|---------|
| T-201 | FC=0x99 豁免路径响应字节（修复 R2-C1） | FC=0x99, ExcCode=0x01 | 响应 PDU=`99 01`（**不是 `19 01`**；0x99\|0x80=0x99 幂等） | bytes PDU=`99 01` | R2-C1 |
| T-202 | FC=0x2B 响应完整结构（修复 R2-C2/R4-H1：MEI Type 统一为 0x0E） | FC=0x2B, MEI=0x0E, Conformity=0x01, More=0x00, Next=0x00, Count=1, Obj={0x00, 4, "ABCD"} | 响应 PDU=`2B 0E 01 01 00 00 01 00 04 41 42 43 44`（含 MEI+Code+Conformity+More+Next+Count+Object 七字段，MEI Type=0x0E=Read Device Identification，修复 R4-H1） | bytes PDU 13 字节完整匹配 | R2-C2/R4-H1 |
| T-203 | FC=0x08 SubFunction=0x0013 合法（修复 R3-H1 改注：0x0013 是 Return IOP Overrun Count，非上限） | FC=0x08, SubFunction=0x0013 | Validate 接受 | 无 error | R3-H1 |
| T-204 | FC=0x08 SubFunction=0x0014 合法（修复 R3-H1；注：0x0014 tshark 3.6 识别为 Clear Overrun Counter and Flag，修复 R4-M1 佐证） | FC=0x08, SubFunction=0x0014 | Validate 接受 | 无 error | R3-H1 |
| T-205 | ResponseValues 与 Values 独立性（修复 R2-H2） | FC=0x03, Values=非空, RV=非空 | 请求 PDU 用 Values，响应 PDU 用 RV，两者独立无交互 | request PDU≠response PDU，无 "response_values only applies to response PDU" 错误（该错误消息已删除） | R2-H2 |

### §7.8 测试用例对照矩阵

| 规格章节 | 测试用例 | 说明 |
|---------|----------|------|
| §1.3 功能码覆盖（19 个 FC） | T-001~T-030, T-052~T-080 | 每 FC 至少 1 条正向用例（修复 M2-HIGH-3） |
| §2.5 异常码（10 个） | T-031~T-040 | 全 10 个异常码各 1 条 |
| §2.7 数量上限 | T-003/T-007/T-098~T-110 | 各 FC 边界 |
| §3.3 各 FC PDU 结构 | T-001~T-030 | 逐 FC 验证 |
| §3.4 异常响应格式 | T-031~T-040 | FC\|0x80 + ExcCode |
| §4.2 TID 分配 | T-041~T-044, T-137~T-141 | 单调递增 + 回绕 |
| §4.4 广播语义 | T-047~T-050, T-094~T-095l | 广播+写/读 FC + 抑制（读类 FC 全参数化，修复 R4-M3） |
| §5.2 字段使用规则 | T-060/T-079 | FC 0x17 Quantity IGNORED |
| §5.3 默认值规则 | T-074/T-075 | nil vs [] |
| §6 HexDump S1-S15 | T-001/T-005/T-019/T-020/T-021/T-023/T-025/T-027 | 每场景至少 1 条对应 |
| §7.4 边界（T-121~T-160） | T-126/T-128/T-130/T-132/T-158/T-159 | qty=1968/123 上限、WriteBC=242、FIFO=31、PDU 边界（修复 R4-L4：矩阵补引用） |
| §8.1 Validate 支持集 | T-081~T-088 | 不支持 FC 拒绝 |
| §8.2 字段范围 Validate | T-098~T-117, T-117b, T-119b | 各 FC 数量/值校验（含 FC 0x18 长度自洽，修复 R4-H4） |
| §8.3 语义非法+ExcCode | T-111 | WriteValue 非法值 |
| §8.4 响应长度公式 | T-007/T-029/T-055/T-062/T-124/T-131/T-158 | 各 FC ResponseValues 长度（含 FIFO Count=0 边界，修复 R4-H4） |
| §9 错误处理 | T-081~T-120 | 全部负向用例 |
| §10.3 gopacket 弱化声明 | T-181~T-200 | tshark 为最终裁判 |
| §11 R1/R2 修订 | T-201~T-205 | R2 复审修复验证 |

---

## §8. Validate 规则

### §8.1 MODBUSConfig 顶层 Validate

| 规则 ID | 字段 | 条件 | 失败动作 |
|---------|------|------|----------|
| V-001 | UnitID | nil（默认 1）或 0-247 | 拒绝（248-255 保留） |
| V-002 | UnitID=0（广播） | 仅纯写功能码（FC 0x05/0x06/0x0F/0x10/0x15/0x16）合法 | 拒绝 `broadcast (unit_id=0) is only valid for write function codes`（修复 R1-M4） |
| V-003 | MasterCount | 1-1000 | 拒绝 |
| V-004 | FlowCount | 1-100 | 拒绝 |
| V-005 | Transactions | nil 或非空（显式 `[]` 合法，表示仅握手+挥手） | 不适用（两态均合法，修复 M2-MED-4） |
| V-006 | Transactions 非空时 | 每事务 FC 必须合法（见 V-101 支持集） | 拒绝 |

### §8.2 MODBUSOperation Validate（功能码相关）

| 规则 ID | 字段 | 条件 | 失败动作 |
|---------|------|------|----------|
| V-101 | FunctionCode | 必须在支持集 {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x0B, 0x0C, 0x0F, 0x10, 0x11, 0x14, 0x15, 0x16, 0x17, 0x18, 0x2B} 内 | 拒绝 `unsupported function code`（0x09/0x0A/0x0D/0x0E/0x12/0x13/0x19-0x2A 等一律拒绝） |
| V-102 | FunctionCode 高位 | bit7 不能置位（0x80-0xFF 拒绝） | 拒绝 `function code high bit must not be set` |
| V-103 | 豁免规则（修复 R1-H1/R2-C1） | FC 不在支持集 **且** ExceptionCode≠0 | **豁免** V-101/V-102：请求按用户字节逐字节透传（无数据时仅 FC 一字节），响应 PDU = `FC\|0x80 + ExceptionCode`。注意 FC 的 bit7 已置位时 `FC\|0x80` 幂等（结果 = FC 原值，如 0x99\|0x80=0x99）。ExceptionCode=0 时非法 FC 一律拒绝（无豁免） |
| V-104 | Quantity（FC 0x01/0x02） | 1-2000 | 拒绝 |
| V-105 | Quantity（FC 0x03/0x04） | 1-125 | 拒绝 |
| V-106 | Quantity（FC 0x0F） | 1-1968 | 拒绝 |
| V-107 | Quantity（FC 0x10） | 1-123 | 拒绝 |
| V-108 | Quantity（FC 0x17） | **IGNORED**（使用 ReadQuantity/WriteQuantity，修复 M2-MED-2） | 不校验（值不影响报文） |
| V-109 | ReadQuantity（FC 0x17） | 1-125，必须显式（0 拒绝） | 拒绝 `read_quantity must be explicit` |
| V-110 | WriteQuantity（FC 0x17） | 1-121，必须显式（0 拒绝） | 拒绝 `write_quantity must be explicit` |
| V-111 | Values（FC 0x0F） | 长度必须 = ⌈Quantity/8⌉ | 拒绝 `values length must be ceil(quantity/8)`（修复 R1-M2） |
| V-112 | Values（FC 0x10） | 长度必须 = Quantity×2 | 拒绝 `values length must be quantity*2` |
| V-113 | Values（FC 0x17） | 长度必须 = WriteQuantity×2 | 拒绝 `values length must be write_quantity*2`（修复 R1-M2） |
| V-114 | Values（FC 0x14） | item 每 7 字节固定步进；item 内 Record Length（偏移 5-6）≥1 | 拒绝 `record length must be >= 1`（修复 R2-M5） |
| V-115 | Values（FC 0x15） | 每 item 按偏移 5-6 的 Record Length 动态步进（7+2×RL，item 首字节为 Reference Type=0x06，item 内无 Byte Count，修复 R4-C1 回退 R3-C2）；item 内 Record Length ≥1 | 拒绝 `item length mismatch` / `record length must be >= 1`（修复 R1-M1） |
| V-116 | WriteValue（FC 0x05） | 必须 ∈ {0, 1, 0xFF00, 0x0000}（0/1 由 planner 在 Plan 阶段映射为 0x0000/0xFF00，修复 R1-H2）或配 ExceptionCode（任意合法异常码背书，见 §8.3） | 拒绝 `write_value must be 0/1/0xFF00/0x0000 or set exception_code` |
| V-117 | SubFunction（FC 0x08） | 0x0000-0x0015（0x0005-0x0009 保留；0x0014=Clear Overrun Counter and Flag、0x0015=Get/Clear Modbus Plus Statistics 均为合法子功能，上限 0x0015 修复 R3-H1） | 拒绝 `sub_function must be 0x0000-0x0015` |
| V-118 | SubFunction（FC 0x2B） | 取低字节作为 MEI Type；高字节必须为 0；低字节必须为 0x0E（Read Device Identification，请求与响应同用；0x0D=CANopen General（CiA 309）本设计不实现，修复 R4-H1 回退 R3-M1 的"0x0D=请求/0x0E=响应侧"误读） | 拒绝 `FC 0x2B sub_function high byte must be 0` / `FC 0x2B sub_function must be 0x000E`（修复 R1-M6） |
| V-119 | FIFO Count（FC 0x18，ResponseValues） | 0-31；且 RV 中值字节数必须 = 2 × FIFO Count（自洽校验，修复 R4-H4）；Byte Count 字段由 planner 按 2+2×FIFO Count 重新计算，用户无需手工维护 | 拒绝 `FIFO count exceeds 31` / `response_values length must match FIFO count`（修复 M2-MED-3/R4-H4） |
| V-120 | ResponseValues | 与 ExceptionCode 互斥（两者同时非空/非零） | 拒绝 `exception_code and response_values are mutually exclusive`（修复 M2-MED-5） |
| V-121 | WriteAddress（FC 0x17） | 0 时回退到 StartingAddress + WriteQuantity（uint16 模运算回绕，修复 R1-H3/R2-M6） | 不拒绝（回退语义） |
| V-122 | ExceptionCode | 必须 ∈ {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x0A, 0x0B}（0x00 视为正常响应不报错；0x09、0x0C-0xFF 拒绝，修复 M2-HIGH-4） | 拒绝 `invalid exception code` |

### §8.3 语义非法值 + ExceptionCode 背书规则（修复 R1-M3/R4-H3）

| 语义非法场景 | 无 ExceptionCode | 配任意合法 ExceptionCode |
|--------------|------------------|--------------------------|
| FC 0x05 WriteValue=0x1234（非 0/1/0xFF00/0x0000） | 拒绝 | **合法**（任意合法异常码均可背书，修复 R1-M3） |
| Quantity=0（各 FC） | 拒绝（V-104~V-107） | **合法** |
| FC 0x18 FIFO Count=32 | 拒绝（V-119） | **合法** |

规则：**任意合法异常码（0x01-0x08, 0x0A, 0x0B 共 10 个）均可背书语义非法值**——不同异常码区间（如 0x01-0x03 与 0x04-0x0B）行为完全相同（仅语义场景不同），Validate 只检查"ExceptionCode 合法且非零"，不区分区间（修复 R4-H3：v2.0.3 表格的 3 列区间布局易误导实现者写出区间分支）。此时请求 PDU 仍按用户配置生成（wire 上保留非法值），响应为 `FC|0x80 + 异常码`——模拟真实 slave 对非法请求回异常的行为。

### §8.4 响应 PDU 长度公式（ResponseValues 语义）

**表头声明（修复 R2-M2）**：以下长度均为 **FC 之后的字节**（ResponseValues 语义 = "响应 PDU 中 FC 之后的字节"，不含 FC 本身）。

| FC | ResponseValues 长度公式 | 说明 |
|----|------------------------|------|
| 0x01/0x02 | 1 + ⌈Quantity/8⌉ | Byte Count + 位数据 |
| 0x03/0x04 | 1 + Quantity×2 | Byte Count + 寄存器值 |
| 0x05/0x06 | 0（echo，planner 自动） | ResponseValues 不适用（响应=请求） |
| 0x07 | 1 | Exception Status |
| 0x08 | 由子功能决定（echo 时 = 请求 PDU 除 FC 外部分） | 默认回显 |
| 0x0B | 4 | Status(2) + EventCount(2) |
| 0x0C | 1 + 6 + N | Byte Count + Status(2) + EventCount(2) + MessageCount(2) + Events(N)（修复 R1-C7：v2.0.0 曾写 1+4+N；字段顺序依规范 §6.6 表 10，修复 R3-H2 核对） |
| 0x0F/0x10 | 4 | Starting Address(2) + Quantity(2) |
| 0x11 | 2 + N | Slave ID(1) + Run Indicator(1) + Additional(N)；**无 Byte Count 字段**（修复 R4-H2） |
| 0x14 | 1 + Σ(item 长度) | Byte Count + items；每 item 长度 = 2 + Record Length × 2（File Response Length + RefType + Record Data，修复 R3-C1） |
| 0x15 | 1 + Σ(item 长度) = 1 + Σ(7+2×RL) | Byte Count + items（item 首字节为 Reference Type=0x06，item 内无 Byte Count，item 总长 = 7+2×RL，修复 R4-C1 回退 R3-C2；响应 echo 请求 PDU，ResponseValues 可选（缺省时 planner 自动 echo）） |
| 0x16 | 0（echo，planner 自动） | ResponseValues 不适用（响应=请求） |
| 0x17 | 1 + ReadQuantity×2 | Byte Count + 读寄存器值 |
| 0x18 | 2 + 2 + FIFOCount×2 | Byte Count(2B) + FIFO Count(2B) + 值(2N)（Byte Count 为 2 字节，与其余 FC 不同；值字节数必须 = 2×FIFO Count，自洽校验见 V-119，修复 R4-H4） |
| 0x2B | 1 + 1 + 1 + 1 + 1 + 1 + Σ(2+ObjLen) | MEI Type + Code + Conformity + More Follows + Next Object ID + Object Count + Σ(Object ID + Object Length + Value)（修复 R2-C2） |

**示例核对（修复 R2-M2/R4-C1）**：
- T-020 的 FC 0x14 响应 `14 06 05 06 1234 5678`：ResponseValues=`06 05 06 1234 5678`=7 字节 = 1(Byte Count) + 1 个 item(2+2×2=6)。按公式 1 + Σ(2+2×RL) = 1 + 6 = 7 ✓。item 内 File Response Length=0x05 = 1 + 2×2 = 5（含 RefType 在内的记录数据字节数）✓，**不是 0x04**（v2.0.2 曾误作"Byte Count=Record Length×2"，修复 R3-C1）。
- T-021 的 FC 0x15 响应 echo 请求 `15 0B 06 0001 0000 0002 1234 5678`：请求 PDU = 13 字节 = FC(1) + 外层 ByteCount(1) + item(11)。item = RefType(1) + File(2) + Record(2) + RecLen(2) + Record Data(4) = 11 = 7 + 2×2 ✓（item 内无 Byte Count 字段，首字节直接是 Reference Type=0x06，修复 R4-C1；外层 Byte Count=0x0B=11=item 总长，自洽）。ResponseValues（FC 之后的字节）= 12 字节 = 外层 ByteCount(1) + item(11)。按公式 1 + Σ(7+2×RL) = 1 + (7+4) = 12 ✓。响应 PDU = FC(1) + 12 = 13 字节 = 请求 PDU，echo 成立 ✓。MBAP Length = 1(Unit) + 13 = 14（0x000E）✓。对照：v2.0.3 形式 `15 0C 0B ...`（item=12 字节、Length=15）被 tshark 3.6.14 标记 Malformed（R4-C1 实测）。

---

## §9. 错误处理

### §9.1 Modbus 异常响应层（§2.5 异常码）

异常响应（Exception Response，异常响应）由配置层 `ExceptionCode` 字段触发，planner 生成 `FC|0x80 + ExceptionCode` 响应 PDU：

| 异常场景 | 异常码 | 处理 |
|---------|--------|------|
| 不支持的功能码 | 0x01 Illegal Function | 配置 ExceptionCode=0x01，响应 = `FC\|0x80 01` |
| 地址越界 | 0x02 Illegal Data Address | 配置 ExceptionCode=0x02 |
| 数量/值非法 | 0x03 Illegal Data Value | 配置 ExceptionCode=0x03（语义非法值需配异常码背书，见 §8.3） |
| 从站设备故障 | 0x04 Slave Device Failure | 配置 ExceptionCode=0x04（FC 0x18 FIFO>31 也用此码，但本设计 Validate 直接拒绝，不模拟） |
| 长操作确认 | 0x05 Acknowledge | 配置 ExceptionCode=0x05 |
| 从站忙 | 0x06 Slave Device Busy | 配置 ExceptionCode=0x06 |
| 否定确认 | 0x07 Negative Acknowledge | 配置 ExceptionCode=0x07（合法码，修复 M2-HIGH-4） |
| 内存奇偶校验错 | 0x08 Memory Parity Error | 配置 ExceptionCode=0x08 |
| 网关路径不可用 | 0x0A Gateway Path Unavailable | 配置 ExceptionCode=0x0A（仅生成响应码，不模拟网关路由） |
| 网关目标无响应 | 0x0B Gateway Target Device Failed to Respond | 配置 ExceptionCode=0x0B（同上） |

**豁免规则交互（§8.1 V-103）**：FC 不在支持集 + ExceptionCode≠0 时走豁免路径——请求按用户字节透传，响应为 `FC|0x80 + ExceptionCode`。该机制模拟"slave 对未知功能码回 Illegal Function"的真实场景。

### §9.2 Validate 错误（配置层）

Validate（配置校验，在 planner 生成报文前的静态检查阶段）拒绝所有非法配置，错误消息规范：

| 错误类别 | 典型错误消息 | 对应规则 |
|---------|-------------|----------|
| 不支持 FC | `unsupported function code 0xXX` | V-101 |
| FC 高位已置位 | `function code high bit must not be set` | V-102 |
| 异常码非法 | `invalid exception code 0xXX` | V-122 |
| 数量越界 | `quantity must be 1-2000` / `quantity must be 1-125` 等 | V-104~V-107 |
| FC 0x17 缺数量 | `read_quantity must be explicit` / `write_quantity must be explicit` | V-109/V-110 |
| Values 长度不符 | `values length must be ceil(quantity/8)` 等 | V-111~V-113 |
| WriteValue 语义非法 | `write_value must be 0/1/0xFF00/0x0000 or set exception_code` | V-116 |
| FC 0x18 FIFO 超限 | `FIFO count exceeds 31` | V-119 |
| FC 0x18 FIFO 长度不自洽 | `response_values length must match FIFO count` | V-119（修复 R4-H4） |
| FC 0x08 子功能超限 | `sub_function must be 0x0000-0x0015` | V-117（修复 R3-H1） |
| FC 0x08 子功能保留 | `sub_function 0x0005-0x0009 reserved` | V-117 |
| FC 0x2B SubFunction 高字节 | `FC 0x2B sub_function high byte must be 0` | V-118（修复 R1-M6） |
| FC 0x2B MEI Type 非法 | `FC 0x2B sub_function must be 0x000E` | V-118（修复 R4-H1：0x0D=CANopen 不实现） |
| 互斥违反 | `exception_code and response_values are mutually exclusive` | V-120（修复 M2-MED-5） |
| 广播+读 FC | `broadcast (unit_id=0) is only valid for write function codes` | V-002（修复 R1-M4） |
| Unit ID 保留 | `unit_id 248 is reserved` 等 | V-001 |
| 文件记录 item 长度 | `record length must be >= 1` / `item length mismatch` | V-114/V-115（修复 R1-M1/R2-M5） |

### §9.3 长度边界处理

| 边界 | 规则 |
|------|------|
| PDU 最小 | 1 字节（仅 FC，如 FC 0x07/0x0B/0x0C/0x11 请求） |
| PDU 最大 | 253 字节（§2.6）；FC 0x03 qty=125 → PDU=252（T-007/T-124 验证）；FC 0x10 qty=123 → PDU=252（T-128） |
| Length 最小 | 2 = 1(Unit) + 1(PDU=仅 FC) |
| Length 最大 | 254 = 1 + 253 |
| MBAP+PDU 总长最大 | 260 = 7 + 253 |
| 总长 259 边界 | FC 0x03 qty=125 → 7+252=259 < 260 ✓（T-159） |
| FIFO Count 上限 | 31（FC 0x18，超出 Validate 拒绝 V-119） |
| TID 回绕 | 65536 事务后回绕至 0（`TID = (N-1) mod 65536`） |

### §9.4 字节序与位序

- **多字节标量（TID/PID/Length/Address/Quantity/Register Value/Mask/Status/EventCount/MessageCount/FIFO Count）**：全部 big-endian（BE）。
- **位数据（FC 0x01/0x02/0x0F 的 coil/input 状态）**：低地址字节先（low-address-first）+ 字节内 LSB 优先（bit0 = starting_address+0）。末字节高位补零。**不使用 little-endian 术语**（修复 M2-LOW-1）。
- **FC 0x18 Byte Count**：2 字节 BE（与其余 FC 的 1 字节 Byte Count 不同）。

### §9.5 gopacket 与 tshark 工具链（修复 R1-M5）

- **gopacket** `layers.ModbusTCP`：仅提供层识别与基础字段（TID/PID/Length/Unit/FC），**不保证 FC 特定字段逐字段解析**（FC 0x14 item 内 File Response Length、FC 0x2B MEI 子字段、FC 0x18 Byte Count 2B 等）。
- **tshark**：FC 特定字段验证以 tshark 为最终裁判（§7.7 集成用例 T-181~T-200 全部用 tshark）。已知限制（修复 R4-M1）：**FC 0x08 子功能 0x0015 在 Wireshark 3.6 值表未收录**（tshark 3.6.14 实测显示 "Diagnostic Code: Unknown (21)"），集成用例不覆盖 0x0015；如需 wire 级验证须用更高版本 tshark 或自写解析器。
- 实现时不应依赖 gopacket 做 FC 特定字段断言；pcap 解析若需 FC 特定字段，应使用 tshark 命令行或自写解析器。

---

## §10. 扩展字段映射

### §10.1 MODBUSConfig 到 MODBUSOperation 字段映射

| MODBUSConfig 字段 | MODBUSOperation 字段 | 说明 |
|------------------|---------------------|------|
| UnitID | （直接写入 MBAP 头 offset 6） | *uint8，nil→默认 1，0=广播 |
| SuppressBroadcast | （planner 控制响应包生成） | 广播时省略响应包 |
| Transactions | MODBUSOperation[] | 每事务独立配置 |
| MasterCount/FlowCount | （planner 控制流数） | 多会话/多流 |
| SharedTIDSpace | （planner 控制 TID 空间） | 跨流共享 vs 独立 |

### §10.2 MODBUSOperation 到 Modbus wire 字节映射

| MODBUSOperation 字段 | wire 偏移 | 大小 | 说明 |
|---------------------|-----------|------|------|
| （planner 计算） Transaction ID | MBAP offset 0 | 2B BE | TID = (N-1) mod 65536 |
| （固定） Protocol ID | MBAP offset 2 | 2B BE | 恒 0x0000 |
| （planner 计算） Length | MBAP offset 4 | 2B BE | = 1(Unit) + PDU 长度 |
| UnitID | MBAP offset 6 | 1B | 0-247，0=广播 |
| FunctionCode | PDU offset 0 | 1B | 支持集 19 个 FC |
| StartingAddress | PDU offset 1 | 2B BE | FC 0x01-0x06/0x0F/0x10/0x16/0x18 通用 |
| Quantity | PDU offset 3 | 2B BE | FC 0x01-0x04/0x0F/0x10；FC 0x17 IGNORED |
| ReadAddress | PDU offset 1 | 2B BE | FC 0x17（覆盖 StartingAddress） |
| ReadQuantity | PDU offset 3 | 2B BE | FC 0x17 |
| WriteAddress | PDU offset 5 | 2B BE | FC 0x17 |
| WriteQuantity | PDU offset 7 | 2B BE | FC 0x17 |
| WriteValue | PDU offset 3 或 4 | 2B BE | FC 0x05/0x06；FC 0x05 时 0/1→0x0000/0xFF00 |
| Values | PDU offset 变化 | 变化 | FC 0x0F/0x10/0x14/0x15/0x17/0x08/0x2B 透传 |
| ResponseValues | 响应 PDU offset 1 | 变化 | 覆盖 planner 自动响应构造 |
| SubFunction | PDU offset 1 | 2B BE | FC 0x08；FC 0x2B 取低字节→MEI Type |
| MaskAnd | PDU offset 3 | 2B BE | FC 0x16 |
| MaskOr | PDU offset 5 | 2B BE | FC 0x16 |
| ExceptionCode | 响应 PDU offset 1 | 1B | 异常响应时 = `FC\|0x80 + ExcCode` |

### §10.3 各 FC 请求/响应 PDU 字段映射（按 §3.3 顺序）

| FC | 请求 PDU 字段顺序（offset:字段:大小） | 响应 PDU 字段顺序 |
|----|-------------------------------------|------------------|
| 0x01/0x02 | 0:FC:1, 1:StartingAddress:2, 3:Quantity:2 | 0:FC:1, 1:ByteCount:1, 2:位数据:⌈qty/8⌉ |
| 0x03/0x04 | 0:FC:1, 1:StartingAddress:2, 3:Quantity:2 | 0:FC:1, 1:ByteCount:1, 2:寄存器值:qty×2 |
| 0x05 | 0:FC:1, 1:OutputAddress:2, 3:OutputValue:2 | echo（同请求） |
| 0x06 | 0:FC:1, 1:RegisterAddress:2, 3:RegisterValue:2 | echo |
| 0x07 | 0:FC:1 | 0:FC:1, 1:ExceptionStatus:1 |
| 0x08 | 0:FC:1, 1:SubFunction:2, 3:DataField:N | 子功能特定（0x0000=echo） |
| 0x0B | 0:FC:1 | 0:FC:1, 1:Status:2, 3:EventCount:2 |
| 0x0C | 0:FC:1 | 0:FC:1, 1:ByteCount:1, 2:Status:2, 4:EventCount:2, 6:MessageCount:2, 8:Events:N（顺序依规范 §6.6，修复 R3-H2 核对） |
| 0x0F | 0:FC:1, 1:StartingAddress:2, 3:Quantity:2, 5:ByteCount:1, 6:OutputsValue:⌈qty/8⌉ | 0:FC:1, 1:StartingAddress:2, 3:Quantity:2 |
| 0x10 | 0:FC:1, 1:StartingAddress:2, 3:Quantity:2, 5:ByteCount:1, 6:RegistersValue:qty×2 | 0:FC:1, 1:StartingAddress:2, 3:Quantity:2 |
| 0x11 | 0:FC:1 | 0:FC:1, 1:SlaveID:1, 2:RunIndicator:1, 3:Additional:N（无 Byte Count 字段，修复 R4-H2） |
| 0x14 | 0:FC:1, 1:ByteCount:1, 2:items:7×M | 0:FC:1, 1:ByteCount:1, 2:items（每 item=FileResponseLength(1)=1+2×RL + RefType(1)=0x06 + RecordData(2×RL)，修复 R3-C1） |
| 0x15 | 0:FC:1, 1:ByteCount:1, 2:items:Σ(7+2×RL)（每 item 首字节=Reference Type=0x06，item 内无 Byte Count，修复 R4-C1） | echo（同请求，含完整 Record Data） |
| 0x16 | 0:FC:1, 1:ReferenceAddress:2, 3:ANDMask:2, 5:ORMask:2 | echo |
| 0x17 | 0:FC:1, 1:ReadAddr:2, 3:ReadQty:2, 5:WriteAddr:2, 7:WriteQty:2, 9:WriteBC:1, 10:WriteValues:WriteQty×2 | 0:FC:1, 1:ByteCount:1, 2:ReadValues:ReadQty×2 |
| 0x18 | 0:FC:1, 1:FIFOPointerAddress:2 | 0:FC:1, 1:ByteCount:2, 3:FIFOCount:2, 5:Values:N×2 |
| 0x2B | 0:FC:1, 1:MEIType:1, 2:MEISpecificData:N | 0:FC:1, 1:MEIType:1, 2:ReadDeviceIDCode:1, 3:ConformityLevel:1, 4:MoreFollows:1, 5:NextObjectID:1, 6:NumberOfObjects:1, 7:Objects:Σ(2+ObjLen) |
| 0x80+（异常） | 同对应 FC 请求 | 0:FC\|0x80:1, 1:ExceptionCode:1 |

### §10.4 扩展表 21 字段覆盖率

| 扩展表字段 | v2.0.2 覆盖 | 验证用例 |
|-----------|-------------|----------|
| protoid（Protocol ID） | ✅ 固定 0x0000 | T-120 |
| len（Length） | ✅ = 1+PDU | T-001~T-080 全场景 |
| func（Function Code） | ✅ 19 个 FC + 豁免 | T-001~T-088 |
| excp（Exception Code） | ✅ 10 个合法码 | T-031~T-040 |
| transid（Transaction ID） | ✅ 递增+回绕 | T-041~T-044 |
| unitid（Unit ID） | ✅ *uint8 支持 0 广播 | T-045~T-050 |
| regcount（Quantity） | ✅ 各 FC 上限 | T-098~T-110 |
| starting_address | ✅ 0-0xFFFF | T-071/T-072 |
| write_value | ✅ 0/1/0xFF00/0x0000 | T-009~T-012 |
| values | ✅ 各 FC 透传 | T-052/T-053/T-108~T-110 |
| mask_and/mask_or | ✅ FC 0x16 | T-023/T-145~T-148 |
| read_address/write_address | ✅ FC 0x17 独立字段 | T-027/T-060/T-156 |
| read_quantity/write_quantity | ✅ FC 0x17 独立字段 | T-027/T-104~T-107 |
| sub_function | ✅ FC 0x08/0x2B | T-018/T-025/T-113~T-117 |
| response_values | ✅ 与 ExcCode 互斥 | T-001~T-080（多场景）/T-093 |
| suppress_broadcast | ✅ 广播响应抑制 | T-049/T-050 |
| direction（已废弃） | ✅ planner 忽略 | T-076 |
| response_mode | ✅ normal/no_response | T-077/T-078 |
| shared_tid_space | ✅ 跨流 TID 共享 | T-140/T-164/T-173 |
| master_count/flow_count | ✅ 多会话/多流 | T-161~T-180 |
| mei_type（FC 0x2B） | ✅ 0x0E（Read Device Identification，请求与响应同用；0x0D=CANopen 不实现，修复 R4-H1） | T-025/T-026 |

---

## §11. 修订记录

### §11.1 v2.0.0（2026-08-05，全量重写）

**修订性质**：基于 `audit/13-modbus-audit-deep.md`（14 项：2 CRITICAL + 4 HIGH + 5 MEDIUM + 3 LOW）与 `audit/13-modbus-audit-r1-v2.md`（20 项：7 CRITICAL + 3 HIGH + 6 MEDIUM + 4 LOW）全量重写（v2.0.0 版本修复了 M2 与 R1 全部问题，详见 §11.3 复核）。

关键修复（v2.0.0 时的声明，供追溯）：
- M2-CRIT-1（FC 0x15 请求 item 漏 Record Data）、M2-CRIT-2（FC 0x11 响应漏 Byte Count）→ §3.3.13/§3.3.11 修复（**R4 更正**：M2-CRIT-2 方向错误——FC 0x11 响应规范中**无 Byte Count 字段**，v2.0.0 加的字段本身多余，见 §11.5 R4-H2）
- M2-HIGH-1（UnitID omitempty 冲突）→ `*uint8` 方案（§5.1）
- M2-HIGH-2（FC 0x0B/0x0C 未规格化）→ §3.3.7/§3.3.8 补齐
- M2-HIGH-3（10 个 FC 无正向用例）→ T-015~T-024 补齐
- M2-HIGH-4（异常码 0x07 缺失）→ §2.5 恢复
- R1-C1~C4（S8/S9/S10/S13 的 Length 算术错误）→ §6 修正为 0x0007/0x0011/0x0008/0x00FD
- R1-C5（FC 0x14 响应 item 漏 Byte Count）→ §3.3.12 修复（**R3 更正**：该字段规范语义为 File Response Length=1+2×RL 而非 Byte Count，R1-C5 的字段名有误，见 §11.4 R3-C1）
- R1-C6（FC 0x16 公式错误）→ §3.3.14 修正为 (Cur AND A) OR (O AND ~A)
- R1-C7（T-018 Byte Count=8 矛盾）→ 改为 0x0A
- R1-H1（豁免规则优先级）→ §8.1 V-103
- R1-H2（WriteValue 0/1 映射）→ §8.2 V-116 + Plan 阶段映射
- R1-H3（WriteAddress 回退公式）→ StartingAddress+WriteQuantity（§5.2）
- R1-M1~M6（item 机制/负向缺失/异常码背书/广播细则/gopacket/MEI 高字节）→ §5.2/§8.2/§4.4/§10.3 修复

v2.0.0 文档规模：1548 行，15 个 HexDump 场景（S1-S15），152 条测试用例（T-001~T-140 + 12 条 b 后缀）。

### §11.2 v2.0.1（2026-08-05，R2 首轮复审修订，中间版本未独立成文）

**修订性质**：依据 `audit/13-modbus-audit-r2-v2.md`（14 项：2 CRITICAL + 2 HIGH + 6 MEDIUM + 4 LOW）首轮修复。v2.0.1 声称修复但实际存在修复不完整（R2-C1 的 `19 01` 错误、R2-C2 的 FC 0x2B 响应未规格化），v2.0.2 全部修复完成（详见 §11.3）。**v2.0.1 为中间版本（同日轮转，未独立成文）**，其修复内容与 v2.0.2 合并记录；文档 §4-§11 在 v2.0.1 之后丢失、于 v2.0.2 重建（修复 L-2）。

### §11.3 v2.0.2（2026-08-05，R2 复审全部修复 + 结构重建）

**修订性质**：v2.0.1 之后文档 §4-§11 丢失重建。本版为最终版，**R2 全部 14 项问题修复**，并修复 R1 的 2 项残留（R1-C5 的 §8.4 公式、R1-H1 的 0x99 幂等语义）：

#### §11.3.1 R2 CRITICAL 修复（2 项）

| 审计 ID | 修复内容 |
|---------|----------|
| R2-C1 | S14（§6.15）与 T-053b（T-201）响应 PDU 改为 `99 01`：0x99\|0x80=0x99（bit7 已置位 OR 幂等），不是 0x19。§1.3 豁免条款补充"异常响应与请求功能码字节相同"的独特语义；与 T-025 的 `C1 01`（0x41\|0x80=0xC1 正常叠加）自洽对照 |
| R2-C2 | §3.3.17 增加 FC 0x2B 响应 PDU 完整字节表（MEI Type + Read Device ID Code + Conformity Level + More Follows + Next Object ID + Object Count + Object 三元组）；T-025/T-202 按完整结构断言；§8.4 FC 0x2B 行补长度公式 |

#### §11.3.2 R2 HIGH 修复（2 项）

| 审计 ID | 修复内容 |
|---------|----------|
| R2-H1 | FC 0x08 子功能上限 0x0018 → 0x0013（§3.3.6/§8.2 V-117），0x0005-0x0009 标注保留；T-063/T-150 验证 0x0013 合法，T-113/T-204 验证 0x0014 拒绝。（**R3 更正**：R2-H1 方向本身有误——0x0013 是 Return IOP Overrun Count 而非上限，0x0014=Clear Overrun Counter and Flag、0x0015=Get/Clear Modbus Plus Statistics 均为合法子功能；正确上限为 0x0015，见 §11.4 R3-H1） |
| R2-H2 | 删除 T-064/T-108 两条不可达断言（"ResponseValues 覆盖请求"）；§4.1 明确 ResponseValues 与 Values 完全独立、无互斥交互；新增 T-205 验证独立性 |

#### §11.3.3 R2 MEDIUM 修复（6 项）

| 审计 ID | 修复内容 |
|---------|----------|
| R2-M1 | T-024 改为"公式语义（文档级）"并明确"实现不执行该公式，无对应实现测试"（§3.3.14 标注）；不再声称 T-024b 验证实现公式 |
| R2-M2 | §8.4 表头声明"长度均为 FC 之后字节（不含 FC）"；FC 0x15 行改为 "1 + Σ(7+2×RL)"；示例核对给出 T-021 的完整推算（ResponseValues=12B，echo 成立）。（**R3 更正**：FC 0x15 请求 item 结构按规范应为"item 内 Byte Count(1) + RefType(1) + File(2) + Record(2) + RecLen(2) + Record Data"，item 总长 = 8 + 2×RL，R2-M2 的 7+2×RL 遗漏了 item 首字节的 Byte Count 字段，见 §11.4 R3-C2）。（**R4 更正**：R3 更正本身方向错误——item 首字节是 Reference Type=0x06 而非 Byte Count，item 总长应为 7+2×RL，R2-M2 的 7+2×RL 本来就是对的，见 §11.5 R4-C1） |
| R2-M3 | T-007/T-124 补充断言 Length=0x00FD=253、PDU=252B 为合法上限；§9.3 增加"PDU=253 合法 / 254 非法"边界说明；T-158 覆盖 FC 0x10 qty=123 同界 |
| R2-M4 | §3.3.11 统一典型响应示例并标注配置来源（S8 用 RV=[0x03,0x01,0xFF,0xAA,0xBB]，T-019 用 5 字节 RV）；示例冗余一致性声明 |
| R2-M5 | T-118 改为"item 内 Record Length=0 → Validate 拒绝（record length must be >= 1）"的语义校验（§8.2 V-114/V-115），不再声称"item 长度为 0" |
| R2-M6 | §5.2 注明"WriteAddress 回退公式按 uint16 模运算回绕"；T-157 新增 StartingAddress=0xFFFF + WriteQuantity=3 → WriteAddress=2 |

#### §11.3.4 R2 LOW 修复（4 项）

| 审计 ID | 修复内容 |
|---------|----------|
| R2-L1 | §1.3 支持集显式列出不支持码（0x09/0x0A/0x0D/0x0E/0x12/0x13/0x19-0x2A）；T-083~T-088 覆盖 0x09/0x0A/0x0D/0x12/0x13/0x20 |
| R2-L2 | §2.6 明确"PDU=253 时 Length=254、报文=260 为理论最大值"；§9.3 说明 252→253 跳变由 T-007/T-124 覆盖；上限 253 的说明与 S13（PDU=252）关系明确 |
| R2-L3 | T-030 与 T-132 标注"与 T-030 等价"（FC 0x18 FIFO Count=31，§7.4 与 §7.15 各一条） |
| R2-L4 | §7.8 矩阵与用例编号统计修正：205 条 = T-001~T-205（含 T-089 的"异常码 0x00 接受"特殊语义）；独立用例数与编号数一致 |

#### §11.3.5 章节结构

| 章节 | 内容 | 状态 |
|------|------|------|
| §1 | 协议概述（支持集/豁免规则/不变式） | 保留（v2.0.0） |
| §2 | 数据类型与编码（异常码表/数量上限） | 保留（v2.0.0） |
| §3 | 消息结构（19 个 FC PDU 格式 + 异常响应） | 保留（v2.0.0），§3.3.17 补充响应表（R2-C2） |
| §4 | 状态机（事务/多事务/TCP 连接/广播/响应推导） | 重建（v2.0.2） |
| §5 | 配置类型定义（MODBUSConfig/MODBUSOperation） | 重建（v2.0.2） |
| §6 | 包序列场景（HexDump S1-S15） | 重建（v2.0.2），全部 Length 逐字节核算 |
| §7 | 测试用例（T-001 ~ T-205 + R4 追加 T-095b~T-095l/T-117b/T-119b） | 重建（v2.0.2），205 条 + R4 追加 13 条（修复 R4-M3/H4） |
| §8 | Validate 规则（V-001 ~ V-122） | 重建（v2.0.2） |
| §9 | 错误处理（异常响应/Validate 错误/边界/工具链） | 重建（v2.0.2） |
| §10 | 扩展字段映射 | 重建（v2.0.2） |
| §11 | 修订记录 | 重建（v2.0.2） |

#### §11.3.6 关键不变量确认（v2.0.2）

1. MBAP 头 7 字节：TID(2B BE) + PID(2B BE=0x0000) + Length(2B BE) + Unit ID(1B) ✓
2. **Length = 1(Unit ID) + PDU 长度**（含功能码），全部 15 个 HexDump 场景逐字节核算 ✓
3. PDU 最小 1 字节（仅 FC）、最大 253 字节；MBAP+PDU 总长 ≤ 260 字节 ✓
4. 异常响应 FC = 原 FC | 0x80（0x99|0x80=0x99 幂等，R2-C1）✓
5. 19 个 FC 全覆盖（支持集 §1.3 = §8.1 V-101 一致）✓
6. 10 个合法异常码（01-08, 0A, 0B，含 0x07）✓
7. FC 0x08 子功能 0x0000-0x0015（0x0005-0x0009 保留；0x0014/0x0015 合法，修复 R3-H1）✓
8. FC 0x2B 响应含 MEI + Code + Conformity + More Follows + Next Object ID + Object Count + Object 三元组 ✓
9. FC 0x11 响应无 Byte Count（首字节即 Slave ID）；FC 0x14 响应 item 含 File Response Length（=1+2×RL，修复 R3-C1）；FC 0x15 请求 item 无 item 内 Byte Count（首字节=Reference Type=0x06，item 总长=7+2×RL，修复 R4-C1）与 Record Data ✓
10. UnitID 用 `*uint8`（nil→1，0=广播），广播仅写功能码合法 ✓
11. 全部多字节字段 big-endian；位数据低地址字节先 + LSB 优先 ✓

### §11.4 v2.0.3（2026-08-05，R3 复审修订）

**修订性质**：依据 `audit/13-modbus-audit-r3-v2.md`（7 项：1 CRITICAL + 2 HIGH + 2 MEDIUM + 2 LOW）全部修复。R3 审计重点复核了前轮"已修复"项的规范符合性，发现 R2 修复方向性错误 2 处（R2-H1 的子功能上限、R2 的 FC 0x14 响应 item 语义）与残留自洽性问题 5 处。全部 15 个 HexDump 与修改的 T-019/T-020/T-021/T-055 示例逐字节核算。

#### §11.4.1 R3 CRITICAL 修复（1 项）

| 审计 ID | 修复内容 |
|---------|----------|
| R3-C1 | FC 0x14 响应 item 字段语义修正：首字节为 **File Response Length(1) = 1 + 2 × Record Length**（含 RefType 在内的记录数据字节数，非"Byte Count"、非"Record Length×2"），item 结构 = File Response Length + RefType(0x06) + Record Data，**不含 File Number/Record Number**（MB-ASYM-TCP §6.14 表 31 / pymodbus file_message.py）。同步修正：§1.5 不变量 9、§3.3.12 响应表、§4.5、§8.4 公式与示例核对、§10.3、T-020（响应 `14 06 05 06 1234 5678`，File Response Length=0x05）、T-186（tshark item 结构断言） |
| R3-C2 | FC 0x15 请求 item 首字节补 **Byte Count(1) = 7 + 2 × Record Length**（含 RefType 在内的 item 内容总长；MB-ASYM-TCP §6.15 表 35 / pymodbus file_message.py）。item 总长由 7+2×RL 更正为 8+2×RL，Record Length 偏移 5-6 → 6-7。同步修正：§3.3.13 示例（`15 0C 0B 06 0001 0000 0002 1234 5678`：外层 Byte Count=0x0C=12=item 总长、item 内 Byte Count=0x0B=11，PDU=14B、MBAP Length=15，逐字节核算自洽）、T-021（Values 首字节补 0x0C）、§8.2 V-115、§8.4 FC 0x15 公式与示例核对、§10.3、§5.2 注释；§11.3.3 R2-M2 历史条目加 R3 更正注 |

#### §11.4.2 R3 HIGH 修复（2 项）

| 审计 ID | 修复内容 |
|---------|----------|
| R3-H1 | FC 0x08 子功能上限 0x0013 → **0x0015**：0x0014=Clear Overrun Counter and Flag、0x0015=Get/Clear Modbus Plus Statistics 均为合法子功能（MB-ASYM-TCP §6.8 / pymodbus diag_message.py），0x0013 是 Return IOP Overrun Count 而非上限，0x0016-0xFFFF 保留。**R2-H1 修复方向本身有误（v2.0.1 的 0x0018 也不对）**。同步修正：§3.3.6 子功能表（补 0x0014/0x0015/0x0016-0xFFFF 行）、§5.2 SubFunction 注释、§3.3.17 MEI 编码规则注释、§8.2 V-117（错误消息改为 `sub_function must be 0x0000-0x0015`）、§9.2、T-064（0x0013 合法改注）、T-113（改为 0x0016 拒绝）、T-150（改为 0x0015 最大合法）、T-203（0x0013 合法改注）、T-204（改为 0x0014 合法）；§11.3.2 R2-H1 历史条目加 R3 更正注、§11.3.6 不变量 7 更新 |
| R3-H2 | FC 0x0C 响应字段顺序核对：**Status(2) → EventCount(2) → MessageCount(2)**（MB-ASYM-TCP §6.6 表 10 / pymodbus other_message.py）。核对结论：v2.0.2 的 §3.3.8/§4.5/§8.4/§10.3 表述顺序与 T-055 期望字节 `FFFF 0064 000A`（EventCount=0x0064=100, MessageCount=0x000A=10）均与规范一致，无字节序错误；本次在 §3.3.8（含依据注）、§4.5、§8.4、§10.3 四处显式标注"顺序依规范 §6.6 表 10"，消除 R1-C7 修复后残留的顺序表述歧义，T-055 配置注释明确 EventCount=100/MessageCount=10 对应关系 |

#### §11.4.3 R3 MEDIUM 修复（2 项）

| 审计 ID | 修复内容 |
|---------|----------|
| R3-M1 | FC 0x2B MEI Type 0x0E 标注更正：0x0E 是 **Read Device Identification 的响应侧 MEI Type**（规范 §6.21 表 42 中 0x0D=请求、0x0E=响应；pymodbus mei_message.py 中 ReadDeviceInformationRequest.sub_function_code=0x0E 即请求侧实际编码），**"CANopen General"为 CiA 309 扩展、V1.1b3 正文未定义**。同步修正：§3.3.17 MEI Type 表、§1.4 不实现清单、§5.2 SubFunction 注释、§8.2 V-118、T-026（改为"0x0E 响应侧合法性"）、§10.4 mei_type 行 |
| R3-M2 | FC 0x11 响应示例逐字节核算修正：①§3.3.11 示例第二行核算确认原字节 `11 04 01 FF AA BB` 自洽（BC=0x04=1+1+2），审计建议的 `11 04 01 FF AA BB CC` 反而不自洽（BC=4 与 5B 数据矛盾），故保留原字节并加核算注释；②逐字节核算发现 v2.0.2 隐藏 bug：T-019 与 §6.9 S8 的 `11 03 01 FF AA BB` 中 BC=0x03 与 4 字节数据（SlaveID+RunInd+Additional 2B）矛盾，BC 值更正为 0x04（RV/ResponseValues 首字节 0x03→0x04，Length=7 不变）；③T-019 的 RV 笔误 `0xAA,BB` 补逗号 |

#### §11.4.4 R3 LOW 修复（2 项）

| 审计 ID | 修复内容 |
|---------|----------|
| R3-L1 | §4.1 关键设计点新增第 4 条：**支持集内合法 FC 配 ExceptionCode 时，请求 PDU 仍按该 FC 正常构造（含 Values 透传、外层 Byte Count），仅响应 PDU 替换为异常 PDU**（§1.3 豁免路径仅适用于 FC 不在支持集时）；T-032 补充请求 PDU 断言（`03 0000 0001`） |
| R3-L2 | 版本时间线统一：文档头新增版本时间线说明（v2.0.0 重写与 v2.0.1/v2.0.2 复审同日完成、v2.0.1 为中间版本未独立成文、§4-§11 在 v2.0.2 重建）；§11.2 明确"v2.0.1 为中间版本未独立成文"；文档头日期行与版本标记同步为 v2.0.3 |

### §11.5 v2.0.4（2026-08-05，R4 复审修订）

**修订性质**：依据 `audit/13-modbus-audit-r4-v2.md`（12 项：1 CRITICAL + 4 HIGH + 3 MEDIUM + 4 LOW）全部修复。R4 审计以**本机 tshark 3.6.14 实测 12 种 wire 形态**为最终裁判交叉核实（文档自认"tshark 为最终裁判"，§7.7），发现 R3 轮 2 处方向性错误（R3-C2/FC 0x15 item、R3-M1/MEI Type 语义）与自 v2.0.0 起历经两轮未发现的 FC 0x11 响应多余 Byte Count 字段（H-2）。修改的 HexDump（S8）与示例（§3.3.11/§3.3.13/§8.4 核对、T-019/T-021/T-025）逐字节核算。

#### §11.5.1 R4 CRITICAL 修复（1 项）

| 审计 ID | 修复内容 |
|---------|----------|
| R4-C1 | FC 0x15 请求 item 结构回退（R3-C2 方向错误）：item 内**无 Byte Count 字段**，首字节即 Reference Type=0x06，item = RefType(1) + File Number(2) + Record Number(2) + Record Length(2) + Record Data(2×RL)，item 总长 = **7 + 2×RL**（恢复 v2.0.2 的 R1-M1 步进），Record Length 偏移 6-7 → 5-6，外层 Byte Count = Σ(7+2×RL)。tshark 3.6.14 实测：规范形式 `15 0B 06 0001 0000 0002 1234 5678` 正常解析（Byte Count=11、RefType=6、File=1、Record=0、WordCount=2、Data）；v2.0.3 形式 `15 0C 0B 06 ...` 被标记 Malformed；pymodbus `WriteFileRecordRequest.encode` 为 `>BHHH` 直接写 0x06。同步修正：§1.5 不变量 9、§3.3.13（表格与示例 `15 0B ...`，PDU=13B、MBAP Length=14=0x000E）、§4.5、§5.2 Values 注释、T-021（Values 首字节 0x0C→0x0B）、V-115（偏移 5-6、步进 7+2×RL）、§8.4 FC 0x15 公式（1+Σ(7+2×RL)）与示例核对、§10.3、T-187（tshark 无 Malformed + Reference Type=6 字段级断言）；§11.3.3 R2-M2 历史条目加 R4 更正注 |

#### §11.5.2 R4 HIGH 修复（4 项）

| 审计 ID | 修复内容 |
|---------|----------|
| R4-H1 | FC 0x2B MEI Type 语义回退（R3-M1 方向错误）：规范 §6.21 表 42 中 0x0D=**CANopen General（CiA 309）**、0x0E=**Read Device Identification**——两者都是请求侧 MEI Type，不存在"0x0D=请求/0x0E=响应侧"的区分（Read Device Identification 的响应与请求同用 0x0E）。tshark 3.6.14 实测：`2B 0D 01 00` → "MEI type: CANopen Request/Response (13)"；`2B 0E 01 00` → "MEI type: Read Device Identification (14)"。FC 0x2B 合法 MEI Type 改为**仅 0x0E**（0x0D=CANopen 不实现），请求 `2B 0E 01 00`、响应 `2B 0E 01 01 00 00 01 00 04 41 42 43 44`。同步修正：§1.4、§3.3.17（MEI Type 表、编码规则注、请求/响应表）、§4.5、§5.2 SubFunction 注释、§5.3 SubFunction 默认值行、T-025/T-026（0x0D 拒绝）、T-117/T-202、V-118、§9.2 错误消息（`must be 0x000E`）、§10.4 mei_type 行 |
| R4-H2 | FC 0x11 响应删除 Byte Count 字段（新问题，v2.0.0 起 M2-CRIT-2 与 R3-M2 两轮均未发现）：规范 §6.11 中 FC 0x11 响应字段顺序为 Slave ID(1) + Run Indicator(1) + Additional Data(N)，**无首字节 Byte Count**（Byte Count 仅存在于 Modbus RTU 的 FC 0x11 响应）；tshark 3.6.14 实测 `11 04 01 FF AA BB` 显示 "Data: 0401ffaabb" 无 Byte Count 字段；pymodbus `ReportSlaveIdResponse` 编码同样无 Byte Count。示例改为 `11 01 FF AA BB`（Slave ID=0x01、Run=0xFF、Additional=AA BB；PDU=5B、Length=6=0x0006）。同步修正：§1.5 不变量 9、§3.3.11 响应表与示例、§4.5、§6.1 S8 索引、§6.9 S8（响应 7+5=12 字节）、T-019、T-080、T-185（断言 tshark "Report Server ID" 且不含 "Byte Count"）、§8.4 0x11 行（2+N）、§10.3；§11.1 M2-CRIT-2 历史条目加 R4 更正注 |
| R4-H3 | §8.3 背书区间列歧义修正：表格由 3 列（无 ExcCode / 配 ExcCode∈{0x01-0x03} / 配 ExcCode∈{0x04-0x0B}）精简为 2 列（无 ExcCode / 配任意合法 ExcCode），并在规则文字中显式声明"不同异常码区间行为完全相同，Validate 只检查 ExceptionCode 合法且非零，不区分区间"，消除对实现者的区间分支误导 |
| R4-H4 | FC 0x18 响应长度自洽规则补充：定义"RV 中值字节数必须 = 2 × FIFO Count"的 Validate 校验（错误消息 `response_values length must match FIFO count`），Byte Count 字段由 planner 按 2+2×FIFO Count 重新计算（用户无需手工维护）。同步修正：§3.3.16 约束、§4.5 0x18 行、V-119、§8.4 0x18 行、T-062/T-131（FIFO Count=0 自洽注）、T-119b（新负向用例）、§9.2 错误消息表、§7.8 矩阵 |

#### §11.5.3 R4 MEDIUM 修复（3 项）

| 审计 ID | 修复内容 |
|---------|----------|
| R4-M1 | FC 0x08 子功能 0x0015 注记：tshark 3.6.14 实测 0x0014 正常识别（Clear Overrun Counter and Flag (20)）、0x0015 显示 "Unknown (21)"（Wireshark 3.6 值表未收录）。§3.3.6 加注"集成用例（T-181~T-200）不覆盖 0x0015，如需 wire 级验证须用更高版本 tshark 或自写解析器"；§9.5 工具链声明同步；T-150 加注；T-204 佐证 0x0014 的 tshark 识别 |
| R4-M2 | 集成用例字段级断言加强（T-181~T-200）：T-185 改为断言无 Byte Count 字段（配合 R4-H2）且 Data 与 `01ffaabb` 匹配；T-186 增加 File Response Length=0x05（=1+2×RL）具体值断言；T-187 增加 Reference Type=6 字段断言与"不含 Malformed"断言；其余用例保持字符串级断言（涉及字段值断言以 tshark 实测为准） |
| R4-M3 | 广播负向用例参数化：新增 T-095b~T-095l 共 11 条（广播 + FC 0x02/0x03/0x04/0x07/0x08/0x0B/0x0C/0x11/0x14/0x18/0x2B 均拒绝），与既有 T-094（0x01）/T-095（0x17）合计覆盖全部读类 FC 的广播拒绝路径；§7.8 矩阵同步 |

#### §11.5.4 R4 LOW 修复（4 项）

| 审计 ID | 修复内容 |
|---------|----------|
| R4-L1 | 依据链删除 RFC 7540（HTTP/2 规范，与 Modbus TCP 无内容关联，系模板遗留）：文档头"规范来源"删除"RFC 7540（信息性）"，§1.1 规范依据改为"TCP 传输通用约定遵循 RFC 793（Transmission Control Protocol）" |
| R4-L2 | 修订记录与正文同错修正（随 R4-C1 一并）：§11.4.1 R3-C2 的"修复声明"在 §11.5.1 R4-C1 中显式标注回退，§11.3.3 R2-M2 历史条目的 R3 更正注追加 R4 更正注（"R2-M2 的 7+2×RL 本来就是对的"），实现者不会误以为该字段已获规范确认 |
| R4-L3 | T-089 归类与 §2.5 表述矛盾修正：§2.5 改为"0x00 在配置层视为'未设置异常'，不报错（V-122），与异常响应无关"；T-089 标注归入正向语义并同步澄清（行为不变，消除与 V-122 的冲突表述） |
| R4-L4 | §7.8 对照矩阵补引用：新增"§7.4 边界（T-121~T-160）"行（T-126 qty=1968、T-128 qty=123、T-130 WriteBC=242、T-132 FIFO=31、T-158/T-159 PDU 边界）；§8.4 行补充 T-062/T-131（FIFO Count=0）；§4.4 行更新为 T-094~T-095l；重复用例 T-122/T-132 保留（与 T-003/T-030 等价，R2-L3 已承认），矩阵注明确说明 |

---

**文档结束（v2.0.4，2026-08-05）**
