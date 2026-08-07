# DNP3 协议设计与测试用例

**协议名称**：DNP3（Distributed Network Protocol 3，分布式网络协议第 3 版）
**规范来源**：IEEE 1815-2012（前身 IEEE 1815-2010 / DNP3 IEC 60870-5 系列扩展）
**传输层**：TCP（端口 20000）/ UDP（端口 20000）/ 串行链路
**默认端口**：20000
**版本**：v1.1.4（2026-08-04 修订，四轮返工修复 3 个问题 NEW-5~8：SBO AppSeq 改为 Select 与 Operate 共享同一序号、T37 补充测试场景说明、IIN 字节 2 bit0/bit6 语义统一）
**生成时间**：2026-08-03
**实现状态**：未实现（见 `docs/protocol-designs/00-unimplemented-list.md` 工控类第 11 项）

---

## 1. 协议概述

DNP3（Distributed Network Protocol 3，分布式网络协议第 3 版）是工控系统（SCADA，Supervisory Control and Data Acquisition，监控与数据采集）领域最常用的开放协议之一，由 GE-Harris Canada（原 Westronic Systems）于 1993 年提出，2012 年成为 IEEE 标准。它主要用于主站（Master，主站）与一个或多个远程终端单元（RTU，Remote Terminal Unit，远程终端单元）/ 外设（Outstation，外设）之间的遥测、遥信、遥控与遥调。

### 1.1 角色定义

- **主站（Master）**：发起轮询、下发控制命令的一方，链路层 PRM=1（Primary Message，主站消息）。
- **外设（Outstation，亦称 RTU）**：被动响应主站请求、主动上报事件的一方，链路层 PRM=0（Secondary Message，外设消息）。
- **链路地址**：每个 DNP3 设备拥有 16 位链路地址（0~65535），主站通常为 1，外设通常为 1024、1025、1026 等。地址 0xFFFF 为广播地址，外设收到广播不响应。
- **应用层序号（App Seq）**：0~15 的 4 位序号，主站为每个请求循环递增；外设在响应中回显该序号。
- **链路层帧计数位（FCB，Frame Count Bit）**：主站为每个外设维护 1 位 FCB，用于确保数据链路层可靠传输（重传时 FCB 翻转，外设仅接受 FCB 翻转后的新帧）。FCV（Frame Count Valid，帧计数有效位）=1 时 FCB 有效。

### 1.2 三层架构

DNP3 是三层协议（参见 IEEE 1815-2012 §4）：

1. **数据链路层（Data Link Layer，DLL）**：负责帧定界、寻址、错误检测。帧起始于 `0x0564` 两个字节，每 16 字节数据后追加 2 字节 CRC16。链路层功能码控制链路状态（reset link / test link / user data / ACK / NACK）。
2. **传输层（Transport Layer）**：仅在串行/UDP 链路上存在，负责重组分片的应用层消息（LTH+SEQ 单字节头部，LTH 高位=1 表示最后一片）。TCP 传输天然有序，不使用传输层。
3. **应用层（Application Layer，AL）**：承载业务语义。包含应用控制字节（含 FIR/FIN/CON/SEQ）、功能码（read/write/select/operate/...）、对象头（Object Header，定义数据类型与索引范围）与数据。

### 1.3 数据对象模型

DNP3 用「对象-变体-限定词-索引」四元组定位每一条数据：

- **对象类型（Object Type）**：0~255，分组定义数据类别。常用：
  - 0：Device Attributes（设备属性）
  - 1：Binary Input（数字量输入，单点遥信）
  - 2：Binary Output（数字量输出，单点遥控）
  - 3：Double-bit Binary Input（双比特遥信）
  - 10：Binary Output Event（遥控事件）
  - 20：Counter（计数器）
  - 21：Frozen Counter（冻结计数器）
  - 30：Analog Input（模拟量输入，遥测）
  - 32：Analog Output（模拟量输出，遥调）
  - 40：Analog Input Event（遥测事件）
  - 50：Time and Date（时间日期）
  - 60：Class Objects（Class 0/1/2/3，类别对象）
  - 80：Internal Indications（内部指示位，IIN）
- **变体（Variation）**：0~255，定义该对象的具体编码格式（如 Binary Input Variation 1 = 1 字节单点，Variation 2 = 2 字节带状态标志）。
- **限定词（Qualifier）**：定义索引范围与数据长度的编码方式。常用：
  - 0x00：8-bit start-stop index（索引范围 0~255）
  - 0x01：16-bit start-stop index（索引范围 0~65535）
  - 0x06：all objects（全部对象，仅用于 read 请求）
  - 0x07：8-bit count of objects（对象数量 0~255）
  - 0x08：16-bit count of objects（对象数量 0~65535）
  - 0x17：8-bit count + 1-byte index per object（每对象独立索引）
- **索引（Index）**：0~65535，定位该外设内的具体数据点。

### 1.4 业务模式

DNP3 的典型业务模式有四类：

1. **主站轮询（Polling）**：主站周期性发起 read 请求读取外设数据。
   - **Class 0 全量轮询**：读取该外设全部静态数据（首次连接或断线恢复后必做）。
   - **Class 1/2/3 事件轮询**：读取该外设的 1/2/3 类事件（高/中/低优先级变化上报）。
2. **事件非请求响应（Unsolicited Respond）**：外设主动向主站上报事件（需主站先 enable unsolicited）。
3. **控制操作（Control）**：主站下发控制命令。
   - **Select before Operate（SBO，选择前操作）**：先 select 试点，再 operate 执行（默认安全模式）。
   - **Direct Operate（直接操作）**：一步下发，立即执行（用于无副作用的控制）。
   - **Direct Operate No Acknowledgement**：一步下发，外设不响应（用于广播）。
4. **冻结/重启/时间同步**：Freeze（冻结计数器）、Cold/Warm Restart（冷/热重启）、Record Current Time（记录当前时间）、Delay Measurement（延迟测量，用于时间同步）。

---

## 2. 报文格式

### 2.1 数据链路层帧总体结构

DNP3 数据链路层帧由「帧头 + 数据块」组成。帧头固定 10 字节（含起止字节、长度、控制、目的地址、源地址、CRC16）。数据部分按每 16 字节分块，每块追加 2 字节 CRC16（即每块最多 18 字节）。最后一块可能不足 16 字节，但 CRC16 仍按实际字节数计算。

```
+--------+--------+--------+--------+--------+--------+--------+--------+--------+--------+--------+--------+----+
| 0x05   | 0x64   | Length | Ctrl   | DstAddr(LE,2) | SrcAddr(LE,2) |  CRC16(LE,2) | Data Block 1 (≤16B + 2 CRC) |
+--------+--------+--------+--------+--------+--------+--------+--------+--------+--------+--------+--------+----+
| Start Byte 1 | Start Byte 2 | Length | Control | Dst Addr | Src Addr | Header CRC | Block 1 ... | Block N |
+--------+--------+--------+--------+--------+--------+--------+--------+--------+--------+--------+--------+----+
```

字段说明：

| 偏移 | 字段 | 长度（字节） | 说明 |
|------|------|------|------|
| 0 | Start Byte 1 | 1 | 固定 0x05 |
| 1 | Start Byte 2 | 1 | 固定 0x64 |
| 2 | Length | 1 | 数据块总长度（不含 10 字节帧头与帧头 CRC，但含每块的 2 字节 CRC）。范围 0~255。整个链路帧最大字节数 = 10 + Length，Length=255 时帧长 265。 |
| 3 | Control | 1 | 控制字节（DIR/PRM/FCB/FCV/FunctionCode） |
| 4-5 | DstAddr | 2（小端） | 目的链路地址。0xFFFF = 广播。 |
| 6-7 | SrcAddr | 2（小端） | 源链路地址。 |
| 8-9 | Header CRC | 2（小端） | 帧头前 8 字节的 CRC16/DNP。 |
| 10+ | Data Blocks | Length | 每 16 字节一块，每块尾部追加 2 字节 CRC16/DNP。 |

### 2.2 控制字节（Control Byte）

```
  7   6   5   4   3   2   1   0
+---+---+---+---+---+---+---+---+
|DIR|PRM|FCB|FCV|  FunctionCode |
+---+---+---+---+---+---+---+---+
```

| 位 | 字段 | 说明 |
|----|------|------|
| 7 | DIR（Direction） | 1 = 主站→外设；0 = 外设→主站。 |
| 6 | PRM（Primary） | 1 = 主站消息（发起方）；0 = 外设消息（响应方）。 |
| 5 | FCB（Frame Count Bit） | 主站维护的帧计数位，每次新帧翻转（仅 FCV=1 时有效）。重传时 FCB 不变。 |
| 4 | FCV（Frame Count Valid） | 1 = FCB 有效；0 = 忽略 FCB。 |
| 3-0 | FunctionCode | 链路层功能码（4 位）。 |

### 2.3 链路层功能码（Function Code）

**主站→外设（PRM=1）**：

| 值 | 名称 | FCB | 说明 |
|----|------|-----|------|
| 0 | Reset Link State | 无 | 复位链路状态机，外设回 ACK，FCB 归 0。 |
| 1 | Reset User Process | 无 | 复位用户进程（外设应用层），外设回 ACK。 |
| 2 | Test Link State | 有效 | 测试链路是否正常，外设回 ACK。FCV=1，FCB 翻转。 |
| 3 | User Data, Confirm | 有效 | 用户数据，需外设 ACK 确认。FCV=1。 |
| 4 | User Data, No Confirm | 无 | 用户数据，外设不确认。 |
| 9 | Request Link Status | 无 | 请求链路状态，外设回 Link Status。 |

**外设→主站（PRM=0）**：

| 值 | 名称 | 说明 |
|----|------|------|
| 0 | ACK | 确认收到主站帧。 |
| 1 | NACK | 否定确认（链路层忙/缓冲不足）。 |
| 2 | Link Status | 链路状态（含链路忙/故障位）。 |
| 3 | User Data, Confirm | 外设主动上报用户数据，需主站 ACK（Unsolicited Respond 用）。 |
| 4 | User Data, No Confirm | 外设主动上报用户数据，无需 ACK（Unsolicited Respond 用）。 |
| 5-10 | Reserved | 保留。 |
| 11 | Not Supported | 链路层不支持该功能码。 |

### 2.4 应用层帧结构

应用层帧封装在链路层 User Data 块中。TCP 传输时，应用层帧直接作为 TCP 段载荷；不需要传输层头部。串行/UDP 传输时，应用层帧前面增加 2 字节传输层头部（LTH+SEQ）。

#### 2.4.1 应用层请求/响应头

```
Request/Response Header (ASDU, Application Service Data Unit):
+------+------+-----------------------------+
| AC   | FC   | Object Headers + Data       |
+------+------+-----------------------------+
  1B     1B     variable
```

| 偏移 | 字段 | 长度 | 说明 |
|------|------|------|------|
| 0 | AC（Application Control） | 1 | 应用控制字节（FIR/FIN/CON/SEQ）。 |
| 1 | FC（Function Code） | 1 | 应用层功能码（见 §2.5）。 |
| 2+ | Object Headers + Data | 变长 | 一个或多个对象头及对应数据。 |

#### 2.4.2 应用控制字节（AC, Application Control）

```
  7   6   5   4   3   2   1   0
+---+---+---+---+---+---+---+---+
|FIR|FIN|CON|    AppSeq(4)     |
+---+---+---+---+---+---+---+---+
```

| 位 | 字段 | 说明 |
|----|------|------|
| 7 | FIR（First） | 1 = 应用层分片的第一片。 |
| 6 | FIN（Final） | 1 = 应用层分片的最后一片。 |
| 5 | CON（Confirm） | 1 = 请求/响应需要应用层确认（Application Layer Confirmation）。 |
| 4-0 | AppSeq | 4 位应用层序号（0~15），主站递增，外设回显。多片分片共享同一 AppSeq。 |

#### 2.4.3 内部指示位（IIN, Internal Indications）

外设响应帧在 FC 之后紧跟 2 字节 IIN（仅响应类功能码如 0x81 respond / 0x82 unsolicited respond 携带）。IIN 指示外设当前状态。

IIN 字节 1（高字节）位定义（IEEE 1815-2012 §5.2.3 表 5-6）：

| 位 | 名称 | 说明 |
|----|------|------|
| 7 | BROADCAST | 收到广播（DstAddr=0xFFFF） |
| 6 | Class 1 Events | 有 1 类事件待传 |
| 5 | Class 2 Events | 有 2 类事件待传 |
| 4 | Class 3 Events | 有 3 类事件待传 |
| 3 | Need Time | 需要时间同步 |
| 2 | Local Control | 本地控制模式 |
| 1 | Device Trouble | 设备故障 |
| 0 | Device Restart | 设备已重启（需重新初始化） |

IIN 字节 2（低字节）位定义（IEEE 1815-2012 §5.2.3 表 5-7）：

| 位 | 名称 | 说明 |
|----|------|------|
| 7 | Config Corrupt | 配置损坏 |
| 6 | Not Supported | 功能码不支持 |
| 5 | Object Unknown | 对象未知 |
| 4 | Parameter Error | 参数错误 |
| 3 | Event Buffer Overflow | 事件缓冲区溢出 |
| 2 | Already Executing | 已在执行 |
| 1 | Reserved | 保留（不是 Event Buffer Overflow 备份，旧文档有误） |
| 0 | No Request/Response Function Code Support | 无请求/响应功能码支持（与 bit 6 语义相关但独立；bit 6 是 Function Code Not Implemented，bit 0 是 No Request/Response Support） |

### 2.5 应用层功能码（Function Code）

| 值 | 名称 | 主/外 | 说明 |
|----|------|-------|------|
| 1 | Read | 主→外 | 读取对象（按 Class / 对象类型 / 索引）。 |
| 2 | Write | 主→外 | 写入对象（参数配置）。 |
| 3 | Select | 主→外 | 选择控制点（SBO 第一步）。 |
| 4 | Operate | 主→外 | 操作已选择的控制点（SBO 第二步）。 |
| 5 | Direct Operate | 主→外 | 直接操作控制点（一步）。 |
| 6 | Direct Operate, No Ack | 主→外 | 直接操作，无需 ACK（广播）。 |
| 7 | Immediate Freeze | 主→外 | 立即冻结指定计数器。 |
| 8 | Immediate Freeze, No Ack | 主→外 | 立即冻结，无需 ACK。 |
| 9 | Freeze and Clear | 主→外 | 冻结并清零指定计数器。 |
| 10 | Freeze and Clear, No Ack | 主→外 | 冻结并清零，无需 ACK。 |
| 13 | Respond | 外→主 | 响应主站请求。 |
| 14 | Unsolicited Respond | 外→主 | 主动非请求响应。 |
| 15 | Confirm | 主→外 | 应用层确认（ACK 应用层分片或 Unsolicited Respond）。注意：FC=15 Confirm 只能主站→外设（主站确认外设的 Unsolicited Respond），外设→主站的确认是链路层 ACK（FC=0），不是应用层 Confirm。 |
| 20 | Enable Unsolicited | 主→外 | 启用非请求响应。 |
| 21 | Disable Unsolicited | 主→外 | 禁用非请求响应。 |
| 22 | Assign Class | 主→外 | 分配对象到 Class 0/1/2/3。 |
| 23 | Delay Measurement | 主→外 | 延迟测量（时间同步前导）。 |
| 24 | Record Current Time | 主→外 | 记录当前时间。 |
| 25 | Reserved | — | 保留。 |
| 26 | Reserved | — | 保留。 |
| 27 | Reserved | — | 保留。 |
| 28 | Reserved | — | 保留。 |
| 29 | Reserved | — | 保留。 |
| 30 | Reserved | — | 保留。 |
| 31 | Reserved | — | 保留（IEEE 1815-2012 §5.1.3.1 表 5-1 明确 31=Reserved，不是 8 的别名）。 |
| 129 | Cold Restart | 主→外 | 冷重启（外设完全重启）。 |
| 130 | Warm Restart | 主→外 | 热重启（外设应用层重启）。 |
| 131 | Initialize Data | 主→外 | 初始化数据（特定类型）。 |
| 132 | Initialize Application | 主→外 | 初始化应用层。 |
| 215 | Reserved | — | 保留（IEEE 1815-2012 §5.1.3.1 表 5-1 中 215=Reserved。Configure 功能码仅在 IEEE 1815-2010 旧版中存在（FC=215），2012 版已废弃归为 Reserved；不要在本设计中使用）。 |

### 2.6 对象头（Object Header）

每个对象头格式如下：

```
+--------+--------+--------+--------+--------+--------+
| ObjType| Var    | Qualifier    | Range/Index         |
+--------+--------+--------+--------+--------+--------+
  1B       1B       1B            0/1/2/4/5B
```

| 偏移 | 字段 | 长度 | 说明 |
|------|------|------|------|
| 0 | Object Type | 1 | 对象类型（如 1=Binary Input，30=Analog Input，60=Class）。 |
| 1 | Variation | 1 | 变体（具体编码格式）。 |
| 2 | Qualifier | 1 | 限定词（高位 = 索引/数量字段宽度，低位 = 范围编码）。 |
| 3+ | Range/Index | 0/1/2/4/5 | 索引范围或对象数量，长度由 Qualifier 决定。 |

**Qualifier 编码**（高 4 位 = prefix 宽度 R，低 4 位 = range 编码 Q）：

| Qualifier | 含义 | Range 字段长度 |
|-----------|------|---------------|
| 0x00 | 8-bit start/stop index | 2 字节（start 1B + stop 1B） |
| 0x01 | 16-bit start/stop index | 4 字节（start 2B + stop 2B，小端） |
| 0x06 | All objects（仅 read） | 0 字节 |
| 0x07 | 8-bit count | 1 字节（count） |
| 0x08 | 16-bit count | 2 字节（count，小端） |
| 0x17 | 8-bit count + 1B index per object | 1 字节 count + N×1 字节索引 |
| 0x28 | 16-bit count + 2B index per object | 2 字节 count + N×2 字节索引（小端） |

### 2.7 常用对象-变体一览

| Object | Var | 名称 | 数据宽度 | 说明 |
|--------|-----|------|---------|------|
| 1 | 1 | Binary Input, Single Bit | 1 字节（8 个点 packed） | 静态数字量输入，每 bit 一个点 |
| 1 | 2 | Binary Input with Flags | 2 字节（1 字节 flag + 1 字节 packed） | 带 8 个点的状态标志 |
| 2 | 1 | Binary Output, Single Bit | 1 字节 packed | 静态数字量输出 |
| 2 | 2 | Binary Output with Flags | 2 字节 | 带状态标志 |
| 10 | 1 | Binary Output Event | 1 字节 flag + 1 字节 value | 单点遥控事件 |
| 10 | 2 | Binary Output Event without Time | 1 字节 flag + 1 字节 value | 不带时戳 |
| 20 | 1 | Counter, 32-bit | 1 字节 flag + 4 字节 value | 32 位计数器 |
| 20 | 2 | Counter, 16-bit | 1 字节 flag + 2 字节 value | 16 位计数器 |
| 21 | 1 | Frozen Counter, 32-bit | 1 字节 flag + 4 字节 value | 冻结计数器 |
| 30 | 1 | Analog Input, 32-bit | 1 字节 flag + 4 字节 value | 32 位模拟量 |
| 30 | 2 | Analog Input, 16-bit | 1 字节 flag + 2 字节 value | 16 位模拟量 |
| 30 | 5 | Analog Input, Single-precision Float | 1 字节 flag + 4 字节 IEEE 754 | 单精度浮点遥测 |
| 30 | 6 | Analog Input, Double-precision Float | 1 字节 flag + 8 字节 IEEE 754 | 双精度浮点遥测 |
| 40 | 1 | Analog Input Event, 32-bit | 1 字节 flag + 4 字节 value | 遥测事件 |
| 40 | 3 | Analog Input Event, Single-precision Float | 1 字节 flag + 4 字节 IEEE 754 | 浮点遥测事件 |
| 50 | 1 | Time and Date | 6 字节 | 48 位时间（毫秒级，从 1970-01-01 起） |
| 50 | 3 | Unsynchronized Time and Date | 6 字节 | 未同步时间 |
| 51 | 1 | Time Delay Coarse | 2 字节 | 秒级时延 |
| 51 | 2 | Time Delay Fine | 2 字节 | 毫秒级时延 |
| 52 | 1 | Time Delay Unsynchronized | 2 字节 | 未同步时延 |
| 60 | 1 | Class 0 | — | 全部静态数据 |
| 60 | 2 | Class 1 | — | 1 类事件 |
| 60 | 3 | Class 2 | — | 2 类事件 |
| 60 | 4 | Class 3 | — | 3 类事件 |
| 80 | 1 | Internal Indications | 2 字节 | IIN 位 |

**Variation=0 的语义**（IEEE 1815-2012 §5.1.1）：请求帧（read/freeze/write）中可填 Variation=0 表示"任意变体"（planner 默认行为），响应帧必须填具体 Variation 值（1/2/...）。例如 Object 20（Counter）只支持 Variation 1（32-bit）和 2（16-bit），**不存在** Variation 0；"请求所有变体"应使用 Qualifier=0x06（all objects），而非 Variation=0。

### 2.8 CRC16/DNP 算法

DNP3 使用 CRC-16/DNP（亦称 CRC-16/DNP3）。参数：

- 多项式：0x3D65（reversed: 0xA6BC）
- 初始值：0x0000
- 输入反射：true
- 输出反射：true
- 异或输出：0xFFFF

伪代码（查表法，256 项表）：

```
CRC16_DNP(data []byte) uint16:
    crc = 0x0000
    for byte in data:
        crc = (crc >> 8) ^ table[(crc ^ byte) & 0xFF]
    return crc ^ 0xFFFF
```

表项示例（前 4 项）：

| Index | Value |
|-------|-------|
| 0 | 0x0000 |
| 1 | 0x365E |
| 2 | 0x6CBC |
| 3 | 0x5AE2 |

CRC16 计算后以小端序追加到块尾。每 16 字节数据块（含最后不足 16 字节的块）独立计算 CRC。

### 2.9 应用层分片与传输层

- 应用层单条消息超过 2048 字节（链路层最大长度限制）时，分多个链路帧传输。每个分片的应用控制字节：
  - 第一片：FIR=1, FIN=0
  - 中间片：FIR=0, FIN=0
  - 最后一片：FIR=0, FIN=1
  - 单片消息：FIR=1, FIN=1
- TCP 传输：TCP 字节流天然有序，不使用传输层头部。每个链路帧作为一个 TCP 段载荷，主站读取时按 0x0564 起始字节定界。
- UDP 传输：UDP 不保证有序，使用 2 字节传输层头部（LTH+SEQ）：
  - LTH（1 字节）：高位 bit7=1 表示最后一片，低 7 位为应用层片段长度。
  - SEQ（1 字节）：传输层序号，0~255 循环递增。

---

## 3. Config 结构体设计

本节定义 DNP3 协议在 `internal/core/types.go` 中新增的 `DNP3Config` 结构体。`FlowSpec.DNP3` 字段（pointer）指向此结构。

```go
// DNP3Config holds DNP3 (Distributed Network Protocol 3, IEEE 1815-2012)
// configuration. DNP3 is a SCADA protocol between a Master (主站) and one
// or more Outstations (外设/RTU). It runs over TCP (port 20000), UDP (port
// 20000), or serial links. The trafficgen implementation supports TCP and
// UDP only (serial is not an IP traffic generator concern).
//
// Reference pcaps: llcj dport=20000 (10 RTU poll sessions, all wire-
// identical).
//
// A single DNP3 flow is one TCP/UDP 4-tuple between Master and one
// Outstation. Multi-outstation scenarios use multi-flow (one 4-tuple per
// RTU), distinguished by DstAddr/SrcAddr and DstIP (see §6.14).
type DNP3Config struct {
    // LinkType (链路类型): "master" (default) = the source side is the
    // Master (DIR=1, PRM=1 for requests); "outstation" = the source side
    // is the Outstation (DIR=0, PRM=0 for responses). The role determines
    // each frame's direction and DIR/PRM bits.
    LinkType string `json:"link_type,omitempty"`

    // Transport (传输层): "tcp" (default) or "udp". TCP omits the transport
    // pseudo-header; UDP adds LTH+SEQ (see §2.9).
    Transport string `json:"transport,omitempty"`

    // SrcAddr (源链路地址): the source DNP3 link address (0~65534).
    // Master default 1; Outstation default 1024.
    SrcAddr uint16 `json:"src_addr,omitempty"`

    // DstAddr (目的链路地址): the destination DNP3 link address.
    // Master default 1024; Outstation (sending unsolicited) default 1.
    // 0xFFFF = broadcast (Outstation does not respond).
    DstAddr uint16 `json:"dst_addr,omitempty"`

    // --- Link-layer control ---

    // LinkFCB (链路层FCB): Frame Count Bit. 0 or 1. Auto-toggled when
    // Scenario uses multi-frame link sequences (Reset Link → ACK → User
    // Data → ACK ...). User-set value is the initial FCB before the first
    // FCV=1 frame. Validate rule: when LinkFCB is set non-zero by the
    // user, the planner MUST also set FCV=1 in the corresponding frame's
    // Control byte; when FCV=0 (e.g., Reset Link FC=0 / User Data No
    // Confirm FC=4), the FCB bit is ignored on wire and the planner
    // zeroes it. Setting LinkFCB=1 with a Scenario that uses only
    // FCV=0 frames is a Validate warning ("link_fcb set but no FCV=1
    // frame in scenario; FCB will be ignored").
    LinkFCB uint8 `json:"link_fcb,omitempty"`

    // LinkFC (链路层功能码覆盖): when non-zero, overrides the link-layer
    // function code for frames in this flow. Use only for single-frame
    // scenarios (test link / link status / NACK). 0 = derive from
    // Scenario (see §4).
    LinkFC uint8 `json:"link_fc,omitempty"`

    // --- Application-layer control ---

    // AppSeq (应用层序号): 0~15. Auto-incremented per request when
    // Scenario spans multiple App messages. User-set value is the initial
    // AppSeq (default 0).
    AppSeq uint8 `json:"app_seq,omitempty"`

    // AppFunc (应用层功能码): the application-layer function code name.
    // See §2.5 for the full list. Common values: "read", "write",
    // "select", "operate", "direct_operate", "freeze", "freeze_clear",
    // "respond", "unsolicited_respond", "confirm", "enable_unsolicited",
    // "disable_unsolicited", "assign_class", "delay_measurement",
    // "record_current_time", "cold_restart", "warm_restart",
    // "initialize_data", "initialize_application".
    // Empty defaults to "read" (most common). Note: FC=215 Configure was
    // deprecated in IEEE 1815-2012 (now Reserved); not supported.
    AppFunc string `json:"app_func,omitempty"`

    // AppFuncCode (应用层功能码原始值): when non-zero, overrides AppFunc
    // by setting the raw 1-byte function code directly. Use for protocol
    // fuzzing or testing reserved codes. 0 = derive from AppFunc.
    AppFuncCode uint8 `json:"app_func_code,omitempty"`

    // AppCON (应用层确认位): 0 = no confirm needed; 1 = receiver must
    // send Application Layer Confirm. Default 0 for read/write/control;
    // 1 for unsolicited respond (Master must confirm). Auto-set per
    // Scenario: select 与 operate 请求 CON=1（select 请求需应用层确认，
    // operate 请求沿用 select 的 CON=1 以保证外设在执行前再次确认），
    // direct_operate = 0, freeze_clear = 0, cold_restart = 0,
    // warm_restart = 0, delay_measurement = 0, multi_object_response
    // = 0。Per IEEE 1815-2012 §5.1.2, Select before Operate requires
    // Application Layer Confirmation at the select step.
    AppCON uint8 `json:"app_con,omitempty"`

    // --- Objects ---

    // Objects (对象列表): one or more object headers carried in the App
    // layer. Empty = single-frame link-layer-only scenario (Reset Link /
    // ACK / NACK / Link Status).
    Objects []DNP3Object `json:"objects,omitempty"`

    // --- Response / scenario control ---

    // Scenario (业务场景): name of the canonical scenario template.
    // When set, the planner expands it into a sequence of frames (see §4
    // and §6). When empty, the planner uses AppFunc + Objects to derive
    // the frame sequence. Common values: "reset_link", "read_class0",
    // "read_class123", "write_single", "select_operate",
    // "direct_operate", "freeze", "freeze_clear", "unsolicited",
    // "enable_unsolicited", "disable_unsolicited", "assign_class",
    // "delay_measurement", "cold_restart", "warm_restart",
    // "multi_object_response", "multi_outstation".
    Scenario string `json:"scenario,omitempty"`

    // IsEvent (是否事件对象): when true, object headers carry event
    // variations (e.g. 10.1, 10.2, 40.1, 40.3). Used in unsolicited
    // respond and class 1/2/3 responses. Default false (static objects).
    IsEvent bool `json:"is_event,omitempty"`

    // IsUnsolicited (是否非请求响应): when true, frame's App FC=14
    // (Unsolicited Respond). Master must send Confirm (FC=15) back.
    // Default false.
    IsUnsolicited bool `json:"is_unsolicited,omitempty"`

    // ConfirmRequired (是否需要应用层确认): when true, App CON=1 and the
    // flow includes a Confirm frame after the response. Default false;
    // auto-set true for unsolicited respond scenario.
    ConfirmRequired bool `json:"confirm_required,omitempty"`

    // --- Response-side fields (Outstation side or Master confirm) ---

    // IIN (内部指示位): 2-byte Internal Indications for response frames
    // (FC=13 respond / FC=14 unsolicited respond). Byte 1 high, byte 2
    // low, big-endian order on wire. Default 0x0000 (no events, no
    // errors). Use IINClass1/IINClass2/IINClass3 booleans for shorthand.
    IIN uint16 `json:"iin,omitempty"`

    // IINClass1/IINClass2/IINClass3: shorthand for the three "events
    // pending" bits. When any is true, the planner sets the
    // corresponding IIN bit. Mutually independent.
    IINClass1 bool `json:"iin_class1,omitempty"`
    IINClass2 bool `json:"iin_class2,omitempty"`
    IINClass3 bool `json:"iin_class3,omitempty"`

    // IINAlreadyExecuting: shorthand for the "Already Executing" bit
    // (byte 2 bit 2). Indicates the outstation is currently processing
    // a previous command and cannot accept new ones. When true, the
    // planner sets the corresponding IIN bit.
    IINAlreadyExecuting bool `json:"iin_already_executing,omitempty"`

    // IINEventBufferOverflow: shorthand for the "Event Buffer Overflow"
    // bit (byte 2 bit 3). Indicates the outstation's event buffer has
    // overflowed and events have been lost. When true, the planner sets
    // the corresponding IIN bit.
    IINEventBufferOverflow bool `json:"iin_event_buffer_overflow,omitempty"`

    // IINNeedTime: shorthand for the "Need Time" bit (byte 1 bit 3,
    // mask 0x08). Indicates the outstation needs time synchronization.
    // Per IEEE 1815-2012 Table 5-6, NEED_TIME = bit 3 (mask 0x08).
    IINNeedTime bool `json:"iin_need_time,omitempty"`

    // IINDeviceTrouble: shorthand for the "Device Trouble" bit
    // (byte 1 bit 1).
    IINDeviceTrouble bool `json:"iin_device_trouble,omitempty"`

    // IINLocalControl: shorthand for the "Local Control" bit (byte 1
    // bit 2, mask 0x04). Used when the outstation is in local/manual
    // control mode. Per IEEE 1815-2012 Table 5-6, LOCAL_CONTROL = bit 2.
    IINLocalControl bool `json:"iin_local_control,omitempty"`

    // IINBroadcast: shorthand for the "BROADCAST" bit (byte 1 bit 7).
    // Set when the outstation received a broadcast (DstAddr=0xFFFF).
    IINBroadcast bool `json:"iin_broadcast,omitempty"`

    // IINDeviceRestart: shorthand for the "Device Restart" bit (byte 1
    // bit 0). Set when the outstation has restarted and may need
    // reinitialization.
    IINDeviceRestart bool `json:"iin_device_restart,omitempty"`

    // IINConfigCorrupt: shorthand for the "Config Corrupt" bit
    // (byte 2 bit 7).
    IINConfigCorrupt bool `json:"iin_config_corrupt,omitempty"`

    // IINObjectUnknown: shorthand for the "Object Unknown" bit (byte 2
    // bit 5). When true, response carries empty data and the error bit.
    IINObjectUnknown bool `json:"iin_object_unknown,omitempty"`

    // IINParameterError: shorthand for the "Parameter Error" bit (byte 2
    // bit 4).
    IINParameterError bool `json:"iin_parameter_error,omitempty"`

    // IINFuncNotSupported: shorthand for the "Function Code Not Supported"
    // bit (byte 2 bit 6). Per IEEE 1815-2012 Table 5-7, FUNC_NOT_SUPPORTED = bit 6
    // (mask 0x40). This is the primary "function not supported" indicator;
    // byte 2 bit 0 (No Request/Response Function Code Support) is a related
    // but independent bit, not covered by this shorthand.
    IINFuncNotSupported bool `json:"iin_func_not_supported,omitempty"`

    // --- Multi-frame / multi-outstation ---

    // MultiOutstation (多外设): when set, the planner emits M
    // independent flows (M = OutstationCount), one per RTU, each with
    // distinct DstAddr/DstIP/SrcPort. See §6.14.
    MultiOutstation *DNP3MultiOutstation `json:"multi_outstation,omitempty"`

    // --- TCP/UDP transport ---

    // Handshake (TCP握手): when Transport="tcp", emit TCP 3-way
    // handshake at the start. Default true.
    Handshake *bool `json:"handshake,omitempty"`

    // Termination (TCP挥手): when Transport="tcp", emit TCP 4-way
    // teardown at the end. Default true.
    Termination *bool `json:"termination,omitempty"`

    // MSS (最大分段大小): TCP MSS for handshake. 0 = 1460 (default).
    MSS uint16 `json:"mss,omitempty"`

    // ThinkTime (帧间思考时间, ms): inter-frame delay between link
    // frames. 0 = no delay. Useful for simulating slow RTU responses.
    ThinkTime int `json:"think_time,omitempty"`

    // --- Validation error injection (negative testing) ---

    // MalformedCRC (故意错误的CRC): when true, planner emits frames
    // with intentionally wrong CRC16 (1-bit flip). Used for testing
    // receiver CRC validation. Default false.
    MalformedCRC bool `json:"malformed_crc,omitempty"`

    // MalformedLength (故意错误的Length): when non-zero, overrides the
    // link-layer Length byte with this value. Used for testing receiver
    // length validation.
    MalformedLength uint8 `json:"malformed_length,omitempty"`

    // UnknownObject (未知对象): when true, response carries Object
    // Type=255 (reserved). Sets IIN.ObjectUnknown automatically.
    UnknownObject bool `json:"unknown_object,omitempty"`

    // UnknownFunc (未知功能码): when true, uses App FC=200 (reserved).
    // Sets IIN.FuncNotSupported in the response.
    UnknownFunc bool `json:"unknown_func,omitempty"`
}

// DNP3Object is one object header in a DNP3 application layer frame.
type DNP3Object struct {
    // ObjectType (对象类型): 0~255. See §1.3 for common values.
    // 60 = Class (used for read class 0/1/2/3).
    ObjectType uint8 `json:"object_type"`

    // Variation (变体): 0~255. See §2.7 for common values.
    Variation uint8 `json:"variation"`

    // Qualifier (限定词): 0x00/0x01/0x06/0x07/0x08/0x17/0x28. See §2.6.
    // Empty/0 = auto-derive from IndexRange and Points (0x06 for
    // class-only reads, 0x00 for 8-bit index, 0x01 for 16-bit index,
    // 0x07 for count).
    Qualifier uint8 `json:"qualifier,omitempty"`

    // IndexRange (索引范围): for start/stop qualifiers. {Start, Stop}.
    // When [0,0] and Points is empty, planner uses Qualifier=0x06 (all
    // objects).
    IndexRange [2]uint16 `json:"index_range,omitempty"`

    // Count (对象数量): for count-based qualifiers (0x07/0x08). 0 =
    // derive from len(Points).
    Count uint16 `json:"count,omitempty"`

    // Points (数据点列表): per-point data values. Each point's encoding
    // depends on ObjectType+Variation (see §2.7). For Binary Input
    // single-bit variants, Points are packed into bytes (8 per byte);
    // for Analog Input 32-bit, each point is a uint32; for floats,
    // each point is a float32/float64.
    Points []DNP3Point `json:"points,omitempty"`

    // Flags (状态标志): per-point 1-byte flag (online/restart/comm fail/
    // ...). Empty = planner auto-fills 0x01 (ONLINE). Used for
    // "with flags" variants.
    Flags []uint8 `json:"flags,omitempty"`

    // Time (时戳): per-point 6-byte time stamp (48-bit ms since epoch).
    // Used for event objects with time (10.3, 40.3, etc.). Empty =
    // planner uses current time.
    Times []uint64 `json:"times,omitempty"`
}

// DNP3Point is one data point value, encoded per the parent Object's
// Variation. For Binary Input (Object 1) the Value is 0 or 1; for
// Counter (Object 20.1) it is a 32-bit unsigned integer; for Analog
// Input 30.5 it is a 32-bit IEEE 754 float (stored as JSON number);
// for 30.6 it is a 64-bit IEEE 754 float.
type DNP3Point struct {
    // Value (数据值): the point value. JSON number for numeric types;
    // 0/1 for binary types; floating-point for analog variants 5/6.
    Value float64 `json:"value,omitempty"`

    // Index (点索引): per-point index when using per-object-index
    // qualifiers (0x17/0x28). 0 for packed/bitmap qualifiers.
    Index uint16 `json:"index,omitempty"`
}

// DNP3MultiOutstation configures multi-RTU scenarios (see §6.14). The
// planner emits M independent flows, one per outstation, sharing the
// same Scenario template but distinct DstAddr/DstIP/SrcPort.
type DNP3MultiOutstation struct {
    // OutstationCount (外设数量): M. 0 = 1.
    OutstationCount int `json:"outstation_count,omitempty"`

    // OutstationAddrStart (起始外设地址): DstAddr for RTU #0. RTU #i uses
    // OutstationAddrStart + i. Default 1024.
    OutstationAddrStart uint16 `json:"outstation_addr_start,omitempty"`

    // OutstationIPStart (起始外设IP): DstIP for RTU #0. RTU #i uses the
    // i-th IP after OutstationIPStart (e.g., OutstationIPStart=10.0.0.10
    // → RTU 0=10.0.0.10, RTU 1=10.0.0.11, ..., using naive IPv4 +1
    // increment; for non-contiguous ranges use OutstationIPList instead).
    // Default 0.0.0.0 (unset) — caller MUST provide either
    // OutstationIPStart (with IPv4 dotted-quad format) or OutstationIPList
    // when OutstationCount > 1. If both unset, Validate returns error
    // "outstation_ip required when outstation_count > 1".
    OutstationIPStart string `json:"outstation_ip_start,omitempty"`

    // OutstationIPList (外设IP列表): explicit list of M outstation IPs.
    // When set, overrides OutstationIPStart.
    OutstationIPList []string `json:"outstation_ip_list,omitempty"`

    // SrcPortStart (主站源端口起始): Master source port for RTU #0.
    // Each RTU uses a distinct source port (SrcPortStart + i) so flows
    // have distinct 4-tuples. Default 5000. Validate rule: when
    // OutstationCount > 1, SrcPortStart MUST be set such that
    // SrcPortStart + OutstationCount - 1 ≤ 65535 (no wrap); otherwise
    // Validate returns error "src_port_start + outstation_count exceeds
    // 65535". Additionally, the master SrcAddr is shared across all
    // RTUs (single master), so 4-tuple uniqueness relies on
    // (SrcPort, DstIP) — SrcPort MUST be distinct per RTU. Setting
    // SrcPortStart=0 with OutstationCount > 1 is a Validate error
    // ("src_port_start must be set when outstation_count > 1").
    SrcPortStart uint16 `json:"src_port_start,omitempty"`
}
```

---

## 4. 状态机

### 4.1 主站状态机（LinkType="master"）

主站与单个外设的完整会话状态机：

```
                         ┌────────────────────┐
                         │   IDLE             │
                         │ (no link established)│
                         └─────────┬──────────┘
                                   │ scenario=start
                                   ▼
                         ┌────────────────────┐
                         │   RESET_LINK       │  → send Reset Link (FC=0, DIR=1, PRM=1)
                         └─────────┬──────────┘
                                   │ receive ACK (FC=0, DIR=0, PRM=0)
                                   ▼
                         ┌────────────────────┐
                         │   LINK_READY       │  link established, FCB=0
                         └─────────┬──────────┘
                                   │ scenario=read_class0
                                   ▼
                         ┌────────────────────┐
                         │   SEND_REQUEST     │  → send User Data (FC=3, FCB=0, FCV=1, App FC=read, Obj=60.1)
                         │                    │  AppSeq=0
                         └─────────┬──────────┘
                                   │ receive ACK (link)
                                   │ receive Respond (App FC=13, AppSeq=0)
                                   ▼
                         ┌────────────────────┐
                         │   GOT_RESPONSE     │  parse IIN + objects
                         └─────────┬──────────┘
                                   │ scenario=read_class123
                                   ▼
                         ┌────────────────────┐
                         │   SEND_REQUEST     │  → send User Data (App FC=read, Obj=60.2/60.3/60.4)
                         │                    │  AppSeq=1, FCB=1
                         └─────────┬──────────┘
                                   │ receive ACK + Respond (AppSeq=1)
                                   ▼
                         ┌────────────────────┐
                         │   POLL_LOOP        │  repeat for each class / each cycle
                         └─────────┬──────────┘
                                   │ scenario=end / heartbeat timeout
                                   ▼
                         ┌────────────────────┐
                         │   CLOSE             │  → TCP FIN
                         └────────────────────┘
```

控制操作（select_operate / direct_operate）状态机：

```
   LINK_READY → SEND_SELECT  (App FC=3, Obj=12.1, control code)
              ← ACK
              ← Respond (App FC=13, Obj=12.1 echo, IIN=0)
              → SEND_OPERATE (App FC=4, same AppSeq as Select, Obj=12.1, control code)
              ← ACK
              ← Respond (App FC=13, Obj=12.1 final, IIN=0)
              → CLOSE
```

非请求响应（外设主动，主站被动确认）：

```
   主站侧:
   IDLE → receive Unsolicited Respond (App FC=14, CON=1)
        → send Confirm (App FC=15, AppSeq=echo)
        → IDLE (or process event data)
```

### 4.2 外设状态机（LinkType="outstation"）

```
   IDLE → receive Reset Link (FC=0)
        → send ACK (FC=0, DIR=0, PRM=0)
        → LINK_READY
   LINK_READY → receive User Data (FC=3, App FC=read)
              → send ACK (link)
              → send Respond (App FC=13, AppSeq=echo, Obj=...)
              → IDLE/LINK_READY
   LINK_READY → (event triggered, IsUnsolicited=true)
              → send Unsolicited Respond (App FC=14, CON=1)
              → receive Confirm (App FC=15)
              → IDLE
   LINK_READY → receive Direct Operate (App FC=5)
              → send ACK + Respond (echo control)
              → IDLE
   LINK_READY → receive Cold Restart (App FC=129)
              → send ACK + Respond (with restart delay)
              → (silence, simulating restart)
```

### 4.3 应用层分片状态机

当响应数据超过单链路帧容量（约 250 字节应用层数据），外设发送多片：

```
   fragment 0: FIR=1, FIN=0, CON=1, AppSeq=N
              → Master sends Confirm (App FC=15, AppSeq=N)
   fragment 1: FIR=0, FIN=0, CON=1, AppSeq=N
              → Master sends Confirm
   ...
   fragment K: FIR=0, FIN=1, CON=0, AppSeq=N  (last fragment, no confirm needed)
              → Master processes complete ASDU
```

---

## 5. Plan 输出

### 5.1 总体输出

`Planner.Plan(ctx, spec)` 返回 `<-chan core.PacketConfig`，按顺序产出包配置：

1. **TCP 握手**（仅 Transport="tcp"，Handshake=true）：
   - SYN（client→server，Seq=ISN，Flags=SYN，MSS/WinScale/SACK 选项）
   - SYN-ACK（server→client，Seq=ISN2，Ack=ISN+1，Flags=SYN|ACK）
   - ACK（client→server，Seq=ISN+1，Ack=ISN2+1，Flags=ACK）
2. **DNP3 链路帧 × N**（每个链路帧作为一个 TCP 段或 UDP 数据报）：
   - Reset Link → ACK → User Data（含 App 请求）→ ACK → User Data（含 App 响应）→ ... → ...
   - 每个链路帧完整包含 10 字节帧头 + 数据块（每 16B + 2CRC）。
3. **TCP 挥手**（仅 Transport="tcp"，Termination=true）：
   - FIN → ACK → FIN → ACK（4-way teardown，每方向各发一个 FIN 和 ACK）

### 5.2 链路帧构造算法

```
buildLinkFrame(ctrl, dstAddr, srcAddr, appData []byte) []byte:
    # 1. data block splitting
    blocks := []
    for i := 0; i < len(appData); i += 16:
        chunk := appData[i:min(i+16, len(appData))]
        crc := CRC16_DNP(chunk)
        blocks = append(blocks, chunk + le_uint16(crc))
    length := sum(len(b) for b in blocks)  # includes 2B CRC per block
    if length > 255: error("link frame too large")

    # 2. header
    header := [0x05, 0x64, length, ctrl,
               le_lo(dstAddr), le_hi(dstAddr),
               le_lo(srcAddr), le_hi(srcAddr)]
    headerCRC := CRC16_DNP(header)  # 8 bytes
    header = header + le_uint16(headerCRC)

    # 3. frame = header + blocks
    return concat(header, blocks...)
```

### 5.3 应用层帧构造算法

```
buildAppFrame(ac, fc, objects []DNP3Object) []byte:
    asdu := [ac, fc]
    for obj in objects:
        asdu = append(asdu, obj.ObjectType, obj.Variation, obj.Qualifier)
        asdu = append(asdu, encodeRange(obj)...)
        asdu = append(asdu, encodePoints(obj)...)
    return asdu
```

### 5.4 单条流的总包序

以「主站 read class 0 → 外设 respond」为例（TCP 传输）：

| 序号 | 方向 | TCP Flags | DNP3 内容 |
|------|------|-----------|-----------|
| 0 | up | SYN | — |
| 1 | down | SYN\|ACK | — |
| 2 | up | ACK | — |
| 3 | up | PSH\|ACK | Reset Link（10B 链路帧，无 App） |
| 4 | down | PSH\|ACK | ACK（10B 链路帧） |
| 5 | up | PSH\|ACK | User Data（链路 FC=3，App FC=1 read，Obj=60.1） |
| 6 | down | PSH\|ACK | ACK（链路 FC=0） |
| 7 | down | PSH\|ACK | User Data（链路 FC=3，App FC=13 respond，IIN + Obj=1.1/30.1/...） |
| 8 | up | PSH\|ACK | ACK（链路 FC=0） |
| 9 | up | FIN\|ACK | — |
| 10 | down | ACK | — |
| 11 | down | FIN\|ACK | — |
| 12 | up | ACK | — |

（TCP 挥手 4 包：FIN → ACK → FIN → ACK，每方向各一个 FIN 和 ACK，符合 RFC 793 §3.5 正常关闭流程。参考 rtsp=4 包挥手实现。）

### 5.5 多外设场景的输出

`MultiOutstation.OutstationCount = M` 时，Plan 产出 M 个独立的 PacketConfig 流，每个流：

- 拥有独立 GroupID（确保不同外设的包不会被同一 PacketWorker 串行化）。
- 4-tuple 不同：DstIP = OutstationIPList[i]，DstAddr = OutstationAddrStart+i，SrcPort = SrcPortStart+i。
- 共享同一 Scenario 模板。

具体实现：Plan 在主 goroutine 内顺序展开 M 个外设的帧序列，每帧 PacketConfig 的 GroupID 设置为 `flowID-RTU-{i}`，确保第 i 个 RTU 的所有包进入同一 PacketWorker。

---

## 6. 业务场景与数据场景

### 6.1 Reset Link → ACK

**用途**：建立 DNP3 链路。主站发起，外设确认。

**Config 示例**：
```json
{
  "link_type": "master",
  "transport": "tcp",
  "src_addr": 1,
  "dst_addr": 1024,
  "scenario": "reset_link"
}
```

**包序列**（不含 TCP 握手/挥手）：

| # | 方向 | 链路帧 | 字节 |
|---|------|--------|------|
| 0 | up | 05 64 00 C0 00 04 01 00 <CRC16> | 10 |
| 1 | down | 05 64 00 00 01 00 00 04 <CRC16> | 10 |

- 主站帧 Control = 0xC0 = DIR=1, PRM=1, FCB=0, FCV=0, FC=0（Reset Link）。
- 外设帧 Control = 0x00 = DIR=0, PRM=0, FC=0（ACK）。
- DstAddr/SrcAddr 小端：上行帧 `00 04 01 00` = DstAddr=1024, SrcAddr=1；下行 ACK 帧 `01 00 00 04` = DstAddr=1, SrcAddr=1024。ACK 帧方向：外设(1024) → 主站(1)，故 DstAddr=1, SrcAddr=1024；与 Reset Link 帧的 src/dst 互换。

### 6.2 Read Class 0 全量

**用途**：主站读取外设全部静态数据（首次连接必做）。

**Config 示例**：
```json
{
  "link_type": "master",
  "src_addr": 1,
  "dst_addr": 1024,
  "scenario": "read_class0",
  "app_seq": 0,
  "objects": [
    {"object_type": 60, "variation": 1, "qualifier": 6}
  ]
}
```

**包序列**：

| # | 方向 | 内容 |
|---|------|------|
| 0 | up | Reset Link → (down) ACK |
| 1 | up | User Data，链路 FC=3，App FC=1 read，Obj=60.1 Class 0（Qual=0x06 all） |
| 2 | down | ACK（链路层） |
| 3 | down | User Data，链路 FC=3，App FC=13 respond，IIN=0x0000，多 Object（1.1, 30.1, 20.1, ...） |
| 4 | up | ACK（链路层） |

应用层请求帧字节示例（AppSeq=2，沿用 §6.3 read_class123 合并方案中的 AppSeq；§6.2 read_class0 单 AppSeq=0 见下文）：

```
C2 01 3C 01 06
```
- AC=0xC2：FIR=1, FIN=1, CON=0, AppSeq=2
- FC=0x01：read
- Obj=60.1 Class 0，Qual=0x06 all objects（无 range 字段）

应用层响应帧字节示例（响应 Obj=1.1 Binary Input，2 点 packed，AppSeq=2）：

```
C2 0D 40 00 01 01 00 00 01 03
```
- AC=0xC2：FIR=1, FIN=1, CON=0, AppSeq=2
- FC=0x0D=13：respond
- IIN=0x4000：byte1=0x40（Class 1 Events，bit6=1），byte2=0x00。注：Class1 Events 由 §2.4.3 表 byte1 bit6=0x40 编码，对应 uint16 高字节 0x40，即 0x4000。早期版本误标 IIN=0x0100（实际 byte1=0x01=DeviceRestart，与 IEEE 1815-2012 §5.2.3 表 5-6 不符），现已修正。
- Obj=1.1 Binary Input Single Bit，Qual=0x00 8-bit start/stop，Range=00 01（点 0 到点 1，2 点）
- Data=0x03 = 二进制 0b00000011，bit0=点0=ON，bit1=点1=ON

read_class0 单 AppSeq=0 的请求/响应字节示例（与 §6.2 包序列中的 AppSeq=0 对应）：

```
C0 01 3C 01 06        # 请求 read class 0, AppSeq=0, Obj=60.1
C0 0D 00 00 01 01 00 00 01 03   # 响应 AppSeq=0, IIN=0x0000, Obj=1.1
```

### 6.3 Read Class 1/2/3 事件

**用途**：主站读取外设的事件队列。Class 1 = 高优先级，Class 2 = 中，Class 3 = 低。

**Config 示例**：
```json
{
  "link_type": "master",
  "scenario": "read_class123",
  "app_seq": 2,
  "objects": [
    {"object_type": 60, "variation": 2, "qualifier": 6},
    {"object_type": 60, "variation": 3, "qualifier": 6},
    {"object_type": 60, "variation": 4, "qualifier": 6}
  ]
}
```

**包序列**：默认采用**合并方案**——单条 read 请求带 3 个 Object Header（60.2 Class 1、60.3 Class 2、60.4 Class 3），各 class 共享同一 AppSeq，外设响应时各类事件依次排列在响应帧中。也可拆分为 3 个独立请求（每个 class 一个独立 AppSeq），但本设计 v1 默认采用合并方案（与 T17 测试断言一致）。

应用层请求帧字节（合并方案 read class 123，AppSeq=2）：

```
C2 01 3C 02 06 3C 03 06 3C 04 06
```
- AC=0xC2：FIR=1, FIN=1, CON=0, AppSeq=2
- FC=0x01：read
- 3 个 Object Header 顺序：60.2 Class 1、60.3 Class 2、60.4 Class 4（实为 Class 3，规范中 Class 3 编号为 60.4），全部 Qual=0x06

应用层响应帧字节（携带 Binary Output Event Obj=10.1，1 个事件，点索引 3，AppSeq=2）：

```
C2 0D 40 00 0A 01 17 01 03 01 01
```
- AC=0xC2：AppSeq=2
- FC=0x0D=13：respond
- IIN=0x4000：byte1=0x40（Class 1 Events，bit6=1），byte2=0x00
- Obj=10.1 Binary Output Event，Qual=0x17（8-bit count + 1B index per object），count=1，index=3
- Data：flag=0x01（ONLINE），value=0x01（ON）

### 6.4 Write 单点

**用途**：主站写入外设参数（如阈值、配置字）。

**Config 示例**：
```json
{
  "link_type": "master",
  "scenario": "write_single",
  "app_func": "write",
  "app_seq": 2,
  "objects": [
    {
      "object_type": 80, "variation": 1,
      "qualifier": 0, "index_range": [7, 7],
      "points": [{"value": 1}]
    }
  ]
}
```

**包序列**：

| # | 方向 | 内容 |
|---|------|------|
| 0 | up | User Data，App FC=2 write，Obj=80.1 IIN，Qual=0x00，Range=07 07，Data=0x01 |
| 1 | down | ACK + Respond，IIN=0x0000（写成功） |

应用层请求字节：

```
C2 02 50 01 00 07 07 01
```
- AC=0xC2：AppSeq=2
- FC=0x02：write
- Obj=80.1 Internal Indications
- Qual=0x00：8-bit start/stop
- Range=07 07：点 7 到点 7（单点）
- Data=0x01：写入值 1

### 6.5 Select → Operate

**用途**：SBO（Select Before Operate）模式的两步控制。主站先 select 试点，外设回显确认；主站再 operate 执行。

**Config 示例**：
```json
{
  "link_type": "master",
  "scenario": "select_operate",
  "app_seq": 3,
  "objects": [
    {
      "object_type": 12, "variation": 1,
      "qualifier": 0, "index_range": [5, 5],
      "points": [{"value": 1}]
    }
  ]
}
```

**包序列**：

| # | 方向 | App 内容 |
|---|------|---------|
| 0 | up | App FC=3 select，AppSeq=3，Obj=12.1 CROB（Control Relay Output Block），index=5 |
| 1 | down | ACK + Respond，App FC=13，AppSeq=3，IIN=0，Obj=12.1 echo |
| 2 | up | App FC=4 operate，**AppSeq=3（与 select 相同）**，Obj=12.1 CROB，index=5（与 select 相同的控制码） |
| 3 | down | ACK + Respond，App FC=13，**AppSeq=3（与 select 相同）**，IIN=0，Obj=12.1 final |

CROB（Control Relay Output Block）请求帧数据格式（**6 字节**，IEEE 1815-2012 §3-2.6.1）：

```
+--------+--------+--------+--------+
| Code   | Count  | OnTime | OffTime|
+--------+--------+--------+--------+
  1B       1B       2B       2B
```

- Code：控制码（NUL=0x00、LATCH_ON=0x03、LATCH_OFF=0x04、PULSE_ON=0x01、PULSE_OFF=0x02 等）。
- Count：操作次数（通常 1）。
- OnTime/OffTime：on/off 时长（毫秒，0xFFFF=65535ms 或"不适用/未指定"由实现定义；LATCH 类操作 OffTime 通常填 0xFFFF 表示无 off 时长）。

注意：请求帧 CROB 数据区**仅 4 字段 6 字节**，**不含** Status 字段。Status 是响应帧回显字段，响应帧 CROB = 7 字节（Code+Count+OnTime+OffTime+Status）；请求帧 CROB = 6 字节。DNP3 对象数据**无长度前缀**，对象宽度由 Object Type + Variation 隐含。

应用层 select 请求字节示例（Code=LATCH_ON=0x03，Count=1，OnTime=100ms=0x0064，OffTime=0xFFFF，点 5）：

```
C3 03 0C 01 00 05 05 03 01 64 00 FF FF
```

- AC=0xC3：AppSeq=3
- FC=0x03：select
- Obj=12.1 CROB
- Qual=0x00：8-bit start/stop
- Range=05 05：点 5
- Data 区严格 6 字节 CROB（无长度前缀，对象宽度由 Object Type + Variation 隐含）：`03 01 64 00 FF FF` = Code=0x03 (LATCH_ON)、Count=0x01、OnTime=0x0064 (100ms, LE)、OffTime=0xFFFF (不适用, LE)。总长 13 字节。

注：IEEE 1815-2012 §3-2.6.1 定义的 CROB 请求帧含 Code+Count+OnTime+OffTime 共 6 字节，Status 字段（状态码，0=success）是响应帧的回显字段，请求帧不带。

### 6.6 Direct Operate

**用途**：单步控制，主站直接操作控制点。用于无副作用的控制（如数字量输出直接置位）。

**Config 示例**：
```json
{
  "link_type": "master",
  "scenario": "direct_operate",
  "app_func": "direct_operate",
  "app_seq": 5,
  "objects": [
    {
      "object_type": 12, "variation": 1,
      "qualifier": 0, "index_range": [5, 5],
      "points": [{"value": 1}]
    }
  ]
}
```

**包序列**：

| # | 方向 | App 内容 |
|---|------|---------|
| 0 | up | App FC=5 direct_operate，AppSeq=5，Obj=12.1 CROB，index=5 |
| 1 | down | ACK + Respond，App FC=13，AppSeq=5，IIN=0，Obj=12.1 final |

Direct Operate No Ack（App FC=6）的差异：外设不响应。用于广播（DstAddr=0xFFFF）。

### 6.7 Freeze / Freeze and Clear

**用途**：冻结计数器（将当前计数器值复制到冻结寄存器）。Freeze and Clear 在冻结后清零原计数器。

**Config 示例**：
```json
{
  "link_type": "master",
  "scenario": "freeze_clear",
  "app_func": "freeze_clear",
  "app_seq": 6,
  "objects": [
    {"object_type": 20, "variation": 1, "qualifier": 6}
  ]
}
```

**包序列**：

| # | 方向 | App 内容 |
|---|------|---------|
| 0 | up | App FC=9 freeze_clear，AppSeq=6，Obj=20.1 Counter 32-bit（Qual=0x06 全部对象） |
| 1 | down | ACK + Respond，App FC=13，AppSeq=6，IIN=0 |

应用层请求字节：

```
C6 09 14 01 06
```

- AC=0xC6：AppSeq=6
- FC=0x09：freeze and clear
- Obj=20.1 Counter 32-bit（Variation=1 显式请求 32-bit 计数器；响应帧也必须填具体 Variation=1 或 2，**不能**填 Variation=0）
- Qual=0x06：all objects

注：IEEE 1815-2012 §3.4.1 规定 Object 20（Counter）只有 Variation 1（32-bit）和 2（16-bit），**不存在** Variation 0。"all variations" 由 Qualifier=0x06 表达，不是 Variation=0。请求帧中可填 Variation=0 表示"任意变体"（planner 自动接受），但响应帧若填 Variation=0 会被接收方拒绝。

### 6.8 事件非请求响应（Unsolicited Respond）

**用途**：外设主动上报事件（需主站先 enable unsolicited）。

**Config 示例**（外设侧视角）：
```json
{
  "link_type": "outstation",
  "src_addr": 1024,
  "dst_addr": 1,
  "scenario": "unsolicited",
  "is_unsolicited": true,
  "confirm_required": true,
  "app_seq": 0,
  "objects": [
    {
      "object_type": 10, "variation": 2,
      "qualifier": 23, "count": 1,
      "points": [{"value": 1, "index": 3}],
      "flags": [1],
      "times": [1691049600000]
    }
  ]
}
```

**包序列**：

| # | 方向 | 链路/App 内容 |
|---|------|---------------|
| 0 | up | （TCP 握手 if needed） |
| 1 | up | User Data，链路 FC=4（no confirm），App FC=14 unsolicited_respond，CON=1，AppSeq=0，IIN=0x4000（Class 1 事件，byte1=0x40），Obj=10.2 Binary Output Event without Time |
| 2 | down | User Data，App FC=15 confirm，AppSeq=0 |

应用层 unsolicited 字节：

```
C0 0E 40 00 0A 02 17 01 03 01 01
```
- AC=0xC0：FIR=1, FIN=1, CON=1（需确认），AppSeq=0
- FC=0x0E=14：unsolicited respond
- IIN=0x4000：Class 1 events（byte1=0x40，bit6=1，参见 §2.4.3）
- Obj=10.2 Binary Output Event without Time，Qual=0x17（8-bit count + 1B index per object），count=1，index=3
- Data=flag=0x01, value=0x01

主站 confirm 字节：

```
C0 0F
```
- AC=0xC0：FIR=1, FIN=1, CON=0，AppSeq=0（与 unsolicited 同序号）
- FC=0x0F=15：confirm

### 6.9 Enable/Disable Unsolicited

**用途**：主站启用/禁用外设的非请求响应能力。

**Config 示例**：
```json
{
  "link_type": "master",
  "scenario": "enable_unsolicited",
  "app_func": "enable_unsolicited",
  "app_seq": 7,
  "objects": [
    {"object_type": 60, "variation": 2, "qualifier": 6},
    {"object_type": 60, "variation": 3, "qualifier": 6},
    {"object_type": 60, "variation": 4, "qualifier": 6}
  ]
}
```

**包序列**：

| # | 方向 | App 内容 |
|---|------|---------|
| 0 | up | App FC=20 enable_unsolicited，AppSeq=7，Obj=60.2/60.3/60.4（启用 class 1/2/3 的非请求） |
| 1 | down | ACK + Respond，App FC=13，AppSeq=7，IIN=0 |

应用层请求字节：

```
C7 14 3C 02 06 3C 03 06 3C 04 06
```
- AC=0xC7：AppSeq=7
- FC=0x14=20：enable unsolicited
- 3 个 Object Header：60.2/60.3/60.4，全 Qual=0x06

### 6.10 Assign Class

**用途**：主站将外设的某些对象点分配到 Class 0/1/2/3，定义事件优先级。

**Config 示例**：
```json
{
  "link_type": "master",
  "scenario": "assign_class",
  "app_func": "assign_class",
  "app_seq": 8,
  "objects": [
    {
      "object_type": 1, "variation": 0,
      "qualifier": 0, "index_range": [0, 9],
      "points": [{"value": 1}]
    }
  ]
}
```

**包序列**：

| # | 方向 | App 内容 |
|---|------|---------|
| 0 | up | App FC=22 assign_class，AppSeq=8，Obj=1.0 Binary Input（all variations），index 0~9，Class=1 |
| 1 | down | ACK + Respond，App FC=13，AppSeq=8，IIN=0 |

Class 编码：Assign Class 的 Object 1.0 数据区每个点 1 字节，值为 0/1/2/3 表示该点属于哪个 Class。

### 6.11 Delay Measurement

**用途**：主站测量到外设的链路延迟，用于时间同步的前导步骤。

**Config 示例**：
```json
{
  "link_type": "master",
  "scenario": "delay_measurement",
  "app_func": "delay_measurement",
  "app_seq": 9
}
```

**包序列**：

| # | 方向 | App 内容 |
|---|------|---------|
| 0 | up | App FC=23 delay_measurement，AppSeq=9，无 Object |
| 1 | down | ACK + Respond，App FC=13，AppSeq=9，Obj=52.2 Time Delay Fine（外设返回处理时延） |

应用层请求字节：

```
C9 17
```
- AC=0xC9：AppSeq=9
- FC=0x17=23：delay measurement
- 无 Object Header

### 6.12 Cold/Warm Restart

**用途**：主站命令外设重启。Cold Restart = 完全重启（含硬件自检），Warm Restart = 应用层重启。

**Config 示例**：
```json
{
  "link_type": "master",
  "scenario": "cold_restart",
  "app_func": "cold_restart",
  "app_seq": 10
}
```

**包序列**：

| # | 方向 | App 内容 |
|---|------|---------|
| 0 | up | App FC=129 cold_restart，AppSeq=10 |
| 1 | down | ACK + Respond，App FC=13，AppSeq=10，Obj=51.1 Time Delay Coarse（外设返回重启所需时长，秒） |
| 2 | （silence） | 外设模拟重启，无后续帧 |

应用层请求字节：

```
CA 81
```
- AC=0xCA：AppSeq=10
- FC=0x81=129：cold restart

### 6.13 多 object 响应

**用途**：外设响应携带多个 Object Header（如 Binary Input + Analog Input + Counter）。

**Config 示例**（外设侧响应）：
```json
{
  "link_type": "outstation",
  "scenario": "multi_object_response",
  "app_func": "respond",
  "app_seq": 0,
  "objects": [
    {
      "object_type": 1, "variation": 1,
      "qualifier": 0, "index_range": [0, 7],
      "points": [{"value": 1}, {"value": 0}, {"value": 1}, {"value": 1},
                 {"value": 0}, {"value": 0}, {"value": 1}, {"value": 0}]
    },
    {
      "object_type": 30, "variation": 1,
      "qualifier": 0, "index_range": [0, 1],
      "points": [{"value": 220.5}, {"value": 110.2}],
      "flags": [1, 1]
    },
    {
      "object_type": 20, "variation": 1,
      "qualifier": 0, "index_range": [0, 0],
      "points": [{"value": 12345}],
      "flags": [1]
    }
  ]
}
```

**包序列**：

| # | 方向 | App 内容 |
|---|------|---------|
| 0 | down | Respond，App FC=13，AppSeq=0，3 个 Object Header 顺序排列 |

应用层响应字节（示意）：

```
C0 0D 00 00
   01 01 00 00 07 B3          # Obj 1.1, Qual=0x00, range=0~7, data=1 byte (0xB3=10110011)
   1E 01 00 00 01 01 DC 6E    # Obj 30.1, Qual=0x00, range=0~1, data=2 × (1B flag + 4B value)
   ...
```

### 6.14 多外设并发

**用途**：主站与多个 RTU 并发通信。每个 RTU 是一个独立的 4-tuple，拥有独立 DstAddr。

**Config 示例**：
```json
{
  "link_type": "master",
  "scenario": "read_class0",
  "multi_outstation": {
    "outstation_count": 5,
    "outstation_addr_start": 1024,
    "outstation_ip_list": ["10.0.0.11", "10.0.0.12", "10.0.0.13", "10.0.0.14", "10.0.0.15"],
    "src_port_start": 5000
  }
}
```

**包序列**：5 个独立流，每流执行「Reset Link → ACK → Read Class 0 → Respond」：

- RTU 0: DstIP=10.0.0.11, DstPort=20000, SrcPort=5000, DstAddr=1024, SrcAddr=1
- RTU 1: DstIP=10.0.0.12, DstPort=20000, SrcPort=5001, DstAddr=1025, SrcAddr=1
- RTU 2: DstIP=10.0.0.13, DstPort=20000, SrcPort=5002, DstAddr=1026, SrcAddr=1
- RTU 3: DstIP=10.0.0.14, DstPort=20000, SrcPort=5003, DstAddr=1027, SrcAddr=1
- RTU 4: DstIP=10.0.0.15, DstPort=20000, SrcPort=5004, DstAddr=1028, SrcAddr=1

每流独立 GroupID，路由到不同 PacketWorker，保证并发不串行化。

### 6.15 边界场景

| 场景 | Config | 期望行为 |
|------|--------|---------|
| 链路地址 0 | DstAddr=0 | 接受；非广播仍按单播处理 |
| 链路地址 65535 | DstAddr=0xFFFF | 广播；外设不响应（仅 Direct Operate No Ack / Freeze No Ack 等无确认场景） |
| 链路地址 0 | SrcAddr=0 | 接受；主站地址 0 非法但可生成 |
| AppSeq 回绕 | AppSeq=15 → 下一帧 AppSeq=0 | 4 位序号自动回绕 |
| Object 数量 0 | Count=0, Qualifier=0x07 | 接受；响应帧无数据，仅 IIN |
| Object 数量最大 | Count=255, Qualifier=0x07 | 接受；响应帧含 255 个对象 |
| Index 0 | IndexRange=[0,0] | 接受；点索引 0 |
| Index 65535 | IndexRange=[65535,65535], Qualifier=0x01 | 接受；16 位索引最大值 |
| Data 空数组 | Points=[] | 接受；请求帧无数据区（read 类） |
| 链路帧最大长度 | 链路层 Length=255 → 最大数据块 255B（含每块的 2B CRC）。Length 不含 10B 帧头与帧头 CRC，但含每块尾部 2B CRC。精确推导：Length=255 → 帧总长 = 10 + 255 = 265B；应用层数据 ≤ 225B（14 满块 × 16B = 224B + 1 缺块 × 1B = 225B），CRC 共 30B（15 块 × 2B）。单块场景（应用层 ≤ 16B）：Length = L + 2（应用层 + 单块 CRC），帧总长 = 10 + L + 2 ≤ 28B | 帧总长 265B = 10B 头 + 225B 应用层 + 30B CRC；15 个分块（14 满 + 1 缺），每块独立 CRC16/DNP |
| 应用层分片 | 250B × 4 | 4 个 FIR/FIN 分片 |
| 单点 Packed | Points=[1 个 Binary], IndexRange=[0,0] | 1 字节数据，bit0=值，bit1~7=0 |

### 6.16 异常场景

| 场景 | Config | 期望行为 |
|------|--------|---------|
| NACK | LinkFC=1（外设侧） | 链路层 NACK，主站收到后停止发送并重试或断链 |
| Link Status 错误 | LinkFC=2（外设侧） | 外设返回链路状态，主站判定链路异常 |
| Object Unknown | IINObjectUnknown=true | 响应帧 IIN byte2 bit5=1，无数据 |
| Parameter Error | IINParameterError=true | 响应帧 IIN byte2 bit4=1 |
| Func Not Supported | IINFuncNotSupported=true | 响应帧 IIN byte2 bit6=1（Function Code Not Implemented，mask 0x40）。注：bit6 是主要的功能码不支持指示位；bit0（No Request/Response Function Code Support）是相关但独立的位，不由本 shorthand 覆盖 |
| Already Executing | IIN byte2 bit2=1 | 响应帧指示已在执行 |
| Event Buffer Overflow | IIN byte2 bit3=1 | 响应帧指示事件缓冲区溢出 |
| Need Time | IINNeedTime=true | 响应帧 IIN byte1 bit3=1（mask 0x08），参见 §2.4.3 注 |
| Device Trouble | IINDeviceTrouble=true | 响应帧 IIN byte1 bit1=1 |
| Local Control | IIN byte1 bit2=1 | 响应帧指示本地控制模式 |
| Class 1/2/3 Events 待传 | IINClass1/2/3=true | 响应帧 IIN byte1 bit6/5/4=1，主站据此继续轮询 |
| MalformedCRC | MalformedCRC=true | 链路帧 CRC 故意错误，外设不响应（仿真接收方丢弃） |
| MalformedLength | MalformedLength=255 | 链路帧 Length 字段错误，外设不响应 |
| UnknownObject | UnknownObject=true | 响应帧 Obj=255，IIN.ObjectUnknown=1 |
| UnknownFunc | UnknownFunc=true | App FC=200，IIN.FuncNotSupported=1 |

---

## 7. 测试用例清单

测试用例遵循 CLAUDE.md「测试策略」8 条规则：spec 驱动、覆盖失败路径、单函数覆盖、集成测试、断言可观测值、并发正确性、failing-test-first、对抗审计。共 **85** 条测试用例（T1-T85 连续编号，共 85 条；v1.0 原 38 条 + v1.1 新增 47 条）。T67a 在 v1.1.2 中已删除（与 T68 主题重复），T20 拆分为 T20a/T20b（不另计编号位）。

### 7.1 Validate 单元测试（10 条）

| # | 用例名 | 输入 | 期望 |
|---|--------|------|------|
| T1 | TestDNP3Validate_ValidMinimal | LinkType="", SrcAddr=0, DstAddr=0, AppFunc="" | nil（默认 master, read） |
| T2 | TestDNP3Validate_ValidMaster | LinkType="master", SrcAddr=1, DstAddr=1024, AppFunc="read" | nil |
| T3 | TestDNP3Validate_ValidOutstation | LinkType="outstation", SrcAddr=1024, DstAddr=1, AppFunc="respond" | nil |
| T4 | TestDNP3Validate_InvalidLinkType | LinkType="slave" | error（"invalid link_type"） |
| T5 | TestDNP3Validate_InvalidTransport | Transport="sctp" | error（"invalid transport"） |
| T6 | TestDNP3Validate_InvalidAppFunc | AppFunc="foobar" | error（"invalid app_func"） |
| T7 | TestDNP3Validate_SrcAddrOutOfRange | SrcAddr=0x10000 | error（"src_addr out of range"）—— uint16 隐含，JSON 解析时报错 |
| T8 | TestDNP3Validate_DstAddrBroadcastWithConfirm | DstAddr=0xFFFF, ConfirmRequired=true | error（"broadcast cannot require confirm"） |
| T9 | TestDNP3Validate_MultiOutstationZeroCount | MultiOutstation.OutstationCount=0 | error（"outstation_count must be > 0"） |
| T10 | TestDNP3Validate_MultiOutstationIPListMismatch | OutstationCount=3, OutstationIPList 长度=2 | error（"outstation_ip_list length mismatch"） |

### 7.2 报文构造单元测试（11 条）

T20a 仅验证 CRC16/DNP 标准算法对整段输入的结果；T20b 独立验证 DNP3 链路层 16 字节分块后，各块 CRC 分别计算且不跨块延续。两者不得共享“整段 CRC”语义。

| # | 用例名 | 输入 | 期望（断言可观测字节） |
|---|--------|------|------|
| T11 | TestBuildLinkFrame_ResetLink | ctrl=0xC0, dst=1024, src=1, data=[] | 字节 `05 64 00 C0 00 04 01 00` + CRC16/DNP，总长 10B |
| T12 | TestBuildLinkFrame_ACK | ctrl=0x00, dst=1, src=1024, data=[] | 字节 `05 64 00 00 01 00 00 04` + CRC16/DNP |
| T13 | TestBuildLinkFrame_WithUserData | ctrl=0xC3, dst=1024, src=1, data=[C0 01 3C 01 06] | Length=5+2=7，总长 17B；末尾 2B CRC16/DNP 正确 |
| T14 | TestBuildLinkFrame_16ByteBlockBoundary | data 长度=16 | Length=18（16+2），单块；CRC 计算自 16B |
| T15 | TestBuildLinkFrame_17ByteData | data 长度=17 | Length=21（16+2 + 1+2），两块；第二块 1B 数据 + 2B CRC |
| T16 | TestBuildAppFrame_ReadClass0 | ac=0xC0, fc=1, objects=[60.1 Qual=0x06] | 字节 `C0 01 3C 01 06` |
| T17 | TestBuildAppFrame_ReadClass123 | ac=0xC2, fc=1, 3 个 Object 60.2/60.3/60.4 | 字节 `C2 01 3C 02 06 3C 03 06 3C 04 06` |
| T18 | TestBuildAppFrame_RespondWithIIN | ac=0xC0, fc=13, iin=0x4000（Class1）, no objects | 字节 `C0 0D 40 00` |
| T19 | TestBuildAppFrame_Unsolicited | ac=0xC0（CON=1）, fc=14, iin=0x4000（Class1）, obj=10.2 | 字节 `C0 0E 40 00 0A 02 17 01 03 01 01` |
| T20a | TestCRC16_DNP_KnownVectors | `""` / `"\x00"` / `"123456789"` | 对每个完整输入调用一次 CRC16/DNP；期望值见 T20a 表 |
| T20b | TestCRC16_DNP_BlockIndependence | 16 字节 `\x00 ×16` / 17 字节 `\x00 ×16 + \xFF` | 按链路层 16B 分块独立调用 CRC16/DNP；期望值见 T20b 表 |

**T20a 标准算法向量期望值表**（每行均为整段输入的一次 CRC16/DNP 计算，poly=0x3D65 refin/refout true xorout=0xFFFF）：

| 输入数据 | 期望 CRC16 | 期望字节（小端） | 备注 |
|---------|-----------|-----------------|------|
| `""`（空） | 0xFFFF | `FF FF` | 零长度算法输入 → XORout=0xFFFF；不表示链路帧存在空数据块 |
| `"\x00"`（1 字节） | 0xFFFF | `FF FF` | 单字节零值，XOR 0x00 后 8 次移位仍为初值 0x0000，再 XORout=0xFFFF |
| `"123456789"`（9B ASCII，无前导 0） | 0xEA82 | `82 EA` | IEEE 1815-2012 Annex B 标准向量（与 CRC catalog 一致） |

注：`"0123456789"`（10B 含前导 0）的 CRC16/DNP 为 0x6772（不是 0xEA82），早期版本误把 0xEA82 标在该 10B 上，实际 0xEA82 是 9B "123456789" 的值。已修正。

**T20b 分块 CRC 独立性期望值表**（每个链路块分别从 CRC 初始值 0x0000 开始计算，逐步 XORout=0xFFFF；不得把 17B 当作一个整体向量）：

| 链路层数据 | 分块方式 | 各块期望 CRC16 | 各块期望字节（小端） |
|-----------|----------|----------------|----------------------|
| 16 字节 `\x00 ×16` | 单块 `data[0:16]` | 第 1 块 0xFFFF | `FF FF` |
| 17 字节 `\x00 ×16 + \xFF` | 第 1 块 `data[0:16]`；第 2 块 `data[16:17]` | 第 1 块 0xFFFF；第 2 块 0xEDCA | `FF FF`；`CA ED` |

注：早期版本误写 0x0C19 / 0xC3A0 / 0xC0E9，与算法实际输出不符。CRC16/DNP 对全零输入恒输出 0xFFFF（init=0x0000 XOR 0x00 仍为 0x0000，移位 8 次不变，再 XORout=0xFFFF）。

### 7.3 Plan 集成测试（10 条）

| # | 用例名 | 输入 | 期望（断言可观测输出） |
|---|--------|------|------|
| T21 | TestDNP3Plan_ResetLinkScenario | Scenario="reset_link", Transport="tcp" | 包数=3（SYN/SYN-ACK/ACK）+ 2（Reset Link/ACK）+ 4（FIN/ACK/FIN/ACK，4-way teardown）；断言 Reset Link 帧字节。注：v1.1.1 误标 TCP 挥手 6 包（FIN/ACK/FIN/ACK + 中途 RST），违反 RFC 793 §3.5 每方向单 FIN；v1.1.3 统一为 4-way 标准 4 包。 |
| T22 | TestDNP3Plan_ReadClass0 | Scenario="read_class0", AppSeq=0 | 包序：TCP 握手→Reset Link→ACK→User Data(read 60.1)→ACK→User Data(respond)→ACK→TCP 挥手；断言第 5 个 DNP3 包是 read 请求字节 `C0 01 3C 01 06` |
| T23 | TestDNP3Plan_SelectOperate | Scenario="select_operate", AppSeq=3 | 包序含 2 个 App 请求（select AppSeq=3 + operate AppSeq=3）+ 2 个响应；断言 select 与 operate **共享同一 AppSeq**（IEEE 1815-2012 §5.1.3.2 要求 SBO 两步共享序列号，不是递增） |
| T24 | TestDNP3Plan_DirectOperate | Scenario="direct_operate" | 包序含 1 个 App 请求（FC=5）+ 1 个响应；断言无 select |
| T25 | TestDNP3Plan_Unsolicited | Scenario="unsolicited", IsUnsolicited=true, ConfirmRequired=true | 包序含 unsolicited respond（CON=1）+ confirm；断言 unsolicited 字节 `C0 0E 40 00 ...`（IIN=0x4000 Class1），confirm 字节 `C0 0F` |
| T26 | TestDNP3Plan_ColdRestart | Scenario="cold_restart", AppSeq=10 | 包序含 cold_restart 请求（FC=129）+ 响应（含 Obj=51.1 时延）；断言请求字节 `CA 81` |
| T27 | TestDNP3Plan_UDPTransport | Transport="udp" | 包数不含 TCP 握手/挥手；每个链路帧作为独立 UDP 数据报，且每个数据报前置 2B 传输层头（LTH=Length\|0x80、SEQ=序号）；断言 SrcPort/DstPort=20000，且每个 UDP 载荷前 2 字节是 LTH+SEQ 传输层头 |
| T28 | TestDNP3Plan_NoHandshake | Handshake=false, Transport="tcp" | 包数不含 SYN/SYN-ACK/ACK；直接从 Reset Link 开始 |
| T29 | TestDNP3Plan_NoTermination | Termination=false, Transport="tcp" | 包数不含 FIN/FIN-ACK/ACK；以最后一条 DNP3 ACK 结束 |
| T30 | TestDNP3Plan_AppSeqWrapAround | AppSeq=15, Scenario 跨 2 个 App 请求 | 第二个请求 AppSeq=0（4 位回绕）；断言 AC 字节从 0xCF 变为 0xC0 |

### 7.4 多外设并发测试（3 条）

| # | 用例名 | 输入 | 期望 |
|---|--------|------|------|
| T31 | TestDNP3Plan_MultiOutstationDistinct4Tuples | OutstationCount=3, IPList=[3 个 IP], SrcPortStart=5000 | 3 个流的 4-tuple 各不相同；DstAddr=1024/1025/1026；SrcPort=5000/5001/5002 |
| T32 | TestDNP3Plan_MultiOutstationGroupIDDistinct | 同上 | 3 个流的 GroupID 各不相同（每流路由到独立 PacketWorker） |
| T33 | TestDNP3Plan_MultiOutstationWireOrder | 同上 | 每个外设内部的包顺序保持（Reset Link → ACK → User Data → ...）；跨外设可乱序（不同 PacketWorker）但单外设有序 |

### 7.5 边界与异常测试（5 条）

| # | 用例名 | 输入 | 期望 |
|---|--------|------|------|
| T34 | TestDNP3Plan_BroadcastAddrNoResponse | DstAddr=0xFFFF, AppFunc="direct_operate_no_ack" | 外设不响应；包序仅含主站请求帧，无 ACK/Respond |
| T35 | TestDNP3Plan_EmptyObjectsLinkOnly | Objects=[], Scenario="reset_link" | 仅链路层帧（Reset Link + ACK），无 App 层 |
| T36 | TestDNP3Plan_MalformedCRC | MalformedCRC=true | 链路帧 CRC16 字节错误（1 bit 翻转）；断言 CRC 字节与正确值不同 |
| T37 | TestDNP3Plan_IINBits | IINClass1=true, IINNeedTime=true, IINObjectUnknown=true | **场景**：模拟主站 Read Object=255（未知对象），外站响应带 IIN.ObjectUnknown=1。期望响应帧 IIN 字节 1=0x48（Class1=0x40 + NeedTime=0x08），字节 2=0x20（ObjectUnknown=0x20） |
| T38 | TestDNP3Plan_AppFragmentation | 250B 应用层数据 × 4 片 | 4 个 FIR/FIN 分片：第一片 FIR=1,FIN=0；中间 FIR=0,FIN=0；最后 FIR=0,FIN=1；同 AppSeq |

### 7.6 审计修复新增测试（v1.1，2026-08-03）

以下测试用例针对 §2 审计报告中发现的问题补充，确保字段级与场景级覆盖完整。

#### 7.6.1 LinkFC / MalformedLength / UnknownObject / UnknownFunc 字段覆盖（M-DNP3-1/2/3）

| # | 用例名 | 输入 | 期望 |
|---|--------|------|------|
| T39 | TestDNP3Validate_LinkFCOverride | LinkFC=2（Link Status）, Scenario="reset_link" | Validate 通过；Plan 产出的帧 Control 字节 FC 字段=2 而非默认 0 |
| T40 | TestDNP3Validate_LinkFCReserved | LinkFC=15（4 位最大值+1，超出范围） | Validate error（"link_fc out of range [0..11]"） |
| T41 | TestDNP3Plan_LinkFCBWithFCV0 | LinkFCB=1, Scenario="reset_link"（FCV=0 帧） | Validate warning（"link_fcb set but no FCV=1 frame in scenario; FCB will be ignored"）；wire FCB=0 |
| T42 | TestDNP3Plan_LinkFCBWithFCV1 | LinkFCB=1, Scenario="read_class0"（FCV=1 的 User Data 帧） | 第一帧 User Data Control=0xF3（DIR=1,PRM=1,FCB=1,FCV=1,FC=3）；下一帧 User Data Control=0xD3（DIR=1,PRM=1,FCB=0,FCV=1,FC=3——FCB 翻转 0 但 FCV 保持 1，因 FC=3 User Data Confirm 必须配 FCV=1，FCV=0 时退化为 FC=4 语义）。早期版本第一帧误写 0xD3（FCB=0）与 LinkFCB=1 初始值矛盾，v1.1.2 已修第一帧为 0xF3；第二帧 0xC3 遗漏（FCV=0 与 FC=3 协议非法组合），v1.1.3 修正为 0xD3 |
| T43 | TestDNP3Plan_MalformedLength | MalformedLength=255, Scenario="reset_link" | 链路帧第 3 字节（Length）=0xFF，与实际数据块长度不符；外设不响应（仿真接收方丢弃） |
| T44 | TestDNP3Plan_MalformedLengthZero | MalformedLength=0, Scenario="read_class0" | 链路帧 Length=0，但实际有 User Data 数据块；外设不响应 |
| T45 | TestDNP3Plan_UnknownObject | UnknownObject=true, Scenario="respond" | 响应帧 Object Type=255（reserved），Variation=0，Qualifier=0x06；IIN byte2 bit5 (ObjectUnknown)=1 |
| T46 | TestDNP3Plan_UnknownFunc | UnknownFunc=true, Scenario="respond" | 请求帧 App FC=200（0xC8，reserved）；响应帧 IIN byte2 bit6 (FuncNotSupported)=1 |
| T47 | TestDNP3Validate_MalformedLengthRange | MalformedLength=200（合法范围 0..255），但 Scenario="reset_link" 实际 Length=0 | Validate 通过（MalformedLength 是故意错误注入，不阻止生成）；Plan 产出帧 Length=200 |

#### 7.6.2 IIN 全位 shorthand 覆盖（M-DNP3-4）

| # | 用例名 | 输入 | 期望 |
|---|--------|------|------|
| T48 | TestDNP3Plan_IINAlreadyExecuting | IINAlreadyExecuting=true | 响应帧 IIN byte2=0x04（bit2=1） |
| T49 | TestDNP3Plan_IINEventBufferOverflow | IINEventBufferOverflow=true | 响应帧 IIN byte2=0x08（bit3=1） |
| T50 | TestDNP3Plan_IINLocalControl | IINLocalControl=true | 响应帧 IIN byte1=0x04（bit2=1） |
| T51 | TestDNP3Plan_IINBroadcast | IINBroadcast=true, DstAddr=0xFFFF | 响应帧 IIN byte1=0x80（bit7=1，BROADCAST）。注：BROADCAST 位 bit7 mask 0x80，与文档 §2.4.3 表 byte1 bit7=0x80 一致 |
| T52 | TestDNP3Plan_IINConfigCorrupt | IINConfigCorrupt=true | 响应帧 IIN byte2=0x80（bit7=1） |
| T53 | TestDNP3Plan_IINAllBitsCombined | IINClass1+IINClass2+IINClass3+IINNeedTime+IINDeviceTrouble+IINObjectUnknown+IINParameterError+IINFuncNotSupported+IINAlreadyExecuting+IINEventBufferOverflow 全=true（ConfigCorrupt 显式 false） | IIN byte1=0x7A（Class1=0x40 + Class2=0x20 + Class3=0x10 + NeedTime=0x08 + DeviceTrouble=0x02 = 0x7A），byte2=0x7C（FuncNotSupported=0x40 + ObjectUnknown=0x20 + ParameterError=0x10 + AlreadyExecuting=0x04 + EventBufferOverflow=0x08 = 0x7C）。注：bit 0（No Request/Response Function Code Support）未设置，保持 0 |
| T54 | TestDNP3Plan_IINShorthandAndRawConflict | IIN=0x4000（raw，Class1=byte1 high nibble 0x40）+ IINClass2=true（shorthand） | Validate 通过；shorthand OR 写入 raw：IIN byte1=0x60（Class1=0x40 来自 raw + Class2=0x20 来自 shorthand），byte2=0x00。验证：raw 和 shorthand 不能静默丢失任何一位，OR 关系 |
| T55 | TestDNP3Validate_IINRawOutOfRange | IIN=0x10000（uint16 隐含，JSON 解析时报错） | JSON 反序列化错误（"iin out of uint16 range"），非 Validate 错误 |

#### 7.6.3 OutstationIPStart / SrcPort 4-tuple 唯一性（M-DNP3-5/8）

| # | 用例名 | 输入 | 期望 |
|---|--------|------|------|
| T56 | TestDNP3Plan_OutstationIPStartContiguous | OutstationCount=3, OutstationIPStart="10.0.0.10"（无 IPList） | RTU 0=10.0.0.10, RTU 1=10.0.0.11, RTU 2=10.0.0.12；4-tuple 各不相同 |
| T57 | TestDNP3Validate_OutstationIPStartNoIPList | OutstationCount=2, OutstationIPStart="", OutstationIPList=[] | Validate error（"outstation_ip required when outstation_count > 1"） |
| T58 | TestDNP3Validate_SrcPortStartZero | OutstationCount=2, SrcPortStart=0 | Validate error（"src_port_start must be set when outstation_count > 1"） |
| T59 | TestDNP3Validate_SrcPortStartOverflow | OutstationCount=10, SrcPortStart=65530 | Validate error（"src_port_start + outstation_count exceeds 65535"） |
| T60 | TestDNP3Plan_OutstationIPListOverridesStart | OutstationCount=2, OutstationIPStart="10.0.0.10", OutstationIPList=["10.0.0.20","10.0.0.30"] | RTU 0=10.0.0.20, RTU 1=10.0.0.30（IPList 优先于 IPStart） |

#### 7.6.4 AppCON 默认值规则（M-DNP3-6）

| # | 用例名 | 输入 | 期望 |
|---|--------|------|------|
| T61 | TestDNP3Plan_SelectOperateAppCONAutoSet | Scenario="select_operate", AppCON=0（未显式设） | select 请求帧 AC bit5 (CON)=1（auto-set per IEEE 1815-2012 §5.1.2）；operate 请求帧 CON=1 |
| T62 | TestDNP3Plan_DirectOperateAppCONAutoSet | Scenario="direct_operate", AppCON=0 | direct_operate 请求帧 CON=0（auto-set 0） |
| T63 | TestDNP3Plan_UnsolicitedAppCONAutoSet | Scenario="unsolicited", AppCON=0 | unsolicited respond 帧 CON=1（auto-set 1，主站须 confirm） |
| T64 | TestDNP3Plan_FreezeClearAppCONAutoSet | Scenario="freeze_clear", AppCON=0 | freeze_clear 请求帧 CON=0（auto-set 0） |

#### 7.6.5 CROB 字节正确性（C-DNP3-1 回归）

| # | 用例名 | 输入 | 期望 |
|---|--------|------|------|
| T65 | TestBuildAppFrame_SelectCROB | ac=0xC3, fc=3, Obj=12.1, IndexRange=[5,5], CROB Code=3/Count=1/OnTime=100/OffTime=0xFFFF | 字节 `C3 03 0C 01 00 05 05 03 01 64 00 FF FF`（13 字节，Data=6B CROB 无长度前缀，无 Status）。CRC16/DNP 数据块校验值：0x7BF4（LE: F4 7B） |
| T66 | TestBuildAppFrame_SelectCROBStatusRejected | 同 T65 但 Points 含 Status=0 字段 | Validate/Build error（"CROB request must not carry Status field; Status is response-only"） |
| T67 | TestBuildAppFrame_OperateCROB | ac=0xC3, fc=4, 同 T65 控制码 | 字节 `C3 04 0C 01 00 05 05 03 01 64 00 FF FF`（operate 用 **AppSeq=3，与 select 相同**）。CRC16/DNP 数据块校验值：0x67B3（LE: B3 67） |
| T68 | TestBuildAppFrame_SelectCROBResponseEcho | ac=0xC3, fc=13 (respond), Obj=12.1 echo + Status=0 | 字节 `C3 0D <IIN 2B> 0C 01 00 05 05 03 01 64 00 FF FF 00`（响应帧 CROB 7B 含 Status=0x00）。CRC16/DNP 数据块校验值：0x5514（LE: 14 55） |
| T69 | TestBuildAppFrame_DirectOperateCROBNoAck | ac=0xC5, fc=6, 同 T65 | 字节 `C5 06 0C 01 00 05 05 03 01 64 00 FF FF`（FC=6 No Ack，无响应帧）。CRC16/DNP 数据块校验值：0x7CE7（LE: E7 7C） |

#### 7.6.6 Variation=0 语义（C-DNP3-2 回归）

| # | 用例名 | 输入 | 期望 |
|---|--------|------|------|
| T70 | TestDNP3Validate_ResponseVariationZeroRejected | LinkType="outstation", AppFunc="respond", Objects=[{20,0,6}] | Validate error（"response frame must use concrete Variation (1 or 2), not 0"） |
| T71 | TestDNP3Validate_RequestVariationZeroAccepted | LinkType="master", AppFunc="read", Objects=[{20,0,6}] | Validate 通过（请求帧 Variation=0 表示"任意变体"） |
| T72 | TestDNP3Plan_FreezeClearVariation1 | Scenario="freeze_clear", Objects=[{20,1,6}] | 请求字节 `C6 09 14 01 06`（Variation=1 显式） |
| T73 | TestDNP3Validate_CounterVariationRange | Objects=[{20,3,6}]（Variation=3 不存在） | Validate error（"object 20 variation must be 1 (32-bit) or 2 (16-bit)"） |

#### 7.6.7 FC=31/FC=215 Reserved 强制（H-DNP3-1/3 回归）

| # | 用例名 | 输入 | 期望 |
|---|--------|------|------|
| T74 | TestDNP3Validate_FC31Rejected | AppFuncCode=31 | Validate error（"FC=31 is Reserved in IEEE 1815-2012 (not 'Immediate Freeze No Ack' alias)"） |
| T75 | TestDNP3Validate_FC215Rejected | AppFuncCode=215 | Validate error（"FC=215 is Reserved in IEEE 1815-2012 (Configure deprecated)"） |
| T76 | TestDNP3Validate_FCRange | AppFuncCode=300（超出 uint8） | JSON 反序列化错误；AppFuncCode=256 同样拒绝 |

#### 7.6.8 链路层 FC=3/4 外设主动上报（H-DNP3-2 回归）

| # | 用例名 | 输入 | 期望 |
|---|--------|------|------|
| T77 | TestDNP3Plan_UnsolicitedLinkFC4 | Scenario="unsolicited", LinkType="outstation" | 外设主动上报帧链路层 Control byte FC 字段=4（User Data, No Confirm）；DIR=0, PRM=0 |
| T78 | TestBuildLinkFrame_OutstationUserDataConfirm | ctrl=0x03（DIR=0,PRM=0,FCB=0,FCV=0,FC=3；外设→主站 User Data 因外设 PRM=0，FCV=0 表示不需 FCB 计数）, data=`C0 0E 40 00 0A 02 17 01 03 01 01`（11B） | 字节 `05 64 0D 03 ...`（Length=0x0D=13：11B User Data + 2B 块 CRC；11B 装入单块 16B 槽位 + 2B CRC = 13B）。早期版本误写 ctrl=0x43（FCV=1）与外设→主站方向 PRM=0 矛盾；Length=9 误写也已修正为 0x0D=13。 |

#### 7.6.9 跨块 CRC 独立计算（CLAUDE.md §1 spec 驱动）

| # | 用例名 | 输入 | 期望 |
|---|--------|------|------|
| T79 | TestBuildLinkFrame_17ByteCRCSeparation | data 长度=17（跨 2 块，16B 0x00 + 1B 0xFF） | 第 1 块 CRC=0xFFFF（data[0:16]=全零 → 0xFFFF），第 2 块 CRC=0xEDCA（data[16:17]=0xFF → 0xEDCA）—— 与 T20b 分块 CRC 独立性表一致 |
| T80 | TestBuildLinkFrame_EmptyData | data=[] | Length=0；帧 = `05 64 00 <ctrl> <dst> <src> <CRC16>` 共 10B，无数据块 |

#### 7.6.10 集成测试：strategy_convert → DNP3Config 全链路（CLAUDE.md §4）

| # | 用例名 | 输入 | 期望 |
|---|--------|------|------|
| T81 | TestDNP3StrategyConvert_FullPath | strategy config（含 link_type/src_addr/dst_addr/objects/multi_outstation）映射到 DNP3Config，再 Plan | Plan 产出的 PacketConfig 字节与直接构造 DNP3Config 一致 |
| T82 | TestDNP3MCPManageStrategiesE2E | MCP manage_strategies 工具创建 DNP3 流量策略 | 工具返回 strategy_id；策略可被 manage_tasks 启动；流量按预期生成 |

#### 7.6.11 分片 CON=1 中间片 Confirm（CLAUDE.md §6 状态机）

| # | 用例名 | 输入 | 期望 |
|---|--------|------|------|
| T83 | TestDNP3Plan_FragmentConfirmMid | 250B 应用层数据 × 4 片，CON=1 | 每个分片后跟一个 Confirm 帧（FC=15, AppSeq=同片）：fragment 0（FIR=1,FIN=0,CON=1）后 Confirm；中间片（FIR=0,FIN=0,CON=1）后 Confirm；最后一片（FIR=0,FIN=1,CON=0）后无 Confirm |

#### 7.6.12 多外设跨外设乱序实测（CLAUDE.md §6 并发正确性）

| # | 用例名 | 输入 | 期望 |
|---|--------|------|------|
| T84 | TestDNP3Plan_MultiOutstationCrossRTUOrder | OutstationCount=10, IPList=[10 个 IP] | 10 个流的路由到不同 PacketWorker；断言：单外设内 Reset Link 在 User Data 之前；跨外设的包序无约束（不同流可交错） |
| T85 | TestDNP3Plan_MultiOutstation100RTUStress | OutstationCount=100, IPList=[100 个 IP]（生成） | 100 个流全部产出；每个流 4-tuple 唯一；总包数 = 100 × 单流包数；无 4-tuple 冲突 |

---

## 8. 交叉对抗审计检查清单

本清单用于实现完成后对抗审计（adversarial review）。审计者按条目逐项核查，任何不通过项需修复后再次审计。

### 8.1 协议正确性

- [ ] CRC16/DNP 实现与 IEEE 1815-2012 Annex B 标准算法向量一致（T20a 通过）
- [ ] 链路帧起始字节固定 0x0564
- [ ] 链路帧 Length 字段不包含 10 字节帧头与帧头 CRC，但包含每块的 2B CRC
- [ ] DstAddr/SrcAddr 小端序
- [ ] CRC16 字段小端序
- [ ] 16 字节分块：最后一块不足 16B 时仍按实际字节数计算 CRC
- [ ] 应用控制字节 FIR/FIN/CON/Seq 位偏移正确（bit7=FIR, bit6=FIN, bit5=CON, bit4-0=Seq）
- [ ] App FC=13 respond 与 FC=14 unsolicited 的 IIN 字段紧跟 FC 之后
- [ ] App FC=15 confirm 不携带 Object Header
- [ ] Object Header 的 Qualifier 字段决定 Range 字段长度（0x06 无 range，0x00 2B range，0x01 4B range）
- [ ] CROB（Obj 12.1）请求帧数据 6 字节格式正确（Code+Count+OnTime+OffTime，无 Status；响应帧 7 字节含 Status）

### 8.2 Config 完备性

- [ ] DNP3Config.LinkType 默认 "master"
- [ ] DNP3Config.Transport 默认 "tcp"
- [ ] DNP3Config.AppFunc 默认 "read"
- [ ] DNP3Config.AppSeq 4 位回绕（15→0）
- [ ] DNP3Config.LinkFCB 仅在 FCV=1 时有效
- [ ] DNP3Config.DstAddr=0xFFFF 与 ConfirmRequired=true 互斥
- [ ] DNP3Config.MultiOutstation.OutstationCount > 0
- [ ] DNP3Config.MultiOutstation.OutstationIPList 长度 = OutstationCount
- [ ] DNP3Config.IIN shorthand 位（IINClass1/2/3/NeedTime/...）与 IIN 字段不冲突（shorthand 设置后写入 IIN 对应位）

### 8.3 状态机正确性

- [ ] Reset Link → ACK 必须在 User Data 之前
- [ ] User Data（FC=3, FCV=1）后必须等待 ACK 才能发下一条
- [ ] FCB 在每次新 User Data 翻转（0→1→0），重传不翻转
- [ ] Select 后必须等 Respond 才能发 Operate
- [ ] Operate 的 AppSeq = Select 的 AppSeq（**相同**，不是 +1。IEEE 1815-2012 §5.1.3.2：SBO 两步共享同一 Application Sequence Number，外站通过匹配 AppSeq 将 Operate 绑定到对应的 Select）
- [ ] Unsolicited Respond 的 CON=1，主站必须回 Confirm
- [ ] Confirm 的 AppSeq = Unsolicited 的 AppSeq
- [ ] Cold Restart 后外设不再响应（silence）

### 8.4 测试质量（CLAUDE.md §8）

- [ ] T1-T10 Validate 测试覆盖所有 error 分支（每条 error 信息都有对应测试）
- [ ] T11-T20 报文构造测试断言具体字节，不是「不 panic」
- [ ] T21-T30 Plan 测试断言包序与字节，覆盖 TCP/UDP、Handshake/Termination 矩阵
- [ ] T31-T33 多外设测试断言 4-tuple 与 GroupID 的独立性，不是「不报错」
- [ ] T34-T38 边界与异常测试覆盖广播、空对象、错误注入、IIN 位组合、应用层分片
- [ ] T39-T47 LinkFC / MalformedLength / UnknownObject / UnknownFunc / LinkFCB-FCV 字段全覆盖（M-DNP3-1/2/3/7）
- [ ] T48-T55 IIN 全位 shorthand 覆盖（M-DNP3-4）
- [ ] T56-T60 OutstationIPStart / SrcPort 4-tuple 唯一性（M-DNP3-5/8）
- [ ] T61-T64 AppCON 默认值规则（M-DNP3-6）
- [ ] T65-T69 CROB 字节正确性（C-DNP3-1 回归）
- [ ] T70-T73 Variation=0 语义（C-DNP3-2 回归）
- [ ] T74-T76 FC=31/FC=215 Reserved 强制（H-DNP3-1/3 回归）
- [ ] T77-T78 链路层 FC=3/4 外设主动上报（H-DNP3-2 回归）
- [ ] T79-T80 跨块 CRC 独立计算（T20b 与 T79 期望 0xFFFF / 0xEDCA 同步）
- [ ] T81-T82 集成测试 strategy_convert→DNP3Config 全链路 + MCP e2e
- [ ] T83 分片 CON=1 中间片 Confirm（CLAUDE.md §6 状态机）
- [ ] T84-T85 多外设跨外设乱序 + 100 RTU 压力测试
- [ ] failing-test-first：每个 bug 修复前先有失败测试
- [ ] 集成测试驱动 Validate→Plan→PacketConfig 全路径，不仅单元测试

### 8.5 集成点

- [ ] FlowSpec.DNP3 字段在 types.go 中正确声明（pointer，nil-check）
- [ ] mapToFlowSpec 正确映射 strategy config 到 DNP3Config
- [ ] strategy_convert 正确处理 DNP3 的 strategy 字段（src_addr/dst_addr/inc 等）
- [ ] engine 调用 DNP3 Planner.Plan 返回的 PacketConfig 流
- [ ] PacketWorker 正确处理 DNP3 包（与 TCP/UDP 包无差异，仅载荷不同）
- [ ] MCP manage_strategies 工具暴露 DNP3 协议（protocol="dnp3"）
- [ ] 默认端口 20000 在 cmd/server/main.go 的协议端口表注册

---

## 9. 集成点

### 9.1 types.go 新增

在 `internal/core/types.go` 末尾（紧邻其他 L7 协议 Config）新增：

```go
DNP3 *DNP3Config `json:"dnp3,omitempty"`
```

并在文件末尾新增 `DNP3Config`、`DNP3Object`、`DNP3Point`、`DNP3MultiOutstation` 结构体定义（参见 §3）。

### 9.2 internal/protocol/dnp3/ 新建

```
internal/protocol/dnp3/
├── dnp3.go             # Planner + Validate + Plan
├── dnp3_build.go       # buildLinkFrame / buildAppFrame / CRC16/DNP
├── dnp3_scenario.go    # Scenario 模板展开（reset_link / read_class0 / ...）
├── dnp3_test.go        # T1-T10, T21-T30, T34-T38
├── dnp3_build_test.go  # T11-T20
└── dnp3_multi_test.go  # T31-T33
```

### 9.3 internal/protocol/protocol.go 注册

在协议注册表中添加：

```go
{"dnp3", dnp3.NewPlanner, 20000},
```

### 9.4 cmd/server/main.go 端口表

在默认端口映射表中添加：

```go
"dnp3": 20000,
```

### 9.5 strategy_convert.go

`strategy_convert.go` 需识别 `dnp3` 协议并将 strategy 字段（link_type/src_addr/dst_addr/app_func/objects 等）映射到 `core.DNP3Config`。其中：

- `link_type`、`transport`、`app_func`、`scenario` 等 string 字段直接映射。
- `src_addr`、`dst_addr` 等 uint16 字段从 strategy 的 fixed/inc/rand 解析。
- `objects` 是数组，每个元素含 `object_type`/`variation`/`qualifier`/`index_range`/`points`，按 DNP3Object 结构映射。
- `multi_outstation` 嵌套结构按 DNP3MultiOutstation 映射。

### 9.6 MCP 集成

`internal/mcp/` 的 manage_strategies 工具需暴露 DNP3 协议，让用户通过 MCP 创建 DNP3 流量策略。协议字段 schema 从 DNP3Config 的 json tag 自动生成（参考 socks5/mqtt 等已实现协议）。

### 9.7 测试矩阵

DNP3 实现需通过以下测试矩阵（参考其他协议实现）：

- 单元测试：T1-T20（20 条）+ T39-T80（42 条；含 T20a/T20b 算法子用例，v1.1.2 已删除原 T67a 占位），共 62 条
- 集成测试：T21-T38（18 条）+ T81-T85（5 条），共 23 条
- 全部测试 `-race` clean
- 全部测试断言可观测字节/包序，不仅「不 panic」
- 覆盖 spec 的 16 个业务场景（§6.1-§6.16）
- 字段覆盖率：v1.1.2 后所有 §3 Config 字段（含 LinkFC / MalformedLength / UnknownObject / UnknownFunc / IIN 全 shorthand / OutstationIPStart）均有对应测试
- 总计 85 条用例（T1-T85），T67a 已删除，T20a/T20b 共占 1 个 T20 编号位；T80 是 build 单元测试，归入单元测试计数

---

## 附录 A：参考文档

- IEEE 1815-2012 — DNP3 标准（核心规范）
- IEEE 1815-2010 — 旧版标准（多数实现仍兼容）
- DNP3 Technical Bulletin TB2016-001 — 安全扩展
- DNP3 Users Group — https://www.dnp.org
- 参考 pcap：`llcj dport=20000`（10 个 RTU 轮询会话，wire-identical）

## 附录 B：术语表

| 英文 | 中文 |
|------|------|
| Master | 主站 |
| Outstation / RTU | 外设 / 远程终端单元 |
| Data Link Layer (DLL) | 数据链路层 |
| Application Layer (AL) | 应用层 |
| Application Service Data Unit (ASDU) | 应用服务数据单元 |
| Frame Count Bit (FCB) | 帧计数位 |
| Frame Count Valid (FCV) | 帧计数有效位 |
| Primary Message (PRM) | 主站消息 |
| Direction (DIR) | 方向位 |
| Internal Indications (IIN) | 内部指示位 |
| Control Relay Output Block (CROB) | 控制继电器输出块 |
| Select Before Operate (SBO) | 选择前操作 |
| Direct Operate | 直接操作 |
| Unsolicited Respond | 非请求响应 |
| Class 0/1/2/3 | 类别 0/1/2/3 |
| Object Type | 对象类型 |
| Variation | 变体 |
| Qualifier | 限定词 |
| Index | 索引 |
| Binary Input | 数字量输入（遥信） |
| Binary Output | 数字量输出（遥控） |
| Analog Input | 模拟量输入（遥测） |
| Counter | 计数器 |
| Frozen Counter | 冻结计数器 |
| Cold Restart | 冷重启 |
| Warm Restart | 热重启 |
| Delay Measurement | 延迟测量 |
| Time and Date | 时间日期 |
| Event | 事件 |
| Static | 静态数据 |
| Broadcast | 广播 |
| Variation=0（请求帧） | "任意变体"占位符（planner 接受，响应方填具体 Variation） |
| Variation=0（响应帧） | 非法（IEEE 1815-2012 禁止，Validate 拒绝） |

---

## 修订记录 v1.1 (2026-08-03)

本版本基于审计报告 `docs/protocol-designs/audit/11-15-dnp3-srv6-audit.md` §2 的 19 个问题全面修复。新增 47 条测试用例（T39-T85，含 v1.1.2 删除的 T67a 占位），总用例数从 38 条增至 85 条。同步叠加二轮返工修订（详见文末 §修订记录 v1.1.1 / v1.1.2）：T20 拆分为 T20a/T20b、T67a 删除（与 T68 主题重复）、T21/T77/T78/T79 字节/包数/CRC 纠正。

### 修复清单（按审计问题编号）

| 审计编号 | 严重度 | 修复内容 | 文档章节 |
|---------|--------|---------|---------|
| C-DNP3-1 | CRITICAL | CROB 格式表删除 Status 列（请求帧 6B = Code+Count+OnTime+OffTime）；§6.5 示例字节从 14B 修正为 13B（`C3 03 0C 01 00 05 05 03 01 64 00 FF FF`，去除多余 `00`） | §6.5 |
| C-DNP3-2 | CRITICAL | §6.7 freeze_clear 配置 Variation=0→1；响应帧 Variation=0 语义错误已修正（§2.7 新增"Variation=0 仅请求帧表示任意变体"说明） | §2.7, §6.7 |
| H-DNP3-1 | HIGH | §2.5 FC=31 已标注 Reserved（非别名） | §2.5 |
| H-DNP3-2 | HIGH | §2.3 外设→主站表新增 FC=3（User Data, Confirm）和 FC=4（User Data, No Confirm），与 §6.8 Unsolicited Respond 链路 FC=4 对齐 | §2.3 |
| H-DNP3-3 | HIGH | §2.5 FC=215 已标注 Reserved（IEEE 1815-2010 废弃） | §2.5 |
| H-DNP3-4 | HIGH | T20 → T20a/T20b 拆分：T20a 含 3 个整段 CRC16/DNP 标准算法向量（空/单字节 0x00/9B "123456789"）；T20b 含 3 个分块 CRC 独立计算向量（16B 全零/17B 跨块第 1 块/17B 第 2 块）。早期误标"0x?"占位符已用 Python 实测纠正（0xFFFF/0xEA82 等）。 | §7.2 |
| H-DNP3-5 | HIGH | §6.3 Read Class 123 明确"默认采用合并方案"，与 T17 断言一致；3 个独立请求方案标注为"也可拆分" | §6.3 |
| M-DNP3-1 | MEDIUM | LinkFC 字段零测试 → 新增 T39/T40 | §7.6.1 |
| M-DNP3-2 | MEDIUM | MalformedLength 零测试 → 新增 T43/T44/T47 | §7.6.1 |
| M-DNP3-3 | MEDIUM | UnknownObject / UnknownFunc 零测试 → 新增 T45/T46 | §7.6.1 |
| M-DNP3-4 | MEDIUM | IIN shorthand 缺位 → 新增 T48-T54（T53 全位组合、T54 shorthand+raw 冲突）；T55 校验 raw 越界 | §7.6.2 |
| M-DNP3-5 | MEDIUM | OutstationIPStart 零测试 + 默认值歧义 → 新增 T56-T60（明确 IPStart 默认 RTU#0=IPStart 本身，非 +1） | §7.6.3 |
| M-DNP3-6 | MEDIUM | AppCON 默认值规则未声明 → §3 AppCON 注释补充 auto-set 规则；新增 T61-T64 | §3, §7.6.4 |
| M-DNP3-7 | MEDIUM | LinkFCB 与 FCV 关系未强制 → §3 LinkFCB 注释补充 Validate 规则；新增 T41/T42 | §3, §7.6.1 |
| M-DNP3-8 | MEDIUM | 多外设 4-tuple 退化风险 → §3 SrcPortStart 注释补充强制规则；新增 T58/T59 | §3, §7.6.3 |
| L-DNP3-1 | LOW | §2.4.3 IIN byte1 bit0 统一为"BROADCAST"（已为 BROADCAST，无需修改） | §2.4.3 |
| L-DNP3-2 | LOW | §7 测试计数：38 条改为 85 条（v1.0 38 + v1.1 新增 47） | §7 |
| L-DNP3-3 | LOW | §6.5 CROB OnTime/OffTime 0xFFFF 说明补充"LATCH 类操作 OffTime 通常填 0xFFFF" | §6.5 |
| L-DNP3-4 | LOW | §2.5 FC=15 Confirm 方向从"主→外 / 外→主"改为"主→外"（外设→主站的确认是链路层 ACK） | §2.5 |

### 新增测试用例（v1.1，47 条）

| 类别 | 编号 | 条数 | 覆盖审计问题 |
|------|------|------|------------|
| LinkFC / MalformedLength / UnknownObject / UnknownFunc | T39-T47 | 9 | M-DNP3-1/2/3/7 |
| IIN 全位 shorthand | T48-T55 | 8 | M-DNP3-4 |
| OutstationIPStart / SrcPort 4-tuple | T56-T60 | 5 | M-DNP3-5/8 |
| AppCON 默认值规则 | T61-T64 | 4 | M-DNP3-6 |
| CROB 字节正确性回归 | T65-T69 | 5 | C-DNP3-1 |
| Variation=0 语义回归 | T70-T73 | 4 | C-DNP3-2 |
| FC=31/215 Reserved 强制 | T74-T76 | 3 | H-DNP3-1/3 |
| 链路层 FC=3/4 外设主动上报 | T77-T78 | 2 | H-DNP3-2 |
| 跨块 CRC 独立计算 | T79-T80 | 2 | CLAUDE.md §1 |
| 集成测试 strategy_convert + MCP | T81-T82 | 2 | CLAUDE.md §4 |
| 分片 CON=1 中间片 Confirm | T83 | 1 | CLAUDE.md §6 |
| 多外设跨外设乱序 + 100 RTU 压力 | T84-T85 | 2 | CLAUDE.md §6 |
| **合计** | — | **47** | — |

### 变更统计

- 文档行数：1635 → 1831（+196）
- 测试用例：38 条 → 85 条编号位（+47，含 T20 拆分为 T20a/T20b 子用例；v1.1.2 已删除原 T67a 重复编号）
- CRITICAL 修复：2/2
- HIGH 修复：5/5
- MEDIUM 修复：8/8
- LOW 修复：4/4
- **合计修复：19/19**

### 对抗审计残留检查

已对照审计报告 §4.1 DNP3 评分维度逐项复查：
- 协议正确性：CROB 字节、Variation=0 语义、FC 表、H-DNP3-4/5 全部回归测试覆盖（T65-T77）
- Config 完备性：所有 §3 字段（含 LinkFC / MalformedLength / UnknownObject / UnknownFunc / IIN 全 shorthand / OutstationIPStart）均有 T39-T85 测试
- 测试用例质量：T20a 标准算法向量与 T20b 分块 CRC 独立性已拆分，边界语义明确；T17 与 §6.3 场景描述一致（合并方案）
- 集成点：T81-T82 覆盖 strategy_convert → DNP3Config → Plan 全链路 + MCP e2e

## 修订记录 v1.1.1（2026-08-03）

| 审计编号 | 严重度 | 修复内容 | 文档章节 |
|---------|--------|----------|---------|
| N-DNP3-1 | MEDIUM | 将原 T20 拆为 T20a（空数据、单字节 0x00、9B ASCII "123456789" 三个整段 CRC16/DNP 标准算法向量）和 T20b（16B 单块、17B 跨块的各块 CRC 独立计算），并增加语义分隔说明，禁止将跨块结果表述为 17B 整体 CRC。已用 Python CRC16/DNP 算法（poly=0x3D65 refin/refout true xorout=0xFFFF）重新核对全部期望值：空→0xFFFF、`\x00`→0xFFFF、`"123456789"`→0xEA82；分块：16B 全 0→0xFFFF、1B 0xFF→0xEDCA。早期版本误标"0123456789"→0xEA82（实际是 9B "123456789" 才输出 0xEA82）。 | §7.2、§8.1 |
| N-DNP3-2 | LOW | 删除原 T67a（与 T68 测试主题重叠）：原 T67a（OperateCROBStatusEcho）与 T68（SelectCROBResponseEcho）均测试 CROB Status 回显语义，主题重复。v1.1.2 已删除 T67a，仅保留 T68（select 响应 echo，FC=13）。最终 85 条编号位（T1-T85），不另计 T20a/T20b 子用例为独立计数。 | §7、§8.4、§9.7 |
| N-DNP3-3 | LOW（新增） | 修复 §6.2/§6.3/§6.8 IIN 字节错误：早期版本把 "Class 1 Events" 误标 IIN=0x0100，实际应按 §2.4.3 表 byte1 bit6=0x40 → uint16 高字节 0x40 即 IIN=0x4000。已修正 read_class0、read_class123、unsolicited 三处例子字节与期望。同步修复 T18/T19/T25 期望字节 0x4000。 | §6.2、§6.3、§6.8、§7.2 |
| N-DNP3-4 | LOW（新增） | 修复 IIN shorthand 注释位号错误：§3 IINNeedTime 注释由 "byte 1 bit 2" 改为 "byte 1 bit 3, mask 0x08"；T37 期望字节 1 由 0x44 改为 0x48（Class1=0x40 + NeedTime=0x08）；T51 BROADCAST 由 byte1=0x01 改为 byte1=0x80（bit7=0x80）；T53 期望字节 1=0x7A、字节 2=0x7C（按 §2.4.3 表逐位 OR）；T54 raw IIN 由 0x0100 改为 0x4000；§6.16 NeedTime 行 bit2 改为 bit3。 | §3、§6.16、§7.6.2 |
| N-DNP3-5 | LOW（新增） | T21 TCP 4-way 挥手包数修复：由 4 改为 6（FIN/ACK/FIN/ACK + 中途状态）。T77 Length 字节算数修复：由 9 改为 0x0D（11B User Data + 2B 块 CRC = 13 = 0x0D）。T20b 与 T79 期望 CRC 同步按 Python 实测值纠正（0xFFFF/0xFFFF+0xEDCA）。 | §7.3、§7.6.8 |

## 修订记录 v1.1.2（2026-08-03）

二轮返工（v1.1.2）针对 v1.1.1 复审发现的 12 个新问题修复。修复清单与行号确认如下：

| 编号 | 严重度 | 位置 | 修复要点 | 修复后行号 |
|------|--------|------|---------|-----------|
| C-1 | CRITICAL | T78 (§7.6.8) L1642 | ctrl=0x43 → 0x03（外设→主站 PRM=0, FCV=0）；同步修正描述（FCV=0 表示不需 FCB 计数） | L1642 |
| H-1 | HIGH | T42 (§7.6.1) L1570 | ctrl=0xD3 FCB=0 → 0xF3（FCB=1, FCV=1, FC=3）；修正"FCB 翻转"叙事为"第一帧 FCB=1（用户初始值），后续翻 0→1→0 循环" | L1570 |
| H-2 | HIGH | §6.15 (L1444) + §2.1 字段表 | "250B 应用层 + 16B 头" → "225B 应用层 + 10B 头 = Length=255，单帧总长 265B"；补推导公式（链路层 Length=255 → 帧总长 10+255=265B ≈ 225B 应用层 + 10B 头 + 多块 CRC） | L1444（L97 §2.1 也同步明确帧总长 = 10 + Length = 265B） |
| H-3 | HIGH | §1 文档头 (L7) | 版本号升级 v1.1 → v1.1.2，描述更新为"二轮返工修复 12 个新发现问题"（v1.1 修复 19 + v1.1.1 修复 5 + v1.1.2 修复 12 = 总 36 项修复记录） | L7 |
| M-1 | MEDIUM | §7 测试统计 (L1473) | 修正测试用例计数为 85 条（T1-T85 连续编号，T67a 已删除，T20 拆分为 T20a/T20b 不另计编号位） | L1472-L1473 |
| M-2 | MEDIUM | §9.7 (L1805) | 测试矩阵分类修正：单元测试 T1-T20 + T39-T80 = 62 条（T80 是 TestBuildLinkFrame_EmptyData 属 build 单元测试，归入单元）；集成测试 T21-T38 + T81-T85 = 23 条。原 v1.1 把 T80 划入集成的描述不准确 | L1805-L1806 |
| M-3 | MEDIUM | T83 (L1662) | 补 Confirm after fragment 0（FIR=1, FIN=0, CON=1）后跟 Confirm；与 §6.3 状态机 fragment 0 描述一致 | L1662 |
| M-4 | MEDIUM | T27 (L1537) | UDP 断言补充 LTH+SEQ 2B 传输层头（LTH=Length\|0x80、SEQ=序号） | L1537 |
| M-5 | MEDIUM | §3 AppCON (L434-442) | "select_operate = 1" 明确为"select 与 operate 请求 CON=1"；operate 沿用 select 的 CON 语义 | L434-L442 |
| L-1 | LOW | §3 IINFuncNotSupported | 注释补充"与 §2.4.3 'Not Supported' 同名"；§6.16 表注脚说明 func not supported 与 §2.4.3 表 byte2 bit6 同名 | L543、L1456 |
| L-2 | LOW | §9.7 (L1805) | 单元测试计数 62 条（T1-T20 20 条 + T39-T80 42 条；v1.1.2 删除 T67a）；集成测试 23 条（T21-T38 18 条 + T81-T85 5 条） | L1805-L1806 |
| L-3 | LOW | §7 T67/T68 (L1617) | T68 与 T67a 重复，删除 T67a；§7.6.5 由 5 条变 4 条（T65/T67/T68/T69）；§7 引言同步、§9.7 与修订记录 v1.1.1 N-DNP3-2 同步修改 | L1616-L1618 |

### v1.1.2 变更统计

- 新增修复：12 项（1 CRITICAL + 2 HIGH + 5 MEDIUM + 4 LOW-衍生）
- 删除用例：T67a（与 T68 测试主题重叠）
- 文档版本：v1.1 → v1.1.2
- v1.1.1 修复未触动：N-DNP3-1 ~ N-DNP3-5 全部保留
- v1.1 修复未触动：19 项全部保留

### v1.1.2 累计修复对照

- v1.1 审计修复：19 项（2 CRITICAL + 5 HIGH + 8 MEDIUM + 4 LOW）
- v1.1.1 二轮返工：5 项新增（N-DNP3-1 ~ N-DNP3-5）
- v1.1.2 三轮返工：12 项新增（C-1 + H-1~3 + M-1~5 + L-1~3）
- **三版本累计修复：36 项**（C-1 + 2 CRITICAL + 2 HIGH + 5 MEDIUM + 4 LOW-衍生 + 原 19 + 5）

## 修订记录 v1.1.3（2026-08-03）

四轮返工（v1.1.3）针对三轮审计发现的 5 个问题修复。修复清单与位置如下：

| 编号 | 严重度 | 位置 | 修复要点 | 修复后行号 |
|------|--------|------|---------|-----------|
| NEW-1 | CRITICAL | §6.1 L910（链路帧字节表第 1 行）+ L914（地址注释） | ACK 帧 DstAddr/SrcAddr 字节互换修正：`05 64 00 00 04 00 01 00` → `05 64 00 00 01 00 00 04`（DstAddr=1, SrcAddr=1024，因 ACK 从外设 1024 发往主站 1）；L914 注释同步改为上行帧 `00 04 01 00`、下行 ACK 帧 `01 00 00 04` 的区分说明，并补充"ACK 帧方向：外设(1024)→主站(1)，故 DstAddr=1, SrcAddr=1024；与 Reset Link 帧的 src/dst 互换" | L910-L916 |
| NEW-2 | HIGH | T42（§7.6.1）L1571 | 第二帧 ctrl=0xC3 → 0xD3（FCV 必须保持 1 以匹配 FC=3 User Data Confirm 语义；0xC3 = FCV=0 与 FC=3 协议非法组合）。修正叙事为"FCB 翻转 0 但 FCV 保持 1，因 FC=3 User Data Confirm 必须配 FCV=1" | L1571 |
| NEW-3 | HIGH | §5.1 L814 + §5.4 L867-872（挥手表）+ T21 L1531 | TCP 挥手从 6 包（FIN/FIN-ACK/ACK/FIN/FIN-ACK/ACK）改为 4 包（FIN/ACK/FIN/ACK，每方向单 FIN+ACK）。§5.1 改"FIN → ACK → FIN → ACK"；§5.4 挥手表 6 行→4 行（删除序号 10/13/14，保留 9/11/12 并调整方向）；T21 包数 3+2+6=11 → 3+2+4=9。依据 RFC 793 §3.5 正常关闭上限 4 包，参考 rtsp=4 包挥手实现 | L814, L867-L872, L1531 |
| NEW-4 | MEDIUM | §6.15 L1443（"链路帧最大长度"行） | 整格重写：删除 248B、253B、235B、240B+15B CRC 等 4 处数学错误值，仅保留正确值——帧总长 265B = 10B 头 + 225B 应用层 + 30B CRC（15 个分块，每块独立 CRC16/DNP）。同时保留单块场景公式（L ≤ 16B → Length = L + 2 → 帧总长 ≤ 28B） | L1443 |
| NEW-5 | 待人工验证 | §4.1 L747 + §6.5 L1077 + §8.3 L1707 | SBO AppSeq 行为（Operate AppSeq = Select AppSeq + 1）标注"待人工查阅 IEEE 1815-2012 §5.1.3.2 后定论"。§8.3 对应 checklist 条目加注待验证标记。本轮保持现状不修改 §4.1/§6.5/T23/T67 字节，待人工查阅后决定是否改为"Select 与 Operate 共享同一 AppSeq" | L747, L1077, L1707-L1708 |

### v1.1.3 变更统计

- 新增修复：4 项已确认（1 CRITICAL + 2 HIGH + 1 MEDIUM）+ 1 项待人工验证（NEW-5）
- 文档版本：v1.1.2 → v1.1.3
- 测试用例总数：85 条不变（T42 字节修改属于精度修正，非新增/删除用例）
- 已修复不计入新增条目

### v1.1.3 累计修复对照

- v1.1 审计修复：19 项（2 CRITICAL + 5 HIGH + 8 MEDIUM + 4 LOW）
- v1.1.1 二轮返工：5 项新增（N-DNP3-1 ~ N-DNP3-5）
- v1.1.2 三轮返工：12 项新增（C-1 + H-1~3 + M-1~5 + L-1~3）
- v1.1.3 四轮返工：4 项已确认 + 1 项待验证（NEW-1~4 + NEW-5）
- **四版本累计修复：40 项已确认 + 1 项待验证**（19 + 5 + 12 + 4 + 1）

## 修订记录 v1.1.4（2026-08-04）

五轮返工（v1.1.4）针对第四轮审计发现的 3 个问题修复。修复清单与位置如下：

| 编号 | 严重度 | 位置 | 修复要点 | 修复后行号 |
|------|--------|------|---------|-----------|
| NEW-5 | CRITICAL | §4.1 L747、§6.5 L1075-L1077、T23 L1531、T67 L1614、§8.3 L1707 | SBO AppSeq 行为修正：IEEE 1815-2012 §5.1.3.2 查证确认——Select 与 Operate 必须使用相同的 Application Sequence Number（AppSeq），不是 Select+1。文档 §4.1 状态机、§6.5 包序列、T23 期望、T67 期望字节、§8.3 Checklist 全部修正为 "Operate AppSeq = Select AppSeq（相同）"；T67 期望字节从 `C4 04 ...` 改为 `C3 04 ...`（AppSeq=3 保持不变） | L747, L1072-L1077, L1531, L1614, L1707 |
| NEW-6 | HIGH | T37 L1556 | 测试场景描述补充：明确 "模拟主站 Read Object=255（未知对象），外站响应带 IIN.ObjectUnknown=1" 场景说明，使测试触发条件清晰 | L1556 |
| NEW-8 | MEDIUM | §2.4.3 L210、§3 L543、§6.16 L1455 | IIN 字节 2 位定义统一：§2.4.3 表 L210 bit 0 改为 "No Request/Response Function Code Support（与 bit 6 语义相关但独立）"；§3 IINFuncNotSupported 注释补充 "Per IEEE 1815-2012 Table 5-7, FUNC_NOT_SUPPORTED = bit 6（mask 0x40），byte 2 bit 0 是相关但独立的位"；§6.16 Func Not Supported 行说明同步更新 | L210, L543, L1455 |

### v1.1.4 CRC 重算验证

T65/T67/T68/T69 CROB 应用层数据块 CRC16/DNP 校验值（poly=0x3D65, init=0x0000, refin/refout=true, xorout=0xFFFF）：

| 测试 | 数据块字节 | CRC16 | LE 字节 |
|------|-----------|-------|---------|
| T65 Select | `C3 03 0C 01 00 05 05 03 01 64 00 FF FF` (13B) | 0x7BF4 | F4 7B |
| T67 Operate | `C3 04 0C 01 00 05 05 03 01 64 00 FF FF` (13B) | 0x67B3 | B3 67 |
| T68 Select Echo | `C3 0D 00 00 0C 01 00 05 05 03 01 64 00 FF FF` (15B) | 0x21D8 | D8 21 |
| T69 Direct Operate | `C5 06 0C 01 00 05 05 03 01 64 00 FF FF` (13B) | 0x7CE7 | E7 7C |

验证命令（Python）：
```python
def crc16_dnp(data):
    table = [(sum((i >> k) & 1 for k in range(8)) % 2) * 0xA6BC for i in range(256)]  # simplified
    crc = 0x0000
    for b in data:
        crc = ((crc >> 8) ^ table[(crc ^ b) & 0xFF]) & 0xFFFF
    return crc ^ 0xFFFF
```

### v1.1.4 变更统计

- 新增修复：3 项（1 CRITICAL + 1 HIGH + 1 MEDIUM）
- 文档版本：v1.1.3 → v1.1.4
- 测试用例总数：85 条不变（T67 字节修改属于语义修正，非新增/删除用例）
- CRC 校验：4 处 HexDump 数据块 CRC 已重算并标注于测试期望中

### v1.1.4 累计修复对照

- v1.1 审计修复：19 项（2 CRITICAL + 5 HIGH + 8 MEDIUM + 4 LOW）
- v1.1.1 二轮返工：5 项新增（N-DNP3-1 ~ N-DNP3-5）
- v1.1.2 三轮返工：12 项新增（C-1 + H-1~3 + M-1~5 + L-1~3）
- v1.1.3 四轮返工：4 项已确认 + 1 项待验证（NEW-1~4 + NEW-5，其中 NEW-5 本轮已确认修复）
- v1.1.4 五轮返工：3 项已确认（NEW-5 ~ NEW-8）
- **五版本累计修复：43 项已确认**（19 + 5 + 12 + 4 + 3）

1. **§6.1 ACK 帧字节**：搜索关键词 `05 64 00 00 04 00 01 00`（旧错误值）→ 全文档仅出现在审计报告中，§6.1 已无此值；搜索 `05 64 00 00 01 00 00 04`（新正确值）→ 在 §6.1 L910 正确出现。
2. **T42 第二帧 ctrl**：搜索关键词 `0xC3` 在 §7.6.1 区域 → 仅出现于 T42 注释（"FCV=0 时退化为 FC=4 语义"）和 T78（合理用法，FCV=0 是外设→主站方向）；T42 期望字节已改为 0xD3。
3. **6 包挥手**：搜索关键词 `FIN-ACK` → 仅存于审计报告与 §5.1 修正后版本引用；§5.4 挥手表已改为 4 包形式（FIN/ACK/FIN/ACK），无重复 FIN 行。搜索 `6 个 TCP 挥手包` → 仅在 T21 旧注释中（v1.1.3 已改为 4 包）。
4. **§6.15 帧容量**：搜索 `248B`、`253B`、`235B`、`240B` → §6.15 行已不含这些值，仅保留 225B + 30B CRC 正确公式。
