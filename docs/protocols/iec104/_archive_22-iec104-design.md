# IEC 60870-5-104（IEC104，电力远动规约）协议设计

> 版本：v1.0.0（初稿）
> 设计日期：2026-08-18
> 范围：IEC 60870-5-104（简称 IEC104）在 TCP 2404 上的流量生成设计：APCI（application protocol control information，应用规约控制信息）帧格式、APDU（application protocol data unit，应用规约数据单元）结构、ASDU（application service data unit，应用服务数据单元，即 IEC 60870-5-101 应用层报文）类型编码、U 帧启动/停止/测试、I 帧数据交换（总召唤、单点/双点遥信、单点/双点命令）、S 帧确认；时钟同步属于规划内容，当前 16 个用例未落盘。
> 实现位置（规划）：`trafficgen/internal/protocol/iec104/`（终结层生成器 + 校验器）、`trafficgen/internal/core/layers/registry.go`（层注册）、`trafficgen/internal/core/types.go`（`IEC104Config` 定义）、`trafficgen/internal/core/strategy_convert.go`（`iec104` flat 键解析）
> 配套参考：层链配置架构（18-layer-config-design.md）；同类"TCP 终结层 + 配置经 flat 键直传"先例：enip（12-enip-design.md）、modbus（13-modbus-design.md）、doip（05-doip-design.md）；同域 IED 协议先例：dnp3（11-dnp3-design.md）
> 实现约束：本任务只产文档 + 用例（cases JSON），不改协议实现代码（审查通过后另开阶段）。

### 0. 术语约定（glossary，先读，避免歧义）

| 术语 | 中文解释 / 定义 | 备注 |
|------|----------------|------|
| IEC104 / IEC 60870-5-104 | IEC 60870-5-101（串行远动规约）在 TCP/IP 网络上的载体版本 | 电力系统远动规约，标准 TCP 2404 |
| 控制站（controlling station / master，主站） | 发起连接、发送命令、接收数据的调度端 | 生成器扮演的角色（客户端） |
| 被控站（controlled station / RTU / slave，厂站） | 监听 2404、上报遥测遥信、执行命令的一端 | 对端（服务器） |
| APCI | 应用规约控制信息（application protocol control information） | 每个 APDU 的前 6 字节 |
| APDU | 应用规约数据单元：APCI（6B）+ 可选 ASDU | 本设计的线上帧 |
| ASDU | 应用服务数据单元：类型标识 + 结构限定词 + 传送原因 + 公共地址 + 信息体 | IEC 60870-5-101 应用层报文 |
| I 帧（information transfer format） | 编号信息帧：APCI 控制域含发送/接收序号，可携带 ASDU | 数据交换载体 |
| S 帧（numbered supervisory format） | 编号监视帧：只含接收序号，无 ASDU | 纯确认 |
| U 帧（unnumbered control format） | 未编号控制帧：STARTDT/STOPDT/TESTFR | 启动/停止/测试 |
| k（发送窗口）/ w（接收窗口） | 未确认 I 帧上限 / 收到 w 个 I 帧后应回 S 帧确认 | §4 状态机 |
| T0/T1/T2/T3 | 连接建立超时 / 发送或测试 APDU 确认超时 / 无数据确认超时 / 长空闲测试超时 | §4.3 |
| 总召唤（general interrogation） | 控制站发 C_IC_NA_1，被控站回全部信息点 | §6 P02 |
| 时钟同步（clock synchronization） | 控制站发 C_CS_NA_1（CP56Time2a），被控站回确认 | 规划未落盘 |
| up / down | up = 控制站→被控站（客户端发）；down = 被控站→控制站（服务器回） | 与事件模式 `MessageEvent.Up` 一一对应 |
| 事件流（event stream） | 终结层产出 `MessageEvent` 的流，tcp 层逐段消费 | §5.1 |
| 遥信 / 遥测 / 遥控 | 状态量（开关位置）/ 测量值（电流电压）/ 命令（合闸分闸） | 电力术语 |

---

## 目录

1. [概述](#1-概述)
2. [数据类型与编码](#2-数据类型与编码)
3. [消息结构](#3-消息结构)
4. [状态机](#4-状态机)
5. [配置类型定义](#5-配置类型定义)
6. [包序列场景（HexDump P01-P12）](#6-包序列场景hexdump-p01-p12)
7. [与 testcase 文档的映射索引](#7-与-testcase-文档的映射索引)
8. [实现集成点](#8-实现集成点)
9. [错误处理](#9-错误处理)
10. [扩展字段映射](#10-扩展字段映射)
11. [修订记录](#11-修订记录)

---

## 1. 概述

### 1.1 定位（这一章回答"我们到底在生成什么"）

**IEC 60870-5-104** 是国际电工委员会（IEC）TC57 制定的电力系统远动规约：把 IEC 60870-5-101（原本跑在串行线路上）的应用层 ASDU 搬上 TCP/IP。IEC104 之于 101，类似 DNP3 TCP 之于 DNP3 串口——**应用层语义不变，传输层换掉**。IEC104 在调度主站与厂站 RTU（remote terminal unit，远方终端单元）之间传输：

- 遥信（单点 M_SP / 双点 M_DP）：开关、刀闸、保护动作等状态量，厂站→主站上报；
- 遥测（测量值 M_ME）：电流、电压、功率等模拟量，厂站→主站上报；
- 遥控（命令 C_SC / C_DC）：合闸/分闸等控制命令，主站→厂站下行；
- 遥调（设定值 C_SE）、总召唤（C_IC）、对时（C_CS）、累积量（M_IT 电能量）等。

**本设计（v1）的生成面**：一个 TCP 连接（默认 2404 端口）上的**会话** = APCI 帧序列：连接建立后的 STARTDT 激活（U 帧）→ I 帧数据交换（总召唤、遥信、遥测、命令）→ STOPDT 停止（可选）→ TCP 挥手。对时属于规划内容，当前 16 个用例未落盘。每个 APDU 是独立的事件（MessageEvent，方向 + 完整字节），由 tcp 层生成器负责握手/seq-ack/挥手/MSS 分段。

**不做**（明确非目标）：
- **冗余组（redundant group）双连接**：调度端与厂站常见"主通道 + 备通道"双 TCP 连接，v1 用**多 flow**（strategy_fc flows）表达独立连接，不建模通道间故障切换（switchover）关系。
- **TESTFR 定期激活的静态节奏**：T3 空闲测试由对端驱动；本生成器只做**显式配置**的 TESTFR 帧（v1 无计时器，不做"空闲 N 秒自动发测试帧"的运行时行为）。
- 不平衡模式（unbalanced，101 的主从轮询语义在 104 中不存在——104 是平衡模式）、ASDU 序列化细节（SQ=1 连续信息体地址打包）、文件传输（F_SC 类型组）。

### 1.2 与 DNP3 的对照（同域先例的继承关系）

| 维度 | DNP3（11-dnp3-design.md） | IEC104（本设计） |
|------|---------------------------|-----------------|
| 标准 | IEEE 1815 | IEC 60870-5-104 |
| 默认端口 | TCP 20000（本工程先例值） | TCP 2404（IANA 注册） |
| 链路层 | 伪链路头（10B header + CRC）+ 传输分段 | 无链路层（APCI 直接坐 TCP 流） |
| 帧类型 | 链路控制字节区分 | APCI 控制域 bit0-1 区分 I/S/U |
| 确认 | 链路层 ACK + 应用层确认 | S 帧（链路级）+ 传送原因 ActCon（应用级） |
| 启动 | 应用层无启动握手 | U 帧 STARTDT act/con（强制） |
| 对象模型 | group + variation | 类型标识（TypeID）+ 信息对象地址（IOA） |

**关键差异对生成器的影响**：IEC104 的**应用层必须 STARTDT 激活后**才能传 I 帧（真实被控站会丢弃 STARTDT 前的 I 帧，§4 状态机），这与 DNP3"reset link → read class0"一样是**会话序言**；但 IEC104 多了 **S 帧**这个链路级确认机制（DNP3 的 ACK 是链路层字节，IEC104 的 S 帧是 APCI 层帧）——生成器必须按序贯推发送/接收序号（§3.2 序号会计）。

### 1.3 层注册（本项目架构的落点）

| 项 | 值 | 出处 |
|----|----|------|
| 层名（name） | `iec104` | §8 实现集成点 |
| 角色（category） | **终结层**（terminal） | 18-layer-config-design.md §5.1 |
| 硬依赖（depends_on） | `["tcp"]` | tcp 层自动补全；载体会话由 tcp 层生成器生产 |
| optional_on | 无 | v1 不做 IEC 62351 TLS（备通道 19998 不在 v1） |
| 层 config（layers 数组条目） | **零负载** `{"iec104":{}}` | 配置全量走 `spec.IEC104` flat 键（enip 同款） |
| 默认目的端口 | **2404**（IANA `iec-104`） | strategy_convert `case "iec104"` 默认化 |
| 默认源端口 | 0 保持（等价于显式 src_port） | 与 modbus/mqtt 同款：不默认化 |

`{"iec104":{}}` 自动补全为 `[ip → tcp → iec104]`；用户写 `{"tcp":{}},{"iec104":{}}` 显式等价。

### 1.4 端口纪律（2404 的测试排布）

IANA services 将 TCP/UDP 2404 注册为 `iec-104`（IEC 60870-5-104 process control over IP），Wireshark 3.6 实测将 `tcp.port 2404` 默认解码为 `iec60870_104`（`tshark -G decodes` 验证）——**本协议用例无需 `decode_as`**（对比 s7 的 `tcp.port==102,tpkt`、NFS 2049 的 `-d` 固定规则）。纪律沿用 moxa §1.4：用例全部**显式**写 `dst_port: 2404`（不依赖默认化），并把 `tcp.dstport == 2404` 纳入断言。

### 1.5 典型拓扑（测试场景的来源）

| 拓扑 | 拓扑描述 | 对应测试场景 |
|------|---------|-------------|
| 点对点总召唤（single） | 一台调度主站连一台厂站 RTU，总召唤 + 上送 | P01/P02/P10（主流程） |
| 遥控下行（control） | 主站发单点/双点命令，RTU 回 ActCon | P06/P07（命令） |
| 多厂站（multi） | 一台调度机连多个厂站（多 4-tuple） | P12（多 flow，src_port 递增） |
| IPv6 厂站（v6） | 新建变电站 IPv6 网段 | P11 |
| 异常断开（abort） | 对端 RST / 我方发 RST 跳过挥手 | 规划未落盘 |

> 每行拓扑 = 一个正向用例家族（§7 映射）。真实调度系统常是冗余双通道，v1 的多会话用多 flow 表达（§4.4），已是"multi"拓扑的忠实投影。

---

## 2. 数据类型与编码

IEC104 的字节级编码承继 IEC 60870-5-4（信息体元素编码规则）与 IEC 60870-5-101 §7.2（ASDU 布局）。本节是线上字节的权威规则，§6 HexDump 场景按此逐字节构建。

### 2.1 字节序（octet order）

IEC104 多字节数值采用小端序（least significant octet first，低字节在前）——注意与 TCP/IP 头的大端序相反。序号、IOA、CP56Time2a 的毫秒/分钟等一律小端。

| 项 | 字节序 | 例（值 1，3 字节 IOA） |
|----|--------|----------------------|
| APCI 发送/接收序号 | 小端（2 字节） | 1 → `01 00` |
| ASDU 公共地址 CA（2B） | 小端 | 1 → `01 00` |
| 信息对象地址 IOA（3B） | 小端 | 1 → `01 00 00` |
| CP56Time2a 各字段 | 小端 | ms=1 → `01 00` |
| 帧长度（APCI length） | 单字节，无字节序 | — |

### 2.2 标量类型（IEC 60870-5-4 类型字母表）

| 字母 | 类型 | 宽度 | 位序 | 本设计覆盖的用途 |
|------|------|------|------|-----------------|
| A | bool（布尔） | 1 bit | LSB 优先 | SIQ 的 SPI（单点信息位） |
| N | 无符号整数（8bit） | 1 字节 | 单字节 | TypeID、VSQ、COT、SCO/DCO 低 2 位 |
| I | 整数（16bit） | 2 字节 | 小端 | 未用（§2.4 边界） |
| F | 32bit 浮点 | 4 字节 | IEEE 754 小端 | 未用（v1 不生成 M_ME 浮点） |

**bit 位序**：布尔与位串按 LSB（bit0）最先排布。SIQ=`0x01` 表示 SPI（bit0）=1；DPI=`0x02`（二进制 `10`）表示 DPI（bit0-1）=2（ON）。

### 2.3 CP56Time2a（56bit 二进制时间，对时用）

IEC 60870-5-4 §6.8：7 字节、逐字段小端：

| 偏移 | 字段 | 宽度 | 编码 |
|------|------|------|------|
| 0-1 | 毫秒 ms | 16 bit 小端 | 0..59999 |
| 2 | 分钟 min | bit0-5（6bit） | 0..59；bit6-7 = IV + 保留 |
| 3 | 小时 hour | bit0-4（5bit） | 0..23；bit6 = SU；bit7 = IV |
| 4 | 日 day-of-month | bit0-4（5bit） | 1..31；bit5-7 = DOW（1..7） |
| 5 | 月 month | bit0-3（4bit） | 1..12 |
| 6 | 年 year | bit0-6（7bit） | 0..99（2000..2099） |

**生成器纪律**：对时帧的时间戳用当前墙钟时间；测试断言用 `nonzero`（字段存在且非零），不断言具体时间值。运行期时间不可硬编码常量；tshark 的 CP56Time2a 字段校验错位会产生 malformed 专家信息。

### 2.4 v1 明确覆盖与不覆盖的编码（诚实边界）

v1 正向用例实际覆盖 TypeID 1、3、9、30、34、45、59、100；TypeID 250 仅用于未知类型负例，不属于支持白名单。以下编码仍不覆盖：

| 编码 | 说明 | 处置 |
|------|------|------|
| SQ=1（连续信息体地址压缩） | 序列化规则不同 | v1 只生成 SQ=0 逐地址信息体 |
| 累积量（M_IT）4B BCR 计数器 | 现网少见于 v1 基线 | 不做；未知 TypeID 校验拒绝（E-T1） |
| CP24Time2a 及其他未列出的带时标信息体 | 信息体布局不同 | 不做；未知 TypeID 校验拒绝（E-T1） |
| IEC 62351-3 TLS（端口 19998） | 安全扩展 | optional_on 预留，v1 无 |

未知 `type_id` 必须返回 ValidationErrors，不许静默降级发错类型（E-T1，§9.1）。

---

## 3. 消息结构

### 3.1 APCI/APDU 总体布局

IEC104 在线上以 APDU（application protocol data unit，应用规约数据单元）为最小事件。每个 APDU 都从 `0x68` 起始，第二字节给出后续长度；长度字段不包含前两个字节本身。

```text
+--------+--------+----------------------+----------------------+
| 0x68   | L      | 控制域 C[0..3]       | ASDU（I 帧才有）     |
| 1B     | 1B     | 4B                   | 0..249B              |
+--------+--------+----------------------+----------------------+
```

| 字段 | 宽度 | 规则 |
|------|------|------|
| Start | 1B | 固定 `0x68` |
| L | 1B | `4 + ASDU_length`；U/S 帧固定 4 |
| Control | 4B | 按 I/S/U 帧格式解释；低两位区分帧型 |
| ASDU | 0..249B | 仅 I 帧允许；TypeID 等按 §3.4 |

`L` 最大为 253（0xfd），超过 249 字节的 ASDU 必须在配置校验阶段拒绝；不得把一个 ASDU 静默截断成多个不带语义的 I 帧。TCP 层可以按 MSS 分段，但分段只发生在 APDU 字节流层，不改变 `L` 或 ASDU 内部布局。

### 3.2 I 帧（编号信息帧）

I 帧的控制域为两个 16 位小端序序号：发送序号 `N(S)` 和接收序号 `N(R)`。二者均为 15bit 计数，线上值为序号左移 1；控制域低位始终为 0。

```text
C[0] = (N(S) << 1) & 0xff
C[1] = (N(S) >> 7) & 0xff
C[2] = (N(R) << 1) & 0xff
C[3] = (N(R) >> 7) & 0xff
```

例：`N(S)=1, N(R)=1` 时控制域为 `02 00 02 00`；当总召唤请求为首个 up I 帧、`N(S)=0, N(R)=0` 时，完整示例为：

```text
68 0b 00 00 00 00 64 01 06 00 01 00 14
```

其中 `L=0x0b`，控制域 4B，ASDU 7B；TypeID=`0x64`（C_IC_NA_1），COT=6（activation），CA=1，QOI=20（station interrogation）。这是 CA=1 的通用编码示例；可执行 P02 用例使用 CA=7，权威字节以 §3.6 和 JSON 为准。若该请求的 `N(S)` 和 `N(R)` 都为 1，则仅控制域变为 `02 00 02 00`。

接收序号只在收到对端 I 帧后推进；S 帧确认也使用当前 `N(R)`，不能把 S 帧本身计入 `N(S)`。

### 3.3 S/U 帧

S 帧只确认已收到的 I 帧，不携带 ASDU。控制域第一字节最低两位为 `01`，其余接收序号编码在 `C[2..3]`：

```text
C[0] = 0x01
C[1] = 0x00
C[2] = (N(R) << 1) & 0xff
C[3] = (N(R) >> 7) & 0xff
```

例如确认 `N(R)=1` 的 S 帧 APDU 是 `68 04 01 00 02 00`。

U 帧控制域低两位为 `11`，v1 固定保留高位为零，仅允许以下六种控制字：

| 语义 | 方向 | 控制域 | 完整 APDU |
|------|------|--------|-----------|
| STARTDT act | up | `07 00 00 00` | `68 04 07 00 00 00` |
| STARTDT con | down | `0b 00 00 00` | `68 04 0b 00 00 00` |
| STOPDT act | up | `13 00 00 00` | `68 04 13 00 00 00` |
| STOPDT con | down | `23 00 00 00` | `68 04 23 00 00 00` |
| TESTFR act | up | `43 00 00 00` | `68 04 43 00 00 00` |
| TESTFR con | down | `83 00 00 00` | `68 04 83 00 00 00` |

U 帧不占用 I 帧发送/接收序号窗口。收到 TESTFR act 必须回 TESTFR con；v1 的 `testfr` 配置显式列出事件，不由 T3 定时器隐式插入。

### 3.4 ASDU 固定前缀

每个 I 帧的 ASDU 从以下 6B 前缀开始，之后是一个或多个信息体：

```text
TypeID(1) | VSQ(1) | COT(2) | CA(2) | InformationObject...
```

| 字段 | 宽度 | v1 规则 |
|------|------|---------|
| TypeID | 1B | 只接受 §3.5 白名单 |
| VSQ | 1B | bit7=SQ；v1 只允许 SQ=0，低 7 位为对象数 |
| COT | 2B | 低 6bit 为 cause，bit6=PN，bit7=reserved，第二字节为 OA |
| CA | 2B | 小端，0..65535 |
| IOA | 3B | 小端，0..16777215；v1 默认 0..0xffffff |

`VSQ` 的对象数必须与后续信息体数量一致。对象数为 0、SQ=1、信息体不足或多余均属于配置错误；解析器不得依据剩余字节猜测对象数量。

### 3.5 v1 TypeID 白名单与信息体

| TypeID | 名称 | 信息体宽度（不含 IOA） | 方向 | 约束 |
|--------|------|------------------------|------|------|
| 1 | M_SP_NA_1 单点信息 | 1B SIQ | down | SIQ bit0 为 SPI |
| 3 | M_DP_NA_1 双点信息 | 1B DIQ | down | DIQ bit0-1 为 DPI（1..3） |
| 9 | M_ME_NA_1 归一化测量值 | 3B NVA+QDS | down | NVA 为 16bit 小端有符号值，QDS 1B |
| 30 | M_SP_TB_1 带时标单点信息 | 8B SIQ+CP56Time2a | down | SIQ 后追加 7B CP56Time2a |
| 34 | M_ME_TD_1 带时标归一化测量值 | 10B NVA+QDS+CP56Time2a | down | NVA/QDS 后追加 7B CP56Time2a |
| 45 | C_SC_NA_1 单点命令 | 1B SCO | up | SCO bit0 为命令值，bit7 为 SE |
| 59 | C_DC_TA_1 带时标双点命令 | 8B DCO+CP56Time2a | up | DCO bit0-1 为 DCS，bit7 为 SE |
| 100 | C_IC_NA_1 总召唤 | 1B QOI | up | QOI=20 站召唤或 21..36 分组召唤 |

TypeID=250 不属于正向白名单，仅用于 `iec104_neg_unknown_type` 负例。信息体长度按 `IOA(3B) + value_width` 累加；例如 TypeID=1、VSQ=1 的 ASDU 为 `6 + 3 + 1 = 10B`，再加 APCI 控制域 4B，故 `L=14 (0x0e)`。TypeID=9 的单对象 ASDU 为 `6 + 3 + 3 = 12B`，APCI 长度字段为 `4 + 12 = 16 (0x10)`。

### 3.6 已核验 HexDump

以下示例均从 Ethernet 负载起算，偏移 54（IPv4 TCP，无 TCP option）处为 APDU 起始：

| 语义 | APDU 字节 |
|------|-----------|
| STARTDT act | `68 04 07 00 00 00` |
| S，确认 N(R)=1 | `68 04 01 00 02 00` |
| M_SP_NA_1，CA=1、IOA=1、SPI=1 | `68 0e 00 00 00 00 01 01 03 00 01 00 01 00 00 01` |
| M_DP_NA_1，CA=1、IOA=1、DPI=2 | `68 0e 00 00 00 00 03 01 03 00 01 00 01 00 00 02` |
| M_ME_NA_1，CA=2、IOA=16、NVA=0x1234、QDS=0 | `68 10 00 00 00 00 09 01 03 00 02 00 10 00 00 34 12 00` |
| M_SP_TB_1，CA=4、IOA=21、SPI=1 | `68 15 00 00 00 00 1e 01 03 00 04 00 15 00 00 01` |
| M_ME_TD_1，CA=3、IOA=17 | `68 17 00 00 00 00 22 01 03 00 03 00 11 00 00` |
| C_SC_NA_1，CA=5、IOA=22、ON、select | `68 0e 00 00 00 00 2d 01 06 00 05 00 16 00 00 81` |
| C_DC_TA_1，CA=6、IOA=23、DCS=2、execute | `68 15 00 00 00 00 3b 01 06 00 06 00 17 00 00 02` |
| C_IC_NA_1，CA=7、QOI=20 | `68 0b 00 00 00 00 64 01 06 00 07 00 14` |

全零 CP56Time2a 仅为结构探针，正向生成时不得使用全零时间，因为它违反时间有效性约束；负例应在 Validate 阶段拒绝或标记 invalid time。

### 3.7 字节长度与 TCP 分段

APDU 是一个逻辑事件，TCP 生成器读取事件后按 `mss` 分段。MSS=1460、APDU=16B 时只生成一个 TCP 数据段；如果将事件配置为 2000B 原始扩展载荷，TCP 层会生成两段，但 IEC104 终结层必须先确认该载荷是合法 APDU 序列，不能把任意 2000B 当作一帧 IEC104。

正向用例的 `frames` 断言只匹配 APDU 前缀。每个断言的 offset 必须按载体头长度逐字段累计：IPv4 无 option 为 `14 + 20 + 20 = 54`，IPv6 为 `14 + 40 + 20 = 74`；SYN 选项不用于数据帧 offset。

---

## 4. 状态机

### 4.1 连接阶段

生成器扮演控制站（客户端）角色，对端被控站由 TCP 事件中的 down 方向代表。TCP 三次握手完成后，IEC104 会话必须先执行 STARTDT，再发送任何 I 帧。状态转移如下：

```text
TCP_ESTABLISHED
      |
      | up: STARTDT act
      v
START_SENT -- down: STARTDT con --> DATA_TRANSFER
   |                                  |
   | down: STOPDT act/con             | up/down: I/S
   v                                  |
STOPPING <---- up: STOPDT act --------+
   |
   | down: STOPDT con / close
   v
CLOSED
```

| 状态 | 允许的 up 事件 | 允许的 down 事件 | 非法事件处理 |
|------|----------------|------------------|--------------|
| TCP_ESTABLISHED | STARTDT act | — | I/S/U（除对端主动 STARTDT act 外）拒绝 |
| START_SENT | — | STARTDT con | 重复 STARTDT act、I 帧拒绝 |
| DATA_TRANSFER | I、S、STOPDT act、TESTFR act | I、S、STOPDT con、TESTFR con | 未知 U 或序号越界拒绝 |
| STOPPING | — | STOPDT con | 先发其他 I 帧拒绝 |
| CLOSED | — | — | 任何事件拒绝 |

被控站主动发送 STARTDT act 的服务器型会话不是 v1 目标；若输入事件第一帧是 down STARTDT act，必须显式配置 `allow_peer_startdt`，默认 Validate 拒绝，避免隐式改变角色。

### 4.2 STARTDT 激活

默认会话序言为两事件：

1. up `STARTDT act`（`68 04 07 00 00 00`）；
2. down `STARTDT con`（`68 04 0b 00 00 00`）。

只有收到确认后才把 `data_ready` 置为 true。`data_ready=false` 时，I 帧、S 帧、业务 ASDU 均为配置错误。为了测试失败路径，允许 `omit_startdt_con=true`，但该配置只出现在负向用例，错误应包含 `iec104: STARTDT confirmation required before I frame`。

### 4.3 I 帧序号与窗口

配置以逻辑事件表示序号行为，终结层维护：

- `send_seq`：最近发送的 I 帧序号，初始为 0；每个 I 帧发送后加 1；
- `recv_seq`：最近收到的对端 I 帧数量，初始为 0；每个 down I 帧收到后加 1；
- `unacked`：已发但未被 S/I 帧确认的 I 帧数；
- `k`：发送窗口上限，默认 12；
- `w`：确认阈值，默认 8。

`unacked >= k` 时，生成器不得继续发送 up I 帧，必须先有 down S 帧或携带确认的 down I 帧。收到 `w` 个 down I 帧后，应产生 S 帧确认，除非下一个 up I 帧将在 T2 前携带 `N(R)`。v1 没有运行时计时器，窗口确认通过显式 `s_frame` 事件或 `auto_s_ack=true` 产生；默认正向用例采用显式 S 帧，包序确定。

序号按模 32768 回绕：

```text
next = (current + 1) % 32768
```

回绕前后比较使用模序关系，不能直接使用有符号整数大小比较。`send_seq`、`recv_seq` 配置值必须在 `[0,32767]`；超界错误见 §9.1 E-S1。

### 4.4 S 帧确认规则

S 帧的接收序号必须等于当前 `recv_seq`。如果显式 `s_frame.rx` 与状态机期望值不同，Validate 阶段报错，并在错误中同时给出 expected 与 got。S 帧不增加 `send_seq`，也不改变 `recv_seq`。

携带确认的 I 帧使用其控制域的 `N(R)` 清除对端发送窗口。对于本生成器的静态事件流，down I 帧的 `rx` 字段可省略，由终结层填入最新的 up 接收序号；若用户同时提供 `rx`，必须与当前状态一致。

### 4.5 U 帧与 T3 测试

U 帧控制字必须来自 §3.3 白名单。STARTDT/STOPDT 是状态转移事件，TESTFR 只维持链路活性：

- up `testfr_act` 后必须有 down `testfr_con`；
- TESTFR 不计入 I 帧窗口；
- v1 不按墙钟自动触发 T3；
- `t3_probe` 仅是显式事件别名，不能与 `testfr_act` 同时设置；
- `testfr_con` 没有对应 act 时拒绝，避免伪造对端响应。

### 4.6 STOPDT 与关闭

STOPDT 必须发生在最后一个业务 I 帧和所有必需的 S 帧之后。标准序列为 up STOPDT act、down STOPDT con，然后交给 TCP 层执行 FIN 四包挥手。若配置 `close_mode:"rst"`，则 STOPDT 仍可显式出现，随后 TCP 以 RST 终止；`close_mode:"fin"` 为默认。

不允许在 STOPDT con 后继续发送 I/S/U 帧。若配置 `stopdt:false`，会话可直接进入 TCP FIN，但这只用于兼容不完整设备的正向场景；默认 `require_stopdt=true` 时 Validate 拒绝缺少 STOPDT 的完整会话。

### 4.7 周期轮询

`poll` 是静态事件模板的重复器，不是隐式后台计时器：

```json
"poll": {
  "count": 3,
  "interval_ms": 1000,
  "request": {"type_id": 100, "qoi": 20},
  "response": [
    {"type_id": 1, "ioa": 1, "siq": 1}
  ]
}
```

每轮展开为 up C_IC_NA_1、down M_SP_NA_1；`count` 必须大于 0，最大 65535；`interval_ms` 只用于事件时间戳/调度提示，pcap 断言不依赖真实墙钟。轮询期间 `send_seq`、`recv_seq` 连续递增，最后一轮后再执行 STOPDT。

### 4.8 多会话隔离

`strategy_fc`（策略级流控）为 `{"type":"flows","value":3}` 时展开多个独立 TCP 会话；每个 flow 都重新从 TCP SYN 与 STARTDT act 开始，序号初始为 0。会话之间不共享 `send_seq`、`recv_seq`、CA 或 IOA 状态。不同 flow 使用递增源端口，目的端口固定 2404；交织顺序由调度器决定，所以多流用例只能断言 `distinct_values`，不能硬编码数据包编号。

---

## 5. 配置类型定义

### 5.1 顶层 generate_traffic 配置

IEC104 采用层链 + flat 协议配置。层链声明 TCP 载体与终结层，协议数据位于顶层 `iec104` 对象；不把业务字段塞入 `layers` 的零负载对象。

```json
{
  "layers": [{"tcp": {}}, {"iec104": {}}],
  "src_ip": "10.0.0.1",
  "dst_ip": "20.0.0.1",
  "src_port": 12345,
  "dst_port": 2404,
  "iec104": {
    "common_address": 1,
    "startdt": true,
    "events": []
  }
}
```

| 顶层字段 | 类型 | 默认 | 约束 |
|----------|------|------|------|
| `layers` | array | 必填 | 必须含 `tcp` 与 `iec104`，顺序为 tcp 后 iec104 |
| `src_ip` | string | 由策略分配 | IPv4 或 IPv6 单地址 |
| `dst_ip` | string | 必填 | IPv4 或 IPv6 单地址 |
| `src_port` | uint16 | 0 | 0 表示 worker 分配 |
| `dst_port` | uint16 | 2404 | 显式值必须为 2404（v1） |
| `iec104` | object | 必填 | 见 §5.2 |

`dst_port=0`、UDP 层、缺少 TCP 层或同时声明两个 `iec104` 层均为配置错误。层注册只负责依赖补全，不能因为协议配置存在就静默补 TCP。

### 5.2 IEC104Config 逻辑字段

| 字段 | JSON 类型 | 默认 | 说明 |
|------|-----------|------|------|
| `common_address` | integer | 1 | ASDU CA，0..65535 |
| `information_object_address` | integer | 0 | 单对象默认 IOA，0..16777215 |
| `startdt` | boolean | true | 是否生成 STARTDT act/con |
| `stopdt` | boolean | true | 是否生成 STOPDT act/con |
| `testfr` | boolean | false | 是否在事件尾部生成 TESTFR act/con |
| `auto_s_ack` | boolean | false | 按窗口自动插 S 帧 |
| `k` | integer | 12 | 发送窗口，1..32767 |
| `w` | integer | 8 | 接收确认阈值，1..k |
| `send_seq` | integer | 0 | 初始 N(S)，0..32767 |
| `recv_seq` | integer | 0 | 初始 N(R)，0..32767 |
| `events` | array | [] | 有序 IEC104 事件列表 |
| `poll` | object | null | 周期轮询模板，见 §4.7 |
| `close_mode` | string | `fin` | `fin` 或 `rst` |
| `allow_peer_startdt` | boolean | false | 是否允许 down STARTDT act |

字段名是 flat 配置对外契约；实现内部可使用 Go `IEC104Config`，但不得改变 JSON 键名或默认值。

### 5.3 事件结构

每个 `events[]` 元素包含 `direction` 与 `kind`。`direction` 只能为 `up` 或 `down`；缺省方向按 kind 推导：请求类为 up，信息上送/确认类为 down。为避免歧义，正式用例全部显式填写。

```json
{
  "direction": "up",
  "kind": "i",
  "type_id": 100,
  "cause": 6,
  "originator": 0,
  "ioa": 0,
  "qoi": 20
}
```

| 字段 | 类型 | 适用 | 校验 |
|------|------|------|------|
| `direction` | string | 所有事件 | `up`/`down` |
| `kind` | string | 所有事件 | `startdt_act`, `startdt_con`, `i`, `s`, `stopdt_act`, `stopdt_con`, `testfr_act`, `testfr_con` |
| `type_id` | integer | I 帧 | §3.5 白名单 |
| `cause` | integer | ASDU | 1..63，按方向约束 |
| `originator` | integer | ASDU | 0..255，编码为 COT 高字节 |
| `common_address` | integer | ASDU | 缺省继承顶层 CA |
| `ioa` | integer | 信息体 | 0..16777215，C_CS 必须 0 |
| `value` | integer/bool | 信息体 | 按 TypeID 解释 |
| `select` | boolean | C_SC/C_DC | true=select，false=execute |
| `qoi` | integer | C_IC | 20..36 |
| `time` | string | C_CS | RFC3339；缺省使用当前时间 |
| `rx` | integer | S/I | 缺省自动填充；显式值须吻合 |

`kind` 与 `type_id` 互斥：U/S 帧不能带 `type_id`，I 帧必须带 `type_id`。字段不适用时拒绝，而不是忽略。

### 5.4 信息体值域

| TypeID | 输入字段 | 合法值 | 线上值 |
|--------|----------|--------|--------|
| 1 | `siq` 或 `value` | 0..255；bit0 为 SPI | 1B SIQ |
| 3 | `diq` 或 `value` | DPI 1..3，或加 IV/NT 位 | 1B DIQ |
| 9 | `value`、`qds` | 有符号 16bit NVA；QDS 0..255 | 2B NVA 小端 + 1B QDS |
| 30 | `siq` 或 `value`、`time` | SIQ 0..255；RFC3339 CP56Time2a | 1B SIQ + 7B CP56Time2a |
| 34 | `value`、`qds`、`time` | 有符号 16bit NVA；QDS 0..255；RFC3339 | 2B NVA 小端 + 1B QDS + 7B CP56Time2a |
| 45 | `sco`、`value`、`select` | value 0/1；select 布尔 | bit0=命令值，bit7=SE |
| 59 | `dco`、`value`、`select`、`time` | DCS 1/2/3；select 布尔；RFC3339 | bit0-1=DCS，bit7=SE + 7B CP56Time2a |
| 100 | `qoi` | 20..36 | 1B QOI |

`value` 与专用字段同时提供时必须一致；例如 `type_id=1,value=1,siq=0` 是冲突错误。所有整数先做范围检查，再转换为定长字节，不能使用截断转换掩盖越界。

### 5.5 方向与传送原因

默认 COT：

| 事件 | 默认 cause | 常见响应 |
|------|------------|----------|
| up 总召唤/命令/对时 | 6 activation | down cause 7 activation confirmation |
| down 信息上送 | 3 spontaneous | — |
| down 命令确认 | 7 activation confirmation | — |
| down 总召唤数据 | 20 interrogation | — |

用户显式 `cause` 时必须符合方向与 TypeID 的约束。`cause=0`、PN 位错误、响应使用 activation 代替 activation confirmation 都应由 Validate 拒绝。originator（OA）缺省 0；COT 编码为 `cause | (pn<<6) | (originator<<8)`。

### 5.6 流控与策略展开

IEC104 的协议配置与策略级 flow control（流控）正交：

```json
"strategy_fc": {"type": "flows", "value": 3}
```

表示创建 3 条独立连接，不表示同一连接重复 3 次。`type="bps"` 只约束发送节奏；`type="time"` 限制会话持续时间。策略字段不写入 APDU，不应出现在 `iec104.events` 中。多 flow 用例的 `src_port` 可省略，由 worker 以 12345 起递增分配。

---

## 6. 包序列场景（HexDump P01-P12）

本节把 §1 的拓扑和 §3 的线上字节落成可执行场景。除特别说明外，所有场景均为 IPv4、`dst_port=2404`、MSS 默认 1460、TCP 三次握手和 FIN 四包挥手。事件模式包数公式为 `3 + 数据段数 + 4`；IEC104 APDU 每个事件通常占一个数据段。

### 6.1 帧偏移规则

数据帧的 APDU 偏移必须由链路头和 IP/TCP 头长度逐字段累计，不凭经验硬编码：

| 载体 | 累计 | APDU offset |
|------|------|-------------|
| Ethernet II + IPv4 + TCP（无 option） | 14 + 20 + 20 | 54 |
| Ethernet II + IPv6 + TCP（无 option） | 14 + 40 + 20 | 74 |
| Ethernet II + IPv4 + TCP option | 14 + 20 + 20 + option_len | 54 + option_len |

同一数据帧中多个断言若指向不同字段，offset 必须随着字段长度继续累加。例如 IPv4 APDU offset=54，APDU 起始 6B 是 `68 L C0 C1 C2 C3`，则 TypeID offset=60、VSQ=61、COT=62、CA=64、IOA=66；不能把 TypeID 与 IOA 都断言在 54。`FrameAssert` 是前缀匹配，场景只把互不重叠的字段放在对应偏移。

### 6.2 P01：STARTDT + 单点遥信

**目的**：验证 TCP 2404、STARTDT 激活、最小 M_SP_NA_1 ASDU、down S 确认和 FIN 关闭。

```text
1 SYN
2 SYN+ACK
3 ACK
4 up  STARTDT act  68 04 07 00 00 00
5 down STARTDT con  68 04 0b 00 00 00
6 up  I, M_SP_NA_1  68 0e 00 00 00 00 01 01 03 00 01 00 01 00 00 01
7 down S ack         68 04 01 00 02 00
8 up  STOPDT act    68 04 13 00 00 00
9 down STOPDT con   68 04 23 00 00 00
10 FIN+ACK
11 ACK
12 FIN+ACK
13 ACK
```

P01 的数据段数为 6，故精确包数为 `3+6+4=13`。断言：包4 `iec60870_104.utype=0x00000001`；包5 为 down STARTDT con；包6 `iec60870_asdu.typeid=1`、`iec60870_asdu.siq.spi=1`、`tcp.dstport=2404`；包7 为 down `iec60870_104.type=S` 并确认 `N(R)=1`；包8/9 为 STOPDT act/con；最后四包为 FIN。包6 APDU offset=54，TypeID 字段 offset=60，CA 字段 offset=64，IOA 字段 offset=66，SIQ 字段 offset=69。

### 6.3 P02：周期总召唤

`iec104_polling` 使用三轮显式事件，每轮为 up `C_IC_NA_1`（TypeID=100、COT=6、QOI=20）、down `M_SP_NA_1`（TypeID=1、COT=20）和 up S 确认。连同 STARTDT act/con、STOPDT act/con，共 13 个应用事件，固定 IPv4 会话包数为 `3+13+4=20`。第一轮业务帧位于 packet 6–8；后续轮次的 packet 号按事件顺序递增。

### 6.4 P03：类型 9 归一化遥测

`iec104_m_me_na_type9` 使用 down TypeID=9、CA=2、IOA=16、NVA=0x1234、QDS=0，固定 APDU 为 `68 10 00 00 00 00 09 01 03 00 02 00 10 00 00 34 12 00`。应用事件为 STARTDT act/con、down I、up S、STOPDT act/con，固定包数为 13。

### 6.5 P04：类型 34 带时标归一化测量

`iec104_timed_measurement` 使用 down TypeID=34、CA=3、IOA=17、NVA=100、QDS=0 和 RFC3339 时间。APDU 长度为 `L=0x17`；CP56Time2a 运行时编码，断言只锁定 `68 17 ... 22 01 03 00 03 00 11 00 00` 前缀和时间字段结构。应用事件顺序与 P03 相同，固定包数为 13。

### 6.6 P05：类型 30 带时标单点

`iec104_timed_single_point` 使用 down TypeID=30、CA=4、IOA=21、SIQ=1 和 CP56Time2a。固定 APDU 前缀为 `68 15 00 00 00 00 1e 01 03 00 04 00 15 00 00 01`；SIQ 位于 APDU 相对偏移 15，CP56Time2a 从偏移 16 开始，不把时间字节误当成 IOA 或 SIQ。固定包数为 13。

### 6.7 P06：单点命令

`iec104_single_command` 使用 up TypeID=45、CA=5、IOA=22、COT=6 的选择请求，随后由 down TypeID=45、COT=7 确认；两帧分别为 `68 0e ... 2d 01 06 00 05 00 16 00 00 81` 和 `68 0e ... 2d 01 07 00 05 00 16 00 00 81`。再加 up S、STOPDT act/con，应用事件数为 7，固定包数为 `3+7+4=14`。

### 6.8 P07：带时标双点命令

`iec104_double_command_timed` 使用 up/down TypeID=59、CA=6、IOA=23、DCS=2、execute，COT 分别为 6/7，DCO 后追加运行时 CP56Time2a。固定 APDU 前缀分别为 `68 15 ... 3b 01 06 00 06 00 17 00 00 02` 和 `68 15 ... 3b 01 07 00 06 00 17 00 00 02`。固定包数为 14。

### 6.9 P08：U 格式控制序列

`iec104_u_frames` 依次发送 STARTDT act/con、TESTFR act/con、STOPDT act/con 六个 U 帧。所有 APDU 的 `L=4`，TESTFR 不消耗 I 帧序号；应用事件数为 6，固定包数为 13。

### 6.10 P09：S 格式确认

`iec104_s_ack` 先发送 up C_IC_NA_1，再由 down M_SP_NA_1 返回，最后由 up S 帧确认 down I，随后正常 STOPDT。确认帧固定为 `68 04 01 00 02 00`，应用事件数为 7，固定包数为 14。该方向约束防止把空 S 帧误判为确认。

### 6.11 P10：突发事件上报

`iec104_spontaneous_event` 在 STARTDT 完成后由 down 方向主动发送 TypeID=1、COT=3、CA=9、IOA=90、SIQ=1，随后由 up S 确认。固定 APDU 前缀为 `68 0e 00 00 00 00 01 01 03 00 09 00 5a 00 00 01`，应用事件数为 6，固定包数为 13；down 业务包的 `tcp.srcport` 必须为 2404。

### 6.12 P11：IPv6 载体

`iec104_ipv6` 保持 IEC104 业务字节不变，仅使用 IPv6 地址和 TCP 2404。down TypeID=3、CA=10、IOA=2、DIQ=2 的业务帧位于 packet 6，APDU offset 为 `14+40+20=74`，固定前缀为 `68 0e 00 00 00 00 03 01 03 00 0a 00 02 00 00 02`。不得沿用 IPv4 的 offset 54。

### 6.13 P12：多会话

`iec104_multi_flow` 在策略层使用顶层 `strategy_fc: {"type":"flows","value":3}`，每条流独立执行 P01 的 6 个应用事件和 TCP 握手/关闭。三条流理论包数为 `3×(3+6+4)=39`，断言使用 `min_packets=39`、源端口 `12345/12346/12347` 聚合和目的端口 `2404` 聚合，不锁定交织后的业务 packet 编号。

### 6.14 规划中的边界场景（未落盘）

B1–B7 和 S10 是设计阶段规划，不属于当前 JSON 的 16 个可执行 ID。特别是 B7（大 ASDU，`L>253`）与 S10（零值、最大值、序号回绕组合）当前没有对应 JSON；它们保留在设计中作为后续实现和用例补充要求，不得写入“已落盘”映射。当前已落盘的超长负例只有 `iec104_neg_oversize_apdu`，其 JSON 探针字段仍需以正式实现 schema 为准。


## 7. 与 testcase 文档的映射索引

`22-iec104-testcase.md` 是本设计的可执行展开；本节只登记当前 JSON 已落盘的 16 个 ID，顺序与 JSON 顶层数组一致。B1–B7、S10 以及 §6.5 中的其他边界名称是规划内容，不是当前可执行 ID。

| 编号 | testcase / JSON id | 正负 | 核心覆盖 |
|------|--------------------|------|----------|
| P01 | `iec104_startdt_msp` | 正 | TCP 2404、I/S/U 序列、M_SP、FIN |
| P02 | `iec104_polling` | 正 | C_IC、QOI=20、M_SP 响应、三轮 S 帧 |
| P03 | `iec104_m_me_na_type9` | 正 | TypeID=9、NVA 小端、QDS |
| P04 | `iec104_timed_measurement` | 正 | TypeID=34、CP56Time2a 测量值 |
| P05 | `iec104_timed_single_point` | 正 | TypeID=30、带时标单点 |
| P06 | `iec104_single_command` | 正 | TypeID=45、SCO 选择/执行、ActCon |
| P07 | `iec104_double_command_timed` | 正 | TypeID=59、DCO、CP56Time2a、ActCon |
| P08 | `iec104_u_frames` | 正 | TESTFR act/con、STOPDT act/con、FIN |
| P09 | `iec104_s_ack` | 正 | down I 后 up S、N(R) 左移编码 |
| P10 | `iec104_spontaneous_event` | 正 | COT=3、down 信息上送、up S |
| P11 | `iec104_ipv6` | 正 | IPv6 头、offset=74、2404 |
| P12 | `iec104_multi_flow` | 正 | `strategy_fc.flows=3`、端口聚合、min_packets=39 |
| N01 | `iec104_neg_control` | 负 | 非法 U 控制域拒绝 |
| N02 | `iec104_neg_unknown_type` | 负 | TypeID=250 白名单拒绝 |
| N03 | `iec104_neg_oversize_apdu` | 负 | APDU 超长拒绝 |
| N04 | `iec104_neg_ioa` | 负 | IOA 越界拒绝 |

### 7.1 三件套一致性规则

1. `id` 必须在本表、testcase 文档目录和 JSON 顶层逐字一致，顺序也一致。
2. testcase 的 `spec_json` 是 JSON 对象而非字符串；顶层至少包含 `layers`、`dst_ip`、`dst_port` 和 `iec104`。
3. 正向 `expect` 只断言实际可观察字段；负向只使用 `expect_error` 与 `error_contains`，不对不存在的 pcap 断言包结构。
4. 每个 IPv4 APDU 帧断言默认从 offset 54 起；IPv6 从 74 起；同一帧中 TypeID、CA、IOA、值字段按 60、64、66、69 等真实字段位置错开。
5. `packet_count` 只用于固定序列。多 flow 使用 `min_packets` + 聚合字段，RST 使用 `min_packets`，不可将交织或内核关闭差异硬编码为单一包序。
6. 当前 8 个正向 TypeID 只有 `1, 3, 9, 30, 34, 45, 59, 100`；TypeID=250 只允许出现在 N02 负例。

---

## 8. 实现集成点

### 8.1 层注册

在 `trafficgen/internal/core/layers/registry.go` 注册 `iec104` 终结层：依赖 `tcp`，默认目的端口 2404，无 `optional_on`。`layers` 中的 `{"iec104":{}}` 为零负载声明，协议字段由 flat `spec.IEC104` 解析。

### 8.2 配置转换

`trafficgen/internal/core/strategy_convert.go` 增加 `iec104` 分支，将 JSON 中的 `common_address`、事件数组、窗口、关闭模式和边界选项转换为 `IEC104Config`。必须保留显式零值，不能以反射或 `omitempty` 逻辑把 `ioa=0`、`ca=0`、`siq=0` 当作缺省。

### 8.3 终结层生成器

规划 `trafficgen/internal/protocol/iec104/iec104.go` 与类型文件：

1. Validate 层链、端口、CA/IOA、TypeID、方向、COT、窗口和 APDU 长度。
2. 生成 STARTDT act/con，建立 `data_ready` 状态。
3. 将每个 I/S/U 逻辑事件编码为一个 `MessageEvent`，up/down 方向与 TCP 端口一致。
4. 对 I 帧维护 N(S)/N(R)、k/w 和显式 S 帧核对。
5. 以当前时间编码 CP56Time2a，不将动态时间写死。
6. 根据 `close_mode` 交给 TCP 终结层执行 FIN 或 RST，确保错误路径排空事件流。

### 8.4 与 TCP 层的边界

IEC104 层只生产完整 APDU 字节，不生成 Ethernet、IP、TCP 头；TCP 层负责握手、序列/确认号、MSS 分段、端口交换、FIN/RST。APDU 不得跨事件拼接，MSS 分段不得修改 APDU 内的长度字段。

### 8.5 可观测字段

实现完成后，pcap 应能由 tshark 解码以下字段，供 `VerifyPcap`（pcap 校验器）断言：`tcp.srcport`、`tcp.dstport`、`iec60870_104.type`、`iec60870_104.utype`、`iec60870_104.tx`、`iec60870_104.rx`、`iec60870_asdu.typeid`、`iec60870_asdu.causetx`、`iec60870_asdu.addr`、`iec60870_asdu.ioa`、`iec60870_asdu.siq.spi`、`iec60870_asdu.diq.dpi`、`iec60870_asdu.sco.on`、`iec60870_asdu.dco.on`、`iec60870_asdu.qoi`、`iec60870_asdu.cp56time`。

---

## 9. 错误处理

### 9.1 Validate 错误表

| ID | 触发条件 | 错误消息要点 | 阶段 |
|----|----------|--------------|------|
| E-T1 | TypeID 不在白名单 | `iec104: unknown type_id` | Validate |
| E-T2 | `events` 为空且未显式启动/测试 | `iec104: empty events` | Validate |
| E-T3 | I 帧缺 ASDU 或 VSQ=0 | `iec104: empty ASDU` | Validate |
| E-T4 | 缺 tcp 层、UDP 或层顺序错误 | `iec104: tcp carrier required` | Convert |
| E-T5 | I 帧出现在 STARTDT con 前 | `iec104: I frame before STARTDT confirmation` | Validate |
| E-T6 | S 帧 rx 不等于当前 recv_seq | `iec104: invalid S acknowledgement` | Validate |
| E-T7 | DIQ/SCO/DCO、CA/IOA、COT 或序号越界 | `iec104: invalid value` | Validate |
| E-T8 | APDU 长度字段与字节数不符 | `iec104: truncated APDU` | Validate |
| E-T9 | `L>253` 或 ASDU>249B | `iec104: APDU too long` | Validate |
| E-T10 | 显式 `dst_port` 不是 2404 | `iec104: dst_port must be 2404` | Convert |
| E-T11 | direction 不是 up/down | `iec104: invalid direction` | Validate |
| E-T12 | C_CS 的 IOA 非 0 或时间无法解析 | `iec104: invalid CP56Time2a` | Validate |
| E-T13 | C_IC 的 QOI 不在 20..36 | `iec104: invalid QOI` | Validate |
| E-T14 | 超过 k 窗口仍发送 I 帧 | `iec104: send window exceeded` | Plan |
| E-T15 | STOPDT con 后仍有事件 | `iec104: event after STOPDT` | Plan |

所有边界错误都应在任务创建/转换或规划阶段返回；不产生空成功任务，不吞掉错误，也不将越界整数截断为定长字段。

### 9.2 运行时错误与关闭

- TCP 连接建立失败或 context 取消：关闭事件通道并返回原始错误。
- 事件编码失败：停止产生后续事件，交给引擎报告任务失败；已排队事件不伪造填充。
- `close_mode="fin"`：业务结束后由 TCP 正常四包挥手。
- `close_mode="rst"`：业务结束后由 TCP 发送 RST；不要求 STOPDT，但若配置了 STOPDT 仍应先发送完整 U 帧。
- 任何错误路径都必须让事件流可结束，避免 TCP worker 在关闭时阻塞等待或触发 send-on-closed panic。

---

## 10. 扩展字段映射

v1 只实现 §3.5 白名单；扩展字段为后续实现预留，但不能在 v1 中静默接受。

| TypeID/字段 | 说明 | 建议配置键 | 当前设计/用例处置 |
|-------------|------|------------|------------------|
| M_ME_NA_1 | 归一化值 | `normalized`, `qds` | 当前白名单包含，TypeID=9 |
| M_ME_TD_1 | 带 CP56Time2a 的归一化值 | `normalized`, `qds`, `time` | 当前白名单包含，TypeID=34 |
| M_ME_NB_1/NC_1 | 标度值/短浮点 | `scaled`, `float` | 后续扩展，unknown TypeID |
| M_ST_NA_1 | 步位置信息 | `step`, `qds` | unknown TypeID |
| M_IT_NA_1 | 累积量 | `counter`, `bcr` | unknown TypeID |
| C_SE_NA/NB/NC_1 | 设点命令 | `setpoint`, `select` | unknown TypeID |
| C_RC_NA_1 | 进程步调节 | `step_command` | unknown TypeID |
| 带时标遥信 | CP24/CP56 附加值 | `time` | unknown TypeID |
| SQ=1 | 连续 IOA 压缩 | `sequence` | 显式拒绝 |
| IEC 62351 TLS | TCP 19998 安全载体 | `tls` | optional_on 预留 |

扩展实现必须新增独立 TypeID、信息体长度、方向、COT 和负例，不能复用当前八类的宽度推断。

---

## 11. 修订记录

| 版本 | 日期 | 变更 |
|------|------|------|
| v1.0.0 | 2026-08-18 | 建立 IEC104 TCP 2404 设计；定义 APCI/APDU、I/S/U 帧、序号窗口、八类 TypeID、CP56Time2a、状态机、轮询、多 flow、IPv4/IPv6、RST 和错误边界；规划文档/用例先行，暂不改实现。 |

---
