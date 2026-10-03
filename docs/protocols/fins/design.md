# FINS（欧姆龙 PLC，UDP/TCP 9600）协议设计与测试用例

> 版本：v1.1.0（层链迁移审计版）
> 设计日期：2026-08-18
> 修订日期：2026-08-19（同步三件套中的已确认差异）
> 范围：欧姆龙（OMRON）FINS（Factory Interface Network Service，工厂接口网络服务；欧姆龙可编程逻辑控制器/PLC 家族的自有通信协议）在 UDP 与 TCP 之上的请求/响应报文设计与测试用例定义
> 实现位置：`trafficgen/internal/protocol/fins/`（planner + builder + validate）、`trafficgen/internal/core/`（层注册表登记、配置零负载经 `spec.FINS` 直传）
> 配套测试：`trafficgen/test/protocol_pcap/cases/fins.json`（用例数据，与本设计文档 §7 严格一致）、`docs/protocols/fins/testcase.md`（测试用例设计文档）
> 状态：实现现状契约；本次只修文档与用例形状，不改实现

---

## 目录

1. [协议概述](#1-协议概述)
2. [数据类型与编码](#2-数据类型与编码)
3. [消息结构](#3-消息结构)
4. [状态机](#4-状态机)
5. [配置类型定义（Go struct）](#5-配置类型定义go-struct)
6. [包序列场景（HexDump S1-S10）](#6-包序列场景hexdump-s1-s10)
7. [测试用例（T-001 ~ T-040）与映射索引](#7-测试用例t-001--t-040与映射索引)
8. [实现集成点](#8-实现集成点)
9. [错误处理](#9-错误处理)
10. [扩展字段映射](#10-扩展字段映射)
11. [修订记录](#11-修订记录)
12. [层链迁移契约（D1-D8）](#12-层链迁移契约d1-d8-2026-09-30-2026-10-01-对账)
13. [规范要求矩阵](#14-规范要求矩阵4-八项--三张-p1-子表)
14. [三路对照与候选方案对比](#15-三路对照与候选方案对比)
15. [依赖 / 错误 / 重试 / 超时 / 性能](#16-依赖--错误--重试--超时--性能)
16. [八要素](#17-八要素p2-代码设计定稿入口实现已落码本节为逆向定稿)
17. [动态字段清单 + 序号算法](#18-动态字段清单--序号算法)
18. [门 1 十四行对照表](#19-门-1-11-14-十四行对照表)
19. [六项审查清单（C1-C6）](#20-六项审查清单c1-c6)

---

## 1. 协议概述

### 1.1 协议定位

FINS（全称 Factory Interface Network Service，中文常称为"工厂接口网络服务"，由欧姆龙提出并维护）是欧姆龙 **PLC（Programmable Logic Controller，可编程逻辑控制器）** 家族（CS/CJ/CP 系列等）使用的自有通信协议，广泛用于**上位机（host computer，人机交互上位软件/SCADA 监控软件）** 与 PLC 之间的内存读写、状态查询、程序上下载等工业运维操作。协议栈本体与厂商私有 Ethernet 链路（如 SYSMAC LINK、Controller Link）配套定义，也可经 **FINS/UDP** 与 **FINS/TCP** 映射到标准 IP 网络，端口均为 **9600**（IANA 未注册，事实标准；见 §3）。

与同域的 dnp3/modbus/enip（本仓库已实现）相比，FINS 的特征是：**固定 10 字节命令头 + 2 字节命令码 + 参数/数据，全大端（big-endian，高位在前）**；没有 modbus 的 CRC、没有 enip 的会话握手语义；对每个请求，PLC 必须回一格**响应帧**，响应里带一个 **MR（main response，主响应码）+ SR（sub response，副响应码）** 合并的两字节**结束码（end code）**（0x0000 = 正常完成）。

### 1.2 与既有协议的关系

| 维度 | FINS | 同域参照 |
|------|------|---------|
| 传输载体 | UDP 9600 / TCP 9600（TCP 时加 16 字节 FINS/TCP 头） | dnp3（TCP/UDP）、modbus（TCP/RTU）、enip（TCP/UDP/UDP 仅 I/O） |
| 报文编码 | 全大端，固定 10 字节命令头 | modbus 大端、enip 小端 |
| 校验 | 无 CRC/校验和 | modbus 有 CRC、enip 无、dnp3 有 CRC |
| 会话 | FINS/TCP 无显式会话握手（直接发命令帧） | enip 需 RegisterSession |
| 结束码 | 响应含 2 字节 MR+SR 结束码 | modbus 无、dnp3 对象+qualifier、enip 有 CIP status |

### 1.3 目标与非目标

**目标**：
- G1：FINS/UDP 与 FINS/TCP 双载体的**请求-响应**双向包序列生成（上位机 → PLC 请求 + 模拟 PLC 的响应回包）
- G2：内存区读写命令集（**Memory Area Read 内存区读** 0101、**Memory Area Write 内存区写** 0102，含位/字两种口径）；辅以 **Memory Area Fill 内存区填充** 0103、**Multiple Memory Area Read 多内存区读** 0104
- G3：覆盖 CIO/工作区 WR/保持区 HR/定时器计数器 TC/数据内存 DM/索引寄存器 IR 六类内存区，位域（bit）与字（word）双口径
- G4：10 字节命令头全部字段可由配置显式指定（ICF/GCT/DNA/DA1/DA2/SNA/SA1/SA2/SID），**无配置时自动生成合法缺省值**；SID（service ID，服务标识号）按"每会话内递增"自动填充
- G5：响应模拟端返回 MR+SR 结束码；**错误码响应**也要能构造（如 0x1101 非法内存区）
- G6：IPv4 与 IPv6 双栈（FINS 载荷与 IP 版本无关，仅上层链路类型不同）
- G7：**多会话（sessions>1）**并发：每条会话独立 SID 计数
- G8：配置零负载直传生成器：`{"fins": {}}` 空配置即可生成一条合法 FINS 默认帧，验证采测试策略"层注册 category=Terminal、DependsOn=["udp"]、TransportOn=["udp","tcp"]"（见 §8）

**非目标**（首版不实现，见 §9 扩展）：
- NG1：参数区（Parameter Area，命令 0201-0203）、程序区（Program Area，0301-0303）读写——首版仅登记结束码映射；若进入需求，先扩 registry/Validate，再补层链用例
- NG2：RUN/STOP 切换（0401/0402）、错误日志（2102/2103）、文件内存（21xx）等系统命令
- NG3：**Tomake/Wireshark 兼容的 "FINS Gateway" 多级路由**语义——GCT 恒为 0x02（单跳直连），DNA/SNA 恒为 0x00
- NG4：FINS/TCP 的 "Node Address Data Send"（命令 0x00/0x01）扩展帧头——本版只做 **Frame Send（帧发送，命令 0x02）** 一种 FINS/TCP 帧

### 1.4 术语（中文解释）

| 术语 | 中文 | 说明 |
|------|------|------|
| PLC | 可编程逻辑控制器 | 欧姆龙工控核心设备，FINS 的服务端 |
| FINS memory area | 内存区 | PLC 内部编址的数据区，见 §2.2 表 |
| word / bit 口径 | 字 / 位口径 | 读写的寻址粒度：16 位字、或单 bit |
| command code | 命令码 | 头后 2 字节大端，标识命令类型（0101 读/0102 写） |
| end code（MR+SR） | 结束码 | 响应帧取代"数据段"的 2 字节状态码，0x0000=正常 |
| ICF | 信息控制字段 | 头第 1 字节：网关/消息类型/响应要求位 |
| SID | 服务标识号 | 头第 10 字节，请求-响应对的关联号，本设计中每会话递增 |
| FINS/TCP header | FINS/TCP 头 | TCP 载荷前 16 字节：'FINS'+4B length+4B command+4B error code |
| Frame Send | 帧发送 | FINS/TCP 命令 0x02：承载标准 FINS 帧 |
| 上位机 | host computer | 发起 FINS 请求的一方（本设计的客户端） |

### 1.5 权威字节事实来源

- gofins（`github.com/l1va/gofins`）header.go/driver.go/memory_area.go/command_code.go/end_code.go
- Wireshark `packet-omron-fins.c`（Sourcefire 维护的 OMRON FINS 解析器）：字段名 `omron.*`、TCP 端口 9600、FINS/TCP 头布局、`get_omron_fins_tcp_pdu_len` 的 length 语义
- 欧姆龙官方手册（W342-E1 系）中的命令码、内存区码、结束码表（上述两个开源实现的数据即转录自此手册，交叉一致）

> 本设计所有字节布局均以"公开实现 + tshark 解析器"交叉核对为准，不凭空构造。

---

## 2. 数据类型与编码

### 2.1 全大端编码

FINS 全部多字节数值（命令码、内存地址、元素数、数据字、结束码、FINS/TCP 的 length/command/error_code）一律**大端序（big-endian，网络字节序，高位字节在前）**。与 enip（小端）形成对比，是本协议最容易写错的点。

| 类型 | 字节数 | 输出示例 |
|------|--------|---------|
| command code（命令码） | 2 | 0x0101 → `01 01` |
| 内存地址 address（起始地址） | 2 | 0x0000 → `00 00`；0x0010 → `00 10` |
| 元素数 item count（BC 读取数/NC 写入数/DC 数据字数） | 2 | 3 → `00 03` |
| 字数据（大端地主读值） | 2×N | 0x1234 → `12 34` |
| end code 结束码（MR+SR） | 2 | 0x0000 → `00 00` |
| FINS/TCP length | 4 | 26 → `00 00 00 1A` |
| FINS/TCP command/error code | 4 | 0x00000002 → `00 00 00 02` |

### 2.2 FINS 内存区（memory area）码表

内存区码是**1 字节**，紧跟命令码。**同一区域有两种口径**：位（bit）与字（word），码值不同。下表给出本设计支持的六类区域（对照 Wireshark `memory_area_code_cv` 与 gofins `memory_area.go`，两处字节值一致）：

| 区域 | 中文 | 位码（bit） | 字码（word） | 备注 |
|------|------|------------|-------------|------|
| CIO | CIO 区（I/O 区） | 0x30 | 0xB0 | CS1 系：输入/输出继电器区，实际 IO 编号 |
| WR（W） | 工作区（work area） | 0x31 | 0xB1 | 位码/字码 |
| HR（H） | 保持区（holding area） | 0x32 | 0xB2 | 掉电保持 |
| TC | 定时器/计数器 | 0x09（完成标志） | 0x89（PV 值） | 位=Completion Flag、字=PV（进程值） |
| DM（D） | 数据内存 | 0x02 | 0x82 | 16 位字区，只可按字读写 |
| IR（Index Register） | 索引寄存器 | — | 0xDC | 仅字口径（CS1），用作间接寻址 |

> 注：gofins 的 `MemoryAreaCIOWord = 0xb0` 与 Wireshark 的 `0xB0 "CS1 mode: CIO Area: Word contents"` 一致；`0x30` 在**非 CS1 模式**另有含义（CIO/TR/CPU Bus Link 位状态），但**在 CS1 模式下等价于 CIO 位区**。本设计采用 CS1 系口径（0x30/0x31/0x32 位、0xB0/0xB1/0xB2 字），这也是 modem 类实现（含 Wireshark 的 memory_area_code_prefix：0x30→"CIO"、0x31→"W"、0x32→"H"、0x82→"D"）的通行映射。
>
> **DM 没有位口径**：D 区是 16 位字区，用户配置 `dm` + bit 时 validate 必须拒绝（见 §9 错误表 E-03）。
>
> **TC 位≠字**：TC 的位码（0x09 Completion Flag，完成标志）与字码（0x89 PV，进程值）语义不同——读 TC 位返回"定时/计数完成与否的 1 bit"，读 TC 字返回 16 位当前值。本设计配置里用 `tc_bit`/`tc_pv` 两个区域名区分。

### 2.3 内存地址 4 字节编码

FINS 内存寻址在命令参数里是固定 4 字节 **【内存区码(1) + 起始地址(2，大端) + 位偏移(1)】**，与命令码一起构成"内存寻址参数"：

```
0   Memory Area Code（内存区码，1B）
1   Beginning Address 起始地址（2B 大端）
3   Bit 位偏移（1B；字口径固定 0，位口径为 00-0F）
```

- 字口径：位偏移必须为 0
- 位口径：位偏移 0x00-0x0F（16 位字的 bit 0-15）；对 CIO/HR 等区，地址按"字地址"写、位偏移给出该字内的 bit 号
- gofins `encodeMemoryAddress`：`bytes[0]=area; BigEndian.PutUint16(bytes[1:3], address); bytes[3]=bitOffset`——与本表完全一致

### 2.4 元素数 / 位计数

命令参数里的"元素数"（item count）字段是 2 字节大端：

- **Memory Area Read（0101）**：`NC`（number of items，读取元素数）——"读取几个单位"。**字口径**单位 = 字，**位口径**单位 = bit（一个 bit 占响应数据 1 字节）
- **Memory Area Write（0102）**：`NC`（写入元素数）+ `DC`（data count，数据字节数）——写 N 个字或 N 个 bit，DC 字节保证表的完整性（D 区一次最多 960、CIO/WR 等一次最多 960 字、TC PV 960）。实际数据长度为 DC 字节，NC 与 DC 的关系：字口径 DC=2×NC；位口径 DC=NC（bit 数据压缩为每 bit 1 字节 0x00/0x01）
- **Range check（范围校验）**：0x00（不检查）

### 2.5 字数据与位数据的载荷编码

- **字数据（word data）**：读响应 `omron.response.data` = 连续 `NC × 2` 字节大端字；写请求载荷同样按大端字排布
- **位数据（bit data）**：读响应每 bit 占 1 字节，取值 0x00（OFF）/0x01（ON）；写请求同样每 bit 1 字节

### 2.6 结束码（end code）编码

响应帧的命令码之后**不是数据而是 2 字节结束码**：

```
0   MR（main response code，主响应码，1B）+ SR（sub response code，副响应码，1B）
```

- 正常完成：`00 00`
- 常见错误（完整表见 §9）：

| 结束码 | 中文 | 场景 |
|--------|------|------|
| 0x0000 | 正常完成 | 一切成功路径 |
| 0x0001 | 服务被中断 | 长命令被打断 |
| 0x0401 | 使用了未定义的命令 | 未知命令码 |
| 0x1001 | 命令超长 | 超过最大允许长度 |
| 0x1101 | 内存区码无效（或 DM 不可用） | **非法内存区**（负路径核心） |
| 0x1102 | 指令中的访问大小错误 | 元素数 NC 非法（如 0） |
| 0x1103 | 第 1 个地址在不可访问区域 | **地址越界**（负路径核心） |
| 0x2002 | 数据被保护 | 写保护区域 |
| 0x2003 | 注册表不存在 | 多区读注册表缺失（0104 专属） |

> gofins `end_code.go` 与 Wireshark `response_codes[]` 的 16 位编排一致：高位字节=主响应码、低位字节=副响应码，二进制的组合位含义见 §9.2。

### 2.7 FINS/TCP 头编码（仅 TCP 载体）

FINS/TCP 帧 = **16 字节 FINS/TCP 头 + FINS 帧**。头为全大端（Wireshark `get_omron_fins_tcp_pdu_len`/`dissect_omron_fins_tcp_pdu` 实测）：

| 偏移 | 长度 | 字段 | tshark 字段名 | 值 |
|------|------|------|--------------|-----|
| 0 | 4 | 魔数（magic bytes） | `omron.tcp.magic` | 0x46494E53 = ASCII `'FINS'` |
| 4 | 4 | 长度（length） | `omron.tcp.length` | **builder 当前为 8 + FINS 帧字节数**（wire 事实以实现/pcap 为准） |
| 8 | 4 | 命令（command） | `omron.tcp.command` | 0x00000000-0x06，本设计只用 0x00000002 = Frame Send |
| 12 | 4 | 错误码（error code） | `omron.tcp.error_code` | 0x00000000 |
| 16 | — | FINS 帧 | 见 §3 | 10 头 + 2 命令码 + 参数 |

**length 的语义（实现事实）**：当前 `wrapTCP` 将 length 写为 `8 + len(FINS frame)`，因此 18 字节 FINS 帧对应 length=26，TCP 总载荷为 16+18=34 字节。该字段口径必须以 builder 与真实 pcap 联合校准，不能沿用旧的“仅 FINS 帧长度”描述。

> **TCP 命令号 vs FINS 命令码混淆警告**：FINS/TCP 头的 command 字段是 4 字节 `0x00000002`（Frame Send），与 FINS 帧内的 2 字节命令码 `01 01`（Memory Area Read）是两回事——一个在 TCP 头、一个在 FINS 帧参数段，必须严格区分。tshark 用 `omron.tcp.command` 与 `omron.command` 两个字段分别显示。

### 2.8 FINS/UDP 帧（无附加头）

FINS/UDP 帧 = **直接 FINS 帧**（10 头 + 2 命令码 + 参数），无 FINS/TCP 头、无长度字段、无校验。UDP 载荷长即帧长。

### 2.9 SID 与响应关联

- SID（service ID，服务标识号）= 命令头第 10 字节，用于把响应与请求配对（同一会话内响应回显请求 SID）
- 上位机规则：本次请求的 SID 可自选；**响应帧的 SID 与请求一致**（gofins `defaultResponseHeader` 复用请求 header 的 serviceID）
- 本设计默认策略：**每会话内 SID 从 1 起递增，每新请求 +1，回绕 255→1**（0 保留给"响应所需"场景最小代价）；多会话（sessions>1）时各会话独立计数
- 用户显式配置 SID 时（`{fields ... "sid": 5}`）该包用配置值；但多包请求序列中用户只给一个固定 SID 会让 tshark 的"请求-响应对"可读性下降——测试用例中固定 SID 仅用于单请求场景，序列场景用自动递增

### 2.10 ICF（Information Control Field，信息控制字段）位布局

ICF 为头第 1 字节（8 位，bit7 为 MSB）。Wireshark `icf_*` 子位字段名与 gofins `encodeHeader` 一致：

| 位 | 名称 | 含义 |
|----|------|------|
| bit7 | 网关使用（gwb） | 0=不使用网关 / 1=使用网关。**本设计恒 1**（在线路上标准上位机报文置 1） |
| bit6 | 消息类型（dtb） | 0=命令（command）/ 1=响应（response） |
| bit5 | 保留（rb0） | 恒 0 |
| bit4 | 保留（rb1） | 恒 0 |
| bit3 | 保留（rb2） | 恒 0 |
| bit2 | 保留（rb3） | 恒 0 |
| bit1 | 保留（rb4） | 恒 0 |
| bit0 | 响应要求（rsb） | 0=需要响应 / 1=不需要响应 |

缺省命令 ICF = `1000 0000` = **0x80**（网关使用 + 需要响应）；响应 ICF = `1100 0000` = **0xC0**（网关使用 + 消息类型=响应 + 需要响应）。bit0 为不响应标志，缺省保持清零。

> 校验点：用户配置 ICF 时（负路径）要求 bit6 与消息方向一致、bit0=0（请求必须期望响应，否则设备不回包）、bit7=1（网关位必须为 1），非法 ICF 走 E-06（见 §9）。

### 2.11 命令头其余字段

| 字段 | 偏移 | 默认值 | 说明 |
|------|------|--------|------|
| RSV | 1 | 0x00 | 保留字节，恒 0 |
| GCT（Gateway Count，网关计数） | 2 | 0x02 | 单跳直连 = 2 |
| DNA（Destination Network Address，目的网络号） | 3 | 0x00 | 本设计唯一合法值 0 |
| DA1（Destination Node，目的节点号） | 4 | 0x00（可由 config 设置） | 目标 PLC 节点号 |
| DA2（Destination Unit，目的单元号） | 5 | 0x00 | 目标 CPU 单元号 |
| SNA（Source Network Address，源网络号） | 6 | 0x00 | 本设计唯一合法值 0 |
| SA1（Source Node，源节点号） | 7 | 0x00（可由 config 设置） | 上位机节点号 |
| SA2（Source Unit，源单元号） | 8 | 0x00 | 上位机单元号 |
| SID（Service ID，服务标识号） | 9 | 递增 | 见 §2.9 |

### 2.12 BCD（Binary Coded Decimal，二-十进制）编码

部分参数（时钟读取 0x0701、节点号等）以 BCD 编码（每 4 bit 一个十进制位，未用到的半字节填 0x0F）。本设计的时钟读取响应中月/日/时/分/秒均为 BCD。**负路径**测试"BCD SID"指：SID 字段本身是普通字节而非 BCD（为满足任务强制覆盖"BCD SID"，设计在时钟读取响应里对"小时 BCD=0x14"这种半字节合法边界给出断言；SID 的 BCD 化是非目标的配置陷阱，见 §9 E-09）。

---

## 3. 消息结构

### 3.1 总览

```
FINS/UDP 帧：
+--------------------------------------------------+
| FINS 命令头 (10B)  ICF RSV GCT DNA DA1 DA2 SNA SA1 SA2 SID
+--------------------------------------------------+
| Command Code (2B 大端)    内存区读 0101 / 写 0102 / ...
+--------------------------------------------------+
| Command Text（命令文本，按命令码解释）
|   读    : 内存寻址参数(4B) + 元素数 NC(2B)
|   写    : 内存寻址参数(4B) + 元素数 NC(2B) + 数据计数 DC(2B) + 数据
+--------------------------------------------------+

FINS/TCP 帧：
+----------------+ FINS/TCP 头 (16B)
| 'FINS' (4B)    | 0x46 49 4E 53
| Length (4B)    | 8 + FINS 帧字节数（builder 当前口径）
| Command (4B)   | 0x00000002 Frame Send
| Error Code(4B) | 0x00000000
+----------------+
| FINS 帧 (同上) ... FINS 命令头 + 命令码 + 命令文本
+----------------+
```

### 3.2 FINS 命令头（10 字节，两种载体共用）

偏移速查：

| 偏移 | 字段 | 字节 |
|------|------|------|
| 0 | ICF | 1 |
| 1 | RSV | 1 |
| 2 | GCT | 1 |
| 3 | DNA | 1 |
| 4 | DA1 | 1 |
| 5 | DA2 | 1 |
| 6 | SNA | 1 |
| 7 | SA1 | 1 |
| 8 | SA2 | 1 |
| 9 | SID | 1 |

### 3.3 FINS 命令码速查

| 命令码 | 中文 | 参数体 | 响应体 |
|--------|------|--------|--------|
| 0x0101 | Memory Area Read 内存区读 | 寻址参数 + NC | 结束码 + NC×2 字节数据 |
| 0x0102 | Memory Area Write 内存区写 | 寻址参数 + NC + DC + 数据 | 结束码（无数据） |
| 0x0103 | Memory Area Fill 内存区填充 | 寻址参数 + NC + DC + 填充数据 | 结束码 |
| 0x0104 | Multiple Memory Area Read 多内存区读 | 寻址数(1B) + [寻址参数+NC]×N | 结束码 + [数据字×N 组] |
| 0x0105 | Memory Area Transfer 内存区传送 | 详见 §10 | 结束码 |
| 0x0701 | Clock Read 时钟读取 | （无参数） | 结束码 + 8 字节 BCD 日期时间 |
| 0x0401/0x0402 | Run/Stop 模式切换 | 1 字节（RUN=0x04/STOP=0x00） | 结束码 |

本设计**首版实现** 0101/0102（主）、0103/0104（强化）、0x0701（辅助，用于 BCD/无参数帧的 HexDump 简单场景）。

### 3.4 Memory Area Read（0101）请求/响应

```
请求：
 00   Command Code（2B）         = 01 01
 02   Memory Area Code（1B）     如 82（DM 字）
 03   Beginning Address（2B）    = 00 64（D100）
 05   Bit（1B）                  字口径=00；位口径=00-0F
 06   Number of Items（2B）      = 00 03（读 3 个字）
 08   总请求 = 10 字节

响应：
 00   Command Code（2B）         = 01 01
 02   End Code（2B）             = 00 00
 04   数据（NC×2 字节）          = 12 34 56 78 9A BC
```

### 3.5 Memory Area Write（0102）请求/响应

```
请求：
 00   Command Code（2B）         = 01 02
 02   Memory Area Code（1B）
 03   Beginning Address（2B）
 05   Bit（1B）
 06   Number of Items NC（2B）   = 00 02
 08   Data Count DC（2B）        = 00 04（2 字 = 4 字节）
 10   数据                    = 11 22 33 44
 14   总请求 = 14 字节（10 参数 + 4 数据）

响应：
 00   Command Code（2B）         = 01 02
 02   End Code（2B）             = 00 00   （无数据）
```

### 3.6 Memory Area Write 位口径（bit write）

写位时 NC=写入 bit 数、DC=NC、数据每 bit 1 字节（0x00/0x01）：

```
 02   内存区码 = 30（CIO 位）
 03   起始字地址 = 00 00（CIO0）
 05   Bit = 03（第 3 bit）
 06   NC = 00 02（2 个 bit）
 08   DC = 00 02
 10   数据 = 01 00（bit3=ON、bit4=OFF）
```

### 3.7 Memory Area Read 位口径（bit read）

与字口径同结构，只是位码 + 响应每 bit 1 字节。例如 CIO0.02 ~ CIO0.03 两个 bit：区域码 0x30、地址 0000、bit 02、NC=2 → 响应 `01 00`（bit2=ON、bit3=OFF）。

### 3.8 Memory Area Fill（0103）

写入区的一部分填同一数据（如刷 0）。**注意：0103 没有 DC 字段**——命令体固定 8 字节 = 寻址参数(4) + NC(2) + 填充数据字(2)；tssark packet-omron-fins.c 对 0103 请求要求剩余长度==8：

```
 00   命令码 = 01 03
 02   区域内参数（区域码/地址/位）     与写相同（4B）
 06   NC（2B）              要填充的元素数
 08   填充数据（2B）         单字模板，按 NC 重复（字口径）
08+N   请求 FINS 帧 = 10 + 2 + 8 = 20 字节（NC=1 时）
```

### 3.9 Multiple Memory Area Read（0104）

```
请求：
 00   命令码 = 01 04
 02   区域内参数数 Word（1B）         = 00 02（读 2 组）
 03   [内存区码 + 起始地址(2B) + Bit + NC(2B)] × 2  每组 6 字节
 15   （2 组 = 12 字节参数）

响应：
 00   命令码 = 01 04
 02   结束码 = 00 00（tshark 对 0104 响应把结束码按 bitmask 解析为 omron.response.code）
 04   读出的数据（按各内存区码推字节长：0x82=2B/字、0x30=1B/bit 等，逐组 omron.response.data）
```

> **tshark 对 0104 请求组的怪癖**：`dissect_omron_fins_common` 的 0104 分支把请求剩余字节按 **4 字节/组**（区域码+地址 2+bit）循环解析，**忽略 NC**；故不要对请求的 NC 做 omron.* 字段断言（不解析），用 FrameAssert 校验原始字节（`01 04 00 02 82 00 64 00 00 01 ...`）。

### 3.10 Clock Read（0x0701）

```
请求：
 00   命令码 = 07 01
 02   （无参数，请求共 12 字节 = 10 头 + 2 命令码）

响应：
 00   命令码 = 07 01
 02   结束码 = 00 00
 04   8 字节 BCD：世纪/年/月/日/时/分/秒/星期
```

字节解析（BCD 半字节；低半字节 0xF 表示未用）：

| 字节 | 含义 | 示例 |
|------|------|------|
| date[0] | 世纪 (BCD) | 20 → 0x20 |
| date[1] | 年（后两位 BCD） | 26 → 0x26 |
| date[2] | 月（BCD 01-12） | 08 → 0x08 |
| date[3] | 日（BCD 01-31） | 18 → 0x18 |
| date[4] | 时（BCD 00-23） | 14 → 0x14 |
| date[5] | 分（BCD 00-59） | 30 → 0x30 |
| date[6] | 秒（BCD 00-59） | 00 → 0x00 |
| date[7] | 星期（0=周日 .. 6=周六，BCD） | 02   |

> "BCD SID"强制覆盖点：SID 为普通字节、不做 BCD；这里用 clock 响应的**小时 BCD 半字节**（0x14）断言 BCD 编码正确性（见 §2.12 与用例 T-012）。
>
> **tshark 对 0x0701 响应的处置**：packet-omron-fins.c 把 0x0701 列入"命令数据长必须为 0"分支——**响应只解析到 SID/命令码即返回**，不解析结束码（无 `omron.response.code`）也不解析 BCD 字节。因此 clock 用例的响应断言一律用 **FrameAssert 原始字节**（结束码 `00 00` + 8B BCD 连续排列），不要用 `omron.response.*` 字段。

---
## 4. 状态机

### 4.1 总体：无会话、每个请求一对请求/响应

FINS 与 enip（需 RegisterSession 建会话）本质不同：**没有显式会话握手**。UDP 上一个 FINS 请求帧 + 一个 FINS 响应帧即一次完整交互；TCP 上也是直接发 Frame Send 命令帧（无需先协商）。因此 planner 的状态机是"每请求一个回合（round，客户端发一帧、模拟设备回一帧）"，多请求构成序列。

### 4.2 回合内状态（请求 → 响应）

```
                   发送请求帧
   ┌──────────────────► ┌──────────────┐
   │  (客户端)          │ 请求已发出     │
   │                    └──────┬───────┘
   │                           │ 设备自动响应
   │                    ┌──────▼───────┐
   │                    │ 响应帧已回     │
   └────────────────────┴──────────────┘
```

- 每个**请求命令**（direction=up）必配一个**响应命令**（direction=down，SID 同请求、ICF 的 dtb=响应、内存区请求的响应含数据/结束码）
- 响应内容按命令码决定：读写类回数据或结束码；时钟读取回 BCD 数据
- 用户配置 `expect_response: false`（或 ICF 的 rsb=1）时该请求不回响应——仅供构造"无响应"实测场景（对应 §9 E-08 的部分观测），默认强制必须有响应

### 4.3 多命令序列状态

```
 命令1              命令2                命令N
 up ──► down        up ──► down          up ──► down
 [   回合1   ]      [   回合2   ]   ...   [   回合N   ]
SID=1              SID=2                SID=N
```

- 按配置顺序顺序执行各命令；同一会话内 SID 逐回合递增（§2.9），响应的 SID=同回合请求的 SID
- 全部回合执行完 = 流结束（比 enip 少"会话关闭"显式动作）

### 4.4 多会话并行（sessions>1）

- 配置 `sessions: N` 时，planner 生成 N 条**并行流（flow）**，每条流内 SID 独立从 1 起递增（会话 1 的 SID=1、会话 2 的 SID=1、……互不干扰）
- 各流可配置不同 4-tuple（源/目的 IP、端口）；缺省共享同一 4-tuple
- 判别/观测：`omron.sid` 的**每流**取值序列独立递增；多流调度时**不承诺**跨包固定顺序（tshark 的 `omron.sid` 在 aggregate 层面会出现 `1,2,3,1,2,3` 交织）
- 实现采用"每流独立 SID 计数器"（不能共享一个全局递增，否则并发下 SID 语义混乱）——这正是 Testing Policy §6 "并发测正确性而非仅无 race" 的关注点：多流用例断言 `distinct_values` 为 `["0x01","0x02",...,"0x0N"]`，且每流内无重复

### 4.5 UDP 载体下的方向与端口

- 请求帧去向：client src_ip:src_port → device dst_ip:9600
- 响应帧：device 9600 → client src_port（回程方向 swap src/dst）
- 测试断言：`udp.srcport` / `udp.dstport` 在请求/响应两包上互为镜像（见用例 T-001）

### 4.6 TCP 载体下的帧边界

- 每个 FINS/TCP PDU = 16 字节 FINS/TCP 头 + 1 个 FINS 帧（Frame Send）
- 请求/响应各自包一个 PDU；靠 tshark 的 `omron.tcp.length` + `omron.tcp.command` 识别边界
- **不实现** TCP 分片重组之外的跨 PDU 拼接（一个 FINS 帧必须完整处于一个 PDU 中；若上层 MSS 不足则整个 PDU 会因 TCP 分片产生 IP 分片——这是网络层行为，与 FINS 无关）
- 首选端口 9600；用户覆盖 dst_port 时 tshark 需 `-d` 提示（cases JSON 的 `decode_as` 字段，见 `docs/protocols/fins/testcase.md` §2）

### 4.7 ICF 方向不变量（validate 校验）

| 约束 | 违规处 |
|------|--------|
| 命令（up）帧 ICF bit6=0，响应（down）帧 bit6=1 | E-06 |
| 请求 ICF bit0=0 且配置要求响应 | n/a |
| RSAV/保留位必须为 0；bit7(网关)=1 | E-06 |
| 响应帧 SID 必须等于同回合请求 SID（planner 内建，非用户可配） | n/a |

---

## 5. 配置类型定义（Go struct）

### 5.1 设计原则

1. **零值可用**：`{"fins": {}}` 生成"DM 区 D100 读 2 字 + 自动响应"的默认合法帧（§8 层注册零负载目标）
2. **策略可引用**：数据负载支持 `StrategyConfig`（fixed/inc/rand/pattern），使多包场景可生成递增数据；SID 默认自动递增
3. **planner 自动填充**：FINS 头长度、命令码长度、结束码（响应）、FINS/TCP length 均由 builder 计算
4. **字节序 builder 处理**：用户写 host-endian 值，builder 负责大端序列化
5. **方向即角色**：up=客户端发出的请求，down=模拟设备回应的响应；一条命令的请求/响应成对出现（§4）

### 5.2 FINSConfig 顶层结构

```go
// FINSConfig 是 FINS 协议的顶层配置（位于 spec_json["fins"]）。
type FINSConfig struct {
    // Transport：udp / tcp（默认 udp）
    Transport string `json:"transport" yaml:"transport"`

    // Commands 是 FINS 命令序列（按顺序执行，up+down 成对）。
    Commands []FINSCommand `json:"commands" yaml:"commands"`

    // 与会话相关的自动行为
    // Sessions：并行流数（默认 1）。>1 时每条流独立 SID 计数（§4.4）。
    Sessions int `json:"sessions" yaml:"sessions"`

    // SIDAuto：true = 每会话内自动递增（默认 true）；false = 用各命令显式 sid。
    SIDAuto bool `json:"sid_auto" yaml:"sid_auto"`

    // === 命令头默认字段（可整体覆盖；不写走 §2.11 默认值） ===
    ICF  uint8 `json:"icf" yaml:"icf"`      // 默认：请求 0x80 / 响应 0xC0（按方向）
    GCT  uint8 `json:"gct" yaml:"gct"`       // 默认 0x02
    DNA  uint8 `json:"dna" yaml:"dna"`       // 默认 0x00（唯一合法值）
    DA1  uint8 `json:"da1" yaml:"da1"`       // 默认 0x00
    DA2  uint8 `json:"da2" yaml:"da2"`       // 默认 0x00
    SNA  uint8 `json:"sna" yaml:"sna"`       // 默认 0x00（唯一合法值）
    SA1  uint8 `json:"sa1" yaml:"sa1"`       // 默认 0x00
    SA2  uint8 `json:"sa2" yaml:"sa2"`       // 默认 0x00

    // SID 为 0 时走自动递增（SIDAuto=true 时忽略显式值）。
    SID  uint8 `json:"sid" yaml:"sid"`

    // === 目标地址（跨 sessions 可覆盖） ===
    DstIP   string `json:"dst_ip"`
    DstPort uint16 `json:"dst_port"`          // 默认 9600
    SrcIP   string `json:"src_ip"`
    SrcPort uint16 `json:"src_port"`          // 默认 0（系统分配）
}
```

### 5.3 FINSCommand 结构（命令+响应成对）

```go
// FINSCommand 是一条命令回合：请求（direction=up）+ 设备响应（direction=down）。
type FINSCommand struct {
    // Command 命令码（0x0101 MemoryAreaRead 等，见 §3.3）。
    Command uint16 `json:"command"`

    // Direction：up（客户端→设备，默认）/ down（设备→客户端）。
    // planner 按 up 命令推导 down 响应；也可显式写 down 命令构造错误码响应。
    Direction string `json:"direction"`

    // === 头字段（单命令覆盖顶层默认） ===
    SID  uint8 `json:"sid"`
    ICF  uint8 `json:"icf"`

    // === 内存区命令参数（0101/0102/0103/0104 用） ===
    MemoryArea  string `json:"memory_area"`    // "cio"/"wr"/"hr"/"tc"/"dm"/"ir"/"tc_bit"/"tc_pv"
    Address     uint16 `json:"address"`        // 起始字地址
    Bit         uint8  `json:"bit"`            // 位偏移 0-15；字口径必 0
    Items       uint16 `json:"items"`          // NC 元素数（字/位单位）
    // Data：写入数据（0102/0103）或读响应数据（0101 的 down）。
    // []int：按 int 序列化（字 = 2 字节大端；位 = 1 字节 0x00/0x01）。
    Data        StrategyConfig `json:"data"`
    // FillWord：0103 内存区填充的字模板（重复 DataCount/2 次）。
    FillWord    uint16 `json:"fill_word"`

    // === 多内存区读（0104） ===
    // ReadAreas：每组 {memory_area, address, bit, items}
    ReadAreas []FINSReadArea `json:"read_areas"`

    // === 时钟读取（0x0701）响应字段 ===
    Clock FINSClock `json:"clock"`

    // === 响应控制 ===
    // ExpectResponse：请求是否期望响应（默认 true）。
    ExpectResponse bool `json:"expect_response"`
    // ResponseEndCode：响应结束码（默认 0x0000）。
    ResponseEndCode uint16 `json:"response_end_code"` // 支持 0x1101/0x1103 等错误码
    // ResponseDataOverride：覆盖自动响应数据（构造错误/异常响应时用）。
    ResponseDataOverride StrategyConfig `json:"response_data_override"`
}

type FINSReadArea struct {
    MemoryArea string `json:"memory_area"`
    Address    uint16 `json:"address"`
    Bit        uint8  `json:"bit"`
    Items      uint16 `json:"items"`
}

// FINSClock 是 Clock Read（0x0701）响应中的 8 字节 BCD 日期时间。
type FINSClock struct {
    Century uint8 `json:"century"` // 20 → 0x20
    Year    uint8 `json:"year"`    // 26 → 0x26
    Month   uint8 `json:"month"`   // 08 → 0x08
    Day     uint8 `json:"day"`     // 18 → 0x18
    Hour    uint8 `json:"hour"`    // 14 → 0x14
    Minute  uint8 `json:"minute"`  // 30 → 0x30
    Second  uint8 `json:"second"`  // 00 → 0x00
    Weekday uint8 `json:"weekday"` // 02 周二
}
```

### 5.4 配置到 FINS 帧的填充顺序（builder）

```
1. 框架：定长度（FINS/TCP 时先算 FINS 帧长再填 16B 头）
2. 命令头：ICF（按方向默认/覆盖）RSV GCT DNA DA1 DA2 SNA SA1 SA2 SID
   SID：SIDAuto → 会话内递增值；否则显式 SID
3. 命令码（2B 大端）
4. 命令文本：
   0101 up   : area+address+bit + items
   0101 down : endcode + data（按 Data 策略 / ResponseDataOverride）
   0102 up   : area+address+bit + items + dc + data   down: endcode
   0103 up   : area+address+bit + items + dc + fill   down: endcode
   0104 up   : read-count + groups                    down: endcode + data
   0701 up   : （无参数）                             down: endcode + 8B BCD
   其他命令  : 按 §3.3 参数体
5. 数据（字 2B / 位 1B 大端）
```

### 5.5 自动响应推导规则（重要）

planner 为用户写的**每个 up 命令**自动生成一个 down 响应命令：

| 命令 | 自动响应 |
|------|---------|
| 0101 读 | 结束码 0x0000 + `items×2` 字节数据（字）或 `items` 字节（位）；数据默认按 `fixed 0x0001,0x0002,...` 递增（若 Data 未配置） |
| 0102 写 | 结束码 0x0000（无数据） |
| 0103 填充 | 结束码 0x0000 |
| 0104 多区读 | 结束码 0x0000 + 各组数据拼接 |
| 0701 时钟 | 结束码 0x0000 + 8 字节默认 BCD（2026-08-18 14:30:00 周二） |
| 其他 | 结束码 0x0000 |

- 用户显式写 `direction: down` 命令（如无请求的单独响应构造）时，`ResponseEndCode` 可决出错误码响应（§9）
- `ExpectResponse: false` 的 up 命令跳过自动响应——该命令只发包请求

---

## 6. 包序列场景（HexDump S1-S10）

> 偏移约定：FINS 帧起点 = **UDP 载体 offset 42**（以太网14 + IP20 + UDP8）；**TCP 载体 offset 70**（以太网14 + IP20 + TCP20 + FINS/TCP头16）。字节为大端。tshark 使用（无 TCP 握手）：案例断言以 `fields`（`omron.*`）为主、`frames`（`offset`+`hex`）为辅。

### S1. FINS/UDP 内存区读写往返（DM 区）

**请求**（D100 读 2 字，client:1234 → device:9600）：

```
42  80 00 02 00 00 00 00 00 00 01    ICF=80(网关+需响应) RSV GCT=02 DNA DA1 DA2 SNA SA1 SA2 SID=01
52  01 01                             命令码 Memory Area Read
54  82 00 64 00 00 02                 DM(82) 地址0064(D100) bit=00 NC=0002
总 UDP 载荷 18 字节
```

**响应**（SID 回显 01、方向位=响应）：

```
42  C0 00 02 00 00 00 00 00 00 01    ICF=C0（bit6=响应）
52  01 01                             命令码
54  00 00                             结束码 正常
56  00 01 00 02                       数据 2 字（0x0001、0x0002）
```

tshark 断言：`omron.icf=0x80`、`omron.sid=0x01`、`omron.command=0x0101`、`omron.memory.area.read=0x82`、`omron.memory.address=0x0064`、`omron.memory.numitems=2`；响应包 `omron.icf=0xC0`、`omron.response.code=0x0000`。

### S2. FINS/TCP 读取（Frame Send，无握手）

TCP 载荷 = FINS/TCP 头(16) + FINS 帧(18) = 34 字节（`omron.tcp.length` 口径见下注）：

```
54  46 49 4E 53                       'FINS' 魔数
58  00 00 00 1A                       length=26（builder 当前口径：8 + FINS 帧 18B）
62  00 00 00 02                       命令 Frame Send
66  00 00 00 00                       error code
70  80 00 02 00 00 00 00 00 00 01    FINS 头（同 S1）
80  01 01                            命令码
82  82 00 64 00 00 02                DM 参数
```

> 帧总字节 34 = 16 + 18，`omron.tcp.length` = 26（builder 当前口径）。响应同构（ICF=C0、含结束码+数据）。

### S3. Memory Area Write 字口径

**请求**（D200 写 2 字 0x1122/0x3344）：

```
52  01 02                            命令码 Memory Area Write
54  82 00 C8 00                       DM(82) 地址00C8(D200) bit=00
58  00 02                             NC=2
60  00 04                             DC=4（2 字 = 4 字节）
62  11 22 33 44                      数据
```

**响应**：命令码 0102 + 结束码 `00 00`（无数据）。

### S4. Memory Area Write 位口径

**请求**（CIO 0.03 bit=ON、CIO 0.04 bit=OFF）：

```
54  30 00 00 03                       CIO 位(30) 地址0000 bit=03
58  00 02                             NC=2（写 2 个 bit）
60  00 02                             DC=2
62  01 00                             bit3=ON、bit4=OFF
```

### S5. Memory Area Read 位口径（HR 区）

**请求**（H 区 0010 的 bit 2、3 读：`32 00 10 02` + NC=0002）→ **响应数据** `01 00`（bit2=ON、bit3=OFF）。ttip：位读响应每 bit 1 字节，2 bit = 2 字节。

### S6. Multiple Memory Area Read（0104，2 组）

**请求**（D100 读 1 字 + D200 读 1 字）：

```
52  01 04                            命令码 Multiple Read
54  00 02                            区域内参数数 = 2 组
56  82 00 64 00 00 01                组1：DM(82) addr0064 bit0 NC=1
62  82 00 C8 00 00 01                组2：DM(82) addr00C8 bit0 NC=1
```

**响应**：结束码 `00 00` + 数据拼接 `00 01 00 02`（2 组各 2 字节）。

### S7. Clock Read（0x0701）与 BCD 数据

**请求**（无参数，12 字节 = 10 头 + 2 命令码）：

```
52  07 01                            命令码 Clock Read
```

**响应**（8 字节 BCD：2026-08-18 14:30:00 周二）：

```
54  00 00                            结束码
56  20 26 08 18                      世纪20 年26 月08 日18
60  14 30 00 02                      时14(BCD) 分30 秒00 星期02
```

> 强制覆盖"BCD SID"指：SID 字节普通递增（本例 SID=01），时钟响应的**时/月/日**用 BCD 半字节（0x14）断言 BCD 正确性（§2.12）。

### S8. FINS/TCP 无握手写（TransportOn=tcp）

Frame Send + Memory Area Write，总载荷 = 16 + (10+2+10) = 38 字节。TCP 头 `omron.tcp.command=0x00000002`，FINS 命令码 `omron.command=0x0102`。断言两类命令号共存于 matrix：`omron.tcp.command` ≠ `omron.command`（防混淆，§2.7 警告）。

### S9. IPv6 载体（FINS/UDP over IPv6）

仅上层链路换 IPv6（IP 头 40 字节），FINS 帧字节与 S1 **完全相同**；帧起点 offset = eth14 + ip6 40 + udp8 = **62**。断言 `ipv6.src/ipv6.dst` 与 `omron.*` 共存。

### S10. 多会话（sessions>1）SID 独立性

2 条会话流，各发 2 个读命令：

- 流 A：SID=01、SID=02；流 B：SID=01、SID=02
- 聚合观测（调度无关）：`omron.sid` 的 `DistinctValues` = `["0x01","0x02"]`，且任一连续同帧方向关联成立（UDP 端口也别流 `src_port` 不同更易辨认）
- **不承诺**固定交织顺序：多流调度非确定（详见 `docs/protocols/fins/testcase.md` 多会话用例）

---

## 7. 测试用例（T-001 ~ T-040）与映射索引
### 7.1 用例映射索引（cases/fins.json 45 条）

> 运行验证交给 45 条 **cases/fins.json 用例**（下表“JSON”列），每条强制覆盖点至少一条落盘；其余条目是设计级索引。设计级条目不得写成已验收，新增 JSON 必须同步两个文档与 §1.3 校验脚本。

| 编号 | 名称 | 强制覆盖点 | 类型 | JSON id（存在=有文件） |
|------|------|-----------|------|------------------------|
| T-001 | FINS/UDP 内存区读-响应往返（DM） | FINS/UDP 请求-响应 | 正 | `fins_udp_dm_read` |
| T-002 | FINS/TCP Frame Send 读取 | FINS/TCP | 正 | `fins_tcp_read` |
| T-003 | FINS/UDP IPv6 载体读取 | IPv4+IPv6 | 正 | `fins_udp_ipv6_read` |
| T-004 | CIO 区字读 | 内存区 CIO | 正 | `fins_cio_read_word` |
| T-005 | WR 区字读 | 内存区 WR | 正 | `fins_wr_read_word` |
| T-006 | HR 区字读 | 内存区 HR | 正 | `fins_hr_read_word` |
| T-007 | TC PV 字读 | 内存区 TC | 正 | `fins_tc_read_pv` |
| T-008 | IR 索引寄存器字读 | 内存区 IR | 正 | `fins_ir_read_word` |
| T-009 | HR 位域读（01 00 数据） | bit 域 | 正 | `fins_hr_read_bit` |
| T-010 | CIO 位域写 | bit 域 + 写 | 正 | `fins_cio_write_bit` |
| T-011 | DM 字写（NC/DC 对账） | DM + 写 | 正 | `fins_dm_write_word` |
| T-012 | Clock Read + BCD 数据（时=0x14） | BCD SID / BCD 编码 | 正 | `fins_clock_read_bcd` |
| T-013 | Memory Area Fill（0103） | 命令集 | 正 | `fins_fill_dm` |
| T-014 | Multiple Memory Area Read（0104） | 命令集 | 正 | `fins_multi_read` |
| T-015 | ICF 方向位（请求 0x80 / 响应 0xC0） | ICF | 正 | `fins_icf_explicit`（T-001 亦断言） |
| T-016 | SID 会话内递增（01→02） | SID 递增 | 正 | `fins_sid_auto_incr` |
| T-017 | 显式固定 SID | SID | 正 | `fins_sid_fixed` |
| T-018 | TCP 命令号 vs FINS 命令码隔离 | FINS/TCP 头 | 正 | 设计行（T-002 断言覆盖） |
| T-019 | expect_response=false 不回响应 | 状态机 | 正 | `fins_expect_response_false` |
| T-020 | sessions=2 双流 SID 独立递增 | **多会话 sessions>1** | 正 | `fins_sessions_two` |
| T-021 | sessions=3 聚合 DistinctValues | 多会话聚合 | 正 | `fins_sessions_three` |
| T-022 | 多会话不同 4-tuple | 多会话 | 正 | 设计行（T-020 断言覆盖） |
| T-023 | 多会话负路径：非法内存区 | 多会话 x 负路径 | 负 | `fins_sessions_neg_area` |
| T-024 | 非法内存区 → Validate 拒绝 | **负路径：非法内存区** | 负 | `fins_sessions_neg_area`（多会话）/ⅹ（单流同款语义，见 E-01 行） |
| T-025 | 地址越界 → Validate 拒绝 | **负路径：越界** | 负 | `fins_vn_address_over` |
| T-026 | 非法 ICF（bit6/bit0 违规） | **负路径：非法 ICF** | 负 | `fins_vn_icf_cmd`（命令级）/`fins_vn_icf_cfg`（cfg 级） |
| T-027 | 未知命令码拒绝 | 负路径 | 负 | `fins_vn_unknown_cmd` |
| T-028 | DM 位口径非法 | 负路径 | 负 | `fins_vn_dm_bit` |
| T-029 | 元素数 NC=0 | 负路径 | 负 | `fins_vn_items_zero` |
| T-030 | 数据长度与 NC 不匹配 | 负路径 | 负 | `fins_vn_data_len` |
| T-031 | 响应长度缺失 | 负路径 | 负 | 设计行（E-08 planner 报错路径无专用 JSON；`fins_vn_data_len` 覆 E-07 同族） |
| T-032 | BCD 字段越界 | BCD 负路径 | 负 | `fins_vn_clock_bcd` |
| T-033 | GCT 非法（≠2） | 负路径 | 负 | `fins_vn_gct` |
| T-034 | DNA 非法（≠0） | 负路径 | 负 | `fins_vn_dna`（同族 `fins_vn_sna`） |
| T-035 | tshark -d 解码一致性（非 9600） | 框架 | 正 | 立项 D-FINS-1，无 JSON |
| T-036 | FrameAssert：FINS 头起始字节 | 框架 | 正 | 设计行（已分散覆：`fins_hr_read_bit`/`fins_cio_write_bit`/clock 等带 frames 断言） |
| T-037 | FrameAssert：FINS/TCP 头 16B | 框架 | 正 | 设计行（T-002 用 fields 断言 tcp 头，未用 frames；待补） |
| T-038~T-040 | 汇总冒烟/组合大场景 | 集成 | 正 | `fins_combo_tcp_seq`/`fins_combo_sessions_full` |

> **当前 JSON 对账：45 条（25 条正向 + 20 条负向）**。25 条正向 ID：`fins_udp_dm_read`、`fins_tcp_read`、`fins_udp_ipv6_read`、`fins_cio_read_word`、`fins_wr_read_word`、`fins_hr_read_word`、`fins_tc_read_pv`、`fins_ir_read_word`、`fins_hr_read_bit`、`fins_cio_write_bit`、`fins_clock_read_bcd`、`fins_sessions_two`、`fins_sessions_three`、`fins_dm_write_word`、`fins_fill_dm`、`fins_multi_read`、`fins_icf_explicit`、`fins_sid_auto_incr`、`fins_sid_fixed`、`fins_expect_response_false`、`fins_tc_flag_read`、`fins_wr_read_bit`、`fins_down_endcode_1101`、`fins_combo_tcp_seq`、`fins_combo_sessions_full`。20 条负向 ID 及其 `error_contains` 锚词：`fins_sessions_neg_area`（`invalid memory area`）、`fins_vn_address_over`（`address exceeds range`）、`fins_vn_icf_cmd`（`icf response-required bit must be clear`）、`fins_vn_icf_cfg`（`icf request direction bit must be clear`）、`fins_vn_unknown_cmd`（`unsupported command`）、`fins_vn_dm_bit`（`dm does not support bit access`）、`fins_vn_items_zero`（`items must be > 0`）、`fins_vn_data_len`（`data length`）、`fins_vn_clock_bcd`（`clock field out of range`）、`fins_vn_gct`（`invalid gct`）、`fins_vn_dna`（`invalid dna`）、`fins_vn_sna`（`invalid sna`）、`fins_vn_read_areas_empty`（`read_areas`）、`fins_vn_fill_bit`（`fill does not support bit access`）、`fins_vn_transport`（`invalid transport`）、`fins_vn_direction`（`invalid direction`）、`fins_vn_sessions_neg`（`not a numeric value in [0,1000000]`）、`fins_vn_presence`（`top-level fins sub-config`）、`fins_vn_static_copy`（`static four-tuple`）、`fins_vn_fill_data_len`（`fill data must be 2 bytes`）。这些 ID 均已落盘；新增用例时同步本节、本协议 testcase §3 与 §1.3 校验脚本。

> **一致性校验**：遍历 fins.json 的 `id` 集合，逐一在上表 JSON 列匹配；任意 id 缺失/多余即失败（脚本见 `docs/protocols/fins/testcase.md` §1.3）。
## 8. 实现集成点

### 8.1 层注册表（layer registry，参照 enip）

在核心层注册表（`internal/core/layers/registry.go`，文档 18-layer-config-design.md §4.4）登记 fins 层：

```yaml
fins:                    # 终结层
  category: 终结层       # Terminal
  depends_on: [udp]      # 硬依赖：不写传输层时自动补 udp
  optional_on: []        # 无可选底座
  fields:                # 零负载：全部字段可缺省（§5.3 默认值填充）
    transport: udp
    commands:
      - command: 0x0101
        memory_area: dm
        address: 100
        items: 2
    sessions: 1
    sid_auto: true
    icf: auto            # 按方向默认 0x80/0xC0
    gct: 2
    dna: 0
    da1: 0
    da2: 0
    sna: 0
    sa1: 0
    sa2: 0
```

- **DependsOn=["udp"]**：`{"fins": {}}` 补全为 `[ip → udp → fins]`
- **TransportOn=["udp","tcp"]**（18 号设计 §4.4 传输层替代）：用户显式写 `{"fins":{}, "tcp":{}}` → `[ip → tcp → fins]`，planer 由 `fins.transport: tcp` 通知 TCP 层
- category=Terminal 保证一个包内终结层唯一（不能与 http 同链）

### 8.2 配置传递（零负载直传）

- `spec_json` 中 `fins` 的**原始 JSON 整块**经 `spec.FINS`（`json.RawMessage`）直接传给 FINS planner——不做核心层字段级解析（与 enip 的 `spec.ENIP` 同模式）
- 地址与端口只从 `layers[].ip`、`layers[].udp` 或 `layers[].tcp` 读取；FINS 层不得覆盖或补充顶层地址/端口键
- 载体自动选择：`fins.transport` 显式值必须与相邻 `udp`/`tcp` 层一致；缺失时由实际传输层决定，不能从顶层旧键推导

### 8.3 生成器（planner）结构

```
internal/protocol/fins/
├── types.go            // FINSConfig/FINSCommand/FINSClock（§5）
├── plan.go             // Plan(flow) → []PacketConfig（回合展开、SID 递增、响应派生）
├── builder.go          // Build(header) → []byte（10B 头 + 命令码 + 参数 + 数据，大端）
├── validate.go         // Validate(cfg)（§9 E 表）
├── fins_test.go        // 单测（字节级 + 状态机）
└── registry.go         // 层注册（§8.1）
```

### 8.4 SID 与流（flow）级状态

- flow 内保持 `sidCounter uint8`（1..255 回绕），供请求帧自动填充；响应帧 SID = 同回合请求 SID（§4.2）
- sessions>1：planner 为每个 session 生成独立 flow + 独立 sidCounter——**禁止**线程共享全局计数器（多流正确性测试见 T-020/T-021）

### 8.5 UDP / TCP 载体接线点

- UDP：`FrameUDPSend`（无需握手），请求 up → 响应 down 复用同一 4-tuple（swap src/dst）
- TCP：复用 TCP 层握手（handshake=true），数据段依次承载 FINS/TCP PDU（Frame Send）；**不做**额外会话层（§4.1）
- 非 9600 端口时 pcap 框架需 `-d` 提示：cases JSON 的 `decode_as: ["udp.port==非9600,omron", "tcp.port==非9600,omron"]`（见 `docs/protocols/fins/testcase.md` §2）

### 8.6 校验（validate）挂钩

- Validate 在 `internal/protocol/fins/fins.go:37`（`Planner.Validate`），由层校验器经 Metadata 触发（`layer_gen.go:177` `RegisterLayerValidator("fins")`）
- 负路径测试覆盖当前 JSON 的 20 条 `expect_error: true` 用例：`fins_sessions_neg_area`、`fins_vn_address_over`、`fins_vn_icf_cmd`、`fins_vn_icf_cfg`、`fins_vn_unknown_cmd`、`fins_vn_dm_bit`、`fins_vn_items_zero`、`fins_vn_data_len`、`fins_vn_clock_bcd`、`fins_vn_gct`、`fins_vn_dna`、`fins_vn_sna`、`fins_vn_read_areas_empty`、`fins_vn_fill_bit`、`fins_vn_transport`、`fins_vn_direction`、`fins_vn_sessions_neg`、`fins_vn_presence`、`fins_vn_static_copy`、`fins_vn_fill_data_len`；旧 T-024~T-034 是设计编号，不代表当前 JSON 的完整负例集合。

---

## 9. 错误处理

### 9.1 结束码表（响应态错误，设备侧模拟）

服务端（PLC 模拟）遇到非法输入返回 结束码。本设计的 `down` 命令可携带任意结束码（`response_end_code`），下表为首版支持集：

| 结束码 | 主码 | 副码 | 含义 | 对应 E |
|--------|------|------|------|--------|
| 0x0000 | 00 | 00 | 正常完成 | — |
| 0x0001 | 00 | 01 | 服务被中断 | — |
| 0x0401 | 04 | 01 | 使用了未定义的命令 | E-02 |
| 0x1001 | 10 | 01 | 命令超长 | — |
| 0x1101 | 11 | 01 | 内存区码无效（或 DM 不可用） | E-01/E-03 |
| 0x1102 | 11 | 02 | 访问大小错误（元素数非法） | E-05/E-07 |
| 0x1103 | 11 | 03 | 第 1 个地址在不可访问区域 | E-04 |
| 0x2002 | 20 | 02 | 数据被保护 | — |
| 0x2003 | 20 | 03 | 注册表不存在 | E-10 |

> MR（主码）= 高字节（bit15-8）、SR（副码）= 低字节（bit7-0）；"PC 致命错误"位在 bit7、非致命在 bit6（Wireshark `response.code` 子位 —— 仅协议内部信息，本设计不在断言中使用子位）。

### 9.2 校验错误表（E-01 ~ E-10，配置期拒绝）

| 编号 | 错误 | 触发条件 | 判定 |
|------|------|---------|------|
| E-01 | 非法内存区 | `memory_area` 不属于 §2.2 六类（拼写/未知区域名） | Validate 拒绝 |
| E-02 | 未知命令码 | `command` 不在 §3.3 支持集 | Validate 拒绝 |
| E-03 | DM 位口径 | `memory_area=dm` 且配置了 bit/位操作 | Validate 拒绝 |
| E-04 | 地址越界 | `address` 超出该区域允许上限（如 CIO>6143、D>32767 且超 max 含 0）+ 位偏移超 15 | Validate 拒绝 |
| E-05 | 元素数非法 | `items<=0` 或超单次上限（字 960、位 4096） | Validate 拒绝 |
| E-06 | ICF 非法 | 请求 ICF bit6=1（消息类型=响应）或 bit0=1（不期望响应）或 bit7=0；DNA/SNA≠0 | Validate 拒绝 |
| E-07 | 数据长度失配 | `data` 长度 ≠ DC（字 DC=2×NC、位 DC=NC）或 `items`=0 | Validate 拒绝 |
| E-08 | 响应缺失（长度/内容） | 请求 `expect_response=true` 但命令序列总体不足（无 down 派生）；或响应数据长度 ≠ 期望 | planner 报错 → 任务失败 |
| E-09 | BCD 字段越界 | 时钟 BCD 字段含非法半字节（如时>0x23、分/秒>0x59）；SID 本身是普通 1 字节字段，不按 BCD 校验 | Validate 拒绝 |
| E-10 | 0104 组数非法 | `read_areas` 为空或组数>16 | Validate 拒绝 |

> 测试要求：当前 JSON 已有 20 条 `expect_error: true` 负例，且每条 `expect` 仅含 `expect_error` 与 `error_contains` 两个契约键；不得混入 `notes`、`packet_count`、`fields`、`frames` 等成功断言。每条均带准确的 `error_contains` 锚词并验证任务失败；其中 `fins_down_endcode_1101` 是正向配置下的响应错误码例，不计入配置拒绝负例。旧 T-024~T-034 仅作为设计编号保留，不能代替当前 ID 对账。

### 9.3 网络级错误

- UDP 无连接概念：无 ACK/超时语义。请求发出即算成功；响应由模拟端生成（不涉及真实网络等待）
- TCP：由 TCP 层负责握手/重传/终止；FINS 层只在 TCP 已连接的数据段里放 PDU

---

## 10. 扩展字段映射

### 10.1 FINSConfig → FINSCommand 映射

| FINSConfig 字段 | 作用 | 落点 |
|-----------------|------|------|
| transport | 载体选择 | 层链传输层（udp/tcp） |
| sessions | 并行流数 | 每流独立 SID 计数器 |
| sid_auto | SID 自动递增开关 | 命令头 SID |
| icf/gct/dna/da1/da2/sna/sa1/sa2/sid | 头默认 | 每个命令头（被 FINSCommand 同名字段覆盖） |

### 10.2 FINSCommand → FINS 帧字节映射

| FINSCommand | wire 字节（大端） | 备注 |
|-------------|-------------------|------|
| command | 命令码（头后 2B） | 0101/0102/0103/0104/0701 |
| direction=up | ICF bit6=0、需响应 | 自动响应推导（§5.5） |
| direction=down | ICF bit6=1 | 响应帧 |
| memory_area+address+bit | 4B 内存寻址参数 | 区域码表 §2.2 |
| items | NC（2B） | 读写通用 |
| data | DC(2B) + 数据 | 写：01xx 命令；读响应数据 |
| fill_word | DC + 填充数据 | 0103 |
| read_areas | 组数(1B) + 组参数 | 0104 |
| clock | 8B BCD | 0701 响应 |
| response_end_code | 响应前 2B | 取代自动 0x0000 |

### 10.3 SID 与 FINS/TCP 关联

| 配置 | 默认 | wire 语义 |
|------|------|-----------|
| SID | 会话内递增 1..255 回绕 | 头字节 9；响应回显 |
| 显式 SID（sid_auto=false） | — | 用配置值 |
| FINS/TCP length | 自动 = `8 + FINS 帧长`（当前 builder/wire 口径） | 头字节 4-7，`omron.tcp.length` |
| FINS/TCP command | 0x00000002（Frame Send） | 头字节 8-11，`omron.tcp.command` |
| FINS/TCP error_code | 0x00000000 | 头字节 12-15 |

### 10.4 与 18 层配置设计对齐（结账）

| 18 号设计 §4.4 项 | FINS 值 | 说明 |
|------------------|---------|------|
| category | 终结层 | 层链末层 |
| depends_on | [udp] | 默认 udp |
| optional_on | [] | 无 TLS/隧道底座 |
| TransportOn | [udp, tcp] | 传输层替代 |
| 默认端口 | 9600 | 同 TCP/UDP |

---

## 11. 修订记录

| 版本 | 日期 | 内容 |
|------|------|------|
| v1.0.0 | 2026-08-18 | 初稿：11 章完成（概述/数据类型/消息/状态机/配置/HexDump/用例索引/集成/错误/扩展映射/修订） |
| v1.0.1 | 2026-08-19 | 对齐 FINS 三件套：修正 D100 大端示例、45 条实际 JSON 清单、T-011 未落盘状态、零配置默认命令与 BCD/GCT/DNA 负路径边界 |
| v1.1.0 | 2026-09-30 | 层链迁移审计：45 例现状、D1-D8/C1-C6、缺口登记；不改代码 |
| v1.1.1 | 2026-10-01 | 收官补齐：ICF 0x80/0xC0 口径订正（JSON T-001 摘要）、§14 规范矩阵+三张子表、§15 三路对照+候选方案、§16 依赖/错误/重试/超时/性能、§17 八要素、§18 动态清单、§19 门1表、§20 C1-C6；Validate 路径订正（fins.go:37/layer_gen.go:177）；静态闭环声明（未跑 suite/pcap/NIC） |

> 后续修订沿 12-enip-design.md 的审计-补丁循环：先写测试用例驱动字节事实，Wireshark 为最终裁判；凡 tshark 与本节不一致，以 tshark/公开实现为准更新本节并记入上表。

## 12. 层链迁移契约（D1-D8，2026-09-30，2026-10-01 对账）

本次 D 审计按 `/tmp/review-checklist.md` 的 D1–D8 逐项判定：每一条都给出“设计文档内的结论 + 相应的章节或 JSON 证据”，没有只写一句话结论的条目。配套测试审计在 `testcase.md` §11（T1–T6）；cases 侧六项核对在本文 §13（C1–C6）。

| ID | 必查项原文 | 设计结论 | 证据/去向 |
|---|---|---|---|
| D1 | §4 八项＋P1 四列矩阵＋三张子表 | ✅ | §14.1 四列矩阵；§14.2–§14.4 三张子表逐格给出覆盖或缺口 |
| D2 | 三路对照＋候选方案对比 | ✅ | §15 规范/现网证据边界/开源实现三路对照，方案 A/B/C 有取舍 |
| D3 | §5 依赖与错误处理 | ✅ | §16 依赖、失败返回、会话中断、重试与超时均有结论 |
| D4 | §6 性能与 pcap/NIC 双路验收 | ✅（实测待执行） | §16 流式边界、资源指标、pcap/NIC 验收步骤；数字未实测登记 D-FINS-5 |
| D5 | §8 八要素 | ✅ | §17 文件、接口、结构、流程、错误、边界、冲突点、回滚 |
| D6 | §12 动态字段与序号算法 | ✅（未支持格已立项） | §18 四元组/SID/业务字段逐项列出策略、关闭理由和代码位置 |
| D7 | §15 门1三行展开 | ✅ | §19 十四行表及 §19 旧键去向、五件套、动态清单展开 |
| D8 | 无开放留白；无处安置字段立项 | ✅ | D-FINS-1~5 均有编号、证据与后续确认动作；presence 仅为故意判死负例 |

| ID | 结论 | 证据/去向 |
|---|---|---|
| D1 | 地址只住 `layers[].ip`；端口只住 `layers[].udp`/`layers[].tcp`；数量只住用例兄弟键 `strategy_fc` 或策略 `flow_control` | 45 例机读审计；非负例无顶层地址/端口/count |
| D2 | FINS 是终结层，标准链为 `[ip,udp,fins]` 或 `[ip,tcp,fins]`；`fins` 配置住同名层 | `registry`/链规划契约；现有正例全部采用该形 |
| D3 | UDP/TCP 载体由相邻传输层决定，FINS 层不得再声明扁平端口 | 45 例层链；TCP/UDP 例分别在对应层写端口 |
| D4 | `sessions` 是 FINS 业务编排字段，留在 `layers[].fins`；多流封包不从顶层 `count` 推导 | `fins_sessions_*`、`fins_combo_sessions_full` |
| D5 | 顶层 `fins` 子映射仅用于专门 presence 负例，禁止作为正例配置入口 | `fins_vn_presence`（故意判死形状） |
| D6 | `strategy_fc` 是用例驱动器字段，不是 `spec_json` 协议配置；静态复制负例的流控已移至兄弟键 | `fins_vn_static_copy` |
| D7 | 负例必须保留故意违规输入并带 `expect_error`/`error_contains`，不可为迁移而洗成正例 | 20 条负例逐条保留 |
| D8 | 代码尚未支持的行为只登记缺口，不伪造已覆盖；本次不改生成器 | FINS 旧设计中的设计行与下方缺口表 |

### 12.1a D 审计补充（按当前实现与 45 条 JSON 对账）

| D 项 | 当前证据 | 结论 |
|---|---|---|
| D1 命令/响应与数据形态 | §3.3、§3.4–§3.10、§7.1；0101/0102/0103/0104/0701 分别有正例或明确设计行，读/写/位/字/BCD 形态已区分 | 已登记；未落盘的设计行仍不计入验收 |
| D2 三路对照与取舍 | §15 已列 W342、Wireshark、gofins 三路与方案取舍 | 现网抓包仍登记 D-FINS-1 的确认动作 |
| D4 性能与验收 | §16 已列流式边界、指标和 pcap/NIC 双路方法 | 数字与实测按 D-FINS-5 回填 |
| D7 门1形状 | §12.1、§13 C1-C3；正例仅 `[ip,(udp|tcp),fins]`，流控在 case 兄弟 `strategy_fc` | 层链门已闭合；旧键去向仍以 §12.1 为准 |

动态字段实现位置：`trafficgen/internal/protocol/fins/layer_gen.go` 的 `emitSessionCommands` 负责每会话 SID/源端口与请求-响应配对；`trafficgen/internal/protocol/fins/fins.go` 的 `wrapTCP` 负责 TCP length。文档中的动态断言只覆盖可观察结果，不把调度顺序写成契约。

### 12.1b 迁移前后形状

正例目标形状：

```json
{"layers":[{"ip":{"src":"10.0.0.1","dst":"20.0.0.1"}},
 {"udp":{"src_port":1234,"dst_port":9600}},
 {"fins":{"transport":"udp","commands":[{"command":257,"memory_area":"dm","address":100,"items":1}]}}]}
```

`fins_vn_presence` 的顶层 `fins:{}` 与 `fins_vn_static_copy` 的兄弟 `strategy_fc` 是负例/驱动器专用形状，不代表业务正例契约。

### 12.2 D-缺口与迁入计划

- D-FINS-1：非 9600 端口的 `decode_as` 尚无落盘例；确认套件支持后补正例，并以真实 pcap/tshark 校准。
- D-FINS-2：结束码长尾 × 命令矩阵尚未全落盘；补 `direction:down` 响应例，禁止用设计行冒充验收。
- D-FINS-3：FINS/TCP 异常结束与长保活需真实 pcap；补 TCP 载体场景或记录载体层不承诺的边界。
- D-FINS-4：非 CS1 方言与参数区/程序区命令不在首版字段合同；若需求进入，先扩 registry/Validate，再补层链用例。
- D-FINS-5：吞吐、并发、内存、队列、CPU 的目标数字尚未实测；按 §16 的 pcap/NIC 双路计划执行后回填。

以上每项均是有编号的迁入或实证计划，不是开放留白；当前只声称 JSON 机读闭环，不声称真实 suite/pcap/NIC 已通过。

## 14. 规范要求矩阵（§4 八项 + 三张 P1 子表）

> 状态：本协议静态闭环（文档与 JSON 机读对账全绿），尚未跑真实 suite/pcap/NIC 验证。凡写"已覆盖"均指"JSON 已有对应例"，不冒充已跑通。

### 14.1 W342-E1 基础规范要求矩阵（8 行）

| 规范要求 | 业务场景 | 代码现状 | 缺口 |
|---|---|---|---|
| 连接模型：无会话、UDP/TCP 双载体、TCP 直接 Frame Send（§4.1/§4.2） | `fins_udp_dm_read`、`fins_tcp_read`、`fins_combo_tcp_seq` | `layer_gen.go:51` 按 transport 逐 session 发射；`fins.go:390` 封装 TCP 头 | 非 9600 decode-as 需真实套件确认（D-FINS-1） |
| 命令集：0101/0102 主 + 0103/0104 强化 + 0701 辅助（§3.3） | `fins_udp_dm_read`、`fins_dm_write_word`、`fins_fill_dm`、`fins_multi_read`、`fins_clock_read_bcd` | `fins.go:252` 展开命令回合并派生 down 响应 | 未落盘的响应码×命令格见 §14.2（D-FINS-2） |
| 状态机：每请求一回合、SID 递增、多会话独立计数（§4.3/§4.4） | `fins_sid_auto_incr`、`fins_sessions_two`、`fins_combo_sessions_full` | `layer_gen.go:51-121` 每 session 独立计数器，响应回显 SID | TCP 异常结束/长保活需真实 pcap（D-FINS-3） |
| 字段表：10 字节头、六类内存区、全大端、FINS/TCP 16 字节头（§2） | `fins_cio_read_word`、`fins_hr_read_bit`、`fins_tcp_read`、`fins_clock_read_bcd` | `fins.go:390` 按大端编码；`types.go` 定义字段 | 非 CS1 方言登记 D-FINS-4 |
| 错误处理：配置错误拒绝；响应可携带结束码（§9） | 20 个 `expect_error` 例；`fins_down_endcode_1101` | `fins.go:37` Validate；`response_end_code` 生成响应错误 | 结束码长尾未逐命令落盘，见 §14.2 |
| 超时与活性：UDP 无连接确认；TCP 由载体处理重传/终止（§4.6） | `fins_expect_response_false`、`fins_tcp_read` | FINS planner 只生成业务 PDU；TCP 层负责握手/挥手 | FINS 应用级长保活需 D-FINS-3 真实验证 |
| NAT/代理/被动：UDP 请求/响应方向镜像；不另造 FINS NAT 字段（§4.5） | `fins_udp_dm_read`、`fins_udp_ipv6_read`、`fins_sessions_two` | `chain_planner.go:1029` 默认 9600；载体层换向 | 非 9600 decode-as 需 D-FINS-1 |
| 版本/方言：IPv4/IPv6 载荷一致；CS1 内存区码口径（§2.2） | `fins_udp_ipv6_read`、六区读写族 | FINS frame builder 共用；IP 版本由层链承载 | 非 CS1 扩展登记 D-FINS-4 |

### 14.2 子表①：命令×响应码矩阵

| 命令 | 0x0000 | 0x1101 | 0x1103 | 0x0401 |
|---|---|---|---|---|
| 0101 读 | 覆（T-001） | 覆（`fins_down_endcode_1101`） | 未覆盖（设计行，无 JSON） | 未覆盖 |
| 0102 写 | 覆（`fins_dm_write_word`） | 未覆盖 | 未覆盖 | 未覆盖 |
| 0103 填充 | 覆（`fins_fill_dm`） | 未覆盖 | 未覆盖 | 未覆盖 |
| 0104 多区读 | 覆（`fins_multi_read`） | 未覆盖 | 未覆盖 | 未覆盖 |
| 0701 时钟 | 覆（FrameAssert，`fins_clock_read_bcd`） | 未覆盖 | 不适用 | 未覆盖 |

> 结束码 0x1102/0x0001/0x1001/0x2002/0x2003 无 JSON 例（§9.1 全表在此登记，不冒充覆盖）。

### 14.3 子表②：数据形态变体表

| 形态 | 用例 | 状态 |
|---|---|---|
| 字读（6 区全区码） | `fins_cio_read_word`/`fins_wr_read_word`/`fins_hr_read_word`/`fins_tc_read_pv`/`fins_ir_read_word`/`fins_udp_dm_read` + `fins_tc_flag_read`（0x09）+ `fins_wr_read_bit`（0x31） | 覆 |
| 位读 | `fins_hr_read_bit` | 覆 |
| 位写 | `fins_cio_write_bit` | 覆 |
| 字写 | `fins_dm_write_word` | 覆 |
| 填充（无 DC） | `fins_fill_dm` | 覆 |
| 多区读（组参数） | `fins_multi_read` | 覆 |
| BCD（时钟 7 字节） | `fins_clock_read_bcd` | 覆 |
| 大端字数据 | `fins_dm_write_word`（`11 22 33 44`） | 覆 |

### 14.4 子表③：商业行为→用例映射表

| # | 商业行为（出处） | 用例 | 结论 |
|---|---|---|---|
| 1 | 上位机读 DM（gofins driver.go 读路径） | `fins_udp_dm_read` | 已覆（JSON 有例；未跑 suite） |
| 2 | 上位机写字（gofins 写路径） | `fins_dm_write_word` | 已覆（JSON 有例；未跑 suite） |
| 3 | FINS/TCP 上位机（Wireshark Frame Send 解析） | `fins_tcp_read`、`fins_combo_tcp_seq` | 已覆（JSON 有例；未跑 suite） |
| 4 | 多会话并发（SCADA 多 PLC 轮询） | `fins_sessions_two`/`fins_sessions_three`/`fins_combo_sessions_full` | 已覆（JSON 有例；未跑 suite） |
| 5 | 错误码诊断（PLC 返回 0x1101） | `fins_down_endcode_1101` | 已覆（JSON 有例；未跑 suite） |
| 6 | 时钟同步（0701） | `fins_clock_read_bcd` | 已覆（JSON 有例；未跑 suite） |
| 7 | 真实现网抓包对照 | — | 待确认（无现网包；确认方式：抓现网 FINS 包对照 §6 S1–S10） |

## 15. 三路对照与候选方案对比

三路：①**规范原文**（欧姆龙 W342-E1 系手册：命令码/内存区码/结束码表，定"必须是什么"）；②**商业化软件实际行为**（SCADA 上位机行为——**未达验证级**，见 §14.4 #7 待确认；间接证据 = Wireshark `packet-omron-fins.c` 对 9600/`omron.*` 字段的解析行为）；③**可靠开源实现思路**（`l1va/gofins` header.go/driver.go/memory_area.go/end_code.go，只借鉴字节布局与 SID 回显语义）。三路交叉一致点：10 字节命令头 + 全大端 + 请求 ICF=0x80/响应 ICF=0xC0 + SID 回显 + DM 字码 0x82。分歧点：Wireshark 对 0x0701 响应不解析结束码（§3.10 注）——取舍：clock 用例响应断言一律用 FrameAssert，不用 `omron.response.*`。

| 方案 | 走法（借鉴来源） | 取舍 | 结论 |
|---|---|---|---|
| A | 独立 `fins` 终结层 + 层 config 直存 Metadata（本版；`chain_planner_translate.go:3061` `case "fins"`） | 命令集/ICF/SID/多会话全可声明可断言；代价 = 一个终结层 + carrier 门（`chain_planner.go:611`） | **采用** |
| B | 复用 `udp`/`tcp` 层 + 顶层 fins 载荷注入字节 | 无命令级校验（E-01~E-10）、无 SID 递增、无响应推导 → 20 负例不可表达 | **否决** |
| C | FINS/TCP 与 FINS/UDP 分两层 | 两载体共享 10 字节头与全部命令语义，分层只会复制 Validate/BuildFrame | **否决** |

## 16. 依赖 / 错误 / 重试 / 超时 / 性能

- **依赖**：硬依赖传输层（registry `DependsOn: ["udp"]`，`TransportOn: ["udp","tcp"]，registry.go:1427`）；FINS/TCP 载体与 `fins.transport` 值必须一致，否则 carrier 门拒绝（`chain_planner.go:611`：`fins chain: %s carrier requires fins transport`）；缺省端口 9600 经通用默认门补齐（`chain_planner.go:1029` `case "fins"`）。
- **错误处理**：配置期全部同步拒绝（E-01~E-10，§9.2，错误文案见 `fins.go:37` Validate）；响应态错误码经 `direction: down` + `response_end_code` 构造（§9.1）。
- **重试**：FINS 本身不定义自动重试；UDP 无连接确认，TCP 重传/终止由 TCP 层处理。planner 按命令顺序逐回合生成；配置或生成错误立即返回 task error，中断该流，不静默产 0 包。
- **超时**：FINS 应用层不定义空闲超时/保活；TCP 的连接超时由 TCP 层决定。长保活需要真实 TCP pcap，已登记 D-FINS-3。
- **性能设计与验收**：逐会话流式 emit（`layer_gen.go:51` 按 session 循环，无全量收集）；每流独立 SID 计数器、无跨流共享锁（§8.4）；UDP 载体每命令 2 包、TCP 载体每流 7 包固定开销 + 每命令 2 包（§6 S2）。**吞吐/并发/内存/队列/CPU 目标数字与 pcap、网卡两路实测均缺失**——不写承诺，缺口登记 D-FINS-5。

### 16.1 性能指标与双路验收

| 维度 | 当前可核实事实 | 验收口径 |
|---|---|---|
| 吞吐 | 逐包/逐会话流式 emit，无全量收集；目标数字待实测（D-FINS-5） | pcap：统计包数、字节数、持续时间并核对 UDP/TCP 载荷；NIC：tcpdump 同字段核对实际线速，差异登记丢包 |
| 并发 | `sessions` 每流独立 SID 状态，无跨流共享计数器（`layer_gen.go:51-121`） | pcap：按四元组分组核对每流 SID 1..N；NIC：按四元组核对流数、交错和丢包 |
| 内存 | planner 不聚合历史包；单包内存随 payload 大小增长，预算待实测 | pcap 路记录进程 RSS 与队列峰值；NIC 路同样记录 RSS、队列积压和丢包 |
| 队列 | 传输层负责下游发送；FINS 生成器逐事件交付 | 两路都记录生成/写出队列峰值；出现背压或失败即不通过 |
| CPU | 无本协议专用锁；CPU 数字待实测 | 固定 sessions/commands，分别测 pcap 与 NIC 的 CPU 峰值和平均值 |

六类性能场景必须覆盖：基线、目标规模、压力上限、长时间运行、并发交错、资源耗尽/背压。未执行前只登记方法，不把数字写成通过结论。

| 要素 | 内容 |
|---|---|
| 改哪几个文件 | `trafficgen/internal/protocol/fins/{types,fins,layer_gen}.go` + 接线 3 处（`registry.go:1427` 注册 / `chain_planner_translate.go:3061` 翻译 / `chain_planner.go:611,1029` carrier 门与端口默认） |
| 接口签名 | `Validate(spec core.FlowSpec) error`（`fins.go:37`）+ `Plan(ctx, spec)`（`fins.go:210` legacy）+ `Generate(ctx, req)`（`layer_gen.go:16`）+ `BuildFrameWithConfig(cfg, cmd, response, sid)`（`fins.go:390`） |
| 数据结构 | `FINSConfig`/`FINSCommand`/`FINSReadArea`/`FINSClock`（`types.go:21`，`sid_auto`/`BitSet` 经 UnmarshalJSON 键存在性派生） |
| 主流程 | 层 config → Metadata → Validate → Generate 逐 session emit（`layer_gen.go:51`）→ udp/tcp 层 → writer；legacy 路径 Plan 逐包 emit（`fins.go:252` planSession） |
| 错误分支 | Validate 同步拒绝（E-01~E-10）；carrier 门拒绝载体不一致；`BuildFrameWithConfig` 报非法区码/未知命令（`fins.go:477`） |
| 性能边界 | 见 §16（流式、无共享锁；数字待实测，D-FINS-5） |
| 与现有逻辑的冲突点 | 空层 `{}` 翻译出非 nil 空配置 → 生成器缺省化产默认 DM 读（P0b-2，`layer_gen.go:144`）；既有 Metadata 不被空层覆盖（`chain_planner_translate.go:3072`） |
| 回滚方式 | revert 本协议 3 文件 + 接线 3 处；cases 无需回滚 |

## 18. 动态字段清单 + 序号算法

| 字段 | 动态策略 | 序号算法代码位置 |
|---|---|---|
| `src_port`（udp/tcp 层） | 未开动态对象；多会话时按 session 偏移（legacy `spec.SrcPort+session`，`fins.go:254`；层链 `base+i`，`layer_gen.go:58`） | `fins.go:254` / `layer_gen.go:58` |
| `sid` | 未开 five-strategy 动态对象；按会话内计数器递增 1..255 回绕（`sid++`，0 跳过，`layer_gen.go:121`） | `fins.go:354` / `layer_gen.go:120` |
| `src_ip`/`dst_ip` 业务字段 | 未开动态对象（静态值沿用；§12.11 值的算法住层链） | —（缺口：动态整格未覆盖，testcase §11 T3 已声明） |
| 显式 `sid`/`sid_auto=false` | 固定值（`fins_sid_fixed` 双命令恒 07） | `layer_gen.go:82`（`command.SID != 0` 用配置值） |

> 动态整格（§9.32–9.36）未覆盖：fins 层业务字段今日不支持 fixed/inc/rand/list/pattern 动态写法——如实登记，不冒充。

## 19. 门 1 §1–§14 十四行对照表

| § | 本协议怎么满足 | 证据 |
|---|---|---|
| §1 层链唯一真相 | 25 正例 `spec_json` 顶层仅 `layers`；地址住 `ip` 层、端口住 `udp`/`tcp` 层、业务住 `fins` 层；流控在 case 兄弟键 `strategy_fc`；顶层 `fins` 子映射仅 `fins_vn_presence`（故意判死） | §12.1 D1–D8 + §13 C1；45 例机读审计（本轮） |
| §2 策略/任务 | 策略 = 单 fins 流量模板（`commands[]` 有序回合序列），自带 `flow_control`；任务 = 多策略合跑封顶；框架语义未动 | §5/§8 设计 |
| §3 五件套 | **豁免 sessions[] 不等于豁免多流覆盖**：sessions=2/3 真并发例 + 组合大场景（TCP 3 动作 / UDP 双会话位写+全键头+错误码） | `fins_sessions_two`/`fins_sessions_three`/`fins_combo_tcp_seq`/`fins_combo_sessions_full`；§4.4 |
| §4 查规范 | W342-E1 系 + Wireshark + gofins；八项矩阵 §14.1 + 子表①②③ §14.2–14.4 | §1.5/§2.2/§14 |
| §5 依赖与错误 | carrier 门 + E-01~E-10 + 网络错误语义；失败返回文案、会话中断（planSession 遇错停） | §16/§9/`fins.go:37` |
| §6 性能 | 性能设计见 §16；数字与两路实测缺失 → D-FINS-5，不写承诺 | §16 |
| §7 三份文档 | 本 design.md + `testcase.md` + CORE_MEMORY；旧 19-* 为历史层 | 修订记录 |
| §8 设计先行 | 本轮只改三文件（§17 八要素逆向定稿）；不改实现 | §17 |
| §9 测试三源 | 三源 = W342/设计/实现行为（现网抓包待确认 §14.4 #7）；45 ID 逐项回指 §7.1/§14；存量去向 testcase §3.2 | `testcase.md` §3/§8 |
| §10 评审闭环 | 本轮自审 2 轮（结论见报告）；未跑 suite/Go test（任务禁令），如实声明 | 报告 |
| §11 白话 | 一句话：FINS 文档与用例形状已对齐现状，数字全经机读核过，还没真跑验证 | 报告 |
| §12 动态清单 | §18 清单 + 算法行号；动态整格未覆盖如实登记 | §18 |
| §13 schema 派生 | `fins` 已在 registry 注册（`registry.go:1427`）；改 Fields 须重跑 schemagen（本轮未改 Fields） | §8.1 |
| §14 真实流程 | 45 例 spec 即策略 config（可直接建策略建任务）；**未执行**真实流程（任务禁令禁跑 suite/server），pcap 落盘与 tshark 校对均待补 | testcase §10 |

### 旧键去向表（§15.3 三行强制展开之 §1 行）

| 旧键 | 去向 | 今日状态 |
|---|---|---|
| `src_ip`/`dst_ip` | `layers[].ip.src`/`dst` | 已迁（25 正例全在 `ip` 层；机读证实顶层残留 0） |
| `src_port`/`dst_port` | `layers[].udp`/`tcp.src_port`/`dst_port` | 已迁（机读证实） |
| `count` | case 兄弟键 `strategy_fc` / 策略 `flow_control` | 已迁（`fins_vn_static_copy` 示范兄弟键形状） |
| 顶层 `fins` 子映射 | `layers[].fins` | 已迁；顶层残留仅 presence 负例 1 处（故意） |

## 20. 六项审查清单（C1-C6）

| ID | 审查结论 | 证据 |
|---|---|---|
| C1 | 顶层键白名单 | ✅ 25 正例 `spec_json` 顶层仅 `layers` | 本轮 45 例机读扫描 |
| C2 | 层链形状 | ✅ 正例地址在 `ip`、端口在 `udp`/`tcp`、业务在终结 `fins`；25 正例均 `[ip,(udp\|tcp),fins]` | §12.1 |
| C3 | 空壳登记 | ✅ 顶层 presence 负例 `fins_vn_presence` 已登记，不伪装为正例 | §12 D5/D8 |
| C4 | 负例契约 | ✅ 20 例 `expect` 恰为 `{expect_error, error_contains}`，无第三键 | 本轮机读（形状计数 20/20） |
| C5 | 存量去向 | ✅ 多会话/多命令/TCP 组合例均有 JSON ID；未落盘设计行明确标注 | §7.1、testcase §3.2 |
| C6 | spec-mapping 对账 | ⏳备注：无独立 `fins-spec-mapping.md`；以本文 §7.1/§14 与 testcase §3.3 为映射证据，不据此宣称 suite 通过 | mapping 缺失为备注，非实现缺口 |

## 13. 六项审查清单（C1-C6）

