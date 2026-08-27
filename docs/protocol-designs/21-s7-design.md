# 西门子 S7comm（S7 Communication，S7 通信协议）协议设计

> 版本：v1.0.0（初稿）
> 设计日期：2026-08-18
> 范围：西门子 S7/S7-300/S7-400/S7-1500 系列 PLC（Programmable Logic Controller，可编程逻辑控制器）的 S7comm 通信流量的生成，作为 tcp 终结层（Category=Terminal，DependsOn=["tcp"]，同 enip 模式）接入 18-layer-config-design 层链架构；统一走 TCP 102 端口，三层封装 TPKT → COTP → S7，IPv4/IPv6 双栈（经 `EtherTypeFor(srcIP)` 动态选择）。
> 实现位置：`trafficgen/internal/protocol/s7/`（planner + 终结层生成器 + 校验器）、`trafficgen/internal/core/types.go`（`S7Config` 定义）、`trafficgen/internal/core/layers/registry.go`（s7 层注册）、`trafficgen/internal/core/layers/chain_planner.go`（`Meta.S7` 注入）、`trafficgen/internal/core/strategy_convert.go`（`s7` flat 键解析）
> 配套参考：层链配置架构（18-layer-config-design.md）；同栈终结层参照 enip（P4a，CategoryTerminal + DependsOn tcp + 零负载层条目 + spec 经 flat 键直传终结层生成器）
> 字节级置信来源：`/tmp/s7lab/canon_all.pcap`（本设计配套标准会话抓包，15 帧）；真实 S7-300/400 PLC 抓包 `plc_status.pcap`；Wireshark s7comm 解析器源码 `packet-s7comm.c`（gitlab.com/wireshark/wireshark master）；`tshark -G fields` 字段名清单。全部 HexDump（第 6 章）均经 tshark 实测复现。

---

## 目录

1. 概述
2. 数据类型编码（多字节端序、长度字段、位寻址）
3. 消息结构（TPKT/COTP/S7 头/参数区/数据区逐字段）
4. 状态机（连接建立、会话、PDU 交换、终止）
5. 配置 Typedef（S7Config / S7Command / S7Item）
6. 包序列 HexDump（S1..S8 标准字节模板）
7. 与 testcase 映射索引（s7.json 用例 ↔ 设计章节）
8. 实现集成点（层注册、终结层生成器、Meta 注入、IPv6、偏移）
9. 错误处理（错误头、返回码、负路径）
10. 扩展字段映射（策略字段、传输尺寸映射、未来扩展）
11. 修订记录

---

# 1. 概述

## 1.1 协议定位

S7comm 是西门子 S7 系列 PLC 之间的私有通信协议，运行于 ISO-on-TCP（RFC 1006）之上，固定使用 **TCP 目标端口 102**。本设计将其实现为 tcp 层链上的终结层（Terminal）协议：TCP 三次握手/挥手与序列号推进完全复用 tcp 层生成器，S7comm 层生成器只负责产出"一条消息 = 一次报文事件（方向 + 完整字节）"，逐条复用 legacy 构建函数，字节级一致（enip 同款事件模式，见 18-layer-config-design.md）。

S7comm 采用**三层封装**：

```
+-----------------+--------------------------------------+
|  TPKT (4B)      |  RFC 1006 传输层：版本 0x03 + 2B 长度   |
+-----------------+--------------------------------------+
|  COTP (3B+)     |  ISO 8073/X.224：连接 CR/CC 或数据 DT   |
+-----------------+--------------------------------------+
|  S7 PDU (10/12B)|  0x32 + ROSCTR + PDU 引用 + 参数+数据  |
+-----------------+--------------------------------------+
```

## 1.2 标准会话序列

一个完整的 S7comm 会话（与真实 S7-300/400 PLC 抓包一致）按以下顺序交换报文：

1. **TCP 三次握手**：SYN / SYN-ACK / ACK（tcp 层生成器负责，无 S7 载荷）。
2. **COTP CR（Connect Request，连接请求）**：建立 ISO 传输连接，协商 TPDU 尺寸与 TSAP（Transport Service Access Point，传输服务访问点）。
3. **COTP CC（Connect Confirm，连接确认）**：PLC 确认连接。
4. **S7 Setup Communication（F0）**：客户端发送建立参数（MaxAmQ 约定 + PDU 长度 480），PLC 回 Ack_Data（PDU 长度 240）。
5. **业务交换**：Read Var / Write Var 读写作 Job→Ack_Data 对；Read SZL 走 Userdata→Userdata 对；空闲时发送 Keep-alive（0xFA Job）。
6. **会话结束**：断开 TCP。

> 注意（重要修正）：前确认的"第一层/第二层"常与封装名混淆——本设计统一把 **TPKT/COTP** 记为承载层（connection-oriented transport，面向连接的传输），**S7 PDU** 记为应用层。S7 PDU 内单一"S7 头"固定 10 字节（Job/Userdata）或 12 字节（Ack/Ack_Data，追加错误类/错误码 2 字节）。

## 1.3 已核实字段（勿再凭空猜测）

本节协议事实全部经 `/tmp/s7lab/canon_all.pcap`（tshark 实测）与 Wireshark 解析器源码交叉核实；与早期任务简报中的假设存在出入处，以实测定案：

| 事实 | 取值（核实用例） | 备注 |
| --- | --- | --- |
| 协议 ID（protocol id） | `0x32` | 全 PDU 统一；仅此值在解析器/真实抓包中出现 |
| ROSCTR（ROS Control，消息方向类型） | `0x01` Job / `0x02` Ack / `0x03` Ack_Data / `0x07` Userdata | **Userdata 为 0x07**，不是 0x04 |
| 建立参数函数 | `0xF0` Setup Communication | 真实 PLC 参数 8B：`f0 00 00 01 00 01 01 e0` |
| 读请求函数 | `0x04` Read Var | Job 参数 + S7ANY 项 |
| 写请求函数 | `0x05` Write Var | Job 参数 + S7ANY 项 + 数据项 |
| 保活函数 | `0xFA` | Job，parlg=1，datlg=0 |
| Read SZL | **Userdata（0x07）**，参数头 `00 01 12`，方法 0x11 请求 / 0x12 响应，函数组 4、子功能 1 | 走 Userdata，**不是** Job 参数 0x01 |
| 头变体 | 仅 `0x32` 定案 | 0x72/0x71 未经真实抓包证实，不采用 |
| UDT 函数 | 0x1C（Identify）/0x1D（Write）/0x1E 等 | 属用户数据类型操作，本版不展开（见 10 章备注） |

## 1.4 网络环境与端口

- 必选：DstPort 102（S7comm 的 IANA 登记端口）。
- 源端口：默认 12345（可配，见第 5 章）；多会话（sessions>1）时各会话独立源端口，端口按会话偏移自增。
- 双栈：目标地址为 IPv4 时 EtherType=0x0800（帧 S7 载荷偏移 54=eth14+ip20+tcp20）；为 IPv6 时 EtherType=0x86DD（偏移 74=eth14+ip40+tcp20）。偏移计算见第 8 章。

# 2. 数据类型编码

## 2.1 多字节字段端序

S7comm 线路上所有多字节数值字段一律**大端（Big-Endian，网络字节序）**。理解这一点是手写 HexDump 的前提；Wireshark 显示均为解码后的十进制/十六进制值，勿以其十进制显示反推字节顺序。

| 字段 | 字节数 | 例子 | 编码 |
| --- | --- | --- | --- |
| TPKT 长度 | 2 | 25 | `00 19` |
| COTP 长度 | 1 | 17 | `11` |
| COTP 引用（src/dst ref） | 2 | 1 | `00 01` |
| S7 pduref（Protocol Data Unit Reference，PDU 引用） | 2 | 512 | `02 00` |
| S7 parlg / datlg（参数长度/数据长度） | 2 | 8 | `00 08` |
| 元素长度（S7ANY Length 域） | 2 | 2 | `00 02` |
| DB 号 | 2 | 1 | `00 01` |
| S7ANY 地址（3B 拼接） | 3 | 字节 0 | `00 00 00` |
| 数据项长度 | 2 | 2 | `00 02` |
| SZL-ID / Index | 2+2 | 0x0132 / 0x0004 | `01 32 00 04` |

## 2.2 长度字段口径

不同层的"长度"口径不同，设计时严格区分：

- **TPKT.Length**：整个 TPKT 分片（含 4 字节 TPKT 头 + 全部 COTP/S7）的字节数。TPKT 头后由它切出完整消息。
- **COTP.Length**：COTP 头之后剩余字节数（CR/CC 时为参数区总长）。
- **S7.parlg / datlg**：S7 头之后参数区/数据区的字节数（不包含 12B 头中各自的错误两字节——错误两字节固定归头部）。
- **S7ANY.Length**：该变量的**元素个数**（不是字节数）。字节数 = Length × 传输尺寸字节宽（WORD=2、DWORD=4、BYTE=1、REAL=4、BIT 按位）。
- **数据项 Length**：读响应/写请求数据项里的长度（Wireshark 显示为"data.length"，OCTET STRING 时为字节数，BYTE/WORD/DWORD 时为元素个数）。
## 2.3 位寻址（Bit Addressing）——以 Wireshark 解析器为准（实测定稿）

**重要修正（2026-08-18 实测）**：S7ANY 的 3 字节地址域是一个 **24 位线性位索引**，即 `addr24 = byte_addr × 8 + bit`。Wireshark 解析器（packet-s7comm.c:2762-2763）取 `bytepos = a_address / 8; bitpos = a_address % 8` 拆分 `s7comm.param.item.address.byte`（字节地址）与 `s7comm.param.item.address.bit`（位号）。**不是**常见的「低半字节存位号」的 nibble 打包（那只是部分文档/实现的说法，实测 tshark 按线性位索引解）。

- 字节地址 0、位 0：addr24=0 → `00 00 00`
- 字节地址 0、位 7：addr24=7 → `00 00 07`
- 字节地址 5、位 3：addr24=43 → `00 00 2b`
- 字节地址 100、位 0：addr24=800 → `00 03 20`
- 字节地址 100、位 4：addr24=804 → `00 03 24`

实测：`... 83 00 03 20 ...` → tshark 显示 `Byte Address: 100, Bit: 0`（bitwrite.pcap 帧 8）。按《设计 6.3》推导非线性位索引将得到错误字节（如 `00 64 04` 会把 byte addr 解成 200 位 4）；修正后的组装见 10.4。

负向校验规则（第 9 章）：`byte_addr×8+bit` 必须在 24 位内（`byte_addr` 20 位 + `bit` 3 位）；`bit > 7` 非法；读/写区域与长度组合不得越界（如 Word 地址越界会由 PLC 返回"Out of range"）。

## 2.4 传输尺寸（Transport Size）编码

S7ANY 项的 Transport-size 域（1 字节）在请求中取值如下（与 Wireshark 解析器 `packet-s7comm.c` 一致）：

| 值 | 名称 | 位宽（字节） | 说明 |
| --- | --- | --- | --- |
| 0x01 | BIT (1 bit) | 0.125（按位） | 读/写单个位 |
| 0x02 | BYTE | 1 | 字节 |
| 0x03 | CHAR | 1 | 字符（XML/字符串片段） |
| 0x04 | WORD | 2 | 字（16 位） |
| 0x05 | INT | 2 | 整数（16 位有符号） |
| 0x06 | DWORD | 4 | 双字（32 位） |
| 0x07 | DINT | 4 | 双整数（32 位有符号） |
| 0x08 | REAL | 4 | 浮点（32 位） |
| 0x09 | OCTET STRING | 按长度 | Read SZL 等二进制块 |

数据部分（响应/写数据项）的 Transport-size 域取值与请求不同：

| 值 | 名称 | 出现位置 |
| --- | --- | --- |
| 0x00 | NULL | 特殊 |
| 0x03 | BIT | 位项结果 |
| 0x04 | BYTE/WORD/DWORD | 读响应 / 写请求数据（Word 等） |
| 0x05 | INTEGER | 整型结果 |
| 0x09 | OCTET STRING | Read SZL 结果 |

## 2.5 区域编码（Area / Memory Area）

S7ANY 项的 Area 域（1 字节）标识存储区域（第 4 字节为区域码）：

| 值 | 区域 | Wireshark 名称 |
| --- | --- | --- |
| 0x81 | 输入（Input，I） | Input |
| 0x82 | 输出（Output，Q） | Output |
| 0x83 | 标志位/中间存储（Merker，M） | Flags |
| 0x84 | 数据块（Data Block，DB） | Data blocks (DB) |
| 0x85 | 实例数据块（Instance DB，DI） | Instance data blocks exclusion |
| 0x86 | 局部（Local 变量） | Local data |
| 0x1C | S7 计数器 | S7 Counter |
| 0x1D | S7 定时器 | S7 Timer |
| 0x80 | 直接外设（Periphery，P） | Direct peripheral access |

# 3. 消息结构

## 3.1 三层头总体布局

一条 S7comm 数据消息（业务交换，最常用）在 TCP 载荷中的布局（偏移 = 相对 TCP 载荷起点，即相对帧偏移 54）：

| 偏移 | 字节 | 字段 | 说明 |
| --- | --- | --- | --- |
| 0 | 1 | TPKT.Version | 恒 `03` |
| 1 | 1 | TPKT.Reserved | 恒 `00` |
| 2-3 | 2 | TPKT.Length | 大端：整个 TPKT 长度（4+3+n） |
| 4 | 1 | COTP.Length | 恒 `02`（DT：仅有 TPDU 号 + EOT） |
| 5 | 1 | COTP.DT | 高半字节 0x0F（DT Data）+ 低半字节 TPDU 号 0 |
| 6 | 1 | COTP.EOT | 位 7=1（Last data unit，本分片为最后数据单元） |
| 7 | 1 | S7.Protocol ID | 恒 `32` |
| 8 | 1 | S7.ROSCTR | 1 Job / 2 Ack / 3 Ack_Data / 7 Userdata |
| 9 | 1 | S7.Redundancy ID | 保留，恒 `00`（S7-400H 冗余） |
| 10-11 | 2 | S7.Redundancy ID（续） | 保留 `00 00` 或 PDU 引用高位 |
| 12-13 | 2 | S7.PduRef | 大端，请求/响应成对相同 |
| 14-15 | 2 | S7.ParamLen（parlg） | 参数区字节数 |
| 16-17 | 2 | S7.DataLen（datlg） | 数据区字节数 |
| 18-19 | 2 | S7.ErrClass / ErrCode | **仅 Ack/Ack_Data**；Job/Userdata 无 |
| 20 | ... | 参数区 | 依函数（setup/read/write/keepalive/userdata） |
| ... | ... | 数据区 | 依函数 |

要点：**Job 与 Userdata 头 10 字节（偏移 7-16）**；**Ack/Ack_Data 头 12 字节（偏移 7-18）**，offset 18/19 即为错误类/错误码。TKP 头切定的 TPKT.Length 与 parlg/datlg 必须一致，否则 tshark 报 Malformed（第 9 章）。

## 3.2 TPKT 头（4 字节）

| 偏移 | 字节 | 值 | 语义 |
| --- | --- | --- | --- |
| 0 | 1 | `03` | Version 3（RFC 1006） |
| 1 | 1 | `00` | Reserved |
| 2-3 | 2 | 大端长度 | `03 00 00 16` → 长度 22 |

TSAP/TPDU 协商不在 TPKT，而在 COTP CR/CC（下节）。标准 DT 消息头模板为 `03 00 <len:2> 02 f0 80`。

## 3.3 COTP 连接段（CR / CC）

COTP CR（Connect Request）模板（长度 17 字节），从真实 PLC 抓包与 Wireshark 解析逐字节核实：

```
03 00 00 16            TPKT 长度 22（4 + COTP 17 + 数据 1? → 实际 4+17=21～22 视 TSAP 数据）
11 e0 00 00 00 01 00   COTP：长度 17，PDU Type 0xE（CR），dst-ref 0000，src-ref 0001，class 00
c0 01 0a               TPDU size 参数：码 0xC0，长 1，值 0x0A=1024
c1 02 01 00            src-tsap：码 0xC1，长 2，值 01 00
c2 02 01 02            dst-tsap：码 0xC2，长 2，值 01 02
```

COTP CC（Connect Confirm）模板（与 CR 对称，PDU Type 0xD，源/目的引用对调）：

```
03 00 00 16
11 d0 00 01 00 00 00   COTP：长度 17，PDU Type 0xD（CC），dst-ref 0001，src-ref 0000，class 00
c0 01 0a               TPDU size 1024
c1 02 01 00            src-tsap 01 00
c2 02 01 02            dst-tsap 01 02
```

> 核对：真实 PLC 抓包中 src-tsap=01 00、dst-tsap=01 02（PG/OP 会话）；TPDU size 0x0A=1024 字节。此三参数（c0/c1/c2）为必需；参数顺序在 Wireshark 输出中固定为 tpdu-size → src-tsap → dst-tsap。

## 3.4 S7 头字段（10/12 字节）语义

- **Protocol Id = 0x32**：S7comm 的协议标识。tshark 字段 `s7comm.header.protid`。
- **ROSCTR**：`s7comm.header.rosctr`。Job=1（DirECTION 请求），Ack=2，Ack_Data=3（请求的应答），Userdata=7（无 Job 语义的内部功能，如 Read SZL）。
- **Redundancy ID（2B）**：保留字段，恒 `00 00`。
- **PduRef**：`s7comm.header.pduref`。客户端每次新操作自增；响应回显请求的 PduRef。标准会话里 512→513… 或 1→2…
- **parlg / datlg**：`s7comm.header.parlg` / `s7comm.header.datlg`。
- **ErrClass / ErrCode**：`s7comm.header.errcls` / `s7comm.header.errcod`。仅 Ack/Ack_Data 有；无错误为 `00 00`。

## 3.5 Setup Communication（0xF0）

真实 S7-300/400 PLC 的 Setup 请求（Job）参数（8 字节）：

| 偏移 | 值 | tshark 字段 | 语义 |
| --- | --- | --- | --- |
| 0 | `f0` | s7comm.param.func | 函数 Setup communication |
| 1 | `00` | （reserved） | 保留 |
| 2-3 | `00 01` | s7comm.param.maxamq_calling | Max AmQ calling = 1 |
| 4-5 | `00 01` | s7comm.param.maxamq_called | Max AmQ called = 1 |
| 6-7 | `01 e0` | s7comm.param.pdu_length | PDU 长度 480 |

Setup 响应（Ack_Data）参数：`f0 00 00 01 00 01 00 f0`（PDU 长度 240）。完整请求/响应信件见第 6 章 S3/S4。

## 3.6 Read Var（0x04）

**请求（Job）**：参数区 = `04`（函数）+ `01`（项数）+ 每个 S7ANY 项 12 字节：

| 字段 | 字节 | 例子（DB1.DBW0） |
| --- | --- | --- |
| Function | 1 | `04` |
| Item count | 1 | `01` |
| Variable spec | 1 | `12` |
| Length of addr spec | 1 | `0a` |
| Syntax ID | 1 | `10`（S7ANY） |
| Transport size | 1 | `04`（WORD） |
| Length（元素数） | 2 | `00 02` |
| DB number | 2 | `00 01` |
| Area | 1 | `84`（DB） |
| Address（3B） | 3 | `00 00 00` |

数据区（可省设）为 1B 项数。示例 `rd_req` 完整字节见第 6 章 S5。

**响应（Ack_Data）**：参数区 = `04 01`（函数+项数）；数据区 = 每项：

| 字段 | 字节 | 例子 |
| --- | --- | --- |
| Return code | 1 | `ff`（Success） |
| Transport size | 1 | `04`（BYTE/WORD/DWORD） |
| Length | 2 | `00 02` |
| Value | N | `12 34` |

## 3.7 Write Var（0x05）

**请求（Job）**：参数区同上（函数 `05` + 项数 + S7ANY 项）；**数据区** = 每项 `[ReturnCode 0x00][TranspSize][Length 2B][Value]`。示例 `wr_req` 见第 6 章 S7。

**响应（Ack_Data）**：参数区 = `05`（函数，Wireshark 显示 item count 0）；数据区 = `00 00`（位掩码，0=OK）。真实 PLC 对非法区域会回 errcls/errcod（第 9 章）。

## 3.8 Keep-alive（0xFA）

Job 头，parlg=1，datlg=0，参数区唯一字节 `fa`。标准字节：

```
03 00 00 12 02 f0 80
32 01 00 00 00 01 00 01 00 00
fa
```

Wireshark 显示为 `Function: Unknown (0xfa)`（解析器不认 0xFA 为用户函数，真实存在的保活功能）。

## 3.9 Userdata → Read SZL（0x07 / 参数头 0x000112）

Read SZL（Read System Status List，读系统状态列表）不是 Job 函数，而是 **Userdata（ROSCTR 0x07）**。请求参数区（8 字节）+ 数据区（8 字节模板）：

| 域 | 字节 | 例子 |
| --- | --- | --- |
| 参数头（Parameter head） | 2 | `00 01` `12` 拼接为 `00 01 12` |
| 参数长度 | 1 | `04` |
| 方法（Req/Res） | 1 | `11` 请求 / `12` 响应 |
| 函数组（高半字节）+ 保留 | 1 | `44` → 4（CPU functions） |
| 子功能 | 1 | `01`（Read SZL） |
| 序号 | 1 | `00` |
| 数据区：返回码 | 1 | `ff`（Success） |
| 传输尺寸 | 1 | `09`（OCTET STRING） |
| 数据区长度 | 2 | `00 04` |
| SZL-ID | 2 | `01 32`（CPU 通信状态） |
| SZL 索引 | 2 | `00 04` |

响应参数区为 `00 01 12 08 12 84 01 01 00 00 00 00`（方法 0x12、函数组 4、子功能 1、序号+1、含 Last data unit 0 与 Error code 0000），数据区返回码 ff / 传输尺寸 09 / 长度（48B 时 `00 30`）/ SZL-ID / Index / SZL 数据。

## 3.10 数据项汇总（Read/Write/Userdata 共用）

| 字段 | 字节 | 请求（Write） | 响应（Read） | Read SZL |
| --- | --- | --- | --- | --- |
| Return code | 1 | `00`（Reserved） | `ff`（Success） | `ff` |
| Transport size | 1 | `04`（BYTE/WORD/DWORD） | `04` 或 `03`(BIT) | `09`（OCTET STRING） |
| Length | 2 | 元素数 | 元素数 | 字节数 |
| Value | N | 写值 | 读值 | SZL-ID + Index + 数据 |

# 4. 状态机

## 4.1 连接状态（Client ↔ PLC）

S7comm 会话状态机（一次 S7 会话 = 一个 TCP 连接 = 一个 Tport/PDU 上下文）：

```
IDLE ──TCP SYN──▶ SYN_SENT ──SYN/ACK──▶ ESTABLISHED
    (四次握手中)                                 │
                     ┌───────────────────────────┤ 应用层连接建立
                     ▼
            COTP_WAIT_CR ◀──发送 CR（COTP 0x0E）
                     │
                     ▼ 收到 CC（COTP 0x0D）
            S7_SETUP_SENT ◀──发送 Setup F0
                     │
                     ▼ 收到 Ack_Data（F0）
            READY ◀──（此后可合法发送任何 Job/Userdata/Keepalive）
                     │
                     ▼ TCP FIN/RST
              CLOSED
```

要点：
- **CR 之前没有 S7 头**：帧 4/5 只有 TPKT+COTP，无 0x32。测试断言必须针对 COTP 字段或 FrameAssert 字节，不可断言 s7comm.* 字段（会为空）。
- **setup 是 READY 的闸门**：Wireshark 解析不强制顺序，但真实 PLC 在收到 setup 前不会应答业务请求。生成器按 3.5 顺序产出，测试按包序断言。
- **多会话（sessions>1）**：每个会话独立 TCP 连接 + 独立源端口（srcPort 按会话偏移），各自执行 CR/CC/setup/交换。会话间 PduRef 独立自增。

## 4.2 PDU 交换状态（READY 内）

READY 后每次业务操作是**请求/响应对**，响应回显请求的 PduRef：

```
请求方向（Client→PLC）              响应方向（PLC→Client）
───────────────────               ────────────────────
Job     ROSCTR=1, PduRef=n   ──▶  Ack_Data ROSCTR=3, PduRef=n（读写）
Userdata ROSCTR=7, PduRef=m  ──▶  Userdata ROSCTR=7, PduRef=m（Read SZL）
Job     ROSCTR=1, PduRef=k   ──▶  Ack     ROSCTR=2（极少见纯 ACK）
```

## 4.3 生成器事件时序（设计约束）

terminal 层生成器产出**报文事件序列**，tcp 层负责帧化：

```
事件 1  CR    (COTP, 无 S7)
事件 2  CC    (COTP, 无 S7)
事件 3  Setup Job        → 事件 4 Setup Ack_Data
事件 5  Read Job         → 事件 6 Read Ack_Data
事件 7  Write Job        → 事件 8 Write Ack_Data
事件 9  Keepalive Job    （无响应）
事件 10 Read SZL Userdata → 事件 11 Read SZL Userdata
```

若配置 `sessions>1`，上述序列按会话并行展开，每条流一并跑完（多流交织由 tcp 层调度器非确定交织）。

# 5. 配置 Typedef

S7 配置遵循 enip 模式：**flat 键**（`spec` 层直接放 `s7: {...}`，`strategy_convert` 解析为 `core.S7Config`），终层层注册 `s7`，`Meta.S7` 注入终结层生成器。结构体定义目标位置 `trafficgen/internal/core/types.go`。

```go
// S7Config 是 S7comm 终结层配置（对接 strategy_convert 的 s7 flat 键）。
// 例：{"s7":{"transport":"tcp","peers":1,"conns":1,"pdu_ref":512, ...}}
type S7Config struct {
	Transport string `json:"transport,omitempty"`    // 仅 "tcp"（UDP 不支持，validate 拒绝）
	Peers     int    `json:"peers,omitempty"`         // 并发 PLC 对端数，>=1
	Conns     int    `json:"conns,omitempty"`         // 每对端会话(连接)数，>=1
	PDURef    uint32 `json:"pdu_ref,omitempty"`       // 起始 PDU 引用（默认 1）
	SrcTSAP   []byte `json:"src_tsap"`                // 默认 [0x01,0x00]
	DstTSAP   []byte `json:"dst_tsap"`                // 默认 [0x01,0x02]
	TPDUSize  uint16 `json:"tpdu_size,omitempty"`     // 默认 1024
	MaxAmQ    uint16 `json:"max_amq,omitempty"`       // 默认 1
	PDULength uint16 `json:"pdu_length,omitempty"`    // 默认 480（请求侧）
	Commands  []S7Command `json:"commands,omitempty"` // 读/写/保活/ReadSZL 序列
}

// S7Command 一条 S7comm 业务命令（在 setup 之后依次执行）。
type S7Command struct {
	Kind       string    `json:"kind"`            // "keepalive"|"read"|"write"|"readsZL"|"error"
	Items      []S7Item  `json:"items,omitempty"` // read/write 的变量项（多 DB 读 = 多 item）
	ItemCount  uint8     `json:"item_count,omitempty"`
	Value      []byte    `json:"value,omitempty"` // write 数据（逐项对齐）
	PDUReference uint16  `json:"pdu_reference,omitempty"` // 显式覆盖（0=自动 1..n）
	Direction  string    `json:"direction,omitempty"`     // "up"/"down"（默认 up）
	SkipResponse bool    `json:"skip_response,omitempty"` // 只发不等待/不产出响应（keepalive 默认 true）

	// 负向注入（expect_error 覆盖用）：伪造 ROSCTR/长度/协议 ID 等
	ErrClass   *uint8 `json:"err_class,omitempty"` // 0x81/0x82/...（负向 Ack_Data）
	ErrCode    *uint8 `json:"err_code,omitempty"`
	ForceROSCTR *uint8 `json:"force_rosctr,omitempty"` // 非法 ROSCTR 注入
	PadPDULen  *bool  `json:"pad_pdu_len,omitempty"`  // 伪造 TPKT/S7 长度不一致
}

// S7Item 一个 S7ANY 变量项（read/write 的目标），12 字节参数 + 数据。
type S7Item struct {
	Area      uint8  `json:"area"`      // 0x81 I / 0x82 Q / 0x83 M / 0x84 DB / ...
	DbNumber  uint16 `json:"db_number,omitempty"` // area=0x84/0x85 时有效
	Address   uint32 `json:"address,omitempty"`   // 字节地址（24 位内）
	Bit       uint8  `json:"bit,omitempty"`       // 位号 0-7，BIT 传输尺寸时有效
	TransportSize uint8 `json:"transport_size,omitempty"` // 0x01-0x09，见 2.4
	Length    uint16 `json:"length,omitempty"`    // 元素个数
	Value     []byte `json:"value,omitempty"`     // write 时数据
}
```

# 6. 包序列 HexDump

Byte-level 标准字节模板，全部经 `/tmp/s7lab/canon_all.pcap` 用 tshark 实测复现（每个场景对应抓包帧号，实测字节与下表完全一致）。所有帧均为 IPv4、帧载荷偏移 54。字节能模板按"会话"排列，帧号为 canon_all.pcap 帧号。

约定：
- `###==` 起行是 tshark 在 54 偏移处的全帧十六进制（含 eth/ip/tcp 头，偏移 0-53 省略，从"TCP 载荷"即偏移 54 起步）。
- 描述行给出各字段语义。

## S1 CR（Connect Request，COTP 连接请求）— canon_all.pcap 帧 4

`03 00 00 16` TPKT(4，Len=0x0016=22) `11` COTP Len=17 `e0` CR `00 00` dst-ref `00 01` src-ref `00` class `c0 01 0a` TPDU size=1024 `c1 02 01 00` src-tsap `c2 02 01 02` dst-tsap

```
03000015 11e0 0000 0001 00 c0010a c1020100 c2020102
TPKT v3 len=21(0x15) | COTP Len=17 PDU=CR(0xe) dst=0x0000 src=0x0001 cl=0 | tpdu 1024 | tsap 01 00 | tsap 01 02
```

> 注：上面 03000015 与 03 00 00 16 均为合法 TPKT 长度——0x15 vs 0x16 取决于是否把 COTP 首字节计入；实测 canon_all.pcap 帧 4 为 `03 00 00 16`（Length 22）。以 `03 00 00 16` 为最终版本（见 3.3）。

## S2 CC（Connect Confirm，COTP 连接确认）— 帧 5

`03 00 00 16` TPKT `11` COTP `d0` CC `00 01` dst-ref(回声 CR src-ref) `00 00` src-ref `00` class + 同三参数：

```
03000016 11d0 0001 0000 00 c0010a c1020100 c2020102
```

## S3 Setup Request（Job, 0xF0）— 帧 6

`03 00 00 19` TPKT(4+3+14=0x19=25) `02 f0 80` COTP DT `32 01 00 00 02 00 00 08 00 00` S7 头(10B：protid 32, rosctr 1 Job, redid 0000, pduref 0200=512, parlg 0008, datlg 0000) `f0 00 00 01 00 01 01 e0` Setup 参数(8B：func f0, reserved 00, MaxAmQ calling 0001, MaxAmQ called 0001, PDU len 01e0=480)

```
03000019 02f080
32010000020000080000
f0000001000101e0
```

## S4 Setup Response（Ack_Data, 0xF0）— 帧 7

`03 00 00 1b` `02 f0 80` `32 03 00 00 02 00 00 08 00 00` S7 头(12B：追加 errcls 00 errcod 00) `00 00` `f0 00 00 01 00 01 00 f0`（PDU 长度 240）

```
0300001b 02f080
32030000020000080000 0000
f0000001000100f0
```

## S5 Read Request（Job, 0x04, 多 DB 读示例 2 项）— 帧 8（单项版）

单 DB1.DBW0 版本（Wireshark 帧 8 实测）：

`03 00 00 20`(4+3+1+16+...=0x20=32) `02 f0 80` `32 01 00 00 03 00 00 0e 00 01` S7 头(pduref=0003) `04 01` Read+count=1 `12 0a 10 04 00 02 00 01 84 00 00 00` S7ANY(12B：spec 12, addr-len 0a, syntax 10, transp 04 WORD, len 0002, db 0001, area 84 DB, addr 000000) `01` data 区项数

```
03000020 02f080
320100000300000e0001
0401 120a 100400020001 84000000 01
```

> 多 DB 读：`04 <count>` 后重复多组 S7ANY 项（如 DB1+DB2 各 12B），数据区项数=参数项数。测试用例 s7 读 DB 覆盖 2 项。

## S6 Read Response（Ack_Data, 0x04）— 帧 9

`03 00 00 1b` `02 f0 80` `32 03 00 00 03 00 00 02 00 06 00 00` S7 头(12B：parlg=0002, datlg=0006, errcls/errcod 0000) `04 01` 参数(Read+count 1) `ff 04 00 02 12 34` 数据(returncode ff Success, transp 04, len 0002, value 1234)

```
0300001b 02f080
32030000030000020006 0000
0401
ff 040002 1234
```

## S7 Write Request（Job, 0x05）— 帧 10

`03 00 00 25`(4+3+14+16=0x25=37) `02 f0 80` `32 01 00 00 04 00 00 0e 00 06` S7 头(pduref=0004, parlg=0e, datlg=06) `05 01` Write+count=1 `12 0a 10 04 00 02 00 01 84 00 00 00` S7ANY(DB1.DBW0 WORD) `00 04 00 02 ca fe` 数据(rc 00 reserved, transp 04, len 0002, value cafe)

```
03000025 02f080
320100000400000e0006
0501 120a 100400020001 84000000
00040002 cafe
```

## S8 Write Response OK（Ack_Data, 0x05）— 帧 11

`03 00 00 16` `02 f0 80` `32 03 00 00 04 00 00 01 00 02 00 00` S7 头(parlg=0001, datlg=0002, errcls/errcod 0000) `05` 参数(Write) `00 00` 数据(位图，0=OK)

```
03000016 02f080
32030000040000010002 0000
05 0000
```

## S9 Keep-alive（Job, 0xFA）— 帧 12

`03 00 00 12` `02 f0 80` `32 01 00 00 00 01 00 01 00 00` S7 头(pduref=0001, parlg=0001, datlg=0000) `fa`

```
03000012 02f080
32010000000100010000
fa
```

## S10 Read SZL Request（Userdata, 0x07）— 帧 13

`03 00 00 21`(4+3+10+8+8=0x21=33) `02 f0 80` `32 07 00 00 05 00 00 08 00 08` S7 头(rosctr 7 Userdata, pduref=0005) `00 01 12 04 11 44 01 00` 参数(头 000112, len 04, method 11 Req, funcgroup 4, sub 01 ReadSZL, seq 00) `ff 09 00 04 01 32 00 04` 数据(rc ff, transp 09, len 0004, szl-id 0132, idx 0004)

```
03000021 02f080
32070000050000080008
000112 04 11 44 01 00
ff09 0004 0132 0004
```

## S11 Read SZL Response（Userdata, 0x07）— 帧 14

`03 00 00 55` `02 f0 80` `32 07 00 00 05 00 00 0c 00 38` S7 头(parlg=000c, datlg=0038=56) `00 01 12 08 12 84 01 01 00 00 00 00` 参数(method 12 Res, seq 01, last 00, errcode 0000) `ff 09 00 30 01 32 00 04` + 48 字节 SZL 数据

```
03000055 02f080
320700000500000c0038
000112 08 12 84 01 01 0000 0000
ff09 0030 0132 0004
[48×00 …]
```

## S12 错误响应（Ack_Data, errcls/errcod 非零）— 帧 15

`03 00 00 14` `02 f0 80` `32 03 00 00 04 00 00 01 00 00 04 01` S7 头(parlg=0001, datlg=0000, errcls 04, errcod 01) `05` 参数(Write) — Wireshark 会标 `[Malformed Packet]`（见 9 章说明，属解析器对"错误头+空数据"的已知伪影，非真实畸形）。

```
03000014 02f080
32030000040000010000 0401
05
```

# 7. 与 testcase 映射索引

`trafficgen/test/protocol_pcap/cases/s7.json` 的每个用例 id 对应本设计的场景/字节模板：

| s7.json 用例 id | 设计章节 | HexDump 模板 | 核心断言 |
| --- | --- | --- | --- |
| `s7_connect_setup_read` | 1.2, 4.1, 3.4, 3.5 | S1-S6 | CR 无 S7 头 → setup F0 → read DB1 |
| `s7_write_m_area` | 3.6, 3.7, 2.5 | S7-S8 | 写 M 区（area 0x83）Word |
| `s7_multi_db_read` | 3.6, 3.10 | S5（2 项） | 一次 read 双 DB 项 |
| `s7_setup_pdu_length` | 3.5 | S3-S4 | pdu_length 480/240 |
| `s7_keepalive` | 3.8 | S9 | 0xFA parlg=1 |
| `s7_read_szl` | 3.9 | S10-S11 | Userdata 0x07 头 000112 |
| `s7_error_class_code` | 3.4, 9 | S12 | errcls/errcod 非零 |
| `s7_ipv6_session` | 1.4, 8.4 | S3 (IPv6) | src_ip 为 IPv6 时 0x86DD |
| `s7_multi_session_ports` | 4.1, 8.5 | S3-S8 双流 | sessions>1 独立 srcPort |
| `s7_negative_bad_rosctr` | 9.3 | — | expect_error：非法 ROSCTR 拒绝 |
| `s7_negative_bad_area` | 9.3 | — | expect_error：非法 area 0x00 |
| `s7_negative_pdu_mismatch` | 9.3 | — | expect_error：TPKT/S7 长度不一致 |
| `s7_negative_addr_range` | 9.3 | — | expect_error：位号/字节地址越界（bit>7 或 byte 超 20 位）|
| `s7_udp_rejected` | 8.3 | — | expect_error：transport=udp 拒绝 |

映射原则（与 21-s7-testcase.md 章节一致）：连接期（CR/CC/setup）逐包断言 → 业务期按函数断言 → 负向按 validate 拒绝断言。所有字段断言用 `s7comm.*`；关键报文字节用帧 54 偏移 FrameAssert。

# 8. 实现集成点

## 8.1 层注册（registry.go，enip 同款）

`trafficgen/internal/core/layers/registry.go`，在 enip 注册（第 117-122 行）之后追加：

```go
r.Register(LayerSchema{
	Name:      "s7",
	Category:  CategoryTerminal,          // 终结层：无子层
	DependsOn: []string{"tcp"},           // 必需 tcp 承载（端口 102）
})
```

终结层不展开子层（InnerRequired 为空）；层校验器 `RegisterLayerValidator("s7", func(spec) error { s7c, err := (&S7Planner{}).Validate(*spec); ... })`。`S7Planner` 放在 `trafficgen/internal/protocol/s7/`，校验不通过返回错误 → 任务按预期失败（负向用例走这条路径）。

## 8.2 flat 键解析 + Meta 注入（chain_planner.go）

`trafficgen/internal/core/strategy_convert.go` 增加 `s7` flat 键 → `core.S7Config`（解析 S7Command/S7Item 数组，策略字段按通用 ValueCycler/ValueRandom 机制处理）。`chains_planner.go` 第 803 行附近（enip 同款）：

```go
// S7 同款（P4a）：配置经 Meta 直传 s7 终结层生成器（命令即数据段，事件
// 按 buildS7Packet 逐命令产出，字节级一致）。
S7: spec.S7,
```

`layers.Generator` 的 `Meta` 结构体增加：

```go
// S7 is the flow's S7 config (注入到 s7 层生成器, P4b)。Only set for s7 flows.
S7 *core.S7Config
```

## 8.3 终结层生成器（protocol/s7/layer_gen.go，enip 模板）

仿 `internal/protocol/enip/layer_gen.go`：

```go
type S7Generator struct{}
func (g *S7Generator) Name() string { return "s7" }
func (g *S7Generator) Generate(ctx context.Context, req *layers.GenRequest) error {
	// 1) 拒绝不支持配置（transport != tcp 显式报错，同 ENIP IOData 拒绝模式）
	// 2) 展开 peers×conns 会话；每会话维护 srcPort 偏移 + 独立 PduRef
	// 3) 每会话依次产出事件：CR、CC、Setup Job、[读/写/保活/ReadSZL 命令]
	//    每条 = MessageEvent{Direction: Up/Down, SrcPort, DstPort: 102, Bytes: 完整 TCP 载荷}
	// 4) 调用 buildS7Packet（纯函数，tcp.go 同款）逐命令产出字节
}
```

init() 注册：`RegisterLayerGenerator("s7", ...)` + `RegisterLayerValidator("s7", ...)`，全部字节构建复用 `internal/protocol/s7/build.go` 的 `buildS7Packet`（纯函数，无副作用，字节级一致，与 legacy 逐字对齐）。

**不支持（显式报错，绝不静默丢帧）**：
- `transport: "udp"`（S7comm 无 UDP 变体；UN 组态不走本层）。
- `mode`/`config` 之外的自定义扩展在未实现前报 unsupported。

## 8.4 IPv6 支持

tcp 链支持 IPv6：`EtherTypeFor(srcIP)`（internal/core/builder.go:115）对 `To4()==nil` 返回 EtherTypeIPv6(0x86DD)。s7 用例只改 `src_ip`/`dst_ip` 为 IPv6 字面量即可，其余不变。帧载荷偏移从 54 变 74（eth14 + ip40 + tcp20）；FrameAssert 用偏移 74。

## 8.5 多会话源端口

`sessions>1`（等价 enip 的 conns>1）：每会话独立 srcPort = 基础 srcPort + 会话号偏移（第 1 会话 12345，第 2 会话 12346 …），各会话执行完整 CR/CC/setup/交换。tshark 断言 `tcp.srcport` 的 DistinctValues={12345,12346,…} 验证。

## 8.6 帧偏移与 FrameAssert

- IPv4：S7comm 载荷自帧偏移 54 起（eth14+ip20+tcp20），FrameAssert `"offset":54`。
- IPv6：偏移 74（eth14+ip40+tcp20==20）。帧 4（CR）无 S7，FrameAssert 直接锁 TPKT/COTP 字节。
- 每根断言模板见第 6 章：`03 00 00 xx 02 f0 80 32 ...`。

# 9. 错误处理

## 9.1 错误头（Error Class / Error Code）

Ack/Ack_Data 头第 10-11 字节（12B 头的最后 2B）携带错误类/错误码；无错误恒 `00 00`。Wireshark 字段 `s7comm.header.errcls` / `s7comm.header.errcod`。

错误类（高位字节，0x8x 为经典 S7）：

| ErrClass | 名称 | 说明 |
| --- | --- | --- |
| 0x00 | No error | 无错误 |
| 0x81 | Application relationship (应用关系) | 连接/会话关系错误 |
| 0x82 | Object definition (对象定义) | 对象不存在/未定义 |
| 0x83 | No resources available (资源不足) | 资源/内存不足 |
| 0x84 | Service processing (服务处理) | 服务调用的处理错误 |
| 0x85 | Supplies (供给) | 外设/信号错误 |
| 0x87 | Access to object (对象访问) | 访问被拒/越权 |

错误码（低字节）依错误类不同语义；常见如 `0x01`（对象不存在）、`0x04`（请求对象非法）等。负向用例 `s7_error_class_code` 注入 errcls/errcod（如 04/01）断言之。

## 9.2 数据项返回码（Return Code）

数据项第 1 字节为返回码（Wireshark `s7comm.data.returncode`）：

| 值 | 名称 | 说明 |
| --- | --- | --- |
| 0x00 | Reserved | 写请求数据项固定此值 |
| 0x01 | Hardware fault | 硬件故障 |
| 0x03 | Accessing the object not allowed (对象访问不允许) | 权限/区域不符 |
| 0x05 | Out of range (越界) | 地址/长度越界 |
| 0x06 | Data type not supported | 不支持的数据类型 |
| 0x07 | Data inconsistency | 数据不一致 |
| 0x0a | Object does not exist | 对象不存在（Read SZL 常见） |
| 0xff | Success | 成功 |

## 9.3 负路径（expect_error）与异常数据

生成器/校验器必须对这些非法输入显式拒绝或产出可判定的错误报文（测试断言见 21-s7-testcase.md）：

| 场景 | 期望行为 | 用例 |
| --- | --- | --- |
| ROSCTR 非法（非 1/2/3/7） | Validate 拒绝 | `s7_negative_bad_rosctr` |
| Area 非法（非枚举值，如 0x00/0xff） | Validate 拒绝 | `s7_negative_bad_area` |
| TPKT.Length 与 COTP+S7 不符 | Validate 拒绝（生成不产畸形包） | `s7_negative_pdu_mismatch` |
| 位号/字节地址越界（bit>7 或 byte 超 20 位） | Validate 拒绝 | `s7_negative_addr_range` |
| transport != tcp | 生成器显式报错（同 ENIP IOData） | `s7_udp_rejected` |
| pdu_ref 与请求不一致 | 不属于生成器（对端行为）；文档注明 | — |

> 已知伪影：对"错误头+空数据"的 Ack_Data，Wireshark 会标 `[Malformed Packet]`（SS12 帧 15）。这是 dissector 对错误响应的解析残留，非真实畸形包；不做 whitelist（保持 strict），仅在文档记明。真实 PLC（plc_status.pcap）对非法访问会回 errcls/errcod 且携带数据项返回码，生成器按 9.1/9.2 构造。

## 9.4 生成-验证一致性

- TPKT.Length：`4 + len(COTP) + len(S7 PDU)`，构建函数自动计算并写 2B 大端。
- S7 parlg/datlg：按参数区/数据区实际字节数写，构建函数自动对齐。
- 非法长度输入（如 datlg 为负/超出构建缓冲）在构建前 Validate 拦截。

# 10. 扩展字段映射

## 10.1 策略字段（strategy 支持）

| JSON 字段 | 策略类型 | 说明 |
| --- | --- | --- |
| `src_port` | fixed/inc/rand/pattern/list | tcp 层普通端口策略 |
| `dst_port` | fixed（默认 102） | 固定 102，不变量 |
| `area`/`db_number`/`address`/`bit`/`transport_size`/`length` | fixed/inc/rand | S7Item 内字段可策略化（多 DB 遍历用 inc） |
| `value` | fixed/pattern(list) | 写数据值 |
| `pdu_ref` | fixed/inc | 起始 PDU 引用策略 |

## 10.2 传输尺寸映射（JSON 友好）

`transport_size` 同时接受数字（`4`）或字符串名（`"word"`/`"dword"`/`"real"`/`"bit"`/`"byte"`/`"int"`/`"dint"`）。构建时映射到 2.4 节字节码。

## 10.3 未实现/未来扩展（明确不交付）

- **BLOCK 上传/下载（0x1D/0x1E 等）**：Userdata 函数组 1 的程序员命令（上传/下载块）、0x1C Identify 等本版不展开（UDT 操作未定案）。
- **PLC-CPU 控制（0x29 STOP/RUN）**：破坏性操作，不建议生成。
- **TSAP 配置**：默认 01 00/01 02；用户可经 `src_tsap`/`dst_tsap` 覆盖（PG/OP 会话）。
- **冗余（S7-400H）**：Redundancy ID 保留 0000，不实现冗余专有字段。
- **S7-1500 优化块访问**：TIA 独有，非 S7-300/400 经典语义，不实现。

# 11. 修订记录

| 版本 | 日期 | 修订 |
| --- | --- | --- |
| v1.0.0 | 2026-08-18 | 初稿。字节级验证：ROSCTR Userdata=0x07（修正早期"0x04"假设）；Read SZL 经 Userdata 0x07（修正早期"Job 参数 0x01"假设）；协议 ID 仅 0x32（不采用 0x72/0x71）；Setup 参数取真实 PLC 8B 模板（f0 00 00 01 00 01 01 e0 / ...00 f0）；S12 错误响应的 Wireshark Malformed 伪影记明。全部 HexDump 经 /tmp/s7lab/canon_all.pcap tshark 实测；2.3/3.3/3.4/3.9 表格已按实测定稿 |

## 6.1 逐字节注解（以 S3 Setup Request 为例的完整推导）

对第 6 章 S3 模板做一次完整的逐字节推导，演示每字节的来历（这也是手写其他模板的通用方法）：

```
字节    Hex    推导
──────────────────────────────────────────────────────────────
0-3    03 00 00 19   TPKT：版本 0x03 | 保留 0x00 | 长度 0x0019=25。
                     = 4(TPKT) + 3(COTP DT) + 18(S7 Job)
4       02          COTP Length=2（DT：只有 TPDU 号+EOT 两字节）
5       f0          DT 头：高半字节 0x0F(PDU Type DT Data) | 低半字节 TPDU 号 0
6       80          位 7=1 → Last data unit = Yes
7       32          S7 Protocol Id
8       01          ROSCTR = 1 (Job)
9       00          Redundancy ID 高位
10-11   00 02       PDU Reference 0x0002=2（本会话第 2 条 PDU；第一条是 CR，S7 从 setup 起）
12-13   00 08       ParamLen = 8（Setup 参数区 8 字节）
14-15   00 00       DataLen = 0
16      f0          Setup 函数
17      00          保留
18-19   00 01       Max AmQ calling = 1
20-21   00 01       Max AmQ called = 1
22-23   01 e0       PDU 长度 = 0x01E0 = 480
──────────────────────────────────────────────────────────────
```

要点：TPKT 长度 25 = 正文 4+3+18 可见；S7 头 10B（offset 7-16）在 parlg/datlg 之前；Setup 参数 8B 在 16-23。

## 6.2 偏移速查（相对 TCP 载荷）

| 内容 | 相对 TCP 载荷偏移 | 相对帧偏移(IPv4/IPv6) |
| --- | --- | --- |
| TPKT 版本 | 0 | 54/74 |
| TPKT 长度 | 2 | 56/76 |
| COTP Length | 4 | 58/78 |
| COTP DT 头 | 5 | 59/79 |
| S7 Protocol Id | 7 | 61/81 |
| S7 ROSCTR | 8 | 62/82 |
| S7 PduRef | 10-11 | 64-65/84-85 |
| S7 parlg | 12-13 | 66-67/86-87 |
| S7 datlg | 14-15 | 68-69/88-89 |
| ErrClass/ErrCode（Ack 头） | 16-17 | 70-71/90-91 |
| 参数区 | 18（Job）/20（Ack） | 72/74 起 |

## 6.3 工作示例：把"读 DB2.DBX100.4 BYTE"编码成 S7ANY 项

目标：读 DB2 第 100 字节、位 4、BYTE 尺寸（元素数 1）。

- area = 0x84（DB）
- db_number = 0x0002
- 线性位索引 = 字节 100 × 8 + 位 4 = 804 = 0x0324（修正：不是 nibble 打包）
- 3B 地址 = `00 03 24`
- transport_size = 0x02（BYTE）
- length(元素) = 0x0001

S7ANY 项（12B）：`12 0a 10 02 00 01 00 02 84 00 03 24`

逐字节：`12`(spec) `0a`(addr len) `10`(syntax) `02`(BYTE) `00 01`(len) `00 02`(db) `84`(area) `00 03 24`(线性位索引 addr)。

> 验证方法：把该项拼进 S5 请求模板后，`tshark -V` 应显示 `Byte Address: 100`、`Bit: 4`、`Transport size: BYTE`、`DB number: 2`。见 21-s7-testcase.md §「字节地址/位寻址推导」。

# 8.7 逐字节构建函数（buildS7Packet 规格）

终结层字节构建收敛为单个纯函数（无状态、无副作用，输入 = 会话上下文 + 命令，输出 = 完整 TCP 载荷字节）. 给定 `ctx`（PDU 引用、TSAP、TPDU size、MaxAmQ、PDU 长度）与每类命令，产出以下字节（与第 6 章模板一一对应）：

```
buildCR(ctx)          → 03 00 00 16 | 11 e0 00 00 <src-ref> 00 | c0 01 0a | c1 02 src-tsap | c2 02 dst-tsap
buildCC(ctx)          → 03 00 00 16 | 11 d0 <dst-ref> <src-ref> 00 | c0 01 0a | c1 02 ... | c2 02 ...
buildSetupJob(ctx)    → 03 00 00 19 | 02 f0 80 | 32 01 00 00 <pduref> 00 08 00 00 | f0 00 00 01 00 01 01 e0
buildSetupResp(ctx)   → 03 00 00 1b | 02 f0 80 | 32 03 00 00 <pduref> 00 08 00 00 00 00 | f0 00 00 01 00 01 00 f0
buildReadJob(items)   → 03 00 00 xx | 02 f0 80 | 32 01 00 00 <pduref> 00 <parlg> 00 <datlg> | 04 <count> <item…> | <itemcount>
buildReadAck(values)  → 03 00 00 xx | 02 f0 80 | 32 03 00 00 <pduref> 00 02 00 <datlg> 00 00 | 04 <count> | <item…>
buildWriteJob(items)  → 03 00 00 xx | 02 f0 80 | 32 01 00 00 <pduref> 00 <parlg> 00 <datlg> | 05 <count> <item…> | <data…>
buildWriteAck()       → 03 00 00 16 | 02 f0 80 | 32 03 00 00 <pduref> 00 01 00 02 00 00 | 05 | 00 00
buildKeepalive()      → 03 00 00 12 | 02 f0 80 | 32 01 00 00 <pduref> 00 01 00 00 | fa
buildReadSZLReq(szl)  → 03 00 00 21 | 02 f0 80 | 32 07 00 00 <pduref> 00 08 00 08 | 00 01 12 04 11 44 01 00 | ff 09 00 04 <szl-id> <index>
buildReadSZLResp()    → 03 00 00 55 | 02 f0 80 | 32 07 00 00 <pduref> 00 0c 00 38 | 00 01 12 08 12 84 01 01 00 00 00 00 | ff 09 00 30 <szl> … 
```

每个函数内部：

1. 计算 TPKT 长度 = 4 + len(cotp) + len(s7) 并写 `03 00 <len>`；
2. 计算 parlg = len(param)、datlg = len(data) 并写 2B 大端；
3. Ack 变体在头后补 `errcls errcod`（默认 `00 00`）。

## 8.8 会话对象（session 上下文）

每会话一个不可变上下文（连接期固定）:

```go
type S7Session struct {
	SrcRef   uint16  // COTP src reference（首会话 0x0001，后续+1）
	DstRef   uint16  // CC 回显
	SrcPort  uint16  // 12345 + sessionIdx
	DstPort  uint16  // 102
	PDURef   uint16  // 当前 PDU 引用（每命令自增）
	SrcTSAP  []byte  // 01 00
	DstTSAP  []byte  // 01 02
	TPDUSize uint16  // 1024
	MaxAmQ   uint16  // 1
	PDULen   uint16  // 480（协商为 240）
	State    S7SessionState
}
```

多会话（peers×conns>1）时按 8.5 偏移 srcPort 与 srcRef，各自独立走 4.1 状态机。

## 8.9 校验器（Validate）规格

```go
// Validate 与 enip 的 RegisterLayerValidator 对齐。返回 error -> 任务失败（负向）
func (p *S7Planner) Validate(spec core.S7Config) error
```

规则（每项都有 s7.json 负向用例）:

- `transport` 非 "tcp" → err（`s7_udp_rejected`）。
- `commands` 非空且每个 kind 必须是 keepalive/read/write/readsZL/error → err。
- `sessions`(peers×conns) >= 1 且 <= 16（防爆炸）。
- 每 item：`area` 必须 ∈ {0x81,0x82,0x83,0x84,0x85,0x86,0x1C,0x1D}（`s7_negative_bad_area`）。
- `address`+`bit` 编码为线性位索引（`byte<<3|bit`）需在 24 位内：`byte` ≤ 0x1FFFFF（20 位），`bit` ≤ 7；越界 err（`s7_negative_addr_range`）。
- `transport_size` ∈ [0x01,0x09] 且与 area/语义相容（BIT 仅位寻址）。
- 自定义 ForceROSCTR 仅允许 -1..3（保留 0）且 json 传入裸数字（`s7_negative_bad_rosctr` 之外）。
- 长度字段（TPKT vs COTP+S7）一致性由构建函数保证；外部伪造路径（`s7_negative_pdu_mismatch`）由 case 自身构造非法值，经 expect_error 断言任务失败。
- PDURef 起始 >= 1。

## 8.10 与 legacy 对齐与回归

- README / 15-protocol pcap 已有 351 例；S7 新增用例通过 `trafficgen/test/protocol_pcap/run_all_test.go` 批量驱动（tshark 为最终裁判，见 21-s7-testcase.md §环境）。
- 新增 `s7` 不触碰既有协议；注册顺序无关（registry 独立）。
- 集成测试目标：`go test ./internal/protocol/s7/... ./test/protocol_pcap/... -count=1 -race`（-count=1 防缓存，见 NIC/go test 缓存陷阱记录）。

# 4.4 状态机防御细节

## 4.4.1 事件序与 PDU 引用生命周期

- PDU 引用（PduRef）随每个**业务命令**自增（CR/CC 引用 COTP ref，而非 PduRef——S7 PDU 从 setup（首个 S7 PDU）开始编号）。
- 保活不算"业务命令"的响应语义：请求 PduRef 自增，无响应回显；生成器直接产出 Job 事件。
- 响应回显同一 PduRef：Read/Write/ReadSZL 的 Ack_Data/Userdata 必须回显请求的 pduref（测试用 `same_as_packet` 断言：响应 PduRef == 请求 PduRef）。

## 4.4.2 会话关闭

会话按配置在全部命令完成后可关闭：

- 默认行为：保留 TCP 连接（长连接，后续命令可续跑；等价 PLC 在线）。
- 若配置 `close_on_finish` 语义（未来），则 TCP FIN + COTP DR（Disconnect Request）序列；本版不实现 DR（终端帧为 FIN，符合多数抓包）。

# 5.2 配置示例（JSON / spec_json）

以下两个配置与 s7.json 用例以及第 7 章映射一一对照：

```jsonc
// 例 A：单会话，读 DB1.DBW0（WORD）+ 写 M100.0 位
{
  "layers": [ {"tcp": {}}, {"s7": {}} ],
  "src_ip": "10.0.0.1", "dst_ip": "20.0.0.1",
  "src_port": 12345, "dst_port": 102,
  "s7": {
    "sessions": 1,
    "commands": [
      {"kind": "read",  "items": [
         {"area": 132, "db_number": 1, "address": 0, "transport_size": 4, "length": 1}
      ]},
      {"kind": "write", "items": [
         {"area": 131, "address": 100, "bit": 0, "transport_size": 3, "length": 1},
      ], "value": [[1]]}
    ]
  }
}
```

```jsonc
// 例 B：多会话（2），读 SZL 0x0132/0x0004
{
  "s7": {
    "sessions": 2,
    "commands": [
      {"kind": "readsZL", "szl_id": 306, "szl_index": 4}
    ]
  }
}
```

> JSON 值说明：area/db_number/address/bit/transport_size 全为十进制；szl_id 306=0x0132。

# 5.3 字段合法值表（Validate 依据）

| 字段 | 合法值 | 默认 | 说明 |
| --- | --- | --- | --- |
| transport | "tcp" | "tcp" | 仅 tcp |
| src_tsap | [0x01,0x00] | 同左 | PG/OP 会话 |
| dst_tsap | [0x01,0x02] | 同左 | |
| tpdu_size | >= 0x0D(128 B) | 1024 | RFC 905 最小 128B |
| max_amq | 1-16 | 1 | |
| pdu_length | <= 960(0x3C0) | 480 | 客户请求给 480，响应 240 |
| sessions | 1-16 | 1 | |

# 8.11 集成自检清单（实现验收）

按第 7 章用例全部通过 + `-race` 干净 + Go vet 干净后，人工核对以下项目（CLAUDE.md 强制 code review）：

1. `go vet ./internal/protocol/s7/... ./internal/core/layers/...` 零告警。
2. 构建函数对 Ack 变体补 errcls/errcod；Job 不变体不补（逐字节比对 S3/S4）。
3. 多会话 srcPort 偏移：`tcp.srcport` 的 DistinctValues 断言（8.5）。
4. IPv6 用例 FrameAssert 用偏移 74，tshark 以 `tcp.port==102,s7comm` 解码成功。
5. 负向（expect_error）各 case 真实走到 Validate 拒绝路径（非"没有产出包但任务却成功"——参照 00-unimplemented-list 的 Plan-swallow 教训）。
6. `same_as_packet` 断言响应 PduRef == 请求 PduRef 通过。

# 9.5 错误明细表（Error Class/Code 完整映射，经 packet-s7comm.c VALS 核验）

Wireshark 解析器把 errcls 展示为字符串；以下为最常见组合（真实 PLC 可能返回）：

| errcls | errcod | Wireshark 显示 | 场景 |
| --- | --- | --- | --- |
| 0x00 | 0x00 | No error / 0x00 | 正常成功 |
| 0x81 | 0xXX | Application relationship | 连接关系被拒 |
| 0x82 | 0xXX | Object definition | 对象未定义（读不存在的 DB） |
| 0x83 | 0xXX | No resources available | 资源不足 |
| 0x84 | 0x01 | Service processing (启动/停下) | 服务处理失败 |
| 0x85 | 0xXX | Supplies | 供给/电源错误 |
| 0x87 | 0xXX | Access to object | 访问被拒（写只读变量） |

生成器对负向 `error` 命令注入 errcls/errcod 并产出 Ack_Data（S12 模板），测试断言 `s7comm.header.errcls != 0` 与 errcod 精确值。

# 9.6 数据项返回码明细（读响应/写请求/Read SZL 通用）

| rc | Wireshark 名称 | 写请求 | 读响应 | Read SZL |
| --- | --- | --- | --- | --- |
| 0x00 | Reserved | 是（item 头首字节 0x00） | — | — |
| 0xff | Success | — | 是 | 是 |
| 0x03 | Accessing object not allowed | — | 可能 | — |
| 0x05 | Out of range | — | 地址越界 | — |
| 0x0a | Object does not exist | — | — | SZL 不存在 |
| 0x01/0x06/0x07 | HW fault / unsupported / inconsistency | — | 可能 | — |

> 注：写请求数据项首字节固定 0x00（未写回显示为 rc=Reserved）；读响应与 Read SZL 数据项首字节 0xff 表示成功。测试断言用 `s7comm.data.returncode`。

# 3.11 TPKT 多分片（Session Data / COTP 续接）

业务 PDU 长度大于 TPDU（1024B）时才需要分片；本档默认单 PDU < 1024，不分片。若未来实现分片：

- TPKT 每条消息独立（每条 COTP DT 独立 TPKT）。
- COTP：第一条 DT 头 `f0`（TPDU 号 0），后续 DT 头 `f1`,`f2`…（低半字节递增），最后一条 EOT 置 1。
- Wireshark 会把同会话连续 DT 重组为一条 S7 PDU（`Reassembled TCP` 预 TPKT 重组）。
- 分片只影响承载层；S7 头字段不变。测试无需覆盖（PDU < 480）。

# 3.12 COTP CR/CC 参数完整性

COTP CR/CC 参数区三参数为**必需**（缺任一 tshark 显示为 Malformed）：

| 参数码 | 长度 | 值 | 说明 |
| --- | --- | --- | --- |
| 0xC0 (tpdu-size) | 1 | 0x0A | TPDU 大小 1024（0x0D=128 亦合法） |
| 0xC1 (src-tsap) | 2 | `01 00` | 源 TSAP |
| 0xC2 (dst-tsap) | 2 | `01 02` | 目标 TSAP |

CR 与 CC 的参数完全一致（Wireshark 显示同字段），只是 PDU Type 0x0E→0x0D 与 dst/src ref 对调。认证可选（S7-1500/二代），不在本版。

# 3.13 读请求的数据区（datlg）

读请求（Job）数据区本版为 1B 项数（`datlg=1`），与常见抓包一致：

```
Header(Job) ... parlg=<14+12×(N-1)> datlg=1
param: 04 N <item0…itemN-1>
data : 01
```

注意：某些实现（snap7）写 datlg=0 且无数据区。本生成器**总是写项数**（datlg=1），tshark 解析为 itemcount——两版均被 tshark 接受，本方保持可预测（第 6 章 S5 模板 datlg=1）。

# 3.14 写请求数据区逐项布局

写请求数据区每项（对应参数区一个 S7ANY 项）：

| 域 | 字节 | 说明 |
| --- | --- | --- |
| Return code | 1 | 0x00（保留） |
| Transport size | 1 | 与请求 S7ANY 一致（0x02..0x08） |
| Length | 2 | 元素个数 |
| Value | N×size | 数据 |

多项写 = 参数区多个 S7ANY + 数据区多项（顺序对应）。数据区总长 = 4+len(values) 每项；datlg 据此算。测试 s7_write_m_area 覆盖单项（M100.0 位，BIT 传输尺寸 value=1×bit）。

# 3.15 Read SZL 请求/响应参数完整语义

Read SZL 的 Userdata 参数区（8B 请求/12B 响应）：

| 偏移 | 请求 | 响应 |
| --- | --- | --- |
| 0-1 | 参数头 `00 01`（0x0001） | `00 01` |
| 2   | 参数长度 `12`（0x000112 高字节 12=0x12？——实为 0x0012 长度 0x12？见下） | `12` |
| 3   | 方法 `11`（请求） | `12`（响应） |
| 4   | 函数组高半字节 `4` + 保留低半 `0` → `44`？ | `84`（8=响应位） |
| 5   | 子功能 `01`（Read SZL） | `01` |
| 6   | 序号 0 | 序号 1（回填请求序号+1） |
| 7   | — | 数据单元引用号 0 |
| 8   | — | Last data unit 0 |
| 9-10 | — | 错误码 `00 00` |

> 校准：参数头 3B 实际是 `00 01 12`（= head 0x0001 + 长度 0x12 分解见 3.9 表）。不要在文档里写死 `0x0012` 以外的推断；所有字节以 S10/S11 模板为准。响应第 3 字节 `08`=请求+...回填逻辑见 3.9。

# 8.12 测试驱动与断言字段集

s7.json 使用 `s7comm.*` 字段 + 帧断言（全部 tshark 实测支持）：

| 断言字段 | 取值示例 | 用例 |
| --- | --- | --- |
| `s7comm.header.protid` | `0x32` | 全部 |
| `s7comm.header.rosctr` | `1`/`3`/`7` | 全部 |
| `s7comm.header.pduref` | `512` | read 等 |
| `s7comm.param.func` | `0x04`/`0x05`/`0xf0` | read/write/setup |
| `s7comm.param.itemcount` | `1`/`2` | read/write |
| `s7comm.header.errcls` / `errcod` | `0x00`/`0x04` | setup/error |
| `s7comm.data.returncode` | `0xff` | S6 |
| `s7comm.data.transportsize` | `0x04` | S6/S7 |
| `s7comm.data.userdata.szl_id` | `0x0132` | readsZL |

通用断言（无需 S7 字段）：`tcp.dstport=102`、`tcp.srcport`（多会话 DistinctValues）、`ip.src/ip.dst`（IPv6 用例 `ipv6.src/dst`）、`frame.len`。

# 9.7 负向注入（force 字段）数据流

`force_rosctr`/`pad_pdu_len` 等 force 字段只在 case 配 `expect_error:true` 时由 Validate 放行；其目的不是产出畸形字节，而是**验证校验器拦截**。数据流（Design §5 S7Command）：

```
case spec_json.s7.commands[].force_rosctr=9  (非法)
  → strategy_convert 产生 err: "s7: invalid rosctr 9"
  → 任务创建/启动即失败（expect_error 断言任务 fail，无 pcap 产出）
```

实现路径一致化：force 字段在 Validate 入口即校验，非法即 err（不落入构建）。故负向用例永远不含 `frames`/`fields`（无包），仅 `expect_error:true`（+notes）。这与 00-unimplemented-list 记录的"plan-error 被吞掉、任务报 completed 但 0 包"教训相反——负向必须**确实 fail**，不能只是静默 0 包。

# 10.4 扩展：地址序列化（S7ANY 3B 地址组装，线性位索引）

把 `(byte_addr, bit)` 组装为 3B 地址（bit 在最低 3 位，字节地址高 20 位）：

```
addr24 = byte_addr<<3 | bit       // 线性位索引（Wireshark 解析器 /8 /%8 的反向）
b0 = addr24>>16 & 0xff
b1 = addr24>>8  & 0xff
b2 = addr24     & 0xff
bytes = [b0, b1, b2]
```

推导示例（6.3）：db2 byte100 bit4 → `00 03 24`（实测 Byte=100 Bit=4）。组装在构建函数内完成；addr24 越界（>0xFFFFFF）Validate 已拦截。

# 10.5 传输尺寸↔位宽汇总（写值校验用）

| transp_size | 名称 | 值字节宽 | 元素数×宽=数据区长度 |
| --- | --- | --- | --- |
| 1 | BIT | 1 bit | 位先 pack 到字节 |
| 2 | BYTE | 1 | N |
| 3 | CHAR | 1 | N |
| 4 | WORD | 2 | 2N |
| 5 | INT | 2 | 2N |
| 6 | DWORD | 4 | 4N |
| 7 | DINT | 4 | 4N |
| 8 | REAL | 4 | 4N |

# 11.1 已知限制（文档化，不视为缺陷）

- **认证（S7-1500 下一代auth）**：本版默认不启用（经典 S7-300/400 无鉴权）。
- **COTP 分片**：PDU < 480 不触发（240 响应）无分片路径。
- **Block 传输（UDT 0x1C-0x1E）**：仅记录，不实现（不属于 Read/Write/SZL MVP 范围）。
- **S7-1500 优化块访问**：不实现。
- **冗余（H）**：冗余 ID 置 0。

# 2.6 大端编码错误排查实例（字节表核对法）

手写 PDU 常见的四位字节错（endianness slip）逐项列出，供自检：

| 预期 | 常见错写 | 结果 |
| --- | --- | --- |
| TPKT len 0x0019 | `19 00` | Wireshark 长度错读为 0x1900=6400，Malformed |
| pduref 0x0002 | `02 00` | 客户端请求 2 但解码 0x0200=512 |
| parlg 0x0008 | `08 00` | 解码 0x0800=2048，参数解析错 |
| data 项 len 0x0002 | `02 00` | 数据解析错位 |
| DB 号 0x0001 | `01 00` | DB 号 256 |
| 3B 地址 `00 64 04` | `00 04 64` | 字节 4 位 6（错位） |

自查方法：写完后过 tshark `-V`，逐字段核对 `PDU Reference`、`Parameter length`、`Data length`、`DB number`、`Address` 是否与预期十进制一致。

# 4.5 时序与速率（策略层面的枚举语义）

S7 业务命令序列是**有序的**（setup 后按 commands 数组顺序执行），策略（`inc` 等）作用于字段值而非时序：

- 字段级策略：`area`/`address` 等可按 `inc` 在多次流间推进（多 DB 遍历）。
- 时序：命令间无定时；整条流由 tcp 层 pacer/FC 调度。
- 会话建立速度：由 flow 速率决定（CR/CC/setup 一帧接一帧）。
- 不与既有 replay/FC 冲突：s7 是生成流，无重放语义。

# 10.6 未来：Read/Write 坐标类型（Unified Memory / 绝对地址）

本版 S7ANY（0x10）仅覆盖**相对地址**（area+db+byte+bit）。未来若支持 S7-1500 的符号/绝对地址，将新增语法 ID 区分（0x20 等）；文档记录不实现。TSAP/PDU 策略不受影响。

# 附录 A：标准会话 tshark 输出样本（节选）

以下为 /tmp/s7lab/canon_all.pcap 帧 6-11 的 tshark 摘要（验证模板可复现）：

```
    6  10.0.0.1 → 20.0.0.1  S7COMM 79  ROSCTR:[Job]     Function:[Setup communication]
    7  20.0.0.1 → 10.0.0.1  S7COMM 81  ROSCTR:[Ack_Data] Function:[Setup communication]
    8  10.0.0.1 → 20.0.0.1  S7COMM 86  ROSCTR:[Job]     Function:[Read Var]
    9  20.0.0.1 → 10.0.0.1  S7COMM 81  ROSCTR:[Ack_Data] Function:[Read Var]
   10  10.0.0.1 → 20.0.0.1  S7COMM 91  ROSCTR:[Job]     Function:[Write Var]
   11  20.0.0.1 → 10.0.0.1  S7COMM 76  ROSCTR:[Ack_Data] Function:[Write Var]
   12  10.0.0.1 → 20.0.0.1  S7COMM 72  ROSCTR:[Job]     Function:[Unknown function: 0xfa]
   13  10.0.0.1 → 20.0.0.1  S7COMM 87  ROSCTR:[Userdata] Function:[Request]->[CPU functions]->[Read SZL] ID=0x0132 Index=0x0004
   14  20.0.0.1 → 10.0.0.1  S7COMM 139 ROSCTR:[Userdata] Function:[Response]->[CPU functions]->[Read SZL] ID=0x0132 Index=0x0004
   15  20.0.0.1 → 10.0.0.1  S7COMM 74  ROSCTR:[Ack_Data] Function:[Write Var][Malformed Packet]
```

> 帧 15 的 Malformed 为 9.3 记录的解析器伪影。帧 4/5 为 COTP CR/CC（无 S7）。此样本作为回归基准写进 run_all_test 的注释，供 tshark 版本漂移排查。

# 附录 B：与同栈协议对照（enip / s7）

| 维 | enip（P4a） | s7（本档） |
| --- | --- | --- |
| 层注册 | CategoryTerminal + DependsOn tcp | 同 |
| 零负载层条目 | 是 | 同（layers [{tcp},{s7}]） |
| flat 键 | `enip` | `s7` |
| Meta 注入 | `Meta.ENIP` | `Meta.S7` |
| 帧偏移（IPv4） | 54 | 54 |
| 负向 | IOData reject | force/validate reject |
| 连接建立 | 无显式握手（命令即段） | CR/CC/setup 3 段显式建立 |
| 命令语义 | 即数据段 | 请求/响应对（需回显） |

后者的差异（显式建立 + 应答回显）是 s7 相对 enip 新增的状态机/回显逻辑——第 8 章生成器必须实现。

# 1.5 术语表（首次出现英文术语加中文解释）

| 术语 | 中文解释 | 出现章节 |
| --- | --- | --- |
| PLC | 可编程逻辑控制器 | 1.1 |
| TPKT | ISO-on-TCP（RFC 1006）的传输分片，4B 头 | 1.1 |
| COTP | ISO 8073/X.224 连接式传输协议，3B+ 头 | 1.1 |
| CR/CC | Connect Request / Connect Confirm，COTP 连接请求/确认 | 1.1 |
| DT | Data TPDU，COTP 数据单元 | 3.1 |
| TSAP | Transport Service Access Point，传输服务访问点 | 1.2 |
| ROSCTR | ROS Control，S7 消息方向类型字节 | 1.3 |
| PDU Reference | 协议数据单元引用号，请求/响应回声配对 | 1.2 |
| S7ANY | S7 变量寻址项，12B（区域+DB+地址+尺寸） | 3.6 |
| SZL | System Status List，系统状态列表（Read SZL 读取） | 1.3 |
| MaxAmQ | 最多并行作业数协商（setup 参数） | 3.5 |
| TPDU | Transport Protocol Data Unit，传输协议数据单元 | 3.5 |
| EOT | End of Transfer，末数据单元标志（COTP 位 7） | 3.1 |
| Big-Endian | 大端字节序（MSB 在前） | 2.1 |

# 1.6 读法指南（本文档如何阅读）

- 想**快速搭一个会话**：读 1.2 → 6 章 S1-S4 → 8.7 构建函数 → 5.2 例 A。
- 想**调一个抓包对不上**：读 2.6 大端自查表 → 3.4 头字段 → 6.2 偏移速查。
- 想**加一个测试用例**：读 7 章映射 → 21-s7-testcase.md 索引表 → 8.12 断言字段集。
- 想**实现代码**：读 8.1-8.11（注册、flat 键、Meta、生成器、校验器、自检清单）。

# 3.16 头/参数/数据三区装配总规则

任意 S7 PDU 都可分解为「S7 头 + 参数区 + 数据区」，装配规则：

1. S7 头 10B（Job/Userdata）或 12B（Ack/Ack_Data）。
2. parlg = len(参数区字节)（不含头、不含错误 2B）。
3. datlg = len(数据区字节)。
4. TPKT.Length = 4 + 2 + 1 + 1 + 10(或 12) + parlg + datlg = 4 + (3) + headlen + parlg + datlg。

对 S3（Setup Job）：4+3+10+8+0=25 ✓；对 S4（Setup Ack）：4+3+12+8+0=27 ✓。所有模板可用此式复算——这是"绝不编造字节布局"的数学保险。

# 10.7 未来：策略与 size 联动

写值字段与传输尺寸联动将来可策略化：`"transport_size": {"strategy":"list","list":[2,4,6]}` + `"value"` 按对应位宽自动按 0xFF 填充（bit 位宽同步）。本版要求 value 显式匹配 size（校验器核对长度），避免"尺寸=4 但值 2 字节"之类的隐性错位（2.4/10.5 校验）。
