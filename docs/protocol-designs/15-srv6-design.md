# SRv6 协议设计与测试用例

**生成时间**：2026-08-05
**版本**：v2.0.2
**规范来源**：RFC 8754（IPv6 Segment Routing Header，SRH，段路由头部）；RFC 8200（Internet Protocol, Version 6 Specification，IPv6 协议规范）§4.4 Routing Header；RFC 8986（SRv6 Network Programming，SRv6 网络编程）作为 SID 行为参考
**传输层**：IPv6 扩展头（Next Header = 43，Routing Type = 4），非独立传输层
**扩展表节点**：`srv6ProtRpt`（见 `docs/protocol-designs/00-unimplemented-list.md` 第 16 项附近）
**优先级**：P0

本文档遵循 `CLAUDE.md` 第 8 条测试策略，所有测试用例均从 RFC 章节 + Config 字段表派生，覆盖正向 / 负向 / 边界三类，每条用例独立且失败优先。v2.0.2 修复 v2.0.1 复审（`audit/15-srv6-audit-r2-v2.md`，9 问题：2 HIGH + 4 MEDIUM + 3 LOW）：L4 校验和伪头 DstIP 改用最终目的（RFC 8200 §8.1，H-SRV6-R4-1）、六帧 UDP 零校验和非法修正（H-SRV6-R4-2）、S16 ICMPv6 校验和 0xB6D9→0xB6D6（M-SRV6-R4-1）、S4/S14 行标 0x0070→0x0068（M-SRV6-R4-2）、S10 内层 UDP 头字段定义（M-SRV6-R4-3）、RFC 章节引用错号修正（M-SRV6-R4-4），及 VR-15/dt4/dt6/EXC-01 去重/端口缺省值等 LOW 项。v2.0.1 修复 v2.0.0 复审（`audit/15-srv6-audit-r1-v2.md`，21 问题：2 CRITICAL + 8 HIGH + 7 MEDIUM + 4 LOW）：HMAC TLV 字节数统一为 Length=38/总长 40（C-SRV6-R3-1）、End.DX6/End.B6.Encaps 外层 Next Header 59→41（C-SRV6-R3-2）、五帧 HexDump 的 IPv6 Payload Length 重算（H-SRV6-R3-1/8）、Hdr Ext Len 公式去除多余 -1（H-SRV6-R3-5）、Pad1 尾部填充规则（H-SRV6-R3-3）、Frames 视角递增语义（H-SRV6-R3-4）、SRHConfig.HdrExtLen 字段（H-SRV6-R3-6）、Direction=down 源节点视角限制（H-SRV6-R3-7）、Reduced 默认规则（H-SRV6-R3-2），及 MEDIUM/LOW 同步修订。v2.0.0 已系统性修复 v1.1 深度对抗审计报告（`audit/15-srv6-audit-deep.md`）发现的 21 个问题（7 CRITICAL + 6 HIGH + 5 MEDIUM + 3 LOW），核心修正为 RFC 8754 原文逐字核对后的反序存储模型、DstIP 关系、TLV 类型、Reduced SRH 语义、End* 地址更新公式。

---

## 1. 协议概述

### 1.1 RFC 来源与版本

| RFC | 标题 | 本设计引用范围 |
|-----|------|----------------|
| RFC 8754 | IPv6 Segment Routing Header (SRH) | §2 SRH 结构（含 Segment List 反序存储）、§2.1 TLV、§4 包处理、§4.1 源节点、§4.1.1 Reduced SRH、§4.3.1.1 SRH 处理伪代码、§8.2 IANA TLV 注册表 |
| RFC 8200 | Internet Protocol, Version 6 Specification | §3 IPv6 固定头、§4.2 TLV 编码（Hop-by-Hop）、§4.3 Hop-by-Hop 头、§4.4 Routing Header 通用规则 |
| RFC 8986 | SRv6 Network Programming | §4.2 End.X、§4.3 End.T、§4.4 End.DX6、§4.5 End.DX4、§4.8 End.DT4、§4.9 End.DT6、§4.13 End.B6.Encaps、§4.14 End.B6.Encaps.Red（参考用，trafficgen 不实现节点行为） |

trafficgen 仅引用 RFC 8754 / RFC 8200 作为字节级生成的依据；RFC 8986 仅用于 `SegType` 字段的语义命名，planner 不实现 End* 节点处理逻辑。

### 1.2 SRv6 与 IPv6 的关系

SRv6（Segment Routing over IPv6，基于 IPv6 的段路由）**不是独立传输层协议**，而是 IPv6 的扩展头（Extension Header，扩展头部），由 RFC 8754 定义。它复用 IPv6 的 Routing Extension Header（路由扩展头，RFC 8200 §4.4，Next Header = 43），并规定 Routing Type = 4，称为 SRH（Segment Routing Header，段路由头部）。

核心思想：源节点（source node，发出报文的节点）在 IPv6 报文中插入一段显式路径——Segment List（段列表，一组 128-bit IPv6 地址，每个地址代表一个网络指令 SID，Segment Identifier），途经的每个 SRv6 节点按列表顺序处理并转发。SRv6 的价值在于流量工程（Traffic Engineering，TE）、VPN、SDN 等场景下，无需中间节点维护流状态即可实现显式路径。

**协议栈位置**：

```
+----------+----------+----------+----------+----------+
| Ethernet | IPv6     | (HopByHop| SRH      | Inner    |
| 0x86DD   | 固定头   | 可选)    | Routing  | L4/L7    |
| 14B+VLAN | 40B      | 变长     | Type=4   | payload  |
+----------+----------+----------+----------+----------+
            NH=43 or  NH=43      NH=内层
            NH=0链式 HopByHop    6/17/58/59
```

- 无 Hop-by-Hop 时：IPv6(NH=43) → SRH(NH=内层)。
- 有 Hop-by-Hop 时：IPv6(NH=0) → HopByHop(NH=43) → SRH(NH=内层)。
- IPv6 固定头的 DstIP 由源节点设为 **Segment List[n-1]**（第一段，最高索引处）。

### 1.3 trafficgen 中的定位

trafficgen 生成的是 L2/L3/L4 帧序列。SRv6 在 trafficgen 中表现为"IPv6 + SRH 扩展头 + 内层协议（TCP/UDP/ICMPv6/IPv6/none）"的单包构造能力，而不是会话状态机（不像 SOCKS5/RADIUS 有握手-认证-数据-拆除的多阶段对话）。Planner 的职责是把用户配置的 Segment List、Segments Left、TLV 等字段组装成完整的 IPv6+SRH+payload 帧序列；多流场景下每流独立标识 = 外层 IPv6 SrcIP/DstIP + 内层 L4 端口对 + 内层协议号（6/17/58，外层 IPv6 Next Header=43 = SRH 不是 L4 协议号，不参与多流识别，详见 §10.1 FlowID 说明）。

**与现有 IPv6 Hop-by-Hop 扩展头（RFC 8200 §4.3，已实现）的关系**：两者都是 IPv6 扩展头，链式 Next Header 方式相同；区别在于 Hop-by-Hop 用 Type-Length-Value 选项列表（Pad1=Type 0，PadN=Type 1），SRH 用固定字段 + Segment List + 可选 TLV（Pad1=Type 0，PadN=Type 4，HMAC=Type 5，注意 SRH 与 Hop-by-Hop 的 PadN Type 不同）。builder 现有 `writeL3v6` 已支持 `L3Config.HopByHop`，新增 SRH 走类似路径，链式 Next Header = 43。

### 1.4 不实现的范围

- **节点处理逻辑**：trafficgen 是流量生成器，不模拟 SRv6 节点（路由器）的 SID 行为执行；`SegType` 字段仅用于标识"生成哪个节点视角的发出报文"，由 planner 生成对应的报文形态（如 End 节点视角下 SegmentsLeft 已递减、DstIP 已更新）。
- **HMAC 真实计算**：v1 仅生成 HMAC TLV 字段结构（Key ID + 全 0 digest 占位），不计算真实 HMAC-SHA-256。RFC 8754 §2.1.2 HMAC 计算需要预共享密钥与对端 DA 校验，超出 trafficgen 范围。
- **SR-MPLS over SRv6 嵌套**（RFC 8660/9256）：v1 不实现 MPLS 与 SRv6 的字节级嵌套。
- **GRE over SRv6 嵌套**（RFC 8986 §4.13 End.B6.Encaps）：v1 不实现 GRE 与 SRv6 的字节级嵌套。
- **PSP/USP/USD 风味**（RFC 8986 §5.1/§5.2/§5.3）：trafficgen 不实现节点处理，故不区分 PSP（Penultimate Segment Pop）/USP（Ultimate Segment Pop）/USD（Ultimate Segment Decapsulation）。

---

## 2. 数据类型与编码

### 2.1 IPv6 地址

128-bit（16 字节），RFC 8200 §3。文本表示 `x:x:x:x:x:x:x:x`（8 组 16-bit hex，冒号分隔），或 `::` 缩写。trafficgen 接受任意合法 IPv6 文本，由 `net.ParseIP` + `To16` 归一化为 16 字节大端字节序。IPv4-mapped IPv6（`::ffff:1.2.3.4`）在 SRv6 上下文中视为非法——SRv6 必须 IPv6。

### 2.2 Segment List（反序存储，RFC 8754 §2，关键）

**RFC 8754 §2 原文**：
> "the first element of the Segment List (Segment List[0]) contains the **last segment** of the SR Policy"
> "the second element contains the penultimate segment of the SR Policy, and so on"

**反序存储规则**：给定 SR Policy `<S1, S2, ..., Sn>`（S1 第一段先处理，Sn 最后一段=最终目的），Segment List 在 SRH 中的字节编码顺序为：

```
Segment List[0] = Sn   (最后一段，最终目的)
Segment List[1] = Sn-1 (倒数第二段)
...
Segment List[n-1] = S1 (第一段，第一个要处理的 segment)
```

整个 Segment List 按处理顺序**反序存储**。这一规则是 SRH 与 MPLS 标签栈的根本差异——MPLS 是 LIFO（后入先出，标签栈顶 = 第一段），SRH 是反序数组（数组首 = 最后一段）。

**示例**：SR Policy `<S1, S2, S3>`（S1→S2→S3 处理顺序）：
- Segment List 字节布局：`[S3, S2, S1]`（List[0]=S3，List[1]=S2，List[2]=S1）
- 源节点 DstIP = S1 = `Segment List[n-1]` = `Segment List[2]`（最高索引）
- SegmentsLeft 初值 = n-1 = 2
- LastEntry = n-1 = 2

### 2.3 DstIP 与 Segment List 关系（RFC 8754 §4.1）

**RFC 8754 §4.1 原文**：
> "The DA of the packet is set with the value of the **first segment**."

源节点发送时，IPv6 固定头的 DstIP = 第一段 = `Segment List[n-1]`（因反序存储，第一段在最高索引）。

**注意**：`DstIP = Segment List[n-1]`，**不是** `Segment List[0]`。这是 v2.0.0 修正 v1.1 的核心错误之一（v1.1 误写为 `DstIP = Segment List[0]`，混淆了数组索引方向）。

### 2.4 TLV 编码（RFC 8754 §2.1.1 + §8.2）

SRH TLV 格式（RFC 8754 §2.1.1）：

| Offset | 长度 | 字段 | 取值 |
|--------|------|------|------|
| 0 | 1 byte | Type | 见 §2.4.1 表 |
| 1 | 1 byte | Length | Value 字节数（不含 Type/Length，0..255） |
| 2 | 变长 | Value | TLV 内容 |

**Type 字段最高位（bit 7）语义**（RFC 8754 §2.1）：
- 0：TLV 数据不在途中改变（immutable en route）
- 1：TLV 数据可能在途中改变（mutable en route，Type 值 128..255）

Pad1 是特例：单字节（仅 Type=0），无 Length/Value。

#### 2.4.1 SRH TLV 类型表（RFC 8754 §8.2 IANA 注册表）

| Type | 名称 | 是否变化 en route | 说明 |
|------|------|-------------------|------|
| 0 | Pad1 | 否 | 单字节填充，无 Length/Value；RFC 8754 §2.1.1.1 |
| 1 | Reserved | — | 保留（draft 阶段曾有定义，RFC 发布时 Reserved） |
| 2 | Reserved | — | 保留 |
| 3 | Reserved | — | 保留 |
| **4** | **PadN** | 否 | N≥2 字节填充，Length = N-2，Value 全 0；RFC 8754 §2.1.1.2 |
| **5** | **HMAC** | 否 | 携带 HMAC Key ID + digest；RFC 8754 §2.1.2 |
| 6 | Reserved | — | 保留（draft 阶段曾有 HMAC-Sig 定义，RFC 发布时已删，不存在 HMAC-Sig TLV） |
| 124-126 | Experimentation and Test | 否 | 实验用 |
| 127 | Reserved | — | 保留（允许 Type 字段未来扩展） |
| 252-254 | Experimentation and Test | 是 | 实验用（mutable en route） |
| 255 | Reserved | — | 保留 |

**关键差异**（v2.0.0 修正 v1.1）：
- SRH PadN Type = **4**，不是 1。RFC 8200 §4.2 Hop-by-Hop 的 PadN 才是 Type = 1。两者是独立的 TLV 注册表，不能混用。
- SRH HMAC 由 TLV（Type=5）携带，**不是 SRH Flags 位**。RFC 8754 §2.1 SRH Flags 全部 8 位 Unused。
- HMAC-Sig TLV（Type=6）**不存在**。draft-ietf-6man-segment-routing-header 早期版本曾有定义，RFC 8754 发布时 Type=6 已 Reserved。

#### 2.4.2 Pad1（Type=0）

RFC 8754 §2.1.1.1：
> "A single Pad1 TLV MUST be used when a single byte of padding is required."
> "Must NOT be used if more than one consecutive byte is needed."

编码：单字节 `0x00`，无 Length 字段，无 Value 字段。

#### 2.4.3 PadN（Type=4）

RFC 8754 §2.1.1.2：
> "The PadN TLV MUST be used when more than one byte of padding is required."

编码：`Type(0x04) + Length(N-2) + (N-2) 字节 0`，总长 N 字节（N≥2）。

例：2 字节填充 → `04 00`；6 字节填充 → `04 04 00 00 00 00`。

#### 2.4.4 HMAC TLV（Type=5，RFC 8754 §2.1.2）

**8n 对齐要求**：HMAC TLV 起始偏移必须是 8 的倍数（RFC 8754 §2.1.2 "Alignment: 8n"）。若 SRH 中 HMAC TLV 之前有未对齐字节，需先 PadN 填充至 8 字节边界再放 HMAC。

| Offset | 长度 | 字段 | 取值 |
|--------|------|------|------|
| 0 | 1 byte | Type | 5 |
| 1 | 1 byte | Length | 后续字段总字节数（D+RES+KeyID+HMAC = 2+4+HMAC_len） |
| 2 | 1 bit | D | 1 = DA verification disabled（仅 reduced SRH，§4.1.1）；0 = 启用 |
| 2 | 15 bit | RESERVED | MUST be 0 |
| 4 | 4 byte | HMAC Key ID | 预共享密钥与算法标识 |
| 8 | 8/16/24/32 byte | HMAC | HMAC-SHA-256 截断 digest（8 的倍数，最大 32） |

**字节数核算**（RFC 8754 §2.1.2）：
- **Length 字段** = D+RES(2) + Key ID(4) + HMAC_len = 2 + 4 + HMAC_len。RFC 8754 §2.1.2 明文："Length: The length of the variable-length data in bytes"——即 Type/Length 之后的所有字节数，**不含** Type/Length 自身。
- **TLV 总长** = Type(1) + Length(1) + 2 + 4 + HMAC_len = 8 + HMAC_len。HMAC = 32 字节时：Length = **38 (0x26)**，TLV 总长 = **40 字节**；HMAC = 8 字节（最小）时：Length = 14，TLV 总长 = 16 字节。
- **8n 对齐**：TLV 总长恒为 8 的倍数（8+HMAC_len，HMAC_len ∈ {8,16,24,32}），故 HMAC TLV 起始偏移为 8 的倍数时（起始需由前置 PadN 保证），TLV 自身不会破坏 SRH 总长的 8 字节对齐。
- HMAC 长度由用户 TLV Value 长度决定（8/16/24/32，RFC 8754 §2.1.2 "HMAC: Keyed HMAC, in multiples of 8 octets, at most 32 octets"），与"截断"概念无关——v1 仅生成字段结构，digest 留全 0 占位（不计算真实 HMAC）。

### 2.5 字节序

SRH 所有多字节字段（Tag、Segment List 项）使用大端序（network byte order，RFC 8200 §3）。IPv6 地址本身是 16 字节大端序，无字节序转换问题。

---

## 3. 消息结构

### 3.1 IPv6 固定头部（RFC 8200 §3，40 字节）

| Offset (bit) | 长度 | 字段 | 取值 | 说明 |
|---------------|------|------|------|------|
| 0.0 | 4 bit | Version | 6 | IPv6 版本号 |
| 0.4 | 8 bit | Traffic Class | (DSCP<<2)\|(ECN&0x03) | 跨字节 0 高 4 bit（bit 4-7）+ 字节 1 低 4 bit（bit 0-3） |
| 1.4 | 20 bit | Flow Label | 0 | 跨字节 1 高 4 bit + 字节 2 + 字节 3 |
| 4 | 2 byte | Payload Length | 含 SRH + 内层 | 不含 IPv6 固定头 40 字节；大端 |
| 6 | 1 byte | Next Header | 43 (Routing) 或 0 (HopByHop) | 指向 SRH 或 HopByHop |
| 7 | 1 byte | Hop Limit | TTL 或 64 | 与 IPv4 TTL 同语义 |
| 8 | 16 byte | Source Address | src_ipv6 | 源节点 IPv6 地址 |
| 24 | 16 byte | Destination Address | segment_list[n-1] | **关键**：源节点发送时 DstIP = Segment List[n-1]（第一段，因反序存储在最高索引） |

**Traffic Class 编码**（RFC 8200 §3，builder 现有 `writeL3v6` 行 990-994）：
- 字节 0 = `(6 << 4) | (tc >> 4)`，其中 tc = (DSCP<<2)|(ECN&0x03)
- 字节 1 = `(tc << 4) | (flow >> 16)`，flow 默认 0
- 字节 2 = `flow >> 8`
- 字节 3 = `flow & 0xff`

**校验和说明**：IPv6 固定头**无校验和字段**（RFC 8200 §3："IPv6 headers do not have a checksum"）；SRH 作为扩展头同样不参与任何校验和计算。builder 的 SRH 路径**不得**新增/误跳 IPv6 头校验和逻辑——SRH 字段（Segment List、SegmentsLeft、DstIP 等）的修改不影响任何校验和；唯一需要计算校验和的是内层 L4（UDP/TCP/ICMPv6，见 §7.4 BYT-13/14/21，伪头规则见 BYT-13）。

**L4 伪头 DstIP 规则（SRv6 特有，RFC 8200 §8.1）**：当 IPv6 包带 Routing Header（含 SRH）时，UDP/TCP/ICMPv6 校验和伪头的 DstIP **必须使用最终目的地址**（final destination），**不是**外层 IPv6 头的 DstIP（第一段）。RFC 8200 §8.1 原文："the Destination Address used in the pseudo-header is that of the final destination. At the originating node, that address will be in the last element of the Routing header"。在 SRv6 场景下，反序存储使"Routing header 的最后一个元素"= `SegmentList[0]`（SR Policy 的最后一段，最终目的）。故源节点视角下：

- **L4 伪头 DstIP = `SegmentList[0]`（最终目的，SR Policy 最后一段）**；
- **不是** 外层 IPv6 DstIP（外层 DstIP = `SegmentList[n-1]` = 第一段，反序存储的最高索引）；
- 单段（n=1）时 `SegmentList[0] == SegmentList[n-1] == 外层 DstIP`，伪头 DstIP 与外层 DstIP 巧合相同，不暴露本规则；
- 多段（n>1）时两者不同，伪头必须用 `SegmentList[0]`，否则 tshark 按 RFC 8200 §8.1 校验会报 bad checksum。

builder 的 SRH 路径**不得**复用 `calculateIPv6PseudoHeader(config.L3.SrcIP, config.L3.DstIP, ...)`（该函数使用外层 DstIP），必须为伪头单独传入最终目的地址（`SegmentList[0]`）。中转节点（End 视角）发出的报文同样遵守此规则——伪头 DstIP 始终是 SR Policy 的最终目的（`SegmentList[0]`），不随 S15-S16 的 DstIP 更新而变化。

### 3.2 SRH 格式（RFC 8754 §2，Routing Type = 4）

| Offset | 长度 | 字段 | 取值 | 说明 |
|--------|------|------|------|------|
| 0 | 1 byte | Next Header | 6/17/58/41/59 | 内层协议：TCP=6、UDP=17、ICMPv6=58、IPv6=41（解封装/封装类，RFC 8986 §4.4 End.DX6 / §4.5 End.DX4 / §4.13 End.B6.Encaps / §4.14 End.B6.Encaps.Red）、NoNextHeader=59 |
| 1 | 1 byte | Hdr Ext Len | (总长/8)-1 | 以 8 字节为单位，**不含前 8 字节**；与 RFC 8200 §4.4 通用规则一致 |
| 2 | 1 byte | Routing Type | 4 | SRH 固定为 4 |
| 3 | 1 byte | Segments Left | 0..255 | 还未处理的 segment 数；源节点 = N-1 |
| 4 | 1 byte | Last Entry | N-1 或 N-2 | non-reduced SRH: N-1；reduced SRH: N-2（RFC 8754 §4.1.1） |
| 5 | 1 byte | Flags | 0x00 | RFC 8754 §2.1 全部 8 位 Unused，MUST be 0；HMAC 由 TLV（Type=5）携带，不由 Flags 表示 |
| 6 | 2 byte | Tag | 任意 16-bit | 大端；0 = 无标签 |
| 8 | 16·(N) byte | Segment List[0..N-1] | IPv6 地址数组 | **反序存储**（RFC 8754 §2）：List[0] = 最后一段（最终目的），List[N-1] = 第一段（同时写入 IPv6 DstIP） |
| 8+16N | 变长 | TLV（可选） | 见 §2.4 | HMAC TLV / PadN / 实验 TLV |

#### 3.2.1 Hdr Ext Len 计算

**RFC 8200 §4.4 通用公式**：
> "Length of the Routing header in 8-octet units, not including the first 8 octets."
> 实际头长度（字节） = (Hdr Ext Len + 1) × 8

**SRH 总长度** = 8（固定头：NH+HdrExtLen+RoutingType+SL+LastEntry+Flags+Tag）+ 16×N（Segment List）+ T（所有 TLV 字节，含 PadN 填充）

**Hdr Ext Len** = (SRH 总长度 / 8) - 1 = (8 + 16N + T) / 8 - 1 = 2N + T/8

其中 T 必须使 (16N + T) 是 8 的倍数（即 SRH 总长对齐 8 字节，由 PadN TLV 补齐）。**注意**：展开式 `2N + T/8` 已包含"总长/8 - 1"的全部语义（T 是 8 的倍数时 (8+16N+T)/8-1 = 2N + T/8），**不能再减 1**——验证：N=2、T=0 时 2N+T/8 = 4，(4+1)×8 = 40 = SRH 总长 ✓。

**简化公式**（无 TLV，T=0）：
- Hdr Ext Len = 2N
- SRH 总长 = 8 + 16N

**计算示例**：

| N（段数） | T（TLV 字节） | SRH 总长 | Hdr Ext Len | 验证 (Hdr Ext Len+1)×8 |
|-----------|---------------|----------|-------------|------------------------|
| 1 | 0 | 24 | 2 | (2+1)×8=24 ✓ |
| 2 | 0 | 40 | 4 | (4+1)×8=40 ✓ |
| 3 | 0 | 56 | 6 | (6+1)×8=56 ✓ |
| 2（reduced，省 1 段） | 0 | 24 | 2 | (2+1)×8=24 ✓ |
| 1 | 14（HMAC TLV，含 PadN） | 38→40（PadN 补齐 2 字节） | 4 | (4+1)×8=40 ✓ |
| 127 | 0 | 2040 | 254 | (254+1)×8=2040 ✓ |
| 128 | 0 | 2056 | 256 | **溢出**（uint8 上限 255） |

**N 上限推导**：Hdr Ext Len 是 uint8，最大 255。无 TLV 时 2N ≤ 255 → N ≤ 127.5 → N 上限 127（Hdr Ext Len=254）。N=128 时 Hdr Ext Len=256 溢出。

**Pad1/PadN 尾部填充规则**（RFC 8754 §2.1.1.1/.2，builder 自动执行，用户不可手动设置）：
- SRH 总长 mod 8 == 0：无需尾部填充；
- SRH 总长 mod 8 == 1：需尾部填充 **1 字节，必须用 Pad1**（Type=0，单字节 `00`，无 Length/Value；RFC 8754 §2.1.1.1 "A single Pad1 TLV MUST be used when a single byte of padding is required"）；
- SRH 总长 mod 8 ∈ {2,3,4,5,6,7}：需尾部填充 **N ≥ 2 字节，必须用 PadN**（Type=4，`04 (N-2) 00…`；RFC 8754 §2.1.1.2 "The PadN TLV MUST be used when more than one byte of padding is required"）。
- 例：SRH 总长 31（mod 8 = 7）→ 末尾 1 字节 Pad1 `00`，总长对齐到 32；SRH 总长 28（mod 8 = 4）→ 末尾 PadN `04 02 00 00` 4 字节，总长对齐到 32（S5 即此例）。
- 注意：HMAC TLV 总长恒为 8 的倍数（§2.4.4），因此只要 HMAC TLV 起始已 8n 对齐，尾部填充不会落在 HMAC 之后（见 §6.4/S4 与 §6.14/S14：SRH 总长 64 直接对齐，无需任何尾部填充）。

### 3.3 Reduced SRH（RFC 8754 §4.1.1）

**RFC 8754 §4.1.1 原文**：
> "A reduced SRH does not contain the **first segment** of the related SR Policy (the first segment is the one already in the DA of the IPv6 header)"
> "the Last Entry field is set to n-2, where n is the number of elements in the SR Policy"

**Reduced SRH 规则**：
- 省略 `Segment List[n-1]`（第一段，因为第一段已在 IPv6 DstIP 中）
- Last Entry = n-2（不是 n-1）
- Segments Left 仍 = n-1（RFC 8754 §4.1 通用规则不变）
- SRH 总长 = 8 + 16×(n-1)（比 non-reduced 少 16 字节）

**示例**：SR Policy `<S1, S2>`（n=2）：
- non-reduced：List = [S2, S1]，LastEntry=1，SL=1，DstIP=S1，Hdr Ext Len=4
- reduced：List = [S2]（仅 1 项，省略 S1），LastEntry=0，SL=1，DstIP=S1，Hdr Ext Len=2

**注意**：Reduced SRH 是 SRH 编码格式（任何 SID 都可用），与 End.B6.Encaps.Red（RFC 8986 定义的 SID 行为，封装时使用 reduced SRH）是两个概念。End.B6.Encaps.Red 在外层封装时**可以**使用 reduced SRH，但 reduced SRH 不是 End.B6.Encaps.Red 专属。

### 3.4 End* 行为类型（RFC 8986，参考用）

trafficgen 不实现节点行为（那是路由器控制平面逻辑），但需要在配置中标识"模拟哪个节点对 SRH 的处理结果"——即生成"该节点处理后的报文形态"。下表列出 29 个 End* 行为，配置项 `seg_type` 选择其一：

| 行为名 | 含义 | 生成的报文形态 |
|--------|------|----------------|
| End | 普通 segment 终结 | SL--，DstIP = SegmentList[SL_new]（RFC 8754 §4.3.1.1 S15-S16） |
| End.X | 邻接转发 | 同 End，但强制指定下一跳 L2 邻接 |
| End.T | 特定表查找 | 同 End，查找指定 IPv6 路由表 |
| End.DX4 | 解封装到 IPv4 | 移除外层 IPv6+SRH，内层为 IPv4 包 |
| End.DX6 | 解封装到 IPv6 | 移除外层 IPv6+SRH，内层为 IPv6 包 |
| End.DX2 | 解封装到 L2 | 移除外层，内层为以太网帧 |
| End.DT4 | 解封装 IPv4 表查找 | 移除外层，IPv4 包按表转发 |
| End.DT6 | 解封装 IPv6 表查找 | 移除外层，IPv6 包按表转发 |
| End.DT2U | 解封装 IPv6 单播表 | 移除外层，IPv6 单播转发 |
| End.DT2M | 解封装 IPv6 多播表 | 移除外层，IPv6 多播转发 |
| End.B6 | Binding SID，外插 SRH | 在内层 IPv6 包前再插一层 SRH |
| End.B6.Encaps | Binding SID，封装新外层 | 在外层再封装一层 IPv6+SRH |
| End.B6.Encaps.Red | B6.Encaps 简化版 | 同 End.B6.Encaps 但外层用 reduced SRH |
| End.BM | Binding MPLS | 外插 MPLS 标签栈 |
| End.Un / End.UA / End.UX / End.UT | unicast-destined 变体 | 与 End/End.A/End.X/End.T 类似但内层 unicast |
| End.uN / End.uA / End.uX / End.uT | uSID 变体 | 128-bit 内嵌多个微 segment |
| End.B / End.D / End.O / End.LN / End.UP / End.UN / End.U | 其他行为 | 见 RFC 8986 |

**trafficgen 限制**：v1 实现重点支持 9 个 seg_type：End / End.X / End.DX6 / End.DX4 / End.B6 / End.B6.Encaps / End.B6.Encaps.Red / End.DT6 / End.DT4。其余 20 个 seg_type 仅做格式生成不做语义验证（用户可自由配置 SegmentList/SegmentsLeft，但 Validate 对未支持的行为只做 seg_type 字符串合法性检查，不做 End* 语义校验）。

---

## 4. 状态机

SRv6 **没有会话状态机**。它是一个"逐包处理"的转发指令——每个节点收到带 SRH 的 IPv6 包后，做一次性处理然后转发。trafficgen 关注的是**生成报文**，所以"状态机"在这里是一个**单包 SRH 处理流程图**，描述不同节点视角下报文应有的形态。

### 4.1 源节点（Source Node）流程

```
1. 构造 SR Policy <S1, S2, ..., Sn>（S1 先处理，Sn 最后）
2. Segment List 反序存储：List[0]=Sn, List[1]=Sn-1, ..., List[n-1]=S1
3. IPv6 DstIP = S1 = List[n-1]
4. SegmentsLeft = n-1
5. LastEntry = n-1（non-reduced）或 n-2（reduced，省略 List[n-1]）
6. Flags = 0x00（RFC 8754 §2.1 全 8 位 Unused）
7. RoutingType = 4
8. Hdr Ext Len = 2N（无 TLV）或 2N + T/8（有 TLV）
9. NextHeader = 内层协议（6/17/58/41/59）
10. 插入 SRH：IPv6(NH=43 或 0 链 HopByHop) → SRH(NH=内层) → 内层
11. 发送
```

### 4.2 中间节点（Transit / End*）流程

RFC 8754 §4.3.1.1 SRH 处理伪代码（关键步骤）：

```
S01. When an SRH is processed {
S02.   If Segments Left == 0 {
S03.     Proceed to process next header
S04.   }
S05.   Else {
S06.     If local configuration requires TLV processing {
S07.       Perform TLV processing
S08.     }
S09.     max_last_entry = (Hdr Ext Len / 2) - 1
S10.     If ((Last Entry > max_last_entry) or
S11.          (Segments Left > (Last Entry+1))) {
S12.       Send ICMP Parameter Problem, Code 0; discard packet
S13.     }
S14.     Else {
S15.       Decrement Segments Left by 1.
S16.       Copy Segment List[Segments Left] to DA of IPv6 header.
S17.       If IPv6 Hop Limit <= 1 {
S18.         Send ICMP Time Exceeded; discard packet
S19.       }
S20.       Else {
S21.         Decrement Hop Limit by 1
S22.         Resubmit packet to IPv6 module for transmission to new DA
S23.       }
S24.     }
S25.   }
S26. }
```

**关键公式**（RFC 8754 §4.3.1.1 S15-S16）：
- S15：`SL_new = SL_old - 1`（先减 1）
- S16：`DA = Segment List[SL_new]`（用减 1 后的新 SL 值索引）

**地址更新公式**：`DA = Segment List[SL_new]`，其中 `SL_new = SL_old - 1`。

**注意**：不要用 `LastEntry - SegmentsLeft + 1` 表达（v1.1 错误公式）——在 reduced SRH 下 LastEntry = n-2 ≠ n-1，该公式会索引错误段。统一用 `SL_new` 索引，与 RFC 8754 §4.3.1.1 S15-S16 一致。

### 4.3 终节点（Final Segment）流程

- SegmentsLeft == 0
- 移除 SRH（PSP）或保留（USP）
- 处理内层 payload

### 4.4 trafficgen 生成视角

每条 FlowSpec.SRv6 对应**一个节点视角的报文**。用户通过 SegType + SegmentsLeft 组合指定"模拟哪个节点的发出报文"：

| 视角 | SegType | SegmentsLeft | DstIP |
|------|---------|--------------|-------|
| 源节点 | "end" | n-1（默认） | SegmentList[n-1] |
| 中间节点 S1 处理后 | "end" | n-2（显式） | SegmentList[n-2]（S15-S16 公式） |
| 中间节点 S2 处理后 | "end" | n-3（显式） | SegmentList[n-3] |
| 终节点 | "end" | 0 | SegmentList[0]（最后一段，最终目的） |

多节点序列由用户在策略层用多条 FlowSpec 串联（或后续 SubFlow 扩展），planner 本身不跨节点串联。

---

## 5. 配置类型定义

新增 `SRv6Config`（结构体）挂到 `FlowSpec.SRv6 *SRv6Config`（指针，nil 表示不启用）。builder 侧 `L3Config` 新增 `SRH *SRHConfig`（指针），由 planner 在 Plan 时填入；builder 的 `writeL3v6` 检测到非 nil 时，在 IPv6 固定头与内层 payload 之间插入 SRH，Next Header 链 IPv6(NH=43) → SRH(NH=内层)。

### 5.1 SRv6Config（用户层 FlowSpec.SRv6）

```go
// SRv6Config configures the SRv6 Segment Routing Header (RFC 8754). When
// non-nil, the planner emits one IPv6 packet per flow carrying an SRH with
// the configured Segment List. SRv6 is an IPv6 extension header (Next
// Header = 43, Routing Type = 4), NOT a standalone transport protocol.
type SRv6Config struct {
    // SrcIPv6 is the outer IPv6 source address. Empty = spec.SrcIP (must
    // be IPv6).
    SrcIPv6 string `json:"src_ipv6,omitempty"`

    // DstIPv6 is the outer IPv6 destination as written by the source node.
    // Empty = SegmentList[n-1] (the first segment to process, stored at
    // the highest index because the list is in reverse order per RFC 8754
    // §2). RFC 8754 §4.1 requires DA = first segment.
    DstIPv6 string `json:"dst_ipv6,omitempty"`

    // SegmentList is the SRv6 segment list in user-facing processing order:
    // entry 0 is the FIRST segment to process, entry n-1 is the LAST
    // segment (final destination). The planner REVERSES this list when
    // writing to the wire (RFC 8754 §2: "the first element of the
    // Segment List (Segment List[0]) contains the last segment of the SR
    // Policy"). 1..127 entries (Hdr Ext Len 8-bit limit: 127 segments →
    // Hdr Ext Len = 254 ≤ 255; 128 segments → Hdr Ext Len = 256 overflow).
    // Type []string at the user layer; the planner parses each entry to
    // 16-byte big-endian once and hands the builder the parsed form (see
    // §5.2 SRHConfig.SegmentList [][]byte) — arbitrary IPv6 text is
    // accepted, never performed per-packet.
    SegmentList []string `json:"segment_list"`

    // SegmentsLeft is the Segments Left field. Source node sets it to
    // len(SegmentList)-1. 0 means "this packet has reached its final
    // segment" (single-segment case, or terminal-node view).
    //
    // NOTE: uint8 zero value = 0 cannot distinguish "user explicitly set 0"
    // from "user did not set". Use SegmentsLeftPtr (*uint8) below — nil
    // means "use default len(SegmentList)-1"; non-nil (including *uint8(0))
    // means "user explicitly set this value".
    SegmentsLeft    uint8  `json:"segments_left,omitempty"`
    SegmentsLeftPtr *uint8 `json:"segments_left_ptr,omitempty"`

    // LastEntry is the index of the last Segment List entry. Source node
    // sets it to len(SegmentList)-1 (non-reduced) or len(SegmentList)-2
    // (reduced SRH, RFC 8754 §4.1.1). 0..126 (non-reduced) / 0..125
    // (reduced). Empty → default per Reduced flag.
    LastEntry    uint8  `json:"last_entry,omitempty"`
    LastEntryPtr *uint8 `json:"last_entry_ptr,omitempty"`

    // Reduced indicates whether to emit a reduced SRH (RFC 8754 §4.1.1).
    // true = omit SegmentList[n-1] (first segment, already in DstIP),
    // LastEntry = len(SegmentList)-2. false (default) = full SegmentList,
    // LastEntry = len(SegmentList)-1.
    // Default value rule: Reduced defaults to true when SegType ==
    // "end.b6.encaps.red", false otherwise (design §5.3 S11). An explicit
    // user value overrides the default.
    Reduced bool `json:"reduced,omitempty"`

    // Flags is the 8-bit SRH Flags field. RFC 8754 §2.1 defines ALL 8
    // bits as Unused (MUST be 0 on transmission). HMAC is carried by the
    // HMAC TLV (Type=5), not by a flag bit. Validate rejects any non-zero
    // Flags value. 0x00 only.
    Flags uint8 `json:"flags,omitempty"`

    // Tag is the 16-bit SRH Tag field. 0 = no tag. Big-endian on wire.
    Tag uint16 `json:"tag,omitempty"`

    // SegType selects which End* behavior to emulate (design §3.4). The
    // planner emits the post-processing packet form for the chosen type.
    // "" / "end" / "end.x" / "end.t" / "end.dx4" / "end.dx6" /
    // "end.dx2" / "end.b6" / "end.b6.encaps" / "end.b6.encaps.red" /
    // "end.dt4" / "end.dt6" / "end.dt2u" / "end.dt2m" / "end.bm" /
    // "end.un" / "end.ua" / "end.ux" / "end.ut" / "end.uN" / "end.uA" /
    // "end.uX" / "end.uT" / "end.b" / "end.d" / "end.o" / "end.ln" /
    // "end.up" / "end.un" / "end.u".
    SegType string `json:"seg_type,omitempty"`

    // PayloadProtocol is the inner protocol carried after the SRH.
    // "tcp" / "udp" / "icmpv6" / "ipv6" / "none". "" = "udp" (or "tcp"
    // when spec.TCP is set). "ipv6" = Next Header = 41 (IPv6
    // encapsulation): REQUIRED for seg_type ∈ 解封装/封装类
    // {end.dx6, end.b6, end.b6.encaps, end.b6.encaps.red} carrying an
    // inner IPv6 packet (RFC 8986 §4.4/§4.13/§4.14 requires Upper-Layer header
    // type 41 for IPv6-in-IPv6; Next Header = 59 (No Next Header) is
    // discarded per RFC 8200 §4.7). "none" = Next Header = 59 (No Next
    // Header), only valid with empty InnerPayload.
    PayloadProtocol string `json:"payload_protocol,omitempty"`

    // InnerPayload is the inner L4 payload bytes. nil = spec.Payload.
    // For seg_type=end.dx6/end.b6/etc., MUST be a valid IPv6 packet (≥ 40
    // bytes starting with IPv6 header). PayloadProtocol MUST be "ipv6" in
    // that case (Next Header = 41, RFC 8986).
    InnerPayload []byte `json:"inner_payload,omitempty"`

    // InnerSrcPort / InnerDstPort are the inner L4 ports. 0 = spec.SrcPort
    // / spec.DstPort. The user MUST explicitly set InnerSrcPort to a
    // non-zero value if it differs from spec.SrcPort; a zero value is
    // indistinguishable from "user did not set", so the planner always
    // uses spec.SrcPort/spec.DstPort for 0 values.
    InnerSrcPort uint16 `json:"inner_src_port,omitempty"`
    InnerDstPort uint16 `json:"inner_dst_port,omitempty"`

    // TLV is the optional TLV list appended after the Segment List. Pad1
    // (Type=0) / PadN (Type=4) are auto-inserted by the builder for 8-byte
    // alignment — users should not add them manually. HMAC TLV (Type=5)
    // requires 8n alignment (RFC 8754 §2.1.2); the builder inserts PadN
    // before HMAC if needed.
    TLV []SRv6TLV `json:"tlv,omitempty"`

    // Frames is the number of SRv6 packets emitted (each gets a distinct
    // Hop Limit / inner IP ID when applicable). 0 = 1. Must be >= 0
    // (Validate rejects negative; JSON int allows -1 which Validate
    // catches as "frames must be >= 0").
    // NOTE: Frames does NOT vary the SRH content — every frame of one
    // FlowSpec carries the same SegmentList/SegmentsLeft/DstIP. "视角递增"
    // (per-frame SegmentsLeft-- / DstIP update per RFC 8754 §4.3.1
    // S15-S16) is expressed by multiple FlowSpecs with explicit
    // segments_left_ptr + dst_ipv6 (design §6.15 S15), never by Frames.
    Frames int `json:"frames,omitempty"`

    // Direction is the flow direction: "up" (default) or "down" (swaps
    // MACs, IPs, ports, AND reverses SegmentList so the reverse-flow
    // still satisfies RFC 8754 §4.1 source-node rule DstIP = new
    // List[n-1]). Direction="down" requires the source-node view
    // (SegmentsLeftPtr MUST be nil — Validate rejects the combination,
    // design §5.4); transit-node views are undefined under list reversal.
    Direction string `json:"direction,omitempty"`
}

// SRv6TLV is one SRH TLV (RFC 8754 §2.1.1 + §8.2).
type SRv6TLV struct {
    // Type is the 8-bit TLV type. RFC 8754 §8.2 defines:
    //   0 = Pad1 (auto-inserted by builder, do not set manually)
    //   1, 2, 3, 6 = Reserved (draft-era leftovers, MUST NOT be used)
    //   4 = PadN (auto-inserted by builder, do not set manually)
    //   5 = HMAC (8n alignment, see §2.4.4)
    //   124-126, 252-254 = Experimentation and Test
    //   127, 255 = Reserved
    // Pad1/PadN are NEVER settable by users — the builder auto-inserts
    // them during 8-byte tail alignment (Pad1 for a single byte, PadN for
    // ≥ 2 bytes, RFC 8754 §2.1.1.1/.2; design §3.2.1).
    Type  uint8  `json:"type"`
    Value []byte `json:"value,omitempty"` // empty for Pad1
}
```

### 5.2 SRHConfig（builder 层 L3Config.SRH）

```go
// SRHConfig is the builder-side SRH (RFC 8754). When non-nil, the builder
// inserts the SRH between the IPv6 fixed header and the inner L4 payload,
// and chains it via Next Header = 43 in the IPv6 fixed header. SegmentList
// here is ALREADY in wire order (reverse of user-facing order) — the
// planner reverses it before handing to builder.
type SRHConfig struct {
    NextHeader   uint8     // inner protocol: 6/17/58/41/59
    RoutingType  uint8     // always 4 (SRH); builder rejects non-4
    SegmentsLeft uint8
    LastEntry    uint8
    Flags        uint8     // MUST be 0x00 (RFC 8754 §2.1 all bits Unused)
    Tag          uint16
    SegmentList  [][]byte  // wire order (reversed): [0]=last segment, [n-1]=first segment; each entry is 16-byte big-endian, parsed ONCE by the planner (net.ParseIP at Plan time, never per-packet)
    TLV          []SRv6TLV // same SRv6TLV type as the user layer (§5.1); planner copies user TLVs verbatim (byte-encoding responsibility stays with the builder)
    Reduced      bool      // true = reduced SRH (RFC 8754 §4.1.1)
    HdrExtLen    uint8     // RFC 8200 §4.4: (SRH total length / 8) - 1. Computed BY the planner at Plan time from SegmentList + TLV lengths, handed to the builder; the builder recomputes it from the bytes it actually serializes and rejects a mismatch (design §7.7 EXC-01). The planner MUST NOT expose HdrExtLen to users (it is not a user-configurable field).
}
```

### 5.2.1 默认 payload 长度（§6 所有 HexDump 场景的全局声明）

§6 每个场景的 HexDump 都以一个固定的**内层 payload 缺省长度**为字节基准。全局规则：**内层 UDP/TCP payload 缺省为 0 字节**（UDP 数据报仅 8 字节头，Length 字段 = 8；TCP 段仅 20 字节头）。例外（显式声明）：S1 的 UDP payload = 8 字节（`"12345678"`）、S6 内层 UDP payload = 8 字节（`"12345678"`）、S16 的 ICMPv6 数据 = 8 字节。若实现选择其他 payload 长度，必须同步重算该场景的 IPv6 Payload Length 与 UDP/TCP/ICMPv6 校验和（见 §7.4 BYT-12/13/14/21 的"Payload Length == SRH + L4 + payload"断言）。

**内层 L4 端口缺省值**（L-SRV6-R4-3）：内层 UDP/TCP 的 SrcPort/DstPort = `spec.SrcPort`/`spec.DstPort`（§5.1 InnerSrcPort/InnerDstPort 规则：Inner* 为 0 时取 spec 值）。spec 未显式配置端口时端口 = 0（§6 各场景未列出的端口一律按此规则）。S4/S14/S5/S7/S15/S10 的内层 UDP 端口按此规则取值（S1 显式 inner_dst_port=53，S2/S12 显式 inner_dst_port，其余场景 spec 端口默认 0）。

**内层 L4 校验和缺省值**（H-SRV6-R4-2）：**UDP over IPv6 必须计算校验和（RFC 8200 §8.1），零校验和非法**（"whenever originating a UDP packet, an IPv6 node must compute a UDP checksum over the packet and the pseudo-header"；"IPv6 receivers must discard UDP packets containing a zero checksum"）。计算得 0 时写 **0xFFFF** 替代（与 builder 现有 `calculateUDPChecksum` 的 0→0xFFFF 实现一致，builder.go ~1300 行）。伪头规则见 §3.1 / BYT-13：DstIP = 最终目的（`SegmentList[0]`）。TCP over IPv6 同样禁止零校验和（RFC 8200 §8.1）。使用符号化地址的场景（S4/S5/S7/S10/S14/S15 的 fc00:s1::1 等占位地址）无法预先给出数值，HexDump 中 UDP 头以"<UDP 头 8 字节>"占位，**校验和数值由 builder 按上述规则计算**，BYT 断言时按伪头公式重算。
```

### 5.3 默认值规则

- **S1**（用户 > 自动 > 不输出）：每个字段用户值优先；空则按下面规则默认。
- **S2** SrcIPv6 空 → spec.SrcIP（必须 IPv6，否则 Validate 报错 "src_ipv6 must be IPv6"）。
- **S3** DstIPv6 空 → SegmentList[n-1]（第一段，反序存储的最高索引；若 SegmentList 也空 → 报错）。
- **S4** SegmentsLeftPtr=nil → 默认 len(SegmentList)-1（源节点初始值）。SegmentsLeftPtr 非 nil（含 *uint8(0)）→ 使用显式值，用于中间节点/终节点视角。
- **S5** LastEntryPtr=nil → non-reduced SRH: len(SegmentList)-1；reduced SRH (Reduced=true): len(SegmentList)-2（RFC 8754 §4.1.1）。
- **S6** PayloadProtocol 空 → "udp"（或 spec.TCP 非空时 "tcp"）。
- **S7** SegType 空 → "end"（最普通行为，仅做 SegmentsLeft-- 转发）。
- **S8** Flags 空 → 0x00；Tag 空 → 0x0000；Reduced 空 → false。
- **S9** Frames 空 → 1。
- **S10** Direction 空 → "up"。
- **S11** **Reduced 默认值**：`SegType == "end.b6.encaps.red"` 时默认 **true**；否则默认 false（§5.1 Reduced 注释）。用户显式配 `reduced` 时以用户值为准（显式覆盖默认）。此规则消除"只配 seg_type=end.b6.encaps.red 不配 reduced"时 LastEntry 默认值的不确定性：S5（LastEntryPtr=nil）按最终 Reduced 值取 len-2（reduced）或 len-1（non-reduced）。

### 5.4 Direction="down" 反向流语义

Direction="down" 时，planner 做以下变换以保持 RFC 8754 §4.1 源节点规则：

1. SrcIP ↔ DstIP 交换
2. SegmentList 整体反转（原 List[n-1] 变 List[0]，原 List[0] 变 List[n-1]）
3. SegmentsLeft 重置为 n-1
4. DstIP = 反转后 List[n-1] = 原 List[0] = 原最终目的
5. MAC 源/目交换
6. L4 端口交换

这样反向流仍满足 RFC 8754 §4.1（DstIP = SegmentList[n-1] = 第一段）。

**限制（v1）**：Direction="down" **仅支持源节点视角**——`SegmentsLeftPtr` 必须为 nil（SegmentsLeft 使用默认 n-1），否则 Validate 报错 `"direction=down requires source-node view (segments_left not set)"`。原因：反转后的 SegmentList 只对源节点规则（DstIP = 新 List[n-1]）自洽；End 中转视角下"用户按正向路径配的 SegmentsLeft/DstIP 对应关系"在反转流中没有定义（S15-S16 的 DstIP 更新公式 `DA = List[SL_new]` 依赖未反转的 List 与显式 dst_ipv6 的对应，反转后无规则可循）。`seg_type` 为 End* 类（含 end.dx6 等解封装/封装类，其内层包不受 Direction 影响）时可配 down，但只改变外层 IPv6 源/目的与 SegmentList 方向。

---

## 6. 包序列场景（HexDump S1-S16）

每个场景先列字段构成，再写 HexDump，验证 Hdr Ext Len = (总长度/8) - 1。所有 HexDump 以 Ethernet+VLAN 剥离后的 IPv6 报文为起点（offset 0 = IPv6 头第一字节）。HexDump 中 `xx` 代表省略的 16 字节 IPv6 地址（具体值见各场景配置）。

### 6.1 S1：单段 SRH（non-reduced）

**配置**：
```json
{
  "src_ip": "fc00:1::1",
  "dst_ip": "fc00:2::2",
  "srv6": {
    "segment_list": ["fc00:2::2"],
    "seg_type": "end",
    "payload_protocol": "udp",
    "inner_dst_port": 53
  }
}
```

**字段构成**：
- SegmentList（用户顺序）：[fc00:2::2]（1 段，n=1）
- SegmentList（wire 反序）：[fc00:2::2]（1 段反转仍是它本身）
- DstIP = SegmentList[n-1] = SegmentList[0] = fc00:2::2
- SegmentsLeft = n-1 = 0
- LastEntry = n-1 = 0
- Flags = 0x00
- Hdr Ext Len = 2N = 2×1 = 2
- SRH 总长 = 8 + 16×1 = 24 字节
- NextHeader = 17（UDP）

**HexDump**（offset 0-39 IPv6 头，40-63 SRH 24 字节，64-79 UDP 头+payload）：

```
0000  60 00 00 00 00 28 2b 40 fc 00 00 00 00 00 00 00
0010  00 00 00 00 00 00 00 01 fc 00 00 00 00 00 00 00
0020  00 00 00 00 00 00 00 02 11 02 04 00 00 00 00 00
0030  fc 00 00 00 00 00 00 00 00 00 00 00 00 00 00 02   <- List[0]=fc00:2::2 (= DstIP)
0040  30 39 00 35 00 10 06 84 31 32 33 34 35 36 37 38   <- UDP: SP=12345,DP=53,Len=16,Cksum=0x0684 + payload "12345678"
```

**字段验证**：
- offset 0-3：`60 00 00 00` = Version=6, TC=0, Flow=0
- offset 4-5：`00 28` = PayloadLength = 40（24 SRH + 8 UDP 头 + 8 payload）✓
- offset 6：`2b` = 43 = NextHeader=Routing ✓
- offset 7：`40` = 64 = HopLimit ✓
- offset 8-23：SrcIP = fc00:1::1
- offset 24-39：DstIP = fc00:2::2 = SegmentList[n-1] = SegmentList[0]（n=1 时最高索引即 0）✓
- offset 40：`11` = 17 = SRH.NextHeader=UDP ✓
- offset 41：`02` = 2 = Hdr Ext Len，(2+1)×8 = 24 = SRH 总长 ✓
- offset 42：`04` = 4 = RoutingType ✓
- offset 43：`00` = 0 = SegmentsLeft（= n-1 = 0）✓
- offset 44：`00` = 0 = LastEntry（= n-1 = 0）✓
- offset 45：`00` = 0 = Flags=0 ✓
- offset 46-47：`00 00` = Tag=0 ✓
- offset 48-63：SegmentList[0] = fc00:2::2（n=1 时该段既是第一段也是最后一段，反序不变）✓
- DstIP（offset 24-39）= SegmentList[0]（offset 48-63）= fc00:2::2 ✓
- offset 64-65：`30 39` = UDP SrcPort=12345；offset 66-67：`00 35` = DstPort=53 ✓
- offset 68-69：`00 10` = UDP Length=16（8 头 + 8 payload）✓
- offset 70-71：`06 84` = UDP Checksum=0x0684（伪头 SrcIP=fc00:1::1 + DstIP=最终目的=SegmentList[0]=fc00:2::2 + Upper-Layer Length=16 + NH=17，RFC 8200 §8.1；n=1 时最终目的 = 外层 DstIP；UDP over IPv6 必须计算校验和，零校验和非法，见 §5.2.1）✓

### 6.2 S2：多段 SRH（3 段，反序存储验证）

**配置**：
```json
{
  "srv6": {
    "src_ipv6": "fc00:a::1",
    "segment_list": ["fc00:s1::1", "fc00:s2::1", "fc00:b::1"],
    "seg_type": "end",
    "payload_protocol": "tcp",
    "inner_dst_port": 8080
  }
}
```

**字段构成**：
- 用户 SegmentList：[fc00:s1::1, fc00:s2::1, fc00:b::1]（S1 先处理，B 最后）
- wire SegmentList（反序）：[fc00:b::1, fc00:s2::1, fc00:s1::1]（List[0]=B 最后一段，List[2]=S1 第一段）
- DstIP = SegmentList[n-1] = SegmentList[2] = fc00:s1::1（第一段）
- SegmentsLeft = n-1 = 2
- LastEntry = n-1 = 2
- Flags = 0x00
- Hdr Ext Len = 2N = 6
- SRH 总长 = 8 + 16×3 = 56 字节
- NextHeader = 6（TCP）
- 内层 TCP：SrcPort=0、DstPort=0（spec 端口默认 0，§5.2.1）、校验和由 builder 按伪头计算（DstIP=最终目的=SegmentList[0]=fc00:b::1，RFC 8200 §8.1；TCP over IPv6 禁止零校验和，见 §5.2.1），负载为空

**HexDump**（offset 0-39 IPv6 头，40-95 SRH 56 字节，96+ TCP；TCP 负载为空）：

```
0000  60 00 00 00 00 4c 2b 40 fc 00 00 00 00 00 00 00
0010  00 00 00 00 00 00 00 01 fc 00 00 00 00 00 00 00
0020  00 00 00 00 00 s1 00 01 06 06 04 02 00 00 00 00
0030  fc 00 00 00 00 00 00 00 00 00 00 00 00 00 00 b1   <- List[0]=fc00:b::1 (最后一段)
0040  fc 00 00 00 00 00 00 00 00 00 00 00 00 00 s2 01   <- List[1]=fc00:s2::1 (中间段)
0050  fc 00 00 00 00 00 00 00 00 00 00 00 00 00 s1 01   <- List[2]=fc00:s1::1 (第一段)
0060  <TCP 头 20 字节>
```

（注：`b1`/`s2 01`/`s1 01` 是简写，实际是 `fc00:b::1` / `fc00:s2::1` / `fc00:s1::1` 的完整 16 字节；以下场景同此简写约定）

**验证**：
- offset 4-5 = `00 4c` = 76 = PayloadLength（56 SRH + 20 TCP 头，TCP 负载为空）✓
- offset 6 = `2b` = 43 = NextHeader=Routing ✓
- offset 40 = `06` = 6 = SRH.NextHeader=TCP ✓
- offset 41 = `06` = 6 = Hdr Ext Len，(6+1)×8 = 56 = SRH 总长 ✓
- offset 42 = `04` = 4 = RoutingType ✓
- offset 43 = `02` = 2 = SegmentsLeft ✓
- offset 44 = `02` = 2 = LastEntry ✓
- offset 45 = `00` = Flags=0 ✓
- offset 46-47 = `00 00` = Tag=0 ✓
- offset 48-63 = List[0] = fc00:b::1（最后一段，反序存储在最低索引）✓
- offset 80-95 = List[2] = fc00:s1::1（第一段，反序存储在最高索引）= DstIP（offset 24-39）✓

### 6.3 S3：Reduced SRH（2 段，省略第一段）

**配置**：
```json
{
  "srv6": {
    "src_ipv6": "fc00:a::1",
    "segment_list": ["fc00:s1::1", "fc00:s2::1"],
    "reduced": true,
    "seg_type": "end.b6.encaps.red",
    "payload_protocol": "udp"
  }
}
```

**字段构成**：
- 用户 SegmentList：[fc00:s1::1, fc00:s2::1]（n=2，S1 先处理，S2 最后）
- wire SegmentList（反序 + reduced 省略 List[n-1]）：[fc00:s2::1]（仅 1 项，省略 S1=List[1]）
- DstIP = SegmentList[n-1] = fc00:s1::1（第一段，已在 DstIP 中，故 SRH 中省略）
- SegmentsLeft = n-1 = 1（不变）
- LastEntry = n-2 = 0（reduced SRH，RFC 8754 §4.1.1）
- Flags = 0x00
- Hdr Ext Len = 2×(n-1) = 2×1 = 2（reduced SRH 少 16 字节）
- SRH 总长 = 8 + 16×1 = 24 字节
- NextHeader = 17（UDP）

**HexDump**（offset 0-39 IPv6 头，40-63 SRH 24 字节，64+ UDP）：

```
0000  60 00 00 00 00 20 2b 40 fc 00 00 00 00 00 00 00
0010  00 00 00 00 00 00 00 01 fc 00 00 00 00 00 00 00
0020  00 00 00 00 00 s1 00 01 11 02 04 01 00 00 00 00
0030  fc 00 00 00 00 00 00 00 00 00 00 00 00 00 s2 01
0040  <UDP 头 8 字节> <UDP payload>
```

**验证**：
- offset 4-5 = `00 20` = 32 = PayloadLength（24 SRH + 8 UDP 头）✓
- offset 24-39 = DstIP = fc00:s1::1（第一段，省略自 SRH）✓
- offset 40 = `11` = 17 = SRH.NextHeader=UDP ✓
- offset 41 = `02` = 2 = Hdr Ext Len，(2+1)×8 = 24 = SRH 总长 ✓
- offset 42 = `04` = 4 = RoutingType ✓
- offset 43 = `01` = 1 = SegmentsLeft（= n-1 = 1，不变）✓
- offset 44 = `00` = 0 = LastEntry（= n-2 = 0，reduced）✓
- offset 45 = `00` = Flags=0 ✓
- offset 48-63 = List[0] = fc00:s2::1（唯一一项，省略了 List[n-1]=S1）✓

### 6.4 S4：HMAC TLV（Type=5，含 8n 对齐）

**配置**：
```json
{
  "srv6": {
    "src_ipv6": "fc00:a::1",
    "segment_list": ["fc00:s1::1"],
    "seg_type": "end",
    "payload_protocol": "udp",
    "tlv": [
      {"type": 5, "value": "0000000100000000000000000000000000000000000000000000000000000000"}
    ]
  }
}
```

（HMAC TLV Value = 2 字节 D+RES（0x0000）+ 4 字节 Key ID `00000001` + 32 字节 HMAC 全 0，共 38 字节）

**字段构成**：
- wire SegmentList：[fc00:s1::1]（1 段）
- DstIP = SegmentList[n-1] = SegmentList[0] = fc00:s1::1
- SegmentsLeft = 0
- LastEntry = 0
- Flags = 0x00（HMAC 由 TLV 携带，不是 Flag 位）
- HMAC TLV：Type=5 + Length=38（0x26）+ Value[38 字节] = D(1bit)+RES(15bit)=0x0000 + KeyID=0x00000001 + HMAC(32 字节 0) = TLV 总长 2+38 = **40 字节**（RFC 8754 §2.1.2：Length = Type/Length 之后的所有字节数 = D+RES(2) + KeyID(4) + HMAC(32) = 38）
- HMAC TLV 8n 对齐检查：HMAC TLV 起始 offset（相对 SRH 头）= 8 + 16×1 = 24，24 % 8 = 0 ✓ 已对齐，无需前置 PadN
- SRH 总长 = 8 + 16 + 40 = **64 字节**，64 % 8 = 0 ✓ 已 8n 对齐，**末尾无需 PadN**
- Hdr Ext Len = (64/8) - 1 = 7
- NextHeader = 17（UDP）
- 内层 UDP：SrcPort=0、DstPort=0（spec 端口默认 0，§5.2.1）、Length=8、校验和由 builder 按伪头计算（DstIP=最终目的=SegmentList[0]=fc00:s1::1，RFC 8200 §8.1；零校验和非法，见 §5.2.1），payload 空（数据报长度 0）

**HexDump**（offset 0-39 IPv6 头，40-103 SRH 64 字节，104+ UDP。M-SRV6-R4-2 修正：0x60 行实际只占 8 字节 SRH 续（offset 96-103），后续 8 字节为 UDP 头起始，行标按真实偏移 0x68 标注）：

```
0000  60 00 00 00 00 48 2b 40 fc 00 00 00 00 00 00 00
0010  00 00 00 00 00 00 00 01 fc 00 00 00 00 00 00 00
0020  00 00 00 00 00 s1 00 01 11 07 04 00 00 00 00 00
0030  fc 00 00 00 00 00 00 00 00 00 00 00 00 00 s1 01   <- List[0]=fc00:s1::1
0040  05 26 00 00 00 00 00 01 00 00 00 00 00 00 00 00   <- HMAC TLV: Type=5, Len=38(0x26), D+RES=0, KeyID=1
0050  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   <- HMAC (32B 全 0)
0060  00 00 00 00 00 00 00 00                            <- HMAC 续 (32B 全 0 尾部，offset 96-103)
0068  <UDP 头 8 字节> <UDP payload 空>
```

（offset 40-103 = 64 字节 SRH；offset 104 = 0x68 起 UDP。0x60 行实际只有 8 字节 SRH 尾部，UDP 起始偏移 = 0x68 = 104，行标按真实偏移标注而非按"每行 16 字节递增"）

**验证**：
- offset 4-5 = `00 48` = 72 = PayloadLength（64 SRH + 8 UDP 头，UDP payload 空）✓
- offset 41 = `07` = 7 = Hdr Ext Len，(7+1)×8 = 64 = SRH 总长 ✓
- offset 45 = `00` = Flags=0（HMAC 不在 Flags，在 TLV）✓
- offset 64 = `05` = HMAC TLV Type=5 ✓
- offset 65 = `26` = 38 = HMAC TLV Length（= D+RES(2) + KeyID(4) + HMAC(32)，RFC 8754 §2.1.2）✓
- offset 66-67 = `00 00` = D bit=0 + RESERVED=0 ✓
- offset 68-71 = `00 00 00 01` = HMAC Key ID=1 ✓
- offset 72-103 = 32 字节 HMAC 全 0 ✓
- HMAC TLV 起始 offset（相对 SRH）= 64-40 = 24，24 % 8 = 0 ✓ 满足 8n 对齐
- SRH 总长 64 已是 8 的倍数，末尾**无 PadN**（40 字节 HMAC TLV 模型下不再需要）✓

### 6.5 S5：PadN TLV 自动填充（Type=4）

**配置**：
```json
{
  "srv6": {
    "segment_list": ["fc00:s1::1"],
    "tlv": [
      {"type": 200, "value": "AB"}
    ]
  }
}
```

（实验 TLV Type=200，Value=2 字节 `AB CD`）

**字段构成**：
- wire SegmentList：[fc00:s1::1]（1 段）
- 自定义 TLV：Type=200 + Length=2 + Value=`AB CD` = 4 字节
- SRH 总长 = 8 + 16 + 4 = 28 字节；28 % 8 = 4，需 PadN 补 4 字节（`04 02 00 00`）使总长对齐到 32
- 调整后 SRH 总长 = 32 字节
- Hdr Ext Len = (32/8) - 1 = 3
- NextHeader = 17（UDP，默认）
- 内层 UDP：SrcPort=0、DstPort=0（spec 端口默认 0，§5.2.1）、Length=8、校验和由 builder 按伪头计算（DstIP=最终目的=SegmentList[0]=fc00:s1::1，RFC 8200 §8.1；零校验和非法，见 §5.2.1），payload 空

**HexDump**（offset 0-39 IPv6 头，40-71 SRH 32 字节，72+ UDP；UDP payload 空）：

```
0000  60 00 00 00 00 28 2b 40 fc 00 00 00 00 00 00 00
0010  00 00 00 00 00 00 00 01 fc 00 00 00 00 00 00 00
0020  00 00 00 00 00 s1 00 01 11 03 04 00 00 00 00 00
0030  fc 00 00 00 00 00 00 00 00 00 00 00 00 00 s1 01   <- List[0]
0040  c8 02 ab cd 04 02 00 00                            <- 自定义TLV(Type=200,Len=2,Val=ABCD) + PadN(4B)
0048  <UDP 头 8 字节>
```

**验证**：
- offset 4-5 = `00 28` = 40 = PayloadLength（32 SRH + 8 UDP 头，UDP payload 空）✓
- offset 41 = `03` = 3 = Hdr Ext Len，(3+1)×8 = 32 = SRH 总长 ✓
- offset 64 = `c8` = 200 = 自定义 TLV Type ✓
- offset 65 = `02` = 2 = 自定义 TLV Length ✓
- offset 66-67 = `ab cd` = Value ✓
- offset 68 = `04` = PadN Type=4 ✓
- offset 69 = `02` = PadN Length=2（N-2=4-2=2 字节 0 填充）✓
- offset 70-71 = `00 00` = PadN Value ✓

### 6.6 S6：嵌套 IPv6（End.DX6 解封装场景）

**配置**：
```json
{
  "srv6": {
    "src_ipv6": "fc00:pe1::1",
    "dst_ipv6": "fc00:pe2::1",
    "segment_list": ["fc00:pe2::1"],
    "segments_left_ptr": 0,
    "seg_type": "end.dx6",
    "payload_protocol": "ipv6",
    "inner_payload": "<40 字节 IPv6 头 + 8 字节 UDP 头 + 8 字节 payload>"
  }
}
```

**字段构成**：
- 外层 wire SegmentList：[fc00:pe2::1]（1 段）
- 外层 DstIP = fc00:pe2::1
- 外层 SegmentsLeft = 0（终节点视角，SegmentsLeftPtr 显式 0）
- 外层 LastEntry = 0
- 外层 Hdr Ext Len = 2
- 外层 SRH 总长 = 24 字节
- 外层 NextHeader = **41（IPv6）**——End.DX6 解封装语义要求内层 IPv6 包由外层 Next Header = 41 标识（RFC 8986 §4.4 "If (Upper-Layer header type == 41(IPv6))"）；若用 59（No Next Header），RFC 8200 §4.7 规定接收端直接丢弃，DX6 解封装永不触发
- InnerPayload = 内层 IPv6(40B) + 内层 UDP(8B) + payload(8B) = 56 字节
- 内层 IPv6 头：SrcIP=fc00::a、DstIP=fc00::b、Payload Length=16（8 UDP 头 + 8 payload）、Next Header=17（UDP）、Hop Limit=64
- 内层 UDP：SrcPort=12345（0x3039）、DstPort=53（0x0035）、Length=16、校验和=0x0675（含 IPv6 伪头，RFC 8200 §8.1 计算；伪头 DstIP = 内层 IPv6 头 DstIP=fc00::b——内层包无 SRH，不适用 Routing header 最终目的规则，§3.1 规则仅约束带 SRH 的包）、payload=`31 32 33 34 35 36 37 38`（"12345678"）

**HexDump**（offset 0-39 外层 IPv6 头，40-63 外层 SRH 24 字节，64-119 内层 IPv6+UDP 56 字节）：

```
0000  60 00 00 00 00 50 2b 40 fc 00 00 00 00 00 00 00
0010  00 00 00 00 00 pe1 00 01 fc 00 00 00 00 00 00 00
0020  00 00 00 00 00 pe2 00 01 29 02 04 00 00 00 00 00
0030  fc 00 00 00 00 00 00 00 00 00 00 00 00 00 pe2 01   <- List[0]
0040  60 00 00 00 00 10 11 40 fc 00 00 00 00 00 00 00   <- 内层 IPv6 头开始
0050  00 00 00 00 00 00 00 0a fc 00 00 00 00 00 00 00   <- 内层 SrcIP=fc00::a + DstIP 前 8B
0060  00 00 00 00 00 00 00 0b 30 39 00 35 00 10 06 75   <- 内层 DstIP=fc00::b + UDP 头(SP=12345,DP=53,Len=16,CKSUM=0x0675)
0070  31 32 33 34 35 36 37 38                            <- 内层 UDP payload="12345678"
```

**验证**：
- offset 4-5 = `00 50` = 80 = PayloadLength（外层 SRH 24 + 内层 56 字节）✓
- offset 40 = `29` = 41 = SRH.NextHeader=IPv6（RFC 8986 §4.4 End.DX6 要求，非 59）✓
- offset 41 = `02` = 2 = Hdr Ext Len，(2+1)×8 = 24 = SRH 总长 ✓
- offset 64 = `60` = 内层 IPv6 Version=6（内层包以 IPv6 头开始）✓
- 内层 offset 68-69 = `00 10` = 16 = 内层 PayloadLength（8 UDP 头 + 8 payload）✓
- 内层 IPv6 头占 offset 64-103（40 字节），其后是内层 UDP

### 6.7 S7：End SID 处理（中间节点视角）

**场景**：模拟 S1 节点处理后的报文——SR Policy `<S1, S2, B>`，S1 节点收到 SL=2 的包后执行 S15-S16（SL-- → 1，DA = List[1] = S2）。

**配置**：
```json
{
  "srv6": {
    "src_ipv6": "fc00:s1::1",
    "dst_ipv6": "fc00:s2::1",
    "segment_list": ["fc00:s1::1", "fc00:s2::1", "fc00:b::1"],
    "segments_left_ptr": 1,
    "last_entry_ptr": 2,
    "seg_type": "end"
  }
}
```

**字段构成**：
- 用户 SegmentList：[S1, S2, B]（n=3）
- wire SegmentList（反序）：[B, S2, S1]（List[0]=B 最后，List[2]=S1 第一）
- S1 节点处理后：SL_new = SL_old - 1 = 2 - 1 = 1；DA = List[SL_new] = List[1] = S2
- DstIP = fc00:s2::1（用户显式设置，等于 S15-S16 公式结果）
- SegmentsLeft = 1（显式）
- LastEntry = 2（不变）
- Flags = 0x00
- Hdr Ext Len = 2×3 = 6
- SRH 总长 = 8 + 48 = 56 字节
- NextHeader = 17（UDP，默认）
- 内层 UDP：SrcPort=0、DstPort=0（spec 端口默认 0，§5.2.1）、Length=8、校验和由 builder 按伪头计算（DstIP=最终目的=SegmentList[0]=fc00:b::1，RFC 8200 §8.1；**注意**：S7 是中转节点视角，伪头 DstIP 仍为最终目的 SegmentList[0]=B，不是当前外层 DstIP=S2，见 §3.1 L4 伪头 DstIP 规则；零校验和非法，见 §5.2.1），payload 空（数据报仅 8 字节 UDP 头）

**HexDump**（offset 0-39 IPv6 头，40-95 SRH 56 字节，96+ UDP）：

```
0000  60 00 00 00 00 40 2b 40 fc 00 00 00 00 00 00 00
0010  00 00 00 00 00 s1 00 01 fc 00 00 00 00 00 00 00
0020  00 00 00 00 00 s2 00 01 11 06 04 01 02 00 00 00
0030  fc 00 00 00 00 00 00 00 00 00 00 00 00 00 00 b1   <- List[0]=B (最后一段)
0040  fc 00 00 00 00 00 00 00 00 00 00 00 00 00 s2 01   <- List[1]=S2 (中间段)
0050  fc 00 00 00 00 00 00 00 00 00 00 00 00 00 s1 01   <- List[2]=S1 (第一段)
0060  <UDP 头 + payload>
```

**验证**：
- offset 24-39 = DstIP = fc00:s2::1 = List[1] = List[SL_new]（SL_new=1）✓ RFC 8754 §4.3.1.1 S15-S16
- offset 43 = `01` = 1 = SegmentsLeft（已减 1）✓
- offset 44 = `02` = 2 = LastEntry（不变）✓
- offset 48-63 = List[0] = B（最后一段，反序存储在最低索引）✓
- offset 80-95 = List[2] = S1（第一段，仍在 SRH 中，non-reduced）✓

### 6.8 S8：End.X SID（邻接转发）

**场景**：End.X 行为——除 End 的标准处理外，强制指定下一跳 L2 邻接（DstMAC 改为指定邻接 MAC）。报文形态与 S7 相同，差异在 L2 DstMAC。

**配置**：与 S7 相同，但 `seg_type = "end.x"`，并在 FlowSpec 层指定 `dst_mac = "00:11:22:33:44:55"`。

**HexDump**：与 S7 IPv6+SRH 部分完全相同；差异在 Ethernet 头（本场景 HexDump 不含 Ethernet 头，故省略）。

**验证**：
- IPv6+SRH 层与 S7 一致 ✓
- L2 DstMAC = 00:11:22:33:44:55（用户指定邻接 MAC，由 builder 写入 Ethernet 头）✓
- 若用户未指定 DstMAC 且 seg_type=end.x，Validate 报错 "end.x requires explicit dst_mac"

### 6.9 S9：End.T SID（特定表查找）

**场景**：End.T 行为——同 End，但查找指定 IPv6 路由表。报文形态与 S7 相同（trafficgen 不模拟路由表，只生成报文）。

**配置**：与 S7 相同，但 `seg_type = "end.t"`。

**HexDump**：与 S7 完全相同。

**验证**：IPv6+SRH 层与 S7 一致；seg_type=end.t 仅做字段合法性检查（v1 支持的 9 个之一），不做路由表语义校验。

### 6.10 S10：多层嵌套（End.B6.Encaps，外层 SRH + 内层 IPv6+SRH）

**场景**：End.B6.Encaps——节点收到外层 SRv6 包后，在外层再封装一层 IPv6+SRH。InnerPayload 携带完整内层 IPv6+SRH+L4 字节流。

**配置**：
```json
{
  "srv6": {
    "src_ipv6": "fc00:outer::1",
    "dst_ipv6": "fc00:outer::2",
    "segment_list": ["fc00:outer::2"],
    "segments_left_ptr": 0,
    "seg_type": "end.b6.encaps",
    "payload_protocol": "ipv6",
    "inner_payload": "<内层 IPv6+SRH+UDP 完整字节流，≥ 40 字节>"
  }
}
```

**字段构成**：
- 外层 wire SegmentList：[fc00:outer::2]（1 段）
- 外层 DstIP = fc00:outer::2
- 外层 SegmentsLeft = 0
- 外层 LastEntry = 0
- 外层 Hdr Ext Len = 2
- 外层 SRH 总长 = 24 字节
- 外层 NextHeader = **41（IPv6）**——End.B6.Encaps 依 RFC 2473 封装规则（RFC 8986 §4.13 End.B6.Encaps）在现有 IPv6 包外封装新外层，内层 IPv6 包由外层 Next Header = 41 标识；59（No Next Header）会被接收端按 RFC 8200 §4.7 丢弃
- InnerPayload = 内层 IPv6(40B) + 内层 SRH(24B) + 内层 UDP(8B + payload 空) = 72 字节
- 内层 IPv6 头：SrcIP=fc00:inner::1、DstIP=fc00:inner::2、Payload Length=32（24 SRH + 8 UDP 头）、Next Header=43（SRH）、Hop Limit=64
- 内层 SRH：NextHeader=17（UDP）、Hdr Ext Len=2、RoutingType=4、SegmentsLeft=0、LastEntry=0、Tag=0、List[0]=fc00:inner::2
- 内层 UDP：SrcPort=0、DstPort=0（spec 端口默认 0，§5.2.1）、Length=8、校验和由 builder 按伪头计算（伪头 DstIP=内层 SRH 的最终目的=内层 SegmentList[0]=fc00:inner::2，RFC 8200 §8.1；零校验和非法，见 §5.2.1；内层包自带 SRH，伪头 DstIP 用内层 SRH 的最终目的，不是内层 IPv6 头 DstIP），payload 空（数据报仅 8 字节 UDP 头）

**HexDump**（offset 0-39 外层 IPv6 头，40-63 外层 SRH 24 字节，64-135 内层 IPv6+SRH+UDP 72 字节）：

```
0000  60 00 00 00 00 60 2b 40 fc 00 00 00 00 00 00 00
0010  00 00 00 00 00 outer 01 fc 00 00 00 00 00 00 00
0020  00 00 00 00 00 outer 02 29 02 04 00 00 00 00 00
0030  fc 00 00 00 00 00 00 00 00 00 00 00 00 00 outer 02
0040  60 00 00 00 00 20 2b 40 fc 00 00 00 00 00 00 00   <- 内层 IPv6 头开始
0050  00 00 00 00 00 inner 01 fc 00 00 00 00 00 00 00
0060  00 00 00 00 00 inner 02 11 02 04 00 00 00 00 00   <- 内层 SRH 开始
0070  fc 00 00 00 00 00 00 00 00 00 00 00 00 00 inner 02
0080  <内层 UDP 头 8 字节>   <- SP=0, DP=0 (spec 默认), Len=8, Cksum 由 builder 计算（伪头 DstIP=内层最终目的=fc00:inner::2，RFC 8200 §8.1；零校验和非法）
```

**验证**：
- 外层 offset 4-5 = `00 60` = 96 = PayloadLength（外层 SRH 24 + 内层 72 字节）✓
- 外层 offset 40 = `29` = 41 = 外层 SRH.NextHeader=IPv6（RFC 8986 §4.13 End.B6.Encaps 要求，非 59）✓
- 外层 offset 41 = `02` = 2 = Hdr Ext Len ✓
- 外层 offset 64 = `60` = 内层 IPv6 Version=6 ✓
- 内层 offset 68-69 = `00 20` = 32 = 内层 PayloadLength（24 内层 SRH + 8 UDP 头）✓
- 内层 offset 104 = `11` = 17 = 内层 SRH.NextHeader=UDP ✓
- 内层 offset 105 = `02` = 2 = 内层 Hdr Ext Len ✓
- InnerPayload 长度 ≥ 40（IPv6 头最小）→ Validate 通过 ✓

### 6.11 S11：错误处理（SegmentsLeft > LastEntry+1）

**配置**：
```json
{
  "srv6": {
    "segment_list": ["fc00:s1::1", "fc00:s2::1"],
    "segments_left_ptr": 5,
    "last_entry_ptr": 1
  }
}
```

**期望**：Validate 报错 "segments_left (5) > last_entry+1 (2)"（RFC 8754 §4.3.1.1 S10-S12 检查）。

**HexDump**：无（Validate 阶段拒绝，不生成字节）。

### 6.12 S12：多流关联（3 流，每流独立 5-tuple）

**场景**：3 条并行 SRv6 流，每流 SegmentList 相同但 SrcPort 递增。

**配置**：
```json
{
  "count": 3,
  "src_port": {"strategy": "inc", "range": [1024, 65535], "step": 1},
  "srv6": {
    "segment_list": ["fc00:s1::1", "fc00:s2::1", "fc00:b::1"],
    "payload_protocol": "tcp",
    "inner_dst_port": 80
  }
}
```

**字段构成**（每流）：
- wire SegmentList：[B, S2, S1]（反序，3 段）
- DstIP = S1 = List[2]
- SegmentsLeft = 2, LastEntry = 2, Hdr Ext Len = 6
- 内层 TCP：SrcPort=1024..1026（src_port 策略递增）、DstPort=80（显式 inner_dst_port）、校验和由 builder 按伪头计算（DstIP=最终目的=SegmentList[0]=B=fc00:b::1，RFC 8200 §8.1；TCP over IPv6 禁止零校验和，见 §5.2.1），负载为空
- 流 1：SrcPort=1024，FlowID=hash(SrcIP,DstIP,1024,80,6)（外层 IPv6 对 + 内层 L4 端口对 + 内层协议号 6=TCP；外层 Next Header=43 不参与，§10.1 FlowID 说明）
- 流 2：SrcPort=1025，FlowID=hash(...,1025,...)
- 流 3：SrcPort=1026，FlowID=hash(...,1026,...)

**HexDump**（3 流，仅 SrcPort 差异，其余相同；以流 1 为例；TCP 负载为空）：

```
0000  60 00 00 00 00 4c 2b 40 fc 00 00 00 00 00 00 00
0010  00 00 00 00 00 00 00 01 fc 00 00 00 00 00 00 00
0020  00 00 00 00 00 s1 00 01 06 06 04 02 00 00 00 00
0030  fc 00 00 00 00 00 00 00 00 00 00 00 00 00 00 b1
0040  fc 00 00 00 00 00 00 00 00 00 00 00 00 00 s2 01
0050  fc 00 00 00 00 00 00 00 00 00 00 00 00 00 s1 01
0060  <TCP 头：SrcPort=04 00 (1024), DstPort=00 50 (80), ...>
```

**验证**：
- offset 4-5 = `00 4c` = 76 = PayloadLength（56 SRH + 20 TCP 头，TCP 负载为空）✓
- 流 1：TCP SrcPort = 1024（offset 96-97 = `04 00`）✓
- 流 2：TCP SrcPort = 1025 ✓
- 流 3：TCP SrcPort = 1026 ✓
- 每流 SRH 字节布局相同（SegmentList 不变）✓
- FlowID 互不相同 ✓

### 6.13 S13：边界值（最大段数 127）

**配置**：
```json
{
  "srv6": {
    "segment_list": ["fc00:s1::1", ..., "fc00:s127::1"],
    "seg_type": "end"
  }
}
```

（127 段，segment_list 长度 127）

**字段构成**：
- wire SegmentList：反序 127 段
- DstIP = SegmentList[126] = 第一段
- SegmentsLeft = 126
- LastEntry = 126
- Hdr Ext Len = 2×127 = 254（uint8 上限 255 之下）
- SRH 总长 = 8 + 16×127 = 2040 字节
- NextHeader = 17（UDP，默认）

**HexDump**（前 64 字节 + 末 32 字节，中间省略；UDP payload 空）：

```
0000  60 00 00 00 08 00 2b 40 fc 00 00 00 00 00 00 00
0010  00 00 00 00 00 00 00 01 fc 00 00 00 00 00 00 00
0020  00 00 00 00 00 s1 00 01 11 fe 04 7e 00 00 00 00
0030  fc 00 00 00 00 00 00 00 00 00 00 00 00 00 s127 01   <- List[0]=最后一段
...
07f0  fc 00 00 00 00 00 00 00 00 00 00 00 00 00 s1 01      <- List[126]=第一段
0800  <UDP 头 + payload>
```

**验证**：
- offset 4-5 = `08 00` = 2048 = PayloadLength（SRH 2040 + UDP 8 头，UDP payload 空）✓
- offset 41 = `fe` = 254 = Hdr Ext Len，(254+1)×8 = 2040 = SRH 总长 ✓
- offset 43 = `7e` = 126 = SegmentsLeft ✓
- offset 44 = `7e` = 126 = LastEntry ✓
- 128 段 → Hdr Ext Len = 256 溢出 → Validate 报错 ✓

### 6.14 S14：HMAC 验证（HMAC TLV + D bit=1 reduced SRH）

**配置**：
```json
{
  "srv6": {
    "src_ipv6": "fc00:a::1",
    "segment_list": ["fc00:s1::1", "fc00:s2::1"],
    "reduced": true,
    "seg_type": "end.b6.encaps.red",
    "payload_protocol": "udp",
    "tlv": [
      {"type": 5, "value": "8000000100000000000000000000000000000000000000000000000000000000"}
    ]
  }
}
```

（HMAC TLV Value = 2 字节 D+RES（0x8000）+ 4 字节 Key ID `00000001` + 32 字节 HMAC 0，共 38 字节）

**字段构成**：
- wire SegmentList（reduced）：[fc00:s2::1]（省略 S1=List[n-1]）
- DstIP = fc00:s1::1（第一段，已在 DstIP）
- SegmentsLeft = 1（n-1）
- LastEntry = 0（n-2，reduced）
- Flags = 0x00
- HMAC TLV：Type=5 + Length=38（0x26）+ Value[38 字节] = D=1(0x80)+RES=0 + KeyID=1 + HMAC(32B 0) = TLV 总长 2+38 = **40 字节**（RFC 8754 §2.1.2：Length = D+RES(2) + KeyID(4) + HMAC(32) = 38）
- HMAC TLV 8n 对齐：HMAC TLV 起始 offset（相对 SRH 头）= 8 + 16×1 = 24，24 % 8 = 0 ✓
- SRH 总长 = 8 + 16 + 40 = **64 字节**，64 % 8 = 0 ✓ 已 8n 对齐，**末尾无需 PadN**
- Hdr Ext Len = (64/8) - 1 = 7
- NextHeader = 17（UDP）
- 内层 UDP：SrcPort=0、DstPort=0（spec 端口默认 0，§5.2.1）、Length=8、校验和由 builder 按伪头计算（DstIP=最终目的=SegmentList[0]=fc00:s2::1，RFC 8200 §8.1；reduced SRH 下 SegmentList 仅 1 项，最终目的 = List[0] = fc00:s2::1；零校验和非法，见 §5.2.1），payload 空（数据报长度 0）

**HexDump**（offset 0-39 IPv6 头，40-103 SRH 64 字节，104+ UDP。M-SRV6-R4-2 修正：0x60 行实际只占 8 字节 SRH 续，UDP 起始偏移 = 0x68 = 104）：

```
0000  60 00 00 00 00 48 2b 40 fc 00 00 00 00 00 00 00
0010  00 00 00 00 00 00 00 01 fc 00 00 00 00 00 00 00
0020  00 00 00 00 00 s1 00 01 11 07 04 01 00 00 00 00
0030  fc 00 00 00 00 00 00 00 00 00 00 00 00 00 s2 01   <- List[0]=fc00:s2::1 (reduced，省略 S1)
0040  05 26 80 00 00 00 00 01 00 00 00 00 00 00 00 00   <- HMAC TLV: Type=5, Len=38(0x26), D=1+RES=0x8000, KeyID=1
0050  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   <- HMAC (32B 全 0)
0060  00 00 00 00 00 00 00 00                            <- HMAC 续 (32B 全 0 尾部，offset 96-103)
0068  <UDP 头 + payload 空>
```

**验证**：
- offset 4-5 = `00 48` = 72 = PayloadLength（64 SRH + 8 UDP 头，UDP payload 空）✓
- offset 41 = `07` = 7 = Hdr Ext Len，(7+1)×8 = 64 = SRH 总长 ✓
- offset 43 = `01` = 1 = SegmentsLeft ✓
- offset 44 = `00` = 0 = LastEntry（reduced，n-2=0）✓
- offset 65 = `26` = 38 = HMAC TLV Length（= D+RES(2) + KeyID(4) + HMAC(32)，RFC 8754 §2.1.2）✓
- offset 66 = `80` = D bit=1（reduced SRH DA verification disabled）✓
- HMAC TLV 起始 offset（相对 SRH）= 24，8n 对齐 ✓
- SRH 总长 64 已是 8 的倍数，末尾**无 PadN** ✓

### 6.15 S15：完整路径（5 段，源节点 + 4 个 End 节点视角，5 帧）

**场景**：SR Policy `<S1, S2, S3, S4, B>`（n=5），生成 5 帧分别模拟源节点 + 4 个 End 节点处理后的报文形态。

**配置驱动方式**：S15 的"视角递增"（每帧 SegmentsLeft--、DstIP 按 S15-S16 更新）**不是**由 §5.1 的 `Frames` 字段驱动——`Frames` 字段只保证 Hop Limit 递减 / 内层 IPID 递增（§5.1 注释），不改变每帧的 SRH 内容。视角递增的语义（SL 递减、DstIP 更新）**仅能由 5 条 FlowSpec 显式串联实现**（每条指定不同的 `segments_left_ptr` 与 `dst_ipv6`），与 §4.4"多节点序列由用户在策略层用多条 FlowSpec 串联"一致。本场景即采用 5 条 FlowSpec 示意；`Frames=5` + 视角递增的组合 v1 不支持，若用户同时配置 `frames>1` 与多条视角递增 FlowSpec，各 FlowSpec 独立展开 Frames 帧，不做跨 FlowSpec 的 SL 递减联动。

**配置**（5 条 FlowSpec 串联，Frame k 的 `segments_left_ptr` = 4-(k-1)，`dst_ipv6` = 第 k 个待处理段）：

```
Frame 1（源节点）：SL=4, DstIP=S1=List[4], LE=4
Frame 2（S1 后）：  SL=3, DstIP=S2=List[3], LE=4
Frame 3（S2 后）：  SL=2, DstIP=S3=List[2], LE=4
Frame 4（S3 后）：  SL=1, DstIP=S4=List[1], LE=4
Frame 5（S4 后）：  SL=0, DstIP=B =List[0], LE=4
```

**字段构成**（每帧）：
- wire SegmentList（反序，5 段，non-reduced）：[B, S4, S3, S2, S1]（不变）
- LastEntry = 4（不变）
- Hdr Ext Len = 2×5 = 10
- SRH 总长 = 8 + 80 = 88 字节
- NextHeader = 17（UDP）
- 内层 UDP：SrcPort=0、DstPort=0（spec 端口默认 0，§5.2.1）、Length=8、校验和由 builder 按伪头计算（DstIP=最终目的=SegmentList[0]=B=fc00:b::1，RFC 8200 §8.1；**注意**：S15 各帧伪头 DstIP 恒为最终目的 SegmentList[0]=B，不随 S15-S16 的外层 DstIP 更新而变化，见 §3.1 L4 伪头 DstIP 规则；零校验和非法，见 §5.2.1），payload 空（数据报仅 8 字节 UDP 头）

**HexDump**（Frame 1 源节点视角，offset 0-39 IPv6 头，40-127 SRH 88 字节，128+ UDP）：

```
0000  60 00 00 00 00 60 2b 40 fc 00 00 00 00 00 00 00
0010  00 00 00 00 00 00 00 01 fc 00 00 00 00 00 00 00
0020  00 00 00 00 00 s1 00 01 11 0a 04 04 00 00 00 00
0030  fc 00 00 00 00 00 00 00 00 00 00 00 00 00 00 b1   <- List[0]=B (最后一段)
0040  fc 00 00 00 00 00 00 00 00 00 00 00 00 00 s4 01   <- List[1]=S4
0050  fc 00 00 00 00 00 00 00 00 00 00 00 00 00 s3 01   <- List[2]=S3
0060  fc 00 00 00 00 00 00 00 00 00 00 00 00 00 s2 01   <- List[3]=S2
0070  fc 00 00 00 00 00 00 00 00 00 00 00 00 00 s1 01   <- List[4]=S1 (第一段=DstIP)
0080  <UDP 头 8 字节>
```

**Frame 2（S1 处理后）**：与 Frame 1 相比逐字段变化为：offset 24-39（DstIP）= fc00:s2::1（= List[3]，S15-S16 公式 DA = List[SL_new=3]）；offset 43（SegmentsLeft）= `03`；其余字段（SRH 布局、SegmentList、LastEntry=4、Hdr Ext Len=10、IPv6 头除 DstIP 外）不变。

**Frame 5（S4 处理后，终节点）**：与 Frame 1 相比逐字段变化为：offset 24-39（DstIP）= fc00:b::1（= List[0]，最终目的）；offset 43（SegmentsLeft）= `00`；其余字段不变。

**验证**：
- Frame 1：DstIP = List[4] = S1，SL=4 ✓
- Frame 2：DstIP = List[3] = S2，SL=3（S15-S16: SL_new=4-1=3, DA=List[3]）✓
- Frame 3：DstIP = List[2] = S3，SL=2 ✓
- Frame 4：DstIP = List[1] = S4，SL=1 ✓
- Frame 5：DstIP = List[0] = B，SL=0 ✓（终节点，最终目的）
- 所有帧 LastEntry = 4 不变 ✓
- 所有帧 Hdr Ext Len = 10 不变 ✓
- 所有帧 offset 4-5 = `00 60` = 96 = PayloadLength（88 SRH + 8 UDP 头）✓

### 6.16 S16：ICMPv6 内层（PayloadProtocol="icmpv6"）

**场景**：SRH 之后携带 ICMPv6 Echo Request（RFC 4443 §4.1）。ICMPv6 校验和必须包含 IPv6 伪头（RFC 4443 §2.3），伪头规则同 BYT-13（Next Header 用内层协议号 58，Upper-Layer Packet Length 不含 SRH，DstIP = 最终目的 = SegmentList[0]，见 §3.1 L4 伪头 DstIP 规则）。

**配置**：
```json
{
  "src_ip": "fc00:1::1",
  "dst_ip": "fc00:2::2",
  "srv6": {
    "segment_list": ["fc00:2::2"],
    "seg_type": "end",
    "payload_protocol": "icmpv6"
  }
}
```

**字段构成**：
- wire SegmentList：[fc00:2::2]（1 段，n=1）
- DstIP = fc00:2::2；SegmentsLeft = 0；LastEntry = 0；Flags = 0x00
- Hdr Ext Len = 2N = 2；SRH 总长 = 24 字节
- SRH.NextHeader = **58（ICMPv6）**
- ICMPv6 Echo Request 头（RFC 4443 §4.1）：Type=128（0x80）、Code=0、Checksum=0xB6D6、Identifier=1、Sequence=1
- ICMPv6 数据 = 8 字节 `31 32 33 34 35 36 37 38`（"12345678"）
- ICMPv6 校验和计算：伪头（SrcIP=fc00:1::1 + DstIP=最终目的=SegmentList[0]=fc00:2::2 + Upper-Layer Packet Length=16 + Next Header=58）⊕ ICMPv6 头+数据（16 字节）→ **0xB6D6**（RFC 4443 §2.3 反码和校验；M-SRV6-R4-1 修正：原值 0xB6D9 是用 fc00::1/fc00::2 算出的，与 HexDump 实际地址 fc00:1::1/fc00:2::2 不符；n=1 时最终目的 = 外层 DstIP = fc00:2::2，伪头 DstIP 规则不暴露 H-SRV6-R4-1）

**HexDump**（offset 0-39 IPv6 头，40-63 SRH 24 字节，64-79 ICMPv6 16 字节）：

```
0000  60 00 00 00 00 28 2b 40 fc 00 00 00 00 00 00 00
0010  00 00 00 00 00 00 00 01 fc 00 00 00 00 00 00 00
0020  00 00 00 00 00 00 00 02 3a 02 04 00 00 00 00 00
0030  fc 00 00 00 00 00 00 00 00 00 00 00 00 00 00 02
0040  80 00 b6 d6 00 01 00 01 31 32 33 34 35 36 37 38   <- ICMPv6 Echo: Type=128,Code=0,Cksum=0xB6D6,ID=1,Seq=1,Data="12345678"
```

**验证**：
- offset 4-5 = `00 28` = 40 = PayloadLength（24 SRH + 16 ICMPv6）✓
- offset 40 = `3a` = 58 = SRH.NextHeader=ICMPv6 ✓
- offset 41 = `02` = 2 = Hdr Ext Len，(2+1)×8 = 24 = SRH 总长 ✓
- offset 64 = `80` = ICMPv6 Type=128（Echo Request）✓
- offset 66-67 = `b6 d6` = ICMPv6 Checksum=0xB6D6（含 IPv6 伪头，RFC 4443 §2.3；伪头 DstIP=fc00:2::2 = HexDump offset 24-39 = 最终目的 = SegmentList[0]）✓
- offset 68-69 = `00 01` = Identifier=1；offset 70-71 = `00 01` = Sequence=1 ✓
- ICMPv6 头之后 offset 72-79 = 8 字节数据 ✓

---

## 7. 测试用例清单

测试用例编号格式 T-SRV6-<类别>-<序号>。每个用例至少包含：前置条件、输入、断言。覆盖正向（P）/负向（N）/边界（B）/字节级（BYT）/多流（MF）/端到端（E2E）/审计（AUD）/补充（NEW）。

### 7.1 Validate 正向（P）

| 用例 ID | 场景 | 关键断言 |
|---------|------|----------|
| T-SRV6-V-P-01 | 最小合法配置（单 segment） | Validate 返回 nil |
| T-SRV6-V-P-02 | 多 segment 显式路径（3 段，反序存储） | Validate 返回 nil；SegmentsLeft 默认 = 2；LastEntry 默认 = 2 |
| T-SRV6-V-P-03 | 全字段显式（src/dst/SL/SL/LE/Flags/Tag/SegType/PayloadProto/TLV） | Validate 返回 nil |
| T-SRV6-V-P-04 | seg_type=end.x + 显式 DstMAC | Validate 返回 nil |
| T-SRV6-V-P-05 | seg_type=end.dx6 + payload_protocol="ipv6" + InnerPayload ≥ 40 字节 | Validate 返回 nil |
| T-SRV6-V-P-06 | seg_type=end.b6 + payload_protocol="ipv6" + InnerPayload ≥ 40 字节 | Validate 返回 nil |
| T-SRV6-V-P-07 | HMAC TLV（Type=5）+ Flags=0x00 | Validate 返回 nil（HMAC 由 TLV 携带，不是 Flag 位） |
| T-SRV6-V-P-08 | Tag=0xFFFF 边界 | Validate 返回 nil |
| T-SRV6-V-P-09 | 127 段（最大） | Validate 返回 nil；LastEntry=126；Hdr Ext Len=254 |
| T-SRV6-V-P-10 | Frames=10 | Validate 返回 nil |
| T-SRV6-V-P-11 | Direction="down"（含 SegmentList 反转语义） | Validate 返回 nil |
| T-SRV6-V-P-12 | PayloadProtocol="none" + InnerPayload 空 | Validate 返回 nil |
| T-SRV6-V-P-13 | PayloadProtocol="icmpv6" | Validate 返回 nil |
| T-SRV6-V-P-14 | 同时配置 SRv6 + HopByHop（IPv6） | Validate 返回 nil |
| T-SRV6-V-P-15 | seg_type=end.b6.encaps.red + Reduced=true + 2 段 | Validate 返回 nil；LastEntry = n-2 = 0（RFC 8754 §4.1.1） |
| T-SRV6-V-P-16 | Reduced=true + 127 段 | Validate 返回 nil；LastEntry=125（n-2）；Hdr Ext Len = 2×126 = 252 |
| T-SRV6-V-P-17 | seg_type=end.dx6 + payload_protocol="ipv6"（Next Header=41）+ InnerPayload ≥ 40 字节 IPv6 包 | Validate 返回 nil（RFC 8986 §4.4 解封装前提成立） |
| T-SRV6-V-P-18 | seg_type=end.b6.encaps.red + reduced 未设置（SegType 默认规则） | Validate 返回 nil；Reduced 默认 = true；LastEntry = n-2（§5.3 S11） |

### 7.2 Validate 负向（N）

| 用例 ID | 场景 | 期望错误 |
|---------|------|----------|
| T-SRV6-V-N-01 | spec.SRv6=nil | "srv6 config is required" |
| T-SRV6-V-N-02 | segment_list=[] | "segment_list must not be empty" |
| T-SRV6-V-N-03 | segment_list 长度 128 | "segment_list too large for 8-bit hdr_ext_len" |
| T-SRV6-V-N-04 | segments_left > last_entry+1 | "segments_left (5) > last_entry+1 (2)" |
| T-SRV6-V-N-05 | segment_list 项非 IPv6 | "segment_list[i] must be IPv6" |
| T-SRV6-V-N-06 | src_ipv6 非 IPv6 | "src_ipv6 must be IPv6" |
| T-SRV6-V-N-07 | spec.SrcIP 是 IPv4 + spec.SRv6 非空 | "srv6 requires IPv6" |
| T-SRV6-V-N-08 | seg_type 未知 | "unknown seg_type" |
| T-SRV6-V-N-09 | flags=0x01（任何非 0 值） | "flags must be 0 (RFC 8754 §2.1 all bits Unused)" |
| T-SRV6-V-N-10 | tlv value 长度 > 255 | "tlv value exceeds 255 bytes" |
| T-SRV6-V-N-11 | tlv type=0（用户显式 Pad1） | "pad1 must not be set manually (builder auto-inserts)" |
| T-SRV6-V-N-12 | tlv type=4（用户显式 PadN） | "padN must not be set manually (builder auto-inserts)" |
| T-SRV6-V-N-13 | tlv type=1（Reserved） | "reserved TLV type 1 must not be set" |
| T-SRV6-V-N-14 | tlv type=2（Reserved） | "reserved TLV type 2 must not be set" |
| T-SRV6-V-N-15 | tlv type=6（Reserved，原 HMAC-Sig） | "reserved TLV type 6 must not be set (HMAC-Sig does not exist in RFC 8754)" |
| T-SRV6-V-N-16 | seg_type=end.x 但未指定 DstMAC | "end.x requires explicit dst_mac" |
| T-SRV6-V-N-17 | seg_type=end.b6 但 InnerPayload < 40 字节 | "end.b6 requires inner_payload >= 40 bytes (IPv6 header)" |
| T-SRV6-V-N-18 | 同时配置 SRv6 + MPLS | "srv6 cannot combine with mpls (v1 limitation)" |
| T-SRV6-V-N-19 | 同时配置 SRv6 + GRE | "srv6 cannot combine with gre (v1 limitation)" |
| T-SRV6-V-N-20 | seg_type=end.dx6 但 InnerPayload < 40 字节 | "end.dx6 requires inner_payload >= 40 bytes" |
| T-SRV6-V-N-21 | seg_type=end.dx6 + payload_protocol="none" + inner_payload 非空 | 报错 "end.dx6 requires payload_protocol=ipv6 (Next Header 41 per RFC 8986 §4.4), got none"（Next Header=59 的包按 RFC 8200 §4.7 被丢弃，解封装永不触发） |
| T-SRV6-V-N-22 | 127 段 + 任意 TLV（Hdr Ext Len 溢出） | "hdr_ext_len overflow (max 255): 127 segments + TLV exceeds 8-bit limit" |
| T-SRV6-V-N-23 | RoutingType 显式设为非 4（builder 层） | builder "routing type must be 4 for SRH (RFC 8754)" |
| T-SRV6-V-N-24 | Direction="down" + segments_left_ptr 非 nil | "direction=down requires source-node view (segments_left not set)"（§5.4：反转列表不支持 End 中转视角） |

### 7.3 Plan 单包生成（P）

| 用例 ID | 场景 | 关键断言 |
|---------|------|----------|
| T-SRV6-P-01 | 单 segment | PacketConfig.L3.SRH 非空；Hdr Ext Len=2；DstIP=SegmentList[n-1]=SegmentList[0]（n=1 时最高索引即 0） |
| T-SRV6-P-02 | 3 segment 显式路径 | SRH SegmentsLeft=2；LastEntry=2；wire SegmentList 反序（[B,S2,S1]） |
| T-SRV6-P-03 | End 节点视角（SegmentsLeft=1） | DstIP=SegmentList[SL_new=1]（RFC 8754 §4.3.1.1 S15-S16）；SegmentsLeft=1；LastEntry=2 不变 |
| T-SRV6-P-04 | End.DX6 解封装 | 外层 SRH 正常；InnerPayload 在 PacketConfig.Payload 中；SRH NextHeader=41（IPv6，RFC 8986 §4.4） |
| T-SRV6-P-05 | End.B6 外插 SRH | 外层 SRH 正常；InnerPayload 以 IPv6 头开始 |
| T-SRV6-P-06 | HMAC TLV | SRH 中含 Type=5 TLV；Flags=0x00（HMAC 不在 Flags） |
| T-SRV6-P-07 | Tag=0xABCD | SRH 字节 6-7 = 0xAB 0xCD |
| T-SRV6-P-08 | Frames=5 | 5 个 PacketConfig；Hop Limit 递减；内层 IPID 递增 |
| T-SRV6-P-09 | Direction="down"（含 SegmentList 反转） | MAC/IP/Port swap；SegmentList 反转；DstIP = 反转后 List[n-1] = 原 List[0] = 原最终目的；SegmentsLeftPtr=nil（源节点视角，§5.4 限制） |
| T-SRV6-P-10 | PayloadProtocol="none" | SRH NextHeader=59；Payload 空 |
| T-SRV6-P-11 | PayloadProtocol="icmpv6" | SRH NextHeader=58；ICMPv6 Echo Request 头在 Payload（Type=128, Code=0, 校验和含 IPv6 伪头 DstIP=最终目的=SegmentList[0]，ID=1, Seq=1，见 §6.16 S16，校验和值 0xB6D6 在 fc00:1::1→fc00:2::2 单段场景下成立） |
| T-SRV6-P-12 | 同时 SRv6 + HopByHop | IPv6 NH=0 → HopByHop NH=43 → SRH NH=内层 |
| T-SRV6-P-13 | TLV 多个（HMAC + 自定义） | TLV 顺序正确；HMAC 8n 对齐；末尾 PadN 对齐 8 字节 |
| T-SRV6-P-14 | IPv6 DstIP 自动从 SegmentList[n-1] 填充 | DstIP == SegmentList[n-1]（最高索引，反序存储的第一段） |
| T-SRV6-P-15 | SegmentsLeft 默认（SegmentsLeftPtr=nil） | SegmentsLeft == len(SegmentList)-1 |
| T-SRV6-P-16 | Reduced SRH（2 段） | wire SegmentList 仅 1 项（省略 List[n-1]）；LastEntry=n-2=0；SegmentsLeft=n-1=1；Hdr Ext Len=2 |
| T-SRV6-P-17 | Reduced SRH + HMAC TLV（D bit=1） | HMAC TLV D bit=1；reduced SRH DA verification disabled 标记 |
| T-SRV6-P-18 | seg_type=end.b6.encaps.red + reduced 未设置 | Reduced 默认=true（§5.3 S11）；LastEntry=n-2；Hdr Ext Len=2(N-1)（reduced 公式） |

### 7.4 Plan 字节级正确性（builder 集成）

| 用例 ID | 场景 | 关键断言（tshark / 字节比对） |
|---------|------|-------------------------------|
| T-SRV6-BYT-01 | 单 segment 字节布局（无 HopByHop） | 字节 0-39 IPv6 头 NH=43；40-63 SRH（24 字节）；64+ payload |
| T-SRV6-BYT-02 | 3 segment 字节布局 | SRH 长度 56 字节；Hdr Ext Len=6 |
| T-SRV6-BYT-03 | SRH RoutingType=4 | 字节 42 = 0x04 |
| T-SRV6-BYT-04 | SRH SegmentsLeft | 字节 43 与配置一致 |
| T-SRV6-BYT-05 | SRH LastEntry | 字节 44 与配置一致 |
| T-SRV6-BYT-06 | SRH Flags=0x00 | 字节 45 = 0x00（RFC 8754 §2.1 全 Unused） |
| T-SRV6-BYT-07 | SRH Tag | 字节 46-47 大端与配置一致 |
| T-SRV6-BYT-08 | SegmentList 反序存储（RFC 8754 §2 核心断言） | 3 段 SR Policy `<S1, S2, S3>`：字节 48-63 = List[0] = S3（最后一段）；字节 80-95 = List[2] = S1（第一段）；DstIP 字节 (offset 24-39) == List[2] 字节 (offset 80-95) == S1 |
| T-SRV6-BYT-09 | TLV PadN（Type=4）对齐 | 末尾 PadN Type=4 + Length + 0 填充，使总长 8 字节倍数 |
| T-SRV6-BYT-10 | tshark 解析无报错 | tshark 输出 "Routing Header, Routing Type: 4 (SRH)" |
| T-SRV6-BYT-11 | tshark 解析 Segment List | tshark 输出 Segment 列表与反序后的配置一致 |
| T-SRV6-BYT-12 | IPv6 Payload Length 字段 | = SRH 长度 + 内层 L4 + payload 长度（RFC 8200 §3）；对每个 HexDump 场景断言（§6）：S2/S12=0x4c、S4/S14=0x48、S5/S16=0x28、S6=0x50、S7=0x40、S10=0x60、S13=0x800、S15=0x60 |
| T-SRV6-BYT-13 | 内层 UDP 校验和（含 IPv6 伪头） | UDP 校验和 = 计算 IPv6 伪头（SrcIP + **DstIP = `SegmentList[0]`（最终目的，RFC 8200 §8.1，SRv6 特有规则，非外层 DstIP=SegmentList[n-1]）** + Upper-Layer Packet Length（= UDP 头+数据，**不含 SRH**）+ Next Header = 内层协议号 17）后正确（RFC 8200 §8.1）；SRH 不参与 UDP 校验和输入；单段 n=1 时最终目的 = 外层 DstIP，多段 n>1 时两者不同，伪头必须用 `SegmentList[0]`；UDP over IPv6 **必须**计算校验和，计算得 0 时写 0xFFFF（RFC 8200 §8.1，零校验和在 IPv6 下非法；与 builder 现有 `calculateUDPChecksum` 的 0→0xFFFF 替代实现一致） |
| T-SRV6-BYT-14 | 内层 TCP 校验和 | 同 BYT-13，伪头 DstIP = `SegmentList[0]`（最终目的，非外层 DstIP），Next Header = 6，Upper-Layer Packet Length = TCP 头+数据（不含 SRH）；TCP 校验和正确；TCP over IPv6 同样禁止零校验和（RFC 8200 §8.1） |
| T-SRV6-BYT-15 | Pad1（Type=0）单字节填充 | 构造 SRH 总长 mod 8 == 7 的配置（如 1 段 + 实验 TLV Value=5 字节：8+16+2+5=31，mod 8=7），断言末尾出现单字节 `00`（无 Length/Value），总长对齐到 32（RFC 8754 §2.1.1.1，§3.2.1 尾部填充规则） |
| T-SRV6-BYT-16 | HMAC TLV 8n 对齐（RFC 8754 §2.1.2） | HMAC TLV 起始偏移（相对 SRH 头）是 8 的倍数；若 HMAC 之前有未对齐字节，先 PadN 再 HMAC；HMAC TLV 全字节数 = 8 + HMAC_len，Length 字段 = 2 + 4 + HMAC_len（S4/S14：Length 字节 = 0x26） |
| T-SRV6-BYT-17 | DstIP = SegmentList[n-1] 字节一致性（反序存储核心断言） | 任意 N 段配置：IPv6 DstIP 字节 (offset 24-39) == SRH SegmentList[N-1] 字节（最高索引，反序存储的第一段） |
| T-SRV6-BYT-18 | Reduced SRH 字节布局 | 2 段 reduced：SRH 仅 24 字节（List 仅 1 项）；Hdr Ext Len=2；LastEntry=0；DstIP = 省略的 List[n-1] |
| T-SRV6-BYT-19 | IPv6 + HopByHop + SRH 链式字节布局 | 字节 0-39 IPv6 NH=0；40+ HopByHop（变长，含 PadN 对齐 8 字节）；HopByHop 之后 SRH（NH=43 指向 SRH）；SRH 之后 payload |
| T-SRV6-BYT-20 | End 节点视角 DstIP = SegmentList[SL_new]（RFC 8754 §4.3.1.1 S15-S16） | 3 段 SL=1 时：DstIP = List[1] = S2（SL_new=1，索引 List[1]）；不是 List[LastEntry-SL+1] |
| T-SRV6-BYT-21 | IPv6 固定头无校验和（RFC 8200 §3） | 带 SRH 的帧：IPv6 头第 7 字节（Hop Limit）之后无校验和字段；SRH 字节变更（如 SegmentsLeft/DstIP 按 S15-S16 更新）不影响任何校验和——因为 L4 伪头 DstIP 恒为最终目的 SegmentList[0]（§3.1），SRH 内 DstIP 字段的更新不在伪头输入内；仅内层 L4 校验和（BYT-13/14）参与计算 |
| T-SRV6-BYT-22 | 多段（n>1）UDP 校验和伪头 DstIP = 最终目的（RFC 8200 §8.1，H-SRV6-R4-1 补充用例） | 3 段 SR Policy `<S1, S2, B>`（如 §6.7 S7 场景）：UDP 校验和 = 伪头（SrcIP + **DstIP = SegmentList[0] = B（最终目的，非外层 DstIP=S2）** + Upper-Layer Length + NH=17）反码和；用外层 DstIP=S2 计算的校验和必须不相等（tshark 按最终目的校验） |

### 7.5 多流并发（MF）

| 用例 ID | 场景 | 关键断言 |
|---------|------|----------|
| T-SRV6-MF-01 | Count=100，每流 src_port 递增 | 100 个 PacketConfig；src_port 1024..1123 |
| T-SRV6-MF-02 | Count=10，SegmentList 不变 | 10 流 SRH 字节相同（仅外层 5-tuple 不同） |
| T-SRV6-MF-03 | Count=10，5-tuple 全唯一 | FlowID 互不相同 |
| T-SRV6-MF-04 | Count=10，Direction="down"（含 SegmentList 反转） | 每流 MAC/IP/Port swap；SegmentList 反转；DstIP = 反转后 List[n-1] = 原 List[0] |
| T-SRV6-MF-05 | GroupID 路由到同一 PacketWorker | 跨流时序保持（同一 worker 顺序发包） |

### 7.6 边界（BND）

| 用例 ID | 场景 | 关键断言 |
|---------|------|----------|
| T-SRV6-BND-01 | 127 段最大（non-reduced） | Validate 通过；Hdr Ext Len = (8+2032-8)/8 = 254 ≤ 255 |
| T-SRV6-BND-02 | 126 段 + 16 字节 TLV（Hdr Ext Len 边界） | Hdr Ext Len = 2×126 + 16/8 = 252+2 = 254 ≤ 255；Validate 通过 |
| T-SRV6-BND-03 | 127 段 + 任意 TLV（Hdr Ext Len 溢出） | Validate 报错 "hdr_ext_len overflow"（127 段 Hdr Ext Len=254，加任何 TLV 都 > 254） |
| T-SRV6-BND-04 | Reduced SRH 127 段 | LastEntry=125（n-2）；Hdr Ext Len = 2×126 = 252；Validate 通过 |
| T-SRV6-BND-05 | Frames=0 | 默认 1 帧 |
| T-SRV6-BND-06 | Frames=1000 | 1000 个 PacketConfig；Hop Limit 0 之后 wrap 1..255（v1 wrap） |
| T-SRV6-BND-07 | Tag=0x0000 | 字节 46-47 = 0x00 0x00 |
| T-SRV6-BND-08 | Tag=0xFFFF | 字节 46-47 = 0xFF 0xFF |
| T-SRV6-BND-09 | Single segment + 1 TLV（HMAC 32 字节 digest） | HMAC TLV 40 字节 → Hdr Ext Len = (8+16+40-8)/8 = 56/8 = 7（S4 场景） |
| T-SRV6-BND-10 | TLV value 长度 255 边界 | Validate 通过；TLV Length 字节 = 0xFF |
| T-SRV6-BND-11 | TLV value 长度 256 | Validate 报错 "tlv value exceeds 255 bytes" |
| T-SRV6-BND-12 | 1 段 + 实验 TLV Value=5 字节（尾部 Pad1） | SRH 总长 = 8+16+7 = 31（mod 8=7）→ 末尾 Pad1 `00` 1 字节，总长 32；Hdr Ext Len = 3；字节断言末尾出现单字节 `00`（RFC 8754 §2.1.1.1） |
| T-SRV6-BND-13 | reduced 流 report 口径（§10.2） | 2 段 reduced 流：srv6_segment_count（wire）= 1，srv6_policy_segments = 2；total_segments（policy 口径）= 2 |

### 7.7 异常（EXC，独立于 V-N 的 builder 层异常）

| 用例 ID | 场景 | 期望错误 |
|---------|------|----------|
| T-SRV6-EXC-01 | builder 收到 SRHConfig 时 HdrExtLen 字段（planner 计算填入，§5.2）与 builder 实际序列化的 SRH 总长不符 | builder 报错 "hdr_ext_len mismatch"（如 planner 填 HdrExtLen=6 但实际序列化仅 1 段 24 字节 → 复核 (24/8)-1=2 ≠ 6） |

### 7.8 集成测试（端到端，配合 builder + tshark）

| 用例 ID | 场景 | 关键断言 |
|---------|------|----------|
| T-SRV6-E2E-01 | 单 segment + UDP payload | tshark 解析 IPv6 + SRH + UDP 全链路无报错 |
| T-SRV6-E2E-02 | 3 segment + TCP payload | tshark 解析 IPv6 + SRH + TCP；TCP 校验和正确（伪头 Next Header=6、DstIP=最终目的=SegmentList[0]，不含 SRH，RFC 8200 §8.1）；Segment List 反序显示 |
| T-SRV6-E2E-03 | HMAC TLV | tshark 解析 SRH TLV；HMAC 字段正确；Flags=0x00 |
| T-SRV6-E2E-04 | 多流 100 包 | tshark 捕获 100 包；每包 IPv6 5-tuple 唯一 |
| T-SRV6-E2E-05 | Frames=10 | tshark 捕获 10 包；Hop Limit 递减；IPID 递增 |
| T-SRV6-E2E-06 | SRv6 + HopByHop 链 | tshark 解析 HopByHop + SRH 链路 |
| T-SRV6-E2E-07 | real NIC 发包（网卡名由环境变量 SRV6_TEST_NIC 指定；测试环境无该变量时 -short 跳过） | 真实网卡发包，tcpdump 捕获 SRH 帧无错 |
| T-SRV6-E2E-08 | MCP e2e（manage_strategies + generate_traffic） | MCP 任务 completed，packets_sent > 0 |
| T-SRV6-E2E-09 | Reduced SRH（2 段） | tshark 解析 reduced SRH；LastEntry=0；SegmentList 仅 1 项；DstIP = 省略段 |
| T-SRV6-E2E-10 | 5 段完整路径（5 条 FlowSpec，模拟源 + 4 个 End 节点） | tshark 捕获 5 包；每包 SL 递减；DstIP 按 S15-S16 公式更新；LastEntry 不变（视角递增由多 FlowSpec 串联表达，非 Frames=5） |
| T-SRV6-E2E-11 | seg_type=end.dx6 + payload_protocol="ipv6" | tshark 解析外层 SRH.NextHeader=41（IPv6），内层 IPv6 包被正确识别为 IPv6-in-IPv6 隧道（RFC 8986 §4.4），而非 No Next Header 残余字节 |

### 7.9 对抗审计用例（覆盖测试策略 §1-§8）

| 用例 ID | 测试策略条款 | 场景 | 关键断言 |
|---------|--------------|------|----------|
| T-SRV6-AUD-01 | §3（一测一路径） | builder `writeSRH` 与 planner `Plan` 分开测试 | planner 测试不调用 builder；builder 测试不调用 planner |
| T-SRV6-AUD-02 | §4（集成测试） | API → engine → builder → writer 全链路 | 任务状态 completed；pcap 文件含 SRH 帧 |
| T-SRV6-AUD-03 | §5（断言可观察） | 断言 Hdr Ext Len 实际字节 | 不止检查 PacketConfig.L3.SRH，而是序列化后字节 [41] |
| T-SRV6-AUD-04 | §6（并发正确性） | 100 流并发 + GroupID 单 worker | 单 worker 100 包顺序 = 提交顺序；rate 不超配置 |
| T-SRV6-AUD-05 | §7（失败优先） | 修 bug：Hdr Ext Len 计算错误 | 先写失败测试（断言错误字节）再修代码 |
| T-SRV6-AUD-06 | §2（负路径） | 23 条 Validate 拒绝路径全部覆盖 | 见 V-N-01..V-N-23 |
| T-SRV6-AUD-07 | §1（spec 驱动） | RFC 8754 §2 每个字段都有用例 | 字段表 8 项 → 至少 8 个用例（已超额） |
| T-SRV6-AUD-08 | §8（测试质量审计） | 每个测试问"测对路径了吗" | 见 §8 检查清单 |
| T-SRV6-AUD-09 | §1（spec 驱动，RFC 8754 §4.3.1.1 伪代码） | S15-S16 DA 更新公式在 End 节点视角用例中断言 | §6.7 / BYT-20 验证 DstIP = SegmentList[SL_new] |
| T-SRV6-AUD-10 | §1（spec 驱动，反序存储核心断言） | RFC 8754 §2 反序存储在 BYT-08/BYT-17 断言 | 字节比对：List[0]=最后一段，List[n-1]=第一段=DstIP |

### 7.10 补充用例（NEW，覆盖审计剩余缺口）

| 用例 ID | 场景 | 关键断言 |
|---------|------|----------|
| T-SRV6-NEW-01 | seg_type=end.dx4 + InnerPayload ≥ 40 字节 IPv4 包 | Validate 返回 nil；SRH NextHeader=4（IPv4，RFC 8986 §4.5） |
| T-SRV6-NEW-01a | seg_type=end.dt4 + InnerPayload ≥ 40 字节 IPv4 包 | Validate 返回 nil；SRH NextHeader=4（IPv4，RFC 8986 §4.8 End.DT4，协议约束同 End.DX4）；payload_protocol 必须为 "ipv4"，否则报错 "end.dt4 requires payload_protocol=ipv4 (Next Header 4 per RFC 8986 §4.8)" |
| T-SRV6-NEW-01b | seg_type=end.dt6 + InnerPayload ≥ 40 字节 IPv6 包 | Validate 返回 nil；SRH NextHeader=41（IPv6，RFC 8986 §4.9 End.DT6，协议约束同 End.DX6）；payload_protocol 必须为 "ipv6"，否则报错 "end.dt6 requires payload_protocol=ipv6 (Next Header 41 per RFC 8986 §4.9)" |
| T-SRV6-NEW-02 | seg_type=end.b6.encaps（完整封装） + InnerPayload ≥ 40 字节 IPv6 包 | Validate 返回 nil；InnerPayload 以 IPv6 头开始 |
| T-SRV6-NEW-03 | InnerSrcPort 未设置（0） + spec.SrcPort=12345 | 内层 L4 SrcPort = 12345（spec.SrcPort，不是 0） |
| T-SRV6-NEW-04 | InnerSrcPort=54321 + spec.SrcPort=12345 | 内层 L4 SrcPort = 54321（用户显式覆盖） |
| T-SRV6-NEW-05 | 多段配置 + SegmentsLeftPtr=nil | SegmentsLeft = len(SegmentList)-1（默认） |
| T-SRV6-NEW-06 | 多段配置 + SegmentsLeftPtr=&0 | SegmentsLeft = 0（终节点视角，不被默认覆盖） |
| T-SRV6-NEW-07 | 单 segment + 断言 Hdr Ext Len 字节 | 序列化后字节 [41] = 0x02（不是 0） |
| T-SRV6-NEW-08 | 3 segment + DstIP 字节比对（反序存储） | IPv6 DstIP 字节 (offset 24-39) == SRH SegmentList[n-1] 字节（最高索引，反序存储的第一段） |
| T-SRV6-NEW-09 | Frames=-1（JSON 反序列化） | Validate 报错 "frames must be >= 0" |
| T-SRV6-NEW-10 | 128 段 SegmentList | Validate 报错 "segment_list too large for 8-bit hdr_ext_len" |
| T-SRV6-NEW-11 | spec.MPLS 非空 + spec.SRv6 非空 | Validate 报错 "srv6 cannot combine with mpls (v1 limitation)" |
| T-SRV6-NEW-12 | spec.GRE 非空 + spec.SRv6 非空 | Validate 报错 "srv6 cannot combine with gre (v1 limitation)" |
| T-SRV6-NEW-13 | 单段 + SegmentsLeftPtr=&1 | Validate 报错 "segments_left (1) > last_entry+1 (1)"（单段 LE=0） |
| T-SRV6-NEW-14 | seg_type="end.un"（v1 未支持的 20 个行为之一） | Validate 通过（v1 仅做 seg_type 字符串合法性检查，不做 End* 语义校验） |
| T-SRV6-NEW-15 | SRV6_TEST_NIC 环境变量缺失 | 测试 -short 跳过；非 short 模式报错明确提示 |
| T-SRV6-NEW-16 | builder 收到 SRHConfig 时 HdrExtLen 字段（planner 填入，§5.2）与 builder 实际序列化 SRH 总长不符 | builder 报错 "hdr_ext_len mismatch"（§7.7 EXC-01） |
| T-SRV6-NEW-17 | seg_type=end.b6.encaps.red + 2 段 SR Policy `<S1, S2>`（Reduced 字节布局） | 外层 SRH reduced 编码：wire SegmentList = [S2]（仅 1 项，S1 省略），LastEntry = n-2 = 0，SegmentsLeft = n-1 = 1，DstIP = S1（省略段），Hdr Ext Len = (8+16-8)/8 = 2 |
| T-SRV6-NEW-18 | seg_type=end.b6.encaps + payload_protocol="ipv6" + InnerPayload ≥ 40 字节 IPv6 包 | Validate 返回 nil；外层 SRH NextHeader=41（RFC 8986 §4.13 End.B6.Encaps，非 59） |
| T-SRV6-NEW-19 | HMAC TLV 字节布局（RFC 8754 §2.1.2） | HMAC 32 字节 digest：Length 字段字节 = 0x26（=38），TLV 总长 40 字节；HMAC 8 字节 digest：Length=0x0e（=14），TLV 总长 16 字节 |

**用例总数**：18 + 24 + 18 + 22 + 5 + 13 + 1 + 11 + 10 + 21 = **143 条**

---

## 8. Validate 规则

### 8.1 协议正确性 Validate 规则

| 规则 ID | 规则 | 错误信息 |
|---------|------|----------|
| VR-01 | spec.SRv6 必须非 nil | "srv6 config is required" |
| VR-02 | segment_list 必须非空 | "segment_list must not be empty" |
| VR-03 | segment_list 长度 ≤ 127 | "segment_list too large for 8-bit hdr_ext_len" |
| VR-04 | segment_list 每项必须是合法 IPv6 | "segment_list[i] must be IPv6" |
| VR-05 | src_ipv6（若非空）必须是 IPv6 | "src_ipv6 must be IPv6" |
| VR-06 | spec.SrcIP 必须是 IPv6（若 spec.SRv6 非空） | "srv6 requires IPv6" |
| VR-07 | seg_type 必须是 §3.4 表中 29 个之一 | "unknown seg_type" |
| VR-08 | flags 必须 = 0x00（RFC 8754 §2.1 全 8 位 Unused） | "flags must be 0 (RFC 8754 §2.1 all bits Unused)" |
| VR-09 | segments_left ≤ last_entry+1（RFC 8754 §4.3.1.1 S10-S11） | "segments_left (X) > last_entry+1 (Y)" |
| VR-10 | tlv value 长度 ≤ 255 | "tlv value exceeds 255 bytes" |
| VR-11 | tlv type ≠ 0（用户不得显式设 Pad1） | "pad1 must not be set manually (builder auto-inserts)" |
| VR-12 | tlv type ≠ 4（用户不得显式设 PadN） | "padN must not be set manually (builder auto-inserts)" |
| VR-13 | tlv type ∉ {1, 2, 3, 6}（Reserved） | "reserved TLV type X must not be set" |
| VR-14 | seg_type=end.x 时必须指定 DstMAC | "end.x requires explicit dst_mac" |
| VR-15 | seg_type ∈ {end.b6, end.b6.encaps, end.b6.encaps.red, end.dx6, end.dx4, end.dt4, end.dt6} 时 InnerPayload ≥ 40 字节；解封装/封装类（end.dx6/end.b6/end.b6.encaps/end.b6.encaps.red）额外要求 payload_protocol="ipv6"（Next Header=41，RFC 8986 §4.4 End.DX6 / §4.13 End.B6.Encaps / §4.14 End.B6.Encaps.Red）；end.dx4 要求 payload_protocol="ipv4"（Next Header=4，RFC 8986 §4.5 End.DX4）；end.dt4 要求 payload_protocol="ipv4"（RFC 8986 §4.8 End.DT4，同 DX4 协议约束）；end.dt6 要求 payload_protocol="ipv6"（RFC 8986 §4.9 End.DT6，同 DX6 协议约束） | "end.X requires inner_payload >= 40 bytes (IPv6 header)" / "end.dx6 requires payload_protocol=ipv6 (Next Header 41 per RFC 8986 §4.4)" / "end.dx4 requires payload_protocol=ipv4 (Next Header 4 per RFC 8986 §4.5)" / "end.dt4 requires payload_protocol=ipv4 (Next Header 4 per RFC 8986 §4.8)" / "end.dt6 requires payload_protocol=ipv6 (Next Header 41 per RFC 8986 §4.9)" |
| VR-16 | spec.MPLS 与 spec.SRv6 互斥 | "srv6 cannot combine with mpls (v1 limitation)" |
| VR-17 | spec.GRE 与 spec.SRv6 互斥 | "srv6 cannot combine with gre (v1 limitation)" |
| VR-18 | non-reduced SRH: Hdr Ext Len = 2N + T/8 ≤ 255 | "hdr_ext_len overflow (max 255)" |
| VR-19 | reduced SRH: Hdr Ext Len = 2(N-1) + T/8 ≤ 255 | "hdr_ext_len overflow (max 255)" |
| VR-20 | 127 段 + 任意 TLV → 溢出（special case of VR-18/19） | "hdr_ext_len overflow (max 255): 127 segments + TLV exceeds 8-bit limit" |
| VR-21 | frames ≥ 0 | "frames must be >= 0" |
| VR-22 | payload_protocol="none" + inner_payload 非空 + seg_type ∉ 解封装/封装类 | 报错 "payload_protocol=none with non-empty inner_payload not allowed (RFC 8200 §4.7: No Next Header packets discarded)"（解封装/封装类走 VR-15 强制 ipv6/ipv4，不触发本规则） |
| VR-23 | Direction="down" + SegmentsLeftPtr 非 nil | "direction=down requires source-node view (segments_left not set)"（§5.4：反转列表不支持 End 中转视角） |

### 8.2 默认值填充规则

| 规则 ID | 字段 | 默认值 |
|---------|------|--------|
| DR-01 | SrcIPv6 空 | spec.SrcIP |
| DR-02 | DstIPv6 空 | SegmentList[n-1]（反序存储的最高索引 = 第一段） |
| DR-03 | SegmentsLeftPtr=nil | len(SegmentList)-1 |
| DR-04 | LastEntryPtr=nil, Reduced=false | len(SegmentList)-1 |
| DR-05 | LastEntryPtr=nil, Reduced=true | len(SegmentList)-2（RFC 8754 §4.1.1） |
| DR-06 | PayloadProtocol 空 + spec.TCP 非空 | "tcp" |
| DR-07 | PayloadProtocol 空 + spec.TCP nil | "udp" |
| DR-08 | SegType 空 | "end" |
| DR-09 | Flags 空 | 0x00 |
| DR-10 | Tag 空 | 0x0000 |
| DR-11 | Reduced 空 | false（默认）；seg_type="end.b6.encaps.red" 时默认 true（§5.3 S11） |
| DR-12 | Frames 空 | 1 |
| DR-13 | Direction 空 | "up" |

### 8.3 Direction="down" 变换规则

| 规则 ID | 字段 | 变换 |
|---------|------|------|
| DD-01 | SrcIP ↔ DstIP | 交换 |
| DD-02 | SegmentList | 整体反转（原 List[n-1] 变 List[0]） |
| DD-03 | SegmentsLeft | 重置为 n-1 |
| DD-04 | DstIP | = 反转后 List[n-1] = 原 List[0] = 原最终目的 |
| DD-05 | MAC 源/目 | 交换 |
| DD-06 | L4 端口 | 交换 |
| DD-07 | 适用性限制 | 仅源节点视角：SegmentsLeftPtr 必须为 nil（否则 Validate 报错，见 VR-23） |

**补充说明**：DD-02 的"整体反转"使反向流仍满足 RFC 8754 §4.1 源节点规则（DstIP = 反转后 List[n-1]）；但反转后的列表与用户显式 SegmentsLeft/DstIP（End 中转视角）的对应关系未定义，故 v1 限制 Direction="down" 仅支持源节点视角（VR-23 / V-N-24）。

---

## 9. 错误处理

### 9.1 Validate 阶段错误（见 §8.1）

所有 VR-* 规则违反在 planner.Validate 阶段拒绝，不生成 PacketConfig。

### 9.2 builder 阶段错误

| 错误 | 触发条件 | 错误信息 |
|------|----------|----------|
| RoutingType 非 4 | SRHConfig.RoutingType ≠ 4 | "routing type must be 4 for SRH (RFC 8754)" |
| Hdr Ext Len mismatch | SRHConfig.HdrExtLen（planner 填入，§5.2）与 builder 实际序列化的 SRH 总长不符（公式 `(总长/8)-1`） | 见 §7.7 EXC-01（"hdr_ext_len mismatch"），错误定义与示例统一在 EXC-01 |
| PadN Type 错误 | builder 内部 PadN 使用 Type ≠ 4 | （不应发生，builder 内部断言） |
| Pad1 多字节场景误用 | builder 内部对 ≥2 字节填充误用 Pad1（Type=0，应使用 PadN） | （不应发生，builder 内部断言；RFC 8754 §2.1.1.1 禁止 Pad1 用于 ≥2 字节） |
| Flags 非 0 | SRHConfig.Flags ≠ 0 | （Validate 已挡，builder 兜底拒绝） |
| Direction=down + SegmentsLeftPtr 非 nil | §5.4 限制 | "direction=down requires source-node view (segments_left not set)"（VR-23） |
| 解封装类 payload_protocol 错误 | seg_type ∈ {end.dx6, end.b6, end.b6.encaps, end.b6.encaps.red} 且 payload_protocol ≠ "ipv6" | （VR-15 已挡） |
| Next Header=59 + 非空 InnerPayload | seg_type ∉ 解封装/封装类且 payload_protocol="none" 且 inner_payload 非空 | （VR-22 已挡，报错而非警告） |

### 9.3 运行时错误

| 错误 | 触发条件 | 处理 |
|------|----------|------|
| Payload Length 溢出 | SRH + 内层 > IPv6 Payload Length uint16 上限 | Validate 报错 "payload length overflow" |
| 大 SegmentList OOM | 127 段 × 16 字节 = 2032 字节 | 不 OOM（流式 yield，不聚合） |
| 大 Frames OOM | Frames=10000 | 不 OOM（流式 yield） |

### 9.4 集成点互斥

| 互斥项 | 规则 | 错误信息 |
|--------|------|----------|
| SRv6 + MPLS | VR-16 | "srv6 cannot combine with mpls (v1 limitation)" |
| SRv6 + GRE | VR-17 | "srv6 cannot combine with gre (v1 limitation)" |
| SRv6 + PPPoE | PPPoE 内层仅 IPv4，不允许 IPv6 扩展头 | "srv6 cannot combine with pppoe (pppoe inner is IPv4-only)" |
| SRv6 + IPv4 | spec.SrcIP 是 IPv4 | VR-06 "srv6 requires IPv6" |

---

## 10. 扩展字段映射

### 10.1 SRv6 元数据（写入 PacketConfig.Metadata）

| Metadata key | 取值 | 说明 |
|--------------|------|------|
| srv6_seg_type | SRv6Config.SegType | 直接取值 |
| srv6_segments_left | SRHConfig.SegmentsLeft | 序列化后的最终值 |
| srv6_last_entry | SRHConfig.LastEntry | 序列化后的最终值 |
| srv6_segment_count | len(SRHConfig.SegmentList) | **wire 反序后的段数**（reduced SRH 下 = n-1，SR Policy 段数 n 见 srv6_policy_segments） |
| srv6_policy_segments | len(SRv6Config.SegmentList) | **SR Policy 段数 n**（用户配置口径，reduced 流也 = n；report 聚合用此口径，§10.2） |
| srv6_reduced | SRHConfig.Reduced | bool → 0/1 |
| srv6_hdr_ext_len | 计算值 | 2N + T/8（non-reduced）/ 2(N-1) + T/8（reduced）；H-SRV6-R3-5 修正后的公式 |
| srv6_srh_total_len | 计算值 | 8 + 16N + T（non-reduced）/ 8 + 16(N-1) + T（reduced） |
| srv6_dst_ipv6 | SRv6Config.DstIPv6 或默认 | 序列化后的 DstIP |
| srv6_tag | SRHConfig.Tag | 16-bit |
| srv6_flags | SRHConfig.Flags | 0x00 |
| srv6_tlv_count | len(SRHConfig.TLV) | 不含 builder 自动插入的 PadN |
| srv6_hmac_present | flow 内存在 TLV Type=5 | bool → 0/1 |
| srv6_hmac_key_id | HMAC TLV Key ID（若存在） | 4 字节 uint32 |
| srv6_hmac_d_bit | HMAC TLV D bit（若存在） | bool → 0/1 |
| srv6_hmac_tlv_total_len | HMAC TLV 总长（若存在） | 8 + HMAC_len；HMAC=32 时为 40（C-SRV6-R3-1 修正） |
| srv6_frames | SRv6Config.Frames | 默认 1 |
| srv6_direction | SRv6Config.Direction | "up"/"down" |
| srv6_payload_protocol | SRv6Config.PayloadProtocol | "tcp"/"udp"/"icmpv6"/"ipv6"/"none" |
| srv6_inner_payload_len | len(SRv6Config.InnerPayload) | 字节数 |

**多流标识说明**（M-SRV6-R3-5）：SRv6 流的"5-tuple"= **外层 IPv6 SrcIP/DstIP + 内层 L4 SrcPort/DstPort + 内层协议号（6/17/58）**。外层 IPv6 Next Header（43 = SRH）不是 L4 协议号，**不参与** FlowID hash 输入；多流识别使用内层协议号。FlowID = hash(SrcIP, DstIP, InnerSrcPort, InnerDstPort, InnerProtocol)。

### 10.2 report 聚合（srv6ProtRpt 节点）

| report 字段 | 聚合方式 |
|-------------|----------|
| seg_type | 取 flow 内 srv6_seg_type 众数 |
| total_segments | sum(srv6_policy_segments)（**SR Policy 段数口径**，reduced 流也计满 n 段） |
| avg_segments_left | mean(srv6_segments_left) |
| max_segments_left | max(srv6_segments_left) |
| reduced_count | count(srv6_reduced == 1) |
| total_hdr_ext_len | sum(srv6_hdr_ext_len) |
| tag_count | count(srv6_tag != 0) |
| hmac_count | count(srv6_hmac_present == 1) |
| frames_total | sum(srv6_frames) |
| direction_down_count | count(srv6_direction == "down") |
| payload_protocol_distribution | groupby(srv6_payload_protocol) 计数 |
| inner_payload_bytes_total | sum(srv6_inner_payload_len) |

**口径说明**（M-SRV6-R3-6）：`total_segments` 使用 **SR Policy 段数口径**（srv6_policy_segments = 用户配置的 SegmentList 长度 n），保证聚合结果与用户配置一致——reduced 流 wire 段数 n-1 仅体现在 srv6_segment_count 元数据中，不参与 report 聚合。

**实现要点**：
1. `internal/core/report.go` 新增 `srv6ProtRpt` 节点处理函数，遍历 `PacketConfig.Metadata["srv6_*"]` 字段聚合。
2. Planner 在 emit 每个 PacketConfig 时，将 SRv6 元数据写入 `Metadata` map（key 前缀 `srv6_`）。
3. report 层不解析 SRv6 字节，仅消费 Metadata，与 pcap 字节解耦。
4. 测试覆盖：T-SRV6-BND-13（reduced 流 report 口径）验证 `total_segments` 在 reduced 流下使用 srv6_policy_segments 口径（= n，不是 wire 段数 n-1）；T-SRV6-AUD-02（API → engine → builder → writer 全链路）验证任务状态 completed 与 pcap 含 SRH 帧。

---

## 11. 修订记录

| 日期 | 版本 | 修订内容 |
|------|------|---------|
| 2026-08-03 | 1.0 | 初始版本（85 条用例）。 |
| 2026-08-03 | 1.1 | 对抗审计（`audit/11-15-dnp3-srv6-audit.md` §3，14 问题）修复。修正类：C-SRV6-1 用例虚胖（删 16 条硬重复）；C-SRV6-2 Hdr Ext Len 自报错误；H-SRV6-1 SegmentList[0] 语义；H-SRV6-2 Hdr Ext Len 单位；H-SRV6-3/4 MPLS/GRE 互斥理由；M-SRV6-1..5 seg_type 覆盖/InnerSrcPort/SegmentsLeftSet/Hdr Ext Len 上限；L-SRV6-1..3 编号冲突/报错信息/网卡硬编码。新增 17 条 NEW 用例。 |
| 2026-08-04 | 2.0.0 | 深度对抗审计（`audit/15-srv6-audit-deep.md`，21 问题：7 CRITICAL + 6 HIGH + 5 MEDIUM + 3 LOW）系统性返工。基于 RFC 8754 / RFC 8200 原文 WebFetch 逐字核对，修正 v1.1 的 7 个协议根本性错误：C-SRV6-R2-1 Segment List 反序存储（List[0]=最后一段，List[n-1]=第一段）；C-SRV6-R2-2 DstIP = SegmentList[n-1]（非 [0]）；C-SRV6-R2-3 SRH PadN Type=4（非 1）；C-SRV6-R2-4 SRH Flags 全 8 位 Unused（HMAC 由 TLV 携带，非 Flag 位）；C-SRV6-R2-5 HMAC-Sig TLV Type=6 不存在（已 Reserved）；C-SRV6-R2-6 Reduced SRH 省略 List[n-1]（非 List[0]），LastEntry=n-2；C-SRV6-R2-7 End* 地址更新公式 DA=SegmentList[SL_new]（SL 减 1 后的新值，非 LastEntry-SL+1）。HIGH 修正：H-SRV6-R2-1 Hdr Ext Len 公式 + 127 段+TLV 溢出；H-SRV6-R2-2 Direction="down" SRv6 反向流语义（含 SegmentList 反转）；H-SRV6-R2-3 BYT-01 字节偏移排除 HopByHop 共存；H-SRV6-R2-4 IPv6 头 Traffic Class 偏移（跨字节 0-1）；H-SRV6-R2-5 LastEntry reduced SRH 边界（0..125）；H-SRV6-R2-6 HMAC TLV 8n 对齐规则。MEDIUM/LOW 同步修正。新增 15 个 HexDump 场景（S1-S15）逐字节核算 Hdr Ext Len；新增 SegmentsLeftPtr *uint8 替代 SegmentsLeftSet bool；用例总数 107 → 130（新增 BYT-16..20 / BND-02..04,09..11 / V-P-16 / V-N-13..15,21..23 / P-16,17 / E2E-09,10 / AUD-09,10 / NEW-14 改 end.un）。文档结构按 §1-§11 重组。 |
| 2026-08-05 | 2.0.1 | 复审（`audit/15-srv6-audit-r1-v2.md`，21 问题：2 CRITICAL + 8 HIGH + 7 MEDIUM + 4 LOW）修复。**CRITICAL**：C-SRV6-R3-1 HMAC TLV 三套数字统一（RFC 8754 §2.1.2：Length=38(0x26)=D+RES(2)+KeyID(4)+HMAC(32)，TLV 总长 40，8n 对齐；§6.4/§6.14 HexDump 删多余 PadN，BND-09 重算）；C-SRV6-R3-2 End.DX6/End.B6.Encaps 外层 SRH Next Header 59→41（RFC 8986 §4.4/§4.13/§4.14），PayloadProtocol 新增 "ipv6"，P-04/S6/S10/E2E-11/VR-15/V-N-21 同步。**HIGH**：H-R3-1/8 五帧 HexDump IPv6 Payload Length 重算（S2/S12=0x4c、S4/S14=0x48、S13=0x800、S6=0x50、S5=0x28、S10=0x60，UDP/TCP payload 缺省 0 字节声明 §5.2.1）；H-R3-2 Reduced 默认规则（SegType=end.b6.encaps.red → 默认 true，§5.3 S11）；H-R3-3 Pad1/PadN 尾部填充规则（§3.2.1，BND-12）；H-R3-4 S15 视角递增由多 FlowSpec 串联表达，Frames 不改 SRH 内容；H-R3-5 Hdr Ext Len 公式去 -1（§3.2.1/§4.1/VR-18/19）；H-R3-6 SRHConfig 新增 HdrExtLen 字段（planner 计算填入、builder 复核，EXC-01/NEW-16 成立）；H-R3-7 Direction=down 仅源节点视角（VR-23/V-N-24/DD-07）。**MEDIUM**：M-R3-1 IPv6 无校验和声明（§3.1/BYT-21）；M-R3-2 UDP/TCP 伪头 Next Header=内层协议号、长度不含 SRH（BYT-13/14）；M-R3-3 VR-22 改为报错并排除解封装类；M-R3-4 ICMPv6 Echo 头字段表 + 校验和（§6.16 S16/BYT-21/P-11）；M-R3-5 FlowID = 外层 IPv6 对+内层端口对+内层协议号（§1.3/§6.12/§10.1）；M-R3-6 report 改 srv6_policy_segments 口径（§10.1/§10.2/BND-13）；M-R3-7 S4/S14 UDP 数据报长度 0 说明。**LOW**：L-R3-1 删除 §6.1 "Wait" 草稿与重复 HexDump；L-R3-2 builder 层 SegmentList 改 [][]byte、类型注释同步；L-R3-3 删除"文档总行数"占位符；L-R3-4 §10.2 实现要点 4 改挂 BND-13。新增用例 10 条（V-P-17,18 / V-N-24 / P-18 / BYT-21 / BND-12,13 / E2E-11 / NEW-18,19），新增场景 §6.16 S16；用例总数 130 → 140。 |
| 2026-08-05 | 2.0.2 | 复审（`audit/15-srv6-audit-r2-v2.md`，9 问题：0 CRITICAL + 2 HIGH + 4 MEDIUM + 3 LOW）修复。**HIGH**：H-SRV6-R4-1 L4 校验和伪头 DstIP 按 RFC 8200 §8.1 用**最终目的**（SRv6 特有规则：伪头 DstIP = SegmentList[0] = SR Policy 最后一段，非外层 DstIP=第一段；builder SRH 路径不得复用 calculateIPv6PseudoHeader 的外层地址；§3.1 新增"L4 伪头 DstIP 规则"小节，BYT-13/14 补最终目的，中转节点视角同样适用，新增 BYT-22 多段校验和断言用例）；H-SRV6-R4-2 UDP over IPv6 零校验和非法（RFC 8200 §8.1："IPv6 receivers must discard UDP packets containing a zero checksum"）：删除 S1/S4/S5/S7/S14/S15 全部"校验和=0 合法"表述，改为"必须计算，得 0 写 0xFFFF 替代（与 builder calculateUDPChecksum 0→0xFFFF 实现一致）"；S1 补真实校验和 0x0684（伪头 fc00:1::1→fc00:2::2 反码和，Python 重算）。**MEDIUM**：M-SRV6-R4-1 S16 ICMPv6 校验和 0xB6D9→**0xB6D6**（原值是用 fc00::1/fc00::2 算出的，与 HexDump 地址 fc00:1::1/fc00:2::2 不符；Python 重算确认）；M-SRV6-R4-2 S4/S14 HexDump 行标 0x0070→**0x0068**（0x60 行实际仅 8 字节 SRH 尾部，UDP 起始 = 0x68 = 104）；M-SRV6-R4-3 S10 内层 UDP 头补全定义（SrcPort/DstPort=0 spec 默认、Length=8、校验和由 builder 计算，伪头 DstIP=内层 SRH 最终目的=fc00:inner::2）；M-SRV6-R4-4 RFC 章节引用错号修正（§2.3→§2、§4.3.1→§4.3.1.1、RFC 8986 §4.3.2→§4.13 End.B6.Encaps、§4.3.x→§4.4/§4.13/§4.14、§6→§4.13、§4.x→§5.1/§5.2/§5.3 PSP/USP/USD）。**LOW**：L-SRV6-R4-1 VR-15 补 end.dt4（payload_protocol="ipv4"，RFC 8986 §4.8）/end.dt6（payload_protocol="ipv6"，RFC 8986 §4.9）协议约束，新增 NEW-01a/01b 用例；L-SRV6-R4-2 §9.2 Hdr Ext Len mismatch 行改为交叉引用 §7.7 EXC-01 去重；L-SRV6-R4-3 §5.2.1 补内层 UDP/TCP 端口缺省值声明（Inner* 为 0 时取 spec.SrcPort/spec.DstPort），S4/S5/S7/S14/S15 字段构成补端口值。同步修订：§1.1 RFC 引用表补全 RFC 8986 章节、P-11/BYT-21/E2E-02 补最终目的语义。新增用例 3 条（BYT-22 / NEW-01a / NEW-01b）；用例总数 140 → 143。 |

---

**文档版本**：v2.0.2
**修订时间**：2026-08-05
**修订依据**：`docs/protocol-designs/audit/15-srv6-audit-r2-v2.md`（9 问题：0 CRITICAL + 2 HIGH + 4 MEDIUM + 3 LOW）
**协议规范**：RFC 8754（SRH）、RFC 8200（IPv6）、RFC 8986（SRv6 Network Programming，参考用）
**用例总数**：143 条（V-P 18 + V-N 24 + P 18 + BYT 22 + MF 5 + BND 13 + EXC 1 + E2E 11 + AUD 10 + NEW 21）
**HexDump 场景数**：16 个（S1-S16）
**对应实现工单**：#29 SRv6（参考 `docs/protocol-designs/00-unimplemented-list.md`）
**下一步**：实现者按 §5 字段定义 → §6 HexDump 场景 → §7 测试用例 顺序开发，每完成一个 §7 子节就跑 `go test -race ./internal/protocol/srv6/`，遵循 `CLAUDE.md` 测试策略 8 条强制规则。
