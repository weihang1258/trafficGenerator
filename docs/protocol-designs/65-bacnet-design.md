# BACnet（楼宇自动化控制网络数据通信协议，Building Automation and Control Network / ASHRAE 135）设计契约

> 版本：v2.1.0（设计阶段）
> 日期：2026-09-01
> 状态：按《协议设计文档与用例文档需求文档 v1.3》完成行为面全枚举重审修复轮（审查员 rr-bacnet：行为面 181 点，✓123/半23/✗35；confirmed findings 10 条（5C+3D+2N）+1 拍板项按判例升格），本版 v2.1.0 为修复轮产物：语义 ID 53 → **97（55 正 + 42 负）**，待 rr-bacnet 复验；v1.1 流程的 14 项审查修复（v2.0.1）记录见 §10 修订记录。
> 配套文件：`docs/protocol-designs/65-bacnet-testcase.md`、`trafficgen/test/protocol_pcap/cases/bacnet.json`（当前 JSON 仅含注册前置占位，本版不写文件、不改代码）
> 规范基线与证据等级（逐项标注出处）：
> ① **ANSI/ASHRAE 135（BACnet 标准，等同 ISO 16484-5）**——条款号引用：Clause 6（网络层，NPDU 控制八位组 6.2.2）、Clause 18（Error/Reject/Abort 错误码组合）、Clause 20（应用层数据编码：20.1.2.4 max-segs-accepted、20.1.2.5 max-APDU-length-accepted、20.2.1 标签通用规则、20.2.1.3.2 构造数据开/闭标签、20.2.6 Real 编码、20.2.7 Double 编码）、Clause 21（APDU 形式化描述）、Clause 23（私有扩展约束）、**Annex J（BACnet/IP，BVLC 与 UDP 47808）**。ASHRAE 135 全文非公开免费分发，条款号以参考实现源码注释逐条引用（见②）与公开综述交叉印证；本文不臆造未印证的条款号，服务级细节一律以②为线格式权威出处；
> ② **bacnet-stack 参考实现**（Steve Karg 维护的开源 BACnet 协议栈，BTL 互操作测试参考栈，github.com/bacnet-stack/bacnet-stack，master 分支）——本文 §3 全部字节布局逐行对照其组包/解包函数给出（出处写"SDK `文件.函数`"）；
> ③ **本机实测**：tshark 3.6.14（Wireshark）`-G fields`/`-G protocols` + 按②逻辑手工构造 pcap 实证（UDP 47808 自动解码、逐字段提取吻合，见用例文档 §1；Wireshark `packet-bvlc.c`/`packet-bacnet.c`/`packet-bacapp.c` dissector 源码同步比对）。
> 修订记录：v2.0.0（2026-09-01）：按《协议设计文档与用例文档需求文档 v1.1》重写，取代 2026-08-20 旧稿（旧稿见 git 历史；旧稿为 20 用例粗粒度契约、无线格式细节，全部重排）。**端序勘误**：本项目任务简报曾假定"Real 为 IEEE 754 小端"——**错误**；本版实证（tshark 解码 + bacnet-stack `encode_bacnet_real` 源码）钉死 BACnet 全部数值字段**统一大端（最高有效字节在前）**，包括 Real/Double，见 §3.4 端序表。

## 1. 范围、profile 和未注册边界

本版定义 **BACnet/IP（BVLC Type 0x81，Annex J）** 的明文 UDP 链路：BVLC 虚拟链路控制（12 种功能函数）、NPDU 网络层数据单元（控制八位组/路由地址/网络层消息）、APDU 八种 PDU 类型（确认请求/非确认请求/SimpleACK/ComplexACK/SegmentACK/Error/Reject/Abort）、应用层服务子集（Who-Is/I-Am/Who-Has/I-Have 发现，ReadProperty/WriteProperty/ReadPropertyMultiple 读写，SubscribeCOV/UnconfirmedCOVNotification 订阅通知，DeviceCommunicationControl 管理，Error/Reject/Abort 失败路径）、应用/上下文标签编码（13 种应用标签全枚举）、APDU 分段（请求/响应双向）与 SegmentACK、BBMD 边界（外部设备登记/BDT/FDT 管理，只断编码不断言真实转发）、IPv4/IPv6、多会话/并发会话与多事务。

| profile（协议档案） | 承载 | 本版允许内容 | 不从 profile 推导 |
|---|---|---|---|
| `bacnet_ip_udp_v1`（主 profile） | UDP 明文（端口 47808） | BVLC 0x81 全部 12 种功能（Secure-BVLL 除外）、NPDU/APDU、§1 服务子集、分段、BBMD 编码边界 | 真实 BBMD 已跨网转发、设备真实在线、属性值真实持久化、COV 被现场接受 |
| `bacnet_ipv6_v1` | 同上，仅外层 IPv6/UDP | 同 `bacnet_ip_udp_v1`，BVLC/NPDU/APDU 字节完全一致 | 从 IPv4 fixture 推导 IPv6 地址 |
| `bacnet_mstp_boundary` | MS/TP（RS-485 令牌环） | **仅边界声明，不设语义用例**：MS/TP 为另一种数据链路（令牌/帧类型/地址编码完全不同），与 BACnet/IP 无线格式共享 | 臆造 MS/TP 帧格式 |
| `bacnet_bvll6_boundary` | BACnet/IPv6（BVLL Type 0x82，带 6 字节虚拟设备地址） | **仅边界声明**：B/IPv6 BVLL 头与 0x81 不同（虚拟源/目的地址），本版不实现 | 把 IPv6 fixture 误当 BACnet/IPv6 BVLL |
| `bacnet_secure_boundary` | BACnet/SC（TLS/WebSocket）与 Secure-BVLL（BVLC 0x0C） | **仅边界声明**：未解密只观察外层，不声称看见 NPDU/APDU | 把加密载荷当明文 BACnet |

**服务子集声明**（功能层正例覆盖集，其余显式边界）：Unconfirmed：I-Am(0)、I-Have(1)、UnconfirmedCOVNotification(2)、Who-Has(7)、Who-Is(8)；Confirmed：SubscribeCOV(5)、ReadProperty(12)、ReadPropertyMultiple(14)、WriteProperty(15)、DeviceCommunicationControl(17)。**边界（不实现、不臆造、不进正例）**：其余全部确认/非确认服务（TimeSynchronization、ReinitializeDevice、AtomicRead/WriteFile、ReadRange、SubscribeCOVProperty、ConfirmedCOVNotification、EventNotification、VT/Security/PrivateTransfer 等）——现网分量低或需全状态设备模型；厂商私有扩展经 UnconfirmedPrivateTransfer（Clause 23）承载，本版不产生。网络层消息仅实现 Who-Is-Router-To-Network(0x00)→I-Am-Router-To-Network(0x01) 一对；其余 NLM 类型（0x02–0x19：路由表初始化/安全载荷/网络号发现等）与 **Vendor NLM（Message Type ≥0x80 + Vendor ID 字段，v2.1 D-3⑤ 显式声明）**均为边界、本版不产生。

当前仓库没有注册 `bacnet` layer（层）、planner（规划器）、validator（校验器）或生成器。`cases/bacnet.json` 只保留一个不计入语义 ID 的注册前置占位 `bacnet_neg_unregistered`（`expect_error=true`、`error_contains="unknown layer"`）。占位的拒绝、0 包或空 PCAP 不得报告为 BACnet 行为通过；注册后按本文 §9 与用例文档 §2 的同一顺序替换为 97 个语义用例。

**输出契约（pcap/NIC 双输出，v2.1 C-2）**：本契约的用例同时服务于 pcap（抓包文件）与 port_group/NIC（网卡）两种输出路径——两路径共用同一份 cases JSON、同一 tshark 字段/帧字节断言，NIC 路径仅抓包口不同，不改变断言语义（与 64-cwmp/66-doh/67-onvif/68-hl7/70-megaco 同形）。**并发会话（v2.1 C-1 翻案纳入）**：废除 v2.0.1"UDP 无连接故不适用"声明（与 megaco #45 UDP 判例相斥——无连接恰使并发交错无握手成本）；单会话事件序仍受 §5 状态机约束，并发只作用于生成器级多连接交错（判例 cwmp⑦/doh#24/onvif#56/hl7#26/megaco#45），`sessions[]` 增 `concurrent: true`（§6），正例 `bacnet_concurrent_sessions`（用例 47）。流关联显式不适用声明**保留**（理由见 §4，本轮不翻案）。

## 2. 协议栈、端口和固定偏移

推荐层链为 `[udp, bacnet]`（引擎自动补 `ip`；需要显式地址族时写 `[ip, udp, bacnet]` 或 IPv6 等价链）。BACnet/IP 报文是 UDP payload 的**整体内容**（无额外长度前缀，UDP 数据报边界即 BACnet 报文边界）——与 coap/udp 同款"UDP 之上直接组帧"的终结层形态。**无 TCP 握手/挥手**：BACnet/IP 是无连接 UDP 协议，一个"会话"就是同一四元组上的一串数据报（见 §5）。

端口：BACnet/IP 默认 UDP 端口 **47808（0xBAC0）**（Annex J；IANA 分配 `bacnet` 端口）。本版 fixture 统一 `src_port=dst_port=47808`；**tshark 仅在 UDP 源或目的端口为 47808 时自动按 BACnet 解码**（本机实测：47809 端口上的相同字节只显示为普通 UDP，见用例文档 §1），故 47808 是断言可执行性的硬约束，配置覆盖端口须显式声明且实现期不得静默回退。多会话用**不同源 IP**区分四元组（源端口保持 47808 以保证 tshark 解码）。

固定偏移：无 VLAN（虚拟局域网）与 IP options 时，**BVLC 首字节（Type 0x81）起点为 IPv4 offset（偏移）42（Ethernet 14 + IPv4 20 + UDP 8）、IPv6 offset 62**（14 + IPv6 40 + UDP 8；构造 pcap 实测：54 字节帧（12B UDP payload）的 BVLC 恰在 42，帧长 - payload = 42）。APDU 起点随 NPDU 变长（§3.2 长度公式），无固定偏移；断言以 tshark `bacapp.*` fields + frames 变长偏移表达。

**IP 分片边界**：单帧 UDP payload 上界受 BVLC Length 2 字节（65535）与以太网 MTU 限制；本版全部 fixture 的 BVLC+NPDU+APDU ≤ 1476+9 字节（单个以太网帧内，不触发 IP 分片），跨"段"的报文由 **APDU 应用层分段**承载（§3.3/§8），不依赖 IP 分片。

## 3. 线格式编码（逐项标注出处）

### 3.1 BVLC（BACnet/IP 虚拟链路控制，Annex J；SDK `datalink/bvlc.h` 常量表 + `datalink/bvlc.c`）

每条 BACnet/IP 报文 = **Type（1 字节）+ Function（1 字节）+ Length（2 字节大端）+ 功能负载**。Length 是**从 BVLC 起始到整个报文末尾**的字节数（含 4 字节头自身），不是 NPDU 长度，也不是 UDP 长度。

| 偏移 | 字段 | 宽度 | 值域 | 端序 | 必选 | 出处 |
|---:|---|---:|---|---|---|---|
| 0 | Type | 1B | `0x81`（BACnet/IP） | — | 是 | SDK `BVLL_TYPE_BACNET_IP`；tshark `bvlc.type` |
| 1 | Function | 1B | `0x00`–`0x0C` | — | 是 | §3.1 功能表；tshark `bvlc.function` |
| 2 | Length | 2B | 4–65535，= 报文总长 | **大端** | 是 | Annex J；tshark 实测 wire 值在帧 offset 44–45 |

功能函数表（12 种实现 + 1 边界；负载形状与长度公式逐条）：

| Function | 名称 | 负载 | Length 公式 | 方向 |
|---:|---|---|---|---|
| 0x00 | BVLC-Result | 2 字节结果码（下表） | 6 | BBMD→请求方 |
| 0x01 | Write-Broadcast-Distribution-Table | N × (6B B/IP 地址[IP 4B+port 2B 均 BE] + 4B 广播掩码) | `4 + 10N` | 配置方→BBMD |
| 0x02 | Read-Broadcast-Distribution-Table | 无 | 4 | 任意→BBMD |
| 0x03 | Read-Broadcast-Distribution-Table-Ack | 同 0x01 负载 | `4 + 10N` | BBMD→请求方 |
| 0x04 | Forwarded-NPDU | 6B 原始源 B/IP 地址 + NPDU | `10 + len(NPDU)` | BBMD→外部设备 |
| 0x05 | Register-Foreign-Device | 2B TTL（秒） | 6 | 外部设备→BBMD |
| 0x06 | Read-Foreign-Device-Table | 无 | 4 | 任意→BBMD |
| 0x07 | Read-Foreign-Device-Table-Ack | N × (6B 地址 + 2B TTL + 2B 超时，均 BE) | `4 + 10N` | BBMD→请求方 |
| 0x08 | Delete-Foreign-Device-Table-Entry | 6B 外部设备地址 | 10 | 管理方→BBMD |
| 0x09 | Distribute-Broadcast-To-Network | NPDU | `4 + len(NPDU)` | 外部设备→BBMD |
| 0x0A | Original-Unicast-NPDU | NPDU | `4 + len(NPDU)` | 设备↔设备 |
| 0x0B | Original-Broadcast-NPDU | NPDU | `4 + len(NPDU)` | 设备→广播域 |
| 0x0C | Secure-BVLL | — | — | **边界，不实现**（§1） |

BVLC-Result 结果码（SDK `bvlc.h` 常量表）：`0x0000` 成功；`0x0010` Write-BDT NAK；`0x0020` Read-BDT NAK；`0x0030` Register-Foreign-Device NAK；`0x0040` Read-FDT NAK；`0x0050` Delete-FDT-Entry NAK；`0x0060` Distribute-Broadcast NAK；`0xFFFF` 无效。**tshark 注意**：`bvlc.length` 字段是 dissector 计算值（功能 >0x08 恒显示 4、0x04 显示 10、<0x09 显示头值），**不是线上的 Length 原值**（本机实测，Wireshark `packet-bvlc.c` 584–639 行）；线上 Length 断言走 frames offset 44–45 的 2 字节 hex，或用 `udp.length` 换算（`udp.payload 字节数 + 8`）。

### 3.2 NPDU（网络层数据单元，Clause 6 / Figure 6-1；SDK `npdu.c npdu_encode_pdu`）

NPDU = **Version（1B）+ Control（1B）+ [条件路由字段] + [条件网络层消息头] + NSDU（APDU 或网络层消息体）**。

| 偏移 | 字段 | 宽度 | 值域/条件 | 端序 | 出处 |
|---:|---|---:|---|---|---|
| 0 | Version | 1B | `0x01`（ASHRAE 135-1995 起） | — | SDK；tshark `bacnet.version` |
| 1 | Control | 1B | 见下表逐位 | — | Clause 6.2.2；tshark `bacnet.control` |
| 2 | DNET | 2B | 0–65535，仅 bit5=1；**0xFFFF=全局广播**（Annex J 路由语义，正例 53——与 NLM 消息体内 DNET 字节同形不同义，路由侧/消息体侧分开断言） | 大端 | `bacnet.dnet` |
| 4 | DLEN | 1B | 0=广播（DADR 缺省）/6=B/IP MAC（IP+端口）；**其他值=对端其他链路 MAC 长度，BACnet/IP 合法域仅 {0,6}，本版不产生（v2.1 D-3③ 显式声明），DLEN∉{0,6} 进负例** | — | `bacnet.dlen` |
| — | DADR | DLEN B | 仅 DLEN>0 | — | `bacnet.dadr_*` |
| — | SNET | 2B | 仅 bit3=1 | 大端 | `bacnet.snet` |
| — | SLEN | 1B | 仅 bit3=1；**0 非法**（源长度不能为空） | — | `bacnet.slen` |
| — | SADR | SLEN B | 仅 SLEN>0 | — | `bacnet.sadr_*` |
| — | Hop Count | 1B | **仅 DNET 存在时**；初始 `0xFF` | — | `bacnet.hopc` |
| — | Message Type | 1B | **仅 bit7=1**；0x00–0x19，≥0x80 为厂商私有 | — | `bacnet.mesgtyp` |
| — | Vendor ID | 2B | 仅 Message Type ≥ 0x80 | 大端 | `bacnet.vendor` |

Control 八位组逐位（Clause 6.2.2，SDK 逐行注释；tshark 布尔子字段全实证）：

| 位 | 含义 | 0 / 1 |
|---:|---|---|
| bit7 (0x80) | NSDU 含网络层消息 | 0=APDU（Message Type 缺省）/ 1=网络层消息（Message Type 必现） |
| bit6 (0x40) | 保留 | 恒 0 |
| bit5 (0x20) | 目的说明符 | 0=DNET/DLEN/DADR/HopCount 全缺省 / 1=上述字段按序出现 |
| bit4 (0x10) | 保留 | 恒 0 |
| bit3 (0x08) | 源说明符 | 0=SNET/SLEN/SADR 缺省 / 1=上述字段出现（SLEN=0 非法） |
| bit2 (0x04) | 期望回复 | 1=本 NSDU 是确认请求/ComplexACK 段/期望回复的网络层消息 |
| bit1–0 | 网络优先级 | `00` Normal / `01` Urgent / `10` Critical Equipment / `11` Life Safety |

直连 BACnet/IP 设备间（无路由器）：Control 通常 `0x00`（无地址信息、普通优先级）或 `0x04`（确认请求期望回复）。经路由器/BBMD 才出现 DNET/SNET 与 Hop Count。**Hop Count 仅随 DNET 出现**（SDK 源码注释：仅当目的为远程网络时存在，初始 0xFF）。网络层消息（本版仅一对）：Who-Is-Router-To-Network（0x00，可选 2B DNET）→ I-Am-Router-To-Network（0x01，DNET 列表 ×2B）；bit7=1 时 NSDU 不再是 APDU。

NPDU 长度公式：`2 + (bit5 ? 3+DLEN : 0) + (bit3 ? 3+SLEN : 0) + (bit5 ? 1 : 0) + (bit7 ? 1 + (type≥0x80 ? 2 : 0) + len(NLM体) : 0) + len(NSDU)`。

### 3.3 APDU（应用层数据单元，Clause 21；SDK `basic/service/h_apdu.c apdu_handler`）

首字节 = **PDU 类型（高 4 位）+ 类型内标志（低 4 位）**。八种 PDU 类型：

| 类型值 | PDU | 首字节低 4 位标志 | 后续字段（按序） |
|---:|---|---|---|
| 0x0_ | Confirmed-Request | bit3 SEG（分段）bit2 MOR（后续还有段）bit1 SA（接受分段响应，正例 52）bit0 保留=0 | [1] max-segs/max-APDU（下表）[2] Invoke ID [3] Sequence Number（仅 SEG）[4] Proposed Window Size（仅 SEG）[5] Service Choice [6..] 服务请求 |
| 0x1_ | Unconfirmed-Request | 保留=0 | [1] Service Choice [2..] 服务请求 |
| 0x2_ | SimpleACK | 保留=0 | [1] Invoke ID [2] Service Ack（回显请求 Service Choice） |
| 0x3_ | ComplexACK | bit3 SEG bit2 MOR | [1] Invoke ID [2] Sequence Number（仅 SEG）[3] Proposed Window Size（仅 SEG）[4] Service Ack [5..] 服务应答 |
| 0x4_ | SegmentACK | bit3–bit2 保留=0、bit1 NAK、bit0 SRV（服务器发出） | [1] Invoke ID [2] Sequence Number [3] Window Size |
| 0x5_ | Error | 保留=0 | [1] Invoke ID [2] Service Choice [3..] error-class + error-code（应用标签 Enumerated ×2） |
| 0x6_ | Reject | 保留=0 | [1] Invoke ID [2] Reject Reason |
| 0x7_ | Abort | bit0 SRV | [1] Invoke ID [2] Abort Reason |

**Invoke ID（0–255）是确认事务的关联标识**：SimpleACK/ComplexACK/Error/Reject/Abort/SegmentACK 必须回显触发它的 Confirmed-Request 的 Invoke ID（Clause 21；SDK TSM）。Unconfirmed-Request 无 Invoke ID。max-segs（高 4 位，Clause 20.1.2.4）与 max-APDU（低 4 位，Clause 20.1.2.5）编码表（SDK `bacdcode.c encode_max_segs_max_apdu`，tshark `bacapp.response_segments`/`bacapp.max_adpu_size` 实证）：

| max-segs 码 | 段数 | max-APDU 码 | 字节 |
|---:|---|---:|---:|
| 0 | 未指定 | 0 | 50 |
| 1 | 2 | 1 | 128 |
| 2 | 4 | 2 | 206 |
| 3 | 8 | 3 | 480 |
| 4 | 16 | 4 | 1024 |
| 5 | 32 | 5 | 1476 |
| 6 | 64 | 6/7 | 未定义（本版不用） |
| 7 | >64 | | |

分段规则（Clause 20.1.2 + Clause 21）：SEG=1 时 Sequence Number 从 0 起，每段递增；MOR=1 表示还有段、MOR=0 为末段；Proposed Window Size 1–255（接收方逐窗回 SegmentACK，window_size=0 非法）；每个段的完整头部字段（max-segs/Invoke ID/service choice）在**首段**之后各段重复携带（ComplexACK 分段无 max-segs 字节，见上表）。分段单位是 APDU，不是 UDP 报文；tshark 自动重组并给出 `bacapp.fragment.count`/`bacapp.reassembled.length`（实测）。

APDU 长度公式：Confirmed-REQ `3 + (SEG?2:0) + 1 + len(请求)`；Unconfirmed `2 + len(请求)`；SimpleACK `3`；ComplexACK `2 + (SEG?2:0) + 1 + len(应答)`；SegmentACK `4`；Error `3 + len(class+code 标签编码)`；Reject `3`；Abort `3`。

### 3.4 应用/上下文标签编码（Clause 20.2.1；SDK `bacdcode.c encode_tag`）

每个应用层数据值前有**标签字节**：bits7–4 = Tag Number（0–14 直存；`0xF`=扩展，后跟 1 字节真实 tag number）；bit3 = Class（0=应用标签，1=上下文标签）；bits2–0 = Length/Value/Type（LVT）：

| LVT | 含义 |
|---:|---|
| 0–4 | 内容字节数 0–4（Boolean 特例：应用标签下 0=FALSE、1=TRUE，无内容字节） |
| 5 | 内容 >4 字节：后跟 1 字节长度（内容 5–253） |
| 5+`254` | 长度标记 254：后跟 2 字节**大端**长度（内容 ≤65535） |
| 5+`255` | 长度标记 255：后跟 4 字节大端长度 |
| 6 | **开标签**（仅上下文标签，构造数据起点，无内容） |
| 7 | **闭标签**（仅上下文标签，与开标签同 Tag Number 配对） |

**无符号/枚举整数编码钉死取最短式**（v2.0.1 策略声明）：内容 ≤4B 时 LVT 直存内容字节数、**不使用** LVT=5 扩展长度（Clause 20.2.1；SDK `encode_application_unsigned` 行为）——如 Unsigned 1476=`22 05c4`（2B 内容直存）、厂商 ID 15=`22 000f`、max-APDU 1024=`22 0400`；扩展式 `25 02 05c4` 虽合法但本协议栈不产生，正例断言按最短式锚定。仅内容 >253B 的字符串/八位组串走 LVT=5 长度字节（>65535B 才用 255 四字节档，本版单帧不可达，见 §8）。

13 种应用标签（Clause 20.2；SDK `bacenum.h BACNET_APPLICATION_TAG`）：0 Null、1 Boolean、2 Unsigned、3 Signed Integer、4 Real、5 Double、6 Octet String、7 Character String、8 Bit String、9 Enumerated、10 Date、11 Time、12 BACnetObjectIdentifier；13–15 保留。Context 标签号由各服务 ASN.1 定义（§3.6 逐服务给出）。

**端序总表（全协议统一大端，逐字段实证——tshark 解码 + SDK 源码双通道）**：

| 字段 | 端序 | 出处/实证 |
|---|---|---|
| BVLC Length | 大端 | 构造 pcap 帧内 `00 0C` 解码 12 |
| DNET/SNET/TTL/FDT 字段/Vendor ID | 大端 | SDK `encode_unsigned16`（MSB 先写）；tshark 实测 |
| Unsigned/Signed（任意宽度 1–4B）/Enumerated | 大端 | 同上 |
| BACnetObjectIdentifier（4B 复合） | 大端 | 同上 |
| **Real（tag 4）/ Double（tag 5）** | **大端**（IEEE 754 最高有效字节在前） | **SDK `bacreal.c encode_bacnet_real`（小端主机显式字节反转成 MSB 先发）+ 本机 pcap 实测：`41 B4 00 00` → tshark `bacapp.present_value.real=22.5`，反向字节序显示为垃圾值**。任务简报"Real 小端"说法据此勘误 |
| Date（4B：年-1900/月/日/星期）/Time（4B：时分秒/厘秒） | 逐字节，无多字节端序问题 | Clause 20.2 |
| Character String | 1B 字符集编码（0=ANSI/UTF-8 家族，4=UCS-2，见 tshark `bacapp.string_character_set`）+ 内容字节 | 实测 |
| Bit String | 1B 未用位数 + MSB 在前的位序列 | Clause 20.2 |

### 3.5 对象与属性编码

**BACnetObjectIdentifier**（4 字节，大端）= **对象类型（高 10 位）| 对象实例（低 22 位）**。标准对象类型 0–127（SDK `bacenum.h`：0 Analog Input、3 Binary Input、8 Device、19 Multi-State Value、20 Trendlog 等 62 种，2016 版起）；**厂商私有类型 128–1023**。实例 0–4194303（0x3FFFFF；SDK `BACNET_MAX_INSTANCE`）。I-Am 的设备标识必须为 Device 类型（8）。

**BACnetPropertyIdentifier**（Enumerated）：标准属性 0–511（SDK `bacenum.h`：75 object-identifier、77 object-name、79 object-type、85 present-value、107 segmentation-supported、120 vendor-identifier、62 max-APDU-length-accepted 等）；512+ 厂商私有。**数组下标**（Unsigned）：缺省=非数组属性；**0=整个数组**（SDK `BACNET_ARRAY_ALL` 语义）；>0=具体元素。

### 3.6 服务逐个编码（服务请求/应答形状；SDK 逐函数）

| 服务 | 选择码 | 方向/承载 | 参数编码（Context 标签号） | SDK 函数 |
|---|---:|---|---|---|
| Who-Is | 8（Unconf） | 客户→广播/单播 | 可选 [0] low-limit（ctx Unsigned）、可选 [1] high-limit（ctx Unsigned）；**均缺省=全局无限制**（最小服务请求 0 字节） | `whois.c whois_request_encode` |
| I-Am | 0（Unconf） | 设备→发现方 | 4 个应用标签依次：设备对象 ID（必为 device 类型）、max-APDU（Unsigned，值域 50/128/206/480/1024/1476）、分段能力（Enumerated 0=both/1=transmit/2=receive/3=none）、厂商 ID（Unsigned ≤65535） | `iam.c bacnet_iam_request_encode` |
| Who-Has | 7（Unconf） | 客户→广播 | 可选 [0] low-limit、可选 [1] high-limit（成对出现）；二选一：[2] object-identifier（ctx ObjectID）**或** [3] object-name（ctx CharacterString） | `whohas.c bacnet_who_has_request_encode` |
| I-Have | 1（Unconf） | 设备→发现方 | 3 个应用标签：设备 ID、对象 ID、object-name（CharacterString） | SDK `ihave.c` |
| ReadProperty | 12（Conf-REQ） | 客户→设备 | [0] 对象 ID（ctx ObjectID）、[1] 属性 ID（ctx Enumerated）、可选 [2] 数组下标（ctx Unsigned） | `rp.c read_property_request_encode` |
| ReadProperty 应答 | 12（ComplexACK） | 设备→客户 | [0] 对象 ID、[1] 属性 ID、可选 [2] 数组下标、[3] 开/闭标签包裹属性值（任意应用标签） | `rp.c read_property_ack_encode` |
| WriteProperty | 15（Conf-REQ） | 客户→设备 | [0] 对象 ID、[1] 属性 ID、可选 [2] 数组下标、[3] 开/闭标签包裹写入值、可选 [4] 优先级（ctx Unsigned 1–16；缺省语义=16 最低优先级） | `wp.c write_property_request_encode` |
| ReadPropertyMultiple | 14（Conf-REQ） | 客户→设备 | SEQUENCE OF ReadAccessSpecification：[0] 对象 ID、开[1] { (ctx0 属性 ID、可选 ctx1 数组下标)* } 闭[1]；可重复多对象 | `rpm.c read_property_multiple_request_encode` |
| SubscribeCOV | 5（Conf-REQ） | 客户→设备 | [0] 订阅者进程 ID（ctx Unsigned）、[1] 被监测对象 ID（ctx ObjectID）、可选 [2] issue-confirmed-notifications（ctx Boolean）、可选 [3] lifetime（ctx Unsigned 秒）；**[2][3] 均缺省=取消订阅** | `cov.c cov_subscribe_apdu_encode` |
| UnconfirmedCOVNotification | 2（Unconf） | 设备→订阅者 | [0] 订阅者进程 ID、[1] 发起设备 ID（device 类型）、[2] 被监测对象 ID、[3] time-remaining（ctx Unsigned 秒）、开[4] { (ctx0 属性 ID、可选 ctx1 下标、开[2]值 闭[2])* } 闭[4] | `cov.c cov_notify_encode_apdu` |
| DeviceCommunicationControl | 17（Conf-REQ） | 管理方→设备 | 可选 [0] time-duration（ctx Unsigned 16 位分）、[1] enable/disable（ctx Enumerated 0=enable/1=disable/2=disable-initiation）、可选 [2] password（ctx CharacterString） | SDK `dcc.c` |
| Error | （ComplexACK 替代） | 设备→客户 | 应用标签 error-class（Enumerated）+ 应用标签 error-code（Enumerated），Clause 18 组合约束 | `bacerror.c bacerror_encode_apdu` |
| Reject | — | 设备→客户 | 首字节表后 1 字节理由：0 other/1 buffer-overflow/2 inconsistent-parameters/3 invalid-parameter-data-type/4 invalid-tag/5 missing-required-parameter/6 parameter-out-of-range/7 too-many-arguments；64–255 厂商私有 | SDK `bacenum.h BACNET_REJECT_REASON` |
| Abort | — | 任一方 | 1 字节理由：0 other/1 buffer-overflow/2 invalid-apdu-in-this-state/3 preempted-by-higher-priority-task/4 segmentation-not-supported/5 security-error/6 insufficient-security/7 window-size-out-of-range/8 application-exceeded-reply-time/9 out-of-resources/10 tsm-timeout/11 apdu-too-long；64–255 厂商私有 | SDK `bacenum.h BACNET_ABORT_REASON` |

**Error class/code 本版取值子集**（Clause 18 组合表中挑现网常见组合，其余不产生但保留负例值域校验）：class 2 (property) + code 32 (unknown-property)；class 2 + code 40 (write-access-denied)；class 2 + code 42 (invalid-array-index)；class 2 + code 37 (value-out-of-range)；class 0–7 + 64–65535 为合法值域边界。

### 3.7 每报文总长度公式汇总

| 报文 | 公式（字节） |
|---|---|
| BVLC 任意 | `4 + len(功能负载)`（§3.1 表） |
| NPDU | §3.2 公式 |
| APDU | §3.3 公式 |
| UDP payload | `= BVLC Length` |
| 以太网帧 | `14 + 20(IPv4)/40(IPv6) + 8 + BVLC Length` |
| Who-Is（无限制） | UDP payload = `4+2+2 = 8`（**BACnet/IP 最小帧**） |
| Who-Is（带范围） | `4+2+2+2+2 = 12`（低/高限各 1B 标签+1B 值） |
| I-Am | `4+2 + 2 + 5+3+2+3 = 21`（APDU 头 2 + 对象 ID 5 + max-APDU 3 + 分段能力 2 + 厂商 ID 3——无符号/枚举最短式，§3.4 策略；构造 pcap 实测帧 63B = 42+21 ✓） |
| ReadProperty 请求 | `4+2 + 4 + (1+4)+(1+1) = 17`（APDU 头 4：类型/maxsegs/invoke/service；实测帧 59B ✓） |
| ReadProperty 应答（Real 值） | `4+2 + 3 + (1+4)+(1+1)+1+1+4+1 = 23`（APDU 头 3 + 开标签 1 + Real 标签 5 + 闭标签 1；实测帧 65B ✓） |
| WriteProperty 请求（布尔值+优先级） | `4+2 + 4 + (1+4)+(1+1)+1+1+1+(1+1) = 22`（开标签+布尔 1B+闭标签+优先级 2B；实测帧 64B ✓） |
| SimpleACK | `4+2+3 = 9`（实测帧 51B ✓） |
| 分段 ComplexACK（每段） | `4+2 + 2+2+1 + 段内容`（APDU 头 2 + seq 1 + window 1 + service ack 1） |
| 标签开销 | 1B（内容≤4）/ 2B（5–253）/ 4B（≤65535：标记254+2B长度） |

## 4. 业务场景分析（现网典型场景与五层覆盖）

**定性声明**：本引擎对 BACnet 采用**声明式脚本化回放**——配置是剧本（sessions[]/events[] 逐条声明），引擎是回放者，按序产出 UDP 数据报；"事件驱动"一词不用于定性整体行为，仅用于两处反应性成分：①**自动应答**（收到 Who-Is 自动补 I-Am、收到确认请求自动补 ACK/Error、收到 BBMD 管理请求（RFD/Write-BDT/Delete-FDT）自动补 BVLC-Result、收到分段自动补 SegmentACK；Distribute-Broadcast 成功为静默转发，不自动补 Result——见 §5⑤）；②**会话边界**（事件序列中源地址/源端口切换即新的事件编排会话，UDP 无连接故无握手开销）。

| 现网场景 | 事务交互 | 驱动顺序 | 对应用例 |
|---|---|---|---|
| ① 设备发现（最常见：BA 系统上线扫描） | Who-Is（广播或定向）→ 各设备 I-Am（设备实例/能力） | 客户端发起，设备应答（自动应答成分） | `bacnet_bvlc_unicast_baseline`、`bacnet_bvlc_broadcast`、`bacnet_min_frame` |
| ② 点位轮询（BMS 周期采集温湿度/状态） | ReadProperty（confirmed）→ ComplexACK（值） | 客户端驱动，逐点或逐对象 | `bacnet_read_property`、`bacnet_read_property_array_index` |
| ③ 批量读取（大型系统一次取多对象多属性） | ReadPropertyMultiple → ComplexACK 多值 | 客户端驱动 | `bacnet_read_property_multiple` |
| ④ 控制下发（开阀/启停/设定值） | WriteProperty（优先级）→ SimpleACK | 客户端驱动；不声称现场执行 | `bacnet_write_property`、`bacnet_write_property_no_priority` |
| ⑤ COV 订阅告警（值变化推送，替代高频轮询） | SubscribeCOV → SimpleACK →（值变化时）UnconfirmedCOVNotification →（到期/主动）SubscribeCOV 取消 → SimpleACK | 客户端订阅，设备推送 | `bacnet_subscribe_cov`、`bacnet_cov_notification`、`bacnet_subscribe_cov_cancel` |
| ⑥ 跨子网/BBMD 部署（园区多子网广播） | 外部设备 Register-Foreign-Device(TTL)→Result；BBMD Forwarded-NPDU 转发；Distribute-Broadcast-To-Network | 外部设备与 BBMD 交互 | `bacnet_bvlc_register_foreign`、`bacnet_bvlc_forwarded`、`bacnet_bvlc_distribute_broadcast` 及 BDT/FDT 管理用例 |
| ⑦ 路由发现（多网络号环境） | 网络层消息 Who-Is-Router-To-Network → I-Am-Router-To-Network | 客户端发起 | `bacnet_npdu_router_discovery` |
| ⑧ 远程管理（禁用通信/门禁） | DeviceCommunicationControl → SimpleACK | 管理方驱动 | `bacnet_device_communication_control` |
| ⑨ 失败路径（读不存在属性/写被拒/超长） | Error(class=property, code=unknown-property)/Reject/Abort，Invoke ID 关联 | 设备侧合法错误应答 | `bacnet_error_response`、`bacnet_reject`、`bacnet_abort`、`bacnet_bvlc_result_nak` |
| ⑩ 单客户端多事务（连续轮询/控制序列） | invoke ID 递增的多笔确认事务 | 客户端驱动 | `bacnet_multi_transaction`、`bacnet_invoke_id_boundary` |

**五层覆盖逐层结论**：功能层——BVLC 12 种功能函数每种正例（Secure-BVLL 边界除外）、APDU 八种 PDU 类型每种正例、§1 服务子集（10 服务）每服务至少 1 正例（请求/应答分开断言）、确认服务每失败形态（Error/Reject/Abort）各 1 正例、网络层消息 1 对正例；每类错误分支负例（§7，42 行逐故障输入：线格式×19、长度×3、值域×9、关联×3、载体×5、状态机×3）。性能层——大 CharacterString（1024B，2 字节扩展长度档）单帧内最大载荷、BACnet/IP 最小帧 8 字节、APDU 分段跨段（请求/应答双向、seq/window/SegmentACK、tshark 重组字段）、max-APDU 1476 上界与编码档位。数据场景层——13 种应用标签全枚举、LVT 三档长度编码、上下文标签开闭配对、对象类型标准/私有边界、实例 0/0x3FFFFF 边界、Invoke ID 0/255 边界、优先级 1–16/缺省 16、分段能力 4 值、TTL/lifetime 值域。地址与流层——IPv4/IPv6 独立 fixture、UDP 单流基线、多会话（多源 IP 四元组按序展开）、**并发会话（v2.1 C-1 翻案纳入，`concurrent: true` 交错回放，正例 47）**、非默认端口显式声明合法通道（正例 46，47809 + `-d` DecodeAs）；**流关联（控制流派生数据流）显式不适用（保留）**：BACnet/IP 单 UDP 流承载全部信令与数据，协议无控制/数据分离概念（Annex J 全文无副连接）。业务层——发现/轮询/控制/订阅/管理/失败路径/多会话多事务均为楼宇自控现网日常（BACnet 是 BAS 主导协议），优先于教科书全服务遍历。

## 5. 消息/事务模型与状态机

**事务定义**：BACnet 事务 = 同一 UDP 通信关系内一次完整的请求/响应交互，**关联标识为 Invoke ID（0–255）**。**两档关联**：①确认事务（Confirmed-Request → SimpleACK/ComplexACK/Error/Reject/Abort，Invoke ID 配对，应答必须回显）；②无 Invoke 事务——非确认事务（Who-Is→I-Am、Who-Has→I-Have，一问一答靠时序配对）与 BBMD 管理事务（RFD/Write-BDT/Delete-FDT/Distribute→BVLC-Result，靠 BVLC 功能与方向配对）。**多事务** = 一个会话内多笔确认事务按序执行，Invoke ID 递增不重用（客户端在收到应答前不得复用 Invoke ID——TSM 约束，Clause 21）；**事务交互**示例：先 Who-Is 发现设备，后 ReadProperty 逐点读取（§4⑩）。

设备侧会话状态机（确定性：同一事件序列必然产出同一帧序列，无随机/未定义行为；生成器在某状态下遇到非法事件——如 ACK 事件无前置确认请求——必须拒绝并报状态机错误，不得静默产出）：

| 状态 | 允许事件（→目标状态） | 必须保持 |
|---|---|---|
| `Idle` | 发任意请求（→`Active`）；收 Who-Is/Who-Has→自动应答（保持） | Invoke ID 从配置值起（默认 0 或 1），不复用未完成事务的 ID |
| `Active`（有待完成确认事务） | 收到对应 Invoke ID 的 ACK/Error/Reject/Abort（→`Idle`）；发送下一个请求（保持，Invoke ID 递增） | 应答 Invoke ID = 请求 Invoke ID；同会话未完成事务期间不发出同 ID 新请求 |
| `SegmentRx`（分段接收中） | 收到窗口内 seq 段（保持，逐段或逐窗回 SegmentACK）；收到 MOR=0 末段（→`Idle`，重组完成） | seq 按窗递增；窗口外/回绕段拒绝 |
| `Subscribed`（COV 订阅存续） | 发 COVNotification（保持）；收到取消订阅请求（→`Idle`） | time-remaining 递减语义由 fixture 显式声明，不隐含时间流逝 |

**自动派生规则**（引擎自动补出的帧，逐条列出触发条件与内容；均可被事件显式覆盖）：①**I-Am**——who_is 事件后自动补（设备实例/max-APDU/分段能力/厂商 ID 从会话配置取）；②**SimpleACK/ComplexACK**——confirmed 请求事件后按配置自动补应答（回显 Invoke ID 与 Service Choice；ComplexACK 的属性值从事件配置取）；③**Error/Reject/Abort**——事件配置 `respond: error/reject/abort` 时替代 ACK 补失败应答（回显 Invoke ID）；④**SegmentACK**——分段事件按窗口自动补 `0x4_` 帧（回显 Invoke ID、seq=已收最大序号、window）；⑤**BVLC-Result**——RFD/Write-BDT/Delete-FDT 事件后自动补 `0x00` 帧结果码（默认 0x0000，可配 NAK）；**Distribute-Broadcast 不自动补 Result**——Annex J 语义：外部设备注册成功后 BBMD 静默转发分发，成功路径无应答（正例 11 packet_count=1），仅事件显式配置失败时产生 NAK 码 0x0060 帧；⑥**Read-BDT-Ack/Read-FDT-Ack**——read_bdt/read_fdt 事件后按配置的表项自动补；⑦**I-Am-Router-To-Network**——router_discovery 事件后按配置网络号列表自动补。

**多会话展开**：`sessions[]` 按序整块回放——先跑完第 1 个会话全部事件，再跑第 2 个，不交错；**第二会话包号起点 = 前一会话总包数 + 1**。各会话四元组（源 IP/端口）独立、Invoke ID 序列与设备身份互不串用。**并发会话（v2.1 C-1 翻案）**：`sessions[]` 支持 `concurrent: true` 交错回放（正例 47）——交错只作用于生成器级多连接，各会话内部事件序/事务配对/状态机断言不放宽。**重传与异常终止口径（v2.1 N-2）**：UDP 无连接——无握手/挥手/RST/保活/重连语义，正例不携带 `has_handshake`/`terminates`；协议级异常中断 = Abort（正例 28）；TSM 重传由 events[] 显式编排（重复 invoke 同 ID 帧序列），协议层重传定时器不实现。UDP 无连接：会话首包即业务包（无握手），会话末包即结束（无挥手），用例 `expect` 不携带 `has_handshake`/`terminates`（恒 false）。

## 6. 配置 typedef（JSON 形状示例，非 Go 代码）

```json
{
  "layers": [{"udp": {}}, {"bacnet": {}}],
  "src_ip": "192.0.2.66", "dst_ip": "198.51.100.66",
  "src_port": 47808, "dst_port": 47808,
  "bacnet": {
    "sessions": [
      {
        "src_ip": "192.0.2.66", "src_port": 47808,
        "events": [
          {"kind": "who_is", "low": 0, "high": 100, "respond_i_am": true},
          {"kind": "i_am", "device_instance": 100, "max_apdu": 1476,
           "segmentation": 3, "vendor_id": 15},
          {"kind": "read_property", "invoke_id": 1,
           "object_type": "analog-input", "instance": 1,
           "property": "present-value",
           "respond": {"ack": "complex", "value": {"type": "real", "value": 22.5}}},
          {"kind": "write_property", "invoke_id": 2,
           "object_type": "analog-input", "instance": 1,
           "property": "present-value",
           "value": {"type": "boolean", "value": true}, "priority": 8,
           "respond": {"ack": "simple"}},
          {"kind": "subscribe_cov", "invoke_id": 3, "process_id": 1,
           "object_type": "device", "instance": 5,
           "issue_confirmed": true, "lifetime": 600, "respond": {"ack": "simple"}},
          {"kind": "cov_notification", "process_id": 1,
           "initiating_device": 5, "object_type": "device", "instance": 5,
           "time_remaining": 540,
           "values": [{"property": "present-value", "value": {"type": "real", "value": 23.0}}]}
        ]
      },
      {"src_ip": "192.0.2.67", "src_port": 47808,
       "events": [
         {"kind": "register_foreign_device", "ttl": 600,
          "respond": {"result": "0x0000"}},
         {"kind": "read_bdt",
          "respond": {"entries": [{"ip": "192.0.2.88", "port": 47808,
                                    "mask": "255.255.255.0"}]}}
       ]}
    ],
    "wire_fault": ""
  }
}
```

形状要点：`sessions[]` = 统一术语的**事件编排会话**（各自带四元组与事件序列，多会话展开按序整块回放，第二会话包号起点 = 前会话总包数 + 1；`concurrent: true` 交错回放——v2.1 C-1，正例 47）；`events[].kind` 覆盖 `who_is`/`i_am`/`who_has`/`i_have`/`read_property`/`write_property`/`rpm`/`subscribe_cov`/`cov_notification`/`dcc`/`error`/`reject`/`abort`/`segmented_request`/`segmented_ack`/`register_foreign_device`/`write_bdt`/`read_bdt`/`read_fdt`/`delete_fdt`/`distribute_broadcast`/`forwarded_npdu`/`router_discovery`/`raw_npdu`（NPDU 层变体注入口：dest/src 地址、hop、优先级、NLM）；`respond` 子对象驱动 §5 自动派生（`respond_i_am`/`ack`/`result`/`entries`/NAK 码）；`value.type` 覆盖 13 种应用标签；`wire_fault` 仅负例注入口，**42 值枚举与 §7 表/用例 §5 表三方同序**：`bvlc_type`、`bvlc_function`、`bvlc_secure`、`bvlc_length_min`、`bvlc_length_mismatch`、`bvlc_length_forwarded`、`npdu_version`、`npdu_dest_missing`、`npdu_src_len_zero`、`npdu_reserved_bits`、`npdu_no_message_type`、`npdu_dlen_invalid`、`apdu_type_invalid`、`apdu_header_confirmed`、`apdu_header_simpleack`、`service_confirmed_unimplemented`、`service_unconfirmed_invalid`、`tag_lvt_mismatch`、`tag_open_unmatched`、`tag_boolean_lvt`、`tag_context_number`、`object_type_overflow`、`object_instance_overflow`、`object_iam_not_device`、`property_id_vendor`、`property_index_negative`、`priority_range`、`error_class_range`、`invoke_mismatch`、`invoke_reuse`、`segment_extra_fields`、`segment_missing_fields`、`segment_window_zero`、`segment_sequence_skip`、`carrier_layer_missing`、`carrier_tcp`、`port_undeclared`、`address_family_mismatch`、`address_family_derived`、`state_ack_no_request`、`state_iam_no_whois`、`state_cov_no_subscribe`；不得成为线上字段。**配置到帧的完整路径**：配置 → validator（层链/端口 47808/事件序状态机/字段值域/Invoke ID 关联与唯一性/标签结构校验）→ planner（事件序列展开为 UDP 数据报序列，逐报文按 §3 公式计算 BVLC Length 与各层长度）→ worker（组包：BVLC 头 + NPDU + APDU + 标签化服务参数；自动派生帧按 §5 插入）→ writer（IPv4/IPv6 + UDP 输出，端口 47808）→ PCAP/NIC。

## 7. 错误处理（负例锚词表）

以下输入必须由 planner/validator 拒绝并传播为 task error（任务错误），不得产出成功 PCAP、`completed/0 packet` 或只剩 UDP 外壳的假成功。**逐故障输入原子拆分（v2.1 C-3）：一行一例，钉死该行注入的单一 `wire_fault`/配置变异；主锚词为钉死的单一字面值**（不再是候选列表），与用例文档 §5 表一一对应（42 行同序）：

| # | 负例 ID | 类别 | 故障输入（单一注入） | 主锚词 `error_contains` |
|---:|---|---|---|---|
| 56 | `bacnet_neg_bvlc_type` | 线格式错 | BVLC Type ≠0x81（如 0x80/0x82/0xFF） | `type` |
| 57 | `bacnet_neg_bvlc_function` | 线格式错 | BVLC Function ∉0x00–0x0B 明文功能域（如 0x0D/0xFF） | `function` |
| 58 | `bacnet_neg_bvlc_secure` | 线格式错 | Secure-BVLL 0x0C 被当明文产生（§1 边界：只观察外层） | `secure` |
| 59 | `bacnet_neg_bvlc_length_min` | 长度错 | BVLC Length <4（如 3，头自身都不完整） | `length` |
| 60 | `bacnet_neg_bvlc_length_mismatch` | 长度错 | BVLC Length ≠ 4+功能负载实际字节（如 >UDP payload） | `length` |
| 61 | `bacnet_neg_bvlc_length_forwarded` | 长度错 | Forwarded-NPDU(0x04) Length 未计入 6B 原始源地址 | `length` |
| 62 | `bacnet_neg_npdu_version` | 线格式错 | NPDU Version ≠0x01（如 0x00/0x02） | `version` |
| 63 | `bacnet_neg_npdu_dest_missing` | 线格式错 | Control bit5=1 而 DNET/HopCount 缺失 | `dnet` |
| 64 | `bacnet_neg_npdu_src_len_zero` | 线格式错 | Control bit3=1 而 SLEN=0（源长度不能为空） | `snet` |
| 65 | `bacnet_neg_npdu_reserved_bits` | 线格式错 | Control 保留位 bit6/bit4 置 1（恒 0） | `control` |
| 66 | `bacnet_neg_npdu_no_message_type` | 线格式错 | Control bit7=1 而 Message Type 缺失 | `control` |
| 67 | `bacnet_neg_npdu_dlen_invalid` | 值域错 | DLEN ∉{0,6}（BACnet/IP 合法域；如 DLEN=1，其他值属其他链路 MAC 长度，本版不产生——D-3③） | `dlen` |
| 68 | `bacnet_neg_apdu_type_invalid` | 线格式错 | APDU 首字节高 4 位 >7（如 0x80–0xFF） | `apdu` |
| 69 | `bacnet_neg_apdu_header_confirmed` | 线格式错 | Confirmed-Request 头部不完整（缺 max-segs 字节，仅 2 字节） | `header` |
| 70 | `bacnet_neg_apdu_header_simpleack` | 线格式错 | SimpleACK <3 字节（仅 2 字节） | `header` |
| 71 | `bacnet_neg_service_confirmed_unimplemented` | 线格式错 | Confirmed Service Choice 不在 §1 子集（如 34 ReadRange） | `service` |
| 72 | `bacnet_neg_service_unconfirmed_invalid` | 线格式错 | Unconfirmed Service Choice ∉{0,1,2,7,8}（如 3） | `service` |
| 73 | `bacnet_neg_tag_lvt_mismatch` | 线格式错 | LVT=4 而内容仅 2 字节（长度与内容不符） | `lvt` |
| 74 | `bacnet_neg_tag_open_unmatched` | 线格式错 | 开标签无同号闭标签配对（如 0x3E 无 0x3F） | `tag` |
| 75 | `bacnet_neg_tag_boolean_lvt` | 线格式错 | Boolean 应用标签 LVT=2（合法仅 0=FALSE/1=TRUE） | `tag` |
| 76 | `bacnet_neg_tag_context_number` | 线格式错 | 上下文标签号超出服务 ASN.1 定义 | `tag` |
| 77 | `bacnet_neg_object_type_overflow` | 值域错 | 对象类型 >1023（10 位溢出，如 1024） | `object` |
| 78 | `bacnet_neg_object_instance_overflow` | 值域错 | 对象实例 >4194303（22 位溢出，如 4194304） | `instance` |
| 79 | `bacnet_neg_object_iam_not_device` | 值域错 | I-Am 设备标识对象类型 ≠8（device） | `object` |
| 80 | `bacnet_neg_property_id_vendor` | 值域错 | 属性 ID >511 而未声明厂商私有（如 512/0xFFFFF） | `property` |
| 81 | `bacnet_neg_property_index_negative` | 值域错 | 数组下标为负（如 -1） | `property` |
| 82 | `bacnet_neg_priority_range` | 值域错 | WriteProperty 优先级 ∉1–16（如 0/17） | `priority` |
| 83 | `bacnet_neg_error_class_range` | 值域错 | error-class 越域（合法 0–7 与 64–65535；如 8 或 65536）——D-3⑦ | `error` |
| 84 | `bacnet_neg_invoke_mismatch` | 关联错 | 应答（ACK/Error/Reject/Abort/SegmentACK）Invoke ID ≠ 触发请求的 Invoke ID | `invoke` |
| 85 | `bacnet_neg_invoke_reuse` | 关联错 | 同一会话未完成事务期间复用同一 Invoke ID | `invoke` |
| 86 | `bacnet_neg_segment_extra_fields` | 线格式错 | SEG=0 却携带 Sequence Number/Window Size 字段 | `segment` |
| 87 | `bacnet_neg_segment_missing_fields` | 线格式错 | SEG=1 缺 Sequence Number/Window Size 字段 | `segment` |
| 88 | `bacnet_neg_segment_window_zero` | 值域错 | Proposed Window Size=0（合法 1–255） | `window` |
| 89 | `bacnet_neg_segment_sequence_skip` | 关联错 | Sequence Number 回绕/跳变（非窗口内单调递增） | `sequence` |
| 90 | `bacnet_neg_carrier_layer_missing` | 配置/载体错 | 层链缺 udp（`[{"bacnet":{}}]` 直连） | `carrier` |
| 91 | `bacnet_neg_carrier_tcp` | 配置/载体错 | TCP 载体声明（BACnet/IP 仅 UDP，Annex J） | `carrier` |
| 92 | `bacnet_neg_port_undeclared` | 配置/载体错 | 端口 ≠47808 而未显式声明（静默回退禁止） | `port` |
| 93 | `bacnet_neg_address_family_mismatch` | 配置/载体错 | IPv6 地址配 IPv4 层链（`[ip,udp,…]` 形态） | `family` |
| 94 | `bacnet_neg_address_family_derived` | 配置/载体错 | 从 IPv4 fixture 推导 IPv6 地址（须独立 fixture） | `address` |
| 95 | `bacnet_neg_state_ack_no_request` | 状态机错 | ACK/Error 事件无前置确认请求 | `state` |
| 96 | `bacnet_neg_state_iam_no_whois` | 状态机错 | I-Am 事件无前置 Who-Is（自动应答关闭时） | `state` |
| 97 | `bacnet_neg_state_cov_no_subscribe` | 状态机错 | COV 通知事件无前置订阅 | `state` |

**不得误报为 planner error 的合法协议事件**（防误报）：BVLC-Result NAK 码（0x0010–0x0060，合法错误路径正例 6）、Error/Reject/Abort 应答（合法失败路径正例 26–28）、Who-Is 无参数（最小帧）、WriteProperty 无优先级（缺省 16 语义）、SubscribeCOV 取消（[2][3] 均缺省）、array_index=0（整个数组）、max-segs=0（未指定）、CharacterString 空串。只有配置、线格式、长度、状态机或关联错误进入负例。

## 8. 边界

- **帧长上界**：单 UDP 数据报内 BVLC Length ≤65535（2 字节字段）；本版 fixture 上界 = max-APDU 1476 + NPDU ≤9 + BVLC 4，以太网帧 ≤1518 内不分片；**超过 1476 字节的应用数据必须走 APDU 分段**（§3.3），不走 IP 分片。
- **最小帧**：Who-Is 无参数 = BVLC 4 + NPDU 2 + APDU 2 = **8 字节 UDP payload**（以太网帧 50B）。
- **Invoke ID**：0–255 全域合法；0 与 255 为边界正例（34），相邻值 1/254 正例（39）；未完成事务期间不得复用（负例）。
- **边界相邻值声明（v2.1 C-4）**：下列相邻值/满值有独立正例——invoke 1/254（39）、实例 1/0x3FFFFE（40，与 33 的 0/0x3FFFFF 构成四点）、类型 127/1023（41，与 33 的 0/128 构成四点）、优先级 1/显式 16（42，与 19 中间值 8、20 缺省 16 构成四态）、window 1/255（43）、厂商 ID 65535（44）、RFD TTL 65535（45，与 5 的 0/600 构成三点）、DNET 65535 全局广播（53，与 12 的 2001 分立）。
- **对象 ID**：类型 0–1023（标准 0–127/私有 128–1023）；实例 0–4194303；实例 0 与 0x3FFFFF 为边界正例；I-Am 设备标识必须 device(8) 类型。
- **优先级**：WriteProperty [4] 1–16，缺省语义 16；NPDU 网络优先级 4 值（00/01/10/11）独立于 WriteProperty 优先级，不可混淆。
- **max-APDU/max-segs 编码档**：50/128/206/480/1024/1476 六档（code 0–5）；段数未指定=0、2=1、4=2 …64=6、>64=7。
- **标签长度三档**：内容 ≤4B（LVT 直存）/ 5–253B（LVT=5+1B 长度）/ ≤65535B（LVT=5+254 标记+2B 大端长度）；`bacnet_large_charstring` 用 1024B 覆盖第三档。
- **分段**：seq 0 起单调递增；window 1–255（提议值不是实际段数，2 段报文可携 window 255——正例 43；0 非法进负例）；请求/应答双向各自分段；段边界 ≠ UDP 报文边界（tshark 按段重组）。
- **UDP 无连接口径（v2.1 N-2）**：无握手/挥手/RST/保活/重连语义；协议级异常中断 = Abort；TSM 重传由 events[] 显式编排（重复 invoke 同 ID 帧序列），协议层重传定时器不实现。
- **TTL/lifetime/time-remaining**：u16 全域（RFD TTL 600s、COV lifetime 600s 常用值）；0=立即到期（合法）。
- **v4/v6**：IPv4/IPv6 独立 fixture，同一逻辑 BACnet 报文字节必须一致，仅外层 IP 头与 BVLC 偏移（42/62）不同；不得从 IPv4 默认值推导 IPv6 地址。
- **多会话**：≥2 个独立四元组（源 IP 区分），Invoke ID 序列/设备实例/COV 订阅互不串用；会话间包序按多会话展开（第二会话起点 = 前会话总包数 + 1）。
- **端口**：47808 默认端口（tshark 自动解码依赖）；**非 47808 显式声明即合法通道（v2.1 C-5，正例 46：47809 + `-d udp.port==47809,bacnet` DecodeAs 口径）**；未显式声明的非 47808 端口拒绝（负例），实现期不得静默改写/回退。
- **代表值策略（v2.1 更新）**：以下值域**只测代表值、不逐值设正例**，值域由 validator/负例校验兜底——① LVT 255 四字节长度档（内容 >65535B）超出单帧上限，本版不产生、仅负例 73 校验长度标记合法性；② SegmentACK NAK bit1 不设正例（正例 29/30 覆盖非 NAK 形态，分段字段一致性由负例 86–89 校验）；③ max-segs=0 不单独设例——每笔确认请求 max-segs/max-APDU 字节高 4 位即 0（如 `00 05`/`0c 23`），全部确认服务正例已覆盖；④ BVLC-Result NAK 六码只测 0x0030（正例 6）与 0x0000 成功（正例 5/7/10），其余 0x0010/0x0020/0x0040/0x0050/0x0060 为 §3.1 表值域声明、validator 校验；⑤ **码族代表值策略（v2.1 D-3乙）**：Reject 理由 0–7 与厂商段 64–255 只测 5（正例 27）；Abort 理由 0–11 与厂商段 64–255 只测 11（正例 28）；Error class 0–7 + code 组合只测 class 2/code 32 与 40（正例 26），class 8–63 越域进负例（`error_class_range`）、class 64–65535 厂商段为 §3.6 合法值域声明；max-APDU 码 0–5 六档只测 5（正例 1）与 4（正例 31），其余档位 50/128/206/480 为本表声明、不逐值设例；⑥ charset 4（UCS-2）与优先级边界 1/16 已由 v2.1 N-3 拍板**升格为例**（正例 55/42），移出本策略。**同形变体并入现有例多帧**的七项（Who-Has [2] 分支、数组下标 0、DLEN=0、TTL=0、分段能力 1/2、Error code 40 组合、Boolean FALSE）见正例 21/17/12/5/31/26/32（用例文档 §4 逐帧断言）。**不产生形态声明（v2.1 D-3②③⑤）**：扩展标签号 0xF 形态（§3.4）本版服务子集不可达、不产生；DLEN ∉{0,6} 不产生（§3.2，负例校验）；Vendor NLM（Message Type ≥0x80）不产生（§1 边界）。

## 9. 原子 ID 与完成定义

**ID 权威 = 用例文档 §2**（v2.1 D-1，megaco D-1 同款判例）：设计不再维护逐 ID 全量镜像表——v2.0.1 的"53 个唯一语义 ID 固化契约"废除；设计、testcase 与未来 `bacnet.json` 使用同一 **97 个语义 ID 集合与顺序（55 正 + 42 负）**，权威序以用例文档 §2 为准，设计按簇给出覆盖图景。当前 JSON 只放 `bacnet_neg_unregistered` 前置占位，不计入 97 个语义 ID。原子原则：一个用例只验证一个协议行为，每 BVLC 功能/每 NPDU 变体/每 PDU 类型/每服务/每标签族/每关联规则/每边界（含相邻值）/每错误分支各一。

**正例 55 条按簇**（编号 = 用例文档 §2 行号）：

- **基线与 BVLC/BBMD 族（1-11、44/45/54）**：单播基线（1）、最小帧（2）、定向广播（3）、Forwarded（4）、RFD TTL 0/600/65535 三点（5/45）、Result 成功/NAK（5-10/6）、BDT/FDT 读写删（7-10）与多表项 N=2（54）、Distribute（11）、厂商 ID 65535（44）。
- **NPDU 族（12-15、52/53）**：DNET/DLEN 路由目的（12）、SNET/SLEN 路由来源（13）、NLM 一对（14）、优先级 4 值（15）、SA bit（52）、全局广播 DNET 0xFFFF（53）。
- **服务族（16-28、42/48-51）**：RP（16/17）、RPM 单对象（18）与双对象（49）、WP 优先级 8/缺省（19/20）与边界 1/16（42）、Who-Has 按名/按 ID（21）与范围对（48）、COV 订阅三形态（22/51/24）+ 通知（23）、DCC 主形态（25）与三变体（50）、失败路径 Error/Reject/Abort/NAK（26/27/28/6）。
- **分段与事务族（29/30、34/35/39/43）**：分段请求/应答+SegmentACK（29/30）、invoke 边界 0/255（34）与相邻 1/254（39）、多事务递增（35）、window 1/255（43）。
- **编码与值域族（31/32/33/38/40/41/55）**：I-Am 能力 0/1/2（31）、13 应用标签+Boolean 双值（32）、对象边界 0/满值/私有首值（33）与相邻（40/41）、1024B 扩展长度档（38）、UCS-2 字符集（55）。
- **载体与会话族（36/37/46/47）**：IPv6 同字节（36）、多会话按序展开（37）、非默认端口 47809+DecodeAs（46）、并发交错（47）。

**负例 42 行（56-97）**：逐故障输入一行一例，与 §7 表一一对应——BVLC×6（56-61：类型/功能/Secure/长度三类）、NPDU×6（62-67：版本/控制位四型/DLEN）、APDU×3（68-70）、服务×2（71-72）、标签×4（73-76）、值域×9（77-83/88：对象/属性/优先级/error-class/window）、关联×3（84-85/89）、载体×5（90-94）、状态机×3（95-97）；`wire_fault` 42 值枚举见 §6（三方同序）。

完成定义：注册 `udp→bacnet` 层链；实现 §3 全部线格式（BVLC 12 功能、NPDU 路由/NLM、8 种 APDU、13 种标签、10 服务、双向分段）与 §5 状态机（Invoke ID 唯一性、分段重组、自动派生 7 条）；55 个正例断言（fields + frames + 重组）与 42 个负例错误传播全部完成；**注册替换占位时同步修正 `bacnet.json` 占位期陈旧 notes（"20 条/14+6"旧稿统计）为用例文档 §2 各行覆盖描述（用例文档 §7 第 8 条登记项，占位期不改 JSON）**；未注册阶段只接受 `unknown layer` 占位。BACnet/SC、Secure-BVLL、MS/TP、BACnet/IPv6 BVLL(0x82) 仍仅在明确实现后才可增加对应断言。

## 10. 修订记录

- v2.1.0（2026-09-01，v1.3 行为面全枚举重审修复轮）：rr-bacnet 181 点重审（✓123/半23/✗35；5C+3D+2N confirmed +1 拍板项）后重出：语义 ID 53 → **97（55 正 + 42 负）**。关键修复：**C-1**（CRITICAL）并发会话翻案纳入（§1/§4/§5/§6 + 正例 47 `bacnet_concurrent_sessions`，判例 megaco#45 同为 UDP）；**C-2**（CRITICAL）pcap/NIC 双输出同一契约声明（§1）；**C-3**（CRITICAL）负例逐故障输入原子拆分 15→42 行（一行一例单一注入、主锚词钉死单一字面值），§7 表整表重排、§6 `wire_fault` 枚举 42 值三方同序；**C-4** 边界相邻值正例簇（39-45，§8 相邻值声明）；**C-5** 非默认端口正例（46，§8 端口行改"显式声明即合法"+DecodeAs 口径）；**D-1**（megaco 判例）§9 固化契约废除——ID 权威改用例文档 §2，设计 §9 改簇级覆盖图景；**D-2** 五处声明形态补例（Who-Has 范围对 48、RPM 双对象 49、DCC 三变体 50、COV issue-confirmed=false 51、Boolean FALSE 并入 32 帧 3）；**D-3** 值域缺口：SA bit 例（52）+ §3.3 引用、全局广播 DNET 0xFFFF 例（53）+ §3.2 同形不同义声明、BDT/FDT 多表项例（54）、error-class 越域负例（83）、扩展标签 0xF/DLEN∉{0,6}/Vendor NLM≥0x80 不产生声明（§3.2/§8）、码族与 max-APDU 档位代表值策略（§8⑤）；**N-1** 用例 §3 IPv6 fixture 地址端口分离；**N-2** UDP 无连接 FIN/RST/保活/重连不适用与 TSM 重传 events[] 编排口径（§5/§8）；**N-3**（拍板按判例升格）charset 4（55）与优先级 1/16（42）升格正例。既有决策未改：三名合一不涉及、端序大端、无符号最短式、代表值策略框架、流关联不适用保留。

- v1.0.0（2026-08-20）：旧稿首版（14 正 + 6 负，粗粒度语义契约，无线格式细节、无端序表、无长度公式）。
- v2.0.0（2026-09-01）：按《协议设计文档与用例文档需求文档 v1.1》独立隔离审查流程重写，取代旧稿（旧稿见 git 历史）。线格式从 bacnet-stack 参考实现（BTL 参考栈）逐函数重新提炼 + 本机 tshark 3.6.14 构造 pcap 逐字段实证：钉死 BVLC 12 功能函数表与结果码、NPDU 控制八位组逐位语义与路由字段条件、8 种 APDU 头部布局、max-segs/max-APDU 编码档、13 种应用标签与 LVT 三档长度编码、10 服务参数标签号（Who-Has [3]/[4] 与 COV 通知 [0]–[4] 均以源码钉死）、**端序统一大端（含 Real/Double，勘误任务简报"Real 小端"错误假定）**；新增 §4 业务场景分析（五层逐层、流关联与并发会话显式不适用）、§5 状态机（TSM/分段/COV/自动派生 7 条）、§6 配置 typedef 与配置到帧路径、§7 负例锚词表 15 类、§8 边界；用例按 v1.1 原子原则从 20 条重排为 53 条（38 正 + 15 负）——每 BVLC 功能、每 NPDU 变体、每 APDU 类型、每服务、每标签族、每关联规则、每边界（最小帧/invoke 0/255/实例 0/0x3FFFFF/优先级/1024B 字符串）各一例。**公开资料缺处标注**：ASHRAE 135 全文非公开，条款号以参考实现注释引用与公开综述交叉印证（§规范基线①），未获印证的条款号一律不写；服务级字段布局以 bacnet-stack 源码为权威出处。状态：**待独立隔离审查**。
