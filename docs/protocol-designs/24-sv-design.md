# IEC 61850-9-2 SV（Sampled Values，采样值）协议设计

> 版本：v1.0.0（初稿）
> 设计日期：2026-08-18
> 范围：IEC 61850-9-2 采样值（SV，Sampled Values）流量的生成，含 9-2LE（Light Edition，采样值简化版）与 9-2 Full 两种配置口径；L2 直承（不经过 IP）
> 实现位置：`trafficgen/internal/protocol/sv/`（planner + 层生成器 + 校验器）、`trafficgen/internal/core/builder.go`（SV 帧头 + BER 编码的 APDU 写入）、`trafficgen/internal/core/types.go`（`SVConfig` 定义）、`trafficgen/internal/core/strategy_convert.go`（`sv` flat 键解析）
> 配套参考：同栈兄妹协议 GOOSE 设计（23-goose-design.md，事件驱动，本文档为周期驱动）；层链配置架构（18-layer-config-design.md）

---

## 目录

1. [概述](#1-概述)
2. [数据类型与编码](#2-数据类型与编码)
3. [消息结构](#3-消息结构)
4. [状态机](#4-状态机)
5. [配置类型定义](#5-配置类型定义)
6. [包序列场景（HexDump S1-Sn）](#6-包序列场景hexdump-s1-sn)
7. [与 testcase 文档的映射索引](#7-与-testcase-文档的映射索引)
8. [实现集成点](#8-实现集成点)
9. [错误处理](#9-错误处理)
10. [扩展字段映射](#10-扩展字段映射)
11. [修订记录](#11-修订记录)

---

## 1. 概述

### 1.1 SV 定位

**SV（Sampled Values，采样值）** 是 IEC 61850 标准族中用于**发布采样测量数据**的实时组播机制，由 **IEC 61850-9-2（特定通信服务映射）** 定义。它把互感器（电流互感器 CT、电压互感器 VT）在**每个采样周期**采集到的模拟量瞬时值（含测量品质 quality）以**周期数据帧**的形式，通过以太网**组播**给合并单元（MU，Merging Unit）的下游装置（主要是保护 IED、测控装置）。

与 GOOSE（Generic Object Oriented Substation Event，面向通用对象的变电站事件，GOOSE）的**事件驱动**截然不同，SV 是**时间驱动**的：

| 维度 | SV（采样值） | GOOSE（通用面向对象变电站事件） |
|------|-------------|------------------------------|
| 触发方式 | **周期**（按采样率固定间隔重发） | **事件**（数据变化/状态变化时立即发送 + 退避重发） |
| 协议标准 | IEC 61850-9-2 | IEC 61850-8-1 |
| 数据内容 | 模拟量采样值（instMag 瞬时值 + quality 品质） | 数字量/状态/模拟量（AllData 数据集） |
| 时敏性 | **硬实时**（μs 级，保护判据依赖采样时序） | 准实时（ms 级） |
| 承载 | 以太网直承（组播 MAC） | 以太网直承（组播 MAC） |
| EtherType | 0x88BA | 0x88B8 |
| 组播 MAC 段 | 01:0C:CD:04:xx:xx | 01:0C:CD:01:xx:xx |
| APDU 类型 | savPdu（采样值应用协议数据单元） | goosePdu（GOOSE 协议数据单元） |
| 重发策略 | 每个采样点发一帧（可选双重发报冗余） | 首发后按 TAL（存活时间）退避重发 |
| smpCnt | 每采样点递增，回绕 | GOOSE 无 smpCnt（有 sqNum/stNum） |

**本设计只实现 SV 的数据帧生成**，不涉及：
- MMS（制造报文规范）服务/报告（IEC 61850-8-1，TCP 102），那是另一协议
- R-SV（RFC 8100 之前基于 UDP 的改进型 SV，R-SV）。本设计只做以太网直承的 L2 SV
- IEC 61850-9-2 中 UDP/TCP 承载的 SV over IP（9-2 Full 允许，但 9-2LE 与典型用例均为以太网直承）

### 1.2 9-2LE 与 9-2 Full

**9-2LE（IEC 61850-9-2 Light Edition，采样值简化版）** 是 UCA International Users Group 在 9-2 基础上为**过程总线（process bus，变电站过程层网络）**制定的工程实现指南，大幅收敛了可选性，使互操作成为可能。9-2LE 的核心约束：

| 项 | 9-2LE 约束 |
|----|-----------|
| 采样率 | **80 采样/周**（50 Hz 系统 = 4000 采样/秒；60 Hz = 4800 采样/秒）或 **256 采样/周**（50 Hz = 12800 采样/秒） |
| 采样模型 | 每周期单采样帧（每个采样点一帧 svPdu），非批量型（区别于块模型 multi-sample-per-ASDU） |
| 通道数 | **4 电流 + 4 电压**（IA、IB、IC、IN + VA、VB、VC、VN），每相 = instMag（32 位整数）+ quality（4 字节品质位串） |
| 数据集 | `TCTR1/2/3/4` + `TVTR1/2/3/4`，svID 如 `xxxxMUnn01`（MUnn = 合并单元号，示例） |
| smpCnt 回绕 | 采样计数器增量后达**每周期采样数**即回 0（80 采样 → 0..3999；256 采样 → 0..12799 等），**同一合并单元所有相共享同一 smpCnt** |
| 帧格式 | 固定结构（以太网头 + 可选 VLAN + 0x88BA + SV 头 8 字节 + savPdu BER），无 ASN.1 可选项抖动 |
| APPID | 典型 0x4000（IEC 61850-9-2 分配区间 0x4000-0x7FFF 为 SV；SV 标准区间详见 §2.4） |
| 组播 MAC | 01:0C:CD:04:xx:xx（IEC 61850-9-2 的 SV 流分配） |

**9-2 Full（完整版 9-2）** 是规范的完整可选空间：ASDU 内所有字段（datSet、refrTm、smpRate、smpMod、gmIdentity 等）均可选，采样率任意，数据集任意（自定义数据集，如单相、混合量、浮点 instMag），ADSU 个数（每帧多 ASDU）可配置，且允许跑在 IP 之上。本设计的 `SVConfig` 提供覆盖 9-2LE 默认与 9-2 Full 自由配置的字段集（§5）。

**对比表（9-2LE vs 9-2 Full）**：

| 项 | 9-2LE（默认 profile） | 9-2 Full（自由 profile） |
|----|----------------------|-------------------------|
| 采样率 | 80 或 256 采样/周（约束） | 任意（SmpMod/SmpRate 自由声明） |
| 通道 | 4I + 4V（约束） | 任意（自定义数据集） |
| ASDU 字段 | 仅 svID + smpCnt + confRev + smpSynch + seqData（典型） | 全部可选字段可自由组合（datSet/refrTm/smpRate/smpMod） |
| smpCnt 回绕 | 每采样周期回绕（0..N-1） | 回绕上限可设（含 0xFFFF 不回绕） |
| 承载 | 仅以太网直承 | 以太网直承或 IP 承载 |
| 目标 | 过程总线互操作 | 完整规范 |

### 1.3 trafficgen 中的定位

SV 是 **L2 终结层**：配置链 `[{"eth":{}},{"sv":{}}]`——以太网帧直接承载 SV，**无 IP 层**（这是 SV 与绝大多数已实现协议的架构性差异，仅 arp/pppoe/mpls 数据面等少数协议类似）。Planner 或层的职责是：

1. 组装以太网头（组播目的 MAC 01:0C:CD:04:xx:xx、可选 VLAN、EtherType 0x88BA）
2. 组装 8 字节 SV 帧头（APPID + Length + Reserve1 + Reserve2）
3. 用 ASN.1 BER 编码 savPdu APDU（0x60 + noASDU(0x80) + seqASDU(0xa2) + ASDU(0x30) 序列）
4. 按采样周期定时产出连续帧（smpCnt 递增 + 回绕、可选双重发、smpSynch 状态位）

### 1.4 与 GOOSE 的架构对照（同栈设计）

SV 与 GOOSE 同属 IEC 61850 二层组播协议，共享大量基础设施，设计上作为**同一波（同栈）**实现：

| 协作点 | GOOSE（23-goose-design.md） | SV（本文档） |
|--------|----------------------------|--------------|
| 组播目的 MAC | 01:0C:CD:01:xx:xx | 01:0C:CD:04:xx:xx |
| EtherType 常量 | 需新增 0x88B8 | 需新增 0x88BA |
| L2 直承链 | `[eth, goose]` | `[eth, sv]` |
| BER 编码器 | goosePdu 各字段构造类型 | savPdu/ASDU 各字段构造类型 |
| 驱动方式 | 事件 + TAL 退避重发定时器 | 采样周期定时器 |
| 校验字段 | stNum/sqNum/confRev | smpCnt/confRev/smpSynch |
| Registry schema | goose：CategoryTerminal，DependsOn 无（eth 垫底不自动补，用户手写 `[eth]`） | sv：同 goose 决策（§5.4） |

两协议共用的**组播发送基础设施**（engine 对组播目的 MAC 的覆盖、VLAN 输出、pad 最小帧）可以抽象复用。

### 1.5 不实现的范围

- **R-SV over UDP/IP**：IEC 61850-9-2 允许 SV over IP（9-2 Full 的 R-SV），本设计 v1 只做以太网直承，`protocol: "udp"` 的 R-SV 不支持（validate 拒绝）
- **MMS/报告**：IEC 61850-8-1 服务（报告、控制、文件传输）不在 SV 范围
- **IEEE 1588 PTP（精确时间协议）同步语义**：smpSynch 只作为**用户可配字段**写入报文，本设计不实现 PTP 时钟同步（那是独立协议）
- **多 ASDU 批量采样块模型**（每帧一个 ASDU、一个采样点，9-2LE 的单采样模型为本设计默认；多 ASDU 与批量模型作为 9-2 Full 自由 profile 标注待决策，见 §5.4 注）
- **数据压缩/加密**：IEC 62351 安全（SV 签名/加密）在 v1 不实现

### 1.6 术语对照表（英文首现 → 中文）

| 英文（首现本文档） | 中文解释 |
|--------------------|----------|
| Sampled Values（SV） | 采样值：周期发布模拟量采样数据的组播机制 |
| Merging Unit（MU） | 合并单元：过程层采集互感器信号发布 SV 的装置 |
| Process Bus（过程总线） | 变电站过程层以太网，承载 SV/GOOSE |
| Light Edition（9-2LE） | 采样值简化版：UCA 对 9-2 的工程收敛子集 |
| Quality（品质） | 采样品质位串，描述 validity/overflow 等 |
| instMag（瞬时幅值） | 采样的瞬时值（AnalogueValue 的整数/浮点形式） |
| smpCnt（采样计数） | ASDU 内采样序号，每采样点递增后回绕 |
| confRev（配置版本） | 数据集配置版本号 |
| smpSynch（同步状态） | 采样时钟同步状态 0/1/2 |
| dsSV/SVControl | 发布控制块（发布方数据语义，v1 不涉及 MMS 控制） |
| Basic Encoding Rules（BER） | ASN.1 基本编码规则（tag+length+value） |
| Subscription（订阅） | IED 对某 APPID/目的 MAC 的采样流监听 |
| Redundancy（冗余报） | 双重发，同采样点重复发送 |

---

## 2. 数据类型与编码

### 2.1 以太网头（组播 MAC）

SV 直接承载在以太网 II（Ethernet II）帧上，**不经过 IP**。帧头：

| 字段 | 长度 | 字节序 | 值 |
|------|------|--------|-----|
| 目的 MAC（Destination Address） | 6 字节 | — | 组播 01:0C:CD:04:xx:xx（IEC 61850-9-2 SV 流段） |
| 源 MAC（Source Address） | 6 字节 | — | 发送方（合并单元）MAC，可配 |
| 可选 VLAN（802.1Q Tag） | 4 字节 | 大端 | TPID 0x8100 + TCI（优先级/VLAN ID） |
| EtherType | 2 字节 | 大端 | **0x88BA**（SV） |

**组播 MAC 分配（01:0C:CD:04:xx:xx）**：
- `01:0C:CD` 是 IEC 61850 组播组的组织唯一标识前缀（IEC 61850-8-1 分配给 GOOSE/SV 等）
- 第四字节 `04` = SV 数据流段（GOOSE 用 `01`）（IEC 61850-9-2 表 A.3/建立于 8-1 附录 A 的分配）
- 低 16 位 `xx:xx` 由用户配置（0x00-0xFF），区分不同 SV 流/合并单元；典型用例是固定分配 `04:00:xx`
- 组播目的 MAC 由用户 `SVConfig` 配置或按默认 `01:0C:CD:04:00:01`；engine 的组播覆盖机制（与 GOOSE/mdns 同款）保证该 MAC 恒为组播（不被单播回退），详见 §8.3

**与 IP 下组播 MAC 推导的区别**：mDNS/RIP 等运行在 IP 之上，目的 MAC 可从多播 IP 推导（01:00:5E/33:33）；SV **无 IP 层**，目的 MAC 就是**显式配置的静态组播地址**，不推导。

### 2.2 VLAN TPID/TCI

SV 可选挂载 802.1Q VLAN：即以太网头之后、EtherType 之前插 4 字节 `TPID(0x8100) + TCI`。

**TCI（Tag Control Information，标签控制信息）** 按 IEEE 802.1Q 大端编码：

```
TCI = Priority(3) << 13 | DropEligible/CFI(1) << 12 | VID(12)
     = 由 "priority" 与 "vlan_id" 两个配置派生
```

| 位段 | 长 | 说明 |
|------|----|------|
| Priority（用户优先级，PCP） | 3 bit | 0-7；SV 典型 4（受控流量，libiec61850 `CONFIG_SV_DEFAULT_PRIORITY=4`） |
| DEI/CFI（丢弃合格指示/规范格式指示） | 1 bit | 0（经典以太网） |
| VID（VLAN 标识） | 12 bit | 0-4095；SV 可运营配置为专用过程总线 VLAN |

**与 GOOSE 的 VLAN 优先级差异**：两者都允许带 VLAN，且**典型优先级都是 4**（过程总线流量）。本设计的 `SVConfig` 提供 `vlan_enabled/vlan_id/vlan_priority` 三字段（§5.1），`vlan_enabled` 默认 false（不插 VLAN 头，帧更短更易解析）；置 true 后写 802.1Q。

### 2.3 EtherType 0x88BA

EtherType 0x88BA（十进制 35002）是 IANA 分配给 **IEC 61850-9-2 Sampled Values** 的类型字段。链路层解复用依据，也是 tshark 识别 SV 的关键（`frame.protocols` 含 `sv`、`eth.type == 0x88ba` 时 Wireshark 自动用 `sv` 解析器解析，字段名 `sv.*`，§2.6）。发送方在以太网头写死 0x88BA，接收方（交换机组播转发、IED）据此把载荷交给 SV 解析器而非 IP。

必须在 builder 层新增常量（当前 core 仅有 `EtherTypeIPv4=0x0800`、`EtherTypeARP=0x0806`、`EtherTypeIPv6=0x86DD` 及 PPPoE/GRE/MPLS 相关）：

```go
// internal/core/builder.go
EtherTypeSV = 0x88BA // IEC 61850-9-2 Sampled Values (IEC 61850-9-2)
```

### 2.4 SV 帧头（APPID/Length/Reserve1/Reserve2）

EtherType 之后是 **8 字节 SV 帧头**，全部大端：

| 偏移 | 长度 | 字段 | 说明 |
|------|------|------|------|
| 0 | 2 字节 | **APPID**（应用标识） | 标识 SV 逻辑流；HTTP/IED 依据它区分流 |
| 2 | 2 字节 | **Length**（长度） | **从 APPID 字段起**到 SV PDU 结束的总字节数（= 8 + APDU 长度） |
| 4 | 2 字节 | **Reserve1**（保留 1） | 保留；仿真位（模拟状态）在 9-2 Profile 中可选置位（位 15） |
| 6 | 2 字节 | **Reserve2**（保留 2） | 保留（供未来安全/扩展） |

**APPID 的分配**（IEC 61850-9-2 附属标准/IEC 61850-8-1 附录对 APPID 的划分）：
- 0x0000-0x3FFF：保留给 GOOSE（IEC 61850-8-1）
- **0x4000-0x7FFF：SV（采样值）**
- 0x8000-0xBFFF：保留
- 0xC000-0xFFFE：用户自定义/将来使用
- 0xFFFF：保留用作无效/未定义

**用户提示条款口径说明**：任务描述曾声称"APPID 0x3FFF 静态默认"，但 0x3FFF 属于 GOOSE 保留段；SV 标准段是 0x4000-0x7FFF（libiec61850 的默认 `CONFIG_SV_DEFAULT_APPID=0x4000`、IEC 61850-9-2 附录一致性）。**本设计默认 APPID=0x4000**，合法范围 0x4000-0x7FFF（用户可显式配置自定义段 0x0000-0xFFFF，validate 允许 0-0xFFFF，见 §9.3）。这是对任务描述的修正，以权威分配为准。

**Length 计算**：SV 头长度字段 = **从 APPID 起**到 APDU 尾的字节数，即本帧 EtherType（0x88BA）之后的所有字节数。固定 8 字节头 + APDU 长度。libiec61850 参考实现把该值写为 `payloadLength + 8`（payloadLength = savPdu 起始到帧尾），与规范口径（计 APPID 起始）一致。**注意**：GOOSE 的 Length 字段也是同口径（从 APPID 起），两协议头结构完全同构，仅 APPID 段不同。

> **精确口径提示**：IEC 61850-8-1/9-2 的 SV header Length 语义沿袭 GOOSE——"length of APDU **plus** the 8 octets of the fields prior to the APDU"（即含本字段之后的部分）。发送方按此计算；接收方/tshark 校验时也按同口径校验。这是 hexdump 用例断言的关键公式。

**Reserve1 位 15（S-bit，仿真位）**：VLAN 仿真/调试流标记，v1 默认 0（真实流）；tshark 3.6+ 有 `sv.reserve1.s_bit` 字段可断言。

### 2.5 ASN.1 BER 编码的 savPdu

SV PDU（mSV）用 **ASN.1 的 BER（Basic Encoding Rules，基本编码规则）** 编码，基本类型结构（摘自关联 ASN.1 定义，按 libiec61850 参考实现与 Wireshark `sv` 解析器实际编码逐字段核对）：

```
IEC61850SV DEFINITIONS ::= BEGIN
SV ::= CHOICE {
    savPdu  [0] IMPLICIT SavPdu,
    ...
}

SavPdu ::= SEQUENCE {
    noASDU  [0] IMPLICIT INTEGER (0..65535),
    seqASDU [2] IMPLICIT SEQUENCE OF ASDU
}

ASDU ::= SEQUENCE {
    svID    [0] IMPLICIT VisibleString,
    datSet  [1] IMPLICIT VisibleString OPTIONAL,
    smpCnt  [2] IMPLICIT INTEGER (0..65535),
    confRev [3] IMPLICIT INTEGER (0..4294967295),
    refrTm  [4] IMPLICIT UtcTime OPTIONAL,
    smpSynch [5] IMPLICIT INTEGER (0..15) OPTIONAL,
    smpRate [6] IMPLICIT INTEGER (0..65535) OPTIONAL,
    seqData [7] IMPLICIT OCTET STRING,   -- 采样数据（自描述）
    smpMod  [8] IMPLICIT INTEGER (0..15) OPTIONAL
}

PhsMeas ::= SEQUENCE {
    instMag [0] IMPLICIT AnalogueValue,  -- 瞬时幅值
    q       [1] IMPLICIT Quality        -- 品质（4 字节位串）
}
AnalogueValue ::= SEQUENCE {
    -32-bit 有符号整数（整数 instMag） |
    -float  (IEEE 754 单精度，可选) | ...
}
```

**BER Tag 分配（本文档的字节级事实，已核实）**：

| Tag（hex） | ASN.1 引用 | 字段 | 类型 | 值长度 |
|-----------|-----------|------|------|--------|
| **0x60**（APPLICATION 0 构造） | `savPdu [0] IMPLICIT` | SavPdu 序列 | 构造 | 变长（帧体） |
| **0x80**（[0] IMPLICIT） | `noASDU` | ASDU 计数 | 整数 | 1-2 字节 |
| **0xa2**（[2] IMPLICIT 构造） | `seqASDU` | ASDU 序列 | 构造 | 变长 |
| **0x30**（SEQUENCE） | `ASDU` | ASDU 序列成员 | 构造 | 变长 |
| **0x80**（[0]） | `svID` | SV 标识串 | VisibleString（字符串） | 变长 |
| **0x81**（[1]） | `datSet` | 数据集引用 | VisibleString | 变长（可选） |
| **0x82**（[2]） | `smpCnt` | 采样计数 | **有符号整数 2 字节** | **固定 2** |
| **0x83**（[3]） | `confRev` | 配置版本 | **有符号整数 4 字节** | **固定 4** |
| **0x84**（[4]） | `refrTm` | 刷新时间 | UtcTime（8 字节） | 固定 8（可选） |
| **0x85**（[5]） | `smpSynch` | 同步状态 | 有符号整数 1 字节 | 固定 1（可选） |
| **0x86**（[6]） | `smpRate` | 采样率 | 有符号整数 2 字节 | 固定 2（可选） |
| **0x87**（[7]） | `seqData` | 采样数据（样本） | OCTET STRING（字节串） | 变长（= 通道数 × 8） |
| **0x88**（[8]） | `smpMod` | 采样模式 | 有符号整数 1 字节 | 固定 1（可选） |

> **与任务提示的差异（重要修正）**：任务描述给出的 tag 为"0x60 savPdu、0x80 svID、0x81 smpCnt、0x82 confRev、0x84 seqData"，但这与参考实现（libiec61850 `sv_publisher.c`）和 Wireshark `sv` 解析器（`packet-sv.c`）的实际编码**不一致**：
> - `smpCnt` 真实 tag 是 **[2] = 0x82**（2 字节有符号整数），不是 0x81；
> - `confRev` 真实 tag 是 **[3] = 0x83**（4 字节），不是 0x82；
> - 采样数据 seqData 真实 tag 是 **[7] = 0x87**（OCTET STRING），不是 0x84；0x84 是可选 refrTm；
> - savPdu 真实 tag 是 `APPLICATION 0` = **0x60**（构造），与提示一致；
> - 中文资料常简短书写为 "savPdu 60/svID 80/smpCnt 82/confRev 83/seqData 87"，本设计以此为准。
>
> **校验采纳原则**：以 libiec61850（广泛部署的开源参考实现，Wireshark 可解析其 SV 帧）和 Wireshark `sv` 解析器为字节级事实源；任务描述中的 tag 编号不采用，并在本文档显式记录该差异以防后续实现误填。

**BER 长度编码**：SV 载荷中所有值长度都很短（1-255 字节），BER 短长度形式（单字节，高位 0）即可；null/超长（如 4000 字节大数据集，实际 9-2LE 单帧 < 128 字节）用长形式。`svID` 长度 = 字符串字节数；`smpCnt`/`confRev`/`smpSynch` 长度固定。构造类型（0x60/0xa2/0x30）长度 = 其内容总字节数。

**数值编码**：所有整数/字符串/字节序 **大端（网络字节序）**。`smpCnt` 以 16 位无符号语义回绕（0xFFFF → 0x0000，或按要求回绕上限）；`confRev` 以 32 位无符号整数递增。

**示例（最小 APDU，1 ASDU，svID="SV01"）**：

```
60 20                -- savPdu [APPLICATION 0], 内容长 32
   80 01 01          -- noASDU = 1
   a2 1d              -- seqASDU [2], 内容长 29
      30 19           -- ASDU [SEQUENCE], 内容长 25
         80 04 53 56 30 31   -- svID "SV01"
         82 02 00 00          -- smpCnt = 0
         83 04 00 00 00 01    -- confRev = 1
         85 01 00             -- smpSynch = 0（未同步）
         87 04 00 00 00 00    -- seqData（此处仅含 1 样本占位，见 §2.7）
```
（注：上例 svID 用 4 字节占位 "SV01"；若用真实样例 10 字节 "xxxxMUnn01"，svID 段为 `80 0a`+10 字节、ASDU 内容 31、savPdu 内容 38、SV Length 48=0x30——see §6.1 完整样例。）

### 2.6 tshark 字段名（sv.*，验证用）

Wireshark/tshark 的 `sv` 解析器（`epan/dissectors/packet-sv.c`）在 EtherType 0x88BA 时字段树为 `sv.*`：

| tshark 字段 | 显示名 | 类型 | 对应字节 |
|------------|--------|------|----------|
| `sv.appid` | APPID | uint16 | SV 头偏移 0 |
| `sv.length` | Length | uint16 | SV 头偏移 2 |
| `sv.reserve1` | Reserved 1 | uint16 | 偏移 4 |
| `sv.reserve1.s_bit` | Simulated | bool | 偏移 4 位 15（3.6+） |
| `sv.reserve2` | Reserved 2 | uint16 | 偏移 6 |
| `sv.savPdu` | savPdu | label | APDU 全段 |
| `sv.noASDU` | noASDU | uint32 | APDU 内 0x80 |
| `sv.seqASDU` | seqASDU | uint32 | APDU 内 0xa2 计数 |
| `sv.svID` | svID | string | ASDU 内 0x80 |
| `sv.datSet` | datSet | string | ASDU 内 0x81 |
| `sv.smpCnt` | smpCnt | uint32 | ASDU 内 0x82 |
| `sv.confRev`(3.6+) / `sv.confRef`(旧) | confRev | uint32 | ASDU 内 0x83 |
| `sv.refrTm` | refrTm | string | ASDU 内 0x84 |
| `sv.smpSynch` | smpSynch | int32 | ASDU 内 0x85 |
| `sv.smpRate` | smpRate | uint32 | ASDU 内 0x86 |
| `sv.seqData` | seqData | bytes | ASDU 内 0x87 |
| `sv.smpMod` | smpMod | int32 | ASDU 内 0x88 |
| `sv.meas_value` | instMag 变化值 | int32 | seqData 解析（PhsMeas） |
| `sv.meas_quality` | quality | uint32 | seqData 解析（PhsMeas 品质） |
| `sv.gmidentity`/`sv.gmidData` | gPTP 主时钟身份 | uint64/bytes | 扩展（可选） |

tshark 对 `seqData` 的解析：命令 `tshark -d tcp.port==xxx,sv` 不适用（无 TCP）；**EtherType 0x88BA 时 tshark 自动识别**（无需 `-d`）。`sv.seqData` 默认按 OCTET STRING 展示为十六进制字节流（`sv.seqData` 可直接断言原始字节）；当传递解码提示 `-d sv.seqData,PhsMeas`（或 tshark 版本支持）时按 PhsMeas 序列解析出 `sv.meas_value`/`sv.meas_quality`。框架的 `FieldAssert` 用 `sv.*` 字段名做 tshark 断言（24-sv-testcase.md §5）。

### 2.7 seqData（采样数据，Sequence of Data 自描述 BER）

`seqData`（Tag 0x87）承载本采样点的全部测量值。**9-2LE 典型布局（4 电流 + 4 电压）**，且是工程默认：

```
seqData = [instMag(A相电流) 4B][quality 4B]
        + [instMag(B相电流) 4B][quality 4B]
        + [instMag(C相电流) 4B][quality 4B]
        + [instMag(中性电流N) 4B][quality 4B]
        + [instMag(A相电压) 4B][quality 4B]
        + [instMag(B相电压) 4B][quality 4B]
        + [instMag(C相电压) 4B][quality 4B]
        + [instMag(中性电压VN) 4B][quality 4B]
```

- **instMag**（瞬时幅值，`AnalogueValue`）：**32 位有符号整数**，**大端**，典型单位是 1/1000（mA/mV 级，如 6350V×√2 ≈ 8980V → 898025 的千分单位）。9-2LE 用整数 instMag（INT32）。
- **quality**（品质）：**4 字节位串**（BIT STRING 编码为字节），按 IEC 61850-7-3 Quality 结构：位 0 validity（00=good/01=invalid/10=reserved/11=questionable）、位 2 overflow、位 3 outOfRange、位 4 badReference、位 6 oscillatory、位 7 failure、位 8 oldData、位 9 inconsistent、位 10 inaccurate、位 11 test（0x800）、位 12 operatorBlocked（0x1000）、位 12-13 source、位 14-15 保留（与 §2.10 表一致）。典型 good = 0x00000000。tshark 拆成 `sv.meas_quality.validity` 等子位。
- **顺序固定**：IA→IB→IC→IN（电流），再 VA→VB→VC→VN（电压），每对 = 8 字节。8 通道 = **64 字节 seqData**。

**自定义数据集（非 9-2LE）**：`seqData` 长度与通道数、每通道字节宽可自由配置——`SVConfig.Data[]`（§5.1）描述每通道类型（int32/float32/int16/int64 + 是否带 quality）。多 ASDU、浮点 instMag、任意通道组合 → 9-2 Full 自由 profile。v1 支持：int32(int32 有符号) / float32（IEEE 754 单精度，大端）两种 instMag 类型 + 可选每通道 quality；扩展类型标注待实现。

**seqData 的自描述性**：`seqData` 是 OCTET STRING（Tag 0x87 + 长度 + 字节），其**内部**的 `instMag/quality` 对打包在字节流中，不再有各自独立 BER tag——接收方按 ASDU 所属数据集（每个通道的类型声明）拆分。方案 A（框架 Phase-1）按**固定每通道 8 字节（4B instMag + 4B quality）**生成，与 9-2LE 完全一致，tshark PhsMeas 解析可验证；方案 B（自定义数据布局，字节宽可变）作为 profile 扩展（§5.4 注）。

### 2.8 数据类型映射总表（Go 类型 ↔ BER ↔ tshark）

| Go 配置字段 | SV 内编码 | BER tag+长度 | tshark 字段 | 大端 | 备注 |
|-------------|-----------|--------------|-------------|------|------|
| `SVConfig.SvID string` | VisibleString（ASCII） | 0x80 + 长度 | `sv.svID` | 无（串） | 长度 = 字节数，≤255 |
| `SVConfig.APPID uint16` | SV 头 | — | `sv.appid` | ✓ | 默认 0x4000 |
| `SVConfig.ConfRev uint32` | INTEGER | 0x83 + 4 | `sv.confRev` | ✓ | 恒 4 字节；≥1 |
| `SVConfig.SamplesPerCycle int` | （不在线上，仅控制回绕） | — | — | — | smpCnt 回绕上限 |
| `SVConfig.SmpSynch int` | INTEGER | 0x85 + 1 | `sv.smpSynch` | ✓ | 0/1/2 |
| `SVConfig.SmpRate *uint16` | INTEGER | 0x86 + 2 | `sv.smpRate` | ✓ | 可选，缺省不编码 |
| `SVConfig.SmpMod *int` | INTEGER | 0x88 + 1 | `sv.smpMod` | ✓ | 可选（ASN.1 1 字节，libiec 实现 2 字节，见 §2.9） |
| `SVConfig.Data[].Type` | AnalogueValue instMag | seqData 内固定宽 | `sv.meas_value` | ✓ | int32/float32 |
| `SVConfig.Data[].Quality uint32` | Quality BIT STRING | seqData 内 4 字节 | `sv.meas_quality` | ✓ | 位串语义 §2.7 |
| `SVConfig.Reserve1/2 uint16` | SV 头 | — | `sv.reserve1/2` | ✓ | 默认 0 |
| （时间戳） | UtcTime（refrTm） | 0x84 + 8 | `sv.refrTm` | ✓ | 可选 |

**每通道字节宽公式**：`seqData 总长 = 通道数 × (instMag宽 + quality宽)`；9-2LE = 8 × (4 + 4) = 64。自定义通道可省 quality → 每通道 4 字节（sparse dataset，§5.1 的 `WithQual`）。

### 2.10 Quality（品质）4 字节位串完整定义

`seqData` 每通道的 quality 是 **4 字节、大端**的位串（IEEE 61850-7-3 Quality），按 Wireshark `sv` 解析器（`packet-sv.c` Q_* 掩码）权威定义：

| 位（从 LSB 起） | 掩码 | Quality 属性 | 说明 |
|-----------------|------|--------------|------|
| 0-1 | 0x03 | validity | 00=good（正常）、01=invalid（无效，向后兼容）；10=invalid（无效）、11=questionable（可疑） |
| 2 | 0x04 | overflow | 超量程/溢出 |
| 3 | 0x08 | outOfRange | 超出测量范围 |
| 4 | 0x10 | badReference | 参考值错误 |
| 5 | 0x20 | oscillatory | 振荡 |
| 6 | 0x40 | failure | 故障 |
| 7 | 0x80 | oldData | 旧数据 |
| 8 | 0x100 | inconsistent | 不一致 |
| 9 | 0x200 | inaccurate | 不精确 |
| 10 | 0x400 | source | 0=process（过程值）、1=substituted（替代表，由处理程序生成） |
| 11 | 0x800 | test | 测试值 |
| 12 | 0x1000 | operatorBlocked | 操作员封锁 |
| 13 | 0x2000 | derived | 派生值（UCA 9-2 实施指南新增） |
| 14-31 | — | 保留 | 0 |

**good 值的约定**：9-2LE 工程默认 quality = **0x00000000**（validity=good，其余位 0）。测试用例 T-SV-S5-01 用此值断言 `sv.meas_quality == 0`；如需制造"无效/检测"样本，把 validity 置 2（0x00000002）或某错误位。

**编码注意**：quality 是位串（BIT STRING），非整数——0x08 表示 outOfRange 而非"数值 8"。配置 `SVDataChannel.Quality`（uint32）直接落 4 字节，无需转换。

### 2.9 参考实现对照（libiec61850 一手码源）

本设计的字节事实以 libiec61850 参考实现的**逐行对照**收敛（不是"大概这样"）：

| 事实 | libiec61850 出处 | 行为 |
|------|-------------------|------|
| Length = payload+8 | `SVPublisher_setupComplete`: `msgLength = payloadLength + 8; buffer[lengthIndex]=...` | SV 头 Length 计从 APPID 起（§2.4）与实现逐字一致 |
| smpCnt 固定 2 字节 | `BerEncoder_encodeTL(0x82, 2, buffer, bufPos)` | tag 0x82 长度始终 2 |
| confRev 固定 4 字节 | `BerEncoder_encodeTL(0x83, 4, ...)` | tag 0x83 长度始终 4 |
| refrTm 8 字节可选 | `if (hasRefrTm) encodeTL(0x84, 8, ...)` | 缺省不编码 |
| smpSynch 1 字节 | `encodeTL(0x85, 1, ...) ; buffer = self->smpSynch` | tag 0x85 |
| smpRate 2 字节可选 | `if (hasSmpRate) encodeTL(0x86, 2, ...)` | 缺省不编码 |
| seqData 变长 | `encodeTL(0x87, self->dataSize, ...)` | tag 0x87 |
| smpMod 2 字节可选 | `if (hasSmpMod) encodeTL(0x88, 2, ...)` | 注意：长度 2（libiec 实现），与表 2.5 的 1 字节有出入（参考实现比 ASN.1 声明少约束，工程中此字段少见） |
| smpCntWrap 默认 4000 | 9-2LE example: `setSmpCntWrap(asdu, 4000)` | 回绕上限可配 |
| svID 9-2LE 惯例 | 9-2LE example: `SVPublisher_addASDU(..., "xxxxMUnn01", NULL, 1)` | svID="xxxxMUnn01"（xx=厂商，MU nn=合并单元号） |
| 80 采样/周 | 9-2LE example: `samplePoint = sampleCount % 80` | 4000/s @ 50Hz（80×50） |
| 4I+4V 通道 | 9-2LE example 逐相 `setINT32`×8 + `setQuality`×8 | I_A..V_N 8 通道 |
| 每采样点一帧 | example 主循环每 250µs 发包 | 单采样模型 |

> **smpMod 长度差异说明**：design §2.5 表中按 ASN.1（SmpMod=INTEGER 0..15，1 字节）与 libiec61850 实现（2 字节）有分歧。本设计工程上**按 1 字节**（IED 少见使用；Wireshark 解析接受两种），并在实现时以 ASN.1 tag 语义为准；如需与 libiec61850 逐字节互通，则该字段按 2 字节写并在此记录。



---

## 3. 消息结构

### 3.1 帧的完整布局（字段级）

SV 帧（以太网直承，够 60 字节最小以太网帧长则无尾部 padding）自 L2 起：

```
 偏移   字段                       长度   字节序   值/说明
 ------------------------------------------------------------------------------
 0     dst MAC   (组播 01:0C:CD:04:xx:xx)  6   --    IED 订阅的 SV 流组播地址
 6     src MAC   (发送方/合并单元)          6   --    用户配置
 12    802.1Q VLAN Tag (可选)  4            BE     TPID 0x8100 + TCI(priority/VID)
 12/16  EtherType                2            BE     0x88BA  (无 VLAN 时在 12，有则在 16)
 14/18 SV 头: APPID              2            BE     0x4000..0x7FFF (默认 0x4000)
 16/20          Length          2            BE     8 + APDU 总长 (从 APPID 起)
 18/22          Reserve1        2            BE     0 (位15 仿真位可选置位)
 20/24          Reserve2        2            BE     0
 ------------------------------------------------------------------------------
 22/26 savPdu (APDU, ASN.1 BER)
        60 <L>  savPdu [APPLICATION 0]                      构造
           80 01 01       noASDU = 1                        [0]
           a2 <L>         seqASDU [2] IMPLICIT              [2] 构造
              30 <L>      ASDU [SEQUENCE]                   构造
                 80 <L> 53 56 30 31 ...    svID            [0] VisibleString
                 81 <L> ...               datSet(可选)      [1]
                 82 02 <hi><lo>           smpCnt(采样计数)  [2] 2 字节
                 83 04 <...4 字节>        confRev(配置版本) [3] 4 字节
                 84 08 <...8 字节>        refrTm(可选)      [4] 8 字节 UtcTime
                 85 01 <v>               smpSynch(可选)     [5] 1 字节
                 86 02 <hi><lo>           smpRate(可选)     [6] 2 字节
                 87 <L> <seqData 采样数据>  seqData           [7] OCTET STRING
                     [每通道 4B instMag][每通道 4B quality]
                 88 01 <v>               smpMod(可选)       [8] 1 字节
                    (多 ASDU 时重复 30 分组)
        可选: 60 后跟多个 30 (每 ASDU 一个)，noASDU 同步加 1
```

**无 IP 层证明**：上表全链路只有 以太网/VLAN(可选)/SV 三部分，**没有任何 IP 头（0x45 识别字节）、无 TCP/UDP 端口**。`frame.protocols` 显示 `eth:sv`（带 VLAN 时为 `eth:vlan:sv`），不含 `ip`。这与 GOOSE 帧（`eth:goose`）结构同级，是 SV 与 TDS/S7 等 TCP 承载协议的最本质差异。

### 3.2 帧头与 APDU 的组合约束

| 约束 | 规则 | 违反后果 |
|------|------|----------|
| Length = 8 + APDU 长度 | 固定 8 字节 SV 头后的载荷起自 savPdu | tshark 按 `sv.length` 定位 APDU 尾；不符则报 `Malformed` |
| noASDU = seqASDU 内 ASDU 个数 | 单采样模型恒 1 | 双发同帧需 2；不符则订阅方丢弃 |
| savPdu 必须紧跟 SV 头 | 无中间字节 | EtherType 0x88BA 后第 1 字节必须 0x60 |
| 一个采样点 = 一个 ASDU | 9-2LE 单采样模型 | 多 ASDU 属 9-2 Full 批量模型（§1.5 不实现） |
| VLAN 优先级典型 4 | 过程总线受控流量 | tshark 可断言 `vlan.priority` |

### 3.3 用 ASN.1 视图表达单帧

```
SV 帧 = [EthernetII 头(14)]
        | [802.1Q Tag(4, 可选)]
        | [SV 头(8): APPID | Length | Reserv1 | Reserv2]
        | [savPdu: 60 { noASDU 80=1, seqASDU a2 { 30 { svID |
                       datSet? | smpCnt | confRev | refrTm? |
                       smpSynch? | smpRate? | seqData | smpMod? } } }]
```

- 可选性符号 `?` 表示字段可按 profile 省略（9-2LE 强制存在集 = svID+smpCnt+confRev+seqData；smpSynch 在工程配置下常显式写 0/2）
- BER 认为任何可选字段缺省即不编码（Tag 不存在），接收方默认值处理——**因此"字段是否编码"本身就是协议行为**，测试用例要用 `sv.*` 字段**存在性**断言来区分（只认长度/字节序不够）

### 3.4 每字段编码规则速查

| 字段 | 编码类 | 长度规则 | 校验 |
|------|--------|----------|------|
| APPID | uint16 BE | 2 字节固定 | 0x4000-0x7FFF 合法 SV 段（§9.3 越界负例） |
| Length | uint16 BE | 2 字节固定 | = 8 + APDU len（§9.4 算错负例） |
| svID | ASCII 可见串 | 1-255 字节（短形式） | 编码后 ≤255 |
| datSet | ASCII 可见串 | 1-255 字节 | 可选 |
| smpCnt | uint16 BE | 2 字节固定 | 回绕说明 §4/§9.1 |
| confRev | uint32 BE | 4 字节固定 | 必须 ≥1（§9.2） |
| refrTm | 8 字节 | 固定 8 | 可选；UtcTime（1970 起秒 + 纳秒举例，见 §10） |
| smpSynch | int8 BE | 1 字节固定 | 0/1/2（§9.5） |
| smpRate | uint16 BE | 2 字节固定 | 可选 |
| seqData | OCTET STRING | 8×通道数 | 与 svID 对应数据集通道数一致（§9.6） |
| smpMod | int8 BE | 1 字节固定 | 可选 |

**全帧字节序**：除 MAC 与 IEEE 网格位序按以太网惯例外，**所有数值字段一律大端**。

### 3.5 帧头/APDU 的组合解析对照（编解码一致性）

约定的**双向解析一致性**：发送方按本表编码，接收方（tshark 与订阅方 IED）按同一表解码。任何"编码字节 ≠ 解析字节"＝ 编码 bug，pcap 用例的 FrameAssert 正是为了锁住这一点。

| 偏移（无 VLAN） | 字节内容 | 编码动作（Go） | 解析方动作 |
|-----------------|----------|----------------|------------|
| 0-5 | 01:0c:cd:04:00:01 | 写 `DstMAC` | 组播订阅匹配（前 3 字节 01:0c:cd） |
| 6-11 | aa:bb:cc:dd:ee:03 | 写 `SrcMAC` | 源绑定检查（可选） |
| 12-13 | 88 ba | `putEtherType(EtherTypeSV)` | `eth.type==0x88ba`→sv 解析器 |
| 14-15 | 40 00 | `be.PutUint16(appid)`（默认 0x4000） | `sv.appid`，订阅过滤 |
| 16-17 | 00 6a | `be.PutUint16(8+len(apdu))` | `sv.length` 定位 APDU 尾 |
| 18-19 | 00 00 | `be.PutUint16(0)` | `sv.reserve1`（位15 仿真位） |
| 20-21 | 00 00 | `be.PutUint16(0)` | `sv.reserve2` |
| 22-23 | 60 60 | `encodeTL(0x60, len(savpduContent))` | `sv.savPdu` start |
| 24 | 80 01 01 | noASDU=int1 编码 | `sv.noASDU` |
| 27 | a2 5b | seqASDU 计数+内容 | `sv.seqASDU` |
| 29 | 30 59 | ASDU 头 | `sv.seqASDU_item`/ASDU 边 |
| 31+ | （字段序列） | 见 §2.5 | `sv.svID`等 |

**tshark 的 BER 容错提示**：sv 解析器按 BER 长度字段推进，`sv.length`（16 位）与 BER 内部长度不一致时 Wireshark 报 `Dissector bug / Malformed`——这帮助负例 T-SV-NEG-03 被观测（§9.4）。

**多 ASDU 的 noASDU/seqASDU 计数**：noASDU 字段值 = seqASDU 内 ASDU 数量（libiec61850 `SVPublisher_ASDU_getEncodedSize×遍历 asduList` 同口径）；本设计 v1 恒 1（§1.5 不实现批量模型），但 BER 解码侧支持任意 noASDU 以便测试确认。

---

## 4. 状态机

### 4.1 发布侧状态机（烟囱式：始终处于 SEND 主态）

SV 是**无握手、无连接的周期组播**，发布侧没有 GOOSE 那样的连接生命周期（GOOSE 有 stNum/sqNum 重发、超时置 invalid）。SV 状态机是**一态为主 + 内部计数**：

```
                    ┌────────────────────────────────────────┐
                    │             周期采样循环 (SEND)          │
                    │                                        │
   (配置生效)──────►│  T ──► 帧(smpCnt=i)                    │
                    │        │ 双重发? ──► 立即补发 1-2 帧     │
                    │        ▼                               │
                    │  i ← (i+1) mod wrap                    │
                    │  smpSynch 状态位按外部同步输入刷新        │
                    │  confRev 仅在 reconfig 指令下 +1        │
                    └────────────────────────────────────────┘
```

任何时刻只存在"配置→恒定周期发送→停止"三个外部动作，可建模为：

| 外部事件 | 前置条件 | 动作 | 进入状态 |
|----------|----------|------|----------|
| SubmitTask(sv) | 配置合法 | 初始化 smpCnt=配置起始值、安装周期定时器（Period） | SEND |
| （周期定时器 ticks） | SEND | 生成一帧（smpCnt 当前值）→ 可选双重发 → smpCnt+1 mod wrap | SEND |
| Engine.Stop() | SEND | 停止定时器、drain 队列 | 终止 |

**与 GOOSE 对照**：GOOSE 发布状态机有 `sqNum`（保值重发序号）+ TAL 退避 + `needs_retransmit`；SV 无这些，只有**恒定的 smpCnt 计数**。但**双重发机制**是共享概念（GOOSE 快速重发 vs SV 双样冗余），可复用发送节拍。

### 4.2 内部状态/计数

| 状态量 | 定义 | 语义 |
|--------|------|------|
| `smpCnt` | 16 位采样计数 | 每(帧)采样点 +1；到 wrap 回绕为 0（4.3） |
| `wrap` | 回绕上限（smpCntWrap） | 9-2LE：80 采样/周=4000、256 采样/周=12800；可配任意 1..65535（长时戳回绕用 65535=0xFFFF 自然回绕） |
| `smpSynch` | 1 字节同步状态 | 0=未同步/本地、1=本地时钟、2=全局时钟；周期性心跳刷新（4.4） |
| `confRev` | 32 位配置版本 | 数据集拓扑变更时 +1 并发新 confRev（4.5） |
| `double_resend` | 布尔 | 每个采样点立即重复发送次数（报冗余，4.6） |

### 4.3 smpCnt 递增与回绕

- 常规：帧 N 的 smpCnt=0，帧 N+1=1，……，到 `wrap-1` 后下一帧**回 0**（9-2LE 的 4000 回绕）。**这是订阅方判断"丢点/双点"的基础**，测试要点（24-sv-testcase.md T 系列）。
- **非法回绕负例**：生成器不得产出"到达 wrap 前跳变回 0"或"超过 wrap 才回绕"的序列——违反即期望错误（§9.1，用例 expect_error）。
- **16 位语义**：wrap 上限不超过 0xFFFF；smpCnt 编码固定 2 字节。长时戳（每秒上千帧跑天级）用 0xFFFF 自然回绕（不做 4000 回绕）。

### 4.4 smpSynch 状态

采样同步状态作为一个**稳定字段**每帧重写（不是事件）：

| 值 | 含义 | 工程用法 |
|----|------|----------|
| 0 | NOT-SYNCHRONIZED（未同步） | 合闸前调试：`0x85 01 00` |
| 1 | LOCAL（本地时钟） | 本地晶振 |
| 2 | GLOBAL（全局时钟，PTP 同步） | 过程总线稳态：`0x85 01 02` |

v1 不实现 PTP 同步升级逻辑（§1.5），只把用户配置值按帧写出。测试要断言**同一流内 smpSynch 恒为配置值不变**（用例 sv_smp_synch_global）。

### 4.5 confRev 变化

- SAMPLING 稳态下 confRev 恒定；**数据集/采样率/通道定义变更**（reconfigure）时发布方 confRev+1，订阅方据此重新解释后续帧。
- 负例：confRev=0 或负（不能用）→ 合法入口校验拒绝（§9.2，expect_error）。
- 测试：两阶段（首段 confRev=1、重配置后 confRev=2）验证"同一流 confRev 变化 + smpCnt 继续递增"（用例 sv_convrev_change）。

### 4.6 双重发（冗余报）

过程总线可靠性手段：同一采样点的帧在**紧跟的一帧（μs 级）重复发出**，两次内容仅有 smpCnt/seqData 相同、appid/length 相同、帧计数不同。订阅方收到相同 smpCnt 被认为冗余。

- 配置 `double_send=true` 时输出：帧(k) smpCnt=s、帧(k+1) smpCnt=s（相同）、帧(k+2) smpCnt=s+1……
- 三样点时序：`s, s[双发], s+1, s+1[双发], s+2, ...`
- 测试断言：出现**同 smpCnt 的两帧**（用例 sv_double_send），且后续 smpCnt 正常递增。

### 4.7 心跳

SV 因为是周期性的，**心跳语义天然收敛到"正常采样帧"**——每个采样帧本身即是心跳；不额外发小结帧。与 GOOSE 的"空闲期 T0 心跳"不同，SV 空闲即停发（订阅方按期望采样周期超时置 invalid）。订阅超时模型见 §4.8。

### 4.8 订阅端超时（设计 v1 只建模不实现）

IED 订阅 SV 流时：期望每 `Period` 收到一帧；超过约定时间未收到则判订阅丢失（通信恢复后重新同步、smpSynch 进入未同步）。**trafficgen 只负责发送，不做订阅端实现**；但设计超时语义以便测试：连续发送时维护"每帧 time 间隔 ≈ Period（±tolerance）"的时序约束（§8.5 时间戳），用例可用 `frame.time_delta` 断言采样间隔稳定。

### 4.9 停止/清理

- Engine.Stop 时停止周期发送，避免 goroutine 泄漏；与 GOOSE 相同的清理（Stop 排水队列）。
- 测试：任务完成发出 N 帧后，无残留定时器（goleak 检查，§8）。

### 4.10 采样发送时序（time diagram）

以 4000 采样/秒（Period=250µs）、双重发、48 帧小窗口为例（`smpSynch=2` 状态下前 8 帧）：

```
时刻(µs)     事件                     smpCnt   帧内容差异
0.000    TICK#1 emit 帧A            0        seqData 样本#0
0.200    (双发)   emit 帧B          0        与帧A 前 103 字节完全同（仅 frame.number/timestamp 不同）
0.250    TICK#2 emit 帧C            1        仅 smpCnt 字段 0x0001
0.450    (双发)   emit 帧D          1
0.500    TICK#3 emit 帧E            2
...
11.750   TICK#48 emit（smpCnt=47）  47
12.000   ——下一样本 ——            48        （若周期到 4000→0 回绕）
```

要点：
- **双发在同一 tick 内、间隙 <瞬间**（模拟硬件冗余报，不占额外周期）；实现用同一次定时器回调连发 2 帧（§8.9 伪码）。
- **smpCnt 跨 tick 递增**，仅受 `SamplesPerCycle` 约束；重配置/同步切换**不重置** smpCnt（§4.4 边界：smpSynch 变化不打断连续性，除非配置明确要求续点重发）。
- **每 tick 一帧**（双发除外）保证 `frame.time_delta` 稳定在 Period 附近而不是聚集块；§S9 用时间戳断言这种"等间隔"而非"突发后停"的模式，避免帧序列被误判成按需填满。

### 4.11 任务级语义（与 engine 队列联动）

| 场景 | 行为 |
|------|------|
| 单 SV 任务（count=N） | 周期定时器运行 N 个 tick（或 N/2 对）后 drain，任务 completed |
| 多 SV 任务并行 | 各自独立定时器 + 独立 smpCnt/confRev；互不共享采样计数（如同多合并单元各自采样） |
| 任务 bps 类流控 | SV 是定时驱动，rate 不由 token bucket 节流（周期已定）；FlowControl 仅约束帧数/时长上限（FlowCounter 语义，见 core 流控设计） |

---

## 5. 配置类型定义

### 5.1 SVConfig 结构

核心配置类型（定义在 `trafficgen/internal/core/types.go`，与 GOOSE 并列）：

```go
// SVConfig 描述一条采样值（SV, Sampled Values）流。
// 覆盖 9-2LE（默认 profile）与 9-2 Full（自由 profile）两种配置口径。
type SVConfig struct {
    SvID            string        // svID：SV 标识字符串（ASDU 内 0x80），如 "SV01"（9-2LE 常为 "xxxxMUnn01"）
    APPID           uint16        // APPID（应用标识）：SV 段默认 0x4000，合法 SV 段 0x4000-0x7FFF
    ConfRev         uint32        // confRev（配置版本）：数据集版本号，必须 ≥1
    SamplesPerCycle int           // 每周波采样数（smpCnt 回绕上限）：9-2LE 80 或 256；0 表示不回绕（0xFFFF 自然回绕）
    SmpSynch        int           // smpSynch 字段：0=未同步 1=本地 2=全局（PTP）
    Period          time.Duration // 采样周期：帧间隔（1/采样率）
    DoubleSend      bool          // 双重发：每采样点连发 2 帧（同 smpCnt 冗余）
    DstMAC          string        // 组播目的 MAC：默认 01:0C:CD:04:00:01
    VlanEnabled     bool          // 是否插 802.1Q VLAN 头
    VlanID          uint16        // VLAN ID（0-4095）
    VlanPriority    uint8         // VLAN 优先级 PCP（0-7），典型 4
    Data            []SVDataChannel // 通道（数据集）定义：每通道 instMag 类型 + 是否带 quality
    Reserve1        uint16        // SV 头 Reserve1：0（位15 仿真位可置位）
    Reserve2        uint16        // SV 头 Reserve2：0
    SmpRate         *uint16       // smpRate（可选）：采样率声明，缺省不编码该字段
    SmpMod          *int          // smpMod（可选）：采样模式，缺省不编码该字段
}

// SVDataChannel 描述一个采样通道（数据集成员）。
type SVDataChannel struct {
    Name     string // 通道名：如 "I_A"(A相电流)、"V_A"(A相电压)
    Type     string // instMag 类型："int32"（9-2LE 默认，4 字节大端）| "float32"（IEEE 754 单精度，4 字节大端）
    WithQual bool   // 是否编码 quality（9-2LE 恒 true）
    Quality  uint32 // 每通道固定 quality 值（默认 0x00000000 = good）
}
```

**默认值语义**（对应 9-2LE 工程默认，全部大端）：

| 字段 | 默认 | 依据 |
|------|------|------|
| SvID | `SV01` | 示例/过程日志标识 |
| APPID | `0x4000` | IED 默认 SV APPID |
| ConfRev | `1` | 初始配置版本 |
| SamplesPerCycle | `4000` | 50 Hz 系统 80 采样/周 × 50 |
| SmpSynch | `2` | 全局同步（工程稳态） |
| Period（派生） | `1s/4000 = 250µs` | 由 SamplesPerCycle/Freq 推导（§5.2） |
| DstMAC | `01:0C:CD:04:00:01` | 9-2 SV 组播段 |
| Data | 4I + 4V（int32+quality），见 §2.7 | 9-2LE 数据集 |

### 5.2 采样率与周期推导

- 采样率（samples/second）=`SamplesPerCycle × 电网频率`（50 Hz 时 = 80×50=4000/s）。
- 帧周期 `Period` = `1 / 采样率` = 250 µs（4000/s）。
- 若配置了 `SmpRate`，179 声明字段应等于采样率（一致性校验，§9）。
- 256 采样/周 → 12800/s → 周期 ~78.125 µs。

### 5.3 层注册（L2 终结层）

SV 作为**终结层**注册进层链（Registry），与 GOOSE 同策略：

```go
// internal/core/layers/registry.go
{
    Name:         "sv",
    Category:     layers.CategoryTerminal, // 终结层
    DependsOn:    nil,                     // SV 直承 L2，不依赖 TCP/UDP/IP
    OptionalOn:   nil,
    InnerRequired: false,
    Fields:       svFieldDesc(),           // "sv.*" 字段描述
    Constraints:  svConstraints(),         // 见 §5.4
}
```

- `DependsOn=nil` ＋ `CategoryTerminal` ⇒ 链 `[{"eth":{}},{"sv":{}}]` 有效，且**不会自动补 IP/TCP 层**——SV 是 L2 直承，这与 http（DependsOn 补 ip+tcp）截然不同，是该协议的关键集成点（§8.2）。
- 校验器（`Validate`）：`sv` 层出现时禁止同链含 `ip`/`tcp`/`udp` 层（SV over IP 的 R-SV 不支持，§1.5）。

### 5.4 flat 配置键与示例

`spec_json` 的 SV 配置为 `spec.sv` 子对象（与 goose/mdns 等一致）。示例（9-2LE 4I+4V，4000 采样/秒，组播发布，**无 IP**）：

```json
{
  "layers": [{ "eth": {} }, { "sv": {} }],
  "src_mac": "aa:bb:cc:dd:ee:03",
  "sv": {
    "sv_id": "SV01",
    "appid": 16384,
    "conf_rev": 1,
    "samples_per_cycle": 4000,
    "smp_synch": 2,
    "period_us": 250,
    "double_send": false,
    "dst_mac": "01:0c:cd:04:00:01",
    "vlan_enabled": false,
    "smp_rate": 4000,
    "data": [
      {"name": "I_A", "type": "int32", "quality": 0},
      {"name": "I_B", "type": "int32", "quality": 0},
      {"name": "I_C", "type": "int32", "quality": 0},
      {"name": "I_N", "type": "int32", "quality": 0},
      {"name": "V_A", "type": "int32", "quality": 0},
      {"name": "V_B", "type": "int32", "quality": 0},
      {"name": "V_C", "type": "int32", "quality": 0},
      {"name": "V_N", "type": "int32", "quality": 0}
    ]
  }
}
```

**字段扁平化到 `sv` 键**：strategy 层（`strategy_convert.go`）新增 `case "sv"` 分支把 `spec.sv` 翻译成 `SVConfig`。字段解析用与 GOOSE 相同的 `parseUnsigned/parseString` 帮助函数。

> **批量/多 ASDU 注**：9-2 Full 的每帧多 ASDU 批量采样块模型（一个 savPdu 含多 ASDU、每 ASDU 一个采样点，9-2LE 单采样模型外）v1 不实现（§1.5），`Data` 通道定义已支持自定义布局（任意通道数/类型），但每帧仍恰好 1 个 ASDU。

---

## 6. 包序列场景（HexDump S1-Sn）

以下每个场景（S1-Sn）是 testcase 文档对应用例的**字节级模板**（完整断言见 24-sv-testcase.md）。所有场景帧均为以太网直承（无 IP）。小端标注 `..` 处为可配动态值。

### 6.1 S1：9-2LE 基础采样帧（smpCnt 递增）

**场景**：单一 SV 流，4000 采样/秒，无 VLAN，无双重发，smpSynch=2（全局同步），4I+4V，连续 3 个采样点（smpCnt = 0, 1, 2）。

每帧布局（以 smpCnt=0 帧为例，完整 8 通道 seqData = 64 字节）：

```
----- 帧 1：smpCnt = 0（9-2LE 完整 4I+4V + smpSynch + smpRate，无 datSet/refrTm/smpMod） -----
偏移   字节                                      说明
0      01 0c cd 04 00 01                       目的 MAC（组播 01:0C:CD:04:xx:xx）
6      aa bb cc dd ee 03                       源 MAC（src_mac）
12     88 ba                                   EtherType = 0x88BA（SV）
14     40 00                                   APPID = 0x4000
16     00 6a                                   Length = 0x6A = 106（SV 头 8 + APDU 98）
18     00 00                                   Reserve1
20     00 00                                   Reserve2
22     60 60                                   savPdu [APPLICATION 0]，内容长 0x60 = 96
24        80 01 01                             noASDU = 1
27        a2 5b                                seqASDU [2]，内容长 0x5B = 91
29           30 59                             ASDU [SEQUENCE]，内容长 0x59 = 89
31              80 04 53 56 30 31              svID "SV01"（本样例用 4 字节；用例 JSON 用 10 字节 "xxxxMUnn01" 时，svID 为 `80 0a`+10B，其后所有 ASDU 字段偏移整体后移 6——见 §6.1 长度核算注与 sv.json 三正例）
37              82 02 00 00                    smpCnt = 0
41              83 04 00 00 00 01              confRev = 1
47              85 01 02                       smpSynch = 2（全局时钟同步）
50              86 02 0f a0                    smpRate = 4000（0x0FA0）
54              87 40                          seqData，内容长 0x40 = 64 字节
56                 00 00 00 1e  00 00 00 00    I_A  instMag=30  quality=good(0)
64                 00 00 00 2d  00 00 00 00    I_B  instMag=45  quality=good
72                 00 00 00 3c  00 00 00 00    I_C  instMag=60  quality=good
80                 00 00 00 4b  00 00 00 00    I_N  instMag=75  quality=good
88                 00 00 00 5a  00 00 00 00    V_A  instMag=90  quality=good
96                 00 00 00 69  00 00 00 00    V_B  instMag=105 quality=good
104                00 00 00 78  00 00 00 00    V_C  instMag=120 quality=good
112                00 00 00 87  00 00 00 00    V_N  instMag=135 quality=good
120 帧尾（帧总长 = 120 字节 = 0x78）
```

**长度核算（逐层，防编造）**：

| 层 | 字节数 | 累积起始偏移 |
|----|--------|--------------|
| 以太网头（dst+src+EtherType） | 14 | 0 |
| SV 头（APPID+Length+Res1+Res2） | 8 | 14 |
| savPdu 标签+长度（60 60） | 2 | 22 |
| savPdu 内容 | 96 | 24 |
| ├─ noASDU（80 01 01） | 3 | 24 |
| ├─ seqASDU（a2 5b） | 2 | 27 |
| ├─ seqASDU 内容 | 91 | 29 |
| │　└─ ASDU（30 59） | 2 | 29 |
| │　└─ ASDU 内容 | 89 | 31 |
| │　　　├─ svID（80 04 + 4） | 6 | 31 |
| │　　　├─ smpCnt（82 02 + 2） | 4 | 37 |
| │　　　├─ confRev（83 04 + 4） | 6 | 41 |
| │　　　├─ smpSynch（85 01 + 1） | 3 | 47 |
| │　　　├─ smpRate（86 02 + 2） | 4 | 50 |
| │　　　└─ seqData（87 40 + 64） | 66 | 54 |
| **帧总长** | **120（0x78）** | — |

**关键公式验证**：
- `SV 头 Length = 8 + APDU 全长 = 8 + 98 = 106 = 0x6A`（APDU = savPdu 完整 TLV = 2 + 96 = 98 字节，不是 96——Length 计的是**含 savPdu 标签字节的完整 APDU**，见 §2.4 口径）
- `帧总长 = 14 + 8 + 98 = 120 = 0x78`
- smpCnt=1/2 帧仅第 37-40 字节变为 `00 00 00 01` / `00 00 00 02`，其余完全一致（Length/帧长不变）

> 本场景为 testcase 文档用例 T-SV-S1-01 的字节模板。

### 6.2 S2：双重发（同 smpCnt 2 帧）

**场景**：`double_send=true`，其余同 S1。输出帧序：

```
帧 A：smpCnt = 0   （内容同 S1 帧）
帧 B：smpCnt = 0   （与帧 A 前 103 字节完全一致；帧计数不同、src MAC 相同）
帧 C：smpCnt = 1
帧 D：smpCnt = 1
帧 E：smpCnt = 2
...
```

字节差异仅在 **smpCnt 字段位置**：帧 A/B 均 `82 02 00 00`。断言 1：同一流内出现两帧 `sv.smpCnt == 0`；断言 2：这两帧除帧序号（`frame.number`）外按原始字节完全相同。

### 6.3 S3：smpCnt 回绕（0 → 3999 → 0）

**场景**：`SamplesPerCycle=4000`，连续采样到回绕点。帧序末尾与起始：

```
... 帧 smpCnt=3998         82 02 0f 9e
    帧 smpCnt=3999         82 02 0f 9f
    帧 smpCnt=0   （回绕）  82 02 00 00
    帧 smpCnt=1             82 02 00 01
```

关键断言：**3999 → 0（不是 4000）**；回绕后 smpCnt 继续递增不中断。负例（非法回绕，§9.1）：超过 wrap（4000）再回 0，或中途跳变，期望错误。

### 6.4 S4：smpSynch 置位（未同步 → 全局）

**场景**：第一段 `SmpSynch=0`（未同步），中间配置改为 2（全局）——模拟合并单元接入 PTP。两段各发 N 帧：

```
段 1 每帧：... 85 01 00 ...（smpSynch = 0）
段 2 每帧：... 85 01 02 ...（smpSynch = 2）
```

断言：两段 smpSynch 各自恒定，段切换点仅在段边界发生；smpCnt 跨段连续递增（不因同步状态改变而重置）。

### 6.5 S5：4I+4V 9-2LE 完整数据量

**场景**：完整 8 通道（64 字节）的 seqData，instMag 递增 + quality 各通道独立取值：

```
seqData:  00 00 00 1e | 00 00 00 01    I_A  instMag=30   quality=invalid(0x01)
          00 00 00 2d | 00 00 00 02    I_B  instMag=45   quality=res2?
          ...（可配，示意）
```

断言（tshark）：`sv.seqData` 长度 64；按 PhsMeas 解码每通道 `sv.meas_value` 与 `sv.meas_quality` 与配置一致。quality 值语义：bit0-1 validity=00 good/01 invalid/10 reserved/11 questionable；bit14 test=0x4000；（本用例以 good=0x0000 为主）。

### 6.6 S6：自定义数据集（非 9-2LE）

**场景**：`data` 仅 2 通道（I_A int32、V_A float32），均无 quality，SmpRate 不编码（nil）、无 datSet、有 smpSynch=2。seqData = 4 + 4 = 8 字节。逐层核算：

```
----- 帧：smpCnt = 0（自定义 2 通道） -----
偏移    字节                               说明
0      01 0c cd 04 00 01                  dst MAC
6      aa bb cc dd ee 03                  src MAC
12     88 ba                             EtherType SV
14     40 00                             APPID = 0x4000
16     00 2e                             Length = 0x2E = 46（8 头 + 38 APDU）
18     00 00                             Reserve1
20     00 00                             Reserve2
22     60 24                             savPdu，内容长 0x24 = 36
24        80 01 01                       noASDU = 1
27        a2 1f                          seqASDU，内容长 0x1F = 31
29           30 1d                       ASDU，内容长 0x1D = 29
31              80 04 53 56 30 31        svID "SV01"
37              82 02 00 00              smpCnt = 0
41              83 04 00 00 00 01        confRev = 1
47              85 01 02                 smpSynch = 2
50              87 08                    seqData，内容长 8
52                 00 00 00 1e           I_A int32 = 30
56                 3f c0 00 00           V_A float32 = 1.5（IEEE 754 单精度大端）
60 帧尾（帧总长 = 60 字节 = 0x3C，恰好最小以太网帧长，无 padding）
```

**核算**：ASDU 内容 = svID(6) + smpCnt(4) + confRev(6) + smpSynch(3) + seqData(10) = 29；帧总长 = 14 + 8 + (2 + [noASDU 3 + a2(2 + [30(2+29)])]) = 14 + 8 + 2 + 3 + 2 + 31 = **60**。

断言：`sv.smpRate` 字段**不存在**（可选字段省略 = 协议行为，§3.3）；`sv.datSet` 不存在；`sv.smpSynch == 2`；seqData 按两通道解码（`sv.seqData` 长度 8）。

### 6.7 S7：无 IP 层证明

**场景**：任何一帧（如 S1 帧）剥离 L2 后**全帧没有 IP 头**。

- `frame.protocols == "eth:sv"`（无 vlan 时）/ `"eth:vlan:sv"`（有 vlan 时），**不得含 "ip"**。
- 帧第 0x0C-0x0D 字节是 `88 ba` 而不是 `08 00`/`86 dd`。
- 无 20 字节 IPv4 头（首字节 0x45）、无端口号。
- 断言 `none`：`ip` 层不存在（或 FrameAssert 偏移 22 直取 0x60）。

### 6.8 S8：VLAN 场景

**场景**：`vlan_enabled=true, vlan_id=100, vlan_priority=4`：

```
0     01 0c cd 04 00 01            dst
6     aa bb cc dd ee 03            src
12    81 00                         TPID（802.1Q）
14    40 00                         0x4000 → TCI：priority=4、VID=0x064(100)
                                        （0x8000|0) | 100 = 0x8064
16    88 ba                         EtherType SV
18    40 00                         APPID ...
```

TCI 计算：priority(4)<<13 = 0x8000；DEI=0；VID=100=0x064 → TCI=0x8064。帧内字段偏移整体 +4。断言：`vlan.id==100`、`vlan.priority==4`、`sv.appid` 正常。

### 6.9 S9：多帧时序（采样周期稳定）

**场景**：连续 100 帧，`period_us=250`。断言：相邻帧 `frame.time_delta` 均值 ≈ 250µs（tolerance 内），无突发；`frame.time_relative` 递增。该用例验证 §4.8 的周期语义（发送节拍未失控、无停发）。

### 6.10 S10：smpSynch 三值逐帧可见 + 回绕数学

**场景**：三个连续任务段，每段 smpCnt 连续、smpSynch 分别 0/1/2；行为同 S4 但通过配置值展示**三个枚举全被编码**，并且验证"同一流 confRev 恒定、不同同步段共用一个 wrap 计数"。

| 段 | smpSynch 字段字节 | 语义 |
|----|-------------------|------|
| A | `85 01 00` | 未同步（合闸前） |
| B | `85 01 01` | 本地时钟 |
| C | `85 01 02` | 全局时钟（PTP） |

**回绕数学验证**（无实际发 4000 帧，用公式推导 + 抽样）：
```
wrap = samples_per_cycle = 4000
N 帧内回绕次数 = floor((起始 smpCnt + N - 1) / wrap)
第 i 帧 smpCnt = (起始 + i) mod wrap          （i 从 0 起）
```
断言：任取 N（如 5000），用该公式算出的 smpCnt 与抓包完全一致（单测可低成本覆盖，pcap 用抽样帧）。

**与 GOOSE 对照（时序采样域的延续）**：GOOSE 的 sqNum 是事件重发计数，SV 的 smpCnt 是采样序号；S4 的"同步状态切换不重置计数"与 S10 的"计数跨段连续"共同表达 SV 的**纯时间驱动**语义。

---

## 7. 与 testcase 文档的映射索引

24-sv-testcase.md 的每个用例对应本文档的某个章节/场景，构成 spec→test 的可追溯链（Testing Policy 第 1 条：测试从规格驱动，非自组织）。

| testcase 用例 ID | 主题 | 本文档依据 | 场景/章节 | 关键断言 |
|------------------|------|-----------|-----------|----------|
| T-SV-S1-01 | 9-2LE 基础采样帧联发 3 帧 | §6.1/§2.5 | S1 | smpCnt 0/1/2 递增；Length=0x6A；帧长 120 |
| T-SV-S1-02 | 帧头字段（APPID/Length/Res1/Res2） | §2.4 | S1 | sv.appid=0x4000、sv.length=112(0x70)、reserve1/2=0 |
| T-SV-S2-01 | 双重发（同 smpCnt 2 帧） | §4.6/§6.2 | S2 | 同 smpCnt 出现 2 次；两帧字节一致 |
| T-SV-S3-01 | smpCnt 回绕 0..3999..0 | §4.3/§6.3 | S3 | 3999→0；不跳到 4000 |
| T-SV-S3-02 | 非法回绕（负例） | §9.1 | S3 | expect_error |
| T-SV-S4-01 | smpSynch 未同步→全局 | §4.4/§6.4 | S4 | 段内恒定、段边界切换 |
| T-SV-S4-02 | smpSynch 非法值（负例） | §9.5 | S4 | expect_error |
| T-SV-S5-01 | 4I+4V 完整数据量 | §2.7/§6.5 | S5 | seqData 64B；每通道 meas_value |
| T-SV-S6-01 | 自定义数据集（2 通道） | §5.1/§6.6 | S6 | smpRate 字段不存在；seqData 8B |
| T-SV-S7-01 | 无 IP 层证明 | §3.1/§6.7 | S7 | frame.protocols=eth:sv 不含 ip |
| T-SV-S8-01 | VLAN 场景 | §2.2/§6.8 | S8 | vlan.id=100、priority=4；EtherType 后移 |
| T-SV-S9-01 | 采样周期稳定 | §4.8/§6.9 | S9 | 帧间隔≈250µs |
| T-SV-NEG-01 | ConfRev<1 负例 | §9.2 | §9 | expect_error |
| T-SV-NEG-02 | APPID 越界负例 | §9.3 | §9 | expect_error |
| T-SV-NEG-03 | Length/APDU 不匹配负例 | §9.4 | §9 | expect_error |
| T-SV-NEG-04 | 通道数据长度不符负例 | §9.6 | §9 | expect_error |

**testcase 覆盖勾选清单**（24-sv-testcase.md §7 逐项核对）：

- [x] 采样值序列：smpCnt 递增 >1 帧（S1）
- [x] 双重发：同 smpCnt 2 帧（S2）
- [x] 回绕：0→3999→0（S3）+ 非法回绕负例（S3-02）
- [x] smpSynch：置位/切换/非法值（S4）
- [x] 4I+4V 9-2LE 数据量（S5）
- [x] 自定义数据集（S6）
- [x] 无 IP 层证明用例（S7）
- [x] 负路径 expect_error：非法 smpCnt 回绕（S3-02）、ConfRev<1（NEG-01）、APPID 越界（NEG-02）

---

## 8. 实现集成点

### 8.1 EtherType 常量（core/builder.go）

新增常量 `EtherTypeSV = 0x88BA`（§2.3）。框架 `builder` 在写 L2 帧头时按层的 EtherType 字段输出（现有 `EtherTypeIPv4` 等模式）。

### 8.2 层注册 + 校验器（internal/core/layers）

- registry.go：注册 `sv` 终结层规格（§5.3）：`Name:"sv"`, `Category: CategoryTerminal`, `DependsOn: nil`。
- `Validate`（`internal/protocol/sv/validator.go`）：SV 层与 `ip`/`tcp`/`udp` 层共存即报错（R-SV 不支持，§1.5）。
- 校验器应导出的 Go 实现位置：`trafficgen/internal/protocol/sv/validator.go`。

### 8.3 组播目的 MAC 覆盖（engine）

SV 无 IP 层，目的 MAC 来自 `SVConfig.DstMAC`（默认 01:0C:CD:04:00:01），**不经过链规划器的 IP-组播推导**（chain_planner 的 `finalEmit` 只对含 IP 层的包做多播覆盖）。SV 层生成器直接在 `pkt.L2.DstMAC` 上写组播值；engine 若有"非组播目的 MAC 修正"逻辑，须对 SV 禁用（SV 恒组播，不退回单播）。

### 8.4 采样定时器与帧生成（internal/protocol/sv/layer_gen.go）

- 基于 `Period`（µs）的定时器驱动（而非事件驱动），每次 tick 生成一帧；`DoubleSend` 时同 tick 连续发 2 帧。
- smpCnt 状态在生成器内部维持（`uint16` 从配置初值起，到 wrap 回绕）。
- 帧的 APDU 用类 `encodeSavPdu(noASDU, asduBytes)` 的 BER 编码函数拼装（§2.5 表逐字段编码）。
- 取消路径（`req.Context`）与 mDNS/GOOSE 层生成器一致的排空清理（goleak 用例验证无泄漏）。

### 8.5 每帧时间戳

帧打上**真实发送时刻**时间戳（wall-clock，非 Plan 覆写时间戳——与 mdns 层同坑，Memory 记录"gap 断言陷阱：Plan 覆写 Timestamp→用 wall-clock"），供 `frame.time_delta` 断言（S9）。发送间隔由定时器决定；若定时器精度不足（µs 级），S9 允许在容差带内断言（如 250µs±200µs）。

### 8.6 strategy_convert.go 分支

新增 `case "sv"`：把 `spec.sv` flat 键翻译为 `SVConfig`（§5.4）。字段校验在 `Validate(spec)` 完成（§9 全部负例），convert 只做无损字段映射。

### 8.7 registry 的 GOOSE/SV 分野

同一 COM 下 GOOSE 与 SV 均注册为终结层 L2 直承；`DependsOn: nil` 意味着 `[{"eth":{}},...]` 链不自动补 ip/tcp。两协议集成点的差异仅 EtherType 常量、BER 编码器、组播 MAC 默认值。可抽公共 L2 组播基础（VLAN 写头、组播 MAC 校验、pad 最小帧），子任务按需。

### 8.8 实现分层（从 Stdlib 到 pcap）

SV 的实现按 5 层划分（对应 15-srv6-design.md 集成点风格）：

| 层 | 组件 | 职责 | 产出 |
|----|------|------|------|
| L1 | `internal/core/types.go` | `SVConfig`/`SVDataChannel` 类型 | 结构定义 |
| L2 | `internal/protocol/sv/ber.go` | BER 原语：`encodeTL`/`encodeStringWithTag`/`encodeUInt16FixedSize`/`encodeUInt32FixedSize` | 字节编解码函数 |
| L3 | `internal/protocol/sv/planner.go` | `Plan(ctx, cfg)` → 按 Period 产出帧配置；含 smpCnt/doubt 状态 | `<-chan PacketConfig` |
| L4 | `internal/protocol/sv/layer_gen.go` | `Generate(ctx, req)` → 组装以太网头 + SV 头 + savPdu 的完整帧 | Packet 结构/字节 |
| L5 | `internal/protocol/sv/validator.go` | `Validate(spec)` → 全部 §9 校验 | error |

每层独立可测（BER 层逐字节单测；planner 层帧序单测；validator 层负例单测），pcap 用例做 L1-L5 端到端。

### 8.9 生成器伪码（period 驱动）

```go
func (g *SVGenerator) run(ctx context.Context, cfg *core.SVConfig, emit func(core.PacketConfig)) error {
    var smpCnt uint16 = 0
    timer := time.NewTicker(cfg.Period)
    defer timer.Stop()
    for {
        select {
        case <-ctx.Done():
            return nil // 取消清理，无 goroutine 泄漏
        case <-timer.C:
            p, _ := g.buildFrame(cfg, smpCnt)  // svID/smpCnt/confRev/smpSynch/seqData 组装
            emit(p)
            if cfg.DoubleSend {
                p2, _ := g.buildFrame(cfg, smpCnt) // 同 smpCnt 冗余报
                emit(p2)
            }
            smpCnt++
            if int(smpCnt) >= cfg.SamplesPerCycle {
                smpCnt = 0 // 回绕（§4.3）
            }
        }
    }
}
```

### 8.10 测试矩阵（单测 + pcap 双覆盖）

| 关注点 | 单测（`sv_test.go`） | pcap 用例（sv.json） |
|--------|----------------------|----------------------|
| BER 编码逐字节 | encodeSavPdu 对照 hex 模板 | T-SV-S1-01 frames |
| smpCnt 递增/回绕 | 生成帧序列断言 | T-SV-S3-01 |
| 双重发帧序 | buildFrame×2 断言 | T-SV-S2-01 |
| Validate 负例 | 直接断言 error | T-SV-NEG-01..04 |
| seqData 通道布局 | 逐通道字节断言 | T-SV-S5-01/S6-01 |
| 定时器无泄漏 | goleak | — |

### 8.11 测试文件位置

| 文件 | 内容 |
|------|------|
| `trafficgen/internal/protocol/sv/sv_test.go` | 单测：BER 编码、smpCnt 回绕、double_send 帧序 |
| `trafficgen/internal/protocol/sv/validate_test.go` | 校验负例（§9 全部） |
| `trafficgen/test/protocol_pcap/cases/sv.json` | pcap 框架用例（与 24-sv-testcase.md 对应） |

### 8.12 时序实现边界（工程取舍）

| 关注点 | 决策 | 理由 |
|--------|------|------|
| 定时器精度 | Go `time.Ticker` 提供 ~µs-ms 抖动 | 测试断言用容差带（250µs±200µs），不追求硬实时 |
| 高采样率保护 | `Period < 50µs`（≈20k 帧/s）建议警告 | 平台 io 速率上限，防环形缓冲溢出（Memory：buffer-overflow-stall 教训） |
| 发送突发 | 帧按 ticker 逐 emit（不批量） | 保持 `frame.time_delta` 均一；双发除外 |
| 统计（可选） | 帧计数/字节计数节流 debug | 便于观测"每秒采样点 == period 倒数" |

---

## 9. 错误处理

### 9.1 smpCnt 回绕越界

| 输入 | 期望行为 |
|------|----------|
| `SamplesPerCycle < 1` | 拒绝：每周采样数至少 1 |
| `SamplesPerCycle > 65535` | 拒绝：smpCnt 是 16 位 |
| 运行时 smpCnt 达 wrap 前不重置（跳变） | 拒绝/终止（帧序列异常） |
| 运行时 smpCnt 超 wrap 才回绕 | 拒绝/终止（序列异常） |
| 用户显式以负值/0 起始 | 拒绝（或按 wrap-1 强制合法映射，文档明确） |

### 9.2 ConfRev < 1

`ConfRev`（配置版本）必须 **≥1**（0 表示未定义版本，IED 不使用）。`conf_rev: 0` → 校验失败，报错，任务 fail（expect_error 用例如 T-SV-NEG-01）。

### 9.3 APPID 越界

| 区间 | 判定 |
|------|------|
| 0x4000-0x7FFF | SV 标准段，默认/推荐 |
| 0x0000-0x3FFF | GOOSE 保留段，显式配置时**拒绝（expect_error）**；负例 T-SV-NEG-02 配置 0x3999 报错 |
| 0x8000-0xFFFF | 保留/用户段，允许（向前兼容） |

（注意：§2.4 中 APPID=0x3FFF 源自任务描述的"0x3FFF 默认"提法，本文档以权威分配 0x4000-0x7FFF 为准，此处负例故意选 0x3999 落于 GOOSE 段以证明校验器区分段位。）

### 9.4 Length / APDU 长度不匹配

框架生成的包必须满足 `SV 头 Length == 8 + len(APDU)`。若内部编码器算出不符（例如 seqData 通道宽配置错误导致实际字节数与声明不符），在 send 前报错（负例 T-SV-NEG-03：手工篡改 Length 或通道数，期望 error）。**校验公式唯一**：帧长 - 14（无 VLAN）− 8 = APDU 长。

### 9.5 smpSynch 非法值

`smpSynch` 合法 {0,1,2}。配置 3-15 → 校验拒绝（版 1 仅 0/1/2，负例 T-SV-S4-02）。工程上表示"不可用"用显式不编码（省略该字段）。

### 9.6 数据通道长度不符

`seqData` 实际字节数 ≠ `8 × sum(通道宽)`（4B int32/4B float32 全是 4 字节 + 可选 quality 4 字节）→ 拒绝（负例 T-SV-NEG-04）。文档声明 8×N（N=通道数），实际编码不符即 error。

### 9.7 通用错误模型

| 错误分类 | 表现 | 位置 |
|----------|------|------|
| 配置校验错误 | 任务 Create/Start 拒绝 | sv validator (§8.2) |
| 帧编码错误 | plan/generate 返回 error；任务 fail | sv layer_gen / builder |
| 时序错误 | 采样周期过密（Period < 10µs？超出生理） | validate 上界保护 |

---

## 10. 扩展字段映射

以下为未来的 SV 扩展字段与其 Metadata 映射（当前未实现，`Metadata` 键为规划中的字段名约定；首见英文加（中文解释））。

| Metadata 键 | 类型 | 语义 | 对应 BER 字段 |
|-------------|------|------|---------------|
| `sv_confrev` | uint32 | 配置版本（动态变化用例） | ASDU 0x83 |
| `sv_smpcnt_offset` | uint16 | smpCnt 起始偏移（模拟样本批次拼接） | ASDU 0x82 |
| `sv_sample_time` | refrTm（8 字节） | 采样时刻 UTC（可选） | ASDU 0x84 |
| `sv_smpmod` | int8 | 采样模式（可选） | ASDU 0x88 |
| `sv_gmid` | uint64 | gPTP 主时钟身份（可选） | ASDU 0x89（扩展） |
| `sv_override_dst_mac` | string | 自定义组播 MAC（覆盖默认） | 以太网头 |
| `sv_ndscom` | — | 保留：不再实现（GOOSE 的表示残留，本协议已并入 noASDU 语义） | — |

**为什么这些以 Metadata 而非配置字段暴露**：它们大多是一次性/动态语义（如 confRev 变化的两阶段、smpCnt 偏移），不适合放静态 `SVConfig`；通过 Metadata 可让包级生成器在运行期注入，而 `SVConfig` 保持业务语义纯净。

### 10.1 扩展关键词的实现前置与互操作约定

| 扩展 | 状态 | v1 前置条件 / 互操作约束 |
|------|------|--------------------------|
| `sv_smpcnt_offset` | 立即支持（廉价） | 生成器起始 smpCnt 读配置而非硬 0；对 9-2LE 互操作无影响（订阅方只认相对递增 + 回绕） |
| `sv_confrev` | 立即支持 | 两阶段任务（reconfigure）→ confRev+1、smpCnt 不重置（§4.5）；tshark `sv.confRev` 可观测 |
| `sv_sample_time`（refrTm） | 待条件 | 需 wall-clock 采样时刻精度（现只有帧发送时刻）；工程上 IED 多忽略，v1 省略 |
| `sv_smpmod` | 待条件 | ASN.1 1 字节 vs libiec61850 2 字节分歧（§2.9 smpMod 注）；实现时先按 1 字节 + 兼容测试 |
| `sv_gmid`（gmIdentity） | 待条件 | 需要 PTP 主时钟身份注入（v1 无 gPTP 栈）；仅在上层提供 CM 时启用 |
| `sv_override_dst_mac` | 立即支持 | 组播覆盖机制对 SV 禁用 IP 推导（§8.3），用户显式写组播即可 |

**互操作拒收清单**（NEVER，明确不实现）：
- R-SV over UDP/IP（validate 拒绝，§1.5/§8.2）
- SV 单播目的 MAC（除非用户显式覆盖且接受非标准）
- 批量块模型（savPdu 多 ASDU 每 ASDU 多采样点，v1 单采样模型）
- IEC 62351 安全（签名/加密改造，破坏裸 BER 可解析性，§1.5）

**向下兼容基线**：所有 v1.0 配置产物均可被 libiec61850 与 Wireshark 完整解码（逐字节一致性见 §2.9）；扩展字段默认**不编码**（BER 省略），从不断言"必须存在"——除非测试显式指定（§3.3 可选性语义）。

---

## 11. 修订记录

| 版本 | 日期 | 内容 |
|------|------|------|
| v1.0.0 | 2026-08-18 | 初稿：完整 11 章；BER 编码以 libiec61850/Wireshark 权威核实；修正任务提示中 APPID=0x3FFF 与 BER tag 的偏差（§2.4/§2.5）；HexDump S1-Sn 逐字节核算（§6）；testcase 映射索引（§7）；实现集成点（§8）；错误处理（§9）；扩展字段（§10） |

> **已核实来源清单**：IEC 61850-9-2 / 9-2LE 规范（Engineering Guide），libiec61850 参考实现（`sampled_values/sv_publisher.c`、`iec61850/inc/sv_publisher.h`、`examples/iec61850_9_2_LE_example.c`），Wireshark SV 解析器（`epan/dissectors/packet-sv.c` 及 dfref 字段表）。全文核心字节事实（段位、tag、Length 口径）均源自上述实现，而非转录未经验证的二手资料。




