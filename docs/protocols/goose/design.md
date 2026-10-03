# IEC 61850-8-1 GOOSE（Generic Object Oriented Substation Event）协议设计

> 版本：v1.1.0（P-PIPE 文档轨、as-built 静态对账版）
> 设计日期：2026-10-01
> 范围：IEC 61850-8-1 通用面向对象变电站事件（GOOSE，Generic Object Oriented Substation Event）流量的生成。以太网组播（0x88B8）直承，**无 IP 层**；包含有限帧序列、数据集变化、测试/送修（test）、配置版本（confRev）、数据值类型编码（MMS Data）与全部负路径
> 实现依据：GOOSE 配置仅从 `layers[].goose` 进入层链；本文只记录当前校验器与有限帧序列生成能力，不承诺尚未实现的运行时调度。
> 配套参考：同栈兄妹协议 SV（采样值，Sampled Values）设计（24-sv-design.md，周期驱动，本文档为事件驱动）；层链配置架构（18-layer-config-design.md）

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

### 1.1 GOOSE 定位

**GOOSE（Generic Object Oriented Substation Event，通用面向对象变电站事件）** 是 IEC 61850 标准族中的**实时事件驱动组播机制**，由 **IEC 61850-8-1（特定通信服务映射）** 定义。它把断路器/隔离开关的分合闸状态、保护动作信号、联锁状态、数字量/模拟量数据集（DataSet，数据集，一组按序排列的数据成员）等**状态与事件**，以带时间戳的帧，通过以太网**组播**给变电站内所有订阅该流的 IED（Intelligent Electronic Device，智能电子设备，具备保护/测控功能的二次装置）。

与 SV（Sampled Values，采样值，IEC 61850-9-2，周期性）截然不同，GOOSE 是**事件驱动**的：

| 维度 | GOOSE（本文档） | SV（采样值） |
|------|-----------------|--------------|
| 触发方式 | **事件**（由有限帧序列表达数据/状态变化） | **周期**（按采样率固定间隔重发） |
| 协议标准 | IEC 61850-8-1 | IEC 61850-9-2 |
| 时敏性 | 准实时（ms 级，跳闸信号要求传输 < 4 ms） | 硬实时（µs 级） |
| 承载 | 以太网直承（组播 MAC） | 以太网直承（组播 MAC） |
| EtherType | 0x88B8 | 0x88BA |
| 组播 MAC 段 | 01:0C:CD:01:xx:xx | 01:0C:CD:04:xx:xx |
| APDU 类型 | goosePdu（GOOSE 协议数据单元） | savPdu（采样值应用协议数据单元） |
| 序号 | stNum（状态号）+ sqNum（序列号） | smpCnt（采样计数） |
| 重发策略 | 由有限 `event_seq`/`count` 表达同事件帧序列 | 每个采样点发一帧 |

**本设计只实现 GOOSE 的事件发布**，不涉及：
- MMS（制造报文规范）服务/报告（IEC 61850-8-1 控制服务，TCP 102）——那是另一协议（GOOSE 的数据集内容编码虽复用 MMS Data 的 BER 类型，但本报文不经 TCP/MMS）
- R-GOOSE（IEC 61850-90-5 基于 UDP 的改进型 GOOSE）：本设计只做以太网直承 L2 GOOSE
- IEC 62351 安全（GOOSE 签名/AEAD 加密改造）：v1 不实现（§1.5）

### 1.2 设计目标

1. 组播目的 MAC 01:0C:CD:01:xx:xx（IEC 61850-8-1 GOOSE 流段），用户可配，默认 01:0C:CD:01:02:03（与当前生成器及 cases 基线一致）。
2. EtherType 0x88B8（IANA 分配的 GOOSE 类型），**不经过 IP**（帧内无 IP 头）。
3. 帧头 8 字节：APPID + Length + Reserve1 + Reserve2（与 SV 同构，仅 APPID 段/含义不同）。
4. APDU 用 ASN.1 的 BER（Basic Encoding Rules，基本编码规则）编码 goosePdu（Tag 0x61），逐字段（gocbRef/timeAllowedToLive/datSet/goID/t/stNum/sqNum/test/confRev/ndsCom/numDatSetEntries/allData）。
5. 有限帧序列：由 `count` 与 `event_seq` 描述心跳帧、事件变化和有限重发，不承诺墙钟调度。
6. 计数语义：事件变化 stNum+1、sqNum 置 0；同一事件的后续帧 sqNum 按配置步进，内容不变时 stNum 恒定。

### 1.3 trafficgen 中的定位

GOOSE 是 **L2 终结层**：配置链 `[{"eth":{}},{"goose":{}}]`——以太网帧直接承载 GOOSE，**无 IP 层**。这是 GOOSE 与绝大多数已实现协议的最架构性差异（仅 arp/SV/mdns 等少数协议类似）。层的职责：

1. 组装以太网头（组播目的 MAC、可选 VLAN、EtherType 0x88B8）；
2. 组装 8 字节 GOOSE 帧头（APPID + Length + Reserve1 + Reserve2）；
3. 用 ASN.1 BER 编码 goosePdu APDU；
4. 按有限帧序列产出配置中的帧，维护 stNum/sqNum。

### 1.4 术语对照表（英文首现 → 中文）

| 英文（首现本文档） | 中文解释 |
|--------------------|----------|
| GOOSE | 通用面向对象变电站事件：事件驱动组播 |
| IED | 智能电子设备：变电站二次装置 |
| DataSet（数据集） | 一组按序排列的数据成员（GOOSE 载体） |
| gocbRef（GOOSE 控制块引用） | 发布控制块的引用路径 |
| timeAllowedToLive（TAL） | 存活时间：订阅方超过此值收不到帧即判通信丢失 |
| stNum（状态号） | 数据集内容变化次数 |
| sqNum（序列号） | 同一事件内的重发序号 |
| confRev（配置版本） | 数据集配置版本号 |
| ndsCom（送修，need commissioning） | 需要整定标记：置 1 表示处于调试/未投运状态 |
| test（测试标志） | 置 1 表示仿真/测试帧，接收方可据其不视为真实状态 |
| numDatSetEntries（数据集条目数） | 数据集成员个数 |
| allData（全部数据） | 数据集成员值的 BER 序列 |
| Basic Encoding Rules（BER） | ASN.1 基本编码规则（tag+length+value） |
| CpTime（八字节时间） | IEC 61850 八字节时间戳（CP 8B） |
| MMS Data（MMS 数据） | 制造报文规范的数据类型集合（本协议复用其 BER 编码） |
| `Retransmission`（有限重发） | 事件后在有限帧序列中重复发送同内容帧 |
| `Heartbeat`（心跳） | 无事件时按 `count` 生成的状态保持帧 |

---

## 2. 数据类型与编码

### 2.1 以太网头（组播 MAC）

GOOSE 直接承载在以太网 II（Ethernet II）帧上，**不经过 IP**。帧头：

| 字段 | 长度 | 字节序 | 值 |
|------|------|--------|-----|
| 目的 MAC（Destination Address） | 6 字节 | — | 组播 **01:0C:CD:01:xx:xx**（IEC 61850-8-1 GOOSE 流段） |
| 源 MAC（Source Address） | 6 字节 | — | 发送方（IED）MAC，可配 |
| 可选 VLAN（802.1Q Tag） | 4 字节 | 大端 | TPID 0x8100 + TCI（优先级/VLAN ID） |
| EtherType | 2 字节 | 大端 | **0x88B8**（GOOSE） |

**组播 MAC 分配（01:0C:CD:01:xx:xx）**：
- `01:0C:CD` 是 IEC 61850 组播组的组织唯一标识前缀（IEC 61850-8-1 分配给 GOOSE/SV 等）
- 第四字节 `01` = GOOSE 数据流段（SV 用 `04`）
- 低 16 位 `xx:xx` 由用户配置（0x00-0xFF），区分不同 GOOSE 流/数据集；典型分配固定 `01:00:xx`
- 默认目的 MAC = `01:0C:CD:01:02:03`；engine 的组播覆盖机制保证恒为组播（不被单播回退），详见 §8.3

**与 IP 组播推导的区别**：mDNS/RIP 等运行在 IP 之上，目的 MAC 可从多播 IP 推导（01:00:5E/33:33）；GOOSE **无 IP 层**，目的 MAC 是显式配置的静态组播地址，不推导。

### 2.2 VLAN TPID/TCI

GOOSE 可选挂载 802.1Q VLAN：即以太网头之后、EtherType 之前插 4 字节 `TPID(0x8100) + TCI`。TCI（Tag Control Information，标签控制信息）按 IEEE 802.1Q 大端编码：

```
TCI = Priority(3) << 13 | DropEligible/CFI(1) << 12 | VID(12)
```

| 位段 | 长 | 说明 |
|------|----|------|
| Priority（用户优先级，PCP） | 3 bit | 0-7；GOOSE 典型 **4**（过程总线受控流量） |
| DEI/CFI（丢弃合格指示/规范格式指示） | 1 bit | 0（经典以太网） |
| VID（VLAN 标识） | 12 bit | 0-4095；过程总线可运营配置专用 VLAN |

**与 SV 同构**：两者默认优先级均为 4。`GooseConfig` 提供 `vlan_enabled/vlan_id/vlan_priority` 三字段（§5.1），默认关（不插 VLAN，帧更短易解析）。

### 2.3 EtherType 0x88B8

EtherType 0x88B8（十进制 35000）是 IANA 分配给 **IEC 61850-8-1 GOOSE** 的类型字段。它是链路层解复用的依据，也是 tshark/交换机识别 GOOSE 的关键（`eth.type == 0x88b8` 时 Wireshark 试用 `goose` 解析器，`frame.protocols` 含 `goose`；若 tshark 缺 goose 解析器则回落到 `data`，此时用 FrameAssert 原始字节断言 APDU BER 标签字节，见 testcase §1.2）。

必须在 builder 层新增常量（现 core 仅有 `EtherTypeIPv4=0x0800`、`EtherTypeARP=0x0806`、`EtherTypeIPv6=0x86DD` 及 PPPoE/GRE/MPLS/SV 相关）：

```go
// internal/core/builder.go
EtherTypeGOOSE = 0x88B8 // IEC 61850-8-1 GOOSE (IEC 61850-8-1)
```

### 2.4 GOOSE 帧头（APPID/Length/Reserve1/Reserve2）

EtherType 之后是 **8 字节 GOOSE 帧头**，全部大端（与 SV 同构）：

| 偏移 | 长度 | 字段 | 说明 |
|------|------|------|------|
| 0 | 2 字节 | **APPID**（应用标识） | 标识 GOOSE 逻辑流；订阅方据此过滤 |
| 2 | 2 字节 | **Length**（长度） | **从 APPID 字段起**到 APDU 结束的总字节数（= 8 + APDU 长度） |
| 4 | 2 字节 | **Reserve1**（保留 1） | 保留；位 15 为仿真位（Simulation，模拟状态标志，3.6+ tshark） |
| 6 | 2 字节 | **Reserve2**（保留 2） | 保留（供未来安全/扩展） |

**APPID 分配**：当前实现仅接受 `0x0000-0x3FFF`（本文档范围，默认 `0x1000`）；大于 `0x3FFF` 的值均拒绝，并返回 `outside GOOSE range 0x0000-0x3fff`。SV/保留/用户自定义区间不属于本实现的可用 GOOSE 配置。

**Length 口径**：`GOOSE 头 Length = 8 + APDU 全长`（计从 APPID 起，含本字段后的 4 字节保留 + APDU）。libiec61850 `GoosePublisher_publish`：`gooseLength = payloadLength + 8`，`payloadLength` = savPdu 式完整 goosePdu 长度。**SV 的 Length 也是同口径**，两协议头结构完全同构。

> **当前文档基线具体值**：默认长引用场景采用 `61 81 <content-length>` 长形式。心跳 APDU content=173、APDU total=176，因此 GOOSE Length=184 (`0x00b8`)；VLAN 单成员场景 content=160、APDU total=163，因此 GOOSE Length=171 (`0x00ab`)。每个 JSON case 的 Length 以其实际 data 成员和 BER 长度形式逐一重算。

**Reserve1 位 15（仿真位 S-bit）**：调试/仿真流标记；v1 默认 0（真实流）。注意该位与 APDU 内 `test`（测试标志）是**两个不同字段**（前者在帧头的 Reserved 内，后者在 APDU 内，§3）。

### 2.5 ASN.1 BER 编码的 goosePdu 与 APDU 完整标签表

GOOSE PDU 用 ASN.1 的 BER（Basic Encoding Rules，基本编码规则）编码。核心 ASN.1 定义（IEC 61850-8-1）：

```
IECGoosePdu ::= SEQUENCE {
    gocbRef            [0] IMPLICIT VisibleString,
    timeAllowedToLive  [1] IMPLICIT INTEGER (0..4294967295),
    datSet             [2] IMPLICIT VisibleString,
    goID               [3] IMPLICIT VisibleString OPTIONAL,
    t                  [4] IMPLICIT UtcTime,
    stNum              [5] IMPLICIT INTEGER (0..4294967295),
    sqNum              [6] IMPLICIT INTEGER (0..4294967295),
    test               [7] IMPLICIT BOOLEAN DEFAULT FALSE,
    confRev            [8] IMPLICIT INTEGER (0..4294967295),
    ndsCom             [9] IMPLICIT BOOLEAN DEFAULT FALSE,
    numDatSetEntries   [10] IMPLICIT INTEGER (0..65535),
    allData            [11] IMPLICIT SEQUENCE OF Data
}
```

**BER Tag 分配（本文档的字节级事实，已逐一对照 libiec61850 `goose_publisher.c` 与 Wireshark `packet-goose.c` 核实）**：

| Tag（hex） | 字段 | ASN.1 类型 | 值编码 | 长度规则 |
|-----------|------|-----------|--------|----------|
| **0x61**（APPLICATION 1 构造） | goosePdu | SEQUENCE | 构造 | 变长（帧体） |
| **0x80**（[0]） | gocbRef | VisibleString | 字符串 | 变长（≤255 短长形式） |
| **0x81**（[1]） | timeAllowedToLive | INTEGER | **BER 最小整数，大端** | 例：500 → `81 02 01 f4`；实现可内部用定长值，但线上断言以最小编码为基线 |
| **0x82**（[2]） | datSet | VisibleString | 字符串 | 变长 |
| **0x83**（[3]） | goID | VisibleString | 字符串 | 变长（可选；**缺省 = gocbRef**） |
| **0x84**（[4]） | t（时间戳） | UtcTime | **8 字节 CP 时间** | 固定 8 |
| **0x85**（[5]） | stNum | INTEGER | 最小编码，大端 | 值 1 → `85 01 01`、值 2 → `85 01 02`（§3.6） |
| **0x86**（[6]） | sqNum | INTEGER | 最小编码，大端 | 值 1 → `86 01 01`（§3.6） |
| **0x87**（[7]） | test | BOOLEAN | 1 字节 `00`/`01` | 固定 1 |
| **0x88**（[8]） | confRev | INTEGER | 最小编码，大端 | 值 1 → `88 01 01`（§3.6） |
| **0x89**（[9]） | ndsCom | BOOLEAN | 1 字节 `00`/`01` | 固定 1 |
| **0x8A**（[10]） | numDatSetEntries | INTEGER | 最小编码（条目数小取 2 字节） | = 数据集条目数，如 1 → `8a 01 01`、10 → `8a 01 0a` |
| **0xAB**（[11]） | allData | SEQUENCE OF Data | 构造 | 变长（= 各成员 Data 编码之和） |

> **与任务初稿标签表的差异（重要修正，同 SV 前例 24-sv-design.md §2.5）**：
> 初稿曾给出 "0x61 GOOSEPDU、0x81 stNum、0x82 sqNum、0x83 test、0x84 confRev、0x85 ndsCom、0x86 numDatSetEntries、0x87 allData（…）、0x88 security、0x89/0x8A 时间（CP 8B）"。这与 IEC 61850-8-1 / libiec61850 / Wireshark 的实际编码**不一致**，本设计不采用：
> - 真实顺序为 gocbRef(0x80)→timeAllowedToLive(0x81)→datSet(0x82)→goID(0x83)→t(0x84)→stNum(0x85)→sqNum(0x86)→test(0x87)→confRev(0x88)→ndsCom(0x89)→numDatSetEntries(0x8A)→allData(0xAB)；初稿把 0x81/0x82 误作 stNum/sqNum、漏掉 gocbRef/timeAllowedToLive/datSet/goID/t；
> - 初稿的 `allData=0x87` 实为 `t`（时间戳）；**0x87 是 APDU 内 test**（BOOLEAN），非 allData；
> - allData 实际 tag = **[11] IMPLICIT SEQUENCE OF Data** = **0xAB（构造）**；
> - **不存在 "0x88 security" 字段**；IEC 62351 安全为独立报文改造（R-GOOSE，§1.5 不实现）；
> - CP 8B 时间戳字段是 `t`（0x84），不是 0x89/0x8A；0x89 是 ndsCom、0x8A 是 numDatSetEntries。
>
> **校验采纳原则**：以 libiec61850（广泛部署的开源参考实现，Wireshark 可解析其 GOOSE 帧）与 Wireshark `packet-goose.c` 为字节级事实源；初稿标签不采用，并在本文档显式记录差异以防后续实现误填（同 SV 文档做法）。

**BER 长度形式**：本协议几乎所有值长度 ≤ 255 字节，用短形式（单字节，高位 0）；`allData` 大数据集（如 4000 条目）可用长形式。构造类型（0x61/0xAB）长度 = 内容总字节数（全字长，此处均 1 字节长度）。

**数值编码**：所有整数/时间戳**大端**；stNum/sqNum 从 1 起。goID 缺省时 libiec 写 gocbRef 值（§3.4 明确该行为供测试锁定）。

---

## 3. 消息结构

### 3.1 帧的完整布局（字段级）

GOOSE 帧（以太网直承，不足 60 字节最小以太网帧长则尾部加 0 padding）自 L2 起：

```
 偏移   字段                       长度   字节序   值/说明
 ------------------------------------------------------------------------------
 0     dst MAC （组播 01:0C:CD:01:xx:xx） 6    --    IED 订阅的 GOOSE 组播地址
 6     src MAC （发送方/发布 IED）        6    --    用户配置
 12    802.1Q VLAN Tag（可选）  4          BE     TPID 0x8100 + TCI(priority/VID)
 12/16 EtherType                2          BE     0x88B8（无 VLAN 在 12，有则在 16）
 14/18 GOOSE 头: APPID          2          BE     0x0000..0x3FFF（默认 0x1000）
 16/20          Length         2          BE     8 + APDU 总长（从 APPID 起）
 18/22          Reserve1       2          BE     0（位 15 仿真位可选置位）
 20/24          Reserve2       2          BE     0
 ------------------------------------------------------------------------------
 22/26 goosePdu (APDU, ASN.1 BER)
        61 81 <L>  goosePdu [APPLICATION 1]（内容长度 >127 时的长形式）
           80 <L> <gocbRef 字符串>         gocbRef            [0] VisibleString
           81 02 <2 字节>                  timeAllowedToLive  [1] 整数（500 示例）
           82 <L> <datSet 字符串>          datSet             [2] VisibleString
           83 <L> <goID 字符串>            goID（可选）       [3] VisibleString
           84 08 <8 字节 CP 时间>          t（时间戳）        [4] UtcTime
           85 01..04 <最小整数>             stNum              [5] 整数
           86 01..04 <最小整数>             sqNum              [6] 整数
           87 01 <00|01>                   test（测试标志）   [7] BOOLEAN
           88 01..04 <最小整数>             confRev(配置版本)  [8] 整数
           89 01 <00|01>                   ndsCom(送修标志)   [9] BOOLEAN
           8a <L> <最小整数>                numDatSetEntries   [10] 整数
           ab <L>                          allData            [11] 构造
               <成员 1 Data BER><成员 2 Data BER>...
```

**无 IP 层证明**：上表全链路只有 以太网 / VLAN（可选）/ GOOSE 三部分，**没有任何 IP 头（0x45 识别字节）、无 TCP/UDP 端口**。`frame.protocols` 显示 `eth:goose`（带 VLAN 时 `eth:vlan:goose`），不含 `ip`——与 SV 帧同级，是 GOOSE 与 TDS/S7 等 TCP 承载协议的最本质差异。

### 3.2 帧头与 APDU 的组合约束

| 约束 | 规则 | 违反后果 |
|------|------|----------|
| Length = 8 + APDU 长度 | 固定 8 字节 GOOSE 头后的载荷起自 goosePdu | tshark 按 `goose.length` 定位 APDU 尾；不符则报 Malformed |
| goosePdu 必须紧跟 GOOSE 头 | 无中间字节 | EtherType 0x88B8 后第 1 字节必须 0x61 |
| numDatSetEntries = allData 内条目数 | 两者恒一致 | 订阅方按条目数解码 allData；不符则解析错位 |
| stNum/sqNum 从 1 起 | 变更后符合状态机（§4） | 订阅方按序号判丢帧/重帧 |
| VLAN 优先级典型 4 | 过程总线受控流量 | tshark 可断言 `vlan.priority` |

### 3.3 用 ASN.1 视图表达单帧

```
GOOSE 帧 = [EthernetII 头(14)]
        | [802.1Q Tag(4, 可选)]
        | [GOOSE 头(8): APPID | Length | Reserve1 | Reserve2]
        | [goosePdu: 61 { gocbRef | timeAllowedToLive | datSet |
                       goID? | t | stNum | sqNum | test | confRev |
                       ndsCom | numDatSetEntries | allData,
                       allData = { Data, Data, ... } }]
```

- 可选性符号 `?` 表示 goID 可按配置省略（此时编码器写 gocbRef 值，§3.4）
- test/ndsCom 是 BOOLEAN，**必须显式编码**（尽管 ASN.1 有 DEFAULT，工程实现 libiec 恒写出 `87 01 00` / `89 01 00`）——因此"字段是否出现"不作为断言点，**取值**才是
- `t`（8 字节 CP 时间）是每帧重写的墙钟时间戳（§8.5）

### 3.4 每字段编码规则速查

| 字段 | 编码类 | 长度规则 | 缺省/可选 |
|------|--------|----------|-----------|
| APPID | uint16 BE | 2 字节固定 | 默认 0x1000；合法段 0x0000-0x3FFF |
| Length | uint16 BE | 2 字节固定 | = 8 + APDU len（§9 负例） |
| gocbRef | ASCII 可见串 | 1-255 字节 | 必填 |
| timeAllowedToLive | uint32 BE | 奇偶 MSB=1 取 4 字节（典型 4） | 必填（ms） |
| datSet | ASCII 可见串 | 1-255 字节 | 必填 |
| goID | ASCII 可见串 | 1-255 字节 | 可选；缺省默认写 gocbRef 内容（libiec 行为） |
| t | UtcTime（CP 8B） | 固定 8 字节 | 必填（§2.6/§8.5） |
| stNum | uint32 BE | BER 最小整数（1–4 字节） | 状态变化计数（§4） |
| sqNum | uint32 BE | BER 最小整数（1–4 字节） | 重发序列计数（§4） |
| test | BOOLEAN | 固定 1 字节（`00`/`01`） | 恒编码 |
| confRev | uint32 BE | 4 字节最小 | 必须 ≥1 |
| ndsCom | BOOLEAN | 固定 1 字节（`00`/`01`） | 恒编码 |
| numDatSetEntries | uint32 BE | ≥2 字节 | = 数据集条目数 |
| allData | SEQUENCE OF Data | 变长 | 恒编码（可空序列） |

**全帧字节序**：除 MAC 与 IEEE 位序按以太网惯例外，所有数值字段一律大端。

### 3.5 组合解析对照（编解码一致性）

发送方按本表编码、接收方（tshark 与订阅 IED）按同一表解码；任何"编码字节 ≠ 解析字节"＝ 编码 bug，pcap 用例 FrameAssert 锁住这一点：

| 偏移（无 VLAN） | 字节内容（示例） | 编码动作（Go） | 解析方动作 |
|-----------------|------------------|----------------|------------|
| 0-5 | 01:0c:cd:01:02:03 | 写 `DstMAC` | 组播订阅匹配（前 3 字节 01:0c:cd） |
| 6-11 | aa:bb:cc:dd:ee:03 | 写 `SrcMAC` | 源绑定检查（可选） |
| 12-13 | 88 b8 | `putEtherType(EtherTypeGOOSE)` | `eth.type==0x88b8` → goose 解析器 |
| 14-15 | 10 00 | `be.PutUint16(appid)`（默认 0x1000） | `goose.appid`，订阅过滤 |
| 16-17 | 00 xx | `be.PutUint16(8+len(apdu))` | `goose.length` 定位 APDU 尾 |
| 18-19 | 00 00 | `be.PutUint16(0)` | `goose.reserve1`（位 15 仿真位） |
| 20-21 | 00 00 | `be.PutUint16(0)` | `goose.reserve2` |
| 22-23 | 61 .. | `encodeTL(0x61, len)` | goosePdu start |
| 24+ | （字段序列，见 §2.5 表） | 逐字段编码 | `goose.gocbRef` 等 |

**tshark 的 BER 容错提示**：goose 解析器按 BER 长度推进；`goose.length`（16 位）与 BER 内部长度不一致时 Wireshark 报 Dissector bug / Malformed——这帮助负例被观测（testcase NEG §5）。

### 3.6 MMS Data 内部 BER 表（allData 成员编码）

allData 的每个成员用 MMS Data 的 BER 编码（IEC 61850-8-1 引用 MMS 的 Data 类型；字节事实对照 libiec61850 `mms_access_result.c` 与 Wireshark `goose_Data_vals`）。**通用标量类型**：

| Tag（hex） | 类型 | 值编码 | 长度 |
|------------|------|--------|------|
| **0x83** | BOOLEAN（布尔） | 1 字节 `00`/`01` | 固定 1 |
| **0x84** | BIT STRING（位串） | **首字节=未用位个数（padding），后跟字节** | 1+ceil(n/8) |
| **0x85** | INTEGER（有符号整数） | 大端，最小字节数以含符号位 | 1-8 字节 |
| **0x86** | UNSIGNED（无符号整数） | 大端，最小字节数 | 1-8 字节 |
| **0x87** | FLOATING POINT（浮点） | 见 §3.7 | 5 字节（32 位，1 指数+4 尾数） |
| **0x89** | OCTET STRING（八位组串） | 原始字节 | 变长 |
| **0x8A** | VISIBLE STRING（可视串） | ASCII | 变长 |
| **0x8C** | BINARY TIME（二进制时间） | 原始字节（TS 二进制时间 6 字节） | 固定 6（libiec） |
| **0x91** | UTC TIME（世界时） | 8 字节 CP 时间（同 `t` 编码） | 固定 8 |

**构造类型**（数据集嵌套）：

| Tag（hex） | 类型 | 值编码 |
|------------|------|--------|
| **0xA1** | ARRAY（数组） | 成员 Data 序列，元素类型相同 |
| **0xA2** | STRUCTURE（结构体） | 成员 Data 序列，元素类型可不同，成员可带功能约束名 |

**带功能约束（FC，Functional Constraint）的结构体成员**：STRUCTURE 的成员可先写 [0] IMPLICIT VisibleString tag=0x80（FC 名字符串）、再写值 Data；若不写 FC 名则直接写值 Data。v1 数据集成员默认**不含 FC 名**（直接写值），FC 名作为 §10 扩展。

**最小编码**：INTEGER/UNSIGNED 均采用"去掉冗余前导字节"的最小字节数（如值 4000 → 2 字节 `0f a0`，值 1 → 1 字节 `01`）；8021Q 的 BOOLEAN 恒 1 字节。**测试断言必须以最小编码为准**，不得假设固定 4 字节。

### 3.7 FLOATING POINT（浮点，IEC 61850 语义）

`floating-point`（Tag 0x87）不是 IEEE 754 裸 4 字节，而是 IEC 61850-7-2 的二进制浮点编码（Wireshark `goose.floating_point` 按此显示）：

```
0x87 0x04 -- tag + 长度=5（格式宽 32 位：1 指数宽 + 4 尾数宽）
  <指数符号 1 bit><尾数符号 1 bit><指数 6 bit><尾数 4 字节>
```

- 32 位格式：`format-width=32, exponent-width=8`（IEC 61850 默认浮点 = FLOAT32）；libiec 写 `encodeFloat(value, 32, 8)`
- 长度字段 = **1 + (format_width/8)** = 1 + 4 = **5**
- 尾数 4 字节大端、指数 6 bit 偏移 32，指数符号/尾数符号在首字节高 2 位
- Wireshark 字段 `goose.floating_point`（bytes）与 `goose.real`（double，解码后值）
- v1 在数据集里对浮点成员按 FLOAT32（32/8）编码；FLOAT64（64/11）作为 §10 扩展

### 3.8 数据值类型支持矩阵（v1）

| 数据集成员类型 | GOOSE `data_type` 键 | 编码 tag | v1 支持 |
|----------------|----------------------|----------|---------|
| 布尔 | `boolean` | 0x83 | ✓ |
| 位串 | `bit_string`（如 `"bpairs:8"`） | 0x84 | ✓ |
| 有符号整数 | `int32`/`int64` | 0x85 | ✓（int32 定宽 4，int64 定宽 8） |
| 无符号整数 | `uint32`/`uint64` | 0x86 | ✓ |
| 浮点 | `float32`（FLOAT32） | 0x87 | ✓（32/8） |
| 八位组串 | `octet_string` | 0x89 | ✓ |
| 可视串 | `visible_string` | 0x8A | ✓ |
| 二进制时间 | `binary_time` | 0x8C | ✓（6 字节） |
| 世界时 | `utc_time` | 0x91 | ✓（8 字节） |
| 数组/结构体 | `array[...]`/`struct[...]` | 0xA1/0xA2 | 规划中（§10） |

---

## 4. 帧序列与计数语义

GOOSE 生成器按配置中的有限帧序列输出，不在本契约中规定墙钟定时器或退避调度。事件序列用于表达数据集变化和重发形状；事件变化使 `stNum` 加一并将首帧 `sqNum` 置零，同一事件内后续帧保持数据内容不变并按序列配置递增 `sqNum`。无事件帧保持 `stNum` 不变。

### 4.1 stNum/sqNum 语义与回绕

GOOSE 是**无握手、无连接的组播**。当前实现只描述有限帧序列，不规定运行时状态机或墙钟调度：

| 状态量 | 定义 | 语义 |
|--------|------|------|
| `stNum` | 32 位状态号 | 数据集内容每变化一次 +1；同一内容期间不变 |
| `sqNum` | 32 位序列号 | 事件首帧为 0；同一事件内按 `event_seq[].sq_num_step` 步进 |
| `event_seq` | 有限事件列表 | 描述内容索引和有限帧形状 |


| 状态量 | 定义 | 语义 |
|--------|------|------|
| `stNum` | 32 位状态号 | 数据集内容每变化一次 +1；同一内容期间不变 |
| `sqNum` | 32 位序列号 | 每次重发 +1；**事件变化置 0**（下一帧 seq=0） |
| `event_seq` | 有限事件列表 | 事件数据索引、`retransmits` 与可选 `sqnum_step` |

`start_stnum`/`start_sqnum` 可设置合法非零起点；实现拒绝 `0xffffffff`，以免有限序列在下一次递增时回绕。`event_seq[].data_idx` 与 `delay_ms` 当前仅解析保存，帧生成不按 data_idx 替换数据、也不按 delay_ms 睡眠；因此文档只把它们作为序列形状元数据，不宣称动态调度或内容变化。### 4.2 stNum/sqNum 约束

GOOSE 生成器只按有限 `count` 与 `event_seq` 生成帧，不使用运行时定时器或墙钟退避；有限序列覆盖就是本节唯一的已实现行为准则：

| 行为 | 规则 | 边界 |
|------|------|------|
| 数据集内容变化 | stNum+1、sqNum=0（首帧） | stNum 不回绕 |
| 无变化 | stNum 不变、sqNum 按事件序列步进 | sqNum 自然 32 位回绕允许 |
| sqNum 不连续（负例） | 事件首帧必须为 0，其后按配置步进 | 违反即期望错误（§9.1） |
| stNum 回绕（负例） | 不得产出回绕 stNum | 违反即期望错误（§9.1） |

**测试断言要点**：同一事件内多帧 `sqNum` 按序列配置递增、`stNum` 恒定；不同事件（内容变化）`stNum` +1 且 `sqNum` 重置为 0。

### 4.3 test/ndsCom 置位

| 字段 | 置 1 含义 | 工程用法 |
|------|-----------|----------|
| test | 仿真/测试数据（非真实运行状态） | 调试期：`test:true` 发送，订阅方不据此操作 |
| ndsCom | need commissioning（需要整定/未投运） | 投运前：`ndsCom:true` 声明处于调试期 |

两者都在配置中显式设置（`test`、`nds_com` 布尔键），按 §3.4 每帧写出。测试断言 `goose.test == true`（若 tshark 有 goose 解析器）或 FrameAssert 字节 `87 01 01`（GoOSE APDU 内 test=true）。

---

## 5. 配置类型定义

### 5.1 GooseConfig 结构

核心配置类型（定义在 `trafficgen/internal/core/types.go`，与 SVConfig 并列）：

```go
// GooseConfig 描述一条 GOOSE（IEC 61850-8-1）事件流。
// L2 终结层：以太网直承 0x88B8，无 IP 层。
type GooseConfig struct {
    GocbRef   string        // gocbRef（GOOSE 控制块引用）：如 "simpleIOGenericIO/LLN0$GO$gcbAnalogValues"
    ConfRev   uint32        // confRev（配置版本）：数据集版本号，必须 >= 1
    DatSet    string        // datSet（数据集引用）：如 "simpleIOGenericIO/LLN0$AnalogValues"
    GoID      string        // goID（GOOSE 标识，可选）：缺省写 gocbRef 内容（§3.4）
    TALms     uint32        // timeAllowedToLive（存活时间 ms）：订阅方超时判丢
    StartStNum uint32       // 起始 stNum；等于 0xffffffff 时校验拒绝
    StartSQNum uint32       // 起始 sqNum；等于 0xffffffff 时校验拒绝
    APPID     uint16        // APPID（应用标识）：GOOSE 段 0x0000-0x3FFF，默认 0x1000
    Test      bool          // test（测试标志）：仿真帧置 1
    NdsCom    bool          // ndsCom（送修标志）：need commissioning 置 1
    DstMAC    string        // 组播目的 MAC：默认 01:0C:CD:01:02:03
    VlanEnabled bool        // 是否插 802.1Q VLAN 头
    VlanID    uint16        // VLAN ID（0-4095）
    VlanPriority uint8      // VLAN 优先级 PCP（0-7），典型 4
    Reserve1  uint16        // GOOSE 头 Reserve1：0（位 15 仿真位可置位）
    Reserve2  uint16        // GOOSE 头 Reserve2：0
    Data      []GooseDataEntry // 数据集成员（allData 顺序）
    // 帧序由有限 count 与 EventSeq 决定
    EventSeq  []GooseEvent  // 每个事件 = 内容变化一次，触发序号状态变化
}

// GooseDataEntry 描述一个数据集成员。Type 取 §3.8 支持矩阵的键。
type GooseDataEntry struct {
    Name  string      // 成员名（debug 用，不上线）
    Type  string      // "boolean"|"bit_string"|"int32"|"uint32"|"float32"|"octet_string"|"visible_string"|"binary_time"|"utc_time"
    Value interface{} // 成员值（按 Type 解码；bit_string 以 "bpairs:8,val" 形式）
}

// GooseEvent 描述一次数据集内容变化（触发 stNum+1、sqNum=0、有限重发）。
type GooseEvent struct {
    DataIdx int   // 数据索引（实现现状未按索引替换内容，仅驱动状态变化）
    DelayMs uint32 // 事件元数据（实现不做墙钟调度）
    Retransmits int // 事件爆发帧数减一：该事件产出 retransmits+1 帧（sqNum 0..retransmits）
    SqNumStep int // 必须为 0/1；>1 校验拒绝（sqNum 必须连续 +1）
}
```

**默认值语义**（工程默认，全部大端）：

| 字段 | 默认 | 依据 |
|------|------|------|
| GocbRef | `simpleIOGenericIO/LLN0$GO$gcbAnalogValues` | libiec61850 示例 |
| ConfRev | `1` | 初始配置版本 |
| DatSet | `simpleIOGenericIO/LLN0$AnalogValues` | libiec61850 示例 |
| TALms | `500` | 示例 TAL=500ms |
| APPID | `0x1000` | GOOSE 段默认 |
| DstMAC | `01:0c:cd:01:02:03` | 当前 GOOSE 生成器/cases 基线的组播目的 MAC |
| Data | （示例 1：int32 1234 + binary_time + int32 5678） | 对齐示例 |

### 5.2 层注册（L2 终结层）

GOOSE 层作为**终结层**注册进层链（Registry），与 SV 同策略：

```go
// internal/core/layers/registry.go
{
    Name:         "goose",
    Category:     layers.CategoryTerminal, // 终结层
    DependsOn:    nil,                     // GOOSE 直承 L2，不依赖 TCP/UDP/IP
    OptionalOn:   nil,
    InnerRequired: false,
    Fields:       gooseFieldDesc(),        // "goose.*" 字段描述
    Constraints:  gooseConstraints(),      // 见 §5.3/§8.2
}
```

- `DependsOn: ["eth"]` ＋ `CategoryTerminal` ⇒ 链 `[{"eth":{}},{"goose":{}}]` 有效；GOOSE 仍直承 L2，不自动补 IP/TCP/UDP。
- 若 Registry 目前对 L2 终结层的 Category 命名或约束与 SV 不同（如暂无 `CategoryTerminal`），则 §8.2 记录为**待实现决策**，实现时与 SV 对齐同一分类。
- 校验器（`Validate`）：`goose` 层出现时禁止同链含 `ip`/`tcp`/`udp` 层（R-GOOSE over UDP 不支持，§1.5）。

### 5.3 层链配置键与示例

`spec_json` 的 GOOSE 配置住 `layers[].goose`（不是顶层 `goose`）。示例（1 member + binary_time + error event，**无 IP**）：

```json
{
  "layers": [
    {"eth": {
      "src_mac": "aa:bb:cc:dd:ee:03",
      "dst_mac": "01:0c:cd:01:02:03"
    }},
    {"goose": {
      "gocb_ref": "simpleIOGenericIO/LLN0$GO$gcbAnalogValues",
      "conf_rev": 1,
      "dat_set": "simpleIOGenericIO/LLN0$AnalogValues",
      "tal_ms": 500,
      "appid": 4096,
      "test": false,
      "nds_com": false,
      "vlan_enabled": false,
      "data": [
        {"name": "pos",  "type": "int32", "value": 1234},
        {"name": "tm",   "type": "binary_time", "value": ""},
        {"name": "rate", "type": "int32", "value": 5678}
      ],
      "event_seq": [
        {"data_idx": -1, "delay_ms": 100, "retransmits": 0},
        {"data_idx": 0,  "delay_ms": 300, "retransmits": 5}
      ]
    }}
  ],
  "flow_control": {"flows": 1}
}
```

**层字段解析**：层链 translator 将 `layers[].eth` 的 `src_mac`/`dst_mac` 与 `layers[].goose` 的业务字段映射为 `GooseConfig`（目的 MAC 属于 Ethernet 层）；配置零负载由 validator 按必填规则拒绝，不走顶层 flat 兼容路径。

**最小配置**：空 GOOSE 层 `{"goose":{}}` 仍被 validator 拒绝（gocb_ref/dat_set/data 必填），参见 `goose_vn_empty_layer`。测试用心跳流可用 `goose_heartbeat` 形状。

**Static vs EventSeq**：
- `EventSeq` 缺省 → 纯心跳流：每帧 sqNum 递增、stNum 恒同——覆盖"静默心跳"用例。
- `EventSeq` 非空 → 按事件序列产出：每个事件触发 stNum+1、sqNum=0，并产出 retransmits+1 帧——覆盖"快速重发序列"与"数据集变化"用例。

---

## 6. 包序列场景（HexDump S1-Sn）

以下每个场景（S1-Sn）是 testcase 文档对应用例的**字节级模板**（完整断言见 `testcase.md`）。所有场景帧均为以太网直承（无 IP，EtherType 0x88B8；无 VLAN 时 APDU 从偏移 22 起）。数据集示例（对齐 libiec61850 示例）：

```
成员 1：int32  pos  = 1234 （0x04D2，最小编码 2 字节）
成员 2：binary_time tm = 6 字节当前时间（运行期动态）
成员 3：int32  rate = 5678 （0x162E，最小编码 2 字节）
```

心跳首帧（gocbRef "simpleIOGenericIO/LLN0$GO$gcbAnalogValues"、datSet "simpleIOGenericIO/LLN0$AnalogValues"）关键字段（§3.1 偏移，**APDU 内容 173 > 127，goosePdu 用 BER 长形式 3 字节 `61 81 <L>`**）：
`0x22 61 81 <L>` → `0x25 80 <L> gocbRef` → `81 02 01 f4 TAL` → `82 <L> datSet` → `83 <L> goID` → `84 08 t(8B)` → `85 01 01 stNum` → `86 01 01 sqNum` → `87 01 00 test` → `88 01 01 confRev` → `89 01 00 ndsCom` → `8a 01 03 num` → `ab <L> 成员...`。

### 6.1 S1：静默心跳流（stNum 恒同、sqNum 递增）

**场景**：无 `event_seq`，`count=3`，数据集 3 成员，stNum 起始 1、sqNum 起始 1，连续 3 帧（sqNum = 1, 2, 3；stNum 恒 1）。t 字段为运行期墙钟。

```
偏移   字节                                         说明
0      01 0c cd 01 02 03                        目的 MAC（组播 GOOSE 段）
6      aa bb cc dd ee 03                        源 MAC（src_mac）
12     88 b8                                    EtherType = 0x88B8
14     10 00                                    APPID = 0x1000
16     <LEN hi><LEN lo>                         Length = 8 + APDU 长（从 APPID 起）
18     00 00                                    Reserve1
20     00 00                                    Reserve2
22     61 81 AD                                  goosePdu [APPLICATION 1] 长形式，内容长 = 173（0xAD；>127 必须长形式）
25        80 23 <gocbRef 字符串>                  gocbRef "simpleIOGenericIO/LLN0$GO$gcbAnalogValues"（0x23=35B）
          81 02 01 f4                             timeAllowedToLive = 500（最小编码 2 字节）
          82 23 <datSet 字符串>                   datSet "simpleIOGenericIO/LLN0$AnalogValues"（0x23=35B）
          83 23 <同 gocbRef>                      goID（缺省 = gocbRef 内容）
          84 08 <8 字节 CP 时间>                  t（运行期墙钟）
          85 01 01                                stNum = 1（最小编码）
          86 01 01                                sqNum = 1（帧 2 = 2，帧 3 = 3）
          87 01 00                               test = false
          88 01 01                                confRev = 1（最小编码）
          89 01 00                               ndsCom = false
          8a 01 03                               numDatSetEntries = 3
          ab <L3>                                allData，内容长 L3
             85 02 04 d2                         pos int32 = 1234
             8c 06 <6 字节二进制时间>            tm binary_time
             85 02 16 2e                         rate int32 = 5678
```

**断言要点**（T-GSE-S1-01）：
- 三帧 stNum 恒 `1`、sqNum = `1,2,3`（单调递增）；帧间差异仅 sqNum 与 t
- EtherType 0x88B8、APPID 0x1000、`frame.protocols` 含 eth 不含 ip
- APDU 首字节 0x61；BER 标签按 §2.5 表逐字节核对（FrameAssert offset 22 起）

### 6.2 S2：快速重发序列 + 数据集变化（stNum+1、sqNum 重置 0）

**场景**：`event_seq` 含一次内容变化，`retransmits:5`，`count:8`。实现只按有限帧数生成，不承诺 TMax/t0 间隔。帧序：

```
#, 内容,           stNum, sqNum, 说明
1  [1234,tm,5678]   1     1       心跳帧（变化前）
2  [5678,tm,5678]   2     0       事件首帧：pos 变化 → stNum+1、sqNum=0（重置为 0！）
3  [5678,tm,5678]   2     1       重发 1
4  [5678,tm,5678]   2     2       重发 2
5  [5678,tm,5678]   2     3       重发 3
6  [5678,tm,5678]   2     4       重发 4
7  [5678,tm,5678]   2     5       重发 5
8  [5678,tm,5678]   2     6       count 补足帧
```

**断言要点**（T-GSE-S2-01 / T-GSE-S2-02）：
- 事件后首帧：stNum 1→2、sqNum = **0**（sqNum 由变化前的 1 重置为 0）
- 内容变化帧与后续重发帧**内容相同**（pos=5678）、stNum 恒 2、sqNum 从 0 单调 +1
- 变化前的第 1 帧 stNum=1、sqNum=1

### 6.3 S3：test 置位 / ndsCom 置位帧

**场景**：`test:true`（其余同 S1），一帧字节片段：

```
... 87 01 01 ...（test = true）
... 89 01 00 ...（ndsCom = false）
```

- 若 tshark 有 goose 解析器：`goose.test == true`；否则 FrameAssert 对应段 hex `87 01 01`
- `nds_com:true` 时：`89 01 01`

### 6.4 S4：VLAN 场景

**场景**：`vlan_enabled:true, vlan_id:100, vlan_priority:4`：

```
0     01 0c cd 01 02 03          dst
6     aa bb cc dd ee 03          src
12    81 00                       TPID（802.1Q）
14    80 64                       0x8000|0 | 0x064 = 0x8064 → TCI：priority=4、VID=100
16    88 b8                       EtherType GOOSE
18    10 00                       APPID ...（其后字段整体偏移 +4）
```

TCI 计算：priority(4)<<13 = 0x8000；DEI=0；VID=100=0x064 → TCI=0x8064。断言 `vlan.id==100`、`vlan.priority==4`、`frame.protocols` 含 vlan。

### 6.5 S5：多类型数据值（Boolean/Integer/Real/BitString/VisibleString）

**场景**：数据集同时含 boolean、uint32、float32、bit_string、visible_string（覆盖 §3.8 通用标量）。

```
ab 19                      allData 内容长 25（0x19；示例 5 成员实际和，§3.8）
   83 01 01                 boolean true
   86 02 0f a0              uint32 = 4000
   87 05 08 3f c0 00 00     floating_point FLOAT32 = 1.5（§3.7：长度 5 = 1 指数宽 + 4 尾数宽）
   84 02 00 fe              bit_string 8 位，unused=0、数据字节 fe（padding = 8−8 = 0）
   8a 05 48 65 6c 6c 6f     visible_string "Hello"
```

- **boolean**：`83 01 01`；**bit_string**：`84 <len> <unused><bytes>`（len = 1 + ceil(n/8)，unused = (byteSize×8) − bitLength）
- **floating_point**：`87 05` + 5 字节（1 指数宽 + 4 尾数宽，§3.7，**非 IEEE 754 裸 4 字节**）
- 断言 FrameAssert 逐成员 hex；tshark 若解析出 `goose.boolean/bit_string/floating_point/real` 也可断言

### 6.6 S6：无 IP 层证明

**场景**：任何一帧（如 S1 帧）剥离 L2 后**全帧没有 IP 头**。

- `frame.protocols` 只用于辅助观察：有 GOOSE 解析器时可能显示 `eth:goose`/`eth:vlan:goose`，无解析器时可能显示 `eth:data`；不能用固定字符串相等断言，核心证据是 EtherType `88 b8` + APDU 起点 `61`，且协议链不含 `ip`
- 帧第 0x0C-0x0D 字节是 `88 b8` 而不是 `08 00`/`86 dd`
- 无 20 字节 IPv4 头（首字节 0x45）、无端口号
- FrameAssert offset 12 hex `88 b8`、offset 22 起 hex `61`（APDU 首字节非 0x45）

### 6.7 S7：多数据集（numDatSetEntries > 1，且 > 3 扩展性）

**场景**：数据集 6 成员（numDatSetEntries = 6），涵盖 §3.8 全部通用标量类型，证明 numDatSetEntries 值正确且 allData 长度与条目数一致：

```
8a 01 06                     numDatSetEntries = 6
ab <L6>                      allData
   83 01 01                  boolean true
   85 02 00 96               int32 = 150
   86 02 27 10               uint32 = 10000
   87 05 08 ff ff ff ff         floating_point FLOAT32 = -2.5
   84 03 02 40 00            bit_string 16 位，unused=2、数据 0x4000
   8a 0b ...                 visible_string "GOOSE_TEST"（11 字符）
```

**断言要点**（T-GSE-S7-01）：
- `numDatSetEntries == 6` 且 allData 恰好包含 6 个成员 Data
- 各成员 tag 与值 hex 逐一对上（FrameAssert 从 0xAB 段起逐段 hex）
- 若无 tshark goose 解析器，仅用 FrameAssert 断言 `8a 01 06` 与 `ab` 段首字节

---

## 7. 与 testcase 文档的映射索引

`testcase.md` 的每个用例对应本文档的某个章节/场景，构成 spec→test 的可追溯链（Testing Policy 第 1 条：测试从规格驱动，非自组织）。

| testcase 用例 ID | 主题 | 本文档依据 | 场景/章节 | 关键断言 |
|------------------|------|-----------|-----------|----------|
| T-GSE-S1-01 | 静默心跳 3 帧（stNum 恒同 sqNum 递增） | §4.1/§6.1 | S1 | stNum=1 恒、sqNum=1/2/3；Length 精确 |
| T-GSE-S1-02 | 帧头字段（APPID/Length/Res1/Res2） | §2.4 | S1 | goose.appid=0x1000、Length、reserve=0 |
| T-GSE-S2-01 | 有限重发序列 | §4.1/§6.2 | S2 | 重发帧 content 恒同、stNum 恒 2、sqNum 0..5 |
| T-GSE-S2-02 | 数据集变化（stNum+1、sqNum 重置 0） | §4.4 | S2 | 事件首帧 sqNum=0、stNum 1→2 |
| T-GSE-S3-01 | test 置位帧 | §4.5/§6.3 | S3 | test=true 字节 `87 01 01` |
| T-GSE-S3-02 | ndsCom 置位帧 | §4.5/§6.3 | S3 | ndsCom=true 字节 `89 01 01` |
| T-GSE-S4-01 | VLAN 场景 | §2.2/§6.4 | S4 | vlan.id=100、priority=4、TCI 0x8064 |
| T-GSE-S5-01 | 多类型数据值 | §3.6/§3.7/§6.5 | S5 | boolean/int32/float32/bit_string 字节 |
| T-GSE-S6-01 | 无 IP 层证明 | §3.1/§6.6 | S6 | frame.protocols=eth:goose 不含 ip |
| T-GSE-S7-01 | 多数据集（6 成员） | §3.8/§6.7 | S7 | numDatSetEntries=6、allData 6 成员 |
| T-GSE-NEG-01 | AppID > 0x3FFF 负例 | §9.2 | §9 | expect_error "appid" |
| T-GSE-NEG-02 | sqNum 不连续负例 | §9.1 | §9 | expect_error "sqNum" |
| T-GSE-NEG-03 | stNum 回绕负例 | §9.1 | §9 | expect_error "stNum" |

**testcase 覆盖勾选清单**（`testcase.md` §7 逐项核对）：

- [x] 静默心跳：多帧 stNum 恒同、sqNum 递增（S1）
- [x] 快速重发序列：sqNum 递增 stNum 恒同（S2）
- [x] 数据集变化：stNum+1、sqNum 重置 0（S2-02）
- [x] test 置位（S3）、ndsCom 置位（S3-02）
- [x] confRev：恒等/变化（并入 S1/S2）
- [x] 数据值类型：Boolean/Integer/Real/FloatingPoint/BitString 各 >1（S5/S7）
- [x] 多数据集：numDatSetEntries>1（S7）
- [x] 无 IP 层证明：帧不含 IP 头（S6）
- [x] 负路径 expect_error：AppID>0x3FFF（NEG-01）、sqNum 不连续（NEG-02）、stNum 回绕（NEG-03）

**IPv4/IPv6 标注**：GOOSE 为 L2 直承协议，IPv4/IPv6 承载均标注 **N/A**（不支持 R-GOOSE over IP，§1.5）；以"帧不含 IP 头"证据用例（T-GSE-S6-01）替代。

---

## 8. 实现集成点

### 8.1 EtherType 常量（core/builder.go）

新增常量 `EtherTypeGOOSE = 0x88B8`（§2.3）。框架 builder 写 L2 帧头时按层区的 EtherType 字段输出（现有 `EtherTypeIPv4` 等模式）。

### 8.2 层注册 + 校验器（internal/core/layers）

- registry.go：注册 `goose` 终结层规格（§5.2）：`Name:"goose"`, `Category: CategoryTerminal`, `DependsOn: nil`。
  - **待实现决策**：若当前 registry 对 L2 终结层的分类命名与 SV 不一致（SV 采用 `CategoryTerminal`），实现时与 SV 对齐同一分类常量；链规约器 `complete.go` 对 Category 的校验（layers_test.go 已有 `CategoryTerminal` 用例）需同时覆盖 goose。这是本设计标注的**待实现点**，实现时确认。
- `Validate`（`internal/protocol/goose/validator.go`）：`goose` 层与 `ip`/`tcp`/`udp` 层共存即报错（R-GOOSE 不支持，§1.5）。
- 校验器应导出的 Go 实现位置：`trafficgen/internal/protocol/goose/validator.go`。

### 8.3 组播目的 MAC 覆盖（engine）

GOOSE 无 IP 层，目的 MAC 来自 `GooseConfig.DstMAC`（默认 01:0C:CD:01:02:03），**不经过链规划器的 IP-组播推导**（chain_planner 的 `finalEmit` 只对含 IP 层的包做多播覆盖）。GOOSE 层生成器直接在 `pkt.L2.DstMAC` 上写组播值；engine 若有"非组播目的 MAC 修正"逻辑，须对 GOOSE 禁用（GOOSE 恒组播，不退回单播）。与 SV/mdns 同款组播覆盖基础设施（Memory 记录 mDNS 的 OverrideDstIP/MAC + TTL 255 机制，GOOSE 无 IP 故只取 MAC 部分）。

### 8.4 有限帧生成（internal/protocol/goose/goose.go）

- 无 `event_seq`：按 `count` 生成心跳帧，stNum 不变、sqNum+1。
- 有 `event_seq`：先生成 1 个心跳帧，再按每个事件生成 `retransmits+1` 帧；事件首帧 stNum+1、sqNum=0，后续 sqNum+1。实现不创建定时器，不按 `delay_ms`、TMax 或 t0 调度。
- APDU 用类 `encodeGoosePdu(cfg, stNum, sqNum, dataBytes)` 的 BER 编码函数拼装（§2.5 表逐字段编码）。
- 取消路径（`req.Context`）与 SV/mdns 层生成器一致的排空清理（goleak 用例验证无泄漏）。

### 8.5 每帧时间戳

帧的 `t`（0x84，CP 8B：秒 4B + 分数秒 4B）打上**真实发送时刻**墙钟时间戳（非 Plan 覆写时间戳——与 mdns 层同坑：Memory "gap 断言陷阱：Plan 覆写 Timestamp→用 wall-clock"）。CP 8B 编码：前 4 字节 = 自 1970-01-01 00:00:00 起秒数（大端）；后 4 字节 = 分数秒，单位 2^-32 秒（0x80000000 = 0.5 秒）。实现按有限帧序生成；测试只断言帧序与字节，不断言墙钟间隔。

### 8.6 strategy_convert.go 分支

新增 `case "goose"`：只从 `spec.layers[].goose`（且前置 `eth` 层）翻译为 `GooseConfig`（§5.3）。字段校验在 `Validate(spec)` 完成（§9 全部负例），convert 只做无损字段映射；不接受顶层 `spec.goose`，也不接受 IP/TCP/UDP 承载；`config` 键允许不含 `data` 时按默认数据集（§5.1）生成。

### 8.7 registry 的 GOOSE/SV 分野

同一 COM 下 GOOSE 与 SV 均注册为终结层 L2 直承；`DependsOn: nil` 意味着 `[{"eth":{}}, ...]` 链不自动补 ip/tcp。两协议集成点的差异仅：EtherType 常量（0x88B8 vs 0x88BA）、BER 编码器（goosePdu vs savPdu）、组播 MAC 默认值（01:0C:CD:01 vs 01:0C:CD:04）、驱动方式（事件 vs 周期）。可抽公共 L2 组播基础（VLAN 写头、组播 MAC 校验、pad 最小帧），子任务按需（与 SV 文档 §8.7 相同的协同点）。

### 8.8 实现分层（从 Stdlib 到 pcap）

| 层 | 组件 | 职责 | 产出 |
|----|------|------|------|
| L1 | `internal/core/types.go` | `GooseConfig`/`GooseDataEntry`/`GooseEvent` 类型 | 结构定义 |
| L2 | `internal/protocol/goose/ber.go` | BER 原语：`encodeTL`/`encodeStringWithTag`/`encodeUInt32Fixed`/`encodeBoolean`/`encodeFloat`/`encodeBinaryTime` | 字节编解码函数 |
| L3 | `internal/protocol/goose/goose.go` | `Plan`/`emitGooseFrames` 按事件序列和有限帧数维护 stNum/sqNum | `<-chan PacketConfig` |
| L4 | `internal/protocol/goose/layer_gen.go` | `Generate(ctx, req)` → 组装以太网头 + GOOSE 头 + goosePdu 完整帧 | Packet 结构/字节 |
| L5 | `internal/protocol/goose/validator.go` | `Validate(spec)` → 全部 §9 校验 | error |

每层独立可测；pcap 用例做 L1-L5 端到端。

### 8.9 生成器伪码（有限帧序列）

实现入口为 `emitGooseFrames`：有限 `count` 内先发心跳，再按 `event_seq[].retransmits` 发事件帧，最后以递增 sqNum 补足。

### 8.10 测试矩阵（pcap 双覆盖）

| 关注点 | 单测（`goose_test.go`） | pcap 用例（goose.json） |
|--------|-------------------------|------------------------|
| BER 编码逐字节 | BuildPayload 对照 hex 模板 | T-GSE-S1-01 frames |
| stNum/sqNum 语义 | 帧序列断言（变化/心跳） | T-GSE-S1-01/S2-01 |
| 有限重发序列 | `emitGooseFrames` 帧序测试 | T-GSE-S2-01 |
| 校验负例 | 直接断言 error | T-GSE-NEG-01..15 |
| 数据值多类型 | 逐成员字节断言 | T-GSE-S5-01/S7-01 |
| 帧序列无泄漏 | 取消上下文后 channel 关闭 | — |

### 8.11 测试文件位置

| 文件 | 内容 |
|------|------|
| `trafficgen/internal/protocol/goose/goose_test.go` | BER 编码、stNum/sqNum 帧序、有限重发、数据值 |
| `trafficgen/internal/protocol/goose/validate_test.go` | 校验负例（§9 全部） |
| `trafficgen/test/protocol_pcap/cases/goose.json` | pcap 框架用例（与 `testcase.md` 对应） |

---

## 9. 错误处理

### 9.1 stNum/sqNum 非法序列

| 输入 | 期望行为 |
|------|----------|
| 事件变化后首帧 sqNum ≠ 0 | 拒绝/终止（sqNum 必须重置 0）——负例 T-GSE-NEG-02 |
| 同事件内 sqNum 不连续（跳号） | 拒绝/终止（序列异常）——负例 T-GSE-NEG-02 |
| stNum 回绕（0xFFFFFFFF → 0x00000000 或跳变） | 拒绝/终止（stNum 不回绕）——负例 T-GSE-NEG-03 |
`stNum`/`sqNum` 的非法上限由 validator 拒绝：`start_stnum` 或 `start_sqnum` 等于 `0xffffffff` 分别命中溢出错误。心跳期由有限 `count` 生成，不定义自然回绕。

### 9.2 APPID 越界

| 区间 | 判定 |
|------|------|
| 0x0000-0x3FFF | GOOSE 可用段，默认/推荐（默认 0x1000） |
| 0x4000-0xFFFF | 实现直接拒绝（负例 `goose_neg_appid` 配置 0x4000，断言 `outside GOOSE range 0x0000-0x3fff`） |

（实现校验范围固定为 `0x0000-0x3FFF`；任何大于 `0x3FFF` 的 APPID 都走同一拒绝路径。）

### 9.3 confRev < 1

`confRev`（配置版本）必须 **≥1**（0 表示未定义版本，IED 不使用）。`conf_rev: 0` → 校验失败，任务 fail（负例并入 NEG 表；testcase 用 `goose_neg_confrev` 断言 error_contains "confRev"）。

### 9.4 Length / APDU 长度不匹配

框架生成的包必须满足 `GOOSE 头 Length == 8 + len(APDU)`。若内部编码器算出不符（如数据成员编码尺寸与声明不符），在 send 前报错。**校验公式**：无 VLAN 帧长 - 14 − 8 = APDU 长；VLAN 帧长 - 18 − 8 = APDU 长。

### 9.5 数据集条目数不符

`numDatSetEntries` 实际编码 ≠ allData 内成员个数 → 拒绝（防静默错位：订阅方按条目数解析 allData，数目不符直接解析错位）。

### 9.6 TAL 字段校验

`tal_ms` 必须在 `1..4294967295`；实现不接受空值或 0。生成器按有限 `count` 产生帧，不承诺运行时 TMax/t0 退避调度或 clamp 语义。

### 9.7 通用错误模型

| 错误分类 | 表现 | 位置 |
|----------|------|------|
| 配置校验错误 | 任务 Create/Start 拒绝 | goose validator (§8.2) |
| 帧编码错误 | plan/generate 返回 error；任务 fail | goose layer_gen / builder |
| 数据成员类型不支持 | Validate 拒绝（§3.8 矩阵外） | goose validator |

---

## 10. 扩展字段映射

以下为未来的 GOOSE 扩展字段与其 Metadata 映射（当前未实现，`Metadata` 键为规划中的字段名约定；首见英文加（中文解释））。

| Metadata 键 | 类型 | 语义 | 对应 BER 字段 |
|-------------|------|------|---------------|
| `goose_stnum_override` | uint32 | stNum 起始覆盖（多 IED 合并场景） | APDU 0x85 |
| `goose_confrev_change` | uint32 | 重配置场景 confRev 动态 +1 | APDU 0x88 |
| `goose_goid` | string | goID 显式值（缺省 = gocbRef） | APDU 0x83 |
| `goose_t_precision` | string | CP 8B 分数秒精度覆盖（默认 2^-32） | APDU 0x84 |
| `goose_ndscom_flip` | bool | 事件内 ndsCom 翻转（投运切换） | APDU 0x89 |
| `goose_array_type` | string | 高级数据集：ARRAY（0xA1）/STRUCTURE（0xA2）嵌套 | allData 成员 |
| `goose_fc_name` | string | 结构体成员 FC（功能约束）名字段 | STRUCTURE 成员 |
| `goose_override_dst_mac` | string | 自定义组播 MAC（覆盖默认） | 以太网头 |

**为什么这些以 Metadata 而非配置字段暴露**：它们大多是一次性/动态语义（如 confRev 变化的两阶段、stNum 覆盖、FC 名注入），不适合放静态 `GooseConfig`；通过 Metadata 可让包级生成器在运行期注入，而 `GooseConfig` 保持业务语义纯净（同 SV 文档 §10）。

### 10.1 扩展关键词的实现前置与互操作约定

| 扩展 | 状态 | v1 前置条件 / 互操作约束 |
|------|------|--------------------------|
| `goose_stnum_override` | 立即支持（廉价） | 生成器起始 stNum 读配置而非硬 1；订阅方只认相对递增，对互操作无影响 |
| `goose_confrev_change` | 立即支持 | 两阶段任务（reconfigure）→ confRev+1、stNum 不重置；tshark `goose.confRev` 可观测 |
| `goose_t_precision` | 待条件 | 需 wall-clock 发送时刻精度（现只有帧发送时刻）；工程上 IED 多忽略分数秒，v1 用 2^-32 全零尾部 |
| `goose_array_type`/`goose_fc_name` | 待条件 | 需要 MMS STRUCTURE/ARRAY 嵌套编码（0xA1/0xA2）与带 FC 名成员；前置 BER 层扩展 |
| `goose_ndscom_flip` | 待条件 | 需事件内字段翻转注入（现为静态配置） |
| `goose_override_dst_mac` | 立即支持 | 组播覆盖机制对 GOOSE 禁用 IP 推导（§8.3），用户显式写组播即可 |

**互操作拒收清单**（NEVER，明确不实现）：
- R-GOOSE over UDP/IP（validate 拒绝，§1.5/§8.2）
- GOOSE 单播目的 MAC（除非用户显式覆盖且接受非标准）
- IEC 62351 安全（签名/AEAD 加密改造，破坏裸 BER 可解析性，§1.5）
- APDU "security"（0x88）之类的杜撰字段——本设计按 IEC 61850-8-1 仅实现 0x80-0x8A + 0xAB（§2.5 差异记录）
- 帧头外的额外包装（无 TPKT 会话层等）

**向下兼容基线**：所有 v1.0 配置产物均可被 libiec61850 与 Wireshark 完整解码（逐字节一致性见 §2.5/§3.6）；扩展字段默认**不编码**（BER 省略），从不断言"必须存在"——除非测试显式指定。

---

## 11. P-PIPE 文档轨契约（D1–D8）

### 11.1 D1：规范要求→业务场景→代码现状→缺口矩阵

| 规范要求 | 业务场景 | 代码现状 | 结论/缺口 |
|---|---|---|---|
| IEC 61850-8-1：GOOSE 是 Ethernet L2 组播，EtherType 0x88B8，无 IP | 静默心跳、事件重发、VLAN | `internal/protocol/goose/goose.go` 生成 Ethernet + GOOSE 头/APDU；`Validate` 拒绝 IP/传输字段 | 已实现；R-GOOSE 不在本版 |
| APPID 0x0000–0x3FFF，Length 从 APPID 起计 | 普通帧、VLAN 帧 | `Validate` 校验 APPID；builder 计算 BER/APDU 长度 | 已实现；每个 pcap case 用 FrameAssert 钉字节 |
| APDU 字段顺序与 BER 最小整数编码 | 多类型数据集 | `BuildPayload` 与 `uintVal`/`intVal`/`tlv` 实现 | 已实现；array/structure 未实现并由校验拒绝 |
| stNum 变化递增，事件首帧 sqNum=0；同状态 sqNum 递增 | 数据集变化、快速重发、心跳 | `emitGooseFrames` 维护状态；Validate 拒绝上限和跳步配置 | 已实现；超长状态序列仍由上限校验保护 |
| test/ndsCom、confRev、numDatSetEntries 与 allData 一致 | 标志、多成员数据集 | 配置字段写入 APDU；成员数由 `len(Data)` 编码 | 已实现；动态 confRev/ndsCom 未提供 |
| 时间戳为运行期值 | 全部正例 | `BuildPayload` 写当前时间 | 已实现；测试只断言 tag+length |
| VLAN PCP 0–7、VID 0–4095 | VLAN 场景 | `Validate` 校验层/配置 VLAN 范围 | 已实现；VLAN wire 由公共 Ethernet builder 负责 |
| 配置失败必须传到任务失败，不得静默 0 包 | 全部负例 | `Validate` 返回 error；pcap cases 用 `expect_error` + `error_contains` | 已覆盖；NIC 运行验收待 P5 |

### 11.2 D2：命令/响应与数据形态子表

GOOSE 无请求/响应命令表；一个发布帧是唯一消息形态。当前状态形态为：有限心跳、事件首帧、事件重发、test、ndsCom、VLAN、无 VLAN。数据成员形态为 boolean、bit_string、int32/int64、uint32/uint64、float32、octet_string、visible_string、binary_time、utc_time；array/structure 当前明确不支持并由负例 `goose_neg_type` 覆盖。

### 11.3 D3：三路对照与候选方案

规范依据为 IEC 61850-8-1；开源实现对照为 libiec61850 的 GOOSE publisher/BER encoder；解析行为对照为 Wireshark `packet-goose.c`。商业 IED 线字节样本未在本工作树取得，不能冒充已确认，登记缺口 G-GOOSE-1（补法：取得厂商 IED pcap 后逐字段对照）。候选方案：A，复用公共 Ethernet/VLAN builder、GOOSE 自有 BER/APDU（采用，边界清晰）；B，把 GOOSE 当 UDP/IP 业务层（否决，违反 L2 规范）；C，复用 SV APDU 编码器（否决，字段和状态机不同）。

### 11.4 D4：性能设计与双路径验收

生成器按帧流式发送，不聚合全部帧；队列和缓冲上限由通用 engine 控制。验收维度为：基线 3 帧、33 cases 全量、并发多策略、长时间心跳、快速重发突发、缓冲背压六类；断言包数、字节长度、字段序列、错误传播、内存/队列积压。吞吐、CPU、NIC 丢包数字尚未基准，登记 G-GOOSE-2；pcap 可执行，真实网卡需 P5 tcpdump 实测。

### 11.5 D5：接口、数据结构与主流程

实现入口为 `Planner.Validate(spec)`、`Planner.Plan(ctx,spec)`、`BuildPayload(*core.GOOSEConfig, st, sq)`；数据结构为 `GooseConfig`、`GooseDataEntry`、`GooseEvent`。主流程是层链校验 → GOOSE planner → 状态序列 → BER APDU → Ethernet/VLAN 封装 → pcap/NIC 输出。失败在 Validate/编码阶段返回 task error；ctx 取消关闭输出 channel。

### 11.6 D6：动态字段清单

GOOSE 业务字段默认固定：gocbRef、datSet、goID、confRev、TAL、APPID、VLAN、`test`、`ndsCom`、Data。目的 MAC 是 `layers[].eth.dst_mac` 的 L2 字段，当前按层内 fixed；`t` 由发送时刻生成，不是策略动态值。`flow_control.flows` 负责流数量，协议层 `count`（存在于现有 case 的 goose 层配置）只表达该流的帧预算，不替代任务流数量；后续收敛协议帧预算字段登记 G-GOOSE-3。

### 11.7 D7：实现冲突、错误边界与回滚

冲突点：旧设计 §5.3 曾展示顶层 `src_mac`/`goose`，与层链唯一真相冲突；本版已改为 `layers[].eth` + `layers[].goose`。现有 cases 的 `[eth,goose]` 是合法 L2 终结链；`goose_neg_ip_carrier` 是故意判死形，不是残留。错误边界覆盖空数据、空引用、超长引用、非法类型、APPID/TAL/confRev/VLAN/序号上限和 IP 载体。回滚仅恢复本文件、testcase.md、goose.json；不涉及代码。

### 11.8 D8：门1与缺口立项

门1结论：正例顶层非结构键为 0；正例链均为 `[eth, goose]`；负例中的顶层 `goose` presence、IP carrier 等均为明确判死对象；地址/MAC/业务字段均住层内；数量新增应走 `flow_control`。未确认项不得写成完成：G-GOOSE-1（商业 IED 对照）、G-GOOSE-2（性能/NIC 基准）、G-GOOSE-3（协议帧预算字段与 flow_control 的最终收敛）。

## 13. P-PIPE 补齐附录（D1–D8，2026-10-01）

### 13.1 D1 P1 规范矩阵（八项）

| 规范要求 | 业务场景 | 代码现状 | 缺口/结论 |
|---|---|---|---|
| 连接模型：L2 无连接组播 | 心跳、事件、重发 | `goose.go` 直接产出以太网帧 | 已覆盖；无会话握手 |
| 命令/消息表：GOOSE 无请求响应 | 单帧 APDU 发布 | `BuildPayload` 编码 goosePdu | 已覆盖；命令响应不适用 |
| 状态机：状态变化与重发序号 | event_seq、心跳 | `emitGooseFrames` | 已覆盖；异常序号由校验拒绝 |
| 字段表：BER tag/长度/大端 | 多类型 allData | `ber.go`/builder | 已覆盖；array/structure 尚未接线，G-GOOSE-4 |
| 错误处理：非法范围/承载/字段 | 15 条负例 | schema/validator 返回错误 | 已覆盖；错误锚词逐例核对 |
| 超时与活性：TAL 语义 | TAL 边界与心跳 | 有限 count，无墙钟调度 | TAL 编码已覆盖；实时退避 G-GOOSE-2 |
| NAT/代理/被动模式 | L2 交换组播 | 无 IP/NAT 路径 | 不适用；GOOSE 不经 IP |
| 版本/方言：IEC 61850-8-1 | 标准 BER、VLAN、test | GOOSE v1 字段集合 | 商业 IED 互操作样本 G-GOOSE-1 |

#### 命令×响应码矩阵

| 消息/状态 | 成功 | 非法输入 | 覆盖 |
|---|---|---|---|
| 心跳发布 | 帧序输出 | 空 data/ref/TAL 拒绝 | `goose_heartbeat`, `goose_neg_no_data`, `goose_neg_gocbref`, `goose_neg_tal` |
| 事件首帧 | stNum+1、sqNum=0 | stNum 溢出拒绝 | `goose_dataset_change`, `goose_neg_stnum` |
| 事件重发 | sqNum 连续 | step>1/上限拒绝 | `goose_retransmit`, `goose_neg_sqnum`, `goose_neg_sqnum_max` |
| 帧编码 | EtherType/APDU 合法 | APPID/VLAN/类型拒绝 | `goose_vlan`, `goose_neg_appid`, `goose_neg_vlan`, `goose_neg_type` |

#### 数据形态变体表

| 形态 | 正例 | 失败边界 |
|---|---|---|
| 无 VLAN/VLAN | `goose_no_ip`, `goose_vlan` | VID/PCP 越界：`goose_neg_vlan` |
| 心跳/事件/多事件 | `goose_heartbeat`, `goose_retransmit`, `goose_combo_event` | 序号跳步/溢出负例 |
| 标量 allData | `goose_multitype`, `goose_int64`, `goose_uint64` | 非支持类型：`goose_neg_type` |
| 字符串/八位组/时间 | `goose_goid`, `goose_octet_string`, `goose_utc_time` | 引用超长：`goose_neg_str255` |
| 合法 L2 链/非法承载链 | 32 例层链 | `goose_neg_ip_carrier` |

#### 商业行为→用例映射表

| 现网行为 | 来源/确认方式 | 用例 | 结论 |
|---|---|---|---|
| 继电保护事件以组播帧发布 | IEC 61850-8-1；厂商抓包待补 | `goose_dataset_change` | 标准行为已实现，厂商差异 G-GOOSE-1 |
| 事件首帧 sqNum=0，随后递增 | libiec61850 publisher + Wireshark dissector | `goose_retransmit`, `goose_dataset_change` | 已覆盖 |
| VLAN PCP 常用 4 | IEC 61850-8-1/802.1Q；厂商抓包待补 | `goose_vlan` | 已覆盖，厂商样本待补 |

### 13.2 D2 三路对照与候选方案

| 路径 | 依据 | 采用结论 |
|---|---|---|
| 规范原文 | IEC 61850-8-1，GOOSE Ethernet 映射与 APDU 字段 | L2、0x88B8、BER 字段为底线 |
| 商业软件/IED | 厂商线包尚未入库；确认方式：取得 IED pcap 后逐 tag/长度比对 | G-GOOSE-1，不伪造完成 |
| 开源实现 | libiec61850 publisher 与 Wireshark `packet-goose.c` | BER/序号实现参照 |

| 真实方案 | 优势 | 代价 | 选择 |
|---|---|---|---|
| A：公共 Ethernet/VLAN + GOOSE 自有 BER | L2 边界清楚，复用少量公共封装 | 需维护 BER 编码 | 采用 |
| B：复用 SV 封装并替换 APDU | 代码复用高 | 字段/序号模型不同，易串协议 | 不采用 |
| C：UDP/IP 承载 | 可复用传输管线 | 违反 IEC 61850-8-1 GOOSE L2 形态 | 不采用 |

### 13.3 D3 依赖与错误处理

依赖顺序为 `eth` 层→`goose` 层→BER 编码→输出；GOOSE 层必须是终结层且不得存在 IP/TCP/UDP。缺 eth、空引用、空 data、非法类型、范围越界时，策略创建/启动返回 validator 错误，任务中断，不重试；编码错误同样使任务失败。有限帧生成仅受 `count`/`event_seq` 控制，`delay_ms` 不触发睡眠；不承诺墙钟超时。上下文取消关闭输出 channel 并释放队列。

### 13.4 D4 性能设计与双路验收

路径是流式逐帧生成，不收集全量帧；预算为每帧 O(1) 临时编码内存、受通用有界队列/缓冲限制，CPU 并行度由 engine worker 配置。必须测基线、目标规模、压力上限、长时间心跳、并发交错、背压六类，并断言包/比特吞吐、延迟、内存、CPU、队列积压、失败与丢包；无实测数字登记 G-GOOSE-2。pcap 路：逐例落盘后用 tshark/FrameAssert 核对 EtherType、Length、BER、序列和包数。网卡路：port_group 发包并 tcpdump，核对帧数、0x88b8、目标组播 MAC、VLAN、序列、丢包与 CPU/队列；两路都不能只看任务成功。

### 13.5 D5 八要素

| 要素 | 定义 |
|---|---|
| 文件 | `internal/core/types.go`、`internal/protocol/goose/{goose.go,ber.go}`、layers/strategy convert；产物 `goose.json` |
| 接口 | `Validate(spec)`、`Plan(ctx,spec)`、`BuildPayload(*GOOSEConfig,st,sq)` |
| 结构 | `GOOSEConfig`、`GooseDataEntry`、`GooseEvent`；`[eth,goose]` |
| 流程 | 校验→规划→BER→Ethernet/VLAN→pcap/NIC |
| 错误 | validator/编码错误返回 task failure；取消关闭 channel |
| 性能边界 | 流式、有界队列；六类性能场景 |
| 冲突点 | 禁止顶层 `goose`、IP/TCP/UDP carrier；GOOSE 不复用 SV APDU |
| 回滚 | 仅回退本协议设计、用例文档和 cases 文件；不动共享代码 |

### 13.6 D6 动态字段清单与序号算法

GOOSE 不存在四元组：`src_ip`、`dst_ip`、`src_port`、`dst_port` 均不适用；源/目的 MAC 是 L2 字段，分别位于 `layers[].eth.src_mac`/`layers[].eth.dst_mac`，当前按层内 fixed。业务字段 `gocb_ref`、`dat_set`、`go_id`、`conf_rev`、`tal_ms`、`appid`、VLAN、`test`、`nds_com`、Data 均按当前代码 fixed；`t` 由发送时刻生成，不是策略动态值。`event_seq` 是唯一序列算法：`emitGooseFrames`（`trafficgen/internal/protocol/goose/goose.go:494`）以事件索引推进 `stNum`，事件首帧 `sqNum=0`，同事件按 `sqNum_step` 递增；心跳按帧序递增。`flow_control.flows` 决定流数量，不能改变 L2 业务字段；多流静态 MAC 在 schema 触发 static-copy 拒绝。动态业务字段与跨流序号算法列为 G-GOOSE-3，不能宣称已支持。

### 13.7 D7/D8 门1三行展开

| 门1行 | 逐项对照 |
|---|---|
| §1 旧键去向 | `src_ip/dst_ip/src_port/dst_port` 不适用且删除；源/目的 MAC 进入 `layers[].eth`；业务进入 `layers[].goose`；数量进入 `flow_control`。完整形状见 §5.3。故意 presence 负例 `goose_vn_presence` 只验证拒绝。 |
| §3 五件套 | 会话表：无连接组播；事务序列：心跳/事件首帧/重发；关联关系：无控制/数据流关联；插入位置：事件列表按顺序插入有限帧；时间线：生成顺序，不按 `delay_ms` 睡眠。 |
| §12 清单 | 四元组不适用；MAC/业务字段逐项 fixed（`t` 为发送时刻）；序号算法在 `goose.go:494`；需动态业务字段时立项 G-GOOSE-3。 |

D8 结论：33 例中 18 正、15 负；正例层链均为 `[eth,goose]`，负例保留一条故意 `[ip,goose]` carrier 和一条顶层 `goose` presence。无开放字段留白；array/structure、厂商行为、性能实测均有编号立项。

---


| 版本 | 日期 | 内容 |
|------|------|------|
| v1.0.0 | 2026-08-18 | 初稿：完整 11 章；BER 编码以 libiec61850/Wireshark 权威核实；修正任务提示中 GOOSEPDU 标签表（§2.5 差异记录：真实顺序 gocbRef=0x80/TAL=0x81/datSet=0x82/goID=0x83/t=0x84/stNum=0x85/sqNum=0x86/test=0x87/confRev=0x88/ndsCom=0x89/numDatSetEntries=0x8A/allData=0xAB；无 0x88 security、CP8B 为 t=0x84 非 0x89/0x8A）；HexDump S1-S7 逐字节核算（§6）；快速重发/数据集变化/静默心跳状态机（§4）；L2 终结层配置与 Typedef（§5）；映射索引（§7）；实现集成点（§8）；错误处理（§9）；扩展字段（§10） |

> **已核实来源清单**：IEC 61850-8-1 规范（GOOSE 报文/APPID/组播 MAC/CP 时间），libiec61850 参考实现（`src/goose/goose_publisher.c`、`src/mms/iso_mms/server/mms_access_result.c`、`src/mms/asn1/ber_encoder.c`、`examples/goose_publisher/goose_publisher_example.c`），Wireshark GOOSE 解析器（`epan/dissectors/packet-goose.c` 及 dfref 字段表：`goose.gocbRef`/`goose.timeAllowedtoLive`/`goose.datSet`/`goose.goID`/`goose.t`/`goose.stNum`/`goose.sqNum`/`goose.simulation(test)`/`goose.confRev`/`goose.ndsCom`/`goose.numDatSetEntries`/`goose.allData`，数据值 `goose.boolean`/`goose.bit_string`/`goose.integer`/`goose.unsigned`/`goose.floating_point`/`goose.real`）。全文核心字节事实（段位、tag、Length 口径、MMS Data 内部 tag、有限重发、CP 8B）均源自上述实现，而非转录未经验证的二手资料。
