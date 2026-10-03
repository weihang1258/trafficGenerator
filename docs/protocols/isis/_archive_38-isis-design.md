# ISIS（中间系统到中间系统，IS-IS）设计文档

> 版本：v1.0.1（设计阶段）
> 日期：2026-08-20
> 状态：仅设计与用例契约；`isis` 层尚未实现，不宣称 MCP（模型上下文协议）套件可以运行。
> 配套文件：`docs/protocol-designs/38-isis-testcase.md`、`trafficgen/test/protocol_pcap/cases/isis.json`、`docs/protocol-designs/audit/38-isis-adversarial-audit.md`
> 规范基线：ISO 10589；以太网承载参考 ISO 10589/ISO 8802-2 LLC（逻辑链路控制）和 IANA EtherType 0x8870。

## 1. 范围、证据等级与版本边界

本版定义 ISO 10589 的 LAN IS-IS（Intermediate System to Intermediate System，中间系统到中间系统）基础 PDU（协议数据单元）：Level-1/Level-2 LAN IIH（IS-IS Hello，Hello 报文）、LSP（Link State PDU，链路状态报文）、CSNP（Complete Sequence Numbers PDU，完整序列号报文）和 PSNP（Partial Sequence Numbers PDU，部分序列号报文）。协议直接承载在以太网二层，不经过 IPv4、IPv6、TCP 或 UDP。

本版定义两个相互独立的 wire profile（线格式档案）：

| profile | 二层承载 | PDU 起点（无 VLAN） | 适用边界 |
|---|---|---:|---|
| `iso10589_llc` | IEEE 802.3 length 字段 + LLC `FE FE 03` + NLPID `83` | offset 17（以太网 14 + LLC 3） | ISO 10589/ISO 8802-2 LLC 载体 |
| `iso10589_ethertype` | EtherType `0x8870`，PDU 直接跟随以太网头 | offset 14 | EtherType 0x8870 载体 |

LLC profile 中，802.3 length 是 length 字段之后的整个 802.3 payload：LLC 3 字节、IS-IS PDU 和为达到 Ethernet 最小 payload 所需的 padding；它不是 EtherType。EtherType profile 中 0x8870 是二层解复用值，不能同时再放 LLC `FE FE 03`。无 VLAN 时，帧前 14 字节是 Ethernet（以太网）头；VLAN 会把 PDU 起点分别推进 4 字节，但本版正例固定无 VLAN，VLAN 只作为后续扩展边界。

本版不编造厂商 TLV（Type-Length-Value，类型-长度-值）或私有扩展。允许的 TLV profile 只使用 ISO 10589、RFC 1195、RFC 5305/RFC 5308 等标准定义的明确类型：Area Addresses（TLV 1）、LSP Entries（TLV 9）、IP Interface Addresses（TLV 132）、IPv6 Interface Addresses（TLV 232）和 IPv6 Reachability（TLV 236）。TLV 22/128/129/135/137 等其他标准类型须以独立字段表和用例加入，未知/厂商 TLV 不得静默解释。

IPv4 与 IPv6 仅作为 TLV 地址族 profile，不改变 IS-IS 的二层载体：`ipv4_basic` 使用 IPv4 Interface Address TLV 132；`ipv6_basic` 使用已定义字段的 IPv6 Interface Address TLV 232；TLV 236 只有在完整字段 fixture 可用时才启用。这里的 IPv4/IPv6 不是 IP 外层，帧仍不含 IP header（头部）。

## 2. 不变式与配置

1. IS-IS PDU 必须直接位于 Ethernet/LLC 或 EtherType 0x8870 后；UDP/TCP/IP 外层、缺失二层载体或 LLC 与 EtherType 混用必须拒绝。
2. Common Header（公共头）固定 8 字节：NLPID=0x83、Header Length=8、Version/Protocol ID Extension=1、ID Length=6、PDU Type、Version=1、Reserved=0、Max Area Addresses。
3. System ID（系统 ID）为 6 字节，按 `xxxx.xxxx.xxxx` 或 6-byte hex 解释；Area Address（区域地址）由 TLV 1 显式携带，不从 System ID、MAC 或目的组播 MAC 猜测。
4. PDU Length 是从 PDU 起点到最后一个非填充 PDU 字节的长度，包含 Common Header 和本 PDU 固定字段/TLV，不包含 Ethernet、LLC 头或以太网最小帧填充；按最终编码字节数以网络字节序回填。
5. LSP 的 Checksum（校验和）是 ISO 10589 Fletcher-16 字段，按规范覆盖 LSP（排除 Remaining Lifetime 的指定计算位置）；`checksum_mode=auto` 必须在长度、LSP ID、序列号和 TLV 完成后计算。IIH/CSNP/PSNP 不把 LSP checksum 规则错误套用。
6. 每个 IIH/LSP/CSNP/PSNP event（事件）只生成一个原子 PDU；planner（规划器）不得隐式补发邻居响应、LSP 或 SNP。
7. Level-1 和 Level-2 由 PDU type/circuit type/profile 显式指定。L1 LAN IIH type=15、L2 LAN IIH type=16；L1 LSP type=18、L2 LSP type=20；L1 CSNP type=24、L2 CSNP type=25；L1 PSNP type=26、L2 PSNP type=27。
8. 邻接状态是会话可观察的事件标注，不是额外 wire 字段。静态事件可从 `Down → Initializing → Up`（以及实现约定的 `Up`/保持）标注，但不得将状态名编码到 PDU。
9. planner/validator（校验器）错误必须传播为 task error（任务错误）终态，不能完成但 0 包或输出损坏 PCAP（抓包文件）。
10. Ethernet destination MAC（目的 MAC）默认与 Level 对应：L1 `01:80:c2:00:00:14`、L2 `01:80:c2:00:00:15`；它是链路承载选择的可观察值，不是 Area/System ID。

推荐配置：

```json
{
  "layers": [{"eth": {}}, {"isis": {}}],
  "src_mac": "02:00:00:00:10:01",
  "isis": {
    "wire_profile": "iso10589_llc",
    "level": "l1",
    "pdu_type": "lan_hello",
    "system_id": "0102.0304.0506",
    "area_addresses": ["49.0001"],
    "tlvs": []
  }
}
```

| 键 | 类型/约束 | 语义 |
|---|---|---|
| `wire_profile` | `iso10589_llc` 或 `iso10589_ethertype` | 二层承载，不写进 PDU |
| `level` | `l1` 或 `l2` | 邻接/数据库层级 |
| `pdu_type` | `lan_hello`、`lsp`、`csnp`、`psnp` | PDU 语义；PDU type 由 level 推导 |
| `system_id` | 6 字节 | Source ID、LSP ID 和 SNP Source ID 的显式身份 |
| `area_addresses` | 3–13 字节地址数组 | 编码为标准 TLV 1；与 `tlvs` 中 type=1 互斥，不从 IP/MAC 派生 |
| `tlvs` | 标准 TLV 数组 | 每项 `type`、`value_hex`；禁止未登记厂商 TLV |
| `address_profile` | `none`、`ipv4_basic`、`ipv6_basic` | 地址族 TLV 组合，不是 IP 外层 |
| `checksum_mode` | `auto` | LSP Fletcher-16；其他 PDU 不生成 LSP checksum |
| `events` | 有序数组 | 每项 `kind`、`level`、`neighbor_state` 及完整 PDU 字段；不得依赖未定义默认值 |
| `start_lsp_id` / `end_lsp_id` | CSNP 必填 | 8 字节 LSP ID 范围端点；不可依赖默认值 |
| `wire_fault` | 仅负例 | 注入 carrier/version/length/checksum/TLV 边界错误，不代表合法线格式 |

## 3. 公共头与二层载体

Common Header（PDU 起点）按网络字节序为：

```text
byte 0       NLPID = 0x83
byte 1       Header Length = 0x08
byte 2       Version/Protocol ID Extension = 0x01
byte 3       ID Length = 0x06
byte 4       PDU Type = 15..27（按 PDU/Level）
byte 5       Version = 0x01
byte 6       Reserved = 0x00
byte 7       Max Area Addresses（正例 0x00 或显式配置）
```

LLC profile 的字节顺序是：

```text
Ethernet(dst 6 | src 6 | 802.3 length 2)
LLC(DSAP FE | SSAP FE | Control 03)
NLPID 83 | IS-IS Common Header ...
```

因此 Common Header 的第一个 `83` 在无 VLAN 帧 offset 17。EtherType profile 的字节顺序是：

```text
Ethernet(dst 6 | src 6 | EtherType 88 70)
NLPID 83 | IS-IS Common Header ...
```

Common Header 的第一个 `83` 在 offset 14。EtherType 0x8870 与 LLC `FE FE 03` 是两种互斥 carrier profile；正例必须在 `eth.type`/原始 frame bytes（帧字节）上观察二者差异，不能只依赖 dissector（解析器）名称。

## 4. PDU 线格式

### 4.1 LAN IIH（Type 15/16）

LAN IIH 的 Common Header 后固定字段为：

| 字段 | 长度 | 说明 |
|---|---:|---|
| Circuit Type | 1 | L1=`0x01`，L2=`0x02`；与 PDU level 一致 |
| Source ID | 6 | 发送方 System ID |
| Holding Timer | 2 | 秒，网络字节序 |
| PDU Length | 2 | 包含 Common Header 和全部 TLV |
| Priority | 1 | 本版使用非平凡显式值 |
| LAN ID | 7 | System ID 6 bytes + circuit ID 1 byte 组成的 LAN ID |

LAN IIH 固定字段为 19 字节（不含 Common Header），无 TLV 时 PDU 长度 27；LAN ID 必须始终是 7 字节（System ID 6 + circuit ID 1）。TLV 1 Area Addresses、TLV 132/232 等可按顺序追加。`area_addresses` 是 TLV 1 的便捷配置形式；若同时提供显式 type=1，校验器必须拒绝重复来源。L1/L2 的优先级、LAN ID 和 Circuit Type 必须独立断言。

### 4.2 LSP（Type 18/20）

LSP 的 Common Header 后固定字段为：

```text
PDU Length       2
Remaining Life   2
LSP ID            8  (System ID 6 + Pseudonode ID 1 + Fragment 1)
Sequence Number   4
Checksum          2  (Fletcher-16)
Partition         1
Circuit Type      1  (L1=1, L2=2)
TLVs              variable
```

固定字段为 20 字节，故无 TLV 时 PDU Length=28。LSP ID 的 System ID 不得与 Source ID 静默替换；Pseudonode/Fragment 的 2 字节也必须按配置保留。LSP `PDU Length` 与 TLV value length 都按编码结果计算，不能用抓包帧含 padding 的长度。

### 4.3 CSNP（Type 24/25）

CSNP 的 Common Header 后固定字段为 `PDU Length(2) | Source ID(6) | Start LSP ID(8) | End LSP ID(8)`，共 24 字节，无 TLV 时 PDU Length=32。TLV 9 LSP Entries 每项 16 字节：Remaining Life 2、LSP ID 8、Sequence Number 4、Checksum 2；类型和长度均必须可观察。

### 4.4 PSNP（Type 26/27）

PSNP 的 Common Header 后固定字段为 `PDU Length(2) | Source ID(6)`，共 8 字节，无 TLV 时 PDU Length=16。PSNP 用 TLV 9 携带一个或多个 16-byte LSP Entry；它没有 CSNP 的 start/end range 字段。

## 5. 标准 TLV profile 与地址族

TLV 编码统一为 `Type(1) | Length(1) | Value(Length)`。本版只允许以下已登记类型：

| TLV | 名称 | 本版 profile | value 约束 |
|---:|---|---|---|
| 1 | Area Addresses | `iso10589_base` | 每个 area 是 3–13 字节，TLV value 可含多个 length-prefixed area |
| 9 | LSP Entries | `snp` | 每项固定 16 字节；仅 CSNP/PSNP |
| 132 | IP Interface Addresses | `ipv4_basic` | 每个 IPv4 地址 4 字节 |
| 232 | IPv6 Interface Addresses | `ipv6_basic` | 每个 IPv6 地址 16 字节 |
| 236 | IPv6 Reachability | `ipv6_basic` | 仅在独立 IPv6 profile 中定义字段表；本版不填厂商子字段 |

`ipv4_basic` 正例使用 TLV 132 的明确 4-byte IPv4 address，并可与 TLV 1 共存；它不产生 IPv4 header。`ipv6_basic` 正例使用 TLV 232 的 16-byte address；TLV 236 只在定义了完整标准 value 的 fixture（固定样本）中出现。若没有完整 TLV 236 编码字段，配置必须拒绝，而不是生成猜测字节。

## 6. Checksum、长度和邻接状态

`checksum_mode=auto` 只对 LSP 生效。编码流程为：先写 Common Header、LSP 固定字段（checksum 置零）、标准 TLV，再按 ISO 10589 Fletcher-16 规则计算并回填。用例观察 `isis.lsp.checksum` 非零；实现单测还必须使用已知字节 fixture 验证 Fletcher-16 数值，覆盖奇偶长度、跨 TLV 和 LSP ID/序列变化。IIH/CSNP/PSNP 不应出现伪造的 `lsp.checksum`。

长度计算示例（均为 PDU 内长度）：

- LAN IIH：`8 + 19 + Σ(TLV header + value)`；无 TLV 为 27；TLV 1 value=4（area length byte + 3-byte area）时为 33。
- LSP：`8 + 20 + Σ(TLV header + value)`；无 TLV 为 28；TLV 132 value=4 时为 34。
- CSNP：`8 + 24 + 2 + 16×entry_count`；一个 LSP Entry TLV 时为 50。
- PSNP：`8 + 8 + 2 + 16×entry_count`；一个 LSP Entry TLV 时为 34。

Ethernet 最小帧填充只属于二层发送，不计入上述 PDU Length。LLC 802.3 length 字段包含 LLC/PDU/padding 的帧载荷长度：PDU=33/40/36 时分别为 `0x2e`（补齐到 46 字节），PDU=50 时为 `0x35`（无 padding）；EtherType profile 不使用该 length 字段。

邻接事件采用显式 `events`：例如 `iih`（Down→Initializing）、`iih`（Initializing→Up）、`lsp`（Up）、`csnp`（Up）、`psnp`（Up）。事件顺序是可观察的 session metadata（会话元数据），不是额外 PDU。不能因一个 IIH 自动生成对端 IIH 或 SNP。

## 7. 负例与错误处理

| 输入故障 | 条件 | 稳定错误锚点 |
|---|---|---|
| carrier | UDP/TCP/IP 外层、缺 eth、LLC+EtherType 混用 | `carrier`/`eth` |
| profile | 未知 wire profile 或 EtherType 非 0x8870 | `profile`/`ethertype` |
| common header | NLPID 非 0x83、header length 非 8、ID length 非 6、version 非 1 | `header`/`version` |
| level/type | L1/L2 与 PDU type/circuit type 不一致 | `level`/`type` |
| identifier | System ID 非 6 字节、LSP ID 长度错误或 Area 缺失 | `system`/`area` |
| length | PDU length 小于固定头、超过编码内容或 TLV 越界 | `length`/`tlv` |
| TLV | 未登记厂商类型、TLV value 长度不匹配、SNP 中 TLV 非 9 | `tlv` |
| checksum | 手工错误 LSP Fletcher-16 或不支持算法 | `checksum` |
| state | 事件在非法邻接状态发送，或事件隐式响应 | `state` |
| address family | IPv4/IPv6 TLV profile 混用或 TLV 236 value 不完整 | `address`/`tlv` |

`wire_fault` 仅为失败优先测试注入入口，不代表合法线上 PDU。所有负例只要求 `expect_error=true` 和 `error_contains`，禁止以“损坏 PCAP 生成成功”作为通过条件。

## 8. 场景和包数映射

IS-IS 二层 PDU 没有 TCP 握手/终止。单事件 `packet_count=1`；四事件邻接序列 `packet_count=4`。每个事件必须提供其 PDU 的完整固定字段和 TLV；事件 kind/状态不是省略必填 wire 字段的理由。EtherType profile 的 PDU frame offset=14，LLC profile 的 PDU offset=17。原始 Ethernet frame 可能因最小帧规则有 padding，但断言只定位 PDU 起点和 PDU Length，不把 padding 计入 PDU。

| # | JSON ID | 类型 | 事件/报文数 | packet_count | 主要 observable |
|---:|---|---|---:|---:|---|
| 1 | `isis_l1_iih_llc` | 正 | 1 | 1 | LLC、NLPID、L1 type、System ID、holding、PDU length |
| 2 | `isis_l2_iih_llc` | 正 | 1 | 1 | LLC、L2 type/circuit、priority、LAN ID |
| 3 | `isis_l1_iih_ethertype` | 正 | 1 | 1 | EtherType 0x8870、L1 IIH |
| 4 | `isis_l2_iih_ethertype` | 正 | 1 | 1 | EtherType 0x8870、L2 IIH |
| 5 | `isis_l1_lsp_ipv4` | 正 | 1 | 1 | L1 LSP、TLV 1/132、length/checksum |
| 6 | `isis_l2_lsp_ipv6` | 正 | 1 | 1 | L2 LSP、TLV 232、IPv6 profile |
| 7 | `isis_l1_lsp_tlv_order` | 正 | 1 | 1 | 多标准 TLV 顺序与长度 |
| 8 | `isis_l1_csnp` | 正 | 1 | 1 | range、TLV 9、LSP entry |
| 9 | `isis_l2_psnp` | 正 | 1 | 1 | TLV 9、无 CSNP range |
| 10 | `isis_length_checksum` | 正 | 1 | 1 | PDU/LSP length 与 Fletcher checksum |
| 11 | `isis_area_system_id` | 正 | 1 | 1 | Area TLV、Source/System/LSP ID |
| 12 | `isis_neighbor_up_sequence` | 正 | 4 | 4 | IIH/IIH/LSP/PSNP 与状态顺序 |
| 13 | `isis_ipv4_ipv6_tlv_profiles` | 正 | 2 | 2 | 独立 IPv4/IPv6 TLV profile |
| 14 | `isis_neg_profile` | 负 | — | — | 仅 task error |
| 15 | `isis_neg_identifier` | 负 | — | — | 仅 task error |
| 16 | `isis_neg_state` | 负 | — | — | 仅 task error |
| 17 | `isis_neg_address_family` | 负 | — | — | 仅 task error |
| 18 | `isis_neg_duplicate_area` | 负 | — | — | 仅 task error |
| 19 | `isis_neg_ip_carrier` | 负 | — | — | 仅 task error |
| 20 | `isis_neg_mixed_carrier` | 负 | — | — | 仅 task error |
| 21 | `isis_neg_header` | 负 | — | — | 仅 task error |
| 22 | `isis_neg_level_type` | 负 | — | — | 仅 task error |
| 23 | `isis_neg_length` | 负 | — | — | 仅 task error |
| 24 | `isis_neg_vendor_tlv` | 负 | — | — | 仅 task error |
| 25 | `isis_neg_checksum` | 负 | — | — | 仅 task error |

## 9. 实现完成定义

1. 注册 `eth→isis` 终结层，支持 LLC `FE FE 03/83` 与 EtherType 0x8870 两 profile；不得自动补 IP/TCP/UDP。
2. 对 Common Header、二层 carrier、L1/L2 IIH、LSP、CSNP、PSNP 逐字段写失败优先单测；长度按最终 PDU bytes 回填。
3. 实现标准 TLV 1、9、132、232 的边界和 TLV 236 的完整字段 profile；未知/厂商 TLV 必须错误传播。
4. 对 LSP Fletcher-16 进行值级测试，确认 checksum 变化、校验位置和 Remaining Lifetime 排除规则；非 LSP PDU 不伪造 checksum。
5. API→engine→PCAP 集成验证全部正负用例；负例必须 task error，不得 completed/0 packet。
6. 对邻接状态 sequence 验证事件顺序和会话隔离；不把状态写成不存在的 wire 字段。
7. RFC 1195/RFC 5308 等额外 IPv4/IPv6 reachability TLV 必须另有字段表、fixture 和独立测试，不能在本 profile 猜测编码。

## 10. 修订记录

- v1.0.0（2026-08-20）：建立 ISO 10589 LAN IS-IS 设计契约；覆盖 LLC/EtherType 载体、L1/L2 IIH、LSP、CSNP、PSNP、标准 TLV、System ID/Area、PDU length、LSP Fletcher-16、邻接状态和 IPv4/IPv6 TLV 边界；厂商 TLV 与未证实扩展保持待实现。
- v1.0.1（2026-08-20）：明确 802.3 length 的最小帧 padding 语义、area_addresses 与显式 TLV 1 互斥、CSNP 范围端点和事件完整字段；补齐 profile/identifier/state/address-family/重复 Area 负例。
