# OSPF（开放最短路径优先）v2 设计文档

> 版本：v1.0.0（设计阶段）  
> 日期：2026-08-20  
> 状态：仅设计与用例契约；`ospf` 层尚未实现，本稿不宣称 MCP（模型上下文协议）套件可以运行。  
> 配套文件：`docs/protocol-designs/37-ospf-testcase.md`、`trafficgen/test/protocol_pcap/cases/ospf.json`、`docs/protocol-designs/audit/37-ospf-adversarial-audit.md`

## 1. 范围、证据等级和 profile（档案）边界

本版只定义 RFC 2328 的 OSPFv2（OSPF 第 2 版）IPv4 profile（档案）。OSPFv2 直接封装在 IPv4 中，IP Protocol（协议号）为 **89**；它没有 TCP/UDP 端口。本文覆盖五类 OSPFv2 packet（报文）：Hello、Database Description（DBD，数据库描述）、Link State Request（LSR，链路状态请求）、Link State Update（LSU，链路状态更新）和 Link State Acknowledgment（LSAck，链路状态确认）。

| 证据等级 | 本版固定内容 | 不在本版伪造的内容 |
|---|---|---|
| IPv4 载体 | IPv4、Protocol=89、Router ID、Area ID、TTL、单播/224.0.0.5/224.0.0.6 目的地址 | 真实邻接、路由收敛或网卡可达性 |
| OSPFv2 公共头 | Version=2、Type、Packet Length、Router ID、Area ID、Checksum、AuType 和 8 字节 Authentication 字段的位置/宽度/网络字节序 | 未声明的认证算法、密钥或线上邻居状态 |
| Hello | 网络掩码、Hello/Dead interval、Options、优先级、DR/BDR 和邻居 Router ID 列表 | 由实现自行决定的选举结果；用例显式提供 DR/BDR |
| DBD | Interface MTU、Options、I/M/MS 标志、DD sequence 和 LSA header 列表 | 未配置的数据库摘要或隐式邻居事件 |
| LSR/LSU/LSAck | 请求三元组、LSA header、Router-LSA/Network-LSA 的基本 body 和长度 | 外部路由、AS-external/opaque/扩展 LSA 的未声明字段 |
| RFC 5340 profile | 仅作为独立 IPv6 边界说明 | 不把 OSPFv2 的 IPv4 头、IPv4 checksum 或 LSA body 复制成 OSPFv3 |

`rfc2328_ipv4` 是本版唯一的正例 wire profile（线格式档案）名。RFC 5340 OSPFv3（IPv6 OSPF）需要独立的 `rfc5340_ipv6` profile：其 IPv6 pseudo-header/checksum 处理、Instance ID、认证/安全扩展和 LSA 语义不能由本版 OSPFv2 默认化。`ospf_ipv6_rfc5340_boundary` 只验证该 profile 边界，不宣称生成 OSPFv3 正例；`ospf_neg_ipv6_v2` 明确拒绝用 `rfc2328_ipv4` 伪装 IPv6。

不变式：

1. OSPFv2 只能位于 IPv4 后，IPv4 Protocol 必须是 89；UDP/TCP 载体、缺 IPv4 或不完整层链拒绝。
2. OSPF 公共头固定为 24 字节，`packet_length` 包含公共头和 OSPF body，按编码字节数回填，最小值为 24。
3. OSPFv2 的 checksum 是 OSPF packet 的 16-bit ones-complement checksum（不含 IPv4 header checksum，且计算排除 8-byte Authentication 字段）；`AuType=0` 时 Authentication 字段仍占 8 字节并填充为 profile 规定的零值。LSA checksum 是独立的 Fletcher-16 校验，计算排除 LSA age。
4. Router ID 和 Area ID 都是 4 字节 IPv4 格式标识；它们不是根据 `src_ip`、`dst_ip` 或 multicast（组播）地址自动猜测。
5. LSA header 固定 20 字节；其中 LSA `length` 包含该 LSA 自身的 20 字节 header。OSPF packet 的 `packet_length` 还必须包含 LSU 的 4 字节 LSA count。
6. Hello、DBD、LSR、LSU、LSAck 的事件必须原子化；planner（规划器）不得偷偷补发响应或把邻居状态变成额外报文。
7. planner/validator（校验器）失败必须传播到 task error（任务错误）终态，不能“完成但 0 包”。
8. OSPFv2 的默认 TTL 为 1；组播 Hello 使用 224.0.0.5，DR/BDR 相关 LSU/LSAck 可以显式使用 224.0.0.6。TTL、目的地址和单播/组播行为必须由配置或 profile 明确。

## 2. 层链、载体和配置

推荐层链：

```json
{
  "layers": [{"ip": {}}, {"ospf": {}}],
  "src_ip": "10.0.0.1",
  "dst_ip": "224.0.0.5",
  "ttl": 1,
  "ospf": {
    "version": 2,
    "profile": "rfc2328_ipv4",
    "router_id": "1.1.1.1",
    "area_id": "0.0.0.0",
    "packet_type": "hello",
    "checksum_mode": "auto"
  }
}
```

`ospf` 是 IPv4 terminal（终结层），不是 TCP/UDP terminal。层链注册时应自动补齐 IPv4，但显式 `ip` 配置必须获胜；不得把 OSPF 当作 UDP payload。单报文用 `packet_type` 及对应字段，多报文邻接场景用有序 `events`。

| 键 | 类型 | 约束 | 语义 |
|---|---|---|---|
| `version` | uint8 | 正例为 `2` | OSPF 版本；与 profile 和 IPv4 载体绑定 |
| `profile` | string | `rfc2328_ipv4`；RFC 5340 另行注册 | 版本化编码选择，不直接写入 wire（线格式） |
| `packet_type` | enum | `hello`、`db_description`、`link_state_request`、`link_state_update`、`link_state_acknowledgment` | 五种 OSPFv2 报文 |
| `router_id` | IPv4 string | 必填且格式有效 | OSPF Router ID，4 字节 |
| `area_id` | IPv4 string | 必填且格式有效 | Area ID，4 字节；普通区域可为 `0.0.0.0` |
| `checksum_mode` | enum | `auto`；显式错误注入除外 | 根据最终 OSPF 字节计算 checksum |
| `auth_type` | uint16 | `0` 为无认证 | AuType；Authentication 始终保留 8 字节 |
| `network_mask` | IPv4 string | 仅 Hello | 接口网络掩码 |
| `hello_interval` | uint16 | 仅 Hello，非负 | 秒 |
| `dead_interval` | uint32 | 仅 Hello，非负 | 秒 |
| `options` | uint8 | 仅 Hello/DBD | OSPF Options |
| `priority` | uint8 | 仅 Hello | DR/BDR 选举优先级 |
| `designated_router` | IPv4 string | 仅 Hello | DR 接口地址；未选举时可为 `0.0.0.0` |
| `backup_designated_router` | IPv4 string | 仅 Hello | BDR 接口地址；未选举时可为 `0.0.0.0` |
| `neighbors` | IPv4 array | 仅 Hello | 已知邻居 Router ID，逐个 4 字节编码 |
| `interface_mtu` | uint16 | 仅 DBD | 接口 MTU |
| `flags` | object | 仅 DBD | `init`/`more`/`master` 三个标志 |
| `dd_sequence` | uint32 | 仅 DBD | Database Description sequence |
| `requests` | array | 仅 LSR | 每项为 `lsa_type`、`link_state_id`、`advertising_router` |
| `lsas` | array | 仅 LSU | LSA 完整 body；本版基本支持 Router/Network LSA |
| `lsa_headers` | array | DBD/LSAck | 每项 20 字节 LSA header |
| `wire_fault` | object | 仅负例 | planner 边界注入，不代表合法线上报文 |
| `events` | array | 多事件场景 | 每项带 `kind`、方向和该报文字段；按顺序发送 |

### 2.1 方向、邻接状态和事件

每个事件可以显式给出 `direction`（`c2s` 或 `s2c`）与 `neighbor_state`。状态是 session（会话）可观察语义，不替代 wire 字段：

```text
Down → Init → ExStart → Exchange → Loading → Full
```

本版的 `ospf_neighbor_full_exchange` 将 Hello、DBD、LSR、LSU、LSAck 拆成六个原子事件，显式观察 Init、ExStart、Exchange、Loading、Full；实现不得把“到达 Full”编码成一个不存在的 OSPF 报文。真实邻接状态机还包括 2-Way、Attempt、退邻接和重传定时器，它们不在单个静态 PCAP（抓包文件）契约中自动推断。

## 3. OSPFv2 公共头和校验

### 3.1 公共头

IPv4 无 option 时 OSPF payload（载荷）起点为 `offset 34 = Ethernet 14 + IPv4 20`；启用 VLAN/IP option 时必须使用实际 header length。公共头按网络字节序为：

```text
byte 0       Version = 2
byte 1       Type = 1..5
byte 2..3    Packet Length（包含 24 字节公共头）
byte 4..7    Router ID
byte 8..11   Area ID
byte 12..13  Checksum
byte 14..15  AuType
byte 16..23  Authentication（8 字节）
byte 24..    Body
```

Type 定义：

| Type | 名称 | 本版 body |
|---:|---|---|
| 1 | Hello | 网络掩码、计时器、Options、优先级、DR/BDR、邻居列表 |
| 2 | Database Description | MTU、Options、I/M/MS、DD sequence、LSA headers |
| 3 | Link State Request | LSA type、LSID、advertising Router ID 三元组 |
| 4 | Link State Update | LSA count + 完整 LSA |
| 5 | Link State Acknowledgment | 一个或多个 LSA header |

### 3.2 Checksum 和长度规则

`checksum_mode=auto` 时编码器先构造 Version/Type/Length/Router ID/Area ID/AuType/Authentication/body，再按 RFC 2328 的 OSPF packet checksum 规则计算并回填公共头 checksum；计算范围排除 8-byte Authentication 字段。用例只将 packet checksum 作为非零可观察值；不会把某个 IP、时间戳或实现版本的常数 checksum 当成跨样本事实。`AuType=0` 的 Authentication 是 8 字节保留字段，不可缩短公共头。每个 LSA header 的 checksum 是独立的 Fletcher-16 校验，计算时排除 LS age 字段，不能用 OSPF packet 的 ones-complement checksum 替代。

长度示例：

- Hello：`24 + 20 + 4×neighbor_count`；一个邻居为 48，两 个邻居为 52。
- DBD：`24 + 8 + 20×lsa_header_count`；一个 LSA header 为 52。
- LSR：`24 + 12×request_count`；一个 request 为 36。
- LSU：`24 + 4 + Σ(LSA length)`；一个 36-byte Router-LSA 为 64，一个 32-byte Network-LSA 为 60。
- LSAck：`24 + 20×lsa_header_count`；两个 header 为 64。

所有长度均按编码后的字节数回填。MSS（最大报文段长度）或其他外层分段出现时，`packet_length` 仍是 OSPF stream（流）消息长度，而 PCAP `packet_count` 应按真实 IPv4 segment（分段）和重组断言调整。

## 4. Hello、DBD、LSR、LSU、LSAck 语义

### 4.1 Hello

Hello 固定 body 为：Network Mask 4、HelloInterval 2、Options 1、Priority 1、DeadInterval 4、Designated Router 4、Backup Designated Router 4，再跟零个或多个 Neighbor Router ID（各 4 字节）。本版固定非平凡的 DR、BDR、优先级、计时器和邻居列表，避免只断言版本/类型。Hello 通常发往 224.0.0.5，TTL 1；实现应允许显式 src/dst 覆盖，但不得把目的组播地址替代 Router ID/DR 字段。

### 4.2 Database Description

DBD body 的固定部分为 Interface MTU 2、Options 1、I/M/MS flags 1、DD sequence 4，共 8 字节，随后为零个或多个 20-byte LSA headers。`ospf_dbd_master` 断言 I/M/MS 全置位（示例值 `0x07`）和 sequence 100；`ospf_dbd_slave` 独立断言标志清零、sequence 101。DBD 的 LSA header 只描述摘要，不携带完整 LSA body。

### 4.3 Link State Request

每个 LSR request 是 12 字节：LSA type 4、Link State ID 4、Advertising Router 4。Router-LSA（type 1）和 Network-LSA（type 2）分开用例，避免只覆盖请求长度而漏掉类型/身份三元组。

### 4.4 Link State Update 和 LSA

LSU body 首先是 4-byte number-of-LSAs，随后串联完整 LSA。

LSA 公共 header：Age 2、Options 1、LS type 1、Link State ID 4、Advertising Router 4、Sequence 4、Checksum 2、Length 2，共 20 字节。Length 包含该 header。

- Router-LSA（type 1）body：Flags 1、保留 1、Link count 2、每个 link 12 字节（Link ID 4、Link Data 4、Link Type 1、TOS 0 1、Metric 2）。本版用一个 type 2 transit link、metric 10，LSA length 为 36。
- Network-LSA（type 2）body：Network Mask 4 + Attached Router IDs；两个 attached Router ID 时 LSA length 为 32。LSID 是 DR 接口地址 `10.0.0.2`，Advertising Router 是 `1.1.1.1`。

本版不把 AS-external-LSA、NSSA-LSA、opaque-LSA、extended-LSA、TOS 扩展或完整拓扑推断塞进 Router/Network 基础用例；新增类型必须独立 profile/case 和长度证据。

### 4.5 Link State Acknowledgment

LSAck 只携带一个或多个 20-byte LSA headers，不携带完整 LSA body。`ospf_lsack` 同时确认 Router-LSA 和 Network-LSA，断言 count、类型、LSID 和 Length，避免只检查 packet type。

## 5. IPv6 RFC 5340 边界

OSPFv3 的 IPv6 profile 不等于“把 IPv4 profile 的 `ip.proto=89`、公共头 offset 34、OSPF checksum 和 Router/Network LSA body 原样搬到 IPv6”。实现 RFC 5340 时必须单独明确：

1. IPv6 Next Header=89、IPv6 payload 起点和 Hop Limit，而不是 IPv4 header/TTL 断言；
2. OSPFv3 header 的 Instance ID、reserved bits 和 checksum 计算边界；
3. OSPFv3 的 LSA header/body 版本差异以及 link-local/interface scope；
4. 认证/安全扩展和 IPv6 地址字段；
5. 独立的正例、失败优先测试和 PCAP 证据。

本版的 `ospf_ipv6_rfc5340_boundary` 使用独立 `rfc5340_ipv6` profile 名，但在代码未实现阶段要求 task error `rfc5340`；它不是 IPv6 OSPF 正例。这样既保留需求边界，又不把 IPv4 OSPFv2 的 pseudo-header（伪首部）或 LSA 字节冒充 OSPFv3。

## 6. 校验和失败处理

planner/validator 必须拒绝：

| 错误 | 条件 | 稳定错误锚点 |
|---|---|---|
| 载体 | UDP/TCP、缺 IPv4、未登记 IPv4→OSPF 关系 | `ip`/`carrier` |
| profile/version | OSPFv3 与 `rfc2328_ipv4` 混用、未知版本/profile | `version`/`rfc5340`/`profile` |
| type | 非 1..5 或 body 与 type 不匹配 | `type` |
| length | 小于 24、超过编码 body、LSA length 与 body 不一致 | `length` |
| Router/Area ID | 非 4-byte IPv4 格式、非法字符串或缺失 | `router`/`area` |
| checksum | 手工错误 checksum（若开启 fault）或不支持的算法 | `checksum` |
| Hello | 缺 mask/timer、负值、邻居字段非 4 字节 | `hello` |
| DBD | flags/sequence/LSA header 边界不完整 | `db_description`/`sequence` |
| LSR | request 三元组缺失或未知 LSA type | `request`/`lsa` |
| LSU/LSAck | count、LSA header/body 数量不一致 | `lsa`/`count` |
| IPv6 profile | RFC 5340 未实现或 IPv4 profile 被复用 | `rfc5340` |

错误必须从 planner 传播到 task error，不能输出损坏 PCAP 后返回 completed。应用层邻接事件（例如状态为 Full）不是错误，也不能用 `expect_error` 替代其 wire 断言。

## 7. 场景与包数映射

OSPFv2 是 raw IPv4（裸 IPv4）报文，不走 TCP 握手，因此单报文正例的 `packet_count=1`；多事件场景按显式事件数计算。小报文、无 IP option、无 VLAN 的 IPv4 OSPF payload 起点为 offset 34。

| # | JSON id | 类型 | 事件/报文数 | packet_count | 主要 observable（可观察锚点） |
|---:|---|---|---:|---:|---|
| 1 | `ospf_hello_dr_bdr` | 正 | 1 | 1 | Hello 计时器、mask、priority、DR/BDR、neighbor、checksum |
| 2 | `ospf_hello_neighbors` | 正 | 1 | 1 | 两个邻居和 length=52 |
| 3 | `ospf_dbd_master` | 正 | 1 | 1 | MTU、I/M/MS、DD sequence、Router-LSA header |
| 4 | `ospf_dbd_slave` | 正 | 1 | 1 | flags 清零、sequence=101 |
| 5 | `ospf_lsr_router_lsa` | 正 | 1 | 1 | type 1 request 三元组 |
| 6 | `ospf_lsr_network_lsa` | 正 | 1 | 1 | type 2 request 三元组 |
| 7 | `ospf_lsu_router_lsa` | 正 | 1 | 1 | Router-LSA flags/link/metric/length |
| 8 | `ospf_lsu_network_lsa` | 正 | 1 | 1 | Network-LSA mask/attached routers/length |
| 9 | `ospf_lsack` | 正 | 1 | 1 | 两个 LSA headers |
| 10 | `ospf_neighbor_full_exchange` | 正 | 6 | 6 | Hello→DBD→LSR→LSU→LSAck 与状态 |
| 11 | `ospf_ipv4_transport` | 正 | 1 | 1 | IPv4 protocol 89、TTL、Area/Router ID |
| 12 | `ospf_checksum_length` | 正 | 1 | 1 | packet/LSA length 和两个 checksum |
| 13 | `ospf_neg_udp` | 负 | — | — | 仅 task error |
| 14 | `ospf_neg_ipv6_v2` | 负 | — | — | 仅 task error，拒绝 v2/IPv6 复用 |
| 15 | `ospf_neg_version` | 负 | — | — | 仅 task error |
| 16 | `ospf_neg_type` | 负 | — | — | 仅 task error |
| 17 | `ospf_neg_length` | 负 | — | — | 仅 task error |
| 18 | `ospf_neg_area` | 负 | — | — | 仅 task error |
| 19 | `ospf_neg_router_id` | 负 | — | — | 仅 task error |
| 20 | `ospf_ipv6_rfc5340_boundary` | 负/边界 | — | — | 仅 task error，独立 RFC5340 profile |

## 8. 实现完成定义

1. 注册 IPv4→`ospf` 层，协议号 89，默认 TTL 1，并拒绝 UDP/TCP/缺 IPv4。
2. 对公共头逐字段写失败优先单测：version/type/length/router ID/area ID/checksum/AuType/authentication。
3. 对 Hello、DBD master/slave、LSR 两种 LSA type、LSU Router/Network LSA、LSAck 多 header 写独立单测；每个长度和字节序都要由编码结果断言。
4. 对 API→engine→PCAP 集成路径验证 20 个 case 的正/负分支；负例必须是 task error，不得 0 包成功。
5. 对 `ospf_neighbor_full_exchange` 验证事件顺序和状态隔离；不以一条 packet type 断言替代五类报文覆盖。
6. 用 IPv4 protocol 89、TTL、224.0.0.5/224.0.0.6 和实际 OSPF checksum 做 PCAP/NIC（网卡）验证；MSS 不适用于 IP 层分片时必须使用重组语义。
7. RFC 5340 OSPFv3 作为独立工作项：取得规范/fixture 后再注册 `rfc5340_ipv6` 正例，不得改写本版 IPv4 case。

## 9. 修订记录

- v1.0.0（2026-08-20）：建立 OSPFv2 RFC2328 IPv4 设计契约；覆盖 Hello、DBD、LSR、LSU、LSAck、Router/Network LSA、邻接状态、DR/BDR、checksum/length、IPv4 Protocol 89 和 20 个原子正/负/边界 case；RFC5340 保持独立 profile 边界。
