# IGMP（互联网组管理协议，Internet Group Management Protocol）设计文档

> 版本：v1.0.0（设计阶段）
> 日期：2026-08-20
> 状态：仅设计与用例契约；`igmp` 层尚未注册，不宣称当前 MCP（模型上下文协议）套件或 PCAP（抓包文件）用例可运行。
> 配套文件：`docs/protocol-designs/39-igmp-testcase.md`、`trafficgen/test/protocol_pcap/cases/igmp.json`、`docs/protocol-designs/audit/39-igmp-adversarial-audit.md`
> 规范基线：RFC 1112（IGMPv1）、RFC 2236（IGMPv2）、RFC 3376（IGMPv3）。

## 1. 范围、证据等级与版本边界

本版定义 IPv4 直接承载的 IGMP 基础消息：Membership Query（成员查询）、Membership Report（成员报告）和 Leave Group（离开组）。覆盖 RFC 1112 的 IGMPv1、RFC 2236 的 IGMPv2，以及 RFC 3376 的 IGMPv3 profile（线格式档案）。IGMP 不是 TCP/UDP 载荷，而是 IPv4 `Protocol=2` 的独立上层协议；正常链路上的 IPv4 TTL 固定为 1。

本版明确以下可观察契约：

- Query 的目的地址按范围选择：General Query 为 `224.0.0.1`，Group-Specific Query 为被查询组地址；v3 Source-Specific Query 仍以被查询组地址为目的地址。
- v1 Report 的目的地址为组地址；v2 Report 的目的地址为组地址；v2 Leave 的目的地址为 `224.0.0.2`；v3 Report 的目的地址为 `224.0.0.22`。
- v1/v2 的 IGMP 固定头为 8 字节：Type、Max Response Time、Checksum、Group Address。v1 Query 的 Max Response Time 字段为 0；v2 Query 的字段以 1/10 秒为单位。
- v3 Query 的固定头为 12 字节：Type、Max Resp Code、Checksum、Group Address、Resv/S/QRV、QQIC、Number of Sources；每个 source address（源地址）再占 4 字节。
- v3 Report 的固定头为 8 字节，后跟 Group Record（组记录）数组；每条记录为 Record Type、Aux Data Len、Number of Sources、Multicast Address、source list 和可选的 32-bit auxiliary data（辅助数据）。
- IPv4 地址可出现在外层源/目的地址、组地址和 source list 中；IPv6 不属于 IGMP 的承载族。

“设计阶段”是证据等级边界：本文件中的字段名、配置名和断言是未来实现的契约，不是当前代码已接受的接口。未注册层、未实现的 profile 或错误配置不得被报告为已生成成功。

## 2. Profile、配置和不变式

每个正例采用建议的层链 `ip → igmp`。以下字段是设计配置，不改变现有未注册层的实现状态：

| 配置 | 取值/语义 |
|---|---|
| `profile` | `v1`、`v2` 或 `v3`；决定消息编码和允许的消息类型 |
| `kind` | `query`、`report`、`leave`；v1 不允许 Leave，v3 Leave 用 Group Record 状态表达而不是 v2 Leave Type |
| `group` | `0.0.0.0` 仅允许 General Query；其余 Query/Report/Leave 为组播 IPv4 地址 |
| `max_response_time` | v1/v2 的十进制秒十分之一字段值；v1 Query 必须 0 |
| `max_response_code` | v3 Query 的 MRC（Max Resp Code，最大响应代码），按 RFC 3376 的直接/浮点编码解释 |
| `s_flag`、`qrv`、`qqic` | v3 Query 的 Suppress Router-side Processing、Querier's Robustness Variable、Querier's Query Interval Code |
| `sources` | v3 Query 的 source list，或 v3 Group Record 的 source list；每项为 IPv4 地址 |
| `records` | v3 Report 的 Group Record 数组；记录类型使用 RFC 3376 名称或对应数值 |
| `address_family` | 仅负例的 IPv6 边界标记；正例固定 IPv4 |
| `wire_fault` | 仅负例的 protocol/checksum/record/source-count 故障注入；不是线上字段 |
| `events` | 多消息会话的有序事件；每个事件有 profile/kind/group 等自己的线格式配置，可带 `state`、`retransmit` 元数据 |

所有事件必须满足：

1. 外层 IPv4 `Protocol=2`、TTL=1，且目的地址与 profile/消息语义一致；不得把 IGMP 放入 UDP 或 TCP。
2. 源地址为单播 IPv4，目的地址必须是合法 IPv4 组播地址；IGMP 使用 `224.0.0.0/4` 的链路本地组播目的不得被改成任意单播地址。
3. `0.0.0.0` 只作为 General Query 的 Group Address；它不是 Report、Leave 或 Group-Specific Query 的合法组地址。
4. v1 只允许 Type `0x11` Query 和 `0x12` Report；v2 允许 Query、`0x16` Report、`0x17` Leave；v3 Query 为 `0x11`，Report 为 `0x22`。profile 与 Type 不得混用。
5. IPv4 总长度、IGMP 长度、v3 source count、Group Record count 和每条记录长度必须由实际字段计算；截断的 source list/auxiliary data 必须拒绝。

## 3. IPv4 载体和目的地址

无 IPv4 options 时，Ethernet 头占 14 字节、IPv4 头占 20 字节，因此 IGMP 起点为 PCAP offset 34；有 VLAN 或 IPv4 options 时不得复用该固定 offset。本阶段正例固定无 VLAN、无 IPv4 options，以便每个 `frames` 断言都有确定起点。

| 消息/profile | IPv4 Protocol | TTL | 目的地址 |
|---|---:|---:|---|
| v1/v2 General Query | 2 | 1 | `224.0.0.1` |
| v1/v2 Group-Specific Query | 2 | 1 | Query 的 group |
| v1 Report | 2 | 1 | Report 的 group |
| v2 Report | 2 | 1 | Report 的 group |
| v2 Leave | 2 | 1 | `224.0.0.2` |
| v3 General Query | 2 | 1 | `224.0.0.1` |
| v3 Group-/Source-Specific Query | 2 | 1 | Query 的 group |
| v3 Report | 2 | 1 | `224.0.0.22` |

目的 Ethernet MAC 应由 IPv4 组播映射生成；本阶段以 `ip.dst` 和 `ip.ttl` 为稳定断言，不把具体 MAC 作为未经实现验证的协议事实。所有报文都必须含 IPv4 header checksum 和 IGMP checksum；checksum 是否正确由实现单测逐字节验证。

## 4. IGMPv1/v2 固定消息

### 4.1 Query

v1/v2 的前 8 字节布局如下：

| 偏移（IGMP 起点） | 宽度 | 字段 |
|---:|---:|---|
| 0 | 1 | Type=`0x11` |
| 1 | 1 | v1 为 0；v2 为 Max Response Time，单位 1/10 秒 |
| 2 | 2 | Checksum |
| 4 | 4 | Group Address |

General Query 的 Group Address 为 `0.0.0.0`，Group-Specific Query 的 Group Address 为目标组。v1 不携带 v2/v3 的 QRV、QQIC 或 source count；若 v1 的 Max Response Time 非 0，必须拒绝。

### 4.2 Report 和 Leave

v1 Report 为 `12 00` 开头，v2 Report 为 `16 00` 开头，v2 Leave 为 `17 00` 开头；后三个字段依次为两字节 checksum 和四字节组地址。v1 不生成 Leave。v2 Report/Leave 的 group address 必须与 IPv4 目的地址或 RFC 2236 规定的全路由器目的地址相符合，不可用 `0.0.0.0`。

## 5. IGMPv3 Query

v3 Query 的布局（IGMP 起点）为：

```text
0       Type = 0x11
1       Max Resp Code (MRC)
2..3    Checksum
4..7    Group Address
8       Resv(4) | S(1) | QRV(3)
9       QQIC
10..11  Number of Sources (N)
12..    N 个 4-byte source address
```

`S=1` 表示抑制路由器侧处理；QRV 的有效编码为 0–7；QQIC 按 RFC 3376 的直接/浮点规则解释。MRC/QQIC 的代码字段不是简单的“秒数”：小代码使用直接编码，扩展代码按 RFC 3376 的 exponent/mantissa 规则解码。设计用例既覆盖直接值，也覆盖边界代码，但不把某个浮点解码结果臆写成非标准常量。

General Query 的 group 为 0、N 为 0；Group-Specific Query 的 group 非 0；Source-Specific Query 的 group 非 0 且 N 大于 0。source list 中每个 IPv4 地址占 4 字节，N 必须等于实际列表长度。

## 6. IGMPv3 Report 与 Group Record

v3 Report 固定头：

```text
0       Type = 0x22
1       Reserved = 0
2..3    Checksum
4..5    Reserved = 0
6..7    Number of Group Records (M)
8..     M 个 Group Record
```

每条 Group Record 的字段为：

| 宽度 | 字段 |
|---:|---|
| 1 | Record Type：MODE_IS_INCLUDE(1)、MODE_IS_EXCLUDE(2)、CHANGE_TO_INCLUDE_MODE(3)、CHANGE_TO_EXCLUDE_MODE(4)、ALLOW_NEW_SOURCES(5)、BLOCK_OLD_SOURCES(6) |
| 1 | Aux Data Len，以 32-bit word 计 |
| 2 | Number of Sources |
| 4 | Multicast Address |
| 4×N | source list |
| 4×Aux Data Len | auxiliary data |

M 必须等于实际记录数；每条记录的 source count 和 auxiliary data length 都必须独立校验。`MODE_IS_INCLUDE`、`MODE_IS_EXCLUDE`、模式变更以及 allow/block source filtering（源码过滤）在正例中分别可观察；未声明的记录类型或非 4 字节对齐的辅助数据必须拒绝。v3 Report 的 IPv4 目的地址是 `224.0.0.22`，不能沿用 v1/v2 Report 的组地址目的。

## 7. Checksum、长度和状态

IGMP checksum 是 IGMP message（消息）本身的 16-bit one's-complement checksum（反码校验和）：把 checksum 字段清零后，以网络字节序按 16-bit word 求 one's-complement sum，再对最终进位回卷并取反。奇数长度时按 RFC 规定补零参与计算，但补零不是线上的 payload 字节。实现必须验证 checksum 覆盖整个 IGMP 消息（包括 v3 source list、Group Records 和 auxiliary data），而不是只验证固定头。

本阶段 PCAP 用例对 checksum 只要求 `nonzero=true` 作为存在性 observable（可观察结果），不把未经逐字节复算且与具体 fixture 绑定的 checksum 常量写入 fields/frames。实现单测必须另行使用独立计算器验证：零校验和注入、奇数长度、v3 多源、多记录和辅助数据变化都会改变结果；错误 checksum 必须在 planner/任务层失败，不生成“成功但损坏”的 PCAP。

长度规则：v1/v2 固定 IGMP 长度为 8；v3 Query 长度为 `12 + 4*N`；v3 Report 长度为 `8 + Σ(8 + 4*N_i + 4*AuxLen_i)`。IPv4 Total Length 必须等于 20 加 IGMP 长度（本阶段无 IPv4 options）。

状态不写入 IGMP 保留字段。会话状态由事件元数据表达：`idle → querying → member`，Leave 或 v3 mode change 进入相应过滤状态；`retransmit=true` 只能重发完全相同的消息语义和组/source 集合，不能随机改变 checksum 或 source count。多个会话必须隔离状态、重传计数和组集合；同一会话的跨事件相等性以 `same_as_packet` 或同值 fields 观察。

## 8. IPv4/IPv6 边界

IGMP 只定义 IPv4 Protocol 2。IPv6 使用 ICMPv6（协议号 58）及 MLD（Multicast Listener Discovery，组播侦听者发现），不是 IGMP 的 v1/v2/v3 变体。因此以下输入都必须拒绝而不是自动“转换”：IPv6 outer header、IPv6 group/source、IPv6 Next Header 2、或同时填写 IPv4 与 IPv6 地址族。设计中不放 IPv6 正例，也不把 MLD 的消息字段映射到 IGMP 字段。

## 9. 场景与包数映射

| 序号 | ID | 类型 | 覆盖 | packet_count |
|---:|---|---|---|---:|
| 1 | `igmp_v1_general_query` | 正 | v1 General Query、TTL/Protocol/目的地址 | 1 |
| 2 | `igmp_v1_report` | 正 | v1 Report、组目的地址 | 1 |
| 3 | `igmp_v2_general_query` | 正 | v2 Query、Max Response Time | 1 |
| 4 | `igmp_v2_group_specific_query` | 正 | v2 Group-Specific Query | 1 |
| 5 | `igmp_v2_report` | 正 | v2 Membership Report | 1 |
| 6 | `igmp_v2_leave` | 正 | v2 Leave、224.0.0.2 | 1 |
| 7 | `igmp_v3_general_query` | 正 | v3 MRC/QRV/QQIC General Query | 1 |
| 8 | `igmp_v3_source_specific_query` | 正 | v3 source list、S/QRV | 1 |
| 9 | `igmp_v3_include_record` | 正 | MODE_IS_INCLUDE | 1 |
| 10 | `igmp_v3_exclude_record` | 正 | MODE_IS_EXCLUDE | 1 |
| 11 | `igmp_v3_change_records` | 正 | mode change、多记录 | 1 |
| 12 | `igmp_v3_allow_block_sources` | 正 | ALLOW/BLOCK source filtering | 1 |
| 13 | `igmp_profile_matrix` | 正 | v1/v2/v3 profile 对照 | 3 |
| 14 | `igmp_retransmit_state` | 正 | querying/member、重传与相等性 | 3 |
| 15 | `igmp_multi_group_sessions` | 正 | 多会话、多组、不同 profile | 4 |
| 16 | `igmp_ipv4_outer_invariants` | 正 | Protocol=2、TTL=1、组播目的 | 1 |
| 17 | `igmp_v3_query_boundaries` | 正 | QRV/MRC/QQIC/source count 边界 | 1 |
| 18 | `igmp_neg_ipv6` | 负 | IPv6 明确 N/A/拒绝 | — |
| 19 | `igmp_neg_nonmulticast_destination` | 负 | 单播目的 | — |
| 20 | `igmp_neg_ttl_not_one` | 负 | TTL 非 1 | — |
| 21 | `igmp_neg_protocol_not_two` | 负 | Protocol 非 2 | — |
| 22 | `igmp_neg_bad_checksum` | 负 | checksum 错误 | — |
| 23 | `igmp_neg_invalid_v3_record` | 负 | 记录类型/长度错误 | — |
| 24 | `igmp_neg_invalid_profile_version` | 负 | profile/type 混用 | — |
| 25 | `igmp_neg_query_source_count_length` | 负 | source count/长度不一致 | — |


## 10. 负路径与错误处理

| ID | 错误输入 | 必须失败的边界 |
|---|---|---|
| `igmp_neg_ipv6` | IPv6 outer/group/source | IGMP 不在 IPv6；拒绝 |
| `igmp_neg_nonmulticast_destination` | Report/Query 目的为单播 | 目的地址与消息语义不符；拒绝 |
| `igmp_neg_ttl_not_one` | TTL=64 | IGMP 链路本地 TTL 不为 1；拒绝 |
| `igmp_neg_protocol_not_two` | IPv4 Protocol=17 | 不得由 UDP 承载 IGMP；拒绝 |
| `igmp_neg_bad_checksum` | 注入错误 ones-complement checksum | 校验失败；任务错误 |
| `igmp_neg_invalid_v3_record` | 未登记 Record Type 或截断 source list | v3 记录长度/类型错误；拒绝 |
| `igmp_neg_invalid_profile_version` | v1/v2/v3 与 Type/字段混用 | profile 交叉污染；拒绝 |
| `igmp_neg_query_source_count_length` | N 与实际 source bytes 不一致 | 长度不一致；拒绝 |

错误用例的 `expect` 必须严格只有 `expect_error` 和 `error_contains`，不检查错误 PCAP、packet_count、fields 或 frames。

## 11. 实现完成定义

实现完成前必须：

1. 注册 `igmp` 层并明确字段 schema（模式、消息、组、source、MRC/QQIC、records、事件状态），同时拒绝未知字段和 IPv6 伪 profile；负例 fault-injection 键必须按上述 schema 注册，不能依赖任意未声明 JSON 键。
2. 逐字段构造 v1/v2/v3 消息，计算 IPv4 总长度、IGMP 长度和 one's-complement checksum；通过奇数长度、多源、多记录和辅助数据单测。
3. 在 planner → worker → PCAP 输出的完整路径传递 Protocol=2、TTL=1、组播目的和事件顺序；错误在任务终态可见。
4. 验证正例的 packet_count、fields、frames，验证负例仅有严格的错误契约；运行前先确认层已注册。未注册时只能报告 rejected/not runnable，不能报告 suite 通过。
5. 增加多会话状态隔离、重传相等性、v1/v2/v3 profile 互斥和 IPv4/IPv6 拒绝的集成测试。

## 12. 修订记录

- v1.0.0（2026-08-20）：建立 RFC 1112/2236/3376 的 IGMPv1/v2/v3 设计、25 个原子场景、IPv4 载体边界、v3 source/record 结构、checksum/状态/负路径契约；明确仅设计阶段，不修改 Go（编程语言）实现。
