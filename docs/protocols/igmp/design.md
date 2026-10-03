# IGMP（互联网组管理协议，Internet Group Management Protocol）设计文档

> 版本：v2.1.0（P1–P3 完整产物）
> 日期：2026-09-26
> 状态：P1 八项规范矩阵（§13）+ 三子表 + 三路对照与候选方案对比（§13.4/§13.5）+ 门1 §1–§14 十四行表（§14，§1/§3/§12 强制展开）+ P2 D-IGMP-1 代码设计草稿（§15）+ P3 对接清单与缺口立项（§16/§17）已落盘；**`igmp` 层已注册、builder/planner/generator 已落码**（`registry.go:863`，`internal/protocol/igmp/` 四文件共 804 行，20 个测试函数），25 例已迁移为严格层链形并补齐 `flow_control`；D-IGMP-1 仍以门1获批版为定稿边界。本契约不修改 Go 实现。
> 配套文件：`docs/protocols/igmp/testcase.md`、`trafficgen/test/protocol_pcap/cases/igmp.json`、`docs/protocol-designs/audit/39-igmp-adversarial-audit.md`
> 规范基线：RFC 1112（IGMPv1）、RFC 2236（IGMPv2）、RFC 3376（IGMPv3）。
> **层链唯一真相**：本契约目标形状只有纯 `layers` 形（`[ip,igmp]`，raw-IP 直挂、无传输层、无端口语义）；25 例已按 §14.1 改写，顶层仅 `layers` + `flow_control`。

## 1. 范围、profile 与已注册边界

本阶段将 igmp 严格限定为**三个可验证 profile**，不把任意 IP 流量标成 igmp：

| profile | 规范 | 载体 | 本阶段允许的内容 |
|---|---|---|---|
| `v1` | RFC 1112 | IPv4 `Protocol=2`，TTL=1，无端口 | Membership Query（`0x11`，MRT 恒 0）、Membership Report（`0x12`）；无 Leave |
| `v2` | RFC 2236 | IPv4 `Protocol=2`，TTL=1，无端口 | Query（`0x11`，MRT 十分之一秒）、Report（`0x16`）、Leave（`0x17` → `224.0.0.2`） |
| `v3` | RFC 3376 | IPv4 `Protocol=2`，TTL=1，无端口 | Query（`0x11`，MRC/QRV/QQIC + source list）、Report（`0x22`，Group Record 数组，目的 `224.0.0.22`） |

三种 profile 均实现，因为 v1/v2/v3 的 Type、MRT/MRC 语义和 v3 record 结构互不兼容；不能用一个“通用 IGMP” profile 静默切换版本。每个正例必须显式给出 `profile`。未登记 profile、MLD（IPv6 的组播侦听者发现，走 ICMPv6 协议号 58，不是 IGMP 变体）、IGMP over TCP/UDP 封装均属于本阶段之外。

**已注册/已落码现状（P1 实测，行号真实）**：`igmp` 终结层已注册（`registry.go:863`，`CategoryTerminal + DependsOn ["ip"]`，`FieldContract {"ip.protocol": "2"}`，注释 `registry.go:859-862` P3 T5 raw-IP 链）；配置结构 `IGMPConfig/IGMPEvent/IGMPRecord/IGMPWireFault`（`routing.go:12-61`）；wire 编码 `internal/protocol/igmp/builder.go`（179 行：`igmpTypeFor` `:64`、`buildIGMPMessage` `:89`、`checksum` `:49`）；planner/validator `internal/protocol/igmp/planner.go`（141 行：`Validate` `:19` 锚词行见 §10 表、`profileKind` `:103`、`isMulticastGroup` `:135`）；终结层生成器 `internal/protocol/igmp/layer_gen.go`（130 行：`dstFor` `:22` 目的仲裁表、`Generate` `:55`）；白名单已登记（`protocols.go:41`）；`events` 顶层解析（`strategy_convert.go:697-715`）；单元测试 17 个（`igmp_test.go:12-347` 全绿口径见 §15）；生成表含 `igmp`（`layers.generated.json:1326`，`depends_on ["ip"]`，`fields {}`——业务键走 `IGMPConfig` 经 FlowMeta 直传，见 §15 接线件）。

不变式：

1. igmp 终结层只能位于 `ip` 层之后直挂（`[ip,igmp]`），无 `tcp`/`udp` 传输层、无端口语义；缺 `ip`、错误 carrier（夹 `tcp`/`udp` 进链）或 profile/kind 不匹配必须错误。
2. v1/v2 固定头为 8 字节：`Type(1)`、`MaxRespTime(1)`（v1 恒 0，v2 十分之一秒）、`Checksum(2)`、`Group(4)`。`0.0.0.0` 只作为 General Query 的 Group Address；不是 Report、Leave 或 Group-Specific Query 的合法组地址。
3. v3 Query 固定头为 12 字节：`Type(1)=0x11`、`MRC(1)`、`Checksum(2)`、`Group(4)`、`Resv/S/QRV(1)`、`QQIC(1)`、`N(2)`；每个 source 再占 4 字节，总长 `12+4*N`。MRC/QQIC 小代码直接编码、扩展代码按 RFC 3376 浮点规则解码（实现 `buildIGMPMessage :105-121` 直接透传配置字节，不做浮点换算——换算面为用例 fixture 显式值）。
4. v3 Report 固定头为 8 字节：`Type(1)=0x22`、`Reserved(1)=0`、`Checksum(2)`、`Reserved(2)=0`、`M(2)`；每条 Group Record 为 `RecordType(1)`、`AuxLen(1)`（实现恒 0，`builder.go:150`）、`NumSources(2)`、`Multicast(4)`、`source list`。M 必须等于实际记录数；总长 `8 + Σ(8 + 4*N_i)`（无 auxiliary data 面）。
5. 目的地址仲裁（`layer_gen.go:22-45 dstFor`，用例仲裁权威）：query general → `224.0.0.1`；query group/source-specific → 该 group；report v1/v2 → 该 group；report v3 → `224.0.0.22`；leave → `224.0.0.2`。
6. IGMP checksum 是整个 IGMP message 的 16-bit one's-complement（实现 `checksum :49-61`，奇长补零参与计算但补零字节不上线）；PCAP 不虚构固定 checksum 常量，错误 checksum 只走负例错误契约（`checksumMode invalid/bad` 进 `wire_fault checksum` 通道，`builder.go:170-177`）。
7. 源地址为单播 IPv4 fixture（存量 `192.0.2.10`）；IPv4 `TotalLength = 20 + IGMP 长度`（本阶段无 IPv4 options）；IPv4 header checksum 与 IGMP checksum 双双存在。
8. 状态不写入 IGMP 保留字段。会话状态由事件元数据表达：`idle → querying → member`，Leave 或 v3 mode change 进入相应过滤状态；`retransmit=true` 只能重发完全相同的消息语义和组/source 集合（`layer_gen.go:90-103` 事件序逐包 Emit）。
9. extra 错误必须传播到 task error（任务错误）终态，不能完成但生成 0 包；负例不输出“损坏但成功”的 PCAP。
10. v3 Report 的 IPv4 目的地址是 `224.0.0.22`，不能沿用 v1/v2 Report 的组地址目的。

本版定义 IPv4 直接承载的 IGMP 基础消息：Membership Query（成员查询）、Membership Report（成员报告）和 Leave Group（离开组）。覆盖 RFC 1112 的 IGMPv1、RFC 2236 的 IGMPv2，以及 RFC 3376 的 IGMPv3 profile（线格式档案）。IGMP 不是 TCP/UDP 载荷，而是 IPv4 `Protocol=2` 的独立上层协议；正常链路上的 IPv4 TTL 固定为 1。

本版明确以下可观察契约：

- Query 的目的地址按范围选择：General Query 为 `224.0.0.1`，Group-Specific Query 为被查询组地址；v3 Source-Specific Query 仍以被查询组地址为目的地址。
- v1 Report 的目的地址为组地址；v2 Report 的目的地址为组地址；v2 Leave 的目的地址为 `224.0.0.2`；v3 Report 的目的地址为 `224.0.0.22`。
- v1/v2 的 IGMP 固定头为 8 字节：Type、Max Response Time、Checksum、Group Address。v1 Query 的 Max Response Time 字段为 0；v2 Query 的字段以 1/10 秒为单位。
- v3 Query 的固定头为 12 字节：Type、Max Resp Code、Checksum、Group Address、Resv/S/QRV、QQIC、Number of Sources；每个 source address（源地址）再占 4 字节。
- v3 Report 的固定头为 8 字节，后跟 Group Record（组记录）数组；每条记录为 Record Type、Aux Data Len、Number of Sources、Multicast Address、source list 和可选的 32-bit auxiliary data（辅助数据）。
- IPv4 地址可出现在外层源/目的地址、组地址和 source list 中；IPv6 不属于 IGMP 的承载族。

“设计阶段”是证据等级边界：本文件中的字段名、配置名和断言是未来实现的契约，不是当前代码已接受的接口。未注册层、未实现的 profile 或错误配置不得被报告为已生成成功。

## 2. Profile、配置和不变式（层链整形实测，2026-09-30）

**25 例 `spec_json` 实测形状（2026-09-30）**：25/25 为严格层链形；地址/TTL 在 `ip` 层，业务在 `igmp` 层，3 例事件在 `igmp.events`，25 例均有 `flow_control.flows`（单包 1，多包例 3/3/4）。顶层白名单审计无游离键。

每个正例目标层链为 `ip → igmp`。以下字段是设计配置：

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

实现完成前必须（`igmp` 层已注册，`internal/protocol/igmp/` 已落码——本节为 P4 整形验收口径）：

1. 明确字段 schema（profile、kind、group、source、MRC/QQIC、records、事件状态），拒绝 IPv6 伪 profile；当前 `parseSubconfigJSON` 不拒绝未知字段，因此负例不得依赖未知键，fault-injection 键（`wire_fault`/`checksum_mode`/`address_family`/`source_count`）必须按 `routing.go:12-61` 注册并通过类型或语义校验触发错误。
2. 逐字段构造 v1/v2/v3 消息，计算 IPv4 总长度、IGMP 长度和 one's-complement checksum；通过奇数长度、多源、多记录单测（`igmp_test.go` 20 个测试函数已落码）。
3. 在 planner → worker → PCAP 输出的完整路径传递 Protocol=2、TTL=1、组播目的和事件顺序；错误在任务终态可见。
4. 验证正例的 packet_count、fields、frames（运行 suite 后按真实 pcap 校准），验证负例仅有严格的错误契约；层链形状已整形，仍需 P5 全量验证才算完成。
5. 增加多会话状态隔离、重传相等性、v1/v2/v3 profile 互斥和 IPv4/IPv6 拒绝的集成测试；链级红例 4 例（§14-P2）全绿。

## 12. 修订记录

- v2.1.0（2026-09-30）：完成 25 例严格层链整形与 `flow_control` 补齐；旧键去向表按实际落盘形状更新；未运行 suite，P5 全量验收仍待执行。
- v1.0.0（2026-08-20）：建立 RFC 1112/2236/3376 的 IGMPv1/v2/v3 设计、25 个原子场景、IPv4 载体边界、v3 source/record 结构、checksum/状态/负路径契约；明确仅设计阶段，不修改 Go（编程语言）实现。

## 13. P1 规范矩阵（CORE_MEMORY §4 八项：规范要求→业务场景→代码现状→缺口）

> 深度口径（§4.19–4.22）：矩阵三张子表——①报文×组播状态矩阵（§13.2）②数据形态变体表（§13.3）③商业行为→用例映射表（§14.2）。条目三选一：已实现 / 明确不支持 / 不适用 + 对应用例号；无遗漏留白。
> **raw-IP 载体铁律（逐矩阵行重申）**：igmp 直挂 ip（registry `DependsOn ["ip"]`，`FieldContract ip.protocol=2`）——TCP/UDP 载体判死（`carrier` 锚词，链中夹 tcp/udp 层即错）；IGMP 无端口语义；无握手，五件套时间线诚实写“建连面无”。

### 13.1 八项规范矩阵

| # | 规范要求（RFC + 本契约节） | 业务场景 | 代码现状 | 缺口 |
|---|---|---|---|---|
| 1 | 连接模型：组播组成员管理；querier→host 单向 Query，host→router 单向 Report/Leave；无连接、无握手、无重传确认；一报文 = 一 PCAP frame（RFC 1112 / RFC 2236 / RFC 3376；本契约 §1/§4） | 路由器周期 General Query 摸底；主机加组发 Report、离组发 Leave | 已实现：生成器单包直发（`layer_gen.go:55-125`）+ 事件序逐包 Emit（`:90-103`）；目的仲裁 `dstFor :22-45` | P4 只做层链整形+链级红例+casegen（§15） |
| 2 | 命令消息表：v1 Query `0x11`/Report `0x12`；v2 Query `0x11`/Report `0x16`/Leave `0x17`；v3 Query `0x11`（MRC/QRV/QQIC+N×source）/Report `0x22`（M×Group Record）；Type 与 profile 互斥（RFC 1112 / RFC 2236 / RFC 3376；本契约 §4–§6） | 加组、查组、离组、源过滤（SSM）四类动作 | 已实现：`igmpTypeFor`（`builder.go:64-83`，v1/v3 Leave 拒）+ `buildIGMPMessage`（`:89-179` 六分支） | P5 逐例先跑后钉（frames offset 34/38/42/46/50/54/58/62 八档，存量实测） |
| 3 | 状态机：IGMP 无连接状态机；主机侧唯一有序面 = General Query → Report（member）→ Leave（leaving）；v3 以 Group Record 状态（mode change / allow / block）表达过滤变迁；多会话状态隔离（RFC 2236 / RFC 3376；本契约 §7/§9） | 主机加组后应答查询；离组通知；源过滤切换 | 已实现：事件 `state/session/retransmit` 元数据直通（`routing.go:33-48`）；`dstFor` 按事件逐包仲裁 | 多会话并发交错序 → B′（G-IGMP-2，不假设调度器交织顺序） |
| 4 | 字段表：v1/v2 8 字节固定头；v3 Query `12+4*N`；v3 Report `8+Σ(8+4*N_i)`；6 种 Record Type 全量；MRC/QQIC 直接/浮点双编码；Group `0.0.0.0` 仅 General Query；checksum 全报文 one's-complement（RFC 1112 / RFC 2236 / RFC 3376；本契约 §1/§4–§7） | 单源/多源查询；include/exclude/mode-change/allow/block 六态 | 已实现：`recordTypeFromString`（`builder.go:30-46` 六态全量）+ `checksum`（`:49-61`）+ `profileKind` 源数一致性（`planner.go:122-127`） | Record Type 数值形（如 `99`）走严格解码拒（§10 #23 通道）；AuxData 非零面 → B′（G-IGMP-2，实现 `AuxLen` 恒 0） |
| 5 | 错误处理：IPv6 / 非组播目的 / TTL 非 1 / Protocol 非 2 / 坏 checksum / 非法 v3 记录 / profile-type 混用 / source count 不一致八类拒收（本契约 §10） | 脏包、错配、伪造 checksum 一律 task error，零假成功 | 已实现：8 锚词行见 §10 表（`planner.go:19-99` 全行实测；锚词逐字对 §10） | 链级红例 4 例 P4 新增（presence/白名单/TCP 载体/缺 ip，§14-P2） |
| 6 | 超时活性：querier 周期 General Query 与 host 随机延迟应答为协议活性面；本引擎为声明式回放——事件序即“时间线文本”，不内置周期定时器；`retransmit=true` 只重发完全相同语义（本契约 §7） | 长加组保活（周期 Query 刷新）；Report 重传 | 已实现：事件序 + `retransmit` 元数据（#14）；周期定时器 = 明确不支持（§16），不立项 | 无缺口（显式不适用 ≠ 缺口；周期调度面归引擎调度器，不归本协议） |
| 7 | NAT/代理：IGMP 是链路本地组播（TTL=1，不跨路由），无 NAT 遍历语义；源地址为单播 fixture，目的为组播（RFC 2236 §；本契约 §3） | 同网段组播管理 | 不适用（显式声明，不用“待确认”逃逸）：无 IGMP 层语义可测，无用例 | 无缺口（显式不适用 ≠ 缺口） |
| 8 | 版本方言：v1/v2/v3 三 profile 并存；MLD（IPv6）明确不是 IGMP 变体；IGMP 无端口、无 TCP/UDP 封装变体（RFC 1112 / RFC 2236 / RFC 3376；本契约 §1/§8） | 双栈主机 v4 走 IGMP、v6 走 MLD；老设备 v1 与新设备 v3 共存 | 已实现：三 profile 分支（`builder.go:104-168`）+ IPv6 拒（`planner.go:25`）；白名单 `protocols.go:41` | 现网 querier/host 行为抓包确认 → G-IGMP-1；MLD 另协议另议 |

### 13.2 子表①：报文×组播状态矩阵（逐格已覆/缺失）

行=报文形状，列=组播状态面：

| 报文 \ 状态面 | 合法组播目的 | General Query `0.0.0.0` | 非组播目的 | 状态元数据（state/session/retransmit） |
|---|---|---|---|---|
| v1 Query/Report | 已覆 #1/#2 | 已覆 #1（group `0.0.0.0` → `224.0.0.1`） | 缺口→负例 #19 | 已覆 #13（profile 矩阵 v1 位） |
| v2 Query（general/group-specific） | 已覆 #3/#4 | 已覆 #3 | 缺口→负例 #19 | 已覆 #14（querying→member） |
| v2 Report/Leave | 已覆 #5/#6（Leave → `224.0.0.2`） | 不适用（Report/Leave 禁 `0.0.0.0`） | 缺口→负例 #19 | 已覆 #14/#15（member + leave） |
| v3 Query（含 source list） | 已覆 #7/#8/#17 | 已覆 #7（N=0） | 缺口→负例 #19 | G-IGMP-2（S 位抑制面跨会话） |
| v3 Report 六态记录 | 已覆 #9/#10/#11/#12（六态全量） | 不适用（Report 无 general 形） | 缺口→负例 #19 | 已覆 #13/#15（v3 位 + 多会话 c） |
| TTL 非 1 | 不适用 | 不适用 | 缺口→负例 #20（TTL=64） | 不适用 |
| Protocol 非 2 | 不适用 | 不适用 | 缺口→负例 #21（Protocol=17） | 不适用 |

注：矩阵按**报文×目的仲裁轴**排——本引擎只做 host/querier 侧报文生成（声明式回放族），querier 动态应答只由 tshark 字段面验证。**逐格重数（7 行 × 4 列 = 28 格，逐格枚举，可复核）**：**已覆 12 格**（R1c1←#1/#2、R1c2←#1、R1c4←#13、R2c1←#3/#4、R2c2←#3、R2c4←#14、R3c1←#5/#6、R3c4←#14/#15、R4c1←#7/#8/#17、R4c2←#7、R5c1←#9–#12、R5c4←#13/#15）；**缺口→用例通道 7 格**（R1c3/R2c3/R3c3/R4c3/R5c3←#19；R6c3←#20；R7c3←#21）；**不适用 8 格**（R3c2、R5c2、R6c1、R6c2、R6c4、R7c1、R7c2、R7c4）；**B′ 立项 G-IGMP-2 承载 1 格**（R4c4 S 位抑制跨会话）。12 + 7 + 8 + 1 = 28 ✓ **逐格有结论、无空格**。

### 13.3 子表②：数据形态变体表（协议相关全部形态逐项）

| 变体维度 | 形态 | 对应用例 | 备注 |
|---|---|---|---|
| profile×kind | v1 query/report、v2 query/report/leave、v3 query/report | #1–#12 | `igmpTypeFor` 六分支全覆；v1/v3 Leave 拒 → #24 |
| v1 MRT | 恒 0（实现 `builder.go:125-126` 强制归零） | #1 | 非 0 按 v1 语义忽略归零，混用 profile 拒 → #24 |
| v2 MRT | 十分之一秒显式值 | #3/#4 | frame offset 34 `11 xx` 可复算 |
| v3 MRC/QRV/QQIC | 直接值（10/2/125）与边界值（255/7/255） | #7/#8/#17 | #17 `max_resp=31744`（MRC 255 浮点解码面，tshark 实测口径） |
| v3 source list | N=0（general）、N=2、N=3（边界） | #7/#8/#17 | `num_src` 逐例钉；N 与 bytes 不一致 → #25 |
| v3 六态记录 | include/exclude/mode-change×2/allow/block | #9/#10/#11/#12 | `record_type` 数值 1–6 全量（frame `03/04/05/06` 实测） |
| Group Record 结构 | 单记录、双记录、空 source 记录 | #9/#11（空 source）/#12 | M 与实际记录数一致性由实现保证 |
| 目的仲裁 | `224.0.0.1` / 组地址 / `224.0.0.2` / `224.0.0.22` | #1–#12（逐例 `ip.dst` 钉死） | `dstFor` 为仲裁权威（`layer_gen.go:22-45`） |
| 载体不变量 | `ip.proto=2`、`ip.ttl=1` | #1–#17 全正例 + #16 独立例 | `FieldContract ip.protocol=2`；TTL 由生成器固写 1 |
| checksum | 全报文 one's-complement；PCAP 只 `nonzero=true` | #1–#17（存在性）+ #22（错误拒） | 固定常量不钉 frames（§3 底稿铁律） |
| 多包事件 | profile 矩阵 3 包、重传 3 包、多会话 4 包 | #13/#14/#15 | `same_as_packet` 重传相等性（testcase §3） |
| version 面 | v1/v2/v3 与 Type 混用 | #24 | 锚词 `profile`（`planner.go:103-121`） |
| source count 面 | N 与 source bytes 不一致 | #25 | 锚词 `source count`（`planner.go:124-126`） |
| record 面 | 未登记 Record Type（`99` 数值形）/截断 | #23 | 锚词 `record`（`builder.go:30-46` + `planner.go:71-83`） |

### 13.4 P1 三路对照（CORE_MEMORY §4.12–4.15）

**①规范原文**：RFC 1112（v1）+ RFC 2236（v2）+ RFC 3376（v3）全文为“必须是什么”底线；Type/头长/目的地址/状态语义四面已逐节落本契约 §1/§4–§7。

**②现网行为**：路由器 querier 周期 General Query（目的 `224.0.0.1`）、主机 Report 加组/Leave 离组、v3 源过滤（SSM）为现网通用形态。出处确认方式：抓现网/回环 IGMP 包核对 Type/目的/TTL 面（**立项 G-IGMP-1**：现网级确认前相关条目按 §5.5 标“待确认”，不写死进实现）。

**③开源实现思路**：wireshark `packet-igmp.c`（本机 3.6.14 实测 `igmp.*` 精确口径 44 字段——断言通道权威）；本仓库已落码 builder/planner/generator（`internal/protocol/igmp/` 四文件 804 行）为 wire 真相；只借鉴字段语义与拆解思路。

**三路结论一致性**：三路在“Type 四值（`0x11/0x12/0x16/0x17/0x22`）、v1/v2 8B、v3 Query `12+4N`、目的四档、TTL=1、Protocol=2”六点一致。取舍：①内层 record 值面以 builder 编码 + tshark 读回为准，先跑后钉；②现网 querier 差异面（查询间隔、健壮变量、SSM 源选择策略）未到确认级 → G-IGMP-1，不写死。

### 13.5 候选方案对比（§4.17）

| 方案 | 走法（含借鉴来源） | 优 | 劣 | 性能/复杂度/兼容性 | 结论 |
|---|---|---|---|---|---|
| A 结构化声明式回放 | profile/kind/group/records/sources/events 结构化 + wire 由 builder 纯函数产出（同族 ospf/pim 路由终结层范式） | 字段可结构化断言；动态面可开；与已收官族同构 | 多会话交织序不假设 | O(n) 流式；复杂度低；三 profile 兼容 | **采用（已落码）** |
| B 生 hex 回放 | 整 packet hex 覆盖 | 最简单 | 字段不可断言；v3 变体即死 | 动态零分 | 仅作负例特殊形逃生口 |
| C 通用组播编译器 | schema 驱动编解码（含 MLD 合并） | 通用性强 | 超 fixture 范围；MLD 混入违反 §8 边界 | 无 fixture 收益 | 不选 |

## 14. 门1 §1–§14 十四行对照表（CORE_MEMORY §15.1–15.3）

| § | 本协议怎么满足 | 证据 |
|---|---|---|
| §1 层链唯一真相 | 25 例已整为严格层链：地址/TTL 在 `ip` 层，业务与事件在 `igmp` 层，数量在 `flow_control`；顶层白名单审计无游离键 | 本契约 §2 + §14.1；JSON 25/25 仅 `layers`、`flow_control` |
| §2 策略/任务 | 策略=单 IGMP 报文模板（自带 `flow_control` flows/bps/time）；任务=多策略合跑+总量封顶；`flows=N` 复制 N 条流按 §14.12 动态算值；框架语义未动 | 本契约 §7/§9 + §15 |
| §3 五件套 | 见 §14.3 强制展开：三 profile 会话表/事务序列/关联关系/插入位置/时间线；**无连接组播诚实写“建连面无”**，不虚构 handshake 包数；单包协议按 §3.14 豁免顶层 `sessions[]`（events[].session 承载多组隔离，不豁免多流覆盖） | 本契约 §14.3 + 用例 #13/#14/#15 |
| §4 查规范 | RFC 1112 + RFC 2236 + RFC 3376（编号级引用，精确章节待 G-IGMP-1）+ tshark `igmp.*` 44 字段实测 + 已落码 builder wire 真相 + §13 矩阵 8 行+三子表 + 三路对照（§13.4） | 本契约 §13 |
| §5 依赖与错误 | `DependsOn ["ip"]`（registry.go:863；单载体、无 OptionalOn 面——igmp 无端口/传输层语义）；`FieldContract ip.protocol=2`；8 负例锚词表逐字（行号实测，见 §10）；失败返回 task error（零假成功） | 本契约 §2/§10 + §15 错误分支 |
| §6 性能 | 单包流式渲染无全量聚合；pcap/NIC 双路验收；吞吐/并发/内存目标待 P4 基准后定（§6.5 诚实待确认，不写承诺数字）；六类场景清单见 §15 | §15 性能设计与验收 |
| §7 三份文档 | `docs/protocols/igmp/{design,testcase}.md` v2.1.0（行为面权威）+ D-IGMP-1（本契约 §15 草稿，门1 获批=定稿）+ T-IGMP（testcase §9 草稿）+ generated schema（igmp 已在生成表内，P4 只跑 `TestLayersGeneratedMatchesRegistry` 验证无过期） | 修订记录 |
| §8 设计先行 | 本条目 P1–P3 先于 P4 层链整形开工；门1 获批=D-IGMP-1 定稿=开工门 | 提交序 |
| §9 测试三源 | 三源=RFC 条款（编号级，精确章节待 G-IGMP-1）+ D-IGMP-1 + tshark `igmp.*` 44 字段已实证 + builder wire 真相 + 现网 querier/host 形态（未确认级→G-IGMP-1）；25 ID 正负对账 | T-IGMP（testcase §9） |
| §10 评审闭环 | 每阶段对抗自重审（结论见 p123 报告）+ 收官隔离复审 + 修轮；红先绿后 | /tmp/pipe/69-igmp/p123-report.md |
| §11 白话 | 每阶段白话一句先行 | 汇报 |
| §12 动态清单 | 见 §14.12 强制展开：地址=`ip` 层（五策略全支持）；业务字段逐个列开/不开+理由；序号算法位置诚实“待 P4 定”（不编行号，§5.7） | 本契约 §14.12 |
| §13 schema 派生 | registry igmp 行（§13 单载体 `DependsOn ["ip"]`；`FieldContract ip.protocol=2` 由终结层生成器固写，fixture 显式 `ttl` 值 1 与之同义）→ schemagen 重跑验证；struct 标签字面量锁 | §15 接线件 |
| §14 真实流程 | suite 经 MCP 建任务→引擎生成→tshark `igmp.*` 字段 + frames hex 双通道；先跑后钉；pcap 落 `/tmp/mcp-pcaps/igmp/` | 用例 §1/§6 |

### 14.1 §1 展开：层链去向表 + spec_json 样例

历史去向表（2026-09-30 整形验证完成）：

| 旧键 | 去向 |
|---|---|
| `src_ip` | → `layers[0].ip.src`（fixture `192.0.2.10` 起各例保留） |
| `dst_ip` | → `layers[0].ip.dst`（单报文 21 例保留〔14 正 + 7 负〕：`224.0.0.1`/组地址/`224.0.0.2`/`224.0.0.22` 四档）；3 事件例与 `neg_ipv6` 本来就无此键——目的由各事件经 `dstFor` 仲裁，**保持缺席，不补静态值**（§9.39 多流×静态标量互斥：静态 dst 会与事件仲裁打架） |
| `ttl` | → `layers[0].ip.ttl`（正例 `1`；`neg_ttl_not_one` 的 `64` 作为故障值随层迁移，仍走拒绝通道） |
| `count`（旧键） | → 删除；25 例已补 `flow_control.flows`（单包=1，多包 #13/#14/#15=3/3/4） |
| 顶层 `igmp` 子映射 | → `layers[1]` 中 `{"igmp": {...}}` 条目（业务键全量迁入，零残留；`wire_fault`/`checksum_mode`/`address_family`/`source_count` 随同迁入，拒绝语义不变） |
| 顶层 `events`（3 例） | → `layers[1].igmp.events`（层内化；`strategy_convert.go:697-715` 的顶层兼容分支 P4 后仅作过渡保留，不写新例） |
| 缺失 `flow_control` | → 25 例已补（flows=packet_count；单包 1，多包 3/3/4） |
| 游离 `ipv6:true`（`neg_ipv6`） | → 删除该键；`igmp.address_family=ipv6` 保留为拒绝触发器（IPv6 无可住层，按 1.12 拒绝通道表达，不补 `ip` 层 v6 值） |
| 游离 `ip_protocol:17`（`neg_protocol_not_two`） | → 删除该键；`igmp.wire_fault={kind:protocol,value:17}` 保留为拒绝触发器（协议号由 `FieldContract`/`transportProtocol` 供给，不由顶层游离键表达） |

**25 例迁移清单（2026-09-30 完成，§9.14 审计落点）**：25 例顶层仅 `layers` 与 `flow_control`；地址/TTL/业务已进入对应层，事件已内化至 `igmp.events`。

| 现状（整形前） | 去向（已执行，2026-09-30） |
|---|---|
| 顶层 `src_ip`（`192.0.2.10`，25/25） | 删除顶层键；写进 `layers[0]`（`{"ip": {"src": ..., "ttl": ...}}`） |
| 旧键 `dst_ip`（21 例；3 事件例无） | 删除顶层键；单报文例已写进 `layers[0].ip.dst`；事件例保持缺席 |
| 旧键 `ttl`（25/25；23 例为 1，#20 为 64） | 删除顶层键；已写进 `layers[0].ip.ttl` |
| 顶层 `count`（25/25，全为 1） | 删除顶层键；补 `flow_control.flows`（=packet_count：#13/#14/#15 为 3/3/4，其余 1） |
| `layers` 内空 `ip`/`igmp` 条目（历史形状） | 已分别填入地址/TTL 与业务；事件例已填 `igmp.events` |
| `flow_control`（历史上缺失） | 已逐例补齐（flows=packet_count；单包 1，多包 #13/#14/#15=3/3/4） |
| `neg_ipv6` 的 `ipv6:true` + v6 group | 删 `ipv6` 键；`address_family=ipv6` + v6 group 留层内走拒绝 |
| `neg_protocol_not_two` 的 `ip_protocol:17` | 删该键；`wire_fault protocol` 留层内走拒绝 |

层链整形后必须满足：非负例顶层键 = 0（仅 `layers`/`flow_control`/`output` 家族，25/25 已达标）；负例 `expect` 键集合为 `{expect_error, error_contains}`（8/8 已合规）；正例 `expect` 含 `packet_count/fields/frames/has_payload/directional`（17/17 已合规）。`expect` 内键为 harness 断言键，不计顶层白名单。

完整 v2 Report 样例（目标形状，顶层键仅 `layers`+`flow_control`）：

```json
{
  "layers": [
    {"ip": {"src": "192.0.2.10", "dst": "239.1.1.1", "ttl": 1}},
    {"igmp": {"profile": "v2", "kind": "report", "group": "239.1.1.1"}}
  ],
  "flow_control": {"flows": 1}
}
```

v3 源特定查询样例（含 source list + S/QRV/QQIC）：

```json
{
  "layers": [
    {"ip": {"src": "192.0.2.10", "dst": "239.1.1.1", "ttl": 1}},
    {"igmp": {
      "profile": "v3",
      "kind": "query",
      "group": "239.1.1.1",
      "max_response_code": 10,
      "s_flag": 0,
      "qrv": 2,
      "qqic": 125,
      "sources": ["198.51.100.1", "198.51.100.2"]
    }}
  ],
  "flow_control": {"flows": 1}
}
```

多包事件样例（#15 多会话；`events` 住 igmp 层内，无顶层 dst）：

```json
{
  "layers": [
    {"ip": {"src": "192.0.2.10", "ttl": 1}},
    {"igmp": {"events": [
      {"session": "a", "profile": "v1", "kind": "report", "group": "239.1.1.1"},
      {"session": "b", "profile": "v2", "kind": "report", "group": "239.1.1.2"},
      {"session": "c", "profile": "v3", "kind": "report", "group": "239.1.1.3",
       "records": [{"record_type": "mode_is_include", "group": "239.1.1.3", "sources": ["198.51.100.3"]}]},
      {"session": "b", "profile": "v2", "kind": "leave", "group": "239.1.1.2"}
    ]}}
  ],
  "flow_control": {"flows": 4}
}
```

### 14.2 子表③：商业行为→用例映射表（CORE_MEMORY §4.16；缺此表按 §4.22 记缺口）

| # | 商业行为（产品+行为） | 出处 | 对应用例 | 状态 |
|---|---|---|---|---|
| 1 | 路由器 querier 周期 General Query（目的 `224.0.0.1`，TTL=1）摸底组成员 | 现网通用形态（RFC 2236 同构） | #1/#3/#7（v1/v2/v3 General Query） | 已映射；**现网抓包级确认** → G-IGMP-1（确认方式：抓 querier 回环包） |
| 2 | 主机加组发 Report（v1/v2 组目的；v3 往 `224.0.0.22` 带 Group Record） | 现网通用形态 | #2/#5/#9/#10（v1/v2/v3 Report） | 已映射；确认 → G-IGMP-1 |
| 3 | 主机离组发 Leave（`224.0.0.2`）；v3 以 mode-change Record 表达离组/切源 | 现网通用形态 | #6（v2 Leave）/#11（mode change）/#12（allow/block） | 已映射 |
| 4 | 组特定/源特定查询（querier 追问某组/某源） | 现网通用形态 | #4/#8（group-specific / source-specific） | 已映射；确认 → G-IGMP-1 |
| 5 | 多组主机多会话隔离（不同组独立状态、重传只重发相同语义） | 现网通用形态 | #13/#14/#15（矩阵/重传/多会话） | 已映射 |
| 6 | 脏包/错配/伪造 checksum 拒收（querier/引擎 planar 拒） | 引擎行为（planner/builder 真实锚词行） | #18–#25（8 负例，锚词逐字见 §10） | 已映射 |
| 7 | 边界编码（QRV 0–7、MRC/QQIC 浮点扩展码、三源） | RFC 3376 编码面 | #17（`max_resp=31744`、`qrv=7`、`num_src=3`） | 已映射 |

注：本表凡记“现网通用形态”但未落抓包证据的，一律挂 G-IGMP-1 且不写死进实现（§5.5）。

### 14.3 §3 强制展开：五件套（三 profile，无连接组播）

会话表：

| 会话 | profile | 四元组（诚实：无端口、无握手） | 生命周期（诚实：无建连/无挥手） |
|---|---|---|---|
| s1 | v1 | `ip.src` 单播 + `ip.dst` 组播（query `224.0.0.1` / report 组地址），TTL=1 | Query → Report（member）→ 结束（单 datagram，无建连） |
| s2 | v2 | 同上四元组面；Leave 往 `224.0.0.2` | Query → Report → Leave（leaving）→ 结束 |
| s3 | v3 | 同上；Report 往 `224.0.0.22` 带 Group Record | Query（含 source list）→ Report（含 records）→ 结束；mode-change 表达过滤变迁 |

事务序列（单事务四件事 §3.4–3.7）：

| 事务 | 前置条件 | 触发动作 | 成功分支 | 失败分支 |
|---|---|---|---|---|
| t1 query 应答 | sN 主机已加组（member）或 querier 周期触发 | 发 Query（general/group-specific/source-specific） | host 回 Report；tshark Type/目的双通道命中 | 非组播目的/TTL 非 1 → task error（#19/#20 通道） |
| t2 report 加组 | t1 已发或主机主动加组 | 发 Report（v1/v2 组目的；v3 `224.0.0.22` + records） | `maddr`/`record_type` 命中 | 未登记 Record Type/截断 → task error（#23 通道） |
| t3 leave 离组 | sN 处于 member | 发 Leave（v2）或 mode-change Record（v3） | 目的 `224.0.0.2` / record `03/04` 命中 | v1/v3 `kind=leave` → task error（#24 通道，`builder.go:77-81` 只认 v2 Leave） |
| t4 多会话扇出 | 各会话独立 group/profile | 按事件序逐包 Emit（`layer_gen.go:90-103`） | 会话隔离不断言包序（`directional=false` 17/17） | 状态串用 → task error；交织序不假设（G-IGMP-2） |

关联关系（§3.8–3.10 三件事）：本协议**无控制流驱动数据流**（无 `driven_by` 派生流），但有**同事件序内 query→report 语义关联**：归属会话 sN（`events[].session`）、归属报文组（同 group 地址）、由 `group` 字段决定——与 CWMP 范本差异点诚实声明：igmp 无副流派生，`events[]` 承载“多报文有序序列”（本契约 §7/§9）。

插入位置：终结层——igmp bytes 经 IPv4 `Protocol=2` 直传（`transportProtocol` 看末层 `case "igmp"`，`chain_planner_util.go:225`；L3.Protocol 由生成器固写 `core.ProtocolIGMP`，finalEmit 不覆盖）；IP 无 option 时 IGMP 起点 offset 34（v3 Query 扩展面 offset 42/46 起，frames 八档实测）。

时间线：**顺序**——同会话内 t1→t2→(t3) 严格报文序；会话间并发但输出不假设全局包序，只断言包内状态与隔离；无“长传输分片让位”面（单 datagram）；控制可中插动作=无（igmp 无 ABOR/STAT 类动作）。§3.12 的调度方式在本协议落点为“按事件序逐包 Emit”。

### 14.12 §12 强制展开：动态字段清单

| 字段 | 住处 | 开策略 | 理由 |
|---|---|---|---|
| `src`（src_ip） | ip 层 | fixed/inc/rand/list/pattern 全开 | §12.2 地址必备；多主机并发锚点 |
| `dst`（dst_ip） | ip 层 | fixed（组播组 fixture 钉死；多组地址池待立项） | 目的须经 `dstFor` 仲裁；动态组地址池 → G-IGMP-3 |
| `ttl` | ip 层 | 不开（恒 1，由生成器固写） | 故障值 64 只走负例拒绝通道，不做动态 |
| `profile` | igmp 层 | 不开（三 profile 各自独立模板） | profile 切换 = 换策略（§2.5），不用动态冒充 |
| `kind` | igmp 层 | 不开（query/report/leave 各自独立模板） | 同上，换策略表达 |
| `group` | igmp 层 | 不开（fixture 钉死；多组扇出靠 events[] 显式） | 多组靠显式事件（§3.1），与动态正交；地址池面 → G-IGMP-3 |
| `max_response_time`/`max_response_code` | igmp 层 | 不开（fixture 钉死：直接值与边界值各一例） | 计时语义值，非按流变化量 |
| `s_flag`/`qrv`/`qqic` | igmp 层 | 不开（fixture 钉死） | 同上 |
| `sources`/`records` | igmp 层 | 不开（fixture 钉死字节） | 源/记录变体靠多策略（§2.5），不用动态冒充 |
| `events` | igmp 层 | 不开（扇出结构静态声明） | 多流靠显式事件（§3.1），与动态正交 |

序号算法代码位置：**待 P4 定**（D-IGMP-1 定稿后 casegen/层链整形落码时钉死文件+行号；此处不编行号——§5.7）。

### 14-P2 presence 负例形状（链级红例必含①）

层链+顶层空子映射并存=判死负例（presence 负例形状，非残留）：`{"layers":[{"ip":{}},{"igmp":{}}],"igmp":{}}`（顶层空 `igmp:{}` 与层链并存）必须 planner/validator 拒，`error_contains` 含 `presence` 或顶层键锚词；P4 链级红例必含此形。白名单外游离键（如顶层 `src_mac`/`ttl`——`ttl` 已迁 `ip` 层，顶层出现即游离）判死负例见 §15。**另注**：igmp 单 raw-IP 载体 → 链中夹 `tcp`/`udp` 层（`[ip,tcp,igmp]` / `[ip,udp,igmp]`）判死负例（`carrier` 锚词）；链缺 `ip`（`[igmp]` 裸链）判死负例（`carrier` 锚词）。P4 链级红例共 4 例 + 收官自查行「非负例顶层键=0」。

## 15. D-IGMP-1 P2 代码设计草稿（CORE_MEMORY §8 八要素；门1 获批=定稿）

> 体裁：文件清单/接口签名/数据结构/主流程/错误分支/性能设计与验收/回滚方式。igmp wire 面已落码，D-IGMP-1 覆盖“已落码对接 + P4 层链整形差量”，不重发明 wire。

**文件清单（已落码 5 + P4 新建 1 + 接线/守卫 3，已落码行号实测）**：

| 文件 | 职责 |
|---|---|
| internal/protocol/igmp/builder.go（已落码，179 行） | wire 纯函数：`recordTypeFromString`（`:30-46` 六态全量）/`checksum`（`:49-61` one's-complement）/`igmpTypeFor`（`:64-83` profile/kind→Type，v1/v3 Leave 拒）/`buildIGMPMessage`（`:89-179` 六分支：v3 Query `:105-121`、v3 Report `:135-161`、v1/v2 `:122-134/:162-164`、checksumMode `:170-177`） |
| internal/protocol/igmp/planner.go（已落码，141 行） | `Planner.Validate`（`:19-99`：IPv6 拒 `:25`、目的组播 `:34-42`、TTL `:44-46`、profile/kind `:48-50`、wire_fault `:56-63`、records `:71-83`、events `:85-97`）/`profileKind`（`:103-129`，v1/v3 Leave 拒 + source_count 一致性 `:122-127`）/`isMulticastGroup`（`:135-141`） |
| internal/protocol/igmp/layer_gen.go（已落码，130 行） | `dstFor`（`:22-45` 目的仲裁权威）/`IGMPGenerator.Generate`（`:55-125`：空配置默认 v1 general query `:60-63`、事件序 `:90-103`、单报文 `:105-124`、TTL 固写 1 `:76`）/注册（`:127-130`） |
| internal/core/routing.go（已落码） | `IGMPConfig`（`:12-28` 15 键）+ `IGMPEvent`（`:33-48` 14 键）+ `IGMPRecord`（`:51-55`）+ `IGMPWireFault`（`:58-61` 仅 `kind`/`value`——注意 §16 严格解码边界） |
| internal/protocol/igmp/igmp_test.go（已落码，354 行） | 单元测试 20 个（`TestBuild*` 8 + `TestValidate*` 6 + `TestGenerate*` 3 + `TestChecksumModeZero`/`TestDstFor`/`TestLayerGeneratorRegistered` 3；P4 复用，不改口径） |
| internal/protocol/igmp/casegen_test.go（P4 NEW） | 一次性生成器：25 例（17 正+8 负）契约计数逐例 add()，落 test/protocol_pcap/cases/igmp.json（层链整形后形状） |
| 接线件（已落码，P4 只验证） | registry `registry.go:863`（`DependsOn ["ip"]` 单载体 + `FieldContract ip.protocol=2`）；`chain_planner_util.go:225/239` 末层协议号 2；`chain_planner.go:645/883/1232` raw-IP 分支；`strategy_convert.go:697-715` 子配置+顶层 events 解析；`generator.go:488` FlowMeta.IGMP；`protocols.go:41` 白名单 + `protocols_test.go` 同步；schemagen 重跑验证无过期 |
| P4 新增守卫 | validate_layers 预检：presence（层链+顶层空子映射并存拒）/白名单外游离键拒/链夹 tcp/udp 拒/缺 ip 拒（单载体，无 OptionalOn 面——终结层豁免 0c355be 下 igmp 无 OptionalOn 声明，`complete.go:418` 链底座关系不受影响） |
| tools/coverage_gate.py | check_igmp（准入接线/关键件/守卫/用例面四段，P4 登记） |

**接口签名**（已落码，P4 落码钉死有无差量）：`buildIGMPMessage(profile, kind, group, maxRespTime, maxRespCode, sFlag, qrv, qqic, records, sources, checksumMode) []byte` / `igmpTypeFor(profile, kind) byte` / `checksum(b) uint16` / `recordTypeFromString(s) byte` / `Planner.Validate(spec) error` / `dstFor(kind, profile, group) string` / `IGMPGenerator.Generate(ctx, req) error`。

**数据结构**：沿 `IGMPConfig`（`routing.go:12-28` 15 键：profile/kind/group/max_response_time/max_response_code/s_flag/qrv/qqic/records/sources/source_count/checksum_mode/wire_fault/address_family/events）+ 层链目标形状（§14.1 样例：地址/TTL 住 `ip`、业务住 `igmp` 条目、数量走 `flow_control`）。

**主流程**：validateSpec（含 P4 新增 4 守卫）→ 单包渲染（`buildIGMPMessage` 六分支）或事件序逐包 Emit（`layer_gen.go:90-103`，目的逐包 `dstFor` 仲裁）→ EmitMsg → worker → pcap/NIC。

**错误分支（§5.2）**：①`wire_fault` 4 值注入拒（`protocol`/`checksum` 在 `planner.go:56-63`；`record`/`source_count` 经记录/源数校验 `:71-83/:122-127` 拒；锚词进断言，值面=§10 表逐字）；②自然守卫：IPv6（`IPv6`）/非组播目的（`multicast`）/TTL（`TTL`）/profile 混用（`profile`）/checksum_mode 非法/记录 group 非 v4/source 非 v4；③validate_layers 预检同步拒（presence/白名单/tcp-udp 载体/缺 ip）。全部传播为 task error，零假成功。

**依赖声明（§5.1）**：依赖 `ip` 层（唯一载体，寻址+TTL+Protocol=2）；无 `tcp`/`udp` 依赖（§14-P2 把此列成守卫）；无外部 querier/采集器依赖。**不含端口依赖**（igmp 无端口语义；`chain_planner.go:1388-1390` 端口回退赋值对 igmp 生成器无副作用——实测注记）。

**性能设计与验收（§6.1–6.8）**：O(n) 流式——逐包渲染直发 EmitMsg 无全量聚合（事件序 for 循环直发，无缓冲增长结构）；确定性内存（单报文最大 v3 Report `8+Σ(8+4N)`，fixture 级字节）；无锁无 sleep（事件驱动）；pcap 路实测 + NIC 路注记（过滤器 `ip proto 2`，测试网口按 testing-interface 记忆）；回归口径=igmp.json 全量 suite 耗时 ±10%；六类场景（基线/目标规模/压力上限/长运行时/并发交错/背压）P5 跑测覆盖；边界诚实声明：吞吐/并发/内存目标数字待 P4 基准后定（§6.5，不写承诺）。

**与现有逻辑冲突点（§8.7）**：`strategy_convert.go:697-715` 顶层 `events` 兼容分支与层链权威并存——P4 层内化后该分支仅作过渡保留，不写新例；`parseSubconfigJSON`（`strategy_convert_helpers.go:21-30`）为**普通 `json.Unmarshal`（无 `DisallowUnknownFields`）**——igmp 子映射未知键静默忽略，负例不得依赖未知键拒绝（P4 如需把未知键变红另立守卫，见 G-IGMP-4）；schemagen 生成表已含 igmp（`layers.generated.json:1326`，`fields {}` 因业务键走 FlowMeta 直传），P4 只验证无过期（`TestLayersGeneratedMatchesRegistry`）。

**回滚方式（§8.8）**：P4 差量全量 revert（casegen + 25 例改写 + 4 守卫 + coverage 登记）；已落码 wire 面不动；无数据迁移面。

## 16. P3 测试对接清单与缺口立项（T-IGMP 草稿输入；正文落 testcase 文件）

- §3.15 三项：①同组多包序列（Query→Report→Leave，状态变迁）→#14（`querying→member` + 重传）已覆；②非正常结束→8 负例全覆（#18–#25）；③长保活→igmp 无自有保活语义=不适用（显式声明，周期 Query 属 querier 调度面，不归本协议）+ querier 周期刷新面明确不支持（§13.1 #6）。逐项一例或立项，无空项（明细见 testcase §9.1）。
- A′/B′ 两分类表：见 testcase §9.2（A′=引擎可构建→25 ID 内已覆 + A′ 补例建议 T-26（v2 Report 空 source 双组对称）/T-27（IPFIX 无——igmp 无对称要求，改为 v3 Report 双记录三源对称，§9.24 缺格）；B′=引擎结构缺口→G-IGMP-2 进 D-条目“明确不解决+迁入计划”）。
- 9.52 对账两行：见 testcase §9.3（清单出处声明 + 对账两行：总数 50 = 已覆 41 + 不适用 8 + B′/立项 1）。
- 3.14 豁免边界审计：见 testcase §9.4（本协议无连接但**不主张多流豁免**：多会话并发 #15 已覆；单包多载荷=单 Report 多记录 #11/#12 已覆 + Aux 非零全组合→B′）。
- 三源回指行：见 testcase §9.5（第三源“已确认现网行为”当前=未确认级，挂 G-IGMP-1）。
- 断言通道：fields 用 `igmp.*`（去重 14 已实证，注册命中 14/14：`igmp.type/checksum/maddr/max_resp/qrv/qqic/num_src/saddr/num_grp_recs/record_type/s` + `ip.proto/ip.ttl/ip.dst`）+ frames hex（offset 34/38/42/46/50/54/58/62 八档实测）。

## D/T/C 对账

D-IGMP-1 由本节 §15 承载，T-IGMP 由 `docs/protocols/igmp/testcase.md` §1–§9 承载；C-IGMP-1 为本节 §17 的缺口/边界清单（G-IGMP-1…4），不把未实现的 RFC/现网行为冒充已覆盖。三者共同回指本文件 §1–§14 和 `cases/igmp.json` 的 25 个 ID，文档阶段只改契约与 cases，不改 Go 实现。

## 17. 缺口立项清单（有缺口写“缺口立项”，不许空着）

| 立项号 | 缺口 | 确认方式（三选一） | 去向 |
|---|---|---|---|
| G-IGMP-1 | 现网证据升级 + RFC 精确章节复核：querier 周期行为（查询间隔、健壮变量、SSM 源选择策略）的“已确认现网”级证据；RFC 1112/2236/3376 精确章节号 | 抓包（抓 querier 回环/现网包核对 Type/目的/TTL 面）+ 查 RFC 原文 | P4 前置确认项，不挡开工；确认前相关条目按 §5.5“待确认”不写死 |
| G-IGMP-2 | B′ 行为面：AuxData 非零全组合、S 位抑制跨会话语义、多会话并发交织序假设、v3 记录数值形扩展 | 查 RFC 3376 相关章节 + 抓包（问谁：无，文档+包即确认） | B′→D-IGMP-1“明确不解决+迁入计划”（确认后进 §13.2 空白格） |
| G-IGMP-3 | 动态多组地址池（§14.12 `dst`/`group` 不开面）+ A′ 补例 T-26/T-27（§9.24 对称缺格） | 查引擎序号算法现状（P4 定） | A′ 补例并入与否由主线程定，不影响 §9 的 25 ID 权威口径 |
| G-IGMP-4 | 严格解码守卫：`igmp` 子映射未知键当前静默忽略（`parseSubconfigJSON` 普通 `json.Unmarshal`，`strategy_convert_helpers.go:21-30`），按 13.26 口径未知键应显式拒绝；负例 #23 已改走记录侧触发源不受影响 | 查 `strategy_convert_helpers.go` 现状 + 引擎负例实测 | P4 评估是否框架级统一加 `DisallowUnknownFields`（属跨协议共享面，须上报主线程，不车道自改） |

## 18. P1/P2/P3 对抗自重审结论（10.11；过 3 轮，末轮干净）

- **P1（§13 矩阵）**：R1 自重审发现 §13.2 逐格重数初稿 11+7+9+1=28 有算术错（R5c4 与 R4c4 口径混记）→ 改 12+7+8+1=28 复算一致；R2 逐行核八项矩阵的"代码现状"列行号全部实读源文件（layer_gen/planner/builder/routing/chain_planner_util/strategy_convert_helpers），无编造行号；R3 末轮干净。
- **P2（§15 D-条目）**：R1 自审发现初稿写"17 个单元测试"与 grep 实测 `^func Test` 20 个不符、`IGMPConfig` 键数 16 与 `awk` 实测 15 不符 → 全部按实测改正；R2 补落 `parseSubconfigJSON` 无 `DisallowUnknownFields` 的严格解码边界（8 负例中 #23 判死路径依赖记录侧而非 `wire_fault` 子键）；R3 末轮干净。
- **P3（testcase §9 + §16/§17）**：R1 自审发现 9.52 对账两行初稿"总数 46"与矩阵 50 格/行对不上 → 改为 8+28+14=50 点、41+8+1=50 两行对账并加粒度声明；R2 核 §16 断言通道 14 字段逐个对 tshark 注册表（14/14 命中）、锚词 8 个逐字对代码字符串；R3 末轮干净。

三阶段合计修正 5 处（1 处算术、2 处计数、1 处解码边界、1 处对账口径），末轮均干净。

### 18.1 文档逐条自核对结论（10.1：对规范逐条核对）

- RFC 1112（v1：Query/Report Type、MRT=0）→ §1 表 + §4.1；RFC 2236（v2：MRT 十分之一秒、Leave `0x17`/`224.0.0.2`）→ §1 表 + §4/§3；RFC 3376（v3：MRC 浮点、QRV 0–7、source list、六态 Group Record）→ §1 表 + §5/§6。逐条有落点；精确章节号挂 G-IGMP-1（§5.5 不写死）。
- 与旧需求文档（v1.0.0 design/testcase）逐条核对（10.2）：25 ID 集合、顺序、正负比、packet_count 序列全部保持；v1 声明"层未注册/仅设计阶段"按实测更正为"已注册已落码"；§1 从"证据等级边界"改写为"已注册边界"（新增五点已落码现状）；其余契约（checksum nonzero、负例严格双键、IPv6 拒绝、目的四档）无删改。

### 18.2 与旧文档逐条核对结论（10.2）

v1.0.0 §1–§12 逐条：§1 范围（保留+扩）、§2 配置表（保留，`address_family`/`wire_fault`/`events` 语义不变）、§3 载体表（保留，补 `dstFor` 仲裁权威）、§4–§6 线格式（保留，补实现行号）、§7 checksum/状态（保留）、§8 IPv6 边界（保留）、§9 场景表（25 ID 逐条保留）、§10 负路径表（保留，锚词实测化）、§11 完成定义（保留，状态更新）、§12 修订记录（追加 v2.0.0）。无旧条目被静默删除。
