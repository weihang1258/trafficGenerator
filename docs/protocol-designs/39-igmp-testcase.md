# IGMP（互联网组管理协议，Internet Group Management Protocol）测试用例设计

> 版本：v1.0.0（设计阶段）
> 日期：2026-08-20
> 配套设计：`docs/protocol-designs/39-igmp-design.md`
> 机器契约：`trafficgen/test/protocol_pcap/cases/igmp.json`
> 状态：`igmp` 层尚未注册；本文只定义实现后的 PCAP 断言，不宣称当前 suite（测试套件）可运行。

## 1. 测试原则

用例由设计 §2–§9 逐项派生，共 25 个唯一 ID，正例 17 个、负例 8 个，顺序与设计 §10 及 JSON 完全一致。每个正例都断言 `packet_count`、`fields` 和 `frames`，并观察 IPv4 Protocol=2、TTL=1、目的组播地址、IGMP Type/profile 及 checksum 存在性。无 IPv4 options、无 VLAN 的正例中 IGMP 起点固定为 offset 34；checksum 字节不在 `frames.hex` 中固化，改由 `fields.nonzero=true` 观察并由实现单测做 one's-complement 逐字节复算。

每个负例的 `expect` 恰有两个键：`expect_error: true` 和 `error_contains`。负例不包含 `packet_count`、`fields`、`frames` 或“错误 PCAP”断言。当前层未注册，执行这些 JSON 前必须先注册实现；否则只能记录 rejected/not runnable。

## 2. 原子用例索引

| # | ID | 覆盖 | packet_count |
|---:|---|---|---:|
| 1 | `igmp_v1_general_query` | v1 General Query，224.0.0.1，MRT=0 | 1 |
| 2 | `igmp_v1_report` | v1 Report，组地址目的 | 1 |
| 3 | `igmp_v2_general_query` | v2 Query，MRT 十分之一秒 | 1 |
| 4 | `igmp_v2_group_specific_query` | v2 Group-Specific Query | 1 |
| 5 | `igmp_v2_report` | v2 Report | 1 |
| 6 | `igmp_v2_leave` | v2 Leave，224.0.0.2 | 1 |
| 7 | `igmp_v3_general_query` | v3 MRC/QRV/QQIC | 1 |
| 8 | `igmp_v3_source_specific_query` | v3 source list 与 S/QRV | 1 |
| 9 | `igmp_v3_include_record` | MODE_IS_INCLUDE | 1 |
| 10 | `igmp_v3_exclude_record` | MODE_IS_EXCLUDE | 1 |
| 11 | `igmp_v3_change_records` | 两种 mode-change 记录 | 1 |
| 12 | `igmp_v3_allow_block_sources` | ALLOW_NEW/BLOCK_OLD | 1 |
| 13 | `igmp_profile_matrix` | v1/v2/v3 profile 顺序 | 3 |
| 14 | `igmp_retransmit_state` | 状态、重传、报文相等 | 3 |
| 15 | `igmp_multi_group_sessions` | 多会话、多组 | 4 |
| 16 | `igmp_ipv4_outer_invariants` | Protocol/TTL/目的地址 | 1 |
| 17 | `igmp_v3_query_boundaries` | QRV=7、MRC/QQIC=255、三源 | 1 |
| 18 | `igmp_neg_ipv6` | IPv6 N/A/拒绝 | — |
| 19 | `igmp_neg_nonmulticast_destination` | 非组播目的 | — |
| 20 | `igmp_neg_ttl_not_one` | TTL=64 | — |
| 21 | `igmp_neg_protocol_not_two` | Protocol=17 | — |
| 22 | `igmp_neg_bad_checksum` | checksum 错误 | — |
| 23 | `igmp_neg_invalid_v3_record` | v3 记录错误 | — |
| 24 | `igmp_neg_invalid_profile_version` | profile/type 混用 | — |
| 25 | `igmp_neg_query_source_count_length` | N 与 source bytes 不一致 | — |

## 3. Positive（正例）断言约定

- `ip.proto=2`、`ip.ttl=1` 是每个正例的字段断言；目的地址按消息表逐包断言。
- `igmp.checksum` 只用 `nonzero=true`，不写未经独立复算的固定十六进制值。`frames` 从 offset 34 的 Type/Code、offset 38 的 group 或 offset 42 的 v3 record 开始，避开 checksum 常量。
- v3 Query 的 offset 42 为 `Resv/S/QRV, QQIC, N`；offset 46 起为 source list。v3 Report offset 42 起为 Group Record。
- 多包用例用每个 packet 的 `fields` 和 `frames` 指明事件顺序；运行期随机 IP/校验和不固化为常量。重传用 `same_as_packet` 观察相同的 group/type/source 集合。

## 4. Negative（负例）契约

`igmp_neg_ipv6`（`address_family=ipv6`）、`igmp_neg_nonmulticast_destination`、`igmp_neg_ttl_not_one`、`igmp_neg_protocol_not_two`、`igmp_neg_bad_checksum`（`wire_fault.kind=checksum`）、`igmp_neg_invalid_v3_record`（`wire_fault.kind=record`）、`igmp_neg_invalid_profile_version` 和 `igmp_neg_query_source_count_length`（`wire_fault.kind=source_count`）必须都以任务错误终止。每项 JSON 的 `expect` 只含 `expect_error`/`error_contains`，不允许通过空 PCAP、0 packet 或忽略错误来满足断言。

## 5. 三方一致性清单

1. 设计、本文和 JSON 各有相同的 25 个 ID、相同顺序、17 正例与 8 负例。
2. 正例 packet_count 序列为 `[1,1,1,1,1,1,1,1,1,1,1,1,3,3,4,1,1]`；负例没有 packet_count。
3. 17 个正例都有 `has_payload=true`、fields 和 frames，并逐包观察 IPv4 Protocol 2、TTL 1 及合法组播目的地址。
4. v1/v2 固定头长度为 8；v3 Query 为 `12+4*N`；v3 Report 按每条 Group Record 的 source/aux 长度计算，JSON frames 只固定可复算字段。
5. v3 records 覆盖 include/exclude、mode change、allow/block、source list；多组/多会话及重传状态有独立场景。
6. checksum 明确为 one's-complement；PCAP 不虚构固定 checksum 常量，错误 checksum 只走负例错误契约。
7. IPv6 只有拒绝用例，未将 MLD 或 IPv6 Next Header 当作 IGMP 正例。
8. 未注册 `igmp` 层不运行、不宣称通过；注册后才执行 MCP/suite（测试套件）和 tshark（抓包解析器）验证。

## 6. 实现后执行顺序

先执行 JSON 语法、ID 顺序、正负 expect 结构、offset/hex 静态检查；再按 1–17 验证 IPv4 载体、v1/v2/v3 消息、v3 source/record、状态重传及多会话；最后按 18–25 验证每个拒绝路径和错误传播。若 tshark 未识别 IGMPv3 扩展字段，以原始 offset bytes、IP protocol/TTL 和实现单测为补充证据，不凭名称字符串宣称通过。

## 7. 修订记录

- v1.0.0（2026-08-20）：建立 17 个正例与 8 个负例，覆盖 RFC 1112/2236/3376、IPv4 载体、v3 source/record、状态/重传、多会话、边界及严格错误契约。
