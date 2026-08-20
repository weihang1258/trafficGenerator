# IGMP（互联网组管理协议，Internet Group Management Protocol）设计与用例对抗审查

> 审查对象：`docs/protocol-designs/39-igmp-design.md`、`docs/protocol-designs/39-igmp-testcase.md`、`trafficgen/test/protocol_pcap/cases/igmp.json`
> 审查日期：2026-08-20
> 审查属性：设计文档阶段；不检查、不修改 Go（编程语言）实现，不运行未注册的 `igmp` 层，不宣称 MCP（模型上下文协议）套件通过。
> 结论：完成两轮自审（逐字段/长度/偏移/校验和/ID/负例契约），最后一轮 clean（通过）。

## 1. 审查口径

本审查使用两个独立视角：

- **规格可实现性视角（代码逻辑替代项）**：逐字段核对 RFC 1112/2236/3376 的 IPv4 Protocol 2、TTL 1、目的组播地址、v1/v2 固定头、v3 Query、v3 Report/Group Record、source filtering、checksum、长度、profile 和状态语义。
- **用例覆盖视角**：反查设计 §9/§10 与 testcase §2–§5，核对 25 个原子 ID、packet_count、positive fields/frames、v3 offset、checksum 非硬编码、IPv4/IPv6 边界和负例 expect 结构。

本审查不把“文件存在”误当作实现完成；层未注册时只能有设计契约，不能产生成功 PCAP 或 suite 通过结论。

## 2. 规格可实现性审查

### 2.1 已确认

1. **IPv4 载体完整**：所有正例要求 IPv4 Protocol=2、TTL=1；无 IPv4 options/VLAN 时 IGMP 起点统一 offset 34，文档说明了有 options/VLAN 时 offset 不得复用。
2. **目的地址按消息分离**：General Query=`224.0.0.1`，Group-Specific Query=组地址，v1/v2 Report=组地址，v2 Leave=`224.0.0.2`，v3 Report=`224.0.0.22`；没有把 v3 Report 错发到组地址。
3. **v1/v2 固定头**：Type/Max Response Time/Checksum/Group Address 的 8-byte 布局明确；v1 MRT=0、v2 MRT 十分之一秒语义明确，v1 不带 v3 字段。
4. **v3 Query 完整**：Type、MRC、checksum、group、S/QRV、QQIC、N 和 4-byte source list 都有字段、长度公式和边界用例。
5. **v3 Report 完整**：8-byte fixed header、M 个 records、record type/aux length/source count/group/source list/aux data 均列出；include/exclude/mode change/allow/block 都有正例。
6. **校验和边界明确**：IGMP checksum 是 one's-complement；要求清零后覆盖整个 IGMP 消息并处理奇数长度；PCAP 只断言 nonzero，不虚构未经复算常量，错误值走负例。
7. **状态/重传不污染 wire**：状态是事件 metadata，重传需保持 group/source/type 语义相等，多会话隔离有单独场景；保留字段不会承载自定义状态。
8. **IPv6 明确拒绝**：IGMP 不在 IPv6；MLD/ICMPv6 不被映射成 v1/v2/v3，IPv6 只出现在负例。

### 2.2 实现阶段守护项（不是当前 finding）

| 项目 | 当前契约 | 实现前必须验证 |
|---|---|---|
| 层注册/schema | JSON 使用建议的 `ip → igmp` 和 profile 配置 | 注册前不运行；注册后校验未知字段及协议号推导 |
| IPv4 options/VLAN | 正例固定无 options/VLAN，offset=34 | builder（构造器）增加 options/VLAN 时重新计算 offset，不复用静态断言 |
| MRC/QQIC 浮点编码 | 255 等扩展代码只作为代码边界，不写臆造秒数 | 以 RFC 3376 编码/解码单测验证 exponent/mantissa |
| checksum | PCAP 不写 checksum 常量 | 独立计算器覆盖固定头、source、records、aux 和奇数长度 |
| 状态与任务错误 | metadata/错误契约已列出 | planner→worker→writer 完整路径验证重传、超时、错误传播 |
| tshark 字段 | 原始 bytes 是补充证据 | 目标 tshark 版本不支持时不能凭 dissector（解析器）名称宣称通过 |

## 3. 用例覆盖对抗审查

### 3.1 正例逐条核对

| ID | 设计覆盖 | 必须观察的 JSON 证据 | 结果 |
|---|---|---|---|
| `igmp_v1_general_query` | v1 General Query | packet_count=1、proto/ttl/dst、Type 11、MRT 0、group 0 | 通过 |
| `igmp_v1_report` | v1 Report | Type 12、组目的、checksum nonzero、group bytes | 通过 |
| `igmp_v2_general_query` | v2 MRT | Type 11、MRT=10、224.0.0.1 | 通过 |
| `igmp_v2_group_specific_query` | v2 group query | 非零 group 同目的地址、MRT | 通过 |
| `igmp_v2_report` | v2 Report | Type 16、组地址、Protocol/TTL | 通过 |
| `igmp_v2_leave` | v2 Leave | Type 17、224.0.0.2、组地址 | 通过 |
| `igmp_v3_general_query` | MRC/QRV/QQIC | Type 11、group 0、S/QRV/QQIC/N | 通过 |
| `igmp_v3_source_specific_query` | source list | 非零 group、source count=2、source bytes | 通过 |
| `igmp_v3_include_record` | include | Type 22、destination 224.0.0.22、record 1/source | 通过 |
| `igmp_v3_exclude_record` | exclude | record 2、source list | 通过 |
| `igmp_v3_change_records` | mode change | record 3 + 4、M=2、两组 | 通过 |
| `igmp_v3_allow_block_sources` | allow/block | record 5 + 6、source filtering | 通过 |
| `igmp_profile_matrix` | v1/v2/v3 | 3 packets、types 11/16/22、profile 各自字段 | 通过 |
| `igmp_retransmit_state` | state/retry | 3 packets、query/report/report、packet 2/3 same group/type | 通过 |
| `igmp_multi_group_sessions` | multi-session/group | 4 packets、不同 profile/组、distinct group | 通过 |
| `igmp_ipv4_outer_invariants` | outer invariants | protocol=2、ttl=1、组播目的 | 通过 |
| `igmp_v3_query_boundaries` | boundaries | QRV=7、MRC/QQIC=255、N=3、三 source | 通过 |

### 3.2 负例逐条核对

| ID | 错误输入 | JSON expect | 结果 |
|---|---|---|---|
| `igmp_neg_ipv6` | IPv6 outer/group | 仅 error + `ipv6` | 通过 |
| `igmp_neg_nonmulticast_destination` | 单播目的 | 仅 error + `multicast` | 通过 |
| `igmp_neg_ttl_not_one` | TTL=64 | 仅 error + `ttl` | 通过 |
| `igmp_neg_protocol_not_two` | Protocol=17 | 仅 error + `protocol` | 通过 |
| `igmp_neg_bad_checksum` | 错误 checksum | 仅 error + `checksum` | 通过 |
| `igmp_neg_invalid_v3_record` | 非法 record/truncation | 仅 error + `record` | 通过 |
| `igmp_neg_invalid_profile_version` | profile/type 混用 | 仅 error + `profile` | 通过 |
| `igmp_neg_query_source_count_length` | N/bytes 不一致 | 仅 error + `length` | 通过 |

每个 negative 的 expect 都没有 packet_count、fields、frames、notes 或其他隐藏放行条件。

## 4. 三方静态一致性

已对三个输入文件做静态复核：

- 设计 §10、testcase §2 与 JSON 均为 25 个 ID，顺序一致；无重复、无遗漏。
- 正例 17 个、负例 8 个；正例 packet_count 为 `[1,1,1,1,1,1,1,1,1,1,1,1,3,3,4,1,1]`。
- 每个正例均含 `packet_count`、`has_payload=true`、非空 `fields` 和非空 `frames`；每个负例均无 packet_count/fields/frames，expect 键集合恰为 `{expect_error,error_contains}`。
- 所有正例的 fields 都观察 `ip.proto=2`、`ip.ttl=1` 和消息相应的组播目的；IGMP 起点/record 起点 offset 与 v1/v2/v3 长度公式一致。
- `frames.hex` 没有跨 checksum 字段写入未经复算的常量；checksum 仅由 `nonzero=true` 观察，设计和 testcase 都要求实现单测做 ones-complement 复算。
- JSON 中未声称任何当前运行结果；spec 的 `layers` 是待注册设计契约。

## 5. 第一轮自审发现与修正

### F-01（已修复：v3 Query offset）

初稿把 v3 Query 的控制字节从 offset 41 开始描述。按 Ethernet 14 + IPv4 20，IGMP 起点为 34；Type/MRC 为 34–35，checksum 为 36–37，group 为 38–41，故 Resv/S/QRV 应从 offset 42 开始，QQIC 为 43、N 为 44–45、source list 从 46 开始。已同步设计、testcase 和 JSON，所有 v3 Query frames 使用 42/46。

### F-02（已修复：v3 Report record 起点）

初稿误将 Report 第一条 Group Record 起点写为 40。v3 Report fixed header 为 8 字节，故 record 从 IGMP 起点+8=42 开始。已同步长度公式、frames 和审查表。

### F-03（已修复：checksum 常量风险）

初稿曾计划在 frames 中写固定 checksum 字节，但没有实现计算器证据。已改为 frames 跳过 checksum 字段，并在 fields 统一使用 `nonzero=true`；设计额外要求实现单测验证 one's-complement 覆盖范围、奇数长度、source/record/aux 修改。

## 6. 第二轮独立反驳与结论

第二轮逐字段反驳确认：

1. v1/v2 的 8-byte 固定头与 v3 Query 12-byte 固定头没有混用；v3 Report 的 8-byte header 与 record 起点 42 分离。
2. v2 Leave 的目的 `224.0.0.2`、v3 Report 的目的 `224.0.0.22`、General Query 的 `224.0.0.1` 均单独出现，没有由“所有组播”泛化。
3. QRV 仅占 3 bit、S 位独立、N/record count 都是网络字节序计数；source/aux 长度均以 4-byte word 计。
4. 负例覆盖 IPv6、目的、TTL、Protocol、checksum、record、profile、source length；每个错误只验证失败终态。
5. 25 个 ID、包数序列、正负数量和 JSON 可解析性闭环；未把未注册层运行结果冒充成功。

完成**自审通过 2 轮，最后一轮 clean（通过）**。当前没有遗留的文档级 finding；实现阶段守护项保持为非本阶段缺陷。
