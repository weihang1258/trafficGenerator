# PIM（协议无关组播，Protocol Independent Multicast）测试用例设计

> 版本：v1.0.0（设计阶段）
> 日期：2026-08-20
> 配套设计：`docs/protocol-designs/40-pim-design.md`
> 机器契约：`trafficgen/test/protocol_pcap/cases/pim.json`
> 状态：`pim` 层尚未实现；本文只定义实现后的 PCAP（抓包文件）断言，不宣称当前套件可运行。

## 1. 测试原则

用例从设计 §1（RFC 7761 PIM-SM、RFC 4607 PIM-SSM 和 IPv6/DF profile 边界）、§2（IPv4 Protocol 103/层链）、§3（4-byte PIM common header/checksum/无 PIM length 字段）、§4（Hello、Join/Prune、Bootstrap、Candidate-RP、Register、Register-Stop、Assert）、§5（SSM）、§6（状态/重传/多邻居多组）和 §7（错误传播）逐项派生。

PIM 是 IPv4 Protocol 103 的 raw IP（裸 IP）协议，不走 TCP/UDP；无 IPv4 option 时 PIM 起点为 `offset 34 = Ethernet 14 + IPv4 20`。一个显式事件对应一个 PIM packet；重传只有配置明确重复时才增加 `packet_count`。正例必须有 `packet_count`、`has_payload=true`、至少一个 observable（可观察字段）和至少一个 `frames` 前缀；负例 `expect` 严格只有 `expect_error`、`error_contains`，不对失败帧作断言。

PIM 公共头前缀 frame 只固定 Version/Type、Reserved 的已证实布局；checksum 使用 `nonzero` 观察，不写未经 fixture 复算的常数。PIM 没有自身 length 字段，长度通过 IPv4 total length 与实际 PIM packet 关系验证。编码地址的保留位、mask 和计数不能在本设计阶段猜测固定十六进制。

## 2. 用例索引

| # | ID | 类型 | 覆盖 | 事件数 | packet_count |
|---:|---|---|---|---:|---:|
| 1 | `pim_sm_hello_holdtime` | 正 | Protocol 103、Hello、Holdtime/interval | 1 | 1 |
| 2 | `pim_sm_hello_options` | 正 | LAN Prune Delay、DR priority、Generation ID | 1 | 1 |
| 3 | `pim_sm_hello_zero_holdtime` | 正 | Holdtime=0 边界 | 1 | 1 |
| 4 | `pim_sm_joinprune_wildcard` | 正 | `(*,G)`、wildcard source、upstream neighbor | 1 | 1 |
| 5 | `pim_sm_joinprune_source` | 正 | `(S,G)`、Join/Prune state | 1 | 1 |
| 6 | `pim_sm_joinprune_multi_group` | 正 | 多组、多 joined/pruned source | 1 | 1 |
| 7 | `pim_sm_joinprune_retransmit` | 正 | 显式重传、packet 保留 | 2 | 2 |
| 8 | `pim_sm_bootstrap_rp_set` | 正 | BSR、hash mask、RP priority | 1 | 1 |
| 9 | `pim_sm_candidate_rp_adv` | 正 | C-RP、Holdtime、组前缀 | 1 | 1 |
| 10 | `pim_sm_register` | 正 | Register flags、RP、inner IPv4 | 1 | 1 |
| 11 | `pim_sm_register_stop` | 正 | Register-Stop group/source | 1 | 1 |
| 12 | `pim_sm_assert` | 正 | group/source、RPT、metric | 1 | 1 |
| 13 | `pim_sm_dr_election` | 正 | 多 Hello、DR priority/address tie-break | 3 | 3 |
| 14 | `pim_sm_multi_neighbor_state` | 正 | 多邻居、多组、`(*,G)` 与 `(S,G)` 隔离 | 6 | 6 |
| 15 | `pim_sm_checksum_length` | 正 | checksum、IPv4 total/PIM payload length | 1 | 1 |
| 16 | `pim_ssm_joinprune_sg` | 正 | RFC 4607 具体 `(S,G)`、无 RP | 1 | 1 |
| 17 | `pim_ssm_multi_group` | 正 | 多 SSM group、具体 source | 2 | 2 |
| 18 | `pim_neg_ipv6_profile` | 负 | IPv6 PIM 独立 profile 未实现 | — | — |
| 19 | `pim_neg_checksum` | 负 | checksum 错误 | — | — |
| 20 | `pim_neg_length` | 负 | IPv4/PIM length 错误 | — | — |
| 21 | `pim_neg_type` | 负 | 未知或事件/type 不一致 | — | — |
| 22 | `pim_neg_address_family` | 负 | IPv4/IPv6 profile 混用 | — | — |
| 23 | `pim_neg_ssm_rp` | 负 | SSM 禁止 RP/Register/wildcard | — | — |
| 24 | `pim_neg_df_profile` | 负 | DF Election 独立于 RFC 7761 PIM-SM | — | — |

## 3. 正向用例契约

以下 payload（载荷）对象使用设计中的语义键；编码器必须按 RFC 7761 的消息字段和 encoded-address（编码地址）结构回填长度/计数。文档不把未由 RFC/fixture 确认的保留字节写成固定 frame。

### 3.1 Hello 与邻居选举

- **`pim_sm_hello_holdtime`**：一个 Hello，Holdtime=105、Hello interval=30、Generation ID=0x01020304，目的 `224.0.0.13`、TTL=1；断言 `ip.proto=103`、`pim.version=2`、`pim.type=0`、`pim.holdtime=105`、`pim.cksum` 非零；Hello interval=30 只作调度元数据，不作为 PCAP 字段断言和 offset 34 的 `20 00`（Version/Type=2/0，Reserved=0）前缀。
- **`pim_sm_hello_options`**：Hello 的 LAN Prune Delay（T-bit、propagation、override）和 DR Priority 为显式非平凡值，Generation ID=0x11223344；断言 option type/length/value 及 `pim.dr_priority`。
- **`pim_sm_hello_zero_holdtime`**：Hello Holdtime=0，其他 option 最小化；断言 `pim.holdtime=0`，证明零值不被默认成普通保持时间。
- **`pim_sm_dr_election`**：同一接口的三个 Hello 事件分别来自三邻居，priority 为 10、20、20，地址为 `192.0.2.10`、`.20`、`.30`；断言 3 包、各 priority/address 和会话 metadata（元数据）的 winner 为显式可复现的高 priority/地址 tie-break 结果。winner 不作为 wire field（线上字段）生成。

### 3.2 Join/Prune、树状态与重传

- **`pim_sm_joinprune_wildcard`**：一个上游邻居、组 `239.1.1.1`，joined source 为 wildcard `*`、pruned 为空，state=`upstream_join`；断言 type=3、neighbor、group、wildcard 标记、join count=1、prune count=0。
- **`pim_sm_joinprune_source`**：组 `232.1.1.1`、source `198.51.100.10`，joined 与 pruned 列表分别配置，state=`downstream_join`/`downstream_prune`；断言具体 `(S,G)`、非 wildcard 和两类计数。
- **`pim_sm_joinprune_multi_group`**：一次 Join/Prune 带 `239.1.1.1` 的 `(*,G)` 和 `232.1.1.2` 的 `(S,G)`，各自显式 joined/pruned source；断言 group_count=2、每组独立 source 列表和状态。
- **`pim_sm_joinprune_retransmit`**：同一完整 Join/Prune 事件显式发送两次，第二次 `retransmission=true`；断言 `packet_count=2`、两包 type/neighbor/group/source 相等，不断言不存在的 sequence number，也不自动生成响应。

### 3.3 BSR、RP 与注册

- **`pim_sm_bootstrap_rp_set`**：Bootstrap 显式给出 BSR 地址、BSR priority、hash mask length、一个 group range 和两个 RP-set 项（RP 地址、priority、Holdtime）；断言 type=4、BSR/hash/range/RP priority 可观察。hash 选择结果应在状态/fixture 层验证，不硬编码未经复算的 frame hex。
- **`pim_sm_candidate_rp_adv`**：Candidate-RP Advertisement 给出 C-RP 地址、priority、Holdtime 和两个 group-prefix；断言 type=8、C-RP、priority/Holdtime/prefix count。
- **`pim_sm_register`**：Register 给出 RP 地址、Register flags、inner IPv4 profile（源、组目的地址及非空 payload）；断言 type=1、flags、inner IPv4 source/destination、payload 非空。不能将 inner payload 的任意字节解释成 TCP/UDP。
- **`pim_sm_register_stop`**：Register-Stop 显式给出 group/source；断言 type=2、两地址和 stop 语义，不从前一个 Register 继承地址。
- **`pim_sm_assert`**：Assert 显式给出 group/source、RPT-bit、metric preference 和 route metric；断言 type=5、地址、RPT 和两个 metric。

### 3.4 多邻居、多组与状态隔离

- **`pim_sm_multi_neighbor_state`**：两个独立邻居各发送 Hello，随后分别对 `(*,239.1.1.1)` 与 `(198.51.100.10,232.1.1.1)` 发送 Join/Prune，再各发送一次显式 prune/refresh，共六个事件；断言 `packet_count=6`、每个 packet 的 wire-level upstream-neighbor/group/source 关联，以及两组状态不会相互覆盖；session neighbor/state 本身不作为 tshark 字段断言。
- **`pim_sm_checksum_length`**：一个带多 option 的 Hello，断言 `ip.len` 等于实际 IPv4 header 加 PIM bytes、PIM checksum 非零、PIM 不出现伪造的 `pim.length` 字段；用例只固定公共头前缀和 offset 34。

### 3.5 SSM

- **`pim_ssm_joinprune_sg`**：`pim_ssm_rfc4607_ipv4` 的一个 Join/Prune，具体 source `198.51.100.10` 和 SSM group `232.1.1.1`；断言 type=3、source 具体、wildcard=false、无 RP/Bootstrap/Register 事件。
- **`pim_ssm_multi_group`**：两个原子 SSM Join/Prune 事件，分别为 `(S1,G1)`、`(S2,G2)`，均具体 source；断言 packet_count=2、group/source 不混淆，且状态维度独立。

## 4. 负向用例契约

| ID | 输入故障 | `error_contains` |
|---|---|---|
| `pim_neg_ipv6_profile` | `layers=[ipv6,pim]` 或 `pim_rfc7761_ipv6_pending` | `profile` |
| `pim_neg_checksum` | `wire_fault.kind=checksum` | `checksum` |
| `pim_neg_length` | `wire_fault.kind=length`，声明 IPv4 total/PIM body 不一致 | `length` |
| `pim_neg_type` | unknown type 或 kind/type mismatch | `type` |
| `pim_neg_address_family` | IPv4 profile 的 group/source 使用 IPv6，或 profile 混用 | `address` |
| `pim_neg_ssm_rp` | SSM 事件为 Bootstrap/Register 或 wildcard `(*,G)` | `ssm` |
| `pim_neg_df_profile` | RFC 7761 PIM-SM 输入 `df_election` | `df` |

每个负例的 `expect` 只有 `expect_error` 与 `error_contains`；不得加 packet_count、fields、frames、notes。错误必须由 planner/validator 返回并传播为 task error；不得成功生成损坏 PCAP。

## 5. 三方闭环与覆盖清单

1. 本文、设计 §8、审计 §3.2 和 JSON 均为 24 个唯一 ID，顺序一致；正例 17 个、负例 7 个。
2. 正例 packet_count 严格为 `[1,1,1,1,1,1,2,1,1,1,1,1,3,6,1,1,2]`（按索引中的 17 个正例顺序）；每条均有 `has_payload=true`、`fields` 和 `frames`。PCAP 字段使用 Wireshark（网络分析器）的注册字段名；Hello interval、neighbor、state、DR winner 只作为调度或会话元数据。
3. 负例不含 `packet_count`、`fields`、`frames` 或其他断言；expect 只含两个键。
4. 所有成功用例都是 IPv4 Protocol 103，PIM 起点 offset 34；不使用 TCP 握手/终止断言，也不把 IPv6 PIM 当作成功正例。
5. 正例覆盖 4-byte common header、checksum、Hello options/holdtime/interval/DR、Join/Prune `(*,G)`/`(S,G)`、多组、多邻居、重传、Bootstrap/RP-set、C-RP、Register/Register-Stop、Assert 和 RFC 4607 SSM。
6. 由于 encoded-address 的保留位和字段组合尚未绑定实现 fixture，frames 只使用 `20 xx` 公共头前缀，不写猜测的长地址常量；实现单测必须补字节级 fixture。
7. 负例覆盖 IPv6、checksum、length、type、address-family、SSM/RP 和 DF profile，并验证错误传播。

## 6. 实现后执行建议

先运行 JSON 语法、24 个 id 唯一性、正负 expect 结构、packet_count、offset 和公共头 frame 前缀静态检查；层注册后按正例索引顺序验证 Hello、Join/Prune、BSR/C-RP、Register、Assert、状态隔离和 SSM，再执行全部负例。取得 RFC 7761 编码 fixture 后，补充 encoded-address 的逐字节 frame 断言和 Internet checksum 数值复算；在此之前不能把猜测常量写入机器契约。

## 7. 修订记录

- v1.0.0（2026-08-20）：建立 17 个 IPv4 PIM-SM/SSM 正例和 7 个负例；覆盖 PIM header/checksum、Hello 计时器/选项/DR、Join/Prune wildcard 与 `(S,G)`、多邻居/多组/重传、Bootstrap/RP-set、Candidate-RP、Register/Register-Stop、Assert、SSM 及 IPv6/DF 边界。
