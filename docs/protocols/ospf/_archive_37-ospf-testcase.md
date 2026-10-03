# OSPF（开放最短路径优先）v2 测试用例设计

> 版本：v1.0.0（设计阶段）  
> 日期：2026-08-20  
> 配套设计：`docs/protocol-designs/37-ospf-design.md`  
> 机器契约：`trafficgen/test/protocol_pcap/cases/ospf.json`  
> 状态：`ospf` 层尚未实现；本文定义实现后的 PCAP（抓包文件）断言，不宣称当前套件可运行。

## 1. 测试原则

用例从设计 §1（RFC2328 IPv4 profile）、§2（配置/层链）、§3（24-byte OSPF header）、§4（五类报文和 Router/Network LSA）、§5（RFC5340 隔离）、§6（错误处理）及 §7（场景映射）逐项派生。

OSPFv2 是直接封装在 IPv4 Protocol 89 的 raw IP（裸 IP）协议，不是 TCP/UDP 会话；因此单报文正例 `packet_count=1`，六事件邻接交换为 `packet_count=6`。IPv4 无 option 时 OSPF header 起点是 `offset 34 = Ethernet 14 + IPv4 20`。正例每条有 `packet_count`、`has_payload`、至少一个字段或 frame（帧）断言；负例和 RFC5340 边界例的 `expect` **只能**包含 `expect_error` 与 `error_contains`，不对失败 PCAP 作结构断言。

固定 frame 只锚定 OSPF 公共头的前四字节（Version、Type、Packet Length），避免把自动 checksum 的未验证常量写死。OSPF packet checksum 和 LSA checksum 以 `nonzero` observable（可观察断言）检查；实际实现单测还必须按 RFC 2328 逐字节复算：packet checksum 排除 Authentication 字段并使用 ones-complement，LSA checksum 排除 LS age 并使用 Fletcher-16。所有 IPv4 应用 offset 均为 34；IPv6 不使用 IPv4 offset，也不把 OSPFv2 checksum/LSA body复制过去。

## 2. 用例索引和包数

| # | id | 类型 | 覆盖 | 报文/事件数 | packet_count |
|---:|---|---|---|---:|---:|
| 1 | `ospf_hello_dr_bdr` | 正 | Hello mask/timer/priority/DR/BDR/neighbor | 1 | 1 |
| 2 | `ospf_hello_neighbors` | 正 | 两个邻居、长度增长 | 1 | 1 |
| 3 | `ospf_dbd_master` | 正 | DBD I/M/MS、MTU、DD sequence、Router-LSA header | 1 | 1 |
| 4 | `ospf_dbd_slave` | 正 | DBD slave flags/sequence | 1 | 1 |
| 5 | `ospf_lsr_router_lsa` | 正 | LSR type 1 三元组 | 1 | 1 |
| 6 | `ospf_lsr_network_lsa` | 正 | LSR type 2 三元组 | 1 | 1 |
| 7 | `ospf_lsu_router_lsa` | 正 | Router-LSA flags/link/metric | 1 | 1 |
| 8 | `ospf_lsu_network_lsa` | 正 | Network-LSA mask/attached routers | 1 | 1 |
| 9 | `ospf_lsack` | 正 | 两个 LSA headers | 1 | 1 |
| 10 | `ospf_neighbor_full_exchange` | 正 | Hello→DBD→LSR→LSU→LSAck、状态 | 6 | 6 |
| 11 | `ospf_ipv4_transport` | 正 | IPv4 Protocol 89、TTL、IDs | 1 | 1 |
| 12 | `ospf_checksum_length` | 正 | packet/LSA length、两类 checksum | 1 | 1 |
| 13 | `ospf_neg_udp` | 负 | UDP 载体 | — | — |
| 14 | `ospf_neg_ipv6_v2` | 负 | IPv6 不得复用 RFC2328 IPv4 | — | — |
| 15 | `ospf_neg_version` | 负 | 不支持的 version/profile | — | — |
| 16 | `ospf_neg_type` | 负 | 未知 packet type | — | — |
| 17 | `ospf_neg_length` | 负 | packet length 故障 | — | — |
| 18 | `ospf_neg_area` | 负 | malformed Area ID | — | — |
| 19 | `ospf_neg_router_id` | 负 | malformed Router ID | — | — |
| 20 | `ospf_ipv6_rfc5340_boundary` | 边界负例 | RFC5340 独立 profile 未实现 | — | — |

## 3. 正例契约

### 3.1 `ospf_hello_dr_bdr`（T-OSPF-S1）

一个 IPv4 OSPFv2 Hello，`packet_length=48`，offset 34 frame 前缀 `02 01 00 30`。24-byte 公共头之后是固定 20-byte Hello body 和一个 4-byte neighbor Router ID。断言 `router_id=1.1.1.1`、`area_id=0.0.0.0`、mask `255.255.255.0`、Hello/Dead=`10/40`、priority=1、DR=`10.0.0.2`、BDR=`10.0.0.3`、neighbor=`2.2.2.2` 以及 OSPF checksum 非零。该例不把 224.0.0.5 推断成 DR。

### 3.2 `ospf_hello_neighbors`（T-OSPF-S2）

Hello 有两个邻居 `2.2.2.2,3.3.3.3`，`packet_length=52`，offset 34 前缀 `02 01 00 34`，断言 neighbor count=2。该例单独证明邻居列表每个 Router ID 增加 4 bytes，而不是让一个邻居例覆盖列表边界。

### 3.3 `ospf_dbd_master`（T-OSPF-S3）

DBD `packet_length=52`，前缀 `02 02 00 34`，Interface MTU=1500，I/M/MS 全置位（observable `flags=0x07`），DD sequence=100，携带一个 type 1 Router-LSA header。DBD 只携带 LSA header，不伪造完整 LSA body。

### 3.4 `ospf_dbd_slave`（T-OSPF-S4）

独立 DBD slave 用例，前缀仍为 `02 02 00 34`，断言 I/M/MS 清零、DD sequence=101 和 type 1 header。master/slave 不能合并为一个 flags 可选的宽松断言，否则会漏掉状态方向错误。

### 3.5 `ospf_lsr_router_lsa`（T-OSPF-S5）

LSR `packet_length=36`，前缀 `02 03 00 24`，请求 `lsa_type=1`、LSID=`1.1.1.1`、advertising Router=`1.1.1.1`。每个 LSR request 固定 12 bytes；字段三元组必须分别断言。

### 3.6 `ospf_lsr_network_lsa`（T-OSPF-S6）

LSR 同为 36 bytes，但 `lsa_type=2`、LSID=`10.0.0.2`、advertising Router=`1.1.1.1`。LSID 是 DR 接口地址；该例避免只测试 Router-LSA type=1。

### 3.7 `ospf_lsu_router_lsa`（T-OSPF-S7）

LSU `packet_length=64`，前缀 `02 04 00 40`，包含 count=1 和一个 36-byte Router-LSA。断言 LSA type=1、LSA length=36、flags=0、link count=1、link type=2、metric=10 和 LSA checksum 非零。长度公式为 `24 + 4 + 36 = 64`。

### 3.8 `ospf_lsu_network_lsa`（T-OSPF-S8）

LSU `packet_length=60`，前缀 `02 04 00 3c`，包含一个 32-byte Network-LSA：mask=`255.255.255.0`、attached routers=`1.1.1.1,2.2.2.2`、LSID=`10.0.0.2`。长度公式为 `24 + 4 + (20 + 4 + 8) = 60`，断言 LSA length=32，避免将 LSU packet length 和 LSA length 混同。

### 3.9 `ospf_lsack`（T-OSPF-S9）

LSAck `packet_length=64`，前缀 `02 05 00 40`，携带两个 20-byte LSA headers，分别是 type 1/2、LSID `1.1.1.1/10.0.0.2`、length `36/32`。只断言 header，不把 LSA body 错塞进 LSAck。

### 3.10 `ospf_neighbor_full_exchange`（T-OSPF-S10）

六个 raw IPv4 OSPF 报文按事件顺序发送：Hello（Init）、DBD master（ExStart）、DBD slave（Exchange）、LSR（Loading）、LSU（Loading）、LSAck（Full）。`packet_count=6`，每个事件占一个 packet；断言每包 type、DBD flags、LSU count、LSAck count 及状态。状态字段必须按独立 session 维护，不得跨 packet 猜测或隐式补响应。

### 3.11 `ospf_ipv4_transport`（T-OSPF-S11）

Hello `packet_length=44`（无邻居），源 `10.0.0.9`、目的 224.0.0.5、TTL=1。断言 `ip.version=4`、`ip.proto=89`、`ip.ttl=1`、目的地址、Router ID=`10.10.10.10`、Area ID=`0.0.0.1` 和非零 checksum。OSPF 没有端口字段，不能用 TCP/UDP 端口替代协议号。

### 3.12 `ospf_checksum_length`（T-OSPF-S12）

含一个 Router-LSA 的 LSU，`packet_length=64`，Area ID=`0.0.0.2`、Router ID=`3.3.3.3`，断言 OSPF packet checksum 和 LSA checksum 均非零，packet length=64、LSA length=36。实现单测必须再验证 packet checksum 的数值和 ones-complement（反码）计算，以及 LSA checksum 的 Fletcher-16（排除 LS age），而非仅满足非零。

## 4. 负例契约

所有负例 `expect` 严格只有两个键；错误必须从 planner/validator 传播为 task error：

| id | 输入故障 | `error_contains` |
|---|---|---|
| `ospf_neg_udp` | `layers=[udp,ospf]` | `ip` |
| `ospf_neg_ipv6_v2` | IPv6 + `version=2` + `rfc2328_ipv4` | `rfc5340` |
| `ospf_neg_version` | version=3 + IPv4 profile | `version` |
| `ospf_neg_type` | unknown packet type | `type` |
| `ospf_neg_length` | declared length smaller than header | `length` |
| `ospf_neg_area` | malformed Area ID fault | `area` |
| `ospf_neg_router_id` | malformed Router ID | `router` |
| `ospf_ipv6_rfc5340_boundary` | explicit RFC5340 profile boundary; no OSPFv3 implementation yet | `rfc5340` |

`wire_fault` 是配置校验注入入口，不是合法线上 payload；禁止生成损坏但成功的 PCAP。`ospf_ipv6_rfc5340_boundary` 不等同 OSPFv3 正例：未来实现 RFC5340 时，应新增独立正例并重新定义其 IPv6 offset、Next Header、Instance ID、checksum 和 LSA 断言。

## 5. 三方一致性检查清单

1. 本文、设计 §7 和 JSON 都是 20 个唯一 ID，顺序一致；正例 12 个，负例/边界 8 个。
2. 正例 packet_count 严格为 `[1,1,1,1,1,1,1,1,1,6,1,1]`；负例没有 `packet_count`。
3. 每个正例都有 `has_payload=true`、至少一个 `fields`/`frames`；单报文 OSPF raw IP 不使用 `has_handshake` 或 `terminates`。
4. 所有 IPv4 frame offset 都是 34；IPv6 case 不出现成功 frame/offset 断言，且 OSPFv2/OSPFv3 边界使用独立 profile 和 `rfc5340` 锚点。
5. 公共头前缀、类型和长度在 JSON、本文逐例说明和设计长度公式中一致；自动 checksum 以非零字段观察，禁止写未经复算的常量。
6. 负例 `expect` 只能包含 `expect_error`、`error_contains`，不混入 fields/frames/packet_count。
7. Router-LSA 与 Network-LSA 分别在 LSR、LSU 和 LSAck 相关断言中出现；Hello、DBD master/slave、LSR、LSU、LSAck 均有独立原子用例。

## 6. 实现后执行建议

先执行 JSON 语法、ID/包数/负例结构和 hex 解析静态检查；层注册后按 S1→S12 顺序验证公共头、长度、五类 packet、LSA body 和状态交换，再执行 N1→N8 验证错误传播。OSPFv2 的 checksum 应用专用计算测试与真实 PCAP/NIC 验证；不要用 UDP decode 或端口过滤替代 Protocol 89。MSS/IP fragmentation（IP 分片）场景使用 OSPF packet length 和重组语义，不能把固定 offset 当成 stream offset。RFC5340 取得规范和 fixture 后，另建 OSPFv3 正例和失败用例，不修改 RFC2328 IPv4 case。

## 7. 修订记录

- v1.0.0（2026-08-20）：建立 12 个 OSPFv2 IPv4 正例和 8 个负例/IPv6 profile 边界例；覆盖 Hello、DBD、LSR、LSU、LSAck、Router/Network LSA、邻接状态、DR/BDR、Protocol 89、checksum/length 以及 RFC5340 独立边界。
