# PIM（协议无关组播，Protocol Independent Multicast）设计契约

> 版本：v1.0.0（设计阶段）
> 日期：2026-08-20
> 状态：仅设计与用例契约；不修改 Go（编程语言）实现，不宣称 `pim` 层已经注册或 MCP（模型上下文协议）套件可以运行。
> 配套文件：`docs/protocol-designs/40-pim-testcase.md`、`trafficgen/test/protocol_pcap/cases/pim.json`、`docs/protocol-designs/audit/40-pim-adversarial-audit.md`
> 规范基线：RFC 7761（PIM-SM，稀疏模式）、RFC 4607（PIM-SSM，源特定组播）；IPv4 直接承载 Protocol 103。

## 1. 范围、证据等级与 profile 边界

本版定义 RFC 7761 的 PIMv2 IPv4 PIM-SM（Protocol Independent Multicast Sparse Mode，协议无关组播稀疏模式）基础报文和 RFC 4607 的 PIM-SSM（Source-Specific Multicast，源特定组播）限制性 profile（档案）。PIM 不是 TCP/UDP 载荷，而是直接封装在 IPv4 中，IPv4 `Protocol=103`。一个显式事件生成一个 PIM IPv4 packet（报文）；planner（规划器）不自动补发邻居响应、注册响应或重传。

| profile | 规范范围 | 允许的事件 | 明确不从本版推导 |
|---|---|---|---|
| `pim_sm_rfc7761_ipv4` | RFC 7761 PIM-SM IPv4 | Hello、Join/Prune、Bootstrap、Candidate-RP Advertisement、Register、Register-Stop、Assert | 真实 RP/BSR 选举、路由表、数据平面复制 |
| `pim_ssm_rfc4607_ipv4` | RFC 4607 SSM over IPv4 | Hello、针对 `(S,G)` 的 Join/Prune、必要的接口/邻居状态事件 | RP、Bootstrap、Candidate-RP、Register/Register-Stop |
| `pim_bidir_rfc5015_pending` | RFC 5015 Bidirectional PIM 的待实现边界 | 不生成 | DF（Designated Forwarder，指定转发器）Election 的编码与状态 |
| `pim_rfc7761_ipv6_pending` | IPv6 PIM 的待实现边界 | 不生成 | IPv6 pseudo-header（伪首部）checksum、IPv6 地址编码、IPv6 profile 的独立字段 |

IPv6 PIM 不能把 IPv4 PIM-SM 的包头、地址编码或 checksum 原样复制。当前 `pim` 设计只接受 IPv4 profile；当输入 IPv6 层或 `pim_rfc7761_ipv6_pending` 时必须返回 profile/address-family（地址族）错误，不生成“看起来像 PIM”的成功 PCAP（抓包文件）。

DF Election 不属于 RFC 7761 PIM-SM 的独立基础消息类型；RFC 7761 PIM-SM 在共享网段上定义的是 Hello 驱动的 DR（Designated Router，指定路由器）选举。DF Election 属于 Bidirectional PIM 的独立 profile，本套件只保留明确的待实现负例，不能把 DR 优先级伪装成 DF wire（线上）报文。

不变式：

1. IPv4 PIM packet 必须位于 `ip` 后且 `ip.proto=103`；UDP、TCP、裸 Ethernet 或缺 IPv4 的层链必须拒绝。
2. PIM common header（公共头）固定 4 字节：Version/Type、Reserved、Checksum。Version 为 2；Type 由事件决定；Reserved 在正例为零；Checksum 按 profile 算法回填。
3. PIM checksum 覆盖完整 PIM packet（checksum 字段置零后计算），使用 Internet checksum（互联网校验和）的标准反码和；checksum 不得因为 IP 头或 Ethernet padding（填充）而改变。IPv6 checksum 语义留给独立 profile。
4. PIM 没有独立的 PIM length 字段。PIM payload length（载荷长度）由 IPv4 `Total Length - IPv4 Header Length` 确定；长度故障表现为 IP 总长度、编码 body 或截断边界不一致，不能凭空增加 PIM length 字段。
5. 地址、邻居、组和源必须显式配置；不能从 `src_ip`、`dst_ip`、RP 或 MAC（媒体访问控制地址）静默猜测组/源树。
6. 每个 Hello、Join/Prune、Bootstrap、Candidate-RP、Register、Register-Stop、Assert 事件均为原子 packet。事件数组只表达发送顺序和 session（会话）状态，不创建不存在的线上字段。
7. planner/validator（校验器）错误必须传播为 task error（任务错误）终态，不能 completed（完成）但 0 包。
8. 同一四元组/接口的多个邻居、多个组和多个源树必须隔离维护；`(*,G)` 与 `(S,G)` 的状态不能互相覆盖。

## 2. 层链、载体与公共配置

推荐层链：

```json
{
  "layers": [{"ip": {}}, {"pim": {}}],
  "src_ip": "192.0.2.1",
  "dst_ip": "224.0.0.13",
  "ttl": 1,
  "pim": {
    "profile": "pim_sm_rfc7761_ipv4",
    "events": [
      {"kind": "hello", "direction": "c2s", "holdtime": 105}
    ],
    "checksum_mode": "auto"
  }
}
```

| 键 | 类型/约束 | 语义 |
|---|---|---|
| `profile` | `pim_sm_rfc7761_ipv4` 或 `pim_ssm_rfc4607_ipv4` | 版本和地址族模板，不编码为 payload（载荷）字段 |
| `events` | 非空有序数组 | 每项为一个 PIM packet；`direction` 为 `c2s`/`s2c` |
| `kind` | `hello`、`join_prune`、`bootstrap`、`candidate_rp_adv`、`register`、`register_stop`、`assert` | RFC 7761 基础事件；SSM 只允许其 profile 支持的子集 |
| `checksum_mode` | 正例为 `auto` | 按完整 PIM 字节计算；负例用 `wire_fault` 注入错误 |
| `neighbor` / `upstream_neighbor` | IPv4 地址 | 发送对象或 Join/Prune 上游邻居，必须显式给出 |
| `group` / `source` | IPv4 地址或前缀 | 组/源树标识；`source=0.0.0.0` 只在显式 wildcard profile 中表示 `*` |
| `state` | `downstream_join`、`downstream_prune`、`upstream_join`、`upstream_prune` 等有限枚举 | 会话状态标注，不写入 PIM common header |
| `retransmission` | 布尔或重试元数据 | 只标记显式重复事件；PIM 基础包不凭空加入序列号 |
| `wire_fault` | 仅负例 | checksum、IP length、type、地址族等失败注入，不代表合法线上字段 |

所有数值字段按 RFC 的网络字节序编码；多组/多源通过显式数组表达。缺省值不能替代必填的 profile、组、源、邻居或计时器。

## 3. PIMv2 公共头与消息类型

IPv4 无 option（选项）时，PIM packet 起点是 `offset 34 = Ethernet 14 + IPv4 20`。公共头按 RFC 7761 为：

```text
byte 0  Version（高 4 bit）| Type（低 4 bit）
byte 1  Reserved
byte 2..3  Checksum（网络字节序）
```

PIM-SM 本版登记的消息类型：

| Type | 名称 | profile/用途 |
|---:|---|---|
| 0 | Hello | 邻居发现、Holdtime、LAN 选项和 DR 选举 |
| 1 | Register | DR 到 RP 的单播注册，后接显式 inner IPv4 profile |
| 2 | Register-Stop | RP 到 DR，停止注册 |
| 3 | Join/Prune | 上游 Join/Prune；承载 `(*,G)`、`(S,G)` 和多组条目 |
| 4 | Bootstrap | BSR 及 RP-Set，支持组范围和 RP 优先级/hash 选择输入 |
| 5 | Assert | 共享网段上的转发者竞争，携带组/源和 metric |
| 7 | Graft-Ack | PIM-DM 扩展，不在本版 profile；输入必须另有 profile |
| 8 | Candidate-RP Advertisement | C-RP 向 BSR 报告 RP 优先级、Holdtime 和组前缀 |

Type 6、9 及其他扩展不在本版登记；未知 type 必须错误。DF Election 没有在本表中虚构一个类型值。

### 3.1 Checksum 和长度

编码顺序是：先完成公共头（checksum 置零）、事件固定字段、地址和所有列表，再对从 PIM Version/Type 开始的完整 PIM packet 计算 Internet checksum，最后回填 2 字节 checksum。IP header checksum、Ethernet padding 和 IP Total Length 字段本身不属于 PIM checksum 输入。实现单测必须用完整字节 fixture（固定样本）复算 checksum，并覆盖偶数/奇数 PIM body、空选项和多条地址列表；PCAP 用例只断言 checksum 非零，不写未经复算的数值常量。

`ip.len` 必须等于实际 IPv4 header 加 PIM packet 字节数（不含 Ethernet padding）。负例 `wire_fault.kind=length` 必须在 planner/validator 层拒绝声明长度与编码结果不一致、截断或溢出。不能将 Ethernet 帧最小长度当作 PIM 长度。

### 3.2 IPv4 地址编码

Join/Prune、Bootstrap、Candidate-RP、Register-Stop、Assert 中的地址使用 RFC 7761 的 PIM Encoded-Address（编码地址）结构；实现必须按地址族、encoding type、保留字段、地址和必要 mask/prefix 字段逐字段编码。本文不手工写保留 octet（字节）或未经 fixture 复算的长 hex；设计/用例只使用已命名的 IPv4 地址语义和公共头前缀。

## 4. PIM-SM 事件和状态

### 4.1 Hello、Holdtime/interval 和 DR election

Hello 的 body 是一串 PIM Hello options（选项）：本版固定支持 Holdtime、LAN Prune Delay、DR Priority 和 Generation ID 四类字段。Holdtime 表示邻居保持时间（秒）；Hello interval 是发送调度参数，不是一个额外 PIM common-header 字段。Holdtime=0 是显式的邻居立即失效边界，不能被默认成实现的普通保持时间。LAN Prune Delay 包含 T-bit、传播延迟和 override interval（覆盖间隔）；DR Priority 和 Generation ID 用于邻居能力/DR 选举状态。

PIM-SM DR election（DR 选举）是共享网段的会话语义：在同一接口/邻居集合内，先比较显式 DR Priority，再按 RFC 规定的 IPv4 地址 tie-break（平局决胜）选择；每个邻居的 Hello 必须独立事件。选举结果是 state metadata（状态元数据），不是 PIM body 中的额外“赢家”字段。多个邻居的 Hello 不能跨接口或跨 group/source tree（组/源树）混用。

### 4.2 Join/Prune、wildcard 与 source tree

Join/Prune 事件必须显式给出：上游邻居、Join/Prune Holdtime、group 条目数组；每个 group 条目包含 joined source 数组和 pruned source 数组。地址列表使用 RFC Encoded-Group/Encoded-Source Address；实现按最终数组长度回填 group/source count。

- `(*,G)`：group 为具体组，source 以显式 wildcard 标记表示 `*`；它建立共享树到 RP 的状态，不得误编码成一个普通的 `0.0.0.0` `(S,G)`。
- `(S,G)`：group 与 source 均为具体 IPv4 地址；它建立源特定树。
- 同一 Join/Prune 可带多个 group，且每个 group 可同时带 joined/pruned source；组计数、Join 计数和 Prune 计数分别可观察。
- `downstream_join`、`downstream_prune`、`upstream_join`、`upstream_prune` 是 planner 状态标签。它们不能被当作额外 wire type，也不能让一个下游 Join 自动产生上游响应。

PIM 基础 Join/Prune 没有 TCP 式 sequence number。重传只能由配置显式重复完整事件，并以 `retransmission=true` 标记；实现必须保持同一邻居、组、源和状态的隔离，不得自动补包或悄悄合并两次事件。

### 4.3 Bootstrap、RP hash/priority 与 Candidate-RP

Bootstrap 事件显式携带 BSR 地址、BSR priority、hash mask length 和 group-range/RP-set 数组。每个 group range 显式携带 RP 地址、RP priority、RP Holdtime 和（如 profile 支持）RP-set 计数。RP 选择应按 RFC 7761 的优先级和 hash 规则执行；本版要求固定输入和可复现结果，但不把某个哈希结果或保留字段常量硬编码到 PCAP frame。

Candidate-RP Advertisement 显式携带 RP 地址、RP priority、Holdtime 和 group-prefix 列表；它是 C-RP 到 BSR 的控制事件，不能误生成成 Bootstrap，也不能把 RP 地址推导为 `src_ip`。

### 4.4 Register、Register-Stop 和 Assert

Register 的公共头 Type=1，body 包含 Register flags，后接一个显式的 inner IPv4 packet profile。inner packet 的源、组目的地址和 payload（载荷）必须在配置中给出；本版不根据任意 bytes 猜测 inner UDP/TCP 语义。Register 是 DR 到 RP 的单向事件，不能自动生成 Register-Stop。

Register-Stop 的 body 显式包含 group/source 地址，表示 RP 要求 DR 停止指定注册；其 group/source 不能从上一条 Register 隐式继承。Assert 的 body 显式包含 group/source、RPT-bit、metric preference 和 route metric。Assert 竞争结果属于共享网段状态，不能把任意较小 metric 的获胜者写成不存在的 wire 字段。

## 5. PIM-SSM RFC 4607 profile

`pim_ssm_rfc4607_ipv4` 只允许源特定 `(S,G)` Join/Prune 和必要的 Hello/邻居事件。SSM 不需要 RP、Bootstrap、Candidate-RP 或 Register/Register-Stop；其加入动作直接指向 `(S,G)`。IPv4 SSM group range（常见为 232/8）必须作为 profile/config 显式边界，不应把任意组地址静默重写到 232/8。

SSM 的多 group session 可在一个 Join/Prune 中携带多个显式 `(S,G)`，也可由多个原子事件表达；每项的 source 必须具体且 wildcard=false。若 SSM profile 出现 wildcard `(*,G)`、RP-set 或 Register 事件，validator 必须返回 `ssm`/`rp`/`address` 锚点错误，而非降级为 PIM-SM。

## 6. 邻居、树状态、边界与重传

状态按 `interface + neighbor + group + source` 维度隔离：

```text
neighbor: down → hello_seen → up/expired
(*,G):    no-state → joined/pruned → timeout
(S,G):    no-state → joined/pruned → timeout
```

这是可观察 session metadata，不是线上的状态字段。Hello 的 Holdtime/interval 必须满足非负和 profile 上限；Holdtime=0 只代表立即过期语义。Join/Prune Holdtime 过期后，规划器不得自动生成刷新包，除非配置了显式 refresh/retransmission event。重复事件应保留 packet_count，并可用同一 group/source/neighbor 字段观察。

边界包括：空 option 列表、Holdtime=0、最大可编码计时器、单/多 group、单/多 joined/pruned source、wildcard 与具体 source 的互斥、多个邻居四元组/接口隔离、Register inner IPv4、IP total length 与实际 PIM body 一致性，以及 checksum 奇偶长度。任何计数/长度溢出都必须错误，不得截断。

## 7. 负例与错误传播

| 输入故障 | 条件 | 稳定错误锚点 |
|---|---|---|
| carrier | UDP/TCP、缺 IPv4、Protocol 非 103 | `carrier`/`ip` |
| checksum | `wire_fault.kind=checksum`，显式破坏 checksum | `checksum` |
| length | IP Total Length、PIM body 或地址列表边界不一致 | `length` |
| type | 未登记 PIM Type 或 type 与事件不一致 | `type` |
| address family | IPv6 层、IPv4 profile 配 IPv6 组/源，或 IPv6 profile 混入 IPv4 | `address`/`profile` |
| SSM/RP | SSM 发送 Bootstrap/Candidate-RP/Register，或 wildcard `(*,G)` | `ssm`/`rp` |
| count/address | group/source 计数与数组、mask 或 encoded address 不一致 | `count`/`address` |
| interval | 负 Holdtime/interval、超出字段可编码范围 | `holdtime`/`interval` |
| DF profile | 把 Bidirectional PIM DF Election 放入 RFC 7761 PIM-SM | `df`/`profile` |

所有负例只要求 task error；损坏的 PIM bytes 不得以成功 PCAP 作为验证结果。错误必须跨 planner→engine（引擎）→task handler（任务处理器）传播。

## 8. 场景、包数与实现完成定义

PIM 是 raw IPv4（裸 IPv4）控制协议，无 TCP handshake（握手）或 FIN termination（终止）包。无 IPv4 option、一个事件一个 packet 时，`packet_count` 等于显式事件数；PIM 起点固定为 offset 34。MSS 不适用；若未来加入 IP fragmentation（IP 分片），必须按重组后的 PIM packet 断言，不能将分片数冒充事件数。

| # | JSON ID | 类型 | 事件数/packet_count | 主要 observable（可观察锚点） |
|---:|---|---|---:|---|
| 1 | `pim_sm_hello_holdtime` | 正 | 1/1 | Protocol 103、Hello、Holdtime、checksum；Hello interval 为调度元数据 |
| 2 | `pim_sm_hello_options` | 正 | 1/1 | LAN Prune Delay、DR priority、Generation ID |
| 3 | `pim_sm_hello_zero_holdtime` | 正 | 1/1 | Holdtime=0 的立即失效边界 |
| 4 | `pim_sm_joinprune_wildcard` | 正 | 1/1 | `(*,G)`、wildcard source、上游邻居 |
| 5 | `pim_sm_joinprune_source` | 正 | 1/1 | `(S,G)` joined/pruned source |
| 6 | `pim_sm_joinprune_multi_group` | 正 | 1/1 | 两个 group、多种 source state |
| 7 | `pim_sm_joinprune_retransmit` | 正 | 2/2 | 显式重复、无隐式 sequence/响应 |
| 8 | `pim_sm_bootstrap_rp_set` | 正 | 1/1 | BSR、hash mask、RP priority/hash 输入 |
| 9 | `pim_sm_candidate_rp_adv` | 正 | 1/1 | C-RP priority/Holdtime/group prefix |
| 10 | `pim_sm_register` | 正 | 1/1 | Register flags、RP、inner IPv4 |
| 11 | `pim_sm_register_stop` | 正 | 1/1 | Register-Stop group/source |
| 12 | `pim_sm_assert` | 正 | 1/1 | group/source、RPT、metric |
| 13 | `pim_sm_dr_election` | 正 | 3/3 | 多邻居 Hello、DR priority/address tie-break |
| 14 | `pim_sm_multi_neighbor_state` | 正 | 6/6 | 两邻居、两 group、独立 `(*,G)`/`(S,G)` 状态 |
| 15 | `pim_sm_checksum_length` | 正 | 1/1 | 完整 PIM checksum、IPv4/PIM payload length |
| 16 | `pim_ssm_joinprune_sg` | 正 | 1/1 | RFC 4607 `(S,G)`、无 RP |
| 17 | `pim_ssm_multi_group` | 正 | 2/2 | 多 group SSM、具体 source |
| 18 | `pim_neg_ipv6_profile` | 负 | — | IPv6 profile 明确拒绝 |
| 19 | `pim_neg_checksum` | 负 | — | malformed checksum |
| 20 | `pim_neg_length` | 负 | — | malformed IP/PIM length |
| 21 | `pim_neg_type` | 负 | — | unknown/mismatched type |
| 22 | `pim_neg_address_family` | 负 | — | IPv4/IPv6 profile 混用 |
| 23 | `pim_neg_ssm_rp` | 负 | — | SSM 禁止 RP/Register |
| 24 | `pim_neg_df_profile` | 负 | — | DF Election 需独立 profile |

实现完成定义：

1. 注册 `ip→pim` IPv4 终结层，Protocol=103；拒绝 UDP/TCP/IPv6/缺 IPv4。
2. 实现 PIMv2 4-byte common header、RFC Internet checksum 和按最终 IPv4 total length 的 body 边界。
3. 对 Hello 四类 options、Join/Prune wildcard 与 `(S,G)`、Bootstrap/RP-set、Candidate-RP、Register/inner IPv4、Register-Stop、Assert 逐字段写失败优先测试。
4. 以独立状态键覆盖多邻居、多组、多源、DR election、upstream/downstream state、Holdtime/interval、显式 retransmission；不自动补响应。
5. RFC 4607 SSM 只允许具体 `(S,G)`，并对 RP/Bootstrap/Register/wildcard 写负例。
6. API→engine→PCAP 正负集成验证全部 24 个 ID；负例必须 task error，不能 completed/0 packet。
7. RFC 5015 DF Election 与 IPv6 PIM 取得独立字段表和 fixture 后，另建 profile/cases；不得改写本版 IPv4 PIM-SM/SSM 契约。

## 9. 修订记录

- v1.0.0（2026-08-20）：建立 RFC 7761 PIM-SM 与 RFC 4607 PIM-SSM IPv4 设计契约；覆盖 PIM header/checksum、Hello/计时器/DR、Join/Prune wildcard 与 `(S,G)`、Bootstrap/RP hash/priority、Candidate-RP、Register/Register-Stop、Assert、多邻居/多组/重传和 IPv6/DF 独立边界；未编造未知地址编码常量。
