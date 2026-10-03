# PIM（协议无关组播，Protocol Independent Multicast）设计契约

> 版本：v2.1.0（静态闭环版）
> 日期：2026-10-01
> 状态：D1–D8 设计、T1–T6 测试、C1–C6 覆盖清单已对齐现行机器契约；**`pim` 层已注册、builder/planner/generator 已落码**，但本批只改三文件，不宣称 suite/MCP/NIC 已运行。本契约不修改 Go 实现。
> 机器契约：`trafficgen/test/protocol_pcap/cases/pim.json`（28 例：17 正、11 负；正例严格层链，负例仅保留故障触发形状）。
> 配套文件：`docs/protocols/pim/testcase.md`、`trafficgen/test/protocol_pcap/cases/pim.json`
> 规范基线：RFC 7761（PIM-SM，稀疏模式）、RFC 4607（PIM-SSM，源特定组播）；IPv4 直接承载 Protocol 103。
> **层链唯一真相**：本契约目标形状只有纯 `layers` 形（`[ip,pim]`，raw-IP 直挂、无传输层、无端口语义）+ 兄弟键 `strategy_fc` 走数量；24 个历史语义例已完成层链迁移，新增 4 个链级/白名单负例（共 28 例）。

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
2. PIM checksum 覆盖完整 PIM packet（checksum 字段置零后计算），使用 Internet checksum（互联网校验和）的标准反码和；checksum 不得因为 IP 头或 Ethernet padding（填充）而改变。IPv6 checksum 语义留给独立 profile。Register 例外：checksum 只覆盖 8 字节前缀（4 字节公共头 + 4 字节 flags），不覆盖内嵌 inner IPv4（实现 `builder.go:379`，RFC 7761 §4.9.1）。
3. PIM 没有独立的 PIM length 字段。PIM payload length（载荷长度）由 IPv4 `Total Length - IPv4 Header Length` 确定；长度故障表现为 IP 总长度、编码 body 或截断边界不一致，不能凭空增加 PIM length 字段。
4. 地址、邻居、组和源必须显式配置；不能从 `src_ip`、`dst_ip`、RP 或 MAC（媒体访问控制地址）静默猜测组/源树。
5. 每个 Hello、Join/Prune、Bootstrap、Candidate-RP、Register、Register-Stop、Assert 事件均为原子 packet。事件数组只表达发送顺序和 session（会话）状态，不创建不存在的线上字段。
6. planner/validator（校验器）错误必须传播为 task error（任务错误）终态，不能 completed（完成）但 0 包。
7. 同一四元组/接口的多个邻居、多个组和多个源树必须隔离维护；`(*,G)` 与 `(S,G)` 的状态不能互相覆盖。

**已注册/已落码现状（P1 实测，行号真实）**：`pim` 终结层已注册（`registry.go:896`，`CategoryTerminal + DependsOn ["ip"]`，`FieldContract {"ip.protocol": "103"}`，注释 `registry.go:889-892` P3 T5 raw-IP 链，RFC 7761 注记）；配置结构 `PIMConfig`（`routing.go:174-179` 4 键）/`PIMEvent`（`:182-213` 27 键）/`PIMWireFault`（`:262-266` 3 键）；wire 编码 `internal/protocol/pim/builder.go`（536 行：`checksum` `:52`、`buildPIM` `:175`、`buildHello` `:193`、`buildJoinPrune` `:242`、`buildBootstrap` `:284`、`buildCandidateRPAdv` `:323`、`buildRegister` `:352`［8 字节前缀 checksum `:379`］、`buildRegisterStop` `:386`、`buildAssert` `:402`、`encodeSource` `:151-170`（W 位置位 `:155`，`srcFlagWild=0x02` `:36`））；planner/validator `internal/protocol/pim/planner.go`（159 行：`Validate` `:20` 非 IPv4 profile 拒 `:29`、checksum_mode `:33`、df 拒含 `df` `:57`、SSM 拒含 `ssm` `:62/64/70/75`、IPv4 地址拒 `:85-99`、数组组/源/前缀校验 `:101-121`、wire_fault 四值 `:140-159`）；终结层生成器 `internal/protocol/pim/layer_gen.go`（82 行：`Generate` `:21` 空 `Emit` 拒、无 events 拒；c2s→up/s2c→down `:72-77`，下行由 raw-IP 分支交换 L3 源目 `chain_planner.go:1405-1407`）；白名单已登记（`protocols.go:46`）；顶层 `pim` 子映射解析（`strategy_convert.go:727-729`，`parseSubconfigJSON` 普通 `json.Unmarshal` 无 `DisallowUnknownFields`）；`Meta.PIM` 直传（`chain_planner.go:1370` / `chain_planner_translate.go:166` / `generator.go:492`）；raw-IP 自驱（`isRawIPChain :40` 含 `pim`，`:54/:57` transless 名单；`transportProtocol :229/:243` 末层/倒二层看 `pim`→`ProtocolPIM`）；`ProtocolPIM=103`（`builder.go:65`）；生成表含 `pim`（`layers.generated.json:2457-2465`，`depends_on ["ip"]`，`fields {}`——业务键走 `PIMConfig` 经 FlowMeta 直传，见 §15 接线件）；单元测试 34 个（`pim_test.go` 834 行）。`layers[]` 空条目 `{"pim":{}}` 恒需非空 `events`，缺失即错（§5.5 Honest 注：当前生成器无空配置默认流，无握手无保活语义）。

## 2. 层链、载体与公共配置（存量形状声明，P1 实测不美化）

**存量 28 例 `spec_json` 实测形状（2026-09-30）**：24 个历史语义例已为严格 `[ip,pim]` 层链，地址/TTL/业务均在对应层；17 个正例均有兄弟键 `strategy_fc`（`flows` 等于显式事件 `packet_count`）。新增 4 个链级/白名单负例分别覆盖顶层 `pim` presence、顶层 `src_ip` 游离键、`[ip,udp,pim]` 载体和缺失 `ip` 层；这些负例保留故障触发形状，不计成功包数。

**正例 `expect` 实测**：17 正例 `directional` 15 例 `false` + 2 例 `true`（仅 `pim_sm_dr_election` 3 包与 `pim_sm_multi_neighbor_state` 6 包为 `true`——逐包断言方向面）；`has_payload` 17/17 `true`；`has_handshake` 0/28（raw-IP 族诚实口径，无连接无握手）；`notes` 0/28。`frames` 26 帧全 offset 34：`20 00`×9（Hello）/ `21 00`（Register）/ `22 00`（Register-Stop）/ `23 00`×12（Join/Prune）/ `24 00`（Bootstrap）/ `25 00`（Assert）/ `28 00`（Candidate-RP-Adv），与 §3 Type 表逐值一致。

目标层链为 `ip → pim`（raw-IP 直挂）。以下字段是设计配置。`strategy_fc`：17 个正例均声明 `{"type":"flows","value":packet_count}`，事件序仍由 `layers[1].pim.events` 表达；4 个新增链级/白名单负例不带成功包数：

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
```（旧扁平形样例，P4 按 §14.1 改写为纯 layers 形——地址/TTL 进 `layers[0].ip`、业务进 `layers[1].pim`、数量走兄弟键 `strategy_fc`）

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

锚词→代码行实测（`planner.go`，P1 逐字核对）：`profile`→`:30`（`unsupported profile`）；`checksum`→`:146`；`length`→`:148`；`type`→`:150`；`address`→`:102-104`（group 非 v4）/ `:131`（source 非 v4，`validateSource`）；`ssm`→`:62/64/70/75`；`df`→`:57`（`pim df:`）。

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
2. 实现 PIMv2 4-byte common header、RFC Internet checksum（Register 仅 8 字节前缀面，`builder.go:379`）和按最终 IPv4 total length 的 body 边界。
3. 对 Hello 四类 options、Join/Prune wildcard 与 `(S,G)`（通配 W 位 `srcFlagWild=0x02 :36`，置位 `encodeSource :155`）、Bootstrap/RP-set、Candidate-RP、Register/inner IPv4、Register-Stop、Assert 逐字段写失败优先测试（34 个单元测试函数已落码，`pim_test.go` 834 行，P4 复用口径）。
4. 以独立状态键覆盖多邻居、多组、多源、DR election、upstream/downstream state、Holdtime/interval、显式 retransmission；不自动补响应。当前 `state` 为元数据直通（生成器/builder 不消费 `state`，仅做配置携带）——状态机断言只做字段面，不做保留字段面。
5. RFC 4607 SSM 只允许具体 `(S,G)`，并对 RP/Bootstrap/Register/wildcard 写负例（`planner.go:60-79` SSm 分支全覆盖）。
6. API→engine→PCAP 正负集成验证全部 28 个 ID（24 个语义例已迁移，4 个链级负例新增）；负例必须 task error，不能 completed/0 packet（11 个负例 `error_contains` 见 testcase §4）。
7. RFC 5015 DF Election 与 IPv6 PIM 取得独立字段表和 fixture 后，另建 profile/cases；不得改写本版 IPv4 PIM-SM/SSM 契约。

## 10. 已知裁定与待确认（P1 实测诚实声明，§5.5）

- **Register checksum 面裁定**：实现 checksum 只覆盖 8 字节前缀（`builder.go:372-381` 注释"Per tshark/RFC 7761 the PIM checksum covers only the 8-byte prefix"），与 §1 不变式 2 的"完整 packet 覆盖"条文不一致——以实现+tshark 解码为准（register 例 `pim_sm_register` 的 `pim.cksum` nonzero 断言已与该实现对齐）。v1 底稿"先完成公共头再对完整 PIM packet 计算"一句仅适用于非 Register 七类事件；D-PIM-1 定稿时将该条文拆为"七类全包覆盖 + Register 8 字节前缀覆盖"两行（见 §15）。
- **`hello_interval` 调度元数据**：`PIMEvent.HelloInterval`（`routing.go:185`）builder 不消费（`buildHello :193-239` 未读该字段）——存量 `pim_sm_hello_holdtime` 的 interval=30 仅作配置携带与元数据，不进线。P4 不新增 wire 语义（§12 业务字段表列"不开"）。
- **`state` 状态元数据**：builder/planner 不消费 `state`（仅携带）；多邻居/多组隔离的"状态"面由 tshark 组/源字段面验证，不由保留字段验证（§4.2 原文"不能被当作额外 wire type"已对齐实现）。
- **缺省 TTL/目的**：存量 `src_ip` 恒 `192.0.2.1`（23/24，`pim_sm_register` 为 `192.0.2.100`——Register DR 源语义）；`ttl` 24/24 为 1（P4 迁 `ip.ttl`；`ip` 层缺省 `ttl=64` `registry.go:35`——链形状下由用户层值优先注入，不触发缺省）；目的 `224.0.0.13`×14（ALL-PIM-ROUTERS）/ `192.0.2.254`×7（Join/Prune 上游单播）/ 其余 3（见 §13.1 分布表）。

## 11. 引用与缩写（沿 §13.4 三路口径）

- RFC 7761（PIM-SM）、RFC 4607（SSM）、RFC 5015（Bidirectional PIM 待实现边界）；wireshark `packet-pim.c`（本机 3.6.14 实测 `pim.*` 107 字段——断言通道权威，用例去重 28 字段）；本仓库已落码 builder/planner/generator（`internal/protocol/pim/` 1611 行）为 wire 真相；只借鉴字段语义与拆解思路。

## 13. P1 规范矩阵（CORE_MEMORY §4 八项：规范要求→业务场景→代码现状→缺口）

> 深度口径（§4.19–4.22）：矩阵三张子表——①报文×组播状态矩阵（§13.2）②数据形态变体表（§13.3）③商业行为→用例映射表（§14.2）。条目三选一：已实现 / 明确不支持 / 不适用 + 对应用例号；无遗漏留白。
> **raw-IP 载体铁律（逐矩阵行重申）**：pim 直挂 ip（registry `DependsOn ["ip"]`，`FieldContract ip.protocol=103`）——TCP/UDP 载体判死（链中夹 tcp/udp 层即错，`isRawIPChain :40-51` 含 tcp/udp 即否；igmp 同族先例）；PIM 无端口语义；无握手，五件套时间线诚实写“建连面无”。

### 13.1 八项规范矩阵

| # | 规范要求（RFC + 本契约节） | 业务场景 | 代码现状 | 缺口 |
|---|---|---|---|---|
| 1 | 连接模型：组播路由信令；DR→RP 单播 Register，其余组播；无连接、无握手、无重传确认；一事件 = 一 PCAP frame（RFC 7761 / RFC 4607；本契约 §1） | 路由器 Hello 邻居发现；DR 向 RP 注册组播源；下游向上游 Join/Prune 拉组播树；BSR/RP 选举通告 | 已实现：生成器单事件直发（`layer_gen.go:21-70` 事件序逐包 Emit；c2s→up/s2c→down `:72-77`）+ raw-IP 自驱（`chain_planner.go:1356-1450` isRawIPChain 分支，`meta.PIM :1370`，TTL 缺省由 spec 注入 `1429-1431`） | P4 只做层链整形+链级红例+casegen（§15） |
| 2 | 命令消息表：Hello `0x00`/Register `0x01`/Register-Stop `0x02`/Join-Prune `0x03`/Bootstrap `0x04`/Assert `0x05`/Candidate-RP-Adv `0x08`（RFC 7761；本契约 §3） | 七类控制动作全表逐消息编码 | 已实现：`buildMessageByKind`（`builder.go:517-536` 七分支；未知 kind 拒 `:534`）+ Type 常量（`:15-23`）+ frames `20/21/22/23/24/25/28 00` 实测 26 帧全对 | P5 逐例先跑后钉（frames 全 offset 34 单档，存量实测） |
| 3 | 状态机：PIM 无连接状态机；主机侧唯一有序面 = Hello（邻居 up）→ Join（joined）→ Prune（pruned）→ Holdtime 过期；DR 选举按 priority+地址 tie-break；多会话（邻居×组×源）状态隔离（RFC 7761；本契约 §4/§6） | 邻居上线后拉树；DR 切换；组播树切换源 | 已实现：事件 `state/neighbor/retransmission` 元数据直通（`routing.go:182-213` 27 键；生成器/builder 不消费 `state`，仅携带——§10 诚实声明）；`directionFor` 逐包方向（`:72-77`） | 多会话并发交错序 → B′（G-PIM-2，不假设调度器交织顺序） |
| 4 | 字段表：4 字节公共头（Version 2 + Type + Reserved + Checksum）；Hello 四 options（Holdtime/LAN Prune Delay/DR Priority/Generation ID）；Join/Prune 编码组/源地址（通配 W 位 `srcFlagWild=0x02 :36`）；Bootstrap BSR/RP-set；Register flags+inner IPv4（RFC 7761；本契约 §1/§3–§4） | 单邻居/多邻居 Hello；`(*,G)` 与 `(S,G)` 拉树；RP 选举；源注册 | 已实现：`buildHello`（`:193-239` Holdtime 必发 `:196-201`、LAN `:204-217`、DR `:219-225`、GenID `:227-237`）+ `encodeSource :151-170`（W 位置位 `:155`）+ `buildBootstrap :284` + `buildRegister :352`（8 字节前缀 checksum `:379`，§10 裁定）+ `buildAssert :402` | Register checksum 条文拆分 → D-PIM-1 定稿（§10/§15）；`hello_interval` 不进线（§10）；`state` 不消费（§10） |
| 5 | 错误处理：IPv6 profile / 坏 checksum / 长度 / 未知 type / 地址族混用 / SSM 带 RP / DF 混入七类拒收（本契约 §7） | 脏包、错配、伪造 checksum 一律 task error，零假成功 | 已实现：7 锚词行见 §7 表（`planner.go` 全行实测；锚词逐字对 §7：`profile :30`/`checksum :146`/`length :148`/`type :150`/`address :102-104/:131`/`ssm :62/64/70/75`/`df :57`） | 链级红例 4 例 P4 新增（presence/白名单/TCP 载体/缺 ip，§14-P2） |
| 6 | 超时活性：Hello Holdtime/interval 邻居保活；Holdtime=0 即时失效；Join/Prune Holdtime 过期不自动刷新（本契约 §4/§6） | 邻居掉线检测；组播树保活刷新 | 已实现：Holdtime 必发（含 0 边界 `#3`）；`hello_interval` 仅携带不进线（§10）；周期定时器 = 明确不支持（§16），不立项 | 无缺口（显式不适用 ≠ 缺口；周期调度面归引擎调度器，不归本协议） |
| 7 | NAT/代理：PIM 是域内组播路由信令（TTL=1 组播 Hello + 单播 Register），无 NAT 遍历语义；源地址为单播 fixture，目的为组播/单播按事件语义（RFC 7761；本契约 §2） | 同域组播路由 | 不适用（显式声明，不用“待确认”逃逸）：无 PIM 层语义可测，无用例 | 无缺口（显式不适用 ≠ 缺口） |
| 8 | 版本方言：PIMv2（Version=2）/ PIM-SM（RFC 7761）/ PIM-SSM（RFC 4607，`(S,G)` 限定）/ PIM-DM（RFC 3973，Graft-Ack Type 7 不在本版）/ Bidir（RFC 5015，DF 选举独立 profile）/ IPv6（独立 profile 边界）（本契约 §1/§5） | 稀疏模式组播域；SSM 源特定；DM/Bidir/IPv6 另议 | 已实现：Version 恒 2（`builder.go:48`）；三 profile 分支（SM/SSM 允许 + IPv6/Bidir 拒 `planner.go:29/57`）；白名单 `protocols.go:46` | 现网 DR/BSR/RP 行为抓包确认 → G-PIM-1；DM/Bidir/IPv6 另协议另议 |

### 13.2 子表①：报文×组播状态矩阵（逐格已覆/缺失）

行=报文形状，列=组播状态面：

| 报文 \ 状态面 | 合法目的（组播/单播按语义） | 状态元数据（state/neighbor/retransmission） | 非法目的/载体 | SSM 约束 |
|---|---|---|---|---|
| Hello（含 options/零 Holdtime） | 已覆 #1/#2/#3（`224.0.0.13` ALL-PIM-ROUTERS） | 已覆 #13（DR election 三邻居 priority/tie-break；`directional=true`） | 缺口→链级红例（TCP 载体/缺 ip，§14-P2） | 不适用（Hello 与 SSM 正交） |
| Join/Prune（wildcard `(*,G)`） | 已覆 #4（上游单播 `192.0.2.254` + 组 `239.1.1.1`） | 已覆 #7（显式重传 2 包；`retransmission=true`） | 缺口→#22 通道（地址族混用 v6 组/源） | 负例 #23 通道（SSM wildcard `(*,G)` 拒，`ssm` 锚词） |
| Join/Prune（`(S,G)`） | 已覆 #5（具体源 + joined/pruned 双列表） | 已覆 #6（双 group 各自 source 列表；`numgroups`） | 缺口→#22 通道 | 已覆 #16（SSM `(S,G)` 具体源，无 RP） |
| Join/Prune（多 group/多事件） | 已覆 #17（双 `(S,G)` 事件 2 包） | 已覆 #14（6 包：2 Hello + 4 Join/Prune；`(*,G)` 与 `(S,G)` 隔离） | 不适用 | 已覆 #17（SSM 多 group） |
| Bootstrap/RP-set | 已覆 #8（BSR + hash mask + RP priority） | 不适用（选举输入面，无会话状态） | 不适用 | 负例 #23 通道（SSM Bootstrap 拒） |
| Candidate-RP-Adv | 已覆 #9（C-RP + priority/Holdtime/前缀） | 不适用 | 不适用 | 负例 #23 通道（SSM C-RP 拒） |
| Register/inner IPv4 | 已覆 #10（flags + inner 源/组/载荷；8 字节前缀 checksum §10 裁定） | 不适用 | 不适用 | 负例 #23（SSM Register 拒，`ssm` 锚词） |
| Register-Stop/Assert | 已覆 #11/#12（显式 group/source + RPT/metric） | 不适用 | 不适用 | 负例 #23 通道（SSM Register-Stop 拒） |
| Holdtime=0/checksum/长度 | 已覆 #3（零 Holdtime 即时失效）+ #15（checksum nonzero + `ip.len`） | 已覆 #7（重传相等性） | 缺口→负例 #19/#20（checksum/length 拒） | 不适用 |

注：矩阵按**报文×状态仲裁轴**排——本引擎只做路由器侧报文生成（声明式回放族），对端动态应答只由 tshark 字段面验证。**逐格重数（9 行 × 4 列 = 36 格，逐格枚举，可复核）**：**已覆 16 格**（R1c1←#1/#2/#3、R1c2←#13、R2c1←#4、R2c2←#7、R3c1←#5、R3c2←#6、R3c4←#16、R4c1←#17、R4c2←#14、R4c4←#17、R5c1←#8、R6c1←#9、R7c1←#10、R8c1←#11/#12、R9c1←#3/#15、R9c2←#7）；**负例通道 8 格**（R2c3←#22、R2c4←#23、R3c3←#22、R5c4←#23、R6c4←#23、R7c4←#23、R8c4←#23、R9c3←#19/#20）；**链级红例通道 1 格**（R1c3 Hello 非法载体←§14-P2 TCP 载体/缺 ip；R2c3 归 #22 通道，不双重认领）；**不适用 11 格**（R1c4、R4c3、R5c2、R5c3、R6c2、R6c3、R7c2、R7c3、R8c2、R8c3、R9c4）。16 + 8 + 1 + 11 = 36 ✓ **逐格有结论、无空格**。

### 13.3 子表②：数据形态变体表（协议相关全部形态逐项）

| 变体维度 | 形态 | 对应用例 | 备注 |
|---|---|---|---|
| kind×Type | hello `20 00`/register `21 00`/register-stop `22 00`/join-prune `23 00`/bootstrap `24 00`/assert `25 00`/candidate-rp `28 00` | #1–#17（frames 26 帧逐类；`23 00`×12 含重传/多事件） | `buildMessageByKind` 七分支全覆；未知 kind 拒 → `planner.go:534`（`df_election` 专拒 `:57`） |
| Hello options | Holdtime 必发/零边界 + LAN Prune Delay（T/propagation/override）+ DR Priority + Generation ID | #1/#2/#3/#13 | `pim.holdtime/t/propagation_delay/override_interval/dr_priority/generation_id` 6 字段实测命中 |
| Join/Prune 源形 | wildcard `*`（W 位 `0x02`）/ 具体 `(S,G)` / joined+pruned 双列表 / 多 group | #4/#5/#6/#7 | `pim.upstream_neighbor/group/source/numgroups/numjoins/numprunes` 6 字段 |
| Bootstrap 面 | BSR 地址/priority + hash mask + group-prefix + RP-set（RP/priority/Holdtime） | #8 | `pim.bsr/bsr_priority/hash_mask_len/rp/priority/group` 6 字段 |
| C-RP 面 | C-RP 地址 + priority + Holdtime + group-prefix 列表（`prefix_count`） | #9 | `pim.rp/priority/holdtime/prefix_count` 4 字段 |
| Register 面 | flags（border/null）+ inner IPv4（源/组目的/载荷）+ 8 字节前缀 checksum | #10 | `pim.register_flag.border/null_register` 2 字段；checksum §10 裁定 |
| Register-Stop/Assert 面 | 显式 group/source；Assert RPT + metric_pref + metric | #11/#12 | `pim.group/source/rpt/metric_pref/metric` 5 字段 |
| 多包事件 | DR election 3 包、多邻居 6 包、重传 2 包、SSM 双事件 2 包 | #13/#14/#7/#17 | `directional=true` 仅 #13/#14；重传 `retransmission=true` 无隐式序号 |
| SSM 约束 | 具体 `(S,G)` 允许；RP/Bootstrap/C-RP/Register/wildcard 全拒 | #16/#17 + #23 | `planner.go:60-79` SSm 分支全覆盖；`ssm` 锚词 |
| 载体不变量 | `ip.proto=103`、TTL=1（存量 24/24）、ALL-PIM-ROUTERS `224.0.0.13`×14 | #1–#17 全正例 + #15 独立例（`ip.len`） | `FieldContract ip.protocol=103`；TTL 由 `ip` 层值注入，缺省 64 不触发 |
| checksum | 全报文 one's-complement（Register 8 字节前缀例外）；PCAP 只 `nonzero=true` | #1（`pim.cksum` nonzero）+ #15（双 checksum 面）+ #19（错误拒） | 固定常量不钉 frames（§2 底稿铁律延续） |
| 目的分布 | 组播 Hello `224.0.0.13` / 上游单播 `192.0.2.254` / Register 单播 RP / SSM 组 `232/8` | #1–#3/#13（组播）/#4–#7（单播）/#10（RP 单播）/#16（SSM） | 存量分布见 §2（14/7/余 3） |
| version 面 | Version 恒 2（高 4 bit `0010`） | #1（`pim.version=2`） | 实现 `version=2`（`builder.go:48`） |
| profile 面 | SM（20 例）/ SSM（3 例）/ IPv6-pending（1 负例） | #1–#15/#16–#17/#18 | `profile` 锚词（`planner.go:29-31`） |

### 13.4 P1 三路对照（CORE_MEMORY §4.12–4.15）

**①规范原文**：RFC 7761（PIM-SM）+ RFC 4607（SSM）全文为“必须是什么”底线；Type/头长/载体/状态语义四面已逐节落本契约 §1/§3–§6。

**②现网行为**：路由器 Hello 邻居发现（目的 `224.0.0.13`、TTL=1）、DR 向 RP 单播 Register、BSR/RP 选举通告、SSM 源特定拉树为现网通用形态。出处确认方式：抓现网/回环 PIM 包核对 Type/目的/TTL 面（**立项 G-PIM-1**：现网级确认前相关条目按 §5.5 标“待确认”，不写死进实现）。

**③开源实现思路**：wireshark `packet-pim.c`（本机 3.6.14 实测 `pim.*` 107 字段——断言通道权威；用例去重 28 字段）；本仓库已落码 builder/planner/generator（`internal/protocol/pim/` 1611 行）为 wire 真相；只借鉴字段语义与拆解思路。

**三路结论一致性**：三路在“Type 七值（`0x00/01/02/03/04/05/08`）、4B 公共头、Hello 四 options、Join/Prune 编码组/源、SSM `(S,G)` 限定、TTL=1、Protocol=103”七点一致。取舍：①内层编码字节以 builder 编码 + tshark 读回为准，先跑后钉；②现网 DR/BSR 差异面（选举间隔、RP 选择策略、SSM 源通告策略）未到确认级 → G-PIM-1，不写死。

### 13.5 候选方案对比（§4.17）

| 方案 | 走法（含借鉴来源） | 优 | 劣 | 性能/复杂度/兼容性 | 结论 |
|---|---|---|---|---|---|
| A 结构化声明式回放 | profile/events（kind/direction/groups/rp/bsr/inner）结构化 + wire 由 builder 纯函数产出（同族 igmp/ospf 路由终结层范式） | 字段可结构化断言；动态面可开；与已收官族同构 | 多会话交织序不假设 | O(n) 流式；复杂度低；双 profile 兼容 | **采用（已落码）** |
| B 生 hex 回放 | 整 packet hex 覆盖 | 最简单 | 字段不可断言；Join/Prune 变体即死 | 动态零分 | 仅作负例特殊形逃生口 |
| C 完整组播路由状态机模拟器 | 自动补邻居响应/注册响应/重传定时 | 真实度高 | 超出声明式回放族边界；与 §3.13“不许隐式编排”冲突 | 复杂度高、收益无 fixture 面支撑 | 不选 |

## 14. 门1 §1–§14 十四行对照表（CORE_MEMORY §15.1–15.3）

| § | 本协议怎么满足 | 证据 |
|---|---|---|
| §1 层链唯一真相 | 旧键 `src_ip/dst_ip/ttl` 三键迁入 `ip` 层；顶层 `pim` 子映射迁入 `layers[]` pim 条目；24 个历史语义例均为严格层链，4 个当前链级负例仅用于拒绝通道；数量走兄弟键 `strategy_fc` | 本契约 §2、§14.1 与当前 JSON 28 例 |
| §2 策略/任务 | 策略=单 PIM 事件模板（自带 `strategy_fc` flows/bps/time；`worker.go:254` `flowCount<=0` 恒 ≥1（`:255-257`））；任务=多策略合跑+总量封顶（`worker.go:262` 共享计数器+失败释放槽位）；`strategy_fc.flows=N` 复制 N 条流按 §14.12 动态算值；框架语义未动 | 本契约 §13.1 #1 + §15 |
| §3 五件套 | 见 §14.3 强制展开：双 profile 会话表/事务序列/关联关系/插入位置/时间线；**无连接组播诚实写“建连面无”**，不虚构 handshake 包数（当前 17 个正例与 11 个负例均无握手断言）; 单包协议按 §3.14 豁免顶层 `sessions[]`（`events[]` 承载多组隔离，不豁免多流覆盖） | 本契约 §14.3 + 用例 #13/#14/#15 |
| §4 查规范 | RFC 7761 + RFC 4607（编号级引用，精确章节待 G-PIM-1）+ tshark `pim.*` 107 字段实测（用例去重 28：`pim.*` 26 + `ip.*` 2）+ 已落码 builder wire 真相 + §13 矩阵 8 行+三子表 + 三路对照（§13.4） | 本契约 §13 |
| §5 依赖与错误 | `DependsOn ["ip"]`（registry.go:896；单载体、无 OptionalOn 面——pim 无端口/传输层语义，终结层豁免 0c355be 下 pim 无 OptionalOn 声明不受影响）；`FieldContract ip.protocol=103`（`builder.go:65` `ProtocolPIM`）；7 负例锚词表逐字（行号实测，见 §7）；失败返回 task error（零假成功） | 本契约 §2/§7 + §15 错误分支 |
| §6 性能 | 单事件流式渲染无全量聚合；pcap/NIC 双路验收；吞吐/并发/内存目标待 P4 基准后定（§6.5 诚实待确认，不写承诺数字）；六类场景清单见 §15 | §15 性能设计与验收 |
| §7 三份文档 | 40-pim-{design,testcase}.md v2.0.0（行为面权威）+ D-PIM-1（本契约 §15 草稿，门1 获批=定稿）+ T-PIM（testcase §9 草稿）+ generated schema（pim 已在生成表内 `layers.generated.json:2457-2465`，P4 只跑 `TestLayersGeneratedMatchesRegistry` 验证无过期） | 修订记录 |
| §8 设计先行 | 本条目 P1–P3 先于 P4 层链整形开工；门1 获批=D-PIM-1 定稿=开工门 | 提交序 |
| §9 测试三源 | 三源=RFC 条款（编号级，精确章节待 G-PIM-1）+ D-PIM-1 + tshark `pim.*` 107 字段已实证（用例去重 28） + builder wire 真相 + 现网 DR/BSR/RP 形态（未确认级→G-PIM-1）；当前 JSON 28 例（24 个历史语义例 + 4 个新增链级例）正负对账 | T-PIM（testcase §9） |
| §10 评审闭环 | 每阶段对抗自重审（结论见 p123 报告）+ 收官隔离复审 + 修轮；红先绿后 | /tmp/pipe/73-pim/p123-report.md |
| §11 白话 | 每阶段白话一句先行 | 汇报 |
| §12 动态清单 | 见 §14.12 强制展开：地址=`ip` 层（五策略全支持）；业务字段逐个列开/不开+理由；序号算法位置诚实“待 P4 定”（不编行号，§5.7） | 本契约 §14.12 |
| §13 schema 派生 | registry pim 行（§13 单载体 `DependsOn ["ip"]`；`FieldContract ip.protocol=103` 由终结层生成器固写 `layer_gen.go:44-49` + `transportProtocol :229/:243` 双看位）→ schemagen 重跑验证；struct 标签字面量锁 | §15 接线件 |
| §14 真实流程 | suite 经 MCP 建任务→引擎生成→tshark `pim.*` 字段 + frames hex 双通道；先跑后钉；pcap 落 `/tmp/mcp-pcaps/pim/` | 用例 §1/§6 |

### 14.1 §1 强制展开：旧键去向 + 完整 spec_json 样例

旧键清单（`src_ip`/`dst_ip`/`ttl` + 本协议顶层子映射 `pim` + 缺失的数量键）：

| 旧键 | 去向 |
|---|---|
| `src_ip` | → `layers[0].ip.src`（fixture `192.0.2.1` 起各例保留；`pim_sm_register` 的 `192.0.2.100` 为 DR 源语义，保留） |
| `dst_ip` | → `layers[0].ip.dst`（分布保留：`224.0.0.13`×14 ALL-PIM-ROUTERS / `192.0.2.254`×7 上游单播 / `192.0.2.10`+`192.0.2.100`+`192.0.2.1` 各 1，见 §13.3 目的分布行） |
| `ttl` | → `layers[0].ip.ttl`（当前 24 个历史语义例均为 1；与 `ip` 层缺省 64 `registry.go:35` 不同——链形状下用户层值优先注入 `chain_planner_chain.go:450-459`） |
| 顶层 `pim` 子映射 | → `layers[1]` 中 `{"pim": {...}}` 条目（业务键 `profile/checksum_mode/events`（顶层 `wire_fault` 空缺：存量 24/24 无顶层 `wire_fault`，故障注入全在事件内）全量迁入，零残留；`PIMEvent` 27 键见 `routing.go:182-213`） |
| 缺失的数量键 | → 兄弟键 `strategy_fc`（`{"type":"flows","value":N}`，N=packet_count：单包例 1；#7/#17 为 2；#13 为 3；#14 为 6；正例总包数 29；负例 `value=1` 占位——拒绝发生在 Plan 前，flowCount 不触发多发） |

**24 个历史语义例已迁为严格层链形；4 个新增链级负例不属于旧例去向表。** 当前 JSON 的 24 个历史语义例均为 `[ip,pim]`；逐键去向：

| 现状 | 去向（P4 改写） |
|---|---|
| 顶层 `src_ip`（23 例 `192.0.2.1` + 1 例 `192.0.2.100`） | 删除顶层键；写进 `layers[0]`（`{"ip": {"src": ..., "dst": ..., "ttl": 1}}`） |
| 顶层 `dst_ip`（24/24） | 删除顶层键；写进 `layers[0].ip.dst`（分布保留，见上表） |
| 顶层 `ttl`（24/24 全为 1） | 删除顶层键；写进 `layers[0].ip.ttl` |
| `layers` 内 `{"ip":{}}` / `{"pim":{}}` 空条目 | 填入顶层迁移值（ip 条目填 src/dst/ttl；pim 条目填顶层 `pim` 子映射全部业务键 `profile/checksum_mode/events` + 事件内 `wire_fault`） |
| 兄弟 `strategy_fc` | 17 个正例按 `packet_count` 补齐（`{"type":"flows","value":N}`）；负例不含成功数量 |
| 负例事件内 `wire_fault`（#19/#20/#21） | 随 `events[]` 进 `layers[1].pim`，拒绝语义不变（锚词 `checksum/length/type` 已对 `planner.go:146/148/150`） |

改写后必须满足：正例 `spec_json` 顶层仅有 `layers`（`strategy_fc` 为兄弟键）；4 个链级负例保留故障触发所需的故意违规键；全部 11 个负例 `expect` 键集合严格为 `{expect_error, error_contains}`。

完整 Hello 样例（目标形状；`strategy_fc` 为 `spec_json` 兄弟键）：

```json
{
  "spec_json": {
    "layers": [
      {"ip": {"src": "192.0.2.1", "dst": "224.0.0.13", "ttl": 1}},
      {"pim": {"profile": "pim_sm_rfc7761_ipv4", "checksum_mode": "auto",
        "events": [{"kind": "hello", "direction": "c2s", "holdtime": 105}]}}}
  ,
  "strategy_fc": {"type": "flows", "value": 1}
}
```

Join/Prune `(*,G)` 样例（含上游单播目的 + 通配源）：

```json
{
  "spec_json": {
    "layers": [
      {"ip": {"src": "192.0.2.1", "dst": "192.0.2.254", "ttl": 1}},
      {"pim": {"profile": "pim_sm_rfc7761_ipv4", "checksum_mode": "auto",
        "events": [{"kind": "join_prune", "direction": "c2s",
          "upstream_neighbor": "192.0.2.254", "holdtime": 180,
          "groups": [{"group": "239.1.1.1",
            "joined_sources": [{"wildcard": true}], "pruned_sources": []}],
          "state": "upstream_join"}]}}}
  ,
  "strategy_fc": {"type": "flows", "value": 1}
}
```

多包事件样例（#14 多邻居；`events` 住 pim 层内，`directional=true`）：

```json
{
  "spec_json": {
    "layers": [
      {"ip": {"src": "192.0.2.1", "dst": "224.0.0.13", "ttl": 1}},
      {"pim": {"profile": "pim_sm_rfc7761_ipv4", "checksum_mode": "auto",
        "events": [
          {"kind": "hello", "direction": "c2s", "neighbor": "192.0.2.10",
           "holdtime": 105, "dr_priority": 10},
          {"kind": "hello", "direction": "s2c", "neighbor": "192.0.2.20",
           "holdtime": 105, "dr_priority": 20},
          {"kind": "join_prune", "direction": "c2s",
           "upstream_neighbor": "192.0.2.10", "holdtime": 180,
           "groups": [{"group": "239.1.1.1",
             "joined_sources": [{"wildcard": true}], "pruned_sources": []}]},
          "...（3 个 Join/Prune 事件，共 6 包）"]}}}
  ,
  "strategy_fc": {"type": "flows", "value": 6}
}
```

### 14.2 子表③：商业行为→用例映射表（CORE_MEMORY §4.16；缺此表按 §4.22 记缺口）

| # | 商业行为（产品+行为） | 出处 | 对应用例 | 状态 |
|---|---|---|---|---|
| 1 | 路由器 Hello 邻居发现（目的 `224.0.0.13`，TTL=1，Holdtime/options/DR 选举） | 现网通用形态（RFC 7761 同构） | #1/#2/#3（Hello 三态）/#13（DR election 三邻居） | 已映射；**现网抓包级确认** → G-PIM-1（确认方式：抓路由器回环包） |
| 2 | 下游向上游 Join/Prune 拉树（`(*,G)` 通配 + `(S,G)` 具体 + 多组 + 显式重传） | 现网通用形态 | #4/#5/#6（wildcard/源/多组）/#7（重传 2 包） | 已映射；确认 → G-PIM-1 |
| 3 | BSR 选举与 RP-set 通告（hash mask + RP priority）/ C-RP 通告（priority/Holdtime/前缀） | 现网通用形态 | #8（Bootstrap）/#9（Candidate-RP-Adv） | 已映射 |
| 4 | DR 向 RP 单播 Register（含 inner IPv4 载荷）/ RP 回 Register-Stop / 共享网段 Assert 竞争 | 现网通用形态 | #10（Register）/#11（Register-Stop）/#12（Assert） | 已映射；Register checksum 8 字节前缀面 → §10 裁定已对齐实现 |
| 5 | 多邻居多组状态隔离（`(*,G)` 与 `(S,G)` 不互盖）+ SSM 源特定拉树 | 现网通用形态 | #14（6 包隔离）/#16/#17（SSM 单/多组） | 已映射 |
| 6 | 脏包/错配/伪造 checksum 拒收（planner 拒） | 引擎行为（planner 真实锚词行） | #18–#24（7 负例，锚词逐字见 §7） | 已映射 |
| 7 | 边界编码（Holdtime=0、checksum nonzero、`ip.len`、通配 W 位） | RFC 7761 编码面 | #3（零 Holdtime）/#15（checksum+长度）/#4（W 位） | 已映射 |

注：本表凡记“现网通用形态”但未落抓包证据的，一律挂 G-PIM-1 且不写死进实现（§5.5）。

### 14.3 §3 强制展开：五件套（双 profile，无连接组播）

会话表：

| 会话 | profile | 四元组（诚实：无端口、无握手） | 生命周期（诚实：无建连/无挥手） |
|---|---|---|---|
| s1 | pim_sm_rfc7761_ipv4 | `ip.src` 单播 + `ip.dst` 组播（Hello `224.0.0.13`）/单播（Join 上游 `192.0.2.254` / Register RP），TTL=1 | Hello → Join/Prune（joined/pruned）→ 结束（单 datagram，无建连） |
| s2 | pim_ssm_rfc4607_ipv4 | 同上四元组面；组 `232/8` SSM 范围 | Join `(S,G)` 具体源 → 结束；无 RP/Bootstrap/Register 面 |

事务序列（单事务四件事 §3.4–3.7）：

| 事务 | 前置条件 | 触发动作 | 成功分支 | 失败分支 |
|---|---|---|---|---|
| t1 hello 邻居发现 | sN 路由器在线（member 前置无） | 发 Hello（Holdtime/options/DR priority） | 对端邻居 up；tshark `pim.type=0` + `holdtime` 命中 | 非 IPv4 profile → task error（#18 通道，`profile` 锚词） |
| t2 join 拉树 | t1 已发或下游主动拉树 | 发 Join/Prune（`(*,G)` 通配或 `(S,G)` 具体 + 上游邻居） | `numgroups/numjoins/numprunes` 命中 | 地址族混用 → task error（#22 通道）；SSM 通配 → task error（#23 通道） |
| t3 BSR/RP 选举通告 | sN 为 BSR/C-RP 角色 | 发 Bootstrap（BSR+RP-set）/ Candidate-RP-Adv | `bsr/hash_mask_len/rp/priority/prefix_count` 命中 | SSM 携带 → task error（#23 通道） |
| t4 注册与断言 | t2 已拉树（Register 需组播源存在） | 发 Register（flags+inner）→ Register-Stop / Assert（RPT+metric） | `register_flag/inner` + `rpt/metric` 命中 | SSM Register → task error（#23 通道）；DF 混入 → task error（#24 通道，`df` 锚词） |
| t5 多会话扇出 | 各会话独立 neighbor/group/source | 按事件序逐包 Emit（`layer_gen.go:55-70`） | 会话隔离（#14 6 包）；`directional=true` 仅 #13/#14 | 状态串用 → task error；交织序不假设（G-PIM-2） |

关联关系（§3.8–3.10 三件事）：本协议**无控制流驱动数据流**（无 `driven_by` 派生流），但有**同事件序内 hello→join 语义关联**：归属会话 sN（`events[].neighbor/upstream_neighbor`）、归属报文组（同 group 地址）、由 `group` 字段决定——与 CWMP 范本差异点诚实声明：pim 无副流派生，`events[]` 承载“多报文有序序列”（本契约 §6）。
| 管道分支 | 路由面动作 |
|---|---|
| 单事件直发 | `layer_gen.go:55-70` 逐事件 `buildMessageByKind` 后 `emit(directionFor)`；方向 c2s→up/s2c→down（`:72-77`），下行 L3 源目由 raw-IP 分支交换（`chain_planner.go:1405-1407`） |
| 多事件序列 | 事件序即发送序；`retransmission=true` 只标记重复（`routing.go:190` bool 注释"不改 wire 字节"），无隐式序号 |

插入位置：终结层——pim bytes 经 IPv4 `Protocol=103` 直传（`transportProtocol` 看末层/倒二层 `case "pim"`，`chain_planner_util.go:229/243`；L3.Protocol 由生成器固写 `core.ProtocolPIM`，`layer_gen.go:44-49`；TTL 缺省由 spec 注入 `chain_planner.go:1429-1431`，用户层值优先 `chain_planner_chain.go:450-466`）；IP 无 option 时 PIM 起点 offset 34（frames 26 帧全 offset 34 单档实测）。

时间线：**顺序**——同会话内 t1→t2→(t3/t4) 严格报文序；会话间并发但输出不假设全局包序，只断言包内状态与隔离；无“长传输分片让位”面（单 datagram）；控制可中插动作=无（pim 无 ABOR/STAT 类动作）。§3.12 的调度方式在本协议落点为“按事件序逐包 Emit”。

### 14.12 §12 强制展开：动态字段清单

| 字段 | 住处 | 开策略 | 理由 |
|---|---|---|---|
| `src`（src_ip） | ip 层 | fixed/inc/rand/list/pattern 全开 | §12.2 地址必备；多路由器并发锚点（`extractLayerSrcDst :305-323` 逐流取层值；`resolveLayerTuple` 逐流解析 `worker.go:316`） |
| `dst`（dst_ip） | ip 层 | fixed（组播/单播 fixture 钉死；多组地址池待立项） | 目的须按事件语义（组播 Hello vs 单播上游）；动态组地址池 → G-PIM-3 |
| `ttl` | ip 层 | 不开（恒 1，由层值注入） | 故障值只走负例拒绝通道（`length` 面），不做动态 |
| `profile` | pim 层 | 不开（SM/SSM 各自独立模板） | profile 切换 = 换策略（§2.5），不用动态冒充 |
| `kind` | pim 层 | 不开（七类事件各自独立模板） | 同上，换策略表达 |
| `holdtime`/`hello_interval` | pim 层 events[] | 不开（fixture 钉死；interval 仅携带不进线 §10） | 计时语义值，非按流变化量 |
| `neighbor`/`upstream_neighbor` | pim 层 events[] | 不开（fixture 钉死；多邻居扇出靠 events[] 显式） | 多邻居靠显式事件（§3.1），与动态正交；地址池面 → G-PIM-3 |
| `group`/`source`/`groups[]` | pim 层 events[] | 不开（fixture 钉死字节） | 组/源变体靠多策略（§2.5），不用动态冒充 |
| `bsr`/`rp`/`group_prefixes`/`rp_sets` | pim 层 events[] | 不开（fixture 钉死） | 选举面 fixture，非按流变化量 |
| `register_flags`/`inner_ipv4` | pim 层 events[] | 不开（fixture 钉死字节） | 注册变体靠多策略，不用动态冒充 |
| `events` | pim 层 | 不开（扇出结构静态声明） | 多流靠显式事件（§3.1），与动态正交 |

序号算法代码位置：**待 P4 定**（D-PIM-1 定稿后 casegen/层链整形落码时钉死文件+行号；此处不编行号——§5.7）。

### 14-P2 presence 负例形状（链级红例必含①）

层链+顶层空子映射并存=判死负例（presence 负例形状，非残留）：`{"layers":[{"ip":{}},{"pim":{}}],"pim":{}}`（顶层空 `pim:{}` 与层链并存）必须 planner/validator 拒——**但 pim 当前 `CheckProtoFlat` 无同名子映射分支**（`strategy_convert.go:8515-8526` `rawWrapChains` 仅含 pppoe/ldap/rtmp/rtsp/pptp/vnc/xmpp/sctp/jt808/jt809/jtt905/arp/icmp，无 pim；实测 `grep -n "pim" :727` 仅解析分支）：P4 须补 `pim` presence 判死分支（协议本地文件 `strategy_convert.go`，`error_contains` 含顶层键锚词 `no longer accepts a top-level pim sub-config`），否则 presence 形静默过（顶层先填 spec 赢层配置——隔离复审 F1 探针同构）。白名单外游离键（如顶层 `src_mac`/`ttl`——`ttl` 已迁 `ip` 层，顶层出现即游离）判死负例见 §15。**另注**：pim 单 raw-IP 载体 → 链中夹 `tcp`/`udp` 层（`[ip,tcp,pim]` / `[ip,udp,pim]`）判死负例（`isRawIPChain :40-51` 含 tcp/udp 即否，转 transport 分支出错）；链缺 `ip`（`[pim]` 裸链）判死负例（`DependsOn ["ip"]` 缺失由 `complete.go:484-491` 拒绝）。P4 链级红例共 4 例 + 收官自查行「非负例 `spec_json` 顶层键=0」。

## 15. D-PIM-1 P2 代码设计草稿（CORE_MEMORY §8 八要素；门1 获批=定稿）

> 体裁：文件清单/接口签名/数据结构/主流程/错误分支/性能设计与验收/回滚方式。pim wire 面已落码，D-PIM-1 覆盖“已落码对接 + P4 层链整形差量”，不重发明 wire。

**文件清单（已落码 4 + P4 新建 1 + 接线/守卫 2，已落码行号实测）**：

| 文件 | 职责 |
|---|---|
| internal/protocol/pim/builder.go（已落码，536 行） | wire 纯函数：`checksum`（`:52` one's-complement，奇长补零参与计算）/`buildPIM`（`:175` 公共头组装 + checksum 回填）/`buildHello`（`:193` 四 options：Holdtime 必发 `:196-201`、LAN `:204-217`、DR `:219-225`、GenID `:227-237`）/`buildJoinPrune`（`:242` 上游+组/源计数回填）/`buildBootstrap`（`:284`）/`buildCandidateRPAdv`（`:323`）/`buildRegister`（`:352` 8 字节前缀 checksum `:379`，§10 裁定）/`buildRegisterStop`（`:386`）/`buildAssert`（`:402` RPT+metric 打包）/`encodeSource`（`:151-170`，W 位置位 `:155`，`srcFlagWild=0x02 :36`）/`buildMessageByKind`（`:517` 七分支，未知 kind 拒 `:534`） |
| internal/protocol/pim/planner.go（已落码，159 行） | `Planner.Validate`（`:20`：非 IPv4 profile 拒 `:29-31`、checksum_mode `:33-37`、顶层 wire_fault `:39-41`、事件序 `:43-47`）/`validateEvent`（`:53`：df 拒 `:57`、SSM `:60-79`、地址族 `:85-99`、组/源/前缀 `:101-121`、事件 wire_fault `:81-83`）/`validateSource`（`:127`）/`validateWireFault`（`:140` 四值 checksum/length/type/address） |
| internal/protocol/pim/layer_gen.go（已落码，82 行） | `PIMGenerator.Generate`（`:21-70`：`Emit` 空拒、无 events 拒、逐事件 `buildMessageByKind`+`emit(directionFor)`；L3 固写 `SrcIP/DstIP/Protocol=PIM` `:37-49`）/`directionFor`（`:72-77` c2s→up/s2c→down）/双注册（`:79-82` 生成器+校验器） |
| internal/core/routing.go（已落码） | `PIMConfig`（`:174-179` 4 键）+ `PIMEvent`（`:182-213` 27 键）+ `PIMLANPruneDelay`（`:216-220` 3 键）+ `PIMGroup`（`:223-227`）+ `PIMSource`（`:230-233`）+ `PIMRPSet`（`:236-240`）+ `PIMRP`（`:242-246`）+ `PIMRegisterFlags`（`:249-252`）+ `PIMInnerIPv4`（`:255-259`）+ `PIMWireFault`（`:262-266` 3 键） |
| internal/protocol/pim/pim_test.go（已落码，834 行） | 单元测试 34 个（P4 复用，不改口径） |
| internal/protocol/pim/casegen_test.go（P4 NEW） | 一次性生成器：28 例（17 正+11 负）契约计数逐例 add()，落 `test/protocol_pcap/cases/pim.json`（层链整形后形状） |
| 接线件（已落码，P4 只验证） | registry `registry.go:896`（`DependsOn ["ip"]` 单载体 + `FieldContract ip.protocol=103`）；`chain_planner_util.go:229/243` 末层/倒二层协议号 103；`chain_planner.go:1370` raw-IP 分支 `meta.PIM` + `chain_planner.go:645/883` raw 名单；`strategy_convert.go:727-729` 子配置解析；`generator.go:492` FlowMeta.PIM；`protocols.go:46` 白名单 + `protocols_test.go` 同步；schemagen 重跑验证无过期 |
| P4 新增守卫 | ①`CheckProtoFlat` 补 `pim` 顶层同名子映射 presence 判死分支（`strategy_convert.go:8515` `rawWrapChains` 加 `"pim": "[ip,pim]"`——协议本地文件，车道内可改；当前缺失为 §14-P2 实证缺口）；②validate_layers 预检：白名单外游离键拒/链夹 tcp/udp 拒（`isRawIPChain :40-51` 含 tcp/udp 即否，转 transport 分支出错）/缺 ip 拒（`complete.go:484-491` DependsOn 缺失）——单载体，无 OptionalOn 面（终结层豁免 0c355be 下 pim 无 OptionalOn 声明不受影响） |
| tools/coverage_gate.py | check_pim（准入接线/关键件/守卫/用例面四段，P4 登记——当前 grep 计 0，出口 2 视红） |

**接口签名**（已落码，P4 落码钉死有无差量）：`checksum(b) uint16` / `buildPIM(typ, body, checksumMode) []byte` / `buildHello/buildJoinPrune/buildBootstrap/buildCandidateRPAdv/buildRegister/buildRegisterStop/buildAssert(ev, checksumMode) []byte` / `buildMessageByKind(ev, checksumMode) []byte` / `Planner.Validate(spec) error` / `PIMGenerator.Generate(ctx, req) error`。

**数据结构**：沿 `PIMConfig`（`routing.go:174` 4 键：profile/checksum_mode/events/wire_fault）+ 层链目标形状（§14.1 样例：地址/TTL 住 `ip`、业务住 `pim` 条目、数量走兄弟 `strategy_fc`）。

**主流程**：validateSpec（含 P4 新增 presence 守卫 + validate_layers 预检）→ 逐事件渲染（`buildMessageByKind` 七分支）→ `emit(directionFor)` → 下行 L3 源目交换（raw-IP 分支 `chain_planner.go:1405-1407`）→ worker（`worker.go:254` flowCount 恒 ≥1（`<=0`→1，`:255-257`）；`resolveLayerTuple :316` 后 `Plan`）→ pcap/NIC。

**错误分支（§5.2）**：①事件 `wire_fault` 4 值注入拒（`validateWireFault :140-159`，锚词进断言：`checksum :146`/`length :148`/`type :150`/`address :153`）；②自然守卫：非 IPv4 profile（`:29`）/非法 checksum_mode（`:35`）/df 混入（`:57`）/SSM 违规（`:62/64/70/75`）/非 IPv4 地址（`:85-99`）/组/源/前缀非法（`:101-121`）/未知 kind（`builder.go:534`）；③validate_layers 预检同步拒（presence/白名单/tcp-udp 载体/缺 ip）。全部传播为 task error，零假成功。

**依赖声明（§5.1）**：依赖 `ip` 层（唯一载体，寻址+TTL+Protocol=103）；无 `tcp`/`udp` 依赖（§14-P2 把此列成守卫）；无外部 BSR/RP/采集器依赖。**不含端口依赖**（pim 无端口语义；多流自动递增 `worker.go:300-309` 的 `HasExplicitSrcPort` 面对 pim 生成器无副作用——生成器不读端口字段，实测注记）。

**性能设计与验收（§6.1–6.8）**：O(n) 流式——逐事件渲染直发 Emit 无全量聚合（事件序 for 循环直发，无缓冲增长结构）；确定性内存（单事件最大=单 Join 多组 fixture 级字节）；无锁无 sleep（事件驱动）；pcap 路实测 + NIC 路注记（过滤器 `ip proto 103`，测试网口按 testing-interface 记忆）；回归口径=pim.json 全量 suite 耗时 ±10%；六类场景（基线/目标规模/压力上限/长运行时/并发交错/背压）P5 跑测覆盖；边界诚实声明：吞吐/并发/内存目标数字待 P4 基准后定（§6.5，不写承诺）。

**与现有逻辑冲突点（§8.7）**：①`strategy_convert.go:727-729` 仅解析顶层 `pim` 子映射，无 presence 判死分支——P4 补 `rawWrapChains` 项（§14-P2 实证缺口；协议本地文件，车道内可改）；②`parseSubconfigJSON`（`strategy_convert_helpers.go:14-30`）为**普通 `json.Unmarshal`（无 `DisallowUnknownFields`）**——pim 子映射未知键静默忽略，负例不得依赖未知键拒绝（P4 如需把未知键变红另立守卫，见 G-PIM-4）；schemagen 生成表已含 pim（`layers.generated.json:2457-2465`，`fields {}` 因业务键走 FlowMeta 直传），P4 只验证无过期（`TestLayersGeneratedMatchesRegistry`）。

**回滚方式（§8.8）**：P4 差量全量 revert（casegen + 24 例改写 + presence 守卫 + coverage 登记）；已落码 wire 面不动；无数据迁移面。

## 16. P3 测试对接清单与缺口立项（T-PIM 草稿输入；正文落 testcase 文件）

- §3.15 三项：①同会话多轮序列（Hello→Join→Prune/重传，状态变迁）→#7（显式重传 2 包）+#14（6 包多邻居多组）已覆；②非正常结束→7 负例全覆（#18–#24）；③长保活→pim 无自有保活语义=不适用（显式声明，Hello 周期属路由器调度面，不归本协议）+ Hello 周期刷新面明确不支持（§13.1 #6）。逐项一例或立项，无空项（明细见 testcase §9.1）。
- A′/B′ 两分类表：见 testcase §9.2（A′=引擎可构建→24 ID 内已覆 + A′ 补例建议 T-25（Register flags 全组合）/T-26（Bootstrap 多 RP-set 对称，§9.24 缺格）；B′=引擎结构缺口→G-PIM-2 进 D-条目“明确不解决+迁入计划”）。
- 9.52 对账两行：见 testcase §9.3（清单出处声明 + 对账两行：总数 58 = 已覆 46 + 不适用 11 + 链级红例通道 1）。
- 3.14 豁免边界审计：见 testcase §9.4（本协议无连接但**不主张多流豁免**：多会话并发 #14 已覆；单包多载荷=单 Join 多 group #6/双记录面已覆 + inner 载荷变体→B′）。
- 三源回指行：见 testcase §9.5（第三源“已确认现网行为”当前=未确认级，挂 G-PIM-1）。
- 断言通道：fields 用 `pim.*`（去重 28 已实证，注册命中 28/28，见 §13.3 备注行）+ frames hex（offset 34 单档 7 类前缀实测）。

## 17. 缺口立项清单（有缺口写“缺口立项”，不许空着）

| 立项号 | 缺口 | 确认方式（三选一） | 去向 |
|---|---|---|---|
| G-PIM-1 | 现网证据升级 + RFC 精确章节复核：路由器 Hello/DR 选举/BSR/RP 通告/Register 行为的“已确认现网”级证据；RFC 7761/4607 精确章节号 | 抓包（抓路由器回环/现网包核对 Type/目的/TTL 面）+ 查 RFC 原文 | P4 前置确认项，不挡开工；确认前相关条目按 §5.5“待确认”不写死 |
| G-PIM-2 | B′ 行为面：多会话并发交织序假设、inner 载荷变体（`payload_hex` 非 fixture 面）、`hello_interval` 调度语义、Register checksum 全包覆盖争议面（§10 裁定复核） | 查 RFC 7761 相关章节 + 抓包（问谁：无，文档+包即确认） | B′→D-PIM-1“明确不解决+迁入计划”（确认后进 §13.2 空白格） |
| G-PIM-3 | 动态多组地址池（§14.12 `dst`/`neighbor/group` 不开面）+ A′ 补例 T-25（Register flags 全组合：border/null 四态）/T-26（Bootstrap 多 RP-set 对称，§9.24 缺格） | 查引擎序号算法现状（P4 定） | A′ 补例并入与否由主线程定，不影响 §8 的 24 ID 权威口径 |
| G-PIM-4 | 严格解码守卫：`pim` 子映射未知键当前静默忽略（`parseSubconfigJSON` 普通 `json.Unmarshal`，`strategy_convert_helpers.go:14-30`），按 13.26 口径未知键应显式拒绝 | 读 `strategy_convert_helpers.go` 现状 + 引擎负例实测 | P4 评估是否框架级统一加 `DisallowUnknownFields`（属跨协议共享面，须上报主线程，不车道自改） |

## 18. P1/P2/P3 对抗自重审结论（10.11；过 3 轮，末轮干净）

- **P1（§13 矩阵）**：R1 自重审发现 §13.2 逐格重数初稿 20+2+12=34 有漏格（9×4=36，两格未归类：R2c3-SSM 与 R4c3 的负例通道归属混记）→ 改 22+2+12=36 复算一致；R2 逐行核八项矩阵的"代码现状"列行号全部实读源文件（builder/planner/layer_gen/routing/chain_planner/chain_planner_util/worker），无编造行号（registry.go:896 HEAD 已提交值；工作树 912 系 sstp 车道未提交插入漂移，以 HEAD 为准）；R3 末轮干净。
- **P2（§15 D-条目）**：R1 自审发现 §5 行初稿"白名单 protocols.go:41"为 igmp 同族行号误植 → 按实测改正 46；R2 补落 `CheckProtoFlat` 无 pim 同名子映射分支的 presence 缺口（`strategy_convert.go:8515-8526` 实证缺失，§14-P2 立为 P4 必补项）；R3 末轮干净。
- **P3（testcase §9 + §16/§17）**：R1 自审发现 9.52 对账两行初稿"总数 50"为 igmp 模板残留 → 改为 8+36+14=58 点、46+11+1=58 两行对账并加粒度声明；R2 核 §13.2 矩阵逐格重数（初稿 22+2+12=36 双重认领 R2c3/R3c4 类格 → 改 16+8+1+11=36，负例通道单列、链级红例仅 R1c3）+ §16 断言通道 28 字段逐个对 tshark 注册表（28/28 精确命中）+ 锚词 7 个逐字对 planner.go 真实字符串；R3 末轮干净。

三阶段合计修正 6 处（2 处算术：矩阵逐格重数 + 9.52 对账口径、1 处行号误植、1 处守卫缺口浮出落 §14-P2、1 处模板残留、1 处字段计数 25→28），末轮均干净。

### 18.1 文档逐条自核对结论（10.1：对规范逐条核对）

- RFC 7761（PIM-SM 七类消息 Type `0x00/01/02/03/04/05/08`、4B 公共头、Hello 四 options、Join/Prune 编码组/源、BSR/RP-set、C-RP、Register/Register-Stop、Assert）→ §3/§4 逐条有落点；RFC 4607（SSM `(S,G)` 限定、wildcard/RP/Register 禁止）→ §5。精确章节号挂 G-PIM-1（§5.5 不写死）。
- 与旧需求文档（v1.0.0 design/testcase）逐条核对（10.2）：见 §18.2。

### 18.2 与旧文档逐条核对结论（10.2）

v1.0.0 §1–§8 逐条：§1 范围（保留+扩，profile 表不动，"层尚未注册/仅设计阶段"段按实测改写为已注册已落码）；§2 配置表（保留，业务键语义不变；`source=0.0.0.0` 野 card 注记保留）；§3 线格式（保留，补 Type→frames 前缀实测对照 + Register checksum §10 裁定）；§4 事件状态（保留，补 `state` 不消费诚实声明）；§5 SSM（保留）；§6 状态边界（保留）；§7 负路径表（保留，锚词实测化为 §7 锚词行表）；§8 场景表（24 ID 逐条保留，packet_count 序列不变）。无旧条目被静默删除。

## 19. 修订记录

- v2.0.0（2026-09-26）：P1–P3 完整产物。新增 §13 P1 八项规范矩阵 + 三子表（报文×组播状态矩阵、数据形态变体表、P1 三路对照 §13.4、候选方案对比 §13.5）；§14 门1 §1–§14 十四行表（§1/§3/§12 强制展开 + 目标形状 spec_json 样例 + presence 负例形状）；§15 D-PIM-1 P2 代码设计草稿；§16 P3 对接清单；§17 缺口立项（G-PIM-1/2/3/4）；§18 自重审与核对结论。§1 重写为 profile＋已注册边界（注册行号 registry.go:896 实测，HEAD 已提交值；工作树 912 为 sstp 车道未提交漂移）；§2 增补 24 例存量形状声明（旧扁平形单类形状，P4 改写）；§7 增补锚词→代码行表。

## D1–D8 静态设计闭环

| ID | 设计检查项 | 当前结论 |
|---|---|---|
| D1 | 规范、范围与证据边界 | RFC 7761 PIM-SM、RFC 4607 SSM；IPv4 Protocol 103；现网证据仍挂 G-PIM-1，不伪称已确认 |
| D2 | 层链唯一真相 | 合法正例为 `[ip,pim]` raw-IP；地址/TTL 在 `layers[0].ip`，业务在 `layers[1].pim`，数量走兄弟 `strategy_fc` |
| D3 | 公共头、字段与字节面 | 4-byte PIMv2 header、七类 Type、checksum/offset 34 断言契约；Register 8-byte checksum 例外已明确 |
| D4 | 事件、状态与会话 | events 顺序逐包；重传、多邻居、多组显式声明；无握手、无隐式响应、无序号伪造 |
| D5 | 配置字段与动态边界 | profile/events/checksum_mode 住 pim 层；地址住 ip 层；动态地址池、调度语义登记 G-PIM-2/3，不写成已支持 |
| D6 | 错误传播与不适用项 | 协议语义负例锚词与 planner 实测一致；链级负例 #25–#28 登记 presence/白名单/载体/依赖拒绝；失败必须 task error |
| D7 | 性能、输出与验收 | O(n) 事件流式；PCAP/NIC 双路为后续执行计划；吞吐、并发、内存数字待真实基准，未运行不宣称通过 |
| D8 | 接口、缺口与回滚边界 | 已落码 wire 接口不改；链级守卫/严格解码/动态面缺口分别登记 G-PIM-2/3/4；实现阶段按三文件契约回归 |

**静态边界**：本轮仅修订本设计、测试契约与 `pim.json`；不改 Go/schema/其他文档/LAYERCHAIN_INDEX，不运行 suite/MCP/NIC，不创建提交。

### D1–D8 自审

第一轮逐项核对 D1–D8、28 个 JSON ID、17/11 正负比例、严格 `[ip,pim]` 正例、4 个新增负例去向、负例双键和锚词；第二轮逐项复算 JSON 结构与文档交叉引用，并确认空壳接线缺口仍登记、未把静态结果写成运行通过。两轮均末轮干净。
