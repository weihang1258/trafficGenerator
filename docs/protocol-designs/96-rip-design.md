# #96 rip（Routing Information Protocol，RFC 1058/2453/2080/4822）设计契约

> 版本：v1.0.1（文档先行批次一，车道 A；v1.0.1 = 补登记 G-RIP-11 结果产物过期）
> 日期：2026-09-28
> 车道：doc-lanes/rip（worktree /tmp/wt3-rip，分支 pipe/rip，基线 cf6e2f0）
> 旧基线：`docs/protocol-designs/10-rip-design.md` v1.0.0（1340 行，9 章；本 #96 为其 P-PIPE 重做契约——语义继承、扁平形状不继承）
> 存量用例：`trafficgen/test/protocol_pcap/cases/rip.json`（71 例 = 52 层链 + 19 扁平；**71/71 顶层旧键残留**，见 §12.1）
> 规范基线：① RFC 1058（RIP v1）、RFC 2453（RIP v2）、RFC 2080（RIPng）、RFC 4822（RIP v2 MD5 认证）——下称 **spec**；② 旧基线设计文档（内部契约，非外部规范）；③ 本仓库落码（`internal/protocol/rip/` 六文件 2914 行 + 接线，§11.1）；④ 本机 tshark 3.6.14 实测（`rip.*` 18 字段 + `ripng.*` 8 字段，§3.6）
> 白话一句：**RIP 是路由器之间互相喊"我知道哪些网段怎么走"的小喇叭——喊的内容就是"网段 + 跳数"的一串小卡片，本协议层只负责把这串卡片按版本要求排好、装进 UDP 发出去。**

## 0. 10→96 沿革与旧稿过期声明校正（门1 必答：基线继承关系）

本 #96 与旧稿 `10-rip-design.md` 是**同一协议的重做契约**，不是新协议。旧稿保留只读参考，本契约逐条校正旧稿已过时的状态声明：

| # | 旧稿说法（10-*） | HEAD 实测（2026-09-28） | 校正结论 |
|---|---|---|---|
| 1 | 只有一份 `10-rip-design.md`（1340 行），**无用例文档** | `docs/protocol-designs/` 无 `10-rip-testcase.md`（实测 `ls`）；本 #96 新建 testcase | 用例文档缺失 → #96 补齐（B6 契约要求两份独立文档） |
| 2 | §9 集成点列 `types.go`/`strategy_convert.go`/`protocol.go` 三处，无层链概念 | 层已注册 `registry.go:184`（`CategoryTerminal` / `DependsOn ["udp"]` / **无 `Fields`**）；生成表 `rip.fields = {}`（机读实测） | 层注册已落码；**层内配置无处可住**（缺口 G-RIP-1） |
| 3 | §3 Config 结构体 = 顶层 `rip` 子映射（flat） | `strategy_convert.go:1584` 有 `case "rip"`（`parseRIPConfig` 搬运顶层子映射）；`chain_planner_translate.go` 的 switch（73 case）**无 `case "rip"`** | flat 接线在；**层内翻译不在**（G-RIP-2） |
| 4 | §5 Plan 输出（legacy planner 直驱） | `internal/protocol/rip/layer_gen.go` 323 行（`RIPGenerator`）已落码，事件面复刻 legacy `Plan`；`chain_planner_translate.go:64` `RIP: spec.RIP` Meta 直传已接线 | 层生成器已落码；legacy `Planner.Plan` 与 `layer_gen.Generate` 双路并存（§11.4） |
| 5 | 旧稿样例全部顶层扁平键（`src_ip/dst_ip/src_port/dst_port` + 顶层 `rip`） | 存量 **71/71** 例含顶层旧键（52 层链例带 `src_port`/`count`/顶层 `rip`；19 扁平例带 `count`/`rip`/部分 `src_ip/dst_ip`；逐键计数见 §12.1） | 旧样例形 = **过渡态违规形**（§1.4/§1.11），属代码阶段收敛（G-RIP-1/G-RIP-2/G-RIP-4）；本契约 §2 样例只给纯层链形 |
| 6 | §5.5「DSCP 默认 CS6」 | `rip.go:502` 算出的 `dscp` 是**死参数**（从未传给 `L3Base`，`emitRIPPacket` 用 `spec` 直配）→ `layer_gen.go:156` 明写「不加默认」；线上 DSCP 恒 = `spec.DSCP`（0 时落 ip 层 schema 默认 0） | **旧稿说法作废**：CS6 默认从不达线；用例不得断言 CS6（§3.3 钉正） |
| 7 | §6.13「多路由器 src_port 由 worker 端 4-tuple 分配器动态分配（默认 52001 起）」 | `rip.go:586-592` `resolveSrcPort` 明写：显式值 > Response 单 router = well-known 520/521 > **52001+routerIdx**（多 router） | 数值一致（52001 起），但归属是 **planner 内 resolveSrcPort** 不是 worker 分配器 → 旧稿归属描述作废 |
| 8 | §2.5「trafficgen 在摘要位置填 0xAA」 | `builder.go` 摘要占位字节机读实测（§3.5 表）；旧稿未给行号 | 待 §3.5 逐字节钉正 |

**依赖链判定纪律**：以上均为可判题（旧文→代码→用例三级对照），直接判定，不问偏好。不可判的（RIP 摘要占位是否需真 HMAC 计算——现网设备行为）标"待确认"并写清确认方式（G-RIP-8）。

## 1. 范围、profile 与实现状态边界

本版定义路由器（RIP speaker）向邻居通告路由表的 **UDP 报文**：RIP v1/v2 经 UDP 520（IPv4）、RIPng 经 UDP 521（IPv6）。RIP 层是 **udp 终结层**（`DependsOn ["udp"]`），只负责生成 RIP 报文体（4B 头 + N×20B 条目 + 可选认证），端口/地址/TTL 由 udp 层与事件级覆盖承担。

| profile | 承载 | 本版允许内容 | 不从 profile 推导 |
|---|---|---|---|
| `rip_v1` | UDP 520 / IPv4（广播 255.255.255.255） | v1 头 + v1 RTE（无掩码）；无认证 | v1 的「MustBeZero」字段是否被对端校验 |
| `rip_v2`（默认） | UDP 520 / IPv4（组播 224.0.0.9 或单播） | v2 头 + v2 RTE（含掩码/下一跳/路由标签）；simple/MD5 认证 | 真实路由收敛过程、定时器驱动的周期性更新 |
| `ripng` | UDP 521 / IPv6（组播 FF02::9） | RIPng 头 + RIPng RTE（16B 前缀 + 前缀长）；无认证 | RIPng 的 IPsec 认证（RFC 2080 §4 交 IPsec，本层不生成） |

显式边界（"不实现、不声称、不许静默转换"）：真实路由表收敛/撤销/垃圾回收定时器不在本版（生成器只按配置发**单次或 N 轮**报文，不模拟 RFC 2453 §2.3 的 30s/180s 定时器）；RFC 2080 的 IPsec 认证不在本版（spec §4 明示 RIPng 用 IPsec，非应用层认证）；RFC 1058 的「9/10 私有命令」不在本版（spec 已废弃）。

**实现状态（2026-09-28 实测）**：`rip` 层已注册（`registry.go:184`）、生成器已落码（`internal/protocol/rip/layer_gen.go` 323 行 `RIPGenerator` + `builder.go` 226 行 + `parser.go` 188 行 + `rip.go` 681 行 + `rip_test.go` 1479 行 + `types.go` 17 行 = 2914 行）、`chain_planner_translate.go:64` Meta 直传已接线、`chain_planner.go:1132` 目的端口保持 0（生成器按版本运行时解析）、`chain_planner_util.go:161` `isRIPChain` 豁免 ip 层 dst 默认删除。**缺口**：层为空壳（G-RIP-1）+ 层内配置不翻译（G-RIP-2）。

**输出契约（pcap/NIC 双输出）**：两路径共用同一 cases JSON 与断言集（`rip.command`/`rip.version`/`rip.family`/`rip.metric`/`udp.dstport`/`ip.dst` + frames `offset/hex`）；NIC 经 tcpdump 捕获（`nic_capture` 用例级开关）；不设仅单路径可用的断言。

## 2. 协议栈、端口和固定偏移

推荐层链为 `[ip, udp, rip]`（引擎自动补 `ip`；最小链 `[udp, rip]`）。RIP 报文是 UDP payload 的**完整内容**（无分片、无流式重组概念——每个 UDP 数据报 = 一个完整 RIP 报文）。

端口：RIP v1/v2 **UDP 520**（spec RFC 2453 §3.6）；RIPng **UDP 521**（spec RFC 2080 §2）。目的端口由生成器按版本运行时解析（`rip.go:348-354` `getDstPort`）；源端口由 `resolveSrcPort`（`rip.go:586-592`）按优先级解析（显式值 > Response 单 router = 520/521 > 52001+idx）。`chain_planner.go:1132` 的 DstPort switch 对 rip **刻意保持 0**（不静态默认化，否则 80 会原样落线）。

固定偏移：无 VLAN/IP options/UDP 校验和字段等变长项时，**RIP 头首字节起点为 IPv4 offset 42（14+20+8）、IPv6 offset 62（14+40+8）**。每个 UDP 数据报内：RIP 头 4B，其后 N×20B 条目（N ≤ 25，首包带认证时 ≤ 24）。

目标形状 spec_json 样例（严格层链形，顶层仅 `layers`；**目标形状声明**：registry `rip` 的 `Fields` 今日为空，层内 `version`/`command`/`routes` 等键今日无处可住，故此形**今天跑不通，需先补代码** G-RIP-1/G-RIP-2，§1.9 口径）：

```json
{
  "layers": [
    {"ip": {"src": "192.168.1.1", "dst": "224.0.0.9", "ttl": 1}},
    {"udp": {"src_port": 520, "dst_port": 520}},
    {"rip": {"version": "v2", "command": "response", "multicast": true, "routes": [{"afi": 2, "ip_addr": "10.0.0.0", "subnet_mask": "255.0.0.0", "metric": 1}]}}
  ]
}
```

多流样例（数量只走 `flow_control`，四元组留空走 worker 保底递增 §12.11）：

```json
{
  "layers": [
    {"ip": {"src": "192.168.1.1", "dst": "224.0.0.9", "ttl": 1}},
    {"udp": {"dst_port": 520}},
    {"rip": {"version": "v2", "multicast": true}}
  ],
  "flow_control": {"flows": 3}
}
```

## 3. 线格式编码（逐项标注出处）

### 3.1 RIP 公共头（4 字节，v1/v2/RIPng 共用；spec RFC 2453 §3 / RFC 2080 §2.1）

| 偏移 | 长度 | 字段 | 取值 | 出处 |
|---:|---:|---|---|---|
| 0 | 1 | Command | 1=Request，2=Response | RFC 2453 §3.1 / RFC 2080 §2.1（RIPng 同值） |
| 1 | 1 | Version | v1=1，v2=2，RIPng=1 | RFC 2453 §3.1；RFC 2080 §2.1（**RIPng 复用 version=1**，须结合端口 521 + IPv6 才能与 v1 区分） |
| 2 | 2 | Routing Domain / MustBeZero | v1：MustBeZero=0；v2：Routing Domain（任意 16-bit）；RIPng：MustBeZero=0 | RFC 1058 §3.1 / RFC 2453 §3.1 / RFC 2080 §2.1 |

**版本字节歧义**：`Version=1` 同时表示 RIP v1 与 RIPng。判别三要素 = Version 字节 + UDP 端口（520 vs 521）+ 地址族（IPv4 vs IPv6）。tshark 按端口 + 地址族分派到 `rip.*` 或 `ripng.*` 两套字段（§3.6）。

### 3.2 RIP v2 Route Entry（20 字节；spec RFC 2453 §3.2）

| 偏移 | 长度 | 字段 | 说明 |
|---:|---:|---|---|
| 0 | 2 | Address Family Identifier (AFI) | IPv4=2；认证条目=0xFFFF；Request 全量时=0 |
| 2 | 2 | Route Tag | 区分内部/外部路由（EGP 引入） |
| 4 | 4 | IP Address | 网络地址 |
| 8 | 4 | Subnet Mask | 掩码；0.0.0.0=缺省路由 |
| 12 | 4 | Next Hop | 下一跳；0.0.0.0=发送者即下一跳 |
| 16 | 4 | Metric | 1–16（16=不可达；**0 非法**） |

### 3.3 RIP v1 Route Entry（20 字节；spec RFC 1058 §3.1）

| 偏移 | 长度 | 字段 | 说明 |
|---:|---:|---|---|
| 0 | 2 | AFI | IPv4=2；Request 全量时=0 |
| 2 | 2 | MustBeZero | 0 |
| 4 | 4 | IP Address | 网络地址 |
| 8 | 4 | MustBeZero | 0（v1 不携带掩码） |
| 12 | 4 | MustBeZero | 0（v1 不携带下一跳） |
| 16 | 4 | Metric | 1–16 |

### 3.4 RIP v2 认证条目（占第一个条目槽位；spec RFC 2453 §3.3 / RFC 4822 §2.1）

**simple（明文）**：

| 偏移 | 长度 | 字段 | 说明 |
|---:|---:|---|---|
| 0 | 2 | AFI | 0xFFFF（认证标记） |
| 2 | 2 | Authentication Type | 0x0002=明文 |
| 4 | 16 | Authentication Data | 16 字节密码（不足补 0；超 16 拒绝） |

**MD5（RFC 4822）**：

| 偏移 | 长度 | 字段 | 说明 |
|---:|---:|---|---|
| 0 | 2 | AFI | 0xFFFF |
| 2 | 2 | Auth Type | 0x0003 |
| 4 | 2 | RIPv2 Packet Length | **regular RIPv2 packet 总长** = 4 + 20 × entry_count（entry_count 含认证条目本身） |
| 6 | 1 | Key ID | 密钥标识 |
| 7 | 1 | Auth Data Len | 摘要长度；RFC 4822 默认 16，允许其它算法值透传；Validate 仅校验 > 0 |
| 8 | 4 | Sequence Number | 单调递增（防重放） |
| 12 | 8 | MustBeZero | 0 |

**MD5 trailer（报文尾；spec RFC 4822 §2.1）**：

| 偏移 | 长度 | 字段 | 说明 |
|---:|---:|---|---|
| +0 | 2 | Auth Marker | 0xFFFF |
| +2 | 2 | Type | 0x0001（**与认证条目的 Auth Type=0x0003 属不同结构，不可混淆**） |
| +4 | AuthDataLen | Auth Data | 摘要（trafficgen 填占位字节，不计算真实 HMAC） |

**条目数上限**：无认证 25/包；首包带认证 24/包（认证条目占 1 槽位）；后续包 25/包且**无 trailer**（spec RFC 4822 §2.1：trailer 仅首包）。

### 3.5 RIPng Route Entry（20 字节；spec RFC 2080 §2.1.1）

| 偏移 | 长度 | 字段 | 说明 |
|---:|---:|---|---|
| 0 | 16 | IPv6 Prefix | 16 字节前缀 |
| 16 | 2 | Route Tag | 2 字节（RFC 2080 §2.1.1 明确是 2 字节，非 1 字节） |
| 18 | 1 | Prefix Length | 0–128 |
| 19 | 1 | Metric | 1–16 |

RIPng **无下一跳字段**（RFC 2080 §2.1.1 规定下一跳由 IPv6 头推导）→ `next_hop` 在 ng 下拒绝（`rip.go:286-287`）。

### 3.6 报文长度公式（可复算）

- **无认证**：`Payload = 4 + 20 × N`，N ≤ 25 → 单包最大 504B。
- **simple 认证**：首包 `Payload = 4 + 20 × (1 + N)`，N ≤ 24 → 最大 504B。
- **MD5 认证**：首包 `Payload = 4 + 20 × (1 + N) + 4 + AuthDataLen`；AuthDataLen=16 且 N=24 → 4 + 500 + 4 + 16 = **524B**；AuthDataLen=20 → 528B。
- **UDP/IP/以太网开销**：+8（UDP）/ +20（IPv4）/ +14（以太网）→ 504B 应用层 = 546B 以太网帧（< 1500 MTU，不触发 IP 分片）。

### 3.7 tshark 断言通道（2026-09-28 实测，tshark 3.6.14）

`rip.*` = **18 字段**（机读）：`rip.command`/`rip.version`/`rip.routing_domain`/`rip.ip`/`rip.netmask`/`rip.next_hop`/`rip.metric`/`rip.family`/`rip.route_tag`/`rip.zero_padding`/`rip.auth.type`/`rip.auth.passwd`/`rip.digest_offset`/`rip.key_id`/`rip.auth_data_len`/`rip.seq_num`/`rip.authentication_data`/`rip.unknown_address_family`。
`ripng.*` = **8 字段**（机读）：`ripng.cmd`/`ripng.version`/`ripng.reserved`/`ripng.rte.ipv6_prefix`/`ripng.rte.route_tag`/`ripng.rte.prefix_length`/`ripng.rte.metric`/`ripng.rte`。

**断言字段一律以本表为准**，不得臆造字段名（历史教训：igmp/ospf/pim 首轮全绿根因即臆造字段）。多播/广播目标断言走 `ip.dst`；MAC 推导断言走 `eth.dst`（`multicastDstMAC`：224.0.0.9→`01:00:5e:00:00:09`、255.255.255.255→`ff:ff:ff:ff:ff:ff`、FF02::9→`33:33:00:00:00:09`）。

### 3.8 tcp/udp 层联动语义

| 层字段 | 本协议语义 |
|---|---|
| `udp.dst_port` 缺席 | 生成器按版本解析（v1/v2→520、ng→521，`getDstPort`）；`chain_planner.go:1132` 刻意保持 spec.DstPort=0 不静态默认化 |
| `udp.src_port` 缺席 | `resolveSrcPort`：Response 单 router→520/521；多 router→52001+idx；request_full 请求侧→52001 |
| `ip.ttl` | multicast/broadcast 强制 1（`rip.go:494-499`）；unicast 用 spec.TTL 或默认 64 |
| `ip.dst` 缺席 | 生成器按版本推导（v1→255.255.255.255、v2→224.0.0.9、ng→FF02::9，`getDstIP`）；`isRIPChain` 豁免 ip 层 dst 默认删除，事件级绝对覆盖 |

## 4. 业务场景分析（现网典型场景与五层覆盖）

**定性**：**声明式剧本回放**——配置声明版本/命令/场景/路由表/路由器数，引擎按序产出 UDP 数据报；udp 层逐事件发一个数据报。

| 现网场景 | 事务交互 | 对应用例 |
|---|---|---|
| ① 周期全表通告 | Response 携带全部路由（≤25/包，超出拆包） | `rip_tpos20_50_entries`、`rip_tpos21_51_entries` |
| ② 请求—应答（启动收敛） | Request（全量请求）→ 对端 Response | `rip_tpos1_request_full`、`rip_tpos1b_user_routes` |
| ③ 组播通告 | 单播改组播 224.0.0.9（TTL=1 限本链路） | `rip_tpos6_multicast_ttl`、`rip_tpos32_v1_multicast_broadcast` |
| ④ 认证网络 | simple 明文 / MD5（RFC 4822） | `rip_tpos8_simple_auth`、`rip_tpos9_md5_auth` |
| ⑤ 多路由器并发 | 每 router 独立四元组 + 独立 FlowID | `rip_tpos16_3_routers`、`rip_tpos17_100_routers`、`rip_tpos28_8_routers` |
| ⑥ 触发更新 | 拓扑变化立即通告（跳过 Request 前导） | `rip_tpos13_triggered` |
| ⑦ 水平分割 / 毒化反转 | 抑制/毒化「从哪学来还从哪发」的路由 | `rip_tpos10_split_horizon`、`rip_tpos12_poison_reverse` |
| ⑧ RIPng IPv6 网络 | 前缀通告（PrefixLen 0–128） | `rip_tpos14_ripng`、`rip_tpos23_ripng_128` |

**五层覆盖逐层结论**：功能层——命令 2 值 × 版本 3 值 × 场景 3 值 × 认证 2 型 × 水平分割/毒化/触发各正例，错误处理 19 条负例；性能层——25/50/51 条路由拆包（25+25+1）、100 路由器压力、504B 最大单包；数据场景层——metric 0/1/16/17/255、掩码 0/全 1/非连续、前缀长 0/128/129、domain 0/0xFFFF、AFI 0/2/3/0xFFFF、密码 16B/17B、AuthDataLen 0/20；地址与流层——v4（v1/v2）与 v6（ng）独立用例、单流基线、多流（3/8/100 router）、端口显式与缺省；**流关联（控制流派生数据流）显式不适用**：RIP 无副连接，多路由器是并列四元组不是主从派生（§12.3 关联关系栏）；**多流（会话内并发流）显式不适用**：每个 RIP 报文独立自足，无会话内并发流概念。业务层——请求应答链、周期通告、触发更新、认证网络、多路由器并发。

**次要合法行为显式不适用声明（不设正例、亦不得进负例）**：① RFC 2453 §2.3 的 30s/180s/120s 定时器（生成器只发配置轮数，不模拟定时器，`rounds` 是显式轮数不是定时器）；② RIPng 的 IPsec 认证（spec §4 交 IPsec，非本层）；③ RFC 1058 的 9/10 私有命令（spec 已废弃）；④ 真实路由收敛/撤销（无状态回放，不模拟）。

## 5. 消息/事务模型与状态机

**事务定义**：一个 RIP 报文（Request 或 Response）的发送。**多事务** = 一个配置内多轮/多 router 多报文：`rip_tpos7_rounds`（rounds=3 三报文）、`rip_tpos16_3_routers`（3 router 各 1 报文）。

RIP 层**无自有状态**：RIP 是 UDP 上的无连接协议，无握手/无挥手/无序号协商（`DependsOn ["udp"]`，无 tcp 载体）。层是「按配置把路由表翻译成报文事件」的纯函数驱动。

| 状态 | rip 层动作 | 用例 |
|---|---|---|
| 无连接（UDP 单发） | 每个 RIP 报文 → 一个 `MessageEvent`（`Bytes` = 完整 RIP 报文） | 全正例 |
| 报文内拆包 | 路由 > 25（或首包 > 24 带认证）→ 拆多报文，共享 FlowID、PacketIndex 递增 | `rip_tpos20_50_entries` 等 |

**多会话展开**：RIP 无会话概念（无连接协议），`sessions[]` **显式不适用**（§3.14 豁免，理由：UDP 单发无连接生命周期）。多流语义由多 router（配置内 `routers[]`，各自独立四元组）或策略级 `flow_control {"flows": N}` 表达。

**自动派生规则**：① `version` 缺席 → 默认 v2（`versionFromString("")` → "v2"，`rip.go:81-93`）；② `command` 缺席 → 默认 Response（`rip.go:412-415`）；③ `scenario` 缺席且 `routes` 为空 → 按 command 推导（Request→`request_full`、Response→`response_default`，`rip.go:423-431`）；④ `routes` 为 nil → 用场景默认（`response_default` 用 5 条示例路由 `defaultRoutes`；显式空 slice → 零路由裸头）；⑤ `routers` 为空 → 单 router 用 FlowSpec 自身四元组；⑥ `rounds` ≤ 0 → 1；⑦ multicast → DstIP 按版本推导 + TTL 强制 1；⑧ 端口缺席 → 按版本/角色解析（§3.8）。

## 6. 性能设计与验收（CORE_MEMORY §6.1–6.8）

- **目标与边界**：单流单报文 ≤ 504B 应用层（546B 以太网帧）；单配置最大报文数 = routers × rounds × ceil(entries/25)（100 router 压力例 = 100 报文）；**吞吐数字待 P5 基准，本版不写承诺**（§6.5）。
- **依据**：路由表流式展开（`layer_gen.go` 逐报文 emit 到 udp 层事件流，无全量收集）；每报文内存 = 20 × N + 头开销（O(N)）；多 router 顺序展开、每 router 局部状态（`ipID`/`packetIndex`）；无跨流共享状态；无锁（常量表只读）。
- **验收两路**：pcap（`/tmp/mcp-pcaps/rip/`）与 NIC（`enp135s0f0np0`，`nic_capture` 开关）共用同一断言集；断言实际 `rip.*` 字段值与报文 hex，不只断言"任务没报错"。
- **六类场景落点**：基线（`rip_tpos6_multicast_ttl`，1 报文）/ 目标规模（`rip_tpos20_50_entries`，2 报文）/ 压力上限（`rip_tedge7_25_entries` 504B 单包 + `rip_tpos17_100_routers` 100 报文）/ 长时间运行（`rip_tpos7_rounds` 多轮）/ 并发交错（多 router 顺序展开承载，无并发路径）/ 背压（`packet_count` 精确计数守卫拆包数漂移）。

## 7. 错误处理（负例锚词表，与 testcase §4 一一对应、同序）

以下输入必须由 planner/validator 拒绝并传播为 task error，不得产出成功 PCAP、`completed/0 packet` 或只剩 UDP 外壳的假成功：

| # | 负例 ID | 故障输入 | `error_contains` 锚词 | 代码出处 |
|---:|---|---|---|---|
| N-1 | `rip_terr1_version_v3` | `version="v3"` | `invalid version` | `rip.go:118` |
| N-2 | `rip_terr3_command_update` | `command="update"` | `invalid command` | `rip.go:102` |
| N-3 | `rip_tedge1_metric0_err` | `metric=0` | `metric must be >= 1` | `rip.go:230` |
| N-4 | `rip_tedge4_metric17_err` | `metric=17` | `metric must be <= 16` | `rip.go:233` |
| N-5 | `rip_tedge5_metric255_err` | `metric=255` | `metric must be <= 16` | `rip.go:233` |
| N-6 | `rip_terr5_afi3` | `afi=3` | `invalid AFI` | `rip.go:260` |
| N-7 | `rip_terr6_afi_ffff` | 路由 `afi=0xFFFF` | `AFI=0xFFFF is reserved for authentication` | `rip.go:257` |
| N-8 | `rip_terr19_afi_ffff_explicit` | 同上（显式形） | `AFI=0xFFFF is reserved for authentication` | `rip.go:257` |
| N-9 | `rip_terr7_auth_sha256` | `auth.type="sha256"` | `invalid auth type` | `rip.go:160` |
| N-10 | `rip_terr8_auth_v1` | `version="v1"` + auth | `RIP v1 does not support authentication` | `rip.go:153` |
| N-11 | `rip_terr9_auth_ng` | `version="ng"` + auth | `RIPng does not support authentication` | `rip.go:156` |
| N-12 | `rip_terr10_password_17b` | simple 密码 17B | `simple auth password must be <= 16 bytes` | `rip.go:165` |
| N-13 | `rip_terr17_authdatalen0` | MD5 `auth_data_len=0` | `md5 auth_data_len must be > 0` | `rip.go:171` |
| N-14 | `rip_tedge12_ip_bcast_err` | 路由 IP `255.255.255.255` | `broadcast address cannot be used as route` | `rip.go:299` |
| N-15 | `rip_terr11_ip_invalid` | 路由 IP `999.1.1.1` | `invalid IP address` | `rip.go:242` |
| N-16 | `rip_terr12_mask_invalid` | 掩码 `not-a-mask` | `invalid subnet mask` | `rip.go:268` |
| N-17 | `rip_terr13_nh_v6` | v2 路由 `next_hop` 为 IPv6 | `next_hop must be IPv4` | `rip.go:293` |
| N-18 | `rip_terr16_router_empty` | `routers=[{}]` | `at least one field must be non-empty` | `rip.go:186` |
| N-19 | `rip_tedge18_ripng_len129_err` | RIPng `prefix_len=129` | `prefix_len must be <= 128` | `rip.go:275` |

**负例原子性**：每例单一故障注入；单次执行不得混注。

**不得误报的合法协议事件**：metric=16（不可达，合法上限，`rip_tedge3_metric16` 正例）；metric=1（合法下限，`rip_tedge2_metric1`）；掩码 0.0.0.0（缺省路由）与 255.255.255.255（主机路由）；非连续掩码 `255.0.0.3`（透传不报错，`rip_tedge15_mask_noncontig`）；domain=0xFFFF（v2 透传）；RIPng `prefix_len`=0 与 128；密码恰 16B；`auth_data_len`=20。

## 8. 边界

- **metric**：1（最小合法）/16（不可达，合法上限）/0、17、255（拒绝）。16 是**合法值**（表示不可达），不是错误——毒化反转就用 metric=16（`rip_tpos10_route_poison`）。
- **掩码**：0.0.0.0（缺省路由）/255.255.255.255（主机路由）合法；非连续 `255.0.0.3` 透传不报错（spec 未禁止，本版不校验连续性）。
- **AFI**：0（Request 全量）/2（IPv4）合法；0xFFFF 保留给认证（显式写拒绝）；其它值拒绝。
- **条目数**：25/包（无认证）、24/包（首包带认证）；26/50/51 条拆包行为已覆。
- **domain**：v2 任意 16-bit 透传（含 0xFFFF）；v1/RIPng 恒 0。
- **认证**：simple 密码 ≤ 16B；MD5 `auth_data_len` > 0（不强制 =16，允许算法扩展透传）；认证仅 v2（v1/ng 拒绝）。
- **地址族**：v1/v2 用 IPv4 字面量；RIPng 用 IPv6（混写拒绝，validator 有分支）。
- 不得产生回绕长度或超量分配（路由表显式声明，不隐式放大）。

## 9. 原子 ID 与完成定义（71 个唯一语义 ID，顺序为权威）

存量 71 例（52 正 + 19 负）语义全部保留（testcase §2 全表，顺序 = JSON 顺序为权威）。分组摘要（ID 前缀机读计数）：

| 组 | 例数 | 正/负 | 覆盖面 |
|---|---:|---|---|
| T-POS（场景/参数） | 32 | 32 / 0 | 场景 3 值、版本 3 值、认证 2 型、domain、多播/单播、rounds、triggered、split/poison、request_full 族 |
| T-EDGE（边界） | 22 | 17 / 5 | metric/掩码/前缀长/条目数/domain/AFI/路由器数边界 + 广播地址/超界值拒绝 |
| T-ERR（异常） | 17 | 3 / 14 | 版本/命令/AFI/认证/IP/掩码/下一跳/router 错误分支 + split+poison 组合告警 |
| 合计 | **71** | 52 / 19 | — |

完成定义：`udp→rip` 层链注册已落码；报文逐字段生成验证；三版本（v1/v2/ng）× 认证 × 拆包 × 多 router 可观测；71 ID 正负断言与错误传播完成；不声称真实路由收敛与定时器。

## 10. P1 规范矩阵（CORE_MEMORY §4 八项：规范要求→业务场景→代码现状→缺口）

### 10.1 八项规范矩阵

| # | 八项 | 规范要求 | 业务场景 | 代码现状 | 缺口 |
|---|---|---|---|---|---|
| 1 | 连接模型 | UDP 无连接；v1/v2 端口 520、ng 端口 521（RFC 2453 §3.6 / RFC 2080 §2） | 场景①–⑧ | `DependsOn ["udp"]`（`registry.go:184`）；`getDstPort`（`rip.go:348`） | 无 |
| 2 | 命令/消息表 | Command 1/2 两值（RFC 2453 §3.1）；RIPng 同（RFC 2080 §2.1） | 全正例 | `commandFromString`（`rip.go:95`）+ Validate 拒绝非 1/2 | 无（9/10 私有命令显式不适用） |
| 3 | 状态机 | 无连接，无状态机（UDP 单发） | — | rip 层纯函数驱动 | **显式不适用**（§5），无缺口 |
| 4 | 字段表 | 头 3 字段 + v2 RTE 6 字段 + v1 RTE 3 字段 + RIPng RTE 4 字段 + 认证条目（§3.1–3.5） | 数据场景层 | `builder.go` 逐字段构造 + `validateRoute` 全分支 | 无（层内字段面见 G-RIP-1/G-RIP-2） |
| 5 | 错误处理 | 19 类负例（§7 表） | 负例 N-1…N-19 | `rip.go` Validate + validateRoute 全分支 | 无（锚词 19/19 钉死） |
| 6 | 超时与活性 | RIP 有 30s/180s/120s 定时器（RFC 2453 §2.3） | — | 协议层无（生成器按显式 `rounds` 发，不模拟定时器） | **显式不适用**（§4 声明），无缺口 |
| 7 | NAT/代理/被动 | 无被动模式概念（UDP 单发） | — | 无 | **显式不适用**；NAT 穿透为框架面 |
| 8 | 版本/方言 | v1（RFC 1058）/v2（RFC 2453）/ng（RFC 2080）三方言 + v2 MD5（RFC 4822） | 正例 52 | `versionFromString` + `getVersionByte` + 认证分支 | 无 |

### 10.2 子表①：命令 × 版本矩阵（逐格已覆/立项/不适用；适配声明：RIP 无响应码概念，「命令 × 版本 × 认证」为等价口径）

| 命令 × 版本 | v1 | v2 | ng |
|---|---|---|---|
| Request | 已覆（`rip_tpos4_v1_broadcast`） | 已覆（`rip_tpos1_request_full`） | A′ 立项（补例 `rip_ripng_request`） |
| Response | 已覆（`rip_tpos32_v1_multicast_broadcast`） | 已覆（`rip_tpos5_unicast`） | 已覆（`rip_tpos14_ripng`） |
| Response + simple 认证 | **不适用**（v1 无认证，拒绝 N-10） | 已覆（`rip_tpos8_simple_auth`） | **不适用**（ng 无认证，拒绝 N-11） |
| Response + MD5 认证 | **不适用**（同上） | 已覆（`rip_tpos9_md5_auth`） | **不适用**（同上） |

**逐格重数**：3 命令/认证行 × 3 版本 = 12 格——已覆 7 / 立项 1 / 不适用 4，零空格。

### 10.3 子表②：数据形态变体表（协议相关全部形态逐项）

| # | 变体 | 落点 |
|---:|---|---|
| 1 | metric=0（非法下界） | 覆（`rip_tedge1_metric0_err`） |
| 2 | metric=1（合法下界） | 覆（`rip_tedge2_metric1`） |
| 3 | metric=16（不可达，合法上界） | 覆（`rip_tedge3_metric16`） |
| 4 | metric=17（上界+1） | 覆（`rip_tedge4_metric17_err`） |
| 5 | metric=255（uint8 满值） | 覆（`rip_tedge5_metric255_err`） |
| 6 | 掩码 0.0.0.0 | 覆（`rip_tedge13_mask_zero`） |
| 7 | 掩码 255.255.255.255 | 覆（`rip_tedge14_mask_ffff`） |
| 8 | 掩码非连续 255.0.0.3 | 覆（`rip_tedge15_mask_noncontig`，透传不报错） |
| 9 | 掩码非法字面 | 覆（`rip_terr12_mask_invalid`） |
| 10 | RIPng PrefixLen=0 | 覆（`rip_tedge16_ripng_len0`） |
| 11 | RIPng PrefixLen=128 | 覆（`rip_tedge17_ripng_len128`） |
| 12 | RIPng PrefixLen=129（上界+1） | 覆（`rip_tedge18_ripng_len129_err`） |
| 13 | domain=0（缺省） | 覆（全正例头字节 00 00） |
| 14 | domain=1 | 覆（`rip_tpos33_domain`） |
| 15 | domain=0xFFFF | 覆（`rip_tedge19_domain_ffff`） |
| 16 | AFI=0（Request 全量） | 覆（`rip_tpos1_request_full`） |
| 17 | AFI=2（IPv4） | 覆（全正例） |
| 18 | AFI=3（非法） | 覆（`rip_terr5_afi3`） |
| 19 | AFI=0xFFFF（保留） | 覆（`rip_terr6_afi_ffff` + `rip_terr19_afi_ffff_explicit`） |
| 20 | 路由数 0（显式空） | 覆（`rip_tedge6_zero_routes`） |
| 21 | 路由数 1 | 覆（`rip_tpos6_multicast_ttl`） |
| 22 | 路由数 25（单包上限） | 覆（`rip_tedge7_25_entries`） |
| 23 | 路由数 26（拆包） | 覆（`rip_tedge8_26_entries`） |
| 24 | 路由数 50 | 覆（`rip_tedge9_50_entries`/`rip_tpos20_50_entries`） |
| 25 | 路由数 51 | 覆（`rip_tedge10_51_entries`/`rip_tpos21_51_entries`） |
| 26 | 认证+25 路由（首包 24 上限） | 覆（`rip_tpos27_auth_25_routes`） |
| 27 | 认证+26 路由（拆包） | 覆（`rip_tpos27b_auth_26_routes`） |
| 28 | 密码恰 16B | 覆（`rip_tpos24_simple_auth_16b`） |
| 29 | 密码 17B（超限） | 覆（`rip_terr10_password_17b`） |
| 30 | AuthDataLen=0 | 覆（`rip_terr17_authdatalen0`） |
| 31 | AuthDataLen=20 | 覆（`rip_tpos25_md5_authdatalen20`） |
| 32 | 默认路由 0.0.0.0/0 | 覆（`rip_tedge11_default_route`） |
| 33 | 主机路由 /32 与 /128 | 覆（`rip_tpos22_host_mask`/`rip_tpos23_ripng_128`） |
| 34 | 广播地址作路由（拒绝） | 覆（`rip_tedge12_ip_bcast_err`） |
| 35 | 路由 IP 非法字面 | 覆（`rip_terr11_ip_invalid`） |
| 36 | next_hop 异族 | 覆（`rip_terr13_nh_v6`） |
| 37 | routers=[]（空） | 覆（`rip_tedge21_routers_empty`） |
| 38 | routers=[{}]（空元素） | 覆（`rip_terr16_router_empty`） |
| 39 | 多 router 3/8/100 | 覆（`rip_tpos16_3_routers`/`rip_tpos28_8_routers`/`rip_tpos17_100_routers`） |
| 40 | rounds=3 | 覆（`rip_tpos7_rounds`） |
| 41 | version 缺席（默认 v2） | 覆（`rip_tpos29_version_default`） |
| 42 | command 缺席（默认 response） | 覆（`rip_tpos30_command_default`） |
| 43 | routes=nil（场景默认 5 条） | 覆（`rip_tpos18_default_routes`/`rip_tedge20_default_routes`） |
| 44 | triggered_update | 覆（`rip_tpos13_triggered`） |
| 45 | split_horizon 单播 | 覆（`rip_tpos10_split_horizon`） |
| 46 | poison_reverse 单播 | 覆（`rip_tpos12_poison_reverse`） |
| 47 | split+poison 组合 | 覆（`rip_terr15_split_poison`） |
| 48 | split + multicast（过滤跳过） | 覆（`rip_terr18_multicast_split`） |
| 49 | multicast 覆盖用户 DstIP | 覆（`rip_terr14_multicast_overrides`） |
| 50 | GroupID 动态（inc/fixed） | 覆（`rip_tedge22_routers_100_inc`/`rip_tpos17_100_routers`） |

50 行全部有落点，零留白。✓

### 10.4 子表③：商业行为→用例映射表

| # | 商业行为（出处） | 用例映射 | 结论 |
|---:|---|---|---|
| 1 | Cisco/Juniper 周期全表通告（RFC 2453 §2.3 现网默认） | `rip_tpos20_50_entries` | 已覆 |
| 2 | 启动收敛请求（RFC 2453 §3.9.1 Request 全量） | `rip_tpos1_request_full` | 已覆 |
| 3 | 组播更新 224.0.0.9（RFC 2453 §3.5 现网默认） | `rip_tpos6_multicast_ttl` | 已覆 |
| 4 | 认证网络（RFC 2453 §3.3 / RFC 4822） | `rip_tpos8_simple_auth`/`rip_tpos9_md5_auth` | 已覆 |
| 5 | 触发更新（RFC 2453 §2.5） | `rip_tpos13_triggered` | 已覆 |
| 6 | 水平分割 / 毒化反转（RFC 2453 §2.2.1/§2.2.2） | `rip_tpos10_split_horizon`/`rip_tpos12_poison_reverse` | 已覆 |
| 7 | IPv6 网络 RIPng（RFC 2080 现网） | `rip_tpos14_ripng` | 已覆 |
| 8 | 多路由器/多接口并发 | `rip_tpos16_3_routers` | 已覆 |
| 9 | RIPng IPsec 认证（RFC 2080 §4） | — | **明确不解决**（v1 范围外，交 IPsec） |
| 10 | 定时器驱动的收敛（30s/180s） | — | **明确不解决**（无状态回放不模拟定时器） |

8 覆 + 2 不适用 = 10。✓无映射无确认即缺口——本表零缺口。

### 10.5 三路对照与候选方案对比（§4.12–4.15 / §4.17）

三路：①规范原文（RFC 1058/2453/2080/4822，定"必须是什么"：头 4B + RTE 20B、端口 520/521、认证条目占槽位）；②商业化软件实际行为（Cisco IOS `router rip` / Juniper Junos `protocols rip` 的现网行为：周期通告 30s、组播 224.0.0.9、水平分割默认开——旧基线 §6 已记载；本版不重复抓包，标注为继承）；③可靠开源实现思路（FRRouting `ripd` / Quagga 的 RTE 构造与拆包策略，只借鉴思路：25/包上限、认证占槽位）。三路一致点：线格式与端口；不一致点 = 多路由器 src_port（RFC 2453 §3.6 规定 Response 源端口=520，trafficgen 用 52001+idx 区分四元组）。

| 方案 | 走法（借鉴来源） | 取舍 | 结论 |
|---|---|---|---|
| A | 独立 `rip` 终结层（本版；波 5c 已落码，dhcp/dhcpv6 同族） | 事件级覆盖 DstIP/TTL/SrcPort/DstPort/FlowID，多路由器与多播可声明可断言；代价 = 一套薄层（2914 行） | **采用** |
| B | 直接 udp 层 + 顶层 payload（旧 §1.5 反对意见） | 单报文单向、无版本/认证/拆包语义 → 71 例中绝大多数不可表达 | **否决** |
| C | 与 ospf/igmp/pim 合并为"路由族"（同为路由协议） | 载体不同（RIP 是 UDP 520，ospf/pim/igmp 是 raw-IP 协议号 89/103/2）；文法不兼容，合并即错 | **否决** |

## 11. 代码设计条目（CORE_MEMORY §8 八要素）

> 状态说明：实现已落码（`internal/protocol/rip/` 六文件 + 接线），本条目为文档先行批次对既有实现的**逆向定稿**（as-built），供门1 批准后作为后续改动的唯一入口；代码阶段动作 = 缺口收敛（§14），不另开新层。

### 11.1 文件清单（实测，非计划）

| 文件 | 职责 | 行数 |
|---|---|---:|
| `trafficgen/internal/core/types.go`（`RIPConfig`/`RIPRoute`/`RIPAuth`/`RIPRouter`） | 配置类型 | —（共享文件） |
| `trafficgen/internal/protocol/rip/rip.go` | `Planner.Validate`（19 种拒绝）+ `Plan`（router/rounds/scenario/auth/split 事件流）+ 端口/目标解析 | 681 |
| `trafficgen/internal/protocol/rip/layer_gen.go` | `RIPGenerator`（`RegisterLayerGenerator("rip")`，事件面复刻 legacy Plan） | 323 |
| `trafficgen/internal/protocol/rip/builder.go` | `BuildRIPHeader`/`BuildRIPPacket`（线格式纯函数） | 226 |
| `trafficgen/internal/protocol/rip/parser.go` | `ParseRIPHeader`（解析，供测试/工具） | 188 |
| `trafficgen/internal/protocol/rip/types.go` | 类型别名 + 常量 re-export | 17 |
| `trafficgen/internal/protocol/rip/rip_test.go` | 单测 | 1479 |
| 接线 | registry 注册（`layers/registry.go:184`）/ translate Meta 直传（`layers/chain_planner_translate.go:64`）/ convert 子配置搬运（`strategy_convert.go:1584`）/ `isRIPChain`（`layers/chain_planner_util.go:161`）/ DstPort 保持 0（`layers/chain_planner.go:1132`）/ SrcPort 保持 0（`layers/chain_planner.go:913`） | — |

### 11.2 接口签名

- `Validate(spec core.FlowSpec) error`（`rip.go:107`）：`RIP==nil` 通过（空配置默认流）；版本/命令/AFI/认证/IP/掩码/前缀长/router 各归一分支，错误文案与 §7 锚词逐字一致。
- `Plan(ctx, spec) (<-chan core.PacketConfig, error)`（`rip.go:391`）：先 Validate；`RIP==nil` 默认化 v2 并写回 spec；按 router × rounds × 拆包 emit。
- 生成器：`Name() "rip"`；`Generate(ctx, req)`（`layer_gen.go:47`）：`req.Meta.RIP == nil` → 默认 v2；逐事件 `EmitMsg`。

### 11.3 数据结构

`RIPConfig{Version, Command, Domain, Routes[], Auth, Multicast, Scenario, Routers[], Rounds, TriggeredUpdate, SplitHorizon, PoisonReverse}`；`RIPRoute{AFI, RouteTag, IPAddr, SubnetMask, PrefixLen, NextHop, Metric}`；`RIPAuth{Type, Password, KeyID, AuthDataLen *uint8, SequenceNumber}`；`RIPRouter{SrcIP, SrcPort, DstIP, DstPort}`（`types.go` 全量，无新增）。

### 11.4 主流程

配置 → validator（19 分支）→ 生成器（scenario 推导 → routes 默认 → router 循环 → 拆包 emit 事件）→ udp 层（逐事件一数据报，事件级 DstIP/TTL/SrcPort/DstPort/FlowID 覆盖）→ ip 层（地址/协议号）→ writer（PCAP/NIC）。**双路并存**：legacy `Planner.Plan` 与 `layer_gen.Generate` 语义等价（`chain_planner_rip_test.go` 字节级对比锁定），链路径走后者。

### 11.5 错误分支

19 种 validator 拒绝（§7 表）；全部传 task error（零假成功）。`Planner.Validate` 与生成器共用同一 Validate。

### 11.6 性能边界

见 §6（逐报文流式、per-router 局部状态、无跨流共享、无锁；吞吐数字待 P5 基准）。

### 11.7 与现有逻辑的冲突点

- **registry `rip` 无 `Fields`**（`registry.go:184`，生成表 `rip.fields = {}` 实测）→ 层内业务键无处可住（`ValidateLayerConfig` 拒 `unknown field "command"`，探针实证）→ 缺口 **G-RIP-1（层空壳）**。
- **`translateTerminalConfig` 无 `case "rip"`**（switch 73 case 全表无 rip，实测）→ 层内配置即使放行也不翻译，`spec.RIP` 恒 nil（`chain_planner_translate.go:64` 只做 Meta 直传，读 spec 不写 spec）→ **G-RIP-2（层内配置不翻译）**。
- **`CheckProtoFlat` 无 rip 分支**（`grep -c 'protocol == "rip"'` = 0 实测）→ 顶层 `rip` 子映射 presence 形今日**不判死**（探针实证：`{layers:[...],rip:{}}` → schema errs=0）→ 缺口 G-RIP-3（禁加单协议黑名单分支，等框架级 unknown-key 白名单）。
- **动态 allowlist**（`internal/core/layer_dyn.go` 头部）：`rip` 零命中 → 业务字段动态对象即拒；四元组 `ip`/`udp` 全开。见 §12.12。

### 11.8 回滚方式

本协议文件独立成包，回滚 = revert 本协议 6 文件 + 接线 6 处（registry/translate/convert/util/chain_planner×2）；不触及其他协议。cases 回滚 = 恢复 71 例 JSON（产物文件，非文档）。

## 12. 门1 §1–§14 十四行对照表（CORE_MEMORY §15.1–15.3）

| § | 本协议怎么满足 | 证据 |
|---|---|---|
| §1 层链唯一真相 | 见 §12.1 强制展开：存量 71/71 顶层含旧键（过渡态违规形，代码阶段收敛 G-RIP-1/G-RIP-2/G-RIP-4）；目标形状见 §2 样例；presence 判死形状缺口 G-RIP-3 | §12.1；`cases/rip.json` 机读实测 |
| §2 策略/任务 | 策略 = 单 rip 流量模板，自带 `flow_control`；任务 = 多策略合跑 + 总量封顶；框架语义未动 | 设计 §2 样例 |
| §3 五件套 | 见 §12.3 强制展开：会话表（无会话，显式不适用+理由）/事务序列/关联关系（无派生流诚实声明）/插入位置（udp 终结层）/时间线 | §12.3 + §5 |
| §4 查规范 | RFC 1058/2453/2080/4822 + 旧基线 + tshark 26 字段实测 + 落码反推；八项矩阵 + 子表①②③ | §10 |
| §5 依赖与错误 | `DependsOn ["udp"]`（`registry.go:184`）；19 种拒绝分支；失败传 task error | §5/§7/§11.5 |
| §6 性能 | 见 §6（6.1–6.8 要素齐；吞吐数字标待 P5 基准，不写承诺） | §6 |
| §7 三份文档 | `96-rip-{design,testcase}.md` v1.0.1（本批）+ 旧稿 `10-rip-design.md` 为历史层（§7.4）；无 `10-rip-testcase.md`（新建补缺） | 修订记录 |
| §8 设计先行 | 本批 = 文档先行；代码阶段动作 = 缺口收敛（G-RIP-1/G-RIP-2） | 提交序 |
| §9 测试三源 | 三源 = RFC 四篇（§10）+ 本设计（§11）+ tshark 26 字段实测（§3.7，替代"已确认现网行为"档；现网行为为旧基线继承，未达抓包级 → G-RIP-9）；71 ID 逐项回指；存量 71 例审计去向 testcase §8 | `96-rip-testcase.md` §2/§5/§8 |
| §10 评审闭环 | 本批自审（结论见 /tmp/pipe/doc-lanes/rip.md）+ 批次隔离审查；红先绿后 | lane 报告 |
| §11 白话 | 本文首节白话一句 | 汇报 |
| §12 动态清单 | 见 §12.12 强制展开：四元组全开（allowlist 实测）；业务字段逐个列开/不开 + 理由；序号算法实读行号 | §12.12 |
| §13 schema 派生 | `rip` 已在 `registry.go:184` 注册（**不新增层**）；生成表 `fields: {}` 与 registry 同代；**代码阶段补 Fields 必须重跑 schemagen** | §11.1 |
| §14 真实流程 | 代码阶段：suite 经 MCP 建策略建任务 → 引擎真实生成 → tshark `rip.*`/`ripng.*` + frames 双通道 → 先跑后钉；pcap 落 `/tmp/mcp-pcaps/rip/` | testcase §7 |

### 12.1 §1 强制展开：旧键去向 + 完整 spec_json 样例

**存量实测（逐例机读，2026-09-28）**：

| 文件 | 例数 | 顶层键分布（**括号内为该顶层键形状的例数，非扁平例数**） | 链形 | 负例 expect 形状 |
|---|---|---|---|---|
| `cases/rip.json` | 71 | `{layers,rip,src_port,count}` ×36 + `{rip,src_port,count}` ×17（无 `layers` 键的扁平形）+ `{layers,rip,src_port,count,dst_ip}` ×7 + `{layers,rip,src_port,count,src_ip,dst_ip,dst_port}` ×5 + `{layers,rip,src_port,count,group_id}` ×4 + `{rip,src_port,count,src_ip,dst_ip,dst_port}` ×2（扁平形） | `[udp,rip]` ×52（层 config 恒 `{}` 空壳） | **✗ 19/19 键集为 `{error_contains,expect_error,notes}`——含 `notes`，非纯净两键**（机读实测） |

**扁平例数口径（防误读）**：上表 `×17`/`×2` 是**顶层键形状的例数**，不是扁平例数。**扁平例（无 `layers` 键）共 19 例**（= 17 + 2），机读实测；且这 19 例**全部是负例**（`expect_error`），链形 52 例**全部是正例**——正负与链/扁恰好同界。

**旧键去向表（§15.3 要求"每个键写去向"）**：

脚本复算（`python3` 机读，链 52 / 扁 19；列式 = 链/扁）：

| 旧键 | 链形例数 | 扁平例数 | 合计 | 去向 |
|---|---:|---:|---:|---|
| `src_ip` | 5 | 2 | **7** | 迁 `layers[i].ip.src`（G-RIP-1/G-RIP-2） |
| `dst_ip` | 12 | 2 | **14** | 迁 `layers[i].ip.dst` |
| `dst_port` | 5 | 2 | **7** | 迁 `layers[i].udp.dst_port`（或删，走 getDstPort 版本解析） |
| `count` | 52 | 19 | **71** | 走 `flow_control`（今日 `count=1` 为多数；>1 的 2 例 `rip_tedge22_routers_100_inc`/`rip_tpos17_100_routers` 补 `strategy_fc flows=N`） |
| 顶层 `rip` 子映射 | 52 | 19 | **71** | **迁 `layers[i].rip`**（须先补 registry `Fields`，G-RIP-1/G-RIP-2） |
| `src_port` | 52 | 19 | **71** | 迁 `layers[i].udp.src_port`（或删，走 resolveSrcPort 保底） |
| **合计** | **178** | **63** | **241** | — |
| 顶层 `group_id` | 4 | 0 | **4** | 白名单允许（1.11 结构性键）→ **保留**（不计入上表合计） |

**两套口径不许混用**：① **241** = 全部 71 例的旧键出现总次数；② **178** = **非负例口径**（= 链形 52 正例的合计 178，因 19 扁平例全为负例），即 §1.11/§1.13 判死口径下要清零的数。两数分别用于"存量规模"与"判死面"两种叙述，不得互换。

**结论**：本协议有实质迁移工作量——§1 门的动作 = ①补 registry `Fields`（version/command/domain/routes/auth/multicast/scenario/routers/rounds/triggered_update/split_horizon/poison_reverse 十三键）；②加 translate 分支（层内 rip→`spec.RIP`）；③71 例整体改写；④收官自查行「非负例顶层键 = 0」由 **178 处 → 0**；旧键全集 **6 个** = `src_ip` / `dst_ip` / `src_port` / **`dst_port`** / `count` / 顶层 `rip` 子映射（逐键 5/12/52/5/52/52，链形口径）。

目标形状样例见 §2（顶层仅 `layers`）。

### 12-P2 判死负例形状（链级红例必含清单①③④）

- ① presence 形状 `{"layers":[…],"rip":{}}` 今日**不会被拒**（`CheckProtoFlat` 无 rip 分支，`grep -c` = 0 实测；探针 `ValidateStrategy` → errs=0）→ **代码阶段不建该负例**（建了会真绿 = 假通过）→ 缺口 G-RIP-3 登记。② 白名单外游离键判死（`rejects flat config field src_ip`）今日**已生效**（`CheckProtoFlat` 通用五键检查，探针实证）→ 代码阶段建一条（A′）。③ 19 负例每条带锚词（已齐，§7）。④ 收官自查「非负例顶层键 = 0」（代码阶段迁移后执行）。

### 12-P3 判死形状与 MCP 可达性：三条探针证据原文（2026-09-28 实测）

**探针环境**：scratch 副本 `/tmp/rip-probe`（`cp -r` 自 worktree），worktree 与仓库零改动。以下为原文摘录。

**证据 1——层为空壳，层内业务键被拒**（`ValidateLayers`，探针测试 `TestZZProbeRIPLayerInternalConfig`）：

```
链 = [{"ip":{...}},{"udp":{...}},{"rip":{"version":"v2","command":"request","scenario":"request_full","multicast":true,"routes":[]}}]
输出 = LAYER-CONFIG-REJECTED: layers: layer "rip": unknown field "command"
```

→ registry `rip` 无 `Fields`，层内 `command`/`version`/`routes` 等键**无处可住**（G-RIP-1）。

**证据 2——71 例经 MCP 建策略直接 400（既非绿也非红）**（`schema.ValidateStrategy("synth","rip",…)`）：

```
存量层链形 {layers:[{udp:{}},{rip:{}}], count:1, src_port:0, rip:{...}}
  → errs = "protocol rip rejects flat config field src_port (use a layers chain: …)"
存量扁平形 {count:1, src_port:0, rip:{...}}
  → errs = "protocol rip rejects flat config field src_port (use a layers chain: …)"
```

→ 52 个层链例（带顶层 `src_port`）与 19 个扁平例**全部 400**：既不是绿（MCP 建不了策略）也不是红（离线套件仍绿）。**存量 71 例不是合法 MCP 任务 spec**（违反 §14.1/§14.2）。

**证据 3——presence 形不判死（CheckProtoFlat 缺 rip 分支的实证）**（同探针）：

```
目标形状 {layers:[{ip:{...}},{udp:{src_port:12345,dst_port:520}},{rip:{version:"v2",multicast:true}}]}
  → errs = "layers: layer "rip": unknown field "multicast""   ← 被 V9 拦（非 presence 门）
presence 形 {layers:[{ip:{...}},{udp:{...}},{rip:{}}], rip:{}}
  → errs = （空，0 条）                                          ← 今日不判死
```

→ `CheckProtoFlat` 内 `grep -c 'protocol == "rip"'` = **0**；**presence 形 `{layers:[…],rip:{}}` → schema errs = 0，今日不判死**（G-RIP-3）。故今日建该负例会**真绿 = 假通过**，代码阶段修复后才建。

**离线套件对照实测**（scratch 副本补 rip 空导入 + `CHAIN_PROTO=rip`）：**52/52 全绿，58.5s**——**仅 52 个链形例被执行；19 个扁平例被 `layer_chain_suite_test.go:138` 的 `if _, ok := specMap["layers"]; !ok { continue }` 跳过、从未执行**。原因 = `:230-236` 剥离 `layers` 后把顶层扁平键直传 `core.MapToFlowSpec`，**绕过 `CheckProtoFlat`** → "绿"不证明 MCP 可达（G-RIP-10）。

### 12-P4 结果产物过期与不完整（G-RIP-11）

**现象**：tracked 结果产物 `trafficgen/docs/protocol-pcap-test/rip.md` 写 `Cases: 1 — pass 1, fail 0, error 0`（**只有 1 例**，与存量 71 例不符——本身即不完整产物）；且末次提交早于扁平判死提交 `0417be5`。**该 1/1 pass 是过期且不完整的产物，不得作为"套件可跑"依据。**

**rip 的双重缺口**：① **不完整**——1 例 vs 存量 71 例（其中 52 个链形例今日仅离线可跑、19 个扁平例被 `layer_chain_suite_test.go:138` 跳过、**从未执行**，见 §12-P3）；② **过期**——产物成文于判死提交之前。经 MCP 建策略今日**全部 400**（§12-P3 证据 2），故该产物所声称的 pass 与今日可达性无关。

**复算证据（2026-09-28 实测，原文）**：

```bash
git log -1 --format='%h %ad %s' --date=short -- trafficgen/docs/protocol-pcap-test/rip.md  # → a674fe9 2026-09-05
git log -1 --format='%h %ad %s' --date=short 0417be5                                       # → 0417be5 2026-09-13
ls trafficgen/docs/protocol-pcap-test/rip/ | wc -l                                         # → 0（目录不存在）
sed -n '3p' trafficgen/docs/protocol-pcap-test/rip.md                                     # → Cases: 1 — pass 1, fail 0, error 0
```

### 12.3 §3 强制展开：五件套

会话表：**无会话**（显式不适用——RIP 是 UDP 无连接协议，无连接生命周期；理由写入 §5；豁免依据 §3.14 无长连接协议）。事务序列：`t1` 发 Request（`rip_tpos1_request_full` 前包）/ `t2` 收 Response（同例后包，自动派生）/ `t3` 发 Response（`rip_tpos5_unicast`）/ `t4` 多轮（`rip_tpos7_rounds` rounds=3）/ `t5` 多 router 并列（`rip_tpos16_3_routers`）；每事务四件事见 §5 状态机 + §4 场景表。关联关系：**无派生流**（诚实声明：RIP 无控制/数据分离，多 router 是并列四元组非主从派生，无 `driven_by`；CancelRequest 类关联不适用）。插入位置：udp 终结层（`[ip,udp,rip]`，无中间层）。时间线：报文内严格顺序 / 多 router 顺序展开（跨 router 不假设全局包序，只断言聚合）/ 无交错（UDP 单发无并发路径）。

### 12.12 §12 强制展开：动态字段清单与序号算法

四元组 `ip.src/dst`、`udp.src_port/dst_port` 五策略全开（allowlist `internal/core/layer_dyn.go` 头部四行实测：`ip`/`tcp`/`udp`/`eth`；保底 `DefaultSrcPort+i`（`strategy_convert.go:49`）；dst 动态与版本端口解析和平共处——显式/动态值非零即不触发解析补齐）。

**业务字段 13 项全关**（`layer_dyn.go:17` 的 `layerDynAllowlist` 表无 `rip` 键——实测该表键集 = `ip`/`tcp`/`udp`/`eth`/`http`/`tls`/`dns`/`mqtt`/`h323`/`mpls`/`ngap`/`telnet`/`sip`/`radius`，无 rip；对象即拒）：`version`/`command`/`domain`/`routes[]`/`auth`/`multicast`/`scenario`/`routers[]`/`rounds`/`triggered_update`/`split_horizon`/`poison_reverse`——逐流变体需求列 A′ 候选（testcase §6.2；今日按 §9.36 口径不冒充覆盖）。**多 router 场景的逐流变化由配置内 `routers[]` 数组承担**（每 router 显式四元组），不是动态字段。

序号算法实读：`parseLayerDyn`（`layer_dyn.go:78`）/ `TupleGenerator.Next`（`tuple_generator.go`）/ 保底自增（`strategy_convert.go:49` + worker 注入）/ allowlist 白名单（`layer_dyn.go` 头部）——**`layerDynAllowlist` 无 `rip` 键**（表键集实测，见上），即层内任何对象值 → `does not support dynamic`。（注：`layer_dyn.go:1036` 注释中出现的 "rip" 是注释文本 "strips it"，与 allowlist 无关。）

## 13. 对接清单（testcase 草稿输入；正文落 testcase 文件）

71 ID（52 正 + 19 负）+ packet_count/锚词 + fixture 常量 + 双通道断言基线 + 存量审计（testcase §2–§5/§8 全量）+ **覆盖反查门建议断言行 20 项**（testcase §9，红项 6 项如实标红：G-RIP-1/G-RIP-2/G-RIP-3/G-RIP-4 未落码 + 形状未统一）。A′ 候选（代码阶段）：`rip_ripng_request`（§10.2 空格）/ `rip_neg_stray_src_ip`（白名单游离键，今日已生效）/ `rip_neg_top_rip_presence`（**待 G-RIP-3 修复后**才建）。

## 14. 缺口立项清单（有缺口写「缺口立项」，不许空着）

每条含三要素：**现象 / 证据（行号）/ 归属阶段**。

| 缺口 | 现象 | 证据（行号/实测） | 归属阶段 |
|---|---|---|---|
| **G-RIP-1** 层空壳 | rip 层无字段表 → 层内业务键无处可住，`ValidateLayerConfig` 直接拒 | `layers/registry.go:184`（`Name:"rip"` / `CategoryTerminal` / `DependsOn ["udp"]` / **无 `Fields`**）；生成表 `schemas/v1/generated/layers.generated.json` → `rip.fields = {}`；`chain_planner_translate.go:852` `if len(s.Fields) == 0 { return }` 使层内配置**根本不被解码**；探针：`ValidateLayers([{ip},{udp},{rip:{version,command,...}}])` → `layers: layer "rip": unknown field "command"` | **代码阶段补**（registry 十三键 + 重跑 schemagen） |
| **G-RIP-2** 层内翻译缺失 | 层内配置即使放行也不翻译 → `spec.RIP` 恒 nil → 生成器走默认流 | `chain_planner_translate.go` 的 `translateTerminalConfig` switch（73 case）**全表无 `case "rip"`**；`:64` `RIP: spec.RIP` 仅 Meta 直传（**读 spec 不写 spec**） | **代码阶段补**（`case "rip"` 严格 JSON 往返解码进 `spec.RIP`） |
| **G-RIP-3** CheckProtoFlat 无 rip 分支 | 顶层 `rip` 子映射 presence 形**今日不判死** | `strategy_convert.go` 内 `grep -c 'protocol == "rip"'` = **0**；探针：`ValidateStrategy("synth","rip",{layers:[…],rip:{}})` → **schema errs = 0**（对照 `{…,src_port:0}` → errs=1） | **代码阶段**；**禁加单协议黑名单分支**，走框架级 unknown-key 白名单（kingbase 裁定先例） |
| **G-RIP-4** 顶层旧键残留 | 71 例顶层越白名单键 **178 处**（非负例口径） | 机读实测：`count` 52 / `rip` 52 / `src_port` 52 / `dst_ip` 12 / `src_ip` 5 / `dst_port` 5 = 178；白名单 = `{layers,strategy_fc,ttl,flow_control,output,output_config,group_id}` | **待代码阶段收敛**（随 G-RIP-1/G-RIP-2；收官「非负例顶层键 = 0」） |
| **G-RIP-5** 业务字段动态全关 | 层内任何对象值 → `does not support dynamic` | `internal/core/layer_dyn.go:17` `layerDynAllowlist` 表**无 `rip` 键**（表键集实测 14 项，无 rip） | A′ 候选，不冒充已覆盖（§9.36 口径） |
| **G-RIP-6** 旧基线无用例文档 | 只有 `10-rip-design.md`，无 `10-rip-testcase.md` | `docs/protocol-designs/` `ls` 实测 | 本批 #96 补齐（已闭环） |
| **G-RIP-7** 旧稿 DSCP 说法与实现相左 | 旧稿 §5.5「DSCP 默认 CS6」是死参数，从不达线 | `rip.go:502` 算出 `dscp` 但 `emitRIPPacket` 用 `spec` 直配；`layer_gen.go:156` 明写「不加默认」 | 本契约 §0 表 #6 已校正（已闭环）；旧稿留只读 |
| **G-RIP-8** MD5 摘要占位是否需真 HMAC | 现网设备互操作未知 | 未达验证级 | 待确认：抓现网 RIP MD5 报文比对，或查 Cisco/Juniper 手册对应章节（三选一）；确认前不写死进实现 |
| **G-RIP-9** 现网行为未达本批抓包级 | Cisco/Juniper 默认 30s 周期、水平分割默认开为旧基线继承 | 旧基线 §6 记载；本批未抓包 | 待确认：抓现网 RIP 报文（三选一）；不冒充第三源 |
| **G-RIP-10** 离线 harness strip-layers | 顶层扁平违规例今日离线仍绿（绕过 CheckProtoFlat） | `test/protocol_pcap/layer_chain_suite_test.go:225-231` 剥离 `layers` 后把顶层扁平键直传 `core.MapToFlowSpec` | 框架级 P6 票（ledger 已登记，跨协议） |
| **G-RIP-11** 结果产物过期且不完整 | tracked 结果产物 `trafficgen/docs/protocol-pcap-test/rip.md` 写 `Cases: 1 — pass 1, fail 0, error 0`——**只有 1 例**（存量 71 例），本身即不完整；且末次提交早于扁平判死提交 `0417be5`，其 pass 声明今日不成立。**不得作为"套件可跑"依据**。rip 双重缺口：不完整（1 vs 71；19 扁平例另被 `layer_chain_suite_test.go:138` 跳过、从未执行）+ 过期（成文于判死前；今日经 MCP 建策略全部 400，§12-P3 证据 2） | `git log -1 --format='%h %ad' --date=short -- trafficgen/docs/protocol-pcap-test/rip.md` → **a674fe9 2026-09-05**；`git log -1 --format='%h %ad' --date=short 0417be5` → **0417be5 2026-09-13**；`ls trafficgen/docs/protocol-pcap-test/rip/` → 目录不存在（**0 个 pcap**）；`sed -n 3p` 原文见 §12-P4 | **代码阶段**（P5 重跑套件后重生成该产物） |

## 15. 修订记录

- v1.0.1（2026-09-28）：**补登记 G-RIP-11（结果产物过期且不完整）**——`trafficgen/docs/protocol-pcap-test/rip.md` 的 `1/1 pass` 系过期且不完整产物（末次提交 `a674fe9` 2026-09-05 早于判死提交 `0417be5` 2026-09-13；存量 71 例 vs 产物 1 例；`docs/protocol-pcap-test/rip/` 0 个 pcap），归属代码阶段（P5 重跑套件后重生成）。新增 §12-P4 复算证据节；缺口表 +1 行；口径对齐 pcep 先例 G-PCEP-11。仅文档，未动 JSON/代码。
- v1.0.0（2026-09-28）：文档先行批次一 #96。旧稿 10-* 语义继承 + 8 项过期校正（§0）；存量 71 例机读审计（顶层残留形状、expect 形状、逐键计数）；§12.1/12.3/12.12 强制展开 + **§12-P3 三条探针证据原文**；代码设计 as-built 定稿（§11）；缺口 G-RIP-1…G-RIP-10（每条含现象/证据行号/归属阶段）；三源 = RFC 四篇 + 落码 + tshark 26 字段实测。
  **主线程裁定（2026-09-28）**：cases/rip.json 不改写——层空壳实证（§12-P3）；缺口编号按主线程口径重排（G-RIP-1 层空壳 / G-RIP-2 translate 缺 case / G-RIP-3 CheckProtoFlat 无分支 / G-RIP-4 顶层旧键 178 处）。
  自审 4 轮，末轮干净（结论见 /tmp/pipe/doc-lanes/rip.md）。
