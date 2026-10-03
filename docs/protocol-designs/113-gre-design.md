# #113 gre（通用路由封装 GRE，RFC 2784 + RFC 2890，IP 协议号 47）设计契约

> 版本：v1.0.0（批次二 as-built 文档轨 P1–P3）
> 日期：2026-09-29
> 车道：文档轨（#113 gre 续号；本批 10 协议为 **as-built**——把现有实现与现有 cases 如实写成契约，不改代码、不改 cases）
> 旧基线：`docs/CODE_DESIGN.md` D-GRE-1 / D-GRE-2 / D-GRE-3 三条目（**本协议无旧 `NN-gre-design.md`**，历史设计只存在于 CODE_DESIGN 的 D-条目）；`docs/TEST_CASES.md` T-GRE-1…T-GRE-22（含 T-GRE-20 作废注记）
> 存量用例：`trafficgen/test/protocol_pcap/cases/gre.json`（**21 例 = 14 正 + 7 负**，本版 §9 逐条对齐；ID/顺序/包数/断言/锚词以该文件为权威）
> 规范基线：① RFC 2784（GRE 基础头：Flags/Version + Protocol Type，§2；校验和算法 §3.1；转发语义 §3）；② RFC 2890（Key 扩展 §2.1/§3、Sequence Number 扩展 §2.2/§4）；③ RFC 2473（IPv6 承载 GRE 的语义参照，§4 矩阵用）；④ IEEE 802.1Q §3（外层可选 VLAN tag：TPID 0x8100 + TCI=`priority<<13|id`）；⑤ 本机 tshark 3.6.14 `gre.*` 字段表与 **21 例落盘 pcap**（`/tmp/mcp-pcaps/gre/`，字段/包数/偏移的唯一权威，本版逐条复算）；⑥ 本仓库落码（`internal/protocol/gre/` 两文件 + `internal/core/` builder/registry/chain_planner 接线，§11）；⑦ 旧基线 `docs/CODE_DESIGN.md` D-GRE-1…3（内部契约，非外部规范）
> 白话一句：**GRE 是「信封套信封」——外层一个 IP 头（协议号 47），中间一张可选的 GRE 便签（旗标位 C/R/K/S 决定便签上多贴几个 4 字节格子），里面再塞一整封完整的信（内层 IP 包，v4 或 v6 都行）。本生成器一次产出 1 帧（或内层 TCP 链的 9 帧），把外内两套地址、两套 TTL 分得清清楚楚。**

## 0. 本协议特殊性（须写清，不得含糊）

GRE 在本仓库里是**隧道底座（tunnel base）**，不是一个"应用协议"。这带来六条与普通终结层协议不同的结构事实，逐条写明（§0.1–§0.6）：

### 0.1 GRE 是隧道层，不是终结层（Category = tunnel）

`registry.go:1668-1677`：

| 属性 | 值 | 含义 |
|---|---|---|
| `Category` | `CategoryTunnel` | **必须包别人**；不能当末层（V4：`must end with a terminal layer`，`complete.go:383`） |
| `DependsOn` | `["ip"]` | 外层 ip **自动补**（隧道端点住在补出来的外层 ip 层） |
| `InnerRequired` | `["ip"]` | 内层必须从 `ip` 起头；直接内层邻居不是 ip 时**自动插入内层 ip**（`complete.go:162-190`） |
| `FieldContract` | `{"ip.protocol": "47"}` | **声明性**（见 §0.4：本键今日无消费者） |
| `Fields` | `key`(uint32,0) / `checksum`(bool,false) / `sequence`(bool,false) | 层内**仅 3 键**可住 |

**由此推出的层链骨架**：补全后恒为 `[ip, gre, ip, …, 终结层]`——两个 `ip` 层各司其职（外层=隧道端点，内层=被封装包的地址），`gre` 夹在中间。**裸 `[ip,gre,ip,udp]` 被 V4 拒**（末层 udp 是 transport），内层必须以**终结层**收尾——存量 18 例用 `dns`（最小 UDP 载荷终结层），2 例用 `http`（内层 TCP 链）。**这 21 例不是随意选形，是 V4 约束下的唯一可用形**。

### 0.2 GRE 的旗标位 + 可选字段是核心（RFC 2784 基础头 vs RFC 2890 扩展）

GRE 头**不是定长**：4 字节基础头 + **每个置位的旗标各带一个 4 字节（Routing 例外）可选字段**。本实现的逐字段规格见 §3.1，存在性依赖见 §3.2。要点：

- **基础头恒 4B**：Flags(2) + Protocol Type(2)。Flags 高字节低 4 位 = C/R/K/S，低字节 = Version（本实现恒 0）。
- **C 位（0x8000）**：置位则加 `Checksum(2) + Reserved(2)` = 4B（RFC 2784 §2）。
- **R 位（0x4000）**：置位则加 `Routing Length(2) + routing data`；**长度可变**（`2 + len(routing)`），且必须 ≥2 且为偶数（RFC 2784 §2）。
- **K 位（0x2000）**：置位则加 `Key(4)`（RFC 2890 §3）。
- **S 位（0x1000）**：置位则加 `Sequence Number(4)`（RFC 2890 §4）。
- **选项字段的物理顺序恒为 C → R → K → S**（`writeGRE`，`builder.go:861-887`），与旗标位在 Flags 里的高低位顺序无关。

**总长度公式**（`greHeaderLen`，`builder.go:552-573`）：

```
GRE 头长 = 4
         + (checksum ? 4 : 0)          // C: Checksum(2) + Reserved(2)
         + (routing  ? 2+len(routing) : 0)  // R: Routing Length(2) + data
         + (key_present ? 4 : 0)       // K: Key(4)
         + (sequence_present ? 4 : 0)  // S: Sequence(4)
```

以太帧长公式（无 VLAN / 无 padding 时）：

```
帧长 = 14 (eth) + 外层IP头 (20 v4 | 40 v6) + GRE头长 + 内层IP头 (20 v4 | 40 v6) + 内层L4 + 内层载荷
```

**可复算校验（存量 4 例，本版实测，§9 逐例）**：
- `gre_basic_ipv4`：14+20+4+20+8+29 = **95** ✓（内层 DNS 查询 29B）
- `gre_checksum`：14+20+8+20+8+29 = **99** ✓（+4 校验和）
- `gre_kcs_combo`：14+20+16+20+8+29 = **107** ✓（+4+4+4=12）
- `gre_v6_in_v6`：14+40+4+40+8+29 = **135** ✓（双 v6 头各 40B）

### 0.3 GRE 被别的协议当承载（depends_on / transport_on 的实际语义）

**本仓库今日没有任何协议把 `gre` 写进自己的 `DependsOn` 或 `TransportOn`**（机读实测：`registry.go` 全表 **127 层**，`grep -n '"gre"' registry.go` 仅命中 **1 处**——`registry.go:1668` 的 gre 自身注册行；`DependsOn`/`TransportOn`/`InnerRequired` 三列中**只有 gre 自己那一行**引用 `"gre"`，其余命中全在注释文本里（nvgre 注记 `:1691` 的"与设计稿 `[ip,gre,nvgre]` 的文档化分歧"））。registry 的 `TransportOn` 字段（`schema.go:87-92`）语义是"**本层可以坐在哪些传输层上**，第一个 = 默认"，与"谁把 gre 当底座"是两个方向——**gre 是 `CategoryTunnel`，它自己不坐传输层（`DependsOn ["ip"]`），也不被任何协议声明为底座**。

**实际存在的"被承载"关系是同一族内的兄弟层，不是 registry 依赖**：

| 兄弟层 | 关系 | 证据 |
|---|---|---|
| `nvgre`（RFC 7637） | **不复用 gre 层**——内层是裸 Ethernet 帧（TEB 0x6558），gre 隧道层要求内层产 L3/L4 包链且 ProtocolType 限 0x0800/0x0806/0x86DD → 无法复用，故实装 `[ip,nvgre]` 由 nvgre 生成器自写外层 IP + `L2.GRE` | `registry.go:1688-1694` 注记；`internal/protocol/nvgre/layer_gen.go:90` |
| `pptp`（RFC 2637 增强 GRE） | 不复用 gre 层——PPTP 模式重定义 GRE 头（K/S/A/Ver 位、Protocol Type 强制 0x880B），由 pptp planner 直写 `L2.GRE` | `internal/protocol/pptp/planner.go:549-556`；`builder.go:826-841` PPTP 分支 |
| `vxlan`/`geneve` | 与 gre **不同族**——它们是 UDP 上的封装（`DependsOn ["udp"]`），与 GRE 的"IP 协议号 47 直载"是两条路 | `registry.go:1679-1687` |

**结论（如实声明）**：gre 是**自成一体的用户协议层**（`validate_layers.go:1405-1420` 的 `outermostProtocol` 明确把 gre 从"承载骨架"名单里排除——`ip/eth/vlan/mpls/pppoe/tcp/udp/tls/http` 被跳过，**gre 不被跳过**），它的"底座"身份体现在**同族协议的语义借鉴**上（nvgre/pptp 各自实现增强 GRE 变体），不体现在 registry 的跨协议依赖上。**本版不声称"某协议 today 走 `[ip,gre,<proto>]`"**——不存在该形态。

### 0.4 外层/内层双 IP 族组合矩阵（§4 地址与流层要求）

GRE 的地址面有**两套 IP**（外层隧道端点 + 内层被封装包），两套**各自独立、可异族**。四个组合格的实现与用例落点：

| 组合 | 外层 | 内层 | GRE Protocol Type | EtherType | 用例 | 状态 |
|---|---|---|---|---|---|---|
| **4in4** | IPv4 | IPv4 | 0x0800 | 0x0800 | `gre_basic_ipv4` | 已覆 |
| **6in6** | IPv6 | IPv6 | 0x86DD | 0x86DD | `gre_v6_in_v6` | 已覆 |
| **6in4**（v4 外 / v6 内） | IPv4 | IPv6 | 0x86DD | 0x0800 | `gre_6in4` | 已覆 |
| **4in6**（v6 外 / v4 内） | IPv6 | IPv4 | 0x0800 | 0x86DD | `gre_4in6` | 已覆 |

**四格全覆**。族判定链（`layer_gen.go:115-124`）：内层地址 `net.ParseIP(innerSrc).To4() == nil` → 内层 v6 → `protoType = 0x86DD` + `buildInnerIPv6Packet`；否则 v4 → `0x0800` + `buildInnerIPv4Packet`。**外层族与内层族解耦**：外层族由 `finalEmit` 的 `l2For`/`EtherTypeFor(pkt.L3.SrcIP)` 从**外层**地址推（`chain_planner_gen.go:231`），GRE Protocol Type 由**内层**地址推——两者互不影响，这正是 6in4/4in6 能成立的原因。

**内层两地址必须同族**（一个 IP 包不可能 v4 源 + v6 目的）：`chain_planner.go:520-522` 结构性拒绝，锚词 `must be the same IP version`（`gre_neg_inner_mixed`）。

### 0.5 内层地址自治（D-GRE-2 修复的静默覆盖 bug）

**历史缺陷（D-GRE-2 §1 探针 A 实锤）**：内层 ip 层的显式地址曾被外层 spec 广播**静默顶掉**——用户写 `ip{src:"fd00::1"}` 做 v6 内层，出包却是外层 v4 地址，**无告警**。今日已修：

- 内层地址权威 = **内层 ip 层的显式值**；缺席才回退 spec 值（`chain_planner.go:508-514`）。
- 生成器读的是**内层包已注入的 `pkt.L3.SrcIP/DstIP`**（`layer_gen.go:80`），不是 spec。
- 存量 `gre_6in4`/`gre_4in6` 两例就是该修复的**正例证据**（内层地址不被外层顶掉）。

### 0.6 本协议在 §1 层的特殊结论（顶层旧键）

**存量 21 例中，14/14 非负例的顶层旧键 = 0**（机读实测：`spec_json` 顶层键分布 = `{layers}` ×20 + `{layers,count}` ×1；那唯一一个 `count` 在**负例 `gre_neg_flat`** 里，是**判死对象本身**）。即：**非负例 14/14 零残留**（20/20 例顶层键 ⊆ `{layers}`，唯一例外即该负例的判死键）——§1 迁移工作量为零（见 §12.1）。

## 1. 范围、profile 与实现状态边界

本版定义 **GRE（RFC 2784 基础头 + RFC 2890 Key/Sequence 扩展）承载于 IP 协议号 47** 的流量生成：外层可选 802.1Q VLAN tag、外层 IPv4/IPv6、GRE 头（4B 基础 + 0…16B 可选字段）、内层完整 IP 包（IPv4/IPv6 + TCP/UDP + 内层终结层载荷）。

| profile | 承载 | 本版允许内容 | 不从 profile 推导 |
|---|---|---|---|
| `gre_4in4_v1`（主） | `[ip,gre,ip,udp,dns]` | 外层 v4 隧道端点 + 内层 v4/UDP/DNS，GRE 无旗标 | 真实隧道路由/转发表 |
| `gre_v6_v1` | 同上，内外层均 v6 | 外层 v6（EtherType 0x86DD）+ GRE proto 0x86DD + 内层 v6 | 从 v4 fixture 推导 v6 地址 |
| `gre_hetero_v1` | 同上，内外异族 | 6in4 / 4in6 两格（§0.4） | — |
| `gre_opts_v1` | 同上，旗标位组合 | C/K/S 三键任意组合（含三键齐开 0xB000） | RFC 2890 §5 的 Key 语义（"Key 由上层定义"，本实现只搬数值） |
| `gre_inner_tcp_v1` | `[ip,gre,ip,tcp,http]` | 内层完整 TCP 会话（握手/数据/挥手 9 帧） | 内层 TCP 的 MSS 分段（由 tcp 层生成器承载） |
| `gre_vlan_v1` | `[vlan,ip,gre,ip,udp,dns]` | 链首 vlan 层 → 外层帧打 802.1Q tag | 内层 VLAN（V7 结构性拒，§8） |

显式边界（"不实现、不声称、不许静默转换"）：

1. **不实现 ARP-over-GRE 的链上路径**：ARP 内层（Protocol Type 0x0806，28B ARP 报文）只有 legacy planner（`planner.go:274-286`）支持；**链上 `InnerRequired=["ip"]` 强制内层从 ip 起头**，ARP 无链层等价物 → 链上不可达（D-GRE-1 明确不解决）。
2. **不实现 Routing（R 位）的链上路径**：`GREConfig.RoutingPresent/Routing`（`types.go:3229-3230`）与 builder 的 R 分支（`builder.go:868-874`）已落码，但 **registry `Fields` 无 `routing` 键** → 层内不可达；legacy flat 路径可用（§8 缺口 G-GRE-1）。
3. **不实现 PPTP 增强 GRE 模式**：`GREConfig.PPTP/AckPresent/CallID/Ack` 存在（`types.go:3244-3259`）且 builder 有分支，但属 pptp 协议包（`internal/protocol/pptp/`），**gre 层 `Fields` 3 键不含**。
4. **不实现内层 TCP options 注入**：`layer_gen.go:33-34` 声明——legacy `cfg.TCPOptions` 由策略直配，**链层无该字段**；生成器 `encodeTCPOptions(…, nil)` 恒传 nil。
5. **不实现内层 VLAN / MPLS / PPP inner**：V7 结构性拒（`gre_vlan_tunnel_test.go:118` 区域）。
6. **不实现 IP 分片/重组**：内层包整包发出（外层 IP Flags 恒 DF，`builder.go:371`）。
7. **不声称 GRE 校验和的转发语义**：本实现按 RFC 2784 §3.1 算出正确的 16 位补码和（§3.3 复算实证），但**不声称**中间路由器会校验/重算它。
8. **不声称 Key 具备隧道识别语义**：RFC 2890 §3 明写"Key 的语义由封装协议决定"，本实现只把用户值写进线（Key=0 时**不置 K 位**，§3.2）。

**实现状态（2026-09-29 实测）**：`gre` 层已注册（`registry.go:1668`，`CategoryTunnel`，`DependsOn ["ip"]`，`InnerRequired ["ip"]`，`Fields` 3 键）；生成器/校验器已落码（`internal/protocol/gre/layer_gen.go` 208 行 + `planner.go` 554 行）；`allowedProtocols["gre"]=true`（`protocols.go:40`）；翻转接线已完成（`cmd/server/main.go:589` `RegisterPlanner(layers.NewChainPlanner("gre"))`）；21 语义用例已落 `cases/gre.json` 且 21 例 pcap 实测在案（§9）。

**输出契约（pcap/NIC 双输出）**：两路径共用**同一份 cases JSON 与断言集**（`gre.flags_and_version`/`gre.proto`/`gre.key`/`gre.checksum`/内层 `ip.version`/`udp.*`/`vlan.*` 字段 + frames 原始 hex + `min_packets`）；NIC 经 tcpdump 捕获（`nic_capture` 用例级开关，`test/protocol_pcap/nic_drive_test.go`）；**不设仅单路径可用的断言**。**本版未跑 NIC 一路**（诚实声明）——本版全部断言在 pcap 一路逐条实测复算（§9），NIC 复用同一契约。

## 2. 协议栈、端口和固定偏移

推荐层链 `[ip, gre, ip, udp, dns]`（**用户只写 `[gre, dns]` 即被补全成此形**：gre 的 `DependsOn ["ip"]` 补外层 ip、`InnerRequired ["ip"]` 补内层 ip、dns 的 `DependsOn ["udp"]` 补 udp）。内层 TCP 链形为 `[ip, gre, ip, tcp, http]`。

**端口**：GRE **本身无端口概念**（IP 协议号 47，无 L4 头）。端口属于**内层**——`udp`/`tcp` 层的 `src_port`/`dst_port` 住内层传输层，随内层包被封进 GRE 载荷。外层**没有**端口可写。因此：
- `gre` 层 `Fields` 3 键**不含端口**（§0.1）。
- 目的端口缺省由 `fieldContractDstPort`（`chain_planner_util.go:291`）读**终结层** FieldContract（dns→53 / http→80）——**不是 gre 层**。
- 存量 21 例一律显式写内层端口（`udp{12345→80}` / `tcp{12345→80|8080}`），无缺省端口例（A′ 候选，§13）。

**固定偏移**（无 VLAN / 无 IP options / 无 TCP options）：

| 层 | IPv4 外层（eth14 + ip20） | IPv6 外层（eth14 + ip40） |
|---|---|---|
| GRE 头起点 | **34** | **54** |
| GRE 可选字段起点 | 38（=34+4） | 58（=54+4） |
| 内层 IP 头起点 | 34 + GRE头长 | 54 + GRE头长 |
| 内层 L4 起点 | 内层 IP 头起点 + 20 | 内层 IP 头起点 + 40 |

**VLAN 情形**：链首 `vlan` 层 → eth 头后插 4B（TPID 0x8100 + TCI），**其后所有偏移 +4**（`gre_vlan_tagged`：GRE 头 offset 34→**38**）。

**目标形状 spec_json 样例（严格层链形，顶层仅 `layers`；本协议存量已是此形，无迁移）**：

```json
{
  "layers": [
    {"ip":  {"src": "10.0.0.1", "dst": "20.0.0.1"}},
    {"gre": {}},
    {"ip":  {"src": "192.168.1.1", "dst": "192.168.1.2"}},
    {"udp": {"src_port": 12345, "dst_port": 80}},
    {"dns": {}}
  ]
}
```

多流样例（数量只走 `flow_control`，存量 5 例用 `strategy_fc` 等价的 `{"type":"flows","value":2}`）：

```json
{
  "layers": [
    {"ip":  {"src": {"strategy": "list", "list": ["10.0.0.1", "10.0.0.2"]}, "dst": "20.0.0.1"}},
    {"gre": {}},
    {"ip":  {"src": "192.168.1.1", "dst": "192.168.1.2"}},
    {"udp": {"src_port": 12345, "dst_port": 80}},
    {"dns": {}}
  ],
  "flow_control": {"flows": 2}
}
```

## 3. 线格式编码

### 3.1 GRE 基础头（4 字节，RFC 2784 §2）

| 偏移（相对 GRE 头起点） | 字段 | 类型/尺寸 | 端序 | 本实现 |
|---:|---|---|---|---|
| 0–1 | Flags + Version | 16 bit | 大端 | 高字节低 4 位 = C/R/K/S；低字节 = Version（**恒 0**） |
| 2–3 | Protocol Type | 16 bit | 大端 | 内层族：`0x0800`(IPv4) / `0x86DD`(IPv6)；`0` → builder 兜底 `0x0800`（`builder.go:857-860`） |

**旗标位定义**（`builder.go:80-83`）：

| 位 | 掩码 | 名称 | 置位后果 |
|---|---:|---|---|
| C | `0x8000` | Checksum Present | +`Checksum(2) + Reserved(2)` |
| R | `0x4000` | Routing Present | +`Routing Length(2) + routing data`（长度可变） |
| K | `0x2000` | Key Present（RFC 2890 §2.1） | +`Key(4)` |
| S | `0x1000` | Sequence Number Present（RFC 2890 §2.2） | +`Sequence Number(4)` |

`writeGRE`（`builder.go:825-888`）按 **C → R → K → S 固定物理顺序**写可选字段（`off` 从 4 起逐段推进），与旗标位顺序无关。

### 3.2 可选字段的存在性依赖（逐条列出）

**核心规则**：**旗标位是可选字段存在的唯一开关**——位置位则字段必然出现（4B / 可变），位不置则字段必然不出现。本实现的逐条映射：

| # | 存在性依赖 | 实现行 | 用例证据 |
|---:|---|---|---|
| D-1 | **K 位置位 ⇔ `key_present=true`** → Key 字段 4B 出现 | `builder.go:851-853` + `:884-887` | `gre_key`（flags `0x2000`，@38 `12 34 56 78`） |
| D-2 | **`key == 0` → 不置 K 位**（KeyPresent 由 `key != 0` 推，不是独立开关） | `layer_gen.go:131` `KeyPresent: key != 0` | `gre_basic_ipv4`（`gre:{}` → key=0 → flags `0x0000`） |
| D-3 | **C 位置位 ⇔ `checksum=true`** → `Checksum(2)+Reserved(2)` 4B 出现，且 Checksum 域被 `fillGREChecksum` 回填 | `builder.go:844-846` + `:862-866` + `:895` | `gre_checksum`（flags `0x8000`，`gre.checksum=0xfb89`） |
| D-4 | **S 位置位 ⇔ `sequence=true`** → Sequence Number 4B 出现，值 = 配置基值 + 帧序号 | `builder.go:854-856` + `:888-891`；`layer_gen.go:136-138` | `gre_sequence_multi`（flags `0x1000`，逐帧 0→8） |
| D-5 | **R 位置位 ⇔ `routing_present=true`** → `Routing Length(2)+data`；**长度 ≥2 且为偶数**否则 builder 拒绝 | `builder.go:868-874`；校验 `:536-538` | **今日无例**（层内不可达，§8 G-GRE-1） |
| D-6 | **C/R/K/S 可任意组合**，头长 = 4 + Σ(各置位字段长) | `greHeaderLen`，`builder.go:552-573` | `gre_kcs_combo`（`0xB000` → 头 16B） |
| D-7 | **Protocol Type 与旗标位完全正交**（族选择与选项无关） | `writeGRE`：Flags 与 protoType 独立写 | 全 21 例 |
| D-8 | **PPTP 模式下 C/R/K/S 位被模式接管**，与之组合是矛盾（builder 拒绝） | `builder.go:519-531` | 层内不可达（pptp 协议包） |

**Key=0 的特殊语义（须写清）**：RFC 2890 §3 允许 Key 值为 0 且 K 位置位；**本实现的选择是 `key == 0` 时不置 K 位**（`layer_gen.go:131`，注释明写"Key 域语义由上层决定，0 值等价无 Key"）。因此**层内无法表达"K 位置位且 Key=0"**——这是本实现的**固定选择**，不是规范强制。存量 `gre_key` 用 `key=305419896`（0x12345678）避开该歧义。

### 3.3 GRE 校验和算法（RFC 2784 §3.1）

`fillGREChecksum`（`builder.go:895-`）：先把 Checksum 域清零，对 **[GRE 头起点, 外层 IP 载荷末端)** 做 16 位一补码和（`ipChecksum16`，`builder.go:513`），**结果 0x0000 时线上发 0xFFFF**。覆盖范围 = GRE 头 + 内层完整包（**不含以太头、不含外层 IP 头、不含以太 padding**）。

**本版逐例复算实证（2026-09-29，`gre.checksum.status=1` = tshark 判 good）**：

| 用例 | 线上 `gre.checksum` | 本版按上述算法复算 | `gre.checksum.status` |
|---|---|---|---|
| `gre_checksum` | `0xfb89` | **0xfb89** ✓ | 1 |
| `gre_kcs_combo` | `0x62dd` | **0x62dd** ✓ | 1 |

**`gre_kcs_combo` 的复算是本版对"可选字段顺序"的独立实证**：若实现把 Key/Sequence 写在 Checksum 之前（错误顺序），复算值不会是 0x62dd。实测吻合 → **C→R→K→S 顺序被校验和交叉验证**（校验和覆盖整个 GRE 头，字段顺序错则和错）。

### 3.4 内层 IPv4 包（`buildInnerIPv4Packet`，`planner.go:361-386`）

| 偏移 | 字段 | 尺寸 | 本实现值 |
|---:|---|---|---|
| 0 | Version(4) + IHL(4) | 1 | **`0x45`**（v4，IHL=5，**无 IP options**） |
| 1 | TOS | 1 | 0 |
| 2–3 | Total Length | 2 大端 | `20 + len(内层L4)` |
| 4–5 | Identification | 2 大端 | `innerIPID`（**链路径从 0 起每帧自增**，`layer_gen.go:123/125`） |
| 6–7 | Flags + FragOffset | 2 大端 | **恒 `0x4000`**（DF 置位，无分片） |
| 8 | TTL | 1 | 内层 ip 层 `ttl`；0 → 默认 64（`DefaultInnerTTL`，`planner.go:36`） |
| 9 | Protocol | 1 | 内层 L4：6(TCP) / 17(UDP) / 1(ICMP) |
| 10–11 | Header Checksum | 2 大端 | `ipChecksum16(头)` |
| 12–15 | Source Address | 4 | 内层 ip 层 `src` |
| 16–19 | Destination Address | 4 | 内层 ip 层 `dst` |

### 3.5 内层 IPv6 包（`buildInnerIPv6Packet`，`planner.go:395-424`）

| 偏移 | 字段 | 尺寸 | 本实现值 |
|---:|---|---|---|
| 0 | Version(4)+TC(4)+FlowLabel 高 4 | 1 | **`0x60`**（v6，TC=0，FlowLabel=0） |
| 1–3 | FlowLabel 低 16 + TC 低 4 | 3 | 0 |
| 4–5 | Payload Length | 2 大端 | `len(内层L4)`（**不含 40B v6 头**） |
| 6 | Next Header | 1 | 6/17/58 |
| 7 | Hop Limit | 1 | 内层 ip 层 `ttl`；0 → 64 |
| 8–23 | Source Address | 16 | 内层 `src` |
| 24–39 | Destination Address | 16 | 内层 `dst` |

**v6 内层无 IPID**（RFC 8200 无该字段）——`innerIPID` 计数器只被 v4 路径消费（`layer_gen.go:111-112` 注释明写）。

### 3.6 内层 L4（`buildInnerL4`，`planner.go:429-488`）

| 协议 | 头长 | 校验和 | 备注 |
|---|---:|---|---|
| TCP (6) | `20 + len(opts)` | 伪头（RFC 793） | **链路径 opts 恒 nil**（§1 边界 4）；flags 默认 `0x18`(PSH\|ACK)，可由内层 tcp 层生成器写入的 seq/ack/flags/window 覆盖（`layer_gen.go:94-101`） |
| UDP (17) | 8 | 伪头（RFC 768） | **与 L2TP 的零校验和不同，本实现算真值**；v6 内层时 `cksum==0 → 0xFFFF`（RFC 6936 §2，`planner.go:468-470`） |
| ICMP (1) | 8 | **仅报文**（RFC 792，无伪头） | 链上不可达（内层终结层无 ICMP 生成器）；legacy 可用 |
| ICMPv6 (58) | 8 | 含伪头（RFC 4443） | 同上 |

### 3.7 外层帧装配（`finalEmit`，`chain_planner_translate.go:324-380`）

外层帧由**外层 ip 层生成器 + `finalEmit`** 装配，GRE 层生成器只负责**内层包字节**与 **`L2.GRE` wire 配置**：

| 步骤 | 动作 | 行 |
|---|---|---|
| 1 | `GREGenerator` 产出 `PacketConfig{Direction, L2.GRE, L3.Protocol=47, Payload=内层包字节}` | `layer_gen.go:139-148` |
| 2 | 外层 ip 层生成器写 `L3.SrcIP/DstIP/TTL`，并把 `L2.GRE` **暂存** | `generator.go:776-826` |
| 3 | `finalEmit` 用 `l2For` **全量重建** `L2`（MAC + EtherType + VLAN），**重建后恢复 `L2.GRE`** | `chain_planner_translate.go:342-349` |
| 4 | down 方向交换 `L3.SrcIP/DstIP`；`L3.TTL = ipTTL(外层 ip 层 cfg)` | `:352-355` |
| 5 | `L3.Protocol` **只在 0 时填充**（GRE 层已写 47，绝不覆盖） | `:361-368` |
| 6 | builder `writeL3` 写外层 IP（total length 覆盖 GRE+内层），`writeGRE` 写 GRE 头，`copy` 写内层包字节，`fillGREChecksum` 回填 | `builder.go:383-386` + `:412-414` |

> **第 3 步的顺序是关键**：注释明写"先取 gre 再 l2For，反了取到的是 nil"——`l2For` 会重建整个 `L2Config`，若先重建再取 `L2.GRE` 就丢了。
**外层 IP 的 TTL**：恒取**外层 ip 层**的 `ttl`（`ipTTL`，`chain_planner_gen.go:278-286`，缺省 64）——与内层 TTL 完全独立（`gre_inner_ttl` 用例：外层 offset 22 = `0x40`(64)、内层 offset 46 = `0x3c`(60)）。

## 4. 业务场景分析（现网典型场景与五层覆盖）

**定性**：**声明式剧本回放**——配置声明内外两套地址与 GRE 旗标，引擎按固定剧本产出隧道帧（单帧封装，或内层 TCP 链的 9 帧会话）。**gre 层无自有状态机**：它逐帧消费内层包、包一层 GRE、交给外层；握手/挥手/分段全在内层 tcp 层，限速/背压在外层 ip 与 worker。

| 现网场景 | 事务交互 | 对应用例 |
|---|---|---|
| ① 站点间 GRE 隧道（4in4 基线） | 外层端点 + 内层私网包，无旗标 | #1 `gre_basic_ipv4` |
| ② 纯 v6 骨干隧道（6in6） | 双 v6 头 + next header 47 | #5 `gre_v6_in_v6` |
| ③ v6 孤岛穿越 v4 骨干（6in4） | 外层 v4 + 内层 v6 | #6 `gre_6in4` |
| ④ v4 孤岛穿越 v6 骨干（4in6） | 外层 v6 + 内层 v4 | #7 `gre_4in6` |
| ⑤ 多隧道复用同一端点（Key 区分） | K 位置位 + Key 值 | #10 `gre_key` |
| ⑥ 隧道质量探测（Sequence） | S 位置位 + 逐帧递增序号 | #8 `gre_sequence_multi` |
| ⑦ 校验和完整性（C 位） | C 位置位 + 算得校验和 | #9 `gre_checksum` |
| ⑧ 三键齐开（C+K+S） | 头 16B，选项顺序 C→R→K→S | #11 `gre_kcs_combo` |
| ⑨ 内层私网独立 TTL 规划 | 内层 ttl=60、外层 64 | #12 `gre_inner_ttl` |
| ⑩ 隧道外层打 VLAN tag（运营商接入） | 链首 vlan 层 → 802.1Q | #15 `gre_vlan_tagged` |
| ⑪ 隧道端点逐流变化（负载均衡） | 外层 ip.src 动态 + flows=2 | #16 `gre_outer_ip_dynamic`、#21 `gre_outer_ip_rand` |
| ⑫ 内层端口逐流变化（多租户复用） | 内层 udp.src_port / tcp.dst_port 动态 | #17、#18 |
| ⑬ 内层承载完整 TCP 会话（HTTP） | 内层 3 握手 + 2 数据 + 4 挥手 = 9 帧 | #8、#18 |

**五层覆盖逐层结论**：

| 层 | 结论 | 证据 |
|---|---|---|
| **功能** | GRE 基础头 + C/K/S 三旗标各自正例 + 三键组合 + 内外族四格 + VLAN；错误处理 5 类负例（配置错/静态复制/关字段动态/内层动态/内层混族），锚词驱动 | §9 表（14 正 + 7 负） |
| **性能** | 帧长边界：最小 = 内层空载荷单帧（存量无此例，A′ 候选）；最大 = 107B（`gre_kcs_combo`）；内层 TCP 链 9 帧序列；**跨 MSS 分段由内层 tcp 层承载**（GRE 层不做分段，如实声明）；无吞吐/并发/内存目标数字（**未测，不承诺**） | §6；`gre_kcs_combo` 107B 实测 |
| **数据场景** | 旗标位全组合（0x0000/0x8000/0x2000/0x1000/0xB000 五形已覆；0x4000 R 位**层内不可达** → A′）；Key 值域（0 与 0x12345678 两端，中间值无例）；Sequence 递增 0→8；内层端口动态 inc/list/rand；Protocol Type 0x0800/0x86DD 两值 | §9；§13 A′ |
| **地址与流** | **内外双 IP 族四格全覆**（§0.4）；单流基线 #1；多流 `flow_control flows=2` 五例；**流关联（控制流派生数据流）显式不适用**——GRE 是单帧封装，无派生连接；**多会话 `sessions[]` 显式不适用**——无长连接概念 | §0.4；§12.3 |
| **业务** | 13 场景全部有落点（上表）；**多事务**（内层 TCP 链 9 帧）已覆 #8/#18；**多流并发**五例 | 上表 |

**次要合法行为显式不适用声明（不设正例、亦不得进负例）**：① ARP-over-GRE 链上路径（`InnerRequired=["ip"]` 强制，§1 边界 1）；② R 位 Routing（层内无 `routing` 键，§8 G-GRE-1）；③ PPTP 增强 GRE（属 pptp 包）；④ 内层 TCP options 注入（链层无字段）；⑤ 内层 ICMP/ICMPv6（无链上终结层生成器）；⑥ IP 分片/重组（内层整包发出）。

## 5. 消息/事务模型与状态机

**事务定义**：GRE **无协议级事务**——没有请求/响应、没有握手、没有状态推进。一个"事务"就是**一次封装动作**：内层产 1 包 → GRE 包 1 帧。

| 场景 | 帧数 | 说明 |
|---|---:|---|
| 单帧封装（UDP/DNS 内层） | **1** | 内层 udp 层为每事件产 1 数据报；GRE 逐包封装 |
| 内层 TCP 链（HTTP） | **9** | 3 握手（SYN/SYN-ACK/ACK）+ 2 数据（GET + 200 OK，各带 ACK）+ 4 挥手（FIN/ACK/FIN/ACK）——**内层 tcp 层生成器的固定序列** |

**`gre` 层无自有状态机**：它是**纯函数式封装器**（逐包 in → 逐包 out）。唯一的跨帧状态是 `sequenceNum`（S 位置位时逐帧自增，`layer_gen.go:136-138`）与 `innerIPID`（内层 v4 包 ID 逐帧自增，`layer_gen.go:125`）。

**方向（Direction）**：`pkt.Direction` 由内层包透传（`layer_gen.go:140`）。down 帧的**内层地址交换**在 GRE 层做（`layer_gen.go:81-83`——"隧道层是内层地址的换向点"），外层地址交换在 `finalEmit` 做。存量 21 例**全为 up**（机读实测：无 down 例；down 由 legacy 单测 `TestPlanner_Direction_Down` 覆盖 → A′ 候选 §13）。

**自动派生规则**：

| # | 规则 | 行 |
|---:|---|---|
| 1 | `key` 缺省 0 → **不置 K 位** | `layer_gen.go:63/131` |
| 2 | `checksum` / `sequence` 缺省 false → 不置位 | `layer_gen.go:64-65` |
| 3 | `sequence` 置位时**基值恒 0**（链层无基值配置），逐帧 +1 | `layer_gen.go:68/136-138` |
| 4 | 内层 TTL 缺省 64（读内层 ip 层 ttl，0 回退） | `layer_gen.go:104-107` |
| 5 | 内层 IPID 从 0 起逐帧 +1（仅 v4 内层） | `layer_gen.go:67/125` |
| 6 | 内层 L4 协议由内层包的 `L4.Protocol` 决定（udp→17，否则 6） | `layer_gen.go:161-166` |
| 7 | GRE Protocol Type 由内层族决定（v6→0x86DD，v4→0x0800） | `layer_gen.go:115-124` |
| 8 | 外层 IP protocol **恒 47**（GRE 层写，`finalEmit` 不覆盖） | `layer_gen.go:145`；`chain_planner_translate.go:361-366` |
| 9 | 外层 TTL 取外层 ip 层 ttl（缺省 64），与内层独立 | `chain_planner_translate.go:355`；`chain_planner_gen.go:278-286` |
| 10 | 外层 EtherType 由外层源地址族推（v6→0x86DD） | `chain_planner_gen.go:231` |
| 11 | 链首 vlan 层 → 外层帧打 tag，**tag 落定在 finalEmit**（vlan 层是透传 wrapper） | `chain_planner_gen.go:230-243`；`chain_planner.go:459-469` |
| 12 | 内层包必须完整（内层 ip 层 → L4 → 终结层），由 V4 强制 | `complete.go:381-387` |

**多流展开（`flows=N`）**：由 worker 逐流驱动，**串行产出**（非交错）：第 i 条流用第 i 组动态值（`DefaultSrcPort + i` 保底，`worker.go:308`），每流独立 `FlowID`/`PacketIndex`。存量 5 例用 `flows=2`（§9）。

## 6. 性能设计与验收（CORE_MEMORY §6）

- **目标与边界**：单流单帧封装（UDP 内层）为最小路径；内层 TCP 链 9 帧为最长路径；**帧长上界由用户配置决定，无协议级硬上界**——最大实测 107B（`gre_kcs_combo`，GRE 头 16B）。**吞吐/并发/内存目标数字本版不写承诺**（未测，D-GRE-1/2/3 三条目均标"待确认"，本版沿此诚实口径）。
- **依据**：逐包流式封装（`layer_gen.go:69-156` 的 `for` 循环，`req.Inner` 通道逐包消费 → `req.Emit` 逐包写出，**无全量聚合**）；每帧内存 = 内层包长 + 外层头 + GRE 头；**无锁、无 sleep**（唯一跨帧状态是两个局部 `uint32` 计数器，单 goroutine 独占）；无跨流共享状态。
- **跨 MSS 分段**：**不在 GRE 层**——内层 tcp 层生成器按内层 MSS 分段（`generator.go` 的 TCPGenerator），GRE 只是把内层包**整包**封进载荷（`layer_gen.go:117-123`）。**内层 IP 分片不实现**（外层 DF 恒置位，内层 Flags 恒 DF）。
- **验收两路（§6.3 强制）**：pcap（`/tmp/mcp-pcaps/gre/`，正例 `<id>.pcap` / 负例 `<id>.neg.pcap`）与 NIC（`nic_capture` 开关）**共用同一断言集**。**本版实测一路**：21 例 pcap 逐条复算（18 条 frame 断言 + 37 条 field 断言 + 14 条 `min_packets`，§9 全绿；7 负例 pcap **0 帧**实测）。**NIC 一路本版未跑**（诚实声明，§1 输出契约）。
- **六类场景落点**：基线（#1，1 帧 95B）/ 目标规模（#8/#18，内层 TCP 链 9 帧）/ 压力上限（#11 最大帧 107B；无更大例 → A′ 候选）/ 长时间运行（**不适用**——GRE 无长连接，多帧由内层协议承载）/ 并发交错（**不适用**——逐流串行；多流由 worker 承载）/ 背压（`min_packets` 精确计数守卫帧数漂移 + builder 的长度守卫）。

## 7. 错误处理（负例锚词表，与 testcase §4 一一对应、同序）

以下输入必须被拒绝并传播为 task error，不得产出成功 PCAP、`completed/0 packet` 或只剩外层壳的假成功：

| # | 负例 ID | 故障输入 | 代码锚词 | 代码位置 | 拒绝阶段 |
|---:|---|---|---|---|---|
| N-1 | `gre_neg_flat` | 层链 + 顶层 `count`（旧扁平键混用） | `rejects flat config field count` | `strategy_convert.go:8632-8636` | 建策略期 400 |
| N-2 | `gre_neg_static_copy` | `flows=2` + 链上四元组全静态标量 | `static four-tuple` | `schema/semantic.go:285` | 建策略期 400 |
| N-3 | `gre_neg_dyn_key` | `gre{key: {strategy:"list",…}}` | `does not support dynamic` | `validate_layers.go:1004` | 建策略期 400 |
| N-4 | `gre_neg_inner_dyn` | 内层 `ip{src: {strategy:"list",…}}` | `inner ip layer does not support dynamic` | `validate_layers.go:1333`（**双侧**：`layer_dyn.go:121` worker 兜底） | 建策略期 400 + worker 侧 |
| N-5 | `gre_neg_inner_mixed` | 内层 `ip{src:"10.0.0.1", dst:"fd00::2"}`（异族） | `must be the same IP version` | `chain_planner.go:520-522` | 建策略期 400 |
| N-6 | `gre_neg_dyn_sequence` | `gre{sequence: {strategy:"list",…}}` | `does not support dynamic` | `validate_layers.go:1004` | 建策略期 400 |
| N-7 | `gre_neg_dyn_checksum` | `gre{checksum: {strategy:"list",…}}` | `does not support dynamic` | `validate_layers.go:1004` | 建策略期 400 |

**锚词口径**：`error_contains` 是**子串**判定；7/7 命中（本版机读核对，§9）。**负例原子性**：每例单一故障注入，单次执行不得混注（机读实测：7/7 负例 `spec_json` 只含该注入点）。**负例 expect 形状**：7/7 = 严格两键 `{expect_error, error_contains}`（机读实测，**无 `notes` 键**——比 opcua 的存量形状更干净）。

**为什么 N-3/N-6/N-7 是同锚词三例而非一例**：`gre` 层 3 键**全部关闭动态**（allowlist 无 `gre` 行，`layer_dyn.go:17-71` 实测无 `"gre"` 条目）。三键各建一例是**逐键覆盖**（一例只能证明一键被拒），符合"每字段一条"的原子原则。

**N-4 的双侧执法（须写清）**：内层 ip 层动态拒绝在**两处独立实现**——`ValidateLayers`（建策略期，`validate_layers.go:1333`）与 `parseLayerDyn`（worker 逐流解析期，`layer_dyn.go:121`）。后者是**兜底**（引擎直调绕过 ValidateLayers 时仍拒）。**两侧锚词逐字相同**，用例只断言子串，故两路都能命中。

**未入用例的拒绝分支（A′ 立项，不得冒充已覆盖）**：

| 分支 | 锚词 | 位置 |
|---|---|---|
| GRE 头骑在非 IP 外层上 | `gre: outer layer must be IP` | `builder.go:498-500` |
| 外层 IP protocol ≠ 47 | `gre: outer IP protocol must be 47` | `builder.go:502-504` |
| GRE 包带非空 L4Config | `gre: the inner packet is carried entirely in Payload` | `builder.go:506-508` |
| ProtocolType 不在白名单 | `gre: ProtocolType 0x%04x not in supported list` | `builder.go:517` |
| Routing 长度非法（<2 或奇数） | `gre: Routing field must be at least 2 bytes and a multiple of 2 bytes` | `builder.go:536-538` |
| GRE + PPPoE 组合 | `gre: cannot combine GRE with PPPoE` | `builder.go:493-495` |
| PPTP 模式 + C/R/K/S 组合（4 分支） | `gre: PPTP mode (RFC 2637 §4.1) …` | `builder.go:519-531` |
| legacy `Validate`：ProtocolType 枚举 | `gre: ProtocolType 0x%04x not in supported list` | `planner.go:56-61` |
| legacy `Validate`：ARP 矛盾 | `gre: ProtocolType 0x0806 (ARP) carries an ARP message` | `planner.go:88-94` |
| legacy `Validate`：内层 IP 版本与模式矛盾 | `gre: %s %q is IPv4 but ProtocolType 0x86DD requires an IPv6 inner packet` | `planner.go:129-134` |
| legacy `Validate`：InnerProto 枚举 | `gre: InnerProto %d not in supported list` | `planner.go:152` |
| legacy `Validate`：Frames < 0 | `gre: Frames %d must be >= 0` | `planner.go:156-158` |
| legacy `Validate`：Direction 枚举 | `gre: Direction %q not in supported list` | `planner.go:160-165` |
| 隧道链外层地址缺失 | `tunnel chain: outer ip addresses required` | `chain_planner.go:505-507` |
| 隧道链内层地址不可解析 | `tunnel chain: inner ip layer %s %q is not a valid IP address` | `chain_planner.go:515-518` |
| 内层非终结层收尾 | `must end with a terminal layer` | `complete.go:381-387` |
| 隧道层当末层 | `must end with a terminal layer, got %q (tunnel)` | `complete.go:383` |

**不得误报的合法协议事件**：多流（`flows=2`，5 例）；内外异族（`gre_6in4`/`gre_4in6`）；三键齐开（`gre_kcs_combo`）；VLAN tag（`gre_vlan_tagged`）；内层动态端口（`gre_inner_udp_dynamic`/`gre_inner_tcp_dynamic`）；外层动态地址（`gre_outer_ip_dynamic`/`gre_outer_ip_rand`）。

## 8. 边界

- **GRE 头长**：最小 **4B**（无旗标）；最大**实测 16B**（C+K+S 三键，`gre_kcs_combo`）；R 位可更长但**层内不可达**（§8 G-GRE-1）。
- **帧长**：实测区间 **95B**（`gre_basic_ipv4`）… **107B**（`gre_kcs_combo`）；内层 TCP 链帧长 **82/120/135B** 三档（`gre_sequence_multi` 实测，握手 82、GET 135、200 OK 120）。**无协议级帧长上界**——上界由内层载荷决定。
- **旗标位组合**：C/R/K/S 各可独立置位；**R 位层内不可达**；C+K+S 组合已覆；**C+R / K+R / S+R 组合今日无例且层内不可达**（R 无键）。
- **Key 值域**：uint32 全域；**`key == 0` 时不置 K 位**（本实现固定选择，§3.2）→ **层内无法表达"K 位置位且 Key=0"**；存量只覆盖 0 与 0x12345678 两端。
- **Sequence 值域**：uint32，链路径基值恒 0 逐帧 +1；存量覆盖 0→8（9 帧）。
- **Protocol Type**：只 0x0800 / 0x86DD 由内层族自动定；**0x0806(ARP) 链上不可达**；`0x6558`(TEB) 只在 builder 白名单（供 nvgre），**gre 层生成器不产**。
- **地址族**：内外四格全覆（§0.4）；**内层两地址异族拒**（N-5）；**外层两地址异族**今日无例（A′ 候选）。
- **端口**：GRE 无端口；内层端口住内层 `udp`/`tcp` 层；**缺省端口（dns 53 / http 80）今日无例**（A′ 候选）。
- **内层 VLAN / MPLS / PPP inner**：V7 结构性拒（不实现）。
- **不得产生回绕长度或超量分配**：GRE 头长由 `greHeaderLen` 一次算定；帧长由 builder 一次算定（`total = l2Len + l3Len + l4Len + len(payload)`）。

## 9. 原子 ID 与完成定义（21 个唯一语义 ID，顺序为权威）

**顺序 = `cases/gre.json` 数组顺序**（本表与 JSON 逐条对齐，机读实测）。

| # | ID | 类型 | 覆盖 | min_packets（实测帧数） |
|---:|---|---|---|---:|
| 1 | `gre_basic_ipv4` | 正 | §3.1/§3.4：4in4 基线，无旗标，proto 0x0800 | 1（95B） |
| 2 | `gre_neg_flat` | 负 | §7 N-1：顶层 `count` 判死 | —（0 帧） |
| 3 | `gre_neg_static_copy` | 负 | §7 N-2：flows=2 + 全静态标量 | —（0 帧） |
| 4 | `gre_neg_dyn_key` | 负 | §7 N-3：`key` 动态拒 | —（0 帧） |
| 5 | `gre_v6_in_v6` | 正 | §0.4 6in6：双 v6 + proto 0x86DD | 1（135B） |
| 6 | `gre_6in4` | 正 | §0.4 6in4：外层 v4 + 内层 v6 | 1（115B） |
| 7 | `gre_4in6` | 正 | §0.4 4in6：外层 v6 + 内层 v4 | 1（115B） |
| 8 | `gre_sequence_multi` | 正 | §3.2 D-4：S 位 + 逐帧序号 0→8；内层 TCP 链 9 帧 | 9（82/135/120B） |
| 9 | `gre_checksum` | 正 | §3.2 D-3 / §3.3：C 位 + 校验和 0xfb89 | 1（99B） |
| 10 | `gre_key` | 正 | §3.2 D-1：K 位 + Key 0x12345678 | 1（99B） |
| 11 | `gre_kcs_combo` | 正 | §3.2 D-6：C+K+S 齐开，flags 0xB000，头 16B | 1（107B） |
| 12 | `gre_inner_ttl` | 正 | §3.4/§3.7：内层 TTL 60 与外层 64 独立 | 1（95B） |
| 13 | `gre_neg_inner_dyn` | 负 | §7 N-4：内层 ip 动态拒（双侧执法） | —（0 帧） |
| 14 | `gre_neg_inner_mixed` | 负 | §7 N-5：内层异族拒 | —（0 帧） |
| 15 | `gre_vlan_tagged` | 正 | §3.7 步骤 5 / IEEE 802.1Q：链首 vlan → tag + 偏移 +4 | 1（99B） |
| 16 | `gre_outer_ip_dynamic` | 正 | §12：外层 ip.src list 双值 + flows=2 | 2（95B×2） |
| 17 | `gre_inner_udp_dynamic` | 正 | §12：内层 udp.src_port inc 41000-41001 + flows=2 | 2（95B×2） |
| 18 | `gre_inner_tcp_dynamic` | 正 | §12：内层 tcp.dst_port inc[80,8080 step8000] + flows=2 | 18（9×2） |
| 19 | `gre_neg_dyn_sequence` | 负 | §7 N-6：`sequence` 动态拒 | —（0 帧） |
| 20 | `gre_neg_dyn_checksum` | 负 | §7 N-7：`checksum` 动态拒 | —（0 帧） |
| 21 | `gre_outer_ip_rand` | 正 | §12：外层 ip.src rand(seed=7) + flows=2 | 2（95B×2） |

**T-编号对照**：`gre_basic_ipv4` ≡ T-GRE-1；`gre_neg_flat` ≡ T-GRE-2；`gre_neg_static_copy` ≡ T-GRE-3；`gre_neg_dyn_key` ≡ T-GRE-4；`gre_v6_in_v6` ≡ T-GRE-5；`gre_6in4` ≡ T-GRE-6；`gre_4in6` ≡ T-GRE-7；`gre_sequence_multi` ≡ T-GRE-8；`gre_checksum` ≡ T-GRE-9；`gre_key` ≡ T-GRE-10；`gre_kcs_combo` ≡ T-GRE-11；`gre_inner_ttl` ≡ T-GRE-12；`gre_neg_inner_dyn` ≡ T-GRE-13；`gre_neg_inner_mixed` ≡ T-GRE-14；`gre_vlan_tagged` ≡ T-GRE-15；`gre_outer_ip_dynamic` ≡ T-GRE-16；`gre_inner_udp_dynamic` ≡ T-GRE-17；`gre_inner_tcp_dynamic` ≡ T-GRE-18；`gre_neg_dyn_sequence` ≡ T-GRE-19；`gre_neg_dyn_checksum` ≡ T-GRE-22；`gre_outer_ip_rand` ≡ T-GRE-21。

**T-GRE-20 作废**（`docs/TEST_CASES.md:2235`）：原为"隧道内 dns 动态拒绝"，D-DNS-1 起 `dns.name` 动态合法 → 依据消亡，**编号保留作废注记、不复用**，用例替换为 `gre_neg_dyn_checksum`（T-GRE-22）。**故 21 例对应 22 个 T 编号（20 缺位）**。

### 9.1 本版实测复算（2026-09-29，全部 21 例）

**18 条 frame 断言逐条复算**：全部命中（`tshark -x` 取帧字节，按 `offset` 前缀比对）。**37 条 field 断言逐条复算**：全部命中（含 4 条 `distinct_values` 聚合断言）。**14 条 `min_packets` 逐例对账**：实测帧数 ≥ 声明值（**14/14 精确相等**）。

**关键实证摘要**：

| 用例 | 实测证据 |
|---|---|
| `gre_basic_ipv4` | 帧 95B；@34 `00 00 08 00`（GRE 头）；@58 `30 39 00 50`（内层 UDP）；`gre.flags.version=0`（Version 恒 0） |
| `gre_v6_in_v6` | 帧 135B；`eth.type=0x86dd`；`gre.proto=0x86dd`；`ipv6.version=6,6`（内外双 v6 同帧互证）；`ipv6.src=fd00::1,fd01::1`（内外分离） |
| `gre_6in4` | 帧 115B；`ip.version=4,6`（外层 v4 + 内层 v6）；`gre.proto=0x86dd`；`ipv6.src=fd01::1`（内层源，未被外层顶掉） |
| `gre_4in6` | 帧 115B；`eth.type=0x86dd`（外层 v6）；`gre.proto=0x0800`（内层 v4）；`ip.src=192.168.1.1` |
| `gre_sequence_multi` | 9 帧；`gre.flags_and_version=0x1000`；**`gre.sequence_number` = 0,1,2,3,4,5,6,7,8**（tshark 逐帧实测，`min_packets=9` 精确）；@38 帧 1 `00 00 00 00` / 帧 9 `00 00 00 08` |
| `gre_checksum` | `gre.checksum=0xfb89`，**本版独立复算 = 0xfb89**；`gre.checksum.status=1`（tshark 判 good） |
| `gre_key` | `gre.key=0x12345678`；`gre.flags.key=1`；@38 `12 34 56 78` |
| `gre_kcs_combo` | 帧 107B；`gre.flags_and_version=0xb000`；`gre.flags.checksum/key/sequence_number` = 1/1/1；`gre.key=0x12345678`；`gre.checksum=0x62dd`（**本版独立复算 = 0x62dd**）；@42 `12 34 56 78`（Key 在 Checksum 之后，顺序 C→K 实证） |
| `gre_inner_ttl` | `ip.ttl = 64,60`（外层先、内层后，两层同名字段）；@22 `40`（外层）/ @46 `3c`（内层） |
| `gre_vlan_tagged` | `vlan.id=100`/`vlan.priority=4`；@12 `81 00`（TPID）；@14 `80 64`（TCI = 4<<13\|100 = 0x8064）；@38 GRE 头（**偏移 +4 实证**） |
| `gre_outer_ip_dynamic` | `ip.src` distinct = `{10.0.0.1,192.168.1.1}` / `{10.0.0.2,192.168.1.1}`（**外层两值互异 + 内层恒 192.168.1.1**，内外分离在同名字段聚合里可见） |
| `gre_inner_udp_dynamic` | `udp.srcport` distinct = `{41000, 41001}` |
| `gre_inner_tcp_dynamic` | 18 帧（2×9）；`tcp.dstport` distinct = `{80, 8080}`（`distinct_exclude:["12345"]` 排掉客户端源端口） |
| `gre_outer_ip_rand` | `ip.src` distinct 同 `gre_outer_ip_dynamic`（seed=7 可复现） |

**7 负例 pcap**：`gre_neg_inner_mixed.neg.pcap` 实测 **0 帧**（其余 6 负例套件未落 .neg 文件——**本版只实测到这一例的落盘产物**，其余按"零包传播 task error"契约声明，A′ 待补，§13）。

**malformed / expert 扫描**：21 例 pcap 全部 `_ws.malformed` **0 命中**；`_ws.expert.message` 命中项**全为 tshark 会话级提示**（`Connection establish request (SYN)` / `GET / HTTP/1.1` / `DNS query retransmission`——后者因两流 DNS 同 txid，`gre_outer_ip_dynamic`/`gre_outer_ip_rand` 各 1 条），**无一条是帧缺陷**。`ip.checksum.status` / `udp.checksum.status` 全为 2（good），**无 ILLEGAL**。

## 10. P1 规范矩阵（CORE_MEMORY §4 八项：规范要求→业务场景→代码现状→缺口）

### 10.1 八项规范矩阵

| # | 八项 | 规范要求 | 业务场景 | 代码现状 | 缺口 |
|---|---|---|---|---|---|
| 1 | 连接模型 | GRE 无连接——封装在 IP 之上，无握手/状态（RFC 2784 §3 转发语义） | 场景①–⑬ | `DependsOn ["ip"]` 单值（`registry.go:1669`）；`CategoryTunnel` 强制包内层 | 无 |
| 2 | 命令/消息表 | 无命令——只有一种报文（GRE 封装帧）；变化维度 = 旗标位组合 × 内外族 | 场景①–⑧ | `writeGRE` 按 C/R/K/S 写头（`builder.go:825`）；族分派（`layer_gen.go:115-124`） | R 位层内不可达（G-GRE-1） |
| 3 | 状态机 | 无状态机（纯封装器） | — | `layer_gen.go` 无状态；跨帧状态仅 2 个局部计数器 | 无 |
| 4 | 字段表 | 基础头 2 字段 + 4 个可选字段（RFC 2784 §2 / RFC 2890 §2-3） | 数据场景层 | `writeGRE` 逐字段（`builder.go:857-891`）；`greHeaderLen` 长度公式（`:552`） | R 字段无层键（G-GRE-1） |
| 5 | 错误处理 | 7 类负例已覆（N-1…N-7）+ **未入例拒绝分支 17 行**（§7 表） | 负例 N-1…N-7 | 建策略期 5 行 + builder 7 行 + legacy Validate 6 行 + 结构 4 行（= 17 行） | A′ 17 行（§13 候选 14 条） |
| 6 | 超时与活性 | **不适用**——GRE 无超时/保活/重传概念（这些属于内层协议或隧道管理面） | — | 无 | **显式不适用** |
| 7 | NAT/代理/被动 | **不适用**——GRE 无角色概念（无主动/被动） | — | 无 `role` 字段；`Direction` 只有 up/down（`planner.go:160-165`） | **显式不适用**；NAT 穿透（GRE 常被 NAT 阻断）为部署面，非生成器面 |
| 8 | 版本/方言 | RFC 2784 基础头 vs RFC 2890 扩展（**本实现两者都支持**）；PPTP 增强 GRE 是第三方方言（属 pptp 包） | 场景⑤–⑧ | 旗标位 4 键（`builder.go:80-83`）；PPTP 分支（`:826-841`） | PPTP 属 pptp 协议（G-GRE-1 关联） |

### 10.2 子表①：旗标位 × 终态矩阵（逐格已覆/立项/不适用）

| 旗标位 | T1 正常终态 | T2 配置拒绝 | T3 RST/异常终态 |
|---|---|---|---|
| 无旗标（0x0000） | 已覆（#1/#5/#6/#7/#12/#15） | 已覆（#2/#3 代表例，拒绝与旗标无关） | **不适用**（GRE 无连接可中断） |
| C（0x8000） | 已覆（#9） | 同上代表已覆 | 不适用 |
| K（0x2000） | 已覆（#10） | 已覆（#4 同键动态拒） | 不适用 |
| S（0x1000） | 已覆（#8） | 已覆（#19 同键动态拒） | 不适用 |
| C+K+S（0xB000） | 已覆（#11） | 同上代表已覆 | 不适用 |
| R（0x4000） | **A′ 立项**（层内无 `routing` 键，G-GRE-1） | A′ 立项（builder 长度校验分支，§7） | 不适用 |

**逐格重数**：6 行 × 3 列 = 18 格——**已覆 10**（T1 列 5 + T2 列 5）/ **A′ 立项 2**（R 行 T1 + R 行 T2）/ **不适用 6**（T3 整列——GRE 无连接可中断）。10 + 2 + 6 = 18 ✓，**零空格**。

### 10.3 子表②：数据形态变体表（协议相关全部形态逐项）

| # | 变体 | 落点 |
|---:|---|---|
| 1 | 无旗标基础头（4B） | 覆（#1/#5/#6/#7/#12/#15） |
| 2 | C 位单独 | 覆（#9） |
| 3 | K 位单独 | 覆（#10） |
| 4 | S 位单独 | 覆（#8） |
| 5 | C+K+S 三键 | 覆（#11） |
| 6 | R 位 | **A′ 立项**（层内无 `routing` 键，G-GRE-1） |
| 7 | Key = 0 | 覆（#1 等 `gre:{}` 全例） |
| 8 | Key = 0x12345678 | 覆（#10/#11） |
| 9 | Key 中间值（如 0x00000001） | A′ 立项（值域中点，低价值） |
| 10 | Sequence 基值 0 + 递增 | 覆（#8 帧 1 = 0） |
| 11 | Sequence 递增至 8（9 帧） | 覆（#8 帧 9 = 8） |
| 12 | Protocol Type 0x0800 | 覆（#1/#4/#7/#9/#10/#11/#12/#15） |
| 13 | Protocol Type 0x86DD | 覆（#5/#6） |
| 14 | Protocol Type 0x0806（ARP）链上 | **明确不解决**（§1 边界 1；legacy 单测已覆字节） |
| 15 | 外层 IPv4 | 覆（#1/#6/#8–#12/#15–#18/#21） |
| 16 | 外层 IPv6 | 覆（#5/#7） |
| 17 | 内层 IPv4 | 覆（#1/#4/#7/#9–#12/#15–#18/#21） |
| 18 | 内层 IPv6 | 覆（#5/#6） |
| 19 | 内外同族 v4（4in4） | 覆（#1） |
| 20 | 内外同族 v6（6in6） | 覆（#5） |
| 21 | 内外异族（6in4 / 4in6） | 覆（#6/#7） |
| 22 | 内层两地址异族 | 覆（#14 负例） |
| 23 | 外层两地址异族 | A′ 立项（今日无例） |
| 24 | 内层 UDP 载荷（DNS） | 覆（#1/#5–#7/#9–#12/#15–#17/#21） |
| 25 | 内层 TCP 载荷（HTTP） | 覆（#8/#18） |
| 26 | 内层 ICMP / ICMPv6 | **明确不解决**（无链上终结层生成器） |
| 27 | 内层空载荷 | A′ 立项（最小帧边界） |
| 28 | 内层大载荷（跨 MSS） | 部分覆（#8/#18 的 135B GET；**无跨 MSS 分段例** → A′） |
| 29 | 内层 TTL 缺省 64 | 覆（除 #12 外全部） |
| 30 | 内层 TTL 显式（60） | 覆（#12） |
| 31 | 内层 IPID 递增 | 覆（隐式：v4 内层全例；**无逐帧 IDID 断言** → A′） |
| 32 | 外层 VLAN tag | 覆（#15） |
| 33 | 内层 VLAN / MPLS | **明确不解决**（V7 结构性拒） |
| 34 | 内层 TCP options | **明确不解决**（链层无字段，§1 边界 4） |
| 35 | 方向 down | A′ 立项（21 例全 up；legacy 单测覆盖） |
| 36 | 多流（flows=2） | 覆（#16–#18/#21） |
| 37 | 缺省端口（dns 53 / http 80） | A′ 立项（21 例全显式写端口） |
| 38 | 帧 padding（<60B 短帧） | **不适用**（存量帧长 82B 起，恒超 60B；padding 逻辑在 builder 但 gre 链不触发） |

**逐格重数**：38 行——**覆 27** + **A′ 立项 6**（行 6/9/23/27/35/37）+ **明确不解决 4**（行 14/26/33/34）+ **不适用 1**（行 38）= 38 ✓。**无"明确不解决"行被计为已覆**（D-GRE-1 §14 边界 1/5 的两项 ARP 与 ICMP 内层在此表显式归"明确不解决"，§1 边界 2/3/4 的 Routing/PPTP/TCPOptions 分别落在行 6/33/34 与 §0.3 表）。

### 10.4 子表③：商业行为→用例映射表

| # | 商业行为（出处） | 用例映射 | 结论 |
|---:|---|---|---|
| 1 | 站点间 GRE 隧道（4in4） | #1 | 已覆 |
| 2 | 纯 v6 骨干隧道 | #5 | 已覆 |
| 3 | v6 孤岛穿越 v4 骨干（6in4） | #6 | 已覆 |
| 4 | v4 孤岛穿越 v6 骨干（4in6） | #7 | 已覆 |
| 5 | 多隧道复用同一端点（Key 区分，RFC 2890 §3） | #10 | 已覆（**结构路径**；Key 语义不声称） |
| 6 | 隧道质量探测（Sequence 丢包检测，RFC 2890 §4） | #8 | 已覆 |
| 7 | 校验和完整性（C 位） | #9 | 已覆 |
| 8 | 运营商接入外层 VLAN tag | #15 | 已覆 |
| 9 | 隧道端点负载均衡（外层地址逐流变） | #16/#21 | 已覆 |
| 10 | 多租户端口复用（内层端口逐流变） | #17/#18 | 已覆 |
| 11 | 内层承载完整 TCP 会话（HTTP over GRE） | #8/#18 | 已覆 |
| 12 | 真实隧道管理面（Keepalive/路由协议 over GRE） | — | **明确不解决**（管理面协议属其它层，如 [ip,gre,ip,ospf] 今日未建） |
| 13 | GRE over IPsec（加密隧道） | — | **明确不解决**（IPsec 属其它层） |
| 14 | GRE 隧道分片与 MTU 发现 | — | **明确不解决**（§1 边界 6） |
| 15 | ERSPAN / WCCP 等 GRE 方言 | — | **明确不解决**（第三方方言，属各自协议） |

**10 覆 + 5 明确不解决 = 15 ✓**，零缺口（「明确不解决」按 §5.2 口径单列一栏，不并入「不适用」）。

### 10.5 三路对照与候选方案对比（§4.12–4.17）

**三路**：
1. **规范原文**：RFC 2784（基础头 + 校验和算法）、RFC 2890（Key/Sequence 扩展）——定"必须是什么"。本版用 RFC 2784 §3.1 的校验和算法**独立复算**了存量两例（§3.3），两例吻合 → 实现与规范一致。
2. **商业化软件实际行为**：**未取到**（未抓真实路由器/云厂商 GRE 隧道的线字节对照）→ **G-GRE-6 待确认**。
3. **可靠开源实现思路**：**未取到**（未核对 Linux 内核 `net/ipv4/gre_demux.c` / `ip_gre.c` 的 GRE 头布局）→ **G-GRE-6 待确认**。

**三路一致点**：GRE 基础头 4B（Flags+Version 2B + Protocol Type 2B 大端）、可选字段 4B 粒度、C→R→K→S 顺序、协议号 47——本版实测与 RFC 一致。
**不一致点**：无（第三路未取到，不构成不一致，只构成**未确认**）。

| 方案 | 走法（借鉴来源） | 取舍 | 结论 |
|---|---|---|---|
| A | **独立 `gre` 隧道层**（本版；与 tls 同属 `CategoryTunnel`） | 内外双 IP 族、旗标位组合、内层包字节可声明可断言；代价 = 一套层（已落码 762 行 + 接线） | **采用** |
| B | 复用 legacy flat planner（顶层 `gre` 子映射） | 无层链组合能力（外层 VLAN、外层动态、内层 tcp 链不可表达）；且顶层子映射已在判死方向上 | **否决**（D-GRE-1 已翻转） |
| C | 拆成"GRE 外层层 + 内层层"两层 | 内外地址/族/端口的配对需跨层状态传递，框架层间无此通道（opcua 方案 C 同款否决理由） | **否决**（状态在单层局部变量，单层内聚更简单） |
| D | 复用 nvgre 的"生成器自写外层 IP"走法 | nvgre 内层是裸 Ethernet 帧；GRE 内层是完整 IP 包——复用会把 GRE 的族分派/TTL/IPID 逻辑塞进 nvgre 形状，语义错位 | **否决**（`registry.go:1688-1694` 已记该分歧） |

## 11. P2 D-GRE-1/2/3 as-built 代码设计（CORE_MEMORY §8 八要素）

> 状态说明：实现已落码，本 P2 条目为**逆向定稿**（as-built），供门1 批准后作为后续改动的唯一入口。

### 11.1 文件清单（实测，非计划）

| 文件 | 职责 | 行数 |
|---|---|---:|
| `trafficgen/internal/protocol/gre/layer_gen.go` | 隧道层生成器 `GREGenerator`（`Generate` 逐包封装 + `innerProtoFor` + 配置读取 + `validateGRESpec` + `init` 注册） | 208 |
| `trafficgen/internal/protocol/gre/planner.go` | legacy planner（`Validate` 6 分支 + `Plan` + 内层包构造 `buildInnerIPv4Packet`/`buildInnerIPv6Packet`/`buildInnerL4`/`buildARPMessage` + `ipChecksum16`/`l4Checksum`） | 554 |
| `trafficgen/internal/protocol/gre/planner_test.go` | 10 个 `Test*`（legacy 编码面：ARP/DNS/HTTP 校验和/Key/Sequence/Checksum 奇数长/Direction down/IPv6/Validate/EndToEnd） | 827 |
| `trafficgen/internal/protocol/gre/layer_validate_test.go` | 3 个 `Test*`（`FlatRejected` / `NilTolerant` / `KeyDynamicRejected`） | 63 |
| `trafficgen/internal/core/types.go`（`:3196-3250`） | `GREConfig`（14 字段，§11.3） | —（共享文件） |
| `trafficgen/internal/core/builder.go`（`:73-83`/`:492-573`/`:825-891`/`:895-`） | 常量 + `validateGREConfig` + `greHeaderLen` + `writeGRE` + `fillGREChecksum` | —（共享文件） |
| 接线 5 件 | registry 注册（`layers/registry.go:1668`）/ protocols 准入（`core/protocols.go:40`）/ ChainPlanner 翻转（`cmd/server/main.go:589`）/ 隧道结构校验（`layers/chain_planner.go:486-523`）/ 层内动态拒绝（`layers/validate_layers.go:1326-1334`） | — |

**旁证测试（非 gre 包，但覆盖 gre 行为）**：`internal/core/layers/gre_v6_test.go`（6 个 Test：`InnerScalarRespected`/`V6InV6`/`InnerMixedFamilyRejected`/`InnerTTLOverride`/`InnerDynRejected`/`V4InV6`）、`gre_vlan_tunnel_test.go`（3 个）、`gre_seq_unit_test.go`（1 个）、`t12_gre_test.go`（10 个）、`chain_planner.go` 结构校验。

### 11.2 接口签名

- `func (g *GREGenerator) Generate(ctx context.Context, req *layers.GenRequest) error`（`layer_gen.go:49`）：**wrapper 型**——从 `req.Inner` 逐包消费，逐包 `req.Emit` 写出。三条前置守卫：`req.Inner == nil` → `gre is a tunnel layer and requires an inner chain`；`req.Emit == nil` → `requires an outer chain`；`req.Layer.Name != "gre"` → 名称不符。
- `func (g *GREGenerator) GenEvents() layers.EventGenerator`（`:46`）：**恒 nil**（gre 是隧道层，不产报文事件）。
- `func (g *GREGenerator) Name() string`：`"gre"`。
- `func validateGRESpec(spec *core.FlowSpec) error`（`:203`）：**nil 容忍**——`spec.GRE == nil` → `nil`（纯层链合法态，链上不读 flat）；非 nil → `(&Planner{}).Validate(*spec)` 全量校验（在库旧策略启动期语义与 legacy 一致）。
- legacy：`func (p *Planner) Validate(spec core.FlowSpec) error`（`planner.go:50`）、`func (p *Planner) Plan(ctx, spec) (<-chan core.PacketConfig, error)`（`:177`）。

### 11.3 数据结构

**层内配置（今日唯一权威，3 键）**：`map[string]interface{}{"key": uint32, "checksum": bool, "sequence": bool}`——由 registry `Fields`（`registry.go:1672-1676`）约束，V9 保证类型合法；生成器经 `greConfigUint32`/`greConfigBool` 读取（`layer_gen.go:170-184`，**防御性转换**：JSON 数字以 float64 到达）。

**wire 配置**：`core.GREConfig`（`types.go:3196-3301`）**21 字段**——`ProtocolType uint16` / `Checksum bool` / `KeyPresent bool` / `Key uint32` / `SequencePresent bool` / `Sequence uint32` / `RoutingPresent bool` / `Routing []byte` / PPTP 组（`PPTP`/`AckPresent`/`CallID`/`Ack`）+ legacy 组（`InnerSrcIP`/`InnerDstIP`/`InnerProto`/`InnerTTL`/`InnerIPID`/`InnerPayload`/`Frames`/`Direction`/`TCPOptions`）。**链路径只填 6 个**（`ProtocolType`/`Checksum`/`KeyPresent`/`Key`/`SequencePresent`/`Sequence`，`layer_gen.go:128-135`），其余 15 个（Routing 2 + PPTP 组 4 + legacy 组 9）留给 legacy flat 路径。

### 11.4 主流程

层链配置 → `ValidateLayers`（registry Fields 3 键 allowlist + 内层动态拒绝 + 隧道结构校验）→ translate（**无 `case "gre"`**——层 config 由生成器直读，不经 spec 中转）→ `ChainPlanner.Plan` → `applySpecToChain`（spec 值注入各层 config）→ 逐层 goroutine 级联（外层 ip ← gre ← 内层 ip ← tcp/udp ← 终结层）→ `finalEmit`（L2 重建 + GRE 恢复 + 方向交换 + TTL）→ builder（`writeL3` 外层 IP → `writeGRE` GRE 头 → `copy` 内层字节 → `fillGREChecksum`）→ worker（多流 + 限速）→ writer（PCAP/NIC）。

### 11.5 错误分支

**建策略期（400）**：5 门——`CheckProtoFlat`（顶层五键 + ftp/http/dns/… 子映射，`strategy_convert.go:8625-8636` 起）/ `checkLayerChainStaticCopy`（`schema/semantic.go:285`）/ `checkLayerDynObjects`（`validate_layers.go:1004`）/ 内层 ip 动态（`validate_layers.go:1333`）/ 隧道结构校验（`chain_planner.go:505-522`）。
**builder 期**：**7 行**（`validateGREConfig`，`builder.go:492-540`：PPPoE 组合 / 外层非 IP / proto≠47 / L4 非空 / ProtocolType 白名单 / Routing 长度 / PPTP 组合（该行 4 子分支））。
**legacy Validate 期**：**6 行**（`planner.go:50-167`：ProtocolType 枚举 / ARP 矛盾 / 内层地址解析 / 内层族一致 / InnerProto 枚举 / Frames≥0 / Direction 枚举 —— 该 6 行对应 **13 个 return 点**，grep 实测）
**隧道结构期**：**4 行**（`chain_planner.go:505-522` 外层缺失 + 内层不可解析；`complete.go:381-387` 内层非终结层 + 隧道当末层）。
全部传 task error（零假成功——负例实测 0 帧）。

### 11.6 性能边界

见 §6：逐包流式、无锁无 sleep、无全量聚合；吞吐数字不承诺。

### 11.7 与现有逻辑的冲突点 / 死配置

| 项 | 事实 | 处置 |
|---|---|---|
| **`FieldContract {"ip.protocol":"47"}` 是死配置** | 唯一消费者 `fieldContractDstPort`（`chain_planner_util.go:291-308`）**只解析 `tcp.dst_port`/`udp.dst_port` 两键**（grep 实测：`"ip.protocol"` 全仓仅出现在 5 处 registry 声明，**零消费者**）；真正写 47 的是 `GREGenerator`（`layer_gen.go:145`）。同款死配置见 igmp/ospf/pim/icmp/icmpv6 五行 | **G-GRE-2 登记**（声明性契约，不改代码；若框架将来实现 `ip.protocol` 契约执行，gre 的声明即自动生效） |
| **`translate` 无 `case "gre"`** | `chain_planner_translate.go` 的层内 switch 无 gre 分支——**不是缺陷**：gre 层 config 由生成器 `req.Layer.Config` 直读（`layer_gen.go:62`），不经 spec 中转（`spec.GRE` 在链路径恒 nil） | 无缺口（**如实记录为设计选择**） |
| **legacy flat 与链路径混用** | 策略同时给顶层 `gre` 子映射（填 `spec.GRE`）与 gre 层链时，**flat 静默忽略**（`layer_gen.go:35-38` 声明） | **G-GRE-3 登记**（flat 已判死方向，实际不可达；若可达则静默忽略是缺陷候选） |
| **`ValidateLayers` 与 `parseLayerDyn` 双侧实现内层动态拒绝** | 两处独立代码、锚词逐字相同（`validate_layers.go:1333` / `layer_dyn.go:121`） | 无缺口（**双保险是设计意图**，注释明写"引擎直调绕过 ValidateLayers 时此处兜底"） |
| **`GREConfig` 21 字段 vs 层 3 键** | 15 个字段（Routing 2 + PPTP 组 4 + legacy 组 9）层内无住处 | **G-GRE-1 登记**（Routing 有 builder 支持但无层键；PPTP 组属 pptp 包；legacy 组是 flat 路径遗存） |

### 11.8 回滚方式

本协议文件独立成包，回滚 = revert `internal/protocol/gre/` 四文件 + 接线 5 处（registry/protocols/main.go/chain_planner/validate_layers）；不触及其他协议。cases 回滚 = 恢复 21 例 JSON（产物文件，非文档）。

## 12. 门1 §1–§14 十四行对照表（CORE_MEMORY §15.1–15.3）

| § | 本协议怎么满足 | 证据 |
|---|---|---|
| §1 层链唯一真相 | 见 §12.1 强制展开：**非负例 14/14 顶层零残留**（20/20 例顶层键 ⊆ `{layers}`；唯一例外是负例 `gre_neg_flat` 的顶层 `count` = 判死对象本身）；目标形状见 §2 且**存量已达标**（本协议无迁移工作量） | §12.1；`cases/gre.json` 机读实测 |
| §2 策略/任务 | 策略 = 单 gre 隧道模板（层链 + 旗标位）；任务 = 多策略合跑 + 总量封顶；框架语义未动 | 设计 §2 样例 |
| §3 五件套 | 见 §12.3 强制展开：会话表（单帧封装，**无 sessions[]——显式豁免**）/事务序列（1 帧或内层 9 帧）/关联关系（**无派生流，显式声明**）/插入位置（隧道层，链中间）/时间线（同步顺序，无交错）。**豁免理由已写清**（§12.3） | §12.3 + §5 |
| §4 查规范 | RFC 2784 + RFC 2890 + RFC 2473（§4 矩阵）+ IEEE 802.1Q §3 + tshark 3.6.14 字段与 21 例 pcap 实测 + 落码反推；八项矩阵 + 子表①②③ + 三路对照 + 方案对比 | §10 |
| §5 依赖与错误 | `DependsOn ["ip"]` + `InnerRequired ["ip"]`（`registry.go:1669-1671`）；7 类负例 + 未入例拒绝分支 17 行（§7 表）；失败传 task error（负例 0 帧实测） | §7/§11.5 |
| §6 性能 | 见 §6（六要素齐；吞吐数字标"未测不承诺"；pcap/NIC 两路契约明写，**NIC 未跑如实声明**） | §6 |
| §7 三份文档 | `113-gre-{design,testcase}.md` v1.0.0（本版）+ D-GRE-1/2/3（`docs/CODE_DESIGN.md:752/835/963`，历史层）+ T-GRE-1…22（`docs/TEST_CASES.md:1948-2490`，含 T-GRE-20 作废注记） | 修订记录 |
| §8 设计先行 | D-GRE-1 → D-GRE-2 → D-GRE-3 三阶段先后落码（提交 `62907e0` → `1af8481` → `f268c72`），每阶段先设计后代码 | `git log` |
| §9 测试三源 | 三源 = RFC 2784/2890 + D-GRE-1/2/3 + tshark 3.6.14 字段与 **21 例 pcap 实测**（**已到抓包级**：18 条 frame + 37 条 field 断言逐条复算 OK，§9.1）；21 ID 逐项回指；存量审计 testcase §8 | `113-gre-testcase.md` §2/§5/§8 |
| §10 评审闭环 | D-GRE-1/2/3 三条目各有"完成回填"段（含 P6 验收记录）；本版为文档轨自审（自审轮次见修订记录） | `docs/CODE_DESIGN.md:764/857/…` |
| §11 白话 | 每阶段白话一句先行（见本文首节 + §0 各条） | 汇报 |
| §12 动态清单 | 见 §12.12 强制展开：四元组外层全开 / **内层 ip 三键全关**（双侧执法）/ gre 业务 3 键全关 + 理由；序号算法实读行号 | §12.12 |
| §13 schema 派生 | `gre` 已在 `registry.go:1668` 注册（**不新增层**）；生成表 `schemas/v1/generated/layers.generated.json` 的 gre 条目与 registry **逐键一致**（机读实测：`category=tunnel`/`depends_on=[ip]`/`inner_required=[ip]`/`field_contract={ip.protocol:47}`/`fields` 3 键同默认值；全表 127 层）；**P4 若改 registry Fields 必须重跑 schemagen** | §11.1；生成表机读 |
| §14 真实流程 | suite 经 MCP 建策略建任务 → 引擎真实生成 → tshark `gre.*` + frames 双通道 → 先跑后钉；pcap 落 `/tmp/mcp-pcaps/gre/` | testcase §7 |

### 12.1 §1 强制展开：旧键去向 + 完整 spec_json 样例

**存量实测（逐例机读，2026-09-29）**：

| 文件 | 例数 | `spec_json` 顶层键分布 | 链形 | 负例 expect 形状 |
|---|---|---|---|---|
| `cases/gre.json` | 21 | **`{layers}` ×20** + `{layers, count}` ×1（那 1 例是 `gre_neg_flat`，`count` 即判死对象） | `[ip,gre,ip,udp,dns]` ×18 + `[ip,gre,ip,tcp,http]` ×2 + `[vlan,ip,gre,ip,udp,dns]` ×1 | 7/7 = `{expect_error, error_contains}`（**严格两键，无 `notes`**） |

**旧键去向表（§15.3 要求"每个键写去向"）**：

| 旧键 | 存量出现例数 | 去向 |
|---|---:|---|
| `src_ip` | **0** | 本协议**从未用过顶层地址**；地址住 `layers[i].ip.{src,dst}`（外层与内层各一） |
| `dst_ip` | **0** | 同上 |
| `src_port` | **0** | 从未用过；端口住 `layers[i].udp.src_port` / `layers[i].tcp.src_port` |
| `dst_port` | **0** | 从未用过；端口住 `layers[i].udp.dst_port` / `layers[i].tcp.dst_port` |
| `count` | **1**（`gre_neg_flat`，负例） | **判死对象本身**——`CheckProtoFlat` 命中即 400（锚词 `rejects flat config field count`）；数量正确住处 = `flow_control` |
| 顶层 `gre` 子映射 | **0** | 从未用过；GRE 配置住 `layers[i].gre`（3 键） |
| `strategy_fc`（用例级） | 5（非 `spec_json` 键） | **用例文件的 harness 字段**，不是 spec 键——`test/protocol_pcap` 驱动读它构造 `flow_control{"type":"flows","value":N}`（`pcaptest/types.go:80-84` StrategyFC）。**不在 §1 白名单违规之列** |

**结论**：**本协议非负例 14/14 顶层零残留**（20/20 例顶层键 ⊆ `{layers}`）——§1 门的动作 = ①**无旧键可删**；②收官自查行「非负例顶层键 = 0」**今日即成立**（机读实测）；③A′ 新增例全部沿用纯 layers 形。

**目标形状 spec_json 样例**：见 §2（顶层仅 `layers`）。

### 12-P2 判死负例形状（链级红例必含清单①③④）

- ① **presence 形状** `{"layers":[…],"gre":{}}` 今日**不会被拒**（`CheckProtoFlat` **无 gre 分支**，`grep -c 'protocol == "gre"' strategy_convert.go` = **0** 实测）→ **不建该负例**（建了会真绿 = 假通过）→ 缺口 **G-GRE-4** 登记。
- ② 白名单外游离顶层键判死（`unknown field`）今日**亦无通用门**（`CheckProtoFlat` 只查五键 + 各协议子映射白名单）→ 同 G-GRE-4。
- ③ 7 负例每条带锚词（已齐，§7）。
- ④ 收官自查「非负例顶层键 = 0」**今日已成立**（§12.1）。

### 12.3 §3 强制展开：五件套

| 件 | 本协议内容 | 豁免/声明 |
|---|---|---|
| **会话表** | `s1` 单隧道（全部 21 例）——**无 `sessions[]`**：GRE 无连接概念，一个策略 = 一条隧道 | **显式豁免**，理由：GRE 是 IP 之上的**无连接封装**（RFC 2784 §3），没有会话建立/拆除，`sessions[]` 无对应语义。多流由 `flow_control{"flows":N}` 承载（5 例） |
| **事务序列** | 单帧封装 = 1 次封装动作；内层 TCP 链 = 内层 tcp 层生成器的固定 9 帧序列（3 握手 + 2 数据 + 4 挥手） | 已覆 #1（1 帧）/#8/#18（9 帧） |
| **关联关系** | **无派生流**——GRE 不派生任何子连接（封装 ≠ 派生；对比 FTP 控制流→数据流） | **显式声明**：无 `driven_by` 字段，无父子流 ID |
| **插入位置** | **隧道层**——链上夹在**外层 ip** 与**内层 ip** 之间（`[ip, gre, ip, …]`）；`InnerRequired ["ip"]` 保证内层从 ip 起头 | `registry.go:1668-1671` |
| **时间线** | **同步顺序产出，无交错**——`layer_gen.go` 单 goroutine 逐包消费 `req.Inner` 并逐包 `req.Emit`；多流由 worker 逐流串行驱动（非交错） | `layer_gen.go:69-156`；`concurrent` 为例外路径，本协议不启用 |

**§3.14 豁免边界核对**：**无长连接协议**（GRE 无连接）→ 豁免 `sessions[]` ✓；但 **§3.14 明写"豁免 `sessions[]` 不等于豁免多流覆盖"**——多流已覆（5 例，§9 #16–#18/#21）；**单包多载荷** = **不适用**（GRE 一帧恰一个内层包，无多 question/多 RR 类形态，如实声明）。

**§3.15 三项核对**：① **同连接/同流内的多轮操作** = 内层 TCP 链 9 帧（#8/#18）已覆；② **非正常结束** = **不适用**（GRE 无连接可异常中断；内层 TCP 的 RST 由内层 tcp 层承载，本层零断言 → A′ 候选 §13）；③ **长保活** = **不适用**（GRE 无保活概念）。**无空项**：① 有例；② 显式不适用；③ 显式不适用。

### 12.12 §12 强制展开：动态字段清单与序号算法

**四元组**（`layerDynAllowlist`，`layer_dyn.go:17-71`）：

| 层 | 字段 | 开/关 | 理由 | 用例 |
|---|---|---|---|---|
| 外层 `ip`（链上第一个） | `src` / `dst` / `ttl` | **全开** | 隧道端点逐流变是现网常态（负载均衡/多端点）；allowlist `"ip": {"src","dst","ttl"}` 通用条目 | #16（list）/ #21（rand seed=7） |
| 内层 `ip`（链上第二个） | `src` / `dst` / `ttl` | **全关** | **单四元组模型**：`LayerDynValues` 只有一套 ip 值，双层动态会**静默打架**（外层对象被内层顶掉，D-GRE-2 探针 C 实锤）→ 双侧拒绝，锚词 `inner ip layer does not support dynamic` | #13（负例） |
| 内层 `udp` | `src_port` / `dst_port` | **全开** | UDP 端口通用条目（多租户复用） | #17（inc 41000-41001） |
| 内层 `tcp` | `src_port` / `dst_port` | **全开** | TCP 端口通用条目 | #18（inc[80,8080] step 8000） |
| `eth` | `src_mac` / `dst_mac` | **全开**（allowlist 有） | 通用条目；存量 gre 例未用 | 无例（A′） |

**业务字段**（`gre` 层 3 键）：

| 字段 | 开/关 | 理由 |
|---|---|---|
| `key` | **关** | 隧道标识常量——逐流变 = 不同隧道，应拆不同策略；且 `key != 0` 才置 K 位，动态化语义歧义（D-GRE-1 §12） |
| `checksum` | **关** | 布尔开关语义，逐流变无意义（D-GRE-1 §12） |
| `sequence` | **关** | 布尔开关语义，同上（D-GRE-1 §12） |

三键各有一条负例（#4 / #19 / #20），锚词统一 `does not support dynamic`（`validate_layers.go:1004`，`LayerDynAllowlisted("gre", …)` 恒 false——allowlist **无 `gre` 行**，机读实测 `layer_dyn.go:17-71` 无 `"gre"` 条目）。

**序号算法实读行号**：

| 算法 | 位置 |
|---|---|
| 层内动态对象解析 | `parseLayerDyn`（`layer_dyn.go:78`） |
| 四元组按流序号取值 | `TupleGenerator.Next(index)`（`tuple_generator.go:26`） |
| worker 逐流驱动 + 保底源端口 | `worker.go:308`（`spec.SrcPort = DefaultSrcPort + uint16(i)`；`DefaultSrcPort = 12345`，`strategy_convert.go:49`） |
| allowlist 白名单（动态开关唯一真相） | `layer_dyn.go:17-71` + `LayerDynAllowlisted`（`layer_dyn.go:1051`） |
| **GRE Sequence 逐帧递增**（本协议自有序号） | `layer_gen.go:67/136-138`（`sequenceNum` 从 0 起，置位时每帧 +1） |
| **内层 IPID 逐帧递增**（本协议自有序号） | `layer_gen.go:67/125`（`innerIPID` 从 0 起，v4 内层每帧 +1） |

**关键声明**：GRE 的两个自有序号（Sequence / IPID）是**帧级**递增，不是**流级**——`flows=2` 时**每条流的 Sequence 都从 0 重新起算**（生成器每流独立实例化，`sequenceNum` 是 `Generate` 的局部变量）。存量 `gre_sequence_multi` 是单流 9 帧（0→8），**无多流序号隔离例** → A′ 候选（§13）。

## 13. P3 对接清单（T-GRE 草稿输入；正文落 testcase 文件）

21 ID（14 正 + 7 负）+ `min_packets`/锚词 + fixture 常量 + 双通道断言基线 + 存量审计（testcase §2–§5/§8 全量）。

**A′ 候选例（P4 补，按价值排序）**：

| # | 候选 ID | 覆盖 | 缺口 |
|---:|---|---|---|
| 1 | `gre_routing_option` | R 位置位 + Routing 数据 | G-GRE-1（需先补 registry `routing` 键） |
| 2 | `gre_key_zero_k_bit` | K 位置位且 Key=0（当前不可表达） | G-GRE-1 |
| 3 | `gre_neg_outer_mixed` | 外层两地址异族拒 | §10.3 行 23 |
| 4 | `gre_default_port` | 内层端口缺省（dns 53 / http 80） | §8 |
| 5 | `gre_neg_routing_len` | Routing 长度 <2 或奇数拒 | §7 |
| 6 | `gre_neg_inner_not_terminal` | 裸 `[ip,gre,ip,udp]` 拒 | §7 |
| 7 | `gre_down_frame` | 方向 down（内外地址双交换） | §10.3 行 35 |
| 8 | `gre_multiflow_sequence_isolation` | flows=2 + S 位 → 两流序号各自从 0 起 | §12.12 |
| 9 | `gre_inner_ipid_increment` | 逐帧内层 IPID 递增断言 | §10.3 行 31 |
| 10 | `gre_min_frame` | 内层空载荷最小帧 | §10.3 行 27 |
| 11 | `gre_inner_icmp` | 内层 ICMP/ICMPv6 | §1 边界 5（需先有链上终结层） |
| 12 | `gre_neg_pppoe_combo` | GRE + PPPoE 组合拒 | §7 |
| 13 | `gre_neg_bad_outer_proto` | 外层 protocol ≠ 47 拒 | §7 |
| 14 | `gre_presence_top_level_gre` | 顶层 `gre` 子映射判死 | G-GRE-4（**需先有框架门**，今日建了假绿） |

**B′（框架面）**：`CheckProtoFlat` gre presence 分支 + 游离顶层键通用门（G-GRE-4）/ `ip.protocol` FieldContract 消费者（G-GRE-2）/ 业务字段动态（G-GRE-5）。

## 14. 缺口立项清单（有缺口写「缺口立项」，不许空着）

| 缺口 | 内容 | 三要素（现象/证据/归属阶段） | 去向 |
|---|---|---|---|
| **G-GRE-1** | **层内无 `routing` 键**（R 位）——`GREConfig.RoutingPresent/Routing`（`types.go:3229-3230`）与 builder R 分支（`builder.go:868-874`）+ 长度校验（`:536-538`）均已落码，但 registry `Fields` 只有 key/checksum/sequence 3 键 → **层内不可达**；同理 ARP-over-GRE（`InnerRequired=["ip"]` 强制内层 ip）、PPTP 增强 GRE（属 pptp 包）、内层 TCP options（链层无字段）今日均无链上入口 | 现象：R 位/ARP 内层/内层 TCP options 层内不可表达；证据：`registry.go:1672-1676`（3 键）+ `builder.go:868-874`（有 R 分支）+ `layer_gen.go:33-34`（注释声明 TCPOptions 不注入）；阶段：**代码阶段** | P4 裁定：补 `routing` 键（含 V9 边界与动态开关）或**明确不解决**并保持 §1 边界声明；ARP/PPTP/TCPOptions 建议明确不解决（各有其它住处） |
| **G-GRE-2** | **`FieldContract {"ip.protocol":"47"}` 是死配置**——唯一消费者 `fieldContractDstPort`（`chain_planner_util.go:291-308`）只解析 `tcp.dst_port`/`udp.dst_port`；`"ip.protocol"` 全仓 5 处声明（igmp/ospf/pim/icmp/icmpv6/gre）**零消费者**（grep 实测）；真正写 47 的是 `GREGenerator`（`layer_gen.go:145`） | 现象：契约声明与实际执行者不一致（声明性 vs 命令式）；证据：`grep -rn '"ip.protocol"' internal/` 命中 6 处全在 registry；阶段：**框架阶段** | P4 裁定：实现 `ip.protocol` 契约执行（则 6 层声明自动生效）或删除该死声明；**本版不改代码** |
| **G-GRE-3** | **flat `spec.GRE` 与链路径混用时静默忽略**——`layer_gen.go:35-38` 注释声明"策略混用 flat gre + gre 链时 flat 静默忽略（legacy 路径不变）"；实际今日不可达（顶层 `gre` 子映射若被 presence 判死则到不了；若未判死则可构造） | 现象：潜在静默丢弃；证据：`layer_gen.go:35-38` 注释 + `CheckProtoFlat` 无 gre 分支（G-GRE-4）；阶段：**框架阶段**（依赖 G-GRE-4） | 与 G-GRE-4 同批处理；今日**不建用例**（不可达） |
| **G-GRE-4** | **`CheckProtoFlat` 无 gre presence 分支**（顶层 `gre` 子映射 `{"layers":[…],"gre":{}}` **不判死**，`grep -c 'protocol == "gre"' strategy_convert.go` = **0** 实测）+ **无游离顶层键通用门** | 现象：presence 负例今日建了会真绿 = 假通过；证据：`strategy_convert.go:8625-8700` 起（无 gre 分支）；阶段：**框架阶段** | P4 先实测再建例；**禁加单协议黑名单分支**（等框架级 unknown-key 白名单，kingbase/opcua/nvgre 同款裁定） |
| **G-GRE-5** | **`gre` 层业务 3 键全关动态**（allowlist 无 `gre` 行，`layer_dyn.go:17-71` 机读实测无该条目） | 现象：key/checksum/sequence 无法逐流变；证据：`LayerDynAllowlisted("gre", …)` 恒 false（`layer_dyn.go:1051`）；阶段：**代码阶段** | 已在 §12.12 逐键写明理由（语义上无逐流变需求）；P4 若采纳则需同步 allowlist + 三条负例改判正例 |
| **G-GRE-6** | **第三源（真实路由器/开源内核实现）未取到**——未抓真实 GRE 隧道的线字节，未核对 Linux 内核 `net/ipv4/gre_demux.c`/`ip_gre.c` 的 GRE 头布局与 RFC 的逐字段一致性 | 现象：三路对照只有第一路（规范）与第三路（本仓实测）；证据：§10.5；阶段：**待确认** | 待确认方式（三选一）：① 抓一台真实 GRE 路由器/云厂商隧道的包；② 读 Linux 内核 `net/ipv4/gre_demux.c` 的 `gre_parse_header`；③ 查 RFC 2784 errata。**风险**：若实测发现可选字段顺序或 Version 语义与 RFC 有出入，**全部 C/K/S 用例的 frame 断言需重钉**（§9.1 已给出本版复算值，可作对照基线） |
| **G-GRE-7** | **7 负例中 6 例无 `.neg.pcap` 落盘产物**——`/tmp/mcp-pcaps/gre/` 只有 `gre_neg_inner_mixed.neg.pcap`（0 帧实测），其余 6 例（`gre_neg_flat`/`gre_neg_static_copy`/`gre_neg_dyn_key`/`gre_neg_inner_dyn`/`gre_neg_dyn_sequence`/`gre_neg_dyn_checksum`）无对应文件 | 现象：负例零包只在本版契约层面声明，无落盘物证；证据：`ls /tmp/mcp-pcaps/gre/*.neg.pcap` = 1 个；阶段：**代码阶段**（P5 重跑套件后补） | P5 重跑后补全 7/7 `.neg.pcap`；在此之前读者不得据本版声明认为 6 例已复跑证实 |
| **G-GRE-8** | **`docs/protocol-pcap-test/gre.md` 是过期产物**——该 tracked 文件写 `Cases: 21 — pass 21, fail 0, error 0`，但其 `Cases` 行由提交 `793dfee`（**2026-09-19**）改定（`git log -1 --format=%ad -- trafficgen/docs/protocol-pcap-test/gre.md` 实测），**早于本版（2026-09-29）**；且 `docs/protocol-pcap-test/gre/` **目录不存在**（`find trafficgen/docs/protocol-pcap-test -name '*.pcap'` = **0 个**，该目录下无任何子目录） | 现象：结果文档的 21/21 未经今日复跑证实，pcap 链接全为死链；证据：`git log` 末次提交 2026-09-19 + 0 个 pcap 文件；阶段：**代码阶段** | **本版不删不改**（tracked 产物，删除属 P5 动作，此处仅登记事实）；**口径与 opcua G-OPCUA-10 / pcep G-PCEP-11 一致**。**须写清（不得夸大）**：gre **不是**"不可跑"协议——21/21 顶层键合规（§12.1）+ 本版对 `/tmp/mcp-pcaps/gre/` 的 21 例产物**逐条实测复算全绿**（§9.1）；本缺口**仅限**"结果文档数字未经今日复跑证实 + 无 pcap 留档" |

**缺口合计 8 条**（G-GRE-1…G-GRE-8）。**本版不建任何新用例、不改任何 cases JSON、不改任何代码**（as-built 文档轨边界）。

## 15. 修订记录

- v1.0.0（2026-09-29）：批次二 as-built 文档轨 P1–P3 首版。**存量 21 例机读审计**（14 正 + 7 负；顶层键分布 `{layers}`×20 + `{layers,count}`×1（负例判死对象）→ **非负例零残留**，本协议无 §1 迁移工作量）；**21 例 pcap 逐条实测复算**（18 条 frame 断言 + 37 条 field 断言 + 14 条 `min_packets` **全绿**；7 负例中 1 例有 `.neg.pcap` 实测 0 帧；malformed 0 命中）；**GRE 校验和独立复算两例**（`gre_checksum` 0xfb89 / `gre_kcs_combo` 0x62dd 均吻合——交叉验证可选字段 C→R→K→S 顺序）；§0 特殊性六条（隧道层身份/旗标位核心/被承载关系/内外族四格矩阵/内层地址自治/顶层零残留）；§3 逐字段规格含**总长度公式**与**存在性依赖 D-1…D-8**；§10 P1 矩阵（八项 + 子表①②③ + 三路对照 + 方案对比 A–D）；§11 as-built 代码设计（含 5 项冲突点/死配置）；§12 门1 十四行 + §12.1/12.3/12.12 强制展开 + 12-P2；§13 A′ 14 条候选；§14 缺口 **G-GRE-1…G-GRE-8**。自审 3 轮，末轮干净。
