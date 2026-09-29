# #113 gre（GRE，RFC 2784 + RFC 2890）测试用例契约

> 版本：v1.0.0（批次二 as-built 文档轨 P1–P3）
> 日期：2026-09-29
> 配套设计：`docs/protocol-designs/113-gre-design.md` v1.0.0（§0 特殊性 / §3 线格式 / §7 负例锚词 / §9 原子 ID / §12 门1 展开）
> 旧基线：`docs/TEST_CASES.md` T-GRE-1…T-GRE-22（**T-GRE-20 已作废**，编号保留不复用，见 §2 注）；`docs/CODE_DESIGN.md` D-GRE-1/2/3
> 机器契约：`trafficgen/test/protocol_pcap/cases/gre.json`（**21 例**：14 正 + 7 负；ID/顺序/包数/断言/锚词与本文 §2 逐条一致，**已机读实测**）
> 白话一句：**二十一条检查：十四条看正常封装（内外网段四种组合、旗标位开与不开、三键齐开、内层 TTL、VLAN、多流），七条看胡来能不能被拦下；每条只查一件事。**

## 1. 测试原则和形状基线

用例从设计 §3–§9 逐项派生，共 **21 个唯一语义 ID：14 正 + 7 负**。派生规则：设计 §3 每个字段/旗标位条款、§4 每个业务场景、§7 每行错误处理在本文有对应断言；断言不得超出设计声明范围。**一个用例只验证一个协议行为**（一个旗标位、一种族组合、一个错误分支、一个动态字段）。

**形状基线（2026-09-29 机读实测）**：

| 项 | 实测值 |
|---|---|
| 用例总数 | **21** |
| 正 / 负 | **14 / 7** |
| 用例级顶层键集合 | `{id, proto, summary, spec_json}` ∪ `{strategy_fc}`（5 例）/ ∪ `{expect}`（全 21 例，`expect` 恒在） |
| `spec_json` 顶层键分布 | **`{layers}` ×20** + **`{layers, count}` ×1**（唯一含 `count` 的是负例 `gre_neg_flat`——`count` 即判死对象） |
| **非负例顶层旧键残留** | **0**（14/14 非负例；20/20 例顶层键 ⊆ `{layers}`，唯一例外是负例 `gre_neg_flat` 的判死键 `count`） |
| 链形分布 | `[ip,gre,ip,udp,dns]` ×18 + `[ip,gre,ip,tcp,http]` ×2 + `[vlan,ip,gre,ip,udp,dns]` ×1 |
| 正例 `expect` 键集合 | `{min_packets, fields, frames, notes}` 或其子集；**14/14 含 `min_packets`**（**`packet_count` 零使用**） |
| 负例 `expect` 键集合 | **`{expect_error, error_contains}` 严格两键 ×7**（**无 `notes` 键**） |
| `proto` 字段 | 21/21 = `"gre"` |

**输出契约（pcap/NIC 双输出）**：两路径共用**同一 cases JSON 与断言集**（`gre.*` / 内层 `ip.version` / `udp.*` / `vlan.*` 字段 + frames 原始 hex + `min_packets`）；NIC 经 tcpdump 捕获（`nic_capture` 用例级开关，`test/protocol_pcap/nic_drive_test.go`）；**不设仅单路径可用的断言**。**本版只实测 pcap 一路**（NIC 未跑，诚实声明）。

**TSHARK 基线（本版实测，`gre.*` 字段 **40 项**）**：

| 断言通道 | 字段 | 进制/形态 | 用例 |
|---|---|---|---|
| 旗标+版本整字 | `gre.flags_and_version` | 十六进制串 `0xNNNN` | #1/#5/#8/#9/#10/#11 |
| 旗标位分解 | `gre.flags.checksum` / `gre.flags.routing` / `gre.flags.key` / `gre.flags.sequence_number` | 0/1 | **今日零使用**（本版实测可用）→ A′ 可收编 |
| 版本 | `gre.flags.version` | 十进制（本版实测恒 `0`） | 今日零使用 |
| 内层协议类型 | `gre.proto` | 十六进制串 `0x0800`/`0x86dd` | #1/#5/#6/#7/#15 |
| 校验和 | `gre.checksum` | 十六进制串 | #9/#11 |
| 校验和状态 | `gre.checksum.status` | 1=good | 今日零使用（本版实测全 1） |
| Key | `gre.key` | 十六进制串 | #10/#11 |
| Sequence | `gre.sequence_number` | **十进制串**（`0`…`8`） | **今日零使用** → A′ 收编（#8 已用 frames 双钉替代） |
| 内层地址 | `ip.src`（#7/#16/#21）/ `ipv6.src`（#5/#6） | 串（同名字段多值时 `,` 连接） | 见左 |
| 内层族 | `ip.version`（#6）/ `ipv6.version`（#5） | 串（`4,6` / `6,6`） | 见左 |
| TTL | `ip.ttl` | 串（`64,60`） | **今日零使用**（#12 用 frames @22/@46 双钉，见 §3.9） |
| 内层端口 | `udp.srcport`（#1/#5/#6/#7/#17）/ `udp.dstport`（#1/#5/#6/#7/#15）/ `tcp.dstport`（#18） | 十进制串 | 见左 |
| 外层 VLAN | `vlan.id` / `vlan.priority` | 十进制串 | #15 |
| 外层 EtherType | `eth.type` | 十六进制串 | #5/#7 |
| 原始字节 | frames `hex` + `offset` | `tshark -x` 转储 | #1/#5/#6/#7/#8/#10/#11/#12/#15（**9 例**） |

**进制纪律（本版实测）**：`gre.flags_and_version`/`gre.proto`/`gre.checksum`/`gre.key`/`eth.type` 用**十六进制串**（`0x` 前缀）；`gre.sequence_number`/`gre.flags.version`/`vlan.id`/`vlan.priority`/端口 用**十进制串**。

**断言基线**：今日 21 例用 **`min_packets`（14）+ `fields`（37 条）+ `frames`（18 条）+ `notes`（16 条）**；**`packet_count` / `has_handshake` / `terminates` / `has_payload` / `directional` / `negotiated` 零使用**（GRE 无握手/无连接，这四个键对本协议无意义——`terminates` 语义是"连接正常结束"，GRE 无连接）。

**`min_packets` 而非 `packet_count` 的理由（须写清）**：多流用例（`flows=2`）的实际帧数受 worker 调度影响，`packet_count` 精确断言会引入 flaky；`min_packets` 是**下界**断言（`verify.go:34` `n < MinPackets` 才报错）。存量 14/14 正例全用 `min_packets`，**实测帧数恰好等于声明值**（本版逐例对账，§3）。

**动态字段禁止硬编码**：生成期值（`gre.sequence_number`、内层 IPID）用 frames 原始 hex 断言（本实现逐帧确定：Sequence 从 0 起 +1，IPID 从 0 起 +1）。

**包数约定（实测）**：

| 场景 | 帧数 | 用例 |
|---|---:|---|
| 单帧封装（内层 UDP/DNS） | **1** | #1/#5/#6/#7/#9/#10/#11/#12/#15 |
| 单帧封装 × 2 流 | **2** | #16/#17/#21 |
| 内层 TCP 链（HTTP）单流 | **9** | #8 |
| 内层 TCP 链 × 2 流 | **18** | #18 |
| 负例 | **0**（实测 1 例落盘，§4） | #2/#3/#4/#13/#14/#19/#20 |

**保活/重试/RST 口径**：**全部不适用**——GRE 无连接、无超时、无重传、无保活（这些属于内层协议或隧道管理面，见设计 §10.1 第 6/7 行）。正例一律产出即结束，无 FIN/RST 概念（内层 TCP 链的 FIN 由**内层** tcp 层生成器承载，本层零断言）。

## 2. 原子用例索引（21 ID = 14 正 + 7 负，顺序为权威）

**顺序 = `cases/gre.json` 数组顺序**（机读实测，与本文逐条对齐）。

| # | ID | 类型 | 覆盖（设计 §） | T-编号 | `min_packets` | 断言条数（field/frame） |
|---:|---|---|---|---|---:|---|
| 1 | `gre_basic_ipv4` | 正 | §3.1/§3.4：4in4 基线，无旗标，proto 0x0800 | T-GRE-1 | 1 | 4 / 2 |
| 2 | `gre_neg_flat` | 负 | §7 N-1：顶层 `count` 判死 | T-GRE-2 | — | — |
| 3 | `gre_neg_static_copy` | 负 | §7 N-2：flows=2 + 全静态标量 | T-GRE-3 | — | — |
| 4 | `gre_neg_dyn_key` | 负 | §7 N-3：`key` 动态拒 | T-GRE-4 | — | — |
| 5 | `gre_v6_in_v6` | 正 | §0.4 6in6：双 v6 + proto 0x86DD | T-GRE-5 | 1 | 7 / 2 |
| 6 | `gre_6in4` | 正 | §0.4 6in4：外层 v4 + 内层 v6 | T-GRE-6 | 1 | 5 / 2 |
| 7 | `gre_4in6` | 正 | §0.4 4in6：外层 v6 + 内层 v4 | T-GRE-7 | 1 | 5 / 2 |
| 8 | `gre_sequence_multi` | 正 | §3.2 D-4：S 位 + 逐帧序号 0→8；内层 TCP 链 | T-GRE-8 | 9 | 1 / 3 |
| 9 | `gre_checksum` | 正 | §3.2 D-3 / §3.3：C 位 + 校验和 | T-GRE-9 | 1 | 2 / 0 |
| 10 | `gre_key` | 正 | §3.2 D-1：K 位 + Key 值 | T-GRE-10 | 1 | 2 / 1 |
| 11 | `gre_kcs_combo` | 正 | §3.2 D-6：C+K+S 齐开，头 16B | T-GRE-11 | 1 | 3 / 1 |
| 12 | `gre_inner_ttl` | 正 | §3.4/§3.7：内层 TTL 与外层独立 | T-GRE-12 | 1 | 0 / 2 |
| 13 | `gre_neg_inner_dyn` | 负 | §7 N-4：内层 ip 动态拒（双侧执法） | T-GRE-13 | — | — |
| 14 | `gre_neg_inner_mixed` | 负 | §7 N-5：内层异族拒 | T-GRE-14 | — | — |
| 15 | `gre_vlan_tagged` | 正 | IEEE 802.1Q §3 / §3.7 步骤 5：链首 vlan → tag | T-GRE-15 | 1 | 4 / 3 |
| 16 | `gre_outer_ip_dynamic` | 正 | §12.12：外层 `ip.src` list 双值 + flows=2 | T-GRE-16 | 2 | 1 / 0 |
| 17 | `gre_inner_udp_dynamic` | 正 | §12.12：内层 `udp.src_port` inc + flows=2 | T-GRE-17 | 2 | 1 / 0 |
| 18 | `gre_inner_tcp_dynamic` | 正 | §12.12：内层 `tcp.dst_port` inc + flows=2 | T-GRE-18 | 18 | 1 / 0 |
| 19 | `gre_neg_dyn_sequence` | 负 | §7 N-6：`sequence` 动态拒 | T-GRE-19 | — | — |
| 20 | `gre_neg_dyn_checksum` | 负 | §7 N-7：`checksum` 动态拒 | T-GRE-22 | — | — |
| 21 | `gre_outer_ip_rand` | 正 | §12.12：外层 `ip.src` rand(seed=7) + flows=2 | T-GRE-21 | 2 | 1 / 0 |

**断言条数合计**：`fields` **37** 条 + `frames` **18** 条（与 §1 基线一致，机读实测）。

**T-GRE-20 作废说明**（`docs/TEST_CASES.md:2235`，**编号保留不复用**）：原 T-GRE-20 = "隧道内 dns 动态拒绝负例"。D-DNS-1 起 `dns.name` 动态在直连链合法（string 面 list，T-DNS-8 13/13 绿），**隧道内层只有内层 ip 三键静态，dns.name 不在内层静态之列** → 原依据消亡，用例 `gre_neg_dyn_dns` 已删，替换为 `gre_neg_dyn_checksum`（T-GRE-22）。**故 21 例对应 22 个 T 编号（20 缺位）**。

**ID 顺序说明**：T 编号顺序（1→22）与 JSON 顺序（1→21）**在 #2–#4 与 #16–#21 段不同**——JSON 把三条负例（`gre_neg_flat`/`gre_neg_static_copy`/`gre_neg_dyn_key`）排在正例 `gre_basic_ipv4` 之后，把两条 rand/checksum 例排在末尾。**以 JSON 顺序为权威**（设计 §9 同口径）。

## 3. 正例逐项断言契约（最低断言集，实现期可增不可减）

**本版实测状态（2026-09-29）**：**14/14 正例**的 `min_packets` / `fields` / `frames` **逐条对 `/tmp/mcp-pcaps/gre/` 落盘 pcap 复算全绿**（14 条 `min_packets` 精确相等；37 条 field 断言命中；18 条 frame 断言按 offset 前缀比对命中）。`_ws.malformed` **0 命中**；`ip.checksum.status`/`udp.checksum.status`/`tcp.checksum.status` **全为 2（good），无 ILLEGAL**。

### 3.1 `gre_basic_ipv4`（1 帧，95B）— T-GRE-1

链 `[ip{10.0.0.1→20.0.0.1}, gre{}, ip{192.168.1.1→192.168.1.2}, udp{12345→80}, dns{}]`。

- `min_packets=1`；实测 **1 帧 / 95B**（= 14+20+4+20+8+29，设计 §0.2 公式复算 ✓）。
- `fields`：`gre.flags_and_version=0x0000`、`gre.proto=0x0800`、`udp.srcport=12345`、`udp.dstport=80`。
- `frames`：帧 1 @**34** `00 00 08 00`（GRE 头 = eth14+ip20）；@**58** `30 39 00 50`（内层 UDP 头 = eth14+ip20+gre4+ip20）。
- **证据链**：@34 即 GRE 头起点（设计 §2 偏移表）；`gre.flags.version=0`（本版实测，Version 恒 0）；`gre.flags.checksum/routing/key/sequence_number` 全 0（无旗标，设计 §3.2）。
- **`gre:{}` 空配置走默认**：key=0 → **不置 K 位**（设计 §3.2 D-2）；checksum=false / sequence=false。

### 3.2 `gre_v6_in_v6`（1 帧，135B）— T-GRE-5

链 `[ip{fd00::1→fd00::2}, gre{}, ip{fd01::1→fd01::2}, udp{12345→80}, dns{}]`。

- `min_packets=1`；实测 **1 帧 / 135B**（= 14+40+4+40+8+29，双 v6 头各 40B ✓）。
- `fields`：`gre.proto=0x86dd`、`gre.flags_and_version=0x0000`、`eth.type=0x86dd`、`udp.srcport=12345`、`udp.dstport=80`、`ipv6.version=6,6`、`ipv6.src=fd00::1,fd01::1`。
- `frames`：帧 1 @**58** `60 00 00 00`（内层 v6 头 = eth14+ip6_40+gre4）；@**98** `30 39 00 50`（内层 UDP = 58+40）。
- **双 v6 同帧互证**：`ipv6.version=6,6` + `ipv6.src=fd00::1,fd01::1`——**外层 v6 与内层 v6 各自独立**（`fd00::` vs `fd01::` 网段分离），这正是 `gre_6in4` 缺陷修复后的内外分离证据。
- **内层 UDP 校验和非零**（RFC 6936 §2，v6 内层不得为零，设计 §3.6）。

### 3.3 `gre_6in4`（1 帧，115B）— T-GRE-6

链 `[ip{10.0.0.1→20.0.0.1}, gre{}, ip{fd01::1→fd01::2}, udp{12345→80}, dns{}]`（**外层 v4、内层 v6**）。

- `min_packets=1`；实测 **1 帧 / 115B**（= 14+20+4+40+8+29 ✓）。
- `fields`：`gre.proto=0x86dd`（**内层族决定**）、`ip.version=4,6`（**外层 4 + 内层 6 同帧互证**）、`udp.srcport=12345`、`udp.dstport=80`、`ipv6.src=fd01::1`（**内层源，未被外层顶掉**）。
- `frames`：帧 1 @**38** `60 00 00 00`（内层 v6 头 = eth14+ip20+gre4）；@**78** `30 39 00 50`。
- **本用例是 D-GRE-2 静默覆盖 bug 修复的正例证据**（设计 §0.5）：`ip.version=4,6` 一个断言同时证明外层仍是 v4、内层是 v6——若缺陷仍在，内层会被换成 v4 地址，该断言必红。

### 3.4 `gre_4in6`（1 帧，115B）— T-GRE-7

链 `[ip{fd00::1→fd00::2}, gre{}, ip{192.168.1.1→192.168.1.2}, udp{12345→80}, dns{}]`（**外层 v6、内层 v4**）。

- `min_packets=1`；实测 **1 帧 / 115B**（= 14+40+4+20+8+29 ✓）。
- `fields`：`gre.proto=0x0800`（内层 v4）、`eth.type=0x86dd`（外层 v6）、`udp.srcport=12345`、`udp.dstport=80`、`ip.src=192.168.1.1`（内层源）。
- `frames`：帧 1 @**58** `45 00 00 39`（内层 v4 头 = eth14+ip6_40+gre4；`45`=v4/IHL5，`00 39`=总长 57）；@**78** `30 39 00 50`。
- **外层 IPv6 头 40B 的直接证据**：GRE 头起点从 v4 的 34 变 **58**（+24 = 40−20 + 4？精确：14+40=54，GRE 头在 54… 但断言在 **58** 是内层 v4 头——因为 GRE 无旗标只占 4B：54+4=58 ✓）。

### 3.5 `gre_sequence_multi`（9 帧）— T-GRE-8

链 `[ip{10.0.0.1→20.0.0.1}, gre{sequence:true}, ip{192.168.1.1→192.168.1.2}, tcp{12345→80}, http{}]`。

- `min_packets=9`；实测 **9 帧**（帧长 82/82/82/135/120/82/82/82/82）。
- `fields`：`gre.flags_and_version=0x1000`（**S 位置位**）。
- `frames`：帧 1 @**34** `10 00 08 00`（GRE 头 flags=0x1000 + proto 0x0800）；帧 1 @**38** `00 00 00 00`（**Sequence = 0**）；帧 9 @**38** `00 00 00 08`（**Sequence = 8**）。
- **逐帧序号实测**：`gre.sequence_number` = `0,1,2,3,4,5,6,7,8`（tshark 逐帧，本版实测）——**frames 双钉（首 0 / 末 8）+ 全序列实测互证**。
- **9 帧分解**（本版实测 tcp.flags）：帧 1 `0x0002`(SYN) / 帧 2 `0x0012`(SYN-ACK) / 帧 3 `0x0010`(ACK) / 帧 4 `0x0018`(PSH-ACK，GET，135B) / 帧 5 `0x0018`(PSH-ACK，200 OK，120B) / 帧 6 `0x0011`(FIN-ACK) / 帧 7 `0x0010`(ACK) / 帧 8 `0x0011`(FIN-ACK) / 帧 9 `0x0010`(ACK)。**= 3 握手 + 2 数据 + 4 挥手**（设计 §5）。
- **`gre.sequence_number` 字段今日未被 JSON 使用**（只用 frames hex）→ A′ 收编候选（§6.2）。

### 3.6 `gre_checksum`（1 帧，99B）— T-GRE-9

链 `[ip{10.0.0.1→20.0.0.1}, gre{checksum:true}, ip{192.168.1.1→192.168.1.2}, udp{12345→80}, dns{}]`。

- `min_packets=1`；实测 **1 帧 / 99B**（= 95 + 4 校验和字段 ✓）。
- `fields`：`gre.flags_and_version=0x8000`（**C 位置位**）、`gre.checksum=0xfb89`。
- **校验和可复算（本版独立复算 = 0xfb89 ✓）**：按 RFC 2784 §3.1 对 [GRE 头（Checksum 域清零）+ 内层完整包] 求 16 位一补码和（设计 §3.3）。**该复算是"字段存在且值正确"的双重证据**——只断言非零不能排除算法错。
- **`gre.checksum.status=1`**（tshark 判 good，本版实测）——**第三方独立验证**。

### 3.7 `gre_key`（1 帧，99B）— T-GRE-10

链 `[ip{10.0.0.1→20.0.0.1}, gre{key:305419896}, ip{192.168.1.1→192.168.1.2}, udp{12345→80}, dns{}]`。

- `min_packets=1`；实测 **1 帧 / 99B**（= 95 + 4 Key 字段 ✓）。
- `fields`：`gre.flags_and_version=0x2000`（**K 位置位**）、`gre.key=0x12345678`（305419896 = 0x12345678）。
- `frames`：帧 1 @**38** `12 34 56 78`（**Key 4B 紧跟 GRE 基头，大端**，设计 §3.2 D-1）。
- **K 位置位与 Key 字段存在的耦合**：`gre.flags.key=1`（本版实测）与 @38 四字节同时成立——**旗标位 ↔ 字段存在性**的直接证据（设计 §3.2 D-1）。
- **Key 值选 0x12345678 的理由**：避开 `key==0`（本实现不置 K 位，设计 §3.2 注）的歧义边界。

### 3.8 `gre_kcs_combo`（1 帧，107B）— T-GRE-11

链 `[ip{10.0.0.1→20.0.0.1}, gre{key:305419896, checksum:true, sequence:true}, ip{192.168.1.1→192.168.1.2}, udp{12345→80}, dns{}]`。

- `min_packets=1`；实测 **1 帧 / 107B**（= 95 + 12 = 4+4+4 三可选域 ✓，GRE 头 **16B**）。
- `fields`：`gre.flags_and_version=0xb000`（**C+K+S 三位齐置**）、`gre.key=0x12345678`、`gre.checksum=0x62dd`。
- `frames`：帧 1 @**42** `12 34 56 78`（**Key 在 offset 42 = 38+4**——即 **Checksum 之后**）。
- **可选字段物理顺序 C→R→K→S 的双重实证**（设计 §3.1/§3.3）：
  1. **偏移实证**：Key 在 42（38+4=Checksum 之后），若顺序颠倒 Key 应在 38；
  2. **校验和实证**：本版按 RFC 2784 §3.1 **独立复算 = 0x62dd ✓**——校验和覆盖整个 GRE 头（含选项字段），**顺序错则和必错**。`gre.checksum.status=1`（tshark 判 good）。
- 本版实测旗标位分解：`gre.flags.checksum=1` / `gre.flags.key=1` / `gre.flags.sequence_number=1` / `gre.flags.routing=0` / `gre.flags.version=0`。

### 3.9 `gre_inner_ttl`（1 帧，95B）— T-GRE-12

链 `[ip{10.0.0.1→20.0.0.1}, gre{}, ip{192.168.1.1→192.168.1.2, ttl:60}, udp{12345→80}, dns{}]`。

- `min_packets=1`；实测 **1 帧 / 95B**（TTL 只改字节值，不改长度）。
- `frames`：帧 1 @**22** `40`（**外层 TTL = 0x40 = 64**，eth14+ip8）；@**46** `3c`（**内层 TTL = 0x3c = 60**，eth14+ip20+gre4+ip8）。
- **两个 TTL 独立的证据（须写清）**：tshark 的 `ip.ttl` 字段在**内外两层同名字段**，`-T fields` 输出 `64,60`（外层先、内层后，本版实测）——**同名聚合无法区分内外**，故本用例**不用 field 断言而用 frames hex 分别钉死**（offset 22 与 46）。这是"断言可执行"的正确形态：断言目标逻辑（内外 TTL 独立），不是断言一个会被聚合混淆的字段。

### 3.10 `gre_vlan_tagged`（1 帧，99B）— T-GRE-15

链 `[vlan{id:100, priority:4}, ip{10.0.0.1→20.0.0.1}, gre{}, ip{192.168.1.1→192.168.1.2}, udp{12345→80}, dns{}]`。

- `min_packets=1`；实测 **1 帧 / 99B**（= 95 + 4 tag ✓）。
- `fields`：`vlan.id=100`、`vlan.priority=4`、`gre.proto=0x0800`、`udp.dstport=80`。
- `frames`：帧 1 @**12** `81 00`（**TPID**，eth14 后即 tag）；@**14** `80 64`（**TCI = priority<<13 | id = 4<<13 | 100 = 0x8064**）；@**38** `00 00 08 00`（GRE 头，**偏移从 34 变 38 = +4**）。
- **VLAN tag 编码实证**：`0x8064` 十进制 32868 = 4×8192 + 100 ✓（IEEE 802.1Q §3）。
- **其余偏移 +4 的实证**：GRE 头 34→**38**（本版实测）。

### 3.11 `gre_outer_ip_dynamic`（2 帧，各 95B）— T-GRE-16

链 `[ip{src:{strategy:list, list:["10.0.0.1","10.0.0.2"]}, dst:"20.0.0.1"}, gre{}, ip{192.168.1.1→192.168.1.2}, udp{12345→80}, dns{}]` + `strategy_fc{type:flows, value:2}`。

- `min_packets=2`；实测 **2 帧**。
- `fields`：`ip.src` **`distinct_values = ["10.0.0.1,192.168.1.1", "10.0.0.2,192.168.1.1"]`**。
- **聚合语义（须写清）**：`ip.src` 在**内外两层同名**，`-T fields` 每帧输出 `外层,内层` 两值用逗号连接（本版实测）。因此 distinct 集合的元素是**二元组串**，不是单 IP。
- **本断言同时证明三件事**：① 外层源两值互异（`10.0.0.1` / `10.0.0.2`，动态生效）；② 内层源恒 `192.168.1.1`（**内层静态，不受外层动态影响**——单四元组模型）；③ 两帧都产出了（`min_packets=2`）。
- **不做 `packet_count` 的理由**：多流调度非确定，用 `distinct_values`（包索引被忽略，`pcaptest/types.go:64-67`）+ `min_packets` 是调度无关口径。

### 3.12 `gre_inner_udp_dynamic`（2 帧，各 95B）— T-GRE-17

链 `[ip{10.0.0.1→20.0.0.1}, gre{}, ip{192.168.1.1→192.168.1.2}, udp{src_port:{strategy:inc, range:[41000,41001]}, dst_port:80}, dns{}]` + `flows=2`。

- `min_packets=2`；实测 **2 帧**。
- `fields`：`udp.srcport` **`distinct_values = ["41000", "41001"]`**（`inc` 策略逐流 +1，设计 §12.12）。
- **内层端口动态的证据**：`udp.srcport` 在**内外两层同名**（内层是唯一 UDP 层，外层无 UDP），故此处聚合就是内层值——**与 #16 的 `ip.src` 不同，本用例无内外歧义**。

### 3.13 `gre_inner_tcp_dynamic`（18 帧）— T-GRE-18

链 `[ip{10.0.0.1→20.0.0.1}, gre{sequence:true}, ip{192.168.1.1→192.168.1.2}, tcp{src_port:12345, dst_port:{strategy:inc, range:[80,8080], step:8000}}, http{}]` + `flows=2`。

- `min_packets=18`；实测 **18 帧**（2 流 × 9 帧，T-GRE-8 口径）。
- `fields`：`tcp.dstport` **`distinct_values = ["80","8080"]`** + **`distinct_exclude = ["12345"]`**。
- **`distinct_exclude` 的必要性（须写清）**：`tcp.dstport` 在双向 TCP 会话中同时承载**服务端端口**（80/8080，客户端→服务端方向）与**客户端端口**（12345，服务端→客户端方向）。`distinct_exclude:["12345"]` 把后者排除，**断言只剩两个内层服务端口**（`pcaptest/types.go:68-70` 语义）。
- **本版逐帧实测**（`tcp.srcport,dstport`）：流 1 全部 `12345→80` / `80→12345`；流 2 全部 `12345→8080` / `8080→12345`——**两流端口隔离清晰**。
- **每流 9 帧的独立证据**：`min_packets=18` + 上述逐帧端口配对（两流各自完整 9 帧会话，非交错）。

### 3.14 `gre_outer_ip_rand`（2 帧，各 95B）— T-GRE-21

链同 #16，但外层 `ip.src` 用 **`rand`**（`range:["10.0.0.1","10.0.0.2"], seed:7`）+ `flows=2`。

- `min_packets=2`；实测 **2 帧**。
- `fields`：`ip.src` **`distinct_values` 与 #16 完全相同**（`["10.0.0.1,192.168.1.1", "10.0.0.2,192.168.1.1"]`）。
- **`seed:7` 的可复现性**：断言"两值互异"而非"顺序固定"——`rand` 策略在 `seed` 固定下逐流可复现（设计 §12.12 序号算法表），但**两流取到的值集合**才是断言目标（调度无关）。
- **本用例覆盖 `rand` 策略**（#16 覆盖 `list`）——设计 §10 口径四要求"inc 回绕/rand 可复现/list 轮转/pattern 替换/静态复制被拒"五类中，本协议**已覆 list（#16）+ rand（#21）+ inc（#17/#18）+ 静态复制被拒（#3）**；**pattern 与 inc 回绕无例** → A′ 候选（§6.2）。

## 4. 负例契约

负例必须在建策略/校验阶段失败并传播为 task error，不得产生成功 PCAP、`completed/0 packet` 或只剩外层壳的假成功。锚词与设计 §7 表一一对应、同序（代码逐字）：

| # | ID | 故障输入（机读实测） | JSON `error_contains` | 代码文案（逐字） | 代码位置 | 拒绝阶段 |
|---:|---|---|---|---|---|---|
| N-1 | `gre_neg_flat` | `spec_json` 含顶层 `count:2`（层链 + 旧键混用） | `no longer accepts flat config field count` | `protocol gre no longer accepts flat config field count (use a layers chain: …)` | `strategy_convert.go:8632-8636` | 建策略期 400 |
| N-2 | `gre_neg_static_copy` | `strategy_fc{flows:2}` + 链上四元组全静态标量 | `static four-tuple` | `layers pin a static four-tuple but flows > 1: every flow would emit identical addresses/ports (static copy). …` | `schema/semantic.go:285` | 建策略期 400 |
| N-3 | `gre_neg_dyn_key` | `gre{key:{strategy:"list", list:[100]}}` | `does not support dynamic` | `layers[1](gre).key does not support dynamic` | `validate_layers.go:1004` | 建策略期 400 |
| N-4 | `gre_neg_inner_dyn` | 内层 `ip{src:{strategy:"list", list:["30.0.0.1","30.0.0.2"]}}` | `inner ip layer does not support dynamic` | `layers[2](ip).src: inner ip layer does not support dynamic (tunnel inner addresses are static; vary the outer ip layer instead)` | `validate_layers.go:1333`（**+ `layer_dyn.go:121` worker 兜底，同锚词**） | 建策略期 400 + worker 侧 |
| N-5 | `gre_neg_inner_mixed` | 内层 `ip{src:"192.168.1.1", dst:"fd00::2"}`（v4 源 + v6 目的） | `must be the same IP version` | `tunnel chain: inner ip layer addresses 192.168.1.1/fd00::2 must be the same IP version` | `chain_planner.go:520-522` | 建策略期 400 |
| N-6 | `gre_neg_dyn_sequence` | `gre{sequence:{strategy:"list", list:[true]}}` | `does not support dynamic` | `layers[1](gre).sequence does not support dynamic` | `validate_layers.go:1004` | 建策略期 400 |
| N-7 | `gre_neg_dyn_checksum` | `gre{checksum:{strategy:"list", list:[true]}}` | `does not support dynamic` | `layers[1](gre).checksum does not support dynamic` | `validate_layers.go:1004` | 建策略期 400 |

**锚词口径**：`error_contains` 是**子串**判定；**7/7 命中**（本版机读核对）。`gre_neg_flat` 的锚词含具体键名 `count`（`strategy_convert.go:8634` 把键名拼进文案）——**断言键名是"确实命中了 `count` 那一支"的证据**，不是泛化命中。

**负例原子性**：每例**单一故障注入**，单次执行不得混注（机读实测：7/7 负例的 `spec_json` 只含该注入点，**无叠加**）。**负例纯净性**：7/7 `expect` = **严格两键 `{expect_error, error_contains}`**——**无 `notes`、无成功包结构断言**（本协议比 opcua 存量更干净：opcua 的 2 负例含 `notes` 键）。

**N-4 的双侧执法（须写清）**：内层 ip 层动态拒绝在**两处独立实现**——`ValidateLayers`（建策略期，`validate_layers.go:1326-1334`）与 `parseLayerDyn`（worker 逐流解析期，`layer_dyn.go:113-126`）。后者是**兜底**（引擎直调绕过 ValidateLayers 时仍拒）。**两侧锚词逐字相同**（`inner ip layer does not support dynamic (tunnel inner addresses are static; vary the outer ip layer instead)`），用例只断言子串 → **两路都能命中**。这是**双保险设计**（`layer_dyn.go:113-115` 注释明写"双侧执法——本函数是 worker 逐流解析入口，引擎直调绕过 ValidateLayers 时此处兜底"）。

**为什么 N-3/N-6/N-7 是同锚词三例而非一例**：`gre` 层 3 键（`key`/`checksum`/`sequence`）**全部关闭动态**（allowlist 无 `gre` 行，`layer_dyn.go:17-71` 机读实测 0 命中）。三键**各建一例是逐键覆盖**——一例只能证明一键被拒（原子原则：删除任一例，该键的"关动态"证据即消失）。**三例同锚词是 allowlist 门的设计结果**（同一函数、同一文案），不是用例冗余。

**负例落盘产物（本版实测，诚实声明）**：`/tmp/mcp-pcaps/gre/` 中**只有 `gre_neg_inner_mixed.neg.pcap`**（**0 帧实测**）；其余 6 例**无对应 `.neg.pcap` 文件**。→ **G-GRE-7 登记**（§5.4）：本版**只实测到 1 例的落盘零包物证**，其余 6 例按"零包传播 task error"契约声明，**不得据本版声明认为 6 例已复跑证实**。

**未入用例的拒绝分支（A′ 立项，不得冒充已覆盖）**：见设计 §7 表——**16 行**（builder 期 6 行 + legacy Validate 期 7 行 + 隧道结构期 3 行），逐行：

| 期 | 行数 | 分支 |
|---|---:|---|
| 建策略期（`CheckProtoFlat` / static-copy / allowlist / 内层 ip / 隧道结构） | 5 | 已全部入例（N-1…N-5）——**不计入未入例行** |
| builder（`validateGREConfig`，`builder.go:492-540`） | 7 | PPPoE 组合 / 外层非 IP / proto≠47 / L4 非空 / ProtocolType 白名单 / Routing 长度 / **PPTP 组合（1 行含 4 子分支）** |
| legacy `Planner.Validate`（`planner.go:50-167`） | 6 | ProtocolType 枚举 / ARP 矛盾 / 内层地址解析 / 内层族一致 / InnerProto 枚举 / Frames≥0 / Direction 枚举（6 行覆盖 **13 个 return 点**，grep 实测） |
| 隧道结构（`chain_planner.go:505-522` + `complete.go:381-387`） | 4 | 外层地址缺失 / 内层地址不可解析 / 内层非终结层（V4）/ 隧道层当末层 |

**合计 17 行**（builder 7 / legacy 6 / 结构 4）——**以「行」为登记粒度**（若按代码 return 点计则为 10 + 13 + 4 = **27 个 return 点**，本表不按该口径计数）。**锚词逐字见设计 §7 表**。

## 5. 覆盖与对账

### 5.1 三源回指行

RFC 2784 + RFC 2890（设计 §3 逐字段）+ IEEE 802.1Q §3（VLAN tag）+ RFC 2473（v6 承载语义）+ D-GRE-1/2/3（设计 §11）+ tshark 3.6.14 `gre.*` 字段表与 **21 例落盘 pcap**（`/tmp/mcp-pcaps/gre/`，本版逐条实测复算）→ 21 ID（本契约 §2）。

**21 ID 逐项回指**：#1←设计 §3.1/§3.4；#2←§7 N-1；#3←§7 N-2；#4←§7 N-3；#5←§0.4/§3.5；#6←§0.4/§0.5；#7←§0.4；#8←§3.2 D-4/§5；#9←§3.2 D-3/§3.3；#10←§3.2 D-1；#11←§3.2 D-6；#12←§3.4/§3.7；#13←§7 N-4/§12.12；#14←§7 N-5；#15←§3.7/§0.4；#16←§12.12；#17←§12.12；#18←§12.12；#19←§7 N-6；#20←§7 N-7；#21←§12.12。

**第三源状态**：**未确认级**——真实路由器/开源内核实现的线字节**未取到** → **G-GRE-6**（§5.4）。本版已到**抓包级**（本仓引擎产出的 21 例 pcap 逐帧核对 + 校验和独立复算），但**不等于**"现网已确认"。按 CORE_MEMORY §5.5 口径，未确认项**不写死进实现**。

### 5.2 对账两行 + 清单出处声明

- **清单出处声明**：本清单来源 = **RFC 2784/2890 公开语义 + IEEE 802.1Q + 旧基线 D-GRE-1/2/3 + 仓库落码反推 + tshark 3.6.14 字段与 21 例 pcap 实测**，**非纯规范反推**（第三源未取到 → G-GRE-6）。
- **对账两行**：**要求逻辑点总数 = 79**（八项 8 行 + 矩阵 18 格 + 变体 38 行 + 商业映射 15 行）；**用例覆盖数 / 不适用 / 开放立项**逐表重数：

| 表 | 行/格数 | 已覆 | A′ 立项 | 明确不解决 | 不适用 |
|---|---:|---:|---:|---:|---:|
| 设计 §10.1 八项矩阵 | 8 | 6 | 0 | 0 | 2 |
| 设计 §10.2 旗标位×终态 | 18 | 10 | 2 | 0 | 6 |
| 设计 §10.3 数据形态变体 | 38 | 27 | 6 | 4 | 1 |
| 设计 §10.4 商业行为映射 | 15 | 10 | 0 | 5 | 0 |
| **合计** | **79** | **53** | **8** | **9** | **9** |

**53 + 8 + 9 + 9 = 79 ✓**。各表逐格重数见设计 §10.1（8 = 覆 6 + 不适用 2）/§10.2（18 = 覆 10 + A′ 2 + 不适用 6）/§10.3（38 = 覆 27 + A′ 6 + 不解决 4 + 不适用 1）/§10.4（15 = 覆 10 + 不解决 5）。

**§10.1 分类口径（须写清）**：§10.1 的"缺口"列是**文字说明**，不是分类标签。8 行按**行主体结论**归：**覆 6**（行 1 连接模型 / 行 2 命令消息表 / 行 3 状态机 / 行 4 字段表 / 行 5 错误处理 / 行 8 版本方言——六项要求的**实现均已存在**）+ **不适用 2**（行 6 超时与活性 / 行 7 NAT·代理·被动——GRE 无此概念）。**行 2/4/8 提到的 R 位与 PPTP 缺口已由 G-GRE-1 单独登记**，行 5 的"17 行未入例分支"已由 §6.2 A′ 登记——**两者都不折进 79**（粒度声明：79 只计"要求点是否已有实现/已适用"，个案覆盖缺口走缺口表与 A′ 表）。


- **门3 抽查候选**：最复杂用例 = **#8 `gre_sequence_multi`**（9 帧内层 TCP 链：3 握手 + 2 数据 + 4 挥手，逐帧 GRE 序号 0→8 递增，S 位置位；交织维度 = 帧位(9) × 序号(9) × 内层 TCP flags(5 种)）；**建议门3 抽 #8 + #11**（`gre_kcs_combo` 补三旗标组合 + 可选字段顺序面）。

### 5.3 T-编号与 ID 对照

见 §2 表（`T-编号` 列）。**T-GRE-20 缺位**（作废，编号不复用）。

### 5.4 缺口登记表（G-GRE-1…G-GRE-8，三要素）

**归属阶段说明**：本批 10 协议是 **as-built 文档轨**（不改代码、不改 cases JSON），故所有缺口的"归属阶段"落在**代码阶段 / 框架阶段 / 待确认**，**无一条属"文档阶段"**。

| 缺口 | 现象 | 证据 | 归属阶段 |
|---|---|---|---|
| **G-GRE-1** | 层内无 `routing` 键（R 位不可达）；ARP-over-GRE / PPTP 增强 GRE / 内层 TCP options 层内亦不可达 | `registry.go:1672-1676`（Fields 仅 3 键）+ `builder.go:868-874`（R 分支已落码）+ `layer_gen.go:33-34`（注释声明 TCPOptions 不注入） | **代码阶段** |
| **G-GRE-2** | `FieldContract {"ip.protocol":"47"}` 是死配置（唯一消费者只解析 `tcp.dst_port`/`udp.dst_port`） | `chain_planner_util.go:291-308`（消费者）+ `grep -rn '"ip.protocol"' internal/` = 6 处全在 registry | **框架阶段** |
| **G-GRE-3** | flat `spec.GRE` 与链路径混用时静默忽略（今日不可达） | `layer_gen.go:35-38`（注释声明）+ `CheckProtoFlat` 无 gre 分支（G-GRE-4） | **框架阶段** |
| **G-GRE-4** | `CheckProtoFlat` 无 gre presence 分支 + 无游离顶层键通用门 | `grep -c 'protocol == "gre"' strategy_convert.go` = **0** 实测 | **框架阶段** |
| **G-GRE-5** | `gre` 层业务 3 键全关动态（allowlist 无 `gre` 行） | `layer_dyn.go:17-71` 机读 0 命中；`LayerDynAllowlisted("gre",…)` 恒 false（`layer_dyn.go:1051`） | **代码阶段** |
| **G-GRE-6** | 第三源（真实路由器 / Linux 内核 `gre_demux.c`）未取到 | 本版只完成规范路 + 本仓实测路 | **待确认** |
| **G-GRE-7** | 7 负例中 **6 例无 `.neg.pcap` 落盘产物**（只有 `gre_neg_inner_mixed.neg.pcap`，0 帧实测） | `ls /tmp/mcp-pcaps/gre/*.neg.pcap` = 1 个 | **代码阶段**（P5 重跑后补全 7/7） |
| **G-GRE-8** | `docs/protocol-pcap-test/gre.md`（**tracked 产物**）写 `Cases: 21 — pass 21, fail 0, error 0`，但其 `Cases` 行由提交 `793dfee`（**2026-09-19**）改定，**早于本版（2026-09-29）**；且 `docs/protocol-pcap-test/gre/` **目录不存在**（`find … -name '*.pcap'` = **0 个**）——pcap 链接全为死链，21/21 未经今日复跑证实 | `git log -1 --format=%ad -- trafficgen/docs/protocol-pcap-test/gre.md` = 2026-09-19；`find trafficgen/docs/protocol-pcap-test -name '*.pcap'` = 0 | **代码阶段** |

**G-GRE-8 须写清（不得夸大，口径与 opcua G-OPCUA-10 / pcep G-PCEP-11 一致）**：gre **不是**"不可跑"协议——21/21 顶层键合规（§1）+ 本版对 `/tmp/mcp-pcaps/gre/` 的 21 例产物**逐条实测复算全绿**（§3）。本缺口**仅限**"结果文档数字未经今日复跑证实 + 无 pcap 留档"。**本版不删不改该 tracked 产物**（删除属 P5 动作）。

**另注**：`docs/protocol-designs/INDEX.md` **无 gre 条目**（机读实测：`grep -i gre INDEX.md` 仅命中 nvgre/postgresql 三行，**无 113 行**）——INDEX 补录由**主线程**执行（本车道不碰该文件）。

### 5.5 A′/B′ 两分类表

**A′（代码阶段接线）**：

| 类 | 内容 | 落点 |
|---|---|---|
| R 位面 | `routing` 键 + R 位正例 + 长度校验负例 | G-GRE-1 |
| Key=0 边界 | "K 位置位且 Key=0"的表达式（当前不可表达） | G-GRE-1 |
| 外层族面 | 外层两地址异族拒 | 设计 §10.3 行 23 |
| 端口面 | 内层端口缺省（dns 53 / http 80） | 设计 §8 |
| 方向面 | down 帧（内外地址双交换） | 设计 §10.3 行 35 |
| 序号隔离面 | flows=2 + S 位 → 两流序号各自从 0 起 | 设计 §12.12 |
| IPID 面 | 逐帧内层 IPID 递增断言 | 设计 §10.3 行 31 |
| 最小帧面 | 内层空载荷最小帧 | 设计 §10.3 行 27 |
| 内层 ICMP 面 | 内层 ICMP/ICMPv6 | 设计 §1 边界 5 |
| 拒绝分支面 | **17 行**（builder 7 / legacy 6 / 结构 4） | 设计 §7 |
| **field 收编面** | `gre.sequence_number`（#8 现用 frames 双钉）、`gre.flags.*` 位分解、`gre.checksum.status`、`gre.flags.version` —— **今日零使用** | 本契约 §1 |
| **负例物证面** | 6 例 `.neg.pcap` 落盘 | G-GRE-7 |

**B′（框架面）**：`CheckProtoFlat` gre presence 分支 + 游离顶层键通用门（G-GRE-4）/ `ip.protocol` FieldContract 消费者（G-GRE-2）/ 业务字段动态（G-GRE-5）/ flat+链混用静默忽略（G-GRE-3）。进设计 §14，「明确不解决 + 迁入计划」。

### 5.6 §3.14 豁免边界审计

**无长连接协议（GRE 无连接）→ `sessions[]` 豁免**，理由：GRE 是 IP 之上的**无连接封装**（RFC 2784 §3），没有会话建立/拆除，`sessions[]` 无对应语义。

**但 §3.14 明写"豁免 `sessions[]` 不等于豁免多流覆盖"**：

| 项 | 本协议状态 |
|---|---|
| **多流并发** | **已覆**——5 例（#16/#17/#18/#21 + #3 的 flows=2 负例），`flow_control{"type":"flows","value":2}` 承载 |
| **单包多载荷** | **显式不适用**——GRE 一帧恰一个内层包（无多 question / 多 RR 类形态），如实声明 |

**§3.15 三项核对**：

| # | 三项 | 本协议对照 | 用例/立项 |
|---:|---|---|---|
| ① | 同连接/同流内的多轮操作 | 内层 TCP 链 9 帧（3 握手 + 2 数据 + 4 挥手） | **已覆 #8/#18** |
| ② | 非正常结束 | GRE 无连接可异常中断；内层 TCP 的 RST 由内层 tcp 层承载，本层零断言 | **显式不适用**（若需断言 → A′ 立项） |
| ③ | 长保活 | GRE 无保活概念 | **显式不适用** |

**无空项**：① 有已覆例；② 显式不适用（有理由）；③ 显式不适用（有理由）。

## 6. 实现后执行建议

1. **P4 顺序（若本协议进 P4）**：①先裁定 G-GRE-1（`routing` 键补/不补）——补则 R 位三例可建；②收编 A′ field 面（`gre.sequence_number` / `gre.flags.*` 位分解 / `gre.checksum.status`）；③补外层异族/缺省端口/down 帧/序号隔离四例；④补 6 例 `.neg.pcap` 物证（G-GRE-7）。**本协议无 §1 迁移步骤**（非负例 14/14 顶层零残留）。
2. **实测顺序**（复用本版基线）：先 #1（GRE 头 offset 34 + 内层 UDP offset 58 基线），再 #5/#6/#7（族矩阵三例，offset 58/38/58 与 `ip.version` 双值），再 #9/#10/#11（旗标位 + 校验和复算），再 #8（9 帧 + 序号 0→8），最后 #15（VLAN 偏移 +4）、#16–#18/#21（多流 distinct）。
3. **门2 三项**（`pipe_gate.sh gre`）：①顶层旧键零残留（**今日已成立**，§1）；②`CASE_PROTO=gre` 全量跑（**本版未跑**，见下条）；③二进制与 HEAD 同代（`find trafficgen -name '*.go' -newer <server-binary>` 无输出）。
4. **本版实测边界（诚实声明）**：本版**未跑 `CASE_PROTO=gre` 套件**，也未起服务端——§3 的"全绿"结论来自**对 `/tmp/mcp-pcaps/gre/` 已落盘 pcap 的离线逐条复算**（`tshark -r` + 逐 offset 比对 + 校验和独立复算），**不等于**"今日经 MCP 端到端跑通"。**G-GRE-7/G-GRE-8 两缺口即为此边界**。
5. 任何 RFC 条款号的具体引用须有规范原文证据（本版引用 RFC 2784 §2/§3.1、RFC 2890 §2.1/§2.2/§3/§4、RFC 6936 §2、IEEE 802.1Q §3，均可回原文）。

## 7. 存量审计（21 例逐条去向）

### 7.1 存量实测面（2026-09-29）

`cases/gre.json` **21 例**：14 正（**14/14 含 `min_packets`，实测帧数精确相等**）+ 7 负（**7/7 `expect` 严格两键 `{expect_error, error_contains}`**，**无 `notes`**）；`spec_json` 顶层键 = `{layers}` ×20 + `{layers,count}` ×1（唯一 `count` 在负例 `gre_neg_flat`，即判死对象）→ **非负例（14/14）顶层旧键残留 0**；`fields` 37 条 + `frames` 18 条 + `notes` 16 条；`proto` 21/21 = `"gre"`。

**用例级顶层键**：`{id, proto, summary, spec_json, expect}` 恒在 + `{strategy_fc}` 5 例（#3/#16/#17/#18/#21）——`strategy_fc` 是 **harness 字段**（`pcaptest/types.go:80-84` StrategyFC 镜像 MCP `flowControlInput`），**不是 spec 键**，不在 §1 白名单违规之列。

**`notes` 键（16 条）**：只出现在**正例**的 `expect` 里（负例无）——内容为 T-编号溯源与实测口径说明。**正例带 `notes` 不违反负例纯净性**（§7 负例纪律只管 `expect_error` 用例）。

### 7.2 现状矛盾点（诚实登记）

1. **本版未端到端跑套件**：§3 全绿来自离线复算（§6 第 4 条）。**G-GRE-8** 的结果文档 21/21 未经今日复跑证实；**G-GRE-7** 的 6 例负例无落盘物证。
2. **第三源未取到**：真实路由器/内核实现线字节未抓 → **G-GRE-6**。若取到后与 RFC 有出入，**全部 C/K/S 用例的 frame 断言需重钉**（本版 §3 已给出复算基线值可作对照）。
3. **`gre.sequence_number` 字段今日未用**：#8 用 frames 双钉（@38 首 0 / 末 8）替代——**不是被迫，是未收编**（本版实测该字段可用且值为 `0…8`）→ A′（§5.5）。
4. **R 位（Routing）层内不可达**：`GREConfig` 与 builder 都支持，缺的是 registry 键 → **G-GRE-1**。
5. **`ip.protocol` FieldContract 是死配置**（6 层同款）→ **G-GRE-2**。
6. **`CheckProtoFlat` 无 gre presence 分支** → **G-GRE-4**（今日建 presence 负例会**真绿 = 假通过**，故不建）。
7. **`docs/protocol-designs/INDEX.md` 无 gre 条目** → 主线程补录（本车道不碰该文件）。

### 7.3 逐条去向表（21 行）

| 存量 id | T-编号 | 去向 | 备注 |
|---|---|---|---|
| `gre_basic_ipv4` | T1 | **保留** | 形状合规（纯 layers）；可补 `gre.flags.*` 位分解断言 |
| `gre_neg_flat` | T2 | **保留** | 严格两键；锚词含键名 `count`（精确命中证据） |
| `gre_neg_static_copy` | T3 | **保留** | 严格两键 |
| `gre_neg_dyn_key` | T4 | **保留** | 严格两键 |
| `gre_v6_in_v6` | T5 | **保留** | 形状合规；可补 `ipv6.dst` 断言 |
| `gre_6in4` | T6 | **保留** | 内外分离正例；可补 `ipv6.dst` |
| `gre_4in6` | T7 | **保留** | 内外分离正例；可补 `ip.dst` |
| `gre_sequence_multi` | T8 | **保留** | 可补 `gre.sequence_number` distinct 断言（替代 frames 双钉） |
| `gre_checksum` | T9 | **保留** | 可补 `gre.checksum.status=1` 断言 |
| `gre_key` | T10 | **保留** | 可补 `gre.flags.key=1` 断言 |
| `gre_kcs_combo` | T11 | **保留** | 可补 `gre.flags.*` 三位置位断言 |
| `gre_inner_ttl` | T12 | **保留** | 无 field 断言（同名聚合），frames 双钉正确 |
| `gre_neg_inner_dyn` | T13 | **保留** | 严格两键；双侧执法 |
| `gre_neg_inner_mixed` | T14 | **保留** | 严格两键；**唯一有 `.neg.pcap` 物证的负例** |
| `gre_vlan_tagged` | T15 | **保留** | 形状合规 |
| `gre_outer_ip_dynamic` | T16 | **保留** | distinct 二元组串语义已在本版 §3.11 写清 |
| `gre_inner_udp_dynamic` | T17 | **保留** | — |
| `gre_inner_tcp_dynamic` | T18 | **保留** | `distinct_exclude` 语义已写清 |
| `gre_neg_dyn_sequence` | T19 | **保留** | 严格两键 |
| `gre_neg_dyn_checksum` | T22 | **保留** | 严格两键；T-GRE-20 作废后的替换例 |
| `gre_outer_ip_rand` | T21 | **保留** | rand 策略覆盖 |

**无"作废不注原因"：0 作废（T-GRE-20 是文档编号作废，非存量用例作废——其替换例 `gre_neg_dyn_checksum` 在存量中），0 等价覆盖（21 例全部保留 + A′ 新增候选 14 条）。**

## 8. 覆盖反查门建议断言行（供主线程合后登记；本车道不碰 `coverage_gate.py`）

建议在主线程合入后，于 `coverage_gate.py` 新增 `check_gre(cases)`（**当前无该函数**——`grep -n "check_gre\b" coverage_gate.py` = 0 命中，机读实测），登记下列断言（**每条均可从本契约与 cases JSON 直接机读，不需新造事实**）：

| # | 建议断言 | 依据 |
|---:|---|---|
| 1 | `len(cases['gre']) == 21` 且 ID 集合 = §2 二十一项，顺序一致 | 本契约 §2 |
| 2 | 21/21 例 `proto == "gre"` | 本契约 §1 |
| 3 | **非负例** `spec_json` 顶层键 == `{layers}`（**零游离键**；负例 `gre_neg_flat` 的 `count` 是判死对象，**白名单例外须显式列出**） | 设计 §12.1 |
| 4 | 14 正例 `min_packets` ∈ `{1,2,9,18}` 且与链形一致（`[ip,gre,ip,udp,dns]`→1 或 2；`[ip,gre,ip,tcp,http]`→9 或 18） | 本契约 §3 |
| 5 | 7 负例 `expect` 键 == `{expect_error, error_contains}`（**严格两键，无 `notes`**） | 本契约 §4 |
| 6 | 负例 `error_contains` ∈ 代码锚词集 `{"no longer accepts flat config field count", "static four-tuple", "does not support dynamic", "inner ip layer does not support dynamic", "must be the same IP version"}` | 设计 §7 |
| 7 | `gre_neg_flat` 的 `spec_json` 含顶层 `count`（**唯一允许含旧键的例**，且该键是判死对象） | 设计 §12.1 |
| 8 | 正例 `frames` 断言的 `offset` ∈ `{12,14,22,34,38,42,46,58,78,98}`（本协议全部合法偏移集，VLAN +4 档已含） | 本契约 §3 |
| 9 | 每正例至少一条断言落在 GRE 头或其内层（`gre.*` field 或 frames offset ≥34） | 本契约 §3 |
| 10 | 层链形状 ∈ `{[ip,gre,ip,udp,dns], [ip,gre,ip,tcp,http], [vlan,ip,gre,ip,udp,dns]}`（**三形闭集**） | 本契约 §1 |
| 11 | 含 `strategy_fc` 的例数 == 5，且 `value == 2`（多流例全用 flows=2） | 本契约 §1 |
| 12 | `gre` 层 config 键 ⊆ `{key, checksum, sequence}`（registry `Fields` 3 键闭集） | 设计 §0.1 |

**另注意**：`docs/protocol-pcap-test/gre.md` 的 21/21 pass 是**过期产物**（G-GRE-8，末次提交 `793dfee` 2026-09-19 早于本版 2026-09-29；`docs/protocol-pcap-test/gre/` 0 个 pcap），**不得作为"今日已复跑"依据**（口径与 opcua G-OPCUA-10 / pcep G-PCEP-11 一致）。**但 gre 的 21 例今日应可跑**（21/21 顶层键合规 + 本版离线复算全绿）——该提醒**仅限**"数字未经今日复跑证实 + 无 pcap 留档"，**不得读成"套件不可跑"**。

## 9. 修订记录

- v1.0.0（2026-09-29）：批次二 as-built 文档轨 P1–P3 首版。**存量 21 例机读审计**（14 正 + 7 负；`spec_json` 顶层键 `{layers}`×20 + `{layers,count}`×1 → **非负例 14/14 零残留**）；**21 例 pcap 离线逐条实测复算**（14 条 `min_packets` 精确相等 + 37 条 field + 18 条 frame **全绿**；`_ws.malformed` 0 命中；checksum status 全 good）；**GRE 校验和独立复算两例**（0xfb89 / 0x62dd 均吻合——交叉验证 C→R→K→S 可选字段顺序）；§2 逐 ID 索引表（含 T-编号对照与 T-GRE-20 作废说明）；§3 十四条正例逐项断言契约（含内外族四格、旗标位耦合、可选字段顺序双重实证、TTL 同名聚合处理、VLAN 偏移 +4、distinct 二元组串语义、`distinct_exclude` 必要性）；§4 负例契约（7/7 锚词 + 原子性 + 纯净性 + 双侧执法）；§5 三源回指 + 对账四表（79 点 = 覆 53 + A′ 8 + 不解决 9 + 不适用 9）+ 缺口 **G-GRE-1…G-GRE-8** + §3.14/§3.15 豁免审计；§6 执行建议（含**本版实测边界诚实声明**：未端到端跑套件）；§7 存量审计 21 行去向（**0 作废**）；§8 覆盖反查门建议 **12 行**（`check_gre` 当前不存在）。自审 3 轮，末轮干净。
