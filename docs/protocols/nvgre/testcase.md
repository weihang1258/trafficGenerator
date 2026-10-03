# #97 nvgre（网络虚拟化 GRE）测试用例契约

> 版本：v1.0.0（P-PIPE 文档轨 P1–P3）
> 日期：2026-09-28
> 配套设计：`docs/protocols/nvgre/design.md` v1.0.0（D-NVGRE-1）
> 旧基线：`docs/protocols/nvgre/_archive_55-nvgre-testcase.md` v1.0.0（20 例；思路继承不搬码）
> 机器契约：`trafficgen/test/protocol_pcap/cases/nvgre.json`（20/20 ID 与本版 §2 一致，顺序一致，已机读实测；**本版保持原样未改**——存量 20/20 今日**全量失效（0 pass）**：扁平形被 `CheckProtoFlat` 拒、层链形被 `unknown field` 拒，两路皆红；顶层旧键 **56 处**残留（**非负例口径**：14 正例 × 4 键 src_ip/dst_ip/count/nvgre，各 14）；迁移**全部落在代码阶段**，G-NVGRE-1）
> 白话一句：**二十条检查：十四条看正常封装（单租户、跨代网段、多租户、多流、内层带 VLAN、大帧、边界值），六条看胡来能不能被拦下；每条只查一件事。关键形状：它不走 UDP、没有端口——信封上只有 GRE 号和 VSID 编号。**

## 1. 测试原则和形状基线

用例从设计 §3–§9 逐项派生，共 **20 个唯一语义 ID：14 正 + 6 负**（继承旧稿计数，负例 N-1…N-6）。派生规则：设计 §3 每个线格式条款、§5 每个事务/展开行为、§7 每行错误处理在本文有对应断言；断言不得超出设计声明范围。**一个用例只验证一个协议行为**。

**形状基线（机读实测，2026-09-28；本版 cases 保持原样）**：20/20 例顶层键 = `{expect,id,proto,spec_json,summary}`（**`notes` 住 `expect` 内**，非顶层——顶层键并集机读无 `notes`）；`spec_json` 顶层键 = `{src_ip, dst_ip, count, nvgre}` ×20（**56 处旧扁平残留**，**非负例口径**：14 正例 × 4 键，各 14；全例口径 80，门脚本 8 键口径 60——见设计 §12.1 口径对账）；**20/20 无 `layers` 键**（链来自已注册 `ChainPlanner` 的 `completedChainUncached`/`completeSynthesized`，`chain_planner_chain.go:59-107`——**非** `BuildLayersPlanner`，后者要求 `layers` 键 `validate_layers.go:23`）；**20/20 无 `src_port`/`dst_port`**（nvgre 无端口概念，设计 §2）；14 正例 `expect` 均含 `packet_count`（分布 1×11 + 3×2 + 2×1 = 14）；6 负例 `expect` 键集合严格为 `{expect_error,error_contains}`（干净）。

**目标形状（代码阶段后）**：`spec_json` 顶层键 = `{layers}`，层链 `[ip,nvgre]`，顶层旧键 0（详见设计 §12.1 去向表）。**本版不改**——层为空壳（`registry.go:1697` 无 Fields + `translate :852` 提前返回 + 无 `case "nvgre"`），改成层链形今日只会硬红（`complete.go:293` unknown field），不构成有效覆盖；迁移与断言重钉一并推后（G-NVGRE-1，§8）。

**层形状基线（与同族对照，设计 §2）**：nvgre 是 **raw-IP 终结层 `[ip,nvgre]`**，**不是** vxlan/geneve 的 `[ip,udp,<proto>]`。故用例**不得**含 `layers[udp]`、不得写 `udp.dst_port`、不得引用 4789/6081 端口。

**输出契约（pcap/NIC 双输出）**：两路径共用同一 cases JSON 与断言集（`ip.proto`、`gre.flags_and_version`、`gre.proto`、`eth.*`、`vlan.*`、`frames[].hex`）；NIC 经 tcpdump 捕获（`nic_capture` 用例级开关）；不设仅单路径可用的断言。NIC 侧允许 checksum offload 差异，GRE flags/protocol/Key/inner 字节不得放宽。

**TSHARK 基线**：本机 tshark 3.6.14 **有** `gre.*`（`gre.proto`/`gre.flags_and_version`/`gre.key`）、`eth.*`/`ip.*`/`ipv6.*`/`vlan.*`；**无 `nvgre.*` dissector**——**不得使用任何 `nvgre.*` 字段**。主锚为 `frames[].hex` raw 字节（偏移见设计 §2），tshark 字段为辅证。

**动态字段禁止硬编码**：生成期值用 `same_as_packet`/`distinct_values`/`nonzero` 断言（#7/#8 的 Key/eth 聚合已用）。

**包数约定**：单 flow 每 datagram 一包（**无握手挥手**，与 moxa 的 `3+N+4` 公式不同）。#1–#6、#9、#10、#12–#14 = 1 包（11 例）；#7/#8 = 3 包（2 例，`datagrams[]` 3 条）；#11 = 2 包（1 例）——合计 11+2+1 = 14 正例。实现期以实际输出校准 `packet_count`，断言以 fields/frames 为准；负例无 `packet_count`。

**无连接口径**：NVGRE 无握手/保活/重试/挥手语义（设计 §4 显式不适用）——不设握手正例、不设保活例、不设 RST 例；正例恒"发完即结束"。

## 2. 原子用例索引（20 ID = 14 正 + 6 负，顺序为权威）

| # | ID | 类型 | 覆盖（设计 §） | packet_count |
|---:|---|---|---|---:|
| 1 | `nvgre_basic_ipv4_inner_ipv4` | 正 | §3.1/§3.2/§3.4：outer v4 + GRE + inner Ethernet/IPv4 | 1 |
| 2 | `nvgre_outer_ipv6_inner_ipv4` | 正 | §3.4：outer v6（NH=47）+ inner IPv4 | 1 |
| 3 | `nvgre_outer_ipv4_inner_ipv6` | 正 | §3.2：outer v4 + inner IPv6（EtherType 0x86dd） | 1 |
| 4 | `nvgre_basic_ipv6_inner_ipv6` | 正 | §3.4：outer/inner IPv6 独立 fixture | 1 |
| 5 | `nvgre_vsid_zero_flow_zero` | 正 | §3.1：VSID=0/FlowID=0 显式保留 | 1 |
| 6 | `nvgre_vsid_max_flow_max` | 正 | §3.1：VSID=0xffffff/FlowID=0xff 不截断 | 1 |
| 7 | `nvgre_multi_vsid` | 正 | §5：多 VSID，Key 高 24-bit 隔离 | 3 |
| 8 | `nvgre_multi_flow_same_vsid` | 正 | §5：同 VSID 多 Flow ID，低 8-bit 隔离 | 3 |
| 9 | `nvgre_inner_vlan` | 正 | §3.2：内层 802.1Q（TPID/TCI/VID） | 1 |
| 10 | `nvgre_inner_ethernet_boundary` | 正 | §3.2/§8：广播 MAC、空 payload、Ethernet 边界 | 1 |
| 11 | `nvgre_outer_inner_family_matrix` | 正 | §4：族矩阵（内层二分；外层由 #2/#4 覆盖） | 2 |
| 12 | `nvgre_mtu_reassembly` | 正 | §3.3/§8：大内层帧完整单帧 + Key raw 字节 | 1 |
| 13 | `nvgre_pcap_nic_consistency` | 正 | §1：pcap/NIC 同一断言集 | 1 |
| 14 | `nvgre_key_endian_and_ttl` | 正 | §3.1/§8：Key 网络字节序 + TTL=255 边界 | 1 |
| 15 | `nvgre_neg_gre_flags_protocol` | 负 | §7 N-1：GRE flags/reserved/version 非法 | — |
| 16 | `nvgre_neg_key_vsid_flow` | 负 | §7 N-2：VSID > 24-bit | — |
| 17 | `nvgre_neg_inner_ethernet_vlan` | 负 | §7 N-3：非法 inner MAC | — |
| 18 | `nvgre_neg_address_family` | 负 | §7 N-4：inner EtherType/地址族不匹配 | — |
| 19 | `nvgre_neg_carrier_length` | 负 | §7 N-5：长度回绕 | — |
| 20 | `nvgre_neg_vsid_flow_isolation` | 负 | §7 N-6：跨 VSID/Flow 状态串用 | — |

T-编号对照：T-NVGRE-S1…S14 ≡ #1…#14；T-NVGRE-N1…N6 ≡ #15…#20（与设计 §9 一一对应）。

## 3. 正例逐项断言契约（最低断言集，实现期可增不可减）

每例均含 `packet_count` + GRE/载体断言 + raw frames 断言。**偏移常量**（设计 §2）：outer IPv4 时 GRE flags=34 / Key=38 / inner DstMAC=42 / inner EtherType=54；outer IPv6 时 54 / 58 / 62 / 74。payload `bnZncmUtaW5uZXItMDE=` = `nvgre-inner-01`（hex `6e 76 67 72 65 2d 69 6e 6e 65 72 2d 30 31`）；`bnZncmUtdnNpZGEtcGF5bG9hZA==` = `nvgre-vsida-payload`（hex `6e 76 67 72 65 2d 76 73 69 64 61 2d 70 61 79 6c 6f 61 64`）。

### 3.1 `nvgre_basic_ipv4_inner_ipv4`（1）

VSID=1000/FlowID=1 → Key `00 03 e8 01`。断言：`ip.proto` 值集含 `47`（外层）+ `253`（内层，RFC 3692 未指派，设计 §3.2）；`gre.flags_and_version=0x2000`；`gre.proto=0x6558`；`eth.src` 值集 `{02:00:00:00:00:01, 02:aa:00:00:00:01}`（外层 + 内层）；`eth.dst` 值集 `{02:00:00:00:00:02, 02:bb:00:00:00:01}`；`ip.src` 值集 `{192.0.2.10, 172.16.1.1}`。frames：offset 34 `20 00 65 58`、offset 38 `00 03 e8 01`、offset 42 `02 bb 00 00 00 01`、offset 48 `02 aa 00 00 00 01`、offset 54 `08 00`。**主锚 = frames raw 字节**（Key 字节序不依赖 tshark `gre.key` 渲染格式，设计 §0 表 #7）。

### 3.2 `nvgre_outer_ipv6_inner_ipv4`（1）

VSID=2000/FlowID=2 → Key `00 07 d0 02`。断言：`ipv6.nxt=47`（外层）；`gre.proto=0x6558`；`eth.type` 值集 `{0x86dd, 0x0800}`（外层 IPv6 + 内层 IPv4）。frames：offset 54 `20 00 65 58`、offset 58 `00 07 d0 02`、offset 62 `02 bb 00 00 00 02`、offset 74 `08 00`。**不得套用 IPv4 的 34/38/42**。

### 3.3 `nvgre_outer_ipv4_inner_ipv6`（1）

VSID=3000/FlowID=3 → Key `00 0b b8 03`。断言：`gre.proto=0x6558`；`eth.type` 值集 `{0x0800, 0x86dd}`；内层 `ipv6.src/dst` = `fc00::1`/`fc00::2`。frames：offset 34 `20 00 65 58`、offset 38 `00 0b b8 03`、offset 42 `02 bb 00 00 00 03`、offset 54 `86 dd`。内层 IPv6 由 `inner.ether_type` 独立选择，**不被 outer IPv4 改写**。

### 3.4 `nvgre_basic_ipv6_inner_ipv6`（1）

VSID=4000/FlowID=4 → Key `00 0f a0 04`。断言：`ipv6.nxt` 值集 `{47, 59}`（外层 proto 47 + 内层 No Next Header 59，设计 §3.2）；`eth.type` 值集 `{0x86dd, 0x86dd}`；`ipv6.src` 值集 `{2001:db8::30, fd00::1}`。frames：offset 54 `20 00 65 58`、offset 58 `00 0f a0 04`、offset 62 `02 bb 00 00 00 04`、offset 74 `86 dd`。

### 3.5 `nvgre_vsid_zero_flow_zero`（1）

VSID=0/FlowID=0 → Key `00 00 00 00`。断言：`gre.key` 为 0；frames offset 38 `00 00 00 00`。**显式 0 是合法边界值，不得被"空值即默认"覆盖**（设计 §3.1；单测 `TestValidatorBoundariesLegal` 同口径）。

### 3.6 `nvgre_vsid_max_flow_max`（1）

VSID=16777215（0xffffff）/FlowID=255（0xff）→ Key `ff ff ff ff`。断言：`gre.key=0xffffffff`；frames offset 38 `ff ff ff ff`。**24-bit VSID 不得截断为 16 位**。

### 3.7 `nvgre_multi_vsid`（3）

`datagrams[]` 3 条（VSID 1000/300000/16777215，FlowID 均 1），各带独立 `inner` fixture。断言：`gre.key` distinct 值集 `{0x0003e801, 0x0493e001, 0xffffff01}`（高 24-bit 互异）；`eth.src` distinct 值集含三条内层 MAC；`ip.src` distinct 值集含三条内层 IP。frames：packet 1 offset 42 `02 bb 00 00 00 07`。**多包调度顺序非确定性——用 distinct 聚合断言，不逐包定位**。

### 3.8 `nvgre_multi_flow_same_vsid`（3）

`datagrams[]` 3 条（VSID 均 5000，FlowID 1/2/3）。断言：`gre.key` distinct 值集 `{0x00138801, 0x00138802, 0x00138803}`（**高 24-bit 相同、低 8-bit 互异**）；`eth.src` distinct 值集含三条内层 MAC。frames：packet 1 offset 42 `02 bb 00 00 00 10`。

### 3.9 `nvgre_inner_vlan`（1）

`inner.ether_type="vlan_ipv4"`、`vlan_id=100`、`vlan_priority=3` → TCI = `3<<13 | 100` = 0x6064。断言：`eth.type` 值集 `{0x0800, 0x8100}`；`vlan.id=100`；`vlan.priority=3`。frames：offset 42 `02 bb 00 00 00 13`（inner DstMAC）、offset 54 `81 00 60 64`（TPID + TCI）、offset 58 `08 00`（**VLAN 后 EtherType 后移 4B**）。**内层 VLAN 不是外层 VLAN**。

### 3.10 `nvgre_inner_ethernet_boundary`（1）

`inner.dst_mac="ff:ff:ff:ff:ff:ff"`（显式广播）、`payload_b64=""`（空 payload 合法）。VSID=7000/FlowID=0 → Key `00 1b 58 00`。断言：`eth.dst` 值集 `{02:00:00:00:00:02, ff:ff:ff:ff:ff:ff}`；`eth.type` 值集 `{0x0800, 0x0800}`。frames：offset 42 `ff ff ff ff ff ff`、offset 48 `02 aa 00 00 00 14`、offset 54 `08 00`。**显式广播 MAC 原样落，不得改写**；空 payload 下 inner 帧 = 14B eth + 20B ip = 34B。

### 3.11 `nvgre_outer_inner_family_matrix`（2）

`datagrams[]` 2 条（VSID 1 + inner v4；VSID 2 + inner v6）。断言：`gre.key` distinct 值集 `{0x00000101, 0x00000201}`；`eth.type` distinct 值集 `{0x0800,0x0800}` 与 `{0x0800,0x86dd}`。frames：packet 1 offset 34 `20 00 65 58`。**口径声明**：外层族是 flow 级属性（由 `ip` 层地址字面量决定），同一 flow 内无法在 datagram 间切换外层 v4/v6——本用例覆盖**内层族二分**；外层 v6 组合由 #2（v6 外层 + v4 内层）与 #4（v6 外层 + v6 内层）覆盖，四组合齐备。

### 3.12 `nvgre_mtu_reassembly`（1）

大内层 payload（`bnZncmUtbXR1LWxhcmdlLWZyYW1lLWNoZWNr` = `nvgre-mtu-large-frame-check`，**27B**）。VSID=1193046（0x123456）/FlowID=122（0x7a）→ Key `12 34 56 7a`。断言：`gre.key=0x1234567a`；`eth.src` 值集 `{02:00:00:00:00:01, 02:aa:00:00:00:17}`。frames：offset 38 `12 34 56 7a`、offset 68 `ac 10 11 01`（内层 IP 源地址 172.16.17.1）、offset 76 = payload 全 **27** 字节 hex。**本版不做底层 IP 分片**：大内层帧作完整单帧发出；分片面按长度上界拒绝表达（设计 §8，G-NVGRE-7）。

### 3.13 `nvgre_pcap_nic_consistency`（1）

VSID=11259375（0xabcdef）/FlowID=17 → Key `ab cd ef 11`。断言：`ip.proto` 含 47；`gre.key=0xabcdef11`；`eth.src`/`eth.dst` 值集含内层 MAC。frames：offset 38 `ab cd ef 11`、offset 42 `02 bb 00 00 00 18`、offset 76 = payload hex。**NIC 侧一致性命中由外部编排**（本驱动产出 PCAP 侧；NIC 侧经 `nic_capture` 独立驱动后比对同一 fixture 的 Key/inner 前缀）。

### 3.14 `nvgre_key_endian_and_ttl`（1）

VSID=0x123456/FlowID=0x7a + `ttl=255`。断言：`ip.ttl` 值集 `{255, 64}`（外层 255 + 内层 64）；`gre.key=0x1234567a`。frames：offset 34 `20 00 65 58`、offset 38 `12 34 56 7a`、offset 42 `02 bb 00 00 00 19`。**Key 网络字节序不交换**；**TTL=255 经外层 IPv4 上线上可观测**。注：TTL=0 与 hop-limit=0 因 builder 对 0 的默认化（当未设置→64）线上无法表现——属框架偏差，登记为 A′（设计 §8），**不得**据此建断言。

**正例总则**：VSID=0/FlowID=0、空 payload、显式广播/组播 MAC、`vlan_id=0`、TTL=255 均为正例形态；只有配置/线格式/长度/关联错误进入负例。

## 4. 负例契约

负例必须在 validator 阶段失败并传播为 task error，不得产生成功 PCAP、`completed/0 packet` 或只剩外层 IP/GRE 的假成功；`expect` 键集合**严格为** `{expect_error,error_contains}`。锚词与设计 §7 表一一对应、同序，取自 `layer_gen.go` 错误字面值：

| ID | 故障输入 | `error_contains` | 代码出处 |
|---|---|---|---|
| `nvgre_neg_gre_flags_protocol` | `wire_fault.kind="flags_reserved"` | `flags` | `layer_gen.go:307` |
| `nvgre_neg_key_vsid_flow` | `vsid=16777216`（> 24-bit） | `vsid` | `layer_gen.go:279` |
| `nvgre_neg_inner_ethernet_vlan` | `inner.src_mac="not-a-mac"` | `inner` | `layer_gen.go:335` |
| `nvgre_neg_address_family` | `inner.ether_type="ipv6"` + `inner.src_ip` 为 IPv4 | `family` | `layer_gen.go:368` |
| `nvgre_neg_carrier_length` | `wire_fault.kind="length_wrap"` | `length` | `layer_gen.go:319` |
| `nvgre_neg_vsid_flow_isolation` | `wire_fault.kind="vsid_flow_isolation"` | `isolation` | `layer_gen.go:315` |

**负例原子性**：每例单一故障注入；单次执行不得混注。

**wire_fault 全 kind 表**（`layer_gen.go:259-268`，7 种）：`flags_reserved` / `protocol_not_teb` / `key_missing` / `key_endian` / `vsid_flow_isolation` / `carrier_protocol` / `length_wrap`；未知 kind 亦拒（`:321`）。**存量仅用 3 种**（N-1/N-5/N-6），余 4 种 A′ 立项（§6.2）。

**不得误报的合法协议事件**：VSID=0/FlowID=0（#5）、VSID 满值（#6）、空 payload（#10）、显式广播 MAC（#10）、`vlan_id=0`、TTL=255（#14）。

## 5. 覆盖与对账

### 5.1 三源回指行

RFC 7637（NVGRE）+ RFC 2784/2890（GRE 基础头/扩展）+ D-NVGRE-1（设计 §11）+ tshark `gre.*`/frames 通道实测（`nvgre.*` 零 dissector）→ 20 ID（本契约 §2）。第三源"已确认现网行为"当前 = **未确认级**（G-NVGRE-8，按 §5.5 不写死进实现）。控制面（NHRP/端点发现）与加密/私有扩展不进入本批用例；分别登记 G-NVGRE-10/G-NVGRE-11，待取得规范或现网证据后补定义与断言。

### 5.2 9.52 对账两行 + 清单出处声明

- **清单出处声明**：本清单来源 = **RFC 7637/2784/2890 + 旧基线契约 + 仓库落码反推 + tshark 通道实测**（nvgre 无独立 tshark dissector，`nvgre.*` 零字段），**非纯规范反推**。raw 字节通道见设计 §2（offset 34/38/42/54 与 54/58/62/74 机读口径）。
- **对账两行**：**要求逻辑点总数 = 70**（八项 8 行 + 矩阵 12 格 + 变体 22 行 + 商业映射 8 行 + 用例形状 20 点〔20 ID，每 ID 一个不可再分测试点〕）；**用例覆盖数 = 53**（八项已覆 5 + 矩阵已覆 7 + 变体已覆 15 + 商业已覆 6 + 形状已覆 20）；**不适用 = 5**（八项 3：状态机/超时活性/NAT 被动；商业 2：控制面/加密扩展）。53 + 5 + 12 = 70；**开放 12 = 矩阵 A′ 5（B1T3/B2T3/B3T3/B4T1/B4T3）+ 变体 A′ 7（行 7/9/13/16/20/21/22）**，即立项覆盖（§9.36 口径，不冒充今日可跑）。**交叉校验**：开放 12 与 §10.2/§10.3 两表 A′ 计数逐格相符。
  **粒度声明**：行/格/ID 粒度每点 1 计；各表"已覆"按表分别计数（同一用例可同时覆盖多表点位，属正常形态——覆盖审查"该点有没有例"，不做跨表去重）；G-NVGRE-1…G-NVGRE-9 不折进 70；设计 §4"次要合法行为"3 项为显式不适用声明（非四表行），单列不计入。**反查全绿 ≠ 覆盖全**（§9.52 原文）。
- **门3 抽查候选**：最复杂用例 = **#7 `nvgre_multi_vsid`**（3 datagram × 独立 VSID × 独立 inner fixture × Key 高 24-bit 隔离 × distinct 聚合）；交织维度 = datagram(3)×VSID(3)×inner fixture(3)×Key 字节段×聚合断言。若按 9.49/9.50 下限偏弱在"异常注入"面，**建议门3 抽 #7 + #9**（`nvgre_inner_vlan` 补 VLAN 偏移面）。

### 5.3 T-编号与旧 id 对照（设计 §9 全表摘要）

`nvgre_basic_ipv4_inner_ipv4` ≡ T-NVGRE-S1；`nvgre_outer_ipv6_inner_ipv4` ≡ T-NVGRE-S2；`nvgre_outer_ipv4_inner_ipv6` ≡ T-NVGRE-S3；`nvgre_basic_ipv6_inner_ipv6` ≡ T-NVGRE-S4；`nvgre_vsid_zero_flow_zero` ≡ T-NVGRE-S5；`nvgre_vsid_max_flow_max` ≡ T-NVGRE-S6；`nvgre_multi_vsid` ≡ T-NVGRE-S7；`nvgre_multi_flow_same_vsid` ≡ T-NVGRE-S8；`nvgre_inner_vlan` ≡ T-NVGRE-S9；`nvgre_inner_ethernet_boundary` ≡ T-NVGRE-S10；`nvgre_outer_inner_family_matrix` ≡ T-NVGRE-S11；`nvgre_mtu_reassembly` ≡ T-NVGRE-S12；`nvgre_pcap_nic_consistency` ≡ T-NVGRE-S13；`nvgre_key_endian_and_ttl` ≡ T-NVGRE-S14；`nvgre_neg_gre_flags_protocol` ≡ T-NVGRE-N1；`nvgre_neg_key_vsid_flow` ≡ T-NVGRE-N2；`nvgre_neg_inner_ethernet_vlan` ≡ T-NVGRE-N3；`nvgre_neg_address_family` ≡ T-NVGRE-N4；`nvgre_neg_carrier_length` ≡ T-NVGRE-N5；`nvgre_neg_vsid_flow_isolation` ≡ T-NVGRE-N6。

## 6. P3 固定动作（CORE_MEMORY 管线：§3.15 三项 + A′/B′ 两分类 + 3.14 豁免）

### 6.1 §3.15 三项逐项一例或立项

| # | 三项 | 本协议对照 | 用例/立项 |
|---|---|---|---|
| ① | 同连接/同流内的多轮操作 | 单 flow 内多 datagram（#7/#8 各 3 条，`datagrams[]` 顺序展开） | 已覆 #7/#8 |
| ② | 非正常结束 | NVGRE 无连接 → 无 FIN/RST 语义（设计 §4 显式不适用）；异常面 = 配置/线格式拒绝 | 已覆 N-1…N-6（6 条）；**无 A′ 补例**（无异常终止报文可测） |
| ③ | 长保活 | 协议层无 keepalive 语义（设计 §4 显式不适用）；长会话 = 单 flow 多 datagram | #7/#8 承载（3 datagram） |

无空项：① 有 #7/#8；② 有 6 条负例（无连接故无终止报文类，如实声明）；③ 有 #7/#8。

### 6.2 A′/B′ 两分类表

**A′（P4 接线）**：

| 类 | 内容 | 落点 |
|---|---|---|
| 层链化 | registry `Fields` 补 6 键 + translate `case "nvgre"` 层内分支 | G-NVGRE-1，用例 #1–#20 全依赖 |
| presence 面 | **计划负例** `nvgre_neg_presence_top_level_nvgre`（本批 JSON 不含，避免 G-NVGRE-2 未闭环时假绿；层链 + 顶层同名空子映射并存形必须原样保留为后续拒绝证据） | G-NVGRE-2 |
| fault 面 | 4 种未用 fault（`protocol_not_teb`/`key_missing`/`key_endian`/`carrier_protocol`）各一例 | G-NVGRE-4 |
| 方向面 | `datagrams[].up=false` 方向变体 + entry `inner` 缺席回退顶层 | G-NVGRE-5 |
| 组合面 | 外层 v6 + 内层 `vlan_ipv6`；VLAN 边界（VID 0/4095、PCP 7） | G-NVGRE-6 |
| 长度面 | inner payload 超上界拒绝（validator `:384` 分支） | G-NVGRE-6 |
| 白名单面 | 顶层游离键判死（`unknown field`） | G-NVGRE-2 同批 |
| 现网面 | VSID-FlowID 分配实践实证 | G-NVGRE-8 |
| 分片面 | 旧稿 §9 #12 IP 分片/重组 | G-NVGRE-7（当前生成器仅发完整单帧，需补分片驱动、重组语义与用例后迁入） |

**B′（框架面）**：`CheckProtoFlat` nvgre presence 分支（G-NVGRE-2，等框架级 unknown-key 白名单，不单独立项）/ 业务字段动态（G-NVGRE-3，allowlist 无 `nvgre` 行）。登记为后续代码立项，当前不冒充覆盖。

### 6.3 3.14 豁免边界审计

无长连接载体 → 不声明会话测试；多 datagram 展开 #7/#8 提供同一流内多动作，单包多载荷不适用（一个 NVGRE 包承载一个内层 Ethernet 帧）。

## 7. 实现后执行建议

1. **代码阶段顺序（本版全部推后，§8.2）**：G-NVGRE-1（registry Fields + translate `case "nvgre"` + schemagen 重跑）→ 20 例改写为纯层链形（删顶层 `src_ip`/`dst_ip`/`count`，`nvgre` 子映射迁层内）→ 先跑后钉 20 例 → 补 presence 负例（**先补 G-NVGRE-2 分支**）→ 补 A′ 例 → 全量复跑。**本版不动 cases**：层为空壳，改了只会硬红。
2. **实测顺序**：先 #1/#5/#6（GRE 头 + Key 边界与 1 包基线），再 #7/#8（多 datagram distinct 聚合），再 #9（VLAN 偏移 54/58），再 #2/#4（IPv6 外层 offset 54/58/62/74），最后 #12（大帧 payload hex）。
3. 二进制与 HEAD 同代确认（门2③：`find trafficgen -name '*.go' -newer <server-binary>` 无输出）；门2② 全量（`CASE_PROTO=nvgre` 全量不是增量）；门2④ 反查绿后进 P6。
4. 任何现网 VSID-FlowID 分配的具体断言须有独立抓包/文档证据和失败优先测试（设计 §1 ⑤ 纪律）。

## 8. 存量审计与缺口登记（20 例逐条去向 → **全部转缺口**）

### 8.1 存量实测面（2026-09-28，机读）

`cases/nvgre.json` **20 例**：14 正带 `packet_count`（**1×11**、3×2、2×1 = 14，全符合「每 datagram 一包」公式）；6 负 `expect` 键集合严格 `{expect_error,error_contains}`；20/20 含顶层 `src_ip`/`dst_ip`/`count` + 顶层 `nvgre` 子映射（**56 处残留**，**非负例口径**：14 正例 × 4 键，各 14；详见设计 §12.1 口径对账）；20/20 **无 `layers` 键**；20/20 无 `src_port`/`dst_port`（nvgre 无端口，此点存量已合规）；3 例用 `wire_fault`（`flags_reserved`/`length_wrap`/`vsid_flow_isolation`）。

### 8.2 为什么 20 例**全部**转缺口而非本版改写（阻塞级）

nvgre 层是**空壳**，三条实证（任一即足以阻塞）：

1. `registry.go:1697` 的 `nvgre` Register **无 `Fields`**（`DependsOn ["ip"]`，无 FieldContract）→ 生成表 `layers.generated.json` = `{"category":"terminal","depends_on":["ip"],"fields":{}}`。
2. `chain_planner_translate.go:852` `if len(s.Fields) == 0 { return }` → 层内配置**根本不被解码**；且 `translateTerminalConfig` **无 `case "nvgre"`** → `spec.NVGRE` 恒 nil，生成器读 `req.Meta.NVGRE` 落 `defaultFixture()`。
3. `complete.go:279` `ValidateLayerConfig` 对**未知字段即拒**（`unknown field` 返回在 `:293`）→ 层内任何键今日报 `layers: layer "nvgre": unknown field "…"`。

**故「本版不动 cases」有两条理由（缺一即误导读者）**：
- **理由 A（改了会硬红）**：层链形今日被 ③ 硬拒（探针实测 `layers: layer "nvgre": unknown field "flow_id"`）——不是静默走错，也不是有效覆盖。
- **理由 B（不改也已经全红）**：存量扁平形今日**同样全红**——扁平路径已被 `CheckProtoFlat` 关闭（`strategy_convert.go:8625-8637`，对全体协议扫顶层 `src_ip`/`dst_ip`/`src_port`/`dst_port`/`count`，无 nvgre 特判），**20/20 例 submit 一律被拒**。故存量**不是"仍可跑的过渡态"**，而是**全量失效（0 pass）**。

**实跑证据（本车道自跑，2026-09-28）**：
```
CASE_PROTO=nvgre go test ./test/protocol_pcap/ -run TestProtocolPcapDrive -count=1
RESULT: 0 pass, 6 fail, 14 error (of 20)
  nvgre    0/20
```
- 14 正例 = `error`（submit 被拒），拒因 `protocol nvgre no longer accepts flat config field src_ip`。
- 6 负例 = **`fail`——被拒但错误文本不含 `flags`/`vsid`/`inner`/`family`/`length`/`isolation`**，harness 报 `rejected but error "..." does not contain "flags"` 等 6 条（锚词**全部失守**，非正确红）。

**结论**：负例今日**不是"正确红"而是"红在锚词不匹配"**——真正的风险面（锚词全失守）在此，**不得**反向解读为"假绿风险已排除"。

### 8.3 缺口登记表（20 例逐条；全部 = 待代码阶段迁移）

| 存量 id | T-编号 | 缺口 | 阻塞原因 | 代码阶段动作 |
|---|---|---|---|---|
| `nvgre_basic_ipv4_inner_ipv4` | T-NVGRE-S1 | 顶层旧键 3 处 + 无 layers | G-NVGRE-1 | 迁 `layers[ip].src/dst` + `layers[nvgre]`；删 `count`；先跑后钉 |
| `nvgre_outer_ipv6_inner_ipv4` | T-NVGRE-S2 | 同上 | G-NVGRE-1 | 同上；offset 54/58/62/74 复核 |
| `nvgre_outer_ipv4_inner_ipv6` | T-NVGRE-S3 | 同上 | G-NVGRE-1 | 同上；offset 34/38/42/54 复核 |
| `nvgre_basic_ipv6_inner_ipv6` | T-NVGRE-S4 | 同上 | G-NVGRE-1 | 同上 |
| `nvgre_vsid_zero_flow_zero` | T-NVGRE-S5 | 同上 | G-NVGRE-1 | 同上；显式 0 须保留（不得被默认化） |
| `nvgre_vsid_max_flow_max` | T-NVGRE-S6 | 同上 | G-NVGRE-1 | 同上 |
| `nvgre_multi_vsid` | T-NVGRE-S7 | 同上 | G-NVGRE-1 | 同上；`datagrams[]` 内联保留；distinct 聚合复核 |
| `nvgre_multi_flow_same_vsid` | T-NVGRE-S8 | 同上 | G-NVGRE-1 | 同上 |
| `nvgre_inner_vlan` | T-NVGRE-S9 | 同上 | G-NVGRE-1 | 同上；VLAN 偏移 54/58 复核 |
| `nvgre_inner_ethernet_boundary` | T-NVGRE-S10 | 同上 | G-NVGRE-1 | 同上；空 payload/广播 MAC 保留 |
| `nvgre_outer_inner_family_matrix` | T-NVGRE-S11 | 同上 | G-NVGRE-1 | 同上；外层族 flow 级口径注记保留 |
| `nvgre_mtu_reassembly` | T-NVGRE-S12 | 同上 | G-NVGRE-1 | 同上；大 payload 内联；分片口径注记保留（G-NVGRE-7） |
| `nvgre_pcap_nic_consistency` | T-NVGRE-S13 | 同上 | G-NVGRE-1 | 同上；NIC 编排注记保留 |
| `nvgre_key_endian_and_ttl` | T-NVGRE-S14 | 同上 | G-NVGRE-1 | 同上；`ttl:255` 迁 `layers[nvgre].ttl`（**外层 TTL 唯一住处**——生成器读 `cfg.TTL` 而非 `spec.TTL`，`layer_gen.go:169`；`layers[ip].ttl` 对本协议是死配置，设计 §12.12 裁定） |
| `nvgre_neg_gre_flags_protocol` | T-NVGRE-N1 | 同上 | G-NVGRE-1 | 同上；锚词 `flags` 不变 |
| `nvgre_neg_key_vsid_flow` | T-NVGRE-N2 | 同上 | G-NVGRE-1 | 同上；锚词 `vsid` 不变 |
| `nvgre_neg_inner_ethernet_vlan` | T-NVGRE-N3 | 同上 | G-NVGRE-1 | 同上；锚词 `inner` 不变 |
| `nvgre_neg_address_family` | T-NVGRE-N4 | 同上 | G-NVGRE-1 | 同上；锚词 `family` 不变 |
| `nvgre_neg_carrier_length` | T-NVGRE-N5 | 同上 | G-NVGRE-1 | 同上；锚词 `length` 不变 |
| `nvgre_neg_vsid_flow_isolation` | T-NVGRE-N6 | 同上 | G-NVGRE-1 | 同上；锚词 `isolation` 不变 |

**计数**：20/20 转缺口（0 本版改写、0 作废、0 等价覆盖）；迁移后预期顶层旧键 **56 → 0**（**非负例口径**）。

### 8.4 覆盖反查门建议断言行（红项如实标红）

`coverage_gate.py nvgre` 今日输出「该协议检查表未登记：nvgre（不挡路）」。代码阶段落地后，建议在 `trafficgen/tools/coverage_gate.py` 增补以下断言行（**今日全红**，红因即 G-NVGRE-1）：

| # | 建议断言 | 今日状态 |
|---:|---|---|
| 1 | 20/20 例 `spec_json` 顶层键 ⊆ `{layers}`（非负例顶层键 = 0） | **红**（20 例各含 src_ip/dst_ip/count + 顶层 nvgre） |
| 2 | 20/20 例层链形状 == `[ip,nvgre]` | **红**（20/20 无 `layers` 键） |
| 3 | 20/20 例无 `udp` 层 / 无 `src_port`/`dst_port` | **绿**（存量已合规） |
| 4 | 6 负例 `expect` 键严格 `{expect_error,error_contains}` | **绿** |
| 5 | 6 负例锚词**设计值**各命中 `layer_gen.go` 错误字面值 | **绿**（§4 已逐条对码——**仅指设计值**；运行时锚词全失守见 #8） |
| 6 | presence 负例存在且锚词含 `top-level` | **红**（G-NVGRE-2：CheckProtoFlat 无 nvgre 分支，建了会假绿，故未建） |
| 7 | 20 例 ID 与 testcase §2 顺序一致 | **绿** |
| 8 | **存量 20/20 例今日可跑（非全红）** | **红（最严重）**——20/20 submit 一律被 `CheckProtoFlat` 拒（`protocol nvgre no longer accepts flat config field src_ip`），**非负例与负例同等**；实跑 `RESULT: 0 pass, 6 fail, 14 error (of 20)` |
| 9 | 结果产物 `docs/protocol-pcap-test/nvgre.md` 非过期（末次提交晚于判死提交 `0417be5`） | **红**（G-NVGRE-9：末次提交 `c0bf5ec` 2026-08-31 早于 `0417be5` 2026-09-13；且声称 20/20 pass 与今日 0/20 **方向相反**） |

**红项合计 5 行**（#1/#2/#6/#8/#9）：#1/#2/#6/#8 由 G-NVGRE-1/G-NVGRE-2 代码阶段收敛；**#9 由 G-NVGRE-9 收敛（P5 重跑套件后重生成该产物）**。**#8 是当前最严重项**：它不是"待迁移"，而是**存量已全量失效**（负例的 6 条 `fail` 更是锚词失守，非正确红）。**#9 是它的产物面镜像**——套件全红，但 tracked 结果文档仍写 20/20 pass，**该文档不得作为"套件可跑"依据**（同 pcep G-PCEP-11 口径）。

## T1–T6 / C1–C6 静态闭环结论（2026-10-01）

| 门 | 结论 |
|---|---|
| T1 形状与边界 | JSON 实际为旧扁平形；目标 `[ip,nvgre]` 形状与当前空 Fields/translate 缺口分开记载。 |
| T2 原子清单 | 20 个唯一 ID，14 正 + 6 负，顺序与设计 §9 一致；正例包数分布 1×11、3×2、2×1。 |
| T3 正例断言 | 正例均有 packet_count、fields/frames；raw frame 是 Key/偏移主锚，未使用 `nvgre.*` 字段。 |
| T4 负例 | 6/6 `expect` 严格为 `{expect_error,error_contains}`，锚词依次为 `flags/vsid/inner/family/length/isolation`。 |
| T5 审计 | 20/20 无 `layers`、无端口；14 正例旧顶层键 56 处（非负例口径）；G-NVGRE-1 阻塞迁移。 |
| T6 执行计划 | 先补 Fields/translate，再迁移、先跑后钉、全量复跑；本轮不运行 suite、MCP 或 NIC。 |
| C1 | JSON 解析/ID/顺序/正负数量静态核对通过。 |
| C2 | 目标层形明确为 `[ip,nvgre]`，不引入 UDP/4789/6081；存量旧形不冒充合规。 |
| C3 | 14 正例各含 `src_ip/dst_ip/count/nvgre`，负例也保留同一存量形；旧键迁移登记 G-NVGRE-1。 |
| C4 | 负例双键严格检查通过，未把未知层拒绝当协议负例通过。 |
| C5 | offset 34/38/42/54 与 54/58/62/74、Key 大端及 VLAN 后移断言与设计逐项对齐。 |
| C6 | 仅维护本 testcase 文件与指定 JSON 契约；Go/schema/索引/其他文档/运行环境均未改动。 |

静态自审：第一轮逐项核对 T1–T6、20 条 ID、正负比例、层形、断言和 G 缺口；第二轮复核 JSON 实际计数、负例双键、锚词、偏移与边界，末轮干净。

## 9. 修订记录

- v1.0.4（2026-10-01，静态闭环修订）：控制面、私有扩展和分片边界均回指 G-NVGRE-7/G-NVGRE-10/G-NVGRE-11 立项；20 例维持 14 正 + 6 负，未伪造层链迁移或运行证据。自审 2 轮，末轮干净。

- v1.0.3（2026-10-01，静态闭环轮）：新增 §T1–T6/C1–C6 静态闭环结论表；按空 Fields/translate 缺口保持 20 条存量 JSON，不机械迁移或运行 suite。自审 2 轮，末轮干净。


- v1.0.0（2026-09-28）：P-PIPE #97 文档轨 P1–P3。旧稿 55-* 20 ID / packet_count / 锚词 / fixture 全量继承（思路参考不搬码）；新增形状基线机读实测（§1，含 `[ip,nvgre]` vs vxlan/geneve 的载体差异声明 + 目标形状）、P3 固定动作（§6）、执行建议（§7）、**存量审计转缺口登记**（§8：20/20 全转缺口 + 阻塞实证 + 覆盖反查门建议断言行）；锚词逐条对码（§4）。**cases 保持原样未改**（层空壳，G-NVGRE-1 阻塞）。自审 5 轮，末轮干净（结论见 `/tmp/pipe/doc-lanes/nvgre.md` §2）。
- v1.0.1（2026-09-28，隔离审查修轮）：同设计 v1.0.1。**P0-1** §8.2 改口——「假绿风险已排除」→「负例锚词全部失守」（贴实跑 RESULT 与 6 条 `does not contain` 原文）；**P0-2** §1/§8.2/§8.4 改「全量失效（0 pass）」，§8.4 增 #8「存量今日可跑」红行（红项 3→4）；**P1-②** §3.12 27B、§1/§8.1 1×11；**P2-1** `:293`；**P2-2** 扁平链来源；**P2-5** `notes` 位置。自审 1 轮，末轮干净。
- v1.0.2（2026-09-28，小补登记）：§8.4 新增红行 **#9**（结果产物过期，G-NVGRE-9，红项 4→5）——`docs/protocol-pcap-test/nvgre.md`（tracked）写「20 — pass 20」，但末次提交 `c0bf5ec`（2026-08-31）早于判死提交 `0417be5`（2026-09-13），`docs/protocol-pcap-test/nvgre/` **0 个 pcap**，今日实跑 `RESULT: 0 pass, 6 fail, 14 error (of 20)`（**方向相反**：声称 20/20，今日 0/20）；归属**代码阶段**（P5 重跑后重生成）。缺口全文见设计 §14。**不改任何 tracked 产物**。自审 1 轮，末轮干净。
