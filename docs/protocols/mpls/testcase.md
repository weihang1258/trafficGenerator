# #121 mpls（MPLS · L2.5 标签栈 · RFC 3031/3032/5462）测试用例契约

> 版本：v1.1.0（P-PIPE 文档轨 批次二 · as-built 型）
> 日期：2026-09-29
> 配套设计：`docs/protocols/mpls/design.md` v1.1.0（D-MPLS-1，as-built）
> 旧基线：**无**——本仓库不存在 mpls 旧设计稿或旧用例文档（`find . -iname "*mpls*"` 零命中；设计 §0）
> 机器契约：`trafficgen/test/protocol_pcap/cases/mpls.json`（**14/14 ID 与本版 §2 一致、顺序一致**，已机读实测 + **今日实跑复核** 14 pass / 0 fail / 0 error，设计 §0.2）
> 白话一句：**十四条检查：七条看正常发"贴着分拣码的 IP 包"（一层码、三连发、回程、组播、内层 TCP、新网段、双流），七条看胡来能不能被拦下（旧写法、静态复制、码号超 20 位、优先级超 3 位、最后一层标志写错位置、内层协议非法、方向非法）；每条只查一件事。**

---

## 1. 测试原则和形状基线

用例从设计 §3–§9 逐项派生，共 **14 个唯一语义 ID：7 正 + 7 负**。派生规则：设计 §3 每条线格式条款、§5 每个自动派生行为、§7 每行错误处理在本文有对应断言；断言不得超出设计声明范围。**一个用例只验证一个协议行为**。

**形状基线（2026-09-29 机读实测）**：

| 项 | 实测 |
|---|---|
| 例数 | **14**（7 正 + 7 负） |
| 顶层键 | **`{layers}` ×12** + **`{layers, group_id}` ×1**（`mpls_port_dyn`，白名单结构键）+ **`{layers, mpls}` ×1**（`mpls_vn_presence`，**判死负例必需形状**） |
| 层链 | **`[ip, mpls]` ×14**（全例同形；raw-IP 自驱终层，链内**无 tcp/udp 层**） |
| 正例 `expect` 键集 | `{packet_count, fields, notes}` ×7（含 frame 断言的唯一一例：`mpls_single_label_ipv4`） |
| 负例 `expect` 键集 | `{expect_error, error_contains}` ×7（严格两键） |
| 断言总量 | **fields 28 条 + frames 1 条**（机读逐例复核） |
| `strategy_fc` | **2 例**（`mpls_vn_static_port`、`mpls_port_dyn`），均 `{"type":"flows","value":2}` |
| 顶层游离键 | **违规 = 0**：非负例 13/13 顶层键 ⊆ `{layers, group_id}`（12 例仅 `layers`；`mpls_port_dyn` 含白名单结构键 `group_id`）；负例 1 例顶层 `mpls`（判死形状，非残留） |

**输出契约（pcap / NIC 双输出）**：两路径共用同一 cases JSON 与同一断言集（`eth.type` / `mpls.label` / `mpls.exp` / `mpls.bottom` / `mpls.ttl` / `ip.src` / `ip.dst` / `ip.id` / `ipv6.src` / `ipv6.hlim` / `udp.srcport` / `udp.dstport` / `tcp.srcport` / `tcp.dstport` / `data.data` 字段 + `offset 14` frame 原始字节）；NIC 经 tcpdump 捕获（`nic_capture` 用例级开关）；**不设仅单路径可用的断言**。**注**：今日实跑的是 **pcap 路**（设计 §0.2），NIC 路**未跑** → G-MPLS-9。

**TSHARK 基线（3.6.14 实测）**：`tshark -G fields | awk -F'\t' '$3 ~ /^mpls\./'` 得 **5 个字段**——`mpls.label`（FT_UINT32，BASE_DEC_HEX，掩码 0xfffff000）、`mpls.exp`（0xe00）、`mpls.bottom`（0x100）、`mpls.ttl`（0xff）、`mpls.invalid_label`（FT_NONE）。**本协议用到前四个**（`mpls_single_label_ipv4` 一例独占 4 条）。**进制纪律（实测）**：`mpls.label`/`mpls.exp`/`mpls.bottom`/`mpls.ttl` 用**十进制串**（BASE_DEC）；`eth.type` 用 `0x` 前缀十六进制串；`ip.id` 用 `0x` 前缀十六进制串（**不含前导零压缩规则**——`0x0001`/`0x0002`/`0x0003` 四位定宽，实跑实证）；端口/`frame.len` 用十进制串；`data.data` 用**紧凑小写 hex 无空格**（`70726f6265` = `probe`）。

**`mpls.invalid_label` 今日未收编**：该字段是 tshark 侧对"非法标签值"的标记，本引擎不产生非法栈（值域在 planner/builder 双门拦死），故**今日零使用**且**无合法断言面**（G-MPLS-6 附注）。

**断言基线（逐例机读计数）**：

| 用例 | fields | frames | `expect` 其余键 |
|---|---:|---:|---|
| `mpls_single_label_ipv4` | 7 | 1 | `packet_count: 1` |
| `mpls_frames_multi` | 6 | 0 | `packet_count: 3` |
| `mpls_direction_down` | 3 | 0 | `packet_count: 1` |
| `mpls_multicast` | 2 | 0 | `packet_count: 1` |
| `mpls_inner_tcp` | 3 | 0 | `packet_count: 1` |
| `mpls_v6` | 3 | 0 | `packet_count: 1` |
| `mpls_port_dyn` | 4 | 0 | `packet_count: 2` |
| 7 负例 | 0 | 0 | `{expect_error, error_contains}` |
| **合计** | **28** | **1** | — |

**包数约定（实测公式，设计 §9）**：

```
单流 = frames（缺省 1；模板面每流帧数）
多流 = flows × frames
负例 = 0（task-time 出 0 帧 .neg.pcap；create-time 无落盘）
```

**保活/重试/RST 口径**：**全部不适用**——MPLS 数据面无连接、无传输层（链内无 tcp/udp 层），故无保活、无重试、无重连、无 FIN/RST、无异常中断（设计 §5 豁免声明）。**这是本协议与其他协议最大的测试面差异**：用例中**不出现** `has_handshake` / `terminates` / `tcp.flags` 类断言（唯一 TCP 相关断言是 `mpls_inner_tcp` 的**端口号**，不断言 flags/seq——裸头合同，G-MPLS-10）。

**动态字段禁止硬编码**：生成期值只有**内层 IP ID**（`planner.go:160-164` 从 1 起逐帧 +1，**确定性、无随机源**）——`mpls_frames_multi` 用固定锚点 `0x0001`/`0x0002`/`0x0003` 断言。**本协议无其他生成期变量**（无 CRV/seq/TID 类），这是"确定性"最容易达成的一个协议。

### 1.1 封装形态测试清单（T1/T2/C1-C3）

规范与实现要求的封装形态先行枚举，再按行为面拆例：

| 形态 | 规范/设计依据 | 代码分支 | 当前证据或缺口 |
|---|---|---|---|
| 以太网 MPLS 单标签 IPv4/UDP | RFC 3032 §2.1/§5；设计 §3.1–§3.4 | `writeMPLSLabels`、MPLS EtherType、内层 IPv4/UDP | `mpls_single_label_ipv4`、`mpls_frames_multi` |
| 以太网 MPLS 单标签 IPv6/UDP | RFC 3032 §2.2；设计 §3.3 | `EtherTypeFor`/`writeL3v6` | `mpls_v6` |
| 内层 TCP 裸头 | 设计 §3.4/§3.7 | `inner_proto=6` | `mpls_inner_tcp` |
| 多标签栈 N≥2 | RFC 3032 §2.1；设计 §3.1 | `writeMPLSLabels` 循环 | G-MPLS-2，补例后校准栈底偏移 |
| VLAN 承载 | RFC 3032 §5；设计 §3.2 | builder VLAN + `mplsOff=18` | G-MPLS-5，补例后校准 |
| 非法/旧封装形态 | CORE §1.11–1.13；设计 §2.1/§7 | presence/static-copy/validator 门 | 7 条负例真实拒绝；顶层 `mpls:{}` 仅 `mpls_vn_presence` 判死形状 |

三源回指：规范为 RFC 3031/3032/5462 对应章节，代码设计为设计 §3/§7/§11，现网字节证据为本仓 pcap 实跑（§5.1）；真实 LSR/FRR 线字节尚未取得，确认方式为抓取 FRR/Linux MPLS 或设备 pcap 后与字段和 offset 逐项对账（G-MPLS-14）。

---

## 2. 原子用例索引（14 ID = 7 正 + 7 负，顺序为权威）

| # | ID | 类型 | 覆盖（设计 §） | 包数（**今日实跑实测**） | 断言数 |
|---:|---|---|---|---:|---:|
| 1 | `mpls_single_label_ipv4` | 正 | §3.1/§3.2/§3.3/§3.4：单标签栈基线（label 100/TC 0/S 1/TTL 64，内层 IPv4/UDP） | **1**（`packet_count: 1`） | 7 fields + 1 frame |
| 2 | `mpls_vn_presence` | 负 | §7 N-1：顶层 `mpls` presence 判死（create-time） | **0**（无落盘） | 0 |
| 3 | `mpls_vn_static_port` | 负 | §7 N-2：层内静态端口 + `flows=2` 静态复制（create-time） | **0**（无落盘） | 0 |
| 4 | `mpls_neg_label` | 负 | §7 N-3：`label` 超 20 bit | **0**（`.neg.pcap`） | 0 |
| 5 | `mpls_neg_tc` | 负 | §7 N-4：`tc` 超 3 bit | **0**（`.neg.pcap`） | 0 |
| 6 | `mpls_neg_sbit` | 负 | §7 N-5：`s` 位非栈底 | **0**（`.neg.pcap`） | 0 |
| 7 | `mpls_neg_innerproto` | 负 | §7 N-6：`inner_proto` 非法 | **0**（`.neg.pcap`） | 0 |
| 8 | `mpls_neg_direction` | 负 | §7 N-7：`direction` 非法 | **0**（`.neg.pcap`） | 0 |
| 9 | `mpls_frames_multi` | 正 | §5：`frames=3` 多帧（IP ID 逐帧 +1） | **3** | 6 fields |
| 10 | `mpls_direction_down` | 正 | §5 规则 12：`direction=down`（地址+MAC 全交换） | **1** | 3 fields |
| 11 | `mpls_multicast` | 正 | §3.2：`multicast` → EtherType 0x8848 | **1** | 2 fields |
| 12 | `mpls_inner_tcp` | 正 | §3.4/§3.7：内层 TCP 裸头（`inner_proto: 6`） | **1** | 3 fields |
| 13 | `mpls_v6` | 正 | §3.3：内层 IPv6 对照 | **1** | 3 fields |
| 14 | `mpls_port_dyn` | 正 | §12.12：`src_port` inc 动态 + `flows=2` | **2** | 4 fields |

**T-编号对照（`docs/TEST_CASES.md:3372-3400`）**：`mpls_single_label_ipv4` ≡ T-MPLS-1；`mpls_vn_presence` ≡ T-MPLS-2；`mpls_vn_static_port` ≡ T-MPLS-3；`mpls_neg_label` ≡ T-MPLS-4；`mpls_neg_tc` ≡ T-MPLS-5；`mpls_neg_sbit` ≡ T-MPLS-6；`mpls_neg_innerproto` ≡ T-MPLS-7；`mpls_neg_direction` ≡ T-MPLS-8；`mpls_frames_multi` ≡ T-MPLS-9；`mpls_direction_down` ≡ T-MPLS-10；`mpls_multicast` ≡ T-MPLS-11；`mpls_inner_tcp` ≡ T-MPLS-12；`mpls_v6` ≡ T-MPLS-13；`mpls_port_dyn` ≡ T-MPLS-14。**序号以 cases JSON 顺序为权威**（JSON 中 7 条负例集中在 #2–#8，正例 #9–#14 随后）。

**ID 顺序与设计 §9 完全一致**（两文档同表，逐行可对照）。

---

## 3. 正例逐项断言契约（最低断言集，实现期可增不可减）

**通用前置**：每例层链 `[ip, mpls]`（raw-IP 自驱）；地址住 `layers[0].ip.{src,dst}`；内层端口住 `layers[1].mpls.{src_port,dst_port}`；标签栈住 `layers[1].mpls.labels`。**无握手/挥手/终止断言**（设计 §5 豁免）。

### 3.1 `mpls_single_label_ipv4`（1 包，`packet_count: 1`）

`ip={src:"10.0.0.1", dst:"20.0.0.1"}`、`mpls={src_port:12345, dst_port:80, labels:[{label:100}], inner_payload:"probe"}`。

- **7 条 field 断言（今日实跑逐条命中）**：`eth.type=0x8847`（MPLS unicast 强制）、`mpls.label=100`、`mpls.exp=0`（TC 缺省）、`mpls.bottom=1`（**栈底 S 自动置 1**——用户未写 S）、`mpls.ttl=64`（**TTL 缺省解析**——用户未写 TTL）、`udp.dstport=80`、`data.data=70726f6265`（`probe` 紧凑 hex）。
- **1 条 frame 断言**：帧 1 `offset 14` = `00 06 41 40`。**这是本协议唯一一条 frame 断言**，也是**位域拼装的直接证据**：

```
0x00064140 = 0000 0000 0000 0110 0100 0001 0100 0000
             |---- Label=100 ---| TC=0 |S=1|TTL=64  |
```

  逐位核对：`Label = 0x00064140 >> 12 = 0x64 = 100` ✓；`TC = (>> 9) & 0x7 = 0` ✓；`S = (>> 8) & 1 = 1` ✓；`TTL = & 0xFF = 0x40 = 64` ✓。**用例原文的算术式 `100<<12|S<<8|TTL64` 与代码 `(Label&0xFFFFF)<<12 | TC<<9 | S<<8 | TTL` 一致**（设计 §3.1 拼装公式）。
- **`packet_count: 1`**：本例要求严格 1 帧，防止帧数漂移（G-MPLS-17 已关闭）。
- **`inner_payload` 显式 "probe"**：`data.data` 断言的是**内层 L4 载荷**（`builder.go` 把它写在标签栈+IP+UDP 之后，offset 46 = 14+4+20+8），不是 MPLS 层载荷（MPLS 无载荷字段）。

### 3.2 `mpls_frames_multi`（3 包）

`frames: 3`（其余同 #1 骨架，无 `inner_payload` → 回退 `spec.Payload` 为空 → 空载荷 + padding 60）。

- **6 条 field 断言（今日实跑逐条命中）**：帧 1/2/3 的 `mpls.label` 均 **100**（**标签栈逐帧完全相同**——`planner.go:179-180` 每帧复用同一解析后的栈）；帧 1/2/3 的 `ip.id` 分别 **`0x0001`/`0x0002`/`0x0003`**（**逐帧 +1**，从 1 起，`planner.go:160-164`）。
- **覆盖的独立分支**：`frames` 键的"多帧"路径（缺省 1 由 #1 覆盖）+ **IP ID 生成器**（唯一生成期变量，确定性）。
- **实跑佐证**：三帧 `frame.len` 均 60，`eth.type` 均 0x8847，`ip.src/dst` 均 10.0.0.1→20.0.0.1。

### 3.3 `mpls_direction_down`（1 包）

`direction: "down"`。

- **3 条 field 断言（今日实跑逐条命中）**：`ip.src=20.0.0.1`、`ip.dst=10.0.0.1`（**地址交换**——`planner.go:171-176` legacy 层自交换）、`mpls.label=100`。
- **双换防护的实证（设计 §5 规则 12）**：planner 已交换地址，`layer_gen.go:51-52` 强制 `Direction="up"` 使 raw-IP 驱动**不再交换**，故帧面保留的正是交换后的地址。**若防护缺失，本用例会看到未交换的 10.0.0.1→20.0.0.1（双换回原值）——本用例是该防护的唯一守卫**。
- **MAC 断言缺失（诚实声明）**：用例注释称"地址+MAC 全交换"，但 **`expect.fields` 只断言 IP，未断言 MAC**（`ip.src`/`ip.dst`/`mpls.label` 三条）——MAC 交换面（`planner.go:173-176`）**今日无断言证据** → A′ 候选（G-MPLS-18，收编 `eth.src`/`eth.dst`）。

### 3.4 `mpls_multicast`（1 包）

`multicast: true`。

- **2 条 field 断言**：`eth.type=0x8848`（**组播 EtherType**，`builder.go:1028-1030` 强制）、`mpls.label=100`。
- **覆盖的独立分支**：EtherType 二值选择器（unicast 由 #1 覆盖，multicast 由本例覆盖）——**这是 `multicast` 键的唯一可观察差异**（其余字节与 #1 同）。
- 存量 notes 引 `RFC 3032 §3.10` —— **条款号错，应为 §5**（设计 §0.1 #4）；锚词与断言**不受影响**（值 0x8848 正确）。

### 3.5 `mpls_inner_tcp`（1 包）

`inner_proto: 6`。

- **3 条 field 断言**：`eth.type=0x8847`、`tcp.srcport=12345`、`tcp.dstport=80`。
- **裸头声明（G-MPLS-10）**：内层 TCP 是**裸头**——无握手、无 seq/ack/flags/window（`spec.TCP` 链路径恒 nil，`planner.go:189-194` 赋值分支不可达）。**用例不断言 `tcp.flags`**，notes 已显式声明。实跑佐证：该帧 `ip.proto = 6`、`ip.total_len = 40`（20 IP + 20 TCP + 0 载荷）。
- **覆盖的独立分支**：`inner_proto` 值域 6 的接受路径（0/17 由其余用例覆盖，1 由 #7 拒）。

### 3.6 `mpls_v6`（1 包）

`ip={src:"2001:db8::1", dst:"2001:db8::2"}`（内层 IPv6）。

- **3 条 field 断言**：`mpls.label=100`、`ipv6.src=2001:db8::1`、`ipv6.hlim=64`（**内层 IPv6 Hop Limit 缺省 64**——框架级 `builder.go:1260` 同 0→64）。
- **"地址族在外层还是内层"的最强证据**：本帧 `eth.type = 0x8847`（**外层仍是 MPLS**），`ipv6.src` 出现在栈底之后（offset 18 起，`62 00 00 00 00 08 11 40` = ver6/TC 0x20/FlowLabel 0/PayloadLen 8/NextHeader 17/HopLimit 64）。**即 MPLS 的内层族与 EtherType 解耦**（设计 §3.3）。
- 存量 notes 引 `RFC 3032 §3.9` —— **条款号错，应为 §2.2 + §1**（设计 §0.1 #5）；断言值**不受影响**。
- **未断言项**：`ipv6.dst`（`2001:db8::2`）与 `mpls.label` 之外的栈字段——A′ 候选（G-MPLS-6 邻域）。

### 3.7 `mpls_port_dyn`（2 包，`strategy_fc: {"type":"flows","value":2}`）

`ip.src` inc `10.0.1.1–10.0.1.2`、`mpls.src_port` inc `30000–30001`、`dst_port: 80`、`group_id: {"strategy":"fixed","value":"mpls-port-dyn"}`。

- **4 条 field 断言（今日实跑逐条命中）**：帧 1 `ip.src=10.0.1.1` + `udp.srcport=30000`；帧 2 `ip.src=10.0.1.2` + `udp.srcport=30001`。
- **E1 逐流端口池（设计 §12.12）**：端口动态**必须**写 `mpls` 层（链内无 tcp/udp 层）；`mpls` 层 `src_port` 的 inc 对象经 `parseLayerDyn`（`layer_dyn.go:238-246`）→ worker `resolveLayerTuple`（`:822-833`）逐流解析落 `spec.SrcPort` → translate（`chain_planner_translate.go:1447-1457`）→ legacy `Plan` 用该端口组装内层 UDP 头。
- **`group_id` 固定单 worker FIFO**：保证两流帧序确定（流 1 帧 1、流 2 帧 2）——这是"多流用例可断言逐包位次"的前提（icmpv6 T-11 先例）。
- **覆盖的独立分支**：`flows>1` × 动态 `ip.src` × 动态 `mpls.src_port` 的**组合**（静态复制的反面：本形态**通过**静态复制门，而 #3 的静态形态**被拒**——两例构成对偶）。

**正例总则**：MPLS 无"消息类型"，正例只有"带标签的包"一种形态；所有正例都是**配置 → 帧**的确定性映射。多帧（#9）、多流（#14）、方向（#10）、EtherType（#11）、内层族（#13）、内层 L4（#12）为可独立判定的六个维度，各由独立用例覆盖。

---

## 4. 负例契约

负例必须在 **create-time 门**或 **planner/validator** 阶段失败并传播为 task error，不得产生成功 PCAP、`completed/0 packet` 或只剩以太网外壳的假成功（**今日实跑：5 例 task-time 负例 `.neg.pcap` 均 0 帧；2 例 create-time 负例无落盘**，文件名 `<id>.neg.pcap`）。锚词与设计 §7 表一一对应、同序：

### 4.1 create-time 门（2 条，无 pcap 落盘）

| ID | 故障输入（机读实测） | JSON `error_contains` | 代码文案（逐字） | 门 |
|---|---|---|---|---|
| `mpls_vn_presence` | `spec_json` 顶层 `"mpls": {}`（**空 map，与层内配置并存**） | `top-level mpls sub-config` | `protocol mpls no longer accepts a top-level mpls sub-config (move it into the mpls layer of an [ip,mpls] layers chain)` | `CheckProtoFlat`（`strategy_convert.go:8947-8951`） |
| `mpls_vn_static_port` | `mpls` 层**静态**端口（12345/80）+ `flows=2`；`ip` 层**空 map**（对门无贡献的最小证明形） | `static four-tuple` | `layers pin a static four-tuple but flows > 1: every flow would emit identical addresses/ports (static copy). …` | `checkLayerChainStaticCopy`（`schema/semantic.go:285`；mpls 已入扫描名单 `:214`） |

**两例的"必死"性质（与 opcua 对照）**：mpls **有** presence 分支与静态复制扩扫（**与 opcua 的 G-OPCUA-1 情形相反**）——两例今日**真能判死**（实跑 create-time 拒，无落盘），**不是假通过**。

**create-time 无 pcap 的原因（机制说明）**：套件在 `SubmitTask` 同步返回错误时直接取 `submitErr.Error()` 作为负例文本（`layer_chain_suite_test.go:262-266`），**此时任务从未进入引擎**，故 `.neg.pcap` 文件不会被创建（MCP 路同款：create 失败无任务记录）。

### 4.2 task-time validator 门（5 条，`.neg.pcap` 0 帧）

| ID | 故障输入（机读实测） | JSON `error_contains` | 代码文案（`planner.go` 逐字） | 代码行 |
|---|---|---|---|---|
| `mpls_neg_label` | `labels:[{label: 1048576}]`（= 2²⁰） | `exceeds 20 bits` | `mpls: label %d (entry %d) exceeds 20 bits (max 0xFFFFF, RFC 3032 §3.1)` | `:66` |
| `mpls_neg_tc` | `labels:[{label:100, tc: 8}]` | `exceeds 3 bits` | `mpls: TC %d (entry %d) exceeds 3 bits (max 7, RFC 5462)` | `:69` |
| `mpls_neg_sbit` | `labels:[{label:1, s:true}, {label:2}]` | `not the bottom of stack` | `mpls: S=true on entry %d but it is not the bottom of stack (only the last entry may set S, RFC 3032 §2.1)` | `:72` |
| `mpls_neg_innerproto` | `inner_proto: 1` | `InnerProto 1 not in supported list` | `mpls: InnerProto %d not in supported list (allowed: 6=TCP, 17=UDP)` | `:80` |
| `mpls_neg_direction` | `direction: "sideways"` | `Direction "sideways" not in supported list` | `mpls: Direction %q not in supported list (allowed: up, down)` | `:91` |

**锚词口径**：`error_contains` 是**子串**判定；5 例均命中代码文案（前缀 `mpls: `）。**N-3 / N-4 的代码文案含错误条款号**（`RFC 3032 §3.1` 应为 `§2.1`；`§3.1` 甚至不存在）——但**锚词取的是不含条款号的子串**（`exceeds 20 bits` / `exceeds 3 bits`），故**条款号错误不污染用例**（设计 §0.1 #1/#2、G-MPLS-1）。

**负例原子性**：每例**单一故障注入**（7 例各自只坏一处：presence / 静态端口 / label 值 / tc 值 / s 位 / inner_proto / direction），无混注。

**负例纯净性**：7 例 `expect` **只有** `{expect_error, error_contains}`，无任何成功包结构断言（无 `fields`/`frames`/`packet_count`）。G-MPLS-16 已关闭。

**未入用例的拒绝分支（A′ 立项，不得冒充已覆盖）**：`mpls: MPLS config is required`（`planner.go:42`，链路径不可达=C 类）；`mpls: %s %q is not a valid IP address`（`:57`）；`mpls: label stack must contain at least one entry (RFC 3032 §2.1)`（`:62` / `builder.go:1118`）；`mpls: Frames %d must be >= 0`（`:84`，V9 先拦）；`mpls: cannot combine MPLS with GRE …`（`builder.go:1106`）；`mpls: cannot combine MPLS with PPPoE …`（`:1109`）；`mpls: inner layer must be IP …`（`:1115`）——共 **7 条**（设计 §7.3）。

---

## 5. 覆盖与对账

### 5.1 三源回指行

RFC 3031/3032/5462（设计 §10）+ D-MPLS-1（设计 §11）+ tshark 3.6.14 `mpls.*`（5 字段）与**今日实跑 12 份 pcap**（`/tmp/mpls-doc-verify/mpls/`，设计 §0.2）→ 14 ID（本契约 §2）。第三源**已到抓包级**：本仓引擎产出的 14 例 pcap 逐帧核对（28 条 field + 1 条 frame 全命中）。**真实设备/开源实现的线字节未取到** → G-MPLS-14（按 §5.4 不写死进实现）。

**14 ID 逐项回指（§9.5 要求）**：#1←设计 §3.1/§3.2/§3.3/§3.4；#2←§7 N-1；#3←§7 N-2；#4←§7 N-3；#5←§7 N-4；#6←§7 N-5；#7←§7 N-6；#8←§7 N-7；#9←§5 自动派生 9；#10←§5 规则 12；#11←§3.2；#12←§3.4/§3.7；#13←§3.3；#14←§12.12。

### 5.2 对账两行 + 清单出处声明

- **清单出处声明**：本清单来源 = **RFC 3031/3032/5462 公开规范 + D-MPLS-1 内部设计 + 仓库落码反推 + tshark 3.6.14 字段表与今日实跑 pcap 实测**，**非纯规范反推**。规范面已逐条核对（设计 §0.1 校正 **22 处**落码条款号），**但真实设备行为未取到**（G-MPLS-14）。
- **对账两行（机读逐格计数，2026-09-29）**：**要求逻辑点总数 = 104**（八项 8 行 + 矩阵 42 格 + 变体 37 行 + 商业映射 17 行 = 8+42+37+17）；**用例覆盖数 = 51**（八项 2 + 矩阵 18 + 变体 23 + 商业 8）；**不适用/明确不解决 = 30**（八项 4 + 矩阵 18 + 商业 8）；**开放立项 = 23**（八项 2 + 矩阵 A′ 6 + 变体 14 + 商业 1）。51 + 30 + 23 = **104** ✓
  **粒度声明**：行/格粒度每点 1 计（矩阵按**格**计、其余按**行**计）；G-MPLS-1…G-MPLS-18 不折进 104。**反查全绿 ≠ 覆盖全**（§9.52 原文）。逐表重数见设计 §10.1（8 行 = 覆 2〔连接模型/字段表〕+ 立项 2〔错误处理/版本方言〕+ 不适用 4〔状态机/超时活性/NAT/命令表〕）/§10.2（42 格 = 覆 18 + A′ 6 + 不适用 18，T3 列整列不适用）/§10.3（37 行 = 覆 23 + 立项 14）/§10.4（17 行 = 覆 8 + 立项 1 + 不解决 8）。
- **门3 抽查候选**：最复杂用例 = **`mpls_frames_multi`**（3 帧 × 6 条断言，含逐帧 IP ID 递增与栈复用两个维度）；**建议门3 抽 `mpls_frames_multi` + `mpls_port_dyn`**（后者补"多流 + 动态端口 + 静态复制对偶"面）。

### 5.3 T-编号与旧 id 对照

见表 §2 末段（14 项一一对应，无缺项）。

### 5.4 封装形态对账与 cases JSON 形状

- 正例 7 例 `spec_json` 顶层键全部合规：`{layers}` 或 `{layers, group_id}`；层链全为 `[ip, mpls]`。
- 负例 7 例：6 例 `spec_json` 顶层仅 `{layers}`；唯一例外 `mpls_vn_presence` 的顶层 `mpls:{}` 为判死负例必需形状，不是旧格式残留。
- 7 条负例 `expect` 均为严格 `{expect_error, error_contains}`，无成功包断言。

## 6. P3 固定动作（CORE_MEMORY 管线：§3.15 三项 + A′/B′ 两分类 + 3.14 豁免）

### 6.1 §3.15 三项逐项一例或立项

| # | 三项 | 本协议对照 | 用例/立项 |
|---|---|---|---|
| ① | 同连接/同流内的多轮操作 | **不适用**——MPLS 无连接（设计 §5 豁免）；同流"多轮"形态 = `frames` 多帧（#9），是**同一动作重复**而非多轮事务 | 已覆 #9（并显式声明语义差异） |
| ② | 非正常结束 | **不适用**——无连接则无结束，无 FIN/RST 概念（链内无 tcp/udp 层） | **不适用**（豁免声明，非缺口） |
| ③ | 长保活 | **不适用**——无保活机制（LDP KeepAlive 属控制面，不生成） | **不适用**（同左） |

**无空项**：① 有已覆例 + 语义声明；②③ 显式不适用 + 理由（CORE_MEMORY §10.2 口径：不适用层显式声明理由，不硬凑用例）。

### 6.2 A′/B′ 两分类表

**A′（代码阶段接线）**：

| 类 | 内容 | 落点 |
|---|---|---|
| 多层栈面 | N=2 栈用例（代码支持、用例缺） | G-MPLS-2 |
| 拒绝分支面 | 空栈 / IP 非法 / 负数 frames / MPLS+GRE / MPLS+PPPoE / 内层非 IP（6 条） | G-MPLS-7 |
| 边界等值面 | `label=0xFFFFF`、`tc=7`（上界等值应过） | G-MPLS-12 |
| TTL 面 | 显式 `labels[].ttl`（如 255） | G-MPLS-11 |
| payload 面 | `inner_payload` 缺席（回退 `spec.Payload`） | G-MPLS-11 |
| VLAN 面 | VLAN 承载（栈起点 18） | G-MPLS-5 |
| 保留标签面 | `label` 0-15 作普通值（钉"无特殊语义"事实） | G-MPLS-4 |
| 动态面 | `mpls.dst_port` 动态 / `ip.ttl` 动态 / `rand`/`list`/`pattern` / inc 回绕 | G-MPLS-13 |
| MAC 面 | `direction=down` 的 `eth.src`/`eth.dst` 断言（今日只断 IP） | G-MPLS-18 |
| DSCP 面 | `ip.dsfield` 断言（今日 0x20 进帧但零断言） | G-MPLS-6 |
| 断言收窄 | `mpls_single_label_ipv4` 的 `min_packets: 1` → `packet_count: 1` | G-MPLS-17 已关闭 |
| NIC 路 | NIC 输出回归（今日只跑 pcap 路） | G-MPLS-9 |
| 异族混写 | `ip.src` v4 + `ip.dst` v6 行为待确认 | §8 |
| 真实设备对照 | 真实 LSR/FRR 线字节 | G-MPLS-14 |

**B′（框架面）**：顶层未知键通用门（G-MPLS-15，等框架级 unknown-key 白名单，不单独立项）。负例 `notes` 键收窄（G-MPLS-16）**已关闭**（2026-09-30）：7 例 `expect` 已收为严格 `{expect_error, error_contains}`，cases JSON 同步。

### 6.3 3.14 豁免边界审计

**无长连接载体 → `sessions[]` 豁免**（设计 §12.3 已论证）：链内**无 tcp/udp 层**，mpls 是 L2.5 层，**连"连接"这个承载概念都不存在**（比 pppoe/icmpv6 更彻底——它们至少有 IP 承载语义）。**多流**由策略级 `flow_control`/`strategy_fc` 承载（#14 已用，`flows=2`）。**单包多载荷** = **不适用**（MPLS 无"一个包里塞多个消息"的形态；标签栈是多层**标签**不是多载荷）。**流关联（控制流派生数据流）** = **不适用**（无控制面，LSP 是网络预置状态，不由本引擎某流派生）。

---

## 7. 实现后执行建议

1. **P4 顺序（本协议为 as-built，P4=缺口收敛）**：①先修 G-MPLS-1（**22 处** RFC 条款号，纯注释/文案，零字节影响）；②补 A′ 拒绝分支例（G-MPLS-7，注意 R-4 的负数被 V9 先拦，锚词口径需按 V9 文案）；③补 A′ 边界等值例（G-MPLS-12）；④补多层栈例（G-MPLS-2，**得先改 cases 才能跑**）；⑤G-MPLS-17 已完成（#1 已为 `packet_count: 1`）；⑥补 NIC 路回归（G-MPLS-9）。
2. **实测顺序**：先 #1（栈字节 `00 06 41 40` 与 7 条 field 基线），再 #9（IP ID 1/2/3），再 #10（down 交换——**双换防护的唯一守卫**），再 #11（0x8848）/ #12（裸头）/ #13（内层 v6 offset 18 起），最后 #14（多流端口池），负例 #2–#8（2 create-time + 5 task-time）。
3. **跑法与坑**：`PCAP_ROOT=<私有可写目录> MCP_API_KEY=dev-mcp-key CASE_PROTO=mpls go test ./test/protocol_pcap/ -run TestProtocolPcapDrive -count=1`（**必须带 `-run` 过滤**，否则连带跑依赖 root 目录的 `TestSmbNegCases`/`TestNicSelection`/`TestDiagPortGroup` 恒红）；**`DOC_DIR` 必须显式设到临时目录**，否则默认 `../../docs/protocol-pcap-test` 会把 tracked 的 `SUMMARY.md` 与 `mpls.md` **就地覆盖**（本车道首次跑即踩：`SUMMARY.md` 被改成 `mpls 14/14`，已 `git checkout` 还原）。
4. **门2② 全量（`CASE_PROTO=mpls` 全量不是增量）+ 门2③ 二进制同代确认**（`find trafficgen -name '*.go' -newer <server-binary>` 无输出）+ 门2④ 反查绿后进 P6。
5. 任何 RFC 条款号的具体引用须有规范原文证据（G-MPLS-1 纪律；本版已实测拉取 R3031/R3032/R5462）。

---

## 8. 存量审计（14 例逐条去向）

### 8.1 存量实测面（2026-09-29，机读 + 实跑）

`cases/mpls.json` **14 例**：7 正带 **`packet_count`**（1/3/1/1/1/1/2），**与今日实跑 pcap 帧数 7/7 逐例一致**；7 负 `expect` 键集合 `{expect_error,error_contains}`（严格两键），其中 **5 例实测 `.neg.pcap` 0 帧、2 例 create-time 无落盘**；14/14 顶层键 ⊆ `{layers, group_id}`（**零违规游离键**）；**28 条 field + 1 条 frame 断言逐条对今日实跑 pcap 复核（全命中）**；层内 `mpls` 键与 registry Fields 8 键**逐键一致**（机读实测）；**与 2026-09-27 存盘产物字段面 md5 7/7 一致**。

### 8.2 现状矛盾点（诚实登记）

1. **落码 RFC 条款号 22 处错误**（设计 §0.1 grep 机读行号）：`§3.1`→`§2.1`（**14 处**）、`§3.10` EtherType→`§5`（4 处）/标签值→`§2.1+§6`（1 处）、`§3.9`→`§2.2+§1`（2 处）、`RFC 3031 §3.12`→`§3.25.1`（1 处）；**保留正确** `§2.1`（9 处）/`RFC 5462`（2 处）。**锚词不受影响**（不含条款号）→ G-MPLS-1。
2. **存量用例 notes 条款号已校正**：`mpls_multicast` 使用 RFC 3032 §5（EtherType），`mpls_v6` 使用 RFC 3032 §2.2 + §1（内层协议判定）；断言值不变。
3. **多层标签栈零覆盖**：代码支持 N≥2（`writeMPLSLabels` 循环 + 单测 `planner_test.go:161-192` 验证 S 位 0/1 分布），**用例零**；`planner_test.go:160` 注释引的"pcap 7、mpls_http.pcap"是**外部参考 pcap**（不在本仓、今日不可复现），**不是本仓用例** → G-MPLS-2。
4. **`mpls_single_label_ipv4` 已改为严格 `packet_count: 1`**：不再使用宽松 `min_packets`，其余 14 ID 与断言保持不变。
5. **`direction=down` 只断 IP 不断 MAC**：用例注释称"地址+MAC 全交换"，实测 `expect.fields` **只有 3 条 IP/栈断言**，MAC 交换面无断言 → G-MPLS-18。
6. **DSCP 0x20 进帧零断言**：全部 14 例内层 TOS = 0x20（框架 `DefaultDSCP=0x08` CS1），**无一条断言** → G-MPLS-6。
7. **显式 TTL / 缺省 payload / 边界等值 三格缺失**：`labels[].ttl` 显式、`inner_payload` 缺席、`label=0xFFFFF`/`tc=7` 等值 → G-MPLS-11 / G-MPLS-12。
8. **NIC 路未跑**：今日只跑 pcap 路 → G-MPLS-9。
9. **结果产物链接悬空**：`trafficgen/docs/protocol-pcap-test/mpls.md`（tracked）的 **12 条** `[pcap](mpls/xxx.pcap)` 相对链接指向的 **`trafficgen/docs/protocol-pcap-test/mpls/` 目录不存在（0 个 pcap）** → G-MPLS-8。**注**：该文件末次提交 `d62db10`（2026-09-19）**晚于**扁平判死提交 `0417be5`（2026-09-13），**不构成"产物过期"缺口**；且其 **14/14 今日已被本车道独立复跑证实**（设计 §0.2）——**不得**读成"套件不可跑"或"数字未经证实"。
10. **顶层未知键无通用门**：白名单外游离顶层键今日不判死 → G-MPLS-15（**不建负例**，建了会真绿）。
11. **（已关闭）负例 `notes` 键**：7 负例 `expect` 原含 `notes`，与严格两键口径不符 → G-MPLS-16。**已于 2026-09-30 关闭**：cases JSON 收窄为 `{expect_error, error_contains}`，锚词逐字不变。

### 8.3 逐条去向表（14 行）

| 存量 id | T-编号 | 去向 | 改写动作（P4） |
|---|---|---|---|
| `mpls_single_label_ipv4` | T1 | **保留** | 已收窄为严格 `packet_count: 1`（G-MPLS-17 已关闭） |
| `mpls_vn_presence` | T2 | **保留** | 形状已合规（判死负例必需形状）；`notes` 已删（G-MPLS-16 关闭，2026-09-30） |
| `mpls_vn_static_port` | T3 | **保留** | 同上 |
| `mpls_neg_label` | T4 | **保留** | `notes` 已删（G-MPLS-16 关闭）；可补等值格 `label=0xFFFFF`（G-MPLS-12） |
| `mpls_neg_tc` | T5 | **保留** | `notes` 已删；可补等值格 `tc=7`（G-MPLS-12）；原 notes 的 `RFC 5462` **正确** |
| `mpls_neg_sbit` | T6 | **保留** | `notes` 已删；原 notes 的 `RFC 3032 §2.1` **正确** |
| `mpls_neg_innerproto` | T7 | **保留** | `notes` 已删 |
| `mpls_neg_direction` | T8 | **保留** | `notes` 已删 |
| `mpls_frames_multi` | T9 | **保留** | 可补 `mpls.ttl`/`ip.dsfield` 断言 |
| `mpls_direction_down` | T10 | **改写** | 补 `eth.src`/`eth.dst` 断言（现只断 IP，G-MPLS-18） |
| `mpls_multicast` | T11 | **保留** | notes 已校正为 RFC 3032 §5（G-MPLS-1 附带动作已完成） |
| `mpls_inner_tcp` | T12 | **保留** | notes 声明正确（裸头合同）；可补 `tcp.flags` 的**零值**断言（"无握手"的可执行形式） |
| `mpls_v6` | T13 | **保留** | notes 已校正为 RFC 3032 §2.2 + §1（G-MPLS-1 附带动作已完成）；可补 `ipv6.dst` 断言 |
| `mpls_port_dyn` | T14 | **保留** | 可扩 `dst_port` 动态与其余策略（G-MPLS-13） |

无"作废不注原因"：**0 作废、0 等价覆盖**（14 例全部保留或改写 + A′ 新增）。**本协议存量 14/14 顶层零违规游离键**。

### 8.4 双轨诚实性声明（本车道实跑 vs 既有产物）

| 项 | 内容 |
|---|---|
| **本车道今日实跑** | `RESULT: 14 pass, 0 fail, 0 error`（设计 §0.2），pcap 落**私有目录** `/tmp/mpls-doc-verify/mpls/`（12 文件）；**未覆盖**共享 `/tmp/mcp-pcaps/mpls/`、**未改**任何 tracked 产物 |
| **与既有存盘产物对账** | 同用例双跑，逐字段 `md5sum` 比对 **7/7 一致**（文件字节含时间戳故 `cmp` 有差，解码字段面无差）→ **先跑后钉复核通过** |
| **tracked 结果产物状态** | `trafficgen/docs/protocol-pcap-test/mpls.md` 末次提交 `d62db10`（2026-09-19）**晚于**判死提交 `0417be5`（2026-09-13）→ **不属"产物过期"**（与 pcep G-PCEP-11 / opcua G-OPCUA-10 判定相反）；其 **14/14 今日已被本车道独立证实**；真实缺口**仅**"12 条 pcap 链接悬空（`docs/protocol-pcap-test/mpls/` 目录不存在）"→ G-MPLS-8 |
| **本车道踩到的坑** | 套件默认 `DOC_DIR=../../docs/protocol-pcap-test`，**首跑即把 tracked 的 `SUMMARY.md` 就地覆盖**（本车道已 `git checkout` 还原，工作树现仅含本车道两份 md 的改动）。复跑**必须** `DOC_DIR=<临时目录>` |

---

## 9. 附：覆盖反查门建议断言行（供主线程合后登记；本车道不碰 `coverage_gate.py`）

**现状**：`coverage_gate.py:619-650` 的 `check_mpls` **已存在**（D-MPLS-1 P5R 反查表：8 条场景面 + 8 条键覆盖 + 6 条锚词 = **22 行**）。本契约**不重复主张**，只补充下列**新增**建议行（**每条均可从本契约与 cases JSON 直接机读，不需新造事实**）：

| # | 建议断言 | 依据 |
|---:|---|---|
| 1 | `len(cases['mpls']) == 14` 且 ID 集合与顺序 = §2 十四项 | 本契约 §2 |
| 2 | 14/14 例 `spec_json` 顶层键 ⊆ `{layers, group_id}`，且**非负例**顶层键（去白名单）= 0（**今日已成立**） | 本契约 §1；设计 §12.1 |
| 3 | 13/13 非负例层链恒为 `['ip','mpls']`（raw-IP 终层，链内**无** tcp/udp 层） | 本契约 §1 |
| 4 | 7 正例 `packet_count` 与实跑帧数一致（1/3/1/1/1/1/2） | 设计 §9 公式 |
| 5 | 7 负例 `error_contains` ∈ 代码锚词集 `{'top-level mpls sub-config','static four-tuple','exceeds 20 bits','exceeds 3 bits','not the bottom of stack','InnerProto 1 not in supported list','Direction "sideways" not in supported list'}` 且**逐例唯一命中一个** | 设计 §7 |
| 6 | 5 例 task-time 负例 `.neg.pcap` 帧数 == 0；2 例 create-time 负例**无 `.neg.pcap` 文件** | 本契约 §4 |
| 7 | `mpls_single_label_ipv4` 的 frame 断言 `offset==14` 且 `hex=='00 06 41 40'`；逐位复算 `label=100, tc=0, s=1, ttl=64` | 设计 §3.1 拼装公式 |
| 8 | 断言总数 == fields 28 + frames 1（逐例分布见本契约 §1 表） | 本契约 §1 |
| 9 | 2 例 `strategy_fc` 均 `{"type":"flows","value":2}`；其余 12 例无该键 | 本契约 §1 |
| 10 | 7 负例 `expect` 键集合 == `{expect_error, error_contains}`（已关闭 G-MPLS-16） | 本契约 §4.2 |
| 11 | 每条正例断言字段 ∈ {`eth.type`,`mpls.label`,`mpls.exp`,`mpls.bottom`,`mpls.ttl`,`ip.src`,`ip.dst`,`ip.id`,`ipv6.src`,`ipv6.hlim`,`udp.srcport`,`udp.dstport`,`tcp.srcport`,`tcp.dstport`,`data.data`} | 本契约 §3 |

**另注意**：`trafficgen/docs/protocol-pcap-test/mpls.md` 的 **12 条 pcap 相对链接悬空**（`docs/protocol-pcap-test/mpls/` 目录不存在，G-MPLS-8）——但该文件的 **14/14 数字今日已被本车道独立复跑证实**（设计 §0.2：`RESULT: 14 pass, 0 fail, 0 error`），**与 pcep G-PCEP-11 / opcua G-OPCUA-10 的"过期产物"性质不同**（mpls.md 末次提交 `d62db10` **晚于**判死提交 `0417be5`）。**不得**把本提醒读成"套件不可跑"。

**跑测避坑（本车道亲踩）**：套件默认 `DOC_DIR=../../docs/protocol-pcap-test`，**不带 `DOC_DIR` 直接跑会把 tracked 的 `SUMMARY.md` 与 `mpls.md` 就地覆盖**（本车道首跑即发生，已 `git checkout` 还原）。复跑时**必须** `DOC_DIR=<临时目录>`。

---

## 10. 修订记录

- v1.2.0（2026-10-01，本轮静态闭环）：修正配套设计路径、同步 as-built planner 测试计数（8 个测试、463 行）、将单标签基线断言收窄为 `packet_count: 1`、校正 cases 中两条 RFC notes；G-MPLS-16/17 关闭。自审 2 轮，末轮干净。

- v1.0.0（2026-09-29，批次二文档轨 as-built 首版）：首次成文（本仓库无 mpls 旧稿）。**核心产出**：①形状基线机读实测（§1：14 例 / 7 正 7 负 / 全例 `[ip,mpls]` / fields 28 + frames 1 / 顶层零违规游离键）；②**今日实跑复核**（§1 + 设计 §0.2：14 pass / 0 fail / 0 error，28 条 field + 1 条 frame 逐条命中，与 2026-09-27 存盘产物字段面 7/7 一致）；③正例逐项断言契约（§3，含 `00 06 41 40` 的**逐位复算**）；④负例契约（§4，2 create-time + 5 task-time，锚词逐字）；⑤对账两行（§5.2：104 逻辑点 = 覆 51 + 不适用 30 + 立项 23，机读逐格计数）；⑥P3 固定动作（§6：§3.15 三项中 ① 已覆、②③ 显式不适用）；⑦执行建议含**跑测避坑**（§7 第 3 条：`DOC_DIR` 未设会覆盖 tracked 产物）；⑧存量审计 14 行逐条去向（§8，0 作废）；⑨**新增**覆盖反查门建议 11 行（§9，不重复既有 `check_mpls` 的 22 行）；⑩缺口 G-MPLS-1…G-MPLS-18 的 testcase 侧落点。自审 3 轮，末轮干净（机读复核：14 ID 与 cases JSON 顺序一致 / 28 field + 1 frame 与实跑 pcap 全命中 / 四表计数机读复算 / 缺口 18 条 testcase 侧落点齐 / 22 处条款号引用面复核）。

**盘点（自审后补记，2026-10-01）**：缺口编号的 testcase 侧落点——**G-MPLS-1**（§8.2 第 1/2 条 + §8.3 的 T11/T13 改写动作）、**G-MPLS-2**（§8.2 第 3 条 + §8.3 T1 邻域）、**G-MPLS-3**（设计 §3.5 TTL 表末行；**本契约无对应用例**——无断言面）、**G-MPLS-4**（§6.2 A′ 保留标签面）、**G-MPLS-5**（§6.2 A′ VLAN 面）、**G-MPLS-6**（§6.2 A′ DSCP 面）、**G-MPLS-7**（§4.2 末段 7 条未入例分支）、**G-MPLS-8**（§8.4 + §9 末段）、**G-MPLS-9**（§1 输出契约 + §6.2 A′ NIC 路）、**G-MPLS-10**（§3.5 裸头声明）、**G-MPLS-11**（§6.2 A′ TTL/payload 面）、**G-MPLS-12**（§6.2 A′ 边界等值面）、**G-MPLS-13**（§6.2 A′ 动态面）、**G-MPLS-14**（§5.1 第三源行）、**G-MPLS-15**（§8.2 第 10 条）、**G-MPLS-16**（§4.2 末段 + §6.2 B′）、**G-MPLS-17**（**已关闭：#1 已收窄为 `packet_count: 1`**）、**G-MPLS-18**（§3.3 MAC 断言缺失段 + §6.2 A′ MAC 面）。
