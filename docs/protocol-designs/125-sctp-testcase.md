# #125 sctp（SCTP · RFC 4960 传输层）测试用例契约

> 版本：v1.0.0（as-built 文档轨）
> 日期：2026-09-29
> 配套设计：`docs/protocol-designs/125-sctp-design.md` v1.0.0（D-SCTP-1 as-built 定稿）
> 旧基线：**无**（本协议此前无任何用例文档，设计 §0）
> 机器契约：`trafficgen/test/protocol_pcap/cases/sctp.json`（**11 例 = 8 正 + 3 负**；ID/顺序/包数/断言本版逐条机读对账，§8）
> 白话一句：**十一条检查：八条看正常跑（建关联、字节钉、双向数据、分片、心跳、多宿、突断、全字段钉），三条看胡来能不能被拦下（备用地址用 v6、分片尺寸越下界、越上界）；每条只查一件事。**

## 1. 测试原则和形状基线

用例从设计 §3–§9 逐项派生，共 **11 个唯一语义 ID：8 正 + 3 负**（负例 N-1/N-2 = A 类建链期 2 条，N-3 = B 类任务期 1 条）。派生规则：设计 §3 每个线格式条款、§5 每个阶段/自动派生行为、§7 每行错误处理在本文有对应断言；断言不得超出设计声明范围。**一个用例只验证一个协议行为**。

**形状基线（2026-09-29 机读实测）**：

| 检查项 | 结果 |
|---|---|
| 例数 / ID 唯一 | **11 / ✓** |
| 层链形 | **11/11 = `[ip, sctp]`**（两层，raw-IP 自驱终层） |
| `spec_json` 顶层键 = `{layers}`（唯一键） | **11/11**（**零游离键、零顶层 sctp 子映射、零顶层四元组——非负例顶层键 = 0 今日即成立**） |
| 用例外层键 | `{expect,id,proto,spec_json,summary}` ×11（无 `strategy_fc`/`group_id` 附加） |
| 正例包数断言 | `packet_count` ×8（全部精确计数，无 `min_packets`） |
| 正例 `has_handshake/negotiated/terminates` | **三键恒 false ×8**——TCP 语义键（runner 仅 true 时检查 → no-op 噪声键，G-SCTP-9）；SCTP 的四握手/三关闭由 `chunk_type` 断言承载 |
| 正例 `notes` | ×8（声明性文案，含中性端口/PPID 选值理由，设计 §0 #1） |
| 负例 `expect` 键集合 | `{expect_error, error_contains, notes}` ×3（**含 `notes`**，非严格两键，G-SCTP-15） |
| 负例锚词命中代码字面值 | ✓ 3/3（§4 表） |

**输出契约（pcap/NIC 双输出）**：两路径共用同一 cases JSON 与断言集（`sctp.srcport/dstport`、`sctp.chunk_type`、`ip.src`、frames offset 46）；NIC 经 tcpdump 捕获（`nic_capture` 用例级开关）；**不设仅单路径可用的断言**——本版 11 例全部只用两路径均可观察的字段。

**TSHARK 基线（实测，tshark 3.6.14）**：`sctp.*` 字段表在册（`srcport/dstport/verification_tag/checksum/chunk_type/chunk_flags/chunk_length/data_tsn/data_sid/data_ssn/data_payload_proto_id/init_initiate_tag/initack_initiate_tag/cookie` 等）；8 个正例 pcap **全部被解码**（`_ws.col.Protocol = SCTP`，Info 列给出 `INIT/INIT_ACK/COOKIE_ECHO/COOKIE_ACK/DATA/SHUTDOWN/SHUTDOWN_ACK/SHUTDOWN_COMPLETE/HEARTBEAT/HEARTBEAT_ACK/ABORT` 全名），**零 `_ws.malformed`**（8 文件逐文件实测 malformed=0）。

可用字段通道（实测）：① `sctp.chunk_type`（**十进制串**）；② `sctp.srcport/dstport`（十进制串）；③ `ip.src/dst`（点分十进制）；④ frames 原始 hex（offset 46）。**进制纪律**：`sctp.verification_tag`/`sctp.checksum` 是 `0x` 前缀十六进制串——存量断言未用（随机面 + M-1 面，见下）。

**M-1 对字段断言的影响（必读，设计 §3.8）**：**被以太网填充的帧（帧短于 60）其线上的 CRC32c 是按"含填充"口径算的**，对按 RFC 4960 §6.8（IP 总长定界）校验的接收端必然失败——8 个正例 70 帧中 **30 帧受影响**（独立复算 30/30 双口径实证）。tshark 报 `sctp.checksum.status=2`（**Unverified**，该校验缺省关闭）故不暴露。**今日 11 例零条断言 checksum 面**（机读实测），故全绿而不自知。**任何 A′ 新增例若断言 `sctp.checksum`，必须按修复后（IP 定界）口径钉，不得按今日字节钉。**

**断言基线（机读实测）**：**20 条 `frames` 断言 + 19 条 `fields` 断言 + 8 条包数断言 = 47 条**，全部对磁盘 pcap（`/tmp/mcp-pcaps/sctp/`，文件日期 2026-09-27）逐条复算，**零不符**。字段分布：`sctp.chunk_type` **10** / `sctp.srcport` **1** / `sctp.dstport` **1** / `ip.src` **2** / frames **20**。

**不可断言字段（纪律，设计 §6/G-SCTP-10）**：`sctp.verification_tag`、`sctp.data_tsn`、`sctp.cookie`、HB nonce 后 8B、`ip.id` **五类无种子随机**（`rand` 直调），同一配置两次运行不同。**今日零条断言**（机读实测），**未来新增断言亦不得钉这五类**（HB 令牌的 magic 4B + counter 4B 可钉，G-SCTP-13）。

**包数约定（实测公式，设计 §9）**：

```
帧数 = 4（握手）+ 2×heartbeat对数（缺省 1）+ Σ_每个 chunk 的分片数
     + (abort ? 1 : 3)
分片数 = ⌈len(data)/fragment_size⌉（fragment_size ≤ 0 时 = 1）
```

负例无包数断言（A 类不产 pcap；B 类 pcap 实测 **0 帧**）。

**保活/重试/RST 口径**：协议层保活 = **HEARTBEAT**（#5/#6 已覆）；**无重试/重连**（无状态机，§5）；**RST 不适用**——sctp 是 raw-IP 自驱层、无 tcp 层，SCTP 自身的异常中断形态 = **ABORT 块（#7 已覆）**。正例恒以 SHUTDOWN 三路（或 #7 的 ABORT）结束。

## 2. 原子用例索引（11 ID = 8 正 + 3 负，顺序为权威）

| # | ID | 类型 | 场景（依据链） | 包数断言（实测） | 断言数 |
|---:|---|---|---|---|---:|
| 1 | `sctp_t1_baseline_assoc` | 正 | 设计 §3.3/§3.6/§3.7：4 握手 + 3 关闭基线，chunk_type 序 1/2/10/11/7/8/14 | `packet_count: 7`（实测 7 ✓） | 9 f + 1 fr |
| 2 | `sctp_t2_handshake_bytes` | 正 | 设计 §3.3/§3.7：显式双 Tag 的 VTag 逐帧钉 + INIT/INIT-ACK/COOKIE-ECHO 字节钉 | 7（实测 7 ✓） | 9 fr |
| 3 | `sctp_t3_data_bidir` | 正 | 设计 §3.4：DATA 双向（up "ping" / down "pong" PPID 1000） | 9（实测 9 ✓） | 2 f + 4 fr |
| 4 | `sctp_t4_fragment_flags` | 正 | 设计 §3.4：分片三 flags（100B@16 → 7 段 B/middle×5/E + TSN 500→506） | 14（实测 14 ✓） | 2 fr |
| 5 | `sctp_t5_heartbeat_primary` | 正 | 设计 §3.5：HEARTBEAT 对 ×2 主路径（插在 COOKIE-ACK 后） | 11（实测 11 ✓） | 4 f |
| 6 | `sctp_t6_altpath_multihoming` | 正 | 设计 §3.3/§3.5：AltPath 多宿（备用 4 元组心跳 + INIT 携 IPv4 Address 参数） | 9（实测 9 ✓） | 3 f + 2 fr |
| 7 | `sctp_t7_abort` | 正 | 设计 §3.6：ABORT 突断**替代**三路关闭（5 帧） | 5（实测 5 ✓） | 1 f + 1 fr |
| 8 | `sctp_t8_explicit_tsn_sid` | 正 | 设计 §3.4：DATA 全头逐字节钉（TSN/SID/SSN/PPID/载荷） | 8（实测 8 ✓） | 1 fr |
| 9 | `sctp_t9_neg_altpath_v6` | 负 B | 设计 §7 N-3：AltPath.SrcIP IPv6 拒（同族约束） | —（实测 0 帧 ✓） | 0 |
| 10 | `sctp_t10_neg_frag_small` | 负 A | 设计 §7 N-1：fragment_size=1 低于下界拒 | —（不产 pcap ✓） | 0 |
| 11 | `sctp_t11_neg_frag_upper` | 负 A | 设计 §7 N-2：fragment_size=1000001 超上界拒 | —（不产 pcap ✓） | 0 |

**包数公式校验（8/8 正例）**：#1/#2 可选 0 → 7 ✓；#3 DATA 2 → 9 ✓；#4 分片 7 → 14 ✓；#5 HB 2 对 → 11 ✓；#6 HB 1 对 → 9 ✓；#7 abort → 5 ✓；#8 DATA 1 → 8 ✓。**与实测 pcap 帧数逐例一致**。

**T-编号对照**：存量 `summary` 中的 `T-1…T-11` 编号 ≡ 本表 #1–#11（`T-1` ≡ `sctp_t1_baseline_assoc` … `T-11` ≡ `sctp_t11_neg_frag_upper`）。**序号以 cases JSON 顺序为权威。**

## 3. 正例逐项断言契约（最低断言集，实现期可增不可减）

每例均含包数断言 + `frames`/`fields`；帧位由 §1 公式与实测 pcap 双向确认。**全部 47 条断言已逐条对磁盘 pcap 复算通过（零不符）。**

**共性断言（8 正例全体的结构事实）**：帧 1/3/5…= up（10.0.0.1→20.0.0.1，端口 12345→5000），帧 2/4/6…= down（地址端口互换）；VTag 面 = 设计 §3.7 表（INIT 恒 0；down 帧带客户端宣告 tag、up 帧带服务端宣告 tag——随机时两侧值不同但**同侧恒同值**，T-1 实测 0x680257af/0x9e2c4ea8 双值交替）。

### 3.1 `sctp_t1_baseline_assoc`（7 帧）

`sctp` 层只给 `{src_port:12345, dst_port:5000}`（Tag/块全缺省）。

- `packet_count=7`；帧 4 `sctp.chunk_type=11` + frames：**帧 4 offset 46 = `0b 00 00 04`**（COOKIE-ACK 纯 4B 头）。
- fields 9 条：帧 1 `sctp.chunk_type=1` + `sctp.srcport=12345` + `sctp.dstport=5000`；帧 2 `chunk_type=2`；帧 3 `chunk_type=10`；帧 4 `chunk_type=11`；帧 5 `chunk_type=7`；帧 6 `chunk_type=8`；帧 7 `chunk_type=14`。
- **chunk_type 序列 1/2/10/11/7/8/14 即四握手+三关闭时间线的直接断言**（设计 §12.3）。
- notes 自陈三项：包数实测钉 7 / SCTP 无 TCP 握手挥手（三 false 键不适用）/ 端口选中性值 5000 避 tshark 启发式误报。

### 3.2 `sctp_t2_handshake_bytes`（7 帧）

加 `verification_tag: 305419896`（0x12345678，客户端宣告）、`initiate_tag: 2271560481`（0x87654321，服务端宣告）。

- frames 9 条（**VTag 语义逐帧钉**，设计 §3.7 表的直接证据）：
  - 帧 1 offset **38** = `00 00 00 00`（INIT 的 VTag 恒 0，RFC 4960 §5.1）
  - 帧 1 offset 46 = `01 00 00 14`（INIT chunk_len 20 = 4+16 固定字段）
  - 帧 2 offset **38** = `12 34 56 78`（INIT-ACK VTag = 客户端宣告 tag）
  - 帧 2 offset 46 = `02 00 00 38`（INIT-ACK chunk_len 56 = 4+16+36 cookie 参数）
  - 帧 3 offset **38** = `87 65 43 21`（COOKIE-ECHO VTag = 服务端宣告 tag）
  - 帧 2 offset **66** = `00 07 00 24`（INIT-ACK 内 State Cookie 参数头：type 7 + len 36 = 4+32）
  - 帧 3 offset 46 = `0a 00 00 24`（COOKIE-ECHO chunk_len 36 = 4+32 cookie）
  - 帧 4 offset 46 = `0b 00 00 04`（COOKIE-ACK）
  - 帧 4 offset **38** = `12 34 56 78`（COOKIE-ACK VTag = 客户端宣告 tag）
- **cookie 32B 每轮随机（rand.Read）——回显一致性静态钉不可为**，由单测 `TestPlanCookieEchoMatchesINITACK` 钉（notes 自陈）。

### 3.3 `sctp_t3_data_bidir`（9 帧）

`chunks=[{direction:"up", data:"ping"}, {direction:"down", ppid:1000, data:"pong"}]`。

- frames 4 条：帧 5 offset 46 = `00 03 00 14`（DATA type 0 / flags 0x03 B+E / len 20 = 4+12+4）；帧 5 offset **54** = `00 00 00 00 00 00 00 00 70 69 6e 67`（**SID+SSN+PPID 全 0 + "ping"**——TSN @50 随机不钉）；帧 6 offset 46 = `00 03 00 14`；帧 6 offset 54 = `00 00 00 00 00 00 03 e8 70 6f 6e 67`（**PPID 000003e8 = 1000 + "pong"**）。
- fields 2 条：帧 5/6 `sctp.chunk_type=0`。
- **方向面证据**：帧 6 是 down 帧（20.0.0.1→10.0.0.1、5000→12345）——断言落在 chunk 内容面，方向由帧内地址排列承载（设计 §2 方向纪律）。

### 3.4 `sctp_t4_fragment_flags`（14 帧）

`fragment_size: 16` + `chunks=[{tsn:500, data:"y"×100}]`。

- frames 2 条：帧 5 offset 46 = `00 02 00 20 00 00 01 f4`（**首段 B flag(0x02)**，chunk_len 32 = 4+12+16，**TSN 500 = 0x01f4**）；帧 11 offset 46 = `00 01 00 14 00 00 01 fa`（**末段 E flag(0x01)**，chunk_len 20 = 4+12+4，**TSN 506 = 500+6**）。
- **中段 flags 0x00 由 7 段序列承载**（帧 6–10 各 78B，实测 flags=00——设计 §3.4 flags 表）。
- 包数证据：4 握手 + 7 分片 + 3 关闭 = 14 ✓。

### 3.5 `sctp_t5_heartbeat_primary`（11 帧）

`heartbeats: {count: 2}`（无 chunks）。

- fields 4 条：帧 5 `sctp.chunk_type=4`（HEARTBEAT）；帧 6 `chunk_type=5`（HEARTBEAT-ACK）；帧 7 `chunk_type=4`；帧 8 `chunk_type=5`——**严格交替对**。
- 包数证据：7 基线 + 2 对（4 帧）= 11 ✓。**插入位置**：COOKIE-ACK 后、（无 DATA 时）SHUTDOWN 前——帧 4 COOKIE-ACK 与帧 9 SHUTDOWN 之间恰 4 帧，位置由包数与 chunk_type 序列间接钉。
- **HB 令牌（"HBTC" magic + 计数器）今日零断言**（frames 空）→ A′ 收编（G-SCTP-13）。

### 3.6 `sctp_t6_altpath_multihoming`（9 帧）

`heartbeats: {alt_path: {alt_src_ip:"10.0.0.9", alt_dst_ip:"20.0.0.9"}}`（count 缺省 = 1 对）。

- frames 2 条：帧 1 offset 46 = `01 00 00 1c`（INIT chunk_len 28 = 20 + IPv4 参数 8）；帧 1 offset **66** = `00 05 00 08 0a 00 00 09`（**IPv4 Address 参数 type 5 / len 8 / IP 10.0.0.9**，RFC 4960 §3.3.2.1）。
- fields 3 条：帧 1 `chunk_type=1`；**帧 5 `ip.src=10.0.0.9`**（HEARTBEAT 走备用源）；**帧 6 `ip.src=20.0.0.9`**（HEARTBEAT-ACK 走备用目的侧）——**多宿换源的直接证据**。
- 包数证据：7 基线 + 1 对 = 9 ✓；端口继承（5000/12345 不变，fields 面未钉但帧 1 端口断言同 #1）。
- **notes 文案缺陷**：note2 "offset74 实测钉：00 05 00 0a" 与本例 frames 断言（offset 66 / len 0x0008）及 note1 矛盾——**frames 断言为准，note2 是错的**（G-SCTP-8，P4 改写）。

### 3.7 `sctp_t7_abort`（5 帧）

`abort: true`。

- frames 1 条：帧 5 offset 46 = `06 00 00 04`（ABORT 纯 4B 头，无 Cause，T bit=0）。
- fields 1 条：帧 5 `sctp.chunk_type=6`。
- **替代非叠加证据**：5 帧 = 4 握手 + 1 ABORT（无任何 SHUTDOWN 系帧）——RFC 4960 §9.1 突断语义（设计 §3.6）。VTag=服务端宣告 tag（随机不钉）。

### 3.8 `sctp_t8_explicit_tsn_sid`（8 帧）

`chunks=[{tsn:100, sid:5, ssn:7, ppid:47, data:"m3ua"}]`。

- frames 1 条：帧 5 offset 46 起 **20 字节全头逐字节** = `00 03 00 14 | 00 00 00 64 | 00 05 | 00 07 | 00 00 00 2f | 6d 33 75 61`（type 0 / flags 03 / len 20 / **TSN 100** / **SID 5** / **SSN 7** / **PPID 47** / "m3ua"）。
- 本例是 **DATA 块全字段布局的唯一完整字节证据**（设计 §3.4 表逐字段对应）。

## 4. 负例契约（3 条，A 类 2 + B 类 1）

负例必须在对应校验点失败并传播为 task error，不得产出成功 PCAP 或假成功。锚词与设计 §7 表一一对应、同序：

### 4.1 A 类：建链期拒绝（create-time，registry V9 层字段范围门，无 pcap）

| ID | 故障输入 | JSON `error_contains` | 代码锚词（逐字） | 拦截点 |
|---|---|---|---|---|
| `sctp_t10_neg_frag_small` | `fragment_size=1` | `out of range [16,1000000]` | `layers: layer "sctp" field "fragment_size" = 1 invalid: out of range [16,1000000]` | registry V9（`complete.go:325`） |
| `sctp_t11_neg_frag_upper` | `fragment_size=1000001` | 同上 | 同上（值不同） | 同上 |

### 4.2 B 类：任务期校验器拒绝（task-time，pcap 实测 0 帧）

| ID | 故障输入 | JSON `error_contains` | 代码锚词（逐字） | 拦截点 |
|---|---|---|---|---|
| `sctp_t9_neg_altpath_v6` | `heartbeats.alt_path.alt_src_ip="2e01::46"` | `only IPv4 multi-homing` | `AltPath.SrcIP 2e01::46 is IPv6; only IPv4 multi-homing is supported (RFC 4960 §3.3.2.1 type 5)` | planner `Validate`（`sctp.go:137`） |

实测 `sctp_t9_neg_altpath_v6.neg.pcap` = 24 字节（仅 pcap 全局头）= **0 帧** ✓。**无假成功**：三例均无成功包结构断言，`expect` 执行期严格只有 `expect_error`/`error_contains`（`notes` 为文档键，G-SCTP-15）。

### 4.3 未入用例的拒绝分支（A′ 立项，不得冒充已覆盖）

`invalid source IP` / `invalid destination IP` / `invalid AltPath.SrcIP`（分支 1/2/3）/ AltPath.DstIP IPv6 与不可解析（分支 6/7）/ 同族约束两分支（分支 5/8）/ `sctp.fragment_size=%d is below minimum`（**分支 9 层内不可达**——registry V9 [16,1e6] 先拦，1–15 落 V9、显式 0 过 V9 且 planner 跳过、负值落 V9 not-a-number）；**顶层 sctp presence 判死**（`rejects a top-level sctp sub-config`，今日已接线无用例）。全部 G-SCTP-14/G-SCTP-7。

## 5. 覆盖与对账

### 5.1 三源回指行

RFC 4960（章节号已核实，设计 §10）+ D-SCTP-1（设计 §11）+ tshark 3.6.14 字段表与 **9 例磁盘 pcap**（`/tmp/mcp-pcaps/sctp/`）→ 11 ID（本契约 §2）。第三源"已确认现网行为"当前 = **抓包级已到**（本仓引擎产出的 8 例 pcap 逐帧复算：47 条断言零不符；CRC32c 70 帧双向复算 = M-1 证据），但**真实 SCTP 栈（Linux 内核等）的线字节未取到、RFC 9260 差异未核对** → G-SCTP-14（按 §5.2 不写死进实现）。

**11 ID 逐项回指（§9.5 要求）**：#1←设计 §3.3/§3.6/§3.7；#2←§3.3/§3.7；#3←§3.4；#4←§3.4；#5←§3.5；#6←§3.3/§3.5；#7←§3.6；#8←§3.4；#9←§7 N-3；#10←§7 N-1；#11←§7 N-2。

### 5.2 对账两行 + 清单出处声明

- **清单出处声明**：本清单来源 = **RFC 4960 原文（章节号经 rfc-editor.org 核实）+ 仓库落码反推 + tshark 3.6.14 字段与 pcap 实测**，**非纯规范反推**（RFC 9260 差异与真实栈线字节未核对 → G-SCTP-14）。
- **对账两行**：**要求逻辑点总数 = 73**（八项 8 行 + 矩阵 33 格 + 变体 22 行 + 商业映射 10 行 = 8+33+22+10）；**用例覆盖数 = 47**；**不适用 = 13**；**开放立项（A′）= 13**。**47 + 13 + 13 = 73** ✓
  **粒度声明（严格按行/格重数，每点 1 计，不折算）**：
  - §10.1 八项：8 = 覆 **3**（连接模型 / 字段表 / 超时活性）+ 立项 **3**（消息表 / 错误处理 / 版本方言）+ 不适用 **2**（状态机 / NAT 被动模式）✓
  - §10.2 矩阵 33 格：覆 **23** + 不适用 **10** ✓
  - §10.3 变体 22 行：覆 **13** + 立项 **9** ✓
  - §10.4 商业 10 行：覆 **8** + 不解决 **1** + 立项 **1** ✓
  - **合计 = 47 覆 + 13 A′ + 13 不适用 = 73** ✓
  **G-SCTP-1…G-SCTP-15 与 M-1 不折进 73**（缺口表另计 15 条，M-1 ≡ G-SCTP-1）。**反查全绿 ≠ 覆盖全**（§9.52 原文）。
- **门3 抽查候选**：最复杂用例 = **#2 `sctp_t2_handshake_bytes`**（7 帧里 9 条 frame 断言，VTag 三值两向 + cookie 参数头交叉；交织维度 = 帧(7)×字段(2 类)×偏移(38/46/66)×Tag 双值）；**建议门3 抽 #2 + #6**（`sctp_t6_altpath_multihoming` 补多宿换源 + 地址参数面）。

## 6. P3 固定动作（CORE_MEMORY 管线：§3.15 三项 + A′/B′ 两分类 + 3.14 豁免）

### 6.1 §3.15 三项逐项一例或立项

| # | 三项 | 本协议对照 | 用例/立项 |
|---|---|---|---|
| ① | 同连接/同流内的多轮操作 | 单关联内多 DATA 块（#3 双向两块；#4 七分片连发） | 已覆 #3/#4 |
| ② | 非正常结束 | SCTP 异常中断形态 = ABORT（#7，5 帧替代关闭）；无 tcp 层 RST 概念 | **已覆 #7**（ABORT 即异常中断生成面） |
| ③ | 长保活 | HEARTBEAT 周期探测（#5 双对；#6 多宿探测） | 已覆 #5/#6 |

无空项：① ② ③ 各有已覆例。

### 6.2 A′/B′ 两分类表

**A′（P4 接线）**：

| 类 | 内容 | 落点 |
|---|---|---|
| checksum 面 | M-1 修复后收编 `sctp.checksum` 断言（IP 定界口径）+ 全帧复算 | G-SCTP-1 |
| 拒绝分支面 | 8 条未入例 Validate 分支（IP 解析 2 / AltPath 不可解析 2 / DstIP v6 / 同族 2 / 分支 9 不可达登记）+ presence 红例 | G-SCTP-14 / G-SCTP-7 |
| 越界截断面 | chunks[].tsn/sid/ssn/ppid 越界拒绝（先修静默截断） | G-SCTP-2 |
| 动态字段面 | 端口 allowlist 行 + `sctp_port_dyn`（inc 端口池 + ip 动态）+ 其余四策略 | G-SCTP-3 |
| 异族面 | 父子同族约束 + `sctp_neg_mixed_family` | G-SCTP-4 |
| IPv6 面 | `sctp_ipv6`（M-1 修复后含 checksum 复算） | G-SCTP-6 |
| 形状清理面 | 8 正例删三 false 键 + 3 负例删 notes + t6 note2 改写 | G-SCTP-9/8/9 |
| 多流面 | `sctp_multi_stream` 双 SID 双 chunk | G-SCTP-12 |
| HB 断言面 | #5 补 frames（magic + counter） | G-SCTP-13 |
| 变体补例面 | 零载荷 DATA / 整除边界 / AltPath 部分覆盖 | 设计 §10.3 行 8/13/20 |
| SHUTDOWN TSN 面 | cumTSN 随机语义裁定 | G-SCTP-10 |
| 死代码面 | SACK/ERROR builder 删除或接线裁定 | G-SCTP-11 |

**B′（框架面）**：顶层未知键通用门（等框架级 unknown-key 白名单，不单独立项）/ `sub_flows` 键静默无效 + `emitSCTPSubFlow` sctp 分支（G-SCTP-5）/ 引用漂移修正（§3.5.1→§3.3.5，G-SCTP-14）。进设计 §14。

### 6.3 3.14 豁免边界审计

**有长连接载体（SCTP 关联）→ `sessions[]` 形态不豁免**——但 registry Fields **无 `sessions` 键**（8 键机读实测），多会话只能靠策略级多流表达（本版未用）；#6 的 AltPath 子流是**同一关联内的备用路径**，不是第二会话（形态差异已声明，设计 §12.3）。**多流并发**由 `flow_control {"flows": N}` 承载（端口动态受限 G-SCTP-3，ip 动态可变址）。**单包多载荷** = **不适用**（一个 SCTP 包按本实现恒单 chunk，无多 question/多 RR 类形态；RFC 允许的 chunk 捆绑未实现，如实声明）。**流关联（控制流派生数据流）** = **AltPath 多宿子流**为本协议特有形态（#6 已覆；GroupID 继承未落码的诚实声明见设计 §12.3/G-SCTP-5）。

## 7. 实现后执行建议

1. **P4 顺序**：①**先修 M-1**（CRC 按 IP 总长定界计算，`builder.go:1326`）——**帧长与包数不变**，故 §2 包数公式与全部 20 条 frames 断言**无需重钉**（frames 不触 checksum 4 字节……**注意**：t2 帧 1 offset 46 起 4B 断言不含 @42 checksum，实测无碰撞；若未来 frames 断言窗口覆盖 @42–45 须按修复后口径重钉）；②补 A′ 拒绝分支例（8 条 + presence 红例）；③补 checksum/动态/多流/IPv6 面；④形状清理（三 false 键 + notes）；⑤全量复跑。
2. **实测顺序**：先 #1（7 帧基线 + chunk_type 序列），再 #2（VTag 逐帧 + cookie 参数头），再 #8（DATA 全头单例），再 #3/#4（双向与分片），再 #5/#6（HB 与多宿），最后 #7（ABORT）。
3. 二进制与 HEAD 同代确认（门2③）；门2② 全量（`CASE_PROTO=sctp` 全量不是增量）；门2④ 反查绿后进 P6。
4. **本协议无 §1 迁移步骤**（非负例顶层键今日已为 0，设计 §12.1）。
5. 任何 RFC 4960 条款号的具体引用须有规范原文证据（G-SCTP-14 纪律；§3.5.1 漂移勿再复制）。

## 8. 存量审计（11 例逐条去向）

### 8.1 存量实测面（2026-09-29）

`cases/sctp.json` **11 例**：8 正带 `packet_count` 精确断言（7/7/9/14/11/9/5/8），**与实测 pcap 帧数 8/8 逐例一致**（tshark 逐文件）；3 负中 A 类 2 例无 pcap、B 类 1 例 pcap **0 帧**（24 字节 neg.pcap）；**非负例顶层键 = 0**（11/11 顶层仅 `{layers}`）；**47 条断言逐条对实测 pcap 复算（全 OK）**；层内 `sctp` 带 **8 键**（与 registry Fields 及生成表逐键一致，机读实测）；CRC32c 70 帧双向复算 = **M-1 证据**（30 帧填充面不符 RFC 口径）。

### 8.2 现状矛盾点（P4 前诚实登记）

1. **M-1 confirmed 缺陷（CRC 填充范围）**：30/70 帧的 CRC32c 含以太网填充字节，对 RFC 定界口径的接收端必然校验失败；tshark Unverified 不暴露；存量断言零覆盖（设计 §3.8）。
2. **t6 note2 文案错误**："offset74 实测钉：00 05 00 0a" 与本例 frames 断言（offset 66 / `00 05 00 08`）及 note1 矛盾——**frames 断言为准**（G-SCTP-8）。
3. **`has_handshake/negotiated/terminates` 三键恒 false ×8**：TCP 语义 no-op 键（runner 仅 true 时检查）——语义上无害（SCTP 无 TCP 标志位），形状上属 TCP 族残留（G-SCTP-9）。
4. **负例 expect 含 `notes` 键 ×3**：非严格两键口径（G-SCTP-15）。
5. **chunk 级字段越界静默截断**：`chunks[].tsn/sid/ssn/ppid` 经 getUint32/getUint16 无范围拒绝（G-SCTP-2）；validate.go 的顶层 sid/ssn 分支双重死。
6. **SHUTDOWN cumTSN 随机语义**：服务端无 DATA 时 serverTSN-1 无意义（G-SCTP-10）。
7. **动态字段零覆盖**：11 例全静态；端口动态不可用（G-SCTP-3）。
8. **`emitSCTPSubFlow` sctp 分支 wire 缺陷**（INIT-ACK type 1 + 空 cookie）+ 顶层 `sub_flows` 静默无效（G-SCTP-5）。
9. **引用漂移**：代码/notes 引 "RFC 4960 §3.5.1"（HEARTBEAT 实为 §3.3.5，rfc-editor.org 核实）（G-SCTP-14）。
10. **结果产物链接悬空（全仓共性，非 sctp 特有）**：`trafficgen/docs/protocol-pcap-test/sctp.md` 写 `Cases: 11 — pass 11` 且链接 `sctp/<id>.pcap`，但 `docs/protocol-pcap-test/` 下**没有任何协议子目录**。**该产物末次提交 `94adc3c`（2026-09-21）晚于判死提交 `0417be5`（2026-09-13），按批次二任务书口径不属于"过期产物"**，不登记该类缺口；悬空链接登记为事实（设计 §0 #3）。
11. **本车道未跑引擎**：§8.1 的"逐条一致"是**存量 JSON 断言 × 磁盘既有 pcap**（文件日期 2026-09-27）的机读对账，**不等于今日复跑套件绿**（设计 §0 取证边界）。
12. **tshark checksum 面结论纠偏**：ngap（#116）文档声称"填充字节计入 CRC 是 RFC 4960 §6.8 要求"——本车道独立复算裁定：**以太网填充不属于 SCTP 包**（IP 总长定界），该结论不采信、不复制（设计 §3.8）。

### 8.3 逐条去向表（11 行）

| 存量 id | T-编号 | 去向 | 改写动作（P4） |
|---|---|---|---|
| `sctp_t1_baseline_assoc` | T-1 | **保留** | 形状已合规（纯 layers）；删三 false 键（G-SCTP-9） |
| `sctp_t2_handshake_bytes` | T-2 | **保留** | 同上；M-1 修复后可补 INIT 帧 VTag=0 已有（frames 已覆盖）——补 `sctp.checksum` 面走新例 |
| `sctp_t3_data_bidir` | T-3 | **保留** | 删三 false 键；可补 down 帧端口换向 field 断言 |
| `sctp_t4_fragment_flags` | T-4 | **保留** | 删三 false 键；可补中段 flags=00 field 断言 |
| `sctp_t5_heartbeat_primary` | T-5 | **改写** | 删三 false 键 + 补 frames 断言（HB 令牌 magic/counter，G-SCTP-13）+ note 引用 §3.5.1→§3.3.5 |
| `sctp_t6_altpath_multihoming` | T-6 | **改写** | 删三 false 键 + **改写 note2**（offset74/00 0a 为错误文案，G-SCTP-8） |
| `sctp_t7_abort` | T-7 | **保留** | 删三 false 键 |
| `sctp_t8_explicit_tsn_sid` | T-8 | **保留** | 形状合规（唯一全字段钉例） |
| `sctp_t9_neg_altpath_v6` | T-9 | **保留** | 收窄 `notes`（G-SCTP-15）；可补 DstIP 分支例（A′） |
| `sctp_t10_neg_frag_small` | T-10 | **保留** | 收窄 `notes`（G-SCTP-15） |
| `sctp_t11_neg_frag_upper` | T-11 | **保留** | 收窄 `notes`（G-SCTP-15） |

**无"作废不注原因"：0 作废，0 等价覆盖**（11 例全部保留/改写 + A′ 新增）。**本协议非负例顶层键今日已为 0**（§1）。

## 9. 附：覆盖反查门建议断言行（供主线程合后登记；本车道不碰 `coverage_gate.py`）

**现状**：`trafficgen/tools/coverage_gate.py` **已有 `check_sctp`**（两处定义 `:3960`/`:6281` 内容逐字相同，后者生效；D-SCTP-1 P6 落地件：11 场景面 + 8 键覆盖 + 2 锚词面 = **21 行**，本车道实测 21/21 全绿；docstring 写 "对账 20/20" 与实际 21 行有一行漂移，随本批登记一并校正）。下列为**增量建议**（在既有 21 行之外追加；每条均可从本契约与 cases JSON 直接机读，不需新造事实）：

| # | 建议断言 | 今日状态 | 依据 |
|---:|---|---|---|
| 1 | `len(cases) == 11` 且 ID 集合/顺序 = §2 十一项 | **绿** | 本契约 §2 |
| 2 | 11/11 例 `spec_json` 顶层键 == `{layers}`（**零游离键**，非负例顶层键 = 0） | **绿** | 本契约 §1；设计 §12.1 |
| 3 | 8 正例 `packet_count` == `4 + 2×HB对数 + Σ分片数 + (abort?1:3)`（各因子由 spec 静态推出） | **绿** | 设计 §9 公式 |
| 4 | 3 负例 `expect` 键 == `{expect_error, error_contains}` | **红**（3/3 含 `notes`——G-SCTP-15 收窄后转绿；**如实标红，不得申报今日已过**） | 本契约 §1/§4 |
| 5 | 负例 `error_contains` ∈ 代码锚词集 `{"only IPv4 multi-homing", "out of range [16,1000000]"}` | **绿** | 设计 §7 |
| 6 | 每正例至少一条 frames 断言落在 offset 46（IPv4 chunk 起点） | **绿**（机读实测 20 条 frames 全部 @38/@46/@54/@66，均 ≥46 锚定 chunk 区域） | 本契约 §3 |

**另注意**：`trafficgen/docs/protocol-pcap-test/sctp.md`（tracked 产物）写 `Cases: 11 — pass 11, fail 0, error 0`，末次提交 `94adc3c`（**2026-09-21**）**晚于**判死提交 `0417be5`（2026-09-13）→ **不属于"过期产物"**（pcep G-PCEP-11 判据不满足）；但其中 `sctp/<id>.pcap` 链接全部悬空（`docs/protocol-pcap-test/` 下无任何协议子目录，全仓共性）。**本车道未跑该套件**，故不以任何形式引用该产物作为"今日已复跑"依据。

## 10. 修订记录

- v1.0.0（2026-09-29）：批次二文档轨 #125 **首次成文**。**11 例逐条索引**（§2，含场景/依据链/包数/断言数）+ 正例逐项断言契约（§3，8 例含实测帧字节与 VTag 面）+ 负例契约（§4，A 类 2 + B 类 1，锚词逐条对码，B 类实测 0 帧）+ 覆盖对账（§5，73 点 = 覆 47 + A′ 13 + 不适用 13）+ P3 固定动作（§6）+ 执行建议（§7）+ 存量审计（§8，11/11 保留或改写，**零作废**；12 条现状矛盾点含 M-1 与 ngap 结论纠偏）+ 覆盖反查门增量建议 6 条（§9，既有 `check_sctp` 21 行之上，其中 1 条如实标红）。**47 断言全部对磁盘 pcap 复算零不符**。**未跑引擎**（§8.2 第 11 条）。自审见 `/tmp/pipe/doc-lanes/sctp.md`。
