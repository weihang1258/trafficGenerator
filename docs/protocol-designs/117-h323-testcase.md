# #117 h323（H.323 · H.225.0/Q.931 呼叫信令 + RAS + RTP）测试用例契约

> 版本：v1.0.0（P-PIPE 文档轨 批次二 · as-built 型）
> 日期：2026-09-29
> 配套设计：`docs/protocol-designs/117-h323-design.md` v1.0.0（D-H323-1，as-built）
> 旧基线：**无**——本仓库不存在 h323 旧设计稿或旧用例文档（`find . -iname "*h323*"` 零命中；设计 §0）
> 机器契约：`trafficgen/test/protocol_pcap/cases/h323.json`（**17/17 ID 与本版 §2 一致、顺序一致**，已机读实测）
> 白话一句：**十七条检查：十一条看正常打电话（接通、四种场景、多呼叫、多流、被叫方、改地址、新网段），六条看胡来能不能被拦下（旧写法、静态复制、角色错、场景错、次数负数、名字超长）；每条只查一件事。**

---

## 1. 测试原则和形状基线

用例从设计 §3–§9 逐项派生，共 **17 个唯一语义 ID：11 正 + 6 负**。派生规则：设计 §3 每条线格式条款、§5 每个事务/自动派生行为、§7 每行错误处理在本文有对应断言；断言不得超出设计声明范围。**一个用例只验证一个协议行为**。

**形状基线（2026-09-29 机读实测）**：

| 项 | 实测 |
|---|---|
| 例数 | **17**（11 正 + 6 负） |
| 顶层键 | **`{layers}` ×15** + **`{layers, group_id}` ×1**（`h323_port_dyn`，白名单结构键）+ **`{layers, h323}` ×1**（`h323_vn_presence`，**判死负例必需形状**） |
| 层链 | **`[ip, h323]` ×17**（全例同形；raw-IP 自驱终层，链内无 tcp/udp 层） |
| 正例 `expect` 键集 | `{packet_count, fields, notes}` ×9 / `{packet_count, fields, frames, notes}` ×1（`calls_multi`）/ `{has_handshake, negotiated, terminates, has_payload, min_packets, fields, frames, notes}` ×1（`smoke_01`，**legacy 8 键集，G-H323-8**） |
| 负例 `expect` 键集 | `{expect_error, error_contains, notes}` ×6（含 `notes`，非严格两键，G-H323-19） |
| 断言总量 | **fields 48 条 + frames 5 条** |
| 顶层游离键 | **违规 = 0**：非负例 16/16 顶层键 ⊆ `{layers, group_id}`（15 例仅 `layers`；`h323_port_dyn` 含白名单结构键 `group_id`）；负例 1 例顶层 `h323`（判死形状，非残留） |

**输出契约（pcap / NIC 双输出）**：两路径共用同一 cases JSON 与同一断言集（`q931.message_type` / `tcp.flags` / `tcp.dstport` / `tcp.srcport` / `ip.src` / `ip.dst` / `ipv6.src` / `ipv6.dst` / `udp.srcport` / `udp.dstport` / `frame.len` 字段 + offset 54 frames 原始字节）；NIC 经 tcpdump 捕获（`nic_capture` 用例级开关）；**不设仅单路径可用的断言**。

**TSHARK 基线（3.6.14 实测）**：`tshark -G fields` 中 **`q931.*` 共 156 字段**，本协议用到 `q931.message_type`（唯一在用例中出现的 q931 字段）。可用但**今日未收编**的字段：`q931.disc`（协议鉴别符，恒 0x08）、`q931.call_ref_len`（恒 2）、`q931.call_ref`（CRV 数值）、`q931.call_ref_flag`（方向标志 0/1）、`q931.information_transfer_capability`、`q931.cause_value` → A′ 立项（G-H323-20）。**进制纪律（实测）**：`q931.message_type`、`tcp.flags` 用 `0x` 前缀十六进制串；`tcp.dstport`/`tcp.srcport`/`udp.srcport`/`udp.dstport`/`frame.len` 用十进制串；`ip.src`/`ip.dst`/`ipv6.src`/`ipv6.dst` 用点分/冒分地址串。

**参考 pcap 基线（`/home/pcap_auto/llcj_pcap/IP-TCP-20.4.2.46-30.4.2.46-30000-1720-10-10-2271-1779.pcap`，20 帧实测）**：Q.931 消息序列 = SETUP(0x05) → CALL PROCEEDING(0x02) → FACILITY(0x62) → **ACK(纯 TCP)** → ALERTING(0x01) → FACILITY → FACILITY → FACILITY → **ACK** → CONNECT(0x07) → **ACK** → RELCOMP(0x5a) → RELCOMP(0x5a)。**CRV 恒 0x2584 双向**，`call_ref_flag` 主叫侧 0 / 被叫侧 1（实测逐帧）。**注意**：本实现**不复刻**该 pcap 的 ACK 插入与 PER 载荷（设计 §0 表 #1/#4、G-H323-1）——参考 pcap 是**消息顺序与头形状**的依据，不是字节依据。

**断言基线**：今日 17 例用 `packet_count`/`min_packets` + `q931.message_type` + `tcp.flags` + 端口/地址 + `frame.len` + 5 条 frames；**`q931.*` 除 message_type 外零使用** → A′ 立项（G-H323-20）。

**动态字段禁止硬编码**：生成期值（CRV、seq/ack）用固定锚点断言——CRV 由配置决定（`h323_calls_multi` 钉 0x1000/0x1001），seq 链路径恒 1000/6000（设计 §3.4），**无随机源**（设计 §5.1 确定性）。

**包数约定（实测公式，设计 §9）**：

```
full         = 3（握手） + 9（Q.931：SETUP/CP/FACILITY/ALERTING/FACILITY×2/CONNECT/RELCOMP×2） + 3（挥手） = 15
tunnel_only  = 3 +  6（SETUP/CP/ALERTING/CONNECT/RELCOMP×2） + 3 = 12
ras_only     = 8   （4 对 RAS；无 TCP）
data_only    = frames（缺省 10；无 TCP）
calls=N      = N × 15
flows=M      = M × 每流包数
```

**保活/重试/RST 口径**：协议层**无保活**（H.323 呼叫信令无心跳；RAS 周期注册是唯一保活形态，本实现只发一轮）；**无重试、无重连**；正例恒 FIN 优雅终止（**注意**：实现为 FIN/FIN/ACK 三次，非 RFC 9293 四次，设计 §3.4、G-H323-13）；RST 为框架 tcp 层能力，本层零断言 → A′ 立项（G-H323-14）。

---

## 2. 原子用例索引（17 ID = 11 正 + 6 负，顺序为权威）

| # | ID | 类型 | 覆盖（设计 §） | packet_count（实测） | 断言数 |
|---:|---|---|---|---:|---:|
| 1 | `h323_smoke_01` | 正 | §3.2 十条 Q.931 + §3.4 握手/挥手基线 | `min_packets: 15`（实际 16） | 11 fields + 3 frames |
| 2 | `h323_vn_presence` | 负 | §7 #1：顶层 `h323` presence 判死 | —（0 帧） | 0 |
| 3 | `h323_vn_static_port` | 负 | §7 #2：层内静态端口 + `flows=2` 静态复制 | —（0 帧） | 0 |
| 4 | `h323_neg_role` | 负 | §7 #3：`role` 非法 | —（0 帧） | 0 |
| 5 | `h323_neg_scenario` | 负 | §7 #4：`scenario` 非法 | —（0 帧） | 0 |
| 6 | `h323_neg_calls` | 负 | §7 #5：`calls` 负数（V9 create-time 先拦） | —（0 帧） | 0 |
| 7 | `h323_neg_display` | 负 | §7 #6：`display_name` 255 字节超界 | —（0 帧） | 0 |
| 8 | `h323_scenario_tunnel` | 正 | §3.2 `tunnel_only` 六条（无 FACILITY） | **12** | 5 fields |
| 9 | `h323_scenario_ras` | 正 | §3.5 RAS 四对（无 TCP） | **8** | 2 fields |
| 10 | `h323_scenario_data` | 正 | §3.6 RTP 缺省 10 帧（无 TCP） | **10** | 2 fields |
| 11 | `h323_calls_multi` | 正 | §3.3 CRV 递增 + §5.3 多呼叫整块 | **32** | 3 fields + 2 frames |
| 12 | `h323_media_full` | 正 | §5.3③ RTP 插 CONNECT 后 | **18** | 5 fields |
| 13 | `h323_dst_default` | 正 | §3.7 `dst_port` 缺省 1720 | **16** | 1 field |
| 14 | `h323_port_dyn` | 正 | §12.12 `src_port` inc 动态 + `flows=2` | **32** | 6 fields |
| 15 | `h323_role_callee` | 正 | §3.3 方向标志翻转 | **16** | 8 fields |
| 16 | `h323_rewrite_addr` | 正 | §3.6（**实为死配置**，G-H323-2） | **16** | 2 fields |
| 17 | `h323_v6` | 正 | §2 IPv6 对照（offset 74） | **16** | 3 fields |

**T-编号对照（设计 §9 表摘要）**：`h323_smoke_01` ≡ T-H323-1；`h323_vn_presence` ≡ T-H323-2；`h323_vn_static_port` ≡ T-H323-3；`h323_neg_role` ≡ T-H323-4；`h323_neg_scenario` ≡ T-H323-5；`h323_neg_calls` ≡ T-H323-6；`h323_neg_display` ≡ T-H323-7；`h323_scenario_tunnel` ≡ T-H323-8；`h323_scenario_ras` ≡ T-H323-9；`h323_scenario_data` ≡ T-H323-10；`h323_calls_multi` ≡ T-H323-11；`h323_media_full` ≡ T-H323-12；`h323_dst_default` ≡ T-H323-13；`h323_port_dyn` ≡ T-H323-14；`h323_role_callee` ≡ T-H323-15；`h323_rewrite_addr` ≡ T-H323-16；`h323_v6` ≡ T-H323-17。**序号以 cases JSON 顺序为权威**（JSON 中 6 条负例紧跟 `smoke_01` 之后，位于正例 #8–#17 之前）。

---

## 3. 正例逐项断言契约（最低断言集，实现期可增不可减）

每例含 `packet_count`（或 `min_packets`）+ fields 断言；帧位与长度由设计 §3.2 公式与实测双向确认。

### 3.1 `h323_smoke_01`（15 包）

`spec_json` = `{"layers":[{"ip":{"src":"10.0.0.1","dst":"20.0.0.1"}},{"h323":{"src_port":12345,"dst_port":1720}}]}`。

- `has_handshake=true`、`negotiated=true`、`terminates=true`、`has_payload=true`、`min_packets=15`。
- **`packet_count=15` 与实际输出一致**（弱断言，差 1 包不会红）→ G-H323-8。
- fields（11 条）：

| 包 | 字段 | 值 | 依据 |
|---:|---|---|---|
| 1 | `tcp.flags` | `0x002` | 握手 SYN（设计 §3.4） |
| 1 | `tcp.dstport` | `1720` | 缺省端口（设计 §3.7） |
| 2 | `tcp.flags` | `0x012` | SYN-ACK |
| 3 | `tcp.flags` | `0x010` | ACK |
| 4 | `q931.message_type` | `0x05` | SETUP |
| 5 | `q931.message_type` | `0x02` | CALL PROCEEDING |
| 6 | `q931.message_type` | `0x62` | FACILITY |
| 7 | `q931.message_type` | `0x01` | ALERTING |
| 11 | `q931.message_type` | `0x07` | CONNECT |
| 12 | `q931.message_type` | `0x5a` | RELEASE COMPLETE |
| 13 | `q931.message_type` | `0x5a` | RELEASE COMPLETE（对侧） |

- frames（3 条，offset 54）：

| 包 | hex | 解码（设计 §3.2） |
|---:|---|---|
| 4 | `03 00 00 1d 08 02 25 84 05 04 03 90 90 a3 28 0d 41 64 6d 69 6e 69 73 74 72 61 74 6f 72` | TPKT `03 00 00 1d`（L=**29**）+ PD `08` + CRVlen `02` + CRV `25 84`（=0x2584，标志 0）+ msgType `05` + BC IE `04 03 90 90 a3` + Display IE `28 0d` + `"Administrator"`（13 B，**无 NUL**） |
| 11 | `03 00 00 1d 08 02 a5 84 07` | TPKT L=29 + CRV `a5 84`（=0x2584\|0x8000，**标志翻转**）+ msgType `07`（CONNECT） |
| 12 | `03 00 00 18 08 02 25 84 5a 28 0d 41 64 6d 69 6e 69 73 74 72 61 74 6f 72` | TPKT L=**24**（无 BC IE，RELCOMP 不带）+ CRV `25 84` + msgType `5a` + Display IE |

- **算术复核**：帧 4 = 54 + 29 = **83**；帧 11 = 54 + 24 = **78**（与 `role_callee` 自述的 83/78 对称一致）。
- **注意（形状不一致）**：本例是唯一用 legacy 8 键 `expect` 的用例（含 `has_handshake`/`negotiated`/`terminates`/`has_payload`/`min_packets`），其余 10 正例用 `{packet_count, fields[, frames], notes}` → G-H323-8。

### 3.2 `h323_scenario_tunnel`（12 包）

`scenario=tunnel_only`、`src_port=12345`。

- `packet_count=12`（= 3 + 6 + 3；设计 §9 公式）。
- fields（5 条）：帧 1 `tcp.flags 0x002` / 帧 4 `q931.message_type 0x05`（SETUP）/ 帧 7 `0x07`（CONNECT）/ 帧 8 `0x5a`（RELCOMP）/ 帧 10 `tcp.flags 0x010`（挥手第三包）。
- **无 FACILITY 断言**（该场景不发射 FACILITY，设计 §3.2 表）——这是与 `smoke_01` 的**唯一结构差异**。
- 帧位推演：3 握手 + 6 Q.931（帧 4–9）+ 3 挥手（帧 10–12）；帧 4=SETUP、5=CP、6=ALERTING、7=CONNECT、8=RELCOMP、9=RELCOMP。

### 3.3 `h323_scenario_ras`（8 包）

`scenario=ras_only`、`ras.enabled=true`、`src_port=12345`。

- `packet_count=8`（= 4 对 RAS；**无 TCP 握手**）。
- fields（2 条）：帧 1 `udp.dstport 1719`（GRQ 上行）/ 帧 2 `udp.srcport 1719`（GCF 下行）。
- **断言面极弱**：无 `msgType` 字段断言（载荷非 PER，`udp` 层无 RAS 解码）→ G-H323-4。
- 消息序列（设计 §3.5）：1=GRQ↑ 2=GCF↓ 3=RRQ↑ 4=RCF↓ 5=ARQ↑ 6=ACF↓ 7=DRQ↑ 8=DCF↓。

### 3.4 `h323_scenario_data`（10 包）

`scenario=data_only`、`media.enabled=true`、`src_port=12345`。

- `packet_count=10`（= `frames` 缺省 10；**无 TCP**）。
- fields（2 条）：帧 1 `udp.srcport 5062` / 帧 1 `udp.dstport 5063`（media 端口缺省，设计 §3.6）。
- **全部 `up` 向**（`h323.go:454`）；RTP 头 12 B + 载荷 160 B → 帧长 = 42 + 12 + 160 = **214**。

### 3.5 `h323_calls_multi`（30 包）

`calls=2`、`crv=4096`（0x1000）、`display_name="t-h323-11"`、`src_port=12345`。

- `packet_count=30`（= 2 × 15）。
- fields（3 条）：帧 4 `q931.message_type 0x05`（呼叫 1 SETUP）/ 帧 19 `0x05`（呼叫 2 SETUP）/ 帧 20 `frame.len 79`。
- frames（2 条，offset 54）：

| 包 | hex | 解码 |
|---:|---|---|
| 4 | `03 00 00 19 08 02 10 00 05 04 03 90 90 a3 28 09 74 2d 68 33 32 33 2d 31 31` | L=**25** + CRV `10 00`（=**0x1000**）+ `05` + BC IE + Display `"t-h323-11"`（9 B） |
| 20 | `03 00 00 19 08 02 10 01 05 04 03 90 90 a3 28 09 74 2d 68 33 32 33 2d 31 31` | L=25 + CRV `10 01`（=**0x1001**，`crv + callNum`）+ 其余全等 |

- **CRV 递增证据**：两帧**唯一差异**在 CRV 第 2 字节（`00` → `01`）——直接证明 `callCRV = crv + uint16(callNum)`（`h323.go:286`）。
- **包号边界证据**：呼叫 2 的 SETUP 在帧 19（= 呼叫 1 的 15 包 + 握手 3 + 1），证明**整块顺序回放**（设计 §5.3①，第 2 会话包号起点 = 前会话总包数 + 1 = 16，SETUP 在 16+3 = 19）。
- 算术复核：54 + 25 = **79** ✓。

### 3.6 `h323_media_full`（17 包）

`media.enabled=true`、`media.frames=2`、`src_port=12345`（`scenario` 缺省 full）。

- `packet_count=17`（= 15 + 2）。
- fields（5 条）：帧 10 `q931.message_type 0x07`（CONNECT）/ 帧 11 `udp.srcport 5062` / 帧 12 `udp.srcport 5062` / 帧 13 `q931.message_type 0x5a` / 帧 14 `0x5a`。
- **插入位置证据**：帧 10=CONNECT、帧 11–12=RTP、帧 13–14=RELCOMP——证明 RTP **插在 CONNECT 之后、RELCOMP 之前**（`h323.go:328-334`，设计 §5.3③）。
- **媒体帧独立 flowID**：`flowID:rtp`（设计 §5.3③），但包号与主控流共用 `packetIndex` 计数器。

### 3.7 `h323_dst_default`（16 包）

`layers[1].h323 = {}`（**空层**）。

- `packet_count=16`（空层走 full 缺省）。
- fields（1 条）：帧 1 `tcp.dstport 1720`（translate 镜像 `setDefaultDstPort`，设计 §3.7）。
- **未断言**：`src_port` 缺省值（单流 = 0，tcp 层同口径"无默认须显式"，设计 §3.7）——A′ 可补。

### 3.8 `h323_port_dyn`（32 包）

`ip.src` inc 动态（`10.0.1.1`–`10.0.1.2`）、`h323.src_port` inc 动态（`30000`–`30001`）、`dst_port=1720`、`group_id` fixed `"h323-port-dyn"`、`strategy_fc = {flows, 2}`。

- `packet_count=32`（= 2 流 × 16）。
- fields（6 条）：帧 1 `tcp.srcport 30000` / 帧 16 `tcp.srcport 30000` / 帧 17 `tcp.srcport 30001` / 帧 32 `tcp.srcport 30001` / 帧 1 `ip.src 10.0.1.1` / 帧 17 `ip.src 10.0.1.2`。
- **逐流成对序证据**：流 1 = 帧 1–16（源口 30000、源 IP 10.0.1.1），流 2 = 帧 17–32（源口 30001、源 IP 10.0.1.2）——`group_id` 固定单 worker FIFO（icmpv6 T-11 先例）。
- **动态端口住 h323 层**（链内无 tcp 层）：`layer_dyn.go:48` allowlist + `resolveLayerTuple`（`layer_dyn.go:806-815`），设计 §12.12。
- **未覆盖的格**：`dst_port` 动态、`ip.ttl` 动态、`rand`/`list`/`pattern`、`inc` 回绕 → G-H323-18。

### 3.9 `h323_role_callee`（16 包）

`role=callee`、`src_port=12345`。

- `packet_count=16`（与 caller 相同——**role 不改包数，只翻方向与标志**）。
- fields（8 条）：帧 1 `tcp.flags 0x002` / 帧 1 `ip.src 10.0.0.1` / 帧 4 `ip.src 20.0.0.1` / 帧 4 `ip.dst 10.0.0.1` / 帧 4 `frame.len 83` / 帧 5 `q931.message_type 0x02` / 帧 11 `0x07` / 帧 13 `0x5a`。
- **方向翻转证据**：帧 1 握手恒 `10.0.0.1 → 20.0.0.1`（`h323.go:288-291`，与 role 无关）；帧 4 起 Q.931 翻为 `20.0.0.1 → 10.0.0.1`（`h323.go:305-310`）。
- **帧长对称证据**：帧 4 `frame.len 83`（与 `smoke_01` 帧 4 全等，因 SETUP 内容与 display 相同）。
- **tshark 方向性伪影（诚实声明）**：down 侧发起的 Q.931（`ip.src=20.0.0.1`）在 tshark 侧**不出 `q931.message_type`**（链路径强制 `Direction="up"`，`layer_gen.go:53`）——故帧 4 的字节结构只能由 `frame.len` 83 承担 → G-H323-13。**本用例不断言帧 4 的 `q931.message_type`**，是**已知限制**而非遗漏。

### 3.10 `h323_rewrite_addr`（16 包）

`rewrite_addr=true`、`src_port=12345`。

- `packet_count=16`。
- fields（2 条）：帧 4 `frame.len 83` / 帧 11 `frame.len 83`。
- **诚实声明（G-H323-2）**：`rewrite_addr` 是**死配置**——`grep -n "RewriteAddr" internal/protocol/h323/h323.go` **零命中**。本用例的 83/83 与 `h323_smoke_01` **实测全等**，故**证明不了任何重写行为**。字节级重写断言属 C 类（模板内嵌 IP 无 tshark 字段面 + `h323_test.go` 零覆盖，设计 §8）。**本用例今日的语义 = "该键被接受且不改变输出"**，不得读成"重写生效"。

### 3.11 `h323_v6`（16 包）

`ip.src=2001:db8::1`、`ip.dst=2001:db8::2`、`src_port=12345`。

- `packet_count=16`。
- fields（3 条）：帧 1 `ipv6.src 2001:db8::1` / 帧 1 `ipv6.dst 2001:db8::2` / 帧 1 `tcp.dstport 1720`。
- **族对称证据**：EtherType 由 `EtherTypeFor` 按 `net.ParseIP` 选（`builder.go:125-134`，0x86DD）；**offset 74**（14+40+20）为 IPv6 帧的 TPKT 起点——本用例**未做 frames 断言**，A′ 可补（G-H323-20）。
- legacy Validate 无族强制（仅 `net.ParseIP`），两族均可跑（设计 §1）。

---

## 4. 负例契约

负例必须在 create-time 或 planner 阶段失败并传播为 task error，不得产生成功 PCAP、`completed/0 packet` 或只剩 TCP 外壳的假成功。锚词与设计 §7 表一一对应、同序（代码逐字）：

| # | ID | 故障输入（机读实测） | JSON `error_contains` | 代码文案（逐字） | 代码行 | 阶段 |
|---:|---|---|---|---|---|---|
| 1 | `h323_vn_presence` | 顶层 `h323:{}` + 层内 `h323:{}` | `top-level h323 sub-config` | `protocol h323 rejects a top-level h323 sub-config (move it into the h323 layer of an [ip,h323] layers chain)` | `strategy_convert.go:8942` | **create-time** |
| 2 | `h323_vn_static_port` | 层内 `{src_port:12345, dst_port:1720}` + `ip:{}` + `flows=2` | `static four-tuple` | 静态复制拒绝（`checkLayerChainStaticCopy`，扫描列表已扩含 h323） | `schema/semantic.go` | **create-time** |
| 3 | `h323_neg_role` | `role: "gatekeeper"` + `src_port:12345` | `invalid role` | `h323: invalid role %q (must be caller or callee)` | `h323.go:125` | **task-time**（`.neg.pcap`） |
| 4 | `h323_neg_scenario` | `scenario: "bogus"` + `src_port:12345` | `invalid scenario` | `h323: invalid scenario %q (must be full, tunnel_only, ras_only, or data_only)` | `h323.go:135` | task-time |
| 5 | `h323_neg_calls` | `calls: -1` + `src_port:12345` | `not a numeric value` | `layers: layer "h323" field "calls" = -1 invalid: not a numeric value in [0,65535]` | `complete.go:315` | **create-time（V9 先拦）** |
| 6 | `h323_neg_display` | `display_name` 255 × `A` + `src_port:12345` | `display_name must be <=` | `h323: display_name must be <= 254 bytes (Display IE length is 1 byte), got 255` | `h323.go:145` | task-time |

**锚词口径**：`error_contains` 是**子串**判定；6 条均命中代码文案。

**#5 的锚词切换（重要）**：registry 的 `calls` 是 `uint16 Min=0`（`registry.go:1347`），`-1` 在 `configUint64` 阶段即失败（`complete.go:315`），故 legacy 的 `h323: calls must be >= 0`（`h323.go:140`）在**链路径不可达**——用例按 V9 先拦口径钉 `not a numeric value`（设计 §7、G-H323-11）。

**#1 的形状特殊性（批次二任务书要求点名）**：`h323_vn_presence` 的 `spec_json` = `{"layers":[{"ip":{…}},{"h323":{}}],"h323":{}}`——**层链 + 顶层空子映射并存**。这是**判死负例的标准形状**（presence 门扫顶层 `h323` 键，**空 map 也死**），**与"旧格式残留"是两回事**。本协议是**唯一**顶层非 `layers` 键例，且**该形状是必需的**——去掉顶层 `h323` 键，本负例即失效。

**负例原子性**：每例单一故障注入；单次执行不得混注。`h323_vn_static_port` 是**依赖链③执法洞的实证**（ip 层无显式地址时，h323 静态端口是唯一四元组真相 → `flows=2` 必拒）。

**expect 键形状注**：存量 6 负例 `expect` = `{expect_error, error_contains, notes}`（含 `notes`），与严格两键口径不符——P4 收窄时删 `notes`（G-H323-19）。

**未入用例的拒绝分支（A′ 立项，不得冒充已覆盖，G-H323-14）**：
- legacy（链路径**不可达**）：`h323: invalid SrcIP %q`（`h323.go:105`）/ `h323: invalid DstIP %q`（`:110`）/ `h323: H323Config is required`（`:116`）/ `h323: TCP.MSS %d too small (min %d)`（`:151`）；
- flat（非链路径）：`h323.role must be "caller" or "callee"`（`strategy_convert.go:4089`）/ `h323.scenario must be full|tunnel_only|ras_only|data_only`（`:4093`）/ `h323.calls must be >= 1`（`:4096`）/ `h323.display_name must be <= 254 bytes (Display IE length is 1 byte)`（`:4099`）/ `h323.media.frames must be >= 0`（`:4111`）/ `h323.media.frame_size must be >= 0`（`:4114`）/ `h323.ras.endpoint_type must be terminal|gateway`（`:4126`）。

**未入用例的静默路径（缺陷候选）**：
- `full` 场景 + `ras.enabled=true` → **静默无 RAS**（`h323.go:317-334` 不检查 `h.Ras`）→ G-H323-5；
- `data_only`/`ras_only` + `calls>1` → **静默只发一轮**（`:196-209` 提前 return）→ G-H323-10；
- `crv ≥ 0x8000` + `calls>1` → **静默污染方向标志**（`:286` 无掩码）→ G-H323-9；
- `display_name` 254 字节 → **通过校验后被静默截为 253**（`:405-407`）→ G-H323-6。

---

## 5. 覆盖与对账

### 5.1 三源回指行

ITU-T H.225.0 / Q.931 / H.245 + RFC 1006 / RFC 3550（设计 §10）+ D-H323-1（设计 §11）+ tshark 3.6.14 `q931.*` 字段表（156 字段）与**参考 pcap 20 帧实测**（`/home/pcap_auto/llcj_pcap/IP-TCP-20.4.2.46-30.4.2.46-30000-1720-10-10-2271-1779.pcap`）→ 17 ID（本契约 §2）。

**17 ID 逐项回指（设计 §9 表）**：#1←§3.2/§3.4；#2←§7 #1；#3←§7 #2；#4←§7 #3；#5←§7 #4；#6←§7 #5；#7←§7 #6；#8←§3.2；#9←§3.5；#10←§3.6；#11←§3.3/§5.3；#12←§5.3③；#13←§3.7；#14←§12.12；#15←§3.3；#16←§3.6（死配置）；#17←§2。

**第三源"已确认现网行为"**：**已到抓包级**——参考 pcap 20 帧逐帧核对（CRV 恒 0x2584 双向、call_ref_flag 主叫 0/被叫 1、消息顺序）；**但**本仓引擎产出的 17 例 pcap **本车道未跑**（as-built 文档车道不跑套件）→ 见 §8.2 第 4 条与 G-H323-12。

### 5.2 对账两行 + 清单出处声明

- **清单出处声明**：本清单来源 = **ITU-T H.225.0/Q.931/H.245 公开语义 + RFC 1006/3550 + 参考 pcap 20 帧实测 + 仓库落码反推 + tshark 3.6.14 字段表**，**非纯规范反推**（H.225.0 §7 RAS PER 逐字段语义、H.245 TCS/MSD 编码**未核对原文** → G-H323-1/G-H323-4）。
- **对账两行（行/格粒度，每点 1 计；逐表可复算）**：
  | 表 | 行/格数 | 已覆 | 立项(A′) | 不适用 |
  |---|---:|---:|---:|---:|
  | §10.1 八项规范矩阵 | 8 | 1 | 7 | 0 |
  | §10.2 子表① 消息×终态 | 10 | 8 | 2 | 0 |
  | §10.3 子表② 数据形态变体 | 12 | 12 | 0 | 0 |
  | §10.4 子表③ 商业行为映射 | 8 | 6 | 1 | 1 |
  | §12.12 动态整格（四元组 4 + 业务 8） | 12 | 1 | 11 | 0 |
  | **合计** | **50** | **28** | **21** | **1** |
  **28 + 21 + 1 = 50 ✓**。**注**：§10.3 的 12 行「已覆」指该行**至少一个取值有例**；行内未覆的子点（如 `crv` 3 取值的 1 个、`display_name` 5 取值的 2 个）计入 G-H323 缺口表，不在此重复计数。
  **粒度声明**：行/格粒度每点 1 计；G-H323-1…G-H323-20（20 条）**不折进 50**（缺口是跨表的归并视角）。**反查全绿 ≠ 覆盖全**（CORE_MEMORY §9.52 原文）。逐表重数见设计 §10.1（8 行）/§10.2（10 行）/§10.3（12 行）/§10.4（8 行）/§12.12（12 格）。
- **门3 抽查候选**：最复杂用例 = **#11 `h323_calls_multi`**（32 帧：2 呼叫 × (3 握手 + 10 Q.931 + 3 挥手)；交织维度 = 呼叫(2) × 消息类型(6) × 方向(2) × CRV(2 值)）；次选 **#14 `h323_port_dyn`**（多流 × 动态端口 × 动态地址，6 条聚合断言）。**建议门3 抽 #11 + #14**（多呼叫 + 多流双面）。

### 5.3 T-编号与旧 id 对照

见 §2 表末（T-H323-1…17 与 17 个 JSON ID **一一对应**；本协议**无虚例**——T 编号集合 = JSON ID 集合，与 opcua 的 T4/T8 虚例情形不同）。

---

## 6. P3 固定动作（CORE_MEMORY 管线：§3.15 三项 + A′/B′ 两分类 + 3.14 豁免）

### 6.1 §3.15 三项逐项一例或立项

| # | 三项 | 本协议对照 | 用例/立项 |
|---:|---|---|---|
| ① | 同连接/同流内的多轮操作 | 同 TCP 连接两轮完整呼叫（`calls=2`，CRV 递增） | **已覆** #11 `h323_calls_multi` |
| ② | 非正常结束 | 正常 FIN 全正例（**注意**：FIN/FIN/ACK 三次，非规范四次）；**RST 零用例** | 部分已覆；**RST A′ 立项**（G-H323-14，本层零断言） |
| ③ | 长保活 | H.323 呼叫信令层**无心跳**；RAS 周期注册（H.225.0 默认 30 s RRQ）是唯一保活形态，**本实现只发一轮** | **A′ 立项**（G-H323-14，需先补实现） |

无空项：① 有已覆例；② 有已覆例 + 1 条 A′ 立项；③ 1 条 A′ 立项（**本协议是少数"③ 无已覆例"的协议**，诚实登记）。

### 6.2 A′/B′ 两分类表

**A′（P4 接线）**：

| 类 | 内容 | 落点 |
|---|---|---|
| H.245 载荷面 | FACILITY 的 `h245Control` / `H323-UserInformation` PER 字节断言——**需先实现 ASN.1 PER** | G-H323-1 |
| RAS 载荷面 | RAS 8 字节载荷的字节断言 + `msgType` 可观察性——**需先实现 PER** | G-H323-4 |
| RAS 场景面 | `full` + `ras.enabled` 的发射路径 | G-H323-5 |
| 死配置面 | `rewrite_addr` 重写生效的字节断言 | G-H323-2 |
| 死配置面 | `ras.endpoint_type=gateway` 的线面差异 | G-H323-3 |
| 边界面 | `display_name=254`（254 vs 253 截断） | G-H323-6 |
| 边界面 | `crv` 显式 0 / `calls=65535` 上界 / `crv` 溢出 bit15 | G-H323-9 |
| 拒绝分支面 | `invalid SrcIP` / `TCP.MSS too small` / flat 7 条锚词 | G-H323-14 |
| 消息类型面 | Q.931 其余 9 种 + RAS 其余 8 种 | G-H323-15 |
| IE 面 | Called/Calling Party Number、User-User、Cause、Channel ID | G-H323-17 |
| 动态整格 | `dst_port` 动态 / `ip.ttl` 动态 / `rand` / `list` / `pattern` / `inc` 回绕 | G-H323-18 |
| 非正常结束 | `tcp.rst` 补例 | G-H323-14 |
| 保活面 | RAS 周期 RRQ | G-H323-14 |
| q931 字段面 | 收编 `q931.disc`/`call_ref`/`call_ref_flag`/`call_ref_len` | G-H323-20 |
| IPv6 frames 面 | `h323_v6` 补 offset 74 frames 断言 | G-H323-20 |

**B′（框架面）**：`h323_smoke_01` 的 legacy 8 键 expect 统一（G-H323-8）/ 负例 `notes` 键收窄（G-H323-19）/ 白名单外游离顶层键通用门（框架级 unknown-key 白名单未落，§12-P2 ②）。进设计 §14。

### 6.3 3.14 豁免边界审计

**有长连接载体（TCP 1720）→ `sessions[]` 不豁免**（设计 §12.3 会话表 s1/s2/sR/sM）。**形态差异已声明**：h323 的"多会话"是 `calls=N`（层内标量，**同四元组复用**），不是 `sessions[]` 数组——与 opcua 的 `sessions` 结构选择器同属"形态差异"（设计 §5.4）；**多流并发**由策略级 `flow_control {"flows": N}` 承载（`h323_port_dyn` 实证 N=2）；**单包多载荷** = **不适用**（每条 Q.931/RAS/RTP 消息独立成帧，无多 question/多 RR 类形态，如实声明）。

---

## 7. 实现后执行建议

1. **P4 顺序（按缺口优先级）**：①先裁定 G-H323-1/G-H323-4（PER 载荷：实现 or 改写注释为诚实边界）——**这是本协议最大的文档-实现落差**；②裁 G-H323-2/G-H323-3（两个死配置：补实现 or 按 CORE_MEMORY §1.12 删键）；③修 G-H323-6（display 254/253 边界对齐）+ G-H323-11（`calls` 三处口径统一）；④补 G-H323-5（full 场景 RAS）+ G-H323-9（CRV 掩码）；⑤收窄形状（G-H323-8/G-H323-19）；⑥补 A′ 例（G-H323-14/G-H323-18/G-H323-20）；⑦全量复跑。
2. **实测顺序**：先 #1（`smoke_01` 基线：握手 3 + Q.931 10 + 挥手 3，帧 4/11/12 字节），再 #8（`tunnel_only` 12 包，帧 4/7/8/10），再 #9/#10（RAS/RTP 单面），再 #11（`calls_multi` CRV 0x1000/0x1001 差异），再 #12（`media_full` 插入位置 11/12-13/14-15），最后 #14（多流逐流成对序）、#17（IPv6 offset 74）。
3. **门2 四项**：①顶层旧键零残留（**违规 = 0**：非负例顶层键 ⊆ `{layers, group_id}`，`group_id` 是 CORE_MEMORY §1.11 白名单结构键；`h323_vn_presence` 的顶层 `h323` 是判死形状，需在门2 脚本内**按负例豁免**——见 §9 建议行 #2）；②`CASE_PROTO=h323` **全量**（不是增量）；③二进制与 HEAD 同代（`find trafficgen -name '*.go' -newer <server-binary>` 无输出）；④反查绿后进 P6。
4. **门3 抽查**：建议抽 #11 + #14（§5.2 门3 候选）。
5. 任何 H.225.0 §7 / H.245 条款号的具体引用须有规范原文证据（G-H323-1/G-H323-4 纪律）。

---

## 8. 存量审计（17 例逐条去向）

### 8.1 存量实测面（2026-09-29）

`cases/h323.json` **17 例**：11 正例带 `packet_count`（12/8/10/32/18/16/32/16/16/16）或 `min_packets`（`smoke_01` = 15）；6 负例 `expect` 键集合 `{expect_error, error_contains, notes}`；**顶层键：非负例 16/16 ⊆ `{layers, group_id}`（15 例仅 `layers`；`h323_port_dyn` 含白名单结构键 `group_id`），负例 1 例含顶层 `h323`（判死形状）；违规游离键 = 0**；**层链 17/17 = `[ip, h323]`**；断言 **fields 48 条 + frames 5 条**；层内 `h323` 键与 registry Fields 10 键**逐键一致**（机读实测）。

### 8.2 现状矛盾点（P4 前诚实登记）

1. **PER 载荷全缺（G-H323-1）**：`types.go:5570-5581` 注释声称"PER 字节模板 / 1440 字节 SETUP / 18 个 fastStart OLC / NUL 终止符"，代码是 29 字节最小头 + 固定 5 字节 BC IE + 无 NUL 的 Display IE。参考 pcap 帧 4 = 1440 字节 vs 实现帧 4 = 29 字节。
2. **RAS 非 PER（G-H323-4）**：`types.go:5593-5595` 注释声称"PER-encoded per H.225.0 §7"，代码是 8 字节手写占位。
3. **"byte-for-byte" 语义澄清（G-H323-1）**：`layer_gen.go:1-6` 的 "reproducing the reference pcap byte-for-byte" 指**链驱动对 legacy 输出零改动**，**不指复刻参考 pcap**。
4. **结果产物链接失效（G-H323-12）**：`trafficgen/docs/protocol-pcap-test/h323.md`（tracked）内 12 条 pcap 相对链接指向 `trafficgen/docs/protocol-pcap-test/h323/`，该目录**不存在（0 个 pcap）**。**口径澄清（重要，不得夸大）**：该 .md 末次提交 `62376e3`（**2026-09-19**）**晚于**判死提交 `0417be5`（2026-09-13），故**不构成"产物过期"缺口**（与 pcep G-PCEP-11 判定条件相反，结论为"**不成立**"）。本项**仅登记链接失效 + 无 pcap 留档**；本车道**未跑**该套件，故**不以任何形式**（含"今日已跑通"）引用该产物的 17/17 作为可跑证据。
5. **两个死配置（G-H323-2/G-H323-3）**：`rewrite_addr` 与 `ras.endpoint_type` 均被 parse + validate + translate 三处接线，在 `internal/protocol/h323/` 内**零消费**（`grep` 零命中）。
6. **`full` 场景忽略 RAS（G-H323-5）**：`ras.enabled=true` + `scenario=full` 静默无 RAS。
7. **Display IE 边界不一致（G-H323-6）**：Validate 允许 254，buildDisplayIE 截断 253。
8. **`calls` 口径三处冲突（G-H323-11）**：legacy `>= 0`（链路径不可达）/ flat `>= 1`（拒 0）/ Plan `0 → 1`（收 0）——②与③语义冲突。
9. **`smoke_01` 形状与弱断言（G-H323-8）**：唯一用 legacy 8 键 expect 的用例；`packet_count=15` 与实际输出一致。
10. **`role_callee` 的 tshark 方向性伪影（G-H323-13）**：链路径强制 `Direction="up"`（`layer_gen.go:53`）导致 down 侧 Q.931 不出 `q931.message_type`；用例**已诚实自述**并由 `frame.len` 83/78 承担字节断言。附带：TCP 拆线 FIN/FIN/ACK 三次（非规范四次），末包后无对端 ACK。
11. **存量未覆盖**：RST 非正常结束、RAS 周期保活、Q.931 其余 9 种消息、RAS 其余 8 种消息、IE 面（Called/Calling Party Number、User-User、Cause、Channel ID）、`dst_port` 动态、`ip.ttl` 动态、`rand`/`list`/`pattern`/回绕、`display_name=254` 边界、`crv` 显式 0、`calls=65535` 上界、CRV 溢出、flat 路径 7 条锚词、legacy 4 条不可达锚词、`q931.*` 字段面（除 message_type）**今日零用例**（A′ 补，G-H323-14/15/17/18/20）。

### 8.3 逐条去向表（17 行）

| 存量 id | T-编号 | 去向 | 改写动作（P4） |
|---|---|---|---|
| `h323_smoke_01` | T1 | **改写** | 形状统一：legacy 8 键 → `{packet_count: 16, fields, frames, notes}`；`min_packets` 弱断言删除（G-H323-8） |
| `h323_vn_presence` | T2 | **保留** | 形状合规（**判死负例必需形状**，不得改）；删 `notes`（G-H323-19） |
| `h323_vn_static_port` | T3 | **保留** | 同上删 `notes` |
| `h323_neg_role` | T4 | **保留** | 同上；可补 `q931.*` 无关（本例 0 帧） |
| `h323_neg_scenario` | T5 | **保留** | 同上 |
| `h323_neg_calls` | T6 | **保留** | 同上；锚词已按 V9 先拦口径（G-H323-11 统一后复核） |
| `h323_neg_display` | T7 | **保留** | 同上；补 254 边界正例（A′，G-H323-6） |
| `h323_scenario_tunnel` | T8 | **保留** | 形状合规；可补帧 9 RELCOMP 断言 |
| `h323_scenario_ras` | T9 | **改写** | 补载荷/`msgType` 可观察断言（需先实现 PER，G-H323-4） |
| `h323_scenario_data` | T10 | **保留** | 形状合规；可补 RTP 头字节断言（seq/PT） |
| `h323_calls_multi` | T11 | **保留** | 断言已充分（CRV 差异 + frame.len + 包号边界） |
| `h323_media_full` | T12 | **保留** | 形状合规；可补 RTP 帧长 214 断言 |
| `h323_dst_default` | T13 | **保留** | 可补 `src_port` 缺省 0 断言 |
| `h323_port_dyn` | T14 | **保留** | 可补 `dst_port` 动态 / `rand`/`list`/`pattern` 格（G-H323-18） |
| `h323_role_callee` | T15 | **保留** | 伪影已诚实声明（G-H323-13）；可补 `q931.call_ref_flag` 断言替代 |
| `h323_rewrite_addr` | T16 | **改写** | 收窄口径为"键被接受且不改输出"（G-H323-2）；重写实现后重钉字节 |
| `h323_v6` | T17 | **保留** | 可补 offset 74 frames 断言（G-H323-20） |

无"作废不注原因"：**0 作废**，0 等价覆盖（17 例全部保留/改写 + A′ 新增）。**本协议非负例违规游离顶层键 = 0**（16/16 顶层键 ⊆ `{layers, group_id}`；负例 1 例顶层 `h323` 为判死形状）。

---

## 9. 附：覆盖反查门建议断言行（供主线程合后登记；本车道不碰 `coverage_gate.py`）

建议在主线程合入后，于 `coverage_gate.py` 的 `check_h323` 段登记下列断言（**每条均可从本契约与 cases JSON 直接机读，不需新造事实**）：

| # | 建议断言 | 依据 |
|---:|---|---|
| 1 | `len(cases['h323']) == 17` 且 ID 集合 = §2 十七项，顺序一致 | 本契约 §2 |
| 2 | **非负例**顶层键 ⊆ `{layers, group_id}`（**16/16，今日已成立**；`group_id` 为 CORE_MEMORY §1.11 白名单结构键，仅 `h323_port_dyn` 使用）；负例允许含顶层 `h323`（**判死形状，必须豁免**——去掉则该负例失效） | 本契约 §1/§4；设计 §12.1 |
| 3 | 17/17 层链 == `[ip, h323]`（raw-IP 自驱终层；**链内不得出现 tcp/udp 层**） | 本契约 §1；设计 §2 |
| 4 | 11 正例 `packet_count` ∈ 公式集：`16`（full）/`12`（tunnel_only）/`8`（ras_only）/`10`（data_only 缺省）/`32`（calls=2 或 flows=2）/`18`（full+2 RTP） | 设计 §9 公式 |
| 5 | 6 负例 `expect` 键 == `{expect_error, error_contains}`（P4 删 `notes` 后） | 本契约 §4 |
| 6 | 负例 `error_contains` ∈ 代码锚词集 `{"top-level h323 sub-config", "static four-tuple", "invalid role", "invalid scenario", "not a numeric value", "display_name must be <="}` | 设计 §7 |
| 7 | 每正例至少一条 `q931.message_type` 或 `tcp.flags` 断言（`ras_only`/`data_only` 例外，用 `udp.*port`） | 本契约 §3 |
| 8 | 帧断言 offset 恒 54（IPv4；`h323_v6` 今日无 frames 断言） | 本契约 §3；设计 §2 |
| 9 | `h323_calls_multi` 两帧 CRV 差异 == 1（0x1000 → 0x1001），其余字节全等 | 本契约 §3.5；设计 §3.3 |
| 10 | `h323_smoke_01` 帧 4 TPKT 长度字节（offset 56-57）== `00 1d`（29），帧 12 == `00 18`（24） | 本契约 §3.1；设计 §3.2 公式 |
| 11 | `h323_neg_calls` 锚词 == `not a numeric value`（**非** legacy `calls must be >= 0`——后者链路径不可达） | 本契约 §4；设计 §7 |
| 12 | 动态端口用例 `h323_port_dyn` 的 `src_port` 断言覆盖两流（30000/30001）且 `ip.src` 同步（10.0.1.1/10.0.1.2） | 本契约 §3.8；设计 §12.12 |

**另注意**：`trafficgen/docs/protocol-pcap-test/h323.md` 的 17/17 pass 是 **tracked 产物**，末次提交 `62376e3`（2026-09-19）**晚于**判死提交 `0417be5`（2026-09-13）——**不构成"产物过期"缺口**（与 pcep G-PCEP-11 判定条件相反）；但其内 12 条 pcap 链接指向的 `trafficgen/docs/protocol-pcap-test/h323/` **目录不存在（0 个 pcap）** → G-H323-12。**本车道未跑该套件**，故不以任何形式引用该产物作为可跑证据。

---

## 10. 修订记录

- v1.0.0（2026-09-29）：批次二文档车道 #117 h323 **首次成文**（本仓库无 h323 旧用例稿，`find` 零命中）。as-built 型：把既有 17 例（`cases/h323.json`）如实写成契约。§1 形状基线（17 例 = 11 正 + 6 负；非负例违规游离顶层键 = 0，顶层键 ⊆ `{layers, group_id}`；层链 17/17 `[ip,h323]`；fields 48 + frames 5；tshark 3.6.14 `q931.*` 156 字段；参考 pcap 20 帧 CRV/标志实测）；§2 17 ID 索引 + T-编号对照（**无虚例**）；§3 十一正例逐项断言契约（含帧 hex 解码与长度算术复核：29/24/25/83/78/79）；§4 六负例锚词表（含 `h323_vn_presence` 判死形状点名、`h323_neg_calls` 锚词切换说明）+ 未入例分支与静默路径清单；§5 三源回指 + **对账两行**（96 = 42 覆 + 9 不适用 + 45 立项）+ 门3 候选；§6 P3 固定动作（§3.15 三项：①已覆 ②部分+RST A′ ③**仅 A′**，本协议为少数"③ 无已覆例"者）+ A′/B′ 两分类 + 3.14 豁免审计；§7 执行建议；§8 存量审计（17 行逐条去向 + 11 条现状矛盾点）；§9 **覆盖反查门建议断言行 12 条**（含 `h323_vn_presence` 顶层键豁免、`not a numeric value` 锚词切换、CRV 差异 == 1 三条特殊性断言）。机读自审（脚本复核计数与断言，不手算）。仅文档，未动任何 `.go` / `cases/*.json` / `trafficgen/tools/**`。
