# #114 pptp（PPTP）测试用例契约

> 版本：v1.0.0（P-PIPE 文档轨批次二 as-built 定稿）
> 日期：2026-09-29
> 配套设计：`docs/protocol-designs/114-pptp-design.md` v1.0.0（D-PPTP-2）
> 历史基线：`docs/CODE_DESIGN.md` 的 **D-PPTP-1**（`CODE_DESIGN.md:3040` 起，P1+P2 定稿 + P4/P5/P6 执行记录，2026-09-20）——本版**承其 T-PPTP-1…20 清单与全部实测结论**
> 机器契约：`trafficgen/test/protocol_pcap/cases/pptp.json`（**20/20 ID 与本版 §2 一致，顺序一致，已机读实测**；**顶层键已是纯层链形，零残留**）
> 白话一句：**二十条检查：十三条看正常收发（全生命周期、控制头字节、四种场景、服务器侧、多路呼叫、SLI 条数、保活、双向数据、内网包、错误码、复合大场景），七条看胡来能不能被拦下；每条只查一件事。**

## 1. 测试原则和形状基线

用例从设计 §3–§9 逐项派生，共 **20 个唯一语义 ID：13 正 + 7 负**。派生规则：设计 §3 每条消息/字段条款、§5 每个事务/自动派生行为、§7 每行错误处理在本文有对应断言；断言不得超出设计声明范围。**一个用例只验证一个协议行为**。

**形状基线（2026-09-29 机读实测）**：

| 项 | 实测 |
|---|---|
| 例数 | **20**（13 正 + 7 负） |
| case 顶层键 | `{expect, id, proto, spec_json, summary}` ×20（完全一致） |
| `spec_json` 顶层键 | **`{layers}` ×20（唯一键，零游离键、零顶层 `pptp` 子映射）** |
| 层链形状 | **`[ip, pptp]` ×20**（唯一形状；**无 `tcp` 层**——TCP 由 pptp 生成器自建） |
| 正例 `expect` 键 | `packet_count` ×11 / `min_packets` ×1 / `has_handshake` ×11 / `terminates` ×11 / `notes` ×20 / `frames` ×2 / `fields` ×1 |
| 负例 `expect` 键 | **`{expect_error, error_contains, notes}` ×7**（含 `notes`，非严格两键 → G-PPTP-1） |

**输出契约（pcap/NIC 双输出）**：两路径共用同一 cases JSON 与断言集（`tcp.dstport`/`tcp.len`、frames 原始 hex @offset 54（控制帧）/34（GRE 帧）、`packet_count`）；NIC 经 tcpdump 捕获（`nic_capture` 用例级开关）；不设仅单路径可用的断言。**存量 NIC 路未跑**（D-PPTP-1 性能段自注"网卡路未跑"）→ G-PPTP-5 附注。

**TSHARK 基线（本机 3.6.14 实测）**：`tshark -G fields | grep -c pptp` = **58 个 `pptp.*` 字段**，含 `pptp.length` / `pptp.type` / `pptp.magic_cookie` / `pptp.control_message_type` / `pptp.call_id` / `pptp.peer_call_id` / `pptp.control_result` / `pptp.error` / `pptp.host_name` / `pptp.vendor_name` / `pptp.framing_capabilities` / `pptp.bearer_capabilities` / `pptp.protocol_version` / `pptp.connect_speed` / `pptp.send_accm` / `pptp.recv_accm` 等（全表见设计 §3 各表"实测钉"列）。参考 pcap 与 20 例 pcap **全部被解码**（tshark 逐帧解出 PPTP 层，**零 malformed**）。

**断言基线**：今日 20 例只用 `packet_count`/`min_packets` + `has_handshake` + `terminates` + **1 条 `fields`（11 个 `tcp.dstport`/`tcp.len` 断言）** + **2 条 `frames`（3 个 hex 断言）**。**`pptp.*` field 断言今日零使用** → A′ 立项（G-PPTP-3，把已可用的 58 个 dissector 字段补起来）。

**进制/口径纪律（实测）**：`pptp.length`/`pptp.control_message_type`/`pptp.call_id` 用**十进制串**；`pptp.magic_cookie` 用 `0x1a2b3c4d` 形式（`BASE_HEX`）；`pptp.host_name`/`pptp.vendor_name` 用字符串。**`tcp.dstport`/`tcp.len` 用十进制串**（存量已用）。

**动态字段禁止硬编码**：生成期随机值（ISN、IPID 种子）**一律不断言**；控制头 Magic Cookie 是常量（`0x1a2b3c4d`）可断（#2 已断 hex 原文）。

**包数约定（实测公式，设计 §9.1）**：

```
非 data_only：N = 3 + 2 + (echo?2:0)
                 + Σ_{calls} [ 2 + (incoming_call?3:0)
                            + (scenario∈{full,control_only} ? sli_count : 0)
                            + (scenario==full ? data_frames+down_data_frames : 0)
                            + 3 ]
                 + 2 + 4
data_only：    N = data_frames + down_data_frames
```

**机读复算结论**：13 个正例中 **11 例 `packet_count` 与公式逐例一致**；#8 `pptp_sli_count_three` 用 `min_packets:20`（公式值 **24**，**松 4**）；#11 `pptp_inner_ip_explicit` **无计数断言**（公式值 **16**）。负例无 `packet_count`（实测 0 帧）。

**保活/重试/RST 口径**：协议层**无 PING 类保活定时器**（RFC 2637 §3.1.4 的 60 秒定时器不建模）；`echo=true` 是**配置驱动的单次 ECRQ/ECRP 插入**（#9），不是心跳；RST 为框架能力，本协议层不新增断言；正例恒 FIN 优雅终止（4 帧挥手）。

## 2. 原子用例索引（20 ID = 13 正 + 7 负，顺序为权威）

| # | ID | 类型 | 覆盖（设计 §） | packet_count |
|---:|---|---|---|---:|
| 1 | `pptp_full_session_ref` | 正 | §5.1：full 全生命周期（参考 pcap 逐字节） | 26 |
| 2 | `pptp_control_header_magic` | 正 | §3.1：控制头 12B 逐字节 | 26 |
| 3 | `pptp_scenario_control_only` | 正 | §5.1：`scenario=control_only` | 21 |
| 4 | `pptp_scenario_tunnel_only` | 正 | §5.1：`scenario=tunnel_only`（**无 SLI、无数据、有拆除**） | 16 |
| 5 | `pptp_scenario_data_only` | 正 | §5.1：`scenario=data_only`（纯 GRE） | 4 |
| 6 | `pptp_role_pac` | 正 | §3.9：`role=pac` 换向 | 21 |
| 7 | `pptp_calls_two` | 正 | §5.1：`calls=2` 多路呼叫 | 31 |
| 8 | `pptp_sli_count_three` | 正 | §3.5：`sli_count=3` | 24（**存量 `min_packets:20`**） |
| 9 | `pptp_echo_keepalive` | 正 | §3.6：`echo=true` ECRQ/ECRP | 23 |
| 10 | `pptp_data_both_directions` | 正 | §3.8：双数据方向 + GRE 头字节 | 24 |
| 11 | `pptp_inner_ip_explicit` | 正 | §3.8：`inner_ip` 显式 | 16（**存量无计数断言**） |
| 12 | `pptp_result_error_fields` | 正 | §3.3/§3.4：`scrp_result`/`ocrp_result` 非 0 | 21 |
| 13 | `pptp_composite_full_multi` | 正 | §5.1：复合（calls 2 + echo + 双数据 + SLI 3） | 33 |
| 14 | `pptp_neg_role_invalid` | 负 | §7 N-1 | —（0 帧） |
| 15 | `pptp_neg_scenario_invalid` | 负 | §7 N-2 | — |
| 16 | `pptp_neg_calls_negative` | 负 | §7 N-3（registry 范围门） | — |
| 17 | `pptp_neg_sli_count_negative` | 负 | §7 N-4（registry 范围门） | — |
| 18 | `pptp_neg_sub_address_hex` | 负 | §7 N-5 | — |
| 19 | `pptp_neg_host_name_long` | 负 | §7 N-6 | — |
| 20 | `pptp_neg_inner_ip_invalid` | 负 | §7 N-7 | — |

T-编号对照：T-PPTP-T1 ≡ #1；T2 ≡ #2；T3 ≡ #3；T4 ≡ #4；T5 ≡ #5；T6 ≡ #6；T7 ≡ #7；T8 ≡ #8；T9 ≡ #9；T10 ≡ #10；T11 ≡ #11；T12 ≡ #12；T13 ≡ #13；T14 ≡ #14；T15 ≡ #15；T16 ≡ #16；T17 ≡ #17；T18 ≡ #18；T19 ≡ #19；T20 ≡ #20（**一一对应，无虚例**；序号以 cases JSON 顺序为权威）。

## 3. 正例逐项断言契约（最低断言集，实现期可增不可减）

每例均含 `packet_count`（或 `min_packets`）+ `terminates` + `has_handshake`（`data_only` 除外）+ notes；帧位由 §1 公式与实测双向确认。

### 3.1 `pptp_full_session_ref`（26）

`spec_json.layers = [{"ip":{"src":"10.0.0.1","dst":"20.0.0.1"}}, {"pptp":{}}]`（空 pptp 层 config = 全默认）。

- `has_handshake=true`、`terminates=true`、`packet_count=26`。
- **`fields` 11 条（本协议唯一 `fields` 用例）**：
  - `packet 1 field tcp.dstport value "1723"`——**1723 恒定性断言面 = 包 1 请求帧**（生成器 `Plan :404` 缺省）。
  - `packet 4/5 field tcp.len = 156 / 156`（SCCRQ/SCCRP）。
  - `packet 6 = 168`（OCRQ）；`packet 7 = 32`（OCRP）；`packet 8 = 24`（SLI 首帧）。
  - `packet 18 = 16`（CCRQ）；`packet 19 = 164`（**CCRQ+CCDN 合并段**）；`packet 20 = 148`（CCDN）；`packet 21 = 16`（StopRQ）；`packet 22 = 16`（StopRP）。
- **帧位全序**（公式 + 实测钉）：1-3 握手；4 SCCRQ / 5 SCCRP / 6 OCRQ / 7 OCRP；8-12 SLI×5（`tcp.len=24`，其中帧 11 位置按参考 pcap 有 TCP ACK 交错，本仓实现连续）；13-17 GRE×5（`data_frames=3` up + `down_data_frames=2` down）；18-20 拆除段；21-22 Stop 对；23-26 挥手 4 帧。
- **notes 口径注**：存量 notes 写"data_frames 缺省 5"——实为 `data_frames=3` + `down_data_frames=2` 之和（结论对、表述误导，G-PPTP-1 ④）。

### 3.2 `pptp_control_header_magic`（26）

同 #1 spec（空 pptp config）。

- `packet_count=26`；**`frames` 2 条（控制头逐字节）**：
  - `packet 4 offset 54 hex "00 9c 00 01 1a 2b 3c 4d 00 01 00 00"`——Length=0x009c=**156**、PPTP Message Type=**1**（control）、Magic Cookie=**0x1a2b3c4d**、Control Message Type=**0x0001**（SCCRQ）、Reserved0=0。
  - `packet 5 offset 54 hex "00 9c 00 01 1a 2b 3c 4d 00 02 00 00"`——同前，Control Message Type=**0x0002**（SCCRP）。
- **偏移证据**：offset 54 = 14（以太）+ 20（IPv4）+ 20（TCP）；实测 pcap **无 VLAN/IP options/TCP options**（设计 §2）。
- **与参考 pcap 逐字节一致**（设计 §0 #13 实测复核）。

### 3.3 `pptp_scenario_control_only`（21）

`{"pptp":{"scenario":"control_only"}}`。

- `has_handshake=true`、`terminates=true`、`packet_count=21`。
- **公式证据**：3+2+1×(2+5+3)+2+4 = 21 ✓（**无 GRE 数据面**，`planner.go:665` 仅 `full` 触发 `emitDataPlane`）。
- **与 #1 的差**：26 − 21 = **5** = GRE 数据帧数（3+2），SLI 与拆除段**均在**。

### 3.4 `pptp_scenario_tunnel_only`（16）

`{"pptp":{"scenario":"tunnel_only"}}`。

- `has_handshake=true`、`terminates=true`、`packet_count=16`。
- **公式证据**：3+2+1×(2+0+0+3)+2+4 = 16 ✓——**无 SLI**（`planner.go:644` 门）、**无数据**（`:665` 门）、**有拆除**（`:673-680` 无门）。
- **语义诚实声明**：`tunnel_only` 的**字面名与实现不符**（不是"隧道建立+数据面"）。存量 notes 文案与此相反 → G-PPTP-1 ①（P4 改写）。P2 errata 已改 JSON `summary`，`expect.notes` 未同步。

### 3.5 `pptp_scenario_data_only`（4）

`{"pptp":{"scenario":"data_only","data_frames":2}}`。

- **无 `has_handshake`、无 `terminates`**（正确：`planner.go:602-607` 直接 return，**无 TCP 握手/挥手**）；`packet_count=4`。
- **公式证据**：`data_frames=2` + `down_data_frames=2`（缺省）= 4 ✓。
- **方向**：2 帧 up（GRE，PNS 侧，seq 0/1、ack 0）+ 2 帧 down（PAC 侧，seq 0/1、ack 1）。

### 3.6 `pptp_role_pac`（21）

`{"pptp":{"role":"pac","scenario":"control_only"}}`。

- `has_handshake=true`、`terminates=true`、`packet_count=21`（与 #3 同数——**换向不改帧数**）。
- **换向证据**：SCCRQ 由 PAC 侧发出（`send("pns", …)` 在 `role=pac` 时走 `down`，`planner.go:516-530`）；握手 SYN 亦反向（`:616-622`）。
- **Call ID 语义反转**：`role=pac` 时 `pnsPort = spec.DstPort`（`planner.go:598-600`），SLI-down 伪影的 peer id 取该值。

### 3.7 `pptp_calls_two`（31）

`{"pptp":{"calls":2,"scenario":"control_only"}}`。

- `has_handshake=true`、`terminates=true`、`packet_count=31`。
- **公式证据**：3+2+2×(2+5+3)+2+4 = 31 ✓。
- **Call ID 递增面**：call 0 用 `callID`/`peerCallID`（`0xa9c0`/`0x35c9`），call 1 用 `+1`（`0xa9c1`/`0x35ca`）——`planner.go:634-635`。
- **SLI 逐 call**：每 call 各自一轮 SLI×5（交替 PNS/PAC 侧）。

### 3.8 `pptp_sli_count_three`（**存量 `min_packets:20`**，公式值 24）

`{"pptp":{"sli_count":3}}`（scenario 缺省 = full）。

- `min_packets=20`、`has_handshake=true`、`terminates=true`；**无 `packet_count`**。
- **公式证据**：3+2+1×(2+3+3+3)+2+4 = **24**。
- **缺陷（G-PPTP-1 ②）**：`min_packets:20` **比实测 24 松 4**（不足以钉帧数）；notes 算式"SLI×3 → 总包数 22-2=20"**错**——把 full 基准当成 22（实为 26），且 26−2 = 24 才对（SLI 由 5 减到 3 少 2 帧）。结果产物 `docs/protocol-pcap-test/pptp.md` 记该例 **Packets 24** ✓。P4 应收窄为 `packet_count: 24`。

### 3.9 `pptp_echo_keepalive`（23）

`{"pptp":{"echo":true,"scenario":"control_only"}}`。

- `has_handshake=true`、`terminates=true`、`packet_count=23`。
- **公式证据**：3+2+**2**+1×(2+5+3)+2+4 = 23 ✓（比 #3 多 2 = ECRQ/ECRP 对）。
- **方向**：ECRQ 由 **PAC 侧**发（`send("pac", buildECRQ())`，`planner.go:628`）、ECRP 由 **PNS 侧**发（`:629`）——RFC 2637 §2.5 注明 Echo-Request 由 PAC 发出。
- **msgType**：5（ECRQ）/ 6（ECRP）；Identifier 恒 **1**（`echoIdentifier`）。
- **无参考 pcap**：ECRQ/ECRP 字节面来自 RFC 模板 + 实现选择，**非实测钉**（设计 §3.6 诚实声明）；本用例只断包数与方向。

### 3.10 `pptp_data_both_directions`（24）

`{"pptp":{"scenario":"full","data_frames":2,"down_data_frames":1}}`。

- `packet_count=24`；**`frames` 1 条（GRE 增强头逐字节）**：
  - `packet 13 offset 34 hex "30 81 88 0b"`——GRE **flags=0x3081**（K\|S\|A\|Ver=1）+ **Protocol Type=0x880B**（PPP），RFC 2637 §4.1。
- **偏移证据**：GRE 帧 offset **34** = 14（以太）+ 20（外层 IPv4）——**无 TCP 层**（与 #2 的 54 是两个不同偏移基，设计 §2）。
- **公式证据**：3+2+1×(2+5+3+**3**)+2+4 = 24 ✓（数据帧 2+1 = 3，比 #1 的 5 少 2 → 26−2 = 24）。
- **帧位**：13-15 = GRE 帧（`ip.proto=47`）；帧 16-18 = 拆除段；19-20 Stop；21-24 挥手。

### 3.11 `pptp_inner_ip_explicit`（**存量无计数断言**，公式值 16）

`{"pptp":{"scenario":"tunnel_only","data_frames":1,"inner_ip":{"src_ip":"192.168.1.10","dst_ip":"10.10.0.5","payload":"inner-pkt"}}}`。

- `has_handshake=true`、`terminates=true`；**无 `packet_count`、无 `min_packets`**（**唯一无计数断言的正例** → G-PPTP-1 ③）。
- **公式证据**：3+2+1×(2+0+0+3)+2+4 = **16**（`tunnel_only` + `data_frames=1`；但 **`tunnel_only` 不触发 `emitDataPlane`** → `data_frames=1` **实际不生效**，帧数与 #4 相同 = 16）。结果产物记 **Packets 16** ✓。
- **`inner_ip` 形状**：**object 型内嵌 7 子键**（`src_ip`/`dst_ip`/`proto`/`src_port`/`dst_port`/`ttl`/`payload`，srv6 `inner_payload` 先例）；`payload` 字符串 = **原文字节**（非 hex、非 base64）。
- **本用例的真实覆盖边界（诚实声明）**：因 `tunnel_only` 不产数据帧，**`inner_ip` 的字节面在本用例中不被实际发出**——用例只覆盖"配置可解析 + 帧数不变"。`inner_ip` 的线字节覆盖需 `scenario=full` 或 `data_only` → **A′ 立项**（G-PPTP-2 附注）。

### 3.12 `pptp_result_error_fields`（21）

`{"pptp":{"scrp_result":5,"ocrp_result":2,"scenario":"control_only"}}`。

- `has_handshake=true`、`terminates=true`、`packet_count=21`（与 #3 同数——**改结果码不改帧数**）。
- **覆盖面**：SCCRP 的 Result Code 字段 = 5（`scrp_result`，`planner.go:205`）、OCRP 的 Result Code = 2（`ocrp_result`，`:258`）。
- **诚实声明**：notes 写"SCCRP/OCRP result-code 字段字节钉（pcap 校准后补）"——**今日无字节断言**（只断帧数）；`pptp.control_result`/`pptp.out_result` 两 tshark 字段可用 → A′ 收编（G-PPTP-3）。
- **RFC 语义注**：`scrp_result=5` **不是 RFC 2637 §2.2 的合法 Result Code**（合法值仅 1 Successful / 2 General error）；这是**故意的越界值透传**（测字段不被 clamp），非协议行为正例。

### 3.13 `pptp_composite_full_multi`（33）

`{"pptp":{"calls":2,"echo":true,"sli_count":3,"data_frames":1,"down_data_frames":1}}`（scenario 缺省 = full）。

- `has_handshake=true`、`terminates=true`、`packet_count=33`。
- **公式证据**：3+2+2+2×(2+3+**2**)+2+4 = 33 ✓（**五类交织**：多 call + 保活 + 双数据 + SLI 计数 + full 拆除序）。
- **本协议最复杂用例**（门3 抽查候选，§5.2）。

**正例总则**：多 call 一 flow、四种场景模板、PAC 换向、保活插入、双数据方向均为正例形态；只有配置/长度/值域错误进入负例。

## 4. 负例契约

负例必须在链路径失败并传播为 task error，不得产生成功 PCAP、`completed/0 packet` 或只剩 TCP 外壳的假成功（**实测 7 例均 0 帧**）。锚词与设计 §7 表一一对应、同序（代码逐字，行号实测）：

| # | ID | 故障输入（机读实测） | JSON `error_contains` | **真实拦截面** | 代码文案（逐字） | 代码行 |
|---:|---|---|---|---|---|---|
| N-1 | `pptp_neg_role_invalid` | `role="switch"` | `invalid pptp role` | planner `Validate` | `invalid pptp role "switch" (allowed: pns, pac)` | `planner.go:118` |
| N-2 | `pptp_neg_scenario_invalid` | `scenario="half"` | `invalid pptp scenario` | planner `Validate` | `invalid pptp scenario "half" (allowed: full, control_only, tunnel_only, data_only)` | `planner.go:124` |
| N-3 | `pptp_neg_calls_negative` | `calls=-1` | `calls` | **registry V9 范围门** | `layers: layer "pptp" field "calls" = -1 invalid: not a numeric value in [0,65535]` | `complete.go:325` |
| N-4 | `pptp_neg_sli_count_negative` | `sli_count=-1` | `sli_count` | **registry V9 范围门** | `layers: layer "pptp" field "sli_count" = -1 invalid: not a numeric value in [0,65535]` | `complete.go:325` |
| N-5 | `pptp_neg_sub_address_hex` | `sub_address="zz"` | `must be hex` | planner `Validate` | `invalid pptp sub_address "zz" (must be hex)` | `planner.go:140` |
| N-6 | `pptp_neg_host_name_long` | `host_name` = **65 字节**（机读实测 `len()==65`） | `exceed 64 bytes` | planner `Validate` | `pptp host_name/vendor_name/phone_number/dialed_number/dialing_number exceed 64 bytes (fixed-size fields, RFC 2637 §2)` | `planner.go:145` |
| N-7 | `pptp_neg_inner_ip_invalid` | `inner_ip.src_ip="300.1.2.3"` | `invalid pptp inner src_ip` | planner `Validate` | `invalid pptp inner src_ip: 300.1.2.3` | `planner.go:149` |

**锚词口径（关键，必须写清）**：`error_contains` 是**子串**判定。**N-3/N-4 的锚词是字段名 `calls`/`sli_count`，不是 planner 文案**——真实拦截面是 registry V9 范围门（`complete.go:325`），其错误串含 `field "calls"` 但**不含** `invalid pptp calls`。**planner 的 `invalid pptp calls %d`（`planner.go:127`）/`invalid pptp sli_count %d`（`:130`）在链路径不可达**（parse 期 `getIntPresence` 收下 -1，registry 范围门先行）。存量 JSON 已按真实拦截面写 ✓。

**负例原子性**：每例单一故障注入；7 例均单键（机读实测）。

**expect 键形状注**：存量 7 负例 `expect` = `{expect_error, error_contains, notes}`（含 `notes`），与 92-moxa 范式的严格两键不同——P4 收窄时删 `notes`（G-PPTP-1）。

**未入用例的拒绝分支（A′ 立项，不得冒充已覆盖）**：

| 锚词 | 代码行 | 链路径可达性 |
|---|---|---|
| `invalid source IP: %s` | `planner.go:105` | 可达（层链 `ip.src` 非法） |
| `invalid destination IP: %s` | `planner.go:110` | 可达 |
| `pptp config is required` | `planner.go:114` | **不可达**（translate 恒产非 nil） |
| `invalid pptp calls %d` | `planner.go:127` | **不可达**（范围门先拦） |
| `invalid pptp sli_count %d` | `planner.go:130` | **不可达** |
| `invalid pptp data_frames %d` | `planner.go:133` | **不可达** |
| `invalid pptp down_data_frames %d` | `planner.go:136` | **不可达** |
| `invalid pptp inner dst_ip: %s` | `planner.go:152` | 可达 |
| `invalid pptp inner proto %d (allowed: 1 ICMP, 6 TCP, 17 UDP)` | `planner.go:155` | 可达（`proto=99`） |
| `layers: layer "pptp" field %q = %v invalid: not a numeric value in [0,65535]` | `complete.go:325` | **已覆**（N-3/N-4 即此面）；其余 2 键（`data_frames`/`down_data_frames`）零用例 |

## 5. 覆盖与对账

### 5.1 三源回指行

RFC 2637 全文实读（15 消息模板 + GRE 增强头 + 状态机，设计 §3/§5）+ **参考 pcap 22 帧 tshark 实测**（`/home/pcap_auto/llcj_mirror/IP-TCP-10.6.2.41-20.6.2.41-49194-1723-12-10-1260-980.pcap`，设计 §3 全部缺省值的唯一权威）+ tshark 3.6.14 `pptp.*` 58 字段 + D-PPTP-1（`CODE_DESIGN.md:3040`）+ D-PPTP-2（设计 §11）→ 20 ID（本契约 §2）。

**第三源"已确认现网行为"当前 = 抓包级已到**（参考 pcap 逐帧核对 + 本仓 20 例），但**真实 pptpd/Windows 客户端的完整拨号会话线字节未取到**（只有 llcj 镜像的一个会话）；开源实现（Linux pptp client）**只借鉴结构决策，未取线字节** → G-PPTP-4 附注。

**20 ID 逐项回指（设计 §）**：#1←§5.1；#2←§3.1；#3←§5.1；#4←§5.1；#5←§5.1；#6←§3.9；#7←§5.1；#8←§3.5；#9←§3.6；#10←§3.8；#11←§3.8；#12←§3.3/§3.4；#13←§5.1；#14←§7 N-1；#15←§7 N-2；#16←§7 N-3；#17←§7 N-4；#18←§7 N-5；#19←§7 N-6；#20←§7 N-7。

### 5.2 对账两行 + 清单出处声明

- **清单出处声明**：本清单来源 = **RFC 2637 公开语义 + 参考 pcap 实测 + D-PPTP-1 历史契约 + 仓库落码反推 + tshark 3.6.14 字段**，**非纯规范反推**。
- **对账两行（机读脚本重数）**：**要求逻辑点总数 = 109**（八项 8 行 + 矩阵 24 格 + 变体 59 行 + 商业映射 18 行）；**用例覆盖数 = 64**（八项 3 + 矩阵 17 + 变体 32 + 商业 12）；**开放立项 = 31**（矩阵 A′ 4 + 变体立项 27）；**不适用 = 9**（矩阵 3 + 商业 6）；**另计 5**（八项矩阵的"有缺口"行，与 G-PPTP-1…10 一一对应，单列不折进前两类）。**逐表重数**：八项 8 = 覆 3 + 缺口 5；矩阵 24 格 = 覆 17 + A′ 4 + 不适用 3；变体 59 行 = 覆 32 + 立项 27；商业 18 行 = 覆 12 + 不适用 6。**64 + 31 + 9 + 5 = 109** ✓
  **粒度声明**：行/格粒度每点 1 计；G-PPTP-1…G-PPTP-10 缺口清单本身不折进 109（八项的 5 个"有缺口"行除外——它们与缺口表一一对应，故显式计入并单列）。**反查全绿 ≠ 覆盖全**。逐表重数见设计 §10（八项 §10 / 矩阵 §10.1 / 变体 §10.2 / 商业 §10.3）。
- **门3 抽查候选**：最复杂用例 = **#13 `pptp_composite_full_multi`**（33 帧：3 握手 + SCCRQ/RP + ECRQ/ECRP + **2 call × (OCRQ/RP + SLI×3 + GRE 2 + 拆除 3)** + Stop 对 + 挥手 4；交织维度 = call(2)×场景段(6)×方向(2)×帧类(TCP/GRE)）；**建议门3 抽 #13 + #1**（`pptp_full_session_ref` 补参考 pcap 逐字节面）+ **#10**（GRE 头字节面）。

### 5.3 存量用例审计（20 例逐条去向）

| # | 存量 id | T | 去向 | 改写动作（P4） |
|---:|---|---|---|---|
| 1 | `pptp_full_session_ref` | T1 | **保留** | notes ④ 改写（"data_frames 缺省 5"→"3+2"）；可补 `pptp.*` field 断言 |
| 2 | `pptp_control_header_magic` | T2 | **保留** | 可补 `pptp.magic_cookie`/`pptp.length`/`pptp.control_message_type` field 断言 |
| 3 | `pptp_scenario_control_only` | T3 | **保留** | 可补"无 `ip.proto==47` 帧"断言 |
| 4 | `pptp_scenario_tunnel_only` | T4 | **改写** | **notes ① 必须改写**（现文案"隧道建立+数据面（无控制拆除）"与实现**完全相反**：实测无数据、有拆除）；可补帧数等值断言 |
| 5 | `pptp_scenario_data_only` | T5 | **保留** | 可补 `ip.proto==47` 帧数断言 |
| 6 | `pptp_role_pac` | T6 | **保留** | 可补"首帧 TCP SYN 由 dst 侧发出"方向断言 |
| 7 | `pptp_calls_two` | T7 | **保留** | 可补 `pptp.call_id` 递增面断言（43456/43457） |
| 8 | `pptp_sli_count_three` | T8 | **改写** | **`min_packets:20` → `packet_count:24`**（松 4，G-PPTP-1 ②）；notes 算式改"26−2=24" |
| 9 | `pptp_echo_keepalive` | T9 | **保留** | 可补 `pptp.control_message_type ∈ {5,6}` 断言 |
| 10 | `pptp_data_both_directions` | T10 | **保留** | 可补 GRE Key 高 16 位（Payload Length）与 Call ID 断言 |
| 11 | `pptp_inner_ip_explicit` | T11 | **改写** | **补 `packet_count:16`**（G-PPTP-1 ③）；**改 `scenario` 为 `full` 或 `data_only` 才能真覆盖 `inner_ip` 字节面**（现 `tunnel_only` 不产数据帧 → 配置不生效） |
| 12 | `pptp_result_error_fields` | T12 | **保留** | 可补 `pptp.control_result=5` / `pptp.out_result=2` 字段断言 |
| 13 | `pptp_composite_full_multi` | T13 | **保留** | 可补分段计数断言（各段帧数分解） |
| 14 | `pptp_neg_role_invalid` | T14 | **保留** | 删 `notes`（严格两键） |
| 15 | `pptp_neg_scenario_invalid` | T15 | **保留** | 删 `notes` |
| 16 | `pptp_neg_calls_negative` | T16 | **保留** | 删 `notes`；锚词 `calls` 保持（真实拦截面是范围门，**不可改成 `invalid pptp calls`**） |
| 17 | `pptp_neg_sli_count_negative` | T17 | **保留** | 删 `notes`；锚词 `sli_count` 同上 |
| 18 | `pptp_neg_sub_address_hex` | T18 | **保留** | 删 `notes` |
| 19 | `pptp_neg_host_name_long` | T19 | **保留** | 删 `notes` |
| 20 | `pptp_neg_inner_ip_invalid` | T20 | **保留** | 删 `notes` |

**汇总**：**17 保留 / 3 改写（#4/#8/#11）/ 0 作废**。**本协议存量 20/20 顶层零残留**（纯层链形）。

### 5.4 现状矛盾点（P4 前诚实登记）

1. **`tunnel_only` 的 notes 与实现相反**（G-PPTP-1 ①）：存量 `expect.notes` 写"隧道建立+数据面（无控制拆除）"，实测**无数据面、有拆除**（`planner.go:644/665/673`）。P2 errata 已改 `summary`，notes 未同步。
2. **`sli_count_three` 断言松 4 且算式错**（G-PPTP-1 ②）：`min_packets:20` vs 公式 24；notes "22-2=20" 把 full 基准当 22（实为 26）。
3. **`inner_ip_explicit` 无计数断言且 `inner_ip` 实际不生效**（G-PPTP-1 ③ + G-PPTP-2 附注）：`scenario=tunnel_only` 不产数据帧 → `data_frames=1` 与 `inner_ip` 配置**都不被发出**；用例只覆盖"可解析 + 帧数不变"。
4. **`full_session_ref` notes 表述误导**（G-PPTP-1 ④）："data_frames 缺省 5" 实为 `data_frames=3` + `down_data_frames=2`。
5. **`pptp.*` 字段零使用**（G-PPTP-3）：58 个可用字段今日零断言；`result_error_fields` 的 notes 自认"字节钉待补"。
6. **7 负例带 `notes` 键**（G-PPTP-1）：与严格两键口径不符。
7. **N-3/N-4 锚词是字段名不是 planner 文案**（非缺陷，**设计事实**）：真实拦截面是 registry V9 范围门；planner 对应分支在链路径不可达（设计 §7）。
8. **39 个 registry 键零用例**（G-PPTP-2 ③）：51 键中仅 12 键有用例。
9. **ICRQ/ICRP/ICCN/WEN 四消息零用例**（G-PPTP-2 ① ②）：`incoming_call`/`wen` 键与 `build*` 均存在。
10. **IPv6 外层零用例**（G-PPTP-7）：`planner_test.go:966` 有单测，无用例。
11. **结果产物 pcap 留档缺失**（G-PPTP-5）：`docs/protocol-pcap-test/pptp.md`（tracked）写"20 — pass 20, fail 0, error 0"，末次提交 `08b8738b`（**2026-09-20**）**晚于**判死提交 `0417be5`（2026-09-13）✓ **未过期**；但 `docs/protocol-pcap-test/pptp/` **目录不存在（0 个 pcap）**，13 个正例的 pcap 链接**全部悬空** → 该 20/20 **未经今日复跑证实、无 pcap 可查**；另 **NIC 路未跑**。**本车道未跑该套件**，故不以任何形式引用该数字。

## 6. P3 固定动作（管线：§3.15 三项 + A′/B′ 两分类）

### 6.1 §3.15 三项逐项一例或立项

| # | 三项 | 本协议对照 | 用例/立项 |
|---:|---|---|---|
| ① | 同连接/同流内的多轮操作 | **本协议核心形态**：单 flow 内 TCP 控制连接多轮消息对（SCCRQ/RP → OCRQ/RP → SLI×N → CCRQ/CCDN → StopRQ/RP）+ GRE 数据面 | 已覆 #1/#7/#13 |
| ② | 非正常结束 | 正常终止 = StopRQ/RP + FIN 四帧（全正例）；**RST 异常中断**本层零断言（框架能力） | 已覆（FIN 全正例）；RST **A′ 立项**（本层零断言） |
| ③ | 长保活 | 协议层**无 keepalive 定时器**（RFC §3.1.4 不建模）；`echo=true` = 单次 ECRQ/ECRP 插入 | 已覆 #9（**结构路径**，非周期） |

无空项：① 有已覆例；② 有已覆例 + 1 条 A′ 立项；③ 有 #9（并诚实声明非定时器）。

### 6.2 A′/B′ 两分类表

**A′（P4 接线）**：

| 类 | 内容 | 落点 |
|---|---|---|
| field 断言面 | 收编 58 个 `pptp.*` 字段（`control_message_type`/`call_id`/`magic_cookie`/`length`/`control_result`/`host_name` 等）——今日零使用 | G-PPTP-3 |
| 存量断言修复 | #4 notes 改写 / #8 `min_packets`→`packet_count:24` / #11 补 `packet_count:16` + 改 scenario / #1 notes 改写 / 7 负例删 `notes` | G-PPTP-1 |
| ICRQ 族面 | `incoming_call=true`（ICRQ/ICRP/ICCN 三消息） | G-PPTP-2 ① |
| WEN 面 | `wen=true`（WAN-Error-Notify） | G-PPTP-2 ② |
| 散键面 | 39 键零用例（`call_id` 族 / `version` / `framing_caps` 族 / `inner_ip.proto=1/6` / 合法 hex `sub_address` / 合法 `host_name` / OCRQ 标量族 / SLI ACCM / Stop/CCDN 结果码 / 长度字段 4 键） | G-PPTP-2 ③ |
| Error Code 枚举 | RFC 2637 §2.16 七值（0–6） | G-PPTP-2 ④ |
| 上限面 | `calls` 上界 65535 / 内层 payload 上限（GRE MTU 1532）/ Payload Length uint16 截断 | G-PPTP-6 |
| 显式零面 | `data_frames=0`（唯一可表达零的键，`planner_test.go:688` 有单测无用例） | G-PPTP-8 ④ |
| 地址族面 | 外层 IPv6（`planner_test.go:966` 有单测） | G-PPTP-7 |
| 端口面 | 非默认 `dst_port`（**今日无配置通道**，需先裁定登记端口键） | G-PPTP-7 |
| 非正常结束 | `tcp.rst` 补例 | ② 的 A′ |
| 动态字段面 | `call_id`/`peer_call_id`/`host_name`/`vendor_name`/`inner_ip` 五类逐流变（需先扩 allowlist） | G-PPTP-10 |

**B′（框架面）**：`CheckProtoFlat` pptp presence 分支 + 游离顶层键通用门（G-PPTP-9，等框架级 unknown-key 白名单，不单独立项）/ 业务字段动态（G-PPTP-10，allowlist 无 `pptp` 行）/ 负例 `notes` 键收窄（G-PPTP-1）。进设计 §14，「明确不解决 + 迁入计划」。

### 6.3 §3.14 豁免边界审计

**有长连接载体（TCP 1723）→ `sessions[]` 不豁免**。但**本协议不用 `sessions[]` 形态**——`calls=N` 是**同一隧道内多路呼叫**（RFC 2637 §3.2.2 三元组 `(PAC, PNS, Call ID)` 定义的 session），**形态差异已声明**（设计 §12.3 会话表 s5：同一四元组内多 call，不是多会话）；`role` 表达 PNS/PAC 两侧。多流并发由策略级 `flow_control {"flows": N}` 承载（本版 20 例未用，存量单 flow）。**单包多载荷** = **已覆**：#1 帧 19 是 **CCRQ+CCDN 合并 TCP 段**（164B，两条 PPTP 消息拼进一个 TCP 载荷）——本协议唯一的"单包多载荷"形态。

## 7. 实现后执行建议

1. **P4 顺序**：①先修 G-PPTP-1 五处存量缺陷（#4 notes / #8 计数 / #11 计数与 scenario / #1 notes / 7 负例删 notes）；②补 A′ field 断言（收编 `pptp.*`）；③补 ICRQ 族 / WEN / Error Code 枚举例；④补 IPv6 与上限例；⑤全量复跑。**本协议无 §1 迁移步骤**（顶层零残留）。
2. **实测顺序**：先 #2（控制头 12B 字节，最稳）、#1（全序 26 帧）、#10（GRE 头 `30 81 88 0b` @offset 34）、#8（SLI 计数 24）、#9（echo 23）、#13（复合 33），最后 #5（`data_only` 4 帧）。
3. **二进制与 HEAD 同代确认**（门2③：`find trafficgen -name '*.go' -newer <server-binary>` 无输出）；门2② 全量（`CASE_PROTO=pptp` 全量不是增量）；门2④ 反查绿后进 P6。
4. **G-PPTP-5 纪律**：`docs/protocol-pcap-test/pptp.md` 的 20/20 **未经今日复跑证实、无 pcap 留档**，**不得作为"今日已复跑"依据**；P5 重跑后重生成该产物 + 落 pcap 文件 + 补 NIC 路。
5. 任何 RFC 2637 条款号的具体引用须有原文证据（本版 §3 已逐节标注）。

## 8. 存量审计汇总（20 例）

见 §5.3（逐条去向表）+ §5.4（现状矛盾点 11 条）。**汇总：17 保留 / 3 改写 / 0 作废**；**20/20 顶层零残留**；**13 正例中 11 例 `packet_count` 与公式一致，1 例松 4（#8），1 例缺失（#11）**；**2 条 `frames`（3 个 hex）+ 1 条 `fields`（11 个断言）为今日全部非计数断言面**。

## 9. 附：覆盖反查门建议断言行（供主线程合后登记；本车道不碰 `coverage_gate.py`）

> **现状**：`coverage_gate.py` 已有 `check_pptp`（`coverage_gate.py:3901` / `:6222` 两处重复定义），内容 = **20 个 ID 存在性 + 12 个层内键存在性 + 7 个锚词出现性**（共 39 行，与 D-PPTP-1 P6 的"反查 39/39"对应）。下列为**本契约新增建议**（每条可从本契约与 cases JSON 直接机读，不需新造事实）：

| # | 建议断言 | 依据 |
|---:|---|---|
| 1 | `len(cases['pptp']) == 20` 且 ID 集合 = §2 二十项，顺序一致 | 本契约 §2 |
| 2 | 20/20 例 `spec_json` 顶层键 ⊆ `{layers}`（**本协议零游离键**） | 本契约 §1；设计 §12.1 |
| 3 | 20/20 例层链形状 == `[ip, pptp]`（**唯一形状**，无 `tcp` 层） | 本契约 §1 |
| 4 | 13 正例 `packet_count` == 设计 §9.1 公式值（P4 修完 #8/#11 后；**今日 #8 为 `min_packets`、#11 缺失，应标红**） | 设计 §9.1 |
| 5 | 7 负例 `expect` 键 == `{expect_error, error_contains}`（P4 删 `notes` 后；**今日含 `notes`，应标红**） | 本契约 §4 |
| 6 | 负例 `error_contains` ∈ 代码锚词集 `{"invalid pptp role", "invalid pptp scenario", "calls", "sli_count", "must be hex", "exceed 64 bytes", "invalid pptp inner src_ip"}` | 设计 §7 |
| 7 | 非负例顶层键计数 == 0（**今日已成立**） | 设计 §12.1 |
| 8 | 每个 GRE 帧断言（`frames`）的 offset == **34**；每个控制帧断言（`frames`）的 offset == **54**（**两个偏移基不可混**） | 设计 §2 |
| 9 | 存在至少一条 `fields` 断言含 `tcp.dstport == "1723"`（1723 恒定性面） | 本契约 §3.1 |
| 10 | 存在至少一条 `frames` 断言 hex 含 `1a 2b 3c 4d`（Magic Cookie 面） | 本契约 §3.2 |
| 11 | 存在至少一条 `frames` 断言 hex 含 `30 81 88 0b`（GRE 增强头面） | 本契约 §3.10 |
| 12 | `expect.notes` 中不得出现 `"tunnel_only"` 与 `"数据面"` 同现（**今日 #4 违反，应标红**，G-PPTP-1 ①） | 设计 §5.1 点 1 |
| 13 | `pptp.*` field 断言计数 ≥ 1（**今日 == 0，应标红**，G-PPTP-3） | 本契约 §1 |
| 14 | 存在 `incoming_call` 键用例（**今日 == 0，应标红**，G-PPTP-2 ①） | 设计 §3.7 |
| 15 | 存在 `wen` 键用例（**今日 == 0，应标红**，G-PPTP-2 ②） | 设计 §3.7 |
| 16 | 存在 IPv6 外层用例（**今日 == 0，应标红**，G-PPTP-7） | 设计 §8 |
| 17 | registry `pptp` Fields 键数 == 51 且与 `parsePPTPConfig` 消费面逐键一致（**今日已成立**，设计 §12.13） | 设计 §12.13 |

**另注意**：`trafficgen/docs/protocol-pcap-test/pptp.md` 的 20/20 pass（末次提交 `08b8738b` **2026-09-20**，**晚于**判死提交 `0417be5` 2026-09-13）**未过期**，但 `docs/protocol-pcap-test/pptp/` **0 个 pcap 文件**（目录不存在）→ 该数字**未经今日复跑证实、无留档**（G-PPTP-5）；**本车道未跑该套件**，不得据此判断套件今日已复跑。

## 10. 自审记录与修订记录

- v1.0.0（2026-09-29）：P-PIPE 文档轨批次二 as-built 定稿。承 D-PPTP-1 的 T-PPTP-1…20 清单（**一一对应，无虚例**）；形状基线机读实测（§1，**顶层零残留**、层链唯一形状 `[ip,pptp]`）；包数公式机读复算 13/13（§1/§5.3，11 例一致 / 1 例松 4 / 1 例缺失）；7 负例锚词与**真实拦截面**（registry 范围门 vs planner）逐条对齐（§4）；存量审计 20 例逐条去向（§5.3：17 保留 / 3 改写 / 0 作废）；现状矛盾点 11 条（§5.4）；P3 固定动作（§6）；执行建议（§7）；覆盖反查门建议 17 行（§9，含 6 条今日应标红项）。**仅文档，未动 JSON/代码。**
- **自审（4 轮，末轮干净；脚本生成，非手算）**：机读复核全部计数与断言——20 例 ID/顺序/顶层键/层链形状/`expect` 键集合/`packet_count`/锚词/层内键使用分布逐项对账；包数公式对 13 正例逐例复算；registry Fields 51 键与 `parsePPTPConfig` 消费面逐键对账（差集 = `{inner_ip}`，经 `parsePPTPInnerIP` 承接）；**§3 逐例断言（`packet_count`/`min_packets`/`frames` packet+offset+hex/`fields` packet+field+value/层内键）与 cases JSON 逐条交叉比对零差异**；§3.2 帧长表与 body 公式逐条对 `build*` 源码复算；§3.3/§3.4/§3.5 全部缺省值与 `resolveDefaults` 源码逐键比对；参考 pcap 帧 4/5/7/8/9/15 字节与字段实测复核；RFC 2637 段落号逐条回查（§2.1–2.16/§3.1/§3.2/§4.1）。**第 1 轮抓 3 项**（矩阵 24 格分类数 17/4/3 非 17/6/1、变体覆/立项 32/27 非 27/32、八项缺口 5 非 4）；**第 2 轮抓 5 项**（`planner.go` 1074 非 1075 / `planner_test.go` 1026 非 1004 / `pptp_chain_test.go` 70 非 71 / `resolved` 44 字段非 54 / `parsePPTPConfig` 消费面差集说明错写 `data_frames` 应为 `inner_ip`）；**第 3 轮抓 1 项**（§0 #18 表述含"14 个"残留 + 一处行号口径 `:126/129` → `:127`）；**第 4 轮零新发现**。
