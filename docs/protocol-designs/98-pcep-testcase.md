# #98 pcep（路径计算元素通信协议）测试用例契约

> 版本：v1.0.0（P-PIPE 文档轨 P1–P3）
> 日期：2026-09-28
> 配套设计：`docs/protocol-designs/98-pcep-design.md` v1.0.0（D-PCEP-1）
> 旧基线：`docs/protocol-designs/42-pcep-testcase.md` v1.0.0（24 例；思路继承不搬码）
> 机器契约：`trafficgen/test/protocol_pcap/cases/pcep.json`（24/24 ID 与本版 §2 一致、顺序一致，已机读实测；**合规判定 = 非负例顶层键 84 处残留 / 17 例全违规**；**存量 24 例今日 create 400 全红**，去五键即可用；G-PCEP-1）
> 白话一句：**二十四条检查：十七条看正常对话（建会话、发保活、问路、回路径、报错、多请求、多会话、v6、扩展档案），七条看胡来能不能被拦下；每条只查一件事。**

## 1. 测试原则和形状基线

用例从设计 §3–§9 逐项派生，共 **24 个唯一语义 ID：17 正 + 7 负**（继承旧稿计数，负例 N-1…N-7）。派生规则：设计 §3 每个线格式条款、§4 每类消息/对象、§5 每个扩展 profile 边界、§7 每行错误处理在本文有对应断言；断言不得超出设计声明范围。**一个用例只验证一个协议行为**。

**形状基线（2026-09-28 机读实测；合规判据 = 非负例顶层键必须为 0，白名单 = `layers`/`strategy_fc`/`ttl`/`flow_control`/`output`/`output_config`/`group_id`）**：24/24 例顶层键 = `{expect,id,notes,proto,spec_json,summary}`（无 `strategy_fc`）；`spec_json` 顶层键 = `{layers, src_ip, dst_ip, src_port, dst_port, pcep}` ×23 + 同形无 `src_port` ×1（#13 多会话，`src_port` 住 `sessions[]`）。

**合规判定：❌ 无一条合规**——非负例（17 例）顶层越白名单键 = `src_ip`×17 + `dst_ip`×17 + `dst_port`×17 + `src_port`×16 + 顶层 `pcep` 子映射×17 = **84 处残留，17/17 例全违规**（全 24 例同口径 119 处，含 7 负例同样残留）。层形 `[tcp,pcep]` ×24 但**层内配置恒 `{}`（非空 0/24）= 空壳**：`registry.go:1391` 无 `Fields`，`translateTerminalConfig`（`chain_planner_translate.go:695`）**无 `case "pcep"`**（`:753-755` 只赋空 `&core.PCEPConfig{}`），故层内配置今日既进不去也不被解码。**顶层 `pcep` 子映射 + 顶层四元组与 `layers` 并存 = 判死形状**（CORE_MEMORY §1.4/§1.11/§1.13），且**存量 24 例今日 create 400 全红**——`core.CheckProtoFlat`（`strategy_convert.go:8632` 五键循环）在 create 门（`schema/semantic.go:130`）无条件执行，pcep **无**顶层子映射分支。**"合规层链形今日跑不通"成立**（无 `Fields`），但**"顶层五键形是唯一可用"不成立**：去掉五键即可用。四形实测（实调 `schema.ValidateStrategy`，命令见 design §15）：

| 形状 | create |
|---|---|
| 存量：`layers` 空壳 + 五键 + 顶层 `pcep` | ❌ **400 ×24/24** |
| `layers` 空壳 + 顶层 `pcep`（**去五键**） | ✅ 24/24 可用 |
| 仅顶层 `pcep`（无 `layers`） | ✅ 24/24 可用 |
| 纯层链 `[ip,tcp,pcep]` 带 `events` | ❌ 0/24（`unknown field "events"`） |

收敛两路并列：**①低成本先解封** = 只删五键（仍非合规形，门1 §1 仍红）；**②合规收敛** = 代码阶段补 registry `Fields` + `translateTerminalConfig` case + `mapToFlowSpec` 收敛（门1 转绿唯一路径）。**文档阶段两件都改不动**（不动代码、不动 JSON）。17 正例 `expect` 均含 `packet_count`；7 负例 `expect` 键集合严格为 `{expect_error,error_contains}`（干净）。

**输出契约（pcap/NIC 双输出）**：两路径共用同一 cases JSON 与断言集（`tcp.dstport/srcport`、`pcep.*` 字段、offset 54 frames）；NIC 经 tcpdump 捕获（`nic_capture` 用例级开关）；不设仅单路径可用的断言。

**TSHARK 基线**：本机 tshark 3.6.14 实测 `pcep.*` 已注册 **379** 个字段（`tshark -G fields | grep -P '\tpcep\.'`）——本协议**可用 pcep 原生 dissector**（与 moxa 的零 dissector 相反）。存量 JSON 使用的 **39** 个 `pcep.*` 字段（去重）+ `tcp.dstport`/`tcp.srcport` 全部逐项实测已注册（无臆造字段）。**注意口径**：`tcp.dstport`/`tcp.srcport` 属 `tcp.*` 通道，不在 `pcep.*` 前缀内，校验脚本需同时放行两族。

**动态字段禁止硬编码**：生成期值用 `same_as_packet`/`distinct_values`/`nonzero` 断言；本协议存量用例未使用动态面（G-PCEP-3），代码阶段收敛时按需引入。

**包数约定**：单流 = 3（握手）+ N（显式事件数）+ 4（FIN 四包挥手）。数据帧从帧 4 起；实现期以实际输出校准 packet_count，断言以 fields/frames 为准；负例无 packet_count。多会话（`sessions[]`）= 各会话包数之和（#13 = 2×11 = 22）。

**保活/重试/RST 口径**：PCEP 的 Keepalive 是**显式事件**（不是引擎自动补的周期消息），已覆 #1/#3；RST 为框架 tcp 层能力，本协议层不新增断言（A′ 补例）；正例恒 FIN 优雅终止。`CheckFault` 是拒绝面：注入 `wire_fault` 即拒（N-1），不产出畸形线包。

## 2. 原子用例索引（24 ID = 17 正 + 7 负，顺序为权威）

| # | ID | 类型 | 覆盖（设计 §） | application events | packet_count |
|---:|---|---|---|---:|---:|
| 1 | `pcep_open_keepalive` | 正 | §4.1：双向 Open（SID 7/8）、Keepalive、common length | 3 | 10 |
| 2 | `pcep_open_bidirectional` | 正 | §4.1/§4.4：双向 Open/Keepalive、TCP direction | 4 | 11 |
| 3 | `pcep_keepalive_direction` | 正 | §4.1：两方向 Keepalive，禁止隐式补发 | 6 | 13 |
| 4 | `pcep_pcreq_ipv4_ero_metric` | 正 | §4.2：IPv4 PCReq、RP/endpoint/ERO/Metric + PCErr | 4 | 11 |
| 5 | `pcep_pcrep_ipv4_ero_rro` | 正 | §4.2：IPv4 PCRep、request ID/RRO/Metric | 4 | 11 |
| 6 | `pcep_pcntf_and_pcerr` | 正 | §4.3：PCNtf、PCErr、Notification/Error | 6 | 13 |
| 7 | `pcep_multi_request` | 正 | §4.4：多 request/response、request ID 隔离 | 7 | 14 |
| 8 | `pcep_ipv6_address_family` | 正 | §4.4：IPv6 endpoint/ERO（外层仍 IPv4） | 4 | 11 |
| 9 | `pcep_lsp_object_flags` | 正 | §5：RFC 8231 LSP/SRP、PLSP-ID | 4 | 11 |
| 10 | `pcep_rro_ipv4_ipv6` | 正 | §4.2：IPv4 RRO subobject 的 L flag 与 flags | 4 | 11 |
| 11 | `pcep_metric_flags` | 正 | §4.2：Metric Cost/Bound flags/value | 4 | 11 |
| 12 | `pcep_tcp_direction` | 正 | §4.4：c2s PCReq/PCNtf、s2c PCRep、TCP 4189 方向 | 5 | 12 |
| 13 | `pcep_multi_session` | 正 | §4.4：两个独立 TCP sessions、SID 隔离 | 8 | 22 |
| 14 | `pcep_stateful_rfc8231_profile` | 正 | §5：Open capability TLV 16/17、LSP/SRP | 3 | 10 |
| 15 | `pcep_delegation_rfc8281_profile` | 正 | §5：delegation flags（delegate/remove/create 三条 pcreq） | **5** | **12** |
| 16 | `pcep_common_header_length` | 正 | §3.1：version/type/message length（Open×2/PCReq/PCRep） | 4 | 11 |
| 17 | `pcep_object_flags` | 正 | §3.2/§4.2：P/I object flags、LSPA flags | 3 | 10 |
| 18 | `pcep_neg_malformed_length` | 负 | §7：N-1 wire_fault length | — | — |
| 19 | `pcep_neg_unknown_type` | 负 | §7：N-2 未知 message type | — | — |
| 20 | `pcep_neg_object_length` | 负 | §7：N-3 object length 越界 | — | — |
| 21 | `pcep_neg_keepalive` | 负 | §7：N-4 Keepalive 带 object | — | — |
| 22 | `pcep_neg_session_id` | 负 | §7：N-5 SID=0 | — | — |
| 23 | `pcep_neg_address_family` | 负 | §7：N-6 IPv4 profile 携 IPv6 | — | — |
| 24 | `pcep_neg_stateful_without_profile` | 负 | §7：N-7 base profile 携 LSP/SRP | — | — |

T-编号对照：T-PCEP-S1…S17 ≡ #1…#17；T-PCEP-N1…N7 ≡ #18…#24（与设计 §9 一一对应）。

**对账（2026-09-28 机读）**：ID 集合、顺序、17 正例 `packet_count`（含 #15 = 12）与设计 §9 表逐行一致。**旧稿偏差**：#15 旧稿写 3 events / 10 packets，实测 5 / 12（漏计两条 Open），本版以实测为准（设计 §0 行 6）。

## 3. 正例逐项断言契约（最低断言集，实现期可增不可减）

每例均含 `packet_count` + 载体与方向断言 + frames 断言。**frames 实测口径**（存量 24 例）：短消息固化 4 字节 common header（Open `20 01 00 0c`、Keepalive `20 02 00 04`），长对象消息只固化 2 字节（`20 06`/`20 07`/`20 04`/`20 03`）；**唯一例外** #13 `pcep_multi_session` 的 Open 只固化 2 字节（`20 01`，帧 4/15）。**全部 24 例 offset = 54**（含 #8 的 IPv6 语义例——外层仍 IPv4，见设计 §4.4）。

### 3.1 `pcep_open_keepalive`（10）

c2s Open（SID=7、KA=30、DT=120）、s2c Open（SID=8、KA=30、DT=120）、c2s Keepalive。帧 4/5（offset 54）hex `20 01 00 0c`；帧 6 hex `20 02 00 04`。fields：帧 4 `pcep.msg=1`、`pcep.version=0x01`、`pcep.flags=0x00`、`pcep.msg_length=12`、`pcep.obj.open.pcep_version=1`、`.keepalive=30`、`.deadtime=120`、`.sid=7`；帧 5 `pcep.msg=1`、`.sid=8`；帧 6 `pcep.msg=2`、`pcep.msg_length=4`；帧 4 `tcp.dstport=4189`。**断言 SID 两方向不同（7/8）即合法**（设计 §4.1 校正旧稿）。`has_payload=false`（帧长 ≤ 阈值）。

### 3.2 `pcep_open_bidirectional`（11）

两方向 Open 后各方向 Keepalive（4 事件）。frames 帧 4/5/6/7 = `20 01 00 0c`×2 + `20 02 00 04`×2；`directional=true`，证明 direction 不是靠端口交换猜测。

### 3.3 `pcep_keepalive_direction`（13）

Open 后 c2s、s2c 各两条显式 Keepalive（6 事件）。frames 四条 `20 02 00 04`；断言四个 Keepalive 的 `pcep.msg=2`、长度 4 和方向；packet_count 只对应显式消息（无自动周期补发）。

### 3.4 `pcep_tcp_direction`（12）

c2s PCReq、s2c PCRep、c2s PCNtf（5 事件）。fields：帧 6 `tcp.dstport=4189` + `pcep.msg=6`；帧 7 `tcp.srcport=4189` + `pcep.msg=7`；帧 8 `pcep.msg=4`。逐包断言 TCP 4189 端口与 PCEP message type，验证请求、响应、通知三方向独立（**本用例不含 PCErr**；PCErr 方向面由 #6 承载）。

### 3.5 `pcep_multi_session`（22）

`sessions[]` 两条：s1 `src_port=40001`（Open SID 7/8 + pcreq/pcrep）、s2 `src_port=40002`（Open SID 22/23 + pcreq/pcrep）。frames：帧 4/15 = `20 01`（**本例 Open 只固化 2 字节**，与 #1 的 4 字节口径不同）、帧 6 = `20 06`、帧 17 = `20 06`。fields：帧 4 `.sid=7`、帧 6 `pcep.obj.rp.requested_id_number=0x00001fa5`（8101）、帧 15 `.sid=22`、帧 17 `requested_id_number=0x00001fa6`（8102）。断言两会话的 SID/request ID 不串联，且第二会话包号起点 = 第一会话总包数 + 1（整块展开，设计 §12.3 时间线）。合计 22。

### 3.6 `pcep_pcreq_ipv4_ero_metric`（11）

c2s PCReq（`request_id=1001` + 事件级 endpoint + 显式 `objects[]` 含 rp/endpoint/ero/metric）、s2c PCErr 关联同一 request ID。fields：帧 6 `pcep.msg=6`、`pcep.obj.rp.requested_id_number=0x000003e9`（1001，**该断言条目在帧 6 出现两次**——因显式 `rp` 对象与事件级 endpoint 触发的自动补 RP **各产出一条同值 RP 对象**，Wireshark 聚合出两个同值条目；见下）、`pcep.obj.end_point.source_ipv4_address=192.0.2.10`、`.destination_ipv4_address=192.0.2.20`、`pcep.subobj.ipv4.ipv4=198.51.100.1`、`pcep.obj.metric.type=1,1`；帧 7 `pcep.msg=3`、`pcep.error.type=1`、`pcep.error.value=2`。**自动派生规则佐证**：`pcep.obj.rp.requested_id_number` 的重复条目对应设计 §4.2 的"事件级 endpoint 自动补 RP"路径（实现 `builder.go:522-528`——该路径只在 `objects[]` 无 `class:"rp"` 时触发；本用例同时给了显式 `rp` 与事件级 endpoint，故是**双 RP 形状**的现状锚点）。P4 重钉时须先跑后钉，并用 `distinct_values` 或拆包断言复核该聚合条目。

### 3.7 `pcep_pcrep_ipv4_ero_rro`（11）

c2s PCReq `request_id=2001`，s2c PCRep 带 END-POINT、ERO、RRO、Metric。fields：帧 6 `requested_id_number=0x000007d1`（2001）；帧 7 `pcep.msg=7`、`requested_id_number=2001`、`pcep.subobj.ipv4.ipv4=198.51.100.1`、`pcep.obj.metric.type=1,2`、`pcep.obj.metric.metric_value=20`、`pcep.obj.rro.type=1`。不宣称真实 CSPF 路径计算正确。

### 3.8 `pcep_multi_request`（14）

两个 c2s PCReq（request ID=3001/3002）+ 两个 s2c PCRep + 尾部 c2s Keepalive（7 事件）。fields：帧 6/7/8/9 的 `requested_id_number` 依次 `0x00000bb9`(3001)/`0x00000bba`(3002)/3001/3002；帧 8/9 `pcep.msg=7`。逐包断言 request ID 按请求-响应配对、不复用错误对象。

### 3.9 `pcep_ipv6_address_family`（11）

`profile=pcep_rfc5440_ipv6`，外层载体仍 IPv4（`src_ip=192.0.2.10`）。fields：帧 6 `pcep.msg=6`、`pcep.obj.end_point.source_ipv6_address=2001:db8::10`、`.destination_ipv6_address=2001:db8::20`、`pcep.subobj.ipv6.ipv6=2001:db8:1::1`；帧 7 `pcep.msg=7`、`pcep.subobj.ipv6.l=1`。不出现 IPv4 subobject。**IPv6 是 PCEP endpoint/profile 语义，不是 IPv6 TCP 或另一端口**（设计 §4.4）。

### 3.10 `pcep_rro_ipv4_ipv6`（11）

**实测为单 IPv4 profile 例**（旧稿称"分别在 IPv4 与 IPv6 profile"与用例不符，设计 §0 行 7）。fields：帧 6 `pcep.subobj.ipv4.ipv4=198.51.100.1`、`pcep.subobj.ipv4.l=1`；帧 7 `pcep.obj.rro.type=1`、`pcep.subobj.flags.lpu=0`。IPv6 RRO 半边为缺口 G-PCEP-7（A′ 补例）。

### 3.11 `pcep_metric_flags`（11）

两个 PCReq 分别设 Metric Cost 与 Bound。fields：帧 6 `pcep.metric.flags.c=1`、`pcep.obj.metric.type=1,1`、`pcep.obj.metric.metric_value=12.5`；帧 7 `pcep.metric.flags.b=1`、`pcep.obj.metric.type=1,2`、`pcep.obj.metric.metric_value=20`。证明 C/B flags 独立于 metric value，不被 bandwidth 字段覆盖。

### 3.12 `pcep_pcntf_and_pcerr`（13）

PCReq 后 s2c PCNtf 与 PCErr，再 c2s Keepalive。fields：帧 6 `pcep.msg=6`；帧 7 `pcep.msg=4`、`pcep.obj.notification.type=1`、`.value=0x01`；帧 8 `pcep.msg=3`、`pcep.error.type=2`、`pcep.error.value=3`；帧 9 `pcep.msg=2`。区分正常 PCErr message（帧 8，任务成功）与 malformed task error（N 系列，任务失败）。

### 3.13 `pcep_lsp_object_flags`（11）

stateful profile 中 c2s PCReq 携 LSP PLSP-ID 与 delegate/create flags、SRP-ID，s2c PCRep 携同一 PLSP-ID。fields：帧 6 `pcep.msg=6`、`pcep.obj.lsp.plsp-id=77`、`pcep.obj.lsp.flags.delegate=1`、`.create=1`、`pcep.obj.srp.id-number=9001`；帧 7 `pcep.obj.lsp.plsp-id=77`。

### 3.14 `pcep_stateful_rfc8231_profile`（10）

显式 Open capability TLV。fields：帧 4 `pcep.stateful-pce-capability.lsp-update=1`、`pcep.sync-capability.include-db-version=1`（`include_db_version=true` 时 TLV 16 与 17 同时出现，设计 §5）；帧 6 `pcep.msg=6`、`pcep.obj.lsp.plsp-id=88`、`pcep.obj.srp.id-number=9100`。只验证显式消息，不自动生成 PCUpd 或全库同步。

### 3.15 `pcep_delegation_rfc8281_profile`（12）

`profile=pcep_rfc8281_delegation`，5 事件 = 2 Open + 3 条 pcreq（delegate / remove / create，各自 LSP+SRP）。fields：帧 6 `pcep.obj.lsp.plsp-id=99`、`pcep.obj.lsp.flags.delegate=1`；帧 7 `.flags.remove=1`；帧 8 `.flags.create=1`。三种 flag 分离事件，不能把 delegation 当作基础 profile 能力（base profile 携 lsp/srp 走 N-7 拒绝）。

### 3.16 `pcep_common_header_length`（11）

Open×2、PCReq、PCRep 四消息（4 事件，顺序 = open c2s / open s2c / pcreq c2s / pcrep s2c）。frames 帧 4 `20 01 00 0c`、帧 6 `20 06`、帧 7 `20 07`；逐包断言 `pcep.version`、`pcep.flags`、`pcep.msg`、`pcep.msg_length`。**Open 长度 = 12（0x0c），旧稿 `0x10` 错**（设计 §0 行 5）。**注意**：旧稿 testcase §3.7 覆盖列写"Open、Keepalive、PCReq、PCRep"但事件序列**不含 keepalive 事件**——本版已按实际事件序列校正（Keepalive 头部长度面由 #1/#3 覆盖）。

### 3.17 `pcep_object_flags`（10）

PCReq 的 RP object flags 与 LSPA object flags。fields：帧 6 `pcep.obj.hdr.flags.p=1,0`、`pcep.obj.hdr.flags.i=1,0`（**两个对象各一值**：RP 带 P/I、LSPA 带 L——`1,0` 为 Wireshark 多值聚合格式，P4 重钉时按 `distinct_values` 或拆包断言复核）、`pcep.lspa.flags.l=1`、`pcep.obj.lspa.setup_priority=3`、`.holding_priority=4`。

**正例总则**：两方向 Open 的 SID 不同、Keepalive 无对象、IPv4 profile 下不出现 IPv6 对象、`sid` 非 0——均为正例形态；只有配置/线格式/状态/关联/长度/地址族错误进入负例。

## 4. 负例契约

负例必须在 planner/validator 阶段失败并传播为 task error，不得产生成功 PCAP、`completed/0 packet` 或只剩 TCP 外壳的假成功；`expect` 键集合**严格为** `{expect_error,error_contains}`。锚词与设计 §7 表一一对应、同序；**实际注入形状逐例实测**（旧稿"错误注入"定性只对 N-1 成立）：

| # | ID | 实际注入形状（机读） | 拒绝分支（`builder.go` 行） | `error_contains` |
|---:|---|---|---|---|
| N-1 | `pcep_neg_malformed_length` | `wire_fault:{kind:"length",declared:2}` | `CheckFault` `:661-670` | `length` |
| N-2 | `pcep_neg_unknown_type` | `{kind:"unknown",message_type:99}` | `:723` | `type` |
| N-3 | `pcep_neg_object_length` | `objects:[{class:"rp",object_length:3}]` | `:773` | `object` |
| N-4 | `pcep_neg_keepalive` | `{kind:"keepalive",objects:[{class:"rp"}]}` | `:732` | `keepalive` |
| N-5 | `pcep_neg_session_id` | `{kind:"open",sid:0}`（**非 SID 漂移**，G-PCEP-9） | `:696-698` | `session` |
| N-6 | `pcep_neg_address_family` | IPv4 profile + IPv6 endpoint/ERO | `:781` | `address` |
| N-7 | `pcep_neg_stateful_without_profile` | base profile + `class:"lsp"`+`class:"srp"` | `:758` | `stateful` |

**锚词子串关系实测**：7/7 锚词均为真实文案的子串（`length`/`type`/`object`/`keepalive`/`session`/`address`/`stateful`），非臆造。

**负例原子性**：每例单一故障注入；单次执行不得混注。

## 5. 覆盖与对账

### 5.1 三源回指行

RFC 5440/8231/8281（§10）+ D-PCEP-1（设计 §11）+ tshark 通道实测（`pcep.*` 379 字段已注册 + 存量 24 例真实 pcap 口径）→ 24 ID（本契约 §2）。第三源"已确认现网行为"当前 = **未确认级**（未做现网 PCE 抓包 → G-PCEP-6，按 §5.5 不写死进实现）。

### 5.2 9.52 对账两行 + 清单出处声明

- **清单出处声明**：本清单来源 = **RFC 5440/8231/8281 原文反推 + 仓库落码反推 + tshark 379 字段实测**（非纯旧稿搬运）。
- **对账两行**：**要求逻辑点总数 = 103**（八项 8 行 + 矩阵 24 格 + 变体 36 行 + 商业映射 11 行 + 用例形状 24 点〔每 ID 一点〕）；**用例覆盖数 = 80**（八项 8 + 矩阵已覆 9 + 变体已覆 30 + 商业已覆 8 + 待确认 1 + 形状已覆 24）；**不适用 = 11**（矩阵 10/12 两行 6 格 + 变体 3 项不适用 + 商业 2 不解决）；**缺口/开放 = 15**（矩阵缺口 3 + 矩阵 A′ 立项 6 + 变体缺口 6）。80 + 11 + 15 = 106，比 103 多 3——**恰好 3 处同源点被两表各计一次**：变体 #15（RRO-in-IPv6）↔ 矩阵 A′ 地址族面；变体 #36（外层 IPv6 载体）↔ 矩阵 A′ 地址族面；变体 #26（msg_length 下界）↔ 变体 #24（同属 G-PCEP-5）。106 − 3 = 103 ✓。逐格明细见设计 §10.2–10.4。
  **粒度声明**：行/格粒度每点 1 计；G-PCEP-1…G-PCEP-10 不折进 103。**反查全绿 ≠ 覆盖全**（§9.52 原文）。
- **门3 抽查候选**：最复杂用例 = **#15 `pcep_delegation_rfc8281_profile`**（5 事件 / 12 包，RFC 8281 委托三 flag 分离 + LSP/SRP 双对象 + profile 边界）；交织维度 = 事件(5)×方向(2)×对象类(LSP/SRP)×flag(delegate/remove/create)×profile 门。次选 **#13 `pcep_multi_session`**（两会话整块展开 + SID/request ID 隔离 + 包号起点）。**建议门3 抽 #15 + #13**（覆盖 §9.49 多会话面与 §9.50 复合场景面）。

### 5.3 T-编号与旧 id 对照（设计 §9 全表摘要）

`pcep_open_keepalive` ≡ T-PCEP-S1；`pcep_open_bidirectional` ≡ T-PCEP-S2；`pcep_keepalive_direction` ≡ T-PCEP-S3；`pcep_pcreq_ipv4_ero_metric` ≡ T-PCEP-S4；`pcep_pcrep_ipv4_ero_rro` ≡ T-PCEP-S5；`pcep_pcntf_and_pcerr` ≡ T-PCEP-S6；`pcep_multi_request` ≡ T-PCEP-S7；`pcep_ipv6_address_family` ≡ T-PCEP-S8；`pcep_lsp_object_flags` ≡ T-PCEP-S9；`pcep_rro_ipv4_ipv6` ≡ T-PCEP-S10；`pcep_metric_flags` ≡ T-PCEP-S11；`pcep_tcp_direction` ≡ T-PCEP-S12；`pcep_multi_session` ≡ T-PCEP-S13；`pcep_stateful_rfc8231_profile` ≡ T-PCEP-S14；`pcep_delegation_rfc8281_profile` ≡ T-PCEP-S15；`pcep_common_header_length` ≡ T-PCEP-S16；`pcep_object_flags` ≡ T-PCEP-S17；`pcep_neg_malformed_length` ≡ T-PCEP-N1；`pcep_neg_unknown_type` ≡ T-PCEP-N2；`pcep_neg_object_length` ≡ T-PCEP-N3；`pcep_neg_keepalive` ≡ T-PCEP-N4；`pcep_neg_session_id` ≡ T-PCEP-N5；`pcep_neg_address_family` ≡ T-PCEP-N6；`pcep_neg_stateful_without_profile` ≡ T-PCEP-N7。

## 6. P3 固定动作（CORE_MEMORY 管线：§3.15 三项 + A′/B′ 两分类 + 3.14 豁免）

### 6.1 §3.15 三项逐项一例或立项

| # | 三项 | 本协议对照 | 用例/立项 |
|---|---|---|---|
| ① | 同连接/同流内的多轮操作 | 单 TCP 连接多轮 PCReq→PCRep（#7 两轮）、多轮 Keepalive（#3 四条）、委托三连（#15） | 已覆 #3/#7/#15 |
| ② | 非正常结束 | 正常 FIN 全正例；应用层正常终止报文 = PCErr（#6，**是协议消息不是连接终止**）；网络层异常 = RST | A′ 补例 `pcep_abort_rst`（框架能力，本层零断言）+ 负例 7 条 |
| ③ | 长保活 | PCEP 有 Keepalive **消息**（显式事件 #1/#3），但**无引擎自动周期补发**（设计 §10.1 第 6 项）；长会话 = 同连接多事件 | #3 承载（4 条 Keepalive） |

无空项：① 有已覆例；② 有负例面 + 1 条 A′ 补例；③ 有 #3。

### 6.2 A′/B′ 两分类表

**A′（P4 接线）**：

| 类 | 内容 | 落点 |
|---|---|---|
| 层链化 | registry `Fields` 补 `profile`/`events`/`sessions` 键 + translate 层内严格解码 | G-PCEP-1，用例 #1–#24 全依赖 |
| 端口面 | dst_port 缺省补齐 4189 | `pcep_default_port`（删键不断言值） |
| 游离键面 | 通用五键游离判死（今日已生效） | `pcep_neg_free_key` |
| 地址族面 | RRO-in-IPv6 / 外层 IPv6 载体 | `pcep_rro_ipv6`（G-PCEP-7）/ `pcep_outer_ipv6` |
| 边界精化 | `object_length` 越界相邻值（0/4/5/65535）、`msg_length` 下界（3/4）、SID 上界 255 | `pcep_neg_object_length_boundary`（G-PCEP-5）/ `pcep_sid_max` |
| 未知类面 | 未知 object class（`builder.go:615` 分支无例） | A′ 候选 |
| 非正常结束 | `tcp.rst` 补例 | `pcep_abort_rst` |
| 命名修正 | `pcep_neg_session_id` → `pcep_neg_open_sid_zero`（G-PCEP-9） | 三处同步改名 |

**B′（框架面）**：`CheckProtoFlat` pcep presence 分支（G-PCEP-2，等框架级 unknown-key 白名单，不单独立项）/ 业务字段动态（G-PCEP-3，allowlist 无 `pcep` 行）/ `PCEPConfig.Transport` 死键（G-PCEP-4，P4 删键）/ PCUpd/PCInitiate（G-PCEP-6，明确不解决 + 迁入计划）。进设计 §14，用例侧 N 系列钉现状。

### 6.3 3.14 豁免边界审计

**有长连接载体 → `sessions[]` 不豁免**（设计 §12.3 会话表 s1/s2；多会话展开 #13）；多流并发 = **不适用**（PCEP 单连接内无并发流语义，`sessions[]` 是独立连接不是会话内多流，如实声明）；单包多载荷 = **已覆**（#4/#5/#9/#15 单消息多对象：RP+endpoint+ero+metric、lsp+srp）。

## 7. 实现后执行建议

1. **代码阶段（P4）顺序**：G-PCEP-1（registry `Fields` + `translateTerminalConfig` case + `mapToFlowSpec` 收敛 + schemagen 重跑）→ 存量 24 例改写（删顶层五键，顶层 `pcep` 子映射迁层内）→ 先跑后钉 24 例 → 补 A′ 例 → 全量复跑。
2. **实测顺序**：先 #1/#16（Open 长度 12 与 10 包基线），再 #15（委托三 flag，重钉 5/12），再 #13（多会话包号起点），再 #8（IPv6 语义例 offset 仍 54），最后 #4（双 RP 形状的 `requested_id_number` 重复聚合条目）。
3. 二进制与 HEAD 同代确认（门2③：`find trafficgen -name '*.go' -newer <server-binary>` 无输出）；门2② 全量（`CASE_PROTO=pcep` 全量不是增量）；门2④ 反查绿后进 P6。
4. 任何 Open 长度/包数断言须先跑后钉（设计 §0 行 5/行 6 已证旧稿常量有误）。

## 8. 存量审计（24 例逐条去向）

### 8.1 存量实测面（2026-09-28）

`cases/pcep.json` **24 例**：17 正带 `packet_count`（10/11/13/11/11/13/14/11/11/11/11/12/22/10/12/11/10，全符合 `3+N+4` 公式：17/17 逐行校验通过）；7 负 `expect` 键集合严格 `{expect_error,error_contains}`；顶层键 24/24 含五键残留（`src_ip`/`dst_ip`/`dst_port` 各 24、`src_port` 23、`pcep` 子映射 24）；层内非空配置 **0/24**；`frames` offset 全 54；**39** 个去重 `pcep.*` 字段 + 2 个 `tcp.*` 字段全部实测已注册。

### 8.2 现状矛盾点（P4 前诚实登记）

1. **存量跑的是违规过渡形，且今日 400 全红（审计主结论）**：按"非负例顶层键必须为 0"判据，24/24 例**全部违规**——非负例 84 处残留（`src_ip`/`dst_ip`/`dst_port` 各 17、`src_port` 16、顶层 `pcep` 子映射 17），全 24 例 119 处。更关键：**存量 24 例今日 create 400 全红**（五键在即被 `CheckProtoFlat` `:8632` 拒），**无一条可创建、断言无一条"今日有效"**。`layers=[{tcp:{}},{pcep:{}}]` 只是**空壳**（层内恒 `{}`，`translateTerminalConfig` 无 `case "pcep"` → 既不校验也不解码），真实配置住顶层 `pcep` 子映射 + 顶层四元组。**去五键即可用**（四形实测表 §1 第 2/3 行），但那是"能跑"不是"合规"。合规化须代码阶段补 registry `Fields` + translate case + `mapToFlowSpec` 收敛（G-PCEP-1），文档阶段改不动。
2. **#15 包数旧稿偏差**：旧稿 design §8 与 testcase §2 均写 3 events / 10 packets，实测 **5 / 12**（漏计两条 Open）。包数断言以实测为准，P4 不改包数。
3. **#10 名不副实**：`pcep_rro_ipv4_ipv6` 实测为单 IPv4 profile 例，无 IPv6 半边（G-PCEP-7）。
4. **#22 名不副实**：`pcep_neg_session_id` 实际注入 `sid:0` 而非 SID 漂移（G-PCEP-9）。
5. **结果文档过期（G-PCEP-11）**：`trafficgen/docs/protocol-pcap-test/pcep.md` 写 "24 — pass 24"，但末次提交 `e60f8de`（2026-08-30）早于判死提交 `0417be5`（2026-09-13）两周；`cases/pcep.json` 末改 `07a5472` 同日；`docs/protocol-pcap-test/pcep/` **0 个 pcap**。该 24/24 pass **是过期产物，不代表今日可跑**。
6. **存量未覆盖精确边界**：`object_length` 边界相邻值 / 缺省端口 / RRO-in-IPv6 / 外层 IPv6 载体 / SID 上界 / 未知 object class **今日零用例**（A′ 补）。

### 8.3 逐条去向表（24 行）

| 存量 id | T-编号 | 去向 | 改写动作（G-PCEP-1 落地时） |
|---|---|---|---|
| `pcep_open_keepalive` | T-PCEP-S1 | **改写** | 目标形状化（`ip` 层地址 + `tcp` 层端口 + `pcep` 层 events）；packet_count 10 不变 |
| `pcep_open_bidirectional` | T-PCEP-S2 | **改写** | 同上；11 不变 |
| `pcep_keepalive_direction` | T-PCEP-S3 | **改写** | 同上；13 不变 |
| `pcep_pcreq_ipv4_ero_metric` | T-PCEP-S4 | **改写** | 同上；11 不变；双 RP 形状（`requested_id_number` 重复聚合条目）先跑后钉 |
| `pcep_pcrep_ipv4_ero_rro` | T-PCEP-S5 | **改写** | 同上；11 不变 |
| `pcep_pcntf_and_pcerr` | T-PCEP-S6 | **改写** | 同上；13 不变 |
| `pcep_multi_request` | T-PCEP-S7 | **改写** | 同上；14 不变 |
| `pcep_ipv6_address_family` | T-PCEP-S8 | **改写** | 地址迁 `ip` 层（仍 IPv4 载体）；offset 54 不变 |
| `pcep_lsp_object_flags` | T-PCEP-S9 | **改写** | 同上；11 不变 |
| `pcep_rro_ipv4_ipv6` | T-PCEP-S10 | **改写** | 同上；**改名或补 IPv6 半边**（G-PCEP-7） |
| `pcep_metric_flags` | T-PCEP-S11 | **改写** | 同上；11 不变 |
| `pcep_tcp_direction` | T-PCEP-S12 | **改写** | 同上；12 不变 |
| `pcep_multi_session` | T-PCEP-S13 | **改写** | `sessions[]` 迁层内；`src_port` 留 `sessions[].src_port`；22 不变 |
| `pcep_stateful_rfc8231_profile` | T-PCEP-S14 | **改写** | 同上；10 不变 |
| `pcep_delegation_rfc8281_profile` | T-PCEP-S15 | **改写** | 同上；**12 为准**（旧稿 10 错） |
| `pcep_common_header_length` | T-PCEP-S16 | **改写** | 同上；11 不变；Open hex `20 01 00 0c` 为准 |
| `pcep_object_flags` | T-PCEP-S17 | **改写** | 同上；10 不变；`1,0` 聚合值复核 |
| `pcep_neg_malformed_length` | T-PCEP-N1 | **改写** | `pcep` 子映射迁层内；锚词 `length` 不变 |
| `pcep_neg_unknown_type` | T-PCEP-N2 | **改写** | 同上；`type` 不变 |
| `pcep_neg_object_length` | T-PCEP-N3 | **改写** | 同上；`object` 不变 |
| `pcep_neg_keepalive` | T-PCEP-N4 | **改写** | 同上；`keepalive` 不变 |
| `pcep_neg_session_id` | T-PCEP-N5 | **改写 + 改名** | `session` 不变；改名 `pcep_neg_open_sid_zero`（G-PCEP-9） |
| `pcep_neg_address_family` | T-PCEP-N6 | **改写** | 同上；`address` 不变 |
| `pcep_neg_stateful_without_profile` | T-PCEP-N7 | **改写** | 同上；`stateful` 不变 |

无"作废不注原因"：0 作废，0 等价覆盖（24/24 改写 + A′ 新增）。

## 9. 覆盖反查门建议断言行（供主线程合后登记；本车道不碰 `coverage_gate.py`）

以下为 pcep 协议建议登记进覆盖反查门的条目清单。**登记动作由主线程执行**，本车道只给建议；每条均可由 `cases/pcep.json` 静态机读判定（不需要跑 suite）。

| # | 建议断言 | 判定方式（静态机读） | 现状 |
|---:|---|---|---|
| G1 | 非负例用例顶层 `spec_json` 键 = 0（五键 + `pcep` 子映射全清） | `spec_json.keys()` ⊆ 白名单（layers/strategy_fc/ttl/flow_control/output/output_config/group_id） | ❌ **非负例 84 处残留 / 17 例全违规**（代码阶段收敛后应变 ✅） |
| G2 | 层链含 `pcep` 且 `pcep` 层配置非空 | `layers` 内 `pcep` 值 != `{}` | ❌ 0/24（层内空壳；代码阶段收敛后应变 ✅） |
| G3 | `tcp.dst_port` 住 `tcp` 层或显式缺省补齐 | `layers[tcp]` 含 `dst_port` 或全缺（走 4189 缺省） | ❌ 住顶层（代码阶段收敛后 ✅） |
| G4 | 24 个 ID 集合与顺序 = 本契约 §2 表 | 逐 ID 比对 | ✅ |
| G5 | 17 正例 `packet_count` = `3 + len(events) + 4`（多会话按会话求和） | 机读重算 | ✅ 17/17 |
| G6 | 7 负例 `expect` 键集合严格 = `{expect_error, error_contains}` | 键集合比对 | ✅ 7/7 |
| G7 | 7 负例 `error_contains` 非空且 ∈ 设计 §7 锚词集 | 锚词集合 ∈ {length,type,object,keepalive,session,address,stateful} | ✅ 7/7 |
| G8 | 正例 fields 的 `pcep.*` 字段全部已注册 | `tshark -G fields` 前缀集合包含（`pcep.*` 注册 379；JSON 去重 39 + `tcp.*` 2） | ✅ **39/39** |
| G9 | 正例 frames offset 全 = 54（外层 IPv4 载体） | offset 集合 = {54} | ✅ 24/24 |
| G10 | `frames.hex` 的 Open 前缀 = `20 01 00 0c`（长度 12） | 前缀比对 | ✅（旧稿 `0x10` 已校正） |
| G11 | 无 PCUpd/PCInitiate 正例（G-PCEP-6 未实现） | 正例中无 `kind` 映射到 type 10/12 | ✅ |
| G12 | `class:"notification"`/`"error"` 只出现在 `pcntf`/`pcerr` 事件内，其余 kind 的 `objects[]` 不得携带 | 机读 (kind, objects[].class) 对 | ✅（`notification` 仅 pcntf、`error` 仅 pcerr） |
| G13 | 业务字段动态对象零出现（G-PCEP-3） | `pcep` 层内无 `{"strategy": …}` 形值 | ✅ |
| G14 | 多会话例 `sessions[].src_port` 非零且互异 | 机读 | ✅（40001/40002） |

**门2 关系**：G1–G3 是门2①（顶层旧键零残留）的协议级细化；G5–G7 是门2②（全量绿 + 负例锚词）的静态前置；G8 是"断言可执行"（§7）的静态前置。**建议 G1/G2/G3 保持红并登记为已知缺口**（勿白名单豁免——CORE_MEMORY §1.12/§1.13）；转绿条件是代码阶段补齐 registry `Fields` + `translateTerminalConfig` case + `mapToFlowSpec` 收敛。**另注意**：`docs/protocol-pcap-test/pcep.md` 的 24/24 pass 是过期产物（G-PCEP-11），不得作为"套件可跑"依据。

## 10. 修订记录

- v1.0.0（2026-09-28）：P-PIPE #98 文档轨 P1–P3。旧稿 42-* 24 ID / packet_count / 锚词全量继承（思路参考不搬码）；三处旧稿偏差机读校正（#15 3/10→5/12、Open 长度 `0x10`→`0x0c`、#22 SID 漂移→`sid:0`）；新增形状基线机读实测（§1）、P3 固定动作（§6）、执行建议（§7）、存量审计（§8，24/24 改写）、覆盖反查门建议断言行（§9，14 条）。P3 自审 2 轮，末轮干净（结论见 `/tmp/pipe/doc-lanes/pcep.md` §2）。
