# #129 wireguard（WireGuard）测试用例契约

> 版本：v1.0.0（P-PIPE 文档轨 P1–P3 首版）
> 日期：2026-09-29
> 配套设计：`docs/protocol-designs/129-wireguard-design.md` v1.0.0（D-WIREGUARD-1）
> 机器契约：`trafficgen/test/protocol_pcap/cases/wireguard.json`（当前仅 1 例，ID 顺序以 JSON 为准）
> 白话一句：**先钉 UDP 承载的四类定长消息、索引、计数器和内层包，再把校验拒绝和层链缺口分开；目标 ID 是施工清单，不把占位登记冒充为今日通过。**

## 1. 测试原则和形状基线

本契约由设计 §2–§9 的字段、事件、错误分支和五层场景反推。一个 ID 只验证一个主行为；同一行为需要多个方向、角色或边界时拆成独立 ID。WireGuard 消息长度是强制断言面：Initiation=148、Response=92、Cookie Reply=64、Transport Data=32+N；无 VLAN/IP options 时，IPv4 WireGuard 起点为 frame offset 42，IPv6 为 62。

**当前 JSON 基线（机读）**：`cases/wireguard.json` 只有 `wireguard_smoke_01` 1 例，顺序唯一；`spec_json` 顶层键为 `src_ip,dst_ip,count,wireguard`，无 `layers`，因此命中 `CheckProtoFlat` 后今日不可创建。其 `expect.packet_count=3`，9 条 `fields` 断言和 3 条 `notes` 与离线生产管线输出一致，但不能据此报告套件已通过。存量去向见 §8。

**目标 JSON 基线**：P4 层内化后，非负例顶层只能有 `layers`（数量/流数走 `flow_control`）；目标 ID 表的 54 行是登记契约，不是当前 cases JSON 的 54 行。X01/X02 是通用形状缺口，在今日缺少判死门时不可建。

**输出契约**：pcap 与 NIC 两路复用同一 cases 断言；字段优先用 `udp.dstport/srcport`、`wg.type/sender/receiver/counter/reserved`，不可把伪随机密文误当作解密字段。失败必须传播为 task error，不得产生 `completed/0 packet` 假成功。

## 2. 原子用例索引

### 2.1 存量 JSON（权威顺序，1 例）

| # | ID | 类型 | 依据链 | packet_count | 断言摘要 |
|---:|---|---|---|---:|---|
| 1 | `wireguard_smoke_01` | 正（**现状判死，待改写**） | 设计 §2/§3.1–3.5；当前 flat spec | 3（JSON） | pkt1 UDP dst 51820/type1/sender1；pkt2 type2/sender2/receiver1；pkt3 type4/receiver2/counter0 |

该行与 JSON 逐字段一致。它只能作为历史形状审计，改写成目标层链后对应 W01；在改写前不计入“今日已绿”。

### 2.2 目标完整索引（54 ID = 36 正 + 16 负 + 2 形状负例）

包数是设计 §5.1 公式：initiator `2+N+K+2×R`；responder `1+N+K+2×R+C`；`handshake=false` 为 `N+K`。`—` 表示负例预期零帧，不是缺少断言。**今日可达性只表示施工阶段的真实边界，不表示已有 JSON。**

| # | ID | 类型 | 场景/依据链 | 今日可达性 | 包数 |
|---:|---|---|---|---|---:|
| W01 | `wg_smoke_default` | 正 | §5.1 默认 Init→Resp→Data；存量改写目标 | 可跑（层链空 config） | 3 |
| W02 | `wg_port_default` | 正 | §2 缺省 dst=51820 | 可跑 | 3 |
| W03 | `wg_port_custom` | 正 | §8 非默认 UDP 端口 | 可跑 | 3 |
| W04 | `wg_src_port_custom` | 正 | §2 显式源端口 | 可跑 | 3 |
| W05 | `wg_ipv6_carrier` | 正 | §2 IPv6 offset 62、帧 210/154/95 | 可跑 | 3 |
| W06 | `wg_init_struct` | 正 | §3.2 type1 148B 字段/偏移 | 可跑 | 3 |
| W07 | `wg_init_sender_auto` | 正 | §3.2 sender 0→1 | 待 A′ | 3 |
| W08 | `wg_init_sender_42` | 正 | §3.2 sender=42 LE | 待 A′ | 3 |
| W09 | `wg_resp_struct` | 正 | §3.3 type2 92B 字段/偏移 | 可跑（默认流内） | 3 |
| W10 | `wg_mac2_zero` | 正 | §3.2 无 cookie，mac2 全零 | 可跑（默认流内） | 3 |
| W11 | `wg_mac2_cookie` | 正 | §3.2 16B cookie，mac2 非零 | 待 A′ | 3 |
| W12 | `wg_role_responder` | 正 | §5.3 responder 序及 receiver=3 | 待 A′ | 2 |
| W13 | `wg_cookie_reply` | 正 | §3.4 type3 64B 帧序 | 待 A′ | 3 |
| W14 | `wg_dir_up` | 正 | §5.3 direction=up | 待 A′ | 3 |
| W15 | `wg_dir_down` | 正 | §5.3 direction=down | 待 A′ | 3 |
| W16 | `wg_dir_both` | 正 | §5.3 偶 up/奇 down | 待 A′ | 4 |
| W17 | `wg_data_struct` | 正 | §3.5 receiver/counter=0 | 可跑（默认流内） | 3 |
| W18 | `wg_data_multi` | 正 | §3.5 N=3，counter 0/1/2 | 待 A′ | 5 |
| W19 | `wg_counter_start100` | 正 | §3.5 InitialCounter=100 | 待 A′ | 3 |
| W20 | `wg_keepalive` | 正 | §3.5 N=0，追加 32B data | 待 A′ | 4 |
| W21 | `wg_keepalive_seq` | 正 | §5.1 keepalive 方向/帧位 | 待 A′ | 4 |
| W22 | `wg_rekey` | 正 | §5.1 threshold=3，插入 Init+Resp | 待 A′ | 8 |
| W23 | `wg_rekey_reset` | 正 | §5.1 counter 归零、旧 receiver 注记 | 待 A′ | 8 |
| W24 | `wg_payload_verbatim` | 正 | §0.1 payload 明文直写边界 | 待 A′ | 3 |
| W25 | `wg_tag16` | 正 | §3.5 固定 16B tag/长度 | 可跑（默认流内） | 3 |
| W26 | `wg_inner_udp4` | 正 | §3.6 IPv4/UDP，UDP v4 checksum=0 | 待 A′ | 3 |
| W27 | `wg_inner_tcp4` | 正 | §3.6 IPv4/TCP checksum | 待 A′ | 3 |
| W28 | `wg_inner_icmp4` | 正 | §3.6 IPv4/ICMP echo | 待 A′ | 3 |
| W29 | `wg_inner_udp6` | 正 | §3.6 IPv6/UDP 必算 checksum | 待 A′ | 3 |
| W30 | `wg_inner_frames2` | 正 | §3.6 DataFrames=2，IPID=1/2 | 待 A′ | 4 |
| W31 | `wg_inner_df` | 正 | §3.6 IPv4 DF=0x4000 | 待 A′ | 3 |
| W32 | `wg_deterministic` | 正 | §0.1 两次生成字节相同 | 可跑（离线） | 3 |
| W33 | `wg_filesource` | 正 | §5.2 FileSource 优先级 | C 类，需 PayloadCache | 3 |
| W34 | `wg_dyn_udp_port` | 正 | §12 动态源端口，flows=3 | 可建 | 9 |
| W35 | `wg_dyn_ip_addr` | 正 | §12 动态合法 IP 端点 | 可建 | 9 |
| W36 | `wg_flows3` | 正 | §12 三流保底递增 | 可建 | 9 |
| N01 | `wg_neg_role` | 负 | §7 V-3 Role 锚词 | 待 A′ | — |
| N02 | `wg_neg_direction` | 负 | §7 V-4 Direction 锚词 | 待 A′ | — |
| N03 | `wg_neg_key_local` | 负 | §7 V-5 LocalStaticPubKey | 待 A′ | — |
| N04 | `wg_neg_key_peer` | 负 | §7 V-6 PeerStaticPubKey | 待 A′ | — |
| N05 | `wg_neg_key_eph` | 负 | §7 V-7 LocalEphemeralPubKey | 待 A′ | — |
| N06 | `wg_neg_psk` | 负 | §7 V-8 PSK | 待 A′ | — |
| N07 | `wg_neg_cookie` | 负 | §7 V-9 Cookie 长度 | 待 A′ | — |
| N08 | `wg_neg_rekey` | 负 | §7 V-10 RekeyAfter | 待 A′ | — |
| N09 | `wg_neg_keepalive` | 负 | §7 V-11 KeepaliveInterval | 待 A′ | — |
| N10 | `wg_neg_payload_mtu` | 负 | §7 V-12 payload >1440 | 待 A′ | — |
| N11 | `wg_neg_inner_src` | 负 | §7 V-14 Inner SrcIP | 待 A′ | — |
| N12 | `wg_neg_inner_mixed` | 负 | §7 V-14 v4/v6 混族 | 待 A′ | — |
| N13 | `wg_neg_inner_proto` | 负 | §7 V-14 Proto=99 | 待 A′ | — |
| N14 | `wg_neg_inner_frames` | 负 | §7 V-14 DataFrames<0 | 待 A′ | — |
| N15 | `wg_neg_inner_mtu` | 负 | §7 V-14 内层超 MTU | 待 A′ | — |
| N16 | `wg_neg_invalid_dst` | 负 | §7 V-2 的 ip 层 `invalid IP endpoint` | 可建（ip 层门） | — |
| X01 | `wg_neg_presence` | 形状负 | §12-P2 layers + 顶层 wireguard 并存 | **不可建**：今日不拒 | — |
| X02 | `wg_neg_stray_topkey` | 形状负 | §12-P2 游离顶层键 | **不可建**：通用门缺失 | — |

重数：54 = 36 + 16 + 2。今日合规可达 15（W01–W06、W09、W10、W17、W25、W32、W34–W36、N16）；待 A′ 36；C 类 W33 1；X01/X02 2。目标行不改变当前 JSON 的 1/1 事实。

## 3. 正例逐项断言契约

每个正例必须至少有 `packet_count`、UDP 端口、消息 type/索引或场景特有字段；固定长度和 offset 必须能由 frames 或 tshark 字段复核。伪随机字段只断言长度/确定性，不断言真实密文内容。

| ID 组 | 最低断言 |
|---|---|
| W01–W06 | `packet_count=3`；type `1,2,4`；sender `1,2`；Response receiver `1`；Data receiver `2`、counter `0`；IPv4/IPv6 frame offset 分别 42/62；消息长度 148/92/33。W02 另断言缺省 dst=51820，W03/W04 断言端口，W05 断言 IPv6 帧长 210/154/95。 |
| W07–W13 | Init sender 自动/42；Response 92B；mac2 无 cookie 全零、有 cookie 非零；responder 不产生 Init、Response receiver=3；CookieReply type3、64B、receiver=3，序在 Response 后。 |
| W14–W25 | direction 的帧方向；多 payload counter 连续；keepalive 为 32B 消息且追加 1 包；rekey 包数/插入位置/重置 counter；payload 原文可读；tag 恰 16B；rekey 后旧 receiver 必按 as-built 断言并标注 G-WIREGUARD-8。 |
| W26–W31 | Transport payload 内完整 inner IP；IPv4 IPID/DF/TTL/校验和；TCP/UDP/ICMP L4；IPv6 UDP checksum；两帧 IPID=1/2；inner length 不超过 1440。单内层帧为 3 包（Init+Resp+Data），W30 两帧为 4 包。 |
| W32–W36 | 两次独立生成字节完全相同；FileSource 优先级；动态端口/IP 值按策略序列；三流 packet_count=9 且每流 3 包。 |

**包数核对**：W01/W02/W03/W04/W05/W06/W07/W08/W09/W10/W11/W14/W15/W17/W19/W24/W25/W26/W27/W28/W29/W31/W32/W33 = 3；W12=2；W13/W16/W18/W20/W21=分别按表中 N/K/C 公式（W20/W21=4，W16=4，W18=5）；W22/W23=8；W30=4；W34–W36=9。实现阶段必须以实际 pcap 重钉，不得只相信登记表。

## 4. 负例契约

每个 N ID 必须在 validator/planner 或其明确的 ip 层边界失败，`expect_error` 为真、`error_contains` 为锚词子串、成功帧数为 0。以下 16 个锚词与设计 §7 同序：

| ID | `error_contains`（逐字锚词） | 触发 |
|---|---|---|
| N01 | `Role must be initiator or responder` | role 非法 |
| N02 | `Direction must be up, down, or both` | direction 非法 |
| N03 | `LocalStaticPubKey must be 32 bytes` | local static 长度 |
| N04 | `PeerStaticPubKey must be 32 bytes` | peer static 长度 |
| N05 | `LocalEphemeralPubKey must be 32 bytes` | ephemeral 长度 |
| N06 | `PSK must be 32 bytes` | PSK 长度 |
| N07 | `Cookie must be 16 bytes` | cookie 长度 |
| N08 | `RekeyAfter too large` | threshold ≥2^60 |
| N09 | `KeepaliveInterval must be >= 0` | interval<0 |
| N10 | `Transport payload` | 单 payload >1440 |
| N11 | `SrcIP` | inner 源地址非法 |
| N12 | `same address family` | inner v4/v6 混族 |
| N13 | `Proto` | inner proto=99 |
| N14 | `DataFrames` | inner frames<0 |
| N15 | `built inner packet` | inner 超 MTU |
| N16 | `invalid IP endpoint` | 外层 ip 层目的地址非法 |

N01–N15 今日层内业务字段会先命中 unknown field，故均标待 A′，不报告为已绿。N16 是 ip 层已有边界可建。V-1 的 SrcIP 变体同属外层 ip 层门，但本版只登记 N16，避免把一个锚词变体重复计数。

## 5. 覆盖与对账

### 5.1 三源回指

规范源为 WireGuard protocol/Whitepaper 与 RFC 8439/7748/7693 的长度/密码学语义；实现源为 `internal/protocol/wireguard/planner.go`、`layer_gen.go`、registry、translate 和 strategy convert；行为源为 15 组离线生产管线 pcap + tshark 3.6.14。当前 cases JSON 只有 §2.1 的 1 例，不能用目标索引冒充已落地覆盖。

### 5.2 两行对账

- **要求逻辑点总数 = 54 个原子目标 ID + 26 个设计变体行 + 12 个消息终态格 + 14 个 validator 锚词组 + 5 个动态字段面 = 111 点。**
- **当前落地覆盖 = 1 个 JSON 历史形状 ID + 15 个今日合规可达目标点；开放/待 A′ = 95 点（按 111 个唯一逻辑点扣除 16 个当前落地点计算；设计变体、终态、动态面与 ID 交叉引用不重复计数）。**

粒度声明：ID/变体/终态/动态按行或格计；同一 ID 对多个设计行只在所属表计一次，交叉引用不重复计数；“当前落地”不等于 MCP 通过，存量 1 例因 flat 判死明确不算今日行为绿。

## 6. P3 固定动作

### 6.1 §3.15 三项

| 固定动作 | 本协议落点 | 状态 |
|---|---|---|
| 同流多轮操作 | W18 多 payload、W22 rekey 后继续 Data | 待 A′ |
| 非正常结束 | UDP 无 FIN/RST；配置拒绝 N01–N16 作为失败终止 | 负例待 A′；不造 TCP 终止断言 |
| 长保活 | W20/W21 仅验证实现追加的单个 keepalive，周期化明确不适用 | 待 A′ |

### 6.2 A′/B′ 两分类

| 分类 | 项目 | 归属 |
|---|---|---|
| A′ 协议/接线 | registry Fields + translate case；存量 flat 改层链；handshake/response 解析；N01–N15；inner IP；Cookie/rekey | G-WIREGUARD-2/3/6/8 |
| B′ 框架/门 | presence 与游离顶层键通用判死；wireguard 业务动态 allowlist；离线 chain suite 纳入；过期结果文档重跑 | G-WIREGUARD-1/4/5/7/9 |

### 6.3 3.14 豁免审计

WireGuard 为 UDP 单五元组，`sessions[]` 和“控制流派生数据流”不适用；rekey 只是同一隧道索引换代，不扩写为多会话。`flow_control.flows` 只表达并发多流，W34–W36 单独覆盖。keepalive 周期和真实 Noise 密码学属于显式不解决边界。

## 7. 实现后执行建议

1. P4 先登记 wireguard 层字段、增加 translate 分支并导出单一解析函数，再将 `wireguard_smoke_01` 改写为 `[ip,udp,wireguard]`，重跑 W01。
2. 随后按 W06→W12/W13→W18/W20→W22→W26–W31→W34–W36 顺序落例；每批同时跑对应 N 负例，失败必须是 task error + 0 帧。
3. 用 tshark `wg`（不是 `wireguard`）读取字段；非 51820 W03 需单独确认启发式解码。真实密码学字段不加入断言。
4. P5 重跑 pcap/NIC 双路径并重生成过期 `docs/protocol-pcap-test/wireguard.md`；在此之前不得引用旧的 “1 pass”。

## 8. 存量审计

| ID | 当前去向 | 原因与 P4 动作 |
|---|---|---|
| `wireguard_smoke_01` | **改写**为 W01 | 当前 `src_ip/dst_ip/count/wireguard` flat 形命中 `CheckProtoFlat`，今日不可创建；保留其 3 包、9 条字段断言语义，迁为顶层仅 `layers`，并在层内化后重跑。 |

不得将该例当前 JSON 的 `packet_count=3` 计入今日通过；它是“断言已由离线生产管线核实、fixture 形状已过期”的历史事实。

## 9. 覆盖反查门建议断言行

供主线程合并时登记到 `coverage_gate.py`，本车道不修改该文件：

1. 当前阶段 `len(cases["wireguard"]) == 1` 且 ID 顺序为 `["wireguard_smoke_01"]`；P4 后目标 ID 集按 §2.2 扩展，顺序保持表序。
2. 存量例在 P4 前 `spec_json` 顶层含 `src_ip/dst_ip/count`，必须被标为 rewrite；P4 后非负例顶层游离键计数为 0。
3. W01 正例 `packet_count=3`，字段集合至少包含 9 条 JSON 存量断言；三帧 type 为 `1,2,4`，sender/receiver/counter 与 §2.1 一致。
4. 正例消息长度满足 type1=148、type2=92、type3=64、type4=32+N；IPv4/IPv6 起点分别 42/62。
5. 负例 `error_contains` 必须属于 §4 的 16 个锚词，且错误用例不得有成功 packet_count。
6. W34–W36 flows=3 的聚合 packet_count 必须为 9，端口/IP 序列按 dynamic strategy 生成而非硬编码单值。
7. X01/X02 在通用 presence/unknown-key 门落地前不得进入 cases；不得以“通过”计数。
8. 过期结果文档的 pass 数不得作为今日复跑证据；必须存在对应 pcap 或明确 error 状态。

## 10. 修订记录

- v1.0.0（2026-09-29）：P-PIPE #129 首版。按现状 JSON 机读登记 1 例；建立 54 ID（36 正 + 16 负 + 2 形状负例）逐 ID 索引；固定四类消息长度、IPv4/IPv6 offset、三类 packet_count 公式；负例锚词与设计 §7 同序；存量例改写去向、A′/B′、3.15 与 3.14 审计、覆盖反查建议行齐备。**自审 1 轮，末轮干净。**
