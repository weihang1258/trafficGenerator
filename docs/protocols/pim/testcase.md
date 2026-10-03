# PIM（协议无关组播，Protocol Independent Multicast）测试用例设计

> 版本：v2.0.0（P3 完整产物）
> 日期：2026-09-26
> 配套设计：`docs/protocols/pim/design.md` v2.1.0（D-PIM-1 静态契约）
> 机器契约：`trafficgen/test/protocol_pcap/cases/pim.json`（28 例；严格层链 `[ip,pim]`，地址/TTL/业务均在对应层，数量在正例 `strategy_fc`）
> 状态：`pim` 层已注册、builder/planner/generator 已落码（`registry.go:896`，`internal/protocol/pim/` 四文件 1611 行，34 个单元测试函数），24 个历史语义例已按 §5 去向表迁移并新增 4 个链级/白名单负例；本批完成静态文档与用例形状闭环，不宣称当前 suite 可运行。

## 1. 测试原则

用例由设计 §1–§8 逐项派生，共 28 个唯一 ID，正例 17 个、负例 11 个，顺序与设计 §8 及 JSON 完全一致。每个正例都断言 `packet_count`、`fields` 和 `frames`，并观察 IPv4 Protocol=103、PIM Type 及 checksum 存在性。无 IPv4 options、无 VLAN 的正例中 PIM 起点固定为 offset 34（26 帧全 offset 34 单档，存量实测）；checksum 字节不在 `frames.hex` 中固化，改由 `fields.nonzero=true` 观察并由实现单测做 one's-complement 逐字节复算（Register 仅 8 字节前缀面，design §10 裁定）。

- 每个正例都有 `packet_count`、非空 `fields`、非空 `frames`、`has_payload=true`（实测 17/17 四项齐全）；`directional` 15 例 `false` + 2 例 `true`（仅 `#13` DR election 3 包与 `#14` 多邻居 6 包为 `true`）。
- 字段全部来自 `tshark -G fields` 已注册的 `pim.*` / `ip.*`；不写未经独立复算的固定 checksum 十六进制值。
- frames 只用可复算前缀（Version/Type 组合字节 `20/21/22/23/24/25/28 00` 七类）；运行时随机/长度校验字段不进 frames。
- 每个负例的 `expect` 恰有两个键：`expect_error` 与 `error_contains`；无 `packet_count`/`fields`/`frames`（实测 11/11 合规）。
- 本协议无端口、无握手：`has_handshake` 零出现（实测 0/28），不虚构建连包数；`notes` 0/28。
- 多包事件例（#7/#13/#14/#17）按事件序断言 packet 1..N；重传（#7）第二包重断言 type/neighbor/group/source，不假设隐式序号。
- **严格解码边界（静态现状）**：`pim` 子映射经 `parseSubconfigJSON`（`strategy_convert_helpers.go:21-30`）用**普通 `json.Unmarshal`（无 `DisallowUnknownFields`）** 解码——未知键被静默忽略、不进 `ValidationErrors`。因此负例不得依赖“未知键被拒”，必须依赖 planner/层链语义校验（11 个负例锚词逐字见 §4）。严格解码缺口登记为 G-PIM-4，不在本批改 Go。
- 28 个例中 17 个正例都有 `strategy_fc`（`flows` 等于 `packet_count`），4 个链级负例与 7 个协议负例均无成功包数。

## 2. 原子用例索引（与设计、JSON 同序）

| # | ID | 类型 | 覆盖 | packet_count |
|---:|---|---|---|---:|
| 1 | `pim_sm_hello_holdtime` | 正 | Hello、Holdtime 105、Version 2、checksum | 1 |
| 2 | `pim_sm_hello_options` | 正 | LAN Prune Delay（T/propagation/override）、DR priority、Generation ID | 1 |
| 3 | `pim_sm_hello_zero_holdtime` | 正 | Holdtime=0 即时失效边界 | 1 |
| 4 | `pim_sm_joinprune_wildcard` | 正 | `(*,G)` 通配、上游邻居、numgroups/numjoins/numprunes | 1 |
| 5 | `pim_sm_joinprune_source` | 正 | `(S,G)` 具体源、joined+pruned 双列表 | 1 |
| 6 | `pim_sm_joinprune_multi_group` | 正 | 双 group（`(*,G)`+`(S,G)`）、各自 source 列表 | 1 |
| 7 | `pim_sm_joinprune_retransmit` | 正 | 显式重传 2 包、无隐式序号 | 2 |
| 8 | `pim_sm_bootstrap_rp_set` | 正 | BSR、bsr_priority、hash_mask_len、双 RP | 1 |
| 9 | `pim_sm_candidate_rp_adv` | 正 | C-RP、priority、Holdtime、prefix_count=2 | 1 |
| 10 | `pim_sm_register` | 正 | Register flags（border/null=0）、inner IPv4 | 1 |
| 11 | `pim_sm_register_stop` | 正 | Register-Stop 显式 group/source | 1 |
| 12 | `pim_sm_assert` | 正 | Assert RPT + metric_pref + metric | 1 |
| 13 | `pim_sm_dr_election` | 正 | 三邻居 Hello、DR priority tie-break（`directional=true`） | 3 |
| 14 | `pim_sm_multi_neighbor_state` | 正 | 双邻居×双组 6 包隔离（`directional=true`） | 6 |
| 15 | `pim_sm_checksum_length` | 正 | checksum nonzero + `ip.len` 存在性 | 1 |
| 16 | `pim_ssm_joinprune_sg` | 正 | SSM 具体 `(S,G)`、无 RP | 1 |
| 17 | `pim_ssm_multi_group` | 正 | SSM 双 `(S,G)` 事件 2 包 | 2 |
| 18 | `pim_neg_ipv6_profile` | 负 | IPv6 profile 明确拒绝 | — |
| 19 | `pim_neg_checksum` | 负 | checksum 错误注入拒 | — |
| 20 | `pim_neg_length` | 负 | length 错误注入拒 | — |
| 21 | `pim_neg_type` | 负 | type 错误注入拒 | — |
| 22 | `pim_neg_address_family` | 负 | IPv4 profile 配 v6 组/源 | — |
| 23 | `pim_neg_ssm_rp` | 负 | SSM 带 Register 拒 | — |
| 24 | `pim_neg_df_profile` | 负 | DF Election 混入 SM 拒 | — |
| 25 | `pim_neg_top_pim_presence_reject` | 负 | 层链 + 顶层空 `pim:{}` 并存判死 | — |
| 26 | `pim_neg_stray_top_src_ip` | 负 | 白名单外顶层 `src_ip` 判死 | — |
| 27 | `pim_neg_carrier_udp` | 负 | `[ip,udp,pim]` 非 raw-IP 载体判死 | — |
| 28 | `pim_neg_carrier_missing_ip` | 负 | `[pim]` 缺 ip 层判死 | — |

## 3. Positive（正例）断言契约

- `ip.proto=103` 在 #1/#3/#15 三例显式断言（其余正例由 `FieldContract ip.protocol=103` + 生成器固写 `layer_gen.go:44-49` 承载，P5 全量复核时按需补钉，不追加工单）；`ip.len` 仅 #15（存在性，非定值）；`ip.dst` 零出现（目的分布见 design §2/§13.3，P4 层链整形后按 `layers[0].ip.dst` 补钉——先跑后钉）。
- `pim.cksum` 只用 `nonzero=true`（#1/#15 共 2 次），不写未经独立复算的固定十六进制值；Register 例 #10 不断言 cksum 数值（8 字节前缀面，design §10 裁定）。
- `pim.version=2` 仅 #1（实现 `version=2`，`builder.go:48`）。
- frames offset 单档实测：**34**（全部 26 帧）；hex 七类前缀：`20 00`×9（Hello）/ `21 00`（Register）/ `22 00`（Register-Stop）/ `23 00`×12（Join/Prune）/ `24 00`（Bootstrap）/ `25 00`（Assert）/ `28 00`（Candidate-RP-Adv），与 design §3 Type 表逐值一致。
- 组/源多值面：tshark 把同包多地址读回为逗号拼接（#4 `pim.group` 双写、`232.1.1.1,232.1.1.1`；#5 `pim.source` 双源；#6 `numjoins 1,1`/`numprunes 0,1`；#8 `pim.rp` 双 RP/`priority 10,20`）——P5 先跑后钉，不照抄本逗号形（tshark 版本相关）。
- 重传（#7）只断言两包 `type` + 第二包 neighbor/group/source 相等；不 séquence number（PIM 无该字段，design §4.2）。
- `directional=true` 仅 #13/#14（多包方向面）；其余 15 正例 `false`（单包无方向区分）。
- 字段去重口径实测 28 个（`pim.*` 26 + `ip.*` 2）：`pim.bsr/bsr_priority/cksum/dr_priority/generation_id/group/hash_mask_len/holdtime/metric/metric_pref/numgroups/numjoins/numprunes/override_interval/prefix_count/priority/propagation_delay/register_flag.border/register_flag.null_register/rp/rpt/source/t/type/upstream_neighbor/version` + `ip.len/ip.proto`（`ip.ttl`/`ip.dst` 零出现→P4 补钉候选）；逐个对 `tshark -G fields`（本机 3.6.14，`pim.*` 107 字段）**命中 28/28，零自创**（P1 实测，见 §9.6）。

## 4. Negative（负例）契约

11 个负例必须都以任务错误终止，`error_contains` 逐字对已落码锚词（P1 实测行号，非设计臆造）：

| # | ID | 故障输入（存量形状） | `error_contains` | 代码锚点（实测） |
|---:|---|---|---|---|
| 18 | `pim_neg_ipv6_profile` | `profile=pim_rfc7761_ipv6_pending` | `profile` | `planner.go:29-31`（`unsupported profile`） |
| 19 | `pim_neg_checksum` | 事件 `wire_fault={kind:checksum}` | `checksum` | `planner.go:146`（`checksum wire fault rejected`） |
| 20 | `pim_neg_length` | 事件 `wire_fault={kind:length,declared_total_length:1}` | `length` | `planner.go:148`（`length wire fault rejected`） |
| 21 | `pim_neg_type` | 事件 `wire_fault={kind:type,value:9}` | `type` | `planner.go:150`（`type wire fault rejected`） |
| 22 | `pim_neg_address_family` | Join 组 `ff0e::1` + 源 `2001:db8::10`（IPv4 profile 配 v6） | `address` | `planner.go:102-104`（group 非 v4）/ `validateSource :131`（source 非 v4） |
| 23 | `pim_neg_ssm_rp` | SSM profile + `kind=register` | `ssm` | `planner.go:62`（`pim ssm: register ... no RP/Register`） |
| 24 | `pim_neg_df_profile` | SM profile + `kind=df_election` | `df` | `planner.go:57`（`pim df:`） |
| 25 | `pim_neg_top_pim_presence_reject` | 层链 + 顶层空 `pim:{}` 并存 | `top-level pim` | 链级守卫契约 |
| 26 | `pim_neg_stray_top_src_ip` | 层链 + 顶层 `src_ip` | `top-level src_ip` | 顶层白名单守卫契约 |
| 27 | `pim_neg_carrier_udp` | `[ip,udp,pim]` | `carrier` | raw-IP 载体守卫契约 |
| 28 | `pim_neg_carrier_missing_ip` | `[pim]` | `carrier` | `ip` 依赖守卫契约 |

不允许通过空 PCAP、0 packet 或忽略错误来满足断言。**注意 §1 严格解码声明**：`wire_fault` 三键（`kind/value/declared_total_length`）对 `PIMWireFault`（`routing.go:262-266`）全量合法——#19/#20/#21 真正生效的判死路径是 `validateWireFault`（`:140-159`），P4 改写时保持事件内触发源。

## 5. 历史 24 例逐条去向审计（§9.14；本批已按本表执行完）

**现行机器契约已收敛为 28 例**：17 个正例、7 个协议语义负例和 4 个新增链级/白名单负例。17 个正例的数量通过兄弟键 `strategy_fc` 表达，`flows` 分别为 `[1,1,1,1,1,1,2,1,1,1,1,1,3,6,1,1,2]`；11 个负例不带成功包数。去向：17 正例、7 协议负例全部合入，4 链级负例新增并登记。

| # | ID | 去向 | 改写要点 |
|---:|---|---|---|
| 1 | `pim_sm_hello_holdtime` | 合入 | `src_ip/dst_ip/ttl`→`layers[0].ip`；`pim` 子映射→`layers[1]`；补 `strategy_fc.flows=1`；`hello_interval` 保留（仅携带不进线，design §10） |
| 2 | `pim_sm_hello_options` | 合入 | 同上；`lan_prune_delay/dr_priority/generation_id` 进 `layers[1]` |
| 3 | `pim_sm_hello_zero_holdtime` | 合入 | 同上；`holdtime=0` 保留即时失效边界 |
| 4 | `pim_sm_joinprune_wildcard` | 合入 | 同上（dst=上游单播 `192.0.2.254`）；`wildcard:true` 保留（W 位面） |
| 5 | `pim_sm_joinprune_source` | 合入 | 同上；joined+pruned 双列表保留 |
| 6 | `pim_sm_joinprune_multi_group` | 合入 | 同上；双 group（`(*,G)`+`(S,G)`）保留 |
| 7 | `pim_sm_joinprune_retransmit` | 合入 | 同上；双事件 + `retransmission:true` 保留；补 `flows=2` |
| 8 | `pim_sm_bootstrap_rp_set` | 合入 | 同上；BSR/hash/RP-set 保留 |
| 9 | `pim_sm_candidate_rp_adv` | 合入 | 同上；C-RP/prefix 保留 |
| 10 | `pim_sm_register` | 合入 | 同上；`src_ip=192.0.2.100`（DR 源语义）保留；flags+inner 保留 |
| 11 | `pim_sm_register_stop` | 合入 | 同上；显式 group/source 保留 |
| 12 | `pim_sm_assert` | 合入 | 同上；RPT/metric 保留 |
| 13 | `pim_sm_dr_election` | 合入 | 同上；三 Hello 事件保留（`directional=true` 保持）；补 `flows=3` |
| 14 | `pim_sm_multi_neighbor_state` | 合入 | 同上；6 事件保留（`directional=true` 保持）；补 `flows=6` |
| 15 | `pim_sm_checksum_length` | 合入 | 同上；`pim.cksum` nonzero + `ip.len` 存在性保持 |
| 16 | `pim_ssm_joinprune_sg` | 合入 | 同上；SSM `(S,G)` 保留 |
| 17 | `pim_ssm_multi_group` | 合入 | 同上；双事件保留；补 `strategy_fc` flows=2 |
| 18 | `pim_neg_ipv6_profile` | 合入 | `profile` 留层内走拒（IPv6 无可住层，按 1.12 拒绝通道表达） |
| 19 | `pim_neg_checksum` | 合入 | 事件 `wire_fault` 留层内；锚词 `checksum` 已对 |
| 20 | `pim_neg_length` | 合入 | 事件 `wire_fault` 留层内；锚词 `length` 已对 |
| 21 | `pim_neg_type` | 合入 | 事件 `wire_fault` 留层内；锚词 `type` 已对 |
| 22 | `pim_neg_address_family` | 合入 | v6 组/源留层内；锚词 `address` 已对 |
| 23 | `pim_neg_ssm_rp` | 合入 | SSM+register 留层内；锚词 `ssm` 已对 |
| 24 | `pim_neg_df_profile` | 合入 | `df_election` 留层内；锚词 `df` 已对 |

作废 0 例，等价覆盖 0 例（无重复语义可合并）。

## 6. 三方一致性清单

1. 设计、本文和 JSON 各有相同的 28 个 ID、相同顺序、17 正例与 11 负例。
2. 正例 packet_count 序列为 `[1,1,1,1,1,1,2,1,1,1,1,1,3,6,1,1,2]`（总包数 29）；负例没有 packet_count。
3. 17 个正例都有 `has_payload=true`、fields 和 frames，并逐包观察 PIM Type 及七类前缀；`ip.proto=103` 在 #1/#3/#15 显式断言（其余由 FieldContract 承载）。
4. Join/Prune 的通配/具体/多组、Bootstrap RP-set、C-RP 前缀、Register flags+inner、Register-Stop/Assert 显式地址、DR election tie-break、多邻居隔离、重传、SSM 单/多组均有独立场景。
5. checksum 明确为 one's-complement（Register 8 字节前缀例外，design §10）；PCAP 不虚构固定 checksum 常量，错误 checksum 只走负例错误契约。
6. IPv6/DF 只有拒绝用例，未将 IPv6 PIM 或 Bidir DF 当作正例。
7. `pim` 层已注册、代码已落码；P4 层链整形后跑全量 suite（`CASE_PROTO=pim`）与 tshark 验证才算完成，不以“任务不失败”充数。

## 7. 实现后执行顺序

先执行 JSON 语法、ID 顺序、正负 expect 结构、offset/hex 静态检查；再按 1–17 验证 Hello、Join/Prune、BSR/C-RP、Register、Assert、状态隔离和 SSM，最后按 18–28 验证每个拒绝路径和错误传播。tshark 对 Join/Prune 扩展字段（`pim.upstream_neighbor/group/source/numgroups/numjoins/numprunes`）与 BSR/RP/C-RP/Assert 字段已在存量断言中实证可读；若个别字段在目标版本未识别，以原始 offset bytes、IP protocol 和实现单测为补充证据，不凭名称字符串宣称通过。

## 8. 修订记录

**现行机器契约 `cases/pim.json` 为 28 例**（旧版记录中的“24 例”仅指 17 个语义正例与 7 个协议负例的存量集合）；本轮新增 4 个链级/白名单负例。
- v1.0.0（2026-08-20）：建立 17 个正例与 7 个负例，覆盖 RFC 7761/4607、IPv4 载体、Hello/Join/Prune/BSR/C-RP/Register/Assert、状态/重传、多邻居、SSM 及 IPv6/DF 边界。

## 9. P3 固定动作（CORE_MEMORY §3.15 / §9.52 / §9.14 / 覆盖审计要求面）

### 9.1 §3.15 三项逐项一例或立项（无例无项即缺口）

| # | 三项 | 本协议对照 | 用例/立项 |
|---|---|---|---|
| ① | 同连接/同流内的多轮操作 | pim 无连接——对照落“同会话多报文序列”：Hello → Join（joined）→ Prune（pruned）/重传相同语义（#7 双包，`retransmission`）；多邻居多组扇出（#14 六包，双邻居×双组） | 已覆：#7 多轮 + #14 多会话 |
| ② | 非正常结束 | IPv6 profile/坏 checksum/长度/type 错误/地址族混用/SSM 违规/DF 混入七类拒收，全部 task error 终态 | 已覆：#18–#24（7 负例，锚词逐字见 §4） |
| ③ | 长保活 | pim 无自有保活/重传确认语义（无连接）→ 显式记**不适用**；Hello 周期刷新 → **明确不支持**（design §13.1 #6，属引擎调度器面，不归本协议） | 不适用 + 明确不支持（显式声明，挂 G-PIM-2 迁入计划） |

无空项。

### 9.2 A′/B′ 两分类表（要求面反推：数据/业务/现网/多流/地址族/断言通道六类）

A′（引擎可构建 → 17 正例与 7 协议负例已覆；**A′ 补例建议 = T-25/T-26**（§9.24 对称缺格），并入与否由主线程定，不影响 §2 的 28 ID 权威口径）：

| 面 | 要求点 | 去向 |
|---|---|---|
| 数据 | Holdtime 必发/零边界 / LAN Prune Delay（T/propagation/override）/ DR Priority / Generation ID / 通配 W 位 / joined+pruned 双列表 / 多 group / BSR+RP-set / C-RP 前缀 / Register flags+inner / RPT+metric | #1/#2/#3/#4/#5/#6/#8/#9/#10/#12 已覆；非法形 → 负例 #19/#20/#21/#22 |
| 业务 | Hello→Join→Prune 状态变迁/重传相同语义/多邻居隔离/SSM 源特定切换 | #7/#13/#14/#16/#17 已覆；SSM 违规/DF 混入 → 负例 #23/#24 |
| 现网 | 路由器 Hello/DR 选举/BSR 通告/Register 注册/Assert 竞争 | #1–#14 已覆外壳；**抓包级确认 → G-PIM-1**（确认方式：抓路由器回环包）；周期调度差异面 → G-PIM-1 |
| 多流 | 双邻居×双组 6 包扇出（#14）+ DR election 3 包（#13）+ 重传相等性（#7）+ SSM 双事件（#17） | #7/#13/#14/#17 已覆；多会话并发交织序 → G-PIM-2（不假设调度器交织顺序）；**Register flags 全组合缺格 → A′ T-25**；**Bootstrap 多 RP-set 对称缺格 → A′ T-26** |
| 地址族 | IPv4 全覆；IPv6 只有拒绝例（Bidir/IPv6 另议） | #18/#22 已覆（拒绝通道）；**IPv6 无正例**=显式设计决策（design §1），不是缺口 |
| 断言通道 | `pim.*` 26 + `ip.*` 2 = 去重 28 字段（28/28 实测命中）+ frames hex 七类前缀 offset 34 单档 | 全正例双通道；checksum 只 nonzero；`ip.dst` 零出现→P4 补钉候选 |

B′（引擎结构缺口 → D-PIM-1「明确不解决 + 迁入计划」，见 design §17 G-PIM-2/G-PIM-4）：多会话并发交织序假设、inner 载荷变体（`payload_hex` 非 fixture 面）、`hello_interval` 调度语义、Register checksum 全包覆盖争议面（design §10 裁定复核）、未知 pim 键拒绝守卫（→ G-PIM-4，跨协议共享面上报主线程）。

### 9.3 9.52 对账两行 + 清单出处声明

- **清单出处声明**：本清单来源 = **规范反推**（RFC 7761 PIM-SM 七类消息；RFC 4607 SSM `(S,G)` 限定；精确章节号待 G-PIM-1），**非**引擎能力面反推。引擎侧只作现状取证：`pim` 已注册（`registry.go:896`）/白名单（`protocols.go:46`）/builder+planner+generator 已落码（`internal/protocol/pim/` 1611 行，34 个测试函数）/`cases/pim.json` 28 例（24 个历史语义例 + 4 个链级负例，当前均为层链或故意拒绝形状）/tshark `pim.*` 107 字段实测。第三源“已确认现网行为”当前=未确认级，挂 G-PIM-1。
- **对账两行**：**规范逻辑点总数 = 58**（design §13.1 八项 8 行 + §13.2 报文×组播状态矩阵 36 格 + §13.3 数据形态变体表 14 行 = 58 格/行）；**用例覆盖数 = 46**（八项 8 行全有结论 + 矩阵 24 格〔已覆 16 + 负例通道 8〕+ 变体 14 行，全部由 28 个 ID 承载）；**不适用 = 11**（矩阵 11 格，显式声明不适用≠缺口）；**链级红例通道 = 1**（矩阵 R1c3 Hello 非法载体 → §14-P2 TCP 载体/缺 ip 守卫，已由 #27/#28 登记）。46 + 11 + 1 = 58 ✓ 无遗漏。
- **口径说明（防误读）**：上行的 58 点中矩阵 36 格按“已覆 16/负例通道 8/链级红例通道 1/不适用 11”归并；八项 8 行按“已覆/缺口/不适用”归并计 1 点/行；变体 14 行逐行有例。**反查 28/28 绿 ≠ 覆盖全**——反查只证明清单内的点有例，本对账才证明清单本身全（§9.52 原文）。

### 9.4 3.14 豁免边界审计

- 本协议**无连接**（单向 IPv4 组播/单播报文，无 tcp/udp 载体）——但 §3.14 明示“豁免 `sessions[]` 不等于豁免多流覆盖”。本文**不主张任何豁免**：多会话/多组由 `events[]` 显式声明（design §14.3 会话表），且 #14 覆盖 6 包双会话扇出。
- **多流并发**：已覆 #14（双邻居×双组 6 包）+ #13（DR election 3 包）。
- **单包多载荷**：单 Join 多 group（#6 双 group `(*,G)`+`(S,G)`）已覆 → 显式记已覆；inner 载荷变体 → B′（G-PIM-2），不是豁免逃逸。
- **多事务**：同会话内 Hello→Join→Prune 多轮 + 重传（#7）已覆。
- 结论：多流、单包多载荷、多包序列三项各有结论，无逃逸。

### 9.5 三源回指行

RFC 7761（七类消息 Type/公共头/Hello options/Join 编码/BSR/RP-set/C-RP/Register/Assert）+ RFC 4607（SSM `(S,G)` 限定）→ **D-PIM-1**（design §15）→ `trafficgen/test/protocol_pcap/cases/pim.json`（28 例）。第三源“已确认的现网行为”当前为**未确认级**（design §13.4 ②），挂 G-PIM-1。ID 权威 = 本文 §2（17 正 + 11 负）。

### 9.6 断言契约核对结论（与 design §1/§7/§15 一致）

1. **28 ID 契约核对**：本文 §2 与 design §8 逐 ID、逐序、逐类型、逐 `packet_count` 一致——17 正例（`[1,1,1,1,1,1,2,1,1,1,1,1,3,6,1,1,2]`，总包数 29）+ 11 负例（`expect` 只有 `expect_error`/`error_contains`，锚词含协议语义与链级 `top-level`/`carrier`）。
2. **存量审计（§9.14）**：见 §5 去向表。24 个历史语义例已迁入 `[ip,pim]`，地址/TTL/业务分别住对应层；4 个新增链级负例保留故意违规形状，不搬运旧期望值。
3. **断言通道核对**：28 个字段（`pim.*` 26 + `ip.*` 2）逐个注册命中（`tshark -G fields` 107 个中的 22 + IP 核心 3）；frames hex 七类前缀 offset 34 单档实测；`has_handshake` 零出现（无连接协议诚实口径）。
4. **packet_count 纪律**：§2 的约定值随 P4 **先跑后钉**（§9.31/§14.6），以落盘 pcap 实测校准；#7/#13/#14/#17 的 2/3/6/2 已在存量断言中给出，需 P5 复核事件数与包数一一对应。

### 9.7 性能设计与验收（§6.1–6.8 要素；细目见 design §15）

- 目标口径：O(n) 流式——`Generate` 逐事件渲染直发 `req.Emit`，事件序为 for 循环直发，无按包增长结构、无全量聚合（design §15 主流程）；无锁无 sleep（事件驱动，非定时器模型）。
- 两路验收（§6.3）：**pcap 路**——suite 全量落盘 `/tmp/mcp-pcaps/pim/`，tshark 逐字段校对；**NIC 路**——过滤器 `ip proto 103`，测试网口按 testing-interface 记忆（`enp135s0f0np0`），关注组播目的与 TTL=1 在线上可见。
- 六类场景（§6.6）P5 跑测覆盖：基线（#1 单包）/目标规模（#14 六包事件）/压力上限（`strategy_fc.flows=N` 大 N × 事件序）/长时间运行/并发交错（#14 多会话）/资源耗尽背压（队列满走既有 pipeline 语义）。

## T1–T6 静态执行契约

| ID | 检查项 | 结论 |
|---|---|---|
| T1 | JSON 可解析、28 个 ID 唯一且顺序与本文 §2/设计 §8 一致 | 28/28；17 正、11 负 |
| T2 | 正例形状与数量 | 17/17 为 `[ip,pim]`；`strategy_fc.flows` 与 `packet_count` 一致；总包数 29 |
| T3 | 负例形状 | 11/11 `expect` 严格仅 `{expect_error,error_contains}`；其中 #25 必须保留层链+顶层空 `pim:{}` 双键 presence 形状 |
| T4 | 断言与锚词 | 正例均有数量、fields、frames、`has_payload`；负例锚词逐字为 `profile/checksum/length/type/address/ssm/df/top-level pim/top-level src_ip/carrier` |
| T5 | 新增 4 例去向 | #25 presence、#26 顶层游离 `src_ip`、#27 UDP 载体、#28 缺失 `ip`；均为新增负例，不改写为正例 |
| T6 | 执行边界 | 只做 `json.tool`/静态 diff-check；未运行 suite、MCP、NIC，pcap 字段和包数仍属 pending-suite |

## C1–C6 覆盖清单

| ID | 覆盖要求 | 当前结论 |
|---|---|---|
| C1 | 七类 PIM-SM 消息与 SSM `(S,G)` | #1–#17 覆盖 Hello、Join/Prune、Bootstrap、C-RP、Register、Register-Stop、Assert、SSM 单/多组 |
| C2 | 层链与载体 | 正例严格 `[ip,pim]`、Protocol 103；#27 UDP 载体与 #28 缺 ip 为故意判死负例 |
| C3 | 多事件/状态面 | #7 重传、#13 三邻居、#14 六包双邻居双组、#17 SSM 双事件；不假设隐式序号 |
| C4 | 字段与原始字节 | 正例 fields/frames 双通道；offset 34 与 `20/21/22/23/24/25/28 00` 前缀来自静态契约，运行后复钉 |
| C5 | 失败传播 | #18–#24 协议语义负例 + #25–#28 链级/白名单负例；均只允许 task error，不允许成功 PCAP 或 completed/0 packet |
| C6 | 双输出与完成边界 | PCAP/NIC 双路仅登记执行计划；本批未运行，不把文档静态闭环写成运行绿 |

## 修订记录

- v2.1.0（2026-10-01）：按现行 `pim.json` 28 例补齐 T1–T6/C1–C6；核对新增 #25–#28 去向、正负比例、层形、负例双键与错误锚词；静态闭环，未运行 suite/MCP/NIC。
- v2.0.0（2026-09-26）：P3 完整产物与 24 例存量审计。