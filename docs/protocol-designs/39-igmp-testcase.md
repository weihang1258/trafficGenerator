# IGMP（互联网组管理协议，Internet Group Management Protocol）测试用例设计

> 版本：v2.0.0（P3 完整产物）
> 日期：2026-09-26
> 配套设计：`docs/protocol-designs/39-igmp-design.md` v2.0.0（D-IGMP-1 草稿 §15；门1 获批=定稿）
> 机器契约：`trafficgen/test/protocol_pcap/cases/igmp.json`（25 例，2054 行；链形 `[ip,igmp]` 已对但层内全空，P4 按 §5 去向表改写）
> 状态：`igmp` 层已注册、builder/planner/generator 已落码（`registry.go:863`，`internal/protocol/igmp/` 四文件 804 行，20 个单元测试函数），D-IGMP-1 未定稿——P4 落码前以门1 获批版为准，不宣称当前 suite 可运行。

## 1. 测试原则

用例由设计 §1–§10 逐项派生，共 25 个唯一 ID，正例 17 个、负例 8 个，顺序与设计 §9/§10 及 JSON 完全一致。每个正例都断言 `packet_count`、`fields` 和 `frames`，并观察 IPv4 Protocol=2、TTL=1、目的组播地址、IGMP Type/profile 及 checksum 存在性。无 IPv4 options、无 VLAN 的正例中 IGMP 起点固定为 offset 34（v3 Query 扩展面 42/46 起）；checksum 字节不在 `frames.hex` 中固化，改由 `fields.nonzero=true` 观察并由实现单测做 one's-complement 逐字节复算。

- 每个正例都有 `packet_count`、非空 `fields`、非空 `frames`、`has_payload=true`、`directional=false`（实测 17/17 五项齐全）。
- 字段全部来自 `tshark -G fields` 已注册的 `igmp.*` / `ip.*`；不写未经独立复算的固定 checksum 十六进制值。
- frames 只用可复算前缀（Type/组合字节、group、source list、record 头），运行时随机/长度校验字段不进 frames。
- 每个负例的 `expect` 恰有两个键：`expect_error` 与 `error_contains`；无 `packet_count`/`fields`/`frames`（实测 8/8 合规）。
- 本协议无端口、无握手：`has_handshake` 零出现（实测 0/25），不虚构建连包数。
- 多包事件例（#13/#14/#15）按事件序断言 packet 1..N；不假设跨会话全局包序。
- **严格解码边界（P1 实测，诚实声明）**：`igmp` 子映射经 `parseSubconfigJSON`（`strategy_convert_helpers.go:21-30`）用**普通 `json.Unmarshal`（无 `DisallowUnknownFields`）** 解码——未知键被静默忽略、不进 `ValidationErrors`。因此负例不得依赖“未知键被拒”，必须依赖 (a) 类型不匹配的解码错误（如数值型 `record_type`）或 (b) `planner.go` 的语义校验。P4 若要把未知键变红，需另立守卫（G-IGMP-2 注记）。

## 2. 原子用例索引（与设计、JSON 同序）

| # | ID | 类型 | 覆盖 | packet_count |
|---:|---|---|---|---:|
| 1 | `igmp_v1_general_query` | 正 | v1 General Query，224.0.0.1，MRT=0 | 1 |
| 2 | `igmp_v1_report` | 正 | v1 Report，组地址目的 | 1 |
| 3 | `igmp_v2_general_query` | 正 | v2 Query，MRT 十分之一秒 | 1 |
| 4 | `igmp_v2_group_specific_query` | 正 | v2 Group-Specific Query | 1 |
| 5 | `igmp_v2_report` | 正 | v2 Report | 1 |
| 6 | `igmp_v2_leave` | 正 | v2 Leave，224.0.0.2 | 1 |
| 7 | `igmp_v3_general_query` | 正 | v3 MRC/QRV/QQIC | 1 |
| 8 | `igmp_v3_source_specific_query` | 正 | v3 source list 与 S/QRV | 1 |
| 9 | `igmp_v3_include_record` | 正 | MODE_IS_INCLUDE | 1 |
| 10 | `igmp_v3_exclude_record` | 正 | MODE_IS_EXCLUDE | 1 |
| 11 | `igmp_v3_change_records` | 正 | 两种 mode-change 记录 | 1 |
| 12 | `igmp_v3_allow_block_sources` | 正 | ALLOW_NEW/BLOCK_OLD | 1 |
| 13 | `igmp_profile_matrix` | 正 | v1/v2/v3 profile 顺序 | 3 |
| 14 | `igmp_retransmit_state` | 正 | 状态、重传、报文相等 | 3 |
| 15 | `igmp_multi_group_sessions` | 正 | 多会话、多组 | 4 |
| 16 | `igmp_ipv4_outer_invariants` | 正 | Protocol/TTL/目的地址 | 1 |
| 17 | `igmp_v3_query_boundaries` | 正 | QRV=7、MRC/QQIC=255、三源 | 1 |
| 18 | `igmp_neg_ipv6` | 负 | IPv6 N/A/拒绝 | — |
| 19 | `igmp_neg_nonmulticast_destination` | 负 | 非组播目的 | — |
| 20 | `igmp_neg_ttl_not_one` | 负 | TTL=64 | — |
| 21 | `igmp_neg_protocol_not_two` | 负 | Protocol=17 | — |
| 22 | `igmp_neg_bad_checksum` | 负 | checksum 错误 | — |
| 23 | `igmp_neg_invalid_v3_record` | 负 | v3 记录错误 | — |
| 24 | `igmp_neg_invalid_profile_version` | 负 | profile/type 混用 | — |
| 25 | `igmp_neg_query_source_count_length` | 负 | N 与 source bytes 不一致 | — |

packet_count 序列（正例 17 个，按序）：`[1,1,1,1,1,1,1,1,1,1,1,1,3,3,4,1,1]`。

## 3. Positive（正例）断言契约

- `ip.proto=2`、`ip.ttl=1` 是每个正例的字段断言（实测 24 次出现：17 正例含多包例的逐包断言）；目的地址按消息表逐包断言（`ip.dst`，24 次）。
- `igmp.checksum` 只用 `nonzero=true`（24 次），不写未经独立复算的固定十六进制值。
- frames offset 八档实测：**34**（v1/v2 头 `Type Code`）、**38**（group 4 字节）、**42**（v3 Query `S/QRV,QQIC,N` 与 v3 Report 首条 record 头）、**46**（v3 Query 首个 source）、**50**（v3 Report 第二条 record 头）、**54**（#12 第二条 record 头）、**58**（#11 记录内 source）、**62**（#12 第二记录 source 对）。
- v3 Query 的 offset 42 为 `Resv/S/QRV, QQIC, N`；offset 46 起为 source list。v3 Report offset 42 起为 Group Record。
- 多包用例用每个 packet 的 `fields` 和 `frames` 指明事件顺序；重传用 `same_as_packet` 观察相同的 group/type/source 集合（#14）。
- 字段去重口径实测 14 个（`igmp.*` 11 + `ip.*` 3）：`igmp.type`/`checksum`/`maddr`/`max_resp`/`qrv`/`qqic`/`num_src`/`saddr`/`num_grp_recs`/`record_type`/`s` + `ip.proto`/`ip.ttl`/`ip.dst`；逐个对 `tshark -G fields`（本机 3.6.14，`igmp.*` 精确口径 44 字段）**命中 14/14，零自创**。
- MRC 浮点面实测钉值：#17 `max_response_code=255` → tshark `igmp.max_resp=31744`（RFC 3376 浮点解码 `(15|16)<<(7+3)`，本机实测口径，非手算断言——P5 重跑复核）。

## 4. Negative（负例）契约

8 个负例必须都以任务错误终止，`error_contains` 逐字对已落码锚词（P1 实测行号，非设计臆造）：

| # | ID | 故障输入（存量形状） | `error_contains` | 代码锚点（实测） |
|---:|---|---|---|---|
| 18 | `igmp_neg_ipv6` | `igmp.address_family=ipv6` + v6 group `ff02::1` | `IPv6` | `planner.go:26`（`igmp: IPv6 is N/A`） |
| 19 | `igmp_neg_nonmulticast_destination` | 顶层 `dst_ip=192.0.2.20`（单播） | `multicast` | `planner.go:37/40`（`non-multicast destination`） |
| 20 | `igmp_neg_ttl_not_one` | 顶层 `ttl=64` | `TTL` | `planner.go:45`（`igmp: TTL must be 1`） |
| 21 | `igmp_neg_protocol_not_two` | `igmp.wire_fault={kind:protocol,value:17}` + 顶层 `ip_protocol=17` | `Protocol 2` | `planner.go:59`（`igmp: IP Protocol 2 required (wire_fault protocol)`） |
| 22 | `igmp_neg_bad_checksum` | `igmp.checksum_mode=invalid` + `wire_fault={kind:checksum}` | `checksum` | `planner.go:61`（`invalid checksum requested`） |
| 23 | `igmp_neg_invalid_v3_record` | `igmp.records[0].record_type=99`（数值形）+ `wire_fault={kind:record}` | `record` | 解码层：`record_type` 为 string 字段收数值 → `json: cannot unmarshal number ... record_type`（`strategy_convert_helpers.go:27-28` 进 `ValidationErrors`）；语义层：`planner.go:73`（`invalid v3 record`） |
| 24 | `igmp_neg_invalid_profile_version` | `profile=v1` + `kind=leave` | `profile` | `planner.go:113/117`（`invalid profile "v1" / kind "leave"`，v1/v3 Leave 拒 `:116-121`） |
| 25 | `igmp_neg_query_source_count_length` | `source_count=2` 而 `sources` 仅 1 项 | `source count` | `planner.go:125`（`v3 query source count 2 != sources 1`） |

不允许通过空 PCAP、0 packet 或忽略错误来满足断言。**注意 §1 严格解码声明**：#23 的 `wire_fault.record_type=99`/`source_count=2` 两个键对 `IGMPWireFault`（`routing.go:58-61` 仅 `kind`/`value`）是未知键、会被静默忽略——该例真正生效的判死路径是记录本身（数值型 `record_type` 或 `planner.go:73`），P4 改写时保持记录侧触发源，不依赖 `wire_fault` 子键。

## 5. 存量 25 例逐条去向审计（§9.14；P1 存量实测，P4 按本表执行）

存量现状（2026-09-26 实测，`cases/igmp.json` 2054 行）：25/25 链形为 `layers=[{"ip":{}},{"igmp":{}}]`（**链形已对**，与 cflow 不同），但层内全空——地址/TTL/业务全在顶层（旧扁平形）。顶层键形状四类：20 例 `['count','dst_ip','igmp','layers','src_ip','ttl']`、3 例 `['count','events','layers','src_ip','ttl']`（#13/#14/#15）、1 例多 `ipv6:true`（#18）、1 例多 `ip_protocol:17`（#21）；25/25 无 `flow_control`。去向：17 正例全部**合入**（层链整形后保留语义，期望值不照抄——先跑后钉）；8 负例全部**合入**（锚词已对真实代码行，见 §4）。

| # | ID | 去向 | 改写要点 |
|---:|---|---|---|
| 1 | `igmp_v1_general_query` | 合入 | `src_ip/ttl/dst_ip`→`layers[0].ip`；`igmp` 子映射→`layers[1]`；补 `flow_control.flows=1`；frames offset 34/38 保持 |
| 2 | `igmp_v1_report` | 合入 | 同上（dst=组地址 `239.1.1.1`） |
| 3 | `igmp_v2_general_query` | 合入 | 同上；`max_response_time` 值保留 |
| 4 | `igmp_v2_group_specific_query` | 合入 | 同上 |
| 5 | `igmp_v2_report` | 合入 | 同上 |
| 6 | `igmp_v2_leave` | 合入 | 同上；dst `224.0.0.2` 由 `dstFor` 仲裁，层内可不写 dst（P4 按仲裁表取舍） |
| 7 | `igmp_v3_general_query` | 合入 | 同上；`s_flag/qrv/qqic/sources` 进 `layers[1]`；offset 42 保持 |
| 8 | `igmp_v3_source_specific_query` | 合入 | 同上；offset 42/46 保持；`num_src=2` 先跑后钉 |
| 9 | `igmp_v3_include_record` | 合入 | `records[]` 进 `layers[1]`；offset 34/42/50 保持 |
| 10 | `igmp_v3_exclude_record` | 合入 | 同上 |
| 11 | `igmp_v3_change_records` | 合入 | 同上；offset 34/42/50/58 保持（空 source 记录 + 单 source 记录） |
| 12 | `igmp_v3_allow_block_sources` | 合入 | 同上；offset 34/42/50/54/62 保持 |
| 13 | `igmp_profile_matrix` | 合入 | **顶层 `events` → `layers[1].igmp.events`**（层内化）；无顶层 dst（目的逐事件 `dstFor` 仲裁）；补 `flows=3` |
| 14 | `igmp_retransmit_state` | 合入 | 同上（`state`/`retransmit` 元数据保留）；补 `flows=3`；`same_as_packet` 保持 |
| 15 | `igmp_multi_group_sessions` | 合入 | 同上（`session` a/b/c 保留，4 事件）；补 `flows=4` |
| 16 | `igmp_ipv4_outer_invariants` | 合入 | 同 #5 形状；offset 34/38 保持 |
| 17 | `igmp_v3_query_boundaries` | 合入 | `max_response_code=255`/`qrv=7`/`qqic=255`/三源保留；`igmp.max_resp=31744` 先跑后钉 |
| 18 | `igmp_neg_ipv6` | 合入 | 删顶层 `ipv6:true`；`address_family=ipv6`+v6 group 留层内走拒（无可住层，按 1.12 拒绝通道表达） |
| 19 | `igmp_neg_nonmulticast_destination` | 合入 | `dst_ip=192.0.2.20` 写进 `layers[0].ip.dst`；锚词 `multicast` 已对 |
| 20 | `igmp_neg_ttl_not_one` | 合入 | `ttl=64` 写进 `layers[0].ip.ttl`；锚词 `TTL` 已对 |
| 21 | `igmp_neg_protocol_not_two` | 合入 | 删顶层 `ip_protocol:17`；`wire_fault protocol` 留层内；锚词 `Protocol 2` 已对 |
| 22 | `igmp_neg_bad_checksum` | 合入 | `checksum_mode`/`wire_fault` 留层内；锚词 `checksum` 已对 |
| 23 | `igmp_neg_invalid_v3_record` | 合入 | 记录侧触发源保持（数值型 `record_type` 或非法名）；`wire_fault` 子键非生效路径（§4 注） |
| 24 | `igmp_neg_invalid_profile_version` | 合入 | `profile=v1`+`kind=leave` 留层内；锚词 `profile` 已对 |
| 25 | `igmp_neg_query_source_count_length` | 合入 | `source_count`/`sources` 留层内；锚词 `source count` 已对 |

作废 0 例，等价覆盖 0 例（无重复语义可合并）。

## 6. 三方一致性清单

1. 设计、本文和 JSON 各有相同的 25 个 ID、相同顺序、17 正例与 8 负例。
2. 正例 packet_count 序列为 `[1,1,1,1,1,1,1,1,1,1,1,1,3,3,4,1,1]`；负例没有 packet_count。
3. 17 个正例都有 `has_payload=true`、fields 和 frames，并逐包观察 IPv4 Protocol 2、TTL 1 及合法组播目的地址。
4. v1/v2 固定头长度为 8；v3 Query 为 `12+4*N`；v3 Report 按每条 Group Record 的 source 长度计算（AuxLen 恒 0），JSON frames 只固定可复算字段。
5. v3 records 覆盖 include/exclude、mode change、allow/block、source list；多组/多会话及重传状态有独立场景。
6. checksum 明确为 one's-complement；PCAP 不虚构固定 checksum 常量，错误 checksum 只走负例错误契约。
7. IPv6 只有拒绝用例，未将 MLD 或 IPv6 Next Header 当作 IGMP 正例。
8. `igmp` 层已注册、代码已落码；P4 层链整形后跑全量 suite（`CASE_PROTO=igmp`）与 tshark 验证才算完成，不以“任务不失败”充数。

## 7. 实现后执行顺序

先执行 JSON 语法、ID 顺序、正负 expect 结构、offset/hex 静态检查；再按 1–17 验证 IPv4 载体、v1/v2/v3 消息、v3 source/record、状态重传及多会话；最后按 18–25 验证每个拒绝路径和错误传播。tshark 对 v3 扩展字段（`igmp.qrv/qqic/num_src/num_grp_recs/record_type/saddr`）已实测可读；若个别字段在目标版本未识别，以原始 offset bytes、IP protocol/TTL 和实现单测为补充证据，不凭名称字符串宣称通过。

## 8. 修订记录

- v2.0.0（2026-09-26）：P3 完整产物。新增 §5 存量 25 例逐条去向审计表（旧扁平形→层链目标形，P4 执行）、§9 固定动作（§3.15 三项 / A′B′ 两分类 / 9.52 对账 / 3.14 豁免审计 / 三源回指 / 断言契约核对 / 性能验收与六类场景）；§4 锚词表改为对已落码行号实测；§1 状态与严格解码边界更正（层已注册、普通 `json.Unmarshal` 未知键静默）；§3 补 offset 八档与字段 14/14 命中实测。
- v1.0.0（2026-08-20）：建立 17 个正例与 8 个负例，覆盖 RFC 1112/2236/3376、IPv4 载体、v3 source/record、状态/重传、多会话、边界及严格错误契约。

## 9. P3 固定动作（CORE_MEMORY §3.15 / §9.52 / §9.14 / 覆盖审计要求面）

### 9.1 §3.15 三项逐项一例或立项（无例无项即缺口）

| # | 三项 | 本协议对照 | 用例/立项 |
|---|---|---|---|
| ① | 同连接/同流内的多轮操作 | igmp 无连接——对照落“同会话多报文序列”：Query → Report（member）→ Leave（leaving）/重传相同语义（#14 三包，`state`+`retransmit`）；多会话多组扇出（#15 四包，session a/b/c） | 已覆：#14 多轮 + #15 多会话 |
| ② | 非正常结束 | IPv6/非组播目的/TTL 非 1/Protocol 非 2/坏 checksum/非法 v3 记录/profile 混用/source count 八类拒收，全部 task error 终态 | 已覆：#18–#25（8 负例，锚词逐字见 §4） |
| ③ | 长保活 | igmp 无自有保活/重传确认语义（无连接）→ 显式记**不适用**；querier 周期 General Query 刷新 → **明确不支持**（design §13.1 #6，属引擎调度器面，不归本协议） | 不适用 + 明确不支持（显式声明，不用“待确认”逃逸） |

无空项。

### 9.2 A′/B′ 两分类表（要求面反推：数据/业务/现网/多流/地址族/断言通道六类）

A′（引擎可构建 → 25 ID 内已覆；**A′ 补例建议 = T-26/T-27**（§9.24 对称缺格），并入与否由主线程定，不影响 §2 的 25 ID 权威口径）：

| 面 | 要求点 | 去向 |
|---|---|---|
| 数据 | v1 MRT 恒 0 / v2 MRT 显式 / v3 MRC 直接值与浮点扩展码（255→31744）/QRV 0–7/QQIC/N=0,2,3/六态 Record Type 全量/`0.0.0.0` 仅 General Query | #1/#3/#7/#8/#17/#9–#12 已覆；非法形 → 负例 #23/#24/#25 |
| 业务 | Query→Report→Leave 状态变迁/重传相同语义/多会话隔离/源过滤（SSM）切换 | #13/#14/#15 已覆；v1/v3 Leave 混用 → 负例 #24 |
| 现网 | querier 周期 General Query/主机加组离组/组特定与源特定查询 | #1–#8 已覆外壳；**抓包级确认 → G-IGMP-1**（确认方式：抓 querier 回环包）；周期调度/查询间隔差异面 → G-IGMP-1 |
| 多流 | 三 profile 多会话扇出（session a/b/c，四包）+ 重传相等性 | #15 已覆；多会话并发交织序 → G-IGMP-2（不假设调度器交织顺序）；**v3 多会话含 records 的对称缺格 → A′ T-26**；**同会话多组（同 session 两 group）缺格 → A′ T-27** |
| 地址族 | IPv4 全覆；IPv6 只有拒绝例（MLD 不是 IGMP 变体） | #18 已覆（拒绝通道）；**IPv6 无正例**=显式设计决策（design §8），不是缺口 |
| 断言通道 | `igmp.*` 11 + `ip.*` 3 = 去重 14 字段（14/14 实测命中）+ frames hex 八档 offset（34/38/42/46/50/54/58/62） | 全正例双通道；checksum 只 nonzero |

B′（引擎结构缺口 → D-IGMP-1「明确不解决 + 迁入计划」，见 design §17 G-IGMP-2/G-IGMP-4）：AuxData 非零全组合（实现 `AuxLen` 恒 0，`builder.go:150`）、S 位抑制跨会话语义、多会话并发交织序假设、v3 记录数值形扩展（严格解码面，§1 注）、未知 igmp 键拒绝守卫（→ G-IGMP-4，跨协议共享面上报主线程）。

### 9.3 9.52 对账两行 + 清单出处声明

- **清单出处声明**：本清单来源 = **规范反推**（RFC 1112 IGMPv1；RFC 2236 IGMPv2；RFC 3376 IGMPv3；精确章节号待 G-IGMP-1），**非**引擎能力面反推。引擎侧只作现状取证：`igmp` 已注册（`registry.go:863`）/白名单（`protocols.go:41`）/builder+planner+generator 已落码（`internal/protocol/igmp/` 804 行）/`cases/igmp.json` 25 例（旧扁平形）/tshark `igmp.*` 44 字段实测。第三源“已确认现网行为”当前=未确认级，挂 G-IGMP-1。
- **对账两行**：**规范逻辑点总数 = 46**（design §13.1 八项 8 行 + §13.2 报文×组播状态矩阵 28 格 + §13.3 数据形态变体表 14 行 = 50 格/行，去重后口径见下）；**用例覆盖数 = 41**（八项 8 行全有结论 + 矩阵 19 格〔已覆 12 + 缺口→用例通道 7〕+ 变体 14 行，全部由 25 个语义 ID 承载）；**不适用 = 8**（矩阵 R3c2/R5c2/R6c1/R6c2/R6c4/R7c1/R7c2/R7c4，显式声明不适用≠缺口）；**B′/立项 = 1**（矩阵 R4c4 S 位面 → G-IGMP-2）。41 + 8 + 1 = 50 ✓ 无遗漏。
- **口径说明（防误读）**：上行的 46/41/8/1 与合计 50 的差异来自矩阵格与八项行的粒度差（8 行按“已覆/缺口/不适用”归并计 1 点/行，逐格重数见 design §13.2 注：12 + 7 + 8 + 1 = 28）。**反查 25/25 绿 ≠ 覆盖全**——反查只证明清单内的点有例，本对账才证明清单本身全（§9.52 原文）。

### 9.4 3.14 豁免边界审计

- 本协议**无连接**（单向 IPv4 组播报文，无 tcp/udp 载体）——但 §3.14 明示“豁免 `sessions[]` 不等于豁免多流覆盖”。本文**不主张任何豁免**：多会话/多组由 `events[].session`/`group` 显式声明（design §14.3 会话表），且 #15 覆盖四包三会话扇出。
- **多流并发**：已覆 #15（session a/b/c 三会话四包，v1/v2/v3 混排）。
- **单包多载荷**：单 Report 多 records（#11 双 mode-change、#12 allow+block 双记录）已覆 → 显式记已覆；Aux 非零全组合 → B′（G-IGMP-2），不是豁免逃逸。
- **多事务**：同会话内 Query→Report→Leave 多轮 + 重传（#14）已覆。
- 结论：多流、单包多载荷、多包序列三项各有结论，无逃逸。

### 9.5 三源回指行

RFC 1112（v1 Query/Report）+ RFC 2236（v2 Query/Report/Leave/MRT）+ RFC 3376（v3 Query MRC/QRV/QQIC/source list、Report Group Record 六态）→ **D-IGMP-1**（design §15）→ `trafficgen/test/protocol_pcap/cases/igmp.json`（25 例）。第三源“已确认的现网行为”当前为**未确认级**（design §13.4 ②），挂 G-IGMP-1 且按 §5.5 不写死进实现。ID 权威 = 本文 §2（17 正 + 8 负）。

### 9.6 断言契约核对结论（与 design §1/§10/§15 一致）

1. **25 ID 契约核对**：本文 §2 与 design §9 逐 ID、逐序、逐类型、逐 `packet_count` 一致——17 正例（`[1,1,1,1,1,1,1,1,1,1,1,1,3,3,4,1,1]`）+ 8 负例（`expect` 只有 `expect_error`/`error_contains`，锚词 `IPv6/multicast/TTL/Protocol 2/checksum/record/profile/source count` 逐字对 `planner.go`/解码层真实行）。
2. **存量审计（§9.14）**：见 §5 去向表。25 例链形已对但层内全空（顶层四键 + `igmp` 子映射或顶层 `events` + 无 `flow_control`），P4 按去向表逐例改写，**不搬运旧期望值**（`num_src`/`max_resp=31744` 等先跑后钉）。
3. **断言通道核对**：14 个字段（`igmp.*` 11 + `ip.*` 3）逐个注册命中（`tshark -G fields` 精确口径 44 个中的 11 + IP 核心 3）；frames hex 八档 offset 实测；`has_handshake` 零出现（无连接协议诚实口径）。
4. **packet_count 纪律**：§2 的约定值随 P4 **先跑后钉**（§9.31/§14.6），以落盘 pcap 实测校准；#13/#14/#15 的 3/3/4 已在存量断言中给出，需 P5 复核事件数与包数一一对应。

### 9.7 性能设计与验收（§6.1–6.8 要素；细目见 design §15）

- 目标口径：O(n) 流式——`Generate` 逐包渲染直发 `req.Emit`，事件序为 for 循环直发，无按包增长结构、无全量聚合（design §15 主流程）；无锁无 sleep（事件驱动，非定时器模型）。
- 两路验收（§6.3）：**pcap 路**——suite 全量落盘 `/tmp/mcp-pcaps/igmp/`，tshark 逐字段校对；**NIC 路**——过滤器 `ip proto 2`，测试网口按 testing-interface 记忆（`enp135s0f0np0`），关注组播目的与 TTL=1 在线上可见。
- 六类场景（§6.6）P5 跑测覆盖：基线（#1 单包）/目标规模（#15 四包事件）/压力上限（`flows=N` 大 N × 事件序）/长时间运行/并发交错（#15 多会话）/资源耗尽背压（队列满走既有 pipeline 语义）。
- 失败边界（§6.5 诚实待确认）：吞吐/并发/内存目标数字待 P4 基准后定，本契约不写承诺数字；功能正确但超预算按 §6.8 视为不合格。
