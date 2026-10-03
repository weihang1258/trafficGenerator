# TDS（Tabular Data Stream，表格数据流）测试用例契约（v1.0.3，P1–P6 交付版）

> 版本：v1.0.3（2026-10-01，文档与机器契约对账；v1.0.2 = P4–P6 记录）
> 日期：2026-10-01
> 配套设计：`docs/protocols/tds/design.md`（v3.1.3，§12–§17 为本文件依据）
> 机器契约：`trafficgen/test/protocol_pcap/cases/tds.json`（当前 **134** 例 = 105 正 + 29 负；P3 审计基线 131，见 §8）
> 规范基线：MS-TDS v20260617（本地 `docs/protocol-designs/ms-tds-spec.txt`，12603 行实测）
> 状态：`tds` 层已注册并入链；去扁平改写已完成——134 例中 105 个正例为纯 layers 形，29 个负例专用于验证拒绝路径。**历史 P6 证据**含 lane5 suite 134/134；本轮未重跑 suite/server/NIC/MCP，134/134 不代表本轮实测。本文件是 TEST_CASES 层交付文本。

## 1. 三源与依据（§9.2–9.4）

| 源 | 出处 | 覆盖对象 |
|---|---|---|
| 规范/官方文档 | MS-TDS v20260617（包头 Type/Status 表、24 个流 token、43 个数据类型 token、ENVCHANGE 18 型、TransMgr 7 型、DONE Status 8 位、COLMETADATA Flags 16 位、PRELOGIN 9 项、FeatureId 13 项、隔离级别 6 档、版本 5 档） | 枚举面全覆盖清单（设计 §12.5 计数表） |
| 设计 | `docs/protocols/tds/design.md` §2/§3/§4（字段与状态机）、§8（50 条 Validate 规则 V-TDS-001…059）、§15 D-TDS-1 | 原子断言与错误分支 |
| 现网行为 | SQL Server 2012+/2022/2025（TDS 7.4，规范脚注 17/72）；SQL Server 错误号 18456/102/1205/2627（用例已钉）；FreeTDS 1.5.15（GitHub Releases，2026-09-26 查询；RPC OptionFlags 2B 读法见设计 §3.4）；tshark 3.6.14 dissector（`tds.*` 唯一名 605 实测） | 商业行为→用例映射（设计 §12.4） |

## 2. 原子用例索引（当前 134 例，按组；P3 的 131 例仅作历史基线）

> 逐条 ID 清单见设计 §16.6；下表为组级索引与去扁平去向。**交付实况（v1.0.3）**：当前 134 例 = 历史 P3 基线 131 例全部保留（ID 未改名）+ presence 负例 1 + 游离键负例 2 = **105 正 + 29 负**；三例名实不符项采 summary 如实注记 + 缺口立项处置（§3 表）。

| 组 | 例数 | 代表 ID | 覆盖点（设计条目） | 去向 |
|---|---:|---|---|---|
| prelogin | 5 | `tds_prelogin_versions` / `_encrypt_on` / `_mars_off` / `_encrypt_required` / `_encrypt_notsup` | T-001/002/005–008/011–013 | 保留（改写形状） |
| login7 | 13 | `tds_login7_default` / `_tds71|72|73a` / `_feature_ext` / `_empty_password` / `_password_obfuscate` / `_database_language` / `_client_lcid` / `_optionflags1` / `_typeflags` / `_db_only_default_user` / `_custom` | T-016–019/023–032/039 | 保留（改写形状）；7.3.B 补例 → G-TDS-7 |
| login（信息） | 1 | `tds_login_info_tokens` | T-151–160（登录响应 INFO 顺序） | 保留 |
| sql | 29 | `tds_sql_select` / `_multi` / `_dml_update` / `_empty_result_set` / `_colname_unicode` / `_curcmd_transparent` / `_error_*` / `_begin_then_commit` / `_txn_begin_done_inxact` … | T-041–095 主体 | 保留；`_txn_begin_done_inxact` 改名 + 注记（§3） |
| rpc | 25 | `tds_rpc_procid_short` / `_longname` / `_params` / `_param_*`（20 型） / `_batch_two_procs` / `_param_xml_json_udt` / `_param_plp_chunking` | T-096–135 | 保留；`_batch_two_procs` 改名 + 单消息多 RPC 补例 → G-TDS-2 |
| transmgr | 6 | `tds_transmgr_begin_commit` / `_rollback` / `_savepoint` / `_begin_payload` / `_promote` / `_commit_payload_chain` | T-171–185（RequestType 5/6/7/8/9） | 保留；RequestType 0/1 补例 → G-TDS-7 |
| attention | 3 | `tds_attention` / `_idle_confirm` / `_pktid_increment` | T-161–170 主体 | 保留 |
| done（宽度） | 3 | `tds_done_rowcount_2g` / `_4gb` / `_5e9` | T-208/209 + 边界 | 保留 |
| mars | 8 | `tds_mars_2sessions` / `_3sessions*` / `_txn_isolation` / `_attention_cancel` / `_two_sessions_interleave` | T-186–195/215–217 | 保留；`_two_sessions_interleave` 改名或补真交错断言（G-TDS-3） |
| inject | 11 | `tds_inject_error_*`（syntax/class14/class13/continue/split/tds71）/ `_info_*` / `_login_fail` | T-136–160 错误与信息分支 | 保留 |
| integration | 1 | `tds_integration_full_flow` | T-215 端到端 | 保留 |
| validate（负例） | 26 | `tds_validate_*`（V-TDS-001…061 锚词） | §8 规则子集（26 个错误码） | 保留（改写为纯 layers 或 presence 负例） |

## 3. 负例契约与名实不符项

**负例（交付 29 例 = 26 V-TDS 锚词 + presence 1 + 游离键 2）**：每个 `expect` 严格只含 `expect_error` 与 `error_contains`，不得携带 `notes`、字段或帧断言；**走真实流程**（MCP 提交必须被拒，14.11）。presence/游离键 3 例锚词为 CheckProtoFlat 判死文案（`no longer accepts flat config field <k>`），V-TDS 26 例为 `V-TDS-0xx` 字面。

**名实不符项（3 例，P6 处置=summary 如实注记 + 缺口立项，ID 未改名）**：

| 用例 | 声明 | 实测断言 | 处置 |
|---|---|---|---|
| `tds_mars_two_sessions_interleave` | T-216「响应按会话归并/交错」 | 仅 `OutstandingRequestCount=2` + `done.status=0x0010`；字节序实为会话串行块（生成器 `layer_gen.go:128-193` 逐会话出块） | 改名 + 注记，或按 G-TDS-3 补真交错断言 |
| `tds_sql_txn_begin_done_inxact` | T-075「DONE_INXACT(0x04)」 | 实钉 `0x0001,0x0010`（MORE\|COUNT，**不含 0x04**） | 改名 + 注记「规范位、SQL Server 不置位」（设计 §3.9 已载） |
| `tds_rpc_batch_two_procs` | T-202「单消息多 RPC 结果隔离」 | 实为两条**独立 RPC 消息**（非 BatchFlag 单消息多 RPC） | 改名 + 立项单消息多 RPC（G-TDS-2） |

**现状断言 + 注记（2 例）**：`tds_sql_tabname_colinfo_unreachable`（TABNAME/COLINFO）、`tds_rpc_returnvalue_unreachable`（RETURNVALUE）——生成侧无注入点，现断言为固定 token 序列；按 9.36 标 B 类缺口（G-TDS-2）。

## 4. 断言边界与动态面（§9.27–9.36 / §12）

- **已钉**：`tds.type` / `tds.done.status`（含 `_more`/`_error`/`_attn`）/ `tds.done.donerowcount64` / `tds.error.number|class|state|msgtext|linenumber` / `tds.envchange.type|*_length` / `tds.loginack.tdsversion|progname` / `tds.all_headers.header.trans_descr|request_cnt` / `tds.prelogin.option.*` / `tds.returnstatus.value` / `tds.query` 等 **41 个字段**，全部命中本机 tshark 3.6.14 的 `tds.*` 名单（605 唯一名）。
- **帧级**：86 例带 `frames`（offset+hex 逐字节），是包序/字节级证据；其余例以字段断言为准。
- **动态面（§12/9.32–9.36）**：四元组动态走 `ip`/`tcp` 层（五策略）——**当前 0 例**（G-TDS-4）；业务字段（SQL 文本/参数/登录字段）无动态机制（`Strategy` 零命中）——G-TDS-10 逐字段三选一。**动态整格用例在 G-TDS-4/G-TDS-10 收口前不得声称覆盖。**

## 5. 9.52 对账两行 + 清单出处（与设计 §12.5/§16.3 同一口径）

- **行 1**：规范逻辑点总数 = 166 枚举点（12 面）+ 50 条 Validate 规则 = **216**。
- **行 2**：用例覆盖数 = 交付 **134** 例（P3 基线 131；设计 §7 的 220 条条目中被引用 **147** 条，**73 条无例**）。
- **清单出处声明**：清单由 MS-TDS v20260617 原文反推（→ 设计 §2/§3/§8 表行），**不是**从现有用例或引擎能力反推。

## 6. 缺口立项（与设计 §16.8 同源）

G-TDS-1（历史已关闭：纯 layers 配置收口）｜G-TDS-2 生成侧注入点族（NBCROW/单消息多 RPC/RETURNVALUE/TABNAME·COLINFO/NoMetaData/UNKNOWN_PLP_LEN/TEXT·NTEXT·IMAGE NULL）｜G-TDS-3 MARS 真交错｜G-TDS-4 多流·长保活·动态面｜G-TDS-5 路由重定向｜G-TDS-6 §8 未落码 23 条规则｜G-TDS-7 枚举面补例包（IPv6/7.3.B/ALL_HEADERS 头型/Status 三值/Flags 位/PRELOGIN 余项/FeatureId 余项/隔离级别/数据类型逐值/错误类 17–19）｜G-TDS-8 NIC 验收面｜G-TDS-9 现网行为待确认（SQL Server 抓包、FreeTDS 核对、Azure 路由）｜G-TDS-10 业务字段动态。

## 7. 执行建议（已执行项标注实测）

1. 先跑 `python3 -m json.tool trafficgen/test/protocol_pcap/cases/tds.json`（形状可解析）——本轮已过；
2. 历史记录中的 `pipe_gate.sh` 与 suite 结果维持为历史证据，本轮未重跑；
3. suite 全量复跑（`CASE_PROTO=tds`，非增量；14.19）——历史记录为 **134/134 全绿**，本轮不新增通过声明；
4. NIC 路径按 G-TDS-8 配置后复跑（`enp135s0f0np0`，过滤 `tcp port 1433`）——维持 open。

## 8. 修订记录

- v1.0.1（2026-09-27）：P4–P6 交付回写——去扁平改写完成（134 例 = 105 正 + 29 负）；三例名实不符项按 summary 如实注记 + G-TDS-2/G-TDS-3 立项处置（ID 未改名）；m2 游离键负例落地 `src_ip`/`count`（`ttl`/`src_mac` → G-PG-6 框架白名单 backlog）；suite 134/134 + 反查 51/51 绿；D-TDS-1 关单（已验收）。
- v1.0.0（2026-09-26）：P3 产物——存量 131 例审计去向（保留 105+26 / 改名注记 3 / 现状断言注记 2 / 作废 0）、去扁平改写清单、9.52 对账两行、G-TDS-1…10 缺口；不修改任何用例文件与 Go 代码。

---

## T1 形状与执行边界

机器契约共 134 例：105 正例、29 负例。正例严格采用 `[ip, tcp, tds]`（IPv6 例使用 `ipv6`）层链，地址在 IP 层、端口在 TCP 层、TDS 业务在 `layers[].tds`；顶层只允许 `layers`、`flow_control`、策略框架键和 `output`。3 个负例故意保留顶层 `tds`、`src_ip` 或 `count`，用于门 2② 验证旧格式被拒绝，不得从它们复制合法配置。

当前文档和 JSON 结构已核对；本轮仅实际执行 JSON 解析与结构审计，未运行 suite/server/NIC/MCP；不得据此新增通过声明。

## T2 原子 ID、正负面与执行边界

| 面 | 结论 |
|---|---|
| 总量 | 134 |
| 正/负 | 105/29 |
| 负例形状 | `expect_error=true` + `error_contains`，且 expect 严格无其他键；必须传播 task error |
| 已验收 | 层链迁移、顶层游离键门禁、现有字段/raw 断言 |
| 缺口 | G-TDS-2…10：token 注入、MARS 真交错、多流/动态、Routing、枚举补例、NIC、现网取证 |

## T3 正例断言

每个正例按其声明断言可观察输出：packet count 或边界、TDS type/token、方向、握手/终止、字段值和必要的 raw offset/hex。断言范围不得扩大为“字段出现即行为覆盖”。

- PRELOGIN：VERSION 第一项、TERMINATOR 最后、encryption/MARS/option 值。
- LOGIN7/LoginAck：版本方向字节序、登录字段、密码混淆、LoginAck 和最终 DONE。
- SQL Batch：单/多 statement 的结果集边界、DONE_MORE、row count、ERROR/INFO。
- RPC：短/长过程名、OptionFlags 2B、参数 TYPE_INFO/NULL/PLP 现有面。
- TransMgrReq：已覆盖 RequestType 5/6/7/8/9 的响应 token；0/1 仍是 G-TDS-7。
- MARS：session/request ID 和 OutstandingRequestCount；现有串行输出不宣称真交错。

地址族、动态策略、长保活、Routing、NIC 和尚无实现/证据的字段，必须在缺口表中保持未覆盖或待确认。

## T4 负例与错误传播

负例必须只验证真实拒绝；每个负例的 `expect` 严格限定为 `{expect_error, error_contains}`，不接受 `notes`、字段/帧或成功结构断言；不接受“任务完成但 0 包”、只生成 TCP 或静默修正。现有 29 例的错误锚词包括 V-TDS 规则字面以及顶层旧键的 `no longer accepts flat config field <key>`。新增负例须先写能复现错误的配置，再确认锚词稳定；无生产校验入口的规范项登记 G-TDS-6，不伪造错误码。

## T5 覆盖审计

| 审计项 | 结果 |
|---|---|
| JSON 解析 | `python3 -m json.tool trafficgen/test/protocol_pcap/cases/tds.json` |
| ID 与总量 | 134；105 正 + 29 负 |
| 顶层旧键 | 合法正例 0；3 个专用负例按门禁保留 |
| 断言边界 | 86 例含 frames；其余按字段/流程断言 |
| 动态整格 | 四元组和业务字段均无已覆盖动态例，见 G-TDS-4/G-TDS-10 |
| 运行边界 | 文档轨本轮未重新跑 suite/NIC；不得据此新增通过声明 |

## C1–C6 覆盖清单

| ID | 覆盖要求 | 当前结论 |
|---|---|---|
| C1 | JSON 可解析、ID 唯一、设计/用例/cases 索引一致 | 134 例已核对；JSON 可解析 |
| C2 | 严格层链与地址/端口归属 | 105 合法正例为 `[ip,tcp,tds]`；3 个游离键仅作拒绝负例 |
| C3 | PRELOGIN、LOGIN7、SQL/RPC/TransMgr、MARS、握手/终止 | 现有正例按组覆盖，串行 MARS 事实已注明 |
| C4 | 字段/token/raw/错误锚词断言与失败路径 | 29/29 负例 expect 严格仅两键；G-TDS-2、G-TDS-6、G-TDS-7 仍有缺口 |
| C5 | 动态、多流、IPv6、Routing、枚举和性能矩阵 | 未覆盖或部分覆盖，分别登记 G-TDS-3/4/5/7/8/10 |
| C6 | PCAP/NIC 双输出真实流程校准 | 既有记录含 PCAP suite 134/134；本轮未重跑 suite/NIC，不新增通过声明 |
## T6 缺口和执行计划

先沿已验收的纯 layers 形状维护门禁；后续按 G-TDS-2→G-TDS-3→G-TDS-4/G-TDS-5→G-TDS-6/G-TDS-7→G-TDS-8/G-TDS-9/G-TDS-10 顺序补实现和用例。每个新增例必须回指设计 D1–D8、使用严格层链、覆盖失败路径，并在真实流程跑全量后再更新数字。

本版修订自审：两轮。第一轮移除 26 个 V-TDS 负例的 `notes` 并逐例核对 29 个负例只含 `expect_error`/`error_contains`；第二轮复核总数 134、正负 105/29、JSON 解析和文档口径，末轮干净。
