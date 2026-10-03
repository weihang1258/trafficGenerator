# PostgreSQL（PostgreSQL 数据库线协议 v3）测试用例契约

> 版本：v1.1.1（P-PIPE 文档轨修订；#82 postgresql）
> 日期：2026-09-30
> 配套设计：`docs/protocols/postgresql/design.md`（v1.1.0）
> 机器契约：`trafficgen/test/protocol_pcap/cases/postgresql.json`（**71** 例）+ `cases/kingbase.json`（15 例，同层同 `proto`，`dialect=kingbase`）
> 状态：**契约与缺口计划**。本文不宣称本轮已跑 suite；ID 权威 = 本文 §2。JSON 中 71 例的逐条去向见 §8。

## 1. 测试原则与形状基线

- **形状基线（CORE_MEMORY §1）**：`spec_json` 必须是**纯 layers** 形——地址只住 `ip` 层（`src`/`dst`；IPv6 地址族同住 `ip` 层，仓库无 `ipv6` 层）、端口只住 `tcp` 层、数量只走 `flow_control`；顶层只允许 `layers`/`flow_control` 家族/`output`（§1.11）。**正例顶层键 = 0**（白名单外即红）。
  **本协议存量实况（实测）**：postgresql.json 当前 71 例，其中 69 例顶层仅 `layers`、1 例合法 `group_id`、#65 为故意 presence 双键负例；kingbase.json 另有 15 例均为纯 layers。正例顶层游离键为 0；presence 负例不可宣称今日真实拒绝。
- **载体**：`postgresql` 为 TCP-only 终结层，链形 `[ip, tcp, postgresql]`（IPv6 同形，只换 `ip` 层地址）。链夹 `udp`（`[ip,udp,postgresql]`）判死（`chain_planner.go:572-575`，锚词 `tcp`）。**UDP 面不存在**（设计 §5）。
- **端口**：`tcp.dst_port` **不写**，由 `postgresql` 层 `FieldContract` 补齐（`registry.go:649` = 5432；`dialect=kingbase` 时 `dialectFieldContract` 覆盖 54321，`registry.go:1886-1890`）。显式写非契约端口 → 拒（锚词含契约端口号，`chain_planner.go:585-591`）。
- **方向（本协议特有，必需维度）**：类型字节**二义**（`H`=Flush/CopyOutResponse、`S`=Sync/ParameterStatus、`C`=CommandComplete/Close、`D`=DataRow/Describe、`E`=ErrorResponse/Execute）——**所有正例必须显式写 `direction`**（`"c2s"`/`"s2c"`），否则同字节在不同方向语义相反（设计 §3.3 警告 + §3.9 探针实测）。
- **断言通道（实测）**：主通道 = tshark `pgsql.*`（本机 TShark 3.6.14 实测 **56** 字段，口径 `tshark -G fields | awk -F'\t' '$3 ~ /^pgsql[.]/' | wc -l`）+ 载体字段 `ip.proto`/`ipv6.nxt`/`tcp.srcport`/`tcp.dstport`/`tcp.flags`/`tcp.len`；辅通道 = `frames` hex（IPv4 起点 **54** = 14+20+20；IPv6 起点 **74** = 14+40+20）。
  **必须走 frames hex 的面**（dissector 3.6.14 实测不可读）：协议版本号 3.1/3.2（读作 `Unknown`）、`v` NegotiateProtocolVersion（`Unknown`）、`R11`/`R12` 带空 payload（`Unknown`）、孤立 typed 报文（无会话上下文时按前端方向猜：`S`→`Sync`、`C`→`Close`、`D`→`Describe`、`E`→`Execute`）。**不自创字段名**。
- **`decode_as` 纪律（实测）**：标准端口 5432 走 dissector 端口启发式，**无需**声明；非标准端口（54321 等）**必须**显式 `["tcp.port==<port>,pgsql"]`——实测同一 SSLRequest 字节在 5432 自动识别为 `SSL request`，在 54321 无 `decode_as` 时返回**空**、加 `decode_as` 后正常。**禁用其他 decode_as 目标**（会把栈压成单层）。
- **动态值纪律（§9.34/§9.35）**：`flows>1` 的逐流变化只用 `nonzero`/`distinct_values`/`same_as_packet` 断言，禁止硬编码；`paramIdx` 循环表在**每个 flow 从 0 起**（per-generator 实例），跨流不共享。
- **负例纪律（§14.11/§14.12）**：`expect` 键集合严格为 `{"expect_error","error_contains"}`；锚词与 validator 字面值一一对应（设计 §4.2/§7）。
- **包数公式（存量 9 正例逐例复算通过）**：单会话 `packet_count = 3（SYN/SYN-ACK/ACK）+ N（事件数）+ 4（FIN-ACK 四way）= N + 7`；多会话 = 各会话独立经此公式后求和（`kingbase_multi_session` 2 会话 × 4 事件 → 2×11 = **22** ✓）。所有约定值按 §9.31/§14.20 **先跑后钉**。
- **「事件数」口径**：`events[]` 数组长度（`sessions[]` 形则为各 session 的 `events` 之和）；**握手/挥手不计入事件数**（由 `tcp` 层 `handshake`/`termination` 默认 true 产出）。

## 2. 原子用例索引（71 ID = 51 正 + 20 负，顺序为 JSON 权威）

「今日」列沿用能力状态：✅ = 当前代码路径可表达；A′ = 目标面需后续接线；负例若依赖尚未存在的守卫，标 A′，不冒充已验证。JSON 当前包含 51 个正例、20 个负例；本轮仅核对形状、契约与缺口，不宣称 suite 已跑绿。

| # | ID | 类型 | 覆盖 | 今日 | 约定 packet_count |
|---:|---|---|---|---|---:|
| 1 | `postgresql_startup_ipv4_basic` | 正 | IPv4 全流程基线：握手→Startup→R0→S*→K→Z→Q→T/D/C→Z→X→挥手 | ✅ | 23 |
| 2 | `postgresql_startup_ipv6_basic` | 正 | IPv6 同构（`ipv6.nxt=6`，起点 74），与 #1 独立 fixture | ✅ | 23 |
| 3 | `postgresql_startup_params_empty` | 正 | 空参数 Startup 最短形（length=9，frames hex 钉） | ✅ | 8 |
| 4 | `postgresql_startup_params_multi` | 正 | 四参数 Startup（length=82 复算）、参数序与值 | ✅ | 8 |
| 5 | `postgresql_startup_protocol_v3_1` | 正 | 版本号 `00 03 00 01`（frames hex；dissector 读 Unknown） | ✅ | 8 |
| 6 | `postgresql_startup_protocol_v3_2` | 正 | 版本号 `00 03 00 02`（frames hex；v3.2 版本面） | ✅ | 8 |
| 7 | `postgresql_ssl_request` | 正 | SSLRequest 8 字节魔数 `04 D2 16 2F`（无响应字节） | ✅ | 8 |
| 8 | `postgresql_gssenc_request` | 正 | GSSENCRequest 8 字节魔数 `04 D2 16 30` | ✅ | 8 |
| 9 | `postgresql_cancel_request` | 正 | CancelRequest 16 字节（`04 D2 16 2E` + pid + secret），独立连接 | ✅ | 8 |
| 10 | `postgresql_auth_ok` | 正 | AuthenticationOk（子类型 0），length=8 | ✅ | 11 |
| 11 | `postgresql_auth_kerberos_v5` | 正 | 子类型 2（无附加 payload） | ✅ | 10 |
| 12 | `postgresql_auth_cleartext` | 正 | 子类型 3 + c2s `p` 明文口令报文（opaque） | ✅ | 11 |
| 13 | `postgresql_auth_md5_salt` | 正 | 子类型 5 + 4 字节 salt（length=12）+ `p` 摘要形（35 字符，opaque） | ✅ | 11 |
| 14 | `postgresql_auth_scm_credential` | 正 | 子类型 6（废弃面，结构等价于无附加 payload） | ✅ | 10 |
| 15 | `postgresql_auth_gss` | 正 | 子类型 7 + c2s GSSResponse（`p` 承载，opaque bytes） | ✅ | 11 |
| 16 | `postgresql_auth_gss_continue` | 正 | 子类型 8（带 Byte^n GSSAPI 数据；frames hex 断言长度） | ✅ | 11 |
| 17 | `postgresql_auth_sspi` | 正 | 子类型 9 + c2s 响应 | ✅ | 11 |
| 18 | `postgresql_auth_sasl_mechanisms` | 正 | 子类型 10：机制名列表（`SCRAM-SHA-256` + 零字节终止），SASLInitialResponse | ✅ | 11 |
| 19 | `postgresql_auth_sasl_continue` | 正 | 子类型 11（SASL 质询）+ c2s SASLResponse | ✅ | 11 |
| 20 | `postgresql_auth_sasl_final` | 正 | 子类型 12（SASL 结果附加数据） | ✅ | 11 |
| 21 | `postgresql_parameter_status_cycle` | 正 | 缺省 7 项按实例计数器循环（无 name/value 的 `parameter_status`） | ✅ | 14 |
| 22 | `postgresql_parameter_status_explicit` | 正 | 显式 name/value 对（`server_version`/`18.0`） | ✅ | 12 |
| 23 | `postgresql_backend_key_data` | 正 | `K` pid + secret 显式值（缺省 12345/67890 另档） | ✅ | 12 |
| 24 | `postgresql_ready_for_query_idle` | 正 | `Z` 状态 `I`（`pgsql.status` 断言） | ✅ | 12 |
| 25 | `postgresql_ready_in_transaction` | 正 | `Z` 状态 `T`（事务块内） | A′ | 12 |
| 26 | `postgresql_ready_failed_transaction` | 正 | `Z` 状态 `E`（失败事务块） | A′ | 12 |
| 27 | `postgresql_query_select_basic` | 正 | Simple Query `SELECT 1` → T/D/C → Z（全响应族） | ✅ | 16 |
| 28 | `postgresql_query_multi_statement` | 正 | 多语句（SQL 含 `;`）：中间**不夹** `Z`，仅整批结束一个 `Z` | A′ | 19 |
| 29 | `postgresql_query_command_tags` | 正 | 命令标签族：`INSERT 0 1` / `UPDATE 3` / `DELETE 2` / `BEGIN`（逐值） | ✅ | 15 |
| 30 | `postgresql_row_description_multi_column` | 正 | 多列 RowDescription（列数 int16 + 逐列七字段） | A′ | 15 |
| 31 | `postgresql_data_row_null_and_multi` | 正 | DataRow 多列 + **NULL 列（长度 -1）** | A′ | 14 |
| 32 | `postgresql_error_response_fields` | 正 | ErrorResponse 字段序列（severity/code/message + 单 0x00 终止） | ✅ | 14 |
| 33 | `postgresql_notice_response` | 正 | NoticeResponse（`N`，与 E 同结构、不结束事务） | A′ | 14 |
| 34 | `postgresql_empty_query_response` | 正 | EmptyQueryResponse（`I`，空查询串，替代 CommandComplete） | A′ | 14 |
| 35 | `postgresql_extended_parse_bind` | 正 | Extended：`P`→`1`、`B`→`2`（含参数格式码/值/NULL 参数） | A′ | 17 |
| 36 | `postgresql_extended_describe` | 正 | Extended：`D`(S/P) → `T` / `n`(NoData) / `t`(ParameterDescription) | A′ | 17 |
| 37 | `postgresql_extended_execute_sync` | 正 | Extended：`E`→`D`*/`C`/`s`(PortalSuspended)、`S`→`Z` | A′ | 18 |
| 38 | `postgresql_extended_close_flush` | 正 | Extended：`C`→`3`、`H`(Flush 无响应) | A′ | 16 |
| 39 | `postgresql_extended_error_skip_to_sync` | 正 | 扩展协议错误：跳至 `Sync` 前全部消息，发 `E`+`Z` | A′ | 15 |
| 40 | `postgresql_notification_response` | 正 | `A` NotificationResponse（LISTEN 后异步推送，pid+channel+payload） | A′ | 14 |
| 41 | `postgresql_function_call_response` | 正 | `F` FunctionCall + `V` FunctionCallResponse（含 NULL 结果 -1） | A′ | 14 |
| 42 | `postgresql_negotiate_protocol_version` | 正 | `v` 报文（最新 minor + 未识别选项 String[]）；frames hex | A′ | 11 |
| 43 | `postgresql_startup_long_params_mss` | 正 | 大参数 Startup 跨 MSS 分段（`tcp.len` 分段断言 + 重组后长度） | ✅ | 9 |
| 44 | `postgresql_query_long_sql_mss` | 正 | 长 SQL 跨 MSS 分段（默认 MSS 1460，`tcp` 层分段） | ✅ | 14 |
| 45 | `postgresql_multi_session_expansion` | 正 | `sessions[]` 两会话整块展开（各自 src_port、各自握手/认证/查询/挥手） | ✅ | 22 |
| 46 | `postgresql_multi_flow_dynamic` | 正 | `flows=N` 多流 + `ip`/`tcp` 层动态五策略（inc 回绕 / rand 可复现 / list 轮转 / pattern 替换） | ✅ | 33 |
| 47 | `postgresql_pcap_nic_consistency` | 正 | 同 fixture 双路（pcap + `port_group`/NIC `enp135s0f0np0`）字段一致 | A′ | 16 |
| 48 | `postgresql_kingbase_dialect_port` | 正 | `dialect=kingbase` → 契约端口 54321 + 非标准端口必须 `decode_as` | ✅ | 11 |
| 49 | `postgresql_neg_udp_carrier` | 负 | 链夹 `udp`（`[ip,udp,postgresql]`） | ✅ | — |
| 50 | `postgresql_neg_noncontract_port` | 负 | 显式 `tcp.dst_port` ≠ 契约端口（dialect=postgresql 写 5433） | ✅ | — |
| 51 | `postgresql_neg_unknown_dialect` | 负 | `dialect` 未登记值 | ✅ | — |
| 52 | `postgresql_neg_unknown_wire_profile` | 负 | `wire_profile` 未登记值 | ✅ | — |
| 53 | `postgresql_neg_wire_profile_native_pending` | 负 | `kingbase_native_pending`（登记但无固定 payload） | ✅ | — |
| 54 | `postgresql_neg_query_before_ready` | 负 | 未收 `Z` 即发 `query`（状态机） | ✅ | — |
| 55 | `postgresql_neg_password_before_ready` | 负 | 未收 `R` 即发 `password`（状态机） | ✅ | — |
| 56 | `postgresql_neg_unknown_event_kind` | 负 | `kind` 未登记值 | ✅ | — |
| 57 | `postgresql_neg_invalid_direction` | 负 | `direction` 非 `c2s`/`s2c` | ✅ | — |
| 58 | `postgresql_neg_empty_sql` | 负 | `query` 的 `sql` 为空/全空白 | ✅ | — |
| 59 | `postgresql_neg_unknown_layer_field` | 负 | 层内第 6 个键（5 键白名单外） | ✅ | — |
| 60 | `postgresql_neg_wire_fault_truncate_startup` | 负 | `wire_fault={"kind":"truncate_startup","value":1}` | ✅ | — |
| 61 | `postgresql_neg_wire_fault_message_limit` | 负 | `wire_fault={"kind":"message_limit","value":"over_limit"}` | ✅ | — |
| 62 | `postgresql_neg_wire_fault_unknown_kind` | 负 | `wire_fault.kind` 未登记值 | ✅ | — |
| 63 | `postgresql_neg_wire_fault_wrong_shape` | 负 | `wire_fault` 为非对象形（字符串/数字） | ✅ | — |
| 64 | `postgresql_neg_terminate_then_query` | 负 | `terminate` 之后再发 `query`（状态守卫缺口，A′ 后转正例守卫） | A′ | — |
| 65 | `postgresql_neg_presence_top_level_postgresql` | 负 | 层链与顶层 `postgresql` 子映射并存（框架级白名单缺口） | A′ | — |
| 66 | `postgresql_neg_static_copy` | 负 | 多流静态四元组复制拒绝 | ✅ | — |
| 67 | `postgresql_multi_query_rounds` | 正 | 同一连接三轮查询后终止，覆盖长会话多动作 | ✅ | 27 |
| 68 | `postgresql_server_abort_rst` | 正 | 服务端 RST 异常结束 | A′ | 8 |
| 69 | `postgresql_auth_failure_disconnect` | 正 | 认证失败 ErrorResponse 后立即终止，不发 ReadyForQuery | A′ | 12 |
| 70 | `postgresql_neg_auth_data_not_hex` | 负 | 认证附加数据不是合法十六进制 | ✅ | — |
| 71 | `postgresql_neg_auth_token_not_hex` | 负 | 认证 token 不是合法十六进制 | ✅ | — |

> **计数说明**：上表 **71 行** = **51 正**（#1–#48、#67–#69）+ **20 负**（#49–#66、#70–#71）。本轮只完成契约、形状和缺口登记；A′ 用例不宣称已通过 suite。JSON 与本文逐条机读对齐（71 例，负例均两键严格）。

- **JSON 审计基线（2026-09-30）**：71 例 = 51 正 + 20 负；69 例顶层仅 `layers`，1 例合法 `group_id` 框架键，1 例故意保留的顶层 `postgresql` presence 负例（G-PG-6，当前不可宣称真实拒绝）。所有负例 `expect` 严格为 `expect_error` + `error_contains`。新增 #67–#69 正例与 #70–#71 负例已列入索引；本轮不启动服务器、不宣称 suite 绿。


> 通则：①每条正例 `expect` 至少含 `packet_count`（或 `min_packets`）、`has_payload`；②字段断言用 `pgsql.*`（56 字段实测）+ 载体字段；③**结构字节走 frames hex**（尤其 §1 列的四个 hex-only 面）；④所有 `direction` 显式；⑤负例零混入。

1. **`postgresql_startup_ipv4_basic`**：链 `[ip,tcp,postgresql]`，`ip.src=192.0.2.82`/`ip.dst=198.51.100.82`，`tcp.src_port=45082`（**不写 dst_port**）。事件 16 条。断言：`tcp.flags` 首包 `0x002`、`tcp.dstport=5432`、`pgsql.type` 依次 `Startup message`/`Authentication request`/`Parameter status`…/`Backend key data`/`Ready for query`/`Simple query`/`Row description`/`Data row`/`Command completion`/`Ready for query`、`pgsql.query=SELECT 1`、`pgsql.tag=SELECT 1`、`pgsql.status`（Z 报文，值 `73`='I'）。`frames`：包 4 起点 54 = `00 00 00 09 00 03 00 00 00`（空参数 Startup）；包 15 起点 54 = `51 00 00 00 0d 53 45 4c 45 43 54 20 31`（Q + length 13 + `SELECT 1`）。`packet_count = 16 + 7 = 23`。
2. **`postgresql_startup_ipv6_basic`**：同 #1 事件序（16 事件），`ip` 层填 IPv6 地址（`2001:db8::82` → `2001:db8::100`）；断言 `ipv6.nxt=6`、frames 起点 **74**；地址**不复用** #1 的 IPv4 fixture（§9.24 对称，`kingbase_ipv6` 先例）。`packet_count = 16 + 7 = 23`。
3. **`postgresql_startup_params_empty`**：事件 = `{kind:"startup"}`（无 `user`/`database`）。断言 `pgsql.length=9` + frames `00 00 00 09 00 03 00 00 00`（本机实测该 9 字节被识别为 `Startup message` 且 `pgsql.length=9`）。`packet_count = 1 + 7 = 8`。
4. **`postgresql_startup_params_multi`**：事件 = `startup` 带 `user`/`database`；四参数形（本机实测 length **82**）。断言 `pgsql.length=82`（或按 fixture 实际参数量复算，**不手算**——以 tshark `pgsql.length` 读回为准）+ `frames` 首 5 字节 `00 00 00 52 00 03 00 00 00`。`packet_count = 1 + 7 = 8`。
5. **`postgresql_startup_protocol_v3_1`**：版本面用例。断言走 **frames hex**（起点 54，第 5–8 字节 `00 03 00 01`）——dissector 实测把 v3.1 读作 `pgsql.type="Unknown"`，**不得**断言 `pgsql.type="Startup message"`。`packet_count = 8`。
6. **`postgresql_startup_protocol_v3_2`**：同上，第 5–8 字节 `00 03 00 02`。`packet_count = 8`。
7. **`postgresql_ssl_request`**：事件 = 一条 c2s 8 字节报文 `00 00 00 08 04 D2 16 2F`。断言 `pgsql.type="SSL request"`（**实测默认端口即识别，无需 `decode_as`**）+ `frames` 起点 54 hex 全等 + **无 s2c 响应字节**（`tcp.len` 只出现在该包）。`packet_count = 8`。
8. **`postgresql_gssenc_request`**：事件 = 一条 c2s GSSENCRequest 报文。断言走 `frames` hex（起点 54）并确认无 s2c 响应字节。`packet_count = 8`。
9. **`postgresql_cancel_request`**：事件 = 一条 c2s CancelRequest 报文。断言走 `frames` hex（起点 54）并确认无 s2c 响应字节。`packet_count = 8`。
10. **`postgresql_auth_ok`**：`R` 子类型 0。断言 `pgsql.type="Authentication request"` + `pgsql.authtype=0` + frames `52 00 00 00 08 00 00 00 00`（9 字节）。`packet_count = 11`；加一条 `password` 变体见 #12。
11. **`postgresql_auth_kerberos_v5`**：子类型 2（length=8，无附加）。`pgsql.authtype=2`（或 frames hex `52 00 00 00 08 00 00 00 02`）。`packet_count = 10`。
12. **`postgresql_auth_cleartext`**：`R`(3) → c2s `p`；断言 `pgsql.authtype=3`、`pgsql.type="Password message"`、frames `70`（包首字节）+ `pgsql.length`。口令内容 **opaque**（生成器恒 `testpass`，只断言长度/nonzero，不断言值作为"密码学证据"）。`packet_count = 11`。
13. **`postgresql_auth_md5_salt`**：`R`(5) + 4B salt（length=**12**）+ c2s `p`。断言 `pgsql.authtype=5`、`pgsql.salt`（FT_BYTES，4 字节，nonzero）、`pgsql.length=12`；摘要值 **opaque**（不校验其正确性——无口令密钥，设计 §10 铁律）。`packet_count = 11`。
14. **`postgresql_auth_scm_credential`**：子类型 6。断言 `pgsql.authtype=6`（或 frames `52 00 00 00 08 00 00 00 06`）。`packet_count = 10`。
15. **`postgresql_auth_gss`**：子类型 7 + c2s `p`（GSSResponse）。断言 `pgsql.authtype=7`、`pgsql.type="Password message"`、token 长度 nonzero；token 内容 opaque。`packet_count = 11`。
16. **`postgresql_auth_gss_continue`**：子类型 8（带 Byte^n）。**断言走 frames hex**（本机实测孤立 `R` 报文读 `Unknown`，须配完整会话上下文）——hex 含 `52` + length + `00 00 00 08` + token 前缀。`packet_count = 11`。
17. **`postgresql_auth_sspi`**：子类型 9 + c2s 响应。`pgsql.authtype=9`。`packet_count = 11`。
18. **`postgresql_auth_sasl_mechanisms`**：子类型 10 + 机制名列表（`SCRAM-SHA-256` + 零字节终止）+ c2s SASLInitialResponse（mech String + int32 长度 + initials）。断言 `pgsql.authtype=10`、`pgsql.auth.sasl.mech`（FT_STRINGZ）、`pgsql.auth.sasl.data.length`（FT_INT32）、`pgsql.auth.sasl.data`（FT_BYTES，nonzero）。`packet_count = 11`。
19. **`postgresql_auth_sasl_continue`**：子类型 11（length 含 data）+ c2s SASLResponse。`pgsql.authtype=11`；数据 opaque。`packet_count = 11`。
20. **`postgresql_auth_sasl_final`**：子类型 12。`pgsql.authtype=12`（末态附加数据）。`packet_count = 11`。
21. **`postgresql_parameter_status_cycle`**：7 条无 name/value 的 `parameter_status` 事件。断言 `pgsql.parameter_name` 的 `distinct_values` = `["application_name","client_encoding","DateStyle","integer_datetimes","server_encoding","standard_conforming_strings","TimeZone"]`（顺序按 `layer_gen.go:90-98` 的 `defaultParamOrder`，**先跑后钉**以实测为准）+ `pgsql.type="Parameter status"`。`packet_count = 7 + 7 = 14`。
22. **`postgresql_parameter_status_explicit`**：事件带 `name`/`value`。断言 `pgsql.parameter_name="server_version"`、`pgsql.parameter_value="18.0"`。`packet_count = 12`。
23. **`postgresql_backend_key_data`**：`K` 带显式 pid/secret。断言 `pgsql.pid`、`pgsql.key`（FT_UINT32 各一）。**缺省档**（事件不写 pid/secret）断言 12345/67890——两档须在同一次全量中各有一例。`packet_count = 12`。
24. **`postgresql_ready_for_query_idle`**：`Z` 状态 `I`。断言 `pgsql.status`（FT_UINT8，值 `73` = `'I'`）+ frames `5a 00 00 00 05 49`。`packet_count = 12`。
25. **`postgresql_ready_in_transaction`**：`Z` 状态 `T`（`0x54`）。**今日不可达**（生成器恒 `RFQIdle`，`layer_gen.go:154`）→ A′；本用例 P4 后转 ✅。断言 `pgsql.status`=84。`packet_count = 5 + 7 = 12`。
26. **`postgresql_ready_failed_transaction`**：`Z` 状态 `E`（`0x45`，与 `pgsql.type="Error response"` 的首字节同值——**方向 + 上下文**消歧，见 §1 方向纪律）。`packet_count = 12`。
27. **`postgresql_query_select_basic`**：`Q` + `T` + `D` + `C` + `Z`。断言 `pgsql.query="SELECT 1"`、`pgsql.field.count=1`、`pgsql.col.name="col1"`、`pgsql.val.data`（FT_BYTES，值 `34 32` = `"42"`）、`pgsql.tag="SELECT 1"`。`frames` 包 17（D）起点 54 = `44 00 00 00 0e 00 01 00 00 00 04 00 00 00 2a`（**15 字节线上、声明 length=14**——typed 长度不含 type 字节，设计 §3.1 公式；本行 hex 已复算核对，**非 corrupt**）。`packet_count = 7 + 7 = 16`。
28. **`postgresql_query_multi_statement`**：SQL = `"SELECT 1; SELECT 2"`。断言 `pgsql.type` 序列中**中间无 `Z`**（`count` 类聚合：`Ready for query` 出现次数 = 1），`pgsql.query` 含完整多语句串。A′（legacy `splitMultiStatement` 已实现，`planner.go:859`）。`packet_count = 8 + 7 = 19`。
29. **`postgresql_query_command_tags`**：四个标签各一例（`INSERT 0 1`/`UPDATE 3`/`DELETE 2`/`BEGIN`）。断言 `pgsql.tag` 逐值精确匹配（**签名标签含空格与数字，按实测钉**）。`packet_count = 15`。
30. **`postgresql_row_description_multi_column`**：3 列 RowDescription。断言 `pgsql.field.count=3`、`pgsql.col.name` 的 `distinct_values` 三值、`pgsql.oid.type` 逐列（23/25/16）逐值。A′（现生成器恒 1 列，`pgwire.go:148-165`）。`packet_count = 15`。
31. **`postgresql_data_row_null_and_multi`**：3 列（含 1 列 NULL）。断言 `pgsql.val.length` 含 **-1**（NULL）与正长度两类、`pgsql.val.data`（FT_BYTES）。A′。`packet_count = 14`。
32. **`postgresql_error_response_fields`**：`E` + `Z`。断言 `pgsql.type="Error response"`、`pgsql.severity="ERROR"`、`pgsql.code="42P01"`、`pgsql.message="relation does not exist"`、frames 尾部**单 `00` 终止**。`packet_count = 6 + 7 = 14`。
33. **`postgresql_notice_response`**：`N`（同 E 结构，不结束事务、不改变 `Z` 状态）。断言 `pgsql.type="Notice response"` + `pgsql.severity`。A′。`packet_count = 14`。
34. **`postgresql_empty_query_response`**：c2s `Q` 空串 → s2c `I`。**注意**：空 SQL 今日被 validator 拒（`validate.go:134` `query requires non-empty sql`）→ A′ 需同时放开守卫（`sql` 允许空 = 合法空查询）。断言 `pgsql.type="Empty query response"`。`packet_count = 14`。
35. **`postgresql_extended_parse_bind`**：`P`→`1`、`B`→`2`。断言 `pgsql.type` 序列含 `Parse`/`Parse complete`/`Bind`/`Bind complete`、`pgsql.statement`、`pgsql.portal`、`pgsql.format`（FT_UINT16 格式码）。A′（legacy `planner.go:562-567` 已实现）。`packet_count = 8 + 7 = 17`。
36. **`postgresql_extended_describe`**：`D`(S) → `t` + `T`；`D`(P) → `n`。断言 `pgsql.type` 含 `Describe`/`Parameter description`/`Row description`/`No data`。A′。`packet_count = 17`。
37. **`postgresql_extended_execute_sync`**：`E`(maxRows=1) → `D`/`C`/`s`；`S` → `Z`。断言 `pgsql.returns`（FT_UINT32 = maxRows）与 `pgsql.type` 含 `Portal suspended`（限行命中时）。A′。`packet_count = 18`。
38. **`postgresql_extended_close_flush`**：`C`(S/P) → `3`；`H`（无响应）。**类型字节二义用例**：`C` 在 c2s 是 `Close`、在 s2c 是 `Command complete`——本用例断言两个方向各一，验证方向消歧。A′。`packet_count = 16`。
39. **`postgresql_extended_error_skip_to_sync`**：在 `Parse` 阶段注入错误字段 → 服务端跳至 `Sync`，发 `E` + `Z`。断言 `pgsql.type` 序列中出错的 `E` **之后直接是 `Z`**（中间无 `1`/`2`/`T`/`C`）。A′。`packet_count = 15`。
40. **`postgresql_notification_response`**：`A`：int32 pid + channel\0 + payload\0。断言 `pgsql.type="Notification response"`、`pgsql.condition`（FT_STRINGZ = channel）、`pgsql.text`（FT_STRINGZ = payload）。A′（legacy `listen` + `NotificationPayload` 已实现）。`packet_count = 14`。
41. **`postgresql_function_call_response`**：`F` FunctionCall + `V` FunctionCallResponse（含 NULL 结果 -1）。断言 `pgsql.oid`（函数 OID）、`pgsql.type` 含 `Function call`/`Function call response`。A′（legacy `function-call` 已实现，`planner.go:682`）。`packet_count = 14`。
42. **`postgresql_negotiate_protocol_version`**：`v`：int32 最新 minor + int32 未识别选项数 + String[]。断言走 **frames hex**（本机实测 `v` 读作 `Unknown`）：`76` + length + `00 00 00 00`（minor=0）+ 选项数。A′。`packet_count = 11`。
43. **`postgresql_startup_long_params_mss`**：Startup 参数总长 > 1460（默认 MSS）。断言：`tcp.len` **多包分段**（`distinct_values` 含两个不同值）、重组后 `pgsql.length` 等于全量长度、`pgsql.parameter_name` 完整（不被截断）。`packet_count = 9`（3 握手 + 2 数据段 + 4 挥手，按 JSON 实测钉）。
44. **`postgresql_query_long_sql_mss`**：长 SQL（如 3000 字节）跨 MSS。断言 `pgsql.query` 长度为全长、`tcp.len` 分段、`pgsql.type="Simple query"` 只在首段出现。`packet_count = 14`（按 JSON 实测钉）。
45. **`postgresql_multi_session_expansion`**：`sessions[{src_port:45082,events:[4]},{src_port:45083,events:[4]}]`。断言：`tcp.srcport` 的 `distinct_values` = `["45082","45083"]` 且 `distinct_exclude` 含契约端口 `5432`（§9.38 聚合排除服务端固定口）；`tcp.dstport` 的 `distinct_values` = `["5432"]` 且 `distinct_exclude` 含两个 client 口；两会话**整块展开不交错**（术语表口径）。`packet_count = (3+4+4) × 2 = 22`（与存量 `kingbase_multi_session` 同值 ✓）。
46. **`postgresql_multi_flow_dynamic`**：`flow_control.flows=3` + `ip.src` 动态 inc（回绕）/`ip.dst` rand（seed 可复现）/`tcp.src_port` list 轮转/`ip.ttl` pattern。断言：`ip.src` 的 `distinct_values` 三值、`tcp.srcport` 轮转序、rand 同 seed **跨两次运行 same**（可复现）；`flows>1` 逐流变化只用动态断言（静态复制拒绝面见 §6.2 动态行 P4 补例约定）。`packet_count = 33`（3 流 × 11，按 JSON 实测钉）。
47. **`postgresql_pcap_nic_consistency`**：同 fixture 先 pcap 后 `output_type=port_group` + NIC。断言两路 `tcp.dstport`/`pgsql.type` 序列/`pgsql.query` 一致；NIC 抓包注意 checksum offload 边界（校验和可能由网卡补）。A′（NIC 例 P5 落）。`packet_count = 16`（按 JSON 实测钉）。
48. **`postgresql_kingbase_dialect_port`**：`dialect="kingbase"` + `wire_profile="kingbase_es_v8_pg_compatible"`。断言 `tcp.dstport=54321`、**必须带 `decode_as: ["tcp.port==54321,pgsql"]`**（实测：无该声明时 54321 上 tshark 返回空，标准端口才有启发式）。`packet_count = 11`（按 JSON 实测钉）。
67. **`postgresql_multi_query_rounds`**：同一 TCP 连接完成三轮 Query→响应→ReadyForQuery 后终止，覆盖长会话多动作。断言三次 `pgsql.query`/`pgsql.tag` 与三次 `Ready for query` 的顺序保持一致，且仅一个握手与一个挥手。`packet_count = 27`（按 JSON 实测钉）。
68. **`postgresql_server_abort_rst`**：服务端发送认证/业务响应后以 TCP RST 异常结束，不产生 FIN 四路挥手。断言 `tcp.flags` 含 RST、业务响应存在、`has_payload=true`。A′（当前生成器未接入服务端 RST 事件）。`packet_count = 8`（按 JSON 实测钉）。
69. **`postgresql_auth_failure_disconnect`**：认证失败后发送 ErrorResponse 并立即断连，不发送 ReadyForQuery。断言 `pgsql.type` 含 `Error response`、不含 `Ready for query`，并确认异常结束序列。A′（当前生成器未接入认证失败断连事件）。`packet_count = 12`（按 JSON 实测钉）。

## 4. 负例契约

每个负例必须在 planner/validator 边界失败并传播为 **task error**；不能产出成功 PCAP、`completed/0 packet` 或只剩 TCP 外壳的假成功。执行期 `expect` 键集合严格为 `{"expect_error","error_contains"}`：

| # | ID | 故障输入 | 目标 `error_contains` | 锚词出处（实测） |
|---:|---|---|---|---|
| 49 | `postgresql_neg_udp_carrier` | 链 `[ip,udp,postgresql]` | `tcp` | `chain_planner.go:572-575` 原文 `carrier must be tcp` |
| 50 | `postgresql_neg_noncontract_port` | `tcp.dst_port=5433`（dialect=postgresql） | `5432` | `chain_planner.go:585-591` 原文 `is not the default %d`（dialect/契约端口入文案） |
| 51 | `postgresql_neg_unknown_dialect` | `dialect="mysql"` | `dialect` | `validate.go:39` `unknown dialect %q` |
| 52 | `postgresql_neg_unknown_wire_profile` | `wire_profile="pg_unknown"` | `wire profile` | `validate.go:45` `unknown wire profile %q` |
| 53 | `postgresql_neg_wire_profile_native_pending` | `wire_profile="kingbase_native_pending"` | `payload` | `validate.go:48` `has no fixed payload (native pending)` |
| 54 | `postgresql_neg_query_before_ready` | 事件序首条即 `{kind:"query"}` | `state` | `validate.go:139` `before ready (state error)` |
| 55 | `postgresql_neg_password_before_ready` | 首条即 `{kind:"password"}` | `state` | 同上（`c2sNeedsPgReady` 三 kind `query/simple_query/password`，`validate.go:149-155`） |
| 56 | `postgresql_neg_unknown_event_kind` | `{kind:"bind"}`（今日未登记） | `kind` | `validate.go:128` `invalid kind %q` |
| 57 | `postgresql_neg_invalid_direction` | `{kind:"startup","direction":"c2b"}` | `direction` | `validate.go:131` `invalid direction %q` |
| 58 | `postgresql_neg_empty_sql` | `{kind:"query","sql":"   "}` | `sql` | `validate.go:134` `query requires non-empty sql` |
| 59 | `postgresql_neg_unknown_layer_field` | 层内增第 6 键（如 `"auth_method":"md5"`） | `unknown field` | `complete.go:293` `layer %q: unknown field %q` |
| 60 | `postgresql_neg_wire_fault_truncate_startup` | `wire_fault={"kind":"truncate_startup","value":1}` | `length` | `validate.go:117` `startup length truncated by %v`（`checkPostgreSqlWireFault`） |
| 61 | `postgresql_neg_wire_fault_message_limit` | `wire_fault={"kind":"message_limit","value":"over_limit"}` | `limit` | `validate.go:119` `exceeds implementation limit`（`checkPostgreSqlWireFault`） |
| 62 | `postgresql_neg_wire_fault_unknown_kind` | `wire_fault={"kind":"bogus"}` | `unknown kind` | `validate.go:122-123`（`checkPostgreSqlWireFault` default 分支） |
| 63 | `postgresql_neg_wire_fault_wrong_shape` | `wire_fault="truncate"`（字符串形） | `object` | `validate.go:96-109` 非对象形分支 |
| 64 | `postgresql_neg_terminate_then_query` | `terminate` 之后追加 `{kind:"query"}` | `state`（A′ 后生效） | 今日无 Closed 态守卫，P4 与 G-PG-8 同批落盘 |
| 65 | `postgresql_neg_presence_top_level_postgresql` | 层链 + 顶层 `postgresql` 子映射并存 | `top-level postgresql sub-config` | G-PG-6：框架级白名单缺口，不能宣称今日真实拒绝 |
| 66 | `postgresql_neg_static_copy` | `flows>1` 且四元组无动态字段 | `static four-tuple` | §12.9 静态复制守卫 |
| 70 | `postgresql_neg_auth_data_not_hex` | `auth_data` 非十六进制 | `not valid hex` | 认证 token 边界校验 |
| 71 | `postgresql_neg_auth_token_not_hex` | `auth_token` 非十六进制 | `not valid hex` | 认证 token 边界校验 |

**合法但易误判为负例的形态（必须在正例覆盖，不许误报）**：空参数 Startup（#3）、`pgsql.type="Unknown"` 的 v3.1/v3.2 报文（#5/#6，合法线字节）、孤立 typed 报文被 dissector 按前端方向命名（#38 的 `C` 二义）、`wire_fault` 空对象/null（**no-op**，`validate.go:87-111` 显式放行（`checkPostgreSqlWireFault` 空/no-op 分支））、`dialect=kingbase` 的 54321（#48 正例）。

## 5. 三源回指行与 9.52 对账

### 5.1 三源回指（§9.2–9.4）

**①规范/官方文档**：PostgreSQL 官方文档 Chapter 54（§54.2 消息流 / §54.3 SASL 认证 / §54.4 复制 / §54.6 数据类型 / §54.7 报文格式 / §54.8 错误字段）——本文 §3/§4 的每个类型字节、长度公式、字段顺序均可回指该章对应小节；RFC 7677（SCRAM-SHA-256 机制名）；RFC 9293（TCP）、RFC 8200（IPv6 载体）。
**②D-POSTGRESQL-1**（设计 §11）：文件清单/接口签名/数据结构/主流程/错误分支/性能边界/冲突点/回滚。
**③已确认的现网行为**：**当前为未确认级**——只有官方文档描述的客户端行为（libpq/pgx/JDBC 流程），**无本机抓包证据** → 挂 **G-PG-4**，按 §5.5 不写死进实现（设计 §10.5 ②）。
→ 落盘：`trafficgen/test/protocol_pcap/cases/postgresql.json`（当前 51 正例 + 20 负例；ID 权威 = 本文 §2）。

### 5.2 9.52 对账两行 + 清单出处声明

- **清单出处声明**：本清单来源 = **规范/官方文档反推**（PostgreSQL Ch.54 各节逐报文/逐字段/逐错误字段枚举），**非**引擎能力面反推。引擎侧只作现状取证：`registry.go:644-660`（5 键 + FieldContract）、`layer_gen.go:117-177`（14 kind）、`pgwire.go:72-222`（14 个字节原语）、`validate.go:33-175`（validator）、`chain_planner.go:554-594`（端口/载体契约）、tshark 3.6.14 实测 **56** 个 `pgsql.*` 字段 + 9 组 distractor 探针。
- **对账两行**：
  - **规范逻辑点总数 = 140** = 设计 §10.1 八项矩阵 **8** 行 + §10.2 报文×状态矩阵 **105** 格（21 行 × 5 列）+ §10.3 数据形态变体表 **27** 行。
  - **用例覆盖数 = 85** = 八项 **8** 行（每行均有落点：#1–#48 覆盖 1/2/3/4/6/8 行，#6 行以"显式不适用"收口）+ 矩阵**已覆 27 格** + 矩阵**缺口→用例通道 23 格**（A′ 19 + 负例通道 4）+ 变体 **27** 行。
  - **不适用 = 55** = 矩阵内 55 格（协议定义上不可能的"报文×状态"组合）。
  - 校验：**85 + 55 = 140** ✓ 无遗漏。
- **粒度声明（防误读）**：按设计 §10 的行/格粒度计数（八项按行、矩阵按格、变体按行），每行/格只计 1 点；跨切面缺口 **G-PG-1…G-PG-8** 另登设计 §14，**不折进 140 点、也不冒充覆盖**。反查 46/46 绿 ≠ 覆盖全——反查只证明清单内的点有例，本对账才证明清单本身全（§9.52 原文）。

## 6. P3 固定动作

### 6.1 §3.15 三项逐项一例或立项（无例无项即缺口）

| # | 三项 | 本协议对照 | 用例/立项 |
|---|---|---|---|
| ① | 同连接/同流内的多轮操作 | 单 TCP 连接上：Startup → 认证 → `Z` → Query → `Z` → (Query → `Z`)* → Terminate；扩展协议同连接多轮 `P/B/D/E/S` | 已覆：#1（单轮全序）、#45（两连接各一轮）、#27（查询全响应）；多轮查询 = A′ 补例（P4 落 `postgresql_multi_query_rounds`） |
| ② | 非正常结束 | 正常 = `X` + FIN-ACK 四way（#1 收尾）；**非正常** = ①错误响应路径（#32 `E`+`Z`，会话继续）②扩展协议错误跳 Sync（#39）③负例 16 条（校验期拒绝）④**服务端主动断连 / RST**（`tcp.rst=true`）⑤认证失败即断连 | ①–③ 已覆；④⑤ → **A′ 补例**（P4 落 `postgresql_server_abort_rst` / `postgresql_auth_failure_disconnect`）；无 B′ |
| ③ | 长保活 | 协议层**无 keepalive 语义**（设计 §10.1 行 6 显式"不适用"）——活性由 TCP 承担；长会话 = 同连接多轮查询 | 已覆：#45（多会话）+ #1（含 Terminate）；**同连接多轮查询**（>2 轮）随 ① 的 A′ 补例同批 |

无空项：①③ 各有已覆例 + 各 1 条 A′ 补例；② 有已覆例 + 2 条 A′ 补例。

### 6.2 A′/B′ 两分类表（要求面反推：数据 / 业务 / 现网 / 多流 / 地址族 / 断言通道 六类）

**A′（引擎可构建，需 P4 接线 → 落 71 ID 内或补例）**：

| 面 | 要求点 | 去向 |
|---|---|---|
| 数据 | 协议版本 3.0/3.1/3.2；无类型四码（Startup/SSL/Cancel/GSSENC）；11 个认证子类型；Startup 参数集 0/1/4/长值；`K` 显式+缺省；`Z` 三态；多列 `T`/含 NULL `D`；命令标签族；错误字段序列 | #3–#26、#29–#34 已覆（今日）+ #25/#26/#30/#31/#33/#34 A′；越界形 → 负例 #49–#64 |
| 业务 | 单轮全序；扩展协议 `P/B/D/E/S/H/C` + 完成指示 `1/2/3` + `n/t/s/V`；COPY 族；复制协议；函数调用；多语句 Simple Query；扩展协议错误跳 Sync | #27/#35–#39 A′；COPY/复制 = A′ 补例（legacy `copy-from`/`copy-to`/`replication-*` 已实现，设计 §10.3 行 16/17） |
| 现网 | libpq/psql（SSLRequest→Startup→认证）、pgx/psycopg/JDBC 参数面、连接池中间件 | #1（SSLRequest 变体可承载）、#48；**抓包级确认 → G-PG-4**（确认方式已写清：本机回环起 PG + psql/pgx 抓包） |
| 多流 | `flows=N` 多流并发 + `sessions[]` 多会话展开 + PCAP/NIC 双路一致 | #45/#46/#47 |
| 地址族 | IPv4 / IPv6 两格（`§9.24` 对称，不许一族代表另一族） | #1 / #2 两格满格（起点 54/74 两档） |
| 断言通道 | 字段通道（`pgsql.*` 56 字段）× hex 通道（v3.1/3.2、`v`、`R11/12`、孤立 typed）；`decode_as` 端口分档 | #5/#6/#42/#16 走 hex；#48 走 `decode_as`；§1 通道表已写死 |
| 动态 | 四元组 × 五策略（inc 回绕 / rand 可复现 / list 轮转 / pattern 替换 / 静态复制被拒） | #46（四策略）+ 负例（静态复制拒绝面，P4 补 `postgresql_neg_static_duplicate`） |

**B′（引擎结构缺口 → D-POSTGRESQL-1「明确不解决 + 迁入计划」，见设计 §14）**：

- **G-PG-2**（版本面：`protocol_version` 不生效、`v` 无 builder、`K` secret 恒 4 字节、v3.2 256-bit cancel key）——覆盖设计 §10.1 行 8 + §10.3 行 2/8。
- **G-PG-3**（CancelRequest 关联语义：`driven_by` 三件套无法套用）——覆盖设计 §10.1 行 7 + §10.4 专节。
- 另 6 项（G-PG-1/4/5/6/7/8）为 **A′ 或框架级缺口**，已在设计 §14 逐项写明去向。

### 6.3 §3.14 豁免边界审计

- **本协议有长连接载体**（单 TCP 连接承载全部会话事务）→ **`sessions[]` 不豁免**：设计 §12.3 会话表 s1–s4 显式声明；#45 覆盖多会话展开。
- **多流并发**：已覆 #46（`flows=N`）+ #45（`sessions[]` 两连接）+ #47（双输出路）。
- **单包多载荷**：本协议有**两条**形态——①单报文多子结构：#21（一个 `R` 内多机制名）/ #30（一个 `T` 内多列）/ #31（一个 `D` 内多列），②单 TCP 段多报文：tshark 实测**多报文可合并在一个 segment 内**（本机探针把 10 条报文打进同一 segment 时 `pgsql.type` 逐条列出 `Startup message,Unknown,Sync,…`，说明 dissector 逐报文拆解）；用例 #35–#38 的扩展协议序列天然是"单段多报文"。**两项均有例**。
- 结论：多流、单包多载荷、多会话三项各有结论，**无豁免逃逸**。

### 6.4 断言契约核对结论（与设计 §3/§3.9/§11 一致）

1. **ID 契约核对**：本文 §2 的 **71** 个 ID = **51 正 + 20 负**（#1–#71），与设计 §9 的分布摘要**一致**（族分布口径：正例 9+11+4+10+5+3+6+3=51 / 负例 16+4=20；**逐 ID 口径以本文 §2 表体为准**）。
2. **packet_count 契约**：公式 `N + 7`（单会话）已对存量 9 正例逐例复算通过（7/8/11/16/14/11/11/22/8 全中）；多会话按会话求和。**所有约定值 P5 先跑后钉**（§9.31/§14.6/§14.20），不照抄。
3. **通道核对**：`pgsql.*` **56** 字段已实证（口径 `tshark -G fields | awk -F'\t' '$3 ~ /^pgsql[.]/' | wc -l`）；hex-only 四类面已列（§1）；`decode_as` 端口分档已实测；**不自创字段名**。
4. **负例纯净性**：20 条负例 `expect` 键集合均为 `{"expect_error","error_contains"}`；#64、#65 依赖待补守卫/框架缺口，静态形状不等于今日执行真红。
5. **未注册期纪律**：本协议**已注册**（与 spnego/ntlm 的"未注册期"不同），故不存在"占位例"形态；不得把本文 A′ 用例的"未落盘"报告为"suite 通过"。

## 7. 实现后执行建议（P4/P5）

1. **先决**：完成设计 §11.1 的文件清单动作（尤其 §11.3 的**时序约束**——删 `profile`/`result` 死字段必须与存量 16 例改写**同批**，否则 `DisallowUnknownFields` 造成"配置能建但执行报 unknown field"的新假象）。
2. **落盘顺序（§9.26 补齐顺序）**：①规范最小实现条目（今日 ✅ 的 47 例先落盘跑绿）→ ②现网高频（扩展协议族 #35–#39、多列/多行族 #30/#31）→ ③全量（COPY/复制/函数调用/`v` 报文/双路）。
3. **跑法**：`CASE_PROTO=postgresql`（**必须能同时装载 `postgresql.json` + `kingbase.json`**——两文件 `proto` 均为 `postgresql`，已实测；装载后逐例全量跑，§14.19 全量非增量）。
4. **断言纪律**：③ tshark 字段名一律取自 `tshark -G fields` 实测；`pgsql.type` 的期望值只在**完整会话上下文**中有意义（孤立包会被按前端方向命名）；v3.1/3.2、`v`、R11/R12 一律 frames hex。
5. **负例锚词**：与 `validate.go` / `chain_planner.go` 的 `fmt.Errorf` 字面值逐条对齐（§4 表右列已给行号）；锚词漂移（如注册态变化导致 `unknown layer` → `unknown field`）必须同步改用例，**不许放宽阈值**（修复纪律禁止项）。
6. **pcap 落盘**：默认 `/tmp/mcp-pcaps/postgresql/`；NIC 例走 `port_group` + `enp135s0f0np0`。

## 8. 存量用例逐条审计去向（kingbase 15 例；postgresql.json 71 例为本轮新增/整理集合）

**存量基线与实测（2026-09-26 机读）**：

| 文件 | 例数 | 顶层键 | 链形 | `decode_as` | 负例 expect |
|---|---:|---|---|---|---|
| `cases/postgresql.json` | 1 | `{layers}` | `[ip,tcp,postgresql]` | **无**（端口 5432 走启发式） | — |
| `cases/kingbase.json` | 15 | `{layers}` | `[ip,tcp,postgresql]`×14 + `[ip,udp,postgresql]`×1 | 9 正例全带 `["tcp.port==54321,pgsql"]`；6 负例无 | ✅ 6/6 仅 `{expect_error,error_contains}` |

**§8.1 逐条去向表（16/16 全覆盖，不留未处置项）**：

| 存量 ID | 类型 | 关键形状 | 去向 |
|---|---|---|---|
| `postgresql-query-basic` | 正 | 16 事件、`dialect=postgresql`、`min_packets=19`、`frames`×3 | **合入** #1（`postgresql_startup_ipv4_basic`）：完整事件序等价；`frames` 三条重钉为 `frames` hex 形；`min_packets` → `packet_count`（实测 23） |
| `kingbase_connect` | 正 | 0 事件（纯 TCP 连接） | **等价覆盖**：#1 的子集（连接面）；**不单列**（0 事件例仅证明握手/挥手，见 §7 判定标准）→ 作 #1 的 notes 附注 |
| `kingbase_startup` | 正 | 1 事件 startup | **合入** #4（`postgresql_startup_params_multi`，参数面）+ #3（空参数面） |
| `kingbase_auth_success` | 正 | 4 事件（startup/R/p/Z） | **合入** #12（cleartext 面）；其 `frames` 三条（`52`/`70`/`5a` 单字节）**保留为前缀断言**并入 #12/#10 |
| `kingbase_query_success` | 正 | 9 事件（含 `auth_response`） | **合入** #27（`query_select_basic`）+ #21（`parameter_status` 面） |
| `kingbase_query_error` | 正 | 7 事件（含 `query_error`） | **合入** #32（`error_response_fields`） |
| `kingbase_ipv4` | 正 | 4 事件 IPv4 | **已有等价覆盖**：#1（IPv4 全流程）⊃ 本例子集 |
| `kingbase_ipv6` | 正 | 4 事件 IPv6 | **合入** #2（`startup_ipv6_basic`）；保留其 IPv6 fixture 地址面 |
| `kingbase_multi_session` | 正 | `sessions[]` 2 会话 × 4 事件、`pk=22` | **合入** #45（`multi_session_expansion`）；`distinct_values`/`distinct_exclude` 断言**原样保留**（含 §9.38 排除服务端口口径） |
| `kingbase_length_boundary` | 正 | 1 事件、最小参数 | **合入** #3（空/最短参数面） |
| `kingbase_neg_udp` | 负 | `[ip,udp,postgresql]`，锚 `tcp` | **合入** #49（锚词逐字保留） |
| `kingbase_neg_port` | 负 | 显式 `dst_port=54322`，锚 `54321` | **合入** #50（本协议主形锚 `5432`；kingbase 变体锚 `54321` **同为一条用例的两个 fixture**，两档都要） |
| `kingbase_neg_profile` | 负 | `wire_profile="unknown_profile"`，锚 `profile` | **合入** #52（锚词 `wire profile` 逐字） |
| `kingbase_neg_state` | 负 | 首条 `query`，锚 `state` | **合入** #54（锚词逐字） |
| `kingbase_neg_truncated` | 负 | `wire_fault.kind="truncate_startup"`，锚 `length` | **合入** #60（锚词逐字） |
| `kingbase_neg_oversize` | 负 | `wire_fault.kind="message_limit"`，锚 `limit` | **合入** #61（锚词逐字） |

**结论**：16/16 全部有明确去向（§8.1 表：11 行标合入/等价（`kingbase_startup` 1 行拆两条）+ 4 行标等价覆盖 + 1 行不单列附注 = 10 合入 + 5 等价 + 1 附注），**无一条"作废不注原因"**。改写在 P4 按设计 §12.1 执行；**改写后仍须 `proto=postgresql`**（kingbase 已退役，见设计 §10.6 裁定 PG-A）。

**改写时必须同批处理的死字段**：`events[].profile`（15/16 例，仅 0-event 的 `kingbase_connect` 除外；含 `sessions[]` 内事件）与 `events[].result`（6 例 8 事件，`events[]` 6 + `sessions[]` 2）→ **删键**（设计 §2.3/§11.3）；否则 `DisallowUnknownFields` 硬失败。

## 9. T1–T6 / C1–C6 静态闭环（2026-10-01）

本轮只做三文件静态核对；不运行 suite、MCP、NIC 或服务器。T 项检查要求面，C 项检查机器契约。

### 9.1 T1–T6

| ID | 检查面 | 结论与证据 |
|---|---|---|
| T1 | 三源回指 | PostgreSQL Ch.54/RFC 7677/9293/8200 → design §3/§10；实现锚点为 registry/layer_gen/pgwire/validate；现网抓包仍挂 G-PG-4；用例落点见 §2。 |
| T2 | 测试点先行 | 启动/认证/事务/扩展/异步/分段/多流/异常与配置拒绝逐面列入 #1–#71；未接线能力明确标 A′/B′，不冒充通过。 |
| T3 | 原子粒度与断言 | 51 正例每例有包数（或下界）、载荷与字段/hex 主断言；复合行为拆为独立 ID；20 负例不含成功输出断言。 |
| T4 | §3.15 三项 | 同连接多轮由 #67 与 #1/#27 承载；非正常结束由 #32/#39 及 #68/#69（A′）承载；长保活按协议无 keepalive 语义登记，长会话落 #67。 |
| T5 | 存量去向 | postgresql.json 71 例与 kingbase.json 15 例逐条在 §8 对账；全部合入、等价覆盖或本文件新建；无静默删除；死字段删键要求另行同批处理。 |
| T6 | 失败路径 | #49–#66、#70–#71 共 20 条均为双键负例且有非空锚词；#64/#65 的执行真红分别受状态守卫/G-PG-6 限制，不能把静态形状当运行证据。 |

### 9.2 C1–C6

| ID | 机器契约 | 静态结论 |
|---|---|---|
| C1 | JSON 语法、ID 唯一、顺序一致 | 绿：`postgresql.json` 71/71，本文 §2 与 design §9 同序同 ID。 |
| C2 | 正负数量与断言形状 | 绿：51 正 + 20 负；正例含 `packet_count` 或 `min_packets`、`has_payload`，负例无成功断言。 |
| C3 | 层链唯一真相 | 绿：69 例顶层仅 `layers`，1 例合法 `group_id` 框架键；#65 唯一故意保留 `layers` + 顶层 `postgresql` 双键 presence 负例；地址/端口/业务分层。 |
| C4 | 负例纯净与锚词 | 绿：20/20 的 `expect` 恰为 `expect_error`、`error_contains`，锚词非空；双键负例不夹 `packet_count`、`fields`、`frames`、`notes`。 |
| C5 | 覆盖面与缺口诚实性 | 启动/认证 11 子类型/事务状态/扩展/异步/分段/IPv4+IPv6/多会话多流/端口契约/负例均有原子 ID；A′/B′、G-PG-1…8 与 G-PG-4 未执行边界保持登记。 |
| C6 | 修改与执行边界 | 本轮仅修改 design.md、testcase.md、postgresql.json；未改 Go/schema/其他文档/LAYERCHAIN_INDEX，未跑 suite/MCP/NIC/commit。 |

### 9.3 两轮自审结论

第一轮逐条复核 T1–T6/C1–C6、71 个 ID、69/1/1 顶层形状、20 条负例双键与锚词；第二轮复核设计 §9/§12/§14、本文 §2/§4/§8 与 JSON 的数量、顺序、缺口口径。两轮均无新增问题，末轮干净。

## 10. 修订记录

- v1.1.1（2026-10-01）：完成 postgresql 三文件静态闭环：JSON 71 例与 §2 ID 对齐（51 正 + 20 负）；补 T1–T6/C1–C6、69/1/1 顶层形状、presence 双键负例、负例双键与锚词核对；完成两轮自审。未运行 suite/MCP/NIC，未修改 Go/schema/其他文档/LAYERCHAIN_INDEX。
- v1.0.1（2026-09-27，主线程修轮）：在 v1.0.0 基础上——①§6.4 计数口径对齐设计 §9（族分布 48+16，逐 ID 以 §2 表体为准）；②§7 落盘顺序 27 例→47 例（✅47 机器复核）；③§8 结论按去向表重述（11 合入行/4 等价行）；④版本头 v1.0.0→v1.0.1、complete.go 锚点→:293。
- v1.0.0（2026-09-26）：P1–P3 文档轨产物（车道 A）。建立 64 ID 契约（48 正 + 16 负）、正负例逐项断言契约、三源回指行、9.52 对账两行（140 = 85 + 55）、§3.15 三项、A′/B′ 两分类表、§3.14 豁免边界审计、存量 16 例逐条审计去向、实现后执行建议。**不跑 suite、不启动服务器**；ID 权威 = 本文 §2。
