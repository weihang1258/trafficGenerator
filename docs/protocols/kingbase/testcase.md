# KingBase（人大金仓）测试用例设计

> 版本：v1.2.0（dialect 变体；历史套件对账）  
> 日期：2026-10-01  
> 修订：2026-10-01（按当前代码和 JSON 机器契约校正）  
> 配套设计：`docs/protocols/kingbase/design.md`  
> 机器契约：`trafficgen/test/protocol_pcap/cases/kingbase.json`  
> 状态：KingBase 身份**已退役而非被阻断**；没有独立 generator/layer，15 例均通过 `proto="postgresql"` + `dialect="kingbase"` 复用共享 postgresql wire。本文和 JSON 是静态契约；本轮未运行 suite、PCAP 或 NIC 验证。

## 1. 测试原则

用例从设计 §1（证据等级/profile）、§2（TCP/端口）、§3（Startup 和 typed message 外层）、§4（配置校验）及 §5（包数/偏移）逐项派生。正例必须有 `packet_count`、TCP 握手/终止断言和至少一个 observable（可观察）`fields` 或 `frames`；负例的 `expect` **只能**有 `expect_error` 与 `error_contains`，不对失败 PCAP 作结构断言。

所有正例以 **postgresql 层 + `dialect="kingbase"`** 表达（`layers: [ip, tcp, postgresql]`，`dst_port` 由 dialect 经 FieldContract 决定 54321），并显式使用 `wire_profile=kingbase_es_v8_pg_compatible`，该名称是版本化实现契约，不是线上字符串。PostgreSQL-compatible 外层允许观察 `pgsql.type`、`pgsql.query` 和传输字段；认证子类型、密码摘要、错误字段、KingBase 私有扩展和参数值不写固定 hex。Startup 只用 tshark 的 `pgsql.type=Startup message`、端口和非空 payload 断言，避免把未核实的参数长度变成伪精确 fixture。

无 TCP option 且应用事件一段时，`packet_count=3+应用事件数+4`；IPv4 应用起点 54，IPv6 起点 74。frame offset 只用于已知的外层 type 字节：Startup 无 type，不在 offset 54 伪造 type；typed message 的 type 位于起点（54/74）。

## 2. 用例索引和包数

> 每个用例的 spec_json 均写为 `layers: [{"ip":{"src","dst"}}, {"tcp":{"src_port"}}, {"postgresql":{"dialect":"kingbase","wire_profile":...,"events":[...]}}]`；不再出现顶层平铺 `src_ip`/`dst_port`/`kingbase` 子块，也不出现独立 `kingbase` 层。

| # | id | 类型 | 覆盖 | 应用事件 | 包数 |
|---:|---|---|---|---:|---:|
| 1 | `kingbase_connect` | 正 | TCP connect、默认端口 | 0 | 7 |
| 2 | `kingbase_startup` | 正 | Startup v3 外层、默认端口 | 1 | 8 |
| 3 | `kingbase_auth_success` | 正 | auth request/response、Ready | 4 | 11 |
| 4 | `kingbase_query_success` | 正 | Startup→auth→Ready→Query→Row description/Data row/Command completion→Ready | 9 | 16 |
| 5 | `kingbase_query_error` | 正 | Query→Error→Ready | 7 | 14 |
| 6 | `kingbase_ipv4` | 正 | IPv4 兼容会话 | 4 | 11 |
| 7 | `kingbase_ipv6` | 正 | IPv6 兼容会话 | 4 | 11 |
| 8 | `kingbase_multi_session` | 正 | 两个独立会话/源端口 | 8（2×4） | 22 |
| 9 | `kingbase_length_boundary` | 正 | Startup 最小合法参数边界 | 1 | 8 |
| 10 | `kingbase_neg_udp` | 负 | UDP 载体 | — | — |
| 11 | `kingbase_neg_port` | 负 | 非标准目的端口 | — | — |
| 12 | `kingbase_neg_profile` | 负 | 未登记 profile | — | — |
| 13 | `kingbase_neg_state` | 负 | Ready 前 Query | — | — |
| 14 | `kingbase_neg_truncated` | 负 | Startup 长度/截断 | — | — |
| 15 | `kingbase_neg_oversize` | 负 | 超出消息上限 | — | — |

## 3. 正例契约

### 3.1 `kingbase_connect`（T-KB-S1）

仅生成 TCP 连接和正常终止，不增加未经配置的应用消息。IPv4、源端口 12345、目的端口 54321，预期 7 包。packet 1/2/3 应观察 SYN、SYN-ACK、ACK；packet 1 的 `tcp.dstport=54321`。该例证明 connect 是传输事件，不把它误写成额外 KingBase 应用 header。

### 3.2 `kingbase_startup`（T-KB-S2）

配置一个 `startup` 事件，profile=`startup_v3`，用户和数据库名为显式配置值，使用 `kingbase_es_v8_pg_compatible`。预期 8 包。packet 4 的 `pgsql.type=Startup message`、`tcp.dstport=54321` 且 `tcp.len` 非零。Startup 无 type 字节，故不在 frame offset 54 写入假定的 `Q/R/Z`；length 和 protocol version 由兼容 profile 的编码单测验证。

### 3.3 `kingbase_auth_success`（T-KB-S3）

事件顺序为 Startup（c2s）、Authentication request（s2c）、Authentication response（c2s）、Ready（s2c），预期 11 包。packet 4 `pgsql.type=Startup message`；packet 5 `pgsql.type=Authentication request`；packet 6 的 dissector 解码值为 `Password message`（设计 §3.2 的 `p` 类别）；packet 7 `pgsql.type=Ready for query`。不对 packet 5 的认证子类型、salt、packet 6 的密码/摘要写 hex；这些由 auth profile 决定。Ready 的具体 status 只在实现有 profile 证据时增加断言。

### 3.4 `kingbase_query_success`（T-KB-S4）

事件顺序为 Startup、Authentication request、Authentication response、Ready、Query(`SELECT 1`)、Row description、Data row、Command completion、Ready，预期 16 包。packet 8 `pgsql.type=Simple query` 且 `pgsql.query=SELECT 1`；packet 9/10/11 分别为 `Row description`、`Data row`、`Command completion`；packet 12 为 `Ready for query`。列元数据、行值和 command tag 的 KingBase 版本细节不固定，事件 profile 只承诺 PostgreSQL-compatible 外层类别。

### 3.5 `kingbase_query_error`（T-KB-S5）

与成功例共享 Startup、认证和 Ready 前置；Query 为 `SELECT missing_column FROM missing_table`，随后发送单一 `query_error` 事件和 Ready，预期 14 包。packet 8 `pgsql.type=Simple query` 且 query 文本可见；packet 9 的 dissector 解码值为 `Error`（本机 tshark 3.6.14 的 pgsql.type 口径，设计 §3.2 的 `E` 类别）；错误字段、SQLSTATE、文本、KingBase 错误码不固定。packet 10 `pgsql.type=Ready for query`，证明错误响应后状态事件仍可观察；若某 profile 规定错误后断开，应另设 profile/case，不修改该例语义。

### 3.6 `kingbase_ipv4`（T-KB-S6）

IPv4、目的端口 54321，事件为 Startup、Authentication request、Authentication response、Ready，预期 11 包。packet 4 `ip.version=4`、`tcp.dstport=54321`、Startup；packet 5 为 Authentication request，packet 7 为 Ready。该例只守护 IPv4 载体和外层事件，不重复断言认证私有字节。

### 3.7 `kingbase_ipv6`（T-KB-S7）

源 `2001:db8::1`、目的 `2001:db8::2`，目的端口 54321，事件同 IPv4，预期 11 包。packet 4 `ipv6.version=6`、`tcp.dstport=54321`、Startup；packet 5/6/7 的外层类型分别为 Authentication request/response/Ready。若无 TCP option，typed message 的 TCP payload 起点为 offset 74；Startup 仍无 type，不能在 offset 74 断言类型字节。

### 3.8 `kingbase_multi_session`（T-KB-S8）

两个独立会话，源端口 12345 与 12346，目的端口均 54321；每条流各发送 Startup→Authentication request→Authentication response→Ready，预期 22 包（每条 11 包）。只断言 `tcp.srcport` 的 distinct values（去重值）为 12345/12346 且排除 54321，`tcp.dstport` 只有 54321；不按全局 PCAP packet 序号推断两个 session 的交错顺序。每条流的事件状态必须独立，不能把一条流的 auth response 配到另一条流。

### 3.9 `kingbase_length_boundary`（T-KB-S9）

使用 `startup` profile 的最小合法非空参数集合（不写固定长度或私有参数 hex），预期 8 包。packet 4 `pgsql.type=Startup message`、`tcp.len` 非零且目的端口 54321。设计验证器必须额外断言编码后的 `length` 等于实际 Startup payload 字节数；PCAP case 不把版本参数长度伪装成 KingBase 跨版本常量。

## 4. 负例契约

负例的 `expect` 严格只有两个键；错误必须从 planner/validator 传播到任务错误终态：

| id | 输入故障 | `error_contains` |
|---|---|---|
| `kingbase_neg_udp` | `layers=[ip,udp,postgresql]`（dialect=kingbase） | `tcp` |
| `kingbase_neg_port` | `tcp.dst_port=54322`（dialect=kingbase 强制 54321） | `54321` |
| `kingbase_neg_profile` | `wire_profile=unknown_profile` | `profile` |
| `kingbase_neg_state` | 首个应用事件直接为 Query | `state` |
| `kingbase_neg_truncated` | Startup `wire_fault.kind=truncate_startup` | `length` |
| `kingbase_neg_oversize` | `wire_fault.kind=message_limit,value=over_limit` | `limit` |

`wire_fault` 是测试注入入口，不是合法线上配置；禁止用它生成损坏但“成功”的 PCAP。若实现采用不同稳定错误文本，必须先同步 design、testcase、JSON 和 audit 四方，再运行 suite；不能把断言放宽为任意失败。

## 5. 三方一致性检查

1. 本文、设计 §5、JSON 三者的 15 个 id 集合和顺序一致。
2. 正例包数严格为 `[7,8,11,16,14,11,11,22,8]`；负例没有 `packet_count`。
3. 每个正例有 `has_handshake=true`、`terminates=true`；有应用事件的正例另有 `has_payload=true`；`kingbase_connect` 只观察 TCP connect。
4. 正例 frame offset 仅在已知 typed message 上使用 IPv4 54/IPv6 74；Startup 不伪造 type offset。JSON 的字段断言应优先使用 `pgsql.*` 外层解码字段。
5. 认证子类型、盐、摘要、SQL 扩展、错误码和私有参数不出现在固定 hex；profile 名和版本边界在 spec_json 中显式出现。
6. 负例 `expect` 只能包含 `expect_error` 和 `error_contains`，不能混入 fields/frames/packet_count。

## 6. 实现后执行建议

先执行 JSON 语法、id/包数/负例结构静态检查；层注册后先跑 S1/S2/S3 验证端口、Startup 和认证外层，再跑成功/错误查询，最后跑 IPv4、IPv6、多会话和 Startup 边界。负例必须确认错误从 planner 经 task handler 传播至错误终态。取得具体 KingbaseES 版本 fixture 后，再逐 profile 增加认证和 SQL 结果字段，不能把 PostgreSQL 参考字节直接复制为 KingBase 断言。

## 7. 修订记录

- v1.1.0（2026-08-26）：按 `34-kingbase-design.md` v1.1.0（postgresql 层 dialect 变体）同步改写——用例由独立 `kingbase` 层 + 顶层平铺，改为 `layers: [ip, tcp, postgresql]` + `postgresql.dialect="kingbase"`；负例 `kingbase_neg_udp` 改为 `[ip,udp,postgresql]`，`kingbase_neg_port` 改为 `tcp.dst_port=54322`。15 个用例 id、包数、断言语义（packet_count/fields/frames/decode_as `tcp.port==54321,pgsql`）全部不变。
- v1.0.0（2026-08-20）：建立 9 个正例和 6 个负例；覆盖 TCP connect/Startup/auth/query success/query error、IPv4/IPv6、多会话、长度边界及负例，并以 profile 隔离版本/兼容模式。


## 8. T1–T3 三源回指与测试点清单

### 8.1 三源回指（T1）

| 测试面 | 规范/官方来源 | 设计条目 | 现网状态与确认方式 | 用例 |
|---|---|---|---|---|
| TCP/54321 | KingbaseES 产品配置口径；TCP 规范 | design §8.1 行 1、§2 | 当前无版本化 pcap；G-KB-1：固定版本回环抓包 | S1/S2 |
| Startup/typed 外层 | PostgreSQL Frontend/Backend Protocol v3 Startup 与 message framing | design §3、§8.1 行 2–3 | 共享 PG 外层；G-KB-1 复核 KingBase 版本差异 | S2–S7/S9 |
| 会话状态 | PostgreSQL message flow | design §3.3、§8.1 行 4 | 生成器状态校验；固定服务端抓包待补 | S3–S5/N4 |
| 载体/端口/Profile 错误 | 设计校验规则 | design §4、§10 | validator 锚词是当前证据 | N1–N3 |
| IPv4/IPv6/多会话 | TCP/IP 规范与共享层行为 | design §8.1 行 6–7 | 当前 cases 双地址族/双会话；NIC 复核列入 G-KB-3 | S6–S8 |

### 8.2 测试点清单矩阵（T2/T3）

| 规范点 | 业务场景 | 代码分支/入口 | 缺口或断言 |
|---|---|---|---|
| TCP-only | UDP carrier | postgresql carrier validator | N1 必须含 tcp 锚词 |
| dialect 端口 | 54321 默认、54322 拒绝 | dialect FieldContract + port validator | S1–S9 fields；N2 error_contains |
| Startup length | 最小参数、截断、超限 | pgwire Startup + wire_fault validator | S2/S9/N5/N6 |
| auth/ready/query 状态 | 成功认证、查询成功/错误、Ready 前 query | event state validator | S3–S5/N4 |
| address family | IPv4 与 IPv6 | ip layer + TCP | S6/S7 version/offset |
| session isolation | 两源端口独立会话 | sessions[] expansion | S8 distinct ports |

颗粒度采用一个 ID 一个行为点；数据类覆盖空/非空/边界/截断，业务类覆盖连接/认证/成功查询/错误查询/多会话，现网类全部标为 G-KB-1 待确认而不冒充已验证。动态整格按设计 §12：四元组的 fixed/inc/rand/list/pattern 是公共层能力；本 JSON 只使用 fixed 与 sessions[]，其余策略对应 G-KB-8 立项，不用静态复制冒充动态覆盖。字段断言使用 `fields`，已知 type 字节才使用 `frames`；错误例只断言错误终态。

## 9. T4 会话三项与 T5 存量审计

| CORE §3.15 面 | 当前覆盖/立项 | 用例 |
|---|---|---|
| 同连接多轮操作 | 查询成功链覆盖一轮；多轮查询作为 G-KB-4 追加例立项 | S4 |
| 非正常结束 | query error、validator 拒绝和截断/超限错误；服务端 RST 作为 G-KB-5 追加例立项 | S5、N1–N6 |
| 长保活 | 协议无独立 keepalive 字段；沿 TCP 生命周期；长会话实测作为 G-KB-6 追加例 | S8 |

存量 15 例逐条去向：`kingbase_connect`→T-KB-S1；`kingbase_startup`→S2；`kingbase_auth_success`→S3；`kingbase_query_success`→S4；`kingbase_query_error`→S5；`kingbase_ipv4`→S6；`kingbase_ipv6`→S7；`kingbase_multi_session`→S8；`kingbase_length_boundary`→S9；六个 `kingbase_neg_*`→T-KB-N1–N6。全部合入，无作废例；JSON summary 已逐例带同一 T 编号。

## 10. T6 失败路径和对账结论

六个负例均只有 `expect_error` 与 `error_contains`，分别触发 UDP carrier、非契约端口、未知 profile、非法状态、Startup 截断和消息上限；锚词来自 validator/planner 稳定错误面，目标是 task error 而非 completed/0 packet。正例均有 packet_count、握手/终止和 fields 或 frames 可观察断言。

退役语义核对：这些例子不等待独立 KingBase generator。`chain_planner_translate.go:2243-2282` 只将 `postgresql` 层翻译为共享 `PostgreSQLConfig`；`strategy_convert.go:1727-1729` 明确旧 `kingbase` 分支已收敛；`chain_planner.go:662-704` 只在共享 PostgreSQL 载体上按 dialect 选择 54321。因此 `proto="postgresql"` + `postgresql.dialect="kingbase"` 是完成形，不是临时过渡。

三方对账：JSON 共 15 例 = 9 正例 + 6 负例；ID 顺序与本节 T-KB-S1–S9、T-KB-N1–N6 一致；所有 spec_json 顶层键均为 `layers`，无旧扁平字段。现网版本化 pcap、MSS 重组和 NIC 双路仍按 design §14 的 G-KB-1–3 立项，不写成已完成。

**静态闭环声明**：本轮（docs loop）不运行 suite、PCAP 或 NIC——§2–§10 全部是对当前 JSON/代码的静态对账；G-KB-4 记录本轮诚实声明（本轮未执行），与 §9 的 G-KB-4 多轮查询追加例立项是两个编号域（本声明归入 design §14 的 G-KB-4）。

## 11. 修订记录

- v1.2.1（2026-10-01）：收官静态对账——修正 headers（路径、版本日期），§3.3/§3.5/§2 表按 JSON 实际 dissector 口径校正（packet 6=`Password message`，packet 9=`Error`）；追加本轮静态闭环声明。
- v1.2.0（2026-09-30）：按 T1–T6 补三源回指、测试点矩阵、§3.15 三项、15 例逐条去向和负例纯净性对账；cases summary 同步加入 T-KB 编号。
