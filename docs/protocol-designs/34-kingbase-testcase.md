# KingBase（人大金仓）测试用例设计

> 版本：v1.0.0（设计阶段）  
> 日期：2026-08-20  
> 配套设计：`docs/protocol-designs/34-kingbase-design.md`  
> 机器契约：`trafficgen/test/protocol_pcap/cases/kingbase.json`  
> 状态：`kingbase` 层尚未实现；本文定义实现后的 PCAP（抓包文件）断言，不宣称当前套件可运行。

## 1. 测试原则

用例从设计 §1（证据等级/profile）、§2（TCP/端口）、§3（Startup 和 typed message 外层）、§4（配置校验）及 §5（包数/偏移）逐项派生。正例必须有 `packet_count`、TCP 握手/终止断言和至少一个 observable（可观察）`fields` 或 `frames`；负例的 `expect` **只能**有 `expect_error` 与 `error_contains`，不对失败 PCAP 作结构断言。

所有正例显式使用 `wire_profile=kingbase_es_v8_pg_compatible`，该名称是版本化实现契约，不是线上字符串。PostgreSQL-compatible 外层允许观察 `pgsql.type`、`pgsql.query` 和传输字段；认证子类型、密码摘要、错误字段、KingBase 私有扩展和参数值不写固定 hex。Startup 只用 tshark 的 `pgsql.type=Startup message`、端口和非空 payload 断言，避免把未核实的参数长度变成伪精确 fixture。

无 TCP option 且应用事件一段时，`packet_count=3+应用事件数+4`；IPv4 应用起点 54，IPv6 起点 74。frame offset 只用于已知的外层 type 字节：Startup 无 type，不在 offset 54 伪造 type；typed message 的 type 位于起点（54/74）。

## 2. 用例索引和包数

| # | id | 类型 | 覆盖 | 应用事件 | 包数 |
|---:|---|---|---|---:|---:|
| 1 | `kingbase_connect` | 正 | TCP connect、默认端口 | 0 | 7 |
| 2 | `kingbase_startup` | 正 | Startup v3 外层、默认端口 | 1 | 8 |
| 3 | `kingbase_auth_success` | 正 | auth request/response、Ready | 4 | 11 |
| 4 | `kingbase_query_success` | 正 | Startup→auth→Ready→Query→Row description/Data row/Command completion→Ready | 9 | 16 |
| 5 | `kingbase_query_error` | 正 | Query→Error response→Ready | 7 | 14 |
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

事件顺序为 Startup（c2s）、Authentication request（s2c）、Authentication response（c2s）、Ready（s2c），预期 11 包。packet 4 `pgsql.type=Startup message`；packet 5 `pgsql.type=Authentication request`；packet 6 `pgsql.type=Authentication response`；packet 7 `pgsql.type=Ready for query`。不对 packet 5 的认证子类型、salt、packet 6 的密码/摘要写 hex；这些由 auth profile 决定。Ready 的具体 status 只在实现有 profile 证据时增加断言。

### 3.4 `kingbase_query_success`（T-KB-S4）

事件顺序为 Startup、Authentication request、Authentication response、Ready、Query(`SELECT 1`)、Row description、Data row、Command completion、Ready，预期 16 包。packet 8 `pgsql.type=Simple query` 且 `pgsql.query=SELECT 1`；packet 9/10/11 分别为 `Row description`、`Data row`、`Command completion`；packet 12 为 `Ready for query`。列元数据、行值和 command tag 的 KingBase 版本细节不固定，事件 profile 只承诺 PostgreSQL-compatible 外层类别。

### 3.5 `kingbase_query_error`（T-KB-S5）

与成功例共享 Startup、认证和 Ready 前置；Query 为 `SELECT missing_column FROM missing_table`，随后发送单一 `query_error` 事件和 Ready，预期 14 包。packet 8 `pgsql.type=Simple query` 且 query 文本可见；packet 9 `pgsql.type=Error response`；错误字段、SQLSTATE、文本、KingBase 错误码不固定。packet 10 `pgsql.type=Ready for query`，证明错误响应后状态事件仍可观察；若某 profile 规定错误后断开，应另设 profile/case，不修改该例语义。

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
| `kingbase_neg_udp` | `layers=[udp,kingbase]` | `tcp` |
| `kingbase_neg_port` | `dst_port=54322` | `54321` |
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

- v1.0.0（2026-08-20）：建立 9 个正例和 6 个负例；覆盖 TCP connect/Startup/auth/query success/query error、IPv4/IPv6、多会话、长度边界及负例，并以 profile 隔离版本/兼容模式。
