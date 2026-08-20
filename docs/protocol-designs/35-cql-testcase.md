# CQL/Cassandra Native Protocol（CQL/Cassandra 原生协议）测试用例设计

> 版本：v1.0.0（设计阶段）  
> 日期：2026-08-20  
> 配套设计：`docs/protocol-designs/35-cql-design.md`  
> 机器契约：`trafficgen/test/protocol_pcap/cases/cql.json`  
> 状态：`cql` 层尚未实现；本文定义实现后的 PCAP（抓包文件）断言，不宣称当前套件可运行。

## 1. 测试原则

用例从设计 §1（v4/v5、认证边界）、§2（层链/配置）、§3（9 字节 native frame）、§4（状态）、§5（失败处理）及 §6（包数/偏移）逐项派生。正例必须有 `packet_count`、TCP 握手/终止断言和至少一个 `fields` 或 `frames`；负例 `expect` **只能**有 `expect_error` 与 `error_contains`，不对失败 PCAP 作结构断言。

frame 头为 `version|flags|stream(2)|opcode|length(4)`；IPv4 无 option 时 payload 起点为 54，IPv6 为 74。`tcp.len` 是 TCP payload 字节数，等于 9+native body length。固定 hex 只锚定可复算外层，不把数据库真实执行结果、认证摘要、SASL 私有 challenge、压缩或 v5 metadata 当作事实。

## 2. 包数公式和索引

`packet_count = 3（TCP 握手） + 应用事件数 + 4（TCP 正常终止）`。每个小型事件一段；ACK 不计为应用事件。

| # | id | 类型 | 覆盖 | 应用事件 | 包数 |
|---:|---|---|---|---:|---:|
| 1 | `cql_v4_startup_ready` | 正 | v4 STARTUP→READY | 2 | 9 |
| 2 | `cql_options_supported` | 正 | OPTIONS→SUPPORTED multimap | 2 | 9 |
| 3 | `cql_auth_empty_sasl` | 正 | AUTHENTICATE/AUTH_RESPONSE/AUTH_SUCCESS | 3 | 10 |
| 4 | `cql_query_void` | 正 | STARTUP/READY/QUERY/RESULT VOID/READY | 5 | 12 |
| 5 | `cql_prepare_execute` | 正 | PREPARE/EXECUTE 请求 | 2 | 9 |
| 6 | `cql_error_server` | 正 | 合法 ERROR 应用响应 | 1 | 8 |
| 7 | `cql_ipv6` | 正 | IPv6 v4 会话 | 4 | 11 |
| 8 | `cql_v5_tracing` | 正 | v5 version 和 flags | 4 | 11 |
| 9 | `cql_multi_session` | 正 | 两条独立 session | 4 | 18 |
| 10 | `cql_length_boundary` | 正 | length=0 OPTIONS | 1 | 8 |
| 11 | `cql_connect` | 正 | TCP connect，无应用事件 | 0 | 7 |
| 12 | `cql_neg_udp` | 负 | UDP 载体 | — | — |
| 13 | `cql_neg_version` | 负 | 未登记 profile/version | — | — |
| 14 | `cql_neg_opcode` | 负 | 非法 opcode | — | — |
| 15 | `cql_neg_length` | 负 | 声明长度超过 body | — | — |
| 16 | `cql_neg_state` | 负 | READY 前 QUERY | — | — |
| 17 | `cql_neg_limit` | 负 | 超过 frame 上限 | — | — |

## 3. 正例契约

### 3.1 `cql_v4_startup_ready`（T-CQL-S1）

v4 profile，客户端 STARTUP（`CQL_VERSION=3.0.0`）后服务端 READY，9 包。packet 4 的 frame offset 54 为：

```text
04 00 00 00 01 00 00 00 16 00 01 00 0b 43 51 4c 5f 56 45 52 53 49 4f 4e 00 05 33 2e 30 2e 30
```

packet 5 为 `84 00 00 00 02 00 00 00 00`。STARTUP 的 string map 使用 short count=1；READY body 为空。断言 tcp.len 分别为 31 和 9。

### 3.2 `cql_options_supported`（T-CQL-S2）

OPTIONS 空 body 后 SUPPORTED multimap，9 包。packet 4 offset 54：`04 00 00 00 05 00 00 00 00`，tcp.len=9。packet 5 是包含 `CQL_VERSION` 和 `COMPRESSION` 的显式 multimap，tcp.len=61；只固定 short count、键和值的可复算字节，不推断服务器支持列表以外的压缩行为。

### 3.3 `cql_auth_empty_sasl`（T-CQL-S3）

`cql_v4_auth` profile，服务端 AUTHENTICATE、客户端零长度 AUTH_RESPONSE、服务端 AUTH_SUCCESS，10 包。packet 4 为 opcode `0x03` 和 authenticator string；packet 5 offset 54 为：

```text
04 00 00 00 0f 00 00 00 04 00 00 00 00
```

其中 length=4、bytes length=0。packet 6 为 `84 00 00 00 10 00 00 00 04 00 00 00 00`。空 SASL bytes 只覆盖 framing 边界，不是密码或认证成功依据；AUTH_SUCCESS 的私有 token 不固定。

### 3.4 `cql_query_void`（T-CQL-S4）

STARTUP→READY→QUERY→RESULT VOID→READY，12 包。packet 6 QUERY 文本为 `INSERT INTO ks.t (k) VALUES (1)`，frame offset 54，tcp.len=50；packet 7 RESULT VOID，frame 为：

```text
84 00 00 00 08 00 00 00 04 00 00 00 01
```

两次 READY 后状态边界明确。结果不包含 rows/metadata，因此不编造列类型、paging state 或真实写入效果。

### 3.5 `cql_prepare_execute`（T-CQL-S5）

两个 c2s 请求，9 包。PREPARE 的 long string 是 `SELECT v FROM ks.t WHERE k = ?`；EXECUTE 使用 `[short bytes]` 的 `pid-1`、consistency=1、flags=0。两帧 offset 54 由 JSON 完整锚定；不隐式制造 PREPARE response，prepared metadata 和 bound values 留作 profile 边界。

### 3.6 `cql_error_server`（T-CQL-S6）

单个合法 s2c ERROR，8 包。frame offset 54：version=`0x84`、opcode=`0x00`、code=`0x00000000`、message=`server error`，tcp.len=27。该 ERROR 是协议内应用结果，不应设置 `expect_error`；具体错误详情字段不作跨版本承诺。

### 3.7 `cql_ipv6`（T-CQL-S7）

v4 profile、IPv6 地址、STARTUP→READY→QUERY→RESULT VOID，11 包。packet 4/5 的 frame offset 为 74，且 `ipv6.version=6`、端口 9042；头布局与 IPv4 完全相同，只改变以太网帧内 payload 起点。

### 3.8 `cql_v5_tracing`（T-CQL-S8）

v5 profile，STARTUP（`CQL_VERSION=5.0.0`）→READY→QUERY→RESULT VOID，11 包。QUERY frame 的 version=`0x05`、flags=`0x02`、opcode=`0x07`、tcp.len=27；v5 beta、tracing response UUID、result metadata 不从 flags 猜测，当前只锁定 header 和基础 QUERY body。

### 3.9 `cql_multi_session`（T-CQL-S9）

两个独立四元组，源端口 12345/12346，各自 STARTUP→READY，18 包。断言源端口 distinct values 为 12345/12346、目的端口为 9042；不按全局 PCAP 序号推断两流交错顺序，stream/state 只在每流内关联。

### 3.10 `cql_length_boundary`（T-CQL-S10）

单个 OPTIONS，body length=0，完整 frame 为 9 字节，8 包。该例证明 `length=0` 合法，不把空 body 当作截断；packet 4 `tcp.len=9`，frame offset 54 断言完整头。

### 3.11 `cql_connect`（T-CQL-S11）

仅 TCP 9042 握手和正常终止，7 包；不隐式生成 STARTUP。packet 1 目的端口 9042，`has_payload=false`。

## 4. 负例契约

负例 expect 严格只有两个键，错误必须由 planner/validator 传播到 task error：

| id | 输入故障 | `error_contains` |
|---|---|---|
| `cql_neg_udp` | `layers=[udp,cql]` | `tcp` |
| `cql_neg_version` | `wire_profile=cql_v3` | `version` |
| `cql_neg_opcode` | `wire_fault.kind=opcode,value=255` | `opcode` |
| `cql_neg_length` | `wire_fault.kind=length,value=declared_gt_body` | `length` |
| `cql_neg_state` | 首个事件直接 QUERY | `state` |
| `cql_neg_limit` | `wire_fault.kind=message_limit,value=over_limit` | `limit` |

`wire_fault` 只表示配置校验注入，不允许生成损坏但成功的 PCAP。若实现最终错误文本不同，须先同步 design、testcase、JSON、audit 四方。

## 5. 三方一致性检查清单

1. 本文、设计 §6 和 JSON 都是 17 个唯一 id，顺序一致。
2. 正例包数严格为 `[9,9,10,12,9,8,11,11,18,8,7]`；负例不出现 `packet_count`。
3. 正例均有 `has_handshake=true`、`terminates=true`；除 `cql_connect` 外均有 `has_payload=true` 和至少一个 frame/field。
4. IPv4 frame offset 只用 54，IPv6 只用 74；所有偏移都从数据包 4 或之后的应用包开始。
5. v4/v5、方向位、opcode、length、OPTIONS 空 body、AUTH_RESPONSE 空 bytes、QUERY flags 均有 observable；私有 SASL/压缩/metadata 不写固定事实。
6. 负例 expect 只能是 `expect_error` + `error_contains`。

## 6. 实现后执行建议

先运行 JSON 语法、hex（十六进制）解析、三方 id/包数/负例键静态检查；层注册后依次跑 v4 header、OPTIONS/SUPPORTED、auth、QUERY/VOID、PREPARE/EXECUTE、ERROR，再跑 IPv6/v5/多会话。MSS 分段必须通过 TCP stream 重组断言。取得认证或 Cassandra 版本 fixture 后，再增加 profile-specific challenge、metadata 和 compression 用例，不把当前边界改成猜测。

## 7. 修订记录

- v1.0.0（2026-08-20）：建立 11 个正例和 6 个负例；覆盖 CQL v4/v5、STARTUP/OPTIONS/READY/SUPPORTED、认证 bytes 边界、QUERY/PREPARE/EXECUTE/RESULT/ERROR、IPv4/IPv6、多会话、frame length/非法 opcode/状态/UDP/上限负例。
