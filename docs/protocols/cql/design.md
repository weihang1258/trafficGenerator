# CQL/Cassandra Native Protocol（CQL/Cassandra 原生协议）设计文档

> 版本：v2.1.0（CORE 对齐审计版）  
> 日期：2026-09-30  
> 状态：P1 八项规范矩阵（§9）+ 三子表 + 三路对照与候选方案（§10）+ 门1 §1–§14 十四行表（§11，§1/§3/§12 强制展开）+ P2 D-CQL-1 代码设计草稿（§12）+ P3 对接清单与缺口立项（§13）已落盘；P6 同步已完成。**`cql` 层已注册、builder/planner/layer_gen 已落码**（`registry.go:1081`，`internal/protocol/cql/` 共 770 行〔builder 316 + planner 184 + layer_gen 78〕+ 单测 `cql_test.go` 1192 行 60 函数），机器契约现为 30 例（15 正 + 15 负），W1 已按 profile 修正，W2 已收窄为握手后 envelope 拒绝。本契约不修改 Go 实现。  
> 配套文件：`docs/protocols/cql/testcase.md`、`trafficgen/test/protocol_pcap/cases/cql.json`；历史审查存档 `docs/protocol-designs.bak-root/audit/35-cql-adversarial-audit.md`（v1.0.0 所引 `docs/protocol-designs/audit/` 路径已不存在，属死链，本版更正）。  
> 规范基线：Apache Cassandra native_protocol_v4.spec（**1219 行**）与 native_protocol_v5.spec（**1537 行**），2026-09-26 自 apache/cassandra trunk 取，本稿引用其章节号；字节面以本仓 builder + tshark 实测双证。  
**层链唯一真相**：本契约目标形状只有纯 `layers` 形（`[ip,tcp,cql]`，IPv6 地址仍住 `ip` 层）；地址只住 `ip`、端口只住 `tcp`、数量只走 `flow_control`。P1 时业务配置经顶层 `cql` 子映射旁路；现已完成接线：`registry.go:1081` 具备 4 个 Fields 与 9042 FieldContract，纯 layers 形已跑通，presence/游离键守卫已闭合（G-CQL-1）。存量 17 例的顶层扁平键已按 §11.1 去向表改写。

## 1. 范围、证据等级和 profile（档案）边界

Cassandra Native Protocol（Cassandra 原生协议）在 TCP 上承载 CQL（Cassandra Query Language，Cassandra 查询语言）请求和响应，常见默认目的端口为 **9042**。本版只固定公开、可由消息头和基础 body（消息体）直接复算的 wire（线格式）字段；v4 和 v5 通过显式 profile 区分，不把一个版本的协商结果推广到另一个版本。

| 证据等级 | 本版固定内容 | 不在本版伪造的内容 |
|---|---|---|
| TCP/IP 外层 | TCP、目的端口 9042、四元组、IPv4/IPv6、握手/正常终止 | 服务器真实可达性、集群拓扑 |
| Native frame（原生帧） | version、flags、stream、opcode、length 的位置/宽度/字节序 | TCP stream 重组后的分段数量 |
| v4 profile | request version `0x04`、response version `0x84`，基础 opcode 和 body | 服务端具体版本、压缩协商结果 |
| v5 profile | request version `0x05`、response version `0x85`，显式 v5 头和请求 flag | beta/v5-only result metadata（结果元数据）除非有 fixture（固定样本） |
| 认证 profile | AUTHENTICATE 外层机制字符串、AUTH_RESPONSE bytes（字节串）边界 | SASL（Simple Authentication and Security Layer，简单认证与安全层）私有机制、密码摘要、真实凭据 |

`cql_v4`、`cql_v4_auth`、`cql_v5` 是实现契约名，不是线上字段；profile 名不会编码进 payload（载荷）。同一 session（会话）不能混用 v4/v5 profile。未来支持新版本必须增加独立 profile 和证据，不得静默降级到 v4。

本版不宣称以下内容已定稿：服务器版本、压缩（Snappy/LZ4）、Beta 协商、TLS、SASL challenge/response 的私有字节、prepared metadata（预编译元数据）、绑定值编码、ROWS metadata、paging state（分页状态）、schema 变更语义和真实数据库执行结果。`ERROR` 是协议内可观察的应用响应，不等于 planner（规划器）配置错误。

不变式：

1. `cql` 终结层只能位于 TCP 后，默认目的端口为 9042；UDP、缺少 TCP 或不完整层链拒绝。
2. 每个 native frame 都是 `9 字节 header + length 指定的 body`；`length` 只计 body，不计 header。
3. version 的最高位表示方向：v4 request/response 为 `0x04/0x84`，v5 为 `0x05/0x85`；其余版本必须由 profile 登记。
4. flags 是 1 字节按位字段，stream 是网络字节序有符号 16 位字段，opcode 是 1 字节，length 是网络字节序有符号 32 位线值；长度按实际编码字节数回填。
5. 一个应用事件默认占一个 TCP data segment；MSS（最大报文段长度）分段时 packet_count（包数）和验证必须改用 TCP stream 重组，不能把 segment 当消息。
6. session 状态、stream ID 和请求/响应关联按 TCP 四元组隔离，不能跨会话复用。
7. planner/validator 错误必须传播到 task error（任务错误）终态，不能“完成但 0 包”。

## 2. 层链和配置

**目标形状（纯 layers，唯一合法形状；`flow_control` 为数量唯一住处）**：

```json
{
  "layers": [
    {"ip": {"src": "10.0.0.1", "dst": "20.0.0.1"}},
    {"tcp": {"src_port": 12345, "dst_port": 9042}},
    {"cql": {"wire_profile": "cql_v4", "events": []}}
  ],
  "flow_control": {"flows": 1}
}
```

**1.9 标注：历史 P1 记录**。P1 实测当时（行号真实）：`registry.go` cql 行仅单行注册（`CategoryTerminal + DependsOn ["tcp"]`，**无 FieldContract、无 Fields**，生成表 cql 条目 `fields:{}`），层条目写任何业务键即 `unknown field` 拒；业务配置经**顶层 `cql` 子映射** Meta 直传，属 1.11 白名单外的旁路，`CheckProtoFlat` 无 cql presence 分支未判死。默认目的端口 9042 只在 legacy planner 缺省，链路无 FieldContract 缺省——P4 已按 §12 接线（G-CQL-1 已闭合）。存量 17 例顶层键逐个去向见 §11.1。

注册契约：`cql` 为 TCP terminal（终结层），硬依赖 TCP（`registry.go:1081`）；TCP 的 MSS、初始序列号、握手和终止由公共层处理。每个 event（事件）含 `kind`、`direction` 和该事件的 profile-specific（版本特定）字段。

| 键 | 类型 | 约束 | 语义 |
|---|---|---|---|
| `wire_profile` | string | `cql_v4`、`cql_v4_auth`、`cql_v5` | 显式版本/认证档案 |
| `events` | array | 可为空；按顺序 | 单会话原子事件 |
| `sessions` | array | 与 `events` 二选一 | 多个独立四元组；每项可覆盖源端口和事件 |
| `kind` | enum | 见 §3 | `startup`、`options`、`supported`、`authenticate`、`auth_response`、`auth_success`、`query`、`prepare`、`execute`、`result`、`error`、`ready` |
| `direction` | enum | `c2s`/`s2c` | 客户端到服务端或反向 |
| `flags` | uint8 | profile 允许的位 | header flags；未登记位由 profile 校验 |
| `stream` | int16 | `-32768..32767` | header stream；默认 0；关联由会话状态解释 |
| `query` | string | 仅 QUERY/PREPARE | UTF-8 长字符串，长度按字节 |
| `prepared_id` | bytes/string | 仅 EXECUTE | `[short bytes]` 形式；值是测试 fixture，不表示真实服务端生成 |
| `consistency` | uint16 | 仅 QUERY/EXECUTE | 协议 short 值；不把枚举名猜成版本私有值 |
| `query_flags` | uint32 | 仅 QUERY/EXECUTE | 协议 flags int；未登记高位拒绝 |
| `options` | map | STARTUP/SUPPORTED | string map 或 string multimap |
| `bytes` | bytes | AUTH_RESPONSE/挑战/成功 | `[int bytes]`；空串是合法 framing 边界，不是真实凭据 |
| `wire_fault` | object | 仅负例 | planner 边界故障注入，不表示合法线上帧 |

事件不会隐式增加服务端响应：例如单独的 `prepare` 和 `execute` 正例只锁定请求 framing，不编造 PREPARE RESULT metadata。成功查询响应可以显式配置 `result` 和 `ready`；业务 `error` 仍是合法响应事件。

## 3. Native frame 线格式

每个 frame 从 TCP payload 起点开始：

```text
byte 0   version（方向位 + 版本）
byte 1   flags
byte 2-3 stream（network-order int16）
byte 4   opcode
byte 5-8 length（network-order int32，body 字节数）
byte 9.. body
```

IPv4、无 IP/TCP option 时 frame 起点为 `14 + 20 + 20 = 54`；IPv6 为 `14 + 40 + 20 = 74`。若启用 TCP option 或 IP 扩展头，必须使用解码字段或实际 header length，不得继续套用常量偏移。

### 3.1 本版固定 opcode

| opcode | 名称 | 方向 | body 外层 |
|---:|---|---|---|
| `0x00` | ERROR | s2c | int code + [string message]；具体错误详情待 profile |
| `0x01` | STARTUP | c2s | [string map]：short count + key/value 字符串 |
| `0x02` | READY | s2c | 空 body |
| `0x03` | AUTHENTICATE | s2c | [string authenticator] |
| `0x05` | OPTIONS | c2s | 空 body |
| `0x06` | SUPPORTED | s2c | [string multimap] |
| `0x07` | QUERY | c2s | [long string query] + consistency short + flags int |
| `0x08` | RESULT | s2c | int result kind；VOID=`0x00000001`，其他 metadata 待 profile |
| `0x09` | PREPARE | c2s | [long string query] |
| `0x0A` | EXECUTE | c2s | [short bytes prepared_id] + consistency short + flags int |
| `0x0F` | AUTH_RESPONSE | c2s | [bytes]：int length + bytes |
| `0x10` | AUTH_SUCCESS | s2c | [bytes]；空 bytes 可用于边界 fixture |

`[string]` 是 2 字节长度加 UTF-8 字节；`[long string]` 是 4 字节长度加 UTF-8 字节；`[bytes]` 是 4 字节长度加任意字节。所有长度均按编码后的字节数计算，不按字符数。`AUTH_CHALLENGE (0x0E)` 的私有 SASL payload 只作为待实现边界，不在正例中伪造。

### 3.2 可复算固定样例

v4 `OPTIONS` 是最小完整 native frame：

```text
04 00 00 00 05 00 00 00 00
```

其中 version=`0x04`、flags=`0`、stream=`0`、opcode=`0x05`、length=`0`。

v4 `READY` 响应：

```text
84 00 00 00 02 00 00 00 00
```

v4 `QUERY(

v4 `QUERY("SELECT 1")`（consistency=1、flags=0）的 body 为：

```text
00 00 00 08 53 45 4c 45 43 54 20 31 00 01 00 00 00 00
```

前 4 字节是 long string 长度 8，随后为 ASCII（美国信息交换标准代码）查询文本；其后是 consistency `0x0001` 和 flags `0x00000000`。对应完整 frame：

```text
04 00 00 00 07 00 00 00 12 00 00 00 08 53 45 4c 45 43 54 20 31 00 01 00 00 00 00
```

例中十六进制只固定公开字段；它不承诺数据库真的执行 SQL。

## 4. 状态与事件语义

推荐的 v4/v5 建连顺序为：

```text
TCP handshake → STARTUP → (AUTHENTICATE → AUTH_RESPONSE → AUTH_SUCCESS)?
→ READY → QUERY/PREPARE/EXECUTE → RESULT 或 ERROR → READY → FIN
```

`OPTIONS → SUPPORTED` 可以在认证前作为独立 capability（能力）交换；它不自动代表 STARTUP 已完成。`AUTHENTICATE` 的机制字符串和 `AUTH_RESPONSE` 的 bytes 外层可观察，但 SASL challenge、密码格式和成功 token 必须由 auth profile/fixture 提供。`RESULT` 的 VOID kind 可稳定编码；ROWS、SET_KEYSPACE、SCHEMA_CHANGE 的 metadata 需独立设计。

- 每个事件显式指定方向；planner 不为请求猜测响应，也不为响应补造请求。
- `QUERY`/`PREPARE`/`EXECUTE` 只能在 profile 允许的 session 状态出现；未 STARTUP/READY 的请求拒绝。
- `stream` 关联只在同一 TCP 四元组内有效。跨 session 的相同 stream 值不冲突。
- 应用 `ERROR` 是合法 s2c 结果；`wire_fault`、未知 opcode、非法 version、截断和超限才是 task error。
- `READY` 和 `AUTH_SUCCESS` 的空 body 是完整合法 frame；空 `AUTH_RESPONSE` 是零长度 SASL framing 边界，不是凭据成功证明。

## 5. 校验和失败处理

planner/validator 必须拒绝：

| 错误 | 条件 | 稳定错误锚点 |
|---|---|---|
| 载体 | `[udp,cql]`、缺少 TCP | `tcp` |
| 版本/profile | 未登记 `wire_profile` 或 request/response 版本不匹配 | `version`/`profile` |
| opcode | 不在 §3.1；方向不允许的 opcode | `opcode` |
| 长度 | header 少于 9 字节、length 与 body 不一致、负 length | `length`/`truncated` |
| 字符串/bytes | 长度超过 body、UTF-8 或字段边界非法 | `length`/`value` |
| 状态 | 未 STARTUP/READY 就 QUERY，认证次序错误 | `state` |
| flags | profile 不允许的保留位 | `flags` |
| 上限 | frame 超过实现声明的 `max_frame_bytes` | `limit`/`frame` |
| 端口 | 非标准目的端口 9042（本版未开放 override） | `9042`/`port` |

失败必须在 planner/validator 传播为 task error，不输出损坏 PCAP。应用级 ERROR 不触发 `expect_error`，因为它是合法协议响应。负例 case 的 `expect` 仅包含 `expect_error` 和 `error_contains`。

## 6. 场景与包数

小 payload、一事件一 TCP segment、默认握手/终止时，`packet_count = 3 + 应用事件数 + 4`。IPv4 应用起点为 54；IPv6 为 74。

| 场景 | JSON id | 应用事件 | 包数 | 主要 observable（可观察锚点） |
|---|---|---:|---:|---|
| v4 Startup/Ready | `cql_v4_startup_ready` | 2 | 9 | header/version、STARTUP、READY |
| OPTIONS/SUPPORTED | `cql_options_supported` | 2 | 9 | 空 OPTIONS、SUPPORTED multimap |
| Auth 空 SASL | `cql_auth_empty_sasl` | 3 | 10 | AUTHENTICATE、零长度 AUTH_RESPONSE、AUTH_SUCCESS |
| QUERY/VOID | `cql_query_void` | 5 | 12 | QUERY、RESULT VOID、READY |
| PREPARE/EXECUTE | `cql_prepare_execute` | 4 | 11 | STARTUP/READY 后的两个请求 header/body |
| ERROR | `cql_error_server` | 1 | 8 | ERROR 外层 code/string |
| IPv6 | `cql_ipv6` | 4 | 11 | IPv6 与 offset 74 |
| v5 flags | `cql_v5_tracing` | 4 | 11 | v5 握手前 unframed 面：OPTIONS/SUPPORTED/STARTUP/READY |
| 多会话 | `cql_multi_session` | 2×2 | 18 | 两个源端口/独立四元组 |
| 零长度边界 | `cql_length_boundary` | 1 | 8 | OPTIONS length=0 |
| TCP connect | `cql_connect` | 0 | 7 | 9042、无应用 payload |
| 非零 stream 关联 | `cql_stream_correlation` | 6 | 13 | stream 1/2 请求与乱序响应按 stream 配对 |
| LOCAL_QUORUM 一致性 | `cql_consistency_quorum` | 4 | 11 | consistency=0x0006 大端编码 |
| flags 方向约束 | `cql_flags_tracing_s2c_warning` | 4 | 11 | c2s tracing=0x02、s2c warning=0x08 |
| 同连接多轮查询 | `cql_multi_round_query` | 7 | 14 | 两轮 QUERY/RESULT 后 READY，不重连 |
| UDP 载体负例 | `cql_neg_udp` | — | — | 仅 task error |
| 版本负例 | `cql_neg_version` | — | — | 仅 task error |
| opcode 负例 | `cql_neg_opcode` | — | — | 仅 task error |
| 长度负例 | `cql_neg_length` | — | — | 仅 task error |
| 状态负例 | `cql_neg_state` | — | — | 仅 task error |
| 上限负例 | `cql_neg_limit` | — | — | 仅 task error |
| 顶层 cql 旁路负例 | `cql_neg_presence_top_level_cql` | — | — | presence 判死 |
| 顶层 src_ip 负例 | `cql_neg_stray_src_ip` | — | — | flat 字段判死 |
| 顶层 count 负例 | `cql_neg_stray_count` | — | — | flat 字段判死 |
| 层内未知字段负例 | `cql_neg_unknown_layer_field` | — | — | unknown field 判死 |
| 缺 TCP 载体负例 | `cql_neg_missing_tcp` | — | — | DependsOn 不得掩盖缺失 |
| 缺 CQL_VERSION 负例 | `cql_neg_startup_missing_cql_version` | — | — | STARTUP 必须含 CQL_VERSION |
| 认证顺序负例 | `cql_neg_auth_order` | — | — | AUTH_RESPONSE 前置状态非法 |
| v5 envelope 负例 | `cql_neg_v5_post_handshake_envelope` | — | — | 握手后 v5 消息需 envelope |
| v4 beta flag 负例 | `cql_neg_beta_flag_v4` | — | — | v5-only beta 位拒绝 |

### 6.1 当前机器契约对账（2026-09-30）

`cases/cql.json` 当前为 **30 例 = 15 正 + 15 负**。15 个正例的 `spec_json` 顶层均仅为 `layers`，层链均为 `[ip,tcp,cql]`；15 个负例的 `expect` 均严格为 `expect_error` 与 `error_contains`，不含成功包数或帧断言。正例包数按 JSON 实际值为 `9,9,10,12,11,8,11,11,18,8,7,13,11,11,14`。历史 17 例迁移去向仍见 testcase §8，新增 presence/游离键/层字段/缺 TCP/动态与状态边界例见 testcase §2.1 与 §4。

## 7. 实现完成定义与边界

1. 注册 TCP→`cql` 层，默认端口 9042，拒绝 UDP/缺 TCP/非法端口。
2. 对 frame header 的方向位、flags、signed stream、opcode 和 body length 做逐字段单测；长度按编码字节回填。
3. 对 STARTUP/OPTIONS/SUPPORTED/READY、QUERY/PREPARE/EXECUTE、RESULT VOID、ERROR 和 AUTH bytes 做失败优先单测及 API→engine→PCAP 集成测试。
4. v4/v5 profile 独立校验；IPv4/IPv6、多会话、MSS 分段使用真实输出和重组验证。
5. 认证机制、SASL 私有摘要、压缩、TLS、v5 beta、ROWS metadata、prepared metadata、绑定值和 schema 结果必须取得对应规范/fixture 后单独实现，不以随机或 v4 回退填充。
6. 负例错误必须到达 task error 终态；不能把 planner 错误吞成 completed/0 packets。

## 8. 修订记录

- v2.0.1（2026-09-28，P6 F4 同期同步）：§9.6 W1/W2 标"P4 已处置"（上）；状态机行"状态门只钉 query"改三门 + G-CQL-6 四门全落。
- v2.0.0（2026-09-26）：P1–P3 完整产物。§1/§2 按实测改写（注册/接线现状 + 目标形状 + 1.9 标注）；新增 §9 P1 八项规范矩阵 + 三子表 + 枚举面计数与 9.52 对账 + §9.5/§9.6 现状偏离登记（W1 QUERY flags 宽度、W2 v5 envelope、层链空壳/顶层旁路）；§10 三路对照与候选方案；§11 门1 十四行表（§1/§3/§12 强制展开 + presence 负例形状）；§12 D-CQL-1 八要素；§13 P3 对接清单与 G-CQL-1…8 缺口立项；§14 自重审结论与旧文核对。§3–§7 正文未动（旧文逐条核对见 §14.2）。
- v1.0.0（2026-08-20）：建立 CQL/Cassandra Native Protocol v4/v5 profile 设计；固定 9 字节 header、基础启动/能力/认证外层、查询/预编译/执行请求、VOID/ERROR、IPv4/IPv6、多会话及长度/版本/opcode/状态/UDP/上限负例；明确 SASL/压缩/v5 metadata 等边界。

## 9. P1 规范矩阵（CORE_MEMORY §4 八项：规范要求→业务场景→代码现状→缺口）

> 深度口径（§4.19–4.22）：三张子表在 §9.2–§9.4；枚举面计数与 9.52 对账在 §9.5；现状偏离登记在 §9.6。每条结论三选一：**已实现 / 明确不支持 / 不适用**，不留白。
> **TCP 载体铁律**：cql rides TCP（`registry.go:1081` `DependsOn ["tcp"]`）——链中夹 `udp` 判死（载体族错）；规范明示 CQL 原生协议只跑 TCP（v4 spec §1 Overview："The CQL binary native protocol is a TCP-based ..."）。

### 9.1 八项规范矩阵

| # | 规范要求（v4/v5 spec 条款） | 业务场景 | 代码现状（实测） | 缺口 |
|---|---|---|---|---|
| 1 | **连接模型**：client→server 单 TCP 长连接，默认 9042；TCP 建连即协议通道，无控制/数据分离通道（v4 spec §1；本契约 §1） | 应用连 Cassandra 集群执行 CQL；连接池多会话 | **已实现**：`CategoryTerminal + DependsOn ["tcp"]`（`registry.go:1081`）；终结层事件生成器 `layer_gen.go:34-58`；FieldContract 默认 9042；`sessions[]` 多源端口多流由 `emitSel` SrcPort 覆盖（`layer_gen.go:47-51`） | sessions 多流展开相容性已在 B 轨实测通过；现网证据仍归 G-CQL-8 |
| 2 | **命令/消息表**：16 opcode（0x00–0x10 除 0x04，v4 spec §2.4:183-201）= 8 请求（STARTUP/AUTH_RESPONSE/OPTIONS/QUERY/PREPARE/EXECUTE/BATCH/REGISTER，§4.1）+ 8 响应（ERROR/READY/AUTHENTICATE/SUPPORTED/RESULT/EVENT/AUTH_CHALLENGE/AUTH_SUCCESS，§4.2） | 连接建立、查询、预编译执行、批处理、事件注册、SASL 认证全流程 | **部分已实现（12/16）**：`opcodeForKind` 12 常量（`builder.go:10-24`）+ buildBody 全 12 分支（`builder.go:138-167`）；**REGISTER(0x0B)/EVENT(0x0C)/BATCH(0x0D)/AUTH_CHALLENGE(0x0E) 4 opcode 无实现**；RESULT 仅 VOID kind（`builder.go:148` 恒 `ResultVoid`）；ERROR 仅通用 `int code + string`（`builder.go:161-163`） | 4 opcode + 4 result kind + 17 码条件 detail → **G-CQL-5**（逐项三选一收口） |
| 3 | **状态机**：STARTUP 必为首消息（OPTIONS 可前置，v4 §4.1.1:285-288）；STARTUP→READY 或 AUTHENTICATE→AUTH_RESPONSE→AUTH_SUCCESS→READY；READY 后 QUERY/PREPARE/EXECUTE/BATCH/REGISTER | 握手次序、认证流程、READY 前发业务请求 | **P4 已处置（P6 已验）**：状态门现为 query/prepare/execute 三门（`planner.go:142-146`）+ 认证次序门（`:124-139`，CQL_VERSION 强制 `:118-123`）+ 方向逐 kind 校验；`cql_prepare_execute` 现 4 事件形即 ready 门产物 | G-CQL-6 四门全落（P6 已验） |
| 4 | **字段表**：9 字节 header version/flags/stream(i16)/opcode/length(i32)（§2.1-2.5）；notation [short]/[string]/[long string]/[bytes]/[string map]/[string multimap]/[consistency]（§3）；QUERY/EXECUTE `<query_parameters>`=consistency(short)+**flags（v4 [byte] 1 字节，§4.1.4:346；v5 扩为 [int]，v5 §4.1.4+§9 Changes#4）**；consistency 11 值（§3:249-259）；STARTUP 选项 CQL_VERSION **mandatory**（§4.1.1:292-294） | 字段级字节面全部可复算 | **部分已实现**：buildHeader 逐字段（`builder.go:104-118` 大端正确）；string map/multimap/long string/short bytes 编码齐（`:171-287`）；W1 已按 profile 选宽（`builder.go:183-190`），v4 `query_flags>0xFF` 拒绝（`planner.go:147-151`）；STARTUP CQL_VERSION、flags per-profile 位校验已落码 | G-CQL-7：其余字段形态与更宽断言面 |
| 5 | **错误处理表**：ERROR 17 码（0x0000 Server…0x2400 Already_exists，v4 §4.2.1:499 + §9:1046-1190 逐码条件 detail）；planner 拒：载体/版本/opcode/长度/状态/flags/上限/端口（本契约 §5）；wire_fault 注入 | 脏配置拒收、语法/不可用/超时等真错误面 | **部分已实现**：`checkWireFault` 3 值（opcode/length/message_limit，`builder.go:296-316`）+ 自然守卫（未知 profile `builder.go:92`、未知 kind `:60`、方向 `planner.go:66-90`、状态 `:93-96`、互斥 `:45-47`、IP `:57-63`）；`maxFrameBytes=256KiB`（`builder.go:52`）；6 负例锚词实测全绿（tcp/version/opcode/length/state/limit） | 17 码仅 0x0000 有例、16 码无条件 detail 面 → **G-CQL-5**；上限负例只测配置校验不测线值（§5 表 `limit` 行）→ A′ 补例（G-CQL-7） |
| 6 | **超时与活性**：协议无心跳/保活消息；连接活性由 TCP 层承载；v5 EVENT 为服务器推送（§4.2.6:754） | 长连接保活 | **不适用（生成器语义）**：CQL 无协议级 keepalive 消息，无超时字段可编码；事件流一次性产出 | 无缺口（显式不适用 ≠ 缺口）；TCP keepalive 归 tcp 层 |
| 7 | **NAT/代理/被动模式**：单 TCP 连接内 stream 多路复用，无 FTP/SIP 式衍生数据连接，无被动模式语义；经 NAT 只影响 TCP/IP 寻址 | 集群经 LB/NAT 可达 | 不适用（显式声明）：无 cql 层语义可测 | 无缺口 |
| 8 | **版本/方言**：v4/v5 双 profile；v5 差异面 = envelope 外层 framing（§2.1-2.3）+ QUERY/EXECUTE/BATCH flags [byte]→[int] + 新增 keyspace/now_in_seconds 字段 + duration 类型 + beta flag 0x10（v5 §9 Changes 10 条） | Cassandra 3.x/4.x（v4/v5）、5.x beta | **部分已实现**：3 profile 白名单（`builder.go:85-93` cql_v4/cql_v4_auth/cql_v5）；v5 方向位 0x05/0x85；**W2（违规范）：v5 envelope 未实现——握手后帧仍为裸 v4 形 9 字节头（`cql_v5_tracing` QUERY/RESULT 帧），v5 spec §2.3.1 要求握手后全部 enveloped（6B 头 CRC24 + payload ≤128KiB + CRC32，小端）**；v5 [int] flags 恰好写对（U32）；v5 新增字段（keyspace/now_in_seconds）未实现 | W2 → **G-CQL-3**（实现 envelope 或"v5 收窄为握手前 unframed 面"收口）；v5 字段差异 → G-CQL-3 并入 |

### 9.2 子表①：消息 × 前置状态矩阵（逐格已覆/缺失）

行=消息（opcode），列=状态/方向面。现引擎状态门只有"query before startup/ready"一道（`planner.go:93-96`），其余列多数落 G-CQL-6 校验缺口：

| 消息（opcode） | 合法前置+方向正确 | 前置缺失 | 方向颠倒 | 认证流违规 |
|---|---|---|---|---|
| STARTUP(0x01) | 已覆 S1/S4/S7/S8/S9 | 不适用（首消息） | 已覆（s2c 拒，`planner.go:74`） | 不适用 |
| OPTIONS(0x05) | 已覆 S2/S10（握手前合法） | 不适用 | 已覆（`:74`） | 不适用 |
| SUPPORTED(0x06) | 已覆 S2 | 不适用 | 已覆（c2s 拒 `:79`） | 不适用 |
| READY(0x02) | 已覆 S1/S4 | 不适用 | 已覆（`:79`） | 不适用 |
| AUTHENTICATE(0x03) | 已覆 S3 | 不适用 | 已覆（`:79`） | **缺失**（未认证先 QUERY 不拒）→ G-CQL-6 |
| AUTH_RESPONSE(0x0F) | 已覆 S3 | **缺失**（无 AUTHENTICATE 前置门）→ G-CQL-6 | 已覆 | 同上 |
| AUTH_SUCCESS(0x10) | 已覆 S3 | **缺失** → G-CQL-6 | 已覆 | 同上 |
| QUERY(0x07) | 已覆 S4/S7/S8 | 已覆 N5（`state` 锚词） | 已覆（`:74`） | **缺失**（认证中 QUERY 放行）→ G-CQL-6 |
| PREPARE(0x09) | 已覆 S5（无前置也放行） | **缺失**（未纳 ready 门）→ G-CQL-6 | 已覆 | 同上 |
| EXECUTE(0x0A) | 已覆 S5 | **缺失** → G-CQL-6 | 已覆 | 同上 |
| RESULT(0x08) | 已覆 S4/S7/S8 | 不适用（响应面） | 已覆 | 不适用 |
| ERROR(0x00) | 已覆 S6 | 不适用 | 已覆 | 不适用 |
| REGISTER(0x0B)/EVENT(0x0C)/BATCH(0x0D)/AUTH_CHALLENGE(0x0E) | **明确不支持**（无 kind，未知 kind 拒 `builder.go:60`） | — | — | — |

逐格结论（13 行 × 4 列 = 52 格，逐格枚举可复核）：**已覆 25 格**（合法前置列 12 + 前置缺失列 1〔QUERY←N5〕+ 方向颠倒列 12）；**缺失→用例通道 10 格**（前置缺失列 4：AUTH_RESPONSE/AUTH_SUCCESS/PREPARE/EXECUTE；认证流违规列 6：AUTHENTICATE/AUTH_RESPONSE/AUTH_SUCCESS/QUERY/PREPARE/EXECUTE）→ 全归 G-CQL-6；**明确不支持 1 格**（REGISTER/EVENT/BATCH/AUTH_CHALLENGE 整行合法前置列，4 opcode）；**不适用 13 格**（首消息/响应面无前置 7 + 认证违规列不涉 6）；**"—"空档 3 格**（不支持行的后三列）。25+10+1+13+3 = 52 ✓ **逐格有结论、无空格**。

### 9.3 子表②：数据形态变体表（协议相关全部形态逐项）

| 变体维度 | 形态 | 对应用例 | 结论 |
|---|---|---|---|
| 方向位 | 0x04/0x84（v4）、0x05/0x85（v5） | 全正例 + S8 | 已覆 |
| stream | 0（同步客户端默认）/非零关联 | 全部正例；`cql_stream_correlation` 覆盖 1/2 乱序响应 | 已覆基础非零关联；更宽 stream/交错面归 G-CQL-7 |
| frame flags | 0x00 / 0x02 tracing（v5） | 全例 / S8 | 0x01 compression/0x04 custom_payload/0x08 warning/0x10 beta 4 位无用例 → G-CQL-6/7 |
| consistency | 11 值 0x0000–0x000A | 全部 QUERY/EXECUTE 例恒 1（ONE） | 10 值无用例 → A′ 补例（G-CQL-7） |
| QUERY/EXECUTE flags | v4 [byte] / v5 [int] | 0x00、tracing 0x02、warning 0x08（`cql_flags_tracing_s2c_warning`） | 已覆基础位形；values/paging/serial/timestamp/names 7 位无用例 → G-CQL-7 |
| result kinds | VOID/ROWS/SET_KEYSPACE/PREPARED/SCHEMA_CHANGE | VOID（S4/S7/S8） | 4 kind 明确不支持 → G-CQL-5 |
| error codes | 17 码 | 0x0000（S6） | 16 码无条件 detail → G-CQL-5 |
| 空体 | OPTIONS/READY 空 body、AUTH_RESPONSE/AUTH_SUCCESS 空 bytes | S2/S3/S10 | 已覆（length=0 边界） |
| 字符串边界 | long string 长/短、UTF-8 字节数 | S1/S4/S5 | 超长/截断无用例（配 maxFrameBytes 256KiB）→ A′（G-CQL-7） |
| STARTUP 选项 | CQL_VERSION mandatory / COMPRESSION / NO_COMPACT / THROW_ON_OVERLOAD | CQL_VERSION 全例；SUPPORTED 显式 COMPRESSION | **CQL_VERSION 缺席不拒**（空 map 照发）→ G-CQL-6；NO_COMPACT/THROW_ON_OVERLOAD 无例 → A′ |
| 多会话 | sessions[] 双源端口 | S9（12345/12346） | 已覆；多流展开 B 轨实测通过 |
| 地址族 | IPv4 / IPv6 | 全例 / S7（offset 74） | 已覆 |
| 载体/链形 | [ip,tcp,cql] / [ip,udp,cql]（负） | 30 例全为纯 layers 链形 | 已覆；UDP/缺 TCP 均有判死负例 |
| wire_fault 值面 | opcode/length/message_limit 3 值 | N3/N4/N6 | 3/3 全用例 ✓；其余故障面（如坏 UTF-8）无注入通道 → 明确不支持（自然守卫面） |
| v5 差异面 | envelope / [int] flags / keyspace+now_in_seconds / beta | 仅 version 字节 + flags 位 | W2 → G-CQL-3；新字段/beta 协商 → G-CQL-3 |

### 9.4 子表③：商业行为→用例映射表（§4.16）

| 商业行为（产品 + 出处） | 对应用例 | 无映射项 + 确认方式 |
|---|---|---|
| cqlsh / DataStax driver 连 Cassandra 4.x：TCP 9042 → STARTUP(CQL_VERSION=3.0.0) → READY → QUERY（stream 0 同步面） | S1/S4 | 现网抓包级确认 → **G-CQL-8**（抓 cqlsh↔Cassandra 回环包核对 flags 宽度与 stream 面） |
| 驱动并发流（python-driver/gocql 多 stream 交错，响应乱序按 stream 归并） | 无 | → G-CQL-7（A′：非零 stream + 乱序响应例）+ G-CQL-8 抓包确认 |
| 认证（PasswordAuthenticator：AUTHENTICATE→AUTH_RESPONSE→AUTH_SUCCESS） | S3 | 私有 SASL token 面 → 明确不支持（不伪造） |
| 预编译执行（PREPARE→prepared id→EXECUTE） | S5 | PREPARED 响应 metadata → G-CQL-5（明确不支持收口） |
| 批处理 BATCH / 事件注册 REGISTER / 服务器推送 EVENT | 无 | → G-CQL-5（逐项三选一：实现或明确不支持） |
| Cassandra 5.x v5-beta 接入（envelope framing） | 无（现有 v5 例线面不合规，W2） | → G-CQL-3 + G-CQL-8 抓 5.x 包证 envelope |

### 9.5 枚举面计数与覆盖对账（9.52 两行在此定稿，报告另摘录）

> **清单出处声明**：本清单**由规范原文反推**——native_protocol_v4.spec（1219 行）逐节枚举 + v5.spec（1537 行）§9 Changes 10 条；**不是**从现有用例或引擎能力反推。

| 规范枚举面 | 点数 | 已覆（用例实测） | 缺口去向 |
|---|---:|---|---|
| opcode（§2.4） | 16 | 12 | 4 → G-CQL-5 |
| frame flags（§2.2） | 4 | 2 形（0x00/0x02） | 4 位 → G-CQL-6/7（v5 beta 0x10 另计 G-CQL-3） |
| QUERY/EXECUTE flags（§4.1.4/4.1.6） | 7 | 2 形（0x00/v5 0x02） | 7 位 → G-CQL-7 |
| consistency（§3） | 11 | 1（ONE） | 10 → G-CQL-7 |
| result kinds（§4.2.5） | 5 | 1（VOID） | 4 → G-CQL-5 |
| error codes（§4.2.1+§9） | 17 | 1（0x0000） | 16 → G-CQL-5 |
| 数据类型（§6，6.1–6.23） | 23 | 0（ROWS metadata 不支持） | 23 → G-CQL-5（明确不支持收口） |
| STARTUP 选项（§4.1.1） | 4 | 1（CQL_VERSION，无缺席校验） | 3 → A′/G-CQL-6 |
| v5 差异（v5 §9 Changes） | 10 | 1（flags [int] 恰写对） | 9 → G-CQL-3 |
| **枚举点小计** | **97** | **20** | — |

**9.52 对账两行**：规范逻辑点总数 = **97 枚举点（9 面，出处 v4/v5 spec 原文反推）**；用例覆盖数 = **30 例**（`cases/cql.json` 实测 15 正 15 负），枚举点已覆 20/97 未覆 77 点全部归入 G-CQL-2/3/5/6/7/8 立项或"明确不支持"，无留白。

### 9.6 现状偏离登记（不许抹平）

1. **W1（P4 已处置，P6 已验）**：原违规范——QUERY/EXECUTE `<flags>` 恒写 4 字节；现按 profile 选宽（`builder.go:183-190` v5→U32 否则 1 字节）+ v4 `query_flags>0xFF` 拒绝（`planner.go:147-151`，锚词 `flags`）+ 单测 `TestValidateCQLV4QueryFlagsOverflow`/`TestBuildQueryFlagsWidthByProfile` 绿；2 例重钉帧与 pcap 实字节一致。→ G-CQL-2 closed。
2. **W2（P4 B2 过渡档收口，P6 已验）**：`cql_v5` 握手后消息需 envelope framing（未实现）一律拒（`planner.go:68-71` 白名单 + `:114-116` 握手后拒，锚词 `envelope`）+ 负例 `cql_neg_v5_post_handshake_envelope` + 单测 `TestValidateCQLV5PostHandshakeRejected` 绿；`cql_v5_tracing` 现形为握手前 4 事件（options/supported/startup/ready）。→ G-CQL-3 open 状态与实现一致（envelope 另轮立项），无冒充 v5。
3. **层链接线与顶层旁路：**`registry.go:1081` 已补 4 个 Fields 与 9042 FieldContract，`translateTerminalConfig` 已接线，纯 layers 形已跑通；presence/游离键守卫已闭合。。
4. **`result_kind` 死字段：**已经按 D1 删除；当前 30 例和 wire 面不再消费该键。。
5. **断言面**：30 例中已有 `cql.*` 协议字段断言（`cql_stream_correlation`、`cql_consistency_quorum`、`cql_flags_tracing_s2c_warning`、`cql_multi_round_query`），其余更宽断言面仍归 G-CQL-7。。

## 10. 三路对照（§4.12–4.15）与候选方案对比（§4.17）

### 10.1 三路对照

**①规范原文**：Apache Cassandra native_protocol_v4.spec（1219 行）/ native_protocol_v5.spec（1537 行），2026-09-26 自 apache/cassandra trunk 取（本地 /tmp 工作副本，本稿全部章节号引用自原文实读）。规范定"必须是什么"：9B header、[byte]→[int] flags 宽度差、envelope framing、17 码 ERROR、CQL_VERSION mandatory。

**②现网行为**：Cassandra 3.x/4.x 生产集群默认 9042、原生协议 v3/v4/v5 协商（STARTUP CQL_VERSION=3.0.0 面）；DataStax 驱动（python-driver/gocql/Java driver）默认并发多 stream、响应按 stream id 归并；v5 自 Cassandra 4.0 起可用（4.x 默认 v5 可协商，5.x 为主流）。**待确认项**：现网抓包逐字段复核（flags 宽度、envelope 实发、stream 交错形态）→ **G-CQL-8**（确认方式：docker 起 Cassandra + cqlsh/python-driver 回环抓包）。

**③可靠开源实现思路**：wireshark 3.6.14 `packet-cql.c` dissector——`cql.*` 唯一字段 **83 个**（实测 `tshark -G fields | awk -F'\t' '$1=="F" && $3~/^cql\./' | sort -u`）；合成 pcap 探针实测 10 字段可解（cql.version/direction/opcode/stream/message_length/flags/consistency/query.flags/result.kind/error_code；`cql.query.flags` FT_UINT8 佐证 v4 [byte]）；**端口前提：必须 9042 才挂 dissector（非标端口不解码，实测）**。本仓 builder/planner（770 行）为 wire 真相。只借鉴字段语义与解析思路。

**三路一致性**：9B header 布局、方向位 0x04/0x84 与 0x05/0x85、12 opcode 值、consistency short 大端、[long string]/[string map]/[multimap] 编码——三路一致。W1 已按规范修正为 v4 [byte]/v5 [int]；W2 采用握手前 unframed 过渡档，握手后 envelope 另轮立项。

### 10.2 候选方案对比（§4.17；每个关键决策至少两个真实走法）

**决策 A：业务配置的住处**

| 方案 | 走法（含借鉴来源） | 优 | 劣 | 结论 |
|---|---|---|---|---|
| A1 层条目唯一住处 | registry 已补 Fields 4 键 + FieldContract 9042 + `translateTerminalConfig` case "cql" + CheckProtoFlat presence 判死 | 满足 1.1–1.13；schema/MCP 描述自动覆盖；顶层可判死 | 已采用（G-CQL-1） |
| A2 维持顶层 `cql` 子映射旁路（现状） | 现状（`strategy_convert.go:1408`） | 零改动 | 违反 1.4/1.11；层条目死配置（ Fields 空） | 不采用（登记为偏离） |
| A3 Payload 搬运（tds 现状形） | 层条目 JSON → spec.Payload | 与 tds 同构 | tds 自己已判待整改（G-TDS-1）；cql 有类型化字段无须旁路 | 不采用 |

**决策 B：v5 面收口**

| 方案 | 走法 | 优 | 劣 | 结论 |
|---|---|---|---|---|
| B1 实现 envelope framing（CRC24/CRC32 + 128KiB 分段 + 小端） | 借鉴 v5 spec §2.1-2.2 伪代码 + Cassandra java driver `FrameEncoder` 思路 | 全 v5 面 | 工作量大；现网 5.x 才主流；无 fixture 面 | 立项候选（G-CQL-3 主方案，P4 后另轮） |
| B2 v5 收窄："仅握手前 unframed 面" | STARTUP/OPTIONS/READY/SUPPORTED/AUTHENTICATE 保持 unframed（合法），握手后事件在 v5 profile 下一律拒 + 注记 | 小改（校验一条）；零假合规 | v5 能力面缩水 | **已采用过渡档**（`cql_v5_tracing` 覆盖握手前 4 事件；envelope 另轮立项） |
| B3 现状照发（握手后裸帧） | 现状 | 零改动 | 线面不合规（W2），冒充 v5 | **禁止** |

**决策 C：QUERY/EXECUTE flags 宽度**

| 方案 | 走法 | 优 | 劣 | 结论 |
|---|---|---|---|---|
| C1 按 profile 选宽（v4 [byte] / v5 [int]） | buildQueryBody/buildExecuteBody 加 reqVer 参数 | 规范合规；双 profile 各自正确 | 已采用（G-CQL-2），存量 2 例帧已重钉 |
| C2 恒 4 字节（现状） | — | 零改动 | v4 线面错 3 字节；tshark FT_UINT8 佐证读者侧也不认 | 不采用 |

**决策 D：`result_kind` 处置（1.12 二选一）**

| 方案 | 走法 | 优 | 劣 | 结论 |
|---|---|---|---|---|
| D1 删除字段 | types.go 删 `ResultKind` + 用例 3 处删键 | 死配置清零 | 若未来接 ROWS 需重加 | **采用**（G-CQL-4；接 ROWS 属 G-CQL-5 另轮） |
| D2 接线 kind 分派 | buildBody 按 ResultKind 分派 5 kind | 一步到位 | ROWS/SCHEMA_CHANGE metadata 面无 fixture，会造出半成品 | 不采用（冒充覆盖） |

## 11. 门1 §1–§14 十四行对照表（CORE_MEMORY §15.1–15.3）

| § | 本协议怎么满足 | 证据 |
|---|---|---|
| §1 层链唯一真相 | 见 §11.1 强制展开；旧键四键已迁 `ip`/`tcp` 层，顶层 `cql` 子映射已迁 `layers[].cql`；非负例顶层键=0（presence 负例见 §11.4）；纯 layers 形已跑通，G-CQL-1 已闭合 | 本契约 §2 + §11.1；当前机器契约 30 例 |
| §2 策略/任务 | 策略=单 CQL 连接模板（自带 `flow_control` flows/bps/time）；任务=多策略合跑+总量封顶；框架语义未动 | 本契约 §9.1 行1 + §12 |
| §3 五件套 | 见 §11.2 强制展开：会话表/事务序列/关联关系（stream id 归并）/插入位置/时间线；TCP 有真握手（15 正例 `has_handshake=true` 已断言） | 本契约 §11.2 + 用例正例集 |
| §4 查规范 | v4/v5 spec 原文（章节号实读，1219/1537 行）+ tshark 83 字段实测 + 10 字段探针实证 + §9 矩阵 8 行+三子表 + 三路对照（§10.1） | 本契约 §9/§10 |
| §5 依赖与错误 | `DependsOn ["tcp"]`（registry cql 行）；wire_fault 3 值 + 自然守卫（§5 锚词表全实测）；失败传播 task error（planner 返 error，零假成功） | 本契约 §5 + §9.1 行5 |
| §6 性能 | 单事件流式渲染无全量聚合；pcap/NIC 双路验收；吞吐/并发/内存目标待 P4 基准后定（§6.5 诚实待确认）；六类场景清单见 §12 性能节 | §12 性能设计与验收 |
| §7 三份文档 | 35-cql-{design,testcase}.md v2.0.0（行为面权威）+ D-CQL-1（§12 草稿，门1 获批=定稿）+ T-CQL（testcase §9 草稿）+ 生成表 cql 条目（P4 接线后 schemagen 重跑） | 修订记录 |
| §8 设计先行 | 本条目 P1–P3 先于 P4；门1 获批=D-CQL-1 定稿=开工门 | 提交序 |
| §9 测试三源 | 三源=v4/v5 spec 条款（§9.5 逐面）+ D-CQL-1 + tshark 实测/现网 Cassandra 形态（未确认级→G-CQL-8）；30 例正负对账 + 9.52 两行 | T-CQL（testcase §9） |
| §10 评审闭环 | 每阶段对抗自重审（结论见 §14 与 p123 报告）+ 收官隔离复审 + 修轮 | /tmp/pipe/75-cql/p123-report.md |
| §11 白话 | 每阶段白话一句先行 | 汇报 |
| §12 动态清单 | 见 §11.3 强制展开：四元组=ip/tcp 层（五策略全开）；业务字段逐个列不开+理由；序号算法位置=层链通用 `layer_dyn.go`（`resolveLayerTuple :767`），业务字段无算法（诚实声明） | 本契约 §11.3 |
| §13 schema 派生 | registry cql 行（`registry.go:1081`：FieldContract 9042 + Fields 4 键）+ 生成表 cql 条目四键齐；白名单已含 cql | §12 接线件 |
| §14 真实流程 | suite 经 MCP 建任务→引擎生成→tshark `cql.*` 字段 + frames hex 双通道（10 字段探针已证可用，**端口必须 9042**）；先跑后钉；pcap 落 `/tmp/mcp-pcaps/cql/` | 用例 §9.6 断言通道 |

### 11.1 §1 强制展开：旧键去向 + 完整 spec_json 样例

旧键清单（`src_ip`/`dst_ip`/`src_port`/`dst_port`/`count` + 本协议顶层子映射 `cql`）：

| 旧键 | 去向 |
|---|---|
| `src_ip` | → `layers[0].ip.src`（**结构性新增 ip 层**：现状 0/17 有 ip 层，旧形 `[tcp,cql]` 靠 `applySpecToChain` 从顶层注入） |
| `dst_ip` | → `layers[0].ip.dst` |
| `src_port` | → `layers[1].tcp.src_port`（`12345`；多会话靠 cql 层 `sessions[].src_port` 12345/12346） |
| `dst_port` | → `layers[1].tcp.dst_port`（`9042`；FieldContract 缺省 P4 补齐后可省略，存量显式值保留合规） |
| `count`（若有） | → 删除，走 `flow_control.flows`（存量 17 例均**无** count，属缺键补齐非迁移；单连接正例 `flows=1`） |
| 顶层 `cql` 子映射 | → `layers[]` 中 `{"cql": {...}}` 条目（业务键 `wire_profile/events/sessions/wire_fault` 4 键全量迁入，零残留；**P4 已补 registry Fields 4 键 + translateTerminalConfig case**，层条目不再触发 `unknown field`） |

**存量 17 例改写清单（P4 已执行；逐例去向见 testcase §8）**：17 例已加 `ip` 层、端口进 tcp 条目、业务键进入 cql 层，并将负例改为纯 layers 非法内容形。当前机器契约共 30 例（15 正 + 15 负）；非负例顶层键=0，负例 `expect` 键集合恰为 `{expect_error, error_contains}`。

完整最小握手样例（当前目标形状，已由机器契约跑通）：

```json
{
  "layers": [
    {"ip": {"src": "10.0.0.1", "dst": "20.0.0.1"}},
    {"tcp": {"src_port": 12345, "dst_port": 9042}},
    {"cql": {
      "wire_profile": "cql_v4",
      "events": [
        {"kind": "startup", "direction": "c2s", "options": {"CQL_VERSION": "3.0.0"}},
        {"kind": "ready", "direction": "s2c"},
        {"kind": "query", "direction": "c2s", "query": "SELECT 1", "consistency": 1, "query_flags": 0},
        {"kind": "result", "direction": "s2c"}
      ]
    }}
  ],
  "flow_control": {"flows": 1}
}
```

### 11.2 §3 强制展开：五件套

**会话表**：

| 会话 | 四元组 | 生命周期 |
|---|---|---|
| 主会话（`events[]` 形） | `ip.src/dst` + `tcp.12345→9042` | TCP 握手（tcp 层）→ STARTUP→(AUTHENTICATE→AUTH_RESPONSE→AUTH_SUCCESS)?→READY → 业务 QUERY/PREPARE/EXECUTE 与 RESULT/ERROR 交替 → FIN/挥手（`terminates=true`） |
| 扩展会话（`sessions[]` 形，与 `events[]` 互斥，`planner.go:45-47`） | 每项独立 `src_port`（S9：12345/12346），`ip/dst_port` 共用 | 同上；**每会话独立 TCP 流、独立握手挥手**（S9 断言 18 包=2×9） |

**事务序列**（单事务四件事 §3.4–3.7）：

| 事务 | 前置条件 | 触发动作 | 成功分支 | 失败分支 |
|---|---|---|---|---|
| t1 连接初始化 | TCP 已建连（tcp 层承载） | OPTIONS/SUPPORTED（可选前置）；STARTUP（首协议消息，v4 §4.1.1） | READY 可进业务 | 次序错 → task error（N5 通道） |
| t2 认证（可选） | STARTUP 后服务端 AUTHENTICATE | AUTH_RESPONSE（SASL bytes） | AUTH_SUCCESS → READY | 认证流违规 → G-CQL-6 校验缺口（现状放行） |
| t3 业务请求 | READY | QUERY / PREPARE→EXECUTE（stream 关联） | RESULT（VOID）或 ERROR（合法应用响应） | READY 前请求 → task error（`state` 锚词） |
| t4 关闭 | 业务完成 | TCP FIN/挥手 | `terminates=true` | 无协议级 logout 消息（显式不适用） |

**关联关系**（§3.8–3.10 三件事）：本协议**无副流派生数据流**（单 TCP 连接内 stream 多路复用），但有**同连接内 stream id 请求/响应关联**——归属会话（`sessions[]` 序或主 events）、归属请求（stream id 值）、由 `stream` 字段决定：**请求 stream X 的响应 stream 必为 X**（v4 §2.3:160 实测原文），并发多请求响应可乱序、按 stream 归并——与 CWMP `driven_by` 范本差异点诚实声明：cql 无跨流派生，关联靠同流内 stream 配对；`stream` 是本协议"关联关系"的承载字段，当前已有非零关联例 `cql_stream_correlation`，更宽字段面仍归 G-CQL-7。

**插入位置**：终结层——cql 事件字节（9B header + body）经 tcp 层包装为 TCP segment；IP 无 option 时 TCP payload 起点 54（IPv6 74）。TCP 语义（握手/MSS/挥手）由 tcp 层承载。

**时间线**：**顺序**——会话内 t1→t2→t3→t4 严格事件序（`layer_gen.go` 逐事件 emit）；并发语义在协议内经 stream 表达（§4.2 无响应序保证），实现为声明式事件序（配 stream 值即可表达乱序响应形状，无调度器）；会话间（S9）并发不假设全局包序，只断言流内状态（`tcp.srcport` distinct）。§3.12 调度方式落点="事件序逐包 emit"。

### 11.3 §12 强制展开：动态字段清单

| 字段 | 住处 | 开策略 | 理由 |
|---|---|---|---|
| `src`/`dst`（src_ip/dst_ip） | ip 层 | 全开（fixed/inc/rand/list/pattern） | §12.2 地址必备；多客户端/多目标锚点 |
| `src_port` | tcp 层 | 全开 + 未写动态保底 `12345+i`（§2.8） | 多会话锚点（12345/12346） |
| `dst_port` | tcp 层 | fixed（9042 单档；FieldContract 缺省 P4 补齐） | 端口=协议身份，动态无业务面 |
| `wire_profile` | cql 层 | 不开（三 profile 各自独立模板） | profile 切换=换策略（§2.5） |
| `events`/`sessions` | cql 层 | 不开（扇出结构静态声明） | 多会话靠 `sessions[]` 显式声明（§3.1），与动态正交 |
| `query`/`prepared_id`/`mechanism`/`options`/`bytes`/`code`/`message`/`stream`/`flags`/`consistency`/`query_flags` | cql 层 events[] | 不开（fixture 钉死字节） | 消息变体靠多事件/多策略；业务动态清单逐个列于此，不开动态=诚实声明（§12.14），如需按流变化另立项 |

序号算法代码位置：四元组动态=层链通用机制 `internal/core/layer_dyn.go`（`resolveLayerTuple :767` 按流序号解析，12.4 语义）；**业务字段无算法**（`internal/protocol/cql/` 全包非测试代码 `Strategy` 零命中，实测——不编行号，§5.7）。

### 11.4 presence 负例形状（链级红例必含①）

层链+顶层空子映射并存=判死负例（presence 负例形状，非残留）：`{"layers":[{"ip":{}},{"tcp":{}},{"cql":{}}],"cql":{}}`（顶层空 `cql:{}` 与层链并存）已被拒，`error_contains` 含 `top-level` 锚词（pipe_gate presence 门豁免形）。白名单外游离键（顶层 `src_mac`/`ttl`）判死负例同批。**另注**：单 TCP 载体 → 链中夹 `udp`（`[ip,udp,cql]`）判死负例（`tcp` 载体锚词）；链缺 `tcp`（`[ip,cql]`）判死负例。

## 12. D-CQL-1 P2 代码设计草稿（CORE_MEMORY §8 八要素；门1 获批=定稿）

> 体裁：文件清单/接口签名/数据结构/主流程/错误分支/性能设计与验收/冲突点/回滚。wire 面已落码（builder/planner/layer_gen 770 行），D-CQL-1 覆盖"层链接线差量 + W1/W2 线格式修正"，不重发明已实现面。

**文件清单（已落码 4 + P4 改 5 + 守卫，行号实测）**：

| 文件 | 职责/改动 |
|---|---|
| internal/protocol/cql/builder.go（已落码 316 行） | 常量/`opcodeForKind :48`/`versionForProfile :85`/`buildHeader :104`/`buildFrame :121`/`buildBody :138`/`buildQueryBody :171`/`checkWireFault :298`。**P4 改**：①G-CQL-2——`buildQueryBody`/EXECUTE 分支按 profile 选宽（v4 `appendU8` / v5 `appendU32`，加 reqVer 参）；②G-CQL-4——删 ResultVoid 恒写处与 `result_kind` 消费面（VOID 固定）；③G-CQL-6——`buildStringMapBody` 前置校验 STARTUP 必含 CQL_VERSION |
| internal/protocol/cql/planner.go（已落码 184 行） | `Validate :22`（互斥/profile/wire_fault/状态门/IP）/`Plan :101`（9042 缺省 `:107`）。**P4 改**：G-CQL-6 状态门补认证次序 + PREPARE/EXECUTE 纳 ready 门 |
| internal/protocol/cql/layer_gen.go（已落码 78 行） | `Generate :34`（逐事件 buildFrame → emitSel）——不动 |
| internal/protocol/cql/cql_test.go（已落码 1192 行 60 函数） | P4 修 W1 后同步改 QUERY/EXECUTE 宽度断言（失败测试先行：先改期望宽度转红再修 builder 转绿） |
| internal/core/layers/registry.go | `:807` cql 行补 `FieldContract {"tcp.dst_port": "9042"}` + `Fields` 4 键（wire_profile/events/sessions/wire_fault）；`schemagen` 重跑（13.18） |
| internal/core/layers/chain_planner_translate.go | `translateTerminalConfig` 新增 `case "cql"`：`completedConfig(s, term.Config)` → JSON 往返 → `spec.CQL`（vnc/ntlm 先例；层优先，flat 判死后无双轨） |
| internal/core/strategy_convert.go | `CheckProtoFlat`（`:8286`）新增 cql presence 分支（mmse/ntlm 先例文案：`protocol cql no longer accepts a top-level cql sub-config (move it into the cql layer of an [ip,tcp,cql] layers chain)`） |
| tools/coverage_gate.py + tools/pipe_gate.sh | `check_cql` 登记（出口 2 视红）+ presence 名单加 cql |
| test/protocol_pcap/cases/cql.json | 30 例契约：17 例迁移改写 + 2 例帧重钉（W1）+ v5 例改形（W2 过渡档）+ 链级红例 + A′ 补例 |

**接口签名**（P4 落码钉死有无差量）：`buildQueryBody(reqVer byte, ev core.CQLEvent) []byte`（改：加版本参）/ `validateEvents` 状态门扩展 / `case "cql"` translate 分支 / 既有 `Generate(ctx, req) error`、`Validate(spec core.FlowSpec) error` 不变。

**数据结构**：沿 `CQLConfig`（types.go:1316 4 键）+ `CQLEvent`（:1292 15 键；**删 `ResultKind`**，G-CQL-4）+ `CQLSession`（:1310 2 键）+ 层链目标形状（§11.1 样例）。

**主流程**：validateSpec（含 P4 4 守卫：presence/白名单游离键/udp 载体/缺 tcp）→ drive（Meta.CQL 直传）→ `layer_gen.Generate` 逐事件 buildFrame → EmitMsg → worker → pcap/NIC。

**错误分支（§5.2）**：①wire_fault 3 值注入拒（锚词 `opcode`/`length`/`limit` 进断言）；②自然守卫：未知 profile（`version`）/未知 kind（`opcode`）/方向（c2s|s2c 文案）/状态（`state`）/互斥/非法 IP/未知 fault kind；③validate_layers 预检（presence/白名单/载体）。全部传播为 task error，零假成功。

**依赖声明（§5.1）**：依赖 `tcp` 层（唯一载体：握手/MSS/挥手/端口 9042）；依赖 `ip` 层（寻址，IPv6 同层）；无 udp/TLS 依赖；无外部 Cassandra 依赖。

**性能设计与验收（§6.1–6.8）**：O(n) 流式——逐事件渲染直发 EmitMsg（`layer_gen.go:34-58` for 循环直发，无切片聚合）；确定性内存（单事件最大=单 frame，fixture 级字节；无跨流共享状态、无锁）；pcap 路实测（suite 落盘 `/tmp/mcp-pcaps/cql/`）+ NIC 路注记（过滤器 `tcp port 9042`，测试网口 `enp135s0f0np0` 按 testing-interface 记忆）；六类场景（基线/目标规模/压力上限/长运行/并发交错/背压）P5 跑测覆盖；边界诚实声明：吞吐/并发/内存目标数字待 P4 基准后定（§6.5，不写承诺）。

**与现有逻辑冲突点（§8.7）**：①W1 宽度修=线面破坏性变更，`cql_query_void`/`cql_prepare_execute` 帧钉值全部重钉（先跑后钉 14.6），与 B 轨 lane 校准同批；②v5 收窄（B2）会删 `cql_v5_tracing` 的握手后事件——用例改形而非删除；③`sessions[]` 多流展开与 mongodb "one flow per chain" 拒绝裁定（p3-execution-todos T4.6）相容性未实测——B 轨首跑即验，若撞同款拒绝则 S9 改形上报；④cql 子映射未知键静默忽略（`parseSubconfigJSON` 普通 unmarshal）——G-CQL-6 不依赖未知键拒绝。

**回滚方式（§8.8）**：若需回滚，应整体 revert P4 差量（接线 + 判死 + 17 例改写 + W1 修 + coverage 登记）；已落码 wire 面其余不动。当前无数据迁移面。

## 13. P3 对接清单与缺口立项

- §3.15 三项：①同连接多事务序列（STARTUP→READY→多轮 QUERY/RESULT→FIN）→ **已覆**（S4 单轮 + `cql_multi_round_query` 多轮）→ 当前契约已落例；②非正常结束→ 6 负例全覆（N1–N6）+ 合法 ERROR 响应 S6；认证失败分支（AUTH_ERROR 码 0x0100 面）无例 → G-CQL-5；③长保活→ **明确不适用**（CQL 无协议级心跳消息，§9.1 行6；TCP keepalive 归 tcp 层）。逐项一例或立项，无空项（明细见 testcase §9.1）。
- A′/B′ 两分类表：见 testcase §9.2（A′=引擎可构建→stream 非零关联/consistency 10 值/flags 位/多轮 QUERY/超长字符串；B′=引擎结构缺口→G-CQL-1/2/3/4/5/6）。
- 9.52 对账两行：见 testcase §9.3（97 枚举点 vs 30 例；出处=v4/v5 spec 原文反推）。
- 3.14 豁免边界审计：见 testcase §9.4（本协议单 TCP 连接但**不主张任何豁免**：多会话 S9 已覆、多事务 A′ 补、单包多载荷不适用——CQL 一帧一消息）。
- 三源回指行：见 testcase §9.5（第三源"已确认现网行为"当前=未确认级，挂 G-CQL-8）。
- 断言通道：`cql.*` 10 字段探针实测可用（version/direction/opcode/stream/message_length/flags/consistency/query.flags/result.kind/error_code）+ `tcp.dstport` 载体面 + frames hex（offset 54/74）；**端口必须 9042**（tshark 非标端口不解码，实测）。

### 13.1 缺口立项清单（有缺口写"缺口立项"，不许空着）

| 立项号 | 缺口 | 分类 | 去向 |
|---|---|---|---|
| G-CQL-1 | 纯 layers 收口：registry Fields 4 键 + FieldContract 9042 + translateTerminalConfig case "cql" + CheckProtoFlat presence 判死 + pipe_gate/coverage_gate 登记 + sessions 多流展开相容性 B 轨实测 | B′ | P4（§12 主条目） |
| G-CQL-2 | W1 修：QUERY/EXECUTE flags 按 profile 选宽（v4 [byte]/v5 [int]）+ 单测先红后绿 + 存量 2 例帧重钉 | B′（CRITICAL） | P4 第一刀 |
| G-CQL-3 | W2 修：v5 过渡档收窄（握手后事件拒+注记）或 envelope 实现（CRC24 0x875060/0x1974F0B + CRC32 + 128KiB）；v5 字段差异表（keyspace/now_in_seconds/beta） | B′（CRITICAL） | 过渡档 P4；envelope 另轮立项 |
| G-CQL-4 | `result_kind` 死字段处置：删除（已完成；VOID 固定，不再消费该键） | B′（1.12） | P4 已处置 |
| G-CQL-5 | 协议面补齐三选一：REGISTER/EVENT/BATCH/AUTH_CHALLENGE 4 opcode；ROWS/SET_KEYSPACE/PREPARED/SCHEMA_CHANGE 4 result kind；ERROR 17 码逐码或分支（0x0100 认证失败面含 §3.15②） | B′ | 逐项"实现/明确不支持/不适用"收口，另轮 |
| G-CQL-6 | 校验补面：STARTUP CQL_VERSION 强制；flags per-profile 位校验（v4 拒 0x10 beta、warning s2c-only）；认证次序门；PREPARE/EXECUTE 纳 ready 门 | B′ | P4 校验刀 |
| G-CQL-7 | A′ 断言与用例补强：`cql.*` 字段断言从 0→10 字段实测面；stream 非零关联例（含乱序响应形状）；consistency 10 值；**同连接多轮 QUERY 已落例**；超长/截断字符串边界 | A′ | P4/P5 用例批次 |
| G-CQL-8 | 现网证据升级：Cassandra 4.x/5.x 抓包（v4 flags 宽度实证、v5 envelope 实发、driver stream 交错形态）；确认方式=docker Cassandra + cqlsh/python-driver 回环抓包 | 待确认 | 确认前相关条目按 §5.5"待确认"不写死；不挡开工 |

## 14. P1/P2/P3 对抗自重审结论（10.11；过 4 轮，末轮干净）

- **P1（§9 矩阵）**：R1 自审曾发现初稿把 9042 写成“FieldContract 缺省”——实读 `registry.go:1081` 已有 `FieldContract`，历史判断已由 P4 接线修正；R2 逐行核八项矩阵代码现状（builder/planner/layer_gen/types/strategy_convert/chain_planner_translate 全实读）；R3 复算 §9.2 逐格重数（13×4=52，已覆 37+缺失 6+不支持 4+不适用 5=52 ✓，首稿 51 漏计 RESULT 行“不适用”格已补）；**R4 终扫发现 W1**——抽查存量帧钉值时核对 v4 §4.1.4 flags 类型，发现实现 4 字节与规范 [byte] 矛盾，升级为 CRITICAL 立项 G-CQL-2，tshark FT_UINT8 + 探针双证后落 §9.6。末轮干净。
- **P2（§12 D-条目）**：R1 自审发现 `result_kind` 死字段在八要素里漏处置（`builder.go:148` 恒 VOID 实测）→ 补 G-CQL-4/D1 裁定；R2 补 `parseSubconfigJSON` 未知键静默面与 sessions 多流展开相容性两处冲突点；R3 末轮干净。
- **P3（testcase §8/§9 + §13）**：R1 自审发现 9.52 初稿"总数 88"漏 STARTUP 选项面与 v5 差异面 → 重算 97（16+4+7+11+5+17+23+4+10，逐面复算一致）；R2 核锚词 6 个逐字对 planner/builder 真实字符串；R3 断言通道 10 字段全部经合成 pcap 探针验证（首轮探针 seq 未对齐致 RESULT 帧不解码——修正 seq 后 10/10 解出，教训=TCP 流序号必须对齐才可断言）；R4 末轮干净。

三阶段合计修正 9 处（CRITICAL 线格式 1〔W1〕、v5 面升级 1〔W2〕、FieldContract 误记 1、死字段漏处置 1、对账口径 1、矩阵复数 1、冲突点补漏 2、断言前提补钉 1〔探针 seq 对齐教训〕），末轮均干净。

### 14.1 文档逐条自核对结论（10.1：对规范逐条核对）

- v4 spec：9B header（§2.1-2.5）→ 本契约 §3 逐字段有落点；16 opcode（§2.4）→ §9.1 行2/§9.2 逐值三选一；8 请求 8 响应消息面（§4.1/§4.2）→ §9.2 矩阵行；[byte]/[int] flags（§4.1.4/§9 Changes#4）→ W1/G-CQL-2；17 码（§4.2.1+§9）→ G-CQL-5；envelope（v5 §2.1-2.3）→ W2/G-CQL-3；CQL_VERSION mandatory（§4.1.1）→ G-CQL-6。
- 与旧需求文档（v1.0.0 design/testcase + bak audit）逐条核对（10.2）见 §14.2。

### 14.2 与旧文档逐条核对结论（10.2）

- v1.0.0 §1–§8 逐条：§1 范围/证据等级表（保留，旧版“cql 层尚未实现”声明已按 `registry.go:1081` 与当前落码实测改正于文首）；§2 层链和配置（**唯一实质改动**：扁平混合样例按 1.4/1.5 判违例删除，换目标形状 + 1.9 标注 + 偏离登记；键表保留）；§3 线格式（保留）；§4 状态语义（保留）；§5 校验表（保留，负例通道实测化）；§6 场景包数（保留）；§7 完成定义（保留）；§8 修订记录（追加 v2.0.0）。旧文引用的 `docs/protocol-designs/audit/` 死链更正为 `.bak-root` 实路径。无旧条目被静默删除；bak-root 副本与 v1.0.0 diff 为零（实测），对照基线成立。
