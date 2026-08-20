# CQL/Cassandra Native Protocol（CQL/Cassandra 原生协议）设计文档

> 版本：v1.0.0（设计阶段）  
> 日期：2026-08-20  
> 状态：仅设计与用例契约；`cql` 层尚未实现，本稿不宣称 MCP（Model Context Protocol，模型上下文协议）套件可以运行。  
> 配套文件：`docs/protocol-designs/35-cql-testcase.md`、`trafficgen/test/protocol_pcap/cases/cql.json`、`docs/protocol-designs/audit/35-cql-adversarial-audit.md`

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

```json
{
  "layers": [{"tcp": {}}, {"cql": {}}],
  "src_ip": "10.0.0.1",
  "dst_ip": "20.0.0.1",
  "src_port": 12345,
  "dst_port": 9042,
  "cql": {
    "wire_profile": "cql_v4",
    "events": []
  }
}
```

注册契约：`cql` 为 TCP terminal（终结层），硬依赖 TCP，默认目的端口 9042；TCP 的 MSS、初始序列号、握手和终止由公共层处理。每个 event（事件）含 `kind`、`direction` 和该事件的 profile-specific（版本特定）字段。

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
| PREPARE/EXECUTE | `cql_prepare_execute` | 2 | 9 | 两个请求 header/body |
| ERROR | `cql_error_server` | 1 | 8 | ERROR 外层 code/string |
| IPv6 | `cql_ipv6` | 4 | 11 | IPv6 与 offset 74 |
| v5 flags | `cql_v5_tracing` | 4 | 11 | v5 version、flags、QUERY |
| 多会话 | `cql_multi_session` | 2×2 | 18 | 两个源端口/独立四元组 |
| 零长度边界 | `cql_length_boundary` | 1 | 8 | OPTIONS length=0 |
| TCP connect | `cql_connect` | 0 | 7 | 9042、无应用 payload |
| UDP 载体负例 | `cql_neg_udp` | — | — | 仅 task error |
| 版本负例 | `cql_neg_version` | — | — | 仅 task error |
| opcode 负例 | `cql_neg_opcode` | — | — | 仅 task error |
| 长度负例 | `cql_neg_length` | — | — | 仅 task error |
| 状态负例 | `cql_neg_state` | — | — | 仅 task error |
| 上限负例 | `cql_neg_limit` | — | — | 仅 task error |

## 7. 实现完成定义与边界

1. 注册 TCP→`cql` 层，默认端口 9042，拒绝 UDP/缺 TCP/非法端口。
2. 对 frame header 的方向位、flags、signed stream、opcode 和 body length 做逐字段单测；长度按编码字节回填。
3. 对 STARTUP/OPTIONS/SUPPORTED/READY、QUERY/PREPARE/EXECUTE、RESULT VOID、ERROR 和 AUTH bytes 做失败优先单测及 API→engine→PCAP 集成测试。
4. v4/v5 profile 独立校验；IPv4/IPv6、多会话、MSS 分段使用真实输出和重组验证。
5. 认证机制、SASL 私有摘要、压缩、TLS、v5 beta、ROWS metadata、prepared metadata、绑定值和 schema 结果必须取得对应规范/fixture 后单独实现，不以随机或 v4 回退填充。
6. 负例错误必须到达 task error 终态；不能把 planner 错误吞成 completed/0 packets。

## 8. 修订记录

- v1.0.0（2026-08-20）：建立 CQL/Cassandra Native Protocol v4/v5 profile 设计；固定 9 字节 header、基础启动/能力/认证外层、查询/预编译/执行请求、VOID/ERROR、IPv4/IPv6、多会话及长度/版本/opcode/状态/UDP/上限负例；明确 SASL/压缩/v5 metadata 等边界。
