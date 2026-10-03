# MongoDB Wire Protocol（MongoDB 有线协议）测试用例设计

> 版本：v1.0.0（设计阶段）  
> 日期：2026-08-20  
> 配套设计：`docs/protocol-designs/32-mongodb-design.md`  
> 机器契约：`trafficgen/test/protocol_pcap/cases/mongodb.json`  
> 状态：`mongodb` 层尚未实现；本文定义实现后的 PCAP 断言，不宣称当前套件可运行。

## 1. 测试原则

用例从设计 §2（消息头/opcode/body）、§3（BSON 类型）、§4（会话/关联/边界）逐项派生。正例必须有 `packet_count`、TCP 握手/终止断言和至少一个可观察 `fields` 或 `frames`；负例 `expect` 只能有 `expect_error` 与 `error_contains`，不对失败 PCAP 做结构断言。

传统 wire（线格式）固定为小端序；所有正例使用 TCP 27017，除 IPv6 例外外消息头起点为 Ethernet+IP+TCP 的 offset 54，IPv6 起点为 74。应用消息一事件一 TCP 数据段，不把 ACK 计入 packet_count。

## 2. 包数公式与索引

`packet_count = 3（TCP 握手） + 应用事件数 + 4（TCP 正常终止）`。

| # | id | 类型 | 覆盖 | 应用事件 | 包数 |
|---:|---|---|---|---:|---:|
| 1 | `mongodb_query_reply` | 正 | OP_QUERY→OP_REPLY、header 关联 | 2 | 9 |
| 2 | `mongodb_write_ops` | 正 | INSERT/UPDATE/DELETE/GET_MORE/KILL_CURSORS | 5 | 12 |
| 3 | `mongodb_bson_types` | 正 | double/string/doc/array/binary/bool/null/int32/int64 | 1 | 8 |
| 4 | `mongodb_empty_boundary` | 正 | 最小 BSON（5 字节）、空 selector | 1 | 8 |
| 5 | `mongodb_ipv6` | 正 | IPv6、OP_QUERY/REPLY | 2 | 9 |
| 6 | `mongodb_multi_session` | 正 | 两个独立 TCP 会话、requestID 配对 | 4 | 18 |
| 7 | `mongodb_message_header` | 正 | length/requestID/responseTo/opCode 逐字节 | 1 | 8 |
| 8 | `mongodb_neg_truncated_header` | 负 | 少于 16 字节 header | — | — |
| 9 | `mongodb_neg_short_length` | 负 | messageLength=15 | — | — |
| 10 | `mongodb_neg_oversize` | 负 | 声明长度超过实现上限 | — | — |
| 11 | `mongodb_neg_bad_opcode` | 负 | 非法 opcode | — | — |
| 12 | `mongodb_neg_bson_length` | 负 | BSON 声明长度越界 | — | — |
| 13 | `mongodb_neg_udp_carrier` | 负 | UDP 载体拒绝 | — | — |

## 3. 正例契约

### 3.1 `mongodb_query_reply`（T-MONGO-S1）

IPv4、TCP 27017，`test.users`，请求 ID 100 的 OP_QUERY，响应 ID 101 且 `responseTo=100` 的 OP_REPLY。预期 9 包。packet 4 的消息头（offset 54）前 16 字节为 `33 00 00 00 64 00 00 00 00 00 00 00 d4 07 00 00`；packet 5 为 `30 00 00 00 65 00 00 00 64 00 00 00 01 00 00 00`。packet 4 的 selector 从 offset 93 开始，以 `0c 00 00 00 10 78 00 01 00 00 00 00` 锚定 BSON 长度和 int32 值。

### 3.2 `mongodb_write_ops`（T-MONGO-S2）

单 session 顺序发送五个请求事件：OP_INSERT(request 110)、OP_UPDATE(120)、OP_DELETE(130)、OP_GET_MORE(140)、OP_KILL_CURSORS(150)，均 `responseTo=0`。预期 12 包。应用包的头 opcode 分别为 `d2 07 00 00`、`d1 07 00 00`、`d6 07 00 00`、`d5 07 00 00`、`d7 07 00 00`；每个 header 的 requestID 分别为 110/120/130/140/150。GET_MORE 和 KILL 的 cursorID 使用固定 fixture `0x0102030405060708`（线值小端序：`08 07 06 05 04 03 02 01`），不宣称真实服务器会分配该游标。

### 3.3 `mongodb_bson_types`（T-MONGO-S3）

OP_INSERT(request 170) 将 design §3.2 的 101 字节 BSON 写入 `test.users`。预期 8 包。packet 4 header offset 54 为 `84 00 00 00 aa 00 00 00 00 00 00 00 d2 07 00 00`，文档长度从 offset 85 开始为 `65 00 00 00`；随后逐字段断言 type byte `01/10/12/02/08/0a/05/04/03` 以及最终终止符。具体文档完整十六进制以 design §3.2 为唯一 fixture，避免按字符长度计算 string。

### 3.4 `mongodb_empty_boundary`（T-MONGO-S4）

OP_QUERY(request 160) 使用空 selector `{}`，其 BSON 恰为 `05 00 00 00 00`。预期 8 包，头 offset 54 为 `2c 00 00 00 a0 00 00 00 00 00 00 00 d4 07 00 00`；selector 位于 offset 93，断言 `05 00 00 00 00`。这覆盖合法最小文档，不把长度 4 当作合法 BSON。

### 3.5 `mongodb_ipv6`（T-MONGO-S5）

源 `2001:db8::1`、目的 `2001:db8::2`、TCP 27017，事件为 OP_QUERY(request 180)→OP_REPLY(request 181,responseTo 180)。预期 9 包；packet 4/5 `ipv6.version=6`，消息头分别位于 offset 74，且 opCode 字节为 `d4 07 00 00`/`01 00 00 00`。IP 版本变化不改变 MongoDB header 字段顺序。

### 3.6 `mongodb_multi_session`（T-MONGO-S6）

两个独立 session，源端口 12345 与 12346，目的端口均 27017；每条流各发送 OP_QUERY→OP_REPLY，ID 对为 200→201 与 300→301。预期 18 包（每流 3+2+4=9 的和）。断言 `tcp.srcport` distinct values 为 12345/12346，且每条流的 response `responseTo` 等于自身请求 ID；不根据跨流 packet 序号推断事件顺序。

### 3.7 `mongodb_message_header`（T-MONGO-S7）

单个 OP_INSERT(request 190) 事件，预期 8 包。header offset 54 的 16 字节应为 `3b 00 00 00 be 00 00 00 00 00 00 00 d2 07 00 00`，逐字段解释为 length=59、requestID=190、responseTo=0、opCode=2002。该例不依赖服务器响应，专门守护四个通用字段的字节序和覆盖范围。

## 4. 负例契约

负例的 `expect` 严格只含两个键：

| id | 输入故障 | `error_contains` |
|---|---|---|
| `mongodb_neg_truncated_header` | `wire_fault.kind=truncate_header,value=10` | `truncated` |
| `mongodb_neg_short_length` | `wire_fault.kind=message_length,value=15` | `length` |
| `mongodb_neg_oversize` | `wire_fault.kind=message_limit,value=over_limit` | `limit` |
| `mongodb_neg_bad_opcode` | `wire_fault.kind=opcode,value=2147483647` | `opcode` |
| `mongodb_neg_bson_length` | `wire_fault.kind=bson_length,value=1000` | `bson` |
| `mongodb_neg_udp_carrier` | `layers=[udp,mongodb]` | `tcp` |

故障注入仅用于校验错误传播；不能让任务“完成但 0 包”而通过。若实现采用不同稳定错误文本，必须先同步更新设计、本文和 JSON 三处，不能把断言放宽成任意失败。

## 5. 三方一致性检查

1. 本文 13 个 id、JSON 13 个 id、设计 §6 的 13 个 id 必须集合相等且顺序相同。
2. 正例包数为 `[9,12,8,8,9,18,8]`，与设计表和 JSON `expect.packet_count` 一致；负例不出现 `packet_count`。
3. 所有正例 `has_handshake=true`、`terminates=true`；负例仅两个 expect 键。
4. IPv4 frame offset 只使用 54 或由其推导的 85/93；IPv6 头 offset 使用 74。包含 TCP option 时不得复用常量。
5. requestID/responseTo、opcode、BSON 长度断言均锚定数据包，不锚定 SYN/ACK。

## 6. 实现后执行建议

先运行 JSON 语法和三方静态脚本，再执行 S1/S7 验证 header；随后执行 S3/S4 的 BSON 长度与终止符，最后执行写操作、IPv6 和多会话。负例必须确认错误从 planner 传播至任务终态。`OP_MSG`/`OP_COMPRESSED` 未在本批执行，待单独设计确定压缩算法和 section 边界后再加入。

## 7. 修订记录

- v1.0.0（2026-08-20）：建立 7 个正例和 6 个负例；覆盖传统 opcode、BSON 基础类型、IPv4/IPv6、多会话及 header/长度/截断/非法 opcode/载体边界。
