# CQL/Cassandra Native Protocol（CQL/Cassandra 原生协议）三件套对抗审查

> 审查日期：2026-08-20  
> 对象：`35-cql-design.md`、`35-cql-testcase.md`、`cases/cql.json`  
> 属性：设计文档阶段审查；无 Go（编程语言）实现，不执行协议正例 suite（测试套件）验收。  
> 结论：两轮自审后 clean（通过）；认证私有字节、压缩、v5 metadata 等均保留为实现边界。

## 1. 审查口径

- **规格可实现性视角**：逐字段核对 CQL Native Protocol v4/v5 的 TCP 载体、9 字节 header、方向位、flags、stream、opcode、length、STARTUP/OPTIONS/SUPPORTED/READY、QUERY/PREPARE/EXECUTE、RESULT VOID、ERROR 和认证 bytes 外层；检查私有 profile 未被伪造。
- **用例覆盖视角**：逐行反查设计错误表和场景表；每个正例检查 observable、包数、帧偏移和原始字节；每个负例检查仅有 `expect_error/error_contains`。
- **静态检查**：加载 JSON，检查唯一 ID、正负分类、十六进制可解析、frame offset、tcp.len、三方包数与事件数。

## 2. 规格可实现性审查

### 2.1 已确认

1. **Header 结构完整**：所有 frame 均是 version(1)+flags(1)+stream(2)+opcode(1)+length(4)，length 只计 body；v4/v5 请求/响应方向分别为 `04/84`、`05/85`。
2. **Byte order（字节序）明确**：stream/length、string/map count、consistency/query flags 均按网络字节序；字符串按 UTF-8 编码后字节长度，不按字符数。
3. **基础 opcode 可复算**：OPTIONS/READY 的 zero-body frame、STARTUP string map、SUPPORTED multimap、QUERY long string/options、PREPARE/EXECUTE request framing、RESULT VOID 和 generic ERROR 均有固定外层。
4. **状态与方向有界**：STARTUP/READY、认证顺序、QUERY 前置状态和显式事件方向均写入契约；planner 不猜响应。
5. **profile 隔离**：v4/v5 显式命名；不把 v4 字节或一套认证摘要隐式推广到 v5；`cql_v3` 负例拒绝。
6. **不编造私有 wire**：SASL challenge、密码/摘要、压缩、TLS、beta、ROWS metadata、paging state、prepared metadata 和真实 SQL 结果均标为待 fixture/profile 边界。
7. **错误传播目标明确**：UDP、版本、opcode、长度、状态和 frame 上限必须到达 task error，不允许成功生成零包。

### 2.2 实现阶段守护项（不是当前文档 finding）

| 项目 | 已写契约 | 实现前必须补充 |
|---|---|---|
| v5 | version/flags 基础头 | beta 协商、v5-only metadata 的版本化 fixture |
| Auth | authenticator string、bytes length | SASL 机制、challenge/response、凭据安全策略 |
| QUERY | query/consistency/flags | values、named values、paging、serial consistency、timestamp、keyspace 等 options |
| EXECUTE | id/consistency/flags 最小请求 | bound values 和 prepared-id 生命周期 |
| RESULT | VOID kind | ROWS/SET_KEYSPACE/SCHEMA_CHANGE 全部 metadata |
| ERROR | SERVER_ERROR code/string | 各错误码条件字段及版本差异 |
| 分片 | 设计说明重组要求 | MSS/多 TCP segment stream 重组集成测试 |

这些是明确的待实现边界，不是用缺省值冒充事实。

## 3. 用例覆盖对抗审查

### 3.1 正例逐条核对

| id | 设计覆盖 | JSON observable | 结果 |
|---|---|---|---|
| `cql_v4_startup_ready` | v4 STARTUP/READY、方向位、长度 | 两个完整 frame、端口、tcp.len | 通过 |
| `cql_options_supported` | 空 OPTIONS、SUPPORTED string multimap | 两个 frame、tcp.len=9/61 | 通过 |
| `cql_auth_empty_sasl` | AUTHENTICATE/AUTH_RESPONSE/AUTH_SUCCESS | opcode/方向、零长度 bytes 三帧 | 通过 |
| `cql_query_void` | QUERY、RESULT VOID、双 READY 状态 | QUERY/RESULT frame、tcp.len=50/13 | 通过 |
| `cql_prepare_execute` | PREPARE/EXECUTE request wire | 两个 frame、目的端口 | 通过 |
| `cql_error_server` | 合法应用 ERROR | s2c frame、code/string、端口 | 通过 |
| `cql_ipv6` | v4 + IPv6 offset 74 | IPv6 version、端口、两帧 | 通过 |
| `cql_v5_tracing` | v5 version、flags=0x02 | v5 STARTUP/QUERY/RESULT frames、tcp.len=27 | 通过 |
| `cql_multi_session` | 两个独立四元组 | srcport distinct 12345/12346、dstport | 通过 |
| `cql_length_boundary` | length=0 合法 OPTIONS | 完整 9-byte frame、tcp.len=9 | 通过 |
| `cql_connect` | TCP connect 无应用事件 | 9042、has_payload=false | 通过 |

### 3.2 负例逐条核对

| id | 设计错误行 | JSON expect | 结果 |
|---|---|---|---|
| `cql_neg_udp` | UDP/缺 TCP | 仅 `expect_error` + `tcp` | 通过 |
| `cql_neg_version` | 未登记 v3 profile | 仅 `expect_error` + `version` | 通过 |
| `cql_neg_opcode` | opcode=255 | 仅 `expect_error` + `opcode` | 通过 |
| `cql_neg_length` | 声明长度超过 body | 仅 `expect_error` + `length` | 通过 |
| `cql_neg_state` | READY 前 QUERY | 仅 `expect_error` + `state` | 通过 |
| `cql_neg_limit` | frame over limit | 仅 `expect_error` + `limit` | 通过 |

## 4. 三方静态一致性结果

执行脚本加载设计/测试文档表和 JSON 后核对：

- ID 集合：17 个，设计 §6、testcase §2、JSON 一致且唯一。
- 正例：11 个；包数 `[9,9,10,12,9,8,11,11,18,8,7]` 与设计、testcase 和 JSON 一致。
- 负例：6 个；每个 `expect` 恰有 `expect_error`、`error_contains`，无 packet_count、fields、frames。
- 正例全部 `has_handshake=true`、`terminates=true`；除 `cql_connect` 外全部 `has_payload=true`，且至少有 fields/frames。
- IPv4 frame offset 只为 54，IPv6 只为 74；均位于应用包，不锚定握手平凡值。
- Header hex 可由 `bytes.fromhex` 解析；JSON 的 `tcp.len` 与 frame 总长度一致。
- v4/v5 direction/version、opcode、empty body、AUTH bytes、QUERY flags 均有实际 observable；未写认证摘要、压缩或 metadata 常量。

## 5. Findings（发现项）

### F-01（已修复：QUERY/EXECUTE options 宽度）

初稿误把 QUERY/EXECUTE 的 flags 作为 1 字节，导致 body 长度和 native protocol 的 4 字节 flags 不一致。已改为 consistency `uint16` + flags `uint32`，同步生成器脚本结果、JSON frame、tcp.len 和 testcase 文本；当前 frame length 可逐字节复算。

### F-02（已修复：长字符串与短字符串混用）

初稿生成器曾用 2 字节 string 编码 QUERY/PREPARE，但协议规定 query 为 4 字节 long string。已改用 `uint32` 长度，重新计算 QUERY/Prepare/v5 frame、tcp.len 和文档固定样例；认证 mechanism 仍保持 2 字节 string，EXECUTE id 保持 2 字节 bytes。

### F-03（保留为实现边界：ERROR 条件字段）

ERROR 的 code 后续字段依赖错误码；本版只使用 SERVER_ERROR code=0 和 message，故无需条件字段。SYNTAX_ERROR、AUTHENTICATION_ERROR、UNAUTHORIZED 等必须在取得版本化编码依据后另增 profile/case，不能由当前 generic ERROR 例推断。

## 6. 结论与自审记录

CQL v4/v5 的可靠公共线格式、基础会话事件、认证 bytes 边界、QUERY/PREPARE/EXECUTE 请求、RESULT VOID、ERROR、IPv4/IPv6、多会话、零长度 header 和负例边界已经形成 design/testcase/JSON/audit 闭环。未实现 Go 层，故没有虚报运行时套件通过；私有认证、压缩和版本差异被明确隔离。

自审完成 **两轮**：第 1 轮发现 F-01（options 宽度）和 F-02（long string 编码）并修复；第 2 轮逐字节复算 header/body length、IPv4/IPv6 offset、事件包数、三方 ID 和负例键，未发现新问题；**最后一轮 clean（通过）**。
