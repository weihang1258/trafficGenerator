# Dameng（达梦数据库）测试用例设计

> 版本：v1.0.0（设计阶段）
> 日期：2026-08-20
> 配套设计：`docs/protocol-designs/33-dameng-design.md`
> 机器契约：`trafficgen/test/protocol_pcap/cases/dameng.json`
> 状态：`dameng` 层尚未实现；本文定义实现后的 PCAP 断言，不宣称当前套件可运行。

## 1. 测试原则

用例从设计 §1（证据等级/不变式）、§2（TCP/IP 载体和状态）、§3（版本化 profile）、§4（配置校验）和 §5（事件/包数）逐项派生。

达梦私有应用消息头、长度字段、认证摘要、SQL 命令和响应码没有可跨版本可靠固定的公开线格式。本套件因此只在当前阶段断言可观察的 TCP 事实：默认端口 5236、方向、IPv4/IPv6、独立四元组、非空 TCP payload、握手和终止。`profile` 只是未来实现契约名，不能把它或语义 SQL 文本直接当成线上十六进制。

正例必须有 `packet_count`、TCP 握手/终止和至少一个传输层 `fields`/`frames` 断言；负例的 `expect` **只能**有 `expect_error` 与 `error_contains`，不对失败 PCAP 作结构断言。当前正例不使用伪造的 Dameng frame offset；取得明确版本 fixture 后，必须补 DM 专用断言并同步修订三方。

## 2. 包数公式与用例索引

小 payload、每个事件一个 TCP 数据段时：

```text
packet_count = 3（握手） + 应用事件数 + 4（FIN 终止）
```

| # | id | 类型 | 覆盖 | 事件数 | 包数 |
|---:|---|---|---|---:|---:|
| 1 | `dameng_connect` | 正 | TCP 连接事件、默认端口 | 1 | 8 |
| 2 | `dameng_auth_success` | 正 | 认证请求/成功响应方向 | 3 | 10 |
| 3 | `dameng_sql_success` | 正 | SQL 请求、成功响应 | 5 | 12 |
| 4 | `dameng_sql_error` | 正 | SQL 请求、错误响应 | 5 | 12 |
| 5 | `dameng_length_boundary` | 正 | profile 声明的最小/边界输入 | 5 | 12 |
| 6 | `dameng_ipv4` | 正 | IPv4 载体 | 5 | 12 |
| 7 | `dameng_ipv6` | 正 | IPv6 载体 | 5 | 12 |
| 8 | `dameng_multi_session` | 正 | 两个独立会话、端口隔离 | 2×3 | 20 |
| 9 | `dameng_neg_udp` | 负 | UDP 载体拒绝 | — | — |
| 10 | `dameng_neg_port` | 负 | 非标准目的端口拒绝 | — | — |
| 11 | `dameng_neg_profile` | 负 | 未登记 profile 拒绝 | — | — |
| 12 | `dameng_neg_state` | 负 | 未认证即 SQL/错误顺序 | — | — |
| 13 | `dameng_neg_truncated` | 负 | 应用消息截断 | — | — |
| 14 | `dameng_neg_oversize` | 负 | 超过实现消息上限 | — | — |

## 3. 正例契约

### 3.1 `dameng_connect`（T-DM-S1）

IPv4、TCP 目的端口 5236，单个 `connect` c2s 事件，profile=`connect_default`。预期 8 包。packet 4 应有 `tcp.dstport=5236` 且 `tcp.len` 非零；`has_payload=true` 只证明连接事件生成了 TCP 载荷，不证明未知私有头字段。

### 3.2 `dameng_auth_success`（T-DM-S2）

事件按顺序为 `connect(c2s)`、`auth_request(c2s)`、`auth_response(s2c,result=success)`，profile=`dm8_profile_pending`/`auth_default`。预期 10 包。packet 4/5 的目的端口为 5236，packet 6 的源端口为 5236；全部应用事件均有非空 TCP payload。认证摘要和用户名字段不作 frame 断言。

### 3.3 `dameng_sql_success`（T-DM-S3）

事件为 connect、auth_request、auth_response(success)、sql_request(`SELECT 1`)、sql_response(success)，预期 12 包。packet 4、5、7 为 c2s（目的端口 5236），packet 6、8 为 s2c（源端口 5236）；最后一个响应必须是独立 s2c 应用段。SQL 文本仅作为语义输入，不能据此断言 ASCII/UTF-8 在 wire 中连续出现。

### 3.4 `dameng_sql_error`（T-DM-S4）

事件序列与 S3 相同，但 SQL 为明确失败语义 `SELECT missing_column FROM missing_table`，响应 `result=error`，profile=`sql_error_default`。预期 12 包。断言请求和响应方向、TCP 5236、非空 payload；不编造错误码、错误文本或结果集格式。

### 3.5 `dameng_length_boundary`（T-DM-S5）

使用 `length_boundary` profile 和 `payload_size="profile_minimum_nonempty"`，事件仍为完整连接、认证和 SQL 成功序列，预期 12 包。packet 4 的 `tcp.len` 非零，且 packet_count 保持 12。这里的“边界”是 profile 声明的最小合法非空编码，不写未经证实的 Dameng 长度字段或数值；实现阶段必须用版本 fixture 把它替换为实际消息长度断言。

### 3.6 `dameng_ipv4`（T-DM-S6）

源 `10.0.0.1`、目的 `20.0.0.1`、TCP 5236，完整 SQL 成功序列，预期 12 包。packet 4 `ip.version=4`，packet 4/5 `tcp.dstport=5236`。应用头起点不作常量 offset 断言。

### 3.7 `dameng_ipv6`（T-DM-S7）

源 `2001:db8::1`、目的 `2001:db8::2`、TCP 5236，完整 SQL 成功序列，预期 12 包。packet 4 `ipv6.version=6`，packet 4/5 `tcp.dstport=5236`，packet 6 `tcp.srcport=5236`。IPv6 只改变外层传输，不改变未定稿的 profile 语义。

### 3.8 `dameng_multi_session`（T-DM-S8）

两条独立 session，源端口 12345、12346，均连接 5236；每条只产生 connect、auth_request、auth_response 三个事件，预期 20 包（每流 10 包）。断言 `tcp.dstport` 只有 5236、`tcp.srcport` distinct values（去重值）包含 5236，且源端口 distinct values 为 12345/12346。不能根据全局 packet 序号推断两流事件交织顺序。

## 4. 负例契约

每个负例 `expect` 仅含两个键，确保错误在 planner/validator（校验器）边界传播，而不是“完成但 0 包”。

| id | 输入故障 | `error_contains` |
|---|---|---|
| `dameng_neg_udp` | `layers=[udp,dameng]` | `tcp` |
| `dameng_neg_port` | `dst_port=5237` | `5236` |
| `dameng_neg_profile` | `wire_profile=unknown_profile` | `profile` |
| `dameng_neg_state` | 直接发 `sql_request`，缺少 connect/auth | `state` |
| `dameng_neg_truncated` | `wire_fault.kind=truncate_message` | `truncated` |
| `dameng_neg_oversize` | `wire_fault.kind=message_limit,value=over_limit` | `limit` |

`wire_fault` 是未来实现的负例注入入口，不是合法生产配置；不能让它输出损坏的 PCAP。若实现阶段使用不同稳定错误文本，先同步修改 design、testcase 和 JSON，再运行 suite（测试套件）。

## 5. 三方一致性检查

1. 本文 14 个 id、设计 §5 的 14 个 id、JSON 数组的 14 个 id 集合和顺序一致。
2. 正例包数严格为 `[8,10,12,12,12,12,12,20]`；每条都有握手、终止、非空 payload 和字段断言。
3. 负例没有 `packet_count`、`fields`、`frames`，`expect` 只能是 `expect_error`/`error_contains`。
4. 当前无任何 Dameng 应用 frame offset；不能把 IPv4 54 或 IPv6 74 误写成应用头起点。以后加入 fixture 必须由 TCP stream 重组或动态 dissector（解析器）字段支撑。
5. 所有正例显式使用 TCP 5236；UDP 和非标准端口各有独立负例。

## 6. 实现后执行建议

先运行 JSON 语法/id/负例结构静态检查，再执行 S1/S2 验证状态和方向，执行 S3/S4 验证成功/错误分叉，最后执行边界、IPv4、IPv6、多会话。取得版本化 PCAP 后，为每个 profile 补失败优先的应用头长度、字节序、认证和 SQL 字节断言；在此之前不能宣称 Dameng wire 已实现。

## 7. 修订记录

- v1.0.0（2026-08-20）：建立 8 个正例和 6 个负例；覆盖连接、认证、SQL 成功/错误、长度边界、IPv4/IPv6、多会话和 TCP/端口/profile/状态/截断/上限错误；明确不固定未证实的 Dameng 私有应用字节。
