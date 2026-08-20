# KingBase（人大金仓）设计与用例对抗审查

> 审查范围：`docs/protocol-designs/34-kingbase-design.md`、`docs/protocol-designs/34-kingbase-testcase.md`、`trafficgen/test/protocol_pcap/cases/kingbase.json`  
> 日期：2026-08-20  
> 状态：设计文档审查；不检查 Go（编程语言）实现，不宣称 `kingbase` 层已注册。

## 1. 审查口径

本审查分为两个独立视角：

- **代码逻辑视角替代项：规格可实现性**：检查设计是否把 KingBase 版本/兼容模式、TCP 载体、PostgreSQL-compatible 外层、profile 边界和失败传播写成可实现而非伪精确的契约。
- **用例覆盖视角**：逐项对照设计表、状态规则和错误处理表，检查 JSON 是否有原子 observable 断言；确认正例包数、id、事件数和负例结构在三方一致。

结论只基于当前文档；私有认证/SQL 扩展/错误字段未取得版本化证据，因此将其列为待实现边界而不是缺陷。

## 2. 规格可实现性审查

### 2.1 已确认的设计约束

1. **profile 隔离清晰**：`kingbase_es_v8_pg_compatible` 是实现契约名而非线上字段；`kingbase_native_pending` 不得自动复用兼容模板；未登记 profile 必须失败。
2. **载体和端口明确**：KingBase 终结层只能位于 TCP 后，默认目的端口统一为 54321；UDP、缺 TCP、非标准端口均有拒绝路径。
3. **外层语义足够具体**：Startup 无 type 字节；typed message 使用 `type + int32 length + payload`；R/p/Z/Q/E/T/D/C/X 的类别、方向和状态角色可由 planner 实现。
4. **不编造私有字节**：认证子类型/盐/摘要、KingBase 私有参数、SQL 扩展、错误码、结果元数据、压缩/TLS 均以 profile/fixture 待实现，不把 PostgreSQL 参考流量冒充 KingBase 事实。
5. **失败传播有明确目标**：unknown profile、载体、端口、状态、Startup 长度和消息上限都要求 task error，而不是零包成功。

### 2.2 需实现阶段守护的边界

| 项目 | 文档契约 | 实现前必须补充 |
|---|---|---|
| Startup 参数 | 用户/数据库名为输入，长度按编码字节回填 | 编码器单测、非 ASCII 字节长度、实际 profile fixture |
| Auth | 只断言 R/p 外层类别 | 每个认证方法的版本/盐/摘要依据；禁止默认猜测 |
| Ready | 只断言 Ready 类别 | status 字节及错误后 session 状态的 profile 规则 |
| Query 成功 | T/D/C 作为三个原子事件 | 列元数据、DataRow 值、command tag 的来源和长度 |
| Query 错误 | E 外层类别和非空载荷 | SQLSTATE/字段标签/KingBase 错误码的版本 fixture |
| 分片 | 小 payload 一事件一段的包数公式 | MSS/重组测试；不能拿 segment offset 当 stream offset |
| 多会话 | 每条流独立四元组和状态 | worker 排序、跨流 response 关联的集成测试 |

以上是实现前的完成定义，不是当前文档 finding（发现项）；设计已经明确将这些内容留作待实现边界。

## 3. 用例覆盖对抗审查

### 3.1 正例逐条核对

| id | 设计覆盖 | JSON observable | 结果 |
|---|---|---|---|
| `kingbase_connect` | TCP connect、54321、握手/终止 | `tcp.dstport`、7 包 | 通过；无应用事件，不误断言 payload |
| `kingbase_startup` | Startup 无 type、非空 payload | `pgsql.type=Startup message`、`tcp.len`、端口 | 通过；不伪造 Startup type hex |
| `kingbase_auth_success` | Startup→R→p→Z | 四个 `pgsql.type` | 通过；不固定认证子类型/摘要 |
| `kingbase_query_success` | Q→T→D→C→Z | Q/query、T/D/C/Z 字段 | 通过；结果拆成三个原子事件，包数 16 |
| `kingbase_query_error` | Q→E→Z | Q/query、E、Z 字段 | 通过；不固定 SQLSTATE/错误码 |
| `kingbase_ipv4` | IPv4 载体、端口和外层 | `ip.version`、R/Z、端口 | 通过 |
| `kingbase_ipv6` | IPv6 载体、端口和外层 | `ipv6.version`、R/Z、端口 | 通过；Startup 不使用固定 type offset |
| `kingbase_multi_session` | 两条独立流 | srcport distinct/exclude、dstport | 通过；不依赖全局交错顺序 |
| `kingbase_length_boundary` | 最小合法 Startup 输入 | Startup、非空 `tcp.len`、端口 | 通过；长度精确检查留给 builder 单测 |

### 3.2 负例逐条核对

| id | 设计错误行 | JSON expect | 结果 |
|---|---|---|---|
| `kingbase_neg_udp` | UDP/缺 TCP | 仅 `expect_error` + `tcp` | 通过 |
| `kingbase_neg_port` | 非 54321 | 仅 `expect_error` + `54321` | 通过 |
| `kingbase_neg_profile` | 未登记 profile | 仅 `expect_error` + `profile` | 通过 |
| `kingbase_neg_state` | Ready 前 Query | 仅 `expect_error` + `state` | 通过 |
| `kingbase_neg_truncated` | Startup 长度/截断 | 仅 `expect_error` + `length` | 通过 |
| `kingbase_neg_oversize` | 消息超限 | 仅 `expect_error` + `limit` | 通过 |

## 4. 三方静态一致性结果

审查时使用脚本读取设计表、测试文档索引和 JSON（不执行未注册协议）：

- id 集合：15 个，设计/测试/JSON 一致且唯一。
- 正例：9 个；包数 `[7, 8, 11, 16, 14, 11, 11, 22, 8]` 与设计表和测试表一致。
- 负例：6 个；每个 `expect` 恰有 `expect_error`、`error_contains`，没有 `packet_count`、`fields` 或 `frames`。
- 正例均有 `has_handshake=true`、`terminates=true`；有应用事件的正例均有 `has_payload=true`。
- profile：正例均显式使用 `kingbase_es_v8_pg_compatible`；负例只在 profile 负例使用 `unknown_profile`。
- 载体：正例全部为 TCP→KingBase 层链；UDP 仅出现在负例。
- 端口：正例均 54321；非标准 54322 仅出现在负例。
- IPv4/IPv6：各有独立正例；多会话使用 12345/12346 两个源端口。

## 5. Findings（发现项）

### F-01（已修复：查询成功的事件/包数曾不原子）

初始草案把 Query 成功结果写成单个 `query_success` 事件，却在 testcase 文字中同时要求 Row description/Data row/Command completion，导致 observable 数量和 `packet_count` 不能唯一推导。已将成功结果拆为三个原子事件，三方统一为 9 个应用事件、16 包，并逐包断言 T/D/C/Z。当前审查结果为已修复。

### F-02（已修复：测试文档包数索引同步）

F-01 修复后同步更新设计场景表、测试索引和三方一致性列表；静态检查确认无旧的 14 包成功值残留。

### F-03（保留为待实现边界，不是文档缺陷：pgsql dissector 文本）

`pgsql.type` 的显示文本依赖 tshark 版本；当前 JSON 使用既有 PostgreSQL case 已验证的显示文本作为外层可观察契约。若未来 tshark 版本显示不同，应更新 decode/field mapping，而不放宽为“任意 payload”。

## 6. 最终结论

本轮为设计文档审查，不涉及 Go 实现。KingBase 版本/兼容模式已通过 profile 隔离；TCP 默认端口 54321、PostgreSQL-compatible Startup/typed message 外层、连接/认证/查询成功/查询错误/Ready、IPv4/IPv6、多会话、长度边界和负例均已覆盖；私有认证、SQL 扩展和字节细节未编造固定 hex。

自审记录：完成两轮逐行审查。第 1 轮发现 F-01/F-02 并修复后复审；第 2 轮检查三方 id、事件数、包数、负例字段和 profile/端口/载体边界，未发现新问题；**最后一轮 clean（通过）**。
