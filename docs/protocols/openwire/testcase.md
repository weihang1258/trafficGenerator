# OpenWire 测试契约（as-built 审计版）

> 版本：v2.1.0（2026-10-01）  
> 机器契约：`trafficgen/test/protocol_pcap/cases/openwire.json`  
> 当前状态：24 条静态 cases，15 正例、9 负例；本轮不运行 suite/server/MCP/NIC，不宣称运行全绿。

## 1. 执行边界与真实形状

OpenWire 当前只能按实现支持的 **flat 业务配置 + `[tcp, openwire]`** 运行。registry 的 `openwire` Fields 只有 `profile`，且 planner 没有把 `layers[].openwire` 翻译为 `spec.OpenWire`；因此本文件不把 cases 改成未被实现支持的严格层链。地址、端口和完整 `openwire` 对象仍位于 `spec_json` 顶层，这是已登记的 `G-OW-1`，不是遗漏。

当前每个正例至少包含 `packet_count`/`min_packets`、可观察 TCP/业务字段或 raw frame；每个负例的 `expect` 严格只有 `expect_error`、`error_contains`，不以空 PCAP、0 包或 completed 冒充错误。

## 2. 原子用例索引与覆盖去向

| # | ID | 类型 | 覆盖 |
|---:|---|---|---|
| 1 | `openwire_wire_format_ipv4` | 正 | IPv4/TCP 61616、WireFormatInfo |
| 2 | `openwire_wire_format_ipv6` | 正 | IPv6/TCP 协商、Next Header |
| 3 | `openwire_connection_session` | 正 | Connection/Session 生命周期 |
| 4 | `openwire_producer_consumer` | 正 | Producer/Consumer/destination |
| 5 | `openwire_message_persistent` | 正 | Message、persistent、body |
| 6 | `openwire_dispatch_ack` | 正 | Dispatch/Ack correlation |
| 7 | `openwire_transaction_commit` | 正 | begin→message→commit |
| 8 | `openwire_transaction_rollback` | 正 | begin→message→rollback |
| 9 | `openwire_multi_flow` | 正 | 多 session/entity/destination |
| 10 | `openwire_multi_connection` | 正 | 多 TCP 连接隔离 |
| 11 | `openwire_message_body_segmentation` | 正 | body 跨 TCP segment |
| 12 | `openwire_exception_response` | 正 | ExceptionResponse correlation |
| 13 | `openwire_remove_shutdown` | 正 | Remove/Shutdown |
| 14 | `openwire_ipv4_ipv6_same_payload` | 正 | 双栈逻辑 payload |
| 15 | `openwire_ack_modes` | 正 | auto/client/individual ACK |
| 16 | `openwire_neg_short_frame` | 负 | `frame` 锚词 |
| 17 | `openwire_neg_unknown_command` | 负 | `command` 锚词 |
| 18 | `openwire_neg_length_overrun` | 负 | `length` 锚词 |
| 19 | `openwire_neg_state_order` | 负 | `session` 锚词 |
| 20 | `openwire_neg_correlation` | 负 | `correlation` 锚词 |
| 21 | `openwire_neg_transaction` | 负 | `transaction` 锚词 |
| 22 | `openwire_neg_entity_scope` | 负 | `entity` 锚词 |
| 23 | `openwire_neg_destination` | 负 | `destination` 锚词 |
| 24 | `openwire_neg_carrier_profile` | 负 | `port` 锚词 |

JSON 与本表均保留 24 个原 ID；当前 cases 文件恢复为实现可消费的原 flat 形状，未作伪迁移。

## 3. 负例严格契约

| ID | 注入 | JSON 锚词 | 实现真实错误锚点 |
|---|---|---|---|
| 16 | `wire_fault.kind=short_frame` | `frame` | validator 返回 `(frame/length)` |
| 17 | `wire_fault.kind=bad_type` | `command` | validator 返回 `(command/type)` |
| 18 | `wire_fault.kind=length_overrun` | `length` | validator 返回 `(length)` |
| 19 | 未建 session 先 producer | `session` | entity scope/state 错误含 session |
| 20 | 未注册 consumer 的 ack | `correlation` | correlation/message 错误 |
| 21 | 无 begin 直接 commit | `transaction` | transaction 错误 |
| 22 | producer 引用未知 session | `entity` | entity/connection 错误 |
| 23 | 非 queue/topic destination | `destination` | destination 错误 |
| 24 | TCP 错误目的端口 61617 | `port` | validator 的 destination port 错误 |

每条负例只保留 `expect_error` 和 `error_contains` 两个键；真实锚词取自 `layer_gen.go`，不使用臆造 dissector 文本。

## 4. 三源测试点清单（T1–T3）

| 测试点 | 规范/行为源 | 代码分支 | case/状态 |
|---|---|---|---|
| WireFormatInfo 首 command、TCP 长连接 | OpenWire WireFormatInfo/transport 定义 | `validateConnection`、`BuildWireFormatInfo` | 1、2；PCAP 待 G-OW-2 |
| Connection/Session 状态 | OpenWire command lifecycle | `connState` | 3、9、10 |
| Producer/Consumer/destination | command fields | `destinationParts`、实体表 | 4、15、23 |
| Message/Dispatch/Ack | message correlation | `connState.messages` | 5、6、15、20 |
| Transaction | TransactionInfo kind | `txOpen/txDone` | 7、8、21 |
| length/type/body/MSS | wire builder + TCP | `frameCommand`、MSS path | 11、16–18 |
| Exception/Remove/Shutdown | command lifecycle | 对应 builder/state | 12、13、19 |
| IPv4/IPv6 | TCP/IP carrier | 自驱生成器 | 1、2、14；未运行 |

## 5. §3.15 与失败路径

OpenWire 有长连接，但当前 schema 没有显式 `sessions[]` 编排层；多轮操作由同一连接的 `events[]` 表达：3–9、15 覆盖多动作序列，12、13、19、21 覆盖异常/关闭路径。heartbeat/idle 保活没有配置入口，登记 `G-OW-4`，不把重复静态事件冒充保活。

负例必须在 planner/validator→engine→task 路径成为 task error。只要真实执行发现 completed/0 packet、静默丢错或锚词不匹配，不能改 expect 迁就，须登记并回到实现阶段。

## 6. 动态、正交和断言边界

当前 OpenWire layer schema 没开放业务字段动态策略，且没有 `flows>1` 入口；本套件仅声明固定 fixture 覆盖。`ip`/`tcp` 的通用动态能力不能冒充 OpenWire 业务动态覆盖，登记 `G-OW-4`。

正交维度已列出：地址族×连接数（1、2、10、14）、实体×ACK（4、6、9、15）、事务 kind（7、8、21）、malformed fault（16–18）。由于本轮不跑 suite，packet_count、字段和帧 hex 是待 G-OW-2 复核的静态断言，不能当作新运行证据；TCP segment 边界也不能当作 command 边界。

## 7. 存量审计（T5）

24/24 ID 在 JSON 中保留，15/15 正例与 9/9 负例均有表格去向；无作废、无等价替代。JSON 机读检查应确认：

1. 24 个 ID 唯一且顺序与本文 §2 一致；
2. 每条 `spec_json` 保留当前实现消费的 flat 地址/端口/业务键与 `[tcp,openwire]` 链；
3. 正例没有 `expect_error`；
4. 负例 `expect` 键集严格等于 `{expect_error,error_contains}`；
5. 锚词分别为 `frame`、`command`、`length`、`session`、`correlation`、`transaction`、`entity`、`destination`、`port`。

## 8. C1–C6 审查结论

| ID | 结论 |
|---|---|
| C1 | JSON 可解析，24 ID 唯一，设计与 testcase 顺序一致。 |
| C2 | 诚实记录当前为 flat 过渡形；不声称严格层链迁移。 |
| C3 | 当前链为 `[tcp, openwire]`；层链与顶层字段混用是实现现状，缺口 G-OW-1。 |
| C4 | 15 条正例有可观察 expect；9 条负例严格双键。 |
| C5 | 多连接、事务、分段、ACK、异常/关闭均有独立 case；动态、TLS/WebSocket、商业抓包等未覆盖均登记 G-*。 |
| C6 | 本轮仅改 design.md、testcase.md、openwire.json；不改 Go/schema/LAYERCHAIN_INDEX/其他协议。 |

## 9. 执行门与缺口

- `G-OW-1`：补 OpenWire registry Fields 与 translate 后，才能迁移为纯严格层链并重新生成 schema；当前不改实现。
- `G-OW-2`：本轮未运行 suite/server/MCP/NIC，PCAP 包数、dissector 字段、raw frame 与双栈 self-drive 待真实流程校准。
- `G-OW-3`：TLS/WebSocket/压缩/selector/集群拓扑需独立承载/解密证据。
- `G-OW-4`：flows 与业务 inc/rand/list/pattern 没有 schema/layer_dyn 入口，后续逐策略整格补例。
- `G-OW-5`：无真实 ActiveMQ broker 版本抓包，商业行为映射待确认。

本轮执行顺序只到静态审计：JSON 解析、ID/键集/形状核对；不运行 suite/server/MCP/NIC，不宣称完成运行验收。

## 10. 修订记录

- v2.1.0（2026-10-01）：按 registry、translate、OpenWire generator 与原 JSON as-built 重审；恢复实现可消费的 flat cases，补 T1–T5、C1–C6 和 G-OW-1…5。
