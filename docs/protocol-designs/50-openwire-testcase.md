# OpenWire（ActiveMQ 原生线协议，ActiveMQ OpenWire）测试用例设计

> 版本：v1.0.0（设计阶段）
> 日期：2026-08-20
> 配套设计：`docs/protocol-designs/50-openwire-design.md`
> 机器契约：`trafficgen/test/protocol_pcap/cases/openwire.json`
> 状态：`openwire` 层尚未注册；本文定义实现后的 PCAP（抓包文件）断言，不宣称当前 suite（测试套件）可运行。

## 1. 测试原则与执行边界

本套件由设计文档 §2–§9 逐项派生，共 25 个唯一 ID：15 个目标正例、9 个目标负例，以及 1 个注册前置占位。由于当前没有 `openwire` layer/planner（层/规划器），JSON 暂时将全部条目标为 `expect_error=true`、`error_contains=unknown layer` 的不可执行占位；实现注册后，前 15 项改为对应 PCAP 断言，后 9 项保持严格错误断言。不能用未注册结果声称协议行为已通过。

OpenWire 使用 TCP，默认端口 61616。无 VLAN/IP options/TCP options 时，IPv4 TCP payload 起点为 offset 54，IPv6 为 offset 74；TCP segment 边界不等于 command 边界，必须按 profile 的长度/编码重组后验证。每个未来正例至少需要 `packet_count` 或 `min_packets`、`fields`、`frames`；负例的 `expect` 严格只有 `expect_error`、`error_contains`，不允许用空 PCAP 或 0 包冒充错误。

OpenWire command type 和 length 依 wire format profile（线格式协议档案）而定；在 `tshark -G fields | grep '\topenwire\.'` 确认字段前，不猜造 `openwire.*` 字段。未来若无稳定 dissector（解析器），使用 TCP/IP 字段、stream 重组后的 raw frames 和明确 notes（说明）验证；动态 command/entity ID 用 `nonzero`/`same_as_packet`，不固定随机常量。

## 2. 原子用例索引

| # | ID | 类型 | 覆盖 | 实现后断言重点 |
|---:|---|---|---|---|
| 1 | `openwire_wire_format_ipv4` | 正 | IPv4 WireFormatInfo 协商与首 command | TCP/61616、版本、协商字段 |
| 2 | `openwire_wire_format_ipv6` | 正 | IPv6/TCP 协商、Next Header=6 | `ipv6.nxt=6`、地址族、协商关联 |
| 3 | `openwire_connection_session` | 正 | ConnectionInfo、SessionInfo 生命周期 | connection/session ID 关联 |
| 4 | `openwire_producer_consumer` | 正 | ProducerInfo、ConsumerInfo、destination | entity ID、queue/topic、session 关联 |
| 5 | `openwire_message_persistent` | 正 | Message、persistent 属性、body | producer/message/destination、body 长度 |
| 6 | `openwire_dispatch_ack` | 正 | MessageDispatch、MessageAck、correlation | consumer/message/ack mode 关联 |
| 7 | `openwire_transaction_commit` | 正 | begin→message→commit | transaction ID 和顺序 |
| 8 | `openwire_transaction_rollback` | 正 | begin→message→rollback | rollback 生命周期 |
| 9 | `openwire_multi_flow` | 正 | 多 session/producer/consumer/destination | flow/entity 状态隔离 |
| 10 | `openwire_multi_connection` | 正 | 多 TCP 连接和状态隔离 | tcp.stream/源端口 distinct |
| 11 | `openwire_message_body_segmentation` | 正 | body 跨 TCP segments、重组长度 | command/body 长度，不按包切分 |
| 12 | `openwire_exception_response` | 正 | ExceptionResponse 与 request correlation | response/request ID 关联 |
| 13 | `openwire_remove_shutdown` | 正 | RemoveInfo、ShutdownInfo 生命周期 | close 后无新业务 command |
| 14 | `openwire_ipv4_ipv6_same_payload` | 正 | 独立双栈 fixture、逻辑 payload 一致 | 外层地址族、payload 重组一致 |
| 15 | `openwire_ack_modes` | 正 | auto/client/individual ACK 边界 | ACK mode、consumer/message 关联 |
| 16 | `openwire_neg_short_frame` | 负 | command header/length 截断 | `error_contains=unknown layer`（当前占位） |
| 17 | `openwire_neg_unknown_command` | 负 | 未知 data structure type | `error_contains=unknown layer`（当前占位） |
| 18 | `openwire_neg_length_overrun` | 负 | command length 越界/溢出 | `error_contains=unknown layer`（当前占位） |
| 19 | `openwire_neg_state_order` | 负 | 未协商/未建 session 先发业务 command | `error_contains=unknown layer`（当前占位） |
| 20 | `openwire_neg_correlation` | 负 | response/ack/message 跨实体关联 | `error_contains=unknown layer`（当前占位） |
| 21 | `openwire_neg_transaction` | 负 | commit/rollback 重复或跨 session | `error_contains=unknown layer`（当前占位） |
| 22 | `openwire_neg_entity_scope` | 负 | producer/consumer/session 跨 connection | `error_contains=unknown layer`（当前占位） |
| 23 | `openwire_neg_destination` | 负 | queue/topic/destination 非法 | `error_contains=unknown layer`（当前占位） |
| 24 | `openwire_neg_carrier_profile` | 负 | 非 TCP、错误端口或 profile 不兼容 | `error_contains=unknown layer`（当前占位） |

## 3. 机器配置示例

以下是实现注册后的设计期配置块，不替代当前 JSON 的未注册占位：

```json
{
  "layers": [{"tcp": {}}, {"openwire": {}}],
  "src_ip": "192.0.2.10",
  "dst_ip": "198.51.100.20",
  "src_port": 40000,
  "dst_port": 61616,
  "openwire": {
    "profile": "activemq_openwire_v12",
    "wire_format": {"version": 12, "tight_encoding": true, "cache_enabled": true},
    "connections": [{
      "connection_id": 1,
      "events": [
        {"kind": "wire_format_info", "direction": "c2s"},
        {"kind": "connection_info", "direction": "c2s"},
        {"kind": "connection_ack", "direction": "s2c"},
        {"kind": "session_info", "session_id": 1, "direction": "c2s"}
      ]
    }]
  }
}
```

## 4. 正例契约（实现后）

1. **`openwire_wire_format_ipv4`**：IPv4/TCP/61616 建连后首个 OpenWire command 为 WireFormatInfo；断言 `tcp.dstport=61616`、版本/profile、协商 options，raw frame 固定稳定命令前缀，不固定运行期 ID。
2. **`openwire_wire_format_ipv6`**：IPv6/TCP 协商；断言 `ipv6.nxt=6`、地址族和首 command，payload offset 74；不把 IPv6 地址写入 WireFormatInfo。
3. **`openwire_connection_session`**：WireFormatInfo 后 ConnectionInfo/ack，再 SessionInfo；断言 connection/session ID 关联和方向，未建立 connection 不生成 session。
4. **`openwire_producer_consumer`**：SessionInfo 后 ProducerInfo、ConsumerInfo，分别绑定 queue/topic destination；断言 entity ID、session、destination 和 lifecycle 顺序。
5. **`openwire_message_persistent`**：已注册 producer 发送 Message，persistent=true，body 非空；断言 message/producer/session/destination、persistent property 和重组 body 长度，不声称 broker 已落盘。
6. **`openwire_dispatch_ack`**：broker dispatch 给已注册 consumer，client 发送 ack；断言 consumer/session/message ID 关联、ack mode 和 redelivery 显式值。
7. **`openwire_transaction_commit`**：显式 transaction begin→Message→commit；断言 transaction ID、session scope 和顺序，commit 后不追加同一事务命令。
8. **`openwire_transaction_rollback`**：begin→Message→rollback；断言 rollback 只结束该事务，不能把 rollback 误解为已持久化。
9. **`openwire_multi_flow`**：同连接多个 session/producer/consumer/destination 交织事件；使用 entity/session distinct 与关联字段，不能按全局 packet index 假定顺序。
10. **`openwire_multi_connection`**：两个独立 TCP 四元组各自完成协商/connection/session；断言 `tcp.stream` 或源端口 distinct、实体/transaction 状态不串。
11. **`openwire_message_body_segmentation`**：body 大于单 TCP MSS，跨多个 TCP segment；按 stream 重组后断言 command length 与 body 总长度，不能把 segment 数当 command 数。
12. **`openwire_exception_response`**：对显式 request 返回 ExceptionResponse；断言 response 与请求 command/correlation 关联、异常字段存在，业务 exception 不应被当作 planner error。
13. **`openwire_remove_shutdown`**：显式 RemoveInfo/ShutdownInfo 后连接终止；断言关闭方向和状态，关闭后不得生成新的 Message/Dispatch。
14. **`openwire_ipv4_ipv6_same_payload`**：使用两个独立同族 fixture：IPv4 `192.0.2.10→198.51.100.20:61616` 与 IPv6 `2001:db8:50::10→2001:db8:50::20:61616`，逻辑 WireFormatInfo/Message payload 相同；分别断言 `ip.version`/`ipv6.nxt` 和重组 bytes，不在一个顶层 IPv4 layer-chain 中混入 session 级 IPv6。
15. **`openwire_ack_modes`**：显式 auto、client、individual 三类 consumer/ack fixture；断言 ACK mode、consumer/message 关联和各自允许的 ACK 次数，不能由重复 body 猜测 ACK。

合法 redelivery、ExceptionResponse、persistent property、rollback 和 broker shutdown 是正例事件；只有配置/线格式错误进入负例。

## 5. 负例契约

每个负例必须由 planner/validator 错误传播为 task error，不得产生成功 PCAP、completed/0 packet 或只剩 TCP ACK 的假成功。注册实现后应将以下占位替换为稳定错误锚点：

| ID | 故障注入 | 目标错误锚点 |
|---|---|---|
| `openwire_neg_short_frame` | command header 少于 profile 最小长度或截断 | `frame`/`length` |
| `openwire_neg_unknown_command` | 未知 data structure type | `command`/`type` |
| `openwire_neg_length_overrun` | command length 越过 stream 或整数溢出 | `length` |
| `openwire_neg_state_order` | 未协商先发业务、未建 session 先发 entity、close 后发 command | `state`/`session` |
| `openwire_neg_correlation` | response/ack/message 跨 producer/consumer/session | `correlation`/`message` |
| `openwire_neg_transaction` | 无 begin commit、重复终止或跨 session transaction | `transaction` |
| `openwire_neg_entity_scope` | producer/consumer/session 引用另一个 connection | `entity`/`connection` |
| `openwire_neg_destination` | 空/非法 queue/topic destination 或类型不符 | `destination` |
| `openwire_neg_carrier_profile` | 非 TCP、错误端口、未知/不兼容 profile | `tcp`/`port`/`profile` |

当前 JSON 只有 1 项未注册层占位，语义 ID 仍是 24 项；它只证明 `openwire` 尚未注册，不证明上述九项 validator 已实现。

## 6. 规范覆盖与三方一致性

| 设计要求 | 覆盖 ID | 证据类型 | 当前状态 |
|---|---|---|---|
| TCP/61616、IPv4/IPv6、payload offset | 1, 2, 10, 14 | TCP/IP fields + raw frames | 待 layer/planner |
| WireFormatInfo 与 connection/session 状态 | 1–3, 19 | command order + correlation | 待 planner |
| producer/consumer/destination | 4, 9, 23 | entity/destination fields | 待 planner/validator |
| Message、persistent、dispatch、ACK | 5, 6, 15, 20 | message/entity/ack fields + body | 待 planner |
| transaction commit/rollback | 7, 8, 21 | transaction order + scope | 待 planner/validator |
| 多连接、多流和状态隔离 | 9, 10, 14, 22 | stream/port distinct + association | 待 planner |
| body 重组和长度边界 | 5, 11, 16, 18 | command/body length + frames | 待 builder/validator |
| Exception/remove/shutdown | 12, 13 | response/termination + fields | 待 planner |
| 错误传播和负路径 | 16–24 | task error | 当前仅未注册占位 |

设计 §9、本文 §2 索引和未来 JSON 数组必须使用同一 24 个语义 ID、同一顺序；当前 JSON 只有一个不计入语义覆盖的 `openwire_neg_unregistered` 前置占位。实现注册后才将前 15 项改为正例断言，并把九个负例替换为目标错误锚点。

## 7. 实现后执行顺序

1. 运行 JSON parser（解析器）、24 个语义 ID 唯一性/顺序、expect 结构和 layer registry 静态检查。
2. 注册 `openwire` 后先验证 IPv4/IPv6 WireFormatInfo、payload offset 和 connection/session 关联。
3. 逐项验证 producer/consumer、Message/persistent、dispatch/ack、事务、body segmentation、多连接、多流、Exception/remove/shutdown 和 ACK modes。
4. 注入 frame/type/length/state/correlation/transaction/entity/destination/carrier 错误，确认 planner→engine→task error，不能 completed 但 0 包。
5. 运行 `-race` 和 suite；未注册错误只计不可运行，不计协议正例 PASS。

## 8. 修订记录

- v1.0.0（2026-08-20）：建立 15 个 OpenWire 目标正例与 9 个严格负例，覆盖 TCP WireFormatInfo、连接/session、producer/consumer、Message/dispatch/ACK、事务、持久化、多连接/多流、IPv4/IPv6、边界和错误传播；当前仅提交设计/用例契约，不修改 Go 实现。
