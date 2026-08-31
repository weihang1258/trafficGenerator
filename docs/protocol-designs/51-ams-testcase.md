# AMS（Apache ActiveMQ 管理协议，ActiveMQ Management Service）测试用例契约

> 版本：v1.0.0（设计阶段）
> 日期：2026-08-20
> 配套设计：`docs/protocol-designs/51-ams-design.md`
> 机器契约：`trafficgen/test/protocol_pcap/cases/ams.json`
> 状态：✅ 已实现并全绿（2026-08-31，20/20 驱动用例）。`ams` 层/planner 已注册；正例 14 项按 PCAP 断言运行（无 tshark dissector，走 TCP 字段与帧字节），负例 6 项保持严格错误断言。占位条目已由语义用例替换。

## 1. 测试原则和未注册边界

用例从设计 §2–§10 逐项派生，共 21 个唯一标识：14 个目标正例、6 个目标负例，以及 1 个注册前置占位。当前 JSON 只保留 `ams_neg_unregistered`，其 `expect` 必须为 `expect_error=true`、`error_contains="unknown layer"`；占位不计入 20 个 AMS 语义 ID，不能用拒绝、0 包或空 PCAP 冒充 AMS 帧行为通过。注册后移除占位，再按本文索引顺序加入 14 个正例和 6 个负例。

AMS 是 TCP 应用层协议。无 VLAN（虚拟局域网）、IP options（IP 选项）和 TCP options 时，IPv4 TCP payload（载荷）起点为 offset（偏移）54，IPv6 为 74。TCP MSS（最大报文段长度）分段后必须先按 Length 重组 AMS frame（帧）；正例实现后每条至少有 `packet_count` 或 `min_packets`、可观测 `fields`（字段）和稳定 `frames`（帧字节）。负例 `expect` 严格只有 `expect_error` 与 `error_contains`。

AMS frame 的稳定最小字节为 `Length(4)|Version(1)|Type(1)|Flags(2)|SessionID(4)|CorrelationID(8)|FrameEnd(2)`；Length 不包含自身 4 字节但包含其余 18 字节和 Payload。FrameEnd 固定 `ae 5a`。动态 SessionID、CorrelationID、message_id 和 sequence 不写死，除非 fixture 显式固定；优先使用 `nonzero`、`same_as_packet`、`distinct_values` 或 raw frame 的稳定前缀。未解密 TLS 只观察 TLS/TCP 外层，不能声称看见 AMS 字段。

## 2. 原子用例索引

| # | ID | 类型 | 覆盖 | 实现后证据 |
|---:|---|---|---|---|
| 1 | `ams_frame_header_ipv4` | 正 | TCP/IPv4、Length/Version/Type/Flags/Session | TCP 61616、offset 54、Length 与尾标记 |
| 2 | `ams_handshake_auth` | 正 | HELLO/HELLO_OK/AUTH/AUTH_OK | Type、方向、profile 和认证状态 |
| 3 | `ams_session_open_close` | 正 | OPEN_SESSION/OPEN_OK/CLOSE/CLOSE_OK | SessionID、状态顺序、终止 |
| 4 | `ams_command_response` | 正 | command/resource/correlation/response | CorrelationID 与状态码关联 |
| 5 | `ams_message_ack` | 正 | message/sequence/ack_for/ack_status | message_id、sequence、确认关联 |
| 6 | `ams_event_retransmission` | 正 | 显式消息重传 | message_id/sequence/payload 相等 |
| 7 | `ams_ping_pong` | 正 | session 内保活 | PING/PONG、session 关联 |
| 8 | `ams_multi_session` | 正 | 单 TCP 多 SessionID | session、correlation 和 ACK 状态隔离 |
| 9 | `ams_multi_stream` | 正 | 两个 TCP stream | 四元组、握手和状态隔离 |
| 10 | `ams_ipv6` | 正 | IPv6/TCP、Next Header=6 | `ipv6.nxt=6`、offset 74 |
| 11 | `ams_ipv4_ipv6_same_payload` | 正 | 两个地址族的相同逻辑帧 | outer address family、重组 payload 一致 |
| 12 | `ams_tlv_and_binary_payload` | 正 | TLV 边界和 binary payload | FieldID/FieldLength、稳定二进制前缀 |
| 13 | `ams_mss_frame_reassembly` | 正 | frame 跨 TCP segments | Length 重组后一次解析完整 frame |
| 14 | `ams_frame_boundary` | 正 | 最小/最大 Length、空字段和序列边界 | Length=18、零长 TLV、边界值 |
| 15 | `ams_neg_frame_encoding` | 负 | Version/Type/Flags/Length/FrameEnd 错误 | `frame`/`length`/`version` |
| 16 | `ams_neg_handshake_state` | 负 | 首帧、方向或认证顺序错误 | `hello`/`handshake`/`auth` |
| 17 | `ams_neg_session_reference` | 负 | 未打开、已关闭或跨连接 SessionID | `session`/`connection` |
| 18 | `ams_neg_correlation_response` | 负 | 响应缺失/重复/未知 CorrelationID | `correlation`/`response` |
| 19 | `ams_neg_message_ack` | 负 | 跨流、未知 message、sequence/ACK 范围错误 | `message`/`sequence`/`ack` |
| 20 | `ams_neg_tlv_length` | 负 | TLV 截断、字段长度或长度加法溢出 | `field`/`tlv`/`length` |
| 21 | `ams_neg_unregistered` | 占位 | 当前层注册前置 | `unknown layer`，不计语义覆盖 |

## 3. 线上编码和偏移断言

每个 AMS frame 的 TCP stream 编码为：

```text
Length(4) | Version(1) | Type(1) | Flags(2) | SessionID(4) |
CorrelationID(8) | Payload(N) | FrameEnd(2)
```

Length 是大端 uint32，值为 `18 + N`，自身 4 字节不计入。Version=1；FrameEnd 为 `ae 5a`。TLV 使用 `FieldID(2)|FieldLength(2)|Value`，FieldLength 只计 Value。`ams_frame_header_ipv4` 在 IPv4 payload offset 54 断言 Version/Type/Flags/SessionID/CorrelationID 的稳定结构和 `ae 5a`；不能将 TCP SYN payload 当 AMS frame。

`ams_handshake_auth` 必须按 HELLO→HELLO_OK→AUTH→AUTH_OK 顺序验证，并断言方向、profile 和协商 heartbeat/session_limit；planner 不自动插入遗漏响应。`ams_session_open_close` 继续验证 OPEN_SESSION→OPEN_OK→CLOSE_SESSION→CLOSE_OK，关闭后无新业务 frame。

`ams_command_response` 和 `ams_message_ack` 必须分别按 COMMAND→RESPONSE、MESSAGE→MESSAGE_ACK 验证；COMMAND/RESPONSE 使用相同非零 CorrelationID，MESSAGE_ACK 的 ack_for 等于 MESSAGE message_id，且 SessionID 与逻辑流一致。不能仅按 TCP packet index 建立关联。

`ams_mss_frame_reassembly` 的 frame 可被切分到多个 TCP segments；必须先重组 TCP stream，再按 Length 取出完整 frame 和 FrameEnd。不能因为单个 segment 不包含完整 frame 就报错，也不能按单包 payload 长度伪造 frame size。

## 4. 正例逐项断言契约

1. **`ams_frame_header_ipv4`**：TCP/IPv4/61616 完成最小 HELLO；断言 TCP destination port、payload presence、offset 54 的 Version=1、Type=HELLO、Length 与 frame 尾标记。不能把 SYN/ACK 视为 AMS frame。
2. **`ams_handshake_auth`**：显式 HELLO→HELLO_OK→AUTH→AUTH_OK；断言方向、profile、auth_method、credential_ref 不为空且不含明文密码。不得跳过 AUTH_OK 直接打开会话。
3. **`ams_session_open_close`**：认证后 OPEN_SESSION→OPEN_OK，再 CLOSE_SESSION→CLOSE_OK；断言同一 SessionID、关闭后终止，不能自动插入业务命令。
4. **`ams_command_response`**：SessionOpen 后发送 `broker.info` 或 `queue.inspect` COMMAND，server 返回 RESPONSE；断言 command/resource、非零 CorrelationID、同 session 和 status。不能声称 broker 的实际资源结果。
5. **`ams_message_ack`**：发送带 ack-required 的 MESSAGE，包含 message_id、message_kind、sequence 和 binary payload；对端返回 MESSAGE_ACK；断言 ack_for、ack_status、session/stream 关联。
6. **`ams_event_retransmission`**：显式重发同一消息；断言 message_id、sequence 和 payload 与原消息相同，重传不是新消息，不能隐式增加 sequence。
7. **`ams_ping_pong`**：SessionOpen 后显式 PING→PONG；断言 SessionID 和 CorrelationID 关联，未配置保活时不自动注入周期 PING。
8. **`ams_multi_session`**：同一 TCP 连接打开至少两个 SessionID，分别执行 command 和 ack-required message；断言 CorrelationID、message_id、sequence 和关闭状态隔离，不能把 session A 的 ACK 配给 B。
9. **`ams_multi_stream`**：两个独立 TCP 四元组分别完成 HELLO/AUTH/OPEN_SESSION 和一项业务；断言 tcp.stream/源端口 distinct，SessionID、CorrelationID 和 close 状态不串用。
10. **`ams_ipv6`**：IPv6/TCP/61616 使用同一最小握手 fixture；断言 `ipv6.nxt=6`、offset 74、应用 frame bytes 与 IPv4 版本一致。
11. **`ams_ipv4_ipv6_same_payload`**：两个独立 fixture 使用相同 AMS frame/TLV bytes；分别断言 `ip.version`/`ipv6.nxt` 与重组 payload 一致，不在单一 layer-chain 顶层混入两种地址族。
12. **`ams_tlv_and_binary_payload`**：COMMAND/MESSAGE 携带多个 TLV、零长可选字段和 base64（Base64 编码）二进制 payload；断言 FieldID/FieldLength 正确，线上发送解码后的 binary bytes，不发送 base64 文本。
13. **`ams_mss_frame_reassembly`**：设置小 MSS 使一帧跨多个 TCP segments；断言重组后 Length、TLV 和 FrameEnd 完整，不能按 packet boundary（包边界）切帧。
14. **`ams_frame_boundary`**：覆盖空 Payload 的 PING/PONG、Length=18、TLV FieldLength=0、最大受支持字段长度和 uint64 sequence/correlation 边界；断言无回绕、无超量分配，最后显式 CLOSE。

合法消息重传、业务 ERROR event、空 PING/PONG 和多会话并行属于正例行为；只有配置、线格式或状态引用错误进入负例。

## 5. 负例契约

负例必须在 planner/validator 处失败并传播为 task error，不得产生成功 PCAP、completed/0 packet 或只剩 TCP ACK。每个负例执行期 `expect` 只允许 `expect_error` 与 `error_contains`。

| ID | 故障输入 | 目标 `error_contains` |
|---|---|---|
| `ams_neg_frame_encoding` | Version 错误、未知 Type、保留 Flags 非零、Length 越界或 FrameEnd 非 `ae 5a` | `frame`、`length` 或 `version` |
| `ams_neg_handshake_state` | 缺 HELLO、方向反转、AUTH 未完成即 OPEN_SESSION 或重复握手 | `hello`、`handshake` 或 `auth` |
| `ams_neg_session_reference` | 未打开/已关闭 SessionID，或跨连接引用 session | `session` 或 `connection` |
| `ams_neg_correlation_response` | RESPONSE 使用未知、重复或跨 session CorrelationID | `correlation` 或 `response` |
| `ams_neg_message_ack` | ACK 未发送 message、跨流确认、sequence 回退或 ACK 范围越界 | `message`、`sequence` 或 `ack` |
| `ams_neg_tlv_length` | TLV 截断、FieldLength 越过 Payload 或长度加法溢出 | `field`、`tlv` 或 `length` |
| `ams_neg_unregistered` | `proto=ams` 且 layers 含未注册 `ams` | **`unknown layer`** |

## 6. 机器契约与静态检查

1. 运行 `python3 -m json.tool trafficgen/test/protocol_pcap/cases/ams.json`，确认当前 JSON 恰有一个 `ams_neg_unregistered` 条目，`proto=ams`，`expect_error=true`，`error_contains` 精确为 `unknown layer`。
2. 当前机器 ID 集合仅包含占位；占位不计入 20 个语义 ID。注册后 JSON 必须按本文 §2 顺序补入 14 个正例和 6 个负例。
3. 正例实现后每条应有 `packet_count`/`min_packets`、已注册 TCP/IP/IPv6 字段和稳定 `frames`；不得伪造未注册的 `ams.*` tshark 字段。AMS frame bytes 使用重组后的 payload offset 54/74。
4. 多会话/多流使用 tcp.stream、方向、端口 distinct 和 SessionID/CorrelationID/message_id 关联，不假设跨流调度顺序。
5. 负例 `expect` 只能包含 `expect_error`、`error_contains`；占位的 unknown layer 不得冒充协议语义负例已执行。

## 7. 三方一致性表

设计 §10、本文 §2 和未来 JSON 必须保持同一 20 个语义 ID、同一顺序；当前 JSON 另有一个不计入语义覆盖的注册前置占位。

```text
ams_frame_header_ipv4
ams_handshake_auth
ams_session_open_close
ams_command_response
ams_message_ack
ams_event_retransmission
ams_ping_pong
ams_multi_session
ams_multi_stream
ams_ipv6
ams_ipv4_ipv6_same_payload
ams_tlv_and_binary_payload
ams_mss_frame_reassembly
ams_frame_boundary
ams_neg_frame_encoding
ams_neg_handshake_state
ams_neg_session_reference
ams_neg_correlation_response
ams_neg_message_ack
ams_neg_tlv_length
```

## 8. 修订记录

- v1.0.0（2026-08-20）：建立 14 个 AMS 管理协议正例、6 个严格负例和 1 个未注册占位，覆盖 frame/TLV、握手认证、会话、命令/响应、消息/确认、重传、保活、IPv4/IPv6、多会话、多流、MSS 重组、边界和错误传播；不修改 Go 实现。
