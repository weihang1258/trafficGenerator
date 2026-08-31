# Swarm（去中心化 P2P 存储协议，Swarm Storage Profile）测试用例契约

> 版本：v1.0.0（设计阶段）
> 日期：2026-08-20
> 配套设计：`docs/protocol-designs/52-swarm-design.md`
> 机器契约：`trafficgen/test/protocol_pcap/cases/swarm.json`
> 状态：✅ 已实现并全绿（2026-08-31，20/20 驱动用例）。`swarm` 层/planner 已注册（ldp 同款 TransportOn 双载体：UDP discovery / TCP storage）；正例 14 项按 PCAP 断言运行（无 tshark dissector，走 TCP/UDP 字段与帧字节），负例 6 项保持严格错误断言。占位条目已由语义用例替换。

## 1. 测试原则和未注册边界

用例从设计 §2–§10 逐项派生，共 21 个唯一标识：14 个目标正例、6 个目标负例，以及 1 个注册前置占位。当前 JSON 只保留 `swarm_neg_unregistered`，其 `expect` 必须为 `expect_error=true`、`error_contains="unknown layer"`；占位不计入 20 个 Swarm 语义 ID，不能用拒绝、0 包或空 PCAP 冒充 Swarm 行为通过。注册后移除占位，再按本文索引顺序加入 14 个正例和 6 个负例。

Swarm profile 同时定义 UDP discovery 和 TCP storage 两种承载。无 VLAN（虚拟局域网）、IP options（IP 选项）和 TCP options 时，IPv4 UDP payload（载荷）起点为 offset（偏移）42，IPv4 TCP 为 54，IPv6 UDP 为 62，IPv6 TCP 为 74。TCP MSS（最大报文段长度）分段后必须先按 Length 重组 storage frame（存储帧）；UDP discovery 以 datagram（数据报）为 frame 边界。正例实现后每条至少有 `packet_count` 或 `min_packets`、可观测 `fields`（字段）和稳定 `frames`（帧字节）。负例 `expect` 严格只有 `expect_error` 与 `error_contains`。

Discovery frame 固定以 `SWD1`（`53 57 44 31`）开始，storage frame 固定以 `SWS1`（`53 57 53 31`）开始，FrameEnd 均为 `ae 5a`。动态 NodeID、Nonce、SessionID、StreamID、CorrelationID、chunk address 和 sequence 不写死随机常量，优先使用 `nonzero`、`same_as_packet`、`distinct_values` 或稳定 raw frame 前缀。未解密 TLS 只观察外层 TLS/TCP，不能声称看见 Swarm 字段。

## 2. 原子用例索引

| # | ID | 类型 | 覆盖 | 实现后证据 |
|---:|---|---|---|---|
| 1 | `swarm_discovery_ipv4` | 正 | UDP/IPv4 discovery PING/PONG | UDP/1634、SWD1、Nonce/NodeID 关联 |
| 2 | `swarm_handshake_tcp_ipv4` | 正 | TCP/IPv4 HELLO/AUTH | TCP/1634、SWS1、方向与能力 |
| 3 | `swarm_session_open_close` | 正 | OPEN_SESSION/OPEN_OK/CLOSE/CLOSE_OK | SessionID、顺序、终止 |
| 4 | `swarm_chunk_store` | 正 | content-addressed STORE/STORE_OK | address、size、payload、响应关联 |
| 5 | `swarm_chunk_retrieve` | 正 | RETRIEVE/CHUNK | CorrelationID、address、chunk bytes |
| 6 | `swarm_chunk_delivery_ack` | 正 | MESSAGE_ACK 和 delivery | message_id、ack_for、状态 |
| 7 | `swarm_manifest_exchange` | 正 | manifest root/entry、chunk 引用 | root、entry、地址关联 |
| 8 | `swarm_stream_multiplex` | 正 | 多 StreamID、交织请求 | stream distinct、请求状态隔离 |
| 9 | `swarm_multi_session` | 正 | 单连接多 SessionID | session/ACK/correlation 隔离 |
| 10 | `swarm_ipv6` | 正 | IPv6 discovery/storage | `ipv6.nxt=17/6`、offset 62/74 |
| 11 | `swarm_ipv4_ipv6_same_payload` | 正 | 两地址族相同逻辑 payload | outer family、重组 bytes 一致 |
| 12 | `swarm_binary_chunk` | 正 | binary/base64 chunk payload | 解码后 bytes 和 chunk size |
| 13 | `swarm_fragment_reassembly` | 正 | fragment index/count/重组 | fragment 字段、总长度 |
| 14 | `swarm_frame_boundary` | 正 | discovery/storage 长度和字段边界 | Length=26、零长 TLV、端点边界 |
| 15 | `swarm_neg_frame_encoding` | 负 | Magic/Version/Kind/Flags/Length/End 错误 | `frame`/`length`/`version` |
| 16 | `swarm_neg_handshake_state` | 负 | discovery、HELLO/AUTH/session 顺序错误 | `handshake`/`auth`/`session` |
| 17 | `swarm_neg_chunk_integrity` | 负 | 地址、长度、offset、fragment 完整性错误 | `chunk`/`address`/`fragment` |
| 18 | `swarm_neg_session_reference` | 负 | 未打开、已关闭或跨连接 session/stream | `session`/`stream`/`connection` |
| 19 | `swarm_neg_ack_correlation` | 负 | ACK 未知 message/chunk 或跨 stream | `ack`/`message`/`correlation` |
| 20 | `swarm_neg_transport_profile` | 负 | UDP/TCP carrier、端口、profile 不匹配 | `transport`/`profile`/`port` |
| 21 | `swarm_neg_unregistered` | 占位 | 当前层注册前置 | `unknown layer`，不计语义覆盖 |

## 3. 线上编码和偏移断言

Discovery datagram 编码为：

```text
Magic(4)=SWD1 | Length(2) | Version(1) | Kind(1) | Nonce(8) |
NodeID(32) | EndpointCount(1) | Endpoint* | FrameEnd(2)=ae 5a
```

Length 是从 Version 到 FrameEnd 的总字节数，不包含 Magic 和 Length 自身。`swarm_discovery_ipv4` 在 IPv4 UDP offset 42 断言 `53 57 44 31`、Version=1、Kind=PING/PONG、Nonce 关联、NodeID 非零和 `ae 5a`；不能把 UDP payload 当 TCP storage frame。

Storage TCP frame 编码为：

```text
Magic(4)=SWS1 | Length(4) | Version(1) | Kind(1) | Flags(2) |
SessionID(8) | StreamID(4) | CorrelationID(8) | Payload(N) | FrameEnd(2)=ae 5a
```

Length 为 `26 + N`，不包含 Magic 和 Length 自身，最小 storage frame 为 26。`swarm_handshake_tcp_ipv4` 在 TCP/IPv4 offset 54 断言 `53 57 53 31`、Version/Kind/Flags 和 FrameEnd；`swarm_ipv6` 分别在 UDP offset 62 或 TCP offset 74 断言相同应用 bytes，并验证 `ipv6.nxt=17` 或 `6`。

STORE 必须按 chunk_address、chunk_size、chunk_payload 验证；CHUNK 的 CorrelationID、chunk_address 和总 payload 必须与 RETRIEVE 对应。带 ack-required 的消息必须收到同一 session/stream 的 MESSAGE_ACK，`ack_for` 等于 message_id 或 CorrelationID。Frame 与 TCP segment 的边界不等价，MSS 测试必须先重组再按 Length 解析。

## 4. 正例逐项断言契约

1. **`swarm_discovery_ipv4`**：UDP/IPv4/1634 显式 PING→PONG；断言 SWD1、offset 42、Nonce same-as、NodeID nonzero 和 endpoint 数量，不把 PONG 自动升级为 TCP session。
2. **`swarm_handshake_tcp_ipv4`**：TCP/IPv4/1634 显式 HELLO→HELLO_OK→AUTH→AUTH_OK；断言 SWS1、方向、profile、capability 和 max_frame/session_limit，不能跳过认证。
3. **`swarm_session_open_close`**：认证后 OPEN_SESSION→OPEN_OK→CLOSE→CLOSE_OK；断言非零 SessionID、状态顺序和终止，关闭后无业务 frame。
4. **`swarm_chunk_store`**：SessionOpen 后 STORE 一个明确 32 字节 chunk_address 和 binary chunk；断言 chunk_size 等于 payload bytes，STORE_OK 使用相同 CorrelationID 和地址，不声称节点持久化结果。
5. **`swarm_chunk_retrieve`**：显式 RETRIEVE→CHUNK；断言 chunk_address、CorrelationID、chunk_size 和重组内容关联，不自动生成未请求 chunk。
6. **`swarm_chunk_delivery_ack`**：STORE 或 CHUNK 设置 ack-required，返回 MESSAGE_ACK；断言 message_id/ack_for、sequence、ack_status 和同 session/stream。
7. **`swarm_manifest_exchange`**：显式 MANIFEST 携带 manifest_root、entry 和 chunk_address 引用；断言 root/entry 字段和地址关联，不推导自动复制。
8. **`swarm_stream_multiplex`**：同一连接交织两个 StreamID 的 STORE/RETRIEVE；断言 stream distinct、CorrelationID 和 chunk 状态独立，不能按全局 packet index 排序。
9. **`swarm_multi_session`**：同一 TCP 连接建立两个 SessionID，分别执行 STORE 和 RETRIEVE/ACK；断言 SessionID、stream、sequence 和关闭状态隔离。
10. **`swarm_ipv6`**：IPv6/UDP discovery 与 IPv6/TCP storage 使用显式 fixture；断言 `ipv6.nxt=17/6`、offset 62/74，应用 bytes 不因地址族改变。
11. **`swarm_ipv4_ipv6_same_payload`**：两个独立地址族 fixture 使用相同 discovery 或 storage logical bytes；分别断言 `ip.version`/`ipv6.nxt` 和重组 payload，一条 layer-chain 不混入两种地址族。
12. **`swarm_binary_chunk`**：chunk 使用 `payload_b64` 生成确定性 binary bytes；断言线上是解码 bytes、chunk_size 正确，不发送 base64 文本。
13. **`swarm_fragment_reassembly`**：一个 chunk 分为多个 CHUNK fragment，断言 index 0..count-1、不重复、共享地址/CorrelationID，重组长度等于 chunk_size；fragment index 不由 TCP packet index 替代。
14. **`swarm_frame_boundary`**：覆盖 SWD1/SWS1 最小 frame、Length 边界、空 TLV、endpoint 地址族、chunk_size=0、fragment_count=1、最大字段和显式 CLOSE；断言无回绕、无超量分配。

合法 discovery 丢包、节点业务 ERROR、显式重传、空 chunk 和多流交织属于正例行为；只有配置、线格式、完整性或状态引用错误进入负例。

## 5. 负例契约

负例必须在 planner/validator 处失败并传播为 task error，不得产生成功 PCAP、completed/0 packet 或只剩 TCP ACK/UDP 空包。每个负例执行期 `expect` 只允许 `expect_error` 与 `error_contains`。

| ID | 故障输入 | 目标 `error_contains` |
|---|---|---|
| `swarm_neg_frame_encoding` | Magic/Version/Kind/Flags 错误、Length 越界、FrameEnd 非 `ae 5a` 或 carrier 错配 | `frame`、`length` 或 `version` |
| `swarm_neg_handshake_state` | discovery response 无 request、HELLO/AUTH/OPEN_SESSION 方向或顺序错误 | `handshake`、`auth` 或 `session` |
| `swarm_neg_chunk_integrity` | chunk_address 长度错误、chunk_size 与 payload 不符、offset/fragment 越界 | `chunk`、`address`、`length` 或 `fragment` |
| `swarm_neg_session_reference` | 未打开/已关闭 SessionID、跨 connection/stream 引用 | `session`、`stream` 或 `connection` |
| `swarm_neg_ack_correlation` | ACK 未知 message/chunk、跨 stream、重复或 sequence 回退 | `ack`、`message`、`correlation` 或 `sequence` |
| `swarm_neg_transport_profile` | UDP/TCP carrier、端口、profile 或地址族与配置不一致 | `transport`、`profile`、`port` 或 `address` |
| `swarm_neg_unregistered` | `proto=swarm` 且 layers 含未注册 `swarm` | **`unknown layer`** |

## 6. 机器契约与静态检查

1. 运行 `python3 -m json.tool trafficgen/test/protocol_pcap/cases/swarm.json`，确认当前 JSON 恰有一个 `swarm_neg_unregistered` 条目，`proto=swarm`，`expect_error=true`，`error_contains` 精确为 `unknown layer`。
2. 当前机器 ID 集合仅包含占位；占位不计入 20 个语义 ID。注册后 JSON 必须按本文 §2 顺序补入 14 个正例和 6 个负例。
3. 正例实现后每条应有 `packet_count`/`min_packets`、已注册 TCP/UDP/IP/IPv6 字段和稳定 `frames`；不得伪造未注册的 `swarm.*` tshark 字段。Discovery/storage bytes 使用重组后的 offset 42/54/62/74。
4. 多会话/多流使用 tcp.stream、方向、端口 distinct、SessionID/StreamID/CorrelationID/chunk_address 关联，不假设跨流调度顺序。
5. 负例 `expect` 只能包含 `expect_error`、`error_contains`；占位的 unknown layer 不得冒充协议语义负例已执行。

## 7. 三方一致性表

设计 §10、本文 §2 和未来 JSON 必须保持同一 20 个语义 ID、同一顺序；当前 JSON 另有一个不计入语义覆盖的注册前置占位。

```text
swarm_discovery_ipv4
swarm_handshake_tcp_ipv4
swarm_session_open_close
swarm_chunk_store
swarm_chunk_retrieve
swarm_chunk_delivery_ack
swarm_manifest_exchange
swarm_stream_multiplex
swarm_multi_session
swarm_ipv6
swarm_ipv4_ipv6_same_payload
swarm_binary_chunk
swarm_fragment_reassembly
swarm_frame_boundary
swarm_neg_frame_encoding
swarm_neg_handshake_state
swarm_neg_chunk_integrity
swarm_neg_session_reference
swarm_neg_ack_correlation
swarm_neg_transport_profile
```

## 8. 修订记录

- v1.0.0（2026-08-20）：建立 14 个 Swarm discovery/storage 正例、6 个严格负例和 1 个未注册占位，覆盖双承载 frame、握手/会话、chunk/manifest、确认、分片、IPv4/IPv6、多会话、多流、MSS 重组、边界和错误传播；当前仅提交设计与用例契约，不修改 Go 实现。
