# Swarm（去中心化 P2P 存储协议，Swarm Storage Profile）测试用例契约

> 版本：v1.1.0（层链迁移审计版）
> 日期：2026-09-30
> 配套设计：`docs/protocols/swarm/design.md`
> 机器契约：`trafficgen/test/protocol_pcap/cases/swarm.json`
> 状态：20 条用例已迁移为严格层链；本次不运行 suite/MCP，不宣称全量 pcap 绿。

## 1. 测试原则和实现边界

用例从设计 §2–§10 逐项派生，共 20 个唯一标识：14 个目标正例、6 个目标负例。`swarm` profile 同时定义 UDP discovery 和 TCP storage 两种承载。无 VLAN（虚拟局域网）、IP options（IP 选项）和 TCP options 时，IPv4 UDP payload（载荷）起点为 offset（偏移）42，IPv4 TCP 为 54，IPv6 UDP 为 62，IPv6 TCP 为 74。正例实现后每条至少有 `packet_count` 或 `min_packets`、可观测 `fields`（字段）和稳定 `frames`（帧字节）；负例 `expect` 严格只有 `expect_error` 与 `error_contains`。

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

## 6. 机器契约与静态检查

1. 运行 `python3 -m json.tool trafficgen/test/protocol_pcap/cases/swarm.json`，确认当前 JSON 恰有 20 条条目，ID 唯一，并按本文 §2 顺序排列 14 个正例与 6 个负例。
2. 非负例 `spec_json` 顶层仅有 `layers`；地址位于 `layers[].ip`，端口位于 `layers[].udp`/`layers[].tcp`，业务位于 `layers[].swarm`。
3. 正例实现后每条应有 `packet_count`/`min_packets`、已注册 TCP/UDP/IP/IPv6 字段和稳定 `frames`；不得伪造未注册的 `swarm.*` tshark 字段。Discovery/storage bytes 使用重组后的 offset 42/54/62/74。
4. 多会话/多流使用 tcp.stream、方向、端口 distinct、SessionID/StreamID/CorrelationID/chunk_address 关联，不假设跨流调度顺序。
5. 负例 `expect` 只能包含 `expect_error`、`error_contains`；6 条负例均为已注册 Swarm 语义错误路径。

## 7. 三方一致性表

设计 §10、本文 §2 和 JSON 必须保持同一 20 个语义 ID、同一顺序。

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

- v1.0.0（2026-08-20）：建立 14 个 Swarm discovery/storage 正例、6 个严格负例，覆盖双承载 frame、握手/会话、chunk/manifest、确认、分片、IPv4/IPv6、多会话、多流、边界和错误传播；明确为项目级 wire profile，不修改 Go 实现。
- v1.1.0（2026-09-30）：20 条用例完成严格层链迁移；删除未注册占位说明，新增 T1-T6 / C1-C6 与迁移缺口引用；本次不运行 suite/MCP，不宣称全量 pcap 绿。

## 10. T1-T6 对照与测试点清单

| ID | 规范行/设计条目 | 业务场景 | 代码分支/输出 | 用例与缺口 |
|---|---|---|---|---|
| T1 | §3 frame 布局、§5 状态机 | discovery、握手、会话和关闭 | `validateDiscovery`、`validateStorage`、逐事件生成 | S1–S14；商业行为需真实节点抓包确认 |
| T2 | §4 Kind/TLV、§6 chunk/fragment | STORE/RETRIEVE/MANIFEST/ACK | `layer_gen.go` 业务校验与 wire 编码 | S4–S7、S12–S13；最大值见 D-GAP-4 |
| T3 | §7 地址族、Session/Stream 隔离 | IPv4/IPv6、双 session、双 stream | ip/tcp/udp 字段和 frame 前缀 | S8–S11；MSS 重组待补 |
| T4 | §3.15 长连接三项 | 同连接多轮、异常结束、长保活 | events/session close、PING/PONG | S3、S8、S9 覆盖多轮/结束；长保活真实时间例为 G-GAP-2 |
| T5 | 历史 S1–S20 | 逐条迁移而非删减 | JSON 20 ID 同序 | 全部合入；无作废例 |
| T6 | §14.11 错误传播 | 6 种配置/状态/完整性错误 | planner error + 锚词 | N1–N6；负例 expect 严格双键，未运行 suite |

测试点清单来源为本 profile §3–§7 的规范条文与设计 §14–§15，逐项映射到 JSON；规范逻辑点总数按上述五类维度登记，20 个原子 ID 覆盖基础可执行面，D-GAP-4/5 与 G-GAP-2 为未闭环项，不将静态反查绿冒充规范全覆盖。

## 11. C1-C6 机器对账补表

| ID | 对账结论 | 证据 |
|---|---|---|
| C1 | 14 正例、6 负例；正负集合与 JSON 同序 | `swarm.json` 实际 20 ID |
| C2 | 正例覆盖 UDP/TCP、IPv4/IPv6、单/多 session/stream、binary/fragment/boundary | §2 与 S1–S14 |
| C3 | 业务行为逐例可拆分；复杂组合为 S8/S9/S11 | §4、S8/S9/S11 |
| C4 | 长度/TLV/fragment/zero/binary 边界均有基础例，上界为 D-GAP-4 | S12–S14 |
| C5 | 6 个负例均有稳定锚词 `version`/`hello`/`chunk`/`session`/`ack`/`port` | N1–N6 `expect` |
| C6 | 本次仅静态 json.tool 与 diff-check；未跑 suite/MCP/服务/NIC | 交付报告 |

### 11.1 三源回指与粒度

每条 S/N 的 `summary` 回指 §2 原子表；设计依据回指 §3–§7 和 §14 矩阵；现网行为仅列为待确认，确认方式为选定节点版本抓取对应 UDP/TCP pcap。正例断言帧前缀、offset、字段和包数，负例断言 validator 锚词；不能由当前 tshark 字段表达的 Session/Stream/Correlation 顺序保持 frame bytes 断言，不伪造 dissector 字段。

## 9. 层链迁移审计（T1-T6，2026-09-30）

| ID | 测试审计结论 | 证据 |
|---|---|---|
| T1 | 20 条 ID 唯一且 JSON 可解析 | `swarm.json` 机读校验 |
| T2 | 14 条正例使用 `[ip,(udp|tcp),swarm]` 严格层链 | 全量 `spec_json.layers` 审计 |
| T3 | 6 条负例保留故意错误输入与错误锚词 | `expect_error`/`error_contains` 审计 |
| T4 | 地址只在 ip 层、端口只在 udp/tcp 层；无顶层旧地址/端口/count/swarm | 全量顶层键审计 |
| T5 | 未使用 `strategy_fc`；无 flows>1 静态复制迁移问题 | 20 例均为单流 |
| T6 | 层链迁移不改变协议字段、断言或负例语义 | 对照旧三件套逐 ID 核对 |

## 10. 六项测试覆盖清单（C1-C6）

| ID | 覆盖要求 | 当前结论 |
|---|---|---|
| C1 | UDP/TCP 双载体 | 已有 `swarm_discovery_ipv4`、`swarm_handshake_tcp_ipv4` |
| C2 | IPv4/IPv6 | 已有 `swarm_ipv6`、`swarm_ipv4_ipv6_same_payload` |
| C3 | 握手/会话/多流/多会话/chunk/manifest/ACK/fragment | 已有 S2–S13；实现不足登记设计 D-GAP |
| C4 | 帧布局、TLV、长度、边界 | 已有 `swarm_frame_boundary`；最大 chunk、fragment 上界、MSS 分段、空 manifest entry 是已登记缺口，见 design D-GAP-4 |
| C5 | 错误处理 | 6 负例均有锚词；错误码响应与配置拒绝分列 |
| C6 | 全量实际流程校准 | 本次未运行 suite/MCP，故不宣称全量 pcap 绿；待设计 D-GAP 闭环后执行 |
```
