# Gnutella（分布式点对点文件检索协议，Gnutella Wire Profile）测试用例契约

> 版本：v1.0.0（设计阶段）
> 日期：2026-08-20
> 配套设计：`docs/protocol-designs/53-gnutella-design.md`
> 机器契约：`trafficgen/test/protocol_pcap/cases/gnutella.json`
> 状态：✅ 已实现并全绿（2026-08-31，20/20 驱动用例）。`gnutella` 层/planner 已注册（ams/openwire 同款事件模式 + 显式地址自驱分支）；正例 14 项按 PCAP（抓包文件）断言运行（tshark 3.6.14 对规范正确的 QUERY_HIT 有已知解析缺陷，5 个含 QUERY_HIT 的用例按 openwire 先例走 `pcaptest.IsMalformedWhitelisted` 白名单，帧字节断言不受影响），负例 6 项保持严格错误断言。占位条目已由语义用例替换。

## 1. 测试原则和未注册边界

用例从设计 §2–§9 逐项派生，共 21 个唯一标识：14 个目标正例、6 个目标负例，以及 1 个注册前置占位。当前 JSON 只保留 `gnutella_neg_unregistered`，其 `expect` 必须为 `expect_error=true`、`error_contains="unknown layer"`；占位不计入 20 个 Gnutella 语义 ID，不能用拒绝、0 包或空 PCAP 冒充协议行为通过。注册后移除占位，再按本文索引顺序加入 14 个正例和 6 个负例。

Gnutella 使用 TCP/6346。无 VLAN（虚拟局域网）、IP options（IP 选项）和 TCP options 时，IPv4 TCP payload（载荷）起点为 offset（偏移）54，IPv6 为 74。握手按 CRLF 重组，业务 message 按 23 字节 header 和 PayloadLength 重组；TCP segment（分段）边界不等于消息边界。正例实现后每条至少需要 `packet_count` 或 `min_packets`、可观察 `fields` 和稳定 `frames`；负例执行期 `expect` 严格只有 `expect_error`、`error_contains`。

二进制 message 头稳定前缀为 `MessageID(16)|Descriptor(1)|TTL(1)|Hops(1)|PayloadLength(4)`，总头长 23 字节；`PING=0x00`、`PONG=0x01`、`PUSH=0x40`、`QUERY=0x80`、`QUERY_HIT=0x81`、`VENDOR=0x31`；动态 GUID、ServentID、QueryID 不写死，优先使用 `nonzero`、`same_as_packet`、`distinct_values` 或 raw frame（原始帧）稳定前缀。未解密 TLS 只观察 TLS/TCP 外层，不能声称看见 Gnutella 字段。

## 2. 原子用例索引

| # | ID | 类型 | 覆盖 | 实现后证据 |
|---:|---|---|---|---|
| 1 | `gnutella_handshake_ipv4` | 正 | TCP/IPv4 CONNECT/200、能力头 | TCP/6346、CRLF、200 状态 |
| 2 | `gnutella_ping_pong` | 正 | PING/PONG、MessageID 和 NodeID | Descriptor、GUID 关联 |
| 3 | `gnutella_query_queryhit` | 正 | QUERY/QUERY_HIT、命中关联 | QueryID、Hits、result |
| 4 | `gnutella_push` | 正 | PUSH、ServentID/FileIndex/地址 | QueryHit 与 Push 关联 |
| 5 | `gnutella_vendor_message` | 正 | Vendor 扩展及长度 | VendorID/selector/payload |
| 6 | `gnutella_forward_ttl_hops` | 正 | MessageID 复用、TTL/Hops 转发 | TTL-1、Hops+1、GUID 不变 |
| 7 | `gnutella_multi_queryhit` | 正 | 多命中结果和 QueryID | Hits 与 result 数一致 |
| 8 | `gnutella_multi_stream` | 正 | 多 TCP stream 状态隔离 | tcp.stream、GUID、Query distinct |
| 9 | `gnutella_multi_connection` | 正 | 多连接节点状态隔离 | 四元组/源端口 distinct |
| 10 | `gnutella_ipv6` | 正 | IPv6/TCP、Next Header=6 | `ipv6.nxt=6`、offset 74 |
| 11 | `gnutella_ipv4_ipv6_same_payload` | 正 | 独立双栈逻辑消息一致 | outer family、重组 bytes |
| 12 | `gnutella_binary_vendor_payload` | 正 | binary/base64 Vendor payload | 解码 bytes、长度 |
| 13 | `gnutella_mss_message_reassembly` | 正 | message 跨 TCP segments 重组 | PayloadLength 与重组 body |
| 14 | `gnutella_frame_boundary` | 正 | header、TTL、长度和 payload 边界 | 零长、最大值、无回绕 |
| 15 | `gnutella_neg_handshake` | 负 | 首行、CRLF、能力和状态错误 | `handshake`/`header` |
| 16 | `gnutella_neg_message_header` | 负 | header 截断、Descriptor/length 错误 | `message`/`length`/`descriptor` |
| 17 | `gnutella_neg_ttl_hops` | 负 | TTL/Hops 回绕或非法转发 | `ttl`/`hops` |
| 18 | `gnutella_neg_query_correlation` | 负 | QueryHit/Push 跨 Query 或节点关联 | `query`/`servent`/`correlation` |
| 19 | `gnutella_neg_payload_encoding` | 负 | PONG/QueryHit/Push 地址和 payload 长度错误 | `payload`/`address`/`length` |
| 20 | `gnutella_neg_transport_profile` | 负 | 非 TCP、端口或 profile 不匹配 | `transport`/`port`/`profile` |
| 21 | `gnutella_neg_unregistered` | 占位 | 当前层注册前置 | `unknown layer`，不计语义覆盖 |

## 3. 线上编码和偏移断言

握手使用 ASCII request/response 行，所有 Header 行以 `\r\n` 结尾，空行结束。正例 `gnutella_handshake_ipv4` 在 IPv4 TCP offset 54 之前先断言应用流中出现 `GNUTELLA CONNECT/0.6` 和 `GNUTELLA/0.6 200 OK`，不能把 SYN/ACK 当握手成功。

业务 message 的 23 字节头为：

```text
MessageID(16) | Descriptor(1) | TTL(1) | Hops(1) | PayloadLength(4) | Payload(N)
```

`PayloadLength` 为小端 uint32，仅计算 payload；消息总长为 `23 + PayloadLength`。`PING=0x00`、`PONG=0x01`、`PUSH=0x40`、`QUERY=0x80`、`QUERY_HIT=0x81`、`VENDOR=0x31`；实现后 frames 必须按重组 payload offset 54/74 断言稳定前缀，不能伪造未注册 `gnutella.*` tshark 字段。

## 4. 正例逐项断言契约

1. **`gnutella_handshake_ipv4`**：TCP/IPv4/6346 显式 CONNECT→200 OK；断言首行、CRLF、User-Agent/能力头和方向，200 响应后才允许业务 message。
2. **`gnutella_ping_pong`**：握手后 PING→PONG；断言两帧 GUID 相同、TTL/Hops 存在、PONG 地址/文件计数字段长度正确，不自动生成额外 PING。
3. **`gnutella_query_queryhit`**：QUERY 携带非空 criteria，节点返回 QUERY_HIT；断言 Query GUID、Hits 和 result 数一致，不声称文件真实存在。
4. **`gnutella_push`**：QueryHit 后显式 PUSH；断言 ServentID、FileIndex、目标地址和端口关联，不自动建立下载 HTTP 流。
5. **`gnutella_vendor_message`**：发送 VendorID/selector/version 和 payload；断言长度覆盖扩展内容，未知扩展作为显式业务事件而非 planner error。
6. **`gnutella_forward_ttl_hops`**：同一 GUID 经显式转发；断言下一跳 TTL 减一、Hops 加一、Payload 不变，不能把转发副本当新 Query。
7. **`gnutella_multi_queryhit`**：同一 Query 返回多个 QueryHit；断言 Query GUID 相同、ServentID 或 result 可区分，Hits 等于结果项数。
8. **`gnutella_multi_stream`**：两个 TCP stream 各自完成握手并执行不同 Query；断言 tcp.stream、GUID、QueryHit 关联隔离，不假设跨 stream 顺序。
9. **`gnutella_multi_connection`**：两个独立四元组连接分别握手并发送 Ping/Query；断言源端口和 stream distinct，节点能力和 Query 状态不串用。
10. **`gnutella_ipv6`**：IPv6/TCP/6346 完成握手和一个 Ping；断言 `ipv6.nxt=6`、offset 74，业务 bytes 按 IPv6 profile 编码。
11. **`gnutella_ipv4_ipv6_same_payload`**：两个独立 fixture 使用相同 Query logical bytes；分别断言 `ip.version`/`ipv6.nxt`、GUID、Descriptor、TTL/Hops 和重组 payload，不在同一 layer-chain 混入两种地址族。
12. **`gnutella_binary_vendor_payload`**：Vendor payload 由 `payload_b64` 解码得到确定性二进制；断言线上不是 Base64 文本且 PayloadLength 等于解码后长度。
13. **`gnutella_mss_message_reassembly`**：设置小 MSS 使 QueryHit 或 Vendor 跨多个 TCP segments；先重组 stream，再断言 23 字节头、PayloadLength 和完整 payload。
14. **`gnutella_frame_boundary`**：覆盖 PayloadLength=0、TTL=0/1/255、Hops=0/255、最小 Ping、空 criteria、最大明确支持的 QueryHit 和 FileIndex 边界；断言无回绕、无超量分配，最后显式关闭。

合法 503 拒绝、无结果 QueryHit、重复 GUID 去重、Vendor 扩展和显式 RST 属于正例行为；只有配置、线格式、长度或关联错误进入负例。

## 5. 负例契约

负例必须在 planner/validator 处失败并传播为 task error，不得产生成功 PCAP、completed/0 packet 或只剩 TCP ACK 的假成功。每个负例执行期 `expect` 只允许 `expect_error`、`error_contains`。

| ID | 故障输入 | 目标 `error_contains` |
|---|---|---|
| `gnutella_neg_handshake` | 首行错误、CRLF 截断、200 前发业务或冲突能力头 | `handshake`、`header` 或 `state` |
| `gnutella_neg_message_header` | 23 字节头截断、未知 Descriptor、长度越界或整数溢出 | `message`、`descriptor` 或 `length` |
| `gnutella_neg_ttl_hops` | TTL/Hops 回绕、TTL=0 仍转发或 Hops 超界 | `ttl` 或 `hops` |
| `gnutella_neg_query_correlation` | QueryHit/Push 引用未知或跨流 Query/ServentID | `query`、`servent` 或 `correlation` |
| `gnutella_neg_payload_encoding` | 地址族字段长度、Hits/result、FileIndex 或 payload 长度不符 | `payload`、`address` 或 `length` |
| `gnutella_neg_transport_profile` | 非 TCP、错误端口、未知 profile 或 TLS 明文误解析 | `transport`、`port` 或 `profile` |
| `gnutella_neg_unregistered` | `proto=gnutella` 且 layers 含未注册 `gnutella` | **`unknown layer`** |

## 6. 机器契约与静态检查

1. 运行 `python3 -m json.tool trafficgen/test/protocol_pcap/cases/gnutella.json`，确认当前 JSON 恰有一个 `gnutella_neg_unregistered` 条目，`proto=gnutella`，`expect_error=true`，`error_contains` 精确为 `unknown layer`。
2. 当前机器 ID 集合仅包含占位；占位不计入 20 个语义 ID。注册后 JSON 必须按本文 §2 顺序补入 14 个正例和 6 个负例。
3. 正例实现后每条应有 `packet_count`/`min_packets`、已注册 TCP/IP/IPv6 字段和稳定 frames；不得伪造未注册 `gnutella.*` tshark 字段。握手与消息 bytes 使用重组后的 offset 54/74。
4. 多流/多连接使用 tcp.stream、方向、端口 distinct、MessageID/QueryID/ServentID 关联，不假设跨流 packet index。
5. 负例 `expect` 只能包含 `expect_error`、`error_contains`；占位的 unknown layer 不得冒充协议语义负例已执行。

## 7. 三方一致性表

设计 §9、本文 §2 和未来 JSON 必须保持同一 20 个语义 ID、同一顺序；当前 JSON 另有一个不计入语义覆盖的注册前置占位。

```text
gnutella_handshake_ipv4
gnutella_ping_pong
gnutella_query_queryhit
gnutella_push
gnutella_vendor_message
gnutella_forward_ttl_hops
gnutella_multi_queryhit
gnutella_multi_stream
gnutella_multi_connection
gnutella_ipv6
gnutella_ipv4_ipv6_same_payload
gnutella_binary_vendor_payload
gnutella_mss_message_reassembly
gnutella_frame_boundary
gnutella_neg_handshake
gnutella_neg_message_header
gnutella_neg_ttl_hops
gnutella_neg_query_correlation
gnutella_neg_payload_encoding
gnutella_neg_transport_profile
```

## 8. 修订记录

- v1.0.0（2026-08-20）：建立 14 个 Gnutella 正例、6 个严格负例和 1 个未注册占位，覆盖握手、Ping/Pong、Query/QueryHit、Push、Vendor、TTL/hops、IPv4/IPv6、多流、多连接、MSS 重组、边界和错误传播；不修改 Go 实现。
