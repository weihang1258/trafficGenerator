# AMQP（高级消息队列协议，Advanced Message Queuing Protocol）测试用例契约

> 版本：v1.0.0（设计阶段）
> 日期：2026-08-20
> 配套设计：`docs/protocol-designs/49-amqp-design.md`
> 机器契约：`trafficgen/test/protocol_pcap/cases/amqp.json`
> 状态：`amqp` 层尚未注册；本文定义实现后的 PCAP（抓包文件）断言，不宣称当前 suite（测试套件）可运行。

## 1. 测试原则和未注册边界

用例从设计 §2–§10 逐项派生，共 21 个唯一标识：14 个目标正例、6 个目标负例，以及 1 个注册前置占位。当前 JSON 只保留 `amqp_neg_unregistered`，其 `expect` 必须为 `expect_error=true`、`error_contains="unknown layer"`；占位不计入 20 个 AMQP 语义 ID，不能用拒绝、0 包或空 PCAP 冒充 AMQP 帧行为通过。注册后移除占位，再按本文索引顺序加入 14 个正例和 6 个负例。

AMQP 是 TCP 应用层协议。无 VLAN（虚拟局域网）、IP options（IP 选项）和 TCP options 时，IPv4 TCP payload（载荷）起点为 offset（偏移）54，IPv6 为 74。TCP MSS（最大报文段长度）分段后必须先按 frame-size（帧长度）重组 AMQP frame（帧）；正例实现后每条至少有 `packet_count` 或 `min_packets`、可观测 `fields`（字段）和稳定 `frames`（帧字节）。负例 `expect` 严格只有 `expect_error` 与 `error_contains`。

协议头、frame header 和 AMQP frame end 的稳定字节可用 `frames` 断言；动态 TCP sequence、协商值、consumer tag、delivery tag 和调度顺序不写死，除非 fixture（固定样本）显式固定。未解密 TLS 只观察 TLS/TCP 外层，不能声称看见 AMQP 方法或正文。

## 2. 原子用例索引

| # | ID | 类型 | 覆盖 | 实现后证据 |
|---:|---|---|---|---|
| 1 | `amqp_protocol_header_ipv4` | 正 | AMQP 0-9-1 8-byte protocol header、TCP/IPv4 | TCP 5672、offset 54 `AMQP\\0\\0\\9\\1` |
| 2 | `amqp_connection_handshake` | 正 | start/start-ok/tune/tune-ok/open/open-ok | method class/id、方向和顺序 |
| 3 | `amqp_channel_open_close` | 正 | channel 1 open/open-ok/close/close-ok | channel、method type、终止 |
| 4 | `amqp_heartbeat` | 正 | type 8、channel 0、size 0、CE | `08 00 00 00 00 00 00 ce` |
| 5 | `amqp_exchange_queue_declare` | 正 | exchange/queue 参数 | class/method、shortstr、响应 |
| 6 | `amqp_basic_publish` | 正 | publish→HEADER→BODY、BodySize | content class、body size、属性 |
| 7 | `amqp_basic_body_segmentation` | 正 | 多 BODY frame、frame_max 和重组 | body 总长与 frame size |
| 8 | `amqp_basic_consume_deliver_ack` | 正 | consumer/deliver/header/body/ack | delivery/consumer/channel 关联 |
| 9 | `amqp_basic_get_empty` | 正 | basic.get 与显式 get-empty | get method 类型和空响应 |
| 10 | `amqp_confirm_transaction` | 正 | confirm.select 或 tx select/commit/rollback | 显式扩展方法顺序 |
| 11 | `amqp_keepalive_multi_channel` | 正 | 单连接多 channel、heartbeat | channel distinct、heartbeat |
| 12 | `amqp_multi_connection` | 正 | 两个 TCP 连接、状态隔离 | tcp.stream/端口 distinct |
| 13 | `amqp_ipv6` | 正 | IPv6/TCP、应用 bytes 不变 | `ipv6.nxt=6`、offset 74 |
| 14 | `amqp_frame_boundary` | 正 | frame_max、空 body、shortstr/size 边界 | frame size、CE、边界值 |
| 15 | `amqp_neg_protocol_header` | 负 | 缺失或错误 protocol header | `protocol`/`version` |
| 16 | `amqp_neg_frame_encoding` | 负 | 未知 type、非 CE、size 越界 | `frame`/`size` |
| 17 | `amqp_neg_handshake_state` | 负 | method 顺序、方向或 tune/open 状态错误 | `handshake`/`tune` |
| 18 | `amqp_neg_channel_state` | 负 | 未打开 channel、channel 0/limit 误用 | `channel`/`session` |
| 19 | `amqp_neg_content_length` | 负 | Header BodySize 与 BODY/size 不一致 | `body`/`length` |
| 20 | `amqp_neg_session_reference` | 负 | delivery/consumer/channel 跨连接引用 | `delivery`/`consumer`/`session` |
| 21 | `amqp_neg_unregistered` | 占位 | 当前层注册前置 | `unknown layer`，不计语义覆盖 |

## 3. 线上编码和偏移断言

AMQP protocol header（协议头）必须是 TCP stream 首个 8 字节：`41 4d 51 50 00 00 09 01`。每个 frame 为 `FrameType(1)|Channel(2)|Size(4)|Payload(Size)|FrameEnd(1)`，整数使用大端序，end marker 固定 `ce`。METHOD payload 开头为 class-id/method-id 各 2 字节；HEARTBEAT 固定 type=8、channel=0、size=0、end=`ce`。

`amqp_protocol_header_ipv4` 在 IPv4 payload offset 54 固定 `41 4d 51 50 00 00 09 01`，并断言 TCP destination port 5672。`amqp_ipv6` 在 offset 74 固定相同 protocol header，断言 `ipv6.nxt=6`；不因外层地址族改变 frame bytes。

`amqp_heartbeat` 固定 frame offset 的 8 字节 `08 00 00 00 00 00 00 ce`。`amqp_basic_publish` 和 `amqp_basic_consume_deliver_ack` 必须按 METHOD→HEADER→BODY 顺序验证；HEADER class-id=60、BodySize 为所有 BODY payload 长度之和，BODY channel 与 METHOD/HEADER 相同。多 BODY frame 必须满足 negotiated `frame_max` 的完整线上长度约束（`7 + Size + 1`），重组后 body bytes 和 BodySize 相等。

AMQP shortstr 是 `uint8 length + bytes`，长度 255 合法，256 必须拒绝；longstr 使用 UI32 长度。Frame size 只计 payload，不含 8-byte frame header/end；FrameEnd 非 `ce`、size 越过 stream 或未知 type 必须失败。channel 0 仅用于 connection methods/heartbeat；业务方法必须使用已打开的非零 channel。

## 4. 正例逐项断言契约

1. **`amqp_protocol_header_ipv4`**：TCP/IPv4/5672 完整握手后客户端发送 AMQP 0-9-1 protocol header；断言 TCP destination port、payload presence 和 offset 54 稳定 8 字节。不能将 TCP SYN payload 当 protocol header。
2. **`amqp_connection_handshake`**：显式 start→start-ok→tune→tune-ok→open→open-ok；断言每个 METHOD 的 class 10、method ID、方向和协商 frame_max/channel_max/heartbeat。planner 不自动插入遗漏响应。
3. **`amqp_channel_open_close`**：握手后 channel 1 open/open-ok，再 channel.close/close-ok，最后 connection.close/close-ok 或显式终止；断言 channel 与 method 顺序、handshake 和 termination。
4. **`amqp_heartbeat`**：连接 open 后发送一个或多个 heartbeat，断言 type 8、channel 0、size 0、end CE；不能用 TCP keepalive 替代 AMQP heartbeat。
5. **`amqp_exchange_queue_declare`**：channel 1 显式 exchange.declare 与 queue.declare，再分别接对应 ok；断言 direct/fanout/topic type、name/flags 的 shortstr 和方向，不断言 broker 自动路由结果。
6. **`amqp_basic_publish`**：basic.publish 后同 channel 的 class 60 content header、BodySize 和一个 BODY；断言 method→header→body 顺序、BodySize 等于 body bytes、FrameEnd CE。
7. **`amqp_basic_body_segmentation`**：设置小于 body 的 frame_max，生成多个 BODY frame；断言每 frame 的完整线上长度 `7 + Size + 1` 不越 negotiated frame_max，重组 body 长度恰等于 Header BodySize，不能按单个 TCP packet 断言。
8. **`amqp_basic_consume_deliver_ack`**：basic.consume/open-ok 后 server basic.deliver→HEADER→BODY，client basic.ack；断言同 channel、delivery tag 关联和 consumer tag 非空，不固定运行期随机 tag。
9. **`amqp_basic_get_empty`**：basic.get 后显式 basic.get-empty response，断言 class 60/method 72（get-empty）和空队列语义；不自动生成 HEADER/BODY。
10. **`amqp_confirm_transaction`**：显式 confirm.select/confirm.select-ok 或 tx.select→tx.commit/rollback，profile 未开启时不得静默接受；断言方法顺序和 channel。
11. **`amqp_keepalive_multi_channel`**：同连接先打开 channel 1/2，分别发送业务方法和 heartbeat；断言业务 channel 非零、heartbeat channel 0、一个 channel 的 close 不重置另一个 channel。
12. **`amqp_multi_connection`**：两个独立 TCP 四元组分别完成 protocol header/handshake，且各自 publish 或 consume；断言 tcp.stream 或源端口 distinct，delivery/consumer/channel 状态不串用。
13. **`amqp_ipv6`**：IPv6/TCP/5672 使用与 IPv4 相同的 protocol header 和显式握手最小帧；断言 `ipv6.nxt=6`、offset 74 和应用 bytes 不变。
14. **`amqp_frame_boundary`**：覆盖 heartbeat/size=0、BodySize=0 仍有 HEADER、shortstr=255、frame_max 上界和可分配 payload；不得默认分配 uint32 最大长度，需断言 size/end marker 和长度回填。

## 5. 负例契约

负例必须在 planner/validator 处失败并传播为 task error，不得输出成功 PCAP、completed/0 packet 或仅有 ACK。每个负例的执行期 `expect` 只允许 `expect_error` 与 `error_contains`。

| ID | 故障输入 | 目标 `error_contains` |
|---|---|---|
| `amqp_neg_protocol_header` | 缺 AMQP header、版本非 `0.9.1` 或首个 bytes 错误 | `protocol` 或 `version` |
| `amqp_neg_frame_encoding` | 未知 frame type、FrameEnd 非 `0xCE`、size 越过 stream | `frame` 或 `size` |
| `amqp_neg_handshake_state` | start/start-ok/tune/open 顺序或方向错误 | `handshake` 或 `tune` |
| `amqp_neg_channel_state` | 未打开 channel、业务方法使用 channel 0、超过 channel_max | `channel` 或 `session` |
| `amqp_neg_content_length` | Header BodySize 与 BODY 总长、frame size 或 channel 不一致 | `body` 或 `length` |
| `amqp_neg_session_reference` | delivery/consumer/channel 引用另一连接或已关闭 session | `delivery`、`consumer` 或 `session` |
| `amqp_neg_unregistered` | `proto=amqp` 且 layers 含未注册 `amqp` | **`unknown layer`** |

## 6. 机器契约与静态检查

1. 运行 `python3 -m json.tool trafficgen/test/protocol_pcap/cases/amqp.json`，确认当前 JSON 恰有一个 `amqp_neg_unregistered` 条目，`proto=amqp`，`expect_error=true`，`error_contains` 精确为 `unknown layer`。
2. 当前机器 ID 集合仅包含占位；占位不计入 20 个语义 ID。注册后 JSON 必须按本文 §2 顺序补入 14 正例和 6 负例。
3. 正例实现后每条应有 `packet_count`/`min_packets`、已注册 TCP/IP/IPv6 字段和稳定 `frames`；不得伪造未注册的 `amqp.*` tshark 字段。AMQP frame bytes 使用重组后的 payload offset 54/74。
4. 多连接/多 channel 用 tcp.stream、方向、端口 distinct 和 channel/delivery/consumer 关联断言，不假设多流调度顺序。
5. 负例 `expect` 只能包含 `expect_error`、`error_contains`；占位的 unknown layer 不得冒充协议语义负例已执行。

## 7. 三方一致性表

设计 §10、本文 §2 和未来 JSON 必须保持同一 20 个语义 ID、同一顺序；当前 JSON 另有一个不计入语义覆盖的注册前置占位。

```text
amqp_protocol_header_ipv4
amqp_connection_handshake
amqp_channel_open_close
amqp_heartbeat
amqp_exchange_queue_declare
amqp_basic_publish
amqp_basic_body_segmentation
amqp_basic_consume_deliver_ack
amqp_basic_get_empty
amqp_confirm_transaction
amqp_keepalive_multi_channel
amqp_multi_connection
amqp_ipv6
amqp_frame_boundary
amqp_neg_protocol_header
amqp_neg_frame_encoding
amqp_neg_handshake_state
amqp_neg_channel_state
amqp_neg_content_length
amqp_neg_session_reference
```

## 8. 修订记录

- v1.0.0（2026-08-20）：建立 14 个 AMQP 0-9-1 正例、6 个严格负例和 1 个未注册占位，覆盖 protocol header、METHOD/HEADER/BODY/HEARTBEAT frame、握手/channel/content 状态、exchange/queue/basic、IPv4/IPv6、多连接、多 channel、MSS/长度边界和错误传播；不修改 Go 实现。
