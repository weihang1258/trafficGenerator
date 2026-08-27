# AMQP（高级消息队列协议，Advanced Message Queuing Protocol）设计契约

> 版本：v1.0.0（设计阶段）
> 日期：2026-08-20
> 状态：仅设计与 PCAP（抓包文件）用例契约；`amqp` 层尚未注册，不修改 Go（编程语言）实现，不宣称当前 suite（测试套件）可运行。
> 配套文件：`docs/protocol-designs/49-amqp-testcase.md`、`trafficgen/test/protocol_pcap/cases/amqp.json`
> 规范基线：AMQP 0-9-1 wire-level specification（线上规范）、RabbitMQ AMQP 0-9-1 extensions（扩展）和 TCP（传输控制协议）。

## 1. 范围、profile 和未注册边界

本版定义 AMQP 0-9-1 over TCP 的确定性帧序列，默认 TCP destination port（目的端口）为 5672。覆盖 protocol header（协议头）、connection/channel lifecycle（连接/信道生命周期）、method frame（方法帧）、content header（内容头）、body frame（正文帧）、basic publish/consume/deliver/ack、queue/exchange 声明，以及 IPv4/IPv6、多连接和错误边界。

| profile（协议档案） | 规范范围 | 本版允许内容 | 不从 profile 推导 |
|---|---|---|---|
| `amqp091_rabbitmq` | AMQP 0-9-1 基础 | connection/channel、exchange/queue、basic publish/consume/deliver/ack、confirm、tx 的显式方法 | 自动 broker（消息代理）路由、持久化、消费者业务处理 |
| `amqp091_minimal` | AMQP 0-9-1 core | protocol header、start/tune/open、channel open/close、connection close | RabbitMQ 私有 extension method、AMQP 1.0、STOMP |
| `amqp091_tls_boundary` | TLS 外层边界 | 仅未来 TLS/TCP 载体定义 | 未解密时不声称看见 AMQP method/header/body |

当前仓库没有注册 `amqp` layer（层）、planner（规划器）、validator（校验器）或生成器。`cases/amqp.json` 只保留一个 `amqp_neg_unregistered` 的 `expect_error=true`、`error_contains="unknown layer"` 占位；该占位不计入下文 20 个语义 ID，不得把拒绝、0 包或空 PCAP 报告为 AMQP 行为通过。

## 2. 协议栈、载体和固定偏移

推荐层链为 `[ip, tcp, amqp]`。AMQP 明文只使用 TCP；UDP、裸 IP、HTTP、WebSocket 和 AMQP 1.0 不得静默当作本版载体。默认目的端口 5672，源端口由 fixture（固定样本）显式给出。

无 VLAN（虚拟局域网）、无 IP options（IP 选项）和无 TCP options 时：

| 载体 | TCP payload（载荷）起点 | 用途 |
|---|---:|---|
| TCP/IPv4 | 54 = Ethernet 14 + IPv4 20 + TCP 20 | protocol header、AMQP frame |
| TCP/IPv6 | 74 = 14 + IPv6 40 + TCP 20 | 同一 AMQP 字节语义 |

TCP segment（分段）边界不是 AMQP frame 边界。实现必须按 `frame-size` 重组一个完整 frame；content body 跨 MSS（最大报文段长度）时，先重组 body 再检查 body size。PCAP 的 `frames` offset 只固定无 options 的稳定 fixture，不将一个 TCP 包等同于一个 AMQP frame。

## 3. Protocol header 和 frame 总体布局

连接建立后客户端首先发送 8 字节协议头：

```text
41 4d 51 50 00 00 09 01
 A  M  Q  P  major=0 minor=9 revision=1
```

`AMQP\0\0\9\1` 必须是 TCP application stream（应用流）的首个 AMQP 字节。随后每个 frame 使用：

```text
FrameType(1) | Channel(2) | Size(4) | Payload(Size) | FrameEnd(1)
```

所有整数均为 network byte order（网络字节序，大端序）；FrameEnd 固定为 `0xCE`。FrameType 取值：1=METHOD、2=HEADER、3=BODY、8=HEARTBEAT。Frame size 只计算 Payload，不计算 7-byte frame header 和 1-byte end marker。METHOD payload 至少 4 字节 `ClassId(2)|MethodId(2)`；HEADER payload 由 class、weight、body-size、property flags 和 properties 构成；BODY payload 是任意 bytes；HEARTBEAT 的 channel=0、size=0。

实现必须拒绝 frame type 未知、FrameEnd 非 `0xCE`、size 越过 TCP stream、METHOD payload 小于 4、BODY/HEADER channel 不匹配、heartbeat 带 payload，以及 frame interleave（交错）违反 content stream 规则的输入。

## 4. AMQP 0-9-1 frame 编码

### 4.1 METHOD frame

METHOD frame 的 payload 起点依次为 `class-id:uint16`、`method-id:uint16`、method arguments。常用 class/method：

| Class | Method | 名称 | 方向/状态 |
|---:|---:|---|---|
| 10 | 10 | connection.start | server→client |
| 10 | 11 | connection.start-ok | client→server |
| 10 | 30 | connection.tune | server→client |
| 10 | 31 | connection.tune-ok | client→server |
| 10 | 40 | connection.open | client→server |
| 10 | 41 | connection.open-ok | server→client |
| 10 | 50 | connection.close | either direction |
| 10 | 51 | connection.close-ok | opposite direction |
| 20 | 10 | channel.open | client→server |
| 20 | 11 | channel.open-ok | server→client |
| 20 | 40 | channel.close | either direction |
| 20 | 41 | channel.close-ok | opposite direction |
| 40 | 10 | exchange.declare | client→server |
| 50 | 10 | queue.declare | client→server |
| 60 | 20 | basic.consume | client→server |
| 60 | 21 | basic.cancel | client→server |
| 60 | 30 | basic.deliver | server→client |
| 60 | 40 | basic.get | client→server |
| 60 | 50 | basic.get-ok | server→client |
| 60 | 60 | basic.ack | either direction |
| 60 | 80 | basic.publish | client→server |

Shortstr（短字符串）编码为 `length:uint8 | UTF-8 bytes`，不能超过 255 bytes；longstr（长字符串）编码为 `length:uint32 | bytes`；table（字段表）以 entry count 和 typed values 编码；bit arguments 按规范从低位到高位打包。配置中的 method 参数顺序必须与 AMQP 0-9-1 class/method 表一致，不能把 JSON key 顺序当作线上顺序。

### 4.2 CONTENT header 和 properties

一个 publish/deliver message 的顺序固定为：METHOD（basic.publish 或 basic.deliver）→ HEADER（class-id=60）→ 一个或多个 BODY。HEADER payload 包含：

```text
ClassId(2)=60 | Weight(2)=0 | BodySize(8) | PropertyFlags(2+) | Properties
```

`BodySize` 是所有 BODY payload 的总字节数，不包含任何 frame header/end。Property flags 以 16-bit word（位字）为单位，continuation bit（续接位）为 1 时继续下一个 flags word；本版至少支持 content-type、content-encoding、headers、delivery-mode、priority、correlation-id、reply-to、expiration、message-id、timestamp、type、user-id、app-id、cluster-id 的显式配置。未设置的 property 必须通过 flags 清零，不得发送未声明的 property bytes。

BODY frame 的 channel 必须等于对应 METHOD/HEADER channel；所有 BODY payload 长度之和必须恰等于 Header BodySize。BodySize=0 允许在显式 empty-message fixture 中出现，但仍需 HEADER，不能省略 content header。一个 body 大于 frame max（最大帧）时必须拆成多个 BODY frame；当 negotiated `frame_max` 非零时，每个 frame 的完整线上长度 `7 + Size + 1` 不得超过 `frame_max`，不能只比较 payload size。

### 4.3 HEARTBEAT

HEARTBEAT frame 固定为 `08 00 00 00 00 00 00 ce`（type=8、channel=0、size=0、end=CE）。只有连接处于 tune/open 后的 heartbeat state（心跳状态）才允许；客户端/服务端方向由事件显式指定。heartbeat 不能携带 METHOD 或 BODY，也不能把 TCP keepalive 替代 AMQP heartbeat。

## 5. 握手和会话状态机

推荐的单连接序列：

```text
TCP SYN/SYN-ACK/ACK
  → protocol header (client→server)
  ← connection.start
  → connection.start-ok
  ← connection.tune
  → connection.tune-ok
  → connection.open
  ← connection.open-ok
  → channel.open (channel 1)
  ← channel.open-ok
  → exchange/queue/basic methods
  → content METHOD → HEADER → BODY*
  ← basic.deliver / basic.ack or close
  → channel.close → connection.close
  ← close-ok responses → TCP FIN/ACK
```

状态不变式：

| 状态 | 允许事件 | 必须保持 |
|---|---|---|
| `TransportReady` | protocol header | 必须为首个 AMQP bytes，版本 profile 一致 |
| `ConnectionStarting` | start/start-ok/tune/tune-ok/open/open-ok | 方向和 method 顺序匹配；tune 参数可观察 |
| `ConnectionOpen` | channel.open、heartbeat、connection.close | frame_max/channel_max/heartbeat 使用协商值；channel 0 专用 connection methods |
| `ChannelOpen` | exchange/queue/basic/tx/confirm methods | channel 非零且已打开；同一 channel 状态独立 |
| `ContentSending` | publish/deliver/get-ok 后 HEADER/BODY | method→header→body 完整；BodySize、channel、delivery tag 一致 |
| `Closing` | close/close-ok、channel.close/close-ok | 关闭后不得生成新的业务 frame；最终 TCP termination |
| `Error` | malformed frame、顺序/长度/状态错误 | planner→engine（引擎）→task error（任务错误），不能 completed/0 packet |

`connection.start` 是服务端方法，不能由客户端伪造为正常握手；`connection.start-ok`、`tune-ok`、`open` 的顺序不能交换。每个 session 有独立 negotiated values、channel table、delivery tag 和 consumer state，不跨连接继承。

## 6. Exchange、queue、publish 和 consume 语义

`exchange.declare` 需显式 exchange name、type（direct/fanout/topic/headers）、passive/durable/auto-delete/internal/nowait flags；`queue.declare` 需显式 queue name 和 flags。planner 只编码配置，不实现 broker 路由算法。未知 type、空的必需 name、同一 channel 重复声明的不一致参数应拒绝或按显式 passive/compatibility profile 处理，不能静默改写。

`basic.publish` 的 exchange、routing-key、mandatory/immediate flags 与 content sequence 必须关联。`basic.consume` 返回 consumer-tag；`basic.deliver` 包含 delivery-tag、redelivered、exchange、routing-key，随后 HEADER/BODY；`basic.ack` 的 delivery-tag 必须来自同一 channel/session。`basic.get-ok` 与 `basic.get-empty` 只能在显式事件中出现，不自动由 basic.get 推导。confirm.select、tx.select/commit/rollback 只在 profile 显式开启时接受。

## 7. IPv4/IPv6、多连接和边界

IPv4 outer EtherType 为 `0x0800`；IPv6 outer EtherType 为 `0x86dd`，TCP Next Header 为 6。相同 AMQP fixture 在 IPv4/IPv6 中协议头、frame type、class/method、size、FrameEnd、BodySize 和 payload bytes 必须一致，仅外层地址族和 payload offset 改变。

多连接至少使用两个独立 TCP 四元组；每个连接有独立 protocol header、握手、channel table、consumer tag、delivery tag、frame_max 和 close sequence。多 session 的 packet 调度不保证交错顺序，验证使用 tcp.stream、源端口 distinct（不同）或同包关联字段，不硬编码跨流 packet index。

边界至少覆盖：最小 heartbeat/frame、空 body、短字符串长度 0/255/256（256 应拒绝）、frame size=0、frame size=frame_max、body 跨多个 BODY frame、BodySize=0、最大明确可分配 payload、channel 0/1 和 channel_max 边界。不得默认分配 `0xffffffff` bytes；任何 uint32/uint64 加法溢出必须失败而不能回绕。

## 8. 配置 typedef（类型定义）

以下是设计契约，不是当前存在的 Go struct（结构体）：

```go
type AMQPConfig struct {
    Profile       string       `json:"profile"`
    FrameMax      uint32       `json:"frame_max"`
    ChannelMax    uint16       `json:"channel_max"`
    Heartbeat     uint16       `json:"heartbeat"`
    Connections   []AMQPConnection `json:"connections"`
    WireFault     string       `json:"wire_fault"` // 仅负例
}

type AMQPConnection struct {
    SrcIP, DstIP string       `json:"src_ip"`
    SrcPort, DstPort uint16   `json:"src_port"`
    Events       []AMQPEvent  `json:"events"`
}

type AMQPEvent struct {
    Kind          string            `json:"kind"`
    Direction     string            `json:"direction"`
    Channel       uint16            `json:"channel"`
    ClassID       uint16            `json:"class_id"`
    MethodID      uint16            `json:"method_id"`
    Arguments     map[string]any    `json:"arguments"`
    Properties    map[string]any    `json:"properties"`
    Body          []byte            `json:"body"`
    BodySizeOverride *uint64         `json:"body_size_override"` // 仅负例
}
```

Validate 必须覆盖 profile、TCP carrier/port、protocol header、frame type/channel/size/end marker、method class/method/argument lengths、handshake order、channel state、content header properties、BodySize/body frames、connection/session count 和 wire fault。`wire_fault` 只能注入失败，不得作为线上字段或被忽略。

## 9. 错误处理、实现集成和完成定义

| 错误 | 稳定错误锚点 |
|---|---|
| protocol header 缺失/版本错误 | `protocol`/`version` |
| frame type/end marker/size 越界 | `frame`/`size`/`frame end` |
| method class/id/参数长度或 shortstr 越界 | `method`/`argument`/`shortstr` |
| handshake 顺序、方向或 tune 参数错误 | `handshake`/`tune` |
| channel 未打开、channel_max 越界或 channel 0 误用 | `channel`/`session` |
| HEADER property flags、class 或 property length 错误 | `header`/`property` |
| BodySize 与 BODY 总长度、channel 或 frame_max 不匹配 | `body`/`length` |
| delivery/consumer/session 引用跨连接或状态回退 | `delivery`/`consumer`/`session` |
| 非 TCP、错误端口、地址族或连接数非法 | `tcp`/`port`/`address`/`connection` |

实现时应登记 `amqp` 为 Category=Terminal、DependsOn=`tcp`，复用 TCP MSS/checksum 和 IPv4/IPv6 builder；以 TCP stream 重组后按 frame size 解析，不能按 TCP packet 边界切 frame。所有 planner/validator 错误须传播为 task error。未注册期间不得把下列正例加入可执行 suite。

## 10. 原子 ID 与完成定义

设计、testcase 和未来 JSON 必须按以下同一顺序使用 20 个唯一语义 ID：14 个正例、6 个负例。当前 JSON 只放额外的 `amqp_neg_unregistered` 前置占位，不计入 20 个语义 ID。

| # | ID | 类型 | 覆盖 |
|---:|---|---|---|
| 1 | `amqp_protocol_header_ipv4` | 正 | AMQP 0-9-1 8-byte protocol header、TCP/IPv4 |
| 2 | `amqp_connection_handshake` | 正 | start/start-ok/tune/tune-ok/open/open-ok |
| 3 | `amqp_channel_open_close` | 正 | channel 1 open/open-ok/close/close-ok |
| 4 | `amqp_heartbeat` | 正 | type 8、channel 0、size 0、CE |
| 5 | `amqp_exchange_queue_declare` | 正 | exchange/queue method 参数和响应 |
| 6 | `amqp_basic_publish` | 正 | publish→HEADER→BODY、BodySize |
| 7 | `amqp_basic_body_segmentation` | 正 | 多 BODY frame、frame_max 和重组 |
| 8 | `amqp_basic_consume_deliver_ack` | 正 | consumer/deliver/header/body/ack 关联 |
| 9 | `amqp_basic_get_empty` | 正 | basic.get 与显式 get-empty |
| 10 | `amqp_confirm_transaction` | 正 | confirm.select 或 tx select/commit/rollback |
| 11 | `amqp_keepalive_multi_channel` | 正 | 单连接多个 channel、heartbeat/状态隔离 |
| 12 | `amqp_multi_connection` | 正 | 两个 TCP 连接、握手和 delivery 状态隔离 |
| 13 | `amqp_ipv6` | 正 | IPv6/TCP、应用 bytes 不变 |
| 14 | `amqp_frame_boundary` | 正 | frame_max、空 body、shortstr/size 边界 |
| 15 | `amqp_neg_protocol_header` | 负 | 缺失或错误 protocol header |
| 16 | `amqp_neg_frame_encoding` | 负 | 未知 type、非 CE、size 越界 |
| 17 | `amqp_neg_handshake_state` | 负 | method 顺序、方向或 tune/open 状态错误 |
| 18 | `amqp_neg_channel_state` | 负 | 未打开 channel、channel 0/limit 误用 |
| 19 | `amqp_neg_content_length` | 负 | Header BodySize 与 BODY/size 不一致 |
| 20 | `amqp_neg_session_reference` | 负 | delivery/consumer/channel 跨连接引用 |

完成定义：注册 `tcp→amqp` 层链；逐字节生成 protocol header/frame；正确编码 method、header properties、body segmentation 和 heartbeat；握手/channel/content 状态可观测；IPv4/IPv6、多连接/多 channel、MSS 重组和边界均有集成测试；20 个语义 ID 的正负断言和错误传播完成；未注册阶段只接受 `unknown layer` 占位。

## 11. 修订记录

- v1.0.0（2026-08-20）：建立 AMQP 0-9-1 over TCP 设计契约，覆盖 protocol header、method/header/body/heartbeat frame、握手和 channel 状态、exchange/queue/basic、IPv4/IPv6、多连接、多 channel、MSS/长度边界和 20 个正负语义 ID；当前仅提交设计与用例契约，不修改 Go 实现。
