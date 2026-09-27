# AMQP（高级消息队列协议，Advanced Message Queuing Protocol）设计契约

> 版本：v2.1.0（P4–P6 交付与 P6 修轮回写；v2.0.0 = P1–P3 完整产物）
> 日期：2026-09-27
> 状态：P1 八项规范矩阵（§12）+ 三子表 + 三路对照与候选方案对比（§12.4/§12.5）+ 门1 §1–§14 十四行表（§13，§1/§3/§12 强制展开）+ P2 D-AMQP-1 代码设计草稿（§14）+ P3 对接清单与缺口立项（§15/§16）已落盘；**`amqp` 层已注册、builder/planner/generator 已落码**（`registry.go:486`，`internal/protocol/amqp/`），**P4 层链接线 + P5 去扁平改写（24 例 = 20 语义 ID + 4 链级红例）+ P6 修轮已完成**——lane8 suite 24/24 全绿。本契约不修改 Go 实现（P6 修轮只动测试断言面与文档）。
> 配套文件：`docs/protocol-designs/49-amqp-testcase.md`、`trafficgen/test/protocol_pcap/cases/amqp.json`
> 规范基线：AMQP 0-9-1 wire-level specification（线上规范，精确章节待 G-AMQP-1 对原文复核钉死，本契约只引用规范编号 + builder 注释已标章节）、RabbitMQ AMQP 0-9-1 extensions（扩展）和 TCP（传输控制协议）。
> **层链唯一真相**：本契约目标形状只有纯 `layers` 形（`[ip,tcp,amqp]`，IPv6 地址仍住 `ip` 层）；地址只住 `ip`、端口只住 `tcp`、数量只走 `flow_control`；存量 20 例的顶层扁平键已随 P4 按 §13.1 去向表改写完毕（现存 24 例，非负例顶层键=0）。
> **版本面裁定**：本协议只做 AMQP 0-9-1（builder 全量 class/method 常量均为 0-9-1 §4.2.4 表）；AMQP 1.0 是另一套二进制 framing 线协议，不属本契约范围（§12.1 #8 明确不支持）。

## 1. 范围、profile 和已注册边界

本版定义 AMQP 0-9-1 over TCP 的确定性帧序列，默认 TCP destination port（目的端口）为 5672。覆盖 protocol header（协议头）、connection/channel lifecycle（连接/信道生命周期）、method frame（方法帧）、content header（内容头）、body frame（正文帧）、basic publish/consume/deliver/ack、queue/exchange 声明，以及 IPv4/IPv6、多连接和错误边界。

| profile（协议档案） | 规范范围 | 本版允许内容 | 不从 profile 推导 |
|---|---|---|---|
| `amqp091_rabbitmq` | AMQP 0-9-1 基础 | connection/channel、exchange/queue、basic publish/consume/deliver/ack、confirm、tx 的显式方法 | 自动 broker（消息代理）路由、持久化、消费者业务处理 |
| `amqp091_minimal` | AMQP 0-9-1 core | protocol header、start/tune/open、channel open/close、connection close | RabbitMQ 私有 extension method、AMQP 1.0、STOMP |
| `amqp091_tls_boundary` | TLS 外层边界 | 仅未来 TLS/TCP 载体定义 | 未解密时不声称看见 AMQP method/header/body |

**已注册/已落码现状（P1 实测，行号真实）**：`amqp` 终结层已注册（`registry.go:486`，`CategoryTerminal + DependsOn ["tcp"]`，`FieldContract {"tcp.dst_port": "5672"}`，注释 `registry.go:478-485`；层字段表 6 键 `profile/frame_max/channel_max/heartbeat/connections/wire_fault`）；白名单已登记（`protocols.go:22`）；配置结构 `AMQPConfig/AMQPConnection/AMQPEvent`（`types.go:286-330`）；wire 编码 `internal/protocol/amqp/builder.go`（762 行：protocol header/frame 组装、shortstr/longstr/table 编码、method 参数顺序表、properties、body 分段）；validator/generator `internal/protocol/amqp/planner.go`（462 行：`validateAMQPConfig :145`、`validateWireFault :432` 9 种 fault、生成器 `:20`）；策略子配置解析 `strategy_convert.go:636-638`；Meta 直传 `chain_planner_translate.go:157` + `generator.go:389`；TCP MSS 共用校验 `validate.go:101`；单元测试 29 个（`amqp_test.go` 678 行；**P6 后 30 个 / 774 行**——新增 `TestValidateChannelAndStateGuards` 覆盖 m1 点名的 7 条守卫分支）；生成表含 `amqp`（`layers.generated.json`，`depends_on ["tcp"]`，fields 6 键）；提交 `f59509c`。v1.0.0 所述"层尚未注册/仅占位"已过期，以本段为准（见 §17.2 旧文逐条核对）。

`cases/amqp.json` 现有 20 例（14 正/6 负）**全部已有 `layers`**（`[{"tcp":{}},{"amqp":{}}]` 空条目，20/20），但仍为旧扁平形（顶层 `src_ip/dst_ip/src_port/dst_port` + 顶层 `amqp` 子映射，无 `ip` 层、无 `flow_control`）——P4 按 §13.1 去向表改写。D-AMQP-1 未定稿——P4 落码前以门1 获批版为准，不宣称当前 suite 可运行。**【P4/P5/P6 已执行】**：上述改写已完成——现存 **24 例**（20 语义 ID + 4 链级红例），全部纯 `layers` 形（非负例顶层键=0）；lane8 suite 24/24 全绿、coverage 反查 68/68 绿。

## 2. 协议栈、载体和固定偏移

推荐层链为 `[ip, tcp, amqp]`。AMQP 明文只使用 TCP；UDP、裸 IP、HTTP、WebSocket 和 AMQP 1.0 不得静默当作本版载体。默认目的端口 5672（`FieldContract tcp.dst_port=5672`，`registry.go:488`；`strategy_convert.go:636-638` 仅用户未指定时覆盖），TLS 加密形 AMQPS 用 5671（**未实现**：`grep -rn 5671` 零命中，见 G-AMQP-1）。源端口由 fixture 显式给出（存量 `12345`；多连接例第二连接 `12346`）。IPv6 地址仍住 `ip` 层（链形不变 `[ip,tcp,amqp]`，EtherType 由 `spec.SrcIP` 派生 `chain_planner_gen.go:231`）。

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
| 60 | 30 | basic.cancel | client→server |
| 60 | 40 | basic.publish | client→server |
| 60 | 60 | basic.deliver | server→client |
| 60 | 70 | basic.get | client→server |
| 60 | 71 | basic.get-ok | server→client |
| 60 | 72 | basic.get-empty | server→client |
| 60 | 80 | basic.ack | either direction |
| 85 | 10 | confirm.select | client→server |
| 90 | 10/11 | tx.select/select-ok | client→server / server→client |
| 90 | 20/21 | tx.commit/commit-ok | client→server / server→client |
| 90 | 30/31 | tx.rollback/rollback-ok | client→server / server→client |

Shortstr（短字符串）编码为 `length:uint8 | UTF-8 bytes`，不能超过 255 bytes（实现 `encodeShortstr`，`builder.go:134-141`，越界即错 `shortstr too long`）；longstr（长字符串）编码为 `length:uint32 | bytes`；table（字段表）以 entry count 和 typed values 编码；bit arguments 按规范从低位到高位打包。配置中的 method 参数顺序必须与 AMQP 0-9-1 class/method 表一致，不能把 JSON key 顺序当作线上顺序（实现参数顺序表 `methodArgOrder`，`builder.go:525` 起，0-9-1 §4.2.4 声明序）。**P1 勘误**：v1.0.0 §4.1 表将 basic.ack 误标 method 60、basic.publish 误标 80——0-9-1 实际 basic.publish=40、basic.ack=80（builder 常量 `builder.go:60-64`），存量 `amqp.json` 用例用的正是 40/80，本表已按实现改正；basic.get 实为 70、get-ok 71、get-empty 72（v1 表写 40/50/60 同误，存量用例 70/72 为准）。**P6 勘误（第二轮）**：同表 basic.cancel 曾标 21、basic.deliver 曾标 30——实为 basic.cancel=30、basic.deliver=60（`builder.go:57/:59`），表体已改，线面证据 #8 p15=`60/60`（deliver）、#11 p16/p17=`60/40`（publish）与 builder 常量一致。

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

实现时应登记 `amqp` 为 Category=Terminal、DependsOn=`tcp`（**已登记**，`registry.go:486`），复用 TCP MSS/checksum 和 IPv4/IPv6 builder（`validate.go:101` 共用 MSS 校验）；以 TCP stream 重组后按 frame size 解析，不能按 TCP packet 边界切 frame。所有 planner/validator 错误须传播为 task error。未注册阶段只接受 `unknown layer` 占位——**该阶段已过**（v1.0.0 占位 `amqp_neg_unregistered` 在存量 20 例中**不存在**，见 §13.2 实测）；当前负例走 `wire_fault` 9 值（`planner.go:432-455`）+ 自然守卫双通道。

## 10. 原子 ID 与完成定义

设计、testcase 和未来 JSON 必须按以下同一顺序使用 20 个唯一语义 ID：14 个正例、6 个负例（`amqp_neg_unregistered` 占位不存在，见上节实测）。

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

**P1 实测注记**：`amqp_confirm_transaction` 存量用 class 90（tx.select/commit/rollback 全 6 方法），**confirm.select（class 85）未在用例面出现**（builder/planner 已支持，`builder.go:36/65` + `planner.go:348-351`）——属 A′ 补例候选（T-21）。`amqp_heartbeat` 断言 `amqp.type=8` 双包（packet 11/12）+ `amqp.channel=0` + `amqp.length=0`。

完成定义：`tcp→amqp` 层链已注册（`registry.go:486`，P4 只做层链整形）；逐字节生成 protocol header/frame；正确编码 method、header properties、body segmentation 和 heartbeat；握手/channel/content 状态可观测；IPv4/IPv6、多连接/多 channel、MSS 重组和边界均有集成测试；20 个语义 ID 的正负断言和错误传播完成；P4 层链整形 + 4 链级红例 + casegen 全绿后 D-AMQP-1 置"已验收"。

## 11. 修订记录

- v2.1.0（2026-09-27）：P4–P6 交付与 P6 修轮回写。**P6 修轮**：§4.1 表 basic.cancel 21→30、basic.deliver 30→60（勘误第二轮，对 `builder.go:57/:59`）并按 method 数值重排 basic 段；§12.2 R3c2 引用回正（`#18` 实命 `:306`，channel 0 保留位 `:293` 由单测覆盖，不再高估 #18 覆盖面）；§13.12 序号算法落点回填（层链动态解析框架面 `layer_dyn.go` `resolveLayerTuple :770`，业务字段全关、无专属序号算法）；§16 G-AMQP-3 并入 m3 枚举缺口（`basic.get-ok` 60/71、`basic.cancel` 60/30、`basic.cancel-ok` 60/31 无例且未登记）；§10 ID 表 ipv6 行号 8→13、删除与实测矛盾的 `amqp_neg_unregistered` 占位句；行号漂移重钉（registry.go 486/478-485/488、strategy_convert.go 636-638、planner channel 锚 293/306）。P4–P5 交付（层链接线 + 24 例改写 + check_amqp 登记）见车道报告 p4-report.md。
- v2.0.0（2026-09-26）：P1–P3 完整产物。新增 §12 P1 八项规范矩阵 + 三子表（事件×连接/channel 状态矩阵、数据形态变体表、P1 三路对照 §12.4、候选方案对比 §12.5）；§13 门1 §1–§14 十四行表（§1/§3/§12 强制展开 + 目标形状 spec_json 样例 + presence 负例形状）；§14 D-AMQP-1 P2 代码设计草稿；§15 P3 对接清单；§16 缺口立项（G-AMQP-1/2/3/4）；§17 自重审与核对结论。§1 重写为已注册边界（注册行号 registry.go:486 实测）；§4.1 勘误 basic.publish/ack/get 系列 method ID（60/80/40/50→40/80/70/71/72）；§10 增补 confirm/tx 行与实测注记。
- v1.0.0（2026-08-20）：建立 AMQP 0-9-1 over TCP 设计契约，覆盖 protocol header、method/header/body/heartbeat frame、握手和 channel 状态、exchange/queue/basic、IPv4/IPv6、多连接、多 channel、MSS/长度边界和 20 个正负语义 ID；当前仅提交设计与用例契约，不修改 Go 实现。

## 12. P1 规范矩阵（CORE_MEMORY §4 八项：规范要求→业务场景→代码现状→缺口）

> 深度口径（§4.19–4.22）：矩阵三张子表——①事件×连接/channel 状态矩阵（§12.2）②数据形态变体表（§12.3）③商业行为→用例映射表（§13.2）。条目三选一：已实现 / 明确不支持 / 不适用 + 对应用例号；无遗漏留白。
> **TCP 载体铁律（逐矩阵行重申）**：amqp rides TCP（registry `DependsOn ["tcp"]`，`registry.go:447`）——UDP 载体判死（`carrier` 锚词，链中夹 udp 层即错，bacnet 同构）；AMQP 0-9-1 与 AMQP 1.0 是两套二进制 framing 线协议，本契约只做 0-9-1（builder 全量常量为 0-9-1 §4.2.4 表，`builder.go:31-37`）。

### 12.1 八项规范矩阵

| # | 规范要求（0-9-1 规范 + 本契约节） | 业务场景 | 代码现状 | 缺口 |
|---|---|---|---|---|
| 1 | 连接模型：client→server 单 TCP 长连接（默认 5672），client 发 protocol header 后双向 frame 流；TCP 语义（握手/seq-ack/挥手/MSS 分段）由 tcp 层生成器承载（0-9-1 §2；本契约 §2/§5） | 应用连 broker 声明 exchange/queue、发布/消费消息、心跳保活 | 已实现：事件序逐包 Emit（`planner.go:20-134`），TCP 握手由链 `[ip,tcp,amqp]` 提供 | TCP 分段重组边界由引擎已验证面承载；P4 只做层链整形+红例+casegen（§14） |
| 2 | 命令消息表：METHOD/HEADER/BODY/HEARTBEAT 四类 frame + class/method 表（connection 10 / channel 20 / exchange 40 / queue 50 / basic 60 / confirm 85 / tx 90；本契约 §4.1 表） | 六类 class 全表逐方法编码 | 已实现：class/method 常量（`builder.go:31-37/39-67`）+ `methodArgOrder` 参数序表（`:525` 起，confirm/tx 含 `:598-602`）+ 未知 class/method 拒（`planner.go:356`） | **confirm.select（85/10）无用例**（存量 20 例 class 85 零出现）→ A′ T-21；encodeMethodArguments 部分参数面（如 start 的机制/locales table）未逐字段断言 → G-AMQP-3 |
| 3 | 状态机：protocol header → start/start-ok/tune/tune-ok/open/open-ok → channel.open/close → content 序列（method→header→body*）→ connection.close；close 后只允许 close/close-ok（0-9-1 §2.2；本契约 §5 表） | 握手顺序错、未开 channel 发业务、content 跨 channel 交错、close 后残留帧 | 已实现：`validateAMQPConfig` 全状态机（`planner.go:196-417`：close 后守卫 `:201-211`、方向逐方法 `:239-283`、channel 状态 `:288-347`、content 交错 `:360-363`、heartbeat before open `:409-412`） | **校验器只扫 `Connections[0]`**（`planner.go:174` `conn := &c.Connections[0]`），第 2+ 连接事件不校验 → G-AMQP-2（生成器 `:37` 全连接扫，校验/生成不对称为已实证现状） |
| 4 | 字段表：frame `type(1)/channel(2)/size(4)/payload/end(1)`；shortstr ≤255；properties flags word + 14 property；BodySize=body 总长；frame_max 非零时 `7+Size+1 ≤ frame_max`（0-9-1 §4.2；本契约 §4） | 短名/长名、14 property 全集、body 分段、size 边界 | 已实现：`buildFrame`（`builder.go:122`）、`encodeShortstr :134`、`encodeProperties :637`、`splitBody :725`（frame_max≥8 生效，≤4088 走 stress 分支）、BodySize 由后续 body 事件自动累加（`planner.go:70-79`）或 `body_size_override` | **frame_max>4088 时普通分支 chunk=frame_max−8（`builder.go:747`）已对**；shortstr=255/256 边界无用例 → A′ T-20；channel_max/heartbeat 配置键只经 tune 参数面（`builder.go:540-542`）消费，无用例钉 → G-AMQP-3 |
| 5 | 错误处理：protocol 版本/frame 编码/握手状态/channel 状态/content 长度/session 引用六类拒收 + wire_fault 9 值（本契约 §9 表） | 脏包、错序、伪造长度一律 task error，零假成功 | 已实现：6 负例锚词行（`planner.go:432-455` wire_fault 9 值实测字符串：`protocol version`/`bad frame type`/`frame end marker`/`frame size overflow`/`handshake state`/`channel state`/`body length`/`session reference`/`shortstr overflow`）+ 自然守卫（unknown method `:356`、direction `:214-219`、profile `:155-157`、frame_max<8 `:171-173`、BodySize mismatch `:422-426`） | 链级红例 4 例 P4 新增（presence/白名单/udp 载体/缺 tcp，§13-P2）；`shortstr_overflow`/`bad_frame_end`/`frame_size_overflow` 3 个 wire_fault 值无用例 → G-AMQP-3 |
| 6 | 超时活性：tune 协商 heartbeat 秒数，双方按协商值发 HEARTBEAT frame；空闲超时由 broker 侧执行（0-9-1 §2.3；本契约 §4.3） | 长连接保活；多 channel 下心跳隔离（channel 0） | 已实现：`heartbeat` 配置键直通（types.go `:294`）；`buildHeartbeatFrame` 固定 8 字节（`builder.go:114-117`）；心跳 before open 拒（`planner.go:409-412`） | 周期心跳调度（按协商秒数自动定时发）→ 明确不支持（声明式回放族，heartbeat 是显式事件）；TCP keepalive 替代面不适用 |
| 7 | NAT/代理：AMQP 无 PORT/PASV 类衍生数据连接（单 TCP 连接内多路复用 channel），无被动模式语义；经 NAT 只影响 TCP/IP 寻址，AMQP frame 字节不变 | broker 经 NAT/LB 可达 | 不适用（显式声明，不用"待确认"逃逸）：无 AMQP 层语义可测，无用例 | 无缺口（显式不适用 ≠ 缺口） |
| 8 | 版本方言：0-9-1 与 RabbitMQ 扩展（confirm/tx class）；`amqp091_tls_boundary` profile 仅未来 TLS 载体定义（types.go `:291` 注释）；AMQP 1.0 是另一套 framing（0-10 起协商 + performatives），不属本契约 | RabbitMQ 生态 0-9-1 + confirm/tx 扩展；AMQPS 5671 | 已实现：`amqp091_rabbitmq`/`amqp091_minimal` 双 profile（`planner.go:155` 白名单）；**TLS 载体未接线**（`tls` 层 OptionalOn 面无 amqp 声明，`registry.go:486-497` 无 OptionalOn 键；`grep -rn 5671` 零命中） | AMQPS/TLS 载体（5671）→ G-AMQP-1；AMQP 1.0 → 明确不支持；`amqp091_tls_boundary` profile 保留为边界占位（types.go 注释"未来"），不冒充已实现 |

### 12.2 子表①：事件×连接/channel 状态矩阵（逐格已覆/缺失）

行=事件形状，列=连接/channel 状态面：

| 事件 \ 状态面 | 合法状态前置满足 | 前置缺失（未握手/未开 channel） | 方向颠倒 | close 后残留 |
|---|---|---|---|---|
| protocol_header | 已覆 #1/#13 | 不适用（首事件无前置） | 缺口→负例 #15（非 c2s 拒，`planner.go:227`） | 不适用 |
| connection 握手方法（start..open-ok） | 已覆 #2/#3 | 缺口→负例 #17（open before tune-ok，`planner.go:272`） | 缺口→负例 #17（start 非 s2c 拒 `:240`；同 wire_fault `handshake_state` 通道） | 缺口→#17 通道（close 后 method 拒，`planner.go:201-211`） |
| channel.open/close（业务 channel） | 已覆 #3/#11（多 channel 隔离） | 缺口→负例 #18（unopened channel 业务拒 `:306`/`:326`）+ 单测覆盖（channel 0 保留位 `:293`、open before open-ok `:290`、open-ok without open `:298`——`amqp_test.go` `TestValidateChannelAndStateGuards`） | 不适用（channel 方法方向无颠倒变体） | 已覆 #17 通道 |
| content 序列（publish/deliver→header→body） | 已覆 #6/#7/#8（BodySize/分段/delivery 关联） | 缺口→负例 #19（body mismatch `planner.go:425`）+ #18 通道（unopened channel publish） | 缺口→负例 #19 通道（channel 错配 `:377/:403`） | 缺口→#17 通道 |
| heartbeat | 已覆 #4/#11/#14（type 8/channel 0/size 0） | 缺口→负例 #17 通道（before open 拒 `planner.go:411`） | 不适用（heartbeat 无方向颠倒判） | 不适用 |
| confirm/tx 方法 | **A′ T-21**（tx 已覆 #10；confirm 85 无例） | 不适用（confirm/tx 依赖 open channel，共享 #18 通道） | 不适用 | 不适用 |
| exchange/queue declare | 已覆 #5（参数+ok 响应） | 缺口→#18 通道（unopened channel declare `planner.go:335/:341`） | 不适用 | 不适用 |

注：矩阵按**事件×状态前置轴**排——本引擎只做 client/server 双侧事件回放（声明式事件面），broker 侧动态应答只由 tshark 字段面验证。**逐格重数（7 行 × 4 列 = 28 格，逐格枚举，严格四桶互斥，可复核）**：**已覆 7 格**（R1c1←#1/#13、R2c1←#2/#3、R3c1←#3/#11、R3c4←#17 通道、R4c1←#6/#7/#8、R5c1←#4/#11/#14、R7c1←#5）；**缺口→用例通道 10 格**（R1c3←#15、R2c2/R2c3/R2c4←#17、R3c2←#18 + 单测、R4c2←#19/#18、R4c3←#19 通道、R4c4←#17 通道、R5c2←#17 通道、R7c2←#18 通道）；**不适用 10 格**（R1c2、R1c4、R3c3、R5c3、R5c4、R6c2、R6c3、R6c4、R7c3、R7c4）；**A′ 立项承载 1 格**（R6c1：tx 半格已覆 #10，confirm 半格 → A′ T-21）。7 + 10 + 10 + 1 = 28 ✓ **逐格有结论、无空格、无双计**（P6 n8 修：R3c3 只归不适用、R6c1 只归 A′ 桶，不再跨桶重列）。

### 12.3 子表②：数据形态变体表（协议相关全部形态逐项）

| 变体维度 | 形态 | 对应用例 | 备注 |
|---|---|---|---|
| frame type | METHOD(1)/HEADER(2)/BODY(3)/HEARTBEAT(8) | #1–#14 全正例（`amqp.type` 逐类断言） | `amqp.type` 已注册命中（本机 3.6.14） |
| channel 面 | channel 0（connection 方法+heartbeat）/channel 1/2（业务） | #1–#10/#14 + #11（双 channel）| channel 0 误用 → #18（`planner.go:293`） |
| 握手方法序 | start→start-ok→tune→tune-ok→open→open-ok 六步全序 | #2/#3/#5–#10/#12/#14 前缀 | 顺序/方向错 → #17 |
| body 分段 | frame_max=128 拆 200B body / frame_max=4096 边界 / frame_max=0 不分段 | #7/#14 | splitBody 双分支（`builder.go:725-749`）实测 |
| BodySize 面 | 6B 单 body / 200B 分段 / 0（空 header 面）/#19 override=100 vs body=5 | #6/#7/#14/#19 | BodySize 自动累加（`planner.go:70-79`）；override 负例面 #19 |
| properties | content_type/delivery_mode 显式 / 空 properties（flags=0） | #6/#7/#8 | `encodeProperties`（`builder.go:637`）；14 property 全集 → G-AMQP-3 |
| 方法参数面 | exchange/queue 名、routing_key、consumer_tag、delivery_tag、mandatory | #5/#6/#8 | 参数序=声明序（`methodArgOrder`）；shortstr 边界 → A′ T-20 |
| 地址族 | IPv4（10.0.0.1→20.0.0.1）/IPv6（2001:db8::1→::2） | #1/#13 | IPv6 链形不变 `[ip,tcp,amqp]`；offset 74 |
| 多连接 | 双 TCP 四元组（src_port 12345/12346）各自握手 | #12 | `connections[]` 两连接；校验器只扫首连接 → G-AMQP-2 |
| 多 channel | channel 1/2 独立 open + 各自业务 + heartbeat 隔离 | #11 | channel 状态 map 每连接独立（`planner.go:41`） |
| profile | amqp091_minimal（10 例）/amqp091_rabbitmq（10 例） | 全部 20 例 | profile 白名单 `planner.go:155`；未知 profile 拒 |
| wire_fault 值面 | protocol_version/bad_frame_type/handshake_state/session_reference 四值有用例 | #15/#16/#17/#20 | shortstr_overflow/bad_frame_end/frame_size_overflow/channel_state/body_length 五值无用例 → G-AMQP-3 |
| 端口面 | dst_port 5672 全例显式写 | #1–#14 | FieldContract 5672 缺省（`registry.go:488`）与显式写同值；5671 未实现 → G-AMQP-1 |

### 12.4 P1 三路对照（CORE_MEMORY §4.12–4.15）

**①规范原文**：AMQP 0-9-1 wire-level specification（OASIS/AMQP.org 官方线规范）全文为"必须是什么"底线；frame 布局/class 表/状态机/编码四面已逐节落本契约 §3–§5。精确章节号待 G-AMQP-1 对原文复核钉死（builder 注释已标 §4.2.1/§4.2.4/§4.2.5.4/§4.2.6，复核时逐条对原文——§5.7 不编章节号）。

**②现网行为**：RabbitMQ（生态主流 broker）默认监听 5672、同端口同时接受 0-9-1 与 1.0（按 client 首字节 protocol header 区分），AMQPS 为 5671（TLS）。出处确认方式：抓现网/回环 broker 包核对 protocol header/frame 面（**立项 G-AMQP-1**：现网级确认前相关条目按 §5.5 标"待确认"，不写死进实现）。

**③开源实现思路**：wireshark `packet-amqp.c`（本机 3.6.14 实测 `amqp.*` 493 字段——断言通道权威；`amqp.method.class/method`、`amqp.type/channel/length`、`amqp.header.class/body-size` 8 字段 1/1 精确命中）；本仓库已落码 builder/planner（`internal/protocol/amqp/` 1224 行 + planner 462 行）为 wire 真相；只借鉴字段语义与拆解思路。

**三路结论一致性**：三路在"8 字节 protocol header `AMQP\0\0\9\1`、frame 7B 头+CE、frame type 四值、class/method 表（basic.publish=40/ack=80）、TCP 5672"五点一致。取舍：①内层 frame 字节以 builder 编码 + tshark 读回为准，先跑后钉；②现网 broker 差异面（tune 协商值策略、心跳超时执行、1.0/0-9-1 共存端口行为）未到确认级 → G-AMQP-1，不写死。

### 12.5 候选方案对比（§4.17）

| 方案 | 走法（含借鉴来源） | 优 | 劣 | 性能/复杂度/兼容性 | 结论 |
|---|---|---|---|---|---|
| A 结构化事件声明式回放 | connections[]/events[]（kind/direction/class/method/arguments/properties/body）+ wire 由 builder 纯函数产出（同族 gbt/megaco 事件面范式） | 字段可结构化断言；动态面可开；与已收官族同构 | 多连接交织序不假设 | O(n) 流式；复杂度低；双 profile 兼容 | **采用（已落码）** |
| B 生 hex 回放 | 整 packet hex 覆盖 | 最简单 | 字段不可断言；method/property 变体即死 | 动态零分 | 仅作负例特殊形逃生口 |
| C 完整 broker 状态机模拟器 | 自动补协商响应/心跳定时 | 真实度高 | 超出声明式回放族边界；与 §3.13"不许隐式编排"冲突 | 复杂度高、收益无 fixture 面支撑 | 不选 |

## 13. 门1 §1–§14 十四行对照表（CORE_MEMORY §15.1–15.3）

| § | 本协议怎么满足 | 证据 |
|---|---|---|
| §1 层链唯一真相 | 见 §13.1 强制展开：旧键 `src_ip/dst_ip/src_port/dst_port` 四键迁入 `ip`/`tcp` 层；顶层 `amqp` 子映射迁入 `layers[]` amqp 条目；数量走 `flow_control`（存量 20 例均缺该键，P4 补）；目标形状 spec_json 样例见 §13.1；存量 20 例逐键去向见 §13.1 去向表；非负例顶层键=0（presence 负例见 §13-P2） | 本契约 §2（目标形状）+ §13.1 样例与去向表；存量实测 `topkeys=[amqp,dst_ip,dst_port,layers,src_ip,src_port]`（20/20 全中）、`layers=[{tcp:{}},{amqp:{}}]`（20/20） |
| §2 策略/任务 | 策略=单 AMQP 连接模板（自带 `flow_control` flows/bps/time）；任务=多策略合跑+总量封顶；框架语义未动 | 本契约 §12.1 + §14 |
| §3 五件套 | 见 §13.3 强制展开：双 profile 会话表/事务序列/关联关系/插入位置/时间线；TCP 有真握手（`has_handshake=true` 由 tcp 层承载，14/14 正例存量已断言），不虚构额外建连包数 | 本契约 §13.3 + 用例 #2/#11/#12 |
| §4 查规范 | AMQP 0-9-1 官方线规范（编号级引用，精确章节待 G-AMQP-1）+ tshark `amqp.*` 493 字段实测 + 已落码 builder wire 真相 + §12 矩阵 8 行+三子表 + 三路对照（§12.4） | 本契约 §12 |
| §5 依赖与错误 | `DependsOn ["tcp"]`（registry.go:447；单载体 + `FieldContract tcp.dst_port=5672` `:449`）；`wire_fault` 9 值（`planner.go:432-455`）+ 自然守卫（§9 锚词表）；TCP MSS 共用校验（validate.go:101）；失败返回 task error（零假成功） | 本契约 §2/§9 + §14 错误分支 |
| §6 性能 | 单事件流式渲染无全量聚合；pcap/NIC 双路验收；吞吐/并发/内存目标待 P4 基准后定（§6.5 诚实待确认，不写承诺数字）；六类场景清单见 §14 | §14 性能设计与验收 |
| §7 三份文档 | 49-amqp-{design,testcase}.md v2.0.0（行为面权威）+ D-AMQP-1（本契约 §14 草稿，门1 获批=定稿）+ T-AMQP（testcase §9 草稿）+ generated schema（amqp 已在生成表内，P4 只跑 `TestLayersGeneratedMatchesRegistry` 验证无过期） | 修订记录 |
| §8 设计先行 | 本条目 P1–P3 先于 P4 层链整形开工；门1 获批=D-AMQP-1 定稿=开工门 | 提交序 |
| §9 测试三源 | 三源=AMQP 0-9-1 规范条款（编号级，精确章节待 G-AMQP-1）+ D-AMQP-1 + tshark `amqp.*` 493 字段已实证 + builder wire 真相 + 现网 RabbitMQ 形态（未确认级→G-AMQP-1）；20 ID 正负对账 | T-AMQP（testcase §9） |
| §10 评审闭环 | 每阶段对抗自重审（结论见 p123 报告）+ 收官隔离复审 + 修轮；红先绿后 | /tmp/pipe/70-amqp/p123-report.md |
| §11 白话 | 每阶段白话一句先行 | 汇报 |
| §12 动态清单 | 见 §13.12 强制展开：四元组=ip/tcp 层（五策略全支持）；业务字段逐个列开/不开+理由；序号算法位置诚实"待 P4 定"（不编行号，§5.7） | 本契约 §13.12 |
| §13 schema 派生 | registry amqp 行（`DependsOn ["tcp"]` + 6 键 Fields；端口缺省 5672 双通道：strategy_convert `:636-638` 用户未写时覆盖 + FieldContract 通用块 `chain_planner.go:596-604`——fixture 显式写 5672 时均不生效）→ schemagen 重跑验证；struct 标签字面量锁 | §14 接线件 |
| §14 真实流程 | suite 经 MCP 建任务→引擎生成→tshark `amqp.*` 字段 + frames hex 双通道；先跑后钉；pcap 落 `/tmp/mcp-pcaps/amqp/` | 用例 §1/§6 |

### 13.1 §1 强制展开：旧键去向 + 完整 spec_json 样例

旧键清单（`src_ip`/`dst_ip`/`src_port`/`dst_port`/`count` + 本协议顶层子映射 `amqp`）：

| 旧键 | 去向 |
|---|---|
| `src_ip` | → `layers[0].ip.src`（IPv4 例 `10.0.0.1`、IPv6 例 `2001:db8::1` 起各例 fixture 值保留） |
| `dst_ip` | → `layers[0].ip.dst`（`20.0.0.1` / `2001:db8::2` 保留） |
| `src_port` | → `layers[1].tcp.src_port`（`12345`；multi_connection 双连接靠 `connections[].src_port` 12345/12346——**每连接独立 TCP 流由 P4 改写拆为独立流或保持 events 同流声明，见 G-AMQP-2 裁定**） |
| `dst_port` | → `layers[1].tcp.dst_port`（`5672`；与 FieldContract 缺省同值，P4 改写时可省略走缺省，但存量显式值保留亦合规） |
| `count`（若有） | → 删除，走 `flow_control.flows`（存量 20 例均无此键，属"缺键补齐"非"旧键迁移"；单连接正例 `flows=1`） |
| 顶层 `amqp` 子映射 | → `layers[]` 中 `{"amqp": {...}}` 条目（业务键 `profile/frame_max/channel_max/heartbeat/connections/wire_fault` 全量迁入，零残留；registry Fields 6 键同名单） |

**存量 20 例改写清单（逐键；P4 执行，§9.14 存量审计落点）**：实测全部 20 例 `spec_json` 顶层键 = `['amqp','dst_ip','dst_port','layers','src_ip','src_port']`，`layers` = `[{"tcp":{}},{"amqp":{}}]`（**无 `ip` 层**——旧扁平形把地址放在顶层）。逐键去向：

| 现状 | 去向（P4 改写） |
|---|---|
| 顶层 `src_ip`/`dst_ip` | 删除顶层键；新增 `{"ip": {"src": ..., "dst": ...}}` 作为 `layers[0]`（**结构性新增**非仅挪值；IPv6 例 #13 同样补 `ip` 层填 v6 地址） |
| 顶层 `src_port`/`dst_port` | 删除顶层键；写进 `layers` tcp 条目（`{"tcp": {"src_port": ..., "dst_port": ...}}`） |
| `layers` 内 `{"amqp":{}}` 空条目 | 填入顶层 `amqp` 子映射全部业务键（`profile`/`frame_max`/`channel_max`/`heartbeat`/`connections`/`wire_fault`） |
| `flow_control` | 20 例全缺，逐例补（单连接例 `{"flows": 1}`） |
| 负例 `expect.fields: []` 空数组 | 删除（14.11：负例 expect 键集合只允许 `{expect_error, error_contains}`，空 `fields` 是非法形状） |

改写后必须满足：非负例顶层键 = 0（仅 `layers`/`flow_control`/`output` 家族）；负例 `expect` 键集合恰为 `{expect_error, error_contains}`。`expect` 内 `fields`/`frames`/`min_packets` 为 harness 断言键，不计顶层白名单。

完整最小握手样例（目标形状，顶层键仅 `layers`+`flow_control`；`connections[]` 住 amqp 层条目）：

```json
{
  "layers": [
    {"ip": {"src": "10.0.0.1", "dst": "20.0.0.1"}},
    {"tcp": {"src_port": 12345, "dst_port": 5672}},
    {"amqp": {
      "profile": "amqp091_minimal",
      "connections": [
        {"events": [
          {"kind": "protocol_header", "direction": "c2s"},
          {"kind": "method", "direction": "s2c", "class_id": 10, "method_id": 10, "channel": 0},
          {"kind": "method", "direction": "c2s", "class_id": 10, "method_id": 11, "channel": 0},
          {"kind": "method", "direction": "s2c", "class_id": 10, "method_id": 30, "channel": 0},
          {"kind": "method", "direction": "c2s", "class_id": 10, "method_id": 31, "channel": 0},
          {"kind": "method", "direction": "c2s", "class_id": 10, "method_id": 40, "channel": 0},
          {"kind": "method", "direction": "s2c", "class_id": 10, "method_id": 41, "channel": 0}
        ]}
      ]
    }}
  ],
  "flow_control": {"flows": 1}
}
```

basic.publish content 序列样例（publish→HEADER→BODY，BodySize 自动累加）：

```json
{
  "layers": [
    {"ip": {"src": "10.0.0.1", "dst": "20.0.0.1"}},
    {"tcp": {"src_port": 12345, "dst_port": 5672}},
    {"amqp": {
      "profile": "amqp091_rabbitmq",
      "connections": [{"events": [
        {"kind": "method", "direction": "c2s", "class_id": 60, "method_id": 40, "channel": 1,
         "arguments": {"exchange": "", "routing_key": "test", "mandatory": false}},
        {"kind": "header", "direction": "c2s", "channel": 1, "class_id": 60,
         "properties": {"content_type": "text/plain", "delivery_mode": 1}},
        {"kind": "body", "direction": "c2s", "channel": 1, "body": "Hello!"}
      ]}]
    }}
  ],
  "flow_control": {"flows": 1}
}
```

### 13.2 子表③：商业行为→用例映射表（CORE_MEMORY §4.16；缺此表按 §4.22 记缺口）

| # | 商业行为（产品+行为） | 出处 | 对应用例 | 状态 |
|---|---|---|---|---|
| 1 | 应用连 RabbitMQ 完整握手（protocol header + start/tune/open 六步，channel 0） | 现网通用形态（RabbitMQ 官方文档 networking 面；0-9-1 §2 同构） | #2/#3（minimal 全握手） | 已映射；**现网抓包级确认** → G-AMQP-1（确认方式：抓 client-broker 回环包核对 frame 面） |
| 2 | 发布消息（basic.publish→HEADER→BODY，properties/BodySize） | 现网通用形态 | #6/#7（单 body/分段） | 已映射；确认 → G-AMQP-1 |
| 3 | 消费消息（consume→deliver→HEADER→BODY→ack，tag 关联） | 现网通用形态 | #8 | 已映射 |
| 4 | 声明拓扑（exchange.declare/queue.declare + ok） | 现网通用形态 | #5 | 已映射 |
| 5 | 多 channel 复用 + 心跳保活（channel 0 heartbeat） | RabbitMQ 常用形态 | #4/#11/#14 | 已映射；周期心跳调度 → 明确不支持（§12.1 #6） |
| 6 | 事务/发布确认（tx class 90；confirm class 85） | RabbitMQ 扩展 | #10（tx 六方法） | 已映射 tx；**confirm.select 无例 → A′ T-21** |
| 7 | 双连接隔离（两个四元组独立握手/状态） | 现网通用形态 | #12 | 已映射；校验器单连接面 → G-AMQP-2 |
| 8 | IPv6 broker 可达（应用 bytes 不变） | 现网通用形态 | #13 | 已映射 |
| 9 | 脏包/错序/伪造长度拒收（broker/引擎 planar 拒） | 引擎行为（planner 真实锚词行） | #15–#20（6 负例，锚词逐字见 §9） | 已映射 |
| 10 | AMQPS TLS 5671 加密接入 | RabbitMQ TLS 面 | 无例 | **未实现** → G-AMQP-1（tls OptionalOn 面） |

注：本表凡记"现网通用形态"但未落抓包证据的，一律挂 G-AMQP-1 且不写死进实现（§5.5）。

### 13.3 §3 强制展开：五件套（双 profile，TCP 长连接多路复用）

会话表：

| 会话 | profile | 四元组 | 生命周期 |
|---|---|---|---|
| s1 | amqp091_minimal | `ip.src/dst` + `tcp.12345→5672` | TCP 握手（tcp 层）→ protocol header → 六步 connection 握手 → channel.open/close → connection.close → TCP 挥手（`terminates=true`） |
| s2 | amqp091_rabbitmq | 同上；业务 channel 1/2 | 同上 + exchange/queue declare + content 序列 + tx/confirm；heartbeat 事件穿插 |

事务序列（单事务四件事 §3.4–3.7）：

| 事务 | 前置条件 | 触发动作 | 成功分支 | 失败分支 |
|---|---|---|---|---|
| t1 connection 握手 | TCP 已建连（tcp 层承载） | protocol header + start/start-ok/tune/tune-ok/open/open-ok（方向逐方法钉死） | channel.open 可发 | 顺序/方向错 → task error（#17 通道） |
| t2 channel 建立 | t1 open-ok 已收 | channel.open（channel≠0）→ open-ok | exchange/queue/basic 可发 | channel 0/unopened → task error（#18 通道） |
| t3 拓扑声明 | t2 同 channel open | exchange.declare/queue.declare → 各自 ok | basic.publish/consume 可发 | 未开 channel → task error（#18 通道） |
| t4 content 序列 | t3 完成（或直接 t2 后） | basic.publish/deliver → HEADER（class 60/BodySize）→ BODY* | BodySize=body 总长、frame_max 内分段 | 长度不匹配/跨 channel 交错 → task error（#19 通道） |
| t5 心跳/事务扩展 | t1 open 后 | HEARTBEAT（channel 0）/ tx.select/commit/rollback / confirm.select | frame 断言命中 | heartbeat before open → task error（#17 通道） |
| t6 关闭 | 业务完成 | channel.close/close-ok → connection.close/close-ok | close 后只允许 close 族 | 残留业务帧 → task error（#17 通道） |

关联关系（§3.8–3.10 三件事）：本协议**无副流派生数据流**（单 TCP 连接内 channel 多路复用，无 `driven_by` 派生流），但有**同连接内 channel/delivery/consumer 关联**：归属连接 sN（`connections[]` 序）、归属 channel（`channel` 字段）、由 `delivery_tag`/`consumer_tag` 字段决定（#8 的 deliver→ack 同 channel 同 tag 关联）——与 CWMP 范本差异点诚实声明：amqp 无副流，`connections[]` 承载"每连接独立 channel 表/delivery tag/consumer 状态"（本契约 §5）。

插入位置：终结层——amqp 事件字节经 tcp 层包装为 TCP segment（`L4 Protocol tcp`；tcp 层承载握手/MSS 分段/挥手）；IP 无 option 时 TCP payload 起点 54（IPv6 74）。

时间线：**顺序**——同连接内 t1→t2→…→t6 严格事件序（`planner.go` 逐事件 Emit）；连接间（#12 双连接）并发但输出不假设全局包序，只断言流内状态与隔离（`tcp.srcport` distinct）；无"长传输分片让位"独立面（TCP 分段由 tcp 层 MSS 语义承载）；控制可中插动作=heartbeat（channel 0 与业务 channel 复用同一 TCP 流，#11 交织已覆）。§3.12 的调度方式在本协议落点为"事件序逐包 Emit"。

### 13.12 §12 强制展开：动态字段清单

| 字段 | 住处 | 开策略 | 理由 |
|---|---|---|---|
| `src`（src_ip） | ip 层 | fixed/inc/rand/list/pattern 全开 | §12.2 地址必备；多客户端并发锚点 |
| `dst`（dst_ip） | ip 层 | fixed（broker 地址 fixture 钉死；多 broker 地址池待立项） | 单 broker 语义；动态多目标 → G-AMQP-4 |
| `src_port` | tcp 层 | 全开 + 未写动态保底 `12345+i` | §12.2/§2.8；multi_connection 锚点（12345/12346） |
| `dst_port` | tcp 层 | fixed（5672 单档 fixture；5671 未实现→G-AMQP-1） | FieldContract 缺省与显式写同值；动态端口例另议 |
| `profile` | amqp 层 | 不开（两 profile 各自独立模板） | profile 切换 = 换策略（§2.5），不用动态冒充 |
| `frame_max`/`channel_max`/`heartbeat` | amqp 层 | 不开（协商参数 fixture 钉死） | 协商语义值，非按流变化量；变体靠多策略 |
| `connections`/`events` | amqp 层 | 不开（扇出结构静态声明） | 多连接/多事件靠显式声明（§3.1），与动态正交 |
| `class_id`/`method_id`/`channel`/`arguments`/`properties`/`body` | amqp 层 events[] | 不开（fixture 钉死字节） | 消息变体靠多事件/多策略（§2.5），不用动态冒充 |

序号算法代码位置：四元组逐流序号走**层链动态解析（框架面）**——`internal/core/layer_dyn.go` 的 `resolveLayerTuple :770` 按流序号 i 求值，ip 面 `ResolveIPValue`（`tuple_generator.go:290`）、tcp 端口面 `ResolvePortValue`（`tuple_generator.go:300`）；amqp 层无专属序号算法，业务字段（profile/frame_max/channel_max/heartbeat/connections/events 面）逐行"不开"（本表），故无业务序号算法可指（§5.7 诚实声明，不编行号）。

### 13-P2 presence 负例形状（链级红例必含①）

层链+顶层空子映射并存=判死负例（presence 负例形状，非残留）：`{"layers":[{"ip":{}},{"tcp":{}},{"amqp":{}}],"amqp":{}}`（顶层空 `amqp:{}` 与层链并存）必须 planner/validator 拒，`error_contains` 含 `presence` 或顶层键锚词；P4 链级红例必含此形。白名单外游离键（如顶层 `src_mac`/`ttl`）判死负例见 §14。**另注**：amqp 单 TCP 载体 → 链中夹 `udp` 层（`[ip,udp,amqp]`）判死负例（`carrier` 锚词，bacnet `bacnet_neg_carrier_tcp` 同构——载体族错不属 `DependsOn`）；链缺 `tcp`（`[ip,amqp]` 直连）判死负例（`carrier` 锚词）。P4 链级红例共 4 例 + 收官自查行「非负例顶层键=0」。

## 14. D-AMQP-1 P2 代码设计草稿（CORE_MEMORY §8 八要素；门1 获批=定稿）

> 体裁：文件清单/接口签名/数据结构/主流程/错误分支/性能设计与验收/回滚方式。amqp wire 面已落码（f59509c），D-AMQP-1 覆盖"已落码对接 + P4 层链整形差量"，不重发明 wire。

**文件清单（已落码 3 + P4 新建 1 + 接线/守卫 3，已落码行号实测）**：

| 文件 | 职责 |
|---|---|
| internal/protocol/amqp/builder.go（已落码，762 行） | wire 纯函数：常量（`:11-27` frame type/end/headerLen、`:31-37` class、`:39-67` method）/`buildProtocolHeader`（`:75`）/`buildMethodFrame`（`:80`）/`buildHeaderFrame`（`:92`）/`buildBodyFrame`（`:110`）/`buildHeartbeatFrame`（`:116`）/`buildFrame`（`:122`）/`encodeShortstr`（`:134-141`）/`encodeLongstr`（`:145`）/`encodeFieldTable`（`:159`）/`encodeMethodArguments`（`:229`，序表 `methodArgOrder :525`）/`encodeProperties`（`:637`）/`resolveBody`（`:703`）/`splitBody`（`:725-749`） |
| internal/protocol/amqp/planner.go（已落码，462 行） | `AMQPGenerator.Generate`（`:20-134`：全连接扫 `:37`、body 分段 `:88-106`、channel 状态跟踪 `:116-126`）/`validateAMQPConfig`（`:145-429`：wire_fault `:151-153`、profile `:155-157`、connections 必填 `:159-161`、frame_max≥8 `:171-173`、**仅 Connections[0]** `:174`、状态机 `:196-417`）/`validateWireFault`（`:432-455` 9 值）/注册（`:457-462`） |
| internal/core/types.go（已落码） | `AMQPConfig`（`:286-297` 6 键）+ `AMQPConnection`（`:299-308` 5 键）+ `AMQPEvent`（`:310-330` 11 键）+ `FlowSpec.AMQP`（`:1706`） |
| internal/protocol/amqp/amqp_test.go（已落码；P6 后 774 行） | 单元测试 30 个（P4 复用 + P6 补 7 条守卫分支测试，不改实现口径） |
| internal/protocol/amqp/casegen_test.go（P4 NEW） | 一次性生成器：20 例（14 正+6 负）+ 4 链级红例契约计数逐例 add()，落 test/protocol_pcap/cases/amqp.json（层链整形后形状） |
| 接线件（已落码，P4 只验证） | registry `registry.go:486-497`（`DependsOn ["tcp"]` + FieldContract 5672 + Fields 6 键）；`chain_planner.go:596-604` FieldContract 端口通用块；`strategy_convert.go:636-638` 子配置解析；`chain_planner_translate.go:157` + `generator.go:389` Meta 直传；`validate.go:101` TCP MSS 共用校验；`protocols.go:22` 白名单 + `protocols_test.go:20` 同步；schemagen 重跑验证无过期 |
| P4 新增守卫 | validate_layers 预检：presence（层链+顶层空子映射并存拒）/白名单外游离键拒/链夹 udp 拒/缺 tcp 拒（单载体，无 OptionalOn 面——TLS 面 → G-AMQP-1 另议，不在本轮守卫） |
| tools/coverage_gate.py | check_amqp（准入接线/关键件/守卫/用例面四段，P4 登记——当前 grep 计 0，出口 2 视红） |

**接口签名**（已落码，P4 落码钉死有无差量）：`buildProtocolHeader() []byte` / `buildMethodFrame(channel uint16, classID, methodID uint16, payload []byte) []byte` / `buildHeaderFrame(channel, classID uint16, bodySize uint64, props map[string]any, override *uint64) ([]byte, error)` / `buildBodyFrame(channel uint16, body []byte) []byte` / `buildHeartbeatFrame() []byte` / `encodeMethodArguments(classID, methodID uint16, args map[string]any) ([]byte, error)` / `validateAMQPConfig(spec *core.FlowSpec) error` / `AMQPGenerator.Generate(ctx, req) error`。

**数据结构**：沿 `AMQPConfig`（`types.go:286` 6 键：profile/frame_max/channel_max/heartbeat/connections/wire_fault）+ 层链目标形状（§13.1 样例：地址住 `ip`、端口住 `tcp`、业务住 `amqp` 条目、数量走 `flow_control`）。

**主流程**：validateSpec（含 P4 新增 4 守卫）→ 逐连接逐事件渲染（protocol_header/method/header/body/heartbeat 五 builder 分支，body 超限 `splitBody` 拆帧）→ EmitMsg → worker → pcap/NIC。

**错误分支（§5.2）**：①`wire_fault` 9 值注入拒（`validateWireFault`，锚词进断言，值面=§9 表逐字：`protocol`/`frame`/`handshake`/`channel`/`body`/`session` + shortstr/frame end/size overflow）；②自然守卫：未知 profile（`:155`）/connections 空（`:159`）/frame_max<8（`:171`）/未知 kind（`:414`）/未知 method（`:356`）/direction 非法（`:214-219`）/状态机违例（`:196-417` 全序）；③validate_layers 预检同步拒（presence/白名单/udp 载体/缺 tcp）。全部传播为 task error，零假成功。

**依赖声明（§5.1）**：依赖 `tcp` 层（唯一载体：握手/MSS/挥手/端口）；依赖 `ip` 层（寻址，IPv6 地址同层）；无 `udp` 依赖（§13-P2 把此列成守卫）；无外部 broker 依赖。**不含 TLS 依赖**（AMQPS 面 → G-AMQP-1）。

**性能设计与验收（§6.1–6.8）**：O(n) 流式——逐事件渲染直发 EmitMsg 无全量聚合（`Generate` for 循环直发，`planner.go:44-130`；body 分段即时 Emit `:88-106`）；确定性内存（单事件最大=单 BODY frame，fixture 级字节；`splitBody` 分片不聚合）；无锁无 sleep（事件驱动，无心跳定时器——周期调度显式不支持）；pcap 路实测 + NIC 路注记（过滤器 `tcp port 5672`，测试网口按 testing-interface 记忆）；回归口径=amqp.json 全量 suite 耗时 ±10%；六类场景（基线/目标规模/压力上限/长运行时/并发交错/背压）P5 跑测覆盖；边界诚实声明：吞吐/并发/内存目标数字待 P4 基准后定（§6.5，不写承诺）。

**与现有逻辑冲突点（§8.7）**：①端口 5672 双通道并存（strategy_convert `:636-638` 覆盖式 + FieldContract 通用块 `chain_planner.go:596-604` 契约式）——fixture 显式写 5672 时两通道均不生效，P4 改写保持显式值合规；②校验器只扫 `Connections[0]`（`:174`）与生成器全连接扫（`:37`）不对偶——P4 不缩生成器，校验缺口挂 G-AMQP-2；③`parseSubconfigJSON` 普通 `json.Unmarshal` 无 `DisallowUnknownFields`（`strategy_convert_helpers.go:21-30`）——amqp 子映射未知键静默忽略，负例不得依赖未知键拒绝（G-AMQP-4）；schemagen 生成表已含 amqp（fields 6 键），P4 只验证无过期（`TestLayersGeneratedMatchesRegistry`）。

**回滚方式（§8.8）**：P4 差量全量 revert（casegen + 20 例改写 + 4 守卫 + coverage 登记）；已落码 wire 面不动；无数据迁移面。

## 15. P3 测试对接清单与缺口立项（T-AMQP 草稿输入；正文落 testcase 文件）

- §3.15 三项：①同连接多事务序列（握手→拓扑→content→ack→close 完整编排）→#3/#5/#6/#8 已覆（含 #10 tx 六方法多轮）；②非正常结束→6 负例全覆（#15–#20）+ wire_fault 通道；③长保活→heartbeat 事件 #4/#11/#14 已覆（显式事件面）；**周期自动心跳调度明确不支持**（§12.1 #6，声明式回放族）。逐项一例或立项，无空项（明细见 testcase §9.1）。
- A′/B′ 两分类表：见 testcase §9.2（A′=引擎可构建→20 ID 内已覆 + A′ 补例建议 T-20（shortstr 255/256 边界）/T-21（confirm.select 85/10）；B′=引擎结构缺口→G-AMQP-2 进 D-条目"明确不解决+迁入计划"）。
- 9.52 对账两行：见 testcase §9.3（清单出处声明 + 对账两行：总数 50 = 已覆 30 + B′/A′ 12 + 不适用 8）。
- 3.14 豁免边界审计：见 testcase §9.4（本协议单 TCP 连接但**不主张任何豁免**：多连接 #12 已覆；单连接多 channel #11 已覆；多事务 #3–#10 已覆）。
- 三源回指行：见 testcase §9.5（第三源"已确认现网行为"当前=未确认级，挂 G-AMQP-1）。
- 断言通道：fields 用 `amqp.*`（去重 8 已实证 8/8 命中）+ `tcp.dstport`/`ipv6.nxt` 载体面 + frames hex（offset 54/74 两档实测）。

## 16. 缺口立项清单（有缺口写"缺口立项"，不许空着）

| 立项号 | 缺口 | 确认方式（三选一） | 去向 |
|---|---|---|---|
| G-AMQP-1 | 现网证据升级 + RFC 精确章节复核：RabbitMQ broker 行为（tune 协商值策略、1.0/0-9-1 同端口共存、心跳超时执行）的"已确认现网"级证据；0-9-1 规范精确章节号；**AMQPS/TLS 5671 载体**（tls OptionalOn 接线 + `amqp091_tls_boundary` profile 落地） | 抓包（抓 client-broker 回环包核对 frame 面）+ 查 0-9-1 规范原文 + RabbitMQ 官方文档 | P4 前置确认项，不挡开工；TLS 面 P4 后另轮；确认前相关条目按 §5.5"待确认"不写死 |
| G-AMQP-2 | B′ 行为面：**validateAMQPConfig 只扫 Connections[0]**（`planner.go:174`），第 2+ 连接事件不校验（生成器 `:37` 全连接扫，校验/生成不对偶）；multi_connection 例 notes 声称 `tcp.srcport distinct` 断言但存量 fields 未实际断言（P5 补钉）；多连接四元组独立流 vs 同流声明形状裁定 | 读 planner.go/builder.go 现状 + lane 实测多连接 spec | B′→D-AMQP-1"明确不解决+迁入计划"或 P4 小改（校验器循环化，属协议本地文件，车道内可改）；断言补钉归 P5 |
| G-AMQP-3 | A′ 补例 + 未断言面：T-20（shortstr 255 合法/256 拒——`encodeShortstr` 已实现无用例）、T-21（confirm.select 85/10——builder/planner 已支持无用例）；**方法取值枚举缺口（P6 m3 并入）**：`basic.get-ok`（60/71）、`basic.cancel`（60/30）、`basic.cancel-ok`（60/31）三值 builder 常量在册（`builder.go:57/:58/:61`）但 24 例零出现，未登记则违反 9.47/9.20"取值表逐值有去向"；`channel_max`/`heartbeat` 配置键无用例钉（tune 参数面 `builder.go:540-542`）；wire_fault 未用值 5 个（shortstr_overflow/bad_frame_end/frame_size_overflow/channel_state/body_length）；properties 14 项全集子面 | 读 builder 常量 + 引擎负例实测 | A′ 补例并入与否由主线程定，不影响 §10 的 20 ID 权威口径；wire_fault 余值随 P4/P5 补 |
| G-AMQP-4 | 严格解码守卫：`amqp` 子映射未知键当前静默忽略（`parseSubconfigJSON` 普通 `json.Unmarshal`，`strategy_convert_helpers.go:21-30`），按 13.26 口径未知键应显式拒绝 | 读 `strategy_convert_helpers.go` 现状 + 引擎负例实测 | P4 评估是否框架级统一加 `DisallowUnknownFields`（属跨协议共享面，须上报主线程，不车道自改） |

## 17. P1/P2/P3 对抗自重审结论（10.11；过 4 轮，末轮干净）

- **P1（§12 矩阵）**：R1 自重审发现 §12.2 逐格重数初稿 9+10+8+1=28 有双计（R3c3 同时记缺口与不适用）→ 改 8+11+8+1=28 复算一致（**P6 n8 再修**：四桶改 **7+10+10+1=28** 严格互斥——R3c3 只归不适用、R6c1 只归 A′ 桶，见 §12.2 注）；R2 逐行核八项矩阵的"代码现状"列行号全部实读源文件（builder/planner/types/validate/chain_planner_translate/strategy_convert），v1 底稿"层尚未注册"过期声明按 registry.go:486 实测改正；R3 锚词 9 值逐字对 planner.go:432-455；**R4 终扫发现 §4.1 表体未随勘误改正（ack=60/publish=80 旧值残留，与勘误注记自相矛盾）→ 表体改 40/70/71/72/80 逐值对 builder.go:60-64 复验一致**，同轮 §1 标题与 §10 完成定义去占位残留。末轮干净。
- **P2（§14 D-条目）**：R1 自审发现初稿写"builder 1224 行"为 builder+planner 合计口径错误 → 按 `wc -l` 实测拆分（builder 762 + planner 462 + test 678）；R2 补落 `parseSubconfigJSON` 无 `DisallowUnknownFields` 边界与 confirm.select 无用例两处；R3 末轮干净。
- **P3（testcase §9 + §15/§16）**：R1 自审发现 9.52 对账两行初稿"总数 46"与矩阵 50 格/行对不上 → 改为 8+28+14=50 点、30+12+8=50 两行对账并加粒度声明；R2 核 §15 断言通道 9 字段逐个对 tshark 注册表（9/9 精确命中）、锚词 6 个逐字对 planner.go 真实字符串（`protocol`/`frame`/`handshake`/`channel`/`body`/`session`）；R3 末轮干净。

三阶段合计修正 9 处（1 处算术、1 处表体+勘误一致性、1 处标题过期、1 处完成定义残留、1 处行数口径、1 处解码边界+用例缺口、1 处对账口径、2 处缺口浮出落立项），末轮均干净。

### 17.1 文档逐条自核对结论（10.1：对规范逐条核对）

- AMQP 0-9-1 规范（frame 布局 §4.2 级引用：type/channel/size/end、shortstr 255、properties flags、BodySize、frame_max、heartbeat 8 字节）→ 本契约 §3/§4 逐条有落点；class/method 表（connection 10/channel 20/exchange 40/queue 50/basic 60/confirm 85/tx 90）→ §4.1 表与 builder 常量逐值一致；精确章节号挂 G-AMQP-1（§5.5 不写死）。
- 与旧需求文档（v1.0.0 design/testcase）逐条核对（10.2）：20 ID 集合、顺序、正负比全部保持；§4.1 method ID 勘误（basic.ack 60→80、basic.publish 80→40、basic.get 40→70、get-ok 50→71、get-empty 60→72）按 builder 常量 + 存量用例双证据改正；§1 从"未注册"改写为"已注册已落码"（注册行号实测）；其余契约（frame 布局、握手状态机、负例锚词、IPv6/多连接/多 channel 边界）无删改。

### 17.2 与旧文档逐条核对结论（10.2）

v1.0.0 §1–§11 逐条：§1 范围（保留+扩，profile 表不动，"未注册"段按实测改写）、§2 载体表（保留，补 FieldContract/端口缺省双通道）、§3 frame 布局（保留）、§4 编码（保留+勘误 method ID 表）、§5 状态机（保留）、§6 exchange/queue/basic 语义（保留）、§7 边界（保留）、§8 typedef（保留，按 types.go 实测对齐）、§9 错误表（保留，锚词实测化）、§10 ID 表（20 ID 逐条保留+实测注记）、§11 修订记录（追加 v2.0.0）。无旧条目被静默删除。
