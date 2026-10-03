# AMS（Apache ActiveMQ 管理协议，ActiveMQ Management Service）设计契约

> 版本：v1.2.1（按 CORE 对齐）
> 日期：2026-10-01
> 状态：AMS 层、生成器和验证器已注册；本轮只做文档/用例静态核对与文档校正，未运行 suite、Go 测试或服务器。当前链式配置尚缺 `translateTerminalConfig` 的 AMS 层配置翻译分支，且自驱路径仍消费 `connections[].src_ip/dst_ip/src_port` 作为 TCP 承载配置；两项分别列为 AMS-G7、AMS-G5，不伪称严格层链已可执行。
> 配套文件：`docs/protocols/ams/testcase.md`、`trafficgen/test/protocol_pcap/cases/ams.json`
> 规范基线：Apache ActiveMQ 管理会话抽象、TCP（传输控制协议）可靠字节流和本项目 AMS wire profile（线上档案）。

## D1 范围、profile 和实现边界

本版定义 AMS 管理客户端与 ActiveMQ 管理端之间的确定性 TCP 帧序列，覆盖连接握手、认证、管理会话、命令/响应、事件消息、确认、心跳、关闭，以及 IPv4/IPv6、多会话、多流和长度边界。AMS 是本项目对 ActiveMQ 管理承载的独立协议层契约，不把 OpenWire（ActiveMQ 原生消息协议）、AMQP（高级消息队列协议）、JMX/RMI 或 Jolokia/HTTP（基于 HTTP 的管理接口）静默当作 AMS。

| profile（协议档案） | 规范范围 | 本版允许内容 | 不从 profile 推导 |
|---|---|---|---|
| `ams_management_v1` | TCP 管理控制面 | hello/auth/session、命令响应、事件消息、确认、ping/pong | broker（消息代理）实际状态或自动命令 |
| `ams_observer_v1` | 只读观察会话 | hello/auth、subscribe、event、ack、close | 写操作、隐式订阅和事件重放 |
| `ams_tls_boundary` | TLS（传输层安全）外层边界 | 仅未来定义 TLS/TCP 载体 | 未解密时不声称看见 AMS frame（帧）字段 |

当前仓库已注册 `ams` layer、planner、validator 和生成器；`cases/ams.json` 的 20 个条目均为语义用例，20/20 的 `spec_json` 形状是 `[ip,tcp,ams]`，但这只是静态层链形状，不等于 suite/PCAP/NIC 已验证。需要特别区分：`connections[]` 内的地址/端口不是 AMS 业务 TLV，而是当前自驱生成器读取的连接级 TCP 承载配置；18 条含 `connections[]` 的用例重复 `connections[].src_port` 与外层 `tcp.src_port`，`ams_multi_stream` 和 `ams_ipv4_ipv6_same_payload` 还依赖连接级源端口，后者另有嵌套 IPv6 地址。因此该字段组与外层 `ip`/`tcp` 重复，违反 CORE §1.1/§1.2 的唯一归属，属于 AMS-G5 代码阻塞。完成 AMS-G5 前不得把这些配置当作严格层链唯一真相。

## D2 协议栈、端口和固定偏移

推荐层链为 `[ip, tcp, ams]`。AMS 只使用 TCP 明文承载；UDP、裸 IP、HTTP、OpenWire 和 AMQP 不得静默转换为本版载体。兼容 profile 的默认 TCP destination port（目的端口）为 61616，源端口由 fixture（固定样本）显式给出；实现若使用独立管理端口，必须通过 `port` 显式配置，不能在 planner（规划器）中悄然改写。

无 VLAN（虚拟局域网）、无 IP options（IP 选项）和无 TCP options 时：

| 载体 | TCP payload（载荷）起点 | 用途 |
|---|---:|---|
| TCP/IPv4 | 54 = Ethernet 14 + IPv4 20 + TCP 20 | AMS 首帧和后续 frame |
| TCP/IPv6 | 74 = 14 + IPv6 40 + TCP 20 | 相同 AMS 字节语义 |

TCP segment（分段）边界不是 AMS frame 边界。实现必须按 Length 重组完整 frame；一帧跨 MSS（最大报文段长度）时，先重组 TCP stream（字节流）再验证长度、字段和尾标记。PCAP 的 `frames` offset 只固定无 options 的稳定 fixture，不把一个 TCP 包等同于一个 AMS frame。

## D3 Frame 总体布局

每个 AMS frame 使用 network byte order（网络字节序，大端序）：

```text
Length(4) | Version(1) | Type(1) | Flags(2) | SessionID(4) |
CorrelationID(8) | Payload(N) | FrameEnd(2)
```

`Length` 是从 `Version` 到 `FrameEnd` 的总字节数，即 `18 + N`，不包含自身 4 字节；最小 frame 长度为 18。`FrameEnd` 固定为 `ae 5a`。`Version=1` 为本版唯一合法版本。`Flags` 的 bit 0 表示 request（请求），bit 1 表示 response（响应），bit 2 表示 ack-required（要求确认），其余位必须为零，除非 profile 显式声明。

| Type | 值 | 方向/语义 |
|---|---:|---|
| `HELLO` | `0x01` | client→server，协议协商 |
| `HELLO_OK` | `0x02` | server→client，协商结果 |
| `AUTH` | `0x03` | client→server，认证凭据引用 |
| `AUTH_OK` | `0x04` | server→client，认证结果 |
| `OPEN_SESSION` | `0x05` | client→server，建立管理会话 |
| `OPEN_OK` | `0x06` | server→client，会话参数 |
| `CLOSE_SESSION` | `0x07` | 任一方向，关闭会话 |
| `CLOSE_OK` | `0x08` | 对端响应关闭 |
| `MESSAGE` | `0x10` | 任一方向，管理事件或消息 |
| `MESSAGE_ACK` | `0x11` | 对端确认 MESSAGE |
| `COMMAND` | `0x20` | client→server，管理命令 |
| `RESPONSE` | `0x21` | server→client，命令结果 |
| `ERROR` | `0x7f` | 任一方向，显式错误 |
| `PING` | `0x30` | 任一方向，保活请求 |
| `PONG` | `0x31` | 对端响应保活 |

未知 Type、Version 不支持、保留 Flags 非零、Length 小于 18、Length 越过 TCP stream 或 FrameEnd 非 `ae 5a` 必须拒绝。Length 不能通过 uint32 回绕；实现不得按 Length 直接分配未受限的内存。

## D4 Payload、字段和确认语义

Payload 由零个或多个 TLV（类型-长度-值）字段组成：

```text
FieldID(2) | FieldLength(2) | Value(FieldLength)
```

`FieldLength` 只计算 Value；字段必须完整落在 Payload 内。重复字段按 profile 处理，未声明的必填字段、同一字段冲突值和超出 frame_max 的字段必须报错。以下字段 ID 是本版稳定观察面：

| FieldID | 名称 | 编码 |
|---:|---|---|
| `0x0001` | client_name | UTF-8 bytes |
| `0x0002` | profile | UTF-8 bytes |
| `0x0003` | capability | UTF-8 bytes |
| `0x0004` | auth_method | UTF-8 bytes |
| `0x0005` | credential_ref | UTF-8 bytes；不在线发送明文密码 |
| `0x0010` | session_name | UTF-8 bytes |
| `0x0011` | session_limit | uint16 |
| `0x0012` | heartbeat | uint16 seconds |
| `0x0020` | command | UTF-8 bytes |
| `0x0021` | resource | UTF-8 bytes |
| `0x0022` | body | opaque bytes |
| `0x0023` | status | uint16 |
| `0x0030` | message_id | uint64 |
| `0x0031` | message_kind | UTF-8 bytes |
| `0x0032` | delivery_mode | uint8 |
| `0x0033` | sequence | uint64 |
| `0x0034` | payload | opaque bytes |
| `0x0040` | ack_for | uint64 |
| `0x0041` | ack_status | uint16 |
| `0x0042` | ack_range_end | uint64 |
| `0x00f0` | error_code | uint16 |
| `0x00f1` | error_text | UTF-8 bytes |

`HELLO` 必须带 `client_name` 和 `profile`；`HELLO_OK` 必须回显协商 profile 并给出 `heartbeat` 和 `session_limit`。`AUTH` 只能携带认证方式和 credential reference，不能把密码或 token（令牌）明文写入 fixture；`AUTH_OK` 必须在 `OPEN_SESSION` 前出现。`OPEN_SESSION` 建立由 `SessionID` 标识的会话，`OPEN_OK` 返回成功状态和服务端限制。

`COMMAND` 的 `CorrelationID` 必须非零并在同一 session 内唯一；对应 `RESPONSE` 使用相同 `CorrelationID`、相同 SessionID 和明确 `status`。命令不得因为没有响应而自动生成成功结果。`MESSAGE` 的 `message_id` 和 `sequence` 必须在同一 session/stream 内可关联；带 `ack-required` 的消息必须收到同一 session 的 `MESSAGE_ACK`，且 `ack_for` 等于消息 ID。重复 ACK、跨 session ACK、确认未发送消息、ACK 范围倒退必须拒绝。

## D5 握手、会话和流状态机

推荐的单连接序列：

```text
TCP SYN/SYN-ACK/ACK
  → HELLO
  ← HELLO_OK
  → AUTH
  ← AUTH_OK
  → OPEN_SESSION
  ← OPEN_OK
  → COMMAND / MESSAGE / PING
  ← RESPONSE / MESSAGE_ACK / PONG
  → CLOSE_SESSION
  ← CLOSE_OK
  → TCP FIN/ACK
```

状态不变式：

| 状态 | 允许事件 | 必须保持 |
|---|---|---|
| `TransportReady` | HELLO | 首个 AMS bytes 必须是合法首帧 |
| `Negotiating` | HELLO_OK、AUTH、AUTH_OK | 版本/profile/方向和协商值一致 |
| `Authenticated` | OPEN_SESSION | AUTH_OK 后才能打开 session |
| `SessionOpen` | COMMAND、RESPONSE、MESSAGE、MESSAGE_ACK、PING/PONG | SessionID 非零且会话未关闭 |
| `AwaitingResponse` | RESPONSE、ERROR | CorrelationID 与未完成 COMMAND 对应 |
| `AwaitingAck` | MESSAGE_ACK、ERROR | ack_for 属于同一 session/stream |
| `Closing` | CLOSE_SESSION、CLOSE_OK | 关闭后不得产生新 command/message |
| `Error` | malformed frame、顺序/长度/状态错误 | planner→engine→task error，不能 completed/0 packet |

一个 TCP 连接可以承载多个 SessionID，但每个 session 的 profile、CorrelationID、message sequence、ack 状态和关闭状态独立。`stream_id` 不是 TCP packet index；本版以 `(TCP stream, SessionID)` 作为逻辑流键。多 TCP 连接必须使用独立四元组，并且不能共享 session、message 或 correlation 状态。跨 TCP stream 的同一 SessionID 默认非法，除非未来 profile 显式声明迁移语义。

## D6 命令、消息和生命周期

`COMMAND` 至少带 `command` 和 `resource`；`body` 可选。推荐命令包括 `broker.info`、`connection.list`、`session.list`、`queue.inspect`、`consumer.list` 和 `subscription.list`。本版只编码显式命令，不模拟 broker 实际查询结果。未知 command、空 resource（对该命令必填时）和超出 profile 权限的写操作必须产生 `ERROR` 或 planner error，不能静默成功。

`MESSAGE` 用于管理事件通知或显式结果推送，至少带 `message_id`、`message_kind`、`sequence` 和 `payload`。消息 payload 可为 UTF-8 JSON（JavaScript Object Notation，JavaScript 对象表示法）或 opaque bytes，但编码必须由 profile 显式给出；不能把 JSON 文本和长度字段混淆。`delivery_mode=0` 表示 at-most-once（至多一次），`delivery_mode=1` 表示 ack-required；只有 mode=1 才要求 MESSAGE_ACK。重传必须复用 message_id 和 sequence，不得伪造新消息。

`PING`/`PONG` 只能在 session open 后出现；heartbeat 为零表示禁用自动保活，不能因 TCP keepalive 自动插入 AMS frame。`CLOSE_SESSION` 必须带合法 SessionID；CLOSE_OK 后不再允许 command、message、ack 或 ping。

## D7 IPv4/IPv6、多会话、多流和边界

IPv4 outer EtherType 为 `0x0800`；IPv6 outer EtherType 为 `0x86dd`，TCP Next Header 为 6。相同 AMS fixture 在 IPv4/IPv6 中 Version、Type、Flags、SessionID、CorrelationID、TLV 和 FrameEnd 必须一致，仅外层地址族与 payload offset 改变。

多会话场景至少建立两个 SessionID，并分别执行一条 command 和一条 message；验证使用 SessionID、CorrelationID、message_id 和 TCP stream 关联，不硬编码跨流 packet index。多流场景至少使用两个 TCP 四元组；每流独立完成 HELLO/AUTH/OPEN_SESSION，禁止把一个连接的 AUTH_OK 或 OPEN_OK 配给另一连接。

边界至少覆盖：空 payload 的 PING/PONG、Length=18 最小 frame、最大允许 frame、TLV length=0、最大受支持字段长度、uint16 session_limit 上界、uint64 correlation/message/sequence 边界、空 command/resource、重复 ACK、MSS 分段和 Body 跨 TCP segment。实现必须在长度加法、TLV 游标前进、sequence/ack 范围和 frame_max 检查中拒绝溢出，不得回绕或分配 `0xffffffff` bytes。

## D8 配置 typedef（类型定义）

以下是设计契约，不是当前存在的 Go struct（结构体）：

```go
type AMSConfig struct {
    Profile      string          `json:"profile"`
    FrameMax     uint32          `json:"frame_max"`
    Heartbeat    uint16          `json:"heartbeat"`
    Connections  []AMSConnection `json:"connections"`
    WireFault    string          `json:"wire_fault"` // 仅负例
}

type AMSConnection struct {
    SrcIP, DstIP string       `json:"src_ip"`
    SrcPort, DstPort uint16  `json:"src_port"`
    Sessions    []AMSSession `json:"sessions"`
}

type AMSSession struct {
    SessionID uint32     `json:"session_id"`
    Events    []AMSEvent `json:"events"`
}

type AMSEvent struct {
    Kind          string            `json:"kind"`
    Direction     string            `json:"direction"`
    Type          uint8             `json:"type"`
    Flags         uint16            `json:"flags"`
    CorrelationID uint64            `json:"correlation_id"`
    MessageID     uint64            `json:"message_id"`
    Sequence      uint64            `json:"sequence"`
    AckFor        uint64            `json:"ack_for"`
    Command       string            `json:"command"`
    Resource      string            `json:"resource"`
    Payload       []byte            `json:"payload"`
}
```

Validate 必须覆盖 profile、TCP carrier/port、首帧、Version/Type/Flags/Length/FrameEnd、TLV 边界、握手方向、SessionID、CorrelationID、message/ack 关联、多个连接/会话/流和 wire fault。`wire_fault` 只能注入失败，不得作为线上字段或被忽略。

## 附录 A 错误处理（含原子 ID 与完成定义）

| 错误 | 稳定错误锚点 |
|---|---|
| 首帧缺失、版本错误或 profile 不一致 | `hello` / `version` / `profile` |
| Type、Flags、Length、FrameEnd 非法 | `frame` / `length` / `frame end` |
| TLV 截断、字段长度越界或必填字段缺失 | `field` / `tlv` / `length` |
| AUTH/OPEN_SESSION 顺序或方向错误 | `handshake` / `auth` / `session` |
| session 未打开、跨连接或关闭后引用 | `session` / `connection` |
| CorrelationID 无对应 command 或响应重复 | `correlation` / `response` |
| message/sequence/ack 不一致或跨流引用 | `message` / `sequence` / `ack` |
| 非 TCP、错误端口或地址族配置 | `tcp` / `port` / `address` |

实现已注册 `ams` 为 Category=Terminal、DependsOn=`tcp`；复用 TCP MSS/checksum 和 IPv4/IPv6 builder；以 TCP stream 重组后按 Length 解析，不能按 TCP packet 边界切 frame。所有 planner/validator 错误须传播为 task error。

### D9.1 原子 ID 与完成定义

设计、testcase 和 JSON 必须按以下同一顺序使用 20 个唯一语义 ID：14 个正例、6 个负例。静态审计确认唯一 ID=20、层链形状 20/20 为 `[ip,tcp,ams]`；18 条含 `connections[]` 的配置有连接级 `src_port`，与外层 `tcp.src_port` 重复，且多流/双栈例保留生成器所需连接级值（AMS-G5）。本轮不宣称 suite、PCAP 或 NIC 通过。

| # | ID | 类型 | 覆盖 |
|---:|---|---|---|
| 1 | `ams_frame_header_ipv4` | 正 | TCP/IPv4、Length/Version/Type/Flags/Session |
| 2 | `ams_handshake_auth` | 正 | HELLO/HELLO_OK/AUTH/AUTH_OK |
| 3 | `ams_session_open_close` | 正 | OPEN_SESSION/OPEN_OK/CLOSE/CLOSE_OK |
| 4 | `ams_command_response` | 正 | command/resource/correlation/response |
| 5 | `ams_message_ack` | 正 | message/sequence/ack_for/ack_status |
| 6 | `ams_event_retransmission` | 正 | 相同 message_id/sequence 的显式重传 |
| 7 | `ams_ping_pong` | 正 | session 内保活和终止 |
| 8 | `ams_multi_session` | 正 | 单 TCP 多 SessionID 状态隔离 |
| 9 | `ams_multi_stream` | 正 | 两个 TCP stream、握手和状态隔离 |
| 10 | `ams_ipv6` | 正 | IPv6/TCP、Next Header=6、应用 bytes 不变 |
| 11 | `ams_ipv4_ipv6_same_payload` | 正 | 两个地址族 fixture 的 payload 一致 |
| 12 | `ams_tlv_and_binary_payload` | 正 | TLV 边界和 binary payload |
| 13 | `ams_mss_frame_reassembly` | 正 | TCP MSS 分段后的 frame 重组 |
| 14 | `ams_frame_boundary` | 正 | 最小/最大 Length、空字段和序列边界 |
| 15 | `ams_neg_frame_encoding` | 负 | Version/Type/Flags/Length/FrameEnd 错误 |
| 16 | `ams_neg_handshake_state` | 负 | 首帧、方向或 AUTH/OPEN 顺序错误 |
| 17 | `ams_neg_session_reference` | 负 | 未打开、已关闭或跨连接 SessionID |
| 18 | `ams_neg_correlation_response` | 负 | 响应缺失/重复/未知 CorrelationID |
| 19 | `ams_neg_message_ack` | 负 | 跨流、未知 message、sequence/ACK 范围错误 |
| 20 | `ams_neg_tlv_length` | 负 | TLV 截断、字段长度或长度加法溢出 |

完成定义：注册 `tcp→ams` 层链；逐字节生成 AMS frame 和 TLV；握手、认证、会话、命令/响应、消息/确认和关闭状态可观测；IPv4/IPv6、多会话、多流、MSS 重组和边界均有集成测试；20 个语义 ID 的正负断言和错误传播完成。

## D10 P1 规范矩阵与三路对照

| # | 规范要求 | 业务场景 | 代码现状 | 缺口 |
|---:|---|---|---|---|
| 1 | TCP 长连接、客户端先 HELLO（AMS profile） | 单连接握手与多轮管理 | `layer_gen.go:87-107` 按连接事件流式展开 | 无 |
| 2 | 帧头 Length/Version/Type/Flags/ID | 帧编码与边界 | `builder.go:109-119` 大端编码 | 无 |
| 3 | TLV 字段完整落入 Payload | 命令、消息和二进制体 | `builder.go:98-105` 序列化 | 解析器/线上真实互通待确认 |
| 4 | HELLO→AUTH→OPEN_SESSION 状态顺序 | 会话建立 | `layer_gen.go:318-419` 验证状态 | 无 |
| 5 | COMMAND↔RESPONSE correlation | broker 查询 | `layer_gen.go:423-444` pending/answered | broker 实际返回值不生成 |
| 6 | MESSAGE↔ACK 与 sequence | 事件投递/重传 | `layer_gen.go:445-476` 关联验证 | 无 |
| 7 | PING/PONG、关闭和异常 | 保活、优雅/错误结束 | `layer_gen.go:328-403` | 自动计时保活不生成 |
| 8 | IPv4/IPv6、版本/方言 | 双栈和不同 profile | `layer_gen.go:496-568` profile/端口校验；`generatePackets`（`layer_gen.go:176-285`）自驱双栈 | TLS 内层未解密观察 |

### D10.1 命令×响应码矩阵

| 命令/响应 | 成功 status=0 | 错误/缺失响应 | 用例 |
|---|---|---|---|
| `broker.info` | RESPONSE | correlation 缺失即拒绝 | `ams_command_response` / `ams_neg_correlation_response` |
| `connection.list` | RESPONSE | 跨 session 即拒绝 | `ams_multi_session` / `ams_multi_stream` |
| `queue.inspect` | RESPONSE | 未打开 session 即拒绝 | `ams_neg_session_reference` |
| MESSAGE | MESSAGE_ACK status=0 | 未知 message/sequence 回退拒绝 | `ams_message_ack` / `ams_neg_message_ack` |
| PING | PONG | 未打开 session 即拒绝 | `ams_ping_pong` |

### D10.2 数据形态变体表

| 形态 | 落点 | 状态 |
|---|---|---|
| TCP/IPv4、TCP/IPv6 | `ams_frame_header_ipv4`, `ams_ipv6` | 已覆盖 |
| HELLO/AUTH/OPEN/CLOSE | `ams_handshake_auth`, `ams_session_open_close` | 已覆盖 |
| TLV、空 TLV、二进制 payload | `ams_tlv_and_binary_payload`, `ams_frame_boundary` | 已覆盖 |
| 多会话、多流 | `ams_multi_session`, `ams_multi_stream` | 已覆盖 |
| MSS 跨 segment | `ams_mss_frame_reassembly` | 已覆盖 |
| TLS 外层解密后的 AMS 字段 | 无 | 缺口 AMS-G1：需 TLS 载体与抓包确认后立项 |

### D10.3 商业行为→用例映射

| 行为（来源） | 用例 | 结论 |
|---|---|---|
| ActiveMQ 管理连接上请求/响应 | `ams_command_response` | 仅按本项目 profile 验证，真实 broker 包待确认 |
| 同连接多轮管理操作 | `ams_multi_session`, `ams_ping_pong` | 已覆盖 |
| 事件确认与重传 | `ams_message_ack`, `ams_event_retransmission` | 已覆盖 |
| TLS 管理边界 | 无 | AMS-G1：抓取真实 TLS profile 后确认 |

### D10.4 三路对照与候选方案

规范基线为 ActiveMQ 管理会话抽象与本项目 wire profile；商业行为以 ActiveMQ 5.x/Artemis 管理端抓包确认；开源思路参考 ActiveMQ 客户端的长连接事件序列。三路共同点是 TCP 字节流、请求/响应关联和显式关闭；真实商业字节尚未取得，不能宣称互操作。

| 方案 | 真实走法 | 取舍 | 结论 |
|---|---|---|---|
| A | AMS 作为 `[ip,tcp,ams]` 终结层，TCP 负责握手/MSS | 复用传输层、流式且改动小 | 采用 |
| B | AMS 自驱 `[ip,ams]` 直接生成 TCP 包 | 可控字节，但重复 TCP 状态与分段逻辑 | 否决 |

## D11 依赖、性能与八要素

### D11.1 依赖与错误处理

| 依赖/前置 | 失败返回 | 继续或中断 | 重试/超时 |
|---|---|---|---|
| `ip`→`tcp` 层及 TCP 三次握手 | planner/engine task error，含 `tcp`/`port`/`address` | 中断该流，不产成功 pcap | 不由 AMS 重试；连接超时交 TCP/任务层 |
| HELLO→AUTH→OPEN_SESSION 状态 | validator error，含 `hello`/`handshake`/`auth`/`session` | 中断连接 | 不重试；由调用方重新建流 |
| frame/TLV 长度与 `frame_max` | validator error，含 `frame`/`length`/`tlv`/`field` | 中断连接，禁止大内存分配 | 不重试 |
| command/message 关联 | validator error，含 `correlation`/`response`/`message`/`sequence`/`ack` | 中断对应连接 | 不重试 |
| 层配置翻译 | 当前缺少 AMS 专用 `translateTerminalConfig` 分支，登记 AMS-G7；不是“已可执行层链” | 任务应报配置错误，不能静默回退 | 修复代码后重提任务 |

### D11.2 性能设计与双路验收

代码依据是回调逐帧产出（`layer_gen.go:90-107`），不全量收集；`frame_max` 默认 4096（`builder.go:88`），通用有界队列承接输出，worker 并行度由 packet workers 决定。包/秒、比特/秒、并发连接数和 CPU/内存预算目前没有基准依据，均为 **P5 待确认**，不得写成承诺；单帧边界为 `frame_max`，队列不得无界。

验收必须分两路：

1. **pcap 路**：每个正例经任务创建→生成 pcap→tshark/原始字节检查；断言 packet_count、TCP 端口/方向、Length/FrameEnd、SessionID/CorrelationID/ACK 关系；MSS 例先按 TCP stream 重组再校验 AMS frame。负例断言任务错误且不产成功 pcap。
2. **网卡路**：同一 spec 走 port group，在 `enp135s0f0np0` 抓包；用同一字段/字节断言，并额外断言无丢包、无错误任务和方向正确。未运行，不能宣称通过。

性能清单覆盖：基线单连接、目标 20 例规模、压力上限（frame_max/并发）、长时间保活、并发多流交错、队列满/资源耗尽背压；每项测吞吐、延迟、内存、CPU、队列积压及丢包/失败，而非只看任务状态。

### D11.3 八要素

| 要素 | AMS 定义 |
|---|---|
| 文件 | `internal/protocol/ams/{builder.go,layer_gen.go}`；共享 `types.go:934-1004`、注册 `registry.go:1757-1772`；层翻译缺口为 `chain_planner_translate.go:756+`（AMS-G7） |
| 接口 | `Generate`、`ValidateSpec`、`ValidateConfig`、`BuildEventFrame`；层翻译需补终结层 config→`spec.AMS` |
| 结构 | `AMSConfig→connections→sessions→events`，每连接独立四元组和状态 |
| 流程 | TCP 建连→HELLO/AUTH→OPEN_SESSION→业务→CLOSE；MSS 后先重组 stream |
| 错误 | validator/task error 带稳定锚词；禁止 completed/0 packet 假成功 |
| 性能边界 | `frame_max` 4096 默认、流式回调、有界队列；实测预算 P5 待确认 |
| 冲突点 | 不将 AMS 当 OpenWire/JMX/HTTP；连接嵌套承载键与外层层链冲突为 AMS-G5 |
| 回滚 | 仅回退 AMS 生成器/注册/翻译改动和 AMS cases，不动其他协议；本轮未改 Go |


## D12 动态字段清单

| 字段 | 策略 | 序号算法/代码 | 未开理由 |
|---|---|---|---|
| `ip.src`, `ip.dst` | fixed/inc/rand/list/pattern | 通用 layer dynamic；按 FlowIndex | 无 |
| `tcp.src_port`, `tcp.dst_port` | fixed/inc/rand/list/pattern | 通用 layer dynamic；按 FlowIndex。注意：当前 JSON 18 条 `connections[].src_port` 只是重复固定值，与外层 `tcp.src_port` 同值，未声明任何策略 | 无 |
| `ams.connections[].src_ip/dst_ip` | fixed | `layer_gen.go:180-190`（自驱 `generatePackets` 回退到 `meta.SrcIP/DstIP`） | 嵌套连接地址无独立动态承接，列 AMS-G2 |
| `ams.connections[].src_port/dst_port` | fixed | `layer_gen.go:191-200`（回退到 `meta.SrcPort/meta.DstPort`）；事件路径 emit 仅用 `src_port` 作会话边界（`layer_gen.go:124-128`、`90-107`） | 同上，列 AMS-G2 |
| `session_id`, `correlation_id`, `message_id`, `sequence`, `ack_for` | fixed | `builder.go:111-121` 编码；`layer_gen.go:423-476` 关联校验；业务序列由配置顺序驱动 | 动态业务 ID 尚无策略解析，列 AMS-G3 |
| `command/resource/payload/message_kind` | fixed | `builder.go:241-268` | 模板内容不是自动变体，列 AMS-G3 |
| `connections[].events/sessions[].events` 业务序号 | fixed/list（按配置顺序；尚未开放动态对象） | `layer_gen.go:90-107`、`423-476`；事件索引 `j` 与 `FlowIndex` 不会自动改写业务 ID | 动态业务字段承接列 AMS-G3 |

> **动态整格边界**：当前代码已实现层级四元组动态接口，但 AMS 业务字段及嵌套连接承载字段尚未接入动态解析。故 inc 尾回绕、rand+seed、list 轮转、pattern 替换和静态复制拒绝应在 AMS-G2/G3 修复后逐格立项；本轮不把 fixed 配置重复当作动态覆盖。

## D13 门1 对照表

| CORE | 本协议满足方式 | 证据 |
|---|---|---|
| §1 旧键去向 | 外层 `src_ip/dst_ip`→`layers.ip`、外层 `src_port/dst_port`→`layers.tcp`；`count`→`flow_control`（本文件例无 count）；顶层 `ams`→`layers.ams`。但嵌套连接承载键仍被自驱路径消费，且层配置翻译缺 AMS 分支，严格可执行唯一真相未完成 | `cases/ams.json` 20/20 顶层仅 `layers`、层链 `[ip,tcp,ams]`；AMS-G5/G7 |
| §3 五件套 | 会话表=connections/sessions；事务=HELLO→AUTH→OPEN→业务→CLOSE；关联=SessionID/CorrelationID/message_id；插入=AMS 终结层；时间线=连接内顺序、会话内顺序、跨连接不共享；无隐式重放 | §5、§6、`ams_multi_session`/`ams_multi_stream` |
| §12 清单 | 四元组与业务字段逐项见 §12；层四元组动态策略有通用入口，AMS 嵌套承载和业务动态列 AMS-G2/G3；序号位置见 `layer_gen.go:90-107,423-476` | §12 |
| §4–§15 | 矩阵、错误、性能、八要素及 cases 对账；§15 仍有 G5/G7 缺口，不宣称过门 | §§10–12、§14、AMS-G5/G7 |


### D13.1 六项审查清单（C1–C6）

| ID | 审查结论 |
|---|---|
| C1 | JSON 可解析，20 个 ID 唯一且与设计 §9.1、testcase §2 同序；14 正、6 负；`spec_json` 20/20 仅 `layers` 键，层链 20/20 为 `[ip,tcp,ams]`。 |
| C2 | 非负例顶层 `spec_json` 仅有 `layers`；负例同样仅有 `layers`，无旧扁平 `src_ip/dst_ip/src_port/dst_port/count`。 |
| C3 | 地址位于 `layers[].ip`（`src/dst`），端口位于 `layers[].tcp`；业务仅位于 `layers[].ams`。但 18 条 `connections[].src_port` 重复外层 `tcp.src_port`，`ams_ipv4_ipv6_same_payload` 另嵌套 `src_ip/dst_ip`（AMS-G5），未达严格唯一真相。 |
| C4 | 14 正例保留可观察 expect（`packet_count` 逐条见 testcase §6）；6 负例 `expect` 严格两键，结果与 validator 锚词一致。 |
| C5 | 多会话、多流、保活、分段和边界均有独立 ID；未覆盖能力登记 AMS-G1/AMS-G2/AMS-G3/AMS-G5/AMS-G6（AMS-G4 已收口，仅位置索引）。 |
| C6 | 本轮范围仅 design.md、testcase.md；不改 cases JSON、Go 或其他协议；未运行 suite/Go 测试/服务器。 |

## D14 缺口立项

| 编号 | 缺口 | 迁入计划 |
|---|---|---|
| AMS-G1 | TLS 外层未解密时无法证明 AMS 字段/商业互操作 | 代码/抓包阶段补 TLS profile 后新增 cases |
| AMS-G2 | connections 嵌套地址/端口未接动态策略 | 代码阶段给嵌套槽位接入动态解析，再补五策略整格 |
| AMS-G3 | 业务 ID、payload、command 等未接动态策略 | 代码阶段定义动态字段承载与序号算法，再补 cases |
| AMS-G4 | 已收口。registry/translate 现行位置：`registry.go:1766-1772`（`ams`，Category=Terminal，DependsOn=tcp，FieldContract `tcp.dst_port=61616`，Fields 仅 `profile`）、`chain_planner_translate.go:185`、`strategy_convert.go:1473-1477`、`types.go:934-1004`、`chain_planner.go:1440-1458`、`chain_planner_util.go:110-118`。代码若变动，由后续实现重钉 | 无进一步动作；保留本行作位置索引 |
| AMS-G5 | 18 条含 `connections[]` 的配置重复 `connections[].src_port` 与外层 `tcp.src_port`（同值固定），其中 `ams_multi_stream`（42051/42053）和 `ams_ipv4_ipv6_same_payload`（42054/42055）依赖连接级源端口做多流/自驱；后者另嵌套 `src_ip/dst_ip`（含一条 IPv6）。当前自驱生成器读取该重复配置（`layer_gen.go:180-200` 缺省回退 `meta`），层链尚非唯一真相 | 代码阶段让生成器只消费外层 `layers.ip/tcp`，迁移并回归 20 例后再移除本缺口 |
| AMS-G6 | TCP 异常/错误帧（RST/异常终止）尚无专门例，仅 `terminates: true` 覆盖优雅关闭 | 新立项时补充 TCP 异常/错误帧例或独立条目 |
| AMS-G7 | `translateTerminalConfig`（`chain_planner_translate.go:756+`）没有 `term.Name == "ams"` 的层 config→`spec.AMS` 分支；当前 `strategy_convert.go:1473-1477` 只覆盖旧 flat `cfg["ams"]`，因此严格 `[ip,tcp,ams]` 层配置不能据此宣称已接线 | 在 translateTerminalConfig 增加 `completedConfig` + `DisallowUnknownFields` 的 AMS 解码，补链级单测和 20 例真实流程；通过后再收口 |

## D15 修订记录

- v1.2.1（2026-10-01）：按 JSON 全量审计校正 20=14+6、负例锚词与真实 validator 文案；补 D3/D4/D5 结构化表、动态整格边界、§15 三行展开；登记 `translateTerminalConfig` AMS 缺口 AMS-G7，未宣称层链可执行。
- v1.2.0（2026-10-01）：静态复核 cases 与代码后校正逐条计数与行号；补 C1–C6 六项审查清单；把“pcap/NIC 路径检查”明确为待执行验收（本轮未运行 suite/Go 测试/服务器）；AMS-G4 行号复核对齐并收口。
- v1.1.0（2026-09-30）：按 CORE §4/§5/§6/§8/§12/§15 补齐 P1 矩阵、三子表、三路对照、候选方案、依赖错误、性能、八要素、动态字段和门1对照；将层链状态按当前实现修正；自审 2 轮。
