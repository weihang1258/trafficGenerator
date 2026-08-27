# AMS（Apache ActiveMQ 管理协议，ActiveMQ Management Service）设计契约

> 版本：v1.0.0（设计阶段）
> 日期：2026-08-20
> 状态：仅设计与 PCAP（抓包文件）用例契约；`ams` 层尚未注册，不修改 Go（编程语言）实现，不宣称当前 suite（测试套件）可运行。
> 配套文件：`docs/protocol-designs/51-ams-testcase.md`、`trafficgen/test/protocol_pcap/cases/ams.json`
> 规范基线：Apache ActiveMQ 管理会话抽象、TCP（传输控制协议）可靠字节流和本项目 AMS wire profile（线上档案）。

## 1. 范围、profile 和未注册边界

本版定义 AMS 管理客户端与 ActiveMQ 管理端之间的确定性 TCP 帧序列，覆盖连接握手、认证、管理会话、命令/响应、事件消息、确认、心跳、关闭，以及 IPv4/IPv6、多会话、多流和长度边界。AMS 是本项目对 ActiveMQ 管理承载的独立协议层契约，不把 OpenWire（ActiveMQ 原生消息协议）、AMQP（高级消息队列协议）、JMX/RMI 或 Jolokia/HTTP（基于 HTTP 的管理接口）静默当作 AMS。

| profile（协议档案） | 规范范围 | 本版允许内容 | 不从 profile 推导 |
|---|---|---|---|
| `ams_management_v1` | TCP 管理控制面 | hello/auth/session、命令响应、事件消息、确认、ping/pong | broker（消息代理）实际状态或自动命令 |
| `ams_observer_v1` | 只读观察会话 | hello/auth、subscribe、event、ack、close | 写操作、隐式订阅和事件重放 |
| `ams_tls_boundary` | TLS（传输层安全）外层边界 | 仅未来定义 TLS/TCP 载体 | 未解密时不声称看见 AMS frame（帧）字段 |

当前仓库没有注册 `ams` layer（层）、planner（规划器）、validator（校验器）或生成器。`cases/ams.json` 只保留一个 `ams_neg_unregistered` 的 `expect_error=true`、`error_contains="unknown layer"` 占位；该占位不计入下文 20 个语义 ID，不得把拒绝、0 包或空 PCAP 报告为 AMS 行为通过。

## 2. 协议栈、端口和固定偏移

推荐层链为 `[ip, tcp, ams]`。AMS 只使用 TCP 明文承载；UDP、裸 IP、HTTP、OpenWire 和 AMQP 不得静默转换为本版载体。兼容 profile 的默认 TCP destination port（目的端口）为 61616，源端口由 fixture（固定样本）显式给出；实现若使用独立管理端口，必须通过 `port` 显式配置，不能在 planner（规划器）中悄然改写。

无 VLAN（虚拟局域网）、无 IP options（IP 选项）和无 TCP options 时：

| 载体 | TCP payload（载荷）起点 | 用途 |
|---|---:|---|
| TCP/IPv4 | 54 = Ethernet 14 + IPv4 20 + TCP 20 | AMS 首帧和后续 frame |
| TCP/IPv6 | 74 = 14 + IPv6 40 + TCP 20 | 相同 AMS 字节语义 |

TCP segment（分段）边界不是 AMS frame 边界。实现必须按 Length 重组完整 frame；一帧跨 MSS（最大报文段长度）时，先重组 TCP stream（字节流）再验证长度、字段和尾标记。PCAP 的 `frames` offset 只固定无 options 的稳定 fixture，不把一个 TCP 包等同于一个 AMS frame。

## 3. Frame 总体布局

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

## 4. Payload、字段和确认语义

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

## 5. 握手、会话和流状态机

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

## 6. 命令、消息和生命周期

`COMMAND` 至少带 `command` 和 `resource`；`body` 可选。推荐命令包括 `broker.info`、`connection.list`、`session.list`、`queue.inspect`、`consumer.list` 和 `subscription.list`。本版只编码显式命令，不模拟 broker 实际查询结果。未知 command、空 resource（对该命令必填时）和超出 profile 权限的写操作必须产生 `ERROR` 或 planner error，不能静默成功。

`MESSAGE` 用于管理事件通知或显式结果推送，至少带 `message_id`、`message_kind`、`sequence` 和 `payload`。消息 payload 可为 UTF-8 JSON（JavaScript Object Notation，JavaScript 对象表示法）或 opaque bytes，但编码必须由 profile 显式给出；不能把 JSON 文本和长度字段混淆。`delivery_mode=0` 表示 at-most-once（至多一次），`delivery_mode=1` 表示 ack-required；只有 mode=1 才要求 MESSAGE_ACK。重传必须复用 message_id 和 sequence，不得伪造新消息。

`PING`/`PONG` 只能在 session open 后出现；heartbeat 为零表示禁用自动保活，不能因 TCP keepalive 自动插入 AMS frame。`CLOSE_SESSION` 必须带合法 SessionID；CLOSE_OK 后不再允许 command、message、ack 或 ping。

## 7. IPv4/IPv6、多会话、多流和边界

IPv4 outer EtherType 为 `0x0800`；IPv6 outer EtherType 为 `0x86dd`，TCP Next Header 为 6。相同 AMS fixture 在 IPv4/IPv6 中 Version、Type、Flags、SessionID、CorrelationID、TLV 和 FrameEnd 必须一致，仅外层地址族与 payload offset 改变。

多会话场景至少建立两个 SessionID，并分别执行一条 command 和一条 message；验证使用 SessionID、CorrelationID、message_id 和 TCP stream 关联，不硬编码跨流 packet index。多流场景至少使用两个 TCP 四元组；每流独立完成 HELLO/AUTH/OPEN_SESSION，禁止把一个连接的 AUTH_OK 或 OPEN_OK 配给另一连接。

边界至少覆盖：空 payload 的 PING/PONG、Length=18 最小 frame、最大允许 frame、TLV length=0、最大受支持字段长度、uint16 session_limit 上界、uint64 correlation/message/sequence 边界、空 command/resource、重复 ACK、MSS 分段和 Body 跨 TCP segment。实现必须在长度加法、TLV 游标前进、sequence/ack 范围和 frame_max 检查中拒绝溢出，不得回绕或分配 `0xffffffff` bytes。

## 8. 配置 typedef（类型定义）

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

## 9. 错误处理、实现集成和完成定义

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

实现时应登记 `ams` 为 Category=Terminal、DependsOn=`tcp`，复用 TCP MSS/checksum 和 IPv4/IPv6 builder；以 TCP stream 重组后按 Length 解析，不能按 TCP packet 边界切 frame。所有 planner/validator 错误须传播为 task error。未注册期间不得把下列正例加入可执行 suite。

## 10. 原子 ID 与完成定义

设计、testcase 和未来 JSON 必须按以下同一顺序使用 20 个唯一语义 ID：14 个正例、6 个负例。当前 JSON 只放额外的 `ams_neg_unregistered` 前置占位，不计入 20 个语义 ID。

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

完成定义：注册 `tcp→ams` 层链；逐字节生成 AMS frame 和 TLV；握手、认证、会话、命令/响应、消息/确认和关闭状态可观测；IPv4/IPv6、多会话、多流、MSS 重组和边界均有集成测试；20 个语义 ID 的正负断言和错误传播完成；未注册阶段只接受 `unknown layer` 占位。

## 11. 修订记录

- v1.0.0（2026-08-20）：建立 AMS TCP 管理协议设计契约，覆盖帧布局、TLV、握手/认证、会话、命令/响应、消息/确认、保活、IPv4/IPv6、多会话、多流、MSS/长度边界和 20 个正负语义 ID；当前仅提交设计与用例契约，不修改 Go 实现。
