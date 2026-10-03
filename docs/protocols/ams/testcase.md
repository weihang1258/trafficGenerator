# AMS（Apache ActiveMQ 管理协议，ActiveMQ Management Service）测试用例契约

> 版本：v1.2.1（按 CORE 对齐）
> 日期：2026-10-01
> 配套设计：`docs/protocols/ams/design.md`
> 机器契约：`trafficgen/test/protocol_pcap/cases/ams.json`
> 状态：JSON 实际 20 例（14 正、6 负）；20/20 `spec_json` 顶层键集合为 `{layers}`，20/20 层链为 `[ip,tcp,ams]`。18 例的 `ams.connections[].src_port`（以及双栈例嵌套地址）仍是当前自驱承载输入，且链式层配置尚缺 `translateTerminalConfig` 的 AMS 解码分支（AMS-G5/G7）；本轮未运行 suite、Go 测试、服务器或网卡。

## T1 测试点清单与三源回指

> **执行前提**：本清单是规范→业务→代码→缺口的先行清单；AMS-G7 未补前，层链 spec 不能宣称可由链式 translate 执行。每个缺口的确认方式是补翻译分支、链级单测，再按 §6 的真实 pcap/NIC 两路重跑。

| 测试点 | 规范/设计 | 业务场景 | 代码分支 | 用例 |
|---|---|---|---|---|
| 帧头与 TLV | 设计 §3–§4 | 正常管理帧 | `buildFrame/BTLV`（`builder.go:111-121/98-107`） | `ams_frame_header_ipv4`, `ams_tlv_and_binary_payload`, `ams_frame_boundary` |
| 握手/会话 | 设计 §5 | 建立与释放 | `validateEvents` 状态机（`layer_gen.go:320-419`） | `ams_handshake_auth`, `ams_session_open_close` |
| 命令/消息关联 | 设计 §4/§6 | 查询与事件确认 | `validateSessionFrame`（`layer_gen.go:423-476`） | `ams_command_response`, `ams_message_ack`, `ams_event_retransmission` |
| 保活/多轮/多流 | CORE §3.15 | 保活、多会话、多连接 | `generateEvents` 事件路径（`layer_gen.go:90-107`）/`generatePackets` 自驱（`:176-285`） | `ams_ping_pong`, `ams_multi_session`, `ams_multi_stream` |
| 地址族/MSS/边界 | 设计 §7 | 双栈、重组、边界 | `emitSegment`、`generatePackets` TCP 自驱 | `ams_ipv6`, `ams_ipv4_ipv6_same_payload`, `ams_mss_frame_reassembly`, `ams_frame_boundary` |
| 失败注入 | 设计 §9、CORE §14.11 | 拒绝并传播 task error | `ValidateConfig`/`ValidateSpec`（`layer_gen.go:496-568`）、`validateWireFault`（`layer_gen.go:537-557`） | 6 个负例 |

三源回指：①设计条目（§§3–§9）；②当前 AMS wire profile 与 validator 的真实拒绝文案；③ActiveMQ 管理线行为。缺口 AMS-G1 的 TLS/真实 broker 行为属于待确认，确认方式为抓包 TLS 管理连接对照。

## T2 颗粒度、场景分类与强度

每个 JSON 条目只验一个主行为点；组合行为拆到独立 ID，复杂例另列交织维度。三类场景分别是：数据（长度、TLV、字节序、空值、边界和非法）、业务（握手、状态迁移、命令/响应、确认、重传、并行/中断）、现网（IPv4/IPv6、TCP MSS、双连接、常见 ActiveMQ 管理行为）。强度要求：类型/标志/错误锚词枚举逐值；地址族×会话/流×操作做正交矩阵；四元组和业务动态做整格；packet_count、offset、FrameEnd、关联 ID 做输出断言边界。当前实现尚无 AMS 动态字段策略，动态整格列 AMS-G2/G3，不以静态样本冒充覆盖。


## T3 §3.15 三项

- 同连接多轮操作：`ams_multi_session`（同一连接双会话各完成命令/消息事务）；`ams_event_retransmission`（同一 session 多次显式消息事件）。
- 非正常结束：无专门 RST/TCP 异常终止例 → AMS-G6：待补 TCP 异常/错误帧例或立项。
- 长保活：`ams_ping_pong`（session 内显式 PING→PONG）。

### T3.1 正交与复杂场景缺口

当前 JSON 有 IPv4/IPv6、单/多 session、单/多 TCP stream、MSS 和错误注入格；尚缺“多事务+多流交错+异常/NAT”三类同时交织的现网复杂例，登记 AMS-G8。补法是新增至少一条真实编排例，来源为 ActiveMQ 官方管理连接抓包，并在设计 §10.3 映射后重跑 pcap/NIC。AMS-G6 的 RST/异常终止仍单独保留。


## T4 存量用例逐条审计去向

当前 JSON 20/20 全部合入，ID 与本文 §2 完全对应；无等价替代、无作废、无旧占位残留。外层结构统一使用 `layers`，但不能据此宣称严格唯一真相：正例仍在 `ams.connections[]` 重复配置当前生成器读取的连接级地址/端口（详见设计 §1、AMS-G5）。

## T5 失败路径

6 个负例 `expect` 均为严格两键 `{expect_error,error_contains}`；锚词分别为 `version`、`hello`、`session`、`correlation`、`message`、`tlv`。这些锚词均可在 `trafficgen/internal/protocol/ams/layer_gen.go:333-553` 找到：例如 `wire_fault bad_version` 含 `version/frame`，首帧错误含 `hello/handshake`，未知 session 含 `session`，未知响应 correlation 含 `correlation/response`，未知 ACK 含 `message/ack`，TLV 故障含 `tlv/field/length`。JSON 选择其中一个真实子串作 `error_contains`，因此不是泛化占位；不得混入 `packet_count`/`frames`。


## T6 与 JSON 对账

文档登记 20 例（14 正、6 负）与 `cases/ams.json` 实际一致；ID 集合与顺序一致。`spec_json` 顶层键形状分布为 `{layers}`：20/20；层链形状分布为 `[ip,tcp,ams]`：20/20；AMS 终结层键为 `connections`：18/20，`wire_fault`：2/20。负例 `expect` 键形状为 `{expect_error,error_contains}`：6/6，且无成功断言键。正例 `packet_count` 依次为 9/11/15/15/15/15/15/21/30/9/18/15/17/19；这些数值未执行真实 pcap 校准，P5 重跑后再钉。


## T7 测试原则与线上断言

已注册，JSON 不含未注册占位条目。

AMS 是 TCP 应用层协议。无 VLAN（虚拟局域网）、IP options（IP 选项）和 TCP options 时，IPv4 TCP payload（载荷）起点为 offset（偏移）54，IPv6 为 74。TCP MSS（最大报文段长度）分段后必须先按 Length 重组 AMS frame（帧）；正例实现后每条至少有 `packet_count` 或 `min_packets`、可观测 `fields`（字段）和稳定 `frames`（帧字节）。负例 `expect` 严格只有 `expect_error` 与 `error_contains`。

AMS frame 的稳定最小字节为 `Length(4)|Version(1)|Type(1)|Flags(2)|SessionID(4)|CorrelationID(8)|FrameEnd(2)`；Length 不包含自身 4 字节但包含其余 18 字节和 Payload。FrameEnd 固定 `ae 5a`。动态 SessionID、CorrelationID、message_id 和 sequence 不写死，除非 fixture 显式固定；优先使用 `nonzero`、`same_as_packet`、`distinct_values` 或 raw frame 的稳定前缀。未解密 TLS 只观察 TLS/TCP 外层，不能声称看见 AMS 字段。

## T8 原子用例索引

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

## T9 线上编码和偏移断言

每个 AMS frame 的 TCP stream 编码为：

```text
Length(4) | Version(1) | Type(1) | Flags(2) | SessionID(4) |
CorrelationID(8) | Payload(N) | FrameEnd(2)
```

Length 是大端 uint32，值为 `18 + N`，自身 4 字节不计入。Version=1；FrameEnd 为 `ae 5a`。TLV 使用 `FieldID(2)|FieldLength(2)|Value`，FieldLength 只计 Value。`ams_frame_header_ipv4` 在 IPv4 payload offset 54 断言 Version/Type/Flags/SessionID/CorrelationID 的稳定结构和 `ae 5a`；不能将 TCP SYN payload 当 AMS frame。

`ams_handshake_auth` 必须按 HELLO→HELLO_OK→AUTH→AUTH_OK 顺序验证，并断言方向、profile 和协商 heartbeat/session_limit；planner 不自动插入遗漏响应。`ams_session_open_close` 继续验证 OPEN_SESSION→OPEN_OK→CLOSE_SESSION→CLOSE_OK，关闭后无新业务 frame。

`ams_command_response` 和 `ams_message_ack` 必须分别按 COMMAND→RESPONSE、MESSAGE→MESSAGE_ACK 验证；COMMAND/RESPONSE 使用相同非零 CorrelationID，MESSAGE_ACK 的 ack_for 等于 MESSAGE message_id，且 SessionID 与逻辑流一致。不能仅按 TCP packet index 建立关联。

`ams_mss_frame_reassembly` 的 frame 可被切分到多个 TCP segments；必须先重组 TCP stream，再按 Length 取出完整 frame 和 FrameEnd。不能因为单个 segment 不包含完整 frame 就报错，也不能按单包 payload 长度伪造 frame size。

## T10 正例逐项断言契约

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

## T11 负例契约

负例必须在 planner/validator 处失败并传播为 task error，不得产生成功 PCAP、completed/0 packet 或只剩 TCP ACK。每个负例执行期 `expect` 只允许 `expect_error` 与 `error_contains`。

| ID | 故障输入 | 目标 `error_contains` |
|---|---|---|
| `ams_neg_frame_encoding` | Version 错误、未知 Type、保留 Flags 非零、Length 越界或 FrameEnd 非 `ae 5a` | `frame`、`length` 或 `version` |
| `ams_neg_handshake_state` | 缺 HELLO、方向反转、AUTH 未完成即 OPEN_SESSION 或重复握手 | `hello`、`handshake` 或 `auth` |
| `ams_neg_session_reference` | 未打开/已关闭 SessionID，或跨连接引用 session | `session` 或 `connection` |
| `ams_neg_correlation_response` | RESPONSE 使用未知、重复或跨 session CorrelationID | `correlation` 或 `response` |
| `ams_neg_message_ack` | ACK 未发送 message、跨流确认、sequence 回退或 ACK 范围越界 | `message`、`sequence` 或 `ack` |
| `ams_neg_tlv_length` | TLV 截断、FieldLength 越过 Payload 或长度加法溢出 | `field`、`tlv` 或 `length` |

## C1–C6 六项静态闭环清单

| ID | 核对项 | 结论 |
|---|---|---|
| C1 | JSON 解析、ID 集合与正负数量 | 20/20 唯一；14 正、6 负；顺序与 D9 原子表一致 |
| C2 | 严格层链形状 | 20/20 顶层仅 `layers`；20/20 为 `[ip,tcp,ams]`；无顶层地址、端口、count |
| C3 | 地址/端口/业务归属 | 外层地址在 `ip`、端口在 `tcp`、业务在 `ams`；18 例连接嵌套承载键重复外层值，AMS-G5 明确保留，不能宣称唯一真相 |
| C4 | 正负 expect 纯净性 | 14 正例有数量与可观察 frames/fields；6 负例严格只有 `expect_error`、`error_contains`，锚词取真实 validator 文案 |
| C5 | 行为面覆盖与缺口 | 握手、会话、命令/响应、消息/ACK、保活、多会话、多流、双栈、MSS、边界均有 ID；TLS、动态字段、RST/异常终止、复杂交错分别登记 AMS-G1/G2/G3/G6/G8 |
| C6 | registry/translate 与双输出边界 | registry 的 `ams` 为 Terminal、DependsOn=`tcp`、FieldContract 默认 61616、Fields 仅 `profile`；`translateTerminalConfig` 当前无 AMS 分支（AMS-G7）；pcap/NIC 与 Go/suite 均未运行 |

## T15 机器契约与静态检查

1. 运行 `python3 -m json.tool trafficgen/test/protocol_pcap/cases/ams.json`，确认 JSON 共 20 条：14 个正例、6 个负例；顶层键仅 `id/proto/summary/spec_json/expect/notes`，正负例 `spec_json` 均为 `{layers}` 且层级为 `[ip,tcp,ams]`。注意：18 条 `ams.connections[]` 内的 `src_port`（及双栈例的 `src_ip/dst_ip`）与 `layers.tcp/ip` 重复，是 AMS-G5 的代码阻塞；AMS-G7 使链式层配置到 `spec.AMS` 的翻译尚未接通，不得宣称严格唯一真相。
2. 正例每条有 `packet_count`/`min_packets`、已注册 TCP/IP/IPv6 字段和稳定 `frames`；不得伪造未注册的 `ams.*` tshark 字段。AMS frame bytes 使用重组后的 payload offset 54/74。
3. 多会话/多流使用 tcp.stream、方向、端口 distinct 和 SessionID/CorrelationID/message_id 关联，不假设跨流调度顺序。
4. 负例 `expect` 只能包含 `expect_error`、`error_contains`，且锚词与 validator 文案一致；本文件记录的 6 个锚词是 JSON 实际值，不扩大为未提交的同义词。

## T16 三方一致性表

设计 §10、本文 §2 和 JSON 保持同一 20 个语义 ID、同一顺序。

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

## T17 修订记录

- v1.2.1（2026-10-01）：按 JSON 逐项机读审计补顶层键/层链/负例键形状分布与真实锚词；补 T2/T3/T4/T6、AMS-G7 层翻译缺口和 AMS-G8 复杂现网场景缺口；未改 JSON。
- v1.1.0（2026-09-30）：按 CORE §9/§3.15 补齐测试点清单、三源回指、§3.15 三项、存量审计和 JSON 对账；删除过期未注册占位条目，保持 20 个语义 ID 与 JSON 一致；外层迁移为 `layers` 形，但 `ams.connections[]` 的重复承载配置作为 AMS-G5 明确保留，未宣称严格唯一真相。
- v1.0.0（2026-08-20）：建立 14 个 AMS 管理协议正例和 6 个严格负例，覆盖 frame/TLV、握手认证、会话、命令/响应、消息/确认、重传、保活、IPv4/IPv6、多会话、多流、MSS 重组、边界和错误传播。
