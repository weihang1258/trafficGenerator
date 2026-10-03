# Swarm（去中心化 P2P 存储协议，Swarm Storage Profile）设计契约

> 版本：v1.1.0（层链迁移审计版）
> 日期：2026-09-30
> 状态：`swarm` 层已注册；本次只迁移文档与 PCAP 用例至严格层链，不修改 Go 实现，不宣称 suite 已全量运行。
> 配套文件：`docs/protocols/swarm/testcase.md`、`trafficgen/test/protocol_pcap/cases/swarm.json`
> 规范边界：本项目 Swarm storage wire profile（存储线协议档案）；不把某一具体实现的 devp2p/RLPx、HTTP API 或 DHT（分布式哈希表）发现报文静默视为本协议。

## 1. 范围、profile 和实现边界

本版定义去中心化 P2P 存储节点之间的确定性发现、握手、会话、内容寻址 chunk（数据块）存取、manifest（清单）交换、确认、分片、流复用和关闭序列。协议同时覆盖 UDP discovery（发现控制面）和 TCP storage session（存储会话）；UDP discovery 不能承载 TCP storage frame，TCP storage frame 也不能伪装成 discovery datagram（数据报）。

| profile（协议档案） | 承载 | 本版允许内容 | 不从 profile 推导 |
|---|---|---|---|
| `swarm_storage_v1` | TCP/1634 | hello/auth/session、chunk store/retrieve、manifest、delivery/ack、ping/close | 节点信誉、路由算法、持久化结果或自动复制 |
| `swarm_discovery_v1` | UDP/1634 | ping/pong、节点 endpoint（端点）和能力公告 | discovery 响应自动建立存储会话 |
| `swarm_tls_boundary` | TLS（传输层安全）/TCP | 仅未来定义加密外层 | 未解密时不声称看见 Swarm frame 字段 |

当前仓库已注册 `swarm` 层（terminal 终结层，ldp 同款 TransportOn 双载体：`udp` discovery / `tcp` storage；`registry.go:1782`）并由 swarm 生成器逐事件产出 wire 字节。`cases/swarm.json` 已改写为严格层链；框架说明与旧形状已在 §12 收敛，不再保留未注册占位论述。tshark 无 Swarm dissector，断言走 TCP/UDP 字段与帧字节。

本版是项目级 wire profile，不宣称是某个外部 Swarm 实现的完整互操作规范；真实实现接入时必须以选定实现和版本的公开规范逐字段复核，不能因为层名相同而自动复用 OpenWire、AMQP 或任意 DHT 编码。

## 2. 协议栈、端口和固定偏移

层链为 `[{ip}, {udp}, {swarm}]`（discovery）或 `[{ip}, {tcp}, {swarm}]`（storage）。默认 discovery 和 storage 目的端口均为 1634，端口必须可显式覆盖；UDP discovery 使用单个 datagram，TCP storage 使用有序字节流。裸 IP、HTTP、WebSocket、AMQP 和 OpenWire 不得静默转换为本版 Swarm carrier（承载）。

无 VLAN（虚拟局域网）、无 IP options（IP 选项）和无 TCP options 时：

| 承载 | 应用 payload（载荷）起点 | 用途 |
|---|---:|---|
| UDP/IPv4 | 42 = Ethernet 14 + IPv4 20 + UDP 8 | discovery frame |
| TCP/IPv4 | 54 = Ethernet 14 + IPv4 20 + TCP 20 | storage frame |
| UDP/IPv6 | 62 = 14 + IPv6 40 + UDP 8 | discovery frame |
| TCP/IPv6 | 74 = 14 + IPv6 40 + TCP 20 | storage frame |

TCP segment（分段）边界不是 Swarm frame 边界。实现必须先按 Length 重组完整 storage frame；一帧跨 MSS（最大报文段长度）时，不能按 TCP packet（包）切帧。UDP datagram 边界保留 discovery frame 边界，但 Length 仍必须与 datagram 内实际字节数相等。

## 3. Discovery 与 storage frame 布局

### 3.1 Discovery frame

Discovery datagram 使用：

```text
Magic(4) | Length(2) | Version(1) | Kind(1) | Nonce(8) |
NodeID(32) | EndpointCount(1) | Endpoint* | FrameEnd(2)
```

`Magic` 固定为 ASCII `SWD1`（`53 57 44 31`），`Length` 为从 Version 到 FrameEnd 的总字节数，不包含 Magic 和 Length 自身；`Version=1`；FrameEnd 固定 `ae 5a`。`Kind=0x01` 为 PING，`0x02` 为 PONG，`0x03` 为 endpoint announcement。每个 endpoint 为 `AddressFamily(1)|Port(2)|Address(4 或 16)`。NodeID 必须是 32 字节非零值，Nonce 用于 request/response 关联。

### 3.2 Storage frame

TCP storage frame 使用：

```text
Magic(4) | Length(4) | Version(1) | Kind(1) | Flags(2) |
SessionID(8) | StreamID(4) | CorrelationID(8) |
Payload(N) | FrameEnd(2)
```

`Magic` 固定为 ASCII `SWS1`（`53 57 53 31`），`Length` 为从 Version 到 FrameEnd 的总字节数，即 `26 + N`，不包含 Magic 和 Length 自身；最小 frame 长度为 26。`Version=1`，FrameEnd 固定 `ae 5a`。`Flags` 的 bit 0 表示 request，bit 1 表示 response，bit 2 表示 ack-required，bit 3 表示 fragment，其他位必须为零，除非 profile 显式声明。

| Kind | 值 | 方向/语义 |
|---|---:|---|
| `HELLO` | `0x10` | client→peer，能力和版本协商 |
| `HELLO_OK` | `0x11` | peer→client，协商结果 |
| `AUTH` | `0x12` | client→peer，节点身份证明引用 |
| `AUTH_OK` | `0x13` | peer→client，认证结果 |
| `OPEN_SESSION` | `0x14` | client→peer，建立存储会话 |
| `OPEN_OK` | `0x15` | peer→client，会话限制 |
| `CLOSE` | `0x16` | 任一方向，关闭会话 |
| `CLOSE_OK` | `0x17` | 对端响应关闭 |
| `STORE` | `0x20` | client→peer，写入 chunk |
| `STORE_OK` | `0x21` | peer→client，写入确认 |
| `RETRIEVE` | `0x22` | client→peer，读取 chunk |
| `CHUNK` | `0x23` | peer→client，chunk 数据/分片 |
| `MANIFEST` | `0x24` | 任一方向，清单或索引 |
| `MESSAGE_ACK` | `0x25` | 对端确认 STORE/CHUNK/MESSAGE |
| `PING` | `0x30` | 任一方向，会话保活 |
| `PONG` | `0x31` | 对端响应保活 |
| `ERROR` | `0x7f` | 任一方向，显式错误 |

未知 Magic、Version、Kind、保留 Flags、Length 越界、FrameEnd 非 `ae 5a` 或 storage frame 在 UDP 上发送必须拒绝。Length 不能通过整数回绕；实现不得按未限制的长度直接分配内存。

## 4. Payload、内容寻址和确认语义

Payload 由零个或多个 TLV（类型-长度-值）字段组成：

```text
FieldID(2) | FieldLength(4) | Value(FieldLength)
```

`FieldLength` 只计算 Value；字段必须完整落在 Payload 内。内容寻址字段使用固定长度：`chunk_address` 为 32 字节，`manifest_root` 为 32 字节，`node_id` 为 32 字节。Hash（哈希）算法和编码必须由 profile 显式声明；planner 不得把任意文本当作已验证地址。

| FieldID | 名称 | 编码 |
|---:|---|---|
| `0x0001` | profile | UTF-8 bytes |
| `0x0002` | capability | UTF-8 bytes |
| `0x0003` | node_id | 32 bytes |
| `0x0004` | nonce | uint64 |
| `0x0010` | session_limit | uint16 |
| `0x0011` | max_frame | uint32 |
| `0x0012` | heartbeat | uint16 seconds |
| `0x0020` | chunk_address | 32 bytes |
| `0x0021` | chunk_size | uint32 |
| `0x0022` | chunk_offset | uint32 |
| `0x0023` | chunk_payload | opaque bytes |
| `0x0030` | manifest_root | 32 bytes |
| `0x0031` | manifest_entry | opaque bytes |
| `0x0040` | message_id | uint64 |
| `0x0041` | sequence | uint64 |
| `0x0042` | ack_for | uint64 |
| `0x0043` | ack_status | uint16 |
| `0x0044` | fragment_index | uint16 |
| `0x0045` | fragment_count | uint16 |
| `0x00f0` | error_code | uint16 |
| `0x00f1` | error_text | UTF-8 bytes |

`HELLO` 必须带 profile、capability、node_id 和 nonce；`HELLO_OK` 必须回显可接受 profile 并给出 max_frame/session_limit。`AUTH` 只能携带节点身份或 credential reference，不能在线发送明文私钥；`AUTH_OK` 必须先于 OPEN_SESSION。OPEN_SESSION 建立非零 SessionID，OPEN_OK 返回协商限制。

`STORE` 必须带 chunk_address、chunk_size 和 chunk_payload；chunk_payload 长度必须等于 chunk_size，内容地址校验由实现按显式 hash profile 执行。`RETRIEVE` 必须带 chunk_address；对应 CHUNK 使用相同 CorrelationID 和 chunk_address。带 ack-required 的 STORE/CHUNK/MESSAGE 必须收到同一 session/stream 的 MESSAGE_ACK，ACK 的 ack_for 等于 message_id 或 CorrelationID。重复 ACK、跨 session ACK、未知 chunk 的成功 STORE_OK 和 offset 越界必须拒绝。

## 5. 握手、会话、流和生命周期状态机

推荐的 TCP storage 序列：

```text
TCP SYN/SYN-ACK/ACK
  → HELLO
  ← HELLO_OK
  → AUTH
  ← AUTH_OK
  → OPEN_SESSION
  ← OPEN_OK
  → STORE / RETRIEVE / MANIFEST / PING
  ← STORE_OK / CHUNK / MESSAGE_ACK / PONG
  → CLOSE
  ← CLOSE_OK
  → TCP FIN/ACK
```

UDP discovery 的 PING/PONG 只提供 endpoint 和 capability，不改变 TCP session 状态。

| 状态 | 允许事件 | 必须保持 |
|---|---|---|
| `DiscoveryReady` | UDP PING/PONG/announcement | Nonce、NodeID、endpoint 长度有效 |
| `TransportReady` | HELLO | 首个 storage bytes 必须是合法 SWS1 frame |
| `Negotiating` | HELLO_OK、AUTH、AUTH_OK | 方向、profile、能力和限制一致 |
| `Authenticated` | OPEN_SESSION | AUTH_OK 后才能建立 session |
| `SessionOpen` | STORE、RETRIEVE、MANIFEST、PING/PONG、CLOSE | SessionID 非零且未关闭 |
| `AwaitingChunk` | CHUNK、ERROR | CorrelationID 与未完成 RETRIEVE 对应 |
| `AwaitingAck` | MESSAGE_ACK、ERROR | ack_for 属于同一 session/stream |
| `Closing` | CLOSE、CLOSE_OK | 关闭后不得产生新业务 frame |
| `Error` | malformed frame、完整性/顺序/引用错误 | planner→engine→task error，不能 completed/0 packet |

一个 TCP 连接可承载多个 StreamID；每个 stream 的 CorrelationID、sequence、fragment 状态独立。一个连接也可承载多个 SessionID，但 profile、chunk request、ACK、关闭状态隔离。多 TCP 连接必须使用独立四元组，不共享 session、stream、message 或 chunk 状态。跨 TCP stream 的同一 SessionID 默认非法，除非 profile 显式声明迁移。

## 6. Manifest、chunk 和分片语义

MANIFEST 至少带 manifest_root 和一个 manifest_entry；entry 必须能够关联 chunk_address 与逻辑大小。协议只编码显式 manifest，不模拟节点自动同步、复制或路由。

一个大 chunk 可由多个 CHUNK frame 传送。fragment_index 从 0 开始，fragment_count 大于 0；所有分片必须共享 SessionID、StreamID、CorrelationID、chunk_address 和 sequence，index 不重复且重组长度等于 chunk_size。TCP segment 分段和 Swarm fragment 是两个不同层次，不能把 packet index 当 fragment_index。

`delivery_mode=0` 表示无确认的显式通知，`delivery_mode=1` 表示 ack-required；只有 profile 和 frame Flags 都要求时才必须发 ACK。合法丢包、显式重传和节点业务 ERROR 是协议行为，不应被 planner 自动改成成功数据或无界重试。

## 7. IPv4/IPv6、多会话、多流和边界

IPv4 outer EtherType 为 `0x0800`；IPv6 outer EtherType 为 `0x86dd`，TCP Next Header 为 6，UDP Next Header 为 17。相同 discovery fixture 在 IPv4/IPv6 中 Magic、Length、Version、Kind、Nonce、NodeID 和 FrameEnd 必须一致；相同 storage fixture 也只改变地址族和 payload offset。

多会话场景至少建立两个 SessionID，并分别执行一个 STORE 与一个 RETRIEVE；多流场景至少使用两个 StreamID，并交织不同 chunk request。验证使用 SessionID、StreamID、CorrelationID、chunk_address 和 tcp.stream 关联，不硬编码跨流 packet index。两个地址族应使用独立 fixture，不能在单一 layer-chain 顶层配置中混入 IPv4 与 IPv6。

边界至少覆盖：UDP discovery 最小/最大 endpoint、TCP Length=26 最小 frame、TLV FieldLength=0、chunk_size=0、最大受支持 chunk、fragment_count=1、fragment_count 上界、uint64 sequence/correlation 边界、MSS 分段、空 manifest entry、重复 ACK 和 close 后业务 frame。长度加法、fragment index、chunk offset 和 frame_max 检查必须拒绝溢出，不得回绕或分配 `0xffffffff` bytes。

## 8. 配置 typedef（类型定义）

以下是设计契约，不是当前存在的 Go struct（结构体）：

```go
type SwarmConfig struct {
    Profile      string             `json:"profile"`
    Discovery    *SwarmDiscovery    `json:"discovery,omitempty"`
    FrameMax     uint32             `json:"frame_max"`
    Heartbeat    uint16             `json:"heartbeat"`
    Connections  []SwarmConnection  `json:"connections"`
    WireFault    string             `json:"wire_fault"` // 仅负例
}

type SwarmDiscovery struct {
    SrcIP, DstIP string       `json:"src_ip"`
    SrcPort, DstPort uint16  `json:"src_port"`
    Events       []SwarmEvent `json:"events"`
}

type SwarmConnection struct {
    Carrier     string          `json:"carrier"` // tcp or udp
    SrcIP, DstIP string         `json:"src_ip"`
    SrcPort, DstPort uint16     `json:"src_port"`
    Sessions    []SwarmSession  `json:"sessions"`
}

type SwarmSession struct {
    SessionID uint64       `json:"session_id"`
    Streams   []SwarmStream `json:"streams"`
}

type SwarmStream struct {
    StreamID uint32       `json:"stream_id"`
    Events   []SwarmEvent `json:"events"`
}

type SwarmEvent struct {
    Kind          string   `json:"kind"`
    Direction     string   `json:"direction"`
    CorrelationID uint64   `json:"correlation_id"`
    MessageID     uint64   `json:"message_id"`
    Sequence      uint64   `json:"sequence"`
    ChunkAddress  []byte   `json:"chunk_address"`
    ChunkOffset   uint32   `json:"chunk_offset"`
    ChunkSize     uint32   `json:"chunk_size"`
    Payload       []byte   `json:"payload"`
    FragmentIndex uint16   `json:"fragment_index"`
    FragmentCount uint16   `json:"fragment_count"`
}
```

Validate 必须覆盖 profile、UDP/TCP carrier、端口、Magic、Version/Kind/Flags/Length/FrameEnd、TLV 边界、NodeID/chunk address、握手方向、SessionID/StreamID、CorrelationID、chunk 完整性、fragment 重组、ACK 关联、多连接/会话/流和 wire fault。`wire_fault` 只能注入失败，不得成为线上字段或被忽略。

## 9. 错误处理、实现集成和完成定义

| 错误 | 稳定错误锚点 |
|---|---|
| Magic、Version、Kind、Flags、Length 或 FrameEnd 非法 | `frame` / `length` / `version` |
| UDP/TCP carrier、端口或地址族与 profile 不一致 | `transport` / `udp` / `tcp` / `port` |
| HELLO/AUTH/OPEN_SESSION 顺序或方向错误 | `handshake` / `auth` / `session` |
| SessionID/StreamID 未打开、跨连接或关闭后引用 | `session` / `stream` / `connection` |
| chunk address、chunk_size、offset 或 payload 不一致 | `chunk` / `address` / `length` |
| fragment 缺失、重复、越界或重组长度错误 | `fragment` / `reassembly` |
| CorrelationID、message、sequence 或 ACK 不一致 | `correlation` / `message` / `sequence` / `ack` |

实现时应登记 `swarm` 为可选 carrier 的 Terminal layer，按 profile 依赖 `udp` 或 `tcp`，复用 TCP MSS/checksum 和 IPv4/IPv6 builder；TCP storage 按 stream 重组后解析 Length，UDP discovery 按 datagram 验证。所有 planner/validator 错误须传播为 task error。

## 10. 原子 ID 与完成定义

设计、testcase 和 JSON 必须按以下同一顺序使用 20 个唯一语义 ID：14 个正例、6 个负例。

| # | ID | 类型 | 覆盖 |
|---:|---|---|---|
| 1 | `swarm_discovery_ipv4` | 正 | UDP/IPv4 discovery PING/PONG |
| 2 | `swarm_handshake_tcp_ipv4` | 正 | TCP/IPv4 HELLO/AUTH |
| 3 | `swarm_session_open_close` | 正 | OPEN_SESSION/OPEN_OK/CLOSE/CLOSE_OK |
| 4 | `swarm_chunk_store` | 正 | content-addressed STORE/STORE_OK |
| 5 | `swarm_chunk_retrieve` | 正 | RETRIEVE/CHUNK、CorrelationID |
| 6 | `swarm_chunk_delivery_ack` | 正 | MESSAGE_ACK、chunk/message 关联 |
| 7 | `swarm_manifest_exchange` | 正 | manifest root/entry 和 chunk 引用 |
| 8 | `swarm_stream_multiplex` | 正 | 多 StreamID、交织请求和状态隔离 |
| 9 | `swarm_multi_session` | 正 | 单连接多 SessionID 隔离 |
| 10 | `swarm_ipv6` | 正 | IPv6 UDP/TCP、Next Header 和 offset |
| 11 | `swarm_ipv4_ipv6_same_payload` | 正 | 两地址族逻辑 payload 一致 |
| 12 | `swarm_binary_chunk` | 正 | binary/base64 chunk payload |
| 13 | `swarm_fragment_reassembly` | 正 | chunk fragment index/count/重组 |
| 14 | `swarm_frame_boundary` | 正 | discovery/storage 长度和字段边界 |
| 15 | `swarm_neg_frame_encoding` | 负 | Magic/Version/Kind/Flags/Length/End 错误 |
| 16 | `swarm_neg_handshake_state` | 负 | discovery、HELLO/AUTH/session 状态错误 |
| 17 | `swarm_neg_chunk_integrity` | 负 | 地址、长度、offset、fragment 完整性错误 |
| 18 | `swarm_neg_session_reference` | 负 | 未打开、已关闭或跨连接 session/stream |
| 19 | `swarm_neg_ack_correlation` | 负 | ACK 未知 message/chunk 或跨 stream |
| 20 | `swarm_neg_transport_profile` | 负 | UDP/TCP carrier、端口、profile 不匹配 |

目标完成定义：discovery/storage 的 `swarm` 层链已注册；逐字节生成 discovery/storage frame、TLV、chunk 和 manifest；握手、会话、流复用、内容存取、确认、分片和关闭状态可观测；IPv4/IPv6、多会话、多流、MSS 重组和边界均有集成测试；20 个语义 ID 的正负断言和错误传播完成。当前实现已注册且 cases 已迁移，但 C4 的最大 chunk、fragment 上界、MSS 分段和空 manifest entry 仍登记为缺口，不能宣称目标完成。

## 11. 层链迁移契约（D1-D8，2026-09-30）

| ID | 结论 | 证据/去向 |
|---|---|---|
| D1 | 地址只住 `layers[].ip.src/dst`；端口只住 `layers[].udp`/`layers[].tcp` 的 `src_port/dst_port`；数量只住用例兄弟键 `strategy_fc`/策略 `flow_control` | 20 例机读审计；迁移后非负例顶层仅 `layers` |
| D2 | `swarm` 是终结层，标准链为 `[{ip},{udp},{swarm}]`（discovery）或 `[{ip},{tcp},{swarm}]`（storage）；`swarm` 配置住同名层 | `registry.go:1782`（DependsOn udp + TransportOn udp/tcp）；20 例全部采用该形 |
| D3 | UDP/TCP 载体由相邻传输层决定，`swarm` 层不得再声明扁平端口 | 20 例层链；discovery 例写 `udp`、storage 例写 `tcp` |
| D4 | `discovery`/`connections[].sessions[].streams[]` 是 Swarm 业务编排字段，留在 `layers[].swarm`；多流封包不从顶层 `count` 推导 | `swarm_stream_multiplex`、`swarm_multi_session` |
| D5 | 顶层 `swarm` 子映射是旧扁平形状，本次已删除；不再以顶层子映射作为配置入口 | 迁移 diff：20 例顶层 `src_ip/dst_ip/src_port/dst_port/swarm` 全部迁入层链 |
| D6 | `strategy_fc` 是用例驱动器字段，不是 `spec_json` 协议配置；本批 20 例均为单流，不使用 | 20 例无 `strategy_fc` 键 |
| D7 | 负例必须保留故意违规输入并带 `expect_error`/`error_contains`，不可为迁移而洗成正例 | 6 条负例逐条保留（N1–N6） |
| D8 | 代码尚未支持的行为只登记缺口，不伪造已覆盖；本次不改生成器 | 下方 D-GAP 表 |

### 11.1 迁移前后形状

正例目标形状（discovery 与 storage 各一例）：

```json
{"layers":[{"ip":{"src":"192.0.2.52","dst":"198.51.100.52"}},
 {"udp":{"src_port":42052,"dst_port":1634}},
 {"swarm":{"discovery":{"src_port":42052,"events":[{"kind":"ping","nonce":4822678189205111}]}}}]}
```

```json
{"layers":[{"ip":{"src":"192.0.2.52","dst":"198.51.100.52"}},
 {"tcp":{"src_port":42052,"dst_port":1634}},
 {"swarm":{"connections":[{"src_port":42052,"events":[{"kind":"hello"},{"kind":"hello_ok"}]}]}}]}
```

迁移前 20 例为 `layers`（仅含载体层与空 `swarm:{}`）+ 顶层 `src_ip/dst_ip/src_port/dst_port` + 顶层 `swarm` 子映射的混用形状；迁移后顶层仅剩 `layers`。帧字节、包号、字段断言与负例锚词未改动。

### 11.2 D-缺口

- D-GAP-1：本次不运行 suite/MCP，不宣称 20 例全量 pcap 绿；帧断言待真实流程（§14）校准后回填结论。
- D-GAP-2：`swarm_neg_transport_profile` 当前输入为 `tcp` 层 + `discovery` 子映射（载体与业务配置错配）且目的端口 1635；实际命中的是 port 校验，`transport` 分支未被单独覆盖，待新增载体错配正例/负例时补。
- D-GAP-3：TCP storage 的握手/挥手包由 TCP 层产生，Swarm 只声明最小业务帧；新增用例不得手算包号，需真实 pcap 校准。
- D-GAP-4：`swarm_frame_boundary` 未覆盖设计 §7 列举的「最大受支持 chunk」「fragment_count 上界」「MSS 分段」「空 manifest entry」四项；待补例。
- D-GAP-5：设计 §8 的 `wire_fault` 枚举面（`bad_magic`/`bad_kind`/`bad_flags`/`bad_frame_end`/`length_overflow` 等）当前仅 `bad_version` 落盘为 N1；其余值待补负例。

## 12. 六项审查清单（C1-C6）

| ID | 审查结论 |
|---|---|
| C1 | JSON 可解析，20 条 ID 唯一，与设计 §10 和 testcase §2 同序一致。 |
| C2 | 非负例顶层仅 `layers`；不存在顶层 `src_ip/dst_ip/src_port/dst_port/count` 或顶层 `swarm` 子映射。 |
| C3 | 地址只在 `ip` 层、端口只在 `udp`/`tcp` 层；协议业务字段只在 `swarm` 层，无游离字段。 |
| C4 | 6 条负例保留错误锚词（`version`/`hello`/`chunk`/`session`/`ack`/`port`），不把配置拒绝冒充协议响应错误。 |
| C5 | 多会话、多流、双栈、分片、边界例均保留，未用「单请求」冒充业务覆盖；实现不足的场景登记 D-GAP。 |
| C6 | 本次范围仅 `design.md`、`testcase.md`、`test/protocol_pcap/cases/swarm.json`；不修改代码、全局索引或其他协议。 |

## 13. 修订记录

- v1.0.0（2026-08-20）：建立 14 个 Swarm storage/discovery 正例、6 个严格负例，覆盖双承载 frame、握手/会话、chunk/manifest、确认、分片、IPv4/IPv6、多会话、多流、边界和错误传播；明确为项目级 wire profile，不修改 Go 实现。
- v1.1.0（2026-09-30）：层链迁移审计：20 例全部改写为严格层链（顶层仅 `layers`），删除未注册占位论述，新增 D1-D8 / C1-C6 / D-GAP-1~5；不改代码、不宣称 suite 已跑。

## 14. D1-D8 / P1 对照补表

### 14.1 P1 规范要求→业务场景→代码现状→缺口矩阵

| 规范要求 | 业务场景 | 代码现状 | 缺口 |
|---|---|---|---|
| 连接模型：UDP discovery、TCP storage 分离 | PING/PONG；HELLO 到 CLOSE | `layer_gen.go` 按 carrier 分支校验并生成 | G-GAP-1：终结层字段表只声明 `profile`，完整业务字段仍经兼容解析路径传递 |
| 消息表：Kind、请求/响应及必选字段 | HELLO/AUTH、STORE/RETRIEVE、ACK | `validateStorage`/`validateDiscovery` 校验顺序与必需关联 | 错误码响应的 wire 断言待补，见 D-GAP-5 |
| 状态机：协商、认证、会话、关闭 | 同连接多轮操作、异常结束 | `validateStorage` 拒绝越序、关闭后新业务帧 | 连接级重试时序尚无独立用例 |
| 字段表：长度、字节序、默认值 | TLV、Length、chunk 和 fragment | 生成器编码固定宽度并校验边界 | 最大 chunk/MSS/空 entry 见 D-GAP-4 |
| 错误处理：格式、引用、完整性 | 六条配置拒绝负例 | 错误返回 planner→task，锚词在 N1–N6 | 其余 `wire_fault` 枚举见 D-GAP-5 |
| 超时与活性：保活、重传 | PING/PONG、显式重传 | planner 不自动无限重试；TCP 由传输层管理 | 长时间保活的真实时间验收待 P5 |
| NAT/代理/地址族 | IPv4/IPv6 独立 fixture | IP 层承载地址；生成器支持 v4/v6 | NAT 改写不属于当前 profile，另立项 |
| 版本/方言：profile 与 Version | `swarm_*_v1`、Version=1 | `ValidateConfig` 拒绝未知 profile/version | profile 跨版本协商用例待补 |

### 14.2 三张子表

命令×响应码矩阵（本 profile 无独立数字响应码，以下为 Kind/错误结果）：

| 请求/消息 | 成功响应 | 错误/当前覆盖 |
|---|---|---|
| PING/HELLO/AUTH/OPEN_SESSION | PONG/HELLO_OK/AUTH_OK/OPEN_OK | N2 顺序错误；D-GAP-5 wire fault |
| STORE/RETRIEVE | STORE_OK/CHUNK | N3 chunk 完整性；N5 ACK 关联 |
| MANIFEST | 无强制响应 | S7 frame 断言；空 entry 见 D-GAP-4 |
| CLOSE | CLOSE_OK | S3 终止；关闭后业务拒绝由状态机覆盖 |

数据形态变体表：

| 形态 | 用例 | 结论 |
|---|---|---|
| UDP/IPv4、UDP/IPv6 discovery | S1、S10 | 已覆盖，offset 42/62 |
| TCP/IPv4、双栈 | S2–S9、S11–S14 | 已覆盖基础形态 |
| binary、zero、fragment | S12、S14、S13 | 已覆盖基础值；上界见 D-GAP-4 |
| 多 Session/Stream | S8、S9 | 已覆盖隔离与交织 |

商业行为→用例映射表（现网行为证据暂以抓包确认）：

| 行为 | 用例 | 证据/确认方式 |
|---|---|---|
| 发现后不自动建立 storage session | S1 | 规范 profile 定义；用真实节点抓 UDP 后 TCP 包确认 |
| 长连接多事务与关闭 | S3–S9 | 设计状态机；用节点抓包确认顺序 |
| binary chunk 与 ACK | S6、S12 | wire profile；用节点抓包确认字段关联 |

### 14.3 三路对照与候选方案

| 规范原文/章节 | 商业软件行为 | 开源实现思路 | 本设计取舍 |
|---|---|---|---|
| 本 profile §3–§6：显式 frame、TLV、状态机 | 节点通常保持 TCP 长连接并复用请求 | libp2p 风格按 stream 管理关联状态 | 采用显式 SessionID/StreamID，不推导自动复制 |
| 本 profile §7：IPv4/IPv6 对称 | 双栈分别建连接 | 独立 transport 实例 | 独立 fixture，不在一条链混地址族 |
| 本 profile §6：chunk 分片 | 大对象按 chunk/fragment 传输 | 流式重组后校验长度 | 先 TCP 重组，再按 Swarm Length/fragment 解析 |

| 候选方案 | 优点 | 缺点 | 结论 |
|---|---|---|---|
| A：业务事件住 `swarm` 终结层，载体由相邻 `udp`/`tcp` 决定 | 配置形状统一，能表达双载体 | 注册表 FieldContract 需补齐业务字段 | 采用；当前 cases 已按此形状迁移 |
| B：为 discovery/storage 各建独立顶层协议入口 | 校验入口直观 | 破坏统一层链，重复地址/端口契约 | 不采用 |

## 15. 实现交付八要素与动态字段清单

| 八要素 | 本协议结论 |
|---|---|
| 文件 | `trafficgen/internal/protocol/swarm/layer_gen.go`、layer planner、三件套 cases/docs |
| 接口 | `ValidateConfig`、`ValidateSpec`、终结层 `Plan/GenRequest` |
| 结构 | `[ip,udp,swarm]` 或 `[ip,tcp,swarm]`；Session/Stream/Event 见 §8 |
| 流程 | carrier 校验→frame 重组→状态校验→逐事件生成 |
| 错误 | planner 返回 error，task 不得 completed/0 packet |
| 性能边界 | 流式事件；frame/chunk 受 `frame_max` 与队列/缓冲限制；实测指标待 P5 |
| 冲突点 | TCP segment 不等于 Swarm frame；业务字段不可伪造为 tshark 字段 |
| 回滚 | 仅回滚本三文件；不改 schema/Go，cases 恢复迁移前版本需重新审计 |

动态字段清单：四元组由 `ip.src/dst` 与 `tcp/udp.src_port/dst_port` 承载；当前 Swarm 生成器没有为这些字段声明五种动态策略。SessionID、StreamID、CorrelationID、Nonce、NodeID、chunk address、sequence、message_id 和 fragment index/count 均是业务字段，当前 cases 使用显式值，未宣称动态支持。序号与生成位置：事件顺序由 `layer_gen.go` 的 `flattenConnection`/逐事件生成路径决定；动态五策略若要开放，须先补 schema/FieldContract/translate 及按流序号测试（G-GAP-1），不得机械把业务键移到顶层。

门 1 三行展开：§1 旧键 `src_ip/dst_ip`→`layers[].ip.src/dst`，`src_port/dst_port`→`layers[].tcp|udp`，`count`→`flow_control`；完整例见 §11.1。§3 五件套为 connections/sessions/streams 表、events 序列、Session/Stream/Correlation 关联、控制帧与业务帧插入点、按连接顺序或 stream 交织时间线（无隐式复制）。§12 四元组与上述业务字段均列为 fixed 现状，动态支持立项 G-GAP-1。
