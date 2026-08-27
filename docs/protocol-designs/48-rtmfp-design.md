# RTMFP（实时消息传输协议，Real-Time Media Flow Protocol）设计契约

> 版本：v1.0.0（设计阶段）
> 日期：2026-08-20
> 状态：已实现（24/24 pcap 通过）。层链 `[ip, udp, rtmfp]`，Generator 事件驱动，Validator 在策略创建时运行。
> 配套文件：`docs/protocol-designs/48-rtmfp-testcase.md`、`trafficgen/test/protocol_pcap/cases/rtmfp.json`
> 规范基线：Adobe RTMFP specification（实时消息传输协议规范）；UDP（用户数据报协议）承载，Adobe AMF（Action Message Format，动作消息格式）编码边界按 profile（档案）显式声明。

## 1. 范围、实现状态和承载边界

RTMFP 是面向实时音视频和数据流的 UDP 应用协议。它提供 endpoint（端点）之间的握手、会话标识、可靠/不可靠消息流、重传、顺序、拥塞控制和关闭语义；它不是 TCP，也不能把任意 UDP payload（载荷）标为 RTMFP。

本设计覆盖：

- IPv4/IPv6 UDP carrier（承载）和默认端口 1935；
- endpoint discovery（端点发现）、initiator/responder handshake（发起方/响应方握手）、cookie（会话 Cookie）和 session ID（会话标识）关联；
- reliable flow（可靠流）与 unreliable flow（不可靠流）、message sequence（消息序号）、fragment（分片）/reassembly（重组）；
- ping/pong keepalive（保活）、flow control（流量控制）、重传/丢包 fixture（固定样本）、close/error 终止；
- IPv4/IPv6、多 session、多 flow 和同一会话内并行流；
- malformed header（格式错误头）、长度越界、cookie/session 关联错误、序号回退、分片缺失等负路径。

不覆盖：TLS/DTLS 加密、TCP/QUIC/HTTP/WebRTC、Adobe Cirrus/Stratus 服务发现实现、真实 NAT（网络地址转换）行为、编解码器、SPS/PPS、播放器时钟和 CDN（内容分发网络）。NAT traversal（NAT 穿越）只定义显式 endpoint/cookie 事件，不伪造公网映射结果。

当前仓库没有 `rtmfp` layer（层）、planner、validator（校验器）或生成实现。所有语义 ID 都是未来契约；当前 JSON 仅使用 `expect_error=true` 与 `error_contains=unknown layer` 占位，不能把拒绝或 0 包报告为 RTMFP 通过。

## 2. 协议栈、端口和偏移

推荐层链为 `[ip, udp, rtmfp]`。RTMFP 明文默认 UDP destination port（目的端口）为 1935；源端口由 session fixture 显式提供。IPv4/IPv6 由外层地址决定，RTMFP message bytes（消息字节）不因地址族改变。

无 VLAN（虚拟局域网）、无 IP options（选项）时，UDP payload 起点为 IPv4 offset（偏移）42（Ethernet 14 + IPv4 20 + UDP 8），IPv6 offset 为 62（14 + IPv6 40 + UDP 8）。UDP datagram（数据报）边界不是 RTMFP logical message（逻辑消息）边界：一个消息可跨多个 RTMFP fragment，多个短消息也可由发送策略放在不同 datagram 中；验证必须按 RTMFP header/length/fragment 规则重组。

PCAP 的 `packet_count` 只在固定发送 fixture 中承诺；重传、ACK（确认）合并和拥塞策略可能改变包数。动态 transaction/cookie/session 字段不应在 `frames` 中固化随机常量。

## 3. 配置 typedef（类型定义）

以下为设计期配置形状，不是当前 Go struct（结构体）：

```json
{
  "layers": [{"udp": {}}, {"rtmfp": {}}],
  "src_ip": "192.0.2.10",
  "dst_ip": "198.51.100.20",
  "src_port": 40000,
  "dst_port": 1935,
  "rtmfp": {
    "profile": "rtmfp_baseline",
    "role": "initiator",
    "sessions": [{
      "session_id": 1,
      "events": [
        {"kind": "hello", "direction": "c2s"},
        {"kind": "hello_ack", "direction": "s2c"},
        {"kind": "reliable", "flow_id": 1, "message": "fixture"},
        {"kind": "close", "direction": "c2s"}
      ]
    }]
  }
}
```

| 键 | 类型/约束 | 语义 |
|---|---|---|
| `profile` | `rtmfp_baseline`、`rtmfp_low_latency` | 选择消息/可靠性 profile；未知 profile 拒绝 |
| `role` | `initiator`、`responder` | 明确握手方向，不从端口猜测 |
| `sessions` | 有序 session 数组 | 每个 session 独立 4-tuple、cookie、session ID、flow 状态 |
| `session_id` | 非负、同一 session 内固定 | response/ACK/close 必须关联正确 session |
| `flow_id` | 正整数；同 session 不重复 | 可靠性、序号、窗口和重传状态按 flow 隔离 |
| `events` | 有序握手、数据、保活、关闭事件 | planner 只生成显式事件，不自动无限补发 |
| `kind` | `hello`、`hello_ack`、`cookie`、`reliable`、`unreliable`、`fragment`、`ack`、`ping`、`pong`、`close`、`error` | 事件类型与线上 header/状态机一致 |
| `direction` | `c2s`、`s2c` | 事件方向；不能以数组位置替代方向 |
| `message`/`message_b64` | 文本或 base64 二进制，二选一 | 作为 AMF/媒体数据 fixture；不能把编码器语义猜入消息 |
| `sequence` | 非负整数，按 flow 单调 | reliable message/fragment 的序号；重传复用原序号 |
| `fragment` | `index`、`count`、`total_length`、`payload` | 组装一个 logical message；count/index/长度必须一致 |
| `ack` | `sequence`、可选 `ranges` | 只确认已接收 flow/sequence；越界 ACK 拒绝 |
| `cookie` | 显式 fixture 或运行期随机值 | handshake 关联；随机值只断言存在/一致，不固化常量 |
| `wire_fault` | 仅负例 | `short_header`、`bad_length`、`session_mismatch`、`sequence_regress`、`fragment_gap` 等 |
| `flow_control` | 窗口/速率的显式 fixture | 约束发送，不由 wall-clock（墙上时钟）隐式推断 |

同一 session 的 `cookie`、`session_id`、flow 映射必须保持一致；不同 session 不得复用隐式状态。可靠消息重传必须复制 message/flow/sequence，不得把重传伪装成新消息；不可靠消息可以丢弃但不能越过配置声明的边界自动重排。

## 4. 线上布局与可观察字段

RTMFP 头字段的具体 bit layout（位布局）由 Adobe profile 决定，planner 必须以注册字段表为唯一来源，不得从普通 UDP 头或 RTMP（实时消息传输协议）头猜测。设计阶段先规定以下逻辑字段：

| 逻辑字段 | 约束 | 未来观察方式 |
|---|---|---|
| packet class/flags | 仅使用 profile 注册的保留位和方向位 | 注册的 `rtmfp.*` 字段或 raw frame |
| session ID | session 内 response/ACK/close 一致 | `rtmfp.session_id` 或 `same_as_packet` |
| flow ID | 同一 session 的流隔离 | `rtmfp.flow_id`、distinct values |
| message/fragment sequence | reliable 单调；重传相等 | `rtmfp.sequence`、same_as_packet |
| message length | 等于 logical message 编码长度 | `rtmfp.length` 与重组 body |
| fragment index/count | index 范围 `[0,count)`，count>0 | `rtmfp.fragment.*` 或 frames |
| ACK/range | 只确认存在的 sequence | `rtmfp.ack.*` |
| cookie | handshake 关联、非零 fixture | `rtmfp.cookie`、same_as_packet |
| payload | AMF/媒体 profile 定义的 bytes | raw frames；不伪造解码字段 |

实现注册后，先用 `tshark -G fields | grep '\trtmfp\.'` 确认可用字段。未注册字段不得写进机器 JSON 的正例断言；若 tshark 没有 RTMFP dissector（解析器），使用 UDP 端口、地址族和重组后的 raw frames，并在 testcase 中明确证据等级。

## 5. 握手、状态机和生命周期

基线握手由显式事件组成：

```text
UDP endpoint discovery/hello
  → responder hello_ack/cookie
  → initiator cookie/session confirmation
  → established
  → reliable/unreliable flow messages
  → ack/retransmit 或 ping/pong
  → close/error
```

状态与不变式：

| 状态 | 允许事件 | 必须保持 |
|---|---|---|
| `Idle` | `hello` | direction、UDP carrier、profile 正确 |
| `HelloSent` | `hello_ack`/`cookie` | response 关联 hello；cookie 非空且不跨 session |
| `Established` | session confirmation、flow open、data | session ID 固定；flow ID 唯一；序号按 flow 管理 |
| `Reliable` | reliable、fragment、ack、retransmit | message 长度、片序、ACK 和重传状态一致 |
| `Unreliable` | unreliable、可选 drop | 不承诺重传；不得误计入 reliable sequence |
| `Keepalive` | ping/pong | 同一 session 关联，超时事件显式配置 |
| `Closing` | close/error | 关闭只影响对应 session；不再生成新数据 |
| `Error` | malformed、超界、关联缺失 | planner/validator → engine（引擎）→ task error；不得 completed/0 packet |

一个 session 的建议包序列为：hello、hello_ack/cookie、session confirmation、显式 flow data、ACK/重传（如配置）、ping/pong（如配置）、close。planner 不得隐式增加 handshake、周期保活或媒体帧；事件数与 UDP 包数不等价。

## 6. 可靠性、分片和多流

可靠 flow 维护独立发送序号、接收确认和重传计数。重复 ACK 不应创造新数据；重传沿用原 session/flow/sequence。sequence 回退、跨 flow ACK、ACK 越过未发送范围和重传 payload 改变均为错误。

消息大于 profile 的 payload limit 时可显式分片。每片携带同一 session/flow/message sequence，`fragment.index` 从 0 开始，`fragment.count` 固定；接收端只有收齐所有片且总长度相等才交付 logical message。缺片、重复片、超范围 index、总长度不一致和跨 session 拼接必须失败。MSS 不适用于 UDP，但 IP fragmentation（IP 分片）不是 RTMFP message fragmentation 的替代品；默认不生成 IP fragmentation。

同一 session 可有多个 flow，例如 metadata（元数据）、audio（音频）和 video（视频）或 data（数据）。flow 的可靠性和 sequence 独立；多 flow 的 PCAP 调度可交织，断言应使用 flow ID/distinct values，不依赖全局 packet index。多 session 使用独立源端口或地址，并隔离 cookie、session ID、flow、sequence 和关闭状态。

## 7. IPv4/IPv6、保活和边界

IPv4 外层 EtherType 为 `0x0800`，IPv6 外层为 `0x86dd`、Next Header（下一头）为 17（UDP）。相同 RTMFP fixture 在两种地址族中使用相同逻辑 payload，但必须作为两个独立、同族的 fixture/spec（配置）提交；不得在一个 layer-chain spec 的顶层 IPv4 配置中混入 session 级 IPv6。两个 fixture 的 session/flow 状态彼此隔离。UDP checksum（校验和）由公共 builder 计算，设计不固定运行期 checksum bytes。

ping/pong 只在事件显式声明时生成；`keepalive_interval` 必须有上界，禁止无限实时生成。close 后重复 data、错误方向 close、空 session、零 flow、非法端口、非法地址和超大 body 必须拒绝。合法丢包/不可靠传输是 profile 语义，不能与 malformed input 混为任务错误。

## 8. 错误处理与实现集成点

以下输入必须由 planner/validator 拒绝并传播为 task error：未知 profile/role/kind、UDP carrier 缺失、非法地址/端口、握手顺序错误、cookie/session 不匹配、重复 flow ID、可靠 sequence 回退、跨 flow ACK、message length 越界、fragment count/index/total length 不一致、缺片、非法保留位、close 后继续发送、跨 session 状态引用。

合法的 packet loss、retransmit、unreliable drop、业务 error event 是协议正例语义；它们不应被验证器误报为生成失败。

实现时应：

1. 在 layer registry 登记 `rtmfp` 为 UDP terminal layer，自动补 `ip→udp`；
2. 在 core/types.go 增加 profile/session/flow/event 配置，并在 strategy converter（策略转换器）保留显式二进制 payload；
3. 新增 planner/generator，复用 UDP/IP builder 和 checksum，不能复用 TCP/RTMP 状态机；
4. 按 session→flow 建立可靠性状态，按事件生成 handshake、ACK、fragment、retransmit、keepalive 和 close；
5. 将 planner 错误接入 task 生命周期；实现前禁止把语义正例加入可执行 suite；
6. 先做逐字节 header/length/sequence/fragment 单测，再做 planner→worker→UDP PCAP/NIC（网卡）全链路测试和 `-race`（竞态检测）。

## 9. 场景与三方 ID

共 24 个唯一 ID：15 个目标正例、9 个负例。当前 JSON 的 24 项全部是未注册层占位，统一 `expect_error=true`、`error_contains=unknown layer`；实现后前 15 项改为 PCAP 断言，后 9 项保留严格 Validate 负例。

| # | ID | 类型 | 覆盖 |
|---:|---|---|---|
| 1 | `rtmfp_handshake_ipv4` | 正 | IPv4 hello/cookie/session establishment |
| 2 | `rtmfp_handshake_ipv6` | 正 | IPv6 UDP handshake、Next Header=17 |
| 3 | `rtmfp_reliable_flow` | 正 | reliable message、sequence、ACK |
| 4 | `rtmfp_unreliable_flow` | 正 | unreliable message、无隐式重传 |
| 5 | `rtmfp_retransmission` | 正 | 同 sequence payload 重传 |
| 6 | `rtmfp_fragment_reassembly` | 正 | 多片、顺序和总长度 |
| 7 | `rtmfp_ping_pong` | 正 | 显式保活和 session 关联 |
| 8 | `rtmfp_close` | 正 | close/error 生命周期 |
| 9 | `rtmfp_multi_flow` | 正 | 同 session 多 flow 隔离 |
| 10 | `rtmfp_multi_session` | 正 | 多 4-tuple、cookie/session 隔离 |
| 11 | `rtmfp_loss_and_ack_ranges` | 正 | 丢包 fixture、ACK range |
| 12 | `rtmfp_binary_payload` | 正 | 显式 binary/base64 payload |
| 13 | `rtmfp_low_latency_profile` | 正 | 低延迟 profile 显式边界 |
| 14 | `rtmfp_ipv4_ipv6_same_payload` | 正 | 两个独立地址族 fixture 使用相同逻辑 payload |
| 15 | `rtmfp_keepalive_bounded` | 正 | 有界保活与终止 |
| 16 | `rtmfp_neg_short_header` | 负 | header 短于 profile 最小长度 |
| 17 | `rtmfp_neg_length_overrun` | 负 | message length 越界 |
| 18 | `rtmfp_neg_cookie_session` | 负 | cookie/session 不匹配 |
| 19 | `rtmfp_neg_sequence_regress` | 负 | reliable sequence 回退 |
| 20 | `rtmfp_neg_fragment_gap` | 负 | 缺片/重复片/总长度不一致 |
| 21 | `rtmfp_neg_ack_unknown` | 负 | ACK 未发送 sequence 或跨 flow |
| 22 | `rtmfp_neg_state_order` | 负 | handshake/data/close 顺序错误 |
| 23 | `rtmfp_neg_profile_carrier` | 负 | profile、role 或 UDP carrier 非法 |
| 24 | `rtmfp_neg_session_leak` | 负 | 跨 session flow/cookie 状态引用 |

## 10. 修订记录

- v1.0.0（2026-08-20）：建立 RTMFP UDP、握手、cookie/session、可靠/不可靠 flow、ACK/重传、分片、多流、多会话、IPv4/IPv6、保活、关闭和负路径设计；不修改 Go 实现。
