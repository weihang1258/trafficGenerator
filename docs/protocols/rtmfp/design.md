# RTMFP（实时消息传输协议，Real-Time Media Flow Protocol）设计契约

> 版本：v2.1.0（层链迁移审计）
> 日期：2026-09-30
> 状态：D1–D8/T1–T6/C1–C6 迁移审计已补齐；当前 `rtmfp` cases 为 29 例（16 正、13 负），正例和负例均采用层链入口，三份目标文件已对账。本批只改文档与 cases，不修改 Go 实现，不宣称 suite/NIC 已复跑。
> 配套文件：`docs/protocols/rtmfp/design.md`、`docs/protocols/rtmfp/testcase.md`、`trafficgen/test/protocol_pcap/cases/rtmfp.json`
> 规范基线：Adobe RTMFP specification（Adobe 官方规范，无 IETF 标准轨 RFC；RFC 7016 为 Adobe RTMFP Profile 的 informational 实践记录）。精确章节号待 G-RTMFP-1 对原文复核钉死，本契约只引用文档名不编章节号（§5.7 不编行）。
> **层链唯一真相**：本契约目标形状只有纯 `layers` 形（`[ip,udp,rtmfp]`，IPv6 地址仍住 `ip` 层）；地址只住 `ip`、端口只住 `udp`、数量只走 `flow_control`；存量 24 例的顶层扁平键随 P4 按 §12.1 去向表改写。
> **线格式诚实声明**：引擎 16 字节头（marker/kind/len/session/flow/seq）是**自建契约化确定性编码**，不是 Adobe RTMFP 原始线格式（原始格式为变长 chunk 编码 + HMAC-SHA256 握手 + AES-128 会话加密）；tshark 3.6.14 **无 RTMFP dissector**（实测 `rtmfp.*` 0 字段），加密面 opaque 不冒充可断言——详见 §4 与 G-RTMFP-2。

## 1. 范围、已注册边界与诚实声明

RTMFP 是面向实时音视频和数据流的 UDP 应用协议。它提供 endpoint（端点）之间的握手、会话标识、可靠/不可靠消息流、重传、顺序、拥塞控制和关闭语义；它不是 TCP，也不能把任意 UDP payload（载荷）标为 RTMFP。

本设计覆盖：

- IPv4/IPv6 UDP carrier（承载）和默认端口 1935；
- endpoint discovery（端点发现）、initiator/responder handshake（发起方/响应方握手）、cookie（会话 Cookie）和 session ID（会话标识）关联；
- reliable flow（可靠流）与 unreliable flow（不可靠流）、message sequence（消息序号）、fragment（分片）/reassembly（重组）；
- ping/pong keepalive（保活，显式事件面）、flow control（流量控制）、重传/丢包 fixture（固定样本）、close/error 终止；
- IPv4/IPv6、多 session、多 flow 和同一会话内并行流；
- malformed header（格式错误头）、长度越界、cookie/session 关联错误、序号回退、分片缺失等负路径。

不覆盖：真实 RTMFP 加密线格式（HMAC-SHA256 握手 / AES-128 会话密钥——引擎为明文 fixture 面，`grep -rni "aes|encrypt|crypto"` 于 `internal/protocol/rtmfp/` 零命中，诚实声明 opaque）、TCP/QUIC/WebRTC、Adobe Cirrus/Stratus 服务发现实现、真实 NAT（网络地址转换）行为、编解码器、播放器时钟和 CDN（内容分发网络）。NAT traversal（NAT 穿越）只定义显式 endpoint/cookie 事件，不伪造公网映射结果。

**已注册/已落码现状（P1 实测，行号真实）**：`rtmfp` 终结层已注册（`registry.go:385`，`CategoryTerminal + DependsOn ["udp"]`，注释 `registry.go:380-384`（P1 写作时）；**P4 已补 `TransportOn ["udp"]` + Fields 6 键（P6 行 `registry.go:482` 起；生成表同步）**，业务键走层 config 经 translate 严格解码）；白名单已登记（`protocols.go:47` + `protocols_test.go:32`）；配置结构 `RTMFPConfig/RTMFPSession/RTMFPEvent/RTMFPFragment/RTMFPFault`（`types.go:241-283`，`FlowSpec.RTMFP` `types.go:1705`）；wire 编码 `internal/protocol/rtmfp/builder.go`（201 行：常量 `:11-30`、`buildHeader` `:89-103` 16 字节头、12 个 kind builder）；validator/generator `internal/protocol/rtmfp/planner.go`（312 行：`Generate :20-123`、`validateRTMFPConfig :134-278`、`validateWireFault :281-305` 8 值、注册 `:307-312`）；单元测试 22 个（`rtmfp_test.go` 397 行）；策略子配置解析 `strategy_convert.go:566-568`；端口默认 1935 实际由 `chain_planner.go:975-977` 供给（`validateBaseDstPortHandled` 含 rtmfp `:642`、允许 0 上包 `:811`）；Meta 直传 `chain_planner_translate.go:158` + `generator.go:388`；提交 c12fe77。v1.0.0 所述"层尚未注册/全部占位"已过期，以本段为准（见 §16.2 旧文逐条核对）。

**层链迁移现状（2026-09-30）**：`cases/rtmfp.json` 当前 29 例（16 正/13 负）均已采用层链入口；16 正例与 9 个协议负例为 `[ip,udp,rtmfp]`，4 个链级负例专门验证静态拒绝形状；顶层正例旧地址/端口/count/协议业务键为 0；`translateTerminalConfig` 已提供 `rtmfp` 翻译分支。运行期 suite/NIC 验证不在本批范围，详见 D1–D8/C1–C6。

**层链迁移现状（2026-09-30）**：`cases/rtmfp.json` 当前 29 例（16 正/13 负）均已采用层链入口；16 正例与 9 个协议负例为 `[ip,udp,rtmfp]`，4 个链级负例专门验证静态拒绝形状。顶层正例旧地址/端口/count/协议业务键为 0。纯 layers 运行接线与真实 suite 验证仍不在本批范围，详见 D1–D8/C1–C6。

## 2. 协议栈、端口和偏移

当前机器契约已统一为 `[ip, udp, rtmfp]` 层链；`translateTerminalConfig` 的 `case "rtmfp"` 已接入。RTMFP 明文默认 UDP destination port（目的端口）为 1935（`chain_planner.go:975-977` 用户未显式写时补默认；**`strategy_convert.go:570-571` 注释声称同款默认但无对应调用，属死注释——见 G-RTMFP-3**）；源端口由 session fixture 显式提供（存量 40000–40015 逐例递增；多会话例 `sessions[].src_port` 覆盖，`RTMFPSession.SrcPort` `types.go:253`，生成器 `planner.go:114-116`）。IPv4/IPv6 由外层地址决定，RTMFP message bytes（消息字节）不因地址族改变。

无 VLAN（虚拟局域网）、无 IP options（选项）时，UDP payload 起点为 IPv4 offset（偏移）42（Ethernet 14 + IPv4 20 + UDP 8），IPv6 offset 为 62（14 + IPv6 40 + UDP 8）。UDP datagram（数据报）边界与 RTMFP logical message（逻辑消息）在本引擎内一一对应：**一个事件 = 一个 RTMFP 消息 = 一个 UDP 数据报**（事件驱动 `Generate :20-123` 逐事件 Emit，UDP 层每事件包一 datagram）；分片消息按 `fragment.count` 拆为多个 datagram。这一一对应是引擎契约面，不是 RTMFP 规范要求（规范允许一 datagram 多消息聚合）——属 §11.5 方案 A 的取舍，已声明。

PCAP 的 `packet_count` 在固定发送 fixture 中可承诺（事件数=包数）；**tshark 无 RTMFP dissector，包内字段断言通道只有 UDP 面与 raw frames hex**（§4）。

## 3. 配置 typedef（类型定义，实测 Go struct）

以下为**已落码**的 Go struct（`types.go:241-283`），不是设计期虚构：

```go
type RTMFPConfig struct {
    Profile           string         `json:"profile,omitempty"`            // rtmfp_baseline, rtmfp_low_latency
    Role              string         `json:"role,omitempty"`               // initiator, responder
    KeepaliveInterval int            `json:"keepalive_interval,omitempty"` // seconds（死配置，见 G-RTMFP-5）
    PingCount         int            `json:"ping_count,omitempty"`         // max rounds（死配置，见 G-RTMFP-5）
    WireFault         *RTMFPFault    `json:"wire_fault,omitempty"`         // negative test only
    Sessions          []RTMFPSession `json:"sessions,omitempty"`
}
type RTMFPSession struct {
    SessionID uint32       `json:"session_id,omitempty"`
    SrcPort   uint16       `json:"src_port,omitempty"` // override source port (multi-session)
    Events    []RTMFPEvent `json:"events,omitempty"`
}
type RTMFPEvent struct {
    Kind       string         `json:"kind,omitempty"`      // hello/hello_ack/cookie/session_confirm/reliable/unreliable/fragment/ack/ping/pong/close/error（+retransmit 别名）
    Direction  string         `json:"direction,omitempty"` // c2s, s2c
    FlowID     uint32         `json:"flow_id,omitempty"`
    Sequence   uint32         `json:"sequence,omitempty"`
    Message    string         `json:"message,omitempty"`
    MessageB64 string         `json:"message_b64,omitempty"` // 优先于 message（builder.go:66-77）
    Cookie     string         `json:"cookie,omitempty"`      // 显式 hex；空则按 sessionID 确定性派生（builder.go:80-85）
    SessionID  *uint32        `json:"session_id,omitempty"`  // 事件级 override（跨 session leak 负例面）
    Ranges     [][2]uint32    `json:"ranges,omitempty"`      // ACK ranges [[start,end],...]
    Fragment   *RTMFPFragment `json:"fragment,omitempty"`
}
type RTMFPFragment struct {
    Index       uint32 `json:"index,omitempty"`
    Count       uint32 `json:"count,omitempty"`
    TotalLength uint32 `json:"total_length,omitempty"`
    Payload     string `json:"payload,omitempty"`
}
type RTMFPFault struct {
    Kind     string `json:"kind,omitempty"`     // 8 值见 §8
    Declared uint32 `json:"declared,omitempty"`
    Actual   uint32 `json:"actual,omitempty"`
}
```

| 键 | 类型/约束 | 语义 |
|---|---|---|
| `profile` | `rtmfp_baseline`、`rtmfp_low_latency`（`planner.go:150-152` 白名单） | 选择消息/可靠性 profile；**当前仅校验不消费**（两 profile 线上字节相同，死配置面——G-RTMFP-5） |
| `role` | `initiator`、`responder`（`planner.go:155-157` 白名单） | 握手角色声明；**当前仅校验不消费**（G-RTMFP-5） |
| `sessions` | 有序 session 数组（空拒 `planner.go:145-147`） | 每个 session 独立 4-tuple（`src_port` 覆盖）、session ID、flow 状态 |
| `session_id` | 非负、同一 session 内固定 | response/ACK/close 必须关联正确 session；事件级 override 供 leak 负例 |
| `flow_id` | 正整数；同 session 不重复 | 可靠性、序号状态按 (session,flow) 隔离（`planner.go:32` 键 `[2]uint32`） |
| `events` | 有序握手、数据、保活、关闭事件 | planner 只生成显式事件，不自动无限补发 |
| `kind` | `hello`、`hello_ack`、`cookie`、`session_confirm`、`reliable`、`unreliable`、`fragment`、`ack`、`ping`、`pong`、`close`、`error`（+`retransmit` 别名映射 reliable，`planner.go:44-48`） | **v2.0.0 勘误**：v1.0.0 §3 kind 清单缺 `session_confirm`/`retransmit` 两值，本表按 `builder.go:33-62` 实测补全 12+1 值 |
| `direction` | `c2s`、`s2c`（空/非法拒 `planner.go:181-186`） | 事件方向；udp 层按方向交换端口（c2s: src=会话端口/dst=1935；s2c 反之） |
| `message`/`message_b64` | 文本或 base64 二进制，b64 优先（`builder.go:66-77`） | payload fixture；base64 非法时静默回退文本（实现现状，注记） |
| `sequence` | 非负整数，按 flow 单调 | reliable/fragment 的序号；retransmit 复用原序号且跳过回归检查（`planner.go:61-67`） |
| `fragment` | `index`、`count`、`total_length`、`payload` | index ∈ [0,count) 拒越界（`planner.go:251-259`）；payload 前缀 idx(4)+count(4)+totalLen(4)+data（`builder.go:153-162`） |
| `ranges` | ACK `[[start,end],...]` | 只确认已接收 flow/sequence（`planner.go:230-248` 越界拒）；线格式 ranges_count(2)+[start(4)+end(4)]*（`builder.go:166-176`） |
| `cookie` | 显式 hex 或按 sessionID 派生（`sessionID + sessionID^0xDEADBEEF` 8 字节，`builder.go:80-85`） | handshake 关联；派生值确定性可断言，无需 nonzero 兜底 |
| `wire_fault` | 仅负例，8 值（§8 表） | 注入失败，`planner.go:141-143` 先于一切校验 |
| `flow_control` | 数量/速率（层链路径） | 约束发送，不由 wall-clock（墙上时钟）隐式推断 |

同一 session 的 `cookie`、`session_id`、flow 映射必须保持一致；不同 session 不得复用隐式状态。可靠消息重传（`retransmit`）必须复制 message/flow/sequence，不得把重传伪装成新消息；不可靠消息可以丢弃但不能越过配置声明的边界自动重排。

## 4. 线上布局与可观察字段（实测 16 字节自建头）

**诚实声明（本节最重要的一段）**：本引擎的 RTMFP wire 面是**自建契约化确定性编码**——16 字节头 + payload，字段与 Adobe RTMFP 概念（marker/类型/会话/流/序号）同名但**线格式不等价于 Adobe 原始编码**（原始 RTMFP 为变长 chunk 编码、scrambled mask、HMAC-SHA256 握手、AES-128 加密会话）。选择自建编码的理由与取舍见 §11.5 方案对比；与真实格式对齐属 B′ 立项 **G-RTMFP-2**（迁入计划已在案），本契约不冒充两者等价。

实测头布局（`builder.go:89-103`，全部大端）：

```text
偏移  长度  字段           取值/语义
0     1    marker         0x0C 数据面（reliable/unreliable/fragment/close/error）
                          0x0E 控制面（hello/hello_ack/cookie/session_confirm/ack/ping/pong）
1     1    kind           0x01..0x0C 对应 12 个 kind（builder.go:15-26）
2     2    total_len      HeaderMinLen(16) + payload 长度
4     4    session_id     会话标识
8     12   flow_id        流标识（控制事件为 0）
12    4    sequence       序号（控制事件为 0）
16..       payload        按 kind：cookie(派生 8B/hex)、消息体、fragment 前缀 12B、ack 前缀 2B+N*8B
```

| 逻辑字段 | 约束 | 观察方式（tshark 3.6.14 实测） |
|---|---|---|
| marker/kind/len/session/flow/seq | 见上表 | **无 `rtmfp.*` dissector 字段**（`tshark -G fields \| grep -ci rtmfp` = 0 实测）→ 只能 raw frames hex 断言（offset 42/62 起，逐字节可复算） |
| UDP 端口/方向 | c2s/s2c 交换 | `udp.dstport`/`udp.srcport`（存量 24 例现用通道） |
| cookie | 派生确定性或显式 hex | frames hex（payload 偏移 16 起可复算） |
| fragment idx/count/total | index ∈ [0,count) | frames hex（消息内偏移 16+12 起） |
| payload | message/b64 解码 bytes | frames hex 长度与前缀 |

实现必须拒绝：unknown kind（`planner.go:199-201`/`builder.go:59-61`）、非法 direction、fragment index ≥ count、ack 越界、sequence 回退、close 后残留、跨 session 引用不存在 session（`planner.go:264-275`）。**未注册的 `rtmfp.*` 字段名不得写进机器 JSON 的正例断言**；正例断言通道 = UDP 面 + frames hex（证据等级：raw，已在 testcase 声明）。

## 5. 握手、状态机和生命周期

基线握手由显式事件组成：

```text
UDP hello（c2s）
  → hello_ack（s2c）
  → cookie（s2c，8B 派生或显式 hex）
  → session_confirm（c2s）
  → established：reliable/unreliable/fragment/ack/retransmit
  → ping/pong（显式事件，不自动周期插入）
  → close/error
```

状态与不变式（校验器实现 `planner.go:159-259`）：

| 状态 | 允许事件 | 必须保持 | 校验锚点 |
|---|---|---|---|
| `Idle` | `hello` | direction、UDP carrier、kind/direction 合法 | `planner.go:178-186` |
| `HelloSent` | `hello_ack`/`cookie`/`session_confirm` | response 关联 hello；cookie 非空 | `planner.go:210-212` |
| `Established` | 数据/ack/ping/pong | **未握手前发数据/ack/ping/pong/close 拒** | `planner.go:213-218` |
| `Reliable` | reliable、fragment、retransmit、ack | 序号按 (session,flow) 单调；retransmit 复用原序号 | `planner.go:221-227` |
| `Unreliable` | unreliable | 不承诺重传；不占 reliable 序号 | `builder.go:145-149`（sequence 恒 0） |
| `Keepalive` | ping/pong | 同一 session 关联 | 显式事件面 |
| `Closing` | close/error | **close 后仅允许 close/error**，不再生成新数据 | `planner.go:204-209` |
| `Error` | malformed、越界、关联缺失 | planner/validator → engine → task error；不得 completed/0 packet | `validateWireFault :281-305` |

一个 session 的建议包序列为：hello、hello_ack、cookie、session_confirm、显式 flow data、ack/retransmit（如配置）、ping/pong（如配置）、close。planner 不得隐式增加 handshake、周期保活或媒体帧；事件数与 UDP 包数一一对应。**`keepalive_interval`/`ping_count` 配置键当前零消费**（types.go 声明、planner/builder 不读——显式事件面即有界保活的实现方式，#15 用例的 2 轮 ping 是 events 显式声明而非参数驱动），见 G-RTMFP-5。

## 6. 可靠性、分片和多流

可靠 flow 维护独立发送序号（(session,flow) 键 `planner.go:32`/`planner.go:165`）。重复 ACK 不应创造新数据；retransmit 沿用原 session/flow/sequence 且跳过回归检查（`planner.go:44-48`，否则"丢包后重传"误判回退）。sequence 回退（`planner.go:221-227`/`:61-67` 双侧守卫）、ACK 越过未发送范围（`:230-248`）均为错误。

消息可显式分片：每片携带同一 session/flow/sequence，`fragment.index` 从 0 开始、`index < count`（`planner.go:256-258`），payload 前缀 idx(4)+count(4)+totalLen(4)+data；#6 用例三片同 sequence=8、count=3。缺片、index 越界和跨 session 拼接必须失败（重组侧断言属 frames hex 通道，G-RTMFP-4）。MSS 不适用于 UDP；默认不生成 IP fragmentation。

同一 session 可有多个 flow（#9：flow 1/2/3 音频/视频/元数据同会话交织）。flow 的可靠性和 sequence 独立；多 flow 的 PCAP 调度按事件序顺序回放，断言使用 flow_id 字段（frames hex）+ UDP 端口面，不依赖全局 packet index。多 session 使用独立源端口（#10：40009/40010，`RTMFPSession.SrcPort` 生成器覆盖 `planner.go:114-116`），并隔离 session ID、flow、sequence 和关闭状态。

## 7. IPv4/IPv6、保活和边界

IPv4 外层 EtherType 为 `0x0800`，IPv6 外层为 `0x86dd`、Next Header（下一头）为 17（UDP）。相同 RTMFP fixture 在两种地址族中使用相同逻辑 payload，但必须作为两个独立、同族的 fixture/spec（配置）提交；不得在一个 layer-chain spec 的顶层 IPv4 配置中混入 session 级 IPv6。两个 fixture 的 session/flow 状态彼此隔离。UDP checksum（校验和）由公共 builder 计算，设计不固定运行期 checksum bytes。

**v2.0.0 勘误**：v1.0.0 §7/testcase §4 称 #14 为"两个独立地址族 fixture"——实测存量 `rtmfp_ipv4_ipv6_same_payload` 只有单 IPv4 fixture（192.0.2.10→198.51.100.20:1935），**IPv6 对偶不存在**（IPv6 面只有 #2 独立例）；用例名与实现不符，P4 补 IPv6 对偶 fixture 或改语义 → G-RTMFP-4。

ping/pong 只在事件显式声明时生成（不自动周期插入——`keepalive_interval` 死配置佐证）；保活有界由事件数天然保证，禁止无限实时生成。close 后重复 data、错误方向 close、空 session、零 flow 事件、非法端口、非法地址和超大 body 必须拒绝。合法丢包/retransmit/不可靠传输/业务 error event 是协议正例语义，不能与 malformed input 混为任务错误。

## 8. 错误处理与实现集成点（锚词逐字实测）

wire_fault 8 值（`planner.go:285-304` 逐字）+ 自然守卫（`planner.go:134-278`）：

| 故障 | wire_fault 值 | 稳定错误锚点 | 代码锚点 |
|---|---|---|---|
| header 短于最小长度 | `short_header` | `header` | `planner.go:287`（`header too short`） |
| message length 越界 | `bad_length` | `length` | `planner.go:289`（`length overruns payload`） |
| cookie/session 不匹配 | `session_mismatch` | `session` | `planner.go:291`（`session mismatch`） |
| reliable sequence 回退 | `sequence_regress` | `sequence` | `planner.go:293`（`sequence regression`）+ 自然守卫 `:223-225`/`:63-65` |
| 缺片/index 越界 | `fragment_gap` | `fragment` | `planner.go:295`（`fragment gap`）+ 自然守卫 `:256-258` |
| ACK 未发送 sequence | `ack_unknown` | `ack` | `planner.go:297`（`ack for unknown sequence`）+ 自然守卫 `:244-246` |
| 握手/数据/close 顺序错 | `state_order` | `state` | `planner.go:299`（`state order violation`）+ 自然守卫 `:204-218` |
| 跨 session 状态引用 | `session_leak` | `session` | `planner.go:301`（`session leak`）+ 自然守卫 `:264-275` |
| 未知 profile/role（自然守卫，非 wire_fault；#23 实测用此面） | — | `profile` | `planner.go:150-157`（`unknown profile`/`unknown role`） |
| 未知 wire_fault 值/空 kind | — | `wire_fault` | `planner.go:282-284`/`:303-304` |

合法的 packet loss、retransmit、unreliable drop、业务 error event 是协议正例语义；它们不应被验证器误报为生成失败。

实现集成（已落码面 + P4 差量）：rtmfp 终结层已登记 `registry.go:385`（`DependsOn ["udp"]` 自动补 ip→udp 链底座）；validator/generator 已注册 `planner.go:307-312`；**P4 需补 `translateTerminalConfig` `case "rtmfp"`（层 config JSON 往返解到 `spec.RTMFP`，socks5 分支 `chain_planner_translate.go:2534-2557` 同构）**——不补则纯 layers 形走到 `Meta.RTMFP == nil` 报错（§1 层链翻译缺口）。

## 9. 场景与三方 ID（29 例，实测正负对账）

共 29 个唯一 ID：16 个正例、13 个负例。历史 v1.0.0 的 24 例占位描述已作废；当前机器契约以 D1–D8/C1–C6 迁移审计为准。

| # | ID | 类型 | 覆盖 | 实测包数 |
|---:|---|---|---|---:|
| 1 | `rtmfp_handshake_ipv4` | 正 | IPv4 hello/hello_ack/cookie/session_confirm（4 事件） | 4 |
| 2 | `rtmfp_handshake_ipv6` | 正 | IPv6 UDP 握手（3 事件，无 cookie） | 3 |
| 3 | `rtmfp_reliable_flow` | 正 | reliable message、sequence、s2c ack | 4 |
| 4 | `rtmfp_unreliable_flow` | 正 | unreliable message、无隐式重传 | 3 |
| 5 | `rtmfp_retransmission` | 正 | 同 sequence=7 retransmit 复用 | 5 |
| 6 | `rtmfp_fragment_reassembly` | 正 | 三片 index 0..2、count=3、total_length=9 | 5 |
| 7 | `rtmfp_ping_pong` | 正 | 显式 ping→pong 保活 | 4 |
| 8 | `rtmfp_close` | 正 | close 生命周期终止 | 4 |
| 9 | `rtmfp_multi_flow` | 正 | 同 session flow 1/2/3（reliable×2+unreliable） | 5 |
| 10 | `rtmfp_multi_session` | 正 | 双 session src_port 40009/40010 隔离 | 6 |
| 11 | `rtmfp_loss_and_ack_ranges` | 正 | 丢 sequence=2 fixture、ACK ranges [[1,1],[3,3]]、retransmit | 6 |
| 12 | `rtmfp_binary_payload` | 正 | message_b64（`UkZN`）二进制面 | 3 |
| 13 | `rtmfp_low_latency_profile` | 正 | `rtmfp_low_latency` profile 声明面（死配置注记 G-RTMFP-5） | 3 |
| 14 | `rtmfp_ipv4_ipv6_same_payload` | 正 | 名义双地址族 IPv4 半边 | 3 |
| 15 | `rtmfp_ipv6_same_payload` | 正 | #14 的 IPv6 对偶 fixture | 3 |
| 16 | `rtmfp_keepalive_bounded` | 正 | 2 轮 ping/pong 显式事件 + close（`ping_count=2` 死配置注记） | 7 |
| 17 | `rtmfp_neg_short_header` | 负 | wire_fault `short_header` → `header` | — |
| 18 | `rtmfp_neg_length_overrun` | 负 | wire_fault `bad_length`（declared=999） → `length` | — |
| 19 | `rtmfp_neg_cookie_session` | 负 | wire_fault `session_mismatch` → `session` | — |
| 20 | `rtmfp_neg_sequence_regress` | 负 | wire_fault `sequence_regress` → `sequence` | — |
| 21 | `rtmfp_neg_fragment_gap` | 负 | wire_fault `fragment_gap` → `fragment` | — |
| 22 | `rtmfp_neg_ack_unknown` | 负 | wire_fault `ack_unknown` → `ack` | — |
| 23 | `rtmfp_neg_state_order` | 负 | wire_fault `state_order`（+未握手 reliable 自然面双保险） → `state` | — |
| 24 | `rtmfp_neg_profile_carrier` | 负 | 自然守卫：`profile=unknown_profile`+`role=invalid` → `profile` | — |
| 25 | `rtmfp_neg_session_leak` | 负 | wire_fault `session_leak` → `session` | — |
| 26 | `rtmfp_neg_top_rtmfp_presence_reject` | 负 | 层链与顶层 `rtmfp` 子映射并存 → presence/顶层键错误 | — |
| 27 | `rtmfp_neg_stray_src_ip` | 负 | 顶层游离 `src_ip` → flat config 字段错误 | — |
| 28 | `rtmfp_neg_carrier_tcp` | 负 | `[ip,tcp,rtmfp]` 错误载体 → `carrier` | — |
| 29 | `rtmfp_neg_carrier_missing_udp` | 负 | `[ip,rtmfp]` 缺 UDP 承载 → `carrier` | — |

共 29 个唯一 ID：16 个正例、13 个负例；负例均要求 `expect` 恰含 `expect_error` 与 `error_contains` 两键，链级拒绝例为 #26–#29。

## 10. 修订记录

- v2.0.0（2026-09-26）：P1–P3 完整产物。新增 §11 P1 八项规范矩阵 + 三子表（事件×会话状态矩阵、数据形态变体表、三路对照 §11.4、候选方案对比 §11.5）；§12 门1 §1–§14 十四行表（§1/§3/§12 强制展开 + 目标形状 spec_json 样例 + presence 负例形状）；§13 D-RTMFP-1 P2 代码设计草稿；§14 P3 对接清单；§15 缺口立项（G-RTMFP-1..5）；§16 自重审与核对结论。§1 重写为已注册边界（`registry.go:385` 实测）+ 层链翻译缺口声明；§3 改实测 Go struct（kind 清单勘误补 `session_confirm`/`retransmit`）；§4 改实测 16 字节自建头（线格式诚实声明）；§8 锚词表逐字实测化；§9 勘误"全部占位"失实声明 + 实测包数列。
- v1.0.0（2026-08-20）：建立 RTMFP UDP、握手、cookie/session、可靠/不可靠 flow、ACK/重传、分片、多流、多会话、IPv4/IPv6、保活、关闭和负路径设计；当时层未注册，相关状态声明已过期作废。

## 11. P1 规范矩阵（CORE_MEMORY §4 八项：规范要求→业务场景→代码现状→缺口）

> 深度口径（§4.19–4.22）：矩阵三张子表——①事件×会话状态矩阵（§11.2）②数据形态变体表（§11.3）③商业行为→用例映射表（§12.2）。条目三选一：已实现 / 明确不支持 / 不适用 + 对应用例号；无遗漏留白。
> **UDP 载体铁律（逐矩阵行重申）**：rtmfp rides UDP（registry `DependsOn ["udp"]` + `TransportOn ["udp"]`（P6 行 `:482` 起；P1 写作时 `:386` 且无 TransportOn/OptionalOn——单载体，无 0c355be complete.go:418 OptionalOn 底座豁免面）——TCP 载体判死（`carrier` 锚词，链中夹 tcp 层即错，bacnet 同构）。

### 11.1 八项规范矩阵

| # | 规范要求（Adobe RTMFP spec + RFC 7016 informational + 本契约节） | 业务场景 | 代码现状 | 缺口 |
|---|---|---|---|---|
| 1 | 连接模型：UDP 无连接但**有应用层会话**——hello/cookie/session_confirm 语义握手建立 endpoint 会话，其后双向消息流（Adobe RTMFP spec 握手章；RFC 7016 informational；本契约 §5） | 实时音视频/数据 endpoint 会话建立与消息收发 | 已实现：事件序逐包 Emit（`planner.go:20-123`），UDP 载体/端口交换由链 `[ip,udp,rtmfp]` 承载（c2s/s2c 交换 `planner.go:106-116` 注记 udp 层 rip 波 5c 语义） | 会话语义为自建契约面（§4 诚实声明）；真实线格式对齐 → G-RTMFP-2 |
| 2 | 消息表：控制面（hello/hello_ack/cookie/session_confirm/ack/ping/pong，marker 0x0E）与数据面（reliable/unreliable/fragment/close/error，marker 0x0C）12 kind（本契约 §3/§4 表） | 12 kind 全表逐值编码 | 已实现：kind 常量+builder 17 函数（`builder.go:11-30/:106-201`）、未知 kind 拒（`planner.go:199-201`） | **`error` kind 无用例** → A′ T-26；retransmit 有别名映射（`planner.go:44-48`）#5/#11 已覆 |
| 3 | 状态机：hello→hello_ack→cookie→session_confirm→数据→close；未握手发数据拒、close 后残留拒（本契约 §5 表） | 握手顺序错、未握手先数据、close 后残留 | 已实现：全状态机 `planner.go:196-259`（close 后守卫 `:204-209`、未握手拒 `:213-218`、sequence 回归 `:221-227`、ack 越界 `:230-248`、fragment 校验 `:251-259`、跨 session leak `:264-275`） | 全负路径 13 例已覆（#17–#29）；生成器侧重复守卫（`:61-67`）与校验器对称（防御性双保险，非缺口） |
| 4 | 字段表：16B 头六字段布局、cookie 8B、fragment 前缀 12B、ack ranges 2+8N（本契约 §4） | 逐字段 hex 可复算断言 | 已实现：`buildHeader`（`builder.go:89-103`）+ 12 kind builder；单测 22 个（`rtmfp_test.go`）逐 builder 断言 | tshark 无 dissector → 引擎断言只能 frames hex（16 正例当前 0 frames → G-RTMFP-4）；真实 Adobe 编码差异 → G-RTMFP-2 |
| 5 | 错误处理：wire_fault 8 值 + 自然守卫（kind/direction/profile/role/state/sequence/ack/fragment/leak）（本契约 §8 表） | 脏包、错序、伪造长度一律 task error，零假成功 | 已实现：8 值锚词逐字（`planner.go:285-304`）+ 自然守卫九类（`:134-278` 分散锚点）；负例 9/9 锚词对真实代码行 | 链级红例 4 例 P4 新增（presence/白名单/tcp 载体/缺 udp，§12-P2） |
| 6 | 超时活性：会话保活（ping/pong）与有界终止；空闲超时由 endpoint 侧执行 | 长会话保活 | 已实现：ping/pong 显式事件面（#7/#15）；**周期保活自动调度明确不支持**（`keepalive_interval`/`ping_count` 死配置零消费——显式事件即有界实现，G-RTMFP-5） | 周期保活调度 → 明确不支持（声明式回放族）；死配置清理 → G-RTMFP-5 |
| 7 | NAT/代理：RTMFP 真实协议有 NAT traversal（行程握手/floating 语义）；本引擎只做显式 endpoint/cookie 事件，不伪造公网映射 | NAT 后 endpoint 可达 | 不适用（显式声明，不用"待确认"逃逸）：NAT traversal 语义在 fixture 面无输入输出可表达（映射结果是网络环境函数，非配置函数），无用例 | 真实 NAT traversal → G-RTMFP-2 同族（真实格式对齐时一并裁定）；引擎面无缺口 |
| 8 | 版本方言：Adobe RTMFP（Flash Media Server/FMS 生态）；RFC 7016 为 informational 记录非标准轨；无版本协商字段（引擎面 profile 两值即方言声明） | FMS/Flash Player 会话互通 | 已实现：双 profile 白名单（`planner.go:150-152`）；UDP 1935 默认（`chain_planner.go:975-977`） | 真实 FMS 行为抓包级确认 → G-RTMFP-1；profile 不消费线字节 → G-RTMFP-5 |

### 11.2 子表①：事件×会话状态矩阵（逐格已覆/缺失）

行=事件形状，列=会话状态面：

| 事件 \ 状态面 | 前置满足 | 前置缺失（未握手/未确认） | 关联越界（cookie/序号/范围） | close 后残留 |
|---|---|---|---|---|
| 握手族（hello/hello_ack/cookie/session_confirm） | 已覆 #1/#2 | 不适用（首事件无前置） | 缺口→负例 #18（cookie/session 不匹配） | 不适用（close 后握手族残留由校验器 `:204-209` 同锚 #22 通道，不单独建格） |
| 数据 reliable/unreliable | 已覆 #3/#4 | 缺口→负例 #22（未握手 reliable 自然面） | 缺口→负例 #19（sequence 回退） | 缺口→#22 通道（close 后 data 拒 `:204-206`） |
| retransmit | 已覆 #5（复用原序号） | 缺口→#22 通道 | 缺口→#19 通道（重传 payload/序号变更语义面） | 不适用（close 后重传无独立语义） |
| fragment | 已覆 #6（三片） | 缺口→#22 通道 | 缺口→负例 #20（缺片/index 越界） | 不适用 |
| ack | 已覆 #3（s2c ack）/#11（ranges） | 缺口→#22 通道 | 缺口→负例 #21（ack 未发送 sequence） | 不适用 |
| ping/pong | 已覆 #7 | 缺口→#22 通道 | 不适用（ping/pong 无序号/cookie 域） | 不适用 |
| close/error | 已覆 #8（close）；**error kind 无例 → A′ T-26** | 缺口→#22 通道（close before handshake 拒 `:215-217`） | 不适用 | 已覆 #8 + #22 通道（close 后无新 data 正负双面） |

注：矩阵按**事件×状态前置轴**排——本引擎只做事件回放（声明式事件面），endpoint 对端动态应答只由 frames hex 面验证。**逐格重数（7 行 × 4 列 = 28 格，逐格枚举，可复核）**：**已覆 8 格**（R1c1←#1/#2、R2c1←#3/#4、R3c1←#5、R4c1←#6、R5c1←#3/#11、R6c1←#7、R7c1←#8 close 面〔error 半格→A′ T-26，随 testcase §10.2 记〕、R7c4←#8+#22 双面）；**缺口→用例通道 12 格**（R1c3←#18、R2c2←#22、R2c3←#19、R2c4←#22 通道、R3c2/R3c3←#22/#19 通道、R4c2←#22、R4c3←#20、R5c2←#22、R5c3←#21、R6c2←#22、R7c2←#22）；**不适用 8 格**（R1c2、R1c4、R3c4、R4c4、R5c4、R6c3、R6c4、R7c3，各自注记列已给理由）。8 + 12 + 8 = 28 ✓ **逐格有结论、无空格**。

### 11.3 子表②：数据形态变体表（协议相关全部形态逐项）

| 变体维度 | 形态 | 对应用例 | 备注 |
|---|---|---|---|
| marker 面 | 0x0C 数据 / 0x0E 控制 | #1（0x0E 族）/#3（0x0C 族） | `builder.go:89-93` 双值已覆；断言走 frames hex（G-RTMFP-4） |
| kind 面 | 12 值 | #1–#8、#11 覆 11 值；**error 无例 → A′ T-26** | `builder.go:15-26` 常量全 |
| direction 面 | c2s/s2c + 端口交换 | 全正例（双向事件均在） | `planner.go:106-116` + udp 层交换 |
| session_id 面 | 显式/事件级 override | #10（双 session）/#19/#25（leak/mismatch 负面） | `planner.go:51-54` |
| flow_id 面 | 0（控制）/1/2/3（数据） | #1（0）/#9（1/2/3） | (session,flow) 键隔离 `planner.go:32` |
| sequence 面 | 单调递进/重传复用/分片同值 | #3（1）/#5（7 复用）/#6（8 三片）/–（回退→#19） | `planner.go:221-227` |
| fragment 面 | idx/count/total/payload 四元组 | #6（0..2/count=3/9B）/#20（越界负） | `builder.go:153-162` |
| ack ranges 面 | 单 range/多 range | #3（[[1,1]] 实际单）/#11（[[1,1],[3,3]] 双） | `builder.go:166-176` |
| cookie 面 | hex 显式/确定性派生 | #1（派生：`1 + 1^0xDEADBEEF` 8B 可复算） | `builder.go:80-85`；#18 mismatch 负面 |
| payload 面 | message 文本/message_b64/空 | #3（"fixture"）/#12（`UkZN`）/控制事件（空） | `builder.go:66-77` |
| profile 面 | baseline/low_latency 两值 | 全例 baseline + #13 low_latency | 白名单 `planner.go:150-152`；**不消费线字节 → G-RTMFP-5** |
| 地址族 | IPv4/IPv6 | #1/#2（独立例）；#14 单 fixture 勘误 | offset 42/62；IPv6 例断言仅 UDP 面（ipv6.nxt 断言缺 → G-RTMFP-4） |
| 多会话面 | 双 src_port 扇出 | #10（40009/40010） | `RTMFPSession.SrcPort` `planner.go:114-116` |
| 长度边界 | header 16B 最小/超长 payload | #16/#17 负面 | `HeaderMinLen=16` `builder.go:29` |

### 11.4 P1 三路对照（CORE_MEMORY §4.12–4.15）

**①规范原文**：Adobe RTMFP specification（Adobe 官方规范文档；无 IETF 标准轨 RFC）全文为"必须是什么"底线；RFC 7016（Adobe RTMFP Profile for Flash Communication，informational）为实践记录参考。握手/会话/流/分片概念四面已落本契约 §3–§6。精确章节号待 G-RTMFP-1 对原文复核钉死（本契约不编章节号——§5.7）。

**②现网行为**：Adobe Flash Media Server / Flash Player 生态经 UDP 1935 建立	RTMFP 会话（端口与 RTMP 共享号段，载体不同 UDP vs TCP）。出处确认方式：抓现网/回环 FMS 会话包核对握手与 chunk 面（**立项 G-RTMFP-1**：现网级确认前相关条目按 §5.5 标"待确认"，不写死进实现）。

**③开源实现思路**：OpenRTMFP/Cumulus（P2P RTMFP 服务器实现，marker 0x0C/0x0E 双面语义借鉴源——本引擎 `builder.go:12-13` 常量即此思路；仓库名/commit 待 G-RTMFP-1 钉）；wireshark 3.6.14 实测**无 RTMFP dissector**（`rtmfp.*` 0 字段、protocols 仅无关 RTmac 命中）——断言通道权威只能是引擎 builder + frames hex，无第三方字段面交叉验证（这正是 G-RTMFP-2 的风险声明）。

**三路结论一致性**：三路在"UDP 1935、marker 双面 0x0C/0x0E、握手 cookie/session 关联、流按 flow_id 复用、会话显式关闭"五点概念一致。取舍：①引擎线格式为自建契约面（非 Adobe 原始编码），确定性可断言优先——§11.5 方案 A；②真实格式/加密对齐未到确认级 → G-RTMFP-2，不写死；③现网 FMS 行为未到确认级 → G-RTMFP-1，不写死。

### 11.5 候选方案对比（§4.17）

| 方案 | 走法（含借鉴来源） | 优 | 劣 | 性能/复杂度/兼容性 | 结论 |
|---|---|---|---|---|---|
| A 自建 16B 头事件驱动回放 | marker/kind/len/session/flow/seq 六字段确定性编码 + 12 kind builder（marker 双面语义借鉴 OpenRTMFP/Cumulus） | 逐字节可复算可断言；无加密依赖；事件驱动流式；已落码 910 行 + 22 单测 | 与 Adobe 原始线格式不等价（chunk/变长/加密）——对外部解码器不可互认 | O(n) 流式；复杂度低；引擎内自洽 | **采用（已落码）**；不等价面 → G-RTMFP-2 迁入计划 |
| B 对齐 Adobe 原始线格式 | 变长 chunk + scrambled mask + HMAC-SHA256 握手 + AES-128 会话加密 | 真实度高、外部互认 | 加密 payload 不可复算断言（fixture 面死亡）；规范未全公开；工程量大 | 每包加密成本；复杂度高 | 不选（本轮）；→ G-RTMFP-2 另轮裁定 |
| C UDP 1935 任意载荷不建协议层 | 不解析不编码 | 零成本 | 违反"不把任意 UDP payload 标为 RTMFP"（底稿铁律）；字段零断言 | 无语义 | 不选 |

## 12. 门1 §1–§14 十四行对照表（CORE_MEMORY §15.1–15.3）

| § | 本协议怎么满足 | 证据 |
|---|---|---|
| §1 层链唯一真相 | 见 §12.1 强制展开：旧键 `src_ip/dst_ip/src_port/dst_port` 四键迁入 `ip`/`udp` 层；顶层 `rtmfp` 子映射迁入 `layers[]` rtmfp 条目；数量走 `flow_control`（存量 24 例均缺该键，P4 补）；目标形状 spec_json 样例见 §12.1；存量 24 例逐键去向见 §12.1 去向表；非负例顶层键=0（presence 负例见 §12-P2） | 本契约 §2（目标形状）+ §12.1 样例与去向表；存量实测 `topkeys=[dst_ip,dst_port,layers,rtmfp,src_ip,src_port]`（24/24 全中）、`layers=[{udp:{}},{rtmfp:{}}]`（29/29） |
| §2 策略/任务 | 策略=单 RTMFP 会话模板（自带 `flow_control` flows/bps/time）；任务=多策略合跑+总量封顶；框架语义未动 | 本契约 §11.1 + §13 |
| §3 五件套 | 见 §12.3 强制展开：会话表/事务序列/关联关系/插入位置/时间线；**UDP 无 TCP 握手诚实写"建连面为应用层会话"**（hello/cookie/session_confirm 语义握手，非 SYN 三次握手），不虚构建连包数 | 本契约 §12.3 + 用例 #1/#10 |
| §4 查规范 | Adobe RTMFP spec + RFC 7016 informational（文档名级引用，精确章节待 G-RTMFP-1）+ tshark 无 dissector 实测（0 字段）+ 已落码 builder wire 真相 + §11 矩阵 8 行+三子表 + 三路对照（§11.4） | 本契约 §11 |
| §5 依赖与错误 | `DependsOn ["udp"]` + `TransportOn ["udp"]`（P6 行 `registry.go:482`；P1 写作时 386 且无 TransportOn/OptionalOn）；wire_fault 8 值 + 自然守卫（§8 锚词表逐字，行号实测）；失败返回 task error（零假成功） | 本契约 §2/§8 + §13 错误分支 |
| §6 性能 | 单事件流式渲染无全量聚合；pcap/NIC 双路验收；吞吐/并发/内存目标待 P4 基准后定（§6.5 诚实待确认，不写承诺数字）；六类场景清单见 §13 | §13 性能设计与验收 |
| §7 三份文档 | 48-rtmfp-{design,testcase}.md v2.0.0（行为面权威）+ D-RTMFP-1（本契约 §13 草稿，门1 获批=定稿）+ T-RTMFP（testcase §10 草稿）+ generated schema（rtmfp 已在 124 层内，P4 只跑 `TestLayersGeneratedMatchesRegistry` 验证无过期） | 修订记录 |
| §8 设计先行 | 本条目 P1–P3 先于 P4 层链整形开工；门1 获批=D-RTMFP-1 定稿=开工门 | 提交序 |
| §9 测试三源 | 三源=Adobe RTMFP spec/RFC 7016 条款（文档名级，精确章节待 G-RTMFP-1）+ D-RTMFP-1 + builder wire 真相（tshark 无 dissector，无第三方字段面——诚实降级 frames hex）+ 现网 FMS 形态（未确认级→G-RTMFP-1）；29 ID 正负对账 | T-RTMFP（testcase §10） |
| §10 评审闭环 | 每阶段对抗自重审（结论见 p123 报告）+ 收官隔离复审 + 修轮；红先绿后 | /tmp/pipe/74-rtmfp/p123-report.md |
| §11 白话 | 每阶段白话一句先行 | 汇报 |
| §12 动态清单 | 见 §12.12 强制展开：四元组=ip/udp 层（五策略全支持）；业务字段逐个列开/不开+理由；序号算法位置=layer_dyn.go:770 + worker.go:307-308（实测行号） | 本契约 §12.12 |
| §13 schema 派生 | registry rtmfp 行（P6 行 `:482`：`DependsOn ["udp"]` + `TransportOn ["udp"]` + Fields 6 键；P1 写作时空 Fields、业务键走 FlowMeta 直传；端口 1935 缺省 `chain_planner.go:1039-1042`（P6 行；P1 写作时 975-977），strategy_convert `:570` 死注释不生效）→ schemagen 重跑验证；struct 标签字面量锁 | §13 接线件 |
| §14 真实流程 | suite 经 MCP 建任务→引擎生成→UDP 字段 + frames hex 双通道（无 `rtmfp.*` 字段面——tshark 3.6.14 实测 0）；先跑后钉；pcap 落 `/tmp/mcp-pcaps/rtmfp/` | 用例 §1/§10 |

### 12.1 §1 强制展开：旧键去向 + 完整 spec_json 样例

旧键清单（`src_ip`/`dst_ip`/`src_port`/`dst_port`/`count` + 本协议顶层子映射 `rtmfp`）：

| 旧键 | 去向 |
|---|---|
| `src_ip` | → `layers[0].ip.src`（IPv4 例 `192.0.2.10`、IPv6 例 `2001:db8:48::10` 起各例 fixture 值保留） |
| `dst_ip` | → `layers[0].ip.dst`（`198.51.100.20` / `2001:db8:48::20` 保留） |
| `src_port` | → `layers[1].udp.src_port`（存量 40000–40015 逐例保留；multi_session 首会话 40009，第二会话住 `sessions[1].src_port` 40010） |
| `dst_port` | → `layers[1].udp.dst_port`（`1935`；与 `chain_planner.go:975-977` 缺省同值，P4 改写时可省略走缺省，但存量显式值保留亦合规） |
| `count`（若有） | → 删除，走 `flow_control.flows`；当前 29 例均未配置，按需显式加入，不放入 RTMFP 层 |
| 顶层 `rtmfp` 子映射 | → `layers[]` 中 `{"rtmfp": {...}}` 条目（业务键 `profile/role/keepalive_interval/ping_count/wire_fault/sessions` 全量迁入，零残留；生成表 Fields 为空、键面以 `RTMFPConfig` 6 键为准） |

**现状：当前 29 例的层链形状与旧迁移记录**：当前所有正例与协议负例已使用 `[ip,udp,rtmfp]`；以下旧去向表仅保存 24 例历史 flat 键如何迁入层链，不能描述当前 cases 状态。

| 现状 | 去向（P4 改写） |
|---|---|
| 顶层 `src_ip`/`dst_ip` | 删除顶层键；新增 `{"ip": {"src": ..., "dst": ...}}` 作为 `layers[0]`（**结构性新增**非仅挪值；IPv6 例 #2 同样补 `ip` 层填 v6 地址） |
| 顶层 `src_port`/`dst_port` | 删除顶层键；写进 `layers` udp 条目（`{"udp": {"src_port": ..., "dst_port": ...}}`） |
| `layers` 内 `{"rtmfp":{}}` 空条目 | 填入顶层 `rtmfp` 子映射全部业务键（`profile`/`role`/`sessions`/`wire_fault` 等） |
| `flow_control` | 当前 JSON 29 例均未配置；需要数量/速率时应显式加入，不能把它放入 RTMFP 层 |
| 负例 `expect` | 当前 13 例均为 `{expect_error, error_contains}` 合法形状；其中 4 例额外验证链级拒绝 |

改写后必须满足：非负例顶层键 = 0（仅 `layers`/`flow_control`/`output` 家族）；负例 `expect` 键集合恰为 `{expect_error, error_contains}`。`expect` 内 `fields`/`frames`/`packet_count` 为 harness 断言键，不计顶层白名单。

完整最小握手样例（目标形状，顶层键仅 `layers`+`flow_control`；`sessions[]` 住 rtmfp 层条目）：

```json
{
  "layers": [
    {"ip": {"src": "192.0.2.10", "dst": "198.51.100.20"}},
    {"udp": {"src_port": 40000, "dst_port": 1935}},
    {"rtmfp": {
      "profile": "rtmfp_baseline",
      "role": "initiator",
      "sessions": [{
        "session_id": 1,
        "events": [
          {"kind": "hello", "direction": "c2s"},
          {"kind": "hello_ack", "direction": "s2c"},
          {"kind": "cookie", "direction": "s2c"},
          {"kind": "session_confirm", "direction": "c2s"}
        ]
      }]
    }}
  ],
  "flow_control": {"flows": 1}
}
```

reliable+ack 样例（#3 目标形状；fragment/ack ranges 同构）：

```json
{
  "layers": [
    {"ip": {"src": "192.0.2.10", "dst": "198.51.100.20"}},
    {"udp": {"src_port": 40002, "dst_port": 1935}},
    {"rtmfp": {
      "profile": "rtmfp_baseline",
      "sessions": [{
        "session_id": 3,
        "events": [
          {"kind": "hello", "direction": "c2s"},
          {"kind": "hello_ack", "direction": "s2c"},
          {"kind": "reliable", "flow_id": 1, "sequence": 1, "message": "fixture", "direction": "c2s"},
          {"kind": "ack", "flow_id": 1, "sequence": 1, "direction": "s2c"}
        ]
      }]
    }}
  ],
  "flow_control": {"flows": 1}
}
```

**P4 前置代码差量（历史计划，已完成）**：`translateTerminalConfig` 的 `case "rtmfp"` 已接入，层 config JSON 往返解到 `spec.RTMFP`；当前状态与 D1–D8/C1–C6 一致。

### 12.2 子表③：商业行为→用例映射表（CORE_MEMORY §4.16；缺此表按 §4.22 记缺口）

| # | 商业行为（产品+行为） | 出处 | 对应用例 | 状态 |
|---|---|---|---|---|
| 1 | endpoint 会话建立（hello→hello_ack→cookie→session_confirm） | Adobe RTMFP spec 概念面（FMS 生态；现网抓包级确认 → G-RTMFP-1） | #1/#2（IPv4/IPv6 握手） | 已映射；确认 → G-RTMFP-1 |
| 2 | 可靠消息收发与确认（reliable→ack，序号） | 同上 | #3/#5（含 retransmit） | 已映射 |
| 3 | 不可靠消息（unreliable，无重传） | 同上 | #4 | 已映射 |
| 4 | 大消息分片重组（fragment idx/count/total） | 同上 | #6 | 已映射 |
| 5 | 会话保活（ping/pong）与有界终止 | 同上 | #7/#15（显式事件面） | 已映射；周期自动保活 → 明确不支持（§11.1 #6） |
| 6 | 会话关闭（close/error） | 同上 | #8 | 已映射；error kind 无例 → A′ T-26 |
| 7 | 同会话多流复用（音/视/数据 flow 隔离） | RTMFP 多路复用核心卖点 | #9（flow 1/2/3） | 已映射 |
| 8 | 多会话并行（双 endpoint 会话隔离） | 同上 | #10（40009/40010） | 已映射 |
| 9 | 丢包确认窗口（ranges + retransmit） | 同上 | #11 | 已映射 |
| 10 | 二进制载荷（b64）与 profile 声明 | 引擎 fixture 面 | #12/#13 | 已映射；profile 不消费线字节 → G-RTMFP-5 |
| 11 | 脏包/错序/伪造长度拒收（引擎 planner 拒） | 引擎行为（planner 真实锚词行） | #17–#25 与新增链级 #26–#213 负例 | 已映射 |
| 12 | 真实 RTMFP 加密会话（AES-128）互通 | Adobe spec | 无例 | **明确不支持**（opaque；G-RTMFP-2 另轮裁定），不冒充覆盖 |

注：本表凡记"概念面"但未落抓包证据的，一律挂 G-RTMFP-1 且不写死进实现（§5.5）。

### 12.3 §3 强制展开：五件套（UDP 无连接，应用层会话）

会话表：

| 会话 | profile | 四元组 | 生命周期（诚实：UDP 无 TCP 握手/挥手） |
|---|---|---|---|
| s1 | rtmfp_baseline | `ip.src/dst` + `udp.40000→1935`，session_id=1 | hello→hello_ack→cookie→session_confirm（应用层语义握手）→ 数据/ack/ping → close；一事件一 datagram，无 SYN/FIN |
| s2 | rtmfp_baseline | 同上；`sessions[1].src_port` 40010（#10） | 同构独立会话；session/flow/序号/关闭状态与 s1 隔离 |

事务序列（单事务四件事 §3.4–3.7）：

| 事务 | 前置条件 | 触发动作 | 成功分支 | 失败分支 |
|---|---|---|---|---|
| t1 握手 | UDP 载体可用（udp 层承载） | hello(c2s)→hello_ack/cookie(s2c)→session_confirm(c2s) | 数据/ack/ping 可发 | 未握手先数据 → task error（#22 通道） |
| t2 可靠数据 | t1 完成 | reliable(flow,seq,payload)→ack(ranges) | seq 单调、ack 不越界 | 回退/越界 → task error（#19/#21 通道） |
| t3 分片 | t2 同 flow 同 seq | fragment(index,count,total)×N | 收齐重组（frames hex 断言） | 缺片/越界 → task error（#20 通道） |
| t4 保活 | t1 完成 | ping(c2s)→pong(s2c)（显式事件，有界） | 两包同 session 关联 | 未握手 ping → task error（#22 通道） |
| t5 重传 | t2 已发 seq X | retransmit(flow,seq=X,payload 同) | 复用原序号不递进 | payload 变更语义面 → #19 通道 |
| t6 关闭 | 业务完成 | close/error | close 后仅 close/error | 残留数据 → task error（#22 通道） |

关联关系（§3.8–3.10 三件事）：本协议**无控制流驱动数据流的副流派生**（无 `driven_by` 派生流——UDP 单四元组内多路复用），但有**同会话内流级关联**：归属会话 sN（`sessions[].session_id`）、归属流（`events[].flow_id`）、由 `sequence`/`ranges` 字段决定确认关联——与 CWMP 范本差异点诚实声明：RTMFP 的多流是**同四元组内逻辑流复用**（flow_id 是线上头字段），不是 TCP 式独立四元组副流；§3.10 的"独立四元组/独立握手"面在本协议 = 不适用（UDP 无连接、复用一个 4-tuple 是 RTMFP 规范结构，不是引擎缺口），独立四元组语义由多会话 `sessions[].src_port` 承载（#10）。

插入位置：终结层——rtmfp 事件字节经 udp payload 直传（`L4 Protocol udp`；UDP 载体/端口交换由 udp 层生成器承载）；IP 无 option 时 payload 起点 42（IPv6 62）。

时间线：**顺序**——同会话内 t1→t2→…→t6 严格事件序（`planner.go` 逐事件 Emit，一事件一 datagram）；会话间（#10 双会话）按序整块回放但输出不假设跨会话包序，只断言流内状态与隔离（src_port distinct 已断言 40009/40010）；无"长传输分片让位"独立面（分片即独立 datagram 序列）；控制可中插动作=ping/pong（显式事件）。§3.12 的调度方式在本协议落点为"事件序逐包 Emit、会话间按序整块回放"。

### 12.12 §12 强制展开：动态字段清单

| 字段 | 住处 | 开策略 | 理由 |
|---|---|---|---|
| `src`（src_ip） | ip 层 | fixed/inc/rand/list/pattern 全开 | §12.2 地址必备；多 endpoint 并发锚点 |
| `dst`（dst_ip） | ip 层 | fixed（endpoint 地址 fixture 钉死；多目标地址池待立项） | 单 endpoint 语义；动态多目标 → G-RTMFP-1 同族另议 |
| `src_port` | udp 层 | 全开 + 未写动态保底 `12345+i`（仅 flows>1 生效） | §12.2/§2.8；多会话锚点亦由 `sessions[].src_port` 承载（#10：40009/40010 事件级） |
| `dst_port` | udp 层 | fixed（1935 单档 fixture） | `chain_planner.go:975-977` 缺省与显式写同值；动态端口例另议 |
| `profile` | rtmfp 层 | 不开（两 profile 各自独立模板；且当前不消费线字节） | profile 切换 = 换策略（§2.5），不用动态冒充；死配置 → G-RTMFP-5 |
| `role` | rtmfp 层 | 不开（声明面，不消费） | 同上 |
| `keepalive_interval`/`ping_count` | rtmfp 层 | 不开（死配置，事件显式面已承载） | G-RTMFP-5 清理 |
| `sessions`/`session_id`/`flow_id`/`sequence`/`cookie`/`ranges`/`fragment`/`message` | rtmfp 层 events[]/sessions[] | 不开（fixture 钉死字节） | 消息/流变体靠多事件/多策略（§2.5），不用动态冒充；会话扇出靠 sessions[] 显式声明（§3.1） |

序号算法代码位置（实测）：逐流动态解析 = `internal/core/layer_dyn.go:770`（`resolveLayerTuple`，worker.go:316/`:774` 两路调用）；源端口保底 = `internal/core/worker.go:307-308`（`flowCount > 1 && !spec.HasExplicitSrcPort` 时 `spec.SrcPort = DefaultSrcPort + uint16(i)`，`DefaultSrcPort=12345` 于 `strategy_convert.go:49`）。协议本地无独立序号算法文件（rtmfp 事件字节全 fixture 钉死，动态面仅四元组）——D-RTMFP-1 定稿后 P4 casegen 落码时复核无新增即钉此两处。

### 12-P2 presence 负例形状（链级红例必含①）

层链+顶层空子映射并存=判死负例（presence 负例形状，非残留）：`{"layers":[{"ip":{}},{"udp":{}},{"rtmfp":{}}],"rtmfp":{}}`（顶层空 `rtmfp:{}` 与层链并存）必须 planner/validator 拒，`error_contains` 含 `presence` 或顶层键锚词；P4 链级红例必含此形。白名单外游离键（如顶层 `src_mac`/`ttl`）判死负例见 §13。**另注**：rtmfp 单 UDP 载体 → 链中夹 `tcp` 层（`[ip,tcp,rtmfp]`）判死负例（`carrier` 锚词，bacnet `bacnet_neg_carrier_tcp` 同构）；链缺 `udp`（`[ip,rtmfp]` 直连）判死负例（`carrier` 锚词）。P4 链级红例共 4 例 + 收官自查行「非负例顶层键=0」。

## 13. D-RTMFP-1 P2 代码设计草稿（CORE_MEMORY §8 八要素；门1 获批=定稿）

> 体裁：文件清单/接口签名/数据结构/主流程/错误分支/性能设计与验收/冲突点/回滚方式。rtmfp wire 面已落码（c12fe77），D-RTMFP-1 覆盖"已落码对接 + P4 层链整形差量"，不重发明 wire。

**文件清单（已落码 3 + P4 新建 1 + 接线/守卫，已落码行号实测）**：

| 文件 | 职责 |
|---|---|
| internal/protocol/rtmfp/builder.go（已落码，201 行） | wire 纯函数：常量（`:11-30` marker 双值/12 kind/HeaderMinLen=16）/`kindCode`（`:33-62`）/`resolveBody`（`:66-77` b64 优先）/`cookieBytes`（`:80-85` 确定性派生）/`buildHeader`（`:89-103` 16B 头）/`buildHello`（`:106`）/`buildHelloAck`（`:111`）/`buildCookie`（`:116`）/`buildSessionConfirm`（`:133`）/`buildReliable`（`:138`）/`buildUnreliable`（`:145`）/`buildFragment`（`:153` 前缀 12B）/`buildAck`（`:166` 前缀 2+8N）/`buildPing`（`:179`）/`buildPong`（`:184`）/`buildClose`（`:189`）/`buildError`（`:194`） |
| internal/protocol/rtmfp/planner.go（已落码，312 行） | `RTMFPGenerator.Generate`（`:20-123`：retransmit 别名 `:44-48`、事件级 session_id `:51-54`、序号回归守卫 `:61-67`、12 kind 分支 `:72-104`、方向/端口 `:106-116`）/`GenEvents`（`:126`）/`EmitEvent` 拒（`:129-131`）/`validateRTMFPConfig`（`:134-278`：wire_fault 前置 `:141-143`、sessions 必填 `:145-147`、profile `:150-152`、role `:155-157`、kind/direction `:178-201`、状态机 `:204-218`、序号 `:221-227`、ack `:230-248`、fragment `:251-259`、leak `:264-275`）/`validateWireFault`（`:281-305` 8 值）/注册（`:307-312`） |
| internal/core/types.go（已落码） | `RTMFPConfig`（`:241-248` 6 键）+ `RTMFPSession`（`:251-255` 3 键）+ `RTMFPEvent`（`:258-270` 10 键）+ `RTMFPFragment`（`:273-278` 4 键）+ `RTMFPFault`（`:281-284` 3 键）+ `FlowSpec.RTMFP`（`:1705`） |
| internal/protocol/rtmfp/rtmfp_test.go（已落码，397 行） | 单元测试 22 个（P4 复用，不改口径） |
| internal/protocol/rtmfp/casegen_test.go（P4 NEW） | 一次性生成器：29 例（16 正+13 负，其中 4 链级红例）逐例 add()，落 test/protocol_pcap/cases/rtmfp.json（层链整形后形状） |
| 接线件（已落码，P4 只验证） | registry P6 行 `:482`（`DependsOn ["udp"]` + `TransportOn ["udp"]` + 6 键；P1 写作时 `:385-387` 单载体无 FieldContract）；`protocols.go:47` 白名单 + `protocols_test.go:32` 同步；`strategy_convert.go:566-568` 子配置解析（`:570-571` 死注释）；`chain_planner.go:642`（validateBaseDstPortHandled）/`:811`（允许 0 上包）/`:975-977`（端口默认 1935）；`chain_planner_translate.go:158` + `generator.go:388` Meta 直传；schemagen 重跑验证无过期 |
| P4 新增翻译分支 | `chain_planner_translate.go` 的 `case "rtmfp"` 已接入，层 config JSON 往返解 `spec.RTMFP`；本批只复核现状，不修改 Go |
| P4 新增守卫 | validate_layers 预检：presence（层链+顶层空子映射并存拒）/白名单外游离键拒/链夹 tcp 拒/缺 udp 拒（单载体，无 OptionalOn 面——0c355be complete.go:418 豁免与本协议无涉） |
| tools/coverage_gate.py | check_rtmfp（准入接线/关键件/守卫/用例面四段，P4 登记——当前 grep 计 0，出口 2 视红） |

**接口签名**（已落码，P4 落码钉死有无差量）：`buildHeader(kind byte, sessionID, flowID, sequence uint32, payloadLen int) []byte` / `buildCookie(sessionID uint32, cookie string) []byte` / `buildReliable(sessionID, flowID, sequence uint32, body []byte) []byte` / `buildFragment(...idx, count, totalLen uint32, data []byte) []byte` / `buildAck(sessionID, flowID, sequence uint32, ranges [][2]uint32) []byte` / `RTMFPGenerator.Generate(ctx, req) error` / `validateRTMFPConfig(spec *core.FlowSpec) error`。

**数据结构**：沿 `RTMFPConfig`（types.go:241，6 键）+ 层链目标形状（§12.1 样例：地址住 `ip`、端口住 `udp`、业务住 `rtmfp` 条目、数量走 `flow_control`）。

**主流程**：validateSpec（含 P4 新增 4 守卫）→ translateTerminalConfig `case "rtmfp"`（P4 新增）→ 逐会话逐事件渲染（12 kind builder 分支，一事件一 datagram）→ EmitMsg → udp 层 wrap（方向端口交换）→ worker → pcap/NIC。

**错误分支（§5.2）**：①`wire_fault` 8 值注入拒（`validateWireFault`，锚词进断言，值面=§8 表逐字：`header`/`length`/`session`/`sequence`/`fragment`/`ack`/`state` + leak `session`）；②自然守卫：空 sessions（`:145`）/未知 profile（`:150`）/未知 role（`:155`）/未知 kind（`:199`）/非法 direction（`:184`）/状态机违例（`:204-218`）/序号回退（`:221`）/ack 越界（`:244`）/fragment 越界（`:256`）/session leak（`:270`）；③validate_layers 预检同步拒（presence/白名单/tcp 载体/缺 udp）；④链路 nil config（`Meta.RTMFP == nil` → `planner.go:25-27`，翻译分支补齐后不触发）。全部传播为 task error，零假成功。

**依赖声明（§5.1）**：依赖 `udp` 层（唯一载体：datagram/checksum/端口交换）；依赖 `ip` 层（寻址，IPv6 地址同层）；无外部 endpoint/密钥依赖。**不含 `tcp` 依赖**（§12-P2 把此列成守卫）。无加密依赖（明文 fixture 面——真实 AES-128 面 → G-RTMFP-2）。

**性能设计与验收（§6.1–6.8）**：O(n) 流式——逐事件渲染直发 EmitMsg 无全量聚合（`Generate` for 循环直发，`planner.go:29-121`）；确定性内存（单事件最大=单 datagram，fixture 级字节；无按包增长结构）；无锁无 sleep（事件驱动，无保活定时器——周期调度显式不支持）；pcap 路实测 + NIC 路注记（过滤器 `udp port 1935`，测试网口按 testing-interface 记忆）；回归口径=rtmfp.json 全量 suite 耗时 ±10%；六类场景（基线/目标规模/压力上限/长运行时/并发交错/背压）P5 跑测覆盖；边界诚实声明：吞吐/并发/内存目标数字待 P4 基准后定（§6.5，不写承诺）。

**与现有逻辑冲突点（§8.7）**：①端口 1935 默认值已由层链 planner 与策略转换路径承接；②`translateTerminalConfig` 的 `rtmfp` case 已接入；③历史 #14 地址族语义与当前新增 IPv6 对偶例按 D7/C4 对账；schemagen 与 registry 继续由后续 suite 校准。

**回滚方式（§8.8）**：P4 差量全量 revert（casegen + 29 例改写 + 翻译分支 + 4 守卫 + coverage 登记）；已落码 wire 面不动；无数据迁移面。

## 14. P3 测试对接清单与缺口立项（T-RTMFP 草稿输入；正文落 testcase 文件）

- §3.15 三项：①同连接多事务序列（握手→数据→ack→重传→保活→close 完整编排）→#3/#5/#11 已覆（单会话 4–6 事务编排）+ #9 多流交织；②非正常结束→13 负例全覆（#17–#29）；③长保活→ping/pong 显式事件 #7/#15 已覆（有界由事件数保证）；**周期自动保活调度明确不支持**（§11.1 #6，声明式回放族）。逐项一例或立项，无空项（明细见 testcase §10.1）。
- A′/B′ 两分类表：见 testcase §10.2（A′=引擎可构建→29 ID 内已覆 + A′ 补例建议 T-26（error kind）/T-27（#14 IPv6 对偶或改语义）；B′=引擎结构缺口→G-RTMFP-2 进 D-条目"明确不解决+迁入计划"）。
- 9.52 对账两行：见 testcase §10.3（清单出处声明 + 对账两行：总数 50 = 已覆 41 + 不适用 8 + A′ 1）。
- 3.14 豁免边界审计：见 testcase §10.4（本协议 UDP 无连接但**不主张任何豁免**：多会话 #10 已覆；同会话多流 #9 已覆；多事务 #3–#11 已覆）。
- 三源回指行：见 testcase §10.5（第三源"已确认现网行为"当前=未确认级，挂 G-RTMFP-1）。
- 断言通道：fields 用 `udp.dstport`/`udp.srcport`（现 130 条已覆）+ frames hex（**内层字节断言面，16 正例当前 0 frames → G-RTMFP-4 补钉**；offset 42/62 两档可复算）；**无 `rtmfp.*` 字段面**（tshark 3.6.14 实测 0——§9.27 断言边界诚实声明）。

## 15. 缺口立项清单（有缺口写"缺口立项"，不许空着）

| 立项号 | 缺口 | 确认方式（三选一） | 去向 |
|---|---|---|---|
| G-RTMFP-1 | 规范基线复核 + 现网证据升级：Adobe RTMFP spec 精确章节号（握手/会话/流/分片四面）；RFC 7016 informational 定位与引用边界；OpenRTMFP/Cumulus 仓库名+commit 钉死；现网 FMS/Flash Player 会话抓包级确认（握手 chunk 面、NAT traversal 行为） | 查 Adobe 规范原文 + RFC 7016 + 抓包（FMS 回环/现网会话） | P4 前置确认项，不挡开工；确认前相关条目按 §5.5"待确认"不写死 |
| G-RTMFP-2 | B′ 行为面：真实 Adobe RTMFP 线格式对齐（变长 chunk、scrambled mask、HMAC-SHA256 握手、AES-128 会话加密）；引擎当前 16B 自建头为契约面（§4 诚实声明）；NAT traversal 语义 | 查 Adobe spec + RFC 7016 + 抓包比对（抓谁：FMS 现网会话） | B′→D-RTMFP-1"明确不解决+迁入计划"（另轮裁定；加密 payload 不可复算断言是结构边界） |
| G-RTMFP-3 | 历史 P4 接线项（翻译分支与策略默认端口）已落码；当前仅需 suite/NIC 运行验证与死配置治理 | 读 `chain_planner_translate.go`/`strategy_convert.go` + 运行期验证 | P4 代码项关闭；C6 运行验证后续登记 |
| G-RTMFP-4 | A′ 断言与地址族扩展：当前 JSON 已含 16 正例与 frames hex；仍需后续运行校准更多 kind/IPv6 对偶和 error kind | 读 builder/planner + 运行期 pcap 落盘校准 | A′ 后续补例，不影响当前 29 ID 权威口径 |
| G-RTMFP-5 | 死配置治理：`role`（校验不消费）、`keepalive_interval`/`ping_count`（types 声明零消费）、`profile`（白名单校验但 baseline/low_latency 线上字节相同——#13 只断 UDP 面）——四个键的"声明面≠线字节"须逐个裁定：删键 / 落实消费 / 保留声明并注记 | 读 types.go/planner.go/builder.go 消费面 grep + 引擎实测同配置换 profile 比对字节 | P4/P5 评估；"明确不支持"面按 1.12 口径：用例配置删掉该字段或注记保留理由 |

## 16. P1/P2/P3 对抗自重审结论（10.11；过 4 轮，末轮干净）

- **P1（§11 矩阵）**：R1 自重审发现 §11.2 逐格重数初稿 9+13+6=28 与表内注记不符（close 后握手族与数据残留双计）→ 改 8+12+8=28 复算一致；R2 逐行核八项矩阵"代码现状"列行号全部实读源文件（builder/planner/types/chain_planner/chain_planner_translate/strategy_convert/worker/layer_dyn），v1 底稿"层尚未注册/全部占位"过期声明按 registry.go:385 + 存量 24 例实测改正；R3 锚词 8 值逐字对 planner.go:285-304、自然守卫逐类对 :134-278；R4 终扫发现 tshark dissector 假设残留（初稿按 amqp/cflow 惯性写了 `rtmfp.*` 字段面通道）→ 实测 `tshark -G fields` 0 命中后全文改"UDP 面+frames hex"双通道并降级证据等级声明。末轮干净。
- **P2（§13 D-条目）**：R1 自审发现初稿漏列 `translateTerminalConfig` 无 rtmfp case 这一 P4 必补项（层链翻译缺口，`grep -n 'case "rtmfp"'` 零命中实证）→ 补入文件清单/冲突点/G-RTMFP-3 三处；R2 核 `strategy_convert.go:570-571` 死注释（对照 rtmp case `:837-839` 有 `setDefaultDstPort` 调用，rtmfp 无）→ 落 G-RTMFP-3 裁定项；R3 末轮干净。
- **P3（testcase §9/§10 + §14/§15）**：R1 自审发现对账两行初稿两个版本数字互斥（§14 写"51=47+1+3"、§16 写"46+1+3=50"）→ 复算统一：总数 50 = 八项 8 + 矩阵 28 + 变体 14；已覆 41 = 八项 8 + 矩阵 20（已覆 8 + 缺口通道 12）+ 变体 13；不适用 8（矩阵格）；A′ 1（变体 error kind → T-26）；41+8+1=50 ✓；R2 核 24 例正负比（16/13）、包数序列（[4,3,4,3,5,5,4,4,5,6,6,3,3,3,7] 共 65 包）、锚词 8 个逐字对 planner.go 真实字符串（`header`/`length`/`session`/`sequence`/`fragment`/`ack`/`state`/`profile`）；R3 末轮干净。

三阶段合计修正 8 处（1 处矩阵算术、1 处过期状态、1 处 dissector 假设、1 处翻译缺口漏列、1 处死注释浮出、1 处对账口径、2 处缺口浮出落立项），末轮均干净。

### 16.1 文档逐条自核对结论（10.1：对规范逐条核对）

- Adobe RTMFP spec/RFC 7016（文档名级引用：握手 cookie/session、流复用、分片、保活、关闭五面）→ 本契约 §3–§6 逐条有落点；精确章节号挂 G-RTMFP-1（§5.5 不写死）。
- 引擎 wire 面对规范的概念映射（marker 双面/kind 分类/session-flow 双键/ack ranges）→ §4 表逐字段对 `builder.go:89-103` 实测一致；自建编码与 Adobe 原始格式的不等价已声明（§4/§11.5/G-RTMFP-2），不冒充等价。
- 与旧需求文档（v1.0.0 design/testcase）逐条核对（10.2）：29 ID 集合、顺序、正负比全部保持；§1/§3/§4/§9 四节勘误（见 16.2）；kind 清单补 `session_confirm`/`retransmit`；其余契约（状态机、负例锚词、IPv6/多流/多会话边界）无删改。

## 17. 层链迁移契约（D1-D8，2026-09-30）

| ID | 结论 | 证据/去向 |
|---|---|---|
| D1 | 地址只住 `layers[].ip`；端口只住 `layers[].udp`；数量/速率若配置只住顶层 `flow_control` | 29 个 `spec_json` 全量机读；正例无顶层地址、端口、count 或业务配置 |
| D2 | RTMFP 是 UDP 终结层，标准链固定为 `[ip,udp,rtmfp]` | 16 正例与 9 个协议负例均为该链；4 个链级负例按故障形状保留专门链 |
| D3 | UDP 负责 datagram、端口方向交换与校验；RTMFP 只产应用事件 | `planner.go` 事件生成与 UDP 层职责；不把 UDP 字段搬入 RTMFP |
| D4 | profile、role、sessions、events 及 RTMFP 业务字段只住 `layers[].rtmfp` | 29 个 case 的 RTMFP 配置均位于终结层；无顶层业务入口正例 |
| D5 | 层链与顶层 `rtmfp` 子映射并存是判死形状 | `rtmfp_neg_top_rtmfp_presence_reject` 专门覆盖；不得把负例当配置入口 |
| D6 | `flow_control` 是策略数量/速率边界，不是 RTMFP 业务字段 | 本批未新增数量语义；按 CORE_MEMORY §2/§1.11 保留结构性顶层白名单 |
| D7 | 迁移不改变既有 ID、顺序、端口 fields、frames、packet_count 或错误锚词 | JSON 机读对账：29 ID 唯一；16 正/13 负；正例断言结构保持 |
| D8 | 未实现的真实加密线格式、周期保活与现网互通继续登记缺口，不伪造覆盖 | G-RTMFP-1/2/5；本批不改 Go、不宣称 suite/NIC 复跑 |

### 17.1 迁移状态与缺口

29/29 case 已为层链入口，顶层旧地址/端口/count/协议业务键为 0；其中 16 正例使用 `[ip,udp,rtmfp]`，9 协议负例同样使用该链，4 个链级负例分别验证 presence、游离地址、错误载体和缺失 UDP。旧文档中的“24 例旧扁平形/纯 layers 今天跑不通”是历史状态，不能作为当前验收结论。G-RTMFP-1/2/4/5 仍按能力边界登记。

## 18. 六项审查清单（C1-C6）

| ID | 覆盖要求 | 当前结论 |
|---|---|---|
| C1 | JSON 可解析、ID 唯一、设计/用例/cases 三方索引一致 | 29/29 JSON 可解析且 ID 唯一；设计表与 testcase 索引需以 29 ID 为准 |
| C2 | 严格层链与地址/端口归属 | 16 正例和 9 协议负例为 `[ip,udp,rtmfp]`；链级负例刻意保留错误链，不计正向能力 |
| C3 | 握手、可靠/不可靠、分片、保活、关闭、多流/多会话 | 16 正例的既有 fields/frames/packet_count 断言保留；不新增虚构断言 |
| C4 | IPv4/IPv6、非默认端口、错误与边界形态 | 正例覆盖 IPv4/IPv6 与 RTMFP 错误锚词；真实加密线格式、现网 NAT 仍为 G-RTMFP-1/2 |
| C5 | validator 负例与静态复制拒绝 | 13 负例均有 `expect_error=true` 与稳定 `error_contains`；presence/游离键/错误载体/缺 UDP 独立登记 |
| C6 | pcap/NIC 双输出全量真实流程校准 | 本批仅静态校验，未运行 suite/NIC/MCP；不宣称通过，待翻译接线与后续实测 |

## 19. 修订记录

- 2026-09-30：按 D1-D8/C1-C6 补齐层链迁移契约，更新 29 例（16 正+13 负）现状；仅改设计、测试契约与 cases。

## 20. 自审结论

自审两轮：第一轮逐条核对 D1-D8、顶层白名单、层顺序、负例分类与 G-RTMFP 缺口；第二轮机读复核 JSON 29 ID、16/13 正负计数及三文件口径，末轮干净。

## 21. 旧文档逐条核对（历史记录）

§1 范围（保留+扩；"未注册"段按实测改写+层链翻译缺口声明）、§2 载体表（保留；端口默认通道实测化+死注释注记）、§3 typedef（保留键面，改实测 Go struct + kind 清单勘误）、§4 布局（保留概念，改实测 16B 自建头+诚实声明）、§5 状态机（保留，补校验锚点列）、§6 可靠性/分片/多流（保留）、§7 边界（保留+#14 勘误）、§8 错误表（保留，锚词实测化）、§9 ID 表（29 ID 逐条保留+实测包数列+勘误注记）、§10 修订记录（追加 v2.0.0）。无旧条目被静默删除。

## P6 附录（2026-09-28，P6 关单主线程）

- P6 判词：**通过**（无 P0/P1；M 级残留 3 项）。suite 29/29（16正+13负）、coverage 76/76、门2 静态四项绿（M-2 新二进制复绿）。
- M-1 本轮勘误（上 5 处：registry TransportOn/Fields、端口缺省行号）：实现侧 P4 已补，文档侧本轮回填。
- M-3 open 维持：suite 缺 mixed-family 负例（family 守卫仅链级单测覆盖），后续轮次补 `[ip(src v4/dst v6),udp,rtmfp]` 负例（锚词 `family`）。
- 248 表：`docs/protocol-designs/248/74-rtmfp-248-table.md`。
