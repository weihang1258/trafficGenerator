# Gnutella（分布式点对点文件检索协议，Gnutella Wire Profile）设计契约

> 版本：v1.0.0（设计阶段）
> 日期：2026-08-20
> 状态：仅设计与 PCAP（抓包文件）用例契约；`gnutella` 层尚未注册，不修改 Go（编程语言）实现，不宣称当前 suite（测试套件）可运行。
> 配套文件：`docs/protocol-designs/53-gnutella-testcase.md`、`trafficgen/test/protocol_pcap/cases/gnutella.json`
> 规范基线：Gnutella 0.6 handshake、Gnutella message header/payload 约定和本项目可观测 wire profile（线协议档案）。

## 1. 范围、profile 和未注册边界

本版定义 Gnutella 节点之间的 TCP 握手、邻居能力协商、Ping/Pong 邻居发现、Query/QueryHit 检索、Push 反向连接、Vendor 扩展、TTL/hops 转发和连接关闭。Gnutella 是消息转发协议，不把 HTTP 下载、BitTorrent、WebSocket、TLS 明文内容或任意搜索结果静默当作 Gnutella message（消息）。

| profile（协议档案） | 承载 | 本版允许内容 | 不从 profile 推导 |
|---|---|---|---|
| `gnutella_v060` | TCP/6346 | HTTP-like handshake、Ping/Pong、Query/QueryHit、Push、Vendor、TTL/hops | 文件实际存在、节点信誉、路由算法或下载内容 |
| `gnutella_ipv6_v1` | TCP/6346 | 同一消息头和 payload，IPv6 地址字段按 profile 编码 | 把 IPv6 地址自动压缩成 IPv4 私有地址 |
| `gnutella_tls_boundary` | TLS/TCP | 仅未来定义加密外层 | 未解密时不声称看见 Gnutella header/payload |

当前仓库没有注册 `gnutella` layer（层）、planner（规划器）、validator（校验器）或生成器。`cases/gnutella.json` 只保留一个 `gnutella_neg_unregistered` 的 `expect_error=true`、`error_contains="unknown layer"` 占位；该占位不计入下文 20 个语义 ID，不得把拒绝、0 包或空 PCAP 报告为 Gnutella 行为通过。

本版将 Gnutella 0.6 的常见线上布局固定为项目测试 profile；真实实现接入时仍需逐字段对照选定版本和扩展规范，不能把历史客户端私有 Vendor 消息当成通用字段。

## 2. 协议栈、端口和固定偏移

推荐层链为 `[ip, tcp, gnutella]`。明文邻居连接默认 TCP destination port（目的端口）为 6346，源端口由 fixture（固定样本）显式给出；端口可覆盖但不能由 planner（规划器）悄然改写。UDP、裸 IP、HTTP 下载、BitTorrent 和 WebSocket 不得静默转换为本版载体。

无 VLAN（虚拟局域网）、IP options（IP 选项）和 TCP options 时，TCP application payload（应用载荷）起点为 IPv4 offset（偏移）54（Ethernet 14 + IPv4 20 + TCP 20），IPv6 offset 为 74（14 + IPv6 40 + TCP 20）。TCP segment（分段）边界不是 Gnutella message 边界；握手行和二进制消息均须按 TCP stream（字节流）重组。

## 3. 握手和消息头编码

### 3.1 Gnutella 0.6 handshake

握手使用 HTTP-like ASCII 行和 CRLF（回车换行）边界：

```text
GNUTELLA CONNECT/0.6\r\n
User-Agent: <token>\r\n
X-Query-Routing: 0.1\r\n
X-Ultrapeer: True|False\r\n
X-Node: <node-id>\r\n
\r\n
GNUTELLA/0.6 200 OK\r\n
X-Query-Routing: 0.1\r\n
X-Ultrapeer: True|False\r\n
X-Node: <node-id>\r\n
\r\n
```

字段名比较按 profile 规则处理；未知或重复冲突的能力字段必须显式拒绝或进入 profile 定义的扩展表，不能静默覆盖。握手响应必须在业务 message 前出现；拒绝响应 `GNUTELLA/0.6 503 ...` 是可观测业务结果，不等同 planner error。

### 3.2 二进制 message header

每条业务消息使用 23 字节头：

```text
MessageID(16) | Descriptor(1) | TTL(1) | Hops(1) | PayloadLength(4) | Payload(N)
```

`MessageID` 是 GUID（全局唯一标识）字节串；`Descriptor` 由 profile 定义为 `0x00 PING`、`0x01 PONG`、`0x40 PUSH`、`0x80 QUERY`、`0x81 QUERY_HIT`，Vendor 扩展使用 `0x31`；`TTL` 和 `Hops` 为无符号 8 位值，转发时 TTL 递减、Hops 递增；`TTL + Hops` 不得回绕。`PayloadLength` 为小端 uint32，表示仅 payload 长度，不包含 23 字节头。

消息总长度为 `23 + PayloadLength`。实现必须限制 `PayloadLength <= frame_max`，不能按未限制长度分配内存；MSS 分段后先按 23 字节头和 payload length 重组完整 message。

## 4. Payload 结构和转发语义

| Descriptor | Payload 结构 | 关键关联 |
|---|---|---|
| `PING` | 可选扩展字段 | MessageID、TTL/hops、邻居发现 |
| `PONG` | Port(2)、IPv4/IPv6 Address、Files(4)、KB(4)、可选扩展 | 回应 PING 的 MessageID；地址族和长度一致 |
| `QUERY` | MinSpeed(2)、SearchCriteria（NUL 终止文本） | Query MessageID、TTL/hops、criteria 非空边界 |
| `QUERY_HIT` | Hits(1)、Port(2)、Address、Speed(4)、Result*、ServentID(16) | Query MessageID、命中数和 result 数一致 |
| `PUSH` | ServentID(16)、FileIndex(4)、IPv4/IPv6 Address、Port(2) | QueryHit 的 ServentID/file index/目标节点 |
| `VENDOR` | VendorID(4)、Selector(2)、Version(2)、Payload | 扩展 ID、长度和同一 MessageID |

Gnutella 0.6 的 PONG、QUERY_HIT 和 PUSH 地址字段必须由 profile 显式声明 IPv4 或 IPv6 编码；不得因 outer address family（外层地址族）自动改变 payload 字段长度。`QUERY_HIT.Hits` 必须等于 result 项数，`PUSH.FileIndex` 为无符号 uint32，ServentID 和 QueryHit 目标一致。

转发语义是显式事件：节点只能转发配置中声明的 Ping/Query 或响应，不自动为每条 message 生成无限 fan-out。转发副本复用 MessageID，TTL 减一、Hops 加一；TTL 为零的消息不得继续转发。重复 MessageID 可由 profile 定义去重，但测试不能把重复消息误当新查询。

## 5. 状态机和生命周期

推荐连接序列：

```text
TCP SYN/SYN-ACK/ACK
  → GNUTELLA CONNECT/0.6 + headers
  ← GNUTELLA/0.6 200 OK + headers
  → PING / QUERY / PUSH / VENDOR
  ← PONG / QUERY_HIT / PUSH / VENDOR
  → TCP FIN/ACK 或拒绝响应
```

| 状态 | 允许事件 | 必须保持 |
|---|---|---|
| `TransportReady` | CONNECT request | 首个应用字节是完整握手行 |
| `Negotiating` | 200/503 response、能力头 | 版本、能力、方向一致 |
| `Established` | PING、QUERY、PUSH、VENDOR | 握手成功且 stream 未关闭 |
| `AwaitingPong` | PONG | MessageID 与未完成 PING 对应 |
| `AwaitingQueryHit` | QUERY_HIT、PUSH | Query MessageID、ServentID 和 result 关联 |
| `Closing` | FIN/RST、拒绝响应 | 关闭后不得产生新业务 message |
| `Error` | malformed header/payload、长度、TTL 或关联错误 | planner→engine（引擎）→task error，不能 completed/0 packet |

每个 TCP stream 有独立握手、MessageID 去重、Query、Pong、ServentID 和 Push 状态。多连接不得共享未声明的 QueryHit、PUSH 或能力状态；验证使用 `tcp.stream`、四元组和 MessageID，不硬编码跨流 packet index。

## 6. 配置 typedef（类型定义）

以下是设计契约，不是当前存在的 Go struct（结构体）：

```go
type GnutellaConfig struct {
    Profile      string             `json:"profile"`
    FrameMax     uint32             `json:"frame_max"`
    Connections  []GnutellaConn     `json:"connections"`
    WireFault    string             `json:"wire_fault"` // 仅负例
}

type GnutellaConn struct {
    SrcIP, DstIP string             `json:"src_ip"`
    SrcPort, DstPort uint16         `json:"src_port"`
    Headers      map[string]string  `json:"headers"`
    Events       []GnutellaEvent    `json:"events"`
}

type GnutellaEvent struct {
    Kind          string   `json:"kind"`
    Direction     string   `json:"direction"`
    MessageID     []byte   `json:"message_id"`
    TTL           uint8    `json:"ttl"`
    Hops          uint8    `json:"hops"`
    QueryID       []byte   `json:"query_id"`
    ServentID     []byte   `json:"servent_id"`
    FileIndex     uint32   `json:"file_index"`
    Criteria      string   `json:"criteria"`
    Payload       []byte   `json:"payload"`
    PayloadB64    string   `json:"payload_b64"`
}
```

`Validate` 必须覆盖 profile、TCP carrier/port、握手首行与 CRLF、Header 冲突、MessageID/Descriptor/TTL/Hops/PayloadLength、Ping/Pong/Query/QueryHit/Push 关联、地址族字段长度、TTL 转发边界、多连接/多流和 wire fault。`wire_fault` 只能注入失败，不得成为线上字段或被忽略。

## 7. IPv4/IPv6、多流、多会话和边界

IPv4 outer EtherType 为 `0x0800`；IPv6 outer EtherType 为 `0x86dd`，TCP Next Header（下一头）为 6。相同逻辑消息在 IPv4/IPv6 fixture（固定样本）中 MessageID、Descriptor、TTL、Hops、PayloadLength 和非地址字段必须一致，仅外层地址族及明确声明的地址字段长度变化；双栈用两个独立 fixture，不在一个 layer-chain 顶层混入两种地址族。

多流场景至少使用两个 TCP 四元组，分别完成握手并发送不同 Query；多会话场景使用两个独立连接和不同源端口，Query、Pong、QueryHit、Push 状态不得串用。对同一 Query 的多条 QueryHit 使用相同 Query MessageID、不同 ServentID 或 result，命中数和结果数量必须一致。

边界至少覆盖：空/最大 User-Agent、Header 行 CRLF 截断、MessageID 全零/非零、TTL=0/1/255、Hops=0/255、PayloadLength=0、最小 PING、PONG 地址族长度、Query criteria 空/最大长度、QueryHit Hits=0/最大支持值、Push FileIndex=0/uint32 最大值、MSS 跨帧分段、长度加法溢出和最大明确可分配 payload。不得回绕或分配 `0xffffffff` bytes。

## 8. 错误处理、实现集成和完成定义

以下输入必须由 planner/validator 拒绝并传播为 task error：非 TCP carrier、错误端口或 profile；握手首行/CRLF/状态错误；Message header 截断、未知 Descriptor、PayloadLength 越界；PONG/QUERY_HIT/PUSH 地址字段与 profile 不匹配；QueryHit 与 Query MessageID 不对应；PUSH ServentID/FileIndex 无来源；TTL/Hops 回绕或 TTL=0 继续转发；关闭后继续发业务 message；未知或冲突能力 Header。

合法 503 拒绝、无结果 QueryHit、重复 MessageID 去重、业务 Vendor 扩展、Query 转发丢弃和显式 RST 是协议事件正例，不应被误报为 planner error；malformed input（畸形输入）才进入 task error。

实现时应：

1. 在 layer registry 登记 `gnutella` 为 TCP terminal layer，自动补 `ip→tcp`；
2. 在配置转换器增加 profile、握手 Header、连接和事件配置，保留显式二进制 payload；
3. 新增 Gnutella planner/generator，复用 TCP handshake、MSS segmentation 和 IPv4/IPv6 builder；
4. 按 TCP stream 重组握手与 23 字节 message header，再按 descriptor 解析 payload；
5. 将 planner/validator 错误接入 task 生命周期；实现前禁止把语义正例加入可执行 suite；
6. 先做逐字节 header/payload/TTL/关联单测，再做 planner→worker→TCP PCAP/NIC（网卡）全链路测试和 `-race`（竞态检测）。

## 9. 原子 ID 与完成定义

设计、testcase 和未来 JSON 必须按以下同一顺序使用 20 个唯一语义 ID：14 个正例、6 个负例。当前 JSON 只放额外的 `gnutella_neg_unregistered` 前置占位，不计入 20 个语义 ID。

| # | ID | 类型 | 覆盖 |
|---:|---|---|---|
| 1 | `gnutella_handshake_ipv4` | 正 | TCP/IPv4 CONNECT/200、能力头 |
| 2 | `gnutella_ping_pong` | 正 | PING/PONG、MessageID 和 NodeID |
| 3 | `gnutella_query_queryhit` | 正 | QUERY/QUERY_HIT、命中关联 |
| 4 | `gnutella_push` | 正 | PUSH、ServentID/FileIndex/地址 |
| 5 | `gnutella_vendor_message` | 正 | Vendor 扩展及长度 |
| 6 | `gnutella_forward_ttl_hops` | 正 | MessageID 复用、TTL/Hops 转发 |
| 7 | `gnutella_multi_queryhit` | 正 | 多命中结果和 QueryID |
| 8 | `gnutella_multi_stream` | 正 | 多 TCP stream 状态隔离 |
| 9 | `gnutella_multi_connection` | 正 | 多连接节点状态隔离 |
| 10 | `gnutella_ipv6` | 正 | IPv6/TCP、Next Header=6 |
| 11 | `gnutella_ipv4_ipv6_same_payload` | 正 | 独立双栈逻辑消息一致 |
| 12 | `gnutella_binary_vendor_payload` | 正 | binary/base64 Vendor payload |
| 13 | `gnutella_mss_message_reassembly` | 正 | message 跨 TCP segments 重组 |
| 14 | `gnutella_frame_boundary` | 正 | header、TTL、长度和 payload 边界 |
| 15 | `gnutella_neg_handshake` | 负 | 首行、CRLF、能力和状态错误 |
| 16 | `gnutella_neg_message_header` | 负 | header 截断、Descriptor/length 错误 |
| 17 | `gnutella_neg_ttl_hops` | 负 | TTL/Hops 回绕或非法转发 |
| 18 | `gnutella_neg_query_correlation` | 负 | QueryHit/Push 跨 Query 或节点关联 |
| 19 | `gnutella_neg_payload_encoding` | 负 | PONG/QueryHit/Push 地址和 payload 长度错误 |
| 20 | `gnutella_neg_transport_profile` | 负 | 非 TCP、端口或 profile 不匹配 |

完成定义：注册 `tcp→gnutella` 层链；逐字节生成握手、消息头、Ping/Pong、Query/QueryHit、Push 和 Vendor payload；TTL/hops、关联、多流、IPv4/IPv6、MSS 和边界均可观测；20 个语义 ID 的正负断言和错误传播完成；未注册阶段只接受 `unknown layer` 占位。

## 10. 修订记录

- v1.0.0（2026-08-20）：建立 Gnutella TCP handshake/message wire profile，覆盖邻居发现、检索、命中、Push、Vendor、TTL/hops、IPv4/IPv6、多流、多连接、MSS、边界和 20 个正负语义 ID；当前仅提交设计与用例契约，不修改 Go 实现。
