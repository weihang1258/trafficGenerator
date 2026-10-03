# #145 gRPC over HTTP/2（h2c）设计契约

> 版本：v1.0.0（as-built 文档轨）
> 日期：2026-09-29
> 机器契约：`trafficgen/test/protocol_pcap/cases/grpc.json`
> 实现：`trafficgen/internal/protocol/grpc/{planner.go,layer_gen.go}`
> 规范基线：RFC 7540/9113（HTTP/2）、RFC 7541（HPACK）、gRPC Protocol over HTTP/2 §4、Protocol Buffers Encoding Guide。

## 0. 范围与实现边界

本契约描述明文 HTTP/2（h2c）上的 gRPC 单 TCP 连接回放：TCP 建连后，客户端发送 HTTP/2 connection preface 与 SETTINGS；双方交换 SETTINGS；每个 gRPC call 使用独立奇数 stream；请求 HEADERS/DATA 后由服务端发送响应 HEADERS/DATA/trailers；连接以 GOAWAY 和 TCP FIN 结束。`grpc` 是 TCP 终结层，registry 中 `CategoryTerminal`、`DependsOn=["tcp"]`，默认目的端口 8604（gRPC 本身不规定端口，8604 是本工程 telemetry 约定）。

实现是声明式脚本回放，不是 gRPC 服务端：不验证真实 RPC schema、HTTP/2 完整状态机或服务端业务结果；响应由配置模板生成。当前传输仅覆盖明文 h2c；`https` 只作为 header 值，TLS 握手、证书与加密记录不在本契约内，属于未覆盖缺口。HPACK 使用静态表与原始字符串，不使用 Huffman；动态表维护结构但不以索引复用动态项。FileSource、raw bytes、base64 protobuf 三种输入均由配置选择。

当前层链目标形状：

```json
{"layers":[{"ip":{"src":"10.0.0.1","dst":"20.0.0.1"}},{"tcp":{"src_port":12345,"dst_port":80}},{"grpc":{"service":"svc","method":"m"}}]}
```

旧式顶层 `grpc` 迁移与 presence/未知顶层键判死不在本协议实现中完成，见 §12 与 §14。

## 1. 五层覆盖与业务场景

| 层 | 已实现行为 | 不适用/缺口 |
|---|---|---|
| 功能 | preface、SETTINGS/ACK、unary/server-stream/client-stream/bidi-stream 编排、HEADERS/DATA/trailers、PING、RST_STREAM、WINDOW_UPDATE、GOAWAY、TCP FIN | 当前 JSON 仅覆盖 unary；其余分支由实现测试覆盖但无 pcap case，见 G-GRPC-2 |
| 性能 | HTTP/2 `MaxFrameSize` 分片；TCP MSS 分段；请求/响应 protobuf 长度前缀；大报文可跨多个 DATA/frame/TCP 段；多 call 共享连接 | 当前 case 未验证跨 MSS、MaxFrameSize 边界、并发流吞吐，见 G-GRPC-3 |
| 数据 | 空 protobuf、raw/base64、gzip、状态码 0–16、超时单位、metadata、authority/scheme、SETTINGS 数值 | 当前 case 仅空请求，未逐项覆盖编码/边界/错误输入 |
| 地址与流 | IPv4/IPv6 由 IP/TCP 透明承载；单连接多 stream，stream id 从 1 起按 2 递增；端口显式/缺省 | 当前 JSON 仅 IPv4；多 stream 与 IPv6 无 case，见 G-GRPC-4 |
| 业务 | 单 unary RPC：`/svc/m`，HTTP/2 200，gRPC status 0，GOAWAY 后优雅 FIN | 多事务/多 call、流式 RPC、取消、保活、重连/异常 RST 未进入 JSON |

现网业务模型：gRPC telemetry/控制调用通常是一条长 TCP/HTTP/2 连接承载多个独立 stream；当前生成器按 `Calls[]` 顺序在同一连接上串行回放，每个 call 共享 SETTINGS/HPACK 状态，不派生子连接。请求与响应按 stream id 配对；trailers 的 `grpc-status` 是该 call 的完成标志。

## 2. 线格式与字段契约

### 2.1 HTTP/2 frame

每帧固定 9 字节头（RFC 7540 §4.1）：`length:24-bit BE | type:8 | flags:8 | stream_id:31-bit BE`，后接 `length` 字节 payload。实现 `buildFrame` 以大端写长度和 stream id，并清除 stream id 最高保留位。主要类型：DATA=0、HEADERS=1、RST_STREAM=3、SETTINGS=4、PING=6、GOAWAY=7、WINDOW_UPDATE=8。`END_STREAM=0x01`、`END_HEADERS=0x04`、SETTINGS/PING ACK=0x01。

### 2.2 connection preface 与 SETTINGS

客户端 payload 首部为固定 24 字节 ASCII `PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n`，紧跟 SETTINGS（type 4、stream 0、无 ACK）。每个 setting 6 字节：identifier 2B BE + value 4B BE；实现按 id 1、2、可选 3、4、5 写入：HEADER_TABLE_SIZE 默认 4096，ENABLE_PUSH=0，INITIAL_WINDOW_SIZE 默认 65535，MAX_FRAME_SIZE 默认 16384，MAX_CONCURRENT_STREAMS 仅非零时写。服务端发送同构 SETTINGS 与空 ACK；客户端再发送空 ACK。SETTINGS_MAX_FRAME_SIZE 合法范围 16384..16777215；INITIAL_WINDOW_SIZE 最大 2147483647。

### 2.3 HPACK 请求/响应头

HPACK literal/index 编码遵循 RFC 7541。请求 HEADERS 必须先写伪首部：`:method=POST`、`:scheme`（默认 `http`）、`:path=/<service>/<method>`、`:authority`（默认目标 host:port，IPv6 加方括号）；随后写 `content-type=application/grpc`、`te=trailers`、`user-agent`（默认 `grpc-trafficgen/1.0`）、`grpc-encoding`（默认 identity）、`grpc-accept-encoding`（默认 `identity, gzip`）、可选 `grpc-timeout` 与 metadata。authorization（大小写不敏感）使用 Never Indexed，其他 metadata 使用 Incremental Indexing。响应初始 HEADERS 为 `:status=200`；trailers 为 `grpc-status`（默认 0）和 percent-encoded `grpc-message`，同时 END_STREAM|END_HEADERS。

### 2.4 gRPC message 与 protobuf

每条 DATA 的 gRPC message 为 5 字节前缀 + body：`compressed-flag:1B | message-length:UInt32 BE | protobuf bytes`（gRPC protocol §4）。identity flag=0；gzip 时对 body 压缩且 flag=1。空 body 合法，仍发送 5 字节长度 0。实现只校验 protobuf 首个 varint key：field number 必须 >=1，wire type 仅 0/1/2/5；不验证完整 schema、长度嵌套或字段重复。HTTP/2 DATA payload 按 `MaxFrameSize` 分帧；每个 DATA frame 再由 TCP MSS 分段。

### 2.5 RPC 编排

| CallType | 请求 | 响应 |
|---|---|---|
| unary | 1 message，末 DATA END_STREAM | 配置响应列表，随后 trailers |
| server-stream | 1 message | 多 response DATA，随后 trailers |
| client-stream | 多 request，最后请求 END_STREAM | response DATA，随后 trailers |
| bidi-stream | 多 request/response 交错 | 初始 response HEADERS 先发，逐对 DATA，随后余项与 trailers |

`Calls[]` 非空时每项独立 call，stream id=`2*i+1`；为空时使用顶层 Service/Method 等字段生成一个 call。`Pings` 在请求与响应间生成请求/ACK 对；`CancelAfter>0` 产生 RST_STREAM(CANCEL=8)，不真实等待毫秒数。`WindowUpdateIncrement>0` 在响应 DATA 后生成 stream 0 与当前 stream 两个 WINDOW_UPDATE；GOAWAY 当前实现始终生成，不能区分显式 false 与默认值。

## 3. 状态机、自动派生与输出路径

状态序列确定为：`TCP_ESTABLISHED → PREFACE → SETTINGS_EXCHANGED → CALL_i_OPEN → REQUEST_HALF_CLOSED → RESPONSE_TRAILERS → GOAWAY → TCP_FIN`。终结层只产生 message events；tcp 层负责 SYN/SYN-ACK/ACK、seq/ack、MSS、FIN 四包。链路为 `layers → ValidateLayers → grpc validator → GRPCGenerator.Generate → tcp event merger → PCAP/NIC writer`。legacy `Planner.Plan` 自产 TCP 包，链上生成器不再自产，防双握手。

成功自动派生：缺省 scheme=http、authority=目标地址、user-agent、accept-encoding、HeaderTableSize/MaxFrameSize/InitialWindow；空 request 变成零长 gRPC message；GOAWAY 默认末尾发出；TCP handshake/termination 由 grpc validator 强制打开。失败自动派生：validator 返回 error，任务必须失败且不生成成功 PCAP，不得把错误变成 completed/0 packets。

pcap 与 NIC 共用同一 cases JSON、字段/原始 frame/包数断言；仅捕获载体不同。IPv4 无 options 时应用 payload 起点通常 54（14+20+20），IPv6 为 74（14+40+20），TCP options 仅影响 SYN。

## 4. 配置、验证与错误契约

`GRPCConfig` 字段由 `types.go` 定义：service/method/authority/scheme/call_type、request/response raw 或 base64、response_status/message、timeout、encoding/accept_encoding、metadata/user_agent、四个 SETTINGS 参数、pings、cancel_after、go_away_after、window_update_increment、calls、file_source。`strategy_convert.go:parseGRPCConfig` 负责 JSON 到结构体转换，registry 行位于 `registry.go:1610`。

验证分支及锚词：无 service/method、call type 非 unary/server-stream/client-stream/bidi-stream、encoding 非 identity/gzip、accept encoding 含未知算法、timeout 格式非法、response status 不在 0..16、MaxFrameSize 超界、InitialWindow 超界、protobuf leading key 非法、FileSource 与 inline message 互斥、Call 字段缺失、Pings/CancelAfter 负数、WINDOW_UPDATE 超 31 位、MSS 小于 536。每一分支都应成为独立负例；当前唯一 JSON 没有负例。

## 5. 动态字段清单

四元组 `ip.src`、`ip.dst`、`tcp.src_port`、`tcp.dst_port` 由框架策略机制承载；序号由 `layer_dyn.go`/`TupleGenerator`/worker 注入。gRPC 业务字段当前无动态 allowlist：service、method、authority、metadata、messages、status、timeout、encoding、call type、SETTINGS、Pings、Calls 均为静态层配置；`Calls[]` 是同一连接的结构列表，不是流级动态策略。未来若开放动态值，必须按 flow 序号确定性展开并回绕，不新增顶层字段。当前唯一 case 使用静态 service/method 与端口 80。

## 6. 门1 §1–§14 对照表

本表严格使用显式章节标识 `§1`、`§2`、`§3`、`§4`、`§5`、`§6`、`§7`、`§8`、`§9`、`§10`、`§11`、`§12`、`§13`、`§14`，无裸数字行。

| § | 本协议怎么满足 | 证据 |
|---|---|---|
| §1 层链唯一真相 | 当前 case `spec_json` 仅 `{layers}`，目标形为 `[ip,tcp,grpc]`；旧顶层键无存量出现，详见 §6.1 | cases/grpc.json；§6.1 |
| §2 策略/任务 | 策略声明一条 TCP/HTTP2 连接及 calls，任务负责合并/总量封顶；Call 是连接内多 stream | `GRPCConfig.Calls`；§2.5 |
| §3 五件套 | 会话表、事务序列、关联、插入位置、时间线在 §6.2 展开；控制流不派生子流 | §3、§6.2 |
| §4 查规范 | HTTP/2 RFC 7540/9113、HPACK RFC 7541、gRPC protocol、protobuf encoding | planner.go:1-7 |
| §5 依赖与错误 | grpc terminal 依赖 tcp；validator 锚词与任务 error 传播契约在 §4 | registry.go:1610；layer_gen.go:328 |
| §6 性能 | HTTP/2 frame/MSS 分段、长度上界、流复用在 §2/§5；吞吐不作协议承诺 | planner.go:495-506 |
| §7 三份文档 | design + testcase + grpc.json；ID/包数/断言以 JSON 为准，冲突记 G-GRPC-1 | §0；testcase §2 |
| §8 设计先行 | 本稿逆向描述已落码实现；未覆盖行为标待实现边界，不冒充 case | §14 |
| §9 测试三源 | RFC/官方协议、实现、grpc.json/pcap 断言三方对照 | testcase §5 |
| §10 评审闭环 | 本车道自审；待独立隔离复审，不以自审替代对抗审查 | 修订记录 |
| §11 白话 | gRPC 是在一条 HTTP/2 长连接上按 stream 发送 protobuf RPC | 文首 |
| §12 动态清单 | 四元组走框架；业务字段全量列出为静态，序号算法见 §5 | §5 |
| §13 schema 派生 | registry 已注册 grpc，FieldContract 仅声明 tcp.dst_port=8604 | registry.go:1610 |
| §14 真实流程 | chain validator → generator events → tcp → pcap/NIC；双输出共用契约 | §3 |

### 6.1 §1 顶层旧键去向与完整 spec_json

现有 `grpc.json` 1/1 例顶层严格只有 `layers`，完整机器形状为：

```json
{
  "layers": [
    {"ip": {"src": "10.0.0.1", "dst": "20.0.0.1"}},
    {"tcp": {"src_port": 12345, "dst_port": 80}},
    {"grpc": {"service": "svc", "method": "m"}}
  ]
}
```

旧式顶层 `src_ip`、`dst_ip`、`src_port`、`dst_port`、`count` 与顶层 `grpc` 子映射均为 0 次出现；它们分别下沉至 `layers[].ip`、`layers[].tcp`、框架 `flow_control`，以及 `layers[].grpc`。本例的 TCP 源/目的端口和 IP 地址均已层内化，不是缺失字段。迁移动作：无存量旧键可删；新增例必须沿用纯 layers，非负例不得携带游离顶层键。

### 6.2 §3 五件套

会话表：s1 = 一个四元组上的 TCP/HTTP2 连接，承载 stream 1（当前 case）；未来 s1 可承载 stream 1,3,5 的 Calls。事务序列：t1 TCP 握手；t2 preface/SETTINGS 三步；t3 每 call 的 HEADERS→DATA→response HEADERS→DATA→trailers；t4 PING/WINDOW_UPDATE/RST（可选）；t5 GOAWAY/FIN。关联关系：stream id 关联请求、响应、trailers；无控制流派生数据流。插入位置：`[ip,tcp,grpc]` 末端。时间线：连接级设置一次，call 按 Calls 顺序整块回放；bidi 在同一 stream 交错，非 Calls 并发。

## 7. 性能与容量边界

单条 payload 以 `MaxFrameSize` 上取整为 HTTP/2 frame 数，再以 MSS 上取整为 TCP 段数；每帧 9B HTTP/2 header，每条 gRPC message 5B prefix。最大允许 HTTP/2 frame payload 为 16777215，默认 16384；InitialWindow 最大 2147483647；protobuf leading key 最大 10B varint 检查。事件生成器按帧流式发送，链上不聚合所有 flow；当前 legacy Plan 使用 channel 逐包输出，链上 generator 使用 EmitMsg。

## 8. 缺口登记

| 缺口 | 现象 | 证据 | 归属阶段 |
|---|---|---|---|
| G-GRPC-1 | 唯一 JSON 的 `min_packets=13` 与 notes 所述 15、实现完整序列不一致；notes 还把 SETTINGS/帧序写成复合包，无法逐条对账 | grpc.json:17-57；planner.go:529-785；layer_gen.go:123-291 | 文档/P4：按实测事件数重钉三件套 |
| G-GRPC-2 | stream call type、Calls、多 metadata、gzip、PING、RST、WINDOW_UPDATE 等代码分支没有 JSON 原子用例 | planner.go:546-750；grpc.json 仅 1 ID | 测试阶段：补正/负例 |
| G-GRPC-3 | MSS、MaxFrameSize、protobuf 长度、SETTINGS 边界与截断/溢出未由 cases 证明 | planner.go:495-506, 637-644；Validate:205-317 | 测试阶段 |
| G-GRPC-4 | IPv6、非默认/缺省端口、多 stream 独立 stream-id/关联未由 cases 证明 | registry.go:1610；planner.go:579-582；grpc.json 仅 IPv4/80 | 测试阶段 |
| G-GRPC-5 | validator 每错误分支没有对应 expect_error case，任务终态传播未在本 JSON 证明 | planner.go:154-319 | 测试阶段 |
| G-GRPC-6 | GoAwayAfter 为 bool，当前实现无论 false/默认均发送 GOAWAY，无法表达显式关闭 | planner.go:752-777；layer_gen.go:283-291 | 实现阶段：字段语义修正或明确固定行为 |
| G-GRPC-7 | tracked `trafficgen/docs/protocol-pcap-test/grpc.md` 末次提交 2026-08-27，早于 0417be5（2026-09-13）；无今日复跑证据，数字不得作为现状证明 | git log；过期产物 | 代码阶段 P5 重跑后重生成 |
| G-GRPC-8 | HPACK 注释声明动态表维护，但 literal 复用/真实服务端兼容性及完整 HTTP/2 状态机未以互操作 pcap 证明 | planner.go:1202-1210；本地实现测试 | 待实现/实证边界 |

## 9. 修订记录

- v1.0.1（2026-10-01）：审计修订：补齐与现存 `grpc.json` 完全一致的 `[ip,tcp,grpc]` spec_json 完整样例及各旧键去向；明确当前唯一正例的严格层链形状与未覆盖的 presence/游离键负例；声明仅覆盖明文 h2c，TLS 未覆盖。第一轮抓出 `[tcp,grpc]` 目标形缺 `ip` 层与 §6.1/JSON 矛盾，已按 JSON 修正；第二轮逐字对账确认 spec_json、`[ip,tcp,grpc]`、h2c/TLS 缺口表述三文件一致，末轮干净。
- v1.0.0（2026-09-29）：#145 as-built 设计文档；依据实现、registry、配置结构与现有 JSON 逆向整理；登记 JSON 包数/notes 矛盾、覆盖缺口、过期结果产物。自审 1 轮，末轮干净；待独立隔离复审。
