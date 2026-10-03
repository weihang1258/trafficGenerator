# SOCKS5 设计契约（文档轨）

> 版本：v1.1.0（2026-09-30）  
> 范围：D1–D8；本轮只改文档与 cases 形状，不改 Go 实现。  
> 依据：RFC 1928 §3–§7、RFC 1929 §2–§3，以及 `trafficgen/internal/protocol/socks5/`。

## D1 范围、证据与边界

SOCKS5 是 TCP 上的代理协商与隧道数据协议：TCP 建连后依次完成 greeting/method、可选用户名密码认证、请求/回复、数据中继和 TCP 终止。实现还保留 SOCKS4/SOCKS4a legacy builder。生产层链入口是 `NewChainPlanner("socks5")` 与 `layer_gen.go`；TCP 握手、序号/ACK、MSS 分段和挥手由 TCP 层负责。

本版覆盖 NO AUTH、USERNAME/PASSWORD、CONNECT、BIND/UDP ASSOCIATE 的配置与编码边界、IPv4/域名/IPv6 地址、REP 回复、TLS 可选承载和 inline data。layer chain 明确拒绝 UDP relay 子流与 `FileSource`，不把 legacy planner 能力冒充为生产链能力。

## D2 严格层链与配置权威

顶层只保留 `layers`、`flow_control`、任务/策略框架字段与 `output`。SOCKS5 的目标形状如下，地址在 `ip`，端口在 `tcp`，业务字段在 terminal `socks5` 层：

```json
{"layers":[{"ip":{"src":"10.0.0.1","dst":"20.0.0.1"}},{"tcp":{"src_port":12345,"dst_port":1080}},{"socks5":{"auth_method":"password","username":"alice","password":"secret","cmd":"connect","dst_addr":"target.example.com","dst_port":8080}}]}
```

不得混用顶层 `src_ip`、`dst_ip`、`src_port`、`dst_port`、`count` 或顶层 `socks`。重复数量属于 `flow_control`。TLS 承载严格写作 `[ip,tcp,tls,socks5]`。当前两个 cases 已迁为纯 layers；`dst_port` 显式钉为 1080，避免通用 80 缺省路径。

## D3 线格式、偏移和长度

IPv4 无扩展头时 Ethernet/IP/TCP 后 TCP payload 起点为 54；IPv6 为 74。SOCKS 字节相对 TCP payload 偏移为 0，pcap frame offset 不是协议内偏移。

- greeting：`05 | NMETHODS | METHODS`，长度 `2+N`；method response：`05 | METHOD`，长度 2。
- RFC1929：`01 | ULEN | USERNAME | PLEN | PASSWORD`，长度 `3+U+P`；响应 `01 | STATUS`。
- request/reply：`VER | CMD/REP | RSV=00 | ATYP | ADDR | PORT`，端口为 2 字节 big-endian。IPv4 地址长度 4、域名为 `LEN+NAME`、IPv6 长度 16，因此总长分别为 10、`7+L`、22。
- UDP relay header 为 `RSV(2)|FRAG|ATYP|ADDR|PORT|DATA`；layer chain 不承载该第二 UDP 4-tuple。

域名和用户名/密码的协议长度上限是 255；现有 builder 对超长域名执行截断而非拒绝，登记为缺口，不写成规范行为。

## D4 状态、命令与地址变体

状态为 `TCP_CONNECTED → METHOD_NEGOTIATION → AUTHENTICATED/NO_AUTH → REQUEST_SENT → REPLY → RELAY/TERMINATED`。method=0xff 或 RFC1929 非零 status 必须关闭；REP 非零回复后不发 data 并终止。CONNECT/BIND/UDP ASSOCIATE 的命令值分别为 1/2/3；三种 ATYP 为 IPv4/domain/IPv6。SOCKS4 无 greeting，SOCKS4a 用 `0.0.0.1` 加 NUL 结尾域名。

依赖：`socks5` 必须有前置 `tcp`，`tls` 只可显式插在 tcp 与 socks5 之间。失败必须传播为 task error 或按协议关闭，禁止 completed/0 packet 假成功。

## D5 会话、事务、流关联与动态

| 项 | 定义 |
|---|---|
| 会话 | 一个 TCP 4-tuple；TLS case 仍是同一 tuple 的外层 TLS 与内层 SOCKS |
| 事务序列 | handshake → method → optional auth → request/reply → data → FIN |
| 关联 | layer chain 无派生业务流；legacy UDP `flowID:udp` 不属于本链 |
| 插入位置 | TCP terminal；TLS transformer 位于 socks5 之前 |
| 时间线 | 严格按事件方向输出，成功 reply 前不输出 data，失败 reply 后终止 |

四元组字段的 fixed/inc/rand/pattern/list 与序号算法由通用层策略负责，值仍只能落在 `ip`/`tcp` 层。SOCKS5 业务字段尚无独立动态 allowlist；`version`、`auth_method`、`username`、`password`、`cmd`、`dst_addr`、`dst_port`、`rep`、`bnd_addr`、`bnd_port`、`user_id`、`data`、`udp` 不得声称已支持五种动态策略。

## D6 错误处理与不适用项

已实现/可观察锚词包括：UDP relay layer-chain rejection、`FileSource` rejection、用户名/密码超过 255、非法 version/auth/cmd/address、MSS 小于 536、REP 非零抑制 data。BIND/UDP relay 的 layer-chain 正路径、UDP FRAG 分片、业务动态字段、GroupID 多 flow 展开尚未实现，列入缺口而非伪造正例。TLS ciphertext 不应按明文 SOCKS 字段断言。

## D7 性能、输出与验收

生成器按事件逐帧流式输出，不聚合全部数据；队列、ring buffer 和 TCP worker 遵循仓库有界约束。当前没有 SOCKS5 专项吞吐/并发/内存基准，数字均待实测。PCAP 验收检查 TCP 握手/挥手、协议 payload 偏移、字段和线字节；TLS case 使用 `tcp.port==1080,tls` 解码。NIC 验收使用真实接口抓取 TCP 1080，记录 checksum/offload 边界；性能验收须补基线、目标规模、压力、长跑、交错、背压六类结果。

## D8 接口、回滚与缺口

接口为 `SOCKS5Generator.Generate(context.Context, *layers.GenRequest) error`，消息通过 `EmitMsg` 输出；validator 在 layer generator 注册处执行前置拒绝。回滚仅回退本轮三文件文档/cases 变更，不改实现。

| 编号 | 缺口 | 计划 |
|---|---|---|
| G-SOCKS5-1 | 现有两例历史断言尚未在本轮真实 suite/pcap 重钉 | 迁移后跑全量，按 tshark/frame 校准 |
| G-SOCKS5-2 | 通用端口缺省与 registry 1080 语义存在冲突 | 修 chain 默认优先级并补负例 |
| G-SOCKS5-3 | socks5 专属 presence/static-copy gate 未登记 | 补 framework gate，禁止 presence 假绿 |
| G-SOCKS5-4 | 超长域名当前截断而非拒绝 | validator 明确 reject 或更新契约 |
| G-SOCKS5-5 | BIND/IPv4/IPv6/REP failure 正例不在现有 pcap cases | 按 A′ 补例并重新校准 |
| G-SOCKS5-6 | UDP relay/FRAG 与 layer chain 能力不一致 | 保持链拒绝，另立 legacy scope case |
| G-SOCKS5-7 | 业务动态 allowlist 缺失 | 先补代码设计与序号算法，再建五策略整格例 |
| G-SOCKS5-8 | tracked pcap 结果需重新生成 | 服务器与 HEAD 同代后跑 MCP suite |
| G-SOCKS5-9 | 三路对照缺“商业软件实际行为”一路（RFC 与代码两路已齐） | 指定产品+版本抓包后逐条映射用例；映射前不宣称现网覆盖 |
| G-SOCKS5-10 | `dst_addr`/`dst_port` 未写在 `socks5` 层时生成零值目标请求（`layer_gen.go:46-50,94` 与 `socks5.go:268` 同款兜底），无拒绝 | 明确“省略=零值目标”契约并补负例，或改为拒绝缺目标配置 |

## 规范—业务—代码—缺口矩阵

| 规范要求（RFC） | 业务场景 | 当前代码证据 | 结论/缺口 |
|---|---|---|---|
| RFC 1928 §3 方法协商 | greeting → method response，NO AUTH 或 USERNAME/PASSWORD | `layer_gen.go:79-93` | 已实现；G-SOCKS5-1 仍待真实 pcap 校准 |
| RFC 1928 §4 请求 | CONNECT/BIND/UDP ASSOCIATE，IPv4/domain/IPv6 | `socks5.go:627-713`, `layer_gen.go:94-108` | CONNECT/地址编码可用；BIND 正例缺口；UDP relay 链路拒绝 |
| RFC 1928 §6 回复 | REP 与 BND 地址/端口 | `socks5.go:645-713`, `layer_gen.go:97-98` | 成功/失败编码路径存在；独立 pcap 例缺口 |
| RFC 1928 §7 UDP relay | 独立 UDP 4-tuple 与 FRAG | `layer_gen.go:51-53`, `:157-165` | legacy 可用；layer chain 明确不适用，见 G-SOCKS5-6 |
| RFC 1929 §2–§3 | 用户名密码子协商及 status | `socks5.go:607-625`, `layer_gen.go:86-92` | 成功路径存在；非零 status 注入例缺口 |

### 命令×响应码矩阵

| CMD / REP | 0x00 成功 | 0x01–0x08 失败 | 0x09–0xff 保留/扩展 |
|---|---|---|---|
| CONNECT | 已编码，正例 T2 | 编码路径存在，pcap 缺口 | 未逐值建例，G-SOCKS5-5 |
| BIND | 编码路径存在，正例缺口 | 编码路径存在，pcap 缺口 | 未逐值建例，G-SOCKS5-5 |
| UDP ASSOCIATE | legacy UDP 可编码；链拒绝 | 编码路径存在，pcap 缺口 | 未逐值建例，G-SOCKS5-6 |

### 数据形态与现网映射

| 维度 | 现状 |
|---|---|
| IPv4 / domain / IPv6 | builder 已有三种 ATYP；当前机器例只有 domain，IPv4/IPv6 为 G-SOCKS5-5 |
| 认证 | NO AUTH 为 T1；password 仅 TLS 组合 T3，明文成功例与非零 status 为缺口 |
| 现网行为 | 当前没有可引用的商业产品版本/抓包证据；不宣称现网映射，立项 G-SOCKS5-9，确认方式为补充指定产品版本抓包 |

候选承载方案：明文 TCP 直接承载 SOCKS（当前默认，字段可逐字校验，复杂度最低）；TLS 位于 TCP 与 socks5 层之间（当前可选，保护信令但明文字段不可校验）。选择“明文默认、TLS 显式启用”，因为两者都符合层链依赖且不把 TLS 密文误当 SOCKS 字段；TLS 业务语义验证待服务端/证书夹具补齐。

## 原子 ID 与完成定义

`S-SOCKS5-01` greeting/method；`-02` no-auth CONNECT；`-03` RFC1929；`-04` IPv4；`-05` domain；`-06` IPv6；`-07` BIND；`-08` REP failure；`-09` relay data；`-10` TLS；`-11` SOCKS4；`-12` UDP rejection。每个 ID 必须有输入形状、方向、线长度/偏移、输出或错误锚词和可观察 pcap 断言；当前 cases 仅覆盖 `-02/-03/-05/-10`。

本轮自审两轮：第一轮核对 D1–D8、层链唯一真相、实现边界和缺口；第二轮逐段核对 cases 形状、端口、偏移公式与未伪造执行证据，末轮干净。
