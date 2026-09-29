# 128 SOCKS5 设计契约（as-built）

## 0. 基线继承与裁定

本版依据 RFC 1928 §3–§8、RFC 1929 §2–§3、`trafficgen/internal/protocol/socks5/` 实现、registry、`types.go`、`strategy_convert.go`、链规划器和 `cases/socks5.json` 编写。实现与 cases 优先于旧文档。协议是 SOCKS5 代理协商/中继 shim，不是应用数据协议。**当前存量两例均因顶层 flat 键在 `CheckProtoFlat` 被拒而无法执行**；下文同时给出目标线格式与今日实际能力边界，不把预期当成实测。

## 1. 范围、profile 与实现边界

- profile：TCP 终结层 `[ip?,tcp,socks5]`；registry `CategoryTerminal`、`DependsOn:[tcp]`、`OptionalOn:[tls]`。默认 SOCKS 服务端口为 1080（registry `FieldContract tcp.dst_port=1080`），但当前链转换的通用缺省仍可能落到 80（`isUniversalDefault(v)==(v==80)`，且 socks5 不在专门端口 switch），故链用例必须显式写 `tcp.dst_port`。
- 支持：NO AUTH、USERNAME/PASSWORD、CONNECT、BIND、UDP ASSOCIATE 的配置模型；IPv4/域名/IPv6 地址；SOCKS4/SOCKS4a 降级；成功回复后方向数据事件；REP 非零时抑制数据。
- 生产链入口是 `NewChainPlanner("socks5")` 和 `layer_gen.go`；没有 `planner.go` 文件。legacy `socks5.go` 的 `Planner.Plan` 仍含自有 TCP 握手/挥手，但生产链由 TCP 层负责握手、序号、ACK、MSS、IP ID、时间戳和终止。
- 链生成器拒绝 UDP relay 配置和 `FileSource` 数据；不声称支持多 flow/GroupID 展开。TLS 仅在显式 `[tcp,tls,socks5]` 时启用，TLS 是 transformer：内层 SOCKS 事件被包装进 application-data records，不改 SOCKS 字节语义。

## 2. 协议栈、端口和固定偏移

IPv4 TCP 应用载荷起点通常为 Ethernet 14 + IPv4 20 + TCP 20 = **54**；IPv6 无扩展头时为 14 + 40 + 20 = **74**。SOCKS 字节偏移以 TCP payload 起点为 0，pcap `frames` 的 `offset` 是完整帧偏移，不能把 54 当协议内偏移。

TCP 建连顺序由 tcp 层产生 SYN、SYN/ACK、ACK；随后客户端方向 greeting，服务端 method response，任选认证子协商，再客户端 request、服务端 reply，成功后 relay data，最后 TCP termination。默认端口固定语义为 1080，但当前 chain 端口缺省漏洞见 G-SOCKS5-2。

## 3. 线格式（逐字段、偏移与长度公式）

### 3.1 方法协商（RFC 1928 §3）

客户端 greeting：`VER(0) | NMETHODS(1) | METHODS(2..1+N)`，总长 `2+N`；VER=0x05，N=1..255。METHOD：0x00 no-auth、0x01 GSSAPI、0x02 username/password、0x03..0x7f IANA、0x80..0xfe private、0xff no acceptable。服务端选择：`VER(0)=0x05 | METHOD(1)`，总长 2；0xff 时客户端必须关闭连接。

### 3.2 RFC 1929 用户名/密码

请求：`VER(0)=0x01 | ULEN(1) | UNAME(2..1+U) | PLEN(2+U) | PASSWD(3+U..2+U+P)`，总长 `3+U+P`，U/P 各 1..255，字节为明文。响应：`VER(0)=0x01 | STATUS(1)`，0x00 成功；其他值服务端必须关闭连接。实现默认 user/pass 为 `user`/`pass`；链例 `alice`/`secret` 的请求为 `01 05 61 6c 69 63 65 06 73 65 63 72 65 74`（`01 05 'alice' 06 'secret'`）。

### 3.3 请求（RFC 1928 §4）

固定头 `VER(0)=05 | CMD(1) | RSV(2)=00 | ATYP(3)`，地址从 4 开始，端口在地址后 2 字节网络序；总长 `4 + addrLen(ATYP) + 2`。CMD：CONNECT=0x01、BIND=0x02、UDP ASSOCIATE=0x03。

| ATYP | 地址布局 | `addrLen` | 总长 |
|---|---|---:|---:|
| 0x01 IPv4 | `DST.ADDR(4)` | 4 | 10 |
| 0x03 DOMAINNAME | `LEN(4) | NAME(5..4+L)`，无 NUL | `1+L` | `7+L` |
| 0x04 IPv6 | `DST.ADDR(16)` | 16 | 22 |

域名长度字段为一字节，超过 255 时当前 builder 截断至 255；端口为 `uint16` big-endian。请求成功与否由服务端 reply 决定。

### 3.4 回复（RFC 1928 §6）

固定头 `VER(0)=05 | REP(1) | RSV(2)=00 | ATYP(3)`，之后 `BND.ADDR`、`BND.PORT`，总长仍为 `4+addrLen+2`。REP：0x00 succeeded、0x01 general failure、0x02 ruleset denied、0x03 network unreachable、0x04 host unreachable、0x05 connection refused、0x06 TTL expired、0x07 command unsupported、0x08 address type unsupported、0x09..0xff unassigned。失败 reply 后 TCP 层应在不超过 10 秒内终止（RFC §6）；当前事件生成器仅以 `Rep==0` 控制数据事件，REP=0xff 可编码但终止时序由 TCP 层负责。BND.ADDR/BND.PORT 可为 `0.0.0.0:0`。

### 3.5 UDP relay（RFC 1928 §7）

UDP header：`RSV(0..1)=0000 | FRAG(2) | ATYP(3) | DST.ADDR | DST.PORT(2) | DATA`。FRAG=0 为独立报文；未实现分片时非零应丢弃。IPv4/域名/IPv6 使用同一三种 ATYP。legacy `emitUDPRelay` 使用 `FlowID=flowID+":udp"`、RSV=0、FRAG=0；但 layer chain 明确拒绝 `SocksConfig.UDP`，故本链契约不把 UDP relay 当作可执行链能力。

## 4. 场景与五层覆盖

| 层 | 不可再分测试点 | 当前证据/状态 |
|---|---|---|
| 功能 | greeting/method；no-auth；RFC1929 auth；CONNECT/BIND/UDP 命令；REP 成功/失败；SOCKS4 降级 | builder 与 layer tests 覆盖；UDP/FileSource 为显式拒绝 |
| 性能 | TCP 握手/挥手、MSS=536 分段、4000B→7×536+248、TLS 记录包装 | legacy/层测试与 TLS case；无吞吐承诺 |
| 数据 | IPv4 4B、domain 1B length/no NUL、IPv6 16B、端口 BE、用户名密码边界、REP 全范围 | builders、IPv6、300 字节域名截断、rep=-1 wire；缺业务字段动态 |
| 地址与流 | 四元组、默认端口、IPv6、单 TCP 流、UDP flow 关联、TLS substrate | TCP/IPv6 实测；动态四元组和端口缺口见 G-SOCKS5-1/G-SOCKS5-2/G-SOCKS5-3 |
| 业务 | 代理认证、目标地址请求、绑定地址回复、relay data、失败关闭 | 事件序列/REP 抑制；存量 cases 今日被 flat 门阻断 |

不适用点（显式声明 + 理由）：BIND/UDP relay 正路径不适用——layer generator/validator 双重拒绝（§7 前两行）；UDP FRAG 分片不适用——链不承载 UDP；业务字段逐流动态不适用——allowlist 无 socks5 行（G-SOCKS5-7）。

## 5. 事务模型与状态机

状态序列：`S0 TCP_CONNECTED → S1 METHOD_NEGOTIATION → S2 AUTHENTICATED/NO_AUTH → S3 REQUEST_SENT → S4 REPLY_OK → S5 RELAY → S6 TCP_TERMINATED`；REP 非零从 S3/S4 进入 `S6`，不进入 relay。

| 当前状态 | 合法下一步 | 非法转换（必须拒绝或关闭） |
|---|---|---|
| S0 | greeting | 先 request/auth；服务端未选方法即收 request |
| S1 | method response | 未收到 greeting 就 auth/request；method=ff 后继续 |
| S2 | request | auth 未成功继续 request；重复/未知 auth |
| S3 | reply | 客户端发送 data；重复 request 未有 reply |
| S4 | relay 或 terminate | REP 非零仍发送 data；把第二条 request 当 data |
| S5 | data/terminate | method/greeting/auth 重新协商 |
| S6 | 无 | 任意新 SOCKS 消息复用已关闭 TCP |

RFC1929 failure 必须关闭；RFC1928 failure reply 后应在 10 秒内关闭。TLS 先完成外层 TLS handshake，再承载 S1–S5，未完成 TLS 不得把 ciphertext 当明文 SOCKS。

## 6. 流关联与插入位置

SOCKS5 是 TCP 终结层，插入 `[ip,tcp,socks5]`；TLS 可插在 socks5 前为 `[ip,tcp,tls,socks5]`。单流内所有协商、认证、请求、回复、relay 共享一个 TCP 4-tuple，无派生业务流。legacy UDP 会产生 `:udp` flow，但层链禁止该配置。`GroupID`/多 flow 展开未由 layer generator 实现。

## 7. 错误处理锚词表

| 输入/分支 | 锚词/行为 | 归属 |
|---|---|---|
| `UDP != nil` 链配置 | `socks5: UDP relay is not supported in layer chains` | layer_gen.go:52/validator:159 |
| `Data[].FileSource != nil` | `socks5: FileSource data is not supported in layer chains` | layer_gen.go:56/validator:163 |
| TCP MSS < 536 | 框架先报 `layer "tcp" field "mss" ... out of range [536,65535]` | framework |
| username/password >255 | `Username exceeds 255 bytes` / `Password exceeds 255 bytes` | socks5.go:181-185 |
| REP !=0 | reply 仍发出，数据事件被抑制 | layer_gen.go / RFC1928 §6 |
| flat 顶层地址/端口与 layers 并存 | `protocol socks5 no longer accepts flat config field src_ip` | CheckProtoFlat；当前两存量例均此错误 |
| 多 flow 静态复制 | `layers pin a static four-tuple but flows > 1... static copy` | checkLayerChainStaticCopy |

## 8. 边界与容量

MaxDomainLen=255；用户名/密码 1..255；TCP 默认 TTL=64、MSS=1460，最小 MSS=536；MSS 分段按 payload 切片。地址族由 ATYP 与地址解析决定。域名截断是当前 builder 行为，不等价于 RFC 输入校验；该差异列 G-SOCKS5-4。UDP FRAG 规范存在但链不承载；TLS 记录大小/证书密码学不由 socks5 层定义。

## 9. 原子 ID 与完成定义

`S-SOCKS5-01` greeting/method；`S-SOCKS5-02` no-auth CONNECT；`S-SOCKS5-03` RFC1929；`S-SOCKS5-04` IPv4 request/reply；`S-SOCKS5-05` domain request/reply；`S-SOCKS5-06` IPv6；`S-SOCKS5-07` BIND；`S-SOCKS5-08` REP failure/close；`S-SOCKS5-09` relay data；`S-SOCKS5-10` TLS substrate；`S-SOCKS5-11` SOCKS4 downgrade；`S-SOCKS5-12` UDP relay rejection. 完成定义：每个 ID 有输入形状、方向、固定偏移/长度公式、预期事件或错误锚词及可观察 pcap 断言。

## 10. P1 规范矩阵

| 规范面 | 实现状态 | 例/缺口 |
|---|---|---|
| RFC1928 method | 已实现 | socks5-connect-basic（今日 flat 阻断） |
| RFC1929 auth | 已实现 | socks5_over_tls；链测试 |
| ATYP 三型 | 已实现 | builder 单测/探针 |
| CMD 三型 | 配置/编码支持，链 UDP 拒绝 | G-SOCKS5-5 |
| REP 0..ff | 编码支持，失败终止由 tcp | S-SOCKS5-08 |
| UDP FRAG | legacy 支持，链不支持 | G-SOCKS5-6 |
| TLS OptionalOn | event transformer | socks5_over_tls |
| 动态四元组 | 框架策略存在，socks5 static-copy 门缺分支核验 | G-SOCKS5-3 |

## 11. P2 代码设计（as-built）

文件面：`socks5/socks5.go`（legacy Planner、builders、UDP、MSS）、`socks5/layer_gen.go`（事件终结层与 validator）、`core/types.go`（SocksConfig/Socks5UDP）、`layers/registry.go`（13 Fields、1080 contract）、`strategy_convert.go`（flat `socks` 解析）、`chain_planner_translate.go:3002-3020`（terminal config JSON round-trip）。生产注册为 `main.go` 的 `NewChainPlanner("socks5")`；无 socks5 `NewPlanner` 注册。

事件流程：generator 发 greeting → method → 可选 auth req/resp → request → reply → `Rep==0` 时按 Direction 发 Data；TCP 层补握手/挥手和传输字段。TLS transformer 在外层完成握手后将事件包入 application_data。UDP/FileSource 在 generator 与 validator 双重拒绝。

## 12. 门1 §1–§14 十四行对照表

| § | 满足方式 | 证据 |
|---|---|---|
| §1 层链唯一真相 | 目标仅 `layers`；现有两例仍含 flat 字段并被拒 | §12.1；cases |
| §2 策略/任务 | flow spec → chain planner → terminal events | §11；chain planner |
| §3 五件套 | 单 TCP 会话、协商/认证/请求/中继/终止、无派生流 | §12.3 |
| §4 查规范 | RFC1928/1929 字段和状态逐项映射 | §2-§5 |
| §5 依赖与错误 | tcp 必需、tls 可选、错误锚词列明 | registry；§7 |
| §6 性能 | MSS/分段/TLS records 有边界，吞吐不承诺 | §4/§8 |
| §7 三份文档 | RFC + 本 design + testcase + 落码/pcap 证据 | §0；testcase §5 |
| §8 设计先行 | 原子 ID、矩阵、缺口先列 | §9/§10/§14 |
| §9 测试三源 | RFC + 代码 + cases/实测 probes | testcase §5 |
| §10 评审闭环 | 本轮逐键/计数/偏移复核，末轮 clean | 修订记录 |
| §11 白话 | SOCKS5 是代理协商 shim | §0/§1 |
| §12 动态字段 | 四元组五策略与 13 业务字段逐项列 | §12.12 |
| §13 schema 派生 | registry Fields 13 键、OptionalOn tls | §11/registry |
| §14 真实流程 | MCP suite → 引擎 → tshark/frames；今日 flat 错误 | testcase §7/§8 |

### 12.1 §1 顶层旧键去向与完整目标形状

旧键 `src_ip`、`dst_ip`、`src_port`、`dst_port`、`count` 不应游离于 layers：地址进 `layers[0].ip.src/dst`，端口进 `layers[1].tcp.src_port/dst_port`，重复数进 `flow_control`/策略；协议配置键应从顶层 `socks` 迁入终结层 `layers[-1].socks5`。今日 `strategy_convert` 仍解析 flat `socks`，且 CheckProtoFlat 拒绝 flat 四元组；两存量例须改写而非声称已合规。

完整目标样例：
```json
{"layers":[{"ip":{"src":"10.0.0.1","dst":"20.0.0.1"}},{"tcp":{"src_port":12345,"dst_port":1080}},{"socks5":{"auth_method":"password","username":"alice","password":"secret","cmd":"connect","dst_addr":"target.example.com","dst_port":8080}}]}
```

### 12.3 §3 五件套

| 件 | SOCKS5 对照 |
|---|---|
| 会话表 | s1：一个 TCP 4-tuple；TLS case 为同一 tuple 的外层 TLS + 内层 SOCKS |
| 事务序列 | t1 TCP handshake → t2 method → t3 auth（可选）→ t4 request/reply → t5 relay → t6 FIN |
| 关联关系 | 无派生业务流；legacy UDP `flowID:udp` 仅非链路径 |
| 插入位置 | TCP terminal；可由 TLS transformer 包裹 |
| 时间线 | 严格方向序，reply 前不发 relay；REP 非零直接终止 |

### 12.12 §12 动态字段清单

四元组 `ip.src`、`ip.dst`、`tcp.src_port`、`tcp.dst_port` 均应支持 fixed、inc、rand、pattern、list 五策略；序号/tuple 解析由 `layer_dyn.go`、`tuple_generator.go` 和 worker 注入，当前 socks5 未有独立业务 allowlist。registry 业务字段逐项：`version`（标量，默认/固定）、`auth_method`（枚举）、`username`、`password`（长度受 255）、`cmd`（枚举）、`dst_addr`（ATYP 推导）、`dst_port`（BE uint16）、`rep`（回复枚举）、`bnd_addr`、`bnd_port`、`user_id`、`data`（方向+payload 列表）、`udp`（对象）。这些字段今日没有 socks5 业务动态 allowlist；不得把对象策略写成已覆盖，登记 G-SOCKS5-7。固定/增量/随机/模板/列表的四元组算法属于底层层策略，不应由终结层复制。

## 13. P3 对接清单

先修存量两例的纯 layers 形状，再重跑 `CASE_PROTO=socks5`；保留 1080 显式端口。基线正例按 no-auth、password、IPv6、TLS 顺序；每次同时检查 tshark fields 与 frames。补充负例须先验证错误在创建阶段传播，不接受“completed/0 packet”假绿。覆盖 gate 建议行见 testcase §9。

## 14. 缺口立项清单

| 缺口 | 现象 | 证据 | 归属阶段 |
|---|---|---|---|
| G-SOCKS5-1 | 两存量 case 顶层 flat 四元组被拒，今日 0/2 可执行 | suite 错误 `protocol socks5 no longer accepts flat config field src_ip`；cases 两例均有 flat 字段 | P4/fixtures |
| G-SOCKS5-2 | registry 声明 1080，但 chain 通用缺省可落 80 | registry FieldContract；`isUniversalDefault(v)==(v==80)`；socks5 不在 dst-port switch | P4 chain |
| G-SOCKS5-3 | socks5 缺 `CheckProtoFlat`/static-copy 专属核验分支，presence 负例会假绿 | semantic.go 清单无 socks5；presence probe 完成 11 帧 | P4 framework |
| G-SOCKS5-4 | 域名 >255 被截断而非拒绝 | `socks5.go:745-747`；300 字符 probe 截为 255 | P4 validator |
| G-SOCKS5-5 | BIND/UDP 的链路行为没有正例；UDP 被设计为链拒绝 | layer_gen.go:52、validator:159；cases 无命令变体 | P4/A′ |
| G-SOCKS5-6 | UDP FRAG/relay legacy 与链能力不一致 | `emitUDPRelay` legacy；layer generator 明确拒绝 UDP | P4 scope decision |
| G-SOCKS5-7 | 13 个业务字段无 socks5 动态 allowlist；动态业务值不可声称覆盖 | registry 13 Fields；layer dynamic allowlist 无 socks5 | P4 framework |
| G-SOCKS5-8 | tracked `trafficgen/docs/protocol-pcap-test/socks5.md` 过期且无 pcap 目录 | last commit c7c1dda (2026-08-31) < 0417be5 (2026-09-13)；目录不存在 | P5 result regeneration |
| G-SOCKS5-9 | `has_payload` 无 socks5 分支，落到 frame.len>80 启发式 | pcaptest/verify.go:228+ | P5 gate |
| G-SOCKS5-10 | TLS case 的明文 SOCKS 字段不能直接靠 tshark socks 字段断言 | TLS transformer 记录封装；需强制 `tcp.port==1080,tls` | P5 decoder |

## 15. 修订记录

- v1.0（2026-09-29）：按 as-built 实现、RFC、registry、layer tests、两份存量 cases 和 probes 初稿；明确无 planner.go、flat 阻断、端口缺省冲突、TLS transformer 与十项缺口。
- 自审 3 轮，末轮干净（第 3 轮为脚本机读：门1 行序/ID 顺序/断言数字/frames hex/缺口三要素/编号连续性全过）。
