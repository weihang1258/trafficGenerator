# #134 Shadowsocks 设计契约

> 版本：v1.2.0（2026-10-01）  
> 范围：D1–D8 设计核对；本轮仅按当前实现与机器用例收敛文档，不改 Go 实现。  
> 机器契约：`trafficgen/test/protocol_pcap/cases/shadowsocks.json`  
> 实现：`trafficgen/internal/protocol/shadowsocks/`  
> 规范基线：RFC 1928（SOCKS5）、RFC 1929（用户名/密码子协商）、Shadowsocks SIP003（AEAD TCP framing）、SIP004（UDP relay framing）、SIP022（2022 cipher 命名与框架）。加密字节按实现的结构模拟，不声称密码学有效。

## 0. 范围与实现边界

本协议层是 TCP 终结层，默认链为 `[ip,tcp,shadowsocks]`；`shadowsocks` registry 行为 `CategoryTerminal`、依赖 `tcp`，默认 TCP 目的端口 8388（`registry.go:1626-1629`，`chain_planner.go:1240-1243`）。当前链路只接受 TCP mode；legacy planner 仍实现 UDP mode，但 layer-chain validator 明确拒绝 UDP，因为 TCP transport 无法输出 Shadowsocks UDP datagram（`layer_gen.go:202-207`）。

链上事件顺序为：TCP 层自动三次握手 → Shadowsocks 终结层按配置输出 SOCKS5/HTTP 可选事件、salt、AEAD chunks → TCP 层自动四次挥手。事件由 `GenRequest.EmitMsg` 传递；TCP 层负责 seq/ack、MSS 分段和握手/终止。生成器不重复生成 TCP 控制包（`layer_gen.go:11-35,53-56`）。

明确不实现或不声称：真实 AEAD 加密/解密、服务端语义、UDP 链上承载、真实 HTTP 混淆协议协商、动态策略字段。`rand.Read` 产生结构占位随机字节；`payload_bytes_format=\"zeros\"` 只使 payload/salt 为零，AEAD 长度和 tag 仍由实现随机生成。

## 1. 配置形状与顶层旧键迁移

目标形状是纯层链；顶层只保留 `layers`（多流数量另由框架 `flow_control` 承载），协议字段住 `shadowsocks` 层：

```json
{
  "layers": [
    {"tcp": {"dst_port": 8388}},
    {"shadowsocks": {} }
  ]
}
```

### 1.1 顶层旧键清单（门1 §1）

当前唯一机器 case 的 `spec_json` 顶层键为 `shadowsocks` 与 `layers`；这是空壳终结层的过渡形，不是最终层链形。`registry.go` 的 Shadowsocks 层没有 `Fields`，且转换器只把顶层 `shadowsocks` 配置传给终结层；把协议字段搬入层内会被 `unknown field` 拒绝。因此本轮按空壳例外保留该映射，登记 G-SS-1，待代码阶段补齐字段契约与转换后再迁移。

| 存量键 | 当前去向/结论 | 目标形状 |
|---|---|---|
| `count` | 历史 legacy FlowSpec 流数量；当前 case 已删除 | `flow_control.flows`（框架级） |
| `dst_port` | 历史 legacy FlowSpec TCP 目的端口；当前 case 已迁入 TCP 层 | `{"tcp":{"dst_port":8388}}` |
| `shadowsocks` | legacy 顶层协议映射 | `{"shadowsocks":{...}}` 层项 |

完整目标示例：

```json
{"layers":[{"tcp":{"dst_port":8388}},{"shadowsocks":{}}],"flow_control":{"flows":1}}
```

当前 case 尚未完成严格层链迁移；空壳层例外要求本轮不删除顶层 `shadowsocks`，否则机器用例无法被当前转换链消费。

## 2. 协议栈、端口和输出

TCP 默认端口为 8388。源端口、源/目的 IP、MAC、TTL 和 TCP MSS 由外层/框架配置；协议层只产生 TCP payload 事件。IPv4 典型 TCP payload 起点为 54（14+20+20，未计 TCP options）；SYN options 使控制包头可能更长。IPv6 可由外层 IP 层承载，但当前 Shadowsocks case 没有 IPv6 用例。

pcap 与 NIC 输出应共用同一 cases JSON、同一字段/帧断言；pcap 由测试驱动保存，NIC 由项目约定接口捕获。当前 JSON 仅有结构性 `tcp.dstport`/`tcp.len` 断言，随机加密内容不作十六进制断言。

## 3. 线格式与字段规格

### 3.1 AEAD TCP

SIP003 TCP stream 的实现布局：

- salt：AEAD cipher 时固定 32 B（`SaltLen`，`planner.go:56-63`），一次、方向 up；`cipher=none` 不输出。
- 每个 chunk：`encrypted_length(2 B) + length_tag(16 B) + payload(N B) + payload_tag(16 B)`，总长 `34+N`（`buildAEADChunk`, `planner.go:670-724`）。长度和 tag 是随机占位；N 可为 0。
- `cipher=none` chunk：`plain_length(2 B, big-endian) + payload(N B)`，总长 `2+N`。
- 默认 cipher 为空时按 `aes-256-gcm` 处理；支持 `aes-128-gcm`、`aes-256-gcm`、`chacha20-ietf-poly1305`、`none` 和三个 `2022-blake3-*` 名称（`planner.go:110-128`）。所有非-`none` 名称都走相同 32 B salt/16 B tag 模拟，未实现真实 SIP022 KDF。

chunk 选择算法（`planner.go:495-531`、`layer_gen.go:124-167`）：`Chunks>0` 时重复 Chunks 次；每块大小取 `ChunkPayloadSize`，否则取 `len(Meta.Payload)` 的上限 16383，空 payload 为 0。`Chunks==0` 且 payload 非空时按 `ChunkPayloadSize`（无效或大于 16383 则 16383）分割；否则产出一个 `ChunkPayloadSize` 块。最大 payload 常量 `0x3fff`。

### 3.2 可选 SOCKS5（RFC 1928/1929）

当 `socks5_handshake=true`，事件顺序为 greeting → method response → 可选 password auth request/response → request → reply（`layer_gen.go:74-102`）。字段：

| 消息 | 布局与长度 |
|---|---|
| Greeting | `VER=0x05, NMETHODS=1, METHOD=0x00/0x02`，4 B |
| Method response | `VER=0x05, METHOD`，2 B |
| Auth request | `VER=0x01, ULEN(1), USER, PLEN(1), PASS`，`3+ULEN+PLEN` B |
| Auth response | `VER=0x01, STATUS=0x00`，2 B |
| Request | `VER,CMD,RSV=0,ATYP,ADDR,PORT(2B BE)`；IPv4 addr 4 B、IPv6 16 B、domain 为 length byte + bytes |
| Reply | `VER,REP=0,RSV,ATYP,BND.ADDR,BND.PORT(2B BE)`；默认 bind `0.0.0.0:0` |

CMD 为 CONNECT `0x01`、BIND `0x02`、UDP ASSOCIATE `0x03`。认证字段长度上限 255；密码模式要求用户名和密码非空（`planner.go:201-220`）。

### 3.3 HTTP obfuscation

当 `obfuscation=http`，且未启用 SOCKS5，输出一个 up 方向明文 header，然后 salt/chunks。默认方法 CONNECT；CONNECT 形状为 `CONNECT host:port HTTP/1.1\\r\\nHost: host:port\\r\\n\\r\\n`；非 CONNECT 方法统一输出 POST 行。自定义 `ObfHeaders` 逐项追加，map 迭代顺序不保证确定性（`planner.go:634-667`）。该功能是字节前缀模拟，不是 HTTP 事务实现。

### 3.4 UDP legacy framing（链上禁用）

legacy `Mode=udp` 每个 datagram 为 AEAD 时 `salt(32) + encrypted(plaintext) + tag(16)`，plaintext 为 `RSV(2 BE=0)+FRAG(1)+ATYP+ADDR+PORT(2 BE)+PAYLOAD`；`none` 为 plaintext。`count<=0` 时产 1 个 datagram（`planner.go:405-437,727-778`）。链 validator 在进入生成器前拒绝该 mode，故不属于当前链契约。

## 4. 事务、会话与状态机

### 4.1 五件套（门1 §3）

| 要求 | Shadowsocks 对照 |
|---|---|
| 会话表 | 单 TCP 连接：`tcp` transport + 一个终结层 Shadowsocks 会话；可选 SOCKS5/HTTP 前缀、salt、chunk loop |
| 事务序列 | TCP handshake → optional negotiation → salt → chunk loop → TCP FIN |
| 关联关系 | TCP seq/ack 关联方向；SOCKS5 request/reply 为相邻方向事件；AEAD chunks 仅流内顺序，无 transaction ID |
| 插入位置 | 协议事件由 `shadowsocks` 终结层插入 TCP payload；TCP 层包化、MSS 分段、握手挥手在外层完成 |
| 时间线 | 事件按 Generate/legacy Plan 固定顺序流式发送；每个 MessageEvent 一个完整逻辑 payload，TCP 层可将其按 MSS 分段 |

不适用：控制流派生数据流/父子流关联、单连接多事务响应状态机、协议 keep-alive/retry/reconnect；当前生成器只回放声明式脚本。`Chunks` 是同一连接内重复数据块，不是独立会话。

### 4.2 状态

状态集合为 `Start → (SOCKS5/HTTP optional) → Salted/Plain → Chunks → Done`。UDP legacy 有独立 `Datagram` 循环，但链上被 validator 拒绝。非法状态主要在配置验证期拒绝：缺 Shadowsocks 配置、非法 cipher/mode、UDP 链模式、SOCKS5 参数冲突、MSS/ChunkPayloadSize 越界。

## 5. 业务场景分析与五层覆盖

现网典型用途是客户端到代理的一条长 TCP 连接：现代客户端通常直接发送 AEAD salt/chunks；兼容 SOCKS5 的部署先做 RFC 1928 协商；部分 fork 在 AEAD 前添加 HTTP CONNECT 外观。生成器按声明顺序回放，不连接真实代理、不验证服务端响应。

- **功能层**：默认 AEAD TCP 已有 `shadowsocks_default_tcp`；SOCKS5、HTTP obfuscation、none cipher、UDP legacy、password、域名/IPv4/IPv6 地址均有代码路径但无当前 JSON case。
- **性能层**：chunk 最大 payload 16383；TCP 层按 MSS 分段；每个事件独立 payload；`Chunks` 与 payload split 随配置线性展开。未实现吞吐承诺。
- **数据层**：cipher、salt、tag、payload bytes format、chunk N、SOCKS5 字段和地址类型均可影响线格式；随机密文不可做固定字节断言。
- **地址与流层**：单 TCP 流已覆盖；IPv4 是当前 case；IPv6 由底层可承载但无 Shadowsocks 专属 case。多流/流关联不适用，框架 `flow_control` 可在更高层展开。
- **业务层**：默认 raw AEAD 单连接已覆盖；SOCKS5、多事务代理请求、HTTP 混淆、UDP relay、并发多会话均未纳入当前机器契约。

## 6. 配置字段与默认值

字段解析来自 `strategy_convert.go:5249-5276`，类型来自 `core/types.go:7353-7441`。

| 字段 | 类型/默认 | 生成语义 |
|---|---|---|
| mode | string/tcp | 链上仅 tcp |
| cipher | string/aes-256-gcm | 非 none 使用 AEAD 模拟 |
| socks5_handshake | bool/false | 增加 SOCKS5 序列 |
| socks5_auth_method | string/none | password 增加 RFC1929 |
| socks5_username/password | string/空 | password 必填，≤255 B |
| socks5_cmd | string/connect | CONNECT/BIND/UDP ASSOCIATE |
| socks5_dst_addr/port | string/0 | request 地址与端口；握手时端口非零 |
| socks5_bnd_addr/port | string/0 | reply bind 地址/端口 |
| chunks | int/0 | >0 固定次数；0 按 payload 或默认一块 |
| chunk_payload_size | int/0 | 每块 N，最大 16383 |
| obfuscation | string/空 | `http` 输出 HTTP 前缀 |
| obf_method/headers | string/map | HTTP 前缀方法/头 |
| payload_bytes_format | string/random | `zeros` 令 payload/salt 零，否则随机 |
| frag | uint8/0 | legacy UDP FRAG |
| file_source | object/nil | legacy planner 解析；当前简化生成器未读取文件内容 |

动态字段清单（门1 §12）：`src_ip`、`dst_ip`、`src_port`、`dst_port` 由 TCP/IP 层接收；协议关键字段 `chunks`、`chunk_payload_size`、`cipher`、SOCKS5 地址/端口、HTTP headers` 由单流配置固定。当前 strategy convert 未为 Shadowsocks 协议字段建立 fixed/inc/rand/list/pattern 的逐流序号算法；因此动态字段要求属于缺口，不声称已实现。

## 7. 错误处理契约

| 错误分支 | 代码锚词 | 位置 |
|---|---|---|
| ShadowsocksConfig 缺失 | `ShadowsocksConfig is required` | `planner.go:157-160` |
| IP 非法 | `invalid SrcIP` / `invalid DstIP` | `planner.go:145-155` |
| cipher 不支持 | `unsupported cipher` | `planner.go:162-169` |
| mode 非法 | `invalid mode` | `planner.go:171-174` |
| HTTP 与 SOCKS5 冲突 | `mutually exclusive` | `planner.go:176-182` |
| HTTP 需 TCP | `requires Mode=tcp` | `planner.go:183-186` |
| MSS 太小 | `TCP.MSS ... too small` | `planner.go:189-193` |
| chunk 太大 | `ChunkPayloadSize ... exceeds max` | `planner.go:197-199` |
| password 缺字段/超长 | `SOCKS5Username/Password ...` | `planner.go:201-217` |
| command/mode 不合 | `CMD=...` | `planner.go:222-231` |
| SOCKS5 目标端口为零 | `SOCKS5DstPort must be non-zero` | `planner.go:233-236` |
| domain 超长 | `SOCKS5DstAddr exceeds 255 bytes` | `planner.go:238-242` |
| layer UDP 拒绝 | `Mode=udp is not supported on the layer chain` | `layer_gen.go:202-207` |

负例必须执行期只断言 `expect_error` 与 `error_contains`，并验证任务错误传播和零成功 PCAP；当前 JSON 没有负例。

## 8. 性能、边界与容量

- AEAD chunk 总长度严格为 `34+N`，N ∈ [0,16383]；默认 case 为 N=0：当前 JSON 未设置 chunk size，链上生成器的默认分支仍产一个 34 B AEAD chunk（salt 32 B + chunk 34 B）。
- TCP 逻辑 payload 超过 MSS 时由 TCP 层分段；Shadowsocks 事件自身不聚合全部流量。
- SOCKS5 username/password/domain 最大 255 B；超过即拒绝（长度按 Go `len` 的字节数）。
- cipher=none 去除 salt/tag，chunk 为 2+N；但链 case 默认 cipher 为 AEAD。
- `rand.Read` 错误未被传播，随机字节失败时可能保留零值；这是当前实现边界。

## 9. 当前机器契约对照

唯一 case `shadowsocks_default_tcp`：层内 `tcp.dst_port=8388`、顶层 `shadowsocks={}`。预期至少 9 包，协商/终止成立，packet 1 `tcp.dstport=8388`，packet 4 TCP payload len 32（salt），packet 5 TCP payload len 34（AEAD chunk）。9 包公式：TCP handshake 3 + salt 1 + chunk 1 + TCP FIN teardown 4。随机 bytes 只做长度结构断言。

## 10. 门1 十四行对照表

| § | 满足方式与证据 |
|---|---|
| §1 顶层形状 | 当前为 `{layers,shadowsocks}` 空壳过渡形；严格目标 `[tcp,shadowsocks]`，迁移阻塞点与计划见 §1.1、G-SS-1；证据 cases JSON、`strategy_convert.go:1379-1384`。 |
| §2 规范依据 | RFC1928/1929、SIP003/004/022；实现布局见 §3。 |
| §3 五件套 | 单 TCP 单会话表、事务序列、seq/ack 关联、终结层插入、事件时间线见 §4。 |
| §4 五层覆盖 | 功能/性能/数据/地址流/业务逐层结论见 §5。 |
| §5 状态机 | Start→optional→salt/plain→chunks→Done；代码 `layer_gen.go:74-167`。 |
| §6 线格式 | salt/chunk/SOCKS5/HTTP/UDP 偏移和长度见 §3。 |
| §7 错误 | validator 锚词表见 §7；当前 JSON 尚无负例。 |
| §8 性能 | 16383 上限、MSS 分段、长度公式见 §8。 |
| §9 业务 | raw AEAD、SOCKS5、HTTP 混淆、UDP 边界见 §5/§9。 |
| §10 输出 | pcap/NIC 共享 cases 断言，见 §2。 |
| §11 注册接线 | registry `registry.go:1626`；translate `chain_planner_translate.go:258-260`；validator `layer_gen.go:194-220`。 |
| §12 动态字段 | 四元组来自 TCP/IP；协议字段当前固定，缺口见 §6。 |
| §13 存量审计 | 1 条存量 case 保留但需层链迁移，见 §11。 |
| §14 过期产物 | `trafficgen/docs/protocol-pcap-test/shadowsocks.md` tracked，末次提交 2026-08-27，早于 `0417be5`；登记 G-SS-3。 |

## 11. 存量审计与缺口登记

| ID | 去向 | 说明 |
|---|---|---|
| `shadowsocks_default_tcp` | 保留，待改写形状 | 行为断言与代码一致；`spec_json` 仍是旧 flat 形，下一阶段迁为纯 layers。 |

### 缺口表

| ID | 现象 | 证据 | 归属阶段 |
|---|---|---|---|
| G-SS-1 | 存量 case 为 `{layers,shadowsocks}` 空壳过渡形，层内字段暂无消费者 | `registry.go:1628-1631` 无 `Fields`；`chain_planner_translate.go` 只注入 `spec.Shadowsocks` | P4 代码阶段补 Fields/translate case 后迁移配置 |
| G-SS-2 | 当前仅覆盖默认 raw AEAD，SOCKS5/HTTP/none/边界/IPv6 无 JSON case | `cases/shadowsocks.json` 仅 1 条；代码 `planner.go:448-481,676-724` | P4 用例扩展 |
| G-SS-3 | tracked 结果文档过期且 pcap 未作为当前复跑证据 | `trafficgen/docs/protocol-pcap-test/shadowsocks.md`，commit 早于 `0417be5` | P5 复跑重生成 |
| G-SS-4 | 链上 UDP 被拒，UDP legacy 无等价 transport 契约 | `layer_gen.go:202-207`、`planner.go:405-437` | P4/P5 载体决策 |
| G-SS-5 | Shadowsocks 协议关键字段未实现五种动态策略 | `strategy_convert.go:5249-5276` 仅静态解析 | P4 动态字段 |
| G-SS-6 | 加密随机失败未传播，真实密码学未实现 | `planner.go:117,490,686-706` | P4 实现边界/安全审计 |

## 12. 覆盖反查门建议断言行

供 `coverage_gate.py` 登记，当前均为待补红项：

1. `layers[0].tcp.dst_port == 8388` 且 `layers[1].shadowsocks` 存在；当前空壳过渡例另外保留顶层 `spec_json.shadowsocks`，代码迁移后必须清除。
2. 默认 case 输出顺序为 TCP SYN/SYN-ACK/ACK、32B salt、34B chunk、FIN 四包，总数 ≥9。
3. `tcp.dstport` 在第一包为 8388；第四包 `tcp.len=32`；第五包 `tcp.len=34`。
4. AEAD payload 不得使用固定 hex 断言；只断言长度及终止。
5. 负例逐锚词验证 validator 错误传播；当前无负例，登记为红项。
6. `Mode=udp` 在 layer chain 必须返回 `Mode=udp is not supported`，不得产 UDP 假成功。
7. `ChunkPayloadSize=16384` 必须返回 `exceeds max`；16383 必须接受。
8. password 用户名/密码 255 字节接受，256 字节拒绝。
9. pcap 与 NIC 使用同一断言集。
10. 过期结果文档不得作为今日复跑通过证据。

## 13. 过期产物核验

`trafficgen/docs/protocol-pcap-test/shadowsocks.md` tracked，末次提交为 `e7e7d1c`（2026-08-27），早于判死提交 `0417be5`（2026-09-13）。该文件记录 1/1 pass 和一个 pcap 链接，但当前工作树未以 2026-10-01 复跑验证它；按门1要求登记 G-SS-3，不申报当前通过。

## 14. 修订记录与自审

- v1.1（2026-09-30）：按实现、registry、strategy parser、cases JSON 和 stale artifact 逆向建立；未改 Go 实现或 cases。
- v1.2（2026-10-01）：按当前实现校正链上生成器锚点、默认 cipher 表述与机器用例摘要；未改 Go 实现。
- 自审第 1 轮：逐条核对常量、包数公式、偏移、错误锚词、registry 行、case ID 与缺口证据。
- 自审第 2 轮：机读核对文档提及的唯一 ID、JSON 键、代码行范围和门1十四行；末轮干净。

**自审 2 轮，末轮干净。**
