# #129 wireguard（WireGuard · UDP 承载加密隧道，Whitepaper + RFC 8439 底层）设计契约

> 版本：v1.0.0（P-PIPE 文档轨 P1–P3 首版；修订记录见 §15）
> 日期：2026-09-29
> 车道：文档轨（#129 wireguard 首号，无旧稿）
> 旧基线：**无**（`docs/protocol-designs/` 全史无 wireguard 设计文档，`git log --all` 实测零命中）
> 存量用例：`trafficgen/test/protocol_pcap/cases/wireguard.json`（**仅 1 例 `wireguard_smoke_01`**，2026-08-16 `d4b2c0f` 固化；**spec_json 为扁平形**——顶层 `src_ip/dst_ip/count/wireguard` 四键、无 `layers`，§12.1 逐键清算；**该形状在判死提交 `0417be5`（2026-09-13 CheckProtoFlat 泛化全协议）之后不可创建策略**，见 G-WIREGUARD-2）
> 规范基线：① WireGuard Whitepaper 与官方 protocol 页（wireguard.com/protocol，2026-09-29 拉取：4 类消息 type 1/2/3/4、`AEAD_LEN(x)=x+16`、nonce=RFC 7539 构造、`Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s`；页面不标章节号——**章节号本车道未逐条核对**，引用一律以消息名/字段名为准，条款级核对列 G-WIREGUARD-10）；② RFC 8439（ChaCha20-Poly1305 AEAD，本文只用其 16 字节 tag 长度语义）；③ RFC 7748（X25519 32 字节公钥长度语义）；④ RFC 7693（BLAKE2s 16 字节 MAC 长度语义）；⑤ tshark 3.6.14 `wg.*` 字段表（30 字段，`tshark -G fields` 实测）+ **本车道 15 组离线生成 pcap 的 tshark 实测**（`ChainPlanner→Builder→PCAPWriter` 真实管线，见 §0.2）；⑥ 本仓库落码（`internal/protocol/wireguard/` 两文件 1077 行 + 接线 6 处，§11）；⑦ 代码内注释自引 `whitepaper §3/§4`（`planner.go:34/42/48`——车道未核对原文页码，同 G-WIREGUARD-10）
> 白话一句：**WireGuard 是一条"看起来加密"的 UDP 隧道：握手两步（发起→响应）换会话号，然后每个数据包 = 16 字节头（收方会话号 + 计数器）+ 载荷 + 16 字节尾。本实现把消息骨架、长度、序号、方向全部做真了，但"加密"部分全是种子伪随机字节——载荷甚至是明文直写。**

## 0. 首版 as-built 声明（门1 必答：实现/用例/规范三方现状）

本 #129 是 wireguard 的**第一份契约文档**，无旧稿可承。三方现状对照（每行给证据）：

| # | 事实 | 证据 |
|---|---|---|
| 1 | 实现已落码且单测全绿：2 文件 1077 行 + 3 个测试文件 4739 行、**253 个 `Test*` 函数**（30+199+24 机读实测），`go test ./internal/protocol/wireguard/ -count=1` OK，`go vet` 零输出 | `wc -l`/`grep -c '^func Test'` 实测（2026-09-29） |
| 2 | 层已注册但**层内字段表为空壳**：`LayerSchema{Name:"wireguard", Category:CategoryTerminal, DependsOn:["udp"], FieldContract:{"udp.dst_port":"51820"}}`——**无 `Fields`**；生成表 127 层中 wireguard 条目 `"fields": {}`（`schemas/v1/generated/layers.generated.json` 机读实测） | `registry.go:498-501`；生成表 JSON 实测 |
| 3 | **层内任何业务键即拒**：`{"layers":[{"udp":{}},{"wireguard":{"role":"responder"}}]}` → `layers: layer "wireguard": unknown field "role"`（探针实测）；`transport_payloads` 动态对象 → `layers[1](wireguard).transport_payloads does not support dynamic`（探针实测） | 本车道探针（ValidateLayers 直调） |
| 4 | **translate 无 wireguard 分支**：`translateTerminalConfig` 的 switch（`chain_planner_translate.go:855` 起 40+ case）无 `case "wireguard"`；全仓 `spec.WireGuard` 赋值仅 2 处（flat 顶层 `strategy_convert.go:1553`、引擎直调） | `grep -rn "spec.WireGuard" internal/ --include=*.go` 实测 3 文件 5 行 |
| 5 | **业务配置唯一 JSON 可达路径 = 顶层 `wireguard` 子映射**（扁平残留）：`{"wireguard":{"role":"responder"}}`（无四元组键）过 `ValidateStrategy`（探针实测 errs 空）；该子映射 `CheckProtoFlat` **无 presence 分支不判死**（`{"layers":[...],"wireguard":{}}` 探针实测通过）→ 与 1.11 顶层白名单冲突，见 G-WIREGUARD-1/G-WIREGUARD-4 | 本车道探针 |
| 6 | **存量 1 例今日不可跑**：`wireguard_smoke_01` spec_json 含顶层 `src_ip/dst_ip/count` → `CheckProtoFlat("wireguard", cfg)` 返回 `protocol wireguard no longer accepts flat config field src_ip`（**以该例逐字 spec 探针实测**）；MCP 套件路径经 strategy create（`strategy_handler.go:30 schemaGate`）必 400 → 用例 status=error | 本车道探针（schema.ValidateStrategy 直调该例 spec_json 逐字）；G-WIREGUARD-2 |
| 7 | 断言内容本身与实现一致：该例 9 条字段断言（type 1/2/4、sender 1/2、receiver 1/2、counter 0、dstport 51820、包数 3）**与离线生成 pcap 逐条吻合**（§0.2）——坏的只是形状，不是断言 | §0.2 实测 |
| 8 | 结果文档过期：`docs/protocol-pcap-test/wireguard.md`（tracked）写 "Cases: 1 — pass 1, fail 0, error 0"，末次提交 `e7e7d1c`（2026-08-27）**早于判死提交 `0417be5`**（2026-09-13）；`docs/protocol-pcap-test/wireguard/` 目录**不存在（0 个 pcap 文件）** | `git log`/`ls` 实测；G-WIREGUARD-9 |
| 9 | `/tmp/mcp-pcaps/wireguard/` 与 `/tmp/mcp-nic-pcaps/wireguard/` 均为**空目录（0 文件）**——本车道也未跑 MCP 套件（live 库边界），套件今日真实状态未知，本文一切运行面结论来自**离线探针**并逐处标注 | `ls -la` 实测 |
| 10 | 离线层链套件不含 wireguard：`chainSuiteProtos` 18 协议名单无 wireguard（`layer_chain_suite_test.go:70-78`）→ flat 形与层链形都**不被离线执行器拾取** | 代码实测 |

### 0.1 加密面诚实边界（本协议特殊性，不得夸大）

`planner.go` 文件头注释（`:7-14`）自述 "It performs NO real cryptography"——**逐字段证实**：

| 线上字段 | 规范真身 | 本实现写什么 | 证据 |
|---|---|---|---|
| `ephemeral`（32B） | X25519 未加密临时公钥 | `fillDeterministic(seed=senderIndex,0)` 伪随机；或用户配 `local_ephemeral_pub_key`（32B）原样写入（**此键真实消费**） | `planner.go:295-299`；实测设 0x11×32 后首包字节改变 |
| `enc_static`（48B） | ChaCha20-Poly1305 加密静态公钥（32+16 tag） | `fillDeterministic(seed=senderIndex,1)` 伪随机 | `planner.go:505-507` |
| `enc_timestamp`（28B） | 加密 Tai64n（12+16 tag） | `fillDeterministic(seed=senderIndex,2)` 伪随机 | `planner.go:510-512` |
| `enc_empty`（16B） | 加密空载荷（0+16 tag） | `fillDeterministic(seed=senderIndex,5)` 伪随机 | `planner.go:555-557` |
| `mac1`（16B） | BLAKE2s keyed MAC | `fillDeterministic(seed=senderIndex,3/6)` 伪随机 | `planner.go:515-517/560-562` |
| `mac2`（16B） | BLAKE2s cookie MAC（无 cookie 恒零） | 无 cookie：**全零**（与真实协议一致）；配 16B cookie：`fillDeterministic(seed=senderIndex,4/7)` 非零 | `planner.go:519-528/564-570`；实测两态 |
| transport `enc_payload`（N+16） | ChaCha20-Poly1305 **密文** | **载荷明文原样直写** + 16B 伪 tag（`fillDeterministic(seed=counter,10)`）——**payload 可在 pcap 中直接读出** | `planner.go:625-632`；实测 "abc" 明文可见 |
| `nonce`（24B，cookie） | XChaCha nonce | `fillDeterministic(seed=receiverIndex,8)` 伪随机 | `planner.go:590-592` |
| `enc_cookie`（32B） | 加密 cookie（16+16） | `fillDeterministic(seed=receiverIndex,9)` 伪随机 | `planner.go:595-597` |

确定性锚：`fillDeterministic`（`planner.go:641-651`）= Go `math/rand` 以 `0xDEADBEEF ^ (s×0x9E3779B97F4A7C15)` 播种——**同配置跨进程字节级可复现**（实测两次独立生成 `wg.ephemeral` base64 完全一致）。**结论**：本实现是"线格式保真、密码学模板"的流量发生器——断言面只能钉长度/偏移/序号/方向，**不得**断言任何密文语义（tshark 的 `wg.handshake_ok`/`wg.timestamp.*` 解密字段永不出现）。

### 0.2 本车道实测基线（15 组离线生成 pcap，tshark 3.6.14 实读）

生成路径：`layers.NewChainPlanner("wireguard").Plan` → `core.NewBuilder().Build` → `output.PCAPWriter`（与生产同管线；spec 固定 `10.0.0.1:12345 → 20.0.0.1:51820`、TTL 64）。**全部零 `_ws.malformed`**：

| 组 | 配置要点 | 包数 | 帧长序列 | 关键读数 |
|---|---|---|---|---|
| default | 空配置 | 3 | 190/134/75 | type 1/2/4；sender 1→2；receiver（resp）=1、（data）=2；counter 0；data 方向 up |
| responder | `role=responder` | 2 | 134/75 | **无 Initiation**；type2 sender=2 receiver=**3**（=`responderIndex+1`）；data receiver=2 |
| cookie | responder+`cookie_reply_threshold=1` | 3 | 134/106/75 | 帧序 Response→**CookieReply(type3, receiver=3)**→Data |
| payload5 | `transport_payloads=5B` | 3 | 190/134/79 | data 帧长 79 = 42+16+5+16 |
| payload1440 | `transport_payloads=1440B` | 3 | 190/134/1514 | **帧长恰 1514**（以太 MTU 顶格） |
| keepalive | `keepalive_interval=10` | 4 | 190/134/75/74 | 第 4 包=32B 纯 tag，counter=1，方向 up |
| rekey3 | 4 payloads + `rekey_after=3` | 8 | 190/134/75/75/75/190/134/75 | counter 0/1/2 →（重握手 init sender=3、resp sender=4 receiver=3）→ data **receiver 仍=2**、counter **0** |
| both | `direction=both` 2 payloads | 4 | 190/134/75/75 | data 交替 up/down（按载荷下标偶 up 奇 down） |
| nohandshake | `Handshake=false`（**结构体指针注入**，见 G-WIREGUARD-6） | 1 | 75 | 只有 data |
| idx42ctr100 | `sender_index=42, initial_counter=100` | 3 | 190/134/75 | sender=0x2a/0x2b；receiver=0x2b；counter=100 |
| ipv6 | 外层 IPv6 | 3 | 210/154/95 | 帧长 = 62+消息长（62=14+40+8） |
| innerip | `inner_ip{udp,53,"abc",2 帧}` | 4 | 190/134/105/105 | data 105 = 42+16+**31**+16；内层 `45 00 00 1f 00 01 40 00 40 11 12 b7` 逐字节可读（IPID=1、DF、TTL64、校验和 12b7、10.10.10.1→10.10.10.2、UDP dport 53、"abc" 明文） |
| cookiecfg | `cookie=16B` | 3 | 190/134/75 | `wg.mac2` 两包均非零 |
| keys | `psk/static×32B` | 3 | 190/134/75 | **与 default 字节级全同**——三把密钥零消费（G-WIREGUARD-7） |
| eph | `local_ephemeral_pub_key=32B` | 3 | 190/134/75 | 首包字节改变（**此键真实消费**） |

**帧长公式（实测闭合）**：帧长 = 42 + 消息长（IPv4）/ 62 + 消息长（IPv6）；消息长：Initiation 148、Response 92、CookieReply 64、Transport `32+N`（N=0 即 keepalive）。校验：190=42+148 ✓、134=42+92 ✓、106=42+64 ✓、75=42+33（N=1）✓、74=42+32 ✓、79=42+37（N=5）✓、1514=42+1472（N=1440）✓、105=42+63（N=31=20+8+3）✓、210/154/95=62+{148,92,33} ✓。**14/14 组全闭合。**

**tshark 进制纪律（实测）**：`wg.type` 十进制串（"1"/"2"/"4"）；`wg.sender`/`wg.receiver` **0x 八位十六进制**（`0x00000001`）；`wg.counter` 十进制串；`wg.reserved` 无前缀十六进制（`000000`）；`wg.mac1`/`wg.mac2` 小写十六进制；`wg.ephemeral` base64。tshark **无** `udp.port==51820,wireguard` 静态绑定（`-d` 报 `Unknown protocol -- "wireguard"`，合法名是 `wg`），解码走**启发式**——格式正确的消息任意端口可解（引擎 pcap 实测），畸形长度消息不解（构造 144B 假 Initiation 实测被拒）；存量用例未用 `decode_as`，非 51820 端口正例依赖启发式成功，纳入断言风险注记（§8）。

## 1. 范围、profile 与实现状态边界

本版定义 **WireGuard 传输面报文合成**承载于 UDP（缺省 51820）：Handshake Initiation（type 1）/ Handshake Response（type 2）/ Cookie Reply（type 3）/ Transport Data（type 4）四类报文的线格式、会话索引与计数器语义、方向/角色驱动序、内层 IP 隧道（`inner_ip`）与 MTU 边界。**不覆盖** Noise IKpsk2 握手密码学（§0.1 诚实边界）、密钥派生、会话状态机超时（`REJECT_AFTER_TIME` 族）、多 peer 路由语义。

| profile | 承载 | 本版允许内容 | 不从 profile 推导 |
|---|---|---|---|
| `wg_udp_v1`（主） | UDP，fixture 51820 | 默认 initiator 序（Init→Resp→Data）、type 1/2/4 结构与序号 | 真实对端握手（密钥协商） |
| `wg_roles_v1` | 同上 | responder 角色序、Cookie Reply、direction up/down/both、rekey | 真实 under-load 判定（CookieReplyThreshold 是开关不是阈值） |
| `wg_tunnel_v1` | 同上 | `inner_ip` 内层 IPv4/IPv6 完整包（ICMP/TCP/UDP） | 内层真实路由 |
| `wg_ipv6_v1` | 同上，仅外层 IPv6 | 同 `wg_udp_v1` | 从 IPv4 fixture 推导 IPv6 地址 |

显式边界（"不实现、不声称、不许静默转换"）：① **不实现任何密码学**（§0.1，G-WIREGUARD-10 明确不解决）；② 不实现会话超时/`REJECT_AFTER`/`rekey_after_time`（`planner.go:283` 显式 `_ = wg.RekeyAfterTime` 忽略，G-WIREGUARD-7）；③ 不实现多 peer/路由表（单四元组单隧道）；④ 不实现 keepalive 周期化——`keepalive_interval>0` 只追加 **1 个** keepalive 包，不是周期流（§5 诚实声明）；⑤ 不实现 Cookie 的 under-load 真实判定（`CookieReplyThreshold>0` 即发一包，:403）；⑥ 不实现传输层分段（UDP 数据报一包一消息，无 TCP 分段问题）。

**实现状态（2026-09-29 实测）**：`wireguard` 层已注册（`registry.go:498`，`CategoryTerminal`，`DependsOn ["udp"]`，FieldContract 51820，**Fields 空**）；planner/generator 已落码（`internal/protocol/wireguard/` 两文件 1077 行）；`allowedProtocols["wireguard"]=true`（`protocols.go:60`）；缺省目的端口 51820（`chain_planner.go:1092-1096`）；源端口 0 放行名单含 wireguard（`chain_planner.go:924`）；FlowMeta 直传（`chain_planner_translate.go:227-229`）；服务端空导入 + 注册 planner（`cmd/server/main.go:204/:610`）；flat 顶层子映射解析（`strategy_convert.go:1551`）。

**输出契约（pcap/NIC 双输出）**：两路径共用同一 cases JSON 与断言集（`udp.dstport/srcport`、`wg.*` 字段、offset 42/62 frames）；NIC 经 tcpdump 捕获（`nic_capture` 用例级开关）；不设仅单路径可用的断言。

## 2. 协议栈、端口和固定偏移

推荐层链为 `[ip, udp, wireguard]`（引擎自动补 `ip`；最小链 `[udp, wireguard]`）。WireGuard 报文是 **UDP payload 的应用层字节**，一消息一数据报（UDP 无握手挥手，tcp 层不参与）。

端口：IANA 缺省 **UDP 51820**（`planner.go:37 DefaultPort`；链路径缺省 `chain_planner.go:1092-1096`；`registry.go:500` FieldContract 同值——**FieldContract 只进生成表/schemagen（`schemagen/main.go:70`），端口实际落地点是 validateSpecBase switch**）。fixture 统一 `dst_port=51820`；用例一律显式写端口并纳入断言（W02 例外：专测缺省补齐）。

固定偏移：无 VLAN/IP options 时，**每帧 WireGuard 消息起点 = IPv4 offset 42**（14+20+8）、**IPv6 offset 62**（14+40+8）。消息内字段偏移按 §3 逐表递推；**四类消息除 Transport 的 enc_payload 外全部定长**——消息长度是本协议的核心常量（148/92/64 恒定，Transport = 16 头 + N + 16 tag）。

目标形状 spec_json 样例（严格层链形，顶层仅 `layers`；**本协议存量 0 例合规——唯一存量例是扁平形**）：

```json
{
  "layers": [
    {"ip": {"src": "10.0.0.1", "dst": "20.0.0.1"}},
    {"udp": {"src_port": 12345, "dst_port": 51820}},
    {"wireguard": {}}
  ]
}
```

**诚实注记**：目标形里的 `wireguard` 层 config **今日只能是 `{}`**——任何键被 V9 拒（§0 #3）。业务配置（role/direction/payload/cookie/rekey/inner_ip）今日唯一可达形状是**顶层 `wireguard` 子映射**（`{"layers":[…],"wireguard":{…}}` 混合形，违规但可跑）或纯扁平形；目标形等 A′ 层内化（G-WIREGUARD-2/G-WIREGUARD-3）后逐例落地，§9.2 目标 ID 表逐例标注今日可达性。

多流样例（数量只走 `flow_control`；源端口走 udp 层动态对象，allowlist 已开）：

```json
{
  "layers": [
    {"udp": {"src_port": {"strategy": "inc", "range": [40000, 40010], "step": 1}}},
    {"wireguard": {}}
  ],
  "flow_control": {"type": "flows", "value": 3}
}
```

## 3. 线格式编码（逐字段，按代码 + 实测钉）

### 3.1 公共头（4 类消息共用前 4 字节）

| 偏移 | 字段 | 尺寸 | 说明 |
|---|---|---|---|
| 0 | `message_type` | 1 字节 | 1=Handshake Initiation、2=Handshake Response、3=Cookie Reply、4=Transport Data（`planner.go:43-46`） |
| 1 | `reserved_zero` | 3 字节 | **恒 `00 00 00`**（make 零值直填，`planner.go:496` 注释口径）；tshark `wg.reserved`=`000000` 实测 |

**端序总则**：所有多整数宇段 **little-endian**（`binary.LittleEndian` 逐处，`planner.go:499/546/549/587/618/621`）；与载荷字节序无冲突（载荷不解释字节序）。**总长度公式**：`Initiation=148`、`Response=92`、`CookieReply=64`（三者为常量）；`Transport=16+16+N=32+N`。

### 3.2 Handshake Initiation（type 1，148 字节，`buildInitiation` `planner.go:489-532`）

| 偏移 | 字段 | 尺寸 | 值来源（as-built） |
|---|---|---|---|
| 4 | `sender_index` | 4B LE | `cfg.SenderIndex`，0→**1**（`planner.go:269-272`）；实测 42→`0x0000002a` |
| 8 | `unencrypted_ephemeral` | 32B | `LocalEphemeralPubKey`（32B 校验）或伪随机（seed=senderIndex,0）；实测两态 |
| 40 | `encrypted_static` | 48B（32+16 tag） | 伪随机（seed=senderIndex,1） |
| 88 | `encrypted_timestamp` | 28B（12+16 tag） | 伪随机（seed=senderIndex,2） |
| 116 | `mac1` | 16B | 伪随机（seed=senderIndex,3）——**非真实 BLAKE2s** |
| 132 | `mac2` | 16B | 无 cookie **全零**；16B cookie → 伪随机（seed=senderIndex,4） |

长度算术闭合：1+3+4+32+48+28+16+16 = **148** ✓（实测帧 190 = 42+148）。

### 3.3 Handshake Response（type 2，92 字节，`buildResponse` `planner.go:536-573`）

| 偏移 | 字段 | 尺寸 | 值来源 |
|---|---|---|---|
| 4 | `sender_index` | 4B LE | initiator 流 = `senderIndex+1`（`:273`）；responder 流 = `senderIndex+1`（同一算式，`:390` 处 initiatorIndex=responderIndex+1 详 §5.3） |
| 8 | `receiver_index` | 4B LE | initiator 流 = `senderIndex`；responder 流 = `senderIndex+2`（实测 role=responder：sender=2、receiver=**3**） |
| 12 | `unencrypted_ephemeral` | 32B | 伪随机（seed=responderIndex,0） |
| 44 | `encrypted_nothing` | 16B（0+16 tag） | 伪随机（seed=senderIndex,5） |
| 60 | `mac1` | 16B | 伪随机（seed=senderIndex,6） |
| 76 | `mac2` | 16B | 同 3.2 规则（无 cookie 全零；有 cookie 伪随机 seed=senderIndex,7） |

长度闭合：1+3+4+4+32+16+16+16 = **92** ✓（实测帧 134）。

### 3.4 Cookie Reply（type 3，64 字节，`buildCookieReply` `planner.go:577-600`）

| 偏移 | 字段 | 尺寸 | 值来源 |
|---|---|---|---|
| 4 | `receiver_index` | 4B LE | = initiatorIndex = `responderIndex+1`（`:403-407`；实测 =3） |
| 8 | `nonce` | 24B | 伪随机（seed=receiverIndex,8） |
| 32 | `encrypted_cookie` | 32B（16+16 tag） | 伪随机（seed=receiverIndex,9） |

长度闭合：1+3+4+24+32 = **64** ✓（实测帧 106）。**触发条件**：仅 `role=="responder" && CookieReplyThreshold>0`（`:403`）——阈值是布尔开关，无 under-load 判定（§1 边界⑤）。**帧序**：恒排在 Response 之后（`:385` 先、`:403` 后；实测帧 1=Response、帧 2=Cookie）。

### 3.5 Transport Data（type 4，`32+N` 字节，`buildTransportData` `planner.go:605-635`）

| 偏移 | 字段 | 尺寸 | 值来源 |
|---|---|---|---|
| 4 | `receiver_index` | 4B LE | **恒 `responderIndex`**（`:457`）——rekey 后**不更新**（仍指旧 responderIndex，实测 rekey 组第 8 包 receiver=0x00000002；§5.5 保真度注记） |
| 8 | `counter` | 8B LE | 起点 = `InitialCounter`（默认 0），每载荷 +1；rekey 插入后**重置 0**（`:450`；实测 0/1/2→0） |
| 16 | `encrypted_encapsulated_packet` | N+16 | **N 字节载荷明文原样** + 16B 伪 tag（seed=counter,10）；`inner_ip` 时 N = 完整内层 IP 包 |

长度闭合：1+3+4+8+N+16 = **32+N** ✓（实测 N=0→74 帧、N=1→75、N=5→79、N=1440→1514）。

### 3.6 内层 IP 包（`inner_ip`，`planner.go:683-974`）

`buildInnerIPPackets` 逐帧产出完整内层包作 Transport 载荷：IPv4 头 20B（`0x45`、总长、**IPID=i+1**、**DF=0x4000**、TTL 默认 64、proto、**头部校验和真实计算** RFC 791 §3.1）；IPv6 头 40B（version 6、**FlowLabel 低 20 位 = i+1**、payload len、NextHeader、HopLimit，无头校验和）。L4：UDP（v4 校验和**合法置 0** RFC 768；v6 **必算**伪头校验 RFC 8200 §8.1）、TCP（两侧必算，窗口 65535）、ICMP（v4 type=8 echo；v6 按 ICMPv6 type=128、proto 58 伪头）。实测证据：`45 00 00 1f 00 01 40 00 40 11 12 b7 0a 0a 0a 01 0a 0a 0a 02 00 00 00 35 00 0b 00 00 61 62 63`（IPID 1、DF、TTL 64、校验和 12b7、dport 53、"abc"）。

## 4. 业务场景分析（现网典型场景与五层覆盖）

**定性**：**声明式剧本回放**——配置声明角色/方向/载荷清单，引擎按固定剧本产出数据报（Init→Resp→[Cookie]→Data×N→[Keepalive]）；udp 层只逐事件封包。WireGuard 本身无连接状态机（UDP），"握手"是消息对不是 TCP 式连接。

| 现网场景 | 事务交互 | 对应用例（目标 ID） |
|---|---|---|
| ① 站点到站点建隧 + 首包 | initiator 完整序 Init→Resp→Data | W01/W06–W09 |
| ② 移动办公客户端周期保活 | Data×N + Keepalive | W20/W21 |
| ③ 包数阈值重密钥 | Data×3 → Rekey(Init+Resp) → Data | W22/W23 |
| ④ 服务器遭 DoS 下发 Cookie | Resp + CookieReply | W13 |
| ⑤ 内层业务流量（DNS/HTTP/ping） | Transport 载完整内层 IP 包 | W26–W31 |
| ⑥ 双栈产线 | 同①仅外层 IPv6 | W05 |
| ⑦ 多客户端并发 | flows=N 多四元组 | W34–W36 |
| ⑧ 配置防呆 | 14 类非法配置拒绝 | N01–N16 |

**五层覆盖逐层结论**：功能层——四类消息正例全布 + 14 类 validator 拒绝分支负例（§7）；性能层——**最大帧 1514**（payload 1440 顶格以太 MTU）、最小数据帧 74（keepalive）、MTU 1440 上界拒绝、多载荷计数器序列；数据场景层——定长消息三类（148/92/64）、变长一类（32+N：0/1/5/1440 边界 + 1441 拒绝）、sender_index 0 自增/42 显式/2^32-1 上界、counter 0/100/2^64-1、cookie 0/15/16/17B、密钥 0/31/32/33B、方向三态、角色两态；地址与流层——v4/v6 独立用例、单流基线、多流 `flow_control`+动态端口；**流关联（控制流派生数据流）显式不适用**：WireGuard 单 UDP 五元组承载全部消息，无副连接；**多会话（sessions[]）显式不适用**：UDP 无连接、会话身份由 sender_index 表达且本实现单隧道单会话索引（rekey 换新索引是唯一"多会话索引"形态，W22 覆盖）；业务层——八场景全部有落点（①–⑧）。

**次要合法行为显式不适用声明（不设正例、亦不得进负例）**：① 真实握手密码学（G-WIREGUARD-10）；② under-load 真实 Cookie 判定（阈值开关替代）；③ keepalive 周期化与 idle timeout（单包模拟）；④ `rekey_after_time` 时间阈值（`:283` 显式忽略，G-WIREGUARD-7）；⑤ 多 peer/allowed-ips 路由（单隧道）；⑥ 非法值进入**合法**通道（reserved 非零/类型 5-255——builder 无分支恒拒不了，tshark 侧 `wg.bad_packet_length` 只对长度，值域门属对端行为不入生成器断言）。

## 5. 消息/事务模型与状态机

**事务定义**：一次握手对（Init+Resp）= t1；一包 Transport Data = t2（可重复）；Keepalive = t3（可选收尾）。**多事务** = 单流内 t1 一次 + t2×N 有序。

wireguard 层无自有状态机：UDP 无连接，wireguard 层是"按配置顺序把角色剧本翻译成数据报"的纯函数驱动；"会话"仅由 sender_index/receiver_index 数值对表达。

### 5.1 事件序（`Plan`，`planner.go:186-485`；initiator 主线）

```
[handshake=true]
  role=initiator:  Emit Up(Initiation, sender=senderIndex)          ← :360-368
                   Emit Down(Response, sender=responderIndex, receiver=senderIndex)  ← :370-381
  role=responder:  Emit Down(Response, sender=responderIndex, receiver=responderIndex+1)  ← :385-400
                   [CookieReplyThreshold>0] Emit Down(CookieReply, receiver=responderIndex+1)  ← :403-416
[transport 循环，逐载荷 i]                                             ← :421-467
  [counter >= rekeyAfter 且未触发] Emit Up(Initiation, sender=senderIndex+2)
                                   Emit Down(Response, sender=senderIndex+3, receiver=senderIndex+2)
                                   counter=0（rekey 每流至多一次，:420 rekeyTriggered）
  dir = resolveDirection(Direction, i)   # up→up / down→down / both→偶 up 奇 down  ← :656-671
  Emit dir(TransportData, receiver=responderIndex, counter=counter); counter++
[keepaliveInterval>0] Emit resolveDirection(Direction, N)(TransportData, nil 载荷=32B)  ← :470-481
```

**实测帧位对账（default 组）**：帧 1=Init(up,190)、帧 2=Resp(down,134)、帧 3=Data(up,75)。**包数公式**：
- initiator+handshake：`2 + N载荷 + K保活(0/1) + 2×R重握手`；default=2+1=3 ✓、keepalive 组=2+1+1=4 ✓、rekey3 组=2+4+0+2=8 ✓
- responder：`1 + N + K + 2×R + C_cookie(0/1)`；responder 组=1+1=2 ✓、cookie 组=1+1+1=3 ✓
- handshake=false：`N + K`；nohandshake 组=1 ✓

### 5.2 服务选择（载荷来源优先级，`planner.go:249-266`，从高到低）

① `FileSource`（文件字节，整文件一包）；② `InnerIP`（内层 IP 包 ×DataFrames）；③ `TransportPayloads`（原字节数组逐项一包）；④ 默认：**单包 1 字节 `{0x00}`**（`:264-266`——default 组第 3 包 33B 的来历）。

### 5.3 角色/方向/开关矩阵（实测 ×代码互证）

| 配置 | 产出 | 实测 |
|---|---|---|
| `role` 缺省/`initiator` | Init(up)+Resp(down)+载荷 | default 组 |
| `role=responder` | **无 Init**；Resp(down)+载荷；Resp 的 receiver=**senderIndex+2**（responderIndex+1） | responder 组 receiver=3 |
| `handshake=false` | 跳过握手直发载荷（**JSON 不可达**——`parseWireGuardConfig` 不解析该键，G-WIREGUARD-6） | nohandshake 组 |
| `response=false` | **仅 responder 分支生效**（`:385` 判 `doResponse`）；initiator 分支不读它——initiator 的 Response 无法关掉 | 代码实测（`:370-381` 无判） |
| `direction=down` | 载荷与 keepalive 全 down（握手帧位不变） | 代码 `:656-671` |
| `direction=both` | 载荷按下标交替（偶 up 奇 down） | both 组 |
| `cookie_reply_threshold>0` | responder 追加 1 包 CookieReply | cookie 组 |
| `rekey_after=R>0` | 第 counter≥R 个载荷前插重握手对，counter 归零，每流至多一次 | rekey3 组 |
| `keepalive_interval>0` | 追加 **1 包** 32B keepalive（非周期，§1 边界④） | keepalive 组 |

### 5.4 自动派生规则（生成器自动补出的帧逐条）

① `SenderIndex==0` → 1；`responderIndex = senderIndex+1`（`:269-273`）；② initiator 流自动补 Response（down）一帧；③ responder 流自动以 `responderIndex+1` 当对端索引；④ rekey 自动补 Init+Resp 对并归零 counter；⑤ keepalive 自动以 `resolveDirection(direction, len(payloads))` 定向；⑥ TCP 握手/挥手无（UDP）；⑦ IP ID：外层由链路 `ipID++` 递增、内层 `IPID=i+1`（`:780`）；⑧ TTL：外层 spec.TTL 缺省 64（`:237-240`）、内层 `ip.ttl` 缺省 64（`:763-766`）。

### 5.5 保真度注记（as-built 与真实协议的偏差，不冒充合规）

① responder 角色不发 Initiation 直接发 Response——真实协议 Response 必答于 Init（本实现是单向角色剧本，非对答模拟）；② **rekey 后 Transport 的 receiver_index 仍指旧 responderIndex**（`:457` 用未更新的变量；真实协议应指新会话索引）——实测第 8 包 receiver=0x00000002（旧值）；③ CookieReplyThreshold 无 under-load 语义（有值即发）；④ keepalive 单包非周期。①②④ 为**确认的 as-built 偏差**，修复属代码阶段裁定项（G-WIREGUARD-8）；本文档与用例**按实现现状钉**，不按真实协议断言这些位。

## 6. 性能设计与验收（CORE_MEMORY §6.1–6.8）

- **目标与边界**：单流帧长域 = `[74, 1514]`（keepalive 32B 最小 → 帧 74；payload 1440 顶格 → 帧 1514，**恰等以太 MTU**，不产生 jumbo）；载荷上界 1440（`MaxTransportPayload`，`planner.go:72`），超界 Validate 拒；单流包数 = `2+N+K`（initiator）线性于载荷数，无上限。吞吐数字待 P4 基准，**本版不写承诺**（§6.5）。
- **依据**：Plan 为单 goroutine channel 流式产出（buffer 256，`:191`），逐包构造即发，无全量聚合；每包内存 = 该包消息体（≤1514-42）；无跨流共享状态、无锁（局部变量 + 值传递；`fillDeterministic` 每 buf 独立 rand 实例）；`InnerIP`/`FileSource` 在流开始一次解析。
- **验收两路（§6.3 强制）**：pcap（`/tmp/mcp-pcaps/wireguard/`，`<id>.pcap` / 负例 `<id>.neg.pcap`）与 NIC（`enp135s0f0np0`，`nic_capture` 开关）共用同一断言集；断言实际 `wg.*` 字段、帧原始 hex 与 `packet_count`，不只断言"任务没报错"。
- **六类场景落点（§6.6）**：基线（W01，3 帧）/ 目标规模（W18 多载荷 5 帧）/ 压力上限（W 之 payload1440 帧 1514 + N10 越界拒绝）/ 长时间运行（**单包模拟**——W20 keepalive 一包承载语义，周期流不在本版）/ 并发交错（W16 交替方向 + W34 动态端口多流）/ 背压（`packet_count` 精确计数守卫 + MTU 上界守卫）。

## 7. 错误处理（负例锚词表，与 testcase §4 一一对应、同序）

以下输入必须由 planner/validator 拒绝并传播为 task error，不得产出成功 PCAP 或 `completed/0 packet` 假成功。锚词逐字取自 `planner.go`（行号实测）：

| # | 锚词（代码逐字） | 代码行 | 触发输入 |
|---:|---|---|---|
| V-1 | `wireguard: SrcIP %q is not a valid IP address` | `:98` | 外层 src 非法（链路径 ip 层先行拦，锚词变体见 §7.2） |
| V-2 | `wireguard: DstIP %q is not a valid IP address` | `:101` | 外层 dst 非法（同上） |
| V-3 | `wireguard: Role must be initiator or responder` | `:110` | `role` 非法值 |
| V-4 | `wireguard: Direction must be up, down, or both` | `:115` | `direction` 非法值 |
| V-5 | `wireguard: LocalStaticPubKey must be 32 bytes (X25519)` | `:120` | 31B/33B |
| V-6 | `wireguard: PeerStaticPubKey must be 32 bytes (X25519)` | `:123` | 非 32B |
| V-7 | `wireguard: LocalEphemeralPubKey must be 32 bytes (X25519)` | `:126` | 非 32B |
| V-8 | `wireguard: PSK must be 32 bytes (Noise_IKpsk2)` | `:131` | 非 32B |
| V-9 | `wireguard: Cookie must be 16 bytes (BLAKE2s output)` | `:136` | 15B/17B |
| V-10 | `wireguard: RekeyAfter too large (recommend < 2^60)` | `:148` | `>= 2^60` |
| V-11 | `wireguard: KeepaliveInterval must be >= 0` | `:153` | 负值 |
| V-12 | `wireguard: Transport payload[%d] exceeds MTU (max %d)` | `:159` | 载荷 > 1440 |
| V-13 | `wireguard: FileSource: %w` | `:166` | 文件源错误 |
| V-14 | `wireguard: InnerIP: %w` | `:173` | 内层 6 分支（下表） |

**V-14 内层分支锚词**（`validateInnerIP`，`planner.go:683-729`）：`SrcIP %q is not a valid IP address` / `DstIP %q is not a valid IP address` / `SrcIP and DstIP must be the same address family (got v4/v6 mix)` / `Proto %d not in supported list (allowed: 1=ICMP, 6=TCP, 17=UDP)` / `DataFrames %d must be >= 0` / `built inner packet (%d bytes) exceeds MTU (max %d)`。

### 7.1 死分支与不可达声明

① `:139-144` SenderIndex==0 检查**空实现**（注释自认无法区分"未设"与"设 0"，零值即自增语义）——无锚词，不设负例；② V-1/V-2 的**层链路径不可达**：地址住 ip 层，ip 层先行以 `layers[0](ip).src: invalid IP endpoint "…"` 拒（探针实测）——层链负例用 ip 层锚词，V-1/V-2 仅 flat 引擎直调可达；③ **V-3…V-14 的层链路径今日全部不可达**（层内键 unknown field 先拒，G-WIREGUARD-2）——今日这些负例只能以顶层子映射形驱动（可跑但形状违规），A′ 层内化前**目标负例逐条标"待 A′"**，不得以"今日已绿"申报。

### 7.2 不得误报的合法协议事件

多载荷多包（W18）；direction=both 交替（W16）；rekey 中插（W22）；keepalive 追加（W20）；responder 无 Initiation（W12，§5.5 偏差按现状断言）；内层 ICMPv6 用 proto=1 + type 128（`:911-916` 注释口径）。

## 8. 边界

- **消息长度**：Init 148 / Resp 92 / Cookie 64 常量；Transport `32+N`，N∈[0,1440]；帧长域 `[74,1514]`（IPv4）。N=1441 拒（V-12）。
- **sender_index**：0=自增（→1）；显式值原样；上界 `MaxSenderIndex=2^32-1`（`:81` 常量存在但 **Validate 无上界分支**——uint32 天然封顶，无拒绝路径，不设负例）。
- **counter**：`InitialCounter` 任意 uint64；rekey 归零；上界 `DefaultRekeyAfter=2^60` 触发拒绝仅作用于**配置阈值**（V-10），计数器本身可溢出（不设断言）。
- **端口**：显式 51820 全正例基线；缺省补齐 51820（`chain_planner.go:1092-1096`）今日无例 → A′ 补（W02）；非默认端口合法（UDP 无约束，tshark 启发式解码风险注记 §0.2）。
- **地址族**：v4/v6 独立用例（W05）；异族混写在 ip 层被拒（`must be same IP version` 通用门，非 wireguard 锚词）。
- **内层**：同族强制、proto ∈ {0→17, 1, 6, 17}、DataFrames ≥0、内层总长 ≤1440（V-14 六分支）。
- **载荷优先级**：FileSource > InnerIP > TransportPayloads > 1B dummy（§5.2）——互斥不叠加，InnerIP 的 `data_frames` 只作用于内层。
- 不得产生回绕长度或超量分配（消息长度由 `make([]byte, total)` 一次算定，`:490/537/578/609`）。

## 9. 原子 ID 与完成定义

### 9.1 存量 ID（现状权威，1 个）

| # | ID | 类型 | 现状 | packet_count |
|---|---|---|---|---:|
| 1 | `wireguard_smoke_01` | 正 | **扁平形判死，今日不可跑**（G-WIREGUARD-2）；断言内容与实现一致（§0 #7），**改写**为层链形后 = W01 | 3（实测） |

### 9.2 目标 ID 全表（54 例 = 36 正 + 16 负 + 2 形状负例不可建；**均未落 JSON**——§1 JSON 纪律：目标行不入当前 ID 集合）

| # | ID | 类型 | 覆盖（设计 §） | 今日可达性 | 包数 |
|---:|---|---|---|---|---:|
| W01 | `wg_smoke_default` | 正 | §5.1 默认流（**存量改写目标形**） | **层链形今日可跑** | 3 |
| W02 | `wg_port_default` | 正 | §2 端口缺省补齐 51820 | 层链形可跑 | 3 |
| W03 | `wg_port_custom` | 正 | §8 非默认端口 | 层链形可跑 | 3 |
| W04 | `wg_src_port_custom` | 正 | §2 源端口显式 | 层链形可跑 | 3 |
| W05 | `wg_ipv6_carrier` | 正 | §2 IPv6（offset 62；帧 210/154/95） | 层链形可跑 | 3 |
| W06 | `wg_init_struct` | 正 | §3.2 Initiation 148B + 偏移 | 层链形可跑 | 3 |
| W07 | `wg_init_sender_auto` | 正 | §3.2 sender=0x00000001 | **待 A′**（层内不可达） | 3 |
| W08 | `wg_init_sender_42` | 正 | §3.2 sender=0x0000002a | 待 A′ | 3 |
| W09 | `wg_resp_struct` | 正 | §3.3 Response 92B | 层链形可跑（默认流内断言） | 3 |
| W10 | `wg_mac2_zero` | 正 | §3.2 mac2 全零 | 层链形可跑 | 3 |
| W11 | `wg_mac2_cookie` | 正 | §3.2 cookie→mac2 非零 | 待 A′ | 3 |
| W12 | `wg_role_responder` | 正 | §5.3 responder 序（无 Init，receiver=+2） | 待 A′ | 2 |
| W13 | `wg_cookie_reply` | 正 | §3.4 Cookie 64B 帧序 | 待 A′ | 3 |
| W14 | `wg_dir_up` | 正 | §5.3 全 up | 待 A′ | 3 |
| W15 | `wg_dir_down` | 正 | §5.3 载荷全 down | 待 A′ | 3 |
| W16 | `wg_dir_both` | 正 | §5.3 交替 | 待 A′ | 4 |
| W17 | `wg_data_struct` | 正 | §3.5 Transport 结构 + counter@50 | 层链形可跑 | 3 |
| W18 | `wg_data_multi` | 正 | §3.5 多载荷 counter 0/1/2 | 待 A′ | 5 |
| W19 | `wg_counter_start100` | 正 | §3.5 InitialCounter=100 | 待 A′ | 3 |
| W20 | `wg_keepalive` | 正 | §3.5/§5.3 keepalive 32B（帧 74） | 待 A′ | 4 |
| W21 | `wg_keepalive_seq` | 正 | §5.1 keepalive 帧位/方向 | 待 A′ | 4 |
| W22 | `wg_rekey` | 正 | §5.1 rekey 插对（8 包） | 待 A′ | 8 |
| W23 | `wg_rekey_reset` | 正 | §5.1 counter 归零 + receiver 旧值注记 | 待 A′ | 8 |
| W24 | `wg_payload_verbatim` | 正 | §0.1 明文直写边界 | 待 A′ | 3 |
| W25 | `wg_tag16` | 正 | §3.5 tag 16B 确定性 | 层链形可跑 | 3 |
| W26 | `wg_inner_udp4` | 正 | §3.6 内层 IPv4/UDP（校验和 0 合法） | 待 A′ | 3 |
| W27 | `wg_inner_tcp4` | 正 | §3.6 内层 TCP 校验和 | 待 A′ | 3 |
| W28 | `wg_inner_icmp4` | 正 | §3.6 内层 ICMP echo | 待 A′ | 3 |
| W29 | `wg_inner_udp6` | 正 | §3.6 内层 IPv6/UDP 必算校验和 | 待 A′ | 3 |
| W30 | `wg_inner_frames2` | 正 | §3.6 data_frames=2（IPID 1/2） | 待 A′ | 4 |
| W31 | `wg_inner_df` | 正 | §3.6 内层 DF=0x4000 | 待 A′ | 3 |
| W32 | `wg_deterministic` | 正 | §0.1 同配置字节复现 | 层链形可跑（双跑比对） | 3 |
| W33 | `wg_filesource` | 正 | §5.2 FileSource 优先 | C 类（需 PayloadCache 环境） | 3 |
| W34 | `wg_dyn_udp_port` | 正 | §12 动态端口 inc flows=3 | **今日可建**（allowlist 已开） | 9 |
| W35 | `wg_dyn_ip_addr` | 正 | §12 动态地址（需合法 IP 端点形状） | 今日可建 | 9 |
| W36 | `wg_flows3` | 正 | §12 多流保底递增 | 今日可建 | 9 |
| N01 | `wg_neg_role` | 负 | §7 V-3 | 待 A′（锚词层链不可达） | —（0 帧） |
| N02 | `wg_neg_direction` | 负 | §7 V-4 | 待 A′ | — |
| N03 | `wg_neg_key_local` | 负 | §7 V-5 | 待 A′ | — |
| N04 | `wg_neg_key_peer` | 负 | §7 V-6 | 待 A′ | — |
| N05 | `wg_neg_key_eph` | 负 | §7 V-7 | 待 A′ | — |
| N06 | `wg_neg_psk` | 负 | §7 V-8 | 待 A′ | — |
| N07 | `wg_neg_cookie` | 负 | §7 V-9 | 待 A′ | — |
| N08 | `wg_neg_rekey` | 负 | §7 V-10 | 待 A′ | — |
| N09 | `wg_neg_keepalive` | 负 | §7 V-11 | 待 A′ | — |
| N10 | `wg_neg_payload_mtu` | 负 | §7 V-12 | 待 A′ | — |
| N11 | `wg_neg_inner_src` | 负 | §7 V-14 内层 src | 待 A′ | — |
| N12 | `wg_neg_inner_mixed` | 负 | §7 V-14 混族 | 待 A′ | — |
| N13 | `wg_neg_inner_proto` | 负 | §7 V-14 proto=99 | 待 A′ | — |
| N14 | `wg_neg_inner_frames` | 负 | §7 V-14 data_frames<0 | 待 A′ | — |
| N15 | `wg_neg_inner_mtu` | 负 | §7 V-14 内层超 MTU | 待 A′ | — |
| N16 | `wg_neg_invalid_dst` | 负 | §7 V-2 的 ip 层锚词变体（`invalid IP endpoint`） | **今日可建**（ip 层锚） | — |
| X01 | `wg_neg_presence` | 形状负 | `{"layers":…,"wireguard":{}}` 并存判死 | **今日不可建**（不判死→建了真绿=假通过，G-WIREGUARD-4） | — |
| X02 | `wg_neg_stray_topkey` | 形状负 | 游离顶层键通用门 | **今日不可建**（同上） | — |

**逐例可达性重数（54 = 15 + 36 + 1 + 2）**：**今日合规可达 15 例**（W01–W06、W09、W10、W17、W25、W32、W34–W36、N16——纯层链形；W09/W10/W17/W25 为默认流内断言不依赖业务键）；**待 A′（层内化）36 例**（W07/W08/W11–W16/W18–W24/W26–W31 共 21 例 + N01–N15 共 15 例）；**C 类 1 例**（W33 FileSource 需 PayloadCache 环境）；**今日不可建 2 例**（X01/X02，G-WIREGUARD-4）。**W34–W36 包数**：flows=3 → 默认流 3 包/流 × 3 流 = 9（`packet_count` 聚合语义按框架口径，实现后钉）。

### 9.3 完成定义

文档阶段完成 = §8.2 八条（需求文档 v1.3）：本文 + testcase + 存量 JSON 三方对 ID/场景/包数/偏移/断言一致（JSON 未落地部分以 testcase §2 为权威并已标待实现）；两主线审查无 confirmed finding；负路径锚词与 §7 表一一对应；pcap/NIC 双输出契约已声明（§1）。**代码阶段（P4）完成**另需：A′ 层内化落地（G-WIREGUARD-2/3）后目标 ID 逐例跑绿、存量例形状迁移（G-WIREGUARD-2）、W02 补缺省例。

## 10. P1 规范矩阵（CORE_MEMORY §4 八项：规范要求→业务场景→代码现状→缺口）

### 10.1 八项规范矩阵

| # | 八项 | 规范要求 | 业务场景 | 代码现状 | 缺口 |
|---|---|---|---|---|---|
| 1 | 连接模型 | UDP 无连接；客户端主动发起握手（protocol 页 First Message） | 场景①–⑧ | `DependsOn ["udp"]`（`registry.go:499`）；Init(up)→Resp(down) 固定 | responder 无 Initiation（§5.5①，G-WIREGUARD-8） |
| 2 | 命令/消息表 | type 1/2/3/4 四类 + `AEAD_LEN(x)=x+16` 字段尺寸 | ①④⑤ | 四类 builder 齐备（§3），尺寸逐条闭合（§0.2） | 无 |
| 3 | 状态机 | 会话索引对（sender/receiver index）+ 计数器反重放 | ①③ | 索引/计数器语义落码（§3.2–3.5）；rekey 换代 | rekey 后 receiver 旧值（§5.5②，G-WIREGUARD-8） |
| 4 | 字段表 | 逐字段偏移/尺寸/端序（§3） | 数据场景层 | 逐字段落码，端序统一 LE | 无 |
| 5 | 错误处理 | 无规范错误码（对端静默丢弃非法包）；本层以 validator 配置校验代之 | ⑧ | 14 分支 + 内层 6 分支（§7） | 层链不可达（G-WIREGUARD-2） |
| 6 | 超时与活性 | REJECT_AFTER 等时间阈值；keepalive 周期 | ② | `keepalive_interval>0` 单包模拟；`rekey_after_time` 显式忽略（`:283`） | 时间维度全部未模拟（§1 边界②④，G-WIREGUARD-7） |
| 7 | NAT/代理/被动 | 无被动模式概念（隧道两端点直连）；Cookie 是 DoS 缓解非 NAT | ④ | CookieReply 开关化（`:403`） | under-load 真实判定不适用（§1 边界⑤） |
| 8 | 版本/方言 | 协议**无版本字段**（reserved_zero 恒零即版本锁定）；IPv4/IPv6 双栈承载 | ⑥ | reserved 恒零 ✓（`wg.reserved=000000` 实测）；双栈已覆 | 无（协议本身无版本协商面） |

### 10.2 子表①：消息 × 终态矩阵（4 消息 × 3 终态，逐格）

| 消息 | T1 正常产出 | T2 配置拒绝 | T3 角色不可达 |
|---|---|---|---|
| Initiation（type1） | 已覆（W06/W07/W08；rekey 中插 W22） | 已覆（代表例 N01——拒绝与消息无关） | responder 角色无此消息（§5.5①，W12 断言其缺席） |
| Response（type2） | 已覆（W09/W12） | 同上代表已覆 | initiator 关不掉（`:370-381` 无判，G-WIREGUARD-6） |
| CookieReply（type3） | 已覆（W13） | 同上代表已覆 | initiator 恒不发（`:403` 角色门） |
| TransportData（type4） | 已覆（W17–W25） | 已覆（N10 专属：MTU） | handshake=false 时仍发（nohandshake 实测） |

逐格重数：4×3=12——已覆 **11**（T1 列 4 + T2 列 4 + T3 格 3：Initiation responder 缺席由 W12 缺席断言覆盖、CookieReply initiator 恒不发由 W12/W13 角色门覆盖、TransportData handshake=false 仍发由 nohandshake 实测覆盖）/ 立项 **1**（T3 Response 格：initiator 关不掉，G-WIREGUARD-6）。11+1=12 ✓

### 10.3 子表②：数据形态变体表（26 行）

| # | 变体 | 落点 |
|---:|---|---|
| 1 | 空配置默认流 | 覆（W01） |
| 2 | 载荷 N=0（keepalive） | 覆（W20，待 A′） |
| 3 | 载荷 N=1（默认 dummy） | 覆（W01，实测 33B） |
| 4 | 载荷 N=5 | 覆（W18，待 A′） |
| 5 | 载荷 N=1440（上界） | 覆（§0.2 payload1440 实测；目标例 W 组待 A′） |
| 6 | 载荷 N=1441（越界） | 覆（N10，待 A′） |
| 7 | sender_index 自增（→1） | 覆（W07，待 A′） |
| 8 | sender_index 显式 42 | 覆（W08，待 A′） |
| 9 | sender_index 2^32-1 | 不设（uint32 天然封顶，§8；无拒绝路径） |
| 10 | initial_counter=0 | 覆（W17） |
| 11 | initial_counter=100 | 覆（W19，待 A′） |
| 12 | mac2 无 cookie 全零 | 覆（W10） |
| 13 | mac2 有 cookie 非零 | 覆（W11，待 A′） |
| 14 | cookie 15B/17B 拒 | 覆（N07，待 A′） |
| 15 | PSK 32B 合法 | 覆（W 组待 A′；**零消费**注记 G-WIREGUARD-7） |
| 16 | 密钥 31/33B 拒 | 覆（N03–N06，待 A′） |
| 17 | ephemeral 显式 32B 消费 | 覆（§0.2 eph 实测；目标例待 A′） |
| 18 | direction 三态 | 覆（W14–W16，待 A′） |
| 19 | role 二态 + 非法 | 覆（W12 待 A′；N01 待 A′） |
| 20 | rekey 阈值触发/归零 | 覆（W22/W23，待 A′） |
| 21 | rekey_after ≥2^60 拒 | 覆（N08，待 A′） |
| 22 | keepalive_interval>0/负值 | 覆（W20 待 A′；N09 待 A′） |
| 23 | 内层 proto 1/6/17 + 非法 | 覆（W26–W29/N13，待 A′） |
| 24 | 内层 data_frames 1/2/负 | 覆（W26/W30/N14，待 A′） |
| 25 | IPv6 外层 | 覆（W05） |
| 26 | IPv6 内层（UDP 必算校验和） | 覆（W29，待 A′） |

覆 25 + 不设 1 = 26 ✓（"待 A′"是**落例**欠账不是行分类——每行变体均已有正/负例落点或"不设"结论；P4 层内化前行 2/4/5/6/7/8/11/13–24/26 的落例不可执行，逐例标注见 §9.2）。

### 10.4 子表③：商业行为→用例映射表

| # | 商业行为（出处：protocol 页 + 现网通用部署） | 用例映射 | 结论 |
|---|---|---|---|
| 1 | 站点到站点隧道建立 | W01/W06–W09 | 已覆 |
| 2 | 数据面吞吐（隧道载荷） | W18/W24 | 已覆（待 A′ 落例） |
| 3 | 漫游客户端保活 | W20/W21 | 已覆（待 A′） |
| 4 | 密钥轮换（rekey） | W22/W23 | 已覆（待 A′） |
| 5 | DoS 防护 Cookie | W13 | 已覆（待 A′；开关化注记） |
| 6 | 双栈部署 | W05/W29 | 已覆 |
| 7 | 内层多协议业务 | W26–W28 | 已覆（待 A′） |
| 8 | 多客户端并发 | W34–W36 | 已覆（今日可建） |
| 9 | 配置错误防呆 | N01–N16 | 已覆（待 A′ 为主） |
| 10 | 真实握手互操作（与真实 wg 对端） | — | **明确不解决**（G-WIREGUARD-10：密码学不在生成器范围） |
| 11 | 会话超时/漫游重握手时间维度 | — | **明确不解决**（G-WIREGUARD-7：时间阈值未模拟） |

10 覆 + 2 不解决 = 12 ✓ 无映射无确认即缺口——本表零缺口。

### 10.5 三路对照与候选方案对比（§4.12–4.15/§4.17）

三路：①规范原文（protocol 页 + RFC 8439/7748/7693 长度语义，定"必须是什么"——本轮实测闭合 §0.2）；②商业化软件实际行为（**未取到**：真实 wg 抓包/内核实现线字节未核对 → G-WIREGUARD-10 待确认）；③可靠开源实现思路（wireguard-go 的 `messageInitiationType` 常量与定长 struct——只借鉴"四类消息定长"思路）。三路一致点：四类消息/类型值/字段序；不一致点：**本实现密码学面为伪随机**（开源实现是真加密）——以"生成器范围"取舍，理由=流量发生器目标是线格式与行为面，不是互操作测试。

| 方案 | 走法 | 取舍 | 结论 |
|---|---|---|---|
| A | 独立 wireguard 终结层（本版；tftp 同构 replay 模式） | 消息序/角色/序号可声明可断言；代价=层内化欠账（已登记 G-WIREGUARD-2/3） | **采用（as-built 逆向定稿）** |
| B | 直接 udp 层 + 顶层 payload | 无消息类型/序号/角色剧本 → 12 例中 9 例不可表达 | **否决** |
| C | 拆"wg-握手层 + wg-数据层"两层 | 索引/counter 跨层状态传递需层间通道，框架无此机制 | **否决**（状态在 Plan 局部变量，单层内聚） |

## 11. P2 D-WIREGUARD-1 代码设计（CORE_MEMORY §8 八要素；as-built 逆向定稿）

> 状态说明：实现已落码，本条目为文档轨对既有实现的**逆向定稿**，供门1 批准后作为后续改动唯一入口；P4 在本协议内为"层内化 + 缺口收敛"（§14），不另开新层。

### 11.1 文件清单（实测）

| 文件 | 职责 | 行数 |
|---|---|---:|
| `trafficgen/internal/core/types.go`（`:8481-8582`） | `WireGuardConfig`（16 键）+ `WireGuardInnerIP`（8 键）+ `FlowSpec.WireGuard` 槽位（`:1875`） | —（共享文件） |
| `trafficgen/internal/protocol/wireguard/planner.go` | 常量 + Validate（14 分支）+ Plan（剧本）+ build* 四函数 + fillDeterministic + resolveDirection + 内层 IP 族（validate/build/checksum 8 函数） | 973 |
| `trafficgen/internal/protocol/wireguard/layer_gen.go` | `WireGuardGenerator`（replay 模式：复用 `Planner.Plan` 逐 PacketConfig → MessageEvent；`L4PortOverride=true` 因 emit 已按方向换端口，`:21-23` 注释）+ init 注册 generator/validator | 104 |
| 测试 3 文件 | planner_test 959（30 Test）/ testpoints 3214（199 Test）/ innerip 566（24 Test） | 4739 |
| 接线 6 处 | registry（`layers/registry.go:498`）/ protocols 准入（`protocols.go:60`）/ convert 子映射（`strategy_convert.go:1551`）/ FlowMeta 直传（`chain_planner_translate.go:229`）/ 缺省端口 + 源口 0 放行（`chain_planner.go:1092/:924`）/ server 注册（`cmd/server/main.go:204/:610`） | — |

**无 builder.go**——build* 纯函数全部在 planner.go（任务书提法校正，实测）。

### 11.2 接口签名

- `Validate(spec core.FlowSpec) error`（`planner.go:96`）：只读不填默认（`:93-95` 契约注释）；nil WireGuard 直接通过（`:103-105`，P0b-2 空配置默认流）。
- `Plan(ctx, spec) (<-chan core.PacketConfig, error)`（`:186`）：`Validate` 先行；goroutine 内按 §5.1 剧本 emit；`ctx.Done` 中断返回。
- 生成器：`Name() "wireguard"`；`GenEvents()` 返回自身；`EmitEvent` 未接线显式错（`layer_gen.go:93-95` 防误调）；`Generate` 逐 PacketConfig 转 `MessageEvent{Up, Bytes, SrcPort, DstPort, Metadata, L4PortOverride:true}`（`:58-65`）。

### 11.3 数据结构

`WireGuardConfig{Role, LocalStaticPubKey, PeerStaticPubKey, LocalEphemeralPubKey, SenderIndex, PSK, Cookie, InitialCounter, RekeyAfter, RekeyAfterTime, KeepaliveInterval, CookieReplyThreshold, TransportPayloads, FileSource, Direction, Handshake, Response, InnerIP}`（`types.go:8484-8549`——**17 键**：Handshake/Response 为 `*bool` 三态）；`WireGuardInnerIP{SrcIP, DstIP, Proto, SrcPort, DstPort, TTL, Payload, DataFrames}`（`:8557-8582`）。

### 11.4 主流程

层链配置 → `ValidateLayers`（V9：**wireguard 层仅容空 config**）→ translate（**无 wireguard case，只 FlowMeta 直传** `spec.WireGuard`）→ ChainPlanner `validateSpecBase`（端口 51820 缺省、src 口 0 放行）→ 生成器 `Generate` → `Planner.Plan` 剧本 → udp 层逐事件一数据报 → writer（PCAP/NIC）。**flat 路径**：顶层 `wireguard` 子映射 → `parseWireGuardConfig`（`:6091`）→ `spec.WireGuard` → 同链（Task 无 Layers 时 `BuildLayersPlanner` 合成链，spec 经 Meta 到达同一生成器）。

### 11.5 错误分支

14 种 planner 拒绝（§7 表）+ 内层 6 分支，全部 task error（Validate 返回值 → Plan 同步失败 → 链路 ValidationErrors → 任务 error；零假成功——单测 `TestWireGuard_Validate_*` 9 例在案）。死分支 1 处（`:139-144` 空实现，§7.1①）。

### 11.6 性能边界

见 §6（channel 流式、per-flow 状态、无锁；帧长域 [74,1514]；吞吐待 P4 基准）。

### 11.7 与现有逻辑的冲突点

- `CheckProtoFlat` **无 wireguard presence 分支**（`grep -c 'protocol == "wireguard"'` 于 `CheckProtoFlat` 函数体 = 0 实测）：顶层 `wireguard` 子映射 presence 不判死——五键判死通用循环虽打中存量例的 `src_ip`，但**业务子映射本身**处于"既违规（1.11）又无门（可跑）"状态 → G-WIREGUARD-1/G-WIREGUARD-4（禁加单协议黑名单分支，等框架级 unknown-key 白名单；kingbase 记忆裁定）。
- **层内化欠账双缺**：registry Fields 空 + translate 无 case（§0 #2/#4）→ 层链形状下业务配置零可达 → G-WIREGUARD-2（P4 必做：登记 Fields 17+8 键 + translate case，`ParseWireGuardConfigFromMap` 导出复用 tftp/imap 单一真相先例）。
- 动态 allowlist：`wireguard` **零命中**（`internal/core/layer_dyn.go` grep 实测）→ 业务字段动态对象即拒；四元组 `ip`/`udp`/`tcp` 全开（探针实测 `udp.dst_port`/`ip.ttl` 动态形状过检）。见 §12.12。
- `parseWireGuardConfig` **缺 `handshake`/`response` 键解析**（`types.go:8533/8537` 声明、`:6091-6117` 不读）→ JSON 无法关闭握手/响应（静默忽略，G-WIREGUARD-6）。
- 离线层链套件 `chainSuiteProtos` 无 wireguard → 层链用例无离线回归通道（G-WIREGUARD-7 附注）。

### 11.8 回滚方式

本协议文件独立成包，回滚 = revert `internal/protocol/wireguard/` 两文件 + 接线 6 处；不触及其他协议。cases 回滚 = 恢复 1 例 JSON（产物文件，非文档）。

## 12. 门1 §1–§14 十四行对照表（CORE_MEMORY §15.1–15.3）

| § | 本协议怎么满足 | 证据 |
|---|---|---|
| §1 层链唯一真相 | 见 §12.1 强制展开：存量 1 例顶层四键**全部违规**；目标形状见 §2 样例（合规层链形今日仅容空 wireguard config） | §12.1；`cases/wireguard.json` 机读 + 探针实测 |
| §2 策略/任务 | 策略 = 单 wireguard 流量模板；任务 = 多策略合跑 + 总量封顶；框架语义未动 | 设计 §2 样例 |
| §3 五件套 | 见 §12.3 强制展开：会话表/事务序列/关联（无派生流声明）/插入位置（终结层）/时间线；UDP 无长连接，`sessions[]` 豁免有据 | §12.3 + §5 |
| §4 查规范 | protocol 页（wireguard.com，2026-09-29 拉取）+ RFC 8439/7748/7693 长度语义 + tshark 3.6.14 字段表 + **15 组离线 pcap 实测** + 落码反推；八项矩阵 + 子表①②③；**条款级章节号未核对** → G-WIREGUARD-10 | §10；§0.2 |
| §5 依赖与错误 | `DependsOn ["udp"]` 单值（`registry.go:499`）；14+6 拒绝分支；失败传 task error（单测 9 例在案）；层链可达性缺口如实登记（G-WIREGUARD-2） | §7/§11.5 |
| §6 性能 | 见 §6（6.1–6.8 要素齐；帧长域 [74,1514] 实测闭合；吞吐标待 P4 基准，不写承诺；pcap/NIC 两路验收明写） | §6 |
| §7 三份文档 | `129-wireguard-{design,testcase}.md` v1.0.0 + D-WIREGUARD-1（§11）+ T-WIREGUARD（testcase §2.2，54 ID）+ 存量 JSON 1 例为历史层 | 修订记录 |
| §8 设计先行 | P1–P3 先于 P4 层内化；门1 获批 = D-WIREGUARD-1 定稿 = 开工门 | 提交序 |
| §9 测试三源 | 三源 = protocol 页 + RFC 长度语义（§10）+ D-WIREGUARD-1（§11）+ tshark 字段与 **15 组实测 pcap**（已到抓包级）；54 ID 逐项回指；存量 1 例审计去向 testcase §8 | `129-wireguard-testcase.md` §2/§5/§8 |
| §10 评审闭环 | 每阶段对抗自重审（机读复核见 §15 自审行）+ 收官隔离复审；红先绿后 | 自审日志 |
| §11 白话 | 每阶段白话一句先行（见本文首节 + §5 各节） | 汇报 |
| §12 动态清单 | 见 §12.12 强制展开：四元组开/业务关逐个列 + 理由；序号算法代码位置 | §12.12 |
| §13 schema 派生 | wireguard 已在注册表（`registry.go:498`）且生成表同代（`"fields": {}` 与 registry 逐键一致，机读实测）；**P4 若登记 Fields 必须重跑 schemagen**（13.18） | §11.1 |
| §14 真实流程 | suite 经 MCP 建策略建任务 → 引擎真实生成 → tshark `wg.*` + frames 双通道 → 先跑后钉；pcap 落 `/tmp/mcp-pcaps/wireguard/`（今日空目录，套件未跑——G-WIREGUARD-9） | testcase §7 |

### 12.1 §1 强制展开：旧键去向 + 完整 spec_json 样例

**存量实测（机读）**：

| 文件 | 例数 | 顶层键分布 | 链形 | expect 形状 |
|---|---|---|---|---|
| `cases/wireguard.json` | 1 | `src_ip, dst_ip, count, wireguard` ×1（**无 `layers`，扁平形**） | 无链 | `{packet_count, fields, notes}`（正例三键，无负例） |

**旧键去向表（§15.3 要求逐键）**：

| 旧键 | 存量出现例数 | 去向 |
|---|---:|---|
| `src_ip` | 1 | **判死键**（CheckProtoFlat 五键之一，探针实测命中）→ 迁 `layers[i].ip.src`（W01 目标形） |
| `dst_ip` | 1 | 同上 → 迁 `layers[i].ip.dst` |
| `count` | 1 | **判死键** → 迁策略级 `flow_control`（flows=1 可省略） |
| `src_port` / `dst_port` | 0 | 本协议存量未用（端口全靠缺省）；目标形按需住 `layers[i].udp` |
| 顶层 `wireguard` 子映射 | 1 | **presence 无门不判死**（G-WIREGUARD-4）：目标形迁 `layers[i].wireguard`——**今日迁不进去**（Fields 空 → unknown field，G-WIREGUARD-2）；过渡期该键继续承担业务配置（违规但可跑，如实声明） |

**结论**：本协议存量**零合规**——§1 门动作 = ①存量例改写（P4：删三判死键 + 业务键层内化后迁层）；②收官自查行「非负例顶层键 = 0」**今日不成立**（1/1 例含顶层业务子映射）；③A′ 新增例全部沿用纯 layers 形。

目标形状样例见 §2（顶层仅 `layers`）。

### 12-P2 判死负例形状（链级红例必含清单①③④）

- ① presence 形状 `{"layers":[…],"wireguard":{}}` 今日**不会被拒**（探针实测通过）→ **P4 不建该负例**（建了会真绿 = 假通过）→ G-WIREGUARD-4。② 白名单外游离键判死（`unknown field`）今日**亦无通用门** → 同 G-WIREGUARD-4，不建（X02）。③ 校验负例锚词已齐 16 条（§7；层链可达性缺口 G-WIREGUARD-2 如实标"待 A′"）。④ 收官自查「非负例顶层键 = 0」今日**不成立**（§12.1）——P4 层内化 + 存量改写后重查。

### 12.3 §3 强制展开：五件套

会话表：`s1` 单隧道基线（UDP 无连接，四元组即身份；全部目标例）。WireGuard 应用层"会话"= sender_index/receiver_index 索引对——**本实现单流恒一组索引**（senderIndex/responderIndex/initiatorIndex 三值由 §3.2–3.4 算式派生），rekey 换代（W22）是唯一多索引形态；`sessions[]` 数组**豁免**（UDP 无连接、无多会话编排语义，3.14 豁免 + §4 层结论）。事务：`t1` 握手对（Init→Resp，tcp 层无涉，UDP 数据报直发）/ `t2` 数据包（Transport Data ×N，计数器递增）/ `t3` keepalive（可选收尾）；每事务四件事——t1{前置:配置就绪/触发:首事件/成功:Resp 收到 receiver=senderIndex/失败:Validate 拒（V-3/V-4）}、t2{前置:握手序完成或 handshake=false/触发:载荷项/成功:counter+1/失败:V-12 MTU 拒}、t3{前置:N 载荷发完/触发:keepalive_interval>0/成功:32B 包/失败:无（布尔开关）}。关联关系：**无派生流**（单五元组承载，无 driven_by；内层 IP 包是载荷不是流）。插入位置：终结层（`[ip,udp,wireguard]`）。时间线：消息内严格顺序 / 载荷按数组序 / 多流并发由策略级 flows 承载（流间无序，worker 并发）；无交错调度（`concurrent` 不适用）。

### 12.12 §12 强制展开：动态字段清单与序号算法

四元组 `ip.src/dst/ttl`、`udp.src_port/dst_port` 五策略全开（allowlist `layer_dyn.go` 头部实测：`ip`/`tcp`/`udp`/`eth` 行存在；探针实测 `udp.dst_port`/`ip.ttl` 动态对象过检）；保底自增 `DefaultSrcPort+i`（`strategy_convert.go:49` + worker 注入）；dst 动态与 51820 缺省和平共处（显式/动态值非零即不触发补齐）。

**业务字段 17+8 项全关**（allowlist 无 `wireguard` 行，grep 零命中实测；对象即 `does not support dynamic`——探针实测 `transport_payloads`）：`role`/`direction`（结构选择器，逐流变破坏角色剧本语义）/ 密钥四把（隧道身份，逐流变无意义）/ `sender_index`/`initial_counter`（会话身份，逐流变破坏索引配对）/ `psk`/`cookie`（加密材料，模板字节逐流变无意义）/ `keepalive_interval`/`cookie_reply_threshold`/`rekey_after`/`rekey_after_time`（行为开关，标量语义）/ `transport_payloads`（列表无动态形状）/ `file_source`（文件源逐流变需框架面）/ `handshake`/`response`（布尔开关，且 JSON 不可达 G-WIREGUARD-6）/ `inner_ip` 全 8 键（嵌套对象，无动态形状）——逐流变体需求列 A′ 候选（testcase §6.2；今日按 §9.36 口径不冒充覆盖）。

序号算法实读：`parseLayerDyn`（`layer_dyn.go:78`）/ 保底自增（`strategy_convert.go:49` + worker 注入）/ allowlist 白名单（`layer_dyn.go` 头部）——**`wireguard` 无块**。**协议自身序号算法**（非动态体系）：sender_index 派生 `planner.go:269-273`、counter 递增/归零 `:466/:450`、内层 IPID=i+1 `:780`、外层 ipID++ `:348`。

## 13. P3 对接清单（T-WIREGUARD 草稿输入；正文落 testcase 文件）

54 ID（36 正 + 16 负 + 2 形状负例不可建）+ packet_count 公式（§5.1 三式）+ 锚词 16 条 + fixture 常量（42/62 offset、帧长公式）+ 15 组实测基线（§0.2）+ 存量审计（testcase §8 全量）+ 今日可达性逐例标注（§9.2 列）。A′ 候选汇总：层内化（G-WIREGUARD-2/3，解锁 40 例）→ 存量改写（W01）→ 缺省端口例（W02）→ `handshake/response` 键解析（G-WIREGUARD-6，解锁 W-之 handshake=false 面）→ 错例行为裁定（G-WIREGUARD-8）。

## 14. 缺口立项清单（有缺口写「缺口立项」，不许空着）

| 缺口 | 内容 | 去向 |
|---|---|---|
| G-WIREGUARD-1 | **顶层 `wireguard` 子映射 = 业务配置唯一 JSON 可达路径**（层内 Fields 空 + translate 无 case），违反 1.11 顶层白名单；`CheckProtoFlat` 无 presence 分支，违规形状今日可跑 | P4 层内化（G-WIREGUARD-2 落地）后由框架级 unknown-key 白名单收口；**禁加单协议黑名单分支**（kingbase 记忆裁定）；过渡期混合形如实标注"违规但可跑"，不登记豁免 |
| G-WIREGUARD-2 | **层内化双缺（P4 必做）**：①registry Fields 空（`registry.go:498-501`）→ 层内任何键 `unknown field` 拒（探针实测）；②`translateTerminalConfig` 无 `case "wireguard"` → 层 config 不进 `spec.WireGuard`（全仓赋值点实测 2 处皆 flat 侧） | P4：Fields 登记 17 键 + `ParseWireGuardConfigFromMap` 导出（tftp/imap 单一真相先例）+ translate case（JSON 往返陷阱：`transport_payloads`/`psk`/`cookie`/`local_*_pub_key` 是 `[]byte`——**数字数组语义**，getByteSlice 双面承接，srv6 inner_payload 同陷阱注记）→ 解锁 §9.2 待 A′ 40 例 → 存量例改写迁移 |
| G-WIREGUARD-3 | **存量 1 例扁平形今日判死**：`wireguard_smoke_01` 顶层 `src_ip/dst_ip/count` 命中 CheckProtoFlat（**逐字 spec 探针实测**返回 `no longer accepts flat config field src_ip`）→ strategy create 400，MCP 套件该例必 error；断言内容与实现一致（§0 #7）不是可跑证明 | P4：改写为层链形（§12.1 去向表）；改写前该例**不得计入任何"今日已绿"口径**；离线套件同不可拾取（`chainSuiteProtos` 无 wireguard） |
| G-WIREGUARD-4 | presence/游离键通用门缺失：`{"layers":[…],"wireguard":{}}` 通过（探针实测）→ X01/X02 **不可建**（建了真绿=假通过）；「非负例顶层键=0」自查今日不成立（1/1 例含顶层子映射） | 等框架级 unknown-key 白名单（G-WIREGUARD-1 同门）；P4 不单独立项 |
| G-WIREGUARD-5 | **动态业务字段全关**：allowlist 无 `wireguard` 行（grep 零命中），17+8 键对象即拒（探针实测）；四元组已开 | A′ 候选（逐流变业务字段需求确认后开）；今日不得声称覆盖（§9.36 口径） |
| G-WIREGUARD-6 | **`handshake`/`response` 键 JSON 不可达**：`*bool` 声明于 `types.go:8533/8537`，`parseWireGuardConfig`（`:6091-6117`）不解析 → 静默忽略（`{"handshake":false}` 无效果）；且 `Response=false` 仅 responder 分支生效（initiator Response 关不掉，`:370-381` 无判） | P4：①parse 补 `getBoolPtr` 两键；②`Response` 语义裁定（initiator 是否尊重）→ 补例 W 组 handshake=false 面 |
| G-WIREGUARD-7 | **配置静默不消费 3 项**：`PSK`/`LocalStaticPubKey`/`PeerStaticPubKey` 仅长度校验零参与字节构造（**字节级实测全同** default 组）；`RekeyAfterTime` 显式忽略（`:283`）；keepalive 单包非周期（§5.5④）；离线套件未纳 wireguard（`chainSuiteProtos` 缺） | P4 裁定：①三键要么消费（入 mac/密钥派生模板）要么登记"明确不解决"并从文档字段表降级；②`RekeyAfterTime` 时间维度明确不解决；③离线套件扩名单（同 G-WIREGUARD-2 批次） |
| G-WIREGUARD-8 | **as-built 保真度偏差 2 处（confirmed）**：①responder 角色无 Initiation 直接发 Response（真实协议 Response 必答于 Init）；②rekey 后 Transport `receiver_index` 仍指旧 responderIndex（`:457` 用未更新变量；实测第 8 包 receiver=0x00000002 旧值） | P4 裁定：修实现（对齐真实协议）或登记"角色剧本式生成、非对答模拟"边界并收窄 W12/W23 断言口径；**修则先写失败用例**（9.7） |
| G-WIREGUARD-9 | **结果文档过期**：`trafficgen/docs/protocol-pcap-test/wireguard.md`（tracked）写 "Cases: 1 — pass 1, fail 0, error 0"，末次提交 `e7e7d1c`（**2026-08-27**）早于判死提交 `0417be5`（2026-09-13）；`docs/protocol-pcap-test/wireguard/` **0 个 pcap**（目录不存在）——该 1/1 pass **未经今日复跑证实，且按 G-WIREGUARD-3 今日必红**；`/tmp/mcp-pcaps/wireguard/`、`/tmp/mcp-nic-pcaps/wireguard/` 均空目录 | 代码阶段（P5 重跑套件后重生成该产物）；本版不删不改（tracked 产物，删除属 P5 动作）；在此之前读者不得据此判断套件已复跑（口径同 pcep G-PCEP-11/opcua G-OPCUA-10） |
| G-WIREGUARD-10 | **规范条款级核对未完成**：protocol 页无章节号、whitepaper PDF 未逐条核对（代码自引 §3/§4 未验）；真实服务器/开源实现（wireguard-go/wg(8)）线字节未抓包对照；tshark 启发式解码对非 51820 端口的稳定性未做矩阵实测 | 待确认：抓真实 wg 包对照 / 核对 whitepaper 条款号；确认前按实现钉、不声称合规；非默认端口正例（W03）落地时补解码实测 |

## 15. 修订记录

- v1.0.0（2026-09-29）：P-PIPE #129 文档轨 P1–P3 首版。无旧稿；存量 1 例机读审计（**扁平形判死**，G-WIREGUARD-3）；**15 组离线生成 pcap 实测基线**（§0.2，帧长公式 14/14 闭合、零 malformed）；线格式逐字段定稿（§3，四消息尺寸/偏移/LE/伪随机填充面）；加密面诚实边界（§0.1，逐字段"真身 vs 实现"表）；五层覆盖 + 八项矩阵 + 三子表（§4/§10，12 格/26 行/12 行零空格）；as-built 保真度偏差 2 处 confirmed（§5.5，G-WIREGUARD-8）；54 例目标 ID 全表 + 今日可达性逐例标注（§9.2，今日合规可达 15 例）；缺口 G-WIREGUARD-1…G-WIREGUARD-10；门1 十四行 + §12.1/12.3/12.12 强制展开。自审见 testcase §10 与 `/tmp/pipe/doc-lanes/`。
