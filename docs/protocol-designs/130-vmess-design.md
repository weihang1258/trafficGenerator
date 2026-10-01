# #130 vmess（VMess · V2Ray 私有加密代理协议，TCP 443）设计契约

> 版本：v1.0.0（P-PIPE 批次二文档轨 as-built；修订记录见 §15）
> 日期：2026-09-29
> 车道：文档轨（#130 vmess）
> 旧基线：**无独立旧稿**——本协议此前无 `NN-vmess-design.md`（全仓 grep 实测：docs/ 内 vmess 仅出现在 layer-chain 需求文档与 pcap 分析文档中，非契约稿）。本文为**首版契约**，继承来源 = ①存量 cases JSON ②仓库落码 ③公开规范（下条）。
> 存量用例：`trafficgen/test/protocol_pcap/cases/vmess.json`（**1 例** `vmess-basic-session`；**扁平形状顶层 6 键**，判死提交 `0417be5` 后 schema 层 400 拒绝——本车道实测，见 §0 #1 与 G-VMESS-1）
> 规范基线：① **v2fly.org 官方《VMess Protocol》开发者规范**（无 RFC；本文引用其章节名：Version / Client Request / AEAD Authentication Format / MD5 Authentication Format / Instruction Section (Common) / Data Section (Common) / Standard Format / Server Response / Response Header Format，下称 **spec**）；② v2fly.org 官方《Mux.Cool Protocol》（章节名：Transport Format / Frame Format / Metadata，下称 **mux-spec**；MUX 帧状态字语义出处）；③ v2ray-core 实现事实（`proxy/vmess/` 的 AEAD 认证、CmdKey 派生——本文仅在规范引文处标注，不逐条引 core 行号）；④ 本机 tshark 3.6.14（**无 vmess dissector：`tshark -G fields` vmess 命中 0**，本车道实测——故本协议全部 pcap 断言只能走 `tcp.*` 字段 + frames 原始 hex，与旧 pcap 分析文档 "VMess(无 dissector+加密随机字节)" 记载一致）；⑤ 本仓库落码（`internal/protocol/vmess/` 4 文件 3662 行 + 接线，§11）
> 白话一句：**加密代理的"挂号信"——客户端把"我要去哪"（目标地址+端口）装进一个加密信封（请求头）寄给代理服务器，服务器拆信后替客户端去连真正的目的地，再把回信装进另一个信封寄回来。本生成器只造"信封外形"（长度/偏移/方向可断言），信封内容是随机字节（不做真实加密）。**

## 0. 基线声明与存量校正（首版，无旧稿沿革）

本 #130 是 vmess 的**首份契约文档**。存量校正对象不是旧稿，而是**存量单例的 notes 文案与仓库注释**——以下 13 条全部为可判题（代码/实测/规范三级对照），逐条给出证据：

| # | 存量说法/形状 | HEAD 实测（2026-09-29） | 校正结论 |
|---|---|---|---|
| 1 | `cases/vmess.json` 存量 1 例 `spec_json` 顶层 = `{src_ip,dst_ip,src_port,dst_port,count,vmess}`（**扁平形**） | schema 层实测：`ValidateStrategy("synth","vmess",扁平形状)` → **`protocol vmess no longer accepts flat config field src_ip`**（判死提交 `0417be5` 2026-09-13 泛化全协议；`CheckProtoFlat` 五键循环无条件） | **存量 1 例今日不可创建/不可跑**；本版 §2 目标形状为纯层链，迁移动作列 G-VMESS-1（本车道不动 JSON） |
| 2 | 存量 notes："vmess 设计无默认 dst_port，必须显式 443" | registry `vmess` FieldContract `tcp.dst_port:443`（`registry.go:1624`）+ 链路径 DstPort switch 缺省 443（`chain_planner.go:1235`） | **链路径有缺省 443**；notes 是 legacy `strategy_convert` 口径（`strategy_convert.go:1550` 确无默认，注释 "vmess has no canonical port; user must specify"）——两口径并存，本文 §2 按链路径钉 |
| 3 | 存量 notes："f5/f7 为服务器响应段 (18B 随机)" | 发射序（`planner.go:533-573`）：f4=req(up) → **f5=客户端终止空块(up, 18B)** → f6=resp(down) → **f7=服务端终止空块(down, 18B)** | **f5 方向标错**（是客户端侧终止块）；包数/长度本身正确。P4 改写 notes（G-VMESS-1） |
| 4 | 存量 notes："AES-128-GCM 加密的请求头 + 负载（含随机 nonce 与**密钥派生**，字节不可预测）" | 实现零真实密码学：无 `crypto/aes`/`crypto/cipher` import（grep 命中 0），无 MD5/FNV/HMAC 运算（命中 0），`rand.Read` **16 处**——IV/body/payload/tag 全部随机填充（`planner.go:27-30` 包注释自述 "does NOT implement real cryptography"）；且缺省 encryption = `aead_chacha20_poly1305`（`:328-331`），**不是** notes 说的 GCM | **notes 夸大**（"密钥派生"不存在）且算法名标错（缺省 chacha20 非 GCM）；P4 改写（G-VMESS-1）。本文 §3 按实现如实钉："合成密文"（synth ciphertext） |
| 5 | 请求体布局：实现 = `[UUID 16B][Ver|AlterID 1B][Cmd][AddrType][Addr][Port 2B][PadLen][Pad][PayloadLen 2B(AEAD)]` | spec 的 Instruction Section（AEAD 明文/MD5 密文通用）= `[Ver 1][ReqIV 16][ReqKey 16][RespAuth V 1][Opt 1][Margin/Sec 1][Reserved 1][Cmd 1][Port 2][AddrType 1][Addr N][Random P][Checksum FNV1a 4]` | **实现 body ≠ spec 指令段**：实现无 ReqKey/RespAuthV/Opt/Checksum(FNV1a) 字段、UUID 在 body 内（spec 中身份在 EAuID/CRC 不在指令段）；差异逐条列 §3.8 + G-VMESS-2 |
| 6 | 实现响应体 = `[UUID 16B][Ver 1B][Cmd 1B][PadLen 1B][Pad][RespPayloadLen 2B(AEAD)]` | spec Response Header = `[RespAuth V 1][Opt 1][Cmd 1][CmdLen M 1][CmdContent M][data]`（RespAuth V 必须回显请求值） | **实现响应 ≠ spec 响应头**（实现回显 UUID，spec 无此字段）；§3.8 + G-VMESS-2 |
| 7 | 实现认证信息槽 = 请求帧 `[Ver 1B][IV 16B][body][tag 16B]` 的 IV 16B | spec AEAD 认证格式 = `[EAuID 16][ALength 18(=2+16GCM tag)][Nonce 8][AHeader Y][Data]`；EAuID 明文 = `[Timestamp 8B BE][Rand 4B][CRC32 4B]`，用 `KDF(CmdKey,"AES Auth ID Encryption")[:16]` AES-128 加密 | **实现的 "IV 16B" 不是 spec 的 EAuID/ALength/Nonce 三段**——无时间戳、无 KDF、无 AES 运算；§3.8 如实声明"只占 16B 随机槽位" |
| 8 | 实现 MD5 认证（Legacy 模式）`legacy_aes_128_cfb` | spec MD5 格式 = `[AuthInfo 16B = HMAC-MD5(UUID, UTC时间±30s)][指令段 AES-128-CFB 加密][Data]`；指令段加密 key = `MD5(UUID+固定串)`、IV = `MD5(4×时间戳)` | **实现 Legacy 无 HMAC-MD5 运算、无 AES-128-CFB 加密**——只是把首字节换成 0x00、IV 全随机、body 内放 AlterID 字节；`alter_id>255` 拒绝（`planner.go:202-204`）是唯一与"1 字节 alterId 语义"挂钩的真实校验 |
| 9 | 实现 MUX 帧 = `[session_id 2B BE][status 1B][length 2B BE][payload]`（`buildMUXFrame`，`planner.go:852-882`） | mux-spec 帧格式 = `[Metadata Length L 2B][Metadata: ID 2B + Status 1B + Opt 1B (+NEW: Net 1B + Port 2B + AddrType 1B + Addr)][Extra Data: Length 2B + Data]` | **实现 MUX ≠ mux-spec**：缺 Opt/NetworkType 字节、长度前缀语义不同（实现=载荷长度；spec=元数据长度先行）；status 值 0x01/0x02/0x03/0x04 与 mux-spec **一致**；§3.5 + G-VMESS-3 |
| 10 | 实现 `Command=0x03`(MUX) 是 VMess 指令段的命令字节 | spec Instruction Section 的 Cmd 只定义 **0x01 TCP / 0x02 UDP**；多路复用在 v2ray 体系是**数据段里跑 Mux.Cool 协议**（mux-spec："主连接目标地址 = v1.mux.cool 时进入 Mux.Cool 模式"），**不是命令字节取值** | **`Cmd=0x03` 是本生成器的私有扩展**（真实 VMess 服务器不会认识该命令字节）；§8 边界 + G-VMESS-3 |
| 11 | tshark 断言面 | `tshark -G fields` grep -i vmess = **0 命中**（3.6.14 实测）；`tshark -G decodes` 无 vmess 绑定 | 无 dissector，全部断言走 `tcp.flags/tcp.len/tcp.dstport` + frames offset hex（存量 8 条 fields + 1 条 frames 即此口径）；与 `docs/pcap_auto_analysis.md` "VMess(无 dissector+加密随机字节)" 旧记载一致 |
| 12 | 层链可承载 vmess 配置 | registry `vmess` **无 Fields**（`registry.go:1622-1625` 仅 4 行）；`translateTerminalConfig` **无 vmess 分支**（`chain_planner_translate.go` grep `case "vmess"` = 0） | **纯层链今日不可表达 vmess 配置**：层内任何键 → `unknown field`（本车道逐键实测 13 键全拒）；空层 `{}` → `vmess: VmessConfig is required`（实测）。唯一可跑形 = `layers + 顶层 vmess 子映射` 混合形（实测 11 包）——G-VMESS-4 |
| 13 | 结果产物 `trafficgen/docs/protocol-pcap-test/vmess.md` | tracked；末次提交 `e7e7d1c`（**2026-08-27**）早于判死提交 `0417be5`（2026-09-13）；`trafficgen/docs/protocol-pcap-test/vmess/` **目录不存在（0 个 pcap）** | **过期产物**："pass 1" 未经今日复跑证实、其执行的正是已判死的扁平形状——不得作为"今日已跑通"依据（口径同 pcep G-PCEP-11 / opcua G-OPCUA-10）；登记 G-VMESS-11，归属代码阶段 |

**依赖链判定纪律**：以上均可判题（旧文案→代码/实测/spec 三级对照），直接判定。不可判的（真实 v2ray-core 服务器对合成帧的接受性）标"待确认"并写清确认方式（G-VMESS-10）。

**产物过期登记（重要，G-VMESS-11）**：`trafficgen/docs/protocol-pcap-test/vmess.md`（**tracked 产物**，`git ls-files` 可证）写 "Cases: 1 — pass 1"，末次提交 `e7e7d1c`（2026-08-27）**早于**判死提交 `0417be5`（2026-09-13）；`docs/protocol-pcap-test/vmess/` **0 个 pcap**（目录不存在）。该 "1/1 pass" 执行的是**扁平形状**（今日 400 拒绝，§0 #1 实测），**未经今日复跑证实，不代表今日可跑**——读者不得据此判断套件已复跑。本车道**未跑**该套件，不以任何形式引用该产物。

## 1. 范围、profile 与实现状态边界

本版定义 **VMess（V2Ray 私有协议）承载于 TCP** 的流量生成：TCP 握手 → VMess 请求帧（版本字节 + IV/认证槽 + 合成加密体 + 载荷 + 16B 标签）→ VMess 响应帧 → 可选 AEAD 数据块 / MUX 帧 / 心跳对 → TCP 挥手。

| profile | 承载 | 本版允许内容 | 不从 profile 推导 |
|---|---|---|---|
| `vmess_tcp_aead_v1`（主） | TCP，链缺省 443 | AEAD 帧（版本 0x01）请求/响应 + 空/实数据块 | 真实服务器语义（UUID 是否注册、时间戳窗口） |
| `vmess_tcp_legacy_v1` | 同上，`encryption=legacy_aes_128_cfb` | Legacy 帧（版本 0x00，IV 全随机，body 含 AlterID） | 真实 AES-128-CFB 加密 / HMAC-MD5 认证（§3.8 诚实边界） |
| `vmess_mux_v1` | 同上，`command=3` + `mux_streams` | MUX 帧序列（NEW/KEEP/END/KEEPALIVE） | mux-spec 逐字节合规（§3.5 差异表） |
| `vmess_heartbeat_v1` | 同上，`heartbeat=true` | N 对最小请求/响应 + 挥手 | spec 依据（心跳非 VMess 协议概念，生成器场景语义，§5） |
| `vmess_udp_v1` | **链上不支持** | legacy `Command=0x02` 产 UDP 数据报（`planner.go:481-491`）；链 validator 同步拒绝 | — |

显式边界（"不实现、不声称、不许静默转换"）：① **不实现真实密码学**——无 AES/ChaCha20/HMAC-MD5/FNV1a/KDF 运算，加密槽位全部随机字节填充（包注释自述，`planner.go:27-30`；grep 证实 0 处密码库调用）；② 不实现 spec 的 EAuID/ALength/Nonce 认证三段（G-VMESS-2）；③ 不实现指令段 Checksum FNV1a 与 Opt/Sec 字节（G-VMESS-2）；④ 不实现 spec 响应头格式与动态端口指令（G-VMESS-2）；⑤ MUX 帧不是 mux-spec 逐字节合规（G-VMESS-3）；⑥ `Command=0x03` 为私有扩展（§0 #10）；⑦ RST 挥手链上不支持（生成器忽略 `spec.TCP.RST`，恒 FIN 4 包，`layer_gen.go:32-34` 注释自述）；⑧ UDP 模式链上拒绝（§1 profile 表）。

**实现状态（2026-09-29 实测）**：`vmess` 层已注册（`registry.go:1622`，`CategoryTerminal`，`DependsOn ["tcp"]`，FieldContract `tcp.dst_port:443`，**Fields 空**）；生成器/校验器已落码（`internal/protocol/vmess/` 4 文件 3662 行：planner.go 1024 / layer_gen.go 228 / planner_test.go 613 / planner_testpoints_test.go 1797；**139 个 Test 函数**——20 集成 + 119 测试点）；`allowedProtocols["vmess"]=true`（`protocols.go:59`）；引擎注册链式 planner（`cmd/server/main.go:609` `NewChainPlanner("vmess")`，空导入 `:199-200`）；层 translate **未接线**（G-VMESS-4）；1 语义用例存 `cases/vmess.json`（扁平形，今日 400）。

**输出契约（pcap/NIC 双输出）**：两路径共用同一 cases JSON 与断言集（`tcp.flags/tcp.len/tcp.dstport`、frames offset 54/74 hex）；NIC 经 tcpdump 捕获（`nic_capture` 用例级开关）；不设仅单路径可用的断言。

## 2. 协议栈、端口和固定偏移

推荐层链为 `[ip, tcp, vmess]`（引擎自动补 `ip`；最小链 `[tcp, vmess]`）。VMess 帧是 TCP payload 的应用层字节流，**由 tcp 层负责分段与握手挥手**；vmess 层每帧一个报文事件（方向 + 完整字节）。

端口：VMess 惯例 **TCP 443**（registry FieldContract `tcp.dst_port:443`，`registry.go:1624` 注释 "VMess 默认 443（V2Ray 惯例）；用户显式非标准端口优先，不强制"）；链路径 DstPort switch 缺省 443（`chain_planner.go:1235-1238`）。**注意区分两个端口**：`tcp.dst_port` 是代理服务器监听端口；`vmess.port`（配置键）是**指令段内声明的目标端口**（代理要替客户端去连的端口，大端 2B 上线）——存量例两者同值 443，语义不同。

固定偏移：无 VLAN/IP options/TCP options 时，**每帧 VMess 载荷起点为 IPv4 offset 54**（14+20+20）、**IPv6 offset 74**（14+40+20）。载荷内字段偏移按 §3.1 头布局递推；**加密槽位字节不可预测**（随机填充），断言只能钉确定性字节（版本字节）与**帧长度**。

**目标形状 spec_json 样例（严格层链形，顶层仅 `layers`；⚠️ 纯层链今日不可跑——`vmess` 层 Fields 空且无 translate 分支，层内键 400 拒绝，见 G-VMESS-4；本样例是 P4 接线后的目标，不是今日可提交形状）**：

```json
{
  "layers": [
    {"ip": {"src": "10.0.0.1", "dst": "20.0.0.1"}},
    {"tcp": {"src_port": 12345, "dst_port": 443}},
    {"vmess": {"uuid": "12345678-1234-1234-1234-123456789012", "port": 443}}
  ]
}
```

**今日唯一可跑形（混合形，扁平残留绕行，本车道实测 11 包通过）**——顶层 `vmess` 子映射 presence 今日不判死（`CheckProtoFlat` 无 vmess 分支）：

```json
{
  "layers": [
    {"tcp": {"dst_port": 443}},
    {"vmess": {}}
  ],
  "vmess": {"uuid": "12345678-1234-1234-1234-123456789012", "port": 443}
}
```

多流样例（数量只走 `flow_control`；本协议存量未用）：

```json
{
  "layers": [
    {"tcp": {"dst_port": 443}},
    {"vmess": {}}
  ],
  "vmess": {"uuid": "...", "port": 443},
  "flow_control": {"flows": 3}
}
```

## 3. 线格式编码（as-built；与 spec 的差异集中在 §3.8）

### 3.1 客户端请求帧（Request，上行）

总布局（`buildVMessRequestPayload`，`planner.go:603-664`；对齐存量 notes "f4 负载 61B (1B 版本 + 16B nonce + 16B tag + 28B 加密头)"）：

| 偏移 | 字段 | 尺寸 | 值/来源 | 可断言性 |
|---|---|---|---|---|
| 0 | Version | 1B | AEAD 模式 `0x01`（`VersionAEAD`）；Legacy 模式 `0x00`（`VersionLegacy`） | **确定字节，可断言**（存量 frames 断言即此） |
| 1 | IV（认证槽） | 16B | AEAD：前 12B 随机 nonce + 后 4B **零计数器**（`planner.go:629-638`：`iv[:NonceLen]` 随机、`iv[12:16]` 保持 0）；Legacy：16B 全随机 | 随机，**不可字节断言**；长度参与总长公式 |
| 17 | EncryptedBody（合成密文） | = len(bodyPlain) | **先按 §3.1.1 算出明文 body，再整段 `rand.Read` 随机填充**（`:641-645`，"synth ciphertext"）——长度确定、字节随机 | 长度可断言，字节不可 |
| 17+len(body) | Payload | len(v.Payload)B（AEAD 且非空时） | 同上随机填充（`:647-651`） | 长度可断言 |
| 末 16B | Tag（认证槽） | 16B（`TagLen`） | 随机填充 | 长度可断言 |

**总长度公式（请求）**：`请求帧长 = 1 + 16 + bodyPlainLen + payloadLen + 16 = 33 + bodyPlainLen + payloadLen`。

### 3.1.1 请求 bodyPlain（明文结构，算长度用；上线前被随机覆盖）

（`buildVMessRequestBodyPlain`，`planner.go:666-724`）

| 序 | 字段 | 尺寸 | AEAD 模式 | Legacy 模式 |
|---|---|---|---|---|
| 1 | UUID | 16B（`UUIDLen`） | 有 | 有 |
| 2 | Ver / AlterID | 1B | `0x01`（版本字节） | `byte(AlterID)`（变更标识；>255 由 Validate 拒绝） |
| 3 | Cmd | 1B | `0x01` TCP（缺省）/ `0x02` UDP / `0x03` MUX | 同左 |
| 4 | AddrType | 1B | `0x01` IPv4 / `0x02` Domain / `0x03` IPv6（`resolveAddress` 自动推导：IPv4 文本→0x01，IPv6→0x03，其余→0x02；空地址→`0x01`+4 个 `0x00`，`:914-928`） | 同左 |
| 5 | Addr | 变长 | IPv4: 4B 裸地址；Domain: 1B 长度 + N B（上限 253，`MaxDomainLen`）；IPv6: 16B | 同左 |
| 6 | Port | 2B **大端** | `byte(P>>8),byte(P)` | 同左 |
| 7 | PadLen | 1B | `HeaderPadLen`（缺省 **0**；>16 由 Validate 拒绝；⚠️ types.go 注释写 "default: random 0-16" 与实现不符——Plan 不做随机默认化，死注释候选 G-VMESS-8） | 同左 |
| 8 | Pad | PadLen B | 随机 | 同左 |
| 9 | PayloadLen | 2B 大端 | **仅 AEAD**（`len(v.Payload)`） | 无此字段 |

**bodyPlainLen**：AEAD = `24 + N + Pad`（16+1+1+1+2+1+2=24）；Legacy = `22 + N + Pad`（无 PayloadLen，UUID+AlterID+Cmd+AddrType+Port+PadLen=16+1+1+1+2+1=22）。

**请求帧长（合写）**：AEAD = `57 + N + Pad + payloadLen`（=33+24+N+Pad+payload；缺省空地址 N=4、Pad=0、payload=0 → **61** ✓ 存量实测）；Legacy = `55 + N + Pad + payloadLen`。

### 3.2 服务端响应帧（Response，下行）

（`buildVMessResponsePayload` / `buildVMessResponseBodyPlain`，`planner.go:726-813`）

布局：`[Version 1B][IV 16B（全随机）][EncryptedBody][ResponsePayload][Tag 16B]`。

bodyPlain：`[UUID 16B（回显客户端 UUID）][Ver 1B][Cmd 1B（回显请求命令）][PadLen 1B][Pad][RespPayloadLen 2B 大端（仅 AEAD）]` → AEAD = `21 + Pad`，Legacy = `19 + Pad`。

**响应帧长**：AEAD = `54 + Pad + respPayloadLen`（缺省 → **54** ✓ 存量实测）；Legacy = `52 + Pad + respPayloadLen`。

### 3.3 AEAD 数据段（chunk）

（`buildAEADPayloadChunks`，`planner.go:815-850`）

- 每块：`[2B 大端长度 n][n B 载荷][16B 随机 tag]`，`n ≤ MaxChunkPayload = 0x3FFF`（16383 = 2^14−1；spec 上限为 2^14=16384，实现取保守值，差 1 列 G-VMESS-9）。
- 块流末尾恒追加**终止空块** `[0x00 0x00][16B 随机 tag]`（18B）。
- **空载荷语义**：`Payload` 为空且 AEAD 模式 → 仍发一帧终止空块（18B）作为独立 TCP 段（`:546-552`）；Legacy 空载荷 → 不发任何块。
- 存量 notes "f5/f7 18B" 即上/下行终止空块（f5 方向标注错，§0 #3）。

### 3.4 MUX 帧（Command=0x03 且 `mux_streams` 非空时追加）

（`buildMUXFrame`，`planner.go:852-882`）

实现布局：`[session_id 2B 大端][status 1B][length 2B 大端][framePayload]`。

- status 取值：`0x01` NEW / `0x02` KEEP / `0x03` END / `0x04` KEEPALIVE（与 mux-spec 状态字**一致**；`MuxStatus*` 常量 `planner.go:121-131`）。
- NEW 帧 framePayload = `[AddrType 1B][Addr N][Port 2B 大端]`（`TargetAddr` 非空时，经 `encodeAddress`）；其余帧 = `frame.Payload` 原样。
- **与 mux-spec 的差异**（§0 #9）：spec 元数据 = `[ID 2B][Status 1B][Opt 1B]`（Opt bit0=D 有附加数据），帧格式 = `[Metadata Length 2B][Metadata][Extra Data: Length 2B + Data]`——实现缺 Opt 字节与 NetworkType 字节（NEW 应有 `Net 1B` 0x01 TCP/0x02 UDP）、长度前缀位置与语义不同。**G-VMESS-3**。
- Validate：`SessionID` 必须非零、`Status` 必须 ∈ [0x01,0x04]（`planner.go:247-257`，锚词见 §7）。

### 3.5 地址编码

`resolveAddress` / `encodeAddress`（`planner.go:884-939`）：

| AddressType | Addr 线格式 | 长度 |
|---|---|---|
| 0x01 IPv4 | 4B 裸地址（`ip.To4()`；解析失败落 `0,0,0,0`） | 4 |
| 0x02 Domain | `1B 长度 L + L B 域名`（L ≤ 253，超长截断） | 1+L |
| 0x03 IPv6 | 16B（`ip.To16()`；解析失败落全零） | 16 |
| 缺省(0) 自动 | 按 Address 文本解析：IPv4→0x01/IPv6→0x03/其余→0x02；**空串→0x01 + 4 零字节** | — |

Validate 侧：`address_type` 显式设置但 `address` 为空 → 拒绝（`planner.go:222-224`）；`address_type` 非法值 → 拒绝（`:291-293`）。

### 3.6 加密面（as-built 诚实边界，不许夸大）

- **实现零真实密码学**：全仓 `internal/protocol/vmess/` 无 `crypto/aes`、`crypto/cipher` import；无 MD5/SHA/HMAC/FNV/ChaCha20 **运算**（grep 0 命中；仅常量名与算法名字符串出现）；随机填充 `rand.Read` 16 处。包注释自述（`planner.go:27-30`）："The planner does NOT implement real cryptography … ensuring wire-conformant framing without cryptographic validity（无真实加密，仅生成格式合规的随机字节）"。
- `encryption` 配置键只是**布局选择器**（三值白名单 `planner.go:145-149`）：`aead_chacha20_poly1305`（**缺省**，`:328-331`）/ `aead_aes_128_gcm`（两者同为 AEAD 布局，线上无差别）/ `legacy_aes_128_cfb`（Legacy 布局：版本 0x00、IV 全随机、body 含 AlterID、无 PayloadLen 字段）。**不声称**所选算法的线字节与真实 VMess 可互解。
- 与 spec 的认证机制对照：spec AEAD = EAuID（AES-128 加密的时间戳+随机+CRC32，key=KDF(CmdKey,…)，CmdKey=MD5(UUID+固定串)）；spec MD5 = HMAC-MD5(UUID, UTC±30s)。**实现两者都未做**——任务书所称 "AES-128-CFB / ChaCha20 + 认证（HMAC-MD5/FNV1a）" 在本实现中**均无运算**，只有布局占位。G-VMESS-2。

### 3.7 帧序与包数公式（TCP 模式，非心跳）

发射序（`planner.go:493-596` legacy / `layer_gen.go:114-177` 链上事件序，逐帧一致）：

```
握手 3（SYN/SYN-ACK/ACK）
→ 请求帧（up）
→ [载荷块帧（up）：AEAD 分块或 Legacy 裸载荷；载荷空且 AEAD → 终止空块 18B]
→ 响应帧（down）
→ [响应块帧（down）：同上规则]
→ [MUX 帧（up）：每流每帧一事件]
→ 挥手 4（FIN-ACK/ACK/FIN-ACK/ACK）
```

**包数公式**：`单流包数 = 3 + R + C_req + 1 + C_resp + M + 4`，其中 R=1（恒有请求帧）、C_req/C_resp ∈ {0,1}（AEAD 空载荷=1 终止空块；有载荷=1 分块帧（≤0x3FFF 时）；Legacy 空载荷=0）、M = MUX 帧数。**缺省（AEAD、无载荷、无 MUX）= 3+1+1+1+1+4 = 11** ✓ 存量实测。

心跳模式：`3 + 2×HeartbeatCount + 4`（跳过常规请求/响应与 MUX，仍挥手；`planner.go:502-529`）。HeartbeatCount ≤0 兜底 1。

### 3.8 与官方 spec 的逐字段差异表（诚实边界汇总，§0 #5-#8 的钉死版）

| spec（v2fly《VMess Protocol》） | 本实现 | 差异定性 |
|---|---|---|
| 请求 = 认证信息 + 指令段 + 数据段；AEAD 认证 `[EAuID 16][ALength 18][Nonce 8][AHeader][Data]` | `[Ver 1][IV 16][body][payload][tag 16]` | **布局不同**：无 EAuID/ALength/Nonce 三段；Ver 字节 spec 无外置先例（指令段内 Ver 恒 1）→ G-VMESS-2 |
| 指令段 13 字段（Ver/IV/Key/RespAuthV/Opt/Margin+Sec/Reserved/Cmd/Port/AddrType/Addr/Random/Checksum） | body 8-9 字段（UUID/Ver或AlterID/Cmd/AddrType/Addr/Port/PadLen/Pad/[PayloadLen]） | **字段集不同**：缺 Key16/RespAuthV/Opt/Checksum-FNV1a；UUID 进 body（spec 身份在认证段）→ G-VMESS-2 |
| Cmd 仅 0x01/0x02 | 增 `0x03` MUX | **私有扩展**（真实服务器不识别）→ G-VMESS-3 |
| 数据段标准格式 `[L 2B][Padding P][data]`，GCM tag 在 R-16 分界；L 上限 2^14 | `[n 2B][payload][tag 16B]` 链 + 终止空块；上限 0x3FFF | **形似质异**：长度前缀+16B 尾部认证+空块终止三点一致；无 count/Mask/padding 运算、上限差 1 → G-VMESS-2/9 |
| 响应头 `[RespAuthV][Opt][Cmd][CmdLen][CmdContent][data]`，RespAuthV 回显请求 | `[UUID 16][Ver][Cmd][PadLen][Pad][RespLen 2]` | **布局不同**：实现回显 UUID，spec 无此字段；无动态端口指令 → G-VMESS-2 |
| MD5 认证 = HMAC-MD5(UUID, 时间戳) + AES-128-CFB 指令段 | Legacy 仅布局切换（0x00 + AlterID 字节 + 全随机 IV） | **零运算** → G-VMESS-2 |
| Mux.Cool 帧 `[MetaLen 2][ID 2][Status 1][Opt 1][…][ExtraLen 2][Data]` | `[ID 2][Status 1][Len 2][payload]` | **缺 Opt/Net 字节、长度语义不同**；状态字一致 → G-VMESS-3 |

## 4. 业务场景分析（现网典型场景与五层覆盖）

**定性**：**声明式剧本回放**——配置声明一组 VMess 会话参数（UUID/命令/地址/加密布局/载荷/心跳/MUX 流），引擎按固定剧本产出帧序列；TCP 语义（握手/挥手/分段）归 tcp 层。

| 现网场景 | 事务交互 | 对应用例 |
|---|---|---|
| ① 代理建连冒烟（UUID+目标端口，默认 AEAD） | 握手→请求帧→终止空块→响应帧→终止空块→挥手 | 存量 #1（`vmess-basic-session`） |
| ② Legacy 兼容客户端（alterId>0） | 同①但版本字节 0x00、body 含 AlterID | A′ `vmess_req_legacy_version00` |
| ③ 域名目标（远端解析） | AddrType=0x02，Addr=1B 长度+域名 | A′ `vmess_req_addr_domain` |
| ④ IPv6 目标 | AddrType=0x03，Addr=16B | A′ `vmess_req_addr_ipv6` |
| ⑤ 心跳保活探测 | N 对最小请求/响应 | A′ `vmess_heartbeat_*` |
| ⑥ 多路复用隧道 | 请求/响应后追加 MUX 帧序列 | A′ `vmess_mux_*` |
| ⑦ 传输用户载荷 | 请求后追加分块数据帧 | A′ `vmess_chunk_*` |
| ⑧ 非标代理端口 | `tcp.dst_port` 显式非 443 | A′ `vmess_port_nondefault` |
| ⑨ 非法配置拦截 | validator 拒绝（§7 全表） | A′ 负例族 |

**五层覆盖逐层结论**：功能层——请求/响应/数据块/MUX/心跳五类正例 + 12 类拒绝分支负例（§7）；性能层——帧长上界（单 chunk 0x3FFF、Payload/ResponsePayload 65535 上界）、MSS 分段（tcp 层承接，emitData 按 MSS 切分 `segmentByMSS`）、多流并发（策略级 `flow_control`）；数据场景层——三地址族/两加密布局/三命令值/PadLen 0-16 边界/UUID 两文本形/端口 1-65535 边界（§8）；地址与流层——v4/v6 外层独立用例（A′）、单流基线（存量 #1）、**流关联显式不适用**（单 TCP 连接承载全部帧，无派生数据流；MUX 的"多子流"是帧内字段不是独立四元组流，如实声明）；**多会话显式不适用**（本实现单 flow=单连接，无 sessions[] 编排；多连接由策略级 flow_control 承载，本版未用）。业务层——九场景全部有落点。

**次要合法行为显式不适用声明（不设正例、亦不得进负例）**：① 真实密码学互解（G-VMESS-2）；② spec 认证三段/响应头/动态端口指令（G-VMESS-2）；③ mux-spec 逐字节合规（G-VMESS-3）；④ UDP 模式链上承载（validator 拒绝，legacy 才有）；⑤ RST 异常终止（链上恒 FIN，G-VMESS-7）；⑥ `file_source` 载荷来源（解析面存在 `parseVmessConfig`，本版无用例，A′ 候选不立项）。

## 5. 消息/事务模型与状态机

**事务定义**：一次 VMess 请求 + 一次响应（一帧对）。**多事务** = 一个连接内多对按序执行：心跳模式 N 对、MUX 模式请求对 + M 流帧。

vmess 层无自有状态机：握手/挥手/分段在 tcp 层；vmess 层是"按配置顺序把帧翻译成事件"的纯函数驱动（`layer_gen.go` Generate 无分支状态）。

| 阶段 | 产出帧 | 方向 |
|---|---|---|
| 传输建连 | SYN/SYN-ACK/ACK | up/down/up（tcp 层） |
| 请求 | Request 帧（+载荷块） | up |
| 响应 | Response 帧（+响应块） | down |
| 复用 | MUX 帧 ×M | up |
| 传输释放 | FIN-ACK/ACK/FIN-ACK/ACK | up/down/down/up（tcp 层） |

**事件序**（`layer_gen.go:114-177`）：`Request(up)` → `[chunk(up)]` → `Response(down)` → `[chunk(down)]` → `[MUX×M(up)]`；心跳分支 `Heartbeat×N: (Request(up), Response(down))` 后直接返回（tcp 层补挥手）。

**服务选择优先级（互斥）**：① `Heartbeat=true` → 心跳 N 对（跳过常规/MUX）；② 常规请求/响应 + 载荷块；③ `Command=0x03 && len(MuxStreams)>0` → 追加 MUX 帧。心跳与常规/MUX **互斥**（`layer_gen.go:91-112` 早返回）。

**自动派生规则**：① encryption 缺省 `aead_chacha20_poly1305`（`layer_gen.go:70-73`）；② Command 缺省 `0x01`（`:74-77`）；③ HeartbeatCount ≤0 → 1（`:78-81`）；④ 空地址 → AddrType 0x01 + 4 零字节（§3.5）；⑤ AEAD 空载荷 → 自动补终止空块（§3.3）；⑥ TCP 握手/挥手由 tcp 层自动补（validator 校准 `spec.TCP.Handshake/Termination=true`，`layer_gen.go:216-226`）；⑦ UDP 命令 → 链上拒绝（`layer_gen.go:64-67` 双保险）。

**确定性**：同一配置两次生成，帧数/长度/方向/版本字节恒同；随机槽位（IV/body/payload/tag）字节不同——断言面按"确定性长度 + 版本字节"设计（§2/testcase §3），随机性由"同长度不同字节"性质承载，不设字节级随机断言。

## 6. 性能设计与验收（CORE_MEMORY §6.1–6.8）

- **目标与边界**：单流全链缺省 ≤11 帧（含握手挥手）；最大服务面 = Payload 65535B 按 MSS 1460 分段 ≈ 45 段 + 3+4 帧；单 chunk 上限 0x3FFF；MUX 帧数 = Σ每流帧数（配置上界=流数×帧数）。吞吐数字待 P4 基准，**本版不写承诺**。
- **依据**：事件序列流式产出（Generate 逐帧 EmitMsg，无全量聚合）；每帧内存 = 该帧字节数（最小 2+16=18 终止空块 / 请求帧 57+N+Pad+payload）；无跨流共享状态；无锁（纯函数 + 局部变量）。
- **验收两路**：pcap 与 NIC 共用同一断言集（`tcp.flags/tcp.len/tcp.dstport` + frames offset 54/74）；断言实际帧长与版本字节，不只断言"任务没报错"。
- **六类场景落点**：基线（存量 #1，11 帧）/ 目标规模（A′ chunk 多块载荷）/ 压力上限（Payload 65535 → 45 段）/ 长时间运行（心跳 N 对承载）/ 并发交错（顺序多对承载，并发路径为例外不启用）/ 背压（packet_count 精确计数守卫帧数漂移）。

## 7. 错误处理（负例锚词表，与 testcase §5 一一对应、同序）

以下输入必须由 validator 拒绝并传播为 task error，不得产出成功 PCAP 或假成功。锚词为代码字面（`planner.go` Validate + `layer_gen.go` 校准块，实测提取 18 锚词）：

| # | 锚词（error_contains） | 故障输入 | 代码行 |
|---:|---|---|---|
| N-1 | `uuid required` | `uuid` 缺失 | `planner.go:186` |
| N-2 | `invalid uuid` | UUID 非 32 hex（去连字符后） | `:189`（parseUUID `:963`） |
| N-3 | `unsupported encryption` | encryption ∉ 三值白名单 | `:195` |
| N-4 | `exceeds 1-byte range` | Legacy 模式 alter_id > 255 | `:203` |
| N-5 | `invalid command` | command ∉ {0,1,2,3} | `:214` |
| N-6 | `address_type set but address is empty` | AddrType 显式但 Address 空 | `:223` |
| N-7 | `invalid IPv4 address` / `invalid IPv6 address` / `invalid address_type` | 地址族错配/非法 | `:267/:271/:292` |
| N-8 | `domain too long` | 域名 > 253B | `:278` |
| N-9 | `port required` | vmess.port 缺失（=0） | `:228` |
| N-10 | `exceeds max 65535` | vmess.port > 65535 | `:231` |
| N-11 | `header_pad_len` + `exceeds max` | HeaderPadLen > 16 | `:236` |
| N-12 | `payload too large for AEAD` / `response payload too large` | 载荷 > 65535（AEAD） | `:241/:244` |
| N-13 | `SessionID must be non-zero` | MUX 流 ID=0 | `:250` |
| N-14 | `Status` + `invalid` | MUX 帧状态 ∉ [0x01,0x04] | `:254` |
| N-15 | `VmessConfig is required` | 层链空配置（spec.Vmess=nil） | `:181` |
| N-16 | `not supported on the layer chain` | Command=0x02（UDP）链上 | `layer_gen.go:214` |
| N-17 | `TCP.MSS` + `too small` | MSS < 536 | `planner.go:176` |
| N-18 | `unknown field`（schema 层） | 层内任何 vmess 键（Fields 空） | registry Fields 空 → `complete.go:292` |

**形状级拒绝（schema 层，非 planner）**：顶层 `src_ip/dst_ip/src_port/dst_port/count` 任一 → `no longer accepts flat config field <k>`（`CheckProtoFlat` 五键循环，实测存量形状命中）。

**不得误报的合法协议事件**：Legacy 模式 alter_id=0（仅注释告警不拒绝，`:208-210`）；AEAD 模式 alter_id>0（同，`:205-207`）；空地址自动 IPv4 零地址；PadLen=0。

**未入用例的静默路径（缺陷候选）**：`resolveAddress` 对显式 AddrType=IPv4/IPv6 但地址解析失败时**静默落全零地址**（`:895/:902`）不报错——非法值应拒绝，A′ 裁定（G-VMESS-8）。`encodeDomain` 超长**截断**不报错（`:932-934`，Validate 已挡 >253，双保险面）。`buildMUXFrame` 对 NEW 帧 `TargetAddr==""` 时静默退化为空载荷帧（`:865-873`）——A′ 裁定。

## 8. 边界

- **帧长**：最小数据帧 = 终止空块 18B；缺省请求帧 61B / 响应帧 54B（存量实测钉死）；上界 = Payload/ResponsePayload ≤ 65535（Validate 强制）+ 单 chunk ≤ 0x3FFF；跨 MSS 分段由 emitData/segmentByMSS 承接（1460 缺省）。
- **端口**：链缺省 443（FieldContract + DstPort switch）；显式非 443 合法（FieldContract 注释"不强制"）；`vmess.port`（指令段目标端口）1-65535、0 拒绝。⚠️ 显式 `dst_port=80` 会命中 `isUniversalDefault` 兜底被**静默改成 443**（`chain_planner.go:1030` 通用行为，vmess 无豁免名单条目）——A′ 立项确认口径（G-VMESS-8）。
- **命令**：0x01/0x02/0x03 白名单；0x02 链上二次拒绝；0x03 仅私有扩展语义。
- **地址族**：外层 v4/v6 由 ip 层承载；指令段三地址族独立于外层（可 v4 外层 + v6 目标地址）——A′ 覆盖。
- **加密**：三值白名单；缺省 chacha20；值仅选布局不选算法运算（§3.6）。
- **心跳**：与常规请求/响应、MUX 互斥；HeartbeatCount 无上界校验（int，负数兜底 1）——A′ 立项上界口径。
- **MUX**：SessionID 非零、Status ∈ [1,4]；NEW 帧目标地址编码复用 §3.5。
- 不得产生回绕长度或超量分配（长度由 append 前算定，PayloadLen 2B 上界由 Validate 守卫）。

## 9. 原子 ID 与完成定义（存量 1 + 目标全集见 testcase §4）

| # | ID | 类型 | 覆盖 | packet_count（公式推算） | 状态 |
|---:|---|---|---|---:|---|
| 1 | `vmess-basic-session` | 正 | §3.1/§3.2/§3.3：缺省 AEAD 冒烟（61/18/54/18 四帧长 + 版本字节） | 11 | **存量**（扁平形，今日 400，G-VMESS-1） |
| 2-45 | A′ 目标 44 例 | 正/负 | testcase §4 全表（线格式/响应/数据段/命令/MUX/心跳/地址族/端口/12 类负例） | 逐例标注 | **A′ 待落**（P4 按 testcase §4 落 JSON） |

**包数公式**：§3.7。存量 1 例公式验证：3+1+1+1+1+4=11 ✓（与 JSON `packet_count:11` 一致；与 legacy 逐帧序一致）。

**完成定义（本协议口径）**：① testcase §4 目标表全量落 JSON 且三方（design/testcase/cases）ID/包数/断言一致；② 纯层链形状可跑（G-VMESS-4 接线完成后）；③ 每条负例锚词与 §7 表一一对应；④ pcap/NIC 双路同契约。

## 10. P1 规范矩阵（CORE_MEMORY §4 八项：规范要求→业务场景→代码现状→缺口）

### 10.1 八项规范矩阵

| # | 八项 | 规范要求（spec/mux-spec 章节） | 业务场景 | 代码现状 | 缺口 |
|---|---|---|---|---|---|
| 1 | 连接模型 | spec《Dependencies/Underlying Protocol》：TCP 承载、无状态、客户端发起 | 场景①-⑨ | DependsOn ["tcp"]（`registry.go:1623`）；握手挥手归 tcp 层 | 无 |
| 2 | 命令/消息表 | 指令段 Cmd 0x01/0x02；响应头 Cmd；mux-spec 状态字 4 值 | ①⑥ | Cmd 0x01/0x02/0x03（0x03 私有）；状态字 4 值一致 | G-VMESS-3 |
| 3 | 状态机 | spec《Communication Process》：无状态协议，请求-响应非对称 | ①⑤ | 纯函数驱动无状态；心跳/MUX 互斥分支 | 无 |
| 4 | 字段表 | 指令段 13 字段 / 响应头 6 字段 / 数据段块格式 | 数据场景层 | 实现自有 8-9 字段布局（§3.1.1/§3.2/§3.3） | **布局偏离 spec** G-VMESS-2 |
| 5 | 错误处理 | —（私有协议无规范错误码；validator 契约即错误面） | 负例族 | 18 锚词（§7） | 静默路径 3 处 G-VMESS-8 |
| 6 | 超时与活性 | spec 无保活语义（时间戳 ±30s 是认证窗口非心跳） | ⑤ | Heartbeat 是生成器场景语义非协议语义（types.go 自述 "simulating a keepalive probe"） | 如实声明，不声称协议保活 |
| 7 | NAT/代理/被动 | 客户端直连代理，无被动模式 | — | 无被动实现 | 显式不适用 |
| 8 | 版本/方言 | spec《Version》恒 1；AEAD/MD5 双认证自动协商 | ①② | 版本字节 0x01/0x00 二值（实现口径） | 认证机制未实现 G-VMESS-2 |

**逐行重数**：八项 8 行 = 覆 2（行 1/3）+ 立项 4（行 2/4/5/8，含 G-VMESS-2 重复挂两行）+ 不适用 1（行 7）+ 如实声明 1（行 6，非缺口）。

### 10.2 子表①：消息 × 终态矩阵

| 消息 | T1 正常终态 | T2 配置拒绝 | T3 RST 异常终态 |
|---|---|---|---|
| Request(AEAD) | 已覆（#1） | 已覆（N-1~N-12 代表） | 显式不适用（恒 FIN，G-VMESS-7） |
| Request(Legacy) | A′（`vmess_req_legacy_*`） | A′/待实现（N-4 alter_id>255） | 同上 |
| Response | 已覆（#1） | 不适用（响应无独立配置拒绝面） | 同上 |
| 空 chunk | 已覆（#1 f5/f7） | 不适用 | 同上 |
| 实载荷 chunk | A′（`vmess_chunk_*`） | A′/待实现（N-12 超界） | 同上 |
| MUX 4 状态 | A′（`vmess_mux_*`×4） | A′/待实现（N-13/N-14） | 同上 |
| 心跳对 | A′（`vmess_heartbeat_*`） | 不适用 | 同上 |
| UDP 模式 | 不适用（链上拒绝） | A′/待实现（N-16） | 不适用 |
| 层链形状 | A′（纯层链正例，接线后） | A′/待实现（N-15/N-18） | 不适用 |

**逐格重数（机读复核）**：9 行 × 3 列 = 27 格——当前 JSON 可执行覆盖仅存量 #1 的 3 个 T1 格；其余正常/拒绝格均 A′/待实现。设计逻辑分类仍为已覆 **9** / A′ **6**（T1 列：Request(Legacy)/实载荷/MUX/心跳/层链 + UDP 模式目标负例）/ **不适用 12**（T3 列 9 全不适用——链上恒 FIN，G-VMESS-7；T2 列 3：Response/空 chunk/心跳无独立配置拒绝面）。9+6+12=27 ✓。

### 10.3 子表②：数据形态变体表

| # | 变体 | 落点 |
|---:|---|---|
| 1 | UUID 标准文本形（带连字符） | 已覆（#1） |
| 2 | UUID hex 形（32 字符无连字符） | A′（parseUUID `:949-961` 双形支持） |
| 3 | UUID 大写 | A′（hexNibble 接受 A-F） |
| 4 | UUID 缺失/非法 | 已覆锚词（N-1/N-2）；A′ 补例 |
| 5 | AddrType IPv4 显式 | A′ |
| 6 | AddrType Domain | A′ |
| 7 | AddrType IPv6 | A′ |
| 8 | AddrType 缺省自动推导 | 已覆（#1 空地址→IPv4 零地址） |
| 9 | 域名 253 上界 | A′（N-8 边界值） |
| 10 | 域名 254 拒绝 | A′ |
| 11 | PadLen 0/8/16 | A′ |
| 12 | PadLen 17+ 拒绝 | A′ |
| 13 | Port 1/65535 边界 | A′ |
| 14 | Port 0 拒绝 | A′（N-9） |
| 15 | encryption 三值 | A′（缺省已覆 #1） |
| 16 | encryption 非法 | A′（N-3） |
| 17 | AEAD 空载荷终止块 | 已覆（#1） |
| 18 | AEAD 实载荷分块 | A′ |
| 19 | AEAD 载荷 >0x3FFF 多块 | A′ |
| 20 | Legacy 空载荷无块 | A′ |
| 21 | 心跳 ×1 / ×3 | A′ |
| 22 | MUX NEW/KEEP/END/KEEPALIVE | A′ |
| 23 | 外层 IPv6（offset 74） | A′ |
| 24 | 非标端口 | A′ |

**逐行重数（机读复核）**：24 行——**已覆 2**（行 1/8：UUID 文本形、地址缺省自动；其余含锚词但无 JSON 例均为 A′/待实现）+ **A′ 20**（含“已覆锚词但该值/边界尚无独立例”的混合行 4/15）= 24 ✓。

### 10.4 子表③：商业行为→用例映射表

| # | 商业行为 | 用例映射 | 结论 |
|---:|---|---|---|
| 1 | 代理客户端建连冒烟 | #1 | 已覆 |
| 2 | 指定远端目标（IP/域名/v6） | A′ 地址族族 | A′ |
| 3 | Legacy 客户端兼容 | A′ legacy 族 | A′ |
| 4 | 隧道内真实业务载荷 | A′ chunk 族 | A′ |
| 5 | 心跳保活 | A′ heartbeat 族 | A′ |
| 6 | 多路复用 | A′ mux 族 | A′ |
| 7 | 与真实 v2ray 服务器互通 | — | **不适用**（本生成器合成帧无真实密码学；互通性需 G-VMESS-10 单独实测） |
| 8 | 认证机制（EAuID/HMAC-MD5） | — | **A′**（实现暂不具备真实认证；按 G-VMESS-2 裁定后决定新增行为例或登记不解决） |
| 9 | mux.cool 逐字节合规 | — | **A′**（实现帧已可断言状态/长度；按 G-VMESS-3 裁定后补逐字节差异例） |
| 10 | 非法配置拦截 | A′ 负例族 | A′ |

**逐行重数（机读复核）**：10 行——已覆 **1**（行 1 冒烟）/ **A′ 8**（行 2-6 + 行 7-10，含真实互通/认证/mux 合规的待裁定行为）/ **不适用 1**（行 7：真实互通需独立服务器与密码学实现，当前生成器不具备）= 10 ✓。

### 10.5 三路对照与候选方案对比

三路：①规范原文（v2fly 官方 VMess/Mux.Cool 规范，定"必须是什么"——已用其校正实现布局偏离，§3.8）；②商业化软件实际行为（**未取到**：真实 v2ray/xray 服务器对合成帧的接受性未实测 → G-VMESS-10 待确认）；③可靠开源实现思路（v2ray-core 的 AEAD 认证/CmdKey 派生，仅作 §3.6 引文，本文不声称实现）。

| 方案 | 走法 | 取舍 | 结论 |
|---|---|---|---|
| A | 独立 `vmess` 终结层（本版现状） | 帧序列/加密布局/命令/MUX/心跳可声明可断言；代价 = translate 未接线（G-VMESS-4） | **采用**（补接线） |
| B | 直接 tcp 层 + 顶层 payload | 无 UUID/Cmd/AddrType 结构断言面，#1 的 frames 断言退化 | **否决** |
| C | 按 spec 逐字节重写布局（EAuID/指令段 13 字段） | 断言面最合规，但实现重写量大且真实加密仍缺 | **A′ 候选**（G-VMESS-2 裁定：布局对齐 or 明确不解决） |

## 11. P2 D-VMESS-1 代码设计（as-built 逆向定稿）

> 实现已落码；本节为对既有实现的 as-built 定稿，供后续改动为唯一入口；P4 = 缺口收敛（§14）。

### 11.1 文件清单（实测）

| 文件 | 职责 | 行数 |
|---|---|---:|
| `internal/core/types.go`（`:8349-8489`） | `VmessConfig`（14 配置键）+ `VmessMuxStream`（4 键）+ `VmessMuxFrame`（2 键）+ `FlowSpec.Vmess` 槽位（`:1874`） | —（共享文件） |
| `internal/protocol/vmess/planner.go` | 常量/Validate（18 锚词）/legacy Plan（握手挥手+UDP 模式）/build* 纯函数/地址与 UUID 解析/MSS 分段 | 1024 |
| `internal/protocol/vmess/layer_gen.go` | 终结层生成器（Generate 事件序 + RegisterLayerGenerator/Validator init） | 228 |
| `internal/protocol/vmess/planner_test.go` | 20 个集成 Test（含 11 包序列/UDP/MUX/心跳/RST/分块结构） | 613 |
| `internal/protocol/vmess/planner_testpoints_test.go` | 119 个测试点 Test（版本/IV/UUID/命令/地址/端口/Pad/载荷/响应/MUX 逐字段） | 1797 |
| 接线 5 件 | registry（`registry.go:1622`）/ allowedProtocols（`protocols.go:59`）/ convert 子映射（`strategy_convert.go:1546`）/ 引擎链 planner（`main.go:609`）/ 端口缺省+源端口保持（`chain_planner.go:1235/:982`） | — |

**与 opcua 范本的构成差异**：无独立 `builder.go`/`types.go`（build* 纯函数住 planner.go；协议类型住 core/types.go）——4 文件形态，非缺陷，如实记录。

### 11.2 接口签名

- `Validate(spec core.FlowSpec) error`（`planner.go:168`）：18 拒绝分支（§7 N-1~N-14、N-17）；**只读不改 spec**。
- 层校验器（`layer_gen.go:206-227` init 注册）：先跑 `Planner.Validate`，再拒 UDP 模式（N-16），再校准 `spec.TCP.Handshake/Termination=true`（防 tcp 层跳过握手挥手——spec.TCP 零值 false 陷阱，mqtt/redis 同款）。
- `Plan(ctx, spec) (<-chan core.PacketConfig, error)`（`planner.go:300`）：legacy 全序（含自产握手挥手与 UDP 数据报模式）；**链路径不直接用**（链走生成器事件序）。
- 生成器 `Generate`（`layer_gen.go:56`）：事件序 §5；`GenEvents()` 标记事件生产者；`EmitEvent` 未接线显式报错（防误调）。

### 11.3 数据结构

`VmessConfig{UUID, AlterID, Encryption, Command, AddressType, Address, Port, HeaderPadLen, Payload, ResponsePayload, FileSource, Heartbeat, HeartbeatCount, MuxStreams}`（14 键，机读实测）；`VmessMuxStream{SessionID, Frames, TargetAddr, TargetPort}`；`VmessMuxFrame{Status, Payload}`。

### 11.4 主流程

层链配置 → `ValidateLayers`（registry Fields allowlist——**vmess 无 Fields，任何键 400**）→ translate（**无 vmess 分支，G-VMESS-4**）→ `protocolValidator`（vmess 层校验器：Validate + UDP 拒 + TCP 校准）→ 生成器 `Generate` → 事件序（§5）→ tcp 层包装（握手/挥手/分段）→ worker → writer（PCAP/NIC）。

### 11.5 错误分支

18 planner 锚词（§7）+ 2 schema 形状锚词（扁平五键 / unknown field）全部传 task error（零假成功；空配置实测 "VmessConfig is required"）。**静默路径 3 处**（§7 末段）列 G-VMESS-8。

### 11.6 性能边界

见 §6。事件线性产出、per-flow 局部状态、无跨流共享、无锁；吞吐待 P4。

### 11.7 与现有逻辑的冲突点

- `CheckProtoFlat` 无 vmess 分支 → 顶层 `vmess` 子映射 presence 不判死（`strategy_convert.go` grep=0 实测）→ 混合形可跑（§2 样例二），纯层链不可跑——**方向与层链唯一真相相反**，G-VMESS-4 核心。
- `validateBaseDstPortHandled` 无 vmess 条目（但 DstPort switch 已承接，行为无缺口；名单维护性缺口随 G-VMESS-4 一并裁定）。
- 动态 allowlist（`layer_dyn.go`）`vmess` 零命中 → 业务字段动态对象即拒；四元组 `ip`/`tcp` 全开。见 §12.12。
- registry `vmess` Fields 空 → 层内零键可住（对比 opcua 11 键）——G-VMESS-4 的另一半。
- `strategy_convert.go:1550` 注释 "vmess has no canonical port; user must specify" 与链路径缺省 443 并存（两口径，§0 #2）。

### 11.8 回滚方式

本协议文件独立成包，回滚 = revert 4 文件 + 接线 5 处；cases 回滚 = 恢复 1 例 JSON。

## 12. 门1 §1–§14 十四行对照表

| § | 本协议怎么满足 | 证据 |
|---|---|---|
| §1 层链唯一真相 | 见 §12.1 强制展开：存量 1/1 顶层 = 扁平 6 键（**判死形**）；目标形状 = 纯层链（§2 样例一）但**今日不可跑**（Fields 空 + 无 translate）→ G-VMESS-4 为 §1 门的本协议主缺口；今日唯一可跑 = 混合形（§2 样例二，仍属扁平残留） | §12.1；cases 机读 + 本车道探针实测 |
| §2 策略/任务 | 策略 = 单 vmess 流量模板；任务 = 多策略合跑 + 总量封顶；框架语义未动 | §2 样例 |
| §3 五件套 | 见 §12.3 强制展开：会话表/事务序列/关联关系（无派生流诚实声明）/插入位置（终结层）/时间线。有长连接，不豁免 | §12.3 + §5 |
| §4 查规范 | 无 RFC——v2fly 官方 VMess/Mux.Cool 规范（章节名级引用）+ v2ray-core 实现事实 + tshark 实测（0 字段）+ 落码反推；八项矩阵 + 三子表 | §10；规范引文见文首与 §3.8 |
| §5 依赖与错误 | DependsOn ["tcp"]；18 锚词 + 2 形状锚词；失败传 task error（空配置实测拒绝） | §7/§11.5 |
| §6 性能 | §6 六要素齐；吞吐待 P4 不写承诺；pcap/NIC 两路明写 | §6 |
| §7 三份文档 | 130-vmess-{design,testcase}.md v1.0.0 + cases JSON（1 例待迁）+ 本节门表 | 修订记录 |
| §8 设计先行 | 文档先行于 P4 缺口收敛（本车道交付即先行）；门1 批准 = 开工门 | 提交序 |
| §9 测试三源 | 三源 = v2fly 规范 + D-VMESS-1（§11）+ tshark/探针实测；1 存量 ID 回指 §3；存量审计 testcase §9 | testcase §2/§9 |
| §10 评审闭环 | 车道内自审（机读探针 + `/tmp/vmess-facts.md` + `/tmp/vmess-probe.sh`）+ 收官隔离复审待主线程派 | 自审记录 |
| §11 白话 | 文首白话一句（挂号信比喻）先行 | 文首 |
| §12 动态清单 | 见 §12.12 强制展开：四元组全开；业务字段逐个列开/不开 + 理由 | §12.12 |
| §13 schema 派生 | `vmess` 已注册（`registry.go:1622`，不新增层）；**Fields 空即生成 schema 无业务键**——P4 补 Fields 必须重跑 schemagen | §11.1/G-VMESS-4 |
| §14 真实流程 | suite 经 MCP 建策略建任务 → 引擎真实生成 → tshark `tcp.*` + frames 双通道（无协议 dissector）；先跑后钉 | testcase §8 |

### 12.1 §1 强制展开：旧键去向 + 完整 spec_json 样例

**存量实测（脚本机读）**：

| 文件 | 例数 | 顶层键分布 | 链形 |
|---|---|---|---|
| `cases/vmess.json` | 1 | `{count, dst_ip, dst_port, src_ip, src_port, vmess}` ×1（**扁平 6 键，判死形**） | 无 layers |

**旧键去向表（逐键）**：

| 旧键 | 存量值 | 去向 |
|---|---|---|
| `src_ip` / `dst_ip` | `10.0.0.1` / `20.0.0.1` | 迁 `layers[].ip.{src,dst}`（§2 样例一） |
| `src_port` | `12345` | 迁 `layers[].tcp.src_port` |
| `dst_port` | `443` | 迁 `layers[].tcp.dst_port`（链缺省 443，可省略） |
| `count` | `1` | 走 `flow_control`（多流）或省略（单流缺省） |
| 顶层 `vmess` 子映射 | `{uuid, port}` | **目标 = 迁 `layers[].vmess.*`；今日层 Fields 空不可住 → G-VMESS-4 接线后迁移**；接线前混合形（§2 样例二）为唯一可跑过渡 |

**目标形状完整样例**：§2 样例一/三（纯层链 + flow_control）。**结论**：§1 门动作 = ①P4 补 registry Fields（14 键）+ translate 分支；②1 例整体改写为纯层链形；③新增 A′ 例全部纯 layers 形；④收官自查「非负例顶层键 = 0」由 **6 键 → 0**。

### 12-P2 判死负例形状（链级红例必含清单①③④）

- ① presence 形状 `{"layers":[…],"vmess":{}}` 今日**不会被拒**（CheckProtoFlat 无 vmess 分支，grep=0 实测）→ **P4 不建该负例**（建了会真绿=假通过）→ G-VMESS-5 登记。② 白名单外游离键判死（`unknown field`）今日层内已可达（Fields 空，任何键即拒）→ **可建真红例**（A′）。③ 现无负例（存量 1 例为正例）——A′ 负例族每条带锚词（§7）。④ 收官自查「非负例顶层键 = 0」**今日不成立**（6 键）→ P4 迁移后执行。

### 12.3 §3 强制展开：五件套

会话表：`s1` 单连接基线（存量 #1 及全部 A′ 正例，各自四元组，握手→请求→[块]→响应→[块]→[MUX]→挥手）。事务：`t1` 请求事务（Request 帧 + 载荷块）/ `t2` 响应事务（Response 帧 + 响应块）/ `t3` 复用事务（MUX 帧 ×M）/ `t4` 心跳事务（N 对最小请求响应）；每事务四件事（前置=tcp 建连完成/触发=配置顺序/成功=帧长与方向符合 §3/失败=validator 拒绝 §7）见 §5 阶段表 + §4 场景表。关联关系：**无派生流**（诚实声明：单 TCP 连接承载全部帧，无 `driven_by`；MUX 子流是帧内 session_id 字段，不派生独立四元组连接）。插入位置：终结层（`[ip,tcp,vmess]`，无中间层）。时间线：帧内严格顺序 / 事务按配置序展开 / 单流不交错（`concurrent` 不适用——本实现无 sessions[] 编排面）。

### 12.12 §12 强制展开：动态字段清单与序号算法

四元组 `ip.src/dst`、`tcp.src_port/dst_port` 五策略全开（allowlist `internal/core/layer_dyn.go` 头部实测：`ip`/`tcp`/`udp`/`eth`；保底 `DefaultSrcPort+i`；dst 动态与 443 缺省和平共处——显式/动态值非零即不触发补齐）。

**业务字段 14 项全关**（allowlist 无 `vmess` 行，grep=0 实测；对象即拒）：`uuid`（标量令牌，逐流变无意义且 identity 语义）/ `alter_id`（布局选择联动）/ `encryption`（布局选择器）/ `command`（结构选择器）/ `address_type`·`address`（目标寻址，逐流变体需求列 A′ 候选）/ `port`（指令段目标端口）/ `header_pad_len`（混淆填充）/ `payload`·`response_payload`（字节载荷）/ `file_source`（文件来源）/ `heartbeat`·`heartbeat_count`（场景开关）/ `mux_streams`（嵌套对象，无动态形状）——逐流变体需求列 A′ 候选（testcase §7；不冒充已覆盖）。

序号算法实读：`parseLayerDyn`（`layer_dyn.go:78`）/ `TupleGenerator.Next`（`tuple_generator.go`）/ 保底自增（`strategy_convert.go:49` + worker 注入）/ allowlist 白名单（`layer_dyn.go` 头部）——**`vmess` 无块**（grep 实测零命中），即层内任何对象值 → `does not support dynamic`。

## 13. P3 对接清单（T-VMESS 草稿输入；正文落 testcase 文件）

存量 1 ID + 目标 44 A′ ID（正 32 + 负 12，testcase §4 全表）+ packet_count 公式（§3.7）+ 锚词表（§7）+ 双通道断言基线 + 存量审计（testcase §9 全量）。A′ 优先序：① G-VMESS-4 接线（Fields+translate）→ ② 纯层链正例复钉 #1 → ③ 线格式族（legacy/地址族/PadLen/端口边界）→ ④ chunk/MUX/心跳 → ⑤ 负例族 12 条。

## 14. 缺口立项清单

| 缺口 | 内容（现象/证据/归属阶段） | 去向 |
|---|---|---|
| G-VMESS-1 | **存量 1 例扁平判死 + notes 三处失实**：①`spec_json` 顶层 6 键（含五判死键）→ schema 400（本车道探针实测锚词 `no longer accepts flat config field src_ip`）；②notes "f5/f7 服务器响应段" 方向标错（f5=up）；③notes "密钥派生" 夸大 + "AES-128-GCM" 算法名错（缺省 chacha20）；④notes "无默认 dst_port" 与链缺省 443 矛盾。证据：cases 机读 + planner.go:328-331/:533-573/registry.go:1624 | **P4 必做**：改写为纯层链形 + 修 notes 四处；本车道不动 JSON |
| G-VMESS-2 | **线布局偏离官方 spec**：无 EAuID/ALength/Nonce 认证三段；指令段缺 Key16/RespAuthV/Opt/Checksum-FNV1a 字段；响应头格式不同；零密码学运算（AES/ChaCha/HMAC-MD5/KDF 全无，rand.Read 16 处）。证据：§3.8 差异表逐行 + planner.go:27-30 包注释 | **裁定项**：(a) 布局对齐 spec（重写 build*，帧长全变）或 (b) 明确不解决（合成帧定位写死）；真实互通验证 → G-VMESS-10。归属 P4 裁定 + 设计阶段 |
| G-VMESS-3 | **MUX 帧偏离 mux-spec**：缺 Opt/NetworkType 字节、长度前缀语义不同、`Command=0x03` 为私有扩展（spec Cmd 仅 0x01/0x02）。证据：§3.4 对比 + mux-spec 引文 | P4 裁定（对齐 or 声明私有扩展并收窄断言）；`mux_streams` 无法从层内配置（G-VMESS-4 联动） |
| G-VMESS-4 | **纯层链不可跑**：registry `vmess` 无 Fields（13 配置键层内全 `unknown field`，逐键实测）+ `translateTerminalConfig` 无 vmess 分支（grep=0）→ 层链空配置 `vmess: VmessConfig is required`（实测）；唯一可跑 = 混合形（层链+顶层 vmess 子映射）。证据：本车道探针三形状实测 | **P4 首动作**：补 Fields 14 键 + translate 分支 + `validateBaseDstPortHandled` 名单核对 + schemagen 重跑；之后 #1 迁纯层链 |
| G-VMESS-5 | presence 负例不可建：顶层 `vmess` 子映射不判死（CheckProtoFlat 无分支）→ 建了会真绿 | **不建**（等框架级 unknown-key 白名单，kingbase 记忆口径）；登记于 §12-P2 |
| G-VMESS-6 | 业务字段动态全关（layer_dyn allowlist 无 vmess 行） | A′ 候选，不冒充已覆盖 |
| G-VMESS-7 | RST 挥手链上不支持（生成器忽略 `spec.TCP.RST`，恒 FIN 4 包；legacy 才有 RST） | A′ 补例 `vmess_rst`（legacy 面）或显式不解决；本层零断言 |
| G-VMESS-8 | 静默路径 3 处：①AddrType 显式但地址解析失败 → 落全零地址不报错（`:895/:902`）；②显式 `dst_port=80` 被 isUniversalDefault 兜底改 443；③MUX NEW 帧 TargetAddr 空退化为空载荷帧。另 types.go HeaderPadLen "default: random 0-16" 死注释与实现（缺省 0）不符 | P4 裁定拒绝或登记；死注释随 P4 改写 |
| G-VMESS-9 | chunk 上限 0x3FFF（2^14−1）与 spec 2^14 差 1 | P4 裁定（对齐 or 登记差异）；影响 A′ 边界例取值 |
| G-VMESS-10 | 第三源未取到：真实 v2ray/xray 服务器对合成帧接受性未验证；本协议无 RFC，规范符合性以 v2fly 文档章节名为引 | 待确认：搭真实服务器抓包对照；确认前不声称互通（§0 待确认口径） |
| G-VMESS-11 | **结果文档过期**：`trafficgen/docs/protocol-pcap-test/vmess.md`（tracked）"pass 1" 末次提交 `e7e7d1c`（2026-08-27）早于判死提交 `0417be5`（2026-09-13）；`docs/protocol-pcap-test/vmess/` 0 个 pcap；其执行的正是已判死扁平形 | **代码阶段**（P5 重跑后重生成）；本版不删不改，仅登记事实；读者不得据此判断可跑（G-PCEP-11 口径） |

## 15. 修订记录

- v1.0.0（2026-09-29）：P-PIPE 批次二文档轨 P1-P3。首版契约（无旧稿沿革）：存量 1 例机读审计（**扁平 6 键判死形**，探针实测 schema 400 + 三形状链路终态）；13 条基线校正（§0，含 notes 四处失实、布局偏离 spec 六面、MUX 私有扩展、tshark 零字段、层链不可跑、结果文档过期）；§3 as-built 线格式（长度公式 61/54/18 与存量断言复算一致）+ §3.8 spec 差异表；§12.1/12.3/12.12 强制展开 + 12-P2；D-VMESS-1 as-built 定稿（§11）；缺口 G-VMESS-1…G-VMESS-11。自审见 `/tmp/vmess-facts.md` + `/tmp/vmess-probe.sh`（机读）。
