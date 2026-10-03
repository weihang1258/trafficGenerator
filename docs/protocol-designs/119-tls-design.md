# #119 tls（Transport Layer Security 1.3，传输层安全协议，RFC 8446）设计契约

> 版本：v1.0.0（as-built 定稿；批次二文档车道）
> 日期：2026-09-29
> 车道：文档轨（#119 tls，续号）
> 基线：`pipe/tls-doc`（基 `300dfc4`）
> 规范基线：① RFC 8446（TLS 1.3：握手序列 §4、record 层 §5.1/§5.2、扩展 §4.2）；② RFC 5246（TLS 1.2，legacy 路径）；③ RFC 6066 §3（SNI）；④ RFC 7301（ALPN）；⑤ RFC 5280（X.509 v3，cert 块产出的 DER）；⑥ RFC 1035（SNI 253B 上限）；⑦ RFC 6528（ISN 随机化）；⑧ RFC 879（MSS 下界 536）；⑨ 本机 tshark 3.6.14 `tls.*` 字段表（**302 字段**，机读实测）+ 本车道探针实测字节（`/tmp/tgprobe`，§0.2）；⑩ 本仓库落码（`internal/protocol/tls/` + `internal/core/layers/`，§11）。
> 机器契约：`trafficgen/test/protocol_pcap/cases/tls.json`（**15 例，权威**；ID/顺序/包数/断言与本文逐条一致，§9/§13）
> 白话一句：**TLS 是一层"信封"——它自己不发包，而是把内层协议（如 http）写好的报文逐条装进 TLS 记录信封里，再在信封前面补一叠握手信封（ClientHello / ServerHello / 证书…），最后整叠交给 TCP 层去贴邮票（分段、序号、握手挥手全归 TCP）。**

## 0. 本协议的特殊性（三件事，务必先读）

### 0.1 tls 是"可选底座"，被 10 个协议依赖

tls 不是一个独立跑的业务协议，而是**被 10 个协议层声明为可选底座**的**半链变换器**（§3.1/§3.5）。registry 实测（`registry.go`，机读）：

| 依赖方 | 关系声明 | 位置 | 契约端口 | 含义 |
|---|---|---|---|---|
| `sstp` | **`DependsOn: ["tls"]`** | `registry.go:1004` | `tcp.dst_port=443` | **强依赖**：缺 tls 层**自动补全** `[ip,tcp,sstp]` → `[ip,tcp,tls,sstp]`（HTTPS 载体） |
| `http` | `OptionalOn: ["tls"]` | `registry.go:103` | `tcp.dst_port=80` | 可选：默认**不启用** → `{"http":{}}` 生成 http 非 https |
| `dns` | `OptionalOn: ["tls"]` | `registry.go:137` | （无 FieldContract） | 可选（DoT） |
| `mqtt` | `OptionalOn: ["tls"]` | `registry.go:405` | （无） | 可选（MQTTS） |
| `ftp` | `OptionalOn: ["tls"]` | `registry.go:1548` | （无） | 可选（FTPS） |
| `smtp` | `OptionalOn: ["tls"]` | `registry.go:1565` | `tcp.dst_port=25` | 可选（SMTPS，提交 587/SMTPS 465 由用户显式写） |
| `pop3` | `OptionalOn: ["tls"]` | `registry.go:1582` | `tcp.dst_port=110` | 可选（POP3S 995 用户显式） |
| `imap` | `OptionalOn: ["tls"]` | `registry.go:1592` | `tcp.dst_port=143` | 可选（IMAPS 993 用户显式） |
| `socks5` | `OptionalOn: ["tls"]` | `registry.go:1632` | `tcp.dst_port=1080` | 可选（SOCKS5-over-TLS） |
| `sip` | `OptionalOn: ["tls"]` | `registry.go:1858` | （无） | 可选（SIPS，事件面） |

**底座契约两条（本协议的核心接口，不得含糊）**：

1. **透传（passthrough）**：`OptionalOn` 列出的 9 家（http/dns/mqtt/ftp/smtp/pop3/imap/socks5/sip）在**不显式写 tls 层**时走普通链（如 `[ip,tcp,http]`），tls 完全不参与——此时**零 TLS 字节**。写 tls 层才启用。
2. **变换器（transformer）**：tls 参与时，**内层终结层照常产自己的事件流**（如 http 产 `GET / HTTP/1.1\r\n…` 与 `HTTP/1.1 200 OK\r\n…`），tls **不重建应用层**，只把每条内层事件字节**包壳**成 TLS record（`content_type=23` ApplicationData）后转发（方向保留）。**这是"半链"的确切含义**：链 `[ip,tcp,tls,http]` 里 tls 是**倒数第二层**，在 transport **之内**（TLS record 是 TCP payload），与 gre 隧道链（tcp 之外）结构相反。

**强依赖自动补全**：`sstp` 的 `DependsOn: ["tls"]` 使 `[ip,tcp,sstp]` 补全为 `[ip,tcp,tls,sstp]`（`complete.go:168-188` 的 `InnerRequired`/`DependsOn` 补全路径）；补全发生在 validate_layers 预检**之前**有专门拦截（`validate_layers.go` `missing tls carrier` 锚词）。

### 0.2 tls 只实现 TLS 1.3 client 快速路径（诚实边界）

**层链路径（生产真相）与 legacy flat 路径的能力面不同**，本文只对层链路径作 as-built 定稿：

| 能力 | legacy flat 路径（`Planner.Plan`） | **层链路径（本文档契约）** |
|---|---|---|
| TLS 1.3 client | 有（`planner.go:417-600`） | **有**（`layer_gen.go:121-130`，7 条握手 record 固定序列） |
| TLS 1.2/1.1/1.0 | 有（`planner.go:601-705`） | **同步拒绝**（`chain_planner.go:539`，锚词 `only "tls1.3"`） |
| role=server | Validate 接受但 Plan 无反转路径 | **同步拒绝**（`chain_planner.go:546`，锚词 `only "client"`） |
| AlertPath / PSK / OCSPStapling / 0-RTT | 有（`planner.go` 各分支） | **不注入**（层 schema 无字段；`buildClientHello` 以 `nil,false,false` 调用） |
| 应用数据 | 合成 128B 随机密文 ×2（`planner.go:584-600`） | **内层终结层事件委托**（`layer_gen.go:152-188`）；无内层时链不成立 |
| cert（真 X.509 DER） | 有（D-TLS-2 后，`planner.go:999/1043`） | **有**（`layer_gen.go:107-116` + `certgen.go`） |
| close_notify | 有（`planner.go:709-715`） | **无**（变换器不产 Alert record——见 G-TLS-2） |

**因此**：本协议文档描述的是 `[ip,tcp,tls,<终结层>]` 链上的 tls 层，**不是** legacy flat 的 `spec.TLS` 全能力面。链上 `spec.TLS` 只承载**动态解析值**（sni/cert.subject/cert.san 的逐流取值），不是 flat 权威（§12.12）。

### 0.3 字节漂移口径（FTP Task 1 先例）

tls 是**半链变换器**：链上 tls 不产 `PacketConfig`，只把内层事件变换后交给 tcp 层。任何"链化前后字节是否漂移"的判断**不得靠猜**——按 FTP Task 1 先例，**漂移则扩展事件 flag 并实测钉死**。本轮实测结论：翻转前后恒为 `[ip,tcp,tls,http]`，**16 帧口径一致**（§9.2 探针实测）。

**本轮实测手段（`/tmp/tgprobe`，只读副本 + 独立 cmd 探针，不改工作树）**：直接 `BuildLayersPlanner("tls", chain)` → `Plan` → `core.NewBuilder().Build` 取真实帧字节，逐帧解析 record/握手头/证书长度字段。**全部关键数字均来自探针实测，非手算、非引用旧稿**（§9.2 表）。

## 1. 范围、profile 与实现状态边界

本版定义 **TLS 1.3 作为可选底座承载内层终结层协议**的流量生成：`[ip, tcp, tls, <terminal>]` 链上，tls 层注入 7 条握手 record 并把内层事件包成 ApplicationData record。

| profile | 承载 | 本版允许内容 | 不从 profile 推导 |
|---|---|---|---|
| `tls13_inner_delegate`（主，唯一实现） | TCP，`[ip,tcp,tls,<terminal>]` | 7 条握手 record（CH/SH/EE/Cert/CertVerify/SFin/CFin）+ 内层事件包 record + tcp 层握手挥手 | 真实密码学（无密钥交换、无 AEAD、无 MAC） |
| `tls13_cert_static` | 同上，`cert` 块标量全填 | 同上（Certificate record 变长） | RSA 密钥、可配 issuer/extensions |
| `tls13_cert_dyn` | 同上，`cert.subject`/`cert.san` 动态 | 同上（逐流 DN/SAN 变） | 逐流 key_type（关） |

**显式边界（"不实现、不声称、不许静默转换"）**：① **不实现真实密码学**——`key_share` 是 32B 随机、`verify_data` 是 32B 随机、`CertificateVerify` 签名是 64B 随机（`planner.go:833-835/1103-1120` 同款）；**不声称**产出的流可被真实 TLS 栈完成握手；② 层链**只实现 tls1.3 client**（§0.2 表）；③ 不实现 AlertPath/PSK/0-RTT/OCSPStapling（层 schema 无字段）；④ 不实现 `key_type` 除 `ecdsa-p256` 外取值（`validate_layers.go:1117` 锚词 `not supported yet`）；⑤ 不实现 client cert / mTLS（链上无 CertificateRequest 序列）；⑥ 不实现 `cert.file_source`（层链 drive 期无文件注入通道）；⑦ **不实现 close_notify**（变换器只注入 7 条握手 record + 内层事件，无 Alert record——G-TLS-2）。

**实现状态（2026-09-29 实测）**：`tls` 层已注册（`registry.go:1652`，`CategoryTunnel`，`DependsOn ["tcp"]`，`FieldContract {"tcp.dst_port":"443"}`，**Fields 5 键**）；生成表 127 层同代（`schemas/v1/generated/layers.generated.json` 的 `tls` 条目 5 字段与 registry 逐键一致，机读实测）；变换器已落码（`layer_gen.go` 263 行，`TransformEvents() true`）；cert 生成器已落码（`certgen.go` 422 行）；`protocols.go:59` `"tls": true`；`strategy_convert.go:1541` `case "tls"`（flat 载体，§12.1）；层内 translate 已接线（`chain_planner_translate.go:1951/1956`）；结构性校验已接线（`chain_planner.go:525-610`）；**15 例已落 `cases/tls.json`**。

**输出契约（pcap/NIC 双输出）**：两路径共用同一 cases JSON 与断言集（`tcp.dstport`/`tcp.srcport`/`tcp.flags`、`tls.handshake.type`/`tls.record.content_type`/`tls.handshake.extensions_server_name`/`tls.handshake.extensions_alpn_str`/`x509ce.dNSName`/`x509sat.printableString`、frames 原始 hex offset 59）；NIC 经 tcpdump 捕获（`nic_capture` 用例级开关）；**不设仅单路径可用的断言**。

## 2. 协议栈、端口和固定偏移

推荐层链为 `[ip, tcp, tls, <终结层>]`（引擎自动补 `ip`）。**tls 不能当末层**——建链最小输入是 `[{"tls":{}},{"http":{}}]`（裸 `[{"tls":{}}]` 被 V6 拒，`validate_layers_test.go:91` T20 锁死），补全后恒为 `[ip,tcp,tls,http]`。

端口：tls 层 `FieldContract {"tcp.dst_port": "443"}`（`registry.go:1654`）——用户未显式写 tcp 层 `dst_port` 时补齐 **443**（`chain_planner.go:730` → `chain_planner_util.go:291` `fieldContractDstPort`，读**末层** FieldContract 的 `tcp.dst_port`/`udp.dst_port`）。15 例全部显式写 `dst_port: 443` 并纳入断言（§13）。

**固定偏移**：无 VLAN/IP options/TCP options 时，**每帧 TLS record 头起点 = IPv4 offset 54**（14+20+20）。record 内字段偏移按 §3.2 递推。**注意 TLS 记录本身可能被 TCP 按 MSS 分段**（§6），只有完整落在单段内的 record 才可用固定 offset 断言——本协议 15 例全部落单段（最大帧 629B < MSS 1460）。

目标形状 spec_json 样例（严格层链形，顶层仅 `layers`）：

```json
{
  "layers": [
    {"ip": {"src": "10.0.0.1", "dst": "20.0.0.1"}},
    {"tcp": {"src_port": 12345, "dst_port": 443}},
    {"tls": {}},
    {"http": {}}
  ]
}
```

多流样例（数量只走 `flow_control`；tls 无 `sessions[]`，多流由 `strategy_fc` + 层动态承载）：

```json
{
  "layers": [
    {"ip": {"src": "192.0.2.10", "dst": "198.51.100.20"}},
    {"tcp": {"dst_port": 443, "src_port": {"strategy": "list", "list": ["41001", "41002"]}}},
    {"tls": {"sni": {"strategy": "list", "list": ["a.com", "b.com"]}}},
    {"http": {}}
  ],
  "strategy_fc": {"type": "flows", "value": 2}
}
```

## 3. 线格式编码（逐字段，字节偏移与长度公式）

### 3.1 三层结构总览

```
以太帧 = [Eth 14B] [IPv4 20B] [TCP 20B] [ TCP payload = TLS record ... ]
                                        └─ offset 54 起
TLS record        = ContentType(1) + ProtocolVersion(2) + Length(2) + payload
TLS handshake msg = HandshakeType(1) + Length(3) + body
```

### 3.2 Record 层（`buildRecord`，`planner.go:745-752`）

| 相对 record 偏移 | 字段 | 类型/尺寸 | 端序 | 本实现取值 |
|---|---|---|---|---|
| 0 | ContentType | uint8 1B | — | `20` CCS（层链未用）/ `21` Alert（层链未用）/ **`22` Handshake** / **`23` ApplicationData** |
| 1–2 | ProtocolVersion | uint16 2B | **大端** | **恒 `0x0303`**（tls1.3 的 `legacy_version`；`layer_gen.go:85-88` `tlsLegacyVersion` 只接受 `tls1.3`→返回 `protocolVersionTLS12=0x0303`） |
| 3–4 | Length | uint16 2B | **大端** | `len(payload)`，**不含 5B 头** |
| 5… | payload | 变长 | — | 握手消息或内层事件字节 |

**总长度公式**：`record_len = 5 + len(payload)`。

**长度上限（RFC 8446 §5.2）**：单条 record 明文上限 **2^14+1 = 16385**（`layer_gen.go:195` `maxPlaintextRecord = 16385`）。内层事件超限时**按 16385 分片成多条 record**（`layer_gen.go:176-187`），每条同方向、顺序不变，tcp 层再按 MSS 切段。**空事件**（`len(payload)==0`）仍产出一条空 record（`layer_gen.go:166-175`，保持事件一一对应）。

**变换器路径不经过 `segmentByMSS`**（`planner.go:1210`，那是 legacy 路径的函数）——链上分段全归 tcp 层。

### 3.3 握手消息头（`buildHandshakeHeader`，`planner.go:756-764`）

| 相对握手消息偏移 | 字段 | 类型/尺寸 | 端序 |
|---|---|---|---|
| 0 | HandshakeType | uint8 1B | — |
| 1–3 | Length | **uint24 3B** | **大端** |
| 4… | body | 变长 | — |

**总长度公式**：`handshake_len = 4 + len(body)`。

**本实现用到的 HandshakeType**（`planner.go:65-78` 常量表）：`1` ClientHello / `2` ServerHello / `8` EncryptedExtensions / `11` Certificate / `15` CertificateVerify / `20` Finished。（`4` NewSessionTicket / `12` ServerKeyExchange / `14` ServerHelloDone / `16` ClientKeyExchange 仅在 legacy 路径出现，层链不用。）

### 3.4 握手 record 序列（`layer_gen.go:121-130`，7 条，固定）

**这是层链路径的核心规格**——7 条 record 在消费内层事件**之前**一次性注入：

| # | 方向 | ContentType | HandshakeType | body 构成 | 长度公式（实测值，§9.2） |
|---:|---|---|---|---|---|
| 1 | **up** | 22 | **1** ClientHello | 见 §3.5 | 见 §3.5 |
| 2 | down | 22 | **2** ServerHello | 见 §3.6 | 见 §3.6 |
| 3 | down | 22 | **8** EncryptedExtensions | `ext_block`（ALPN 一条扩展） | `4 + 2 + (4 + 2 + 1 + len(alpn[0]))` |
| 4 | down | 22 | **11** Certificate | 见 §3.7 | 见 §3.7 |
| 5 | down | 22 | **15** CertificateVerify | `sig_alg(2) + sig_len(2) + sig(64)` | `4 + 4 + 64 = 72` body；record `5+4+68 = 77` |
| 6 | down | 22 | **20** Finished（server） | `verify_data(32)` 随机 | `4 + 32 = 36` body；record `5+36 = 41` |
| 7 | **up** | 22 | **20** Finished（client） | `verify_data(32)` 随机 | 同上 |

**方向语义**：1 与 7 为 `up`（client→server），2–6 为 `down`（server→client）。`MessageEvent{Up: bool}` 逐条携带（`layer_gen.go:122-129`）。

**CertificateVerify 签名算法恒 `sigECDSA256r1 = 0x0403`**（`layer_gen.go:127`，硬编码）；签名恒 **64B 随机**（`buildCertificateVerify(sigECDSA256r1, 64)`）。

**Finished verify_data 恒 32B 随机**（`buildFinished(32)`；TLS 1.3 SHA-256 口径）。

### 3.5 ClientHello body（`buildClientHello`，`planner.go:767-903`）

body 布局（**顺序固定**）：

| 偏移 | 字段 | 尺寸 | 本实现取值 |
|---|---|---|---|
| 0–1 | `legacy_version` | 2B BE | **`0x0303`**（恒） |
| 2–33 | `random` | 32B | **随机**（`rand.Read`） |
| 34 | `session_id` 长度 | 1B | `0x00`（空） |
| 35–36 | `cipher_suites` 长度 | 2B BE | `len(cipherSuites)*2` |
| 37… | `cipher_suites` | 2B×n BE | **恒 3 个**：`0x1301` / `0x1302` / `0x1303`（`layer_gen.go:118`） |
| … | `compression_methods` 长度 | 1B | `0x01` |
| … | `compression_methods` | 1B | `0x00`（null） |
| … | `extensions` 长度 | 2B BE | `len(ext_block)` |
| … | `extensions` | 变长 | 见下 |

**扩展块（`extBuf`）逐条顺序与内容**（`planner.go:787-891`；层链调用 `psks=nil, allowEarlyData=false, ocspStapling=false`，故 PSK/early_data/OCSP 三条**不出现**）：

| 序 | 扩展 | type | body | 触发条件 |
|---:|---|---|---|---|
| 1 | `server_name`（SNI） | `0x0000` | `list_len(2) + name_type(1=0x00) + name_len(2) + name` | **仅当 `sni != ""`**（`layer_gen.go:98` 读层 config） |
| 2 | `application_layer_protocol_negotiation`（ALPN） | `0x0010` | `proto_list_len(2) + Σ(1B len + proto)` | **恒有**（alpn 空 → 默认 `["h2","http/1.1"]`，`layer_gen.go:100-102`） |
| 3 | `supported_versions` | `0x002b` | `0x04 0x03 0x04 0x03 0x03`（len=4 + 0x0304 + 0x0303） | **恒有**（`effectiveVersion=="tls1.3"`） |
| 4 | `supported_groups` | `0x000a` | `len(2) + 0x001D,0x0017,0x0018` | **恒有**（`layer_gen.go:119`） |
| 5 | `signature_algorithms` | `0x000d` | `len(2) + 0x0403,0x0804,0x0401` | **恒有**（`layer_gen.go:120`） |
| 6 | `key_share` | `0x0033` | `list_len(2) + group(2=0x001D) + key_len(2=32) + key(32B 随机)` | **恒有**（tls1.3） |
| 7 | `signature_algorithms_cert` | `0x0050` | `len(2) + 同 sigAlgs` | **恒有**（tls1.3） |
| — | `session_ticket` / `psk_key_exchange_modes` / `pre_shared_key` / `early_data` / `status_request` / `ec_point_formats` | — | — | **层链不出现**（psks nil / 非 tls1.3 分支） |

**SNI 扩展 wire 形（RFC 6066 §3，`planner.go:791-800`）**：`ServerNameList = list_len(2) + ServerName[name_type(1) + name_len(2) + name]`，`name_type = 0x00`（host_name）。**`list_len` 不可省**（2026-09-14 修过缺 `list_len` 的真 bug）。`example.com` 的扩展体 = `2 + 1 + 2 + 11 = 16B`。

**ALPN 扩展 wire 形（`buildALPNExtension`，`planner.go:1151-1161`）**：`ProtocolNameList = list_len(2) + Σ(1B len + name)`。

**长度公式（实测锚定，§9.2）**：默认参数（无 sni，alpn=`["h2","http/1.1"]`）→ `record_len = 156`，以太帧长 **215**。加 `sni="example.com"`（+16B 扩展）→ `record_len = 176`，以太帧长 **235**。

### 3.6 ServerHello body（`buildServerHello13`，`planner.go:906-948`）

| 偏移 | 字段 | 尺寸 | 取值 |
|---|---|---|---|
| 0–1 | `legacy_version` | 2B BE | **恒 `0x0303`**（硬编码 `body = append(body, 0x03, 0x03)`） |
| 2–33 | `random` | 32B | 随机 |
| 34 | `session_id` 长度 | 1B | `0x00` |
| 35–36 | `cipher_suite` | 2B BE | **`cipherSuites[0]` = `0x1301`**（`layer_gen.go:124`） |
| 37 | `compression_method` | 1B | `0x00` |
| 38–39 | `extensions` 长度 | 2B BE | `len(ext_block)` |
| 40… | `extensions` | 变长 | 两条：`supported_versions`（`0x002b`，body `0x03 0x04`，**ServerHello 内无长度前缀**）+ `key_share`（`0x0033`，body = `group(2=0x001D) + key_len(2=32) + key(32B 随机)`，**无 list_len**——`planner.go:933` 直接传 `entry`） |

**实测**：`record_len = 90`，以太帧长 **149**（§9.2）。

### 3.7 Certificate body（`buildCertificate13FromDER`，`planner.go:1011-1039`）

**TLS 1.3 Certificate（server 侧，无 client auth）布局**：

| 层级 | 字段 | 尺寸 | 取值 |
|---|---|---|---|
| body | `certificate_request_context` | 1B | **`0x00`**（server；`clientAuth=true` 时为 `0x01 0x00` 2B，层链恒 false） |
| body | `certificate_list` 长度 | **3B BE** | `len(entry)` |
| entry | `cert_data` 长度 | **3B BE** | `len(DER)` |
| entry | `cert_data` | 变长 | **真 X.509 DER**（`certgen.go`） |
| entry | `extensions` 长度 | 2B | `0x00 0x00`（空） |

**长度公式**：`entry_len = 3 + len(DER) + 2`；`body_len = 1 + 3 + entry_len`；`handshake_len = 4 + body_len`；`record_len = 5 + handshake_len`。

**实测（§9.2，探针直读长度字段 + `x509.ParseCertificate` 回读；**⚠ 下列数字非恒定——见 G-TLS-1**）**：

| 场景 | DER | `entry` | body | handshake | **record** | 以太帧 |
|---|---:|---:|---:|---:|---:|---:|
| 默认 cert（`tls:{}`） | **464 或 466** | 469 / 471 | 473 / 475 | 477 / 479 | **477 或 479** | **536 或 538** |
| `tls-cert-static`（自定义 DN/SAN） | **556 或 557** | 561 / 562 | 565 / 566 | 569 / 570 | **569 或 570** | **628 或 629** |

> **⚠ 长度非恒定（G-TLS-1，confirmed finding）**：上表两列是**两次不同进程各测一次**的观测值，**不是常量**。`BuildCertDER` 因 `fixedEntropyReader` 的有状态 `ctr` 流 + Go `ecdsa.Sign` 的 `MaybeReadByte` 额外读取而**非确定**（§3.9 末段、G-TLS-1）——DER 长度在 ±2B 内浮动。**实测分布**：默认 cert 跨 10 个新进程 → `record=477/flen=536` ×7、`record=479/flen=538` ×3；cert-static 跨 10 个新进程 → `record=570/flen=629` ×6、`record=569/flen=628` ×4。**同一进程内**因 `certCache`（键 = 5 个明文参数）命中而稳定——但 `Load`/`Store` 之间的竞态窗口使**并发首次生成同参数**仍可产出两份不同 DER。**任何断言不得钉这些长度**。
>
> **口径说明（诚实登记）**：`cases/tls.json` 的 `tls-handshake-basic` notes 写"默认参数 DER **466B**……（record 479/handshake 475/certs 471/cert 466）"。**该组数字是 466 那一支的观测**（探针实测确能复现 466/479/475/471 这一支 ✓），但**不是唯一取值**（另一支为 464/477/473/469）。以 cases 为准的断言（`tls.handshake.type` / `x509ce.dNSName`）**不受影响**（它们不断言长度）。

### 3.8 ApplicationData record（内层委托）

内层终结层事件（`layers.MessageEvent{Bytes, Up}`）逐条包成 `contentTypeApplicationData (23)` record：

- `record = buildRecord(23, 0x0303, chunk)`；
- 超 16385B 分片（§3.2）；
- **方向保留**（`ev.Up` 原样传给 `EmitMsg`）；
- **空事件**产空 record（`len(payload)==0` → `record_len = 5`）。

**实测（`tls-handshake-basic` 默认内层 http）**：

| 帧 | ContentType | record_len | 明文起点（offset 59） |
|---|---:|---:|---|
| f11（up） | 23 | **53**（`0x35`） | `47 45 54 20 2f 20 48 54 54 50 2f 31 2e 31`（`GET / HTTP/1.1`） |
| f12（down） | 23 | **38**（`0x26`） | `48 54 54 50 2f 31 2e 31 20 32 30 30`（`HTTP/1.1 200`） |

`tls-http-inner`（内层 `uri="/tls-inner"`）→ f11 `record_len = 62`（`0x3e`），明文 `47 45 54 20 2f 74 6c 73 2d 69 6e 6e 65 72`。

### 3.9 证书生成器（`certgen.go`）

`BuildCertDER(ref *certgenRef) ([]byte, error)`（`certgen.go:317`）：

1. `ref == nil` → `defaultCertRef()`（**"缺省给全"**：cert 块缺席或单键缺席一律填完整默认，**不报缺参错**）；
2. 缓存命中（`certCache sync.Map`，键 = `canonKey()`）→ 直接返回；
3. DN 解析（`parseDN`：`CN`/`O`/`OU`/`L`/`ST`/`C` 六属性，`CN` 必填，未知属性拒）；
4. 日期解析（RFC3339）+ `not_after > not_before` 检查；
5. `keyType != "ecdsa-p256"` → 拒（`not supported yet`）；
6. 序列号 = `SHA-256(canonKey)[:8]`（**派生，非随机**）；
7. 模板固定：`KeyUsage = DigitalSignature|KeyEncipherment`、`ExtKeyUsage = ServerAuth`、`BasicConstraintsValid=true`、`IsCA=false`、**自签**（`Issuer=Subject`）；
8. 私钥 = `fixedP256Key()`（**SHA-256(固定种子) → P-256 标量 → `ScalarBaseMult` 推公钥**；私钥永不进配置、永不落盘）；
9. `x509.CreateCertificate(&fixedEntropyReader{seed: certSignSeed}, tmpl, tmpl, pub, priv)`；
10. 存入缓存并返回。

**默认值常量**（`certgen.go:52-58`）：`defaultCertSubject = "CN=trafficgen-test,O=TrafficGen Test Lab,C=CN"`；`defaultCertSAN = "example.com"`；`defaultCertKeyType = "ecdsa-p256"`；`defaultCertNotBefore = "2026-01-01T00:00:00Z"`；`defaultCertNotAfter = "2036-01-01T00:00:00Z"`。

**`fallbackCertDER()`**（`certgen.go:410`）：`BuildCertDER` 失败时的确定性占位（全默认 ref 必成功）。**只用于 legacy 路径**（`planner.go:1004/1046`）；层链路径的失败在 `layer_gen.go:113-116` **同步报错**，不走 fallback。

**determinism 声明（与实测不符，见 G-TLS-1）**：`certgen.go:36-39` 注释称"同参数 DER 逐字节相等，默认参数 **465B**"。**本轮实测证伪**：DER 长度在 464/466（默认 ref）间浮动，且同一进程内 40 个不同参数产出 423–427 五种长度。**根因已定位**（G-TLS-1）。

## 4. 业务场景分析（现网典型场景与五层覆盖）

**定性**：**声明式剧本回放 + 内层委托**——配置声明链与 tls 层参数，引擎按固定剧本注入 7 条握手 record，再把内层终结层按自己剧本产出的事件逐条包壳转发；tcp 层负责握手、分段、序号、挥手。

| 现网场景 | 事务交互 | 对应用例 |
|---|---|---|
| ① HTTPS 建连（1.3 全握手） | TCP 握手 → 7 条 TLS 握手 record → AppData 请求/响应 → FIN | #1（`tls-handshake-basic`） |
| ② SNI 与 ALPN 协商 | ClientHello 带 SNI/ALPN → EncryptedExtensions 回选首项 | #2（`tls-sni-alpn`） |
| ③ https 套娃（内层业务委托） | 内层 http 报文包进 ApplicationData | #9（`tls-http-inner`） |
| ④ 服务端证书校验 | Certificate record 携带真 X.509 DER，客户端解出 CN/SAN/有效期 | #10（`tls-cert-static`） |
| ⑤ 多域名/多租户（逐流 SNI） | flows=N，每流不同 SNI | #5（list）/ #6（pattern）/ #7（fixed 对照） |
| ⑥ 逐流证书（逐流 DN/SAN） | flows=N，每流不同 Subject/SAN | #11（subject）/ #12（san） |
| ⑦ 反模式拦截（静态复制） | flows>1 + 全静态四元组 → 拒绝 | #4（`tls-neg-static-copy`） |
| ⑧ 配置错误拦截 | 扁平键/关字段动态/非法枚举/坏日期 → 拒绝 | #3/#8/#13/#14/#15 |

**五层覆盖逐层结论**：

- **功能层**：握手序列 7 条 record（#1 逐条 `tls.handshake.type` 断言 1/2/8/11/15/20/20）+ 内层委托（#9）+ 证书路径（#10）+ 负例 5 类（#3 扁平、#4 静态复制、#8 关字段动态、#13 关字段动态、#14/#15 非法值）。
- **性能层**：单流恒 16 帧（3 握手 + 7 TLS 握手 + 2 AppData + 4 挥手）；多流 32 帧（2×16）；**record 明文上限 16385 分片**（`layer_gen.go:195`，今日无用例 → A′ G-TLS-4）；**最大帧 = 629B**（`tls-cert-static` f7，§3.7），远低于 MSS 1460 故不分段；无吞吐/并发/内存目标（沿 D-TLS-1 §6 口径，网卡未跑）。
- **数据场景层**：空 `tls:{}`（#1）→ 默认 cert/ALPN；sni 标量（#2）/list（#5）/pattern（#6）/fixed（#7）；cert 标量全填（#10）/subject list（#11）/san list（#12）；非法 key_type（#14）/坏日期（#15）；**version/role 非默认值今日零用例**（层链同步拒绝 → A′ G-TLS-3）。
- **地址与流层**：**IPv4 全覆盖（15/15 例 `layers[0].ip` 均为 IPv4）**；**IPv6 今日零用例 → A′ G-TLS-5**；单流基线（#1/#2/#9/#10/#13/#14/#15）；多流（#5/#6/#11/#12 的 `flows=2`）。**流关联（控制流派生数据流）显式不适用**：tls 无副连接概念，内层委托是**同连接内**的事件变换。**多会话（`sessions[]`）显式不适用**：tls 层 schema 无 `sessions` 键，多流由 `strategy_fc` + 层动态承载（D-TLS-1 §2 已裁定）。
- **业务层**：八场景全部有落点（§4 表）。

**次要合法行为显式不适用声明（不设正例、亦不得进负例）**：① 真实密码学（§1 边界①）；② tls1.2/1.1/1.0 与 role=server（层链同步拒绝，§0.2）；③ AlertPath/PSK/0-RTT/OCSPStapling（层 schema 无字段）；④ mTLS/client cert（链上无 CertificateRequest）；⑤ `cert.file_source`（无注入通道）；⑥ close_notify（变换器不产，G-TLS-2）；⑦ `key_type` 除 `ecdsa-p256`（G-TLS-6）；⑧ **RST 异常中断**（框架 tcp 层能力，本层零断言，A′ G-TLS-7）。

## 5. 消息/事务模型与状态机

**事务定义**：一次 TLS 握手（7 条 record 一次性注入）算一个事务；内层每条事件包一条 record 算一次数据交换。**多事务** = 一个连接内握手事务 + N 次数据交换（#1 = 1 + 2）。

tls 层**无自有状态机**——它是"读层 config → 注入固定握手序列 → 逐条包壳内层事件 → 转发"的**纯变换函数**（`TLSGenerator` 无字段，`layer_gen.go:33`）。握手/挥手/分段/序号全归 tcp 层。

| 阶段 | 产出 | 归属 | 用例 |
|---|---|---|---|
| TCP 握手 | SYN / SYN-ACK / ACK（3 帧） | **tcp 层** | 全正例（f1–f3） |
| TLS 握手 | 7 条 record（f4–f10） | **tls 变换器注入** | 全正例 |
| 应用数据 | 内层事件包 record（f11/f12） | **tls 变换器转发** | #1/#2/#9/#10 |
| 关闭 | 4 帧挥手（f13–f16） | **tcp 层** | 全正例 |

**驱动与自动派生规则**（逐条列出，不依赖隐含知识）：

1. **版本缺省**：层 config `version` 缺省/空串 → **`tls1.3`**（`layer_gen.go:81-84`）。
2. **role 缺省**：`role` 缺省/空串 → **`client`**（`layer_gen.go:90-93`）；非 client → 同步拒绝（`chain_planner.go:546`）。
3. **ALPN 缺省**：`alpn` 缺省/空 list → **`["h2","http/1.1"]`**（`layer_gen.go:100-102`）；EncryptedExtensions 取 **`alpn[0]`**（`layer_gen.go:125`）。
4. **SNI 缺省**：`sni` 缺省/空串 → **不发 server_name 扩展**（`planner.go:791`）。
5. **cert 缺省**：`cert` 缺省/空对象/单键缺 → **全默认填满**（§3.9 步骤 1）。
6. **握手参数硬编码**（`layer_gen.go:118-120`）：cipher suites `[0x1301,0x1302,0x1303]`、supported groups `[0x001D,0x0017,0x0018]`、sig algs `[0x0403,0x0804,0x0401]`——**层 config 无对应键**，不可配。
7. **tcp 握手/挥手 pin true**：`validateTLSSpec`（`layer_gen.go:253-263`）强制 `spec.TCP.Handshake = true`、`spec.TCP.Termination = true`（`spec.TCP` nil 则先建）——**防零值链静默丢握手**（mqtt/D-HTTP-1 范式）。
8. **变换器接线断言**：`assertEventWiring`（`chain_planner_chain.go:228`）要求终结层与 transport 之间**每层必须是 `EventTransformer`**（`TransformEvents() true`）；tls 由 `layer_gen.go:44` 返回 true。**未标记则同步拒绝**（锚词 `cannot transform terminal events`），不静默透传。

**`assertEventWiring` 的 transport 定位是类型扫描而非 `len-2`**（`transportIndex`，`chain_planner_chain.go:262`）：tls 链 `[ip→tcp→tls→http]` 的 `len-2` 是 **tls**，若按 `len-2` 找传输层会误判——这是 T13 泛化的关键（旧 `len-2` 定位会让 tcp 不启动 → 空流或挂死）。

**多流展开**：`flows=N` 产出 **N 条独立流**（各自四元组 + 各自完整 16 帧序列），由 `strategy_fc` 驱动，**每流独立走完整 `Generate`**（非交错语义由框架调度决定，用例用 `distinct_values` 聚合断言规避包位依赖）。

## 6. 性能设计与验收（CORE_MEMORY §6.1–6.8）

- **目标与边界**：单流 **16 帧**（3 + 7 + 2 + 4）；多流 `N × 16`；**最大帧 = 629B**（`tls-cert-static` f7，§3.7）；**最大 record 明文 = 16385**（分片上限）；**无吞吐/并发/内存目标**（沿 D-TLS-1 §6，网卡未跑，本版**不写承诺**）。
- **依据**：变换器**逐事件转发、无全量收集**（`layer_gen.go:152-188` 的 for 循环逐条 `emit`）；7 条握手 record 是**固定切片**（`layer_gen.go:121-130`），与配置规模无关；`TLSGenerator` **无状态无字段**；**无锁无 sleep**；cert DER 带 `sync.Map` 缓存（同参数 → 同缓存命中，只读无竞争；首次生成 1 次 ECDSA 签名）。
- **验收两路（§6.3 强制）**：pcap（用例断言 `tls.*`/`x509*` 字段 + frames hex）与 NIC（`nic_capture` 开关）**共用同一断言集**；断言实际字段值与原始字节，不只断言"任务没报错"。
- **六类场景落点（§6.6）**：基线（#1，16 帧）/ 目标规模（#5/#11/#12 多流 32 帧）/ 压力上限（#10 最大帧 629B；record 16385 分片上限**今日无例 → A′ G-TLS-4**）/ 长时间运行（多流展开承载）/ 并发交错（顺序多流承载，tls 层无并发语义）/ 背压（`min_packets` 计数守卫帧数漂移 + record 长度字段自洽）。

## 7. 错误处理（负例锚词表，与 testcase §4 一一对应、同序）

以下输入必须由 **validate_layers / chain_planner 结构性校验 / 动态形状门** 在**建任务期**拒绝，不得产出成功 PCAP、`completed/0 packet` 或只剩 TCP 外壳的假成功：

| # | 负例 ID | 故障输入 | 代码锚词 | 代码位置 |
|---:|---|---|---|---|
| N-1 | `tls-neg-flat` | 顶层 `src_ip`（与层链混用） | `rejects flat config field src_ip` | `strategy_convert.go:8634` |
| N-2 | `tls-neg-static-copy` | `flows=2` + 全静态标量四元组 | `layers pin a static four-tuple but flows > 1` | `schema/semantic.go:285` |
| N-3 | `tls-neg-dyn-closed-version` | `tls.version` 写动态对象 | `does not support dynamic` | `validate_layers.go:1004` |
| N-4 | `tls-cert-neg-dyn-keytype` | `tls.cert.key_type` 写动态对象 | `does not support dynamic` | `validate_layers.go:1046` |
| N-5 | `tls-cert-neg-keytype-value` | `cert.key_type="rsa-2048"` | `not supported yet (only "ecdsa-p256")` | `validate_layers.go:1117`（layers 侧）/ `certgen.go:170`（tls 侧镜像） |
| N-6 | `tls-cert-neg-bad-date` | `cert.not_before="yesterday"` | `invalid RFC3339 timestamp` | `validate_layers.go:1126` / `certgen.go:174` |

**负例原子性**：每例**单一故障注入**，单次执行不得混注；**6 例 `expect` 键集合均为严格两键 `{expect_error, error_contains}`**（机读实测，§13）。

**未入用例的拒绝分支（A′ 立项，不得冒充已覆盖）**：

| 分支 | 锚词 | 代码位置 |
|---|---|---|
| 链上非 1.3 版本 | `tls chain: version %q not supported in the layer chain yet (only "tls1.3")` | `chain_planner.go:539` |
| 链上非 client 角色 | `tls chain: role %q not supported in the layer chain yet (only "client")` | `chain_planner.go:546` |
| SNI 超 253B | `tls chain: SNI length %d exceeds max 253 bytes (RFC 1035)` | `chain_planner.go:552` |
| ALPN 名单项超 255B | `tls chain: ALPN protocol name length %d exceeds max 255 bytes` | `chain_planner.go:560` |
| cert 非对象 | `tls chain: cert must be an object` | `chain_planner.go:574` |
| cert 子键未知 | `tls chain: cert: unknown field %q` | `chain_planner.go:602` |
| cert 子键非串 | `tls chain: cert.%s must be a string` | `chain_planner.go:583` |
| san 形状错 | `tls chain: cert.san must be a string or string array` | `chain_planner.go:592/599` |
| `not_after <= not_before` | `tls chain: cert.not_after must be after not_before` | `validate_layers.go:1135` |
| SAN 条目超 253B | `tls chain: cert.san entry length %d exceeds max 253 bytes` | `validate_layers.go:1141/1147` |
| DN 非法 | `tls chain: cert.subject %q invalid DN (want K=V pairs)` | `validate_layers.go:1174` |
| DN 空值 | `tls chain: cert.subject %q has empty value for %q` | `validate_layers.go:1178` |
| DN 未知属性 | `tls chain: cert.subject has unknown attribute %q` | `validate_layers.go:1185` |
| DN 缺 CN | `tls chain: cert.subject %q missing CN` | `validate_layers.go:1189` |
| legacy 侧 SNI 超长 | `tls: SNI length %d exceeds max 253 bytes (RFC 1035)` | `planner.go:190` |
| legacy 侧版本非法 | `tls: Version %q invalid (must be tls1.0/tls1.1/tls1.2/tls1.3)` | `planner.go:177` |
| legacy 侧角色非法 | `tls: Role %q invalid (must be client or server)` | `planner.go:185` |
| legacy 侧 AlertPath 非法 | `tls: AlertPath.After %q invalid` / `AlertPath.Level %d invalid` | `planner.go:198/201` |
| legacy 侧 PSK 空 Identity | `tls: PSKs[%d] has empty Identity` | `planner.go:207` |
| legacy 侧 MSS 过小 | `tls: TCP.MSS %d too small (min %d per RFC 879)` | `planner.go:166` |
| 变换器未标记 | `layers: layer %q cannot transform terminal events` | `chain_planner_chain.go:249` |
| 缺 tls 载体（sstp） | `missing tls carrier` | `validate_layers.go` |

**不得误报的合法协议事件**：空 `tls:{}`（#1）；多流（#5/#6/#11/#12）；逐流 SNI/cert（#5/#11/#12）；自定义 DN/SAN（#10）；cert 单键缺席（填默认，合法）；ALPN 缺省（默认双协议）。

## 8. 边界

- **帧长**：单流恒 **16 帧**；最小帧 = **60B**（f3/f13–f16 纯 ACK/FIN 段）；**最大帧 = 629B**（`tls-cert-static` f7）；TLS record 最大 = 570B（同帧）；**远低于 MSS 1460，全部单段**。
- **record 明文上限**：**16385B**（`layer_gen.go:195`）；超限分片（今日无例 → A′ G-TLS-4）。**注意**：`buildRecord` 的 Length 是 **uint16**，若不分片，>65535 会**截断**——分片逻辑是必需的守卫。
- **SNI**：≤ **253B**（`chain_planner.go:552`；RFC 1035）。
- **ALPN**：单协议名 ≤ **255B**（`chain_planner.go:560`；`buildALPNExtension` 用 1B 长度前缀）。
- **cert**：`key_type` 仅 **`ecdsa-p256`**；日期 RFC3339 且 `not_after > not_before`；SAN 条目 ≤253B；DN 必含 CN、属性限 CN/O/OU/L/ST/C。
- **cert DER 长度**：**不固定**（默认 464B，浮动 464/466——G-TLS-1）；自定义 DN/SAN 时按内容变化（`tls-cert-static` = 557B）。**任何断言不得钉 DER 长度**。
- **版本/角色**：层链**只接受 `tls1.3` + `client`**；其余同步拒绝。
- **端口**：显式 443 全 15 例；缺省 443 由 tls 层 FieldContract 补齐（`registry.go:1654`）——**缺省端口今日无例 → A′ G-TLS-8**。
- **地址族**：15/15 为 IPv4；**IPv6 今日无例 → A′ G-TLS-5**；异族混写在 ip 层校验（`chain_planner.go:517-524` 隧道内层同款）。
- **多流**：`flows=N` 由 `strategy_fc` 驱动；tls 无 `sessions[]`。

## 9. 原子 ID 与完成定义（15 个唯一语义 ID，顺序为权威）

| # | ID | 类型 | 覆盖 | `min_packets`（JSON 权威） |
|---:|---|---|---|---:|
| 1 | `tls-handshake-basic` | 正 | §3.4/§3.5/§3.6/§3.7/§3.8：1.3 全握手基线 + 内层 http 委托 | 16 |
| 2 | `tls-sni-alpn` | 正 | §3.5：SNI + ALPN 进 ClientHello / EE 回选首项 | 16 |
| 3 | `tls-neg-flat` | **负** | §7 N-1：顶层扁平键判死 | —（无） |
| 4 | `tls-neg-static-copy` | **负** | §7 N-2：静态复制拒绝（`flows=2`） | —（无） |
| 5 | `tls-dyn-sni-list` | 正 | §12.12：`sni` list 轮转（2 流） | 32 |
| 6 | `tls-dyn-sni-pattern` | 正 | §12.12：`sni` pattern 替换（2 流） | 32 |
| 7 | `tls-dyn-sni-fixed` | 正 | §12.12：`sni` fixed 对照端（单流） | 16 |
| 8 | `tls-neg-dyn-closed-version` | **负** | §7 N-3：`version` 关字段动态拒绝 | —（无） |
| 9 | `tls-http-inner` | 正 | §3.8：https 套娃（内层 `uri` 委托） | 16 |
| 10 | `tls-cert-static` | 正 | §3.7/§3.9：cert 标量全填 → 真 X.509 DER | 16 |
| 11 | `tls-cert-dyn-subject` | 正 | §12.12：`cert.subject` list 轮转（2 流） | 32 |
| 12 | `tls-cert-dyn-san` | 正 | §12.12：`cert.san` list 轮转（2 流） | 32 |
| 13 | `tls-cert-neg-dyn-keytype` | **负** | §7 N-4：`cert.key_type` 关字段动态拒绝 | —（无） |
| 14 | `tls-cert-neg-keytype-value` | **负** | §7 N-5：`key_type` 非法值 | —（无） |
| 15 | `tls-cert-neg-bad-date` | **负** | §7 N-6：坏日期 | —（无） |

**计数**：**15 例 = 9 正 + 6 负**。

**包数口径（本协议用 `min_packets` 而非 `packet_count`——诚实登记）**：9 个正例**全部**只写 `min_packets`（16 或 32），**无 `packet_count`**（机读实测）。原因：多流用例的帧数受调度影响，`min_packets` 是下界断言。单流正例的 `min_packets=16` 与实测 16 **相等**（§9.2），但**不是精确断言**（多出的帧不会被判失败）。

### 9.1 包数公式

单流 = **3（TCP 握手）+ 7（TLS 握手 record）+ 2（AppData 请求/响应）+ 4（FIN 四包）= 16**。多流 = `N × 16`（**4 个多流例 #5/#6/#11/#12** `min_packets=32` = 2×16）。

### 9.2 探针实测表（2026-09-29，`/tmp/tgprobe` 直读帧字节）

| 用例 | 帧数 | 关键实测值 |
|---|---:|---|
| `tls-handshake-basic` | **16** | f4 CH `record_len=156`（以太 215）；f5 SH `90`（149）；f6 EE `15`（74）；f7 Cert `477 或 479`（**536 或 538**，**非恒定——G-TLS-1**）；f8 CV `72`（131）；f9/f10 Fin `36`（95）；f11 AppData `53`（112）明文 `GET / HTTP/1.1`；f12 `38`（97）明文 `HTTP/1.1 200 OK` |
| `tls-sni-alpn` | **16** | f4 CH `record_len=176`（以太 **235**，比默认 **+20B** = SNI 扩展 16B + 长度字段差）；f6 EE 仍 `15`（ALPN 只回选首项 `h2`）；**f7 同 #1（非恒定）** |
| `tls-http-inner` | **16** | f11 AppData `62`（`0x3e`，以太 121）明文 `GET /tls-inner HTT…`；**f7 同 #1（非恒定）** |
| `tls-cert-static` | **16** | f7 Cert `record_len=569 或 570`（以太 **628 或 629**，**非恒定**），内嵌 DER **556 或 557B**，tshark/x509 回读 `CN=api.test.local` `O=[TestOrg]` `SAN=[api.test.local www.test.local]` |

**DER 字节级实测（默认 cert，两支观测）**：**支 A**（`cert_data` 长度字段 = `00 01 d0` = **464**；`record_len=477`；`handshake_len=473`；`listLen=469`；`entryLen=466`）；**支 B**（`cert_data` = `00 01 d2` = **466**；`record_len=479`；`handshake_len=475`；`listLen=471`；`entryLen=468`）。两支 DER 尾部均 = `… 00 00`（空 extensions）。**跨 10 个新进程分布：支 A ×7 / 支 B ×3**——**非恒定**（G-TLS-1）。

**帧长自洽校验（逐支）**：支 A `536 = 54 + 477 + 5` ✓；支 B `538 = 54 + 479 + 5` ✓；cert-static `628 = 54 + 569 + 5` / `629 = 54 + 570 + 5` ✓；`215 = 54 + 156 + 5` ✓；`235 = 54 + 176 + 5` ✓。

## 10. P1 规范矩阵（CORE_MEMORY §4 八项：规范要求→业务场景→代码现状→缺口）

### 10.1 八项规范矩阵

| # | 八项 | 规范要求 | 业务场景 | 代码现状 | 缺口 |
|---|---|---|---|---|---|
| 1 | 连接模型 | TCP 承载，TLS record 是 TCP payload（RFC 8446 §5.1） | 场景①–⑧ | `DependsOn ["tcp"]`（`registry.go:1653`）；tls 在 tcp **之内**（`transportIndex` 类型扫描，`chain_planner_chain.go:262`） | 无 |
| 2 | 命令/消息表 | 7 类握手消息（CH/SH/EE/Cert/CV/Fin×2）（RFC 8446 §4） | #1 逐条 | `layer_gen.go:121-130` 固定 7 条 | 无 |
| 3 | 状态机 | 握手序列 + 应用数据 + 关闭 | #1 | tls 层无状态机（纯变换器）；tcp 层拥有握手挥手 | 无 |
| 4 | 字段表 | Record 头 3 键（§3.2）+ 握手头 2 键（§3.3）+ CH/SH/Cert 逐字段（§3.5–3.7） | 数据场景层 | `buildRecord`/`buildHandshakeHeader`/`buildClientHello`/`buildServerHello13`/`buildCertificate13FromDER` 逐字段 | 无 |
| 5 | 错误处理 | 6 类负例 + 22 个未入例拒绝分支（§7） | 负例 N-1…N-6 | validate_layers 1004/1046 + chain_planner 525-610 + certgen 170-189 | A′ 见 §14 |
| 6 | 超时与活性 | 协议无 PING 类保活；**层链不产 close_notify**（G-TLS-2） | — | 变换器只注 7 条握手 record + 内层事件 | G-TLS-2 |
| 7 | NAT/代理/被动 | 无被动模式概念（客户端直连） | — | 层 schema 无 `sessions`/`src_port` 反转 | **显式不适用** |
| 8 | 版本/方言 | 层链只 1.3/client；cert 只 ecdsa-p256 | 正例 9 | `chain_planner.go:539/546`；`validate_layers.go:1117` | G-TLS-3/G-TLS-6 |

**逐项重数**：8 行 = **已覆 4**（行 1 连接模型 / 2 命令消息表 / 3 状态机 / 4 字段表）/ **A′ 立项 3**（行 5 错误处理 / 6 超时与活性 / 8 版本方言）/ **不适用 1**（行 7 NAT/代理/被动）。4 + 3 + 1 = **8** ✓

### 10.2 子表①：握手消息 × 终态矩阵（逐格已覆/立项/不适用）

| 握手消息 | T1 正常终态 | T2 配置拒绝 | T3 RST 异常终态 |
|---|---|---|---|
| ClientHello（1） | 已覆（#1/#2/#5/#6/#7/#9/#10/#11/#12） | 已覆（#3 代表例） | A′ 立项（G-TLS-7） |
| ServerHello（2） | 已覆（#1/#2/#10） | 同上代表已覆 | A′ 立项（G-TLS-7） |
| EncryptedExtensions（8） | 已覆（#1/#2） | 同上 | A′ 立项（G-TLS-7） |
| Certificate（11） | 已覆（#1/#10/#11/#12） | 已覆（#13/#14/#15） | A′ 立项（G-TLS-7） |
| CertificateVerify（15） | 已覆（#1） | 同上 | A′ 立项（G-TLS-7） |
| Finished（20，server） | 已覆（#1） | 同上 | A′ 立项（G-TLS-7） |
| Finished（20，client） | 已覆（#1） | 同上 | A′ 立项（G-TLS-7） |
| ApplicationData（23） | 已覆（#1/#2/#9/#10） | 不适用（内层委托非配置拒绝面） | A′ 立项（G-TLS-7） |

**逐格重数**：8 行 × 3 列 = **24 格**——**已覆 15**（T1 列 8 全覆 + T2 列 7 覆，ApplicationData 行除外）/ **A′ 立项 8**（T3 列 8 行全列，RST 异常终态本层零断言）/ **不适用 1**（ApplicationData 行的 T2——内层委托不是配置拒绝面）。15 + 8 + 1 = **24** ✓

### 10.3 子表②：数据形态变体表（协议相关全部形态逐项）

共 **26 行**：

| # | 变体 | 落点 |
|---:|---|---|
| 1 | 空 `tls:{}`（全默认） | 覆（#1/#3/#4/#8/#9/#13/#14/#15） |
| 2 | `sni` 标量非空 | 覆（#2，`example.com`） |
| 3 | `sni` 空（不发扩展） | 覆（#1 等 8 例） |
| 4 | `sni` list | 覆（#5） |
| 5 | `sni` pattern | 覆（#6） |
| 6 | `sni` fixed | 覆（#7） |
| 7 | `sni` inc/rand（string 面拒绝） | **A′ 立项**（`layer_dyn.go:341`，锚词 `not supported for string field`） |
| 8 | `sni` >253B | **A′ 立项**（`chain_planner.go:552` 有分支） |
| 9 | `alpn` 缺省（默认双协议） | 覆（#1 等） |
| 10 | `alpn` 显式双协议 | 覆（#2） |
| 11 | `alpn` 单协议 | **A′ 立项**（`layer_gen.go:100-102` 有分支） |
| 12 | `alpn` 名单项 >255B | **A′ 立项**（`chain_planner.go:560` 有分支） |
| 13 | `version` 缺省（→1.3） | 覆（15/15 例全不写 version） |
| 14 | `version="tls1.3"` 显式 | **A′ 立项**（与缺省同效，无独立例） |
| 15 | `version` 非 1.3（1.2/1.1/1.0） | **A′ 立项**（`chain_planner.go:539` 有分支） |
| 16 | `role` 缺省（→client） | 覆（15/15 例全不写 role） |
| 17 | `role="server"` | **A′ 立项**（`chain_planner.go:546` 有分支） |
| 18 | `cert` 缺席（全默认） | 覆（#1 等） |
| 19 | `cert` 标量全填 | 覆（#10） |
| 20 | `cert.subject` list | 覆（#11） |
| 21 | `cert.san` list | 覆（#12） |
| 22 | `cert.san` 标量单串 | **A′ 立项**（`certgen.go:118-124` 有分支） |
| 23 | `cert.key_type="ecdsa-p256"` 显式 | 覆（#10 显式写） |
| 24 | `cert.key_type` 非法值 | 覆（#14） |
| 25 | `cert.not_before/not_after` 坏值 | 覆（#15） |
| 26 | `cert.not_after <= not_before` | **A′ 立项**（`validate_layers.go:1135` 有分支） |

**重数**：覆 **17**（行 1,2,3,4,5,6,9,10,13,16,18,19,20,21,23,24,25 —— 共 17 行）/ 立项 **9**（行 7,8,11,12,14,15,17,22,26）。17 + 9 = **26** ✓

### 10.4 子表③：商业行为→用例映射表

| # | 商业行为（出处） | 用例映射 | 结论 |
|---:|---|---|---|
| 1 | HTTPS 建连（RFC 8446 §4 全握手） | #1 | 已覆 |
| 2 | SNI 域名指示（RFC 6066 §3） | #2/#5/#6/#7 | 已覆 |
| 3 | ALPN 协议协商（RFC 7301） | #2 | 已覆 |
| 4 | 内层业务报文加密承载 | #1/#9 | 已覆 |
| 5 | 服务端证书校验（RFC 5280） | #10 | 已覆 |
| 6 | 多租户/多域名（逐流 SNI） | #5/#6 | 已覆 |
| 7 | 逐流证书（灰度/多域名证书） | #11/#12 | 已覆 |
| 8 | 反模式拦截（同四元组重复） | #4 | 已覆 |
| 9 | 配置错误拦截 | #3/#8/#13/#14/#15 | 已覆 |
| 10 | 真实 TLS 握手完成（密码学） | — | **明确不解决**（§1 边界①） |
| 11 | TLS 1.2 兼容连接 | — | **明确不解决**（层链同步拒绝，§0.2） |
| 12 | 服务端角色 | — | **明确不解决**（同上） |
| 13 | 会话恢复 / 0-RTT | — | **明确不解决**（层 schema 无字段） |
| 14 | 客户端证书（mTLS） | — | **明确不解决**（链上无 CertificateRequest） |
| 15 | OCSP Stapling | — | **明确不解决**（层 schema 无字段） |
| 16 | close_notify 优雅关闭 | — | **明确不解决**（G-TLS-2，变换器不产 Alert） |
| 17 | DoT/MQTTS/FTPS/SMTPS/POP3S/IMAPS/SOCKS5-TLS/SIPS 具体承载 | — | **不适用**（属各依赖方协议文档；tls 只提供底座契约，§0.1） |

**重数**：覆 **9** + 不适用 **8** = **17** ✓ 无映射无确认即缺口——本表零缺口。

### 10.5 三路对照与候选方案对比

三路：①**规范原文**（RFC 8446/5246/6066/7301/5280/1035/6528/879，定"必须是什么"）；②**商业化软件实际行为**（**未取到**——未抓真实浏览器/OpenSSL 的 TLS 1.3 字节对照 → G-TLS-9）；③**可靠开源实现思路**（只借鉴"record 头 ContentType+Version+Length、握手头 Type+3B Length"的帧结构；**不搬加密实现**——synth 密文是既定语义）。三路一致点：record/握手头布局、大端、legacy_version `0x0303`、TLS 1.3 的 7 条握手序列；不一致点：**Certificate 的 DER 长度是否确定**（本实现自称确定，实测浮动——G-TLS-1）。

| 方案 | 走法（借鉴来源） | 取舍 | 结论 |
|---|---|---|---|
| A | **事件变换器半链**（本版；tls 在 tcp 之内，不产 PacketConfig） | 内层协议零改动即可获得 TLS 承载；握手/分段/序号全归 tcp，职责单一；代价 = 需要 `EventTransformer` 标记 + `assertEventWiring` 接线（已落码） | **采用** |
| B | tls 作独立终结层（自产 PacketConfig） | 需自行实现 TCP 握手/分段/序号/挥手（与 tcp 层重复）；内层协议要重写一遍 | **否决** |
| C | tls 作外层隧道（tcp 之外，仿 gre） | TLS record 不是 IP 载荷而是 **TCP payload**——结构上放错位置 | **否决**（结构错误） |
| D | 在 legacy `Planner.Plan` 上扩展内层委托 | legacy 已有完整 1.0–1.3 路径，扩内层委托会与链架构双真相 | **否决**（§12.1 双真相禁忌） |

## 11. 代码设计（as-built 定稿；CORE_MEMORY §8 八要素）

> 状态说明：实现已落码，本条为**逆向定稿**（as-built），供后续改动的唯一入口。

### 11.1 文件清单（实测）

| 文件 | 职责 | 行数 |
|---|---|---:|
| `trafficgen/internal/protocol/tls/planner.go` | legacy flat 路径：`Validate`（10 分支）+ `Plan`（全版本序列）+ 全部 builder 函数（`buildRecord`/`buildHandshakeHeader`/`buildClientHello`/`buildServerHello13`/`buildServerHello12`/`buildEncryptedExtensions`/`buildCertificate13FromDER`/`buildCertificate12`/`buildCertificateVerify`/`buildFinished`/`buildAlert`/`buildNewSessionTicket`/`buildALPNExtension`/`buildPSKExtension`/`appendExtension`/`segmentByMSS`/`synOptions`） | 1238 |
| `trafficgen/internal/protocol/tls/layer_gen.go` | **层链变换器**：`TLSGenerator`（`Generate`/`TransformEvents`/`GenEvents`）+ `tlsLegacyVersion` + `validateTLSSpec` + `init` 注册 | 263 |
| `trafficgen/internal/protocol/tls/certgen.go` | 真 X.509 DER 生成：`BuildCertDER`/`parseCertConfig`/`validateCertRef`/`parseDN`/`fixedP256Key`/`fixedEntropyReader`/`certRefFromX509`/`fallbackCertDER` | 422 |
| `trafficgen/internal/protocol/tls/certgen_test.go` | 3 个 `Test*`（DER 确定性/可解析/缺省填全） | 72 |
| `trafficgen/internal/protocol/tls/layer_validate_test.go` | validator 面 | 60 |
| `trafficgen/internal/protocol/tls/planner_test.go` | legacy 编码面 | 1236 |
| `trafficgen/internal/protocol/tls/planner_testpoints_test.go` | legacy 测试点面 | 2427 |
| `trafficgen/internal/core/types.go`（`:8291-8350`） | `TLSConfig`（13 键）/`X509Ref`/`PSKIdentity`/`AlertStep` + `FlowSpec.TLS` 槽位（`:1873`） | （共享文件） |
| `trafficgen/internal/core/layer_dyn.go`（`:32`/`:182`/`:327`/`:938-975`） | allowlist `tls: {sni, cert}` + cert 下钻 + `checkTLSCertDynShape` + `resolveLayerTuple` 回填 | （共享文件） |
| `trafficgen/internal/core/layers/registry.go`（`:1652-1666`） | `tls` 层注册（tunnel 类，5 字段） | （共享文件） |
| `trafficgen/internal/core/layers/chain_planner.go`（`:525-610`） | tls 结构性校验段 | （共享文件） |
| `trafficgen/internal/core/layers/validate_layers.go`（`:963`/`:1004`/`:1046`/`:1106-1190`） | `checkLayerDynObjects` 下钻 + `validateTLSCertScalars` | （共享文件） |
| `trafficgen/internal/core/layers/chain_planner_translate.go`（`:1951`/`:1956`/`:3537`/`:3586`） | `translateTLSSNI` / `translateTLSCert` | （共享文件） |
| `trafficgen/internal/core/layers/chain_planner_chain.go`（`:228`/`:262`） | `assertEventWiring` / `transportIndex` | （共享文件） |
| `trafficgen/internal/core/protocols.go:59` | `"tls": true` 准入 | （共享文件） |
| `trafficgen/internal/core/strategy_convert.go:1541` | `case "tls"` flat 载体（`parseTLSConfig` + `setDefaultDstPort 443`） | （共享文件） |
| `trafficgen/schemas/v1/generated/layers.generated.json` | 生成表 127 层，`tls` 条目 5 字段 | （生成产物） |

### 11.2 接口签名

- `(*TLSGenerator).Generate(ctx context.Context, req *layers.GenRequest) error`（`layer_gen.go:49`）：读 `req.Layer.Config`（version/sni/alpn/role/cert）与 `req.Meta.Events`（内层事件流），注入 7 条握手 record 后逐条包壳转发。
- `(*TLSGenerator).TransformEvents() bool`（`:44`）：恒 `true`——`assertEventWiring` 据此放行。
- `(*TLSGenerator).GenEvents() layers.EventGenerator`（`:40`）：恒 `nil`——tls 不是事件生产者。
- `validateTLSSpec(spec *core.FlowSpec) error`（`:253`）：调 `(&Planner{}).Validate(*spec)` + pin `Handshake/Termination = true`。
- `BuildCertDER(ref *certgenRef) ([]byte, error)`（`certgen.go:317`）。
- `parseCertConfig(v interface{}) (*certgenRef, error)`（`:94`）：缺键填默认；未知子键/类型不符 → 错。
- `validateCertRef(ref *certgenRef) error`（`:168`）：tls 包侧业务约束。
- `validateTLSCertScalars(cert map[string]interface{}) string`（`validate_layers.go:1106`）：layers 包侧**同语义镜像**（import 禁忌：layers 不 import protocol/tls）。

**drain 纪律（`layer_gen.go:55-73`）**：任何结构性错误返回**前**必须排空 `req.Meta.Events`——本生成器是 `transformCh[0]` 的唯一消费者，同步写者（终结层主线程）在满缓冲（64）时会**永久阻塞**，不消费则 drive 死锁（review transform-wiring F1 / MED-2 同款纪律）。

### 11.3 数据结构

**层 schema**（`registry.go:1652-1666`，5 键，与生成表逐键一致）：

| 键 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `version` | string | `"tls1.3"` | 层链只接受 `tls1.3` |
| `sni` | string | `""` | 空 = 不发扩展；≤253B |
| `alpn` | list | `[]` | 空 → 生成器默认 `["h2","http/1.1"]` |
| `role` | string | `"client"` | 层链只接受 `client` |
| `cert` | object | （无） | 5 子键：`subject`/`san`/`key_type`/`not_before`/`not_after` |

**`core.TLSConfig`**（`types.go:8291`，**13 键**，flat 载体用）：`Version`/`Role`/`SNI`/`ALPN`/`CipherSuites`/`SupportedGroups`/`SignatureAlgorithms`/`ClientCertificate`/`ServerCertificate`/`PSKs`/`AllowEarlyData`/`AlertPath`/`OCSPStapling`。**注意：层 schema 5 键是它的子集**——`CipherSuites`/`SupportedGroups`/`SignatureAlgorithms`/`PSKs`/`AllowEarlyData`/`AlertPath`/`OCSPStapling` **层内不可达**（§0.2）。

**`certgenRef`**（`certgen.go:65`，**非导出**）：`subject`/`san`/`keyType`/`notBefore`/`notAfter`——5 个明文字段（私钥永不进配置）。

**`LayerTLSDyn`**（`types.go:3665`）：`SNI`/`CertSubject`/`CertSAN` 三个 `*StrategyConfig` 指针。

### 11.4 主流程

```
层链配置 → ValidateLayers（registry Fields 5 键 allowlist + checkLayerDynObjects 下钻）
  → 链补全（[tls,http] → [ip,tcp,tls,http]）
  → ValidateSpec 结构性校验（chain_planner.go:525-610：version/role/SNI/ALPN/cert）
  → assertEventWiring（tls 必须 TransformEvents）
  → translate（translateTLSSNI/translateTLSCert 解析动态值 → spec.TLS）
  → drive：终结层（http）产事件流 → tls 变换器（注入 7 条握手 record + 逐条包壳）→ tcp 层（握手/分段/序号/挥手）
  → writer（PCAP/NIC）
```

**配置权威**：**层链是唯一真相**。地址只落 `ip` 层、端口只落 `tcp` 层（FieldContract `tcp.dst_port=443`）、数量只走 `flow_control`/`strategy_fc`；tls 业务 5 字段只落 `tls` 层。顶层 `tls` 子映射是**过渡载体**（`strategy_convert.go:1541`，本版**不迁**——见 §12.1 与 G-TLS-10）。

### 11.5 错误分支

见 §7 表（6 类负例 + 22 个未入例分支）。**关键**：所有结构性错误在 **create/ValidateSpec 期同步拒绝**，**不落 drive 期**——因为 drive 期生成器报错会被 Plan goroutine 吞成 0 包空流（`chain_planner.go:525-527` 注释明写"同 gre HIGH-2 先例"）。

**生成器独立防御层**（`layer_gen.go:85-116`）：`version` 非 1.3 / `role` 非 client / `parseCertConfig` 失败 / `BuildCertDER` 失败 → **drain 后返回错**（覆盖引擎直调路径，不吞成空流）。

### 11.6 性能边界

见 §6（逐事件转发、固定 7 条握手切片、无状态、无锁、cert DER 带缓存）。

### 11.7 与现有逻辑的冲突点

- **`CheckProtoFlat` 无 tls 分支**（`strategy_convert.go:8625-8660` 实测：`case` 列表含 http 族 9 家 / dns / mqtt / cwmp 等，**无 tls**）→ 顶层 `tls` 子映射 presence **不判死**（G-TLS-10）。**禁加单协议黑名单分支**（等框架级 unknown-key 白名单；kingbase 记忆裁定）。
- **顶层未知键通用门也缺**：游离顶层键（如 `{layers:[…], bogus: 1}`）今日**不判死**（`CheckProtoFlat` 只查五键 + 各协议子映射白名单）→ presence 负例今日建了会真绿 = **假通过**，**不建**（G-TLS-10，与 moxa G-MOXA-2 / opcua G-OPCUA-1 同款）。
- **`TransformEvents` 在 registry 是死字段**：`LayerSchema.TransformEvents`（`schema.go:109`）只有 `http` 用到（`registry.go:104`，http_flv 链）；tls 的变换器标记**只由生成器接口方法提供**（`layer_gen.go:44`），registry 未声明。**当前无功能影响**（`assertEventWiring` 查生成器接口，不查 schema），但两处语义不一致 → G-TLS-11。
- **动态 allowlist**：`layer_dyn.go:32` `"tls": {"sni": true, "cert": true}`（顶层 2 键 + cert 下钻 2 子键）→ 其余 3 键（version/alpn/role）对象即拒。
- **legacy 与层链双真相**：`planner.go` 的 `buildClientHello` 等被**两条路径共用**（legacy `Plan` 与层链 `Generate` 都调它）——**这是刻意的**（单真相的 builder），但**参数面不同**（层链传 `nil,false,false`）。修改这些 builder 必须**同时**考虑两条路径。

### 11.8 回滚方式

本协议文件独立成包，回滚 = revert `internal/protocol/tls/` 7 文件 + 接线 6 处（registry / protocols / translate / convert / chain_planner / layer_dyn）；不触及其他协议。cases 回滚 = 恢复 15 例 JSON（产物文件，非文档）。

## 12. 门1 §1–§14 十四行对照表（CORE_MEMORY §15.1–15.3）

| § | 本协议怎么满足 | 证据 |
|---|---|---|
| §1 层链唯一真相 | 见 §12.1 强制展开：15 例中 **14/15 顶层仅 `{layers}`**；**1 例（`tls-neg-flat`）顶层多 `src_ip` 且其 `spec_json` 多顶层 `src_ip`——这是负例的执法对象本身，不是残留**（判死负例形状，见 §12-P2 ④） | §12.1；`cases/tls.json` 机读实测 |
| §2 策略/任务 | 策略 = 单 tls 流量模板；任务 = 多策略合跑 + 总量封顶；tls 无 `sessions[]`，多流只走 `strategy_fc` + 层动态 | 设计 §2 样例；§12.3 |
| §3 五件套 | 见 §12.3 强制展开：会话表/事务序列/关联（**无派生流**诚实声明）/插入位置（**变换器半链**）/时间线 | §12.3 + §5 |
| §4 查规范 | RFC 8446/5246/6066/7301/5280/1035/6528/879 + tshark 3.6.14 字段表 + 探针实测字节；八项矩阵 + 子表①②③ | §10 |
| §5 依赖与错误 | `DependsOn ["tcp"]` 单值 + **`OptionalOn` 10 家底座契约**（§0.1）；6 类负例 + 22 未入例分支；失败传 task error | §0.1/§7/§11.5 |
| §6 性能 | 见 §6（6.1–6.8 要素齐；吞吐数字标待基准，不写承诺；pcap/NIC 两路验收明写） | §6 |
| §7 三份文档 | `119-tls-{design,testcase}.md`（本文 + 配套）+ cases JSON 15 例 | 修订记录 |
| §8 设计先行 | 本 as-built 定稿先于后续改动；门1 获批 = 开工门 | 提交序 |
| §9 测试三源 | 三源 = RFC 系列（§10）+ 本设计（§3/§11）+ **探针实测字节**（§9.2，已到帧级）；15 ID 逐项回指；存量 15 例审计去向 testcase §8 | `119-tls-testcase.md` §2/§5/§8 |
| §10 评审闭环 | 每阶段对抗自重审 + 收官隔离复审；红先绿后 | 自审日志 |
| §11 白话 | 本文首节白话一句先行 | 本文头 |
| §12 动态清单 | 见 §12.12 强制展开：四元组全开；业务 2 键开（sni + cert 下钻 2 子键）/3 键关 + 理由；序号算法实读行号 | §12.12 |
| §13 schema 派生 | `tls` 已在 `registry.go:1652` 注册（**不新增层**）；生成表 127 层同代（`tls` 条目 5 字段与 registry 逐键一致，机读实测）；**改 registry Fields 必须重跑 schemagen** | §11.1/§11.3 |
| §14 真实流程 | suite 经 MCP 建策略建任务 → 引擎真实生成 → tshark `tls.*`/`x509*` + frames 双通道 → 先跑后钉 | testcase §7 |

### 12.1 §1 强制展开：旧键去向 + 完整 spec_json 样例

**存量实测（逐例机读，2026-09-29）**：

| 文件 | 例数 | 顶层键分布 | 链形 | 负例 expect 形状 |
|---|---|---|---|---|
| `cases/tls.json` | 15 | `{expect,id,proto,spec_json,summary}` ×10；`+strategy_fc` ×5 | **`[ip,tcp,tls,http]` ×15**（唯一链形） | 6/6 = 严格两键 `{expect_error,error_contains}` |

**旧键去向表（§15.3 要求"每个键写去向"）**：

| 旧键 | 存量出现例数 | 去向 |
|---|---:|---|
| `src_ip` / `dst_ip` | **0**（顶层 `spec_json`）；**1**（`tls-neg-flat` 的 `spec_json.src_ip`，**负例执法对象**） | 已住 `layers[0].ip.{src,dst}`（15/15）；负例那一处是判死靶子，**保留** |
| `src_port` | **0** | 已住 `layers[1].tcp.src_port`（15/15 显式写，含 5 例动态 list） |
| `dst_port` | **0** | 已住 `layers[1].tcp.dst_port`（15/15 显式写 443） |
| `count` | **0** | 走 `strategy_fc`（5 例用 `{"type":"flows","value":2}`） |
| 顶层 `tls` 子映射 | **0** | 已住 `layers[2].tls`（15/15） |
| `strategy_fc` | **5** | 保留（多流唯一载体，tls 无 `sessions[]`） |

**结论**：**本协议存量顶层零残留**（除 1 例判死负例的执法靶子）——§1 门的动作 = ①**无旧键可删**；②收官自查行「**非负例**顶层键 = 0」**今日即成立**（机读：14 例非负例顶层仅 `{expect,id,proto,spec_json,summary}` + 5 例 `strategy_fc`；`spec_json` 顶层仅 `{layers}`）；③A′ 新增例全部沿用纯 layers 形。

**目标形状样例**见 §2（顶层仅 `layers`）。

### 12-P2 判死负例形状（链级红例必含清单①③④）

- ① presence 形状 `{"layers":[…],"tls":{}}` 今日**不会被拒**（`CheckProtoFlat` 无 tls 分支，实测）→ **不建该负例**（建了会真绿 = 假通过）→ 缺口 G-TLS-10 登记。② 白名单外游离键判死（`unknown field`）今日**亦无通用门** → 同 G-TLS-10，不建。③ **6 负例每条带锚词**（已齐，§7）。④ 收官自查「非负例顶层键 = 0」**今日已成立**（§12.1）。

### 12.3 §3 强制展开：五件套

- **会话表**：`s1` 单连接基线（15/15 例各自四元组；`[ip,tcp,tls,http]` 一条链，TCP 握手 3 → TLS 握手 7 → 内层委托 AppData → FIN 4）。**无 `sessions[]` 数组**——tls 层 schema 无 `sessions` 键（**形态差异已声明**，非遗漏）。
- **事务序列**：`t1` TCP 建连（tcp 层）/ `t2` TLS 握手（tls 变换器一次性注入 7 条 record）/ `t3` 内层业务交换（终结层事件逐条包壳）/ `t4` 关闭（tcp 层 FIN 四包）。每事务四件事（前置/触发/成功/失败）见 §5 阶段表 + §4 场景表。
- **关联关系**：**无派生流**（诚实声明）——tls 不派生子连接，内层委托是**同连接内**的事件变换，**无 `driven_by`**；与 FTP（控制流派生数据流）/SIP（信令派生媒体）不同。
- **插入位置**：**变换器半链**——tls 在 transport **之内**（`[ip,tcp,tls,<terminal>]`，倒数第二层），不产 `PacketConfig`，`GenEvents()` 恒 `nil`，由 `assertEventWiring` 强制 `TransformEvents() true`。
- **时间线**：**严格顺序**——7 条握手 record 在**消费内层事件之前**一次性注入（`layer_gen.go:139-144` 的 for 循环），内层事件随后逐条转发；**无交错**（多流由框架调度，tls 层内无并发语义）。

### 12.12 §12 强制展开：动态字段清单与序号算法

**四元组 5 策略全开**（allowlist `layer_dyn.go:17-21` 实测）：`ip.src`/`ip.dst`/`ip.ttl`、`tcp.src_port`/`tcp.dst_port`、`udp.src_port`/`udp.dst_port`、`eth.src_mac`/`eth.dst_mac`。保底 `DefaultSrcPort+i`（`strategy_convert.go:49`）；dst 动态与 443 缺省和平共处（显式/动态值非零即不触发补齐）。

**业务字段逐个列（`layer_dyn.go:32` allowlist + `:327` 下钻）**：

| 键 | 开/关 | 面 | 理由 |
|---|---|---|---|
| `sni` | **开** | **string 面**（fixed/list/pattern） | 域名是逐流可变的真实业务字段（多域名/多租户）；`inc`/`rand` 产整数串对域名无意义 → 形状层拒（锚词 `not supported for string field`，`layer_dyn.go:341`） |
| `cert` | **开（下钻）** | 对象 → 下钻 2 子键 | allowlist 登记顶层 `cert`（值为对象即下钻，不直接 parse） |
| `cert.subject` | **开** | string 面 | 整 DN 串替换语义（逐流证书）；颗粒度 = 整串（F1 决策） |
| `cert.san` | **开** | string 面 | 逐流 SAN；list 端点是域名串（`checkDynEndpoints` 的 isIP/isMAC/isPort/isTTL 全假 → 只判非空） |
| `cert.key_type` | **关** | — | 对象即 `does not support dynamic`（`checkTLSCertDynShape` default 分支）；密钥类型切换会改证书长度与签名算法，包长断言全需重钉，无逐流变需求 |
| `cert.not_before` / `cert.not_after` | **关** | — | 同上（日期逐流变无业务意义） |
| `version` | **关** | — | 常量协商：层链只实现 1.3，逐流变无意义 |
| `role` | **关** | — | 常量：层链只实现 client |
| `alpn` | **关** | — | 列表无允许的解析面，且现状无轮转需求（D-TLS-1 §12 裁定） |

**序号算法实读**（不重写，复用框架单一真相）：

- `parseLayerDyn`（`layer_dyn.go:78`）——层 config → `LayerDynValues`（含 `TLS.SNI`/`TLS.CertSubject`/`TLS.CertSAN`）；
- `checkDynShape`（`:369`）→ tls 的 `cert.subject`/`cert.san` 转 `checkTLSCertDynShape`（`:331`）；
- `CheckLayerDynShape(lname, field, m)`（`:1037`）——形状门入口；
- `ResolveStringValue(s, i)`（`tuple_generator.go:310`）——string 面逐流解析（fixed/list/pattern）；
- `genStringValue`（`shard_router.go:58`）——`{n}` 替换与四元组 pattern **同算法**（单真相）；
- `resolveLayerTuple(spec, i)`（`layer_dyn.go:770`）——回填 `spec.TLS.SNI` / `spec.TLS.ServerCertificate.{Subject,San}`（`:938-975`）；
- **生产真相 = `translateTLSSNI`/`translateTLSCert`**（`chain_planner_translate.go:3537/3586`）——drive 期按 `spec.FlowIndex` 解析并注入层 config 副本；`resolveLayerTuple` 那段只服务直调/单测口径（源码注释明写）。

**序号域对齐**：`sni`/`cert.subject`/`cert.san` 与四元组**同序号域**（同 `i`）——用例 #5/#11/#12 用 `tcp.src_port` list 作"static-copy 门逃逸口"并借此对齐（41001→a.com、41011→a.test）。

## 13. P3 对接清单（T-TLS 草稿输入；正文落 testcase 文件）

15 ID（9 正 + 6 负）+ `min_packets`/锚词 + fixture 常量 + 双通道断言基线 + 存量审计（testcase §2–§5/§8 全量）。

**A′ 候选（见 §14 缺口）**：`tls_neg_version_12`（层链拒 1.2）/ `tls_neg_role_server` / `tls_neg_sni_too_long`（254B）/ `tls_neg_alpn_too_long`（256B）/ `tls_neg_cert_not_object` / `tls_neg_cert_unknown_field` / `tls_neg_date_order`（not_after ≤ not_before）/ `tls_neg_san_too_long` / `tls_neg_dn_bad`（非法/缺 CN/未知属性）/ `tls_sni_rand_rejected`（string 面）/ `tls_alpn_single` / `tls_alpn_default_implicit`（显式写 version=tls1.3）/ `tls_cert_san_scalar` / `tls_record_fragmentation`（>16385 内层消息）/ `tls_ipv6` / `tls_default_port`（删 dst_port）/ `tls_abort_rst`。

## 14. 缺口立项清单（有缺口写「缺口立项」，不许空着）

| 缺口 | 内容 | 去向 |
|---|---|---|
| **G-TLS-1** | **`BuildCertDER` 不是确定性的（confirmed finding，本车道探针实测）**。① 同一进程内 40 个**不同**参数产出 **5 种** DER 长度（423/424/425/426/427）；② **同参数跨进程**默认 ref 在 **464↔466** 间浮动（12 次进程：464×11 / 466×1；40 次：464×26 / 466×14）；③ **同参数同进程**因 `certCache`（键 = `canonKey()` = 仅 5 个明文参数）命中而稳定，但 `cache.Load` 与 `cache.Store` 之间存在竞态窗口——**并发首次生成同参数**可产出两份不同 DER。**根因已定位**：`certgen.go:299-313` `fixedEntropyReader` 是 `ctr` 递增的**有状态**流（`SHA-256(seed‖ctr)`），而 Go 的 `ecdsa.Sign` 会按 `randutil.MaybeReadByte` **非确定性地**额外读 1 字节——**同一 `(seed, ctr)` 序列在是否插入该额外读取时产生不同 ECDSA nonce `k`**，而 P-256 签名中 `r = (kG).x mod n` 的**首字节为零的概率约 1/256**，DER 整数编码随之少 1 字节。**实证**：40 次相同模板的 `CreateCertificate` → 签名长度 `map[70:23 71:17]`，`reader.Read` 调用次数 1/2/3 混杂。**与代码注释矛盾**：`certgen.go:36-39` 自称"同参数 DER 逐字节相等，默认参数 465B"——**实测证伪**（默认 ref 实测 464/466，非 465；且非确定）。**与 cases notes 矛盾**：`tls-handshake-basic` notes 写"默认参数 DER **466B**（record 479/handshake 475/certs 471/cert 466）"——**本轮探针实测 DER 464 / record 477 / handshake 473 / listLen 469 / entryLen 466**（§9.2）。**线级实证（本车道最终一轮）**：跑完整链 `[ip,tcp,tls,http]` → `Builder.Build` 取真实帧，**跨 10 个新进程**测 f7：默认 cert → `record=477/flen=536` ×7、`record=479/flen=538` ×3；`tls-cert-static` → `record=570/flen=629` ×6、`record=569/flen=628` ×4。即**非确定性已传导到 wire 帧长**（不是仅 DER 内部差异）。**影响面（须写清，不得夸大）**：今日 15 例**无一断言 DER 长度或 record 长度**（只断言 `tls.handshake.type`/`x509ce.dNSName`/`x509sat.printableString`），故**今日套件不受影响**；受影响的是**任何未来想钉 DER/record 长度的断言**，以及"确定性"这一**代码注释与设计承诺**。 | **代码阶段**：① 修 `fixedEntropyReader` 为**无状态确定性流**（如 `HMAC-DRBG` 或对 `(seed, 读取序号)` 而非 `ctr` 计数，且让 `Read` 一次返回全部所需字节以规避 `MaybeReadByte` 的额外读取）；② 或改用 `crypto/rand` 之外的自实现确定性签名；③ 修后**必须**把 `certgen.go:36-39` 注释的"465B"与 cases notes 的"466B/479/475/471"一并改为**实测值**；④ 若选择钉长度，须同时钉 `record/handshake/listLen/entryLen` 四个层级。**本车道不改代码、不改 cases**（边界） |
| **G-TLS-2** | **层链不产 `close_notify`**：`planner.go:709-715` 的 close_notify（Alert record，`level=1, description=0`）在 legacy 路径有，**层链变换器不注入**——`layer_gen.go` 只注入 7 条握手 record + 内层事件，无 Alert 分支。故链上 TLS 会话**无优雅关闭通知**，TCP FIN 直接切断。**今日 15 例无一断言 Alert**（机读：`fields` 无 `tls.alert_message`） | A′ 补例 `tls_close_notify`（若补实现）；或**明确不解决**并在本文档声明（当前口径）。RFC 8446 §6.1 要求 close_notify，**当前实现与之不符**（诚实登记） |
| **G-TLS-3** | **`version`/`role` 非默认值的拒绝分支今日零用例**（`chain_planner.go:539/546` 有分支）；**显式写 `version="tls1.3"`** 亦无例（15/15 全不写） | A′ 补例 3 条（`tls_neg_version_12` / `tls_neg_role_server` / `tls_alpn_default_implicit`） |
| **G-TLS-4** | **record 明文 16385 分片上限今日无例**（`layer_gen.go:195` 有实现，`layer_gen.go:176-187` 有分片循环）；**空内层事件产空 record** 亦无例（`:166-175`） | A′ 补例（大内层消息 → 多 record；需内层终结层支持大 body） |
| **G-TLS-5** | **IPv6 今日零用例**（15/15 例 `layers[0].ip` 均为 IPv4，机读实测） | A′ 补例 `tls_ipv6`（offset 74；RFC 8446 §5.1 record 与地址族解耦，字节不变） |
| **G-TLS-6** | **`key_type` 只支持 `ecdsa-p256`**（`validate_layers.go:1117` / `certgen.go:170`）；`rsa-2048`/`rsa-4096`/`ecdsa-p384` 拒绝。RSA 需嵌入固定测试私钥常量或确定性素数搜索（~秒级），无需求先不做（D-TLS-2 已登记） | **明确不解决**；`tls-cert-neg-keytype-value` 已覆盖拒绝面 |
| **G-TLS-7** | **RST 非正常结束补例**（§3.15② 后半）：`spec.TCP.RST` 在 legacy `planner.go:718-721` 有分支，**层链路径由 tcp 层承载**（本层零断言） | A′ 补例 `tls_abort_rst`（tcp 层能力，本层零断言） |
| **G-TLS-8** | **缺省端口今日无例**：tls 层 `FieldContract {"tcp.dst_port":"443"}`（`registry.go:1654`）→ 用户不写 `dst_port` 时补齐 443；15/15 例**全部显式写 443** | A′ 补例 `tls_default_port`（删 `dst_port`，断言 443） |
| **G-TLS-9** | **第三源未取到**：真实浏览器/OpenSSL 的 TLS 1.3 字节未抓包对照；RFC 条款号未逐条核对（§10.5 三路对照第②路） | 待确认：抓真实 TLS 1.3 会话对照 record/握手布局；确认前按实现钉、**不声称合规** |
| **G-TLS-10** | **`CheckProtoFlat` 无 tls 分支**（`strategy_convert.go:8625-8660` 实测）→ 顶层 `tls` 子映射 presence **不判死**；**无游离顶层键通用门** → presence 负例今日建了会真绿（假通过），**不建**。**顶层 `tls` 子映射迁层未做**（`strategy_convert.go:1541` 的 `case "tls"` 仍是 flat 载体）——D-TLS-1 §1 已裁定"本轮不迁"（链上参数本就由层 config 驱动，`layer_gen.go` 不读 `spec.TLS`，迁入无消费方） | **禁加单协议黑名单分支**（等框架级 unknown-key 白名单）；顶层 `tls` 子映射去向 = **明确不解决**（无消费方）+ 若未来引入消费方再迁 |
| **G-TLS-11** | **`TransformEvents` 双语义不一致**：`LayerSchema.TransformEvents`（`schema.go:109`）只有 `http` 用到（`registry.go:104`）；tls 的变换器标记**只由生成器接口方法**提供（`layer_gen.go:44`），registry **未声明**。`assertEventWiring` 查生成器接口（`chain_planner_chain.go:247`）故**当前无功能影响**，但两处语义漂移（schema 字段成死字段，或 tls 漏声明） | 代码阶段裁定：schema 字段补声明 tls，或删除该死字段 |
| **G-TLS-12** | **结果文档过期（tracked 产物）**：`trafficgen/docs/protocol-pcap-test/tls.md` 写 `Cases: 15 — pass 15, fail 0, error 0`，末次提交 `793dfee`（**2026-09-19**）。**判死提交 `0417be5` = 2026-09-13**，故 `793dfee` **晚于**判死提交 → **不落入"早于判死提交"的过期口径**（与 pcep G-PCEP-11 / opcua G-OPCUA-10 不同）。**但**：① `trafficgen/docs/protocol-pcap-test/tls/` 目录**不存在**（`ls` 实测 `No such file or directory`）——**0 个 pcap 留档**；② 该目录下**全仓 0 个 `.pcap` 文件**（`find … -name '*.pcap' \| wc -l` = 0）。故该 15/15 **数字未经今日复跑证实，不得作为"今日已复跑"依据**；本车道**未跑**该套件，**不以任何形式**引用该产物作为套件可跑证据 | **代码阶段**（P5 重跑套件后重生成该产物）；本版**不删不改**（tracked 产物）。口径与 pcep G-PCEP-11 一致，但**登记理由不同**（此处是"无 pcap 留档 + 未今日复跑"，**不是**"早于判死提交"） |
| **G-TLS-13** | **`tls-http-inner` 与 `tls-handshake-basic` 的 frames 断言 offset 口径需复核**：两例都断 `offset 59` 明文起点，但 `tls-http-inner` 的 `record_len=62`（探针实测）而 notes 未写 record 长度；`tls-handshake-basic` 的 notes 写 f11 `len 53=0x35` / f12 `len 38=0x26`，**与探针实测一致 ✓** | A′ 收窄：给 `tls-http-inner` 补 record 长度断言（62=0x3e，探针实测） |
| **G-TLS-14** | **`has_payload` 在 tls 上是弱断言**：`pcaptest/verify.go` 的 `checkHasPayload` **无 tls 专用分支**（机读：分支列表含 coap/iec104/dameng/cql/drda/thrift/openwire/ams/gnutella/nmea/swarm/postgresql/igmp/ospf/pim，**无 tls**）→ 走通用帧长启发式（帧长 > 阈值）。本协议帧普遍 >80B（f4 215 / f7 536 / f11 112），故 `has_payload=true` 实质是"存在大于阈值的帧"，**不能证明"存在 TLS ApplicationData record"**——而设计 §3.8 的委托语义恰恰是"内层事件被包成 record"。**5 例正例带 `has_payload`**（#1/#2/#9/#10 等） | **代码阶段**：给 `verify.go` 加 tls 分支（断言存在 `tls.record.content_type=23` 的 record，或 `tcp.len>0` 且 record 结构自洽——postgresql/nmea 同款口径）。本车道不改 tools |
| **G-TLS-15** | **9 个正例全部只写 `min_packets`，无一写 `packet_count`**（机读实测）——与 101-opcua（10 正例全带精确 `packet_count`）**口径不一致**。单流例 `min_packets=16` 与探针实测 16 相等，但**语义是下界**（多出帧不判失败）；多流例 `min_packets=32` 同理。**风险**：帧数漂移（如某天多出 1 帧）不会被任何用例捕获 | **代码阶段**：单流 9 例中 7 例可收窄为 `packet_count=16`（探针实测稳定 16 帧）；多流 4 例因调度交织保留 `min_packets`（或加 `packet_count=32` 若调度确定）。**本车道不改 cases** |
| **G-TLS-16** | **动态 `tcp.src_port` 的 list 值是字符串**（机读 5 例：`{"strategy":"list","list":["41001","41002"]}` 等，值均为 `"41001"` 形**字符串**而非数字）。**本车道未验证字符串端口值的解析路径**（`checkDynEndpoints` 的 isPort 解析对字符串的接受度、以及 `resolveLayerTuple` 回填 `spec.SrcPort` 的类型转换）。**风险**：若字符串端口未被正确解析，多流例的"同序号域对齐"（41001↔a.com）可能不成立 | **代码阶段**：验证字符串端口值路径（或改 cases 为数字值）。本车道不改 cases |

## 15. 修订记录

- v1.0.0（2026-09-29）：批次二文档车道 as-built 定稿。**门1 §1–§14 十四行对照表**（§12，含 §1/§3/§12 三行强制展开）；§0 特殊性三件事（底座契约 10 家依赖 / 只实现 1.3 client / 字节漂移口径）；§3 线格式逐字段（record 层/握手头/CH/SH/Cert/AppData/证书生成器，含长度公式与**探针实测锚定值**）；五层覆盖（§4）；§7 负例锚词表（6 类入例 + 22 未入例）；§9.2 **探针实测表**（16/32 帧、record 长度、DER 字节级）；§10 八项矩阵 + 子表①②③（24 格 / 26 行 / 17 行逐格重数）；§11 as-built 代码设计；**缺口 G-TLS-1…G-TLS-16**（其中 **G-TLS-1 为 confirmed finding**——`BuildCertDER` 非确定性，探针实测 + 根因定位 + 与注释/notes 矛盾）。**未改任何代码、cases JSON、tools**。自审见下。
