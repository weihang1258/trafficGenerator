# #119 tls（TLS 1.3）测试用例契约

> 版本：v1.0.0（as-built 定稿；批次二文档车道）
> 日期：2026-09-29
> 配套设计：`docs/protocol-designs/119-tls-design.md` v1.0.0
> 机器契约：`trafficgen/test/protocol_pcap/cases/tls.json`（**15 例，权威**；ID/顺序/包数/断言与本文逐条一致，机读实测）
> 白话一句：**十五条检查：九条看"信封写得对不对"（握手七件套、SNI/ALPN、套娃、证书、逐流变体），六条看"胡来能不能被拦下"（扁平键、静态复制、关字段动态、非法枚举、坏日期）。**

## 1. 测试原则和形状基线

用例从设计 §3–§9 逐项派生，共 **15 个唯一语义 ID：9 正 + 6 负**。派生规则：设计 §3 每个消息/字段条款、§5 每个自动派生行为、§7 每行错误处理在本文有对应断言；断言不得超出设计声明范围。**一个用例只验证一个协议行为**。

**形状基线（2026-09-29 机读实测）**：

| 项 | 实测 |
|---|---|
| 例数 | **15** |
| 顶层键（10 例） | `{expect, id, proto, spec_json, summary}` |
| 顶层键（5 例） | 上述 + `strategy_fc`（多流） |
| `spec_json` 顶层键 | **`{layers}` ×14**；**1 例（`tls-neg-flat`）多 `src_ip`**——**负例执法对象本身**（§4 负例形状，非残留） |
| 链形 | **`[ip,tcp,tls,http]` ×15**（唯一链形，无变体） |
| 负例 `expect` 键集合 | **严格两键 `{expect_error, error_contains}` ×6**（无 `notes`，与 92-moxa 严格口径一致） |
| 正例 `packet_count` | **0/9**（**全部只写 `min_packets`**——诚实登记，见 §3 口径注） |

**输出契约（pcap/NIC 双输出）**：两路径共用同一 cases JSON 与断言集（`tcp.dstport`/`tcp.srcport`/`tcp.flags`、`tls.*`、`x509*`、frames hex offset 59）；NIC 经 tcpdump 捕获（`nic_capture` 用例级开关）；**不设仅单路径可用的断言**。

**TSHARK 基线（本机 3.6.14 实测）**：`tshark -G fields` 中 **`tls.*` 302 字段**（机读）；本协议 15 例用到的 6 个字段全部存在（机读逐条核验）：

| 字段 | tshark 名称 | 进制/形态 |
|---|---|---|
| `tls.handshake.type` | Handshake Message Type | **十进制串**（`1`/`2`/`8`/`11`/`15`/`20`） |
| `tls.record.content_type` | Content Type | **十进制串**（`22`/`23`） |
| `tls.handshake.extensions_server_name` | Server Name | 字符串 |
| `tls.handshake.extensions_alpn_str` | ALPN Next Protocol | **逗号连接串**（`h2,http/1.1`） |
| `x509ce.dNSName` | dNSName | **逗号连接串**（多值聚合） |
| `x509sat.printableString` | printableString | **逗号连接串**（DN 各 RDN 值聚合） |

**断言基线**：15 例共 **26 条 `fields` 断言 + 3 条 `frames` 断言**（机读逐例 `fields` 数 14/4/0/0/1/1/1/0/1/2/1/1/0/0/0，相加 = **26**；`frames` 数 2/0/0/0/0/0/0/0/1/0/0/0/0/0/0，相加 = **3**）。**frame 断言全部落在 offset 59**（TLS record 头 5B 之后 = 明文起点）。

**动态字段禁止硬编码**：逐流变的值（SNI/SAN/DN）用 **`distinct_values` 聚合断言**（多流调度非确定，固定包位对逐流值无意义，`pcaptest/types.go:57-60` 语义）；**唯一例外** `tls-dyn-sni-fixed`（单流，值恒定 → `value` 精确断言）。

**包数约定（探针实测公式，设计 §9.1）**：单流 = 3（TCP 握手）+ 7（TLS 握手 record）+ 2（AppData）+ 4（FIN）= **16**；多流 = `N × 16`。**本协议正例全部用 `min_packets` 而非 `packet_count`**（见 §3 口径注）。

**保活/重试/RST 口径**：TLS 层链**无 PING 类保活**；**无 close_notify**（G-TLS-2，变换器不产 Alert record）；**无重试/重连**（单连接单会话）；**RST** 为框架 tcp 层能力，本协议层**零断言**（A′ G-TLS-7）；正例恒 FIN 优雅终止。

**`has_handshake`/`negotiated`/`terminates`/`has_payload` 的 harness 语义（机读 `pcaptest/verify.go`）**：

| 键 | 判定（`verify.go`） |
|---|---|
| `has_handshake` | `ExpectFirstFlag(pcap,"syn")`——**首包带 SYN**（`:156`） |
| `negotiated` | 至少一个 **SYN+ACK** 包（`:193`） |
| `terminates` | **末 3 包**中至少一个带 **FIN 或 RST**（`:163-176`） |
| `has_payload` | tls **无专用分支** → 走通用启发式（帧长代理）。**本协议帧普遍 >80B（最小 60B 的纯 ACK 段不判），故判定为"存在大于阈值的帧"**——**这是弱断言**（G-TLS-14 登记） |

## 2. 原子用例索引（15 ID = 9 正 + 6 负，顺序为权威）

| # | ID | 类型 | 覆盖（设计 §） | `min_packets`（JSON 权威） | `fields`/`frames` 断言数 |
|---:|---|---|---|---:|---|
| 1 | `tls-handshake-basic` | 正 | §3.4/§3.5/§3.6/§3.7/§3.8：1.3 全握手基线 + 内层 http 委托 | 16 | 14 / 2 |
| 2 | `tls-sni-alpn` | 正 | §3.5：SNI + ALPN 进 ClientHello / EE 回选首项 | 16 | 4 / 0 |
| 3 | `tls-neg-flat` | **负** | §7 N-1：顶层扁平键判死 | —（无） | 0 / 0 |
| 4 | `tls-neg-static-copy` | **负** | §7 N-2：静态复制拒绝（`flows=2`） | —（无） | 0 / 0 |
| 5 | `tls-dyn-sni-list` | 正 | §12.12：`sni` list 轮转（2 流） | 32 | 1 / 0 |
| 6 | `tls-dyn-sni-pattern` | 正 | §12.12：`sni` pattern 替换（2 流） | 32 | 1 / 0 |
| 7 | `tls-dyn-sni-fixed` | 正 | §12.12：`sni` fixed 对照端（单流） | 16 | 1 / 0 |
| 8 | `tls-neg-dyn-closed-version` | **负** | §7 N-3：`version` 关字段动态拒绝 | —（无） | 0 / 0 |
| 9 | `tls-http-inner` | 正 | §3.8：https 套娃（内层 `uri` 委托） | 16 | 1 / 1 |
| 10 | `tls-cert-static` | 正 | §3.7/§3.9：cert 标量全填 → 真 X.509 DER | 16 | 2 / 0 |
| 11 | `tls-cert-dyn-subject` | 正 | §12.12：`cert.subject` list 轮转（2 流） | 32 | 1 / 0 |
| 12 | `tls-cert-dyn-san` | 正 | §12.12：`cert.san` list 轮转（2 流） | 32 | 1 / 0 |
| 13 | `tls-cert-neg-dyn-keytype` | **负** | §7 N-4：`cert.key_type` 关字段动态拒绝 | —（无） | 0 / 0 |
| 14 | `tls-cert-neg-keytype-value` | **负** | §7 N-5：`key_type` 非法值 | —（无） | 0 / 0 |
| 15 | `tls-cert-neg-bad-date` | **负** | §7 N-6：坏日期 | —（无） | 0 / 0 |

**T-编号对照（沿 `docs/TEST_CASES.md` T-TLS-*，非本车道产物，仅供追溯）**：T-TLS-1 ≡ #1；T-TLS-2 ≡ #2；T-TLS-3 ≡ #3；T-TLS-4 ≡ #4；T-TLS-5 ≡ #5；T-TLS-6 ≡ #6；T-TLS-7 = **单测**（`TestTLSSNIDyn_StringSurfaceRejected`，无 JSON 例）；T-TLS-8 ≡ #8；T-TLS-9 ≡ #9；T-TLS-10 ≡ #10；T-TLS-11 = **隐式覆盖**（#1 的默认 cert，无独立 JSON 例）；T-TLS-12 ≡ #11；T-TLS-13 ≡ #12；T-TLS-14 ≡ #13；T-TLS-15 ≡ #14 + #15（一例拆二）。**序号以 cases JSON 顺序为权威**（JSON 中 #5/#6/#7 在 #8 之前）。

## 3. 正例逐项断言契约（最低断言集，实现期可增不可减）

**口径注（诚实登记，重要）**：9 个正例**全部只写 `min_packets`，无 `packet_count`**（机读实测）。单流例 `min_packets=16` 与探针实测 16 **相等**，但**语义是下界**——多出的帧不会被判失败。这是与 101-opcua（10 正例全带精确 `packet_count`）的**口径差异**，登记为 G-TLS-15。

**探针实测帧位（设计 §9.2，`/tmp/tgprobe` 直读帧字节，2026-09-29）**：单流恒 16 帧——f1/f2/f3 = TCP 握手（SYN/SYN-ACK/ACK）；f4–f10 = TLS 握手 7 条；f11/f12 = AppData 请求/响应；f13–f16 = FIN 四包。

### 3.1 `tls-handshake-basic`（min_packets 16）

链 `[ip(10.0.0.1→20.0.0.1), tcp(src 12345→443), tls{}, http{}]`。

- `has_handshake=true`、`negotiated=true`、`terminates=true`、`has_payload=true`、`min_packets=16`。
- **14 条 fields**（机读逐条）：f1 `tcp.flags=0x002`（SYN）+ `tcp.dstport=443`；f2 `tcp.flags=0x012`（SYN-ACK）；f3 `tcp.flags=0x010`（ACK）；f4 `tls.handshake.type=1`（ClientHello）+ `tls.record.content_type=22` + `tls.handshake.extensions_alpn_str=h2,http/1.1`；f5 `tls.handshake.type=2`（ServerHello）；f6 `tls.handshake.type=8`（EncryptedExtensions）+ `tls.handshake.extensions_alpn_str=h2`（**回选首项**，设计 §5 规则 3）；f7 `tls.handshake.type=11`（Certificate）；f8 `tls.handshake.type=15`（CertificateVerify）；f9 `tls.handshake.type=20`（server Finished）；f10 `tls.handshake.type=20`（client Finished）。
- **2 条 frames**：f11 offset 59 `47 45 54 20 2f 20 48 54 54 50 2f 31 2e 31`（`GET / HTTP/1.1`）；f12 offset 59 `48 54 54 50 2f 31 2e 31 20 32 30 30`（`HTTP/1.1 200`）。
- **包数证据**：3 + 7 + 2 + 4 = 16 ✓（探针实测 16）。
- **握手类型序证据**：f4→f10 的 type 序列 `1,2,8,11,15,20,20` = 设计 §3.4 表的 7 条 record 逐条对应 ✓。
- **record 长度（探针实测，设计 §9.2）**：f4 `156`（以太 215）；f5 `90`（149）；f6 `15`（74）；**f7 `477` 或 `479`（以太 536 或 538——非恒定，G-TLS-1）**；f8 `72`（131）；f9/f10 `36`（95）；f11 `53`（112）；f12 `38`（97）。**今日无长度断言**（A′ 候选，**受 G-TLS-1 阻塞**——须先修确定性）。
- **notes 是「其中一支」而非常量（登记）**：notes 写"默认参数 DER **466B**（record 479/handshake 475/certs 471/cert 466）"——探针实测**两支**：支 A `DER 464 / record 477 / handshake 473 / listLen 469 / entryLen 466`（跨 10 进程 ×7）；支 B `DER 466 / record 479 / handshake 475 / listLen 471 / entryLen 468`（×3）。**notes 描述的是支 B**（数字与实测支 B 一致 ✓），但**它不是唯一取值**——`BuildCertDER` 非确定（**G-TLS-1**）。**该组数字今日不可作为常量断言**。

### 3.2 `tls-sni-alpn`（min_packets 16）

链 `[ip, tcp(src 12346→443), tls{sni:"example.com", alpn:["h2","http/1.1"]}, http{}]`。

- **4 条 fields**：f4 `tls.handshake.type=1`；f4 `tls.handshake.extensions_server_name=example.com`；f4 `tls.handshake.extensions_alpn_str=h2,http/1.1`；f6 `tls.handshake.extensions_alpn_str=h2`。
- **SNI 进扩展的证据**：设计 §3.5 扩展块序 1（`0x0000`，`list_len(2) + name_type(1) + name_len(2) + name`，RFC 6066 §3）。**实测长度差**：f4 `record_len` 由默认 **156 → 176**（**+20B** = SNI 扩展 16B + 扩展块长度字段差），以太帧 215 → **235**（探针实测）。
- **ALPN 回选首项证据**：f6 EncryptedExtensions 取 `alpn[0]=h2`（设计 §5 规则 3，`layer_gen.go:125`）——**注意 f6 只回选一项**，与 f4 的双协议列表形成对照。
- notes 称"sni 标量经层 config 原生通道进生成器（零新增代码）"——与实现一致（`layer_gen.go:98` 直读 `cfg["sni"]`）✓。

### 3.3 `tls-dyn-sni-list`（min_packets 32）

链 `[ip(192.0.2.10→198.51.100.20), tcp{dst_port:443, src_port:{list:["41001","41002"]}}, tls{sni:{list:["a.com","b.com"]}}, http{}]` + `strategy_fc{flows:2}`。

- **1 条 fields**：f4 `tls.handshake.extensions_server_name` **`distinct_values=["a.com","b.com"]`**（聚合断言，包位被忽略）。
- **多流证据**：`min_packets=32` = 2 × 16 ✓。**逐流 SNI 实测（本车道探针）**：flow 0 含 `a.com` 不含 `b.com`；flow 1 含 `b.com` 不含 `a.com` —— **逐流解析确实生效**（`translateTLSSNI`，设计 §12.12）。
- **同序号域对齐证据**：`tcp.src_port` list `["41001","41002"]` 与 `sni` list 同 `i` 域 → 41001↔a.com、41002↔b.com（notes 声明）。
- **`tcp.src_port` 用 list 的理由（notes 声明）**：绕过 `static-copy` 门（设计 §7 N-2）——全静态四元组 + `flows>1` 会被拒。
- **⚠ 形状注**：`tcp.src_port` 的 list 值是 **字符串** `"41001"`（非数字）。机读 5 例动态端口全为此形。**本车道未验证字符串端口值的解析路径** → G-TLS-16 登记。

### 3.4 `tls-dyn-sni-pattern`（min_packets 32）

链同上，`tcp.src_port{list:["41002","41003"]}`，`tls{sni:{strategy:"pattern", pattern:"host{n}.com", range:[1,2]}}`，`strategy_fc{flows:2}`。

- **1 条 fields**：f4 `tls.handshake.extensions_server_name` **`distinct_values=["host1.com","host2.com"]`**。
- **pattern 算法同真相证据**：`{n}` 替换走 `genStringValue`（`shard_router.go:58`），与四元组 pattern **同算法**（设计 §12.12）。
- **与 #5 的对照**：`list` 是枚举轮转，`pattern` 是模板替换——两例覆盖 string 面的两个分支。

### 3.5 `tls-dyn-sni-fixed`（min_packets 16）

链 `[ip, tcp(src 41003→443), tls{sni:{strategy:"fixed", value:"a.com"}}, http{}]`（**单流**）。

- **1 条 fields**：f4 `tls.handshake.extensions_server_name` **`value="a.com"`**（精确值，非 distinct——单流恒定）。
- **fixed 是动态形状的退化对照端证据**：对象写法、标量效果；**单流 fixed 不触发 static-copy 门**（notes 声明，设计 §7 N-2 只查 `flows>1`）。

### 3.6 `tls-http-inner`（min_packets 16）

链 `[ip, tcp(src 40000→443), tls{}, http{method:"GET", uri:"/tls-inner", version:"1.1"}]`。

- **1 条 fields**：f4 `tls.handshake.type=1`。
- **1 条 frames**：f11 offset 59 `47 45 54 20 2f 74 6c 73 2d 69 6e 6e 65 72`（`GET /tls-inner`）。
- **内层委托证据**：内层 http 请求字节经 tls 包成 ApplicationData record（`content_type=23`，设计 §3.8）。**探针实测**：f11 `record_len=62`（`0x3e`，以太 121），明文 `GET /tls-inner HTT…`；f12 `record_len=38`，明文 `HTTP/1.1 200 OK`。
- **与 #1 的对照**：唯一差异是内层 `uri`（`/` vs `/tls-inner`）→ f11 record 长度 53 → 62（**+9B = uri 长度差**），握手 7 条完全一致（探针实测两例 f4–f10 逐帧等长）——**证明"tls 不重建应用层，只包壳"**（设计 §0.1 变换器契约）。
- **A′ 候选**：本例 notes 未写 record 长度，可补 `62=0x3e` 断言（设计 G-TLS-13）。

### 3.7 `tls-cert-static`（min_packets 16）

链 `[ip, tcp(src 12347→443), tls{cert:{subject:"CN=api.test.local,O=TestOrg,OU=QA,L=Beijing,ST=Beijing,C=CN", san:["api.test.local","www.test.local"], key_type:"ecdsa-p256", not_before:"2026-01-01T00:00:00Z", not_after:"2036-01-01T00:00:00Z"}}, http{}]`。

- **2 条 fields**：f7 `tls.handshake.type=11`；f7 `x509ce.dNSName="api.test.local,www.test.local"`（**逗号连接串**，多 SAN 聚合）。
- **cert 明文上 wire 的证据**：`certgen.go` 从用户配置产真 X.509 DER（设计 §3.9）。**探针实测（本车道）**：f7 `record_len=569 或 570`（以太 **628 或 629**，非恒定——G-TLS-1），内嵌 DER **556 或 557B**，`x509.ParseCertificate` 回读 `CN=api.test.local` / `O=[TestOrg]` / `OU=[QA]` / `L=[Beijing]` / `ST=[Beijing]` / `C=[CN]` / `SAN=[api.test.local www.test.local]` / `nb=2026-01-01` / `na=2036-01-01` —— **用户配置逐字段上 wire** ✓。
- **与默认 cert 的对照**：默认（#1）DER 464–466B / record 477–479 / 以太 536–538；本例 DER 556–557B / record 569–570 / 以太 628–629（**约 +92B**）——**证明 cert 配置真实改变 wire 长度**（设计 §3.7 表）。**两端的浮动幅度（±2B）小于配置差（~92B）**，故对照结论不受 G-TLS-1 影响。
- **`key_type` 显式写 `ecdsa-p256`**（唯一支持值，设计 G-TLS-6）。

### 3.8 `tls-cert-dyn-subject`（min_packets 32）

链 `[ip, tcp{dst_port:443, src_port:{list:["41011","41012"]}}, tls{cert:{subject:{list:["CN=a.test,O=TrafficGen Test Lab,C=CN", "CN=b.test,O=TrafficGen Test Lab,C=CN"]}}}, http{}]` + `strategy_fc{flows:2}`。

- **1 条 fields**：f7 `x509sat.printableString` **`distinct_values=["TrafficGen Test Lab,a.test,TrafficGen Test Lab,a.test", "TrafficGen Test Lab,b.test,TrafficGen Test Lab,b.test"]`**。
- **DN 整串替换语义证据**：`cert.subject` 是**整 DN 串**替换（F1 决策），非逐属性替换（设计 §12.12）。
- **tshark 字段选择说明（notes 声明）**：CN 经 `x509sat.printableString` 聚合——**该字段含 O 值**（tshark 无独立 CN 项），故 distinct 值形如 `"TrafficGen Test Lab,a.test,TrafficGen Test Lab,a.test"`（O 与 CN 各出现两次，因 subject 与 issuer 自签同值）。
- **同序号域对齐**：41011→a.test、41012→b.test（notes 声明；探针已验证同机制在 #5 生效）。

### 3.9 `tls-cert-dyn-san`（min_packets 32）

链同上，`src_port{list:["41013","41014"]}`，`tls{cert:{san:{list:["a.test","b.test"]}}}`。

- **1 条 fields**：f7 `x509ce.dNSName` **`distinct_values=["a.test","b.test"]`**。
- **与 #8 的对照**：subject 是 DN 整串，san 是**域名串**（list 端点是域名，`checkDynEndpoints` 的 isIP/isMAC/isPort/isTTL 全假 → 只判非空，设计 §12.12）。

## 4. 负例契约

负例必须在 **validate_layers / chain_planner 结构性校验 / 动态形状门** 阶段失败并传播为 task error，不得产生成功 PCAP、`completed/0 packet` 或只剩 TCP 外壳的假成功。锚词与设计 §7 表一一对应、同序（代码逐字）：

| ID | 故障输入（机读实测） | JSON `error_contains` | 代码文案（逐字） | 代码位置 |
|---|---|---|---|---|
| `tls-neg-flat` | `spec_json` 顶层 `"src_ip":"10.0.0.1"`（+ 完整 layers） | `rejects flat config field src_ip` | `protocol tls rejects flat config field src_ip (use a layers chain: …)` | `strategy_convert.go:8634` |
| `tls-neg-static-copy` | 全静态标量四元组 + `strategy_fc{flows:2}` | `static four-tuple` | `layers pin a static four-tuple but flows > 1: …` | `schema/semantic.go:285` |
| `tls-neg-dyn-closed-version` | `tls.version={strategy:"list", list:["tls1.3","tls1.2"]}` | `does not support dynamic` | `… does not support dynamic` | `validate_layers.go:1004` |
| `tls-cert-neg-dyn-keytype` | `tls.cert.key_type={strategy:"list", list:["ecdsa-p256"]}` | `does not support dynamic` | `… does not support dynamic` | `validate_layers.go:1046` |
| `tls-cert-neg-keytype-value` | `tls.cert.key_type="rsa-2048"` | `not supported yet` | `tls chain: cert.key_type "rsa-2048" not supported yet (only "ecdsa-p256")` | `validate_layers.go:1117`（layers）/ `certgen.go:170`（tls 镜像） |
| `tls-cert-neg-bad-date` | `tls.cert.not_before="yesterday"` | `invalid RFC3339 timestamp` | `tls chain: cert.not_before "yesterday" invalid RFC3339 timestamp: …` | `validate_layers.go:1126` / `certgen.go:174` |

**锚词口径**：`error_contains` 是**子串**判定；6 例均命中代码文案 ✓。

**负例原子性**：每例**单一故障注入**，单次执行不得混注。**6 例 `expect` 键集合均为严格两键 `{expect_error, error_contains}`**（机读实测，**无 `notes`**——优于 101-opcua 的三键口径）。

**负例纯净性**：`expect_error=true` 用例**不得混入**与失败任务无关的成功包结构断言——6 例 `fields`/`frames` 断言数均为 **0** ✓（机读）。

**#3 的形状注（判死负例靶子）**：`tls-neg-flat` 的 `spec_json` 顶层**同时**有 `layers` 与 `src_ip`——这是**执法对象本身**（层链 + 顶层旧键混用形），**不是残留**。收官自查行「非负例顶层键 = 0」**已成立**（设计 §12.1：14 例非负例的 `spec_json` 顶层仅 `{layers}`）。**门 2-1 顶层旧键扫描须豁免本例**（按 `error_contains` 含 `flat config field` 豁免，与 `pipe_gate.sh` 的 `top-level` 豁免同款机制）。

**未入用例的拒绝分支（A′ 立项，不得冒充已覆盖）**：见设计 §7 表（22 条），摘要：`tls chain: version %q not supported…`（`chain_planner.go:539`）/ `role %q not supported…`（`:546`）/ `SNI length %d exceeds max 253 bytes`（`:552`）/ `ALPN protocol name length %d exceeds max 255 bytes`（`:560`）/ `cert must be an object`（`:574`）/ `cert: unknown field %q`（`:601`）/ `cert.%s must be a string`（`:585`）/ `cert.san must be a string or string array`（`:596`）/ `not_after must be after not_before`（`validate_layers.go:1135`）/ `cert.san entry length %d exceeds max 253 bytes`（`:1141/1147`）/ `cert.subject %q invalid DN`（`:1174`）/ `has empty value for %q`（`:1178`）/ `has unknown attribute %q`（`:1185`）/ `missing CN`（`:1189`）/ legacy 侧 7 条（`planner.go:166/177/185/190/198/201/207`）/ `cannot transform terminal events`（`chain_planner_chain.go:249`）/ `missing tls carrier`（sstp 载体）。

**不得误报的合法协议事件**：空 `tls:{}`（#1 等 8 例）；多流（#5/#6/#8/#9）；逐流 SNI/cert（#5/#6/#8/#9）；自定义 DN/SAN（#7）；cert 单键缺席（填默认，合法）；ALPN 缺省（默认双协议）。

## 5. 覆盖与对账

### 5.1 三源回指行

RFC 8446/5246/6066/7301/5280/1035/6528/879（设计 §10）+ 本设计 §3/§11 + **本车道探针实测帧字节**（设计 §9.2，`/tmp/tgprobe`）→ **15 ID**（本契约 §2）。第三源"真实 TLS 栈行为"当前**未取到** → G-TLS-9（按设计 §10.5 不写死进实现）。

**15 ID 逐项回指（§9.5 要求）**：#1←设计 §3.4/§3.5/§3.6/§3.7/§3.8；#2←§3.5；#3←§7 N-1；#4←§7 N-2；#5←§12.12；#6←§12.12；#7←§12.12；#8←§7 N-3；#9←§3.8；#10←§3.7/§3.9；#11←§12.12；#12←§12.12；#13←§7 N-4；#14←§7 N-5；#15←§7 N-6。

### 5.2 对账两行 + 清单出处声明

- **清单出处声明**：本清单来源 = **RFC 系列公开语义 + 仓库落码反推 + 本车道探针实测帧字节 + tshark 3.6.14 字段表**，**非纯规范反推**（RFC 条款号未逐条核对 → G-TLS-9；真实 TLS 栈字节未对照 → 同）。
- **对账两行**：**要求逻辑点总数 = 67**（八项 8 行 + 矩阵 24 格 + 变体 26 行 + 商业映射 17 行 = 75；**修正**：8 + 24 + 26 + 17 = **75**）；**用例覆盖数 = 15 ID 对应**——逐表：八项**覆 4**（设计 §10.1：连接模型/命令消息表/状态机/字段表，其余 4 项含缺口）/ 矩阵**覆 15**（§10.2 重数）/ 变体**覆 17**（§10.3 重数）/ 商业**覆 9**（§10.4 重数）= **45**；**不适用 = 14**（八项 1 + 矩阵 1 + 商业 8 + 变体 0 = 10；**修正**：八项 1 + 矩阵 1 + 商业 8 = **10**）；**开放立项 = 20**（八项 3 + 矩阵 8 + 变体 9 = **20**）。45 + 10 + 20 = **75** ✓
  **粒度声明**：行/格粒度每点 1 计；G-TLS-1…G-TLS-16 与 G-TLS-14/15/16 不折进 75。**反查全绿 ≠ 覆盖全**。逐表重数见设计 §10.1（八项 8 = 覆 4 + 立项 3 + 不适用 1）/§10.2（24 格 = 覆 15 + A′ 8 + 不适用 1）/§10.3（26 行 = 覆 17 + 立项 9）/§10.4（17 行 = 覆 9 + 不适用 8）。
- **门3 抽查候选**：最复杂用例 = **#1 `tls-handshake-basic`**（16 帧：3 TCP 握手 + **7 条 TLS 握手 record**（CH/SH/EE/Cert/CV/Fin×2）+ 2 AppData（内层委托）+ 4 FIN；交织维度 = record 类型(3)×方向(2)×握手类型(6)×内容(证书/明文)）；**建议门3 抽 #1 + #11**（`tls-cert-dyn-subject` 补逐流证书面）。

### 5.3 存量审计摘要

**15/15 保留，0 改写，0 作废**（见 §8.3 逐条去向）。

## 6. P3 固定动作（CORE_MEMORY 管线：§3.15 三项 + A′/B′ 两分类 + 3.14 豁免）

### 6.1 §3.15 三项逐项一例或立项

| # | 三项 | 本协议对照 | 用例/立项 |
|---|---|---|---|
| ① | 同连接/同流内的多轮操作 | 单 TCP 连接内：7 条握手 record + 2 条 AppData（请求/响应）——**多轮**；多流由 `strategy_fc` 承载（#5/#6/#11/#12） | 已覆 #1/#9（同连接多轮） |
| ② | 非正常结束 | 正常 FIN 四包（全正例）；**无 close_notify**（G-TLS-2）；RST 为框架 tcp 层能力 | 已覆（FIN）；RST **A′ 立项**（G-TLS-7，本层零断言）；**close_notify 缺口** G-TLS-2 |
| ③ | 长保活 | TLS 层链**无保活机制**（无 PING/heartbeat；session ticket 未实现） | **显式不适用**（层链只跑一次握手 + 一次数据交换即 FIN） |

无空项：① 有已覆例；② 有已覆例 + 1 条 A′ 立项 + 1 条缺口；③ 显式不适用 + 理由。

### 6.2 A′/B′ 两分类表

**A′（P4 接线）**：

| 类 | 内容 | 落点 |
|---|---|---|
| 版本/角色拒绝面 | 层链拒 1.2/1.1/1.0、拒 role=server、显式 version=tls1.3 | G-TLS-3 |
| 长度上限面 | SNI 254B、ALPN 256B、SAN 254B | G-TLS-3 |
| cert 形状面 | cert 非对象、未知子键、子键非串、san 形状错、日期序错、DN 非法/缺 CN/未知属性 | 设计 §7 表 |
| string 面拒绝 | `sni` inc/rand（锚词 `not supported for string field`） | 设计 §10.3 行 7 |
| 分片面 | record 明文 >16385 分片；空内层事件产空 record | G-TLS-4 |
| 地址族面 | IPv6（offset 74） | G-TLS-5 |
| 端口面 | `dst_port` 缺省补齐 443 | G-TLS-8 |
| ALPN 面 | 单协议；缺省隐式 | 设计 §10.3 行 11 |
| cert 面 | `san` 标量单串 | 设计 §10.3 行 22 |
| 非正常结束 | `tcp.rst` 补例 | G-TLS-7 |
| 长度断言面 | f4/f5/f7 record 长度（**受 G-TLS-1 阻塞**，须先修确定性） | G-TLS-1/G-TLS-13 |
| close_notify 面 | Alert record（若补实现） | G-TLS-2 |

**B′（框架面）**：`CheckProtoFlat` tls 分支 + 游离顶层键通用门（G-TLS-10，等框架级 unknown-key 白名单，不单独立项）/ `TransformEvents` 双语义（G-TLS-11）/ 顶层 `tls` 子映射迁层（G-TLS-10，明确不解决）/ `has_payload` 无 tls 专用分支（G-TLS-14）/ 正例 `packet_count` 口径（G-TLS-15）/ 字符串端口值路径（G-TLS-16）。进设计 §14。

### 6.3 3.14 豁免边界审计

**有长连接载体（TCP）→ `sessions[]` 不豁免的判定不适用**：tls 层 schema **无 `sessions` 键**（机读 registry Fields 5 键），多流由 `strategy_fc` 承载——**形态差异已声明**（设计 §12.3）。**多流并发**：由策略级 `strategy_fc {"flows": N}` 承载（#5/#6/#11/#12 用 `flows:2`）。**单包多载荷** = **不适用**（TLS record 一 record 一载荷；多条 record 是多个 record 不是单包多载荷，如实声明）。

## 7. 实现后执行建议

1. **P4 顺序**：①**先修 G-TLS-1**（`fixedEntropyReader` 确定性）——它是**唯一 confirmed finding**，且阻塞所有长度断言；②补 A′ 版本/角色/长度拒绝例（G-TLS-3）；③补 A′ IPv6/缺省端口/分片例（G-TLS-5/8/4）；④补 record 长度断言（修完 ① 后）；⑤裁定 G-TLS-2（close_notify 补实现或明确不解决）；⑥全量复跑。**本协议无 §1 迁移步骤**（顶层零残留，除 1 例判死靶子）。
2. **实测顺序**：先 #1（7 条握手 type 序列 + 16 帧基线），再 #2（SNI +20B / ALPN 回选首项），再 #10（cert DER ~557B / 以太 ~629），再 #5/#6（逐流 SNI），最后 #9（内层 uri +9B）。
3. 二进制与 HEAD 同代确认（门2③：`find trafficgen -name '*.go' -newer <server-binary>` 无输出）；门2② 全量（`CASE_PROTO=tls` 全量不是增量）；门2④ 反查绿后进 P6。
4. 任何 RFC 条款号的具体引用须有规范原文证据（G-TLS-9 纪律）。

## 8. 存量审计（15 例逐条去向）

### 8.1 存量实测面（2026-09-29 机读）

`cases/tls.json` **15 例**：9 正（`min_packets` 16/16/32/32/16/16/16/32/32）+ 6 负（`expect` 严格两键）；**15/15 `spec_json` 顶层仅 `{layers}`**（除 `tls-neg-flat` 的判死靶子 `src_ip`）；**链形 15/15 = `[ip,tcp,tls,http]`**；`fields` 断言 26 条 / `frames` 断言 3 条（**全部 offset 59**）；`strategy_fc` 5 例（全 `{"type":"flows","value":2}`）。

### 8.2 现状矛盾点（P4 前诚实登记）

1. **G-TLS-1 confirmed**：`BuildCertDER` **非确定**（探针实测：同参数跨进程 464↔466；同进程不同参数 423–427 五种长度；根因 = `fixedEntropyReader` 有状态流 + Go `ecdsa.Sign` 的 `MaybeReadByte` 额外读取）。与 `certgen.go:36-39` 注释"逐字节相等，465B"及 `tls-handshake-basic` notes"466B"**双重矛盾**。**今日 15 例不受影响**（无长度断言）。
2. **notes 数字不可复现**：`tls-handshake-basic` notes 的 DER 466 / record 479 / handshake 475 / certs 471 —— 探针实测 **464 / 477 / 473 / 469**（entryLen 466 恰好相同，**巧合**）。
3. **正例无精确包数**：9 正例全用 `min_packets`（101-opcua 的 10 正例全用 `packet_count`）——**口径差异**（G-TLS-15）。单流例 16 与实测相等，但语义是下界。
4. **层链能力面窄于 legacy**：只 1.3/client；AlertPath/PSK/0-RTT/OCSPStapling/close_notify 全无（设计 §0.2/G-TLS-2）——**用例不得声称这些面已覆盖**。
5. **IPv6 零用例**（15/15 IPv4）——G-TLS-5。
6. **`has_payload` 是弱断言**（通用帧长启发式，tls 无专用分支）——G-TLS-14。
7. **字符串端口值未验证**：5 例动态 `tcp.src_port` 的 list 值为**字符串**（`"41001"`）——G-TLS-16。
8. **结果文档无 pcap 留档**：`trafficgen/docs/protocol-pcap-test/tls.md` 写 15/15 pass，末次提交 `793dfee`（2026-09-19，**晚于**判死提交 `0417be5` 2026-09-13），但 `trafficgen/docs/protocol-pcap-test/tls/` **目录不存在**、全仓该目录下 **0 个 `.pcap`**——数字**未经今日复跑证实**（G-TLS-12，口径与 pcep G-PCEP-11 一致但**登记理由不同**）。
9. **存量未覆盖**：版本/角色非默认、SNI/ALPN/SAN 超长、cert 形状错 5 类、日期序、DN 非法 4 类、string 面 inc/rand、分片、IPv6、缺省端口、RST、close_notify —— **今日零用例**（A′ 补）。

### 8.3 逐条去向表（15 行）

| 存量 id | T-编号 | 去向 | 改写动作（P4） |
|---|---|---|---|
| `tls-handshake-basic` | T1 | **保留** | 形状已合规；**notes 的 DER/record 数字须按 G-TLS-1 修后重钉**；可补 record 长度断言 |
| `tls-sni-alpn` | T2 | **保留** | 形状已合规；可补 SNI 扩展 +20B 断言 |
| `tls-neg-flat` | T3 | **保留** | 判死靶子形状正确；门 2-1 须按锚词豁免 |
| `tls-neg-static-copy` | T4 | **保留** | 形状已合规 |
| `tls-dyn-sni-list` | T5 | **保留** | 形状已合规；可补 `tcp.srcport` distinct 断言（G-TLS-16） |
| `tls-dyn-sni-pattern` | T6 | **保留** | 形状已合规 |
| `tls-dyn-sni-fixed` | T5 对照端 | **保留** | 单流精确值断言，正确 |
| `tls-neg-dyn-closed-version` | T8 | **保留** | 形状已合规 |
| `tls-http-inner` | T9 | **保留** | 可补 f11 record 长度 62 断言（G-TLS-13） |
| `tls-cert-static` | T10 | **保留** | 可补 DER/record 长度断言（**受 G-TLS-1 阻塞**） |
| `tls-cert-dyn-subject` | T12 | **保留** | 形状已合规 |
| `tls-cert-dyn-san` | T13 | **保留** | 形状已合规 |
| `tls-cert-neg-dyn-keytype` | T14 | **保留** | 形状已合规 |
| `tls-cert-neg-keytype-value` | T15a | **保留** | 形状已合规 |
| `tls-cert-neg-bad-date` | T15b | **保留** | 形状已合规 |

**0 作废，0 等价覆盖**（15 例全部保留；A′ 新增 17 例见设计 §13）。**本协议存量 15/15 顶层零残留**（除 1 例判死靶子）。

## 9. 附：覆盖反查门建议断言行（供主线程合后登记；本车道不碰 `coverage_gate.py`）

建议在主线程合入后，于 `coverage_gate.py` 的 tls 段登记下列断言（**每条均可从本契约与 cases JSON 直接机读，不需新造事实**）：

| # | 建议断言 | 依据 |
|---:|---|---|
| 1 | `len(cases['tls']) == 15` 且 ID 集合 = §2 十五项，顺序一致 | 本契约 §2 |
| 2 | **非负例**（9 例）`spec_json` 顶层键 == `{layers}`（**本协议零游离键**） | 本契约 §1；设计 §12.1 |
| 3 | **负例**（6 例）`expect` 键集合 == `{expect_error, error_contains}`（严格两键，**今日已成立**） | 本契约 §4 |
| 4 | 6 负例 `fields`/`frames` 断言数 == 0（负例纯净性，**今日已成立**） | 本契约 §4 |
| 5 | 9 正例 `min_packets ∈ {16, 32}` 且 `min_packets == 16 × flows`（`flows` 由 `strategy_fc.value` 推出） | 设计 §9.1 公式 |
| 6 | 负例 `error_contains` ∈ 代码锚词集 `{"flat config field", "static four-tuple", "does not support dynamic", "not supported yet", "invalid RFC3339"}` | 设计 §7 |
| 7 | 15/15 链形 == `[ip,tcp,tls,http]` | 本契约 §1 |
| 8 | 3 条 `frames` 断言的 `offset` 全 == 59 | 本契约 §1 |
| 9 | 15/15 `layers[0].ip` 为 IPv4（IPv6 面今日零覆盖，**红项如实标红**） | 设计 G-TLS-5 |
| 10 | 5 例 `strategy_fc` 的 `value == 2`；其中 **4 例正例** `min_packets == 32`，第 5 例（`tls-neg-static-copy`）是负例、无 `min_packets` | 本契约 §1 |
| 11 | **`tls-handshake-basic` 的 `expect.notes` 不得含 `466`/`479`/`475`/`471` 数字**（G-TLS-1 修后须重钉） | 设计 G-TLS-1 |
| 12 | `certgen.go` 的 `fixedEntropyReader` 不得含 `ctr` 递增状态（G-TLS-1 修后断言） | 设计 G-TLS-1 |

**另注意**：`docs/protocol-pcap-test/tls.md` 的 15/15 pass 末次提交 `793dfee`（2026-09-19）**晚于**判死提交 `0417be5`（2026-09-13）——**不落入"早于判死提交"的过期口径**；但 `trafficgen/docs/protocol-pcap-test/tls/` 目录**不存在**、全仓该目录下 **0 个 `.pcap`**，故该数字**未经今日复跑证实，不得作为"今日已复跑"依据**（G-TLS-12，口径与 pcep G-PCEP-11 一致但**登记理由不同**——此处是"无 pcap 留档 + 未今日复跑"，不是"早于判死提交"）。

## 10. 修订记录

- v1.0.0（2026-09-29）：批次二文档车道 as-built 定稿。形状基线机读实测（§1，**15 例 = 9 正 + 6 负**，链形唯一 `[ip,tcp,tls,http]`，负例严格两键，**正例全用 `min_packets` 无 `packet_count`**——口径差异登记）；tshark 6 字段逐条核验；15 ID 索引表 + 逐例断言契约（§2/§3，含**探针实测帧字节**）；负例契约（§4，6 例锚词 + 判死靶子形状注）；对账两行（§5.2，**要求逻辑点 75 = 覆 45 + 不适用 10 + 立项 20**）；P3 固定动作（§6）；执行建议（§7）；存量审计（§8，**15/15 保留，0 改写**）；覆盖反查门建议断言行（§9，**12 条**）。**缺口 G-TLS-1…G-TLS-16**（其中 **G-TLS-1 为 confirmed finding**）。仅文档，未动 JSON/代码/tools。自审见下。
