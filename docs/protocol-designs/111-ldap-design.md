# #111 ldap（LDAP · RFC 4511 轻量目录访问协议，BER/DER 承载 TCP 389）设计契约

> 版本：v1.0.0（批次二 as-built 文档轨；修订记录见 §15）
> 日期：2026-09-29
> 车道：文档轨（#111 ldap 续号）
> 存量用例：`trafficgen/test/protocol_pcap/cases/ldap.json`（22 例 = 16 正 + 6 负；**顶层键已是纯层链形，零残留**，§12.1）
> 规范基线：① RFC 4511（LDAPv3 协议：LDAPMessage 信封 / 各 protocolOp / Filter CHOICE / LDAPResult，下称 **spec**，本机 `curl` 拉取原文逐节引用，§3 各表标章节）；② RFC 4512（目录信息模型——RootDSE 与属性选择面，§4.5.1.8 注）；③ RFC 879 / RFC 6528（MSS 分段与 ISN 随机化，承载面）；④ 本机 tshark 3.6.14 `ldap.*` 字段表与**自建探针 pcap 实测**（§1.3，`ldap.messageID`/`ldap.protocolOp`/`ldap.resultCode`/`ldap.scope`/`ldap.filter`/`ldap.attributes` 六字段逐条实证）；⑤ 本仓库落码（`internal/protocol/ldap/` 三文件 + 接线，§11）；⑥ 本机 Python 复算的 BER 编码副本（§3.1，与 JSON frames 断言逐字节一致）。
> 白话一句：**LDAP 是"查电话簿"——先报名字（bind），再问"某某人的哪些栏位"（search），服务器逐条报（entry）后说"报完了"（done），最后挂断（unbind）。所有报文都是"标签 + 长度 + 内容"三层套娃（BER），本实现每一层都用 4 字节长形长度（Active Directory 客户端习惯）。**

## 0. 本协议特殊性（须写清，不得含糊）

LDAP 与同批其它协议的**根本差异**在于线格式：它不是"固定头 + 字段"或"文本行"，而是 **BER（Basic Encoding Rules）的 TLV 嵌套结构**。因此本设计文档的 §3 与同批范本（101-opcua §3）形态不同——**必须逐字段写清字节偏移与长度公式**，而不是只给字段表。

| # | 特殊性 | 本协议怎么写清 |
|---:|---|---|
| 1 | **TLV 嵌套** | 每个协议动作 = `LDAPMessage ::= SEQUENCE { messageID INTEGER, protocolOp CHOICE }`，protocolOp 内又是各自 SEQUENCE。嵌套层数最深 5 层（searchResEntry → PartialAttributeList → PartialAttribute → vals SET OF）。§3.2 给逐层公式 |
| 2 | **长度编码三形态** | BER 长度有短形（<128B，1 字节）、长形（≥128B，`0x8n` + n 字节）、不定长（`0x80` + 内容 + `00 00`）。**本实现只用前两种，且 constructed 值恒用 `0x84` + 4 字节长形**（AD 客户端行为），primitive 值 <128B 用短形、≥128B 用 `0x84`。§3.1 逐函数写清 |
| 3 | **恒长形陷阱**（同族记忆） | 参考 pcap（AD 客户端）对**每个 constructed 值**都用 `0x84+4B`，**即便内容只有 7 字节**——所以 bindRequest 外层是 `30 84 00 00 00 10`（16 字节内容却占 6 字节头），不是 `30 10`。**这是本实现最容易写错的一处**，§3.1 给完整对照表 |
| 4 | **应用标签是上下文类** | protocolOp 的 6 个标签 `0x60/0x61/0x63/0x64/0x65/0x42` 全部是 **APPLICATION class**（bit7-6 = 01），不是 universal。`0x42` 是 primitive（unbindRequest 无内容），其余 5 个是 constructed。§3.3 标签表 |
| 5 | **srcport 12345 陷阱**（同族记忆） | 链路径 `[ip,ldap]` **无端口位**，`spec.SrcPort` 由 worker 保底 `12345+i` 注入（`strategy_convert.go:49`），目的端口 389 由 `Plan` 内部缺省（`ldap.go:303-305`）。用例**不得断言 srcport 值**，只断 `tcp.dstport=389`。§12.1 旧键去向表 |
| 6 | **与 radius 对称的 raw 实现** | ldap 与 radius/rtmp/rtsp/pptp/vnc/xmpp/sctp/jt808/jt809/jtt905 同属 **raw 自驱族**：legacy `Planner.Plan` 自建 TCP 握手/MSS 分段/BER 消息面/挥手全套，链路径只是把每包 Direction 改写成 `"up"` 后转发 `Emit`（防 raw-IP drive 二次换向）。§5.4 诚实声明 |

**同族记忆对照（本协议复用，逐条落到本设计）**：① "BER 恒长形" → §3.1；② "srcport 12345 陷阱" → §12.1；③ "raw 自驱五件套" → §5.4/§11。

**产物过期登记（G-LDAP-1）**：`trafficgen/docs/protocol-pcap-test/ldap.md`（**tracked 结果产物**，`git ls-files` 可证）写 `Cases: 22 — pass 22, fail 0, error 0`，但该文件末次提交 `064f9b6`（**2026-09-20**），**早于**本批次文档轨道开工日 2026-09-29，且 `docs/protocol-pcap-test/ldap/` 目录**根本不存在（0 个 pcap 文件）**。**该结果文档是过期产物，22/22 未经今日复跑证实，不代表今日已复跑**——读者不得据此判断套件已复跑。本车道**未跑**该套件，故本文档**不以任何形式**（含"今日已跑通"）引用该产物作为套件可跑证据（口径与 pcep G-PCEP-11、opcua G-OPCUA-10 一致）。
> **注（与 opcua 的差异，须写清不得夸大）**：ldap 的 `064f9b6`（2026-09-20）**晚于**扁平判死提交 `0417be5`（2026-09-13），故本协议**不存在** opcua 那种"末次提交早于判死提交"的形态；本缺口的唯一内容是**"22/22 数字未经今日复跑证实 + 无 pcap 留档"**。存量 22/22 例 `spec_json` 顶层键仅 `{layers}`（机读实测，§12.1），故 22 例**今日仍应可跑**。

## 1. 范围、profile 与实现状态边界

本版定义 **LDAPv3（RFC 4511）承载于 TCP 389** 的流量生成：一次 TCP 会话内的 **bind → search → unbind** 信令交换，报文为 BER 编码的 LDAPMessage 流。

| profile | 承载 | 本版允许内容 | 不从 profile 推导 |
|---|---|---|---|
| `ldap_tcp_v1`（主） | TCP，fixture 389 | bind（匿名/simple）→ search（scope 三枚举 + Filter present/equality + 属性选择）→ 可选 unbind → FIN | 真实目录服务器语义（条目是否存在、权限、匹配规则） |
| `ldap_ipv6_v1` | 同上，仅外层 IPv6 | 同上（字节与 IPv4 **完全一致**，仅以太帧载荷起点从 offset 54 变 74） | 从 IPv4 fixture 推导 IPv6 地址 |

**显式边界（"不实现、不声称、不许静默转换"）**：
1. **不实现 SASL 认证**（RFC 4511 §4.2.1 `sasl [3] SaslCredentials`）——参考 pcap 的 GSS-API 报文是 Kerberos 密文，不可复现，本实现恒发 simple 认证（`ldap.go:211-213` 注释明写）。
2. **不实现 Filter CHOICE 的其余 8 支**（`and`/`or`/`not`/`substrings`/`greaterOrEqual`/`lessOrEqual`/`approxMatch`/`extensibleMatch`，RFC 4511 §4.5.1.7）——只实现 `present [7]` 与 `equalityMatch [3]`；其余 8 支在 `Validate` 阶段拒绝（锚词 `invalid filter type`）。
3. **不实现 BER 不定长形**（`0x80`）——只用短形与 `0x84` 长形（§3.1）。
4. **不实现 Controls**（RFC 4511 §4.1.11 `controls [0] Controls OPTIONAL`）——LDAPMessage 恒为 `SEQUENCE { messageID, protocolOp }` 两元素（`ldap.go:179-182`）。
5. **不实现 Modify/Add/Delete/Compare/Abandon/Extended 六类操作**（RFC 4511 §4.6–§4.14）——只实现 Bind/Unbind/Search 三族。
6. **不实现 startTLS**（RFC 4511 §4.14.1 ExtendedRequest 承载）——registry 注释明写 `startTLS/SASL/其余 Filter CHOICE=B′ 注记`（`registry.go:1888`）。
7. **不声称**参考 pcap 的字节可逐字节复现——参考 pcap 是 AD 客户端的 SASL/GSS-API 会话，本实现是 simple 认证的合成会话；**能复现的是 BER 编码形态与消息长度规律**（§3.7 长度表逐条与参考量级对齐）。
8. **不实现引用（referral）与 searchResRef**（RFC 4511 §4.1.10/§4.5.2）——`searchResRef [APPLICATION 19]` 不产。

**实现状态（2026-09-29 实测）**：`ldap` 层已注册（`registry.go:1890`，`CategoryTerminal`，`DependsOn ["ip"]`，**Fields 15 键**）；planner 已落码（`internal/protocol/ldap/` 三文件 1077 行：`ldap.go` 498 / `ldap_test.go` 506 / `layer_gen.go` 73）；`allowedProtocols["ldap"]=true`（`protocols.go:46`）；层内 translate 已接线（`chain_planner_translate.go:2775-2781`）；扁平转换分支已接线（`strategy_convert.go:1309-1315`，含缺省端口 389）；raw 自驱链已接线（`chain_planner_util.go:40` `isRawIPChain` 名单含 ldap；`chain_planner.go:1518` `meta.LDAP = spec.LDAP`）；端口 0 豁免已登记（`chain_planner.go:748` `validateBaseDstPortHandled` 含 ldap）；顶层 `ldap` 子映射 presence 判死已接线（`CheckProtoFlat` `rawWrapChains` 表含 `"ldap": "[ip,ldap]"`）；22 语义用例已落 `cases/ldap.json`。

**输出契约（pcap/NIC 双输出）**：两路径共用同一 cases JSON 与断言集（`tcp.dstport`、`tcp.flags`、offset 54/74 frames）；NIC 经 tcpdump 捕获（`nic_capture` 用例级开关）；不设仅单路径可用的断言。

### 1.3 tshark 通道实证（自建探针，2026-09-29）

`tshark -G fields` 中 `ldap.*` **159 字段**；`tshark -G decodes` 有 `tcp.port 389 ldap`（另有 3268/636/cldap 绑定）。**本车道用本机 Python 复算的 BER 副本**（与 §3 各公式一致）**自建探针 pcap**，经 tshark 3.6.14 解码，**零 `_ws.malformed`**，实测可用字段通道：

| 字段 | 类型 | 探针实测值（bindReq id=1 / searchReq id=2 / bindResp 49 / equality / unbind） |
|---|---|---|
| `ldap.messageID` | FT_UINT32 | `1` / `2` / `1` / `2` / `3` |
| `ldap.protocolOp` | FT_UINT32（**枚举号，非名字**） | `0`(bindRequest) / `3`(searchRequest) / `1`(bindResponse) / `3` / `2`(unbindRequest) |
| `ldap.resultCode` | FT_UINT32 | — / — / `49` / — / — |
| `ldap.scope` | FT_UINT32 | — / `0` / — / `0` / — |
| `ldap.filter` | FT_UINT32（Filter CHOICE 分支号） | — / `7`(present) / — / `3`(equalityMatch) / — |
| `ldap.attributes` | FT_UINT32（**AttributeSelection 项数**） | — / `15` / — / `0` / — |

**`-V` 树形态（可读性实证）**：`LDAPMessage bindRequest(1) "<ROOT>" simple` / `messageID: 1` / `protocolOp: bindRequest (0)` / `version: 3`；`LDAPMessage searchRequest(2) "<ROOT>" baseObject` / `Filter: (objectclass=*)` / `filter: present (7)` / `attributes: 15 items`；`LDAPMessage bindResponse(1) invalidCredentials` / `resultCode: invalidCredentials (49)`；`Filter: (uid=alice)` / `filter: equalityMatch (3)`；`LDAPMessage unbindRequest(3)` / `protocolOp: unbindRequest (2)`。

**进制纪律（实测）**：上表六字段全为**十进制整数串**；枚举名（`bindRequest`/`present`/`invalidCredentials`）只在 `-V` 树里出现，`-T fields` 输出的是**枚举号**。

## 2. 协议栈、端口和固定偏移

推荐层链为 `[ip, ldap]`（**ldap 是 raw 自驱终结层，链中无 tcp/udp 层**——TCP 由生成器自建，§5.4）。这是本协议与 opcua（`[ip,tcp,opcua]`）在**链形上的根本差异**。

端口：LDAP 默认 **TCP 389**（RFC 4511 §3 / IANA `ldap/tcp`）。链路径**层 config 无端口位**（registry Fields 15 键无 `dst_port`），目的端口由 legacy `Plan` 内部缺省（`ldap.go:303-305`：`if spec.DstPort == 0 { spec.DstPort = DefaultPort }`）；`validateBaseDstPortHandled("ldap")` 为 true（`chain_planner.go:748`）故通用 FieldContract 块不介入。源端口由 worker 保底 `DefaultSrcPort+i`（12345+i，`strategy_convert.go:49`）。

固定偏移：无 VLAN/IP options/TCP options 时，**每帧 BER 消息起点为 IPv4 offset 54**（14 Eth + 20 IP + 20 TCP）、**IPv6 offset 74**（14 + 40 + 20）。握手 SYN 帧带 TCP options（MSS/WinScale/SACK，`ldap.go:462-471`），故 **SYN/SYN-ACK 的以太帧长 = 54 + 20 + 12 = 86**；数据帧与 FIN 帧无 options，以太帧长 = 54 + 20 + len(BER)。

目标形状 spec_json 样例（严格层链形，顶层仅 `layers`；**本协议存量 22 例已是此形，无需迁移**）：

```json
{
  "layers": [
    {"ip": {"src": "10.0.0.1", "dst": "20.0.0.1"}},
    {"ldap": {"rounds": 2, "filter_type": "equality", "search_filter": "uid", "filter_value": "alice", "unbind": false}}
  ]
}
```

多流样例（数量只走 `flow_control`；本协议存量未用，四元组由 worker 保底递增）：

```json
{
  "layers": [
    {"ip": {"src": "10.0.0.1", "dst": "20.0.0.1"}},
    {"ldap": {}}
  ],
  "flow_control": {"flows": 3}
}
```

## 3. 线格式编码（逐字段、逐偏移、逐长度公式）

### 3.1 BER 编码原语（本实现的**全部**编码规则，`ldap.go:130-173`）

**三个原语函数是全部线格式的生成器**，读懂这三行即可复算任意报文的每一个字节：

| 原语 | 行 | 规则 | 形态 |
|---|---|---|---|
| `berInt(n)` | `:130-145` | INTEGER：最小字节数**大端**内容；`n<0` 归零；`n=0` → 内容 `00`；**内容首字节 bit7=1 时前置 `00`**（防被读成负数） | `02 LL <body>` |
| `berWrap(tag, content)` | `:151-156` | **constructed 值**：**恒用 `0x84` + 4 字节大端长度**，即使内容 <128B | `TT 84 00 00 LL LL <content>`（头恒 6 字节） |
| `berPrim(tag, content)` | `:160-169` | **primitive 值**：`len<128` 短形；`len≥128` 用 `0x84`+4B 长形 | `TT LL <content>` 或 `TT 84 00 00 LL LL <content>` |

**恒长形是本协议最易写错处（特殊性 #3）**。对照表（**JSON frames 断言逐字节实证**）：

| 值 | 内容长度 | 本实现头部 | 短形会是 | 差 |
|---|---:|---|---|---:|
| LDAPMessage 外层 SEQUENCE | 16 | `30 84 00 00 00 10` | `30 10` | +5B |
| bindRequest protocolOp | 7 | `60 84 00 00 00 07` | `60 07` | +5B |
| bindResponse protocolOp | 7 | `61 84 00 00 00 07` | `61 07` | +5B |
| searchRequest protocolOp | 335 | `63 84 00 00 01 4f` | —（本已 ≥128） | 0 |
| unbindRequest protocolOp | 0 | **`42 00`**（primitive，见下） | 同 | 0 |
| present filter `[7]` | 11 | **`87 0b`**（primitive 短形） | 同 | 0 |
| equalityMatch `[3]` | 16 | `a3 84 00 00 00 10`（constructed） | `a3 10` | +5B |

**两个例外（不是恒长形，必须记住）**：
- **`unbindRequest` 是 primitive 且零长**：RFC 4511 §4.3 `UnbindRequest ::= [APPLICATION 2] NULL`——NULL 类型编码为 `42 00`（标签 + 长度 0，**无内容字节**），`ldap.go:284-287` 直接写字面量 `0x42, 0x00`，不经 `berWrap`。
- **`present` filter 是 primitive**：RFC 4511 §4.5.1.7 `present [7] AttributeDescription`——AttributeDescription 是 OCTET STRING，故 `[7]` 是**隐式标签的 primitive 值**，短形 `87 0b`（11 = `objectclass` 长度），`ldap.go:240` 用 `berPrim`。

其余辅助（`ldap.go:171-173`）：`berOctet(s)` = `berPrim(0x04, s)`；`berEnum(n)` = `berPrim(0x0a, [n])`（**恒 1 字节内容**，因所有枚举值 ≤127）；`berBoolFalse()` = 字面 `01 01 00`。

### 3.2 LDAPMessage 信封（RFC 4511 §4.1.1）

```
LDAPMessage ::= SEQUENCE { messageID MessageID, protocolOp CHOICE {...} }
```

| 偏移（相对 BER 起点） | 字段 | 编码 | 长度 |
|---:|---|---|---:|
| 0 | 外层 SEQUENCE | `berWrap(0x30, body)` | **恒 6** |
| 6 | messageID | `berInt(mid)`（§4.1.1.1 要求非零） | 3（mid ≤127）/ 4（mid ≥128） |
| 6+len(mid) | protocolOp | `berWrap(opTag, opContent)` | **恒 6 + len(opContent)** |

**总长度公式**：`len(LDAPMessage) = 6 + len(berInt(mid)) + 6 + len(opContent) = 12 + len(berInt(mid)) + len(opContent)`。
`buildLDAPMessage`（`ldap.go:179-182`）：`body = berInt(mid) ++ berWrap(opTag, opContent)`；`return berWrap(0x30, body)`。

**messageID 三态（`berInt` 实测）**：`mid ∈ [1,127]` → `02 01 XX`（3B）；`mid ∈ [128,32767]` → `02 02 XX XX`（4B，首字节 ≥0x80 但**不会**触发 `00` 前置，因为 2 字节表示的首字节仅当 ≥0x80 且**值 ≥32768** 才会——`MaxMessageID=0x7FFF` 保证最高位为 0，故恒 `02 02 7f ff` 封顶）；`mid=0` → `02 01 00`（本实现不用：`base==0` 缺省为 1，`ldap.go:310-313`）。
> **`00` 前置分支在本协议不可达**：`MaxMessageID = 0x7FFF`（`ldap.go:22`）+ `Validate` 上限检查（`:120-122`）保证 `mid ≤ 32767`，2 字节表示首字节 ≤ `0x7f`，永不置位 bit7。该分支是 `berInt` 的通用防御，**非本协议可达路径**（§7 未入例分支）。

### 3.3 protocolOp 标签表（RFC 4511 §4.1.1 CHOICE，全部 APPLICATION class）

| 标签 | 类型 | 名称 | 方向 | 内容公式 | 用例 |
|---:|---|---|---|---|---|
| `0x60` | constructed | bindRequest | up | §3.4.1 | T-1/4/5/6/11/14 |
| `0x61` | constructed | bindResponse | down | §3.4.2 | T-1/10/11/14 |
| `0x42` | **primitive** | unbindRequest | up | `NULL`（零长，§3.1 例外） | T-1/3 |
| `0x63` | constructed | searchRequest | up | §3.5.1 | T-1/2/3/7/8/9/11/12/14/15/16 |
| `0x64` | constructed | searchResEntry | down | §3.5.2 | T-1 |
| `0x65` | constructed | searchResDone | down | §3.5.3 | T-1/10/11/14 |
| `0x73` | constructed | searchResRef | — | **不实现**（§1 边界⑧） | — |

**方向与配对**：`messageID` 是**唯一关联标识**（RFC 4511 §4.1.1.1）——响应回显请求的 messageID。配对表（`ldap.go:410-419`）：

| 轮 r（0-based） | 请求 mid | 响应 mid | 说明 |
|---|---|---|---|
| 第 r 轮 bind | `base + 3r` | 同（回显） | `buildBindRequest(rb)` → `buildBindResponse(rb)` |
| 第 r 轮 search | `base + 3r + 1` | 同（回显） | `buildSearchRequest(rb+1)` → `buildSearchResEntry(rb+1)` + `buildSearchResDone(rb+1)` |
| 会话末尾 unbind | `base + 3(rounds-1) + 2` | **无响应**（RFC 4511 §4.3：unbind 不响应） | `buildUnbind(...)` |

**messageID 分配公式（序号算法实读）**：`mid(r, op) = base + 3r + k`，其中 `k=0`（bind）/`k=1`（search）/`k=2`（unbind，仅 `r=rounds-1` 时发一次）；`base = MessageIDBase`（`0` → 缺省 `1`，`ldap.go:310-313`）。上限检查（`ldap.go:120-122`）：`base + 3×(rounds-1) + 2 > 0x7FFF` 即拒（锚词 `exceeds 0x7FFF`）。
> **诚实声明（与 doc 注释的差异）**：`types.go:8943-8945` 的 `LDAPConfig` 注释写"default MessageIDBase=2423"，**该缺省未落码**——`parseLDAPConfig`（`strategy_convert.go:5698-5713`）与 `Plan`（`ldap.go:310-313`）都用 `0 → 1`。**以代码为准**（§7 G-LDAP-4）。

### 3.4 Bind 族

#### 3.4.1 bindRequest（RFC 4511 §4.2.1）

```
BindRequest ::= [APPLICATION 0] SEQUENCE {
     version        INTEGER (1..127),
     name           LDAPDN,               -- OCTET STRING
     authentication AuthenticationChoice } -- simple [0] OCTET STRING
```

| opContent 偏移 | 字段 | 编码 | 长度 | 缺省 |
|---:|---|---|---:|---|
| 0 | version | `berInt(versionOf(cfg))` | 3（值 ≤127） | **3**（`cfg.Version==0` → 3，`ldap.go:194-199`） |
| 3 | name | `berOctet(cfg.BindDN)` | 2 + len（空串 → `04 00`，2B） | `""`（匿名 bind） |
| 3+len(name) | authentication | `berPrim(0x80, []byte(cfg.BindPassword))` | 2 + len（空串 → `80 00`，2B） | `""` |

**总长度公式**：`len(bindRequest opContent) = 3 + 2 + len(BindDN) + 2 + len(BindPassword) = 7 + len(BindDN) + len(BindPassword)`。
**整包长度**：`len(LDAPMessage) = 12 + 3 + opContent = 22 + len(BindDN) + len(BindPassword)`。
**实测（JSON frames 逐字节）**：匿名（`BindDN=""`,`pw=""`）→ opContent 7，`60 84 00 00 00 07 02 01 03 04 00 80 00`，整包 **22**；`cn=admin,dc=test`+`s3cret` → opContent 29，整包 **44**。
`buildBindRequest`（`ldap.go:214-219`）。

#### 3.4.2 bindResponse（RFC 4511 §4.2.2）

```
BindResponse ::= [APPLICATION 1] SEQUENCE { COMPONENTS OF LDAPResult, serverSaslCreds [7] OPTIONAL }
```

本实现**恒不发 `serverSaslCreds`**（§1 边界①：只用 simple 认证，§4.2.2 明言 simple 下该字段 SHALL NOT 出现）。内容 = LDAPResult（§3.6），`buildBindResponse`（`ldap.go:222-224`）。

### 3.5 Search 族

#### 3.5.1 searchRequest（RFC 4511 §4.5.1）

| opContent 偏移 | 字段 | 编码 | 长度 | 缺省/值 |
|---:|---|---|---:|---|
| 0 | baseObject | `berOctet(cfg.SearchBaseDN)` | 2 + len | `""` = **RootDSE**（参考 pcap 形） |
| 2 | scope | `berEnum(cfg.SearchScope)` | 3（`0a 01 XX`） | **0** = baseObject |
| 5 | derefAliases | `berEnum(0)` **恒 0** | 3 | neverDerefAliases（**不可配**） |
| 8 | sizeLimit | `berInt(cfg.SizeLimit)` | 3 | 0 = 不限 |
| 11 | timeLimit | `berInt(cfg.TimeLimit)` | 3 | 0 = 不限（参考 pcap 用 120） |
| 14 | typesOnly | `berBoolFalse()` 恒 `01 01 00` | 3 | false（**不可配**） |
| 17 | filter | §3.5.4 | 13（present）/ 18（equality，本缺省属性） | present `objectclass` |
| 17+len(filter) | attributes | `berWrap(0x30, Σ berOctet(name))` | **6 + Σ(2+len(name))** | 15 个 RootDSE 属性（§3.5.5） |

**总长度公式**：`len(opContent) = 17 + len(filter) + 6 + Σ_i (2 + len(attr_i))`。
`buildSearchRequest`（`ldap.go:246-260`）。

**实测（复算副本 + JSON frames 双向一致）**：

| 配置 | filter 长度 | opContent | 整包 | 外层头 hex |
|---|---:|---:|---:|---|
| 缺省（15 属性 / present） | 13 | 335 | **350** | `30 84 00 00 01 58`（344 = 3 + 341） |
| `attributes: ["cn","mail"]` | 13 | 46 | **61** | `30 84 00 00 00 37` |
| 15 属性 + equality | 18 | 340 | **355** | `30 84 00 00 01 5d` |
| `attributes: []`（显式空） | 13 | 36 | **51** | `30 84 00 00 00 2d` |
| 100 × 20 字符属性（单测） | 13 | 2236 | **2251** | `30 84 00 00 08 c5`（2245 = 3 + 2242） |

> **T-2 帧断言的精确含义**：`30 84 00 00 01 58` 中 **`0x158 = 344` 是外层 SEQUENCE 的 content 长度**（= `berInt(2)` 3B + `berWrap(0x63, …)` 341B），**不是消息全长**（全长 350）。消息全长 = 344 + 6（外层头）= 350。同一 JSON 的 notes 写"searchReq 0x158=344"，口径为**content 长度**——本设计文档沿用同一口径并显式声明。

#### 3.5.2 searchResEntry（RFC 4511 §4.5.2）

| opContent 偏移 | 字段 | 编码 | 长度 |
|---:|---|---|---:|
| 0 | objectName | `berOctet(cfg.SearchBaseDN)`（**与请求 baseObject 同值**） | 2 + len |
| 2 | attributes (PartialAttributeList) | `berWrap(0x30, Σ partial)` | 6 + Σ len(partial) |
| ↑ 每个 partial | PartialAttribute | `berWrap(0x30, berOctet(name) ++ berWrap(0x31, berOctet(name)))` | 6 + (2+len) + 6 + (2+len) = **16 + 2×len(name)** |

`PartialAttribute ::= SEQUENCE { type AttributeDescription, vals SET OF AttributeValue }`（§4.1.7）——**值就是属性名本身**（确定性合成数据，`ldap.go:266-275`）。

**总长度公式**：`len(opContent) = 2 + len(baseDN) + 6 + Σ_i (16 + 2×len(attr_i))`。
**实测**：15 个 RootDSE 属性 → opContent **786**，整包 **801**（`30 84 00 00 03 1b`）；100 × 20 字符 → 整包 **5623**；`attributes: []` → opContent 8，整包 **23**。
> **口径警告（G-LDAP-2）**：entry 的 vals 是**属性名自身**（如 `cn` 的值为 `cn`），不是真实目录数据。这是"确定性合成数据"的显式选择（`ldap.go:264-265` 注释），**不得声称**其具备真实条目语义。

#### 3.5.3 searchResDone（RFC 4511 §4.5.3）

```
SearchResultDone ::= [APPLICATION 5] LDAPResult
```

内容 = LDAPResult（§3.6），整包恒 **22**（`30 84 00 00 00 10 02 01 XX 65 84 00 00 00 07 …`）。`buildSearchResDone`（`ldap.go:278-280`）。

#### 3.5.4 Filter CHOICE（本实现 2/10 支，RFC 4511 §4.5.1.7）

| `filter_type` | 标签 | 类 | 编码 | 长度公式 |
|---|---:|---|---|---|
| `"present"`（缺省）/ `""` | `0x87` | **primitive** [7] | `berPrim(0x87, []byte(name))` | `2 + len(name)` |
| `"equality"` | `0xa3` | constructed [3] | `berWrap(0xa3, berOctet(name) ++ berOctet(value))` | `6 + (2+len(name)) + (2+len(value))` |

`name = cfg.SearchFilter`，空串缺省 `"objectclass"`（`ldap.go:232-235`）。
**equalityMatch 是隐式标签的 AttributeValueAssertion**（§4.1.6 `AttributeValueAssertion ::= SEQUENCE { attributeDesc, assertionValue }`）——**context tag 替换了 SEQUENCE 标签，故内容直接是两个 OCTET STRING，无嵌套 SEQUENCE**（`ldap.go:226-230` 注释明写）。实测 `uid`+`alice` → `a3 84 00 00 00 10 04 03 75 69 64 04 05 61 6c 69 63 65`（18B）。
**未实现的 8 支**（`and [0]`/`or [1]`/`not [2]`/`substrings [4]`/`greaterOrEqual [5]`/`lessOrEqual [6]`/`approxMatch [8]`/`extensibleMatch [9]`）→ `Validate` 拒绝（锚词 `invalid filter type`，`ldap.go:100-102`）。

#### 3.5.5 AttributeSelection（RFC 4511 §4.5.1.8）

`attributes` 是 `SEQUENCE OF LDAPString`，本实现编成 `berWrap(0x30, Σ berOctet(name))`（`ldap.go:254-258`）。
**三态语义（`attributesOf`，`ldap.go:204-209`）**：

| JSON | `cfg.Attributes` | 实际发出 | 依据 |
|---|---|---|---|
| **键缺席** | `nil` | **15 个 RootDSE 属性**（`ldap.go:56-62` 常量表） | 参考 pcap 的 AD 客户端查询了这 15 个，顺序一致 |
| `"attributes": ["cn","mail"]` | 2 元素 | 2 个 | 显式覆盖缺省 |
| `"attributes": []` | `nil`（**空切片被解析成 nil**） | **15 个 RootDSE 属性**（回退缺省） | `parseStringList`（`strategy_convert.go:5901-5916`）空数组返回 nil |

> **G-LDAP-3（confirmed finding）**：`parseStringList` 使 `"attributes": []` **无法表达"请求 0 个属性"**——它与键缺席同为 `nil`，双双回退 15 个缺省属性。而 `ldap.go:206-207` 注释明写"an explicitly empty slice requests no attributes"，**该注释描述的能力经层链 JSON 路径不可达**（只有引擎直调 `core.FlowSpec{LDAP:{Attributes: []string{}}}` 才可达）。用例 T-1 的 notes 写 `searchReq 0x158=344（15 属性 RootDSE）` 与此一致（发的是 15 个）。
> **可表达空属性的唯一路径**：`attributes: ["1.1"]`（RFC 4511 §4.5.1.8 `noattrs = "1.1"`）——但本实现不做 ABNF 校验，它会被当作普通属性名 `1.1` 编出（长度 3 的属性）。**今日无例**（G-LDAP-3）。

15 个缺省属性与各自 BER 长度（`ldap.go:56-62`，逐条复算）：

| # | 属性 | len | BER | # | 属性 | len | BER |
|---:|---|---:|---|---:|---|---:|---|
| 1 | `subschemaSubentry` | 17 | 19 | 9 | `supportedLDAPVersion` | 20 | 22 |
| 2 | `dsServiceName` | 13 | 15 | 10 | `supportedLDAPPolicies` | 21 | 23 |
| 3 | `namingContexts` | 14 | 16 | 11 | `supportedSASLMechanisms` | 23 | 25 |
| 4 | `defaultNamingContext` | 20 | 22 | 12 | `dnsHostName` | 11 | 13 |
| 5 | `schemaNamingContext` | 19 | 21 | 13 | `ldapServiceName` | 15 | 17 |
| 6 | `configurationNamingContext` | 26 | 28 | 14 | `serverName` | 10 | 12 |
| 7 | `rootDomainNamingContext` | 23 | 25 | 15 | `supportedCapabilities` | 21 | 23 |
| 8 | `supportedControl` | 16 | 18 | | **合计** | | **299** |

### 3.6 LDAPResult（RFC 4511 §4.1.9，bindResponse 与 searchResDone 共用）

```
LDAPResult ::= SEQUENCE { resultCode ENUMERATED, matchedDN LDAPDN, diagnosticMessage LDAPString, referral [3] OPTIONAL }
```

| opContent 偏移 | 字段 | 编码 | 长度 | 本实现值 |
|---:|---|---|---:|---|
| 0 | resultCode | `berEnum(cfg.ResultCode)` | 3 | `ResultCode`（0–127） |
| 3 | matchedDN | `berOctet("")` | 2 | **恒空** |
| 5 | diagnosticMessage | `berOctet("")` | 2 | **恒空** |
| — | referral | — | — | **不发**（OPTIONAL，§1 边界⑧） |

**总长度恒 7**（`ldapResult`，`ldap.go:186-191`）；整包恒 **22**。
> **诚实声明**：`matchedDN` 与 `diagnosticMessage` **不可配、恒空串**——即便 `result_code=49`（invalidCredentials）也不填诊断文本。§4.1.9 明言 diagnosticMessage 非标准化、实现 MUST NOT 依赖其值；空串是合法形态（"If the server chooses not to return a textual diagnostic, the diagnosticMessage field MUST be empty"）。**本设计不声称**错误响应的可读性。

### 3.7 完整长度表（复算副本 + JSON frames 双向一致，2026-09-29）

| 消息 | opContent | 整包（`12 + len(mid) + opContent`，mid ≤127 时 len(mid)=3） | 以太帧（IPv4，无 options） | JSON 锚 |
|---|---:|---:|---:|---|
| bindRequest（匿名） | 7 | **22** | 76 | T-1 帧4 `30 84 00 00 00 10 02 01 01 60` |
| bindRequest（dn+pw） | 7+len(dn)+len(pw) | 22+len(dn)+len(pw) | +… | T-5 |
| bindResponse | 7 | **22** | 76 | T-1 帧5 `… 02 01 01 61` |
| searchRequest（15 属性 present） | 335 | **350** | 404 | T-1/T-2 帧6 `30 84 00 00 01 58 02 01 02 63` |
| searchRequest（2 属性 present） | 46 | **61** | 115 | T-12 |
| searchResEntry（15 属性） | 786 | **801** | 855 | — |
| searchResDone | 7 | **22** | 76 | — |
| unbindRequest | 0（primitive NULL） | **15** | 69 | T-1 帧9 `30 84 00 00 00 05 02 01 03 42 00` |

**校验**：T-1 帧9 `30 84 00 00 00 05` 的 content 长度 `0x05 = 5` = `berInt(3)` 3B + `42 00` 2B ✓；T-1 帧4 `0x10 = 16` = `berInt(1)` 3B + `berWrap(0x60, 7B)` 13B ✓；T-2 帧6 `0x158 = 344` = `berInt(2)` 3B + `berWrap(0x63, 335B)` 341B ✓。

### 3.8 TCP 承载面（自建，`ldap.go:402-433`）

| 阶段 | 帧 | flags | seq/ack | 备注 |
|---|---|---|---|---|
| 握手 | SYN(up) / SYN-ACK(down) / ACK(up) | `0x02` / `0x12` / `0x10` | ISN 随机（RFC 6528） | SYN/SYN-ACK 带 options（MSS/WinScale/SACK） |
| 数据 | 每 BER 消息按 MSS 分段的 PSH-ACK | `0x18` | 发送方 seq 累加 | 见下 |
| 挥手 | FIN-ACK(up) / ACK(down) / FIN-ACK(down) / ACK(up) | `0x11`/`0x10`/`0x11`/`0x10` | — | 恒 4 帧 |

- **ISN**：`clientSeq` 取 `spec.TCP.InitialSeq`，为 0 时 `randomUint32()`（`ldap.go:346-353`）；`serverSeq` 恒随机。**故 seq/ack 值不可断言**（用例只断 flags 与载荷）。
- **MSS 分段**（RFC 879，`segmentByMSS`，`ldap.go:441-458`）：payload 按 `mss` 切块，**空 payload 产 1 个空块**；`mss ≤ 0` 时整块不切。默认 MSS **1460**（`DefaultMSS`），可由 `spec.TCP.MSS` 覆盖。
- **分段数公式**：`segments(msg) = ceil(len(msg) / mss)`（`len(msg)>0`）。缺省 MSS 1460 下**本协议所有消息都是单段**（最长 searchResEntry 100 属性 = 5623B → 4 段；缺省 15 属性 = 801B → 1 段）。单测 `TestPlan_MSSSegmentation` 用 MSS=100 验证 350B → 4 段（100/100/100/50）。
- **TCP 窗口**：恒 `65535`（`ldap.go:366`），**不可配**。
- **IP TTL**：`spec.TTL`，0 → 缺省 **64**（`ldap.go:334-337`）。**IP ID**：每包 `randomIPID()+i` 递增（`ldap.go:328-333`）——**不可断言**。

## 4. 业务场景分析（现网典型场景与五层覆盖）

**定性**：**声明式剧本回放**——配置声明轮数与各字段，引擎按固定剧本产出事件序列（握手 → 每轮 bind 对 + search 三件 → unbind → 挥手），TCP 承载由生成器自建。

| 现网场景 | 事务交互 | 对应用例 |
|---|---|---|
| ① AD RootDSE 探测（参考 pcap 形） | 匿名 bind → 查 15 个 RootDSE 属性 → unbind | T-1（`ldap_session_full`）、T-2 |
| ② 匿名 bind 基线 | name 空串 + simple 空密码 | T-4（`ldap_bind_anonymous`） |
| ③ 服务账号 simple bind | DN + 密码入 bindRequest | T-5（`ldap_bind_simple`）、T-14 |
| ④ LDAPv2 兼容客户端 | version=2 报文 | T-6（`ldap_bind_version2`） |
| ⑤ 按层级遍历目录树 | scope 1/2 | T-7、T-8 |
| ⑥ 按属性值精确定位用户 | equalityMatch 过滤器 | T-9（`ldap_filter_equality`）、T-14 |
| ⑦ 认证失败分支 | resultCode 49 进响应 | T-10（`ldap_result_invalid_credentials`） |
| ⑧ 长会话多轮查询 | rounds≥2 连续 bind/search | T-3、T-11、T-14 |
| ⑨ 按需索取栏位 | 自定义 AttributeSelection | T-12（`ldap_attributes_custom`）、T-14 |
| ⑩ 会话分页/限流 | sizeLimit / timeLimit | T-16（`ldap_size_time_limit`） |
| ⑪ 指定子树搜索 | 非 RootDSE baseObject | T-15（`ldap_search_base_dn`） |
| ⑫ 客户端不发 unbind 直接关 | unbind 抑制 | T-13（`ldap_unbind_suppressed`） |

**五层覆盖逐层结论**：
- **功能层**：Bind（匿名/simple/version2）三正例 + Search（scope 三枚举 / Filter 两分支 / 属性三态 / baseDN / 双 limit）七正例 + Unbind 两态（发/抑制）+ resultCode 分支一例；**错误处理 6 类负例**（version/scope/filter_type/result_code/size_limit/messageID，§7）。
- **性能层**：MSS 跨分段（`TestPlan_MSSSegmentation`，MSS=100 → 350B 分 4 段）；长度边界（长形↔短形切换，T-2 专钉）；字段长度上界（100×20 属性 = 2251B，单测）；多轮会话帧数上界（rounds=2 → 18 帧）。
- **数据场景层**：字段值域全覆盖（version 2/3、scope 0/1/2、filter 2 分支、result_code 0/49/128、size/time limit 0/10/60/-1、rounds 1/2、attributes 缺省/自定义）；**编码变体**（短形/长形长度、primitive/constructed 标签、INTEGER 三态）；非法值拒绝（6 负例）。
- **地址与流层**：**IPv4 全 22 例**；**IPv6 今日无例**（A′ 立项，G-LDAP-5——链路径 `[ip,ldap]` 的 ip 层可写 v6，`EtherTypeFor` 自动取 `0x86DD`，但**无用例走过**）；单流基线（22 例全单流）；**流关联（控制流派生数据流）显式不适用**——LDAP 单 TCP 连接承载全部操作，无副连接；**多流（会话内并发流）显式不适用**——单连接串行收发，多流由策略级 `flow_control` 承载（本版未用）。
- **业务层**：十二场景全部有落点（上表）。

**次要合法行为显式不适用声明（不设正例、亦不得进负例）**：① SASL 认证（未实现，§1 边界①）；② Filter 其余 8 支（未实现，§1 边界②）；③ BER 不定长形（未实现，§1 边界③）；④ Controls（未实现，§1 边界④）；⑤ Modify/Add/Delete/Compare/Abandon/Extended（未实现，§1 边界⑤）；⑥ startTLS（未实现，§1 边界⑥）；⑦ referral / searchResRef（未实现，§1 边界⑧）；⑧ RST 异常中断（框架面，本层零断言）。

## 5. 消息/事务模型与状态机

**事务定义**：一次请求 + 一次响应（bindRequest/bindResponse 或 searchRequest/searchResEntry+searchResDone）。**多事务** = 一个连接内多轮按序执行（`rounds=N` → N 轮，每轮 2 个事务）。

### 5.1 状态机（RFC 4511 §3 协议模型）

RFC 4511 定义 LDAP 会话的三态：**匿名（anonymous）→ 已绑定（bound）→ 操作**。本实现的**实际状态机极简**——它是剧本回放器，不是状态机实现：

| 状态 | 触发 | 本实现行为 |
|---|---|---|
| 匿名 | 会话建立（TCP 握手后） | 直接进第 1 轮 bind（**不做前置检查**） |
| 已绑定 | bindResponse 后 | 直接进 search（**不校验 resultCode**） |
| 操作中 | searchRequest 后 | 发 entry + done |
| 关闭 | unbind 或 FIN | 挥手 |

**非法转移逐条列出（RFC 4511 定义 vs 本实现）**：

| # | 非法转移（规范） | 规范依据 | 本实现行为 | 用例 |
|---:|---|---|---|---|
| 1 | search 前未 bind | §3 协议模型 | **不检查**——`Plan` 恒按 bind→search 顺序产出，配置无法表达"先 search" | 不可达（结构上排除） |
| 2 | bind 失败（resultCode≠0）后继续 search | §4.2.2 客户端 SHOULD 终止会话 | **不检查**——`result_code` 只影响响应字节，不影响后续轮次 | T-10（`result_code=49` 后仍发 search，**行为已固化**） |
| 3 | 同 messageID 并发请求 | §4.1.1.1 MUST NOT | **不可能**——messageID 由 `base+3r+k` 确定性分配，同轮内三个值互异、跨轮递增 | 不可达 |
| 4 | 响应 messageID ≠ 请求 | §4.1.1.1 MUST | **不可能**——`build*Response(rb)` 与请求共用同一 `rb` 变量 | T-3（逐帧钉 id） |
| 5 | unbind 后期望响应 | §4.3 unbind 无响应 | **不产响应**（`ldap.go:423-425` 只 `emitData` 一次，无 down 包） | T-1/T-3（unbind 后直接 FIN） |
| 6 | 会话中发第二个 unbind | §4.3 | **不可能**——unbind 只在 `rounds-1` 轮后发一次 | 不可达 |
| 7 | bind 中断其它进行中操作 | §4.2.1 | **不适用**——无并发请求 | 不适用 |

> **诚实声明（G-LDAP-6）**：本实现**没有状态机校验**——非法转移 #1/#2 在结构上不可达（配置无法表达），不是"被检测后拒绝"。用例 T-10（`result_code=49`）**固化的是"bind 失败仍继续 search"这一非规范行为**，其 notes 只写"RFC 4511 §4.1.9 ENUMERATED 49=invalidCredentials"，**未声称符合 §4.2.2 的终止建议**。本设计不声称状态机合规。

### 5.2 事件序（`Plan`，`ldap.go:317-434`）

```
SYN(up) → SYN-ACK(down) → ACK(up)                        ← 3 帧，恒
for r in 0..rounds-1:                                     ← rounds 轮
    bindRequest(rb)      (up)
    bindResponse(rb)     (down)
    searchRequest(rb+1)  (up)
    searchResEntry(rb+1) (down)
    searchResDone(rb+1)  (down)                           ← 注意：entry 与 done 同向连续
if unbind != false:
    unbindRequest(base+3(rounds-1)+2) (up)                ← 1 帧，无响应
FIN-ACK(up) → ACK(down) → FIN-ACK(down) → ACK(up)         ← 4 帧，恒
```

**包数公式（`packet_count`，实测与 JSON 22/22 一致）**：
`packet_count = 3 + rounds × 5 + [unbind 时 1] + 4 = 7 + 5×rounds + [unbind]`。
校验：T-1（rounds=1，unbind 发）→ 7+5+1 = **13** ✓；T-4（rounds=1，unbind 抑制）→ **12** ✓；T-3/T-11（rounds=2，unbind 发/抑制）→ 7+10+1 = **18** / 7+10 = **17** ✓；T-14（rounds=2，抑制）→ **17** ✓。

### 5.3 自动派生规则（逐条列触发条件与内容，不依赖隐含知识）

| # | 派生帧 | 触发条件 | 内容 |
|---:|---|---|---|
| 1 | SYN / SYN-ACK / ACK | 恒 | flags 0x02/0x12/0x10；SYN 与 SYN-ACK 带 MSS/WinScale/SACK options |
| 2 | bindResponse | 每个 bindRequest 后 | 同 messageID + LDAPResult（`ResultCode`） |
| 3 | searchResEntry | 每个 searchRequest 后 | 同 messageID + baseDN + 每属性一个 PartialAttribute |
| 4 | searchResDone | 每个 searchResEntry 后 | 同 messageID + LDAPResult（`ResultCode`） |
| 5 | unbindRequest | `cfg.Unbind == nil \|\| *cfg.Unbind` | messageID `base+3(rounds-1)+2`；**无响应** |
| 6 | FIN 四帧 | 恒 | flags 0x11/0x10/0x11/0x10 |
| 7 | 分段 | 消息长 > MSS | 按 MSS 切块，各为 PSH-ACK |

**缺省化规则（`Plan` 内二次应用，`ldap.go:300-313`）**：① `spec.DstPort == 0` → **389**；② `Rounds <= 0` → **1**；③ `MessageIDBase == 0` → **1**；④ `Version == 0` → **3**；⑤ `SearchFilter == ""` → `"objectclass"`；⑥ `Attributes == nil` → 15 个 RootDSE 属性；⑦ `Unbind == nil` → 发；⑧ `TTL == 0` → 64；⑨ `MSS == 0` → 1460。
> **注意 ①③ 的双份缺省**：`Validate` 收到的是 `spec` 的**值拷贝**（`ldap.go:296` 注释明写"Validate sees a value copy, so defaults applied there are lost for Plan"），故 `Plan` 必须重复应用——这是**有意的**（两处都读同一份缺省规则），不是重复代码缺陷。

### 5.4 驱动与交互规格（raw 自驱，与 radius 对称）

**配置 → 帧的完整路径**：

```
层链 JSON {layers:[{ip:{...}},{ldap:{...}}]}
  → ValidateLayers（registry Fields 15 键 allowlist + 类型/范围）
  → chain_planner_translate.go:2781 core.ParseLDAPConfigFromMap(term.Config) → spec.LDAP
  → ChainPlanner.ValidateSpec → validateSpecBase（IP 解析/同族检查）
      → protocolValidator("ldap") → (&Planner{}).Validate(spec)   [7 锚]
  → isRawIPChain("ldap", [ip,ldap]) == true（chain_planner_util.go:40）
  → chain_planner.go:1518 meta.LDAP = spec.LDAP（raw-IP drive 分支）
  → LDAPGenerator.Generate（layer_gen.go:30-62）
      → NewPlanner().Plan(ctx, spec) → configChan（PacketConfig 流）
      → 逐包 pkt.Direction = "up" 后 req.Emit(pkt)               [防双换]
  → worker → writer（PCAP/NIC）
```

**防双换（本协议 raw 链的核心机制，`layer_gen.go:56`）**：legacy `Plan` 已对方向在**包内部**完成 MAC/IP/端口换向并置 `Direction="down"`；raw-IP drive 的 `Emit` 包装对 `"down"` 包会**再换一次** L3 地址（`chain_planner.go:1546-1548`）。生成器统一把每包 `Direction` 改写为 `"up"` 后转 `Emit`——**L3/L4 保持 legacy 换向结果**（不再被换第二次），**L2 MAC/EtherType 保持 legacy 写入值**（非空，drive 的回填分支 `pkt.L2.SrcMAC == ""` 跳过）。语义与 legacy 扁平路径**逐字节一致**。

**诚实声明（与 opcua 事件面范本的差异）**：ldap 的 `GenEvents()` **恒返回 nil**（`layer_gen.go:27`）——它**不走事件面**，而是走 raw 自驱（生成器直接产完整 `PacketConfig`）。故 §5.2 的事件序是**生成器内部剧本**，不是框架事件序列（`events[]`）。这是 raw 自驱族（radius/rtmp/rtsp/pptp/vnc/xmpp/sctp/jt808/jt809/jtt905/pppoe/arp/icmp/igmp/ospf/pim/nvgre/srv6/icmpv6/h323/mpls/ngap/telnet/sip）的**统一形态**，非本协议特有。

**多会话展开**：本协议**无 `sessions[]` 结构**——`rounds` 是**同连接内的多轮**（不是多会话）。多会话由策略级 `flow_control {"flows": N}` 承载（worker 逐流注入四元组），本版 22 例全单流。

## 6. 性能设计与验收（CORE_MEMORY §6）

- **目标与边界**：单流全链 ≤18 帧（rounds=2 + unbind，含握手挥手）；**最大单消息 = searchResEntry（15 属性）= 801B**；**最大以太帧 = 855B**（同上，IPv4）；最小帧 = 握手 ACK（54+20 = 74B）；最大测试量级 = 100×20 属性 searchRequest **2251B**（单测 `TestPlan_BigAttributes`）。吞吐数字待 P4 基准，**本版不写承诺**（§6.5）。
- **依据**：`Plan` 是**流式**（`configChan` 缓冲 256，逐包 `select { case configChan <- cfgOut; case <-ctx.Done() }`，`ldap.go:385-388`）——**不聚合全量包**；每轮 BER 消息按需构造（局部变量，无跨轮缓存）；无跨流共享状态；无锁（全部局部变量 + `crypto/rand` 单次调用）。
- **验收两路（§6.3 强制）**：pcap（`<id>.pcap` / 负例 `<id>.neg.pcap`）与 NIC（`enp135s0f0np0`，`nic_capture` 开关）共用同一断言集；断言实际 `tcp.dstport`/`tcp.flags` 值与**帧原始 hex**，不只断言"任务没报错"。
- **六类场景落点（§6.6）**：基线（T-1，13 帧）/ 目标规模（T-3，18 帧 rounds=2）/ 压力上限（`TestPlan_BigAttributes` 2251B + `TestPlan_MSSSegmentation` 4 段）/ 长时间运行（rounds 多轮展开承载语义）/ 并发交错（顺序多轮承载语义，并发路径为例外不启用）/ 背压（`packet_count` 精确计数守卫帧数漂移）。
- **容量约束**：`configChan` maxsize 256（有界，防无界增长）；`MaxMessageID=0x7FFF` 限制 `rounds ≤ 10922`（`base=1` 时 `3(rounds-1)+2 ≤ 32767`）；`ResultCode ≤ 127`（`Validate` 检查）。

## 7. 错误处理（负例锚词表，与 testcase §4 一一对应、同序）

以下输入必须被拒绝并传播为 task error，不得产出成功 PCAP、`completed/0 packet` 或只剩 TCP 外壳的假成功：

| # | 负例 ID | 故障输入 | 代码锚词（逐字） | 代码行 |
|---:|---|---|---|---|
| N-1 | `ldap_neg_version_invalid` | `version: 4` | `ldap: invalid version %d (allowed: 2, 3)` | `ldap.go:94-96` |
| N-2 | `ldap_neg_scope_invalid` | `search_scope: 3` | `ldap: invalid scope %d (allowed: 0, 1, 2)` | `ldap.go:97-99` |
| N-3 | `ldap_neg_filter_type_invalid` | `filter_type: "substring"` | `ldap: invalid filter type %q (allowed: present, equality)` | `ldap.go:100-102` |
| N-4 | `ldap_neg_result_code_range` | `result_code: 128` | `ldap: result_code %d out of ENUMERATED range (0-127)` | `ldap.go:103-105` |
| N-5 | `ldap_neg_size_limit_negative` | `size_limit: -1` | `layers: layer "ldap" field "size_limit" = -1 invalid: out of range [0,2147483647]` | **`complete.go:325`**（非 ldap.go，见下） |
| N-6 | `ldap_neg_message_id_overflow` | `message_id_base: 32767, rounds: 2` | `ldap: message id %d exceeds 0x7FFF` | `ldap.go:120-122` |

**N-5 的锚词来源是本协议最特殊的一条（G-LDAP-7，confirmed finding）**：`size_limit: -1` **不由 ldap validator 拒绝**——`Planner.Validate` 的 `cfg.SizeLimit < 0` 分支（`ldap.go:106-108`，锚词 `ldap: size_limit must be >= 0`）在**层链路径不可达**。层链路径上 registry schema 声明 `"size_limit": {Type:"int", Min:0, Max:2147483647}`（`registry.go:1899`），`ValidateLayers → ValidateLayerConfig` 先于 translate 执行，负值在 `complete.go:325` 被判死（锚词含 `size_limit` 与 `out of range`）。
**即：`error_contains: "size_limit"` 同时命中两个不同来源**——层链路径命中 `complete.go:325`，引擎直调路径命中 `ldap.go:107`。用例今日在层链路径执行，**实际锚词来自 `complete.go:325`**。本设计如实登记两处，**不声称 ldap validator 覆盖该输入**。
> 同族对照：`time_limit: -1`（`ldap.go:109-111` 分支）**今日零用例**，且层链路径同样先被 `complete.go:325` 拦（registry `Min:0`）→ A′ 立项（G-LDAP-8）。

**未入用例的拒绝分支（A′ 立项，不得冒充已覆盖）**：

| 分支 | 锚词 | 行 | 层链路径可达性 |
|---|---|---|---|
| `size_limit < 0`（ldap validator 面） | `ldap: size_limit must be >= 0` | `ldap.go:106-108` | **不可达**（`complete.go:325` 先拦，G-LDAP-7） |
| `time_limit < 0` | `ldap: time_limit must be >= 0` | `ldap.go:109-111` | **不可达**（同上，G-LDAP-8） |
| `LDAP == nil` | `ldap config is required` | `ldap.go:89-91` | **不可达**（translate 恒产非 nil，`chain_planner_translate.go:2781`） |
| `SrcIP` 非法 | `invalid source IP: %s` | `ldap.go:79-83` | **不可达**（层链 IP 由 `validateSpecBase` 先验） |
| `DstIP` 非法 | `invalid destination IP: %s` | `ldap.go:84-88` | **不可达**（同上） |
| `berInt` 的 `00` 前置分支 | —（编码分支非拒绝） | `ldap.go:141-143` | **不可达**（`MaxMessageID=0x7FFF` 保证，§3.2） |

**不得误报的合法协议事件**：`rounds=2` 多轮（T-3/T-11/T-14）；`unbind: false`（T-4/T-11/T-12/T-13/T-14）；`result_code=49`（T-10）；`attributes` 自定义（T-12）；`search_base_dn` 非空（T-15）；`version=2`（T-6）。

**负例语义**：6 例均为 **Validate 阶段拒绝、零包**（非"字节仍能发出靠 tshark 捕获"）。存量 6 例 `expect` 键集合 = `{expect_error, error_contains, notes}`（**含 `notes`，非严格两键**，G-LDAP-9）。

## 8. 边界

- **帧长**：最小 = 握手 ACK **74B**（54+20，无载荷）；最大 = searchResEntry(15 属性) 以太帧 **855B**（54+801）；最大单测 = searchRequest(100×20 属性) **2251B BER / 2305B 以太帧**。
- **BER 长度编码**：primitive 值在 **128 字节**处切换短形↔长形（`berPrim`，`ldap.go:160-169`）；constructed 值**恒长形**（`berWrap`，`:151-156`）。**边界相邻值 127/128 今日无例**（A′ 立项，G-LDAP-10）——可用 `bind_dn` 长度 120/121（密码 0）精确构造。
- **messageID**：`[1, 0x7FFF]`；`base=0` → 1；上限检查 `base+3(rounds-1)+2 ≤ 0x7FFF`。**`mid ≥ 128` 的 4 字节 INTEGER 编码今日无例**（A′ 立项，G-LDAP-10）。
- **version**：只接受 `0`（缺省 3）/`2`/`3`（`ldap.go:94-96`）；RFC 4511 §4.2.1 值域 `(1..127)`，本实现**收窄到 {2,3}**。
- **scope**：只接受 0/1/2（`ldap.go:97-99`）；RFC 4511 §4.5.1.2 可扩展（`...`），本实现**收窄**。
- **resultCode**：`[0,127]`（`ldap.go:103-105`）；RFC 4511 §4.1.9 可扩展，本实现**收窄到 7 位**。
- **filter**：只 `present`/`equality`（`ldap.go:100-102`）。
- **attributes**：`nil` → 15 个缺省；`[]` → **同 nil**（G-LDAP-3）；无 ABNF 校验（`"*"`/`"1.1"` 被当普通名）。
- **端口**：显式/缺省 389（`ldap.go:303-305`）；**层 config 无 `dst_port` 键**（registry Fields 15 键）——用户**无法在 ldap 层写端口**，只能由 `Plan` 缺省。`tcp.dst_port` 显式写（若链含 tcp 层）会走通用 FieldContract 块——但 ldap 是 `[ip,ldap]` 链，**无 tcp 层**。
- **地址族**：`EtherTypeFor(spec.SrcIP)` 自动取 0x0800/0x86DD（`ldap.go:379`）；`validateSpecBase` 拒绝异族混写（`chain_planner.go:886`）。**IPv6 今日无例**（G-LDAP-5）。
- **多轮**：`rounds` 上界由 messageID 检查隐式给出（`rounds ≤ 10922`，`base=1`）。
- 不得产生回绕长度或超量分配（BER 长度由内容一次算定；`configChan` 有界 256）。

## 9. 原子 ID 与完成定义（22 个唯一语义 ID，顺序为权威）

| # | ID | 类型 | 覆盖（设计 §） | packet_count |
|---:|---|---|---|---:|
| 1 | `ldap_session_full` | 正 | §3.2/§3.3/§3.7：全会话 13 帧，六 protocolOp 标签逐帧 | 13 |
| 2 | `ldap_ber_long_form_length` | 正 | §3.1/§3.7：恒长形长度前缀专钉（`30 84`/`60 84`） | 13 |
| 3 | `ldap_message_id_increment` | 正 | §3.3：messageID 递增钉（rounds=2 → 1,4,2,5,3…） | 18 |
| 4 | `ldap_bind_anonymous` | 正 | §3.4.1：匿名 bind（name 空串 + simple 空） | 12 |
| 5 | `ldap_bind_simple` | 正 | §3.4.1：simple bind（DN + 密码入 `80` 标签） | 12 |
| 6 | `ldap_bind_version2` | 正 | §3.4.1：version=2 兼容面 | 12 |
| 7 | `ldap_scope_single_level` | 正 | §3.5.1：scope=1 | 12 |
| 8 | `ldap_scope_whole_subtree` | 正 | §3.5.1：scope=2 | 12 |
| 9 | `ldap_filter_equality` | 正 | §3.5.4：equalityMatch `[3]` 隐式标签 | 12 |
| 10 | `ldap_result_invalid_credentials` | 正 | §3.6：resultCode 49 | 12 |
| 11 | `ldap_rounds_two` | 正 | §5.2：rounds=2 多轮（unbind 抑制） | 17 |
| 12 | `ldap_attributes_custom` | 正 | §3.5.5：自定义 AttributeSelection | 12 |
| 13 | `ldap_unbind_suppressed` | 正 | §5.3 #5：unbind 抑制 | 12 |
| 14 | `ldap_composite_multi_round` | 正 | §4 场景⑧⑨⑪：多轮+equality+bind+自定义属性交织 | 17 |
| 15 | `ldap_search_base_dn` | 正 | §3.5.1：baseObject 显式 | 12 |
| 16 | `ldap_size_time_limit` | 正 | §3.5.1：sizeLimit/timeLimit 两 INTEGER | 12 |
| 17 | `ldap_neg_version_invalid` | 负 | §7 N-1 | —（0 帧） |
| 18 | `ldap_neg_scope_invalid` | 负 | §7 N-2 | —（0 帧） |
| 19 | `ldap_neg_filter_type_invalid` | 负 | §7 N-3 | —（0 帧） |
| 20 | `ldap_neg_result_code_range` | 负 | §7 N-4 | —（0 帧） |
| 21 | `ldap_neg_size_limit_negative` | 负 | §7 N-5（层 schema 门） | —（0 帧） |
| 22 | `ldap_neg_message_id_overflow` | 负 | §7 N-6 | —（0 帧） |

**包数公式校验（机读实测，22/22 一致）**：`pc = 7 + 5×rounds + [unbind]`。
`rounds=1,unbind` → 13（#1/#2）；`rounds=1,!unbind` → 12（#4–#10,#12,#15,#16）；`rounds=2,unbind` → 18（#3）；`rounds=2,!unbind` → 17（#11,#14）。

**T-编号对照**（存量 summary 内嵌的 T 号，非独立 ID）：T-1≡#1、T-2≡#2、T-3≡#3、T-4≡#4、T-5≡#5、T-6≡#6、T-7≡#7、T-8≡#8、T-9≡#9、T-10≡#10、T-11≡#11、T-12≡#12、T-13≡#13、T-14≡#14、T-15≡#15、T-16≡#16、T-负例×5≡#17–#21、T-22≡#22。**无虚号**（与 opcua 旧稿 T4/T8 虚例不同）。

**序号口径（三处一致声明）**：JSON 顺序 = 本表顺序 = testcase §2 顺序。#1 与 #2 的 `spec_json` **逐字节相同**（`{layers:[{ip:…},{ldap:{}}]}`）、#4 与 #13 相同（`{ldap:{"unbind":false}}`）——**同配置不同断言面**，见 testcase §8.3 的覆盖论证。

## 10. P1 规范矩阵（CORE_MEMORY §4 八项：规范要求→业务场景→代码现状→缺口）

### 10.1 八项规范矩阵

| # | 八项 | 规范要求 | 业务场景 | 代码现状 | 缺口 |
|---:|---|---|---|---|---|
| 1 | 连接模型 | TCP 客户端主动建连（RFC 4511 §3）；LDAP 会话随连接建立/终止 | 场景①–⑫ | `DependsOn ["ip"]` 单值（`registry.go:1890`）；**自建 TCP**（`ldap.go:402-433`） | 无 |
| 2 | 命令/消息表 | LDAPMessage 信封 + protocolOp CHOICE 24 类（§4.1.1） | 场景①–⑫ | **实现 6 类**（bind 请求/响应、unbind、search 请求/entry/done）；其余 18 类不实现（§1 边界⑤） | G-LDAP-11（操作族覆盖） |
| 3 | 状态机 | 匿名→绑定→操作（§3 协议模型） | 场景①⑧ | **无状态机校验**（剧本回放，§5.1 诚实声明） | G-LDAP-6 |
| 4 | 字段表 | LDAPMessage 2 键 + BindRequest 3 键 + SearchRequest 8 键 + LDAPResult 3 键 + Filter 10 支 | 数据场景层 | `berInt`/`berWrap`/`berPrim` 三原语 + 8 个 builder 逐字段（§3） | 无 |
| 5 | 错误处理 | 6 类负例 + 6 个未入例分支（§7） | 负例 N-1…N-6 | `Validate` 7 分支（`ldap.go:79-123`）+ 层 schema 范围门 | A′ 6 条（§14） |
| 6 | 超时与活性 | sizeLimit/timeLimit 是**服务端**约束，非心跳；LDAP 无协议级保活 | 场景⑩ | `size_limit`/`time_limit` 已落码（`ldap.go:250-251`）；**无保活** | 无（§14 G-LDAP-12 登记 3.15③） |
| 7 | NAT/代理/被动 | 无被动模式概念（客户端直连） | — | 无 `sessions[].src_port`；多流走策略级 `flow_control` | **显式不适用**被动模式 |
| 8 | 版本/方言 | LDAPv3（§1）；v2 兼容面 | 场景④ | `version` 二值 {2,3}（`ldap.go:94-96`）；缺省 3 | 无 |

**逐行重数（缺口列口径）**：8 行 = **覆 5 行**（#1/#4/#6/#7/#8——#7 的"显式不适用"写在缺口列但**非缺口**，故计入覆）+ **立项 3 行**（#2 G-LDAP-11 / #3 G-LDAP-6 / #5 A′ 6 条）+ **不适用 0 行**。**5 + 3 + 0 = 8** ✓

### 10.2 子表①：操作 × 终态矩阵（逐格已覆/立项/不适用）

| 操作 | T1 正常终态 | T2 配置拒绝 | T3 RST 异常终态 |
|---|---|---|---|
| bindRequest/Response（匿名） | 已覆（#4） | 已覆（#17 代表例，拒绝与操作无关） | A′ 立项（G-LDAP-13） |
| bindRequest/Response（simple） | 已覆（#5） | 同上代表已覆 | A′ 立项（G-LDAP-13） |
| bindRequest（version2） | 已覆（#6） | 同上代表已覆 | A′ 立项（G-LDAP-13） |
| searchRequest（scope 0/1/2） | 已覆（#1/#7/#8） | 已覆（#18 scope 拒） | A′ 立项（G-LDAP-13） |
| searchRequest（present filter） | 已覆（#1） | 已覆（#19 filter 拒） | A′ 立项（G-LDAP-13） |
| searchRequest（equality filter） | 已覆（#9） | 同上代表已覆 | A′ 立项（G-LDAP-13） |
| searchResEntry | 已覆（#1） | 不适用（无配置面） | A′ 立项（G-LDAP-13） |
| searchResDone | 已覆（#1） | 同上代表已覆 | A′ 立项（G-LDAP-13） |
| unbindRequest | 已覆（#1） | 已覆（#13 抑制面） | A′ 立项（G-LDAP-13） |
| LDAPResult 错误码 | 已覆（#10） | 已覆（#20 resultCode 拒） | 不适用（错误码非传输异常） |
| 其余 18 类 protocolOp | 不适用（不实现） | 不适用（不实现） | 不适用（不实现） |

**逐格重数（逐格清点，不靠减法）**：11 行 × 3 列 = **33 格**。
- T1 列：行 1–10 已覆 = **10**；行 11 不适用 = 1。合计 11 ✓
- T2 列：行 1/2/3/4/5/6/8/9/10 已覆 = **9**；行 7 不适用 = 1；行 11 不适用 = 1。合计 11 ✓
- T3 列：行 1–9 A′ 立项 = **9**；行 10 不适用 = 1；行 11 不适用 = 1。合计 11 ✓

**总账**：已覆 **19**（10 + 9）/ A′ 立项 **9** / 不适用 **5**（1 + 2 + 2）。**19 + 9 + 5 = 33** ✓

### 10.3 子表②：数据形态变体表（协议相关全部形态逐项）

| # | 变体 | 落点 |
|---:|---|---|
| 1 | `rounds=1`（缺省） | 覆（#1/#2/#4–#10/#12/#13/#15/#16） |
| 2 | `rounds=2` | 覆（#3/#11/#14） |
| 3 | `rounds=0`（缺省化 → 1） | 覆（全正例的隐含路径——`Plan` 缺省分支 `:307-309`） |
| 4 | `rounds` 大值（messageID 上界） | A′ 立项（`ldap.go:120-122`，`rounds ≤ 10922` 今日无例） |
| 5 | `message_id_base` 缺省（0 → 1） | 覆（全正例） |
| 6 | `message_id_base` 非缺省 | 覆（#22 输入面）；**正例无** → 补面立项（G-LDAP-10） |
| 7 | `version` 缺省（0 → 3） | 覆（#1/#2/#3/#4/#5/#7–#16） |
| 8 | `version=2` | 覆（#6） |
| 9 | `version` 非法 | 覆（#17） |
| 10 | `bind_dn` 缺省（空 = 匿名） | 覆（#4/#13） |
| 11 | `bind_dn` 非空 | 覆（#5/#14） |
| 12 | `bind_password` 缺省（空） | 覆（#4） |
| 13 | `bind_password` 非空 | 覆（#5/#14） |
| 14 | `bind_dn`+`bind_password` 长度 ≥128（长形 primitive） | A′ 立项（G-LDAP-10，**短形↔长形边界今日无例**） |
| 15 | `search_base_dn` 缺省（空 = RootDSE） | 覆（#1/#2/#4–#14/#16） |
| 16 | `search_base_dn` 非空 | 覆（#15） |
| 17 | `search_scope=0`（缺省） | 覆（#1） |
| 18 | `search_scope=1` | 覆（#7） |
| 19 | `search_scope=2` | 覆（#8） |
| 20 | `search_scope` 非法（3 / -1） | 覆（#18；`-1` 由层 schema `Min:0` 拦，同 N-5 口径） |
| 21 | `size_limit=0`（缺省） | 覆（#1） |
| 22 | `size_limit=10` | 覆（#16） |
| 23 | `time_limit=0`（缺省） | 覆（#1） |
| 24 | `time_limit=60` | 覆（#16） |
| 25 | `size_limit` 负 | 覆（#21，层 schema 门） |
| 26 | `time_limit` 负 | A′ 立项（G-LDAP-8） |
| 27 | `filter_type` 缺省（present `objectclass`） | 覆（#1） |
| 28 | `filter_type="present"` 显式 | A′ 立项（机读实测：**今日无例显式写 `"present"`**——缺省路径覆了同一分支，但**显式串未测**） |
| 29 | `filter_type="equality"` | 覆（#9/#14） |
| 30 | `filter_type` 非法 | 覆（#19） |
| 31 | `search_filter` 缺省（`objectclass`） | 覆（#1） |
| 32 | `search_filter` 非缺省 | 覆（#9 `uid`、#14 `sAMAccountName`） |
| 33 | `filter_value` 缺省（空） | 覆（#1 的 present 路径不用该值）；**equality + 空 value 今日无例** → 补面立项（G-LDAP-10） |
| 34 | `filter_value` 非空 | 覆（#9/#14） |
| 35 | `attributes` 缺省（15 RootDSE） | 覆（#1/#2/#3/#4–#11/#13–#16） |
| 36 | `attributes` 自定义 2 元素 | 覆（#12/#14） |
| 37 | `attributes` 显式空 `[]` | **不可表达**（G-LDAP-3，`parseStringList` 归 nil） |
| 38 | `attributes` 100×20（长度上界） | 单测覆（`TestPlan_BigAttributes`）；**用例无** → 补面立项（G-LDAP-10） |
| 39 | `result_code=0`（缺省） | 覆（全正例除 #10） |
| 40 | `result_code=49` | 覆（#10） |
| 41 | `result_code` 越界（128） | 覆（#20） |
| 42 | `result_code` 边界相邻（127） | A′ 立项（G-LDAP-10） |
| 43 | `unbind` 缺省（发） | 覆（#1/#2/#3） |
| 44 | `unbind=false`（抑制） | 覆（#4–#14/#15/#16） |
| 45 | IPv4 载体 | 覆（全 22 例） |
| 46 | IPv6 载体 | A′ 立项（G-LDAP-5，`EtherTypeFor` 支持但无用例） |
| 47 | MSS 跨分段 | 单测覆（`TestPlan_MSSSegmentation`）；**用例无** → 补面立项（G-LDAP-10） |
| 48 | 异族混写（v4 src + v6 dst） | A′ 立项（`chain_planner.go:886` 有分支） |

**逐行重数（逐行清点，口径明写）**：48 行 = **覆 36 行** + **A′ 立项 11 行** + **不可表达 1 行**（行 37）。
- **覆 36 行**：行 1/2/3/5/7/8/9/10/11/12/13/15/16/17/18/19/20/21/22/23/24/25/27/29/30/31/32/34/35/36/39/40/41/43/44/45。
- **A′ 立项 11 行**：8 行**纯立项**（行 4/14/26/28/42/46/47/48——今日该形态零用例）+ 3 行**"覆 + 补面"复合行**（行 6 `message_id_base` 非缺省只有负例输入面、行 33 `filter_value` 空只有 present 路径、行 38 `attributes` 100×20 只有单测——**主分类按"待补面"计立项**，其已覆面在行内注明）。
- **不可表达 1 行**：行 37（`attributes: []`，G-LDAP-3）。

**36 + 11 + 1 = 48** ✓（**无重复计数**：每行只按主分类计一次）

### 10.4 子表③：商业行为→用例映射表

| # | 商业行为（出处） | 用例映射 | 结论 |
|---:|---|---|---|
| 1 | AD RootDSE 探测（参考 pcap 形） | #1/#2 | 已覆 |
| 2 | 匿名 bind | #4 | 已覆 |
| 3 | 服务账号 simple bind | #5/#14 | 已覆 |
| 4 | LDAPv2 兼容 | #6 | 已覆 |
| 5 | 层级遍历（scope） | #7/#8 | 已覆 |
| 6 | 属性值精确定位 | #9/#14 | 已覆 |
| 7 | 认证失败分支 | #10 | 已覆 |
| 8 | 长会话多轮查询 | #3/#11/#14 | 已覆 |
| 9 | 按需索取栏位 | #12/#14 | 已覆 |
| 10 | 分页/限流 | #16 | 已覆 |
| 11 | 指定子树搜索 | #15 | 已覆 |
| 12 | 不发 unbind 直接关 | #13 | 已覆 |
| 13 | SASL/GSS-API 认证（AD 现网主流） | — | **明确不解决**（§1 边界①） |
| 14 | startTLS 升级 | — | **明确不解决**（§1 边界⑥） |
| 15 | Modify/Add/Delete 写操作 | — | **明确不解决**（§1 边界⑤） |
| 16 | 分页控制（pagedResultsControl） | — | **明确不解决**（§1 边界④ Controls） |
| 17 | 引用跟踪（referral） | — | **明确不解决**（§1 边界⑧） |
| 18 | LDAPS（636/TLS） | — | **明确不解决**（传输替代，非本层） |

12 覆 + 6 不适用 = 18 ✓ 无映射无确认即缺口——本表零缺口。

### 10.5 三路对照与候选方案对比

三路：①**规范原文**（RFC 4511，本机拉取原文逐节引用——§3 各表的章节号与 ASN.1 定义均来自原文，非记忆）；②**商业化软件实际行为**（**部分取到**：参考 pcap 是 AD 客户端的真实会话，其 BER 恒长形习惯被本实现镜像，§3.1；**但完整字节未取到**——参考 pcap 文件不在本仓，G-LDAP-14）；③**可靠开源实现思路**（OpenLDAP `liblber` 的 `ber_printf` 长度编码、Go `go-asn1-ber` 的 `Encode`——只借鉴"constructed 用长形更省心"这一条思路，未取代码）。

三路一致点：LDAPMessage 信封布局、protocolOp 标签值、messageID 配对语义、Filter present/equality 编码。不一致点：**长度编码形态**——规范允许短形（内容 <128B 时短形是**规范推荐**的最小编码），本实现为镜像 AD 客户端而**恒用长形**（§3.1）。**这是刻意的非最小编码**，不违反 BER（长形是合法编码），但**不是最短编码**。

| 方案 | 走法（借鉴来源） | 取舍 | 结论 |
|---|---|---|---|
| A | **独立 `ldap` raw 自驱终结层**（本版；radius/rtmp/rtsp 同构先例） | 自建 TCP + BER 消息面全套，wire 字节完全可控；代价 = 一套层（已落码 1077 行） | **采用** |
| B | 复用 tcp 层 + 顶层 payload | 无 bind/search 语义、无 messageID 配对、无 BER 结构 → 22 例中 20 例不可表达 | **否决** |
| C | 拆成"TCP 载体层 + BER 消息层"两层 | BER 层需读 TCP 层的 seq/MSS 状态，框架层间无此通道（raw 自驱族统一结论） | **否决** |

## 11. P2 D-LDAP-1 代码设计（CORE_MEMORY §8 八要素；as-built 逆向定稿）

> 状态说明：实现已落码（`internal/protocol/ldap/` 三文件 1077 行 + 接线 6 处），本 P2 条目为文档轨对既有实现的**逆向定稿**（as-built 定稿），供门1 批准后作为后续改动的唯一入口。

### 11.1 文件清单（实测，非计划）

| 文件 | 职责 | 行数 |
|---|---|---:|
| `trafficgen/internal/core/types.go`（`:8921-8967` + `:1860`） | `LDAPConfig`（15 字段）+ `FlowSpec.LDAP` 槽位 | —（共享文件） |
| `trafficgen/internal/protocol/ldap/ldap.go` | BER 三原语 + 8 个 builder + `Validate`（7 分支）+ `Plan`（TCP 自建 + 轮循环） | 498 |
| `trafficgen/internal/protocol/ldap/layer_gen.go` | 终结层生成器（`RegisterLayerGenerator` + `RegisterLayerValidator`，`init()`）+ 防双换 | 73 |
| `trafficgen/internal/protocol/ldap/ldap_test.go` | **23 个 `Test*`**（编码面 13 + Plan 面 8 + Validate 面 2） | 506 |
| `trafficgen/internal/core/layers/ldap_chain_test.go` | 链级 2 例（raw 链 18 包形状 + 7 锚背 door） | 92 |
| 接线 6 件 | registry 注册（`layers/registry.go:1890`，Fields 15 键）/ translate 层内分支（`chain_planner_translate.go:2775`）/ convert 子配置搬运（`strategy_convert.go:1309`）/ protocols 准入（`protocols.go:46`）/ `isRawIPChain` 名单（`chain_planner_util.go:47`）/ 端口 0 豁免（`chain_planner.go:748`）+ `CheckProtoFlat` presence（`strategy_convert.go` `rawWrapChains`） | — |

### 11.2 接口签名

- `Validate(spec core.FlowSpec) error`（`ldap.go:78`）：IP 解析 → `LDAP==nil` 拒 → version 枚举 → scope 范围 → filter_type 枚举 → result_code 范围 → size/time_limit 非负 → messageID 上限。
- `Plan(ctx, spec) (<-chan core.PacketConfig, error)`（`ldap.go:295`）：`Validate` 前置 → 缺省化 → goroutine 流式产包。
- 生成器：`Name() "ldap"`；`GenEvents()` **返回 nil**（raw 自驱，不走事件面）；`Generate` 逐包改写 `Direction="up"` 后 `req.Emit`（`layer_gen.go:30-62`）。
- 注册（`layer_gen.go:64-73`）：`RegisterLayerGenerator("ldap", …)` + `RegisterLayerValidator("ldap", …)`（后者不注册则链上 7 锚全漏，pppoe 决策 G 同款）。

### 11.3 数据结构

`LDAPConfig{Rounds int, MessageIDBase uint16, Version int, BindDN string, BindPassword string, SearchBaseDN string, SearchScope int, SizeLimit int, TimeLimit int, FilterType string, SearchFilter string, FilterValue string, Attributes []string, ResultCode uint8, Unbind *bool}`（`types.go:8938-8967`，15 字段 = registry Fields 15 键**逐键一致**）。
> `Unbind` 是**三态指针**：`nil` = 发（缺省）；`&false` = 抑制；`&true` = 发。JSON 解析在 `parseLDAPConfig`（`strategy_convert.go:5714-5717`）：只在键存在且为 bool 时置指针。

### 11.4 主流程

层链配置 → `ValidateLayers`（registry Fields 15 键 allowlist + 类型/范围）→ translate（`core.ParseLDAPConfigFromMap` → `spec.LDAP`）→ `validateSpecBase`（IP 解析/同族）→ `protocolValidator("ldap")`（`Planner.Validate`，7 锚）→ `isRawIPChain` → `meta.LDAP` → `LDAPGenerator.Generate` → `Plan`（自建 TCP 握手 → rounds 轮 bind/search → unbind → 挥手，逐包 `Direction="up"` 转发）→ worker → writer（PCAP/NIC）。

### 11.5 错误分支

`Validate` 7 分支（`ldap.go:79-123`）中 **4 个在层链路径可达**（version/scope/filter_type/result_code，对应用例 #17–#20）；**3 个不可达**（`LDAP==nil`、`SrcIP`/`DstIP` 非法——层链 IP 由 `validateSpecBase` 先验）；**2 个被层 schema 门抢拦**（`size_limit`/`time_limit` 负值，`complete.go:325` 先于 translate）→ §7 逐条登记。
全部拒绝均传 task error（零假成功——6 负例零包）。

### 11.6 性能边界

见 §6（流式 `configChan` 缓冲 256、每轮局部构造、无跨流共享、无锁；吞吐数字待 P4 基准）。

### 11.7 与现有逻辑的冲突点

- **`CheckProtoFlat` 有 ldap 分支**（`rawWrapChains` 表 `"ldap": "[ip,ldap]"`）：顶层 `ldap` 子映射 presence **判死**（空 map 也死）。与 opcua（无分支，G-OPCUA-1）**不同**——本协议该门**已合**。但**顶层未知游离键通用门仍缺**（如 `{layers:[…], bogus: 1}` 今日不判死）→ G-LDAP-15（禁加单协议黑名单分支，等框架级 unknown-key 白名单，kingbase 记忆裁定）。
- **动态 allowlist（`internal/core/layer_dyn.go`）**：`ldap` **零命中**实测（`grep -n ldap layer_dyn.go` 无输出）→ 业务字段动态对象即拒（`field X does not support dynamic`）；四元组 `ip`/`tcp`/`udp`/`eth` 全开。见 §12.12。
- **registry `ldap` 有 Fields 15 键** → 层内 15 键今日全部可住；但**端口无位**（Fields 无 `dst_port`）——用户无法在层内写端口，只能由 `Plan` 缺省 389（G-LDAP-16 登记为"设计选择"而非缺口，理由见下）。
- **`src_port` 无位**：链路径无 tcp 层，worker 保底 `12345+i`。**这是本协议端口语义的完整形态**（特殊性 #5），不是缺口。

### 11.8 回滚方式

本协议文件独立成包，回滚 = revert 本协议 3 文件 + 接线 6 处（registry/protocols/translate/convert/isRawIPChain/validateBaseDstPortHandled）；不触及其他协议。cases 回滚 = 恢复 22 例 JSON（产物文件，非文档）。

## 12. 门1 §1–§14 十四行对照表（CORE_MEMORY §15.1–15.3）

| § | 本协议怎么满足 | 证据 |
|---|---|---|
| §1 层链唯一真相 | 见 §12.1 强制展开：存量 22/22 顶层 = `{layers}` **仅此一键，零残留**；目标形状见 §2 样例且**存量已达标**（本协议无迁移工作量） | §12.1；`cases/ldap.json` 机读实测 |
| §2 策略/任务 | 策略 = 单 ldap 流量模板；任务 = 多策略合跑 + 总量封顶；框架语义未动 | 设计 §2 样例 |
| §3 五件套 | 见 §12.3 强制展开：会话表/事务序列/关联（无派生流诚实声明）/插入位置（raw 自驱终结层）/时间线。**有长连接（TCP），不豁免** | §12.3 + §5 |
| §4 查规范 | RFC 4511 原文（本机拉取，逐节引用）+ RFC 4512/879/6528 + tshark 3.6.14 字段表与自建探针 pcap 实测 + 落码反推；八项矩阵 + 子表①②③ | §10 |
| §5 依赖与错误 | `DependsOn ["ip"]` 单值（`registry.go:1890`）；7 拒绝分支（4 可达 + 3 不可达）；失败传 task error（6 负例零包） | §5/§7/§11.5 |
| §6 性能 | 见 §6（要素齐；吞吐数字标待 P4 基准，不写承诺；pcap/NIC 两路验收明写） | §6 |
| §7 三份文档 | `111-ldap-{design,testcase}.md`（本版）+ D-LDAP-1（§11，as-built 定稿）+ T-LDAP（testcase §2，22 ID） | 修订记录 |
| §8 设计先行 | 本版为 as-built 文档轨（批次二口径：代码/cases 已存在，文档如实写成契约）；门1 获批 = D-LDAP-1 定稿 | 提交序 |
| §9 测试三源 | 三源 = RFC 4511 原文（§10）+ D-LDAP-1（§11）+ tshark 3.6.14 字段表与**自建探针 pcap 实测**（§1.3，六字段逐条实证）；22 ID 逐项回指；存量 22 例审计去向 testcase §8 | `111-ldap-testcase.md` §2/§5/§8 |
| §10 评审闭环 | 每阶段对抗自重审（结论见本文 §15 修订记录）+ 收官隔离复审；红先绿后 | 自审日志 |
| §11 白话 | 每阶段白话一句先行（见本文首节） | 汇报 |
| §12 动态清单 | 见 §12.12 强制展开：四元组全开（allowlist 实测）；业务字段逐个列开/不开 + 理由；序号算法实读行号 | §12.12 |
| §13 schema 派生 | `ldap` 已在 `registry.go:1890` 注册（**不新增层**）；Fields 15 键与 `LDAPConfig` 15 字段逐键一致（机读实测）；**P4 若改 registry Fields 必须重跑 schemagen** | §11.1 |
| §14 真实流程 | suite 经 MCP 建策略建任务 → 引擎真实生成 → tshark `ldap.*` + frames 双通道 → 先跑后钉 | testcase §7 |

### 12.1 §1 强制展开：旧键去向 + 完整 spec_json 样例

**存量实测（逐例机读，2026-09-29）**：

| 文件 | 例数 | 顶层键分布 | 链形 | 负例 expect 形状 |
|---|---|---|---|---|
| `cases/ldap.json` | 22 | **`{layers}` ×22**（唯一顶层键，**零游离键**） | `[ip,ldap]` ×22 | 6/6 = `{expect_error, error_contains, notes}` |

**旧键去向表（§15.3 要求"每个键写去向"）**：

| 旧键 | 存量出现例数 | 去向 |
|---|---:|---|
| `src_ip` / `dst_ip` | **0** | 已住 `layers[0].ip.{src,dst}`（22/22 显式写 `10.0.0.1`/`20.0.0.1`） |
| `src_port` | **0** | **层内无位**——worker 保底 `DefaultSrcPort+i`（`strategy_convert.go:49`，12345+i）；**用例不断言 srcport**（特殊性 #5） |
| `dst_port` | **0** | **层内无位**（registry Fields 15 键无该键）——由 `Plan` 缺省 389（`ldap.go:303-305`）；用例断 `tcp.dstport=389` |
| `count` | **0** | 走 `flow_control`（本版未用，22 例全单流） |
| 顶层 `ldap` 子映射 | **0** | 已住 `layers[1].ldap`（22/22）；顶层子映射 presence 由 `CheckProtoFlat` `rawWrapChains` **判死**（已合） |
| `strategy_fc` / `flow_control` | **0** | 本协议无多流用例；目标形按需加 |
| `tcp` 层 | **0** | **本协议链形无 tcp 层**（raw 自驱，§2） |

**结论**：**本协议存量 22/22 顶层零残留**——§1 门的动作 = ①**无旧键可删**；②收官自查行「非负例顶层键 = 0」**今日即成立**（机读实测 22/22 顶层仅 `layers`）；③A′ 新增例全部沿用纯 layers 形（testcase §9）。

### 12-P2 判死负例形状（链级红例必含清单①③④）

- ① presence 形状 `{"layers":[…],"ldap":{}}` 今日**会被拒**（`CheckProtoFlat` `rawWrapChains` 有 ldap 分支，锚词 `rejects a top-level ldap sub-config`）——**与 opcua 相反**（opcua 无分支故 P4 不建该例）。**本协议该负例今日可建**，但**存量 22 例中无此例** → A′ 立项（G-LDAP-17）。
- ② 白名单外游离键判死（`unknown field`）今日**无通用门**（§11.7）→ G-LDAP-15，**P4 不建该例**（建了会真绿 = 假通过）。
- ③ 6 负例每条带锚词（已齐，§7）。
- ④ 收官自查「非负例顶层键 = 0」**今日已成立**（§12.1）。

### 12.3 §3 强制展开：五件套

**会话表**：`s1` 单连接基线（22/22 例，各自四元组；`[ip,ldap]` raw 链自建 TCP 握手 → rounds 轮 bind/search → unbind → FIN 四包）。**本协议无 `sessions[]` 结构**——`rounds` 是**同连接内的多轮**（不是多会话），多会话由策略级 `flow_control` 承载（本版未用）。**有长连接载体（TCP）→ 不豁免 §3**，会话表按单连接如实填。

**事务序列**（每事务四件事，CORE_MEMORY §3.4–3.7）：

| 事务 | 前置条件 | 触发动作 | 成功分支 | 失败分支 |
|---|---|---|---|---|
| `t1` bind | TCP 握手完成 | 发 bindRequest（version+name+simple） | 收到 bindResponse（同 messageID）→ 进 `t2` | **不检查 resultCode**（§5.1 非法转移 #2，行为已固化于 T-10） |
| `t2` search | `t1` 完成（**不校验绑定结果**） | 发 searchRequest（baseObject+scope+filter+attrs） | 收到 searchResEntry + searchResDone（同 messageID）→ 下一轮 `t1` 或 `t3` | **不检查 resultCode** |
| `t3` unbind | 末轮 `t2` 完成 | 发 unbindRequest（NULL） | **无响应**（RFC 4511 §4.3）→ FIN | 不适用（单向） |
| `t4` 关闭 | `t3` 完成（或抑制时末轮 `t2` 完成） | FIN-ACK | ACK → FIN-ACK → ACK（4 帧） | 不适用 |

**关联关系**：**无派生流**（诚实声明：单 TCP 连接承载全部操作，无 `driven_by`；search 不派生新连接）。事务间关联标识 = **messageID**（`base+3r+k`，§3.3），响应恒回显。**插入位置**：raw 自驱终结层（`[ip,ldap]`，链中**无 tcp 层**，无中间层）。

**时间线**：消息内严格顺序（`Plan` 串行 `emit`）；轮次顺序展开（`for r := 0; r < rounds; r++`）；**无交错**（`concurrent` 为例外路径，本协议不启用）；**unbind 在末轮后单发**；FIN 四帧恒在末尾。**多会话展开**不适用（无 `sessions[]`）。

### 12.12 §12 强制展开：动态字段清单与序号算法

**四元组五策略全开**（allowlist `internal/core/layer_dyn.go` 头部实测：`ip{src,dst,ttl}` / `tcp{src_port,dst_port}` / `udp{src_port,dst_port}` / `eth{src_mac,dst_mac}`）。本协议链形 `[ip,ldap]` 中可动态住的层 = **仅 `ip` 层**（`src`/`dst`/`ttl`）——**端口无层可住**（无 tcp/udp 层），由 worker 保底 `DefaultSrcPort+i`（`strategy_convert.go:49`）。dst 动态与 389 缺省和平共处（端口不由层表达，无冲突面）。

**业务字段 15 项全关**（allowlist **无 `ldap` 行**，`grep -n ldap layer_dyn.go` **零命中**实测；层内对象值 → `does not support dynamic`）：

| 字段 | 开/关 | 理由（逐项） |
|---|---|---|
| `rounds` | **关** | 轮数=会话结构选择器，逐流变破坏"每流一条会话"语义（同 h323 `scenario` 判） |
| `message_id_base` | **关** | 消息号基址=会话内身份，逐流变无意义（同 telnet `credentials` 判） |
| `version` | **关** | 协议版本=联结身份，逐流变会产出混版会话 |
| `bind_dn` / `bind_password` | **关** | 认证凭据=会话身份（telnet `credentials` 同款判） |
| `search_base_dn` | **关** | 查询基准=会话语义，逐流变无现网对应 |
| `search_scope` | **关** | 结构选择器（同 h323 `scenario`） |
| `size_limit` / `time_limit` | **关** | 服务端约束标量，逐流变无意义 |
| `filter_type` | **关** | 结构选择器（CHOICE 分支选择） |
| `search_filter` / `filter_value` | **关** | 查询条件；**逐流变体需求列 A′ 候选**（多用户批量查询场景真实存在），今日按"不冒充覆盖"口径不列为已覆 |
| `attributes` | **关** | **列表无动态形状**（allowlist 只登记标量字段；同 http `request_headers` 判） |
| `result_code` | **关** | 错误注入面（同 opcua `error_inject` 判） |
| `unbind` | **关** | 布尔开关（同 opcua `close` 判） |

**序号算法实读（逐处行号）**：
- allowlist 白名单：`internal/core/layer_dyn.go:20-73`（`layerDynAllowlist`）——**`ldap` 无块**。
- `parseLayerDyn`：`layer_dyn.go:78` 起（对象值 → `*StrategyConfig`；非 allowlist 对象在 `ValidateLayers` 阶段即拒）。
- 逐流解析：`TupleGenerator.Next`（`tuple_generator.go`）+ worker `resolveLayerTuple(i)`。
- 保底自增：`strategy_convert.go:49` `DefaultSrcPort = 12345` + worker 注入 `12345+i`。

**静态复制禁令（§12.9）**：本协议 `flows=N` 且层内无动态时，四元组由 worker 保底 `src_port = 12345+i` 区分（**保底防撞**，非真动态，§12.10 口径）→ **今日无"N 条完全相同四元组"的静默重包**；但**真动态字段零覆盖**（业务 15 键全关）→ G-LDAP-18 登记。

## 13. P3 对接清单（T-LDAP 草稿输入；正文落 testcase 文件）

22 ID（16 正 + 6 负）+ packet_count/锚词 + fixture 常量 + 双通道断言基线 + 存量审计（testcase §2–§5/§8 全量）。

**A′ 候选例（逐条对应 §14 缺口，供主线程登记）**：`ldap_ipv6`（G-LDAP-5）/ `ldap_neg_time_limit_negative`（G-LDAP-8）/ `ldap_neg_presence_toplevel`（G-LDAP-17，`{"layers":[…],"ldap":{}}` 判死——**本协议该门已合，可建**）/ `ldap_ber_boundary_127_128`（G-LDAP-10，短形↔长形边界）/ `ldap_message_id_4byte`（G-LDAP-10，`mid ≥ 128`）/ `ldap_result_code_127`（G-LDAP-10，边界相邻）/ `ldap_attributes_100`（G-LDAP-10，长度上界）/ `ldap_filter_present_explicit`（§10.3 #28）/ `ldap_equality_empty_value`（§10.3 #33）/ `ldap_mss_segmentation`（G-LDAP-10）/ `ldap_abort_rst`（G-LDAP-13）/ `ldap_neg_mixed_family`（§10.3 #48）。

## 14. 缺口立项清单（有缺口写「缺口立项」，不许空着）

| 缺口 | 内容 | 归属阶段 |
|---|---|---|
| G-LDAP-1 | **结果文档过期**：`trafficgen/docs/protocol-pcap-test/ldap.md`（**tracked 产物**）写 `Cases: 22 — pass 22, fail 0, error 0`，末次提交 `064f9b6`（2026-09-20），`docs/protocol-pcap-test/ldap/` **0 个 pcap**（目录不存在）——该 22/22 **未经今日复跑证实，不得作为"今日已复跑"依据**。**ldap 特殊性**：`064f9b6`（2026-09-20）**晚于**判死提交 `0417be5`（2026-09-13），故**不存在** opcua 那种"末次提交早于判死提交"形态；存量 22/22 顶层键仅 `{layers}`，22 例**今日仍应可跑** | **代码阶段**（P5 重跑套件后重生成该产物）；本版**不删不改**（tracked 产物，删除属 P5 动作，此处仅登记事实）。口径与 pcep G-PCEP-11 / opcua G-OPCUA-10 一致 |
| G-LDAP-2 | **entry 值为属性名自身**（合成数据，非真实目录数据）——`buildSearchResEntry` 的 vals 恒 = 属性名（`ldap.go:266-275`） | **明确不解决**（真实目录数据非生成器范围）+ 本设计 §3.5.2 已显式声明；若未来实现真实数据须新增独立例并重算帧长 |
| G-LDAP-3 | **`attributes: []` 不可表达**——`parseStringList`（`strategy_convert.go:5901-5916`）空数组返回 nil，与键缺席同为 15 个缺省属性；`ldap.go:206-207` 注释声称"explicitly empty slice requests no attributes"**经层链 JSON 路径不可达**（仅引擎直调可达）。**confirmed finding** | **P4 裁定**：①改 `parseStringList` 或 ldap 专用解析以区分 `[]` 与缺失；或②删注释、登记"显式空属性不支持"。**A′ 候选**：`attributes: ["1.1"]`（RFC 4511 §4.5.1.8 noattrs，可表达空属性集） |
| G-LDAP-4 | **注释缺省与代码不符**——`types.go:8943-8945` 写 "default MessageIDBase=2423"，实际 `parseLDAPConfig`/`Plan` 都用 `0 → 1`（`ldap.go:310-313`） | **代码阶段**（P4 改注释或改代码；**以代码为准**，本设计 §3.3 已按代码钉） |
| G-LDAP-5 | **IPv6 今日无例**——`EtherTypeFor(spec.SrcIP)` 支持 v6（`ldap.go:379`），链路径 `[ip,ldap]` 的 ip 层可写 v6，但 **22 例全 IPv4** | **A′ 补例** `ldap_ipv6`（offset 74；BER 字节应与 IPv4 完全一致，仅载荷起点变） |
| G-LDAP-6 | **无状态机校验**——非法转移 #1（search 前未 bind）/#2（bind 失败继续 search）在结构上不可达而非被检测拒绝；T-10 固化了"bind 失败仍继续 search"的非规范行为（RFC 4511 §4.2.2 建议终止会话） | **明确不解决**（剧本回放器无状态机）+ 本设计 §5.1 逐条声明。**若未来实现状态机须新增负例并改 T-10 语义** |
| G-LDAP-7 | **N-5 锚词来源非 ldap validator**——`size_limit: -1` 在层链路径由 `complete.go:325`（registry `Min:0`）拦，`ldap.go:106-108` 分支**不可达** | **P4 裁定**：①删除不可达分支；或②保留并登记"仅引擎直调可达"。本设计 §7 已如实登记两处来源 |
| G-LDAP-8 | **`time_limit < 0` 零用例**——`ldap.go:109-111` 分支层链路径不可达（同 G-LDAP-7） | **A′ 补例** `ldap_neg_time_limit_negative`（锚词将来自 `complete.go:325`，与 N-5 同口径） |
| G-LDAP-9 | **负例 `expect` 含 `notes` 键**——6 负例 `expect` = `{expect_error, error_contains, notes}`，与严格两键口径（92-moxa 范式）不同 | **P4 收窄**：删 6 条负例的 `notes` 键 |
| G-LDAP-10 | **边界/上界/分段面零用例**——①BER 短形↔长形边界（127/128）；②`mid ≥ 128` 的 4 字节 INTEGER；③`result_code=127` 边界相邻；④`attributes` 100×20 长度上界（仅单测）；⑤MSS 跨分段（仅单测）；⑥`bind_dn` 长 ≥128（primitive 长形） | **A′ 补例**（6 条，§13 候选清单）；今日**不得冒充覆盖** |
| G-LDAP-11 | **protocolOp CHOICE 24 类只实现 6 类**——Modify/Add/Delete/Compare/Abandon/Extended/ModifyDN 等 18 类未实现（§1 边界⑤） | **明确不解决**（本版范围 = bind/search/unbind 三族）+ 本设计 §1 显式边界；若扩展须新开层能力 |
| G-LDAP-12 | **§3.15③ 长保活**——LDAP 协议层**无保活心跳**；`sizeLimit`/`timeLimit` 是服务端约束非活性探测 | **显式不适用 + 一例**：`rounds=2`（T-3/T-11）作为"同连接内多轮操作"（§3.15①）的落点；§3.15③ 登记为**协议不适用**（不硬凑用例） |
| G-LDAP-13 | **RST 非正常结束补例**（§3.15②后半） | **A′ 补例** `ldap_abort_rst`（`tcp.rst` 框架能力，本层零断言） |
| G-LDAP-14 | **第三源未取全**——参考 pcap 文件不在本仓（仅其编码习惯被镜像，§10.5）；真实 AD/OpenLDAP 服务器线字节未抓包核对 | **待确认**：抓真实 LDAP 服务器包对照；确认前按实现钉、不声称合规 |
| G-LDAP-15 | **顶层未知游离键通用门缺**——`{layers:[…], bogus: 1}` 今日**不判死**（`CheckProtoFlat` 只查五键 + `rawWrapChains` 子映射白名单）→ presence 负例今日建了会真绿 = 假通过，**不建** | **框架面（B′）**：等框架级 unknown-key 白名单（CORE_MEMORY §1.11/§1.13）；**禁加单协议黑名单分支**（kingbase 记忆裁定）。同 opcua G-OPCUA-1 / moxa G-MOXA-2 |
| G-LDAP-16 | **端口无层位**——registry Fields 15 键无 `dst_port`/`src_port`；目的端口只能由 `Plan` 缺省 389，源端口由 worker 保底 12345+i | **设计选择（非缺口）**：raw 自驱族统一形态（radius/rtmp/rtsp/pptp/vnc/xmpp/sctp 同款，`validateBaseDstPortHandled` 豁免名单）。**登记为事实**，不立项；用例不断言 srcport（§12.1） |
| G-LDAP-17 | **presence 判死负例未建**——`CheckProtoFlat` `rawWrapChains` **有 ldap 分支**（与 opcua 相反），故 `{"layers":[…],"ldap":{}}` **今日会被拒**，该负例**可建**但存量无 | **A′ 补例** `ldap_neg_presence_toplevel`（锚词 `rejects a top-level ldap sub-config`）。**注**：`CheckProtoFlat` 无 ldap 专项单测（`grep` 实测零命中，pim/isis/amqp/tds/smb/mmse 等有）→ 本负例同时补该单测空白 |
| G-LDAP-18 | **业务字段动态零覆盖**——allowlist 无 `ldap` 行，15 键全关（§12.12）；`search_filter`/`filter_value` 的多用户批量查询场景真实存在但今日无动态支持 | **A′ 候选**（不冒充已覆盖）；若实现须先开 allowlist 并补 §12.15 五类测试 |
| G-LDAP-19 | **`ldap.*` field 断言零使用**——22/22 例 `fields` 数组只含 `tcp.*`；6 个已实测可用的 ldap dissector 字段（`messageID`/`protocolOp`/`resultCode`/`scope`/`filter`/`attributes`，§1.3）**未被收编** | **A′ 收编**（testcase §6.2）；今日**不是被迫用 frames**，是未收编 |
| G-LDAP-20 | **summary/notes 文案包数错 6 处**——`packet_count` 值**全部正确**，仅文案数字错：`ldap_session_full` summary `挥手4=12 包`→13；`ldap_bind_anonymous` notes `11 包`→12；`ldap_message_id_increment` notes `挥手=17`→18；`ldap_rounds_two` notes `挥手=16`→17；`ldap_unbind_suppressed` summary `11 包`→12；`ldap_composite_multi_round` summary `16 包`→17。**confirmed finding** | **P4 改文案**（6 处）；testcase §8.2 已逐条登记正确值。**注意口径**：机读正则 `(\d+)\s*包` **只命中 4 处**（`ldap_message_id_increment` 的 `挥手=17` 与 `ldap_rounds_two` 的 `挥手=16` 均**无"包"字**），故 **6 处须人读核对，不可只靠正则**——本缺口本身即该教训的实例 |
| G-LDAP-21 | **`ldap_attributes_custom` notes 措辞不准**——原文"消息缩短，长形→短形边界面"；本实现 constructed 值**恒长形**，该例 searchRequest 外层**仍是 `30 84`**（§3.1 复算实测）。变化的是**长度数值**（344 → 37），不是**长度形态**。**confirmed finding** | **P4 改文案**（删"长形→短形"，改"长度数值缩短"） |

**缺口统计**：**21 条**（G-LDAP-1…G-LDAP-21）。其中 confirmed finding **4 条**（G-LDAP-3 `attributes:[]` 不可表达、G-LDAP-7 N-5 锚词来源、G-LDAP-20 文案包数错、G-LDAP-21 notes 措辞不准），**代码阶段** 3 条（G-LDAP-1/G-LDAP-4/G-LDAP-14 待确认），**明确不解决** 3 条（G-LDAP-2/6/11），**框架面 B′** 1 条（G-LDAP-15），**设计选择非缺口** 1 条（G-LDAP-16），**A′ 补例/收编** 9 条（G-LDAP-5/8/9/10/12/13/17/18/19）。
> **归属说明**：G-LDAP-19/20/21 的**证据与逐条清单在 testcase §8.2**（本表给一句话摘要），两份文档的缺口编号**连续且一致**（1…21）。

**对账总账（与 testcase §5.2 同源，逐表清点）**：要求逻辑点 **107** = 八项 8 + 矩阵 33 + 变体 48 + 商业 18；覆盖 **72** + 立项 **23** + 不适用 **12** = 107 ✓

## 15. 修订记录

- v1.0.0（2026-09-29）：批次二 as-built 文档轨 #111。**承同族记忆**（BER 恒长形 / srcport 12345 陷阱 / raw 自驱五件套）逐条落到 §0/§3.1/§12.1/§5.4。规范基线 = RFC 4511 原文（本机 `curl` 拉取 3811 行，逐节引用 §3 各表）；**自建探针 pcap 经 tshark 3.6.14 解码零 malformed**，六字段通道实证（§1.3）；**本机 Python 复算 BER 副本与 JSON frames 断言逐字节一致**（§3.1/§3.7 长度表）。存量 22 例机读审计（**顶层零残留**，本协议无迁移工作量）；包数公式 `7+5×rounds+[unbind]` 与 22/22 一致；门1 十四行齐 + §12.1/§12.3/§12.12 强制展开 + 12-P2；D-LDAP-1 as-built 定稿（§11）；**G-LDAP-3 / G-LDAP-7 两条 confirmed finding**；缺口 G-LDAP-1…G-LDAP-21。**自审 4 轮，末轮干净**（逐轮见 testcase §10 修订记录）：轮 1–2 机读复核（ID/包数/键集合/BER 复算/文案扫描）；轮 3 对账重数**发现 §10.2/§10.3 两处计数错**（矩阵 22→19/8→9/3→5；变体 34→36/13→11）并修正；轮 4 发现 **§10.3 `rounds` 上界算错**（10921→**10922**）+ **G-LDAP-20 漏 1 处文案**（5→**6** 处，正则只认"N 包"、漏 `挥手=17`）并修正。**末轮无新发现**。
