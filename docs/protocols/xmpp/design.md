# #124 xmpp（XMPP · Extensible Messaging and Presence Protocol，RFC 6120/6121，TCP 5222）设计契约

> 版本：v1.0.1（P4 收敛：T-11 summary 3 段校正 + `has_payload` 补齐 + 负例 expect 两键收窄；修订记录见 §15）
> 日期：2026-09-29
> 车道：文档轨（#124 xmpp 首号，**无旧稿基线**——本仓此前从未有过 xmpp 设计文档）
> 旧基线：`docs/protocol-designs/` 下无任何 `*xmpp*` 文件（机读实测）；本版是**首版契约**，不是续号。内部契约 = `docs/CODE_DESIGN.md` D-XMPP-1 条目（`:3179` 起，P1+P2 定稿 2026-09-20），本版为该条目的 as-built 定稿展开
> 存量用例：`trafficgen/test/protocol_pcap/cases/xmpp.json`（**11 例 = 9 正 + 2 负**；**11/11 顶层键仅 `{layers}`，零残留**；层形 `[ip,xmpp]` ×11；本版 §9 与之一一对应，机读实测）
> 规范基线：① **RFC 6120**（XMPP Core：XML 流、SASL 绑定、资源绑定、流关闭）；② **RFC 6121**（XMPP IM：presence、message 节）；③ RFC 4616（PLAIN）/ RFC 2831（DIGEST-MD5）/ RFC 5802（SCRAM-SHA-1）/ RFC 4505（ANONYMOUS）四 SASL 机制；④ 本机 tshark 3.6.14（`xmpp.*` **162 字段**实测、`tcp.port 5222 xm` 绑定在案）；⑤ **9 例实测 pcap**（`/tmp/mcp-pcaps/xmpp/`，2026-09-27 落盘，本车道逐帧复核 46 断言全过）；⑥ 参考现网 pcap（`/home/pcap_auto/llcj_pcap/IP-TCP-10.3.1.89-20.3.1.89-58340-5222-11-7-1203-1392.pcap`，18 帧 SCRAM-SHA-1 **失败会话** `<invalid-authzid/>`；同目录 5222 共 24 个，其中 **12 个 IPv6**——v6 参考在案但 e2e 零用例，G-XMPP-4）；⑦ 本仓库落码（`internal/protocol/xmpp/` 三文件 1623 行 + 接线 9 处，§11.1）
> 白话一句：**聊天软件的"先对暗号再发消息"——客户端先开一条 XML 流报家门，服务端回一条流并把能用的认证方式列出来；客户端挑一种认证（四选一），认证成功后重开一条流、绑定一个资源名、建立会话，然后就能发在线状态和聊天消息；最后双方互发流关闭标签、TCP 挥手走人。全程没有长度前缀——每条消息是一段 XML 文本，靠 XML 标签配对定界，一条 TCP 段可载一条节（超 MSS 才拆段）。**

## 0. 首版沿革与既有事实校正声明（门1 必答：基线继承关系）

本协议**无旧设计文档可承**，本节不写"旧稿 vs 实测"对照，改写**"既有内部契约/产物 vs 实测事实"**对照——这是 xmpp 在文档轨上的全部历史包袱：

| # | 既有说法（代码注释/产物/内部契约） | 实测（2026-09-29） | 校正结论 |
|---|---|---|---|
| 1 | `xmpp.go` 包头注释："10 phases … The fixed signaling phase (2-6) is protocol-driven; messages (8) and presence (7) are user-controlled" | 实测 10 阶段全序在案（T-1 19 帧逐帧对账）；presence 默认开、messages 可零可多条 | **注释属实**；本版 §3/§5 按实测钉死 |
| 2 | `layer_gen.go` 注释："raw 自驱 wrap legacy Plan（自建 TCP+10 阶段零分叉），防双换 Direction=up" | 实测 T-6 f15/f16：direction 的唯一 e2e 可观察 = L3 侧别（ip.src 10.0.0.1/20.0.0.1 双向钉）；f16 down 帧 ip.src=20.0.0.1 证明单换向正确 | **属实**；防双换回归面由 T-6 字段断言承住（隔离复审第 4 轮补钉） |
| 3 | `CODE_DESIGN.md` D-XMPP-1："缺省住 flat setDefaultDstPort（:945）" | flat 缺省实测 `strategy_convert.go:1378`（`setDefaultDstPort(&spec, cfg, 5222)`）；**链路径**缺省住 `chain_planner.go:1039-1043` DstPort switch（xmpp 特有：legacy Plan 无内部缺省，rtsp 式必选） | **两处缺省在案**（第 4 轮复审已勘误 :944→:945）；本版 §2.2 双缺省口径钉死 |
| 4 | T-11 summary（cases JSON 内）：曾写“~3060B→2 个 TCP 段” | 实测 **3 段**（1460+1460+146 = 3066B；pcap f15/16/17 `tcp.len` 1460/1460/146） | **已校正**：summary 现为 ~3066B→3 个 TCP 段；见 testcase §8.2 C-1 |
| 5 | T-11 expect 键集合 | **已含 `has_payload: true`**（9/9 正例一致） | **已校正**；见 testcase §8.2 C-2 |
| 6 | `trafficgen/docs/protocol-pcap-test/xmpp.md`（**tracked 产物**）写 "Cases: 11 — pass 11, fail 0, error 0" | 该文件末次提交 `4caf4b9`（**2026-09-21**），**晚于**判死提交 `0417be5`（2026-09-13）——**不满足任务书「末次提交早于 0417be5」的过期判定条件**；但 `trafficgen/docs/protocol-pcap-test/xmpp/` 目录**不存在**（0 个 pcap，11 条 `[pcap](xmpp/…)` 链接全悬空） | **不登记为过期缺口**（判定条件未命中，如实声明，vnc 车道同口径）；留档缺失单列 G-XMPP-13。**本车道证据 = 实跑 tshark 逐帧复核 `/tmp/mcp-pcaps/xmpp/` 的 11 例 pcap（§0 #7），非引用该产物** |
| 7 | — | `/tmp/mcp-pcaps/xmpp/` **11 个 pcap 全部在案**：9 正例（`<id>.pcap`）+ 2 负例（`<id>.neg.pcap`）；**9/9 正例 tshark 帧数与 JSON `packet_count` 逐例一致**（19/21/23/19/18/21/19/19/22）；2/2 负例均 **0 帧**；**21 条 frame 断言逐字节复核全 OK**；**14 条 field 断言全 OK**（`tcp.flags` 走 pcaptest 位比较 `0x002≡0x002`，`verify.go:114`）；合计 **46/46 断言 PASS**（本车道自审脚本 `/tmp/wt5-xmpp-audit.py`） | **本协议存量套件今日实测可跑且断言全绿**（本车道 tshark 复核，非引产物）；负例纯净性 = expect 仅 `{expect_error,error_contains,notes}`，无成功包结构断言 ✓ |
| 8 | `verify.go:574` 白名单：`strings.HasPrefix(caseID,"xmpp_")` + "Closing an unopened tag" | 实测每正例 **2 帧 malformed**（`</stream:stream>` 双帧，T-5 为 f14/15）——tshark 对字节合法的流关闭标签报专家级伪影（RFC 6120 §4.4 合法节） | **白名单口径属实**；本版 §7.3 钉死该伪影面，负例 0 malformed |

**依赖链判定纪律**：以上均为可判题（注释/产物/代码/pcap 四级对照），直接判定，不问偏好。不可判的（RFC 6120 对流重启后 `id` 是否必须变化、DIGEST-MD5 步序与 RFC 2831 原文的条款级对应）标"待确认"并写清确认方式（G-XMPP-15）。

## 1. 范围、profile 与实现状态边界

本版定义 **XMPP client-to-server（RFC 6120/6121）承载于 TCP 5222** 的流量生成：流开启 → 服务端宣告（STARTTLS/SASL 机制/压缩/roster 版本）→ SASL 认证四机制 → 流重启 → 资源绑定 → 会话建立 → presence → message 节交换 → 流关闭 → TCP 拆链。

| profile | 承载 | 本版允许内容 | 不从 profile 推导 |
|---|---|---|---|
| `xmpp_plain_v1`（主，缺省） | TCP，fixture 5222 | 流开启对 → PLAIN auth+success → 流重启对 → bind 对 → session 对 → presence（默认开）→ messages → 流关闭对 → 拆链 | 真实 SASL 密码学（§3.4 诚实边界） |
| `xmpp_digest_md5_v1` | 同上，`auth_mechanism="DIGEST-MD5"` | 同上但 SASL 面换四步质询应答（auth/challenge/response/success+rspauth） | 真实 MD5 摘要计算 |
| `xmpp_scram_sha1_v1` | 同上，`auth_mechanism="SCRAM-SHA-1"` | 同上但 SASL 面换六步交换（与参考 pcap 同机制同形） | 真实 SHA-1/HMAC 计算 |
| `xmpp_anonymous_v1` | 同上，`auth_mechanism="ANONYMOUS"` | 同上但 SASL 面换匿名单轮 | 匿名会话真实服务器语义 |

显式边界（"不实现、不声称、不许静默转换"）：

1. **不实现 STARTTLS 协商**——features 宣告 `<starttls/>`（`nsTLS`），但**从不发出 `<starttls/>` 请求、从不进入 TLS 握手**；全程明文（G-XMPP-7）。任务书所述状态机 "Initial→**TLS**→SASL→…" 中的 TLS 态在本实现**不存在**——宣告面≠协商面，本版如实声明。
2. **不实现压缩协商**——features 宣告 `<compression><method>zlib</method>`（`nsCompress`），从不启用（G-XMPP-7）。
3. **不实现 SASL 失败路径**——参考 pcap 全为 `<invalid-authzid/>` 失败会话（帧 15 `<failure>`），trafficgen 只产 happy path（`<success/>`），无 `<failure>` 分支（G-XMPP-7）。
4. **不实现真实密码学**——DIGEST-MD5/SCRAM-SHA-1 的 challenge/response/rspauth/verification 是**固定 base64 示例串**（`xmpp.go:715-742`），非密钥派生算法输出；PLAIN 的 base64 是真实格式（RFC 4616 `\0authzid空\0authcid\0passwd`）但凭据本身是配置值（G-XMPP-7）。
5. **不实现 5269 server-to-server**——`DefaultPort=5222` 唯一（`xmpp.go:50`）；全仓 grep 无 5269；DNS SRV 发现未建模（G-XMPP-8）。
6. **不实现 XEP-0199 IQ ping 长保活**——无空闲间隔编排（G-XMPP-9，裁定4 账本继承）。
7. **不实现运行时状态机**——生成器是**声明式剧本回放**（fixed script）：10 阶段顺序硬编码（`xmpp.go:286-465`），无任何配置键能改变阶段顺序或引入条件分支；"非法转移"在配置面**不可表达**（§5.3）。无 XML 解析器——引擎不解析对端字节，只按剧本发射。
8. **不实现 roster 名册交换**——`<ver/>`（roster version）只在 features 宣告，无 `<iq type='get'><query xmlns='jabber:iq:roster'/></iq>` 交换。

**实现状态（2026-09-29 实测）**：`xmpp` 层已注册（`registry.go:2048`，`CategoryTerminal`，`DependsOn ["ip"]`，**Fields 9 键**）；planner/生成器已落码（`internal/protocol/xmpp/` 三文件 **1623 行**，**38 个 `Test*` 函数**）；`allowedProtocols["xmpp"]=true`（`protocols.go:60`）；层内 translate 已接线（`chain_planner_translate.go:2856`）；raw-IP 自驱已接线（`chain_planner.go:795` 名单 + `:1528` `meta.Xmpp` + `chain_planner_util.go:54/57` `isRawIPChain`）；顶层 `xmpp` 子映射判死已接线（`strategy_convert.go:9098` rawWrapChains）；缺省目的端口 5220→**5222**（`:1378` flat + `chain_planner.go:1043` 链 switch 双缺省）；11 语义用例已落 `cases/xmpp.json` 且 **11 例 pcap 实测在案**。

**输出契约（pcap/NIC 双输出）**：两路径共用同一 cases JSON 与断言集（`tcp.dstport`/`tcp.flags`、`xmpp.id`/`xmpp.type`、`ip.src`、offset 54 frames）；NIC 经 tcpdump 捕获（`nic_capture` 用例级开关）；**不设仅单路径可用的断言**——11 例的 `packet_count`/`has_handshake`/`negotiated`/`terminates`/`has_payload`/`frames`/`fields` 七类断言均为路径无关（帧计数与载荷字节由引擎决定，与落盘方式无关）。

## 2. 协议栈、端口和固定偏移

### 2.1 层链

推荐层链为 `[ip, xmpp]`（引擎自动补 `ip`；**最小链 `[xmpp]` 经 DependsOn 补全同形**）。**本协议是 raw-IP 自驱终结层，链上不含 tcp 层**（D-XMPP-1 裁定1，六连协议对称）：xmpp 生成器**自建** TCP 三次握手、MSS 分段与三次挥手（`xmpp.go:286-294` 握手 / `:273-284` `emitData`→`segmentByMSS` 分段 / `:457-465` 拆链）。若用户显式写 `[ip,tcp,xmpp]`，`isRawIPChain` 因链含 tcp 返回 false（`chain_planner_util.go:48-51`）→ 落入事件分支，而 xmpp 生成器 `GenEvents()=nil`、drive 尾段直调 `Generate`（`chain_planner_translate.go:606`）→ 行为**今日未探针、未入契约**（G-XMPP-14，不许冒充已覆盖）。

目标形状 spec_json 样例（严格层链形，顶层仅 `layers`；**存量 11 例已是此形，零残留**）：

```json
{
  "layers": [
    {"ip": {"src": "10.0.0.1", "dst": "20.0.0.1"}},
    {"xmpp": {"auth_mechanism": "PLAIN", "messages": [{"direction": "down", "to": "a@b.c", "body": "hi"}]}}
  ]
}
```

### 2.2 端口

- **目的端口 5222**（client-to-server，RFC 6120 §13.3；IANA 登记）。**双缺省**：① flat 路径 `strategy_convert.go:1378`（`setDefaultDstPort(&spec, cfg, 5222)`，仅用户未写时覆盖）；② 链路径 `chain_planner.go:1039-1043` DstPort switch（`case "xmpp": spec.DstPort = 5222`，含 80 通用缺省兜底）——**legacy Plan 无内部缺省**（xmpp 与 pptp 唯一差异，rtsp 式必选，`chain_planner.go:795` 注释）。`validateBaseDstPortHandled` 含 xmpp（`:740` 函数 + `:795` 名单项），FieldContract 通用块不接管。
- **源端口 12345**（`strategy_convert.go:49` `DefaultSrcPort`，mapToFlowSpec 写入）；多流时 worker 保底递增 `12345+i`（`worker.go:307-309`，仅无显式 src_port 时）。链形**无端口位**：xmpp 层 Fields 9 键无 src_port/dst_port（registry `:2048`），`src_port`/`dst_port` 顶层已被判死 → **非默认端口在链形不可表达**（G-XMPP-2）；链上亦无 tcp 层可写端口动态对象（§12.12）。
- **5269**：未实现（§1 边界⑤）。

### 2.3 固定偏移

无 VLAN/IP options 的数据帧，**每帧 XMPP 字节起点为 IPv4 offset 54**（14 eth + 20 ip + 20 tcp）；IPv6 下为 offset 74（14+40+20）——但**存量 11 例全为 IPv4**（`10.0.0.1 → 20.0.0.1`），21 条 frame 断言 offset 集合 = `{54}`（机读实测），offset 74 今日**零证据**（G-XMPP-4）。SYN/SYN-ACK 两帧带 TCP 选项（MSS 4B + WS 3B + SACK 2B + NOP 对齐 → 12B，`xmpp.go:698-707`），载荷偏移不是 54——但存量 frame 断言无一落在帧 1/2，无冲突。

TTL 缺省 64（`xmpp.go:197-200`，常量 `xmpp.go:53`，spec.TTL 零值兜底）；IP 头 ID：帧 1 引擎随机会话 ID，其后 `ip.id` 从 1 起逐包递增（实测 pcap `0x91ba, 0x0001, 0x0002, …`）；TCP 窗口恒 65535（`xmpp.go:228`，缩放后 tshark 显示 8388480 = 65535×2⁷）。

## 3. 线格式编码（XML 流，无长度前缀）

### 3.1 承载与定界（本协议第一特性）

XMPP 载荷是 **XML 文本流**：一条 TCP 连接上双向各开一条逻辑 XML 流，节（stanza）是流内的顶层 XML 元素。**无任何长度前缀**——定界靠 XML 标签配对解析（tshark `xmpp` dissector 按 `tcp.port 5222` 绑定解析，实测 162 个 `xmpp.*` 字段）。引擎实现**逐节一 PSH-ACK 段**：每阶段产出一串 XML 字节，`segmentByMSS`（`xmpp.go:677-694`）按 MSS（缺省 1460）切块，块即 TCP 段；存量 10/10 数据帧均为单节单段，仅 T-11 的 3066B message 节拆 3 段（1460+1460+146，唯一真实分段边界证据）。**流是长连接**：一条 TCP 连接承载 10 阶段全部报文，引擎内无第二连接。

### 3.2 命名空间表（8 常量，`xmpp.go:69-76`）

| 常量 | URI | 用途 |
|---|---|---|
| `nsXMPPClient` | `jabber:client` | 流与节的默认命名空间（client-to-server） |
| `nsStream` | `http://etherx.jabber.org/streams` | `stream:` 前缀（流头/features 声明） |
| `nsSASL` | `urn:ietf:params:xml:ns:xmpp-sasl` | auth/challenge/response/success/failure 节 |
| `nsTLS` | `urn:ietf:params:xml:ns:xmpp-tls` | `<starttls/>` **宣告面**（从不协商，G-XMPP-7） |
| `nsBind` | `urn:ietf:params:xml:ns:xmpp-bind` | 资源绑定 iq |
| `nsSession` | `urn:ietf:params:xml:ns:xmpp-session` | 会话建立 iq（RFC 3921 遗产，RFC 6121 起兼容保留） |
| `nsCompress` | `http://jabber.org/features/compress` | zlib 压缩宣告面（从不启用） |
| `nsRosterVer` | `urn:xmpp:features:rosterver` | roster 版本宣告面（无名册交换） |

**三层结构**：① 流层 = `<stream:stream>`（默认 ns `jabber:client` + `stream:` 前缀 ns）；② 特性层 = `<stream:features>` 内的 starttls（nsTLS）/mechanisms（nsSASL）/compression（nsCompress）/ver（nsRosterVer），认证后第二张 features 只有 bind（nsBind）/session（nsSession）/ver；③ 节层 = `<message>`/`<presence>`/`<iq>`（默认 ns）。

### 3.3 节属性逐字段（from/to/id/type）

| 节 | 属性 | 取值（缺省） | 生成函数 |
|---|---|---|---|
| 客户端流头 | `to` / `xmlns` / `xmlns:stream` / `version` | `to`=配置 `from`（缺省 `example.com`）；`version='1.0'` | `buildStreamOpen` `:488` |
| 服务端流头 | `xmlns` / `xmlns:stream` / `from` / `id` / `version` | `from`=同上；`id`=配置 `stream_id`（缺省 `a1b2c3d4e5f6`）——**重启流沿用同一 id**（G-XMPP-15） | `buildStreamFeatures` `:503` / `buildPostAuthFeatures` `:530` |
| `<auth>` | `xmlns` / `mechanism` / 文本 | mechanism ∈ {PLAIN, DIGEST-MD5, SCRAM-SHA-1, ANONYMOUS}（Validate 枚举，`xmpp.go:122-126`）；PLAIN 带 base64 文本，其余自闭合 | `:548/:560/:569` |
| `<challenge>`/`<response>`/`<success>` | `xmlns` / 文本 | DIGEST/SCRAM 带固定 base64 示例串（`:715-742`） | `:577-596` |
| `<iq>` bind | `type='set'` / `id='bind_1'` / `<resource>` | resource 缺省 `trafficgen` | `buildBindRequest` `:600` |
| `<iq>` bind result | `type='result'` / `id='bind_1'` / `<jid>` | `jid/resource` 全 JID（缺省 `user@example.com/trafficgen`） | `buildBindResult` `:609` |
| `<iq>` session | `type='set'` / `id='sess_1'` | —（RFC 3921 遗产） | `:619/:628` |
| `<message>` | `to` / `type='chat'` / `<body>` | `to` 缺省 `bob@example.com`、body 缺省 `Hello from trafficgen`（**缺省路径今日零用例**，G-XMPP-12） | `buildMessageStanza` `:636` |
| `<presence/>` | 无属性 | 三态：nil→发（缺省）、`true`→发（同路径）、`false`→不发（`:410-417`） | 内联 |

**方向语义**：`messages[].direction` ∈ {up（client→server，缺省）, down（server→client）}；**节字节不含方向**——down 节与 up 节同字节（同 `buildMessageStanza`），方向唯一 e2e 可观察 = L3 侧别（T-6 f15 ip.src=10.0.0.1 / f16 ip.src=20.0.0.1，隔离复审第 4 轮补钉）。down 帧在 legacy Plan 内已按发送方翻转 L3/L4 并置 `Direction="down"`；raw 链 Emit 对 "down" 会再换一次 L3 → `layer_gen.go:55` 统一改写 `Direction="up"` 防双换。

### 3.4 SASL 四机制（`xmpp.go:309-381` switch）

| 机制 | 步数 | 帧序（up/down） | 字节要点 | 实测帧长 |
|---|---:|---|---|---|
| PLAIN（缺省） | 2 | auth(up) → success(down) | auth = `<auth xmlns='…sasl' mechanism='PLAIN'>base64(\0user\0pass)</auth>`（RFC 4616，authzid 空）；**缺省凭据钉 `AHVzZXIAcGFzcw==`**（T-1 f6，第 4 轮复审补钉） | 88 / 51 |
| DIGEST-MD5 | 4 | auth(up) → challenge(down) → response(up) → success(down) | challenge = base64(`realm="example.com",nonce="dGhpcyBpcyBhIG5vbmNl",qop="auth",charset=utf-8,algorithm=md5-sess`) 124 字符；response 292 字符；success 内嵌 rspauth 56 字符（**固定示例串非真摘要**，G-XMPP-7） | 71 / 188 / 354 / 116 |
| SCRAM-SHA-1 | 6 | auth(up) → challenge(down,**空**) → response(up) → challenge(down) → response(up) → success(down) | 与参考 pcap 同机制同形（帧 8-15）；四个载荷均为固定示例串（`biws…`/`cj1…`/`Yz1…`/`dj1…`） | 72 / 64 / 94 / 164 / 166 / 100 |
| ANONYMOUS | 2 | auth(up) → success(down) | `<auth xmlns='…sasl' mechanism='ANONYMOUS'/>` 自闭合（RFC 4505） | 70 / 51 |

**宣告面 vs 枚举面不一致（confirmed，G-XMPP-14）**：features 宣告 5 机制 = CRAM-MD5/LOGIN/PLAIN/DIGEST-MD5/SCRAM-SHA-1（照抄参考 pcap，`xmpp.go:506`），但 Validate 枚举只收 PLAIN/DIGEST-MD5/SCRAM-SHA-1/ANONYMOUS 4 值——CRAM-MD5/LOGIN 宣告却不可选；ANONYMOUS 可选却未宣告。P4 裁定对齐（改宣告表或补枚举）。

### 3.5 长度公式汇总（全部对 pcap tcp.len 逐帧复核）

| 元素 | 公式（字符数） | 缺省实测 | 函数行 |
|---|---|---:|---|
| streamOpen(to) | `127 + len(to)` | 138（example.com）| `:488` |
| features(from,id) | `590 + len(from) + len(id)` | 613 | `:503` |
| postAuthFeatures(from,id) | `313 + len(from) + len(id)` | 336 | `:530` |
| authPlain(u,p) | `72 + 4·⌈(len(u)+len(p)+2)/3⌉` | 88（user/pass） | `:548` |
| authMech(m) | `61 + len(m)` | 71 / 72 | `:560` |
| authAnonymous | 恒 70 | 70 | `:569` |
| success | 恒 51 | 51 | `:577` |
| successWithContent(c) | `60 + len(c)` | 116 | `:583` |
| challenge(c) | `64 + len(c)` | 64（SCRAM 空 challenge） | `:589` |
| response(c) | `62 + len(c)` | 94 | `:594` |
| bindRequest(r) | `107 + len(r)` | 117（trafficgen） | `:600` |
| bindResult(j,r) | `101 + len(j) + len(r)`（含 `/`） | 127 | `:609` |
| sessionRequest | 恒 86 | 86 | `:619` |
| sessionResult | 恒 31 | 31 | `:628` |
| presence | 恒 11 | 11 | 内联 `:415` |
| streamClose | 恒 16 | 16 | 内联 `:450/:454` |
| message(to,body) | `50 + len(to) + len(body)` | 71（alice@example.com/ping） | `:636` |

## 4. 业务场景分析（现网典型场景与五层覆盖）

**定性**：**声明式剧本回放**——配置声明身份四键 + 凭据 + 机制 + presence 开关 + messages 清单，引擎按固定 10 阶段剧本产出事件序列；TCP 握手/分段/拆链由生成器自建。无事件驱动成分（不解析对端、不自动应答未知输入）。

| 现网场景 | 事务交互 | 对应用例 |
|---|---|---|
| ① 标准登录 + 上线广播（现网最主流） | PLAIN 登录 → bind → session → presence | #1（`xmpp_t1_smoke_plain`） |
| ② 老服务器摘要认证 | DIGEST-MD5 四步 | #2 |
| ③ 现代服务器 SCRAM 认证（参考 pcap 同机制） | SCRAM 六步 | #3 |
| ④ 匿名/临时会话 | ANONYMOUS 单轮 | #4 |
| ⑤ 仅收不发（隐身监听） | presence 关断 | #5 |
| ⑥ 双向聊天（问一答一） | up/down message 各一节 | #6 |
| ⑦ 企业自建域名/机器人身份 | from/jid/resource/stream_id 四键定制 | #7 |
| ⑧ 凭据轮换/多账号 | username/password 定制 | #8 |
| ⑨ 机制名错误 | Validate 拒 | #9（负） |
| ⑩ 方向配置错误 | Validate 拒 | #10（负） |
| ⑪ 长消息（大 body） | 超 MSS 分段 | #11 |

**五层覆盖逐层结论**：功能层——10 阶段全序正例（#1 承接）+ SASL 四机制各一例（#1/#2/#3/#4）+ presence 开关（#5 缺席 / 其余默认开）+ messages 双向（#6）+ 身份凭据定制（#7/#8）+ 拒绝分支 2 类负例（§7）；性能层——MSS 分段边界（#11，3066B→3 段，引擎唯一真实分段证据）、最小帧（presence 11B payload/65B 以太帧）、最小会话 18 帧（#5）、最大会话 23 帧（#3）；数据场景层——机制 4 枚举、身份 4 字符串键、凭据 base64 两形态（缺省/定制）、direction 2 枚举 + 枚举外拒绝、to/body 透传；地址与流层——**IPv4 单族（v6 零用例，G-XMPP-4）**、单流基线（11/11）、**多流零用例（G-XMPP-3）**、**流关联显式不适用**：XMPP 单 TCP 连接承载全部节，无控制流派生数据/媒体流（Jingle 媒体面不在本协议范围，如实声明不硬凑）；业务层——十一场景全部有落点。

**次要合法行为显式不适用声明（不设正例、亦不得进负例）**：① STARTTLS 协商与压缩协商（宣告面未协商，G-XMPP-7）；② SASL 失败/流错误 `<failure>`/`<stream:error>`（G-XMPP-7）；③ CRAM-MD5/LOGIN 认证（宣告未实现枚举，G-XMPP-14）；④ roster 名册/订阅（XEP 面未建模）；⑤ 多资源多设备并发（无多流，G-XMPP-3）；⑥ XEP-0199 ping 保活（G-XMPP-9）。

## 5. 消息/事务模型与状态机

### 5.1 事务定义与十阶段序列

**事务** = 一次请求 + 一次响应（流开启对、bind 对、session 对、SASL 交换对），或单向动作（presence、message、流关闭）。**多事务** = 单连接内 6 组事务按序执行：#1（流开启 + SASL + 重启 + bind + session + 关闭 5 组）至 #6（+ presence + 2 messages）。

**事件序**（`buildEvents` 等价面 = `Planner.Plan` 顺序发射，`xmpp.go:286-465`；以 PLAIN+1 message 为例的实测帧位）：帧 1-3 握手 → 4 streamOpen(up) → 5 features(down) → 6 auth(up) → 7 success(down) → 8 restart(up) → 9 postAuth(down) → 10 bindReq(up) → 11 bindRes(down) → 12 sessReq(up) → 13 sessRes(down) → 14 presence(up) → 15 msg(up) → 16 流关闭(up) → 17 流关闭(down) → 18-20 FIN/FIN-ACK/ACK。

**包数公式（9/9 实测逐例一致）**：

```
packet_count = 3(握手) + 2(流开对) + A + 2(重启对) + 2(bind对) + 2(session对) + P + ΣS + 2(流关对) + 3(拆链)
             = 16 + A + P + ΣS
A = SASL 帧数（PLAIN 2 / DIGEST-MD5 4 / SCRAM-SHA-1 6 / ANONYMOUS 2）
P = presence（缺省 1；显式 false 为 0）
ΣS = Σ message 节分段数（每节 ⌈len(节)/1460⌉ 段）
```

校验：#1 16+2+1+0=19 ✓；#2 16+4+1=21 ✓；#3 16+6+1=23 ✓；#4 16+2+1=19 ✓；#5 16+2+0=18 ✓；#6 16+2+1+2=21 ✓；#7/#8 19 ✓；#11 16+2+1+3=22 ✓（3066B→3 段）。

### 5.2 状态机（as-built 诚实声明）

任务书所述 RFC 状态机 "Initial→**TLS**→SASL→Bind→Session→Closed" 中，**TLS 态在本实现不存在**（§1 边界①）：实现的是 **Initial→Features→SASL→Restart→Bind→Session→Active→Closed** 八态**线性剧本**——无转移条件、无输入驱动、无回退，"状态机"实为**固定发射顺序**（`xmpp.go:286-465` 顺序语句）。每阶段的四件事（CORE_MEMORY 3.4-3.7）：前置 = 上一阶段已发射（纯顺序，无依赖检查）；触发 = 顺序到达；成功 = 下一阶段；失败 = **不存在**（无失败分支——失败路径未建模，G-XMPP-7）。

### 5.3 非法转移逐条列出（配置面不可表达声明）

RFC 6120/6121 定义的非法转移，在本实现的配置面逐条判定如下——**生成器是硬编码顺序剧本，任何配置键都无法改变阶段顺序或引入额外节**，故下列全部转移**结构上不可表达**（无负例、无运行时拒绝，如实声明非"已防"）：

| # | RFC 非法转移 | 规范出处 | 本实现判定 |
|---:|---|---|---|
| 1 | 未开流先发节（auth/iq/message） | RFC 6120 §4.2 | 不可表达（剧本固定顺序） |
| 2 | SASL 前发 `<iq type='set'><bind/>` | RFC 6120 §7.1（须先认证） | 不可表达 |
| 3 | 未 bind 先发 presence/message | RFC 6121 §4.2/§5.2（须已绑定资源） | 不可表达 |
| 4 | 同一流二次 bind / 二次 SASL | RFC 6120 §6.1/§7.1 | 不可表达（各只发射一次） |
| 5 | 认证成功后不重启流直接 bind | RFC 6120 §4.3.3.2（restart 强制） | 不可表达（restart 硬编码在 auth 与 bind 之间） |
| 6 | 流关闭后继续发节 | RFC 6120 §4.4 | 不可表达（关闭是倒数第二三帧） |
| 7 | 明文流上使用 PLAIN（RFC 6120 §13.8 要求 TLS 保护） | RFC 6120 §13.8 | **实现就是明文 PLAIN**（§1 边界①③）——规范违背如实声明，G-XMPP-7 |
| 8 | config 可达的非法输入 | — | 仅 3 类：auth_mechanism 枚举外（#9 拒）、direction 枚举外（#10 拒）、IP 解析失败（框架层拒）；逐锚见 §7 |

### 5.4 自动派生规则

① `xmpp` 层 config 为空 `{}`（或最小链自动补全）→ 全缺省 PLAIN 19 帧参考形（translate 保底非 nil，`chain_planner_translate.go:2860-2863`；**引擎直调绕过翻译时 layer_gen 二级保底**，`layer_gen.go:34-37`）；② 9 个配置键全部"user > default > none"：缺省住 `xmpp.go:79-86` 常量（from/jid/resource/stream_id/mech/username/password/messageTo + body 内联 `:437`）；③ presence 三态 nil/true 同路径发、false 跳过；④ messages 每条按 direction 发射，down 帧字节同 up（§3.3）；⑤ TCP 握手/拆链/SYN 选项自动补（无配置开关）；⑥ seq/ack 双向独立递增（`emitData` 按段长推进，`xmpp.go:273-284`）；ISN 随机（RFC 6528，`spec.TCP.InitialSeq` 仅 flat 直调可达，链形不可达）。

## 6. 性能设计与验收（CORE_MEMORY §6.1–6.8）

- **目标与边界**：单流全链 18–23 帧（含握手拆链，SASL 机制决定）；单节上界 = 无规范上界（XML 无长度域），分段数 = ⌈节长/1460⌉（T-11 为 3 段实测锚）；多流吞吐由框架 `flow_control`/worker 并行度承载，协议层无速率概念。
- **依据**：`Planner.Plan` 顺序发射进带缓冲 channel（cap 256，`xmpp.go:155`），**流式无全量聚合**；每帧内存 = 该帧字节数；单 flow 无跨流共享状态、无锁（闭包局部变量）；分段复制一次 payload 切片。
- **验收两路（§6.3 强制）**：pcap（`/tmp/mcp-pcaps/xmpp/`，`<id>.pcap` / 负例 `<id>.neg.pcap`）与 NIC（`enp135s0f0np0`，`nic_capture` 开关）共用同一断言集；断言实际 `xmpp.*` 字段、帧原始 hex 与 `packet_count`，不只断言"任务没报错"。
- **六类场景落点（§6.6）**：基线（#1，19 帧）/ 目标规模（#3，23 帧最大会话）/ 压力上限（#11 分段 3 段）/ 长时间运行（messages 多条线性展开语义，`session` 面无周期）/ 并发交错（**顺序多流承载语义**，`concurrent` 为例外路径不启用）/ 背压（`packet_count` 精确计数守卫帧数漂移）。
- **吞吐数字待 P4 基准，本版不写承诺（§6.5）**。

## 7. 错误处理（负例锚词表，与 testcase §4 一一对应、同序）

以下输入必须由 planner/validator 拒绝并传播为 task error，不得产出成功 PCAP、`completed/0 packet` 或只剩 TCP 外壳的假成功（实测 2 负例 pcap 均 **0 帧**，文件名 `<id>.neg.pcap`）：

| # | 负例 ID | 故障输入 | JSON `error_contains` | 代码锚词（逐字） | 代码行 |
|---:|---|---|---|---|---|
| N-1 | `xmpp_t9_neg_mech` | `auth_mechanism="NTLM"`（枚举外） | `unsupported auth mechanism` | `xmpp: unsupported auth mechanism %q (supported: PLAIN, DIGEST-MD5, SCRAM-SHA-1, ANONYMOUS)` | `xmpp.go:125` |
| N-2 | `xmpp_t10_neg_direction` | `messages[0].direction="left"` | `invalid direction` | `xmpp: message[%d] invalid direction %q (must be up or down)` | `xmpp.go:139` |

**锚词可达性（链路径实测）**：两锚均经 `layers.RegisterLayerValidator`（`layer_gen.go:69`）→ `protocolValidator`（定义 `chain_planner_gen.go:137/142`；调用点 `chain_planner.go:413`）在 ValidateSpec 内命中——链级红例已由 `xmpp_chain_test.go:73`（NTLM 锚断言）实证背 door；大小写不敏感：`normalizeAuthMech` ToUpper 归一（`plain` 亦命中 PLAIN 路径；`NTLM` 大小写均可拒）。

**负例原子性**：每例单一故障注入；单次执行不得混注。两例均为**单注入**（NTLM 例 messages 空；direction 例机制缺省 PLAIN）✓。

**未入用例的拒绝分支（A′ 立项，不得冒充已覆盖）**：
- `xmpp: invalid SrcIP %q`（`:102`）/ `xmpp: invalid DstIP %q`（`:107`）——**链形被 validateSpecBase 的 `invalid source IP: %s` 先行遮蔽**（`chain_planner.go:867`，先于 protocolValidator `:413`），两锚仅 flat/直调可达（G-XMPP-11）；
- `xmpp: XmppConfig is required`（`:113`）——链形不可达（translate 保底非 nil + layer_gen 二级保底），仅引擎直调可达（G-XMPP-11）；
- `xmpp: TCP.MSS %d too small (min %d)`（`:131`）——链形不可达（`[ip,xmpp]` 无 tcp 层，`spec.TCP` 恒 nil；仅 flat 顶层 `tcp` 游离键可达且该键自身违反 1.11 白名单，G-XMPP-11）。

**不得误报的合法协议事件**：机制名小写（`plain`→PLAIN，归一化合法）；direction 大写（`UP`→up）；messages 空数组；presence 显式 true；`from`/`stream_id` 含特殊字符（**无 XML 转义**——`%s` 直接拼入属性/文本，含 `'`/`<` 即产非法 XML 而 validator 不拒 → 缺陷候选，G-XMPP-16）。

**tshark 伪影（非缺陷）**：每正例 2 帧 malformed = `</stream:stream>` 双帧的 "Closing an unopened tag" 专家级标记（字节合法，RFC 6120 §4.4；dissector 无法跨帧关联流上下文）——白名单 `verify.go:574` 按 `xmpp_` 前缀精确豁免；流头帧另有 "Unknown attribute to/version"、"Unknown element: features"、iq set 帧 "Packet without response" 专家信息（非 malformed，不入白名单口径）。

## 8. 边界

- **帧长与节长**：最小数据帧 = presence 11B（payload）/ 65B（以太帧）；最大存量节 = features 613B（#1/#2/#4/#5/#6/#8，from/example.com + id/a1b2c3d4e5f6）；最大以太帧 = #11 f15/f16 的 1514B（1460 payload）。XML 无规范长度上界，`segmentByMSS` 线性切块无上限守卫（#11 即上界证据）。
- **会话帧数**：18（#5 最小）/ 19（PLAIN·ANONYMOUS 缺省）/ 21（DIGEST-MD5、或 PLAIN+2 messages）/ 22（PLAIN+3066B message）/ 23（SCRAM-SHA-1 最大）——公式 §5.1，9/9 实测一致。
- **机制枚举**：只接受 4 值（Validate）；CRAM-MD5/LOGIN 宣告不可选（G-XMPP-14）；大小写不敏感归一（G-XMPP-10）。
- **端口**：链形目的端口恒 5222（双缺省 + 无配置位，G-XMPP-2）；源端口链形恒 12345（多流 worker 递增，G-XMPP-3）；非默认端口不可表达。
- **地址族**：v4 单族（11/11）；v6 路径在案（`TestValidate_IPv6`/`TestPlan_IPv6EtherType` 单测 + 参考 pcap 12 例）但 e2e 零证据（G-XMPP-4）；异族混写由框架 same-version 门拒绝（`chain_planner.go:871-881`）。
- **多会话**：`sessions[]` 结构不存在（单连接剧本）；多逻辑会话 = 多流（flow_control），今日零用例（G-XMPP-3）。
- **不产生回绕长度或超量分配**（节长由字符串构造一次算定，分段逐块发射）。

## 9. 原子 ID 与完成定义（11 个唯一语义 ID，顺序为权威）

| # | ID | 类型 | 覆盖 | packet_count（实测） |
|---:|---|---|---|---:|
| 1 | `xmpp_t1_smoke_plain` | 正 | §3.3/§3.4：PLAIN 缺省 10 阶段全序 + 5222 + 缺省凭据钉 | 19 |
| 2 | `xmpp_t2_digest_md5` | 正 | §3.4：DIGEST-MD5 四步质询应答 | 21 |
| 3 | `xmpp_t3_scram_sha1` | 正 | §3.4：SCRAM-SHA-1 六步（参考 pcap 同机制同形） | 23 |
| 4 | `xmpp_t4_anonymous` | 正 | §3.4：ANONYMOUS 匿名单轮 | 19 |
| 5 | `xmpp_t5_presence_off` | 正 | §3.3：presence=false 缺席（f14 位置证明） | 18 |
| 6 | `xmpp_t6_messages_both` | 正 | §3.3：messages 双向 + direction 值钉（ip.src 双向） | 21 |
| 7 | `xmpp_t7_identity_custom` | 正 | §3.3：from/jid/resource/stream_id 四键定制值钉 | 19 |
| 8 | `xmpp_t8_plain_credentials` | 正 | §3.4：PLAIN 凭据定制 base64 钉 | 19 |
| 9 | `xmpp_t9_neg_mech` | 负 | §7 N-1：机制枚举外拒绝 | —（0 帧） |
| 10 | `xmpp_t10_neg_direction` | 负 | §7 N-2：direction 枚举外拒绝 | —（0 帧） |
| 11 | `xmpp_t11_long_body_mss` | 正 | §3.1：长 body 超 MSS 分段（3 段实测钉） | 22 |

**9/9 正例 pcap 帧数与 `packet_count` 逐例一致；2/2 负例 0 帧；21 frame + 14 field 断言逐条对 pcap 复核全 OK（46/46，自审脚本实测）**。T-编号对照：T-1…T-11 ≡ #1…#11（CODE_DESIGN D-XMPP-1 P3 清单同号，T-11 为追加轮 4 新增）。

### 9.1 对账两行 + 粒度声明（§9.52）

- **要求逻辑点总数 = 106**（八项 8 行 + 矩阵 39 格 + 变体 39 行 + 商业映射 20 行）；**用例覆盖数 = 57**（八项已覆 1 + 矩阵已覆 18 + 变体已覆 27 + 商业已覆 11）；**不适用 = 18**（八项 1 + 矩阵 8 + 商业 9）；**开放立项 = 31**（八项 6 + 矩阵 A′ 13 + 变体立项 12）。57 + 18 + 31 = 106 ✓。
  **粒度声明**：行/格粒度每点 1 计；G-XMPP-1…G-XMPP-17 与 confirmed 项（§0 #4/#5、§3.4 宣告不一致）不折进 106。**反查全绿 ≠ 覆盖全**（§9.52 原文）。逐表重数见 §10.1（8 = 覆 1 + 立项 6 + 不适用 1）/§10.2（39 格 = 覆 18 + A′ 13 + 不适用 8）/§10.3（39 行 = 覆 27 + 立项 12）/§10.4（20 行 = 覆 11 + 不适用 9）。
- **门3 抽查候选**：最复杂用例 = **#3 `xmpp_t3_scram_sha1`**（23 帧：10 阶段全序 × SCRAM 六步交换 × 参考 pcap 同机制交织）；建议门3 抽 #3 + #11（分段面）。

## 10. P1 规范矩阵（CORE_MEMORY §4 八项：规范要求→业务场景→代码现状→缺口）

### 10.1 八项规范矩阵

| # | 八项 | 规范要求 | 业务场景 | 代码现状 | 缺口 |
|---|---|---|---|---|---|
| 1 | 连接模型 | client→server TCP 5222 单连接全双工 XML 流（RFC 6120 §13.3/§4） | 场景①–⑪ | `DependsOn ["ip"]` 单值；自建握手/拆链（§2.1） | 无 |
| 2 | 命令/消息表 | 流头/features/SASL 四节/bind iq/session iq/presence/message/流关闭（§4/§6/§7，RFC 6121 §4/§5） | 场景①–⑧ | `build*` 15 函数逐节落码（§3.5 行号） | 宣告面 vs 枚举面 G-XMPP-14 |
| 3 | 状态机 | Initial→TLS→SASL→Bind→Session→Active→Closed；restart 强制（§4.3.3.2） | #1–#6 | 线性剧本八态（§5.2）；**TLS 态不存在** | G-XMPP-7（宣告未协商） |
| 4 | 字段表 | XML 元素/属性（文本协议无定长布局）；四机制载荷格式（RFC 4616/2831/5802/4505） | 数据场景层 | 逐字段 §3.2/§3.3/§3.4 + 长度公式 §3.5 | SCRAM/DIGEST 载荷示例串 G-XMPP-7 |
| 5 | 错误处理 | `<failure>` SASL 失败、`<stream:error>` 流错误 | 负例 N-1/N-2 | Validate 6 锚（2 锚入例，3 锚链不可达） | 失败路径未建模 G-XMPP-7；链不可达锚 G-XMPP-11 |
| 6 | 超时与活性 | 无强制心跳（whitespace ping / XEP-0199 为扩展） | — | 无 keepalive 面 | G-XMPP-9 |
| 7 | NAT/代理/被动 | 无被动模式概念（客户端直连） | — | 无 `sessions[].src_port`；端口恒缺省 | **显式不适用**（端口面缺口另记 G-XMPP-2） |
| 8 | 版本/方言 | `version='1.0'` 唯一 profile；`to`/`from`/`id` 语义（§4.7） | 全部正例 | `version='1.0'` 硬编码；restart 沿用同 id | G-XMPP-15（待确认） |

### 10.2 子表①：阶段 × 终态矩阵（13 行 × 3 列 = 39 格，逐格已覆/立项/不适用）

| 阶段 | T1 正常终态 | T2 配置拒绝 | T3 RST 异常终态 |
|---|---|---|---|
| 流开启（streamOpen） | 已覆（#1） | 不适用（无该阶段专属配置分支） | A′ 立项（G-XMPP-16） |
| features 宣告 | 已覆（#1） | 不适用 | A′ 立项（G-XMPP-16） |
| SASL PLAIN | 已覆（#1） | 已覆（#9 代表例） | A′ 立项（G-XMPP-16） |
| SASL DIGEST-MD5 | 已覆（#2） | 已覆（#9 代表例） | A′ 立项（G-XMPP-16） |
| SASL SCRAM-SHA-1 | 已覆（#3） | 已覆（#9 代表例） | A′ 立项（G-XMPP-16） |
| SASL ANONYMOUS | 已覆（#4） | 已覆（#9 代表例） | A′ 立项（G-XMPP-16） |
| 流重启 + postAuth | 已覆（#1） | 不适用 | A′ 立项（G-XMPP-16） |
| bind 对 | 已覆（#1/#7） | 不适用 | A′ 立项（G-XMPP-16） |
| session 对 | 已覆（#1） | 不适用 | A′ 立项（G-XMPP-16） |
| presence | 已覆（#1 开/#5 关） | 不适用（开闭均合法非拒绝） | A′ 立项（G-XMPP-16） |
| message 节 | 已覆（#6/#11） | 已覆（#10） | A′ 立项（G-XMPP-16） |
| 流关闭对 | 已覆（全部正例） | 不适用 | A′ 立项（G-XMPP-16） |
| TCP 拆链 | 已覆（全部正例） | 不适用 | A′ 立项（G-XMPP-16） |

**逐格重数**：13 × 3 = 39——已覆 **18**（T1 列 13 + T2 列 5）/ A′ 立项 **13**（T3 列）/ **不适用 8**（T2 列 8），零空格。18 + 13 + 8 = 39 ✓

### 10.3 子表②：数据形态变体表（39 行，每行均有正例/负例落点或立项/不适用结论）

| # | 变体 | 落点 |
|---:|---|---|
| 1 | `to` 缺省 example.com | 覆（#1 f4） |
| 2 | `to` 定制 chat.x.cn | 覆（#7 f4） |
| 3 | `from` 缺省 | 覆（#1 f5） |
| 4 | `from` 定制 | 覆（#7 f5） |
| 5 | `stream_id` 缺省 | 覆（#1 f5） |
| 6 | `stream_id` 定制 | 覆（#7 f5） |
| 7 | `jid` 缺省 | 覆（#1 f11） |
| 8 | `jid` 定制 | 覆（#7 f11） |
| 9 | `resource` 缺省 | 覆（#1 f10） |
| 10 | `resource` 定制 | 覆（#7 f10） |
| 11 | `auth_mechanism` 缺省（=PLAIN） | 覆（#1/#5/#6/#7/#8/#11，6 例） |
| 12 | `auth_mechanism` 显式 "PLAIN" | A′ 立项（0 例显式写） |
| 13 | `auth_mechanism="DIGEST-MD5"` | 覆（#2） |
| 14 | `auth_mechanism="SCRAM-SHA-1"` | 覆（#3） |
| 15 | `auth_mechanism="ANONYMOUS"` | 覆（#4） |
| 16 | `auth_mechanism` 枚举外 | 覆（#9 负） |
| 17 | `auth_mechanism` 小写变体（`plain`） | A′ 立项（G-XMPP-10） |
| 18 | username/password 缺省 | 覆（#1 f6） |
| 19 | username/password 定制 | 覆（#8 f6） |
| 20 | `presence` 缺省（nil→发） | 覆（#1 等 8 例） |
| 21 | `presence=false` | 覆（#5） |
| 22 | `presence=true` 显式 | A′ 立项（G-XMPP-1，nil 同路） |
| 23 | messages 空/缺席 | 覆（#1） |
| 24 | message 单条 up | 覆（#11） |
| 25 | message 双向 up/down | 覆（#6） |
| 26 | direction 缺省（空→up） | A′ 立项（0 例缺席 direction） |
| 27 | `to` 缺省 bob@example.com | A′ 立项（0 例缺席 to） |
| 28 | `body` 缺省 Hello from trafficgen | A′ 立项（0 例缺席 body） |
| 29 | body ≤ MSS 单段 | 覆（#6 两节 71/70B） |
| 30 | body 超 MSS 多段 | 覆（#11，3066B→3 段） |
| 31 | body = MSS 边界（1454B 节恰好 1 段） | A′ 立项（边界相邻值） |
| 32 | IPv4 载体 | 覆（11/11） |
| 33 | IPv6 载体 | A′ 立项（G-XMPP-4，offset 74 零证据） |
| 34 | 端口缺省 5222 | 覆（#1 f1 字段断言） |
| 35 | 端口非缺省 | A′ 立项（链形不可达，G-XMPP-2） |
| 36 | 多流 flows>1（ip 动态对象 + worker 递增） | A′ 立项（G-XMPP-3） |
| 37 | 顶层 `xmpp` 子映射 presence 判死形 | A′ 立项（G-XMPP-6，能力在案零例） |
| 38 | xmpp 业务字段动态对象 | A′ 立项（G-XMPP-5，allowlist 即拒） |
| 39 | 负例纯净性（expect 仅两键 + notes） | 覆（#9/#10，G-XMPP-12 注 notes 键待收窄） |

27 覆 + 12 立项 = 39 ✓

### 10.4 子表③：商业行为→用例映射表（20 行）

| # | 商业行为（出处） | 用例映射 | 结论 |
|---:|---|---|---|
| 1 | 标准 IM 登录+上线（现网主流，参考 pcap 同族） | #1 | 已覆 |
| 2 | 老服务器摘要认证 | #2 | 已覆（结构路径） |
| 3 | 现代服务器 SCRAM 认证 | #3 | 已覆（与参考 pcap 同机制） |
| 4 | 匿名/临时会话（访客聊天） | #4 | 已覆 |
| 5 | 隐身监听（仅收不发） | #5 | 已覆 |
| 6 | 双向聊天收发 | #6 | 已覆 |
| 7 | 企业自建域名/机器人身份 | #7 | 已覆 |
| 8 | 多账号凭据轮换 | #8 | 已覆 |
| 9 | 认证机制配置错误 | #9 | 已覆 |
| 10 | 消息方向配置错误 | #10 | 已覆 |
| 11 | 大消息/文件传输类长节 | #11 | 已覆（分段面） |
| 12 | 凭据错误被服务器拒（SASL failure） | — | **明确不解决**（G-XMPP-7） |
| 13 | TLS 加密会话（STARTTLS） | — | **明确不解决**（G-XMPP-7） |
| 14 | 压缩会话（zlib） | — | **明确不解决**（G-XMPP-7） |
| 15 | 服务器联邦（s2s 5269） | — | **明确不解决**（G-XMPP-8） |
| 16 | 名册/订阅/群聊（MUC XEP-0045） | — | **明确不解决**（§1 边界⑧） |
| 17 | 多资源多设备同账号 | — | **明确不解决**（无多流，G-XMPP-3） |
| 18 | 空闲保活（XEP-0199 ping） | — | **明确不解决**（G-XMPP-9） |
| 19 | 消息回执（XEP-0184） | — | **明确不解决** |
| 20 | 流管理（XEP-0198 断线重连） | — | **明确不解决** |

11 覆 + 9 不适用 = 20 ✓ 无映射无确认即缺口——本表零缺口。

### 10.5 三路对照与候选方案对比（§4.12–4.15 / §4.17）

三路：①规范原文（RFC 6120/6121 + 四 SASL 机制 RFC——定"必须是什么"，§3 逐节标注）；②商业化软件实际行为（**参考 pcap 已到抓包级**：llcj 24 个 5222 会话含 v6，SCRAM 失败形在案；但 ejabberd/prosody 真机线字节未抓 → G-XMPP-15 待确认）；③可靠开源实现思路（strophe.js/ejabberd 的流状态机——只借鉴"restart 强制"一条，本实现顺序剧本已内含）。三路一致点：流头属性面、SASL 交换步形、bind/session/presence 顺序；不一致点：真实服务器对 restart 发新 id（本实现沿用同 id，G-XMPP-15）、明文 PLAIN 在现网会被服务器拒（本实现无对端校验，G-XMPP-7）。

| 方案 | 走法（借鉴来源） | 取舍 | 结论 |
|---|---|---|---|
| A | `[ip,xmpp]` raw 自驱 wrap（本版；vnc/pptp 同构先例） | 10 阶段字节零分叉可断言；代价 = 生成器自建 TCP（已落码） | **采用**（D-XMPP-1 裁定1） |
| B | `[ip,tcp,xmpp]` 事件面 | XML 流需 TCP 传输层事件化，生成器大改 → 零字节回归风险 | **否决**（裁定1 候选对比） |
| C | xmpp 拆"流层 + 节层"两层 | 层间需流状态（id/资源）传递，框架层间无此通道 | **否决**（状态在 Plan 闭包局部变量，单层内聚更简单） |

## 11. P2 D-XMPP-1 代码设计（CORE_MEMORY §8 八要素；as-built 定稿）

> 状态说明：实现已落码（`internal/protocol/xmpp/` 三文件），本 P2 条目为文档轨对既有实现的**逆向定稿**（as-built），供门1 批准后作为后续改动的唯一入口；P4 在本协议内为"缺口收敛"（§14），不另开新层。

### 11.1 文件清单（实测，非计划）

| 文件 | 职责 | 行数 |
|---|---|---:|
| `trafficgen/internal/core/types.go`（`:1877` 槽位 + `:9266/:9314` 类型） | `XmppConfig`（9 字段）/`XmppMessage`（3 字段）+ `FlowSpec.Xmpp` 槽位 | —（共享文件） |
| `trafficgen/internal/protocol/xmpp/xmpp.go` | 单文件全家桶：常量 8 命名空间 + 9 缺省值 + `Planner.Validate`（6 锚）/`Planner.Plan`（10 阶段 + 自建 TCP）+ `build*` 15 节构造函数 + `segmentByMSS`/`synOptions`/`normalize*` + 固定示例载荷 | 742 |
| `trafficgen/internal/protocol/xmpp/layer_gen.go` | raw 链终结层生成器（`RegisterLayerGenerator` + `RegisterLayerValidator`，`init()`）+ 防双换 Direction=up | 72 |
| `trafficgen/internal/protocol/xmpp/xmpp_test.go` | 36 个 `Test*`（Validate 面 + Plan 包数/字节/方向 + L2/L3 面 + 上下文取消） | 809 |
| 接线 9 处 | registry 注册（`layers/registry.go:2048`）/ translate 层内分支（`chain_planner_translate.go:2856`）/ convert 子配置搬运 + flat 缺省（`strategy_convert.go:1372-1378`）/ `ParseXmppConfigFromMap` 导出（`:3975`）/ rawWrapChains 判死（`:9098`）/ raw 名单双处（`chain_planner.go:795` + `chain_planner_util.go:54/57`）/ Meta 直传（`chain_planner.go:1528` + `generator.go:524`）/ protocols 准入（`protocols.go:60`）/ main 翻转（`main.go:205-206` 空白导入 + `:611` RegisterPlanner） | — |

### 11.2 接口签名

- `Validate(spec core.FlowSpec) error`（`xmpp.go:99`）：SrcIP/DstIP 解析、`Xmpp==nil` 拒、机制枚举（归一后四值）、MSS 下界 536、messages direction 枚举。零配置不通过（`XmppConfig is required`）——**与 opcua 的 nil-默认流相反**：xmpp 层空配置由 translate 保底非 nil 后才到达 Validate。
- `Plan(ctx, spec) (<-chan core.PacketConfig, error)`（`xmpp.go:150`）：Validate → goroutine 内 10 阶段顺序 `emit`/`emitData` → channel（cap 256）→ close。ctx 取消即停止（`TestPlan_ContextCancellation` 在案）。
- 生成器：`Name() "xmpp"`；`GenEvents()` 返回 nil（raw 面防误入事件分支）；`Generate` 逐包 `pkt.Direction="up"` 后 `req.Emit`（防双换，`layer_gen.go:55`）；`req.Emit==nil` 显式错（`:30-32`）。
- 层校验器：`RegisterLayerValidator("xmpp", …)` 包装 `(&Planner{}).Validate`（`layer_gen.go:69`）——链上 ValidateSpec 经 `protocolValidator` 调用（定义 `chain_planner_gen.go:142`，调用 `chain_planner.go:413`）。

### 11.3 数据结构

`XmppConfig{From, JID, Resource, StreamID, AuthMechanism, Username, Password string; Presence *bool; Messages []XmppMessage}`（`types.go:9266-9310`）；`XmppMessage{Direction, To, Body string}`（`:9314-9326`）。Presence 用 `*bool` 三态（nil=缺省开，PadMinFrame 同款模式）。

### 11.4 主流程

层链配置 → `ValidateLayers`（registry Fields 9 键 allowlist）→ translate（层内 config → `spec.Xmpp`，空 `{}` 出非 nil 缺省壳）→ validateSpecBase（IP/端口/MSS 框架锚）→ protocolValidator（xmpp 6 锚）→ 端口缺省（DstPort switch 5222）→ `isRawIPChain` 命中 → raw 驱动 `XMPPGenerator.Generate` → `Planner.Plan`（自建 TCP + 10 阶段）→ 防双换 → worker（ip.id/时间戳回填）→ writer（PCAP/NIC）。

### 11.5 错误分支

6 种 planner 拒绝（`xmpp.go:99-144`）全部传 task error（负例 2 锚实测 0 帧——零假成功）；其中 3 锚链形状不可达（G-XMPP-11，§7 已列）。`normalizeAuthMech` 未知值**落入 default 返回原串 → 后续枚举 switch 拒绝**（无静默通过路径 ✓）。

### 11.6 性能边界

见 §6（顺序发射、per-flow 闭包局部状态、无跨流共享、无锁；吞吐数字待 P4 基准）。

### 11.7 与现有逻辑的冲突点

- **端口动态不可达**：`[ip,xmpp]` 链无 tcp 层 → `tcp.src_port/dst_port` 动态对象无从书写；仅 `ip.src/dst/ttl` 动态可达（allowlist `layer_dyn.go` ip 行）→ 多流变地址可行、变端口不可行（G-XMPP-3/5）。
- **静态复制门**：`checkLayerChainStaticCopy` 的 lname 表含 `ip`（`internal/core/schema/semantic.go:214`）→ 存量 11 例若开 `flows>1` 会因 ip 标量被拒——多流必须先把 `ip.src/dst` 写成动态对象（规则在案，零 xmpp 例，G-XMPP-3）。
- **`[ip,tcp,xmpp]` 混搭形**：`isRawIPChain` 返 false → 落 drive 尾段直调 `Generate`——行为未探针未入契约（G-XMPP-14）。
- **XML 无转义**：9 个字符串键 `%s` 直拼（§7 末条）——含引号/尖括号值产非法 XML 不拒（G-XMPP-16）。

### 11.8 回滚方式

本协议文件独立成包，回滚 = revert 本协议 3 文件 + 接线 9 处（registry/translate/convert×3/chain_planner×2/protocols/main）；不触及其他协议。cases 回滚 = 恢复 11 例 JSON（产物文件，非文档）。

## 12. 门1 §1–§14 十四行对照表（CORE_MEMORY §15.1–15.3）

| § | 本协议怎么满足 | 证据 |
|---|---|---|
| §1 层链唯一真相 | 见 §12.1 强制展开：存量 11/11 顶层 = `{layers}` **仅此一键，零残留**；目标形状见 §2.1 样例且**存量已达标**（本协议无迁移工作量；与 vnc/rtsp 等 27 协议同形） | §12.1；`cases/xmpp.json` 机读实测 |
| §2 策略/任务 | 策略 = 单 xmpp 流量模板；任务 = 多策略合跑 + 总量封顶；框架语义未动 | 设计 §2.1 样例 |
| §3 五件套 | 见 §12.3 强制展开：会话表/事务序列/关联（无派生流诚实声明）/插入位置（raw 终结层）/时间线。有长连接，不豁免 | §12.3 + §5 |
| §4 查规范 | RFC 6120/6121 + 四 SASL 机制 RFC + tshark 3.6.14 字段与 11 例 pcap 实测 + 落码反推；八项矩阵 + 子表①②③ | §10 |
| §5 依赖与错误 | `DependsOn ["ip"]` 单值（`registry.go:2048`）；6 种 planner 拒绝分支（2 入例）；失败传 task error（两负例 0 帧实测） | §5/§7/§11.5 |
| §6 性能 | 见 §6（6.1–6.8 要素齐；吞吐数字标待 P4 基准，不写承诺；pcap/NIC 两路验收明写） | §6 |
| §7 三份文档 | `124-xmpp-{design,testcase}.md` v1.0.0（草稿层）+ D-XMPP-1（§11，门1 获批 = 定稿）+ T-XMPP（testcase §2，11 ID）+ CODE_DESIGN 内部条目为历史层 | 修订记录 |
| §8 设计先行 | P1–P3 先于 P4 缺口收敛；门1 获批 = D-XMPP-1 定稿 = 开工门 | 提交序（CODE_DESIGN :3179 已有 P1+P2 定稿记录） |
| §9 测试三源 | 三源 = RFC 6120/6121 + 四机制 RFC（§10）+ D-XMPP-1（§11）+ tshark 3.6.14 字段与 pcap 实测（**已到抓包级**：11 例 pcap 在案、35 条断言逐条复核 OK）；11 ID 逐项回指；存量 11 例审计去向 testcase §8 | `124-xmpp-testcase.md` §2/§5/§8 |
| §10 评审闭环 | 每阶段对抗自重审（CODE_DESIGN 记录 4 轮复审：追加轮 1 断言松钉 + 轮 3 值断言缺口 + 轮 4 隔离复审 1 中 2 低全修）+ 收官隔离复审；红先绿后 | `CODE_DESIGN.md` D-XMPP-1 P6 段 |
| §11 白话 | 每阶段白话一句先行（见本文首节） | 汇报 |
| §12 动态清单 | 见 §12.12 强制展开：四元组 ip 三键开/tcp 端口链不可达；业务字段逐个列开/不开 + 理由；序号算法实读行号 | §12.12 |
| §13 schema 派生 | `xmpp` 已在 `registry.go:2048` 注册（**不新增层**）；生成表 `layers.generated.json` 同代（9 fields / depends_on [ip] / category terminal 逐键一致，机读实测）；**P4 若改 registry Fields 必须重跑 schemagen** | §11.1 |
| §14 真实流程 | suite 经 MCP 建策略建任务 → 引擎真实生成 → tshark `xmpp.*` + frames 双通道 → 先跑后钉；pcap 落 `/tmp/mcp-pcaps/xmpp/` | testcase §7 |

### 12.1 §1 强制展开：旧键去向 + 完整 spec_json 样例

**存量实测（逐例机读，2026-09-29）**：

| 文件 | 例数 | 顶层键分布 | 链形 | 负例 expect 形状 |
|---|---|---|---|---|
| `cases/xmpp.json` | 11 | **`{layers}` ×11**（唯一顶层键、零游离键） | `[ip,xmpp]` ×11 | 2/2 = `{expect_error, error_contains}`（严格两键） |

**旧键去向表（§15.3 要求"每个键写去向"）**：

| 旧键 | 存量出现例数 | 去向 |
|---|---:|---|
| `src_ip` / `dst_ip` | **0** | 本协议**从未用过顶层地址**；地址已住 `layers[0].ip.{src,dst}`（11/11） |
| `src_port` / `dst_port` | **0** | 本已 absent（链形无端口位：src 保底 12345、dst 缺省 5222，§2.2）；目标形**无端口键可写**（层无端口位 + 顶层判死）——非默认端口不可表达（G-XMPP-2） |
| `count` | **0** | 走 `flow_control`（本版未用，G-XMPP-3） |
| 顶层 `xmpp` 子映射 | **0** | 已住 `layers[i].xmpp`（11/11）；presence 判死已接线（rawWrapChains `:9098`） |
| `strategy_fc` / `flow_control` | **0** | 本协议无多流用例；目标形按需加（须配 ip 动态对象，§11.7） |

**结论**：**本协议存量 11/11 顶层零残留**——§1 门的动作 = ①**无旧键可删**；②收官自查行「非负例顶层键 = 0」**今日即成立**（机读实测 11/11 顶层仅 `layers`）；③A′ 新增例全部沿用纯 layers 形（§13）。
> **注**：全仓 `cases/*.json` 中共 27 个协议今日已是纯 `{layers}` 形（vnc 车道 §0 #5 机读清单含 **xmpp**），本协议是其中之一，**非唯一**；本协议的**特有事实**仅是"11/11 例今日即零残留"，不构成全仓唯一性。

目标形状样例见 §2.1（顶层仅 `layers`）。

### 12-P2 判死负例形状（链级红例必含清单①③④）

- ① presence 形状 `{"layers":[…],"xmpp":{}}` 今日**会被拒**（`CheckProtoFlat` rawWrapChains 含 xmpp，`strategy_convert.go:9098`，锚词 `protocol xmpp no longer accepts a top-level xmpp sub-config (move it into the xmpp layer of a [ip,xmpp] layers chain)`）→ **能力在案但零用例**：P4 可建该负例（与 opcua/thrift 的"建了会假绿"相反——本协议判死已接线，建例即真红），A′ 立项 G-XMPP-6。② 白名单外游离键判死（`unknown field`）今日**无通用门** → 不建（G-XMPP-6，与 moxa G-MOXA-2 同款）。③ 2 负例每条带锚词（已齐，§7）。④ 收官自查「非负例顶层键 = 0」**今日已成立**（§12.1）。

### 12.3 §3 强制展开：五件套

会话表：`s1` 单连接基线（#1–#11 全部，各自四元组 10.0.0.1:12345→20.0.0.1:5222，握手→10 阶段→拆链）。事务：`t1` TCP 建连（自建握手）/ `t2` 流开启（streamOpen→features 对）/ `t3` SASL 交换（2/4/6 帧按机制）/ `t4` 流重启+postAuth（对）/ `t5` bind（对）/ `t6` session（对）/ `t7` presence（单向，可关）/ `t8` message（按配置 0..N 条，双向可混）/ `t9` 流关闭（对）/ `t10` TCP 拆链（自建 FIN 三包）；每事务四件事（前置/触发/成功/失败）见 §5.2（失败分支不存在——线性剧本，G-XMPP-7）。关联关系：**无派生流**（诚实声明：单 TCP 连接承载全部节，无 `driven_by`；媒体面 Jingle 不在本协议）。插入位置：raw 终结层（`[ip,xmpp]`，无中间层——**生成器自建 TCP，链上无 tcp 层**）。时间线：节内严格顺序 / 事务对内 up→down 严格配对 / 多流顺序展开（`concurrent` 为例外路径不启用）/ 无交错。

### 12.12 §12 强制展开：动态字段清单与序号算法

**四元组**：`ip.src`/`ip.dst`/`ip.ttl` 三键动态**开**（allowlist `internal/core/layer_dyn.go` ip 行实测）；`tcp.src_port`/`tcp.dst_port` allowlist 开**但链形不可达**（`[ip,xmpp]` 无 tcp 层，动态端口对象无处书写）→ **端口动态今日零可达**（G-XMPP-3）；`udp`/`eth` 同理不可达。保底：src 12345+i（`worker.go:307-309`，仅 flows>1 且无显式端口）；dst 5222（DstPort switch）。

**业务字段 9 项全关**（allowlist 无 `xmpp` 行，grep 零命中实测；对象即 `does not support dynamic`）：`from`/`jid`/`resource`/`stream_id`（身份四键，字符串标量）/ `auth_mechanism`（枚举选择器，逐流变无意义）/ `username`/`password`（凭据，逐流变会破坏会话语义）/ `presence`（布尔开关）/ `messages`（剧本清单，列表无动态形状）——逐流变体需求列 A′ 候选（testcase §6.2；今日按 §9.36 口径不冒充覆盖）。

**序号算法实读**：① TCP seq/ack 双向独立递增，数据段按 `len(seg)` 推进（`xmpp.go:273-284` emitData）；② ISN 随机（`randUint32` crypto/rand，`xmpp.go:219-226` + `:668`；RFC 6528；`spec.TCP.InitialSeq` 仅 flat 可达）；③ `ip.id` 帧 1 会话随机、其后 1 起递增（`nextIPID` `xmpp.go:212-216` + SessionState.IPID，pcap `0x91ba,0x0001,0x0002…` 实测）；④ 源端口 `12345+i`（`worker.go:308`）；⑤ IQ id 恒 `bind_1`/`sess_1`（无会话内递增，`xmpp.go:602/:621` 硬编码）。

## 13. P3 对接清单（T-XMPP 草稿输入；正文落 testcase 文件）

11 ID（9 正 + 2 负）+ packet_count/锚词 + fixture 常量（8 命名空间 + 9 缺省值）+ 双通道断言基线 + 存量审计（testcase §2–§5/§8 全量）。A′ 候选 12 例：`xmpp_neg_top_level`（顶层 xmpp 子映射判死红例）/ `xmpp_default_port_assert`（删 dst 侧断言仅保缺省路径）/ `xmpp_neg_bad_ip`（SrcIP/DstIP 非法，flat 形锚）/ `xmpp_ipv6`（offset 74）/ `xmpp_multiflow_dyn_ip`（flows=2 + ip 动态对象 + 端口递增断言）/ `xmpp_presence_true`（显式 true）/ `xmpp_msg_defaults`（to/body 缺省钉）/ `xmpp_mech_lowercase`（`plain` 归一）/ `xmpp_mss_boundary`（节长恰 MSS±1 边界相邻值）/ `xmpp_abort_rst`（RST，G-XMPP-16）/ `xmpp_neg_mixed_family`（异族混写，框架锚）/ field 断言收编（`xmpp.to`/`xmpp.attribute`/`xmpp.cdata`，G-XMPP-17）。

## 14. 缺口立项清单（有缺口写「缺口立项」，不许空着）

| 缺口 | 内容 | 去向 |
|---|---|---|
| G-XMPP-1 | `presence=true` 显式形零用例（nil/true 同路径，D-XMPP-1 备忘已记 n/a；本版维持"低优先"但登记不冒充覆盖） | A′ 候选（低） |
| G-XMPP-2 | 非默认端口**链形不可表达**（xmpp 层 9 键无端口位 + 顶层 dst_port 判死 + DstPort switch 覆盖 80 兜底）；5222 缺省断言仅 #1 一处 | 边界声明 + A′ 候选（若框架开层内端口位则补例；禁冒充已覆盖） |
| G-XMPP-3 | 多流 `flows>1` 零用例（静态复制门要求 ip 层动态对象，规则在案零例；worker 12345+i 无 e2e 证据）；tcp 层端口动态链形不可达（§11.7） | A′ 补例 `xmpp_multiflow_dyn_ip` |
| G-XMPP-4 | IPv6 零用例（11/11 全 v4，offset 74 零证据）；单测在案（`TestValidate_IPv6`/`TestPlan_IPv6EtherType`）+ 参考 pcap 12 例 v6 在案 | A′ 补例 `xmpp_ipv6` |
| G-XMPP-5 | 业务字段动态全关（allowlist 无 `xmpp` 行，对象即拒） | A′ 候选，不冒充已覆盖（§9.36 口径） |
| G-XMPP-6 | 游离顶层未知键无通用门（`{"layers":[…],"bogus":1}` 今日不判死）；**顶层 xmpp 子映射判死已接线**（`:9098`）但零用例 | 框架面（禁加单协议分支，等 unknown-key 白名单）；判死红例 `xmpp_neg_top_level` A′ 可建（今日建即真红） |
| G-XMPP-7 | **宣告面/实现面三缺口**（B′ 账本继承，裁定4）：STARTTLS 宣告未协商（TLS 态不存在）；zlib 宣告未启用；SASL 失败路径未建模（参考 pcap 全失败会话）+ 真实密码学未实现（DIGEST/SCRAM 固定示例串）+ 明文 PLAIN 违 RFC 6120 §13.8 | **明确不解决**（真实密码学/TLS 非生成器范围）+ 用例只断结构；若未来实现须新增独立例并重算帧数 |
| G-XMPP-8 | 5269 server-to-server + DNS SRV 发现未实现（全仓无 5269） | 边界声明（§1 边界⑤），明确不解决 |
| G-XMPP-9 | XEP-0199 IQ ping 长保活未建模（3.15 长保活项，裁定4 账本） | B′ 立项（确认方式=抓 ejabberd 空闲会话包；建模面=IQ get/result 对 + 空闲间隔） |
| G-XMPP-10 | `normalizeAuthMech` ToUpper 大小写宽松（RFC 4422 机制名区分大小写——legacy 宽松行为如实，零用例） | B′ 注记（裁定4）+ A′ 候选 `xmpp_mech_lowercase` |
| G-XMPP-11 | 3 个 planner 锚链形状不可达：`invalid SrcIP/DstIP`（被 validateSpecBase 先行遮蔽）、`XmppConfig is required`（translate+layer_gen 双保底非 nil）、`TCP.MSS too small`（链无 tcp 层 spec.TCP 恒 nil）——死分支如实登记 | 如实声明（禁冒充已覆盖）；A′ 候选仅 flat 直调面 |
| G-XMPP-12 | 存量 JSON 形状/文字矛盾已收敛：T-11 summary 已改为 3 段、`has_payload` 已补齐、两负例 `expect` 已收窄为两键；messages to/body 缺省路径仍零用例 | **已完成前三项**；`xmpp_msg_defaults` 仍为 A′ 候选 |
| G-XMPP-13 | **结果产物 pcap 留档缺失**：`trafficgen/docs/protocol-pcap-test/xmpp/` 目录不存在（0 个 pcap，11 条链接全死链）；xmpp.md 末次提交 `4caf4b9`（2026-09-21）**晚于**判死提交 `0417be5`（2026-09-13）→ **不满足过期判定条件，不登记为过期缺口**（vnc 车道同口径，如实声明）；本车道证据 = 实跑 tshark 复核 `/tmp/mcp-pcaps/xmpp/` 46/46 断言，非引用该产物 | **代码阶段**（P5 重跑套件时补 pcap 留档）；本版不删不改 tracked 产物 |
| G-XMPP-14 | ① features 宣告 5 机制 vs Validate 4 枚举不一致（CRAM-MD5/LOGIN 宣告不可选、ANONYMOUS 可选未宣告）；② `[ip,tcp,xmpp]` 混搭形行为未探针未入契约 | ① P4 裁定：对齐宣告表（推荐）或补枚举；② 探针后裁定拒绝或声明边界，禁冒充已覆盖 |
| G-XMPP-15 | 流重启沿用同一 `stream_id`（RFC 6120 §4.7.3 对 restart 后 id 是否必须变化无逐字强制——现网服务器发新 id）；DIGEST-MD5 步序与 RFC 2831 条款级对应未逐条核对 | 待确认：查 RFC 原文 + 抓 ejabberd restart 包对照；确认前按实现钉、不声称合规 |
| G-XMPP-16 | XML 无转义：9 字符串键 `%s` 直拼属性/文本，含 `'`/`<`/`&` 值产非法 XML 而 validator 不拒（缺陷候选） | A′ 立项（先写失败用例再补转义/拒绝分支） |
| G-XMPP-17 | tshark `xmpp.*` 162 字段仅消费 2 类（`xmpp.id`/`xmpp.type`，12 条）；`xmpp.to`/`xmpp.from`/`xmpp.iq`/`xmpp.xmlns`/`xmpp.cdata`/`xmpp.attribute` 实测可用零使用 | A′ 收编（先跑后钉 dissector 口径，不许凭字段名臆造） |

## 15. 修订记录

- v1.0.1（2026-09-30）：P4 收敛三项已落地：T-11 summary 按实测改为 3066B/3 段，补 `has_payload: true`，两负例 `expect` 收窄为两键；messages to/body 缺省路径仍登记 G-XMPP-12 A′。此前 v1.0.0 内容保留如下。自审 2 轮，末轮干净。

- v1.0.0（2026-09-29）：P-PIPE 批次二文档轨首版。**xmpp 首号契约**（无旧稿；承 CODE_DESIGN D-XMPP-1 内部条目展开）：11 例存量机读审计（**顶层零残留**，本协议无迁移工作量）；46/46 断言对 11 例 pcap 逐条复核（21 frame + 14 field + 11 packet_count，全 OK）；§3 十阶段逐字节 + 17 条长度公式全量实测钉死；§5 线性剧本状态机 + 8 条非法转移配置面判定 + 包数公式 `16+A+P+ΣS`（9/9 一致）；§12.1/12.3/12.12 强制展开 + 12-P2（判死已接线零例——本协议红例今日可建即真红）；缺口 G-XMPP-1…G-XMPP-17。自审 2 轮（机读脚本 + 逐数复核），末轮干净。
