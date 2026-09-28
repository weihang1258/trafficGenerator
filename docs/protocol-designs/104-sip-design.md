# #104 sip（会话初始协议 · RFC 3261，信令 + 媒体流关联）设计契约

> 版本：v1.0.0（as-built 逆向定稿；修订记录见 §15）
> 日期：2026-09-29
> 车道：文档轨批次二（#104 sip）
> 前身条目：`docs/CODE_DESIGN.md` **D-SIP-1**（层链化，P-PIPE #19，2026-09-19 验收）+ **D-SIP-2**（引擎结构补全四 WP，2026-09-20 验收）；用例清单 `docs/TEST_CASES.md` **T-SIP-1…96**。本 #104 是 as-built 契约文档，**不搬前身条目的状态行与数字**，逐条见 §0。
> 存量用例：`trafficgen/test/protocol_pcap/cases/sip.json`（**96 例 = 87 正 + 9 负**，ID/顺序/包数/断言均机读实测，见 §9/§12.1）
> 规范基线：① **RFC 3261**（SIP 核心：§7 消息语法/§8.1.1 强制头/§8.1.3.2 响应回显/§9 CANCEL/§13.2 INVITE 事务/§14.2 glare/§17 事务/§19.1.1 地址与 URI/§20 头字段与 compact 形/§22.1 摘要鉴权/§26.2 SIPS 与 TLS）；② **RFC 3581**（§4 rport/received）；③ **RFC 3550**（§5.1 RTP 头）；④ **RFC 3264**（§5.1/§6 offer-answer 与方向属性）；⑤ **RFC 4566**（SDP）；⑥ **RFC 3262**（PRACK/RAck）、**RFC 3311**（UPDATE）、**RFC 3515**（REFER）、**RFC 3891**（Replaces）、**RFC 3265/3842**（SUBSCRIBE/NOTIFY、MWI）、**RFC 3903**（PUBLISH）、**RFC 3428**（MESSAGE）、**RFC 2976**（INFO）、**RFC 3966**（tel: URI）、**RFC 4028**（Session Timer）、**RFC 4244**（History-Info）、**RFC 3323/3325/3326**（IMS 私有头与 Reason）、**RFC 4575/4579**（会议）、**RFC 5621**（multipart）、**RFC 3725**（3PCC）；⑦ 本仓库落码（`internal/protocol/sip/` 三文件 1739 行 + 接线，§11）；⑧ 本机 tshark 3.6.14 字段表与 96 例断言面（断言字段名与取值格式的唯一权威）
> 白话一句：**SIP 就是"打电话用的对讲机协议"——一条 TCP 通道上先把电话簿对好（INVITE 里带上"我这边用什么地址收声音"），对方响铃、接听、说话（声音走另一条 UDP 通道，端口就是刚才对好的那个），说完挂断。本生成器把这段对话按你写的剧本逐句念出来，并把声音通道也一并铺好。**

## 0. 沿革与实现状态（门1 必答：基线继承与 as-built 边界）

本协议**无编号前身设计文档**（不像 opcua 有 25-*）。它的设计史住在 `docs/CODE_DESIGN.md` 的 **D-SIP-1 / D-SIP-2** 两条目，用例史住在 `docs/TEST_CASES.md` 的 **T-SIP-1…96**。本 #104 是**同一实现的 as-built 契约文档**，与前身条目的关系逐条列出：

| # | 前身条目说法 | HEAD 实测（2026-09-29） | 本版处置 |
|---|---|---|---|
| 1 | D-SIP-1 状态行写"存量 1 例 → P5 改写后 18 例"；T-SIP-1…57 状态行写"57/57 ×2 稳态+反查 68/68" | `cases/sip.json` 实测 **96 例**（T-SIP-1…96 全量落盘） | **前身数字是阶段快照**（18→24→43→57→96 五次扩量）；本版 §9 按 **96** 钉死 |
| 2 | D-SIP-1 §1 称 registry 行"Fields 4 键（dialog/media/src_port/dst_port）" | `registry.go:1857-1869` 实测 **8 键**（+sessions/medias/interleave/nat，D-SIP-2 四 WP 追加）；`layers.generated.json` 同 8 键逐键一致（机读实测） | **前身 4 键是 WP-A 之前快照**；本版 §11.1 按 8 键 |
| 3 | D-SIP-1 称 `isRawIPChain` 加 sip 即完成自驱接线 | `chain_planner_util.go:40-51` 实测**已加传输层守卫**（链含 tcp/udp → 返回 false）——D-SIP-2 WP-D 修的"自驱分支拦截事件面"缺陷 | 本版 §5 按现码：**双模式**（raw 自驱 / 事件面） |
| 4 | D-SIP-2 WP-D 称"drive meta 补 SIP 字段" | `chain_planner_translate.go:107`（事件面 drive 内联 meta）+ `chain_planner_chain.go:28`（`flowMetaFor`）**两处独立清单均已含 SIP** | **双清单是硬约束**：漏任一处则该路径 `req.Meta.SIP == nil` → 生成器报 `no config` 或静默空流。本版 §11.4 逐处点名（同族 sip 质询教训） |
| 5 | D-SIP-2 裁定 3 称 NAT 合成锚词为"`media is not supported on a tls sip chain`" | 实现锚词实测为 **`media is not supported on a tcp/tls sip chain`**（`event_gen.go:41` + `semantic.go:619/622` 同款） | **前身裁定的字面值与实现差一处**（`a tls` vs `a tcp/tls`）；本版 §7 按实现锚词 |
| 6 | D-SIP-1 §6 性能段称"基线 12（五消息）/空 dialog 7" | 实测公式 `单流 = 7 + Σ分段 + Σ媒体帧`，**× flows**；96 例中 28 例用精确 `packet_count`、59 例用 `min_packets` | 本版 §6/§9 按实测公式与两种断言语义分别钉 |
| 7 | T-SIP-1…57 称"RTP 帧 offset=42 实测校准（rtp.* 字段 tshark 3.6 无效改 frames pin）" | `cases` 实测：`sip_rtp_media` 帧 9 offset **42** hex `80`（RTP 头首字节 V=2）——**tshark 3.6.14 无 `rtp.*` 可用字段的结论今日仍成立**（本版未取到新证据推翻，按现状如实登记为 G-SIP-7） | 本版 §9 沿用 frames pin；RTP 字段面列缺口 |
| 8 | 前身条目未登记**下行信令包 L2 目的 MAC 取值缺陷** | `sip.go:338` 实测 `emitData("down", spec.DstMAC, spec.DstMAC, …)`——**第二参数应为 `spec.SrcMAC`**；同文件另三处 down emit（`:217`/`:379`/`:381`）均为 `spec.DstMAC, spec.SrcMAC` 正确形 | **本版新发现 confirmed finding（M-1）**，§3.8 详列 |

**依赖链判定纪律**：以上均为可判题（前身条目→代码行→cases 三级对照），直接判定，不问偏好。不可判的（真实 UA/服务器互操作字节）标"待确认"并写清确认方式（G-SIP-8）。

**产物过期登记（G-SIP-10，与 pcep G-PCEP-11 / opcua G-OPCUA-10 同口径）**：`trafficgen/docs/protocol-pcap-test/sip.md` 是 **tracked 结果产物**（`git ls-files` 可证），写 "Cases: 96 — pass 96, fail 0, error 0"，末次提交 `bbf4f7c`（**2026-09-20**）。该日期**晚于**判死提交 `0417be5`（2026-09-13，扁平判死泛化全协议 `CheckProtoFlat`），故**不构成"早于判死提交"的过期情形**；但该文件链接的 `trafficgen/docs/protocol-pcap-test/sip/` 目录**不存在**（`ls` 实测 No such file or directory，0 个 pcap 留档——`.gitignore:88 *.pcap` 使 pcap 从不入库）。**结论：96/96 数字来自 2026-09-20 那次真实跑，但其 pcap 证据未入库留档；本车道今日未复跑该套件**，故本文档**不以任何形式**引用该产物作为"今日已复跑"依据。

**sip 特殊性（须写清，不得含糊）**：sip 是本批**唯一的"信令 + 媒体流关联"双载体协议**——一条 TCP 信令连接派生零到多条独立 UDP 媒体子流（§4 流关联层、§12.3 五件套强制展开）。它与 opcua（单连接串行、无派生流）在流关联维度上**正好相反**，故本版的 §4/§5/§12.3 比 opcua 版厚得多。

## 1. 范围、profile 与实现状态边界

本版定义 **SIP 信令承载于 TCP（缺省 5060 / SIPS 5061）**，以及 **SDP 协商出的 RTP 媒体子流承载于 UDP** 的流量生成。

| profile | 承载层链 | 本版允许内容 | 不从 profile 推导 |
|---|---|---|---|
| `sip_raw_v1`（主） | `[ip, sip]`（**raw 自驱**，生成器自建 TCP 握手/挥手） | dialog 或 sessions 消息序列 + 可选 RTP 子流（media/medias）+ NAT rport | 真实 UA 状态机（Timer A/B/F、重传退避） |
| `sip_tcp_v1` | `[ip, tcp, sip]`（**事件面**，tcp 层持有握手/挥手/分段） | dialog 消息序列（明文） | sessions/media/medias（显式拒绝，§7） |
| `sip_tls_v1` | `[ip, tcp, tls, sip]`（**事件面 + TLS 变换器**） | 同上，Via 传输令牌写 `TLS` | 真实证书链校验（tls 层缺省全数据，G-SIP-4） |
| `sip_ipv6_v1` | 上述任一，外层 IPv6 | 同上 | 从 IPv4 fixture 推导 IPv6 地址 |

显式边界（"不实现、不声称、不许静默转换"）：① **不实现 RFC 3261 §17 事务定时器**（Timer A/B/D/E/F/G/H/K）与重传退避——重传由用户在 dialog 里显式写第二条同 CSeq 请求表达（`sip_100_trying_retrans` 即此形）；② **不实现 UDP 承载信令**（SIP over UDP）——信令恒走 TCP 或 TCP+TLS；③ **不实现真实摘要鉴权计算**——401/407 的 `WWW-Authenticate`/`Authorization` 头由用户原文承载，引擎不做 MD5/SHA 摘要（`sip_register_digest_auth`/`sip_invite_401_challenge` 只验证头族存在与事务序）；④ **不实现 RTP 加密**（SRTP）与 RTCP——只发 RTP 数据帧；⑤ **不实现 SDP 协商决策**——只从 SDP 文本里**读** `m=audio <port>` 与 `a=<direction>`（§3.6），不做 offer/answer 匹配；⑥ **不实现重定向跟随**——302 的 Contact 由用户显式写后续 INVITE 表达（`sip_302_redirect`）；⑦ **不实现事件包（SUBSCRIBE）的订阅状态机**——NOTIFY 由用户显式写。

**实现状态（2026-09-29 实测）**：`sip` 层已注册（`registry.go:1857`，`CategoryTerminal`，`DependsOn ["ip"]`，`OptionalOn ["tls"]`，Fields **8 键**）；生成器双模式已落码（`internal/protocol/sip/`：`sip.go` 1534 行 + `layer_gen.go` 102 行 + `event_gen.go` 103 行 = **1739 行**）；`allowedProtocols["sip"]=true`（`protocols.go:54`）；translate 已接线（`chain_planner_translate.go:1656` case "sip"）；`isRawIPChain` 含 sip 且带传输层守卫（`chain_planner_util.go:40-51`）；端口语义豁免已登记（`chain_planner.go:748` `validateBaseDstPortHandled` 含 sip）；schema 三道语义门（`checkSIPSessionsMutex:297` / `checkSIPMediasMutex:388` / `checkSIPEventPlane:588`）；96 语义用例已落 `cases/sip.json`。

**输出契约（pcap/NIC 双输出）**：两路径共用同一 cases JSON 与断言集（`tcp.flags`/`tcp.dstport`/`tcp.srcport`/`udp.srcport`/`udp.dstport`/`sip.*`/`ipv6.dst`/`tls.record.content_type` 字段 + offset 54/74/42 frames）；NIC 经 tcpdump 捕获（用例级 `nic_capture` 开关——**存量 96 例今日均未启用该开关**，见 G-SIP-6）；不设仅单路径可用的断言。

## 2. 协议栈、端口和固定偏移

推荐层链为 `[ip, sip]`（引擎自动补 `ip`；最小链 `[sip]`）。**raw 链**下 sip 层生成器自建 TCP 握手/挥手并把 SIP 文本作为 TCP payload 直出；**事件面链**（`[ip,tcp,(tls),sip]`）下握手/挥手/分段归 tcp 层，sip 只产消息事件。

端口：SIP 信令默认 **TCP 5060**（`chain_planner_translate.go:1722` dst_port 缺席补齐；RFC 3261 §19.2 明文承载缺省口）；SIPS 缺省 **5061**（**不自动注入**，用户显式写——D-SIP-2 决策 5，§14 G-SIP-4）。RTP 媒体端口缺省 **5004**（`sip.go:1096/1108`，标准 RTP 音频口），可由显式/动态/SDP `m=audio` 三路覆盖（§3.6）。fixture 统一 `dst_port=5060`（TLS 例写 5061）。

固定偏移（无 VLAN/IP options/TCP options 时）：
- **IPv4 + TCP 载荷起点 = offset 54**（14 eth + 20 ip + 20 tcp）——所有 `[ip,sip]` 信令帧与 `[ip,tcp,sip]` 事件面帧。
- **IPv6 + TCP 载荷起点 = offset 74**（14 + 40 + 20）。
- **IPv4 + UDP 载荷起点 = offset 42**（14 + 20 + 8）——RTP 媒体帧（`sip_rtp_media` 帧 9 offset 42 hex `80` = RTP 头首字节 V=2）。

目标形状 spec_json 样例（严格层链形，顶层仅 `layers`）：

```json
{
  "layers": [
    {"ip": {"src": "10.0.0.1", "dst": "20.0.0.1"}},
    {"sip": {"src_port": 12001, "dst_port": 5060, "dialog": [
      {"method": "INVITE", "uri": "sip:callee@20.0.0.1", "emit_media": true},
      {"status_code": 200, "status_text": "OK"},
      {"method": "ACK", "uri": "sip:callee@20.0.0.1"},
      {"method": "BYE", "uri": "sip:callee@20.0.0.1"},
      {"status_code": 200, "status_text": "OK"}
    ], "media": {"frames": 2}}}
  ]
}
```

多会话 + 媒体 + NAT 合成形（D-SIP-2 四 WP 全开；`sip_conf_burst_3party` 即此形）：

```json
{
  "layers": [
    {"ip": {"src": "10.0.0.1", "dst": "20.0.0.1"}},
    {"sip": {
      "nat": {"rport": true},
      "sessions": [
        {"src_port": 22001, "call_id": "party-a@10.0.0.1",
         "dialog": [{"method": "INVITE", "uri": "sip:conf@20.0.0.1", "emit_media": true},
                    {"status_code": 200, "status_text": "OK"},
                    {"method": "ACK", "uri": "sip:conf@20.0.0.1"}],
         "medias": [{"direction": "up", "frames": 2, "src_port": 30004},
                    {"direction": "down", "frames": 2, "src_port": 30005, "dst_port": 30006}]}
      ]}}
  ]
}
```

多流（数量只走 `strategy_fc`；四元组走层内动态对象，§12.12）：

```json
{
  "layers": [
    {"ip": {"src": {"strategy": "inc", "range": ["10.0.1.1", "10.0.1.2"], "step": 1}, "dst": "20.0.0.1"}},
    {"sip": {"src_port": {"strategy": "inc", "range": [20000, 20001], "step": 1},
             "dst_port": {"strategy": "fixed", "value": 5060},
             "dialog": [{"method": "INVITE", "uri": "sip:callee@20.0.0.1"}, {"status_code": 200, "status_text": "OK"}]}}
  ],
  "strategy_fc": {"type": "flows", "value": 2}
}
```

## 3. 线格式编码（RFC 3261 §7 文本格式，逐函数按代码钉）

### 3.1 消息总形（`renderSIPMessage`，`sip.go:455-503`）

```
请求行 / 状态行 CRLF
头1 CRLF
头2 CRLF
...
CRLF                      ← 头体分隔空行（无体时也必须有）
体（若有）
```

| 行型 | 格式 | 代码 |
|---|---|---|
| 请求行 | `<Method> SP <URI> SP "SIP/2.0" CRLF` | `sip.go:458-462` |
| 状态行 | `"SIP/2.0" SP <StatusCode> SP <StatusText> CRLF` | `sip.go:463-468` |
| 头 | 用户原文逐行 + `CRLF` | `sip.go:477-479` |
| 空行 | `CRLF`（**有无体都写**） | `sip.go:494-496`（有体）/ `:497-500`（无体） |
| 体 | `Body` 原文（无 CRLF 追加） | `sip.go:495` |

**`Method` 与 `StatusCode` 双空 → 返回 nil**（`sip.go:469-472`）：该消息**不产任何包**。这是 `sip_msg_empty_entry_skipped` 的语义钉点（§9）。

**Content-Length 自动追加**（`sip.go:490-493`）：当 `Body != ""` **且**头数组里没有 `Content-Length`（**大小写不敏感**，`EqualFold`，`sip.go:482-487`）时，追加 `Content-Length: <len(Body)>\r\n`。**用户自带的 Content-Length 恒赢、不重复追加**（`sip_hdr_cl_user_wins`）。注意 `len(Body)` 是**字节数**——`"v=0\r\n"` 计 5 字节不是 4。

**`Method` 与 `StatusCode` 双给**：`renderSIPMessage` 的 if/else-if **请求行优先**（`Method != ""` 即走请求行分支，`StatusCode` 被忽略）。引擎**不报错**——这是形状边界，非拒绝面（G-SIP-5）。

### 3.2 强制头补全（`completeDialogHeaders` / `completeRequestHeaders` / `completeResponseHeaders`）

RFC 3261 §8.1.1：Via / From / To / Call-ID / CSeq 是**每个请求必带**（外加 Max-Forwards），§8.1.3.2：响应**回显**它回答的那个请求的头。引擎实现"**user > 补全 > 无**"三态。

**状态载体 `dialogCtx`**（`sip.go:519-548`）：

| 字段 | 语义 |
|---|---|
| `active` | 对话已建立（见到或生成了 Call-ID） |
| `callID`/`from`/`to`/`via`/`maxForwards` | 对话级值，**首次出现即锁定**（首个请求的值为准） |
| `inviteCSeq` | 最近一次 INVITE 的 CSeq 号 |
| `cseqNext` | 最后一个非 ACK/CANCEL 请求的 CSeq 号 |
| `lastCSeq`/`lastFrom`/`lastTo`/`lastVia` | 最后一个请求的整行，供响应回显 |
| `defaultCallID`/`sessionScoped` | sessions 模式专用（§3.5） |
| `viaTransport` | 生成 Via 的传输令牌（`TCP` 自驱 / `TLS` 事件面，§3.4） |

**激活规则**（`sip.go:558-591`）：上下文**只从请求播种**——响应只消费，不定义对话值。含**纯响应**的 dialog（无任何请求）→ 上下文不激活 → 每条消息**逐字原文渲染**（响应不能凭空发明它回答的对话）。`Method` 与 `StatusCode` 双空的消息**直接返回**，不播种。

**Call-ID**（§8.1.1.4）：请求缺 Call-ID 且上下文未激活 → 生成 `Call-ID: sip<8位hex>@<srcIP>`（`generateCallID`，`sip.go:781-783`，hex 来自 `rand.Uint32()`）并**激活上下文**。sessions 模式下优先用 `defaultCallID`（§3.5）。

**CSeq 推进**（`completeRequestHeaders`，`sip.go:613-665`）：

| 情形 | 取值 |
|---|---|
| 用户显式写 CSeq | **原样保留**，并**重同步**计数器（INVITE → `inviteCSeq=cseqNext=n`；ACK/CANCEL → 不动；其余 → `cseqNext=n`） |
| INVITE 且 `cseqNext==0` | `n=1` |
| INVITE 且 `cseqNext!=0` | `n=cseqNext+1`（**re-INVITE = 新事务**，§14.1） |
| ACK / CANCEL | `n=inviteCSeq`（**复用 INVITE 事务号**，§13.2.2.4 / §9.1）；`inviteCSeq==0` 时取 1 |
| 其余方法 | `cseqNext==0 ? 1 : cseqNext+1` |

生成行 = `CSeq: <n> <Method>`（§20.16：CSeq 方法名必须与请求方法一致）。

**其余强制头生成**（`sip.go:667-694`）：

| 头 | 生成值 | 依据 |
|---|---|---|
| `Call-ID` | 上下文 `callID`（可能来自生成） | §20.8 |
| `From` | `From: <sip:user@<srcIP>>` | §8.1.1.3 |
| `To` | URI 以 `sip:`/`sips:` 开头 → `To: <URI>`；否则 `To: <sip:user@<dstIP>>` | §8.1.1.2 + §13.2.1 |
| `Via` | §3.4 | §8.1.1.7 |
| `Max-Forwards` | 对话级值，缺省 `Max-Forwards: 70` | §20.22 |

**地址渲染 `sipHostOf`**（`sip.go:764-772`）：空地址 → `0.0.0.0`；含 `:`（IPv6）→ `[addr]`（§19.1.1 方括号）；否则原样。

**响应回显**（`completeResponseHeaders`，`sip.go:706-722`）：缺失的 `Call-ID`/`From`/`To`/`Via`/`CSeq` 逐个回填 `dc.last*`（**CSeq 整行回显 = 号 + 方法名**，§8.1.3.2）。

### 3.3 头查找（`findHeader`，`sip.go:729-740`）

按**首个冒号**切分头名，`EqualFold` 大小写不敏感（§7.3.1）。无冒号的行跳过。返回**整行**（`"Call-ID: sip1@example.com"`）。

**`parseCSeqNumber`**（`sip.go:745-758`）：取冒号后首个十进制整数前缀，非法/缺失返回 0（调用方回退默认编号）。

### 3.4 Via 生成与传输令牌（`generateViaT` / `generateViaSess`）

| 模式 | 格式 | 代码 |
|---|---|---|
| dialog 模式 | `Via: SIP/2.0/<tr> <host>:<srcPort>;branch=z9hG4bK<8位hex>`（hex = `rand.Uint32()`） | `sip.go:860-862` |
| sessions 模式 | `Via: SIP/2.0/<tr> <host>:<srcPort>;branch=z9hG4bK-<8位hex>`（hex = **FNV-1a(callID)**，确定性可复现，§12.4） | `sip.go:871-882` |

`<tr>` 传输令牌：自驱 `[ip,sip]` 链 = `TCP`；事件面 tls 链 = `TLS`（RFC 3261 §26.2.1：SIPS 必须走 TLS）。**`generateViaT` 是唯一格式化点**（D-SIP-2 WP-D 单点化），自驱路径字节零漂移。`branch` 恒以 RFC 3261 §19.1.1 magic cookie `z9hG4bK` 开头。

**用户显式写的 Via 恒赢、不被重写**（只有 NAT 回填会改，§3.9）。

### 3.5 sessions 模式（`sip.go:394-433`）

`sessions[]` 每项 = **一条独立 TCP 信令连接**（独立握手/挥手/四元组/生命周期，CORE_MEMORY §3.1-3.3）。

| 字段 | 取值优先级 | 代码 |
|---|---|---|
| `src_port` | 显式标量 > 动态对象（`ResolvePortValue(SrcPortDyn, FlowIndex)`，非 0 才赢）> **派生 `12345 + FlowIndex×M + sessIdx`**（M = session 总数，防撞） | `sip.go:398-412` |
| `dst_port` | 显式 > 动态 > **`spec.DstPort`**（层预写值，缺省 5060） | `sip.go:404-415` |
| `call_id` | 显式 > 动态（`ResolveStringValue`，非空才赢）> **派生 `"{FlowIndex}-{sessIdx}@{srcIP}"`** | `sip.go:416-424` |

派生 Call-ID 在进 `dialogCtx` 前加前缀 `"Call-ID: "`（`sip.go:428`）——`dialogCtx.callID` 存的是**整行**，保持与 `findHeader`/`generateCallID` 的不变量一致。

**会话 FlowID** = `"{srcIP}-{dstIP}-{srcPort}-{dstPort}"`（`sip.go:429`）——**逐会话独立**，故 resequencer 按会话分别排序。

**与 dialog 互斥**：`len(Sessions)>0` 时**完全不看** `Dialog`（`sip.go:394` 提前 return）。互斥的**执法**在 schema（`checkSIPSessionsMutex`，create 期 400）与 `Validate`（task 期背 door）两路，**translate 只解析不判**（§7）。

### 3.6 RTP 媒体子流（`sipMediaStream` / `newSIPMediaStream` / `emitFrame`）

RTP 帧 = **12 字节头 + payload**，UDP 承载（`sip.go:1198-1230`）：

| 偏移 | 字段 | 值 |
|---|---|---|
| 0 | V/P/X/CC | `0x80`（V=2，无 padding/extension/CSRC） |
| 1 | M / PT | `pt & 0x7F`（M 恒 0）；`pt` 缺省 0 = PCMU |
| 2–3 | Sequence Number | **随机初值** + 帧序（`rand.Uint32()` 取低 16 位，RFC 3550 §5.1） |
| 4–7 | Timestamp | **随机初值** + `i × frameSize`（大端） |
| 8–11 | SSRC | **随机**（`rand.Uint32()`） |
| 12– | Payload | FileSource 分块 或 `frameSize` 字节零填充 |

**参数缺省**（`sip.go:1110-1118`）：`payload_type` 0（合法值，不 defaulting）；`sample_rate` 8000；`frame_size` 160（G.711 20ms @8kHz）；`frames` ≤0 → 1。

**端口推导四级优先**（`sip.go:1084-1109`，顺序 = `dyn > static > SDP > 5004`）：

| 级 | src_port 来源 | dst_port 来源 |
|---|---|---|
| 1 | `media.SrcPort` 显式 | `media.DstPort` 显式 |
| 2 | `media.SrcPortDyn` 动态对象（`ResolvePortValue(…, FlowIndex)`） | `media.DstPortDyn` |
| 3 | **INVITE 的 SDP `m=audio <port>`**（`scanSDPMediaPorts` 返回值 1） | **200 OK 的 SDP `m=audio <port>`**（返回值 2） |
| 4 | `5004` | `5004` |

**方向推导**（`sip.go:1119-1134`）：`media.Direction` 显式 > SDP `a=<direction>` 属性（`scanSDPDirection`）> `"up"`。`a=sendonly` → up（offerer 发）；`a=recvonly` → down（answerer 发）；`a=sendrecv`/`inactive`/缺失 → up（`parseSDPDirection`，`sip.go:1318-1334`）。

**下行线元组交换**（`sip.go:1140-1150`，`strings.EqualFold(dir,"down")`）：`srcIP/srcMAC/srcPort` ← 对端值，`dstIP/dstMAC/dstPort` ← 本端值。即 `medias[{direction:"down", src_port:30005, dst_port:30006}]` 上线为 **src=30006 / dst=30005**（`sip_medias_bidirectional` P5 校准钉）。

**SDP 扫描状态机 `scanSDPMediaPorts`**（`sip.go:1387-1453`）：跟踪"下一个 200 OK 回答的是谁"——INVITE 置 `lastWasInvite` 并清 pending；非 INVITE 请求置 `pendingNonInviteMethod`；200 OK 仅当 pending 是 **UPDATE**（RFC 3311 会话修改）或 pending 空且 `lastWasInvite` 时才捕获 `ok200Port`（last-wins，支持 re-INVITE）；ACK 捕获 `invitePort`（delayed-offer）。

**`scanSDPDirection`**（`sip.go:1473-1485`）：**只扫 INVITE 与 ACK 的体**（offerer 侧，RFC 3264 §5.1）；200 OK 的 answerer 体**不扫**（answerer 可翻转方向，§6.1）。

**SDP 正则**（`sip.go:1270`/`:1295`）：`m=audio[ \t]+(\d+)` 多行锚定（**空格/制表符，不匹配 CRLF**——防"下一行的数字"被误当端口）；`^[ \t]*a=(sendonly|recvonly|sendrecv|inactive)[ \t]*\r?$` 大小写不敏感 + 行尾锚定。**只匹配 `m=audio`**，video/application/data 跳过（引擎只发音频 RTP）。

**FileSource 优先合同**（`sip.go:1047-1070`）：`FileSource != nil` 时经 `PayloadCache.GetOrLoad` 取字节，按 `FrameSize` 切块，**帧数由字节数决定**（覆盖 `Frames`）；`FrameSize ≤ 0` → 整块一帧；空字节 → 仍发 1 帧。**无 cache 注入时返回 nil = 不发子流**（不静默退化为零字节合成，`sip.go:1049-1051`）。

**子流 FlowID**（`sip.go:249-259`）：单 `media` → `"{parentFlowID}:rtp"`；`medias[i]` → `"{parentFlowID}:rtp-<direction小写>"`（CORE_MEMORY §3.10 `parent:sub-idx` 形状）。

**交错调度（`interleave:true`）**（`sip.go:266-271` + `:305-308` + `:370-372`）：设总帧数 T、间隔数 G（= EmitMedia 消息之后的剩余消息数 + 1），第 g 个间隔承担 `T/G + (g < T%G ? 1 : 0)` 帧（**确定性等分**，CORE_MEMORY §3.12）。`sip_medias_interleave`：T=4/G=3 → 2/1/1。**无 interleave** 时全部帧在 EmitMedia 消息后一次性 round-robin 发出（up/down 交替 = RFC 3550 真双向）。

### 3.7 TCP 载体（raw 自驱链）

| 阶段 | 帧 | flags | 代码 |
|---|---|---|---|
| 握手 | SYN(up) / SYN-ACK(down) / ACK(up) | `0x02` / `0x12` / `0x10` | `sip.go:214-220` |
| 数据 | 每条 SIP 消息按 MSS 分段，每段 PSH-ACK | `0x18` | `sip.go:224-230` |
| 挥手 | FIN-ACK(up) / ACK(down) / FIN-ACK(down) / ACK(up) | `0x11` / `0x10` / `0x11` / `0x10` | `sip.go:376-384` |

**MSS**（`sip.go:143-147`）：`spec.TCP.MSS > 0` 则用之，否则 `DefaultMSS = 1460`（RFC 879 下限 `MinMSS = 536`）。SYN 与 SYN-ACK 携带 TCP options：**MSS + Window Scale(0x07) + SACK-Permitted**（`synOptions`，`sip.go:926-935`）。

**分段**（`segmentByMSS`，`sip.go:903-920`）：按 MSS 切块，末段可短；**空 payload → 单个空块**（仍发 1 段 PSH-ACK）。段间 seq 连续递增。

**序列空间**：每方向**连续**（`clientSeq`/`serverSeq` 各自推进）；每条消息的 ACK 覆盖对端已发全部字节。ISN 随机（RFC 6528），`spec.TCP.InitialSeq` 可固定（可复现测试）；server ISN 恒随机。

**窗口**：恒 `65535`（`sip.go:177`）。

### 3.8 M-1：下行信令包 L2 目的 MAC 取值错（confirmed finding）

| 项 | 值 | 出处 |
|---|---|---|
| 本实现 | 下行 **SIP 信令 payload** 段的 L2 = `SrcMAC=spec.DstMAC` / `DstMAC=spec.DstMAC` | `sip.go:338`：`emitData("down", spec.DstMAC, spec.DstMAC, spec.DstIP, spec.SrcIP, dstPort, srcPort, …)` |
| 应为 | `SrcMAC=spec.DstMAC` / **`DstMAC=spec.SrcMAC`** | 同文件另三处 down emit 的正确形：`:217` SYN-ACK、`:379` 服务器 ACK、`:381` 服务器 FIN-ACK 均为 `emit("down", spec.DstMAC, spec.SrcMAC, …)` |
| 影响面 | **84 例**（全部 `[ip,sip]` raw 链中**含至少一条下行响应消息**的用例）的响应帧 L2 目的 MAC 等于本机 MAC | 机读：96 例中 **90 例** raw 链，其中 **84 例**含下行响应消息（另 6 例为纯请求或空 dialog，无下行 payload 帧）；raw 链下行 payload 全部走该行 |
| 为何存量 96 例全绿 | ① cases **零 L2 断言**（`grep` 实测：96 例 `expect` 无 `eth.*` 字段）；② raw-IP Emit 补偿逻辑（`chain_planner.go:1543-1550`）只在 `SrcMAC==""` / `DstMAC==""` 时才补 `l2For`，此处两值均非空故**不补偿**；③ 唯一断言 L2 的单测（`sip_rtp_test.go:476`）只查 RTP 帧的 `EtherType`，不查 MAC | 三条独立原因叠加 |
| 不受影响面 | **RTP 子流**（`sipMediaStream` 自建正确元组，`sip.go:1140-1150`）；**事件面链**（L2 由 tcp 层/`l2For` 生成）；TCP 握手/挥手四帧 | 逐处对照 |

**修复**：`sip.go:338` 第二参数改为 `spec.SrcMAC`。**修复后须重跑后钉**：**帧数与所有现存断言不变**（MAC 不在任何断言面内），但建议同步新增 L2 断言用例（§13 A′）。

### 3.9 NAT rport/received 回填（RFC 3581 §4，`rewriteViaRPort`，`sip.go:814-843`）

**只作用于 up 请求**（`sip.go:322-330`；下行响应**逐字回放用户原文**，零二次改写——D-SIP-2 裁定 3 的诚实边界）。

| 情形 | 行为 |
|---|---|
| Via 含裸 `;rport` 参数 | 替换为 `rport=<实际srcPort>`，并补 `received=<srcIP>`（**无需开关**——RFC 3581 客户端行为） |
| Via 含 `rport=<值>` | 替换为实际值 |
| Via 含 `received=<值>` | 替换为实际 srcIP |
| Via 无任何 rport 标记 **且** `nat.rport=true` | **追加** `;rport=<port>;received=<host>` |
| Via 无任何 rport 标记 **且** `nat.rport` 未开 | **原样返回**（零字节漂移线） |

参数按 `;` 切分逐段比对（`TrimSpace` + `ToLower`）。**会话模式下 `<实际srcPort>` = 该会话的真实端口**（非 spec 端口）——`sip_nat_sessions_port` 钉：会话 `src_port=22001` → `rport=22001;received=10.0.0.1`。

## 4. 业务场景分析（现网典型场景与五层覆盖）

**定性**：**声明式剧本回放**——配置声明一段信令消息序列（dialog）或多段独立连接（sessions），可选声明 RTP 媒体流；引擎按固定剧本产出事件序列，TCP 握手/挥手/分段由自驱路径自建或由 tcp 层托管。

| 现网场景 | 事务交互 | 对应用例 |
|---|---|---|
| ① 基础呼叫建立/释放 | INVITE→100→180→200→ACK→BYE→200 | #1 `sip_basic_dialog`、#19 `sip_reinvite_refresh` |
| ② 注册与生命周期 | REGISTER→401→REGISTER+Authorization→200；REGISTER Expires:0 注销 | #6、#25、#26 |
| ③ 能力探测/保活 | OPTIONS→200；会话中 OPTIONS 保活 | #7、#22 |
| ④ 会话内重协商 | re-INVITE / UPDATE / HOLD-resume / 491 glare | #19、#31、#34、#53 |
| ⑤ 异常结束 | CANCEL→487 / 486 Busy / 302 重定向 / 503 Retry-After | #20、#21、#33、#94 |
| ⑥ 媒体子流 | INVITE 带 SDP → RTP 双向（端口由 SDP 派生） | #11、#12、#13、#14、#72、#73、#76 |
| ⑦ 多会话并发 | sessions[] 多独立连接，各自 Call-ID/四元组/生命周期 | #58、#59、#60、#71 |
| ⑧ NAT 穿越 | Via rport/received 发射期回填 | #77、#78、#79、#80 |
| ⑨ 加密信令 | SIPS over TLS，Via 令牌 TLS | #81、#82 |
| ⑩ 增值业务 | REFER 转移 / SUBSCRIBE-NOTIFY MWI / PUBLISH / MESSAGE / INFO DTMF / 会议 | #28、#29、#36、#46、#47、#49 |
| ⑪ 多方与并发 | 并行分叉 / 同连接交错双呼 / 三方会议风暴 | #45、#54、#87 |

**五层覆盖逐层结论**：

- **功能层**——方法面 **14 个方法**（机读实测：INVITE/ACK/BYE/CANCEL/REGISTER/OPTIONS/PRACK/REFER/NOTIFY/SUBSCRIBE/INFO/UPDATE/MESSAGE/PUBLISH）+ 响应码面 **25 个码值**（机读实测）：1xx{100,180,183}/2xx{200,202}/3xx{300,302}/4xx{401,403,404,407,408,420,422,480,481,486,487,488,489,491}/5xx{500,503}/6xx{600,603}；头补全三态（生成/user 赢/纯响应 verbatim）；错误处理 **9 条负例覆盖 7 条独立锚词**（§7）。
- **性能层**——MSS 分段（3000B → 3 段，`sip_mss_segment`）；超长头与长 URI（512B 级 Digest + 226B 参数化 URI，`sip_long_auth_uri`）；最大帧（三方会议 42 包，`sip_conf_burst_3party`）；RTP 帧长（`frame_size` 160 缺省，FileSource 分块）；多流并发（flows=2 × 会话数）。帧长公式与容量约束见 §6。
- **数据场景层**——文本编码（UTF-8 display name / tel: URI / 引号显示名）；体形态（SDP 单流/双流/无体/multipart/pidf/conference-info/sipfrag/dtmf-relay/ISUP）；头方言（紧凑形 `v=/f=/t=/i=/l=`、头名大小写混写、多跳 Via 链、IMS P 头、Reason Q.850、History-Info）；空值（空 dialog、空消息条目）；边界（Content-Length 用户值 vs 自动值）。
- **地址与流层**——**IPv4 与 IPv6 双族**独立用例（#15 `sip_v6` offset 74、#57 `sip_v6_port_dyn`、#71 `sip_sessions_v6`；IPv6 字面量在头值里加方括号 §19.1.1）；**单流基线**（#1）；**流关联**（信令→媒体主从，§12.3 强制展开）；**多会话**（sessions[]，#58/#59/#60/#71）；**多流**（flows=2 的 12 例动态格）。
- **业务层**——十一类现网场景全部有落点（上表）；多事务（同连接多笔请求/响应，CSeq 驱动顺序）；多会话（独立状态互不串用，#58 断言两会话 Call-ID 各自独立）。

**次要合法行为显式不适用声明（不设正例、亦不得进负例）**：① RFC 3261 §17 事务定时器与重传退避（未实现，§1 边界①）；② SIP over UDP 信令承载（未实现，§1 边界②）；③ 真实摘要鉴权计算（未实现，§1 边界③）；④ SRTP/RTCP（未实现，§1 边界④）；⑤ SDP offer/answer 匹配决策（未实现，只读不决策，§1 边界⑤）；⑥ 重定向自动跟随（未实现，§1 边界⑥）；⑦ SUBSCRIBE 订阅状态机（未实现，§1 边界⑦）；⑧ 事件面链上的 media/medias/sessions（**显式拒绝**，§7 锚词——不是"不适用"，是"判死"）。

## 5. 消息/事务模型与状态机

### 5.1 事务定义与多事务

**事务** = 一次请求 + 它引发的响应（RFC 3261 §17）。**多事务** = 一条连接内多笔按序执行的事务，关联标识 = **CSeq 号**（§3.2 的推进规则保证同对话内单调、ACK/CANCEL 复用 INVITE 号）。

**引擎不做事务状态机**（无 Timer、无重传）——事务序完全由 `dialog[]` 数组顺序驱动，CSeq 由 `completeRequestHeaders` 的计数器按上述规则自动编号。**这是"剧本回放"与"协议栈"的分界**：引擎保证产出的 CSeq 序列**合法**（符合 §14.1 单调与 §13.2.2.4 复用），但不实现超时重传。

### 5.2 INVITE→100→180→200→ACK→BYE 全流程（用例 #1 实测帧位）

| 帧 | 方向 | 内容 | 说明 |
|---:|---|---|---|
| 1 | up | SYN | 自驱 TCP 握手 |
| 2 | down | SYN-ACK | |
| 3 | up | ACK | |
| 4 | up | `INVITE sip:callee@20.0.0.1 SIP/2.0` | 请求行 + 用户头 + 补全头 |
| 5 | down | `SIP/2.0 200 OK` | 响应回显请求的 Call-ID/CSeq/From/To/Via |
| 6 | up | `ACK …` | CSeq 复用 INVITE 号（实测 seq=1 method=ACK） |
| 7 | up | `BYE …` | CSeq 递增（实测 seq=2 method=BYE） |
| 8 | down | `SIP/2.0 200 OK` | 回显 BYE 的 CSeq |
| 9–12 | up/down | FIN-ACK / ACK / FIN-ACK / ACK | 自驱 TCP 挥手 |

包数 = 3 + 5 + 4 = **12** ✓（`packet_count=12`）。

### 5.3 状态集合（dialog 上下文状态机）

引擎的"状态"就是 `dialogCtx`（§3.2），其状态集合与转移：

| 状态 | 进入条件 | 事件 | 转移 |
|---|---|---|---|
| **未激活** | 初始 | 请求带 Call-ID | → 激活，锁定对话值 |
| 未激活 | | 请求不带 Call-ID | → **生成 Call-ID** → 激活 |
| 未激活 | | 响应 | 保持未激活，**逐字原文渲染** |
| **激活** | | 后续请求带 Call-ID | 值不变（首次出现即锁定，后续请求的 Call-ID **不回改**对话值） |
| 激活 | | 请求缺某强制头 | 补 `dc.*` 或生成 |
| 激活 | | 响应缺某强制头 | 回填 `dc.last*` |

**非法转移（引擎行为，逐条写明）**：

| 非法输入 | 引擎行为 | 依据 |
|---|---|---|
| `Method` 与 `StatusCode` 双空 | **静默跳过该条，不产包** | `sip.go:469-472` + `:314-316`；用例 #96 |
| `Direction` 既非 `up` 也非 `down`（非空） | **静默跳过该条** | `sip.go:314-316` |
| 渲染后 payload 为空 | **静默跳过该条** | `sip.go:332-334` |
| 响应出现在任何请求之前 | 上下文未激活 → **原文渲染**（不补头） | `sip.go:588-590` |
| `sessions` 与 `dialog` 同给 | **400 拒绝**（create 期 schema + task 期 Validate 双路） | §7 N-3 |
| `media` 与 `medias` 同给 | **400 拒绝**（双路） | §7 N-5 |
| 事件面链上给 `sessions`/`media`/`medias` | **400 拒绝**（schema + 生成器运行时双保险） | §7 N-6/N-7/N-9 |
| `sips:` URI 在无 tls 的链上 | **400 拒绝** | §7 N-8 |

### 5.4 自动派生规则（逐个列出触发条件与内容）

| 派生帧/字段 | 触发条件 | 内容 | 代码 |
|---|---|---|---|
| TCP 三握手 | raw 链，每个 session/flow 起始 | SYN / SYN-ACK / ACK（带 MSS+WS+SACK options） | `sip.go:214-220` |
| TCP 四挥手 | raw 链，每个 session/flow 结尾 | FIN-ACK / ACK / FIN-ACK / ACK | `sip.go:376-384` |
| MSS 分段 | 单条消息渲染后长度 > MSS | 切成 ⌈len/MSS⌉ 段 PSH-ACK，seq 连续 | `sip.go:224-230` |
| `Content-Length` | `Body != ""` 且用户未写 | `Content-Length: <字节数>` | `sip.go:490-493` |
| `Call-ID` | 请求缺且上下文未激活 | `sip<8hex>@<srcIP>`（dialog）/ `{flow}-{sess}@{srcIP}`（sessions） | `sip.go:616-623`/`:422-424` |
| `From` | 请求缺且对话无值 | `From: <sip:user@<srcIP>>` | `sip.go:670-675` |
| `To` | 请求缺且对话无值 | `To: <URI>` 或 `To: <sip:user@<dstIP>>` | `sip.go:676-681` |
| `Via` | 请求缺且对话无值 | `Via: SIP/2.0/<tr> <host>:<port>;branch=z9hG4bK…` | `sip.go:682-687` |
| `Max-Forwards` | 请求缺且对话无值 | `Max-Forwards: 70` | `sip.go:688-694` |
| `CSeq` | 请求缺 | `CSeq: <n> <Method>`（§3.2 规则） | `sip.go:636-665` |
| 响应五头回显 | 响应缺且 `dc.active` | `dc.last{CSeq,From,To,Via}` + `dc.callID` | `sip.go:706-722` |
| Via rport/received | up 请求 + 裸 `;rport` 或 `nat.rport` | `rport=<实际端口>;received=<srcIP>` | `sip.go:814-843` |
| RTP 帧 | 某消息 `emit_media:true` 且 media/medias 非空 | N 帧 UDP RTP（12B 头 + payload） | `sip.go:349-367` |
| 交错插帧 | `interleave:true` 且有媒体 | 按 T/G 等分插在后续消息之间 | `sip.go:266-271`/`:305-308`/`:370-372` |

**生成器在某状态下遇到合法/非法事件分别做什么**：合法 → 按上表派生并发射；非法（§5.3 表）→ **静默跳过**（空消息/非法方向/空 payload）或 **拒绝整任务**（互斥/载体/URI 类）。**静默跳过 vs 拒绝的分界**：影响**单条消息**的非法 → 跳过（其余消息照常，用例 #96 钉）；影响**整体结构**的非法 → 拒绝（§7）。

### 5.5 双模式分派（raw 自驱 vs 事件面）

| 链形 | `isRawIPChain` | `InitChain` 结果 | `GenEvents()` | 路径 |
|---|---|---|---|---|
| `[ip, sip]` | **true**（链无 tcp/udp，末层 sip） | `eventMode=false` | **nil** | raw 自驱：`Generator.Generate` 调 `legacy.Plan` 拿完整包，`Direction="up"` 强制（防 raw-IP 驱动二次换向），逐包 `Emit` |
| `[ip, tcp, sip]` | false（有 tcp） | `eventMode=true` | `g` | 事件面：`generateEvents` 把 dialog 翻成 `MessageEvent`，tcp 层持有握手/挥手/分段 |
| `[ip, tcp, tls, sip]` | false | `eventMode=true, tlsMode=true` | `g` | 事件面 + TLS 变换器；Via 令牌写 `TLS` |

**`isRawIPChain` 的传输层守卫**（`chain_planner_util.go:44-48`）是硬约束：链里出现 `tcp` 或 `udp` 即返回 false——**raw 自驱（自建握手挥手）绝不允许拦截事件面链**，否则双份握手。这是 D-SIP-2 WP-D 修的缺陷，**本版 §11.7 列为不可回退点**。

**事件面形状拒绝**（`event_gen.go:37-42`）：`len(Sessions)>0` 或 `Media!=nil` 或 `len(Medias)>0` → 报错。**`interleave` 不拒**（无 media 即惰性，`event_gen.go` 未检查）。

**事件面方向**（`event_gen.go:67-73`）：`msg.Direction` 空则 `inferDirection`；非 up/down 则 `continue`（跳过）。

**`EmitEvent` 未接线**（`event_gen.go:101-103`）：显式返回错误，防误调——事件只走 `GenRequest.EmitMsg` 同步回调。

## 6. 性能设计与验收（CORE_MEMORY §6.1–6.8）

- **目标与边界**：单流包数公式见 §9；最大用例 **42 包**（`sip_conf_burst_3party`：三会话 19+9+13=41 消息+握手挥手，实测 42）；单条消息分段上界 = ⌈渲染长/MSS⌉；RTP 帧数由 `frames`/FileSource 字节数决定。吞吐数字**待基准，本版不写承诺**（§6.5）。
- **依据**：事件序列**流式产出**——`Plan` 返回 `chan PacketConfig`（缓冲 **256**，`sip.go:126`），逐包发射无全量收集；`dialogCtx` 与 `sipMediaStream` 均为**流内局部状态**（`runSession` 闭包内），**无跨流共享**、**无锁**（仅 `rand` 全局源）；`sessions` 仅增一层 for 循环，零新增常驻内存。RTP 帧 payload 为 `frameSize` 字节零填充或 FileSource 分块，**无累加缓冲**。
- **验收两路（§6.3 强制）**：pcap 路径 = 套件（`/tmp/mcp-pcaps/sip/` 为历史落盘位，**今日未复跑**，G-SIP-10）；NIC 路径 = `enp135s0f0np0` + 用例级 `nic_capture` 开关（**存量 96 例均未启用**，G-SIP-6）。两路共用同一断言集，不设单路径专用断言。
- **六类场景落点（§6.6）**：基线（#1，12 包）/ 目标规模（#87，42 包）/ 压力上限（#39 超长头 + #10 MSS 分段）/ 长时间运行（`sip_options_keepalive` #22 的会话中保活承载语义）/ 并发交错（#54 同连接交错双呼、#73 interleave 媒体插帧）/ 背压（`packet_count` 精确计数守卫帧数漂移——28 例精确值 + 59 例下界）。
- **帧长公式**：TCP 帧长 = 14 + 20/40 + 20 + payload 段长（IPv4/IPv6）；RTP 帧长 = 14 + 20 + 8 + 12 + payload = **54 + payload**（IPv4）。MSS 只约束 SIP 文本段，不约束 RTP。

## 7. 错误处理（负例锚词表，与 testcase §4 一一对应、同序）

以下输入必须被 schema（create 期 400）或 planner/生成器（task 期）拒绝并传播为 task error，不得产出成功 PCAP、`completed/0 packet` 或只剩 TCP 外壳的假成功：

| # | 负例 ID | 故障输入 | 锚词（代码逐字） | 代码行 |
|---:|---|---|---|---|
| N-1 | `sip_flat_presence` | 顶层 `sip` 子映射存在（**空 map 也死**） | `protocol sip no longer accepts a top-level sip sub-config (move it into the sip layer of an [ip,sip] layers chain)` | `strategy_convert.go:8970` |
| N-2 | `sip_flat_static_port` | 层内标量端口 + `flows=2` | `layers pin a static four-tuple but flows > 1: every flow would emit identical addresses/ports (static copy). …` | `semantic.go:285` |
| N-3 | `sip_neg_sessions_dialog_mutex` | `sessions` 与 `dialog` 同给 | `sip: sessions and dialog are mutually exclusive (use sessions for the multi-session shape, dialog for the single-dialog shorthand)` | `semantic.go:311` + `sip.go:110` |
| N-4 | `sip_neg_sessions_empty` | `sessions: []`（空数组，同锚词面） | 同 N-3 | `semantic.go:314` |
| N-5 | `sip_neg_sessions_static` | `sessions[].src_port` 标量 + `flows=2` | 同 N-2 | `semantic.go:273`（嵌套扫描） |
| N-6 | `sip_neg_medias_mutex` | `media` 与 `medias` 同给 | `sip: media and medias are mutually exclusive (use media for a single stream, medias for the multi-stream shape)` | `semantic.go:402` + `sip.go:115` |
| N-7 | `sip_neg_tls_media` | tls 链上给 `media` | `sip generator: media is not supported on a tcp/tls sip chain (RTP is a bare UDP stream outside the transport; use the self-drive [ip, sip] chain for media)` | `semantic.go:619` + `event_gen.go:41` |
| N-8 | `sip_neg_sips_no_tls` | 无 tls 链上 `sips:` URI | `sip: sips uri requires a tls layer in the chain` | `semantic.go:628` + `event_gen.go:48` |
| N-9 | `sip_neg_tls_sessions` | tls 链上给 `sessions` | `sip generator: sessions are not supported on a tcp/tls sip chain (one connection per chain; use the self-drive [ip, sip] chain for sessions)` | `semantic.go:616` + `event_gen.go:38` |

**锚词口径**：`error_contains` 是**子串**判定；9 例覆盖 **7 条独立锚词**（机读去重实测：N-2/N-5 同锚词不同注入点；N-3/N-4 同锚词不同形状；载体族 N-7/N-8/N-9 各一条独立锚词）。**expect 键形状**：7 例严格两键 `{expect_error, error_contains}`，2 例（N-1/N-2）含 `notes`——**与严格两键口径不符**，列缺口 G-SIP-2。

**双路闭合（C 类，两路独立）**：N-3/N-4/N-5/N-6 由 `checkSIPSessionsMutex`/`checkSIPMediasMutex`/`checkLayerChainStaticCopy`（create 期）+ `Planner.Validate`（task 期背 door）两路独立执法，**锚词同文案**；N-7/N-8/N-9 由 `checkSIPEventPlane`（create 期）+ `event_gen.go`（运行时）两路。

**未入用例的拒绝分支（A′ 立项，不得冒充已覆盖）**：
- `invalid source IP: %s` / `invalid destination IP: %s`（`sip.go:91`/`:96`）——链路径由 schema 先拦（IP 语法校验），**层内不可达**。
- `MSS %d too small (min %d per RFC 879)`（`sip.go:102`）——**层内不可达**（MSS 住 `spec.TCP`，链路径 `spec.TCP` 恒 nil，`sip.go:100` 的 `spec.TCP != nil` 短路）。
- `sip generator: invalid request`（`layer_gen.go:58`）——防御性，生产不可达。
- `sip generator: no config (spec.sip required)`（`event_gen.go:31`）——translate 恒填非 nil，不可达。
- `sip generator: sip: sips uri requires a tls layer in the chain`（`event_gen.go:48`）——schema 先拦，运行时为背 door。

**不得误报的合法协议事件**：多节点/多事务同连接（#55 五事务）；多会话（#58）；双向 RTP（#72）；`interleave`（#73）；NAT 回填（#77/#78）；纯响应 dialog（原文渲染）；空消息条目（#96 静默跳过）；`Content-Length` 用户值（#95）；SIPS over TLS（#81/#82）。

## 8. 边界

- **包数**：见 §9 公式；实测最大 42（#87）、最小 7（#18 空 dialog）。
- **帧长**：SIP 文本段 ≤ MSS（1460 缺省 / 用户值，下限 536）；RTP 帧 = 54 + `frame_size`（缺省 160 → 214B）。
- **端口**：信令 5060 缺省（显式可覆盖）；SIPS 5061 **用户显式写**（不自动注入）；RTP 5004 缺省（显式/动态/SDP 三路覆盖）。
- **地址族**：v4/v6 独立用例（#15/#57/#71 为 IPv6）；**异族混写（ip 层 v4 + sip 层 v6 语义）无专门拒绝门** → G-SIP-5。
- **`Method` 与 `StatusCode` 双给**：请求行优先，不报错 → G-SIP-5。
- **sessions 端口派生**：`12345 + FlowIndex×M + sessIdx`；**显式写死则撞号 = 用户责任**（§12.9 只拒"完全静态 + 多流"）。
- **SDP 扫描范围**：`scanSDPMediaPorts`/`scanSDPDirection` **扫全 dialog**（不限于当前 EmitMedia 索引之前）——**future-bleed 已知限制**（`sip.go:1077-1081` / `:1469-1472` 代码自认），re-INVITE 之后的端口会前渗到先前的 emit。**明确不解决**（修复需传 dialog index，大重构）→ G-SIP-3。
- **RTP 随机量**：seq/timestamp/ssrc 随机（RFC 3550 合同），**不钉值**；TCP ISN 随机（`spec.TCP.InitialSeq` 可固定，链路径不可达）。
- **不得产生回绕长度或超量分配**：分段与切块均为流式，无累加缓冲。

## 9. 原子 ID 与完成定义（96 个唯一语义 ID，顺序为权威）

**总览**：96 例 = **87 正 + 9 负**；层链分布 = `[ip,sip]` **90** / `[ip,tcp,tls,sip]` **4** / `[ip,tcp,sip]` **2**。

**包数公式（实测反推，机读校验 85/87 精确命中）**：

```
单流（raw [ip,sip]，dialog 形）  = 7 + Σ消息分段数 + Σ媒体帧数
单流（raw [ip,sip]，sessions 形）= Σ_sess (7 + Σ该会话消息分段数 + Σ该会话媒体帧数)
单流（事件面 [ip,tcp,sip]）      = 7 + Σ消息数
单流（事件面 [ip,tcp,tls,sip]）  = 7 + 7 + Σ消息数        （+7 = TLS 握手 record）
总包数 = 单流 × flows                                    （strategy_fc.value）
其中 7 = 3（TCP 握手）+ 4（TCP 挥手）；Σ消息分段数 = Σ ⌈渲染长/MSS⌉
```

**校验（机读逐例）**：#1（5 消息/12 包）= 7+5 ✓；#18（空 dialog）= 7 ✓；#58（2 会话 × 2 消息）= 2×(7+2)=18 ✓；#87（3 会话 8+3+2 消息 + 4 帧）= (7+8+4)+(7+3)+(7+2)=42 ✓；#81（TLS，2 消息）= 7+7+2=16 ✓；#17（flows=2 × 5 消息）= 2×12=24 ✓；#73（interleave，3 消息 + 4 帧）= 7+3+4=14 ✓。**28 例精确 `packet_count` 全部命中（28/28）**；59 例 `min_packets` 中 **56 例满足**（公式值 ≥ 下界），**1 例例外**（#10 `sip_mss_segment`，见下），另 **2 例下界低于公式值**（宽松下界：#55 `sip_status_enum_4xx` min=21 vs 公式 22、#56 `sip_status_enum_56xx` min=12 vs 公式 13——**下界是容忍值，不要求等于**）。合计 **85/87 满足**。

**#10 的包数说明**：`sip_mss_segment` 用 `min_packets=11`，而"消息数"公式给 9（3+1+1+4）——**差额 2 来自 MSS 分段**：3000B 体渲染后总长 3235B（含补全头与 `Content-Length` 行），按 MSS=1460 切为 1460+1460+315 **三段**，故 3+3+1+4=**11**。用下界而非精确值断言，是因**分段数是渲染后长度的函数**，会随头补全规则演化而漂移（cases `notes` 记"P5 校准：末段=315"）。**即：`Σ消息分段数` 只在消息长 ≤ MSS 时等于 `Σ消息数`**——本版公式的"消息数"简写对 **86/87 例成立**（其余例的渲染长均 ≤1460），唯 #10 例外且已用下界覆盖。

**两种断言语义**：**28 例**用精确 `packet_count`；**59 例**用 `min_packets`（下界，容忍分段数变化）；**9 例负例无包数**。

### 9.1 逐 ID 索引（96 行，顺序 = cases JSON 顺序 = 权威）

| # | ID | 类型 | 覆盖（设计 §） | 包数 |
|---:|---|---|---|---:|
| 1 | `sip_basic_dialog` | 正 | §3.1/§3.2/§5.2：五消息基础对话 | 12 |
| 2 | `sip_flat_presence` | 负 | §7 N-1：顶层 sip 子映射判死 | — |
| 3 | `sip_flat_static_port` | 负 | §7 N-2：静态四元组 + flows=2 | — |
| 4 | `sip_hdr_completion` | 正 | §3.2：无头 INVITE 全生成 | 12 |
| 5 | `sip_hdr_user_wins` | 正 | §3.2：user 头赢 + 响应回显 | 9 |
| 6 | `sip_register` | 正 | §5.1：REGISTER 方法枚举 | 9 |
| 7 | `sip_options` | 正 | §5.1：OPTIONS 方法枚举 | 9 |
| 8 | `sip_status_codes` | 正 | §5.1：100/180/200/404 枚举 | 15 |
| 9 | `sip_sdp_body` | 正 | §3.1：SDP 体 + CL 自动 | 9 |
| 10 | `sip_mss_segment` | 正 | §3.7：3000B → MSS 分段 | ≥11 |
| 11 | `sip_rtp_media` | 正 | §3.6：RTP 子流（frames=2） | 14 |
| 12 | `sip_rtp_down` | 正 | §3.6：RTP down + 显式端口交换 | 10 |
| 13 | `sip_sdp_port` | 正 | §3.6：SDP `m=` 派生端口 | 10 |
| 14 | `sip_rtp_filesource` | 正 | §3.6：FileSource 优先 | 10 |
| 15 | `sip_v6` | 正 | §2：IPv6 offset 74 | 12 |
| 16 | `sip_default_port` | 正 | §2：缺省 5060 | 12 |
| 17 | `sip_port_dyn` | 正 | §12.12：层端口动态 + flows=2 | 24 |
| 18 | `sip_empty_dialog` | 正 | §5.3：空 dialog 最小联结 | 7 |
| 19 | `sip_reinvite_refresh` | 正 | §5.1：re-INVITE 会话刷新 | 15 |
| 20 | `sip_cancel` | 正 | §5.1：CANCEL 取消 | 13 |
| 21 | `sip_busy_reject` | 正 | §5.1：486 拒绝非正常结束 | 10 |
| 22 | `sip_options_keepalive` | 正 | §5.1：会话内 OPTIONS 保活 | 14 |
| 23 | `sip_status_class_enum` | 正 | §5.1：5xx/6xx 大类 | 13 |
| 24 | `sip_callflow_complete` | 正 | §5.1：PRACK/RAck 组合流 | 15 |
| 25 | `sip_register_digest_auth` | 正 | §1 边界③：注册摘要鉴权序 | 11 |
| 26 | `sip_register_expire0` | 正 | §5.1：注册刷新注销 | 11 |
| 27 | `sip_two_calls_sequential` | 正 | §5.1：同流双呼独立 Call-ID | 15 |
| 28 | `sip_refer_transfer` | 正 | §4 场景⑩：REFER 盲转 | 16 |
| 29 | `sip_subscribe_notify_mwi` | 正 | §4 场景⑩：MWI 留言灯 | 13 |
| 30 | `sip_early_media_183` | 正 | §5.1：183 早媒体 + PRACK | 13 |
| 31 | `sip_hold_resume` | 正 | §3.6：HOLD 方向属性翻转 | 16 |
| 32 | `sip_info_dtmf` | 正 | §4 场景⑩：INFO DTMF | 14 |
| 33 | `sip_302_redirect` | 正 | §1 边界⑥：302 重定向 | 13 |
| 34 | `sip_update_session_timer` | 正 | §5.1：UPDATE 会话刷新 | 12 |
| 35 | `sip_invite_401_challenge` | 正 | §1 边界③：INVITE 401 质询 | 13 |
| 36 | `sip_message_im` | 正 | §4 场景⑩：MESSAGE IM | 9 |
| 37 | `sip_compact_form` | 正 | §3.3：紧凑形头方言 | 12 |
| 38 | `sip_via_chain` | 正 | §3.4：多跳 Via 链 | 12 |
| 39 | `sip_long_auth_uri` | 正 | §6：超长头 + 长 URI | 9 |
| 40 | `sip_tel_uri_utf8` | 正 | §3.2：tel: URI + UTF-8 | 12 |
| 41 | `sip_sdp_video_multistream` | 正 | §3.6：SDP 双流（只取 audio） | 12 |
| 42 | `sip_body_multipart` | 正 | §3.1：multipart 双体 | 12 |
| 43 | `sip_hdr_case_mix` | 正 | §3.3：头名大小写混写 | 12 |
| 44 | `sip_100_trying_retrans` | 正 | §1 边界①：100 + 同 CSeq 重传 | 13 |
| 45 | `sip_forked_invite` | 正 | §5.1：并行分叉竞速 | 13 |
| 46 | `sip_conference_join` | 正 | §4 场景⑪：会议加入 + 名册 | 12 |
| 47 | `sip_replaces_attended` | 正 | §4 场景⑩：Replaces 询转 | 16 |
| 48 | `sip_offerless_3pcc` | 正 | §3.6：offerless / 3PCC | 12 |
| 49 | `sip_publish_presence` | 正 | §4 场景⑩：PUBLISH 在线状态 | 11 |
| 50 | `sip_reason_q850` | 正 | §3.1：Reason Q.850 | 12 |
| 51 | `sip_ims_pheaders` | 正 | §3.1：IMS 私有头 | 12 |
| 52 | `sip_history_info_fwd` | 正 | §3.1：History-Info 呼转链 | 13 |
| 53 | `sip_491_glare` | 正 | §5.1：491 glare | 13 |
| 54 | `sip_interleaved_two_calls` | 正 | §5.1：同连接交错双呼 | 18 |
| 55 | `sip_status_enum_4xx` | 正 | §5.1：4xx 五码长尾 | 21 |
| 56 | `sip_status_enum_56xx` | 正 | §5.1：5xx/6xx 枚举 | 12 |
| 57 | `sip_v6_port_dyn` | 正 | §12.12：v6 × 动态端口 × flows=2 | 18 |
| 58 | `sip_sessions_two_dialogs` | 正 | §3.5：双会话独立面 | 18 |
| 59 | `sip_sessions_derived_callid` | 正 | §3.5：Call-ID 缺省派生 | 18 |
| 60 | `sip_sessions_explicit_wins` | 正 | §3.5：显式三级赢 | 9 |
| 61 | `sip_neg_sessions_dialog_mutex` | 负 | §7 N-3 | — |
| 62 | `sip_neg_sessions_empty` | 负 | §7 N-4 | — |
| 63 | `sip_neg_sessions_static` | 负 | §7 N-5 | — |
| 64 | `sip_sessions_port_inc` | 正 | §12.12：会话端口 inc | 18 |
| 65 | `sip_sessions_port_rand` | 正 | §12.12：会话端口 rand（seed=7） | 18 |
| 66 | `sip_sessions_port_list` | 正 | §12.12：会话端口 list | 18 |
| 67 | `sip_sessions_port_fixed` | 正 | §12.12：会话端口 fixed | 18 |
| 68 | `sip_sessions_port_pattern` | 正 | §12.12：会话端口 pattern | 18 |
| 69 | `sip_sessions_callid_pattern` | 正 | §12.12：call_id pattern | 18 |
| 70 | `sip_sessions_callid_fixed` | 正 | §12.12：call_id fixed | 18 |
| 71 | `sip_sessions_v6` | 正 | §2：v6 双会话对称 | 18 |
| 72 | `sip_medias_bidirectional` | 正 | §3.6：双向交替 + 线元组交换 | 16 |
| 73 | `sip_medias_interleave` | 正 | §3.6：interleave 等分调度 | 14 |
| 74 | `sip_neg_medias_mutex` | 负 | §7 N-6 | — |
| 75 | `sip_medias_port_dyn` | 正 | §12.12：medias 端口动态 | 22 |
| 76 | `sip_medias_filesource` | 正 | §3.6：medias FileSource | 10 |
| 77 | `sip_nat_rport_fill` | 正 | §3.9：裸 rport 回填 | 9 |
| 78 | `sip_nat_switch_forces` | 正 | §3.9：开关强制补参数 | 9 |
| 79 | `sip_nat_default_passthrough` | 正 | §3.9：缺省零漂移 | 9 |
| 80 | `sip_nat_sessions_port` | 正 | §3.9：会话真值端口回填 | 8 |
| 81 | `sip_tls_options` | 正 | §5.5：SIPS over TLS | 16 |
| 82 | `sip_tls_register` | 正 | §5.5：REGISTER over TLS | 16 |
| 83 | `sip_tcp_options` | 正 | §5.5：纯 tcp 事件面明文 | 9 |
| 84 | `sip_neg_tls_media` | 负 | §7 N-7 | — |
| 85 | `sip_neg_sips_no_tls` | 负 | §7 N-8 | — |
| 86 | `sip_neg_tls_sessions` | 负 | §7 N-9 | — |
| 87 | `sip_conf_burst_3party` | 正 | §4 场景⑪：三方会议风暴 | 42 |
| 88 | `sip_resp_202_refer` | 正 | §5.1：202 分支值 | 9 |
| 89 | `sip_resp_300_contacts` | 正 | §5.1：300 多 Contact | 10 |
| 90 | `sip_resp_407_proxy_auth` | 正 | §5.1：407 代理鉴权 | 10 |
| 91 | `sip_resp_420_bad_extension` | 正 | §5.1：420 扩展协商失败 | 10 |
| 92 | `sip_resp_422_session_timer` | 正 | §5.1：422 定时器协商失败 | 10 |
| 93 | `sip_resp_489_bad_event` | 正 | §5.1：489 同码异上下文 | 9 |
| 94 | `sip_resp_503_retry_after` | 正 | §5.1：503 + Retry-After | 10 |
| 95 | `sip_hdr_cl_user_wins` | 正 | §3.1：用户 CL 禁二次追加 | 9 |
| 96 | `sip_msg_empty_entry_skipped` | 正 | §5.3：空条目静默跳过 | 9 |

**#10 的包数说明**：见上文公式校验段——`sip_mss_segment` 是本版**唯一**"消息数"简写不成立的用例（3000B 体渲染后 3235B → 3 段），用 `min_packets=11` 覆盖。

### 9.2 断言面统计（机读实测）

| 项 | 数 | 说明 |
|---|---:|---|
| `fields` 断言总数 | **314** | 其中 `value` 形 **284** / `distinct_values` 形 **24** / **裸 field**（只给 `packet`+`field`，断"该字段存在"）**4** / `same_as_packet` 形 **1**（#83 `sip.Via` 回显请求帧）/ `distinct_exclude`+`distinct_values` 形 **1**（#87） |
| `frames` 断言总数 | **8** | 分布在 **5 例**（#1 四条 / #4 / #11 / #14 / #15 各一条） |
| 涉及字段种类 | **26** | `sip.*` **18** 种、`tcp.*` 4 种（`flags`/`dstport`/`srcport`/`len`）、`udp.*` 2 种（`srcport`/`dstport`）、`ipv6.dst`、`tls.record.content_type`（18+4+2+1+1 = 26） |
| 标量断言 | `negotiated` / `terminates` | **各 39 例** |
| `strategy_fc` | **12 例** | 全部 `{"type":"flows","value":2}` |
| `nic_capture` | **0 例** | 存量未启用 NIC 路径（G-SIP-6） |

**`fields` 断言形态口径（逐形说明，供 testcase 与反查门对齐）**：284 条 `value` 是**单值等值**断言；24 条 `distinct_values` 是**聚合面**（该字段在全流/全包集合里的去重取值集合等于给定列表，用于多流/多会话场景）；4 条**裸 field** 只断字段存在；1 条 `same_as_packet` 断"该字段值与另一帧相同"（#83 响应 Via 回显请求 Via，RFC 3261 §8.1.3.2）；1 条 `distinct_exclude` 断"去重集合不含某值"（#87 排除服务端 5060）。

**frames 断言清单（8 条，逐条实测）**：

| 用例 | 帧 | offset | hex | 含义 |
|---|---:|---:|---|---|
| #1 `sip_basic_dialog` | 4 | 54 | `49 4e 56 49 54 45 20 73 69 70 …` | `INVITE sip:… SIP/2.0` |
| #1 | 5 | 54 | `53 49 50 2f 32 2e 30 20 32 30 30 20 4f 4b 0d 0a` | `SIP/2.0 200 OK\r\n` |
| #1 | 6 | 54 | `41 43 4b 20 73 69 70 …` | `ACK sip:… SIP/2.0` |
| #1 | 7 | 54 | `42 59 45 20 73 69 70 …` | `BYE sip:… SIP/2.0` |
| #4 `sip_hdr_completion` | 4 | 54 | `49 4e 56 49 54 45 20 73 69 70 …` | 无头 INVITE 仍渲染合法请求行 |
| #11 `sip_rtp_media` | 9 | **42** | `80` | RTP 头首字节 V=2（UDP 载荷起点） |
| #14 `sip_rtp_filesource` | 6 | 54 | `70 61 79` | `"pay"` FileSource 实字节 |
| #15 `sip_v6` | 4 | **74** | `49 4e 56 49 54 45` | IPv6 载荷起点偏移 |

### 9.3 未覆盖面（A′ 立项，不得冒充已覆盖）

见 §13 与 §14。

## 10. P1 规范矩阵（CORE_MEMORY §4 八项：规范要求→业务场景→代码现状→缺口）

### 10.1 八项规范矩阵

| # | 八项 | 规范要求 | 业务场景 | 代码现状 | 缺口 |
|---|---|---|---|---|---|
| 1 | 连接模型 | 客户端主动建 TCP（RFC 3261 §18.1）；信令与媒体分离（§13.1 SDP 协商） | 场景①–⑪ | raw 链自建握手（`sip.go:214`）；事件面由 tcp 层持有（`layer_gen.go:28-37`）；RTP 独立 UDP 四元组（`sip.go:1140-1150`） | 无 |
| 2 | 命令/消息表 | 方法 14 种 + 响应码 1xx–6xx 大类（§7.1/§7.2/§21） | 场景①–⑪ | 方法/状态码由用户文本驱动，引擎不枚举不校验；CSeq 自动编号（`sip.go:613`） | 冷码长尾（405/406/410/…）无独立用例 → A′ 按需扩充 |
| 3 | 状态机 | 事务状态机（§17）+ 对话状态（§12） | #1/#19/#20/#53 | **引擎无事务状态机**（无 Timer/重传）；`dialogCtx` 实现对话状态（§5.3） | RFC 3261 §17 Timer 族 **明确不解决**（§1 边界①） |
| 4 | 字段表 | §20 头字段定义 + §7.3 语法 + §7.3.1 大小写不敏感 | 数据场景层 | `findHeader`（`sip.go:729`）+ `renderSIPMessage`（`:455`）+ 补全 5 头（`:667-694`） | compact 形 `i:` 不进补全长形识别 → G-SIP-1 |
| 5 | 错误处理 | 9 类负例 **7 条独立锚词**（§7） | 负例 N-1…N-9 | schema 三门 + planner Validate 2 分支 + 生成器 4 分支 | A′ 5 条（§7 未入例分支） |
| 6 | 超时与活性 | §11 会话中保活（OPTIONS/UPDATE）；§17.1.1.2 重传 | #22/#34/#44 | OPTIONS/UPDATE 由用户剧本表达（#22/#34）；重传 = 用户显式写第二条同 CSeq 请求（#44） | 引擎无自动保活/重传 → 明确不解决（§1 边界①） |
| 7 | NAT/代理/被动 | RFC 3581 rport/received；多跳 Via 链（§16.6） | 场景⑧、#38 | `rewriteViaRPort`（`sip.go:814`）；Via 链由用户头数组承载（#38） | 无 |
| 8 | 版本/方言 | SIP/2.0 唯一版本；SIPS（§26.2）；compact 形（§20）；tel: URI（RFC 3966） | #37/#40/#81/#82 | 版本串恒 `SIP/2.0`（`sip.go:462`/`:465`）；compact 透传（#37）；SIPS 双模式（§5.5） | 5061 不自动注入 → G-SIP-4 |

### 10.2 子表①：方法 × 终态矩阵（逐格已覆/立项/不适用）

| 方法 | T1 正常终态 | T2 配置拒绝 | T3 RST 异常终态 |
|---|---|---|---|
| INVITE | 已覆（#1/#8/#19/#87） | 已覆（#3/#63 代表例） | A′ 立项（G-SIP-5） |
| ACK | 已覆（#1/#8/#21） | 同上代表已覆 | A′ 立项（G-SIP-5） |
| BYE | 已覆（#1/#27） | 同上 | A′ 立项（G-SIP-5） |
| CANCEL | 已覆（#20/#87） | 同上 | A′ 立项（G-SIP-5） |
| REGISTER | 已覆（#6/#25/#26/#82） | 同上 | A′ 立项（G-SIP-5） |
| OPTIONS | 已覆（#7/#22/#83） | 同上 | A′ 立项（G-SIP-5） |
| PRACK | 已覆（#24/#30） | 同上 | A′ 立项（G-SIP-5） |
| REFER | 已覆（#28/#47/#88） | 同上 | A′ 立项（G-SIP-5） |
| NOTIFY | 已覆（#29/#46） | 同上 | A′ 立项（G-SIP-5） |
| SUBSCRIBE | 已覆（#29/#93） | 同上 | A′ 立项（G-SIP-5） |
| INFO | 已覆（#32） | 同上 | A′ 立项（G-SIP-5） |
| UPDATE | 已覆（#34/#31） | 同上 | A′ 立项（G-SIP-5） |
| MESSAGE | 已覆（#36） | 同上 | A′ 立项（G-SIP-5） |
| PUBLISH | 已覆（#49） | 同上 | A′ 立项（G-SIP-5） |

**逐格重数**：14 行 × 3 列 = **42 格**——已覆 **28**（T1 列 14 + T2 列 14）/ A′ 立项 **14**（T3 列 14）/ 不适用 **0**。28 + 14 + 0 = 42 ✓

### 10.3 子表②：数据形态变体表（协议相关全部形态逐项）

共 **30 行**：

| # | 变体 | 落点 |
|---:|---|---|
| 1 | 纯文本头（无体） | 覆（#1–#8 等多数） |
| 2 | SDP 单流体 | 覆（#9/#13/#48） |
| 3 | SDP 双流（audio+video） | 覆（#41，只取 `m=audio`） |
| 4 | 非 SDP 体（pidf/isup/multipart/sipfrag/dtmf-relay） | 覆（#42/#46/#49/#28/#32） |
| 5 | Content-Length 自动追加 | 覆（#9） |
| 6 | Content-Length 用户自带（禁二次追加） | 覆（#95） |
| 7 | 紧凑形头 `v=/f=/t=/i=/l=` | 覆（#37） |
| 8 | 头名大小写混写 | 覆（#43） |
| 9 | 多跳 Via 链 + Record-Route/Route | 覆（#38） |
| 10 | IMS 私有头（P-Asserted/P-Preferred/Privacy） | 覆（#51） |
| 11 | Reason: Q.850 | 覆（#50） |
| 12 | History-Info | 覆（#52） |
| 13 | RAck（PRACK 关联） | 覆（#24/#30） |
| 14 | tel: URI | 覆（#40） |
| 15 | UTF-8 display name（带引号） | 覆（#40） |
| 16 | 超长头（512B 级 Digest） | 覆（#39） |
| 17 | 超长 URI（226B 参数化） | 覆（#39） |
| 18 | IPv6 字面量方括号 | 覆（#57/#71，`sipHostOf`） |
| 19 | 空 dialog（无消息） | 覆（#18） |
| 20 | 空消息条目（无 method 无 status） | 覆（#96） |
| 21 | `Method` 与 `StatusCode` 双给 | **A′ 立项**（G-SIP-5，请求行优先语义未钉） |
| 22 | `Direction` 非法值（非 up/down 非空） | **A′ 立项**（G-SIP-5，静默跳过语义未钉） |
| 23 | 纯响应 dialog（无任何请求） | **A′ 立项**（G-SIP-5，原文渲染语义未钉） |
| 24 | 响应先于请求出现 | **A′ 立项**（G-SIP-5，同 23） |
| 25 | 用户显式 Via（不被重写） | 覆（#77/#80 部分面；显式 Via + nat 同例） |
| 26 | 多节点/多事务同连接（五事务） | 覆（#55） |
| 27 | RTP FileSource 二进制（含 NUL） | **A′ 立项**（单测覆盖 `sip_filesource_test.go:207`，**cases 未覆**） |
| 28 | RTP `frame_size` 非缺省 | **A′ 立项**（cases 全用缺省 160） |
| 29 | RTP `payload_type` 非 0 | **A′ 立项**（cases 全用 0/PCMU） |
| 30 | RTP `sample_rate` 非缺省 | **A′ 立项**（引擎仅注释性使用，`sip.go:1251-1256`） |

覆 **19** + A′ 立项 **11** = 30 ✓

### 10.4 子表③：商业行为→用例映射表

| # | 商业行为（出处） | 用例映射 | 结论 |
|---:|---|---|---|
| 1 | 基础呼叫建立与释放（RFC 3261 §13） | #1 | 已覆 |
| 2 | 注册与鉴权（§10/§22.1） | #6/#25/#26 | 已覆 |
| 3 | 能力探测（§11.1 OPTIONS） | #7 | 已覆 |
| 4 | 会话保活（§11/§12） | #22/#34 | 已覆 |
| 5 | 呼叫取消（§9 CANCEL） | #20 | 已覆 |
| 6 | 呼叫拒绝（486/603） | #21/#23 | 已覆 |
| 7 | 呼叫转移（RFC 3515/3891） | #28/#47 | 已覆 |
| 8 | 呼叫重定向（§8.1.3.4 302） | #33/#52 | 已覆 |
| 9 | 留言灯 MWI（RFC 3265/3842） | #29 | 已覆 |
| 10 | 在线状态（RFC 3903 PUBLISH） | #49 | 已覆 |
| 11 | 即时消息（RFC 3428） | #36 | 已覆 |
| 12 | IVR 按键（RFC 2976 INFO） | #32 | 已覆 |
| 13 | 早媒体/彩铃（RFC 3262） | #30 | 已覆 |
| 14 | 保持/恢复（RFC 3264 §6） | #31 | 已覆 |
| 15 | 多方会议（RFC 4575/4579） | #46/#87 | 已覆 |
| 16 | 并行分叉（RFC 3261 §16.7） | #45 | 已覆 |
| 17 | NAT 穿越（RFC 3581） | #77/#78/#79/#80 | 已覆 |
| 18 | 加密信令（RFC 3261 §26.2 SIPS） | #81/#82 | 已覆（结构路径） |
| 19 | Kamailio `force_rport()` 行为 | #78 | 已覆（开关代客户端补参数对） |
| 20 | Asterisk 多 dialog 并存 | #58/#59 | 已覆（sessions 多连接） |
| 21 | FreeSWITCH 会议焦点行为 | #46/#87 | 已覆（名册事件承载） |
| 22 | 真实摘要鉴权计算（MD5/SHA） | — | **明确不解决**（§1 边界③） |
| 23 | SRTP/RTCP 媒体加密与统计 | — | **明确不解决**（§1 边界④） |
| 24 | SIP over UDP 信令 | — | **明确不解决**（§1 边界②） |
| 25 | 事务重传与 Timer 族 | — | **明确不解决**（§1 边界①） |

已覆 **21** + 明确不解决 **4** = 25 ✓ 无映射无确认即缺口——本表零缺口。

### 10.5 三路对照与候选方案对比（§4.12–4.15 / §4.17）

三路：①**规范原文**（RFC 3261 及 19 个配套 RFC，定"必须是什么"——本轮用 §8.1.1/§8.1.3.2/§20 校正了补全头的生成规则与回显规则，§3.2/§3.3）；②**商业化软件实际行为**（Kamailio `force_rport()` / Asterisk `chan_sip` 多 dialog / FreeSWITCH 会议焦点——出处为各产品官方文档，映射见子表③行 19–21；**真实线字节未抓包核对** → G-SIP-8）；③**可靠开源实现思路**（kamailio `msg_parser.c` 的 rport 解析思路 / opensips tls 模块的事件化思路——只借鉴"rport 是 Via 参数、需按 `;` 切分"与"传输层事件化"两条思路，不搬运代码）。三路一致点：Via 参数语法、Call-ID 生成责任在 UAC、SIPS 必须 TLS；不一致点：**重传策略**（RFC 有 Timer 退避，引擎零实现，§1 边界①）。

| 方案 | 走法（借鉴来源） | 取舍 | 结论 |
|---|---|---|---|
| A | **双模式**：`[ip,sip]` raw 自驱 + `[ip,tcp,(tls),sip]` 事件面（本版） | 自驱保字节等价线（TCP 握手/挥手/分段与 RTP 子流一体产出）；事件面复用框架 tls 变换器。代价 = 两套入口需 `InitChain` 分派 + 两条 meta 清单 | **采用** |
| B | 全量事件面（单模式） | dialog 头补全状态机 + RTP 子流须全量重写为事件流；RTP 是裸 UDP 流**无法**进单连接事件流（§7 N-7 正是此结论） | **否决** |
| C | 全量 raw 自驱（单模式） | tls 链不可达（无法插 tls 变换器）；SIPS 无表达 | **否决** |

## 11. P2 D-SIP-1/D-SIP-2 代码设计（CORE_MEMORY §8 八要素；as-built 定稿）

> 状态说明：实现已落码（`internal/protocol/sip/` 三文件），本 P2 条目为文档轨对既有实现的**逆向定稿**（as-built 定稿），供门1 批准后作为后续改动的唯一入口。

### 11.1 文件清单（实测，非计划）

| 文件 | 职责 | 行数 |
|---|---|---:|
| `internal/protocol/sip/sip.go` | 线编码 + 头补全状态机 + TCP 自驱 + RTP 子流 + SDP 扫描 | **1534** |
| `internal/protocol/sip/layer_gen.go` | 双模式分派（`InitChain`/`GenEvents`/`Generate`）+ 终结层注册 | **102** |
| `internal/protocol/sip/event_gen.go` | 事件面：dialog → `MessageEvent` + 形状拒绝 + sips 预检 | **103** |
| **合计（本包三文件）** | | **1739** |
| 包内单测 **9 文件** | `grep -c '^func Test'` 实测 **115** 个 `Test*` | — |
| `internal/core/types.go`（`:2574-2708`） | `SIPConfig`/`SIPSession`/`SIPNAT`/`SIPMessage`/`SIPMedia` | —（共享文件） |
| `internal/core/strategy_convert.go`（`:1103` 扁平 + `:1656` 层内 + `:8970` presence + `:6364-6520` 解析族） | 配置搬运与判死 | — |
| `internal/core/schema/semantic.go`（`:297`/`:388`/`:588` + `:198` 嵌套扫描） | 三道语义门 | — |
| 接线 6 件 | registry 注册（`layers/registry.go:1857`，8 键）/ translate（`chain_planner_translate.go:1656`）/ `isRawIPChain` + 传输层守卫（`chain_planner_util.go:40-51`）/ 端口豁免（`chain_planner.go:748`）/ `protocols.go:54` / `layer_dyn.go:66`+`:259`+`:857` | — |
| 接线测试 5 件 | `layers/sip_migrate_test.go` / `layers/tls_sip_chain_test.go` / `schema/sip_static_port_test.go` / `schema/proto_flat_test.go`（sip 段）/ `core/convert_test.go`（sip 段） | — |

### 11.2 接口签名

- `Validate(spec core.FlowSpec) error`（`sip.go:88`）：IP 语法 ×2（层内不可达）、`spec.TCP.MSS < MinMSS`（层内不可达）、**sessions×dialog 互斥**、**media×medias 互斥**。`SIP == nil` 合法（空配置默认流）。
- `Plan(ctx, spec) (<-chan core.PacketConfig, error)`（`sip.go:121`）：返回缓冲 256 的 channel，goroutine 内 `runSession` 逐包发射。
- `runSession(flowID string, srcPort, dstPort uint16, dialog []core.SIPMessage, media *core.SIPMedia, medias []core.SIPMedia, interleave bool, defaultCallID string)`（`sip.go:165`）：一条信令连接的完整生命周期。
- 生成器：`Name() "sip"`；`InitChain([]layers.Layer)`（链感知）；`GenEvents()` 按 `eventMode` 返回自身或 nil；`Generate(ctx, req)` 按 `req.EmitMsg != nil` 分派；`EmitEvent` 未接线显式错（`event_gen.go:101-103`）。

### 11.3 数据结构

`SIPConfig{Dialog []SIPMessage, Media *SIPMedia, Sessions []SIPSession, NAT *SIPNAT, Medias []SIPMedia, Interleave bool}`（`types.go:2574-2601`）；`SIPSession{SrcPort, DstPort uint16, CallID string, Dialog []SIPMessage, Media *SIPMedia, Medias []SIPMedia, Interleave bool, SrcPortDyn/DstPortDyn/CallIDDyn *StrategyConfig(json:"-")}`（`:2610-2625`）；`SIPNAT{RPort bool}`（`:2630-2632`）；`SIPMessage{Method, URI string, StatusCode int, StatusText string, Headers []string, Body string, Direction string, EmitMedia bool}`（`:2638-2660`）；`SIPMedia{SrcPort, DstPort uint16, Frames int, PayloadType uint8, SampleRate uint32, FrameSize int, Direction string, FileSource *filesystem.FileSource, SrcPortDyn/DstPortDyn *StrategyConfig}`（`:2684-2708`）。

### 11.4 主流程（**双 meta 清单是硬约束**）

层链配置 → `ValidateLayers`（registry 8 键 allowlist）→ `checkSIPSessionsMutex`/`checkSIPMediasMutex`/`checkSIPEventPlane`（create 期）→ `checkLayerChainStaticCopy`（含 sip 层与 sessions[] 嵌套）→ translate（层内 config → `spec.SIP`）→ **两处独立 meta 清单必须同时含 SIP**：

| 路径 | meta 清单位置 | 漏配后果 |
|---|---|---|
| **raw 自驱** `[ip,sip]` | `chain_planner_chain.go:28`（`flowMetaFor`，含 `SIP: spec.SIP`） | `Generator.Generate` 走 `req.Meta.SIP == nil` → 报 `sip generator: invalid request` |
| **事件面** `[ip,tcp,(tls),sip]` | `chain_planner_translate.go:107`（drive 内联 meta，含 `SIP: spec.SIP`） | `generateEvents` 报 `sip generator: no config (spec.sip required)`，**或**（若两处都漏）静默空流 |

**这是同族记忆（sip 质询教训）钉死的一条**：raw 链与事件面链走**两个不同的代码路径**，各有独立的 meta 组装点，**改一处必查另一处**。D-SIP-2 WP-D 的 P5 校准记录里"drive meta 补 SIP 字段"正是漏配后修的第②处。

后续：`Planner.Validate` → `Generator.Generate`（raw：`legacy.Plan` → `Direction="up"` 强制 → `Emit`；事件面：`generateEvents` → `EmitMsg`）→ worker（raw 链的 L2 补偿 `chain_planner.go:1543-1550`；事件面链的 tcp 层握手/分段）→ writer（PCAP/NIC）。

### 11.5 错误分支

- **schema 期 400**：`checkSIPSessionsMutex`（`:297`，含空数组同锚词面）/ `checkSIPMediasMutex`（`:388`，含空数组）/ `checkSIPEventPlane`（`:588`，tls×media/medias、sips 无 tls、tcp|tls×sessions）/ `checkLayerChainStaticCopy`（`:198`，含 sip 层端口与 sessions[] 嵌套端口）/ `CheckProtoFlat`（`strategy_convert.go:8970`，顶层 sip presence）。
- **task 期**：`Planner.Validate` 2 分支（互斥 ×2）+ `event_gen.go` 4 分支（sessions/media/medias/sips）。
- **不可达分支**（层内）：IP parse ×2、MSS min、`invalid request`、`no config` —— §7 已逐条列出。
- 全部传 task error（零假成功）。

### 11.6 性能边界

见 §6（流式 channel 256 缓冲、per-flow 局部状态、无跨流共享、无锁；吞吐数字待基准）。

### 11.7 与现有逻辑的冲突点（不可回退点）

- **`isRawIPChain` 的传输层守卫**（`chain_planner_util.go:44-48`）：链含 `tcp`/`udp` → 返回 false。**若移除该守卫，`[ip,tcp,sip]` 链会被 raw 自驱拦截，产生双份 TCP 握手**（D-SIP-2 WP-D 修复的红线）。本版列为**不可回退**。
- **`Direction="up"` 强制**（`layer_gen.go:79`）：raw-IP Emit 路径会按 `pkt.Direction == "down"` 交换 L3 地址（`chain_planner.go:1544-1546`），而 legacy 已自行换向 → **必须强制 up 防双换**。
- **`genEvents` 的 `interleave` 不拒**：事件面无 media 时 `interleave` 惰性，不报错。**若未来给事件面加媒体支持，必须重新评估此豁免**。
- **动态 allowlist**（`internal/core/layer_dyn.go:66`）：`sip` 只开 `src_port`/`dst_port`；业务 2 键（`dialog`/`media`）**全关** → 对象即 `does not support dynamic`。但 `sessions[].src_port/dst_port/call_id` 与 `medias[].src_port/dst_port` 的动态**在 parse 层独立承接**（`ParseSIPSessions`/`ParseSIPMedias` 的 `*Dyn` 旁挂字段），**不走 allowlist**——这是"层顶键 allowlist + 嵌套槽位 parse 旁挂"的双轨设计，**改一处必查另一处**。见 §12.12。
- **`CheckProtoFlat` 只判 sip 自己的顶层子映射**：**游离顶层未知键**（如 `{layers:[…], bogus: 1}`）今日**不判死** → presence 负例若建了会真绿 = 假通过，**不建**（G-SIP-1，等框架级 unknown-key 白名单，与 opcua G-OPCUA-1 同款）。
- **M-1 缺陷**（`sip.go:338`，§3.8）：**未修**。修复属代码阶段。

### 11.8 回滚方式

本协议文件独立成包，回滚 = revert `internal/protocol/sip/` 三文件 + 接线 6 处（registry/translate/isRawIPChain/端口豁免/protocols/layer_dyn）；不触及其他协议。**注意**：`isRawIPChain` 与 `validateBaseDstPortHandled` 是共享函数，回滚须只摘 sip 项、保留他协议项。cases 回滚 = 恢复 96 例 JSON（产物文件，非文档）。

## 12. 门1 §1–§14 十四行对照表（CORE_MEMORY §15.1–15.3）

| § | 本协议怎么满足 | 证据 |
|---|---|---|
| §1 层链唯一真相 | 见 §12.1 强制展开：存量 96 例中 **94 例顶层 = `{layers}` 唯一键**；2 例例外逐条说明（1 例是负例的判死对象、1 例是 `group_id`）；目标形状见 §2 | §12.1；`cases/sip.json` 机读实测 |
| §2 策略/任务 | 策略 = 单 sip 流量模板（dialog 或 sessions）；任务 = 多策略合跑 + 总量封顶；框架语义未动 | 设计 §2 样例 |
| §3 五件套 | 见 §12.3 强制展开：会话表/事务序列/**关联关系（信令→媒体主从，三件事全齐）**/插入位置（终结层，双模式）/时间线（含 interleave 调度）。**有派生流，不豁免** | §12.3 + §5 + §3.6 |
| §4 查规范 | RFC 3261 + 19 个配套 RFC + 本机 tshark 3.6.14 字段 + 96 例断言面 + 落码反推；八项矩阵 + 子表①②③ | §10 |
| §5 依赖与错误 | `DependsOn ["ip"]` 单值 + `OptionalOn ["tls"]`（`registry.go:1857-1858`）；schema 5 门 + planner 2 分支 + 生成器 4 分支；9 负例 **7 条独立锚词** | §5/§7/§11.5 |
| §6 性能 | 见 §6（6.1–6.8 要素齐；吞吐数字标待基准，不写承诺；pcap/NIC 两路验收明写，NIC 未启用如实登记 G-SIP-6） | §6 |
| §7 三份文档 | `104-sip-{design,testcase}.md` v1.0.0（本版）+ D-SIP-1/D-SIP-2（§11 as-built 定稿）+ T-SIP（testcase §2，96 ID） | 修订记录 |
| §8 设计先行 | D-SIP-1（2026-09-19）→ D-SIP-2 四 WP（2026-09-20）→ 本 as-built 文档（2026-09-29） | 提交序 |
| §9 测试三源 | 三源 = RFC 族（§10）+ D-SIP-1/D-SIP-2（§11）+ tshark 3.6.14 字段与 96 例断言面；96 ID 逐项回指（testcase §2）；存量审计去向 testcase §8 | `104-sip-testcase.md` §2/§5/§8 |
| §10 评审闭环 | as-built 机读复核（**28 例精确包数 28/28 命中 + 85/87 公式满足**、形状分布、断言面统计）+ 自审 3 轮；红先绿后 | 自审日志 |
| §11 白话 | 首节白话一句先行 | 本文首节 |
| §12 动态清单 | 见 §12.12 强制展开：四元组 `ip.src/dst` + `sip.src_port/dst_port` 全开；**嵌套槽位独立轨**（`sessions[].{src_port,dst_port,call_id}` + `medias[].{src_port,dst_port}`）；业务 2 键全关；序号算法实读行号 | §12.12 |
| §13 schema 派生 | `sip` 已在 `registry.go:1857` 注册（**不新增层**）；`layers.generated.json` 127 层同代，sip 条目 **8 键与 registry 逐键一致**（机读实测）；**P4 若改 registry Fields 必须重跑 schemagen** | §11.1 |
| §14 真实流程 | suite 经 MCP 建策略建任务 → 引擎真实生成 → tshark `sip.*`/`tcp.*`/`udp.*` + frames 双通道 → 先跑后钉；pcap 落 `/tmp/mcp-pcaps/sip/`（历史位，今日未复跑 G-SIP-10） | testcase §7 |

### 12.1 §1 强制展开：旧键去向 + 完整 spec_json 样例

**存量实测（逐例机读，2026-09-29）**：

| 文件 | 例数 | 顶层键分布 | 链形 | 负例 expect 形状 |
|---|---|---|---|---|
| `cases/sip.json` | 96 | `{layers}` ×**94** / `{layers,sip}` ×1 / `{group_id,layers}` ×1 | `[ip,sip]` ×90 + `[ip,tcp,tls,sip]` ×4 + `[ip,tcp,sip]` ×2 | 7 例严格两键 + 2 例含 `notes` |

**两例例外逐条说明（不是残留）**：

| 用例 | 顶层键 | 性质 |
|---|---|---|
| `sip_flat_presence` | `{layers, sip}` | **负例的判死对象**——`"sip": {}` 正是 `CheckProtoFlat` 要拒绝的顶层子映射。这是 CORE_MEMORY `presence-negative-case-shape` 定义的**判死负例形状**（层链 + 顶层空子映射并存），**非残留**。 |
| `sip_port_dyn` | `{group_id, layers}` | `group_id` 是**跨流绑定的合法顶层键**（CORE_MEMORY §12.13 批量路径基线），非协议子映射。**非残留**。 |

**旧键去向表（§15.3 要求"每个键写去向"）**：

| 旧键 | 存量出现例数 | 去向 |
|---|---:|---|
| `src_ip` / `dst_ip` | **0** | 已住 `layers[0].ip.{src,dst}`（96/96 例均显式或动态写 ip 层） |
| `src_port` | **0** | 已住 `layers[i].sip.src_port`（90 例 raw 链显式或动态写；事件面链住 `layers[i].tcp.src_port`） |
| `dst_port` | **0** | 已住 `layers[i].sip.dst_port`（缺省 5060 由 translate 补） |
| `count` | **0** | 已退役；数量走 `strategy_fc {"type":"flows","value":N}`（12 例） |
| 顶层 `sip` 子映射 | **1**（`sip_flat_presence`） | **判死负例对象**，非在用键（`strategy_convert.go:8970` 拒绝） |
| `strategy_fc` | **12** | 合法顶层数量键（非协议子映射） |
| `group_id` | **1** | 合法顶层跨流绑定键 |

**结论**：①**无旧键可删**——本协议 96 例从未使用顶层地址/端口/`count` 键（D-SIP-1 就是层链化改造，起点即层链形）；②收官自查行「**非负例顶层键 = 0**」**今日即成立**（机读：96 例中唯一的非 layers 顶层键是 `sip_flat_presence` 的判死对象与 `sip_port_dyn` 的 `group_id`，两者均非"非负例顶层键"）；③A′ 新增例全部沿用纯 layers 形（§13）。

目标形状样例见 §2。

### 12-P2 判死负例形状（链级红例必含清单①③④）

- ① **presence 形状** `{"layers":[…],"sip":{}}` **今日已被拒**（`CheckProtoFlat` sip 分支存在，`strategy_convert.go:8968-8972` 实测）→ **存量已建该负例**（`sip_flat_presence`）✓
- ② **白名单外游离键判死**（`unknown field`）今日**无通用门** → 不建（建了会真绿 = 假通过）→ 缺口 G-SIP-1。
- ③ 9 负例每条带锚词 ✓（§7）
- ④ 收官自查「非负例顶层键 = 0」**今日已成立** ✓（§12.1）

### 12.3 §3 强制展开：五件套

**会话表**：

| 会话 | 形态 | 四元组 | 生命周期 | 用例 |
|---|---|---|---|---|
| `s1` | 单信令连接（dialog 形） | `ip.src/dst` + `sip.src_port/dst_port` | 3 握手 → N 消息 → 4 挥手 | #1–#57（`[ip,sip]`）及 #83/#81/#82（事件面） |
| `s2` | 多独立连接（sessions[] 形，每条一项） | **逐会话独立** `src_port`/`dst_port` + 独立 `FlowID` | **逐会话完整** 3 握手 → 该会话消息 → 4 挥手 | #58–#71/#80/#86/#87 |
| `s3` | 媒体子流（media / medias[]，**派生自 s1/s2**） | **独立 UDP 四元组**（端口由 SDP/显式/动态推导） | **无握手挥手**（裸 UDP 流），随 EmitMedia 消息点起止 | #11–#14/#72/#73/#75/#76/#87 |

**事务序列**（每事务四件事：前置/触发/成功/失败，CORE_MEMORY §3.4–3.7）：

| 事务 | 前置条件 | 触发动作 | 成功分支 | 失败分支 |
|---|---|---|---|---|
| `t1` TCP 建连 | 无 | 会话起始 | → `t2` | 无（合成器无连接失败语义） |
| `t2` INVITE 对话建立 | `t1` 完成 | 发 INVITE（可带 SDP offer） | 收 2xx → `t3`（ACK） | 收 3xx/4xx/5xx/6xx → ACK → 会话终止（#21/#33/#55/#56） |
| `t3` ACK 确认 | `t2` 收 2xx | 发 ACK（CSeq 复用 INVITE 号） | → 媒体流 `s3` 起 / → `t4` | 不适用 |
| `t4` 会话内重协商 | `t3` 完成 | re-INVITE / UPDATE / INFO / PRACK | 收 2xx → 继续 | 收 491 glare → ACK（#53） |
| `t5` BYE 释放 | `t3`/`t4` | 发 BYE（CSeq 递增） | 收 2xx → `t6` | 不适用 |
| `t6` TCP 挥手 | `t5` 完成 | 会话末尾 | 4 帧 FIN/ACK | 不适用 |
| `t7` 注册事务（独立） | `t1` 完成 | REGISTER | 200 → 完；401 → 带 Authorization 重发（#25） | 401 无重发 = 会话终止 |
| `t8` 订阅事务（独立） | `t1` 完成 | SUBSCRIBE | 200 → NOTIFY（#29/#93） | 489 Bad Event（#93） |
| `t9` 转移事务（独立） | `t3` 完成 | REFER | 202 → NOTIFY sipfrag（#28/#47/#88） | 不适用 |

**关联关系（信令 → 媒体，CORE_MEMORY §3.8–3.10 三件事）**：

| 三件事 | 本协议实现 | 代码 |
|---|---|---|
| ① **归属哪个会话** | 子流 `FlowID = parentFlowID + ":rtp"`（单 media）或 `+ ":rtp-<direction>"`（medias[i]）——**父 FlowID 即归属会话** | `sip.go:251`/`:258` |
| ② **归属哪个事务** | 触发点 = **带 `emit_media:true` 的那条消息**（通常是 ACK = 会话建立时刻）；帧插在该消息**之后** | `sip.go:349` |
| ③ **由哪个字段决定** | **端口**由三路决定（显式 `src_port`/`dst_port` > 动态对象 > **SDP `m=audio`** > 5004）；**方向**由 `direction` 显式 > **SDP `a=`** > up | `sip.go:1084-1134` |

**这是 sip 与 opcua 的本质差别**：opcua 无派生流（单 TCP 连接承载全部消息）；sip 的媒体流是**真正的独立四元组 + 独立流 ID + 独立序号空间**（RTP seq/ts/ssrc 自成体系，与 TCP 信令的 seq 无关）。

**插入位置**：**终结层**（`[ip,sip]` raw 自驱，无中间层）/ **事件面终结层**（`[ip,tcp,(tls),sip]`，传输层由 tcp 持有）。**RTP 子流不经过层链**——它是终结层生成器内部产出的独立 UDP 流（`emitFrame` 直接构造 `PacketConfig`，`sip.go:1232-1247`）。

**时间线**：

| 维度 | 语义 | 用例 |
|---|---|---|
| 消息内 | 严格顺序（请求行 → 头 → 空行 → 体），MSS 分段保序 | #1/#10 |
| 事务间 | `dialog[]` 数组序；CSeq 由计数器按 §3.2 规则推进 | #19/#55 |
| 会话间 | **顺序整块**——`sessions[]` 逐项跑完（3 握 → 消息 → 4 挥），**不交错**；第 2 会话包号起点 = 第 1 会话总包数 + 1 | #58 |
| 媒体 vs 信令 | **无 interleave**：全部帧在 EmitMedia 消息后一次性 round-robin（up/down 交替）；**`interleave:true`**：按 T/G 等分插在后续消息之间（确定性可复现） | #72/#73 |
| 多流（flows=N） | 逐流独立整块（worker 按流序号复制模板）；**并发路径 `concurrent` 为例外不启用** | #17/#57 |

**包时间戳**：引擎无时钟，全部包 `Timestamp = now`（`runSession` 起始取一次，`sip.go:149`）——**断言面是帧序而非绝对时间**（CORE_MEMORY §3.12 口径如实）。

### 12.12 §12 强制展开：动态字段清单与序号算法

**四元组层顶键**（allowlist `internal/core/layer_dyn.go:66` 实测：`"sip": {"src_port": true, "dst_port": true}`）：

| 字段 | 开/关 | 理由 | 用例 |
|---|---|---|---|
| `ip.src` / `ip.dst` | **开** | 逐流地址池（allowlist `"ip": {"src","dst","ttl"}`） | #17（inc）、#57 |
| `sip.src_port` / `sip.dst_port` | **开** | 信令联结端口逐流池（E1 决策，h323/mpls/ngap/telnet 同款延续） | #17（inc）、#57（inc 双 group_id） |

**嵌套槽位（独立轨，不经 allowlist）**——由 `ParseSIPSessions`/`ParseSIPMedias` 的 `*Dyn` 旁挂字段承接（`strategy_convert.go:6430-6434`/`:6483-6485`）：

| 字段 | 开/关 | 理由 | 用例 |
|---|---|---|---|
| `sessions[].src_port` | **开** | 逐流逐会话端口池（多会话多流主用例面） | #64 inc / #65 rand(seed=7) / #66 list / #67 fixed / #68 pattern |
| `sessions[].dst_port` | **开** | 同上 | （与 src 同轨，cases 未单独覆盖 → A′ G-SIP-9） |
| `sessions[].call_id` | **开**（pattern/fixed） | 标识派生覆盖口（B2 决策：缺省派生 + 显式赢） | #69 pattern / #70 fixed |
| `medias[].src_port` / `dst_port` | **开** | RTP 端口逐流池 | #75 inc |
| `media.src_port` / `dst_port`（单数形） | **开** | 同轨（`parseSIPMedia` 后由 `parseStrategyConfigDyn` 补 `*Dyn`） | #12（显式标量）；动态形 **cases 未覆** → A′ G-SIP-9 |

**业务字段**：

| 字段 | 开/关 | 理由 |
|---|---|---|
| `sip.dialog` | **关** | 会话结构（消息序列），列表无动态形状；allowlist 无该键 → 对象即 `does not support dynamic` |
| `sip.media` / `sip.medias` | **关**（层顶键） | 同上（对象即拒）；其**内部端口槽位**另走上表的嵌套轨 |
| `sip.sessions` | **关**（层顶键） | 结构选择器；内部槽位同上 |
| `sip.nat.rport` | **关** | 布尔开关，逐流变无意义 |
| `sip.interleave` | **关** | 布尔开关 |
| `media.direction` / `payload_type` / `frames` / `frame_size` / `sample_rate` / `file_source` | **关** | 结构/媒体参数，无逐流语义 |
| `SIPMessage.method/uri/status_code/status_text/headers/body/direction/emit_media` | **关** | 消息内容=回放模板（CORE_MEMORY §3.13：不许用同模板连续重复冒充编排；逐流变体需求列 A′ 候选） |

**序号算法实读（逐处行号）**：

| 环节 | 位置 | 语义 |
|---|---|---|
| allowlist 白名单 | `internal/core/layer_dyn.go:66` | `sip` 只放行 `src_port`/`dst_port` |
| 层内动态对象提取 | `layer_dyn.go:259-265` | `case "sip"`：`src_port` → `out.SIP.SrcPort`，否则 `DstPort` |
| 逐流解析落 spec | `layer_dyn.go:857-866` | `ResolvePortValue(ld.SIP.SrcPort, i)` → `spec.SrcPort`；**非 0 才覆盖**（0 值 no-op，保持"non-zero wins"） |
| 会话端口派生 | `sip.go:398-412` | 显式 > `ResolvePortValue(Sess.SrcPortDyn, FlowIndex)` > `12345 + FlowIndex×M + sessIdx` |
| 会话 Call-ID 派生 | `sip.go:416-424` | 显式 > `ResolveStringValue(Sess.CallIDDyn, FlowIndex)` > `"{FlowIndex}-{sessIdx}@{srcIP}"` |
| 媒体端口解析 | `sip.go:1086-1103` | 显式 > `ResolvePortValue(media.SrcPortDyn/DstPortDyn, FlowIndex)` > SDP > 5004 |
| 通用策略引擎 | `tuple_generator.go` / `strategy_convert.go:49`（保底 `12345+i`） | 五种策略实现（fixed/inc/rand/list/pattern）；`rand` 用 `seed + 流序号` 确定性 |

**五策略整格矩阵**（CORE_MEMORY §12.15 要求五类全测）：inc 回绕（#64/#17）✓ / rand 同 seed 可复现（#65，seed=7 → 23187/23189）✓ / list 轮转（#66）✓ / pattern 替换（#68/#69）✓ / 静态复制被拒（#3/#63）✓。**十格逐格不抽样**：`sessions[].src_port`×5（#64–#68）+ `sessions[].call_id`×2（#69/#70）+ `medias[].src_port`×1（#75）+ `sip.src_port`×1（#17）+ v6 矩阵格（#57）。

## 13. P3 对接清单（T-SIP 草稿输入；正文落 testcase 文件）

96 ID（87 正 + 9 负）+ 包数公式 + 锚词 + fixture 常量 + 双通道断言基线 + 存量审计（testcase §2–§5/§8 全量）。

**A′ 候选（本版新立项，逐条可执行）**：

| # | 候选 ID | 内容 | 归属缺口 |
|---:|---|---|---|
| 1 | `sip_neg_method_status_both` | `Method` 与 `Status_Code` 双给 → 请求行优先语义钉 | G-SIP-5 |
| 2 | `sip_neg_bad_direction` | `direction:"sideways"` → 静默跳过（不产该条包） | G-SIP-5 |
| 3 | `sip_response_only_dialog` | 纯响应 dialog（无请求）→ 逐字原文渲染（不补头） | G-SIP-5 |
| 4 | `sip_response_before_request` | 响应先于请求 → 原文渲染 | G-SIP-5 |
| 5 | `sip_neg_bad_src_ip` | 非法源 IP（层内**不可达**——schema 先拦，建了会真绿，**需先证可达**） | G-SIP-5 |
| 6 | `sip_rtp_payload_type_8` | RTP PT=8（PCMA）非缺省 | G-SIP-7 |
| 7 | `sip_rtp_frame_size_custom` | `frame_size` 非缺省（如 320）→ 帧长与 ts 增量 | G-SIP-7 |
| 8 | `sip_rtp_filesource_binary` | FileSource 含 NUL 的二进制字节（单测已覆，cases 未覆） | G-SIP-7 |
| 9 | `sip_media_port_dyn` | 单数 `media.src_port` 动态对象（cases 只覆显式标量） | G-SIP-9 |
| 10 | `sip_sessions_dst_port_dyn` | `sessions[].dst_port` 动态（cases 未覆） | G-SIP-9 |
| 11 | `sip_m1_mac_assert` | 下行信令帧 L2 目的 MAC 断言（M-1 修复后必加） | M-1/G-SIP-6 |
| 12 | `sip_nic_capture` | 任一例启用 `nic_capture` 走 NIC 路径 | G-SIP-6 |
| 13 | `sip_abort_rst` | RST 非正常结束（§3.15②后半） | G-SIP-5 |
| 14 | `sip_cold_status_code` | 冷码长尾（405/406/410/412 等）按需扩充 | §10.1 缺口 |

## 14. 缺口立项清单（有缺口写「缺口立项」，不许空着）

| 缺口 | 内容 | 去向 |
|---|---|---|
| **G-SIP-1** | ①`CheckProtoFlat` **只判 sip 自己的顶层子映射**，**游离顶层未知键**（`{layers:[…], bogus:1}`）今日**无通用门** → 建了 presence 负例会真绿 = 假通过，**不建**；②`CheckProtoFlat` 的 sip 分支是**单协议黑名单**形态（每协议一段），非框架级 unknown-key 白名单 | 等框架级 unknown-key 白名单（**禁加单协议分支**，kingbase 记忆裁定）；与 opcua G-OPCUA-1 / moxa G-MOXA-2 同款 |
| **G-SIP-2** | 2 例负例（`sip_flat_presence`/`sip_flat_static_port`）`expect` 含 `notes` 键，与**严格两键**（`{expect_error, error_contains}`）口径不符；另 7 例已是严格两键 | A′ 收窄：删 2 处 `notes`（P4 动作，**文档不碰 cases**） |
| **G-SIP-3** | **SDP future-bleed 已知限制**：`scanSDPMediaPorts`/`scanSDPDirection` **扫全 dialog**（不限于当前 EmitMedia 索引之前）——re-INVITE 之后的端口/方向会**前渗**到先前的 emit（`sip.go:1077-1081` / `:1469-1472` 代码自认） | **明确不解决**（修复需把 dialog 索引传入 emit 路径 = 大重构）；用例侧规避（#13 避开 re-INVITE 后端口变化）；用户可用显式 `media.src_port/dst_port/direction` 覆盖 |
| **G-SIP-4** | **SIPS 5061 不自动注入**（D-SIP-2 决策 5）：tls 链的 SIPS 端口由用户显式写 `tcp.dst_port=5061`（tls 层 FieldContract 是单值合同 `tcp.dst_port=443`，不适用双载口协议）；另 **真实证书链校验不实现**（tls 层缺省全数据） | **明确不解决**（双载口协议契约冲突，需 FieldContract 变体支持）；用例 #81/#82 显式写 5061 |
| **G-SIP-5** | **未入用例的合法/非法边界 6 类**：①`Method`+`StatusCode` 双给（请求行优先，不报错）；②`Direction` 非法值（静默跳过）；③纯响应 dialog（原文渲染）；④响应先于请求（原文渲染）；⑤RST 非正常结束；⑥冷码长尾（405/406/410/412/…） | A′ 补例（§13 候选 1–5/13/14）；**①–④ 是"静默语义"而非"拒绝语义"，用例须断"不产包/原文渲染"而非断错误** |
| **G-SIP-6** | ①**NIC 路径零覆盖**：96 例 `nic_capture` 计数 = **0**（机读实测），双输出契约中 NIC 一路**今日无用例**；②**无 L2 断言**：96 例 `expect` 无任何 `eth.*` 字段 → **M-1 缺陷（§3.8）不被任何断言捕获** | A′ 补例（§13 候选 11/12）：M-1 修复后加下行帧 L2 目的 MAC 断言 + 至少一例启用 `nic_capture` |
| **G-SIP-7** | **RTP 字段面零覆盖**：①tshark 3.6.14 的 `rtp.*` 字段在本机实测**不可用**（前身 T-SIP-1…57 记"rtp.* 字段 tshark 3.6 无效改 frames pin"），今日沿用 frames pin offset 42；②RTP 参数面 `payload_type`（恒 0）、`frame_size`（恒 160）、`sample_rate`（引擎仅注释性使用）、FileSource 二进制**均无用例** | ①**待确认**：确认方式 = 用 `tshark -G fields \| grep '^rtp\.'` 复核当前版本字段表，若可用则收编（口径同 opcua G-OPCUA-3）；②A′ 补例（§13 候选 6–8） |
| **G-SIP-8** | **第三源（真实 UA/服务器线字节）未取到**：Kamailio/Asterisk/FreeSWITCH 的行为映射（§10.4 行 19–21）出自**官方文档**而非抓包；RFC 3261 §17 事务状态机、§16.7 分叉的引擎等价性未经真实互操作验证 | **待确认**：抓 Kamailio 5.6 现网包对照，或跑 sipp/Asterisk 互操作；确认前**按实现钉、不声称互操作合规** |
| **G-SIP-9** | **动态整格有 2 空格**：`sessions[].dst_port` 动态（cases 只覆 src_port 五策略）与单数 `media.src_port` 动态（cases 只覆 `medias[].src_port`）**今日零用例** | A′ 补例（§13 候选 9/10）；**不得冒充已覆盖**（CORE_MEMORY §12.15 整格口径） |
| **G-SIP-10** | **结果产物 pcap 无留档**：`trafficgen/docs/protocol-pcap-test/sip.md`（**tracked**）写 "Cases: 96 — pass 96, fail 0, error 0"，末次提交 `bbf4f7c`（2026-09-20，**晚于**判死提交 `0417be5` 2026-09-13，故**不属**"早于判死提交"的过期情形）；但其链接的 `trafficgen/docs/protocol-pcap-test/sip/` 目录**不存在**（0 个 pcap，`.gitignore:88 *.pcap` 使 pcap 从不入库）——故 **96/96 数字无 pcap 留档佐证，本车道今日未复跑该套件** | **代码阶段**（P5 重跑套件后重生成该产物）；本版**不删不改**（tracked 产物，删除属 P5 动作，此处仅登记事实）；在此之前读者不得据此判断套件已复跑（口径与 pcep G-PCEP-11 / opcua G-OPCUA-10 一致） |
| **M-1** | **`sip.go:338` 下行信令包 L2 目的 MAC 取值错**（第二参数 `spec.DstMAC` 应为 `spec.SrcMAC`）——影响全部 raw 链下行响应帧；**存量 96 例零 L2 断言故未被捕获** | **代码阶段修复**（§3.8 已给修复点与影响面）；修复后帧数与现存断言不变；同步加 L2 断言例（§13 候选 11） |

## 15. 修订记录

- v1.0.0（2026-09-29）：批次二文档轨 #104 sip as-built 定稿。**沿革 8 项**（§0，含 registry 4→8 键、`isRawIPChain` 传输层守卫、**双 meta 清单**硬约束、锚词字面差 `a tls` vs `a tcp/tls`）；**96 例机读全量审计**（形状分布 / 包数公式 **28 例精确 28/28 + 85/87 公式满足** / 断言面 314 fields + 8 frames / 两种断言语义 28 精确 + 59 下界 + 3 例已登记例外）；**新发现 M-1 confirmed finding**（`sip.go:338` L2 目的 MAC）；§12.1/12.3/12.12 强制展开 + 12-P2；P1 矩阵（八项 8 行 + 方法×终态 42 格 + 数据形态 30 行 + 商业映射 25 行）；P2 as-built 定稿（§11）；**缺口 G-SIP-1…G-SIP-10 + M-1**。自审 3 轮，末轮干净。
