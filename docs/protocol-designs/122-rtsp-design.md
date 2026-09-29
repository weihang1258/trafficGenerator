# #122 rtsp（RTSP 实时流传输协议 · RFC 2326/7826，文本信令 TCP 554 + RTP 媒体子流 UDP）设计契约

> 版本：v1.0.0（批次二文档车道，as-built 型）
> 日期：2026-09-29
> 车道：批次二文档轨（协议编号 #122）
> 旧基线：**无独立 rtsp 设计文档**——`docs/protocol-designs/` 下无 `NN-rtsp-*` 稿（`ls | grep rtsp` 实测零命中）。唯一文档基线是 ① 结果产物 `trafficgen/docs/protocol-pcap-test/rtsp.md`（tracked，12 行 pass 表）；② `CASE_PCAP_MAPPING.md:261-273` 的 `RTSP.1.1`–`RTSP.1.9` 映射表；③ 代码注释反复引用的 `/tmp/l7_planner_design/testcases_rtsp.md`（**该目录在 HEAD 不存在**，`ls` 实测 "No such file or directory"，死引用——`rtsp_test.go:3` 与 `rtsp_rtp_test.go` 同引）。本 #122 为 **as-built 逆向定稿**（§0 逐条校正）。
> 存量用例：`trafficgen/test/protocol_pcap/cases/rtsp.json`（**12 例 = 11 正 + 1 负**，已机读实测；顶层键已是纯层链形，零残留——见 §12.1）
> 规范基线：① **RFC 2326**（Real Time Streaming Protocol，1998；方法族 §10.1、状态码 §10.2、头字段 §12、状态机附录 A，下称 **spec**）；② **RFC 7826**（RTSP 2.0，2016；`PLAY_NOTIFY` §13.4 等补充，仅取被实现引用的部分）；③ **RFC 3550**（RTP，§5.1 RTP 固定头 12B / 随机初值 / seq 递增 / ts 递增，§5.3 端口约定）；④ **RFC 4566**（SDP，body 逐字节透传）；⑤ **RFC 879**（MSS 下限 536）；⑥ 本机 tshark 3.6.14 `rtsp.*` 字段表 + 12 例实测 pcap（唯一权威）；⑦ 本仓库落码（`internal/protocol/rtsp/` 四文件 + 接线，§11）。
> 白话一句：**点播服务器那一套"遥控器对话"——客户端发 OPTIONS/DESCRIBE/SETUP/PLAY/PAUSE/TEARDOWN 的文本请求，服务器回 "RTSP/1.0 200 OK"；CSeq 是每句话的编号，Session 是服务器在第一个 SETUP 应答里发的会话号，后面的每句话都要带；SETUP 时双方谈好用哪两个 UDP 口传视频，PLAY 应答里再报一句"流从第几号包开始"，紧接着那串 RTP 包就顺着谈好的口流出来。引擎里它是一层自驱终结层——TCP 握手、分段、挥手都由它自己产，不走 tcp 层。**

## 0. 基线校正与实测声明（门1 必答：基线继承关系）

本 #122 **没有前序设计稿可继承**，故本节做的是"对现存三种非设计型基线的逐条校正"，全部为可判题（文档/代码/实测三级对照），直接判定，不问偏好。

| # | 旧基线说法 | HEAD 实测（2026-09-29） | 校正结论 |
|---|---|---|---|
| 1 | `docs/protocol-designs/` 有 rtsp 设计稿 | `ls docs/protocol-designs/ \| grep -i rtsp` **零命中**（同目录下 sip 亦零命中） | **不存在**；本 #122 为 rtsp 的**首份设计契约**，"承旧稿"一说不成立 |
| 2 | `rtsp_test.go:3` / `rtsp_rtp_test.go` 头注引 `/tmp/l7_planner_design/testcases_rtsp.md` 为用例来源 | `ls /tmp/l7_planner_design/` → **No such file or directory** | **死引用**（与 opcua 车道 `audit/` 目录死引用同款）；本契约不复制该引用，改用 RFC 2326 章节号作依据链 |
| 3 | `CASE_PCAP_MAPPING.md:261` 标 "RTSP(`run_rtsp.py`, 端口 554, TCP+UDP RTP)"，列出 `RTSP.1.1`–`RTSP.1.9` 九场景 | 该九场景是**外部脚本产出的参考 pcap 清单**（`rtsp_1_1.pcap` 等），非本仓用例；本仓 `cases/rtsp.json` 是 12 例（T-1…T-12），与九场景**不是同一集合** | 映射表是**参考素材来源**，不是用例契约；本契约 §9 以 cases JSON 12 例为权威 |
| 4 | 结果产物 `trafficgen/docs/protocol-pcap-test/rtsp.md` 写 "Cases: 12 — pass 12, fail 0, error 0" | 末次提交 `ddfb40b`（**2026-09-20**），**晚于**判死提交 `0417be5`（2026-09-13）；本车道**今日已实跑**该 12 例（离线链套件，见下） | **本协议不构成 pcep G-PCEP-11 式过期产物**（时间序不倒挂），但 **`docs/protocol-pcap-test/rtsp/` 目录 0 个 pcap**（`git ls-files` 实测 0 行、`ls` 不存在）——表内 11 条 `[pcap](rtsp/…)` 链接**全部悬空**（G-RTSP-6） |
| 5 | 结果产物表内 `rtsp_emit_media_rtp` 记 **16** 包、`rtsp_composite_full_session_media` 记 **18** 包 | 本车道实跑（离线链套件，§0 末）与代码推演**一致：16 / 18** | **两例包数可信**，但 **cases JSON 内无 `packet_count` 断言**（G-RTSP-5）——数字只在结果产物里，不在机器契约里 |
| 6 | 结果产物表内 `rtsp_pause_teardown` 记 **13** 包；该例 JSON `notes` 写 "3 握手+6 消息+4 挥手=**15**" | 实跑 **13** 包（3 + 6 + 4 = 13） | **`notes` 算术错**（写成 15，正确 13）；`packet_count` 字段值 13 是对的——**同一对象内自相矛盾**（G-RTSP-5） |
| 7 | 结果产物表内 `rtsp_neg_dialog_required` 记 `pass`、Packets `0`、Pcap 列**空链接** | 实跑：ValidateSpec 直接拒（锚词命中），**0 包、无 pcap**——负例正确行为 | 记 `pass` **正确**（负例无 pcap 是预期），但"pass"字面易被读成"产了 0 包的假成功"；本契约 §7 按"Validate 拒绝、零包、传 task error"钉死 |
| 8 | 本协议层注册形（旧基线未提） | `registry.go:1931-1936`：`Name:"rtsp"`、`Category: CategoryTerminal`、`DependsOn ["ip"]`（**无 tcp！**）、Fields **2 键**（`dialog` list / `media` object） | 与 sip 的 `Fields 含 src_port/dst_port` **不同**：rtsp 层**无端口键**（G-RTSP-3） |
| 9 | `rtsp.go:11-23` 包注释称 "TCP 3-way handshake … TCP 4-way teardown" | `rtsp.go:203-209`（3 包 SYN/SYN-ACK/ACK）+ `:265-275`（4 包 FIN-ACK/ACK/FIN-ACK/ACK）逐帧实测 | **属实**；本协议**自建** TCP 握手挥手（不经 tcp 层），与 ldap/rtmp/pptp/vnc/xmpp/sctp/jt808/jt809/jtt905 同族（`chain_planner_util.go:54` raw-IP 名单） |
| 10 | `types.go:2714` 注释称媒体 "ports are negotiated via the Transport header" | `rtsp.go:458-466`（请求侧 `client_port=<DstPort>-<DstPort+1>`）+ `:526-539`（响应侧补 `server_port=<SrcPort>-<SrcPort+1>`）实测 | **属实**；端口来自 `RTSPMedia.SrcPort/DstPort`，缺省 5004（`rtsp.go:78` `DefaultRTPPort`） |
| 11 | `types.go:2719-2721` 注释称 "CSeq … a response echoes the CSeq of the request it answers" | `rtsp.go:430-440`（请求侧取号/重同步）+ `:502-509`（响应侧回显 `dc.lastReqCSeq`）实测 | **属实**；另有用户值重同步分支（`parseCSeqNumber`，`:852-867`） |
| 12 | `CASE_PCAP_MAPPING.md:265` 称 "RTP 全 down 方向" | `rtsp.go:759-762` `dir` 缺省 `"down"`；但 raw 链路径下**外层 `Direction` 被生成器统一改写为 `"up"`**（`layer_gen.go:53`，防 raw-IP drive 二次换向） | **"down" 只体现在 L3 地址翻转**（src=server IP），**不体现在 `PacketConfig.Direction`**——用 `Direction` 断 RTP 方向的用例今日必假绿（§3.5 诚实边界、G-RTSP-4） |

**依赖链判定纪律**：以上均为可判题，直接判定。不可判的（真实 QuickTime/ffmpeg 服务器的线字节）标"待确认"并写清确认方式（G-RTSP-8）。

**产物过期登记（G-RTSP-6）**：`trafficgen/docs/protocol-pcap-test/rtsp.md` 是 **tracked 产物**（`git ls-files` 可证），末次提交 `ddfb40b`（**2026-09-20**），**晚于**判死提交 `0417be5`（2026-09-13），**故不落入 pcep G-PCEP-11 的"过期产物"口径**。但其 `docs/protocol-pcap-test/rtsp/` 子目录**根本不存在**（0 个 pcap 文件），表内 11 条 `[pcap](rtsp/…)` 链接**全部悬空**——这是**产物不完整**，不是产物过期，两者口径分开登记。

**本车道今日实跑证据（唯一一次，方法可复现）**：在 `trafficgen/test/protocol_pcap/layer_chain_suite_test.go` 的协议空导入块**临时**加入 `_ "…/internal/protocol/rtsp"`（该文件基线**不含 rtsp**，见 G-RTSP-2），执行
`CHAIN_PROTO=rtsp go test ./test/protocol_pcap/ -run TestLayerChainSuite -count=1` →
**12/12 PASS**（8.25s），逐例耗时 0.01–1.40s。**该临时改动已回滚**（`git status --short` 实测零改动），本车道**未提交任何 `.go`/cases 改动**。逐例包数与帧位见 §9；逐例报文原文见 §3。

## 1. 范围、profile 与实现状态边界

本版定义 **RTSP 1.0 文本信令（TCP 554）+ 可选 RTP 媒体子流（UDP，端口经 SETUP Transport 协商）** 的流量生成：连接建立（自建 TCP 三次握手）→ 信令对话（配置声明的消息序列，每消息一个 PSH-ACK 段）→ 可选媒体子流（`emit_media` 触发的 RTP 帧序列）→ 连接释放（自建 TCP 四次挥手）。

| profile | 承载 | 本版允许内容 | 不从 profile 推导 |
|---|---|---|---|
| `rtsp_tcp_v1`（主） | `[ip, rtsp]` raw 自驱链；RTSP 自建 TCP 握手/分段/挥手；fixture 554 | 全部消息族（12 方法 + 状态码）、头自动补全、SDP body、分段、IPv4/IPv6 | 真实服务器语义（资源是否存在、权限、认证） |
| `rtsp_rtp_v1` | 同上 + `media` 配置 + 消息 `emit_media:true` | RTP 固定头 12B + 载荷；UDP 子流；RTP-Info 与帧参数一致 | 真实编解码、抖动、丢包、RTCP 反馈（**未实现**） |
| `rtsp_ipv6_v1` | 同上，仅外层 IPv6（offset 74） | 同主 profile（URI 主机方括号化） | 从 IPv4 fixture 推导 IPv6 地址 |

显式边界（"不实现、不声称、不许静默转换"）：① **不实现 RTSP 状态机执法**——方法序完全由配置声明，生成器不拒绝非法状态转移（§5 诚实声明）；② 不实现认证（`Authorization` / `WWW-Authenticate` 由用户当普通头写，生成器不做 401→重试握手）；③ 不实现 `interleaved` 传输（RTP over TCP，RFC 2326 §10.12）——媒体恒走 UDP 子流；④ 不实现 RTCP（RFC 3550 §6）——只有 RTP 单向帧；⑤ 不实现真实 RTP 载荷编码——载荷是 `FrameSize` 字节零填充或 `file_source` 提供的字节切片（§3.5）；⑥ 不实现 RTP 时间戳与墙钟的对应（`ts += FrameSize`，`SampleRate` 字段**被解析但不被消费**，G-RTSP-1）；⑦ 不实现多连接/`sessions[]`——raw 链一次一条 TCP 连接（多流由策略级 `flow_control` 承载，见 §12.12）；⑧ **不声称**方法序、状态码、Session 号与真实服务器一致（Session 号是随机 15 位 hex，§3.3）。

**实现状态（2026-09-29 实测）**：`rtsp` 层已注册（`registry.go:1931`，`CategoryTerminal`，`DependsOn ["ip"]`，Fields 2 键）；planner/builder 合体于 `internal/protocol/rtsp/rtsp.go`（974 行）+ raw 链生成器 `layer_gen.go`（68 行）；`allowedProtocols["rtsp"]=true`（`protocols.go:53`）；`cmd/server/main.go:142` 空导入触发 init 注册、`:573` `RegisterPlanner(layers.NewChainPlanner("rtsp"))`；层内 translate 已接线（`chain_planner_translate.go:2791`）；缺省目的端口 554（`chain_planner.go:1035`，链路径）；12 语义用例已落 `cases/rtsp.json`。单元测试 64 个 `Test*`（`grep -c` 实测：`rtsp_test.go` 44 + `rtsp_rtp_test.go` 20），`go test ./internal/protocol/rtsp/` **ok**。

**输出契约（pcap/NIC 双输出）**：两路径共用同一 cases JSON 与断言集（`tcp.dstport`、`tcp.flags`、offset 54/74 frames）；NIC 经 tcpdump 捕获（`nic_capture` 用例级开关）；不设仅单路径可用的断言。**今日 12 例只用了 `packet_count`/`has_handshake`/`terminates`/`tcp.dstport`/`tcp.flags` 五个通道，`rtsp.*` 专用字段零使用**（G-RTSP-7，A′ 立项）。

## 2. 协议栈、端口和固定偏移

推荐层链为 **`[ip, rtsp]`**——**链上不放 tcp/udp**。rtsp 是 raw-IP 自驱终结层：它自产完整 L3/L4（`rtsp.go:169-200` 的 `emit` 闭包写 `core.L3Base(...)` + `L4Config{Protocol:"tcp"}`），并在内部自建 TCP 握手与挥手。**放 tcp 层会静默产 0 包**（§0 实测 `[ip,tcp,rtsp]` → `Plan` 返回 0 包、无错误，G-RTSP-2）。

端口：RTSP 控制通道 **TCP 554**（IANA）。链路径缺省住 `chain_planner.go:1035` `case "rtsp": spec.DstPort = 554`（D-RTSP-1 注释：legacy `mapToFlowSpec` `setDefaultDstPort(&spec, cfg, 554)` 的链路径等价承接，`strategy_convert.go:1124-1126`）。RTP 媒体端口缺省 **5004**（`rtsp.go:78` `DefaultRTPPort`；RFC 3550 §5.3 音频默认口），成对使用 `N` / `N+1`（RTCP 位，本版不发 RTCP）。

**源端口**：rtsp 层**无 `src_port` 键**（registry Fields 只有 dialog/media），链路径的源端口规则是 `chain_planner.go:996` raw 链同列——**0 保持 0**，由 worker 按 `DefaultSrcPort + i = 12345 + i` 注入（`worker.go:308`）。单流（`flows=1`）时 `spec.SrcPort` 不被注入，故实测报文里客户端源端口显示为 **0**（§3 逐例原文可证）——这是**链路径保底语义**，不是缺陷。

固定偏移：无 VLAN/IP options/TCP options 时，**每帧 RTSP 消息起点为 IPv4 offset 54**（14+20+20）、**IPv6 offset 74**（14+40+20）。RTP 帧同为 IPv4 54 / IPv6 74（UDP 头 8B 在 IP 头之后）。

目标形状 spec_json 样例（严格层链形，顶层仅 `layers`；**本协议存量 12 例已是此形**）：

```json
{
  "layers": [
    {"ip": {"src": "10.0.0.1", "dst": "20.0.0.1"}},
    {"rtsp": {
      "dialog": [
        {"method": "OPTIONS"},
        {"status_code": 200, "status_text": "OK"},
        {"method": "DESCRIBE"},
        {"status_code": 200, "status_text": "OK", "body": "v=0\r\n"},
        {"method": "SETUP"},
        {"status_code": 200, "status_text": "OK"},
        {"method": "PLAY"},
        {"status_code": 200, "status_text": "OK"},
        {"method": "TEARDOWN"},
        {"status_code": 200, "status_text": "OK"}
      ]
    }}
  ]
}
```

媒体子流样例（`emit_media` 挂在 PLAY **请求**上——本仓存量两例即此形；挂在 PLAY **响应**上才能自动补 `RTP-Info`，见 §3.3）：

```json
{
  "layers": [
    {"ip": {"src": "10.0.0.1", "dst": "20.0.0.1"}},
    {"rtsp": {
      "dialog": [
        {"method": "SETUP"},
        {"status_code": 200, "status_text": "OK"},
        {"method": "PLAY", "emit_media": true},
        {"status_code": 200, "status_text": "OK"}
      ],
      "media": {"direction": "down", "frames": 2, "payload_type": 96, "frame_size": 160}
    }}
  ]
}
```

## 3. 线格式编码（RFC 2326 §10/§12，逐字段按代码钉）

### 3.1 消息骨架（`renderRTSPMessage`，`rtsp.go:296-352`）

```
request-line 或 status-line CRLF
header₁ CRLF
header₂ CRLF
...
CRLF                       ← 头体分隔空行（恒发，§3.1 注）
body（若有，逐字节透传）
```

**总长度公式**：`len(msg) = len(line) + 2 + Σ(len(hᵢ)+2) + 2 + len(body)`；其中 `len(line)` = 请求行 `len(Method)+1+len(URI)+len(" RTSP/1.0")`（`rtsp.go:300-303`）或状态行 `len("RTSP/1.0 ")+len(strconv.Itoa(code))+1+len(reason)`（`:312-316`）。**CRLF 恒为 `\r\n`**（`rtsp.go:303/316/327`；`TestRTSPPlan_CRLF_Only` 断言全串无裸 `\n`）。

**请求行**（`Method != ""`，`rtsp.go:298-303`）：`<Method> SP <URI> SP RTSP/1.0 CRLF`。**URI 缺省**在补全阶段填（§3.3），空 URI 到不了这里。
**状态行**（`Method == "" && StatusCode != 0`，`rtsp.go:304-316`）：`RTSP/1.0 SP <code> SP <reason> CRLF`；`reason` 取 `StatusText`，为空则查 `rtspReasonPhrase`（§3.2）。
**两者皆空**（`rtsp.go:317-320`）：`return nil` —— 该消息**被静默跳过**，不产包（§7 静默路径）。

### 3.2 状态码与 reason phrase（`rtspReasonPhrase`，`rtsp.go:568-662`；RFC 2326 §10.2）

实现映射 **45 个码**（含 RFC 7826 补充）。逐值实测（`TestRTSPPlan_StatusCode_AllSupported` 断言 22 个，全表如下）：

| 段 | 码 → reason |
|---|---|
| 2xx | 200 OK / 201 Created / 250 Low on Storage Space |
| 3xx | 300 Multiple Choices / 301 Moved Permanently / 302 Moved Temporarily / 303 See Other / 304 Not Modified / 305 Use Proxy |
| 4xx | 400 Bad Request / 401 Unauthorized / 402 Payment Required / 403 Forbidden / **404 Not Found** / 405 Method Not Allowed / 406 Not Acceptable / 407 Proxy Authentication Required / 408 Request Timeout / 410 Gone / 411 Length Required / 412 Precondition Failed / 413 Request Entity Too Large / 414 Request-URI Too Long / 415 Unsupported Media Type / 451 Parameter Not Understood / 452 Conference Not Found / 453 Not Enough Bandwidth / **454 Session Not Found** / **455 Method Not Valid in This State** / 456 Header Field Not Valid for Resource / 457 Invalid Range / 458 Parameter Is Read-Only / 459 Aggregate Operation Not Allowed / 460 Only Aggregate Operation Allowed / 461 Unsupported Transport / 462 Destination Unreachable / 463 Key Management Failure |
| 5xx | 500 Internal Server Error / 501 Not Implemented / 502 Bad Gateway / 503 Service Unavailable / 504 Gateway Timeout / 505 RTSP Version Not Supported / 551 Option not supported / 552 Session Parameter Not Supported |

**表外码**：`rtspReasonPhrase` 无 `default` 分支 → 返回 `""` → 状态行渲染成 `RTSP/1.0 999 \r\n`（**空 reason，双空格**；`TestRTSP_StatusCodeText_EmptyRendersCodeOnly` 覆盖）。用户 `status_text` **恒胜**（`rtsp.go:308-311`）。
**注**：`454`/`455` 是 **spec §10.2 定义、本实现可渲染但永不自动产出**的码——它们是**用户声明的值**，不是生成器对状态机的裁决（§5 诚实声明、G-RTSP-9）。

### 3.3 头自动补全（`completeRTSPHeaders`，`rtsp.go:384-564`；RFC 2326 §12）

**优先级恒为 用户 > 自动 > 无**。自动头以**块**形式**前置**（`rtsp.go:468`/`:563` `append(auto, msg.Headers...)`），故输出序 = 自动头（按生成序）→ 用户头（保原序）。生成序：请求侧 `CSeq → Session → Transport`；响应侧 `CSeq → Session → Transport → Content-Type → RTP-Info`。

#### 3.3.1 CSeq（§12.17）

| 侧 | 条件 | 行为 | 代码 |
|---|---|---|---|
| 请求 | 用户已给 | 原样保留；**重同步计数器** `dc.cseq = n`（仅当值为纯数字，`parseCSeqNumber`） | `:430-434` |
| 请求 | 用户未给 | `dc.cseq++` → 自动 `CSeq: <n>` | `:435-440` |
| 响应 | 用户未给且有前序请求 | 回显 `dc.lastReqCSeq`（**逐字，含用户原文**） | `:502-505` |
| 响应 | 用户未给且**无**前序请求（对话以响应开篇） | `dc.cseq++` → 自动取号 | `:506-508` |

`parseCSeqNumber`（`:852-867`）对非纯数字（如 `abc`）返回 -1 → **不回同步**，计数器停在原值（`TestRTSPPlan_CSeq_NonNumericUserValue`：下一请求取 1）。**逐例实测**（`rtsp_play_session_full`）：OPTIONS/200 得 `CSeq: 1`/`1`，DESCRIBE/200 得 `2`/`2`，SETUP/200 得 `3`/`3`，PLAY/200 得 `4`/`4`，TEARDOWN/200 得 `5`/`5` —— **请求取号、响应回显、双向同号**。

#### 3.3.2 Session（§12.37）

签发点：**第一个 SETUP 的响应**（`dc.lastMethod == "SETUP" && dc.session == ""`）→ `dc.session = generateSessionID()` 并写头（`:518-523`）。
`generateSessionID`（`:872-879`）：**15 位小写 hex**（参考 pcap QuickTime 形 `8d9dea6f8d9deaa8f`），**随机**（`rand.Intn(16)` 逐位），**不可复现**（无 seed 入口）——故用例只能断言**格式**（`^[0-9a-f]{15}$`）或**跨包相等**，不能断言字面值。
签发后：**每个后续请求**自动补 `Session: <id>`（`:443-447`）；**每个后续响应**同样补（`:516-517`）；**用户显式给的 Session 在响应里被采信为会话号**（`:512-515`，`TestRTSPPlan_Session_UserSuppliedInResponse`）。
**逐例实测**（`rtsp_play_session_full`）：pkt 9（SETUP 响应）首次出现 `Session: 53de09956fb2808`；pkt 10/11/12/13（PLAY 请求/响应、TEARDOWN 请求/响应）**逐字回显同值**。

#### 3.3.3 Transport（§12.39）

仅 `dc.lastMethod == "SETUP"` 且 `media != nil` 时自动生成；用户已给则不生成。

| 侧 | 生成值 | 代码 |
|---|---|---|
| 请求 | `Transport: RTP/AVP;unicast;client_port=<DstPort>-<DstPort+1>` | `:458-466` |
| 响应 | `Transport: RTP/AVP;unicast;client_port=<DstPort>-<DstPort+1>;server_port=<SrcPort>-<SrcPort+1>` | `:526-539` |

`SrcPort`/`DstPort` 为 0 时各取 `DefaultRTPPort`（5004）。**逐例实测**（`rtsp_emit_media_rtp`，media 未写端口）：请求 pkt 8 `Transport: RTP/AVP;unicast;client_port=5004-5005`；响应 pkt 9 `Transport: RTP/AVP;unicast;client_port=5004-5005;server_port=5004-5005` —— **两侧 client_port 同值，响应追加 server_port**，与 RTP 帧实际使用的端口一致（§3.5）。

#### 3.3.4 Content-Length / Content-Type（§12.14 / §12.16）

- `Content-Length`：`Body != ""` 且用户未给（**名字大小写不敏感**匹配，`rtsp.go:331-336`）→ 追加 `Content-Length: <len(Body)>`（`:339-342`）。**`len(Body)` 是 Go 字符串字节长**（`TestRTSPPlan_Body_UTF8ContentLength` 覆盖多字节）。
- `Content-Type`：**仅响应侧**，`Body != ""` 且用户未给 → `Content-Type: application/sdp`（`:543-547`）。**请求侧不补**（`TestRTSPPlan_ContentType_UserOverride`）。

**逐例实测**（`rtsp_describe_sdp_body`，body = `"v=0\r\no=- 0 0 IN IP4 20.0.0.1\r\n"` 共 30 字节）→ 响应 pkt 5 渲染为
`RTSP/1.0 200 OK\r\nCSeq: 1\r\nContent-Type: application/sdp\r\nContent-Length: 30\r\n\r\n` + body 逐字节。

#### 3.3.5 RTP-Info（§12.33）

触发条件**三者同时**：`dc.lastMethod == "PLAY"` && `media != nil` && `!dc.mediaEmitted`，且用户未给（`:550-561`）。
值：`RTP-Info: url=<trackID>;seq=<params.seq>;ssrc=<int32(params.ssrc)>;rtptime=<params.ts>`。
- `url` 取 `dc.trackID`——SETUP 请求 URI 里 `trackID=…` 段（`extractTrackID`，`:893-907`，正则 `(?i)trackID=([^/?#]+)`），无该段则取 URI 最后一段；**SETUP URI 为空则 `dc.trackID == ""` → 整个 RTP-Info 不生成**（`:552` 守卫）。
- `ssrc` 以 **有符号 int32** 打印（`:556-558` 注释：QuickTime 参考 pcap 形 `ssrc=-1919345977` 对应 `0x8D991AC7`）。
- `seq`/`ssrc`/`rtptime` 与**随后实际发出的 RTP 帧**取自**同一个 `params` 指针**（`rtsp.go:227-231` 预生成 → `:260` 传给 `emitRTSPMedia`）→ 头里报的 `seq` 就是下一帧的 `seq`（`TestRTSPPlan_RTPInfo_MatchesEmittedFrames`）。
- `dc.mediaEmitted` 由 `emitRTSPMedia` 调用点置真（`:261`），并在**每个请求**开头清零（`:421`）——故 **`emit_media` 挂在 PLAY 请求上时，紧随的 PLAY 响应拿不到自动 RTP-Info**（`TestRTSPPlan_RTPInfo_EmitMediaOnRequest_ResponseGetsNone`）。**本仓存量两例（`rtsp_emit_media_rtp`/`rtsp_composite_full_session_media`）正是此形** → **今日无一例产出过 RTP-Info 头**（G-RTSP-4）。

### 3.4 方向推断（`inferDirection`，`rtsp.go:668-680`）

| 输入 | 输出 |
|---|---|
| `Method` 非空且 ∈ {`REDIRECT`, `PLAY_NOTIFY`} | `"down"`（服务器发起，RFC 2326 §10.6 / RFC 7826 §13.4） |
| `Method` 非空（其余） | `"up"` |
| `Method` 空且 `StatusCode != 0` | `"down"` |
| 两者皆空 | `""` → 消息被跳过（`rtsp.go:242-244`） |
| 用户显式 `Direction` 非空 | **覆盖**上述推断（`rtsp.go:238-241`）；取值 ∉ {`up`,`down`} → **静默跳过** |

`Method` 与 `StatusCode` **同时非空**时 `renderRTSPMessage` 走请求分支（`Method` 胜，`rtsp.go:298` 先判），但 `inferDirection` 也先判 `Method` → 二者一致（`TestRTSPPlan_MethodAndStatusCode_MethodWins`）。

### 3.5 RTP 媒体子流（`emitRTSPMedia`，`rtsp.go:716-833`；RFC 3550 §5.1）

**每帧 = 一个 UDP 数据报**，载荷 = **12 字节 RTP 固定头** + `FrameSize` 字节媒体。

| 头偏移 | 字段 | 值 | 代码 |
|---:|---|---|---|
| 0 | V/P/X/CC | `0x80`（V=2，P=X=0，CC=0） | `:800` |
| 1 | M/PT | `pt & 0x7F`（M 恒 0） | `:801` |
| 2–3 | Sequence Number | `params.seq` **大端** | `:802-803` |
| 4–7 | Timestamp | `params.ts` **大端** | `:804-807` |
| 8–11 | SSRC | `params.ssrc` **大端** | `:808-811` |
| 12… | Payload | `FrameSize` 字节（零填充，或 `file_source` 切片） | `:791-798` |

**参数**：`ssrc`/`seq`/`ts` 在对话开始前一次性随机（`rtsp.go:227-231`，RFC 3550 §5.1 随机初值）。逐帧推进：`params.seq++`、`params.ts += uint32(frameSize)`（`:830-831`）。**`SampleRate` 字段被解析（`strategy_convert.go:6576`）但从不被消费** → G-RTSP-1。

**端口**：`SrcPort`（server 侧发口）/ `DstPort`（client 侧收口），0 → 5004（`:746-753`）。**与 SETUP Transport 头同源**（§3.3.3）→ DPI 可据此把 RTP 流关联回信令。
**方向**：`media.Direction` 缺省 `"down"`（`:759-762`）；大小写不敏感（`strings.EqualFold`，`:769`）。`down` = `srcIP=spec.DstIP, srcPort=SrcPort`；`up` = 反向。**逐例实测**（`rtsp_emit_media_rtp`）：RTP 帧 pkt 11 = `20.0.0.1:5004 -> 10.0.0.1:5004`（server→client）✓。
**载荷**：`file_source` 设定时经 `PayloadCache.GetOrLoad` 取字节，按 `FrameSize` 切片，**帧数被切片数覆盖**（`:738-744`）；`file_source` 设定但 context 无 `PayloadCache` → **整段不产**（`:734-737` 提前 return，防"文件源静默退化成零填充"）。
**帧数**：`media.Frames <= 0` → 1（`:727-730`）。
**FlowID**：`<parentFlowID>:rtp`（`:779`）——**独立 FlowID**，但共享 parent 的 `GroupID` 以路由到同一 PacketWorker（`rtsp.go:17-19` 注释），保证线序 = emit 序。

**诚实边界（方向断言陷阱，G-RTSP-4）**：raw 链路径下 `layer_gen.go:53` 把**每一包**的 `PacketConfig.Direction` 改写为 `"up"`（防 raw-IP drive 的 `chain_planner.go:1546` 二次 L3 换向）。实测 dump 里 **RTP 帧的 `Direction` 也是 `"up"`**——用 `Direction=="down"` 断 RTP 方向的用例**必假绿**。RTP 方向**只能**经 `ip.src`/`udp.srcport` 观测。

### 3.6 TCP 承载（自建，非 tcp 层）

| 阶段 | 帧 | flags | 代码 |
|---|---|---|---|
| 握手 | SYN（client→server，带 MSS/WScale/SACK-Permit 选项） | `0x02` | `:203`、`:934-943` |
| | SYN-ACK（server→client，同选项） | `0x12` | `:206` |
| | ACK | `0x10` | `:209` |
| 数据 | 每消息 `ceil(len/MSS)` 个 PSH-ACK | `0x18` | `:211-219` |
| 挥手 | FIN-ACK（client） / ACK（server） / FIN-ACK（server） / ACK（client） | `0x11`/`0x10`/`0x11`/`0x10` | `:265-275` |

`segmentByMSS`（`:912-929`）：MSS 缺省 1460（`DefaultMSS`，`:70`）；空载荷 → **单个空 chunk**（裸 PSH-ACK）；每段推进发送方 seq（`:216`）。MSS 下限 536（`MinMSS`，`:74`；RFC 879），由 `Validate` 拒（`:103-107`）。
**逐例实测**（`rtsp_play_session_full`）：pkt 4 长 51B（OPTIONS 请求）、pkt 7 长 83B（DESCRIBE 响应含 SDP），**全部单段**——今日 12 例无跨 MSS 分段（最大单消息 126B，见 §8）。

## 4. 业务场景分析（现网典型场景与五层覆盖）

**定性**：**声明式剧本回放**——配置声明一段 dialog（方法/状态码/头/体/方向/媒体触发），引擎按序渲染成文本消息、自建 TCP 承载、按需插入 RTP 子流，tcp 语义（握手/分段/挥手）由本层自产。

| 现网场景 | 事务交互 | 对应用例 |
|---|---|---|
| ① 能力探测（客户端问服务器支持什么方法） | OPTIONS → 200 | #1（`rtsp_options_smoke`）、#12（`rtsp_status_text_default`） |
| ② 完整点播（VLC/QuickTime 形） | OPTIONS→DESCRIBE→SETUP→PLAY→TEARDOWN 各一对 | #2（`rtsp_play_session_full`） |
| ③ 媒体描述（取 SDP） | DESCRIBE → 200 + `application/sdp` body | #3（`rtsp_describe_sdp_body`） |
| ④ 资源不存在 | DESCRIBE → 404 | #4（`rtsp_response_404`） |
| ⑤ 暂停/恢复/结束 | PLAY → PAUSE → TEARDOWN 各一对 | #5（`rtsp_pause_teardown`） |
| ⑥ URI 显式 vs 缺省构造 | 请求行 URI 取值 | #6（`rtsp_uri_explicit_and_default`） |
| ⑦ 客户端自定义头（User-Agent 等） | 用户头与自动 CSeq 共存 | #7（`rtsp_headers_custom`） |
| ⑧ 媒体流实际流出 | PLAY 后 RTP 帧序列 | #8（`rtsp_emit_media_rtp`） |
| ⑨ 服务器主动消息（重定向/通知） | `direction:"down"` 覆盖推断 | #9（`rtsp_direction_explicit`） |
| ⑩ 复合真实会话（五方法+媒体+自定义头+SDP） | 十消息全序 + RTP | #10（`rtsp_composite_full_session_media`） |
| ⑪ 配置错误（空 dialog） | Validate 拒绝 | #11（`rtsp_neg_dialog_required`，负） |
| ⑫ 状态码 reason 缺省 | 200 无 status_text | #12（`rtsp_status_text_default`） |

**五层覆盖逐层结论**：
- **功能层**——12 方法族中 10 个在单测覆盖（`TestRTSPPlan_Methods_AllSupported`：DESCRIBE/SETUP/PLAY/TEARDOWN/OPTIONS/PAUSE/GET_PARAMETER/SET_PARAMETER/ANNOUNCE/RECORD），**用例层只落 6 个方法**（OPTIONS/DESCRIBE/SETUP/PLAY/PAUSE/TEARDOWN）→ 其余 6 方法 **A′ 立项**（G-RTSP-10）；45 个状态码只落 200/404 两值 → A′；头自动补全 5 类中 **4 类有用例**（CSeq/Session/Transport/Content-Length 间接），**RTP-Info 零例**（G-RTSP-4）；负例**仅 1 条**（空 dialog）→ §7 列出 4 条未入例拒绝分支 + 4 条静默路径（G-RTSP-9）。
- **性能层**——今日 12 例**最大单消息 126 字节**（`rtsp_emit_media_rtp` pkt 9 SETUP 响应），**远低于 MSS 1460 → 零跨 MSS 分段用例**（单测 `TestRTSPPlan_LongBody_SegmentedContiguousSeq` 覆盖分段，用例层无）→ A′（G-RTSP-10）；最小帧 = 握手 40B（IPv4，无载荷）；RTP 帧载荷上界 = `FrameSize`，无 IP 分片守卫（`TestRTSPPlan_RTP_LargeFrameSize_NoUDPFragmentation` 单测覆盖）。
- **数据场景层**——文本编码（请求行/状态行/头/体）；状态码 45 值只覆 2；reason 缺省覆 2（200/404）；body 覆 2 形（`v=0\r\n` 5B、30B 多行 SDP）；URI 覆 2 形（缺省构造 + 显式）；CSeq 覆自动取号 + 回显，**用户重同步零例**；Session 覆自动签发 + 回显，**用户供给零例**；Transport 覆自动双侧，**用户覆盖零例**；RTP 覆默认参数（PT=0、FrameSize=160、端口 5004）。
- **地址与流层**——IPv4 12/12，**IPv6 零例**（单测 `TestRTSPPlan_IPv6_Session` 覆盖，用例层无）→ A′；单流基线 12/12；**流关联（控制流派生媒体流）已覆 2 例**（#8/#10：UDP 子流 + Transport 端口同源）✓ 这是本协议**必须覆盖**的层；多会话/多流**零例**（raw 链单连接，多流走 `flow_control`）。
- **业务层**——11 个现网场景中 10 个有落点（②③④⑤⑥⑦⑧⑨⑩⑫）；⑪为负例。**多会话**（并发多连接，状态互不串）**零例**（raw 链无 `sessions[]`，G-RTSP-11）；**多事务**（同连接内多笔，关联标识 CSeq/Session）**已覆**（#2 五事务、#5 三事务、#10 五事务）✓。

**次要合法行为显式不适用声明（不设正例、亦不得进负例）**：① RTCP（RFC 3550 §6，未实现）；② `interleaved` RTP-over-TCP（RFC 2326 §10.12，未实现）；③ 认证挑战（401→`Authorization` 重试，生成器不做——`Authorization` 只能当用户头写）；④ 真实 RTP 编解码（载荷恒零填充或文件切片）；⑤ 状态机执法（§5 诚实声明）。

## 5. 事务模型与状态机

**事务定义**：一次请求 + 一次响应（一对）。**多事务** = 一个 TCP 连接内多对按序执行，关联标识 = **CSeq**（逐事务递增，响应回显）+ **Session**（第一个 SETUP 响应签发，之后逐消息回显）。今日最长的多事务序列 = #2/#10（各 5 对）。

### 5.1 RFC 2326 附录 A 参考状态机（规范面）

| 状态 | 合法方法 | 转移到 |
|---|---|---|
| **Init** | SETUP / TEARDOWN | SETUP → Ready；TEARDOWN → Init |
| **Ready** | PLAY / RECORD / TEARDOWN / SETUP | PLAY → Playing；RECORD → Recording；TEARDOWN → Init |
| **Playing** | PAUSE / TEARDOWN / PLAY | PAUSE → Ready；TEARDOWN → Init |
| **Recording** | PAUSE / TEARDOWN / RECORD | PAUSE → Ready；TEARDOWN → Init |

**非法转移（RFC 2326 §10.2 用 455 `Method Not Valid in This State` 拒绝）逐条**：① Init 态收 PLAY/PAUSE/RECORD；② Ready 态收 PAUSE（未 PLAY 先 PAUSE）；③ Playing 态收 SETUP/RECORD；④ Recording 态收 SETUP/PLAY；⑤ 任意非 Init 态收 SETUP 建第二条 track（本版无多 track 语义）；⑥ TEARDOWN 后（回 Init）再收 PLAY/PAUSE。

### 5.2 as-built 诚实声明：生成器**不执法**状态机

`Planner` **没有任何状态字段**——`Plan`（`rtsp.go:118-279`）只做"按配置顺序渲染 + 派生头"。因此：

- **非法转移可被原样生成**（如 dialog 直接写 `PLAY → PAUSE → SETUP`），生成器**不拒、不报错、不产 455**；
- 455 是**用户显式写的 `status_code`**（`rtsp.go:626-627` 只是 reason 表条目），**永不自动产出**；
- 生成器**唯一**的状态化行为 = `dialogCtx`（`rtsp.go:369-376`）的 6 个字段：`cseq` 计数器 / `lastReqCSeq` 回显源 / `lastMethod`（驱动 Transport 与 RTP-Info 挂点）/ `session`（SETUP 响应签发）/ `trackID`（SETUP URI 解析）/ `mediaEmitted`（RTP-Info 抑制位）。**这是"会话号生命周期"的片段状态机**，不是 RTSP 会话状态机。

**会话号生命周期状态机（本实现实际拥有的那个）**：

| 状态 | 触发 | 动作 | 代码 |
|---|---|---|---|
| `Init`（`session == ""`） | 任意请求 | 不补 Session 头 | `:443-447` |
| | 非 SETUP 的响应 | 不签发 | `:518` 条件不满足 |
| `Ready`（`session != ""`） | 第一个 SETUP 的**响应** | 签发 15 位 hex + 写头 | `:518-523` |
| | 后续请求/响应 | 逐条回显（用户已给则不重复） | `:443-447`/`:516-517` |
| | 响应带用户 Session 且 `session == ""` | **采信用户值**为会话号（跳过随机签发） | `:512-515` |

**生成器在某状态下遇到合法/非法事件分别做什么**：合法与非法**都照渲染**——唯一的"分支"是响应侧 SETUP 判据 `dc.lastMethod == "SETUP"`，它决定**是否签发 Session / 是否补 Transport**；非法序（如无 SETUP 直接 PLAY）下 `lastMethod != "SETUP"` → 不签发 Session、不补 Transport，**但 PLAY 消息照样发**。

**确定性**：同一配置**不产生同一输出**——`ssrc`/`seq`/`ts` 随机（`:227-231`）、`clientSeq`/`serverSeq` 随机（`:157-164`）、`ipID` 随机（`:148`）、`Session` 随机（`:872-879`）。**唯一可复现入口** = `spec.TCP.InitialSeq`（客户端 ISN，`:158-163`），但 raw 链路径**不注入 `spec.TCP`**（`layer_gen.go:36-47` 只搬 RTSP/IP/MAC/端口/TTL/Payload/FlowIndex）→ **链路径完全不可复现**（G-RTSP-12）。可断言量限于：结构、长度、常量、格式、跨包相等关系（§3.3.2）。

### 5.3 自动派生规则（逐条）

| # | 派生 | 触发条件 | 内容 | 代码 |
|---:|---|---|---|---|
| 1 | TCP 三次握手 | 恒（`Plan` 开头） | SYN(+MSS/WScale/SACK) / SYN-ACK / ACK | `:203-209` |
| 2 | TCP 四次挥手 | 恒（`Plan` 结尾） | FIN-ACK / ACK / FIN-ACK / ACK | `:265-275` |
| 3 | `CSeq` | 请求无该头 | `dc.cseq++` 取号 | `:435-440` |
| 4 | `CSeq` 回显 | 响应无该头 | 复制 `dc.lastReqCSeq` | `:502-505` |
| 5 | `Session` 签发 | 第一个 SETUP 响应 | 15 位随机 hex | `:518-523` |
| 6 | `Session` 回显 | `dc.session != ""` 且本消息无该头 | `Session: <id>` | `:443-447`/`:516-517` |
| 7 | `Transport`（请求） | SETUP + `media != nil` + 无该头 | `client_port=<DstPort>-<DstPort+1>` | `:458-466` |
| 8 | `Transport`（响应） | `lastMethod=="SETUP"` + `media != nil` + 无该头 | 追加 `server_port=<SrcPort>-<SrcPort+1>` | `:526-539` |
| 9 | `URI` | 请求无 URI | `rtsp://<host>/media`（IPv6 加方括号） | `:423-425`、`:884-889` |
| 10 | `Content-Length` | `Body != ""` + 无该头（大小写不敏感） | `len(Body)` 字节数 | `:339-342` |
| 11 | `Content-Type` | **响应** + `Body != ""` + 无该头 | `application/sdp` | `:543-547` |
| 12 | `RTP-Info` | `lastMethod=="PLAY"` + `media != nil` + `!mediaEmitted` + `trackID != ""` + 无该头 | `url=…;seq=…;ssrc=…;rtptime=…` | `:550-561` |
| 13 | 消息分段 | `len(msg) > MSS` | 每 MSS 一段 PSH-ACK，seq 连续推进 | `:211-219` |
| 14 | RTP 帧序列 | 消息 `EmitMedia=true` + `media != nil` | `max(frames,1)` 个 UDP 数据报 | `:259-262`、`:716-833` |

## 6. 性能设计与验收（CORE_MEMORY §6）

- **目标与边界**：单流全链 ≤ **18 帧**（今日最大 = #10，含 1 个 RTP 帧）；信令消息数上界由 `dialog` 长度决定（**无上限守卫**）；单消息字节上界由 MSS 分段承担（MSS 缺省 1460）；RTP 帧载荷上界 = `FrameSize`（**无守卫**，超 65507 会产 IP 分片）。吞吐数字待基准，**本版不写承诺**。
- **依据**：`Plan` 以 goroutine + `chan core.PacketConfig`（缓冲 256，`rtsp.go:123`）流式产出，**逐消息渲染 → 逐段发出**，不聚合全量包；每帧内存 = 该帧字节长（最小 40B 握手帧，最大 172B RTP 帧，见 §8）；`params`/`dialogCtx` 为 goroutine 局部，**无跨流共享状态、无锁**。
- **验收两路（§6.3 强制）**：pcap（离线链套件，`t.TempDir()` 内产出 + `pcaptest.VerifyPcap` 同验证器）与 NIC（`enp135s0f0np0`，`nic_capture` 开关）共用同一断言集；今日断言落在 `tcp.dstport`/`tcp.flags`/frames/`packet_count`/`has_handshake`/`terminates`，**未断言实际 RTSP 文本内容**（G-RTSP-7）。
- **六类场景落点（§6.6）**：基线（#1，9 帧）/ 目标规模（#2 五事务 17 帧、#10 复合 18 帧）/ 压力上限（**今日无跨 MSS 分段用例** → A′，G-RTSP-10）/ 长时间运行（**无长连接保活用例** → A′）/ 并发交错（raw 链单连接串行，**不适用**）/ 背压（`packet_count` 精确计数守卫帧数漂移；**但两例无 `packet_count`**，见 G-RTSP-5）。

## 7. 错误处理（负例锚词表 + 未入例分支）

### 7.1 已入例负例（1 条）

| # | 负例 ID | 故障输入 | 代码锚词（逐字） | 代码行 | 实测 |
|---:|---|---|---|---|---|
| N-1 | `rtsp_neg_dialog_required` | `{"rtsp":{"dialog":[]}}` | `rtsp: dialog is required (config.rtsp.dialog must contain at least one message)` | `rtsp.go:111-112` | ValidateSpec 拒，**0 包** |

**负例原子性**：单一故障注入。**负例纯净性**：`expect` 键集合 = `{expect_error, error_contains, notes}`——含 `notes`，**非严格两键**（与 92-moxa 范式不同，G-RTSP-9）。

### 7.2 未入例的拒绝分支（A′ 立项，不得冒充已覆盖）

| 分支 | 锚词 | 代码行 | 可达性 |
|---|---|---|---|
| 源 IP 非法 | `invalid source IP: %s` | `rtsp.go:94` | 链路径 `ip.src` 已由 `ValidateLayers` 先拦 → **层内不可达** |
| 目的 IP 非法 | `invalid destination IP: %s` | `rtsp.go:99` | 同上 |
| MSS 过小 | `MSS %d too small (min %d per RFC 879)` | `:105` | **链路径不可达**（rtsp 层无 MSS 键；`chain_planner.go:1303-1312` 另有 `MSS %d too small (min 536 per RFC 879)` 前置拦截） |
| `RTSP == nil` | 同上 `dialog is required` | `:111` | **可达**：`{"rtsp":{}}` 实测即命中此分支（`spec.RTSP` 被 translate 填成非 nil 空结构后 `len(Dialog)==0`） |

### 7.3 未入例的静默路径（缺陷候选，G-RTSP-9）

以下输入**不报错、不产包**（静默），与"配置错必须报错"的纪律冲突：

| 输入 | 实测行为 | 代码行 |
|---|---|---|
| `{"dialog":[{}]}`（方法/状态码皆空） | 该消息 `renderRTSPMessage` 返回 nil → `continue`；**总包数 7**（只剩握手挥手），**无错误** | `rtsp.go:234-237` + `:317-320` |
| `{"dialog":[{"method":"OPTIONS","direction":"sideways"}]}` | 方向非法 → `continue`；**总包数 7**，**无错误** | `:242-244` |
| 全空 dialog 的每一元素皆空 | 同上，**静默产一条只有 TCP 握挥手的流** | 同上 |
| `{"dialog":[…],"media":{…}}` 但无任何 `emit_media:true` | `media` 配置被解析、**永不消费**；Transport 头仍会补（若含 SETUP），RTP 帧 0 个 | `:259` 条件不满足 |

**不得误报的合法协议事件**：多事务同连接（#2/#5/#10）；`direction:"down"` 的服务器主动消息（#9）；`status_text` 缺省（#4/#12）；空 body 无 Content-Length（#1/#5/#6/#7/#9/#12）；IPv6 承载（单测覆盖，今日无用例）；`media` 与 `dialog` 并存但零 `emit_media`（合法，只是不发媒体）。

## 8. 边界

- **帧长**：最小 = **40 字节**（IPv4 握手帧：14+20+20）；最大实测 = **172 字节**（RTP 帧：14+20+8+12+160 载荷，`rtsp_emit_media_rtp` pkt 11）。信令消息最大实测 = **126 字节**（同例 pkt 9 SETUP 响应，含 Session + Transport 两头）。
- **MSS**：缺省 1460，下限 536（RFC 879）；**今日 12 例无一跨 MSS**（最大 126B）→ 分段路径零用例覆盖（G-RTSP-10）。
- **RTP 载荷**：`FrameSize` 缺省 160（G.711 20ms）；`Frames` 缺省 1；`PayloadType` **0 是合法值（PCMU）不做缺省化**（`rtsp.go:754` 注释）；`SrcPort`/`DstPort` 缺省 5004。
- **状态码**：表内 45 值，表外码渲染空 reason（`RTSP/1.0 <code> \r\n`）。
- **CSeq**：计数器为 Go `int`，无上界守卫；用户非数字值不回同步（`parseCSeqNumber` 返回 -1）。
- **Session**：恒 15 位小写 hex，随机不可复现；`generateSessionID` 无 seed 入口。
- **URI**：缺省 `rtsp://<host>/media`；含 `:` 的主机加方括号（IPv6）；`trackID` 正则 `(?i)trackID=([^/?#]+)`。
- **地址族**：今日 12/12 IPv4；IPv6 承载路径已落码（`rtspHostOf` 方括号 + `EtherTypeFor`）但**零用例** → A′（G-RTSP-10）。
- **端口**：控制通道 554（链路径缺省）；RTP 5004/5005（成对）。**rtsp 层无端口键** → 层内改端口不可能（G-RTSP-3）。
- **不得产生回绕长度或超量分配**：消息长度由 `renderRTSPMessage` 一次算定；RTP 载荷由 `FrameSize` 一次分配（`:799`）。

## 9. 原子 ID 与完成定义（12 个唯一语义 ID，顺序为权威）

| # | ID | 类型 | 覆盖 | `packet_count`（实测） | 帧位 |
|---:|---|---|---|---:|---|
| 1 | `rtsp_options_smoke` | 正 | §3.1/§3.3.1：OPTIONS 基线 + CSeq 自动补 + 554 缺省 | 9 | 4 请求 / 5 响应 |
| 2 | `rtsp_play_session_full` | 正 | §3.3.2/§3.3.3：五方法全序 + Session 签发回显 | 17 | 4/5, 6/7, 8/9, 10/11, 12/13 |
| 3 | `rtsp_describe_sdp_body` | 正 | §3.3.4：SDP body 透传 + Content-Length/Content-Type 自动补 | 9 | 4 请求 / 5 响应（109B） |
| 4 | `rtsp_response_404` | 正 | §3.2：404 reason 缺省 `Not Found` | 9 | 4 请求 / 5 响应（35B） |
| 5 | `rtsp_pause_teardown` | 正 | §5.3：PLAY/PAUSE/TEARDOWN 三事务 | 13 | 4/5, 6/7, 8/9 |
| 6 | `rtsp_uri_explicit_and_default` | 正 | §3.3 规则 9：URI 缺省构造 + 显式值 | 11 | 4/5, 6/7 |
| 7 | `rtsp_headers_custom` | 正 | §3.3：用户头（User-Agent）与自动 CSeq 共存、序为自动在前 | 9 | 4（75B）/ 5 |
| 8 | `rtsp_emit_media_rtp` | 正 | §3.5：RTP 子流 + SETUP Transport 双侧 + **`emit_media` 挂请求** | 16 | 8/9 SETUP 对，**11 = RTP（172B UDP）** |
| 9 | `rtsp_direction_explicit` | 正 | §3.4：显式 `direction` 覆盖方法推断 | 9 | 4 = **服务器 IP 发出**的请求（L3 已翻转） |
| 10 | `rtsp_composite_full_session_media` | 正 | §4：五方法 + RTP + 自定义头 + SDP 四类交织 | 18 | 4/5 … 12/13, **11 = RTP**, 13/14 TEARDOWN |
| 11 | `rtsp_neg_dialog_required` | 负 | §7 N-1：空 dialog | —（实测 0 包） | 无 |
| 12 | `rtsp_status_text_default` | 正 | §3.2：200 无 `status_text` → reason `OK` | 9 | 4 请求 / 5 响应 |

**包数公式**（实测推导，§0 末实跑 12/12 逐例吻合）：

```
packet_count = 7                                    ← 3 握手 + 4 挥手（§3.6）
             + Σ_{m ∈ dialog} ceil(render_len(m) / MSS)   ← 每消息段数（今日恒 1）
             + (任一消息 EmitMedia ? max(media.Frames, 1) : 0)   ← RTP 帧数
```

校验：#1/#3/#4/#7/#9/#12 = 7+2×1 = **9** ✓；#6 = 7+2×2 = **11** ✓；#5 = 7+2×3 = **13** ✓；#8 = 7+8+1 = **16** ✓；#2 = 7+10 = **17** ✓；#10 = 7+10+1 = **18** ✓。

**逐例实测报文原文**（关键帧，offset 54，`10.0.0.1`=client / `20.0.0.1`=server）：

- #1 pkt 4：`OPTIONS rtsp://20.0.0.1/media RTSP/1.0\r\nCSeq: 1\r\n\r\n`（51B）；pkt 5：`RTSP/1.0 200 OK\r\nCSeq: 1\r\n\r\n`（28B）。
- #2 pkt 7：`RTSP/1.0 200 OK\r\nCSeq: 2\r\nContent-Type: application/sdp\r\nContent-Length: 5\r\n\r\nv=0\r\n`（83B）；pkt 9 首次出现 `Session: <15hex>`；pkt 12/13 回显同值。
- #3 pkt 5：`Content-Length: 30` + 两行 SDP（109B）。
- #4 pkt 5：`RTSP/1.0 404 Not Found\r\nCSeq: 1\r\n\r\n`（35B）。
- #7 pkt 4：`OPTIONS … \r\nCSeq: 1\r\nUser-Agent: trafficgen\r\n\r\n`（75B）——**自动头在用户头之前**。
- #8 pkt 8：`SETUP …\r\nCSeq: 3\r\nTransport: RTP/AVP;unicast;client_port=5004-5005\r\n\r\n`；pkt 9 追加 `;server_port=5004-5005`；**pkt 11 = UDP `20.0.0.1:5004 → 10.0.0.1:5004`，172B**；pkt 12 = PLAY 响应（**无 RTP-Info**，因 `emit_media` 挂在请求上）。
- #9 pkt 4：`OPTIONS …` 但**发出方 = 20.0.0.1**（L3 已按 `direction:"down"` 翻转）；pkt 5 = 10.0.0.1 发出的 `200 OK`。

**包数双向确认**：本车道实跑（§0 末）12/12 PASS，逐例 `packet_count` 与 JSON 字段**逐例一致**（10 例有字段：9/17/9/9/13/11/9/9/9/9；2 例无字段由本表补齐：16/18）；结果产物 `rtsp.md` 表内 11 例数字与实跑**11/11 一致**（`rtsp_neg_dialog_required` 记 0 包，一致）。

## 10. 规范矩阵（CORE_MEMORY §4 八项：规范要求→业务场景→代码现状→缺口）

### 10.1 八项规范矩阵

| # | 八项 | 规范要求 | 业务场景 | 代码现状 | 缺口 |
|---|---|---|---|---|---|
| 1 | 连接模型 | 客户端主动建 TCP 到 554；信令与媒体**分离载体**（RFC 2326 §1.3） | 场景①–⑫ | `[ip,rtsp]` raw 自驱；自建 TCP（`rtsp.go:203-275`）；媒体走 UDP 子流（`:716-833`） | 无 |
| 2 | 命令/消息表 | 12 方法（§10.1）+ 45 状态码（§10.2） | 场景①②④⑤⑨ | 方法族全渲染（`renderRTSPMessage`）；reason 表 45 值（`:568-662`） | 用例层方法 6/12、状态码 2/45 → A′（G-RTSP-10） |
| 3 | 状态机 | Init→Ready→Playing→Recording（附录 A） | 场景②⑤ | **无执法**；仅会话号生命周期片段（§5.2） | G-RTSP-9（455 永不自动产出） |
| 4 | 字段表 | 请求行/状态行 + §12 头族（CSeq/Session/Transport/RTP-Info/Content-Length/Content-Type） | 数据场景层 | 逐字段落码（§3.1/§3.3）；5 类自动头 | RTP-Info 零用例（G-RTSP-4） |
| 5 | 错误处理 | 4xx/5xx 状态码 + 455 状态机拒绝 | 场景④ | 1 负例 + 4 拒绝分支（§7.1/§7.2）+ 4 静默路径（§7.3） | G-RTSP-9 |
| 6 | 超时与活性 | `Session` 头支持 `timeout` 参数（§12.37）；`GET_PARAMETER` 可当保活（§10.8） | — | 不实现保活；`timeout` 可当用户头写；`GET_PARAMETER` 可当普通方法写 | A′（G-RTSP-10） |
| 7 | NAT/代理/被动 | RTSP 无被动模式概念（服务器监听 554 是常态）；`interleaved` 用于穿 NAT（§10.12） | — | 无 `sessions[].src_port`；多流走策略级 `flow_control` | **显式不适用**被动模式；`interleaved` 明确不解决（§1 边界③） |
| 8 | 版本/方言 | RTSP 1.0（RFC 2326）与 2.0（RFC 7826） | 全场景 | 版本串**硬写** `RTSP/1.0`（`:303`/`:312`）；RFC 7826 只借 `PLAY_NOTIFY` 方向（`:671`） | RTSP 2.0 版本串不可配 → G-RTSP-13 |

### 10.2 子表①：方法 × 终态矩阵（逐格已覆/立项/不适用）

| 方法 | T1 正常终态 | T2 配置拒绝 | T3 RST 异常终态 |
|---|---|---|---|
| OPTIONS | 已覆（#1/#7/#12） | 已覆（#11 代表例） | A′ 立项（G-RTSP-14） |
| DESCRIBE | 已覆（#2/#3/#4/#6） | 同上代表已覆 | A′ 立项（G-RTSP-14） |
| SETUP | 已覆（#2/#8/#10） | 同上代表已覆 | A′ 立项（G-RTSP-14） |
| PLAY | 已覆（#2/#5/#8/#10） | 同上代表已覆 | A′ 立项（G-RTSP-14） |
| PAUSE | 已覆（#5） | 同上代表已覆 | A′ 立项（G-RTSP-14） |
| TEARDOWN | 已覆（#2/#5/#10） | 同上代表已覆 | A′ 立项（G-RTSP-14） |
| GET_PARAMETER | **A′ 立项**（G-RTSP-10） | 同上代表已覆 | A′ 立项（G-RTSP-14） |
| SET_PARAMETER | **A′ 立项**（G-RTSP-10） | 同上代表已覆 | A′ 立项（G-RTSP-14） |
| ANNOUNCE | **A′ 立项**（G-RTSP-10） | 同上代表已覆 | A′ 立项（G-RTSP-14） |
| RECORD | **A′ 立项**（G-RTSP-10） | 同上代表已覆 | A′ 立项（G-RTSP-14） |
| REDIRECT | **A′ 立项**（G-RTSP-10） | 同上代表已覆 | A′ 立项（G-RTSP-14） |
| PLAY_NOTIFY | **A′ 立项**（G-RTSP-10） | 同上代表已覆 | A′ 立项（G-RTSP-14） |

**逐格重数**：12 行 × 3 列 = **36 格**——已覆 **18**（T1 列 6 + T2 列 12）/ A′ 立项 **18**（T1 列 6 + T3 列 12）/ 不适用 **0**。18 + 18 = 36 ✓

### 10.3 子表②：数据形态变体表

| # | 变体 | 落点 |
|---:|---|---|
| 1 | 请求无 `uri`（缺省构造） | 覆（#1–#5/#7/#8/#9/#10/#12 全部） |
| 2 | 请求显式 `uri` | 覆（#6 后半） |
| 3 | 请求无 `headers` | 覆（除 #7/#10） |
| 4 | 请求带自定义头 | 覆（#7/#10 `User-Agent`） |
| 5 | 响应无 `body` | 覆（#1/#2 大部分/#5/#6/#7/#9/#10/#12） |
| 6 | 响应带 `body`（单行 SDP） | 覆（#2/#8/#10，`v=0\r\n` 5B） |
| 7 | 响应带 `body`（多行 SDP） | 覆（#3，30B） |
| 8 | `status_text` 显式给 | 覆（#1/#2/#3/#5/#6/#7/#8/#9/#10） |
| 9 | `status_text` 缺省 | 覆（#4 404、#12 200） |
| 10 | `status_code` 表内码 | 覆（200、404 两值） |
| 11 | `status_code` 表外码 | A′ 立项（`rtspReasonPhrase` 无 default，渲染空 reason） |
| 12 | `method` 与 `status_code` 同给 | A′ 立项（单测覆盖，`Method` 胜） |
| 13 | 消息方法/状态码皆空 | A′ 立项（**静默跳过**，§7.3） |
| 14 | `direction` 缺省（推断） | 覆（除 #9） |
| 15 | `direction` 显式 `down`（请求） | 覆（#9 前半） |
| 16 | `direction` 显式 `up`（响应） | 覆（#9 后半） |
| 17 | `direction` 非法值 | A′ 立项（**静默跳过**，§7.3） |
| 18 | `CSeq` 缺省（自动取号） | 覆（全部正例） |
| 19 | `CSeq` 用户显式（重同步） | A′ 立项（单测覆盖） |
| 20 | `Session` 自动签发 | 覆（#2/#8/#10） |
| 21 | `Session` 用户供给（响应） | A′ 立项（单测覆盖） |
| 22 | `Transport` 自动（请求侧） | 覆（#8/#10） |
| 23 | `Transport` 自动（响应侧，含 server_port） | 覆（#8/#10） |
| 24 | `Transport` 用户覆盖 | A′ 立项（单测覆盖） |
| 25 | `Content-Length` 自动补 | 覆（#2/#3/#8/#10） |
| 26 | `Content-Length` 用户给（不重复） | A′ 立项（单测覆盖） |
| 27 | `Content-Type` 自动补（响应带 body） | 覆（#2/#3/#8/#10） |
| 28 | `Content-Type` 用户覆盖 | A′ 立项（单测覆盖） |
| 29 | `RTP-Info` 自动生成 | **A′ 立项**（触发条件要求 `emit_media` 挂响应；存量两例挂请求 → 今日零例，G-RTSP-4） |
| 30 | `media` 缺省（无媒体） | 覆（#1–#7/#9/#12） |
| 31 | `media` + `emit_media:true` | 覆（#8/#10） |
| 32 | `media` 有配置但无 `emit_media` | A′ 立项（静默，§7.3） |
| 33 | `media.frames` 缺省（→1） | A′ 立项（存量两例显式给 1/2） |
| 34 | `media.payload_type` 显式 | A′ 立项（存量未写，恒 0=PCMU） |
| 35 | `media.frame_size` 显式 | A′ 立项（存量未写，恒 160） |
| 36 | `media.src_port`/`dst_port` 显式 | A′ 立项（存量未写，恒 5004） |
| 37 | `media.direction` 显式 `down` | 覆（#8/#10） |
| 38 | `media.direction` 缺省 | A′ 立项（缺省也是 down，行为等价但分支未走） |
| 39 | `media.file_source` | A′ 立项（单测覆盖，需 `PayloadCache`） |
| 40 | 消息跨 MSS 分段 | A′ 立项（今日最大 126B < 1460，G-RTSP-10） |
| 41 | IPv4 载体 | 覆（12/12） |
| 42 | IPv6 载体 | **A′ 立项**（`rtspHostOf` 方括号路径已落码，零用例，G-RTSP-10） |
| 43 | 非默认控制端口 | A′ 立项（rtsp 层无端口键，只能改 `ip` 层之外的链——**不可达**，G-RTSP-3） |
| 44 | 多流（`flow_control.flows>1`） | A′ 立项（raw 链单连接；多流由 worker 注入 `12345+i`） |
| 45 | 多会话（`sessions[]`） | **显式不适用**（raw 链无 `sessions[]` 数组，§1 边界⑦） |

**重数**：45 行 = 覆 **23** + A′ 立项 **21** + 不适用 **1**。23 + 21 + 1 = 45 ✓

### 10.4 子表③：商业行为→用例映射表

| # | 商业行为（出处） | 用例映射 | 结论 |
|---:|---|---|---|
| 1 | 能力探测（OPTIONS，§10.1） | #1/#12 | 已覆 |
| 2 | 媒体描述获取（DESCRIBE + SDP，§10.2） | #2/#3 | 已覆 |
| 3 | 传输参数协商（SETUP + Transport，§10.4） | #2/#8/#10 | 已覆 |
| 4 | 播放启动（PLAY，§10.5） | #2/#5/#8/#10 | 已覆 |
| 5 | 暂停/恢复（PAUSE，§10.6） | #5 | 已覆 |
| 6 | 会话结束（TEARDOWN，§10.7） | #2/#5/#10 | 已覆 |
| 7 | 媒体实际流出（RTP，RFC 3550） | #8/#10 | 已覆（1 帧/例） |
| 8 | 资源不存在（404） | #4 | 已覆 |
| 9 | 服务器主动重定向（REDIRECT，§10.9） | #9（仅方向面） | 部分覆（方法字面零例，G-RTSP-10） |
| 10 | 服务器主动通知（PLAY_NOTIFY，RFC 7826 §13.4） | — | A′ 立项（G-RTSP-10） |
| 11 | 录制（RECORD/ANNOUNCE，§10.10/§10.11） | — | A′ 立项（G-RTSP-10） |
| 12 | 参数读写（GET/SET_PARAMETER，§10.8/§10.9） | — | A′ 立项（G-RTSP-10） |
| 13 | 认证挑战（401 + Authorization，§14） | — | **明确不解决**（§1 边界②） |
| 14 | RTP over TCP（interleaved，§10.12） | — | **明确不解决**（§1 边界③） |
| 15 | RTCP 反馈（RFC 3550 §6） | — | **明确不解决**（§1 边界④） |
| 16 | 真实编解码载荷 | — | **明确不解决**（§1 边界⑤） |
| 17 | 长连接保活（GET_PARAMETER/Session timeout，§12.37） | — | A′ 立项（G-RTSP-10） |

**重数**：17 行 = 覆 **9**（含 1 部分覆）+ A′ 立项 **4** + 明确不解决 **4**。9 + 4 + 4 = 17 ✓

### 10.5 三路对照与候选方案对比

三路：① **规范原文**（RFC 2326 §10/§12/附录 A + RFC 3550 §5.1 + RFC 4566，定"必须是什么"）；② **商业化软件实际行为**（**部分取到**：代码内引用 QuickTime Streaming Server 参考 pcap `proto_rtsp.pcap` 的 Session 形 `8d9dea6f8d9deaa8f`、`RTP-Info ssrc=-1919345977`；`CASE_PCAP_MAPPING.md:261-273` 列 VLC/QuickTime 形九场景；**但真实服务器线字节本轮未抓包复核** → G-RTSP-8）；③ **可靠开源实现思路**（live555 / GStreamer rtspsrc 的 CSeq 单调、Session 回显、Transport `client_port`/`server_port` 成对——只借鉴"头必须在首个 SETUP 应答签发"这一条思路）。

三路一致点：请求行/状态行语法、CSeq 双向同号、Session 在 SETUP 应答签发并后续回显、Transport 双侧端口成对、RTP 12B 固定头大端。
不一致点：**RTP-Info 的挂点**——参考 pcap 形是"PLAY **应答**带 RTP-Info，随后 RTP 帧流出"（`rtsp.go:20-22` 注释明写此意图），但**本仓存量两例把 `emit_media` 挂在 PLAY 请求上**，导致应答反而**不**带 RTP-Info（G-RTSP-4）。

| 方案 | 走法（借鉴来源） | 取舍 | 结论 |
|---|---|---|---|
| A | 独立 `rtsp` raw 自驱终结层（本版；ldap/rtmp 同构先例） | 自建 TCP 握手/分段/挥手 → 单层内聚、零跨层状态；代价 = 自建 TCP 与 tcp 层重复实现（约 60 行） | **采用**（已落码） |
| B | 复用 tcp 层事件面（`[ip,tcp,rtsp]` + `EmitMsg`） | 理论上更省码；实测**静默产 0 包**（`isRawIPChain` 命中 raw 分支，rtsp 生成器不实现 `GenEvents`，事件链无生产者） | **否决**（实测 0 包，G-RTSP-2） |
| C | 拆"信令层 rtsp + 媒体层 rtp"两层 | 两层的边界（Transport 协商端口 → RTP 帧端口）需跨层状态传递，框架层间无此通道；且 RTP 与信令**不同四元组**，同链双载体框架不支持 | **否决**（状态在 `params`/`media` 局部，单层内聚更简单） |

## 11. as-built 代码设计（CORE_MEMORY §8 八要素）

> 状态说明：实现已落码（`internal/protocol/rtsp/` 四文件 + 接线），本条为**逆向定稿**，供后续改动的唯一入口。

### 11.1 文件清单（实测，非计划）

| 文件 | 职责 | 行数 |
|---|---:|---:|
| `trafficgen/internal/core/types.go`（`:2739-2743` + `:2749-2767` + `:2796-2809` + `:1700`） | `RTSPConfig` / `RTSPMessage` / `RTSPMedia` + `FlowSpec.RTSP` 槽位 | —（共享文件） |
| `trafficgen/internal/protocol/rtsp/rtsp.go` | 全部实现：`Validate` + `Plan`（自建 TCP + 对话渲染 + RTP 子流）+ 头补全 + reason 表 + 工具函数 | 974 |
| `trafficgen/internal/protocol/rtsp/layer_gen.go` | raw 链终结层生成器（`RTSPGenerator` + `init()` 注册生成器与校验器） | 68 |
| `trafficgen/internal/protocol/rtsp/rtsp_test.go` | 44 个 `Test*`（Validate 面 + CSeq/Session/Transport/Content-Length 面 + 方法/状态码/URI 面 + TCP 面） | 1007 |
| `trafficgen/internal/protocol/rtsp/rtsp_rtp_test.go` | 20 个 `Test*`（RTP 头字节 + 默认值 + 方向 + file_source + RTP-Info + seq/ack 连续性） | 502 |
| 接线 6 件 | registry 注册（`registry.go:1931`）/ translate 层内分支（`chain_planner_translate.go:2791`）/ 扁平 convert（`strategy_convert.go:1117`）/ protocols 准入（`protocols.go:53`）/ 缺省端口 554（`chain_planner.go:1035`）+ 源端口 0 保持（`:997`）/ raw 链名单（`chain_planner_util.go:54`）/ Meta 直传（`chain_planner.go:1522`）/ 顶层 presence 判死（`strategy_convert.go:9100-9116` 的 `rawWrapChains`）/ 服务器空导入 + 注册（`cmd/server/main.go:142`/`:573`） | — |

**合计实现码 1042 行**（`rtsp.go` 974 + `layer_gen.go` 68），测试 1509 行，**64 个 `Test*`**。

### 11.2 接口签名

- `Validate(spec core.FlowSpec) error`（`rtsp.go:91`）：SrcIP/DstIP 可解析、`spec.TCP.MSS >= 536`、`spec.RTSP != nil && len(Dialog) > 0`。**空配置不通过**（与 opcua 的"空配置默认流"相反——rtsp 有必需项）。
- `Plan(ctx, spec) (<-chan core.PacketConfig, error)`（`:118`）：先 `Validate`，再 goroutine 流式产出（缓冲 256）。
- `renderRTSPMessage(msg core.RTSPMessage) []byte`（`:296`）：纯函数，`Method`/`StatusCode` 皆空返回 nil。
- `completeRTSPHeaders(msg *core.RTSPMessage, dc *dialogCtx, spec, media, params)`（`:384`）：就地改 `msg.Headers`（`Plan` 内 `msg` 是每轮循环副本，**用户配置不被污染**）。
- `emitRTSPMedia(ctx, ch, media, spec, parentFlowID, now, *packetIndex, nextIPID, params)`（`:716`）。
- 生成器：`Name() "rtsp"`；`GenEvents() nil`（**显式无事件面**——防被事件路径误用）；`Generate` 逐包 `req.Emit`，**每包 `Direction` 改写为 `"up"`**（`layer_gen.go:53`）。

### 11.3 数据结构

`RTSPConfig{Dialog []RTSPMessage, Media *RTSPMedia}`（`types.go:2739-2743`；注释明写 MSS 归 `TCPConfig.MSS`）。
`RTSPMessage{Method, URI, StatusCode int, StatusText, Headers []string, Body, Direction string, EmitMedia bool}`（`:2749-2767`）。
`RTSPMedia{SrcPort, DstPort uint16, Frames int, PayloadType uint8, SampleRate uint32, FrameSize int, Direction string, FileSource *filesystem.FileSource}`（`:2796-2809`）。
`dialogCtx{cseq int, lastReqCSeq, lastMethod, session, trackID string, mediaEmitted bool}`（`rtsp.go:369-376`）。
`rtpParams{ssrc uint32, seq uint16, ts uint32}`（`:685-689`）。

### 11.4 主流程

层链配置 → `ValidateLayers`（registry Fields 2 键 allowlist + 动态对象门）→ `ValidateSpec`（554 缺省 + 源端口 0 保持）→ translate（`ParseRTSPConfigFromMap` → `spec.RTSP`）→ `ChainPlanner.Plan` → `isRawIPChain("rtsp", …)` 命中 → raw 自驱分支（`chain_planner.go:1497-1584`）→ `RTSPGenerator.Generate` → `NewPlanner().Plan` → `buildEvents` 等价物（握手 → 逐消息渲染+分段 → RTP 子流 → 挥手）→ `req.Emit`（补 L2/TTL/时间戳/FlowID）→ worker → writer（PCAP/NIC）。

### 11.5 错误分支

`Validate` 4 个拒绝分支（§7.2）全部传 task error（负例实测 0 包，**零假成功**）。**无 builder 层拒绝**——`renderRTSPMessage` 不返回错误（非法输入走"静默跳过"，§7.3）。

### 11.6 性能边界

见 §6（流式产出、per-flow 局部状态、无跨流共享、无锁）。

### 11.7 与现有逻辑的冲突点

- **`isRawIPChain` 与 `[ip,tcp,rtsp]` 冲突（G-RTSP-2）**：`chain_planner_util.go:44-51` 明确"链上带 tcp/udp 的终结层走事件面"，但 rtsp 生成器 `GenEvents()` 返回 nil（`layer_gen.go:25`）→ 事件链无生产者 → **`Plan` 返回 0 包且无错误**（实测）。而 `strategy_convert.go:9097` 的迁移指引把 rtsp 目标链写成 **`[ip,rtsp]`**（正确），故用户若照别的协议惯例加 tcp 层即静默产空流。
- **顶层 presence 判死已覆盖（无缺口）**：`strategy_convert.go:9100-9116` 的 `rawWrapChains` 含 `"rtsp": "[ip,rtsp]"` → 顶层 `rtsp` 子映射 presence 判死（实测文案 `protocol rtsp no longer accepts a top-level rtsp sub-config (move it into the rtsp layer of a [ip,rtsp] layers chain)`）。**游离顶层未知键（如 `{"layers":[…],"bogus":1}`）无通用门** → 实测 `CheckProtoFlat` 返回空串（不判死）→ 该负例建了会真绿 = **假通过，不建**（G-RTSP-15，与 moxa G-MOXA-2 / opcua G-OPCUA-1 同款）。
- **动态 allowlist（`internal/core/layer_dyn.go:17-19`）无 `rtsp` 行** → 层内任何对象（`dialog`/`media`）即拒 `layers[i](rtsp).<field> does not support dynamic`（实测三例：dialog/media/dst_port 全拒）。**rtsp 层无端口键**，`dst_port` 对象先撞 V9 `unknown field`。见 §12.12。
- **源端口 0 直传（G-RTSP-12）**：`chain_planner.go:996` raw 链同列——**0 保持 0**，单流时实测报文客户端源端口 = **0**（§3 逐例可证）。这不是缺陷（与 pppoe/ldap/rtmp 同族语义），但**任何断言 `tcp.srcport` 非 0 的用例会假红**。
- **`chain_planner.go:1522` Meta 直传 `spec.RTSP`**：与 `layer_gen.go:32` 读 `req.Meta.RTSP` 配对；若 translate 未填 `spec.RTSP`，生成器 fallback 到 `&core.RTSPConfig{}` → `Validate` 立即以 `dialog is required` 拒绝（**不是静默空流**，此路径正确）。

### 11.8 回滚方式

本协议文件独立成包，回滚 = revert `internal/protocol/rtsp/` 四文件 + 接线 7 处（registry/protocols/translate/convert/chain_planner 两处/chain_planner_util/main.go）；不触及其他协议。cases 回滚 = 恢复 12 例 JSON（产物文件，非文档）。

## 12. 门1 §1–§14 十四行对照表（CORE_MEMORY §15.1–15.3）

| § | 本协议怎么满足 | 证据 |
|---|---|---|
| §1 层链唯一真相 | 见 §12.1 强制展开：存量 **12/12 顶层 = `{layers}`（唯一键，零游离键）**；顶层 `rtsp` 子映射 presence 已判死（`rawWrapChains`）；目标形状见 §2 样例且**存量已达标**（无迁移工作量） | §12.1；`cases/rtsp.json` 机读实测；`strategy_convert.go:9100-9116` |
| §2 策略/任务 | 策略 = 单 rtsp 流量模板（dialog+media）；任务 = 多策略合跑 + 总量封顶；框架语义未动 | 设计 §2 样例 |
| §3 五件套 | 见 §12.3 强制展开：会话表/事务序列/**关联关系（有派生媒体流，非豁免）**/插入位置（raw 终结层）/时间线 | §12.3 + §5 |
| §4 查规范 | RFC 2326 §10/§12/附录 A + RFC 7826 + RFC 3550 §5.1 + RFC 4566 + RFC 879 + 本机 tshark 3.6.14 + 12 例实测；八项矩阵 + 子表①②③ | §10 |
| §5 依赖与错误 | `DependsOn ["ip"]` 单值（`registry.go:1931`）；4 拒绝分支 + 4 静默路径；失败传 task error（负例 0 包实测） | §5/§7/§11.5 |
| §6 性能 | 见 §6（目标边界/依据/两路验收/六类场景落点齐；吞吐数字不写承诺） | §6 |
| §7 三份文档 | `122-rtsp-{design,testcase}.md` v1.0.0（本对）+ `cases/rtsp.json`（12 ID）+ 结果产物 `docs/protocol-pcap-test/rtsp.md`（**pcap 悬空**，G-RTSP-6） | 修订记录 |
| §8 设计先行 | 本对文档先于任何后续改动；**本车道未动代码/cases** | `git status --short` 零改动 |
| §9 测试三源 | 三源 = RFC 2326/7826/3550/4566（§10）+ 本契约（§11）+ tshark 3.6.14 与 **12 例实跑**（**今日已到抓包级**：12/12 PASS，逐例包数与帧位在案）；12 ID 逐项回指；存量 12 例审计去向 testcase §8 | `122-rtsp-testcase.md` §2/§5/§8 |
| §10 评审闭环 | 本车道自审 + 收官隔离复审；红先绿后 | 修订记录 |
| §11 白话 | 本文首节白话一句 | 汇报 |
| §12 动态清单 | 见 §12.12 强制展开：四元组**仅地址可动态**（`ip` 层 src/dst/ttl）；**端口动态不可达**（rtsp 层无端口键 + 无 tcp 层）；业务 2 键全关；序号算法实读行号 | §12.12 |
| §13 schema 派生 | `rtsp` 已在 `registry.go:1931` 注册（**不新增层**）；Fields 2 键；**改 registry Fields 必须重跑 schemagen** | §11.1 |
| §14 真实流程 | 12 例经离线链套件真实生成 → tshark 验证（`pcaptest.VerifyPcap` 同验证器）→ 先跑后钉；逐例包数/帧位在 §9 | §0 末实跑证据 |

### 12.1 §1 强制展开：旧键去向 + 完整 spec_json 样例

**存量实测（逐例机读，2026-09-29）**：

| 文件 | 例数 | 顶层键分布 | 链形 | 负例 expect 形状 |
|---|---|---|---|---|
| `cases/rtsp.json` | 12 | **`{layers}` ×12**（唯一顶层键，**零游离键**） | `[ip,rtsp]` ×12（**无例外**） | 1/1 = `{expect_error, error_contains, notes}` |

**旧键去向表（§15.3 要求"每个键写去向"）**：

| 旧键 | 存量出现例数 | 去向 |
|---|---:|---|
| `src_ip` / `dst_ip` | **0** | 已住 `layers[0].ip.{src,dst}`（12/12，`10.0.0.1`→`20.0.0.1`） |
| `src_port` | **0** | rtsp 层**无该键**；链路径 0 保持 0，单流时实测源端口 = 0，多流由 worker 注入 `12345+i` |
| `dst_port` | **0** | 链路径缺省 554（`chain_planner.go:1035`）；**rtsp 层无该键**，层内改端口不可能（G-RTSP-3） |
| `count` | **0** | 走 `flow_control`（本版未用） |
| 顶层 `rtsp` 子映射 | **0** | 已住 `layers[1].rtsp`（12/12）；presence 已判死（`rawWrapChains`，实测文案见 §11.7） |
| `strategy_fc` / `flow_control` | **0** | 本协议无多流用例；目标形按需加 |

**结论**：**本协议存量 12/12 顶层零残留**——§1 门的动作 = ①**无旧键可删**；②收官自查行「非负例顶层键 = 0」**今日即成立**（机读实测 12/12 顶层仅 `layers`）；③A′ 新增例全部沿用纯 layers 形（§13）。
> **注**：全仓 `cases/*.json` 中已有多协议为纯 `{layers}` 形（batch2 同批另 9 个协议 + 批次一 10 个 + 更早若干），**本协议不构成全仓唯一性**；本协议的**特有事实**仅是"12/12 例今日即零残留 + 链形 12/12 恒为 `[ip,rtsp]`"。

目标形状样例见 §2（顶层仅 `layers`）。

### 12-P2 判死负例形状（链级红例必含清单①③④）

- ① **presence 形状 `{"layers":[…],"rtsp":{}}` 今日已被拒**（`rawWrapChains` 覆盖 rtsp，实测文案命中）→ **P4 可建该负例且会真红**（与 opcua/moxa 不同——本协议此门**已通**）✓。② **白名单外游离键判死（`unknown field`）今日无通用门** → 实测 `CheckProtoFlat("rtsp", {"layers":[…],"bogus":1})` 返回空串（不判死）→ **P4 不建该负例**（建了会真绿 = 假通过）→ G-RTSP-15。③ 1 负例带锚词（`dialog is required`，已齐，§7.1）。④ 收官自查「非负例顶层键 = 0」**今日已成立**（§12.1）。

### 12.3 §3 强制展开：五件套

**会话表**：`s1` 单连接基线（12/12 例）——一条 TCP 连接（`10.0.0.1:0` ↔ `20.0.0.1:554`，IPv4）+ 自建握手（3 帧）/ 消息序列（N 帧）/ 自建挥手（4 帧）；`s2` 媒体子流（#8/#10）——**同一会话派生的第二条四元组** `20.0.0.1:5004 ↔ 10.0.0.1:5004`（UDP）。**本协议无 `sessions[]` 多会话形态**（raw 链单连接，§1 边界⑦）→ 多会话层**显式不适用**（不是遗漏，是链形态决定）。

**事务序列**：`t1` 传输建连（自建 TCP 三次握手，`rtsp.go:203-209`）→ `t2` 信令事务 ×N（每对请求/响应，`CSeq` 配对）→ `t3` 媒体子流（`emit_media` 触发的 RTP 帧序列，`:259-262`）→ `t4` 连接释放（自建四次挥手，`:265-275`）。每事务四件事：**前置**（`dc` 状态 + 媒体配置）/ **触发**（配置里的下一条消息）/ **成功**（渲染字节 + 分段 + 发出）/ **失败**（`Validate` 拒绝 → task error；渲染期无失败分支，非法输入走静默跳过 §7.3）。

**关联关系（本协议必答项，非豁免）**：
- **主从**：RTSP 信令（控制流，TCP 554）= **主**；RTP 媒体（数据流，UDP）= **从**，由消息上的 `EmitMedia` 标记派生。
- **端口推导链**：`RTSPMedia.SrcPort/DstPort`（缺省 5004）→ ① 自动补的 SETUP `Transport` 头 `client_port=<DstPort>-<DstPort+1>` / `server_port=<SrcPort>-<SrcPort+1>`（`:458-466`/`:526-539`）→ ② **同一对值**写入实际 RTP 帧的 `L4.SrcPort/DstPort`（`:746-753`/`:825`）。**头与帧同源**，DPI 可据此关联。
- **参数推导链**：`rtpParams`（ssrc/seq/ts）在对话前一次性随机（`:227-231`）→ ① `RTP-Info` 头（若生成）携带 `seq/ssrc/rtptime`（`:550-561`）→ ② 同一 `params` 指针逐帧推进并写入 RTP 头（`:802-811`/`:830-831`）。**头里报的就是下一帧的值**（`TestRTSPPlan_RTPInfo_MatchesEmittedFrames`）。
- **排序保证**：RTP 帧 FlowID = `<parent>:rtp`（`:779`）但共享 parent 的 `GroupID` → 路由到同一 PacketWorker → **线序 = emit 序**（`:15-18` 注释）。实测 #8 中 RTP 帧落在 pkt 11（PLAY 请求 pkt 10 之后、PLAY 响应 pkt 12 之前）✓。

**插入位置**：**raw 自驱终结层**（`[ip, rtsp]`）——链上**无 tcp/udp 层**（`isRawIPChain` 名单 `chain_planner_util.go:54`）；TCP 握手/分段/挥手由本层自产（§3.6）；媒体子流也由本层自产（不经 udp 层）。

**时间线**：消息内严格顺序（行→头→空行→体）；消息间 = 配置 `dialog` 数组序；RTP 帧插在 `emit_media` 消息**之后**（`:259-262` 位于消息 emit 之后）；多消息无交错（单连接串行）；**无并发路径**（`concurrent` 为例外路径不启用）。

### 12.12 §12 强制展开：动态字段清单与序号算法

**四元组**：

| 字段 | 动态可达性 | 说明 |
|---|---|---|
| `ip.src` / `ip.dst` | **开**（allowlist `layer_dyn.go:21` `"ip": {"src","dst","ttl"}`） | 五策略全支持（fixed/inc/rand/list/pattern） |
| `ip.ttl` | **开**（同上） | 同上 |
| `rtsp.src_port` / `rtsp.dst_port` | **关且不可达** | rtsp 层 registry **无端口键**（`registry.go:1931-1936` 只登记 `dialog`/`media`）→ 层内写 `dst_port` 实测撞 V9 `layers: layer "rtsp": unknown field "dst_port"`；写对象则撞 `layers[1](rtsp).dst_port does not support dynamic` |
| `tcp.src_port` / `tcp.dst_port` | **不可达** | 链上**不能**放 tcp 层（`[ip,tcp,rtsp]` 实测 0 包，G-RTSP-2）→ tcp 层动态键无落点 |

→ **结论：rtsp 链的端口动态完全不可达**（G-RTSP-3）。单流源端口实测 = 0，多流由 worker 注入 `DefaultSrcPort + i = 12345 + i`（`worker.go:308`）；目的端口恒 554（`chain_planner.go:1035`）。

**业务字段逐个列（rtsp 层 Fields 2 键，全关）**：

| 字段 | 开/关 | 理由 |
|---|---|---|
| `dialog` | **关** | 会话结构（消息数组），无动态形状；allowlist 无 `rtsp` 行 → 对象即 `layers[i](rtsp).dialog does not support dynamic`（实测） |
| `media` | **关** | 嵌套对象（端口/帧数/PT/帧长），对象即 `layers[i](rtsp).media does not support dynamic`（实测） |

→ **rtsp 无任何业务字段支持动态**（G-RTSP-3，A′ 候选，不冒充已覆盖）。

**序号算法实读**：`parseLayerDyn`（`layer_dyn.go:78`）/ `TupleGenerator.Next`（`tuple_generator.go`）/ 保底自增（`strategy_convert.go:49` `DefaultSrcPort = 12345` + `worker.go:308`）/ allowlist 白名单（`layer_dyn.go:17-19`）——**`rtsp` 无块**（`grep -n rtsp internal/core/layer_dyn.go` 零命中实测），即层内任何对象值 → `does not support dynamic`。**本协议存量 12 例无任何动态字段**（机读实测：12/12 的 `ip` 层 `src`/`dst` 均为字面字符串）。

## 13. 对接清单（T-RTSP 输入；正文落 testcase 文件）

12 ID（11 正 + 1 负）+ `packet_count`/锚词 + fixture 常量 + 双通道断言基线 + 存量审计（testcase §2–§5/§8 全量）。

**A′ 候选（按缺口分组）**：
- **方法面**（G-RTSP-10）：`rtsp_get_parameter` / `rtsp_set_parameter` / `rtsp_announce` / `rtsp_record` / `rtsp_redirect`（含 `direction:"down"` 推断）/ `rtsp_play_notify`。
- **状态码面**（G-RTSP-10）：`rtsp_status_454` / `rtsp_status_455` / `rtsp_status_unknown_code`（表外码空 reason）。
- **头面**（G-RTSP-4/G-RTSP-10）：`rtsp_rtp_info_auto`（**`emit_media` 挂 PLAY 响应**，本仓首例产出 RTP-Info）/ `rtsp_cseq_user_resync` / `rtsp_session_user_supplied` / `rtsp_transport_user_override` / `rtsp_content_length_user`。
- **媒体面**（G-RTSP-10）：`rtsp_media_multi_frame`（`frames>1`）/ `rtsp_media_payload_type` / `rtsp_media_frame_size` / `rtsp_media_ports` / `rtsp_media_up_direction` / `rtsp_media_file_source`。
- **载体面**（G-RTSP-10）：`rtsp_ipv6`（URI 方括号 + offset 74）/ `rtsp_mss_segmented`（长 body 跨 MSS）。
- **负例面**（G-RTSP-9）：`rtsp_neg_top_level_rtsp_subconfig`（presence 判死，**今日已通，会真红**）/ `rtsp_neg_empty_message`（静默路径转判死，需先修实现）/ `rtsp_neg_bad_direction`（同上）。
- **端口/流面**（G-RTSP-3/G-RTSP-11）：`rtsp_multi_flow`（`flow_control.flows=3`，断言 `tcp.srcport` ∈ {12345,12346,12347}）。

## 14. 缺口立项清单（有缺口写「缺口立项」，不许空着）

| 缺口 | 内容 | 去向 |
|---|---|---|
| **G-RTSP-1** | `RTSPMedia.SampleRate` 被解析（`strategy_convert.go:6576`）但**从不被消费**——RTP 时间戳恒 `ts += FrameSize`（`rtsp.go:831`），与采样率无关 | A′ 候选：要么消费（`ts += FrameSize * 90000 / SampleRate`）要么登记为死字段；今日**不得声称**时间戳符合 RFC 3550 §5.1 的时钟语义 |
| **G-RTSP-2** | **`[ip,tcp,rtsp]` 静默产 0 包**：`isRawIPChain`（`chain_planner_util.go:44-51`）对"带 tcp/udp 的链"返回 false → 走事件分支；但 `RTSPGenerator.GenEvents()` 返回 nil（`layer_gen.go:25`）→ 事件链无生产者 → `Plan` 返回 0 包、**无错误** | **代码阶段**：① 在 `isRawIPChain` 的 rtsp 分支加"即便链含 tcp 也走 raw"或在 `GenEvents` 返回显式错误；② A′ 补负例断言（今日建了会假绿）。**P4 不得只补用例不改代码** |
| **G-RTSP-3** | **端口动态完全不可达**：rtsp 层 registry 无 `src_port`/`dst_port` 键（`registry.go:1931-1936`）+ 链上不能放 tcp 层（G-RTSP-2）→ 非默认控制端口不可表达、端口动态五策略全不可用 | **代码阶段**裁定：① 在 rtsp 层 Fields 补端口 2 键（h323/mpls/ngap/telnet/sip/radius 六协议先例，`layer_dyn.go:60-80`）+ 补 allowlist；② 或**明确不解决**并登记。今日不得声称端口可配 |
| **G-RTSP-4** | **RTP-Info 自动生成路径零覆盖**：触发条件要求 `emit_media` 挂在 **PLAY 响应**上（`rtsp.go:550`），而存量两例（#8/#10）把 `emit_media` 挂在 **PLAY 请求**上（`dc.mediaEmitted` 已置真 → 响应被抑制）→ **今日无一例产出过 RTP-Info 头**。代码注释（`:20-22`）明写"为字节保真应挂在 PLAY 响应上"，与存量用例**相反** | A′ 补例 `rtsp_rtp_info_auto`（改挂响应）；**P4 必做**：改写 #8/#10 的 `expect.notes` 文案——它们声称"RTP-Info 头"由 legacy 生成，实测未生成 |
| **G-RTSP-5** | **cases JSON 断言过弱**：① #8/#10 **无 `packet_count`**（仅 `has_handshake`+`terminates`）→ 帧数漂移不被发现；② #3/#4/#6/#7/#9/#12 无 `fields`；③ #5 的 `notes` 算术错（写"=15"，实测 13）；④ **无一例断言 RTSP 文本内容**（`rtsp.*` 字段零使用、frames 零使用） | A′ 补断言（§13）；**P4 必做**：修 #5 `notes` 算术、给 #8/#10 补 `packet_count`（16/18） |
| **G-RTSP-6** | **结果产物不完整**：`trafficgen/docs/protocol-pcap-test/rtsp.md`（tracked）表内 11 条 `[pcap](rtsp/…)` 链接**全部悬空**——`docs/protocol-pcap-test/rtsp/` 目录**不存在**（0 个 pcap，`git ls-files` 实测 0 行）。**注意**：该文件末次提交 `ddfb40b`（2026-09-20）**晚于**判死提交 `0417be5`（2026-09-13）→ **不落入 pcep G-PCEP-11 的"过期产物"口径**，是**产物缺失**而非过期 | **代码阶段**（P5 重跑套件后补 pcap 留档）；本版**不删不改** tracked 产物；在此之前读者不得据表内链接访问 pcap |
| **G-RTSP-7** | **`rtsp.*` 专用字段零使用**：tshark 3.6.14 有 rtsp dissector（`rtsp.*` 字段可用），12 例全部只走 frames/通用 TCP 字段 | A′ 立项：收编 `rtsp.cseq` / `rtsp.session` / `rtsp.transport` / `rtsp.method` / `rtsp.status_code` 等字段断言；**收编前须先 `tshark -G fields` 实测字段名与进制**（igmp/ospf 臆造字段教训） |
| **G-RTSP-8** | **第三源未取到**：真实 QuickTime/VLC/live555 服务器的线字节本轮未抓包复核；`CASE_PCAP_MAPPING.md:261-273` 的九场景 pcap（`rtsp_1_1.pcap` 等）**未在本仓、未在本轮核对** | 待确认：抓 live555/ffmpeg 包对照，或逐条核对 `proto_rtsp.pcap`（`/home/pcap_auto/…/rtsp/proto_rtsp.pcap` 存在但本轮未解析）；确认前按实现钉、不声称合规 |
| **G-RTSP-9** | **静默路径 4 条**（§7.3）：空消息、非法 `direction`、`media` 无 `emit_media`、`RTSP==nil` 与空 dialog 同锚——前两条**不报错不产包**，与"配置错必须报错"纪律冲突；且 455 状态机拒绝**永不自动产出** | **代码阶段**裁定：空消息/非法 direction 改为 Validate 拒绝（或登记为合法容忍）；A′ 补负例（需先改实现，否则假绿） |
| **G-RTSP-10** | **用例面缺口**：方法 6/12、状态码 2/45、IPv6 0 例、跨 MSS 0 例、多帧媒体 0 例、`media` 参数（PT/FrameSize/端口/方向）0 例、`GET_PARAMETER` 保活 0 例、REDIRECT/PLAY_NOTIFY 字面 0 例 | A′ 补例（§13 分组清单） |
| **G-RTSP-11** | **多会话不可表达**：raw 链单连接，无 `sessions[]` 数组 → "并发多连接状态互不串"面**显式不适用**；多流只能走策略级 `flow_control`（存量 0 例） | A′ 补例 `rtsp_multi_flow`（`flow_control.flows=3`）；**多会话**记为**显式不适用**（链形态决定，非遗漏） |
| **G-RTSP-12** | **链路径不可复现**：`ssrc`/`seq`/`ts`/`clientSeq`/`serverSeq`/`ipID`/`Session` 全随机，且 raw 链**不注入 `spec.TCP`**（`layer_gen.go:36-47` 只搬 RTSP/IP/MAC/端口/TTL/Payload/FlowIndex）→ 唯一可复现入口 `spec.TCP.InitialSeq`（`rtsp.go:158-163`）**在链路径不可达** | **代码阶段**：把 `spec.TCP` 或 `initial_seq` 键透传进 `layer_gen.go` 的 spec 构造；A′ 补可复现用例。今日**不得声称**链路径可复现 |
| **G-RTSP-13** | **RTSP 2.0 不可表达**：版本串硬写 `RTSP/1.0`（`rtsp.go:303`/`:312`），无版本配置项；RFC 7826 只被借用了 `PLAY_NOTIFY` 的方向判定（`:671`） | A′ 候选或**明确不解决**（登记）；今日不得声称支持 RTSP 2.0 |
| **G-RTSP-14** | **RST 非正常结束零覆盖**（§3.15②后半）：全部正例恒 FIN 优雅终止（自建四次挥手），无 RST 用例 | A′ 补例（框架 tcp 层能力，本层零断言）——**注意**：本层自建 TCP，RST 需在生成器内构造，非框架能力，须先裁定 |
| **G-RTSP-15** | **游离顶层未知键无通用门**：`CheckProtoFlat("rtsp", {"layers":[…],"bogus":1})` 实测返回空串（不判死）；**顶层 `rtsp` 子映射 presence 已判死**（`rawWrapChains`，无缺口） | **P4 不建**该负例（建了会真绿 = 假通过）；等框架级 unknown-key 白名单（与 moxa G-MOXA-2 / opcua G-OPCUA-1 同款） |

## 15. 修订记录

- v1.0.0（2026-09-29，批次二文档车道）：**rtsp 首份设计契约**（无前序设计稿，§0 校正对象为结果产物 + 映射表 + 死引用三源）。as-built 逆向定稿：12 项基线校正（含 3 项实测反转/新发现——`notes` 算术错、`rtsp/` 目录 0 pcap、`Direction` 恒 `"up"`）；线格式逐字段到字节偏移（§3）；状态机按 RFC 附录 A 列表 + as-built 诚实声明（生成器**不执法**，§5.2）；五件套强制展开含**流关联（有派生媒体流）**（§12.3）；§12.1/§12.12 强制展开；规范矩阵八项 + 子表①②③（36 格 / 45 行 / 17 行，逐格重数闭合）；**本车道今日实跑 12/12 PASS**（离线链套件，临时空导入已回滚，零 `.go` 改动）；缺口 **G-RTSP-1…G-RTSP-15**。自审 2 轮，末轮干净。
