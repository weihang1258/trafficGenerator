# #120 http_flv（HTTP-FLV · HTTP/1.1 GET 承载 FLV 字节流）设计契约

> 版本：v1.0.0（批次二 as-built 文档轨；修订记录见 §15）
> 日期：2026-09-29
> 车道：文档车道（http_flv 续号 120）
> 旧基线：`docs/protocol-designs/45-http-flv-design.md` v3.0.0（2026-08-24，同协议旧稿）+ `45-http-flv-testcase.md` v3.0.0。**沿革见 §0**——45 号是同一协议的旧稿，本 #120 为 as-built 重做，**承其 FLV 线格式与层链模型，不搬其过时结论与错误断言**。
> 存量用例：`trafficgen/test/protocol_pcap/cases/http_flv.json`（**15 例，机读实测**；ID/顺序/包数/断言以它为准，本文逐条对齐）
> 规范基线：① Adobe **Video File Format Specification v10.1**（FLV 容器：FLV Header / Tag / PreviousTagSize，下称 **spec**）；② Adobe **Action Message Format 0 (AMF0) Specification**（script tag 元数据）；③ **RFC 9112**（HTTP/1.1 消息语法）+ **RFC 9110**（HTTP 语义）；④ ISO/IEC 14496-15（AVC/AVCDecoderConfigurationRecord）与 ISO/IEC 14496-3（AAC/AudioSpecificConfig）**结构边界**（不解码）；⑤ 本仓库落码（`internal/protocol/http_flv/` 三文件 + `internal/protocol/http/layer_gen.go` 变换器，§11）；⑥ 本机 tshark 3.6.14 字段表与 15 例实测 pcap（`/tmp/mcp-pcaps/http_flv/`，**2026-09-29 本车道复跑**，包数/偏移的唯一权威）。
> 白话一句：**HTTP-FLV 就是"用 HTTP 下载一个永不结束的文件"——客户端发一句 `GET /live/xxx.flv`，服务端回 `200` + `Content-Type: video/x-flv`，然后在这个 HTTP 响应体里一直灌 FLV 数据块（先 9 字节文件头，再一个个"标签"：脚本标签放元数据、音频标签放声音、视频标签放画面）。**

## 0. 45→120 沿革与旧稿校正声明（门1 必答：基线继承关系）

本 #120 与 `45-http-flv-*` 是**同一协议的续号契约**，不是新协议。旧稿保留在磁盘只读参考。逐条给出校正结论（区分"承旧稿"与"旧稿过时"）：

| # | 旧稿说法（45-*） | HEAD 实测（2026-09-29） | 校正结论 |
|---|---|---|---|
| 1 | design 10 章、testcase 8 章；无沿革章、无门1 十四行表、无 P1 规范矩阵、无动态清单、无五件套、无缺口清单、无覆盖反查门建议行 | — | **结构缺口**，本版按 §10/§12/§6/§12.3/§14/§9 补齐 |
| 2 | 引用配套 JSON 为 `cases/http-flv.json`（**连字符**） | 磁盘实际文件名 = `cases/http_flv.json`（**下划线**，`ls` 实测）；全仓无 `http-flv.json` | **旧稿文件名错**（死引用）；本版按实测文件名 |
| 3 | §2 表："HTTP request/response 起点 54（IPv4）/74（IPv6）"；§1 testcase "FLV 起点 IPv4 119、IPv6 139" | 实测 **HTTP 头起点确为 54/74**（正确），但 **FLV 起点不是 119/139**：`Content-Length` 头长度随 FLV body 长度**逐例变化**，实测 FLV 起点 ∈ {139, 140, 145, 160}（§3.4 表） | **旧稿把 FLV 起点写死为常数**（错）；本版 §3.4 给出"FLV 起点 = HTTP 头长 + 54"的可复算公式 + 逐例实测值 |
| 4 | §1 testcase：response header "长度为 65，因此 FLV 起点为 IPv4 119" | 实测 200 响应头 **85–91 字节**（固定部分 66 + `Content-Length` 行 17+位数 + `Connection` 值差 0/5；86 为 close 且 CL 三位数时的常见值），**不是 65** | **旧稿 header 长度算错 21 字节**；本版 §3.1 按代码 `buildHTTPFlvResponse` 逐行复算 |
| 5 | §9 表：15 例 = 12 正 + 3 负，ID 与顺序如下表 | 存量 15 例 **ID 集合与顺序逐条一致**（机读实测）；包数 9×11 + 11×1 | **旧稿 ID 表正确**（承之）；本版 §9 逐条钉包数 |
| 6 | §3.4："示例首字节 0xa0：SoundFormat=10、SoundRate=3（44kHz）、SoundSize=1（16-bit）、SoundType=0（mono）" | 代码 `builder.go:250` 实际写 **0xa5**（`byte(audioAAC<<4) \| 0x05` = 0xa0 \| SoundRate=1(22kHz) \| 16-bit \| **stereo**）；实测音频 tag data 首字节 **`a5`** | **旧稿注释与实际编码不符**（mono/44kHz vs stereo/22kHz）；本版 §3.6 按代码 + 实测钉 |
| 7 | §8 "已完成"6 条完成定义（层注册/HTTP 状态机/DataSize 边界/重组/负例传播/字段断言） | 层注册 ✓、HTTP 变换器 ✓、负例传播 ✓（3 例实测 0 帧）；但"DataSize 边界有断言"**不成立**（#8 断言的是 HTTP 头，非 DataSize，§9.2） | **旧稿完成定义有虚项**；本版 §9 逐条按实测重钉 |
| 8 | §6 错误表 8 行（HTTP method/response/FLV signature/tag header/PreviousTagSize/AAC-AVC/sessions/地址族） | 代码实际只有 **3 个拒绝分支**（`planner.go:80/83/91`：flags 保留位 / rounds 负 / tag 类型未知）；表内其余 5 行**无对应实现** | **旧稿错误表 5/8 行是设计意图，未落码**；本版 §7 按代码钉 3 分支，余项列缺口 |
| 9 | §5："`WireFault` 只允许测试注入"；§9 表 13 例名 `http_flv_neg_truncated_tag` "HTTP/FLV body 截断" | `WireFault` 字段**已落码**（`builder.go:214`，值 `"truncated"` 截尾 5 字节）但**存量 15 例零使用**（机读实测）；#13 实际注入的是 **tag 类型 `"unknown"`**，锚词 `tag` | **旧稿"截断"语义与实际用例不符**（实际是未知 tag 类型）；本版 §7/§9.3 按实测钉，`wire_fault` 列为未覆盖分支 |
| 10 | §3.3 script tag："允许配置 width/height/framerate/…；**键的出现顺序必须按配置保持**" | 代码 `resolveTag` 的 script 分支**忽略 `t.Data` 为空时的任何用户元数据**，恒产**固定 6 键**（width 1280 / height 720 / framerate 25 / videocodecid 7 / audiocodecid 10 / duration 0）；**无任何配置入口可改这 6 键或顺序** | **旧稿"可配置元数据"未实现**；本版 §3.5 按代码钉（唯一自定义入口是 `Data` 非空时整块原样透传，绕过 AMF0 编码） |
| 11 | §3.2："`PreviousTagSize` 必须等于前一个 tag 的完整线上长度" | 代码 `buildFLVTag:63` 恒写 `11 + len(data)` ✓（**是当前 tag 自身长度**，与 spec "PreviousTagSize = 前一 tag 总长"等价——因为写入位置在该 tag 之后）；**注意**：首个 tag 的 PreviousTagSize 正确，但 **Header 后的 `PreviousTagSize0` 恒 0**（`builder.go:206`）✓ 合 spec | **旧稿正确**（承之）；本版 §3.3 给出字节偏移 |
| 12 | §8 实现集成点 2："`core/types.go` 增加 `HTTPFLVConfig`（**types.go:201**）"；6："**registry.go:223**" | 实测 `HTTPFLVConfig` 在 `types.go:337`、`FLVTag` 在 `types.go:345`、`FlowSpec.HTTPFLV` 槽位在 `types.go:1710`；registry 行在 `registry.go:570` | **旧稿行号全过时**（代码演进）；本版 §11 按实测行号 |
| 13 | §5："默认模板（Flags=0x05, Tags=[…], Rounds=1）在 chain_planner translateTerminalConfig 中应用" | 实测：`chain_planner_translate.go:789-806` **确有该默认模板**，但**该块对层内配置只补默认值、不搬运用户值**（§11.7 详述）；用户配置的真实入口是**顶层 `http_flv` 子映射**（`strategy_convert.go:832`） | **旧稿表述方向正确但不完整**；本版 §11.7 把"哪条路活着"写清（**本协议核心缺口 G-HTTPFLV-1**） |
| 14 | §1："http_flv 层已注册为 Category=Terminal、DependsOn=http" | 实测 `registry.go:570`：`Category: CategoryTerminal`、`DependsOn: []string{"http"}`、**Fields 4 键**（flags/rounds/tags/wire_fault）、`FieldContract {"tcp.dst_port":"80"}` | **旧稿正确**（承之）；本版 §11.1 补 Fields/FieldContract 细节 |
| 15 | testcase §1："验证优先使用 tshark 已注册的 HTTP/TCP/IP 字段：…`http.connection`、`tcp.stream`、`ip.version`" | 实测 15 例**只用 6 个去重字段名**（`tcp.dstport` / `http.request.method` / `http.request.uri` / `http.response.code` / `http.content_type` / `ipv6.nxt`）；`http.connection`/`tcp.stream`/`ip.version` **零使用** | **旧稿"优先使用"是意图非事实**；本版 §1 按实测列今日字段面 |
| 16 | testcase §6 覆盖清单 8 行"当前状态 = 已实现" | 实测 8 行中 **"空/最小/24-bit 边界 tag" 与 "IPv4/IPv6" 两行断言不成立**（§9.2）；其余 6 行成立 | **旧稿覆盖清单 2/8 行虚报**；本版 §9.2 逐条按实测重钉 |

**依赖链判定纪律**：以上均为可判题（旧文 → 代码/pcap 三级对照），直接判定，不问偏好。不可判的（Adobe spec v10.1 的 AMF0 键序强制力、`Content-Length` 在直播场景的合 spec 性）标"待确认"并写清确认方式（G-HTTPFLV-8）。

**产物过期登记（G-HTTPFLV-9）**：`trafficgen/docs/protocol-pcap-test/http_flv.md`（**tracked 结果产物**，`git ls-files` 可证）写 "Cases: 15 — pass 15, fail 0, error 0"，但该文件**末次提交 `e7e7d1c`（2026-08-27）**，**早于**判死提交 `0417be5`（2026-09-13，扁平判死泛化全协议 `CheckProtoFlat`）；且 `docs/protocol-pcap-test/http_flv/` 目录**不存在（0 个 pcap 文件）**——文档内 15 条 `[pcap](http_flv/….pcap)` 链接**全部是死链**。**该结果文档是过期产物**。本车道**今日已复跑**该套件（§9.4 实测证据），15/15 数字**今日成立**，但**过期产物本身不得作为"今日已复跑"依据**——今日证据是本次复跑的 `/tmp/mcp-pcaps/http_flv/`。

**http_flv 特殊性（须写清，不得夸大）**：
1. **http_flv 是 http 族协议**（http 是 8 个协议的底座：http/http_flv/hls/hds/gbt/getwork/cwmp/doh/onvif，见 `CheckProtoFlat` 白名单 `strategy_convert.go:8643`）。与 http 层的关系是**变换器契约**（不是透传）：http_flv 终结层只产 FLV body 字节事件（down 方向），http 层作为 `EventTransformer`（`registry.go:104` `TransformEvents: true`）把每个 body 包成 **GET 请求 + 200 响应** 一对。registry 的 `DependsOn` 是 **`["http"]`**（单值），http 再 `DependsOn ["tcp"]`，链自动补全为 `[ip, tcp, http, http_flv]`。
2. **长连接流式**：HTTP 响应 body 持续推送 FLV tag，**不是一次性响应**。本实现的"流式"以 `rounds` 表达（每轮一个 FLV body + 一对 GET/200），**不是**无限推送；`Content-Length` 每轮按 body 实际长度写出（§3.1 诚实边界）。

## 1. 范围、profile 与实现状态边界

本版定义 **HTTP-FLV（Adobe FLV 容器承载于 HTTP/1.1 GET 响应体）** 的流量生成：TCP 建连 → HTTP GET → 200 + `video/x-flv` → FLV header + tag 序列 → TCP 挥手。

| profile | 承载 | 本版允许内容 | 不从 profile 推导 |
|---|---|---|---|
| `http_flv_http1_v1`（主） | TCP，fixture 80 | GET/200 对 ×`rounds` + FLV header + tag 序列 | 真实流媒体服务器语义（码率/时钟同步） |
| `http_flv_ipv6_v1` | 同上，仅外层 IPv6 | 同上（FLV 字节完全相同） | 从 IPv4 fixture 推导 IPv6 地址 |

显式边界（"不实现、不声称、不许静默转换"）：① 不实现 HTTPS/TLS（`tls→tcp→http→http_flv` 链不在本版）；② 不实现 HTTP/2、HTTP/3、WebSocket-FLV、RTMP；③ 不实现 chunked transfer coding 重组（本实现恒写 `Content-Length`）；④ 不解码 SPS/PPS/AVCDecoderConfigurationRecord、不解码 AudioSpecificConfig——只搬运配置字节；⑤ 不实现 AMF3、不实现 FLV 的加密 tag（Filter 位）；⑥ **不声称**无限直播推送——"流式"由 `rounds` 计数表达；⑦ **不声称**多会话/多流的状态隔离有实现（§5 诚实声明）。

**实现状态（2026-09-29 实测）**：`http_flv` 层已注册（`registry.go:570`，`CategoryTerminal`，`DependsOn ["http"]`，Fields 4 键，FieldContract `tcp.dst_port=80`）；终结层生成器 + 校验器已落码（`internal/protocol/http_flv/planner.go:71-95`）；FLV 字节构造已落码（`builder.go`，258 行）；http 层变换器已落码（`internal/protocol/http/layer_gen.go:131-265`）；`allowedProtocols["http_flv"]=true`（`protocols.go:43`）；`main.go:491` `NewChainPlanner("http_flv")` + `:55` 空白导入；15 语义用例已落 `cases/http_flv.json`，**今日复跑 15/15 绿**（§9.4）。

**输出契约（pcap/NIC 双输出）**：两路径共用同一 cases JSON 与断言集（`tcp.dstport`、`http.request.method/uri`、`http.response.code`、`http.content_type`、`ipv6.nxt`、frame 原始 hex）；NIC 经 tcpdump 捕获（`nic_capture` 用例级开关）；不设仅单路径可用的断言。**本协议 15 例今日只走 pcap 路径**（离线套件），NIC 路径未复跑（G-HTTPFLV-10）。

## 2. 协议栈、端口和固定偏移

推荐层链为 `[ip, tcp, http, http_flv]`（引擎自动补 `ip`；http_flv `DependsOn ["http"]` → http `DependsOn ["tcp"]`）。http_flv 只产 FLV body 字节事件，**HTTP 帧与 TCP 分段/握手挥手分别由 http 层与 tcp 层负责**。

端口：http 族默认 **TCP 80**（`registry.go:570` `FieldContract {"tcp.dst_port":"80"}`，经通用契约块 `chain_planner.go:715` 补齐；http_flv **不在** `validateSpecBase` 的 DstPort switch 内，走契约路径）。fixture 统一 `dst_port=80`；存量 15 例**均未显式写 `tcp.dst_port`**（机读实测），由契约补齐。

固定偏移（无 VLAN/IP options/TCP options）：

| 承载 | Ethernet+IP+TCP | HTTP 起点 | FLV 起点 |
|---|---:|---:|---|
| TCP/IPv4 | 14+20+20 = **54** | **54** | **54 + HTTP 响应头长**（逐例可复算，§3.4） |
| TCP/IPv6 | 14+40+20 = **74** | **74** | **74 + HTTP 响应头长** |

**HTTP 头长 = 83 + digits(`Content-Length`)（close）/ 88 + digits(...)（keep-alive）**（`buildHTTPFlvResponse`，`layer_gen.go:249-263`；逐行复算见 §3.1），故 body ≥ 100 字节且 `Connection: close` 时 **FLV 起点 = 54+86 = 140（IPv4）/ 74+86 = 160（IPv6）**；body < 100 字节时少 1（139）；`keep-alive` 轮次多 5（145）。逐例实测值见 §3.4。

目标形状 spec_json 样例（严格层链形，顶层仅 `layers`）：

```json
{
  "layers": [
    {"ip": {"src": "192.0.2.10", "dst": "198.51.100.20"}},
    {"http": {"method": "GET", "uri": "/live/test.flv", "version": "HTTP/1.1"}},
    {"http_flv": {"flags": 5, "rounds": 2, "tags": [{"type": "script", "timestamp": 0}]}}
  ]
}
```

> **今日该样例不可用**：`http_flv` 层内配置**不被解码**（`translateTerminalConfig` 的 `switch term.Name` 无 `case "http_flv"`，§11.7）；能生效的配置载体是**顶层 `http_flv` 子映射**（`strategy_convert.go:832`）——见 §12.1 与缺口 G-HTTPFLV-1。

多流样例（数量只走 `flow_control`；本协议存量未用）：

```json
{
  "layers": [
    {"ip": {"src": "192.0.2.10", "dst": "198.51.100.20"}},
    {"http": {"method": "GET", "uri": "/live/test.flv"}},
    {"http_flv": {}}
  ],
  "http_flv": {"rounds": 3},
  "flow_control": {"flows": 3}
}
```

## 3. 线格式编码（按代码 + 实测钉）

### 3.1 HTTP/1.1 帧（由 http 层变换器产出）

**请求**（`buildHTTPFlvGetRequest`，`layer_gen.go:234-245`）：

```text
GET /live/test.flv HTTP/1.1\r\n
Host: 198.51.100.20\r\n
Connection: keep-alive|close\r\n
\r\n
```

`method`/`uri`/`version` 从 **http 层 config** 读（`layerConfigString`，`layer_gen.go:267`）；缺省 `GET` / `/live/stream.flv` / `HTTP/1.1`；裸版本号（`"1.1"`）归一为 `HTTP/1.1`（`layer_gen.go:171-176`）。`Host` = `req.Meta.DstIP`（IPv6 用 `bracketHost` 加方括号）。

**响应**（`buildHTTPFlvResponse`，`layer_gen.go:249-263`）：

```text
HTTP/1.1 200 OK\r\n
Content-Type: video/x-flv\r\n
Content-Length: <len(flvBody)>\r\n
Connection: keep-alive|close\r\n
\r\n
<flvBody 字节>
```

**响应头长度复算**（逐行，实测）：固定部分（不含 `Content-Length` 值、`Connection: close`）= `"HTTP/1.1 200 OK\r\n"`(17) + `"Content-Type: video/x-flv\r\n"`(28) + `"Connection: close\r\n"`(19) + `"\r\n"`(2) = **66**；加 `"Content-Length: N\r\n"`（`17 + digits(N)`）→ **头长 = 83 + digits(N)（close）/ 88 + digits(N)（keep-alive）**。

| 用例 / 轮次 | body 长度 | `Content-Length` | `Connection` | 头长 | 实测 |
|---|---:|---:|---|---:|---|
| `get_header` 等 11 例 | 240 | `249`（3 位） | close | **86** | ✓ |
| `tag_boundary` | 58 | `67`（2 位） | close | **85** | ✓ |
| `keep_alive` 帧 5（第 1 轮） | 240 | `249`（3 位） | **keep-alive** | **91** | ✓ |
| `keep_alive` 帧 7（第 2 轮） | 240 | `249`（3 位） | close | **86** | ✓ |
| `ipv6` 帧 5 | 240 | `249`（3 位） | close | **86** | ✓ |

> 旧稿"恒 65"（§0 #4）**错**——65 是**不含 `Content-Length` 行、且 `Connection: close`** 的固定部分，不是完整头长。**`Connection` 值长度也不同**（`keep-alive` 比 `close` 长 5 字节），故头长逐例可复算、**不得硬编码**。

**Connection 语义**（`layer_gen.go:186`）：`keepAlive := i < rounds-1` —— **仅最后一轮写 `close`**，其余写 `keep-alive`。实测 `http_flv_keep_alive`（rounds=2）：帧 4/5 = `keep-alive`、帧 6/7 = `close` ✓。

**诚实边界**：本实现**恒写 `Content-Length`**，是"有限点播 fixture"形态；真实 HTTP-FLV 直播响应通常省略 `Content-Length` 并持续推送。本版**不声称**覆盖真实直播的长连接语义（§1 边界⑥、G-HTTPFLV-4）。

### 3.2 FLV Header（9 字节，承 45 稿审计通过）

`buildFLVHeader`（`builder.go:46-53`），全字段 **big-endian**：

| 偏移 | 长度 | 字段 | 本实现取值 | 实测 hex |
|---:|---:|---|---|---|
| 0 | 3 | Signature | ASCII `FLV` | `46 4c 56` |
| 3 | 1 | Version | `0x01`（`flvVersion`，`builder.go:14`） | `01` |
| 4 | 1 | Flags | `flvFlags(c)`：配置值，**缺省 0x05**（audio bit2 `0x04` \| video bit0 `0x01`） | `05` / `01` |
| 5 | 4 | DataOffset | UI32 = `9`（`flvDataOffset`，`builder.go:15`） | `00 00 00 09` |

紧随其后 4 字节 **`PreviousTagSize0` = `00 00 00 00`**（`builder.go:206` 字面量 `0,0,0,0`），合 spec（header 之前无 tag）。

**总长 = 13 字节**（9 + 4），由单测 `TestBuildFLVBody_DefaultConfig` 钉死（`http_flv_test.go:173`：空 body 长度 = 13）。

**Flags 校验**（`planner.go:79-80`）：`Flags & 0x05 != Flags` 即拒，锚词 **`reserved bits`**。合法值仅 `0x00/0x01/0x04/0x05`（单测 `TestValidator_FlagsValid`，`http_flv_test.go:458`）。

### 3.3 FLV Tag（11 字节 Tag Header + Data + 4 字节 PreviousTagSize）

`buildFLVTag`（`builder.go:58-81`）：

| 相对偏移 | 长度 | 字段 | 编码 |
|---:|---:|---|---|
| 0 | 1 | TagType | `8`=audio（`0x08`）/ `9`=video（`0x09`）/ `18`=script（`0x12`） |
| 1 | 3 | DataSize | UI24 BE = `len(data)`（可被 `DataSizeOverride` 覆盖，负例注入） |
| 4 | 3 | TimestampLower | UI24 BE = `timestamp & 0x00ffffff` |
| 7 | 1 | TimestampExtended | `timestamp >> 24` |
| 8 | 3 | StreamID | **恒 `00 00 00`**（`builder.go:77` 字面量） |
| 11 | DataSize | Data | tag 载荷 |
| 11+DataSize | 4 | PreviousTagSize | UI32 BE = `11 + len(data)`（可被 `PreviousSizeOverride` 覆盖） |

**总长公式 = `15 + DataSize`**（11 + DataSize + 4）。单测 `TestBuildFLVTag`（`http_flv_test.go:39-65`）钉：DataSize=4 → PreviousTagSize=15 → 总长 19 ✓。

**Timestamp 语义**：32-bit 毫秒值，按 `TimestampExtended << 24 | TimestampLower` 拆分（spec 定义）。存量 15 例**全部 timestamp=0**（机读实测）。

**StreamID 恒 0**：本实现无多 stream 概念（§5）。

### 3.4 FLV 起点（逐例实测，非固定常数）

`http_flv` 的 body 事件起点 = **HTTP 响应头结束位置** = 54（IPv4）/74（IPv6）+ 响应头长（86 或 88，§3.1）。

| 用例 | 实测 FLV 起点 | 响应头长 | 说明 |
|---|---:|---:|---|
| 多数 IPv4 例（body 240B，`Content-Length: 249`，close） | **140** | 86 | `249` 是 3 位数 |
| `http_flv_tag_boundary`（body 58B，`Content-Length: 67`，close） | **139** | 85 | body < 100 → CL 2 位数 |
| `http_flv_keep_alive` 帧 5（第 1 轮，`keep-alive`） | **145** | 91 | keep-alive 比 close 长 5 字节 |
| `http_flv_keep_alive` 帧 7（第 2 轮，`close`） | **140** | 86 | 同多数例 |
| `http_flv_ipv6` | **160** | 86 | 74 + 86 |

> **实测注**：FLV 起点**逐例可复算 = 载体起点（54/74）+ 响应头长**，而头长随 `Content-Length` 位数与 `Connection` 值变化，**不得硬编码**（旧稿 §2/§1 的 119/139 已作废，§0 #3/#4）。

### 3.5 Script Tag（TagType=18）

`resolveTag` 的 `"script"` 分支（`builder.go:226-248`），**两种路径**：

1. **`Data` 非空** → **原样透传**（`return tagScript, t.Data, nil`）。调用方须自备合法 AMF0 字节；生成器**不做任何校验**（诚实边界：可传非法 AMF0，不报错）。
2. **`Data` 为空** → 生成**固定 6 键** onMetaData：

```text
AMF0 String("onMetaData")           02 00 0a "onMetaData"
AMF0 ECMAArray (count=6)            08 00 00 00 06
  "width"          Number 1280.0    00 05 "width"  00 <f64 BE>
  "height"         Number 720.0     00 06 "height" 00 <f64 BE>
  "framerate"      Number 25.0      00 09 "framerate" ...
  "videocodecid"   Number 7.0       00 0c "videocodecid" ...
  "audiocodecid"   Number 10.0      00 0c "audiocodecid" ...
  "duration"       Number 0.0       00 08 "duration" ...
ECMAArray 结束                      00 00 09
```

实测（`http_flv_script_tag` 帧 5）：`02 00 0a 6f 6e 4d 65 74 61 44 61 74 61 08 00 00 00 06 00 05 77 69 64 74 68 …` ✓。

**长度公式**（逐项可复算，实测 DataSize = **139**）：

| 组成 | 字节 | 复算 |
|---|---:|---|
| AMF0 String `"onMetaData"` | 13 | `1`(marker 0x02) + `2`(UI16 len) + `10` |
| ECMAArray 头 | 5 | `1`(marker 0x08) + `4`(UI32 count=6) |
| 6 个键值对 | 118 | Σ(`2`(UI16 key_len) + `len(key)` + `1`(marker 0x00) + `8`(f64)) = 16+17+20+23+23+19 |
| ECMAArray 尾 | 3 | `00 00 09` |
| **合计** | **139** | ✓ 与实测 DataSize 一致 |

**AMF0 编码函数**：`buildAMF0String`（marker `0x02` + UI16 len + bytes，`builder.go:86`）、`buildAMF0ECMAArray`（marker `0x08` + UI32 count + 逐键值 + `00 00 09`，`builder.go:97-128`）、`buildAMF0Number`（marker `0x00` + f64 BE，`builder.go:137`）、`buildAMF0Bool`（marker `0x01` + 1 字节，`builder.go:144`）。ECMAArray 值分派支持 string / 数值 / bool / nil / `[]byte`（按 string 编码）（`builder.go:107-123`）。

**诚实边界（G-HTTPFLV-2）**：① 6 个元数据键**写死**，**无配置入口**可改键、值或顺序（旧稿 §3.3 "键的出现顺序必须按配置保持" 未实现，§0 #10）；② `buildAMF0Number`/`buildAMF0Bool`/`buildAMF0String` 的**唯一调用方是 `buildAMF0ECMAArray`**，而 `buildAMF0ECMAArray` 的**唯一调用方是 `resolveTag` script 分支**——即**这三个函数仅在硬编码 6 键路径上被触达**，`Data` 非空路径完全绕过它们。

### 3.6 Audio Tag（TagType=8）

`resolveTag` 的 `"audio"` 分支（`builder.go:249-252`）：data = `[first_byte, 0x00] + t.Data`。

- `first_byte = byte(10<<4) | 0x05` = `0xa5`（`builder.go:250`）。按 Adobe spec 位域：SoundFormat=**10**(AAC) \| SoundRate=**1**(22 kHz) \| SoundSize=**1**(16-bit) \| SoundType=**1**(stereo)。
- 第 2 字节 `0x00` = **AACPacketType = 0**（sequence header）。
- 其后 `t.Data` 为用户配置字节（fixture 用 `11 90` = AudioSpecificConfig：AAC-LC / 44.1 kHz / 立体声）。

实测（`http_flv_audio_aac`）：tag type=8、DataSize=**4**（2 + 2）、data = `a5 00 11 90`。

**诚实边界**：① SoundRate/SoundSize/SoundType **写死为 0x05**，无配置入口；② AACPacketType **写死为 0**（sequence header），**raw AAC（type=1）不可达**；③ `buildAudioAACData`（`builder.go:173-188`）是**死代码**——其 `if/else if` 链把 `first` 原样赋回自身（`builder.go:174-185`），无任何生产调用方（`grep` 实测：非测试调用点 0 处）。旧稿 §3.4 的"示例首字节 0xa0 mono/44kHz"与代码不符（§0 #6）。

### 3.7 Video Tag（TagType=9）

`resolveTag` 的 `"video"` 分支（`builder.go:253-255`）：data = `[0x17, 0x00, 0x00, 0x00, 0x00] + t.Data`。

- `0x17` = FrameType(4bit)=**1**(keyframe) \| CodecID(4bit)=**7**(AVC/H.264)。
- 第 2 字节 `0x00` = **AVCPacketType = 0**（sequence header）。
- 第 3–5 字节 `00 00 00` = **CompositionTime** = 0（signed 24-bit BE）。
- 其后 `t.Data` = AVCDecoderConfigurationRecord 字节（fixture 用 `01 42 00 1e ff e1 00 1c 67 42 …`）。

实测（`http_flv_video_avc`）：tag type=9、DataSize=**48**（5 + 43）、data 头 = `17 00 00 00 00 01 42 00 1e …`。

**诚实边界**：① FrameType **写死 1**（keyframe）——**inter frame（2）不可达**；② AVCPacketType **写死 0**——**NALU（1）与 end-of-sequence（2）不可达**；③ CompositionTime **写死 0**；④ `buildVideoAVCData`（`builder.go:193-198`）**死代码**（无生产调用方，`grep` 实测 0 处）。

### 3.8 装配与负例注入

`buildFLVBody`（`builder.go:204-221`）：`FLV header(9)` + `PreviousTagSize0(4)` + 逐 tag（按 `c.Tags` 顺序）。

**`wire_fault = "truncated"`**（`builder.go:214-219`）：body 长度 ≤ 16 时报错（锚词 `truncated`）；否则**截去末尾 5 字节**。**存量 15 例零使用**（机读实测，§0 #9）→ 未覆盖分支（G-HTTPFLV-3）。

**负例注入字段**：`DataSizeOverride`（`*uint32`，覆盖 TagHeader 的 DataSize）、`PreviousSizeOverride`（`*uint32`，覆盖 PreviousTagSize）——`buildFLVTag:59-66`。存量**仅 #8 使用 `data_size_override`**（值 65536）；`previous_size_override` **零使用**（G-HTTPFLV-3）。

## 4. 业务场景分析（现网典型场景与五层覆盖）

**定性**：**声明式剧本回放**——配置声明 FLV tag 清单与轮数，引擎按固定剧本产出事件序列（GET → FLV body → 200），http 层变换、tcp 层分段与握手挥手。

| 现网场景 | 事务交互 | 对应用例 |
|---|---|---|
| ① 直播拉流（单次 GET） | GET → 200 + FLV header + 三标签 | #1–#8（rounds=1 的 11 个正例） |
| ② 点播/短连 | 同上，连接随后关闭 | 全正例（`Connection: close` 末轮） |
| ③ 同连接多段拉流 | rounds=2 → 两对 GET/200 | #9（`http_flv_keep_alive`） |
| ④ IPv6 产线 | 同上，仅外层 IPv6 | #11（`http_flv_ipv6`） |
| ⑤ 多客户端并发 | 多 TCP 会话 | #10（`http_flv_multi_session`）、#12（`http_flv_multi_stream`）— **但见 §5 诚实声明** |
| ⑥ 畸形流拒绝 | 配置非法 → 任务失败 | #13/#14/#15 |

**五层覆盖逐层结论**：
- **功能层**：FLV header/tag 三类型正例 + 3 类拒绝分支负例（§7）。
- **性能层**：最小帧（`get_header` 9 帧基线）、多轮序列（`keep_alive` 11 帧）、**大 tag 边界**（`tag_boundary` DataSize=65536，**声明值非实际分配**，§9.2）；**帧长上界**见 §6。
- **数据场景层**：FLV header flags 三取值（0x01/0x05）、tag 三类型、空 tag（DataSize=0 语义**未实现**，§9.2）、DataSizeOverride 边界、AMF0/AAC/AVC 三种编码形态。
- **地址与流层**：IPv4（#1–#10、#12）与 IPv6（#11）独立用例；单流基线；**多会话（#10/#12）**——但**实现为单会话**（§5 诚实声明）；**流关联（控制流派生数据流）显式不适用**：HTTP-FLV 是单连接单向推送，无副连接。
- **业务层**：六场景中 ①–④⑥ 有落点；⑤ 名义有落点但**语义不成立**（§5）。

**次要合法行为显式不适用声明（不设正例、亦不得进负例）**：① HTTPS/TLS 承载（§1 边界①）；② chunked transfer coding（恒写 Content-Length）；③ 真实无限直播推送（`rounds` 有限）；④ AMF3 / FLV 加密 tag；⑤ SPS/PPS/AudioSpecificConfig 解码（只搬运）。

## 5. 消息/事务模型与状态机

**事务定义**：一次 `GET` + 一次 `200`（含一个 FLV body）。**多事务** = 一个连接内 `rounds` 对按序执行（#9 两对）。

**事件序**（`HTTPFLVGenerator.Generate`，`planner.go:28-58` + `generateHTTPFLVTransformer`，`layer_gen.go:131-211`）：

```text
[生产者] http_flv 生成器：每轮产 1 个 FLV body 事件（Up=false，down 方向）
            ↓ transformCh
[变换器] http 生成器（每轮）：GET(up) → 读 1 个 body 事件 → 200(down)
            ↓
[承载]   tcp 层：握手 3 包 + 分段 + 挥手 4 包
```

**实测帧位**（`http_flv_get_header`，9 帧）：1–3 TCP 握手（SYN/SYN-ACK/ACK）→ 4 GET（up）→ 5 200+FLV（down）→ 6–9 FIN 四包。`keep_alive`（rounds=2，11 帧）：1–3 握手 → 4 GET → 5 200 → 6 GET → 7 200 → 8–11 FIN 四包 ✓。

**包数公式**：单流 = 3（握手）+ 2×rounds（GET/200 对）+ 4（FIN 四包）= **7 + 2×rounds**。
校验：rounds=1 → 9 ✓（11 例）；rounds=2 → 11 ✓（#9）。**12/12 正例与实测 pcap 逐例一致**（§9.4）。

**http_flv 层无自有状态机**：握手/挥手/分段在 tcp 层；FLV tag 序列是"按配置顺序翻译"的纯函数；`rounds` 循环在 http 变换器（`layer_gen.go:183`）。

**自动派生规则**：① `Flags` 缺省 → `0x05`（`builder.go:38-43` `flvFlags`）；② `Tags` 缺省 → **script(onMetaData 6 键) + audio(AAC seq header `11 90`) + video(AVC seq header 43B)** 三标签模板（`chain_planner_translate.go:797-803`）；③ `Rounds` 缺省 → `1`（`chain_planner_translate.go:804`；`planner.go:37-40` 同款兜底）；④ `Content-Type: video/x-flv` 与 `Content-Length` 由 http 变换器自动补（`layer_gen.go:253-254`）；⑤ `Connection` 由轮次自动决定（末轮 close）；⑥ TCP 握手/FIN 由 tcp 层自动补。

**多会话诚实声明（G-HTTPFLV-5）**：`HTTPFLVConfig` **无 `sessions`/`streams` 字段**（`types.go:337-343`）；`Generate` 只按 `rounds` 循环（`planner.go:43`）。存量 #10 `http_flv_multi_session` 与 #12 `http_flv_multi_stream` 的 `spec_json` **与 #1 完全相同**（机读实测：8 例共用同一份 spec_json，§9.2），**均产 9 帧单会话流**（实测：`tcp.stream` 恒 `0`，仅 1 对 GET/200）。故：**本实现没有"多会话"与"多流"**——旧稿 §4/§9 表第 10/12 行的"多 TCP session 隔离"/"多 stream 映射"描述**未落码**。用例今日的断言（`packet_count=9` + `http.request.method=GET` + `http.response.code=200`）**与单会话实现一致，故绿**；但**用例 ID/摘要声称的语义未被验证**（§9.2）。

**http 层的双模式分派**（`layer_gen.go:45-55`）：`req.Meta.HTTPFLV != nil` → 变换器模式；否则终结层模式。**注释自述"终结层模式该字段恒 nil"**——但 §11.7 实测：`translateTerminalConfig` 的 `spec.HTTPFLV == nil` 守卫**不覆盖**"顶层子映射已置值"的情形，故该判别式今日由**顶层子映射**驱动。

## 6. 性能设计与验收（CORE_MEMORY §6.1–6.8）

- **目标与边界**：单流全链 = `7 + 2×rounds` 帧（rounds=1 → 9 帧）；最大 tag DataSize 受 UI24 上限 `0xffffff`（16,777,215）约束；**HTTP 响应头长 85–91 字节**（85 close+CL 两位数 / 86 close+CL 三位数 / 91 keep-alive+CL 三位数；§3.1）。吞吐数字待 P4 基准，**本版不写承诺**。
- **依据**：事件序列流式产出（`Generate` 每轮 `EmitMsg` 一个 body，**不聚合全部轮次**）；每轮 body 内存 = `13 + Σ(15+DataSize)`；http 变换器逐轮读写（`readInnerBody` 一次一个事件）；无跨流共享状态；无锁（常量与局部变量）。
- **验收两路（§6.3 强制）**：pcap（`/tmp/mcp-pcaps/http_flv/`，`<id>.pcap` / 负例 `<id>.neg.pcap`）与 NIC（`enp135s0f0np0`，`nic_capture` 开关）共用同一断言集；断言实际字段值、帧原始 hex 与 `packet_count`，不只断言"任务没报错"。**今日仅 pcap 路径复跑**（G-HTTPFLV-10）。
- **六类场景落点（§6.6）**：基线（#1，9 帧）/ 目标规模（#9 两轮，11 帧）/ 压力上限（#8 大 DataSize 声明）/ 长时间运行（多轮展开承载语义）/ 并发交错（顺序轮次承载语义，并发路径未启用）/ 背压（`packet_count` 精确计数守卫帧数漂移 + UI24 边界）。
- **帧上界**：**实测最大帧 = 409 字节**（`http_flv_ipv6` 帧 5；IPv4 侧 **394**，`http_flv_keep_alive` 帧 5 的 keep-alive 轮）；**配置理论上界** = UI24 DataSize 满值（未测，G-HTTPFLV-6）。

## 7. 错误处理（负例锚词表，与 testcase §4 一一对应、同序）

以下输入必须由 validator 拒绝并传播为 task error，不得产出成功 PCAP、`completed/0 packet` 或只剩 TCP 外壳的假成功（**实测 3 例 pcap 均 0 帧**，§9.4）：

| # | 负例 ID | 故障输入（机读实测） | 代码锚词 | 代码行 |
|---:|---|---|---|---|
| N-1 | `http_flv_neg_truncated_tag` | `tags[0].type = "unknown"` | `http_flv: tag[%d] unknown type %q` | `planner.go:91` |
| N-2 | `http_flv_neg_length_mismatch` | `rounds = -1` | `http_flv: rounds %d must be >= 0` | `planner.go:83` |
| N-3 | `http_flv_neg_validate` | `flags = 255` | `http_flv: flags 0x%02x has reserved bits set …` | `planner.go:80` |

**validator 三分支全集**（`planner.go:75-95`）：`HTTPFLV == nil` → 通过（空配置默认流）；`Flags & 0x05 != Flags` → 拒；`Rounds < 0` → 拒；`Tags[i].Type ∉ {script,audio,video}` → 拒。**除这三支外无其它拒绝分支**（旧稿 §6 表 8 行中 5 行未落码，§0 #8）。

**锚词口径**：`error_contains` 是**子串**判定；三例分别命中 `tag` / `rounds` / `flags`（前缀 `http_flv: `）。

**负例原子性**：每例单一故障注入；单次执行不得混注。三例 `expect` 键集合**严格两键** = `{expect_error, error_contains}`（机读实测 ✓，合 §7 负例纯净性）。

**未入用例的拒绝/失败分支（A′ 立项，不得冒充已覆盖）**：
| 分支 | 代码位置 | 说明 |
|---|---|---|
| `wire_fault="truncated"` 且 body > 16 | `builder.go:214-219` | 截尾 5 字节；**零用例** |
| `wire_fault="truncated"` 且 body ≤ 16 | `builder.go:215-217` | 报 `truncated tag: FLV body too short`；**零用例** |
| `resolveTag` script 空 data | `builder.go:240-242` | `script tag: empty data`；**不可达**（`meta` 恒非空，死分支） |
| `resolveTag` 未知类型 | `builder.go:256-257` | `unknown tag type`；**不可达**（validator 已先拒） |
| `EmitMsg == nil` | `planner.go:29-31` | 接线错误；单测覆盖，无用例 |
| `EmitEvent` 直调 | `planner.go:67-69` | 接线错误；单测覆盖，无用例 |
| `inner stream closed before body event` | `layer_gen.go:199` | 配置不一致（rounds 与事件数不符）；**零用例** |

**不得误报的合法协议事件**：rounds>1 多轮（#9）；IPv6（#11）；`Flags=0x01`（仅视频，#6）；`DataSizeOverride`（#8）；空 `Tags`（11 例，走默认三标签模板）。

## 8. 边界

- **帧长**：最小 9 帧（rounds=1）；最大 **11 帧**（rounds=2，#9）。**实测最大以太帧 = 409 字节**（`http_flv_ipv6` 帧 5：74 + 86 + 249 body）；IPv4 侧最大 = **394**（`keep_alive` 帧 5：54 + 91 + 249，keep-alive 头长 5 字节）；常见帧 = **389**（54 + 86 + 249）；最小 = **206**（`tag_boundary` 帧 5）。
- **DataSize 边界**：UI24 上限 `0xffffff`；#8 注入 `65536`（**声明值 ≠ 实际分配**，§9.2）。**满值 16 MiB 无例** → A′ 立项（G-HTTPFLV-6）。
- **空 tag**：spec 允许 `DataSize=0`（线上仍有 11+4 字节）。**本实现无此形态**：`resolveTag` 的 script 分支在 `Data` 为空时**不产空 data，而是产 139 字节的默认 onMetaData**（§3.5）。#6 `http_flv_empty_tag` 名义覆盖"DataSize=0"、**实际产 DataSize=139**（§9.2，G-HTTPFLV-2）。
- **Flags**：只接受 `0x00/0x01/0x04/0x05`；其余位即拒（`planner.go:79-80`）。
- **Tag 类型**：只接受 `script`/`audio`/`video`（`planner.go:87-92`）。
- **Timestamp**：32-bit；存量全 0（无 timestamp 递增/回绕用例，G-HTTPFLV-6）。
- **端口**：缺省 80（FieldContract）；**存量 15 例均未显式写** → 缺省端口路径**今日即被覆盖**（但无"非默认端口"用例，G-HTTPFLV-6）。
- **地址族**：v4/v6 独立用例（#1–#10/#12 为 IPv4、#11 为 IPv6）；**异族混写拒绝零用例**（G-HTTPFLV-6）。
- **多会话/多流**：**实现为单会话**（§5 诚实声明，G-HTTPFLV-5）。
- 不得产生回绕长度或超量分配（DataSize 由 `len(data)` 一次算定）。

## 9. 原子 ID 与完成定义（15 个唯一语义 ID，顺序为权威）

| # | ID | 类型 | 覆盖 | packet_count（实测） | 断言形态 |
|---:|---|---|---|---:|---|
| 1 | `http_flv_get_header` | 正 | §3.1：GET 请求行 + Host + HTTP/1.1 | 9 | fields×3 + frames×1 |
| 2 | `http_flv_header_flags` | 正 | §3.1：200 + `video/x-flv` | 9 | fields×2 + frames×1 |
| 3 | `http_flv_script_tag` | 正 | §3.5：AMF0 onMetaData 6 键 | 9 | frames×1 |
| 4 | `http_flv_audio_aac` | 正 | §3.6：AAC seq header `a5 00` | 9 | frames×1 |
| 5 | `http_flv_video_avc` | 正 | §3.7：AVC seq header `17 00 00 00 00` | 9 | frames×1 |
| 6 | `http_flv_empty_tag` | 正 | §8：DataSize=0 边界（**名义**） | 9 | frames×1 |
| 7 | `http_flv_minimal_tags` | 正 | §3.5–3.7：三标签齐备 | 9 | frames×3 |
| 8 | `http_flv_tag_boundary` | 正 | §8：UI24 DataSize 边界（**声明**） | 9 | frames×1 |
| 9 | `http_flv_keep_alive` | 正 | §3.1：rounds=2 两对 GET/200 | 11 | fields×2 |
| 10 | `http_flv_multi_session` | 正 | §5：多会话（**名义**） | 9 | fields×2 |
| 11 | `http_flv_ipv6` | 正 | §2：IPv6 外层（offset 74） | 9 | fields×3 |
| 12 | `http_flv_multi_stream` | 正 | §5：多流 StreamID=0（**名义**） | 9 | fields×2 |
| 13 | `http_flv_neg_truncated_tag` | 负 | §7 N-1：未知 tag 类型 | —（实测 0 帧） | `{expect_error, error_contains}` |
| 14 | `http_flv_neg_length_mismatch` | 负 | §7 N-2：rounds 负值 | —（实测 0 帧） | 同上 |
| 15 | `http_flv_neg_validate` | 负 | §7 N-3：flags 保留位 | —（实测 0 帧） | 同上 |

**包数公式**：`7 + 2×rounds`。校验：#1–#8/#10–#12 rounds=1 → 9 ✓（11 例）；#9 rounds=2 → 11 ✓。**12/12 与实测 pcap 逐例一致**（§9.4）。

### 9.1 正例断言面（实测，offset 为**帧绝对偏移**）

| 用例 | `fields` 断言 | `frames` 断言（@offset，除 #1 外均 20B） | 断言**实际**覆盖的内容 |
|---|---|---|---|
| #1 | p4 `tcp.dstport=80`、`http.request.method=GET`、`http.request.uri=/live/test.flv` | p4 @54（29B） | **完整请求行** `GET /live/test.flv HTTP/1.1\r\n` ✓ |
| #2 | p5 `http.response.code=200`、`http.content_type=video/x-flv` | p5 @119 | HTTP 头 `Connection: close\r\n\r`（**不含任何 FLV 字节**） |
| #3 | — | p5 @132 | `lose\r\n\r\n` + **FLV header 9B** + `PreviousTagSize0` 首 2B |
| #4 | — | p5 @139 | `\n` + **FLV header 9B** + `PreviousTagSize0` 4B + tag0 `12` + DataSize 首 2B |
| #5 | — | p5 @146 | FLV header 尾 3B + `PreviousTagSize0` 4B + `12 00 00 8b` + … |
| #6 | — | p5 @119 | **与 #2 逐字节相同**（同 hex、同 offset、同长度） |
| #7 | — | p5 @132 / @139 / @146 | 三条 = #3/#4/#5 的**同一组字节**（同一帧、同 offset） |
| #8 | — | p5 @132 | `ose\r\n\r\n` + **FLV header 9B** + `PreviousTagSize0` 4B |
| #9 | p4 `GET`、p5 `200` | — | 两轮各一对（**无 frame 断言**） |
| #10 | p4 `GET`、p5 `200` | — | 无 frame 断言 |
| #11 | p4 `ipv6.nxt=6`、`tcp.dstport=80`、`http.request.method=GET` | — | 无 frame 断言 |
| #12 | p4 `GET`、p5 `200` | — | 无 frame 断言 |

**10 条 frame 断言已逐条对实测 pcap 复核（10/10 字节一致，帧绝对偏移口径，§9.4）**。

> **须注意（不是缺陷，但影响覆盖可读性）**：#2–#8 的断言**全部落在 FLV header 区或其之前的 HTTP 头**——**没有任何一条断言覆盖 tag header 的 DataSize 三字节 / Timestamp / StreamID / PreviousTagSize 字段**，也没有覆盖 audio/video tag 的 data 首字节。tag 层语义今日只由 §3 代码事实支撑，**不由用例断言支撑**（§9.2）。

### 9.2 断言与语义偏差（as-built 必读，G-HTTPFLV-2）

**以下 4 条是"用例 ID/摘要声称的语义"与"实际断言/实际线内容"的偏差，全部如实登记，不得读作用例已覆盖该语义**：

| # | 用例 | 摘要声称 | 实际线内容 | 实际断言覆盖 | 判定 |
|---:|---|---|---|---|---|
| a | #6 `http_flv_empty_tag` | "Empty script tag with **DataSize=0**, 11+4 bytes on wire" | tag0 **DataSize=139**（默认 onMetaData）；FLV flags=`01`（顶层 `flags:1` 生效） | 只断 `Connection: close` 头片段（@119），**未断任何 FLV 字节** | **语义未覆盖**；且 #2 断言文案与之完全相同（重复） |
| b | #8 `http_flv_tag_boundary` | "24-bit DataSize boundary with DataSizeOverride" | TagHeader 声明 **65536**，实际 data **39 字节**，PreviousTagSize **50**（自洽但整体错位） | 只断 `…FLV 01 05 00 00 00 09 00 00 00 00`（FLV header），**未断 DataSize 三字节** | **边界未覆盖**（65536 本就在 24-bit 内，非边界；UI24 满值无例） |
| c | #10 `http_flv_multi_session` | "Multiple independent TCP sessions with isolated state" | **单会话**：`tcp.stream` 恒 0、1 对 GET/200、9 帧；spec_json 与 #1 **完全相同** | `GET`/`200`/`packet_count=9` | **语义未覆盖**（§5 诚实声明） |
| d | #12 `http_flv_multi_stream` | "Multiple streams with StreamID=0" | 同 c：单会话 9 帧 | `GET`/`200`/`packet_count=9` | **语义未覆盖**；StreamID 恒 0 是**实现常量**（§3.3），非"多流映射"结果 |

**另有 1 条口径偏差**：#4 `http_flv_audio_aac` 摘要称 "SoundFormat=10"，实际首字节 `a5` → SoundFormat=10 ✓ **但 SoundRate=1(22kHz)/SoundType=1(stereo)**，与旧稿 §3.4 注释"0xa0 mono/44kHz"不符（§0 #6）。摘要本身不含 SoundRate/SoundType 声明，**不构成虚报**，但设计文档须按实测钉（§3.6 已钉）。

**8 例共用同一份 `spec_json`**（机读实测）：#1/#2/#3/#4/#5/#7/#10/#12 —— 即这些用例**在配置层面完全等价**，仅靠 `expect` 区分。按 §7 原子原则"删除该 case 后至少一个独立规范逻辑/分支/边界失去直接证据"：**#10/#12 今日不满足该判据**（删除后无证据损失），列为 A′ 改写对象（G-HTTPFLV-5）。

### 9.3 存量审计：15 例逐条去向

| 存量 ID | 去向 | 理由 / P4 动作 |
|---|---|---|
| #1 `http_flv_get_header` | **保留** | 请求行/URI/Host 断言有效 |
| #2 `http_flv_header_flags` | **改写** | 断言 @119 落在 `Connection: close` 头（非 FLV header）；应改断 FLV header 9 字节（@140） |
| #3 `http_flv_script_tag` | **保留** | 断言覆盖 FLV header + tag0 头部 ✓ |
| #4 `http_flv_audio_aac` | **保留** | 断言覆盖 FLV header + tag0 头部；可补 `a5` 首字节断言 |
| #5 `http_flv_video_avc` | **保留** | 同上；可补 `17` 首字节断言 |
| #6 `http_flv_empty_tag` | **改写** | 语义（DataSize=0）未实现且未断言；且与 #2 断言重复（G-HTTPFLV-2a） |
| #7 `http_flv_minimal_tags` | **保留** | 三条 frame 断言覆盖三标签区 ✓ |
| #8 `http_flv_tag_boundary` | **改写** | 断的是 FLV header 非 DataSize；65536 非边界值（G-HTTPFLV-2b/6） |
| #9 `http_flv_keep_alive` | **保留** | rounds=2 两对 GET/200 断言有效，包数 11 ✓ |
| #10 `http_flv_multi_session` | **改写** | 语义未实现（单会话），spec 与 #1 等价（G-HTTPFLV-5） |
| #11 `http_flv_ipv6` | **保留** | `ipv6.nxt=6` + offset 74 路径 ✓ |
| #12 `http_flv_multi_stream` | **改写** | 同 #10；StreamID 恒 0 是常量（G-HTTPFLV-5） |
| #13 `http_flv_neg_truncated_tag` | **改写** | 语义是"未知 tag 类型"非"截断"；`wire_fault` 零使用（G-HTTPFLV-3） |
| #14 `http_flv_neg_length_mismatch` | **改写** | 语义是"rounds 负值"非"长度不一致"；`previous_size_override` 零使用（G-HTTPFLV-3） |
| #15 `http_flv_neg_validate` | **保留** | flags 保留位锚词正确 ✓ |

**去向统计：0 作废；保留 9（#1/#3/#4/#5/#7/#9/#11/#15 + #13 保留待补）；改写 6（#2/#6/#8/#10/#12/#14）。**

### 9.4 今日复跑实测证据（2026-09-29）

- **套件**：`PCAP_ROOT=/tmp/mcp-pcaps MCP_API_KEY=dev-mcp-key CASE_PROTO=http_flv go test ./test/protocol_pcap/ -run TestProtocolPcapDrive -count=1` → **PASS**，`http_flv 15/15`。
- **pcap 时间戳**：`/tmp/mcp-pcaps/http_flv/*.pcap` 全部 **2026-09-29 01:11** 重新生成（非陈旧产物）。
- **包数对账**：12 正例 `packet_count` 与 `tshark -r … | wc -l` **12/12 一致**（9×11 + 11×1）；3 负例 pcap **均 0 帧**。
- **frame 断言对账**：10 条 frame 断言按**帧绝对偏移**逐条比对原始 hex，**10/10 OK**。
- **未复跑**：NIC 路径（G-HTTPFLV-10）；`coverage_gate.py`（本车道不碰）。

## 10. P1 规范矩阵（CORE_MEMORY §4 八项：规范要求→业务场景→代码现状→缺口）

### 10.1 八项规范矩阵

| # | 八项 | 规范要求 | 业务场景 | 代码现状 | 缺口 |
|---|---|---|---|---|---|
| 1 | 连接模型 | HTTP/1.1 over TCP；GET 请求→200 响应（RFC 9112 §3） | 场景①–⑥ | `DependsOn ["http"]`（`registry.go:570`）；GET/200 由 `layer_gen.go:234/249` 落码 | 无 |
| 2 | 命令/消息表 | FLV：Header + Tag(script 18/audio 8/video 9) + PreviousTagSize；HTTP：GET/200 | 场景①–④ | `resolveTag` 三分支（`builder.go:224-258`）；http 变换器一对 GET/200 | 无 |
| 3 | 状态机 | 建连→GET→200→body→（多轮）→挥手 | #9（两轮） | http_flv 层无自有状态；`rounds` 循环在 `layer_gen.go:183` | 无 |
| 4 | 字段表 | FLV Header 4 键 + Tag Header 5 键 + HTTP 头 | 数据场景层 | `buildFLVHeader`/`buildFLVTag` 逐字段 | 无 |
| 5 | 错误处理 | 3 类负例（§7） | 负例 N-1/N-2/N-3 | validator 三分支（`planner.go:80/83/91`） | A′ 6 条（§7 未覆盖分支表） |
| 6 | 超时与活性 | HTTP/1.1 keep-alive（RFC 9112 §9.3）；FLV 无心跳 | #9 | `Connection` 由轮次决定（`layer_gen.go:186`）；**无 keep-alive 超时/重试** | 无（协议无心跳） |
| 7 | NAT/代理/被动 | 无被动模式（客户端主动 GET） | — | 无 `sessions[].src_port`；多流走策略级 `flow_control` | **显式不适用**被动模式；NAT 穿透为框架面 |
| 8 | 版本/方言 | HTTP/1.1 唯一；FLV v1；AMF0；AVC/AAC | 正例 12 | `version` 归一 `HTTP/1.1`（`layer_gen.go:171`）；FLV Version 恒 1 | AMF3/FLV 加密/HTTPS → 明确不解决；Adobe spec 键序强制力 → G-HTTPFLV-8 |

**逐行重数（分类器机读）**：8 行 = **已覆 5**（行 1/2/3/4/6，缺口列「无」）+ **立项 2**（行 5「A′ 6 条」、行 8「G-HTTPFLV-8」）+ **不适用 1**（行 7「显式不适用」）。5 + 2 + 1 = **8** ✓

### 10.2 子表①：Tag 变体 × 终态矩阵（逐格已覆/立项/不适用）

| Tag 变体 | T1 正常终态 | T2 配置拒绝 | T3 传输异常终态 |
|---|---|---|---|
| 默认 onMetaData（三标签模板） | 已覆（#3/#7/#8） | 已覆（#13 代表例，拒绝与 tag 类型无关） | A′ 立项（G-HTTPFLV-7） |
| script（自定义 `Data` 透传） | **A′ 立项**（`builder.go:228` 分支零用例） | 同上代表已覆 | A′ 立项（G-HTTPFLV-7） |
| script（DataSize=0 空 tag） | **A′ 立项**（`Data` 为空 → 产 139B 默认元数据，无法产空 tag，§3.5/§8） | 同上代表已覆 | A′ 立项（G-HTTPFLV-7） |
| audio（AAC seq header） | 已覆（#4/#7） | 同上代表已覆 | A′ 立项（G-HTTPFLV-7） |
| audio（raw AAC, type=1） | **A′ 立项**（PacketType 写死 0，不可达，§3.6） | 同上代表已覆 | A′ 立项（G-HTTPFLV-7） |
| video（AVC seq header） | 已覆（#5/#7） | 同上代表已覆 | A′ 立项（G-HTTPFLV-7） |
| video（NALU/end-of-seq） | **A′ 立项**（PacketType 写死 0，不可达，§3.7） | 同上代表已覆 | A′ 立项（G-HTTPFLV-7） |
| 未知类型 | 不适用（非法输入） | 已覆（#13） | 不适用 |
| 空 `Tags` 数组 | 已覆（11 例走默认模板） | 同上代表已覆 | A′ 立项（G-HTTPFLV-7） |

**逐格重数（分类器机读，2026-09-29）**：9 行 × 3 列 = 27 格——**已覆 13**（T1 列 4：默认模板 / AAC / AVC / 空 `Tags`；T2 列 9：每行一条代表负例）/ **A′ 立项 12**（T1 列 4：自定义 `Data` / 空 tag / raw AAC / NALU；T3 列 8：RST 异常终态补例）/ **不适用 2**（未知类型行 T1「非法输入」与 T3）。13 + 12 + 2 = **27** ✓ **零空格**。

### 10.3 子表②：数据形态变体表（协议相关全部形态逐项）

共 **20 行**，每行均有正例/负例落点或立项/不适用结论：

| # | 变体 | 落点 |
|---:|---|---|
| 1 | FLV Flags = 0x05（audio+video） | 覆（11 例） |
| 2 | FLV Flags = 0x01（仅 video） | 覆（#6） |
| 3 | FLV Flags = 0x04（仅 audio） | A′ 立项（单测覆盖，无用例） |
| 4 | FLV Flags = 0x00 | A′ 立项（单测覆盖，无用例） |
| 5 | FLV Flags 保留位（0xFF） | 覆（#15 负例） |
| 6 | DataOffset = 9 | 覆（全正例 frame 断言） |
| 7 | Version = 1 | 覆（全正例 frame 断言） |
| 8 | PreviousTagSize0 = 0 | 覆（全正例 frame 断言） |
| 9 | 单 tag（script only） | 覆（#6/#8） |
| 10 | 三 tag 齐备（默认模板） | 覆（#7 及 11 例） |
| 11 | DataSize = 0（空 tag） | **A′ 立项**（实现不可达，§8） |
| 12 | DataSize = 65536（override） | 覆（#8，**但断言未覆盖**，§9.2b） |
| 13 | DataSize = UI24 满值 0xffffff | A′ 立项（G-HTTPFLV-6） |
| 14 | PreviousTagSize 正确值 | 覆（全正例可复算） |
| 15 | PreviousTagSize 错值（override） | A′ 立项（字段已落码，零用例，G-HTTPFLV-3） |
| 16 | Timestamp = 0 | 覆（15/15 例全 0） |
| 17 | Timestamp 非零 / 回绕 | A′ 立项（G-HTTPFLV-6） |
| 18 | StreamID = 0 | 覆（全正例，实现常量） |
| 19 | script 自定义 `Data` 透传 | A′ 立项（§3.5 路径 1，零用例） |
| 20 | `wire_fault="truncated"` | A′ 立项（字段已落码，零用例，G-HTTPFLV-3） |

**12 覆 + 8 立项 = 20** ✓

### 10.4 子表③：商业行为→用例映射表

| # | 商业行为（出处） | 用例映射 | 结论 |
|---:|---|---|---|
| 1 | 直播拉流（GET + 持续 body） | #1–#8 | 已覆（单轮形态） |
| 2 | 同连接多段拉流（keep-alive） | #9 | 已覆 |
| 3 | 点播短连（Connection: close） | 全正例末轮 | 已覆 |
| 4 | IPv6 产线 | #11 | 已覆 |
| 5 | 多客户端并发 | #10/#12 | **名义映射，语义未实现**（§5/G-HTTPFLV-5） |
| 6 | 畸形流拒绝 | #13/#14/#15 | 已覆（3 分支） |
| 7 | 真实无限直播推送 | — | **明确不解决**（`rounds` 有限，§1 边界⑥） |
| 8 | HTTPS 加密承载 | — | **明确不解决**（§1 边界①） |
| 9 | HTTP/2、WebSocket-FLV、RTMP | — | **明确不解决**（§1 边界②） |
| 10 | chunked transfer coding | — | **明确不解决**（恒 Content-Length） |
| 11 | SPS/PPS/AAC 解码与转码 | — | **明确不解决**（只搬运字节） |
| 12 | 播放器时钟同步 / 码率自适应 | — | **明确不解决**（非本生成器范围） |

**5 覆 + 6 不适用 + 1 名义缺口 = 12** ✓（行 5「多客户端并发」映射到 #10/#12，但语义未实现 → 按 G-HTTPFLV-5 计缺口，不计覆盖）。

### 10.5 三路对照与候选方案对比（§4.12–4.15 / §4.17）

三路：①**规范原文**（Adobe FLV Spec v10.1 + AMF0 Spec + RFC 9112/9110，定"必须是什么"）；②**商业化软件实际行为**（**未取到**：真实 HTTP-FLV 服务器（nginx-rtmp / SRS）的线字节未抓包核对 → G-HTTPFLV-8 待确认）；③**可靠开源实现思路**（FFmpeg `flvenc.c` 的 tag 布局、`flv.js` 的解析器——只借鉴"DataSize 不含 11 字节 tag header"这一条）。三路一致点：FLV header 9 字节布局、Tag Header 11 字节布局、DataSize 语义、PreviousTagSize 语义；不一致点：**直播响应是否省略 Content-Length**（本实现恒写，真实直播常省略，G-HTTPFLV-4/G-HTTPFLV-8）。

| 方案 | 走法（借鉴来源） | 取舍 | 结论 |
|---|---|---|---|
| A | 独立 `http_flv` 终结层 + http 变换器（本版；hls/hds 同构先例） | FLV tag 可声明可断言；http 帧复用 http 层；代价 = 依赖 http 变换器契约 | **采用**（已落码） |
| B | 直接 http 层 + `response_body_b64` 塞 FLV 字节 | 无 FLV tag 结构/无 DataSize/无 tag 类型 → 15 例中 12 例不可表达 | **否决** |
| C | 独立 `http_flv` 层自带 HTTP 帧（不用 http 变换器） | 与 http 层重复实现请求/响应/头序，且破坏 http 族 9 协议统一底座 | **否决**（gbt/getwork 走"事件含完整 HTTP 帧 + identity 透传"，形态不同，不混用） |

## 11. P2 D-HTTPFLV-1 代码设计（CORE_MEMORY §8 八要素；as-built 定稿）

> 状态说明：实现已落码（`internal/protocol/http_flv/` 三文件 + http 变换器），本 P2 条目为文档轨对既有实现的**逆向定稿**（as-built 定稿），供门1 批准后作为后续改动的唯一入口。

### 11.1 文件清单（实测，非计划）

| 文件 | 职责 | 行数 |
|---|---|---:|
| `trafficgen/internal/core/types.go`（`:333-350` + `:1710`） | `HTTPFLVConfig`（`:337`）/`FLVTag`（`:345`）+ `FlowSpec.HTTPFLV` 槽位（`:1710`） | —（共享文件） |
| `trafficgen/internal/protocol/http_flv/builder.go` | FLV 线编码：header / tag / AMF0 / AAC / AVC / body 装配 / 负例注入 | 258 |
| `trafficgen/internal/protocol/http_flv/planner.go` | 终结层生成器（`Generate`/`GenEvents`/`EmitEvent`）+ validator（三分支）+ `init()` 注册 | 95 |
| `trafficgen/internal/protocol/http_flv/http_flv_test.go` | 单测（编码面 + 生成器面 + Validate 面） | 558 |
| `trafficgen/internal/protocol/http/layer_gen.go`（`:131-265`） | http 层 `EventTransformer`：`generateHTTPFLVTransformer` + `buildHTTPFlvGetRequest`/`buildHTTPFlvResponse` | —（共享文件） |
| 接线 5 件 | registry 注册（`layers/registry.go:570`）/ convert 顶层子映射（`strategy_convert.go:832`）/ protocols 准入（`protocols.go:43`）/ main.go 空白导入 + ChainPlanner（`cmd/server/main.go:55/491`）/ FieldContract 端口（`registry.go:586`） | — |

### 11.2 接口签名

- `HTTPFLVGenerator.Name() string` → `"http_flv"`（`planner.go:19`）。
- `Generate(ctx, *layers.GenRequest) error`（`planner.go:28`）：每轮 `buildFLVBody` → `req.EmitMsg(MessageEvent{Up:false, Bytes:body})`；`EmitMsg == nil` → 显式错。
- `GenEvents() layers.EventGenerator`（`planner.go:62`）：返回自身（producer marker）。
- `EmitEvent(ev) error`（`planner.go:67`）：**未接线显式错**（防误调）。
- 层 validator（`planner.go:75`）：`func(spec *core.FlowSpec) error`，三分支（§7）。
- http 变换器 `generateHTTPFLVTransformer`（`layer_gen.go:131`）：每轮 GET(up) → `readInnerBody` → 200(down)；结束 `drain()` 排空残余。

### 11.3 数据结构

`HTTPFLVConfig{Flags uint8; Tags []FLVTag; Rounds int; WireFault string}`（`types.go:337-343`，JSON 键 `flags`/`tags`/`rounds`/`wire_fault`，全 `omitempty`）；`FLVTag{Type string; Timestamp uint32; Data []byte; DataSizeOverride *uint32; PreviousSizeOverride *uint32}`（`types.go:345-350`，JSON 键 `type`/`timestamp`/`data`/`data_size_override`/`previous_size_override`）。**无 `sessions`/`streams`/`method`/`uri` 字段**（HTTP 语义在 http 层配置，多会话未实现）。

### 11.4 主流程

层链配置 → `ValidateLayers`（registry Fields 4 键 allowlist）→ translate（**今日不搬运层内 http_flv 配置**，§11.7）→ `spec.HTTPFLV`（由**顶层子映射**经 `strategy_convert.go:832` 置值）→ `flowMetaFor` 直传（`chain_planner_translate.go:116`）→ 生成器 `Generate`（每轮一个 body 事件）→ http 变换器（GET/200 对）→ tcp 层补握手挥手与分段 → writer（PCAP/NIC）。

### 11.5 错误分支

3 种 validator 拒绝（`planner.go:80/83/91`）+ 7 种未入例分支（§7 表）全部传 task error（零假成功——3 负例实测 0 帧）。**`wire_fault` 只在 builder 触发**（`builder.go:214`），经 `Generate` 的 `%w` 包装上抛（`planner.go:51`）。

### 11.6 性能边界

见 §6（事件序列流式产出、逐轮局部状态、无跨流共享、无锁；吞吐数字待 P4 基准）。

### 11.7 与现有逻辑的冲突点（本协议核心缺口 G-HTTPFLV-1）

**层内 http_flv 配置今日不被解码**——证据链：

1. `translateTerminalConfig`（`chain_planner_translate.go:695`）的 `switch term.Name` **无 `case "http_flv"`**（`grep 'case "http_flv"'` 在 `chain_planner_translate.go` 实测 **0 命中**）；该 switch（`:853`）的 case 全集见 `:856` 起（goose/sv/arp/…/fins，无 http_flv）。
2. 该函数在 switch **之前**有 `if term.Name == "http_flv"` 块（`:789-806`），**只做三件事**：`spec.HTTPFLV == nil` 时置零值结构体（`:790`）、`Flags == 0` 时补 `0x05`（`:795`）、`Tags == nil` 时补默认三标签模板（`:798`）、`Rounds == 0` 时补 1（`:805`）。**它从不读 `term.Config`**——用户的 `{"http_flv":{"flags":1,"rounds":2}}` 层内值**被静默丢弃**。
3. 该函数的 `if len(s.Fields) == 0 { return }`（`:852-854`）**不是**拦截点（http_flv 有 4 个 Fields），故控制流**进入** switch 并在无 case 时落空——`Fields` 非空但无 `case`，属 modbus 同款形态（docs-first-workflow 记忆判据二）。
4. **实测复现**（本车道 `BuildLayersPlanner` 探针，`internal/core/layers`）：
   - `layers=[…,{"http_flv":{"flags":1,"rounds":2}}]` → 最终 `flags=0x5 rounds=1 tags=3`（**层内值全丢**）。
   - `layers=[…,{"http_flv":{}}]` + 顶层 `{"http_flv":{"flags":1,"rounds":2}}` → 最终 `flags=0x1 rounds=2 tags=3`（**顶层值生效**）。
   - 分裂注入（层内 flags=1 + 顶层 rounds=2）→ `flags=0x5 rounds=2`（**层内 flags 丢、顶层 rounds 生效**）。
5. **今日唯一活着的配置载体是顶层 `http_flv` 子映射**（`strategy_convert.go:832-835` → `parseSubconfigJSON` → `spec.HTTPFLV`）。
6. **但该载体本身违反 CORE_MEMORY §1 顶层白名单**（记忆 `core-memory-1-11-13-top-level-whitelist`：顶层只放行 `layers`/`flow_control` 家族/`output`），且 `CheckProtoFlat`（`strategy_convert.go:8625`）**无 http_flv 子映射判死分支**（`:8643` 只判顶层 `http`，非 `http_flv`）→ **顶层 `http_flv` 子映射今日不被拒**（探针实测 `CheckProtoFlat("http_flv", {layers,http_flv})` 返回 `""`）。

**结论**：存量 15 例是"**层链（空壳 http_flv 层）+ 顶层 `http_flv` 子映射**"的**过渡形态**，**不是** §1 目标形状；`cases/http_flv.json` 的 `spec_json` 目标形状应为**纯 `layers`**（层内携带 flags/rounds/tags）。修法 = 补 `case "http_flv"` 走 `completedConfig` + JSON 往返 + `DisallowUnknownFields`（bgp/hds 同款），**P4 动作，本车道不碰代码**。

### 11.8 回滚方式

本协议文件独立成包，回滚 = revert `internal/protocol/http_flv/` 三文件 + http 变换器块（`layer_gen.go:131-265`）+ 接线 5 处；不触及其他协议。cases 回滚 = 恢复 15 例 JSON（产物文件，非文档）。

## 12. 门1 §1–§14 十四行对照表（CORE_MEMORY §15.1–15.3）

| § | 本协议怎么满足 | 证据 |
|---|---|---|
| §1 层链唯一真相 | 见 §12.1 强制展开：存量 15/15 顶层 = `{layers, http_flv}` —— **顶层 `http_flv` 子映射是今日唯一活着的配置载体**（§11.7），属违规残留（G-HTTPFLV-1）；目标形状 = 纯 `layers` | §12.1；`cases/http_flv.json` 机读实测 |
| §2 策略/任务 | 策略 = 单 http_flv 流量模板；任务 = 多策略合跑 + 总量封顶；框架语义未动 | 设计 §2 样例 |
| §3 五件套 | 见 §12.3 强制展开：会话表/事务序列/关联（无派生流诚实声明）/插入位置（终结层 + http 变换器）/时间线。有长连接，不豁免 | §12.3 + §5 |
| §4 查规范 | Adobe FLV Spec v10.1 + AMF0 Spec + RFC 9112/9110 + tshark 3.6.14 字段与 15 例 pcap 实测 + 落码反推；八项矩阵 + 子表①②③ | §10 |
| §5 依赖与错误 | `DependsOn ["http"]` 单值（`registry.go:570`，http 再依赖 tcp）；3 种拒绝分支 + 7 种未入例分支；失败传 task error（3 负例 0 帧实测） | §5/§7/§11.5 |
| §6 性能 | 见 §6（6.1–6.8 要素齐；吞吐数字标待 P4 基准，不写承诺；pcap/NIC 两路验收明写，NIC 今日未复跑 G-HTTPFLV-10） | §6 |
| §7 三份文档 | `120-http_flv-{design,testcase}.md` v1.0.0（本文）+ D-HTTPFLV-1（§11）+ T-HTTPFLV（testcase §2，15 ID）+ 旧稿 45-* 为历史层 | 修订记录 |
| §8 设计先行 | 本批为 **as-built 文档轨**（实现已落码）；文档先于后续 P4 改动定稿 = 开工门 | 提交序 |
| §9 测试三源 | 三源 = Adobe FLV/AMF0 + RFC 9112/9110（§10）+ D-HTTPFLV-1（§11）+ tshark 3.6.14 字段与 pcap 实测（**今日已复跑**：15/15 + 12/12 包数 + 10/10 frame，§9.4）；15 ID 逐项回指；存量审计去向 testcase §8 | `120-http_flv-testcase.md` §2/§5/§8 |
| §10 评审闭环 | 本文档完成后交独立隔离复审；红先绿后 | 自审日志 |
| §11 白话 | 每阶段白话一句先行（见本文首节） | 汇报 |
| §12 动态清单 | 见 §12.12 强制展开：四元组全开（allowlist 实测）；业务字段逐个列开/不开 + 理由；序号算法实读行号 | §12.12 |
| §13 schema 派生 | `http_flv` 已在 `registry.go:570` 注册（**不新增层**）；Fields 4 键；**P4 若改 registry Fields 必须重跑 schemagen** | §11.1 |
| §14 真实流程 | suite 经 MCP 建策略建任务 → 引擎真实生成 → tshark 字段 + frames 双通道 → 先跑后钉；pcap 落 `/tmp/mcp-pcaps/http_flv/` | testcase §7 |

### 12.1 §1 强制展开：旧键去向 + 完整 spec_json 样例

**存量实测（逐例机读，2026-09-29）**：

| 文件 | 例数 | 顶层键分布 | 链形 | 负例 expect 形状 |
|---|---|---|---|---|
| `cases/http_flv.json` | 15 | **`{http_flv, layers}` ×15** | `[ip, http, http_flv]` ×15 | 3/3 = `{expect_error, error_contains}` |

**旧键去向表（§15.3 要求"每个键写去向"）**：

| 旧键 | 存量出现例数 | 去向 |
|---|---:|---|
| `src_ip` / `dst_ip` | **0** | 本协议从未用过顶层地址；IPv6 例已住 `layers[0].ip.{src,dst}`（#11） |
| `src_port` | **0** | 本已 absent（保底 `12345+i`）；目标形按需迁 `layers[i].tcp.src_port` |
| `dst_port` | **0** | 已住 `layers[].http`？**否**——存量 15 例**均未写端口**，由 FieldContract 补 80；目标形按需显式写 `layers[].tcp.dst_port` |
| `count` | **0** | 走 `flow_control`（本版未用） |
| **顶层 `http_flv` 子映射** | **15** | **今日唯一活着的配置载体**（§11.7）；目标形 = 迁入 `layers[].http_flv`（**需先补 `case "http_flv"`**，G-HTTPFLV-1） |
| `strategy_fc` / `flow_control` | **0** | 本协议无多流用例；目标形按需加 |

**结论**：**本协议存量 15/15 顶层含 `http_flv` 子映射**——§1 门的动作 = ①**迁移面 15 例**（顶层子映射 → 层内，**依赖 P4 先补 translate case**）；②收官自查行「非负例顶层键 = 0」**今日不成立**（机读实测 15/15 残留）；③A′ 新增例须待 P4 接线后沿用纯 layers 形。

**目标形状**（P4 接线后生效）：见 §2 样例（纯 `layers`，`http_flv` 层内携带 `flags`/`rounds`/`tags`）。

### 12-P2 判死负例形状（链级红例必含清单①③④）

- ① **presence 形状** `{"layers":[…],"http_flv":{}}` 今日**不会被拒**（`CheckProtoFlat` 无 `http_flv` 子映射分支，`grep` 实测；`:8643` 只判顶层 `http`）→ **P4 不建该负例**（建了会真绿 = 假通过）→ 缺口 G-HTTPFLV-1。
- ② 白名单外游离键判死（`unknown field`）今日**亦无通用门** → 同 G-HTTPFLV-1，P4 不建。
- ③ 3 负例每条带锚词（已齐，§7）。
- ④ 收官自查「非负例顶层键 = 0」**今日不成立**（15/15 含 `http_flv`，§12.1）——**如实标红**。

### 12.3 §3 强制展开：五件套

- **会话表**：`s1` 单连接基线（#1–#8、#11，各自四元组：`src 192.0.2.10:12345 → dst 198.51.100.20:80`，TCP 握手 → GET → 200+FLV → FIN 四包）；`s2` 单连接双轮（#9，`rounds=2`，两对 GET/200 顺序展开，非交错）；`s3` **名义多会话**（#10/#12，**实现为单会话**，§5 诚实声明）。
- **事务序列**：`t1` TCP 建连（tcp 层自动，3 包）；`t2` HTTP 请求（GET，up）；`t3` HTTP 响应（200 + FLV body，down）；`t4` 多轮重复 `t2/t3`（`rounds-1` 次）；`t5` TCP 挥手（tcp 层自动，4 包）。每事务四件事（前置/触发/成功/失败）：前置 = 上一事务完成；触发 = 生成器 `EmitMsg`；成功 = 200 帧含完整 FLV body；失败 = validator 三分支（§7）。
- **关联关系**：**无派生流**（诚实声明：HTTP-FLV 是单 TCP 连接上的请求/响应，无 `driven_by`、无副连接、无父子流）。**FLV 内部的 PreviousTagSize 链是容器内自洽，不是流关联**。
- **插入位置**：终结层（`[ip,tcp,http,http_flv]`），http_flv 是**链末**；http 在它**下方**充当事件变换器（`TransformEvents: true`，`registry.go:104`）。
- **时间线**：HTTP 内严格顺序（GET 先于 200）；FLV 内 tag 顺序 = 配置顺序；多轮顺序展开（#9）；无交错（`concurrent` 为例外路径不启用）；timestamp 恒 0（无时间线推进）。

### 12.12 §12 强制展开：动态字段清单与序号算法

四元组 `ip.src/dst`、`tcp.src_port/dst_port` 五策略全开（allowlist `internal/core/layer_dyn.go:18-21` 实测：`ip`/`tcp`/`udp`/`eth`；保底 `DefaultSrcPort+i`；dst 动态与 80 缺省和平共处——显式/动态值非零即不触发补齐）。

**业务字段 4 项全关**（allowlist `layer_dyn.go` **无 `http_flv` 行**，`grep "http_flv" internal/core/layer_dyn.go` 实测 **0 命中**；对象即拒）：`flags`（层/会话级标量，逐流变无意义）/ `rounds`（轮数计数器，逐流变会破坏包数契约）/ `tags`（**列表**，无动态形状）/ `wire_fault`（负例注入器）。**http 层业务字段**中 `uri` 动态已开（`layer_dyn.go:25`，属 http 层，非本层）。

**序号算法实读**：`parseLayerDyn`（`layer_dyn.go:78`）/ `TupleGenerator.Next`（`tuple_generator.go`）/ 保底自增（`strategy_convert.go:49` + worker 注入）/ allowlist 白名单（`layer_dyn.go:18-25`）——**`http_flv` 无块**（grep 实测零命中），即层内任何对象值 → `does not support dynamic`。

## 13. P3 对接清单（T-HTTPFLV 草稿输入；正文落 testcase 文件）

15 ID（12 正 + 3 负）+ packet_count/锚词 + fixture 常量 + 双通道断言基线 + 存量审计（testcase §2–§5/§8 全量）。A′ 候选（9 例）：`http_flv_neg_wire_truncated`（`wire_fault`）/ `http_flv_neg_prev_size`（`previous_size_override`）/ `http_flv_flags_audio_only`（0x04）/ `http_flv_flags_none`（0x00）/ `http_flv_custom_script`（script `Data` 透传）/ `http_flv_multi_round_3`（rounds=3 包数公式外推）/ `http_flv_neg_unknown_field`（层内未知键，待 P4 接线）/ `http_flv_dst_port_custom`（非默认端口）/ `http_flv_neg_mixed_family`（异族混写）。**#10/#12 语义改写**（多会话未实现）另计。

## 14. 缺口立项清单（有缺口写「缺口立项」，不许空着）

| 缺口 | 内容 | 去向 |
|---|---|---|
| G-HTTPFLV-1 | **层内 http_flv 配置今日不被解码**：`chain_planner_translate.go` 的 `switch term.Name` **无 `case "http_flv"`**（`grep` 0 命中）；`:789-806` 块只补默认值、不读 `term.Config`；实测层内 `{flags:1,rounds:2}` → 最终 `flags=0x5 rounds=1`（值全丢）。**今日唯一活着的载体是顶层 `http_flv` 子映射**（`strategy_convert.go:832`），而它违反 CORE_MEMORY §1 顶层白名单，且 `CheckProtoFlat` **无 http_flv 子映射判死分支**（`:8643` 只判顶层 `http`）→ **存量 15/15 顶层残留**，§1 目标形状今日不可达 | **P4 必做**：补 `case "http_flv"`（`completedConfig` + JSON 往返 + `DisallowUnknownFields`，bgp/hds 同款）→ 层内配置生效 → 15 例 `spec_json` 迁纯 `layers` 形；**禁加单协议黑名单分支**（等框架级 unknown-key 白名单，kingbase/opcua 记忆裁定） |
| G-HTTPFLV-2 | **断言语义偏差 4 条**（§9.2）：(a) #6 "DataSize=0" 实际 DataSize=139 且断言只落 HTTP 头（与 #2 断言重复）；(b) #8 "24-bit 边界" 实际 65536 非边界、断言只落 FLV header；(c) #10/#12 多会话/多流语义未实现；(d) **8 例共用同一份 spec_json**（#10/#12 删除后无证据损失，违反 §7 不可再分判据）。另：script 6 键**写死无配置入口**（旧稿"键序按配置保持"未实现）；audio/video 的 SoundRate/SoundType/FrameType/AVCPacketType/CompositionTime 全写死；AAC raw / AVC NALU / 空 tag **实现不可达** | **P4 必做**：① 改写 #2/#6/#8 断言（落到 FLV 字节 + 补 `data_size` 精确断言）；② 改写 #10/#12 语义或收窄摘要（多会话未实现，不得声称隔离）；③ 扩 A′ 9 例；④ `wire_fault`/`previous_size_override`/`flags=0x04`/`flags=0x00`/script 自定义 Data 补例 |
| G-HTTPFLV-3 | **负例语义与注入字段不符**：#13 名为 `truncated_tag` 实为**未知 tag 类型**；#14 名为 `length_mismatch` 实为 **rounds 负值**；`wire_fault="truncated"` 与 `previous_size_override` **已落码但零用例** | A′ 补例（`wire_fault` / `previous_size_override` 各一）；P4 改写 #13/#14 摘要 |
| G-HTTPFLV-4 | **恒写 `Content-Length`**，不覆盖真实直播"省略 Content-Length + 持续推送"形态（§3.1 诚实边界） | **明确不解决**（`rounds` 有限形态为本实现契约）+ 若未来实现须新增独立例并重算头长 |
| G-HTTPFLV-5 | **多会话/多流未实现**：`HTTPFLVConfig` 无 `sessions`/`streams` 字段；`Generate` 只按 `rounds` 循环；#10/#12 实测单会话（`tcp.stream` 恒 0、1 对 GET/200）。旧稿 §4/§9 表第 10/12 行描述未落码 | A′ 候选：补实现（每会话独立四元组 + 独立 FLV 状态）或**明确不解决**并收窄 #10/#12 摘要与断言；**用例今日不得声称状态隔离** |
| G-HTTPFLV-6 | **边界覆盖缺失**：DataSize UI24 满值（0xffffff）无例；Timestamp 非零/回绕无例；非默认端口无例；异族混写拒绝无例 | A′ 补例（4 例） |
| G-HTTPFLV-7 | **RST 非正常结束补例**（§3.15② 后半） | A′ 补例 `http_flv_abort_rst`（`tcp.rst` 框架能力，本层零断言） |
| G-HTTPFLV-8 | **第三源未取到**：真实 HTTP-FLV 服务器（nginx-rtmp/SRS）线字节未抓包核对；Adobe FLV Spec v10.1 的 **AMF0 键序强制力**与**直播响应省略 Content-Length 的合规性**未逐条核对条款 | 待确认：抓真实服务器包对照，或查 Spec 原文；确认前按实现钉、不声称合规 |
| G-HTTPFLV-9 | **结果文档过期**：`trafficgen/docs/protocol-pcap-test/http_flv.md`（**tracked 产物**）写 `Cases: 15 — pass 15, fail 0, error 0`，但末次提交 `e7e7d1c`（**2026-08-27**）早于判死提交 `0417be5`（2026-09-13）；`docs/protocol-pcap-test/http_flv/` **0 个 pcap**（目录不存在），文档内 15 条 pcap 链接**全部死链**。**该产物未经今日复跑证实**；本车道今日**已另行复跑**（§9.4，`/tmp/mcp-pcaps/http_flv/`），故 15/15 今日成立——但**过期产物本身不得作为依据** | **代码阶段**（P5 重跑套件后重生成该产物）；本版**不删不改**（tracked 产物）；口径与 pcep G-PCEP-11 / opcua G-OPCUA-10 一致 |
| G-HTTPFLV-10 | **NIC 双输出路径今日未复跑**：§1 输出契约声称 pcap/NIC 共用同一断言集，但本车道只跑了 pcap 离线套件；`nic_capture` 路径未验证 | **代码阶段**（P5 双输出全量回归）；本版不声称 NIC 已验 |
| G-HTTPFLV-11 | **死代码**：`buildAudioAACData`（`builder.go:173`）与 `buildVideoAVCData`（`builder.go:193`）**零生产调用方**（`grep` 实测）；`buildAudioAACData` 内 `if/else if` 链把 `first` 原样赋回自身（`builder.go:174-185`，无操作）。`resolveTag` 的 script "empty data" 分支（`builder.go:240`）不可达 | P4 裁定：删死代码或接线（`AACPacketType`/`AVCPacketType`/`FrameType` 若开放为配置项则接线）；不可达分支同裁 |

## 15. 修订记录

- v1.0.0（2026-09-29）：批次二文档轨 as-built 首版。**续号 45→120 沿革与 16 项旧稿校正**（§0，含 FLV 起点写死错、响应头长 65→86 错、音频首字节 0xa0→0xa5 错、错误表 5/8 行未落码、多会话/多流未实现、文件名 `http-flv.json` 死引用、行号全过时）；存量 15 例机读审计（**顶层 15/15 含 `http_flv` 子映射**，§12.1）+ **今日复跑证据**（15/15 绿、12/12 包数一致、10/10 frame 一致，§9.4）；**§9.2 断言语义偏差 4 条**（#6/#8/#10/#12）；D-HTTPFLV-1 as-built 定稿（§11）；**G-HTTPFLV-1 层内配置不解码**（探针实证）+ 缺口 G-HTTPFLV-1…G-HTTPFLV-11。自审见汇报。
