# #86 HTTP（HTTP/1.0/1.1 over TCP）设计契约

> 版本：v1.0.1（P-PIPE 文档轨批次二 · as-built）
> 日期：2026-09-29
> 车道：文档轨（#86 http）
> 前序基线：本仓 `docs/protocol-designs/` 无 HTTP（`120-http_flv-*` 是 http_flv，非本协议）；本版是首份 HTTP 设计文档。
> 机器契约：`trafficgen/test/protocol_pcap/cases/http.json`（67 例 = 59 正 + 8 负；ID、顺序、包数、断言以 JSON 为唯一权威）
> 白话一句：**TCP 先完成三次握手，客户端发 HTTP 请求、服务端回 HTTP 响应，最后四帧挥手；同一连接可交错或流水线发送多笔事务，TCP 层负责 MSS 分段。**

## 1. 范围、载体与实现边界

HTTP 是 TCP 终结层，推荐链为 `[ip,tcp,http]`，目的端口缺省 80；TLS 是可选底座。HTTP 终结层生成完整请求/响应字节事件，TCP 负责握手、ACK、MSS 分段和 FIN 挥手。依赖 HTTP 的八个注册层是 `http_flv`/`hls`/`hds`/`gbt`/`cwmp`/`getwork`/`doh`/`onvif`：前三者由 HTTP 包装内层 body 事件，后五者由内层产出完整 HTTP 帧并由 HTTP 原样透传。`mmse` 也依赖 HTTP；`ntlm`/`ocsp`/`spnego` 的 registry 关系是 `DependsOn:[tcp]`、`OptionalOn:[http]`，只有显式 HTTP profile 才走 HTTP 透传，不能把它们写成 HTTP 必选载体。本版 67 个机器用例只覆盖 HTTP 终结层；`isHTTPRPCInner` 的完整透传入口见 §6。

已实现：方法、URI、HTTP 版本、请求/响应头、文本及 base64 body、gzip、chunked、chunk_size、响应状态码/状态文本、keep-alive、多事务、pipelined、file_source、IPv4/IPv6、TTL、TCP MSS、层字段动态。未从本版推导真实服务器状态、TLS 加密线字节或 NIC 抓包结论；这些均待 P5 重跑/专项验证。

实现位置：`trafficgen/internal/protocol/http/http.go`（legacy planner、事务和字节构造）；`layer_gen.go:25-389`（终结层生成器、校验器和变换器）；`trafficgen/internal/core/layers/registry.go`（http 注册）；`chain_planner_translate.go`（层翻译）；`strategy_convert.go`（顶层 http 判死）；`layer_dyn.go`（动态白名单）。

## 2. 协议栈、线格式与包数

无 VLAN/IP options/TCP options 时，HTTP payload 起点为 IPv4 offset 54、IPv6 offset 74；`http_req_chunk_size_multi` 的 frames 断言固定在 packet 4、offset 54。请求首行是 `METHOD URI HTTP/VERSION`，响应首行是 `HTTP/VERSION CODE TEXT`，行和头以 CRLF 结束。

每个普通单事务流：SYN、SYN-ACK、ACK、请求、响应、ACK、FIN、FIN-ACK、ACK，共 9 包。keep-alive/pipelined 的三事务基线为 13 包；MSS 分段使 `http_mss_segments_long_response` 为 10 包、`http_mss_req_segments_long_body` 为 14 包、`http_req_chunked_mss` 为 10 包；多流按每流包数累加（18、27、36、45 等 JSON 既有值）。负例不设 packet_count。

## 3. 目标配置形状与五件套

层链是唯一配置真相，目标 `spec_json`：

```json
{
  "layers": [
    {"ip": {"src": "192.0.2.10", "dst": "198.51.100.20"}},
    {"tcp": {"src_port": 40010, "dst_port": 80}},
    {"http": {"method": "GET", "uri": "/", "version": "1.1"}}
  ]
}
```

完整事务五件套：

1. 会话表：TCP 单连接由 IP/TCP 四元组标识；HTTP `transactions` 在同一连接内复用。
2. 事务序列：默认每笔 `request → response`；`pipelined=true` 改为全部 request 后全部 response。
3. 关联：TCP seq/ack 由 planner 递进；请求和响应方向分别为 up/down，保持同一连接序列。
4. 插入位置：HTTP 是 TCP 之上的终结层；在 HTTP-RPC/FLV/HLS/HDS 变换模式中，HTTP 位于 TCP 与内层终结层之间。
5. 时间线：握手 → HTTP 消息（按事务模式）→ FIN 四帧挥手；同一时间戳由 planner 生成，真实发送节奏不在本协议契约内。

## 4. 字段和行为契约

- `method` 缺省 GET；`uri` 缺省 `/`；`version` 层值 `1.1` 归一为 `HTTP/1.1`。
- HTTP/1.1 自动加 Host（IPv6 以 `[addr]` 形式）；HTTP/1.0 不自动加 Host。
- 未显式 Connection 时，单事务默认 close；多事务或 `keep_alive` 默认 keep-alive；显式头优先。
- body 非空且未显式 Content-Length 时自动写长度；**空 body 且非 chunked 写 `Content-Length: 0`**——RFC 7230 §3.3.3：无 CL/chunked 的 HTTP/1.1 响应以连接关闭定界，缺 CL 的空响应在 keep-alive 流上无法定界（Wireshark 全部显示为 reassembly segment；2026-10-03 用户实测，b094d7e 修复）。JSON/HTML 等 body 自动嗅探 Content-Type。
- gzip 在 Content-Type 嗅探后压缩；chunked 在 content encoding 后编码并抑制 Content-Length；非 gzip encoding 只写头，不改变 body。
- `body_b64`/`response_body_b64` 解码成功时作为二进制 body；非法 base64 回退同侧文本 body。
- `response_status_code`、`response_status_text` 支持未知状态码/自定义文本；响应头可覆盖自动值。
- `file_source` 在注入 `PayloadCache` 时覆盖内联 body；未注入缓存时不声称文件内容已落线。
- `mss` 由 TCP 层控制，HTTP planner 仅按 MSS 分段；小于 RFC 879 最小值 536 被拒。

## 5. 规范与实现依据

规范基线为 RFC 7230（消息语法、头、Content-Length/Transfer-Encoding）、RFC 7231（方法、状态码）、RFC 9112 §6.3.2（pipelining）、RFC 879（MSS）以及 IPv4/IPv6/TCP 载体规范。实现依据为 `internal/protocol/http/http.go` 的 `Planner.Validate`、`Planner.Plan`、`segmentByMSS`、`buildHTTPRequestBody`、`buildHTTPResponseBody`、`resolveRequestBody`/`resolveResponseBody`；层接线依据 `layer_gen.go`、registry 和 translate 分支。机器行为依据 67 条 `http.json`（2026-10-03 套件 67/67、http 族 sweep 565/565、NIC 实发 5/5 复跑通过，b094d7e 空 body CL:0 修复后）。

## 6. 依赖、注册和错误边界

registry 将 http 注册为 `CategoryTerminal`，`DependsOn:["tcp"]`，`OptionalOn:["tls"]`，`TransformEvents:true`；TCP 为必需载体。链翻译分派 `http`，使用 `ParseHTTPConfigFromMap` 的单一解析面。顶层 `http` presence（包括空 map）由 `CheckProtoFlat` 拒绝，必须迁入 http 层。

8 个负例的拒绝面是：TCP `src_port` pattern 动态不支持；MSS 过小；顶层 flat `src_ip`；静态四元组多流复制；缺少 GBT 的 HTTP carrier；URI 使用 inc；method 使用动态；顶层 http 子映射。实际 `strategy_fc` 为 19 条，其中 17 条正例、2 条负例（pattern 与 static-copy）；数量只在该控制对象中表达，不混入业务配置。错误锚词以 cases JSON 为准，文档不替换实际文案。

### 6.1 依赖、失败、重试与超时

| 阶段 | 前置/失败条件 | 可观察结果 | 重试/超时边界 |
|---|---|---|---|
| 层注册/补全 | `http` 必须依赖 TCP；缺 carrier 或 schema 不匹配即拒绝 | planner/任务错误，不得零包成功 | 不重试配置错误；请求级超时由上层任务控制 |
| 动态解析 | 仅 allowlist 字段和允许策略；string 的 inc/rand、method 动态、pattern 端口按锚词拒绝 | Plan/worker 错误 | 不重试确定性校验错误 |
| HTTP 生成 | `EmitMsg` 未接线、上下文取消、内层变换流提前关闭 | generator 返回错误/取消；不得静默丢事件 | 仅由任务取消/重启策略决定，不由 HTTP 自行重试 |
| 文件源 | `PayloadCache` 可选；未注入缓存不声称文件内容落线 | 使用可解析内容，否则保持配置语义 | 缓存/文件重试由 cache 层负责 |
| TCP/输出 | MSS < 536、队列背压、输出失败 | 任务失败或取消，TCP 负责分段/挥手 | 连接重传不是 HTTP planner 契约 |

HTTP 本身不定义自动重试；本协议不为响应状态码或 keep-alive 添加隐式重试。

## 7. 数据和动态行为

动态值由 flow index 逐流解析，不改变层链形状。HTTP 业务动态白名单共 6 个字段：`uri`、`body`、`body_b64`、`response_body`、`response_body_b64`、`response_status_code`。字符串字段支持 fixed/list/pattern，拒绝 inc/rand；`response_status_code` 支持 fixed/list/inc/rand，pattern 被拒。请求 method、version、headers、response headers、keep_alive、transactions、pipelined、chunk_size、file_source、encoding 等不支持动态对象。

层地址/端口动态由通用 IP/TCP 面处理；机器用例实际覆盖 TCP `src_port` 的 fixed/list/inc/rand/repro、IP `src` 的 rand，以及 HTTP `uri` 的 fixed/list/pattern、`body`/`response_body`/`body_b64`/`response_body_b64` 的 list、`response_status_code` 的 list/inc/rand。HTTP 字符串字段的 inc/rand、除上述字段外的动态对象没有正例，缺口见 §14；随机值以 cases 断言的 `distinct_values` 为观察契约，顺序不硬编码。

## 8. 门 1 §1–§14 十四行对照表

| §1 层链唯一真相 | 65 例 `spec_json` 顶层仅 `{layers}`；1 例额外 `src_ip`、1 例额外顶层 `http` 均为负例并登记 P4 缺口；完整目标样例见 §3 | `http.json` 机读 |
| §2 策略/任务 | 单 HTTP 流由层链模板定义；多流通过 `tcp.src_port` 或 `ip.src` 上的动态 `list`/`inc`/`rand` 策略展开，事务数量住 http 层 | `http.json`、translate |
| §3 五件套 | 会话/事务/关联/插入/时间线分别见 §3；TCP 握手、HTTP 事务、FIN 顺序由 `Planner.Plan`/`HTTPGenerator.terminalLoop` 维护；HTTP-FLV/HLS/HDS 为包装变换，GBT/CWMP/GetWork/DoH/ONVIF 为完整 HTTP 帧透传 | `http.go`、`layer_gen.go` |
| §4 查规范 | RFC 7230/7231/9112/879 + 落码 + `http.json` 字段/包数；未宣称 pcap/NIC 证据 | §5 |
| §5 依赖与错误 | registry `DependsOn:[tcp]`、`OptionalOn:[tls]`、`FieldContract tcp.dst_port=80`；八个负例按实际锚词登记；八个 HTTP 包装/透传层与 `mmse` 通过 `DependsOn:[http]` 复用 carrier；`ntlm`/`ocsp`/`spnego` 为 `OptionalOn:[http]`，不是 HTTP 必选载体 | registry、§6 |
| §6 性能 | 流式 channel、TCP MSS 分段、FileSource 缓存路径；性能数字待 P5 基准，不在本文承诺 | `http.go` |
| §7 三份文档 | `86-http-{design,testcase}.md`、D-HTTP-1/实现与 cases 机器契约；本协议无旧设计稿 | 修订记录 |
| §8 设计先行 | 本版为实现与 67 例先存后的 as-built 逆向定稿；定稿后以本文和 testcase 为唯一文档入口 | §1、§13 |
| §9 测试三源 | 规范 + 实现/registry/translate + `http.json` 67 ID；无今日 pcap/NIC 复跑声称 | testcase §5/§8 |
| §10 评审闭环 | 本轮文档自审 2 轮，末轮 clean；代码/用例改动不在本任务范围 | 修订记录 |
| §11 白话 | 首节头块已给出一句 HTTP 收发白话 | 本文头块 |
| §12 动态清单 | 6 个 HTTP 业务开关及序号算法位置见 §7/§11；正例实际形状为 uri fixed/list/pattern、body/response_body/body_b64/response_body_b64 list、status fixed/list/inc/rand；拒绝格与未覆盖字符串策略见 §14 | `layer_dyn.go` |
| §13 schema 派生 | http registry 已有 Fields；不新增 schema，若改 Fields 必须重跑生成/校验 | registry |
| §14 真实流程 | cases 由策略/任务进入层 planner，再由 TCP builder 形成握手、分段和挥手；本版只写待 P5 重跑，不写通过 | testcase §7 |

### 8.1 §1 旧键逐键去向与完整目标例

本协议无旧设计稿；按机器契约逐键审计：`src_ip` 仅在 `http_neg_flat_src_ip` 以负例故意存在（目标去向 `layers[0].ip.src`）；HTTP 正例均把地址放 `layers[0].ip.src/dst`、端口放 `layers[1].tcp.src_port/dst_port`；`count` 不出现，多流数量只由 19 条用例的 `strategy_fc.type=flows` 表达（17 正例、2 负例），具体地址/端口变化仍由 `tcp.src_port` 的固定值或 `list`/`inc`/`rand` 策略、`ip.src` 的 `rand` 策略表达；顶层 `http` 仅 `http_neg_top_http` 故意存在，正常配置迁入 `layers[-1].http`；`transactions`、`keep_alive`、`pipelined` 等业务键住 http 层。完整正常目标例即 §3 JSON。

## 9. 覆盖和 P4 缺口

机器契约 65/67 例为纯 `{layers}`，两种非纯形各 1 例，均为负例：`http_neg_flat_src_ip`（`{layers,src_ip}`，G-HTTP-1）、`http_neg_top_http`（`{layers,http}`，G-HTTP-2）。另有 `http_neg_missing_carrier_gbt` 使用 `[ip,tcp,gbt]` 而非 HTTP 终结层，作为 carrier 缺失负例（G-HTTP-3）。这些不是正例残留，也未被文档改写为通过。

P3 固定动作：同连接多轮由 `http_keepalive_multi_transactions`/`http_pipelined` 覆盖；非正常结束由负例拒绝契约覆盖；长保活由 keep-alive 三事务例覆盖。A′/B′ 缺口：真实 pcap/NIC 留证、完整动态拒绝矩阵、FileSource 注入路径、carrier 族联调和顶层迁移负例的任务链复跑，均待 P4/P5，不能宣称已通过。

## 10. 修订记录

- v1.0.0（2026-09-29）：首份 HTTP as-built 设计文档；机器契约 67 例（59 正、8 负）、三种顶层键形（纯 `{layers}` 65、`{layers,src_ip}` 1、`{http,layers}` 1）及门 1 十四行完成；未声称 pcap/NIC 测试通过。自审 2 轮，末轮 clean。
- v1.0.2（2026-10-01）：按 registry 校正 HTTP carrier 依赖口径：`mmse` 与八个 HTTP 层依赖 `http`，`ntlm`/`ocsp`/`spnego` 仅 `OptionalOn:[http]`；修正性能例引用至实际四流用例。未改 JSON、未运行任何测试。

## 11. 动态字段清单与序号算法（门 1 §12 强制展开）

| 字段 | 类型/允许策略 | 代码位置 | 序号语义 |
|---|---|---|---|
| `uri` | string：fixed/list/pattern | `layer_dyn.go`、`chain_planner_translate.go` | `FlowIndex` |
| `body` | string：fixed/list/pattern | 同上 | `FlowIndex` |
| `body_b64` | string：fixed/list/pattern | 同上 | `FlowIndex` |
| `response_body` | string：fixed/list/pattern | 同上 | `FlowIndex` |
| `response_body_b64` | string：fixed/list/pattern | 同上 | `FlowIndex` |
| `response_status_code` | int：fixed/list/inc/rand；pattern 拒绝 | `layer_dyn.go` | `FlowIndex` |

解析算法位置：`chain_planner_translate.go` 的 `case "http"` 调用 `translateHTTPDyn`；`translateHTTPDyn` 按 worker 写入的 `spec.FlowIndex` 解析并回填 HTTPConfig，同一 flow 的所有事务复用该值。字符串端点校验和策略拒绝在 `layer_dyn.go`，回填字段在其 HTTP 分支。层内 TCP/IP 地址和端口动态走通用 IP/TCP 分支；cases 对这些字段使用 distinct 集合断言。

## 12. P1 规范—场景—实现—缺口矩阵（D1/D2/D3）

| 规范要求 | 业务场景 | 代码现状 | 用例/缺口 |
|---|---|---|---|
| RFC 7230 §3 消息语法与 CRLF | 请求/响应首行、头、body | `buildHTTPRequestBody`/`buildHTTPResponseBody` | T-HTTP-7/8/17/22/43/44；已覆 |
| RFC 7230 §3.3.2/§3.3.3 长度与分块 | Content-Length、空体、chunked、gzip 后分块 | `build*Body` | T-HTTP-8/13/20/21/26/35/49；已覆 |
| RFC 7231 §4 方法 | GET/POST/PUT/DELETE/HEAD | planner 方法字段 | T-HTTP-7/8/29/30/31；已覆 |
| RFC 7231 §6 状态码 | 200/201/301/404/418/500/599 | response status 构造 | T-HTTP-7/34/32/11/24/33/25；已覆 |
| RFC 9112 §6.3.2 流水线 | 同连接请求先行、响应后行 | `Planner.Plan` pipelined | T-HTTP-10；已覆 |
| RFC 879 MSS | 最小 MSS 与跨段 payload | `segmentByMSS` + TCP 层 | T-HTTP-28/39/48/49；下界拒绝 T-HTTP-1 |
| IPv4/IPv6 TCP 承载 | 双地址族、Host 格式、非默认端口 | ip/tcp 层 + planner | T-HTTP-7/15/16/41/47/48；已覆 |
| RFC 7230 §6.3 保活 | 多事务、流水线与 close | transaction/keep_alive | T-HTTP-9/10/40；长时 NIC 待 P5 |

三路对照：规范以 RFC 7230/7231/9112/879 为底线；商业行为以 HTTP/1.1 常见 Origin/Reverse Proxy 的 Host、keep-alive、chunked 行为作待抓包核验基线；开源实现参考 Go `net/http` 的请求行/头规范化思路（不复制代码）。差异取规范约束，商业抓包证据尚缺，登记 G-HTTP-4。

## 13. 性能设计与六类验收（D4）

生成路径按事务和 MSS 分段流式产出，不汇总全流 payload；队列/环形缓冲上限由通用 pipeline 配置控制。验收指标与边界：基线 9 包（T-HTTP-7）、三事务 13 包（T-HTTP-9）、流水线 13 包（T-HTTP-10）；目标规模为多流展开（T-HTTP-41/47 两流、T-HTTP-53/54/57 四流级）；压力上限为最大单体 body 在 MSS 下分段（T-HTTP-28/39/48/49）；长时间为 keep-alive 多事务；并发交错为多流动态策略展开；资源耗尽为有界队列背压。每项须记录包数、吞吐、延迟、RSS、CPU、队列积压和失败/丢包；pcap 用 tshark 校字段，NIC 用真实接口抓包。吞吐、RSS、CPU、规模上限和 NIC 结果待 P5 基准，不能承诺数字。

## 14. 设计八要素、缺口与回滚（D5/D6/D7/D8）

改动边界为 HTTP planner、层翻译/校验、registry 与三件机器契约文件；接口为层链 `[ip,tcp,http]` 和动态策略对象，数据结构为 HTTPConfig/transactions/body 动态对象。主流程是 TCP 握手→事务请求/响应→MSS 分段→FIN；错误分支在 planner/validator 拒绝并返回 cases 锚词，不能零包成功。与现有逻辑的冲突点是旧顶层 HTTP 子映射、静态多流四元组和缺 carrier，均以判死负例约束。回滚只回退本协议三文件及对应实现提交，不回退其他协议。

缺口登记（沿用 testcase §8 已占用的 G-HTTP-1/2/3 编号，续编）：G-HTTP-4 商业行为抓包、真实 NIC 与 TLS 线证据待 P5；G-HTTP-5 IPv6 keep-alive/pipelined 零例；G-HTTP-6 FileSource 注入缓存路径待专测；G-HTTP-7 完整动态拒绝矩阵和 HTTP-RPC/FLV/HLS/HDS carrier 联调待代码阶段。上述缺口不写入正例，不以“已实现”冒充已验收。

### 14.1 动态与底座边界（真实用例对账）

HTTP 业务动态 allowlist 只有 6 个字段（代码位置：`trafficgen/internal/core/layer_dyn.go:22-25`，实际字段在 HTTP 回填分支的 `HTTP.URI/Body/BodyB64/ResponseBody/ResponseBodyB64/ResponseStatusCode`）；cases 的正例不覆盖全部允许策略：`uri` 覆盖 fixed/list/pattern，`body`、`response_body`、`body_b64`、`response_body_b64` 仅覆盖 list，`response_status_code` 覆盖 fixed/list/inc/rand。HTTP 字符串字段的 inc/rand 和 method/version/headers/response headers/连接及事务参数的动态对象没有正例；拒绝格仅由 URI-inc、method-list、TCP 端口-pattern 三个负例钉住。通用 IP/TCP 动态与 HTTP 业务动态是两条解析面，不能用端口或地址用例替代业务字段覆盖。

`strategy_fc` 只在 19 条用例中承载 `flows` 数量（17 正例、2 负例），不进入 `spec_json` 层链；正例无 `count` 字段。多流正例通过 TCP 源端口或 IP 源地址动态展开，静态四元组复制由负例拒绝。## 15. 规范形态逐格表（D1）

结构×地址族（逐格可指用例号）：

| 结构 \ 地址族 | IPv4 | IPv6 |
|---|---|---|
| 单事务请求/响应 | 已覆 T-HTTP-7 | 已覆 T-HTTP-15 |
| 多事务 keep-alive | 已覆 T-HTTP-9 | 缺口 G-HTTP-5 |
| pipelined | 已覆 T-HTTP-10 | 缺口 G-HTTP-5 |
| MSS 分段 | 已覆 T-HTTP-28/39/49 | 已覆 T-HTTP-48 |
| 多流 `flows>1` | 已覆 T-HTTP-41 | 已覆 T-HTTP-47 |

版本×Host 行为：

| 版本 | Host 自动 | 用例 |
|---|---|---|
| HTTP/1.0 | 不自动 | T-HTTP-14 |
| HTTP/1.1 | 自动（IPv6 加方括号） | T-HTTP-7 / T-HTTP-15 |

逐格重数：结构表 5 行 × 2 列 = 10 格，已覆 8 + 缺口 2（G-HTTP-5），零空格；版本表 2 格均已覆。商业行为→用例映射：Host/连接策略→T-HTTP-7/14/15/40，keep-alive/流水线→T-HTTP-9/10，chunked/gzip→T-HTTP-12/13/19/20/21/30/35，状态→T-HTTP-11/24/25/32/33/34，动态→T-HTTP-53–T-HTTP-72。
