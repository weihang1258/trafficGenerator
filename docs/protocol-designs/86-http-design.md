# #86 HTTP（HTTP/1.0/1.1 over TCP）设计契约

> 版本：v1.0.0（P-PIPE 文档轨批次二 · as-built）
> 日期：2026-09-29
> 车道：文档轨（#86 http）
> 前序基线：本仓 `docs/protocol-designs/` 无 HTTP（`120-http_flv-*` 是 http_flv，非本协议）；本版是首份 HTTP 设计文档。
> 机器契约：`trafficgen/test/protocol_pcap/cases/http.json`（67 例 = 59 正 + 8 负；ID、顺序、包数、断言以 JSON 为唯一权威）
> 白话一句：**TCP 先完成三次握手，客户端发 HTTP 请求、服务端回 HTTP 响应，最后四帧挥手；同一连接可交错或流水线发送多笔事务，TCP 层负责 MSS 分段。**

## 1. 范围、载体与实现边界

HTTP 是 TCP 终结层，推荐链为 `[ip,tcp,http]`，目的端口缺省 80；TLS 是可选底座。HTTP 终结层生成完整请求/响应字节事件，TCP 负责握手、ACK、MSS 分段和 FIN 挥手。HTTP 也可作为 `http_flv`、HLS、HDS 及 HTTP-RPC 族的事件变换/透传层；本版 67 个机器用例只覆盖 HTTP 终结层。

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
- body 非空且未显式 Content-Length 时自动写长度；JSON/HTML 等 body 自动嗅探 Content-Type。
- gzip 在 Content-Type 嗅探后压缩；chunked 在 content encoding 后编码并抑制 Content-Length；非 gzip encoding 只写头，不改变 body。
- `body_b64`/`response_body_b64` 解码成功时作为二进制 body；非法 base64 回退同侧文本 body。
- `response_status_code`、`response_status_text` 支持未知状态码/自定义文本；响应头可覆盖自动值。
- `file_source` 在注入 `PayloadCache` 时覆盖内联 body；未注入缓存时不声称文件内容已落线。
- `mss` 由 TCP 层控制，HTTP planner 仅按 MSS 分段；小于 RFC 879 最小值 536 被拒。

## 5. 规范与实现依据

规范基线为 RFC 7230（消息语法、头、Content-Length/Transfer-Encoding）、RFC 7231（方法、状态码）、RFC 9112 §6.3.2（pipelining）、RFC 879（MSS）以及 IPv4/IPv6/TCP 载体规范。实现依据为 `internal/protocol/http/http.go` 的 `Planner.Validate`、`Planner.Plan`、`segmentByMSS`、`buildHTTPRequestBody`、`buildHTTPResponseBody`、`resolveRequestBody`/`resolveResponseBody`；层接线依据 `layer_gen.go`、registry 和 translate 分支。机器行为依据 67 条 `http.json`（未声称 pcap/NIC 已复跑）。

## 6. 依赖、注册和错误边界

registry 将 http 注册为 `CategoryTerminal`，`DependsOn:["tcp"]`，`OptionalOn:["tls"]`，`TransformEvents:true`；TCP 为必需载体。链翻译分派 `http`，使用 `ParseHTTPConfigFromMap` 的单一解析面。顶层 `http` presence（包括空 map）由 `CheckProtoFlat` 拒绝，必须迁入 http 层。

8 个负例的拒绝面是：pattern 动态不支持；MSS 过小；顶层 flat `src_ip`；静态四元组多流复制；缺少 GBT 的 HTTP carrier；URI 使用 inc；method 使用动态；顶层 http 子映射。错误锚词以 cases JSON 为准，文档不替换实际文案。

## 7. 数据和动态行为

动态值由 flow index 逐流解析，不改变层链形状。HTTP 业务动态白名单共 6 个字段：`uri`、`body`、`body_b64`、`response_body`、`response_body_b64`、`response_status_code`。字符串字段支持 fixed/list/pattern，拒绝 inc/rand；`response_status_code` 支持 fixed/list/inc/rand，pattern 被拒。请求 method、version、headers、response headers、keep_alive、transactions、pipelined、chunk_size、file_source、encoding 等不支持动态对象。

层地址/端口动态由通用 IP/TCP 面处理；用例覆盖 TCP src_port/dst_port、IP src，以及 URI/body/response body/status 的 list/pattern/inc/rand/repro 形状。随机值以 cases 断言的 `distinct_values` 为观察契约，顺序不硬编码。

## 8. 门 1 §1–§14 十四行对照表

| §1 层链唯一真相 | 65 例 `spec_json` 顶层仅 `{layers}`；1 例额外 `src_ip`、1 例额外顶层 `http` 均为负例并登记 P4 缺口；完整目标样例见 §3 | `http.json` 机读 |
| §2 策略/任务 | 单 HTTP 流由层链模板定义；多流仅通过例级 `strategy_fc`（19 例）表达，事务数量住 http 层 | `http.json`、translate |
| §3 五件套 | 会话/事务/关联/插入/时间线分别见 §3；TCP 握手、HTTP 事务、FIN 顺序由 `Planner.Plan` 维护 | `http.go` |
| §4 查规范 | RFC 7230/7231/9112/879 + 落码 + `http.json` 字段/包数；未宣称 pcap/NIC 证据 | §5 |
| §5 依赖与错误 | registry `DependsOn:[tcp]`、`OptionalOn:[tls]`；8 负例按实际锚词登记 | registry、§6 |
| §6 性能 | 流式 channel、TCP MSS 分段、FileSource 缓存路径；性能数字待 P5 基准，不在本文承诺 | `http.go` |
| §7 三份文档 | `86-http-{design,testcase}.md`、D-HTTP-1/实现与 cases 机器契约；本协议无旧设计稿 | 修订记录 |
| §8 设计先行 | 本版为实现与 67 例先存后的 as-built 逆向定稿；定稿后以本文和 testcase 为唯一文档入口 | §1、§13 |
| §9 测试三源 | 规范 + 实现/registry/translate + `http.json` 67 ID；无今日 pcap/NIC 复跑声称 | testcase §5/§8 |
| §10 评审闭环 | 本轮文档自审 2 轮，末轮 clean；代码/用例改动不在本任务范围 | 修订记录 |
| §11 白话 | 首节头块已给出一句 HTTP 收发白话 | 本文头块 |
| §12 动态清单 | 6 个 HTTP 业务开关及序号算法位置见 §7/§11；通用 IP/TCP 动态另见实现 | `layer_dyn.go` |
| §13 schema 派生 | http registry 已有 Fields；不新增 schema，若改 Fields 必须重跑生成/校验 | registry |
| §14 真实流程 | cases 由策略/任务进入层 planner，再由 TCP builder 形成握手、分段和挥手；本版只写待 P5 重跑，不写通过 | testcase §7 |

### 8.1 §1 旧键逐键去向与完整目标例

本协议无旧设计稿；按机器契约逐键审计：`src_ip` 仅在 `http_neg_flat_src_ip` 以负例故意存在（目标去向 `layers[0].ip.src`）；HTTP 正例均把地址放 `layers[0].ip.src/dst`、端口放 `layers[1].tcp.src_port/dst_port`；`count` 不出现，多流用 `strategy_fc`；顶层 `http` 仅 `http_neg_top_http` 故意存在，正常配置迁入 `layers[-1].http`；`transactions`、`keep_alive`、`pipelined` 等业务键住 http 层。完整正常目标例即 §3 JSON。

## 9. 覆盖和 P4 缺口

机器契约 65/67 例为纯 `{layers}`，两种非纯形各 1 例，均为负例：`http_neg_flat_src_ip`（`{layers,src_ip}`，G-HTTP-1）、`http_neg_top_http`（`{layers,http}`，G-HTTP-2）。另有 `http_neg_missing_carrier_gbt` 使用 `[ip,tcp,gbt]` 而非 HTTP 终结层，作为 carrier 缺失负例（G-HTTP-3）。这些不是正例残留，也未被文档改写为通过。

P3 固定动作：同连接多轮由 `http_keepalive_multi_transactions`/`http_pipelined` 覆盖；非正常结束由负例拒绝契约覆盖；长保活由 keep-alive 三事务例覆盖。A′/B′ 缺口：真实 pcap/NIC 留证、完整动态拒绝矩阵、FileSource 注入路径、carrier 族联调和顶层迁移负例的任务链复跑，均待 P4/P5，不能宣称已通过。

## 10. 修订记录

- v1.0.0（2026-09-29）：首份 HTTP as-built 设计文档；机器契约 67 例（59 正、8 负）、三种顶层键形（纯 `{layers}` 65、`{layers,src_ip}` 1、`{http,layers}` 1）及门 1 十四行完成；未声称 pcap/NIC 测试通过。自审 2 轮，末轮 clean。

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
