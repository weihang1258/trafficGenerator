# GetWork（Bitcoin legacy 工作获取 RPC）设计契约

> 版本：v2.0.0（设计契约）
> 日期：2026-09-02
> 状态：v2.0.0 文档契约已完成；`getwork` 层、planner、validator 与生成器已注册，配套 62 条 cases 已完成层链迁移。本文保留待实现边界（动态策略扩展、pcap/NIC 实驱复核），不把未实驱内容宣称为已验收。
> 配套文件：`docs/protocols/getwork/testcase.md`、`trafficgen/test/protocol_pcap/cases/getwork.json`。
> 规范基线：Bitcoin legacy `getwork` JSON-RPC 接口（Bitcoin Wiki "getwork" 页——**data 字段 128B/256 hex、提交 = getwork(data) 单参**的口径出处；JSON-RPC 1.0 规范（jsonrpc.org spec 1.0——成员序 method/params/id、响应 result/error/id 三元组、无版本成员）；RFC 7230/7231（HTTP/1.1 请求行/状态行/头序/Content-Length/keep-alive）；RFC 7617（Authorization Basic）。BIP 22（getblocktemplate）与 X-Long-Polling 为显式边界（§1）。

## 1. 范围、profile 和实现边界

本契约覆盖 Bitcoin daemon（守护进程）/矿工之间以 **HTTP POST 承载的 legacy `getwork` JSON-RPC**：客户端申请一份工作（`getwork` + 空参数）、服务器返回 work 对象（`data`/`target`/`midstate`/`hash1`）、客户端修改 nonce 后以 **同一方法名 `getwork` + 单参 `data`** 提交、服务器返回 accepted（`result:true`）/rejected（`result:false`）/错误对象三态。

**协议事实（v2.0.0 更正，G-1/G-2）**：
- **`data` = 128 字节 = 256 个十六进制字符**（80B 区块头右补零到 128B——SHA-256 双轮 + midstate 64B 块对齐；Bitcoin Wiki getwork 口径）。v1.0.0 旧稿"64B/128 hex"**错一倍，作废**。`target`/`midstate` 各 32B/64 hex、`hash1` 64B/128 hex（hash1 为 legacy 常量，fixture 钉死 canonical 值，§3.4）。
- **提交方法名就是 `getwork`**：`method="getwork"`、`params=[data]`（单元素数组）。**不存在名为 `submit` 的 RPC 方法**（那是 Stratum 的 mining.submit）；v1.0.0 的 "submit 别名" 属臆造协议面，作废。用例 ID 保留 `submit` 字样仅为测试命名，覆盖列与方法名一律指回 `getwork(data)`。

**Authorization Basic 与状态码三态（G-3）**：bitcoind/矿池 RPC 现网**强制凭证**——请求默认携带 `Authorization: Basic <base64(user:pass)>`（fixture 钉死 `dXNlcjpwYXNz`）；无凭证请求得到 **HTTP 401**（观测正例）；RPC 层错误以 **HTTP 500 + `{"result":null,"error":{code,message},…}`** 返回（正例，保留请求 id）。HTTP 200 只承载 result:true/false/object 三态。

**JSON-RPC 形态（G-16 落字）**：本版 fixture **默认 1.0 形态**（请求无 `jsonrpc` 成员、成员序 `{"id":N,"method":…,"params":…}`；响应成员序 `{"result":…,"error":…,"id":N}`——与 bitcoind legacy 实际一致）；**2.0 形态**（`{"jsonrpc":"2.0",…}` 前置版本成员）为现网矿池代理真实存在形态，设一例观测正例，其余用例一律 1.0。序列化**恒紧凑**（无空格），成员序由本契约钉死（§3.2）——同一配置同一字节。

**显式边界（G-15，待实现不声称）**：`X-Long-Polling` 头与 longpoll 挂起请求（77-gbt 对的 getblocktemplate longpoll 族）**不在本版**；`getblocktemplate`/`getblockchaininfo` 等 BIP 22 及后继方法**不在本版**（配置注入归口 §7 `unknown_method` 负例）；HTTPS（8332 上的 TLS）**不在本版**（TLS 载体按既有 `tls` 层另行声明，`[ip,tcp,tls,http,getwork]` 属未来扩展）；chunked 传输编码**不在本版**（bitcoind RPC 响应恒 Content-Length 定界）；HTTP/1.0 + `Connection: close` 为合法观测形态（正例 11）。

**实现边界**：当前仓库已注册 `getwork` layer、planner、validator 和生成器；`cases/getwork.json` 已包含 45 个正例和 17 个负例，全部使用 `[ip,tcp,http,getwork]` 层链。真实 pcap/NIC 驱动复核仍是实现阶段验收，不把静态 cases 或单元测试冒充为实驱结果。

**输出契约（pcap/NIC 双输出，G-5）**：本契约的用例同时服务于 pcap（离线抓包文件）与 port_group/NIC（网卡输出，实测口 enp135s0f0np0）两种输出路径——两路径共用同一份 cases JSON、同一 tshark 字段/帧字节断言集与包数约定，不设仅单路径可用的断言；NIC 路径经 tcpdump 捕获（用例级 `nic_capture` 开关）后以同一断言集核验，网卡 checksum offload 不影响本契约（断言不含 IP/TCP 校验和字段）；MSS 跨段、多会话与并发在两路径均按 `tcp.stream` 重组或区分（与 64-cwmp/66-doh/68-hl7/75-stratum 同形）。

**动态值策略**：运行期 `id`、`data`/`target`/`midstate` 的具体值、nonce、share 结果为 fixture 钉死或配置值——本版 fixture **钉死全量样本值**（§3.4，G-12：`data=00…00/11×32/22×32/…` 可逐字节复算），动态性声明保留给实现期（同一输入同一输出；"动态"指跨事务取值不同，不指运行期随机）。断言用精确值、`same_as_packet`（关联）、`distinct`（跨事务）与 `json.path` 定位；不硬编码运行期时间戳。

## 2. 协议栈、端口和固定偏移

推荐层链 `[ip, tcp, http, getwork]`（**复用 `http` 层**承载请求行/状态行/头/Content-Length/keep-alive，能依赖绝不重复造轮子；IPv6 载体仍用 `ip` 层，配置合法 IPv6 字面，例如正例 44 的 `2001:db8::76 → 2001:db8::100:76`）。`getwork` 终结层只产出 JSON-RPC body 与事务序列。

端口：默认 `dst_port=8332`（bitcoind RPC 常见端口）；80 为常见 HTTP 载体正例；非默认显式端口（如矿池 9332）**显式声明即合法通道**，未声明的非常规端口拒绝（§7）。**非默认端口断言通道**：本机 tshark 3.6.14 实测（/tmp/getwork_v13/gw.pcap）——**8332 端口 HTTP POST 无需 decode-as 即自动解出**（启发式命中，Protocol 列 `HTTP/JSON`；80/9332 同），**无 DecodeAs 依赖**；若未来版本启发式行为变化，按实测补 `-d tcp.port==N,http` 并在用例文档 §1 登记版本口径。

固定偏移：无 VLAN、IP options、TCP options 时，HTTP 起行起点为 IPv4 offset（偏移）54（Ethernet 14 + IPv4 20 + TCP 20）、IPv6 offset 74（14 + IPv6 40 + TCP 20）。JSON-RPC body 在 HTTP body 内，起点 = 54/74 + 该 fixture 固定 HTTP 头集合的字节长（§3.1 头序钉死，偏移可预算）；HTTP 消息边界由 Content-Length 界定，**TCP 分段边界不是 HTTP/JSON 消息边界**（跨 MSS 用例见 §5）。

## 3. 线格式编码（逐项标注出处）

### 3.1 HTTP 载体规则（RFC 7230/7231；bitcoind RPC 现网形态）

| 交互 | HTTP 形态 | body |
|---|---|---|
| 申请工作 | UA→daemon `POST <uri> HTTP/1.1` + `Authorization: Basic` + `Content-Type: application/json` | `{"id":N,"method":"getwork","params":[]}` |
| 工作响应 | `HTTP/1.1 200 OK` + 同 Content-Type | `{"result":{work 对象},"error":null,"id":N}` |
| 提交工作 | 同连接 `POST`（同方法名） | `{"id":M,"method":"getwork","params":["<data>"]}` |
| 提交响应（三态） | `HTTP/1.1 200 OK` | `{"result":true,"error":null,"id":M}` / `{"result":false,…}` / `{"result":{status,share_id},…}` |
| RPC 错误 | **`HTTP/1.1 500 Internal Server Error`** + 同 Content-Type | `{"result":null,"error":{"code":C,"message":"…"},"id":K}` |
| 无凭证 | **`HTTP/1.1 401 Authorization Required`** + `WWW-Authenticate: Basic realm="jsonrpc"` | 空 body（Content-Length: 0） |

**请求头序（钉死，fixture 逐字节可预算）**：`POST 行` → `Host: <dst_ip>:<port>` → [`Authorization: Basic <b64>`（默认在场）] → `Content-Type: application/json` → `Content-Length: <N>` → `Connection: keep-alive`（末事务可 `close`）。**响应头序**：状态行 → `Content-Type: application/json` → `Content-Length: <N>` → `Connection: keep-alive`。HTTP/1.0 观测形态（正例 11）：请求行 `HTTP/1.0`、无 Host、响应 `Connection: close` 后紧跟 FIN 挥手。URI 默认 `/`，可显式声明 daemon 端点（如 `/rpc`，正例 5），planner 不得静默改写。

**规则**：HTTP 200 ≠ RPC 成功（业务状态在 result）；HTTP 500 承载 RPC error 且保留请求 id；401 body 恒空。keep-alive 连接上多事务按 Content-Length 分隔。

### 3.2 JSON-RPC 消息结构（JSON-RPC 1.0 spec；bitcoind 形态）

**1.0 形态（默认）**——请求成员序 `id, method, params`（无版本成员），响应成员序 `result, error, id`：

```
请求  = {"id":<id>,"method":"getwork","params":<params>}
申请  params = []                          ; 空数组
提交  params = ["<data 256 hex>"]          ; 单元素（G-2）
响应  = {"result":<true|false|work 对象|{status,…}>,"error":null,"id":<id>}
错误  = {"result":null,"error":{"code":<int>,"message":"<str>"},"id":<id>}
```

**2.0 观测形态（正例 10）**：请求前置 `"jsonrpc":"2.0"` 成员（`{"jsonrpc":"2.0","id":1,"method":…,"params":…}`），响应 `{"jsonrpc":"2.0","result":…,"error":null,"id":N}`。除该例外全用例 1.0。

**id 类型与关联**：id 为数字或字符串（两种形态均有例：数字序列 1/2/3 与字符串 `"rpc-001"`）；请求/响应按**同一 HTTP 会话内 id 配对**，响应 id 必须等于请求 id（负例 `id_mismatch`）。通知（无 id 请求）不是 getwork 的消息形态，不产生。

**序列化钉死**：恒紧凑（无空格、无转义外字符）；hex 字段恒小写；布尔恒 `true`/`false`；错误对象成员序 `code, message`。

### 3.3 work 对象逐字段（Bitcoin Wiki getwork；G-1 口径）

| 字段 | 类型 | 宽度（线上 hex 字符数） | 值域/默认 | 必选性 | 出处 |
|---|---|---|---|---|---|
| `data` | hex 字符串 | **恰 256**（128B：80B 区块头 + 48B 零填充；nonce 编码在区块头尾 4B，即 data 的第 153-160 hex 字符位） | `[0-9a-f]`；小写 | M | Wiki getwork（**G-1：旧稿 128 hex 作废**） |
| `target` | hex 字符串 | 恰 64（32B） | `[0-9a-f]` | M | Wiki getwork |
| `midstate` | hex 字符串 | 恰 64（32B） | `[0-9a-f]`；由 data 前 64B 导出（本版只断宽度/字符集，不断哈希值） | M | Wiki getwork |
| `hash1` | hex 字符串 | 恰 128（64B） | legacy 常量，fixture 钉死 canonical 值（§3.4） | M | Wiki getwork |
| `job_id` | — | — | **标准 getwork 无此字段**（v1.0.0 的"job_id 扩展"声明作废）；pool 扩展属 BIP 22 族边界 | 不产生 | §1 边界 |

**nonce 关联**：提交的 data = 最近申请 data 的副本、仅 nonce 4B 位（第 153-160 hex）改变——前 152 hex `same_as_packet`、后 96 hex（含 nonce 与填充）按 fixture 精确断言。nonce 变化不跨会话（负例 `cross_session_work`）。

### 3.4 fixture 常量与字节基线（G-12：全量钉死，逐字节可复算）

**fixture 常量**：IPv4 `192.0.2.76:4076 → 198.51.100.76:8332`；IPv6 `2001:db8::76 → 2001:db8:100:76`（端口同；实现取合法字面 `2001:db8::100:76`——四组无 `::` 缩写非法，gbt 判例）；非默认端口例 9332；auth `user:pass` → `Authorization: Basic dXNlcjpwYXNz`；id 数字序列 1/2/3…、字符串例 `"rpc-001"`；`data_work = "00000020" + "11"×32 + "22"×32 + "66dead00" + "1b0404cb" + "00000000"(nonce) + "00"×48`（256 hex）；`data_submit` 同 data_work 仅 nonce 位改 `"2f9f2e1d"`；`target = "00000000" + "ffff" + "00"×26`（8+4+52 = 64 hex）；`midstate = "33"×32`（64 hex）；`hash1 = "00000080" + "00"×56 + "80020000"`（128 hex，legacy 常量）；500 错误 `{"code":-32601,"message":"method not found"}`。

**核心消息长度公式**（紧凑 1.0 形态；N = len(id 字面)）：

| 消息 | 公式 | fixture 值（id=1/2） |
|---|---|---|
| getwork 申请请求 body | `38 + N` | 39B |
| work 响应 body | `78 + N + 256+64+64+128`（= `78+N+512`） | 591B（id=1） |
| 提交请求 body | `40 + N + 256` | 297B（id=2） |
| 布尔提交响应 body | `34 + N`（true）/ `35 + N`（false） | 35B/36B（id=2） |
| 对象提交响应 body | `57 + N + len(status) + len(share_id)` | 73B（status=accepted/share_id=sh-0001，id=2） |
| 500 错误响应 body | `52 + N + len(code 字面) + len(message)` | 75B（id=3，code=-32601/message=method not found） |
| 基线 HTTP 请求全长 | 头 156（含 Authorization）+ body | **195B** |
| 基线 HTTP 响应全长 | 头 96 + body | **687B** |

字节级 hex 基线（请求/响应前缀+后缀、短消息全 hex）见用例文档 §3。

### 3.5 提交与结果语义

提交必须引用**同一会话最近一次申请**的 data（nonce 修改后）；`result:true` 只证明线路 accepted 语义，不证明真实 PoW/区块（本版无链上下文，不断言 share 有效）；`result:false` 为可观察 rejected 正例；结果对象形态（`{status,share_id}`）为 schema 声明的合法第三态。**不能把 error 静默转成 accepted、不能把 200+result:null 误判为成功**（`error:null` 与 `result:null` 是两个位置——后者只见于 500 错误响应）。

## 4. 业务场景分析（现网典型场景与五层覆盖；G-10）

**定性**：声明式脚本化回放——配置是剧本（sessions[]/events[] 逐条声明两端 HTTP 事务），引擎是回放者。**事务模型（双层关联）**：外层 HTTP transaction（请求/响应按同一连接内顺序配对），内层 RPC id 配对；**无应用层会话状态机**——RPC 无状态，上下文由"id 配对 + 会话内最近 work"承载（显式声明，取代 v1.0.0 散文）。

| 现网场景 | 交互 | 驱动 | 对应用例 |
|---|---|---|---|
| ① 矿工冷启动申请 | POST getwork()→200 work | 矿工 | 1、2、13 |
| ② 挖掘循环 | getwork→改 nonce→getwork(data)→true/false→循环 | 矿工 | 26-32 |
| ③ 长连接复用 | keep-alive 连续多事务 | 矿工 | 33、34 |
| ④ 服务端错误与重试 | 500→同连接重发 | 矿工 | 8、40 |
| ⑤ 断流重连 | 连接断→新四元组→新 work | 矿工 | 41、42 |
| ⑥ 无凭证探测 | 缺 Authorization→401 | 观测 | 7 |
| ⑦ 多矿工并行 | 多会话按序/并发交错 | 矿场 | 37-39 |
| ⑧ 矿池代理（2.0 形态） | JSON-RPC 2.0 前置成员 | 代理 | 10 |

**五层覆盖逐层结论**：功能层——getwork 申请/提交/三态结果/401/500/1.0 与 2.0 形态/id 配对各一例，负例 17 行逐故障（§7）。性能层——MSS 跨段重组、多事务粘连拆分（35/36）。数据场景层——work 四字段宽度/字符集/边界 target、nonce 位关联、无 job_id。地址与流层——IPv4/IPv6/双栈、8332/80/9332 端口、多会话（按序）、**并发会话（`concurrent: true`，正例 38）**、RST/重连（42/41）；**流关联（控制流派生数据流）显式不适用**：getwork 单 HTTP 流承载全部 RPC，无控制/数据分离；**多流（会话内部并发流）显式不适用**：HTTP/1.1 单连接请求/响应严格配对（RFC 7230 §6.3）。业务层——上表八场景均为现网日常。

## 5. 会话/事务模型与状态（并发、重试、终止；G-4/G-9）

**多会话展开**：`sessions[]` 按序整块回放——先跑完第 1 个会话全部事件，再跑第 2 个，不交错；第二会话握手包号 = 前会话总包数 + 1。各会话四元组、id 序列、最近 work 互不串用。**并发会话（`concurrent: true`）**：多连接交错回放（正例 38）——交错只作用于生成器级多连接，各会话内部事务配对/id 关联不放宽；断言 N 值 `tcp.stream` distinct + 交织帧序 + 各会话 work/id 不串（判例 cwmp⑦/doh#24/onvif#56/hl7#26/megaco#45/bacnet#47）。**v1.0.0 "multi_flow" 术语作废**（多流 ≠ 多连接，G-4）。

**重试与重连分立**：重试（正例 40）= 同一连接上失败响应（500）后重发请求，重试请求 id 显式新值或声明关联；重连（正例 41）= 连接终止后新四元组新连接新 work 上下文，`tcp.stream` distinct。**终止口径**：全部 TCP 正例挥手统一 FIN/ACK×2（`terminates: true`）；RST 中断为独立正例 42（`tcp.flags.reset==1`、其后无 body 帧、无 FIN 挥手）；`Closed` 后不产生新业务帧（正例 43）。**保活口径**：HTTP keep-alive 连接复用即活性，**TCP 层 keepalive 探测不产生**（无应用层心跳帧）。

**包数约定（G-13）**：单事务会话 = 3（握手）+ 2（请求 1 + 响应 1）+ 4（FIN×2×ACK）= **9**；keep-alive N 事务 = 3 + 2N + 4；MSS 跨段 = 基线 +（实际段数 − 消息数）；RST 中断 = 3 + 1 + 1 = **5**（握手 3 + 请求 1 + RST 1）；重连 = Σ两连接；多会话按序/并发 = Σ会话（并发仅交织不改总数）。v1.0.0 的 12/10/16/24 拍脑袋值全部作废重算。

**HTTP body 重组**：body 跨多 TCP 段时按 `tcp.stream` 重组后解码；多个 HTTP 消息粘在同一段时按头/Content-Length 边界拆分（正例 35/36）。Content-Length 截断/过长/重复/不一致为负例（§7），不得用 FIN/PSH/包数自动补全。

## 6. 配置 typedef（JSON 形状；对齐 harness 形态）

```json
{
  "layers": [
    {"ip": {"src": "192.0.2.76", "dst": "198.51.100.76"}},
    {"tcp": {"src_port": 4076, "dst_port": 8332}},
    {"http": {}},
    {"getwork": {"sessions": [{"role": "miner", "events": [{"kind": "request", "id": 1, "method": "getwork"}, {"kind": "response", "result_kind": "work"}]}]}}
  ]
}
```

The previous flat example is superseded: addresses and ports now live in their carrier layers, and the getwork transaction tree is in the terminal layer.

形状要点：**顶层 layers**（无 protocol/config 包裹，与 cases JSON 占位/harness 一致）；`sessions[]` = 事件编排会话（各带四元组与事件序列；`concurrent: true` 顶层声明交错回放，§5）；`events[]` 元素为一笔 RPC 事务一侧（kind=request/response；request 带 `id/method/params`，params 可内联或 `params_from` 引用本会话最近 work 的派生 data；response 带 `status`（200/401/500）与 `result_kind`（work/true/false/object/error_object）；`auth` 会话级声明（缺省 = 无凭证 401 场景）；`http.uri/version/connection` 会话级覆盖）；`wire_fault` 仅负例注入口，**17 值枚举与 §7 表、用例文档 §5 三方同序一一映射**：`bad_json`、`body_truncated`、`content_length_mismatch`、`unknown_method`、`getwork_params_nonempty`、`submit_two_params`、`data_not_hex`、`data_length`、`field_missing`、`submit_work_uncorrelated`、`id_mismatch`、`cross_session_work`、`udp_carrier`、`port_undeclared`、`address_family`、`http_method_get`、`error_propagation`，不得成为线上字段。

**配置到帧路径**：配置 → validator（层链/载体/端口声明/id 配对/方法值域/params 形态/work 字段宽度字符集/nonce 关联/wire_fault 仅注入不落线）→ planner（events[] 展开，按 §3.4 公式计算 body 与头）→ worker（keep-alive 按事务组段、MSS 切段、pack 粘连）→ writer（PCAP/NIC 双输出，§1 契约）。

## 7. 错误处理（负例锚词表；G-6/G-7 原子拆分）

以下输入必须由 planner/validator 拒绝并传播为 task error（任务错误），不得产出成功 PCAP、`completed/0 packet` 或只剩 TCP/HTTP 外壳的假成功。**单一注入纪律：一行一例，钉死该行注入的单一 `wire_fault`；主锚词钉死单一字面值（备选括注）**，与用例文档 §5 表一一对应（17 行同序）：

| # | 负例 ID | `wire_fault` | 故障输入（单一注入） | 主锚词（备选） |
|---:|---|---|---|---|
| 46 | `getwork_neg_bad_json` | `bad_json` | 声明的 body 序列化后非合法 JSON（如手写 body 少闭括号） | `json` |
| 47 | `getwork_neg_body_truncated` | `body_truncated` | body 截断（Content-Length 声明值大于实际内容） | `truncat`（body） |
| 48 | `getwork_neg_content_length_mismatch` | `content_length_mismatch` | Content-Length ≠ 实际 body 字节数 | `content-length` |
| 49 | `getwork_neg_unknown_method` | `unknown_method` | method 取支持集外值（如 `getblocktemplate`——BIP 22 边界归口） | `method`（unknown） |
| 50 | `getwork_neg_getwork_params_nonempty` | `getwork_params_nonempty` | 申请请求 params 非空数组（如 `[data]`） | `params`（getwork） |
| 51 | `getwork_neg_submit_two_params` | `submit_two_params` | 提交请求 params 为两元素（如 `[data, flag]`） | `params`（submit） |
| 52 | `getwork_neg_data_not_hex` | `data_not_hex` | data 含非十六进制字符（如插入 `zz`） | `hex` |
| 53 | `getwork_neg_data_length` | `data_length` | data 长度 ≠ 256 hex（如 254/258） | `length`（data） |
| 54 | `getwork_neg_field_missing` | `field_missing` | work 对象缺任一必选字段（注入 hash1 缺失） | `hash1`（missing） |
| 55 | `getwork_neg_submit_work_uncorrelated` | `submit_work_uncorrelated` | 提交的 data 与本会话最近 work 无 nonce 关联（前 152 hex 不一致） | `correlation`（work） |
| 56 | `getwork_neg_id_mismatch` | `id_mismatch` | 响应 id 与请求 id 不一致（如请求 1 响应 9） | `id`（mismatch） |
| 57 | `getwork_neg_cross_session_work` | `cross_session_work` | 会话 B 的提交引用会话 A 的 work data | `session`（cross） |
| 58 | `getwork_neg_udp_carrier` | `udp_carrier` | UDP 载体承载 getwork（仅 TCP 上的 HTTP 合法） | `carrier`（udp） |
| 59 | `getwork_neg_port_undeclared` | `port_undeclared` | 非 8332/80 端口未显式声明（如 9443 静默使用） | `port`（undeclared） |
| 60 | `getwork_neg_address_family` | `address_family` | IPv6 地址配 IPv4 层链（或反向） | `family`（address） |
| 61 | `getwork_neg_http_method_get` | `http_method_get` | GET 方法承载 getwork 请求（必须 POST） | `post`（method） |
| 62 | `getwork_neg_error_propagation` | `error_propagation` | validator 已知错误被吞、任务 completed/0 packet 假成功 | `propagat`（error） |

**不得误报为 planner error 的合法协议事件（防误报）**：`result:false` rejected（业务拒绝是正例形态——用例 27）、HTTP 500 + error 对象（用例 8）、HTTP 401 无凭证响应（用例 7）、HTTP/1.0 + close（用例 11）、2.0 形态（用例 10）、无 `job_id`（标准形态，用例 22）、字符串 id（用例 14）、非 `/` URI（用例 5）。只有配置、载体、JSON/HTTP 编码、字段宽度/字符集、关联错误进入负例。

## 8. 边界

- **BIP 22 / getblocktemplate / X-Long-Polling**：显式不产生（§1）；配置注入归口 `unknown_method` 负例。
- **HTTPS（8332 TLS）**：不在本版；TLS 按 `tls` 层另行声明。
- **chunked 传输编码**：不产生（恒 Content-Length 定界）；配置声明归口 `content_length_mismatch` 拒绝。
- **通知（无 id 请求）/服务端主动推送**：不是 getwork 消息形态，不产生。
- **真实 PoW/区块/难度验证**：不断言（无链上下文）；`result:true` 仅线路语义。
- **job_id / pool 扩展字段**：标准接口无此字段，不产生（§3.3）；v1.0.0 "job_id 扩展" 声明作废。

## 9. 原子 ID 与完成定义

**ID 权威 = 用例文档 §2**（G-14，megaco D-1/bacnet D-1 判例）：设计不维护逐 ID 全量镜像表——设计、testcase 与 `getwork.json` 使用同一 **62 个语义 ID 集合与顺序（45 正 + 17 负）**，权威序以用例文档 §2 为准，设计按簇给出覆盖图景。原子原则：一个用例只验证一个协议行为。

**正例 45 条按簇**（编号 = 用例文档 §2 行号）：载体/HTTP/形态族（1-16：IPv4/IPv6/80/9332 四载体、URI 变体、Basic 凭证、401/500、1.0/2.0 形态、HTTP/1.0、Host 头、id 数字序列/字符串/边界值、空参数形态）；work 字段族（17-25：四字段宽度各一、字符集、无 job_id、json.path 通道、target 边界、error:null 三元组形状）；提交族（26-32：true/false/object 三态、单参形态、nonce 位关联、循环、跨事务 distinct work）；会话/流/中断族（33-45：keep-alive 多事务与末事务 close、MSS 跨段、粘连拆分、多会话、并发、状态隔离、500 重试、重连、RST、FIN 后无帧、双栈、双输出一致性）。

**负例 17 行（46-62）**：JSON/HTTP 编码×3、方法/参数×3、work 字段×3、关联×3、载体×4、传播×1——逐行见 §7 表。

完成定义：`getwork` layer、planner、validator、生成器均已注册；§3 全部线格式（HTTP 头序/三态状态码/紧凑 1.0 与 2.0 JSON/work 四字段/nonce 关联）、§5 会话模型（id 配对、keep-alive、重试/重连分立、并发）、§7 错误传播（17 行主锚词）均有对应契约；45 个正例断言（http.* + json.* 双通道 + frames hex）与 17 个负例错误传播已落入 cases；pcap/NIC 双输出共用本契约（§1），真实双路径驱动复核仍待实现阶段验收。BIP 22 族、TLS、chunked 仍仅在明确实现后才可增加对应断言。

## 11. CORE 对照与实现门

### 11.1 D1 规范要求→场景→现状→缺口矩阵

| 规范要求 | 业务场景 | 代码现状 | 缺口/验收 |
|---|---|---|---|
| JSON-RPC 1.0 请求/响应成员与 id 配对 | 申请、提交、循环 | getwork planner/generator 已接入 | 正例 1/13/26 验收 |
| getwork 四字段宽度/hex | work 返回 | builder fixture 已接入 | 正例 17–25；宽度和字符集逐项验收 |
| HTTP POST、Content-Length、keep-alive | 单连接多事务 | 复用 http 层契约 | 正例 33/35/36；负例 47/48 |
| 401/500 错误状态 | 无凭证、RPC 错误 | builder/planner 已接入 | 正例 7/8；不得当 planner 错误 |
| 同连接提交 nonce 关联 | 挖掘循环 | session planner/generator 已接入 | 正例 26/30/39 |
| 长短连接与异常终止 | close、RST、重连 | 层链 transport 接入；实驱待验 | 正例 40–43 |
| IPv4/IPv6 与显式端口 | 双栈、80/9332 | ip/tcp 层承载 | 正例 2–4/44；负例 59/60 |
| legacy 与代理 2.0 方言 | 1.0 默认、2.0 观测 | builder 已接入；实驱待验 | 正例 9/10；2.0 仅观测形态 |

**命令×响应码矩阵**：申请→200/work、401/空 body；提交→200/true、200/false、200/object；RPC 错误→500/error；每格分别由 1/7/26/27/28/8 覆盖。**数据形态变体表**：IPv4/IPv6、8332/80/9332、HTTP/1.0/1.1、1.0/2.0 JSON、数字/字符串 id、空/单参数、四字段宽度/字符集、粘连/MSS、RST/FIN，分别由 §9 用例簇覆盖。**商业行为→用例映射**：bitcoind legacy 冷启动=1/2，矿工循环=26/31/32，keep-alive=33/34，认证=6/7，矿池代理=10，错误重试=8/40；尚无本仓库现网抓包，需注册后按 pcap 复核。

### 11.2 D2 三路依据与候选方案

规范依据为 Bitcoin Wiki getwork、JSON-RPC 1.0、RFC 7230/7231/7617（§1/§3）；商业行为基于 bitcoind legacy 的 Basic、Content-Length、200/401/500 形态（注册后以现网 pcap 复核）；开源实现思路借鉴 Bitcoin Core legacy RPC 的 method/params/result/error 组织（不搬代码）。候选方案：A 在 getwork 终结层生成完整 HTTP，优点单文件可控、缺点重复 HTTP；B 复用 `[ip,tcp,http,getwork]`，优点复用分段/keep-alive/头处理、缺点需定义终结层事件接口。选 B，避免重复载体实现。

### 11.3 D3/D4/D5 执行约束

依赖顺序为 ip→tcp→http→getwork；任一前置层、事件序列、字段宽度或 nonce 关联失败，validator/planner 返回 task error，停止该任务，不重试配置错误；运行期连接 RST/500 按 §5 事件语义结束或重试。性能验收不承诺未测数字：目标为流式生成、不聚合全量 body；单消息最大 687B（§3.4），并发规模以 buffer/队列配置为上限，需记录包/秒、bit/s、会话数、峰值内存、队列积压、CPU。pcap 路径用 tshark 校验字段/重组，NIC 路径用 tcpdump 后复用同断言；基线、目标规模、压力、长时、并发交错、背压六类均需记录。改动文件为 getwork layer/planner/validator、对应 cases 与文档；接口沿现有层注册和任务入口；回滚为撤销 getwork 注册及三文件迁移，恢复占位例。

### 11.4 D6 动态字段清单

四元组动态字段均落 carrier 层：`src_ip`/`dst_ip` 在 `ip`，`src_port`/`dst_port` 在 `tcp`；按流序号使用 fixed/inc/rand/list/pattern 时需由通用 dynamic_value 求值，未声明即 fixed，`src_port` 仅有 `12345+i` 保底。业务 `id`、nonce/data、URI、Authorization、work 四字段、share 结果当前均为 fixture/fixed；尚未有 getwork 专用序号实现，注册时必须在 planner 文件补充确定性 `i` 算法并以 12.4/12.15 五格用例验收，不能宣称自动动态。

### 11.5 D7/D8 门表

| 门1条目 | 去向/证据 |
|---|---|
| §1 旧 `src_ip/dst_ip/src_port/dst_port/count` 与顶层 `getwork` | 地址/端口进 ip/tcp，数量进 flow_control；业务进终结层；完整例见 §6.1 与 testcase §7 |
| §3 五件套 | 会话、事务、关联、插入位置、时间线见 §4–§5；单 HTTP 流无控制/数据分离，已明确不适用并有 3.15 用例 |
| §12 动态清单 | 四元组及业务字段见 §11.4；实现前需补序号算法代码位置 |

层链已迁移可确认字段；当前无处安置的动态业务算法不是顶层豁免，而是 **GW-DYN-1**：在 getwork planner 注册时补通用 dynamic_value 接线、五策略序号测试后关闭。动态策略扩展属于实现阶段待办，不影响已落地的静态层链契约。


- v1.0.0（2026-08-21）：旧稿首版（20 = 14 正 + 6 负，未过审查流程）。
- v2.0.0（2026-09-02，v1.3 重写级修复轮）：独立审查报告（docs-bacnet，/tmp/getwork_v13/report.md）17 findings = C 7 / D 7 / N 3 + §0 行为面枚举 ~90 测试点逐条落，20 → **62 例（45 正 + 17 负）**。逐条落点：**G-1（C）** data 字段 128B/256 hex 更正（旧稿错一倍）；**G-2（C）** 臆造 submit 方法名删除——提交 = getwork(data) 单参、job_id 扩展声明作废（§1/§3.2/§3.3）；**G-3（C）** Authorization Basic 默认形态 + 401/500 正例（§1/§3.1）；**G-4（D）** multi_flow 术语作废 → concurrent:true 并发会话（§5/§6 + 正例 38）；**G-5（D）** §1 双输出契约段（六项式）；**G-6（C）** 负例 6 行打包 → 17 行原子拆分（§7）；**G-7（C）** wire_fault 8 值 → 17 值三方同序映射（§6/§7/用例 §5）；**G-8（D）** 版本化 tshark 实测基线（8332 免 decode-as、json.* 断言通道）+ 9332 非默认端口正例（§2/用例 §1）；**G-9（D）** RST/重连分立正例 + 保活口径 + terminates 声明（§5）；**G-10（C）** §4 业务场景八场景 + 五层结论 + 事务模型双层关联节；**G-11（C）** §3.1-§3.4 逐字段表 + 头序/成员序/紧凑序列化钉死 + 长度公式表；**G-12（D）** fixture 常量全量钉死（含 canonical hash1、base64 样本）+ hex 基线（用例 §3）；**G-13（D）** 包数约定节 + 逐例重算（单事务 = 9，旧稿 12/10 作废）；**G-14（N）** 依据列 + ID 权威 = 用例 §2；**G-15（D）** BIP 22/longpoll/TLS/chunked 显式边界（§1/§8）；**G-16（N）** 1.0 形态钉死为默认 + 2.0 观测例（正例 10）+ HTTP/1.0 观测例（正例 11）；**G-17（N）** JSON notes 注册同步项登记（用例 §7）。**状态记录**：v2.0.0 文档与 62 条层链 cases 已完成；真实 pcap/NIC 驱动复核与动态策略扩展仍属实现阶段边界。
