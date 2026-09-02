# GBT（GetBlockTemplate，BIP 22/23 区块模板 RPC）设计契约

> 版本：v2.0.0（设计阶段）
> 日期：2026-09-02
> 状态：按《协议设计文档与用例文档需求文档 v1.3》对 v1.0.0 初稿（2026-08-21）执行**重写级修复轮**（独立审查报告 /tmp/gbt_v13/report.md：CRITICAL 6 + MAJOR 10 + MINOR 4 + N 3，行为面 114 点 ✓50/半20/✗44）；本版为修复轮产物：20 → **81 例（53 正 + 28 负）**，待复验关闭。`gbt` 层尚未注册，不修改 Go（编程语言）/MCP（模型上下文协议）实现，不宣称当前 suite（测试套件）可运行。
> 配套文件：`docs/protocol-designs/77-gbt-testcase.md`、`trafficgen/test/protocol_pcap/cases/gbt.json`（当前 JSON 仅含注册前置占位，本版不写文件、不改代码）
> 规范基线：**BIP 22**（getblocktemplate——模板 25 键/longpoll 机制/submitblock/workid/mutable 定义值/proposal 模式）；**BIP 23**（getblocktemplate 服务的 pooled block validation——proposal 模式出处）；RFC 7230/7231（HTTP/1.1）；RFC 7617（Authorization Basic）。BIP 9（vbavailable/vbrequired）与 BIP 145（segwit 扩展）为显式边界（§1/§8）。

## 1. 范围、profile 和未注册边界

本契约覆盖 Bitcoin daemon（守护进程）/矿工之间以 **HTTP POST 承载的 `getblocktemplate`/`submitblock` JSON-RPC**（BIP 22，与 76-getwork 同族）：客户端请求区块模板（可带 rules/capabilities/longpollid/mode 参数）、服务器返回模板对象（版本/前块哈希/交易集/coinbase 参数/target/bits/时间/高度等）、客户端组装区块后 `submitblock` 提交、服务器返回接受（`result:null`）/拒绝（`result:"<reason>"`）/错误对象三态；模板轮询与 longpoll 挂起（BIP 22 §Long Polling）。

**层链更正（G-4/G-5，v1.0.0 主层链错误作废）**：GBT 是 HTTP JSON-RPC，**主层链 `[ip, tcp, http, gbt]`**（IPv6 `[ipv6, tcp, http, gbt]`）——**复用 `http` 层**承载请求行/状态行/头/Content-Length/keep-alive（项目准则"能依赖绝不重复造轮子"）；v1.0.0 的 `[ip, tcp, gbt]` 裸 TCP JSON 主层链与自身 HTTP 语义矛盾，作废。**`jsonrpc-line` profile 删除（G-6）**：GBT 无 TCP 裸行形态（那是 stratum 族载体）；配置取该值归口 §7 `line_profile` 负例拒绝。

**longpoll 真实语义（G-11，v1.0.0 描述错误作废）**：按 BIP 22 §Long Polling——模板响应携带 **`longpolluri`** 字段；客户端向该 URI 发起**独立请求**（params 携带最近模板的 **`longpollid`**），服务器**挂起**直至新模板可用再返回。v1.0.0"下一次 getblocktemplate params 中提交该 ID"的简化描述作废。

**Authorization Basic 与状态码三态（G-12/G-13）**：现网 Bitcoin RPC 强制 `Authorization: Basic <base64(user:pass)>`（fixture 钉死 `dXNlcjpwYXNz`）；无凭证 → **HTTP 401**（观测正例）；服务端错误 → **HTTP 500 + `{"result":null,"error":{code,message},…}`**（正例，保留请求 id）。**HTTP 状态码 ≠ JSON-RPC error 分离断言**（HTTP 200 只承载 result 三态，业务状态在 result/error——对照 mmse"HTTP 200 ≠ MMS 状态"同款）。

**JSON-RPC 形态（N-3 落字）**：本版 fixture 默认 **bitcoin-cli 形态**——请求带 `"jsonrpc":"1.0"` 成员、成员序 `jsonrpc,id,method,params`；响应**无** jsonrpc 成员、成员序 `result,error,id`（与 /tmp/gbt_v13 probe 实测一致；与 76-getwork 的"1.0 无成员"默认各自钉死、互不强制）。2.0 形态（请求/响应均带 `"jsonrpc":"2.0"`）设一例观测正例。序列化恒紧凑，成员序由本契约钉死（§3.2）。

**显式边界（G-14，待实现不声称）**：**BIP 9**（模板 `vbavailable`/`vbrequired` 版本位部署字段）**不在本版**（归口 `bip9_field` 负例）；**BIP 145**（segwit 扩展：`default_witness_commitment` 字段、`sigoplimit`/`sizelimit` 的 `{base,total}` 对象形态、tx 元素 `weight` 字段）**不在本版**（归口 `witness_commitment` 负例；本版 limits 恒标量）；**`coinbasetxn` 完整模板形态**（capability=coinbasetxn 时替代 coinbaseaux/coinbasevalue）**不在本版**（归口 `coinbasetxn_form` 负例）；**TLS/HTTPS**（8332 上 TLS）不在本版（`tls` 层另行声明）；**chunked** 不产生（恒 Content-Length 定界）；`rules` 支持集 = `{segwit}`，未知 rule 归口 `unknown_rule` 负例。

**动态值两类纪律（G-18，v1.0.0 自相矛盾作废）**：**值域枚举与预配置常量允许 fixture 精确断言**（bits=1d00ffff、noncerange=00000000ffffffff、coinbasevalue=5000000000、height=1000 等——§3.4 全量钉死）；**运行期值禁硬编码**（跨事务递增的 curtime/longpollid 变体、tx data 内容按 fixture 变体精确给定但断言用前缀+nonzero）。本版 fixture 钉死全量样本值（同一输入同一输出），动态性指跨事务取值不同。

**未注册边界**：当前仓库没有注册 `gbt` layer/planner/validator/生成器。`cases/gbt.json` 只保留 `gbt_neg_unregistered` 注册前置占位（`expect_error=true`、`error_contains` 精确为 `unknown layer`），不计入 81 个语义 ID；占位的拒绝、0 包或空 PCAP 不得报告为 GBT 行为通过。

**输出契约（pcap/NIC 双输出，G-8）**：本契约的用例同时服务于 pcap（离线抓包文件）与 port_group/NIC（网卡输出，实测口 enp135s0f0np0）两种输出路径——两路径共用同一份 cases JSON、同一 tshark 字段/帧字节断言集与包数约定，不设仅单路径可用的断言；NIC 路径经 tcpdump 捕获（用例级 `nic_capture` 开关）后以同一断言集核验，checksum offload 不影响本契约（断言不含 IP/TCP 校验和字段）；MSS 跨段、多会话与并发在两路径均按 `tcp.stream` 重组或区分（与 64-cwmp/66-doh/75-stratum/76-getwork 同形）。**v1.0.0 的 #14 `gbt_pcap_nic_consistency` 用例删除**（测试方法非协议语义——hl7 v2.0 判例；其内容并入本契约段）。

## 2. 协议栈、端口和固定偏移

主层链 `[ip, tcp, http, gbt]`（§1）；`gbt` 终结层只产出 JSON-RPC body 与事务序列。端口：默认 `dst_port=8332`；非默认显式端口（如 18332 测试网惯例）**显式声明即合法通道**（正例），未声明的非常规端口拒绝（§7）。**非默认端口断言通道（G-10，实测背书）**：本机 tshark 3.6.14 实测（/tmp/gbt_v13/probe.pcap frame 9）——**18332 端口同载荷 http+json 全自动解出**，断言通道经 `Content-Type: application/json` 触发 http→json 内层 dissect，**与端口无关、无 DecodeAs 依赖**（8332 本身亦非 http 注册端口，TCP 路径启发式识别）。

固定偏移：无 VLAN、IP options、TCP options 时，HTTP 起行起点为 IPv4 offset（偏移）54（Ethernet 14 + IPv4 20 + TCP 20）、IPv6 offset 74。JSON-RPC body 在 HTTP body 内，起点 = 54/74 + 固定头集合字节长（§3.1 头序钉死）；HTTP 消息边界由 Content-Length 界定，**TCP 分段边界不是 HTTP/JSON 消息边界**（跨 MSS 用例见 §5）。

## 3. 线格式编码（逐项标注出处；G-3 逐字段规格）

### 3.1 HTTP 载体规则（RFC 7230/7231；Bitcoin RPC 现网形态）

| 交互 | HTTP 形态 | body |
|---|---|---|
| 请求模板 | UA→daemon `POST <uri> HTTP/1.1` + `Authorization: Basic` + `Content-Type: application/json` | `{"jsonrpc":"1.0","id":N,"method":"getblocktemplate","params":[…]}` |
| 模板响应 | `HTTP/1.1 200 OK` + 同 Content-Type | `{"result":{模板对象},"error":null,"id":N}` |
| longpoll 挂起 | 同连接或独立连接 POST `<longpolluri>` | params 携带 `{"longpollid":"…"}`（BIP 22） |
| 提交区块 | 同连接 `POST`，`submitblock` | `{"jsonrpc":"1.0","id":M,"method":"submitblock","params":["<hexdata>"[,"<workid>"]]}`（G-16：双参形态） |
| 提交响应三态 | `HTTP/1.1 200 OK` | `{"result":null,…}`（接受）/ `{"result":"<reason>",…}`（拒绝）/ `{"result":true,…}`（proposal 通过） |
| RPC 错误 | **`HTTP/1.1 500 Internal Server Error`** | `{"result":null,"error":{"code":C,"message":"…"},"id":K}` |
| 无凭证 | **`HTTP/1.1 401 Authorization Required`** + `WWW-Authenticate: Basic realm="jsonrpc"` | 空 body |

**请求头序（钉死）**：`POST 行` → `Host: <dst_ip>:<port>` → [`Authorization: Basic <b64>`（默认在场）] → `Content-Type: application/json` → `Content-Length: <N>` → `Connection: keep-alive`（末事务可 close）。**响应头序**：状态行 → `Content-Type` → `Content-Length` → `Connection`。URI 默认 `/`；**longpoll 请求的 URI 取自模板 `longpolluri` 字段**（BIP 22——fixture `http://198.51.100.77:8332/longpoll`，planner 不得静默改写为 `/`）。

### 3.2 JSON-RPC 消息结构（bitcoin-cli 形态默认；§1 N-3）

```
请求  = {"jsonrpc":"1.0","id":<id>,"method":<method>,"params":<params>}
响应  = {"result":<值>,"error":null,"id":<id>}          ; 无 jsonrpc 成员
错误  = {"result":null,"error":{"code":<int>,"message":"<str>"},"id":<id>}
2.0 观测形态（正例 8）：请求/响应均前置 "jsonrpc":"2.0"
```

**方法与参数（BIP 22/23）**：

| method | params | 说明 |
|---|---|---|
| `getblocktemplate` | `[]`（基线）或 `[{options}]` | options 成员：`rules`（数组，支持集 `{segwit}`，正例 14）/`capabilities`（客户端能力数组）/`mode`（`"template"` 缺省｜`"proposal"`——BIP 23，携 `data` hexdata）/`longpollid`（longpoll 挂起请求携最近模板 ID，BIP 22） |
| `submitblock` | `["<hexdata>"]` 或 `["<hexdata>","<workid>"]` | hexdata 必选（区块 hex）；workid 可选第二参——**回传模板 workid 关联工作**（G-15/G-16） |

**id 类型与关联**：数字或字符串（两种均有例）；请求/响应按同一 HTTP 会话内 id 配对（响应 id = 请求 id，负例 `id_mismatch`）。

### 3.3 模板对象逐字段（BIP 22 §Block Template；G-3 逐字段表）

**本版模板顶层键序（18 键 = 14 必选 + 4 可选，紧凑序列化，成员序钉死）**：

| # | 键 | 类型 | 线上形态 | 值域/fixture 值 | 必选性 | 出处 |
|---:|---|---|---|---|---|---|
| 1 | `version` | int | 数值 | 536870912（0x20000000） | M | BIP 22 |
| 2 | `previousblockhash` | hex 串 | **恰 64 hex**（32B 内部序） | `11`×32 | M | BIP 22 |
| 3 | `transactions` | 数组 | 空数组或 tx 元素数组 | 空（基线）/1 元素/3 元素（大模板变体） | M | BIP 22 |
| 4 | `coinbaseaux` | 对象 | `{"flags":"<hex>"}` | flags=`706f6f6c31`（矿池标签 hex，G-17） | M | BIP 22 |
| 5 | `coinbasevalue` | int | 数值（大整数） | 5000000000（50 BTC 聪） | M | BIP 22 |
| 6 | `target` | hex 串 | **恰 64 hex** | `00000000ffff`+`00`×26 | M | BIP 22 |
| 7 | `mintime` | int | 秒 | 1756684800 | M | BIP 22 |
| 8 | `mutable` | 字符串数组 | 数组 | **定义值**：`["time","transactions","prevblock"]`（BIP 22 定义值全集；BIP 145 扩展值不产生，G-17） | M | BIP 22 §Mutable |
| 9 | `noncerange` | hex 串 | **恰 16 hex**（8B） | `00000000ffffffff` | M | BIP 22 |
| 10 | `sigoplimit` | int | 标量数值 | 80000（**BIP 145 对象形态不产生**，§1） | M | BIP 22/145 边界 |
| 11 | `sizelimit` | int | 标量数值 | 4000000（同上） | M | BIP 22/145 边界 |
| 12 | `curtime` | int | 秒 | 1756685100（≥ mintime） | M | BIP 22 |
| 13 | `bits` | hex 串 | **恰 8 hex**（4B） | `1d00ffff` | M | BIP 22 |
| 14 | `height` | int | 正整数 | 1000；刷新模板递增 +1（负例 `height_nonincrement`） | M | BIP 22 |
| 15 | `longpollid` | 字符串 | 任意标识 | `lp-1000-1`（longpoll 模板在场） | O | BIP 22 §Long Polling |
| 16 | `longpolluri` | 字符串 | URI | `http://198.51.100.77:8332/longpoll` | O | BIP 22 §Long Polling（**G-11：挂起请求发往此 URI**） |
| 17 | `capabilities` | 字符串数组 | 数组 | `["proposal"]`（服务器能力） | O | BIP 22 |
| 18 | `workid` | 字符串 | 任意标识 | `w-1`（submitblock 第二参回传，G-15） | O | BIP 22 |

**tx 元素键序（6 键）**：`data`（hex 串，交易线格式）/`txid`（64 hex）/`hash`（64 hex，BIP 145 witness txid 不产生）/`depends`（数组，空）/`fee`（int）/`sigops`（int）。

**不产生边界字段（§1/G-14，注入归口负例）**：`vbavailable`/`vbrequired`（BIP 9）、`default_witness_commitment`（BIP 145）、`coinbasetxn`（完整 coinbase 交易形态）、tx 元素 `weight`（BIP 145）。

### 3.4 fixture 常量与消息长度（G-3/G-12：全量钉死）

**fixture 常量**：IPv4 `192.0.2.77:4077 → 198.51.100.77:8332`；IPv6 `2001:db8::77 → 2001:db8:100:77`；非默认 18332；auth `user:pass` → `dXNlcjpwYXNz`；id 1/2/3…、字符串例 `"rpc-001"`、大数值 `2147483647`；模板 18 键值 = §3.3 表 fixture 列（version=536870912、prevhash=`11`×32、coinbaseaux.flags=`706f6f6c31`、coinbasevalue=5000000000、target=`00000000ffff`+`00`×26、mintime=1756684800、curtime=1756685100、mutable 三值、noncerange=`00000000ffffffff`、sigoplimit=80000、sizelimit=4000000、bits=`1d00ffff`、height=1000、longpollid=`lp-1000-1`、longpolluri=`http://198.51.100.77:8332/longpoll`、capabilities=`["proposal"]`、workid=`w-1`）；tx 元素 data=`02`+`ab`×99+`aa`（202 hex）、txid=`22`×32、hash=`33`×32、depends=[]、fee=1000、sigops=1；submitblock hexdata=`aa`×80（160 hex）；刷新模板 height=1001、curtime+600、longpollid=`lp-1001-1`；大模板变体 = 3 个 tx 元素 data=`ff`×740；500 错误 `{"code":-1,"message":"getblocktemplate: unsupported rule"}`；proposal 拒绝理由 `"prev-blk-not-found"`。

**核心消息长度公式**（紧凑序列化；N = id 字面十进制位数）：**请求 body = `45 + N + len(method 名) + len(params JSON)`**（`getblocktemplate` 16 字符、`submitblock` 11 字符）；**响应 body = `30 + N + len(result JSON)`**；**错误响应 body = `29 + N + len(error 对象)`**。

| 消息 | 构成 | fixture 值（程序复算钉死） |
|---|---|---|
| 基线请求 body（空参 params=[]） | `45+N+16+2` | 64B（id=1） |
| rules 请求 body（params 22B） | `45+N+16+22` | 84B（id=1，["segwit"]） |
| longpoll 请求 body（params 28B） | `45+N+16+28` | 90B（id=2，lp-1000-1） |
| proposal 请求 body（params 233B） | `45+N+16+233` | 295B（id=3，data 202 hex） |
| submitblock body（单参 params 164B） | `45+N+11+164` | 221B（id=4，160 hex） |
| submitblock body（workid 双参 params 170B） | `45+N+11+170` | 227B（id=4，w-1） |
| 模板响应 body（18 键模板 576B） | `30+N+576` | **607B**（id=1） |
| 普通模板响应 body（14 必选键模板 457B） | `30+N+457` | 488B（id=1，无可选族） |
| 1-tx 模板响应 body（模板 853B） | `30+N+853` | 884B（id=1） |
| 大模板响应 body（3×740 hex data 模板 5481B） | `30+N+5481` | **5512B**（id=1，HTTP 全长 5609B 跨 4 MSS 段） |
| 接受（null）/proposal 通过（true）响应 body | `30+N+4` | 35B（id=4/3） |
| 拒绝理由响应 body（reason 带引号 20B） | `30+N+20` | 51B（prev-blk-not-found，id=4） |
| 500 错误响应 body（error 对象 59B） | `29+N+59` | 89B（id=5） |
| 基线 HTTP 请求全长 | 头 156 + body | **220B** |
| 基线模板响应全长 | 头 96 + body | **703B** |

字节级 hex 基线（请求/响应前缀+后缀、短消息全 hex）见用例文档 §3。

### 3.5 提交与关联语义（BIP 22）

`submitblock` 的 hexdata 必选、workid 可选（回传最近模板 `workid`——longpoll 模板刷新后提交防错块，负例 `workid_mismatch`）；接受 = `result:null`（**null 是 BIP 22 接受语义**，非错误——error 位为 null 才是无错）、拒绝 = `result:"<reason>"` 字符串（正例观测形态，不伪装 accepted）；proposal 模式（BIP 23）响应 `result:true`（通过）/`"reason"`（拒绝）。**不能把 HTTP 200+error 对象误判为成功**（500 承载 error 且保留 id）。

## 4. 业务场景分析（现网典型场景与五层覆盖；G-1）

**定性**：声明式脚本化回放——配置是剧本（sessions[]/events[] 逐条声明两端 HTTP 事务），引擎是回放者。**事务模型（双层关联）**：外层 HTTP transaction（同连接内顺序配对），内层 RPC id 配对；**无应用层会话状态机**——RPC 无状态，上下文由"id 配对 + 会话内最近模板（workid/longpollid/height）"承载（显式声明）。

| 现网场景（BIP 22/23） | 交互 | 驱动 | 对应用例 |
|---|---|---|---|
| ① 矿工冷启动取模板 | POST getblocktemplate([])→200 模板 | 矿工 | 1、2、9 |
| ② 挖掘提交循环 | 取模板→组装→submitblock→null/reason | 矿工 | 36-40 |
| ③ 模板轮询刷新 | 再取模板（height+1） | 矿工 | 35 |
| ④ longpoll 挂起 | 模板给 longpolluri→独立请求携 longpollid→挂起返回新模板 | 矿工 | 30-32 |
| ⑤ 矿池标签与能力协商 | coinbaseaux.flags / rules / capabilities | 矿池 | 14、15、26 |
| ⑥ proposal 验证 | mode=proposal+data→true/reason | 矿池 | 39、40 |
| ⑦ 无凭证探测 | 缺 Basic→401 | 观测 | 5 |
| ⑧ 多矿工并行 | 多会话按序/并发交错 | 矿场 | 45-47 |

**五层覆盖逐层结论**：功能层——两方法各形态（基线/rules/longpoll/proposal/submitblock 三态）、401/500、1.0/2.0 形态、id 配对各一例，负例 28 行逐故障（§7）。性能层——大模板跨 MSS（53）、多响应打包跨段（43）、粘连拆分（44）。数据场景层——模板 17 键逐键宽度/值域例（17-29）、tx 元素、coinbaseaux/mutable/limits 值。地址与流层——IPv4/IPv6/双栈、8332/18332、多会话（按序）、**并发会话（`concurrent: true`，正例 46）**、RST/重连（50/49）；**流关联（控制流派生数据流）显式不适用**：模板在 HTTP 响应体内带内传输，无派生流；**多流（会话内部并发流）显式不适用**：HTTP/1.1 单连接请求/响应严格配对（RFC 7230 §6.3）。业务层——上表八场景均为现网日常。

## 5. 会话/事务模型与状态（并发、重试、终止；G-7）

**多会话展开**：`sessions[]` 按序整块回放（第二会话握手包号 = 前会话总包数 + 1）；各会话四元组、id 序列、最近模板互不串用。**并发会话（`concurrent: true`）**：多连接交错回放（正例 46）——交错只作用于生成器级多连接，各会话内部事务配对/id 关联不放宽；断言 N 值 `tcp.stream` distinct + 交织帧序 + 各会话模板/id 不串（判例 cwmp⑦/doh#24/onvif#56/hl7#26/megaco#45/bacnet#47）。**v1.0.0 "multi_flow" 术语作废**（G-7）。

**重试与重连分立**：重试（正例 48）= 同连接 500 后重发（新 id）；重连（正例 49）= 连接终止后新四元组新模板上下文（`tcp.stream` distinct）。**终止口径**：全部 TCP 正例挥手统一 FIN/ACK×2（`terminates: true`）；RST 中断为独立正例 50（`tcp.flags.reset==1`、其后无 body 帧、无 FIN）；`Closed` 后不产生新业务帧（正例 51）。**保活口径**：HTTP keep-alive 连接复用即活性，**TCP 层 keepalive 探测不产生**。**v1.0.0 的 RST 零声明作废**（审查⑥）。

**包数约定**：单事务会话 = 3（握手）+ 2（请求+响应）+ 4（FIN×2×ACK）= **9**；keep-alive N 事务 = 7 + 2N；大模板/打包跨段 = 3 + 请求段数 + ceil(响应总字节/1460) + 4；RST = 5；重连/多会话 = Σ连接。v1.0.0 的 12/10/18/24 拍脑袋值作废重算。

**HTTP body 重组**：body 跨多 TCP 段按 `tcp.stream` 重组后解码（json 解码在 http.file_data 重组后生效，跨 MSS 无 DecodeAs 需求）；多消息粘单段按头/Content-Length 边界拆分（正例 43/44/53）。Content-Length 截断/不一致为负例。

## 6. 配置 typedef（JSON 形状；G-2 事件编排）

```json
{
  "layers": [{"ip": {}}, {"tcp": {}}, {"http": {}}, {"gbt": {}}],
  "src_ip": "192.0.2.77", "dst_ip": "198.51.100.77",
  "src_port": 4077, "dst_port": 8332,
  "concurrent": false,
  "sessions": [{
    "role": "miner",
    "auth": {"user": "user", "pass": "pass"},
    "http": {"uri": "/", "version": "HTTP/1.1", "connection": "keep-alive"},
    "events": [
      {"kind": "request",  "id": 1, "method": "getblocktemplate", "params": []},
      {"kind": "response", "id": 1, "status": 200, "result_kind": "template", "template": "fixture_template"},
      {"kind": "request",  "id": 4, "method": "submitblock", "params": ["<hexdata>", "workid_from:fixture_template"]},
      {"kind": "response", "id": 4, "status": 200, "result_kind": "accepted_null"}
    ]
  }]
}
```

形状要点：**顶层 layers**（含 http 层，G-5）；`sessions[]` = 事件编排会话（`concurrent: true` 顶层声明交错，§5）；`events[]` 元素为一笔事务一侧（request 带 `id/method/params`，params 内联或 `*_from` 引用会话最近模板派生——`workid_from`/`longpollid_from`；response 带 `status`（200/401/500）与 `result_kind`：template/accepted_null/reject_reason/proposal_true/proposal_reject/error_object）；`auth` 会话级（缺省 = 401 场景）；longpoll 请求事件的 URI 由 `uri_from: template.longpolluri` 派生（§3.1）；**自动派生规则**：①`http` 层自动补请求行/状态行与通用头（Host/Content-Type/Content-Length/Connection），Content-Length 恒等于 body 字节数；②响应 id 自动回带请求 id（负例 `id_mismatch` 注入才偏离）；③刷新模板事件自动派生 height+1/curtime+600/longpollid 变体；④连接边界：源端口变化触发新 TCP 连接，多会话展开第二会话包号 = 前会话+1。`wire_fault` 仅负例注入口，**28 值枚举与 §7 表、用例文档 §5 三方同序一一映射**：`bad_json`、`body_truncated`、`content_length_mismatch`、`unknown_method`、`template_params_nonobject`、`submitblock_no_hexdata`、`submitblock_third_param`、`prevhash_length`、`bits_length`、`noncerange_length`、`target_length`、`field_missing`、`workid_mismatch`、`id_mismatch`、`longpollid_missing`、`longpollid_stale`、`height_nonincrement`、`mode_invalid`、`unknown_rule`、`bip9_field`、`witness_commitment`、`coinbasetxn_form`、`line_profile`、`udp_carrier`、`port_undeclared`、`address_family`、`http_method_get`、`error_propagation`，不得成为线上字段。

## 7. 错误处理（负例锚词表；G-9 原子拆分）

以下输入必须由 planner/validator 拒绝并传播为 task error，不得产出成功 PCAP、`completed/0 packet` 或只剩 TCP/HTTP 外壳的假成功。**单一注入纪律：一行一例、主锚词钉死单一字面值（备选括注）**，与用例文档 §5 逐行同序（28 行）：

| # | 负例 ID | `wire_fault` | 故障输入（单一注入） | 主锚词（备选） |
|---:|---|---|---|---|
| 54 | `gbt_neg_bad_json` | `bad_json` | 声明的 body 序列化后非合法 JSON | `json` |
| 55 | `gbt_neg_body_truncated` | `body_truncated` | body 截断（Content-Length 大于实际） | `truncat`（body） |
| 56 | `gbt_neg_content_length_mismatch` | `content_length_mismatch` | Content-Length ≠ 实际 body 字节数 | `content-length` |
| 57 | `gbt_neg_unknown_method` | `unknown_method` | method 取支持集外值（如 `getwork`——族分立） | `method`（unknown） |
| 58 | `gbt_neg_template_params_nonobject` | `template_params_nonobject` | getblocktemplate params[0] 非对象（如字符串） | `params`（template） |
| 59 | `gbt_neg_submitblock_no_hexdata` | `submitblock_no_hexdata` | submitblock params 缺 hexdata（空数组） | `params`（submitblock） |
| 60 | `gbt_neg_submitblock_third_param` | `submitblock_third_param` | submitblock 三参数（BIP 22 至多双参） | `params`（submitblock） |
| 61 | `gbt_neg_prevhash_length` | `prevhash_length` | previousblockhash ≠ 64 hex | `length`（prevhash） |
| 62 | `gbt_neg_bits_length` | `bits_length` | bits ≠ 8 hex | `length`（bits） |
| 63 | `gbt_neg_noncerange_length` | `noncerange_length` | noncerange ≠ 16 hex | `length`（noncerange） |
| 64 | `gbt_neg_target_length` | `target_length` | target ≠ 64 hex | `length`（target） |
| 65 | `gbt_neg_field_missing` | `field_missing` | 模板缺任一必选键（注入 height 缺失） | `height`（missing） |
| 66 | `gbt_neg_workid_mismatch` | `workid_mismatch` | submitblock workid 与本会话最近模板不符 | `workid`（mismatch） |
| 67 | `gbt_neg_id_mismatch` | `id_mismatch` | 响应 id 与请求 id 不一致 | `id`（mismatch） |
| 68 | `gbt_neg_longpollid_missing` | `longpollid_missing` | longpoll 请求 params 缺 longpollid（BIP 22） | `longpollid`（missing） |
| 69 | `gbt_neg_longpollid_stale` | `longpollid_stale` | longpollid 非本会话最近模板的 ID（陈旧） | `longpollid`（stale） |
| 70 | `gbt_neg_height_nonincrement` | `height_nonincrement` | 刷新模板 height 未 +1（同值或回退） | `height`（increment） |
| 71 | `gbt_neg_mode_invalid` | `mode_invalid` | options.mode 取值域外（如 `"template-x"`） | `mode` |
| 72 | `gbt_neg_unknown_rule` | `unknown_rule` | rules 含支持集 {segwit} 外值（如 `"taproot"`） | `rule`（unknown） |
| 73 | `gbt_neg_bip9_field` | `bip9_field` | 模板注入 vbavailable/vbrequired（BIP 9 边界归口） | `unsupported`（bip9） |
| 74 | `gbt_neg_witness_commitment` | `witness_commitment` | 模板注入 default_witness_commitment（BIP 145 归口） | `unsupported`（witness） |
| 75 | `gbt_neg_coinbasetxn_form` | `coinbasetxn_form` | 模板注入 coinbasetxn 完整形态 | `unsupported`（coinbasetxn） |
| 76 | `gbt_neg_line_profile` | `line_profile` | profile 取 jsonrpc-line（臆造形态归口，G-6） | `carrier`（profile） |
| 77 | `gbt_neg_udp_carrier` | `udp_carrier` | UDP 载体（仅 TCP 上的 HTTP 合法） | `carrier`（udp） |
| 78 | `gbt_neg_port_undeclared` | `port_undeclared` | 非 8332/18332 端口未显式声明 | `port`（undeclared） |
| 79 | `gbt_neg_address_family` | `address_family` | IPv6 地址配 IPv4 层链（或反向） | `family`（address） |
| 80 | `gbt_neg_http_method_get` | `http_method_get` | GET 方法承载（必须 POST） | `post`（method） |
| 81 | `gbt_neg_error_propagation` | `error_propagation` | 注入 wire_fault=bad_json 已知非法配置，断言任务以 task error 终止（含底层锚词）而非 completed/0 packet 假成功 | `propagat`（error） |

**不得误报为 planner error 的合法协议事件（防误报）**：submitblock `result:null`（接受，正例 36）、`result:"<reason>"`（拒绝是正例形态，正例 37）、proposal reject（正例 40）、HTTP 500+error（正例 6）、401（正例 5）、HTTP/1.0（正例 12）、2.0 形态（正例 8）、空 transactions（正例 27）、字符串 id（正例 10）、`result:true`（proposal 通过，BIP 23 合法形态）。

## 8. 边界

- **BIP 9**（vbavailable/vbrequired）：显式不产生；归口 `bip9_field` 负例。
- **BIP 145**（default_witness_commitment、limits 对象形态、tx weight）：显式不产生；归口 `witness_commitment` 负例（limits 对象形态同归口）。
- **coinbasetxn 完整形态**：不产生；归口 `coinbasetxn_form` 负例。
- **`jsonrpc-line` profile**：臆造形态（G-6）；归口 `line_profile` 负例。
- **TLS/HTTPS**：不在本版；`tls` 层另行声明。
- **chunked**：不产生（恒 Content-Length）；声明归口 `content_length_mismatch` 拒绝。
- **通知（无 id 请求）**：不是 GBT 消息形态，不产生。
- **真实 PoW/签名/区块验证**：不断言（无链上下文）；result:null 仅线路接受语义。
- **无 jsonrpc 成员的旧 1.0 形态**：本版不产生（fixture 统一 bitcoin-cli 形态，§1 N-3）；2.0 为观测例。

## 9. 原子 ID 与完成定义

**ID 权威 = 用例文档 §2**（G-20，megaco D-1/bacnet D-1 判例）：设计不维护逐 ID 全量镜像表——设计、testcase 与未来 `gbt.json` 使用同一 **81 个语义 ID 集合与顺序（53 正 + 28 负）**，权威序以用例文档 §2 为准，设计按簇给出覆盖图景。当前 JSON 只放 `gbt_neg_unregistered` 前置占位，不计入 81。

**正例 53 条按簇**：载体/HTTP/形态族（1-16：IPv4/IPv6/18332、Basic、401/500、1.0/2.0、id 序列/字符串/大值、HTTP/1.0、Host、空参、rules、capabilities）；模板字段族（17-29：18 键序、四 hex 宽度各一、height/coinbasevalue/时间、mutable/coinbaseaux/limits、transactions 空/元素）；longpoll/关联族（30-35：longpolluri/longpoll 请求/longpollid 参数/workid/双参提交/刷新）；提交族（36-40：null/reason/500/proposal 通过/拒绝）；会话/流/中断族（41-53：keep-alive 多事务与 close、跨段/粘连/大模板、多会话/并发/隔离、重试/重连、RST、FIN 后无帧、双栈）。

**负例 28 行（54-81）**：JSON/HTTP 编码×3、方法/参数×4、模板字段×5、关联×5、模式/规则×2、边界归口×3（BIP9/145/coinbasetxn）、臆造形态×1（line_profile）、载体×4、传播×1——逐行见 §7 表。

完成定义：注册 `gbt` layer；实现 §3 全部线格式（HTTP 头序/三态状态码/紧凑 bitcoin-cli 与 2.0 JSON/模板 18 键/tx 元素/workid 双参）、§5 会话模型（id 配对、longpoll 派生、刷新派生、并发）、§7 错误传播（28 行主锚词）；53 个正例断言（http.* + json.* 双通道 + frames hex）与 28 个负例错误传播全部完成；未注册阶段只接受 `unknown layer` 占位；pcap/NIC 双输出共用本契约（§1）。BIP 9/145 族、coinbasetxn、TLS、chunked 仅在明确实现后才可增加对应断言。

## 10. 修订记录

- v1.0.0（2026-08-21）：旧稿首版（20 = 14 正 + 6 负，未过审查）。
- v2.0.0（2026-09-02，v1.3 重写级修复轮）：独立审查报告（rr-gbt，/tmp/gbt_v13/report.md）CRITICAL 6 + MAJOR 10 + MINOR 4 + N 3，行为面 114 点，20 → **81 例（53 正 + 28 负）**。逐条落点：**G-1（C）** §4 业务场景八场景 + 五层结论 + 双层关联事务模型；**G-2（C）** §6 sessions[]/events[] 事件编排 + 自动派生规则（sessions:1 数字形态作废）；**G-3（C）** §3.3 模板 18 键逐字段表（hex 宽度 64/8/16/64、mutable 定义值）+ §3.4 fixture 常量与长度公式；**G-4/G-5（C/M）** 主层链改 [ip,tcp,http,gbt]（复用 http 层）；**G-6（M）** jsonrpc-line profile 删除 + line_profile 负例归口；**G-7（M）** concurrent:true 并发会话（multi_flow 作废）+ 流关联/多流不适用声明；**G-8（M）** §1 双输出契约段 + #14 pcap_nic 用例删除（hl7 判例）；**G-9（C）** 负例 6 行捆 ≈25 输入 → 28 行原子拆分 + wire_fault 三方同序；**G-10（M）** 18332 非默认端口正例 + 无 DecodeAs 依赖声明（probe 实测）；**G-11（M）** longpoll 真实语义重写（longpolluri 字段 + 独立请求携 longpollid 挂起）；**G-12（M）** Authorization Basic 默认 + http.authorization 精确断言；**G-13（M）** 401/500 三态 + 状态码≠RPC error 分离声明；**G-14（M）** BIP 9/145/coinbasetxn 显式边界 + 归口负例；**G-15（M）** workid 字段 + submitblock 第二参关联 + workid_mismatch 负例；**G-16（m）** submitblock 双参形态落字；**G-17（m）** mutable 定义值域 + coinbaseaux.flags 语义；**G-18（m）** 动态值两类纪律（矛盾作废）；**G-19（C）** 全部叙述式断言作废 → http.*/json.* 字段 + hex 基线 + 包数算式（probe 实测基线采用）；**G-20（m）** ID 权威 = 用例 §2 + §8 一致性块；error_propagation 负例保留（v1.3 §4 最小清单 L79 错误传播要求 + 13 对判例一致），审查员的删除建议以可构造式表述化解（§7 #81）。待复验关闭。
