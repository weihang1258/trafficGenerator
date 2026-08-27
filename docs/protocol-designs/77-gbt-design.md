# GBT（Bitcoin getblocktemplate，获取区块模板）设计契约

> 版本：v1.0.0（设计阶段）
> 日期：2026-08-21
> 状态：仅设计与 PCAP（抓包文件）/NIC（网卡）用例契约；`gbt` 层尚未注册，不修改 Go（编程语言）/MCP（模型上下文协议）实现，不宣称当前 suite（测试套件）可运行。
> 配套文件：`docs/protocol-designs/77-gbt-testcase.md`、`trafficgen/test/protocol_pcap/cases/gbt.json`
> 规范基线：Bitcoin Core `getblocktemplate`（GBT）JSON-RPC（远程过程调用）约定、BIP 22/BIP 23 模板与 proposal（提案）模式、`submitblock`（提交区块）约定；实现前以注册 schema（模式）和固定抓包样本为最终约束。

## 1. 范围、证据等级和未注册边界

本契约定义 Bitcoin 矿工、矿池或节点之间可观察的明文 JSON-RPC over TCP/HTTP 应用语义，不执行真实工作量证明（Proof of Work，工作量证明），不验证区块哈希是否满足网络目标，不判断交易签名或 coinbase（铸币交易）经济有效性。覆盖 `getblocktemplate` 的 template（模板）和 proposal 模式、`submitblock`、规则与能力协商、交易/coinbase 字段、longpoll（长轮询）、keep-alive（持久连接）、重试和错误响应，以及 IPv4/IPv6、多流/多会话、PCAP/NIC 观察。

运行期 request ID（请求标识）、template 对象、height（高度）、previousblockhash（前一区块哈希）、target（目标）、nonce（随机数）、longpollid（长轮询标识）和 submitblock 返回值均不得硬编码；只使用 `presence`（存在）、`nonzero`（非零）、`distinct`（不同）、`same_as_packet`（与指定包相同）及 schema 规定的类型/长度/十六进制字符集断言。模板字段展示结构事实，不代表节点返回了现实主网工作。

当前仓库没有注册 `gbt` layer（层）、planner（规划器）、validator（校验器）或生成器。`cases/gbt.json` 只保留一个 `gbt_neg_unregistered` 注册前置占位，必须 `expect_error=true` 且 `error_contains="unknown layer"`；占位不计入下面 20 个语义 ID。注册前拒绝、0 包、空 PCAP 或只有 TCP/HTTP 外壳都不是 GBT 行为通过。

## 2. 推荐配置、层链和载体 profile（档案）

推荐明文层链为 `[ip, tcp, gbt]` 或 `[ipv6, tcp, gbt]`。常见 JSON-RPC HTTP 载体可在 profile 明确声明时使用 `[ip, tcp, http, gbt]`；HTTPS/TLS（传输层安全）没有解密证据时只观察 TLS/TCP，不能断言 GBT 字段。

```json
{
  "layers": [{"ip": {}}, {"tcp": {}}, {"gbt": {}}],
  "src_ip": "192.0.2.77", "dst_ip": "198.51.100.77",
  "src_port": 4077, "dst_port": 8332,
  "gbt": {
    "profile": "jsonrpc-http",
    "methods": ["getblocktemplate", "submitblock"],
    "sessions": 1,
    "keep_alive": true
  }
}
```

| 配置键 | 约束 |
|---|---|
| `profile` | `jsonrpc-http`、`jsonrpc-line` 或明确声明的等价 profile；必须说明 HTTP body（正文）边界或换行边界，不能把 TCP segment（分段）当 JSON 消息。 |
| `transport`/端口 | 应用载体为 TCP；HTTP RPC 常见端口 8332，端口仅为 fixture（固定样本）约定，不是唯一协议识别证据；UDP 属于负例。 |
| `method`/`mode` | `getblocktemplate` 支持 `template`（默认语义）和 `proposal`；`submitblock` 请求只能提交声明的 block hex（区块十六进制数据），不能静默改成 template 请求。 |
| `params` | `getblocktemplate` 的 rules（规则）和 capabilities（能力）按声明的数组/对象形状传递；`longpollid`、`data` 等参数类型必须固定。 |
| `template` | 至少声明动态 `version`、`previousblockhash`、`transactions`、`coinbaseaux`、`coinbasevalue`、`target`、`mintime`、`mutable`、`noncerange`、`sigoplimit`、`sizelimit`、`curtime`、`bits`、`height`；实现可按 schema 增减字段，但不能把必需字段静默置空。 |
| `transactions` | 数组元素至少保持 transaction data（交易数据）和 txid（交易标识）/hash（哈希）等 schema 声明的类型；不验证交易签名、费用或 merkle root（默克尔根）的现实正确性。 |
| `coinbaseaux`/`coinbasevalue` | `coinbaseaux` 是对象，`coinbasevalue` 是非负整数（按实现声明的 JSON number 范围）；不把二者混为完整 coinbase bytes。 |
| `longpoll`/`keep_alive` | longpoll 使用模板返回的 `longpollid`，HTTP keep-alive 允许同一 TCP session（会话）多次请求；超时/重试必须保留请求 ID 和会话状态。 |
| `sessions`/`flow_count` | 每个会话有独立 request ID map（映射）、模板、height、previous hash、target 和 longpoll 状态；多流并发不能串状态。 |
| `wire_fault` | 仅负例注入口：`json`、`method`、`field`、`boundary`、`carrier`、`id`、`propagation`。 |

## 3. JSON-RPC 消息结构和 HTTP 边界

以下示例只表示字段位置，动态值不能照抄为期望值：

```json
{"jsonrpc":"2.0","id":"id-dynamic","method":"getblocktemplate","params":[{"capabilities":["longpoll","coinbasetxn"],"rules":["segwit"]}]}
{"jsonrpc":"2.0","id":"id-dynamic","result":{"version":1,"previousblockhash":"hash-dynamic","transactions":[],"coinbaseaux":{"flags":"flags-dynamic"},"coinbasevalue":5000000000,"target":"target-dynamic","longpollid":"lp-dynamic","mutable":["time","transactions","prevblock"],"noncerange":"00000000ffffffff","curtime":1,"bits":"1d00ffff","height":1},"error":null}
{"jsonrpc":"2.0","id":"id-dynamic","method":"submitblock","params":["block-hex-dynamic"]}
{"jsonrpc":"2.0","id":"id-dynamic","result":null,"error":null}
```

通用约束如下：

- 每条 JSON-RPC 消息必须是完整 object（对象）；HTTP profile 以响应的 Content-Length（正文长度）或 chunked（分块）边界恢复 body，line profile 以 `\n` 分隔；不能跨流拼接。
- 请求至少包含 `id`、`method`、`params`；响应包含 `id` 与 `result`/`error`。错误响应保留原请求 ID，不能静默变成成功结果。
- `getblocktemplate` 响应必须区分 `template` 和 `proposal`：template 返回工作字段；proposal 返回接受/拒绝或错误状态，不得把 proposal 结果伪造成完整模板。
- `submitblock` 的 `params` 至少包含一个 block hex 字符串；响应可以是 `null` 表示接受，也可以是声明的 reject reason（拒绝原因）或 error object（错误对象），具体值动态化。
- 同一 session 内 request ID 必须一一关联；相同数字 ID 在不同 session 中可以独立存在，不能跨流匹配。

## 4. getblocktemplate 模式与模板字段

### 4.1 template 模式

客户端发送 `getblocktemplate`，可在 params 中声明 `rules`、`capabilities` 和 `longpollid`。服务端返回模板 object，至少保留以下字段和类型：`version` 整数、`previousblockhash` 十六进制字符串、`transactions` 数组、`coinbaseaux` object、`coinbasevalue` 非负整数、`target` 十六进制字符串、`longpollid` 字符串、`mutable` 字符串数组、`noncerange` 十六进制范围、`sigoplimit`/`sizelimit` 非负整数、`curtime`/`mintime` 整数、`bits` 字符串和 `height` 正整数。字段具体位宽、hex 长度和可选性以注册 schema 为准。

模板的 `previousblockhash`、`target`、`height` 和 `longpollid` 是动态工作上下文。模板刷新时可以出现新的 previous hash、height、target 或 longpollid；后续请求应引用最近有效模板，不能使用全局最后模板跨会话配对。

### 4.2 proposal 模式

`getblocktemplate` 的 proposal 请求在 params 中携带 `mode:"proposal"` 和声明的 block hex。服务端返回 proposal 接受、拒绝原因或 JSON-RPC error；该模式不要求返回普通 template 字段。测试只断言 mode、请求/响应 ID、结果类型和错误方向，不宣称区块真实有效。

### 4.3 rules、capabilities 与兼容性

`rules` 是客户端要求/声明的规则名称数组，例如 `segwit`；`capabilities` 是客户端能够处理的模板能力数组，例如 `longpoll`、`coinbasetxn`、`coinbasevalue`。服务端可以返回声明的规则/能力或拒绝不支持项；未知规则、错误类型和空值边界必须按 schema 显式处理，不能默默删掉请求字段。能力协商不等同于启用真实共识规则。

### 4.4 transactions、coinbase 与数值边界

`transactions` 的数组边界、交易数据与 txid/hash 字段、重复交易和空数组都应可观察。`coinbaseaux` 的扩展字段保留 object 结构；`coinbasevalue` 的 0、最小非零值和接近实现上限的值按 schema 测试，不能用浮点数代替整数。模板中的交易/coinbase 字段只作为 wire（线上）结构，不验证脚本、签名、手续费或经济规则。

## 5. longpoll、keep-alive、重试与 submitblock

### 5.1 longpoll 生命周期

模板返回 `longpollid` 后，客户端可在下一次 `getblocktemplate` params 中提交该 ID，连接在模板变化或超时后返回新模板。longpoll 请求可占用 keep-alive session；返回后必须保留请求 ID、方向、HTTP body 边界和新的模板上下文。超时、服务端暂时错误和客户端 retry（重试）必须产生可关联的错误/下一次请求，不可静默丢包或把空响应当成功模板。

### 5.2 keep-alive 与重用连接

HTTP keep-alive 允许同一 TCP stream（字节流）承载多个 request/response；每个响应仍按 Content-Length/chunked 边界独立解码。允许请求响应交错但不允许响应 ID 错配；Connection close、超时或 retry 后建立新 session 时，旧 session 的模板、longpollid 和 request map 不得泄漏。

### 5.3 submitblock 三态

`submitblock` 提交动态 block hex 后，服务端可以返回 `null`/accepted、字符串 reject reason 或 error object。accepted 只表示响应结构；不断言真实区块已广播或满足 PoW。拒绝/错误是正例可观察状态，必须保留请求 ID、方向和原因类型，不能伪造成 `null` 成功。

## 6. 动态字段和关联规则

模板 `height`、`previousblockhash`、`target`、`bits`、`curtime`、`coinbasevalue`、`longpollid`、交易 txid/hash 和 request ID 都使用 presence/nonzero/distinct/same_as 断言。`nonce` 可以是测试 fixture 声明的 block header 字段或提交上下文字段；其宽度、hex 编码和与模板/submitblock 的关联以 schema 为准，不能把任意 TCP 偏移当作 nonce 偏移。

`getblocktemplate` 请求 ID 与响应 ID 必须匹配；longpoll 重试的新请求有自己的动态 ID，但对应返回仍只能关联该 session 的请求。`submitblock` 的 block、nonce（若单独存在）和最近模板的 previous hash/height 只断言声明的关联，不硬编码运行值。跨 session 即使字段格式相同，也必须维持独立工作状态。

## 7. TCP、HTTP、IPv4/IPv6、多流与 PCAP/NIC

TCP 是字节流。HTTP body 可能跨多个 TCP segment，也可能多个 JSON request/response 粘在一个 segment；应用消息边界来自 HTTP framing 或 line framing，不来自 SYN、PSH、MSS（最大报文段长度）或 packet_count（包数量）。IPv4 载体观察 `ip.proto=6`，IPv6 载体观察 `ipv6.nxt=6`（无扩展头 fixture）或最终 TCP next header。

至少两个并发 session 时，每个流独立维护 HTTP keep-alive 状态、request ID map、模板、height、previous hash、target 和 longpoll retry；全局包交织不能改变关联。PCAP 与 NIC 必须使用同一 fixture，观察 TCP 握手/终止、双向方向、端口、HTTP/JSON 边界、动态字段和错误状态；checksum offload（校验和卸载）差异只影响校验和显示，不改变应用证据。推荐过滤器为 `tcp port 8332`，若 fixture 显式改端口则以配置端口为准。

## 8. 错误处理和完成定义

六个语义负例必须在 planner/validator 阶段失败并传播为 task error（任务错误），不能输出成功 PCAP、`completed/0 packet` 或只有 TCP/HTTP 外壳的假成功。未来注册后的负例执行期 `expect` 键集合严格为 `{\"expect_error\", \"error_contains\"}`；当前 JSON 占位不属于 20 个语义 ID。

| ID | 故障输入 | 目标 `error_contains` |
|---|---|---|
| `gbt_neg_invalid_json_rpc` | 非法/截断 JSON、非 object、HTTP body/换行边界处无法解码 | `json`、`decode` 或 `body` |
| `gbt_neg_method_params` | 未知 method、mode 错误、rules/capabilities/params 类型或数量错误 | `method`、`mode`、`params` 或 `field` |
| `gbt_neg_template_field_boundary` | 缺失必需模板字段、错误整数/hex 长度、负值/溢出、transactions/coinbaseaux 类型错误 | `template`、`field`、`length`、`range` 或 `type` |
| `gbt_neg_longpoll_transport` | longpollid 错配、无 keep-alive 边界、超时 retry 状态丢失、UDP/错误 HTTP framing | `longpoll`、`retry`、`framing`、`http` 或 `carrier` |
| `gbt_neg_id_correlation` | 响应 ID 错配、跨会话错配、proposal/submitblock 响应错序 | `id`、`match` 或 `correlation` |
| `gbt_neg_error_propagation` | planner/validator 错误被吞掉、任务假成功、0 包或错误响应丢失 | `error`、`propagat` 或 `task` |

上述输入均是不合法契约输入，不得被描述为可接受的特殊格式。服务端正常 proposal reject、submitblock reject 或 RPC error 是正例状态；只有构造非法配置并要求错误传播时才是负例。错误文本必须保留原始原因，不能用泛化的“0 packets”替代。

实现完成定义：注册 `gbt` layer；实现 template/proposal 两种 `getblocktemplate` 模式、rules/capabilities、transactions/coinbaseaux/coinbasevalue、target/previousblockhash/height/nonce 动态字段、longpoll/keep-alive/retry、submitblock accepted/rejected/error、JSON-RPC ID map、HTTP/TCP framing、IPv4/IPv6、多流/多会话、PCAP/NIC 输出及错误传播；测试覆盖下列 20 个场景和竞态/集成路径。不声称 PoW、区块广播、交易签名、脚本执行或主网凭证有效。

## 9. 二十个语义场景和 packet_count 映射

以下 20 个唯一 ID 必须与 `77-gbt-testcase.md` §2 同序同集合，为 14 个正例和 6 个负例；当前 JSON 另有一个不计数的注册前置占位。

| # | ID | 类型 | 覆盖 | 约定 packet_count |
|---:|---|---|---|---:|
| 1 | `gbt_ipv4_template` | 正 | IPv4/TCP JSON-RPC template 请求响应、动态模板字段 | 12 |
| 2 | `gbt_ipv6_template` | 正 | IPv6/TCP template 请求响应和地址族隔离 | 12 |
| 3 | `gbt_proposal_mode` | 正 | getblocktemplate proposal 模式、block 与响应状态 | 10 |
| 4 | `gbt_rules_capabilities` | 正 | rules/capabilities 协商和未知能力边界 | 10 |
| 5 | `gbt_transactions_coinbase` | 正 | transactions、coinbaseaux、coinbasevalue 和数值边界 | 12 |
| 6 | `gbt_longpoll_keepalive` | 正 | longpollid、HTTP keep-alive、模板刷新与重用连接 | 18 |
| 7 | `gbt_submitblock_success` | 正 | submitblock 接受路径、动态 block/nonce 与 ID | 10 |
| 8 | `gbt_submitblock_reject` | 正 | submitblock reject/error 状态和原因传播 | 10 |
| 9 | `gbt_retry_after_error` | 正 | RPC/HTTP 暂时错误、retry、重新获取模板 | 16 |
| 10 | `gbt_jsonrpc_id_matching` | 正 | 多请求/响应 ID 关联、proposal 与 submitblock 方向 | 14 |
| 11 | `gbt_multi_session_stream` | 正 | 多 TCP/HTTP session 状态和模板隔离 | 24 |
| 12 | `gbt_multi_flow_concurrency` | 正 | 多流并发、全局交织和独立动态字段 | 24 |
| 13 | `gbt_dynamic_field_association` | 正 | request ID/template/height/hash/target/nonce 关联 | 14 |
| 14 | `gbt_pcap_nic_consistency` | 正 | PCAP/NIC 一致、TCP/HTTP/JSON 边界和方向 | 18 |
| 15 | `gbt_neg_invalid_json_rpc` | 负 | 非法 JSON-RPC、截断 body 或非 object | — |
| 16 | `gbt_neg_method_params` | 负 | method/mode/rules/capabilities/params 错误 | — |
| 17 | `gbt_neg_template_field_boundary` | 负 | 模板字段缺失、类型/hex/整数边界错误 | — |
| 18 | `gbt_neg_longpoll_transport` | 负 | longpoll、keep-alive、retry 或 carrier/framing 错误 | — |
| 19 | `gbt_neg_id_correlation` | 负 | JSON-RPC ID、跨流或响应顺序错配 | — |
| 20 | `gbt_neg_error_propagation` | 负 | planner/validator 错误未传播、假成功或丢错 | — |

三方契约必须保持本文 §9、`77-gbt-testcase.md` §2、注册后的 `gbt.json` 同一组 20 个 ID、同一顺序、14 正例+6 负例；当前 JSON 另有一个不计数的 `gbt_neg_unregistered`，且唯一预期为 `unknown layer`。

## 10. 修订记录

- v1.0.0（2026-08-21）：建立 14 个 Bitcoin GBT JSON-RPC 正例和 6 个严格负例，覆盖 template/proposal、rules/capabilities、transactions/coinbase、longpoll/keep-alive/retry、submitblock、动态字段、IPv4/IPv6、多流/多会话、PCAP/NIC 与错误传播；不修改 Go/MCP。
