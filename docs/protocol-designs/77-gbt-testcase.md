# GBT（Bitcoin getblocktemplate，获取区块模板）测试用例契约

> 版本：v1.0.0（设计阶段）
> 日期：2026-08-21
> 配套设计：`docs/protocol-designs/77-gbt-design.md`
> 机器契约：`trafficgen/test/protocol_pcap/cases/gbt.json`
> 状态：`gbt` 层尚未注册；本文定义实现后的 PCAP（抓包文件）/NIC（网卡）断言，不宣称当前 suite（测试套件）可运行。

## 1. 测试原则和未注册边界

用例从设计 §2–§9 逐项派生，共 20 个唯一语义 ID：14 个正例和 6 个负例。当前 JSON 只保留一个不计入语义覆盖的注册前置占位 `gbt_neg_unregistered`，其 `expect` 必须 `expect_error=true`、`error_contains="unknown layer"`；注册后移除占位，再按本文 §2 顺序加入 20 个语义用例。

GBT 测试按 HTTP/TCP stream（字节流）重组，再按 Content-Length/chunked 或 line profile 恢复 JSON-RPC body；segment（分段）边界不是消息边界。没有真实节点、交易签名或 PoW（工作量证明）材料时，只断言结构、方向、字段类型、动态值存在和消息间关联，不声称模板可挖、区块有效或 submitblock 已广播。

运行期 request ID、template、height、previousblockhash、target、longpollid、nonce、交易 txid/hash 和 block hex 使用 `presence`、`nonzero`、`same_as_packet`、`distinct` 与类型/长度断言；禁止固定具体动态值。

## 2. 原子用例索引

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

## 3. 正例逐项断言契约

1. **`gbt_ipv4_template`**：建立 IPv4/TCP，客户端发送 `getblocktemplate` template 请求，服务端返回 JSON-RPC template object；断言 `ip.proto=6`、HTTP/JSON 边界、响应 ID matching（匹配）、`previousblockhash`/`target`/`height`/`transactions`/`coinbaseaux`/`coinbasevalue`/`longpollid` 等字段存在且类型正确，`packet_count=12`。
2. **`gbt_ipv6_template`**：独立 IPv6/TCP fixture，断言 `ipv6.nxt=6`、IPv6 地址族、template 请求/响应和动态字段；不能继承 IPv4 地址或 session 状态，`packet_count=12`。
3. **`gbt_proposal_mode`**：请求 params 明确 `mode:"proposal"` 与动态 block hex，断言服务端返回 proposal 接受/拒绝/error 类型和响应 ID；proposal 不被伪造成完整 template，不断言区块有效，`packet_count=10`。
4. **`gbt_rules_capabilities`**：请求携带 `rules` 数组和 `capabilities` 数组，断言字段类型、响应中声明的兼容结果、未知能力的显式状态；不把协商结果当真实共识启用，`packet_count=10`。
5. **`gbt_transactions_coinbase`**：断言 template 的 `transactions` 数组元素结构、空数组与非空边界、`coinbaseaux` object、`coinbasevalue` 非负整数和动态 txid/hash；不验证签名、费用或 coinbase 经济有效性，`packet_count=12`。
6. **`gbt_longpoll_keepalive`**：先取得动态 `longpollid`，再在同一 keep-alive TCP/HTTP session 发起 longpoll 并收到刷新 template；断言 Content-Length/chunked 边界、请求 ID、new height/hash/longpollid 的状态关联和方向，`packet_count=18`。
7. **`gbt_submitblock_success`**：使用动态 block hex 提交 `submitblock`，断言响应 ID matching、`result=null` 或 profile 声明的 accepted 类型、双向方向和 TCP/HTTP body；不断言 PoW 或区块广播，`packet_count=10`。
8. **`gbt_submitblock_reject`**：提交结构合法但 fixture 返回动态 reject reason/error，断言响应保留 ID、拒绝类型/原因和方向，不能伪装成 null 成功，`packet_count=10`。
9. **`gbt_retry_after_error`**：先观察模板或 longpoll 的暂时 RPC/HTTP 错误，再以新 request ID retry 获取模板；断言错误传播、重试顺序/会话边界、后续 template 动态字段和旧状态未串用，`packet_count=16`。
10. **`gbt_jsonrpc_id_matching`**：同 session 编排多个 template/proposal/submitblock 请求、响应和 error；断言每个 response ID 与对应 request 关联，不能按全局位置或跨流配对，`packet_count=14`。
11. **`gbt_multi_session_stream`**：至少两个 TCP/HTTP session 并行，各自 template、longpoll、submitblock；断言 request ID、height、previous hash、target、longpollid 和错误状态独立，不假设全局包序，`packet_count=24`。
12. **`gbt_multi_flow_concurrency`**：至少两个 worker/flow 多流并发，断言四元组、HTTP keep-alive、动态模板和 ID 按流隔离；允许全局包交织，不跨流消费 template/nonce，`packet_count=24`。
13. **`gbt_dynamic_field_association`**：完整 gettemplate→longpoll/刷新→submitblock 上下文，断言 request ID、template ID、height、previousblockhash、target、nonce/block hex、longpollid 的存在和声明关联；不固定动态值，`packet_count=14`。
14. **`gbt_pcap_nic_consistency`**：同一明文 fixture 分别输出 PCAP 并执行 NIC 捕获；断言 TCP 握手/终止、双向方向、8332（或显式端口）、HTTP body/JSON 边界、template/proposal/submitblock 动态字段和 ID 关联在两种观察中一致。推荐过滤器 `tcp port 8332`，记录 checksum offload 差异，`packet_count=18`。

没有真实 Bitcoin 节点、PoW、交易脚本/签名和主网凭证时，不添加“nonce 满足 target”“区块已广播”“交易已确认”“coinbase 可兑换”或固定运行期值断言。没有专用 GBT dissector（解析器）时，使用 `tcp`、`http`、重组 raw JSON 和稳定字段断言；不把 segment 数量当 JSON 消息数。

## 4. 负例契约

每个负例必须在 planner/validator 阶段失败并传播为 task error（任务错误）；不能产生成功 PCAP、`completed/0 packet` 或只有 TCP/HTTP 外壳的假成功。执行期 `expect` 键集合严格为 `{"expect_error", "error_contains"}`：

| ID | 故障输入 | 目标 `error_contains` |
|---|---|---|
| `gbt_neg_invalid_json_rpc` | 非法/截断 JSON、非 object、HTTP body/换行边界无法解码 | `json`、`decode` 或 `body` |
| `gbt_neg_method_params` | 未知 method、mode 错误、rules/capabilities/params 类型或数量错误 | `method`、`mode`、`params` 或 `field` |
| `gbt_neg_template_field_boundary` | 缺失必需模板字段、错误整数/hex 长度、负值/溢出、transactions/coinbaseaux 类型错误 | `template`、`field`、`length`、`range` 或 `type` |
| `gbt_neg_longpoll_transport` | longpollid 错配、无 keep-alive 边界、超时 retry 状态丢失、UDP/错误 HTTP framing | `longpoll`、`retry`、`framing`、`http` 或 `carrier` |
| `gbt_neg_id_correlation` | 响应 ID 不匹配、跨会话错配、proposal/submitblock 响应错序 | `id`、`match` 或 `correlation` |
| `gbt_neg_error_propagation` | planner/validator 已知错误被吞掉、任务假成功、0 包或错误响应丢失 | `error`、`propagat` 或 `task` |

## 5. 三方一致性和静态检查

1. 设计 §9 的 20 个 ID、本文 §2、注册后的 JSON 和审计必须保持同一组 20 个 ID、同一顺序：14 正例 + 6 负例；当前 JSON 另有一个不计数的 `gbt_neg_unregistered` 占位。
2. 未来 14 个正例均有 `packet_count`/`min_packets`、TCP/HTTP carrier、方向、JSON body 边界和动态 template/height/hash/target/nonce 字段断言；6 个负例的 `expect` 键集合恰为 `{expect_error, error_contains}`，不添加 `notes`、`packet_count` 或其他键。
3. template/proposal/submitblock/longpoll/retry 的 method、params 类型、响应 ID matching 和错误方向按重组后的完整 JSON 断言；不以 TCP segment 数量代替消息数量。
4. `rules`、`capabilities`、`transactions`、`coinbaseaux`、`coinbasevalue`、`target`、`previousblockhash`、`height`、`longpollid`、`nonce` 按声明类型/长度和最近模板上下文关联；禁止固定运行期值。
5. 每个 TCP session 独立 HTTP body 缓存、request ID map、模板和 longpoll 状态；多流、多 worker 与 IPv4/IPv6 并发不依赖全局包序。
6. HTTP profile 按 Content-Length/chunked 解 body；line profile 按换行；未解密 TLS 不断言内部 JSON。keep-alive 不能省略响应边界。
7. PCAP 与 NIC 观察必须同时能看见 TCP 方向、端口、HTTP/JSON 边界和字段关联；checksum offload 只影响校验和显示，不改变应用层断言。
8. `python3 -m json.tool trafficgen/test/protocol_pcap/cases/gbt.json` 应成功；当前数组只能含 `gbt_neg_unregistered`，且 `proto=gbt`、`expect_error=true`、`error_contains` 精确为 `unknown layer`。
9. 未来注册后，20 个语义 case 按本文 §2 顺序加入；负例 `expect` 键集合必须恰为 `{expect_error, error_contains}`，占位不计入 20 个 ID。

## 6. 实现后执行建议

注册 `gbt` layer 后，先核对 JSON-RPC parser（解析器）、HTTP/TCP 层链、Content-Length/chunked/line 边界、template/proposal/submitblock 状态、longpoll retry、动态字段关联和 ID 顺序，再运行 1–14 的 PCAP/NIC 正例与 15–20 的错误传播。若环境没有 GBT dissector，使用通用 TCP/HTTP/raw JSON 重组和 JSON 解码断言；不能将唯一 placeholder（占位）的拒绝结果报告为 GBT suite 通过。

## 7. 修订记录

- v1.0.0（2026-08-21）：建立 14 个 Bitcoin GBT JSON-RPC 正例和 6 个严格负例，覆盖 template/proposal、rules/capabilities、transactions/coinbase、longpoll/keep-alive/retry、submitblock、动态字段、IPv4/IPv6、多流/多会话、PCAP/NIC 与错误传播；不修改 Go/MCP。
