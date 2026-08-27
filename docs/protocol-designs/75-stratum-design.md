# Stratum（矿池工作分配协议，Stratum）v1 设计契约

> 版本：v1.0.0（设计阶段）  
> 日期：2026-08-20  
> 状态：仅设计与 PCAP（抓包文件）/NIC（网卡）用例契约；`stratum` 层尚未注册，不修改 Go（编程语言）实现，不宣称当前 suite（测试套件）可运行。  
> 配套文件：`docs/protocol-designs/75-stratum-testcase.md`、`trafficgen/test/protocol_pcap/cases/stratum.json`  
> 规范基线：Stratum v1 常见 Bitcoin 矿池 JSON-RPC（远程过程调用）约定、JSON-RPC 2.0 风格消息、TCP 行式传输约定；实现前以具体矿池 fixture（固定样本）与注册 schema（说明书）为最终约束。

## 1. 范围、证据等级和未注册边界

本契约聚焦 Stratum v1（矿池客户端与服务端之间的工作分配协议）：TCP 明文 JSON 行式消息（newline-delimited JSON，换行分隔 JSON），每个应用消息以一个 `\n` 结束。覆盖订阅、授权、工作通知、难度通知、提交 share（份额）、JSON-RPC 请求/响应关联、可选版本/配置扩展、IPv4/IPv6、多流/多会话、TCP 分段与粘连，以及 PCAP/NIC 观察。

Stratum v1 不定义私有 TCP record header（二进制记录头），也没有消息长度前缀；消息边界只由 JSON 文本后的换行决定。TCP segment（分段）不是应用消息边界，planner（规划器）必须支持一个 JSON 行跨多个 segment，也必须支持多行粘在一个 segment。测试不把 segment 数量误当 JSON 消息数。

本契约只观察明文 JSON 结构、字段类型、行边界、方向和关联关系。Stratum 没有内置加密/签名；没有矿池真实 job（任务）或工作量证明上下文时，不能声称已计算、验证或伪造有效 share、区块、挑战应答或密码学结果。`nonce`、`extra_nonce`、`job_id`、`prevhash`、merkle root、coinbase、`ntime`、`nbits`、difficulty 和 JSON-RPC `id` 均是动态字段，只使用 `presence`（存在）、`nonzero`（非零）、`same_as_packet`（与指定包相同）或 `distinct`（彼此不同）断言。

当前仓库没有注册 `stratum` layer、planner、validator（校验器）或生成器。`cases/stratum.json` 只保留一个 `stratum_neg_unregistered` 注册前置占位，必须 `expect_error=true` 且 `error_contains="unknown layer"`；占位不计入下文 20 个语义 ID。注册前拒绝、0 包、空 PCAP 或只有 TCP 外壳的失败都不是 Stratum 行为通过。

## 2. 推荐配置层链和载体

推荐层链为 `[ip, tcp, stratum]` 或 `[ipv6, tcp, stratum]`。`stratum+tcp` 是 URI（统一资源标识符）/端口命名习惯，不是另一种二进制封装，也不自动引入 TLS（传输层安全）。以下是实现后的建议配置形态：

```json
{
  "layers": [{"ip": {}}, {"tcp": {}}, {"stratum": {}}],
  "src_ip": "192.0.2.75", "dst_ip": "198.51.100.75",
  "src_port": 4075, "dst_port": 3333,
  "stratum": {
    "profile": "v1",
    "sessions": 1,
    "worker": "worker-1",
    "password": "x",
    "messages": ["subscribe", "authorize", "notify", "set_difficulty", "submit"]
  }
}
```

| 配置键 | 约束 |
|---|---|
| `profile` | 本契约固定 `v1`；`v2`/加密扩展不在本期可执行范围，不能以 v1 JSON 行冒充 v2 二进制消息。 |
| `transport`/端口 | 仅 TCP；端口可由 URI 或配置显式指定，默认 fixture 使用 3333。错误端口或 UDP 进入负例，不由 planner 静默修正。 |
| `line_ending` | 必须是 `\n`；JSON 文本可以包含空格但不能用私有长度前缀取代换行。 |
| `messages` | 按会话顺序编排请求、通知和响应；必须保留请求/响应方向，不跨 TCP session（会话）共享状态。 |
| `worker`/`password` | `mining.authorize` 的 params 字符串；密码只是明文 fixture 字段，不声称真实凭证有效。 |
| `job_id`/`nonce`/`extra_nonce` | 运行期生成或由最近 `mining.notify` 提供；只能用动态关联断言，禁止固定具体值。 |
| `flow_count`/`sessions` | 每个 session 有独立四元组、请求 ID、job 状态、行缓存和动态字段；多 worker 可以并发但不得串状态。 |
| `wire_fault` | 仅负例注入口：`json`、`method`、`correlation`、`version`、`framing`、`carrier`。 |

推荐端口 3333 仅为常见 fixture；不把端口数字当作协议识别的唯一证据。IPv4 与 IPv6 使用独立 fixture，分别验证 IP family（地址族）与 TCP 载体。

## 3. JSON-RPC 行式消息结构

请求或通知的常见形态如下；每个示例表示一整行，实际线上末尾必须追加 `\n`：

```json
{"id":1,"method":"mining.subscribe","params":["miner/1.0",null,"stratum+tcp",3333]}
{"id":2,"method":"mining.authorize","params":["worker-1","x"]}
{"method":"mining.notify","params":["job-dynamic","prevhash-dynamic","coinb1-dynamic","coinb2-dynamic",[],"version-dynamic","nbits-dynamic","ntime-dynamic",true]}
{"id":3,"method":"mining.submit","params":["worker-1","job-dynamic","extranonce-dynamic","ntime-dynamic","nonce-dynamic"]}
{"id":1,"result":[[["mining.notify","subscription-dynamic"]],"extra_nonce-dynamic",4],"error":null}
{"id":2,"result":true,"error":null}
{"id":3,"result":true,"error":null}
```

示例中的动态值只是字段位置说明，不是测试中可硬编码的期望值。`mining.notify` 是通知（无 `id`）；响应含 `id`、`result` 和 `error`，成功时 `error` 通常为 `null`。JSON-RPC 2.0 风格允许 `id` 为 number（数字）或 `null`，但本契约不把通知的 `null` 当作请求响应 ID；实现必须按消息角色区分。

### 3.1 通用结构约束

- 每行必须是一个完整 JSON object（对象）；行内不可出现未转义控制字符。
- 请求至少包含 `id`、`method`、`params`；通知不包含 `id`，而不是把 `id` 写成固定伪值。
- 响应包含 `id`、`result`、`error`；成功与失败由 `error` 是否为 `null` 和字段类型共同判断。
- `id` 只用于同一 session 内关联，不能跨 session 复用来掩盖错配；动态 ID 只断言存在、类型和对应关系。
- `params` 数组位置有语义：`authorize` 至少 worker/password；`submit` 至少 worker/job_id/extra_nonce/ntime/nonce；`notify` 至少 job_id、prevhash、coinb1、coinb2、merkle 分支、version、nbits、ntime、clean_job。

## 4. Stratum v1 消息阶段与字段

### 4.1 订阅与授权

客户端首先发送 `mining.subscribe`，服务端返回订阅结果、运行期 `extra_nonce` 和 `extra_nonce` 大小等字段。随后客户端发送 `mining.authorize`，服务端返回成功或错误响应。响应 `id` 必须分别匹配订阅/授权请求；不能以 TCP 顺序或固定数字替代关联。worker 名称和密码可以是 fixture 字符串，但不声称矿池认证成功具有现实凭证含义。

### 4.2 工作通知 `mining.notify`

服务端通知必须无 `id`，params 顺序至少为：动态 `job_id`、`prevhash`、`coinb1`、`coinb2`、merkle branch 数组、version、nbits、ntime、`clean_job`。`clean_job` 是布尔值；merkle branch 即使为空也必须保持数组类型。客户端后续 `mining.submit` 的 `job_id` 必须来自最近有效 notify；`ntime` 可来自该工作上下文；不能把 notify 行当作响应或生成固定 job。

### 4.3 难度与提交

`mining.set_difficulty` 是无 `id` 的服务端通知，params 至少包含 difficulty 数值；测试覆盖正数、最小合法边界和会话内变更，但不声称该难度对应真实网络目标。`mining.submit` params 至少含 worker、job_id、extra_nonce、ntime、nonce。nonce、extra_nonce、job_id 等均只做 presence/nonzero，并断言 submit 的 job_id 与最近 notify 相同；不验证 share 是否满足真实 PoW。

### 4.4 版本和配置扩展

`client.get_version` 是客户端请求；服务端返回版本字符串。`mining.configure` 可携带扩展名和 options（选项）对象，例如版本协商扩展；本契约只断言 JSON 类型、请求/响应 ID matching（匹配）和明确声明的字段，不声称已经建立 Stratum v2 加密或二进制语义。未声明方法不能被静默当作合法 v1 方法。

### 4.5 授权失败与错误响应

授权拒绝必须保留失败响应的 `id`，`result`/`error` 类型和方向可观察；不能用成功 `result=true` 伪装。error 的具体矿池文本和 code 可动态/fixture 化；除非配置明确给出，不硬编码现实矿池错误文案。失败只表示协议错误路径可观察，不表示真实身份验证。

## 5. TCP framing、分段合并与状态关联

TCP 是字节流。planner/worker（工作进程）输出时应允许：一行 JSON 被拆成多个 TCP payload；多行 JSON 在同一 payload 粘连；空闲后继续发送下一行。接收端按 `\n` 重组，每行独立 JSON 解码；不能以 SYN、PSH、segment 或 packet_count 作为消息边界。最后一行没有换行终止属于负例，不能为方便解析自动补换行并报成功。

每个 session 保持独立的 line buffer（行缓存）、订阅/授权阶段、最近 notify job、difficulty、请求 ID map（映射表）和响应队列。多会话之间即使 worker 名称相同，也不能共享 job_id、extra_nonce、nonce 或响应；同一 session 的多个请求可以交错，但响应必须按 `id` 关联而不是简单按位置配对。多流并发下，不能假设全局 packet order（包顺序）。

在无 VLAN/IP/TCP options 的明确 fixture 中，IPv4 TCP payload 参考偏移为 `14+20+20=54`，IPv6 为 `14+40+20=74`；偏移只用于该 fixture，不能写成通用 Stratum record header。MSS（最大报文段长度）分段不改变行内容，PCAP 断言须先按 TCP stream 重组再检查 JSON 行。

## 6. IPv4/IPv6、多 worker、多会话和 PCAP/NIC

正例至少包含独立 IPv4、独立 IPv6、多个 worker/会话和一个同时涉及 PCAP 与 NIC 的观察用例。IPv4 断言 `ip.proto=6`；IPv6 断言 `ipv6.nxt=6`（不含扩展头的 fixture）或最终 TCP next header，地址和端口不可从另一地址族 fixture 借用。每个 session 的四元组、动态 job、nonce、请求 ID 和行缓存独立。

PCAP 观察内容包括 TCP 三次握手/终止、客户端到服务端和服务端到客户端方向、3333（或显式端口）、完整重组后的 JSON 行、换行边界、请求/响应 ID 和 notify 无 ID。NIC 捕获使用相同 fixture 与过滤器，记录 checksum offload（校验和卸载）可能造成的校验和显示差异；不能因校验和显示为未计算而否定应用字段。

## 7. 错误处理、PCAP/NIC 证据和完成定义

6 个语义负例必须在 planner/validator 阶段失败并传播为 task error（任务错误），不能输出成功 PCAP、`completed/0 packet` 或只有 TCP 外壳的假成功。未来注册后的每个语义负例执行期 `expect` 键集合严格为 `{"expect_error", "error_contains"}`；占位 JSON 为满足注册前审计可带说明 `notes`，不属于 20 个语义负例。

| ID | 故障输入 | 目标 `error_contains` |
|---|---|---|
| `stratum_neg_invalid_json` | 非法 JSON、截断对象、非 object 行或无法在换行处解码 | `json`、`decode` 或 `line` |
| `stratum_neg_method_params` | 未知 method、缺少必需 params、params 类型/位置错误 | `method`、`params` 或 `field` |
| `stratum_neg_id_correlation` | 响应 ID 不匹配请求、通知带伪 ID、跨会话错配或响应错序 | `id`、`match` 或 `correlation` |
| `stratum_neg_version_method` | 未知 profile/version 或 v2 二进制/未声明 method 混入 v1 | `version`、`profile` 或 `method` |
| `stratum_neg_line_framing` | 无 `\n` 终止、把 TCP segment 当行、私有长度前缀或跨流拼行 | `framing`、`newline` 或 `stream` |
| `stratum_neg_carrier` | UDP、非 TCP、错误端口、IPv4/IPv6 层链不一致 | `carrier`、`tcp`、`port` 或 `family` |

PCAP/NIC 正例只断言可观察事实：TCP carrier、地址族、方向、端口、重组后的每行 JSON、方法/params 类型、动态字段存在与关联、响应 error 路径和通知无 ID。不得断言 nonce/extra_nonce/job_id 的固定值、真实 share 有效、真实区块产生、矿池密码有效或加密已完成。没有专用 dissector（解析器）时，使用 `tcp`、`json` raw bytes（原始字节）和稳定的行边界断言，不自创字段名。

实现完成定义：注册 `stratum` layer；实现 v1 JSON 行编排、TCP 行重组、subscribe/authorize/notify/set_difficulty/submit/get_version/configure、错误响应和 ID 关联；planner→worker→PCAP/NIC output（输出）正负完整传播；-race（竞态检测）与集成测试覆盖 IPv4/IPv6、多会话、多 worker、MSS 分段、粘连和错误传播；不声称 PoW/share 或凭证验证。

## 8. 20 个语义场景和 packet_count 映射

共 20 个唯一语义 ID：14 个正例和 6 个负例；顺序必须与 `75-stratum-testcase.md` §2 及注册后的 `stratum.json` 完全一致。当前 JSON 只有不计数的注册前置占位。

| # | ID | 类型 | 覆盖 | 约定 packet_count |
|---:|---|---|---|---:|
| 1 | `stratum_tcp_ipv4_subscribe_authorize` | 正 | IPv4/TCP 建立、subscribe+authorize 成功闭环 | 12 |
| 2 | `stratum_tcp_ipv6_subscribe_authorize` | 正 | 独立 IPv6/TCP fixture、订阅授权关联 | 12 |
| 3 | `stratum_notify_job_message` | 正 | mining.notify 行式 JSON 完整字段和无 ID 通知 | 10 |
| 4 | `stratum_set_difficulty` | 正 | mining.set_difficulty、难度边界和会话状态 | 8 |
| 5 | `stratum_submit_share` | 正 | mining.submit、job/nonce/extra_nonce 动态关联 | 12 |
| 6 | `stratum_jsonrpc_id_matching` | 正 | 请求/响应 ID 关联、通知无 ID、错误响应方向 | 12 |
| 7 | `stratum_line_framing_reassembly` | 正 | TCP 分段/合并、多行粘连、按换行重组 | 12 |
| 8 | `stratum_get_version_configure` | 正 | client.get_version、mining.configure 扩展协商 | 10 |
| 9 | `stratum_authorize_reject` | 正 | authorize 失败和 error 响应路径 | 10 |
| 10 | `stratum_multi_session_stream` | 正 | 多 TCP session/worker 状态隔离 | 24 |
| 11 | `stratum_multi_worker_concurrency` | 正 | 多 worker 并发、多流独立 job/ID/nonce | 24 |
| 12 | `stratum_ipv4_ipv6_dual` | 正 | IPv4/IPv6 并行地址族、TCP 方向和状态隔离 | 24 |
| 13 | `stratum_dynamic_field_association` | 正 | job_id、prevhash、extra_nonce、ntime、nbits 动态存在与关联 | 12 |
| 14 | `stratum_pcap_nic_consistency` | 正 | PCAP/NIC 一致、方向、重组行边界和 TCP 观察 | 16 |
| 15 | `stratum_neg_invalid_json` | 负 | 非法 JSON、截断行、非 object 消息 | — |
| 16 | `stratum_neg_method_params` | 负 | 未知 method、缺字段、params 类型/位置错误 | — |
| 17 | `stratum_neg_id_correlation` | 负 | ID 不匹配、通知伪 ID、跨流错配/错序 | — |
| 18 | `stratum_neg_version_method` | 负 | 未知版本、v2/未声明 method 混入 v1 | — |
| 19 | `stratum_neg_line_framing` | 负 | 无换行、私有长度前缀、segment 当边界、跨流拼行 | — |
| 20 | `stratum_neg_carrier` | 负 | 非 TCP、错误端口、IPv4/IPv6 层链错误 | — |

三方契约必须保持本文 §8、`75-stratum-testcase.md` §2、注册后的 `stratum.json` 同一组 20 个 ID、同一顺序、14 正例+6 负例；当前 JSON 另有一个不计数的 `stratum_neg_unregistered`，且唯一预期为 `unknown layer`。

## 9. 修订记录

- v1.0.0（2026-08-20）：建立 14 个 Stratum v1 TCP/JSON 行式正例和 6 个严格负例，覆盖 subscribe、authorize、notify、difficulty、submit、版本/配置、动态字段关联、TCP 重组、IPv4/IPv6、多会话/多 worker、PCAP/NIC 与错误传播；不修改 Go 实现。
