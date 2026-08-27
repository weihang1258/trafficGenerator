# XMRMining（门罗币挖矿协议，Monero/CryptoNote Mining）设计契约

> 版本：v1.0.0（设计阶段）  
> 日期：2026-08-21  
> 状态：仅设计与 PCAP（抓包文件）/NIC（网卡）用例契约；`xmrmining` 层尚未注册，不修改 Go（编程语言）/MCP（模型上下文协议）实现，不宣称当前 suite（测试套件）可运行。  
> 配套文件：`docs/protocol-designs/74-xmrmining-testcase.md`、`trafficgen/test/protocol_pcap/cases/xmrmining.json`  
> 规范基线：CryptoNote（加密笔记协议族）/Monero（门罗币）矿池 Stratum（矿池工作分配协议）常见 JSON 行式约定、Monero JSON-RPC（远程过程调用）`getjob`/`submit`/`login` 消息；实际实现以注册 schema（模式）和固定抓包样本为最终约束。

## 1. 范围、证据等级和未注册边界

本契约定义 Monero/CryptoNote 矿工客户端与矿池之间可观察的明文 TCP 应用语义，不执行真实 RandomX/CryptoNight 工作量证明（Proof of Work，工作量证明），不验证区块或 share（份额）的密码学有效性。覆盖 Stratum-like（类 Stratum）登录、工作通知、share 提交、接受/拒绝/错误响应，以及 JSON-RPC 风格 `login`、`getjob`、`submit`、`keepalived` 方法。每个 JSON 消息的方向、行边界、请求 `id` 与响应关联必须保留。

工作对象中的动态 `job_id`、`blob`、`target`、`height`、`seed_hash`、`algo`、`nonce`、`share_id` 和 `extra_nonce` 只能断言 `presence`（存在）、`nonzero`（非零）、`distinct`（不同）、`same_as_packet`（与指定包相同）或 schema（模式）规定的长度/字符集，不能硬编码运行期值。`blob` 是 CryptoNote block template（区块模板）或其矿池变体的十六进制编码；nonce 可能是独立提交字段，也可能在实现声明的 blob 偏移处更新，不能假设任意固定偏移。

当前仓库没有注册 `xmrmining` layer（层）、planner（规划器）、validator（校验器）或生成器。`cases/xmrmining.json` 只保留一个 `xmrmining_neg_unregistered` 注册前置占位，必须 `expect_error=true` 且 `error_contains="unknown layer"`；该占位不计入下面 20 个语义 ID。注册前拒绝、0 包、空 PCAP 或只有 TCP 外壳都不是 XMRMining 行为通过。

## 2. 推荐配置、层链和载体 profile（档案）

推荐明文层链为 `[ip, tcp, xmrmining]` 或 `[ipv6, tcp, xmrmining]`。HTTP JSON-RPC 只有在 profile 明确声明 HTTP body（正文）承载时才可使用 `[ip, tcp, http, xmrmining]`；未解密 TLS（传输层安全）仅观察 TLS/TCP，不能断言内部矿池字段。

```json
{
  "layers": [{"ip": {}}, {"tcp": {}}, {"xmrmining": {}}],
  "src_ip": "192.0.2.74", "dst_ip": "198.51.100.74",
  "src_port": 4074, "dst_port": 18081,
  "xmrmining": {
    "profile": "stratum-json",
    "methods": ["login", "job", "submit", "keepalived"],
    "sessions": 1,
    "dynamic_work": true
  }
}
```

| 配置键 | 约束 |
|---|---|
| `profile` | `stratum-json`、`jsonrpc`、`http-jsonrpc` 或 `tls-opaque`；必须明确消息格式，不能将 HTTP/TLS 外壳误当成 XMRMining 应用成功。 |
| `transport`/端口 | 应用载体为 TCP；常见矿池端口由 fixture（固定样本）显式指定，Monero daemon RPC 常见 18081/18082；端口不是唯一识别证据，UDP 不属于本契约。 |
| `messages` | 按会话编排 login、job/getjob、submit、keepalived 和响应；每条 JSON 行末尾为 `\n`，除非 HTTP body profile 明确使用 Content-Length（正文长度）。 |
| `work`/`job` | 工作通知至少声明动态 `job_id`、`blob`、`target`，可含 `height`、`seed_hash`、`algo`、`difficulty`、`extranonce`；字段类型和十六进制长度由 schema 约束。 |
| `submit` | 提交必须引用同一会话最近有效 job，带 worker/login 标识、job ID、nonce 和声明的 blob/height/share 字段；旧 job 必须走 stale/rejected/error（过期/拒绝/错误）路径。 |
| `sessions`/`flow_count` | 每个会话独立维护登录状态、请求 ID 映射、最近工作、blob、nonce、target 和 share 状态，不跨流串接。 |
| `wire_fault` | 仅负例注入口：`json`、`method`、`blob`、`nonce`、`share`、`id`、`carrier`、`propagation`。 |

## 3. CryptoNote/Monero 消息结构

Stratum-like profile 采用 JSON 行式消息。常见阶段为 `login` 请求、服务端 `job` 响应/通知、客户端 `submit`、服务端 accepted/rejected/error（接受/拒绝/错误）响应；具体矿池可以将方法命名为 `login`/`submit`，也可以使用 JSON-RPC `method` 字段。示例中的值只表示字段位置：

```json
{"id":"id-dynamic","method":"login","params":{"login":"worker-dynamic","pass":"x","agent":"miner-dynamic"}}
{"id":"id-dynamic","jsonrpc":"2.0","result":{"id":"session-dynamic","job":{"job_id":"job-dynamic","blob":"blob-hex-dynamic","target":"target-hex-dynamic","height":1,"algo":"rx/0"}},"error":null}
{"id":"id-dynamic","method":"submit","params":{"id":"session-dynamic","job_id":"job-dynamic","nonce":"nonce-hex-dynamic","blob":"blob-hex-dynamic"}}
{"id":"id-dynamic","jsonrpc":"2.0","result":{"status":"OK","share_id":"share-dynamic"},"error":null}
```

通用约束如下：

- 每条消息必须是完整 JSON object（对象）；裸 TCP profile 以 `\n` 分隔，JSON 可以跨 TCP segment（分段）或多行粘连。
- 请求至少含动态 `id`、`method`、`params`；服务端通知可以没有 `id`，不得用固定 `null` 冒充通知或响应关联。
- `result` 与 `error` 的角色由 profile/schema 明确；错误响应保留原请求 ID，不把错误静默变成成功结果。
- `params` 可以是 object（对象）或数组，但同一 profile 内必须固定并按方法约束字段名、位置和类型。
- 字符串形式的 `blob`、`target`、`nonce`、`seed_hash`、`job_id` 和 `share_id` 若声明为 hex（十六进制），必须满足偶数长度和 schema 规定的解码字节长度；不把十进制 JSON number（数字）当 hex 字符串。

## 4. 登录、工作和 share 生命周期

### 4.1 `login`/订阅

客户端 `login` 请求携带 worker/login 标识、密码或 token（令牌）和可选 agent；服务端响应可返回会话 ID、初始 job、身份状态或 error。密码/token 在 fixture 中只作为字段，不声称现实凭证有效。登录响应的 `id` 必须与请求同会话匹配。

### 4.2 `job`/`getjob`

服务端可以主动发送无 `id` 的 `job` 通知，或响应客户端 `getjob` 请求。工作至少包含动态 `job_id`、`blob` 和 `target`；Monero 变体可加入 `height`、`seed_hash`、`algo`、`difficulty`、`reserved_offset`、`extra_nonce` 或 `clean_job`。`blob` 的具体布局由实现声明；测试只断言 hex 格式、长度、存在和后续提交关联，不把任意 bytes 当作固定 block header 字段。

工作轮换由新的 `job_id`、`blob`、`height`、`seed_hash` 或 target 触发。轮换后旧 job 提交必须进入 stale/rejected/error，不能静默套用新 blob/target。每个会话的最近工作独立维护，多流之间即使 job ID 形式相同也不能共享状态。

### 4.3 `submit` 与 nonce/blob 关联

客户端 `submit` 必须引用最近有效 job，并提交 nonce；profile 若要求完整 blob，则 blob 必须与该 job 关联，若仅提交 nonce，则 planner（规划器）仍须能从会话工作上下文建立关联。nonce 的编码、宽度及是否为 blob 内字段由 schema 声明；不能把 TCP 偏移或固定 nonce 值作为通用规则。响应可为 `{status:"OK"}`/accepted、`"INVALID"`/rejected 或 JSON-RPC error。

### 4.4 accepted/rejected/error 三态

1. **accepted**：响应保留请求 `id`，result/status 表示接受，可含动态 share ID；只断言线路状态和字段关联，不断言真实 PoW。
2. **rejected**：响应保留请求 `id`，status/reason 明确拒绝，例如 stale job、低难度或无效 nonce；不能伪装为成功。
3. **error**：响应保留请求 `id`，error object（错误对象）含 code/message/data（若声明）；错误方向和结构必须完整。

### 4.5 `keepalived`/状态消息

`keepalived` 或等价心跳只能在 profile 声明后使用；请求/响应或通知方向、ID 角色和空参数类型必须稳定。心跳不是 job、share 或登录成功的替代品。

## 5. 动态字段、CryptoNote blob 和编码规则

所有声明为 hex 的字段必须是偶数个 ASCII（美国信息交换标准代码）十六进制字符，长度按解码后 bytes 计算。允许 `0x` 前缀与否必须由 schema 明确。空字符串、奇数长度、非法字符、错误固定宽度、把 object/number 代替字符串都应拒绝。`job_id` 可以是矿池生成的 hex 或 opaque（不透明）字符串，不能强行套用 Monero block hash 长度。

`blob` 与 `target` 必须按 profile 约束保持同一工作上下文；`nonce` 必须是该 job 的尝试值。若 fixture 声明 nonce 在 blob 中，测试应按声明的字段/偏移做关联；否则只断言独立 nonce 字段和 job ID 关联。`height`、`seed_hash`、`algo`、`difficulty`、`extra_nonce` 和 `share_id` 都是运行期值，使用 presence/nonzero/distinct/same_as，不硬编码。

## 6. TCP、HTTP、IPv4/IPv6、多流与多会话

TCP 是字节流。裸 JSON 行可跨多个 segment，多个 JSON 消息也可在一个 payload 中粘连；重组器必须按 `\n` 或 HTTP body 长度恢复消息，不能使用 SYN、PSH、MSS（最大报文段长度）或 packet_count（包数量）推断应用消息数。最后一行缺少 `\n` 属于 framing（封帧）负例，不能自动补全。

IPv4 载体观察 `ip.proto=6`；IPv6 载体观察 `ipv6.nxt=6`（无扩展头 fixture）或最终 TCP next header。地址族、四元组和端口必须来自该 fixture，不能用 IPv4 字段解释 IPv6。至少两个并发流时，每个流独立维护登录、job/blob/target、nonce、share 和请求 ID map（映射），不能按全局最后 job 或全局包序配对。

HTTP JSON-RPC profile 断言 POST/keep-alive、Content-Type、Content-Length/body 边界和 JSON object；HTTPS/TLS opaque profile 只断言 TLS 握手/记录、方向、端口和 TCP 流，除非 fixture 提供解密证据，不断言内部 XMRMining 字段。

PCAP 与 NIC 捕获必须使用同一 fixture。观察 checksum offload（校验和卸载）差异时，以 TCP 方向、重组 JSON、动态字段关联为应用证据；不能把校验和显示差异当作应用失败。

## 7. 错误处理和完成定义

六个语义负例必须在 planner/validator 阶段失败并传播为 task error（任务错误），不能输出成功 PCAP、`completed/0 packet` 或只有 TCP/HTTP 外壳的假成功。未来注册后的负例 `expect` 键集合严格为 `{"expect_error", "error_contains"}`；当前 JSON 占位可带 `notes`，不属于 20 个语义 ID。

| ID | 故障输入 | 目标 `error_contains` |
|---|---|---|
| `xmrmining_neg_invalid_json` | 非法/截断 JSON、非 object 行、行边界无法解码 | `json`、`decode` 或 `line` |
| `xmrmining_neg_method_params` | 未知 method、login/getjob/submit 参数类型/数量/字段错误 | `method`、`params` 或 `field` |
| `xmrmining_neg_blob_nonce_share_mismatch` | blob/job/target/nonce/share 与最近工作不匹配，或 hex/长度错误 | `blob`、`nonce`、`work`、`share` 或 `length` |
| `xmrmining_neg_id_correlation` | 响应 ID 错配、跨会话消费、通知伪 ID 或方向错配 | `id`、`match` 或 `correlation` |
| `xmrmining_neg_carrier_profile` | UDP、错误 TCP/HTTP profile、端口或 IPv4/IPv6 层族不一致 | `carrier`、`tcp`、`http`、`port` 或 `family` |
| `xmrmining_neg_error_propagation` | 已知 planner/validator 错误被吞掉，任务假成功、0 包或错误响应丢失 | `error`、`propagat` 或 `task` |

错误文本应保留原始原因，不用泛化的“0 packets”替代；服务端正常 share rejected/error 是正例可观察状态，只有构造非法契约输入并要求错误传播时才是负例。

## 8. 二十个语义场景和 packet_count 映射

以下 20 个唯一 ID 必须与 `74-xmrmining-testcase.md` §2 同序同集合，为 14 个正例和 6 个负例；当前 JSON 另有一个不计数的注册前置占位。

| # | ID | 类型 | 覆盖 | 约定 packet_count |
|---:|---|---|---|---:|
| 1 | `xmrmining_stratum_ipv4_login_job` | 正 | IPv4/TCP login、动态 job/blob/target 和响应关联 | 12 |
| 2 | `xmrmining_stratum_ipv6_login_job` | 正 | IPv6/TCP login、独立地址族工作响应 | 12 |
| 3 | `xmrmining_getjob_rpc` | 正 | JSON-RPC getjob 请求、动态 job/blob/target 响应 | 10 |
| 4 | `xmrmining_submit_rpc_share` | 正 | JSON-RPC submit、nonce/blob/job 关联和 share 状态 | 12 |
| 5 | `xmrmining_stratum_job_notify` | 正 | 无 ID job 通知、height/seed/algo/target 动态字段 | 10 |
| 6 | `xmrmining_stratum_submit_share` | 正 | Stratum submit 的 job/nonce/extra nonce 动态关联 | 12 |
| 7 | `xmrmining_share_accept` | 正 | accepted/status OK、请求 ID 和 share ID 关联 | 10 |
| 8 | `xmrmining_share_reject` | 正 | rejected/stale/低难度路径和原因 | 10 |
| 9 | `xmrmining_share_error` | 正 | JSON-RPC error code/message/data 保留 | 10 |
| 10 | `xmrmining_blob_nonce_association` | 正 | blob、nonce、target、job 和 schema 偏移/字段关系 | 12 |
| 11 | `xmrmining_jsonrpc_id_correlation` | 正 | 并发请求/响应 ID、通知无 ID、错误方向 | 12 |
| 12 | `xmrmining_multi_session_stream` | 正 | 多会话独立登录、job/blob/nonce/share 状态 | 24 |
| 13 | `xmrmining_multi_flow_concurrency` | 正 | 多流并发、动态字段和全局交织下的状态隔离 | 24 |
| 14 | `xmrmining_pcap_nic_consistency` | 正 | PCAP/NIC 方向、载体、动态 JSON 字段一致 | 16 |
| 15 | `xmrmining_neg_invalid_json` | 负 | 非法 JSON、截断行、非 object 消息 | — |
| 16 | `xmrmining_neg_method_params` | 负 | 未知 method、缺字段、params 类型/位置错误 | — |
| 17 | `xmrmining_neg_blob_nonce_share_mismatch` | 负 | blob/job/nonce/share/hex 长度不匹配 | — |
| 18 | `xmrmining_neg_id_correlation` | 负 | JSON-RPC ID 或跨会话关联错误 | — |
| 19 | `xmrmining_neg_carrier_profile` | 负 | TCP/HTTP/端口/IPv4/IPv6 载体链错误 | — |
| 20 | `xmrmining_neg_error_propagation` | 负 | planner/validator 错误未传播、假成功或丢错 | — |

实现完成定义：注册 `xmrmining` layer；实现 CryptoNote/Monero Stratum-like 与 RPC 明文行格式、login/getjob/job/submit/keepalived、动态 job/blob/target/height/seed/algo/nonce/share 字段、accepted/rejected/error 三态、ID map、IPv4/IPv6、多流/多会话、MSS 重组、PCAP/NIC 输出和错误传播；测试覆盖上述 20 个场景及竞态/集成路径。不声称真实 RandomX/CryptoNight PoW、区块产生、矿池凭证有效或 share 密码学有效。

## 9. 修订记录

- v1.0.0（2026-08-21）：建立 14 个 CryptoNote/Monero Stratum/RPC 正例和 6 个严格负例，覆盖动态 job/blob/nonce/share 关联、IPv4/IPv6、多流、多会话、PCAP/NIC 与错误传播；不修改 Go/MCP。
