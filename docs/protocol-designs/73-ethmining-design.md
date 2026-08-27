# ETHMining（以太坊挖矿协议，Ethereum Mining）设计契约

> 版本：v1.0.0（设计阶段）  
> 日期：2026-08-21  
> 状态：仅设计与 PCAP（抓包文件）/NIC（网卡）用例契约；`ethmining` 层尚未注册，不修改 Go（编程语言）/MCP（模型上下文协议）实现，不宣称当前 suite（测试套件）可运行。  
> 配套文件：`docs/protocol-designs/73-ethmining-testcase.md`、`trafficgen/test/protocol_pcap/cases/ethmining.json`  
> 规范基线：Ethereum JSON-RPC（远程过程调用）约定中的 legacy（传统）挖矿方法、Stratum-like（类 Stratum）矿池消息、JSON-RPC 2.0 消息结构；实际实现以注册 schema（模式）和固定抓包样本为最终约束。

## 1. 范围、证据等级和未注册边界

本契约定义以太坊挖矿客户端与节点/矿池之间的应用语义，不声称执行真实工作量证明（Proof of Work，工作量证明）或产生有效区块。覆盖传统 Ethereum JSON-RPC 方法 `eth_getWork`、`eth_submitWork`、`eth_getHashrate`、`eth_submitHashrate`，以及 Stratum-like 的工作通知、share（份额）提交、接受/拒绝/错误响应。JSON-RPC 请求和响应必须保留 `id`、方法、参数、结果/错误的方向与关联。

工作对象中的 epoch（纪元）、seed hash（种子哈希）、header hash（区块头哈希）、boundary/target（目标边界）、nonce（随机数）和 share ID（份额标识）均为运行期值；测试只能断言 `presence`（存在）、`nonzero`（非零）、`distinct`（不同）、`same_as_packet`（与指定包相同）或长度/字符集，不得硬编码具体值。`extranonce`、job ID、JSON-RPC `id`、session ID（会话标识）同理。

当前仓库没有注册 `ethmining` layer（层）、planner（规划器）、validator（校验器）或生成器。`cases/ethmining.json` 只保留一个 `ethmining_neg_unregistered` 注册前置占位，必须 `expect_error=true` 且 `error_contains="unknown layer"`；该占位不计入下面 20 个语义 ID。注册前拒绝、0 包、空 PCAP 或只有 TCP/HTTP 外壳都不是 ETHMining 行为通过。

## 2. 推荐配置、层链和载体 profile（档案）

推荐明文 JSON-RPC 层链为 `[ip, tcp, ethmining]` 或 `[ipv6, tcp, ethmining]`；HTTP JSON-RPC 可由 `[ip, tcp, http, ethmining]` 承载；TLS（传输层安全）版本只在明确解密的 fixture（固定样本）中断言应用内容，未解密时仅观察 TLS/ TCP。

```json
{
  "layers": [{"ip": {}}, {"tcp": {}}, {"ethmining": {}}],
  "src_ip": "192.0.2.73", "dst_ip": "198.51.100.73",
  "src_port": 4073, "dst_port": 8545,
  "ethmining": {
    "profile": "jsonrpc",
    "methods": ["eth_getWork", "eth_submitWork", "eth_getHashrate", "eth_submitHashrate"],
    "sessions": 1,
    "dynamic_work": true
  }
}
```

| 配置键 | 约束 |
|---|---|
| `profile` | `jsonrpc`、`stratum-like`、`http-jsonrpc` 或 `tls-opaque`；不得把 HTTP/TLS 外壳误当成 ETHMining 应用成功。 |
| `transport`/端口 | 应用载体为 TCP；JSON-RPC 常见端口 8545/8546，矿池可使用显式 TCP 端口；HTTP 为显式 HTTP profile，UDP 不属于本契约。端口不是唯一识别证据。 |
| `methods` | 传统方法至少覆盖 `eth_getWork`、`eth_submitWork`、`eth_getHashrate`、`eth_submitHashrate`；Stratum-like 方法必须在 profile 中声明，未知 method 不得静默接受。 |
| `work` | 由服务端动态生成或通知，包含工作标识、header/seed/target 等字段；epoch 与 hash 的值不能固定写入断言。 |
| `submit` | 绑定最近有效工作，包含动态 nonce、工作 hash/job ID、可选 mix hash 和 share ID；只能断言存在、长度、同包关联。 |
| `sessions`/`flow_count` | 每个会话维护独立请求 ID 映射、最近工作、epoch、nonce、share 状态和 TCP 缓冲，不能跨流串接。 |
| `wire_fault` | 仅负例注入口：`jsonrpc`、`params`、`hex`、`work`、`nonce`、`id`、`carrier`、`propagation`。 |

HTTP JSON-RPC 的请求体是 JSON object（对象），响应体也是 JSON object；`Content-Type`、HTTP method 和 body 边界必须一致。裸 TCP 的 JSON 可以按换行分隔；如载体采用 Stratum-like 行式消息，消息边界为 newline（换行），不是 TCP segment（分段）数量或私有长度前缀。HTTP keep-alive（保持连接）允许多个请求交错，但每个请求/响应仍按 `id` 关联。

## 3. JSON-RPC 消息契约

每条请求至少包含 JSON-RPC 版本、动态 `id`、`method` 和数组 `params`；响应包含同值语义的 `id`、`result` 或 `error`。通知可省略 `id`，不得将固定伪值当作请求 ID。示意字段如下，动态值仅表示位置：

```json
{"jsonrpc":"2.0","id":"id-dynamic","method":"eth_getWork","params":[]}
{"jsonrpc":"2.0","id":"id-dynamic","result":["work-hash-dynamic","seed-hash-dynamic","target-dynamic"]}
{"jsonrpc":"2.0","id":"id-dynamic","method":"eth_submitWork","params":["nonce-dynamic","work-hash-dynamic","mix-hash-dynamic"]}
{"jsonrpc":"2.0","id":"id-dynamic","result":true}
```

`id` 可以是数字或字符串；本契约不规定固定值，只要求同一会话请求/响应一致，且不同并发请求的 ID 可区分。错误响应必须保留原请求 ID，包含 JSON-RPC error object（错误对象）的 code/message，可有动态 data；错误不得悄悄变成成功 `result` 或只返回 TCP/HTTP 外壳。

参数必须按方法定义的位置和类型传递。未知 method、缺少 params、将 object 代替数组、混用响应字段和请求字段、重复或错类型 `id` 都应在 planner/validator 阶段拒绝并传播 task error（任务错误）。

## 4. Legacy Ethereum 挖矿方法

### 4.1 `eth_getWork`

客户端请求 `params=[]`，服务端响应结果数组通常含三项：当前工作 header hash、seed hash、target；具体客户端实现也可能附带工作上下文。数组长度、每项十六进制（hexadecimal，十六进制）格式和字节长度必须由 schema 明确，不得用固定运行值替代。响应得到的工作 hash/job ID 是后续提交的唯一上下文来源。

### 4.2 `eth_submitWork`

客户端提交 `[nonce, header_hash, mix_hash]`，三项为十六进制字符串，且长度与实现的字段宽度一致。`nonce` 通常是固定宽度的 8 hex 字符（4 bytes）；header hash、mix hash 常为 32 bytes，但实际 schema 可为显式变体。planner 必须检查 hex 字符集、偶数长度、字段长度和当前工作匹配；不能把 nonce 作为十进制或截断字符串。接受、拒绝与验证错误分别用 `result` 或 `error` 表达，并保留请求 ID。

### 4.3 `eth_getHashrate` 与 `eth_submitHashrate`

`eth_getHashrate` 无参数或按 schema 规定的空参数请求，返回当前会话/矿工的动态算力值；不得硬编码具体算力。`eth_submitHashrate` 至少提交 hashrate 与 miner identifier（矿工标识）两个十六进制字段，字段长度/格式按 schema 约束；响应可为布尔接受或 JSON-RPC error。哈希率上报不等于 share 或区块有效。

## 5. Stratum-like 工作与 share 生命周期

Stratum-like profile 采用显式声明的 JSON-RPC 风格方法或行式 JSON 消息，最小阶段为：建立会话、订阅/登录（如声明）、服务端发送工作、客户端提交 share、服务端返回 accepted/rejected/error（接受/拒绝/错误）。消息可以采用 `mining.notify`、`mining.submit` 等方法名，但不得在未声明 profile 时把 Bitcoin Stratum 或 v2 二进制消息伪装为 Ethereum legacy RPC。

工作轮换（work rotation）由新的动态 job/work ID、header hash、epoch/seed 或 target 触发。旧工作提交必须进入明确的 stale/rejected/error（过期/拒绝/错误）路径，不得静默套用新工作。工作通知可能在已有会话中重复出现；会话状态应按流隔离，不能按全局最后一份工作覆盖其他矿工。

share 有三种可观察终态：

1. **accepted**：响应保留请求 `id`，结果表示接受；share ID、nonce、工作 hash 与最近工作具有关联。
2. **rejected**：响应保留请求 `id`，结果为拒绝或显式 rejected reason；不把拒绝伪装成区块成功。
3. **error**：JSON-RPC error 保留请求 `id`，错误 code/message/data 的结构完整，原因可为无效参数、旧工作、nonce 不匹配或服务端验证错误。

无真实链状态或 PoW 验证上下文时，不能声称 accepted share 达到真实网络 target、产生区块或完成密码学验证；只断言线路上的状态和动态字段关联。

## 6. 十六进制字段、动态工作和关联规则

所有声明为 hex 的字段必须为偶数个 ASCII hex 字符，长度按解码后的 bytes 计算。`0x` 前缀是否允许必须由 schema 明确，不能由 planner 猜测；空字符串、非 hex 字符、奇数长度、错误固定宽度、将 JSON 数字代替 hex 字符串都应拒绝。动态 epoch、nonce、work hash、seed hash、target、mix hash、share ID、extra nonce 和 JSON-RPC id 禁止写成断言常量。

提交的 work hash/job ID 必须来自同一会话最近有效工作；nonce 必须属于该工作尝试，错误会话、旧 epoch、轮换前 job 或不匹配 header/mix hash 必须走拒绝/错误路径。响应 `id` 只能与同一会话中对应请求关联；相同数字 ID 在不同会话可独立存在，但跨流响应不能互相消费。

## 7. TCP、HTTP、TLS、IPv4/IPv6 与多流

TCP 是字节流。JSON 行可跨多个 segment，多个 JSON 消息也可在一个 payload 中粘连；重组器必须按 HTTP body 长度或 newline/JSON 解码边界恢复消息，不能用 SYN、PSH、MSS 或 packet_count（包数量）推断应用消息数。MSS 分段只改变传输边界，不改变 JSON 字节。

IPv4 载体应观察 `ip.proto=6`，IPv6 载体应观察 `ipv6.nxt=6`（无扩展头的固定样本）或最终 TCP next header。地址族、四元组和端口必须来自该 fixture；不能用 IPv4 字段解释 IPv6。多会话/多流并发时，工作、epoch、nonce、share ID、请求 ID map（映射）和缓冲按会话隔离，不能假设全局包序。

HTTP 明文 profile 断言 request method、Content-Type、Content-Length/body、响应状态和 JSON-RPC 对象；HTTPS/TLS opaque（不透明）profile 只断言 TLS 握手/记录、方向、端口和 TCP 流，除非 fixture 提供解密证据，不断言内部 JSON。PCAP 与 NIC 观察应使用同一 fixture；校验和卸载显示差异不否定应用字段。

## 8. 错误处理和完成定义

六个语义负例必须在 planner/validator 阶段失败并传播为 task error，不能输出成功 PCAP、`completed/0 packet` 或只有 TCP/HTTP 外壳的假成功。未来注册后的负例 `expect` 键集合严格为 `{"expect_error", "error_contains"}`；当前 JSON 占位可带 `notes`，不属于 20 个语义 ID。

| ID | 故障输入 | 目标 `error_contains` |
|---|---|---|
| `ethmining_neg_jsonrpc_params` | JSON-RPC 版本、method、params 类型/数量、字段角色错误 | `jsonrpc`、`method` 或 `params` |
| `ethmining_neg_hex_length` | nonce/work hash/mix hash/target/hashrate 字符非 hex、奇数长度或错误解码长度 | `hex`、`length` 或 `hash` |
| `ethmining_neg_nonce_work_mismatch` | nonce、旧 epoch、header/work hash、mix hash 或 share 与最近工作不匹配 | `nonce`、`work`、`epoch` 或 `share` |
| `ethmining_neg_id_correlation` | 响应 ID 错配、跨会话消费、请求/响应 method 或方向错配 | `id`、`match` 或 `correlation` |
| `ethmining_neg_carrier_profile` | HTTP method/body、TLS/裸 TCP、UDP、端口或 IPv4/IPv6 层族不一致 | `carrier`、`http`、`tcp`、`port` 或 `family` |
| `ethmining_neg_error_propagation` | validator/planner 已知错误被吞掉，任务假成功、0 包或错误响应丢失 | `error`、`propagat` 或 `task` |

错误文本应保留原始原因，不用泛化的“0 packets”替代；服务端 share rejected/error 是正例可观察协议状态，只有构造无效配置且要求错误传播时才是负例。

## 9. 二十个语义场景和 packet_count 映射

以下 20 个唯一 ID 必须与 `73-ethmining-testcase.md` §2 同序同集合，为 14 个正例和 6 个负例；当前 JSON 另有一个不计数的注册前置占位。

| # | ID | 类型 | 覆盖 | 约定 packet_count |
|---:|---|---|---|---:|
| 1 | `ethmining_jsonrpc_ipv4_work` | 正 | IPv4/TCP JSON-RPC 建立、动态 getWork 与响应 | 8 |
| 2 | `ethmining_jsonrpc_ipv6_work` | 正 | IPv6/TCP JSON-RPC 和独立地址族工作响应 | 8 |
| 3 | `ethmining_getwork_legacy` | 正 | legacy `eth_getWork` 三项工作结果与请求 ID | 8 |
| 4 | `ethmining_submitwork_legacy` | 正 | legacy `eth_submitWork` nonce/header/mix 动态提交 | 10 |
| 5 | `ethmining_hashrate_methods` | 正 | `eth_getHashrate`、`eth_submitHashrate` 与动态值 | 10 |
| 6 | `ethmining_work_rotation` | 正 | epoch/job/work 轮换、旧工作过期和新工作关联 | 14 |
| 7 | `ethmining_share_accept` | 正 | share accepted、请求 ID、nonce/work/share ID 关联 | 10 |
| 8 | `ethmining_share_reject` | 正 | share rejected、原因和旧/低难度工作路径 | 10 |
| 9 | `ethmining_share_error` | 正 | share error 的 JSON-RPC error code/message/data 保留 | 10 |
| 10 | `ethmining_jsonrpc_id_correlation` | 正 | 并发请求/响应 ID、通知无 ID、错误响应方向 | 12 |
| 11 | `ethmining_http_jsonrpc_carrier` | 正 | HTTP POST/keep-alive、JSON body/header 与响应 | 12 |
| 12 | `ethmining_tcp_stratum_like_carrier` | 正 | 裸 TCP/行式类 Stratum 工作通知与提交 | 12 |
| 13 | `ethmining_multi_session_stream` | 正 | 多会话/多流、独立工作/epoch/nonce/share 状态 | 24 |
| 14 | `ethmining_pcap_nic_consistency` | 正 | PCAP/NIC 方向、载体、动态 JSON 字段一致 | 16 |
| 15 | `ethmining_neg_jsonrpc_params` | 负 | JSON-RPC/params/method/字段类型错误 | — |
| 16 | `ethmining_neg_hex_length` | 负 | hex 字符、奇偶性和字段长度错误 | — |
| 17 | `ethmining_neg_nonce_work_mismatch` | 负 | nonce/work hash/epoch/share 不匹配 | — |
| 18 | `ethmining_neg_id_correlation` | 负 | JSON-RPC ID 或跨会话关联错误 | — |
| 19 | `ethmining_neg_carrier_profile` | 负 | HTTP/载体/端口/IPv4/IPv6 族错误 | — |
| 20 | `ethmining_neg_error_propagation` | 负 | planner/validator 错误未传播、假成功或丢错 | — |

实现完成定义：注册 `ethmining` layer；完成 legacy 四方法、Stratum-like 工作通知/share 三态、动态字段生成、JSON-RPC ID map、HTTP/TCP/TLS carrier、IPv4/IPv6、多会话/多流、MSS 重组、PCAP/NIC 输出和错误传播；测试需覆盖上述 20 个场景及竞态/集成路径。不声称真实 PoW、区块、矿池凭证或 share 密码学有效。

## 10. 修订记录

- v1.0.0（2026-08-21）：建立 14 个 ETHMining JSON-RPC/Stratum-like 正例和 6 个严格负例，覆盖 legacy 四方法、动态工作轮换、share 接受/拒绝/错误、HTTP/TCP/TLS、IPv4/IPv6、多会话、多流、PCAP/NIC 和错误传播；不修改 Go/MCP。
