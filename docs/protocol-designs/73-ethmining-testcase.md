# ETHMining（以太坊挖矿协议，Ethereum Mining）测试用例契约

> 版本：v1.0.0（设计阶段）  
> 日期：2026-08-21  
> 配套设计：`docs/protocol-designs/73-ethmining-design.md`  
> 机器契约：`trafficgen/test/protocol_pcap/cases/ethmining.json`  
> 状态：`ethmining` 层尚未注册；本文定义实现后的 PCAP（抓包文件）/NIC（网卡）断言，不宣称当前 suite（测试套件）可运行。

## 1. 测试原则和未注册边界

用例从设计 §2–§9 逐项派生，共 20 个唯一语义 ID：14 个正例和 6 个负例。当前 JSON 只保留一个不计入语义覆盖的注册前置占位 `ethmining_neg_unregistered`，其 `expect` 必须 `expect_error=true`、`error_contains="unknown layer"`；注册后移除占位，再按本文 §2 顺序加入 20 个语义用例。

动态 epoch（纪元）、nonce（随机数）、work hash（工作哈希）、seed hash（种子哈希）、target（目标）、mix hash、job ID、share ID（份额标识）、extra nonce 和 JSON-RPC（远程过程调用）`id` 均不得硬编码；使用 `presence`（存在）、`nonzero`（非零）、`distinct`（不同）、`same_as_packet`（与指定包相同）及运行期长度断言。无真实链状态/PoW（工作量证明）验证上下文时，不断言 share 有效或区块产生。

## 2. 原子用例索引

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
| 16 | `ethmining_neg_hex_length` | 负 | hex（十六进制）字符、奇偶性和字段长度错误 | — |
| 17 | `ethmining_neg_nonce_work_mismatch` | 负 | nonce/work hash/epoch/share 不匹配 | — |
| 18 | `ethmining_neg_id_correlation` | 负 | JSON-RPC ID 或跨会话关联错误 | — |
| 19 | `ethmining_neg_carrier_profile` | 负 | HTTP/载体/端口/IPv4/IPv6 族错误 | — |
| 20 | `ethmining_neg_error_propagation` | 负 | planner/validator 错误未传播、假成功或丢错 | — |

## 3. 正例逐项断言契约

1. **`ethmining_jsonrpc_ipv4_work`**：建立 IPv4/TCP，断言请求 JSON-RPC 版本、动态 `id`、`eth_getWork` 和空 params；响应 ID `same_as_packet`，result 为至少三项动态 hex 工作字段，`packet_count=8`。
2. **`ethmining_jsonrpc_ipv6_work`**：独立 IPv6/TCP fixture（固定样本），断言 `ipv6.nxt=6`、地址族和动态工作响应；IPv6 地址不能从 IPv4 fixture 继承，`packet_count=8`。
3. **`ethmining_getwork_legacy`**：断言 legacy `eth_getWork` 请求无参数，响应数组中 header hash、seed hash、target 均 presence/nonzero、hex 格式和 schema 长度；不硬编码工作值，`packet_count=8`。
4. **`ethmining_submitwork_legacy`**：先获取动态工作，再提交 `eth_submitWork` 的 nonce/header hash/mix hash；断言参数为字符串、nonce 固定宽度、三者 hex 且 header 与最近工作 `same_as`，响应 ID 匹配，`packet_count=10`。
5. **`ethmining_hashrate_methods`**：分别断言 `eth_getHashrate` 的动态 result，以及 `eth_submitHashrate` 的 hashrate/miner identifier 字段、hex 长度和响应 ID；不把算力上报当作 share，`packet_count=10`。
6. **`ethmining_work_rotation`**：服务端发出至少两份不同工作/epoch/job，上一次工作后发生 rotation（轮换）；断言新工作 `distinct`、新提交绑定新工作，旧工作进入 stale/rejected/error，而不静默套用新工作，`packet_count=14`。
7. **`ethmining_share_accept`**：客户端提交动态 nonce、工作 hash、mix hash/share ID；服务端返回 accepted/result=true 或声明的接受对象，响应 ID 与提交匹配，字段仅做动态关联，不断言真实 PoW，`packet_count=10`。
8. **`ethmining_share_reject`**：提交格式合法但被服务端拒绝的 share；断言响应 ID、rejected result/reason、工作和 nonce 关联，拒绝不能伪装为区块成功，`packet_count=10`。
9. **`ethmining_share_error`**：提交触发 JSON-RPC error，断言 response 仍有对应 ID、error code/message/data 类型和方向；错误文本可 fixture 化，不硬编码现实矿池文案，`packet_count=10`。
10. **`ethmining_jsonrpc_id_correlation`**：同一会话并发两个 legacy 请求和一个 Stratum-like 通知；断言通知无 ID、各响应 ID 与对应 method/request 匹配而非按 TCP 位置配对，错误响应也保留 ID，`packet_count=12`。
11. **`ethmining_http_jsonrpc_carrier`**：HTTP POST/keep-alive 承载 JSON-RPC，断言 request method、`Content-Type`、body 长度、响应 HTTP 状态和 JSON 对象；多个 body 按 HTTP 边界独立关联，`packet_count=12`。
12. **`ethmining_tcp_stratum_like_carrier`**：裸 TCP 行式 Stratum-like fixture，断言工作通知、share submit、accepted/rejected/error 响应和换行重组；TCP 分段不作为 JSON 消息边界，`packet_count=12`。
13. **`ethmining_multi_session_stream`**：至少两个 TCP 会话/多流并行，每流有独立动态工作、epoch、nonce、share 和请求 ID；断言同值 ID 在不同会话可独立但状态不串流，不假设全局包序，`packet_count=24`。
14. **`ethmining_pcap_nic_consistency`**：同一明文 JSON-RPC 或 Stratum-like fixture 分别输出 PCAP 并在 NIC 捕获；断言 TCP 方向、IPv4/IPv6、HTTP/裸 TCP carrier、动态 JSON 字段和 ID 关联一致。推荐过滤器 `tcp port 8545 or tcp port 8546`，`packet_count=16`。

没有专用 ETHMining dissector（解析器）时，使用 `tcp`、`http`、JSON raw bytes（原始字节）和稳定的方向/长度断言；未解密 TLS 只断言 TLS/ TCP 记录，不能断言内部 JSON。

## 4. 负例契约

每个负例必须在 planner/validator 阶段失败并传播为 task error（任务错误）；不能产生成功 PCAP、`completed/0 packet` 或只有 TCP/HTTP 外壳的假成功。执行期 `expect` 键集合严格为 `{"expect_error", "error_contains"}`：

| ID | 故障输入 | 目标 `error_contains` |
|---|---|---|
| `ethmining_neg_jsonrpc_params` | JSON-RPC 版本、method、params 类型/数量或字段角色错误 | `jsonrpc`、`method` 或 `params` |
| `ethmining_neg_hex_length` | nonce/work hash/mix hash/target/hashrate 非 hex、奇数长度或错误解码长度 | `hex`、`length` 或 `hash` |
| `ethmining_neg_nonce_work_mismatch` | nonce、旧 epoch、header/work hash、mix hash 或 share 与最近工作不匹配 | `nonce`、`work`、`epoch` 或 `share` |
| `ethmining_neg_id_correlation` | response ID 错配、跨会话消费、请求/响应 method 或方向错配 | `id`、`match` 或 `correlation` |
| `ethmining_neg_carrier_profile` | HTTP method/body、TLS/裸 TCP、UDP、端口或 IPv4/IPv6 层族不一致 | `carrier`、`http`、`tcp`、`port` 或 `family` |
| `ethmining_neg_error_propagation` | planner/validator 已知错误被吞掉，任务假成功、0 包或错误响应丢失 | `error`、`propagat` 或 `task` |

`ethmining_neg_*` 六项的 `expect` 不得包含 frames、fields、packet_count、notes 等运行成功断言。服务端正常 share rejected/error 是正例状态，不应被误报为配置负例。

## 5. 三方一致性和静态检查

1. 设计 §9 的 20 个 ID、本文 §2、注册后的 JSON 和审计必须保持同一组 ID、同一顺序：14 正例 + 6 负例；当前 JSON 另有一个不计数的注册前置占位。
2. 未来 14 个正例均有 `packet_count`/`min_packets`、carrier、方向和动态 JSON/hex 字段断言；6 个负例的 `expect` 只能有 `expect_error`、`error_contains`。当前未注册 JSON 只验证 placeholder（占位）结构。
3. legacy 四方法必须分别测试 method、params、result/error、动态 ID 和字段格式；不能只测试一条 TCP/HTTP 外壳。
4. 工作轮换、nonce/work mismatch、share accepted/rejected/error 和 JSON-RPC ID correlation 必须按会话状态断言；运行期值不得硬编码。
5. HTTP body 按 Content-Length/JSON 边界，裸 TCP/Stratum-like 按 newline/流重组；TCP segment、MSS 和 packet_count 不是应用消息边界。
6. IPv4/IPv6、多会话和 PCAP/NIC 断言以流内状态为准；未解密 TLS 不断言 HTTP/JSON 明文。
7. `python3 -m json.tool trafficgen/test/protocol_pcap/cases/ethmining.json` 应成功；当前数组只能含 `ethmining_neg_unregistered`，且 `proto=ethmining`、`expect_error=true`、`error_contains` 精确为 `unknown layer`。

## 6. 实现后执行建议

注册 `ethmining` layer 后，先核对 JSON parser（解析器）、ID 顺序、正负 expect 键集合、legacy 四方法、hex 长度、工作轮换、nonce 绑定、share 三态、HTTP/TCP/TLS carrier 和错误传播，再运行 1–14 的 PCAP/NIC 正例及 15–20 的错误传播。若环境无专用 dissector，使用通用 TCP/HTTP/TLS/raw bytes 证据；不能将唯一 placeholder 运行结果报告为 ETHMining suite 通过。

## 7. 修订记录

- v1.0.0（2026-08-21）：建立 14 个 Ethereum legacy JSON-RPC/Stratum-like 正例和 6 个严格负例，覆盖动态工作、share 三态、JSON-RPC ID、HTTP/TCP/TLS、IPv4/IPv6、多会话、多流、PCAP/NIC 与错误传播；不修改 Go/MCP。
