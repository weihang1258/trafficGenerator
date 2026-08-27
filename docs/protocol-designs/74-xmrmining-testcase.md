# XMRMining（门罗币挖矿协议，Monero/CryptoNote Mining）测试用例契约

> 版本：v1.0.0（设计阶段）  
> 日期：2026-08-21  
> 配套设计：`docs/protocol-designs/74-xmrmining-design.md`  
> 机器契约：`trafficgen/test/protocol_pcap/cases/xmrmining.json`  
> 状态：`xmrmining` 层尚未注册；本文定义实现后的 PCAP（抓包文件）/NIC（网卡）断言，不宣称当前 suite（测试套件）可运行。

## 1. 测试原则和未注册边界

用例从设计 §2–§8 逐项派生，共 20 个唯一语义 ID：14 个正例和 6 个负例。当前 JSON 只保留一个不计入语义覆盖的注册前置占位 `xmrmining_neg_unregistered`，其 `expect` 必须 `expect_error=true`、`error_contains="unknown layer"`；注册后移除占位，再按本文 §2 顺序加入 20 个语义用例。

动态 `job_id`、`blob`、`target`、`height`、`seed_hash`、`algo`、`nonce`、`share_id`、`extra_nonce` 和 JSON-RPC（远程过程调用）`id` 均不得硬编码；使用 `presence`（存在）、`nonzero`（非零）、`distinct`（不同）、`same_as_packet`（与指定包相同）及 schema（模式）规定的长度/字符集断言。无真实 RandomX/CryptoNight 工作量证明（Proof of Work，工作量证明）上下文时，不断言 share 有效或区块产生。

## 2. 原子用例索引

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

## 3. 正例逐项断言契约

1. **`xmrmining_stratum_ipv4_login_job`**：建立 IPv4/TCP，客户端发送 login，服务端返回动态 session/job；断言 JSON 行以 `\n` 结束、请求/响应 ID 匹配、job 含动态 `job_id`、hex `blob` 与 `target`，`packet_count=12`。
2. **`xmrmining_stratum_ipv6_login_job`**：独立 IPv6/TCP fixture（固定样本），断言 `ipv6.nxt=6`、IPv6 地址族、login/job 响应和行尾；IPv6 地址及流状态不能从 IPv4 fixture 继承，`packet_count=12`。
3. **`xmrmining_getjob_rpc`**：客户端发送 JSON-RPC `getjob`，服务端返回 result.job；断言动态 job ID、blob、target presence/nonzero、hex 格式和响应 ID，`packet_count=10`。
4. **`xmrmining_submit_rpc_share`**：先获取动态工作，再提交 JSON-RPC `submit` 的 job ID、nonce、blob/height 字段；断言 nonce 为 schema 规定的字符串、job/blob 与最近工作 `same_as_packet`，响应 ID 匹配，`packet_count=12`。
5. **`xmrmining_stratum_job_notify`**：服务端发送无 `id` 的 job 通知；断言 params/result 中动态 job ID、blob、target，以及声明的 height、seed_hash、algo/difficulty 字段类型，通知不能被当作响应，`packet_count=10`。
6. **`xmrmining_stratum_submit_share`**：先 job 再 submit，断言 submit 的 job ID、nonce、extra_nonce 与最近工作关联；动态字段只做 presence/nonzero/same_as，不断言真实 share，`packet_count=12`。
7. **`xmrmining_share_accept`**：客户端提交格式合法的动态 share，服务端返回 accepted/status OK；断言响应 ID、job/nonce 关联和动态 share ID，不能断言真实 PoW，`packet_count=10`。
8. **`xmrmining_share_reject`**：提交格式合法但进入 stale/低难度/无效 nonce 的拒绝路径；断言响应 ID、rejected status/reason、job/nonce 关联，拒绝不能伪装成成功，`packet_count=10`。
9. **`xmrmining_share_error`**：提交触发 JSON-RPC error，断言 response 仍有对应 ID、error code/message/data 类型和方向；不固定现实矿池文案，`packet_count=10`。
10. **`xmrmining_blob_nonce_association`**：工作通知带动态 blob、target、可选 reserved offset/height；提交带 nonce 或声明的 blob 更新；断言按 schema 字段/偏移关联，而不把任意固定偏移当通用规则，`packet_count=12`。
11. **`xmrmining_jsonrpc_id_correlation`**：同一会话并发 login/getjob/submit 请求和一个无 ID job 通知；断言通知无 ID、各响应 ID 与对应 method/request 匹配，错误响应也保留 ID，`packet_count=12`。
12. **`xmrmining_multi_session_stream`**：至少两个 TCP session 并行，每流独立 login、动态 job/blob/nonce/share 和请求 ID；断言同值 ID 在不同会话可独立但状态不串流，不假设全局包序，`packet_count=24`。
13. **`xmrmining_multi_flow_concurrency`**：至少两个 worker/flow 多流并发，断言四元组、登录状态、动态 job/nonce 和响应 ID 按流隔离；允许全局包交织，`packet_count=24`。
14. **`xmrmining_pcap_nic_consistency`**：同一明文 Stratum/RPC fixture 分别输出 PCAP 并执行 NIC 捕获；断言 TCP 握手/终止、双向方向、IPv4/IPv6/端口、重组 JSON 行、动态 job/blob/nonce/share 字段和 ID 关联在两种观察中一致。推荐过滤器 `tcp port 18081 or tcp port 18082`，`packet_count=16`。

没有专用 XMRMining dissector（解析器）时，使用 `tcp`、`http`、JSON raw bytes（原始字节）和稳定的方向/长度断言；未解密 TLS 只断言 TLS/TCP 记录，不能断言内部字段。TCP segment、MSS 和 packet_count 不是应用消息边界。

## 4. 负例契约

每个负例必须在 planner/validator 阶段失败并传播为 task error（任务错误）；不能产生成功 PCAP、`completed/0 packet` 或只有 TCP/HTTP 外壳的假成功。执行期 `expect` 键集合严格为 `{"expect_error", "error_contains"}`：

| ID | 故障输入 | 目标 `error_contains` |
|---|---|---|
| `xmrmining_neg_invalid_json` | 非法 JSON、截断对象、非 object 行或换行处无法解码 | `json`、`decode` 或 `line` |
| `xmrmining_neg_method_params` | 未知 method、login/getjob/submit 缺字段或 params 类型/位置错误 | `method`、`params` 或 `field` |
| `xmrmining_neg_blob_nonce_share_mismatch` | blob/job/target/nonce/share 不匹配，或 hex/长度错误 | `blob`、`nonce`、`work`、`share` 或 `length` |
| `xmrmining_neg_id_correlation` | 响应 ID 不匹配请求、通知带伪 ID、跨会话错配或响应错序 | `id`、`match` 或 `correlation` |
| `xmrmining_neg_carrier_profile` | UDP、非 TCP、错误 HTTP profile、端口或 IPv4/IPv6 层链不一致 | `carrier`、`tcp`、`http`、`port` 或 `family` |
| `xmrmining_neg_error_propagation` | planner/validator 已知错误被吞掉，任务假成功、0 包或错误响应丢失 | `error`、`propagat` 或 `task` |

上述故障均是不合法契约输入，不得被描述成可接受的特殊格式。服务端正常 share rejected/error 是正例状态，不应被误报为配置负例。

## 5. 三方一致性和静态检查

1. 设计 §8 的 20 个 ID、本文 §2、注册后的 JSON 和审计必须保持同一组 ID、同一顺序：14 正例 + 6 负例；当前 JSON 另有一个不计数的 `xmrmining_neg_unregistered` 占位。
2. 未来 14 个正例均有 `packet_count`/`min_packets`、TCP/HTTP carrier、方向和动态 job/blob/nonce/share 字段断言；6 个负例的 `expect` 键集合恰为 `{expect_error, error_contains}`，不添加 `notes`、`packet_count` 或其他键。
3. login/getjob/job/submit/keepalived 的 method、params 类型、通知无 ID、响应 ID matching（匹配）按真实重组后的整行 JSON 断言；不以 TCP segment 数量代替消息数量。
4. blob、target、height、seed_hash、algo、extra_nonce、nonce、share_id 的动态字段按声明类型与最近工作上下文关联；禁止固定运行期值。
5. 每个 TCP session 独立行缓存、登录状态、请求 ID map、最近 job/blob/target；多流并发不依赖全局包序，不能跨流拼接 JSON。
6. HTTP body 按 Content-Length/JSON 边界，裸 TCP/Stratum-like 按 newline/流重组；未解密 TLS 不断言内部明文。
7. PCAP 与 NIC 观察必须同时能看见 TCP 方向、端口、重组行边界和字段关联；checksum offload 只影响校验和显示，不改变应用层断言。
8. `python3 -m json.tool trafficgen/test/protocol_pcap/cases/xmrmining.json` 应成功；当前数组只能含 `xmrmining_neg_unregistered`，且 `proto=xmrmining`、`expect_error=true`、`error_contains` 精确为 `unknown layer`。

## 6. 实现后执行建议

注册 `xmrmining` layer 后，先核对 JSON parser（解析器）、层链、TCP stream（字节流）重组、换行/HTTP 边界、动态 job/blob/nonce/share 关联和 ID 顺序，再运行 1–14 的 PCAP/NIC 正例与 15–20 的错误传播。若环境无专用 dissector，使用通用 TCP/HTTP/raw payload 重组和 JSON 解码断言；不能将唯一 placeholder（占位）的拒绝结果报告为 XMRMining suite 通过。

## 7. 修订记录

- v1.0.0（2026-08-21）：建立 14 个 CryptoNote/Monero Stratum/RPC 正例和 6 个严格负例，覆盖动态工作/blob/nonce/share、JSON-RPC ID、TCP/HTTP、IPv4/IPv6、多会话、多流、PCAP/NIC 与错误传播；不修改 Go/MCP。
