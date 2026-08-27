# GetWork（Bitcoin 工作获取 RPC，GetWork）v1 测试用例契约

> 版本：v1.0.0（设计阶段）  
> 日期：2026-08-21  
> 配套设计：`docs/protocol-designs/76-getwork-design.md`  
> 机器契约：`trafficgen/test/protocol_pcap/cases/getwork.json`  
> 状态：`getwork` 层尚未注册；本文定义实现后的 PCAP（抓包文件）/NIC（网卡）断言，不宣称当前 suite（测试套件）可运行。

## 1. 测试原则和未注册边界

用例从设计 §2–§7 逐项派生，共 20 个唯一语义 ID：14 个正例和 6 个负例。当前 JSON 只保留一个不计入语义覆盖的注册前置占位 `getwork_neg_unregistered`，其 `expect` 必须 `expect_error=true`、`error_contains="unknown layer"`；注册后移除占位，再按本文 §2 顺序加入 20 个语义用例。

GetWork carrier（载体）是 HTTP POST over TCP（基于 TCP 的 HTTP POST），body 里承载 Bitcoin legacy JSON-RPC（旧式 JSON-RPC）。标准请求使用 `method="getwork"`、空 params；申请响应包含动态 `data`/work、`target`、`midstate`、`hash1`，后续提交引用最近工作并修改 nonce。测试按 HTTP headers/body 边界重组后再解码 JSON；不能把 TCP segment（分段）、MSS（最大报文段长度）、PSH 或 packet_count（包数量）当应用消息边界。

运行期 request ID（请求标识）、job_id（扩展工作标识）、work/data（工作 blob）、nonce、target、midstate、hash1 和 submit result（提交结果）不得硬编码；用 `presence`（存在）、`nonzero`（非零）、`distinct`（不同）、`same_as_packet`（同包值）、类型与声明长度断言。没有真实区块链或工作量证明上下文时，不断言 nonce 达标、share 有效或区块生成。

## 2. 原子用例索引

| # | ID | 类型 | 覆盖 | 约定 packet_count |
|---:|---|---|---|---:|
| 1 | `getwork_http_ipv4_8332` | 正 | IPv4/TCP/HTTP 8332 申请工作、请求响应 ID | 12 |
| 2 | `getwork_http_ipv6_8332` | 正 | IPv6/TCP/HTTP 8332 与地址族隔离 | 12 |
| 3 | `getwork_http_port80` | 正 | 常见 HTTP 80 carrier、POST 与 JSON-RPC body | 10 |
| 4 | `getwork_work_fields` | 正 | data/work blob、target、midstate、hash1 类型/长度/存在 | 12 |
| 5 | `getwork_dynamic_job_nonce` | 正 | 动态 request ID、job_id 扩展、work 与 nonce 关联 | 12 |
| 6 | `getwork_submit_accepted` | 正 | 申请→nonce 修改→submit accepted 结果 | 12 |
| 7 | `getwork_submit_rejected` | 正 | submit rejected/false 结果和请求 ID 保留 | 10 |
| 8 | `getwork_target_boundary` | 正 | target 边界 fixture、非零十六进制工作字段 | 10 |
| 9 | `getwork_keepalive_transactions` | 正 | keep-alive 上连续 getwork/submit、多 body 边界 | 16 |
| 10 | `getwork_retry_reassociation` | 正 | HTTP 失败后 retry、request ID 与 work 重新关联 | 16 |
| 11 | `getwork_multi_session_isolation` | 正 | 多会话独立 work、nonce、ID 和 submit 状态 | 24 |
| 12 | `getwork_multi_flow_concurrency` | 正 | 多流/多 worker 并发和全局交织状态隔离 | 24 |
| 13 | `getwork_ipv4_ipv6_dual` | 正 | IPv4/IPv6 并行 HTTP/TCP 方向和动态字段隔离 | 24 |
| 14 | `getwork_pcap_nic_consistency` | 正 | PCAP/NIC carrier、HTTP 边界、字段关联一致 | 16 |
| 15 | `getwork_neg_invalid_json` | 负 | JSON、body 或 Content-Length 边界非法 | — |
| 16 | `getwork_neg_method_params` | 负 | method/params/data 参数缺失或类型错误 | — |
| 17 | `getwork_neg_work_fields` | 负 | work 字段编码/长度/nonce 关联错误 | — |
| 18 | `getwork_neg_id_correlation` | 负 | RPC ID、事务或会话关联错误 | — |
| 19 | `getwork_neg_carrier_profile` | 负 | HTTP/TCP/端口/IPv4/IPv6 载体链错误 | — |
| 20 | `getwork_neg_error_propagation` | 负 | planner/validator 错误未传播或 RPC error 丢失 | — |

## 3. 正例逐项断言契约

1. **`getwork_http_ipv4_8332`**：建立 IPv4/TCP 连接到 8332，发送 HTTP/1.1 POST `/`，body 为 `getwork` 空 params；断言 TCP 握手、HTTP method、Content-Type、Content-Length、JSON object、动态 request ID 及响应 `id` matching（匹配），result 含 data/target/midstate/hash1，`packet_count=12`。
2. **`getwork_http_ipv6_8332`**：独立 IPv6/TCP/HTTP fixture，断言 `ipv6.nxt=6`（无扩展头）、8332 端口、请求响应 body 边界与 ID；IPv6 地址和状态不从 IPv4 流继承，`packet_count=12`。
3. **`getwork_http_port80`**：使用 TCP 80 作为常见 HTTP carrier，断言 POST、Host、JSON Content-Type、Content-Length 和 getwork body；端口只作载体观察，不把 80 当唯一协议识别，`packet_count=10`。
4. **`getwork_work_fields`**：申请工作并断言 result 中动态 data/work、target、midstate、hash1 均存在、非零、为合法偶数长度十六进制；legacy fixture 可断言 data=128、midstate/target=64、hash1=128 hex 字符，但不计算哈希，`packet_count=12`。
5. **`getwork_dynamic_job_nonce`**：fixture 显式提供动态 job_id 与 nonce 字段；断言 request ID、job_id、nonce 存在且非零，submit 的 job/data/nonce 与最近申请工作 `same_as_packet` 或 schema 声明的关联一致，不固定运行期值，`packet_count=12`。
6. **`getwork_submit_accepted`**：先 getwork，再修改工作中的 nonce 并提交；断言提交 method/params、work 关联、响应 ID 匹配和 result=true 或 schema 声明的 accepted object。accepted 不等于真实 PoW 成功，`packet_count=12`。
7. **`getwork_submit_rejected`**：提交结构合法但 fixture 返回 result=false/rejected；断言 HTTP/JSON 方向、submit ID、result 类型和拒绝状态，不能伪装为 accepted，也不固定现实拒绝文案，`packet_count=10`。
8. **`getwork_target_boundary`**：使用 schema 声明的最小或边界 target fixture；断言 target、data、midstate、hash1 的存在、十六进制字符集和长度，target 非零但不计算难度或 nonce 是否达标，`packet_count=10`。
9. **`getwork_keepalive_transactions`**：在同一 `Connection: keep-alive` session 上发送 getwork→submit→getwork 等连续事务；按 Content-Length 拆分粘连 body，断言每个 request/response ID 与对应事务关联、每份 work 独立、无跨事务错配，`packet_count=16`。
10. **`getwork_retry_reassociation`**：注入 HTTP 5xx/连接重置后按声明次数 retry；断言失败响应/重试方向可观察、重试 request ID 动态且关联正确，成功申请后的 submit 不消费失败事务的空 work，`packet_count=16`。
11. **`getwork_multi_session_isolation`**：至少两个 TCP sessions，各自 getwork/submit；断言每流独立 HTTP 缓冲、request ID、data/job/nonce 和结果，即使文本 ID 相同也不跨流配对，不依赖全局 packet order，`packet_count=24`。
12. **`getwork_multi_flow_concurrency`**：至少两个 worker/flow 并发输出，允许包交织；断言每个四元组、最近 work、submit nonce 和响应 ID 按流隔离，动态 work 可 `distinct`，不以全局最后工作关联，`packet_count=24`。
13. **`getwork_ipv4_ipv6_dual`**：同时输出独立 IPv4 与 IPv6 HTTP/TCP 流；断言 IPv4 `ip.proto=6`、IPv6 TCP next header、地址族/端口/方向和各自 work/nonce/ID 状态，不跨族复用字段，`packet_count=24`。
14. **`getwork_pcap_nic_consistency`**：同一明文 fixture 分别输出 PCAP 并执行 NIC 捕获；断言 TCP 握手/终止、HTTP 请求/响应方向、8332 或 80 端口、headers/body 边界、JSON method/id、work 字段和 submit result 在两种观察中一致。记录 checksum offload 差异；推荐过滤器 `tcp port 8332 or tcp port 80`，`packet_count=16`。

没有专用 GetWork dissector（解析器）时，使用 `tcp`、`http`、重组 raw JSON payload（原始 JSON 载荷）和稳定 headers 断言；不创建不存在的字段名。不得断言固定动态 request ID、job_id、data、target、midstate、hash1、nonce 或真实 share/区块结果。

## 4. 负例契约

每个负例必须在 planner/validator 阶段失败并传播为 task error（任务错误）；不能产生成功 PCAP、`completed/0 packet` 或只有 TCP/HTTP 外壳的假成功。执行期 `expect` 键集合严格为 `{"expect_error", "error_contains"}`：

| ID | 故障输入 | 目标 `error_contains` |
|---|---|---|
| `getwork_neg_invalid_json` | 非法/截断 JSON、非 object body、Content-Length 与 body 不一致 | `json`、`decode` 或 `body` |
| `getwork_neg_method_params` | 未知 method、getwork 非空 params、submit 缺 data/nonce 或参数类型错误 | `method`、`params` 或 `field` |
| `getwork_neg_work_fields` | data/target/midstate/hash1 缺失、非 hex、长度错误，或 work/nonce 不关联 | `work`、`data`、`target`、`midstate`、`nonce` 或 `length` |
| `getwork_neg_id_correlation` | 响应 ID 错配、跨事务/会话消费、submit 响应错序或伪造通知 ID | `id`、`match` 或 `correlation` |
| `getwork_neg_carrier_profile` | UDP/非 HTTP、错误方法/端口、HTTP 层链与 IPv4/IPv6 不一致 | `carrier`、`http`、`tcp`、`port` 或 `family` |
| `getwork_neg_error_propagation` | planner/validator 已知错误被吞掉，任务假成功、0 包或 RPC error 丢失 | `error`、`propagat` 或 `task` |

上述故障均是不合法契约输入，不得被描述成可接受的特殊格式。正常 result=false/rejected 和 JSON-RPC error 响应分别由正例 7/错误观察覆盖；负例只检查非法配置和错误传播。

## 5. 三方一致性和静态检查

1. 设计 §7 的 20 个 ID、本文 §2、注册后的 JSON 和审计必须保持同一组 ID、同一顺序：14 正例 + 6 负例；当前 JSON 另有一个不计数的 `getwork_neg_unregistered` 占位。
2. 未来 14 个正例均有 `packet_count`/`min_packets`、HTTP/TCP carrier、方向、body 边界和动态 work 字段断言；6 个负例的 `expect` 键集合恰为 `{expect_error, error_contains}`，不添加 `notes`、`packet_count` 或其他键。
3. getwork 申请必须是 `method=getwork`、空 params；submit 必须按 profile 声明 data/nonce/work 关联；响应 ID 按真实 HTTP transaction matching，不以 TCP segment 数量代替消息数量。
4. data/work、target、midstate、hash1、job_id、nonce 和 result 按声明类型/长度/上下文关联；动态值只使用 presence/nonzero/distinct/same_as。
5. 每个 HTTP TCP session 独立 header/body 缓冲、RPC ID map、最近 work 和 retry 计数；keep-alive 连续事务和多流并发不依赖全局包序。
6. IPv4/IPv6 地址族、80/8332 端口和 HTTP 层链必须与 fixture 一致；UDP、非 HTTP 或错误 family 进入负例。
7. PCAP 与 NIC 观察必须同时能看见 TCP 方向、HTTP headers/body 边界、JSON method/id 和动态 work/nonce 关联；checksum offload 只影响校验和显示。
8. `python3 -m json.tool trafficgen/test/protocol_pcap/cases/getwork.json` 应成功；当前数组只能含 `getwork_neg_unregistered`，且 `proto=getwork`、`expect_error=true`、`error_contains` 精确为 `unknown layer`。

## 6. 实现后执行建议

注册 `getwork` layer 后，先核对 HTTP parser（解析器）、Content-Length/keep-alive 边界、JSON-RPC ID、work 字段 schema、nonce/data 关联、重试与错误传播，再运行 1–14 的 PCAP/NIC 正例与 15–20 的错误传播。若环境无专用 dissector，使用通用 TCP/HTTP/raw body 重组和 JSON 解码断言；不能将唯一 placeholder（占位）的拒绝结果报告为 GetWork suite 通过。

## 7. 修订记录

- v1.0.0（2026-08-21）：建立 14 个 Bitcoin legacy getwork HTTP/JSON-RPC 正例和 6 个严格负例，覆盖 80/8332 载体、动态 work/target/midstate/hash1/job/nonce、submit 结果、keep-alive、重试、IPv4/IPv6、多会话、多流、PCAP/NIC 与错误传播；不修改 Go/MCP。
