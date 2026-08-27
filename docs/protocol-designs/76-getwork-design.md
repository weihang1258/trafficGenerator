# GetWork（Bitcoin 工作获取 RPC，GetWork）v1 设计契约

> 版本：v1.0.0（设计阶段）  
> 日期：2026-08-21  
> 状态：仅设计与 PCAP（抓包文件）/NIC（网卡）用例契约；`getwork` 层尚未注册，不修改 Go（编程语言）/MCP（模型上下文协议）实现，不宣称当前 suite（测试套件）可运行。  
> 配套文件：`docs/protocol-designs/76-getwork-testcase.md`、`trafficgen/test/protocol_pcap/cases/getwork.json`  
> 规范基线：Bitcoin（比特币）旧式 `getwork` JSON-RPC（远程过程调用）接口、HTTP/1.1（超文本传输协议）请求/响应和 JSON-RPC 关联约定；注册 schema（模式）与固定 fixture（固定样本）是实现后的最终约束。

## 1. 范围、证据等级和未注册边界

本契约覆盖 Bitcoin daemon（守护进程）/矿工之间以 HTTP POST 承载的 legacy `getwork` RPC：客户端申请一份工作、服务器返回工作 blob（工作数据块）、target（目标）、midstate（中间状态）和 hash1（首轮哈希辅助常量），客户端修改 nonce（随机数）后提交工作，服务器返回 accepted/rejected（接受/拒绝）结果或 JSON-RPC error（错误）。覆盖常见 TCP 载体端口 8332 和 HTTP 端口 80、IPv4/IPv6、多流、多会话、keep-alive（保持连接）、重试、PCAP/NIC 观察和错误传播。

`getwork` 是 HTTP body（正文）中的 JSON-RPC 方法，不是独立二进制 TCP record（记录）或固定长度线协议。HTTP `Content-Length`（正文长度）或明确声明的分块封装决定 body 边界；TCP segment（分段）、PSH、MSS（最大报文段长度）和 packet_count（包数量）都不是 JSON 消息边界。每个 HTTP body 必须独立 JSON 解码；同一 TCP 连接上多个请求/响应按 HTTP 顺序关联。

运行期 `id`、job_id（工作任务标识，若扩展提供）、work/data（工作 blob）、nonce、midstate、hash1、target 和 submit result（提交结果）均不得用固定运行值冒充动态行为。测试只使用 `presence`（存在）、`nonzero`（非零）、`distinct`（不同）、`same_as_packet`（与指定包相同）、类型、十六进制字符集和声明长度断言；没有真实链、矿池或工作量证明上下文时，不声称 nonce 满足 target、share（份额）有效或区块生成成功。

当前仓库没有注册 `getwork` layer（层）、planner（规划器）、validator（校验器）或生成器。`cases/getwork.json` 只保留一个 `getwork_neg_unregistered` 注册前置占位，必须 `expect_error=true` 且 `error_contains="unknown layer"`；该占位不计入下面 20 个语义 ID。注册前拒绝、0 包、空 PCAP 或只有 TCP/HTTP 外壳都不是 GetWork 行为通过。

## 2. 推荐配置、层链和 HTTP 载体

推荐层链为 `[ip, tcp, http, getwork]` 或 `[ipv6, tcp, http, getwork]`；若实现把 HTTP 作为 getwork 的内部载体，也必须在 schema 中明确，不得将裸 TCP JSON 或未解密 TLS（传输层安全）误报为 GetWork 成功。

```json
{
  "layers": [{"ip": {}}, {"tcp": {}}, {"http": {}}, {"getwork": {}}],
  "src_ip": "192.0.2.76", "dst_ip": "198.51.100.76",
  "src_port": 4076, "dst_port": 8332,
  "http": {
    "method": "POST", "uri": "/", "version": "HTTP/1.1",
    "request_headers": {"Content-Type": "application/json", "Connection": "keep-alive"}
  },
  "getwork": {
    "profile": "bitcoin-legacy-jsonrpc",
    "methods": ["getwork", "submit"],
    "sessions": 1, "transactions": 2,
    "dynamic_work": true, "retry": 0
  }
}
```

| 配置键 | 约束 |
|---|---|
| `profile` | 固定 `bitcoin-legacy-jsonrpc`；JSON-RPC 1.0/2.0 的版本字段可由 fixture 显式选择，但不能以 Stratum（矿池工作分配协议）行式消息或二进制 v2 消息冒充 getwork。 |
| `transport`/`port` | 仅 TCP 上的 HTTP POST；8332 是 Bitcoin RPC 常见端口，80 是常见 HTTP carrier（载体）边界用例。端口不是唯一识别证据；UDP、错误 HTTP 方法和未声明端口进入负例。 |
| `uri` | 默认 `/`；路径可显式设置为 daemon 暴露的 RPC endpoint（端点），不能静默把任意路径改写成 `/`。 |
| `headers` | 请求至少声明 `Content-Type: application/json` 和正确 `Content-Length`，响应保持 `Content-Type` 与 body 边界一致；`Connection: keep-alive` 只在明确配置时使用。 |
| `method` | 申请工作使用 `getwork` 且 params（参数）为空数组；提交使用同一方法名的 data 参数，或 schema 明确声明的 `submit` 别名，不能混用未声明方法。 |
| `work` | 响应至少含动态 `data`/work blob、`target`、`midstate`、`hash1`；扩展可以含动态 `job_id`，但标准 getwork 不凭空生成 job 字段。 |
| `submit` | 提交必须引用同一会话最近工作并带修改后的 data/nonce；响应 result 为声明的布尔或 object 类型，不能把 error 静默转成 accepted。 |
| `sessions`/`flow_count` | 每个 TCP session 有独立 HTTP 缓冲、请求 ID、最近 work、nonce 和响应队列；多流不得共享全局工作状态。 |
| `retry`/`keep_alive` | 重试应产生新的动态 request ID 或显式重试关联；keep-alive 可复用连接但不能跨会话消费工作。重试次数为 0 时不得凭空增加请求。 |
| `wire_fault` | 仅负例注入口：`json`、`http`、`method`、`work`、`nonce`、`id`、`carrier`、`propagation`。 |

HTTP/1.1 的常见请求形态如下；动态值只表示字段位置：

```http
POST / HTTP/1.1
Host: 198.51.100.76:8332
Content-Type: application/json
Content-Length: <dynamic>
Connection: keep-alive

{"jsonrpc":"2.0","id":"id-dynamic","method":"getwork","params":[]}
```

服务器申请响应示例：

```http
HTTP/1.1 200 OK
Content-Type: application/json
Content-Length: <dynamic>
Connection: keep-alive

{"jsonrpc":"2.0","id":"id-dynamic","result":{"data":"work-hex-dynamic","target":"target-hex-dynamic","midstate":"midstate-hex-dynamic","hash1":"hash1-hex-dynamic","job_id":"job-dynamic"},"error":null}
```

服务器收到提交后可返回：

```json
{"jsonrpc":"2.0","id":"submit-id-dynamic","result":true,"error":null}
```

标准 legacy fixture 中，`data` 是 64-byte（字节）工作 blob，即 128 个十六进制字符；`midstate` 和 `target` 各为 32-byte，即 64 个十六进制字符；`hash1` 为 64-byte，即 128 个十六进制字符。若具体 schema 选择其他长度，必须在 profile 中显式声明，不能让测试从 TCP 长度猜测字段布局。

## 3. GetWork JSON-RPC 语义

### 3.1 申请工作

客户端发送 `method="getwork"`、`params=[]` 的 POST 请求。服务器返回与请求 `id` 相同的响应；`result` 为 work object（工作对象），至少包含 `data`、`target`、`midstate`、`hash1`。如果 fixture 声明了 `job_id`，它必须是动态且只在当前 session（会话）内有效；标准接口没有强制的 job_id，不能把一个固定占位字符串当作标准字段。

申请请求重复发送时，每个 transaction（事务）必须保留自己的 `id` 和 body 边界。重试可能返回新 work，也可能返回同一 work；测试根据 fixture 选择 `distinct` 或 `same_as_packet`，不能无条件声称两次一定不同。

### 3.2 工作字段和编码

- `data`/work blob 是待提交的十六进制工作数据；legacy fixture 默认 128 hex 字符。空值、奇数长度、非十六进制字符或声明长度不符必须拒绝。
- `target` 是目标阈值的十六进制表示；默认 64 hex 字符。测试只断言存在、字符集、声明长度和边界 fixture，不计算真实难度或 PoW。
- `midstate` 是由工作前半段导出的中间状态；默认 64 hex 字符。不能把任意 data 前缀的摘要当作已验证 midstate。
- `hash1` 是 legacy SHA-256 辅助常量；默认 128 hex 字符。它不是第二个 target，也不能与 midstate 互换。
- `nonce` 是矿工尝试值。标准 legacy 提交通常把 nonce 编码进 data；若 schema 额外暴露 `nonce` 字段，必须声明编码、宽度和与 data 的关联，测试不硬编码具体值。
- `job_id` 不是所有 legacy getwork 响应的标准字段；只有 profile 明确提供时才观察其动态存在和 submit 关联。没有 job_id 时，以 work blob/request 关联作为上下文。

### 3.3 提交工作和结果

客户端将最近 work 的 data 复制并修改 nonce 后提交。提交请求必须保留申请阶段可建立的 work/job 关联；不得跨 session 使用另一份 data、target 或 job_id。服务端 result 可以是布尔 `true`/`false`，也可以是 schema 声明的 object（例如含 status/share_id）；具体 fixture 必须固定类型。

`true` 只证明线路返回 accepted 语义，不证明真实区块或 PoW；`false` 是可观察 rejected（拒绝）正例，不是 planner（规划器）错误。JSON-RPC error 必须保留提交请求 ID、HTTP 状态/响应 body 和 error object；不能把 HTTP 200 或空 result 误判为成功。

### 3.4 ID、版本和错误

请求与响应按同一 HTTP session 内 `id` 关联，而不是只按 TCP packet order（包序）关联。通知不是 legacy getwork 的必需消息；如果扩展提供无 ID work notification（工作通知），必须在 profile 中声明，不能把缺失 ID 的响应当作成功申请。JSON-RPC 2.0 的 `jsonrpc`、`result` 和 `error` 字段类型必须稳定；1.0 profile 不得混入 2.0-only 字段而不声明。

正常的 rejected result 和协议错误响应是正例可观察状态；只有非法配置、字段缺失、载体错误或错误未传播才进入负例。错误信息应保留 `json`、`method`、`work`、`id`、`carrier` 或 `task` 等原始原因，不以 `completed/0 packet` 替代。

## 4. HTTP framing、keep-alive、重试与状态隔离

HTTP body 由 `Content-Length` 或 schema 明确的 chunked（分块）编码界定。请求/响应 body 跨多个 TCP segment 时，重组后才解码 JSON；多个 HTTP transaction 粘在同一 TCP payload 时，必须按 headers/body 边界拆分。`Content-Length` 截断、过长、重复或与 body 不一致属于负例；不能用 TCP FIN、PSH 或 packet_count 自动补全。

keep-alive 允许一个 session 连续执行 getwork→submit→getwork。每个事务仍需独立 `id`、HTTP headers 和 body；响应不得错配到上一事务。retry 在连接重置、明确 HTTP 5xx 或 fixture 指定条件下重新发送；重试次数和等待只作为可观察配置，不能无限生成流量。重试后的 submit 仍引用声明的 work 上下文，不能把失败申请的空 work 提交为 accepted。

每个 session 独立维护：HTTP header/body 缓冲、RPC ID map（映射表）、最近 work/data、job_id（如有）、nonce、submit result 和 retry counter（重试计数）。多 session 即使 worker 名称、request ID 或 job_id 文字相同，也不能串状态；多 flow（流）并发允许全局 packet order 交织。

## 5. IPv4/IPv6、多流、多会话和 PCAP/NIC

IPv4 fixture 观察 `ip.proto=6`；IPv6 fixture 观察 `ipv6.nxt=6`（无扩展头）或最终 TCP next header。8332 与 80 各至少有一个正例；端口仅作为 HTTP carrier 观察，不作为唯一协议识别依据。IPv4/IPv6 地址、端口和 session 状态必须来自各自 fixture，不得跨地址族复用动态 work。

PCAP/NIC 观察包含 TCP 三次握手/终止、HTTP POST 请求、响应方向、Host/Content-Type/Content-Length、JSON-RPC method/id、work 字段存在和 submit result。没有专用 GetWork dissector（解析器）时，使用 `tcp`、`http`、JSON raw payload（原始载荷）及 TCP stream reassembly（流重组）断言，不自创字段名。checksum offload（校验和卸载）可能影响校验和显示，但不改变 HTTP/JSON 证据。

同一 fixture 的 PCAP 与 NIC 捕获必须使用相同的动态字段断言策略：运行期值只做 presence/nonzero/distinct/same_as；不硬编码 request ID、job_id、data、nonce、target、midstate、hash1 或 share 结果。若输出为 PCAP 文件，不能因无真实网卡而声称 NIC 已验证；若输出为 NIC，不能把 tcpdump 无包误报成 planner 成功。

## 6. 错误处理和完成定义

6 个语义负例必须在 planner/validator 阶段失败并传播为 task error（任务错误），不能产生成功 PCAP、`completed/0 packet` 或只有 TCP/HTTP 外壳的假成功。未来注册后的负例 `expect` 键集合严格为 `{"expect_error", "error_contains"}`；当前 JSON 占位可带说明 `notes`，不属于 20 个语义 ID。

| ID | 故障输入 | 目标 `error_contains` |
|---|---|---|
| `getwork_neg_invalid_json` | 非法/截断 JSON、非 object body、Content-Length/HTTP body 无法完整解码 | `json`、`decode` 或 `body` |
| `getwork_neg_method_params` | 未知 method、getwork 非空 params、submit 缺 data/nonce 或参数类型错误 | `method`、`params` 或 `field` |
| `getwork_neg_work_fields` | data/target/midstate/hash1 缺失、非 hex、长度错误，或提交 work/nonce 不关联 | `work`、`data`、`target`、`midstate`、`nonce` 或 `length` |
| `getwork_neg_id_correlation` | 响应 ID 错配、跨事务/会话消费、submit 响应错序或伪造通知 ID | `id`、`match` 或 `correlation` |
| `getwork_neg_carrier_profile` | UDP/非 HTTP、错误方法/端口、HTTP 层链与 IPv4/IPv6 不一致 | `carrier`、`http`、`tcp`、`port` 或 `family` |
| `getwork_neg_error_propagation` | planner/validator 已知错误被吞掉，任务假成功、0 包或 RPC error 丢失 | `error`、`propagat` 或 `task` |

## 7. 二十个语义场景和 packet_count 映射

以下 20 个唯一 ID 必须与 `76-getwork-testcase.md` §2 同序同集合，为 14 个正例和 6 个负例；当前 JSON 另有一个不计数的注册前置占位。

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

实现完成定义：注册 `getwork` layer；实现 HTTP POST JSON-RPC getwork 申请、work 字段 schema、nonce/data 关联、submit accepted/rejected/error、ID map、keep-alive、重试、IPv4/IPv6、多流/多会话、HTTP body 重组、PCAP/NIC 输出和错误传播；-race（竞态检测）与集成测试覆盖上述 20 个场景。不声称真实 PoW、区块产生、target 达标或现实 RPC 凭证有效。

## 8. 修订记录

- v1.0.0（2026-08-21）：建立 14 个 Bitcoin legacy getwork HTTP/JSON-RPC 正例和 6 个严格负例，覆盖 80/8332 载体、动态 work/target/midstate/hash1/job/nonce、submit 结果、keep-alive、重试、IPv4/IPv6、多会话、多流、PCAP/NIC 与错误传播；不修改 Go/MCP。
