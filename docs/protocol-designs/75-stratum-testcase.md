# Stratum（矿池工作分配协议，Stratum）v1 测试用例契约

> 版本：v1.0.0（设计阶段）  
> 日期：2026-08-20  
> 配套设计：`docs/protocol-designs/75-stratum-design.md`  
> 机器契约：`trafficgen/test/protocol_pcap/cases/stratum.json`  
> 状态：`stratum` 层尚未注册；本文定义实现后的 PCAP（抓包文件）/NIC（网卡）断言，不宣称当前 suite（测试套件）可运行。

## 1. 测试原则和未注册边界

用例从设计 §2–§8 逐项派生，共 20 个唯一语义 ID：14 个正例和 6 个负例。当前 JSON 只保留一个不计入语义覆盖的注册前置占位 `stratum_neg_unregistered`，其 `expect` 必须 `expect_error=true`、`error_contains="unknown layer"`；注册后移除占位，再按本文 §2 顺序加入 20 个语义用例。

Stratum v1 carrier（载体）为明文 TCP JSON 行；没有私有长度前缀。测试先按 TCP stream（字节流）重组，再按 `\n` 取得消息；一个 segment（分段）可含半行或多行，不能把 segment 边界当 JSON 边界。没有真实矿池、PoW（工作量证明）上下文或凭证验证材料时，只断言结构、方向、字段类型、动态字段存在和消息间关联，不声称 share 有效、区块成立、密码正确或加密已完成。

运行期 `nonce`、`extra_nonce`、`job_id`、`prevhash`、merkle root、coinbase、`ntime`、`nbits`、difficulty 和 `id` 使用 `presence`、`nonzero`、`same_as_packet`、`distinct` 与类型断言；禁止固定具体动态值。

## 2. 原子用例索引

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

## 3. 正例逐项断言契约

1. **`stratum_tcp_ipv4_subscribe_authorize`**：建立 IPv4/TCP，客户端发送 `mining.subscribe` 与 `mining.authorize`，服务端响应 `id` 分别匹配；断言 TCP 握手、3333 端口、每行 `\n`、JSON object、授权成功 `error=null`，动态 subscription/extra_nonce 只 presence/nonzero，`packet_count=12`。
2. **`stratum_tcp_ipv6_subscribe_authorize`**：独立 IPv6/TCP fixture，断言 `ipv6.nxt=6`、IPv6 地址族、subscribe/authorize 请求响应和行尾；不继承 IPv4 地址或 stream 状态，`packet_count=12`。
3. **`stratum_notify_job_message`**：服务端发送无 `id` 的 `mining.notify`，断言 params 依次包含 job_id、prevhash、coinb1、coinb2、merkle branch 数组、version、nbits、ntime、clean_job 布尔值；动态字段 presence/nonzero，不硬编码，`packet_count=10`。
4. **`stratum_set_difficulty`**：服务端发送无 `id` 的 `mining.set_difficulty`，断言 params 中 difficulty 为数值、覆盖最小正值和会话内变更；通知不当成响应，`packet_count=8`。
5. **`stratum_submit_share`**：先 notify 再 submit，断言 submit params 含 worker、job_id、extra_nonce、ntime、nonce，submit job_id `same_as_packet` 最近 notify，动态 nonce/extra_nonce presence/nonzero；不断言真实 share 有效，`packet_count=12`。
6. **`stratum_jsonrpc_id_matching`**：发送多个请求、通知和成功/错误响应，断言请求与响应 id 类型存在且逐项匹配，同一 session 内关联；notify 不含 id，不能用 null 伪造请求 ID，`packet_count=12`。
7. **`stratum_line_framing_reassembly`**：将一行拆成多个 TCP payload，并将多行粘连在一个 payload；按重组 stream 后断言每一行独立 JSON、恰有换行分隔，segment 边界不产生额外消息，`packet_count=12`。
8. **`stratum_get_version_configure`**：断言 `client.get_version` 请求/响应及 `mining.configure` 的 method、params 类型和 id matching；只观察声明的版本/扩展字段，不宣称 v2 加密或二进制协商，`packet_count=10`。
9. **`stratum_authorize_reject`**：发送授权失败 fixture，断言服务端响应方向、响应 id 与 authorize 匹配、`error` 为 object/数组等声明类型且 result 不被伪造成成功；不固定现实错误文本，`packet_count=10`。
10. **`stratum_multi_session_stream`**：至少两个 TCP session 并行，各自 subscribe/authorize/notify/submit；断言行缓存、request id、job_id、extra_nonce 和响应状态隔离，不能跨流配对，`packet_count=24`。
11. **`stratum_multi_worker_concurrency`**：至少两个 worker 多流并发，断言每流独立四元组、worker 参数、动态 job/nonce 和响应 ID；允许全局包交织，不依赖固定全局顺序，`packet_count=24`。
12. **`stratum_ipv4_ipv6_dual`**：同时输出独立 IPv4 与 IPv6 流，断言 IPv4 `ip.proto=6`、IPv6 TCP next header、地址族/方向/端口和各自状态隔离；不跨地址族复用动态字段，`packet_count=24`。
13. **`stratum_dynamic_field_association`**：完整 notify→set_difficulty→submit 上下文，断言 job_id、prevhash、coinbase/merkle、ntime、nbits、extra_nonce、nonce 均按声明类型存在，submit job/ntime 与工作上下文关联；值只 presence/nonzero/same_as，`packet_count=12`。
14. **`stratum_pcap_nic_consistency`**：同一明文 fixture 分别输出 PCAP 并执行 NIC 捕获；断言 TCP 握手/终止、双向方向、端口、重组 JSON 行、换行、notify 无 id、请求响应 id 和动态字段关联在两种观察中一致。过滤器推荐 `tcp port 3333`，记录 checksum offload 差异，`packet_count=16`。

没有真实 PoW/矿池验证材料时，不添加“nonce 满足目标”“share accepted 必然有效”“密码正确”“job 属于真实区块”或固定动态值断言。没有专用 Stratum dissector（解析器）时，使用 `tcp`、重组 raw payload 和稳定 JSON 行字段断言；不把私有 record header 加入正例。

## 4. 负例契约

每个负例必须在 planner/validator 失败并传播为 task error；不能产生成功 PCAP、`completed/0 packet` 或只有 TCP 外壳的假成功。执行期 `expect` 键集合严格为 `{"expect_error", "error_contains"}`：

| ID | 故障输入 | 目标 `error_contains` |
|---|---|---|
| `stratum_neg_invalid_json` | 非法 JSON、截断对象、非 object 行或换行处无法解码 | `json`、`decode` 或 `line` |
| `stratum_neg_method_params` | 未知 method、缺少必需 params、params 类型/位置错误 | `method`、`params` 或 `field` |
| `stratum_neg_id_correlation` | 响应 ID 不匹配请求、通知带伪 ID、跨会话错配或响应错序 | `id`、`match` 或 `correlation` |
| `stratum_neg_version_method` | 未知 profile/version 或 v2 二进制/未声明 method 混入 v1 | `version`、`profile` 或 `method` |
| `stratum_neg_line_framing` | 无 `\n` 终止、把 TCP segment 当行、私有长度前缀或跨流拼行 | `framing`、`newline` 或 `stream` |
| `stratum_neg_carrier` | UDP、非 TCP、错误端口、IPv4/IPv6 层链不一致 | `carrier`、`tcp`、`port` 或 `family` |

上述故障均是不合法契约输入，不得被描述成“可接受的特殊格式”。特别是没有换行终止、私有长度前缀、TCP segment 边界和跨 stream 拼接不能成为正例 framing（封帧）行为；负例必须由 validator/planner 报出明确原因。动态字段缺失或错配必须报字段/关联错误，不得以空字符串或固定零值静默补全。

## 5. 三方一致性和静态检查

1. 设计 §8 的 20 个 ID、本文 §2、注册后的 JSON 和审计必须保持同一组 ID、同一顺序：14 正例 + 6 负例；当前 JSON 另有一个不计数的 `stratum_neg_unregistered` 占位。
2. 未来 14 个正例均有 `packet_count`/`min_packets`、TCP carrier、方向、行边界和稳定 JSON 字段；6 个负例的 `expect` 键集合恰为 `{expect_error, error_contains}`，不添加 `notes`、`packet_count` 或其他键。
3. subscribe/authorize/notify/set_difficulty/submit/get_version/configure 的 method、params 类型、通知无 id、响应 id matching 按真实重组后的整行 JSON 断言；不以 TCP segment 数量代替消息数量。
4. `mining.notify` 的 job、prevhash、coinb、merkle、version、nbits、ntime、clean_job 字段按位置和类型观察；`mining.submit` 的 job_id 必须来自同 session 最近 notify，动态值使用 presence/nonzero/same_as。
5. 每个 TCP session 独立行缓存、请求 ID map、job/difficulty/extra_nonce；多 worker 和 IPv4/IPv6 并发不依赖全局包序，不能跨 stream 拼接 JSON。
6. `stratum+tcp` 只是 URI/端口 profile 名称；v1 不含私有 record header，不把 v2 二进制、TLS 或 UDP 当作合法 v1 载体。
7. PCAP 与 NIC 观察必须同时能看见 TCP 方向、端口、重组行边界和字段关联；checksum offload 只影响校验和显示，不改变应用层断言。
8. `python3 -m json.tool trafficgen/test/protocol_pcap/cases/stratum.json` 应成功；当前数组只能含 `stratum_neg_unregistered`，且 `proto=stratum`、`expect_error=true`、`error_contains` 精确为 `unknown layer`。
9. 未来注册后，20 个语义 case 按本文 §2 顺序加入；负例 `expect` 键集合必须恰为 `{expect_error, error_contains}`，占位不计入 20 个 ID。

## 6. 实现后执行建议

注册 `stratum` layer 后，先检查 JSON parser、层链、TCP stream 重组、换行边界、动态字段关联和 ID 顺序，再运行 1–14 的 PCAP/NIC 正例与 15–20 的错误传播。若环境没有 Stratum dissector，使用通用 TCP/raw payload 重组和 JSON 解码断言；不能将唯一 placeholder 的拒绝结果报告为 Stratum suite 通过。

## 7. 修订记录

- v1.0.0（2026-08-20）：建立 14 个 Stratum v1 TCP/JSON 行式正例和 6 个严格负例，覆盖消息阶段、动态字段关联、TCP 重组、IPv4/IPv6、多会话/多 worker、PCAP/NIC 与错误传播；不修改 Go 实现。
