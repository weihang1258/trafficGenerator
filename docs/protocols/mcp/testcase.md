# MCP 测试用例契约

> 版本：v1.0.0（P-PIPE 文档轨 as-built）  
> 日期：2026-09-29  
> 配套设计：`docs/protocols/mcp/design.md` v1.1.3（当前层链设计契约）  
> 机器契约：`trafficgen/test/protocol_pcap/cases/mcp.json`  
> 一句话：**103 条 MCP 用例，89 条正例覆盖 stdio、HTTP+SSE、Streamable HTTP、生命周期、能力协商、工具/资源/提示词/采样和状态机；14 条负例验证配置、状态、传输与字段边界被拒绝。**

## 1. 测试原则与机读基线

本文件只记录 `mcp.json` 当前真实存在的用例、断言形状和可由设计文档回指的行为，不把设计文档中尚未落入 cases JSON 的场景写成已覆盖。用例编号、顺序和 ID 以 JSON 文件为权威；本文按文件顺序编号 #1–#103。

### 1.1 总量

| 项 | 机读结果 |
|---|---:|
| 总例数 | **103** |
| 正例 | **89** |
| 负例 | **14** |
| 正例 `packet_count` | 89/89（当前没有 `min_packets`） |
| 正例包数合计 | **1202** |
| `expect.fields` 条数 | **64** |
| `expect.frames` 条数 | **149** |
| `expect.notes` | 89/103 |
| 例级 `notes` | 6/103 |
| `strategy_fc` | 4/103 |

正例 packet count 合计只用于描述现有 JSON，不等价于今日全量生成或 PCAP 通过证据。

### 1.2 顶层形状

- 102/103 例的 `spec_json` 顶层键严格为 `{layers}`。
- `mcp_t090_presence_reject`（#90）为故意的 presence 负例，顶层键为 `{layers,mcp}`，用于验证顶层 MCP 子配置被拒绝；这不是正例残留。
- 93 例的例级顶层键为 `{expect,id,proto,spec_json,summary}`；6 例追加例级 `notes`；2 例追加 `strategy_fc`；2 例同时追加 `strategy_fc` 与例级 `notes`。
- 正例 `expect` 都含 `packet_count`；负例不含 `packet_count`、`fields` 或 `frames`。
- 负例 `expect`：14 例严格为 `{expect_error,error_contains}`。
- 正例 `expect.fields` 仅使用 `tcp.*` 字段通道；帧级断言使用 `frames[].offset + hex`。

### 1.3 传输基线

| 传输值 | 例数 | 说明 |
|---|---:|---|
| `stdio` | 94 | 行分隔 JSON over TCP |
| `streamable` | 4 | 单端点 HTTP；含认证、DELETE 和完整流程 |
| `http_sse` | 3（正例 2、负例 1） | 正例 GET SSE 先行、endpoint 事件、POST 202；负例验证非法认证方案 |
| 未写 `transport` | 1 | #91 `mcp_t091_default_dual`，由实现默认值处理 |
| 非法 `websocket` | 1 | #95 `mcp_t095_transport_reject`，负例 |

设计 §2.3–§2.5 声明的三种合法传输均有正例；WebSocket 不属于设计允许集合，仅作为非法输入负例。

## 2. 原子用例索引

下表保留 JSON 的精确顺序、ID、正负类型、包数和断言计数。`F` 为 `expect.fields` 条数，`R` 为 `expect.frames` 条数；负例以 `—` 表示不产生成功包数断言。

| # | ID | 类型 | 包数 | F | R | 主要覆盖 |
|---:|---|---|---:|---:|---:|---|
| 1 | `mcp_tpos1_stdio_initialize` | 正 | 14 | 5 | 6 | stdio 默认会话 |
| 2 | `mcp_tpos2_stdio_default_seq` | 正 | 14 | 2 | 3 | requests 缺省序列 |
| 3 | `mcp_tpos3_stdio_ping` | 正 | 12 | 3 | 2 | ping 配对 |
| 4 | `mcp_tpos4_stdio_resources` | 正 | 14 | 1 | 4 | resources/list/read |
| 5 | `mcp_tpos5_stdio_notifications` | 正 | 14 | 2 | 2 | progress/message 通知 |
| 6 | `mcp_tpos6_stdio_error_response` | 正 | 14 | 0 | 2 | -32602/-32601 响应 |
| 7 | `mcp_tpos7_http_sse_session` | 正 | 19 | 2 | 8 | HTTP+SSE 完整会话 |
| 8 | `mcp_tpos8_streamable_http` | 正 | 17 | 2 | 6 | Streamable + DELETE |
| 9 | `mcp_t024_stdio_prompts_get` | 正 | 12 | 4 | 2 | prompts/get |
| 10 | `mcp_t026_stdio_completion_complete` | 正 | 12 | 4 | 2 | completion |
| 11 | `mcp_t027_stdio_logging_setlevel` | 正 | 12 | 4 | 2 | logging/setLevel |
| 12 | `mcp_t050_stdio_parse_error` | 正 | 12 | 3 | 2 | -32700 响应 |
| 13 | `mcp_t092_stdio_resources_read_32002` | 正 | 12 | 2 | 2 | -32002 响应 |
| 14 | `mcp_t036_http_sse_bearer_auth` | 正 | 19 | 0 | 2 | Bearer 头 |
| 15 | `mcp_t037_streamable_basic_auth` | 正 | 17 | 0 | 1 | Basic 头 |
| 16 | `mcp_t039_stdio_state_complete` | 正 | 13 | 4 | 3 | completed 状态 |
| 17 | `mcp_t086_stdio_roots_gated` | 正 | 12 | 0 | 5 | roots 能力门控 |
| 18 | `mcp_t087_stdio_experimental_warning` | 正 | 12 | 0 | 3 | experimental 透传 |
| 19 | `mcp_t088_stdio_roots_sampling_negotiated` | 正 | 14 | 0 | 4 | 双向能力协商 |
| 20 | `mcp_t089_stdio_capabilities_empty_obj` | 正 | 12 | 0 | 1 | 空 capabilities |
| 21 | `mcp_t090_stdio_client_caps_dup_key` | 负 | — | 0 | 0 | Client capabilities 非对象 |
| 22 | `mcp_t099_stdio_server_caps_dup_key` | 负 | — | 0 | 0 | Server capabilities 非对象 |
| 23 | `mcp_t053_stdio_capabilities_empty` | 正 | 12 | 0 | 3 | 空能力对象 |
| 24 | `mcp_t065_stdio_caps_omitted` | 正 | 12 | 1 | 1 | capabilities 省略 |
| 25 | `mcp_t038_streamable_auth_in_init_response` | 正 | 15 | 0 | 3 | initialize authentication |
| 26 | `mcp_t011_stdio_protocol_version_downgrade` | 正 | 12 | 2 | 3 | 版本降级 |
| 27 | `mcp_t043_stdio_multiflow_3_sessions` | 正 | 36 | 1 | 0 | 三会话 |
| 28 | `mcp_t044_stdio_multiflow_id_seq` | 正 | 36 | 1 | 0 | 多流 ID 序列 |
| 29 | `mcp_t077_stdio_teardown_sequence` | 正 | 12 | 12 | 0 | teardown 字段序列 |
| 30 | `mcp_t002_stdio_newline_escape` | 正 | 12 | 1 | 1 | 换行转义 |
| 31 | `mcp_t033_stdio_roots_list_changed` | 正 | 13 | 1 | 1 | roots 变更通知 |
| 32 | `mcp_t034_stdio_sampling_full_request` | 正 | 12 | 2 | 5 | sampling 完整请求 |
| 33 | `mcp_t020_stdio_resources_read_blob` | 正 | 12 | 0 | 1 | 二进制资源 |
| 34 | `mcp_t023_stdio_prompts_list_args` | 正 | 12 | 0 | 1 | prompts/list 参数 |
| 35 | `mcp_t015_stdio_tools_call_iserror` | 正 | 12 | 1 | 2 | 工具层 `isError` |
| 36 | `mcp_t016_stdio_tools_call_image` | 正 | 12 | 0 | 1 | image content |
| 37 | `mcp_t017_stdio_tools_call_unknown_tool` | 正 | 12 | 0 | 1 | 未知工具 |
| 38 | `mcp_t021_stdio_resources_subscribe_updated` | 正 | 13 | 0 | 3 | 资源订阅更新 |
| 39 | `mcp_t025_stdio_prompts_get_multi_role` | 正 | 12 | 0 | 1 | 多 role 响应 |
| 40 | `mcp_t029_stdio_cancelled_requestid` | 正 | 13 | 0 | 2 | cancelled requestId |
| 41 | `mcp_t035_stdio_sampling_stopreason` | 正 | 12 | 0 | 1 | sampling stopReason |
| 42 | `mcp_t040_stdio_state_input_required` | 正 | 13 | 0 | 2 | input_required |
| 43 | `mcp_t041_stdio_state_failed` | 正 | 12 | 1 | 1 | failed |
| 44 | `mcp_t042_stdio_state_canceled` | 正 | 13 | 0 | 2 | canceled |
| 45 | `mcp_t047_stdio_progress_parentid` | 正 | 13 | 0 | 1 | parentId |
| 46 | `mcp_t063_stdio_subscribe_unsupported` | 正 | 12 | 0 | 1 | subscribe 不支持 |
| 47 | `mcp_t066_stdio_notifications_logger` | 正 | 13 | 0 | 1 | logger |
| 48 | `mcp_t068_stdio_prompts_get_parts` | 正 | 12 | 0 | 1 | parts |
| 49 | `mcp_t069_stdio_tools_call_meta_metadata` | 正 | 12 | 0 | 1 | metadata |
| 50 | `mcp_t070_stdio_tools_call_push_notification` | 正 | 12 | 0 | 1 | pushNotification |
| 51 | `mcp_t072_stdio_resources_templates_list` | 正 | 12 | 0 | 2 | resource templates |
| 52 | `mcp_t073_stdio_resources_list_changed` | 正 | 13 | 0 | 1 | resources 列表通知 |
| 53 | `mcp_t074_stdio_sampling_fields` | 正 | 12 | 0 | 1 | sampling 字段 |
| 54 | `mcp_t080_stdio_progress_no_state` | 正 | 13 | 0 | 1 | progress 无 state |
| 55 | `mcp_t093_stdio_sampling_reject_code_minus1` | 正 | 12 | 0 | 1 | sampling -1 |
| 56 | `mcp_t094_stdio_content_resource_link` | 正 | 12 | 0 | 1 | resource_link |
| 57 | `mcp_t095_stdio_content_resource_embedded` | 正 | 12 | 0 | 1 | resource 嵌入 |
| 58 | `mcp_t100_stdio_tools_list_pagination` | 正 | 12 | 0 | 2 | tools/list 分页 |
| 59 | `mcp_t101_stdio_roots_list_no_params` | 正 | 12 | 0 | 1 | roots/list 无 params |
| 60 | `mcp_t102a_stdio_ping_empty_params` | 正 | 12 | 0 | 1 | ping 空 params |
| 61 | `mcp_t102b_stdio_ping_nonempty_params` | 正 | 12 | 0 | 2 | ping 非空 params |
| 62 | `mcp_t103_stdio_sampling_temperature_stop` | 正 | 12 | 0 | 1 | temperature/stopSequences |
| 63 | `mcp_t104_stdio_unknown_tool_message` | 正 | 12 | 0 | 1 | Unknown tool 文案 |
| 64 | `mcp_t071a_stdio_unsubscribe_20250326` | 正 | 14 | 0 | 2 | 2025-03-26 unsubscribe |
| 65 | `mcp_t071b_stdio_unsubscribe_20241105` | 正 | 12 | 0 | 1 | 旧版本拒绝 unsubscribe |
| 66 | `mcp_t048_stdio_mixed_id_reject` | 负 | — | 0 | 0 | ID 自动/显式混用 |
| 67 | `mcp_t049_stdio_empty_method_reject` | 负 | — | 0 | 0 | method 为空 |
| 68 | `mcp_t061_stdio_invalid_protocol_version` | 负 | — | 0 | 0 | 版本非法 |
| 69 | `mcp_t079_stdio_error_code_positive_reject` | 负 | — | 0 | 0 | 错误码为正 |
| 70 | `mcp_t046_stdio_context_id_chain` | 正 | 12 | 0 | 1 | contextId |
| 71 | `mcp_t064_stdio_initialized_no_params` | 正 | 12 | 0 | 1 | initialized 无 params |
| 72 | `mcp_t013_stdio_tools_list_default3` | 正 | 12 | 0 | 3 | 默认三工具 |
| 73 | `mcp_t014_stdio_tools_call_success` | 正 | 12 | 0 | 2 | 工具成功 |
| 74 | `mcp_t019_stdio_resources_read_text` | 正 | 12 | 0 | 1 | 文本资源 |
| 75 | `mcp_t022_stdio_resources_read_404` | 正 | 12 | 0 | 1 | 资源 404 语义 |
| 76 | `mcp_t032_stdio_roots_list_changed` | 正 | 13 | 0 | 1 | roots 变更 |
| 77 | `mcp_t052_stdio_invalid_params_error` | 正 | 12 | 0 | 1 | invalid params |
| 78 | `mcp_t062_stdio_tools_call_missing_name` | 正 | 12 | 0 | 2 | tools/call 缺 name |
| 79 | `mcp_t067_stdio_initialize_credentials` | 正 | 12 | 0 | 2 | credentials |
| 80 | `mcp_t080_rounds2` | 正 | 14 | 0 | 2 | rounds=2 |
| 81 | `mcp_t081_shutdown_false` | 正 | 8 | 1 | 0 | 不关闭连接 |
| 82 | `mcp_t082_sampling_parts` | 正 | 12 | 0 | 1 | sampling parts |
| 83 | `mcp_t083_composite_tools` | 正 | 17 | 0 | 0 | 组合工具流程 |
| 84 | `mcp_t084_composite_resources` | 正 | 20 | 0 | 0 | 组合资源流程 |
| 85 | `mcp_t085_longtask_full` | 正 | 16 | 0 | 0 | 长任务完整流程 |
| 86 | `mcp_t086_v6` | 正 | 12 | 1 | 1 | IPv6 承载 |
| 87 | `mcp_t087_streamable_full` | 正 | 15 | 0 | 1 | Streamable 完整流程 |
| 88 | `mcp_t088_auth_scheme_reject` | 负 | — | 0 | 0 | 认证方案非法 |
| 89 | `mcp_t089_sampling_gated` | 正 | 12 | 0 | 1 | sampling 能力门控 |
| 90 | `mcp_t090_presence_reject` | 负 | — | 0 | 0 | 顶层 mcp presence |
| 91 | `mcp_t091_default_dual` | 正 | 28 | 1 | 0 | 默认双向流 |
| 92 | `mcp_t092_static_copy_reject` | 负 | — | 0 | 0 | 静态四元组复制 |
| 93 | `mcp_t093_error_32600` | 正 | 12 | 0 | 1 | Invalid Request |
| 94 | `mcp_t094_error_32603` | 正 | 12 | 0 | 1 | Internal error |
| 95 | `mcp_t095_transport_reject` | 负 | — | 0 | 0 | websocket 非法 |
| 96 | `mcp_t096_state_reject` | 负 | — | 0 | 0 | state 非法 |
| 97 | `mcp_t097_id_counter_reject` | 负 | — | 0 | 0 | id_counter 越界 |
| 98 | `mcp_t098_parts_role_reject` | 负 | — | 0 | 0 | parts role 非法 |
| 99 | `mcp_t099_step_range_reject` | 负 | — | 0 | 0 | notification step 越界 |
| 100 | `mcp_t100_content_audio` | 正 | 12 | 0 | 1 | audio content |
| 101 | `mcp_t101_claude_desktop` | 正 | 12 | 0 | 1 | 客户端信息 |
| 102 | `mcp_t102_cursor` | 正 | 12 | 0 | 1 | 客户端信息 |
| 103 | `mcp_t103_flowb_server` | 正 | 12 | 0 | 1 | 服务端信息 |

## 3. 传输与 TCP 会话契约

### 3.1 stdio

stdio 用 TCP 承载行分隔 JSON-RPC。正例以握手后应用数据包验证 JSON 字节，典型完整流程为 initialize request/response、`notifications/initialized`、业务 request/response、三包 teardown。#1、#2、#3、#4、#5、#6、#9–#13、#16–#20、#23–#24、#26、#29–#65、#70–#86、#89、#91、#93–#94、#100–#103 属于该族。

### 3.2 HTTP+SSE

#7 `mcp_tpos7_http_sse_session` 与 #14 `mcp_t036_http_sse_bearer_auth` 覆盖正向 HTTP+SSE；#88 `mcp_t088_auth_scheme_reject` 是该传输族的非法认证方案负例。其断言面包括：GET `/mcp` 先于 POST、服务端首个 SSE 事件为 `endpoint`、后续 `event: message`、POST 返回 `202 Accepted`、会话 URI/认证头落线。当前机器统计 `http_sse` 为 3 例（正例 2、负例 1），具体 ID 如上。

### 3.3 Streamable HTTP

#8、#15、#25、#87 覆盖 Streamable HTTP：POST 单端点、200/202 响应、Mcp-Session-Id、Basic 或初始化认证，以及 #8 的 DELETE `/mcp` + 204 终止。HTTP 断言主要在 `frames` 中完成，因为 cases 中部分 TCP 序列未形成可供 dissector 完整重组的连续流。

### 3.4 握手、终止与方向

- 正例中 85 例显式 `has_handshake=true`。
- 正例中 81 例显式 `terminates=true`；#81 `shutdown=false` 是不终止连接边界。
- 三包 teardown 的协议行为由 #29 的 12 条 TCP 字段断言和 #1/#8 等帧断言共同覆盖。
- #27/#28 三会话例每例 36 包，用于会话/ID 独立性；JSON 当前未提供帧级断言，不能把“有 3 条流”扩写为已完成的全字段隔离证明。

## 4. MCP 方法与数据场景覆盖

### 4.1 生命周期与基础 JSON-RPC

initialize 缺省/自定义信息：#1、#2、#23、#24、#25、#26、#67、#79、#101–#103。`notifications/initialized`：#1、#71。ping：#3、#18、#20、#60、#61、#89。请求/响应错误对象：#6、#12、#13、#37、#55、#65、#75、#77、#78、#93、#94。

### 4.2 工具

- tools/list 默认工具和分页：#1、#2、#58、#72。
- tools/call 成功、工具层错误、未知工具、缺参：#1、#3、#5、#6、#35–#37、#49、#50、#63、#73、#78、#83。
- 内容类型：image #36、resource #57、resource_link #56、audio #100。
- 长任务、状态和进度：#5、#16、#40–#45、#49、#50、#54、#85。

### 4.3 资源

resources/list/read：#4、#13、#33、#51、#58、#74、#75、#84。订阅和更新：#38、#46、#52、#65。资源模板：#51。二进制 blob：#33；文本资源：#4、#74。

### 4.4 提示词、补全、日志

- prompts/list/get 与参数元数据：#9、#34、#39、#48。
- completion/complete：#10。
- logging/setLevel 与日志通知：#5、#11、#47。

### 4.5 Roots、sampling、能力协商

roots：#17、#19、#31、#59、#76。sampling：#19、#32、#41、#53、#55、#62、#82、#89。能力空对象/省略/实验扩展/重复键输入：#17–#24、#64、#86、#88、#90；#21/#22 的实际输入是非对象拒绝，原始重复键仍登记为缺口。

### 4.6 认证、并发、动态与边界

认证：#14、#15、#25。多会话：#27、#28。rounds：#80。IPv6：#86。默认双向：#91。客户端信息：#101、#102；服务端信息：#103。HTTP session、认证方案、协议版本、shutdown 和状态边界共同分布于 #7、#8、#14–#16、#25–#26、#64–#65、#80–#87。

## 5. 字段与帧断言契约

### 5.1 fields

当前 64 条 `expect.fields` 全部为 `tcp.*`，覆盖：

- `tcp.srcport` / `tcp.dstport`：端口和 HTTP/stdio 载体确认；
- `tcp.flags`：应用数据及 teardown 标志；
- `tcp.len`：initialize、请求、响应、通知和长任务字节长度；
- #29 的 12 条 teardown 字段断言验证方向、序号和标志序列。

这意味着 MCP JSON-RPC 语义不能仅由 `fields` 得出，需同时读取 `frames` 的偏移和十六进制字节。

### 5.2 frames

当前 149 条帧断言分布如下：

- stdio JSON 行：以 `7b 22`（`{"`）开头并以 `0a` 行结束；
- HTTP 请求：`GET /mcp`、`POST /mcp` 或带 session 查询串；
- HTTP 响应：`HTTP/1.1 200/202/204`；
- SSE：`event: endpoint` 必须先于 `event: message`；
- JSON-RPC 错误：-32700、-32601、-32602、-32002 等编码在 hex 中直接确认；
- capabilities、authentication、content、state、sampling 和客户端/服务端信息以 JSON 字段片段确认。

frames 数量为 149，不代表每个正例都有帧断言：#27、#28、#81、#83–#85、#91 等存在 0 帧的正例，不能宣称其完整 payload 已字节核验。

### 5.3 字节断言注意事项

设计文档 §6 和现有 cases 的 notes 记录了 Go map 键序、capabilities 省略与 `{}` 的差异，以及部分 HTTP TCP 序列无法由 dissector 重组的限制。本文沿用这些现状，不把 notes 中的预期描述替换成额外的“通过”结论。

## 6. 状态机与能力门控

### 6.1 会话状态

正例覆盖 initialize 前后的生命周期、operating 阶段请求、通知和关闭：#1、#7、#8、#16、#29、#64、#71、#81、#87。长任务状态覆盖：

| 状态/行为 | 用例 |
|---|---|
| `submitted`/`working`/`completed` | #16、#85 |
| `input_required` | #42 |
| `failed` | #43 |
| `canceled` | #44 |
| progress 无 `state` | #54 |
| cancelled requestId | #40 |

#96 为非法 `state.initial` 负例。

### 6.2 能力协商

- 客户端 roots、服务端不支持，后续请求返回 -32601：#17。
- experimental 能力透传：#18。
- roots + sampling 与 tools + resources 双向协商：#19。
- capabilities 空对象：#20、#23。
- capabilities 省略：#24。
- sampling 门控：#89。
- #21/#22 的目标是重复键拒绝，但机读输入已是字符串/非对象，实际锚词为 `must be a JSON object`；原始重复键字节流仍登记 `MCP-GAP-4`，不计作已覆盖。

## 7. 负例契约与判死验证

负例必须在 planner/validator 阶段报错并传播为 task error；不得以成功 PCAP、`completed/0 packet` 或仅有 TCP 外壳代替失败。当前 14 个负例均没有成功包数、fields 或 frames 断言。

| # | ID | 故障输入/路径 | `error_contains` |
|---:|---|---|---|
| 21 | `mcp_t090_stdio_client_caps_dup_key` | Client capabilities 不是 JSON object | `must be a JSON object` |
| 22 | `mcp_t099_stdio_server_caps_dup_key` | Server capabilities 不是 JSON object | `must be a JSON object` |
| 66 | `mcp_t048_stdio_mixed_id_reject` | 自动 ID 与显式 ID 混用 | `mixed auto and explicit id assignment is not allowed` |
| 67 | `mcp_t049_stdio_empty_method_reject` | request method 为空 | `mcp: requests[0].method is required` |
| 68 | `mcp_t061_stdio_invalid_protocol_version` | protocol version 不在允许枚举 | `mcp: invalid protocol_version` |
| 69 | `mcp_t079_stdio_error_code_positive_reject` | error code=42 | `mcp: responses[0].error.code=42 out of JSON-RPC reserved range` |
| 88 | `mcp_t088_auth_scheme_reject` | auth scheme 非法 | `invalid auth scheme` |
| 90 | `mcp_t090_presence_reject` | `layers` 与顶层 `mcp` 并存 | `no longer accepts a top-level mcp sub-config` |
| 92 | `mcp_t092_static_copy_reject` | flows>1 但四元组静态复制 | `static four-tuple` |
| 95 | `mcp_t095_transport_reject` | transport=`websocket` | `invalid transport` |
| 96 | `mcp_t096_state_reject` | state.initial 非法 | `invalid state.initial` |
| 97 | `mcp_t097_id_counter_reject` | id_counter 为负 | `id_counter must be >= 0` |
| 98 | `mcp_t098_parts_role_reject` | parts.role 非 user/assistant | `parts[0].role` |
| 99 | `mcp_t099_step_range_reject` | notification step 超出请求范围 | `notifications[0].step=9 out of range` |

### 7.1 负例形状审计

- 14/14 均设置 `expect_error=true`。
- 14/14 均没有正例 packet count。
- #90 的顶层 `mcp` 是故意的 presence 判死形状，不登记为正例游离键。
- #21/#22 的 summary 称“重复键”，但机读输入已经不是原始重复键字节流；该事实必须保留，不能宣称重复键本身已被测试。

## 8. 设计回指与覆盖对账

### 8.1 设计章节回指

| 设计范围 | 当前用例 |
|---|---|
| §2.3 stdio 编码 | #1–#6、#30、#54、#64、#71 |
| §2.4 HTTP+SSE | #7、#14 |
| §2.5 Streamable HTTP | #8、#15、#25、#87 |
| §3 生命周期/方法表 | #1–#5、#9–#11、#31–#63、#70–#79 |
| §4 Config/default/Validate | #2、#20、#23–#26、#66–#69、#88、#90、#92、#95–#99 |
| §5 状态机/能力门控 | #16–#24、#40–#45、#54、#86、#89 |
| §6 Plan 与 TCP 序列 | #1、#7、#8、#27–#29、#80–#87、#91 |
| §7 业务和数据场景 | #3–#6、#9–#65、#70–#79、#100–#103 |

### 8.2 字段族覆盖

现有正例已出现的设计字段/场景包括：`id`、`method`、`params`、`result`、`error`、`protocolVersion`、`clientInfo`、`serverInfo`、`capabilities`、`authentication`、`schemes`、`credentials`、`sessionId`、`level`、`logger`、`data`、`arguments`、`isError`、`content`、`mimeType`、`uri`、`roots`、`role`、`parts`、`metadata`、`pushNotification`、`verificationToken`、`contextId`、`parentId`、`state`、`inputSchema` 及分页 cursor 等。

该表只证明字段在 cases JSON 中出现，不证明每个字段已经有独立字段级断言；许多字段只存在于 frames 的部分 hex 或 notes 描述中。

## 9. 缺口、残留与未覆盖面

### 9.1 当前残留

1. **#21/#22 不是原始重复键测试**：API 结构解码后无法保留重复 JSON object key，当前实际验证的是 capabilities 非对象输入拒绝；重复键 tokenizer 的真实输入路径仍待专门入口。
2. **正例断言不均匀**：89 条正例中部分只有 packet count 或 notes，#83–#85、#91 等没有 frames，不能据此声称组合流程 payload 已逐字节确认。
3. **fields 面单一**：64 条字段断言全部为 `tcp.*`，没有 MCP dissector 字段断言；应用语义主要依赖 frame hex。
4. **多会话隔离证据不完整**：#27/#28 有包数和少量 TCP 字段，但没有逐流 sessionId、四元组、ID 序列的完整字段/帧断言。
5. **HTTP 重组限制**：部分 cases notes 已记录 TCP sequence/重组限制；HTTP 状态、SSE 和 session 主要用 frame hex 验证。
6. **未声明的复杂状态面**：`ThinkTime`、完整 `Rounds` 字节级展开、长 JSON MSS 分段以及多流实际并发调度在本文件没有独立完整帧契约。
7. **认证覆盖不完整**：已有 Bearer/Basic；OAuth2 仅作为 Bearer 占位语义，未覆盖真实 OAuth2 流程（设计 §7.14 明确不模拟真实 flow）。
8. **未宣称运行结果**：本文没有今日 suite、PCAP、NIC 或真实网络抓包通过结论；这些均待 P5 证据。

### 9.2 设计中存在但本 JSON 未形成独立原子例的面

- 完整 31 字段逐字段断言矩阵；
- capabilities 重复键的原始字节输入；
- 64KB/8KB 大消息 MSS 分段重组；
- 100 会话并发及全局 packet index 唯一性；
- Streamable GET 缺 session 的 400 分支；
- HTTP+SSE 批量请求/响应和 Streamable SSE 批量响应；
- 批量空数组、批量整体解析失败和批量逐项非法元素；
- `notifications/resources/updated`、`notifications/message` 等全部方向/字段矩阵的独立字节闭环；
- 所有 §7.18 边界项逐项一例。

以上仅登记为待补覆盖，不把设计文档中的条目倒灌成已存在 ID。

## 10. P5 执行契约

1. 先以 `mcp.json` 的 103 个 ID 和顺序为输入清单，不重编号、不删改负例语义。
2. 负例逐例验证错误传播：必须是明确 task error，不能以空成功任务代替。
3. 正例先核对 packet count，再核对 64 条 fields，最后核对 149 条 frames；frame 偏移以 cases JSON 为准。
4. 对 HTTP 族优先检查 GET/POST/SSE/DELETE 的状态行和事件顺序，再检查 JSON body。
5. 对多流例补充按流分组的四元组、sessionId、ID 序列和包数聚合检查；当前文档不提前宣称这些检查已完成。
6. P5 需要分别记录 pcap、NIC、tshark 版本、运行命令和产物路径；在证据落盘前，本文只使用“待 P5”。

## 11. 收官自审与修订记录

### 11.1 自审清单

- [x] 重新机读确认 103 例、89 正、14 负。
- [x] 重新机读确认 JSON 顺序和 103 个 ID 均在索引中。
- [x] 重新机读确认正例包数合计 1202、fields 64、frames 149。
- [x] 记录 `spec_json` 顶层键：102 例 `{layers}`，#90 为故意 `{layers,mcp}` presence 负例。
- [x] 记录合法传输分布：stdio 94、streamable 4、http_sse 3；非法 websocket 负例 1；未写 transport 1。
- [x] 逐条登记 14 个负例 ID 和 `error_contains`，未把负例写成正例。
- [x] 明确 #21/#22 的重复键测试实际退化为非对象输入拒绝。
- [x] 未写入今日 suite、pcap、NIC 或真实网络通过声明。
- [x] 缺口均标为现状缺口或待 P5，没有虚构新 ID。

**passed 2 rounds, last round clean.**

### 11.2 修订记录

- v1.0.0（2026-09-29）：依据 `mcp.json` 103 例机读结果新建 as-built 测试用例契约；覆盖 89 正/14 负、1202 正例包数、64 fields、149 frames；保留 #90 presence 负例和 #21/#22 重复键输入限制；登记 HTTP、多会话、批量、MSS、NIC、PCAP 等待 P5 缺口；两轮自审，末轮干净。

## 12. 层链迁移审计（T1–T6，2026-09-30）

| ID | 测试审计结论 | 证据 |
|---|---|---|
| T1 | 103 条 ID 唯一且 JSON 可解析。 | `mcp.json` 机读校验。 |
| T2 | 89 条正例和动态多流正例使用 `[ip,tcp,mcp]` 严格层链。 | 全量 `spec_json.layers` 审计。 |
| T3 | 14 条负例保留故意错误输入与稳定错误锚词。 | `expect_error`/`error_contains` 审计。 |
| T4 | 地址只在 ip 层、端口只在 tcp 层、MCP 字段只在 mcp 层；无顶层旧地址/端口/count。 | 103 条 `spec_json` 顶层键审计。 |
| T5 | `strategy_fc` 仅作为 cases 条目兄弟键表达 flows，不混入 `spec_json`；4 条使用例均已对账。 | `mcp_t043`、`mcp_t044`、`mcp_t091`、`mcp_t092`。 |
| T6 | 层链迁移未改变协议字段、包数、64 条 fields、149 条 frames 或负例语义。 | 对照现有文件统计与设计 §12 逐 ID 核对。 |

### 12.1 迁移状态与缺口

- 已迁移：103/103 条 cases 的 `spec_json` 可解析；102 条顶层仅 `{layers}`，#90 故意保留 `{layers,mcp}` presence 负例。
- 正例：89 条均为严格层链目标形；多会话与静态复制负例保留 `strategy_fc` 兄弟键，不把它误写进层链。
- 负例：14 条均保留 `expect_error`/`error_contains`；不能清洗为正例或改成协议响应错误。
- 缺口：设计 `MCP-GAP-1..4` 尚未通过本次文档变更闭环；本文不宣称 suite、PCAP、NIC 或 tshark 今日全量通过。

**passed 2 rounds, last round clean.**

## 14. T1–T6 机读闭环（2026-10-01）

| ID | 要求 | 当前结论与证据 |
|---|---|---|
| T1 | 规范行→设计条目→现网行为三源回指 | §8.1 将传输、生命周期、方法、配置、状态、Plan、业务分别回指设计 §2–§7；现网行为以 `mcp.json` 帧/fields/notes 为准；未形成独立 wire 证据的场景明确列 `MCP-GAP-1`，确认方式为 P5 pcap/tshark。 |
| T2 | 测试点清单先行 | §2–§7 原子索引按规范场景、业务路径、代码分支组织；§8.1 逐设计范围回指；缺口不倒灌为已覆盖。 |
| T3 | 不可再分、三类场景与强度 | §2–§6 将数据、业务、现网场景拆分；枚举逐值、正交传输/能力矩阵、动态字段整格和 packet/frame 边界由索引与断言计数覆盖。 |
| T4 | §3.15 三项 | 同连接多轮 `mcp_t080_rounds2`；非正常结束 `mcp_t081_shutdown_false`；长保活 `mcp_tpos7_http_sse_session`、`mcp_t087_streamable_full`；运行证据列 `MCP-GAP-1`。 |
| T5 | 存量逐条去向 | §2 原子索引保留 103 个 JSON 顺序与 ID；历史 T 编号在 `summary`/`expect.notes` 登记合入或等效覆盖；未落 JSON 的历史面在 §9.2 登记待补。 |
| T6 | 失败路径真会红 | 14 个负例均严格 `{expect_error,error_contains}`，锚词对应真实拒绝文案；无成功断言。任务级传播尚未运行，列 `MCP-GAP-1`。 |

### 14.1 C1–C6 对账补充

| ID | 结论 |
|---|---|
| C1 | 103 条 ID 唯一、JSON 可解析；89 正例、14 负例，正例 `packet_count` 89/89。 |
| C2 | 正例层链均为 `[ip,tcp,mcp]`；4 条 `strategy_fc` 为例级数量控制，`count` 不进 `spec_json`。 |
| C3 | #90 `layers+mcp` 仅为 presence 判死负例；其他 102 条顶层仅 `layers`。 |
| C4 | 14/14 负例严格双键，锚词与真实拒绝文案逐项对账。 |
| C5 | 每条 summary 含 T/§ 回指；多流、HTTP、状态、认证和边界 ID 在 §2–§8 有去向。 |
| C6 | 无 `*-spec-mapping.md` 文件，按规则记为非缺口备注。 |

**T1–T6/C1–C6 自审：** 对照 JSON 103 条顺序、ID、顶层键、4 条 `strategy_fc`、14 条负例双键复核两轮；未运行 suite、服务、MCP 或 NIC。
**passed 2 rounds, last round clean.**