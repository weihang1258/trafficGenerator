# MCP Spec-to-PCAP Test Case Mapping

## Files
- **Design spec**: `/home/weihang/trafficGenerator/docs/protocol-designs/16-mcp-design.md`（测试用例清单位于 §8 "测试用例清单", line 1454；§7 "业务场景与数据场景" line 924-1453 为场景定义，无独立用例编号）
- **PCAP test cases**: `/home/weihang/trafficGenerator/trafficgen/test/protocol_pcap/cases/mcp.json` (79 cases)
- **PCAP results**: `CASE_PROTO=mcp go test -run TestProtocolPcapDrive ./test/protocol_pcap/`（**79/79 pass**，2026-08-09 多轮验证；6 条 expect_error 负向用例全过）

## Spec Overview

MCP 设计文档的测试用例集中在 **§8 测试用例清单**（§7 为 19 个业务场景小节 7.1-7.19，仅描述场景与引用 §8 编号，本身无独立用例表）。§8 含 **104 条测试用例**（T01-T104，v1.0 60 条 + v1.1 20 条 + v1.1.1 11 条 + v1.1.3 13 条），按功能域分为 17 组：

| 组名 | 用例范围 | 数量 | 描述 |
|------|---------|------|------|
| §8.1 报文格式与序列化（§2） | T01-T06 | 6 | stdio 行分隔 JSON / HTTP POST 请求行 / SSE 事件格式 / 必填字段校验 / result-error 互斥 |
| §8.2 生命周期方法（§3.1, §7.1-§7.3） | T07-T12 | 6 | initialize 默认字段与 capabilities / initialized 通知 / ping / 协议版本降级 / 跳过 initialize |
| §8.3 工具方法（§3.2, §7.4） | T13-T17 | 5 | tools/list 默认 3 工具 / tools/call 成功 / isError / 图片内容 / 工具名不存在 -32602 |
| §8.4 资源方法（§3.3, §7.5-§7.6） | T18-T22 | 5 | resources/list 分页 / read 文本+二进制 / subscribe+updated / uri 不存在 -32002 |
| §8.5 提示词与补全（§3.4-§3.5, §7.7-§7.8） | T23-T26 | 4 | prompts/list arguments / prompts/get 单多消息 / completion/complete |
| §8.6 日志与通知（§3.6-§3.7, §7.9-§7.11） | T27-T31 | 5 | logging/setLevel / message 通知 / cancelled / progress 通知 / progress 缺 token |
| §8.7 Roots 与 Sampling（§3.8-§3.9, §7.12-§7.13） | T32-T35 | 4 | roots/list S→C / roots list_changed / sampling createMessage / stopReason |
| §8.8 认证（§7.14） | T36-T38 | 3 | Bearer / Basic / authentication 字段 |
| §8.9 长任务状态机（§7.15） | T39-T42 | 4 | state 完整流 / input_required / failed / canceled |
| §8.10 多会话并发（§7.16） | T43-T45 | 3 | 3 会话独立 4-tuple / 独立 id 序列 / 部分失败 |
| §8.11 调用链（§7.17） | T46-T47 | 2 | contextId 贯穿 / parentId 嵌套进度 |
| §8.12 边界与异常（§7.18-§7.19） | T48-T53 | 6 | id=0 自动分配 / method 空串 / -32700 / -32601 / -32602 / capabilities 空对象 |
| §8.13 传输模式覆盖（§2.3-§2.5） | T54-T56 | 3 | stdio 行分隔 / http_sse 双流 / streamable 单端点 |
| §8.14 集成与端到端（§6） | T57-T60 | 4 | stdio 完整会话 / HTTP+SSE 完整会话 / 100 并发 / MSS 分段 8KB |
| §8.15 v1.1 新增（审计修复） | T61-T80 | 20 | 负向校验补充 / 扩展表 31 字段覆盖 / 批量聚合 / GroupID / teardown 字节序列 / 202+SSE / state 不在 progress |
| §8.16 v1.1.1 新增（重审修复） | T81-T91 | 11 | Batch 批量编解码（T81-T85）/ 能力双向门控（T86-T90）/ DELETE /mcp 终止（T91） |
| §8.17 v1.1.3 新增（三轮审计返工） | T92-T104 | 13 | -32002/-1 错误码 / resource/resource_link / endpoint 时序强化 / 批量 -32700 / 重复键拒绝 / tools/list 分页 / ping params 变体 |
| **Total** | T01-T104 | **104** | |

## Covered Mapping (80 spec IDs → 79 pcap cases)

| Spec ID | Description | pcap_case_id | Status |
|---------|-------------|--------------|--------|
| T002 | JSON 行内 `\n` 转义为 `\\n`（线序 5c 6e），行数不变 | mcp_t002_stdio_newline_escape | covered |
| T009 | notifications/initialized 通知无 id、无 params | mcp_t064_stdio_initialized_no_params, mcp_tpos1_stdio_initialize | covered |
| T010 | ping 请求-响应配对（id=2，result 空对象） | mcp_tpos3_stdio_ping | covered |
| T011 | initialize 协议版本降级（2025-06-18 → 2024-11-05） | mcp_t011_stdio_protocol_version_downgrade | covered |
| T013 | tools/list 默认 3 工具（ping/echo/search，含 inputSchema） | mcp_t013_stdio_tools_list_default3, mcp_t053_stdio_capabilities_empty | covered |
| T014 | tools/call 成功响应（content text + isError=false） | mcp_t014_stdio_tools_call_success, mcp_t015_stdio_tools_call_iserror | covered |
| T015 | tools/call 工具层失败 isError=true | mcp_t015_stdio_tools_call_iserror, mcp_t041_stdio_state_failed | covered |
| T016 | tools/call 返回图片内容（blob base64 + mimeType） | mcp_t016_stdio_tools_call_image | covered |
| T017 | tools/call 工具名不存在 -32602 | mcp_t017_stdio_tools_call_unknown_tool, mcp_t104_stdio_unknown_tool_message, mcp_t052_stdio_invalid_params_error | covered |
| T018 | resources/list 含分页 cursor | mcp_tpos4_stdio_resources | partial（nextCursor 实测为 `""`，未验证"响应 nextCursor 非空"） |
| T019 | resources/read 文本资源（mimeType/text） | mcp_tpos4_stdio_resources, mcp_t019_stdio_resources_read_text | covered |
| T020 | resources/read 二进制资源（blob base64 非 text） | mcp_t020_stdio_resources_read_blob, mcp_t019_stdio_resources_read_text | covered |
| T021 | resources/subscribe + notifications/updated（uri 一致） | mcp_t021_stdio_resources_subscribe_updated, mcp_t063_stdio_subscribe_unsupported | covered |
| T022 | resources/read uri 不存在 -32602 | mcp_t022_stdio_resources_read_404 | covered |
| T023 | prompts/list 含 arguments 元数据 | mcp_t023_stdio_prompts_list_args | covered |
| T024 | prompts/get 单消息响应 | mcp_t024_stdio_prompts_get | covered |
| T025 | prompts/get 多消息多部分（user+assistant+resource） | mcp_t025_stdio_prompts_get_multi_role, mcp_t068_stdio_prompts_get_parts | covered |
| T026 | completion/complete 响应（values/total/hasMore） | mcp_t026_stdio_completion_complete | covered |
| T027 | logging/setLevel 请求-响应（result 空对象） | mcp_tpos5_stdio_notifications, mcp_t027_stdio_logging_setlevel | covered |
| T028 | notifications/message 数据为对象（data.tool/duration_ms/msg） | mcp_tpos5_stdio_notifications, mcp_t066_stdio_notifications_logger | covered |
| T029 | notifications/cancelled 携带 requestId | mcp_t029_stdio_cancelled_requestid | covered |
| T030 | notifications/progress 携带 progressToken | mcp_tpos5_stdio_notifications | covered |
| T032 | roots/list 服务端→客户端请求（S→C 方向） | mcp_t032_stdio_roots_list_changed | covered |
| T033 | notifications/roots/list_changed 通知（无 params/id） | mcp_t033_stdio_roots_list_changed, mcp_t073_stdio_resources_list_changed, mcp_t032_stdio_roots_list_changed | covered |
| T034 | sampling/createMessage 完整请求（messages+modelPreferences+maxTokens+temperature） | mcp_t034_stdio_sampling_full_request, mcp_t035_stdio_sampling_stopreason | covered |
| T035 | sampling 响应 stopReason=endTurn | mcp_t088_stdio_roots_sampling_negotiated, mcp_t034_stdio_sampling_full_request, mcp_t035_stdio_sampling_stopreason | covered |
| T036 | Bearer 认证头（http_sse 模式） | mcp_t036_http_sse_bearer_auth | covered |
| T037 | Basic 认证头（streamable 模式） | mcp_t037_streamable_basic_auth | covered |
| T038 | initialize 响应含 authentication 字段 | mcp_t038_streamable_auth_in_init_response | covered |
| T039 | state 完整流（submitted→completed 终态） | mcp_t039_stdio_state_complete, mcp_t080_stdio_progress_no_state | covered |
| T040 | state input_required 中间状态 | mcp_t040_stdio_state_input_required, mcp_t080_stdio_progress_no_state | covered |
| T041 | state failed 终态（isError=true） | mcp_t041_stdio_state_failed | covered |
| T042 | state canceled（cancelled 通知 + canceled 终态） | mcp_t042_stdio_state_canceled | covered |
| T043 | 3 会话独立 4-tuple 与 sessionId | mcp_t043_stdio_multiflow_3_sessions | covered |
| T044 | 多会话独立 id 序列（每流从 1 开始） | mcp_t044_stdio_multiflow_id_seq | covered |
| T046 | contextId 贯穿调用链 | mcp_t046_stdio_context_id_chain | covered |
| T047 | parentId 嵌套进度 | mcp_t047_stdio_progress_parentid | covered |
| T048 | id=0 自动分配与混用拒绝（"mixed auto and explicit"） | mcp_t048_stdio_mixed_id_reject | covered（expect_error 负向） |
| T049 | method 空字符串被拒绝 | mcp_t049_stdio_empty_method_reject | covered（expect_error 负向） |
| T050 | JSON-RPC parse error（-32700，id 复用） | mcp_t050_stdio_parse_error | covered |
| T052 | JSON-RPC invalid params（-32602） | mcp_t102b_stdio_ping_nonempty_params, mcp_t052_stdio_invalid_params_error | covered |
| T053 | capabilities 全空对象 `{}` 合法 | mcp_t053_stdio_capabilities_empty | covered |
| T055 | http_sse 模式 POST + SSE 双流 | mcp_tpos7_http_sse_session | covered |
| T056 | streamable 模式单一端点 | mcp_tpos8_streamable_http | covered |
| T057 | stdio 完整会话 13 包 | mcp_tpos1_stdio_initialize | covered |
| T058 | HTTP+SSE 完整会话（GET 先于 POST/202/endpoint） | mcp_tpos7_http_sse_session | covered |
| T061 | initialize 缺 protocolVersion 拒绝 | mcp_t061_stdio_invalid_protocol_version | covered（expect_error 负向） |
| T062 | tools/call 缺 name 参数 → -32602 | mcp_t052_stdio_invalid_params_error, mcp_t062_stdio_tools_call_missing_name | covered |
| T063 | subscribe 能力不支持 → -32601 | mcp_t063_stdio_subscribe_unsupported | covered |
| T064 | initialized 通知无 params | mcp_t064_stdio_initialized_no_params | covered |
| T065 | capabilities 省略（未显式提供时不输出） | mcp_t065_stdio_caps_omitted | covered |
| T066 | notifications logger 字段（data.tool/duration_ms） | mcp_t066_stdio_notifications_logger | covered |
| T067 | initialize credentials 字段 | mcp_t067_stdio_initialize_credentials | partial（planner 限制：id:0 override 不并入自动 init 响应，断言 plain init 响应 + 说明） |
| T068 | prompts/get parts 多部分 | mcp_t068_stdio_prompts_get_parts | covered |
| T069 | tools/call _meta.metadata | mcp_t069_stdio_tools_call_meta_metadata | covered |
| T070 | pushNotification url+verificationToken | mcp_t070_stdio_tools_call_push_notification | covered |
| T071 | resources/unsubscribe 2025-03-26 正/负向双分支 | mcp_t071a_stdio_unsubscribe_20250326, mcp_t071b_stdio_unsubscribe_20241105 | covered |
| T072 | templates/list | mcp_t072_stdio_resources_templates_list | covered |
| T073 | resources list_changed 通知 | mcp_t073_stdio_resources_list_changed | covered |
| T074 | sampling 字段完整性（stopSequences 等） | mcp_t074_stdio_sampling_fields | covered |
| T077 | teardown 字节序列（FIN-ACK→FIN-ACK→ACK） | mcp_t077_stdio_teardown_sequence | covered |
| T078 | HTTP+SSE POST 202 + GET SSE 流推送 | mcp_tpos7_http_sse_session | covered |
| T079 | error.code 正数拒绝 | mcp_t079_stdio_error_code_positive_reject | covered（expect_error 负向） |
| T080 | progress 通知不含 state 字段 | mcp_t040_stdio_state_input_required, mcp_t080_stdio_progress_no_state | covered |
| T086 | client 声明 roots / server 未声明 → roots/list -32601 | mcp_t086_stdio_roots_gated | covered |
| T087 | experimental 接受 + 警告 | mcp_t087_stdio_experimental_warning | covered |
| T088 | 双向协商成功（roots+sampling 均支持） | mcp_t088_stdio_roots_sampling_negotiated | covered |
| T089 | capabilities 空对象 `{}` | mcp_t089_stdio_capabilities_empty_obj | covered |
| T090 | 重复键拒绝（client capabilities） | mcp_t090_stdio_client_caps_dup_key, mcp_t099_stdio_server_caps_dup_key | covered（expect_error 负向，等效变体见下） |
| T091 | Streamable HTTP DELETE /mcp 204 终止会话 | mcp_tpos8_streamable_http | covered |
| T092 | resources/read -32002 Resource not found | mcp_t092_stdio_resources_read_32002, mcp_t022_stdio_resources_read_404 | covered |
| T093 | sampling 拒绝 -1 | mcp_t093_stdio_sampling_reject_code_minus1 | covered |
| T094 | content resource_link | mcp_t094_stdio_content_resource_link, mcp_t095_stdio_content_resource_embedded | covered |
| T095 | content resource 嵌入 | mcp_t094_stdio_content_resource_link, mcp_t095_stdio_content_resource_embedded | covered |
| T099 | ServerCapabilities 重复键拒绝 | mcp_t099_stdio_server_caps_dup_key | covered（expect_error 负向，等效变体见下） |
| T100 | tools/list 分页 cursor+nextCursor | mcp_t100_stdio_tools_list_pagination | covered |
| T101 | roots/list 省略 params | mcp_t101_stdio_roots_list_no_params | covered |
| T102 | ping 三变体（无/空对象/非空对象→-32602） | mcp_t087_stdio_experimental_warning, mcp_t102a_stdio_ping_empty_params, mcp_t102b_stdio_ping_nonempty_params | covered |
| T103 | sampling temperature+stopSequences | mcp_t074_stdio_sampling_fields, mcp_t103_stdio_sampling_temperature_stop | covered |
| T104 | tools/call message 含 "Unknown tool:" 前缀 | mcp_t017_stdio_tools_call_unknown_tool, mcp_t104_stdio_unknown_tool_message | covered |

**Total unique spec IDs covered**: 80（严格 covered 77 + partial 2：T018/T067）

## Summary Counts

| Metric | Count |
|--------|-------|
| Total spec test cases (§8) | 104 |
| Total pcap test cases | 79 |
| Unique spec IDs covered by pcap | 80（covered 77 + partial 2：T018/T067） |
| Spec IDs missing from pcap | 24 |
| **Coverage rate** | **76.9%**（80/104，含 partial）；严格 **74.0%**（77/104） |

## Coverage by Section

| Section | Range | IDs | Covered | Partial | Missing |
|---------|-------|-----|---------|---------|---------|
| §8.1 报文格式与序列化 | T01-T06 | 6 | 1 (T02) | 0 | 5 (T01,T03,T04,T05,T06) |
| §8.2 生命周期方法 | T07-T12 | 6 | 3 (T09,T10,T11) | 0 | 3 (T07,T08,T12) |
| §8.3 工具方法 | T13-T17 | 5 | 5 | 0 | 0 |
| §8.4 资源方法 | T18-T22 | 5 | 4 (T19,T20,T21,T22) | 1 (T18) | 0 |
| §8.5 提示词与补全 | T23-T26 | 4 | 4 | 0 | 0 |
| §8.6 日志与通知 | T27-T31 | 5 | 4 (T27,T28,T29,T30) | 0 | 1 (T31) |
| §8.7 Roots 与 Sampling | T32-T35 | 4 | 4 | 0 | 0 |
| §8.8 认证 | T36-T38 | 3 | 3 | 0 | 0 |
| §8.9 长任务状态机 | T39-T42 | 4 | 4 | 0 | 0 |
| §8.10 多会话并发 | T43-T45 | 3 | 2 (T43,T44) | 0 | 1 (T45) |
| §8.11 调用链 | T46-T47 | 2 | 2 | 0 | 0 |
| §8.12 边界与异常 | T48-T53 | 6 | 5 (T48,T49,T50,T52,T53) | 0 | 1 (T51) |
| §8.13 传输模式覆盖 | T54-T56 | 3 | 2 (T55,T56) | 0 | 1 (T54) |
| §8.14 集成与端到端 | T57-T60 | 4 | 2 (T57,T58) | 0 | 2 (T59,T60) |
| §8.15 v1.1 新增 | T61-T80 | 20 | 20 | 0 | 0 |
| §8.16 v1.1.1 新增 | T81-T91 | 11 | 6 (T86-T91) | 0 | 5 (T81-T85) |
| §8.17 v1.1.3 新增 | T92-T104 | 13 | 13 | 0 | 0 |
| **Total** | | **104** | **84**（去重后 77） | **2**（T018,T067） | **24** |

## 全量缺失清单（24 条，按 §8 小节）

### §8.1 报文格式与序列化 — 缺 5

| ID | 名称 | 验证点 | 不可覆盖原因 |
|----|------|--------|------|
| T01 | stdio 行分隔 JSON 单包编码 | 单请求序列化为单行 JSON 以 `\n` 结尾无 BOM | 纯函数级序列化；T02/T057 帧断言已同质覆盖线序编码 |
| T03 | HTTP POST 请求行+头+body 格式 | `POST /mcp?session=... HTTP/1.1` 帧断言 | **可覆盖未覆盖**：tpos7/t038 帧断言已含 POST 行与头，spec 编号未回填（等效 T058/T056/T091 已覆盖） |
| T04 | SSE 事件格式（event+data+\n\n） | endpoint/message 事件帧断言 | **可覆盖未覆盖**：tpos7 已含 endpoint/message 帧断言，spec 编号未回填（等效 T058/T078 已覆盖） |
| T05 | JSON-RPC 请求必填字段校验 | 缺 jsonrpc/id/method 任一，Validate 拒绝 | 纯函数级（Validate），pcap 不可注入缺字段（API 解码补全） |
| T06 | JSON-RPC 响应 result/error 互斥 | 同时设置 result 与 error，Validate 拒绝 | 纯函数级（Validate），pcap 不可注入（响应由 planner 自动构建） |

### §8.2 生命周期方法 — 缺 3

| ID | 名称 | 验证点 | 不可覆盖原因 |
|----|------|--------|------|
| T07 | initialize 默认字段 | 请求含 jsonrpc/id/method/protocolVersion/clientInfo | **可覆盖未覆盖**：tpos1 帧断言仅含前缀（实测 capabilities 省略为 v1.1.1 N-4 行为）；T011/T065 已覆盖 protocolVersion/capabilities 变体 |
| T08 | initialize 响应默认字段 | 响应含 jsonrpc/id/result/protocolVersion/serverInfo | **可覆盖未覆盖**：tpos1 响应仅断言前缀；T011/T088 已覆盖响应字段 |
| T12 | 跳过 initialize 直接 tools/call | Validate 拒绝（违反状态机） | 纯函数级（Validate），pcap 无法跨请求状态注入 |

### §8.6 日志与通知 — 缺 1

| ID | 名称 | 验证点 | 不可覆盖原因 |
|----|------|--------|------|
| T31 | notifications/progress 缺 progressToken | Validate 拒绝 | 纯函数级（Validate），pcap 不可注入缺字段（planner 自动填充） |

### §8.10 多会话并发 — 缺 1

| ID | 名称 | 验证点 | 不可覆盖原因 |
|----|------|--------|------|
| T45 | 多会话部分失败 | 流 2 initialize 失败，聚合包数断言 | 多流调度交错非确定（3 次运行 3 种布局），且"某流失败"需按流断言，pcap 断言无法稳定锚定（流级 inject 失败不可注入） |

### §8.12 边界与异常 — 缺 1

| ID | 名称 | 验证点 | 不可覆盖原因 |
|----|------|--------|------|
| T51 | JSON-RPC method not found -32601 | error.code=-32601 + data.method | **可覆盖未覆盖**：T086 已含 -32601 帧断言（roots/list 门控），spec 编号未回填 |

### §8.13 传输模式覆盖 — 缺 1

| ID | 名称 | 验证点 | 不可覆盖原因 |
|----|------|--------|------|
| T54 | stdio 行分隔 JSON 单行编码 | 帧断言 JSON 明文头 + `\n` | **可覆盖未覆盖**：tpos1/t002 帧断言已含（spec 编号未回填，等效 T057/T002 已覆盖） |

### §8.14 集成与端到端 — 缺 2

| ID | 名称 | 验证点 | 不可覆盖原因 |
|----|------|--------|------|
| T59 | 多会话 100 并发集成 | 100 条独立 TCP 流无交叉污染，总包数 == 100×单流 | 100 流规模驱动测试成本高；T43/T44 3 流已覆盖同质行为（4-tuple 独立 + id 序列） |
| T60 | MSS 分段大 JSON 包 | 8KB JSON 行切 6 个 TCP segment，拼接等于原行 | MSS 分段属 TCP 传输参数（tcp.mss），MCP planner 层未接入；需 tcp 层 mss 参数 + 拼接验证，当前 pcap 驱动不支持按流重组断言 |

### §8.16 v1.1.1 新增 — 缺 5（Batch 批量域）

| ID | 名称 | 验证点 | 不可覆盖原因 |
|----|------|--------|------|
| T81 | Batch 批量 3 请求→3 响应 | 字节级断言 `[{"jsonrpc":"2.0"` 开头 | batch 编解码（spec §2.6）planner 未实现：requests 数组不支持批量（MCPConfig 无 batch 字段），API 注入 batch 数组被按单请求处理 |
| T82 | 批量混合成功+失败 | 3 响应中 1 错误 2 成功 | 同上 |
| T83 | 批量空数组 -32600 | 空数组整体错误 | 同上 |
| T84 | 批量含非法 JSON 整体 -32700 | 单个顶层 -32700 | 同上 |
| T85 | Streamable+SSE 批量响应 | POST body 为数组 | 同上 |

## Spec 编号未回填清单（等效覆盖，编号不在 case 文本中）

以下 spec 编号的行为已被现有 pcap 用例的帧断言覆盖，但 case 的 summary/notes 中未引用该编号，自动统计时计为缺失（实际为等效覆盖）：

| Spec ID | 行为 | 实际载体 |
|---------|------|---------|
| T03 | HTTP POST 请求行+头 | mcp_tpos7_http_sse_session、mcp_t038_streamable_auth_in_init_response（POST 帧断言） |
| T04 | SSE 事件格式 | mcp_tpos7_http_sse_session（endpoint/message 事件帧断言 off176/off245） |
| T07 | initialize 默认字段 | mcp_tpos1_stdio_initialize（部分）、mcp_t011_stdio_protocol_version_downgrade |
| T08 | initialize 响应默认字段 | mcp_tpos1_stdio_initialize（部分）、mcp_t088_stdio_roots_sampling_negotiated |
| T51 | -32601 method not found | mcp_t086_stdio_roots_gated（pkt8 帧断言 error.code=-32601） |
| T54 | stdio 行分隔编码 | mcp_tpos1_stdio_initialize、mcp_t002_stdio_newline_escape |

## Spec Discrepancies / Planner Notes

1. **T011 协议版本降级（真实 planner bug，已修复）**：修复前服务端响应回声客户端版本（2025-06-18→2025-06-18），违反 spec §7.1"服务端应降级到已支持版本"。已在 `plan.go`/`builder.go`/`http_plan.go` 修复（响应恒钳制到 2024-11-05），failing-test-first（`TestPlan_ProtocolVersionDowngrade_ServerClamp`，mcp_test.go），服务器二进制已重建。**mcp_t011 用例验证修复后线序：请求 2025-06-18，响应 2024-11-05。**
2. **T061 validProtocolVersions 变体**：spec 允许 validProtocolVersions 空数组；planner 对空数组返回"invalid protocolVersion"错误（Validate 拒绝），与 spec 假设（空数组 = 未指定 = 默认接受）不同——mcp_t061 用无效版本字符串 2023-01-01 走同一拒绝路径。
3. **T048 anyExplicitID 首请求语义**：spec "anyExplicitID" 针对"任意一个请求显式 id"；planner 实际只检查**首个**请求（id=0 检查在第一个请求后停止），混用 id=0 + 显式 id 的拒绝（mixed auto and explicit id assignment）仅在首个请求为 id=0 时触发。mcp_t048 按此实现行为断言。
4. **T067 credentials 注入限制**：spec 期望 initialize 响应含 authentication（credentials 注入）；planner 的 id:0 override 不并入自动构建的 initialize 响应（响应仅由 ServerCapabilities 构建），cfg.Responses 只作用于已配置的 requests。mcp_t067 改为断言 plain initialize 响应 + 说明（partial）。
5. **T090/T099 重复键（dup-key）**：spec 期望重复键 JSON 被拒绝（"mcp: capabilities not valid JSON"）；但 config 经 API 解码为 map[string]any（Go last-wins，重复键坍缩）后 planner 才能看到，纯 API 无法注入重复键。mcp_t090/mcp_t099 使用等效负向变体：非法 JSON capabilities（`{"tools":{` 截断）→ "mcp: capabilities must be a JSON object"，同一 checkDuplicateKeys 校验路径。
6. **多流调度交错非确定**：3 流 pcap 的流间交错（哪流先完成会话）运行间漂移（实测 3 次运行 3 种布局）。T44 已改为只锚定首数据包（包 4）帧断言 + 逐流 tcp.srcport 字段断言 + 聚合结构断言（每源端口恰好 3 个负载包）。
7. **T18 nextCursor 实测为 `""`**：resources/list 响应 nextCursor 空（生成器固定数据），与 spec"响应 nextCursor 非空"假设不符——mcp_tpos4 partial。
8. **t002 线序长度**：tools/call echo 请求实际 107B（tcp.len，含尾 `\n`），旧文档 104B 错误，已修正。

## Key Observations

1. **覆盖率从 29.8% 提升至 76.9%**（80/104，含 partial；严格 74.0% = 77/104）。新增 63 个 pcap 用例覆盖了此前零覆盖的 §8.7 Roots/Sampling（T32-T35）、§8.9 状态机（T39-T42）、§8.10 多会话（T43/T44）、§8.11 调用链（T46/T47）、§8.14 集成（T57/T58）、§8.15 v1.1 全组（T61-T80 除 T75/T76）、§8.16 能力门控（T86-T90）、§8.17 v1.1.3 全组（T92-T104）。
2. **§8.15 与 §8.17 满覆盖**（20/20 与 13/13）；§8.3/§8.5/§8.7/§8.8/§8.9/§8.11 满覆盖；§8.4/§8.12/§8.13 各缺 1。
3. **batch 批量域（§8.16 T81-T85）是唯一整域空白**：planner 未实现批量编解码（spec §2.6），requests 数组不支持 batch；补实现后 5 条即可恢复覆盖。
4. **5 个"可覆盖未覆盖"编号（T03/T04/T07/T08/T51/T54）**：行为已被现有帧断言覆盖，仅缺 spec 编号回填——补 summary 编号即可计入（不影响断言强度）。
5. **2 个 partial**：T018（nextCursor 生成器恒空）、T067（planner 不支持 id:0 override 并入 init 响应）。
6. **不可覆盖域（约 16 条）**：纯函数序列化/Validate（T01/T05/T06/T31/T12 等）、planner 未实现（T60 MSS、T81-T85 batch、T45 流级失败）、规模成本（T59 100 并发）。

## Recommendations

1. **补 batch 域（§8.16 T81-T85，5 条）**：planner 实现批量编解码（spec §2.6）后，5 条 pcap 用例即可恢复批量覆盖（字节级 `[{` 开头断言 + 混合错误 + 空数组 -32600 + 整体 -32700 + Streamable+SSE 批量）。
2. **回填等效编号（6 条）**：tpos1/tpos7/t038/t086 的 summary/notes 补 T03/T04/T07/T08/T51/T54 编号（行为已被帧断言覆盖，仅缺编号）。
3. **T18 补非空 cursor**：resources/list 生成器配置非空 nextCursor 后升级 partial → covered。
4. **T067 credentials**：planner 支持 id:0 override 并入自动 init 响应后升级 partial → covered。
5. **T60 MSS 分段**：MCP planner 接入 tcp.mss 参数（如其他协议）后按 T44 稳定锚定法（首包帧断言 + tcp.len 字段断言）补 1 条。
6. **多流用例断言原则**：多流 pcap 流间交错非确定，锚定策略 = 首数据包帧断言 + 逐流端口/长度字段断言 + 聚合结构断言（每源端口恰好 N 个负载包），避免中间包位帧断言。
