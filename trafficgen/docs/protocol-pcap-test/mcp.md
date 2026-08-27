# mcp Pcap Test Results

Cases: 79 — pass 79, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| mcp_t002_stdio_newline_escape | T-002/§2.3: JSON 行内 \n 转义，params 含换行符字符串序列化为 \\n，行数不变 | pass | 12 | [pcap](mcp/mcp_t002_stdio_newline_escape.pcap) |
| mcp_t011_stdio_protocol_version_downgrade | T-011/§7.1: initialize 协议版本降级，客户端 2025-06-18 → 服务端响应 2024-11-05 | pass | 12 | [pcap](mcp/mcp_t011_stdio_protocol_version_downgrade.pcap) |
| mcp_t013_stdio_tools_list_default3 | T-013/§7.4: tools/list 默认 3 工具响应 ping/echo/search，含 inputSchema | pass | 12 | [pcap](mcp/mcp_t013_stdio_tools_list_default3.pcap) |
| mcp_t014_stdio_tools_call_success | T-014/§7.4: tools/call 成功响应 content 含 text 块，isError=false | pass | 12 | [pcap](mcp/mcp_t014_stdio_tools_call_success.pcap) |
| mcp_t015_stdio_tools_call_iserror | T-015/§7.4: tools/call 工具层失败 result.isError=true，content 含错误文本 | pass | 12 | [pcap](mcp/mcp_t015_stdio_tools_call_iserror.pcap) |
| mcp_t016_stdio_tools_call_image | T-016/§7.4: tools/call 返回图片内容 content 含 image 块，data 为 base64，mimeType=image/png | pass | 12 | [pcap](mcp/mcp_t016_stdio_tools_call_image.pcap) |
| mcp_t017_stdio_tools_call_unknown_tool | T-017/§7.4: tools/call 工具名不存在 → error -32602 Invalid params，message 含工具名 | pass | 12 | [pcap](mcp/mcp_t017_stdio_tools_call_unknown_tool.pcap) |
| mcp_t019_stdio_resources_read_text | T-019/§7.5: resources/read 文本资源 contents[0].text 字符串 + mimeType=text/plain | pass | 12 | [pcap](mcp/mcp_t019_stdio_resources_read_text.pcap) |
| mcp_t020_stdio_resources_read_blob | T-020/§7.5: resources/read 二进制资源，contents[0].blob 为 base64（非 text 字段） | pass | 12 | [pcap](mcp/mcp_t020_stdio_resources_read_blob.pcap) |
| mcp_t021_stdio_resources_subscribe_updated | T-021/§7.5: resources/subscribe 请求 → 空响应 → notifications/updated 通知，uri 一致 | pass | 13 | [pcap](mcp/mcp_t021_stdio_resources_subscribe_updated.pcap) |
| mcp_t022_stdio_resources_read_404 | T-022/§7.5: resources/read uri 不存在 → error -32002 Resource not found + data.uri | pass | 12 | [pcap](mcp/mcp_t022_stdio_resources_read_404.pcap) |
| mcp_t023_stdio_prompts_list_args | T-023/§7.7: prompts/list 含 arguments 元数据，arguments 数组 + required 字段 | pass | 12 | [pcap](mcp/mcp_t023_stdio_prompts_list_args.pcap) |
| mcp_t024_stdio_prompts_get | T-024/§7.7: prompts/get 单消息响应，messages[0].role=user，content.type=text | pass | 12 | [pcap](mcp/mcp_t024_stdio_prompts_get.pcap) |
| mcp_t025_stdio_prompts_get_multi_role | T-025/§7.7: prompts/get 多消息多部分响应，messages 含 user+assistant+resource 三种 role | pass | 12 | [pcap](mcp/mcp_t025_stdio_prompts_get_multi_role.pcap) |
| mcp_t026_stdio_completion_complete | T-026/§7.8: completion/complete 响应，completion.values 数组，total+hasMore 字段 | pass | 12 | [pcap](mcp/mcp_t026_stdio_completion_complete.pcap) |
| mcp_t027_stdio_logging_setlevel | T-027/§7.9: logging/setLevel 请求-响应，level=debug，result 空对象 | pass | 12 | [pcap](mcp/mcp_t027_stdio_logging_setlevel.pcap) |
| mcp_t029_stdio_cancelled_requestid | T-029/§7.10: notifications/cancelled 携带 requestId 等于被取消请求的 id | pass | 13 | [pcap](mcp/mcp_t029_stdio_cancelled_requestid.pcap) |
| mcp_t032_stdio_roots_list_changed | T-032/§7.12: notifications/roots/list_changed 通知，无 params 无 id | pass | 13 | [pcap](mcp/mcp_t032_stdio_roots_list_changed.pcap) |
| mcp_t033_stdio_roots_list_changed | T-033/§7.12: notifications/roots/list_changed 通知，无 params 无 id，方向 C→S | pass | 13 | [pcap](mcp/mcp_t033_stdio_roots_list_changed.pcap) |
| mcp_t034_stdio_sampling_full_request | T-034/§7.13: sampling/createMessage 完整请求，messages+modelPreferences+maxTokens+temperature | pass | 12 | [pcap](mcp/mcp_t034_stdio_sampling_full_request.pcap) |
| mcp_t035_stdio_sampling_stopreason | T-035/§7.13: sampling 响应 stopReason=endTurn，role=assistant + content.type=text + model 非空 | pass | 12 | [pcap](mcp/mcp_t035_stdio_sampling_stopreason.pcap) |
| mcp_t036_http_sse_bearer_auth | T-036/§7.14: Bearer 认证头，Authorization: Bearer <token> | pass | 19 | [pcap](mcp/mcp_t036_http_sse_bearer_auth.pcap) |
| mcp_t037_streamable_basic_auth | T-037/§7.14: Basic 认证头，Authorization: Basic <base64(user:pass)> | pass | 17 | [pcap](mcp/mcp_t037_streamable_basic_auth.pcap) |
| mcp_t038_streamable_auth_in_init_response | T-038/§7.14: initialize 响应含 authentication.schemes 数组（OAuth2 方案） | pass | 15 | [pcap](mcp/mcp_t038_streamable_auth_in_init_response.pcap) |
| mcp_t039_stdio_state_complete | T-039/§7.15: state 完整流 submitted→working→completed，progress 通知 + _meta.state=completed 终态 | pass | 13 | [pcap](mcp/mcp_t039_stdio_state_complete.pcap) |
| mcp_t040_stdio_state_input_required | T-040/§7.15: state input_required 中间状态，响应 _meta.state=input_required；progress 通知不含 state | pass | 13 | [pcap](mcp/mcp_t040_stdio_state_input_required.pcap) |
| mcp_t041_stdio_state_failed | T-041/§7.15: state failed 终态，最终响应 isError=true + _meta.state=failed | pass | 12 | [pcap](mcp/mcp_t041_stdio_state_failed.pcap) |
| mcp_t042_stdio_state_canceled | T-042/§7.15: state canceled（客户端取消），notifications/cancelled + 响应 _meta.state=canceled | pass | 13 | [pcap](mcp/mcp_t042_stdio_state_canceled.pcap) |
| mcp_t043_stdio_multiflow_3_sessions | T-043/§7.16: 3 会话独立 4-tuple，src_port 递增 12345/12346/12347，聚合包数 33 | pass | 36 | [pcap](mcp/mcp_t043_stdio_multiflow_3_sessions.pcap) |
| mcp_t044_stdio_multiflow_id_seq | T-044/§7.16: 多会话独立 id 序列，每条流 id 从 1 开始（initialize id=1, ping id=2） | pass | 36 | [pcap](mcp/mcp_t044_stdio_multiflow_id_seq.pcap) |
| mcp_t046_stdio_context_id_chain | T-046/§7.17: contextId 贯穿调用链——config 接受 + 请求/响应显式注入 _meta.contextId | pass | 12 | [pcap](mcp/mcp_t046_stdio_context_id_chain.pcap) |
| mcp_t047_stdio_progress_parentid | T-047/§7.17: notifications/progress params.parentId 非空（嵌套进度） | pass | 13 | [pcap](mcp/mcp_t047_stdio_progress_parentid.pcap) |
| mcp_t048_stdio_mixed_id_reject | T-048/§4.1: 混用自动/显式 id 分配 → Validate 拒绝（部分 0 部分非零） | pass | 0 | [pcap]() |
| mcp_t049_stdio_empty_method_reject | T-049/§4.4: 请求 method 空字符串 → Validate 拒绝 | pass | 0 | [pcap]() |
| mcp_t050_stdio_parse_error | T-050/§7.19: JSON-RPC parse error 响应 -32700，显式 error 对象注入 | pass | 12 | [pcap](mcp/mcp_t050_stdio_parse_error.pcap) |
| mcp_t052_stdio_invalid_params_error | T-052/§7.19: JSON-RPC invalid params 响应 -32602，data.param+reason | pass | 12 | [pcap](mcp/mcp_t052_stdio_invalid_params_error.pcap) |
| mcp_t053_stdio_capabilities_empty | T-053/§7.18: capabilities 全空对象 {} 合法（spec optional） | pass | 12 | [pcap](mcp/mcp_t053_stdio_capabilities_empty.pcap) |
| mcp_t061_stdio_invalid_protocol_version | T-061/§4.4: 非法 protocol_version（2023-01-01）→ Validate 拒绝 | pass | 0 | [pcap]() |
| mcp_t062_stdio_tools_call_missing_name | T-062/§7.4: tools/call 缺 name 参数 → error -32602，data.param=name reason=required | pass | 12 | [pcap](mcp/mcp_t062_stdio_tools_call_missing_name.pcap) |
| mcp_t063_stdio_subscribe_unsupported | T-063/§7.5: resources/subscribe 服务端 capabilities 不支持 → -32601 Method not found | pass | 12 | [pcap](mcp/mcp_t063_stdio_subscribe_unsupported.pcap) |
| mcp_t064_stdio_initialized_no_params | T-064/§7.2: notifications/initialized 严格 spec 无 params 字段（仅 jsonrpc+method） | pass | 12 | [pcap](mcp/mcp_t064_stdio_initialized_no_params.pcap) |
| mcp_t065_stdio_caps_omitted | T-065/§7.18: capabilities 省略（最小客户端），initialize 请求无 capabilities 字段 | pass | 12 | [pcap](mcp/mcp_t065_stdio_caps_omitted.pcap) |
| mcp_t066_stdio_notifications_logger | T-066/§7.9: notifications/message params.logger 非空（扩展表 31 字段 logger 覆盖） | pass | 13 | [pcap](mcp/mcp_t066_stdio_notifications_logger.pcap) |
| mcp_t067_stdio_initialize_credentials | T-067/§8.15: initialize 请求 params._meta.credentials（扩展表 31 字段 credentials 覆盖） | pass | 12 | [pcap](mcp/mcp_t067_stdio_initialize_credentials.pcap) |
| mcp_t068_stdio_prompts_get_parts | T-068/§7.7: prompts/get 响应 content 含 parts 数组（multi-part 内容块） | pass | 12 | [pcap](mcp/mcp_t068_stdio_prompts_get_parts.pcap) |
| mcp_t069_stdio_tools_call_meta_metadata | T-069/§8.15: tools/call 请求 _meta.metadata 自定义 map（扩展表 31 字段 metadata 覆盖） | pass | 12 | [pcap](mcp/mcp_t069_stdio_tools_call_meta_metadata.pcap) |
| mcp_t070_stdio_tools_call_push_notification | T-070/§8.15: tools/call 长任务请求 _meta.pushNotification 含 url + verificationToken | pass | 12 | [pcap](mcp/mcp_t070_stdio_tools_call_push_notification.pcap) |
| mcp_t071a_stdio_unsubscribe_20250326 | T-071a/§8.7: resources/unsubscribe（spec 2025-03-26 专用）protocol_version=2025-03-26 正向 | pass | 14 | [pcap](mcp/mcp_t071a_stdio_unsubscribe_20250326.pcap) |
| mcp_t071b_stdio_unsubscribe_20241105 | T-071b/§8.7: resources/unsubscribe 在 2024-11-05 下 -32601 Method not found（spec 未定义） | pass | 12 | [pcap](mcp/mcp_t071b_stdio_unsubscribe_20241105.pcap) |
| mcp_t072_stdio_resources_templates_list | T-072/§8.7: resources/templates/list 请求 → 响应 resourceTemplates 数组（uriTemplate/name/mimeType） | pass | 12 | [pcap](mcp/mcp_t072_stdio_resources_templates_list.pcap) |
| mcp_t073_stdio_resources_list_changed | T-073/§8.7: notifications/resources/list_changed S→C 通知，无 id 无 params | pass | 13 | [pcap](mcp/mcp_t073_stdio_resources_list_changed.pcap) |
| mcp_t074_stdio_sampling_fields | T-074/§8.13: sampling/createMessage 字段完整性 messages+systemPrompt+maxTokens（可选字段可缺省） | pass | 12 | [pcap](mcp/mcp_t074_stdio_sampling_fields.pcap) |
| mcp_t077_stdio_teardown_sequence | T-077/§6.2: stdio teardown 3 包字节序列 FIN-ACK(up)→FIN-ACK(down)→ACK(up)，flags 0x11/0x11/0x10 | pass | 12 | [pcap](mcp/mcp_t077_stdio_teardown_sequence.pcap) |
| mcp_t079_stdio_error_code_positive_reject | T-079/§4.4: MCPError.Code=42（正数）→ Validate 拒绝（JSON-RPC 错误码不可为正） | pass | 0 | [pcap]() |
| mcp_t080_stdio_progress_no_state | T-080/§8.12: progress 通知 params 仅 progressToken/progress/total/message，无 state 字段 | pass | 13 | [pcap](mcp/mcp_t080_stdio_progress_no_state.pcap) |
| mcp_t086_stdio_roots_gated | T-086/§5.4: client 声明 roots，server 未声明 → roots/list 被拒绝 -32601 Method not found | pass | 12 | [pcap](mcp/mcp_t086_stdio_roots_gated.pcap) |
| mcp_t087_stdio_experimental_warning | T-087/§5.4: client 声明 experimental.xyz 非标准字段，server 保留 + _meta.warnings，后续请求不拒绝 | pass | 12 | [pcap](mcp/mcp_t087_stdio_experimental_warning.pcap) |
| mcp_t088_stdio_roots_sampling_negotiated | T-088/§5.4: 双向协商成功，client roots+sampling 声明 + server tools+resources 声明 + S→C roots/list + sampling/createMessage | pass | 14 | [pcap](mcp/mcp_t088_stdio_roots_sampling_negotiated.pcap) |
| mcp_t089_stdio_capabilities_empty_obj | T-089/§5.4: 能力声明空对象 {} 合法不报错，双方按无能力处理 | pass | 12 | [pcap](mcp/mcp_t089_stdio_capabilities_empty_obj.pcap) |
| mcp_t090_stdio_client_caps_dup_key | T-090/§5.4: ClientCapabilities 重复键 → Validate 拒绝 | pass | 0 | [pcap]() |
| mcp_t092_stdio_resources_read_32002 | T-092/§7.5: resources/read uri 不存在 -32002 Resource not found（spec 合规错误码） | pass | 12 | [pcap](mcp/mcp_t092_stdio_resources_read_32002.pcap) |
| mcp_t093_stdio_sampling_reject_code_minus1 | T-093/§8.13: sampling 拒绝响应 error.code=-1（spec 用户拒绝示例） | pass | 12 | [pcap](mcp/mcp_t093_stdio_sampling_reject_code_minus1.pcap) |
| mcp_t094_stdio_content_resource_link | T-094/§8.15: MCPContent.Type=resource_link（spec 2025-06-18 新增），uri+name 引用形式 | pass | 12 | [pcap](mcp/mcp_t094_stdio_content_resource_link.pcap) |
| mcp_t095_stdio_content_resource_embedded | T-095/§8.15: MCPContent.Type=resource 嵌入资源（uri+mimeType+text 内联） | pass | 12 | [pcap](mcp/mcp_t095_stdio_content_resource_embedded.pcap) |
| mcp_t099_stdio_server_caps_dup_key | T-099/§5.4: ServerCapabilities 重复键 → Validate 拒绝（与 T90 对称） | pass | 0 | [pcap]() |
| mcp_t100_stdio_tools_list_pagination | T-100/§8.10: tools/list 分页 cursor + nextCursor（spec 分页机制） | pass | 12 | [pcap](mcp/mcp_t100_stdio_tools_list_pagination.pcap) |
| mcp_t101_stdio_roots_list_no_params | T-101/§8.11: roots/list 请求省略 params（spec 示例一致，id=12） | pass | 12 | [pcap](mcp/mcp_t101_stdio_roots_list_no_params.pcap) |
| mcp_t102a_stdio_ping_empty_params | T-102a/§8.4: ping 请求带空对象 params:{}（宽松 spec 接受） | pass | 12 | [pcap](mcp/mcp_t102a_stdio_ping_empty_params.pcap) |
| mcp_t102b_stdio_ping_nonempty_params | T-102b/§8.4: ping 带非空 params {x:1} → 严格 spec 服务端 -32602 Invalid params | pass | 12 | [pcap](mcp/mcp_t102b_stdio_ping_nonempty_params.pcap) |
| mcp_t103_stdio_sampling_temperature_stop | T-103/§8.13: sampling 请求含 temperature=0.7 + stopSequences=["\n\n"]（可选字段） | pass | 12 | [pcap](mcp/mcp_t103_stdio_sampling_temperature_stop.pcap) |
| mcp_t104_stdio_unknown_tool_message | T-104/§8.10: tools/call 未知工具 error.message 含 "Unknown tool:" 前缀 + 工具名 | pass | 12 | [pcap](mcp/mcp_t104_stdio_unknown_tool_message.pcap) |
| mcp_tpos1_stdio_initialize | T-POS-1/§6.2: stdio 单会话默认流程（initialize→tools/list→tools/call→shutdown），13 包，行分隔 JSON | pass | 14 | [pcap](mcp/mcp_tpos1_stdio_initialize.pcap) |
| mcp_tpos2_stdio_default_seq | T-POS-2/§4.3: 不提供 requests 时默认序列 tools/list+tools/call，13 包（默认端口 80） | pass | 14 | [pcap](mcp/mcp_tpos2_stdio_default_seq.pcap) |
| mcp_tpos3_stdio_ping | T-POS-3/§7.3: ping 心跳请求-响应配对，id=99，result 空对象 | pass | 12 | [pcap](mcp/mcp_tpos3_stdio_ping.pcap) |
| mcp_tpos4_stdio_resources | T-POS-4/§7.5: resources/list + resources/read 流程，id 2/3，响应含 hosts 资源 | pass | 14 | [pcap](mcp/mcp_tpos4_stdio_resources.pcap) |
| mcp_tpos5_stdio_notifications | T-POS-5/§7.11+§7.9: progress 通知（step=0，客户端+服务端）+ notifications/message，通知无 id | pass | 14 | [pcap](mcp/mcp_tpos5_stdio_notifications.pcap) |
| mcp_tpos6_stdio_error_response | T-NEG-6/§7.19: 显式错误响应 tools/call 未知工具 -32602 + 方法不存在 -32601，error 帧字节断言 | pass | 14 | [pcap](mcp/mcp_tpos6_stdio_error_response.pcap) |
| mcp_tpos7_http_sse_session | T-POS-7/§6.3+§2.4: http_sse 完整会话，GET 先于 POST、endpoint 事件、202 Accepted、SSE message 推送 | pass | 19 | [pcap](mcp/mcp_tpos7_http_sse_session.pcap) |
| mcp_tpos8_streamable_http | T-POS-8/§6.4+§2.5: streamable 单端点 POST + 200 JSON 响应 + DELETE /mcp 204 终止 | pass | 17 | [pcap](mcp/mcp_tpos8_streamable_http.pcap) |
