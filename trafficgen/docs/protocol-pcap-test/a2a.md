# a2a Pcap Test Results

Cases: 185 — pass 185, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| a2a_s10_sse_5events | S10/T051/T048/T049: 流式 5 事件（task→status-update→artifact-update×2 append/lastChunk→status-update final:true），单包 SSE 8 包 | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_s10_sse_5events.pcap) |
| a2a_s11_error_32001 | S11/T058/T192: tasks/get id=nonexistent 响应 error -32001 Task not found，id 与请求一致，8 包 | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_s11_error_32001.pcap) |
| a2a_s12_artifact_append | S12/T123/T125/T126/T127/T128: artifact-update 3 块 append 语义（A→B append→C lastChunk），SSE 流 8 包 | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_s12_artifact_append.pcap) |
| a2a_s13_multi_part | S13/T028/T029: message/send 3 Part（text+data+file bytes base64），8 包 | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_s13_multi_part.pcap) |
| a2a_s14_webhook | S14/T151/T153/T155: 服务端→客户端 webhook（pushNotifications=true）：POST /webhook/a2a 含 X-A2A-Notification-Token+Authorization，body 为 Task 对象，8 包 | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_s14_webhook.pcap) |
| a2a_s15b_edge_skills_empty | T019/T173: AgentCard skills 空数组合法（design V12 允许 0-1024 元素）+ capabilities 全 false，Discover 响应 200，12 包 | pass | 11 | [pcap](/tmp/mcp-pcaps/a2a/a2a_s15b_edge_skills_empty.pcap) |
| a2a_s1_agent_card | S1/T013/T015: Discover=true 发 GET /.well-known/agent.json，响应 200 + AgentCard JSON（protocolVersion/securitySchemes/security），3 握手+3 Discover+3 Task+3 挥手=12 包 | pass | 11 | [pcap](/tmp/mcp-pcaps/a2a/a2a_s1_agent_card.pcap) |
| a2a_s2_message_send | S2/T025/T026/T033: message/send 同步文本消息，params 无 id，响应 result.kind=task 含 artifacts，8 包 | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_s2_message_send.pcap) |
| a2a_s2b_result_message | T034: message/send 响应 result.kind=message（简单交互无 Task），8 包 | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_s2b_result_message.pcap) |
| a2a_s3_message_stream | S3/T041/T042/T045/T046/T047: message/stream SSE 流 3 事件（task→artifact-update→status-update final:true），Accept=text/event-stream，chunked 分帧，8 包 | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_s3_message_stream.pcap) |
| a2a_s4_tasks_get | S4/T055/T056/T061: tasks/get 带 historyLength=5，响应 result.history 含 2 条 Message，8 包 | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_s4_tasks_get.pcap) |
| a2a_s5_tasks_cancel | S5/T065/T070: tasks/cancel 响应 result.status.state=canceled，8 包 | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_s5_tasks_cancel.pcap) |
| a2a_s6_resubscribe | S6/T073/T074/T079: tasks/resubscribe SSE 续传（1 status-update final:true 事件），Accept=text/event-stream，8 包 | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_s6_resubscribe.pcap) |
| a2a_s7_push_set | S7/T081/T082/T083/T084: tasks/pushNotificationConfig/set 请求含 taskId+pushNotificationConfig{url,token,authentication}，响应含 id，8 包 | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_s7_push_set.pcap) |
| a2a_s8_bearer_auth | S8/T093: Bearer Token 认证，请求含 Authorization: Bearer <token> 头，8 包 | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_s8_bearer_auth.pcap) |
| a2a_s8b_basic_auth | T094: Basic 认证，Authorization: Basic base64(user:pass)，8 包 | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_s8b_basic_auth.pcap) |
| a2a_s8c_apikey_header | T095: API Key 认证（header），请求含 X-API-Key 头，8 包 | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_s8c_apikey_header.pcap) |
| a2a_s9_multi_task_serial | T161/T169/T171/T172: 同 TCP 连接 2 task 串行（task-1 Connection:keep-alive，task-2 Connection:close），12 包 | pass | 11 | [pcap](/tmp/mcp-pcaps/a2a/a2a_s9_multi_task_serial.pcap) |
| a2a_t001_envelope_fields | T001: JSON-RPC 请求信封含 jsonrpc/method/params/id 四字段齐全（frame 字节断言） | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t001_envelope_fields.pcap) |
| a2a_t002_both_result_error | T002: 同时设 result 与 error，V16 互斥，Validate 拒绝（负向） | pass | 0 | [pcap]() |
| a2a_t003_id_string_consistency | T003: JSON-RPC id=string 一致，请求与响应 id 均为字符串 req-t003 | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t003_id_string_consistency.pcap) |
| a2a_t004_neg_missing_request_id | T004: 请求缺 JSON-RPC id 拒绝（近似 -32600） | pass | 0 | [pcap]() |
| a2a_t005_sse_data_line | T005: SSE 事件仅含 data: 行、无 event: 字段（spec v0.2.2 §3.1） | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t005_sse_data_line.pcap) |
| a2a_t006_sse_event_boundary | T006: SSE 事件边界双换行 \n\n 分隔（spec SSE §4） | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t006_sse_event_boundary.pcap) |
| a2a_t007_sse_multi_data_lines | T007: SSE 多行 data 拼接（多事件每行 data:，客户端按 \n 拼接） | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t007_sse_multi_data_lines.pcap) |
| a2a_t009_content_type_json | T009: 同步路径请求 Content-Type=application/json | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t009_content_type_json.pcap) |
| a2a_t010_content_type_sse | T010: 流式路径响应 Content-Type=text/event-stream | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t010_content_type_sse.pcap) |
| a2a_t011_keepalive | T011: 非最后请求 Connection: keep-alive（HTTP/1.1 默认行为） | pass | 11 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t011_keepalive.pcap) |
| a2a_t012_bearer_authorization | T012: Auth.Scheme=bearer 时请求含 Authorization: Bearer <token> 头 | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t012_bearer_authorization.pcap) |
| a2a_t014_agentcard_fields | T014/T020/T023/T024: AgentCard 必填字段+2 skills+provider+supportsAuthenticatedExtendedCard | pass | 11 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t014_agentcard_fields.pcap) |
| a2a_t016_securityschemes_map | T016/T017/T099-T102/T212d: securitySchemes map + security array + mutualTLS 不拒绝 | pass | 11 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t016_securityschemes_map.pcap) |
| a2a_t018_capabilities_all_false | T018: AgentCard.capabilities 全 false 合法 | pass | 11 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t018_capabilities_all_false.pcap) |
| a2a_t021_agentcard_custom_path | T021: agentCardPath 自定义路径（404 不可生成，验证路径可配置） | pass | 11 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t021_agentcard_custom_path.pcap) |
| a2a_t022_agentcard_malformed | T022: AgentCard JSON 畸形（响应体原样输出 {not valid） | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t022_agentcard_malformed.pcap) |
| a2a_t027_contextid_field | T027: message.contextId 非空，随请求发出 | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t027_contextid_field.pcap) |
| a2a_t030_file_uri | T030/T150: 文件 Part FileWithUri（file.uri=URL） | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t030_file_uri.pcap) |
| a2a_t031_configuration_metadata | T031/T032: params.configuration{acceptedOutputModes,blocking} + params.metadata | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t031_configuration_metadata.pcap) |
| a2a_t035_response_completed | T035/T064: 响应 result.status.state=completed 且 kind=task | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t035_response_completed.pcap) |
| a2a_t036_response_input_required | T036: 响应 state=input-required 含 status.message（role=agent） | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t036_response_input_required.pcap) |
| a2a_t037_neg_no_message | T037: params 无 message 拒绝 | pass | 0 | [pcap]() |
| a2a_t038_neg_role_system | T038: role=system 拒绝 | pass | 0 | [pcap]() |
| a2a_t039_neg_parts_empty | T039: parts=[] 拒绝 | pass | 0 | [pcap]() |
| a2a_t040_neg_kind_datastream | T040: Message.kind=data-stream 拒绝 | pass | 0 | [pcap]() |
| a2a_t043_stream_first_task | T043: message/stream 首事件 kind=task（SSE 首事件 result.kind=task） | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t043_stream_first_task.pcap) |
| a2a_t044_message_first_event | T044: Message-only 流首事件 result.kind=message | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t044_message_first_event.pcap) |
| a2a_t050_neg_streaming_false | T050/T195/T199: message/stream 但 streaming=false 拒绝 | pass | 0 | [pcap]() |
| a2a_t052_multi_stream_same_task | T052: 多并发流同 task（2 个流共享 taskId=task-052，事件广播） | pass | 11 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t052_multi_stream_same_task.pcap) |
| a2a_t053_neg_stream_no_parts | T053: message/stream parts=[] 拒绝 | pass | 0 | [pcap]() |
| a2a_t054_neg_stream_kind_filestream | T054: Message.kind=file-stream 拒绝 | pass | 0 | [pcap]() |
| a2a_t057_get_metadata | T057/T064: tasks/get 带 params.metadata，响应 result.kind=task | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t057_get_metadata.pcap) |
| a2a_t059_neg_get_no_id | T059: tasks/get 无 taskId 拒绝 | pass | 0 | [pcap]() |
| a2a_t060_get_artifacts | T060: tasks/get 响应 result.artifacts 数组非空 | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t060_get_artifacts.pcap) |
| a2a_t062_history_zero | T062: historyLength=0 边界（请求省略该参数，响应 history 空数组） | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t062_history_zero.pcap) |
| a2a_t063_history_1000 | T063: historyLength=1000 上限边界（请求参数输出 1000） | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t063_history_1000.pcap) |
| a2a_t066_cancel_terminal_32002 | T066: tasks/cancel 终态任务响应 -32002 | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t066_cancel_terminal_32002.pcap) |
| a2a_t067_neg_cancel_no_id | T067: tasks/cancel 缺 id（params 无 taskId，V8 拒绝） | pass | 0 | [pcap]() |
| a2a_t068_cancel_nonexistent_32001 | T068: tasks/cancel 任务不存在响应 -32001 | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t068_cancel_nonexistent_32001.pcap) |
| a2a_t069_cancel_metadata | T069: tasks/cancel 带 params.metadata | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t069_cancel_metadata.pcap) |
| a2a_t071_submitted_canceled | T071/T111: submitted→canceled 合法转换（SSE 事件序列） | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t071_submitted_canceled.pcap) |
| a2a_t072_working_canceled | T072: working→canceled 合法转换（SSE 事件序列） | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t072_working_canceled.pcap) |
| a2a_t075_neg_resubscribe_sync | T075: tasks/resubscribe 但 streaming=false 拒绝 | pass | 0 | [pcap]() |
| a2a_t076_neg_resubscribe_no_id | T076: tasks/resubscribe 无 taskId 拒绝 | pass | 0 | [pcap]() |
| a2a_t077_resubscribe_nonexistent | T077: tasks/resubscribe 任务不存在响应 -32001（错误注入） | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t077_resubscribe_nonexistent.pcap) |
| a2a_t078_resubscribe_resume | T078: resubscribe SSE 流携带断线后后续事件（working→input-required→working→completed） | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t078_resubscribe_resume.pcap) |
| a2a_t080_resubscribe_unnamed | T080: tasks/resubscribe SSE 事件未命名（无 event: 字段，data: 行起始） | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t080_resubscribe_unnamed.pcap) |
| a2a_t085_push_error_32003 | T085/T194/T200: pushNotifications 不支持响应 error.code=-32003 | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t085_push_error_32003.pcap) |
| a2a_t086_neg_set_no_taskid | T086: pushNotificationConfig/set 缺 taskId 拒绝 | pass | 0 | [pcap]() |
| a2a_t087_neg_set_no_config | T087: pushNotificationConfig/set 缺 pushNotificationConfig（V8 拒绝） | pass | 0 | [pcap]() |
| a2a_t088_neg_set_url_empty | T088: pushNotificationConfig.url 空拒绝 | pass | 0 | [pcap]() |
| a2a_t089_push_get | T089/T090/T232: pushNotificationConfig/get 查询，响应含 url/id/token/authentication | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t089_push_get.pcap) |
| a2a_t091_push_get_error_32001 | T091: pushNotificationConfig/get 任务不存在响应 -32001 | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t091_push_get_error_32001.pcap) |
| a2a_t092_neg_get_no_id | T092: pushNotificationConfig/get 缺 id 拒绝 | pass | 0 | [pcap]() |
| a2a_t096_apikey_query | T096: API Key 认证（query 参数） | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t096_apikey_query.pcap) |
| a2a_t097_oauth2_bearer | T097: OAuth2 认证 → Authorization: Bearer | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t097_oauth2_bearer.pcap) |
| a2a_t098_oidc_bearer | T098: OpenID Connect 认证 → Authorization: Bearer | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t098_oidc_bearer.pcap) |
| a2a_t100_security_apikey | T100: AgentCard.securitySchemes apiKey（type=apiKey,in=header,name=X-API-Key） | pass | 0 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t100_security_apikey.pcap) |
| a2a_t101_security_oauth2 | T101: AgentCard.securitySchemes oauth2（type=oauth2,flows.clientCredentials） | pass | 0 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t101_security_oauth2.pcap) |
| a2a_t103_none_no_auth | T103: Auth.Scheme=none 不带 Authorization 头 | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t103_none_no_auth.pcap) |
| a2a_t104_auth_required_state | T104: 响应状态 auth-required，status.message 含认证说明 | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t104_auth_required_state.pcap) |
| a2a_t105_state_machine_success | T105/T108: 状态机 submitted→working→completed 经典成功路径（SSE 流） | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t105_state_machine_success.pcap) |
| a2a_t106_multi_round_interaction | T106: submitted→working→input-required→working→completed 多轮交互 | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t106_multi_round_interaction.pcap) |
| a2a_t107_state_machine_failed | T107: 状态机 submitted→working→failed 失败路径（SSE 流） | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t107_state_machine_failed.pcap) |
| a2a_t109_submitted_rejected | T109: submitted→rejected Agent 拒绝 | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t109_submitted_rejected.pcap) |
| a2a_t110_auth_required_flow | T110/T122: submitted→auth-required→working→completed in-task 认证 | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t110_auth_required_flow.pcap) |
| a2a_t112_submitted_auth_required | T112: submitted→auth-required 需认证才开始 | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t112_submitted_auth_required.pcap) |
| a2a_t113_input_required_canceled | T113: input-required→canceled 等待输入时取消 | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t113_input_required_canceled.pcap) |
| a2a_t114_auth_required_canceled | T114: auth-required→canceled 等待认证时取消 | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t114_auth_required_canceled.pcap) |
| a2a_t115_unknown_state | T115: tasks/get 响应 state=unknown（taskId 过期） | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t115_unknown_state.pcap) |
| a2a_t116_neg_terminal_completed | T116: completed→working 终态不可变（Validate 拒绝） | pass | 0 | [pcap]() |
| a2a_t117_neg_terminal_failed | T117: failed→working 终态不可变拒绝 | pass | 0 | [pcap]() |
| a2a_t118_neg_terminal_canceled | T118: canceled→working 终态不可变拒绝 | pass | 0 | [pcap]() |
| a2a_t119_neg_terminal_rejected | T119: rejected→working 终态不可变拒绝 | pass | 0 | [pcap]() |
| a2a_t120_neg_input_required_completed | T120: input-required→completed 未定义转换拒绝 | pass | 0 | [pcap]() |
| a2a_t124_artifact_append_false | T124: artifact-update append=false 替换（同 artifactId 第二块 append=false 替换语义） | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t124_artifact_append_false.pcap) |
| a2a_t129_artifact_taskid_contextid | T129: artifact-update 含 taskId/contextId 字段 | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t129_artifact_taskid_contextid.pcap) |
| a2a_t130_neg_artifact_missing | T130: artifact-update 事件缺 artifact 拒绝 | pass | 0 | [pcap]() |
| a2a_t131_status_update_fields | T131/T134/T135/T136/T137: TaskStatusUpdateEvent 含 kind/taskId/contextId/status.state/final 字段，无 artifact | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t131_status_update_fields.pcap) |
| a2a_t132_status_update_final | T132/T136: status-update final=true 末事件 status.state 枚举值 | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t132_status_update_final.pcap) |
| a2a_t133_status_update_intermediate | T133: status-update final=false 中间事件（working 转换） | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t133_status_update_intermediate.pcap) |
| a2a_t139_role_user | T139: Message.role=user 请求（messageToMap 输出 role 字段），帧断言 role 字段字节 | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t139_role_user.pcap) |
| a2a_t140_message_role_agent | T140: Message.role=agent | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t140_message_role_agent.pcap) |
| a2a_t140_role_agent | T140: Message.role=agent 请求（text+data 双 Part） | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t140_role_agent.pcap) |
| a2a_t141_messageid_present | T141: Message.messageId 必填（请求携带 messageId 非空，V7 正向） | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t141_messageid_present.pcap) |
| a2a_t142_message_taskid_optional | T142: Message.taskId 可选字段 | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t142_message_taskid_optional.pcap) |
| a2a_t142_taskid_optional | T142: Message.taskId 可选（message 内 taskId 省略时合法；此处显式带 taskId 验证输出） | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t142_taskid_optional.pcap) |
| a2a_t144_reference_extensions | T144/T184/T185: referenceTaskIds 10 个 + extensions 5 个 URI | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t144_reference_extensions.pcap) |
| a2a_t145_message_extensions | T145: Message.extensions 多 URI | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t145_message_extensions.pcap) |
| a2a_t146_kind_message | T146: Message.kind=message（默认补全后随请求输出） | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t146_kind_message.pcap) |
| a2a_t146_message_kind | T146: Message.kind=message | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t146_message_kind.pcap) |
| a2a_t147_part_kind_text | T147: Part kind=text | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t147_part_kind_text.pcap) |
| a2a_t147_part_text | T147: Part kind=text，text 字段非空（parts 数组序列化） | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t147_part_text.pcap) |
| a2a_t148_part_data | T148: Part kind=data，data 字段为对象（JSON 序列化） | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t148_part_data.pcap) |
| a2a_t148_part_kind_data | T148: Part kind=data | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t148_part_kind_data.pcap) |
| a2a_t149_part_file_bytes | T149: Part kind=file（FileWithBytes base64 bytes） | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t149_part_file_bytes.pcap) |
| a2a_t149_part_kind_file_bytes | T149: Part kind=file（FileWithBytes） | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t149_part_kind_file_bytes.pcap) |
| a2a_t160_http_url | T160: webhook URL http:// 合法（Validate 警告不拒绝） | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t160_http_url.pcap) |
| a2a_t162_context_id | T162/T143: 2 task 共享 contextId=ctx-shared（tasks/get + message/send），同 TCP 连接，12 包 | pass | 11 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t162_context_id.pcap) |
| a2a_t163_multi_context_diff | T163: 多 Task 不同 contextId 合法 | pass | 11 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t163_multi_context_diff.pcap) |
| a2a_t164_multi_flow_count3 | T164: 多会话 3 task 同连接串行（3×POST 同 TCP，15 包） | pass | 13 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t164_multi_flow_count3.pcap) |
| a2a_t165_multi_session_taskid | T165: 多会话独立 taskId（3 流各自 taskId，strategy flows=3） | pass | 27 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t165_multi_session_taskid.pcap) |
| a2a_t167_100_flows | T167: 10 task 同连接聚合包数（10×POST+10 响应+握手+挥手=36 包） | pass | 27 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t167_100_flows.pcap) |
| a2a_t168_multi_flow_concurrency | T168: 并发流会话聚合（strategy flows=3 → 3 完整会话，27 包） | pass | 27 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t168_multi_flow_concurrency.pcap) |
| a2a_t174_text_1mb | T174: Part.text=1MB 边界（MSS 分段） | pass | 727 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t174_text_1mb.pcap) |
| a2a_t175_history_1000_get | T175: tasks/get historyLength=1000（请求参数+响应） | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t175_history_1000_get.pcap) |
| a2a_t176_history_zero_get | T176: tasks/get historyLength=0（请求省略参数，响应空 history） | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t176_history_zero_get.pcap) |
| a2a_t177_file_10mb | T177: FileWithBytes 10MB 边界（base64 编码传输） | pass | 9585 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t177_file_10mb.pcap) |
| a2a_t178_metadata_key_128 | T178: params.metadata key=128 字节边界 | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t178_metadata_key_128.pcap) |
| a2a_t179_id_128 | T179: JSON-RPC id=128 字节边界 | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t179_id_128.pcap) |
| a2a_t180_skills_1024 | T180: AgentCard.skills=1024 元素边界 | pass | 57 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t180_skills_1024.pcap) |
| a2a_t181_parts_1024 | T181: Message.parts=1024 元素边界 | pass | 31 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t181_parts_1024.pcap) |
| a2a_t182_contextid_128 | T182: Message.contextId=128 字节边界 | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t182_contextid_128.pcap) |
| a2a_t183_description_4096 | T183: AgentCard.description=4096 字节边界 | pass | 14 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t183_description_4096.pcap) |
| a2a_t186_sse_zero_middle_events | T186: SSE 流 0 中间事件（task→status-update final 仅 2 事件） | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t186_sse_zero_middle_events.pcap) |
| a2a_t187_error_32700 | T187: -32700 JSON 解析失败（错误注入） | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t187_error_32700.pcap) |
| a2a_t188_error_32600 | T188: -32600 无效 JSON-RPC 请求（缺 jsonrpc，错误注入） | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t188_error_32600.pcap) |
| a2a_t189_error_32601 | T189/T202: tasks/get 收到错误 method 模拟 -32601 MethodNotFoundError（响应端注入） | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t189_error_32601.pcap) |
| a2a_t190_error_32602 | T190: -32602 参数无效（params 缺必填，错误注入） | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t190_error_32602.pcap) |
| a2a_t191_error_32603 | T191: 服务端内部错误响应 error -32603 InternalError | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t191_error_32603.pcap) |
| a2a_t193_error_32002 | T193/T066: tasks/cancel 终态任务响应 error -32002 TaskNotCancelableError，id 与请求一致 | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t193_error_32002.pcap) |
| a2a_t196_error_32004_pnc | T196: -32004 通用不支持（pushNotificationConfig/list 不存在，错误注入到 set） | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t196_error_32004_pnc.pcap) |
| a2a_t196_neg_pnc_list_method | T196: pushNotificationConfig/list 方法不存在（Validate 拒绝） | pass | 0 | [pcap]() |
| a2a_t197_error_32005 | T197: 内容类型不支持响应 -32005 | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t197_error_32005.pcap) |
| a2a_t198_error_32006 | T198: Agent 响应无效 -32006 | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t198_error_32006.pcap) |
| a2a_t201_error_32004 | T201: 终态任务再发 message/send 响应 -32004 | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t201_error_32004.pcap) |
| a2a_t202_neg_sendsubscribe | T202: tasks/sendSubscribe 方法不存在（近似 -32601） | pass | 0 | [pcap]() |
| a2a_t203_neg_part_datastream | T203: 不支持的 Part kind=data-stream（Validate 拒绝） | pass | 0 | [pcap]() |
| a2a_t204_discover_send_e2e | T204: Agent Card 发现 + message/send 端到端（GET agent.json → POST message/send → 200） | pass | 11 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t204_discover_send_e2e.pcap) |
| a2a_t205_stream_full_flow | T205: message/stream 全流程（stream → SSE 流 → final:true → 流关闭） | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t205_stream_full_flow.pcap) |
| a2a_t207_resubscribe_resume_e2e | T207: tasks/resubscribe 断线重连（续传事件流） | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t207_resubscribe_resume_e2e.pcap) |
| a2a_t208_multi_task_serial_seq | T208: 多 task 同连接串行（task-2 seq > task-1 响应 seq） | pass | 11 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t208_multi_task_serial_seq.pcap) |
| a2a_t209_bearer_e2e | T209: AgentCard.securitySchemes → Bearer 认证全流程 | pass | 11 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t209_bearer_e2e.pcap) |
| a2a_t210_tshark_json_rpc | T210: tshark 解析 A2A JSON-RPC（POST body 解析为 JSON） | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t210_tshark_json_rpc.pcap) |
| a2a_t211_tshark_sse | T211: tshark 解析 SSE 流（http.file_data 含 data: JSON-RPC） | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t211_tshark_sse.pcap) |
| a2a_t212_protocol_version | T212/T015: AgentCard.protocolVersion 字段（Discover 响应 JSON 含 protocolVersion=0.3.0） | pass | 0 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t212_protocol_version.pcap) |
| a2a_t212a_additional_interfaces | T212a/T212b: AgentCard.additionalInterfaces + preferredTransport | pass | 11 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t212a_additional_interfaces.pcap) |
| a2a_t213_securityschemes_map | T213: AgentCard.securitySchemes map（与 T016 等价） | pass | 11 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t213_securityschemes_map.pcap) |
| a2a_t214_security_array | T214: AgentCard.security 数组（与 T017 等价） | pass | 11 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t214_security_array.pcap) |
| a2a_t215_result_contextid | T215: Task.result.contextId 字段非空（非 sessionId） | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t215_result_contextid.pcap) |
| a2a_t216_task_kind | T216: Task.kind=task（响应 result） | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t216_task_kind.pcap) |
| a2a_t217_messageid_required | T217: Message.messageId 必填（与 T141 等价） | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t217_messageid_required.pcap) |
| a2a_t218_contextid_assoc | T218: Message.contextId 关联（与 T143 等价） | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t218_contextid_assoc.pcap) |
| a2a_t219_message_kind | T219: Message.kind=message（响应 result=Message 对象含 kind 字段） | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t219_message_kind.pcap) |
| a2a_t219_message_kind_resp | T219: Message.kind=message（响应 result=Message） | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t219_message_kind_resp.pcap) |
| a2a_t220_status_update_taskid | T220: TaskStatusUpdateEvent.taskId（非 id） | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t220_status_update_taskid.pcap) |
| a2a_t221_artifact_update_full | T221: TaskArtifactUpdateEvent 完整字段（taskId/contextId/kind/artifact/append/lastChunk） | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t221_artifact_update_full.pcap) |
| a2a_t222_text_only | T222: Part kind=text 仅 text 字段（3 个 text Part，无 data/file） | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t222_text_only.pcap) |
| a2a_t223_data_only | T223: Part kind=data 仅 data 字段（无 text/file） | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t223_data_only.pcap) |
| a2a_t224_file_only | T224: Part kind=file 仅 file 字段（无 text/data） | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t224_file_only.pcap) |
| a2a_t225_neg_part_text_data | T225: Part kind=text 同时含 data 拒绝 | pass | 0 | [pcap]() |
| a2a_t226_neg_part_data_file | T226: Part kind=data 同时含 file 拒绝 | pass | 0 | [pcap]() |
| a2a_t227_neg_part_file_text | T227: Part kind=file 同时含 text 拒绝 | pass | 0 | [pcap]() |
| a2a_t228_method_message_send | T228: method=message/send（非 tasks/send，D-C1） | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t228_method_message_send.pcap) |
| a2a_t229_method_message_stream | T229: method=message/stream（非 tasks/sendSubscribe，D-C2） | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t229_method_message_stream.pcap) |
| a2a_t230_neg_subscribe | T230: tasks/subscribe 方法不存在（近似 -32601） | pass | 0 | [pcap]() |
| a2a_t231_method_pnc_set | T231: method=tasks/pushNotificationConfig/set（含 Config，D-C3） | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t231_method_pnc_set.pcap) |
| a2a_t233_wellknown_agent_singular | T233: GET /.well-known/agent.json（单数，D-C4） | pass | 11 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t233_wellknown_agent_singular.pcap) |
| a2a_t234_wellknown_agents_plural | T234: GET /.well-known/agents.json（复数）— planner 不建模 404，断言路径 | pass | 11 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t234_wellknown_agents_plural.pcap) |
| a2a_t235_kinds_only_three | T235: Part kind 仅 text/data/file（三种同时出现合法） | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t235_kinds_only_three.pcap) |
| a2a_t236_neg_kind_datastream | T236: Part kind=data-stream 拒绝（D-C5 验证） | pass | 0 | [pcap]() |
| a2a_t237_neg_kind_filestream | T237: Part kind=file-stream 拒绝（D-C5 验证） | pass | 0 | [pcap]() |
| a2a_t238_pnc_id | T238: PushNotificationConfig.id 字段（非 userId，D-H1 修复） | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t238_pnc_id.pcap) |
| a2a_t239_pnc_no_userid | T239: PushNotificationConfig 无 userId 字段（D-H1 验证） | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t239_pnc_no_userid.pcap) |
| a2a_t240_sse_no_event_field | T240: SSE 事件无 event: 字段（与 T080/T005 等价） | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t240_sse_no_event_field.pcap) |
| a2a_t241_status_no_artifact | T241: TaskStatusUpdateEvent 无 artifact 字段（D-H3） | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t241_status_no_artifact.pcap) |
| a2a_t242_artifact_independent | T242: TaskArtifactUpdateEvent 独立事件（与 T046/T124 等价） | pass | 9 | [pcap](/tmp/mcp-pcaps/a2a/a2a_t242_artifact_independent.pcap) |
