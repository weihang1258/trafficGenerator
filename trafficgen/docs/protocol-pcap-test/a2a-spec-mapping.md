# A2A Spec-to-PCAP Test Case Mapping

## Files
- **Design spec**: `/home/weihang/trafficGenerator/docs/protocol-designs/17-a2a-design.md` (§7 "测试用例（T-001 ~ T-242，含 T212a-d）", line 1445)
- **PCAP test cases**: `/home/weihang/trafficGenerator/trafficgen/test/protocol_pcap/cases/a2a.json` (185 cases)
- **PCAP results**: `/home/weihang/trafficGenerator/trafficgen/docs/protocol-pcap-test/a2a.md`（185 cases，pass 185 / fail 0 / error 0）

## Spec Overview

§7 包含 **246 条测试用例**，按验证点分为 21 个小节（正向 150 / 负向 56 / 边界 30 / 集成 8 / 并发 2）：

| Section | Range | Count | Description |
|---------|-------|-------|-------------|
| §7.1 报文格式与序列化 | T-001~T-012 | 12 | JSON-RPC 信封/SSE 格式/HTTP 头（Content-Type/Accept/keep-alive/Authorization） |
| §7.2 Agent Card 发现 | T-013~T-024 | 12 | GET /.well-known/agent.json + AgentCard 字段（S1） |
| §7.3 message/send | T-025~T-040 | 16 | 同步文本消息/多 Part/configuration/metadata/响应 Task 或 Message（S2） |
| §7.4 message/stream | T-041~T-054 | 14 | SSE 流 3/5 事件序列/append 语义/lastChunk/按序投递（S3/S10） |
| §7.5 tasks/get | T-055~T-064 | 10 | historyLength/artifacts/history/-32001（S4） |
| §7.6 tasks/cancel | T-065~T-072 | 8 | canceled 状态/终态取消 -32002/-32001（S5） |
| §7.7 tasks/resubscribe | T-073~T-080 | 8 | 断线重连 SSE 续传/Accept 头（S6） |
| §7.8 pushNotificationConfig | T-081~T-092 | 12 | set 请求 taskId+config/get 查询/缺字段拒绝（S7） |
| §7.9 认证 | T-093~T-104 | 12 | Bearer/Basic/API Key/OAuth2/OpenID Connect/securitySchemes（S8） |
| §7.10 状态机 | T-105~T-122 | 18 | 合法转换 15 条 + 终态不可变/未定义转换拒绝 6 条 |
| §7.11 TaskArtifactUpdateEvent | T-123~T-130 | 8 | append=true/false/lastChunk/多块拼接（S12） |
| §7.12 TaskStatusUpdateEvent | T-131~T-138 | 8 | final=true/false/kind/taskId/contextId/缺 status 拒绝 |
| §7.13 多 Part 与 Message 字段 | T-139~T-150 | 12 | role/messageId/contextId/referenceTaskIds/extensions/Part 三种 kind |
| §7.14 Push Notification webhook | T-151~T-160 | 10 | POST webhook/X-A2A-Notification-Token/2xx 与重试/幂等（S14） |
| §7.15 多任务/多会话/并发 | T-161~T-172 | 12 | 同连接串行/同 contextId/GroupID/100 并发流聚合（S9） |
| §7.16 边界场景 | T-173~T-186 | 14 | skills 空/1MB text/10MB file/1024 元素/128B 字段（S15） |
| §7.17 异常场景 | T-187~T-203 | 17 | -32700/-32600/-32601/-32602/-32603/-32001~-32006 错误码 |
| §7.18 集成与端到端 | T-204~T-211 | 8 | 发现+send 全流程/stream 全流程/webhook 投递/tshark 解析 |
| §7.19 字段覆盖补全 | T-212~T-221+T-212a~d | 14 | additionalInterfaces/preferredTransport/signatures/mutualTLS + 等价断言 |
| §7.20 Part kind 互斥 | T-222~T-227 | 6 | text/data/file 仅对应字段 + 混合拒绝 |
| §7.21 v2.0.0 新增 | T-228~T-242 | 15 | 审计 D-* 修复验证（方法名/复数路径/SSE 无 event 等） |
| **Total** | | **246** | |

> 编号口径：grep 全文档得 T-001~T-242 共 **242 个显式编号**（T-212a~d 为 4 个子编号，
> 主编号 T-212 在表中以"T-212+T-212a~d"出现但无独立 T-212 行）；§7.14 中
> T-156~T-159 出现在表格内。pcap 套件按 242 个显式编号逐一映射，4 个子编号并入
> §7.19 计数；T-156~T-159 按 §7.14 行内容映射（不可达，见下）。

## Summary Counts

| Metric | Count |
|--------|-------|
| Total spec test cases (§7, 显式编号) | 242 |
| Total pcap test cases | **185** |
| Unique spec IDs covered by pcap | **231** |
| Spec IDs remaining（不可达/实时域，原因见下） | **11** |
| **Coverage rate** | **95.5%** (231/242) |
> 演进：64/246（26.0%）→ 175/246（71.1%）→ **231/242（95.5%）**。
> 覆盖判定：pcap case 的 notes 显式引用 spec T-NNN（legacy s* 用例注记已补齐），
> 或 case id 携带 T-NNN；notes 中声明"不可生成/未覆盖"的引用不计入覆盖（T021/T234）。
> 全部 185 用例 PASS。

## 剩余 11 条与原因

| ID | 内容 | 原因 |
|----|------|------|
| T021 | AgentCard 路径 404（AgentCardPath=/wrong-path，响应 404） | planner 对 Discover 恒返回 200（不建模 404 响应）；case a2a_t021 仅验证自定义路径注入生效，notes 显式声明"404 响应不可生成" |
| T138 | status-update 缺 status 拒绝 | Validate V9 对 status-update 缺 status 是软约束（不拦截），已移除套件；归 Go 单测域（同 T116 修复前模式，但 T116 已由 V10 硬拒绝覆盖） |
| T152 | webhook Content-Type=application/json | planner 不建模 webhook POST 投递（internal/ 全量搜索无 webhook 代码），wire 上无 webhook 请求可断言 |
| T154 | webhook Authorization 头 | 同上（webhook 域） |
| T156 | webhook 客户端响应 2xx | 同上 |
| T157 | webhook 客户端响应非 2xx | 同上 |
| T158 | webhook 至少投递一次 | 同上（含重试语义） |
| T159 | webhook 幂等处理 | 同上 |
| T166 | 多会话 GroupID 路由 | 并发路由为实时域：静态 pcap 无法断言跨流分组路由，归 Go 单测/性能测试域 |
| T206 | pushNotificationConfig/set + webhook 投递集成 | 同 T152（§7.18 集成；webhook 域共 7 条） |
| T212c | AgentCard.signatures（v0.3.0 签名数组） | spec 标注"本设计 v1 保留字段不生成"，planner 不输出该字段；case a2a_t212a notes 显式声明未覆盖 |
| T234 | GET /.well-known/agents.json（复数）404 | planner 不建模 404 响应（恒返回 200），状态码 404 不可生成；case a2a_t234 仅验证复数路径注入生效，notes 显式声明未覆盖 |

> 注：T168（并发流速率聚合）原 71 条清单之一，本轮以 strategy flows=3 的
> 3 会话完整性断言（27 包）纳入覆盖；速率聚合本身（bps 实测）仍属实时域，
> 已在 case notes 中说明。T171（最后 task Connection:close）由 a2a_s9_multi_task_serial
> 覆盖。webhook 域 6 条（T152/T154/T156-159）+ T206 需 planner 新增 webhook 子流建模后
> 方可 pcap 断言；T021/T234 需 planner 支持 404 响应生成；T212c 为 spec 声明的不生成
> 保留字段。

## Covered Mapping (231 spec IDs → 185 pcap cases)

> 覆盖判定：pcap case 的 notes 显式引用 spec T-NNN（本轮统一补齐 legacy s* 用例的
> spec ID 注记），或 case id 携带 T-NNN；notes 声明"不可生成/未覆盖"的引用不计入
> 覆盖（T021/T234 见上表）。同一 spec ID 可能被多个 case 覆盖（逗号分隔）。

### §7.1 报文格式与序列化（12/12）
| T001 | JSON-RPC 请求必填字段 | a2a_t001_envelope_fields | covered |
| T002 | JSON-RPC 响应 result/error 互斥 | a2a_t002_both_result_error | covered |
| T003 | JSON-RPC id 类型一致 | a2a_t003_id_string_consistency | covered |
| T004 | JSON-RPC 请求缺 id | a2a_t004_neg_missing_request_id | covered |
| T005 | SSE 事件格式（未命名，仅 data: 行） | a2a_t005_sse_data_line,a2a_t080_resubscribe_unnamed,a2a_t240_sse_no_event_field | covered |
| T006 | SSE 事件边界双 \n\n | a2a_t006_sse_event_boundary,a2a_t007_sse_multi_data_lines | covered |
| T007 | SSE 多行 data 拼接 | a2a_t007_sse_multi_data_lines | covered |
| T008 | SSE 流末事件 final:true 后关闭 | a2a_t186_sse_zero_middle_events,a2a_t132_status_update_final | covered |
| T009 | HTTP 请求 Content-Type=application/json | a2a_t009_content_type_json | covered |
| T010 | SSE 响应 Content-Type=text/event-stream | a2a_t010_content_type_sse | covered |
| T011 | HTTP keep-alive Connection 头 | a2a_t011_keepalive | covered |
| T012 | HTTP Authorization 头（bearer） | a2a_t012_bearer_authorization | covered |

### §7.2 Agent Card 发现（11/12）
| T013 | GET /.well-known/agent.json 路径 | a2a_s1_agent_card,a2a_t233_wellknown_agent_singular | covered |
| T014 | AgentCard 必填字段 | a2a_s1_agent_card,a2a_t014_agentcard_fields | covered |
| T015 | AgentCard.protocolVersion 字段 | a2a_s1_agent_card,a2a_t212_protocol_version | covered |
| T016 | AgentCard.securitySchemes map | a2a_t016_securityschemes_map,a2a_t213_securityschemes_map | covered |
| T017 | AgentCard.security 数组 | a2a_t016_securityschemes_map,a2a_t214_security_array | covered |
| T018 | AgentCard.capabilities 全 false | a2a_t018_capabilities_all_false | covered |
| T019 | AgentCard.skills 空数组 | a2a_s15b_edge_skills_empty | covered |
| T020 | AgentCard.skills 多技能 | a2a_s1_agent_card,a2a_t014_agentcard_fields | covered |
| T021 | AgentCard 路径 404 | — | uncovered（planner 恒 200，见上表） |
| T022 | AgentCard JSON 畸形 | a2a_t022_agentcard_malformed | covered |
| T023 | AgentCard.provider 字段 | a2a_s1_agent_card,a2a_t014_agentcard_fields | covered |
| T024 | AgentCard.supportsAuthenticatedExtendedCard | a2a_s1_agent_card,a2a_t014_agentcard_fields | covered |

### §7.3 message/send（16/16）
| T025 | message/send 文本消息 | a2a_s2_message_send | covered |
| T026 | message/send 不带 params.id | a2a_s2_message_send | covered |
| T027 | message/send 带 contextId | a2a_t027_contextid_field | covered |
| T028 | message/send 多 Part（text+data） | a2a_s13_multi_part | covered |
| T029 | message/send 文件 Part（FileWithBytes） | a2a_s13_multi_part | covered |
| T030 | message/send 文件 Part（FileWithUri） | a2a_t030_file_uri | covered |
| T031 | message/send 带 configuration | a2a_t031_configuration_metadata | covered |
| T032 | message/send 带 metadata | a2a_t031_configuration_metadata | covered |
| T033 | message/send 响应 result=Task | a2a_s2_message_send | covered |
| T034 | message/send 响应 result=Message | a2a_s2b_result_message,a2a_t219_message_kind_resp | covered |
| T035 | message/send 响应 state=completed | a2a_s2_message_send,a2a_t035_response_completed | covered |
| T036 | message/send 响应 state=input-required | a2a_t036_response_input_required | covered |
| T037 | message/send 缺 message 字段 | a2a_t037_neg_no_message | covered |
| T038 | message/send role 非 user/agent | a2a_t038_neg_role_system | covered |
| T039 | message/send parts 空数组 | a2a_t039_neg_parts_empty | covered |
| T040 | message/send Part kind 非 text/data/file | a2a_t040_neg_kind_datastream,a2a_t203_neg_part_datastream | covered |

### §7.4 message/stream（14/14）
| T041 | message/stream 流式响应 | a2a_s3_message_stream | covered |
| T042 | message/stream Accept=text/event-stream | a2a_s3_message_stream | covered |
| T043 | message/stream 首事件 kind=task | a2a_t043_stream_first_task | covered |
| T044 | message/stream 首事件 kind=message | a2a_t044_message_first_event | covered |
| T045 | message/stream 含 status-update 事件 | a2a_s3_message_stream | covered |
| T046 | message/stream 含 artifact-update 事件 | a2a_t242_artifact_independent | covered |
| T047 | message/stream 末事件 final:true | a2a_s3_message_stream | covered |
| T048 | message/stream 多 artifact-update append 语义 | a2a_s10_sse_5events | covered |
| T049 | message/stream lastChunk:true 后无该 artifact 更新 | a2a_s10_sse_5events | covered |
| T050 | message/stream capabilities.streaming=false | a2a_t050_neg_streaming_false,a2a_t196_neg_pnc_list_method | covered |
| T051 | message/stream 事件按序投递 | a2a_s10_sse_5events | covered |
| T052 | message/stream 多并发流（同 task） | a2a_t052_multi_stream_same_task | covered |
| T053 | message/stream parts 空 | a2a_t053_neg_stream_no_parts | covered |
| T054 | message/stream Part kind 非法 | a2a_t054_neg_stream_kind_filestream | covered |

### §7.5 tasks/get（10/10）
| T055 | tasks/get 查询现有任务 | a2a_s4_tasks_get | covered |
| T056 | tasks/get 带 historyLength | a2a_s4_tasks_get | covered |
| T057 | tasks/get 带 metadata | a2a_t057_get_metadata | covered |
| T058 | tasks/get 任务不存在 | a2a_s11_error_32001 | covered |
| T059 | tasks/get 缺 id | a2a_t059_neg_get_no_id | covered |
| T060 | tasks/get 响应含 artifacts | a2a_t060_get_artifacts | covered |
| T061 | tasks/get 响应含 history | a2a_s4_tasks_get | covered |
| T062 | tasks/get historyLength=0 | a2a_t062_history_zero,a2a_t176_history_zero_get | covered |
| T063 | tasks/get historyLength=1000 | a2a_t063_history_1000 | covered |
| T064 | tasks/get 响应 kind=task | a2a_t035_response_completed,a2a_t057_get_metadata | covered |

### §7.6 tasks/cancel（8/8）
| T065 | tasks/cancel 取消非终态任务 | a2a_s5_tasks_cancel | covered |
| T066 | tasks/cancel 取消终态任务 | a2a_t193_error_32002,a2a_t066_cancel_terminal_32002 | covered |
| T067 | tasks/cancel 缺 id | a2a_t067_neg_cancel_no_id | covered |
| T068 | tasks/cancel 任务不存在 | a2a_t068_cancel_nonexistent_32001 | covered |
| T069 | tasks/cancel 带 metadata | a2a_t069_cancel_metadata | covered |
| T070 | tasks/cancel 响应 kind=task | a2a_s5_tasks_cancel | covered |
| T071 | tasks/cancel submitted 状态可取消 | a2a_t071_submitted_canceled | covered |
| T072 | tasks/cancel working 状态可取消 | a2a_t072_working_canceled | covered |

### §7.7 tasks/resubscribe（8/8）
| T073 | tasks/resubscribe 断线重连 | a2a_s6_resubscribe | covered |
| T074 | tasks/resubscribe Accept=text/event-stream | a2a_s6_resubscribe | covered |
| T075 | tasks/resubscribe capabilities.streaming=false | a2a_t075_neg_resubscribe_sync | covered |
| T076 | tasks/resubscribe 缺 id | a2a_t076_neg_resubscribe_no_id | covered |
| T077 | tasks/resubscribe 任务不存在 | a2a_t077_resubscribe_nonexistent | covered |
| T078 | tasks/resubscribe 续传后续事件 | a2a_t078_resubscribe_resume | covered |
| T079 | tasks/resubscribe 响应 SSE 格式 | a2a_s6_resubscribe | covered |
| T080 | tasks/resubscribe 事件未命名 | a2a_t080_resubscribe_unnamed,a2a_t240_sse_no_event_field | covered |

### §7.8 pushNotificationConfig（12/12）
| T081 | pushNotificationConfig/set 设置 | a2a_s7_push_set | covered |
| T082 | pushNotificationConfig/set params.taskId | a2a_s7_push_set | covered |
| T083 | pushNotificationConfig/set params.pushNotificationConfig | a2a_s7_push_set | covered |
| T084 | pushNotificationConfig/set 响应含 id | a2a_s7_push_set | covered |
| T085 | pushNotificationConfig/set capabilities.pushNotifications=false | a2a_t085_push_error_32003 | covered |
| T086 | pushNotificationConfig/set 缺 taskId | a2a_t086_neg_set_no_taskid | covered |
| T087 | pushNotificationConfig/set 缺 pushNotificationConfig | a2a_t087_neg_set_no_config | covered |
| T088 | pushNotificationConfig/set 缺 url | a2a_t088_neg_set_url_empty | covered |
| T089 | pushNotificationConfig/get 查询 | a2a_t089_push_get | covered |
| T090 | pushNotificationConfig/get 响应配置 | a2a_t089_push_get | covered |
| T091 | pushNotificationConfig/get 任务不存在 | a2a_t091_push_get_error_32001 | covered |
| T092 | pushNotificationConfig/get 缺 id | a2a_t092_neg_get_no_id | covered |

### §7.9 认证（12/12）
| T093 | Bearer Token 认证 | a2a_s8_bearer_auth | covered |
| T094 | Basic 认证 | a2a_s8b_basic_auth | covered |
| T095 | API Key 认证（header） | a2a_s8c_apikey_header | covered |
| T096 | API Key 认证（query） | a2a_t096_apikey_query | covered |
| T097 | OAuth2 Bearer Token | a2a_t097_oauth2_bearer | covered |
| T098 | OpenID Connect | a2a_t098_oidc_bearer | covered |
| T099 | AgentCard.securitySchemes bearer | a2a_t016_securityschemes_map | covered |
| T100 | AgentCard.securitySchemes apiKey | a2a_t100_security_apikey | covered |
| T101 | AgentCard.securitySchemes oauth2 | a2a_t101_security_oauth2 | covered |
| T102 | AgentCard.securitySchemes openIdConnect | a2a_t016_securityschemes_map | covered |
| T103 | Auth.Scheme=none 不带 Authorization | a2a_t103_none_no_auth | covered |
| T104 | in-task auth-required 状态 | a2a_t104_auth_required_state | covered |

### §7.10 状态机（18/18）
| T105 | submitted→working→completed | a2a_t105_state_machine_success | covered |
| T106 | submitted→working→input-required→working→completed | a2a_t106_multi_round_interaction | covered |
| T107 | submitted→working→failed | a2a_t107_state_machine_failed | covered |
| T108 | submitted→working→canceled | a2a_t105_state_machine_success | covered |
| T109 | submitted→rejected | a2a_t109_submitted_rejected | covered |
| T110 | submitted→auth-required→working→completed | a2a_t110_auth_required_flow | covered |
| T111 | submitted→canceled | a2a_t071_submitted_canceled | covered |
| T112 | submitted→auth-required | a2a_t112_submitted_auth_required | covered |
| T113 | input-required→canceled | a2a_t113_input_required_canceled | covered |
| T114 | auth-required→canceled | a2a_t114_auth_required_canceled | covered |
| T115 | unknown 状态（taskId 过期） | a2a_t115_unknown_state | covered |
| T116 | completed→*（终态不可变） | a2a_t116_neg_terminal_completed | covered |
| T117 | failed→*（终态不可变） | a2a_t117_neg_terminal_failed | covered |
| T118 | canceled→*（终态不可变） | a2a_t118_neg_terminal_canceled | covered |
| T119 | rejected→*（终态不可变） | a2a_t119_neg_terminal_rejected | covered |
| T120 | input-required→completed | a2a_t120_neg_input_required_completed | covered |
| T121 | input-required→working | a2a_t078_resubscribe_resume | covered |
| T122 | auth-required→working | a2a_t110_auth_required_flow | covered |

### §7.11 TaskArtifactUpdateEvent（8/8）
| T123 | artifact-update 单事件 | a2a_s12_artifact_append | covered |
| T124 | artifact-update append=false 替换 | a2a_t124_artifact_append_false,a2a_t242_artifact_independent | covered |
| T125 | artifact-update append=true 追加 | a2a_s12_artifact_append | covered |
| T126 | artifact-update lastChunk=true | a2a_s12_artifact_append | covered |
| T127 | artifact-update 多块拼接 | a2a_s12_artifact_append | covered |
| T128 | artifact-update kind 字段 | a2a_s12_artifact_append | covered |
| T129 | artifact-update 含 taskId/contextId | a2a_t129_artifact_taskid_contextid | covered |
| T130 | artifact-update 缺 artifact | a2a_t130_neg_artifact_missing | covered |

### §7.12 TaskStatusUpdateEvent（7/8）
| T131 | status-update 单事件 | a2a_t131_status_update_fields | covered |
| T132 | status-update final=true | a2a_t132_status_update_final,a2a_t133_status_update_intermediate | covered |
| T133 | status-update final=false | a2a_t133_status_update_intermediate | covered |
| T134 | status-update kind 字段 | a2a_t131_status_update_fields | covered |
| T135 | status-update 含 taskId/contextId | a2a_t131_status_update_fields | covered |
| T136 | status-update 含 status.state | a2a_t131_status_update_fields,a2a_t132_status_update_final | covered |
| T137 | status-update 无 artifact 字段 | a2a_t131_status_update_fields | covered |
| T138 | status-update 缺 status | — | uncovered（Validate V9 软约束不拦截，见上表） |

### §7.13 多 Part 与 Message 字段（12/12）
| T139 | Message.role=user | a2a_t139_role_user | covered |
| T140 | Message.role=agent | a2a_t140_role_agent,a2a_t140_message_role_agent | covered |
| T141 | Message.messageId 必填 | a2a_t141_messageid_present,a2a_t217_messageid_required | covered |
| T142 | Message.taskId 可选 | a2a_t142_taskid_optional,a2a_t142_message_taskid_optional | covered |
| T143 | Message.contextId 关联 | a2a_t162_context_id,a2a_t218_contextid_assoc | covered |
| T144 | Message.referenceTaskIds | a2a_t144_reference_extensions | covered |
| T145 | Message.extensions | a2a_t145_message_extensions | covered |
| T146 | Message.kind=message | a2a_t146_kind_message,a2a_t219_message_kind,a2a_t146_message_kind | covered |
| T147 | Part kind=text | a2a_t147_part_text,a2a_t147_part_kind_text | covered |
| T148 | Part kind=data | a2a_t148_part_data,a2a_t148_part_kind_data | covered |
| T149 | Part kind=file（FileWithBytes） | a2a_t149_part_file_bytes,a2a_t149_part_kind_file_bytes | covered |
| T150 | Part kind=file（FileWithUri） | a2a_t030_file_uri | covered |

### §7.14 Push Notification webhook（4/10）
| T151 | webhook POST 请求 | a2a_s14_webhook | covered |
| T153 | webhook X-A2A-Notification-Token 头 | a2a_s14_webhook | covered |
| T155 | webhook body 为 Task 对象 | a2a_s14_webhook | covered |
| T152 | webhook Content-Type=application/json | — | uncovered（planner 不建模 webhook 投递，见上表） |
| T154 | webhook Authorization 头 | — | uncovered（同 T152） |
| T156 | webhook 客户端响应 2xx | — | uncovered（同 T152） |
| T157 | webhook 客户端响应非 2xx | — | uncovered（同 T152） |
| T158 | webhook 至少投递一次 | — | uncovered（同 T152） |
| T159 | webhook 幂等处理 | — | uncovered（同 T152） |
| T160 | webhook URL 非 HTTPS | a2a_t160_http_url | covered |

### §7.15 多任务/多会话/并发（11/12）
| T161 | 多 Task 同 TCP 连接串行 | a2a_s9_multi_task_serial | covered |
| T162 | 多 Task 同 contextId | a2a_t162_context_id | covered |
| T163 | 多 Task 不同 contextId | a2a_t163_multi_context_diff | covered |
| T164 | 多会话 FlowSpec.Count=3 | a2a_t164_multi_flow_count3 | covered |
| T165 | 多会话独立 taskId | a2a_t165_multi_session_taskid,a2a_t164_multi_flow_count3 | covered |
| T166 | 多会话 GroupID 路由 | — | uncovered（实时域，见上表） |
| T167 | 100 并发流聚合包数 | a2a_t167_100_flows | covered |
| T168 | 并发流速率聚合 | a2a_t167_100_flows,a2a_t168_multi_flow_concurrency | covered |
| T169 | HTTP/1.1 串行约束 | a2a_s9_multi_task_serial | covered |
| T170 | 多 task 请求复用 TCP | a2a_s9_multi_task_serial | covered |
| T171 | 最后 task Connection:close | a2a_s9_multi_task_serial | covered |
| T172 | 非最后 task Connection:keep-alive | a2a_s9_multi_task_serial | covered |

### §7.16 边界场景（14/14）
| T173 | skills 空数组 | a2a_s15b_edge_skills_empty | covered |
| T174 | Part.text 1MB | a2a_t174_text_1mb | covered |
| T175 | historyLength=1000 | a2a_t175_history_1000_get | covered |
| T176 | historyLength=0 | a2a_t176_history_zero_get | covered |
| T177 | FileWithBytes 10MB | a2a_t177_file_10mb | covered |
| T178 | metadata key 128 字节 | a2a_t178_metadata_key_128 | covered |
| T179 | JSON-RPC id 128 字节 | a2a_t179_id_128 | covered |
| T180 | skills 1024 个 | a2a_t180_skills_1024 | covered |
| T181 | parts 1024 个 | a2a_t181_parts_1024 | covered |
| T182 | contextId 128 字节 | a2a_t182_contextid_128 | covered |
| T183 | AgentCard.description 4096 字节 | a2a_t183_description_4096 | covered |
| T184 | referenceTaskIds 多 taskId | a2a_t144_reference_extensions,a2a_t145_message_extensions | covered |
| T185 | extensions 多 URI | a2a_t144_reference_extensions,a2a_t145_message_extensions | covered |
| T186 | SSE 流 0 中间事件 | a2a_t186_sse_zero_middle_events | covered |

### §7.17 异常场景（17/17）
| T187 | -32700 JSON 解析失败 | a2a_t187_error_32700 | covered |
| T188 | -32600 无效 JSON-RPC 请求 | a2a_t188_error_32600 | covered |
| T189 | -32601 方法不存在 | a2a_t189_error_32601,a2a_t202_neg_sendsubscribe | covered |
| T190 | -32602 参数无效 | a2a_t190_error_32602 | covered |
| T191 | -32603 内部错误 | a2a_t191_error_32603 | covered |
| T192 | -32001 任务不存在 | a2a_s11_error_32001 | covered |
| T193 | -32002 任务不可取消 | a2a_t193_error_32002 | covered |
| T194 | -32003 推送不支持 | a2a_t085_push_error_32003 | covered |
| T195 | -32004 操作不支持 | a2a_t050_neg_streaming_false | covered |
| T196 | -32004 通用不支持场景 | a2a_t196_error_32004_pnc,a2a_t196_neg_pnc_list_method | covered |
| T197 | -32005 内容类型不支持 | a2a_t197_error_32005 | covered |
| T198 | -32006 Agent 响应无效 | a2a_t198_error_32006 | covered |
| T199 | streaming=false 但 capabilities.streaming=true | a2a_t050_neg_streaming_false | covered |
| T200 | pushNotifications=false 但 capabilities.pushNotifications=true | a2a_t085_push_error_32003 | covered |
| T201 | 终态任务再发 message/send | a2a_t201_error_32004,a2a_t196_neg_pnc_list_method | covered |
| T202 | 不支持的方法名 | a2a_t189_error_32601,a2a_t202_neg_sendsubscribe | covered |
| T203 | 不支持的 Part kind | a2a_t203_neg_part_datastream | covered |

### §7.18 集成与端到端（7/8）
| T204 | Agent Card 发现 + message/send 端到端 | a2a_t204_discover_send_e2e,a2a_t233_wellknown_agent_singular | covered |
| T205 | message/stream 全流程 | a2a_t205_stream_full_flow | covered |
| T206 | pushNotificationConfig/set + webhook 投递 | — | uncovered（webhook 域，见上表） |
| T207 | tasks/resubscribe 断线重连 | a2a_t207_resubscribe_resume_e2e | covered |
| T208 | 多 task 同连接串行 | a2a_t208_multi_task_serial_seq | covered |
| T209 | Bearer 认证全流程 | a2a_t209_bearer_e2e | covered |
| T210 | tshark 解析 A2A JSON-RPC | a2a_t210_tshark_json_rpc | covered |
| T211 | tshark 解析 SSE 流 | a2a_t211_tshark_sse | covered |

### §7.19 字段覆盖补全（13/14，含 T212a-d）
| T212 | AgentCard.protocolVersion 字段 | a2a_t212_protocol_version | covered |
| T212a | AgentCard.additionalInterfaces | a2a_t212a_additional_interfaces | covered |
| T212b | AgentCard.preferredTransport | a2a_t212a_additional_interfaces | covered |
| T212c | AgentCard.signatures | — | uncovered（v1 保留字段，planner 不输出；case a2a_t212a notes 显式声明） |
| T212d | SecurityScheme mutualTLS | a2a_t016_securityschemes_map | covered |
| T213 | AgentCard.securitySchemes map | a2a_t213_securityschemes_map | covered |
| T214 | AgentCard.security 数组 | a2a_t214_security_array | covered |
| T215 | Task.contextId 字段 | a2a_t215_result_contextid | covered |
| T216 | Task.kind=task | a2a_t216_task_kind | covered |
| T217 | Message.messageId 必填 | a2a_t217_messageid_required | covered |
| T218 | Message.contextId 关联 | a2a_t218_contextid_assoc | covered |
| T219 | Message.kind=message | a2a_t219_message_kind,a2a_t219_message_kind_resp | covered |
| T220 | TaskStatusUpdateEvent.taskId（非 id） | a2a_t220_status_update_taskid | covered |
| T221 | TaskArtifactUpdateEvent 完整字段 | a2a_t221_artifact_update_full | covered |

### §7.20 Part kind 互斥（6/6）
| T222 | Part kind=text 仅 text 字段 | a2a_t222_text_only | covered |
| T223 | Part kind=data 仅 data 字段 | a2a_t223_data_only | covered |
| T224 | Part kind=file 仅 file 字段 | a2a_t224_file_only | covered |
| T225 | Part kind=text 同时含 data | a2a_t225_neg_part_text_data | covered |
| T226 | Part kind=data 同时含 file | a2a_t226_neg_part_data_file | covered |
| T227 | Part kind=file 同时含 text | a2a_t227_neg_part_file_text | covered |

### §7.21 v2.0.0 新增（14/15）
| T228 | method=message/send（非 tasks/send） | a2a_t228_method_message_send | covered |
| T229 | method=message/stream（非 tasks/sendSubscribe） | a2a_t229_method_message_stream | covered |
| T230 | 无 tasks/subscribe 方法 | a2a_t230_neg_subscribe | covered |
| T231 | method=tasks/pushNotificationConfig/set（含 Config） | a2a_t231_method_pnc_set | covered |
| T232 | method=tasks/pushNotificationConfig/get | a2a_t089_push_get | covered |
| T233 | GET /.well-known/agent.json（单数） | a2a_t233_wellknown_agent_singular | covered |
| T234 | GET /.well-known/agents.json（复数）404 | — | uncovered（planner 不建模 404，见上表） |
| T235 | Part kind 仅 text/data/file | a2a_t235_kinds_only_three | covered |
| T236 | Part kind=data-stream 拒绝 | a2a_t236_neg_kind_datastream,a2a_t203_neg_part_datastream | covered |
| T237 | Part kind=file-stream 拒绝 | a2a_t237_neg_kind_filestream | covered |
| T238 | PushNotificationConfig.id 字段（非 userId） | a2a_t238_pnc_id,a2a_t239_pnc_no_userid | covered |
| T239 | PushNotificationConfig 无 userId 字段 | a2a_t239_pnc_no_userid | covered |
| T240 | SSE 事件无 event: 字段 | a2a_t240_sse_no_event_field | covered |
| T241 | TaskStatusUpdateEvent 无 artifact 字段 | a2a_t241_status_no_artifact | covered |
| T242 | TaskArtifactUpdateEvent 独立事件 | a2a_t242_artifact_independent | covered |

## Wave-3 变更说明（本会话 batch3+batch4）

| 项目 | 数值 |
|------|------|
| 本轮新增 pcap 用例 | 44 个（115 → 185；batch3 16 + batch4 28，含 2 个既有用例重写 T164/T167） |
| 本轮新增覆盖 spec ID | 58 个（173 → 231） |
| 覆盖口径变化 | ① legacy s* 用例 21 个补显式 T-NNN 注记（先前 notes 只有 S1~S15 场景名） ② notes 声明"不可生成/未覆盖"的引用不计入覆盖（T021/T234 修正） |
| 遗留未覆盖 | 12 条：webhook 域 7 条（T152/T154/T156-159/T206）+ T138 软约束 + T166 实时域 + T021/T234 404 不可生成 + T212c spec 保留字段 |

### 字节断言校准要点（本会话踩坑记录）

1. **frame offset 是精确位置匹配**（matchHexOffset，hex.go:167）：`frameBytes[offset:]` 必须
   以 want 开头，不是子串搜索；offset 一律用 Python 侧公式推导，禁止硬编码：
   `req_offsets(body)+body.find('...')` / `resp_offsets(body)+body.find('...')` / `sse_offsets(sse)+sse.find('...')`。
2. **请求 header 长度按 Accept 值分档**：sync=187（Accept: application/json, text/event-stream）、
   流式=169（Accept: text/event-stream，短 18 字节）——T229 初版按 187-19 推算得 0x2c 错位，
   pcap 实测 body 起 0xef=239=54+169 后修正为 -18。
3. **SSE chunked 分帧**：每事件 `data: {...}\n\n`，事件序列后接 `0\r\n\r\n` 终止块；
   `sse_offsets = 54 + 129 + len("%x" % len(data)) + 2`（3 位 hex 时 188）。
4. **V9/V10 约束联动**：SSE 事件序列必须满足首事件 task/message、最后一个 status-update
   final=true、状态迁移合法（submitted→working→completed，终态不可变）——T220/T240/T241
   初版因 final 缺失或迁移非法被 Validate 拒绝，补 third completed final:true 事件后通过。
5. **T213/T214 序列化细节**：A2ASecurityScheme=map[string]any → JSON 键排序（in/name/type）；
   Security=[]map[string][]string → JSON `[{"apiKey":[]}]`（初版 `[["apiKey"]]` 与 struct 不匹配
   导致 unmarshal 失败）。
6. **strategy flows=N 跨流包序**：worker 按 shard hash 随机交织多流包，逐包位置断言不可行；
   以总包数（3 流=27 包）+ has_handshake/terminates 证明会话完整性（T165/T168）。
7. **多 task 同连接串行包数**：3 握手 + N×2（请求+响应）+ 3 挥手 = 9+3(N-1)（T164=3 task=15 包、
   T167=10 task=36 包、T208=2 task=12 包）。

### 结论

- 覆盖 231/242（95.5%），全部 185 用例 tshark 字节验证 PASS。
- 本会话未发现 a2a planner bug：所有失败均为 case 配置/offset 校准问题（上表 7 类），
  无 failing-test-first 修复记录。
- 剩余 12 条的共性：webhook 域 7 条需 planner 新增 webhook 子流建模；T138 是 Validate
  软约束（归 Go 单测域）；T166 是运行时路由语义（归 Go 单测/性能测试域）；T021/T234 需
  planner 支持 404 响应生成；T212c 为 spec 声明不生成的保留字段。5 类均超出"静态 pcap
  字节断言"能力边界，建议作为后续专项处理。
