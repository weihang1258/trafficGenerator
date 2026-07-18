# flowB MCP 测试场景矩阵

本文档按"工具 × 动作 × 场景"列出 MCP 的全量测试用例矩阵，标注现有覆盖与缺口。

> 测试位于 `trafficgen/internal/mcp/*_test.go`。所有测试均开启 `-race`。

---

## 1. 传输层（Transport）

| 场景                                | 测试名                                       | 状态 |
|-------------------------------------|----------------------------------------------|------|
| 构造校验：empty listen              | `TestHTTPServer_ConstructorValidation`       | ✅   |
| 构造校验：empty api_key             | `TestHTTPServer_ConstructorValidation`       | ✅   |
| API key 缺失 -> 401                 | `TestAPIKeyMiddleware_MissingKey`            | ✅   |
| API key 错误 -> 401                 | `TestAPIKeyMiddleware_WrongKey`              | ✅   |
| API key 正确 -> 200                 | `TestAPIKeyMiddleware_ValidKey`              | ✅   |
| API key 时序安全（短/长 wrong key） | `TestAPIKeyMiddleware_TimingSafe`            | ✅   |
| HTTP 协议流（initialize+list+call） | `TestHTTPServer_ProtocolFlow`                | ✅   |
| HTTP 缺 key -> connect 失败 401     | `TestHTTPServer_ProtocolFlow_MissingKey`     | ✅   |
| 原始 initialize 请求（SSE 解析）    | `TestHTTPServer_RawInitialize`               | ✅   |
| **CORS preflight 无 API key**       | `TestHTTPServer_CORS_PreflightWithoutAPIKey` | ✅   |
| CORS 允许的 Origin                  | `TestCORSMiddleware_PreflightAllowedOrigin`  | ✅   |
| CORS 阻止的 Origin                  | `TestCORSMiddleware_BlockedOrigin`           | ✅   |
| CORS 通配符 `*`                     | `TestCORSMiddleware_Wildcard`                | ✅   |

**缺口**：
- ❌ CORS `Vary: Origin` 头（性能/缓存正确性）
- ❌ CORS `Access-Control-Max-Age` 缓存
- ❌ CORS `Access-Control-Expose-Headers: Mcp-Session-Id`
- ❌ 会话超时（30min idle -> 自动清理）
- ❌ 并发 initialize（多个 session 同时建立）
- ❌ Session-id 重用（已关闭 session 的 id 被拒绝）

---

## 2. 系统查询（`flowb_query_system`）

| action               | 测试                              | 状态 |
|----------------------|-----------------------------------|------|
| status               | `TestMCP_QuerySystem_Status`      | ✅   |
| protocols            | `TestMCP_QuerySystem_Protocols`   | ✅   |
| stats                | `TestMCP_QuerySystem_Stats`       | ✅   |
| health               | `TestMCP_QuerySystem_Health`      | ✅   |
| ready                | `TestMCP_QuerySystem_Ready`       | ✅   |
| interfaces           | `TestMCP_QuerySystem_Interfaces`  | ✅   |
| ports                | `TestMCP_QuerySystem_Ports`       | ✅   |
| refresh_interfaces   | -                                 | ❌   |
| invalid action       | `TestMCP_QuerySystem_InvalidAction` | ✅ |

**缺口**：refresh_interfaces

---

## 3. 策略管理（`flowb_manage_strategies`）

| action     | 测试                                  | 状态 |
|------------|---------------------------------------|------|
| create     | `TestMCP_ManageStrategies_CreateAndList` | ✅   |
| list       | `TestMCP_ManageStrategies_CreateAndList` | ✅   |
| get        | -                                     | ❌   |
| update     | `TestMCP_ManageStrategies_Update`     | ✅   |
| delete     | `TestMCP_ManageStrategies_Delete`     | ✅   |
| list_tasks | `TestMCP_ManageStrategies_ListTasks`  | ✅   |
| invalid    | `TestMCP_ManageStrategies_InvalidAction` | ✅   |

**缺口**：get；幂等 create（重复 name）；update 不存在的 strategy（404）

---

## 4. 用户管理（`flowb_manage_users`）

service account 角色=user，所有 admin-only 动作返回 403。

| action          | 测试                                       | 状态 |
|-----------------|--------------------------------------------|------|
| list            | `TestMCP_ManageUsers_List_ForbiddenInServiceMode` | ✅ |
| get             | `TestMCP_ManageUsers_Get_ForbiddenInServiceMode`  | ✅ |
| update          | -                                          | ❌   |
| delete          | -                                          | ❌   |
| reset_password  | -                                          | ❌   |
| invalid         | `TestMCP_ManageUsers_InvalidAction`        | ✅   |

**缺口**：update/delete/reset_password 的 403 路径（与 list/get 一致，但应显式覆盖）

---

## 5. 认证（`flowb_manage_auth`）

| action    | 测试                                       | 状态 |
|-----------|--------------------------------------------|------|
| register  | `TestMCP_ManageAuth_RegisterAndLogin`      | ✅   |
| login     | `TestMCP_ManageAuth_RegisterAndLogin`      | ✅   |
| login 错密码 | `TestMCP_ManageAuth_LoginWrongPassword` | ✅   |
| validate  | `TestMCP_ManageAuth_ValidateToken`         | ✅   |
| validate 空 | `TestMCP_ManageAuth_ValidateToken_Empty` | ✅   |
| validate 无效 | `TestMCP_ManageAuth_ValidateToken_Invalid` | ✅ |
| logout    | `TestMCP_ManageAuth_Logout`                | ✅   |
| refresh   | -                                          | ❌   |
| invalid   | `TestMCP_ManageAuth_InvalidAction`         | ✅   |

**缺口**：refresh

---

## 6. 个人资料（`flowb_manage_profile`）

| action  | 测试                                  | 状态 |
|---------|---------------------------------------|------|
| get     | `TestMCP_ManageProfile_Get`           | ✅   |
| update  | `TestMCP_ManageProfile_UpdateEmail`   | ✅   |
| delete  | -                                     | ❌   |
| invalid | `TestMCP_ManageProfile_InvalidAction` | ✅   |

**缺口**：delete（需先 create 一个可删的 service account 副本）

---

## 7. PCAP 资产（`flowb_manage_pcaps`，17 actions）

| action                  | 测试                                          | 状态 |
|-------------------------|-----------------------------------------------|------|
| import                  | `TestMCP_ManagePcaps_ImportAndList`           | ✅   |
| import 缺 file_path     | `TestMCP_ManagePcaps_ImportMissingFilePath`   | ✅   |
| **import 路径校验**     | `TestMCP_ManagePcaps_ImportPathValidation`    | ✅   |
| list                    | `TestMCP_ManagePcaps_ImportAndList`           | ✅   |
| get                     | `TestMCP_ManagePcaps_Get`                     | ✅   |
| delete                  | `TestMCP_ManagePcaps_Delete`                  | ✅   |
| list_flows              | `TestMCP_ManagePcaps_ListFlowsAndGetFlow`     | ✅   |
| get_flow                | `TestMCP_ManagePcaps_ListFlowsAndGetFlow`     | ✅   |
| list_packets            | `TestMCP_ManagePcaps_ListPackets`             | ✅   |
| list_packets_by_asset   | `TestMCP_ManagePcaps_ListPacketsByAssetAndGetPacket` | ✅ |
| get_packet              | `TestMCP_ManagePcaps_ListPacketsByAssetAndGetPacket` | ✅ |
| get_packet_payload      | `TestMCP_ManagePcaps_GetPacketPayload`        | ✅   |
| get_stream              | `TestMCP_ManagePcaps_GetStream`               | ✅   |
| **get_stream 空**       | `TestMCP_ManagePcaps_GetStream_Empty`         | ✅   |
| get_body                | `TestMCP_ManagePcaps_GetBody`                 | ✅   |
| **get_body 空**         | `TestMCP_ManagePcaps_GetBody_Empty`           | ✅   |
| search                  | `TestMCP_ManagePcaps_Search`                  | ✅   |
| match_preview           | `TestMCP_ManagePcaps_MatchPreview`            | ✅   |
| extract                 | `TestMCP_ManagePcaps_Extract`                 | ✅   |
| download                | `TestMCP_ManagePcaps_Download`                | ✅   |
| reparse                 | `TestMCP_ManagePcaps_Reparse`                 | ✅   |
| invalid                 | `TestMCP_ManagePcaps_InvalidAction`           | ✅   |
| **缺 id 预校验**        | `TestMCP_ManagePcaps_MissingIDPreValidation`  | ✅   |
| **缺 flow_id 预校验**   | `TestMCP_ManagePcaps_MissingFlowIDPreValidation` | ✅ |
| **缺 packet_id 预校验** | `TestMCP_ManagePcaps_MissingPacketIDPreValidation` | ✅ |

**缺口**：
- get_stream 带 offset/limit 范围读
- get_stream 错误 direction
- search 带 flow_filter + packet_filter
- extract 带多个 fields
- download 不存在的 asset（404）
- reparse 不存在的 asset
- delete 被 task 引用的 asset（force=false 失败 + force=true 成功）

---

## 8. 端口组（`flowb_manage_port_groups`）

| action  | 测试                                  | 状态 |
|---------|---------------------------------------|------|
| create  | `TestMCP_ManagePortGroups_CRUD`       | ✅   |
| list    | `TestMCP_ManagePortGroups_CRUD`       | ✅   |
| get     | `TestMCP_ManagePortGroups_CRUD`       | ✅   |
| delete  | `TestMCP_ManagePortGroups_CRUD`       | ✅   |
| invalid | `TestMCP_ManagePortGroups_InvalidAction` | ✅ |

**缺口**：create 缺 interfaces（参数校验）；get 不存在的 id（404）

---

## 9. 系统设置（`flowb_manage_settings`）

| action         | 测试                                       | 状态 |
|----------------|--------------------------------------------|------|
| get            | `TestMCP_ManageSettings_GetAndUpdate`      | ✅   |
| update         | `TestMCP_ManageSettings_GetAndUpdate`      | ✅   |
| update 无效 log_level | `TestMCP_ManageSettings_InvalidLogLevel` | ✅ |
| invalid        | `TestMCP_ManageSettings_InvalidAction`     | ✅   |

---

## 10. 任务管理（`flowb_manage_tasks`）

| action        | 测试                                  | 状态 |
|---------------|---------------------------------------|------|
| create        | `TestMCP_ManageTasks_CreateAndStart`  | ✅   |
| create_batch  | `TestMCP_ManageTasks_CreateBatch`     | ✅   |
| list          | `TestMCP_ManageTasks_List`            | ✅   |
| get           | (covered via CreateAndStart + StopRunning) | ✅ |
| start         | `TestMCP_ManageTasks_CreateAndStart`  | ✅   |
| stop          | `TestMCP_ManageTasks_StopRunning`     | ✅   |
| stop 非运行中 | `TestMCP_ManageTasks_StopFailsNonRunning` | ✅ |
| delete        | (implicit)                            | ✅   |
| delete 运行中 | `TestMCP_ManageTasks_DeleteFailsRunning` | ✅ |
| history       | `TestMCP_ManageTasks_History`         | ✅   |
| invalid       | `TestMCP_ManageTasks_InvalidAction`   | ✅   |

**缺口**：
- create 不存在的 strategy_id（400）
- create_batch 部分失败
- list 分页（page/size）
- list 状态过滤
- start 已启动任务（幂等/冲突）

---

## 11. 工作流：`flowb_generate_traffic`

| 场景                       | 测试                                          | 状态 |
|----------------------------|-----------------------------------------------|------|
| Happy path                 | `TestMCP_GenerateTraffic_HappyPath`           | ✅   |
| PCAP 副作用（文件生成）   | `TestMCP_GenerateTraffic_PcapSideEffect`      | ✅   |
| 幂等（同 task_name）       | `TestMCP_GenerateTraffic_DuplicateIdempotent` | ✅   |
| Flow control 传递          | `TestMCP_GenerateTraffic_FlowControl`         | ✅   |
| 缺 name -> InvalidParams   | `TestMCP_ErrorMapping_MissingName`            | ✅   |
| 并发生成（多 goroutine）   | `TestMCP_ConcurrentGenerate`                  | ✅   |

**缺口**：
- 协议无效（400）
- output_type 缺失/无效
- output_config.pcap_path 不可写
- port_group_id 不存在
- Step 2 失败（task 创建失败）应返回 strategy_id
- Step 3 失败（start 失败）应返回 task_id+strategy_id+status=created

---

## 12. 工作流：`flowb_get_task_progress`

| 场景              | 测试                                       | 状态 |
|-------------------|--------------------------------------------|------|
| Happy path        | `TestMCP_GetTaskProgress_HappyPath`        | ✅   |
| 缺 task_id        | `TestMCP_GetTaskProgress_MissingTaskID`    | ✅   |
| 不存在的 task_id  | `TestMCP_GetTaskProgress_NotFound`         | ✅   |

---

## 13. 工作流：`flowb_stop_all_tasks`

| 场景                | 测试                                       | 状态 |
|---------------------|--------------------------------------------|------|
| 无运行中任务        | `TestMCP_StopAllTasks_NoRunningTasks`      | ✅   |
| 停止运行中任务      | `TestMCP_StopAllTasks_StopsRunningTask`    | ✅   |

**缺口**：
- 多于 100 个任务（分页回归）
- 部分任务在 list 与 stop 间自然完成（errors 字段）

---

## 14. 工作流：`flowb_wait_for_task`

| 场景              | 测试                                  | 状态 |
|-------------------|---------------------------------------|------|
| 完成（completed） | `TestMCP_WaitForTask_Completes`       | ✅   |
| 缺 task_id        | `TestMCP_WaitForTask_MissingTaskID`   | ✅   |
| 超时              | `TestMCP_WaitForTask_Timeout`         | ✅   |

**缺口**：
- 任务进入 error/failed 状态（terminal 但非 completed）
- context cancel（客户端断连）
- timeout > 300s 被钳制为 300s
- poll_interval < 1s 被钳制为 1s

---

## 15. 工作流：`flowb_replay_pcap`

| 场景                | 测试                                       | 状态 |
|---------------------|--------------------------------------------|------|
| 创建策略+任务       | `TestMCP_ReplayPcap_CreatesStrategyAndTask` | ✅ |
| 缺 pcap_asset_id    | `TestMCP_ReplayPcap_MissingAssetID`        | ✅   |
| 无效 pcap_asset_id  | `TestMCP_ReplayPcap_InvalidAssetID`        | ✅   |

**缺口**：
- speed.mode=multiplier
- speed.mode=bps
- speed.mode=pps（应被拒绝）
- speed.mode=max（应被拒绝）
- direction=dual（缺 interface2）
- flow_scaling

---

## 16. 错误映射

| 场景                      | 测试                                  | 状态 |
|---------------------------|---------------------------------------|------|
| 400 -> InvalidParams      | (multiple)                            | ✅   |
| 404 -> InvalidParams      | `TestMCP_ErrorMapping_NotFound`       | ✅   |
| 409 -> 成功（幂等）       | `TestMCP_GenerateTraffic_DuplicateIdempotent` | ✅ |
| 500 -> InternalError      | (via panic recovery)                  | ✅   |
| handler panic -> 500      | (via callHandler recover)             | ✅   |

---

## 17. 数据隔离

| 场景                                  | 测试                          | 状态 |
|---------------------------------------|-------------------------------|------|
| service account 只看自己的 strategy   | (implicit via isolation)      | ✅   |
| service account 只看自己的 task       | (implicit via isolation)      | ✅   |
| service account 只看自己的 pcap       | (implicit via isolation)      | ✅   |

**缺口**：显式跨用户测试（需要两个 user context）

---

## 18. 并发

| 场景                       | 测试                          | 状态 |
|----------------------------|-------------------------------|------|
| 并发 generate_traffic      | `TestMCP_ConcurrentGenerate`  | ✅   |
| 并发 manage_tasks(start)   | -                             | ❌   |
| 并发 stop_all_tasks        | -                             | ❌   |
| 并发 PCAP import           | -                             | ❌   |

---

## 优先级补全清单

按风险排序：

1. **HIGH**：`flowb_replay_pcap` 的 pps/max 拒绝（审计修复要求）
2. **HIGH**：`flowb_wait_for_task` 的 failed 状态（已有 fix，需测试）
3. **MEDIUM**：`flowb_manage_users` 的 update/delete/reset_password 403 路径
4. **MEDIUM**：`flowb_manage_auth` 的 refresh
5. **MEDIUM**：`flowb_manage_strategies` 的 get
6. **MEDIUM**：`flowb_query_system` 的 refresh_interfaces
7. **LOW**：`flowb_manage_profile` 的 delete
8. **LOW**：CORS Vary/Max-Age/Expose-Headers
9. **LOW**：session timeout/并发 initialize
