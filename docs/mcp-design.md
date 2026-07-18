# MCP 层设计文档（flowB）

> 设计日期：2026-07-16
> 范围：trafficgen 后端 MCP（Model Context Protocol）层 - 产品名 **flowB**
> 状态：设计阶段（待评审）
> 依赖：[后端知识图谱](./backend-knowledge-graph.md)

---

## 目录

1. [设计目标与原则](#1-设计目标与原则)
2. [核心决策](#2-核心决策)
3. [架构设计](#3-架构设计)
4. [工具设计](#4-工具设计)
5. [资源设计](#5-资源设计)
6. [长任务处理](#6-长任务处理)
7. [PCAP 文件处理](#7-pcap-文件处理)
8. [错误处理](#8-错误处理)
9. [配置项](#9-配置项)
10. [安全考虑](#10-安全考虑)
11. [实现计划](#11-实现计划)
12. [开放问题](#12-开放问题)

---

## 1. 设计目标与原则

### 1.1 目标

把 trafficgen 后端的**全部业务能力**（13 个业务域共 58 个功能端点）暴露为 MCP（Model Context Protocol）工具与资源，让大模型（Claude / GPT / 本地 LLM）能直接：

- 创建/修改/删除流量策略与任务
- 上传/查询/下载/抽取 PCAP 资产
- 启动/停止/监控流量生成任务
- 查询系统状态、网络接口、端口、端口组
- 管理系统设置（max_tasks/buffer_size/log_level）
- 认证管理（注册/登录/校验/注销/刷新）
- 用户管理（admin 域：list/get/update/delete/reset_password，受 RBAC 限制）
- 当前用户 profile 自管
- 执行常见工作流（"生成 100 条 TCP 流" / "以 1Gbps 回放这个 pcap"）

**产品名 flowB**：MCP server 在协议握手时声明 `name=flowB`，所有 tool 名以 `flowb_` 前缀，资源 URI 用 `flowb://` scheme，让大模型在多 MCP server 共存时清晰识别来源。

### 1.2 设计原则

- **同进程直调**：MCP server 与 tgserver 同进程，直接 import `internal/*` 包调用业务逻辑，无 HTTP 开销、无认证中间件重复
- **服务账号**：MCP 持有一个配置好的 service account，所有操作以该身份执行，大模型不感知多用户
- **双传输**：stdio 供本地工具（Claude Desktop）使用，HTTP/SSE 供远程客户端使用
- **全功能覆盖 + 域分组**：9 个域分组 tool 覆盖 13 个业务域共 58 个功能端点（含 auth/users/profile/settings），另设 5 个高阶工作流 tool 覆盖常见场景。RBAC 由后端强制，service account role=user 天然限制越权
- **长任务不阻塞**：tool 立即返回 task_id，单独提供等待/查询工具，避免 MCP 调用超时
- **文件走路径不走 base64**：同进程可直接访问文件系统，PCAP 用本地路径引用，避免 base64 膨胀

---

## 2. 核心决策

| 决策点 | 选择 | 理由 |
|---|---|---|
| 部署架构 | 同进程直接调用 | 无 HTTP 开销、类型安全、可复用 engine/db 实例 |
| 传输协议 | stdio + HTTP/SSE 双支持 | stdio 适配 Claude Desktop，HTTP/SSE 适配远程 |
| 认证模型 | service account | 简单、大模型不感知多用户、起步成本低 |
| 工具粒度 | 域分组 + 工作流 | 平衡 LLM 上下文负担与覆盖面 |
| 工具命名 | `flowb_` 前缀 + snake_case | 产品品牌化，多 MCP server 共存可识别 |
| 资源 URI | `flowb://<path>` 单斜杠 | 标准 URI 风格，scheme 标识产品 |
| MCP Go 库 | `modelcontextprotocol/go-sdk` | 官方 SDK，协议合规性强 |
| 全功能覆盖 | 暴露所有后端域（含 auth/users/profile/settings）| 用户明确要求"MCP 必须支持后端的所有功能"；RBAC 由后端强制，service account role=user 天然限制越权 |
| service account 角色 | `user`（自身隔离） | LLM 只能操作 mcp-service 名下数据；admin 域工具（manage_users 等）虽暴露但 RBAC 拒绝，Phase 3 多用户模式解锁 |
| service account 密码 | 默认 `flowb-mcp-change-me` + 允许登录 + 启动 warn | 运维方便检查，warn 提醒修改 |
| HTTP/SSE 认证 | 单 key + 配置文件（`X-MCP-Key`） | 阶段 1 简单，阶段 2 过渡多 key + `Authorization` |
| 审计溯源 | `client_id`（MCP 协议 initialize 自带） | 零成本区分调用来自哪个 LLM 客户端 |

---

## 3. 架构设计

### 3.1 同进程部署

MCP server 作为 tgserver 的可选子模块启动。在 `cmd/server/main.go` 的 `Application` 结构中新增 `mcpServer` 字段，启动流程在 `initServer` 之后增加 `initMCPServer`：

```
main
  -> config.Load
  -> initDatabase
  -> initEngine
  -> initServer (REST)
  -> initMCPServer (新增，若 cfg.MCP.Enabled)
      -> 注册 tools / resources
      -> 启动 stdio listener (goroutine)
      -> 启动 HTTP/SSE listener (goroutine, 若配置)
  -> app.Start
```

MCP server 直接持有 `*core.Engine` / `*storage.DB` / `*netif.Manager` 引用，调用 handler 层的业务逻辑（复用 `internal/api/rest/*_handler.go` 的方法，或抽取共享的 service 层）。

### 3.2 包结构

```
internal/mcp/
├── server.go          # MCP server 初始化、tool/resource 注册
├── transport.go       # stdio / HTTP-SSE 传输抽象
├── tools_strategy.go  # flowb_manage_strategies tool
├── tools_task.go      # flowb_manage_tasks tool
├── tools_pcap.go      # flowb_manage_pcaps tool
├── tools_system.go    # flowb_query_system tool
├── tools_portgroup.go # flowb_manage_port_groups tool
├── tools_settings.go  # flowb_manage_settings tool
├── tools_auth.go      # flowb_manage_auth tool（register/login/validate/logout/refresh）
├── tools_user.go      # flowb_manage_users tool（admin 域：list/get/update/delete/reset_password）
├── tools_profile.go   # flowb_manage_profile tool（当前用户自管：get/update/delete）
├── tools_workflow.go  # 高阶工作流 tools（generate/replay/wait/progress/stop_all）
├── resources.go       # MCP resource 定义
├── errors.go          # 错误映射
└── context.go         # service account context 构造 + callHandler（含 headers 扩展支持 auth token）
```

**全功能覆盖原则**：后端 13 个业务域（auth/profile/users/strategies/tasks/port-groups/ports/interfaces/system/settings/pcaps/history/health）全部有对应 MCP 工具或 action。`tools_auth.go` / `tools_user.go` / `tools_profile.go` / `tools_settings.go` 是新增文件，覆盖原设计遗漏的 15 个端点（auth 5 + profile 3 + users 5 + settings 2）。

### 3.3 service account 机制（阶段 1）

**阶段 1（MVP，当前）**：service account 模式。MCP server 持有一个配置好的非人类账号，所有 LLM 调用以该身份执行，LLM 不感知用户体系。

- 配置文件新增 `mcp.service_user_id`（默认 `mcp-service`）
- **角色**：`user`（自身隔离），LLM 只能操作 mcp-service 名下数据
- **密码**：默认 `flowb-mcp-change-me`，允许前端登录（运维检查用），启动时 warn 提醒修改
- 启动时校验该用户存在且 `Enabled=true`，**不存在则拒绝启动**（不自动创建，避免日志记录密码等不安全实践）
- 构造 `gin.Context` 等价的内部 context，写入 `userID` / `username` / `roles`，复用 `auth.GetUserID(c)` 等 helper
- 所有 MCP tool 调用业务逻辑时注入该 context

**LLM 调用 MCP 的认证方式**：
- **stdio 传输**：不认证（本地进程信任）。LLM（Claude Desktop）启动 MCP server 子进程，直接通信。
- **HTTP/SSE 传输**：`X-MCP-Key` header 与配置的 `mcp.api_key` 比对（单 key，所有客户端共用）。验证通过后仍用 service account 身份执行。

**局限**：所有数据归 service account，无法区分真实用户。阶段 2 有页面后需过渡到多用户认证，见 §12.1。

**RBAC 行为（关键）**：service account 角色 `user`，后端 `auth.AuthMiddlewareWithDB` + `UserHandler` 内置 admin 校验依然生效。这意味着：

- ✅ **可用工具**：`flowb_manage_strategies` / `flowb_manage_tasks` / `flowb_manage_pcaps` / `flowb_manage_port_groups` / `flowb_query_system` / `flowb_manage_settings` / `flowb_manage_profile` / `flowb_manage_auth(register/login/validate/logout/refresh)` / 5 个工作流 tool —— 均操作 service account 自身数据或公开端点
- ⚠️ **受限工具**：`flowb_manage_users(action=list/get/update/delete/reset_password)` —— 后端 `UserHandler` 强制 admin 角色，service account role=user 调用时返回 403。工具仍注册，便于 Phase 3 多用户模式（API key 映射真实 admin 用户）时直接可用
- ⚠️ **受限 action**：`flowb_manage_auth(action=register)` —— 若后端开启公开注册则可用；否则受 admin 限制

**设计意图**：暴露所有工具是为了"接口完整性"，实际可用性由后端 RBAC 决定。Phase 1 service account 模式下 admin 工具返回 403 是预期行为；Phase 3 多用户认证后，admin 用户的 API key 调用这些工具即可正常工作。

```go
// internal/mcp/context.go
func (s *Server) newServiceContext() *gin.Context {
    c, _ := gin.CreateTestContext(nil)
    c.Set("userID", s.serviceUserID)
    c.Set("username", s.serviceUsername)
    c.Set("roles", []string{"user"})  // service account 角色 user，自身隔离
    return c
}

// callHandlerWithHeaders 用于 auth 域工具（需传 Authorization header）
func (s *Server) callHandlerWithHeaders(ctx context.Context, body []byte, id string, query url.Values, headers map[string]string, handler func(*gin.Context)) (*backendResponse, error) {
    // 同 callHandler，但允许覆盖 Authorization 等头（auth 工具需要）
}
```

### 3.4 传输层

**stdio**：
- 标准输入输出通信，适配 Claude Desktop / Cursor
- 启动方式：`tgserver mcp --transport stdio`
- MCP 库：`github.com/modelcontextprotocol/go-sdk`（官方 SDK）

**HTTP/SSE**：
- 监听独立端口（默认 `127.0.0.1:8081`），与 REST API `:8080` 分离，默认绑回环地址
- 端点：`POST /mcp`（工具调用）、`GET /sse`（SSE 订阅）
- 适配远程客户端、多客户端共享
- 启动方式：配置 `mcp.http_listen = "127.0.0.1:8081"`

**抽象层**（transport.go）：
```go
type Transport interface {
    Start(ctx context.Context) error
    Stop() error
}
```

stdio 和 HTTP/SSE 各实现一个，server.go 根据 config 选择启动哪些。

---

## 4. 工具设计

### 4.1 命名规范

- **产品前缀**：所有 tool 名以 `flowb_` 开头，让大模型在多 MCP server 共存时识别来源
- **域分组工具**：`flowb_manage_<domain>` / `flowb_query_<domain>`，用 `action` 参数区分操作
- **工作流工具**：动词短语，如 `flowb_generate_traffic` / `flowb_replay_pcap`
- **参数**：snake_case
- **返回**：结构化 JSON（成功）或 MCP error（失败）

### 4.1.1 JSON Schema 规范

每个 tool 在注册时必须给出完整的 `inputSchema`（JSON Schema draft-07），MCP 协议要求。设计文档中的 JSON 示例仅为示意，实现时按下列原则转 Schema：

- 所有可选字段标 `required: false` 并给默认值
- `action` 字段用 `enum` 限定取值
- `config` / `batch` 等开放字段按协议分 oneOf 子 schema
- 引用知识图谱 §3 的数据模型字段类型

### 4.2 域分组工具（5 个）

#### 4.2.1 `flowb_manage_strategies`

**参数**：
```json
{
  "action": "create|list|get|update|delete|list_tasks",
  "id": "strategy-id",           // get/update/delete/list_tasks 必填
  "name": "策略名",               // create/update
  "mode": "synth|replay",        // create/update，默认 synth
  "protocol": "tcp|udp|...",     // synth 必填
  "config": { ... },             // create/update 必填
  "flow_control": {              // 可选
    "type": "flows|bps|time",
    "value": 100
  },
  "page": 1, "size": 20          // list
}
```

**映射**：
- create -> `StrategyHandler.Create`
- list -> `StrategyHandler.List`
- get -> `StrategyHandler.Get`
- update -> `StrategyHandler.Update`
- delete -> `StrategyHandler.Delete`
- list_tasks -> `StrategyHandler.ListTasks`

#### 4.2.2 `flowb_manage_tasks`

**参数**：
```json
{
  "action": "create|create_batch|list|get|start|stop|delete|history",
  "id": "task-id",               // get/start/stop/delete 必填
  "name": "任务名",
  "strategy_ids": ["id1"],       // create
  "batch": {                     // create_batch
    "classes": [
      {
        "id": "class-1",
        "type": "tcp|udp|...|replay",
        "flow_count": 100,
        "config": { ... },       // 非 replay 类必填
        "replay": { ... },       // type=replay 必填（见 §4.3.2 replay_pcap 的 replay 字段）
        "bps": "200k"            // 可选，类级限速
      }
    ],
    "flows": {"count": 100}      // 可选
  },
  "output_type": "port_group|pcap",
  "output_config": {
    "port_group_id": "...",
    "pcap_path": "...",
    "interface2": "..."
  },
  "flow_control": { "type": "...", "value": ... },
  "status": "running|completed", // list 过滤
  "page": 1, "size": 20
}
```

**映射**：对应 `TaskHandler` 的 8 个方法。

#### 4.2.3 `flowb_manage_pcaps`

PCAP 资产域全功能覆盖（17 个 action 对应后端 17 个端点）。

**参数**：
```json
{
  "action": "import|list|get|delete|list_flows|get_flow|list_packets|list_packets_by_asset|get_packet|get_packet_payload|get_stream|get_body|search|match_preview|extract|download|reparse",
  "id": "asset-id",                       // 除 import/list 外必填
  "file_path": "/path/to/file.pcap",      // import：本地路径
  "flow_id": "...",                       // get_flow/list_packets/get_stream/get_body
  "packet_id": "...",                     // get_packet/get_packet_payload
  "direction": "client|server",           // get_stream/get_body（流方向）
  "offset": 0, "length": 0,               // get_stream/get_body（字节范围，可选）
  "filters": { ... },                     // search/match_preview/extract
  "extract_rules": [ ... ],               // extract：抽取规则
  "force": false,                         // delete：强制删除（即使有任务引用）
  "page": 1, "size": 50                   // list/list_flows/list_packets 分页
}
```

**action 全清单（17 个，按语义分组）**：

| 分组 | action | 映射端点 | 说明 |
|------|--------|---------|------|
| 导入 | `import` | POST /pcaps | 本地路径导入，绕过 multipart |
| 重解析 | `reparse` | POST /pcaps/:id/reparse | 重新解析已有资产 |
| 列表 | `list` | GET /pcaps | 资产列表 |
| 详情 | `get` | GET /pcaps/:id | 资产元数据 |
| 删除 | `delete` | DELETE /pcaps/:id | 删除资产 |
| 流查询 | `list_flows` | GET /pcaps/:id/flows | 流列表 |
| 流查询 | `get_flow` | GET /pcaps/:id/flows/:fid | 单流详情 |
| 包查询 | `list_packets` | GET /pcaps/:id/flows/:fid/packets | 指定流的包列表 |
| 包查询 | `list_packets_by_asset` | GET /pcaps/:id/packets | 资产级包列表 |
| 包查询 | `get_packet` | GET /pcaps/:id/packets/:pid | 单包详情 |
| 包查询 | `get_packet_payload` | GET /pcaps/:id/packets/:pid/payload | 单包 payload（base64）|
| 流内容 | `get_stream` | GET /pcaps/:id/flows/:fid/stream | 流级 reassembled stream |
| 流内容 | `get_body` | GET /pcaps/:id/flows/:fid/body | 流级 body 内容 |
| 搜索 | `search` | POST /pcaps/:id/search | trigram 索引搜索 |
| 预览 | `match_preview` | POST /pcaps/:id/match-preview | 匹配预览 |
| 抽取 | `extract` | POST /pcaps/:id/extract | 按规则抽取新 pcap |
| 下载 | `download` | GET /pcaps/:id/download | 返回文件路径 + 大小 |

**import 特殊处理**：同进程直接读 `file_path`，调 `pcapparser.Parse` + `PcapRepository.CreateAsset`，不走 multipart。

**download 特殊处理**：返回文件路径 + 大小，大模型可直接读。

**get_packet_payload / get_stream / get_body 返回**：base64 编码内容（可能较大，LLM 应节制调用）。

#### 4.2.4 `flowb_query_system`

系统域工具，覆盖 8 个 action（含 health/ready 公开端点 + refresh_interfaces mutation）。settings 已拆分到 `flowb_manage_settings`。

**参数**：
```json
{
  "action": "status|protocols|stats|health|ready|interfaces|ports|refresh_interfaces",
  "interface": "eth0"  // 可选，预留给单接口查询
}
```

**action 语义**：

| action | 映射端点 | 类型 | 说明 |
|--------|---------|------|------|
| `status` | GET /system/status | 查询 | 引擎状态（worker 池/缓冲区/运行任务数）|
| `protocols` | GET /system/protocols | 查询 | 已注册协议清单 + 各协议字段 schema |
| `stats` | GET /system/stats | 查询 | 全局流量统计（pps/bps/累计字节）|
| `health` | GET /health | 查询（公开）| 存活检查（process alive）|
| `ready` | GET /ready | 查询（公开）| 就绪检查（依赖就绪：DB/engine）|
| `interfaces` | GET /interfaces | 查询 | 网卡列表（含 IP/MAC/状态/在用分配）|
| `ports` | GET /ports | 查询（公开）| 端口列表（PCI/状态/当前任务）|
| `refresh_interfaces` | POST /interfaces/discover | **mutation** | 重新扫描网卡 |

**映射**：`SystemHandler.GetStatus/GetProtocols/GetStats/HealthCheck/ReadyCheck` + `listInterfaces/listPorts` + `discoverInterfaces`（`refresh_interfaces` action）。

**注意**：`health`/`ready` 在后端是无认证端点，MCP 仍以 service account 调用（绕过 auth middleware，直接调 handler），不暴露敏感信息。

#### 4.2.5 `flowb_manage_port_groups`

**参数**：
```json
{
  "action": "create|list|get|delete",
  "id": "group-id",
  "name": "组名",
  "ports": [{"interface": "eth0", "weight": 1}]
}
```

#### 4.2.6 `flowb_manage_settings`（新增）

系统设置域，2 个 action。设置是全局的（无 user_id 隔离），所有用户共享，service account 可读写。

**参数**：
```json
{
  "action": "get|update",
  "max_tasks": 100,        // update：引擎最大并发任务数（立即生效）
  "buffer_size": 4096,     // update：环形缓冲区大小（下次重启生效）
  "log_level": "info"      // update：日志级别 debug/info/warn/error（立即生效）
}
```

**action 语义**：

| action | 映射端点 | 说明 |
|--------|---------|------|
| `get` | GET /settings | 返回 `{max_tasks, buffer_size, log_level}` |
| `update` | PUT /settings | 持久化到 DB + 应用运行时可生效项（log_level/max_tasks 立即，buffer_size 重启生效）|

**映射**：`SettingsHandler.Get/Update`。

**特殊说明**：`buffer_size` 修改后需要重启 engine 才生效（环形缓冲区是固定大小的）。MCP tool 返回时携带 `applied: ["log_level", "max_tasks"], pending_restart: ["buffer_size"]` 提示 LLM。

#### 4.2.7 `flowb_manage_auth`（新增）

认证域，5 个 action。这是 service account 模式下最敏感的工具，需配合 `callHandlerWithHeaders` 支持传递 JWT token。

**参数**：
```json
{
  "action": "register|login|validate|logout|refresh",
  "username": "alice",          // register/login
  "password": "...",            // register/login
  "email": "alice@example.com", // register
  "token": "eyJhbGciOi..."      // validate/logout/refresh：JWT token
}
```

**action 语义**：

| action | 映射端点 | 鉴权 | 说明 |
|--------|---------|------|------|
| `register` | POST /auth/register | 公开 | 注册新用户（role 始终为 user，admin 只能配置文件创建）|
| `login` | POST /auth/login | 公开 | 用户名+密码登录，返回 JWT + 过期时间 |
| `validate` | GET /auth/validate | 公开 | 校验 token 有效性，返回 user_id/username/role |
| `logout` | POST /auth/logout | Bearer token | 注销 token（加入黑名单）|
| `refresh` | POST /auth/refresh | Bearer token | 刷新 token，返回新 JWT |

**映射**：`AuthHandler.Register/Login/ValidateToken/Logout/Refresh`。

**service account 模式行为**：
- `register`：若后端允许公开注册则可用，否则返回 403
- `login`：LLM 可用任意用户凭据登录（凭据从配置或用户提供），返回 JWT
- `validate`/`logout`/`refresh`：需 LLM 提供 `token` 参数，MCP 通过 `Authorization: Bearer <token>` header 传递给后端

**安全注意**：
- 密码不入审计日志（仅记 hash）
- token 不入审计日志（仅记前 8 字符指纹）
- `register`/`login` 失败次数过多应触发速率限制（Phase 4）
- Phase 3 多用户模式后，LLM 可用 `login` 拿到真实用户 JWT，再用 `validate`/`refresh` 管理 session

#### 4.2.8 `flowb_manage_users`（新增）

用户管理域（admin only），5 个 action。service account role=user 时这些 action 返回 403，工具注册便于 Phase 3 多用户模式。

**参数**：
```json
{
  "action": "list|get|update|delete|reset_password",
  "id": "user-id",              // get/update/delete/reset_password 必填
  "username": "new_name",       // update
  "email": "new@example.com",   // update
  "role": "user|admin",         // update（仅 admin 可改角色）
  "enabled": true,              // update
  "new_password": "..."         // reset_password
}
```

**action 语义**：

| action | 映射端点 | RBAC | 说明 |
|--------|---------|------|------|
| `list` | GET /users | admin | 列出所有用户 |
| `get` | GET /users/:id | admin | 单用户详情 |
| `update` | PUT /users/:id | admin | 更新用户（角色/启用状态/邮箱）|
| `delete` | DELETE /users/:id | admin | 删除用户 |
| `reset_password` | POST /users/:id/reset-password | admin | 重置用户密码 |

**映射**：`UserHandler.List/Get/Update/Delete/ResetPassword`。

**service account 模式行为**：所有 action 后端强制 admin 校验（`auth.IsAdmin(c)`），service account role=user 调用返回 403。这是预期行为，工具存在是为 Phase 3 多用户认证后 admin API key 可直接使用。

#### 4.2.9 `flowb_manage_profile`（新增）

当前用户自管域，3 个 action。service account 可管理自身 profile。

**参数**：
```json
{
  "action": "get|update|delete",
  "username": "new_name",   // update（可选）
  "email": "new@example.com", // update（可选）
  "password": "...",        // delete：确认密码
  "new_password": "..."     // update：改密码（可选）
}
```

**action 语义**：

| action | 映射端点 | 说明 |
|--------|---------|------|
| `get` | GET /user/profile | 当前用户 profile |
| `update` | PUT /user/profile | 更新自身 username/email/password |
| `delete` | DELETE /user/profile | 注销自身账户（需密码确认）|

**映射**：`AuthHandler.GetProfile/UpdateProfile/DeleteProfile`。

**service account 模式行为**：
- `get`：返回 mcp-service 账户信息
- `update`：可改 service account 自身密码（运维场景）
- `delete`：慎用，删除 service account 会导致后续 MCP 调用失败（启动校验不过）

### 4.3 工作流工具（5 个）

#### 4.3.1 `flowb_generate_traffic`

**用途**：一步完成"创建策略 + 创建任务 + 启动"，最常用场景。

**参数**：
```json
{
  "task_name": "我的 TCP 流量任务",
  "protocol": "tcp",
  "config": {
    "src_ip": "10.0.0.1",
    "dst_ip": "10.0.0.2",
    "src_port": {"strategy": "rand", "range": [1024, 65535]},
    "dst_port": 80,
    "tcp": {"payload_size": 1024, "syn_options": {"mss": 1460}}
  },
  "strategy_flow_control": {"type": "flows", "value": 100},
  "task_flow_control": {"type": "bps", "value": 100000000},
  "output_type": "pcap",
  "output_config": {"pcap_path": "/tmp/out.pcap"}
}
```

**config 字段**：按 protocol 分子 schema（参考知识图谱 §3 FlowSpec）。`flowb_query_system(action=protocols)` 可返回各协议的字段清单，LLM 据此填写。

**流程**：
1. 调 `StrategyHandler.Create`（mode=synth）
2. 调 `TaskHandler.Create`（用返回的 strategy_id）
3. 调 `TaskHandler.Start`
4. 返回 `{task_id, strategy_id, status: "running"}`

**幂等**：策略和任务创建都支持 config_hash 幂等，重试安全。

**Batch 支持**：本 tool 仅单策略。批量场景用 `flowb_manage_tasks(action=create_batch)` + `flowb_manage_tasks(action=start)` 两步完成（Phase 2 可考虑加 `flowb_generate_batch` 工作流 tool）。

#### 4.3.2 `flowb_replay_pcap`

**用途**：一步完成"（可选导入）+ 创建 replay 策略 + 创建任务 + 启动"。

**参数**：
```json
{
  "task_name": "回放任务",
  "pcap_path": "/path/to/file.pcap",  // 本地路径
  "pcap_asset_id": "...",             // 若已导入，直接用
  "speed": {"mode": "bps", "bps": "1G"},
  "direction": "single|dual",
  "rewrites": [ ... ],                // 可选重写规则
  "checksum_mode": "recompute",
  "task_flow_control": {"type": "time", "value": 60},
  "output_type": "port_group",
  "output_config": {"port_group_id": "...", "interface2": "eth1"}
}
```

**流程**：
1. 若无 `pcap_asset_id`，调 `PcapHandler.Import`（走 `file_path`）
2. 调 `StrategyHandler.Create`（mode=replay，config 含 pcap_asset_id + speed）
3. 调 `TaskHandler.Create`
4. 调 `TaskHandler.Start`
5. 返回 `{task_id, strategy_id, pcap_asset_id, status}`

**R-F2 不变量防护**：speed.mode=`original`/`multiplier` 使用 TimestampPacer，**禁止**同时配 `task_flow_control.bps`。workflow 在第 2 步前调 `validateReplayBPSConflict`（复用 `task_handler.go:1258`），冲突直接返回错误：
```
{"error": {"code": -32602, "message": "speed.mode=original/multiplier conflicts with task_flow_control.bps (R-F2 invariant)"}}
```
speed.mode=`bps` 或空允许配 `task_flow_control.bps`（前者走 pacer，后者走 engine 子桶，不冲突）。

#### 4.3.3 `flowb_wait_for_task`

**用途**：阻塞等待任务完成，返回最终状态与统计。避免大模型反复轮询。

**参数**：
```json
{
  "task_id": "...",
  "timeout_seconds": 300  // 最长等待，默认 300，上限 3600
}
```

**返回**：
```json
{
  "task_id": "...",
  "status": "completed|failed|stopped|timeout",
  "stats": {"packets_sent": 12345, "bytes_sent": 67890, "duration_seconds": 12.5},
  "error": "..."  // 失败时
}
```

**实现**（混合回调 + 轮询）：
1. 注册 engine 的 `OnTaskComplete` / `OnTaskFailed` / `OnTaskStopped` 回调（一次性，绑 task_id）
2. `select` 回调 channel + `time.After(timeout)`
3. 回调触发 -> 返回最终状态
4. 超时 -> 返回 `status: "timeout"`，**任务不受影响继续运行**
5. 兜底：若 engine 未提供回调注册，降级为 1 秒间隔轮询 `taskStore.Get`

**超时后 reconnect**：LLM 可再次调 `flowb_wait_for_task` 续等（idempotent）。task 已完成则立即返回最终状态。

#### 4.3.4 `flowb_get_task_progress`

**用途**：获取任务实时进度与统计快照（非阻塞）。

**参数**：
```json
{
  "task_id": "...",
  "include_packet_samples": false  // 是否返回最近 N 个包
}
```

**返回**：task status + progress + stats + 策略摘要。

#### 4.3.5 `flowb_stop_all_tasks`

**用途**：紧急停止所有运行中任务。

**参数**：
```json
{
  "confirm": true,     // 必须为 true，防误触
  "reason": "..."      // 必填，描述为何紧急停止，写入审计日志
}
```

**返回**：`{stopped: ["task-id-1", "task-id-2"], failed_to_stop: [...]}`

### 4.4 工具总数

- 域分组：9 个
  - `flowb_manage_strategies`（6 actions）
  - `flowb_manage_tasks`（8 actions）
  - `flowb_manage_pcaps`（17 actions）
  - `flowb_query_system`（8 actions）
  - `flowb_manage_port_groups`（4 actions）
  - `flowb_manage_settings`（2 actions）-- 新增
  - `flowb_manage_auth`（5 actions）-- 新增
  - `flowb_manage_users`（5 actions）-- 新增
  - `flowb_manage_profile`（3 actions）-- 新增
- 工作流：5 个
  - `flowb_generate_traffic`
  - `flowb_replay_pcap`
  - `flowb_wait_for_task`
  - `flowb_get_task_progress`
  - `flowb_stop_all_tasks`
- **合计 14 个 tool**，覆盖后端 13 个业务域共 58 个功能端点（ws/prometheus 不计入功能端点；ws 由 resource 订阅覆盖，prometheus 由运维侧访问）

**工具数 vs LLM 上下文负担**：14 个 tool 仍在 LLM 可承受范围（Claude/GPT 等 LLM 一般可处理 30+ tool）。每个 tool 的 action 数量较多（pcaps 17 个），但通过 `action` 字段路由，LLM 只需理解一份参数 schema。

---

## 5. 资源设计

MCP resources 供大模型订阅/读取动态数据。URI scheme 统一用 `flowb://`，path 部分用单斜杠。

### 5.1 资源清单

| URI | 类型 | 说明 |
|---|---|---|
| `flowb://task/{id}` | subscribe | 任务状态 + 实时统计（映射 WebSocket 推送） |
| `flowb://task/active` | read | 当前运行中任务列表 |
| `flowb://strategy/{id}` | read | 策略详情 |
| `flowb://pcap/{id}` | read | PCAP 资产元数据 |
| `flowb://pcap/{id}/flows` | read | 资产流列表 |
| `flowb://pcap/{id}/flow/{fid}` | read | 单流详情 |
| `flowb://system/status` | read | 系统状态（CPU/Mem/buffer） |
| `flowb://system/interfaces` | read | 网卡列表 |
| `flowb://system/stats` | subscribe | 全局流量统计实时推送 |

（删除原 `strategy:///all` - 与 `flowb_manage_strategies(action=list)` 功能重复，保留 list tool 即可。）

### 5.2 订阅机制

- `flowb://task/{id}` 订阅时，MCP server 注册到 WebSocket Hub，把 `status_update` / `stats_update` / `progress_update` 转发给客户端
- 任务进入终态（completed/failed/stopped）后，server 推送最终状态包，**然后自动关闭订阅**（避免悬挂连接）
- `flowb://system/stats` 订阅时，5 秒一次推送全局 pps/bps
- 读取（read）类型资源是一次性 GET，不订阅
- 客户端断开连接时，server 清理 Hub 注册项

### 5.3 资源 vs 工具

- **资源**：被动读取/订阅的状态数据，大模型不修改
- **工具**：主动执行的动作（create/start/stop）
- 例：读任务状态用资源 `flowb://task/{id}`，启动任务用工具 `flowb_manage_tasks(action=start)`

---

## 6. 长任务处理

流量生成任务是长时运行的异步操作。MCP tool 不能阻塞等待（会超时），采用以下策略：

### 6.1 启动即返回

`flowb_generate_traffic` / `flowb_replay_pcap` / `flowb_manage_tasks(action=start)` 立即返回 `task_id` + `status: "running"`，不等待完成。

### 6.2 三种查询方式

1. **`flowb_get_task_progress` tool**：非阻塞快照，适合一次性查询
2. **`flowb_wait_for_task` tool**：阻塞带超时，适合"发起后等结果"场景
3. **`flowb://task/{id}` resource 订阅**：实时推送，适合持续监控

### 6.3 超时与清理

- `flowb_wait_for_task` 超时后返回 `status: "timeout"`，任务不受影响继续运行
- MCP server 不主动取消超时任务（大模型可显式调 `stop`）
- 超时后 LLM 可再次调 `flowb_wait_for_task` 续等（idempotent），task 已完成则立即返回终态
- service account 模式下，MCP server 退出时所有由它启动的运行中任务**继续运行**（engine 不依赖 MCP server 生命周期）
- MCP server 重启后，原 task 的 `flowb_wait_for_task` 回调注册丢失 - LLM 需重新调用（不会自动 reconnect）

---

## 7. PCAP 文件处理

同进程部署的优势：直接访问文件系统，无需 base64。

### 7.1 导入

`flowb_manage_pcaps(action=import)` 接受 `file_path` 参数：
- MCP server 直接读文件，算 sha256
- 调 `PcapHandler.Import` 等价逻辑（绕过 multipart，直接走 `pcapparser.Parse` + `PcapRepository.CreateAsset`）
- 返回 `{pcap_asset_id, packet_count, flow_count, protocol_dist}`

### 7.2 下载

`flowb_manage_pcaps(action=download)`：
- 返回 `{file_path: "/data/pcaps/{id}.pcap", size: 12345, original_filename: "..."}`
- 大模型可直接读路径（若在同一机器）或调 MCP file resource

### 7.3 流/包查询

`list_flows` / `list_packets` / `get_flow` 等直接走 repository，返回结构化 JSON。

### 7.4 大文件考虑

- 导入上限沿用 2GB（pcap_handler.go:47-50）
- 大模型应避免在 tool 参数里传 base64 编码的 pcap（会撑爆上下文）
- 若大模型只有 base64 数据，需先写本地文件再传路径（工作流 tool 可提供 `save_temp_file` 辅助，但默认不暴露以防滥用）

---

## 8. 错误处理

### 8.1 错误映射

后端 `Response{Code, Message, Data}` 映射到 MCP error：

| 后端 Code | MCP error | 说明 |
|---|---|---|
| 0 | success | 正常返回 |
| 400 | InvalidParams | 参数错误 |
| 401 | Internal error (config error) | service account 配置错误，应告警 |
| 403 | InvalidRequest | 权限不足 |
| 404 | InvalidRequest | 资源不存在 |
| 409 | success (idempotent hit) | 冲突（幂等命中返回已存在 ID） |
| 500 | Internal error | 内部错误 |

### 8.2 错误响应格式

MCP error 标准格式：
```json
{
  "error": {
    "code": -32602,
    "message": "invalid strategy id: strat-xxx",
    "data": {
      "backend_code": 404,
      "backend_message": "strategy not found"
    }
  }
}
```

### 8.3 幂等性处理

策略创建（config_hash）和任务创建（sorted strategy_ids + output + fc）都支持幂等。后端返回 `message: "strategy already exists"` 时，MCP tool **识别为成功**并返回已存在的 ID，不报错。

**幂等命中返回格式**：
```json
{
  "id": "strat-xxx",
  "created": false,
  "message": "strategy already exists (idempotent hit)"
}
```

### 8.4 异常路径

- `HealthCheck` / `ReadyCheck` 通过 `flowb_query_system(action=health|ready)` 暴露，返回简化结构 `{status: "ok"|"degraded", checks: {...}}`
- 认证中间件 401 不应出现（service account 内部注入 context），若出现视为配置错误，记入审计日志并返回 Internal error
- `flowb_manage_users` 在 service account 模式下返回 403 是预期行为（RBAC 拒绝），MCP 将 403 映射为 `InvalidParams` 返回给 LLM，提示"service account 模式下此操作需要 admin 角色"

---

## 9. 配置项

`configs/config.yaml` 新增 `mcp` 段：

```yaml
mcp:
  enabled: true
  service_user_id: "mcp-service"        # 必须是已存在的 enabled 用户；不存在则拒绝启动
  service_user_role: "user"             # 默认 user（自身隔离）
  service_account_password: "flowb-mcp-change-me"  # 默认密码，启动时 warn 提醒修改
  api_key: "..."                        # HTTP/SSE 单 key（X-MCP-Key header 校验）
  transports:
    stdio: true                         # 启动 stdio（与 tgserver 同进程时用）
    http:
      enabled: true
      listen: "127.0.0.1:8081"          # 默认绑回环地址；远程访问需显式配置内网 IP
      cors_origins:                     # 默认仅 localhost，生产环境按需放开
        - "http://localhost:*"
        - "http://127.0.0.1:*"
  max_wait_timeout_seconds: 3600        # flowb_wait_for_task 上限
  audit_log: true                       # 记录所有 MCP 操作到日志（含 client_id）
  max_subscriptions: 100                # 同时活跃的 SSE 订阅数上限
```

### 9.1 service account 初始化

- 启动时校验 `service_user_id` 存在且 `Enabled=true`
- **若不存在，拒绝启动**并打印配置错误（不自动创建，避免日志记录密码等不安全实践）
- **密码默认 `flowb-mcp-change-me`**：启动时若检测到默认密码，打印 warn 日志提醒运维修改
- 该用户的 token 不入 `tokens` 表（MCP 走内部 context，不走 JWT 校验路径）
- 允许前端登录（运维可用该账号登录检查 mcp-service 名下数据）

---

## 10. 安全考虑

### 10.1 service account 权限与 RBAC 分层

- **角色 `user`（自身隔离）**：LLM 只能操作 mcp-service 名下数据
- **admin 域工具存在但被 RBAC 拒绝**：`flowb_manage_users`（list/get/update/delete/reset_password）后端强制 admin 校验，service account role=user 调用返回 403。这是设计预期，工具存在是为 Phase 3 多用户认证后 admin API key 可直接使用
- **`flowb_manage_auth` 行为分层**：
  - `register`/`login` 是公开端点，service account 可调
  - `validate`/`logout`/`refresh` 需 LLM 提供 `token` 参数（任意用户的 JWT），MCP 通过 `Authorization: Bearer` header 传递
  - service account 自身的 JWT 不在 MCP 内部使用（MCP 用内部 context），但 LLM 可显式调 `login` 拿 JWT 用于其他场景
- **敏感操作防护**：
  - `flowb_stop_all_tasks` 加 `confirm=true` + `reason` 字段双重防护
  - `flowb_manage_users(action=delete)` 删除自身 service account 时返回错误（防锁死）
  - `flowb_manage_profile(action=delete)` 删除 service account 时 warn 提示（不阻止，但记入审计日志）
  - `flowb_manage_settings(action=update)` 修改 `buffer_size` 时返回 `pending_restart` 提示

### 10.2 HTTP/SSE 传输保护

若启用 HTTP/SSE，MCP endpoint 暴露在网络上，需要：
- **绑定内网地址**：`listen: "127.0.0.1:8081"` 或内网 IP（默认回环）
- **API key 校验**：HTTP header `X-MCP-Key` 与配置的 `mcp.api_key` 比对，不匹配返回 401
- **CORS 限制**：默认仅 localhost，生产环境收紧 `cors_origins`
- **速率限制**：复用 `pkg/config.RateLimitConfig`
- **TLS（生产推荐）**：Phase 3 增加配置项 `mcp.transports.http.tls.cert_file` / `key_file`

### 10.3 审计日志

所有 MCP tool 调用记录到 zap 日志，含 `client_id`（MCP 协议 initialize 时客户端自带 name+version，零成本溯源）：
```json
{"level":"info","msg":"mcp tool called","tool":"flowb_generate_traffic","client_id":"claude-desktop","client_version":"0.7.0","caller":"...","task_id":"...","duration_ms":123,"params_hash":"...","status":"success"}
```

敏感参数处理（关键）：
- `password` / `new_password` / `token` / `api_key` **绝不入日志**（连 hash 都不记，直接省略字段）
- `pcap_path` / `config` 记 hash 不记明文
- `reason` 字段（如 `flowb_stop_all_tasks` 的 reason）记明文供审计追溯
- `flowb_manage_auth(action=login)` 失败时记 `username` 但不记 `password`
- `flowb_manage_auth(action=validate/refresh)` 记 `token_fingerprint`（前 8 字符 + sha256 后 8 字符）

### 10.4 文件访问边界

- PCAP 导入/下载限制在 `data/pcaps/` 目录及配置的白名单路径
- 拒绝绝对路径越权访问（`../` 穿越）
- 工作流 tool 的 `pcap_path` 参数校验前缀
- `flowb_manage_pcaps(action=import)` 的 `file_path` 必须在白名单目录内

### 10.5 资源耗尽

- `flowb_wait_for_task` 单次最长 3600 秒，防大模型长时间占用
- 同时活跃的 MCP 订阅数上限（默认 100，防 SSE 连接耗尽）
- `flowb_generate_traffic` 批量调用受 `max_tasks` 设置约束
- `flowb_manage_auth(action=login/register)` 失败次数达阈值后速率限制（Phase 4 实现）
- `flowb_manage_pcaps(action=import)` 大文件（>2GB）拒绝

### 10.6 并发隔离

- service account 共享，并发安全靠 engine/db 本身线程安全（已验证 `-race` clean）
- 多个 LLM 同时调用产生不同 task_id，互不影响
- task_id 是随机 hex，不可预测，防止跨用户越权（service account 模式下实际单用户，但为未来多用户预留）
- `flowb_manage_settings(action=update)` 并发写时由 DB 事务保证一致性

---

## 11. 实现计划

### 11.1 Phase 1：基础框架（MVP）

**目标**：stdio 传输 + 3 个核心 tool 跑通

- [x] 引入 `github.com/modelcontextprotocol/go-sdk`（官方 SDK v1.6.1，Go 1.25）
- [x] `internal/mcp/server.go`：server 结构、tool 注册框架
- [x] `internal/mcp/context.go`：service account context 构造 + 启动校验（含默认密码 warn）
- [x] `internal/mcp/transport.go`：stdio 实现
- [x] `internal/mcp/audit.go`：审计日志（含 client_id 从 MCP initialize 提取）
- [x] `internal/mcp/errors.go`：backend 响应解析 + jsonrpc.Error 映射
- [x] `internal/mcp/tools_strategy.go`：`flowb_manage_strategies` 完整实现
- [x] `internal/mcp/tools_task.go`：`flowb_manage_tasks` 完整实现
- [x] `internal/mcp/tools_workflow.go`：`flowb_generate_traffic` 实现（synth 单策略，R-F2 由 Start 内部校验）
- [x] 配置项（`mcp` 段）+ main.go 集成 `initMCPServer` + `startMCPServer` + `Stop` 清理
- [x] **仓库内集成测试**（遵循 CLAUDE.md 测试政策）：14 个测试 `-race` 通过，覆盖 create/list/get/update/delete/start/stop/generate/concurrent/error-mapping
- [ ] Claude Desktop 联调（端到端验证，需用户手动）

### 11.2 Phase 2：完整工具集

**目标**：实现剩余 11 个 tool（manage_pcaps/query_system/manage_port_groups/manage_settings/manage_auth/manage_users/manage_profile + replay_pcap/wait_for_task/get_task_progress/stop_all_tasks），覆盖全部 58 个后端端点。

- [ ] `flowb_manage_pcaps`（17 actions：import/list/get/delete/list_flows/get_flow/list_packets/list_packets_by_asset/get_packet/get_packet_payload/get_stream/get_body/search/match_preview/extract/download/reparse）
- [ ] `flowb_query_system`（8 actions：status/protocols/stats/health/ready/interfaces/ports/refresh_interfaces）
- [ ] `flowb_manage_port_groups`（4 actions）
- [ ] `flowb_manage_settings`（2 actions：get/update，含 buffer_size 重启提示）
- [ ] `flowb_manage_auth`（5 actions：register/login/validate/logout/refresh，需 `callHandlerWithHeaders` 支持）
- [ ] `flowb_manage_users`（5 actions：list/get/update/delete/reset_password，RBAC 403 兜底测试）
- [ ] `flowb_manage_profile`（3 actions：get/update/delete，含删除 service account 防护）
- [ ] `flowb_replay_pcap` 工作流（含 R-F2 冲突校验）
- [ ] `flowb_wait_for_task`（回调 + 轮询兜底）
- [ ] `flowb_get_task_progress`
- [ ] `flowb_stop_all_tasks`（含 reason 审计）

### 11.3 Phase 3：资源与 HTTP 传输

- [ ] `internal/mcp/resources.go`：resource 定义与订阅
- [ ] `flowb://task/{id}` 订阅（桥接 WebSocket Hub，终态自动关闭）
- [ ] `flowb://system/stats` 订阅
- [x] HTTP/SSE transport 实现（`internal/mcp/http_server.go`，基于 `StreamableHTTPHandler`，含 API key 鉴权 + CORS + 30min session timeout）
- [x] API key 校验（`X-MCP-Key` header，`crypto/subtle.ConstantTimeCompare` 防时序攻击）
- [x] main.go 集成（`startMCPHTTP` + `Stop` 优雅关闭）
- [x] 测试覆盖（11 个测试 `-race` 通过：constructor 验证、API key 鉴权 3 路径、CORS 3 场景、SDK 客户端完整 protocol flow、SSE 原始解析）
- [ ] 订阅数上限（`max_subscriptions`）

### 11.4 Phase 4：安全与审计

- [ ] 审计日志（params_hash + reason 明文）
- [ ] 文件路径白名单校验
- [ ] 速率限制（per-tool 与 HTTP 层）
- [ ] CORS 收紧（按部署环境）
- [ ] service account 权限收敛（生产降为 user 角色）

### 11.5 测试策略（遵循 CLAUDE.md）

- **spec-driven**：每个 tool 对应知识图谱 §6 的路由，按路由清单逐个覆盖
- **失败路径**：无效参数、资源不存在、权限不足、超时、R-F2 冲突
- **集成测试**：MCP tool 调用 -> engine 执行 -> 验证副作用（DB / 文件 / 网卡）
- **并发**：多个 `flowb_wait_for_task` 并发，验证不互相干扰；service account 共享下多 LLM 并发产生不同 task_id
- **failing-test-first**：每个 bug 先写失败测试
- **仓库内集成测试为主**，Claude Desktop 联调为端到端验证（不依赖外部工具做正确性验证）

---

## 12. 开放问题

### 12.1 多用户认证过渡（阶段 2 必做）

当前 service account 模式所有数据归 `mcp-service`，无法区分真实用户。阶段 2 有页面后需过渡到多用户认证。

**触发条件**：Web UI 上线、多用户开始使用 trafficgen。

**候选方案**：
- API key 映射：用户在页面生成 API key（绑 user_id），LLM 配置 key，MCP server 验证 -> 注入 user context
- JWT 透传：用户登录拿 JWT，LLM 配置 JWT，MCP server 验证 -> 注入 user context
- OAuth 2.0：MCP server 作 OAuth resource server（标准但复杂）

**推荐**：API key 映射（长期有效无需刷新、用户可吊销、兼容 stdio env + HTTP header）。

**阶段 1 不预留抽象**（YAGNI）：`newServiceContext` 保持简单实现。阶段 2 重构为 `newAuthContext(authToken string)`，tool 代码不改（只改 context 构造层）。新增 `mcp_api_keys` 表 + 验证中间件即可过渡。

### 12.2 handler 复用 vs 抽取 service 层

MCP 直接调 `*Handler` 方法需要构造 `gin.Context`，略 hacky。备选：
- 抽取 `internal/service/` 层，handler 和 MCP 都调 service
- 保留现状，MCP 用 `gin.CreateTestContext` 构造 context

**建议**：Phase 1 用现状（快速验证），Phase 2 视代码洁癖程度决定是否重构。

### 12.3 流量生成结果回传

`flowb_generate_traffic` 生成的 pcap 文件如何回传给大模型？
- 返回文件路径，大模型自己读
- 提供 `flowb_read_pcap_file` tool 分片读
- 用 MCP resource `flowb://pcap/output/{task_id}`

**建议**：返回路径 + 提供 resource，大模型按需读。

### 12.4 任务结果摘要

任务完成后，大模型可能想要"结果摘要"（发了多少包、持续多久、有无错误）。`flowb_wait_for_task` 返回 stats，但更详细的报告（如协议分布、流统计）需要额外查询。是否提供 `flowb_get_task_report` tool？

**建议**：Phase 2 加 `flowb_get_task_report`，聚合 task + history + stats。

### 12.5 batch 工作流 tool

`flowb_generate_traffic` 仅支持单策略，批量场景当前需两步（create_batch + start）。是否加 `flowb_generate_batch` 工作流 tool 一步完成？

**建议**：Phase 2 视使用频率决定。

---

## 附：与后端知识图谱的映射

| MCP tool | 后端路由（知识图谱 §6） | 覆盖端点数 |
|---|---|---|
| `flowb_manage_strategies` | §6.3 策略域 | 6 |
| `flowb_manage_tasks` | §6.4 任务域（含 history） | 8 |
| `flowb_manage_pcaps` | §6.5 PCAP 资产域 | 17 |
| `flowb_query_system` | §6.6 系统域 + health/ready + interfaces + ports | 8 |
| `flowb_manage_port_groups` | §6.6 端口组 | 4 |
| `flowb_manage_settings` | §6.7 设置域 | 2 |
| `flowb_manage_auth` | §6.1 认证域 | 5 |
| `flowb_manage_users` | §6.2 用户域（admin only） | 5 |
| `flowb_manage_profile` | §6.2 用户自管 profile | 3 |
| `flowb_generate_traffic` | 组合 §6.3 create + §6.4 create + start | 0（工作流）|
| `flowb_replay_pcap` | 组合 §6.5 import + §6.3 create + §6.4 create + start | 0（工作流）|
| `flowb_wait_for_task` | 新增（订阅 engine 回调 + 轮询兜底） | 0（工作流）|
| `flowb_get_task_progress` | §6.4 get + WebSocket stats | 0（工作流）|
| `flowb_stop_all_tasks` | 组合 §6.4 list + stop | 0（工作流）|
| **合计** | | **58 个功能端点全覆盖** |

**覆盖面**：知识图谱 §6 中所有 13 个业务域（认证/用户/策略/任务/PCAP/系统/端口组/端口/接口/设置/历史/健康/Profile）共 58 个功能端点全部被 MCP 工具覆盖。WebSocket `/ws` 由 §5 resource 订阅覆盖（`flowb://task/{id}` / `flowb://system/stats`），Prometheus `/metrics` 由运维侧直接访问（不入 MCP）。

**RBAC 分层小结**：
- ✅ Phase 1 service account role=user 可用：strategies/tasks/pcaps/port_groups/system/settings/profile + auth(register/login) + 5 个工作流 = 41 个端点
- ⚠️ Phase 1 受 RBAC 限制返回 403：users 域 5 个端点 + auth(validate/logout/refresh 若无 token) = 8 个端点（工具注册但被后端拒绝）
- 🔓 Phase 3 多用户认证后：admin API key 调用 users 域解锁；任意用户 JWT 调用 auth(validate/logout/refresh) 解锁 -- 全部 58 个端点可用
