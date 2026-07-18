# 后端知识图谱

> 生成日期：2026-07-16
> 范围：trafficgen Go 后端全栈（cmd / internal / pkg）
> 用途：MCP 层设计与后续开发的持久参考，避免每次重读代码

---

## 目录

1. [项目结构与技术栈](#1-项目结构与技术栈)
2. [配置与启动](#2-配置与启动)
3. [数据模型](#3-数据模型)
4. [存储层与 user_id 隔离](#4-存储层与-user_id-隔离)
5. [认证与授权](#5-认证与授权)
6. [REST API 全量路由](#6-rest-api-全量路由)
7. [核心引擎](#7-核心引擎)
8. [Worker Pipeline](#8-worker-pipeline)
9. [流量控制（Flow Control）](#9-流量控制flow-control)
10. [协议规划器与 BatchSpec](#10-协议规划器与-batchspec)
11. [输出路由](#11-输出路由)
12. [PCAP 解析器](#12-pcap-解析器)
13. [回放子系统](#13-回放子系统)
14. [网络接口管理](#14-网络接口管理)
15. [WebSocket 实时推送](#15-websocket-实时推送)
16. [工具包](#16-工具包)
17. [关键不变量与设计约束](#17-关键不变量与设计约束)
18. [已知限制与遗留问题](#18-已知限制与遗留问题)
19. [关键文件索引](#19-关键文件索引)

---

## 1. 项目结构与技术栈

### 1.1 仓库布局

```
/home/weihang/trafficGenerator/        # git 根
├── CLAUDE.md                          # 项目规范（代码 review + 测试政策）
├── docs/                              # 设计文档（本文件在此）
├── trafficgen/                        # Go 后端 + 前端
│   ├── cmd/server/main.go             # 入口
│   ├── internal/
│   │   ├── api/rest/                  # REST API + WebSocket
│   │   ├── api/websocket/             # WS Hub
│   │   ├── core/                      # 引擎、worker、buffer、types
│   │   ├── replay/                    # 回放规划器、pacer、rewriter
│   │   ├── pcapparser/                # PCAP 解析
│   │   ├── storage/                   # GORM 模型 + repository
│   │   ├── output/                    # InterfaceWriter
│   │   └── protocol/                  # 协议规划器实现
│   ├── pkg/
│   │   ├── auth/                      # JWT + RBAC + middleware
│   │   ├── config/                    # viper 配置
│   │   ├── logger/                    # zap 日志
│   │   ├── netif/                     # 网卡发现 + 端口调度
│   │   ├── metrics/                   # Prometheus 指标
│   │   └── version/                   # 版本信息
│   ├── configs/config.yaml            # 默认配置
│   └── web/                           # 前端（Vue）
└── high_performance_traffic_generator.py  # 旧版 Python 原型（已弃用）
```

### 1.2 技术栈

| 层 | 技术 |
|---|---|
| 语言 | Go |
| HTTP 框架 | `github.com/gin-gonic/gin` |
| ORM | `gorm.io/gorm` |
| 数据库 | PostgreSQL（生产）/ SQLite（pure Go，`github.com/glebarez/sqlite`，测试） |
| 缓存 | Redis（可选，降级为 `sync.Map`） |
| 配置 | `spf13/viper`（YAML + env 前缀 `TG_`） |
| 日志 | `go.uber.org/zap` |
| PCAP | `github.com/google/gopacket` + `gopacket/pcapgo` |
| 认证 | JWT (HS256) + DB token 吊销表 |
| 指标 | Prometheus |
| 实时推送 | WebSocket |

---

## 2. 配置与启动

### 2.1 Config 结构（`pkg/config/config.go:14-23`）

```go
type Config struct {
    Server    ServerConfig    // host, port, mode, allowed_origins
    Database  DatabaseConfig  // type, PostgresConfig, SQLiteConfig, PoolConfig
    Redis     RedisConfig     // enabled, addr, password, db, pool_size
    Engine    EngineConfig    // config_workers, packet_workers, output_workers, buffer_size, queue_size
    Logging   LoggingConfig   // level, format, output, FileConfig
    Auth      AuthConfig      // jwt_secret, jwt_issuer, jwt_expires_in, AdminConfig
    RateLimit RateLimitConfig // enabled, requests_per_second, burst
    Metrics   MetricsConfig   // enabled, path
}
```

- **加载入口**：`Load(configPath)` (config.go:127-165)
- **查找路径**：`./configs`、`.`、`/etc/trafficgen`
- **环境变量**：前缀 `TG`，`AutomaticEnv()`，字符串内 `${VAR}` / `$VAR` 展开
- **命令行 flag**：仅 `-config`（cmd/server/main.go:34）

### 2.2 启动流程（`cmd/server/main.go:52-130`）

```
flag.Parse
  -> config.Load
  -> logger.Init
  -> initDatabase          (storage.NewDBWithAdmin)
  -> initInterfaceManager  (netif.NewManager + Discover，失败不致命)
  -> initPortScheduler     (netif.NewScheduler + StartAutoRelease 30s)
  -> initOutputManager     (output.NewManager)
  -> initEngine            (注册 planner + replay planner + buildFunc)
  -> initWebSocket         (hub + handler)
  -> initServer            (rest.NewServer)
  -> app.Start             (engine + HTTP server + metrics goroutine)
  -> 等待 SIGINT/SIGTERM
  -> app.Stop              (server.Shutdown 10s -> engine.Stop -> db.Close)
```

### 2.3 引擎初始化（`main.go:179-235`）

- 从 DB 读 `SettingsModel` 覆盖 buffer_size
- `core.NewEngine`，`MaxBufferBytes: 100MB`（硬编码）
- 注册协议 planner：tcp / udp / http / dns / icmp / arp
- `engine.SetBuildFunc(replay.NewBuildFunc(builder.Build))`
- `engine.SetReplayPlanner(replay.NewReplayPlanner(app.db))`

---

## 3. 数据模型

所有模型在 `internal/storage/models.go`。**未使用 GORM 外键约束**，关系靠应用层 `user_id` 过滤。

### 3.1 模型清单

| 模型 | 表名 | 行号 | 用途 |
|---|---|---|---|
| `TaskModel` | `tasks` | 12-30 | 流量生成任务 |
| `StrategyModel` | `strategies` | 38-49 | 策略（synth/replay） |
| `HistoryModel` | `history` | 57-69 | 任务执行历史 |
| `UserModel` | `users` | 77-87 | 用户 |
| `PortAllocationModel` | `port_allocations` | 95-102 | 端口分配持久化 |
| `PortModel` | `ports` | 110-119 | 网络端口 |
| `PortGroupModel` | `port_groups` | 127-133 | 端口组 |
| `TokenModel` | `tokens` | 141-148 | JWT token 校验 |
| `SettingsModel` | `settings` | 156-162 | 单例运行时设置 |
| `PcapAssetModel` | `pcap_assets` | 172-197 | PCAP 文件元数据 |
| `FlowModel` | `pcap_flows` | 207-279 | 流级聚合 |
| `PacketModel` | `pcap_packets` | 289-307 | 包级最小索引 |

### 3.2 JSON 存储字段（`gorm:"type:text"`）

| 模型 | 字段 | 行号 | 内容 |
|---|---|---|---|
| TaskModel | `StrategyIDs` | 17 | `["id1","id2"]` |
| TaskModel | `BatchConfig` | 19 | BatchSpec |
| TaskModel | `OutputConfig` | 21 | 输出配置 |
| TaskModel | `FlowControl` | 22 | `{"type":"bps","value":1e9}` |
| StrategyModel | `Config` | 44 | synth=FlowSpec；replay=ReplaySpec |
| StrategyModel | `FlowControl` | 45 | `{"type":"flows","value":1}` |
| PortGroupModel | `PortsConfig` | 130 | `[{"interface":"eth0","weight":1}]` |
| PcapAssetModel | `ProtocolDist` | 194 | `{"tcp":120,"udp":30}` |
| FlowModel | `FlagsSummary` | 244 | `{syn:n,fin:n,...}` |
| FlowModel | `TCPOptions` | 248 | TCP 选项 |
| FlowModel | `L7Metadata` | 254 | 按协议展开 |
| FlowModel | `OffsetLayout` | 273 | 字段->偏移（改写用） |

### 3.3 关键索引

- `idx_pkt_flow_seq`（pcap_packets: pcap_asset_id, flow_id, index_in_flow）- in-flow 分页
- `idx_pcaps_user_hash`（pcap_assets: user_id, file_hash UNIQUE）- 并发导入去重

### 3.4 Asset Status 状态机（`pcap_repository.go:62-68`）

```
"" -> importing -> ready           # 正常
importing -> error                 # 解析失败
error -> reindexing -> ready       # 重建索引
error -> importing                 # 强制重试
ready -> reindexing -> ready       # parser 升级
```

---

## 4. 存储层与 user_id 隔离

### 4.1 DB 类型（`internal/storage/db.go`）

- `DB` 包装 `*gorm.DB` + `*config.DatabaseConfig`
- `NewDBWithAdmin` (db.go:31-81)：初始化 + 建 admin 用户
- 支持后端：`postgres` / `sqlite`（其他报错）
- 事务仅用于 `PcapRepository.DeleteAssetComplete` / `DeleteAssetFlowsAndPackets`

### 4.2 Repository 清单

| Repository | 位置 | user_id 隔离 |
|---|---|---|
| `TaskRepository` | db.go:211-277 | ❌ **全部方法无 user_id 过滤**，靠 handler 层 |
| `StrategyRepository` | db.go:280-337 | ❌ 同上 |
| `HistoryRepository` | db.go:340-378 | ❌ 同上 |
| `PcapRepository` | pcap_repository.go:14-393 | ✅ **全部读路径强制 user_id** |

**关键安全约束**：Task/Strategy/History 的隔离完全在 API handler 层（`auth.GetUserID(c)` + `WHERE user_id = ?`）。PcapRepository 是唯一在 repository 层强制的，作 defense-in-depth。

### 4.3 PcapRepository 关键方法

**Asset**：
- `GetAsset(id, userID)` - `id = ? AND user_id = ?`
- `GetAssetByHash(userID, fileHash)` - 去重导入
- `ListAssets(userID, page, size, status)`
- `DeleteAssetComplete(id)` - 事务删 DB + 磁盘文件
- `CountReplayReferences(assetID)` - 跨用户统计引用

**Flow**：
- `ListFlowsByAsset(assetID, userID, page, size)` - 按 first_ts_us
- `GetFlow(flowID, userID)`
- `SearchFlows(assetID, userID, filters, page, size)` - 列名白名单防注入

**Packet**：
- `ListPacketsByFlow(flowID, userID, page, size)`
- `ListAllPacketsByAsset(assetID, userID)` - 按 raw_offset，replay 用
- `GetPacket(packetID, userID)`

---

## 5. 认证与授权

### 5.1 JWT（`pkg/auth/auth.go`）

- 算法：HS256
- `JWTManager` (auth.go:13-17)：`secret`、`issuer`、`expiresIn`
- `Claims` (auth.go:20-25)：`UserID`、`Username`、`Roles []string` + `jwt.RegisteredClaims`
- `GenerateToken(userID, username, roles)` (auth.go:37-53)
- `ValidateToken(tokenString)` (auth.go:56-73) - 校验签名 + 有效期
- 密码哈希：bcrypt.DefaultCost

### 5.2 双层校验（`pkg/auth/middleware.go`）

**`AuthMiddlewareWithDB`** (middleware.go:82-156)：
1. 解析 `Authorization: Bearer <token>`
2. JWT 签名 + 有效期校验
3. `tokenHash = SHA256(token)` 查 `tokens` 表
   - 不存在 -> 401 "token not recognized"
   - `status != "active"` -> 401 "token has been revoked"
   - DB 过期 -> 401 "token has expired"
4. 写入 gin context：`userID` / `username` / `roles`

**注册位置**：`server.go:133-136`，挂在 `/api/v1` 分组上。

### 5.3 不需要认证的端点

`/health`、`/ready`、`/ws`（WS 升级时校验 token）、`/metrics`、`/api/v1/auth/register`、`/api/v1/auth/login`、`/api/v1/auth/validate`、`/api/v1/auth/logout`、`/api/v1/ports`、`/api/v1/port-groups`（GET）、静态资源。

### 5.4 RBAC

- `RBAC` 结构 (auth.go:98-101) 已定义但 **server.go 未挂 RBACMiddleware**
- admin 鉴权靠 handler 内 `auth.IsAdmin(c)` 手动判断
- 默认角色：`admin`（`["*"]`）、`user`（task:* / strategy:read / interface:read）、`viewer`（全 read）

### 5.5 用户隔离实现

1. JWT 携带 `UserID`
2. Middleware 提取塞 context：`c.Set("userID", claims.UserID)`
3. Helper：`GetUserID(c)` / `GetUsername(c)` / `GetRoles(c)` / `IsAdmin(c)`
4. Handler 第一行 `userID := auth.GetUserID(c)`，SQL 拼 `WHERE id = ? AND user_id = ?`
5. 资源归属检查：`if asset.UserID != userID { NotFound }`（不返回 403，防越权探测）

### 5.6 登录响应（`auth_handler.go:43-48`）

```go
type LoginResponse struct {
    Token     string `json:"token"`
    ExpiresAt int64  `json:"expires_at"`
    UserID    string `json:"user_id"`
    Username  string `json:"username"`
}
```

---

## 6. REST API 全量路由

**路由注册**：`internal/api/rest/server.go:84-233`（`setupRoutes`）
**全局中间件**：`gin.Recovery()` -> `CORSMiddleware()` -> `LoggerMiddleware()`
**业务前缀**：`/api/v1`

### 6.1 认证域

| Method | Path | Handler | 功能 |
|---|---|---|---|
| POST | `/api/v1/auth/register` | `authHandler.Register` | 注册 |
| POST | `/api/v1/auth/login` | `authHandler.Login` | 登录拿 JWT |
| GET | `/api/v1/auth/validate` | `authHandler.ValidateToken` | 校验 token |
| POST | `/api/v1/auth/logout` | `authHandler.Logout` | 撤销当前 token |
| POST | `/api/v1/auth/refresh` | `authHandler.Refresh` | 刷新 token（需认证） |

### 6.2 用户域

| Method | Path | Handler | 权限 |
|---|---|---|---|
| GET | `/api/v1/user/profile` | `authHandler.GetProfile` | 本人 |
| PUT | `/api/v1/user/profile` | `authHandler.UpdateProfile` | 本人 |
| DELETE | `/api/v1/user/profile` | `authHandler.DeleteProfile` | 本人（admin 禁） |
| GET | `/api/v1/users` | `userHandler.List` | admin |
| GET | `/api/v1/users/:id` | `userHandler.Get` | admin |
| PUT | `/api/v1/users/:id` | `userHandler.Update` | admin |
| DELETE | `/api/v1/users/:id` | `userHandler.Delete` | admin（禁删 admin） |
| POST | `/api/v1/users/:id/reset-password` | `userHandler.ResetPassword` | admin，返回临时密码 |

### 6.3 策略域

| Method | Path | Handler | 功能 |
|---|---|---|---|
| POST | `/api/v1/strategies` | `strategyHandler.Create` | 创建（synth/replay，幂等） |
| GET | `/api/v1/strategies` | `strategyHandler.List` | 列出当前用户策略 |
| GET | `/api/v1/strategies/:id` | `strategyHandler.Get` | 获取单个 |
| GET | `/api/v1/strategies/:id/tasks` | `strategyHandler.ListTasks` | 引用该策略的 task |
| PUT | `/api/v1/strategies/:id` | `strategyHandler.Update` | 更新（按 mode 校验，方案 A 保留 mode） |
| DELETE | `/api/v1/strategies/:id` | `strategyHandler.Delete` | 删除（被 task 引用拒） |

**CreateStrategyRequest** (strategy_handler.go:29-35)：
```go
type CreateStrategyRequest struct {
    Name        string                 `json:"name" binding:"required"`
    Mode        string                 `json:"mode"`     // "synth"(default) | "replay"
    Protocol    string                 `json:"protocol"` // synth 必填
    Config      map[string]interface{} `json:"config" binding:"required"`
    FlowControl *FlowControlRequest    `json:"flow_control"`
}

type FlowControlRequest struct {
    Type  string  `json:"type" binding:"required"`  // "flows"|"bps"|"time"
    Value float64 `json:"value" binding:"required"`
}
```

### 6.4 任务域

| Method | Path | Handler | 功能 |
|---|---|---|---|
| POST | `/api/v1/tasks` | `taskHandler.Create` | 创建（幂等，按 sorted strategy_ids+output+fc 判重） |
| POST | `/api/v1/tasks/batch` | `taskHandler.CreateBatch` | 批量多协议混合（立即启动） |
| GET | `/api/v1/tasks` | `taskHandler.List` | 列出（分页+status/sort） |
| GET | `/api/v1/tasks/:id` | `taskHandler.Get` | 详情（含 StrategyBrief） |
| POST | `/api/v1/tasks/:id/start` | `taskHandler.Start` | 启动（optimistic lock） |
| POST | `/api/v1/tasks/:id/stop` | `taskHandler.Stop` | 停止 |
| DELETE | `/api/v1/tasks/:id` | `taskHandler.Delete` | 删除（运行中拒） |
| GET | `/api/v1/history` | `taskHandler.History` | 已完成历史 |

**CreateTaskRequest** (task_handler.go:276-282)：
```go
type CreateTaskRequest struct {
    Name         string                `json:"name" binding:"required"`
    StrategyIDs  []string              `json:"strategy_ids" binding:"required,min=1"`
    OutputType   string                `json:"output_type" binding:"required"` // "port_group"|"pcap"
    OutputConfig *OutputConfigRequest  `json:"output_config" binding:"required"`
    FlowControl  *FlowControlRequest   `json:"flow_control"` // 可选
}

type OutputConfigRequest struct {
    PortGroupID string `json:"port_group_id"`
    PcapPath    string `json:"pcap_path"`
    Interface2  string `json:"interface2,omitempty"` // 双口第二接口
}
```

### 6.5 PCAP 资产域（17 个端点）

| Method | Path | Handler | 功能 |
|---|---|---|---|
| POST | `/api/v1/pcaps` | `pcapHandler.Import` | 上传（multipart `file`，限 2GB，sha256 去重） |
| GET | `/api/v1/pcaps` | `pcapHandler.List` | 列表（page/size/status） |
| GET | `/api/v1/pcaps/:id` | `pcapHandler.Get` | 详情 |
| DELETE | `/api/v1/pcaps/:id` | `pcapHandler.Delete` | 删除（?force=true 强删） |
| GET | `/api/v1/pcaps/:id/flows` | `pcapHandler.ListFlows` | 流列表 |
| GET | `/api/v1/pcaps/:id/flows/:fid` | `pcapHandler.GetFlow` | 流详情 |
| GET | `/api/v1/pcaps/:id/flows/:fid/packets` | `pcapHandler.ListPackets` | 流内包 |
| GET | `/api/v1/pcaps/:id/flows/:fid/stream` | `pcapHandler.GetStream` | 重组流字节（?dir=c2s\|s2c&offset=&limit=） |
| GET | `/api/v1/pcaps/:id/flows/:fid/body` | `pcapHandler.GetBody` | 应用层 body |
| GET | `/api/v1/pcaps/:id/packets` | `pcapHandler.ListPacketsByAsset` | 按资产维度的包 |
| GET | `/api/v1/pcaps/:id/packets/:pid` | `pcapHandler.GetPacket` | 单包详情（动态重解析） |
| GET | `/api/v1/pcaps/:id/packets/:pid/payload` | `pcapHandler.GetPacketPayload` | payload 字节 |
| POST | `/api/v1/pcaps/:id/search` | `pcapHandler.Search` | 多条件检索 |
| POST | `/api/v1/pcaps/:id/match-preview` | `pcapHandler.MatchPreview` | FlowMatcher 命中预览 |
| POST | `/api/v1/pcaps/:id/extract` | `pcapHandler.Extract` | 批量抽取字段 |
| GET | `/api/v1/pcaps/:id/download` | `pcapHandler.Download` | 下载原始 pcap |
| POST | `/api/v1/pcaps/:id/reparse` | `pcapHandler.Reparse` | 重新解析 |

### 6.6 系统域

| Method | Path | Handler | 功能 |
|---|---|---|---|
| GET | `/health` | `systemHandler.HealthCheck` | 健康检查 |
| GET | `/ready` | `systemHandler.ReadyCheck` | 就绪检查（engine 是否运行） |
| GET | `/api/v1/system/status` | `systemHandler.GetStatus` | CPU/Mem/buffer/uptime/active_tasks |
| GET | `/api/v1/system/protocols` | `systemHandler.GetProtocols` | 支持的协议 |
| GET | `/api/v1/system/stats` | `systemHandler.GetStats` | 流量统计（pps/bps/协议分布） |
| GET | `/api/v1/interfaces` | `s.listInterfaces` | 网卡列表（含端口分配） |
| POST | `/api/v1/interfaces/discover` | `s.discoverInterfaces` | 重新发现接口 |
| GET | `/api/v1/ports` | `s.listPorts` | 所有 PortModel |
| GET | `/api/v1/port-groups` | `portGroupHandler.List` | 端口组列表（公开） |
| GET | `/api/v1/port-groups/:id` | `portGroupHandler.Get` | 端口组详情（公开） |
| POST | `/api/v1/port-groups` | `portGroupHandler.Create` | 创建端口组 |
| DELETE | `/api/v1/port-groups/:id` | `portGroupHandler.Delete` | 删除端口组 |
| GET | `/api/v1/settings` | `settingsHandler.Get` | 全局设置 |
| PUT | `/api/v1/settings` | `settingsHandler.Update` | 更新（log_level/max_tasks 立即生效，buffer_size 需重启） |

### 6.7 统一响应格式（`response.go:11-15`）

```go
type Response struct {
    Code    int         `json:"code"`
    Message string      `json:"message"`
    Data    interface{} `json:"data,omitempty"`
}
```

业务码：`0=Success, 400=InvalidParam, 401=Unauthorized, 403=Forbidden, 404=NotFound, 409=Conflict, 500=Internal`。

Helper：`Success` / `Created` / `BadRequest` / `Unauthorized` / `Forbidden` / `NotFound` / `Conflict` / `InternalError`。

**注意**：`HealthCheck` / `ReadyCheck` / 认证中间件 401 走裸 `gin.H`，结构与 `Response` 不一致。

---

## 7. 核心引擎

**文件**：`internal/core/engine.go`（881 行）

### 7.1 Engine 结构（engine.go:16-77）

关键字段：
- `planners map[string]ProtocolPlanner` - 协议规划器注册表
- `buildFunc func(PacketConfig) ([]byte, error)` - 包构造回调
- `replayPlanner ReplayPlanner` - 重放规划器
- `taskChan chan Task` - Task 入口队列（缓冲 QueueSize）
- `configChan chan PacketConfig` - ConfigWorker->PacketWorker（缓冲 QueueSize*2）
- `packetChan chan PacketOutput` - PacketWorker->OutputWorker（缓冲 QueueSize*2）
- `buffer *PacketBuffer` - 多视图环形缓冲
- `outputWriters map[string]PacketWriter` - 单口输出（按 taskID）
- `dualWriters map[string]*DualPortWriter` - 双口输出（按 taskID）
- `rateLimiters map[string]*TokenBucket` - 速率限流器（按 ClassID 或 ParentTaskID）
- `flowCounters map[string]*int64` - 任务级 flow 上限共享计数器（按 ParentTaskID）
- `taskStore map[string]*taskEntry` - 活跃任务表
- 回调：`OnTaskComplete` / `OnTaskFailed` / `OnBufferOverflow` / `OnOutputError` / `OnProgress`

### 7.2 EngineConfig（engine.go:126-138）

- `ConfigWorkers` / `PacketWorkers` / `OutputWorkers`
- `BufferSize` - 每个 RingBuffer 包数容量
- `QueueSize` - taskChan 缓冲；configChan/packetChan 为其 2 倍
- `MaxBufferBytes` - 单 buffer 字节上限
- `ReplayOrderPreserve` - true 时强制 PacketWorkers=1 保 pcap 顺序

### 7.3 生命周期

- `NewEngine` (engine.go:141-151)：仅初始化 map，不启动
- `Start` (engine.go:240-324)：创建 ctx/channel/buffer，启动 worker 池
- `Stop` (engine.go:327-399)：close(taskChan) -> cancel() -> wg.Wait() -> close channels -> 关闭 writers
- **无 Pause/Resume**，停止任务用 `StopTask` 取消单任务 ctx

### 7.4 Task 状态机

```
SubmitTask -> [created ->] running
  ├─ SetTaskTotalConfigs(count==0) -> completed
  ├─ SetTaskTotalConfigs(written>=count) -> completed
  ├─ OnPacketWritten(written>=count) -> completed
  ├─ FailTask -> failed (但 stopped 状态保留)
  └─ StopTask -> stopped (后续 FailTask 不覆盖)
```

### 7.5 SubmitTask（engine.go:402-516）

1. 校验 `engine.running`
2. `ValidateTask(task)`
3. maxTasks 上限检查
4. 速率限制预分配：
   - Batch: 每类 `SetClassRateLimit(taskID+":"+classID, bps)`
   - 单协议: `SetClassRateLimit(taskClassID, bps)`
   - 任务级 bps 父桶: `SetClassRateLimit(ParentTaskID, bps)`
   - 任务级 flows 计数器: `getOrCreateFlowCounter(ParentTaskID)`
5. 构造 per-task ctx（优先级：batch Duration > TaskFCType=time > Spec.Duration > 无超时）
6. 创建 taskEntry，状态置 `running`
7. 入队 taskChan（5 秒超时，失败清理 rateLimiters + taskStore）

---

## 8. Worker Pipeline

**文件**：`internal/core/worker.go`（891 行）

### 8.1 ConfigWorker（worker.go:51-580）

- 从 taskChan 拉 task，分发到 semaphore=4 的 goroutine
- `processTask` 三分支：
  - `task.Batch != nil` -> `processBatchTask`
  - `task.Mode=="replay"` -> `processReplayTask`
  - 其他 -> 单协议分支（循环 flowCount 次调 `planner.Plan()`）
- 每条 config 写 configChan，同时 select ctx.Done() drain 防止 planner goroutine 泄漏
- flows 上限：`atomic.AddInt64(flowCounter, 1) > TaskFCValue` 则 break
- Plan 失败时回滚 flowCounter
- 完成时调 `onTaskDone(taskID, err, configCount)`

### 8.2 PacketWorker（worker.go:582-726）

- 从 configChan 拉 PacketConfig
- `processConfig` (worker.go:645-717)：
  1. `packet = buildFunc(config)`
  2. 三层速率限制（见 §9）
  3. 构造 PacketOutput（保留 Timestamp）
  4. 写 packetChan

### 8.3 OutputWorker（worker.go:731-891）

- 从 packetChan 拉 PacketOutput
- `writePacket` (worker.go:802-882)：
  1. 路由：`dualWriters[taskID]` 按 Direction 分流，否则 `outputWriters[taskID]`
  2. 优先 `TimedWriter` 接口（pcap 用），否则 `WritePackets`
  3. 写 buffer（溢出只记日志，不失败）
  4. `engine.OnPacketWritten(taskID)`

### 8.4 PacketBuffer（buffer.go）

- `RingBuffer`：`mu sync.RWMutex` / `buffer [][]byte` / `head/tail/count` / `bytes/maxBytes`
- 溢出策略：`count >= size` 或 `bytes+len > maxBytes` 返回 false（**丢新包不丢旧包**）
- `PacketBuffer`：三视图 `upBuffer` / `downBuffer` / `combinedBuffer`
- Engine.Start 总是 `EnableCombined: true`
- `Get(mode)`：up/down/combined

### 8.5 重新排序（resequencer）

**当前未使用**。worker.go:728-729 注释：单 PacketWorker 保证顺序。多 PacketWorker 时需重新启用。

---

## 9. 流量控制（Flow Control）

### 9.1 三层速率限制（worker.go:661-701）

| 层级 | 触发条件 | 桶 key | 作用 |
|---|---|---|---|
| 1. Pacer | `config.Metadata["_pacer"]` 存在 | n/a | replay 时间戳/速率 |
| 2. Child bucket | `config.ClassID != ""` 且无 pacer | `classID`（`{taskID}-{strategyID}`） | per-strategy bps |
| 3. Parent bucket | `parent_task_id != ""` | `parentTaskID` | 任务级 bps 上限 |

**关键不变量**：父桶**始终**应用（即使 pacer 已运行），作 defense-in-depth。

### 9.2 TokenBucket（buffer.go:290-365）

- `NewTokenBucket(rate, burst int64)` - rate 单位是 **bytes/second**
- 初始 `tokens = burst`，按 elapsed 累积，capped at burst
- `rate=0` 视为无限
- `Wait` 循环调 Allow，失败 10ms 重试或 ctx.Done 退出
- 并发安全：`sync.Mutex`

### 9.3 FlowCounter

- 存储：`flowCounters map[string]*int64`，key 为 `parentTaskID`
- 跨策略共享：多个子任务指同一指针
- 使用：每条新 flow 前 `atomic.AddInt64(flowCounter, 1) > TaskFCValue` 则 break
- Plan 失败时 `atomic.AddInt64(flowCounter, -1)` 回滚

### 9.4 清理

- `getOrCreateFlowCounter` (engine.go:743-752)：双检锁懒创建
- `CleanupTaskFlowControl` (engine.go:759-771)：所有策略结束后调，删父桶 + 计数器 + 前缀子桶
- `cleanupTaskRateLimiters` (engine.go:572-582)：单任务完成时调，删 taskID 与 `taskID:` 前缀（**不删 parentTaskID**）

---

## 10. 协议规划器与 BatchSpec

### 10.1 ProtocolPlanner 接口（worker.go:22-32）

```go
type ProtocolPlanner interface {
    Name() string
    Plan(ctx context.Context, spec FlowSpec) (<-chan PacketConfig, error)
    Validate(spec FlowSpec) error
}
```

注册：`engine.RegisterPlanner(planner)` -> `e.planners[planner.Name()]`

### 10.2 ReplayPlanner 接口（worker.go:46-48）

```go
type ReplayPlanner interface {
    PlanReplay(ctx, specJSON, taskID, classID, userID string, fc *ReplayFC) (<-chan PacketConfig, error)
}

type ReplayFC struct {
    FlowCounter *int64  // nil=无 flows 上限
    Ceiling int64
}
```

### 10.3 BatchSpec（types.go:258-302）

- `Classes []TrafficClass`
- `Global GlobalConfig`（TotalFlows, DurationSeconds）
- `TrafficClass`：ID, Type（协议名/replay）, BPS, FlowsPerSecond, FlowCount, Tuples, Config, Replay

### 10.4 ValidateBatchSpec（convert.go:132-182）

- 至少一个 class
- class.ID 非空且唯一
- class.Type ∈ {tcp, udp, http, dns, icmp, arp, replay}
- replay 类：必有 `c.Replay` 且 `ValidateReplaySpec` 通过
- synth 类：`FlowCount > 0` + `ValidateConfigRanges` + `ValidateProtocolSubConfigs` + `ValidateFlowSpec`

### 10.5 StrategyModelToTask（strategy_convert.go:13-114）

把策略转 Task：
- `OutputType="port_group"` -> OutputMode="interface"
- 其他 -> OutputMode="pcap"
- replay 分支：`task.Replay = json.RawMessage(strategy.Config)`；speed.mode=="bps" 提取到 Spec.BPS
- synth 分支：`mapToFlowSpec(cfg, protocol)` + FlowControl 写入 spec（bps/flows/time）
- **Task.ID = `{taskID}-{strategyID}`**，ParentTaskID = taskModel.ID

---

## 11. 输出路由

### 11.1 PacketWriter 接口（engine.go:80-83）

```go
type PacketWriter interface {
    WritePackets(packets [][]byte) error
    Close() error
}
```

**TimedWriter 可选接口**（engine.go:90-92）：`WriteTimedPackets(packets []PacketOutput) error`，pcap 实现它保 scheduled send time。

### 11.2 注册机制

- `RegisterOutputWriter(taskID, writer)` (engine.go:218-222)
- `UnregisterOutputWriter(taskID)` (engine.go:227-237) - 锁内删 + 锁外 Close（PCAPWriter.Close 会 fsync）
- `RegisterDualWriter(taskID, c2s, s2c)` (engine.go:181-185)
- `UnregisterDualWriter(taskID)` (engine.go:188-203)

### 11.3 InterfaceWriter（`internal/output/interface.go`）

- `NewInterfaceWriter(iface)` -> `pcap.OpenLive(iface, 65535, true, pcap.BlockForever)`
- `Write(packets)`：持锁 + 遍历 `handle.WritePacketData(pkt)`，返回第一个错误
- adapter 在 `task_handler.go:1333-1340`（`interfacePacketWriter`）

### 11.4 PCAPWriter

- 实现在 `task_handler.go:1314`（`pcapPacketWriter.WritePackets`）
- 实现 `TimedWriter` 接口保时间戳

### 11.5 OutputType 映射

- `TaskModel.OutputType="port_group"` -> OutputMode="interface"
- 其他 -> OutputMode="pcap"
- `"both"` 字符串约定存在但未独立常量化

---

## 12. PCAP 解析器

**文件**：`internal/pcapparser/`

### 12.1 Parse 入口（parser.go:92-330）

- 拒绝 pcapng/gzip（RawOffset 必须是文件字节偏移）
- 仅支持 `LinkTypeEthernet`
- `pcapGlobalHeaderLen = 24`、`pcapRecordHeaderLen = 16`
- 单遍扫描：建 PacketModel -> computeFlowKey -> 分片处理 -> TCP 重组 -> 批转发
- EOF 后：flush TCP 流 -> 物化 `.payloads` -> finalize FlowModel -> 写 trigram 索引

### 12.2 FlowModel 提取（flow.go）

**5-tuple 归一化**：
- TCP/UDP：`flowKeyTCPUDP` 按 (IP, Port) 排序 -> `proto|a|b`
- ICMP：`flowKeyICMP` -> `1|minIP|maxIP|type|id`
- ARP：`flowKeyARP` -> `arp|op|min|sender|target|...`

**方向判定**（direction.go:30-60）：
- 首包：`DirStatus="uncertain"`，firstSrcIP/Port 作 client 候选
- 校准：
  - TCP SYN -> src 是 client
  - TCP SYN+ACK -> dst 是 client
  - UDP wellKnownServerPorts（53/67/68/123/161/162/389/636/520）-> port 侧为 server
- 校准后 `DirStatus="classified"`
- 包方向：`classifyDirection` - src==client -> `c2s`，否则 `s2c`

### 12.3 PacketModel 字段（models.go:289-307）

| 字段 | 用途 |
|---|---|
| `RawOffset` | 文件字节偏移（重解析入口） |
| `Length` | 包长 |
| `TimestampUs` | 微秒时间戳 |
| `IndexInFlow` | 流内序号 |
| `Direction` | `c2s` / `s2c` |
| `L4Protocol` | tcp/udp/icmp/arp |
| `PayloadHash` | sha256(L4 payload) |
| `AnomalyFlag` | truncated/oversize/undersize |
| `FragGroupID` | 分片组 ID |
| `FragOffset` | 分片偏移（8 字节单位），-1=非分片 |

### 12.4 OffsetLayout（offset.go:17-46）

```go
type OffsetLayout struct {
    L2Start, L3Start, L4Start int
    SrcMAC, DstMAC int           // L2
    VlanTCO int                  // VLAN TCI（-1=无 VLAN）
    SrcIP, DstIP int             // IPv4 only
    TTL, DSCPECN, IPFlagsFrag, IPID int
    SrcPort, DstPort int
    Seq, Ack, Window, TCPFlags int // TCP
    L4Protocol string            // tcp|udp|icmp|arp|ipv6
}
```

`ExtractOffsetLayout` (offset.go:71-121) 按层 contents 累加偏移。

### 12.5 支持的协议

- TCP：握手追踪、SYN options（MSS/WindowScale/SACK）、seq 范围、重传/乱序计数
- UDP：每包独立 payload
- HTTP：文本协议识别
- DNS：query_name 提取
- TLS：SNI 从 ClientHello 提取
- ICMP：echo 按 (type, id) 区分
- ARP：按 op + sender/target 分组

### 12.6 Fragmented TCP（fragment.go:55-99）

- 按 `(IPID+src+dst+proto)` 分组
- 第一分片（offset=0）作基帧
- 末分片（MF=0）记录总 payload 长度
- 完整组 -> `tryReassemble` 拼回完整 IP datagram -> `feedReassembledToAssembler`

---

## 13. 回放子系统

**文件**：`internal/replay/`

### 13.1 ReplaySpec（types.go:13-22）

| 字段 | 取值 | 含义 |
|---|---|---|
| `PcapAssetID` | asset UUID | 引用资产 |
| `Loop` | 0=无限（v1 强制 1） | 重放轮数 |
| `Speed` | ReplaySpeed | 速率模型 |
| `Direction` | `single` / `dual` | 单/双端口 |
| `ChecksumMode` | `recompute`(默认) / `preserve` | 校验和策略 |
| `Rewrites` | []RewriteRule | 重写规则 |
| `FlowScaling` | *FlowScaling | 多流放大（可选） |
| `Inject` | *InjectConfig | v2 预留异常注入 |

**ReplaySpeed.Mode**：`original` / `multiplier` / `bps` / `""`（max 折叠为空，pps 已移除）

### 13.2 ReplayPlanner.Plan（planner.go:75-314）

1. 加载校验 asset（user-scoped，status==ready）
2. 加载 flows，预计算 per-flow patches
3. 加载 packets（按 RawOffset 文件序）；**空 pcap 报错**（M6 修复）
4. Pacer 选择（R-F2 不变量）：

| Speed.Mode | fc==nil（batch） | fc!=nil（单协议） |
|---|---|---|
| original/multiplier | TimestampPacer | TimestampPacer |
| bps | TokenBucketPacer | nil（走 engine 子桶） |
| ""/max | MaxPacer | nil |

5. 同步打开 pcap 文件 + 校验 FlowScaling + 预生成 clones（M1 修复：失败同步返回 error）
6. goroutine 循环产出 PacketConfig

### 13.3 Patch 组装（planner.go:397-422）

`assemblePatches` 组装四类：
1. 流级 patches（ipmap/portmap/field set）
2. endpoint patches（方向相关，c2s 改 src，s2c 改 dst）
3. apply:offset patches（`new = orig + delta`，保流内 delta）
4. macmap patches（从 raw 读 MAC，查映射表）

### 13.4 countFlow 闭包（planner.go:160-177）

- `seen` map 去重 flow ID（多包流只计一次）
- `skipped` map 记录超 ceiling 的 flow
- `atomic.AddInt64(fc.FlowCounter, 1)` 跨协程安全
- **M3 已知限制**：seen map 每 Plan 一份，多 strategy 重复计数（见 §18）

### 13.5 FlowScaling

- **Stack 模式**（默认）：外层包 -> 内层克隆
- **Serial 模式**：外层克隆 -> 内层包（clone 1 跑完全部包，再 clone 2）
- 跨轮时间偏移：`loopBase += pcapDuration`（lastTs - firstTs）

### 13.6 Pacer 实现（pacing.go）

| Pacer | 机制 | 并发安全 |
|---|---|---|
| `TimestampPacer` | 按原始时间戳调度，drift 吸收避免追赶 burst | sync.Mutex |
| `TokenBucketPacer` | bps 限速，sync.Once 延迟初始化 | 底层 TokenBucket mutex |
| `MaxPacer` | 不限速 | n/a |
| `PPSPacer` | pps 限速（**已从 NewPacer 移除，dead code 但有测试**） | mu 跨 sleep 串行化 |

### 13.7 Rewriter（rule.go + rewriter.go + checksum.go）

**RewriteRule.Kind**：
- `field` - 单字段 override
- `endpoint` - 双向端点（方向相关）
- `ipmap` - IP 映射（精确 + CIDR 平移）
- `portmap` - 端口映射
- `macmap` - MAC 映射（per-packet，MAC 不在 FlowModel）

**apply:offset**（planner.go:452-472）：`newVal = orig + delta`（uint32/uint16 自然 wrap）

**checksum_mode**（rewriter.go:21-51）：
- `recompute`（默认）：始终重算 IP + L4
- `preserve`：仅 patch 触及 L3/L4 时强制重算
- L2 patch 不触发重算

### 13.8 fieldSpecFor（rule.go:84-116）

| target | layer | width |
|---|---|---|
| src_ip/dst_ip | l3 | 4 |
| src_port/dst_port | l4 | 2 |
| src_mac/dst_mac | l2 | 6 |
| ttl | l3 | 1 |
| dscp/ecn | l3 | 1（同一字节 TOS） |
| ip_id | l3 | 2 |
| seq/ack | l4 | 4（TCP） |
| window | l4 | 2（TCP） |
| tcp_flags | l4 | 1（TCP） |

---

## 14. 网络接口管理

**文件**：`pkg/netif/`

### 14.1 Manager（manager.go）

- `Interface` 结构：Name, MAC, IPs, IsUp, LinkUp, MTU, Description, IsVirtual
- 虚拟接口识别：黑名单（`any`/`lo`）+ 前缀白名单（`nf`/`usbmon`/`bluetooth`/`bridge`/`docker`/`veth`/`virbr`/`vnic`/`cni-`/`flannel`/`tun`/`tap`/`gre`/`sit`/`ipip`/`wg`/`ovs-`/`br-`）
- `Discover()`：`pcap.FindAllDevs()` + `net.Interfaces()` 合并，非虚拟接口探测 link
- `Get/List/Refresh/ValidateInterface`
- `GetMAC(name)` / `GetIP(name)` 返回 `IPs[0]`

### 14.2 Scheduler（scheduler.go）- 端口分配器

**不是任务定时器**，只做端口分配的并发控制与过期回收。

- `PortAllocation`：Interface, Port, TaskID, AllocatedAt, ExpiresAt
- `AllocatePortWithContext(ctx, iface, port, taskID)`：已分配则入 waitQueue
- `ReleasePort` / `ReleaseByTask`
- `StartAutoRelease(30s)` - main.go:166 传入

### 14.3 dual-port 模式

**未在 netif 内实现**。`Interface` 是单数结构，双口需调用方用两个实例。replay 的 `Direction="dual"` + `Interface2` 字段在 task 层处理。

---

## 15. WebSocket 实时推送

**文件**：`internal/api/websocket/handler.go`

- **端点**：`GET /ws`（server.go:102）
- **认证**：WS 升级时校验 JWT（`Handler.SetJWTManager`）
- **客户端协议**：
  - `{type:"subscribe", task_id:"..."}` -> `{type:"subscribed"}`
  - `{type:"unsubscribe", task_id:"..."}` -> `{type:"unsubscribed"}`
  - `{type:"ping"}` -> `{type:"pong"}`
- **服务端推送类型**：
  - `status_update` - 任务状态变更
  - `stats_update` - 实时统计
  - `progress_update` - 进度（0-100，节流 ≥2s）
  - `task_completed` / `task_failed`
  - `error` / `heartbeat`
- **载体**：`{Type string, Data interface{}, Timestamp int64}`

---

## 16. 工具包

### 16.1 pkg/logger

- zap 全局：`Log *zap.Logger` / `Sugar *zap.SugaredLogger`
- `atom zap.AtomicLevel` 支持运行时改级别
- `Init(cfg)` / `SetLevel(level)` / `Sync()`
- 输出：stdout/stderr/文件（OpenFile O_APPEND|O_CREATE|O_WRONLY）

### 16.2 pkg/metrics

Prometheus 指标（17 个）：

| 指标 | 类型 | Labels |
|---|---|---|
| `trafficgen_packets_sent_total` | Counter | protocol, interface |
| `trafficgen_bytes_sent_total` | Counter | protocol, interface |
| `trafficgen_packets_dropped_total` | Counter | reason |
| `trafficgen_flows_created_total` | Counter | protocol |
| `trafficgen_flows_completed_total` | Counter | protocol, status |
| `trafficgen_active_tasks` | Gauge | - |
| `trafficgen_active_flows` | Gauge | - |
| `trafficgen_buffer_usage` | Gauge | buffer |
| `trafficgen_buffer_size` | Gauge | buffer |
| `trafficgen_task_duration_seconds` | Histogram | protocol |
| `trafficgen_packet_latency_seconds` | Histogram | stage |
| `trafficgen_worker_queue_length` | Gauge | worker_type |
| `trafficgen_api_requests_total` | Counter | method, path, status |
| `trafficgen_api_latency_seconds` | Histogram | method, path |
| `trafficgen_websocket_connections` | Gauge | - |
| `trafficgen_port_allocations` | Gauge | - |
| `trafficgen_port_wait_queue` | Gauge | - |

### 16.3 pkg/version

- `Version = "1.0.0"` / `GitCommit = "unknown"` / `BuildDate = "unknown"`
- **注意**：main.go:35 有独立 `version = "1.0.0"`，与 pkg/version 不同步

---

## 17. 关键不变量与设计约束

### 17.1 R-F2：Pacer 与任务级 bps 互斥

TimestampPacer（original/multiplier）与任务级 bps 父桶**永不在同一包上相遇**。

- original/multiplier + 任务级 bps -> **校验拒绝**（`validateReplayBPSConflict`，Create + Start 两道）
- bps/空 -> pacer=nil，走 engine 子桶/父桶

### 17.2 STRAT4-BR2：校验先于所有权检查

Update 策略时，坏输入 -> 400，无论策略是否存在/归属。

- 显式 mode：先校验后查 DB
- 空 mode（方案 A）：从 DB 读现有 mode 按该 mode 校验；未命中则 fallback 到 synth 校验，坏输入仍 400，好输入校验通过后 404

### 17.3 父桶始终应用

`processConfig` 中父桶（parentTaskID）**始终**应用，即使 pacer 已运行。作 defense-in-depth 防止 pacer 驱动的 replay 绕过任务级 bps 上限。

### 17.4 user_id 隔离

- PcapRepository：repository 层强制
- Task/Strategy/History：handler 层强制（`WHERE user_id = ?`）
- 资源归属检查返回 404（不返回 403，防越权探测）

### 17.5 单 PacketWorker 保序

`ReplayOrderPreserve && PacketWorkers > 1` -> 强制 PacketWorkers=1。replay 必须保 pcap 文件顺序。

### 17.6 停止状态保留

`FailTask` 看到 `stopped` 状态不覆盖为 `failed`，避免用户主动 stop 被报失败。

---

## 18. 已知限制与遗留问题

### 18.1 M3：counter 跨策略 over-counting

`planner.go` countFlow 的 `seen` map 是 per-Plan-call（per-strategy），但 `fc.FlowCounter` 跨策略共享。两个策略都含同一 flow X 时，各自 seen 独立记录 X，counter 被加两次 -> 提前触顶跳过。under-count 不可能。修复需把 seen 提到 fc 级别。

### 18.2 RBAC 中间件未挂载

`RBACMiddleware` 已定义但 `server.go` 未 `api.Use(RBACMiddleware(...))`。admin 鉴权靠 handler 内 `auth.IsAdmin(c)` 手动判断。

### 18.3 TaskRepository 无 user_id 隔离

Task/Strategy/History Repository 全部方法无 user_id 过滤，隔离完全在 handler 层。若未来新增调用方忘记带 user_id，存在越权风险。

### 18.4 resequencer 未启用

多 PacketWorker 时包顺序不保证。当前靠 `ReplayOrderPreserve` 强制单 worker 保序，但 synth 模式多 worker 时不重排。

### 18.5 dual-port 未在 netif 内实现

`Interface` 是单数结构，双口需调用方用两个实例。replay 的 `Direction="dual"` + `Interface2` 在 task 层处理。

### 18.6 version 不同步

main.go:35 硬编码 `version = "1.0.0"`，与 `pkg/version` 不同步，未用 ldflags 注入。

### 18.7 HealthCheck/ReadyCheck 响应格式不一致

走裸 `gin.H`，与业务 `Response{Code, Message, Data}` 结构不一致。

### 18.8 显式非法 mode 未拒绝

Update 策略时 `req.Mode = "garbage"` 不在 synth/replay 之列，但代码走 else 当 synth 校验，写入 DB 的 `strategy.Mode` 用原 garbage 值。方案 A 之前就存在。

---

## 19. 关键文件索引

| 模块 | 文件 |
|---|---|
| 入口 | `cmd/server/main.go` |
| 路由注册 | `internal/api/rest/server.go:84-233` |
| 认证 handler | `internal/api/rest/auth_handler.go` |
| 策略 handler | `internal/api/rest/strategy_handler.go` |
| 任务 handler | `internal/api/rest/task_handler.go` |
| PCAP handler | `internal/api/rest/pcap_handler.go` |
| 系统 handler | `internal/api/rest/system.go` |
| 响应 helper | `internal/api/rest/response.go` |
| WebSocket | `internal/api/websocket/handler.go` |
| Engine | `internal/core/engine.go` |
| Worker | `internal/core/worker.go` |
| Buffer | `internal/core/buffer.go` |
| Types | `internal/core/types.go` |
| Builder | `internal/core/builder.go` |
| Validate | `internal/core/validate.go` |
| Convert | `internal/core/convert.go` |
| Strategy Convert | `internal/core/strategy_convert.go` |
| Tuple Generator | `internal/core/tuple_generator.go` |
| Replay Planner | `internal/replay/planner.go` |
| Pacer | `internal/replay/pacing.go` |
| Rewriter | `internal/replay/rewriter.go` + `rule.go` + `checksum.go` |
| Replay Types | `internal/replay/types.go` |
| PCAP Parser | `internal/pcapparser/parser.go` |
| Flow | `internal/pcapparser/flow.go` |
| Direction | `internal/pcapparser/direction.go` |
| Fragment | `internal/pcapparser/fragment.go` |
| Offset | `internal/pcapparser/offset.go` |
| Storage Models | `internal/storage/models.go` |
| DB | `internal/storage/db.go` |
| Pcap Repository | `internal/storage/pcap_repository.go` |
| Interface Writer | `internal/output/interface.go` |
| JWT/RBAC | `pkg/auth/auth.go` |
| Auth Middleware | `pkg/auth/middleware.go` |
| Config | `pkg/config/config.go` |
| Logger | `pkg/logger/logger.go` |
| Netif Manager | `pkg/netif/manager.go` |
| Port Scheduler | `pkg/netif/scheduler.go` |
| Metrics | `pkg/metrics/metrics.go` |
| Version | `pkg/version/version.go` |

---

## 附：MCP 设计参考要点

基于本知识图谱，MCP 层设计应考虑：

1. **能力域划分**：按本文件的 §6 路由分组（认证/用户/策略/任务/PCAP/系统）映射为 MCP tool 命名空间
2. **认证透传**：MCP server 需持有 JWT 或用 service account，所有调用透传 user_id 隔离
3. **长任务处理**：Task 创建是异步的，MCP tool 需暴露 Create + Start + 轮询 Get 或订阅 WebSocket
4. **文件传输**：PCAP 上传走 multipart，MCP tool 需支持二进制 base64 或引用本地路径
5. **错误映射**：业务 `Response.Code` 非 0 映射为 MCP error；注意 HealthCheck/middleware 401 走裸 gin.H
6. **实时数据**：WebSocket 推送的 `stats_update` / `progress_update` 可映射为 MCP resource 订阅
7. **幂等性**：策略和任务创建都支持幂等（config_hash / sorted strategy_ids），MCP tool 可安全重试
