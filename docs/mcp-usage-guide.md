# flowB MCP 使用文档

本文档告诉你**怎么用** trafficgen 的 MCP 服务器。设计文档见 [mcp-design.md](./mcp-design.md)。

本文档顺序：**先讲配置 → 再讲客户端怎么接 → 再讲 14 个工具 → 再讲业务场景与错误处理**。

---

## 1. 概述

flowB MCP 服务器把 trafficgen 后端**全部能力**以 MCP 工具的形式暴露给 LLM 客户端（Claude Desktop、Claude Code、Cursor、VS Code Copilot 等）。

- **14 个工具**：9 个域工具 + 5 个工作流工具，覆盖后端全部功能。
- **双传输**：
  - **stdio**：本地 LLM 客户端（Claude Desktop、Cursor 等），零鉴权。
  - **HTTP / Streamable HTTP**：远程 LLM 客户端（claude-code、Web 集成等），需要 `X-MCP-Key` 鉴权 + CORS。
- **同进程部署**：MCP 与 REST API 共享同一进程，复用 engine、db、ifaceMgr 等核心组件。MCP 工具不经过 HTTP 网络，通过构造 `gin.Context` 直接调用 REST handler 方法。

### 1.1 关键事实（务必先读）

1. **trafficgen 二进制只有一个入口**：`trafficgen --config /path/to/config.yaml`。没有 `mcp-serve` 子命令。
2. **MCP 由配置驱动**：在 `config.yaml` 里把 `mcp.enabled` 设为 `true`，启动主进程时 MCP 就在同一进程内自动启动 stdio 和/或 HTTP 传输。**stdio 与 HTTP 可以同时启用**——主进程同时监听 stdin 和 HTTP 端口。
3. **stdio 与 REST/HTTP 服务共存**：主进程既起 REST API、WebSocket、Metrics，也起 MCP stdio 与 MCP HTTP。不需要为了 MCP 起第二个进程。
4. **stdio 模式下日志强制走 stderr**：MCP JSON-RPC 拥有 stdout，主进程在检测到 stdio + 日志输出=stdout 时会自动把日志重定向到 stderr，避免污染 JSON-RPC 流。

---

## 2. 配置（服务端）

### 2.1 最小可用配置：仅 stdio（本地）

`config.yaml`：

```yaml
mcp:
  enabled: true
  service_user_id: "mcp-service"
  service_user_role: "user"
  service_account_password: "flowb-mcp-change-me"
  # api_key 留空，stdio 模式不需要
  api_key: ""

  transports:
    stdio: true
    http:
      enabled: false

  max_wait_timeout_seconds: 3600
  audit_log: true
```

启动：

```bash
trafficgen --config /path/to/config.yaml
```

启动后，主进程在 stdin 上等待 JSON-RPC 消息。LLM 客户端（Claude Desktop 等）通过启动该进程作为子进程、用 stdin/stdout 与之通信。

### 2.2 最小可用配置：仅 HTTP（远程，主要场景）

`config.yaml`：

```yaml
mcp:
  enabled: true
  service_user_id: "mcp-service"
  service_user_role: "user"
  service_account_password: "flowb-mcp-change-me"
  # HTTP 传输必须配置非空 api_key，否则 NewHTTPServer 拒绝启动
  api_key: "flowb-remote-KEY-CHANGE-ME-TO-A-LONG-RANDOM-STRING"

  transports:
    stdio: false        # 关掉 stdio，避免抢占 stdout
    http:
      enabled: true
      listen: "127.0.0.1:8081"
      # 允许的浏览器 Origin。默认仅 localhost 任意端口。
      # 生产环境按需放宽；"*" 允许全部（仅建议开发环境）
      cors_origins:
        - "http://localhost:*"
        - "http://127.0.0.1:*"
        # - "https://your-frontend.example.com"

  max_wait_timeout_seconds: 3600
  audit_log: true
```

启动：

```bash
trafficgen --config /path/to/config.yaml
```

启动后，`POST http://127.0.0.1:8081/mcp` 为 MCP 端点。

**远程访问（LAN/公网）**：把 `listen` 改成 `0.0.0.0:8081` 或具体内网 IP；同时把 `cors_origins` 显式列出允许的前端 Origin（不要用 `*`）。SDK 默认启用 DNS rebinding 防护，公网域名无法访问 localhost 绑定的服务器。

### 2.3 stdio + HTTP 同时启用（开发调试）

```yaml
mcp:
  enabled: true
  service_user_id: "mcp-service"
  service_user_role: "user"
  service_account_password: "flowb-mcp-change-me"
  api_key: "dev-key-change-me"

  transports:
    stdio: true            # 本地客户端用 stdio
    http:
      enabled: true         # 远程客户端用 HTTP
      listen: "127.0.0.1:8081"
      cors_origins:
        - "http://localhost:*"

  audit_log: true
```

同一个进程同时接受 stdin（stdio）和 HTTP 请求。开发时方便对比两种传输的行为。

### 2.4 service account 要求

服务器启动时会按 `service_user_id` 查找用户。该用户必须满足：

1. 存在于 `users` 表；
2. `enabled=true`；
3. `role=user`（非 admin）——service account 使用普通用户角色实现数据自隔离。

SQL 示例：

```sql
INSERT INTO users (id, username, password_hash, email, role, enabled)
VALUES (UUID(), 'mcp-service', '<bcrypt-hash>', 'mcp@trafficgen.local', 'user', true);
```

### 2.5 配置项参考

| 字段                                  | 默认值                                          | 说明                                                            |
|---------------------------------------|------------------------------------------------|-----------------------------------------------------------------|
| `mcp.enabled`                         | `false`                                         | 总开关                                                          |
| `mcp.service_user_id`                 | `"mcp-service"`                                | service account 用户名（必须在 users 表存在且 enabled）         |
| `mcp.service_user_role`               | `"user"`                                        | 应为 `user`，不建议 `admin`                                     |
| `mcp.service_account_password`       | `"flowb-mcp-change-me"`                        | 仅在 service account 未登录场景下用于内部凭据                  |
| `mcp.api_key`                         | `""`                                           | HTTP 传输鉴权密钥，stdio 不需要；HTTP enabled 时**必须非空**     |
| `mcp.transports.stdio`                | `true`                                         | stdio 传输开关                                                  |
| `mcp.transports.http.enabled`         | `false`                                        | HTTP 传输开关                                                   |
| `mcp.transports.http.listen`          | `"127.0.0.1:8081"`                             | HTTP 绑定地址                                                   |
| `mcp.transports.http.cors_origins`    | `["http://localhost:*","http://127.0.0.1:*"]` | 允许的 Origin；`*` 允许全部（仅开发）；末尾 `:*` 视为端口通配  |
| `mcp.max_wait_timeout_seconds`        | `3600`                                         | `flowb_wait_for_task` 硬上限（实际再被钳到 300s）               |
| `mcp.audit_log`                       | `true`                                         | 工具调用审计日志（zap）                                         |
| `mcp.max_subscriptions`              | `100`                                          | 并发订阅上限                                                    |

---

## 3. 客户端配置（怎么把 flowB 接到 LLM 工具）

### 3.1 Claude Desktop（stdio）

编辑 `~/Library/Application Support/Claude/claude_desktop_config.json`（macOS）或 `%APPDATA%\Claude\claude_desktop_config.json`（Windows）：

```json
{
  "mcpServers": {
    "flowb": {
      "command": "/opt/trafficgen/bin/trafficgen",
      "args": ["--config", "/opt/trafficgen/etc/config.yaml"],
      "env": {
        "HOME": "/opt/trafficgen"
      }
    }
  }
}
```

要求：
- `config.yaml` 里 `mcp.enabled=true` 且 `mcp.transports.stdio=true`；
- `mcp.transports.http.enabled=false`（stdio 模式下不需要 HTTP）；
- Claude Desktop 会把 trafficgen 当作子进程启动，通过 stdin/stdout 与之通信。

重启 Claude Desktop 后，在对话框右下角的工具图标中应能看到 `flowb` 的 14 个工具。

### 3.2 Claude Code（stdio）

Claude Code 通过 `~/.config/claude-code/mcp_servers.json` 或项目级 `.claude/mcp_servers.json` 配置：

```json
{
  "mcpServers": {
    "flowb": {
      "command": "/opt/trafficgen/bin/trafficgen",
      "args": ["--config", "/opt/trafficgen/etc/config.yaml"],
      "cwd": "/opt/trafficgen"
    }
  }
}
```

或者在 shell 启动时通过 CLI 注册（推荐做法）：

```bash
claude mcp add flowb -- /opt/trafficgen/bin/trafficgen --config /opt/trafficgen/etc/config.yaml
```

注册完成后，`claude` 交互界面内可以用 `/mcp` 查看状态，自然语言对话即可触发 `flowb_*` 工具。

### 3.3 Cursor（stdio）

编辑 `~/.cursor/mcp.json`（用户级）或项目 `.cursor/mcp.json`：

```json
{
  "mcpServers": {
    "flowb": {
      "command": "/opt/trafficgen/bin/trafficgen",
      "args": ["--config", "/opt/trafficgen/etc/config.yaml"]
    }
  }
}
```

Cursor Settings → MCP → 看到绿色指示灯即连上。Composer 内可用自然语言调用工具。

### 3.4 VS Code Copilot（stdio，0.55+）

`.vscode/mcp.json`：

```json
{
  "servers": {
    "flowb": {
      "type": "stdio",
      "command": "/opt/trafficgen/bin/trafficgen",
      "args": ["--config", "/opt/trafficgen/etc/config.yaml"]
    }
  }
}
```

### 3.5 远程 HTTP 客户端（claude-code、Cline、Web 前端等）

适用场景：flowB 服务器在远程机器/容器里，LLM 客户端在本地或浏览器里。

**Claude Code（HTTP 模式）**：

```bash
claude mcp add --transport http flowb http://flowb-host:8081/mcp \
  --header "X-MCP-Key: flowb-remote-KEY-CHANGE-ME"
```

或写入配置文件：

```json
{
  "mcpServers": {
    "flowb": {
      "type": "http",
      "url": "http://flowb-host:8081/mcp",
      "headers": {
        "X-MCP-Key": "flowb-remote-KEY-CHANGE-ME"
      }
    }
  }
}
```

**Cline（VS Code 扩展，HTTP 模式）**：

`.cline/mcp_settings.json`：

```json
{
  "mcpServers": {
    "flowb": {
      "url": "http://flowb-host:8081/mcp",
      "headers": {
        "X-MCP-Key": "flowb-remote-KEY-CHANGE-ME"
      }
    }
  }
}
```

**curl（手动验证）**：

```bash
# 1) initialize —— 响应头里拿到 Mcp-Session-Id
curl -i -X POST http://flowb-host:8081/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "X-MCP-Key: flowb-remote-KEY-CHANGE-ME" \
  -d '{
    "jsonrpc":"2.0","id":1,"method":"initialize",
    "params":{
      "protocolVersion":"2025-11-25",
      "capabilities":{},
      "clientInfo":{"name":"curl","version":"1.0.0"}
    }
  }'

# 2) tools/list —— 列出全部 14 个工具
curl -X POST http://flowb-host:8081/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "X-MCP-Key: flowb-remote-KEY-CHANGE-ME" \
  -H "Mcp-Session-Id: <从上一步响应头复制>" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'

# 3) tools/call —— 调一个工具
curl -X POST http://flowb-host:8081/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "X-MCP-Key: flowb-remote-KEY-CHANGE-ME" \
  -H "Mcp-Session-Id: <session-id>" \
  -d '{
    "jsonrpc":"2.0","id":3,"method":"tools/call",
    "params":{
      "name":"flowb_query_system",
      "arguments":{"action":"status"}
    }
  }'
```

**Go SDK 客户端**：

```go
httpClient := &http.Client{
    Transport: &apiKeyTransport{
        base:   http.DefaultTransport,
        apiKey: "flowb-remote-KEY-CHANGE-ME",
    },
}
transport := &mcp.StreamableClientTransport{
    Endpoint:   "http://flowb-host:8081/mcp",
    HTTPClient: httpClient,
}
client := mcp.NewClient(&mcp.Implementation{Name: "my-app", Version: "v1.0.0"}, nil)
session, err := client.Connect(ctx, transport, nil)
// session.CallTool(ctx, &mcp.CallToolParams{Name: "flowb_query_system", Arguments: ...})
```

`apiKeyTransport` 的实现就是把 `X-MCP-Key` 头加到每个出站请求：

```go
type apiKeyTransport struct {
    base   http.RoundTripper
    apiKey string
}

func (t *apiKeyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
    req.Header.Set("X-MCP-Key", t.apiKey)
    return t.base.RoundTrip(req)
}
```

### 3.6 鉴权与 CORS 注意事项（HTTP 模式必读）

- **`X-MCP-Key` 必填**：每个请求（含 `initialize`、`tools/list`、`tools/call`、SSE GET）都必须带 `X-MCP-Key` 头，值等于服务端 `mcp.api_key`。比较用 `crypto/subtle.ConstantTimeCompare`，防时序攻击。
- **`Mcp-Session-Id`**：首次 `initialize` 响应头里返回，后续请求必须回传。Session 空闲 30 分钟自动过期。
- **CORS（浏览器前端必读）**：
  - 默认 `cors_origins = ["http://localhost:*", "http://127.0.0.1:*"]`，末尾 `:*` 视为端口通配符——`http://localhost:3000` / `http://localhost:5173` 都能匹配。
  - 生产环境必须显式列出允许的前端 Origin，不要用 `*`。
  - 中间件顺序：CORS 在 API key 外层——浏览器 preflight（OPTIONS）按规范不能携带自定义 header，CORS 在外层才能让 preflight 直接返回 204 + CORS 头。
  - 响应头里包含 `Access-Control-Expose-Headers: Mcp-Session-Id` 和 `Vary: Origin`，前端 JS 才能读到 session id。

---

## 4. 工具详解

每个工具通过 `action` 字段选择具体操作。输入字段使用 `jsonschema` 描述，LLM 据此构造参数。

### 4.1 `flowb_query_system` — 系统查询

```jsonc
{ "action": "status|protocols|stats|health|ready|interfaces|ports|refresh_interfaces" }
```

| action              | 用途                                              |
|---------------------|---------------------------------------------------|
| `status`            | 综合状态（版本、运行时长、引擎状态、任务计数）        |
| `protocols`         | 支持的协议列表（tcp/udp/http/dns/icmp/arp）          |
| `stats`             | 性能统计（缓冲区、worker、内存）                     |
| `health`            | 健康检查（always 200，返回引擎/DB 状态）             |
| `ready`             | 就绪检查（引擎未就绪时 503）                         |
| `interfaces`        | 网络接口列表（含状态、速率、MAC）                    |
| `ports`             | 端口组绑定的物理端口                                |
| `refresh_interfaces`| 刷新接口缓存                                        |

### 4.2 `flowb_manage_strategies` — 策略管理

```jsonc
{
  "action": "create|list|get|update|delete|list_tasks",
  "id": "<strategy-id>",            // for get/update/delete/list_tasks
  "name": "...",                    // for create
  "mode": "synth|replay",           // for create
  "protocol": "tcp|udp|http|dns|icmp|arp|replay",
  "config": { /* protocol-specific */ },
  "flow_control": { /* optional */ },
  "page": 1, "size": 20,            // for list
  "sort_by": "created_at|updated_at|name",
  "sort_order": "ascending|descending"
}
```

### 4.3 `flowb_manage_users` — 用户管理（admin only）

```jsonc
{
  "action": "list|get|update|delete|reset_password",
  "id": "<user-id>",
  "email": "new@example.com",
  "role": "admin|user|guest",
  "enabled": true
}
```

> service account 角色=user，所有 admin-only 动作返回 403。该工具为 Phase 3 多用户模式预留。

### 4.4 `flowb_manage_auth` — 认证

```jsonc
{
  "action": "register|login|validate|logout|refresh",
  "username": "...",
  "email": "...",
  "password": "...",
  "token": "..."                    // for validate/logout/refresh
}
```

MCP 在 `validate/logout/refresh` 时会**查 DB 校验 token 状态**：JWT 签名有效但 `tokens.status != "active"`（已 logout/revoked）的 token 会被拒绝。这是防止 LLM 持有陈旧 token 绕过撤销。

### 4.5 `flowb_manage_profile` — 当前用户资料

```jsonc
{
  "action": "get|update|delete",
  "email": "...",
  "password": "...",                // for update (new) OR delete (confirm)
  "new_password": "..."             // for update (alternative)
}
```

### 4.6 `flowb_manage_pcaps` — PCAP 资产（17 个动作）

```jsonc
{
  "action": "import|list|get|delete|list_flows|get_flow|list_packets|list_packets_by_asset|get_packet|get_packet_payload|get_stream|get_body|search|match_preview|extract|download|reparse",
  "id": "<asset-id>",               // required for all except import/list
  "file_path": "/abs/path.pcap",    // import only; MUST be absolute, no traversal
  "flow_id": "<flow-id>",           // get_flow/list_packets/get_stream/get_body
  "packet_id": "<packet-id>",       // get_packet/get_packet_payload
  "direction": "c2s|s2c",           // get_stream/get_body
  "offset": 0, "limit": 65536,      // get_stream (optional byte range)
  "filters": { /* search spec */ },
  "extract_rules": { /* extract spec */ },
  "matcher": { /* match_preview FlowMatcher */ },
  "force": false,                   // delete even if referenced
  "page": 1, "size": 50,            // list/list_flows/list_packets
  "status": "ready|importing|error|reindexing"
}
```

**二进制内容编码**：`get_packet_payload` / `get_stream` / `get_body` 返回：

```json
{ "payload_base64": "<base64>", "length": 1234 }
```

空流时 `payload_base64=""`、`length=0`（不再返回 JSON envelope 的 base64，避免 LLM 误以为是真实 payload）。

**路径校验**：`import` 要求 `file_path` 为绝对路径且 `filepath.Clean` 后与原值一致，拒绝 `../`、`./`、`//` 等可疑模式。

### 4.7 `flowb_manage_port_groups` — 端口组

```jsonc
{
  "action": "create|list|get|delete",
  "id": "<port-group-id>",
  "name": "...",                    // for create
  "interfaces": ["enp1s0", "enp2s0"]
}
```

### 4.8 `flowb_manage_settings` — 全局设置

```jsonc
{
  "action": "get|update",
  "max_tasks": 10,                  // max concurrent tasks (applies immediately)
  "buffer_size": 2048,              // ring buffer size (applies on next restart)
  "log_level": "debug|info|warn|error"
}
```

### 4.9 `flowb_manage_tasks` — 任务管理

```jsonc
{
  "action": "create|create_batch|list|get|start|stop|delete|history",
  "id": "<task-id>",                // for get/start/stop/delete
  "name": "...",                    // for create/create_batch
  "strategy_ids": ["..."],          // for create
  "batch": { /* batch spec */ },    // for create_batch
  "output_type": "port_group|pcap",
  "output_config": {
    "port_group_id": "...",         // for output_type=port_group
    "pcap_path": "/abs/path.pcap",  // for output_type=pcap
    "interface2": "enp2s0"          // for dual-port replay
  },
  "flow_control": { /* optional task-level */ },
  "page": 1, "size": 20,            // for list/history
  "status": "running|completed|...",// filter
  "sort_by": "created_at|updated_at|name|status|progress",
  "sort_order": "ascending|descending",
  "start_time": 0, "end_time": 0    // history filter (unix seconds)
}
```

### 4.10 `flowb_generate_traffic` — 一键生成流量

最高频使用的工作流：创建策略 → 创建任务 → 启动任务。

```jsonc
{
  "task_name": "my-traffic",
  "protocol": "tcp|udp|http|dns|icmp|arp",
  "config": { /* protocol-specific */ },
  "strategy_flow_control": { /* optional strategy-level */ },
  "task_flow_control": { /* optional task-level aggregate ceiling */ },
  "output_type": "port_group|pcap",
  "output_config": { /* see 4.9 */ }
}
```

返回 `{task_id, strategy_id, status}`。`status="running"` 表示已启动；`status="created"` 表示任务已建但启动失败（返回 `task_id` 让 LLM 重试 start）。

### 4.11 `flowb_get_task_progress` — 任务进度

```jsonc
{ "task_id": "..." }
```

返回任务的完整状态 JSON（status/progress/pps/bps/packets_sent 等）。

### 4.12 `flowb_stop_all_tasks` — 停止所有运行中任务

```jsonc
{}
```

自动分页列出当前用户所有 `status=running` 的任务并逐个 stop（每页 100，最多 100 页 = 10,000 任务）。返回 `{stopped: [...], errors: [{task_id, error}]}`。

### 4.13 `flowb_wait_for_task` — 阻塞等待任务终态

```jsonc
{
  "task_id": "...",
  "timeout_seconds": 60,            // default 60, max 300
  "poll_interval_seconds": 2        // default 2, min 1
}
```

阻塞直到任务进入 `completed|stopped|error|failed` 或超时。短任务用此工具，长任务用 `flowb_get_task_progress` 轮询。

### 4.14 `flowb_replay_pcap` — 一键回放 PCAP

```jsonc
{
  "task_name": "replay-1",
  "pcap_asset_id": "<asset-id>",
  "loop": 0,                        // 0=infinite
  "speed": {
    "mode": "original|multiplier|bps",  // pps/max 被拒绝
    "multiplier": 2.0,               // for mode=multiplier
    "bps": "100M"                    // for mode=bps
  },
  "direction": "single|dual",       // default single
  "checksum_mode": "recompute|preserve",
  "rewrites": [ /* rewrite rules */ ],
  "flow_scaling": { /* optional */ },
  "strategy_flow_control": { /* optional; replay only supports type=time */ },
  "task_flow_control": { /* optional task-level */ },
  "output_type": "port_group|pcap",
  "output_config": { /* see 4.9 */ }
}
```

返回 `{task_id, strategy_id, status}`。失败时返回 `strategy_id` + `status="strategy_created"` 让 LLM 重试任务创建。

---

## 5. 典型业务场景

### 5.1 生成 TCP 流量并写入 PCAP

```
用户: 帮我生成 100 个 TCP 流量到 10.0.0.1:80，写入 /tmp/out.pcap
LLM:
  1. flowb_query_system(action=status)             -- 确认后端就绪
  2. flowb_generate_traffic(
       task_name="tcp-to-10.0.0.1",
       protocol="tcp",
       config={"dst_ip":"10.0.0.1","dst_port":80,"count":100},
       output_type="pcap",
       output_config={"pcap_path":"/tmp/out.pcap"}
     )
  3. flowb_wait_for_task(task_id=..., timeout_seconds=60)
  4. flowb_get_task_progress(task_id=...)           -- 确认 packets_sent=100
```

### 5.2 回放已导入的 PCAP（双口）

```
用户: 把 demo.pcap 在 enp1s0 + enp2s0 上双口回放，2 倍速
LLM:
  1. flowb_manage_pcaps(action=import, file_path=/abs/demo.pcap)  -- 得到 asset_id
  2. flowb_manage_port_groups(action=create, name="dual",
       interfaces=["enp1s0","enp2s0"])                            -- 得到 port_group_id
  3. flowb_replay_pcap(
       task_name="replay-demo",
       pcap_asset_id=asset_id,
       speed={"mode":"multiplier","multiplier":2},
       direction="dual",
       output_type="port_group",
       output_config={"port_group_id":port_group_id}
     )
  4. flowb_get_task_progress(task_id=...)  -- 监控
```

### 5.3 查询任务历史

```
用户: 看看昨天到今天失败的任务
LLM:
  flowb_manage_tasks(
    action=history,
    status=error,
    start_time=<yesterday unix>,
    end_time=<today unix>,
    sort_by=created_at,
    sort_order=descending
  )
```

### 5.4 PCAP 流量提取

```
用户: 从 demo.pcap 中提取所有 HTTP 流的 body
LLM:
  1. flowb_manage_pcaps(action=import, file_path=/abs/demo.pcap)         -- asset_id
  2. flowb_manage_pcaps(action=list_flows, id=asset_id)                  -- 得到 flows
  3. 对每个 flow: flowb_manage_pcaps(action=get_body, id=asset_id,
       flow_id=..., direction=s2c)                                       -- 解码 base64
```

### 5.5 停止所有任务

```
用户: 紧急停止所有正在跑的任务
LLM: flowb_stop_all_tasks()
```

---

## 6. 错误处理

MCP 工具错误使用 JSON-RPC 错误码：

| 后端 code | JSON-RPC code              | 含义                          |
|-----------|----------------------------|-------------------------------|
| 400       | `InvalidParams` (-32602)   | 参数错误                      |
| 401       | `InternalError` (-32603)   | service account 配置错误       |
| 403       | `InvalidParams` (-32602)   | 权限不足（admin-only 动作）    |
| 404       | `InvalidParams` (-32602)   | 资源不存在                    |
| 409       | （视为成功，幂等命中）       | 资源已存在                    |
| 500       | `InternalError` (-32603)   | 后端内部错误                  |

**工作流部分失败**：`generate_traffic` / `replay_pcap` 在某一步失败时，会返回已创建的资源 ID（`strategy_id` 或 `task_id`）+ 状态字段，让 LLM 决定重试或回滚。例如：

- Step 1 (create strategy) 失败：返回空 + error
- Step 2 (create task) 失败：返回 `{strategy_id, status="strategy_created"}` + error
- Step 3 (start) 失败：返回 `{task_id, strategy_id, status="created"}` + error

---

## 7. 审计日志

当 `mcp.audit_log=true` 时，每次工具调用都会记录：

- 工具名
- 耗时
- 状态（success/error）
- 错误信息（如有）

日志走 zap，与 REST API 的审计日志格式一致。stdio 模式下日志强制走 stderr（避免污染 JSON-RPC 流）。

---

## 8. 已知限制

1. **service account 角色=user**：admin-only 工具（`flowb_manage_users`）在 Phase 1 全部返回 403。Phase 3 多用户模式解锁。
2. **路径校验非沙箱**：`flowb_manage_pcaps(action=import)` 的路径校验只拒绝明显的遍历模式，service account 仍能读 OS 用户能读的任何文件。
3. **`flowb_wait_for_task` 最大 300 秒**：长任务必须用 `flowb_get_task_progress` 轮询。
4. **`flowb_stop_all_tasks` 最多 10,000 任务**：超过的需要分批处理。
5. **`speed.mode` 只支持 `original|multiplier|bps`**：`pps` 和 `max` 被 `validateReplaySpec` 拒绝（按审计修复要求）。
6. **HTTP `api_key` 必须非空**：HTTP 传输启用但 `api_key` 为空时，`NewHTTPServer` 直接拒绝启动，避免未鉴权暴露。

---

## 9. 快速验证清单

部署完成后按顺序跑一遍：

1. **服务端配置检查**：`config.yaml` 里 `mcp.enabled=true`，stdio 或 http 至少开一个；HTTP 开了就要填 `api_key`。
2. **启动主进程**：`trafficgen --config /path/to/config.yaml`。看日志确认 `starting mcp server (stdio)` 或 `starting mcp http server` 出现。
3. **stdio 验证**：用 Claude Desktop / Claude Code 加上 §3.1/§3.2 的配置，重启客户端，工具图标里能看到 `flowb_*` 14 个工具。
4. **HTTP 验证**：用 §3.5 的 curl 流程跑一遍 `initialize → tools/list → tools/call`。`tools/list` 必须返回 14 个工具。
5. **鉴权验证**：去掉 `X-MCP-Key` 头再请求，必须收到 401 + `WWW-Authenticate: X-MCP-Key`。
6. **CORS 验证（浏览器前端）**：从允许的 Origin 发 preflight OPTIONS，必须返回 204 + `Access-Control-Allow-Origin`；从不允许的 Origin 发，必须没有 ACAO。
7. **端到端工作流**：用 `flowb_generate_traffic` 生成一小段 TCP 流量写 PCAP，`flowb_wait_for_task` 等结束，`flowb_get_task_progress` 看 packets_sent。

---

## 10. 相关文档

- [mcp-design.md](./mcp-design.md) — 设计文档（架构、工具映射、错误码）
- [mcp-test-results.md](./mcp-test-results.md) — 测试结果汇总（118 测试，含 4 个 CRITICAL 修复回归）
- [pcap-replay-design.md](./pcap-replay-design.md) — PCAP 回放设计
- [pcap-parser-design.md](./pcap-parser-design.md) — PCAP 解析引擎设计
