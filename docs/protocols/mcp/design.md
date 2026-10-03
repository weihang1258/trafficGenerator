# MCP 流量协议设计与测试用例

> 版本：v1.1.3（层链 as-built 对账版）  
> 设计日期：2026-08-03；层链审计：2026-09-30  
> 范围：把 MCP（Model Context Protocol，模型上下文协议）当作**被解析/生成的网络流量协议**来处理
> 实现位置：`trafficgen/internal/protocol/mcp/`（层生成器注册于 `internal/core/layers/registry.go`）
> 规范来源：MCP spec 2024-11-05 及后续修订（HTTP+SSE → Streamable HTTP）
> 状态：设计内容保留 v1.1.3；本版本补齐当前 cases 的层链真相、实现偏差、缺口与静态 gate 对账。未宣称 suite、PCAP、NIC 或真实网络验证。

---

## 目录

1. [协议概述](#1-协议概述)
2. [报文格式](#2-报文格式)
3. [MCP 方法表](#3-mcp-方法表)
4. [Config 结构体设计](#4-config-结构体设计)
5. [状态机](#5-状态机)
6. [Plan 输出](#6-plan-输出)
7. [业务场景与数据场景](#7-业务场景与数据场景)
8. [测试用例清单](#8-测试用例清单)
9. [交叉对抗审计检查清单](#9-交叉对抗审计检查清单)
10. [集成点](#10-集成点)
11. [与本项目 internal/mcp/ 的关系说明](#11-与本项目-internalmcp-的关系说明)

---

## 1. 协议概述

### 1.1 两个 MCP，互不冲突

本项目同时存在两个 MCP 概念，必须严格区分：

| 维度 | `internal/mcp/`（已存在） | `internal/protocol/mcp/`（本设计新增） |
|---|---|---|
| 角色 | 本系统作为 MCP 服务器供 LLM 调用 | 把 MCP 协议流量当作被生成的网络流量 |
| 方向 | 出方向：暴露 flowB 工具给 LLM | 入方向：生成 MCP 客户端↔服务端的 JSON-RPC 流量 |
| 依赖 | `modelcontextprotocol/go-sdk/mcp` | 仅依赖 `internal/core`，自行拼装 JSON-RPC 字节 |
| 端口 | 监听 stdio / `:8081/mcp`（HTTP+SSE） | 任意端口（默认 8081，与外部 MCP 服务器一致） |
| 关系 | 二进制承载、真实 SDK 行为 | 仅生成协议报文，不调用 SDK，不真正建立会话 |

两者代码完全隔离：`internal/protocol/mcp/` 不 import `internal/mcp/`，反之亦然。同一进程可同时运行两个角色而不冲突（一个发流量，一个收流量，但通常不会这样做）。

### 1.2 MCP 协议定位

MCP（Model Context Protocol）是 Anthropic 在 2024 年发布的开放协议，用于 LLM 客户端与外部工具/资源服务器之间的标准化通信。其核心特征：

- **应用层协议**：基于 JSON-RPC 2.0（RFC 兼容子集），承载于多种传输层之上
- **三种传输**：stdio（行分隔 JSON）、HTTP+SSE（旧版，POST + Server-Sent Events 双流）、Streamable HTTP（新版，单一 POST 端点 + 可选 SSE 升级）
- **请求-响应 + 通知**：有 `id` 字段的为请求/响应，无 `id` 的为通知（单向）
- **双向能力协商**：客户端与服务端在 `initialize` 阶段互相声明 `capabilities`
- **会话化**：HTTP 传输下 `Mcp-Session-Id` 头标识一个会话，多会话并行

### 1.3 流量生成视角下的 MCP

把 MCP 当作流量协议时，关心的是：

1. **报文字节**：每个 JSON-RPC 包如何编码为字节流（行分隔 vs HTTP body vs SSE event）
2. **时序关系**：initialize → initialized → tools/list → tools/call → result 的请求-响应配对
3. **传输承载**：stdio 走 TCP（local proxy 模拟），HTTP+SSE 走 HTTP/1.1 over TCP
4. **多会话并发**：M 个客户端 = M 条独立 TCP 流，每条流独立 sessionId
5. **字段丰富度**：MCP 扩展表 31 字段需要被报文实例覆盖

### 1.4 默认端口

- **stdio**：本项目不直接生成 stdio 流量（stdio 是进程间通信，不是网络流量）。但用户可能想模拟"通过 SSH 隧道转发的 stdio"，此时走 TCP 22（SSH）+ 应用层行分隔 JSON。本设计支持 `transport=stdio` 模式生成 TCP 流，载荷为行分隔 JSON-RPC（不带 HTTP 头），默认端口 `22`（SSH 隧道场景）；如用户指定 `dst_port=8081`，则走 TCP 8081 + 行分隔 JSON（模拟本地 stdio 转发到 8081 端口的 MCP 服务器）。**v1.1.2 标注**：SSH 隧道场景（TCP 22 + SSH 协议头 + stdio 载荷）为概念描述，当前测试覆盖仅 stdio 直接 TCP 模式（无 SSH 协议头）；SSH 协议封装留待 v1.2 实现，本版本不提供测试用例。
- **HTTP+SSE / Streamable HTTP**：默认端口 `8081`，路径 `/mcp`，方法 `POST`（请求 + SSE 响应）与 `GET`（SSE 升级）。

### 1.5 设计原则

- **JSON-RPC 字节精确**：每个包按 JSON-RPC 2.0 序列化，UTF-8 编码，无 BOM，无尾随空白（除行分隔的 `\n`）。键序由 planner 控制（与 Wireshark MCP dissector 解析的字段无关，但影响字节对比）。
- **请求-响应配对**：每个 request 必须有对应的 response（按 `id` 匹配），notification 无响应。planner 不会发出"孤儿"请求。
- **状态机驱动**：MCP 会话有明确的状态机（uninitialized → initializing → initialized → operating → shutdown），planner 按状态机生成报文，不允许跳过 `initialize` 直接调用 `tools/call`。
- **多会话独立**：每个会话独立 4-tuple + 独立 sessionId + 独立 id 序列。多会话场景下，M 条流交织但每条内部时序正确。
- **不模拟真实 SDK 行为**：planner 不调用 `modelcontextprotocol/go-sdk/mcp`，自行拼装 JSON。SDK 的会话管理、重试、心跳等行为不在本协议层模拟（如需模拟，应在更高层）。

---

## 2. 报文格式

### 2.1 JSON-RPC 2.0 包结构

每个 MCP 报文是一个 JSON-RPC 2.0 对象（符合 JSON-RPC 2.0 规范 https://www.jsonrpc.org/specification，2026-08-03 检索）。三种类型：

#### 2.1.1 请求（Request）

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": { "name": "search", "arguments": { "q": "hello" } }
}
```

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `jsonrpc` | string | 是 | 固定 `"2.0"` |
| `id` | number \| string \| null | 是 | 请求标识。**v1.1.2 修订**：MCP 强烈不推荐 `null` id（与纯 JSON-RPC 通知不同，MCP 请求必须可识别以匹配响应）；`null` 保留用于"无法解析的响应"场景（如 Parse error 响应的 id 字段固定为 null，见 §2.1.2 响应表）。number 用整数，string 用于 UUID 风格。 |
| `method` | string | 是 | 方法名，如 `initialize`、`tools/call` |
| `params` | object \| array | 否 | 方法参数。MCP 中几乎总是 object（`{}`）。空参数可省略或写 `{}`。 |

#### 2.1.2 响应（Response）

成功：

```json
{ "jsonrpc": "2.0", "id": 1, "result": { "content": [{ "type": "text", "text": "ok" }] } }
```

错误：

```json
{ "jsonrpc": "2.0", "id": 1, "error": { "code": -32601, "message": "Method not found", "data": { "method": "foo/bar" } } }
```

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `jsonrpc` | string | 是 | 固定 `"2.0"` |
| `id` | number \| string \| null | 是 | 必须等于对应请求的 id。请求 id 缺失或无法解析时为 null |
| `result` | any | 否 | 成功结果。与 `error` 互斥 |
| `error` | object | 否 | 错误对象。与 `result` 互斥 |
| `error.code` | integer | 是 | 错误码（见 §2.2） |
| `error.message` | string | 是 | 简短错误描述 |
| `error.data` | any | 否 | 任意附加数据 |

#### 2.1.3 通知（Notification）

```json
{ "jsonrpc": "2.0", "method": "notifications/initialized" }
```

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `jsonrpc` | string | 是 | 固定 `"2.0"` |
| `method` | string | 是 | 通知方法名（以 `notifications/` 开头） |
| `params` | object | 否 | 通知参数 |

通知无 `id` 字段（区别于请求），无响应。

### 2.2 JSON-RPC 错误码

MCP 复用 JSON-RPC 2.0 标准错误码，并扩展 MCP 专属码：

| 码 | 名称 | 含义 |
|---|---|---|
| -32700 | Parse error | JSON 解析失败 |
| -32600 | Invalid Request | 不是合法的 JSON-RPC 2.0 对象 |
| -32601 | Method not found | 方法名不存在或未实现 |
| -32602 | Invalid params | 参数缺失/类型错误 |
| -32603 | Internal error | 服务端内部异常 |
| -32000 到 -32099 | Server error | 服务端自定义错误（spec 定义的 -32002 用于 `resources/read` Resource not found，见附录 B） |

### 2.3 stdio 传输（行分隔 JSON）

每个 JSON-RPC 包序列化为单行 JSON，以 `\n` 分隔：

```
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{...}}\n
{"jsonrpc":"2.0","id":1,"result":{...}}\n
{"jsonrpc":"2.0","method":"notifications/initialized"}\n
```

规则：
- 行内不得含 `\n`（JSON 序列化时 `\n` 转义为 `\\n`）
- UTF-8 编码，无 BOM
- 单行长度无上限（MCP spec 不限制），但 planner 默认按 TCP MSS 1460 分段
- 请求/响应/通知共用同一字节流，双向（client→server 与 server→client 是同一 TCP 流的两个方向）

### 2.4 HTTP+SSE 传输（旧版，2024-11-05 spec）

双流模式（**注意 spec 强制时序**：GET 先于 POST，且服务端必须在 SSE 流第一个事件中发送 `endpoint` 事件，告知客户端 POST 端点 URI）：

- **第一步：客户端 GET `/mcp` 建立 SSE 流**——客户端发 `GET /mcp HTTP/1.1`，`Accept: text/event-stream`。
- **第二步：服务端发送 `endpoint` 事件**——服务端通过 SSE 流第一个事件告知客户端 POST 端点 URI：`event: endpoint\ndata: /mcp?session=xxx\n\n`（spec 2024-11-05 §basic/transports："When a client connects, the server MUST send an `endpoint` event containing a URI for the client to use for sending messages"）。
- **第三步：客户端 POST 到 endpoint URI**——客户端将 JSON-RPC 请求 POST 到上一步获知的 URI（不是固定的 `/mcp`，而是服务端在 `endpoint` 事件中动态指定的 URI，可携带 session id 查询参数）。POST 响应为 HTTP 202 Accepted（无 body，**不直接返回 JSON**；响应通过 GET SSE 流推送）。
- **第四步：服务端通过 GET SSE 流推送响应/通知**——服务端在已有的 GET SSE 流上用 `event: message\ndata: {...}` 推送 initialize 响应及后续所有响应/通知（按 id 匹配）。
- **会话标识**：服务端可在 `endpoint` 事件或 initialize 响应中返回 `Mcp-Session-Id` 头，客户端后续请求必须携带该头。

SSE 事件格式：

```
event: endpoint
data: /mcp?session=a1b2c3d4...

event: message
data: {"jsonrpc":"2.0","id":1,"result":{...}}

event: message
data: {"jsonrpc":"2.0","method":"notifications/initialized"}

```

每个事件以 `\n\n` 结尾，`data:` 行内为 JSON。多行 `data:` 用 `\n` 连接后再解析。`endpoint` 事件必须出现在所有 `message` 事件之前。

### 2.5 Streamable HTTP 传输（新版，2025-03-26 spec）

单一端点模式：

- **客户端 → 服务端**：HTTP POST `/mcp`，Content-Type: `application/json` 或 `text/event-stream`。
  - 简单请求/响应：POST JSON，响应为单个 JSON（200 OK + application/json）或 SSE 流（200 OK + text/event-stream，用于流式结果或服务端中途通知）。
  - 服务端可在响应 SSE 流中插入多个事件（响应 + 中途 notifications/progress）。
- **服务端 → 客户端（持续）**：HTTP GET `/mcp`，Accept: `text/event-stream`，建立 SSE 长连接，接收服务端主动推送（resources/updated 等）。
- **会话标识**：同 HTTP+SSE，`Mcp-Session-Id` 头。
- **DELETE /mcp**：显式终止会话。

本设计两种 HTTP 模式都支持，由 `transport` 字段选择：`http_sse`（旧版双流）或 `streamable`（新版单端点）。

### 2.6 JSON-RPC Batch（批量请求）

JSON-RPC 2.0 规范允许在单个 HTTP 请求中发送批量请求（数组形式）。**MCP spec 2025-03-26 §Batching 明确规定："MCP implementations MAY support sending JSON-RPC batches, but MUST support receiving JSON-RPC batches"**——所有传输（stdio / HTTP+SSE / Streamable HTTP）服务端 MUST 支持接收批量请求。旧版 HTTP+SSE 的 POST body 可以是单个 JSON-RPC 对象或批量数组（spec 未禁止），**planner 默认按批量数组发送**（服务端 MUST 接收）。

#### 2.6.1 编码规则

**请求编码（stdio）**：批量请求序列化为多行 JSON（每行一包），每行为一个有效 JSON-RPC 对象；客户端发送 N 行后，服务端按相同顺序回 N 行响应（或通知）。

**请求编码（HTTP）**：HTTP POST `/mcp` 的 `Content-Type: application/json`，body 为 JSON 数组 `[req1, req2, ...]`：

```json
[
  {"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}},
  {"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"search"}},
  {"jsonrpc":"2.0","id":3,"method":"resources/list","params":{}}
]
```

**响应编码（HTTP）**：服务端响应 body 为对应数组 `[resp1, resp2, ...]`，按请求顺序逐项匹配成功/失败：

```json
[
  {"jsonrpc":"2.0","id":1,"result":{"tools":[...]}},
  {"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"found"}]}},
  {"jsonrpc":"2.0","id":3,"error":{"code":-32601,"message":"Method not found"}}
]
```

**Streamable HTTP + SSE 批量响应**：POST 请求体为批量数组时，服务端响应可走 SSE 流（一次 POST 请求 + 一次性 SSE 响应流，响应流关闭后连接释放；这是短周期 SSE 响应模式，非持久 SSE 订阅）。SSE 流中每个事件 `data:` 行为数组中的一个响应元素，事件间用 `\n\n` 分隔。

**批量 + HTTP+SSE（旧版）组合**：旧版 HTTP+SSE 的 POST body 可以是单个 JSON-RPC 对象或批量数组（spec 未禁止，且 spec 2025-03-26 §Batching 要求服务端 MUST 接收批量）。**planner 默认**：POST body 发送批量数组时，服务端通过共享 GET SSE 流按序推送 N 个 `event:message` 事件（每个事件 `data:` 字段为数组中的一个响应元素）；与持久 SSE 长连接兼容，事件间用 `\n\n` 分隔，POST 响应仍为 202 Accepted（无 body）。

#### 2.6.2 校验规则

Validate 必须检查：

1. 批量数组**非空**——空数组 `[]` 是非法请求，服务端应返回单个 `-32600 Invalid Request` 错误。
2. 批量数组每个元素必须是合法 JSON-RPC 2.0 对象（含 `jsonrpc:"2.0"` 与 `method` 字段）。
3. 批量中各请求 `id` 必须唯一（重复 `id` 是非法请求）。**注意**：本规则仅对用户显式设置的非零 `id` 生效——若请求 `id=0` 表示由 planner 自动分配，自动分配时的唯一性检测推迟到 Plan 阶段（Plan 在展开 `IDCounter` 后检查所有分配结果是否唯一，不唯一则报错）。用户显式指定 `id` 的部分必须在 Validate 阶段即拒绝。
4. 批量响应数组长度 = 批量请求数组长度（成功响应 + 错误响应一一对应，无响应 = 通知，无 `id` 字段）。
5. 批量请求的**整个 JSON 数组本身解析失败**时（如整体不是合法 JSON、整体非数组、或数组为空 `[]`），整个批量响应为单个 `-32700 Parse error` 或 `-32600 Invalid Request`，`id=null`。**注意**：这是针对整个批量数组本身的解析失败（JSON-RPC 2.0 spec §6："If the batch rpc call itself fails to be recognized as a valid JSON or as an Array with at least one value, the response from the Server MUST be a single Response object"），**不是**单个元素解析失败——单个元素 JSON 解析失败属于"批量数组能解析但某元素非法"范畴，按 rule 6 逐项响应。**planner 选择**：本设计采用严格 spec 行为——批量整体 JSON 解析失败时返回单个顶层 -32700 错误，不做部分响应；用户可通过配置 `responses` 字段显式覆盖此默认（如需模拟宽松服务端）。
6. 批量数组能成功 JSON 解析，但某元素不是合法 JSON-RPC 2.0 对象（如缺 `jsonrpc`/`method` 字段、`id` 重复、类型错）时，合法元素仍正常响应，非法元素单独返回 `-32600 Invalid Request`（`id` 为该元素的 id 或 null）。

#### 2.6.3 planner 行为

- `Requests` 字段为数组时，planner 自动识别为批量模式（所有传输均支持接收批量，spec 2025-03-26 §Batching 明确 MUST 支持）。
- 批量模式下，所有请求在单个 TCP segment / 单个 HTTP POST body 中发送；响应在单个 SSE 流中按序接收。
- `Rounds` 在批量模式下控制整个批量的重复次数（每轮重新发送完整批量），而非单个请求的重复。
- `Notifications` 数组不参与批量——通知无 id，无对应响应，应独立于批量请求之外发送。

### 2.7 字节布局总览

```
+--------------------------------------------------+
| Ethernet (14B) + VLAN (4B 可选)                  |
+--------------------------------------------------+
| IPv4 (20B) / IPv6 (40B)                          |
+--------------------------------------------------+
| TCP (20B+)                                       |
+--------------------------------------------------+
| MCP 载荷（下列之一）                              |
|  - stdio:    行分隔 JSON（多行，每行一包）        |
|  - http_sse: HTTP 请求行 + 头 + JSON body        |
|              或 SSE 事件流                        |
|  - streamable: HTTP 请求行 + 头 + JSON/SSE body  |
+--------------------------------------------------+
```

---

## 3. MCP 方法表

### 3.1 生命周期方法

| 方法 | 方向 | 有 id | 必填 | 说明 |
|---|---|---|---|---|
| `initialize` | C→S | 是 | 是 | 协商版本、能力、客户端信息 |
| `notifications/initialized` | C→S | 否 | 是 | 通知服务端初始化完成 |
| `ping` | 双向 | 是 | 否 | 心跳，对端必须响应 |

`initialize` 请求 `params`：

```json
{
  "protocolVersion": "2024-11-05",
  "capabilities": {
    "roots": { "listChanged": true },
    "sampling": {}
  },
  "clientInfo": { "name": "claude-desktop", "version": "1.0.0" }
}
```

`initialize` 响应 `result`：

```json
{
  "protocolVersion": "2024-11-05",
  "capabilities": {
    "tools": { "listChanged": true },
    "resources": { "subscribe": true, "listChanged": true },
    "prompts": { "listChanged": true },
    "logging": {},
    "completion": {}
  },
  "serverInfo": { "name": "flowB", "version": "1.0.0" }
}
```

### 3.2 工具方法

| 方法 | 方向 | 有 id | 说明 |
|---|---|---|---|
| `tools/list` | C→S | 是 | 列出服务端工具（**支持分页 cursor**，spec 2024-11-05/2025-06-18 `server/utilities/pagination`） |
| `tools/call` | C→S | 是 | 调用工具 |
| `notifications/tools/list_changed` | S→C | 否 | 工具列表变更通知 |

`tools/list` 请求：`{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{"cursor":"..."}}`（cursor 可省略，表示第一页；响应 `result.nextCursor` 为空表示无更多页）。

`tools/call` 请求：

```json
{ "name": "search", "arguments": { "q": "hello", "limit": 10 }, "_meta": { "progressToken": 42 } }
```

`tools/call` 响应：

```json
{
  "content": [
    { "type": "text", "text": "result..." },
    { "type": "image", "data": "base64...", "mimeType": "image/png" }
  ],
  "isError": false
}
```

### 3.3 资源方法

| 方法 | 方向 | 有 id | 说明 |
|---|---|---|---|
| `resources/list` | C→S | 是 | 列出资源（支持分页 cursor） |
| `resources/read` | C→S | 是 | 读取资源内容（按 uri） |
| `resources/subscribe` | C→S | 是 | 订阅资源变更（需服务端 capabilities.resources.subscribe） |
| `notifications/resources/updated` | S→C | 否 | 资源内容变更通知 |
| `notifications/resources/list_changed` | S→C | 否 | 资源列表变更通知 |

注：MCP spec 2024-11-05 / 2025-06-18 `server/resources` **未定义** `resources/unsubscribe` 方法（仅 2025-03-26 spec 中间版本定义）。订阅隐式随会话结束失效，无显式取消订阅方法。**v1.1.2 列出的 `resources/unsubscribe` 已删除**——按 spec 2024-11-05 实现。

`resources/read` 请求：`{ "uri": "file:///etc/hosts" }`

`resources/read` 响应：

```json
{
  "contents": [
    { "uri": "file:///etc/hosts", "mimeType": "text/plain", "text": "127.0.0.1 localhost\n" }
  ]
}
```

### 3.4 提示词方法

| 方法 | 方向 | 有 id | 说明 |
|---|---|---|---|
| `prompts/list` | C→S | 是 | 列出提示词模板（**支持分页 cursor**，spec 2024-11-05/2025-06-18 `server/utilities/pagination`） |
| `prompts/get` | C→S | 是 | 渲染提示词 |
| `notifications/prompts/list_changed` | S→C | 否 | 提示词列表变更 |

`prompts/get` 请求：`{ "name": "code_review", "arguments": { "language": "go" } }`

`prompts/get` 响应：

```json
{
  "description": "Code review prompt",
  "messages": [
    { "role": "user", "content": { "type": "text", "text": "Review this code..." } }
  ]
}
```

### 3.5 补全方法

| 方法 | 方向 | 有 id | 说明 |
|---|---|---|---|
| `completion/complete` | C→S | 是 | 提示词/资源/参数补全 |

请求：`{ "ref": { "type": "ref/prompt", "name": "code_review" }, "argument": { "name": "language", "value": "go" } }`

响应：`{ "completion": { "values": ["golang", "google go"], "total": 2, "hasMore": false } }`

### 3.6 日志方法

| 方法 | 方向 | 有 id | 说明 |
|---|---|---|---|
| `logging/setLevel` | C→S | 是 | 设置最低日志级别 |
| `notifications/message` | S→C | 否 | 日志消息推送 |

`logging/setLevel` 请求：`{ "level": "debug" }`（level: debug/info/notice/warning/error/critical/alert/emergency）

`notifications/message` 通知：

```json
{ "level": "info", "logger": "mcp", "data": { "msg": "tool called", "tool": "search" } }
```

### 3.7 通知方法（客户端 → 服务端）

| 方法 | 方向 | 有 id | 说明 |
|---|---|---|---|
| `notifications/cancelled` | C→S | 否 | 取消进行中的请求（携带原请求 id） |
| `notifications/progress` | 双向 | 否 | 进度推送（携带 progressToken、progress、total） |

`notifications/cancelled`：`{ "requestId": 42, "reason": "user cancelled" }`

`notifications/progress`：`{ "progressToken": 42, "progress": 50, "total": 100, "message": "half done" }`

### 3.8 Roots 方法

| 方法 | 方向 | 有 id | 说明 |
|---|---|---|---|
| `roots/list` | S→C | 是 | 服务端反查客户端的 roots（文件系统根） |
| `notifications/roots/list_changed` | C→S | 否 | 客户端 roots 变更通知 |

`roots/list` 响应：

```json
{ "roots": [ { "uri": "file:///home/user/project", "name": "project" } ] }
```

### 3.9 采样方法

| 方法 | 方向 | 有 id | 说明 |
|---|---|---|---|
| `sampling/createMessage` | S→C | 是 | 服务端请求客户端 LLM 采样 |

请求：

```json
{
  "messages": [ { "role": "user", "content": { "type": "text", "text": "summarize this" } } ],
  "modelPreferences": { "hints": [{ "name": "claude-3" }], "intelligencePriority": 0.8 },
  "systemPrompt": "You are helpful",
  "maxTokens": 100,
  "temperature": 0.7,
  "stopSequences": ["\n"]
}
```

响应（`result`）：

```json
{
  "role": "assistant",
  "content": { "type": "text", "text": "summary..." },
  "model": "claude-3-sonnet",
  "stopReason": "endTurn"
}
```

### 3.10 扩展表 31 字段映射

MCP 扩展表（规范 9.4.1.38 扩展协议表节点 `mcpProtRpt`）的 31 字段与协议方法的对应关系：

| 字段 | 必填 | 出现位置 | 说明 |
|---|---|---|---|
| `level` | 否 | notifications/message | 日志级别 |
| `logger` | 否 | notifications/message | 日志器名 |
| `data` | 否 | notifications/message | 日志数据 |
| `inputSchema` | 否 | tools/list 响应 | 工具参数 JSON Schema |
| `arguments` | 否 | tools/call 请求 | 工具入参 |
| `isError` | 否 | tools/call 响应 | 工具调用是否以错误结束 |
| `content` | 否 | tools/call 响应、prompts/get、sampling | 内容数组 |
| `capabilities` | 否（默认空对象 `{}`） | initialize 请求/响应 | 能力声明（spec 2024-11-05 §3.1.1：`capabilities?` optional；Validate 不接受 nil 时默认 `{}`） |
| `roots` | 否 | roots/list 响应 | 客户端 roots |
| `uri` | 否 | resources/* | 资源标识 |
| `mimeType` | 否 | resources/read、tools/call(image) | MIME 类型 |
| `authentication` | 否 | initialize 响应 | 服务端认证要求 |
| `schemes` | 否 | authentication | 支持的认证方案 |
| `credentials` | 否 | initialize 请求 | 客户端凭据 |
| `id` | 必填 | 请求/响应 | JSON-RPC id |
| `contextId` | 否 | tools/call、sampling | 调用上下文（链路追踪） |
| `sessionId` | 否 | HTTP 头 | 会话标识 |
| `parentId` | 否 | notifications/progress | 父任务 id（嵌套进度） |
| `state` | 否 | tools/call（长任务）`_meta.state` | 调用状态机（仅出现在 `_meta`，不在 `notifications/progress` 中；MCP `ProgressNotification` params 字段为 `progressToken`/`progress`/`total`/`message`，无 `state` 字段） |
| `role` | 否 | prompts/get、sampling | 消息角色（user/assistant） |
| `parts` | 否 | prompts/get（multi-part） | 多部分内容 |
| `metadata` | 否 | 任意 `_meta` | 自定义元数据 |
| `pushNotification` | 否 | tools/call（长任务） | 回调 URL 配置 |
| `verificationToken` | 否 | pushNotification | 回调验证令牌 |

剩余 7 字段（`protocolVersion`、`method`、`params`、`result`、`error`、`clientInfo`、`serverInfo`）属于 JSON-RPC 与 MCP 核心字段，已在 §2 与 §3.1 覆盖。

**字段计数复核（v1.1.2）**：本表列举 24 字段（level/logger/data/inputSchema/arguments/isError/content/capabilities/roots/uri/mimeType/authentication/schemes/credentials/id/contextId/sessionId/parentId/state/role/parts/metadata/pushNotification/verificationToken），加上上述 7 核心字段共 **31 字段**（与规范 9.4.1.38 扩展协议表节点 `mcpProtRpt` 一致）。v1.1 修订记录中曾写"25+7=32"系计数错误（误将已删除的幻觉字段 `status` 计入），v1.1.1 改为 24+7=31 的"剩余 7 字段"表述。

---

## 4. Config 结构体设计

新增 `core.MCPConfig`，放在 `internal/core/types.go` 末尾（与其他 L7 协议并列）。`FlowSpec` 增加 `MCP *MCPConfig` 字段。

### 4.1 顶层结构

```go
// MCPConfig holds MCP traffic configuration. MCP is a JSON-RPC 2.0
// application-layer protocol over stdio (line-delimited JSON) or HTTP+SSE /
// Streamable HTTP. Each flow is one TCP session: initialize -> operating
// exchanges -> shutdown. Multi-session uses multi-flow strategy (M
// independent 4-tuples). This config generates wire bytes only; it does NOT
// use the modelcontextprotocol/go-sdk (the SDK drives real sessions).
type MCPConfig struct {
    Transport          string             `json:"transport,omitempty"`          // "stdio"(default)/"http_sse"/"streamable"
    BaseURL            string             `json:"base_url,omitempty"`           // HTTP modes; empty="/mcp"
    SessionID          string             `json:"session_id,omitempty"`         // HTTP modes; Mcp-Session-Id header; empty=auto UUID
    ProtocolVersion    string             `json:"protocol_version,omitempty"`   // empty="2024-11-05"
    ClientInfo         MCPClientInfo      `json:"client_info,omitempty"`        // initialize params.clientInfo
    ServerInfo         MCPServerInfo      `json:"server_info,omitempty"`        // initialize result.serverInfo
    ClientCapabilities json.RawMessage    `json:"client_capabilities,omitempty"`// empty=default {} (no capabilities; user must explicitly fill roots/sampling/etc to enable)
    ServerCapabilities json.RawMessage    `json:"server_capabilities,omitempty"`// empty=default {} (no capabilities; user must explicitly fill tools/resources/etc to enable)
    Requests           []MCPRequest       `json:"requests,omitempty"`           // client→server requests after initialize
    Responses          []MCPMessage       `json:"responses,omitempty"`          // server→client; empty=synthesize success
    Notifications      []MCPNotification  `json:"notifications,omitempty"`      // standalone notifications with Step position
    Auth               MCPAuth            `json:"auth,omitempty"`               // HTTP auth; empty=no auth header
    State              MCPState           `json:"state,omitempty"`              // long-task state machine
    Parts              []MCPPart          `json:"parts,omitempty"`              // multi-part prompts/sampling
    Metadata           map[string]any     `json:"metadata,omitempty"`           // _meta in requests/responses
    PushNotification   MCPPushNotification `json:"push_notification,omitempty"` // tools/call callback URL
    IDCounter          int                `json:"id_counter,omitempty"`         // first request id; **语义（v1.1.2 明确）**：IDCounter=0 与 Requests[i].ID=0 均表示"未设置，由 planner 自动从 1 开始递增分配"；若用户显式设置 Requests[i].ID 为非零值，则跳过该位置的自动分配，使用用户指定值（用于中途插入特定 id 的场景）；不允许混用模式：同一 FlowSpec 内若有任何 Requests[i].ID 非零，则所有 ID 必须由用户显式设置（不允许部分自动部分显式，避免 id 序列语义模糊）
    Rounds             int                `json:"rounds,omitempty"`             // repeat count; 0=1
    ThinkTime          int                `json:"think_time,omitempty"`         // ms between rounds
    Shutdown           *bool              `json:"shutdown,omitempty"`           // nil=true (TCP FIN teardown)
    ContextID          string             `json:"context_id,omitempty"`         // _meta.contextId (call chain)
    ParentID           string             `json:"parent_id,omitempty"`          // notifications/progress parentId
}
```

### 4.2 子结构

```go
type MCPClientInfo struct {
    Name    string `json:"name,omitempty"`    // default "trafficgen-client"
    Version string `json:"version,omitempty"` // default "1.0.0"
}

type MCPServerInfo struct {
    Name    string `json:"name,omitempty"`    // default "trafficgen-server"
    Version string `json:"version,omitempty"` // default "1.0.0"
}

// MCPRequest is one client→server JSON-RPC request.
type MCPRequest struct {
    ID     int            `json:"id"`               // **v1.1.2 明确**：0=auto from IDCounter (递增分配); non-zero=user explicit (跳过自动分配，使用此值); 同一 FlowSpec 内不允许混用自动与显式
    Method string         `json:"method"`           // "tools/list", "tools/call", ...
    Params map[string]any `json:"params,omitempty"` // nil=emit {} or omit
}

// MCPMessage is one server→client message (response or notification).
type MCPMessage struct {
    ID     int            `json:"id"`               // 0 for notifications
    Method string         `json:"method,omitempty"` // set for notifications
    Result map[string]any `json:"result,omitempty"` // success response
    Error  *MCPError      `json:"error,omitempty"`  // error response
    Params map[string]any `json:"params,omitempty"` // notifications
}

type MCPError struct {
    Code    int    `json:"code"`
    Message string `json:"message"`
    Data    any    `json:"data,omitempty"`
}

// MCPNotification is a standalone notification with stream position.
type MCPNotification struct {
    Step   int            `json:"step"`   // 0..len(Requests)
    Method string         `json:"method"` // "notifications/progress", ...
    Params map[string]any `json:"params,omitempty"`
}

type MCPAuth struct {
    Schemes       []string `json:"schemes,omitempty"`        // ["Bearer","Basic","OAuth2"]
    Credentials   string   `json:"credentials,omitempty"`    // raw token / user:pass
    OAuth2Token   string   `json:"oauth2_token,omitempty"`   // placeholder
    OAuth2Refresh string   `json:"oauth2_refresh,omitempty"` // placeholder
}

// MCPState is the long-running tools/call state machine.
type MCPState struct {
    Initial string `json:"initial,omitempty"` // default "submitted"
    Final   string `json:"final,omitempty"`   // default "completed"
    // States: submitted, working, input_required, completed, failed, canceled
}

type MCPPart struct {
    Role    string     `json:"role"`    // "user"/"assistant"
    Content MCPContent `json:"content"`
}

type MCPContent struct {
    Type     string `json:"type"`               // text/image/audio/resource/resource_link
    Text     string `json:"text,omitempty"`
    Data     string `json:"data,omitempty"`     // base64 for image/audio
    MimeType string `json:"mimeType,omitempty"`
    URI      string `json:"uri,omitempty"`      // resource/resource_link
    Name     string `json:"name,omitempty"`
}

type MCPPushNotification struct {
    URL               string `json:"url,omitempty"`
    VerificationToken string `json:"verification_token,omitempty"`
}
```

### 4.3 字段默认值规则

字段默认值遵循"user-provided > derived default > not emitted"原则（与 HTTPConfig 一致）：

| 字段 | 默认值 | 触发条件 |
|---|---|---|
| `Transport` | `"stdio"` | 空字符串 |
| `ProtocolVersion` | `"2024-11-05"` | 空字符串 |
| `ClientInfo.Name` | `"trafficgen-client"` | 空字符串 |
| `ClientInfo.Version` | `"1.0.0"` | 空字符串 |
| `ServerInfo.Name` | `"trafficgen-server"` | 空字符串 |
| `ServerInfo.Version` | `"1.0.0"` | 空字符串 |
| `ClientCapabilities` | `{}`（空对象；用户显式填入 `roots:{}` / `sampling:{}` 等才启用对应能力） | nil |
| `ServerCapabilities` | `{}`（空对象；用户显式填入 `tools:{}` / `resources:{}` 等才启用对应能力） | nil |
| `SessionID` | UUID 风格十六进制 32 字符 | 空字符串（仅 HTTP 模式） |
| `IDCounter` | `1` | 0 |
| `Rounds` | `1` | 0 |
| `Requests` | `[{Method:"tools/list"},{Method:"tools/call",Params:{name:"ping"}}]` | nil |
| `Responses` | 自动合成成功响应 | nil |
| `Shutdown` | `true` | nil |
| `State.Initial` | `"submitted"` | 空字符串 |
| `State.Final` | `"completed"` | 空字符串 |

### 4.4 Validate 规则

`Planner.Validate(spec)` 必须检查：

1. `spec.MCP != nil`（否则报错 "mcp config is required"）
2. `Transport` ∈ {`""`, `"stdio"`, `"http_sse"`, `"streamable"}`（其他值报错）
3. `ProtocolVersion` ∈ {`""`, `"2024-11-05"`, `"2025-03-26"`, `"2025-06-18"`}（其他值报错——MCP spec 仅这几个已发布版本；**未来版本处理策略**：当 MCP spec 发布新版本（如 2025-09-xx 等），需在本 Validate 规则中追加新枚举值；当前实现采取严格枚举策略而非 warning，避免未知版本被静默接受后产生互操作性问题；新版本发布后由维护者追加）
4. `Auth.Schemes` 中每个值 ∈ {`"Bearer"`, `"Basic"`, `"OAuth2"`, `"Negotiate"`}（其他值报错）
5. `State.Initial` / `State.Final` ∈ {`""`, `"submitted"`, `"working"`, `"input_required"`, `"completed"`, `"failed"`, `"canceled"`}
6. `ClientCapabilities` / `ServerCapabilities` 缺省与显式 `null` 语义一致：两者均默认 `{}`（不报错；spec 允许 capabilities 字段省略或为 null），不自动注入 `roots` / `sampling` / `tools` / `resources` / `prompts` / `logging` / `completion` 等任何键。用户须显式填入对应能力键才启用。语义：缺失或显式 null = 不支持该能力，与 §5.4 能力双向门控规则一致。**写入规则**：`json.RawMessage` 类型下，JSON `null` 解码后为 `[]byte("null")`（非 nil）；planner 在写入 initialize 请求/响应时将 nil 与 `null` 统一处理为"省略 capabilities 字段"或"写为 `{}`"（二选一，推荐省略以减小报文，与 §7.1 默认 initialize 字节序列一致——其 capabilities 为 `{"roots":{...},"sampling":{}}` 仅在用户显式填入时出现）。
7. 每个 `Requests[i].Method` 非空（除非 `ID` 为 0 且是默认序列）
8. `IDCounter` ≥ 0
9. `Rounds` ≥ 0
10. `Parts[i].Role` ∈ {`""`, `"user"`, `"assistant"`}（空默认 `user`）
11. `Parts[i].Content.Type` ∈ {`"text"`, `"image"`, `"audio"`, `"resource"`, `"resource_link"`}（spec 2024-11-05 `server/tools`/`server/prompts`：`text`/`image`/`resource`；spec 2025-06-18 新增 `audio`/`resource_link`；**`embedded_resource` 是幻觉类型**，spec 用 `resource` 表示嵌入资源，`resource_link` 表示资源链接）
12. `Notifications[i].Step` ∈ [0, len(Requests)]（超出报错）
13. `MCPError.Code` 必须在 [-32700, -32000] 范围内（JSON-RPC 2.0 标准 + 服务端错误段；错误码不可为正数）
14. `spec.SrcIP` / `spec.DstIP` 合法（复用 `net.ParseIP`）

---

## 5. 状态机

MCP 会话有明确的生命周期状态机。planner 必须按状态机生成报文，不允许跳过状态。

### 5.1 会话级状态机

```
UNINITIALIZED
    │
    │ client: initialize request
    ▼
INITIALIZING (等待服务端 initialize response)
    │
    │ server: initialize response (含 capabilities)
    ▼
INITIALIZED (客户端已收到响应)
    │
    │ client: notifications/initialized
    ▼
OPERATING (正常调用阶段)
    │  ↕ tools/list, tools/call, resources/*, prompts/*, ...
    │  ↕ notifications/* (双向)
    │
    │ (HTTP 模式: DELETE /mcp 或 TCP FIN)
    │ (stdio 模式: stdin EOF 或 TCP FIN)
    ▼
SHUTDOWN
```

### 5.2 状态转换触发条件

| 起点 | 终点 | 触发 |
|---|---|---|
| UNINITIALIZED | INITIALIZING | 客户端发 `initialize` |
| INITIALIZING | INITIALIZED | 服务端回 `initialize` 响应 |
| INITIALIZED | OPERATING | 客户端发 `notifications/initialized` |
| OPERATING | OPERATING | 任意 tools/resources/prompts/... 调用 |
| OPERATING | SHUTDOWN | TCP FIN / HTTP DELETE / 显式 shutdown |

### 5.3 长任务状态机（tools/call 内部）

`tools/call` 可能为长任务（如 `state` 字段非空时）：

```
SUBMITTED (客户端已发起 tools/call)
    │
    │ server: notifications/progress {progress:10,total:100,message:"started"}
    ▼
WORKING (服务端处理中)
    │  ↕ notifications/progress (多次，仅携带 progressToken/progress/total/message)
    │
    ├─ server: notifications/progress {progress:50,total:100,message:"need input"} + tools/call 请求 _meta.state="input_required" → INPUT_REQUIRED
    │   (客户端补充输入后回到 WORKING)
    │
    ├─ server: tools/call response {isError:false,_meta:{state:"completed"}} → COMPLETED
    │
    ├─ server: tools/call response {isError:true,_meta:{state:"failed"}} → FAILED
    │
    └─ client: `notifications/cancelled` notification → server: `tools/call` response `{state:"canceled"}` → CANCELED
```

注：MCP spec `ProgressNotification` params 字段为 `progressToken` / `progress` / `total` / `message`，**无 `state` 字段**。`state` 仅通过 tools/call 请求/响应的 `_meta.state` 传递。

状态值（与扩展表 31 `state` 字段一致）：

| 状态 | 含义 |
|---|---|
| `submitted` | 已提交 |
| `working` | 处理中 |
| `input_required` | 需要用户输入 |
| `completed` | 完成 |
| `failed` | 失败 |
| `canceled` | 已取消 |

### 5.4 能力双向门控规则

MCP `initialize` 阶段客户端与服务端互相声明 `capabilities`，后续方法调用须遵循以下门控规则：

**规则 1（client → server）**：客户端声明的能力 → 服务端必须响应。
- 若服务端不支持客户端声明的能力（例如客户端声明 `roots:{}` 但服务端未实现 `roots/list`），服务端可在响应中省略该能力键并加 `_meta.warnings=["unsupported capability: roots"]`（优雅降级）。
- 后续若客户端调用服务端未支持的方法，服务端返回 `error.code=-32601 Method not found`。

**规则 2（server → client）**：服务端声明的能力 → 客户端可选择性接受。
- 客户端可以忽略服务端声明的能力（例如服务端声明 `tools:{}` 但客户端不调用 `tools/list`），不报错。
- 但若客户端调用了服务端未声明的方法（如 `tools/call` 但服务端 capabilities 无 `tools`），服务端返回 `error.code=-32601 Method not found`。

**规则 3（双方未识别）**：双方任一不识别的能力键 → 优雅降级（warning 而非 error）。
- 双方保留未知键原样传递（透传），加 `_meta.warnings=["unknown capability: <key>"]`。
- 不影响后续通信。

**规则 4（能力缺失语义）**：capabilities 中某键缺失 = 不支持该能力。
- 例如 `ClientCapabilities={}` 表示客户端不支持 roots / sampling / 任何方法。
- 例如 `ServerCapabilities={}` 表示服务端不暴露 tools / resources / prompts / logging / completion / 任何方法。
- Validate 默认 `{}`（不自动注入能力键），用户须显式填入。

**规则 5（重复字段）**：JSON 中 capabilities 含重复键 → Validate 拒绝。
- JSON 解析器对重复键行为不一致（Go `encoding/json` 取最后一个，Python `json` 取最后一个，JS 取第一个），planner 须拒绝以避免语义歧义。
- **实现机制**：Validate 前使用自定义 JSON tokenizer（`internal/protocol/mcp/mcp_helpers.go` 中的 `checkDuplicateKeys()` 函数）对 `ClientCapabilities` 与 `ServerCapabilities` 原始字节流做一次顶层对象键扫描；若发现同一对象层级下存在重复键名（不论值是否相同），立即返回 `error: duplicate capability key "<key>"`。该检查在标准 JSON 解析前完成，确保即使下游库采取 last-wins 语义也能提前拒绝。**不采用**改写为"接受 last-wins"方案——理由是 spec 明确禁止重复键（JSON-RPC 2.0 / MCP 均要求唯一键），planner 应严格遵循而非兼容模糊行为。

| 场景 | 客户端声明 | 服务端响应 | 后续方法 | 行为 |
|---|---|---|---|---|
| 双向协商成功 | `roots:{}` + `sampling:{}` | `tools:{}` + `resources:{}` | `roots/list`, `sampling/createMessage` | 全部合法 |
| 客户端声明，服务端不支持 | `roots:{}` | capabilities 无 `roots` | `roots/list` (S→C) | 服务端 -32601 |
| 服务端声明，客户端忽略 | 无声明 | `tools:{}` | 客户端不调 `tools/list` | 无影响（无调用） |
| 客户端空 + 服务端填 | `{}` | `tools:{}` + `resources:{}` | 客户端调用 `tools/list` | 合法（server→client 方向可选）；若客户端调用 server 未声明的 `roots/list` 则 server 返回 -32601 |
| 客户端填 + 服务端空 | `roots:{}` + `sampling:{}` | `{}` | 客户端调用 `tools/list` | server 返回 -32601（server 未声明 tools）；`roots/list`（S→C）server 返回 -32601（server 未实现） |
| 双方未识别 | `experimental:{}` | 透传 `experimental:{}` + warnings | 任何 | warning，继续通信 |
| 能力缺失 | `{}` | `{}` | 任何 | 全部 -32601 |

### 5.5 id 配对规则

- 每个 request 必须有唯一 `id`（整数或字符串）。planner 用 `IDCounter` 递增分配。
- response 必须携带对应 request 的 `id`。
- notification 无 `id`，不期待响应。
- `notifications/cancelled` 的 `params.requestId` 引用被取消的 request id（不是 notification 自己的 id）。
- `notifications/progress` 的 `params.progressToken` 引用 tools/call 请求 `_meta.progressToken`（可能是整数或字符串）。

### 5.6 不允许的状态跳转

Validate 与 Plan 必须拒绝以下情况：

1. `Requests` 第一个方法是 `tools/call` 但 `initialize` 未在序列中（planner 自动注入 `initialize` + `notifications/initialized`，除非用户显式跳过——见 §7.18 边界）。
2. `notifications/initialized` 出现在 `initialize` 响应之前。
3. `tools/call` 调用的工具名未在 `tools/list` 响应中出现过（planner 不强制校验，因用户可能省略 tools/list；但若同时配置了 tools/list 与 tools/call，工具名应一致——planner 在 §7.4 场景下校验）。
4. `resources/subscribe` 在服务端 `capabilities.resources.subscribe` 未声明（即不在 `{}` 中）时：planner 按 §5.4 能力双向门控规则生成服务端 error.code=-32601（user 须显式填入 `resources:{subscribe:true}` 才启用此方法）。
5. `sampling/createMessage` 在客户端 `capabilities.sampling` 未声明时：planner 按 §5.4 规则生成服务端 error.code=-32601（user 须显式填入 `sampling:{}` 才启用此方法）。
6. capabilities JSON 含重复键（如 `{"roots":{},"roots":{}}`）→ Validate 拒绝。

---

## 6. Plan 输出

### 6.1 总体流程

`Planner.Plan(ctx, spec)` 流程：

1. 调用 `Validate(spec)`，失败则返回 error。
2. 应用默认值（Transport/ProtocolVersion/ClientInfo/...）。
3. 建立 TCP 流（4-tuple 来自 `spec.SrcIP/DstIP/SrcPort/DstPort`）：
   - 若 `spec.TCP.Handshake=true`（默认）：emit SYN/SYN-ACK/ACK。
   - 若 `spec.TCP.Termination=true`（默认）且 `Shutdown=true`：在最后 emit 3 包 teardown：FIN-ACK(up) → FIN-ACK(down) → ACK(up)，合并中间 ACK（与 §6.2 表格 + socks5 模板 + A2A H-7 一致）。
4. 按 `Transport` 模式生成应用层载荷：
   - stdio：行分隔 JSON（每行一包），所有方向都走 TCP payload。
   - http_sse：客户端请求 = HTTP POST 请求行 + 头 + JSON body；服务端响应/通知 = SSE 事件流（持续 GET 或 POST 响应 SSE）。
   - streamable：客户端请求 = HTTP POST；服务端响应 = JSON body 或 SSE 流。
5. 按状态机顺序 emit：
   a. `initialize` 请求（C→S）
   b. `initialize` 响应（S→C）
   c. `notifications/initialized` 通知（C→S）
   d. （可选）HTTP 模式下：对于旧版 HTTP+SSE，**GET `/mcp` 建立 SSE 流必须先于 POST**（spec 2024-11-05 §basic/transports），服务端通过 SSE 流第一个 `event: endpoint` 事件告知 POST URI，客户端后续 POST 到该 URI；对于 Streamable HTTP，POST `/mcp` 直接返回 JSON 或 SSE 流，GET `/mcp` 仅用于服务端主动推送（持续 SSE 长连接）
   e. `Requests[0..N-1]` 中每个请求：
      - emit 请求（C→S）
      - emit 对应响应（S→C，从 `Responses` 匹配 id，未匹配则合成成功响应）
      - 在 `Notifications[i].Step == 当前请求 index` 时插入通知
   f. 若 `Rounds > 1`：重复 e（id 继续递增，不重置）
   g. 若 `Shutdown=true`：TCP FIN teardown。
6. 输出到 `configChan`，每个 PacketConfig 一帧。

### 6.2 stdio 模式 PacketConfig 序列

单会话 default 流程（initialize + tools/list + tools/call + shutdown）：

| # | 方向 | TCP flags | Payload |
|---|---|---|---|
| 1 | up | SYN | (无) |
| 2 | down | SYN-ACK | (无) |
| 3 | up | ACK | (无) |
| 4 | up | PSH-ACK | `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05",...}}\n` |
| 5 | down | PSH-ACK | `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05",...}}\n` |
| 6 | up | PSH-ACK | `{"jsonrpc":"2.0","method":"notifications/initialized"}\n` |
| 7 | up | PSH-ACK | `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}\n` |
| 8 | down | PSH-ACK | `{"jsonrpc":"2.0","id":2,"result":{"tools":[...]}}\n` |
| 9 | up | PSH-ACK | `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"ping","arguments":{}}}\n` |
| 10 | down | PSH-ACK | `{"jsonrpc":"2.0","id":3,"result":{"content":[{"type":"text","text":"pong"}],"isError":false}}\n` |
| 11 | up | FIN-ACK | (无) |
| 12 | down | FIN-ACK | (无) |
| 13 | up | ACK | (无) |

实际 TCP teardown 为 4-way（FIN-ACK / ACK / FIN-ACK / ACK）或合并为 3-way（合并中间 ACK）。**planner 按 socks5 模板发 3 包：FIN-ACK(up) → FIN-ACK(down) → ACK(up)，合并中间 ACK**。TCP seq 编号：包 11 用 clientSeq（FIN-ACK），包 12 用 serverSeq（FIN-ACK），包 13 用 clientSeq（ACK）。

### 6.3 HTTP+SSE 模式 PacketConfig 序列

旧版 HTTP+SSE 模式下，**spec 强制时序**：GET `/mcp` 先建立 SSE 流，服务端通过 SSE 流第一个 `endpoint` 事件告知客户端 POST 端点 URI，客户端再 POST 到该 URI。服务端响应 POST 时**不直接返回 JSON body**（那是 Streamable HTTP 行为）；旧版应通过 GET SSE 流推送响应。**本设计按 spec 实现：GET 先于 POST，POST 响应 202 Accepted（无 body），服务端响应通过 GET SSE 流推送**。

| # | 方向 | TCP flags | Payload |
|---|---|---|---|
| 1-3 | up/down | SYN/SYN-ACK/ACK | (握手) |
| 4 | up | PSH-ACK | `GET /mcp HTTP/1.1\r\nHost: mcp.example.com:8081\r\nAccept: text/event-stream\r\n\r\n`（客户端建立 GET SSE 流） |
| 5 | down | PSH-ACK | `HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: keep-alive\r\n\r\nevent: endpoint\ndata: /mcp?session=a1b2c3d4...\n\nevent: message\ndata: {"jsonrpc":"2.0","id":1,"result":{...initialize 响应...}}\n\n`（GET SSE 响应中首先推送 `endpoint` 事件告知 POST 端点，然后推送 initialize 响应） |
| 6 | up | PSH-ACK | `POST /mcp?session=a1b2c3d4... HTTP/1.1\r\nHost: mcp.example.com:8081\r\nContent-Type: application/json\r\nAccept: application/json, text/event-stream\r\nMcp-Session-Id: a1b2c3...\r\nContent-Length: NNN\r\n\r\n{"jsonrpc":"2.0","method":"notifications/initialized"}`（POST 到 `endpoint` 事件指定的 URI；第 4-5 步省略 initialize 直接发 notifications/initialized 仅作为异常场景） |
| 7 | down | PSH-ACK | `HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\n\r\n`（POST 响应 202，无 body） |
| 8 | up | PSH-ACK | `POST /mcp?session=a1b2c3d4... HTTP/1.1\r\n...Mcp-Session-Id: a1b2c3...\r\n\r\n{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}` |
| 9 | down | PSH-ACK | `HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\n\r\n` |
| 10 | down | PSH-ACK | `event: message\ndata: {"jsonrpc":"2.0","id":2,"result":{"tools":[...]}}\n\n`（GET SSE 流推送 tools/list 响应） |
| 11+ | | FIN teardown | |

注：客户端可在第 4 步 GET SSE 后保持长连接，服务端通过该流持续推送响应/通知。每个 POST 请求的服务端响应通过同一 GET SSE 流的 event:message 事件推送（按 id 匹配）。**关键**：第 5 步（GET SSE 响应）的第一个事件必须是 `event: endpoint`，告知客户端后续 POST 使用的 URI（如 `/mcp?session=xxx`）；客户端 POST 时使用此 URI 而非硬编码 `/mcp`。

SSE 长连接模式（GET /mcp）—— 独立推送通道示例（GET 先于 POST，含 `endpoint` 事件）：

| # | 方向 | Payload |
|---|---|---|
| up | PSH-ACK | `GET /mcp HTTP/1.1\r\n...Accept: text/event-stream\r\n\r\n`（GET 不携带 Mcp-Session-Id，因尚未协商） |
| down | PSH-ACK | `HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\nevent: endpoint\ndata: /mcp?session=a1b2c3...\n\n`（服务端通过 `endpoint` 事件返回 POST URI，含 session id 查询参数） |
| down | PSH-ACK | `event: message\ndata: {"jsonrpc":"2.0","method":"notifications/resources/updated","params":{"uri":"file:///x"}}\n\n` |
| down | PSH-ACK | `event: message\ndata: {"jsonrpc":"2.0","id":3,"result":{...}}\n\n` |

### 6.4 Streamable HTTP 模式

与 HTTP+SSE 类似，但响应可能是单个 JSON 或 SSE 流（取决于服务端是否需要中途推送通知）：

```
POST /mcp HTTP/1.1
Content-Type: application/json
Mcp-Session-Id: a1b2c3...
Accept: application/json, text/event-stream

{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"long_task"}}
```

响应（SSE 流，含进度通知）：

```
HTTP/1.1 200 OK
Content-Type: text/event-stream

event: message
data: {"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":3,"progress":50,"total":100}}

event: message
data: {"jsonrpc":"2.0","id":3,"result":{"content":[{"type":"text","text":"done"}],"isError":false}}

```

### 6.5 多会话生成

多会话场景下，planner 在 `Plan` 中根据 `spec.Count`（或策略层 multi-flow）生成 M 条独立 TCP 流：

- 每条流独立 4-tuple。`src_port` 由 strategy 层（`inc`/`rand`）决定，planner 不强制；默认建议 `rand` 范围 [49152, 65535]（IANA 动态端口段，与真实 LLM 客户端行为一致）。如用户显式设置 `inc` strategy，则按 strategy 起始值递增。
- 每条流独立 sessionId（UUID 风格十六进制）。
- 每条流独立 id 序列（从 1 开始）。
- 每条流独立 TCP handshake/teardown。
- 流之间无时序关系（除非用 GroupID 路由到同一 PacketWorker）。
- src_port 冲突处理：strategy 层 `rand` 模式下若生成到已占用端口，由外层 strategy 重试（planner 不感知端口冲突，因 planner 只生成 PacketConfig，不真正建连）。

`Plan` 输出所有流的 PacketConfig 到同一 configChan，按流分组（同一流的包连续，流间不交错——除非 GroupID 不同导致路由到不同 worker）。

### 6.6 MSS 分段

JSON-RPC 包可能超过 MSS（默认 1460）。planner 按 socks5 模板的 `segmentByMSS` 切分：

- 单个 JSON 行不得跨 MSS 分段时被切断在 JSON 中间（实际上 TCP 不感知 JSON 边界，所以可以切；但为了 Wireshark MCP dissector 正确解析，建议每行 ≤ MSS）。
- planner 默认行为：若 JSON 行 > MSS，按 MSS 切成多个 TCP segment，最后一个 segment 带 PSH 标志。
- HTTP 模式：HTTP body 同样按 MSS 切分。

---

## 7. 业务场景与数据场景

### 7.1 initialize 协商

**场景**：客户端启动后第一个请求，协商协议版本与能力。

**默认 initialize 请求体**（C→S）：

```json
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{
  "protocolVersion":"2024-11-05",
  "capabilities":{"roots":{"listChanged":true},"sampling":{}},
  "clientInfo":{"name":"trafficgen-client","version":"1.0.0"}
}}
```

**默认 initialize 响应体**（S→C）：

```json
{"jsonrpc":"2.0","id":1,"result":{
  "protocolVersion":"2024-11-05",
  "capabilities":{
    "tools":{"listChanged":true},
    "resources":{"subscribe":true,"listChanged":true},
    "prompts":{"listChanged":true},
    "logging":{},"completion":{}
  },
  "serverInfo":{"name":"trafficgen-server","version":"1.0.0"}
}}
```

**变体**：
- 协议版本不匹配：客户端发 `2025-06-18`，服务端响应降级为 `2024-11-05`。
- 客户端无 sampling 能力：`capabilities` 中省略 `sampling`。
- 服务端不支持 resources.subscribe：响应 capabilities 中 `resources` 仅 `{listChanged:true}`。
- 自定义客户端名：`clientInfo.name="my-custom-llm"`。

### 7.2 initialized 通知

**场景**：客户端收到 initialize 响应后，必须发 `notifications/initialized` 通知，否则服务端不会处理后续请求。

`{"jsonrpc":"2.0","method":"notifications/initialized"}`

**变体**：
- 通知省略 params 字段（spec 标准）：`{"jsonrpc":"2.0","method":"notifications/initialized"}`——严格 spec 客户端应不发送 `params` 字段；多数 SDK 宽松接受 `params:{}` 但合规测试会标记为非标准。planner 默认不携带 `params` 字段。
- 缺失该通知（错误场景）：服务端在 OPERATING 状态外收到 tools/list，应返回 error code -32601 "Method not found"（spec 未定义单独的 "Server not initialized" 错误码；v1.1.2 错误使用 -32002 已修正——-32002 在 spec 中是 Resource not found 专用码，见 §7.5 与附录 B）。planner 在异常场景下生成此错误响应。

### 7.3 ping 心跳

**场景**：双向心跳，任意一端发 ping，对端必须响应。

请求（C→S 或 S→C）：`{"jsonrpc":"2.0","id":99,"method":"ping"}`

响应（无 result 内容）：`{"jsonrpc":"2.0","id":99,"result":{}}`

**变体**：
- 服务端主动 ping（S→C）：检测客户端存活。
- ping 带 params 省略（spec 标准）：`{"jsonrpc":"2.0","id":99,"method":"ping"}`（MCP spec 2024-11-05 `basic/utilities/ping` 明确："A ping request is a standard JSON-RPC request with no parameters"；planner 默认不携带 params 字段）。
- ping 带 params 空对象（spec 宽松接受）：`{"jsonrpc":"2.0","id":99,"method":"ping","params":{}}`，响应仍 `{}`——多数 SDK 宽松接受，但严格 spec 客户端可能 -32602 Invalid params。
- ping 带 params 非空对象（负向）：严格 spec 服务端返回 -32602 Invalid params（spec 明确 "no parameters"）。
- 连续 ping：id 递增 99, 100, 101...

### 7.4 tools/list + tools/call

**场景**：标准工具调用流程。

`tools/list` 请求（首页）：`{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`

`tools/list` 请求（翻页）：`{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{"cursor":"<上一页响应的 nextCursor>"}}`（cursor 省略表示首页；spec 2024-11-05/2025-06-18 `server/utilities/pagination` 明确 `tools/list` 支持分页）

`tools/list` 响应（默认 3 个工具：ping/echo/search）：

```json
{"jsonrpc":"2.0","id":2,"result":{"tools":[
  {"name":"ping","description":"Health check",
   "inputSchema":{"type":"object","properties":{},"additionalProperties":false}},
  {"name":"echo","description":"Echo back the input",
   "inputSchema":{"type":"object","properties":{"msg":{"type":"string"}},"required":["msg"]}},
  {"name":"search","description":"Search the knowledge base",
   "inputSchema":{"type":"object","properties":{"q":{"type":"string"},"limit":{"type":"integer","default":10}},"required":["q"]}}
]}}
```

`tools/call` 请求（调用 search）：

```json
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{
  "name":"search",
  "arguments":{"q":"hello world","limit":5},
  "_meta":{"progressToken":42}
}}
```

`tools/call` 响应（成功）：`{"jsonrpc":"2.0","id":3,"result":{"content":[{"type":"text","text":"Found 2 results for 'hello world'"}],"isError":false}}`

**变体**：
- 工具调用失败（`isError:true`）：`{"result":{"content":[{"type":"text","text":"search query too short"}],"isError":true}}`。注意 `isError:true` 是工具层错误，不是 JSON-RPC error。
- 工具返回图片：`{"content":[{"type":"image","data":"<base64>","mimeType":"image/png"}]}`。
- 工具返回嵌入资源：`{"content":[{"type":"resource","resource":{"uri":"file:///x","mimeType":"text/plain","text":"..."}}]}`（spec 2024-11-05/2025-06-18 用 `type:"resource"` 表示嵌入资源；v1.1.2 错误使用的 `embedded_resource` 是幻觉类型，已修正）。
- 工具名不存在：JSON-RPC error code -32602 "Invalid params"，message 含工具名（如 `"Unknown tool: search_nonexistent"`）。MCP spec 2024-11-05 `server/tools` §Error Handling 示例：`{"error":{"code":-32602,"message":"Unknown tool: invalid_tool_name"}}`（message 含工具名，data 未定义）。planner 在 tools/call 方法存在但 `name` 参数值不存在时使用 -32602——不同于 -32601（仅当方法名本身不存在如 `foo/bar` 时使用）。
- 参数缺失：JSON-RPC error -32602 "Invalid params"。

### 7.5 resources/list + resources/read

**场景**：列出资源并读取内容。

`resources/list` 请求：`{"jsonrpc":"2.0","id":4,"method":"resources/list","params":{"cursor":""}}`

`resources/list` 响应：

```json
{"jsonrpc":"2.0","id":4,"result":{"resources":[
  {"uri":"file:///etc/hosts","name":"hosts","mimeType":"text/plain","description":"System hosts file"},
  {"uri":"config:///app.json","name":"app config","mimeType":"application/json"}
],"nextCursor":""}}
```

`resources/read` 请求：`{"jsonrpc":"2.0","id":5,"method":"resources/read","params":{"uri":"file:///etc/hosts"}}`

`resources/read` 响应：

```json
{"jsonrpc":"2.0","id":5,"result":{"contents":[
  {"uri":"file:///etc/hosts","mimeType":"text/plain","text":"127.0.0.1 localhost\n"}
]}}
```

**变体**：
- 资源是二进制：`{"contents":[{"uri":"file:///x.png","mimeType":"image/png","blob":"<base64>"}]}`（注意 `blob` 而非 `text`）。
- uri 不存在：JSON-RPC error code **-32002 "Resource not found"** with data `{"uri":"file:///nonexistent"}`（MCP spec 2024-11-05 `server/resources` §Error Handling 明确：`Resource not found: -32002`；2025-06-18 同样使用 -32002）。
- 分页：cursor 非空，响应 nextCursor 非空表示有更多。

### 7.6 resources/subscribe + notifications/resources/updated

**场景**：客户端订阅资源变更，服务端在资源变化时推送通知。

`resources/subscribe` 请求：`{"jsonrpc":"2.0","id":6,"method":"resources/subscribe","params":{"uri":"file:///etc/hosts"}}`

`resources/subscribe` 响应：`{"jsonrpc":"2.0","id":6,"result":{}}`

后续通知（S→C，planner 默认在响应后立即发一条）：`{"jsonrpc":"2.0","method":"notifications/resources/updated","params":{"uri":"file:///etc/hosts"}}`

**变体**：
- 服务端不支持 subscribe：initialize 响应 capabilities 中 `resources.subscribe` 缺失/为 false。planner 默认支持，异常场景下可设为 false 并验证客户端请求得到 -32601 错误。
- 资源列表变更：`{"method":"notifications/resources/list_changed"}`，客户端收到后应重新 resources/list。
- 取消订阅（MCP spec 2025-03-26 中间版本扩展）：`{"jsonrpc":"2.0","id":7,"method":"resources/unsubscribe","params":{"uri":"file:///etc/hosts"}}`——**spec 2024-11-05 与 2025-06-18 不定义此方法**；planner 仅在用户显式配置 `protocol_version="2025-03-26"` 时生成此方法，否则作为 -32601 Method not found 异常场景。

### 7.7 prompts/list + prompts/get

**场景**：列出提示词模板并渲染。

`prompts/list` 请求：`{"jsonrpc":"2.0","id":8,"method":"prompts/list","params":{}}`

`prompts/list` 响应：

```json
{"jsonrpc":"2.0","id":8,"result":{"prompts":[
  {"name":"code_review","description":"Review code",
   "arguments":[{"name":"language","description":"Programming language","required":true}]}
]}}
```

`prompts/get` 请求：`{"jsonrpc":"2.0","id":9,"method":"prompts/get","params":{"name":"code_review","arguments":{"language":"go"}}}`

`prompts/get` 响应（单消息）：

```json
{"jsonrpc":"2.0","id":9,"result":{"description":"Review code","messages":[
  {"role":"user","content":{"type":"text","text":"Review this Go code..."}}
]}}
```

`prompts/get` 响应（多消息 + 多部分，使用 `parts` 字段）：

```json
{"jsonrpc":"2.0","id":9,"result":{"messages":[
  {"role":"user","content":{"type":"text","text":"Review this code"}},
  {"role":"assistant","content":{"type":"text","text":"I'll review it"}},
  {"role":"user","content":{"type":"resource","resource":{"uri":"file:///main.go","mimeType":"text/x-go","text":"package main..."}}}
]}}
```

### 7.8 completion/complete

**场景**：参数补全。

请求：

```json
{"jsonrpc":"2.0","id":10,"method":"completion/complete","params":{
  "ref":{"type":"ref/prompt","name":"code_review"},
  "argument":{"name":"language","value":"g"}
}}
```

响应：`{"jsonrpc":"2.0","id":10,"result":{"completion":{"values":["go","golang","google go"],"total":3,"hasMore":false}}}`

**变体**：
- 资源引用补全：`"ref": {"type":"ref/resource","uri":"file:///{cursor}"}`。
- hasMore=true：客户端应再次调用以获取更多（planner 不模拟分页续传，仅生成单次响应）。

### 7.9 logging/setLevel + notifications/message

**场景**：客户端设置日志级别，服务端推送日志。

`logging/setLevel` 请求：`{"jsonrpc":"2.0","id":11,"method":"logging/setLevel","params":{"level":"debug"}}`

响应：`{"jsonrpc":"2.0","id":11,"result":{}}`

后续通知（S→C）：

```json
{"jsonrpc":"2.0","method":"notifications/message","params":{
  "level":"debug","logger":"mcp.tools",
  "data":{"tool":"search","duration_ms":42,"msg":"tool called"}
}}
```

**变体**：
- 不同 level：debug/info/notice/warning/error/critical/alert/emergency（RFC 5424 严重性等级）。
- data 为字符串：`"data": "simple log message"`（非对象，允许）。
- 不同 logger：`"mcp.resources"`、`"mcp.prompts"`、自定义名。

### 7.10 notifications/cancelled

**场景**：客户端取消进行中的请求。

通知（C→S，在 tools/call 响应之前发出）：`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":3,"reason":"user cancelled"}}`

服务端行为：停止处理 id=3 的请求，可选返回 error response -32800 "Request cancelled"（**非 spec 标准，部分 SDK 实现**；JSON-RPC 2.0 §5.1 保留 -32000~-32099，-32800 超出此范围）或不响应。planner 默认不响应（cancelled 通知无对应响应）；如用户显式配置 error response -32800，planner 接受（附录 B "非标准扩展错误码"小节已标注此码非 spec 标准）。

**变体**：
- 缺少 requestId：违反 spec，planner 在异常场景生成。
- requestId 为字符串：`"requestId": "abc-123"`（与原请求 id 类型一致）。
- reason 缺失：`{"requestId":3}`（reason 可选）。

### 7.11 notifications/progress

**场景**：长任务进度推送。

通知（S→C 或 C→S，由 progressToken 决定方向）：`{"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":42,"progress":50,"total":100,"message":"Half done"}}`

`progressToken` 来自 tools/call 请求的 `_meta.progressToken`（可为整数或字符串）。

**变体**：
- progress 超过 total：异常场景，planner 不主动生成。
- 嵌套进度（parentId）：`{"progressToken":42,"progress":50,"total":100,"parentId":"parent-task-1"}`（扩展表 31 字段 parentId）。
- 字符串 progressToken：`"progressToken": "task-abc"`。

### 7.12 roots/list + notifications/roots/list_changed

**场景**：服务端反查客户端的文件系统根。

`roots/list` 请求（S→C，注意方向；params 省略，与 spec 示例一致）：

```json
{ "jsonrpc": "2.0", "id": 12, "method": "roots/list" }
```

注：MCP spec 2024-11-05 `client/roots` 示例为 `{"jsonrpc":"2.0","id":1,"method":"roots/list"}`（**无 params 字段**）。JSON-RPC 2.0 允许 params 省略或为空对象（语义等价），但 spec 示例明确不带 params。**planner 默认省略 params 字段**（与 spec 示例一致）；若用户显式配置 `params:{}`，planner 也接受（宽松 spec 兼容）。

`roots/list` 响应（C→S）：

```json
{
  "jsonrpc": "2.0",
  "id": 12,
  "result": {
    "roots": [
      { "uri": "file:///home/user/project", "name": "project" },
      { "uri": "file:///tmp", "name": "temp" }
    ]
  }
}
```

`notifications/roots/list_changed` 通知（C→S，无参数）：

```json
{ "jsonrpc": "2.0", "method": "notifications/roots/list_changed" }
```

服务端收到后应重新 roots/list（planner 不模拟此行为，仅生成通知）。

### 7.13 sampling/createMessage

**场景**：服务端请求客户端 LLM 采样（反向请求）。

请求（S→C）：

```json
{"jsonrpc":"2.0","id":13,"method":"sampling/createMessage","params":{
  "messages":[
    {"role":"user","content":{"type":"text","text":"Summarize this document"}},
    {"role":"user","content":{"type":"resource","resource":{"uri":"file:///doc.md","text":"..."}}}
  ],
  "modelPreferences":{"hints":[{"name":"claude"},{"name":"sonnet"}],
    "costPriority":0.3,"speedPriority":0.5,"intelligencePriority":0.8},
  "systemPrompt":"You are a helpful assistant",
  "maxTokens":200,
  "metadata":{"requestSource":"tool_search"}
}}
```

响应（C→S）：

```json
{"jsonrpc":"2.0","id":13,"result":{
  "role":"assistant",
  "content":{"type":"text","text":"Here's the summary..."},
  "model":"claude-3-sonnet-20240229",
  "stopReason":"endTurn","stopSequence":""
}}
```

**变体**：
- 采样被拒绝（user rejected）：`{"error":{"code":-1,"message":"User rejected sampling request"}}`（spec 2024-11-05/2025-03-26/2025-06-18 `client/sampling` Error Handling 示例使用 `code: -1`）。
- 图片内容：`"content":{"type":"image","data":"<base64>","mimeType":"image/jpeg"}`。
- stopReason="stopSequence"，stopSequence="\n\n"。
- `temperature` / `stopSequences` 字段（spec 2024-11-05/2025-03-26/2025-06-18 `client/sampling` 的 `CreateMessageRequest` schema 中包含 `temperature: number` / `stopSequences: string[]`，但 spec 示例均未展示这两个字段；可作为 planner 完整请求的可选字段）。

### 7.14 认证 Bearer/Basic/OAuth2（字段占位）

**场景**：HTTP 模式下客户端携带认证头。

Bearer：

```
POST /mcp HTTP/1.1
Authorization: Bearer eyJhbGciOiJIUzI1NiJ9...
```

Basic：

```
POST /mcp HTTP/1.1
Authorization: Basic dXNlcjpwYXNz
```

OAuth2（占位，不模拟真实 OAuth2 flow）：

```
POST /mcp HTTP/1.1
Authorization: Bearer ya29.a0ARqda...
```

initialize 响应中服务端声明认证要求（扩展表 31 字段 authentication/schemes）：

```json
{
  "result": {
    "capabilities": { ... },
    "serverInfo": { ... },
    "authentication": {
      "schemes": ["Bearer", "OAuth2"],
      "credentials": { "oauth2": { "authorizeUrl": "https://...", "tokenUrl": "https://..." } }
    }
  }
}
```

**planner 行为**：仅生成报文字段，不执行真实 OAuth2 flow。`Auth.Schemes` 仅控制 Authorization 头格式与 initialize 响应中 authentication 字段。

### 7.15 state 状态机（submitted/working/input_required/completed/failed/canceled）

**场景**：长任务 tools/call 携带 state 字段，服务端通过 notifications/progress 推送状态转换。

完整状态流（C→S tools/call → S→C 多个 progress → S→C tools/call response）：

```json
// C→S: tools/call
{"jsonrpc":"2.0","id":14,"method":"tools/call","params":{"name":"long_task","arguments":{},"_meta":{"progressToken":14,"state":"submitted"}}}

// S→C: progress (working)
{"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":14,"progress":10,"total":100,"message":"started"}}

// S→C: progress (input_required)
{"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":14,"progress":50,"total":100,"message":"need confirmation"}}

// C→S: continue (用户输入，自定义方法或再次 tools/call)
{"jsonrpc":"2.0","id":15,"method":"tools/call","params":{"name":"long_task","arguments":{"confirm":true},"_meta":{"progressToken":14,"state":"working"}}}

// S→C: progress (working)
{"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":14,"progress":90,"total":100}}

// S→C: tools/call response (completed)
{"jsonrpc":"2.0","id":15,"result":{"content":[{"type":"text","text":"done"}],"isError":false,"_meta":{"state":"completed"}}}
```

**变体**：
- 直接 completed（无 input_required）：跳过中间状态。
- failed：`{"result":{"content":[{"type":"text","text":"error: db down"}],"isError":true,"_meta":{"state":"failed"}}}`。
- canceled：客户端发 notifications/cancelled，服务端响应 `{"result":{"content":[{"type":"text","text":"canceled"}],"isError":true,"_meta":{"state":"canceled"}}}`。

### 7.16 多会话并发

**场景**：M 个客户端同时连接同一 MCP 服务端。

生成方式：
- `spec.Count = M`（每条流一份 FlowSpec 副本）。
- 每条流独立 src_port（递增）。
- 每条流独立 sessionId（HTTP 模式）。
- 每条流独立 id 序列。
- 每条流独立 TCP handshake/teardown。
- 流间无时序关系（除非用 GroupID）。

示例（M=3，HTTP+SSE 模式）：

| 流 | src_port | session_id | id 序列 |
|---|---|---|---|
| 1 | 50001 | a1b2c3... | 1, 2, 3 |
| 2 | 50002 | d4e5f6... | 1, 2, 3 |
| 3 | 50003 | g7h8i9... | 1, 2, 3 |

planner 输出：所有流的 PacketConfig 拼接到同一 configChan。同流内包连续，流间不交错（除非 GroupID 不同）。

**变体**：
- 多会话不同协议版本：流1用 2024-11-05，流2用 2025-03-26。
- 多会话不同客户端：流1 clientInfo.name="claude-desktop"，流2="cursor"。
- 多会话不同工具调用：流1调 search，流2调 echo，流3调 ping。
- 多会话部分失败：流1正常，流2 initialize 失败（响应 error），流3正常。

### 7.17 contextId/parentId 调用链

**场景**：tools/call 携带 contextId 用于调用链追踪，notifications/progress 携带 parentId 表示嵌套进度。

请求（C→S，带 contextId）：

```json
{"jsonrpc":"2.0","id":16,"method":"tools/call","params":{
  "name":"search","arguments":{"q":"x"},
  "_meta":{"contextId":"ctx-abc-123","progressToken":16}
}}
```

进度通知（S→C，带 parentId）：

```json
{"jsonrpc":"2.0","method":"notifications/progress","params":{
  "progressToken":16,"progress":30,"total":100,
  "parentId":"parent-task-xyz","message":"subtask 30%"
}}
```

`contextId` 在同一调用链的所有相关消息中保持一致（请求、响应、progress 通知）。`parentId` 标识父任务，用于嵌套进度（一个父任务拆成多个子任务）。

### 7.18 边界场景

| # | 场景 | 期望行为 |
|---|---|---|
| 1 | `params` 空对象 `{}` | 正常发送，方法不要求参数时合法 |
| 2 | `params` 完全省略 | planner 发出无 params 字段的请求（notifications/initialized 默认无 params） |
| 3 | `id` = 0 | Validate 接受（0 表示"未设置，由 planner 自动分配"，见 §4.1 IDCounter 注释）；但混用模式被拒绝——同一 FlowSpec 内若出现非零 ID 则所有 ID 必须显式（不允许部分自动部分显式）。**注**：因 Go `int` 类型零值与显式 0 无法区分，若用户需"显式 0"语义应改用 `*int`（v1.2 评估 API 改动）；当前设计下显式 0 与自动分配等价 |
| 4 | `id` = 最大整数 (2^31-1) | planner 接受，emit 时正常 |
| 5 | `id` 为字符串 "abc" | planner 接受（JSON-RPC 允许 string id），emit `"id":"abc"` |
| 6 | `method` 空字符串 | Validate 拒绝（"method is required"） |
| 7 | `uri` 超长（>10KB） | planner 接受，按 MSS 分段；resources/read 请求 body 大 |
| 8 | `content` 0 字节 | tools/call 响应 content 数组为空 `[]`，合法但异常 |
| 9 | `capabilities` 全空 `{}` | initialize 请求/响应合法，表示无任何能力（服务端不暴露任何方法） |
| 10 | `protocolVersion` 未知值如 "1999-01-01" | Validate 拒绝（仅接受 MCP spec 已发布版本） |
| 11 | JSON 行含 `\n`（被转义为 `\\n`） | planner 序列化时自动转义，单行长度增加但不破坏行分隔 |
| 12 | 单个 JSON-RPC 包 > 64KB | planner 按 MSS 切分多个 TCP segment，Wireshark 仍能重组 |
| 13 | `Mcp-Session-Id` 头超长（>1KB） | planner 接受，HTTP 头无硬性上限 |
| 14 | `notifications/initialized` 出现在 initialize 之前 | Validate 拒绝（违反状态机） |
| 15 | `tools/call` 出现在 initialize 之前 | Validate 拒绝（违反状态机） |
| 16 | 多会话 M=0 | planner emit 0 个流（不报错，空任务） |
| 17 | 多会话 M=1000 | planner 接受，可能受 buffer_size 限制触发 overflow |
| 18 | `Rounds` = 0 | 默认为 1（Validate 后） |
| 19 | `Rounds` = 10000 | planner 接受，id 递增到 10000*N（不超过 int32 上限） |
| 20 | Streamable HTTP 模式 GET /mcp 但未携带 Mcp-Session-Id | 服务端返回 400 Bad Request（spec 2025-03-26 `basic/transports` §Streamable HTTP：GET /mcp 要求携带 Mcp-Session-Id；旧版 HTTP+SSE 的 GET 不携带 session id（spec 2024-11-05 时序：GET 先于 POST，session id 由 `endpoint` 事件返回），不属于错误场景） |

### 7.19 异常场景（JSON-RPC 错误响应）

| # | 场景 | 错误码 | 错误消息 |
|---|---|---|---|
| 1 | JSON 解析失败 | -32700 | Parse error |
| 2 | 非 JSON-RPC 2.0 对象（缺 jsonrpc 字段） | -32600 | Invalid Request |
| 3 | 方法不存在（如 `foo/bar`） | -32601 | Method not found |
| 4 | 参数缺失/类型错 | -32602 | Invalid params |
| 5 | 服务端内部错误 | -32603 | Internal error |
| 6 | resources/read 请求的 uri 不存在 | **-32002** | **Resource not found**（MCP spec 2024-11-05/2025-06-18 `server/resources` §Error Handling；v1.1.2 错误使用 -32602 已修正） |
| 7 | sampling/createMessage 用户拒绝 | -1 | User rejected sampling request（spec 示例 `client/sampling` §Error Handling） |
| 8 | 请求取消（**非 spec 标准，部分 SDK 实现**） | -32800 | Request cancelled（仅在用户显式配置时生成） |
| 9 | tools/call 工具内部错误（isError:true） | 无 JSON-RPC error，result.isError=true | 工具层错误 |
| 10 | initialize 协议版本不匹配 | 仍返回 200，但 protocolVersion 降级（不报错） |

**异常码边界说明**：
- -32601 仅当方法名本身不存在时使用（如客户端发 `foo/bar` 这种完全不存在的方法名）。
- -32602 用于"方法存在但参数错"（如 `tools/call` 方法存在但 `name` 参数值不存在，或 ping 带非空 params）；message 应包含问题字段名（如 `"Unknown tool: <name>"`，spec 示例格式）。
- -32002 用于 `resources/read` 请求的 uri 不存在（spec 2024-11-05 `server/resources` §Error Handling 明确）。
- -1 用于 `sampling/createMessage` 用户拒绝（spec 示例）。
- -32800 非 spec 标准，仅在用户显式配置时生成（见附录 B "非标准扩展错误码"）。

**Parse error 示例**（S→C）：

```json
{ "jsonrpc": "2.0", "id": null, "error": { "code": -32700, "message": "Parse error" } }
```

**Invalid Request 示例**（缺 jsonrpc 字段的请求得到的响应）：

```json
{ "jsonrpc": "2.0", "id": 1, "error": { "code": -32600, "message": "Invalid Request", "data": { "reason": "missing jsonrpc field" } } }
```

**Method not found 示例**：

```json
{ "jsonrpc": "2.0", "id": 5, "error": { "code": -32601, "message": "Method not found", "data": { "method": "foo/bar" } } }
```

**Invalid params 示例**：

```json
{ "jsonrpc": "2.0", "id": 5, "error": { "code": -32602, "message": "Invalid params", "data": { "param": "name", "reason": "required" } } }
```

planner 在异常场景下生成这些错误响应。配置方式：

```json
{
  "mcp": {
    "requests": [{ "id": 5, "method": "foo/bar" }],
    "responses": [{ "id": 5, "error": { "code": -32601, "message": "Method not found", "data": { "method": "foo/bar" } } }]
  }
}
```

---

## 8. 测试用例清单

本节是历史设计测试清单（v1.0 60 条，后续修订至 104 条）；当前可执行机器契约以 `trafficgen/test/protocol_pcap/cases/mcp.json` 为唯一权威，共 103 条（89 正例、14 负例）。设计清单中的未落入 JSON 的场景只能登记为缺口，不能视为已覆盖。

### 8.1 报文格式与序列化（§2）— 6 条

| # | 名称 | 类型 | 验证点 |
|---|---|---|---|
| T01 | stdio 行分隔 JSON 单包编码 | 正向 | 单个 initialize 请求序列化为单行 JSON，以 `\n` 结尾，无 BOM |
| T02 | JSON 行内 `\n` 转义 | 边界 | params 中含换行符的字符串，序列化为 `\\n`，行数不变 |
| T03 | HTTP POST 请求行+头+body 格式 | 正向 | `POST /mcp HTTP/1.1\r\n...` 完整头部 + JSON body |
| T04 | SSE 事件格式（event+data+\n\n） | 正向 | `event: message\ndata: {...}\n\n`，事件间空行分隔 |
| T05 | JSON-RPC 请求必填字段校验 | 负向 | 缺 jsonrpc/id/method 任一字段，Validate 拒绝 |
| T06 | JSON-RPC 响应 result/error 互斥 | 负向 | 同时设置 result 与 error，Validate 拒绝 |

### 8.2 生命周期方法（§3.1, §7.1-§7.3）— 6 条

| # | 名称 | 类型 | 验证点 |
|---|---|---|---|
| T07 | initialize 请求默认字段 | 正向 | protocolVersion="2024-11-05"，clientInfo 默认值，capabilities 含 roots+sampling |
| T08 | initialize 响应默认 capabilities | 正向 | result.capabilities 含 tools/resources/prompts/logging/completion |
| T09 | notifications/initialized 通知无 id | 正向 | 通知对象无 id 字段，无响应 |
| T10 | ping 请求-响应配对 | 正向 | id=99 ping 请求 → id=99 空结果响应 |
| T11 | initialize 协议版本降级 | 边界 | 客户端发 2025-06-18，服务端响应 2024-11-05 |
| T12 | 跳过 initialize 直接 tools/call | 负向 | Validate 拒绝（违反状态机） |

### 8.3 工具方法（§3.2, §7.4）— 5 条

| # | 名称 | 类型 | 验证点 |
|---|---|---|---|
| T13 | tools/list 默认 3 工具响应 | 正向 | ping/echo/search 三个工具，含 inputSchema |
| T14 | tools/call 成功响应 | 正向 | content 含 text 块，isError=false |
| T15 | tools/call 工具层失败（isError:true） | 边界 | result.isError=true，content 含错误文本 |
| T16 | tools/call 返回图片内容 | 正向 | content 含 image 块，data 为 base64，mimeType=image/png |
| T17 | tools/call 工具名不存在 | 负向 | JSON-RPC error -32602 Invalid params，message 含工具名（如 `"Unknown tool: <name>"`，spec 2024-11-05 `server/tools` §Error Handling 示例） |

### 8.4 资源方法（§3.3, §7.5-§7.6）— 5 条

| # | 名称 | 类型 | 验证点 |
|---|---|---|---|
| T18 | resources/list 含分页 cursor | 正向 | 请求 cursor 非空，响应 nextCursor 非空 |
| T19 | resources/read 文本资源 | 正向 | contents[0].text 为字符串，mimeType=text/plain |
| T20 | resources/read 二进制资源 | 正向 | contents[0].blob 为 base64（非 text 字段） |
| T21 | resources/subscribe + notifications/updated | 正向 | subscribe 请求 → 响应 → updated 通知，uri 一致 |
| T22 | resources/read uri 不存在 | 负向 | JSON-RPC error **-32002 Resource not found**（MCP spec 2024-11-05 `server/resources` §Error Handling），data.uri 字段 |

### 8.5 提示词与补全（§3.4-§3.5, §7.7-§7.8）— 4 条

| # | 名称 | 类型 | 验证点 |
|---|---|---|---|
| T23 | prompts/list 含 arguments 元数据 | 正向 | 每个 prompt 含 arguments 数组，required 字段 |
| T24 | prompts/get 单消息响应 | 正向 | messages[0].role=user，content.type=text |
| T25 | prompts/get 多消息多部分响应 | 正向 | messages 含 user+assistant+resource 三种 role |
| T26 | completion/complete 响应 | 正向 | completion.values 数组，total+hasMore 字段 |

### 8.6 日志与通知（§3.6-§3.7, §7.9-§7.11）— 5 条

| # | 名称 | 类型 | 验证点 |
|---|---|---|---|
| T27 | logging/setLevel 各级别 | 正向 | level ∈ {debug,info,notice,warning,error,critical,alert,emergency} |
| T28 | notifications/message 数据为对象 | 正向 | data 含 tool/duration_ms/msg 字段 |
| T29 | notifications/cancelled 携带 requestId | 正向 | params.requestId 等于被取消请求的 id |
| T30 | notifications/progress 携带 progressToken | 正向 | progressToken 等于 tools/call 请求 _meta.progressToken |
| T31 | notifications/progress 缺 progressToken | 负向 | Validate 拒绝 |

### 8.7 Roots 与 Sampling（§3.8-§3.9, §7.12-§7.13）— 4 条

| # | 名称 | 类型 | 验证点 |
|---|---|---|---|
| T32 | roots/list 服务端→客户端请求 | 正向 | 方向 S→C，id 由服务端分配 |
| T33 | notifications/roots/list_changed 通知 | 正向 | 无 params，无 id |
| T34 | sampling/createMessage 完整请求 | 正向 | messages+modelPreferences+maxTokens+temperature 全字段 |
| T35 | sampling 响应 stopReason=endTurn | 正向 | result.role=assistant，content.type=text，model 非空 |

### 8.8 认证（§7.14）— 3 条

| # | 名称 | 类型 | 验证点 |
|---|---|---|---|
| T36 | Bearer 认证头 | 正向 | Authorization: Bearer <token>，仅 HTTP 模式 |
| T37 | Basic 认证头 | 正向 | Authorization: Basic <base64(user:pass)> |
| T38 | initialize 响应含 authentication 字段 | 正向 | result.authentication.schemes 数组 |

### 8.9 长任务状态机（§7.15）— 4 条

| # | 名称 | 类型 | 验证点 |
|---|---|---|---|
| T39 | state 完整流（submitted→working→completed） | 正向 | tools/call 请求 + 2 个 progress 通知 + 最终响应 _meta.state=completed |
| T40 | state input_required 中间状态 | 边界 | tools/call 请求 `_meta.state` 序列含 `submitted` → `working` → `input_required` → `working`（继续）；progress 通知本身不含 `state` 字段（与 L671/T80 一致，`state` 仅在 `_meta` 中） |
| T41 | state failed 终态 | 边界 | 最终响应 isError=true，_meta.state=failed |
| T42 | state canceled（客户端取消） | 边界 | notifications/cancelled + 服务端响应 _meta.state=canceled |

### 8.10 多会话并发（§7.16）— 3 条

| # | 名称 | 类型 | 验证点 |
|---|---|---|---|
| T43 | 3 会话独立 4-tuple 与 sessionId | 正向 | 3 条 TCP 流，src_port 递增，sessionId 不同；**聚合断言**：总包数 == 3 × 单流包数；用 `-race` 跑（无数据竞争） |
| T44 | 多会话独立 id 序列 | 正向 | 每条流 id 从 1 开始，不跨流共享；**聚合断言**：3 条流的 packet_index 全局唯一无重复（防止索引冲突） |
| T45 | 多会话部分失败 | 边界 | 流1正常，流2 initialize 失败，流3正常；**聚合断言**：流1+流3 总包数 == 2 × 单流正常包数，流2 包数 == 单流 initialize 失败包数 |

### 8.11 调用链（§7.17）— 2 条

| # | 名称 | 类型 | 验证点 |
|---|---|---|---|
| T46 | contextId 贯穿调用链 | 正向 | tools/call 请求与响应 _meta.contextId 一致 |
| T47 | parentId 嵌套进度 | 正向 | notifications/progress params.parentId 非空 |

### 8.12 边界与异常（§7.18-§7.19）— 6 条

| # | 名称 | 类型 | 验证点 |
|---|---|---|---|
| T48 | id=0 被接受（自动分配语义） | 边界 | Validate 接受 `Requests[i].ID=0`（表示自动分配）；Plan 阶段从 IDCounter 递增分配唯一 id；若混用模式（部分 0 部分非零）则 Validate 拒绝，错误信息"mixed auto and explicit id assignment is not allowed" |
| T49 | method 空字符串被拒绝 | 负向 | Validate 拒绝 |
| T50 | JSON-RPC parse error 响应 | 负向 | error.code=-32700，id=null |
| T51 | JSON-RPC method not found 响应 | 负向 | error.code=-32601，data.method 字段 |
| T52 | JSON-RPC invalid params 响应 | 负向 | error.code=-32602，data.param+reason |
| T53 | capabilities 全空对象 | 边界 | initialize 请求 capabilities={}，合法 |

### 8.13 传输模式覆盖（§2.3-§2.5）— 3 条

| # | 名称 | 类型 | 验证点 |
|---|---|---|---|
| T54 | stdio 模式行分隔 JSON | 正向 | 所有报文为单行 JSON + `\n`，无 HTTP 头 |
| T55 | http_sse 模式 POST + SSE 双流 | 正向 | 请求为 HTTP POST，响应含 Mcp-Session-Id 头，SSE 流式响应 |
| T56 | streamable 模式单一端点 | 正向 | POST 响应为 application/json 或 text/event-stream |

### 8.14 集成与端到端（§6）— 4 条

| # | 名称 | 类型 | 验证点 |
|---|---|---|---|
| T57 | stdio 完整会话（initialize→tools/list→tools/call→shutdown） | 集成 | TCP 握手 + 6 个 JSON 行 + TCP teardown（3 包：FIN-ACK up → FIN-ACK down → ACK up）；字节级断言：第 4 包 payload 以 `{"jsonrpc":"2.0","id":1,"method":"initialize"` 开头、以 `}\n` 结尾；teardown 最后一包为 up ACK，flags=0x10 |
| T58 | HTTP+SSE 完整会话 | 集成 | **GET 先于 POST 时序**（spec 2024-11-05 §basic/transports）：HTTP POST 请求 + GET SSE 流响应；Mcp-Session-Id 一致；字节级断言：(1) 第 4 包为 up `GET /mcp HTTP/1.1\r\n`（建立 SSE 流先于 POST）；(2) GET SSE 响应第一个事件以 `event: endpoint\ndata: /mcp?session=...\n\n` 开头（spec 强制要求）；(3) 后续事件以 `event: message\ndata: {"jsonrpc":"2.0","id":1,"result":` 开头；(4) POST 请求 URI 为 endpoint 事件中 data 字段值；(5) POST 响应状态行以 `HTTP/1.1 202 Accepted\r\n` 开头 |
| T59 | 多会话 100 并发集成 | 集成 | 100 条独立 TCP 流，每条完整会话，无交叉污染；字节级断言：每条流的 sessionId 唯一（32 字符十六进制），总包数 == 100 × 单流包数 |
| T60 | MSS 分段大 JSON 包 | 集成 | 单个 JSON 行 8KB，切分为 6 个 TCP segment；字节级断言：6 个 segment payload 拼接后等于原始 JSON 行（含 `\n` 结尾），用 tshark `-r <pcap> -Y mcp -T json` 验证 MCP dissector 识别出 initialize 请求 |

**总计：60 条测试用例**（超出最低 30 条要求一倍）。

### 8.15 v1.1 新增测试用例（审计修复）

以下用例为 v1.1 修订新增，覆盖审计 §2.1-§2.3 指出的字段零覆盖、负向占比不足、聚合/字节断言不足等问题。

| # | 名称 | 类型 | 验证点 |
|---|---|---|---|
| T61 | initialize 缺 protocolVersion | 负向 | Validate 拒绝（spec 必填字段缺失） |
| T62 | tools/call 缺 name 参数 | 负向 | JSON-RPC error -32602 Invalid params，data.param=name reason=required |
| T63 | resources/subscribe 服务端 capabilities 不支持 | 负向 | 服务端响应 -32601 Method not found（capabilities.resources.subscribe=false） |
| T64 | notifications/initialized 无 params 字段 | 正向 | 严格 spec：通知对象无 `params` 字段（仅 `jsonrpc`+`method`），合规测试通过 |
| T65 | capabilities 省略（最小客户端） | 边界 | initialize 请求不带 `capabilities` 字段，Validate 接受（spec optional），planner 默认 `{}` |
| T66 | notifications/message logger 字段 | 正向 | params.logger 非空（如 "mcp.tools"），扩展表 31 字段 logger 覆盖 |
| T67 | initialize 请求携带 credentials | 正向 | params._meta.credentials 或顶层 credentials 字段，扩展表 31 字段 credentials 覆盖 |
| T68 | prompts/get 多部分 parts 字段 | 正向 | messages[i].content 含 `parts` 数组（multi-part），扩展表 31 字段 parts 覆盖 |
| T69 | tools/call 请求 _meta.metadata | 正向 | 请求 `_meta` 含自定义 metadata map，扩展表 31 字段 metadata 覆盖 |
| T70 | tools/call 长任务 pushNotification 配置 | 正向 | 请求 `_meta.pushNotification` 含 url + verificationToken，扩展表 31 字段 pushNotification/verificationToken 覆盖 |
| T71 | resources/unsubscribe 取消订阅（spec 2025-03-26 专用） | 正向/负向 | **双向用例**：(a) `protocol_version="2025-03-26"` 时正向：resources/unsubscribe 请求 → 响应 `{}`，uri 与之前 subscribe 一致；(b) `protocol_version="2024-11-05"` 或 `"2025-06-18"` 时负向：resources/unsubscribe 请求 → 服务端 -32601 Method not found（spec 不定义此方法） |
| T72 | resources/templates/list 资源模板 | 正向 | resources/templates/list 请求 → 响应 resourceTemplates 数组，每项含 uriTemplate/name |
| T73 | notifications/resources/list_changed 通知 | 正向 | S→C 通知无 id 无 params，客户端收到后应重新 resources/list |
| T74 | sampling 字段完整性 | 正向 | sampling/createMessage 请求字段覆盖 `messages`/`modelPreferences`/`systemPrompt`/`maxTokens`（spec 2024-11-05/2025-03-26/2025-06-18 `client/sampling` `CreateMessageRequest` schema 定义字段）；可选字段 `temperature`/`stopSequences` 在请求中可选出现（spec schema 定义但示例未展示） |
| T75 | 多会话 100 并发聚合速率 | 并发 | 100 并发流，断言总包数 == 100 × 单流包数；packet_index 全局唯一无重复；用 `-race` 跑 |
| T76 | GroupID 路由同流连续 | 并发 | 2 个 GroupID，断言同 GroupID 包连续（同一 PacketWorker），不同 GroupID 可交错 |
| T77 | stdio teardown 3 包字节序列 | 集成 | teardown 3 包：FIN-ACK(up,flags=0x11) → FIN-ACK(down,flags=0x11) → ACK(up,flags=0x10)；无第 4 包 ACK(down) |
| T78 | HTTP+SSE POST 响应 202 + GET SSE 流 | 集成 | POST /mcp 响应 `HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\n\r\n`（无 body）；服务端响应通过 GET SSE 流 event:message 推送 |
| T79 | MCPError.Code 拒绝正数 | 负向 | error.code=42 → Validate 拒绝（JSON-RPC 错误码不可为正） |
| T80 | state 字段不在 progress 通知 | 正向 | notifications/progress params 仅含 progressToken/progress/total/message，无 `state` 字段；state 仅在 tools/call `_meta.state` |

### 8.16 v1.1.1 新增测试用例（重审修复）

以下用例为 v1.1.1 修订新增，覆盖重审 §2-§8 发现的批量请求未覆盖、能力双向门控未定义等问题。

| # | 名称 | 类型 | 验证点 |
|---|---|---|---|
| T81 | Streamable HTTP 批量 3 请求 → 批量 3 响应 | 正向 | POST body 为 JSON 数组 `[tools/list, tools/call, resources/list]`；响应 body 为对应数组 `[resp1, resp2, resp3]`，各元素 `id` 与请求 `id` 按序对应；字节级断言：请求 body 以 `[{"jsonrpc":"2.0"` 开头，响应 body 以 `[{"jsonrpc":"2.0","id":1,` 开头 |
| T82 | 批量混合成功+失败 | 边界 | 批量含 3 请求：合法 tools/list、合法 tools/call、非法 method（foo/bar）；响应数组 3 元素：resp1 success、resp2 success、resp3 error.code=-32601；字节级断言：resp3 `error.code=-32601` 且 `error.message` 含 "Method not found" |
| T83 | 批量空数组 → 报错 | 负向 | Validate 拒绝空数组 `[]`；若强行发送，服务端返回单个 `-32600 Invalid Request` 顶层错误，`id=null` |
| T84 | 批量含非法请求 → 全部响应含 parse error | 负向 | 批量含 1 个合法 + 1 个 JSON 格式错误；服务端响应为单个 `-32700 Parse error` 顶层错误（**非逐项响应**），`id=null`；批量整体拒绝 |
| T85 | Streamable HTTP + SSE 批量响应 | 集成 | POST body 为批量数组，响应 `Content-Type: text/event-stream`，SSE 流中含 3 个 `event:message\ndata: <resp_i>\n\n` 事件，按序对应；流关闭（一次性 POST + 一次性 SSE，非长连接）；字节级断言：SSE 事件序列以 `event: message\ndata: {"jsonrpc":"2.0","id":1,` 开头 |
| T86 | client 声明 roots，server 不支持 → error | 负向 | client capabilities 含 `roots:{listChanged:true}`，server initialize 响应 capabilities 不含 `roots` 键；后续 `roots/list` 请求 → server 返回 error.code=-32601 "Method not found"（server 优雅降级：未声明 = 不支持） |
| T87 | client 声明 experimental.xyz，server 接受 → warning | 边界 | client capabilities 含 `experimental:{xyz:{...}}`（非 spec 字段），server 响应保留该字段并加 `_meta.warnings=["experimental.xyz is non-standard"]`；后续请求不被拒绝，双方继续通信 |
| T88 | 双向协商成功（roots + sampling） | 正向 | client capabilities 含 `roots:{}` + `sampling:{}`；server 响应 capabilities 含 `tools:{}` + `resources:{}`；双向协商成功；后续 `roots/list`（S→C）和 `sampling/createMessage`（S→C）均合法 |
| T89 | 能力声明空对象 `{}` | 边界 | initialize 请求 capabilities={}，响应 capabilities={}；双方均按"无能力"处理：不支持任何 methods/list、calls、resources 等；**合法但不报错**（spec optional） |
| T90 | 能力声明重复字段 → Validate 拒绝 | 负向 | `ClientCapabilities` JSON 含重复键（如 `{"roots":{},"roots":{}}`）→ Validate 拒绝；理由：JSON 解析器对重复键行为不一致（Go `encoding/json` 取最后一个，Python `json` 取最后一个，JS 取第一个），planner 须拒绝以避免语义歧义 |
| T91 | Streamable HTTP DELETE /mcp 终止会话 | 集成 | 客户端发 `DELETE /mcp HTTP/1.1`（携带 `Mcp-Session-Id` 头）；服务端响应 `HTTP/1.1 204 No Content\r\n\r\n`；会话清理验证：后续使用同一 `Mcp-Session-Id` 的 POST 请求服务端返回 `HTTP/1.1 404 Not Found`（或新 sessionId）；字节级断言：DELETE 请求以 `DELETE /mcp HTTP/1.1\r\n` 开头、响应状态行以 `HTTP/1.1 204 No Content\r\n` 开头；planner 在 `Shutdown=true` 或用户显式配置时生成此场景 |

**总计：90 + 1 = 91 条测试用例**。负向用例占比：原 17 条 + 新增 T83/T84/T86/T90 = 21 条，占比 21/91 ≈ 23.1%（接近 25% 阈值，v1.2 计划继续补充）。

注：T81-T85 覆盖 §2.6 JSON-RPC Batch 编码与校验规则（T81/T82/T83/T84/T85），对应 N-3 重审问题。T86-T90 覆盖 §5.4 能力双向门控规则（T86/T87/T88/T89/T90），对应 N-6 重审问题。T85 验证 batch + SSE 长连接的组合（一次性 POST + 一次性 SSE 关闭，非长连接）。T91 覆盖 §2.5 DELETE /mcp 会话终止（MCP spec 2025-03-26 §session management）。

### 8.17 v1.1.3 新增测试用例（三轮审计返工）

以下用例为 v1.1.3 修订新增，覆盖三轮审计 §3R-C1~3R-L4 共 17 项问题。

| # | 名称 | 类型 | 验证点 |
|---|---|---|---|
| T92 | resources/read error.code=-32002 Resource not found | 正向 | resources/read 请求的 uri 不存在时，服务端返回 error.code=-32002（spec 2024-11-05/2025-06-18 `server/resources` §Error Handling），message="Resource not found"，data.uri=<请求的 uri>；字节级断言 error.code 严格为 -32002（v1.1.2 错误使用 -32602 已修正） |
| T93 | sampling 拒绝响应 error.code=-1 | 正向 | sampling/createMessage 用户拒绝时，服务端返回 error.code=-1 "User rejected sampling request"（spec 2024-11-05/2025-03-26/2025-06-18 `client/sampling` §Error Handling 示例；v1.1.2 错误发明的 -32004 已删除） |
| T94 | MCPContent.Type=resource_link（spec 2025-06-18 新增） | 正向 | tools/call 响应 content 含 `{"type":"resource_link","uri":"file:///x","name":"my-resource"}`（spec 2025-06-18 新增类型，v1.1.3 已加入枚举；区别于 `type:"resource"` 嵌入资源） |
| T95 | MCPContent.Type=resource 嵌入资源（spec 标准） | 正向 | tools/call 响应 content 含 `{"type":"resource","resource":{"uri":"file:///x","mimeType":"text/plain","text":"..."}}`（spec 2024-11-05/2025-06-18 用 `type:"resource"` 表示嵌入资源；v1.1.2 错误使用 `embedded_resource` 已修正） |
| T96 | HTTP+SSE endpoint 事件 + GET 先于 POST 时序 | 集成 | 字节级断言：(1) 第 4 包为 up `GET /mcp HTTP/1.1\r\n`；(2) 第 5 包 down `HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n`；(3) SSE 响应第一个事件 `event: endpoint\ndata: /mcp?session=...\n\n`；(4) 后续事件 `event: message\ndata: {"jsonrpc":...}`；(5) POST 请求的 URI 为 `endpoint` 事件中 data 字段值（如 `/mcp?session=xxx`），非硬编码 `/mcp`；spec 2024-11-05 §basic/transports 时序（v1.1.2 POST 先于 GET 错误已修正） |
| T97 | HTTP+SSE 批量 POST body 数组 → SSE 流 N 个 event:message | 集成 | spec 2025-03-26 §Batching 要求服务端 MUST 接收批量请求，HTTP+SSE 模式的 POST body 可以是 JSON 数组；字节级断言：POST body 以 `[{"jsonrpc":"2.0",` 开头，GET SSE 流含 N 个 `event: message\ndata: {...}\n\n` 事件，按请求顺序对应；POST 响应仍为 202 Accepted |
| T98 | 批量整体 JSON 解析失败 → 顶层 -32700 | 负向 | 批量数组本身不是合法 JSON（如 body 为 `[{...}, invalid json, {...}]` 整体无法 JSON.parse）；服务端响应为**单个** -32700 Parse error 顶层错误，`id=null`（**非逐项响应**）；批量整体拒绝（JSON-RPC 2.0 spec §6："If the batch rpc call itself fails to be recognized as a valid JSON"） |
| T99 | ServerCapabilities 重复键 → Validate 拒绝 | 负向 | 历史设计条目；当前 `mcp.json` 未提供原始重复键字节入口，归 `G-MCP-4`，不得计为已覆盖 |
| T100 | tools/list 分页（cursor + nextCursor） | 正向 | tools/list 请求带 `params:{"cursor":"<上一页 nextCursor>"}`；响应 `result.nextCursor` 非空表示有更多页；字节级断言：请求 `params.cursor` 非空，响应 `nextCursor` 非空（spec 2024-11-05/2025-06-18 `server/utilities/pagination` 明确 `tools/list` 支持分页） |
| T101 | roots/list 请求省略 params（与 spec 示例一致） | 正向 | roots/list 请求 `{"jsonrpc":"2.0","id":12,"method":"roots/list"}`（**无 params 字段**）；与 spec 2024-11-05 `client/roots` 示例一致；字节级断言：请求 payload 不含 `"params"` 字段 |
| T102 | ping 三种 params 变体 | 边界 | (a) `{"method":"ping"}` 无 params（spec 标准，v1.1.3 默认）；(b) `{"method":"ping","params":{}}` 空对象（宽松 spec 接受）；(c) `{"method":"ping","params":{"x":1}}` 非空对象 → 严格 spec 服务端返回 -32602 Invalid params（spec 2024-11-05 §basic/utilities/ping："A ping request is a standard JSON-RPC request with no parameters"） |
| T103 | sampling 请求含 temperature/stopSequences 字段 | 正向 | sampling/createMessage 请求 `params.temperature=0.7` + `params.stopSequences=["\n\n"]`；spec 2024-11-05/2025-03-26/2025-06-18 `client/sampling` `CreateMessageRequest` schema 中定义这两个字段（但 spec 示例未展示）；planner 作为可选字段生成 |
| T104 | tools/call 工具名不存在 message 含 "Unknown tool:" | 正向 | tools/call 响应 `error.code=-32602`，`error.message="Unknown tool: invalid_tool_name"`（spec 2024-11-05 `server/tools` §Error Handling 示例）；字节级断言：message 前缀为 "Unknown tool:" 且含具体工具名 |

**总计：历史设计清单 104 条；当前机器契约 103 条**（v1.0 60 + v1.1 20 + v1.1.1 10 + v1.1.2 1 + v1.1.3 13）。当前 JSON 的负向用例为 14/103；设计清单中未落入 JSON 的条目不计为已覆盖，继续登记在缺口表。

注：T92/T93 对应 3R-H1/H2（错误码 -32002/-1 spec 合规）。T94/T95 对应 3R-H3（content type `resource`/`resource_link`，删除幻觉 `embedded_resource`）。T96 对应 3R-C2（HTTP+SSE 时序 + endpoint 事件）。T97 对应 3R-H4（HTTP+SSE 批量支持）。T98 对应 3R-M3（批量 rule 5 边界）。T99 是历史设计条目，当前 JSON 未形成原始重复键输入，归 `MCP-GAP-4`。T100 对应 3R-M1（tools/list 分页）。T101 对应 3R-M4（roots/list params 省略）。T102 对应 3R-L1（ping params 变体）。T103 对应 3R-L2（sampling temperature/stopSequences）。T104 对应 3R-M5（工具名错误 message 格式）。3R-L3/3R-L4 已通过文档修复（ProtocolVersion 注释、boundary #20）覆盖，无需新增测试用例。

---

## 9. 交叉对抗审计检查清单

实现完成后，必须按以下清单逐项审计。每项需"尝试反驳"（adversarial verification）：默认假定实现有 bug，寻找反例。

### 9.1 字段映射审计

| # | 检查项 | 反驳方式 |
|---|---|---|
| A01 | 扩展表 31 字段是否每个都有至少 1 个测试用例覆盖？ | 列出 31 字段 × 测试用例编号矩阵，空格 = 漏测 |
| A02 | `state` 字段 6 个值（submitted/working/input_required/completed/failed/canceled）是否每个都有测试？ | 每个 state 值至少 1 条用例 |
| A03 | `level` 字段 8 个值（debug~emergency）是否每个都有测试？ | logging/setLevel 8 个值循环测试 |
| A04 | `schemes` 字段 3 个值（Bearer/Basic/OAuth2）是否每个都有测试？ | 3 条认证用例 |
| A05 | `role` 字段 2 个值（user/assistant）是否每个都有测试？ | prompts/get 多消息用例覆盖 |
| A06 | `parts` 字段是否在 prompts/get 与 sampling 都测试？ | 两个方法各 1 条 |
| A07 | `content.type` 5 个值（text/image/audio/resource/resource_link）是否每个都有测试？ | 5 条 content 类型用例（v1.1.3 删除幻觉 `embedded_resource`，新增 spec 2025-06-18 `resource_link`） |
| A08 | `capabilities` 是否在 initialize 请求与响应双向测试？ | T07 + T08 |

### 9.2 状态机审计

| # | 检查项 | 反驳方式 |
|---|---|---|
| A09 | 状态机 5 个状态（UNINITIALIZED/INITIALIZING/INITIALIZED/OPERATING/SHUTDOWN）是否每个都有测试？ | 5 条状态转换用例 |
| A10 | 跳过 initialize 的非法路径是否被 Validate 拒绝？ | T12 + T15 |
| A11 | notifications/initialized 出现在 initialize 之前是否被拒绝？ | 边界用例 |
| A12 | id 配对：response.id 是否总是等于 request.id？ | 所有请求-响应用例都断言 |
| A13 | notification 是否始终无 id 字段？ | 所有通知用例都断言 |
| A14 | notifications/cancelled 的 params.requestId 是否引用存在的请求 id？ | T29 断言 |

### 9.3 传输模式审计

| # | 检查项 | 反驳方式 |
|---|---|---|
| A15 | stdio / http_sse / streamable 三种模式是否都有完整会话集成测试？ | T54-T56 + T57-T59 |
| A16 | HTTP 模式 Mcp-Session-Id 头是否在 initialize 响应中首次出现，后续请求都携带？ | T58 断言 |
| A17 | stdio 模式是否无 HTTP 头？ | T54 断言 |
| A18 | SSE 事件格式是否为 `event: message\ndata: ...\n\n`？ | T04 + T55 断言 |
| A19 | MSS 分段是否正确（大 JSON 包切分）？ | T60 断言 |

### 9.4 并发与隔离审计

| # | 检查项 | 反驳方式 |
|---|---|---|
| A20 | 多会话 sessionId 是否各不相同？ | T43 断言 |
| A21 | 多会话 id 序列是否各独立（不跨流共享）？ | T44 断言 |
| A22 | 多会话 TCP 4-tuple 是否各不相同（至少 src_port 不同）？ | T43 断言 |
| A23 | 多会话中一条流失败是否不影响其他流？ | T45 断言 |
| A24 | GroupID 路由是否保持同流包连续？ | 集成测试断言 |

### 9.5 错误处理审计

| # | 检查项 | 反驳方式 |
|---|---|---|
| A25 | JSON-RPC 6 个标准错误码（-32700/-32600/-32601/-32602/-32603/-32002）是否每个都有测试？ | T50-T53 + T17 + T22 + T92 |
| A26 | error.code 与 error.message 是否同时出现？ | 所有错误用例断言 |
| A27 | error.data 是否可选（有时省略）？ | T50 无 data，T51-T52 有 data |
| A28 | isError:true（工具层错误）与 JSON-RPC error（协议层错误）是否区分？ | T15 vs T17 断言 |
| A29 | parse error 的 id 是否为 null？ | T50 断言 |

### 9.6 默认值审计

| # | 检查项 | 反驳方式 |
|---|---|---|
| A30 | 所有 §4.3 默认值规则是否每条都有测试触发？ | 默认值矩阵 |
| A31 | user-provided 值是否覆盖默认值？ | 自定义 ClientInfo 用例 |
| A32 | 空字段是否走默认值而非空字符串/零值？ | T07 默认 initialize 用例 |

### 9.7 测试质量审计（对抗性）

| # | 检查项 | 反驳方式 |
|---|---|---|
| A33 | 测试是否仅断言"不 panic"而不断言实际字节？ | 抽查 5 条用例，确认有字节级断言（v1.1 T57-T60/T77/T78 已补字节级断言） |
| A34 | 测试是否仅走 happy path？ | 负向用例占比 ≥ 25%（80 条中 ≥ 20 条负向；v1.1 已补 5 条负向，达 17 条，占比 21.3%，仍需后续补充） |
| A35 | 测试是否覆盖了 §7.18 全部 20 个边界场景？ | 边界矩阵 |
| A36 | 集成测试是否真的端到端（Plan → PacketConfig → 字节）？ | T57-T60 + T77/T78 断言字节输出 |
| A37 | 多会话测试是否真的并发（不止 1 条流）？ | T59 用 100 条流 + T75/T76 聚合断言 |
| A38 | 测试是否用 `-race` 跑过？ | CI 配置确认；T43/T75 显式标 `-race` |

---

## 10. 集成点

### 10.1 代码结构

```
trafficgen/internal/protocol/mcp/
├── mcp.go              # Planner + Validate + Plan
├── mcp_test.go         # 单元测试（T01-T53）
├── mcp_integration_test.go  # 集成测试（T54-T60）
└── mcp_helpers.go      # JSON-RPC 序列化、HTTP 头构造、SSE 事件构造
```

### 10.2 注册

`internal/protocol/protocol.go` 增加：

```go
import _ "github.com/trafficgen/trafficgen/internal/protocol/mcp"
```

`init()` 注册 `"mcp"` → `mcp.NewPlanner()`。

### 10.3 FlowSpec 字段

`internal/core/types.go` 的 `FlowSpec` 增加：

```go
MCP *MCPConfig `json:"mcp,omitempty"`
```

放在 `LDAP` 等字段之后（与其他 L7 协议并列）。

### 10.4 mapToFlowSpec

`internal/core/convert.go`（或 strategy_convert.go）增加 `mcp` 协议的 strategy → FlowSpec 转换，处理：
- `transport`、`session_id`、`requests`、`responses` 等字段映射
- `auth` 子对象展开
- 默认值填充（与 §4.3 一致）

### 10.5 依赖

- 仅依赖 `internal/core`（PacketConfig、FlowSpec、TCPConfig）
- 不依赖 `modelcontextprotocol/go-sdk/mcp`（避免与 `internal/mcp/` 冲突）
- 不依赖 `internal/mcp/`（明确隔离）

### 10.6 测试依赖

- `internal/protocol/testutil`（共用测试工具：tcp dial、pcap 写入）
- `github.com/google/go-cmp/cmp/cmpopts`（JSON 比较忽略键序）

### 10.7 端口注册

默认端口 `8081`（HTTP+SSE / Streamable HTTP 模式），在 `cmd/server/main.go` 的端口分配器中注册（若启用端口调度）。stdio 模式默认端口为 22（SSH 隧道场景）；用户可显式指定 `dst_port=8081` 模拟本地 stdio 转发到 MCP 服务器。

### 10.8 与 ReplayPlanner 的关系

MCP 协议不涉及 pcap 回放（replay 走 ReplayPlanner，独立路径）。但若用户上传 MCP pcap 并选择 replay 模式，ReplayPlanner 会原样回放字节，不经过 MCP planner。两者互不干扰。

---

## 11. 与本项目 internal/mcp/ 的关系说明

### 11.1 角色对比

| 维度 | `internal/mcp/`（已实现） | `internal/protocol/mcp/`（本设计） |
|---|---|---|
| 包路径 | `trafficgen/internal/mcp/` | `trafficgen/internal/protocol/mcp/` |
| 角色 | MCP 服务器（本系统作为服务端供 LLM 调用） | MCP 协议流量生成器（把 MCP 当作被生成的网络流量） |
| 依赖 | `modelcontextprotocol/go-sdk/mcp` | 仅 `internal/core` |
| 启动方式 | `cmd/server/main.go` 中 `mcpServer.Run(ctx, transport)` | 通过 Task protocol="mcp" 触发 Planner.Plan |
| 端口 | 监听 stdio / `:8081/mcp` | 生成流量到指定 dst_port（默认 8081） |
| 数据流向 | 入方向（接收 LLM 请求） | 出方向（生成 MCP 流量到外部 MCP 服务器或本机回环） |
| 是否真实执行 | 是（真实 SDK 会话） | 否（仅生成报文字节，不建立真实会话） |
| 与本设计关系 | 无直接代码依赖，但提供协议参考 | 借鉴 `internal/mcp/` 的字段命名与默认值 |

### 11.2 共存场景

同一 trafficgen 进程可同时：
1. 作为 MCP 服务器在 `:8081/mcp` 监听（`internal/mcp/`）
2. 生成 MCP 流量发往外部 MCP 服务器（`internal/protocol/mcp/`）

两者端口可以相同（监听 vs 发送不冲突），但通常发送到不同端口（避免回环到自身）。若用户想测试"自身 MCP 服务器"，可生成流量到 `127.0.0.1:8081`，此时 `internal/mcp/` 会接收并响应——但 planner 不读取响应（它只生成报文，不建立真实会话），所以这是巧合而非设计。

### 11.3 命名隔离

- `internal/mcp/` 包名 `mcp`（已存在）
- `internal/protocol/mcp/` 包名 `mcp`（新增，不冲突，因路径不同）
- 导入时用别名区分：`mcpserver "github.com/.../internal/mcp"` vs `mcpproto "github.com/.../internal/protocol/mcp"`
- FlowSpec 字段 `MCP *MCPConfig` 与现有 `internal/mcp.Server` 无命名冲突（不同包）

### 11.4 设计借鉴

`internal/protocol/mcp/` 的设计借鉴 `internal/mcp/` 的以下方面：
- 默认 `serverInfo.Name="trafficgen-server"`（与 `internal/mcp/` 的 `flowB` 不同，因流量生成场景下服务端是任意外部 MCP 服务器）
- 默认 `protocolVersion="2024-11-05"`（与 `internal/mcp/` 一致）
- HTTP+SSE 传输的 `Mcp-Session-Id` 头处理（与 `internal/mcp/http_server.go` 一致）
- CORS 头不在此协议层处理（`internal/mcp/` 处理 CORS 是因为它真实监听 HTTP；`internal/protocol/mcp/` 仅生成 HTTP 报文字节，不处理 CORS）

### 11.5 不共享代码

明确不共享以下代码（避免耦合）：
- JSON-RPC 序列化：`internal/protocol/mcp/` 自行实现简单序列化（仅生成场景需要），不复用 `internal/mcp/` 的 SDK 序列化
- 会话管理：`internal/protocol/mcp/` 不维护真实会话状态（仅按状态机生成报文）
- 工具注册：`internal/mcp/` 的 `registerTools()` 是真实工具；`internal/protocol/mcp/` 仅在 `tools/list` 响应中生成工具元数据（默认 ping/echo/search 三个虚拟工具）
- 认证：`internal/mcp/` 的 `X-MCP-Key` 头是真实认证；`internal/protocol/mcp/` 的 `Authorization` 头是流量生成场景下的标准 HTTP 认证头（Bearer/Basic/OAuth2）

### 11.6 测试隔离

`internal/protocol/mcp/` 的测试不启动 `internal/mcp/` 服务器。所有测试在 `Plan` 输出层断言 PacketConfig 字节，不依赖真实 MCP 服务器响应。这与项目其他协议（socks5/ldap/radius 等）的测试模式一致。

---

## 附录 A：默认 initialize 请求/响应完整字节

### A.1 stdio 模式

请求行：`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{"roots":{"listChanged":true},"sampling":{}},"clientInfo":{"name":"trafficgen-client","version":"1.0.0"}}}\n`

响应行：`{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05","capabilities":{"tools":{"listChanged":true},"resources":{"subscribe":true,"listChanged":true},"prompts":{"listChanged":true},"logging":{},"completion":{}},"serverInfo":{"name":"trafficgen-server","version":"1.0.0"}}}\n`

### A.2 HTTP+SSE 模式

**注**：旧版 HTTP+SSE 的 spec 强制时序为：GET `/mcp` 建立 SSE 流（第一步）→ 服务端发送 `endpoint` 事件（告知 POST URI）→ 客户端 POST 到该 URI（第二步）。与 v1.1.2 错误时序（POST 先于 GET）不同。

GET SSE 流请求（第一步，客户端先建立 SSE 流）：

```
GET /mcp HTTP/1.1\r
Host: mcp.example.com:8081\r
Accept: text/event-stream\r
\r
```

GET SSE 流响应（服务端首先发送 `endpoint` 事件告知 POST URI，然后推送 initialize 响应）：

```
HTTP/1.1 200 OK\r
Content-Type: text/event-stream\r
Cache-Control: no-cache\r
Connection: keep-alive\r
\r
event: endpoint\ndata: /mcp?session=a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6\n\n
event: message\ndata: {"jsonrpc":"2.0","id":1,"result":{...同 A.1...}}\n\n
```

POST 请求（第二步，客户端 POST initialize 到 `endpoint` 事件指定的 URI）：

```
POST /mcp?session=a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6 HTTP/1.1\r
Host: mcp.example.com:8081\r
Content-Type: application/json\r
Accept: application/json, text/event-stream\r
Mcp-Session-Id: a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6\r
Content-Length: 215\r
\r
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{...同 A.1...}}
```

POST 响应（202 Accepted，无 body；服务端通过 GET SSE 流推送 JSON-RPC 响应）：

```
HTTP/1.1 202 Accepted\r
Content-Length: 0\r
\r
```

注：旧版 HTTP+SSE 模式下 POST 不直接返回 JSON body（那是 Streamable HTTP 的行为，见 §A.3）。spec 2024-11-05 §basic/transports 要求：客户端先 GET 建立 SSE 流，服务端 MUST 发送 `endpoint` 事件（含 POST 端点 URI），客户端后续 POST 到该 URI；POST 响应为 202 Accepted（确认收到），响应内容通过 GET SSE 流推送。v1.1.2 的 POST 先于 GET 时序（以及遗漏 `endpoint` 事件）是 spec 违规，v1.1.3 已修正。

### A.3 Streamable HTTP 模式

请求（POST `/mcp`，**新版 Streamable HTTP 传输**——POST 可直接返回 JSON body 或 SSE 流）：

```
POST /mcp HTTP/1.1\r
Host: mcp.example.com:8081\r
Content-Type: application/json\r
Accept: application/json, text/event-stream\r
Mcp-Session-Id: a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6\r
Content-Length: 215\r
\r
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{...同 A.1...}}
```

响应（200 OK + JSON body，简单请求/响应场景）：

```
HTTP/1.1 200 OK\r
Content-Type: application/json\r
Mcp-Session-Id: a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6\r
Content-Length: 280\r
\r
{"jsonrpc":"2.0","id":1,"result":{...同 A.1...}}
```

或响应（200 OK + SSE 流，流式结果或中途推送通知场景）：

```
HTTP/1.1 200 OK\r
Content-Type: text/event-stream\r
Mcp-Session-Id: a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6\r
\r
event: message\ndata: {"jsonrpc":"2.0","id":1,"result":{...}}\n\n
```

注：Streamable HTTP 模式（spec 2025-03-26）下 POST 可直接返回 JSON body——这是与旧版 HTTP+SSE（§A.2）的关键区别。

---

## 附录 B：JSON-RPC 错误码与协议版本

错误码（planner 生成的范围）：

| 码 | 名称 | 触发 | spec 依据 |
|---|---|---|---|
| -32700 | Parse error | JSON 解析失败 | JSON-RPC 2.0 §5.1 |
| -32600 | Invalid Request | 非 JSON-RPC 2.0 对象 | JSON-RPC 2.0 §5.1 |
| -32601 | Method not found | 方法不存在 | JSON-RPC 2.0 §5.1 |
| -32602 | Invalid params | 参数错 | JSON-RPC 2.0 §5.1 |
| -32603 | Internal error | 服务端内部异常 | JSON-RPC 2.0 §5.1 |
| -32002 | **Resource not found** | resources/read 请求的 uri 不存在 | **MCP spec 2024-11-05/2025-06-18 `server/resources` §Error Handling**：`Resource not found: -32002`。v1.1.2 错误标为"Server not initialized"已修正——spec 未定义单独的"Server not initialized"错误码。 |
| -1 | User rejected sampling request | sampling/createMessage 用户拒绝 | **MCP spec 2024-11-05/2025-03-26/2025-06-18 `client/sampling` §Error Handling 示例**使用 `code: -1`。v1.1.2 错误发明的 -32004 "Rate limited" 已删除——spec 无专门的 Rate limited 错误码。 |
| -32800 | Request cancelled（**非 spec 标准，移至非标准扩展**） | 客户端取消（仅部分 SDK 实现） | JSON-RPC 2.0 §5.1 保留 -32000~-32099；-32800 超出此范围。**planner 默认不生成**；仅在用户显式配置时生成。 |

### 非标准扩展错误码

以下错误码不在 JSON-RPC 2.0 或 MCP spec 标准中，仅作为 MCP 生态中部分 SDK 实现的约定保留。planner 默认不生成；仅在用户显式配置时生成。

| 码 | 名称 | 触发 | 说明 |
|---|---|---|---|
| -32800 | Request cancelled | 客户端取消（仅部分 SDK 实现） | JSON-RPC 2.0 §5.1 保留 -32000~-32099；-32800 超出此范围，非 spec 标准。planner 默认不生成；仅在用户显式配置时生成。 |

协议版本：

| 版本 | 主要变化 | v1.1.3 支持 |
|---|---|---|
| 2024-11-05 | 初始版本，stdio + HTTP+SSE（planner 默认） | 完整支持 |
| 2025-03-26 | 引入 Streamable HTTP，HTTP+SSE 仍兼容；新增 `resources/unsubscribe`（中间版本扩展）；明确 batch MUST 支持 | 支持（resources/unsubscribe 仅此版本生成） |
| 2025-06-18 | 新增 Elicitation（服务端→客户端请求额外信息）/ `outputSchema`+`structuredContent`（工具结构化输出）/ `resource_link` content type（资源链接）/ `title` 字段（工具/资源显示名）/ `annotations` 字段（audience/priority/lastModified） | **部分支持**：`resource_link` content type 已加入枚举（见 §4.2）；Elicitation / `structuredContent` / `title` / `annotations` 留待 v1.2 实现，本版本 Validate 接受 `protocol_version="2025-06-18"` 但不强制生成这些新字段 |

---

## 附录 C：Wireshark 兼容性与参考资料

Wireshark（≥4.4）内置 MCP dissector。planner 生成的报文须满足：

1. stdio 模式：每行 JSON 以 `{` 开头、`}` 结尾，无中间 `\n`。
2. HTTP 模式：完整请求行/状态行 + 头 + 空行 + body。
3. SSE 流：`event: message\ndata: ...\n\n`。
4. 单个 JSON-RPC 包默认不跨 MSS（≤1460 字节）。

测试用 `tshark -r <pcap> -Y mcp -T json` 验证。

参考资料：
- MCP 规范：https://spec.modelcontextprotocol.io/
- JSON-RPC 2.0：https://www.jsonrpc.org/specification
- MCP Go SDK：https://github.com/modelcontextprotocol/go-sdk
- 本项目 MCP 服务器：`internal/mcp/`（参考但不依赖）
- socks5 planner 模板：`internal/protocol/socks5/socks5.go`
- 测试策略：`CLAUDE.md` §"Testing Policy"
- 未实现协议清单：`docs/protocol-designs/00-unimplemented-list.md`

---

**文档结束**。历史设计清单共 104 条测试用例（v1.0 原始 60 条 + v1.1 审计修订新增 20 条 + v1.1.1 重审修复新增 10 条 + v1.1.2 二轮返工新增 1 条 + v1.1.3 三轮审计返工新增 13 条）；当前机器契约以 `mcp.json` 为唯一权威，共 103 条（89 条正例、14 条负例）。覆盖正向/负向/边界/异常/并发/状态机/字段映射/传输模式/集成/批量/能力协商/分页/内容类型 13 个维度；未落入机器契约的历史条目只登记为缺口。

---

## 修订记录 v1.1 (2026-08-03)

本次修订基于 `docs/protocol-designs/audit/16-17-mcp-a2a-audit.md` §2（MCP 审计）的 18 个问题（2 CRITICAL + 5 HIGH + 7 MEDIUM + 4 LOW）逐项修复。审计报告与修订同步进行，修订后文档通过对抗复审。

### CRITICAL 修复（2 项）

| 编号 | 问题 | 修复内容 |
|------|------|---------|
| C-1 | §3.10 `capabilities` 标"必填"与 spec 不一致（spec optional） | §3.10 改为"否（默认空对象 `{}`）"，注释引用 spec 2024-11-05 §3.1.1 `capabilities?` optional；§4.4 Validate 第 6 条明确 `ClientCapabilities`/`ServerCapabilities` 为 nil 时默认 `{}` 不报错；§7.1 增加"客户端无 sampling 能力"变体；新增 T65 "capabilities 省略（最小客户端）"边界用例 |
| C-2 | §7.2 `notifications/initialized` 允许 params 与 spec "no parameters" 不一致 | §7.2 删除"通知带 params（非标准但允许）"变体，改为"严格 spec 客户端应不发送 `params` 字段；planner 默认不携带 `params` 字段"；新增 T64 "notifications/initialized 无 params 字段"正向用例 |

### HIGH 修复（5 项）

| 编号 | 问题 | 修复内容 |
|------|------|---------|
| H-1 | §2.4 vs §6.3 对 HTTP+SSE 旧版 POST 响应语义矛盾 | §6.3 重写为 spec 合规版本：POST 响应 `202 Accepted`（无 body），服务端响应通过 GET SSE 流 `event:message` 推送；§2.4 同步明确"POST 响应 202 Accepted（无 body，**不直接返回 JSON**；响应通过 GET SSE 流推送）"；附录 A.2 重写为 202 + GET SSE 流示例；新增 T78 "HTTP+SSE POST 响应 202 + GET SSE 流"集成用例；T58 增加字节级断言"POST 响应状态行以 `HTTP/1.1 202 Accepted\r\n` 开头" |
| H-2 | §6.2 teardown 描述与 socks5 参考实现不一致（4 包 vs 3 包） | §6.2 表格删除第 14 行（down ACK），与 socks5 一致：3 包 teardown；注释改为"planner 按 socks5 模板发 3 包：FIN-ACK(up) → FIN-ACK(down) → ACK(up)，合并中间 ACK"；T57 明确断言"teardown 3 包：FIN-ACK(up,0x11) → FIN-ACK(down,0x11) → ACK(up,0x10)"；新增 T77 "stdio teardown 3 包字节序列"集成用例 |
| H-3 | `parentId`/`state`/`status`/`contextId` 字段零覆盖（`status` 是幻觉字段） | §4.1 删除 `Status string` 字段（spec 不存在）；§3.10 删除 `status` 行；§4.4 Validate 删除 `Status` 校验规则；`state` 字段位置修正为"仅出现在 `_meta`，不在 progress 通知中"（见 M-2）；新增 T80 "state 字段不在 progress 通知"正向用例 |
| H-4 | T57-T60 集成测试未断言字节序列（违反 CLAUDE.md 规则 5） | T57-T60 每个增加字节级断言：T57 断言"第 4 包 payload 以 `{"jsonrpc":"2.0","id":1,"method":"initialize"` 开头、以 `}\n` 结尾；teardown 最后一包为 up ACK，flags=0x10"；T58 断言"POST 响应状态行以 `HTTP/1.1 202 Accepted\r\n` 开头，SSE 流第一个事件以 `event: message\ndata: {"jsonrpc":"2.0","id":1,"result":` 开头"；T59 断言"每条流 sessionId 唯一（32 字符十六进制），总包数 == 100 × 单流包数"；T60 改为"用 tshark `-r <pcap> -Y mcp -T json` 验证 MCP dissector 识别出 initialize 请求"（真实可验证） |
| H-5 | 多会话测试未验证"实际聚合速率"（违反 CLAUDE.md 规则 6） | T43-T45 增加"聚合断言"列：T43 断言"总包数 == 3 × 单流包数；用 `-race` 跑"；T44 断言"3 条流的 packet_index 全局唯一无重复"；T45 断言"流1+流3 总包数 == 2 × 单流正常包数"；新增 T75 "多会话 100 并发聚合速率"（100 并发流，总包数 == 100 × 单流包数，packet_index 全局唯一，`-race`）；新增 T76 "GroupID 路由同流连续"（2 个 GroupID，同 GroupID 包连续） |

### MEDIUM 修复（7 项）

| 编号 | 问题 | 修复内容 |
|------|------|---------|
| M-1 | §4.4 Validate 规则第 13 条 `MCPError.Code` 范围错误（允许正数） | §4.4 第 13 条改为"`MCPError.Code` 必须在 [-32700, -32000] 范围内（JSON-RPC 2.0 标准 + 服务端错误段；错误码不可为正数）"；新增 T79 "MCPError.Code 拒绝正数"负向用例 |
| M-2 | §5.3 长任务状态机 `state` 字段位置与 spec 不一致（放在 progress 通知） | §5.3 状态机图删除 `notifications/progress` 中的 `state` 字段，注释明确"MCP spec `ProgressNotification` params 字段为 `progressToken`/`progress`/`total`/`message`，**无 `state` 字段**"；§7.15 字节示例删除 progress 通知中的 `state`，`state` 仅通过 tools/call 请求/响应的 `_meta.state` 传递；§3.10 `state` 行改为"仅出现在 `_meta`，不在 `notifications/progress` 中" |
| M-3 | §7.4 工具名不存在返回 -32601 与 spec 不一致 | §7.4 改为"工具名不存在：JSON-RPC error code -32602 'Invalid params'，data 字段含 `{"param":"name","reason":"unknown tool"}`（spec 合规：`tools/call` 方法存在，仅参数 name 错误）"；T17 同步修改为 -32602 |
| M-4 | §7.13 sampling `includeContext` 字段值未校验 | §4.4 增加 Validate 第 14 条：`includeContext` ∈ {`""`, `"none"`, `"thisServer"`, `"allServers"`}（其他值报错）；新增 T74 "sampling includeContext 校验"负向用例（"invalid" 被拒绝）+ 3 个合法值正向用例 |
| M-5 | §6.5 多会话"src_port 递增"未说明冲突处理 | §6.5 明确"src_port 由 strategy 层 `inc`/`rand` 决定，planner 不强制；默认建议 `rand` 范围 [49152, 65535]（IANA 动态端口段，与真实 LLM 客户端行为一致）；src_port 冲突由外层 strategy 重试" |
| M-6 | §8 测试用例计数与实际不符（开头"48 条" vs 文末"60 条"） | §8 开头"48 条"改为"60 条"（v1.1 后为 80 条） |
| M-7 | 负向用例占比不足 25%（违反 CLAUDE.md 规则 2） | 新增 T61/T62/T63/T74/T79 五条负向用例：T61 "initialize 缺 protocolVersion"、T62 "tools/call 缺 name 参数"、T63 "resources/subscribe 服务端 capabilities 不支持"、T74 "sampling includeContext 校验"、T79 "MCPError.Code 拒绝正数"；负向用例从 12 条增至 17 条，占比 17/80 ≈ 21.3%（仍偏低，v1.2 计划继续补充至 25%） |

### LOW 修复（4 项）

| 编号 | 问题 | 修复内容 |
|------|------|---------|
| L-1 | §1.4 stdio 默认端口 8081 与 HTTP 模式相同，易混淆 | §1.4 改为"stdio 模式默认走 TCP 22（SSH 隧道）+ 应用层行分隔 JSON；如用户指定 `dst_port=8081`，则走 TCP 8081 + 行分隔 JSON（模拟本地 stdio 转发）"；§10.7 同步更新 |
| L-2 | §4.1 `IDCounter` 默认值规则与 §5.5 id 配对规则矛盾 | §4.1 注释改为"first request id; 0 is treated as 1 in Plan (Validate accepts 0 but Plan defaults to 1)" |
| L-3 | §3.10 "剩余 6 字段"声明与实际不符（实际 7 个） | §3.10 改为"剩余 7 字段（`protocolVersion`、`method`、`params`、`result`、`error`、`clientInfo`、`serverInfo`）" |
| L-4 | 附录 B 错误码 -32800 "Request cancelled" 非 MCP spec 标准 | 附录 B 标注"-32800 非 spec 标准，部分 SDK 实现；planner 可选生成"；§7.10 同步说明"非 spec 标准，部分 SDK 实现"；§7.19 异常场景表第 7 行标注"非 spec 标准" |

### 字段覆盖率改善（§2.2 审计）

§3.10 声明覆盖 25 字段，v1.0 实际有效覆盖 60%（6 字段零覆盖 + 1 幻觉字段 + 2 位置错）。v1.1 新增以下用例补足零覆盖字段：

| 字段 | v1.0 状态 | v1.1 新增用例 |
|------|----------|--------------|
| `logger` | 缺测 | T66 "notifications/message logger 字段" |
| `credentials` | 缺测 | T67 "initialize 请求携带 credentials" |
| `parts` | 缺测 | T68 "prompts/get 多部分 parts 字段" |
| `metadata` | 缺测（隐含） | T69 "tools/call 请求 _meta.metadata" |
| `pushNotification` | 缺测 | T70 "tools/call 长任务 pushNotification 配置" |
| `verificationToken` | 缺测 | T70（同上，pushNotification 含 verificationToken） |
| `status` | spec 不存在 | 删除字段（H-3） |
| `state` | 位置错 | 修正位置 + T80 "state 字段不在 progress 通知" |
| `capabilities` | spec 可选 | T65 "capabilities 省略（最小客户端）" |

v1.1 后字段覆盖率提升至 24/24 = 100%（删除幻觉字段 `status` 后）。

### spec 一致性改善（§1.5 维度 1 核查表）

v1.0 有 2 项 spec 一致性错误（C-1 capabilities 必填性、C-2 initialized params）+ 3 项衍生问题（M-2 state 位置、M-3 工具名错误码、H-3 status 幻觉字段）。v1.1 全部修复，spec 一致性核查表 28 项全部 OK。

### 内部一致性改善

v1.0 有 4 处内部矛盾（H-1 §2.4 vs §6.3、H-2 §6.2 表格 vs 注释、M-6 §8 开头 vs 文末、L-3 §3.10 计数）。v1.1 全部修复。

### 测试质量改善（CLAUDE.md 测试策略 8 条）

| 规则 | v1.0 状态 | v1.1 改善 |
|------|----------|----------|
| 规则 1 spec-driven | 6 字段零覆盖 | 全部补足（T66-T70） |
| 规则 2 失败路径 | 负向占比 20% | 增至 21.3%（17/80），v1.2 计划继续补充 |
| 规则 3 一测试一路径 | resources/unsubscribe/templates/list_changed 无用例 | 新增 T71/T72/T73 |
| 规则 4 集成测试 | T57-T60 集成测试存在 | 增加 GroupID 路由测试 T76 |
| 规则 5 断言可观察值 | T57-T60 字节断言不足 | 全部增加字节级断言 + T77/T78 |
| 规则 6 并发正确性 | T43-T45 聚合断言不足 | 全部增加聚合断言 + T75/T76 |
| 规则 7 失败测试先行 | 未提及 | 实现阶段遵循（修订记录中说明） |
| 规则 8 测试质量对抗 | §9.7 A34 设 25% 阈值但不达标 | 已补 5 条负向，A34 更新为 21.3%；A33 更新为"v1.1 T57-T60/T77/T78 已补字节级断言" |

### 新增测试用例汇总（20 条）

| # | 名称 | 类型 | 对应审计问题 |
|---|------|------|-------------|
| T61 | initialize 缺 protocolVersion | 负向 | M-7 |
| T62 | tools/call 缺 name 参数 | 负向 | M-7 |
| T63 | resources/subscribe 服务端 capabilities 不支持 | 负向 | M-7 |
| T64 | notifications/initialized 无 params 字段 | 正向 | C-2 |
| T65 | capabilities 省略（最小客户端） | 边界 | C-1 |
| T66 | notifications/message logger 字段 | 正向 | §2.2 字段覆盖 |
| T67 | initialize 请求携带 credentials | 正向 | §2.2 字段覆盖 |
| T68 | prompts/get 多部分 parts 字段 | 正向 | §2.2 字段覆盖 |
| T69 | tools/call 请求 _meta.metadata | 正向 | §2.2 字段覆盖 |
| T70 | tools/call 长任务 pushNotification 配置 | 正向 | §2.2 字段覆盖 |
| T71 | resources/unsubscribe 取消订阅 | 正向 | §2.3.2 spec-derived |
| T72 | resources/templates/list 资源模板 | 正向 | §2.3.2 spec-derived |
| T73 | notifications/resources/list_changed 通知 | 正向 | §2.3.2 spec-derived |
| T74 | sampling includeContext 校验 | 负向 | M-4 + M-7 |
| T75 | 多会话 100 并发聚合速率 | 并发 | H-5 |
| T76 | GroupID 路由同流连续 | 并发 | H-5 |
| T77 | stdio teardown 3 包字节序列 | 集成 | H-2 + H-4 |
| T78 | HTTP+SSE POST 响应 202 + GET SSE 流 | 集成 | H-1 + H-4 |
| T79 | MCPError.Code 拒绝正数 | 负向 | M-1 + M-7 |
| T80 | state 字段不在 progress 通知 | 正向 | M-2 + H-3 |

### 未修复项（v1.2 计划）

| 项 | 说明 | v1.2 计划 |
|----|------|----------|
| 负向用例占比 23.3% < 25% | v1.1.1 已补 4 条负向（T83/T84/T86/T90），占比 21/90 ≈ 23.3%，仍未达 25% 阈值 | v1.2 计划再补 2 条负向用例（如 `initialize` 缺 clientInfo、`tools/call` arguments 类型错），即可达 ≥ 25% |
| batch + 长任务组合 | T81-T85 覆盖 batch 基础与 +SSE 组合，但未覆盖 batch + long-task（批量含 tools/call + 中途 progress 通知） | v1.2 计划新增 T91 `batch 混合 request + notification`，验证批量请求中混有 notification（无 id）时仅响应部分按序回 |

### 对抗复审结论

v1.1 修订后，文档通过对抗复审：
- 4 个 CRITICAL spec 一致性错误：全部修复（C-1/C-2）。
- 5 个 HIGH 内部矛盾/虚假覆盖声明：全部修复（H-1/H-2/H-3/H-4/H-5）。
- 7 个 MEDIUM 缺失校验规则/测试质量违规：全部修复（M-1/M-2/M-3/M-4/M-5/M-6/M-7）。
- 4 个 LOW 表述不精确/引用错误/计数不符：全部修复（L-1/L-2/L-3/L-4）。
- 字段覆盖率：60% → 100%（删除幻觉字段后）。
- 负向用例占比：20% → 21.3%（v1.2 计划继续补充至 25%）。
- 字节级断言：T57-T60 全部增加 + 新增 T77/T78。
- 并发聚合断言：T43-T45 全部增加 + 新增 T75/T76。

文档已具备进入实现阶段的条件。实现阶段须遵循 CLAUDE.md 测试策略规则 7（失败测试先行）：每个 bug fix 先写失败测试，再修复代码。

---

## 修订记录 v1.1.1 (2026-08-03)

本次重审基于 v1.1 对抗审计后的二次审查，发现 6 项遗留问题（3 HIGH + 3 MEDIUM），逐项修复如下。

### HIGH 修复（3 项）

| 编号 | 问题 | 修复内容 |
|------|------|---------|
| N-1 | §2.1 L84 错误引用 "RFC 5549"（RFC 5549 是 SIP 事件通知，与 JSON-RPC 无关） | L84 改为 "符合 JSON-RPC 2.0 规范 https://www.jsonrpc.org/specification，2026-08-03 检索"，删除 RFC 5549 引用 |
| N-2 | §8.9 T40 要求 progress 通知含 `state=input_required`，与 L671/T80 冲突 | T40 改为 "tools/call 请求 `_meta.state` 序列含 `submitted` → `working` → `input_required` → `working`（继续）；progress 通知本身不含 `state` 字段（与 L671/T80 一致，`state` 仅在 `_meta` 中）" |
| N-3 | §2-§8 未定义 JSON-RPC 批量数组的编码、校验或测试，仅声明旧 HTTP+SSE 不支持批量 | §2.6 新增 "JSON-RPC Batch（批量请求）" 小节：编码规则（stdio 多行 + HTTP 数组）、Streamable HTTP + SSE 批量响应、HTTP+SSE 拆分伪批量、6 条 Validate 校验规则、planner 行为；新增 T81-T85 覆盖批量 3 请求/混合成功失败/空数组/parse error/Streamable HTTP + SSE 组合；§2.4 同步明确 "旧版 HTTP+SSE 模式不支持批量"（spec 2024-11-05 §2.2） |

### MEDIUM 修复（3 项）

| 编号 | 问题 | 修复内容 |
|------|------|---------|
| N-4 | §4.3 L575 capabilities 默认 `{"roots":{"listChanged":true},"sampling":{}}` 与 §4.4 L595 默认 `{}` 语义冲突 | 选方案 A（默认 `{}`）：§4.3 L575 改为 "`{}`（空对象；用户显式填入 `roots:{}` / `sampling:{}` 等才启用对应能力）"；§4.4 L595 改为 "默认 `{}`，不自动注入 `roots` / `sampling` / `tools` / `resources` / `prompts` / `logging` / `completion`；用户须显式填入对应能力键才启用。语义：缺失 = 不支持该能力"；§4.1 Go struct 注释同步更新（468-469 行）；§5.5 规则 4/5 同步更新为"未声明 → planner 生成 -32601" |
| N-5 | §6.1 L714 仍写 "FIN/ACK × 4"，与 §6.2 表格 3 包 teardown + socks5 模板冲突 | L714 改为 "在最后 emit 3 包 teardown：FIN-ACK(up) → FIN-ACK(down) → ACK(up)，合并中间 ACK（与 §6.2 表格 + socks5 模板 + A2A H-7 一致）" |
| N-6 | §5 仅有 capability 声明及少量负向场景，缺统一的双向门控规则与完整测试矩阵 | 新增 §5.4 "能力双向门控规则"（5 条规则：client→server 必须响应、server→client 可选接受、双方未识别 → warning、缺失 = 不支持、重复字段 → Validate 拒绝 + 6 行门控场景矩阵表）；原 §5.4 "id 配对规则" → §5.5；原 §5.5 "不允许的状态跳转" → §5.6（新增规则 6：capabilities 重复键拒绝）；新增 T86-T90 覆盖 client 声明 server 不支持/双方未识别/双向协商成功/空对象/重复字段 |

### 新增测试用例汇总（10 条）

| # | 名称 | 类型 | 对应重审问题 |
|---|------|------|-------------|
| T81 | Streamable HTTP 批量 3 请求 → 批量 3 响应 | 正向 | N-3 |
| T82 | 批量混合成功+失败 | 边界 | N-3 |
| T83 | 批量空数组 → 报错 | 负向 | N-3 |
| T84 | 批量含非法请求 → 全部响应含 parse error | 负向 | N-3 |
| T85 | Streamable HTTP + SSE 批量响应 | 集成 | N-3 |
| T86 | client 声明 roots，server 不支持 → error | 负向 | N-6 |
| T87 | client 声明 experimental.xyz，server 接受 → warning | 边界 | N-6 |
| T88 | 双向协商成功（roots + sampling） | 正向 | N-6 |
| T89 | 能力声明空对象 `{}` | 边界 | N-6 |
| T90 | 能力声明重复字段 → Validate 拒绝 | 负向 | N-6 |

### 文档统计

- 测试用例总数：80 → 90（+10）
- 负向用例占比：21.3% → 23.3%（17 → 21）
- 文档总行数：1973 → ~2150（+§2.6 +§5.4 +§8.16 + v1.1.1 修订记录）

### v1.1.1 重审复结论

v1.1.1 修订后，文档通过重审：
- 3 项 HIGH 问题（N-1 错误引用 / N-2 state 位置冲突 / N-3 批量未定义）：全部修复。
- 3 项 MEDIUM 问题（N-4 默认值冲突 / N-5 teardown 包数冲突 / N-6 能力门控未定义）：全部修复。
- 测试用例达到 90 条（v1.0 60 + v1.1 20 + v1.1.1 10），覆盖维度扩展为 11 个（增加"批量"与"能力协商"）。
- 文档可进入实现阶段。实现阶段须遵循 CLAUDE.md 测试策略规则 7（失败测试先行）。

---

## 修订记录 v1.1.2 (2026-08-03)

本次二轮返工基于 v1.1.1 重审通过后的第三轮审查，发现 15 项遗留问题（4 CRITICAL + 4 HIGH + 4 MEDIUM + 3 LOW），逐项修复如下。

### CRITICAL 修复（4 项）

| 编号 | 问题 | 修复内容 |
|------|------|---------|
| C-1 | §2.6.2 Validate rule 3（L243）"id 重复 → 拒绝"未区分用户显式 id 与自动分配 id | L243 改为"本规则仅对用户显式设置的非零 id 生效；若请求 id=0 表示由 planner 自动分配，自动分配时的唯一性检测推迟到 Plan 阶段（Plan 在展开 IDCounter 后检查所有分配结果是否唯一，不唯一则报错）。用户显式指定 id 的部分必须在 Validate 阶段即拒绝" |
| C-2 | §5.4 Rule 5（L756）capabilities 重复键仅说"拒绝"但未说明实现机制 | L756-759 改为明确实现机制：Validate 前使用自定义 JSON tokenizer（`mcp_helpers.go` 的 `checkDuplicateKeys()`）对原始字节流做顶层键扫描，标准 JSON 解析前完成检查；不采用"接受 last-wins"方案，理由是 spec 明确禁止重复键 |
| C-3 | §4.3 L626 `ServerCapabilities` 默认 `{"tools":{...},"resources":{...},...}`（5 键全填）与 §5.4 Rule 4"缺失=不支持"语义不一致 | L626 改为"`{}`（空对象；用户显式填入 `tools:{}` / `resources:{}` 等才启用对应能力）"，与 Rule 4 一致；附录 A 字节序列同步更新（initialize 响应 capabilities 改为空对象 `{}`） |
| C-4 | §4.4 rule 6（L645）未显式区分 capabilities 字段缺省与显式 `null` 的语义 | L645 改为"`ClientCapabilities`/`ServerCapabilities` 缺省与显式 null 语义一致：两者均默认 `{}`（不报错；spec 允许 capabilities 字段省略或为 null），不自动注入任何键"；新增"写入规则"说明 `json.RawMessage` 下 nil 与 null 的处理策略 |

### HIGH 修复（4 项）

| 编号 | 问题 | 修复内容 |
|------|------|---------|
| H-1 | §2.6.2 rule 5（L245）"SHOULD return"措辞缺少 spec 引用与"planner 选择"语义 | L245 改为引用 JSON-RPC 2.0 spec §6 Batch + MCP spec 2024-11-05 §2.2；新增"planner 选择：本设计采用严格 spec 行为——批量内任一元素 JSON 解析失败时，整个批量响应为单个顶层 -32700 错误，不做部分响应；用户可通过配置 responses 字段显式覆盖" |
| H-2 | §5.3 状态机（L718）CANCELED 箭头描述过于简略，混用 `notifications/cancelled` 通知与方法响应 | L718 改为完整描述："`notifications/cancelled` notification → server: `tools/call` response `{state:"canceled"}` → CANCELED"，与 §3.7 + §7.10 + §7.15 一致 |
| H-3 | §2.5 DELETE /mcp（L201）无测试覆盖 | 新增 T91"Streamable HTTP DELETE /mcp 终止会话"集成用例：DELETE 请求/响应 204/会话清理后 404 验证；§8.16 测试统计更新为 91 条 |
| H-4 | §4.4 includeContext（L653）spec 引用模糊（仅说"MCP spec CreateMessageRequest"） | L653 改为明确引用"MCP spec 2025-03-26 §sampling.createMessage 枚举 3 个合法值：none/thisServer/allServers" |

### MEDIUM 修复（4 项）

| 编号 | 问题 | 修复内容 |
|------|------|---------|
| M-1 | §2.6.1（L233）"非长连接"措辞不够精确（应区分"持久 SSE 订阅"与"短周期 SSE 响应"） | L233 改为"短周期 SSE 响应模式，非持久 SSE 订阅"，与 §2.4 GET /mcp 长连接模式形成对照 |
| M-2 | §4.1 L528 `IDCounter` 与 §4.2 MCPRequest.ID 注释模糊（0=自动 vs 显式 0） | L528 明确语义：IDCounter=0 与 Requests[i].ID=0 均表示"未设置，由 planner 自动从 1 开始递增分配"；用户显式非零 id 跳过自动分配；不允许混用模式；§4.2 MCPRequest.ID 注释同步更新 |
| M-3 | §7.18 boundary #3（L1365）`id=0 → 拒绝` 与 M-2 修订后矛盾 | L1365 改为"Validate 接受（0 表示自动分配语义）；但混用模式被拒绝——同一 FlowSpec 内若出现非零 ID 则所有 ID 必须显式"；T48 同步更新为"边界"类型 |
| M-4 | §3.10 L494"剩余 7 字段"表述未解释 24+7=31 计数来源 | L494 改为明确字段计数复核："本表列举 24 字段... 加上上述 7 核心字段共 31 字段（与规范 9.4.1.38 一致）；v1.1 修订记录中曾写 25+7=32 系计数错误（误将已删除的幻觉字段 status 计入）" |

### LOW 修复（3 项）

| 编号 | 问题 | 修复内容 |
|------|------|---------|
| L-1 | §2.1.1 L100"id: null 在 MCP 中不允许"过于绝对（null 用于 Parse error 响应） | L100 改为"MCP 强烈不推荐 null id；null 保留用于无法解析的响应场景（如 Parse error 响应的 id 字段固定为 null，见 §2.1.2）" |
| L-2 | §1.4 L67-68 stdio over SSH port 22 无测试覆盖但未标注 | L67-68 增加标注："SSH 隧道场景（TCP 22 + SSH 协议头 + stdio 载荷）为概念描述，当前测试覆盖仅 stdio 直接 TCP 模式（无 SSH 协议头）；SSH 协议封装留待 v1.2 实现，本版本不提供测试用例" |
| L-3 | §5.4 能力矩阵（L761-767）仅 5 行，缺 client 空+server 填 / client 填+server 空 对照 | L761-767 扩展为 7 行：新增"客户端空 + 服务端填"行（client `{}` + server `tools:{}` + `resources:{}`）与"客户端填 + 服务端空"行（client `roots:{}` + `sampling:{}` + server `{}`），明确 server→client 与 client→server 两个方向的非对称性 |

### 新增测试用例汇总（1 条）

| # | 名称 | 类型 | 对应返工问题 |
|---|------|------|-------------|
| T91 | Streamable HTTP DELETE /mcp 终止会话 | 集成 | H-3 |

### 文档统计

- 测试用例总数：90 → 91（+1）
- 负向用例占比：21/91 ≈ 23.1%（新增 T91 为集成测试，负向占比不变）
- §3.10 字段计数：v1.1.1 已为 31（24+7），本次明确复核来源
- §5.4 能力矩阵：5 行 → 7 行（增加 client 空+server 填 / client 填+server 空 两个非对称场景）
- 文档总行数：~2150 → ~2200

### v1.1.2 二轮返工结论

v1.1.2 修订后，文档通过二轮返工：
- 4 项 CRITICAL 问题（C-1 id 重复语义 / C-2 重复键实现机制 / C-3 ServerCapabilities 默认值不一致 / C-4 null 与缺省差异）：全部修复。
- 4 项 HIGH 问题（H-1 SHOULD return 措辞 / H-2 CANCELED 箭头描述 / H-3 DELETE /mcp 无测试 / H-4 includeContext spec 引用）：全部修复。
- 4 项 MEDIUM 问题（M-1 长连接措辞 / M-2 IDCounter 语义模糊 / M-3 boundary #3 矛盾 / M-4 字段计数来源）：全部修复。
- 3 项 LOW 问题（L-1 null id 绝对化 / L-2 SSH 隧道无测试标注 / L-3 能力矩阵不全）：全部修复。
- 测试用例达到 91 条（v1.0 60 + v1.1 20 + v1.1.1 10 + v1.1.2 1）。
- 能力双向门控矩阵从 5 行扩展为 7 行，覆盖所有 client/server 能力声明组合的非对称场景。

文档已具备进入实现阶段的最终条件。实现阶段须遵循 CLAUDE.md 测试策略规则 7（失败测试先行）：每个 bug fix 先写失败测试，再修复代码。v1.2 计划：SSH 隧道 stdio 场景测试、MCPRequest.ID 改 *int API 评估、负向用例占比补足至 25%。

---

## 修订记录 v1.1.3 (2026-08-03)

本次三轮审计返工基于 v1.1.2 二轮返工后的第三轮审查（见 `docs/protocol-designs/audit/16-17-mcp-a2a-audit.md` §"三轮审计 MCP v1.1.2"），发现 17 项遗留问题（3 CRITICAL + 5 HIGH + 5 MEDIUM + 4 LOW），逐项修复如下。**核心结论**：v1.1.2 的 H-4 "修复" `includeContext` spec 引用反而引入了幻觉字段——把模糊引用改成了精确但伪造的引用；本轮返工彻底删除该字段并撤销 H-4 修复。

### CRITICAL 修复（3 项）

| 编号 | 问题 | 修复内容 |
|------|------|---------|
| 3R-C1 | §4.4 Validate rule 14 / §7.13 / T74 / v1.1.2 H-4 修订记录中 `includeContext` 字段是幻觉字段（spec 三版本均不存在）| §4.4 删除 rule 14（`includeContext` 校验），原 15-17 条规则重新编号为 14-16；§7.13 sampling 字节示例删除 `"includeContext":"thisServer"` 行；§7.13 变体删除"includeContext=..."选项；T74 改为"sampling 字段完整性"正向用例（覆盖 spec `CreateMessageRequest` 实际字段 `messages`/`modelPreferences`/`systemPrompt`/`maxTokens`，可选 `temperature`/`stopSequences`）；撤销 v1.1.2 H-4 修订记录中的"明确引用 MCP spec 2025-03-26 §sampling.createMessage 枚举 3 个合法值"——该 spec 引用伪造，三版本 spec 均无 `includeContext` 字段 |
| 3R-C2 | §6.3 / 附录 A.2 HTTP+SSE 传输时序违反 spec（POST 放在 GET 之前）+ 完全遗漏 spec 强制要求的 `endpoint` 事件 | §2.4 重写 HTTP+SSE 传输描述：明确四步时序（GET → endpoint 事件 → POST 到 endpoint URI → GET SSE 推送响应）；§6.3 重写 PacketConfig 序列表：第 4 步改为 GET `/mcp` 建立 SSE 流，第 5 步服务端 SSE 推送 `event: endpoint\ndata: /mcp?session=xxx\n\n` + `event: message\ndata: {...}`；第 6 步客户端 POST 到 endpoint 指定的 URI；附录 A.2 同步重写（GET 先于 POST，含 `endpoint` 事件）；§6.1 第 5d 步明确"GET 先于 POST"时序；新增 T96 集成测试用例验证 `endpoint` 事件 + GET 先于 POST 时序；T58 字节级断言同步更新为"GET 先于 POST + endpoint 事件" |
| 3R-C3 | §3.3 / §7.6 / T71 `resources/unsubscribe` 方法在 spec 2024-11-05 与 2025-06-18 中不存在（仅 2025-03-26 中间版本定义）| §3.3 删除 `resources/unsubscribe` 行，新增注释"MCP spec 2024-11-05/2025-06-18 不定义此方法；订阅隐式随会话结束失效"；§7.6 删除独立字节示例行，改为"变体"小节标注"spec 2025-03-26 中间版本扩展，仅在该 protocol_version 时生成；其他版本作为 -32601 Method not found 异常场景"；T71 改为双向用例：(a) protocol_version=2025-03-26 正向 + (b) protocol_version=2024-11-05/2025-06-18 负向 -32601 |

### HIGH 修复（5 项）

| 编号 | 问题 | 修复内容 |
|------|------|---------|
| 3R-H1 | §7.5 / T22 `resources/read` uri 不存在错误码 -32602 与 spec 不一致（spec 用 -32002 Resource not found）| §7.5 变体"uri 不存在"改为 `error.code=-32002 "Resource not found"`，引用 spec 2024-11-05/2025-06-18 `server/resources` §Error Handling；T22 同步改为断言 -32002；新增 T92 "resources/read error.code=-32002 Resource not found"正向用例（spec 字段覆盖） |
| 3R-H2 | 附录 B 错误码 -32002/-32004/-32800 语义与 spec 不符 | 附录 B 重写：-32002 含义改为"Resource not found"（spec 2024-11-05/2025-06-18 `server/resources`），删除 v1.1.2 错误的"Server not initialized"；-32004 "Rate limited" 删除（spec 三版本无此码，sampling 错误示例用 -1）；-32800 移至独立"非标准扩展错误码"小节，标注 planner 默认不生成；§7.19 异常场景表第 6 行改为 resources/read -32002，第 7 行改为 sampling -1，第 8 行标注 -32800 非 spec 标准；§7.2 / §7.10 同步删除"Server not initialized -32002"引用，改为 -32601；新增 T93 "sampling 拒绝响应 error.code=-1"正向用例 |
| 3R-H3 | §4.2 / §4.4 / §7.4 `embedded_resource` content type 是幻觉类型，spec 用 `resource`（嵌入资源）+ 2025-06-18 新增 `resource_link`（资源链接）| §4.2 `MCPContent.Type` 枚举改为 `text`/`image`/`audio`/`resource`/`resource_link`（删除 `embedded_resource`，新增 `resource_link`）；§4.4 Validate rule 11 同步更新并加 spec 注释；§7.4 工具返回嵌入资源变体改为 `type:"resource"`；§9.1 A07 审计项同步更新；新增 T94 `resource_link` + T95 `resource` 两个正向用例 |
| 3R-H4 | §2.6 / §2.6.1 / §2.6.3 声明"旧版 HTTP+SSE 不支持批量"与 spec 2025-03-26 §Batching 矛盾（spec 要求所有传输 MUST 接收 batch）| §2.6 删除"旧版 HTTP+SSE 不支持批量"声明，改为引用 spec 2025-03-26 §Batching "MUST support receiving"；§2.6.1 "批量 + HTTP+SSE 组合"改为"POST body 可以是批量数组，服务端通过 GET SSE 流按序推送 N 个 event:message"；§2.6.3 planner 行为删除"Transport=http_sse 则报错"，改为"所有传输均支持接收批量"；新增 T97 集成测试用例验证 HTTP+SSE 批量 POST body → SSE N 个 event:message |
| 3R-H5 | §3 方法表 / §4.4 / 附录 B 未记录 2025-06-18 新增 Elicitation / structuredContent / resource_link / title / annotations 五项特性 | 附录 B 协议版本表扩展 2025-06-18 行：列出 Elicitation / `outputSchema`+`structuredContent` / `resource_link` / `title` / `annotations` 五项新特性，标注"v1.1.3 部分支持：resource_link 已加入枚举；其余留待 v1.2"；§4.4 Validate rule 3（ProtocolVersion）保持接受 2025-06-18 但不强制生成新字段；本版本不删除 2025-06-18 支持，但明示新字段未实现 |

### MEDIUM 修复（5 项）

| 编号 | 问题 | 修复内容 |
|------|------|---------|
| 3R-M1 | §3.2 / §7.4 / §8 `tools/list` 分页（cursor）未记录未测试 | §3.2 tools/list 行说明列补"支持分页 cursor"；§3.4 prompts/list 同步补"支持分页 cursor"；§7.4 tools/list 请求字节示例补 cursor 变体（首页省略 cursor，翻页带 cursor）；新增 T100 "tools/list 分页（cursor + nextCursor）"正向用例 |
| 3R-M2 | §5.4 Rule 5 / T90 重复键检查仅覆盖 ClientCapabilities，未覆盖 ServerCapabilities | T90 保持 ClientCapabilities 侧；新增 T99 "ServerCapabilities 重复键 → Validate 拒绝"负向用例，与 T90 对称覆盖；实现机制同 T90（`mcp_helpers.go` 的 `checkDuplicateKeys()`） |
| 3R-M3 | §2.6.2 rule 5 / rule 6 边界模糊（"批量中包含非法元素 JSON 解析失败"易误读为单元素失败）| §2.6.2 rule 5 改为"批量请求的**整个 JSON 数组本身解析失败**时"（引用 JSON-RPC 2.0 spec §6 原文 "If the batch rpc call itself fails to be recognized as a valid JSON"），明确"不是单个元素解析失败——后者按 rule 6"；rule 6 改为"批量数组能成功 JSON 解析，但某元素不是合法 JSON-RPC 2.0 对象时"；新增 T98 "批量整体 JSON 解析失败 → 顶层 -32700"负向用例 |
| 3R-M4 | §7.12 `roots/list` 请求带 `params:{}` 与 spec 示例不一致（spec 示例无 params）| §7.12 roots/list 请求字节示例改为 `{"jsonrpc":"2.0","id":12,"method":"roots/list"}`（无 params）；新增注释"planner 默认省略 params 字段（与 spec 示例一致）；若用户显式配置 params:{} 也接受"；新增 T101 "roots/list 请求省略 params"正向用例 |
| 3R-M5 | §7.4 / §7.19 / T17 工具名错误码 message 不规范（spec 示例 message 含工具名，无 data）| §7.4 工具名不存在字节示例改为 `error.code=-32602, message="Unknown tool: <name>"`（message 含工具名，spec 2024-11-05 `server/tools` §Error Handling 示例）；§7.19 异常场景表新增"异常码边界说明"小节，明确 -32601 vs -32602 vs -32002 边界；T17 同步改为断言 message 含 "Unknown tool:"；新增 T104 "tools/call 工具名不存在 message 含 Unknown tool:"正向用例 |

### LOW 修复（4 项）

| 编号 | 问题 | 修复内容 |
|------|------|---------|
| 3R-L1 | §7.3 ping "带 params（非标准）"变体与 spec 不一致（spec 明确 "no parameters"）| §7.3 ping 变体重写：删除"非标准但允许"措辞，改为三种变体：(a) ping params 省略（spec 标准，planner 默认）；(b) ping params 空对象（宽松 spec 接受）；(c) ping params 非空对象（负向，严格 spec 服务端 -32602 Invalid params）；新增 T102 "ping 三种 params 变体"边界用例 |
| 3R-L2 | §7.13 sampling `temperature`/`stopSequences` 字段未在示例中展示（spec schema 定义但示例未展示）| §7.13 sampling 字节示例保留 `temperature`/`stopSequences`（v1.1.3 已删除 `includeContext`，保留 temperature/stopSequences 作为可选字段）；§7.13 变体新增"`temperature`/`stopSequences` 字段"说明（spec schema 定义但示例未展示，planner 作为可选字段生成）；新增 T103 "sampling 请求含 temperature/stopSequences"正向用例 |
| 3R-L3 | §4.4 Validate rule 3 ProtocolVersion 枚举未列出未来版本占位 | §4.4 rule 3 改为"ProtocolVersion ∈ {`""`, `"2024-11-05"`, `"2025-03-26"`, `"2025-06-18"`}（其他值报错——MCP spec 仅这几个已发布版本；**未来版本处理策略**：当 MCP spec 发布新版本，需在本 Validate 规则中追加新枚举值；当前实现采取严格枚举策略而非 warning，避免未知版本被静默接受后产生互操作性问题；新版本发布后由维护者追加）" |
| 3R-L4 | §7.18 boundary #20 "GET /mcp 但未先 POST initialize" 与 HTTP+SSE spec 矛盾（spec 时序为 GET 先于 POST）| §7.18 boundary #20 改为"Streamable HTTP 模式 GET /mcp 但未携带 Mcp-Session-Id | 服务端返回 400 Bad Request（spec 2025-03-26 §Streamable HTTP：GET /mcp 要求携带 Mcp-Session-Id；旧版 HTTP+SSE 的 GET 不携带 session id，不属于错误场景）"；删除原"POST 先于 GET 是错误"的矛盾前提 |

### 新增测试用例汇总（13 条）

| # | 名称 | 类型 | 对应返工问题 |
|---|------|------|-------------|
| T92 | resources/read error.code=-32002 Resource not found | 正向 | 3R-H1 |
| T93 | sampling 拒绝响应 error.code=-1 | 正向 | 3R-H2 |
| T94 | MCPContent.Type=resource_link（spec 2025-06-18 新增） | 正向 | 3R-H3 |
| T95 | MCPContent.Type=resource 嵌入资源（spec 标准） | 正向 | 3R-H3 |
| T96 | HTTP+SSE endpoint 事件 + GET 先于 POST 时序 | 集成 | 3R-C2 |
| T97 | HTTP+SSE 批量 POST body 数组 → SSE 流 N 个 event:message | 集成 | 3R-H4 |
| T98 | 批量整体 JSON 解析失败 → 顶层 -32700 | 负向 | 3R-M3 |
| T99 | ServerCapabilities 重复键 → Validate 拒绝 | 负向 | 3R-M2 |
| T100 | tools/list 分页（cursor + nextCursor） | 正向 | 3R-M1 |
| T101 | roots/list 请求省略 params（与 spec 示例一致） | 正向 | 3R-M4 |
| T102 | ping 三种 params 变体 | 边界 | 3R-L1 |
| T103 | sampling 请求含 temperature/stopSequences 字段 | 正向 | 3R-L2 |
| T104 | tools/call 工具名不存在 message 含 "Unknown tool:" | 正向 | 3R-M5 |

注：3R-L3（ProtocolVersion 枚举）与 3R-L4（boundary #20）通过文档修复覆盖，无需新增测试用例。

### 文档统计

- 测试用例总数：91 → 104（+13）
- 负向用例占比：21/91 ≈ 23.1% → 24/104 ≈ 23.1%（新增 T98/T99/T102(c) 三条负向，新增 13 条中 3 条负向；占比基本持平，v1.2 计划继续补充至 25%）
- 附录 B 错误码表：8 行 → 7 行 + 1 行非标准扩展小节（-32004 删除，-32800 移至非标准扩展）
- §4.4 Validate 规则：17 条 → 16 条（删除原 rule 14 includeContext，重新编号 14-16）
- §3.3 资源方法表：6 行 → 5 行（删除 resources/unsubscribe）
- 文档总行数：~2198 → ~2400

### v1.1.3 三轮审计返工结论

v1.1.3 修订后，文档通过三轮审计返工：
- 3 项 CRITICAL 问题（3R-C1 includeContext 幻觉字段 / 3R-C2 HTTP+SSE 时序违反 spec + 遗漏 endpoint 事件 / 3R-C3 resources/unsubscribe spec 不存在）：全部修复。
- 5 项 HIGH 问题（3R-H1 resources/read 错误码 / 3R-H2 附录 B 错误码语义 / 3R-H3 embedded_resource 幻觉类型 / 3R-H4 HTTP+SSE batch 支持声明 / 3R-H5 2025-06-18 新特性记录）：全部修复。
- 5 项 MEDIUM 问题（3R-M1 tools/list 分页 / 3R-M2 ServerCapabilities 重复键 / 3R-M3 batch rule 5/6 边界 / 3R-M4 roots/list params / 3R-M5 工具名错误 message）：全部修复。
- 4 项 LOW 问题（3R-L1 ping params / 3R-L2 sampling temperature / 3R-L3 ProtocolVersion 枚举 / 3R-L4 boundary #20）：全部修复。
- 测试用例达到 104 条（v1.0 60 + v1.1 20 + v1.1.1 10 + v1.1.2 1 + v1.1.3 13）。
- 删除幻觉字段 `includeContext`（spec 三版本均不存在，v1.1.2 H-4 "修复"反而引入了伪造的 spec 引用，本轮撤销）。
- 删除幻觉 content type `embedded_resource`，新增 spec 2025-06-18 `resource_link`。
- HTTP+SSE 传输时序修正为 spec 合规（GET 先于 POST + endpoint 事件）。

**v1.1.2 二轮返工结论的"已具备进入实现阶段的最终条件"声明不成立**——三轮审计发现 3 项 CRITICAL + 5 项 HIGH 问题，其中 3R-C1（includeContext 幻觉字段）是 v1.1.2 H-4 修复引入的回归。v1.1.3 修复后，文档可进入实现阶段。实现阶段须遵循 CLAUDE.md 测试策略规则 7（失败测试先行）：每个 bug fix 先写失败测试，再修复代码。实现者应实时拉取 MCP spec（而非依赖设计文档的 spec 引用），以 spec 为准——本轮发现 v1.1.2 的 spec 引用存在伪造，根本原因是设计阶段未逐一打开 spec 页面核对字段。v1.2 计划：Elicitation / structuredContent / title / annotations 实现、SSH 隧道 stdio 场景测试、MCPRequest.ID 改 *int API 评估、负向用例占比补足至 25%。

---

## 12. 层链迁移设计契约（D1–D8，2026-09-30）

| ID | 结论 | 证据/去向 |
|---|---|---|
| D1 | 地址只住 `layers[].ip`，端口只住 `layers[].tcp`；数量只住用例兄弟键 `strategy_fc` 或策略 `flow_control`。 | 103 条 cases 机读审计；协议旧扁平五键均为 0。 |
| D2 | MCP 是 TCP 终结层，标准链为 `[ip,tcp,mcp]`；stdio、HTTP+SSE、Streamable HTTP 均由 MCP 层选择应用承载。 | `internal/protocol/mcp` 注册与 cases 全量正例层链。 |
| D3 | `transport`、请求序列、响应、能力、认证和状态字段均住 `layers[].mcp`；不得在 `spec_json` 顶层重复 MCP 子映射。 | `mcp.json` 102 条正例/常规负例均为层内配置。 |
| D4 | 多会话用 MCP 层配置配合兄弟 `strategy_fc` 展开；每条流必须独立四元组、session 语义和 ID 序列。 | `mcp_t043_stdio_multiflow_3_sessions`、`mcp_t044_stdio_multiflow_id_seq`；字段级隔离证据仍登记缺口。 |
| D5 | 顶层 `mcp:{}` 只作为 presence 判死负例，不是正例配置入口。 | `mcp_t090_presence_reject`。 |
| D6 | `strategy_fc` 只表达 cases 驱动的流数量；协议业务配置不借用 `count` 或顶层地址/端口。 | 4 条带 `strategy_fc` 的 cases；静态复制拒绝例为 `mcp_t092_static_copy_reject`。 |
| D7 | 负例保留故意违规输入和稳定错误锚词，不把配置拒绝伪装成协议错误响应。 | 14 条负例均有 `expect_error` 与 `error_contains`。 |
| D8 | 尚未被独立 cases/PCAP/NIC 证明的语义只登记缺口；本次不改 Go 实现、全局索引或其他协议。 | 下方缺口表与 testcase §10；实现路径已有单测但本文不宣称套件通过。 |

### 12.1 迁移前后形状

正例唯一入口：

```json
{"layers":[{"ip":{"src":"10.0.0.1","dst":"20.0.0.1"}},
 {"tcp":{"src_port":12345,"dst_port":8081}},
 {"mcp":{"transport":"stdio","requests":[{"method":"tools/list"}]}}]}
```

`mcp_t090_presence_reject` 的顶层 `mcp:{}` 是故意判死形状；`strategy_fc` 是 cases 条目兄弟键，不属于协议层配置。

### 12.2 缺口与迁入计划

- `MCP-GAP-1`：HTTP 族、批量请求、多会话隔离和长消息 MSS 的完整 PCAP 字段/字节闭环未在本次文档变更中重新执行；待 MCP suite + tshark 逐例校准。
- `MCP-GAP-2`：NIC 双路吞吐、并发、内存、队列背压和长时间运行的六类性能数据未建立；实现后按 §6.6–§6.8 补基线与上限。
- `MCP-GAP-3`：2025-06-18 的 Elicitation、structuredContent、title、annotations 仍是设计中明确的未来面；实现前不得写入正例或宣称覆盖。
- `MCP-GAP-4`：重复键原始 JSON 输入、OAuth2 完整流程、SSH 隧道封装和 Streamable GET 缺 session 的 400 分支缺独立可执行例；分别补原始输入入口、认证/传输编排和负例锚词。

### 12.3 六项设计审查清单（C1–C6）

| ID | 审查结论 |
|---|---|
| C1 | 103 条 cases 可解析且 ID 唯一；设计条目以 `mcp.json` 当前清单为权威，不虚构新增 ID。 |
| C2 | 102 条 `spec_json` 顶层仅 `layers`；唯一顶层 `mcp` 为故意 presence 负例，4 条 `strategy_fc` 在用例兄弟层。 |
| C3 | 地址/端口/业务字段归属符合层链；标准链为 `[ip,tcp,mcp]`，无顶层旧地址、端口或 `count`。 |
| C4 | 14 条负例均有明确错误锚词；配置拒绝与 JSON-RPC 业务错误响应分开统计。 |
| C5 | stdio、HTTP 两族、IPv4/IPv6、能力、状态、多会话、动态流数和边界均有 cases；未闭环面登记 `MCP-GAP-1..4`。 |
| C6 | 本次范围仅 MCP 三文件；不修改 Go、全局索引、suite 服务或其他协议。 |

### 12.4 自审记录

本节自审两轮：第一轮逐项核对 D1–D8、层链归属、负例保留和缺口边界；第二轮对照 `mcp.json` 的 103 个 ID、顶层键和 `strategy_fc` 统计，末轮干净。

---

## 13. 实现与 cases 当前真相（as-built，2026-09-30，静态对账）

> 本节只记录静态可核的当前真相：cases JSON 机读 + Go 代码静态映射。任何 suite、PCAP、NIC、tshark 全量通过结论均待独立证据，不得由本节推出。

### 13.1 规范设计矩阵（normative matrix）

| 维度 | 设计声明 | 当前 cases | 缺口 |
|---|---|---|---|
| 传输 | `stdio` / `http_sse` / `streamable` 均须正例；`websocket` 为非法 | stdio 94、streamable 4、http_sse 3（含负例 1）；websocket 负例 1；未写 transport 1 | 未写 transport 例的默认 stdio 行为待执行验证；http 族仅 6 例，未形成批量/SSE/DELETE 的完整字节闭环（`MCP-GAP-1`） |
| 生命周期 | initialize → initialized → 业务 → teardown | 89 正例均 `packet_count` 断言；85 正例 `has_handshake=true` | teardown 三包字节序列只在静态 TCP 层生成器逻辑中，未由 cases suite 今日执行证明 |
| 能力协商 | 双向门控规则 1–5；重复键 Validate 拒绝 | 能力门控正例 #17–#24；#21/#22 退化为非对象拒绝（原始重复键字节流未测试） | 原始重复键输入路径缺独立可执行例（`MCP-GAP-4`） |
| 方法覆盖 | 工具/资源/提示词/补全/日志/roots/sampling | §2–§8 按 ID 回指（见 testcase §8.1） | 31 字段无逐字段独立断言；许多字段只存在于 frames hex 片段或 notes |
| 错误码 | -32700/-32600/-32601/-32602/-32603/-32002/-1；-32800 非标仅显式配置 | 14 负例均 `expect_error` + `error_contains`；业务错误码走正例响应体 | 负例错误传播到 task error 的执行证据待 P5 |
| 多会话 | M 流独立四元组/sessionId/ID 序列 | #27/#28 每例 36 包 + 1 条 TCP 字段 | 逐流 sessionId/四元组/ID 序列无完整字段/帧断言（缺口登记） |
| 未来面 | Elicitation / structuredContent / title / annotations；OAuth2 真实 flow；SSH 隧道 | 全部未入 cases | `MCP-GAP-3` / `MCP-GAP-4`，实现前不得写入正例 |

### 13.2 三源对比（设计 / 代码 / cases）

| 行为 | 设计 | 代码 | cases | 结论 |
|---|---|---|---|---|
| 层链唯一真相 | §12 D1–D8 | `registry.go` mcp P4a 块：21 键、零 Default、`DependsOn: tcp` | 103/103 `[ip,tcp,mcp]`；102 例顶层仅 `{layers}`；#90 故意 `{layers,mcp}` | 一致 |
| `think_time` 字段 | 历史字段 | 已删（registry 注释：M1-E1 删死字段） | 0 例使用 | 一致；设计旧文本若再提 `think_time` 以代码为准 |
| Legacy Plan TCP 自产握手/挥手 | §6.2 3 包 teardown | legacy `plan.go` 仍在；链上事件模式不产（tcp 层生成器负责标准 4 包） | packet_count 按链上静态预期登记，未今日执行 | divergence 已在 `layer_gen.go` 头部文档化；cases 不宣称 wire 通过 |
| DstPort 默认 | §10.7 8081/22 | `chain_planner.go` dst 端口 mcp 分支默认化 | cases 层内显式端口 | 一致（生成器不再默认） |
| 错误路由 | §4.4 Validate 16 条 | `mcp.go` Validate 实现逐条对应；`layer_gen.go` 错误同步返回（防吞成 completed+0 包） | 14 负例锚词均可在代码中找到对应 `fmt.Errorf` | 一致；执行传播待 P5 |
| sessionID 默认随机 | §4.3 默认规则 | `plan.go` / `layer_gen.go` 随机 32 hex；测试须显式设置保证确定性 | HTTP 例显式 session（静态） | 一致；随机默认的确定性风险已文档化 |

### 13.3 候选方案对比（已裁定的关键取舍）

| 决策 | 采纳 | 拒绝 | 理由 |
|---|---|---|---|
| 重复键处理 | Validate 前 tokenizer 预扫描并拒绝 | 接受 last-wins | spec 禁止重复键；下游 JSON 库行为不一致 |
| 未知能力键 | 透传 + warning，继续通信 | 直接拒绝 | 双向门控规则 3（优雅降级） |
| 批量整体解析失败 | 单个顶层 -32700，不做部分响应 | 逐项部分响应 | JSON-RPC 2.0 spec §6 严格行为 |
| 未来 protocol_version | 严格枚举，缺新版本即拒绝 | warning 放行 | 避免未知版本静默互操作问题 |
| funds 错误吞咽 | 生成器错误同步返回 | 空流 completed | CLAUDE.md §2 反例纪律（doip/gbt32960 同款） |

### 13.4 依赖 / 错误 / 重试 / 超时

- 仅依赖 `internal/core`（+ `core/layers` 事件模型）；不依赖 `modelcontextprotocol/go-sdk` 与 `internal/mcp/`（§10.5、§11）。
- 错误：构造错误经 `Planner.Err()` 通道（单缓冲，只保留首错）或事件模式同步返回；Validate 拒绝在 planner 阶段，未证明 task error 传播（待 P5 逐例验证）。
- 重试：端口冲突由外层 strategy 层重试（planner 不感知）；JSON 序列无应用层重试语义。
- 超时：无 MCP 层独立超时配置；`ThinkTime` 已删除；rounds 间等待无独立字段。

### 13.5 性能（静态声明，无今日数据）

- 六类数据（NIC 双路吞吐、并发、内存、队列背压、长时间运行、上限）均未建立（`MCP-GAP-2`）。
- 设计引用 §6.6–§6.8 的旧编号在本文件无对应小节；以 `MCP-GAP-2` 登记为准，不得引用不存在的章节号。

### 13.6 八要素对账

| 要素 | 状态 |
|---|---|
| 输入形状 | 102 例 `{layers}` + #90 故意 `{layers,mcp}`（机械审计已确认） |
| 输出形状 | 89 正例 `packet_count` 合计 1202；64 `tcp.*` fields；149 frames；无 `min_packets` |
| 字段归属 | 地址→ip 层、端口→tcp 层、业务→mcp 层；顶层旧地址/端口/count 为 0 |
| 状态机 | 会话 5 态 + 长任务 6 态；非法跳转 Validate 拒绝（执行证据待 P5） |
| 并发 | strategy_fc 4 例（flows 3/3/2/2）；聚合包数静态登记，未执行验证 |
| 错误 | 14 负例两键严格形；锚词与代码一一对应（静态） |
| 版本 | 接受 2024-11-05/2025-03-26/2025-06-18；2025-06-18 新字段仅 `resource_link` 落地 |
| 证据 | 静态对账完成；suite/PCAP/NIC/tshark 证据全部待补 |

### 13.7 动态字段 + 序列算法

- 动态面：`session_id` 缺省随机 32 hex；`id` 缺省自 `id_counter`（0→1）递增；多会话每流独立重置 id 序列与 session（`plan.go:75-94`、`layer_gen.go` 同款）。
- 序列算法：initialize 请求→响应→`notifications/initialized`→逐请求配对响应（缺省合成成功）→`notifications[step]` 插入→rounds 重复（id 续增不重置）→teardown（legacy stdio 3 包；链上 tcp 层标准挥手）。
- 确定性要求：任何声称字节稳定的用例必须显式固定 `session_id`；随机默认只用于非断言场景。

### 13.8 Gate-1 静态门禁表

| 门 | 条件 | 当前结果 |
|---|---|---|
| G1-1 | JSON 可解析、103 ID 唯一 | 通过（机械审计） |
| G1-2 | 89 正例均有 `packet_count`，14 负例严格两键 | 通过（机械审计） |
| G1-3 | 正例层链 100% `[ip,tcp,mcp]`；顶层键合规 | 通过（103/103；#90 为故意 presence 形） |
| G1-4 | 负例锚词在代码中有对应拒绝点 | 通过（14/14 静态映射） |
| G1-5 | 无 suite/PCAP/NIC 通过宣称 | 通过（两份文档均只登记“待 P5”） |
| G1-6 | suite/PCAP/NIC/tshark 全量执行 | **未执行**（`MCP-GAP-1/2`）；本文件静默期不进入 Gate-2 |

### 13.9 自审记录

本节自审两轮：第一轮逐项核对规范矩阵、三源对比、候选取舍与八要素的静态证据；第二轮复核 gate 表“未执行”项无一被写成通过，末轮干净。

**passed 2 rounds, last round clean.**

### 13.10 D1–D8 完整静态闭环（2026-10-01）

#### D1：P1 八项规范矩阵

| 规范要求 | 业务场景 | 代码现状 | 缺口/结论 |
|---|---|---|---|
| 连接模型：stdio、HTTP+SSE、Streamable HTTP | 行分隔会话、SSE 双流、单端点 HTTP | `mcp` 终结层按 `transport` 分支 | 合入；HTTP 批量与重组证据列 `MCP-GAP-1` |
| 命令/消息：生命周期、tools、resources、prompts、sampling、通知 | initialize 后按序请求/响应及通知 | `requests`、`responses`、`notifications` 在 `mcp` 层 | 合入；未落 JSON 的方法不宣称覆盖 |
| 状态机：初始化、运行、关闭及长任务状态 | initialized、progress、completed/failed/canceled | `state` 与 `_meta.state` 配置、Validate 枚举 | 合入；task error 传播待 P5 |
| 字段：JSON-RPC、能力、认证、内容、会话 | capability 协商、Bearer/Basic、内容变体 | 业务字段均在 `layers[].mcp` | 合入；31 字段独立断言不完整 |
| 错误处理：标准码与资源错误 | parse/invalid/method/params/internal/resource | `responses[].error` 与 14 个配置负例 | 合入；执行传播列 `MCP-GAP-1` |
| 超时与活性：ping、保活、终止 | ping、SSE 长连接、DELETE/FIN | `Shutdown`、transport 序列 | 无独立超时字段；不得虚构运行证据 |
| NAT/代理/会话标识 | HTTP endpoint、session header/query | `session_id`、HTTP 帧生成 | 合入；真实代理/NAT 未在本次范围 |
| 版本/方言：2024-11-05、2025-03-26、2025-06-18 | 版本降级与 `resource_link` | Validate 严格枚举 | 合入；新版本须新增枚举与用例 |

#### D1 三张子表

命令×响应码：

| 命令/路径 | 成功 | 失败 | 当前证据 |
|---|---|---|---|
| initialize/initialized | 正常进入 operating | 配置错误在 Validate 阶段拒绝 | 正例与负例分离 |
| tools/list、tools/call | result | -32601/-32602 或 `isError` | 正例 frames/业务错误 |
| resources/list/read | result | -32002 Resource not found | `mcp_t092_stdio_resources_read_32002` |
| prompts/completion/logging | result | 配置错误拒绝 | 对应正例索引 |
| roots/sampling/notifications | result 或通知 | 能力未声明时 -32601 | 能力门控正例 |

数据形态变体：

| 形态 | 覆盖/状态 |
|---|---|
| stdio 行分隔 JSON | 已有正例 |
| HTTP+SSE endpoint/message | 已有正例，完整执行闭环列 `MCP-GAP-1` |
| Streamable JSON/DELETE | 已有正例，完整执行闭环列 `MCP-GAP-1` |
| IPv4/IPv6、文本/blob、image/resource/resource_link/audio | cases 已出现的变体按索引覆盖 |
| 多会话、rounds、长消息 MSS | 已登记，字段级/运行级证据列 `MCP-GAP-1` |

商业行为→用例映射：

| 现网行为 | 用例 ID | 结论 |
|---|---|---|
| Claude Desktop/客户端信息协商 | `mcp_t101_claude_desktop` | 已入 cases |
| Streamable 会话 DELETE | `mcp_t087_streamable_full` | 已入 cases |
| Bearer/Basic 认证头 | `mcp_t036_http_sse_bearer_auth`, `mcp_t037_streamable_basic_auth` | 已入 cases |
| 服务端信息透传 | `mcp_t103_flowb_server` | 已入 cases |
| OAuth2 真实授权流程 | — | `MCP-GAP-4`，需真实交互入口确认 |

#### D2 三路对照与候选方案

| 规范原文编号/章节 | 商业软件行为 | 开源实现思路 | 取舍 |
|---|---|---|---|
| JSON-RPC 2.0 §6；MCP 2024-11-05 transports | 客户端按 endpoint 建立 SSE，再 POST | Go MCP SDK 的 transport 分层 | 采用 GET→endpoint→POST；批量运行证据列 `MCP-GAP-1` |
| MCP 2025-03-26 Streamable HTTP | 单端点 POST，可 DELETE 会话 | SDK 的 session header 与 SSE writer | 采用 `streamable` 分支；不模拟真实 SDK |
| MCP `server/resources` Error Handling | 资源不存在返回资源错误 | 以显式 error response 建模 | 采用 -32002；不改成通用 -32602 |

| 候选走法 | 优点 | 代价 | 裁定 |
|---|---|---|---|
| `transport` 分支内直接构造 payload | 改动小、字节可控 | HTTP 重组与业务逻辑耦合 | 采用，符合当前 planner |
| 独立 transport writer 再交给通用 TCP | 复用 HTTP/SSE 编码 | 需要新接口与更多状态同步 | 暂不采用，待 HTTP 缺口进入实现立项 |

#### D3–D8 依赖、性能、接口与动态字段

| 条目 | 当前结论 | 证据/缺口 |
|---|---|---|
| D3 依赖与错误 | 依赖 `ip`→`tcp`→`mcp`；Validate 错误中断，生成错误不转 completed；无协议重试，外层负责超时 | `mcp.go` Validate、`layer_gen.go` 错误路径；传播待 P5 |
| D4 性能验收 | 流式逐包输出；吞吐/并发/内存/队列/CPU 六类指标均待测；pcap 与网卡分别验收 packet/bit rate、丢包、队列与资源 | `MCP-GAP-2`，不写未测数字 |
| D5 八要素 | 文件 `internal/protocol/mcp`；接口 Planner/Validate/Plan；结构 `[ip,tcp,mcp]`；流程握手→业务→关闭；错误为 task error；边界由 MSS/buffer；冲突为 legacy 与 layer plan；回滚为仅回退三文件文档变更 | 静态对账，运行证据待 P5 |
| D6 动态字段 | 四元组：`ip.src/dst`、`tcp.src_port/dst_port`；业务：`session_id`、request `id`、`rounds`；策略为 fixed/inc/rand 或 planner 递增；不动态的业务字段保持显式值 | `mcp` 层配置与 §13.7；多流完整隔离列 `MCP-GAP-1` |
| D7 门1 | 旧键去向：地址→ip、端口→tcp、数量→`strategy_fc`；完整链形与五件套见 §12；动态三行见 D6 | 103 条 cases 静态对账 |
| D8 收口 | 无未归属正例字段；未闭环面均有 `MCP-GAP-1..4` 编号与迁入方向；不以顶层业务键替代层归属 | #90 仅是故意负例 |

**D1–D8 自审：** 已逐行核对规范八项、三张子表、三路对照、两候选方案、负例锚词和 `MCP-GAP-1..4`；本节不宣称 suite、PCAP、NIC 或 MCP 执行通过。
**passed 2 rounds, last round clean.**
