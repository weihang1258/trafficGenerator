# A2A 协议设计文档

> 版本：**v2.0.3**（2026-08-05）
> 依据：A2A spec v0.2.2 / v0.2.5 / v0.3.0 / v1.0.0 / v1.0.1（已实拉 raw.githubusercontent.com 验证字段与方法名）
> 范围：A2A（Agent2Agent，Agent 间协议）流量生成器协议设计
> 审计对照：`audit/17-a2a-audit-deep.md` v1.1 深审报告 24 项问题（5 CRITICAL / 6 HIGH / 8 MEDIUM / 5 LOW）全部修复；v2.0.1 依据 `audit/17-a2a-audit-r1-v2.md` 复审报告 17 项问题（0 CRITICAL / 3 HIGH / 7 MEDIUM / 7 LOW）全部修复；v2.0.2 依据 `audit/17-a2a-audit-r2-v2.md` 复审报告 8 项问题（0 CRITICAL / 0 HIGH / 5 MEDIUM / 3 LOW）全部修复；v2.0.3 依据 `audit/17-a2a-audit-r3-v2.md` 复审报告 2 项问题（0 CRITICAL / 0 HIGH / 1 MEDIUM / 1 LOW）全部修复

---

## 目录

1. [协议概述](#1-协议概述)
2. [数据类型与编码](#2-数据类型与编码)
3. [消息结构](#3-消息结构)
4. [状态机](#4-状态机)
5. [配置类型定义](#5-配置类型定义)
6. [包序列场景](#6-包序列场景)
7. [测试用例](#7-测试用例)
8. [Validate 规则](#8-validate-规则)
9. [错误处理](#9-错误处理)
10. [扩展字段映射](#10-扩展字段映射)
11. [修订记录](#11-修订记录)

---

## 1. 协议概述

### 1.1 定位

A2A（Agent2Agent，Agent 间协议）是 Google 主导的开放协议，用于"客户端 Agent"与"远程 Agent"之间的互操作。底层传输为 HTTP(S)，载荷格式为 JSON-RPC 2.0（JSON-RPC 2.0，基于 JSON 的远程过程调用协议）。流式响应通过 SSE（Server-Sent Events，服务器发送事件）承载。

本设计文档定义 trafficGenerator 中 A2A 流量生成器的协议层规范：从 Agent Card（Agent 名片，描述 Agent 能力的 JSON 元数据文档）发现、消息发送、任务（Task，A2A 协议的工作单元）生命周期管理，到流式响应、推送通知（Push Notification，服务端主动调用客户端 webhook 通知任务更新）与认证。

### 1.2 与 JSON-RPC 2.0 的关系

A2A 所有请求与响应（不含 SSE 流外层包装）均为 JSON-RPC 2.0 报文：

- 请求：`{"jsonrpc":"2.0","method":<string>,"params":<object>,"id":<string|integer>}`
- 响应（成功）：`{"jsonrpc":"2.0","result":<object>,"id":<string|integer>}`
- 响应（失败）：`{"jsonrpc":"2.0","error":{"code":<int>,"message":<string>,"data":<any>?},"id":<string|integer|null>}`
- 通知（无 id）：A2A 不使用 JSON-RPC 通知，所有方法均为请求-响应模式

`id` 为 JSON-RPC 信封标识（客户端分配，服务端原样回填），与 A2A 协议层的 `taskId`（任务标识，服务端分配）是两个独立概念，详见 §11.6 #1。

### 1.3 Agent 发现

Agent 通过 Agent Card 自描述，发布在 well-known 路径：

- **路径**：`/.well-known/agent.json`（单数 `agent`，遵循 RFC 8615 Well-Known URIs 机制）
- **方法**：HTTP `GET`（非 JSON-RPC，纯 HTTP）
- **spec 出处**：A2A spec v0.2.2 §5.3、v0.2.5 同上、v0.2.6 同上均用 `agent.json`；**v0.3.0 起（含 v1.0.0/v1.0.1）改用 `agent-card.json` 并已完成 IANA 注册（URI suffix: agent-card.json），v1.0 从未恢复为 `agent.json`**。`agent.json` 仅存在于 v0.2.x
- **设计选择**：本设计以 v0.2.x 为目标版本，默认 `agent.json`；对接 v0.3.0/v1.0 的 Agent 时须通过 `AgentCardPath` 覆盖为 `/.well-known/agent-card.json`（见 V13）

> **注**：v0.2.x 用 `agent.json`；**v0.3.0 起（含 v1.0）用 `agent-card.json`**（实拉 v1.0.0 §8.2/§14.3 IANA 注册、v1.0.1 §8.2 验证，v1.0 从未"恢复为 agent.json"）。本设计目标版本为 v0.2.x，默认 `agent.json`；对接 v0.3.0/v1.0 Agent 时须将 `AgentCardPath` 覆盖为 `agent-card.json`。

Agent Card 含 `securitySchemes`（安全方案 map）与 `security`（安全要求数组）字段声明认证要求，客户端据此在后续 JSON-RPC 请求中携带 `Authorization` 头。

### 1.4 Task 生命周期

A2A 协议是"以 Task 为中心"的协议。一次 `message/send` 调用：

1. 客户端发送 `Message`（消息，含 role 与 parts）到 Agent
2. Agent 创建 `Task`（任务），分配 `taskId`（任务标识）与 `contextId`（上下文标识，用于关联同会话的多 Task）
3. Agent 异步处理，状态在 9 个枚举值间转换（见 §4.1）
4. 客户端通过 `tasks/get` 轮询、`message/stream` 订阅 SSE、或配置 Push Notification webhook 接收更新
5. Task 进入终态（completed/failed/canceled/rejected/unknown）后不再变化

### 1.5 设计目标

- **协议骨架正确**：方法名、Agent Card 路径、Part kind、事件类型必须与 spec v0.2.2+ 严格一致，避免 `-32601 Method not found` 或 404
- **可生成**：每个字段都有 spec 出处，planner 输出的 JSON 字节流可被任何真实 A2A 服务端/客户端互操作
- **可测试**：200+ 测试用例从 spec §5-§9 派生（spec-driven，CLAUDE.md 测试策略规则 1），覆盖正向/负向/边界/异常/并发/状态机/字段映射
- **可扩展**：通过 `metadata`（元数据 map）与 `extensions`（扩展 URI 数组）承载 spec 未定义的附加信息

### 1.6 不变式

1. **传输**：HTTP/1.1 over TCP（默认端口 80/443，可配置）；JSON-RPC 载荷 `Content-Type: application/json`；SSE 载荷 `Content-Type: text/event-stream`
2. **JSON-RPC 版本**：所有请求/响应 `jsonrpc` 字段恒为 `"2.0"`
3. **方法名**：spec v0.2.2+ 共 **7 个 JSON-RPC 核心方法 + 1 个 HTTP GET 扩展卡片端点**（`agent/authenticatedExtendedCard`，非 JSON-RPC，见 §3.1 方法表注）；v0.3.0 新增 2 个 JSON-RPC 方法（list/delete），本设计 v1 实现核心 7 个，list/delete 与扩展卡片端点标注为 v2 路线图（见 §3 方法表注）
4. **Agent Card 路径**：默认 `/.well-known/agent.json`（单数），可通过 `AgentCardPath` 覆盖
5. **Part kind**：仅 `text` / `data` / `file` 三种（spec 任何版本都无 `data-stream`/`file-stream`，v1.1 的 H-6 修订是幻觉，已撤销）
6. **Task 状态**：9 个枚举值（submitted/working/input-required/completed/canceled/failed/rejected/auth-required/unknown），不允许其他值
7. **Task ID 分配**：服务端分配（client 不在 `message/send` 请求 params 中传 `id`）；仅 `tasks/get`/`tasks/cancel`/`tasks/pushNotificationConfig/*`/`tasks/resubscribe` 在 params 中携带已分配的 `taskId`/`id`
8. **流式方法**：`message/stream` 与 `tasks/resubscribe` 走 SSE 路径（`Accept: text/event-stream`，响应 `Content-Type: text/event-stream`）
9. **SSE 事件**：使用**未命名事件**（仅 `data:` 行，无 `event:` 字段），事件类型通过 JSON payload 的 `kind` 字段区分（`task`/`message`/`status-update`/`artifact-update`）。v1.1 固定 `event: update` 是 spec 违规，已撤销
10. **会话关联**：用 `contextId`（非 `sessionId`）关联同会话的多 Task 与 Message
11. **认证字段分离**：AgentCard 用 `securitySchemes`(map) + `security`(array)；PushNotificationConfig.Authentication 用 `PushNotificationAuthenticationInfo`({schemes[], credentials})——两者结构不同，不复用同一 Go 类型

---

## 2. 数据类型与编码

### 2.1 JSON-RPC 2.0 请求

所有 A2A JSON-RPC 请求共享如下结构（spec v0.2.2 §7 通用）：

```json
{
  "jsonrpc": "2.0",
  "method": "message/send",
  "params": { ... },
  "id": "req-001"
}
```

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| jsonrpc | string | 是 | 恒为 `"2.0"` |
| method | string | 是 | 方法名，见 §3 方法表 |
| params | object | 否 | 方法参数（A2A 所有方法均使用 object 类型 params） |
| id | string\|integer | 是（除通知） | JSON-RPC 信封标识，客户端分配；服务端响应原样回填 |

> **注**：A2A 不使用 JSON-RPC 通知（无 id 的请求），所有方法均为请求-响应模式。

### 2.2 JSON-RPC 2.0 响应（同步路径）

```json
{
  "jsonrpc": "2.0",
  "result": { ... },
  "id": "req-001"
}
```

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| jsonrpc | string | 是 | 恒为 `"2.0"` |
| result | object | 是（成功时） | 方法返回值；与 `error` 互斥 |
| error | object | 是（失败时） | `JSONRPCError`，见 §9；与 `result` 互斥 |
| id | string\|integer\|null | 是 | 必须与请求 id 一致；请求 id 无法识别时为 null |

### 2.3 SSE 事件流（流式路径）

`message/stream` 与 `tasks/resubscribe` 的响应是 SSE 流。**使用未命名事件**（仅 `data:` 行，无 `event:` 字段），每个 `data:` 字段含一个完整的 JSON-RPC 2.0 Response 对象（spec 称 `SendStreamingMessageResponse`，是成功与错误的 anyOf 联合：`JSONRPCErrorResponse | SendStreamingMessageSuccessResponse`）。成功响应（`JSONRPCSuccessResponse`）的 `result` 字段为以下 4 种事件类型之一：

- `Task`（`kind:"task"`）
- `Message`（`kind:"message"`）
- `TaskStatusUpdateEvent`（`kind:"status-update"`）
- `TaskArtifactUpdateEvent`（`kind:"artifact-update"`）

SSE 字节格式（spec v0.2.2 §3.3.1）：

```
data: {"jsonrpc":"2.0","id":"req-001","result":{"kind":"task",...}}\n\n
data: {"jsonrpc":"2.0","id":"req-001","result":{"kind":"status-update",...}}\n\n
data: {"jsonrpc":"2.0","id":"req-001","result":{"kind":"artifact-update",...}}\n\n
data: {"jsonrpc":"2.0","id":"req-001","result":{"kind":"status-update","final":true,...}}\n\n
```

| SSE 规则 | 说明 |
|----------|------|
| 事件边界 | 两个 `\n`（空行）分隔事件 |
| 多行 data | 单个事件可拆为多行 `data:`，客户端按 `\n` 拼接；planner 默认单行 |
| 未命名事件 | 无 `event:` 字段；客户端用 `addEventListener("message", ...)` 接收 |
| 成功 data | `JSONRPCSuccessResponse`，result 为 Task/Message/TaskStatusUpdateEvent/TaskArtifactUpdateEvent 之一 |
| 错误 data | `JSONRPCErrorResponse`（error 对象，见 §9.5），流式路径的错误同样经 SSE 投递 |
| 关闭时机 | 服务端发送 `final:true` 的 `TaskStatusUpdateEvent` 后关闭流（典型）；错误事件后同样关闭 |

> **注**：v1.1 固定 `event: update` 是 spec 违规（D-H4），已撤销。spec 用未命名事件 + payload `kind` 字段区分类型。

### 2.4 Agent Card（GET /.well-known/agent.json）

```http
GET /.well-known/agent.json HTTP/1.1
Host: agent.example.com
Accept: application/json
```

```http
HTTP/1.1 200 OK
Content-Type: application/json
Content-Length: 501

{
  "name": "example-agent",
  "description": "An example A2A agent",
  "url": "https://agent.example.com/a2a",
  "version": "1.0.0",
  "protocolVersion": "0.3.0",
  "capabilities": {
    "streaming": true,
    "pushNotifications": true,
    "stateTransitionHistory": true
  },
  "skills": [
    {"id":"skill-1","name":"greeting","description":"Greets users","tags":["chat"]}
  ],
  "securitySchemes": {
    "bearerAuth": {"type":"http","scheme":"bearer","bearerFormat":"JWT"}
  },
  "security": [{"bearerAuth":[]}],
  "defaultInputModes": ["text"],
  "defaultOutputModes": ["text"]
}
```

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| name | string | 是 | Agent 人类可读名称 |
| description | string | 是 | Agent 描述（CommonMark 可选） |
| url | string | 是 | A2A 服务基础 URL（绝对，HTTPS 推荐） |
| version | string | 是 | Agent 或 A2A 实现版本 |
| protocolVersion | string | 是 | 协议版本（v0.2.5+ 必填，如 `"0.3.0"`） |
| provider | AgentProvider | 否 | 服务方信息 {organization, url} |
| iconUrl | string | 否 | Agent 图标 URL |
| documentationUrl | string | 否 | 文档 URL |
| capabilities | AgentCapabilities | 是 | 能力声明，见下表 |
| securitySchemes | map[string,SecurityScheme] | 否 | 安全方案定义（OpenAPI 风格） |
| security | array[map[string,string[]]] | 否 | 安全要求（哪些方案必选） |
| defaultInputModes | string[] | 是 | 默认输入 MIME 类型 |
| defaultOutputModes | string[] | 是 | 默认输出 MIME 类型 |
| skills | AgentSkill[] | 是 | 技能数组（action 类 Agent 至少 1 个） |
| supportsAuthenticatedExtendedCard | boolean | 否 | 是否支持认证后扩展 Card |
| additionalInterfaces | AgentInterface[] | 否 | 额外接口（v0.2.5+，每项 {url 必填, transport 必填}，如 `{"url":".../a2a","transport":"JSONRPC"}`） |
| preferredTransport | string | 否 | 首选传输（v0.2.5+，schema 示例为 `"JSONRPC"`/`"GRPC"`/`"HTTP+JSON"`，默认 `"JSONRPC"`） |
| signatures | AgentCardSignature[] | 否 | Agent Card JWS 签名（v0.3.0，RFC 7515/8785，本设计 v1 不实现，保留字段） |

> **注**：v1.1 用 `authentication:{schemes:[]}` 是 spec 违规（D-H2），已撤销。spec 用 OpenAPI 风格的 `securitySchemes` map + `security` 数组。

**AgentCapabilities**：

| 字段 | 类型 | 必填 | 默认 | 说明 |
|------|------|------|------|------|
| streaming | boolean | 否 | false | 是否支持 SSE 流式方法 |
| pushNotifications | boolean | 否 | false | 是否支持 Push Notification |
| stateTransitionHistory | boolean | 否 | false | 是否支持状态转换历史 |
| extensions | AgentExtension[] | 否 | [] | 扩展列表 |

**AgentSkill**：

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| id | string | 是 | 技能唯一标识 |
| name | string | 是 | 技能名称 |
| description | string | 是 | 技能描述 |
| tags | string[] | 是 | 标签（用于发现） |
| examples | string[] | 否 | 示例提示 |
| inputModes | string[] | 否 | 覆盖 defaultInputModes |
| outputModes | string[] | 否 | 覆盖 defaultOutputModes |

**SecurityScheme**（anyOf，OpenAPI 风格）：

| 子类型 | type 常量 | 必填字段 |
|--------|----------|----------|
| APIKeySecurityScheme | `apiKey` | in(cookie/header/query), name |
| HTTPAuthSecurityScheme | `http` | scheme(如 bearer/basic)；可选 bearerFormat |
| OAuth2SecurityScheme | `oauth2` | flows（含 authorizationCode/clientCredentials/implicit/password） |
| OpenIdConnectSecurityScheme | `openIdConnect` | openIdConnectUrl |
| MutualTLSSecurityScheme | `mutualTLS` | 必填 type（const=`mutualTLS`，v0.3.0 新增；本设计 v1 不实现，Validate 接受但 planner 不生成） |

> **注**：spec v0.3.0 `SecurityScheme.anyOf` 共 **5** 种子类型（含 MutualTLSSecurityScheme）。本设计 §5.2 的 `A2ASecurityScheme` 为 `map[string]any`，可承载全部子类型，不会拒绝 mutualTLS 配置。

### 2.5 Task 对象

```json
{
  "id": "task-001",
  "contextId": "ctx-abc",
  "status": {"state":"completed","timestamp":"2026-08-05T10:00:00Z"},
  "artifacts": [
    {"artifactId":"art-1","name":"report","parts":[{"kind":"text","text":"result"}]}
  ],
  "history": [
    {"role":"user","parts":[{"kind":"text","text":"hello"}],"messageId":"m1","kind":"message"}
  ],
  "kind": "task",
  "metadata": {"client":"trafficgen"}
}
```

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| id | string | 是 | 服务端分配的任务标识 |
| contextId | string | 是 | 服务端分配的上下文标识（关联同会话多 Task） |
| status | TaskStatus | 是 | 当前状态 {state, message?, timestamp?} |
| artifacts | Artifact[] | 否 | 产出数组 |
| history | Message[] | 否 | 历史消息（按 historyLength 返回） |
| kind | string | 是 | 恒为 `"task"` |
| metadata | object | 否 | 附加元数据 |

> **注**：v1.1 用 `sessionId` 是 spec 违规（D-L3），已撤销。spec 用 `contextId`。

**TaskStatus**：

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| state | TaskState | 是 | 9 个枚举值之一，见 §4.1 |
| message | Message | 否 | 状态附加上下文消息 |
| timestamp | string | 否 | ISO 8601 UTC 时间戳 |

**Artifact**：

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| artifactId | string | 是 | 产出标识 |
| name | string | 否 | 显示名 |
| description | string | 否 | 描述 |
| parts | Part[] | 是 | 产出内容（至少 1 个） |
| extensions | string[] | 否 | 扩展 URI |
| metadata | object | 否 | 附加元数据 |

### 2.6 Message 与 Part

**Message**：

```json
{
  "role": "user",
  "parts": [{"kind":"text","text":"hello"}],
  "messageId": "m-001",
  "contextId": "ctx-abc",
  "taskId": "task-001",
  "kind": "message",
  "metadata": {"seq":1}
}
```

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| role | string | 是 | `"user"` 或 `"agent"` |
| parts | Part[] | 是 | 内容数组（至少 1 个） |
| messageId | string | 是 | 消息标识（发送方分配） |
| taskId | string | 否 | 关联的任务标识 |
| contextId | string | 否 | 关联的上下文标识 |
| referenceTaskIds | string[] | 否 | 引用的其他任务标识 |
| extensions | string[] | 否 | 扩展 URI |
| kind | string | 是 | 恒为 `"message"` |
| metadata | object | 否 | 附加元数据 |

**Part**（anyOf，3 种 kind，spec 任何版本都无 `data-stream`/`file-stream`）：

| kind | 类型 | 必填字段 | 说明 |
|------|------|----------|------|
| `text` | TextPart | text | 文本内容 |
| `data` | DataPart | data | 结构化 JSON 数据 |
| `file` | FilePart | file | 文件（FileWithBytes 或 FileWithUri） |

**TextPart**：
```json
{"kind":"text","text":"hello","metadata":{}}
```

**DataPart**：
```json
{"kind":"data","data":{"key":"value"},"metadata":{}}
```

**FilePart**（FileWithBytes）：
```json
{"kind":"file","file":{"name":"a.txt","mimeType":"text/plain","bytes":"aGVsbG8="},"metadata":{}}
```

**FilePart**（FileWithUri）：
```json
{"kind":"file","file":{"name":"img.png","mimeType":"image/png","uri":"https://example.com/img.png"},"metadata":{}}
```

| FileWithBytes 字段 | 类型 | 必填 | 说明 |
|--------------------|------|------|------|
| name | string | 否 | 文件名 |
| mimeType | string | 否 | MIME 类型（强烈推荐） |
| bytes | string | 是 | base64 编码内容 |

| FileWithUri 字段 | 类型 | 必填 | 说明 |
|------------------|------|------|------|
| name | string | 否 | 文件名 |
| mimeType | string | 否 | MIME 类型 |
| uri | string | 是 | 文件 URL |

> **注**：v1.1 声称 spec 0.3 引入 `data-stream`/`file-stream` 是伪造引用（D-C5），spec 任何版本都只有上述 3 种 kind。spec 的流式语义在 `TaskStatusUpdateEvent`/`TaskArtifactUpdateEvent` 两个独立事件类型上，不在 Part 层。

### 2.7 TaskStatusUpdateEvent（SSE 中间事件）

```json
{
  "taskId": "task-001",
  "contextId": "ctx-abc",
  "kind": "status-update",
  "status": {"state":"working","timestamp":"2026-08-05T10:00:01Z"},
  "final": false,
  "metadata": {}
}
```

| 字段 | 类型 | 必填 | 默认 | 说明 |
|------|------|------|------|------|
| taskId | string | 是 | | 任务标识 |
| contextId | string | 是 | | 上下文标识 |
| kind | string | 是 | | 恒为 `"status-update"` |
| status | TaskStatus | 是 | | 新状态 |
| final | boolean | 是（spec required） | | true 表示当前流周期的最后事件，服务端通常随后关闭 SSE；**false 时也必须显式输出该字段**（spec `TaskStatusUpdateEvent.required` = [contextId, final, kind, status, taskId]，缺字段无法通过真实 A2A 客户端/服务端校验） |
| metadata | object | 否 | | 事件元数据 |

> **注**：v1.1 在此类型中塞入 `artifact` 字段是 spec 违规（D-H3），已撤销。artifact 在独立的 `TaskArtifactUpdateEvent` 中。

### 2.8 TaskArtifactUpdateEvent（SSE 中间事件）

```json
{
  "taskId": "task-001",
  "contextId": "ctx-abc",
  "kind": "artifact-update",
  "artifact": {
    "artifactId": "art-1",
    "name": "report",
    "parts": [{"kind":"text","text":"# Section 1\n\n"}]
  },
  "append": false,
  "lastChunk": false,
  "metadata": {}
}
```

| 字段 | 类型 | 必填 | 默认 | 说明 |
|------|------|------|------|------|
| taskId | string | 是 | | 任务标识 |
| contextId | string | 是 | | 上下文标识 |
| kind | string | 是 | | 恒为 `"artifact-update"` |
| artifact | Artifact | 是 | | 产出（完整或增量块） |
| append | boolean | 否 | false | true=追加 parts 到已有 artifact；false=替换 |
| lastChunk | boolean | 否 | false | true=该 artifact 的最后一块 |
| metadata | object | 否 | | 事件元数据 |

> **注**：v1.1 完全遗漏此事件类型（D-H3），已新增。

### 2.9 PushNotificationConfig

```json
{
  "url": "https://client.example.com/webhook/a2a",
  "id": "pnc-001",
  "token": "client-opaque-token",
  "authentication": {
    "schemes": ["Bearer"],
    "credentials": "secret-credentials"
  }
}
```

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| url | string | 是 | 客户端 webhook URL（建议 HTTPS，spec 为 SHOULD 建议而非 MUST，见 V15） |
| id | string | 否 | v0.2.2 由服务端创建（"created by server"）；**v0.3.0 起由客户端设置**（"set by the client to support multiple notification callbacks"，支持多回调时客户端可在请求中指定） |
| token | string | 否 | 客户端生成的 opaque token（服务端在 `X-A2A-Notification-Token` 头回填） |
| authentication | PushNotificationAuthenticationInfo | 否 | 服务端调用 webhook 时使用的认证 |

**PushNotificationAuthenticationInfo**：

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| schemes | string[] | 是 | 认证方案名（如 `"Bearer"`/`"Basic"`/`"ApiKey"`，spec 示例用首字母大写） |
| credentials | string | 否 | 静态凭证或方案特定配置（涉密时谨慎处理） |

> **注**：v1.1 用 `userId` 字段是幻觉（D-H1），spec 实际字段是 `id`。`id` 语义随版本变化：v0.2.2 为服务端创建，v0.3.0 起为客户端设置（请求中可携带，用于多回调）。v1.1 强制 schemes 小写是错误约束（D-M4），spec 示例用大写 `"Bearer"`。

### 2.10 长度字段约束

| 字段 | 类型 | 约束 |
|------|------|------|
| JSON-RPC id | string\|integer | string 时 ≤ 128 字节；integer 时 ≥ 0 |
| taskId / contextId / messageId | string | 1-128 字节，UTF-8 |
| AgentCard.name / version | string | 1-128 字节 |
| AgentCard.description | string | 0-4096 字节 |
| Part.text | string | 0-1MB |
| FileWithBytes.bytes | string (base64) | 解码后 ≤ 10MB（planner 默认） |
| metadata key/value | string/any | key ≤ 128 字节，value 序列化后 ≤ 64KB |
| skills 数组 | array | 0-1024 个 |
| parts 数组 | array | 1-1024 个 |
| history 数组 | array | 0-1000 个（按 historyLength 截断） |

---

## 3. 消息结构

### 3.1 方法表（spec v0.2.2+ 核心方法）

| 方法 | 路径 | params 必填 | result 类型 | 说明 |
|------|------|-------------|-------------|------|
| `message/send` | POST {url} | message | Task \| Message | 发送消息（同步），发起或继续交互 |
| `message/stream` | POST {url} | message | SSE 流（Task\|Message\|TaskStatusUpdateEvent\|TaskArtifactUpdateEvent） | 发送消息并订阅 SSE 流（需 capabilities.streaming=true） |
| `tasks/get` | POST {url} | id | Task | 查询任务当前状态 |
| `tasks/cancel` | POST {url} | id | Task | 取消任务（仅非终态可取消） |
| `tasks/resubscribe` | POST {url} | id | SSE 流 | 断线重连已有任务的 SSE 流（需 streaming=true） |
| `tasks/pushNotificationConfig/set` | POST {url} | taskId, pushNotificationConfig | TaskPushNotificationConfig | 设置推送通知配置（需 pushNotifications=true） |
| `tasks/pushNotificationConfig/get` | POST {url} | id | TaskPushNotificationConfig | 查询推送通知配置（需 pushNotifications=true） |

**v0.2.x HTTP 端点（非 JSON-RPC 方法）**：

| 端点 | 方法 | 说明 |
|------|------|------|
| `agent/authenticatedExtendedCard` | HTTP GET（URL 为 `{AgentCard.url}/../agent/authenticatedExtendedCard`） | 获取认证后的扩展 Agent Card（spec v0.2.2 §7.8、v0.2.5 §7.10、v0.3.0 均保留；需 `supportsAuthenticatedExtendedCard: true`，错误语义 401/403/404）。本设计 v1 不生成，标注 v2 路线图（v0.3.0 另有 JSON-RPC 方法 `agent/getAuthenticatedExtendedCard`，-32007，同标 v2 路线图） |

**spec v0.3.0 新增方法（本设计 v1 不实现，v2 路线图）**：

| 方法 | 说明 |
|------|------|
| `tasks/pushNotificationConfig/list` | 列出任务的所有推送配置 |
| `tasks/pushNotificationConfig/delete` | 删除推送配置 |
| `agent/getAuthenticatedExtendedCard` | 获取认证后的扩展 Agent Card（JSON-RPC 方法，-32007） |

> **注**：v0.2.x 除 7 个 JSON-RPC 核心方法外，还有 HTTP GET 端点 `agent/authenticatedExtendedCard`（非 JSON-RPC 方法，v2 路线图）；v1.1 把 `message/send` 写成 `tasks/send`、`message/stream` 写成 `tasks/sendSubscribe`、`tasks/pushNotificationConfig/set` 写成 `tasks/pushNotification/set`、凭空发明 `tasks/subscribe` 全是 spec 违规（D-C1/D-C2/D-C3），已全部修正。

### 3.2 各方法请求/响应格式

#### 3.2.1 message/send

**请求**：
```json
{
  "jsonrpc": "2.0",
  "method": "message/send",
  "params": {
    "message": {
      "role": "user",
      "parts": [{"kind":"text","text":"hello"}],
      "messageId": "m-001",
      "contextId": "ctx-abc"
    },
    "configuration": {
      "acceptedOutputModes": ["text"],
      "blocking": true,
      "historyLength": 10
    },
    "metadata": {}
  },
  "id": "req-001"
}
```

| params 字段 | 类型 | 必填 | 说明 |
|-------------|------|------|------|
| message | Message | 是 | 消息内容（role 通常为 user） |
| configuration | MessageSendConfiguration | 否 | 配置 |
| metadata | object | 否 | 请求元数据 |

**MessageSendConfiguration**：

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| acceptedOutputModes | string[] | 是 | 接受的输出 MIME 类型 |
| blocking | boolean | 否 | 是否阻塞（默认 true） |
| historyLength | integer | 否 | 返回历史消息数 |
| pushNotificationConfig | PushNotificationConfig | 否 | 内联推送配置 |

> **注**：v1.1 在 params 中携带 `id`（task id）是 spec 违规（D-M7/D-M8），`message/send` 请求不带 task id（task id 由服务端分配）。

**响应（成功）**：result 为 `Task` 或 `Message`（简单交互直接返回 Message，无 Task 跟踪）。

#### 3.2.2 message/stream

**请求**：params 同 `message/send`。

**响应**：HTTP 200，`Content-Type: text/event-stream`，SSE 流。每个 `data:` 含一个完整的 JSON-RPC Response（`SendStreamingMessageResponse`：成功 `JSONRPCSuccessResponse` 或错误 `JSONRPCErrorResponse`），成功时 result 为 4 种事件类型之一。

#### 3.2.3 tasks/get

**请求**：
```json
{
  "jsonrpc": "2.0",
  "method": "tasks/get",
  "params": {"id":"task-001","historyLength":10},
  "id": "req-002"
}
```

| params 字段 | 类型 | 必填 | 说明 |
|-------------|------|------|------|
| id | string | 是 | 任务标识（服务端分配的 taskId） |
| historyLength | integer | 否 | 返回历史消息数 |
| metadata | object | 否 | 请求元数据 |

**响应（成功）**：result 为 `Task`。

#### 3.2.4 tasks/cancel

**请求**：
```json
{
  "jsonrpc": "2.0",
  "method": "tasks/cancel",
  "params": {"id":"task-001"},
  "id": "req-003"
}
```

| params 字段 | 类型 | 必填 | 说明 |
|-------------|------|------|------|
| id | string | 是 | 任务标识 |
| metadata | object | 否 | 请求元数据 |

**响应（成功）**：result 为 `Task`（取消后状态，理想为 `canceled`）。

#### 3.2.5 tasks/resubscribe

**请求**：params 同 `tasks/cancel`（仅 `id`）。

**响应**：HTTP 200，`Content-Type: text/event-stream`，SSE 流（同 `message/stream` 格式，携带断线后的后续事件）。

#### 3.2.6 tasks/pushNotificationConfig/set

**请求**：
```json
{
  "jsonrpc": "2.0",
  "method": "tasks/pushNotificationConfig/set",
  "params": {
    "taskId": "task-001",
    "pushNotificationConfig": {
      "url": "https://client.example.com/webhook",
      "token": "tok-abc",
      "authentication": {"schemes":["Bearer"],"credentials":"sec"}
    }
  },
  "id": "req-004"
}
```

| params 字段 | 类型 | 必填 | 说明 |
|-------------|------|------|------|
| taskId | string | 是 | 任务标识 |
| pushNotificationConfig | PushNotificationConfig | 是 | 推送配置 |
| metadata | object | 否 | 请求元数据 |

**响应（成功）**：result 为 `TaskPushNotificationConfig`（服务端可能省略/掩盖敏感字段）。

#### 3.2.7 tasks/pushNotificationConfig/get

**请求**：params 同 `tasks/cancel`（仅 `id`，v0.3.0+ 可选 `pushNotificationConfigId`）。

**响应（成功）**：result 为 `TaskPushNotificationConfig`。

### 3.3 通用字段表

| 字段 | 出现位置 | 类型 | 说明 |
|------|----------|------|------|
| jsonrpc | 所有请求/响应 | string | 恒 `"2.0"` |
| method | 请求 | string | 见 §3.1 |
| params | 请求 | object | 方法参数 |
| id | 请求/响应 | string\|integer | JSON-RPC 信封标识 |
| result | 成功响应 | object | 方法返回值 |
| error | 失败响应 | object | JSONRPCError |
| kind | Task/Message/事件 | string | 类型判别符 |
| role | Message | string | user/agent |
| parts | Message/Artifact | Part[] | 内容数组 |
| state | TaskStatus | string | 9 个枚举值 |
| taskId | 事件/Message | string | 任务标识 |
| contextId | Task/Message/事件 | string | 上下文标识 |
| messageId | Message | string | 消息标识 |
| final | TaskStatusUpdateEvent | boolean | 是否最后事件 |
| append/lastChunk | TaskArtifactUpdateEvent | boolean | artifact 增量控制 |

### 3.4 错误码表（JSON-RPC error.code）

| code | 错误名 | 说明 |
|------|--------|------|
| -32700 | JSONParseError | JSON 解析失败 |
| -32600 | InvalidRequestError | 无效 JSON-RPC 请求 |
| -32601 | MethodNotFoundError | 方法不存在或不支持 |
| -32602 | InvalidParamsError | 参数无效（类型错/缺必填） |
| -32603 | InternalError | 服务端内部错误 |
| -32001 | TaskNotFoundError | 任务不存在/过期/已清理 |
| -32002 | TaskNotCancelableError | 任务不可取消（已终态） |
| -32003 | PushNotificationNotSupportedError | 不支持推送通知（capabilities.pushNotifications=false） |
| -32004 | UnsupportedOperationError | 操作不支持（含 streaming/pushNotification/list 等场景，spec 通用"不支持"错误） |
| -32005 | ContentTypeNotSupportedError | 内容类型不支持 |
| -32006 | InvalidAgentResponseError | Agent 响应类型无效（v0.3.0+） |
| -32007 | AuthenticatedExtendedCardNotConfiguredError | 扩展 Agent Card 未配置（v0.3.0+，本设计 v1 不实现） |

> **注**：v1.1 把 -32004 固定为"Streaming not supported"是窄化 spec 语义（D-H6），-32004 是通用"操作不支持"。v1.1 遗漏 -32006/-32007，已新增。

---

## 4. 状态机

### 4.1 Task 状态枚举（9 个，spec v0.2.2+）

| 状态 | 说明 | 是否终态 |
|------|------|----------|
| `submitted` | 任务已接收，处理尚未开始 | 否 |
| `working` | 任务正在处理 | 否 |
| `input-required` | 需客户端补充输入（暂停） | 否（暂停态） |
| `auth-required` | 需客户端补充认证（暂停） | 否（暂停态） |
| `completed` | 成功完成 | 是 |
| `canceled` | 已取消 | 是 |
| `failed` | 处理失败 | 是 |
| `rejected` | Agent 拒绝执行 | 是 |
| `unknown` | 状态无法确定（taskId 无效/过期） | 是 |

> **注**：v1.1 遗漏 `rejected`/`auth-required`（D-H5），已新增。spec v0.2.2+ 共 9 个状态。

### 4.2 合法状态转换

| 起点 → 终点 | 说明 |
|-------------|------|
| submitted → working | 处理开始 |
| submitted → canceled | 提交后立即取消 |
| submitted → failed | 提交后立即失败 |
| submitted → rejected | Agent 拒绝执行 |
| submitted → auth-required | 需认证才能开始 |
| working → completed | 成功完成 |
| working → failed | 处理失败 |
| working → canceled | 处理中取消 |
| working → input-required | 需补充输入 |
| working → auth-required | 处理中需认证 |
| input-required → working | 客户端补充输入后恢复 |
| input-required → canceled | 等待输入时取消 |
| input-required → failed | 等待输入时失败 |
| auth-required → working | 客户端补充认证后恢复 |
| auth-required → canceled | 等待认证时取消 |
| auth-required → failed | 等待认证时失败 |
| (终态) → (任意) | 不允许（终态不可变） |
| (任意非终态) → unknown | 异常：taskId 过期/失效 |

**禁止的转换**（Validate 拒绝）：
- `input-required → completed`：spec 未定义此路径，Validate 拒绝（v1.1 标"罕见保留"是 spec 违规 D-M3，已改为拒绝）
- `completed → *` / `canceled → *` / `failed → *` / `rejected → *`：终态不可变
- `unknown → *`：unknown 是终态

### 4.3 流式响应状态机

`message/stream` 的 SSE 流典型模式：

1. 首事件：`Task`（`kind:"task"`，state=submitted 或 working）
2. 中间事件 0 个或多个：`TaskStatusUpdateEvent`（kind=status-update）与 `TaskArtifactUpdateEvent`（kind=artifact-update）交替
3. 末事件：`TaskStatusUpdateEvent`（`final:true`，state=终态）

两种流模式（spec v0.2.2 §3.3.2）：
- **Message-only 流**：仅 1 个 Message 事件，立即关闭（简单交互无 Task 跟踪）
- **Task 生命周期流**：Task → 0+ 事件 → final status-update

事件必须按生成顺序投递，不可重排序（spec v0.2.2 §3.3.2）。

### 4.4 stateTransitionHistory

`capabilities.stateTransitionHistory=true` 时，`tasks/get` 响应的 `Task.history` 可包含状态转换记录。planner 在历史数组中按时间序追加 `TaskStatusUpdateEvent` 对应的 Message（state 字段变化）。

---

## 5. 配置类型定义

### 5.1 A2AConfig（顶层）

```go
// A2AConfig 描述一组 A2A 流量生成配置（一个 Agent Card + 多 Task）。
type A2AConfig struct {
    BaseURL        string                `json:"baseUrl"`        // Agent 的 A2A 服务 URL（AgentCard.url），如 https://agent.example.com/a2a
    AgentCardPath  string                `json:"agentCardPath"`  // Agent Card 路径，默认 /.well-known/agent.json
    Discover       bool                  `json:"discover"`       // 是否在首包前发 GET Agent Card
    AgentCard      *A2AAgentCard         `json:"agentCard"`      // Agent Card 内容（Discover=true 时用作响应 body）
    Tasks          []A2ATask             `json:"tasks"`          // 任务数组（按序在同 TCP 连接上串行）
    Auth           A2AAuth               `json:"auth"`           // 认证配置
    HTTP           A2AHTTP               `json:"http"`           // HTTP 层配置
    TCP            A2ATCP                `json:"tcp"`            // TCP 层配置
    FlowControl    *A2AFlowControl       `json:"flowControl"`    // 流控
}

type A2AAuth struct {
    Scheme      string `json:"scheme"`      // none/bearer/basic/apikey/oauth2/openIdConnect，默认 none
    Token       string `json:"token"`       // bearer/oauth2 的 token
    Username    string `json:"username"`    // basic 的用户名
    Password    string `json:"password"`    // basic 的密码
    APIKey      string `json:"apiKey"`      // apikey 的值
    APIKeyName  string `json:"apiKeyName"`  // apikey 的头/查询参数名，默认 X-API-Key
    APIKeyIn    string `json:"apiKeyIn"`    // header/query/cookie，默认 header
}

type A2AHTTP struct {
    Version          string `json:"version"`          // HTTP/1.1（默认）
    UserAgent        string `json:"userAgent"`        // 默认 trafficgen-a2a/2.0
    Accept           string `json:"accept"`           // 默认 application/json, text/event-stream
    Connection       string `json:"connection"`       // keep-alive/close
    ExtraHeaders     map[string]string `json:"extraHeaders"`
}

type A2ATCP struct {
    Handshake    bool `json:"handshake"`    // TCP 三次握手，默认 true
    Termination  bool `json:"termination"`  // TCP 四次挥手，默认 true
    InitialSeq   uint32 `json:"initialSeq"` // ISN，0 时随机
    MSS          uint16 `json:"mss"`        // 默认 1460
    ACKPolicy    string `json:"ackPolicy"`  // lazy/immediate，默认 immediate
}

type A2AFlowControl struct {
    BPS         string `json:"bps"`         // 比特率上限
    Concurrent  int    `json:"concurrent"`  // 并发 Task 数
}
```

### 5.2 A2AAgentCard

```go
// A2AAgentCard 对应 spec AgentCard（v0.2.2+）。
type A2AAgentCard struct {
    Name                             string                   `json:"name"`                             // 必填
    Description                      string                   `json:"description"`                      // 必填
    URL                              string                   `json:"url"`                              // 必填
    Version                          string                   `json:"version"`                          // 必填
    ProtocolVersion                  string                   `json:"protocolVersion"`                  // 必填（v0.2.5+），默认 "0.3.0"
    Provider                         *A2AAgentProvider        `json:"provider,omitempty"`
    IconURL                          string                   `json:"iconUrl,omitempty"`
    DocumentationURL                 string                   `json:"documentationUrl,omitempty"`
    Capabilities                     *A2AAgentCapabilities    `json:"capabilities"`                     // 必填
    SecuritySchemes                  map[string]A2ASecurityScheme `json:"securitySchemes,omitempty"`     // OpenAPI 风格 map
    Security                         []map[string][]string    `json:"security,omitempty"`               // 安全要求数组
    DefaultInputModes                []string                 `json:"defaultInputModes"`                // 必填
    DefaultOutputModes               []string                 `json:"defaultOutputModes"`               // 必填
    Skills                           []A2AAgentSkill          `json:"skills"`                           // 必填（action 类至少 1 个）
    SupportsAuthenticatedExtendedCard bool                    `json:"supportsAuthenticatedExtendedCard,omitempty"`
    AdditionalInterfaces             []A2AAgentInterface      `json:"additionalInterfaces,omitempty"`   // v0.2.5+
    PreferredTransport               string                   `json:"preferredTransport,omitempty"`     // v0.2.5+
    Signatures                       []A2AAgentCardSignature  `json:"signatures,omitempty"`            // v0.3.0，本设计 v1 不实现，保留字段
}

type A2AAgentInterface struct {
    URL       string `json:"url"`       // 必填
    Transport string `json:"transport"` // 必填
}

// A2AAgentCardSignature 对应 spec AgentCardSignature（v0.3.0，JWS 签名）。本设计 v1 不实现。
type A2AAgentCardSignature map[string]any

type A2AAgentProvider struct {
    Organization string `json:"organization"` // 必填
    URL          string `json:"url"`          // 必填
}

type A2AAgentCapabilities struct {
    Streaming                bool                `json:"streaming"`
    PushNotifications        bool                `json:"pushNotifications"`
    StateTransitionHistory   bool                `json:"stateTransitionHistory"`
    Extensions               []A2AAgentExtension `json:"extensions,omitempty"`
}

type A2AAgentExtension struct {
    URI         string         `json:"uri"`         // 必填
    Required    bool           `json:"required,omitempty"`
    Description string         `json:"description,omitempty"`
    Params      map[string]any `json:"params,omitempty"`
}

type A2AAgentSkill struct {
    ID          string   `json:"id"`          // 必填
    Name        string   `json:"name"`        // 必填
    Description string   `json:"description"` // 必填
    Tags        []string `json:"tags"`        // 必填
    Examples    []string `json:"examples,omitempty"`
    InputModes  []string `json:"inputModes,omitempty"`
    OutputModes []string `json:"outputModes,omitempty"`
}

// A2ASecurityScheme 对应 spec SecurityScheme（v0.3.0 anyOf 5 种）。用 map[string]any 占位以兼容所有子类型。
// 子类型判别：type 字段 ∈ {apiKey, http, oauth2, openIdConnect, mutualTLS}。
type A2ASecurityScheme map[string]any
```

> **注**：v1.1 用 `Authentication *A2AAuthentication` 是 spec 违规（D-H2/D-M5），已改为 spec 的 `SecuritySchemes map + Security array`。

### 5.3 A2ATask（单任务）

```go
// A2ATask 描述一次 A2A 任务的请求与响应配置。
type A2ATask struct {
    Method              string                      `json:"method"`              // 见 §3.1 方法表，默认 message/send
    RequestID           jsonutil.ID                 `json:"requestId"`           // JSON-RPC 信封 id（客户端分配）
    Message             A2AMessage                  `json:"message"`             // message/send 与 message/stream 的 params.message
    Configuration       *A2AMessageSendConfiguration `json:"configuration,omitempty"`
    ParamsMetadata      map[string]any              `json:"paramsMetadata,omitempty"`

    // tasks/get / tasks/cancel / tasks/resubscribe / tasks/pushNotificationConfig/* 的 params.id/taskId
    // 在 message/send 请求中不携带（task id 由服务端分配）。
    TaskID              string                      `json:"taskId,omitempty"`
    HistoryLength       int                         `json:"historyLength,omitempty"`

    // PushNotification 配置（tasks/pushNotificationConfig/set 用）
    PushNotificationConfig *A2APushNotificationConfig `json:"pushNotificationConfig,omitempty"`

    // 响应配置
    Response            A2ATaskResponse             `json:"response"`
    Streaming           bool                        `json:"streaming"`           // true=message/stream 或 tasks/resubscribe，false=同步方法（message/send/tasks/get/tasks/cancel/tasks/pushNotificationConfig/*）
    SSEEvents           []A2ASSEEvent               `json:"sseEvents,omitempty"` // 流式响应的事件序列
}

type A2AMessageSendConfiguration struct {
    AcceptedOutputModes   []string                 `json:"acceptedOutputModes"`
    Blocking              *bool                    `json:"blocking,omitempty"`
    HistoryLength         *int                     `json:"historyLength,omitempty"`
    PushNotificationConfig *A2APushNotificationConfig `json:"pushNotificationConfig,omitempty"`
}

// A2ATaskResponse 描述服务端响应（planner 据此生成下行包）。
type A2ATaskResponse struct {
    Result      json.RawMessage            `json:"result"`      // 序列化后的 Task/Message/TaskPushNotificationConfig
    Error       *A2AError                  `json:"error,omitempty"`
    StatusCode  int                        `json:"statusCode"`  // HTTP 状态码，默认 200
}

type A2AError struct {
    Code    int    `json:"code"`
    Message string `json:"message"`
    Data    any    `json:"data,omitempty"`
}
```

### 5.4 A2AMessage / A2APart

```go
type A2AMessage struct {
    Role             string           `json:"role"`             // user/agent
    Parts            []A2APart        `json:"parts"`
    MessageID        string           `json:"messageId"`
    TaskID           string           `json:"taskId,omitempty"`
    ContextID        string           `json:"contextId,omitempty"`
    ReferenceTaskIDs []string         `json:"referenceTaskIds,omitempty"`
    Extensions       []string         `json:"extensions,omitempty"`
    Kind             string           `json:"kind"`             // 恒 "message"
    Metadata         map[string]any   `json:"metadata,omitempty"`
}

// A2APart 是 oneof 联合类型。Kind 决定哪个 content 字段有效（见 §8 规则 4 互斥校验）。
type A2APart struct {
    Kind     string         `json:"kind"`               // text/data/file（仅此 3 种）
    Text     string         `json:"text,omitempty"`     // Kind=text 时有效
    Data     map[string]any `json:"data,omitempty"`     // Kind=data 时有效
    File     *A2AFile       `json:"file,omitempty"`     // Kind=file 时有效
    Metadata map[string]any `json:"metadata,omitempty"`
}

type A2AFile struct {
    Name     string `json:"name,omitempty"`
    MimeType string `json:"mimeType,omitempty"`
    Bytes    string `json:"bytes,omitempty"` // base64，FileWithBytes 时有效
    URI      string `json:"uri,omitempty"`   // FileWithUri 时有效
}
```

> **注**：v1.1 的 `A2AFilePart`/`BytesB64` 命名不一致（D-M2），已统一为 `A2AFile` 含 `Bytes`/`URI`。

### 5.5 A2ASSEEvent（流式事件）

```go
// A2ASSEEvent 描述一个 SSE 事件（data: 行的 JSON payload）。
type A2ASSEEvent struct {
    Kind string `json:"kind"` // task/message/status-update/artifact-update
    // Kind=task 时填 Task
    Task *A2ATaskObject `json:"task,omitempty"`
    // Kind=message 时填 Message
    Message *A2AMessage `json:"message,omitempty"`
    // Kind=status-update 时填 StatusUpdate
    StatusUpdate *A2ATaskStatusUpdateEvent `json:"statusUpdate,omitempty"`
    // Kind=artifact-update 时填 ArtifactUpdate
    ArtifactUpdate *A2ATaskArtifactUpdateEvent `json:"artifactUpdate,omitempty"`
}

type A2ATaskObject struct {
    ID        string         `json:"id"`
    ContextID string         `json:"contextId"`
    Status    A2ATaskStatus  `json:"status"`
    Artifacts []A2AArtifact  `json:"artifacts,omitempty"`
    History   []A2AMessage   `json:"history,omitempty"`
    Kind      string         `json:"kind"` // 恒 "task"
    Metadata  map[string]any `json:"metadata,omitempty"`
}

type A2ATaskStatus struct {
    State     string       `json:"state"` // 9 个枚举值
    Message   *A2AMessage  `json:"message,omitempty"`
    Timestamp string       `json:"timestamp,omitempty"`
}

type A2AArtifact struct {
    ArtifactID string         `json:"artifactId"`
    Name       string         `json:"name,omitempty"`
    Description string       `json:"description,omitempty"`
    Parts      []A2APart     `json:"parts"`
    Extensions []string       `json:"extensions,omitempty"`
    Metadata   map[string]any `json:"metadata,omitempty"`
}

type A2ATaskStatusUpdateEvent struct {
    TaskID    string         `json:"taskId"`
    ContextID string         `json:"contextId"`
    Kind      string         `json:"kind"` // 恒 "status-update"
    Status    A2ATaskStatus  `json:"status"`
    Final     bool           `json:"final"` // 必填（spec required），false 时也必须输出，禁用 omitempty
    Metadata  map[string]any `json:"metadata,omitempty"`
}

type A2ATaskArtifactUpdateEvent struct {
    TaskID    string         `json:"taskId"`
    ContextID string         `json:"contextId"`
    Kind      string         `json:"kind"` // 恒 "artifact-update"
    Artifact  A2AArtifact    `json:"artifact"`
    Append    bool           `json:"append,omitempty"`
    LastChunk bool           `json:"lastChunk,omitempty"`
    Metadata  map[string]any `json:"metadata,omitempty"`
}
```

### 5.6 A2APushNotificationConfig

```go
type A2APushNotificationConfig struct {
    URL            string                        `json:"url"`            // 必填
    ID             string                        `json:"id,omitempty"`   // v0.2.2 服务端创建；v0.3.0 起客户端设置（多回调）
    Token          string                        `json:"token,omitempty"`
    Authentication *A2APushNotificationAuth      `json:"authentication,omitempty"`
}

// A2APushNotificationAuth 对应 spec PushNotificationAuthenticationInfo。
// 仅用于 PushNotificationConfig.Authentication（不用于 AgentCard，见 §5.2 SecuritySchemes）。
type A2APushNotificationAuth struct {
    Schemes     []string `json:"schemes"`               // 如 ["Bearer"]，spec 示例用首字母大写
    Credentials string   `json:"credentials,omitempty"`
}
```

> **注**：v1.1 用 `UserID` 是幻觉（D-H1），已改为 spec 的 `ID`。v1.1 复用 `A2AAuthentication` 类型于 AgentCard 和 PushNotificationConfig 是混淆（D-M6），已拆分为 `A2ASecurityScheme`（AgentCard 用）与 `A2APushNotificationAuth`（PushNotificationConfig 用）。

### 5.7 默认值规则

| 字段 | 默认值 |
|------|--------|
| AgentCardPath | `/.well-known/agent.json` |
| AgentCard.ProtocolVersion | `"0.3.0"` |
| AgentCard.Capabilities.Streaming | false |
| AgentCard.Capabilities.PushNotifications | false |
| AgentCard.Capabilities.StateTransitionHistory | false |
| AgentCard.DefaultInputModes | `["text"]` |
| AgentCard.DefaultOutputModes | `["text"]` |
| Auth.Scheme | `none` |
| Auth.APIKeyIn | `header` |
| Auth.APIKeyName | `X-API-Key` |
| HTTP.UserAgent | `trafficgen-a2a/2.0` |
| HTTP.Accept | `application/json, text/event-stream` |
| HTTP.Connection | `keep-alive` |
| TCP.Handshake | true |
| TCP.Termination | true |
| TCP.MSS | 1460 |
| TCP.ACKPolicy | `immediate` |
| A2ATask.Method | `message/send` |
| A2AMessage.Role | `user` |
| A2AMessage.Kind | `message` |
| A2ATaskObject.Kind | `task` |
| A2ATaskStatusUpdateEvent.Kind | `status-update` |
| A2ATaskArtifactUpdateEvent.Kind | `artifact-update` |
| A2ATaskResponse.StatusCode | 200 |
| Configuration.Blocking | true |

---

## 6. 包序列场景

### 6.1 总体包序列

每个 `A2AConfig` 生成如下 `PacketConfig` 序列（flow_id = src-dst-ports）：

1. （可选）TCP SYN / SYN-ACK / ACK（`TCP.Handshake=true`，默认 true）
2. （可选）Agent Card 发现（`Discover=true`）：
   - 1 个 PSH-ACK 上行包，payload = `GET /.well-known/agent.json HTTP/1.1\r\n...`
   - 1 个 PSH-ACK 下行包，payload = `HTTP/1.1 200 OK\r\n...Content-Type: application/json\r\n\r\n<AgentCard JSON>`
   - 1 个纯 ACK 上行包（可选）
3. 对每个 task（按 Tasks 数组顺序，HTTP/1.1 串行）：
   - 1 个 PSH-ACK 上行包，payload = HTTP 请求（请求行 + 头 + JSON-RPC body），按 MSS 分段
   - 1 或多个 PSH-ACK 下行包，payload = HTTP 响应：
     - 同步路径：JSON-RPC 响应（超过 MSS 时按 MSS 分段）
     - 流式路径：SSE 头 + N 个 SSE 事件（每个事件按 MSS 切段）
   - 1 个纯 ACK 上行包（`TCP.ACKPolicy != "lazy"` 时）
4. （可选）TCP FIN-ACK (up) → FIN-ACK (down) → ACK (up)（`TCP.Termination=true`，3 包合并中间 ACK）

### 6.2 HexDump 场景 S1-S15

#### S1: Agent Card 发现

客户端发现 Agent 能力。TCP 三次握手后 GET Agent Card。

```
上行包 1（PSH-ACK，GET /.well-known/agent.json）：
0000  47 45 54 20 2f 2e 77 65 6c 6c 2d 6b 6e 6f 77 6e  GET /.well-known
0010  2f 61 67 65 6e 74 2e 6a 73 6f 6e 20 48 54 54 50  /agent.json HTTP
0020  2f 31 2e 31 0d 0a 48 6f 73 74 3a 20 61 67 65 6e  /1.1\r\nHost: agen
0030  74 2e 65 78 61 6d 70 6c 65 2e 63 6f 6d 0d 0a 41  t.example.com\r\nA
0040  63 63 65 70 74 3a 20 61 70 70 6c 69 63 61 74 69  ccept: applicati
0050  6f 6e 2f 6a 73 6f 6e 0d 0a 55 73 65 72 2d 41 67  on/json\r\nUser-Ag
0060  65 6e 74 3a 20 74 72 61 66 66 69 63 67 65 6e 2d  ent: trafficgen-
0070  61 32 61 2f 32 2e 30 0d 0a 43 6f 6e 6e 65 63 74  a2a/2.0\r\nConnect
0080  69 6f 6e 3a 20 6b 65 65 70 2d 61 6c 69 76 65 0d  ion: keep-alive\r
0090  0a 0d 0a                                         \n\r\n

下行包 1（PSH-ACK，200 OK + AgentCard JSON）：
HTTP/1.1 200 OK\r\n
Content-Type: application/json\r\n
Content-Length: 501\r\n
\r\n
{
  "name": "example-agent",
  "description": "An example A2A agent",
  "url": "https://agent.example.com/a2a",
  "version": "1.0.0",
  "protocolVersion": "0.3.0",
  "capabilities": {"streaming":true,"pushNotifications":true,"stateTransitionHistory":true},
  "skills": [{"id":"skill-1","name":"greeting","description":"Greets users","tags":["chat"]}],
  "securitySchemes": {"bearerAuth":{"type":"http","scheme":"bearer","bearerFormat":"JWT"}},
  "security": [{"bearerAuth":[]}],
  "defaultInputModes": ["text"],
  "defaultOutputModes": ["text"]
}
```

**断言**：请求行路径为 `/.well-known/agent.json`（单数）；响应 JSON 含 `protocolVersion`/`securitySchemes`/`security` 字段。Content-Length 501 对应下方 JSON 的紧凑序列化字节数（`json.Marshal` 无缩进），与展示的缩进排版无关。

#### S2: message/send（同步文本消息）

```
上行包（PSH-ACK，POST + JSON-RPC）：
POST /a2a HTTP/1.1\r\n
Host: agent.example.com\r\n
Content-Type: application/json\r\n
Accept: application/json\r\n
Content-Length: 258\r\n
Connection: keep-alive\r\n
\r\n
{
  "jsonrpc": "2.0",
  "method": "message/send",
  "params": {
    "message": {
      "role": "user",
      "parts": [{"kind":"text","text":"hello"}],
      "messageId": "m-001",
      "contextId": "ctx-abc",
      "kind": "message"
    },
    "configuration": {"acceptedOutputModes":["text"],"blocking":true}
  },
  "id": "req-001"
}

下行包（PSH-ACK，200 OK + Task 响应）：
HTTP/1.1 200 OK\r\n
Content-Type: application/json\r\n
Content-Length: 257\r\n
\r\n
{
  "jsonrpc": "2.0",
  "result": {
    "id": "task-001",
    "contextId": "ctx-abc",
    "status": {"state":"completed","timestamp":"2026-08-05T10:00:00Z"},
    "artifacts": [{"artifactId":"art-1","name":"reply","parts":[{"kind":"text","text":"hi there"}]}],
    "kind": "task"
  },
  "id": "req-001"
}
```

**断言**：method=`message/send`；params 无 `id` 字段（task id 由服务端分配，仅在响应 result.id）；响应 result.kind=`task`。Content-Length 258/257 对应上下两段 JSON 的紧凑序列化字节数。

#### S3: message/stream（流式响应）

```
上行包（PSH-ACK，POST + JSON-RPC，method=message/stream）：
POST /a2a HTTP/1.1\r\n
Host: agent.example.com\r\n
Content-Type: application/json\r\n
Accept: text/event-stream\r\n
\r\n
{
  "jsonrpc": "2.0",
  "method": "message/stream",
  "params": {
    "message": {"role":"user","parts":[{"kind":"text","text":"stream this"}],"messageId":"m-002","kind":"message"}
  },
  "id": "req-002"
}

下行包（PSH-ACK，200 OK + SSE 流，3 个事件）：
HTTP/1.1 200 OK\r\n
Content-Type: text/event-stream\r\n
Cache-Control: no-cache\r\n
Transfer-Encoding: chunked\r\n
Connection: keep-alive\r\n
\r\n
data: {"jsonrpc":"2.0","id":"req-002","result":{"kind":"task","id":"task-002","contextId":"ctx-def","status":{"state":"working","timestamp":"2026-08-05T10:00:01Z"}}}\n\n
data: {"jsonrpc":"2.0","id":"req-002","result":{"kind":"artifact-update","taskId":"task-002","contextId":"ctx-def","artifact":{"artifactId":"art-2","parts":[{"kind":"text","text":"chunk-1 "}]},"append":false,"lastChunk":false}}\n\n
data: {"jsonrpc":"2.0","id":"req-002","result":{"kind":"status-update","taskId":"task-002","contextId":"ctx-def","status":{"state":"completed","timestamp":"2026-08-05T10:00:02Z"},"final":true}}\n\n
```

**断言**：SSE 事件为**未命名事件**（仅 `data:` 行，无 `event:` 字段）；3 个事件 result.kind 依次为 `task`/`artifact-update`/`status-update`；末事件 `final:true`。

#### S4: tasks/get（查询任务）

```
上行包：
POST /a2a HTTP/1.1\r\n
Content-Type: application/json\r\n
Accept: application/json\r\n
\r\n
{"jsonrpc":"2.0","method":"tasks/get","params":{"id":"task-001","historyLength":5},"id":"req-003"}

下行包：
HTTP/1.1 200 OK\r\n
Content-Type: application/json\r\n
\r\n
{
  "jsonrpc": "2.0",
  "result": {
    "id": "task-001",
    "contextId": "ctx-abc",
    "status": {"state":"completed","timestamp":"2026-08-05T10:00:00Z"},
    "history": [
      {"role":"user","parts":[{"kind":"text","text":"hello"}],"messageId":"m-001","kind":"message"},
      {"role":"agent","parts":[{"kind":"text","text":"hi there"}],"messageId":"m-002","kind":"message"}
    ],
    "kind": "task"
  },
  "id": "req-003"
}
```

**断言**：method=`tasks/get`；params 含 `id`（已分配的 taskId）；响应 result.history 含 2 条 Message。

#### S5: tasks/cancel（取消任务）

```
上行包：
POST /a2a HTTP/1.1\r\n
Accept: application/json\r\n
\r\n
{"jsonrpc":"2.0","method":"tasks/cancel","params":{"id":"task-001"},"id":"req-004"}

下行包：
HTTP/1.1 200 OK\r\n
\r\n
{
  "jsonrpc": "2.0",
  "result": {
    "id": "task-001",
    "contextId": "ctx-abc",
    "status": {"state":"canceled","timestamp":"2026-08-05T10:00:03Z"},
    "kind": "task"
  },
  "id": "req-004"
}
```

**断言**：响应 result.status.state=`canceled`。

#### S6: tasks/resubscribe（断线重连）

```
上行包：
POST /a2a HTTP/1.1\r\n
Accept: text/event-stream\r\n
\r\n
{"jsonrpc":"2.0","method":"tasks/resubscribe","params":{"id":"task-002"},"id":"req-005"}

下行包（SSE 流，续传后续事件）：
HTTP/1.1 200 OK\r\n
Content-Type: text/event-stream\r\n
Transfer-Encoding: chunked\r\n
\r\n
data: {"jsonrpc":"2.0","id":"req-005","result":{"kind":"status-update","taskId":"task-002","contextId":"ctx-def","status":{"state":"completed","timestamp":"2026-08-05T10:00:05Z"},"final":true}}\n\n
```

**断言**：method=`tasks/resubscribe`；Accept=`text/event-stream`；响应为 SSE 流。

#### S7: tasks/pushNotificationConfig/set（设置推送）

```
上行包：
POST /a2a HTTP/1.1\r\n
Content-Type: application/json\r\n
Accept: application/json\r\n
\r\n
{
  "jsonrpc": "2.0",
  "method": "tasks/pushNotificationConfig/set",
  "params": {
    "taskId": "task-001",
    "pushNotificationConfig": {
      "url": "https://client.example.com/webhook/a2a",
      "token": "tok-abc",
      "authentication": {"schemes":["Bearer"],"credentials":"sec"}
    }
  },
  "id": "req-006"
}

下行包：
HTTP/1.1 200 OK\r\n
\r\n
{
  "jsonrpc": "2.0",
  "result": {
    "taskId": "task-001",
    "pushNotificationConfig": {
      "url": "https://client.example.com/webhook/a2a",
      "id": "pnc-001",
      "token": "tok-abc",
      "authentication": {"schemes":["Bearer"]}
    }
  },
  "id": "req-006"
}
```

**断言**：method=`tasks/pushNotificationConfig/set`（含 `Config`）；params 含 `taskId` 与 `pushNotificationConfig`；响应 result.pushNotificationConfig.id 在 v0.2.2 语义下由服务端分配（v0.3.0 起客户端可在请求中设置 id）。

#### S8: 认证（Bearer Token）

```
上行包（含 Authorization 头）：
POST /a2a HTTP/1.1\r\n
Host: agent.example.com\r\n
Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMSJ9.signature\r\n
Content-Type: application/json\r\n
Accept: application/json\r\n
\r\n
{"jsonrpc":"2.0","method":"message/send","params":{"message":{"role":"user","parts":[{"kind":"text","text":"auth"}],"messageId":"m-003","kind":"message"}},"id":"req-007"}
```

**断言**：请求含 `Authorization: Bearer <token>` 头。

#### S9: 多 Task 并发（独立 TCP 连接）

`FlowSpec.Count=3` 时，3 个客户端各自独立 TCP 连接（独立 src_port），并发发送 message/send：

```
Client-1 (src_port=51001): SYN → SYN-ACK → ACK → PSH-ACK(message/send, m-101) → PSH-ACK(200 OK, task-101) → FIN-ACK → FIN-ACK → ACK
Client-2 (src_port=51002): SYN → SYN-ACK → ACK → PSH-ACK(message/send, m-102) → PSH-ACK(200 OK, task-102) → FIN-ACK → FIN-ACK → ACK
Client-3 (src_port=51003): SYN → SYN-ACK → ACK → PSH-ACK(message/send, m-103) → PSH-ACK(200 OK, task-103) → FIN-ACK → FIN-ACK → ACK
```

**断言**：3 个流独立 4-tuple，task id 各不相同；HTTP/1.1 串行约束仅在单 TCP 连接内生效（多连接可并发）。

#### S10: 流式响应（多 SSE 事件混合）

`message/stream` 响应含 5 个事件：task → status-update(working) → artifact-update(chunk1) → artifact-update(chunk2, lastChunk) → status-update(completed, final)。

```
data: {"jsonrpc":"2.0","id":"req-008","result":{"kind":"task","id":"task-003","contextId":"ctx-ghi","status":{"state":"submitted"}}}\n\n
data: {"jsonrpc":"2.0","id":"req-008","result":{"kind":"status-update","taskId":"task-003","contextId":"ctx-ghi","status":{"state":"working"},"final":false}}\n\n
data: {"jsonrpc":"2.0","id":"req-008","result":{"kind":"artifact-update","taskId":"task-003","contextId":"ctx-ghi","artifact":{"artifactId":"art-3","parts":[{"kind":"text","text":"part1 "}]},"append":false,"lastChunk":false}}\n\n
data: {"jsonrpc":"2.0","id":"req-008","result":{"kind":"artifact-update","taskId":"task-003","contextId":"ctx-ghi","artifact":{"artifactId":"art-3","parts":[{"kind":"text","text":"part2"}]},"append":true,"lastChunk":true}}\n\n
data: {"jsonrpc":"2.0","id":"req-008","result":{"kind":"status-update","taskId":"task-003","contextId":"ctx-ghi","status":{"state":"completed"},"final":true}}\n\n
```

**断言**：5 个事件 result.kind 依次为 task/status-update/artifact-update/artifact-update/status-update；第 4 事件 `append:true,lastChunk:true`；第 5 事件 `final:true`。

#### S11: 错误处理（-32001 TaskNotFoundError）

```
上行包：
POST /a2a HTTP/1.1\r\n
Content-Type: application/json\r\n
Accept: application/json\r\n
\r\n
{"jsonrpc":"2.0","method":"tasks/get","params":{"id":"nonexistent"},"id":"req-009"}
下行包：
HTTP/1.1 200 OK\r\n
Content-Type: application/json\r\n
\r\n
{"jsonrpc":"2.0","error":{"code":-32001,"message":"Task not found"},"id":"req-009"}
```

**断言**：error.code=-32001；error.message=`Task not found`；id 与请求一致。

#### S12: TaskArtifactUpdateEvent（独立事件）

已在 S3 与 S10 中展示。本场景单独验证 `append` 与 `lastChunk` 语义：

```
事件 1：artifact-update(artifactId=art-4, parts=[{text:"A"}], append=false, lastChunk=false)
事件 2：artifact-update(artifactId=art-4, parts=[{text:"B"}], append=true, lastChunk=false)
事件 3：artifact-update(artifactId=art-4, parts=[{text:"C"}], append=true, lastChunk=true)
```

**断言**：客户端拼接得 `ABC`；append=false 替换，append=true 追加；lastChunk=true 后该 artifact 不再有更新。

#### S13: 多 Part 消息（text + data + file）

```
上行包（message/send，3 种 Part）：
POST /a2a HTTP/1.1\r\n
Accept: application/json\r\n
\r\n
{
  "jsonrpc": "2.0",
  "method": "message/send",
  "params": {
    "message": {
      "role": "user",
      "parts": [
        {"kind":"text","text":"query"},
        {"kind":"data","data":{"key":"value"}},
        {"kind":"file","file":{"name":"a.txt","mimeType":"text/plain","bytes":"aGVsbG8="}}
      ],
      "messageId": "m-004",
      "kind": "message"
    }
  },
  "id": "req-010"
}
```

**断言**：parts 数组 3 个元素，kind 依次 text/data/file；data Part 的 `data` 字段为对象；file Part 的 `file.bytes` 为 base64。

#### S14: Push Notification webhook（服务端→客户端 webhook）

任务完成后，Agent 服务端 POST 客户端 webhook：

```
Agent → Client webhook：
POST /webhook/a2a HTTP/1.1\r\n
Host: client.example.com\r\n
Authorization: Bearer sec\r\n
Content-Type: application/json\r\n
X-A2A-Notification-Token: tok-abc\r\n
\r\n
{
  "id": "task-001",
  "contextId": "ctx-abc",
  "status": {"state":"completed","timestamp":"2026-08-05T10:00:10Z"},
  "kind": "task"
}
```

**断言**：webhook 请求含 `X-A2A-Notification-Token` 头（值=PushNotificationConfig.token）；body 为 Task 对象（`kind:"task"`）；Authorization 头由 PushNotificationConfig.authentication 驱动。

> **注**：spec v0.2.2 webhook payload 是 Task 对象；spec v1.0 改为 StreamResponse 包装（含 task/message/statusUpdate/artifactUpdate 之一）。本设计 v1 采用 v0.2.2 语义（Task 对象）。

#### S15: 边界值（空 skills + 1MB text + max historyLength）

```
AgentCard.skills = []
Part.text = "a" * 1048576  (1MB)
tasks/get params.historyLength = 1000
```

**断言**：skills 空数组合法；1MB text 单 Part 合法（不超 §2.10 上限）；historyLength=1000 合法（≤1000 上限）。

---

## 7. 测试用例

测试用例从 spec §5-§9 派生（CLAUDE.md 测试策略规则 1：spec-driven）。共 **246 条**，覆盖正向/负向/边界/异常/并发/状态机/字段映射/集成。按类型统计：正向 150 / 负向 56 / 边界 30 / 集成 8 / 并发 2 = 246，负向用例占比 56/246 ≈ **22.8%**（注：v2.0.1 起如实标注，不再声称 ≥30%；v2.0.1 新增 T212a-T212d 共 4 条、T004 类型由边界改为负向、T199/T200 改为跨层一致性断言，故总数由 242 变为 246；v2.0.2 将 T160 由负向改为正向——webhook HTTP URL 合法、Validate 警告不拒绝，故负向 57→56、正向 149→150）。

### 7.1 报文格式与序列化（§2）— 12 条

| # | 名称 | 类型 | 验证点 |
|---|------|------|--------|
| T001 | JSON-RPC 请求必填字段 | 正向 | jsonrpc="2.0"+method+params+id 四字段齐全 |
| T002 | JSON-RPC 响应 result/error 互斥 | 负向 | 同时设 result 与 error，Validate 拒绝 |
| T003 | JSON-RPC id 类型一致 | 正向 | 请求 id=string，响应 id=同 string |
| T004 | JSON-RPC 请求缺 id | 负向 | 请求缺 id 属 Invalid Request（JSON-RPC 2.0 §6.11.2），响应 -32600 且 id=null |
| T005 | SSE 事件格式（未命名，仅 data: 行） | 正向 | `data: {...}\n\n`，无 `event:` 字段 |
| T006 | SSE 事件边界双 \n\n | 正向 | 两事件间空行分隔 |
| T007 | SSE 多行 data 拼接 | 边界 | 单事件拆多行 `data:`，客户端按 \n 拼接 |
| T008 | SSE 流末事件 final:true 后关闭 | 正向 | status-update final:true 后无更多事件 |
| T009 | HTTP 请求 Content-Type=application/json | 正向 | 同步路径请求头含 application/json |
| T010 | SSE 响应 Content-Type=text/event-stream | 正向 | 流式路径响应头含 text/event-stream |
| T011 | HTTP keep-alive Connection 头 | 正向 | 非最后请求 Connection: keep-alive |
| T012 | HTTP Authorization 头（bearer） | 正向 | Auth.Scheme=bearer 时请求含 Authorization: Bearer <token> |

### 7.2 Agent Card 发现（§2.4, §6.1 S1）— 12 条

| # | 名称 | 类型 | 验证点 |
|---|------|------|--------|
| T013 | GET /.well-known/agent.json 路径 | 正向 | 请求行路径为 `/.well-known/agent.json`（单数） |
| T014 | AgentCard 必填字段 | 正向 | name/description/url/version/protocolVersion/capabilities/skills/defaultInputModes/defaultOutputModes 齐全 |
| T015 | AgentCard.protocolVersion 字段 | 正向 | 响应 JSON 含 protocolVersion="0.3.0" |
| T016 | AgentCard.securitySchemes map | 正向 | securitySchemes 为 map（非 array），key 为方案名 |
| T017 | AgentCard.security 数组 | 正向 | security 为 array[map[string,string[]]] |
| T018 | AgentCard.capabilities 全 false | 边界 | streaming/pushNotifications/stateTransitionHistory 全 false 合法 |
| T019 | AgentCard.skills 空数组 | 边界 | skills=[] 合法 |
| T020 | AgentCard.skills 多技能 | 正向 | skills 数组含 2+ 个 AgentSkill |
| T021 | AgentCard 路径 404 | 负向 | AgentCardPath=/wrong-path，响应 404 |
| T022 | AgentCard JSON 畸形 | 边界 | ResponseBody 注入 `{not valid`，planner 原样输出 |
| T023 | AgentCard.provider 字段 | 正向 | provider 含 organization+url |
| T024 | AgentCard.supportsAuthenticatedExtendedCard | 边界 | supportsAuthenticatedExtendedCard=true 合法 |

### 7.3 message/send（§3.2.1, §6.2 S2）— 16 条

| # | 名称 | 类型 | 验证点 |
|---|------|------|--------|
| T025 | message/send 文本消息 | 正向 | method=message/send，parts=[text] |
| T026 | message/send 不带 params.id | 正向 | params 无 id 字段（task id 服务端分配） |
| T027 | message/send 带 contextId | 正向 | message.contextId 非空 |
| T028 | message/send 多 Part（text+data） | 正向 | parts 2 元素，kind text/data |
| T029 | message/send 文件 Part（FileWithBytes） | 正向 | parts[0].file.bytes=base64 |
| T030 | message/send 文件 Part（FileWithUri） | 正向 | parts[0].file.uri=URL |
| T031 | message/send 带 configuration | 正向 | configuration.acceptedOutputModes/blocking 齐全 |
| T032 | message/send 带 metadata | 正向 | params.metadata 非空 |
| T033 | message/send 响应 result=Task | 正向 | result.kind=task，含 id/contextId/status |
| T034 | message/send 响应 result=Message | 正向 | 简单交互 result.kind=message |
| T035 | message/send 响应 state=completed | 正向 | result.status.state=completed |
| T036 | message/send 响应 state=input-required | 正向 | result.status.state=input-required，含 status.message |
| T037 | message/send 缺 message 字段 | 负向 | params 无 message，Validate 拒绝 |
| T038 | message/send role 非 user/agent | 负向 | message.role=system，Validate 拒绝 |
| T039 | message/send parts 空数组 | 负向 | parts=[]，Validate 拒绝（至少 1 个） |
| T040 | message/send Part kind 非 text/data/file | 负向 | kind=data-stream，Validate 拒绝 |

### 7.4 message/stream（§3.2.2, §6.2 S3/S10）— 14 条

| # | 名称 | 类型 | 验证点 |
|---|------|------|--------|
| T041 | message/stream 流式响应 | 正向 | method=message/stream，响应 SSE 流 |
| T042 | message/stream Accept=text/event-stream | 正向 | 请求 Accept 头含 text/event-stream |
| T043 | message/stream 首事件 kind=task | 正向 | SSE 首事件 result.kind=task |
| T044 | message/stream 首事件 kind=message | 正向 | Message-only 流首事件 result.kind=message |
| T045 | message/stream 含 status-update 事件 | 正向 | SSE 流含 status-update 事件 |
| T046 | message/stream 含 artifact-update 事件 | 正向 | SSE 流含 artifact-update 事件 |
| T047 | message/stream 末事件 final:true | 正向 | 末事件 status-update final:true |
| T048 | message/stream 多 artifact-update append 语义 | 正向 | append=true 追加，append=false 替换 |
| T049 | message/stream lastChunk:true 后无该 artifact 更新 | 正向 | lastChunk=true 后该 artifactId 不再出现 |
| T050 | message/stream capabilities.streaming=false | 负向 | streaming=false 调用 message/stream，响应 -32004 |
| T051 | message/stream 事件按序投递 | 正向 | 事件 result 顺序与生成顺序一致 |
| T052 | message/stream 多并发流（同 task） | 正向 | 同 taskId 多 SSE 流，事件广播到所有流 |
| T053 | message/stream parts 空 | 负向 | parts=[]，Validate 拒绝 |
| T054 | message/stream Part kind 非法 | 负向 | kind=file-stream，Validate 拒绝 |

### 7.5 tasks/get（§3.2.3, §6.2 S4）— 10 条

| # | 名称 | 类型 | 验证点 |
|---|------|------|--------|
| T055 | tasks/get 查询现有任务 | 正向 | params.id 存在，响应 result=Task |
| T056 | tasks/get 带 historyLength | 正向 | params.historyLength=5，响应 history 含 ≤5 条 |
| T057 | tasks/get 带 metadata | 正向 | params.metadata 非空 |
| T058 | tasks/get 任务不存在 | 负向 | params.id=nonexistent，响应 error -32001 |
| T059 | tasks/get 缺 id | 负向 | params 无 id，Validate 拒绝 |
| T060 | tasks/get 响应含 artifacts | 正向 | result.artifacts 数组非空 |
| T061 | tasks/get 响应含 history | 正向 | result.history 数组非空 |
| T062 | tasks/get historyLength=0 | 边界 | historyLength=0，响应 history 空或省略 |
| T063 | tasks/get historyLength=1000 | 边界 | historyLength=1000，响应 history ≤1000 条 |
| T064 | tasks/get 响应 kind=task | 正向 | result.kind=task |

### 7.6 tasks/cancel（§3.2.4, §6.2 S5）— 8 条

| # | 名称 | 类型 | 验证点 |
|---|------|------|--------|
| T065 | tasks/cancel 取消非终态任务 | 正向 | 响应 result.status.state=canceled |
| T066 | tasks/cancel 取消终态任务 | 负向 | 已 completed 的任务，响应 error -32002 |
| T067 | tasks/cancel 缺 id | 负向 | params 无 id，Validate 拒绝 |
| T068 | tasks/cancel 任务不存在 | 负向 | params.id=nonexistent，响应 error -32001 |
| T069 | tasks/cancel 带 metadata | 正向 | params.metadata 非空 |
| T070 | tasks/cancel 响应 kind=task | 正向 | result.kind=task |
| T071 | tasks/cancel submitted 状态可取消 | 正向 | submitted→canceled 合法 |
| T072 | tasks/cancel working 状态可取消 | 正向 | working→canceled 合法 |

### 7.7 tasks/resubscribe（§3.2.5, §6.2 S6）— 8 条

| # | 名称 | 类型 | 验证点 |
|---|------|------|--------|
| T073 | tasks/resubscribe 断线重连 | 正向 | method=tasks/resubscribe，响应 SSE 流 |
| T074 | tasks/resubscribe Accept=text/event-stream | 正向 | 请求 Accept 头含 text/event-stream |
| T075 | tasks/resubscribe capabilities.streaming=false | 负向 | streaming=false，响应 -32004 |
| T076 | tasks/resubscribe 缺 id | 负向 | params 无 id，Validate 拒绝 |
| T077 | tasks/resubscribe 任务不存在 | 负向 | params.id=nonexistent，响应 error -32001 |
| T078 | tasks/resubscribe 续传后续事件 | 正向 | SSE 流携带断线后的后续事件 |
| T079 | tasks/resubscribe 响应 SSE 格式 | 正向 | 响应 Content-Type=text/event-stream |
| T080 | tasks/resubscribe 事件未命名 | 正向 | SSE 事件无 event: 字段 |

### 7.8 tasks/pushNotificationConfig/set 与 get（§3.2.6/§3.2.7, §6.2 S7）— 12 条

| # | 名称 | 类型 | 验证点 |
|---|------|------|--------|
| T081 | pushNotificationConfig/set 设置 | 正向 | method=tasks/pushNotificationConfig/set（含 Config） |
| T082 | pushNotificationConfig/set params.taskId | 正向 | params 含 taskId |
| T083 | pushNotificationConfig/set params.pushNotificationConfig | 正向 | params 含 pushNotificationConfig{url,token,authentication} |
| T084 | pushNotificationConfig/set 响应含 id | 正向 | result.pushNotificationConfig.id（v0.2.2 语义服务端分配；v0.3.0 起客户端设置） |
| T085 | pushNotificationConfig/set capabilities.pushNotifications=false | 负向 | 响应 error -32003 |
| T086 | pushNotificationConfig/set 缺 taskId | 负向 | Validate 拒绝 |
| T087 | pushNotificationConfig/set 缺 pushNotificationConfig | 负向 | Validate 拒绝 |
| T088 | pushNotificationConfig/set 缺 url | 负向 | pushNotificationConfig.url 空，Validate 拒绝 |
| T089 | pushNotificationConfig/get 查询 | 正向 | method=tasks/pushNotificationConfig/get |
| T090 | pushNotificationConfig/get 响应配置 | 正向 | result.pushNotificationConfig 含 url/id/token/authentication |
| T091 | pushNotificationConfig/get 任务不存在 | 负向 | 响应 error -32001 |
| T092 | pushNotificationConfig/get 缺 id | 负向 | Validate 拒绝 |

### 7.9 认证（§2.4, §6.2 S8）— 12 条

| # | 名称 | 类型 | 验证点 |
|---|------|------|--------|
| T093 | Bearer Token 认证 | 正向 | Authorization: Bearer <token> |
| T094 | Basic 认证 | 正向 | Authorization: Basic <base64(user:pass)> |
| T095 | API Key 认证（header） | 正向 | 请求头含 X-API-Key: <key> |
| T096 | API Key 认证（query） | 正向 | 请求 URL 含 ?api_key=<key> |
| T097 | OAuth2 Bearer Token | 正向 | Authorization: Bearer <oauth2-token> |
| T098 | OpenID Connect | 正向 | Authorization: Bearer <oidc-token> |
| T099 | AgentCard.securitySchemes bearer | 正向 | securitySchemes 含 {type:http,scheme:bearer} |
| T100 | AgentCard.securitySchemes apiKey | 正向 | securitySchemes 含 {type:apiKey,in:header,name:X-API-Key} |
| T101 | AgentCard.securitySchemes oauth2 | 正向 | securitySchemes 含 {type:oauth2,flows:{...}} |
| T102 | AgentCard.securitySchemes openIdConnect | 正向 | securitySchemes 含 {type:openIdConnect,openIdConnectUrl:...} |
| T103 | Auth.Scheme=none 不带 Authorization | 正向 | Auth.Scheme=none，请求无 Authorization 头 |
| T104 | in-task auth-required 状态 | 边界 | Task 状态 auth-required，status.message 含认证说明 |

### 7.10 状态机（§4）— 18 条

| # | 名称 | 类型 | 验证点 |
|---|------|------|--------|
| T105 | submitted→working→completed | 正向 | 经典成功路径 |
| T106 | submitted→working→input-required→working→completed | 正向 | 多轮交互 |
| T107 | submitted→working→failed | 正向 | 失败路径 |
| T108 | submitted→working→canceled | 正向 | 取消路径 |
| T109 | submitted→rejected | 正向 | Agent 拒绝 |
| T110 | submitted→auth-required→working→completed | 正向 | in-task 认证 |
| T111 | submitted→canceled | 正向 | 提交即取消 |
| T112 | submitted→auth-required | 边界 | 需认证才开始 |
| T113 | input-required→canceled | 正向 | 等待输入时取消 |
| T114 | auth-required→canceled | 正向 | 等待认证时取消 |
| T115 | unknown 状态（taskId 过期） | 边界 | tasks/get 返回 state=unknown |
| T116 | completed→*（终态不可变） | 负向 | completed→working，Validate 拒绝 |
| T117 | failed→*（终态不可变） | 负向 | failed→working，Validate 拒绝 |
| T118 | canceled→*（终态不可变） | 负向 | canceled→working，Validate 拒绝 |
| T119 | rejected→*（终态不可变） | 负向 | rejected→working，Validate 拒绝 |
| T120 | input-required→completed | 负向 | spec 未定义，Validate 拒绝 |
| T121 | input-required→working | 正向 | 补充输入后恢复 |
| T122 | auth-required→working | 正向 | 补充认证后恢复 |

### 7.11 TaskArtifactUpdateEvent（§2.8, §6.2 S12）— 8 条

| # | 名称 | 类型 | 验证点 |
|---|------|------|--------|
| T123 | artifact-update 单事件 | 正向 | SSE 流含 1 个 artifact-update |
| T124 | artifact-update append=false 替换 | 正向 | append=false，客户端替换 artifact |
| T125 | artifact-update append=true 追加 | 正向 | append=true，客户端追加 parts |
| T126 | artifact-update lastChunk=true | 正向 | lastChunk=true，该 artifact 最后一块 |
| T127 | artifact-update 多块拼接 | 正向 | 3 块 append=true，拼接得完整内容 |
| T128 | artifact-update kind 字段 | 正向 | kind=artifact-update |
| T129 | artifact-update 含 taskId/contextId | 正向 | 事件含 taskId 与 contextId |
| T130 | artifact-update 缺 artifact | 负向 | 事件无 artifact 字段，Validate 拒绝 |

### 7.12 TaskStatusUpdateEvent（§2.7）— 8 条

| # | 名称 | 类型 | 验证点 |
|---|------|------|--------|
| T131 | status-update 单事件 | 正向 | SSE 流含 1 个 status-update |
| T132 | status-update final=true | 正向 | final=true，末事件 |
| T133 | status-update final=false | 正向 | final=false，中间事件 |
| T134 | status-update kind 字段 | 正向 | kind=status-update |
| T135 | status-update 含 taskId/contextId | 正向 | 事件含 taskId 与 contextId |
| T136 | status-update 含 status.state | 正向 | status.state 为 9 个枚举值之一 |
| T137 | status-update 无 artifact 字段 | 正向 | 事件无 artifact（artifact 在独立事件） |
| T138 | status-update 缺 status | 负向 | 事件无 status 字段，Validate 拒绝（spec `TaskStatusUpdateEvent.required` = [contextId, final, kind, status, taskId]，见 V9） |

### 7.13 多 Part 与 Message 字段（§2.6）— 12 条

| # | 名称 | 类型 | 验证点 |
|---|------|------|--------|
| T139 | Message.role=user | 正向 | role=user |
| T140 | Message.role=agent | 正向 | role=agent |
| T141 | Message.messageId 必填 | 正向 | messageId 非空 |
| T142 | Message.taskId 可选 | 边界 | taskId 省略时合法 |
| T143 | Message.contextId 关联 | 正向 | contextId 关联同会话多 Task |
| T144 | Message.referenceTaskIds | 边界 | referenceTaskIds 含 2+ taskId |
| T145 | Message.extensions | 边界 | extensions 含扩展 URI |
| T146 | Message.kind=message | 正向 | kind 恒 message |
| T147 | Part kind=text | 正向 | kind=text，text 字段非空 |
| T148 | Part kind=data | 正向 | kind=data，data 字段为对象 |
| T149 | Part kind=file（FileWithBytes） | 正向 | kind=file，file.bytes 为 base64 |
| T150 | Part kind=file（FileWithUri） | 正向 | kind=file，file.uri 为 URL |

### 7.14 Push Notification webhook（§6.2 S14）— 10 条

| # | 名称 | 类型 | 验证点 |
|---|------|------|--------|
| T151 | webhook POST 请求 | 正向 | Agent POST 客户端 webhook |
| T152 | webhook Content-Type=application/json | 正向 | webhook 请求头含 application/json |
| T153 | webhook X-A2A-Notification-Token 头 | 正向 | 头值=PushNotificationConfig.token |
| T154 | webhook Authorization 头 | 正向 | 头值由 PushNotificationConfig.authentication 驱动 |
| T155 | webhook body 为 Task 对象 | 正向 | body 含 kind=task |
| T156 | webhook 客户端响应 2xx | 正向 | 客户端响应 200/202 |
| T157 | webhook 客户端响应非 2xx | 负向 | 客户端响应 4xx，Agent 重试 |
| T158 | webhook 至少投递一次 | 正向 | Agent 至少投递 1 次 |
| T159 | webhook 幂等处理 | 边界 | 客户端对重复通知幂等处理 |
| T160 | webhook URL 非 HTTPS | 正向 | PushNotificationConfig.url=http:// 合法（spec 为 SHOULD 建议），Validate 默认警告不拒绝（见 V15） |

### 7.15 多任务/多会话/并发（§6.2 S9）— 12 条

| # | 名称 | 类型 | 验证点 |
|---|------|------|--------|
| T161 | 多 Task 同 TCP 连接串行 | 正向 | task-2 请求在 task-1 响应后 |
| T162 | 多 Task 同 contextId | 正向 | 2 Task 共享 contextId |
| T163 | 多 Task 不同 contextId | 正向 | 2 Task 不同 contextId |
| T164 | 多会话 FlowSpec.Count=3 | 正向 | 3 独立 TCP 连接，独立 src_port |
| T165 | 多会话独立 taskId | 正向 | 3 流 taskId 各不相同 |
| T166 | 多会话 GroupID 路由 | 正向 | GroupID 控制是否共享 src_port 池 |
| T167 | 100 并发流聚合包数 | 并发 | 100 流总包数=100*(握手+task+teardown) |
| T168 | 并发流速率聚合 | 并发 | 100 流聚合速率 ≤ 配置 bps |
| T169 | HTTP/1.1 串行约束 | 正向 | 同连接 task-2 请求 seq > task-1 响应 seq |
| T170 | 多 task 请求复用 TCP | 正向 | keep-alive 复用连接 |
| T171 | 最后 task Connection:close | 正向 | 最后 task 请求 Connection:close |
| T172 | 非最后 task Connection:keep-alive | 正向 | 非最后 task 请求 Connection:keep-alive |

### 7.16 边界场景（§6.2 S15）— 14 条

| # | 名称 | 类型 | 验证点 |
|---|------|------|--------|
| T173 | skills 空数组 | 边界 | AgentCard.skills=[] |
| T174 | Part.text 1MB | 边界 | text 长度 1048576 |
| T175 | historyLength=1000 | 边界 | tasks/get historyLength=1000 |
| T176 | historyLength=0 | 边界 | tasks/get historyLength=0 |
| T177 | FileWithBytes 10MB | 边界 | bytes 解码后 10MB |
| T178 | metadata key 128 字节 | 边界 | metadata key 长度 128 |
| T179 | JSON-RPC id 128 字节 | 边界 | id 字符串长度 128 |
| T180 | skills 1024 个 | 边界 | skills 数组 1024 元素 |
| T181 | parts 1024 个 | 边界 | parts 数组 1024 元素 |
| T182 | contextId 128 字节 | 边界 | contextId 长度 128 |
| T183 | AgentCard.description 4096 字节 | 边界 | description 长度 4096 |
| T184 | referenceTaskIds 多 taskId | 边界 | referenceTaskIds 含 10 个 taskId |
| T185 | extensions 多 URI | 边界 | extensions 含 5 个 URI |
| T186 | SSE 流 0 中间事件 | 边界 | task→status-update(final) 仅 2 事件 |

### 7.17 异常场景（§9）— 17 条

| # | 名称 | 类型 | 验证点 |
|---|------|------|--------|
| T187 | -32700 JSON 解析失败 | 负向 | 请求 body 非法 JSON，响应 -32700 |
| T188 | -32600 无效 JSON-RPC 请求 | 负向 | 缺 jsonrpc 字段，响应 -32600 |
| T189 | -32601 方法不存在 | 负向 | method=tasks/send（错误名），响应 -32601 |
| T190 | -32602 参数无效 | 负向 | params 缺必填字段，响应 -32602 |
| T191 | -32603 内部错误 | 负向 | 服务端内部错误，响应 -32603 |
| T192 | -32001 任务不存在 | 负向 | tasks/get id=nonexistent，响应 -32001 |
| T193 | -32002 任务不可取消 | 负向 | tasks/cancel 终态任务，响应 -32002 |
| T194 | -32003 推送不支持 | 负向 | pushNotifications=false 调 set，响应 -32003 |
| T195 | -32004 操作不支持 | 负向 | streaming=false 调 message/stream，响应 -32004 |
| T196 | -32004 通用不支持场景 | 负向 | pushNotificationConfig/list 不支持，响应 -32004 |
| T197 | -32005 内容类型不支持 | 负向 | parts 含不支持的 mimeType，响应 -32005 |
| T198 | -32006 Agent 响应无效 | 负向 | Agent 返回非法 result，响应 -32006 |
| T199 | streaming=false 但 AgentCard.capabilities.streaming=true | 负向 | capabilities 声明与实际配置冲突，-32004（跨层一致性断言，区别于 T195） |
| T200 | pushNotifications=false 但 AgentCard.capabilities.pushNotifications=true | 负向 | capabilities 声明与实际配置冲突，-32003（跨层一致性断言，区别于 T194） |
| T201 | 终态任务再发 message/send | 负向 | -32004 UnsupportedOperationError |
| T202 | 不支持的方法名 | 负向 | method=tasks/sendSubscribe（spec 无），响应 -32601 |
| T203 | 不支持的 Part kind | 负向 | kind=data-stream（spec 无），Validate 拒绝 |

### 7.18 集成与端到端（§6）— 8 条

| # | 名称 | 类型 | 验证点 |
|---|------|------|--------|
| T204 | Agent Card 发现 + message/send 端到端 | 集成 | GET agent.json → POST message/send → 200 OK |
| T205 | message/stream 全流程 | 集成 | stream → SSE 流 → final:true → 流关闭 |
| T206 | pushNotificationConfig/set + webhook 投递 | 集成 | set → 任务完成 → webhook POST |
| T207 | tasks/resubscribe 断线重连 | 集成 | stream 中断 → resubscribe → 续传事件 |
| T208 | 多 task 同连接串行 | 集成 | 2 task 串行，task-2 seq > task-1 响应 seq |
| T209 | Bearer 认证全流程 | 集成 | AgentCard.securitySchemes → 请求 Authorization → 200 |
| T210 | tshark 解析 A2A JSON-RPC | 集成 | tshark 解析 POST 请求 body 为 JSON-RPC |
| T211 | tshark 解析 SSE 流 | 集成 | tshark 解析 SSE data: 行为 JSON-RPC 响应 |

### 7.19 字段覆盖补全（针对 spec 实际字段）— 14 条

| # | 名称 | 类型 | 验证点 |
|---|------|------|--------|
| T212 | AgentCard.protocolVersion 字段 | 正向 | 与 T015 等价（响应含 protocolVersion），不重复断言 |
| T212a | AgentCard.additionalInterfaces | 正向 | v0.2.5+ 额外接口 {url,transport} 必填，响应含该字段 |
| T212b | AgentCard.preferredTransport | 正向 | v0.2.5+ 首选传输，响应含该字段 |
| T212c | AgentCard.signatures | 边界 | v0.3.0 签名数组，本设计 v1 保留字段不生成 |
| T212d | SecurityScheme mutualTLS | 边界 | v0.3.0 mutualTLS 方案，A2ASecurityScheme 为 map 不拒绝 |
| T213 | AgentCard.securitySchemes map | 正向 | 与 T016 等价（securitySchemes 为 map），不重复断言 |
| T214 | AgentCard.security 数组 | 正向 | 与 T017 等价（security 为 array），不重复断言 |
| T215 | Task.contextId 字段 | 正向 | result.contextId 非空（非 sessionId） |
| T216 | Task.kind=task | 正向 | result.kind=task |
| T217 | Message.messageId 必填 | 正向 | 与 T141 等价（message.messageId 非空），不重复断言 |
| T218 | Message.contextId 关联 | 正向 | 与 T143 等价（message.contextId 关联 task），不重复断言 |
| T219 | Message.kind=message | 正向 | 与 T146 等价（message.kind=message），不重复断言 |
| T220 | TaskStatusUpdateEvent.taskId（非 id） | 正向 | 事件 taskId 字段（非 id） |
| T221 | TaskArtifactUpdateEvent 完整字段 | 正向 | 事件含 taskId/contextId/kind/artifact/append/lastChunk |

### 7.20 Part kind 互斥（§8 规则 4）— 6 条

| # | 名称 | 类型 | 验证点 |
|---|------|------|--------|
| T222 | Part kind=text 仅 text 字段 | 正向 | text Part 无 data/file |
| T223 | Part kind=data 仅 data 字段 | 正向 | data Part 无 text/file |
| T224 | Part kind=file 仅 file 字段 | 正向 | file Part 无 text/data |
| T225 | Part kind=text 同时含 data | 负向 | Validate 拒绝 |
| T226 | Part kind=data 同时含 file | 负向 | Validate 拒绝 |
| T227 | Part kind=file 同时含 text | 负向 | Validate 拒绝 |

### 7.21 v2.0.0 新增（审计 D-* 修复验证）— 15 条

| # | 名称 | 类型 | 验证点 |
|---|------|------|--------|
| T228 | method=message/send（非 tasks/send） | 正向 | D-C1 修复 |
| T229 | method=message/stream（非 tasks/sendSubscribe） | 正向 | D-C2 修复 |
| T230 | 无 tasks/subscribe 方法 | 负向 | method=tasks/subscribe，响应 -32601 |
| T231 | method=tasks/pushNotificationConfig/set（含 Config） | 正向 | D-C3 修复 |
| T232 | method=tasks/pushNotificationConfig/get | 正向 | D-C3 修复 |
| T233 | GET /.well-known/agent.json（单数） | 正向 | D-C4 修复 |
| T234 | GET /.well-known/agents.json（复数）404 | 负向 | D-C4 验证 |
| T235 | Part kind 仅 text/data/file | 正向 | D-C5 修复 |
| T236 | Part kind=data-stream 拒绝 | 负向 | D-C5 验证 |
| T237 | Part kind=file-stream 拒绝 | 负向 | D-C5 验证 |
| T238 | PushNotificationConfig.id 字段（非 userId） | 正向 | D-H1 修复 |
| T239 | PushNotificationConfig 无 userId 字段 | 正向 | D-H1 验证 |
| T240 | SSE 事件无 event: 字段 | 正向 | D-H4 修复 |
| T241 | TaskStatusUpdateEvent 无 artifact 字段 | 正向 | D-H3 修复 |
| T242 | TaskArtifactUpdateEvent 独立事件 | 正向 | D-H3 修复 |

---

## 8. Validate 规则

Validate 在 Plan 前执行，违反返回 error。规则编号 V1-V16。

### V1: Task 状态枚举
`A2ATaskResponse.Result`（反序列化为 Task 后）的 `status.state` ∈ `{submitted, working, input-required, completed, canceled, failed, rejected, auth-required, unknown, ""}`。空字符串允许（未设置时）。

### V2: 方法名枚举
`A2ATask.Method` ∈ `{message/send, message/stream, tasks/get, tasks/cancel, tasks/resubscribe, tasks/pushNotificationConfig/set, tasks/pushNotificationConfig/get}`。v0.3.0 的 list/delete/agent/getAuthenticatedExtendedCard 标注为 v2 路线图，v1 拒绝。

### V3: 流式方法与 capabilities 一致
- `Method ∈ {message/stream, tasks/resubscribe}` 时，`AgentCard.Capabilities.Streaming` 必须为 true（否则 Validate 警告：spec 要求 streaming=true；用户可强制覆盖）
- `Method ∈ {tasks/pushNotificationConfig/set, tasks/pushNotificationConfig/get}` 时，`AgentCard.Capabilities.PushNotifications` 必须为 true（同上）

### V4: Part kind 与 content 互斥
`A2APart.Kind` ∈ `{text, data, file}`（仅此 3 种，无 data-stream/file-stream）。互斥规则：
- `Kind=text` 时 `Data`/`File` 必须为 nil
- `Kind=data` 时 `Text`/`File` 必须为 nil
- `Kind=file` 时 `Text`/`Data` 必须为 nil

### V5: PushNotificationConfig 字段
- `URL` 必填；建议 HTTPS（`https://` 前缀，spec 为 SHOULD 建议而非 MUST，见 V15），HTTP URL 合法、Validate 默认警告不拒绝
- `Authentication.Schemes` 非空数组（若 Authentication 非 nil）
- `Authentication.Schemes` 每个值为非空字符串（spec 无大小写约束，推荐 RFC 7235 注册名如 Bearer/Basic）
- 无 `UserID` 字段（spec 无此字段，已撤销 v1.1 的幻觉）

### V6: AgentCard 必填字段
`Name`/`Description`/`URL`/`Version`/`ProtocolVersion`/`Capabilities`/`Skills`/`DefaultInputModes`/`DefaultOutputModes` 非空。`SecuritySchemes` 与 `Security` 可选（但若 `Security` 非空，`SecuritySchemes` 必须含对应 key）。

### V7: A2AMessage 必填字段
`Role` ∈ `{user, agent}`；`Parts` 数组 ≥1 元素；`MessageID` 非空；`Kind` 恒 `message`。

### V8: A2ATask 请求/响应字段
- `Method=message/send` 或 `message/stream` 时，`Message` 必填，`TaskID` 应为空（task id 服务端分配）
- `Method ∈ {tasks/get, tasks/cancel, tasks/resubscribe, tasks/pushNotificationConfig/get}` 时，`TaskID` 必填（params.id）
- `Method=tasks/pushNotificationConfig/set` 时，`TaskID` 与 `PushNotificationConfig` 必填
- `RequestID`（JSON-RPC id）必填
- **`Streaming` 与 `Method` 一致**：`Streaming=true` 时 `Method` 必须为 `message/stream` 或 `tasks/resubscribe`（两者均走 SSE 路径，见 §1.6 #8）；`Streaming=false` 时 `Method` 必须为 `message/send`、`tasks/get`、`tasks/cancel`、`tasks/pushNotificationConfig/set` 或 `tasks/pushNotificationConfig/get`（均为同步请求-响应路径，见 §3.1 方法表；冲突配置 Validate 拒绝）

### V9: SSE 事件序列
`A2ATask.Streaming=true` 时，`SSEEvents` 数组：
- 首事件 `Kind` ∈ `{task, message}`
- 末事件（若 `Kind=status-update`）`Final=true`
- `Kind=artifact-update` 事件必须含 `Artifact.Parts`（≥1）
- 事件 `Kind` ∈ `{task, message, status-update, artifact-update}`
- **所有 `Kind=status-update` 事件必须含 `Status` 字段**（spec required，见 §2.7 表；支撑 T138）
- **所有 `Kind=status-update` 事件必须含 `Final` 字段**（spec required；`Final=false` 的中间状态事件也必须显式输出 `"final":false`，不得省略）

### V10: 状态转换合法性
按 §4.2 状态转换表。**仅 §4.2 转换表列举的转换合法，其余一律拒绝**（含 `input-required→completed`、`auth-required→completed`、`submitted→completed` 等未定义转换，以及终态→任意、unknown→任意）。

### V11: 错误码枚举
`A2ATaskResponse.Error.Code` ∈ `{-32700, -32600, -32601, -32602, -32603, -32001, -32002, -32003, -32004, -32005, -32006, -32007}`。-32007 本设计 v1 不实现（标 v2 路线图），但 Validate 接受。

### V12: 长度约束
按 §2.10 长度字段约束表。超长字段 Validate 拒绝。

### V13: AgentCardPath 路径
默认 `/.well-known/agent.json`（单数，spec v0.2.x）。若用户配置 `/.well-known/agents.json`（复数）Validate 警告但不拒绝（用户可显式覆盖）。**注意**：v0.3.0 起（含 v1.0）spec 路径为 `/.well-known/agent-card.json`（IANA 已注册，v1.0 从未恢复 agent.json），对接 v0.3.0/v1.0 Agent 时 `AgentCardPath` 应设为该值。

### V14: HTTP 头生成
- `Method ∈ {message/stream, tasks/resubscribe}` 时，`Accept` 头应含 `text/event-stream`
- 其余方法 `Accept` 头为 `application/json`
- `Content-Type` 恒 `application/json`（请求）

### V15: webhook URL HTTPS
`PushNotificationConfig.URL` 建议 `https://` 前缀（spec 为 SHOULD 建议而非 MUST，schema 对 url 无格式约束），HTTP URL 合法、Validate 默认警告不拒绝。

### V16: JSON-RPC 响应 result/error 互斥
`A2ATaskResponse.Result` 与 `A2ATaskResponse.Error` 互斥：同一响应不得同时设置两者（§2.2 语义在 Validate 规则集中显式编码，支撑 T002）。同时设置时 Validate 拒绝。

---

## 9. 错误处理

### 9.1 JSON-RPC 错误响应格式

```json
{"jsonrpc":"2.0","error":{"code":-32001,"message":"Task not found","data":{}},"id":"req-009"}
```

`error` 对象字段：

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| code | integer | 是 | 错误码，见 §3.4 |
| message | string | 是 | 人类可读摘要 |
| data | any | 否 | 附加结构化信息 |

### 9.2 错误码使用场景

| 错误码 | 触发场景 |
|--------|----------|
| -32700 | 请求 body 非法 JSON |
| -32600 | 缺 jsonrpc 字段或值非 "2.0" |
| -32601 | method 不在 §3.1 枚举内（如 tasks/send/tasks/sendSubscribe/tasks/subscribe/tasks/pushNotification/set） |
| -32602 | params 缺必填字段、类型错（如 message/send 无 message） |
| -32603 | 服务端内部异常 |
| -32001 | tasks/get/cancel/resubscribe 的 id 不存在/过期 |
| -32002 | tasks/cancel 的 id 已终态 |
| -32003 | tasks/pushNotificationConfig/* 但 capabilities.pushNotifications=false |
| -32004 | message/stream/resubscribe 但 streaming=false；或 pushNotificationConfig/list 不支持；或终态任务再发 message/send |
| -32005 | parts 含不支持的 mimeType |
| -32006 | Agent 返回非法 result（如 SSE 事件缺 kind） |
| -32007 | agent/getAuthenticatedExtendedCard 但未配置（v2 路线图） |

### 9.3 HTTP 状态码

JSON-RPC 错误响应的 HTTP 状态码通常为 200（JSON-RPC 错误在 body 中表达）。以下场景用非 200：

| HTTP 状态 | 场景 |
|-----------|------|
| 400 | HTTP 请求格式错误（非 JSON-RPC 层） |
| 401 | 认证失败（Authorization 头缺失/无效） |
| 403 | 授权失败（认证通过但无权限） |
| 404 | Agent Card 路径不存在；或 GET 方法路由不到 |
| 405 | HTTP 方法不允许（如 GET 到 POST-only 端点） |
| 500 | 服务端内部错误（同 -32603） |
| 501 | 方法未实现 |

### 9.4 Validate 错误

Validate 在 Plan 前执行，违反规则 V1-V16 返回 Go error（不生成包）。错误消息格式：

```
a2a validate: <rule>: <detail>
```

例：`a2a validate: V4: Part kind=data-stream not in {text,data,file}`

### 9.5 SSE 流错误

SSE 流中的错误通过 `JSONRPCErrorResponse` 投递：

```
data: {"jsonrpc":"2.0","error":{"code":-32603,"message":"internal error"},"id":"req-002"}\n\n
```

服务端发送错误事件后关闭流。

---

## 10. 扩展字段映射

### 10.1 扩展表 17 上报字段

| 上报字段 | 来源 | 说明 |
|----------|------|------|
| protocol | A2AConfig | 恒 "a2a" |
| method | A2ATask.Method | 见 §3.1 |
| task_id | Task.ID | 服务端分配 |
| context_id | Task.ContextID | 上下文标识 |
| request_id | A2ATask.RequestID | JSON-RPC 信封 id |
| message_id | A2AMessage.MessageID | 消息标识 |
| task_state | TaskStatus.State | 9 个枚举值 |
| part_count | len(Message.Parts) | Part 数量 |
| part_kind_distribution | Part.Kind 计数 | text/data/file 分布 |
| artifact_count | len(Task.Artifacts) | 产出数量 |
| sse_event_count | len(SSEEvents) | 流式事件数量 |
| sse_event_kind_distribution | SSEEvent.Kind 计数 | task/message/status-update/artifact-update 分布 |
| auth_scheme | A2AAuth.Scheme | none/bearer/basic/apikey/oauth2/openIdConnect |
| streaming | A2ATask.Streaming | 是否流式 |
| http_status | A2ATaskResponse.StatusCode | HTTP 状态码 |
| error_code | A2ATaskResponse.Error.Code | JSON-RPC 错误码 |
| discover | A2AConfig.Discover | 是否发 Agent Card 发现 |

### 10.2 FlowSpec 字段映射

| FlowSpec 字段 | A2AConfig 字段 |
|---------------|----------------|
| Count | Tasks 数组长度 × Count |
| GroupID | 多会话 src_port 共享 |
| BPS | FlowControl.BPS |
| Direction | up（请求）/down（响应） |
| SrcIP/DstIP/SrcPort/DstPort | TCP 4-tuple |

### 10.3 与 ReplayPlanner 的关系

A2A planner 与 ReplayPlanner 互斥（一个 FlowSpec 只能用一个）。ReplayPlanner 复用 pcap，A2A planner 按 Config 生成。两者共享 TCP/HTTP 层生成器。

### 10.4 代码集成

```go
// internal/protocol/a2a/planner.go
package a2a

type Planner struct {
    spec core.FlowSpec
    cfg  *A2AConfig
}

func (p *Planner) Plan(ctx context.Context) (<-chan core.PacketConfig, error)
func (p *Planner) Validate() error
```

注册：
```go
// internal/core/registry.go
registry.Register("a2a", func(spec FlowSpec) (Planner, error) {
    var cfg A2AConfig
    if err := json.Unmarshal(spec.Config, &cfg); err != nil { return nil, err }
    return &Planner{spec: spec, cfg: &cfg}, nil
})
```

### 10.5 MCP 集成（A2A over MCP）

A2A 与 MCP（Model Context Protocol）可共存：A2A 是 Agent 间协议，MCP 是 Agent 与工具间协议。两者都基于 JSON-RPC 2.0，但方法名空间不冲突（A2A 用 `message/send` 等，MCP 用 `tools/call` 等）。

### 10.6 已知限制与坑

1. **Task ID vs Request ID**：Task.ID 是 A2A 协议层任务标识（服务端分配）；A2ATask.RequestID 是 JSON-RPC 信封 id（客户端分配）。两者独立，不要混淆。
2. **SSE 事件边界**：`\n\n` 分隔事件，单事件内 `\n` 需转义。
3. **HTTP keep-alive**：多 task 复用 TCP 连接，但 HTTP/1.1 串行（task-2 请求在 task-1 响应后）。
4. **Content-Length 与流式**：HTTP/1.1 中响应体长度必须由 Content-Length、Transfer-Encoding: chunked 或连接关闭三者之一确定。流式（SSE）响应**默认带 `Transfer-Encoding: chunked`**（无 Content-Length，Connection: keep-alive 时唯一合法的定界方式，见 S3/S6）；planner 对 `HTTP.ExtraHeaders` 中的显式设置保留优先级，用户也可改用 `Connection: close` 定界。
5. **JSON-RPC id 类型一致**：请求 id=string 时响应 id=同 string；请求 id=integer 时响应 id=同 integer。
6. **Agent Card 路径**：默认 `/.well-known/agent.json`（单数，spec v0.2.x 用此路径）；**v0.3.0 起（含 v1.0）改用 `/.well-known/agent-card.json`（IANA 已注册，v1.0 从未恢复 agent.json）**，对接 v0.3.0/v1.0 Agent 时须用 `AgentCardPath` 覆盖。
7. **stateTransitionHistory**：同步路径（tasks/get）在 history 数组返回；流式路径（message/stream）在 status-update 事件返回。
8. **unknown 状态不带 message**：unknown 表示 taskId 过期/失效，status.message 应为空。
9. **pushNotification URL HTTPS**：spec 为 SHOULD 建议（schema 无格式约束），Validate 默认警告不拒绝 HTTP；生产环境建议 HTTPS。
10. **capabilities 与方法兼容性**：streaming=false 调 message/stream → -32004；pushNotifications=false 调 set/get → -32003。
11. **Part kind 仅 3 种**：text/data/file，无 data-stream/file-stream（spec 任何版本都无）。
12. **SSE 未命名事件**：无 `event:` 字段，事件类型通过 payload `kind` 区分。
13. **TaskArtifactUpdateEvent 独立**：artifact 在此事件，不在 TaskStatusUpdateEvent。
14. **contextId 非 sessionId**：spec 用 contextId 关联同会话多 Task。
15. **PushNotificationConfig.id 非 userId**：spec 字段为 `id`（无 userId）；v0.2.2 由服务端创建，v0.3.0 起由客户端设置（多回调）。
16. **AgentCard 用 securitySchemes/security**：非 authentication.schemes（spec OpenAPI 风格）。
17. **method=message/send 非 tasks/send**：spec v0.2.2+ 实际方法名。
18. **method=message/stream 非 tasks/sendSubscribe**：spec v0.2.2+ 实际方法名。
19. **method=tasks/pushNotificationConfig/set 非 tasks/pushNotification/set**：含 Config。
20. **tasks/resubscribe 是断线重连**：不是"订阅已有 task"（spec 无 tasks/subscribe 方法）。

---

## 11. 修订记录

### v2.0.3（2026-08-05）— r3-v2 复审 2 项问题修复

依据复审报告 `audit/17-a2a-audit-r3-v2.md`（0 CRITICAL + 0 HIGH + 1 MEDIUM + 1 LOW）逐项修复。

#### MEDIUM 修复（1 项）

| 编号 | 问题 | 修复 |
|------|------|------|
| M-1 | V8 `Streaming=false` 分支仍只允许 `Method=message/send`，遗漏 `tasks/get`/`tasks/cancel`/`tasks/pushNotificationConfig/{set,get}` 4 个同步方法（r2-v2 M-C 修复不完整），导致合法同步方法配置被 Validate 误拒 | V8 `Streaming=false` 分支扩展为同步方法集：`Method` ∈ `{message/send, tasks/get, tasks/cancel, tasks/pushNotificationConfig/set, tasks/pushNotificationConfig/get}`（均为同步请求-响应路径，见 §3.1 方法表）；§5.3 `A2ATask.Streaming` 注释同步更新为 `// true=message/stream 或 tasks/resubscribe，false=同步方法（message/send/tasks/get/tasks/cancel/tasks/pushNotificationConfig/*）` |

#### LOW 修复（1 项）

| 编号 | 问题 | 修复 |
|------|------|------|
| L-1 | §3.1 方法表 `tasks/pushNotificationConfig/get` 未标注"需 pushNotifications=true"（set 行已标注），与 V3 规则不一致 | §3.1 方法表 `tasks/pushNotificationConfig/get` 行"说明"列补"（需 pushNotifications=true）"，与 set 行保持一致 |

### v2.0.2（2026-08-05）— r2-v2 复审 8 项问题修复

依据复审报告 `audit/17-a2a-audit-r2-v2.md`（0 CRITICAL + 0 HIGH + 5 MEDIUM + 3 LOW）逐项修复。

#### MEDIUM 修复（5 项）

| 编号 | 问题 | 修复 |
|------|------|------|
| M-A | §7 类型细分"边界 28"错误，实际 30（149+57+30+8+2=246） | §7 改为"边界 30"，求和与总数 246 一致 |
| M-B | T138 声称的 Validate 行为无规则支撑（v2.0.1 M-3 修复未落地：V9 实际只强化了 Final 字段） | V9 补全"所有 `Kind=status-update` 事件必须含 `Status` 字段（spec required，见 §2.7 表；支撑 T138）"；T138 验证点补充 spec `TaskStatusUpdateEvent.required` 依据；本节 M-3 措辞更正为与 V9 实际内容一致 |
| M-C | V8"Streaming=true → Method 必须为 message/stream"遗漏 tasks/resubscribe（同为流式方法，合法配置被误拒） | V8 改为"`Streaming=true` 时 `Method` 必须为 `message/stream` 或 `tasks/resubscribe`；`Streaming=false` 时 `Method` 必须为 `message/send`"；§5.3 `A2ATask.Streaming` 注释同步说明 |
| M-D | 遗漏 v0.2.x 的 `agent/authenticatedExtendedCard` HTTP GET 端点（spec §7.8，非 JSON-RPC 方法），§1.6"7 个核心方法"不准确 | §3.1 新增"v0.2.x HTTP 端点（非 JSON-RPC 方法）"表（HTTP GET，URL 为 `{AgentCard.url}/../agent/authenticatedExtendedCard`，需 supportsAuthenticatedExtendedCard=true，401/403/404 错误语义，v1 不实现、v2 路线图）；§1.6 #3 改为"7 个 JSON-RPC 核心方法 + 1 个 HTTP GET 扩展卡片端点"；v0.3.0 的 `agent/getAuthenticatedExtendedCard`（JSON-RPC，-32007）补充说明 |
| M-E | V15/T160/§10.6 #9 将 webhook URL 的 HTTPS 要求（规范为 SHOULD，schema 无格式约束）误作 MUST，拒绝规范允许的配置 | V15 改为"建议 https://（spec 为 SHOULD），HTTP URL 合法、Validate 默认警告不拒绝"；V5 首条同步改为"URL 必填；建议 HTTPS（SHOULD），HTTP URL 合法、警告不拒绝"；T160 由负向改为正向（http:// 合法，Validate 警告不拒绝），§7 类型统计同步更正为正向 150 / 负向 56 / 边界 30 / 集成 8 / 并发 2 = 246；§10.6 #9 与 §2.9 url 字段说明同步改为 SHOULD 建议 |

#### LOW 修复（3 项）

| 编号 | 问题 | 修复 |
|------|------|------|
| L-A | MutualTLSSecurityScheme 实际 required=['type']，文档称"无必填字段" | §2.4 SecurityScheme 表改为"必填 type（const=`mutualTLS`）" |
| L-B | preferredTransport/additionalInterfaces 示例值（"http"/"SSE"）不在 schema examples（JSONRPC/GRPC/HTTP+JSON）中 | §2.4 示例改为 `"JSONRPC"`，并注明 schema 示例集为 `["JSONRPC","GRPC","HTTP+JSON"]`、preferredTransport 默认 `"JSONRPC"` |
| L-C | §7.19 有 6 组与既有章节重复的测试验证点 | T212/T213/T214/T217/T218/T219 验证点标注"与 T015/T016/T017/T141/T143/T146 等价，不重复断言"，保留编号不删行 |

#### v2.0.1 修订记录更正

- M-3 措辞"V9 新增'status-update 事件必须含 Status'"实际未落地（V9 当时只加了 Final 必含）——已在 v2.0.2 落地，措辞更正为"V9 新增 Final 字段必含（支撑 H-2）"，Status 必含见 v2.0.2 M-B
- 统计口径统一为 r2-v2 实拉口径并随 v2.0.2 修正：正向 150 / 负向 56 / 边界 30 / 集成 8 / 并发 2 = 246（v2.0.1 写"边界 28"为笔误，v2.0.2 M-A 修正；v2.0.1 写"负向 57"为 T160 误标负向所致，v2.0.2 M-E 将 T160 改为正向后为 56）

### v2.0.1（2026-08-05）— r1-v2 复审 17 项问题修复

依据复审报告 `audit/17-a2a-audit-r1-v2.md`（0 CRITICAL + 3 HIGH + 7 MEDIUM + 7 LOW）逐项修复。实拉补充验证 A2A spec v1.0.0/v1.0.1 `docs/specification.md`。

#### HIGH 修复（3 项）

| 编号 | 问题 | 修复 |
|------|------|------|
| H-1 | "v1.0 已撤回恢复为 agent.json"是事实错误 | 实拉 v1.0.0/v1.0.1 确认均用 `/.well-known/agent-card.json`（IANA 已注册）；§1.3/§10.6 #6/V13 改为"v0.2.x 用 agent.json；v0.3.0 起（含 v1.0）用 agent-card.json，agent.json 仅存在于 v0.2.x"；默认值保持 agent.json（v0.2.x 目标），强调 AgentCardPath 覆盖 |
| H-2 | `TaskStatusUpdateEvent.final` 标可选且 Go 结构体 omitempty，false 时省略字段违反 spec required | §2.7 表改为"是（spec required）"并注明 false 也必须输出；§5.5 结构体改为 `Final bool \`json:"final"\``（去 omitempty）；V9 新增"所有 status-update 事件必须含 Final 字段" |
| H-3 | §2.3 称 SSE data 只能是 JSONRPCSuccessResponse，与 spec 及 §9.5 矛盾 | §2.3/§3.2.2 统一为 `SendStreamingMessageResponse` 联合类型（成功 `JSONRPCSuccessResponse` \| 错误 `JSONRPCErrorResponse`）；§2.3 SSE 规则表补"错误 data"行 |

#### MEDIUM 修复（7 项）

| 编号 | 问题 | 修复 |
|------|------|------|
| M-1 | 测试数量声称 203 实际 242 | §7 改为"共 242 条"；同步修正 §7.17（实际 17 条）与 §7.21（实际 15 条）标题计数，并将 §7.19 标题更新为 14 条；v2.0.1 新增 T212a-T212d 后全表共 246 条 |
| M-2 | 负向占比声称 ≥30% 实际 23.1% | §7 改为如实标注"57/246 ≈ 23.2%（v2.0.1 起不再声称 ≥30%）"；§11 v2.0.0 修订记录"≥ 30%"同步更正 |
| M-3 | T002/T138 声称的 Validate 行为在 V1-V15 无规则 | 新增 V16（result/error 互斥，支撑 T002）；V9 新增"status-update 事件必须含 Status"（支撑 T138）；新增 V8"Streaming 与 Method 一致性"（L-5 一并修复） |
| M-4 | PushNotificationConfig.id 版本标注错误 | §2.9 表/注、§5.6 结构体、§10.6 #15、S7 断言、T084 全部改为"v0.2.2 服务端创建；v0.3.0 起客户端设置（多回调）" |
| M-5 | 字段覆盖率"100%"不实 | §2.4 表补 additionalInterfaces/preferredTransport（v0.2.5+）/signatures（v0.3.0）；SecurityScheme 表补 mutualTLS 行（v0.3.0 共 5 种子类型）；§5.2 结构体补 A2AAgentInterface/A2AAgentCardSignature；§7.19 新增 T212a-T212d；§11 "100%" 改为"覆盖目标版本（v0.2.2 核心 + v0.2.5 protocolVersion/additionalInterfaces/preferredTransport）全部必填字段" |
| M-6 | S1/S2 Content-Length 与 JSON 字节不符 | 按紧凑序列化实际字节数修正：S1 612→**501**、S2 请求 187→**258**、S2 响应 215→**257**；S1/S2 断言注明 Content-Length 对应紧凑序列化字节数 |
| M-7 | SSE 响应无 Content-Length 也无 chunked | S3/S6 响应头补 `Transfer-Encoding: chunked`；§10.6 #4 改为"SSE 响应默认带 chunked（keep-alive 时唯一合法定界），用户显式设置保留优先级" |

#### LOW 修复（7 项）

| 编号 | 问题 | 修复 |
|------|------|------|
| L-1 | -32007 错误名错误 | §3.4 改为 spec 实际名称 `AuthenticatedExtendedCardNotConfiguredError` |
| L-2 | S4-S7 请求缺 Accept 头 | S4/S5/S7/S11/S13/S8 请求补 `Accept: application/json`（S3/S6 流式已含 `Accept: text/event-stream`，与 V14 一致） |
| L-3 | T199/T200 与 T194/T195 重复 | 改为 capabilities 声明与实际配置冲突的跨层一致性断言（区别于 T194/T195），保持编号连续；§7.17 标题 18→17 条 |
| L-4 | T004 描述含糊 | 改为"请求缺 id 属 Invalid Request（JSON-RPC 2.0 §6.11.2），响应 -32600 且 id=null" |
| L-5 | A2ATask.Streaming 与 Method 无一致性校验 | V8 新增"Streaming=true 时 Method 必须为 message/stream"（与 M-3 一并修复） |
| L-6 | §6.1 "同步路径：单包 JSON-RPC 响应"误导 | 改为"JSON-RPC 响应（超过 MSS 时按 MSS 分段）" |
| L-7 | §4.2 禁止转换列举不完整 | V10 明确"仅 §4.2 转换表列举的转换合法，其余一律拒绝" |

#### v2.0.0 修订记录更正

- "测试用例从 87 条增至 242 条（含 v2.0.0 新增 16 条）"→ v2.0.0 实际新增 15 条（T228-T242 无缺号）；v2.0.1 全表共 246 条（新增 T212a-T212d）
- "负向用例占比 ≥ 30%"→ 实际 23.2%（57/246）
- "字段覆盖率提升至 100%"→ 改为目标版本覆盖表述
- "所有 JSON 字段完整"→ 补充说明 Content-Length 对应紧凑序列化字节数

### v2.0.0（2026-08-05）— spec 一致性全面返工

依据审计报告 `audit/17-a2a-audit-deep.md` 24 项问题（5 CRITICAL + 6 HIGH + 8 MEDIUM + 5 LOW）逐项修复，已实拉 spec v0.2.2/v0.2.5/v0.3.0 `a2a.json` 与 `docs/specification.md` 验证。

#### CRITICAL 修复（5 项）

| 编号 | 问题 | 修复 |
|------|------|------|
| D-C1 | method 名 `tasks/send` spec 不存在 | 全文改为 `message/send`；Validate V2 合法方法集更新 |
| D-C2 | method 名 `tasks/sendSubscribe`/`tasks/subscribe` spec 不存在 | 改为 `message/stream`；删除 `tasks/subscribe`（spec 无此方法） |
| D-C3 | method 名 `tasks/pushNotification/{set,get}` 缺 Config | 改为 `tasks/pushNotificationConfig/{set,get}`；新增 v0.3.0 的 list/delete 标注 v2 路线图 |
| D-C4 | Agent Card 路径 `agents.json`（复数） | 改为 `agent.json`（单数，spec v0.2.x）；v0.3.0 起（含 v1.0）路径为 `agent-card.json`（v2.0.1 H-1 修正） |
| D-C5 | Part kind `data-stream`/`file-stream` 是幻觉 | 删除；spec 任何版本都仅 text/data/file 3 种 |

#### HIGH 修复（6 项）

| 编号 | 问题 | 修复 |
|------|------|------|
| D-H1 | PushNotificationConfig.UserID 是幻觉 | 改为 spec 的 `ID` 字段（v0.3.0+） |
| D-H2 | AgentCard.Authentication 字段错 | 改为 spec 的 `SecuritySchemes` map + `Security` array；新增 A2ASecurityScheme 类型 |
| D-H3 | TaskStatusUpdateEvent.Artifact 字段错置 | 删除 artifact 字段；新增独立 TaskArtifactUpdateEvent 类型（§2.8） |
| D-H4 | SSE 固定 `event: update` 是 spec 违规 | 改为未命名事件（仅 data: 行，payload kind 区分类型） |
| D-H5 | Task 状态枚举遗漏 rejected/auth-required | 新增，9 个枚举值 |
| D-H6 | 错误码 -32004 语义窄化 | 改为通用 UnsupportedOperationError；新增 -32006/-32007 |

#### MEDIUM 修复（8 项）

| 编号 | 问题 | 修复 |
|------|------|------|
| D-M1 | A2APart 允许多 content 字段 | 新增 V4 互斥校验 |
| D-M2 | A2AFile.Bytes vs A2AFilePart.BytesB64 命名不一致 | 统一为 A2AFile.Bytes |
| D-M3 | input-required→completed 标"罕见保留" | 改为 Validate 拒绝（spec 未定义） |
| D-M4 | schemes 强制小写是错误约束 | 改为非空字符串（spec 示例用大写 Bearer） |
| D-M5 | A2AAgentCard 缺 protocolVersion | 新增 ProtocolVersion 字段，默认 "0.3.0" |
| D-M6 | A2AAuthentication 类型混淆 | 拆分为 A2ASecurityScheme（AgentCard）与 A2APushNotificationAuth（PushNotificationConfig） |
| D-M7 | params 必填字段含 id（message/send） | 删除 id；message/send 不带 task id（服务端分配） |
| D-M8 | A2ATask.ID 注释"客户端分配"错 | 改为"服务端分配；请求中仅 tasks/get/cancel 等携带" |

#### LOW 修复（5 项）

| 编号 | 问题 | 修复 |
|------|------|------|
| D-L1 | A2AAgentCard.Description omitempty | 默认值表给 Description 默认 "A2A Agent" |
| D-L2 | A2ASkill Name/Description omitempty | 改为必填（spec required） |
| D-L3 | Task 对象 sessionId 字段 | 改为 contextId |
| D-L4 | 流式 Content-Length 绝对断言 | 改为"通常省略，接受显式设置" |
| D-L5 | T83 编号重复 | 重新编号全部测试用例 T001-T242 |

#### 字段覆盖率改善

按 spec 实际字段重新核查，覆盖率从 v1.1 的 65%（基于错误字段集）提升至**覆盖本设计目标版本（v0.2.2 核心 + v0.2.5 的 protocolVersion/additionalInterfaces/preferredTransport）的全部必填字段**（v0.3.0 新增字段如 signatures/mutualTLS 在本设计 v1 保留声明、不生成）：

- 新增 AgentCard.protocolVersion/securitySchemes/security 字段
- 新增 Task.contextId（替代 sessionId）
- 新增 Task.kind 字段
- 新增 Message.messageId/taskId/contextId/kind 字段
- 新增 TaskStatusUpdateEvent.taskId/contextId/kind 字段
- 新增 TaskArtifactUpdateEvent 完整类型
- 新增 PushNotificationConfig.id 字段（替代 userId）
- 新增 PushNotificationAuthenticationInfo 完整字段

#### 测试用例改善

- 测试用例从 87 条增至 **242 条**（含 v2.0.0 新增 15 条 D-* 修复验证，T228-T242 无缺号；v2.0.1 新增 T212a-T212d 后共 246 条）
- 负向用例占比 57/246 ≈ **23.2%**（v2.0.1 起如实标注，不再声称 ≥ 30%）
- 新增 Part kind 互斥测试（V4）
- 新增 TaskArtifactUpdateEvent 独立测试（D-H3）
- 新增 SSE 未命名事件测试（D-H4）
- 新增 spec 方法名验证测试（D-C1/D-C2/D-C3）
- 新增 Agent Card 单数路径测试（D-C4）
- 全部测试用例从 spec §5-§9 派生（spec-driven，CLAUDE.md 测试策略规则 1）

#### HexDump 场景

新增 15 个 HexDump 场景 S1-S15，覆盖 Agent Card 发现、message/send、message/stream、tasks/get、tasks/cancel、tasks/resubscribe、pushNotificationConfig/set、认证、多 Task 并发、流式响应、错误处理、TaskArtifactUpdateEvent、多 Part 消息、Push Notification webhook、边界值。所有 JSON 字段完整、方法名正确、与 spec v0.2.2+ 严格一致。

#### v1.1 修订撤销

v1.1 修订记录中以下"修复"实际引入了新的 spec 违规，已在 v2.0.0 撤销：

- H-6（声称 spec 0.3 引入 data-stream/file-stream）→ 撤销（伪造 spec 引用）
- S-2（固定 event: update）→ 撤销（spec 用未命名事件）
- C-4（删 Credentials 留 UserID）→ 撤销 UserID，改为 spec 的 ID
- L-6/L-7（agents.json 路径"固定 vs 可覆盖"措辞）→ 改为 agent.json 单数

教训：**每个 spec 引用必须实拉原文验证**，不能基于"看起来合理"的猜测。v1.1 的"基于猜测的修复"模式与一审 3R-C1（MCP includeContext 幻觉）是同一类错误复发。

---

## 参考资料

1. A2A spec v0.2.2：https://raw.githubusercontent.com/google/A2A/v0.2.2/docs/specification.md
2. A2A spec v0.2.2 JSON schema：https://raw.githubusercontent.com/google/A2A/v0.2.2/specification/json/a2a.json
3. A2A spec v0.2.5 JSON schema：https://raw.githubusercontent.com/google/A2A/v0.2.5/specification/json/a2a.json
4. A2A spec v0.3.0 JSON schema：https://raw.githubusercontent.com/google/A2A/v0.3.0/specification/json/a2a.json
5. JSON-RPC 2.0：https://www.jsonrpc.org/specification
6. SSE（Server-Sent Events）：HTML Living Standard §9.2
7. RFC 8615（Well-Known URIs）：https://www.rfc-editor.org/rfc/rfc8615
8. RFC 7515（JSON Web Signature）：https://www.rfc-editor.org/rfc/rfc7515
9. RFC 8785（JSON Canonicalization Scheme）：https://www.rfc-editor.org/rfc/rfc8785
10. RFC 7235（HTTP Authentication）：https://www.rfc-editor.org/rfc/rfc7235
11. 审计报告：`audit/17-a2a-audit-deep.md`（v1.1 深审，24 项问题）
12. 审计报告：`audit/17-a2a-audit-r1-v2.md`（v2.0.1 复审，17 项问题）
13. 审计报告：`audit/17-a2a-audit-r2-v2.md`（v2.0.2 复审，8 项问题）
14. 审计报告：`audit/17-a2a-audit-r3-v2.md`（v2.0.3 复审，2 项问题）

---

**文档结束**。v2.0.3 已修复 r3-v2 复审的 2 项问题（0 CRITICAL / 0 HIGH / 1 MEDIUM / 1 LOW），协议骨架（方法名/路径/Part kind/事件类型）与 spec v0.2.2+ 严格一致，可进入实现阶段。
