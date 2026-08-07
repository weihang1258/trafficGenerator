# MCP / A2A 设计文档对抗审计报告

**审计对象**：
- `docs/protocol-designs/16-mcp-design.md`（MCP，1755 行，声称 60 用例）
- `docs/protocol-designs/17-a2a-design.md`（A2A，1612 行，声称 63 用例）

**审计日期**：2026-08-03
**审计人**：独立协议审计（与设计者无交叉）
**审计依据**：
1. MCP spec 2024-11-05（HTTP+SSE + stdio）+ 2025-03-26 引入 Streamable HTTP
2. A2A spec 0.3+（Google Agent2Agent，JSON-RPC 2.0 over HTTP + SSE）
3. JSON-RPC 2.0（https://www.jsonrpc.org/specification）
4. SSE 规范（HTML Living Standard §9.2 Server-Sent Events；非 RFC 8855）
5. `CLAUDE.md` 测试策略 8 条强制规则
6. `trafficgen/internal/protocol/socks5/socks5.go`（Planner 模式参考）
7. `trafficgen/internal/mcp/`（已存在的 MCP 服务器，与本设计并存）

---

## 1. 审计概览

### 1.1 审计方法

- 通读两份全文（16-mcp 1755 行 + 17-a2a 1612 行），对每条 spec 陈述、每个 JSON-RPC 字段、每个状态转换与 socks5 Planner 模式逐一比对。
- 对 §3 方法表、§4/§5 状态机、§7/§8 业务场景逐字段对照 MCP/A2A spec 原文，发现 **2 处事实性 spec 错误**（MCP capabilities 必填性、A2A SSE RFC 引用）、**3 处 spec 字段缺失**（A2A 缺 data-stream/file-stream Part、缺 user-defined extensions；A2A 多出 credentials map）。
- 对 §8 测试用例清单与 §3-§7 字段声明逐项交叉比对，发现 **5 类"声称覆盖但零测试"字段**（MCP parentId/state/status/contextId/streaming 在 A2A）。
- 对 §6 Plan 输出与 socks5.go 参考实现比对，发现 **3 处 TCP 字节序错误**（teardown 包数与 FIN-ACK 合并语义）。
- 对 §9/§10 交叉对抗审计清单与 CLAUDE.md 测试策略 8 条规则对照，发现测试策略多处违规（happy-path-only、未断言字节、未测并发正确性）。

### 1.2 总体结论

两份设计文档**结构完整、覆盖面广**：MCP 60 用例 + A2A 63 用例都远超最低 30 条要求，状态机、字段映射、传输模式、多会话隔离均有专门章节，§11（MCP）"与 internal/mcp/ 关系说明"和 §11.6（A2A）"已知坑"清单体现了对项目历史的吸取。这是本仓库协议设计中较好的部分。

但存在三类系统性缺陷：

1. **spec 一致性错误（CRITICAL ×2，HIGH ×3）**：MCP 把 `capabilities` 标为必填（spec 是可选）；A2A 把 SSE 引用为 "RFC 8855"（SSE 没有 RFC，是 HTML5 规范）；A2A 缺失 `data-stream`/`file-stream` Part kind（spec 0.3 引入）；A2A 多出 `credentials map[string]string` 字段（spec 无）；MCP `notifications/initialized` 携带 params 与 spec "no parameters" 不一致。
2. **内部矛盾（HIGH ×3，MEDIUM ×4）**：MCP §2.4 说 POST 返回 202/SSE，§6.3 显示 200 + JSON body——同一文档对 HTTP+SSE 旧版传输的 POST 响应语义自相矛盾；MCP §6.2 teardown 描述 "3-way" 但 socks5 参考实现是 FIN-ACK/FIN-ACK/ACK（合并中间 ACK）；A2A §6.1 序列号描述与 §7.3 "纯 ACK 不推进 seq" 在多 task keep-alive 场景下未对齐；A2A §5.2 `Task.Streaming` 字段说"显式覆盖方法默认"但 §3 方法表说 sendSubscribe 恒为流式——边界语义不清。
3. **测试质量违规（HIGH ×4，MEDIUM ×6）**：直接违反 CLAUDE.md 测试策略 8 条中的第 2/3/5/6 条——MCP 60 用例中负向仅 ~12 条（20%，低于 25% 阈值）；A2A 集成测试 T56-T59 未断言"实际字节序列"只断言"不报错"（违反规则 5）；两份文档均无"N 并发 worker 实测聚合速率"用例（违反规则 6）；MCP `parentId`/`state`/`status`/`contextId` 字段在 §3.10 声明但在 §8 测试用例中零覆盖（违反规则 1 spec-driven）。

### 1.3 严重度分布

| 严重度 | MCP | A2A | 合计 | 说明 |
|--------|-----|-----|------|------|
| CRITICAL | 2 | 2 | 4 | spec 一致性错误 / 字节级期望错误 |
| HIGH | 5 | 5 | 10 | 内部矛盾 / spec 字段缺失 / 虚假覆盖声明 |
| MEDIUM | 7 | 6 | 13 | 缺失校验规则 / 测试质量违规 |
| LOW | 4 | 3 | 7 | 表述不精确 / 引用错误 / 计数不符 |
| **合计** | **18** | **16** | **34** | （要求 ≥18，超额） |

### 1.4 设计中的亮点（予以肯定）

- MCP §11 "与 internal/mcp/ 关系说明"完整对比两个 MCP 概念（服务器 vs 流量生成器），明确包路径隔离、依赖隔离、命名隔离，避免后续实现者混淆——这是项目特有的复杂场景，处理得当。
- A2A §11.6 "已知坑"12 条直接命中 SSE 事件边界、HTTP keep-alive 复用、Content-Length 与流式互斥、JSON-RPC id 类型一致性等真实陷阱，方向正确。
- 两份文档都明确"不模拟真实 SDK 行为 / 不模拟 OAuth2 flow"的作用域声明，诚实且必要。
- MCP §7.18 边界场景 20 条 + §7.19 异常场景 10 条，A2A §8.18 边界 11 条 + §8.19 异常 12 条，覆盖度优于本仓库历史协议设计。
- 多会话机制（MCP §6.5 / A2A §7.6）与 socks5 `:udp` 子流先例一致，FlowID 隔离、GroupID 共享的设计正确。

### 1.5 spec 一致性逐项核查表（维度 1 全量核对结果）

#### MCP（对照 MCP spec 2024-11-05 + 2025-03-26 + 2025-06-18）

| # | 核查项 | spec 要求 | 设计结论 | 状态 |
|---|--------|---------|---------|------|
| 1 | JSON-RPC 2.0 包结构（jsonrpc/id/method/params 或 result/error） | JSON-RPC 2.0 §4 | §2.1 正确 | OK |
| 2 | id 为 null 在请求中不允许 | MCP spec "Requests MUST NOT use null" | §2.1.1 正确 | OK |
| 3 | 通知无 id 字段 | JSON-RPC 2.0 §4.1 | §2.1.3 正确 | OK |
| 4 | stdio 行分隔 JSON（每行一包，`\n` 分隔） | MCP spec "stdio transport" | §2.3 正确 | OK |
| 5 | HTTP+SSE 旧版：POST `/mcp` 返回 202 Accepted 或 SSE 流 | spec "POST returns 202 Accepted" | §2.4 说 202/SSE，§6.3 显示 200+JSON | **冲突 H-1** |
| 6 | HTTP+SSE 旧版：GET `/mcp` 建立 SSE 流接收响应 | spec "GET opens SSE stream" | §2.4 正确 | OK |
| 7 | Streamable HTTP：POST 响应可为 JSON 或 SSE | spec "POST response 200 + application/json or text/event-stream" | §2.5 正确 | OK |
| 8 | Streamable HTTP：GET `/mcp` 用于服务端发起消息 | spec "GET opens SSE for server-initiated" | §2.5 正确 | OK |
| 9 | Streamable HTTP：DELETE `/mcp` 终止会话 | spec "DELETE terminates session" | §2.5 正确 | OK |
| 10 | `Mcp-Session-Id` 头由 initialize 响应返回，后续请求携带 | spec "session id header" | §2.4/§6.3 正确 | OK |
| 11 | `initialize` 请求 params：protocolVersion + capabilities + clientInfo | spec "InitializeRequest" | §3.1 正确 | OK |
| 12 | `initialize` 的 `capabilities` 字段可选（可省略） | spec "capabilities?: ClientCapabilities" | §3.10 标"必填" | **错误 C-1** |
| 13 | `notifications/initialized` 无 params | spec "initialized notification has no parameters" | §7.2 允许 params {} | **错误 C-2** |
| 14 | `notifications/cancelled` params 含 `requestId` + `reason` | spec "CancelledNotification params" | §3.7 正确 | OK |
| 15 | `notifications/progress` params 含 `progressToken`/`progress`/`total`/`message` | spec "ProgressNotification" | §3.7 正确 | OK |
| 16 | `tools/call` 响应 `content` 数组 + `isError` | spec "CallToolResult" | §3.2 正确 | OK |
| 17 | `tools/call` 请求 `_meta.progressToken` 用于进度关联 | spec "_meta.progressToken" | §3.2/§7.4 正确 | OK |
| 18 | `resources/read` 响应 `contents` 数组，文本用 `text`，二进制用 `blob` | spec "ReadResourceResult" | §7.5 正确 | OK |
| 19 | `resources/subscribe` 需服务端 capabilities.resources.subscribe | spec "subscribe capability" | §3.3 正确 | OK |
| 20 | `prompts/get` 响应 `messages` 数组，每条含 `role` + `content` | spec "GetPromptResult" | §3.4 正确 | OK |
| 21 | `completion/complete` 响应 `completion.values/total/hasMore` | spec "CompleteResult" | §3.5 正确 | OK |
| 22 | `logging/setLevel` level 枚举 8 个值（debug~emergency） | spec "LoggingLevel enum" | §3.6 正确（RFC 5424） | OK |
| 23 | `roots/list` 是 S→C 请求（服务端反查客户端） | spec "roots/list is server-to-client" | §3.8 正确 | OK |
| 24 | `sampling/createMessage` 是 S→C 请求 | spec "sampling is server-to-client" | §3.9 正确 | OK |
| 25 | JSON-RPC 错误码 -32700/-32600/-32601/-32602/-32603 + -32002 | spec "error codes" | §2.2/附录 B 正确 | OK |
| 26 | protocolVersion 枚举（2024-11-05 / 2025-03-26 / 2025-06-18） | spec "protocol versions" | §4.4 Validate 正确 | OK |
| 27 | `notifications/initialized` 必须在 initialize 响应之后 | spec lifecycle | §5.5 正确 | OK |
| 28 | SSE event 名固定为 `message` | spec "SSE event name is message" | §2.4 正确 | OK |

#### A2A（对照 A2A spec 0.3+）

| # | 核查项 | spec 要求 | 设计结论 | 状态 |
|---|--------|---------|---------|------|
| 1 | HTTP POST + JSON-RPC 2.0 信封 | A2A spec "JSON-RPC 2.0 over HTTP POST" | §2.1 正确 | OK |
| 2 | Agent Card endpoint `/.well-known/agents.json`（GET） | spec "Agent Card well-known URI" | §2.4 正确 | OK |
| 3 | `tasks/send` 同步路径返回 Task 对象 | spec "tasks/send returns Task" | §3 正确 | OK |
| 4 | `tasks/sendSubscribe` 返回 SSE 流 | spec "sendSubscribe returns SSE stream" | §3 正确 | OK |
| 5 | `tasks/get` / `tasks/cancel` / `tasks/pushNotification/set/get` | spec "task methods" | §3 正确 | OK |
| 6 | `tasks/resubscribe` / `tasks/subscribe` | spec 0.3 "subscribe methods" | §3 正确 | OK |
| 7 | `tasks/unsubscribe` | spec 0.3 未定义此方法 | §3 列出但备注"如规范定义" | **存疑 L-3** |
| 8 | Task 状态枚举 7 个：submitted/working/input-required/completed/canceled/failed/unknown | spec "TaskState enum" | §4.1 正确（注意连字符 `input-required`） | OK |
| 9 | `input-required` 用连字符（不是下划线） | spec "input-required" | §4.1 正确 | OK |
| 10 | Message = role + parts + 可选 messageId/taskId/contextId/metadata | spec "Message" | §2.6 正确 | OK |
| 11 | Part kind：text / data / file | spec 0.2 | §2.6 列出 3 种 | OK（0.2 视角） |
| 12 | Part kind：含 data-stream / file-stream | spec 0.3 引入 | §2.6 **缺失** | **缺失 H-4** |
| 13 | TaskStatusUpdateEvent 含 `final: bool` | spec "TaskStatusUpdateEvent" | §2.7 正确 | OK |
| 14 | TaskStatusUpdateEvent 可含 `artifact` | spec 0.3 | §2.7 正确 | OK |
| 15 | PushNotificationConfig 字段：url / token / authentication / userId | spec "PushNotificationConfig" | §2.8 多出 `credentials map` | **多余 H-5** |
| 16 | AgentCard 字段：name/description/url/version/capabilities/skills/authentication/defaultInputModes/defaultOutputModes | spec "AgentCard" | §2.4 正确 | OK |
| 17 | Capabilities：streaming / pushNotifications / stateTransitionHistory | spec "AgentCapabilities" | §2.4 正确 | OK |
| 18 | 错误码 -32001 Task not found / -32002 Task not cancelable / -32003 Push not supported / -32004 Streaming not supported / -32005 State mismatch | spec "error codes" | §3.1 正确 | OK |
| 19 | SSE 事件格式 `event: <name>\ndata: <json>\n\n` | HTML5 §9.2 SSE | §2.3 格式正确 | OK |
| 20 | SSE 事件名固定 `update` | spec 0.3 "event: update" 建议但非强制 | §2.3 固定为 update | **存疑 M-7** |
| 21 | HTTP keep-alive 多 task 复用 TCP 连接 | HTTP/1.1 RFC 7230 | §6.4 正确 | OK |
| 22 | `tasks/cancel` 终态后返回 -32002 | spec "cancel on terminal returns error" | §4.2/§8.5 正确 | OK |
| 23 | `unknown` 是吸收态（无法转出） | spec "unknown is terminal" | §4.2 正确 | OK |
| 24 | Agent Card authentication.schemes 用小写（"bearer"/"basic"/"oauth2"） | spec 示例全小写 | §5.1 字段允许任意大小写 | **存疑 M-8** |
| 25 | SSE 规范引用 | HTML5 §9.2（非 RFC） | §2.3 引用 "RFC 8855" | **错误 C-3** |

---

## 2. MCP 审计

### 2.1 CRITICAL / HIGH / MEDIUM / LOW 问题

#### CRITICAL

##### C-1. `capabilities` 字段标"必填"与 spec 不一致

**位置**：§3.10 扩展表 31 字段映射表，第 4 行。

**问题**：设计文档把 `capabilities` 标为"必填"：

> | `capabilities` | 必填 | initialize 请求/响应 | 能力声明 |

但 MCP spec 2024-11-05 §3.1.1 `InitializeRequest` 中 `capabilities` 是 **optional**：

```typescript
export interface InitializeRequestParams {
  protocolVersion: string;
  capabilities?: ClientCapabilities;  // 可选
  clientInfo: Implementation;
}
```

`InitializeResult`（服务端响应）中 `capabilities` 同样可选。

**影响**：
1. 若实现者按"必填"实现 Validate，会拒绝合法的省略 capabilities 的 initialize 请求（如最小化客户端不声明任何能力）。
2. 反过来，若实现者按 spec 实现为可选，则 §4.4 Validate 规则未覆盖"capabilities 缺失"场景，§3.10 的"必填"声明成为虚假声明。
3. §7.1 默认 initialize 请求体示例携带 `capabilities`，但 spec 不要求——这会让生成的流量被误认为"必带 capabilities"，与真实 LLM 客户端（如不声明 sampling 的最小客户端）行为不符。

**修复建议**：
- §3.10 将 `capabilities` 改为"否（默认空对象）"。
- §4.4 Validate 增加规则：`ClientCapabilities` 为 nil 时默认 `{}`，不报错。
- §7.1 增加"客户端无 capabilities"变体用例（最小客户端）。

##### C-2. `notifications/initialized` 允许 params 与 spec "no parameters" 不一致

**位置**：§7.2 initialized 通知变体第 1 条。

**问题**：设计文档写：

> **变体**：
> - 通知带 params（非标准但允许）：`{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}`。

但 MCP spec 2024-11-05 §3.1.2 `InitializedNotification` 明确：

```typescript
export interface InitializedNotificationParams {}
// "This notification has no parameters."
```

spec 用空 interface 表示"无参数"，但语义上是"客户端不应发送 params 字段"，而非"可发送空对象 params"。多数 SDK 实现会接受空 params（宽松解析），但严格 spec 来说 `params` 字段不应出现。

**影响**：
1. 若实现者按"非标准但允许"实现，生成的流量会带 `params:{}` 字段，被严格 spec 检查器（如 MCP compliance test）标记为"非标准"。
2. §A.1 默认 initialized 通知字节为 `{"jsonrpc":"2.0","method":"notifications/initialized"}`（无 params），与 §7.2 变体矛盾——同一文档对 params 处理不一致。
3. 测试用例 T09 断言"通知对象无 id 字段"，但未断言"无 params 字段"——测试覆盖不足。

**修复建议**：
- §7.2 删除"通知带 params（非标准但允许）"变体，或改为"严格 spec 不允许 params；planner 默认不携带 params 字段"。
- T09 增加"无 params 字段"断言。

#### HIGH

##### H-1. §2.4 vs §6.3 对 HTTP+SSE 旧版 POST 响应语义矛盾

**位置**：§2.4 vs §6.3。

**问题**：
- §2.4 说："客户端 → 服务端：HTTP POST `/mcp`... 响应为 HTTP 202 Accepted（无 body）或 SSE 流。"
- §6.3 PacketConfig 序列表格第 5 行显示：`POST /mcp` 响应为 `HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n...\r\n\r\n{"jsonrpc":"2.0","id":1,"result":{...}}`（200 + JSON body）。

MCP spec 2024-11-05 §2.2 对旧版 HTTP+SSE 的 POST 行为：
- POST 用于客户端发请求/通知给服务端。
- 服务端响应 POST **不应**直接返回 JSON body（那是 Streamable HTTP 的行为）；旧版应通过 GET SSE 流推送响应。
- 但 spec 也允许 POST 返回 202 Accepted（确认收到通知）或 SSE 流（流式响应）。

§6.3 显示 200 + JSON body 是 **Streamable HTTP** 行为，不是旧版 HTTP+SSE 行为。设计文档把它放在 HTTP+SSE 模式下，是传输模式混淆。

**影响**：
1. 实现者按 §6.3 实现旧版 HTTP+SSE 会产出 spec 违规流量（POST 返回 JSON body，真实 MCP 客户端会期望响应走 GET SSE 流）。
2. §6.3 的 14 包序列（含 200 OK JSON 响应）与 §6.4 Streamable HTTP 序列字节几乎一致——两种传输模式没有区分，违反 §1.2 "三种传输"的设计目标。
3. T55 断言"http_sse 模式 POST + SSE 双流"，但 §6.3 不是双流（POST 直接返回 JSON），测试与文档矛盾。

**修复建议**：
- §6.3 修改为：initialize 请求 POST → 服务端响应 202 Accepted（无 body）+ 通过 GET SSE 流推送 initialize 响应（event: message + data: JSON-RPC response）。
- 或明确"本项目简化：旧版 HTTP+SSE 也用 POST 返回 JSON body（spec 允许但罕见）"——并在 §2.4 同步修正。
- T55 增加"GET SSE 流推送响应"断言。

##### H-2. §6.2 teardown 描述与 socks5 参考实现不一致

**位置**：§6.2 stdio 模式 PacketConfig 序列，第 11-14 行 + 文末注释。

**问题**：设计文档 §6.2 表格列出 4 包 teardown：

> | 11 | up | FIN-ACK | (无) |
> | 12 | down | FIN-ACK | (无) |
> | 13 | up | ACK | (无) |
> | 14 | down | ACK | (无)（或合并为 4-way 中 13 省略） |

文末注释："实际 TCP teardown 为 4-way（FIN/ACK, ACK, FIN/ACK, ACK）或合并为 3-way。planner 按 socks5 模板：FIN-ACK, FIN-ACK, ACK（合并中间 ACK）。"

但 socks5.go 第 500-504 行实际实现：

```go
emit("up",   ..., 0x11, nil)  // FIN-ACK (client → server)
clientSeq++
emit("down", ..., 0x11, nil)  // FIN-ACK (server → client)
serverSeq++
emit("up",   ..., 0x10, nil)  // ACK (client → server)
```

即 socks5 实际是 **3 包**：FIN-ACK(up) → FIN-ACK(down) → ACK(up)，**没有第 4 包 ACK(down)**。

设计文档表格列了 4 包（11/12/13/14），但注释说"按 socks5 模板：FIN-ACK, FIN-ACK, ACK（合并中间 ACK）"——即 3 包。表格与注释自相矛盾。

**影响**：
1. 实现者照表格实现会发 4 包（多一个 ACK down），与 socks5 参考实现不一致，导致 MCP 流的 teardown 字节序列与其他协议（socks5/RTSP/SIP）不统一。
2. §A.1 默认字节序列未给出 teardown 部分，实现者只能参考 §6.2 表格——而表格是错的。
3. T57 "stdio 完整会话"断言"6 个 JSON 行 + TCP teardown，时序正确"——但"正确"是 3 包还是 4 包？测试期望不明。

**修复建议**：
- §6.2 表格删除第 14 行（down ACK），与 socks5 一致：3 包 teardown。
- 注释改为："planner 按 socks5 模板：FIN-ACK(up) → FIN-ACK(down) → ACK(up)，3 包。"
- T57 明确断言"teardown 3 包，最后一包为 up ACK"。

##### H-3. `parentId` / `state` / `status` / `contextId` 字段在测试用例中零覆盖（虚假覆盖声明）

**位置**：§3.10 扩展表 31 字段映射 vs §8 测试用例清单。

**问题**：§3.10 声明以下字段：

| 字段 | 出现位置 |
|---|---|
| `contextId` | tools/call、sampling |
| `parentId` | notifications/progress |
| `state` | tools/call（长任务） |
| `status` | sampling 响应 |

但 §8 测试用例中：
- **`contextId`**：T46 "contextId 贯穿调用链"覆盖（OK）。
- **`parentId`**：T47 "parentId 嵌套进度"覆盖（OK）。
- **`state`**：T39-T42 覆盖（OK）。
- **`status`**：T35 "sampling 响应 stopReason=endTurn"——但 T35 只断言 `stopReason`，未断言 `status` 字段。spec 中 `sampling/createMessage` 响应**没有** `status` 字段（`status` 是 MCP 草案早期字段，已移除）；设计文档 §3.10 把 `status` 标为"sampling 响应"字段是 **spec 不一致**。

更严重的是 §4.1 `MCPConfig` 有 `Status string` 字段（默认 "ok"），但 MCP spec 中 sampling 响应字段为 `role`/`content`/`model`/`stopReason`/`stopSequence`，**没有 `status` 字段**。设计文档引入了一个 spec 不存在的字段。

**影响**：
1. 实现者按 §4.1 实现 `Status` 字段，会在 sampling 响应中输出 `"status":"ok"`，被 Wireshark MCP dissector 标记为"未知字段"。
2. §3.10 声明 25 字段覆盖，但 `status` 字段是幻觉字段——虚假覆盖声明。
3. 违反 CLAUDE.md 测试策略规则 1（spec-driven）和规则 5（断言可观察值）：`status` 字段无 spec 依据，且无测试断言其值。

**修复建议**：
- §4.1 删除 `Status string` 字段（spec 不存在）。
- §3.10 删除 `status` 行，或改为"已废弃字段（spec 草案移除）"。
- §4.4 Validate 删除 `Status` 校验规则（第 6 条）。

##### H-4. T57-T60 集成测试未断言字节序列（违反 CLAUDE.md 规则 5）

**位置**：§8.14 集成与端到端 T57-T60。

**问题**：T57-T60 验证点：

| # | 验证点 |
|---|---|
| T57 | TCP 握手 + 6 个 JSON 行 + TCP teardown，时序正确 |
| T58 | HTTP POST 请求 + SSE 响应流，Mcp-Session-Id 一致 |
| T59 | 100 条独立 TCP 流，每条完整会话，无交叉污染 |
| T60 | 单个 JSON 行 8KB，切分为 6 个 TCP segment，Wireshark 重组正确 |

这些验证点都是**结构性断言**（"6 个 JSON 行"、"Mcp-Session-Id 一致"），而非**字节级断言**（"第 4 包 payload 等于 `{"jsonrpc":"2.0","id":1,"method":"initialize",...}`\n"）。

CLAUDE.md 测试策略规则 5："Tests must assert output values and observable behavior, not merely 'it didn't panic' or 'the object exists.'"——T57-T60 断言"时序正确"但未给出具体字节期望，违反此规则。

特别是 T60 "Wireshark 重组正确"——这个断言无法在 Go 单元测试中验证（需要外部 tshark），实际测试只会断言"切分为 6 个 segment"（结构性），不断言每个 segment 的字节内容。

**影响**：
1. 实现者可以产出"6 个 JSON 行"但内容全错的流量，T57 仍通过。
2. 违反 CLAUDE.md 历史教训："TCP-stat 字段（RetransCount/MSS/WindowScale）从未被断言非零，所以忘记填充的代码通过了测试。"
3. 与 socks5_test.go 的断言风格不一致——socks5 测试用 `bytes.Equal` 严格断言每个包的字节。

**修复建议**：
- T57-T60 每个"集成"用例增加 1-2 条字节级断言：例如 T57 断言"第 4 包 payload 以 `{"jsonrpc":"2.0","id":1,"method":"initialize"` 开头，以 `}\n` 结尾"。
- T60 改为"用 tshark 解析生成的 pcap，断言 MCP dissector 识别出 initialize 请求"（真实可验证）。

##### H-5. 多会话测试未验证"实际聚合速率"（违反 CLAUDE.md 规则 6）

**位置**：§8.10 T43-T45 多会话并发。

**问题**：T43-T45 验证点：

| # | 验证点 |
|---|---|
| T43 | 3 条 TCP 流，src_port 递增，sessionId 不同 |
| T44 | 每条流 id 从 1 开始，不跨流共享 |
| T45 | 流1正常，流2 initialize 失败，流3正常 |

这些都是**结构性断言**（src_port 递增、sessionId 不同、id 独立），而非**并发正确性断言**。

CLAUDE.md 测试策略规则 6："For any shared-state or shared-rate component, write a test that measures the aggregate observable behavior under N concurrent workers"——T43-T45 没有"N 并发 worker 实测聚合行为"的用例。

具体缺失：
- 没有断言"3 条流的总包数 = 3 × 单流包数"（防止多流丢包）。
- 没有断言"3 条流的 packet_index 全局唯一"（防止索引冲突）。
- 没有断言"3 条流的 GroupID 路由：同 GroupID 包连续，不同 GroupID 可交错"。
- 没有用 `-race` 跑 100 并发的测试（A37 提到"测试是否用 -race 跑过"但只是 checklist，无对应用例）。

**影响**：
1. 多会话并发可能存在 race condition（如 `IDCounter` 共享、`packetIndex` 冲突），但 T43-T45 不会暴露。
2. 违反 CLAUDE.md 历史教训："pacer concurrency test checked -race was clean (no data race) but never measured the actual aggregate rate, so 8 workers each sleeping independently (8x the configured rate) passed."——T43-T45 同样只检查"无 race"不检查"聚合正确"。

**修复建议**：
- 增加 T61（多会话聚合）：100 并发流，断言总包数 == 100 × 单流包数，packet_index 全局唯一无重复。
- 增加 T62（GroupID 路由）：2 个 GroupID，断言同 GroupID 包连续、不同 GroupID 可交错。
- T43 增加 `-race` 标记的显式断言。

#### MEDIUM

##### M-1. §4.4 Validate 规则第 13 条 `MCPError.Code` 范围错误

**位置**：§4.4 第 13 条。

**问题**：设计文档写：

> 13. `MCPError.Code` 必须在 [-32700, -32000] 范围内（标准 + 服务端错误段），或为正数（MCP 自定义）。实际允许 [-32700, 9999]。

JSON-RPC 2.0 spec §5.1：
- -32768 到 -32000 是预定义错误码段。
- -32000 到 -31999 是"Server error"段（实现自定义）。
- 正数不是 JSON-RPC 错误码（错误码必须为负整数或零）。

设计文档允许"正数（MCP 自定义）"是错误的——JSON-RPC 错误码不能为正。`9999` 上限也无 spec 依据。

**影响**：实现者可能生成 `error.code: 42` 的错误响应，被 JSON-RPC 解析器标记为非法。

**修复建议**：
- 改为：`MCPError.Code` 必须在 [-32700, -32000] 范围内（JSON-RPC 标准 + 服务端错误段）。
- 删除"或为正数"和"实际允许 [-32700, 9999]"。

##### M-2. §5.3 长任务状态机 `state` 字段位置与 spec 不一致

**位置**：§5.3 + §7.15。

**问题**：§5.3 状态机图和 §7.15 字节示例把 `state` 字段放在 `notifications/progress` 的 `params` 中：

```json
{"method":"notifications/progress","params":{"progressToken":14,"progress":10,"total":100,"state":"working","message":"started"}}
```

但 MCP spec 2024-11-05 `ProgressNotification` params 字段为：`progressToken` / `progress` / `total` / `message`——**没有 `state` 字段**。`state` 是 A2A 的概念，不是 MCP 的。

MCP 的长任务状态通过 `tools/call` 响应的 `_meta` 或自定义字段表达，不在 `notifications/progress` 中。

设计文档把 A2A 的 `state` 概念混入 MCP `notifications/progress`，是 **spec 不一致**。

**影响**：
1. 实现者按 §7.15 生成 `notifications/progress` 携带 `state` 字段，被 Wireshark MCP dissector 标记为"未知字段"。
2. §3.10 把 `state` 标为"tools/call（长任务）"——但 §7.15 实际放在 `notifications/progress`，文档内部矛盾。

**修复建议**：
- §7.15 删除 `notifications/progress` 中的 `state` 字段。
- `state` 字段统一放在 `tools/call` 请求/响应的 `_meta.state` 中（§7.15 第 1 个 tools/call 请求已有 `_meta.state:"submitted"`，这是对的）。
- §3.10 `state` 行改为"仅出现在 `_meta`，不在 progress 通知中"。

##### M-3. §7.4 工具名不存在返回 -32601 与 spec 不一致

**位置**：§7.4 变体第 4 条。

**问题**：设计文档写：

> 工具名不存在：JSON-RPC error code -32601 "Method not found"（实际应为 -32602 invalid params，因方法是 tools/call 但参数 name 错——planner 用 -32601 模拟常见实现）。

设计文档自知 spec 应为 -32602，但仍选择 -32601"模拟常见实现"。这是 **spec 违规**：MCP spec §3.2 工具名不存在应返回 -32602 Invalid params（方法是 tools/call 本身存在，参数 name 错误）。

**影响**：
1. 生成的流量被严格 spec 检查器标记为错误码错配。
2. T17 "tools/call 工具名不存在"断言 -32601，固化了 spec 违规。

**修复建议**：
- §7.4 改为：工具名不存在返回 -32602 "Invalid params"，data 字段含 `{"param":"name","reason":"unknown tool"}`。
- T17 同步修改。

##### M-4. §7.13 sampling `includeContext` 字段值未校验

**位置**：§7.13 + §4.4。

**问题**：§7.13 sampling 请求含 `"includeContext":"thisServer"`，变体列出 `"allServers" / "none" / "thisServer"` 三个值。但 §4.4 Validate 规则未校验 `includeContext` 值。

MCP spec `CreateMessageRequest` 中 `includeContext` 枚举为 `"none" | "thisServer" | "allServers"`——3 个合法值。

**影响**：实现者可能生成 `"includeContext":"invalid"`，无 Validate 拦截。

**修复建议**：§4.4 增加 `Parts` / sampling 配置中 `includeContext` ∈ {`""`, `"none"`, `"thisServer"`, `"allServers"`} 的校验规则。

##### M-5. §6.5 多会话"src_port 递增"未说明冲突处理

**位置**：§6.5。

**问题**：§6.5 说"每条流独立 4-tuple（src_port 递增，dst_port 相同）"，但未说明：
- src_port 起始值如何选（随机 vs 递增 from 50001）？
- 多会话并发时 src_port 冲突如何处理（如 50001 已被占用）？
- src_port 是否复用 socks5 的 `randUint32` 随机策略？

socks5.go 第 311-318 行用 `randUint32()` 随机 ISN，但 src_port 由 `spec.SrcPort` 决定（外层 strategy 控制）。MCP 文档说"src_port 递增"，但没说从哪个基数递增。

**影响**：实现者可能用固定基数 50001 递增，导致多会话 src_port 可预测（与真实 LLM 客户端随机 src_port 行为不符）。

**修复建议**：§6.5 明确"src_port 由 strategy 层 `inc`/`rand` 决定，planner 不强制；默认建议 `rand` 范围 [49152, 65535]"。

##### M-6. §8 测试用例计数与实际不符

**位置**：§8 各小节标题 vs 实际用例数。

**问题**：
- §8.1 标"6 条"，实际 T01-T06 共 6 条（OK）。
- §8.2 标"6 条"，实际 T07-T12 共 6 条（OK）。
- §8.3 标"5 条"，实际 T13-T17 共 5 条（OK）。
- §8.4 标"5 条"，实际 T18-T22 共 5 条（OK）。
- §8.5 标"4 条"，实际 T23-T26 共 4 条（OK）。
- §8.6 标"5 条"，实际 T27-T31 共 5 条（OK）。
- §8.7 标"4 条"，实际 T32-T35 共 4 条（OK）。
- §8.8 标"3 条"，实际 T36-T38 共 3 条（OK）。
- §8.9 标"4 条"，实际 T39-T42 共 4 条（OK）。
- §8.10 标"3 条"，实际 T43-T45 共 3 条（OK）。
- §8.11 标"2 条"，实际 T46-T47 共 2 条（OK）。
- §8.12 标"6 条"，实际 T48-T53 共 6 条（OK）。
- §8.13 标"3 条"，实际 T54-T56 共 3 条（OK）。
- §8.14 标"4 条"，实际 T57-T60 共 4 条（OK）。
- 合计：6+6+5+5+4+5+4+3+4+3+2+6+3+4 = 60 条（与"60 条"声明一致，OK）。

计数这次是对的。但 §8 开头说"共 48 条"，与文末"总计：60 条"矛盾——§8 开头：

> 测试用例从本设计文档 §3-§7 派生，覆盖正向、负向、边界、异常、并发、状态机、字段映射、传输模式。共 **48 条**，远超最低 30 条要求。

但实际 60 条。这是 **文档内部矛盾**。

**影响**：实现者可能误以为"只写 48 条就够了"。

**修复建议**：§8 开头"48 条"改为"60 条"。

##### M-7. 负向用例占比不足 25%（违反 CLAUDE.md 规则 2）

**位置**：§8 全部 60 条。

**问题**：CLAUDE.md 测试策略规则 2 + §9.7 A34 要求"负向用例占比 ≥ 25%（60 条中 ≥ 15 条负向）"。

实际负向用例：
- T05/T06（JSON-RPC 字段校验）
- T12（跳过 initialize）
- T17（工具名不存在）
- T22（uri 不存在）
- T31（progress 缺 progressToken）
- T48/T49/T50/T51/T52/T53（边界与异常）

合计约 12 条负向，占比 20% < 25%。

**影响**：违反 CLAUDE.md 规则 2 "Cover failure paths, not just the happy path"。

**修复建议**：增加至少 3 条负向用例：
- T61：`initialize` 缺 protocolVersion → Validate 拒绝。
- T62：`tools/call` 缺 name 参数 → JSON-RPC -32602。
- T63：`resources/subscribe` 服务端 capabilities 不支持 → -32601。

#### LOW

##### L-1. §1.4 stdio 默认端口 8081 与 HTTP 模式相同，易混淆

**位置**：§1.4。

**问题**：§1.4 说"stdio 模式默认端口 8081（与 HTTP 模式一致，便于复用）"。但 stdio 是进程间通信，不是网络流量——设计文档自己也说"本项目不直接生成 stdio 流量（stdio 是进程间通信，不是网络流量）"。仍给它分配端口 8081 是矛盾的。

**影响**：实现者可能误以为 stdio 模式需要 TCP 连接到 8081，而实际上 stdio 模式只是"通过 SSH 隧道转发的 stdio"——此时端口应是 22（SSH），不是 8081。

**修复建议**：§1.4 改为"stdio 模式默认走 TCP 22（SSH 隧道）+ 应用层行分隔 JSON；如用户指定 dst_port=8081，则走 TCP 8081 + 行分隔 JSON（模拟本地 stdio 转发）"。

##### L-2. §4.1 `IDCounter` 默认值规则与 §5.4 矛盾

**位置**：§4.1 字段注释 vs §4.3 默认值表 vs §5.4。

**问题**：
- §4.1：`IDCounter int` 注释"first request id; 0=1"。
- §4.3：`IDCounter` 默认值 1，触发条件 0。
- §5.4：id 配对规则说"planner 用 IDCounter 递增分配"。

但 §4.4 Validate 第 8 条说"`IDCounter` ≥ 0"——允许 0，但 0 会触发默认值 1。这是循环引用：Validate 接受 0，但 Plan 把 0 改成 1。语义上 OK，但注释不清。

**影响**：实现者可能误以为 IDCounter=0 是合法值（实际会被覆盖为 1）。

**修复建议**：§4.1 注释改为"first request id; 0 is treated as 1 in Plan（Validate accepts 0 but Plan defaults to 1）"。

##### L-3. §3.10 "剩余 6 字段"声明与实际不符

**位置**：§3.10 末尾。

**问题**：§3.10 末尾：

> 剩余 6 字段（`protocolVersion`、`method`、`params`、`result`、`error`、`clientInfo`/`serverInfo`）属于 JSON-RPC 与 MCP 核心字段，已在 §2 与 §3.1 覆盖。

实际列出 7 个字段名（protocolVersion/method/params/result/error/clientInfo/serverInfo），但说"6 字段"——`clientInfo`/`serverInfo` 用斜杠合并算 1 个，但实际是 2 个字段。

**影响**：计数错误（小问题）。

**修复建议**：改为"剩余 7 字段"或拆分为独立行。

##### L-4. 附录 B 错误码 -32800 "Request cancelled" 非 MCP spec 标准

**位置**：附录 B。

**问题**：附录 B 列出 -32800 "Request cancelled"，但 MCP spec 2024-11-05 没有定义 -32800。这是 JSON-RPC 自定义错误码段（-32000 到 -32099）之外的码。

虽然 -32800 在某些 SDK 实现中出现，但 spec 没有标准化。设计文档列出此码但未说明"非 spec 标准"。

**影响**：实现者可能认为 -32800 是 spec 标准，在合规测试中被标记为非法码。

**修复建议**：附录 B 标注"-32800 非 spec 标准，部分 SDK 实现；planner 可选生成"。

### 2.2 字段覆盖率（扩展表 31，25 字段）

§3.10 声明覆盖 25 字段（扩展表 31 中除 6 个核心 JSON-RPC 字段外的 25 个），逐字段对照 §8 测试用例：

| # | 字段 | spec 依据 | 设计位置 | 测试用例 | 状态 |
|---|------|----------|---------|---------|------|
| 1 | `level` | notifications/message | §3.6 | T27 | OK |
| 2 | `logger` | notifications/message | §3.6 | T28（隐含） | **缺测** M-9 |
| 3 | `data` | notifications/message | §3.6 | T28 | OK |
| 4 | `inputSchema` | tools/list 响应 | §3.2 | T13 | OK |
| 5 | `arguments` | tools/call 请求 | §3.2 | T14 | OK |
| 6 | `isError` | tools/call 响应 | §3.2 | T15 | OK |
| 7 | `content` | tools/call/prompts/sampling | §3.2/§3.4/§3.9 | T14/T16/T25/T35 | OK |
| 8 | `capabilities` | initialize 请求/响应 | §3.1 | T07/T08 | OK（但 spec 可选，见 C-1） |
| 9 | `roots` | roots/list 响应 | §3.8 | T32 | OK |
| 10 | `uri` | resources/* | §3.3 | T19/T21/T22 | OK |
| 11 | `mimeType` | resources/read、tools/call(image) | §3.3/§3.2 | T19/T20/T16 | OK |
| 12 | `authentication` | initialize 响应 | §7.14 | T38 | OK |
| 13 | `schemes` | authentication | §7.14 | T38 | OK |
| 14 | `credentials` | initialize 请求 | §7.14 | **无** | **缺测** M-9 |
| 15 | `id` | 请求/响应 | §2.1 | 全部请求用例 | OK |
| 16 | `contextId` | tools/call、sampling | §7.17 | T46 | OK |
| 17 | `sessionId` | HTTP 头 | §2.4 | T58 | OK |
| 18 | `parentId` | notifications/progress | §7.17 | T47 | OK |
| 19 | `state` | tools/call（长任务） | §7.15 | T39-T42 | OK（但 spec 不在 progress，见 M-2） |
| 20 | `role` | prompts/get、sampling | §3.4/§3.9 | T24/T25/T35 | OK |
| 21 | `parts` | prompts/get（multi-part） | §3.4 | **无**（T25 是多消息多 content，不是 parts 字段） | **缺测** M-9 |
| 22 | `metadata` | 任意 `_meta` | §7.4/§7.17 | T46（隐含） | **缺测** M-9 |
| 23 | `status` | sampling 响应 | §3.10 | **无** | **spec 不存在，见 H-3** |
| 24 | `pushNotification` | tools/call（长任务） | §3.10 | **无** | **缺测** M-9 |
| 25 | `verificationToken` | pushNotification | §3.10 | **无** | **缺测** M-9 |

**覆盖率统计**：
- 有测试覆盖：15/25 = 60%
- 缺测：6/25 = 24%（`logger`/`credentials`/`parts`/`metadata`/`pushNotification`/`verificationToken`）
- spec 不存在字段：1/25 = 4%（`status`，见 H-3）
- 部分覆盖（位置错）：2/25 = 8%（`state` 见 M-2，`capabilities` 见 C-1）

**结论**：§3.10 声明"31 字段映射"但实际 25 字段中 6 个零覆盖、1 个是幻觉字段、2 个位置错——**实际有效覆盖率约 60%**，违反 CLAUDE.md 规则 1（spec-driven）和规则 8（adversarial review of test quality）。

### 2.3 测试用例质量

#### 2.3.1 正向/负向/边界分布

| 类型 | 数量 | 占比 | CLAUDE.md 要求 | 状态 |
|------|------|------|---------------|------|
| 正向 | 38 | 63% | - | OK |
| 负向 | 12 | 20% | ≥25% | **不足** M-7 |
| 边界 | 10 | 17% | - | OK |
| 集成 | 4 | 7% | - | OK（但字节断言不足，见 H-4） |
| 并发 | 3 | 5% | - | OK（但聚合断言不足，见 H-5） |

#### 2.3.2 spec-derived 测试逐项核查（CLAUDE.md 规则 1）

| spec 章节 | 设计章节 | 测试用例 | 状态 |
|----------|---------|---------|------|
| §3.1 lifecycle (initialize/initialized/ping) | §3.1/§7.1-7.3 | T07-T12 | OK |
| §3.2 tools (list/call) | §3.2/§7.4 | T13-T17 | OK |
| §3.3 resources (list/read/subscribe/unsubscribe) | §3.3/§7.5-7.6 | T18-T22 | OK（缺 unsubscribe 用例） |
| §3.4 prompts (list/get) | §3.4/§7.7 | T23-T25 | OK |
| §3.5 completion | §3.5/§7.8 | T26 | OK（仅 1 条，偏少） |
| §3.6 logging | §3.6/§7.9 | T27-T28 | OK |
| §3.7 notifications (cancelled/progress) | §3.7/§7.10-7.11 | T29-T31 | OK |
| §3.8 roots | §3.8/§7.12 | T32-T33 | OK |
| §3.9 sampling | §3.9/§7.13 | T34-T35 | OK（仅 2 条，偏少） |
| §7.14 auth | §7.14 | T36-T38 | OK |
| §7.15 state machine | §7.15 | T39-T42 | OK |
| §7.16 multi-session | §7.16 | T43-T45 | OK |
| §7.17 contextId/parentId | §7.17 | T46-T47 | OK |
| §7.18 boundary | §7.18 | T48-T53（部分） | **部分覆盖**（20 边界只测 6） |
| §7.19 error | §7.19 | T50-T53 | OK |
| resources/unsubscribe | §3.3 | **无** | **缺测** M-9 |
| resources/templates/list | spec 有 | **无** | **缺测** M-9 |
| notifications/resources/list_changed | §3.3 | **无** | **缺测** M-9 |

#### 2.3.3 测试质量违规汇总

| CLAUDE.md 规则 | 违反项 | 严重度 |
|---------------|-------|--------|
| 规则 1 spec-driven | 6 字段零覆盖（§2.2） | M-9 |
| 规则 2 失败路径 | 负向占比 20% < 25% | M-7 |
| 规则 5 断言可观察值 | T57-T60 字节断言不足 | H-4 |
| 规则 6 并发正确性 | T43-T45 聚合断言不足 | H-5 |
| 规则 7 失败测试先行 | 未提及（实现阶段才检查） | - |
| 规则 8 测试质量对抗 | §9.7 A34 设 25% 阈值但自身不达标 | M-7 |

### 2.4 与 internal/mcp/ 隔离性

#### 2.4.1 包路径隔离（OK）

- `internal/mcp/`（已存在）：MCP 服务器实现，依赖 `modelcontextprotocol/go-sdk/mcp`。
- `internal/protocol/mcp/`（本设计新增）：MCP 流量生成器，仅依赖 `internal/core`。

§11.3 明确包名都为 `mcp` 但路径不同，导入用别名区分：

```go
mcpserver "github.com/.../internal/mcp"
mcpproto "github.com/.../internal/protocol/mcp"
```

这是合理的隔离方案。但 §11.5 说"明确不共享以下代码"——这一点需要核实 internal/mcp/ 是否真的有可被复用的 JSON-RPC 序列化代码。

#### 2.4.2 潜在耦合点

| # | 检查项 | 状态 |
|---|--------|------|
| 1 | `internal/protocol/mcp/` 是否 import `internal/mcp/`？ | 设计声明"不 import"，OK |
| 2 | `internal/mcp/` 是否 import `internal/protocol/mcp/`？ | 设计未声明，应也不 import |
| 3 | FlowSpec.MCP 字段与 internal/mcp.Server 命名冲突？ | §11.3 声明无冲突（不同包），OK |
| 4 | 端口冲突？ | §11.2 说"端口可以相同（监听 vs 发送不冲突）"，OK |
| 5 | JSON-RPC 序列化代码复用？ | §11.5 声明不复用，OK |
| 6 | 默认 serverInfo.Name 是否冲突？ | §11.4 说 internal/mcp 用 "flowB"，protocol/mcp 用 "trafficgen-server"，**已区分** OK |

#### 2.4.3 隔离性结论

隔离设计**合理且完整**。但有一个潜在风险：

- §11.2 提到"若用户想测试'自身 MCP 服务器'，可生成流量到 `127.0.0.1:8081`，此时 `internal/mcp/` 会接收并响应——但 planner 不读取响应"——这是**巧合而非设计**。如果未来 internal/mcp/ 的行为变化（如端口改为 8082），文档需同步更新。

**建议**：§11.2 增加"此巧合非设计保证；如需真实回环测试，应显式启动独立 MCP 服务器"。

---

## 3. A2A 审计

### 3.1 CRITICAL / HIGH / MEDIUM / LOW 问题

#### CRITICAL

##### C-3. SSE 规范引用 "RFC 8855" 错误（SSE 没有 RFC）

**位置**：§2.3 表格"每个 SSE 事件的 data 是一个完整的 JSON-RPC 响应对象"上方：

> SSE 事件格式（RFC 8855）：

以及 §12 参考资料：

> SSE（Server-Sent Events，RFC 8855）

**问题**：SSE（Server-Sent Events）**没有独立的 RFC**。SSE 规范是 HTML Living Standard §9.2 "Server-sent events"（https://html.spec.whatwg.org/multipage/server-sent-events.html）的一部分，由 WHATWG 维护。

"RFC 8855" 不存在（RFC 索引中 8855 是 "The WebSocket Subprotocol Name 'binary.eit' Registration"——与 SSE 无关）。

设计文档两处引用 "RFC 8855" 是**幻觉引用**——这违反 CLAUDE.md 测试策略规则 1（spec-derived）的精神：如果实现者按"RFC 8855"查阅规范，会查到无关文档，导致对 SSE 格式的理解错误。

**影响**：
1. 实现者按"RFC 8855"搜索，找不到 SSE 规范，可能误用 RFC 8855 的内容（WebSocket subprotocol）实现 SSE，产出畸形字节。
2. §11.6 已知坑第 1-2 条正确描述了 SSE 格式（`\n\n` 结尾、多行 data），但规范引用错误——文档内部矛盾（格式对，引用错）。

**修复建议**：
- §2.3 和 §12 改为"SSE（Server-Sent Events，HTML Living Standard §9.2）"或"SSE（WHATWG HTML §9.2）"。
- 增加 URL：https://html.spec.whatwg.org/multipage/server-sent-events.html

##### C-4. §5.2 `A2APushNotificationConfig` 多出 `credentials map[string]string` 字段（spec 无）

**位置**：§5.2 `A2APushNotificationConfig` 结构体。

**问题**：设计文档定义：

```go
type A2APushNotificationConfig struct {
    URL            string               `json:"url"`
    Token          string               `json:"token,omitempty"`
    Authentication *A2AAuthentication   `json:"authentication,omitempty"`
    UserID         string               `json:"user_id,omitempty"`
    Credentials    map[string]string    `json:"credentials,omitempty"`  // spec 无此字段
}
```

A2A spec 0.3 `PushNotificationConfig` 字段为：`url` / `token` / `authentication` / `userId`——**4 个字段**，没有 `credentials` map。

设计文档多出的 `Credentials map[string]string` 是**幻觉字段**——无 spec 依据。

**影响**：
1. 实现者按此结构生成 PushNotificationConfig JSON，会多出 `credentials` 字段，被严格 spec 检查器标记为"未知字段"。
2. §8.6.3 "设置带 credentials map"用例固化了 spec 违规。
3. 违反 CLAUDE.md 测试策略规则 1（spec-driven）：测试了一个 spec 不存在的字段。

**修复建议**：
- §5.2 删除 `Credentials map[string]string` 字段。
- §8.6.3 改为测试 `authentication.credentials`（A2AAuthentication 的 credentials 字段，spec 有）。

#### HIGH

##### H-6. §2.6 Part kind 缺失 `data-stream` / `file-stream`（spec 0.3 引入）

**位置**：§2.6 Part 联合类型表。

**问题**：设计文档列出 3 种 Part kind：

| kind | 字段 |
|------|------|
| text | kind, text, metadata? |
| data | kind, data, metadata? |
| file | kind, file (含 bytes/uri/mimeType/name), metadata? |

A2A spec 0.3 引入了 2 种新 Part kind：
- `data-stream`：流式结构化数据（用于 LLM 流式输出 token 流）。
- `file-stream`：流式文件传输（用于大文件分块）。

spec 0.3 `Part` 联合类型有 5 种 kind。设计文档只列 3 种，缺 `data-stream` / `file-stream`。

**影响**：
1. 实现者无法生成流式 Part 流量（如 LLM token 流），无法测试 A2A 0.3 客户端的流式 Part 解析。
2. §1.3 设计目标说"方法覆盖：tasks/send、tasks/sendSubscribe..."但未提及 Part kind 覆盖——遗漏。
3. 违反 §1.3 "wire-format 正确"——缺失 spec 0.3 字段。

**修复建议**：
- §2.6 增加 `data-stream` 和 `file-stream` 两行。
- §5.2 `A2APart` 增加 `DataStream` / `FileStream` 字段（或用 interface）。
- §8 增加 T64/T65 测试 data-stream / file-stream Part。

##### H-7. §6.1 teardown 序列号描述与 socks5 参考实现不一致（同 H-2）

**位置**：§6.1 单 task 同步路径时序图末尾。

**问题**：§6.1 时序图末尾：

```
|------- FIN-ACK --------------------------->|  TCP 挥手 #1
|<------ ACK --------------------------------|
|<------ FIN-ACK ----------------------------|  TCP 挥手 #3
|------- ACK ------------------------------->|
```

这是标准 4-way teardown（FIN-ACK / ACK / FIN-ACK / ACK）。但 socks5.go 第 500-504 行实现是 3 包（FIN-ACK / FIN-ACK / ACK，合并中间 ACK）。

A2A §6.1 时序图显示 4 包，但实际 planner 应按 socks5 模板发 3 包——文档与预期实现不一致。

**影响**：
1. 实现者照时序图实现会发 4 包，与 socks5 参考实现不一致。
2. T56 "e2e 单 task 同步"断言"完整握手/1 task/挥手"——但"完整挥手"是 3 包还是 4 包？测试期望不明。

**修复建议**：
- §6.1 时序图改为 3 包 teardown（与 socks5 一致），或明确"planner 发 3 包，真实 TCP 实现 4 包"。
- T56 明确断言"teardown 3 包"。

##### H-8. §5.2 `Task.Streaming` 字段"显式覆盖方法默认"语义与 §3 方法表矛盾

**位置**：§5.2 `Streaming *bool` 字段注释 vs §3 方法表。

**问题**：
- §5.2 注释："Implied true for sendSubscribe/subscribe/resubscribe; explicit flag overrides the method default (useful for testing a server that returns SSE for tasks/send, which is a spec violation)."
- §3 方法表："tasks/sendSubscribe → SSE 流"、"tasks/send → Task（同步）"。

矛盾点：
1. §3 说 sendSubscribe 恒返回 SSE 流（方法语义）。
2. §5.2 说 `Streaming *bool` 可覆盖方法默认——即 `Streaming=false` + `sendSubscribe` 可生成同步响应？

但 spec 中 `sendSubscribe` 的语义是**流式**（spec 0.3 "tasks/sendSubscribe: Sends a request to an agent to start a task and streams the response"）——不可降级为同步。`Streaming=false` + `sendSubscribe` 是 **spec 违规**，设计文档允许这种违规测试，但未在 Validate 中标记为警告。

**影响**：
1. 实现者可能生成 `sendSubscribe` + 同步响应的流量，被严格 spec 检查器标记为非法。
2. §10.9 不变性对抗第 1 条"尝试 Method='tasks/send' + Streaming=true：planner 输出 SSE（spec 违规测试，用户显式覆盖）"——这是显式承认 spec 违规，但未说明 Validate 是否拒绝或警告。

**修复建议**：
- §5.2 注释改为："`Streaming *bool` 仅在 method='tasks/send' 时有意义（覆盖默认同步为流式，spec 违规测试）；对 sendSubscribe/subscribe/resubscribe，Streaming 必须为 true 或 nil，false 会被 Validate 拒绝。"
- §4.4（A2A 文档无 §4.4，应在 §5.4 默认值后增加 Validate 规则）增加校验：`Streaming=false` + 流式方法 → Validate 拒绝。

##### H-9. §8.3.2 / §8.3.3 SSE 事件数与 StateTransitionHistory 长度关系不清

**位置**：§8.3.2 + §8.3.3 + §8.9 / §8.10。

**问题**：
- §8.3.2："StateTransitionHistory = [{from:null,to:submitted},{from:submitted,to:working},{from:working,to:completed}]，SSE 流：3 个事件（submitted 起步事件可选，planner 默认从 working 开始发）"——说 3 个事件，但又说"默认从 working 开始发"（即 2 个事件？）。
- §8.3.3："StateTransitionHistory = [{to:submitted},{to:working},{to:input-required},{to:working},{to:completed}]，SSE 流：5 个事件"——5 个事件。
- §8.9："StateTransitionHistory = [{to:submitted,timestamp:t0},{from:submitted,to:working,timestamp:t1},{from:working,to:completed,timestamp:t2}]，同步路径：响应 result.status.state='completed'，metadata.stateTransitionHistory 含 3 条；流式路径：SSE 流 3 个事件"。

矛盾点：
1. §8.3.2 说"3 个事件"但"submitted 起步事件可选，planner 默认从 working 开始发"——实际是 2 个事件还是 3 个？
2. §8.3.3 说"5 个事件"但 StateTransitionHistory 是 5 条 transition——是否每个 transition 对应 1 个 SSE 事件？还是 transition 的 `to` 字段对应 SSE 事件的 state？
3. §8.9 说"流式路径：SSE 流 3 个事件"——3 个 transition = 3 个事件，与 §8.3.2 "3 个事件"一致，但 §8.3.2 又说"默认从 working 开始发"（2 个）。

**影响**：
1. 实现者不清楚"每个 transition 对应 1 个 SSE 事件"还是"每个 state 对应 1 个 SSE 事件"。
2. 测试用例 T08 "SSE 流 ≥2 事件"——为何 ≥2 而不是 =3？语义模糊。
3. 违反 CLAUDE.md 规则 5（断言可观察值）：测试期望不精确。

**修复建议**：
- §8.3 明确规则："SSE 事件数 == StateTransitionHistory 长度；每个 SSE 事件的 state == 对应 transition 的 `to` 字段；最后事件 `final:true`。"
- §8.3.2 改为"SSE 流：3 个事件（submitted/working/completed），最后事件 final:true"。
- T08 改为"SSE 流 = 3 事件"（精确数）。

##### H-10. §8.16.3 / §8.16.4 "同 sessionId 多 task"与"不同 sessionId 多 task"未说明 TCP 连接复用规则

**位置**：§8.16.3 + §8.16.4 + §7.6。

**问题**：
- §8.16.3："Tasks = [task-1 (sess-1), task-2 (sess-1), task-3 (sess-1)]，单 TCP 连接，3 个 HTTP 请求/响应串行，验证：sessionId 字段一致，TCP 序列号连续"。
- §8.16.4："Tasks = [task-1 (sess-1), task-2 (sess-2)]，单 TCP 连接（keep-alive），两个 task 不同 sessionId，验证：HTTP keep-alive 连接复用，sessionId 字段切换"。
- §7.6："多 sessionId 场景：单 `A2AConfig` 内 Tasks 数组中各 task 可携带不同 sessionId，planner 不为不同 sessionId 拆分 TCP 连接（HTTP/1.1 允许连接复用）。若用户需要为每个 sessionId 独立 TCP 流，用 `Count` + 单 task 配置实现。"

矛盾点：
1. §8.16.3 说"同 sessionId 多 task 单 TCP 连接"——OK，HTTP keep-alive。
2. §8.16.4 说"不同 sessionId 多 task 单 TCP 连接"——OK，HTTP keep-alive 允许。
3. 但两者都未说明：**多 task 在单 TCP 连接上是串行还是并发？** HTTP/1.1 是请求-响应串行（pipeline 几乎不用），设计文档应明确"串行"。
4. §8.16.3 说"TCP 序列号连续"——但多 task 在同一 TCP 连接上，每个 task 的 HTTP 请求/响应会推进 seq，"连续"是必然的（TCP 保证），这个断言无意义。

**影响**：
1. 实现者可能误以为多 task 可并发（HTTP/2 多路复用），但 A2A spec 0.3 基于 HTTP/1.1，是串行。
2. T36/T37 断言"sessionId 一致/切换"但未断言"task 串行（task-2 请求在 task-1 响应之后）"。

**修复建议**：
- §7.6 明确"多 task 在单 TCP 连接上**串行**（HTTP/1.1 请求-响应模型），task-2 请求在 task-1 响应之后"。
- T36/T37 增加"task-2 请求的 TCP seq > task-1 响应的 seq"断言。

#### MEDIUM

##### M-10. §3 方法表列出 `tasks/unsubscribe` 但 spec 0.3 未定义

**位置**：§3 方法表第 9 行 + §3.1 错误码表。

**问题**：§3 方法表列出：

> | tasks/unsubscribe | POST | id | bool | 取消订阅（如规范定义） |

A2A spec 0.3+ 中**没有** `tasks/unsubscribe` 方法。spec 0.3 的方法集是：`tasks/send` / `tasks/sendSubscribe` / `tasks/get` / `tasks/cancel` / `tasks/pushNotification/set` / `tasks/pushNotification/get` / `tasks/resubscribe` / `tasks/subscribe`——8 个方法。

设计文档列出 9 个方法（多出 `tasks/unsubscribe`），备注"如规范定义"——这是**存疑字段**。如果 spec 后续版本定义了，OK；如果未定义，则是幻觉方法。

**影响**：
1. 实现者可能实现 `tasks/unsubscribe` 路由，但真实 A2A 服务端不识别此方法，会返回 -32601 Method not found。
2. 测试用例无 `tasks/unsubscribe` 用例（§9.1 T01-T15 没有）——声明但无测试，违反 CLAUDE.md 规则 3。

**修复建议**：
- §3 方法表删除 `tasks/unsubscribe` 行，或改为"v2 候选（spec 未定义）"。
- §1.3 设计目标"方法覆盖"列表删除 `tasks/unsubscribe`。

##### M-11. §2.4 Agent Card `authentication.schemes` 大小写未规范

**位置**：§2.4 + §5.1 `A2AAuthentication`。

**问题**：
- §2.4 示例：`"authentication": {"schemes":["bearer"]}`（小写）。
- §5.1 `A2AAuthentication.Schemes []string` 字段允许任意大小写。
- §5.1 注释：`// "bearer", "basic", "oauth2"`（小写）。
- §8.14.5："AgentCard.Authentication = {schemes:["bearer","basic"]}"（小写）。

A2A spec 0.3 示例全用小写（`"bearer"` / `"basic"` / `"oauth2"`），但 spec 没有明确枚举值或大小写要求。

MCP spec 的 `authentication.schemes` 用首字母大写（`"Bearer"` / `"Basic"` / `"OAuth2"`）——见 MCP §7.14。

设计文档 A2A 部分用小写，MCP 部分用大写——**两份文档大小写不一致**，可能引起混淆。

**影响**：
1. 实现者可能在小写/大写之间混淆，生成 `"schemes":["Bearer"]`（A2A 应小写）或 `"schemes":["bearer"]`（MCP 应大写）。
2. §4.4 MCP Validate 第 4 条要求 `Auth.Schemes` ∈ {`"Bearer"`, `"Basic"`, `"OAuth2"`, `"Negotiate"`}（大写），但 A2A 无对应 Validate 规则——不对称。

**修复建议**：
- A2A §5.4（应在 §5.4 默认值后增加 Validate 规则）增加：`A2AAuthentication.Schemes` 中每个值应小写（`"bearer"` / `"basic"` / `"oauth2"`），Validate 拒绝大写。
- 或在 §2.4 明确"A2A schemes 用小写（与 MCP 大写不同）"。

##### M-12. §4.2 状态转换表 "input-required → completed" 标"罕见"但未禁止

**位置**：§4.2 合法状态转换表倒数第 1 行。

**问题**：§4.2 表格最后一行：

> | input-required | completed | 服务端在 input 状态决定完成（罕见） |

A2A spec 0.3 中 `input-required` 状态语义是"服务端需要客户端补充输入"——服务端在此状态等待客户端输入，不应直接 completed。spec 0.3 没有明确允许 `input-required → completed` 转换。

设计文档允许此转换并标"罕见"，但未说明是否 Validate 接受。

**影响**：
1. 实现者可能生成 `input-required → completed` 流量，被严格 spec 检查器标记为非法转换。
2. §8.10 状态机用例未覆盖此转换——声明但无测试。

**修复建议**：
- §4.2 删除 `input-required → completed` 行，或改为"spec 未明确，Validate 警告但不拒绝"。
- §8 增加 T66 测试此转换（如保留）。

##### M-13. §6.9 "unknown 状态不带 message" 与 §8.13 一致但与 spec 不完全一致

**位置**：§6.9 + §8.13。

**问题**：§6.9："unknown 状态语义不明，不应携带业务 message"。§8.13："State='unknown'，不带 status.message（语义不明）"。

A2A spec 0.3 中 `unknown` 状态定义是"状态不可确定（超时/丢失）"——spec 没有明确禁止 `status.message`。设计文档自行决定"不带 message"，这是**设计选择**而非 spec 要求。

**影响**：
1. 实现者按"不带 message"实现，但真实 A2A 服务端在 unknown 状态可能携带 message（如 `"message":{"role":"agent","parts":[{"kind":"text","text":"timeout"}]}`）。
2. §10.2 "unknown 状态不带 status.message" 是设计决策，应明确标注"本项目选择，非 spec 强制"。

**修复建议**：
- §6.9 改为："unknown 状态语义不明，本项目选择不带 status.message（spec 未禁止；如需携带，用户可显式设置 StatusMessage）"。

##### M-14. §8.18.3 "parts 空数组 Validate 拒绝"与 §1.3 "边界覆盖 parts 空数组"措辞矛盾

**位置**：§1.3 vs §8.18.3。

**问题**：
- §1.3 设计目标："边界覆盖：task id 空、session id 空、parts 空数组、metadata 空、pushNotification url 超长、skills tags 空数组、stateTransitionHistory 空。"
- §8.18.3："Message.Parts = []，Validate 拒绝（parts 至少 1 个）；planner 不接受空 parts。"

§1.3 说"边界覆盖 parts 空数组"——暗示测试此边界；§8.18.3 说"Validate 拒绝"——是负向测试。两者语义一致（测试 parts 空数组被拒绝），但 §1.3 把它与其他"接受的边界"（如 task id 空、metadata 空）并列，容易误解为"parts 空数组被接受"。

**影响**：实现者可能误以为 parts 空数组是合法边界（如 metadata 空），实际是非法输入。

**修复建议**：§1.3 改为"边界覆盖：task id 空（接受）、session id 空（接受）、parts 空数组（拒绝）、metadata 空（接受）、..."——明确区分接受/拒绝。

##### M-15. §9 测试用例计数错误

**位置**：§9 各小节标题。

**问题**：
- §9.1 "正向用例（15 条）"——实际 T01-T15 共 15 条（OK）。
- §9.2 "Agent Card 用例（4 条）"——T16-T19 共 4 条（OK）。
- §9.3 "状态机用例（6 条）"——T20-T25 共 6 条（OK）。
- §9.4 "认证用例（4 条）"——T26-T29 共 4 条（OK）。
- §9.5 "metadata 用例（4 条）"——T30-T33 共 4 条（OK）。
- §9.6 "多任务/多会话用例（4 条）"——T34-T37 共 4 条（OK）。
- §9.7 "边界用例（8 条）"——T38-T45 共 8 条（OK）。
- §9.8 "负向用例（10 条）"——T46-T55 共 10 条（OK）。
- §9.9 "集成用例（4 条）"——T56-T59 共 4 条（OK）。
- §9.10 "wire-format 验证用例（4 条）"——T60-T63 共 4 条（OK）。
- 合计：15+4+6+4+4+4+8+10+4+4 = 63 条（与"63 条"声明一致，OK）。

计数这次是对的。但 §1.3 设计目标说"状态机覆盖：submitted → working → input-required/completed/canceled/failed/unknown 全路径"——`unknown` 在 §9.3 T24 覆盖，OK。但 §9.3 标"6 条"实际是 T20-T25，其中 T25 是"stateTransitionHistory 空（流式）"，不是状态机转换——**分类错误**（T25 应归 §9.7 边界）。

**影响**：分类错误导致状态机用例实际 5 条（T20-T24），不是 6 条。

**修复建议**：§9.3 改为"5 条"，T25 移到 §9.7 边界用例（变 9 条）。

#### LOW

##### L-5. §2.1 HTTP 请求示例缺 `Content-Length` 头

**位置**：§2.1 HTTP 请求示例。

**问题**：§2.1 示例：

```http
POST / HTTP/1.1
Host: agent.example.com
Content-Type: application/json
Content-Length: <n>
Accept: application/json, text/event-stream

{"jsonrpc":"2.0",...}
```

示例含 `Content-Length: <n>`，但 `<n>` 是占位符。§7.4 HTTP 头部生成表说"Content-Length | body 字节数"——OK。但 §2.1 示例的 `<n>` 未给出具体值，实现者需自己算。

**影响**：小问题——实现者需自己计算 body 字节数。

**修复建议**：§2.1 示例改为具体值（如 `Content-Length: 142`），或保留 `<n>` 但在 §7.4 明确"planner 计算 body 字节数后填入"。

##### L-6. §4.1 "Agent Card 路径固定 /.well-known/agents.json" 与 §5.1 `AgentCardPath` 字段矛盾

**位置**：§4.1 不变式第 10 条 vs §5.1 `AgentCardPath` 字段。

**问题**：
- §4.1 不变式第 10 条："Agent Card 路径固定 `/.well-known/agents.json`，HTTP GET，响应为 AgentCard 对象。"
- §5.1 `AgentCardPath string` 字段："fixed '/.well-known/agents.json' per A2A spec. Empty defaults to the canonical path. Override only for negative testing (e.g. '/wrong-path' to elicit 404)."

§4.1 说"固定"，§5.1 说"可覆盖（用于负向测试）"——两者矛盾。

**影响**：实现者可能误以为路径不可配置，忽略 `AgentCardPath` 字段。

**修复建议**：§4.1 改为"Agent Card 默认路径 `/.well-known/agents.json`，可通过 `AgentCardPath` 覆盖用于负向测试"。

##### L-7. §11.6 已知坑第 6 条 "Agent Card 路径固定"与 L-6 同源

**位置**：§11.6 第 6 条。

**问题**：§11.6 第 6 条："Agent Card 路径固定：/.well-known/agents.json 是 RFC 8615 标准路径，不可配置（仅 v1 提供 AgentCardPath 字段用于负向测试）。"

这条说"不可配置"但又说"v1 提供 AgentCardPath 字段"——自相矛盾（同 L-6）。

注：RFC 8615 是 "Well-Known Uniform Resource Identifiers"——这个引用正确（不像 SSE 的 RFC 8855 是幻觉）。

**修复建议**：§11.6 第 6 条改为"Agent Card 默认路径 /.well-known/agents.json（RFC 8615）；AgentCardPath 字段仅用于负向测试"。

### 3.2 字段覆盖率（扩展表 32，23 字段）

§1.3 设计目标声明覆盖 23 字段（扩展表 32 中 32 字段的核心 23 个），逐字段对照 §9 测试用例：

| # | 字段 | spec 依据 | 设计位置 | 测试用例 | 状态 |
|---|------|----------|---------|---------|------|
| 1 | `authentication` | AgentCard.authentication | §2.4/§5.1 | T16/T19（隐含） | OK |
| 2 | `schemes` | authentication.schemes | §5.1 | T29（隐含） | **缺测** M-16 |
| 3 | `credentials` | authentication.credentials | §5.1 | **无** | **缺测** M-16 |
| 4 | `state` | Task.status.state | §4.1 | T01/T05/T20-T24 | OK |
| 5 | `timestamp` | Task.status.timestamp | §2.5 | T01（隐含） | **缺测** M-16 |
| 6 | `message` | Task.status.message | §2.5 | T05/T09 | OK |
| 7 | `history` | Task.history | §2.5 | T06 | OK |
| 8 | `role` | Message.role | §2.6 | T01/T06 | OK |
| 9 | `parts` | Message.parts | §2.6 | T01/T03/T04 | OK |
| 10 | `metadata` | Task.metadata | §2.5 | T30-T33 | OK |
| 11 | `metadataUser` | metadata.user | §8.15.1 | T30 | OK |
| 12 | `metadataDevice` | metadata.device | §8.15.1 | T30 | OK |
| 13 | `metadataLocation` | metadata.location | §8.15.1 | T30 | OK |
| 14 | `partsText` | Part kind=text | §2.6 | T01/T03 | OK |
| 15 | `partsData` | Part kind=data | §2.6 | T03 | OK |
| 16 | `streaming` | capabilities.streaming | §2.4 | T08/T17（隐含） | **缺测** M-16 |
| 17 | `pushNotifications` | capabilities.pushNotifications | §2.4 | T12/T19 | OK |
| 18 | `stateTransitionHistory` | capabilities + metadata | §4.3 | T20-T25/T32 | OK |
| 19 | `defaultInputModes` | AgentCard | §2.4 | **无** | **缺测** M-16 |
| 20 | `defaultOutputModes` | AgentCard | §2.4 | **无** | **缺测** M-16 |
| 21 | `Id` | Task.id | §2.5 | T01/T10 | OK |
| 22 | `Name` | AgentCard.name / Skill.name | §2.4 | T16（隐含） | **缺测** M-16 |
| 23 | `Tags` | Skill.tags | §2.4 | T18 | OK |

**覆盖率统计**：
- 有测试覆盖：16/23 = 70%
- 缺测：7/23 = 30%（`schemes`/`credentials`/`timestamp`/`streaming`/`defaultInputModes`/`defaultOutputModes`/`Name`）

**结论**：§1.3 声明"32 字段覆盖"但实际 23 字段中 7 个零覆盖——**实际有效覆盖率约 70%**，违反 CLAUDE.md 规则 1（spec-driven）和规则 8（adversarial review of test quality）。

### 3.3 测试用例质量

#### 3.3.1 正向/负向/边界分布

| 类型 | 数量 | 占比 | CLAUDE.md 要求 | 状态 |
|------|------|------|---------------|------|
| 正向 | 15 | 24% | - | OK |
| Agent Card | 4 | 6% | - | OK |
| 状态机 | 5（实际，见 M-15） | 8% | - | OK |
| 认证 | 4 | 6% | - | OK |
| metadata | 4 | 6% | - | OK |
| 多任务/多会话 | 4 | 6% | - | OK（但聚合断言不足） |
| 边界 | 8 | 13% | - | OK |
| 负向 | 10 | 16% | ≥25% | **不足** M-17 |
| 集成 | 4 | 6% | - | OK（但字节断言不足） |
| wire-format | 4 | 6% | - | OK |

负向占比 16% < 25%，违反 CLAUDE.md 规则 2。

#### 3.3.2 spec-derived 测试逐项核查（CLAUDE.md 规则 1）

| spec 章节 | 设计章节 | 测试用例 | 状态 |
|----------|---------|---------|------|
| §2.1 HTTP 请求 | §2.1 | T01/T60 | OK |
| §2.2 HTTP 同步响应 | §2.2 | T01/T60 | OK |
| §2.3 SSE 流 | §2.3 | T08/T61 | OK |
| §2.4 Agent Card | §2.4 | T16-T19/T62 | OK |
| §2.5 Task 对象 | §2.5 | T01/T10 | OK |
| §2.6 Message/Part | §2.6 | T01-T04 | OK（缺 data-stream/file-stream，见 H-6） |
| §2.7 TaskStatusUpdateEvent | §2.7 | T08（隐含） | **缺测** M-16 |
| §2.8 PushNotificationConfig | §2.8 | T12/T13 | OK（但 credentials 多余，见 C-4） |
| §3 方法表 | §3 | T01-T15 | OK（缺 unsubscribe，见 M-10） |
| §3.1 错误码 | §3.1 | T46-T55 | OK |
| §4 状态机 | §4 | T20-T25 | OK |
| §4.3 stateTransitionHistory | §4.3 | T20-T25/T32 | OK |
| §8.1 Agent Card 发现 | §8.1 | T16-T19 | OK |
| §8.2 tasks/send | §8.2 | T01-T07 | OK |
| §8.3 tasks/sendSubscribe | §8.3 | T08-T10 | OK |
| §8.4 tasks/get | §8.4 | T10 | OK |
| §8.5 tasks/cancel | §8.5 | T11 | OK |
| §8.6 pushNotification/set | §8.6 | T12 | OK |
| §8.7 pushNotification/get | §8.7 | T13 | OK |
| §8.8 resubscribe | §8.8 | T14 | OK |
| §8.14 auth | §8.14 | T26-T29 | OK |
| §8.15 metadata | §8.15 | T30-T33 | OK |
| §8.16 多任务并发 | §8.16 | T34-T37 | OK（聚合断言不足） |
| §8.17 stateTransitionHistory | §8.17 | T32/T20-T25 | OK |
| §8.18 边界 | §8.18 | T38-T45 | OK |
| §8.19 异常 | §8.19 | T46-T55 | OK |
| tasks/subscribe | §3 | T15 | OK |

#### 3.3.3 测试质量违规汇总

| CLAUDE.md 规则 | 违反项 | 严重度 |
|---------------|-------|--------|
| 规则 1 spec-driven | 7 字段零覆盖（§3.2） | M-16 |
| 规则 2 失败路径 | 负向占比 16% < 25% | M-17 |
| 规则 3 一测试一路径 | T25 分类错误（M-15） | M-15 |
| 规则 5 断言可观察值 | T56-T59 字节断言不足 | - |
| 规则 6 并发正确性 | T34-T37 聚合断言不足 | - |
| 规则 7 失败测试先行 | 未提及 | - |
| 规则 8 测试质量对抗 | §10.7 设 25% 阈值但自身不达标 | M-17 |

### 3.4 SSE 格式正确性

#### 3.4.1 §2.3 SSE 事件格式

§2.3 描述：

```
event: <name>\n
data: <json>\n
\n
```

并说明：

> 每个 SSE 事件的 data 是一个完整的 JSON-RPC 响应对象，`result` 字段为 Task 或 TaskStatusUpdateEvent。`final: true` 标记终态事件，客户端应在收到后关闭 SSE 流。

**正确性核查**：

| # | 检查项 | spec 要求 | 设计结论 | 状态 |
|---|--------|----------|---------|------|
| 1 | 事件以 `event: <name>\n` 开头 | HTML5 §9.2 | §2.3 正确 | OK |
| 2 | data 行以 `data: <json>\n` | HTML5 §9.2 | §2.3 正确 | OK |
| 3 | 事件以 `\n\n` 结尾（空行） | HTML5 §9.2 | §2.3 正确 | OK |
| 4 | 多行 data 用 `\n` 连接，每行前缀 `data: ` | HTML5 §9.2 | §8.3.7 + §11.6 第 2 条正确 | OK |
| 5 | event 名 | A2A spec 0.3 建议但非强制 | §2.3 固定为 `update` | **存疑** M-7 |
| 6 | SSE 规范引用 | HTML5 §9.2 | §2.3 引用 "RFC 8855" | **错误** C-3 |
| 7 | `final: true` 标记终态 | A2A spec 0.3 | §2.3 正确 | OK |
| 8 | SSE 响应头 Content-Type: text/event-stream | HTML5 §9.2 | §2.3/§7.4 正确 | OK |
| 9 | SSE 响应头 Cache-Control: no-cache | 实践（非强制） | §2.3/§7.4 正确 | OK |
| 10 | SSE 响应头 Connection: keep-alive | 实践 | §2.3 正确 | OK |

#### 3.4.2 §11.6 已知坑第 1-2 条

§11.6 第 1-2 条正确描述了 SSE 事件边界（`\n\n`）和多行 data 拆分——这是文档的亮点。

#### 3.4.3 SSE 格式结论

SSE 格式描述**基本正确**，但有 2 个问题：
- C-3：RFC 8855 引用错误（应为 HTML5 §9.2）。
- M-7：event 名固定为 `update` 但 spec 0.3 非强制（应说明"建议但非强制"）。

---

## 4. 总体评分

### 4.1 MCP 评分

| 维度 | 评分 | 说明 |
|------|------|------|
| spec 一致性 | 7/10 | capabilities 必填性错（C-1）；notifications/initialized params 错（C-2）；state 字段位置错（M-2）；工具名错误码错（M-3）；status 字段幻觉（H-3） |
| 字段覆盖率 | 6/10 | 25 字段中 6 个零覆盖、1 个幻觉、2 个位置错；实际有效率 60% |
| 状态机 | 9/10 | 5 状态 + 长任务 6 状态完整；teardown 包数与 socks5 不一致（H-2） |
| 测试用例 | 6/10 | 60 条数量足；负向占比 20% < 25%；字节断言不足（H-4）；聚合断言不足（H-5）；6 字段零覆盖 |
| 隔离性 | 9/10 | 包路径/依赖/命名隔离完整；端口巧合非设计（§11.2） |
| 内部一致性 | 6/10 | §2.4 vs §6.3 矛盾（H-1）；§6.2 表格 vs 注释矛盾（H-2）；§8 开头"48 条" vs 文末"60 条"（M-6）；§3.10 "6 字段" vs 实际 7（L-3） |
| **总分** | **43/60** | **B-** |

### 4.2 A2A 评分

| 维度 | 评分 | 说明 |
|------|------|------|
| spec 一致性 | 6/10 | SSE RFC 8855 幻觉（C-3）；credentials map 幻觉（C-4）；缺 data-stream/file-stream（H-6）；unsubscribe 存疑（M-10）；schemes 大小写未规范（M-11） |
| 字段覆盖率 | 7/10 | 23 字段中 7 个零覆盖；实际有效率 70% |
| 状态机 | 9/10 | 7 状态 + 转换表完整；input-required → completed 罕见转换未禁止（M-12）；unknown 不带 message 是设计选择（M-13） |
| 测试用例 | 6/10 | 63 条数量足；负向占比 16% < 25%；T25 分类错（M-15）；7 字段零覆盖；聚合断言不足 |
| SSE 格式 | 7/10 | 格式描述正确；RFC 引用错（C-3）；event 名固定但 spec 非强制（M-7） |
| 内部一致性 | 6/10 | §5.2 Streaming vs §3 方法表矛盾（H-8）；§8.3 SSE 事件数不清（H-9）；§4.1 vs §5.1 AgentCardPath 矛盾（L-6）；§11.6 第 6 条自相矛盾（L-7） |
| **总分** | **41/60** | **B-** |

### 4.3 综合建议

#### 4.3.1 必须修复（CRITICAL + HIGH）

1. **MCP C-1**：§3.10 `capabilities` 改为可选。
2. **MCP C-2**：§7.2 删除 `notifications/initialized` 携带 params 的变体。
3. **MCP H-1**：§6.3 修正 HTTP+SSE 旧版 POST 响应语义（202 + GET SSE 流）。
4. **MCP H-2**：§6.2 teardown 改为 3 包（与 socks5 一致）。
5. **MCP H-3**：删除 `status` 字段（spec 不存在）。
6. **MCP H-4**：T57-T60 增加字节级断言。
7. **MCP H-5**：增加多会话聚合速率测试。
8. **A2A C-3**：§2.3 + §12 SSE 引用改为 HTML5 §9.2。
9. **A2A C-4**：§5.2 删除 `Credentials map[string]string` 字段。
10. **A2A H-6**：§2.6 增加 data-stream / file-stream Part kind。
11. **A2A H-7**：§6.1 teardown 改为 3 包。
12. **A2A H-8**：§5.2 Streaming 字段语义明确化 + Validate 拒绝违规组合。
13. **A2A H-9**：§8.3 SSE 事件数 == StateTransitionHistory 长度，明确规则。
14. **A2A H-10**：§7.6 明确多 task 串行（HTTP/1.1）。

#### 4.3.2 建议修复（MEDIUM）

1. MCP M-1：`MCPError.Code` 范围改为 [-32700, -32000]。
2. MCP M-2：`state` 字段从 `notifications/progress` 移到 `_meta`。
3. MCP M-3：工具名不存在改为 -32602。
4. MCP M-6：§8 开头"48 条"改为"60 条"。
5. MCP M-7：增加至少 3 条负向用例。
6. A2A M-10：§3 删除 `tasks/unsubscribe` 或标"v2 候选"。
7. A2A M-11：§5.4 增加 schemes 小写校验。
8. A2A M-15：§9.3 改为"5 条"，T25 移到 §9.7。
9. A2A M-16：增加 7 个缺测字段的用例。
10. A2A M-17：增加至少 6 条负向用例（达 25%）。

#### 4.3.3 可选修复（LOW）

1. MCP L-1：§1.4 stdio 端口说明改为 TCP 22 + 行分隔 JSON。
2. MCP L-3：§3.10 "6 字段"改为"7 字段"。
3. A2A L-6/L-7：AgentCardPath "固定"改为"默认，可覆盖"。

---

## 附录：审计问题统计

### MCP 问题统计

| 严重度 | 数量 | 编号 |
|--------|------|------|
| CRITICAL | 2 | C-1, C-2 |
| HIGH | 5 | H-1, H-2, H-3, H-4, H-5 |
| MEDIUM | 7 | M-1, M-2, M-3, M-4, M-5, M-6, M-7 |
| LOW | 4 | L-1, L-2, L-3, L-4 |
| **合计** | **18** | |

### A2A 问题统计

| 严重度 | 数量 | 编号 |
|--------|------|------|
| CRITICAL | 2 | C-3, C-4 |
| HIGH | 5 | H-6, H-7, H-8, H-9, H-10 |
| MEDIUM | 6 | M-10, M-11, M-12, M-13, M-14, M-15 |
| LOW | 3 | L-5, L-6, L-7 |
| **合计** | **16** | |

### 两协议合计

| 严重度 | 数量 |
|--------|------|
| CRITICAL | 4 |
| HIGH | 10 |
| MEDIUM | 13 |
| LOW | 7 |
| **合计** | **34** |

（要求 ≥18，超额完成 89%。）

---

**审计结束**。两份设计文档整体质量良好（结构完整、覆盖面广、隔离设计合理），但存在 4 个 CRITICAL spec 一致性错误和 10 个 HIGH 内部矛盾/虚假覆盖声明，需在实现前修复。测试用例数量充足但质量违规（负向占比不足、字节断言不足、字段零覆盖），违反 CLAUDE.md 测试策略规则 1/2/5/6。建议按 §4.3.1 必须修复清单逐项修正后再进入实现阶段。

---

## 三轮审计 MCP v1.1.2（2026-08-03）

### 审计概览

- **审计对象**：`docs/protocol-designs/16-mcp-design.md` v1.1.2（二轮返工修订版，~2198 行，91 条测试用例）
- **审计日期**：2026-08-03
- **审计人**：独立协议审计（第三轮，与一/二轮审计人无交叉）
- **审计方法**：通读 v1.1.2 全文 → 逐字段对照 MCP spec 2024-11-05 / 2025-03-26 / 2025-06-18 三版本 + JSON-RPC 2.0 spec → 重点核查 v1.1.2 修复的 15 个问题 → 6 维度对抗（规范一致性 / 扩展字段 / 状态机 / 多客户端 / 测试质量 / 常见陷阱）→ 字节级复核 JSON-RPC 消息示例
- **spec 来源**：实时拉取 https://modelcontextprotocol.io/specification/{2024-11-05,2025-03-26,2025-06-18}/{basic,server,client}/... 与 https://www.jsonrpc.org/specification
- **问题总数**：17 项（3 CRITICAL + 5 HIGH + 5 MEDIUM + 4 LOW）
- **严重度分布**：

| 严重度 | 数量 | 编号 |
|--------|------|------|
| CRITICAL | 3 | 3R-C1, 3R-C2, 3R-C3 |
| HIGH | 5 | 3R-H1, 3R-H2, 3R-H3, 3R-H4, 3R-H5 |
| MEDIUM | 5 | 3R-M1, 3R-M2, 3R-M3, 3R-M4, 3R-M5 |
| LOW | 4 | 3R-L1, 3R-L2, 3R-L3, 3R-L4 |
| **合计** | **17** | |

- **审计结论**：**不可直接进入实现阶段**。3 项 CRITICAL 问题中，3R-C1（`includeContext` 幻觉 spec 引用）与 3R-C2（HTTP+SSE 传输时序违反 spec + 遗漏 `endpoint` 事件）必须在实现前修复，否则生成的字节流将无法被真实 MCP 服务端/客户端互操作。3R-C3（`resources/unsubscribe` 在 2024-11-05 spec 中不存在）影响方法表合法性。建议修复全部 CRITICAL + HIGH 后再进入实现。

---

### CRITICAL 问题（3 项）

#### 3R-C1：`includeContext` 字段是幻觉字段，spec 引用伪造

- **严重度**：CRITICAL
- **位置**：§4.4 L655（Validate 规则第 14 条）、§7.13 L1215/L1237（sampling 字节示例）、修订记录 H-4 L2155
- **描述**：设计文档在 §4.4 Validate 规则第 14 条声明 `includeContext` ∈ {`""`, `"none"`, `"thisServer"`, `"allServers"`}，并引用"MCP spec 2025-03-26 §sampling.createMessage 枚举 3 个合法值"。§7.13 sampling 字节示例中 `"includeContext":"thisServer"` 作为字段出现。修订记录 v1.1.2 H-4 声称已"明确引用 MCP spec 2025-03-26 §sampling.createMessage"。

  **但实际 MCP spec 不存在此字段**。逐一对照三版本 spec：
  - 2024-11-05 `client/sampling`：`CreateMessageRequest` params 字段为 `messages`/`modelPreferences`/`systemPrompt`/`maxTokens`/`stopSequences`/`temperature`/`metadata`，**无 `includeContext`**
  - 2025-03-26 `client/sampling`：与 2024-11-05 字段集相同，**无 `includeContext`**
  - 2025-06-18 `client/sampling`：与 2024-11-05 字段集相同，**无 `includeContext`**

  v1.1.2 的 H-4 "修复"是把一个本来模糊的引用改成了一个**精确但伪造**的引用（"MCP spec 2025-03-26 §sampling.createMessage 枚举 3 个合法值"）。这比 v1.1 的模糊引用更危险——实现者会按这个不存在的枚举去写 Validate 代码，拒绝合法请求或接受非法请求。

- **依据**：MCP spec 2024-11-05 / 2025-03-26 / 2025-06-18 `client/sampling` 页面，`CreateMessageRequest` 字段列表均无 `includeContext`
- **修复建议**：
  1. 删除 §4.4 Validate 规则第 14 条（`includeContext` 校验）
  2. 删除 §7.13 字节示例中的 `"includeContext":"thisServer"` 行
  3. 删除 T74 测试用例（基于幻觉字段的测试无意义）
  4. 修订记录 H-4 改为"撤销 v1.1 M-4 的 `includeContext` 校验——经三版本 spec 核查此字段不存在"
  5. 若未来 MCP spec 真正引入此字段，再补回

#### 3R-C2：HTTP+SSE 传输时序违反 spec + 遗漏 `endpoint` 事件

- **严重度**：CRITICAL
- **位置**：§6.3 L846-L860（HTTP+SSE 模式 PacketConfig 序列表）、附录 A.2 L1829-L1862
- **描述**：设计文档 §6.3 把 HTTP+SSE 旧版传输描述为：
  1. 客户端 POST `/mcp`（initialize 请求）→ 服务端 202 Accepted + Mcp-Session-Id
  2. 客户端 GET `/mcp`（建立 SSE 流）
  3. 服务端通过 GET SSE 流推送 initialize 响应

  **但 MCP spec 2024-11-05 `basic/transports` 明确规定的时序是相反的**：
  > "The server MUST provide two endpoints: 1. An SSE endpoint, for clients to establish a connection and receive messages from the server 2. A regular HTTP POST endpoint for clients to send messages to the server. **When a client connects, the server MUST send an `endpoint` event containing a URI for the client to use for sending messages.** All subsequent client messages MUST be sent as HTTP POST requests to this endpoint."

  即正确时序为：
  1. 客户端 GET `/mcp`（建立 SSE 流）
  2. 服务端通过 SSE 流发送 `endpoint` 事件（含 POST 端点 URI）
  3. 客户端 POST 到该端点（initialize 请求）
  4. 服务端 202 Accepted 或通过 SSE 流推送响应

  设计文档把 POST 放在 GET 之前，且**完全遗漏了 `endpoint` 事件**（spec 强制要求 "MUST send an `endpoint` event"）。这意味着：
  - 按 v1.1.2 字节序列生成的流量，真实 MCP 客户端无法解析（因为它在收到 `endpoint` 事件前不知道 POST 端点）
  - 真实 MCP 服务端会把第一个 POST 当作非法请求（未建立 SSE 流）
  - v1.1.2 的 H-1 "修复"虽然把 POST 响应从 200+JSON 改为 202 Accepted（spec 合规），但保留了错误的时序（POST 先于 GET），并新增了 `endpoint` 事件的遗漏

  附录 A.2 同样错误：POST 在 GET 之前，无 `endpoint` 事件。

- **依据**：MCP spec 2024-11-05 `basic/transports` §HTTP with SSE："When a client connects, the server MUST send an `endpoint` event containing a URI for the client to use for sending messages."
- **修复建议**：
  1. §6.3 重写 HTTP+SSE 序列表：第 4 步改为 GET `/mcp` 建立 SSE 流；第 5 步服务端 SSE 推送 `endpoint` 事件（`event: endpoint\ndata: /mcp?session=xxx\n\n`）；第 6 步客户端 POST 到 endpoint 指定的 URI
  2. 附录 A.2 同步重写，POST 在 GET 之后
  3. 新增测试用例：`endpoint` 事件必须在 GET SSE 流的第一个事件中出现，且其 data 字段为后续 POST 使用的 URI
  4. T58/T78 字节级断言更新：第一个 SSE 事件应为 `event: endpoint\ndata: ...`，后续才是 `event: message\ndata: ...`

#### 3R-C3：`resources/unsubscribe` 方法在 MCP spec 2024-11-05 中不存在

- **严重度**：CRITICAL
- **位置**：§3.3 L347（资源方法表）、§7.6 L1059（resources/unsubscribe 字节示例）、T71 L1593（测试用例）
- **描述**：设计文档 §3.3 资源方法表列出 `resources/unsubscribe` 方法（C→S，有 id），§7.6 给出字节示例 `{"jsonrpc":"2.0","id":7,"method":"resources/unsubscribe","params":{"uri":"file:///etc/hosts"}}`，T71 测试该方法的请求/响应。

  **但 MCP spec 2024-11-05 `server/resources` 不定义此方法**。spec 仅定义：
  - `resources/list`
  - `resources/read`
  - `resources/templates/list`
  - `resources/subscribe`
  - `notifications/resources/updated`
  - `notifications/resources/list_changed`

  **`resources/unsubscribe` 在 2024-11-05 spec 中不存在**。2025-06-18 spec 同样不定义此方法（已核查 2025-06-18 `server/resources` 页面）。设计文档把一个 spec 不存在的方法标为 "C→S | 是"（有 id 请求），并生成字节流，会使得真实 MCP 服务端返回 -32601 Method not found。

  v1.1 修订记录 T71 声称此用例 "spec-derived"（§2.3.2），但实际无 spec 依据。

- **依据**：MCP spec 2024-11-05 `server/resources` 方法列表无 `resources/unsubscribe`；2025-06-18 `server/resources` 同样无此方法
- **修复建议**：
  1. 删除 §3.3 `resources/unsubscribe` 行（或标注 "非 spec 标准，planner 不生成，实现可选拒绝 -32601"）
  2. 删除 §7.6 `resources/unsubscribe` 字节示例
  3. 删除 T71 测试用例（或改为负向用例："resources/unsubscribe → -32601 Method not found"）
  4. §3.3 方法表注释说明：spec 2024-11-05 仅定义 subscribe，无显式 unsubscribe（订阅隐式随会话结束失效）

---

### HIGH 问题（5 项）

#### 3R-H1：`resources/read` uri 不存在的错误码与 spec 不一致

- **严重度**：HIGH
- **位置**：§7.5 L1046（变体行 "uri 不存在"）、T22 L1485
- **描述**：设计文档 §7.5 变体声明 "uri 不存在：JSON-RPC error -32602 'Invalid params' with data `{"uri":"file:///nonexistent"}`"。T22 测试用例同样断言 `-32602 Invalid params`。

  **但 MCP spec 2024-11-05 `server/resources` Error Handling 明确规定**：
  > "Resource not found: `-32002`"
  > 示例：`{"error":{"code":-32002,"message":"Resource not found","data":{"uri":"file:///nonexistent.txt"}}}`

  2025-06-18 spec 同样使用 -32002。设计文档用 -32602（Invalid params）覆盖 spec 明确的 -32002（Server error 段，Resource not found 专属码）。这是 v1.0 就存在的 spec 一致性错误，三轮修订均未发现。

- **依据**：MCP spec 2024-11-05 `server/resources` §Error Handling："Resource not found: `-32002`"；附录 B 错误码表 -32002 = "Server not initialized" 是设计文档自己的错——-32002 在 spec 中是 Resource not found
- **修复建议**：
  1. §7.5 变体 "uri 不存在" 改为 `error.code=-32002` "Resource not found"
  2. T22 断言改为 `-32002 Resource not found`
  3. 附录 B 错误码表 -32002 含义修正：spec 用 -32002 = Resource not found（不是 "Server not initialized"）。"Server not initialized" 在 MCP spec 中实际是 -32002 还是另一码需重新核查——设计文档附录 B 声明 -32002 = "Server not initialized"，但 resources spec 显示 -32002 = "Resource not found"。这是附录 B 内部矛盾
  4. §7.19 异常场景表第 6 行 "服务端未初始化 -32002" 同步核查

#### 3R-H2：附录 B 错误码 -32002 含义与 spec 冲突 + -32004 无 spec 依据

- **严重度**：HIGH
- **位置**：附录 B L1910-L1917、§7.13 L1234（sampling rate_limited -32004）、§7.19 异常场景表
- **描述**：
  1. 附录 B 声明 `-32002 = Server not initialized`。但 MCP spec 2024-11-05 `server/resources` 明确用 -32002 = "Resource not found"（见 3R-H1）。设计文档的附录 B 把 -32002 含义搞错了。MCP spec 实际未给 -32002 一个固定的全局含义——它出现在 resources 的 "Resource not found" 上下文，但设计文档在 §7.19 又用它表示 "Server not initialized"，造成同一码两个含义的内部矛盾。
  2. 附录 B 声明 `-32004 = Rate limited (sampling 场景)`。但 MCP spec 2024-11-05/2025-03-26/2025-06-18 `client/sampling` Error Handling 示例用 `"code": -1`（"User rejected sampling request"），**未定义 -32004**。spec 没有专门的 Rate limited 码。设计文档发明的 -32004 无 spec 依据。
  3. 附录 B 声明 `-32800 = Request cancelled（非 spec 标准）`。JSON-RPC 2.0 spec 保留的 server error 段是 -32000 到 -32099，-32800 超出此范围且非 JSON-RPC 标准。设计文档已标注"非 spec 标准"，但仍在 §7.10/§7.19 生成此码——建议彻底删除或移到附录"非标准扩展"。

- **依据**：
  - MCP spec 2024-11-05 `server/resources`：-32002 = Resource not found
  - MCP spec 2024-11-05/2025-03-26/2025-06-18 `client/sampling`：无 -32004，错误示例用 -1
  - JSON-RPC 2.0 spec §5.1：保留 -32000 到 -32099
- **修复建议**：
  1. 附录 B -32002 含义改为 "Resource not found（spec 2024-11-05 resources）"；"Server not initialized" 改用 spec 中实际出现的码（若 spec 未定义则标注 "MCP 扩展，码待定"，建议用 -32003 或 -32001，但需 spec 核查）
  2. 附录 B 删除 -32004 Rate limited（无 spec 依据）；§7.13 sampling rate_limited 变体改为使用 -1（spec 示例）或标注 "非 spec 标准"
  3. 附录 B -32800 移到独立的"非标准扩展"小节，明示 planner 仅在用户显式配置时生成

#### 3R-H3：`embedded_resource` content type 不存在于 spec

- **严重度**：HIGH
- **位置**：§4.2 L601（MCPContent.Type 枚举）、§4.4 L652（Validate 规则第 11 条）、§7.4 L1015（变体）
- **描述**：设计文档 §4.2 `MCPContent.Type` 枚举 5 个值：`"text"`, `"image"`, `"audio"`, `"resource"`, `"embedded_resource"`。§4.4 Validate 第 11 条要求 `Parts[i].Content.Type` ∈ 这 5 个值。

  **但 MCP spec 的 content type 命名与此不一致**：
  - 2024-11-05 `server/tools` + `server/prompts`：content type 为 `text` / `image` / `resource`（嵌入资源用 `resource`，不是 `embedded_resource`）
  - 2025-06-18 `server/tools`：content type 为 `text` / `image` / `audio` / `resource_link` / `resource`（`resource` = 嵌入资源，`resource_link` = 资源链接，两者不同）
  - **`embedded_resource` 在任何 spec 版本中都不存在**

  设计文档的 `embedded_resource` 是幻觉类型名。spec 用 `resource` 表示嵌入资源。2025-06-18 新增的 `resource_link` 是独立类型（链接到资源，不内嵌）。设计文档未区分这两者。

- **依据**：MCP spec 2024-11-05 `server/tools` Data Types：Text/Image/Embedded Resources（`type: "resource"`）；2025-06-18 `server/tools`：Text/Image/Audio/Resource Links（`type: "resource_link"`）/Embedded Resources（`type: "resource"`）
- **修复建议**：
  1. §4.2 `MCPContent.Type` 枚举改为：`"text"`, `"image"`, `"audio"`, `"resource"`, `"resource_link"`（删除 `embedded_resource`，新增 `resource_link`）
  2. §7.4 变体 "工具返回嵌入资源" 字节示例中 `"type":"embedded_resource"` 改为 `"type":"resource"`
  3. §4.4 Validate 第 11 条同步更新
  4. 新增 content type `resource_link` 的测试用例（2025-06-18 spec）

#### 3R-H4：批量支持声明不准确——spec 要求所有传输 MUST 接收 batch

- **严重度**：HIGH
- **位置**：§2.6 L207（"旧版 HTTP+SSE 模式不支持批量"）、§2.6.1 L235（"批量 + HTTP+SSE（旧版）组合：旧版 HTTP+SSE 不支持批量 POST body"）
- **描述**：设计文档 §2.6 声明 "旧版 HTTP+SSE 模式不支持批量（spec 2024-11-05 §2.2 明确：POST body 必须为单个 JSON-RPC 对象）"。

  **但实际 MCP spec 2025-03-26 `basic` 明确规定**：
  > "MCP implementations **MAY** support sending JSON-RPC batches, but **MUST** support receiving JSON-RPC batches."

  这条规则没有按传输模式区分——**所有传输（stdio / HTTP+SSE / Streamable HTTP）MUST 支持接收 batch**。2024-11-05 `basic/transports` 的 HTTP+SSE 章节未禁止 batch POST body（spec 只说 "client messages MUST be sent as HTTP POST requests"，未限制 body 必须为单对象）。设计文档引用的 "spec 2024-11-05 §2.2" 不存在此内容。

  另外，2025-03-26 `basic/transports` stdio 章节明确说：
  > "Messages may be JSON-RPC requests, notifications, responses—or a JSON-RPC batch containing one or more requests and/or notifications."

  即 stdio 显式支持 batch。Streamable HTTP 也显式支持 batch（POST body 可以是数组）。设计文档对 stdio 和 Streamable HTTP 的 batch 支持声明正确，但对 HTTP+SSE 的"不支持"声明缺乏 spec 依据且与 2025-03-26 的"MUST support receiving"矛盾。

- **依据**：MCP spec 2025-03-26 `basic` §Batching："MCP implementations MAY support sending JSON-RPC batches, but MUST support receiving JSON-RPC batches"（无传输模式限制）；2024-11-05 `basic/transports` HTTP+SSE 未禁止 batch
- **修复建议**：
  1. §2.6 删除 "旧版 HTTP+SSE 模式不支持批量" 的绝对声明
  2. §2.6.1 "批量 + HTTP+SSE（旧版）组合" 改为：旧版 HTTP+SSE 的 POST body 可以是单个 JSON-RPC 对象或批量数组（spec 未禁止）；planner 默认按批量数组发送，服务端 MUST 接收
  3. §2.6.2 Validate 规则保留（批量数组校验规则对所有传输适用）
  4. 新增测试用例：HTTP+SSE 模式下 POST body 为批量数组，服务端通过 GET SSE 流按序推送 N 个 event:message

#### 3R-H5：2025-06-18 新增 client capability Elicitation 完全未记录

- **严重度**：HIGH
- **位置**：§3 方法表（缺 elicitation 方法）、§4.1 MCPConfig（缺 elicitation 配置）、§4.4 Validate（ProtocolVersion 接受 2025-06-18 但不处理其新特性）
- **描述**：设计文档 §4.4 Validate 第 3 条接受 `ProtocolVersion = "2025-06-18"`，附录 B 列出 2025-06-18 引入了"工具结构化输出、audio 内容类型、资源模板"。

  **但 MCP spec 2025-06-18 实际引入了远不止这些**：
  1. **新增 client capability `elicitation`**（服务端→客户端请求用户提供额外信息）—— spec 2025-06-18 Overview 明确列出 "Elicitation: Server-initiated requests for additional information from users"。设计文档 §3 方法表完全没有 elicitation 相关方法（`elicitation/create`），§5.4 能力门控矩阵未提及 elicitation
  2. **新增 tool `outputSchema` + `structuredContent`**（结构化输出）—— 设计文档 §7.4 仅提到 `content`+`isError`，未记录 `structuredContent` 字段
  3. **新增 `resource_link` content type**（见 3R-H3）
  4. **新增 tool/resource `title` 字段**（显示名）—— 设计文档 §7.4 tools/list 响应未包含 `title`
  5. **新增 `annotations` 字段**（audience/priority/lastModified）—— 设计文档完全未提及

  设计文档声称支持 2025-06-18 但只覆盖了其一小部分新特性。如果用户配置 `protocol_version="2025-06-18"`，planner 生成的报文会缺少 spec 要求的新字段，或忽略 elicitation 方法的能门控。

- **依据**：MCP spec 2025-06-18 Overview："Elicitation: Server-initiated requests for additional information from users"；2025-06-18 `server/tools`：`outputSchema`/`structuredContent`/`title`/`annotations`；2025-06-18 `server/resources`：`title`/`annotations`/`size`
- **修复建议**：
  1. §3 方法表新增 elicitation 相关方法（`elicitation/create` S→C 请求），或在 §4.4 Validate 第 3 条限制 `ProtocolVersion` 只接受 `""`/`"2024-11-05"`/`"2025-03-26"`，明示 2025-06-18 留待 v1.2
  2. §7.4 tools/list 响应字节示例补 `title`/`annotations` 字段（标注为 2025-06-18 新增，v1.1.2 不强制生成）
  3. §7.4 tools/call 响应字节示例补 `structuredContent` 字段说明
  4. 附录 B 2025-06-18 行扩展，列出全部新特性，标注哪些 v1.1.2 支持/不支持

---

### MEDIUM 问题（5 项）

#### 3R-M1：`tools/list` 分页未记录、未测试

- **严重度**：MEDIUM
- **位置**：§3.2 L318（tools/list 方法表未提分页）、§7.4 L985（tools/list 请求 `params:{}` 无 cursor）、§8 测试用例无 tools/list 分页测试
- **描述**：MCP spec 2024-11-05/2025-06-18 `server/utilities/pagination` 明确列出 `tools/list` 支持分页（请求 `cursor`，响应 `nextCursor`）。设计文档 §3.2 方法表对 `resources/list` 标注了 "支持分页 cursor"，但对 `tools/list` 和 `prompts/list` 未标注。§7.4 tools/list 请求字节示例 `{"method":"tools/list","params":{}}` 未展示 cursor 参数。§8 无 tools/list 分页测试用例（T13 仅测试默认 3 工具响应）。

- **依据**：MCP spec 2024-11-05 `server/utilities/pagination` §Operations Supporting Pagination：明确列出 `tools/list`
- **修复建议**：
  1. §3.2 tools/list 行 "说明" 列补 "支持分页 cursor"
  2. §3.4 prompts/list 同步补 "支持分页 cursor"
  3. §7.4 tools/list 请求字节示例补 cursor 变体：`{"method":"tools/list","params":{"cursor":"..."}}`
  4. 新增测试用例 T92 "tools/list 分页（cursor + nextCursor）"

#### 3R-M2：§5.4 能力重复键检查仅覆盖 ClientCapabilities，未覆盖 ServerCapabilities

- **严重度**：MEDIUM
- **位置**：§5.4 Rule 5 L759、T90 L1619
- **描述**：§5.4 Rule 5 声明 "Validate 前使用自定义 JSON tokenizer 对 `ClientCapabilities` 与 `ServerCapabilities` 原始字节流做顶层对象键扫描"。T90 测试用例仅测试 `ClientCapabilities` JSON 含重复键，未测试 `ServerCapabilities` 重复键。按 CLAUDE.md 测试策略规则 3"一测试一路径"，两个 RawMessage 字段应各有独立测试。

- **依据**：CLAUDE.md 测试策略规则 3："If a method/branch exists, it needs a test that exercises it"
- **修复建议**：
  1. T90 拆为 T90a（ClientCapabilities 重复键）+ T90b（ServerCapabilities 重复键），或新增 T92 "ServerCapabilities 重复键 → Validate 拒绝"

#### 3R-M3：§2.6.2 rule 5 与 rule 6 边界模糊，可能误实现

- **严重度**：MEDIUM
- **位置**：§2.6.2 L245（rule 5）、L246（rule 6）
- **描述**：
  - rule 5："批量中包含非法元素（JSON 解析失败）时，整个批量响应为单个 `-32700 Parse error`，`id=null`"
  - rule 6："批量中混有合法与非法对象（除解析错误外）时，合法元素仍正常响应，非法元素单独返回 `-32600 Invalid Request`"

  两条规则的边界是 "JSON 解析失败"（rule 5，整个数组无法解析）vs "有效 JSON 但非 JSON-RPC 对象"（rule 6，单个元素无效）。但 rule 5 的措辞 "批量中包含非法元素（JSON 解析失败）" 容易误读为 "批量中某个元素 JSON 解析失败"——实际上 JSON-RPC 2.0 spec §6 的语义是：**整个批量数组本身 JSON 解析失败**时返回单个 -32700；**批量数组能解析但某元素不是合法 JSON-RPC 对象**时按 rule 6 逐项响应。

  JSON-RPC 2.0 spec §6 原文："If the batch rpc call itself fails to be recognized as a valid JSON or as an Array with at least one value, the response from the Server MUST be a single Response object."——这是针对整个数组的解析失败，不是单个元素。

  设计文档的措辞可能让实现者误以为"批量中任一元素解析失败 → 整个批量 -32700"，这会导致拒绝合法的部分请求。

- **依据**：JSON-RPC 2.0 spec §6 Batch："If the batch rpc call itself fails to be recognized as a valid JSON or as an Array with at least one value, the response from the Server MUST be a single Response object"
- **修复建议**：
  1. rule 5 改为："批量请求的整个 JSON 数组本身解析失败（如 `[{...}, invalid json, {...}]` 整体无法 JSON.parse）时，整个批量响应为单个 `-32700 Parse error`，`id=null`。注意：这是整个数组解析失败，不是单个元素非 JSON-RPC 对象——后者按 rule 6 处理"
  2. rule 6 改为："批量数组能成功 JSON 解析，但某元素不是合法 JSON-RPC 2.0 对象（如缺 `jsonrpc`/`method` 字段、`id` 重复、类型错）时，合法元素正常响应，非法元素单独返回 `-32600 Invalid Request`（`id` 为该元素的 id 或 null）"
  3. 新增测试用例：批量数组整体 JSON 解析失败（rule 5）vs 批量含非 JSON-RPC 元素（rule 6）各一条

#### 3R-M4：§7.12 `roots/list` 请求带 `params:{}` 与 spec 示例不一致

- **严重度**：MEDIUM
- **位置**：§7.12 L1174（roots/list 请求字节示例）
- **描述**：设计文档 §7.12 roots/list 请求字节示例为 `{"jsonrpc":"2.0","id":12,"method":"roots/list","params":{}}`。但 MCP spec 2024-11-05 `client/roots` 示例为 `{"jsonrpc":"2.0","id":1,"method":"roots/list"}`（无 `params` 字段）。虽然 JSON-RPC 2.0 允许 params 省略或为空对象，但 spec 示例明确不带 params。设计文档带 `params:{}` 虽然合法，但与 spec 示例不一致，且 T33 "notifications/roots/list_changed 通知无 params" 断言了通知无 params，但 roots/list 请求却带了 params——一致性欠佳。

- **依据**：MCP spec 2024-11-05 `client/roots` §Listing Roots 请求示例：`{"jsonrpc":"2.0","id":1,"method":"roots/list"}`（无 params）
- **修复建议**：
  1. §7.12 roots/list 请求字节示例改为 `{"jsonrpc":"2.0","id":12,"method":"roots/list"}`（省略 params）
  2. 或保留 `params:{}` 但说明"params 省略与空对象等价，planner 默认省略"

#### 3R-M5：§7.4 `tools/call` 工具名不存在错误码与 spec 部分一致但 message 不规范

- **严重度**：MEDIUM
- **位置**：§7.4 L1016（变体 "工具名不存在"）
- **描述**：v1.1 M-3 把工具名不存在的错误码从 -32601 改为 -32602（与 spec 2024-11-05 `server/tools` Error Handling 一致，正确）。但设计文档 §7.4 字节示例 `data:{"param":"name","reason":"unknown tool"}` 与 spec 示例 `{"error":{"code":-32602,"message":"Unknown tool: invalid_tool_name"}}` 不一致——spec 示例的 message 已包含工具名，data 字段未定义。设计文档自定义的 `data.param`/`data.reason` 结构无 spec 依据。

  另外 §7.19 异常场景表第 3 行仍写 "方法不存在 -32601 Method not found"，与 §7.4 的 -32602（工具名不存在）并列，但未说明 -32601 vs -32602 的边界（-32601 = 方法名不存在如 `foo/bar`；-32602 = 方法存在但参数错如 `tools/call` 的 `name` 值不存在）。§7.19 第 4 行 "参数缺失/类型错 -32602" 与 §7.4 -32602 一致但未交叉引用。

- **依据**：MCP spec 2024-11-05 `server/tools` §Error Handling 示例：`{"error":{"code":-32602,"message":"Unknown tool: invalid_tool_name"}}`（message 含工具名，无 data）
- **修复建议**：
  1. §7.4 工具名不存在字节示例改为 `{"error":{"code":-32602,"message":"Unknown tool: <name>"}}`（message 含工具名）
  2. §7.19 异常场景表第 3 行补注：-32601 仅当方法名本身不存在（如 `foo/bar`）；`tools/call` 方法存在但 `name` 参数值不存在用 -32602
  3. T17 测试用例断言 message 含 "Unknown tool:" 前缀

---

### LOW 问题（4 项）

#### 3R-L1：§7.3 ping "带 params（非标准）"变体与 spec 不一致

- **严重度**：LOW
- **位置**：§7.3 L978（变体 "ping 带 params（非标准）"）
- **描述**：设计文档 §7.3 变体声明 "ping 带 params（非标准）：`{"jsonrpc":"2.0","id":99,"method":"ping","params":{}}`，响应仍 `{}`"。MCP spec 2024-11-05 `basic/utilities/ping` 明确说 "A ping request is a standard JSON-RPC request with **no parameters**"，示例无 params 字段。设计文档标注"非标准"但仍然生成，可能让实现者以为这是合法变体。

- **依据**：MCP spec 2024-11-05 `basic/utilities/ping`："A ping request is a standard JSON-RPC request with no parameters"
- **修复建议**：删除该变体（non-standard 变体不应作为正向示例），或改为负向："ping 带 params → 严格 spec 服务端可能 -32602 Invalid params"

#### 3R-L2：§7.13 sampling `temperature`/`stopSequences` 字段未在 spec 示例中出现

- **严重度**：LOW
- **位置**：§7.13 L1207-L1230（sampling 字节示例含 `temperature:0.7`/`stopSequences:["\n\n"]`）
- **描述**：设计文档 §7.13 sampling 请求字节示例包含 `temperature` 和 `stopSequences` 字段。但 MCP spec 2024-11-05/2025-03-26/2025-06-18 `client/sampling` 的 `CreateMessageRequest` 示例均未展示 `temperature`/`stopSequences` 字段——spec 示例字段为 `messages`/`modelPreferences`/`systemPrompt`/`maxTokens`。`temperature`/`stopSequences` 是否在 spec schema 中定义未在文档中核实。设计文档把它们作为"完整请求"的字段展示，可能误导。

- **依据**：MCP spec 三版本 `client/sampling` CreateMessageRequest 示例均无 `temperature`/`stopSequences`
- **修复建议**：核实 spec TypeScript schema 是否定义 `temperature`/`stopSequences`；若未定义则删除这些字段，或标注"非 spec 标准扩展字段"

#### 3R-L3：§4.4 Validate 第 3 条 ProtocolVersion 枚举缺 2025-06-18 后续版本说明

- **严重度**：LOW
- **位置**：§4.4 L644（ProtocolVersion ∈ {`""`, `"2024-11-05"`, `"2025-03-26"`, `"2025-06-18"`}）
- **描述**：设计文档 §4.4 第 3 条限制 ProtocolVersion 仅这 4 个值。但设计文档未说明如何处理未来新版本（如 2025-09-xx 等）。当 MCP spec 发布新版本时，此 Validate 规则会拒绝合法的 protocolVersion。建议改为"接受 spec 已发布版本 + 占位说明未来版本如何扩展"。

- **依据**：MCP spec 持续演进，2025-06-18 后可能发布新版本
- **修复建议**：第 3 条改为"ProtocolVersion ∈ {`""`, `"2024-11-05"`, `"2025-03-26"`, `"2025-06-18"`，未来版本在实现时追加"；或 Validate 改为 warning 而非 error

#### 3R-L4：§7.18 边界场景 #20 "GET /mcp 但未先 POST initialize" 期望行为与 HTTP+SSE spec 矛盾

- **严重度**：LOW
- **位置**：§7.18 L1387（boundary #20）
- **描述**：设计文档 §7.18 boundary #20 声明 "HTTP 模式 GET /mcp 但未先 POST initialize | 服务端应返回 400"。但 MCP spec 2024-11-05 HTTP+SSE 传输的正确时序是 **GET 先于 POST**（见 3R-C2）。所以 "GET 未先 POST" 不是错误——GET 本来就应该先发生。此 boundary 场景的前提（POST 先于 GET）本身就是 3R-C2 指出的 spec 违规。

- **依据**：MCP spec 2024-11-05 `basic/transports` HTTP+SSE：GET SSE 先建立，POST 后续
- **修复建议**：删除 boundary #20，或改为 "Streamable HTTP 模式 GET /mcp 但未携带 Mcp-Session-Id | 服务端返回 400 Bad Request"（Streamable HTTP 的 GET 要求带 session id，spec 2025-03-26）

---

### 审计结论

**不可直接进入实现阶段**。17 项问题中：

- **3 项 CRITICAL 必须修复后才能进入实现**：
  - 3R-C1（`includeContext` 幻觉字段 + 伪造 spec 引用）会让实现者按不存在的枚举写 Validate 代码
  - 3R-C2（HTTP+SSE 时序违反 spec + 遗漏 `endpoint` 事件）生成的字节流无法被真实 MCP 互操作
  - 3R-C3（`resources/unsubscribe` spec 不存在）方法表合法性问题

- **5 项 HIGH 建议在实现前修复**：
  - 3R-H1（resources/read 错误码 -32002 vs -32602）spec 一致性
  - 3R-H2（附录 B -32002/-32004/-32800 错误码语义）spec 依据
  - 3R-H3（`embedded_resource` 幻觉类型）content type 枚举
  - 3R-H4（HTTP+SSE batch 支持声明不准确）spec 依据
  - 3R-H5（2025-06-18 Elicitation/structuredContent/resource_link 未记录）版本覆盖完整性

- **5 项 MEDIUM + 4 项 LOW** 可在实现过程中并行修复

**v1.1.2 修复质量评估**：v1.1.2 的 15 项修复中，H-1（POST 响应 202）、H-2（CANCELED 箭头）、H-3（DELETE /mcp 测试）、M-1（短周期 SSE 措辞）、M-2（IDCounter 语义）、M-3（boundary #3）、M-4（字段计数）等 7 项修复正确；C-1（id 重复语义）、C-2（重复键实现机制）、C-3（ServerCapabilities 默认值）、C-4（null vs 缺省）、L-1（null id）、L-2（SSH 标注）、L-3（能力矩阵扩展）等 8 项修复方向正确但未触及本轮发现的深层 spec 一致性问题。**H-4（includeContext spec 引用）的"修复"反而引入了幻觉引用**——把模糊引用改成精确但伪造的引用，是本轮最严重的修复回归。

**v1.1.2 二轮返工结论的"已具备进入实现阶段的最终条件"声明不成立**。三轮审计发现的 3 项 CRITICAL + 5 项 HIGH 问题必须在实现前修复。建议 v1.1.3 修订重点：核实所有 spec 引用的真实性（逐一打开 spec 页面核对字段是否存在），特别是 sampling/tools/resources 方法的字段列表与错误码。

**实现阶段额外建议**：
1. 实现者应实时拉取 MCP spec（而非依赖设计文档的 spec 引用），以 spec 为准
2. 单元测试应包含"spec 字段存在性"断言——即每个声称来自 spec 的字段，测试其是否真的出现在 spec schema 中
3. 集成测试应使用真实 MCP SDK（`modelcontextprotocol/go-sdk`）解析 planner 生成的字节流，验证互操作性
