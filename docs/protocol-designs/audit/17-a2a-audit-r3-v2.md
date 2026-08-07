# A2A 设计文档独立复审报告（v2.0.2 复审，r3-v2）

**审计对象**：`docs/protocol-designs/17-a2a-design.md` v2.0.2（2215 行，声明 246 条用例）
**审计日期**：2026-08-05
**审计人**：独立协议审计员（与 r1-v2 / r2-v2 复审报告无交叉）
**审计依据**（全部实拉验证）：
1. A2A spec v0.2.2 `specification/json/a2a.json`（79651 B）+ `docs/specification.md`（86950 B）
2. A2A spec v0.2.5 `specification/json/a2a.json`（91502 B）
3. A2A spec v0.3.0 `specification/json/a2a.json`（103940 B）
4. JSON-RPC 2.0（https://www.jsonrpc.org/specification）
5. `CLAUDE.md` 测试策略 8 条强制规则
6. 上轮复审报告 `audit/17-a2a-audit-r2-v2.md`（8 项问题：0 CRITICAL / 0 HIGH / 5 MEDIUM / 3 LOW）

> 注：任务要求对照 "Google A2A spec v0.2.2/v0.2.5/v0.3.0"，可用 WebFetch github.com/a2aproject/A2A 核实。本审计实拉 raw.githubusercontent.com/a2aproject/A2A 的 v0.2.2/v0.2.5/v0.3.0 三个历史 tag 的 schema 与规范文档逐版本核验。所有文件字节数（79651/86950/91502/103940 B）与 r2-v2 报告声明一致，证明拉取的是同一版本。

**审计方法**：
- 通读 v2.0.2 全文 2215 行
- 对 r2-v2 报告的 8 项问题逐项核实修复是否落地
- 程序化统计 246 条用例编号连续性、各节计数、类型分类
- 逐字节计算 S1/S2 Content-Length
- 逐字段核对方法名 / Agent Card 路径 / Part kind / 事件类型 / 9 个状态枚举 / SSE 格式 / 错误码 / SecurityScheme 子类型 / preferredTransport 示例值
- 检查 Validate 规则 V1-V16 与测试用例声称行为的对应关系（重点 V8/V9）
- 默认"有 bug"，除非证据确凿

---

## 1. 审计概览

### 1.1 重点检查项（任务指定 10 项）核对结果

| 重点检查项 | 结果 | 依据 |
|-----------|------|------|
| M-A：§7 类型统计求和一致（150+56+30+8+2=246） | ✅ 已正确修复 | §7（L1447）"正向 150 / 负向 56 / 边界 30 / 集成 8 / 并发 2 = 246"；程序化统计 246 行吻合；负向占比 56/246≈22.8% |
| M-B：V9 规则补全"status-update 事件必须含 Status 字段" | ✅ 已正确修复 | V9（L1847）"所有 `Kind=status-update` 事件必须含 `Status` 字段（spec required，见 §2.7 表；支撑 T138）"；实拉 v0.2.2/v0.3.0 schema `TaskStatusUpdateEvent.required=[contextId,final,kind,status,taskId]` 确认 |
| M-C：V8 规则补全 tasks/resubscribe | ⚠️ 部分修复 | V8（L1839）`Streaming=true` 分支已补 `tasks/resubscribe` ✅；但 `Streaming=false` 分支仍只允许 `message/send`，遗漏 `tasks/get`/`tasks/cancel`/`tasks/pushNotificationConfig/{set,get}` 这些同步方法——见 M-1 |
| M-D：§1.6 补充 agent/authenticatedExtendedCard HTTP GET 端点 | ✅ 已正确修复 | §1.6 #3（L79）"7 个 JSON-RPC 核心方法 + 1 个 HTTP GET 扩展卡片端点"；§3.1（L487-491）"v0.2.x HTTP 端点"表含 URL `{AgentCard.url}/../agent/authenticatedExtendedCard`、需 `supportsAuthenticatedExtendedCard:true`、401/403/404 错误语义；实拉 v0.2.2 §7.8（L726-752）确认 |
| M-E：V15/V5 HTTPS 要求改为 SHOULD 建议 | ✅ 已正确修复 | V15（L1868）"建议 `https://` 前缀（spec 为 SHOULD 建议而非 MUST，schema 对 url 无格式约束），HTTP URL 合法、Validate 默认警告不拒绝"；V5（L1823）、§2.9 url 字段（L442）、§10.6 #9（L2021）、T160（L1677）同步改为 SHOULD；实拉 v0.2.2 schema `PushNotificationConfig.url={type:string}`（无格式约束）确认 |
| L-A：MutualTLSSecurityScheme required=['type'] | ✅ 已正确修复 | §2.4 SecurityScheme 表（L249）"必填 type（const=`mutualTLS`）"；实拉 v0.3.0 `MutualTLSSecurityScheme.required=["type"]`、`type.const="mutualTLS"` 确认 |
| L-B：preferredTransport 示例值修正为 JSONRPC/GRPC/HTTP+JSON | ✅ 已正确修复 | §2.4（L215）"schema 示例为 `JSONRPC`/`GRPC`/`HTTP+JSON`，默认 `JSONRPC`"；additionalInterfaces 示例改为 `"transport":"JSONRPC"`（L214）；实拉 v0.3.0 schema `preferredTransport.examples=["JSONRPC","GRPC","HTTP+JSON"]`、`AgentInterface.transport.examples` 同 确认 |
| L-C：T212-T219 等价标注 | ✅ 已正确修复 | §7.19（L1754-1765）T212/T213/T214/T217/T218/T219 验证点均标注"与 T015/T016/T017/T141/T143/T146 等价，不重复断言"，保留编号不删行 |
| 协议骨架（方法名/路径/Part kind/状态枚举）正确 | ✅ 全部正确 | 实拉 v0.2.2 schema const：7 个 JSON-RPC 方法名 `message/send`/`message/stream`/`tasks/get`/`tasks/cancel`/`tasks/resubscribe`/`tasks/pushNotificationConfig/set`/`tasks/pushNotificationConfig/get` 全对；Agent Card 路径 v0.2.2 `/.well-known/agent.json`、v0.3.0 `/.well-known/agent-card.json`；Part.anyOf=TextPart/FilePart/DataPart（3 种）；TaskState.enum 9 值全对；错误码 -32700~-32603、-32001~-32006（v0.2.2/v0.2.5）、-32007（v0.3.0 `AuthenticatedExtendedCardNotConfiguredError`）全对 |
| 测试用例符合 CLAUDE.md §Testing Policy | ⚠️ 基本符合 | 负向 56 条覆盖全部 12 个错误码 + 非法输入 + 状态机非法转换；集成 8 条、并发 2 条；spec-driven；但 V8 与 tasks/get 等同步方法冲突（M-1）会影响 T055-T064/T065-T072/T081-T092 等用例的实现 |

### 1.2 严重度分布

| 严重度 | 数量 | 编号 |
|--------|------|------|
| CRITICAL | 0 | — |
| HIGH | 0 | — |
| MEDIUM | 1 | M-1 |
| LOW | 1 | L-1 |
| **合计** | **2** | |

### 1.3 最终结论

**有条件通过——协议骨架（方法名/Agent Card 路径/Part kind/事件类型/状态枚举/错误码/SecurityScheme 子类型）与 spec v0.2.2/v0.2.5/v0.3.0 严格一致，r2-v2 的 8 项问题中 7 项正确修复。但 M-C 修复不完整（V8 `Streaming=false` 分支仍误伤 `tasks/get`/`tasks/cancel`/`tasks/pushNotificationConfig/{set,get}` 合法同步方法），必须在实现前修复。**

---

## 2. r2-v2 修复验证（8 项逐项复核）

### 2.1 已确认正确修复（7 项）

| 编号 | 验证结果 |
|------|---------|
| M-A（§7 类型统计求和） | ✅ 程序化统计 246 条用例：正向 150 / 负向 56 / 边界 30 / 集成 8 / 并发 2，求和 246 吻合；§7（L1447）文字与统计一致 |
| M-B（V9 补 Status 必含） | ✅ V9（L1847）新增"所有 `Kind=status-update` 事件必须含 `Status` 字段"；T138（L1645）验证点补充 spec `TaskStatusUpdateEvent.required` 依据；实拉 v0.2.2/v0.3.0 schema `required=[contextId,final,kind,status,taskId]` 确认 |
| M-D（agent/authenticatedExtendedCard 端点） | ✅ §3.1（L487-491）新增"v0.2.x HTTP 端点"表；§1.6 #3（L79）改为"7 个 JSON-RPC 核心方法 + 1 个 HTTP GET 扩展卡片端点"；实拉 v0.2.2 §7.8（L726-752）确认端点存在、HTTP GET、URL `{AgentCard.url}/../agent/authenticatedExtendedCard`、401/403/404 错误语义 |
| M-E（V15/V5 HTTPS 改 SHOULD） | ✅ V15（L1868）、V5（L1823）、§2.9 url（L442）、§10.6 #9（L2021）、T160（L1677，类型由负向改为正向）五处一致；实拉 v0.2.2/v0.3.0 schema `PushNotificationConfig.url={type:string}` 无格式约束确认 |
| L-A（MutualTLS required=['type']） | ✅ §2.4（L249）改为"必填 type（const=`mutualTLS`）"；实拉 v0.3.0 `MutualTLSSecurityScheme.required=["type"]` 确认 |
| L-B（preferredTransport 示例值） | ✅ §2.4（L215）示例改为 `JSONRPC`/`GRPC`/`HTTP+JSON`；additionalInterfaces 示例 `transport:JSONRPC`（L214）；实拉 v0.3.0 `preferredTransport.examples=["JSONRPC","GRPC","HTTP+JSON"]`、default `"JSONRPC"` 确认 |
| L-C（T212-T219 等价标注） | ✅ §7.19（L1754-1765）T212/T213/T214/T217/T218/T219 验证点均标注"与 T015/T016/T017/T141/T143/T146 等价，不重复断言" |

### 2.2 修复不完整（1 项）

| 编号 | 问题 | 验证结果 |
|------|------|---------|
| M-C | V8 Streaming/Method 一致性规则补全 tasks/resubscribe | ✅ `Streaming=true` 分支已补 `tasks/resubscribe`；❌ `Streaming=false` 分支仍只允许 `message/send`，遗漏 `tasks/get`/`tasks/cancel`/`tasks/pushNotificationConfig/{set,get}`——见 M-1 |

---

## 3. MEDIUM 问题（1 项）

### M-1：V8 `Streaming=false` 分支遗漏 tasks/get 等同步方法（r2-v2 M-C 修复不完整）

- **位置**：§8 V8（L1839）、§5.3 `A2ATask.Streaming` 注释（L880）
- **描述**：r2-v2 M-C 报告 V8 "`Streaming=true` 时 `Method` 必须为 `message/stream`" 遗漏 `tasks/resubscribe`。v2.0.2 修复了 `Streaming=true` 分支（"`Method` 必须为 `message/stream` 或 `tasks/resubscribe`"），但 `Streaming=false` 分支仍为"`Method` 必须为 `message/send`"。然而 §3.1 方法表中 `tasks/get`、`tasks/cancel`、`tasks/pushNotificationConfig/set`、`tasks/pushNotificationConfig/get` 这 4 个方法同样是同步路径（HTTP POST → JSON-RPC 响应，非 SSE 流），其响应配置 `A2ATaskResponse` 也是同步 JSON-RPC 响应而非 SSE 事件序列。这些方法对应的 `A2ATask.Streaming` 应为 `false`，但 V8 现表述"`Streaming=false` 时 `Method` 必须为 `message/send`"会拒绝这 4 个合法同步方法的配置。
- **依据**：
  - V8 原文（L1839）："`Streaming=false` 时 `Method` 必须为 `message/send`（冲突配置 Validate 拒绝）"
  - §5.3 注释（L880）：`Streaming bool // true=message/stream 或 tasks/resubscribe，false=message/send`
  - §3.1 方法表（L481-485）：`tasks/get`、`tasks/cancel`、`tasks/pushNotificationConfig/set`、`tasks/pushNotificationConfig/get` 均为 POST + 同步响应（result 为 Task/TaskPushNotificationConfig，非 SSE 流）
  - §6.2 S4（tasks/get）、S5（tasks/cancel）、S7（pushNotificationConfig/set）三个场景的响应均为同步 JSON-RPC 响应（无 `data:` 行、无 `Content-Type: text/event-stream`）
  - 实拉 v0.2.2 spec §7.3-§7.6 确认这 4 个方法均为同步请求-响应模式（非 SSE）
- **影响**：
  - 实现者按 V8 实现 Validate 后，T055-T064（tasks/get）、T065-T072（tasks/cancel）、T081-T092（pushNotificationConfig/set+get）等共约 28 条用例的合法配置（`Method=tasks/get` + `Streaming=false`）会被 Validate 拒绝
  - 或实现者自行放宽规则导致实现与文档不一致
  - 违反 CLAUDE.md 测试策略规则 3（每个分支都需要测试）——`Streaming=false` + `Method=tasks/get` 这条合法分支无对应 V 规则保护
- **修复建议**：V8 改为：
  - `Streaming=true` 时 `Method` ∈ `{message/stream, tasks/resubscribe}`
  - `Streaming=false` 时 `Method` ∈ `{message/send, tasks/get, tasks/cancel, tasks/pushNotificationConfig/set, tasks/pushNotificationConfig/get}`
  - §5.3 L880 注释同步更新为 `// true=message/stream 或 tasks/resubscribe，false=同步方法（message/send/tasks/get/tasks/cancel/tasks/pushNotificationConfig/*）`

---

## 4. LOW 问题（1 项）

### L-1：§3.1 方法表 tasks/pushNotificationConfig/get 未标注"需 pushNotifications=true"

- **位置**：§3.1 方法表（L485）
- **描述**：§3.1 方法表中 `tasks/pushNotificationConfig/set` 标注"需 pushNotifications=true"（L484），但 `tasks/pushNotificationConfig/get` 未标注。实拉 v0.2.2 spec §7.6 明确"`tasks/pushNotificationConfig/get` Requires the server to have `AgentCard.capabilities.pushNotifications: true`"。V3（L1814）规则已正确覆盖（`Method ∈ {tasks/pushNotificationConfig/set, tasks/pushNotificationConfig/get}` 时 `PushNotifications` 必须为 true），仅方法表遗漏标注。
- **依据**：v0.2.2 spec §7.6（L706）"Requires the server to have `AgentCard.capabilities.pushNotifications: true`"；V3（L1814）规则正确；§3.1 表 L485 遗漏。
- **影响**：文档内部不一致（方法表 vs V3 规则）；实现者读方法表可能误以为 get 不需要 pushNotifications=true。
- **修复建议**：§3.1 方法表 L485 `tasks/pushNotificationConfig/get` 行"说明"列补"（需 pushNotifications=true）"，与 set 行保持一致。

---

## 5. 其它观察（不构成问题）

- **§1.6 #3 措辞**："`agent/authenticatedExtendedCard`" 与 §3.1 "v0.2.x HTTP 端点" 表中 URL 表达 `{AgentCard.url}/../agent/authenticatedExtendedCard` 一致，与 spec v0.2.2 §7.8 原文一致。
- **§2.10 长度约束**：全部长度限制（1MB text、10MB bytes、128 字节 id、1024 skills 等）均为文档设计决策，规范 schema 无任何 maxLength/maxItems 约束。文档未明示其为设计约束，建议在表注中注明，避免实现者误认为协议兼容性要求（r2-v2 §5 已观察到，本审计沿用）。
- **§4.2 状态转换表**：规范（v0.2.2/v1.0.1）未定义正式的状态转换表，仅定义状态枚举与使用模式。文档的转换表是合理的设计约束（r2-v2 §5 已观察到）。
- **spec 内部 final 矛盾**：v0.2.2 规范 markdown §7.2.2 表称 final 为"否（可选，默认 false）"，而 v0.2.2/v0.3.0 JSON schema 的 required 数组含 final。文档选择 schema（required）是正确的（r2-v2 §5 已观察到）。
- **SSE 事件格式**：实拉 v0.2.2 spec §9.3（L969-1081）的 SSE 示例确认为未命名事件（仅 `data:` 行，无 `event:` 字段），与设计文档 §2.3 一致。
- **webhook payload**：实拉 v0.2.2 spec §9.5（L1313-1327）确认 webhook body 为 Task 对象（`kind:"task"`），与设计文档 S14 一致；v1.0 改为 StreamResponse 包装的注释也与设计文档 §6.2 S14 注一致。
- **Content-Length 字节计算**：逐字节紧凑序列化验证 S1=501B、S2 请求=258B、S2 响应=257B，全部吻合（r2-v2 已验证，本审计复算确认）。
- **测试编号连续性**：T001-T242 全部出现且唯一，T212a-T212d 全部出现，共 246 个无缺号无重复（程序化验证）。
- **各节标题计数**：§7.1-§7.21 共 21 节，每节标题计数（12/12/16/14/10/8/8/12/12/18/8/8/12/10/12/14/17/8/14/6/15）与实际行数全对（程序化验证）。

---

## 6. 与 CLAUDE.md §Testing Policy 的符合性评估

| 规则 | 评估 |
|------|------|
| 规则 1（spec-driven） | 符合。用例按 spec §5-§9 组织，字段覆盖较全；§7.19 等价标注已差异化 |
| 规则 2（失败路径） | 符合。负向 56 条覆盖全部 12 个错误码 + 非法输入 + 状态机非法转换；占比 22.8% 如实标注 |
| 规则 3（每路径一测试） | 有缺口。V8 `Streaming=false` + `Method=tasks/get` 等合法分支无 V 规则保护（M-1） |
| 规则 4（集成测试） | 符合。T204-T211 有 8 条端到端用例 |
| 规则 5（断言可观察结果） | 符合。Content-Length 字节级断言已修正；S1-S15 断言可观察 |
| 规则 6（并发正确性） | 符合。T167/T168 测量聚合包数与聚合速率 |
| 规则 7（failing-test-first） | 符合。r2-v2 修复均配有验证用例或文档修订 |
| 规则 8（测试质量对抗审查） | 本文档为该维度产物；发现 V8 false 分支遗漏（M-1） |

---

## 7. 详细证据附录（关键 Spec 引文，全部实拉）

### 7.1 v0.2.2 JSON-RPC 方法 consts（schema 实拉）

```
message/send, message/stream, tasks/cancel, tasks/get,
tasks/pushNotificationConfig/get, tasks/pushNotificationConfig/set, tasks/resubscribe
```

### 7.2 v0.2.2 TaskStatusUpdateEvent.required

```
required = ["contextId","final","kind","status","taskId"]
```
（v0.2.2 markdown §7.2.2 表却标 final 为"No，默认 false"——规范内部矛盾，schema 为权威；v0.3.0 同 required）

### 7.3 v0.2.2 TaskArtifactUpdateEvent.required

```
required = ["artifact","contextId","kind","taskId"]
```

### 7.4 v0.2.2 TaskState.enum（9 值）

```
submitted, working, input-required, completed, canceled, failed, rejected, auth-required, unknown
```

### 7.5 v0.2.2 Part.anyOf（3 种 kind）

```
TextPart (required: kind, text)
FilePart (required: file, kind)
DataPart (required: data, kind)
```

### 7.6 v0.2.2 AgentCard required

```
v0.2.2: [capabilities, defaultInputModes, defaultOutputModes, description, name, skills, url, version]
v0.2.5: 上述 + protocolVersion
v0.3.0: 同 v0.2.5（signatures 可选）
```

### 7.7 v0.3.0 preferredTransport / AgentInterface

```
preferredTransport: default "JSONRPC", examples ["JSONRPC","GRPC","HTTP+JSON"]
AgentInterface.transport: examples ["JSONRPC","GRPC","HTTP+JSON"]
AgentInterface.required: [transport, url]
```

### 7.8 v0.3.0 MutualTLSSecurityScheme

```
required = ["type"], type const = "mutualTLS"
```

### 7.9 v0.3.0 SecurityScheme.anyOf（5 种子类型）

```
APIKeySecurityScheme, HTTPAuthSecurityScheme, OAuth2SecurityScheme,
OpenIdConnectSecurityScheme, MutualTLSSecurityScheme
```

### 7.10 PushNotificationConfig.id 语义

- v0.2.2 schema description: "Push Notification ID - created by server to support multiple callbacks"
- v0.3.0 schema description: "A unique ID for the push notification configuration, set by the client to support multiple notification callbacks"
- v0.2.2/v0.3.0 PushNotificationConfig.required = ["url"]（仅 url 必填）

### 7.11 PushNotificationConfig.url HTTPS 要求

- v0.2.2/v0.3.0 schema：url 无格式约束（type: string）
- v0.2.2 spec markdown §6.8 表："Absolute HTTPS webhook URL"（描述用 HTTPS，但 schema 无约束）
- v0.2.2 §4.1 "production deployments MUST use HTTPS" 针对 A2A 传输层，非客户端 webhook URL

### 7.12 v0.2.x 扩展卡片端点（spec §7.8 实拉）

```
agent/authenticatedExtendedCard
- HTTP Method: GET
- Endpoint URL: {AgentCard.url}/../agent/authenticatedExtendedCard
- Requires supportsAuthenticatedExtendedCard: true
- 401/403/404/5xx 错误语义
- 非 JSON-RPC 方法
```

### 7.13 v0.3.0 新增方法 consts（实拉）

```
agent/getAuthenticatedExtendedCard (-32007 AuthenticatedExtendedCardNotConfiguredError)
tasks/pushNotificationConfig/delete
tasks/pushNotificationConfig/list
```

### 7.14 错误码（v0.2.2/v0.3.0 schema code.const）

- v0.2.2/v0.2.5：-32700/-32600/-32601/-32602/-32603/-32001/-32002/-32003/-32004/-32005/-32006
- v0.3.0：上述 + -32007 `AuthenticatedExtendedCardNotConfiguredError`

### 7.15 SendStreamingMessageResponse（v0.2.2/v0.3.0 schema）

```
anyOf = [JSONRPCErrorResponse, SendStreamingMessageSuccessResponse]
SendStreamingMessageSuccessResponse.result anyOf = [Task, Message, TaskStatusUpdateEvent, TaskArtifactUpdateEvent]
```

### 7.16 message/send 响应 result（v0.2.2/v0.3.0 schema）

```
SendMessageSuccessResponse.result anyOf = [Task, Message]
```
（确认 message/send 响应可为 Message——简单交互无 Task 跟踪）

### 7.17 Content-Length 字节计算（紧凑序列化，json.Marshal 无缩进）

```
S1 Agent Card body  = 501 字节 ✅
S2 请求 body        = 258 字节 ✅
S2 响应 body        = 257 字节 ✅
```

### 7.18 测试用例统计（程序化）

```
总数 246；编号 T001-T242 连续 + T212a-T212d；无缺号无重复
正向 150 / 负向 56 / 边界 30 / 集成 8 / 并发 2 = 246
负向占比 56/246 ≈ 22.8%
各节标题计数（12/12/16/14/10/8/8/12/12/18/8/8/12/10/12/14/17/8/14/6/15）与实际行数全对
```

---

## 8. 最终结论

**本文档是否可以进入实现阶段：有条件通过（是，但需先修复 1 项 MEDIUM）。**

- **CRITICAL：0**。协议骨架（方法名/Agent Card 路径/Part kind/事件类型/状态枚举/错误码/SecurityScheme 子类型）经 v0.2.2/v0.2.5/v0.3.0 三个历史 tag 实拉验证与 spec 严格一致。
- **HIGH：0**。r2-v2 的 5 项 MEDIUM 中 4 项（M-A/M-B/M-D/M-E）与 3 项 LOW（L-A/L-B/L-C）全部正确修复并验证。
- **MEDIUM：1**。M-1（V8 `Streaming=false` 分支遗漏 tasks/get 等同步方法，r2-v2 M-C 修复不完整）直接影响实现者的 Validate 逻辑，会在合法的 tasks/get/cancel/pushNotificationConfig 场景下拒绝配置，必须在实现前修复。
- **LOW：1**。L-1（§3.1 方法表 pushNotificationConfig/get 未标注需 pushNotifications=true）为文档内部不一致，V3 规则已正确覆盖。

修复优先级建议：M-1 → L-1。M-1 修复仅需扩展 V8 `Streaming=false` 分支的 Method 集合，不涉及结构性改动；修复后本文档可进入实现阶段。

---

**审计结束**。
