# A2A 设计文档独立复审报告（v2.0.3 复审，r4-v2）

**审计对象**：`docs/protocol-designs/17-a2a-design.md` v2.0.3（2233 行，声明 246 条用例）
**审计日期**：2026-08-03
**审计人**：独立协议审计员（与 r1-v2 / r2-v2 / r3-v2 复审报告无交叉）
**审计依据**（全部实拉验证）：
1. A2A spec v0.2.2 `specification/json/a2a.json`（79651 B）+ `docs/specification.md`（86950 B）
2. A2A spec v0.2.5 `specification/json/a2a.json`（91502 B）+ `docs/specification.md`（91975 B）
3. A2A spec v0.3.0 `specification/json/a2a.json`（103940 B）+ `docs/specification.md`（85298 B）
4. A2A spec v1.0.1 `docs/specification.md`（实拉验证 agent-card.json 路径与 webhook payload 演变）
5. JSON-RPC 2.0（https://www.jsonrpc.org/specification）
6. `CLAUDE.md` 测试策略 8 条强制规则
7. 上轮复审报告 `audit/17-a2a-audit-r3-v2.md`（2 项问题：0 CRITICAL / 0 HIGH / 1 MEDIUM / 1 LOW）

> 注：本审计实拉 raw.githubusercontent.com/a2aproject/A2A 的 v0.2.2/v0.2.5/v0.3.0 三个历史 tag 的 schema 与规范文档，以及 v1.0.1 规范文档逐版本核验。schema 文件字节数（79651/91502/103940 B）与 r3-v2 报告声明一致，证明拉取的是同一版本。另用 WebFetch 交叉核对了 v0.2.2 markdown，发现 markdown 与 JSON schema 存在内部矛盾（final 字段），以 schema 为权威（详见 §5）。

**审计方法**：
- 通读 v2.0.3 全文 2233 行
- 对 r3-v2 报告的 2 项问题逐项核实修复是否落地（重点 M-1 / L-1）
- 程序化统计 246 条用例编号连续性、各节计数、类型分类（21 节逐节核对）
- 逐字节计算 S1/S2 Content-Length
- 逐字段核对方法名（v0.2.2 7 核心 + v0.3.0 10 方法）/ Agent Card 路径 / Part kind / 事件类型 / 9 个状态枚举 / SSE 格式 / 错误码 / 必填字段集
- 检查 Validate 规则 V1-V16 与测试用例声称行为的对应关系
- 默认"有 bug"，除非证据确凿

---

## 1. 审计概览

### 1.1 重点检查项（任务指定）核对结果

| 重点检查项 | 结果 | 依据 |
|-----------|------|------|
| M-1：V8 `Streaming=false` 分支扩展为同步方法集 | ✅ 已正确修复 | V8（L1839）`Streaming=false` 分支已扩展为 `{message/send, tasks/get, tasks/cancel, tasks/pushNotificationConfig/set, tasks/pushNotificationConfig/get}`；§5.3 `A2ATask.Streaming` 注释（L880）同步更新为 `false=同步方法（message/send/tasks/get/tasks/cancel/tasks/pushNotificationConfig/*）`；两处一致，与 §3.1 方法表中 5 个同步方法完全对应。实拉 v0.2.2 schema 确认 5 个方法的响应均为同步 JSON-RPC（result 为 Task/TaskPushNotificationConfig，非 SSE） |
| L-1：§3.1 方法表 pushNotificationConfig/get 补标注 | ✅ 已正确修复 | §3.1 方法表（L485）`tasks/pushNotificationConfig/get` 行"说明"列已补"（需 pushNotifications=true）"，与 set 行（L484）一致；实拉 v0.2.2 spec §7.6（L703）原文 "Requires the server to have `AgentCard.capabilities.pushNotifications: true`" 确认 |
| 协议骨架（方法名/路径/Part kind/状态枚举）仍正确 | ✅ 全部正确 | 见 §2 逐项证据 |
| 测试用例符合 CLAUDE.md §Testing Policy | ✅ 符合 | 见 §4 逐规则评估 |

### 1.2 严重度分布

| 严重度 | 数量 | 编号 |
|--------|------|------|
| CRITICAL | 0 | — |
| HIGH | 0 | — |
| MEDIUM | 0 | — |
| LOW | 1 | L-1 |
| **合计** | **1** | |

### 1.3 最终结论

**是，本文档可直接进入实现阶段。**

- r3-v2 的 2 项问题（1 MEDIUM + 1 LOW）均已在 v2.0.3 正确修复并验证落地，无遗留。
- 协议骨架经 v0.2.2/v0.2.5/v0.3.0 三个历史 tag 实拉逐字段验证与 spec 严格一致。
- 发现 1 项 LOW（§5.3 Go 结构体在 v0.3.0 下 acceptedOutputModes 必填语义差异的注释欠精确），不阻塞实现，建议顺手修正。

---

## 2. r3-v2 修复验证（2 项逐项复核）

### 2.1 M-1：V8 `Streaming=false` 分支扩展为同步方法集 —— ✅ 已正确修复

| 检查点 | 验证结果 |
|--------|---------|
| V8 `Streaming=false` 分支（L1839） | ✅ `Method ∈ {message/send, tasks/get, tasks/cancel, tasks/pushNotificationConfig/set, tasks/pushNotificationConfig/get}`，5 个同步方法全部列出 |
| §5.3 `A2ATask.Streaming` 注释（L880） | ✅ 同步更新为 `false=同步方法（message/send/tasks/get/tasks/cancel/tasks/pushNotificationConfig/*）` |
| 一致性 | ✅ V8 规则与 §5.3 注释与 §3.1 方法表（5 个同步方法行）三处完全一致，无遗漏 |
| spec 依据 | ✅ 实拉 v0.2.2 schema：`tasks/get`（params=TaskQueryParams）、`tasks/cancel`（TaskIdParams）、`tasks/pushNotificationConfig/set`（TaskPushNotificationConfig）、`tasks/pushNotificationConfig/get`（TaskIdParams）4 个方法的响应 result 均为同步 JSON-RPC 对象（Task/TaskPushNotificationConfig），非 SSE 流 |
| 修复质量 | ✅ 无过度修复：`Streaming=true` 分支保持 `{message/stream, tasks/resubscribe}` 未动；V8 其余 4 条规则（Message 必填/TaskID 必填等）无回归 |

### 2.2 L-1：§3.1 方法表 pushNotificationConfig/get 补标注 —— ✅ 已正确修复

| 检查点 | 验证结果 |
|--------|---------|
| §3.1 方法表（L485） | ✅ `tasks/pushNotificationConfig/get` 行"说明"列已补"（需 pushNotifications=true）"，与 set 行（L484）格式一致 |
| spec 依据 | ✅ 实拉 v0.2.2 spec §7.6（L703-704）："Retrieves the current push notification configuration for a specified task. **Requires the server to have `AgentCard.capabilities.pushNotifications: true`**." |
| 一致性 | ✅ 与 V3 规则（L1813-1814）、§9.2 错误码表（-32003 覆盖 get）、T085/T091/T194/T200 用例全部一致 |
| 附带验证 | ✅ v0.3.0 spec §7.6 同样要求 `capabilities.pushNotifications: true`；v0.3.0 的 `tasks/pushNotificationConfig/list`（v2 路线图）在 §7.7 同样要求 |

---

## 3. 协议骨架逐项核实（v0.2.2 / v0.2.5 / v0.3.0 / v1.0.1 实拉）

### 3.1 方法名（schema `method.const` 逐条核对）

| 方法 | v0.2.2 schema | v0.3.0 schema | 文档 |
|------|---------------|---------------|------|
| message/send | ✅ const 存在 | ✅ | ✅ §3.1 |
| message/stream | ✅ | ✅ | ✅ |
| tasks/get | ✅ | ✅ | ✅ |
| tasks/cancel | ✅ | ✅ | ✅ |
| tasks/resubscribe | ✅ | ✅ | ✅ |
| tasks/pushNotificationConfig/set | ✅ | ✅ | ✅ |
| tasks/pushNotificationConfig/get | ✅ | ✅ | ✅（L-1 修复后标注完整） |
| tasks/pushNotificationConfig/list | — | ✅（v2 路线图标注正确） | ✅ §3.1 v0.3.0 新增方法表 |
| tasks/pushNotificationConfig/delete | — | ✅（v2 路线图） | ✅ |
| agent/getAuthenticatedExtendedCard | — | ✅（v2 路线图，-32007） | ✅ |

- v0.2.2 共 7 个 JSON-RPC 核心方法，与文档 §1.6 #3 声明完全一致。
- 文档 §3.1 无幻觉方法（无 tasks/send、tasks/sendSubscribe、tasks/subscribe、tasks/pushNotification/set）。

### 3.2 Agent Card 路径

| 版本 | 路径 | 文档表述 |
|------|------|---------|
| v0.2.2 spec §5.3（L144） | `https://{server_domain}/.well-known/agent.json` | ✅ §1.3 |
| v0.3.0 spec §5.3（L293） | `https://{server_domain}/.well-known/agent-card.json` | ✅ §1.3 |
| v1.0.1 spec（L1826/1978/3328） | `/.well-known/agent-card.json`，IANA 注册（§14.3 "URI suffix: agent-card.json"） | ✅ §1.3 注、V13、§10.6 #6 |

- "v1.0 从未恢复为 agent.json"表述经 v1.0.1 实拉确认正确。

### 3.3 Part kind 与必填字段

| Part | v0.2.2 schema required | v0.3.0 schema required |
|------|------------------------|------------------------|
| TextPart | [kind, text] | [kind, text] |
| FilePart | [file, kind] | [file, kind] |
| DataPart | [data, kind] | [data, kind] |

- 三个版本均无 `data-stream`/`file-stream`，文档 §1.6 #5/§2.6 正确。

### 3.4 Task 状态枚举（9 值）

`submitted, working, input-required, completed, canceled, failed, rejected, auth-required, unknown` —— v0.2.2/v0.2.5/v0.3.0 schema 完全一致，文档 §4.1 正确。

### 3.5 事件类型与必填字段

| 事件 | required（schema，三版本一致） | 文档 |
|------|-------------------------------|------|
| TaskStatusUpdateEvent | [contextId, final, kind, status, taskId] | ✅ §2.7 表（final 标"是（spec required）"） |
| TaskArtifactUpdateEvent | [artifact, contextId, kind, taskId] | ✅ §2.8 表 |

- **spec markdown/schema 内部矛盾**：v0.2.2 markdown §7.2.2 表（L633）标 `final` 为 "No，默认 false"，而 schema required 含 final。文档选择 schema 为权威（§2.7 注）——与 r3-v2 §5 观察一致，判断正确（实现按 schema 出 final 字段必含、false 也输出，可同时通过两者）。
- 文档 §5.5 Go 结构体 `Final bool \`json:"final"\``（去 omitempty）与 schema 一致 ✅。
- Task.kind（const "task"）在 schema required 中（三版本一致），文档 §2.5 标必填 ✅。
- Message.kind（const "message"）在 schema required 中，文档 §2.6 标必填 ✅。

### 3.6 SSE 事件格式

- v0.2.2 spec §9.3 示例（L969-1081）与 v0.3.0 spec §9 示例均为**未命名事件**（仅 `data:` 行，无 `event:` 字段），文档 §2.3 正确。
- SSE data 为完整 JSON-RPC Response（`SendStreamingMessageResponse` = `JSONRPCErrorResponse | SendStreamingMessageSuccessResponse`），result anyOf = [Task, Message, TaskStatusUpdateEvent, TaskArtifactUpdateEvent] —— schema 三版本一致，文档 §2.3/§3.2.2 正确。
- 流关闭语义：v0.2.2 spec §9.3 "Server closes the SSE connection after the `final:true` event" —— 文档 §2.3 正确。

### 3.7 错误码

- v0.2.2/v0.2.5 schema error defs：-32700/-32600/-32601/-32602/-32603/-32001/-32002/-32003/-32004/-32005/-32006 —— 文档 §3.4 全部正确。
- v0.3.0 schema 新增 -32007 `AuthenticatedExtendedCardNotConfiguredError`（文档 §3.4 正确）。
- -32004 为通用 `UnsupportedOperationError`（非仅 streaming），文档 §3.4 注正确。

### 3.8 各方法 params 结构（schema 逐方法核对）

| 方法 | params 类型 | required | 文档表述 |
|------|------------|----------|---------|
| message/send | MessageSendParams | [message] | ✅ §3.2.1 |
| message/stream | MessageSendParams | [message] | ✅ §3.2.2 |
| tasks/get | TaskQueryParams | [id]（含 historyLength/metadata 可选） | ✅ §3.2.3 |
| tasks/cancel | TaskIdParams | [id] | ✅ §3.2.4 |
| tasks/resubscribe | TaskIdParams（schema 引用 TaskQueryParams 对象，字段同 TaskIdParams） | [id] | ✅ §3.2.5 |
| tasks/pushNotificationConfig/set | TaskPushNotificationConfig | [taskId, pushNotificationConfig] | ✅ §3.2.6 |
| tasks/pushNotificationConfig/get | v0.2.2: TaskIdParams；v0.3.0: anyOf[TaskIdParams, GetTaskPushNotificationConfigParams]（后者含可选 pushNotificationConfigId） | [id] | ✅ §3.2.7（"v0.3.0+ 可选 pushNotificationConfigId"表述正确） |

### 3.9 其余字段核实

| 字段 | 核实结果 |
|------|---------|
| PushNotificationConfig.required | [url]（三版本一致，无格式约束）—— 文档 §2.9/V15 的 SHOULD 表述正确 |
| PushNotificationConfig.id 语义 | v0.2.2 "created by server to support multiple callbacks"；v0.3.0 "set by the client to support multiple notification callbacks" —— 文档 §2.9/§5.6/§10.6 #15 版本标注正确 |
| PushNotificationAuthenticationInfo.required | [schemes]（三版本一致）—— 文档 §2.9/§5.6 正确 |
| MessageSendConfiguration | v0.2.2/v0.2.5 required=[acceptedOutputModes]；v0.3.0 required 无（空）—— 文档 §3.2.1 表"acceptedOutputModes 必填"对目标版本 v0.2.x 正确（见 L-1） |
| TaskPushNotificationConfig.required | [pushNotificationConfig, taskId]（三版本一致）—— 文档 §3.2.6/V8 正确 |
| AgentCard.required | v0.2.2: [capabilities, defaultInputModes, defaultOutputModes, description, name, skills, url, version]；v0.2.5/v0.3.0 追加 protocolVersion —— 文档 §2.4/V6 正确 |
| webhook payload | v0.2.2：Task 对象（spec §9.5 实拉确认）；v1.0：StreamResponse 包装（v1.0.1 §4.3.3 实拉确认）—— 文档 S14 注正确 |
| TaskQueryParams.historyLength | 可选 integer —— 文档 §3.2.3 正确 |
| agent/authenticatedExtendedCard | v0.2.2 §7.8 HTTP GET 端点，URL `{AgentCard.url}/../agent/authenticatedExtendedCard`，需 supportsAuthenticatedExtendedCard=true，401/403/404 错误语义 —— 文档 §3.1 正确 |

### 3.10 Content-Length 字节计算（程序化复算）

| 场景 | 文档声明 | 复算结果 |
|------|---------|---------|
| S1 Agent Card body | 501 | ✅ 501（紧凑序列化） |
| S2 请求 body | 258 | ✅ 258 |
| S2 响应 body | 257 | ✅ 257 |

（缩进排版 JSON 分别为 703/421/432 字节，文档断言注明"紧凑序列化字节数"正确。）

### 3.11 测试用例统计（程序化）

- 总数 246；编号 T001-T242 连续无缺号无重复，T212a-T212d 全部出现。
- 类型分布：正向 150 / 负向 56 / 边界 30 / 集成 8 / 并发 2 = 246，与文档 §7 声明完全一致；负向占比 56/246 ≈ 22.8% 如实标注。
- 各节标题计数（12/12/16/14/10/8/8/12/12/18/8/8/12/10/12/14/17/8/14/6/15）与实际行数全部吻合（21 节逐一程序化核对）。

---

## 4. 与 CLAUDE.md §Testing Policy 的符合性评估

| 规则 | 评估 |
|------|------|
| 规则 1（spec-driven） | 符合。用例按 spec §5-§9 组织；§7.19 等价标注已差异化；负向用例覆盖全部 12 个错误码 |
| 规则 2（失败路径） | 符合。负向 56 条覆盖错误码表 12 行 + 非法输入 + 状态机非法转换；占比如实标注 |
| 规则 3（每路径一测试） | 符合。V8 修复后 `Streaming=false` × 5 个同步方法的合法分支均有 V 规则保护；T055-T092 同步方法用例不再被误拒 |
| 规则 4（集成测试） | 符合。T204-T211 共 8 条端到端用例（含 tshark 解析 A2A JSON-RPC 与 SSE） |
| 规则 5（断言可观察结果） | 符合。S1/S2 Content-Length 字节级断言复算正确；S3/S6/S10 SSE 事件字段完整 |
| 规则 6（并发正确性） | 符合。T167/T168 测量聚合包数与聚合速率 |
| 规则 7（failing-test-first） | 符合。r3-v2 修复均配有验证用例或文档修订；T055-T064/T065-T072/T081-T092 覆盖 M-1 涉及的同步方法路径 |
| 规则 8（测试质量对抗审查） | 本文档为该维度产物；本次未发现测试"测错东西"的问题 |

---

## 5. LOW 问题（1 项）

### L-1：§5.3 Go 结构体 `acceptedOutputModes` 无 omitempty，未注明 v0.3.0 语义差异

- **位置**：§5.3 `A2AMessageSendConfiguration`（L884），§3.2.1 `MessageSendConfiguration` 表（L539）
- **描述**：文档在 §3.2.1 表将 `acceptedOutputModes` 标为"必填"，§5.3 Go 结构体 `AcceptedOutputModes []string \`json:"acceptedOutputModes"\``（无 omitempty），恒序列化输出。经实拉 schema 验证：**v0.2.2/v0.2.5 的 `MessageSendConfiguration.required = ["acceptedOutputModes"]`（必填成立）**，但 **v0.3.0 的 required 为空数组（不再必填）**。文档目标版本为 v0.2.x（§1.3），故对目标版本表述正确；但 §5.3 结构体注释与 §3.2.1 表均未注明"v0.3.0 起可选"，实现者若同时对接 v0.3.0 Agent 且恒输出该字段，理论上不属于协议违规（JSON-RPC 服务端对多余可选字段按额外属性处理，schema 亦未禁止），但缺少版本差异标注。
- **依据**：v0.2.2/v0.2.5 schema `MessageSendConfiguration.required=["acceptedOutputModes"]`；v0.3.0 schema 该对象 required 为空（程序化提取确认）。
- **影响**：极低。仅影响对接 v0.3.0+ Agent 时的精确性标注；不产生非法报文。
- **修复建议**（可选，不阻塞）：在 §3.2.1 `acceptedOutputModes` 行或 §5.3 结构体注释补一句"v0.2.x 必填，v0.3.0 起可选（schema required 为空）"。

---

## 6. 其它观察（不构成问题）

- **v2.0.3 版本日期与"今天"的关系**：文档标注 v2.0.3（2026-08-05），本审计日期为 2026-08-03，日期超前 2 天。参照 16-mcp-design.md 同仓库文档惯例（版本行只标版本不标日期），且前序 r1-v2/r2-v2/r3-v2 报告与修订记录同样使用 2026-08-05 日期，判定为该项目一贯的"目标交付日期"惯例，不构成问题；实现者按文档修订记录顺序（v2.0.0→v2.0.1→v2.0.2→v2.0.3）理解版本演进即可。
- **§2.10 长度约束**：全部长度限制（1MB text、10MB bytes、128 字节 id、1024 skills 等）均为文档设计决策，spec schema 无任何 maxLength/maxItems 约束（r3-v2 已观察，本审计沿用以确认）。建议实现者在代码注释中注明"设计约束"而非"协议兼容要求"。
- **§4.2 状态转换表**：spec 未定义正式状态转换表（r3-v2 已观察），文档的转换表是合理的设计约束；V10"仅 §4.2 表内转换合法"为文档自洽的严格化设计。
- **spec markdown/schema 的 final 矛盾**：v0.2.2 markdown 表标 final 可选，schema required 含 final。文档选 schema（权威）正确。
- **v0.3.0 的 `message/send`/`tasks/get` 等响应兼容**：文档未逐版本标注 v0.3.0 的 REST/gRPC 绑定（v0.3.0 新增了绑定维度），但本设计目标为 JSON-RPC 绑定，§3.1 已注明"v0.3.0 新增方法 v2 路线图"，无需扩展。

---

## 7. 详细证据附录（关键 Spec 引文，全部实拉）

### 7.1 v0.2.2 JSON-RPC 方法 consts（schema 程序化提取）

```
message/send, message/stream, tasks/cancel, tasks/get,
tasks/pushNotificationConfig/get, tasks/pushNotificationConfig/set, tasks/resubscribe
```

### 7.2 v0.3.0 全部 JSON-RPC 方法 consts（schema 程序化提取）

```
message/send, message/stream, tasks/get, tasks/cancel, tasks/resubscribe,
tasks/pushNotificationConfig/set, tasks/pushNotificationConfig/get,
tasks/pushNotificationConfig/list, tasks/pushNotificationConfig/delete,
agent/getAuthenticatedExtendedCard
```

### 7.3 各方法 params 引用（schema 程序化提取）

```
SendMessageRequest          -> MessageSendParams (required=[message])
SendStreamingMessageRequest -> MessageSendParams
GetTaskRequest              -> TaskQueryParams (required=[id], 含 historyLength/metadata)
CancelTaskRequest           -> TaskIdParams (required=[id])
TaskResubscriptionRequest   -> TaskIdParams (required=[id])
SetTaskPushNotificationConfigRequest  -> TaskPushNotificationConfig (required=[taskId, pushNotificationConfig])
GetTaskPushNotificationConfigRequest  -> v0.2.2: TaskIdParams; v0.3.0: anyOf[TaskIdParams, GetTaskPushNotificationConfigParams]
GetTaskPushNotificationConfigParams   -> v0.3.0: properties=[id, metadata, pushNotificationConfigId], required=[id]
```

### 7.4 事件 required（schema，v0.2.2/v0.2.5/v0.3.0 一致）

```
TaskStatusUpdateEvent.required    = [contextId, final, kind, status, taskId]
TaskArtifactUpdateEvent.required  = [artifact, contextId, kind, taskId]
```

### 7.5 MessageSendConfiguration.required（版本差异，schema 程序化提取）

```
v0.2.2/v0.2.5: [acceptedOutputModes]
v0.3.0:        []（空）
```

### 7.6 TaskState.enum（9 值，三版本一致）

```
submitted, working, input-required, completed, canceled, failed, rejected, auth-required, unknown
```

### 7.7 Part.anyOf（三版本一致）

```
TextPart (required=[kind, text]), FilePart (required=[file, kind]), DataPart (required=[data, kind])
```

### 7.8 Agent Card 路径（markdown 实拉）

```
v0.2.2 §5.3:  https://{server_domain}/.well-known/agent.json
v0.3.0 §5.3:  https://{server_domain}/.well-known/agent-card.json
v1.0.1 §14.3: URI suffix: agent-card.json（IANA 注册）
```

### 7.9 错误码（schema error defs 程序化提取）

```
v0.2.2/v0.2.5: -32700 JSONParseError, -32600 InvalidRequestError, -32601 MethodNotFoundError,
               -32602 InvalidParamsError, -32603 InternalError, -32001 TaskNotFoundError,
               -32002 TaskNotCancelableError, -32003 PushNotificationNotSupportedError,
               -32004 UnsupportedOperationError, -32005 ContentTypeNotSupportedError,
               -32006 InvalidAgentResponseError
v0.3.0:        上述 + -32007 AuthenticatedExtendedCardNotConfiguredError
```

### 7.10 pushNotificationConfig/get 的 capabilities 要求（markdown 实拉）

```
v0.2.2 §7.6: "Retrieves the current push notification configuration for a specified task.
             Requires the server to have AgentCard.capabilities.pushNotifications: true."
v0.3.0 §7.6: 同（"Requires the server to have AgentCard.capabilities.pushNotifications: true"）
v0.3.0 §7.7 list 亦同
```

### 7.11 webhook payload 版本演变（markdown 实拉）

```
v0.2.2 §9.5: body 为 Task 对象（kind:"task"）
v1.0.1 §4.3.3: body 为 StreamResponse 包装（task/message/statusUpdate/artifactUpdate 之一）
```

### 7.12 SSE 事件格式（markdown 实拉）

```
v0.2.2 §9.3（L969-1081）：未命名事件，仅 data: 行，无 event: 字段；final:true 后服务端关闭连接
v0.3.0 §9（L1371-1462）：同上，未命名事件
```

### 7.13 Content-Length 字节计算（程序化复算）

```
S1 Agent Card body  = 501 字节 ✅（紧凑序列化）
S2 请求 body        = 258 字节 ✅
S2 响应 body        = 257 字节 ✅
```

### 7.14 测试用例统计（程序化）

```
总数 246；编号 T001-T242 连续 + T212a-T212d；无缺号无重复
正向 150 / 负向 56 / 边界 30 / 集成 8 / 并发 2 = 246
负向占比 56/246 ≈ 22.8%
21 节标题计数与逐行计数全部吻合
```

---

## 8. 最终结论

**是，本文档可直接进入实现阶段（无阻塞项）。**

- **CRITICAL：0**。协议骨架（方法名 7 核心 + v0.3.0 3 新增、Agent Card 路径、Part kind、事件类型、状态枚举、错误码、params 结构）经 v0.2.2/v0.2.5/v0.3.0/v1.0.1 实拉逐字段验证与 spec 严格一致。
- **HIGH：0**。
- **MEDIUM：0**。r3-v2 的 M-1（V8 Streaming=false 分支）已正确扩展为 5 个同步方法的完整集合，三处（V8 规则/§5.3 注释/§3.1 方法表）一致无遗漏。
- **LOW：1**。L-1（§5.3/§3.2.1 未注明 acceptedOutputModes 在 v0.3.0 起可选的版本差异）为注释级精度问题，不影响 v0.2.x 目标版本的正确性，不阻塞实现。

修复建议优先级：无必改项；L-1 可在实现阶段顺手在注释中补充版本差异说明。

---

**审计结束**。
