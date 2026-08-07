# A2A 设计文档深度对抗审计报告（独立二审）

**审计对象**：`docs/protocol-designs/17-a2a-design.md` v1.1（约 1859 行，声明 87 条用例）
**审计日期**：2026-08-04
**审计人**：独立协议审计员（非设计者，与一审 / 修订人无交叉）
**审计依据**：
1. A2A spec v0.2.2 / v0.2.5 / v0.3.0（Google A2A / a2aproject/A2A 仓库历史 tag 实拉验证）
2. JSON-RPC 2.0（https://www.jsonrpc.org/specification）
3. SSE（Server-Sent Events，HTML Living Standard §9.2；非 RFC 文档）
4. RFC 8615（Well-Known URIs）
5. `CLAUDE.md` 测试策略 8 条强制规则
6. 一审报告 `audit/16-17-mcp-a2a-audit.md` §3（A2A 16 项问题）+ v1.1 修订记录

**审计方法**：
- 通读 v1.1 全文 1859 行
- 对照 A2A spec v0.2.2 / v0.2.5 / v0.3.0 三个历史 tag（已通过 raw.githubusercontent.com 拉取 `specification/json/a2a.json` + `docs/specification.md` 核验字段）
- 逐字段比对 §3 方法表 / §4 状态机 / §5 Config 结构体 / §9 测试用例
- 6 维度对抗：spec 一致性 / 字段覆盖率 / 状态机 / 测试质量 / 内部一致性 / 已知坑
- 默认"有 bug"，除非证据确凿

---

## 1. 审计概览

### 1.1 总体结论

v1.1 修订对一审 16 项问题（2 CRITICAL + 5 HIGH + 6 MEDIUM + 3 LOW）逐项做了修复尝试，并在测试用例维度做了大量补强（87 条用例、负向占比 26.4%、新增 T64-T87 共 24 条、字节级断言）。这是值得肯定的工程态度。

但本轮独立深审（对照 spec v0.2.2 / v0.2.5 / v0.3.0 三个真实历史版本逐字段核验）发现：**v1.1 仍存在 5 项 CRITICAL spec 一致性错误**，全部集中在 spec 方法名 / 字段命名 / Part kind 这三处"协议骨架"层面。这些不是表述瑕疵，而是会让生成的字节流**无法被任何真实 A2A 服务端 / 客户端互操作**的根本性错误——因为设计文档的方法名（`tasks/send`、`tasks/sendSubscribe`、`tasks/subscribe`、`tasks/pushNotification/set`、`tasks/pushNotification/get`）在 spec 0.2.x/0.3.0 全部历史版本中**从未存在**，spec 实际方法名是 `message/send` / `message/stream` / `tasks/pushNotificationConfig/set` / `tasks/pushNotificationConfig/get`。

更严重的是：一审报告 C-3/C-4/H-6 等问题已正确指出 spec 一致性方向，但 v1.1 修订时**没有实拉 spec 原文**，仅靠"看起来合理"的猜测做了修复（如把 `tasks/unsubscribe` 删了，却保留了同样不存在的 `tasks/subscribe`；把 `data-stream`/`file-stream` 加上了，但这两种 kind 在 spec 任何版本都不存在）。这种"基于猜测的修复"导致 v1.1 引入了**新的 spec 违规**（详见 CRITICAL 部分）。

### 1.2 严重度分布

| 严重度 | 数量 | 编号 |
|--------|------|------|
| CRITICAL | 5 | D-C1, D-C2, D-C3, D-C4, D-C5 |
| HIGH | 6 | D-H1, D-H2, D-H3, D-H4, D-H5, D-H6 |
| MEDIUM | 8 | D-M1 ~ D-M8 |
| LOW | 5 | D-L1 ~ D-L5 |
| **合计** | **24** | |

### 1.3 最终结论

**否，本文档不可直接进入实现阶段。**

必须先返工的 CRITICAL 问题编号：**D-C1, D-C2, D-C3, D-C4, D-C5**。

理由：D-C1（方法名 `tasks/send` 全错）+ D-C2（方法名 `tasks/sendSubscribe` / `tasks/subscribe` 全错）+ D-C3（pushNotification 方法名错）+ D-C4（Agent Card 路径错为复数 `agents.json`）+ D-C5（`data-stream`/`file-stream` Part kind 是幻觉）这 5 项**全部是协议骨架层的字段命名错误**，实现者按此生成的 JSON-RPC 请求会被任何真实 A2A 服务端以 `-32601 Method not found` 拒绝，Agent Card 发现请求会返回 404。继续实现等同于实现一个"看起来像 A2A 但不是 A2A"的私有协议。

---

## 2. CRITICAL 问题（5 项，必须修复后才能进入实现）

### D-C1：核心方法名 `tasks/send` 在 spec 全部历史版本中均不存在

- **严重度**：CRITICAL
- **位置**：§1.1 L18（"task，任务"）、§1.3 L29（方法覆盖列表）、§1.4 L40 不变式 4、§2.1 L64 请求示例、§3 方法表 L211、§5.2 L457 Method 字段枚举、§5.5 L667 Validate 规则 2、§6.1 L686 时序图、§8.2 L904、§9.1 T01-T02、§10.1 L1509、§10.3 L1535、§11.2 L1655 MCP 集成示例、§11.6 #7 L1726、修订记录多处
- **描述**：

  设计文档把"发送任务"的 JSON-RPC 方法名定为 `tasks/send`，并在 §3 方法表（L211）声明这是 spec 0.3+ 的 8 个方法之一。§5.5 Validate 规则 2（L667）枚举合法方法集为 `{tasks/send, tasks/sendSubscribe, tasks/get, tasks/cancel, tasks/pushNotification/set, tasks/pushNotification/get, tasks/resubscribe, tasks/subscribe}`。

  **但 A2A spec 全部历史版本的实际方法名是 `message/send`，不是 `tasks/send`**。已逐 tag 核验：

  - **v0.2.2**（`specification/json/a2a.json` + `docs/specification.md`）：方法集为 `message/send` / `message/stream` / `tasks/get` / `tasks/cancel` / `tasks/pushNotificationConfig/set` / `tasks/pushNotificationConfig/get` / `tasks/resubscribe` —— **无 `tasks/send`**。`message/send` 的描述是"Sends a message to an agent to initiate a new interaction or to continue an existing one"。
  - **v0.2.5**（同上）：方法集与 v0.2.2 一致 —— **无 `tasks/send`**。
  - **v0.3.0**（`specification/json/a2a.json` + `docs/specification.md`）：方法集为 `message/send` / `message/stream` / `tasks/get` / `tasks/cancel` / `tasks/pushNotificationConfig/{set,get,list,delete}` / `tasks/resubscribe` / `agent/getAuthenticatedExtendedCard` —— **无 `tasks/send`**。
  - **v1.0**（最新）：方法集改为 PascalCase `SendMessage` / `SendStreamingMessage` / `GetTask` / `CancelTask` / `SubscribeToTask` / `CreateTaskPushNotificationConfig` 等，HTTP 路径为 `/message:send` / `/message:stream` —— **仍无 `tasks/send`**。

  即设计文档声明的"spec 0.3+ 方法集共 8 个：tasks/send、tasks/sendSubscribe、tasks/get、tasks/cancel、tasks/pushNotification/set、tasks/pushNotification/get、tasks/resubscribe、tasks/subscribe"中——**`tasks/get` / `tasks/cancel` / `tasks/resubscribe` 这 3 个是对的，其余 5 个全是错的**。

- **依据**：
  - A2A spec v0.2.2 §7.1：方法名 `message/send`（https://raw.githubusercontent.com/a2aproject/A2A/refs/tags/v0.2.2/docs/specification.md）
  - A2A spec v0.2.5 `a2a.json`：`"const": "message/send"`（https://raw.githubusercontent.com/a2aproject/A2A/refs/tags/v0.2.5/specification/json/a2a.json）
  - A2A spec v0.3.0 `a2a.json`：`"const": "message/send"`（https://raw.githubusercontent.com/a2aproject/A2A/refs/tags/v0.3.0/specification/json/a2a.json）
- **影响**：
  1. 实现者按 §3 方法表生成 `{"method":"tasks/send",...}` 请求，真实 A2A 服务端（v0.2.x/0.3.0/v1.0）会以 `-32601 Method not found` 拒绝——**整个协议的核心方法名错了**。
  2. §5.5 Validate 规则 2 把合法方法集枚举为含 `tasks/send`，会把真实合法的 `message/send` 当作"非法方法"拒绝（实现者按此 Validate 写代码，用户配置 `message/send` 会被报错）。
  3. §11.6 #7（L726）"Task ID 与 Request ID 区分"的注释基于错误的 method 名立论。
  4. 一审报告 C-3（SSE RFC 引用）/ C-4（credentials map）已正确指出 spec 一致性方向，但**修订人没有实拉 spec 验证方法名**，导致这个最根本的错误在三轮修订（v1.0→v1.1）中始终未被发现。
- **修复建议**：
  1. §1.1 / §1.3 / §1.4 / §2.1 / §3 方法表 / §5.2 Method 注释 / §5.5 Validate 规则 2 / §6.1 时序图 / §8.2 / §9.1 / §10.1 / §10.3 / §11.2 全文替换：`tasks/send` → `message/send`；`tasks/sendSubscribe` → `message/stream`（详见 D-C2）
  2. §5.5 Validate 规则 2 合法方法集改为：`{message/send, message/stream, tasks/get, tasks/cancel, tasks/pushNotificationConfig/set, tasks/pushNotificationConfig/get, tasks/pushNotificationConfig/list, tasks/pushNotificationConfig/delete, tasks/resubscribe, agent/getAuthenticatedExtendedCard}`（v0.3.0 实际 10 个方法）
  3. §3 方法表"注：A2A spec 0.3+ 定义的方法集共 8 个"改为"共 10 个"（v0.3.0）或"共 7 个"（v0.2.2）
  4. 修订记录应新增"v1.2 修复 D-C1：方法名 tasks/send → message/send（spec 一致性）"

### D-C2：方法名 `tasks/sendSubscribe` 与 `tasks/subscribe` 在 spec 中均不存在

- **严重度**：CRITICAL
- **位置**：§1.3 L29、§1.4 不变式 8 L48、§2.3 L92（SSE 流标题）、§3 方法表 L212/L218、§5.2 L457 Method 字段、§5.4 L656-L657 默认值表、§5.5 L667 规则 2、§5.5 规则 6 L671、§6.2 L713 时序图、§7.1 L814-L816 包序列、§7.4 L841 Accept 头、§8.3 L947、§8.8 L1056、§9.1 T08-T09/T14-T15、§10.1 L1518、§10.3 L1536/L1541、§10.9 L1608-L1609 对抗清单、T75/T87
- **描述**：

  设计文档把"流式发送任务"的方法名定为 `tasks/sendSubscribe`，把"订阅已有 task"的方法名定为 `tasks/subscribe`。§5.5 Validate 规则 6（L671）甚至专门为"流式方法"定义了一个拒绝规则：`Streaming=false + Method ∈ {tasks/sendSubscribe, tasks/subscribe, tasks/resubscribe}` 拒绝。

  **但 A2A spec 全部历史版本的实际方法名是 `message/stream`（流式发送）和 `tasks/resubscribe`（断线重连）—— 没有 `tasks/sendSubscribe`，也没有 `tasks/subscribe`**：

  - **v0.2.2/v0.2.5/v0.3.0**：方法集为 `message/send`（同步）/ `message/stream`（流式）/ `tasks/resubscribe`（断线重连）。**没有 `tasks/sendSubscribe`，没有 `tasks/subscribe`**。
  - spec 中 `tasks/resubscribe` 的语义是"reconnect to an SSE stream after interruption"——即断线重连，**不是**"订阅已有 task"。设计文档把 `tasks/subscribe` 当作独立方法（§3 方法表 L218："订阅已有 task 的 SSE 流"）是凭空发明。
  - 一审报告 M-10 已指出 `tasks/unsubscribe` 不存在，v1.1 删除了 `tasks/unsubscribe`，**但保留了同样不存在的 `tasks/subscribe`**——这是修复不彻底。

- **依据**：A2A spec v0.2.2/v0.2.5/v0.3.0 `docs/specification.md` + `specification/json/a2a.json`：方法集均无 `tasks/sendSubscribe` / `tasks/subscribe`
- **影响**：
  1. 实现者按 §3 方法表生成 `{"method":"tasks/sendSubscribe",...}` 请求，真实 A2A 服务端以 `-32601` 拒绝。
  2. §5.5 Validate 规则 6 把不存在的 `tasks/sendSubscribe` / `tasks/subscribe` 当作"流式方法"保护，真实流式方法 `message/stream` 反而没被规则 6 覆盖——规则 6 形同虚设。
  3. T75（`Streaming=false + sendSubscribe`）/ T87（`Streaming=false + resubscribe`）测试用例基于错误方法名，固化了 spec 违规。
  4. §7.4 Accept 头生成规则（L841）"sendSubscribe/subscribe/resubscribe → Accept: text/event-stream"对真实 `message/stream` 不生效。
- **修复建议**：
  1. 全文替换：`tasks/sendSubscribe` → `message/stream`；删除 `tasks/subscribe`（spec 无此方法）
  2. §5.5 规则 6 流式方法集改为：`{message/stream, tasks/resubscribe}`
  3. §3 方法表删除 `tasks/subscribe` 行；`tasks/sendSubscribe` 改为 `message/stream` 并更名"流式发送消息"
  4. T08/T09/T14/T15 测试用例方法名同步更新；T87 改为 `message/stream` + `Streaming=false`
  5. §10.9 对抗清单"尝试 Method='tasks/send' + Streaming=true"改为"message/send + Streaming=true"

### D-C3：方法名 `tasks/pushNotification/set` 与 `tasks/pushNotification/get` 应为 `tasks/pushNotificationConfig/set` 与 `tasks/pushNotificationConfig/get`

- **严重度**：CRITICAL
- **位置**：§1.3 L29、§3 方法表 L215-L216、§5.2 L457 Method 字段枚举、§5.5 L667 规则 2、§8.6 L1022、§8.7 L1045、§9.1 T12-T13、§10.3 L1539-L1540、§11.4 L1683 扩展表字段
- **描述**：

  设计文档把推送通知配置的方法名定为 `tasks/pushNotification/set` / `tasks/pushNotification/get`（注意：`pushNotification` 单数，无 `Config`）。

  **但 A2A spec 全部历史版本的实际方法名是 `tasks/pushNotificationConfig/set` / `tasks/pushNotificationConfig/get`（含 `Config`）**：

  - **v0.2.2** §7.5：方法名 `tasks/pushNotificationConfig/set`
  - **v0.2.5**：同上
  - **v0.3.0**：方法集扩展为 `tasks/pushNotificationConfig/{set,get,list,delete}` 4 个方法（设计文档只列了 set/get，漏了 list/delete）
  - **v1.0**：改为 PascalCase `CreateTaskPushNotificationConfig` / `GetTaskPushNotificationConfig` / `ListTaskPushNotificationConfigs` / `DeleteTaskPushNotificationConfig`

  设计文档不仅方法名拼写错误（少了 `Config`），还遗漏了 v0.3.0 新增的 `tasks/pushNotificationConfig/list` 和 `tasks/pushNotificationConfig/delete` 两个方法。

- **依据**：A2A spec v0.2.2/v0.2.5/v0.3.0 `docs/specification.md` §7.5：方法名 `tasks/pushNotificationConfig/set`（含 `Config`）
- **影响**：
  1. 实现者按 §3 方法表生成 `{"method":"tasks/pushNotification/set",...}` 请求，真实 A2A 服务端以 `-32601` 拒绝。
  2. §11.4 扩展表 17 上报字段"方法分布"会基于错误方法名统计，导致上报数据无法与真实 A2A 服务端日志对齐。
  3. T12/T13 测试用例固化了错误方法名。
- **修复建议**：
  1. 全文替换：`tasks/pushNotification/set` → `tasks/pushNotificationConfig/set`；`tasks/pushNotification/get` → `tasks/pushNotificationConfig/get`
  2. §3 方法表新增 v0.3.0 的 `tasks/pushNotificationConfig/list` 和 `tasks/pushNotificationConfig/delete` 两个方法（或在"注"中说明 v1 不实现 list/delete）
  3. §5.5 规则 2 合法方法集同步更新
  4. T12/T13 方法名同步更新；可选新增 T88/T89 测试 list/delete

### D-C4：Agent Card well-known 路径应为 `/.well-known/agent.json`（单数），不是 `/.well-known/agents.json`（复数）

- **严重度**：CRITICAL
- **位置**：§1.3 L31、§1.4 不变式 10 L49、§2.4 L118 标题与示例、§5.1 L345-L348 AgentCardPath 字段、§5.4 L644 默认值表、§8.1 L879/L881、§9.2 T16、§9.2 T19、§10.1 L1519、§11.6 #6 L1725、修订记录 L-6/L-7
- **描述**：

  设计文档把 Agent Card 的 well-known 路径定为 `/.well-known/agents.json`（复数 `agents`）。§1.4 不变式 10（L49）："Agent Card 默认路径 `/.well-known/agents.json`（RFC 8615）"。§2.4 示例（L121）：`GET /.well-known/agents.json HTTP/1.1`。

  **但 A2A spec 全部历史版本的实际路径是 `/.well-known/agent.json`（单数 `agent`）**：

  - **v0.2.2** §5.3："The recommended location is `https://{server_domain}/.well-known/agent.json`"
  - **v0.2.5**：同上
  - **v0.3.0**：路径改为 `/.well-known/agent-card.json`（v0.3.0 release notes #841："Changed from agent.json to agent-card.json"）—— 但**仍是单数，不是复数 `agents.json`**
  - **v1.0**：`/.well-known/agent.json`（单数，恢复）

  设计文档用复数 `agents.json` 在 spec 任何版本中都不存在。一审报告 L-6/L-7 已指出 §1.4 不变式 10 与 §5.1 AgentCardPath 字段的内部矛盾，v1.1 修复时改了措辞但**没有实拉 spec 验证路径名**，导致"复数 vs 单数"这个根本错误未被发现。

- **依据**：
  - A2A spec v0.2.2 §5.3：`/.well-known/agent.json`（单数）
  - A2A spec v0.3.0 release notes #841：改为 `/.well-known/agent-card.json`（仍是单数）
  - RFC 8615：well-known URI 注册表机制（设计文档引用正确，但路径名错）
- **影响**：
  1. 实现者按 §2.4 生成 `GET /.well-known/agents.json` 请求，真实 A2A 服务端返回 404（路径不存在）。
  2. §9.2 T16/T19 测试用例断言"GET /.well-known/agents.json"，固化错误路径。
  3. §11.6 #6（L1725）"Agent Card 默认路径 /.well-known/agents.json 是 RFC 8615 标准路径"——RFC 8615 是机制标准，不是路径名标准；路径名由 A2A spec 定义，spec 用单数。
  4. 一审 L-6/L-7 修复时把"固定"改为"默认，可覆盖"，但底层路径名仍错。
- **修复建议**：
  1. 全文替换：`/.well-known/agents.json` → `/.well-known/agent.json`（v0.2.x/v1.0）或 `/.well-known/agent-card.json`（v0.3.0）
  2. §5.1 AgentCardPath 默认值改为 `/.well-known/agent.json`（推荐用 v0.2.x/v1.0 的单数形式，因 v0.3.0 的 `agent-card.json` 已被 v1.0 撤回）
  3. §1.4 不变式 10 同步修正
  4. T16/T19 测试用例路径同步更新
  5. §11.6 #6 改为"Agent Card 默认路径 /.well-known/agent.json（单数，A2A spec v0.2.x/v1.0；v0.3.0 临时用 agent-card.json 已被 v1.0 撤回）"

### D-C5：Part kind `data-stream` 与 `file-stream` 是幻觉，spec 任何版本都不存在

- **严重度**：CRITICAL
- **位置**：§1.4 不变式 5 L44、§2.6 L171-L172 Part kind 表、§2.6 L174 注意、§5.2 L571 A2APart.Kind 注释、§5.5 规则 4 L669、§9.11 T64-T65、§10.1 L1518、修订记录 H-6 L1761
- **描述**：

  设计文档 §2.6 Part 联合类型表列出 5 种 kind：`text` / `data` / `file` / `data-stream` / `file-stream`。§1.4 不变式 5（L44）："Part `kind` 可为 text/data/file/data-stream/file-stream（spec 0.3+）"。§5.5 规则 4（L669）Validate 接受这 5 种 kind。修订记录 H-6（L1761）声称："§2.6 增加 data-stream / file-stream 两行……spec 0.3 引入"。

  **但 A2A spec 全部历史版本的 Part kind 只有 3 种：`text` / `data` / `file`，从未有过 `data-stream` / `file-stream`**：

  - **v0.2.2** §6.5：Part union "MUST be one of the following": TextPart (kind:"text") / FilePart (kind:"file") / DataPart (kind:"data") —— **3 种**
  - **v0.2.5** `a2a.json`：Part anyOf TextPart/FilePart/DataPart —— **3 种**
  - **v0.3.0** `a2a.json`：Part anyOf TextPart/FilePart/DataPart —— **3 种**
  - **v1.0**：Part 改为 oneof `text`/`raw`/`url`/`data`（去掉 kind 字段，改用 oneof content）—— **仍无 data-stream/file-stream**

  修订记录 H-6 声称"spec 0.3 引入 data-stream/file-stream"是**伪造的 spec 引用**——这与一审报告 3R-C1（MCP includeContext 幻觉字段）是同一类错误："基于猜测的 spec 引用"。v1.1 修订人没有实拉 spec v0.3.0 验证，而是凭"spec 0.3+ 应该有流式 Part"的直觉加了两种 kind。

  spec 实际的流式语义在 `TaskStatusUpdateEvent` / `TaskArtifactUpdateEvent` 两个独立事件类型上（v0.3.0 §7.2.2/§7.2.3），**不在 Part 层**。Part 始终是原子单元，流式由 SSE 事件流承载。

- **依据**：
  - A2A spec v0.2.2 §6.5：Part 3 种 kind
  - A2A spec v0.3.0 `a2a.json`：Part anyOf 3 种（TextPart/FilePart/DataPart）
  - A2A spec v1.0 `a2a.proto`：Part oneof content 4 种（text/raw/url/data），无 kind 字段
- **影响**：
  1. 实现者按 §2.6 生成 `{"kind":"data-stream","data":{...}}` Part，真实 A2A 服务端会按 JSON schema 校验失败（schema 只允许 kind ∈ {text,data,file}）。
  2. §5.5 规则 4 Validate 接受 `data-stream`/`file-stream`，把不合法的 kind 当合法——实现者写 Validate 代码时会接受 spec 违规输入。
  3. T64/T65 测试用例基于幻觉 kind，固化 spec 违规。
  4. 修订记录 H-6 的"修复"反而**引入了新的 spec 违规**——v1.0 没有 data-stream/file-stream，v1.1 凭空加了。这是"修复回归"。
  5. 违反 CLAUDE.md 测试策略规则 1（spec-driven）：测试了 spec 不存在的字段。
- **修复建议**：
  1. §2.6 Part kind 表删除 `data-stream` / `file-stream` 两行
  2. §1.4 不变式 5 改为"Part `kind` 可为 text/data/file（spec 0.2.x/0.3.0）"
  3. §5.2 A2APart.Kind 注释改为"kind ∈ {text, data, file}"
  4. §5.5 规则 4 改为"A2APart.Kind ∈ {text, data, file}"
  5. T64/T65 删除（或改为测试 TaskArtifactUpdateEvent 的流式 artifact 传输，这是 spec 真实的流式语义）
  6. 修订记录新增"v1.2 撤销 v1.1 H-6 的 data-stream/file-stream（spec 任何版本都不存在，是幻觉）"

---

## 3. HIGH 问题（6 项）

### D-H1：`PushNotificationConfig.UserID` 字段是幻觉，spec 任何版本都无此字段

- **严重度**：HIGH
- **位置**：§2.8 L194（注："spec 0.3 `PushNotificationConfig` 仅含上述 4 个字段"）、§5.2 L614-L619 `A2APushNotificationConfig` 结构体、§5.2 L612 注释
- **描述**：

  设计文档 §5.2 `A2APushNotificationConfig` 结构体（L614-L619）：

  ```go
  type A2APushNotificationConfig struct {
      URL            string               `json:"url"`
      Token          string               `json:"token,omitempty"`
      Authentication *A2AAuthentication   `json:"authentication,omitempty"`
      UserID         string               `json:"user_id,omitempty"`  // 幻觉字段
  }
  ```

  §2.8 表（L188-L194）列出 4 个字段：`url` / `token` / `authentication` / `userId`，并在注（L195）中说"spec 0.3 `PushNotificationConfig` 仅含上述 4 个字段；凭证通过 `authentication.credentials` 传递，无顶层 `credentials` map"。

  **但 A2A spec 全部历史版本的 `PushNotificationConfig` 实际字段是 `url` / `token` / `authentication` / `id`（v0.2.x/v0.3.0），没有 `userId`**：

  - **v0.2.2** §6.8：`PushNotificationConfig` 字段 = `url` / `token` / `authentication`（3 个，无 `id`，无 `userId`）
  - **v0.2.5**：同 v0.2.2
  - **v0.3.0** `a2a.json`：`PushNotificationConfig` 字段 = `url`(required) / `id` / `token` / `authentication`（4 个，有 `id`，**无 `userId`**）
  - **v1.0** `a2a.proto`：`TaskPushNotificationConfig` 字段 = `tenant` / `id` / `task_id` / `url` / `token` / `authentication`（6 个，**无 `user_id`**）

  设计文档 §2.8 注明确说"spec 0.3 仅含 4 个字段：url/token/authentication/userId"——这是**伪造的 spec 引用**。spec 0.3.0 的第 4 个字段是 `id`（push notification config 的唯一标识），不是 `userId`。

  v1.1 修订记录 C-4（L1755）声称"删除 `Credentials map[string]string` 字段（spec 0.3 无此字段）"——这个修复方向正确，但**修订人没有顺带核查 `UserID` 字段是否在 spec 中存在**，导致 `Credentials` 删了但同样幻觉的 `UserID` 留下了。

- **依据**：
  - A2A spec v0.3.0 `a2a.json` `PushNotificationConfig`：properties = `{url, id, token, authentication}`，无 `userId`
  - A2A spec v1.0 `a2a.proto` `TaskPushNotificationConfig`：fields = `{tenant, id, task_id, url, token, authentication}`，无 `user_id`
- **影响**：
  1. 实现者按 §5.2 生成 `{"url":"...","userId":"u1"}` 的 PushNotificationConfig，真实 A2A 服务端会按 JSON schema 校验失败（schema 不允许 `userId` 字段）或忽略该字段。
  2. §2.8 注"spec 0.3 仅含 4 个字段"是虚假声明，违反 CLAUDE.md 测试策略规则 1（spec-derived）。
  3. v1.1 修订记录 C-4 修复 `Credentials` 幻觉时，遗漏了同源的 `UserID` 幻觉——修复不彻底。
- **修复建议**：
  1. §5.2 `A2APushNotificationConfig` 删除 `UserID` 字段；新增 `ID string` 字段（json:"id,omitempty"）
  2. §2.8 表第 4 行 `userId` 改为 `id`，说明改为"push notification config 的唯一标识（v0.3.0+）"
  3. §2.8 注改为"spec 0.3.0 含 4 字段：url/id/token/authentication；v0.2.x 含 3 字段（无 id）"
  4. 修订记录新增"v1.2 修复 D-H1：UserID → ID（spec 0.3.0 实际字段）"

### D-H2：`AgentCard.Authentication` 字段名错，spec 用 `securitySchemes` + `security`

- **严重度**：HIGH
- **位置**：§2.4 L134 示例、§5.1 L398 `A2AAgentCard.Authentication` 字段、§5.1 L422-L425 `A2AAuthentication` 类型、§5.5 规则 5 L670、§8.14.5 L1124、§9.12 T66-T67/T74/T82、§10.1 L1520、§10.6 L1577-L1579、修订记录 M-11
- **描述**：

  设计文档 §2.4 Agent Card 示例（L134）：`"authentication": {"schemes":["bearer"]}`。§5.1 `A2AAgentCard`（L398）有 `Authentication *A2AAuthentication` 字段。`A2AAuthentication`（L422-L425）含 `Schemes []string` + `Credentials string`。

  **但 A2A spec 全部历史版本的 AgentCard 用的是 `securitySchemes`（map）+ `security`（数组）两个字段，不是单一 `authentication` 对象**：

  - **v0.2.2** §5.5 AgentCard 字段：`securitySchemes: { [scheme: string]: SecurityScheme }` + `security: { [scheme: string]: string[] }[]` —— **无 `authentication` 字段**
  - **v0.2.5/v0.3.0**：同 v0.2.2
  - **v1.0** `a2a.proto`：`security_schemes` (map) + `security_requirements` (repeated) —— **无 `authentication` 字段**

  spec 的 `SecurityScheme` 是一个 oneof 联合类型（APIKeySecurityScheme / HTTPAuthSecurityScheme / OAuth2SecurityScheme / OpenIdConnectSecurityScheme / MutualTlsSecurityScheme），每种 scheme 有自己的字段结构——**不是简单的 `{schemes: [], credentials: ""}`**。

  设计文档把 spec 复杂的 `securitySchemes` + `security` 简化为单一 `authentication: {schemes, credentials}`，这是**字段结构幻觉**。`A2AAuthentication` 类型（含 `Schemes []string`）实际对应 spec 的 `PushNotificationAuthenticationInfo`（用于 PushNotificationConfig.authentication），不是 AgentCard 的认证字段。

  §5.5 规则 5（L670）"A2AAuthentication.Schemes 中每个值 ∈ {bearer, basic, oauth2}（小写）"也是基于幻觉字段——spec 的 `securitySchemes` 是 map（key 是 scheme 名，value 是 SecurityScheme 对象），不是 string 数组。

- **依据**：
  - A2A spec v0.2.2 §5.5 AgentCard：`securitySchemes` + `security` 字段
  - A2A spec v0.3.0 `a2a.json` AgentCard：`securitySchemes` + `security` 字段
  - A2A spec v1.0 `a2a.proto` AgentCard：`security_schemes` + `security_requirements`
- **影响**：
  1. 实现者按 §5.1 生成 AgentCard JSON 含 `"authentication":{"schemes":["bearer"]}`，真实 A2A 客户端按 spec 解析会找不到 `securitySchemes` 字段，无法发现认证要求。
  2. §5.5 规则 5 校验 `A2AAuthentication.Schemes` 小写——但 spec 的 `securitySchemes` 是 map，key 命名遵循 OpenAPI 规范（如 `"google"` / `"bearerAuth"`），不是固定枚举。
  3. T66/T67/T74/T82 测试用例基于幻觉字段结构，固化 spec 违规。
  4. §5.1 `A2AAuthentication` 类型被同时用于 AgentCard 和 PushNotificationConfig——但 spec 中两者结构不同（AgentCard 用 SecurityScheme oneof，PushNotificationConfig 用 PushNotificationAuthenticationInfo {schemes, credentials}）。
- **修复建议**：
  1. §5.1 `A2AAgentCard` 删除 `Authentication *A2AAuthentication` 字段；新增 `SecuritySchemes map[string]A2ASecurityScheme` 和 `Security []map[string][]string` 字段
  2. §5.1 新增 `A2ASecurityScheme` 类型（oneof：APIKey/HTTPAuth/OAuth2/OpenIdConnect/MutualTLS），或简化为 `map[string]any` 占位
  3. `A2AAuthentication` 类型保留，但仅用于 `PushNotificationConfig.Authentication`（spec 名 `PushNotificationAuthenticationInfo`）
  4. §2.4 Agent Card 示例改为 `"securitySchemes": {...}, "security": [...]`
  5. §5.5 规则 5 改为校验 `PushNotificationConfig.Authentication.Schemes`（小写 bearer/basic/oauth2 是 PushNotificationAuthenticationInfo 的语义，OpenAPI 的 securitySchemes 无此约束）
  6. T66-T67/T74/T82 测试用例同步更新

### D-H3：`TaskStatusUpdateEvent.Artifact` 字段错置——artifact 在 `TaskArtifactUpdateEvent`，不在 `TaskStatusUpdateEvent`

- **严重度**：HIGH
- **位置**：§2.7 L184（TaskStatusUpdateEvent 表）、§5.2 无对应结构体（设计文档未定义 TaskStatusUpdateEvent Go 类型）
- **描述**：

  设计文档 §2.7 TaskStatusUpdateEvent 表（L178-L184）列出字段：`id` / `status` / `final` / `artifact` / `metadata`。其中 `artifact` 字段（L184）说明为"流式产出 artifact"。

  **但 A2A spec 中 `TaskStatusUpdateEvent` 没有 `artifact` 字段——artifact 在独立的 `TaskArtifactUpdateEvent` 事件类型中**：

  - **v0.2.2** §7.2.2 `TaskStatusUpdateEvent`：字段 = `taskId` / `contextId` / `kind`("status-update") / `status` / `final` / `metadata` —— **6 个字段，无 `artifact`**
  - **v0.2.2** §7.2.3 `TaskArtifactUpdateEvent`：字段 = `taskId` / `contextId` / `kind`("artifact-update") / `artifact` / `append` / `lastChunk` / `metadata` —— **artifact 在这里**
  - **v0.3.0**：同 v0.2.2 结构
  - **v1.0** `a2a.proto`：`TaskStatusUpdateEvent` = `task_id` / `context_id` / `status` / `metadata`（无 final，无 artifact）；`TaskArtifactUpdateEvent` = `task_id` / `context_id` / `artifact` / `append` / `last_chunk` / `metadata`

  设计文档把 `artifact` 字段塞进 `TaskStatusUpdateEvent`，混淆了 spec 的两个独立事件类型。spec 的流式语义是：`statusUpdate` 事件携带状态变化，`artifactUpdate` 事件携带 artifact 产出——**两者是 SSE 流中并列的不同事件，不是同一个事件的字段**。

  另外，§2.7 字段名用 `id`（L180），spec 用 `taskId`（camelCase）——字段名也不一致。

- **依据**：A2A spec v0.2.2 §7.2.2 / §7.2.3；v0.3.0 `a2a.json` TaskStatusUpdateEvent / TaskArtifactUpdateEvent 定义
- **影响**：
  1. 实现者按 §2.7 生成 `{"kind":"status-update","artifact":{...}}` 事件，真实 A2A 客户端按 spec 解析会忽略 `artifact` 字段（schema 不允许）或校验失败。
  2. spec 的 `TaskArtifactUpdateEvent`（携带 artifact）在整个设计文档中**完全没有出现**——这是遗漏整个事件类型。
  3. §2.7 `id` 字段名错（应为 `taskId`），实现者生成 `{"id":"task-1"}` 而非 `{"taskId":"task-1"}`，客户端解析失败。
- **修复建议**：
  1. §2.7 TaskStatusUpdateEvent 表删除 `artifact` 字段；字段名 `id` 改为 `taskId`；新增 `contextId` / `kind` 字段
  2. §2.7 新增 `TaskArtifactUpdateEvent` 子节，字段 = `taskId` / `contextId` / `kind`("artifact-update") / `artifact` / `append` / `lastChunk` / `metadata`
  3. §5.2 新增 `A2ATaskStatusUpdateEvent` 和 `A2ATaskArtifactUpdateEvent` Go 结构体
  4. §8.3 SSE 流示例应同时展示 status-update 和 artifact-update 两类事件
  5. 新增测试用例：SSE 流含混合 status-update + artifact-update 事件

### D-H4：SSE 事件名固定为 `update` 但 spec 用未命名事件（仅 `data:` 行）

- **严重度**：HIGH
- **位置**：§2.3 L100-L104 示例、§2.3 L112 表格行、§6.2 L727/L731 时序图、§6.6 L768/L772/L776 SSE 示例、§8.3 L947、§9.1 T08、§10.1 L1513、§10.7 L1586、修订记录 S-2 L1791
- **描述**：

  设计文档 §2.3 SSE 事件格式表（L112）："事件类型，本协议固定 `update`"。所有 SSE 示例都用 `event: update\n`。修订记录 S-2（L1791）："§2.3 事件名行加注'A2A spec 0.3 建议此名但非强制；本设计固定以简化实现与测试断言'"。

  **但 A2A spec 全部历史版本的 SSE 流用未命名事件（仅 `data:` 行，无 `event:` 字段）**：

  - **v0.2.2** §3.3.1："each SSE `data` field contains a complete JSON-RPC 2.0 Response object"——示例只有 `data:` 行，无 `event:` 字段
  - **v0.2.5/v0.3.0**：同 v0.2.2
  - spec 的 SSE 示例（§9.3）全部是 `data: {...}\n\n` 形式，**没有 `event: update` 或任何 `event:` 行**

  修订记录 S-2 声称"A2A spec 0.3 建议此名但非强制"——这是**伪造的 spec 引用**。spec 0.3.0 从未建议过 `event: update`，spec 明确用未命名事件，事件类型区分通过 JSON payload 的 `kind` 字段（`"kind":"status-update"` / `"kind":"artifact-update"` / `"kind":"task"` / `"kind":"message"`）实现。

- **依据**：A2A spec v0.2.2/v0.2.5/v0.3.0 §3.3.1 + §9.3 SSE 示例：仅 `data:` 行，无 `event:` 字段
- **影响**：
  1. 实现者按 §2.3 生成 `event: update\ndata: {...}\n\n`，真实 A2A 客户端解析 SSE 时会收到带 `event:update` 的 NamedEvent，而 spec 客户端期望的是未命名 MessageEvent——两者在 EventSource API 中是不同的事件类型（`addEventListener("update", ...)` vs `addEventListener("message", ...)`），导致客户端无法接收事件。
  2. T08 字节级断言"第 1 事件以 `event: update\ndata: {` 开头"固化了 spec 违规。
  3. §10.7 L1586"流式用例断言字节级：第 1 事件以 `event: update\ndata: {` 开头"同上。
- **修复建议**：
  1. §2.3 SSE 事件格式表删除"event: <name>"行；改为"本协议使用未命名 SSE 事件（仅 `data:` 行），事件类型通过 JSON payload 的 `kind` 字段区分（spec 0.2.x/0.3.0）"
  2. §2.3 所有 SSE 示例删除 `event: update\n` 行
  3. §6.2/§6.6/§8.3 SSE 示例同步删除 `event: update`
  4. T08 / T57 字节级断言改为"第 1 事件以 `data: {` 开头"
  5. §10.1 L1513 / §10.7 L1586 同步更新
  6. 修订记录 S-2 撤销"固定 event: update"，改为"使用未命名事件（spec 一致）"

### D-H5：`Task` 状态枚举遗漏 `rejected` 和 `auth-required`（spec 0.2.2+ 已有 9 个状态）

- **严重度**：HIGH
- **位置**：§1.4 不变式 6 L45、§4.1 L254-L262 状态枚举表、§5.5 规则 1 L666、§5.2 L484-L487 State 字段注释
- **描述**：

  设计文档 §4.1 状态枚举表列出 7 个状态：`submitted` / `working` / `input-required` / `completed` / `canceled` / `failed` / `unknown`。§1.4 不变式 6（L45）："Task 状态枚举固定 7 个……不允许其他值"。§5.5 规则 1（L666）Validate 接受的 state 集合也是这 7 个 + ""。

  **但 A2A spec v0.2.2+ 的 TaskState 枚举有 9 个值**：

  - **v0.2.2** §6.3：`submitted` / `working` / `input-required` / `completed` / `canceled` / `failed` / `rejected` / `auth-required` / `unknown` —— **9 个**
  - **v0.2.5/v0.3.0** `a2a.json`：同上 9 个
  - **v1.0** `a2a.proto`：`TASK_STATE_UNSPECIFIED` / `SUBMITTED` / `WORKING` / `COMPLETED` / `FAILED` / `CANCELED` / `INPUT_REQUIRED` / `REJECTED` / `AUTH_REQUIRED` —— 9 个（含 UNSPECIFIED）

  设计文档遗漏了 `rejected`（agent 拒绝执行任务）和 `auth-required`（需要认证才能继续）两个状态。这两个都是 spec 0.2.2 就有的状态，不是 0.3.0 新增。

  §5.5 规则 1 Validate 会把合法的 `rejected` / `auth-required` 状态当作"非法 state"拒绝——这会导致用户无法生成 spec 合规的 rejected/auth-required 流量。

- **依据**：A2A spec v0.2.2 §6.3 TaskState 枚举 9 个值；v0.3.0 `a2a.json` 同上
- **影响**：
  1. 实现者按 §5.5 规则 1 写 Validate，会拒绝合法的 `rejected` / `auth-required` 状态配置。
  2. §4.2 状态转换表完全没有 `rejected` / `auth-required` 的转换行——状态机不完整。
  3. §9.3 状态机用例 T20-T24 只覆盖 5 个状态（submitted/working/input-required/completed/canceled/failed/unknown 中选 5），无 rejected/auth-required 用例。
  4. §3.1 错误码表无对应 rejected/auth-required 的错误码（spec 中 auth-required 对应 -32007 AuthenticatedExtendedCardNotConfiguredError 的语义边界，需核查）。
- **修复建议**：
  1. §4.1 状态枚举表新增 `rejected`（已拒绝，终态）和 `auth-required`（需认证，中断态）两行
  2. §1.4 不变式 6 改为"Task 状态枚举固定 9 个"
  3. §5.5 规则 1 合法 state 集合新增 `rejected` / `auth-required`
  4. §4.2 状态转换表新增：`submitted → rejected` / `submitted → auth-required` / `auth-required → working` / `auth-required → canceled` 等转换
  5. §9.3 新增 T88/T89 测试 rejected / auth-required 状态机用例

### D-H6：错误码 `-32004` 语义错——spec 是 `UnsupportedOperationError`，设计文档定义为 `Streaming not supported`

- **严重度**：HIGH
- **位置**：§3.1 L244 错误码表、§8.19.8 L1307、§9.8 T51、§10.3 L1543
- **描述**：

  设计文档 §3.1 错误码表（L244）：`-32004 | Streaming not supported | capabilities.streaming=false`。§8.19.8（L1307）："streaming not supported（-32004），capabilities.streaming=false 但调用 sendSubscribe，响应：code -32004"。T51 测试同。

  **但 A2A spec 的 -32004 是 `UnsupportedOperationError`，语义是"操作不支持"，与 streaming 无关**：

  - **v0.2.2** §8.2：`-32004 | UnsupportedOperationError | Operation or aspect of it not supported by the server`
  - **v0.2.5/v0.3.0**：同 v0.2.2
  - spec 中 `capabilities.streaming=false` 调用流式方法应返回的是 `UnsupportedOperationError`（-32004）的一种实例，但 message 应是"Streaming not supported"——错误码本身的语义是"操作不支持"，不是"流式不支持"。

  设计文档把 -32004 的 message 固定为"Streaming not supported"，并把 §3.1 表的"触发场景"限定为"capabilities.streaming=false"——这窄化了 spec 语义。spec 的 -32004 还可用于"不支持 pushNotification/list"等其他操作不支持场景。

  另外，spec v0.3.0 还有 -32006 `InvalidAgentResponseError` 和 -32007 `AuthenticatedExtendedCardNotConfiguredError` 两个错误码，设计文档 §3.1 完全没有列出。

- **依据**：A2A spec v0.2.2/v0.3.0 §8.2 错误码表
- **影响**：
  1. 实现者按 §3.1 把 -32004 语义固定为"Streaming not supported"，无法生成 spec 合规的其他 -32004 场景（如 pushNotification/list 不支持）。
  2. §3.1 遗漏 -32006 / -32007，用户无法配置这两个错误响应。
  3. T51 断言 -32004 的 message="Streaming not supported"，固化了窄化语义。
- **修复建议**：
  1. §3.1 -32004 行改为"`-32004 | UnsupportedOperationError | 操作不支持（含 streaming/pushNotification/list 等场景）`"
  2. §3.1 新增 -32006 `InvalidAgentResponseError` 和 -32007 `AuthenticatedExtendedCardNotConfiguredError`（v0.3.0）
  3. §5.5 规则 8 Validate 接受的 error code 集合新增 -32006 / -32007
  4. §8.19 新增"invalid agent response（-32006）"和"authenticated extended card not configured（-32007）"场景
  5. T51 保留但 message 改为"Streaming not supported"（spec 合规的 -32004 实例）；新增 T90 测试 -32006、T91 测试 -32007

---

## 4. MEDIUM 问题（8 项）

### D-M1：§5.2 `A2APart` 结构体允许 Part 同时携带多种 content 字段，违反 spec oneof 语义

- **严重度**：MEDIUM
- **位置**：§5.2 L570-L576 `A2APart` 结构体、§5.2 L568 注释
- **描述**：

  设计文档 §5.2 `A2APart`（L570-L576）：

  ```go
  type A2APart struct {
      Kind     string         `json:"kind"`
      Text     string         `json:"text,omitempty"`
      Data     map[string]any `json:"data,omitempty"`
      File     *A2AFile       `json:"file,omitempty"`
      Metadata map[string]any `json:"metadata,omitempty"`
  }
  ```

  §5.2 注释（L568）："the planner does not enforce exclusivity (a single Part may carry multiple fields, with kind selecting the canonical one)"。

  **但 A2A spec 的 Part 是 oneof 联合类型，text/data/file 三者互斥**：
  - v0.2.2 §6.5：Part union "MUST be one of the following"
  - v0.3.0 `a2a.json`：Part anyOf TextPart/FilePart/DataPart，每个子类型用 `kind` discriminator + 对应 content 字段（TextPart 只有 text，FilePart 只有 file，DataPart 只有 data）
  - v1.0 `a2a.proto`：Part oneof content（text/raw/url/data 互斥）

  设计文档允许"Part 同时携带 text + data + file"是 spec 违规。注释"planner does not enforce exclusivity"是承认违规但不修复。

- **依据**：A2A spec v0.2.2 §6.5 / v0.3.0 `a2a.json` Part anyOf 定义
- **影响**：
  1. 实现者按 §5.2 生成 `{"kind":"text","text":"hello","data":{...}}` Part，真实 A2A 客户端按 schema 校验失败（TextPart schema 不允许 data 字段）。
  2. §5.5 规则 4 只校验 Kind 枚举值，不校验 content 字段互斥——Validate 漏检。
- **修复建议**：
  1. §5.2 `A2APart` 改为 oneof 语义：用 interface{} 或独立类型 `A2ATextPart` / `A2ADataPart` / `A2AFilePart`
  2. 或保留单结构体但 §5.5 新增 Validate 规则：`Kind=text` 时 `Data`/`File` 必须为 nil；`Kind=data` 时 `Text`/`File` 必须为 nil；`Kind=file` 时 `Text`/`Data` 必须为 nil
  3. §5.2 注释删除"does not enforce exclusivity"

### D-M2：§5.2 `A2AFile.Bytes` 字段类型为 `string`，spec 是 base64 编码 bytes

- **严重度**：MEDIUM
- **位置**：§5.2 L580 `A2AFile` 结构体
- **描述**：

  设计文档 §5.2 `A2AFile`（L580）：`Bytes string `json:"bytes,omitempty"` // base64-encoded`。

  spec v0.2.2/v0.3.0 的 FilePart.file.bytes 字段确实是 base64 字符串，但 spec v1.0 改为 `bytes` 类型（proto bytes，JSON 编码为 base64）。设计文档用 `string` 类型在 JSON 序列化时与 spec 一致，但注释"base64-encoded"应更明确。

  这本身不是大错，但 §5.2 `A2AFilePart`（L587-L592）的 `BytesB64 string` 字段命名与 `A2AFile.Bytes` 不一致（一个叫 Bytes，一个叫 BytesB64），实现者可能混淆。

- **依据**：A2A spec v0.2.2 §6.5 FilePart；v0.3.0 `a2a.json` FilePart.file.bytes
- **影响**：字段命名不一致，实现者需额外记忆两个字段名。
- **修复建议**：
  1. §5.2 `A2AFile.Bytes` 注释改为"base64-encoded file content（spec v0.2.x/0.3.0 file.bytes）"
  2. §5.2 `A2AFilePart.BytesB64` 改名为 `Bytes`（与 `A2AFile` 一致），或统一用 `A2AFile` 类型替换 `A2AFilePart`

### D-M3：§4.2 状态转换表 `input-required → completed` 标"罕见"但 spec 未明确允许

- **严重度**：MEDIUM（一审 M-12 修复不彻底）
- **位置**：§4.2 L281、§9.14 T83、§10.9 L1619
- **描述**：

  v1.1 修订记录 M-12（L1773）："§4.2 改为'spec 未明确允许；Validate 警告但不拒绝（保留以兼容潜在服务端实现）'"。§4.2 L281 现状："input-required → completed | spec 未明确允许；Validate 警告但不拒绝（罕见路径，保留以兼容潜在服务端实现）"。

  **但 A2A spec v0.2.2/v0.3.0 的状态转换语义中，`input-required` 是"Pause"状态（等待用户输入），spec 没有定义 `input-required → completed` 转换**。spec §6.3 明确的状态转换是：
  - `submitted → working / canceled / failed / rejected / auth-required`
  - `working → completed / failed / canceled / input-required / auth-required`
  - `input-required → working / canceled / failed`（用户响应后 resume 或取消或超时）

  spec 没有列 `input-required → completed`。v1.1 保留此转换并"警告但不拒绝"是设计选择，但 T83 测试此转换的存在会让实现者误以为这是 spec 合规路径。

- **依据**：A2A spec v0.2.2/v0.3.0 §6.3 TaskState + 状态转换语义
- **影响**：
  1. T83 测试 `input-required → completed` 转换，实现者按此生成流量，真实 A2A 服务端可能拒绝。
  2. §10.9 L1619 "尝试 input-required → completed 转换：Validate 警告但不拒绝" 固化了 spec 违规测试。
- **修复建议**：
  1. §4.2 `input-required → completed` 行改为"spec 不允许；Validate 拒绝（'invalid state transition: input-required → completed'）"
  2. T83 改为负向用例："input-required → completed → Validate 拒绝"
  3. §10.9 L1619 改为"尝试 input-required → completed：Validate 拒绝"

### D-M4：§5.5 规则 5 强制 schemes 小写是错误约束——spec 的 securitySchemes 是 map，无大小写约束

- **严重度**：MEDIUM（与 D-H2 同源，但聚焦 Validate 规则）
- **位置**：§5.5 规则 5 L670、§9.13 T74、§10.6 L1578
- **描述**：

  §5.5 规则 5："A2AAuthentication.Schemes 中每个值 ∈ {bearer, basic, oauth2}（小写）"。T74 测试"大写 Bearer 被拒绝"。

  如 D-H2 所述，spec 的 AgentCard 用 `securitySchemes` (map) + `security` (array)，不是 `authentication.schemes` (string array)。`A2AAuthentication.Schemes` 实际对应 spec 的 `PushNotificationAuthenticationInfo.schemes`，spec 对其值无大小写枚举约束（spec 示例用 `"Bearer"` 大写，见 v0.3.0 §9.5 示例 `"authentication": { "schemes": ["Bearer"] }`）。

  设计文档强制小写 `bearer`/`basic`/`oauth2` 与 spec 示例 `"Bearer"` 大写矛盾。

- **依据**：A2A spec v0.3.0 §9.5 示例 `"schemes": ["Bearer"]`（大写）；v0.2.2 §6.8 PushNotificationAuthenticationInfo 无大小写约束
- **影响**：
  1. T74 断言"大写 Bearer 被拒绝"，但 spec 示例用大写——实现者按 T74 写 Validate 会拒绝 spec 合规输入。
  2. §5.5 规则 5 的"小写"约束无 spec 依据。
- **修复建议**：
  1. §5.5 规则 5 改为"`PushNotificationConfig.Authentication.Schemes` 中每个值应为非空字符串（spec 无大小写约束；推荐用 RFC 7235 注册的 scheme 名，如 Bearer/Basic/Bearer）"
  2. T74 改为"非法 scheme 空字符串 → Validate 拒绝"
  3. §10.6 L1578 "A2AAuthentication.Schemes 大写值被 Validate 拒绝"删除

### D-M5：§5.1 `A2AAgentCard` 缺少 spec 必填字段 `protocolVersion`，多了 spec 没有的字段

- **严重度**：MEDIUM
- **位置**：§5.1 L391-L401 `A2AAgentCard` 结构体
- **描述**：

  设计文档 §5.1 `A2AAgentCard`（L391-L401）：

  ```go
  type A2AAgentCard struct {
      Name              string
      Description       string
      URL               string
      Version           string
      Capabilities      *A2ACapabilities
      Skills            []A2ASkill
      Authentication    *A2AAuthentication   // 错，见 D-H2
      DefaultInputModes []string
      DefaultOutputModes []string
  }
  ```

  spec v0.2.2 AgentCard 必填字段：`name` / `description` / `url` / `version` / `capabilities` / `defaultInputModes` / `defaultOutputModes` / `skills` —— **8 个必填**。可选字段含 `protocolVersion`（v0.2.5+ 必填）/ `provider` / `iconUrl` / `documentationUrl` / `securitySchemes` / `security` / `supportsAuthenticatedExtendedCard` 等。

  设计文档 `A2AAgentCard` 缺少 `ProtocolVersion`（v0.2.5+ 必填）、`Provider` / `IconURL` / `DocumentationURL` / `SupportsAuthenticatedExtendedCard` 等可选字段。多了 `Authentication`（spec 无此字段，见 D-H2）。

- **依据**：A2A spec v0.2.2 §5.5 AgentCard 字段表；v0.2.5 protocolVersion 改为必填
- **影响**：
  1. 实现者按 §5.1 生成 AgentCard JSON 缺 `protocolVersion` 字段，spec v0.2.5+ 服务端拒绝。
  2. §5.4 默认值表未给 `ProtocolVersion` 默认值。
- **修复建议**：
  1. §5.1 `A2AAgentCard` 新增 `ProtocolVersion string` 字段（json:"protocolVersion"），默认值 "0.3.0"
  2. 新增 `Provider` / `IconURL` / `DocumentationURL` / `SupportsAuthenticatedExtendedCard` 可选字段
  3. 删除 `Authentication` 字段（见 D-H2），改为 `SecuritySchemes` + `Security`
  4. §5.4 默认值表新增 `ProtocolVersion` 默认 "0.3.0"

### D-M6：§5.2 `A2AAuthentication` 类型混淆了 spec 的 `PushNotificationAuthenticationInfo` 与 AgentCard 的 `SecurityScheme`

- **严重度**：MEDIUM（D-H2 的衍生）
- **位置**：§5.1 L422-L425 `A2AAuthentication`、§5.2 L617 `A2APushNotificationConfig.Authentication`
- **描述**：

  设计文档定义单一 `A2AAuthentication` 类型（含 `Schemes []string` + `Credentials string`），同时用于：
  - `A2AAgentCard.Authentication`（spec 实际是 `securitySchemes` map + `security` array，结构完全不同）
  - `A2APushNotificationConfig.Authentication`（spec 实际是 `PushNotificationAuthenticationInfo`，字段是 `schemes []string` + `credentials string`）

  spec 的 `PushNotificationAuthenticationInfo` 字段是 `schemes`（小写 s，复数）+ `credentials`，与设计文档的 `A2AAuthentication`（`Schemes` + `Credentials`）字段名一致但 JSON 序列化不同（设计文档 `Schemes` → JSON "schemes"，OK；但 `A2AAgentCard.Authentication` 用同一类型则错——AgentCard 应是 `securitySchemes` map）。

- **依据**：A2A spec v0.2.2 §5.5 vs §6.8
- **影响**：实现者用同一 Go 类型序列化两种 spec 不同结构，会产出一种对的（PushNotificationConfig）一种错的（AgentCard）。
- **修复建议**：
  1. `A2AAuthentication` 改名为 `A2APushNotificationAuth`，仅用于 `A2APushNotificationConfig.Authentication`
  2. `A2AAgentCard` 新增独立的 `SecuritySchemes map[string]A2ASecurityScheme` + `Security []map[string][]string` 字段（见 D-H2）
  3. §5.1 删除 `A2AAuthentication` 的 AgentCard 用途说明

### D-M7：§3 方法表"params 必填字段"列与 spec 实际 params 结构不符

- **严重度**：MEDIUM
- **位置**：§3 方法表 L209-L218、§3 通用字段表 L222-L231
- **描述**：

  §3 方法表"params 必填字段"列：`tasks/send | id, message` / `tasks/sendSubscribe | id, message` / `tasks/get | id` 等。

  **但 spec 的 params 结构与设计文档描述不符**：
  - spec `message/send` params = `message` (required) + `configuration` (optional SendMessageConfiguration) + `metadata` (optional) —— **无 `id` 字段**（task id 由服务端分配，不在请求 params 中）
  - spec `message/stream` params = 同 `message/send`
  - spec `tasks/get` params = `id` (required) + `historyLength` (optional) + `metadata` (optional)
  - spec `tasks/cancel` params = `id` (required) + `metadata` (optional)
  - spec `tasks/pushNotificationConfig/set` params = `id` (required, task id) + `pushNotificationConfig` (required) + `metadata` (optional)

  设计文档把 `id` 列为 `tasks/send` 的必填 params 字段是错——spec 的 `message/send` 不带 task id（task id 在响应中由服务端分配）。设计文档 §2.1 示例（L64）`"params":{"id":"task-001","sessionId":"sess-abc","message":{...}}` 也带了 `id` 字段，这与 spec 不符。

  另外 `sessionId` 在 spec 中不是 Message 级别的字段——spec 用 `contextId`（Message.contextId）做会话关联，不用 `sessionId`。

- **依据**：A2A spec v0.2.2/v0.3.0 §7.1 SendMessageRequest params = {message, configuration?, metadata?}，无 id/sessionId
- **影响**：
  1. 实现者按 §3 方法表生成 `{"id":"task-1","message":{...}}` 请求，真实 A2A 服务端会忽略 `id` 字段（spec 不识别）或 -32602 Invalid params。
  2. §2.1 示例固化了错误 params 结构。
  3. `sessionId` vs `contextId` 命名差异会导致会话关联失败。
- **修复建议**：
  1. §3 方法表 `message/send` / `message/stream` 的 params 必填字段改为 `message`（删除 `id`）
  2. §2.1 示例改为 `"params":{"message":{"role":"user","parts":[...],"contextId":"sess-abc"}}`
  3. §3 通用字段表删除 `sessionId` 行，改为 `contextId`（Message 字段，非 params 顶级字段）
  4. §5.2 `A2ATask.SessionID` 改名为 `ContextID`，或保留 SessionID 但说明"映射到 Message.contextId"

### D-M8：§5.2 `A2ATask.ID` 作为请求 params 的 `id` 字段，但 `message/send` 请求不带 id——设计混淆了请求与响应

- **严重度**：MEDIUM（D-M7 的衍生）
- **位置**：§5.2 L449 `A2ATask.ID` 字段、§5.2 L457 Method 字段注释
- **描述**：

  设计文档 §5.2 `A2ATask.ID`（L449）："ID (任务 ID): the A2A task ID. Empty defaults to 'task-<index>'"。这个 ID 被用于：
  - 请求 params.id（§2.1 示例 L64）
  - 响应 result.id（§2.2 示例 L83）

  **但 spec 中 `message/send` 请求不带 task id（task id 由服务端分配），只有 `tasks/get` / `tasks/cancel` 等查询/操作类请求才带 id**。设计文档把同一个 `A2ATask.ID` 用于请求和响应两端，混淆了 spec 语义：
  - 请求端：`message/send` params 无 id；`tasks/get` params 有 id
  - 响应端：`message/send` 响应 result（Task 对象）有 id（服务端分配）

  设计文档 §5.2 `A2ATask.ID` 注释"客户端分配"是错——spec 中 task id 由服务端分配。

- **依据**：A2A spec v0.2.2 §7.1 SendMessageRequest 无 id 字段；§6.1 Task.id 由服务端分配
- **影响**：
  1. 实现者按 §5.2 在 `message/send` 请求 params 中填 `id`，spec 服务端忽略或拒绝。
  2. §5.2 注释"客户端分配"与 spec"服务端分配"矛盾。
- **修复建议**：
  1. §5.2 `A2ATask.ID` 注释改为"任务 ID（响应中由服务端分配；请求中仅 tasks/get/cancel/pushNotificationConfig/* 携带此 id）"
  2. §5.2 新增字段 `RequestID` 已有（JSON-RPC id），但需明确区分 Task.ID（A2A 协议层）vs RequestID（JSON-RPC 信封 id）
  3. §2.1 `message/send` 请求示例删除 params.id；§2.2 响应示例保留 result.id

---

## 5. LOW 问题（5 项）

### D-L1：§5.2 `A2AAgentCard.Description` 在 spec v0.2.2 是必填，设计文档标 `omitempty`

- **严重度**：LOW
- **位置**：§5.1 L393 `Description string ... json:"description,omitempty"`
- **描述**：spec v0.2.2 §5.5 AgentCard `description` 是必填字段。设计文档 `omitempty` 表示空值时省略，会生成缺 `description` 字段的 AgentCard JSON，被 spec 服务端拒绝。
- **依据**：A2A spec v0.2.2 §5.5
- **修复建议**：`Description` 的 `omitempty` 删除（必填字段不应 omitempty）；或 §5.4 默认值表给 Description 默认值 "A2A Agent"

### D-L2：§5.1 `A2ASkill` 字段 `ID`/`Name`/`Description` 在 spec v0.2.2 全部必填，设计文档 `Name`/`Description` 标 `omitempty`

- **严重度**：LOW
- **位置**：§5.1 L411-L416 `A2ASkill`
- **描述**：spec v0.2.2 §5.5.4 AgentSkill 必填字段 = `id` / `name` / `description` / `tags`。设计文档 `Name`/`Description` 用 `omitempty`，会生成缺这些字段的 skill。
- **依据**：A2A spec v0.2.2 §5.5.4
- **修复建议**：`Name`/`Description` 的 `omitempty` 删除；`Tags` 也应必填（spec 标 required）

### D-L3：§2.5 Task 对象表 `sessionId` 字段在 spec 中不存在（spec 用 `contextId`）

- **严重度**：LOW（与 D-M7 同源，但聚焦 Task 对象）
- **位置**：§2.5 L145 Task 对象表
- **描述**：§2.5 Task 对象表列出 `sessionId` 字段。spec v0.2.2/v0.3.0 Task 对象字段 = `id` / `contextId` / `status` / `artifacts` / `history` / `metadata` —— **无 `sessionId`**。设计文档用 `sessionId` 是字段名错。
- **依据**：A2A spec v0.2.2 §6.1 Task 对象定义
- **修复建议**：§2.5 `sessionId` 改为 `contextId`；§5.2 `A2ATask.SessionID` 改名为 `ContextID`

### D-L4：§11.6 #4 "Content-Length 与流式：流式路径响应不应有 Content-Length"——SSE 可用 chunked 或连接关闭定界，但 spec 未禁止 Content-Length

- **严重度**：LOW
- **位置**：§11.6 #4 L1723
- **描述**：设计文档断言"流式路径响应不应有 Content-Length"。HTTP/1.1 SSE 实践中通常用 chunked transfer-encoding（无 Content-Length），但 spec 未明确禁止 Content-Length（若服务端 buffer 全部 SSE 事件后一次性发送，可带 Content-Length）。设计文档的绝对断言过于强。
- **依据**：HTTP/1.1 RFC 7230 + SSE 实践
- **修复建议**：§11.6 #4 改为"流式路径响应通常用 chunked transfer-encoding（无 Content-Length）；planner 默认省略 Content-Length，但接受用户显式设置"

### D-L5：§9 测试用例编号 T83 出现两次（§9.14 状态机边界 + 隐含在 §9.13 负向补全引用）

- **严重度**：LOW
- **位置**：§9.14 T83 L1490
- **描述**：§9.14 标题"状态机边界用例（1 条，针对 M-12）"，T83 出现。但 §9.13 负向补全用例的 T81 引用"tasks/cancel 已终态 task（state mismatch）"与 T83 的 input-required → completed 边界用例编号相近，易混淆。实际 T83 仅出现一次，但 §9.13 标题"12 条"与 T73-T82+T86+T87 共 12 条计数对，T83 单独成节——分类逻辑可改善。
- **依据**：§9.13 vs §9.14 编号
- **修复建议**：T83 移到 §9.7 边界用例（与 T25 stateTransitionHistory 空同类），或 §9.14 改名为"状态机边界用例（1 条）"并加注"T83 与 §9.13 负向用例不重叠"

---

## 6. 字段覆盖率核查（针对 v1.1 声明的 23 字段）

v1.1 修订记录声称字段覆盖率提升至 23/23 = 100%。本轮核查发现：v1.1 新增的 T66-T72 用例确实覆盖了原缺测字段，**但覆盖的是设计文档自己定义的字段集，不是 spec 实际字段集**。

按 spec 实际字段重新核查：

| # | spec 实际字段 | 设计文档字段 | 测试用例 | 状态 |
|---|------|------|---------|------|
| 1 | AgentCard.name | A2AAgentCard.Name | T72 | OK |
| 2 | AgentCard.description | A2AAgentCard.Description | T72（隐含） | OK |
| 3 | AgentCard.url | A2AAgentCard.URL | T16（隐含） | OK |
| 4 | AgentCard.version | A2AAgentCard.Version | T16（隐含） | OK |
| 5 | AgentCard.protocolVersion | **缺失** | 无 | **缺字段 D-M5** |
| 6 | AgentCard.capabilities | A2AAgentCard.Capabilities | T17/T69 | OK |
| 7 | AgentCard.skills | A2AAgentCard.Skills | T18/T72 | OK |
| 8 | AgentCard.securitySchemes | **错为 Authentication** | T66（基于幻觉字段） | **错字段 D-H2** |
| 9 | AgentCard.security | **缺失** | 无 | **缺字段 D-H2** |
| 10 | AgentCard.defaultInputModes | A2AAgentCard.DefaultInputModes | T70 | OK |
| 11 | AgentCard.defaultOutputModes | A2AAgentCard.DefaultOutputModes | T71 | OK |
| 12 | AgentCapabilities.streaming | A2ACapabilities.Streaming | T69 | OK |
| 13 | AgentCapabilities.pushNotifications | A2ACapabilities.PushNotifications | T12（隐含） | OK |
| 14 | AgentCapabilities.stateTransitionHistory | A2ACapabilities.StateTransitionHistory | T20-T25 | OK |
| 15 | Task.id | A2ATask.ID | T01/T10 | OK |
| 16 | Task.contextId | **错为 sessionId** | T02 | **错字段 D-L3** |
| 17 | Task.status | A2ATask.State/StatusMessage/Timestamp | T01/T05/T68 | OK |
| 18 | Task.history | A2ATask.History | T06 | OK |
| 19 | Task.artifacts | A2ATask.Artifacts | T07 | OK |
| 20 | Task.metadata | A2ATask.Metadata | T30-T33 | OK |
| 21 | Message.role | A2AMessage.Role | T01 | OK |
| 22 | Message.parts | A2AMessage.Parts | T01-T04 | OK |
| 23 | Message.messageId | A2AMessage.MessageID | **无** | **缺测** |
| 24 | Message.contextId | A2AMessage.ContextID | **无** | **缺测** |
| 25 | Message.taskId | A2AMessage.TaskID | **无** | **缺测** |
| 26 | Part.kind (text/data/file) | A2APart.Kind | T01/T03/T04 | OK |
| 27 | PushNotificationConfig.url | A2APushNotificationConfig.URL | T12 | OK |
| 28 | PushNotificationConfig.id | **缺失** | 无 | **缺字段 D-H1** |
| 29 | PushNotificationConfig.token | A2APushNotificationConfig.Token | T12 | OK |
| 30 | PushNotificationConfig.authentication | A2APushNotificationConfig.Authentication | T67 | OK |
| 31 | TaskStatusUpdateEvent.taskId | **错为 id** | T08（隐含） | **错字段 D-H3** |
| 32 | TaskStatusUpdateEvent.kind | **缺失** | 无 | **缺字段 D-H3** |
| 33 | TaskStatusUpdateEvent.final | 设计文档有 | T08 | OK |
| 34 | TaskArtifactUpdateEvent（整个类型） | **缺失** | 无 | **缺类型 D-H3** |

**实际 spec 字段覆盖率**：约 22/34 ≈ 65%（设计文档声称 100% 基于错误的字段集）。

---

## 7. 测试用例质量核查（CLAUDE.md 测试策略 8 条规则）

| 规则 | v1.1 状态 | 本轮核查 |
|------|----------|---------|
| 规则 1 spec-driven | v1.1 声称 23/23 字段覆盖 | **违反**：基于错误的字段集（D-H1/D-H2/D-H3/D-M5 等字段幻觉或缺失）；T64/T65 测试幻觉 Part kind（D-C5） |
| 规则 2 失败路径 | v1.1 负向占比 26.4% | **达标**（数量上）；但 T74/T75/T87 等负向用例基于错误的 Validate 规则（D-M4/D-C2） |
| 规则 3 一测试一路径 | v1.1 新增 T87 覆盖 resubscribe 路径 | **部分违反**：T64/T65 测试不存在的 Part kind 路径；T83 测试 spec 违规路径（D-M3） |
| 规则 4 集成测试 | T56-T59 存在 | **部分违反**：T56 断言"POST /"路径，但 spec message/send 路径是 POST 到 AgentCard.url（不是 "/"） |
| 规则 5 断言可观察值 | v1.1 增加字节级断言 | **部分违反**：T08 断言 `event: update\ndata: {` 开头，但 spec SSE 用未命名事件（D-H4） |
| 规则 6 并发正确性 | T84/T85 存在 | **达标** |
| 规则 7 失败测试先行 | 修订记录提及 | 不适用（实现阶段） |
| 规则 8 测试质量对抗 | §10.7 清单 | **违反**：§10.7 清单基于错误的字段集和方法集 |

---

## 8. 内部一致性核查

v1.1 修订记录声称修复了 4 处内部矛盾（H-8/H-9/H-10/M-14）+ 1 处自查矛盾（S-1）+ 3 处表述不一致（M-12/M-13/L-6/L-7）。本轮核查发现 v1.1 仍存在以下内部矛盾：

1. **§5.5 规则 6 流式方法集** vs **§3 方法表**：规则 6 列 `{tasks/sendSubscribe, tasks/subscribe, tasks/resubscribe}`，§3 方法表也列这些——两者一致，但都错（应为 `message/stream` + `tasks/resubscribe`）。
2. **§2.7 TaskStatusUpdateEvent.artifact** vs **spec TaskArtifactUpdateEvent**：设计文档把 artifact 塞进 TaskStatusUpdateEvent，spec 在独立事件类型——内部自洽但与 spec 不一致。
3. **§5.2 `A2AAuthentication` 同时用于 AgentCard 和 PushNotificationConfig**：内部复用同一类型，但 spec 两者结构不同——内部自洽但与 spec 不一致。
4. **§9.11 T64/T65 测试 data-stream/file-stream** vs **§2.6 Part kind 表**：两者一致，但都错（spec 无此 kind）。

---

## 9. 已知坑核查（§11.6）

§11.6 列出 12 条已知坑。本轮核查：

| # | 坑内容 | 核查 |
|---|--------|------|
| 1 | SSE 事件边界 `\n\n` | 正确 |
| 2 | SSE 多行 data 拆分 | 正确 |
| 3 | HTTP keep-alive Connection 头 | 正确 |
| 4 | Content-Length 与流式 | 部分错（D-L4） |
| 5 | JSON-RPC id 类型一致性 | 正确 |
| 6 | Agent Card 默认路径 | 错（D-C4：agents.json → agent.json） |
| 7 | Task ID 与 Request ID 区分 | 正确 |
| 8 | stateTransitionHistory 同步 vs 流式 | 正确 |
| 9 | unknown 状态不带 message | 设计选择，OK |
| 10 | pushNotification URL 校验 | 正确 |
| 11 | capabilities 与方法兼容性 | 正确 |
| 12 | AgentCard 字段 vs DiscoverAgentCard | 正确 |

**新增应加入已知坑**：
- spec 方法名是 `message/send` / `message/stream`，不是 `tasks/send` / `tasks/sendSubscribe`（D-C1/D-C2）
- Agent Card 路径是单数 `agent.json`，不是复数 `agents.json`（D-C4）
- Part kind 只有 `text` / `data` / `file`，无 `data-stream` / `file-stream`（D-C5）
- TaskStatusUpdateEvent 与 TaskArtifactUpdateEvent 是两个独立事件类型，不要混淆（D-H3）
- SSE 用未命名事件，不要加 `event: update`（D-H4）

---

## 10. 修复优先级与返工建议

### 10.1 必须修复（CRITICAL，阻断实现）

| 编号 | 问题 | 修复工作量 |
|------|------|-----------|
| D-C1 | 方法名 tasks/send → message/send（全文替换 + Validate 规则 + 测试用例） | 大（涉及 §1-§11 全文） |
| D-C2 | 方法名 tasks/sendSubscribe → message/stream；删除 tasks/subscribe | 大 |
| D-C3 | 方法名 tasks/pushNotification/{set,get} → tasks/pushNotificationConfig/{set,get} | 中 |
| D-C4 | 路径 agents.json → agent.json | 中 |
| D-C5 | 删除 Part kind data-stream / file-stream | 中（涉及 §2.6/§5.2/§5.5/T64-T65） |

### 10.2 建议修复（HIGH，影响互操作性）

| 编号 | 问题 | 修复工作量 |
|------|------|-----------|
| D-H1 | PushNotificationConfig.UserID → ID | 小 |
| D-H2 | AgentCard.Authentication → SecuritySchemes + Security | 大（结构体重构） |
| D-H3 | TaskStatusUpdateEvent.Artifact 删除；新增 TaskArtifactUpdateEvent 类型 | 中 |
| D-H4 | SSE 删除 event: update 行 | 中（涉及所有 SSE 示例） |
| D-H5 | Task 状态枚举新增 rejected / auth-required | 中 |
| D-H6 | 错误码 -32004 语义修正；新增 -32006/-32007 | 小 |

### 10.3 可选修复（MEDIUM + LOW）

D-M1 ~ D-M8、D-L1 ~ D-L5 可在实现过程中并行修复。

### 10.4 返工建议

1. **第一步**：实拉 spec v0.3.0 `a2a.json` 与 `docs/specification.md`，逐字段比对设计文档 §2-§5，重写方法表 / 字段表 / 结构体
2. **第二步**：重写 §9 测试用例，确保每个用例对应 spec 实际字段（不是设计文档自造字段）
3. **第三步**：跑一次"spec 字段存在性"断言——每个声称来自 spec 的字段，测试其是否真的出现在 spec schema 中（CLAUDE.md 测试策略规则 1 的硬性要求）
4. **第四步**：实现者应实时拉取 spec（而非依赖设计文档的 spec 引用），以 spec 为准

---

## 11. 总结

### 11.1 发现问题总数

**24 项**：5 CRITICAL + 6 HIGH + 8 MEDIUM + 5 LOW

### 11.2 各严重度数量

| 严重度 | 数量 |
|--------|------|
| CRITICAL | 5 |
| HIGH | 6 |
| MEDIUM | 8 |
| LOW | 5 |
| **合计** | **24** |

### 11.3 最终结论

**否，本文档不可直接进入实现阶段。**

必须先返工的问题编号：**D-C1、D-C2、D-C3、D-C4、D-C5**（5 项 CRITICAL）。

理由：这 5 项全部是协议骨架层的字段命名错误（方法名 / Agent Card 路径 / Part kind），实现者按此生成的 JSON-RPC 请求会被任何真实 A2A 服务端以 `-32601 Method not found` 拒绝，Agent Card 发现请求会返回 404。继续实现等同于实现一个"看起来像 A2A 但不是 A2A"的私有协议。

v1.1 修订对一审 16 项问题的修复方向部分正确（如 C-3 SSE RFC 引用、C-4 credentials map 删除），但**修订人没有实拉 spec 原文验证**，导致：
- 一审 M-10 修了 `tasks/unsubscribe` 但留下了同样不存在的 `tasks/subscribe`
- 一审 C-4 删了 `Credentials` 但留下了同样幻觉的 `UserID`
- 一审 H-6 加了 `data-stream`/`file-stream` 但 spec 任何版本都没有这两种 kind（**修复回归**）
- 一审 L-6/L-7 改了"固定 vs 可覆盖"措辞但没改底层路径名 `agents.json` → `agent.json`

这种"基于猜测的修复"模式与一审报告 3R-C1（MCP includeContext 幻觉 spec 引用）是同一类错误的复发——**修订人需要养成"每个 spec 引用都实拉原文验证"的习惯**，否则修订本身会引入新的 spec 违规。

**v1.1 的"修订后文档通过对抗复审"声明不成立**。本轮独立深审发现的 5 项 CRITICAL + 6 项 HIGH 问题必须在实现前修复。建议 v1.2 修订重点：实拉 spec v0.3.0 `a2a.json` 与 `docs/specification.md`，逐字段重写 §2-§5，删除所有幻觉字段与方法名，确保每个字段都有 spec 出处。

---

**审计结束**。

附件：
- spec v0.2.2：https://raw.githubusercontent.com/a2aproject/A2A/refs/tags/v0.2.2/docs/specification.md
- spec v0.2.2 JSON schema：https://raw.githubusercontent.com/a2aproject/A2A/refs/tags/v0.2.2/specification/json/a2a.json
- spec v0.3.0 JSON schema：https://raw.githubusercontent.com/a2aproject/A2A/refs/tags/v0.3.0/specification/json/a2a.json
- spec v1.0 proto：https://raw.githubusercontent.com/a2aproject/A2A/main/specification/a2a.proto
