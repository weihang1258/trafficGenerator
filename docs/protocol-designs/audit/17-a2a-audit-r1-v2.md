# A2A 设计文档独立复审报告（v2.0.0 复审，r1-v2）

**审计对象**：`docs/protocol-designs/17-a2a-design.md` v2.0.0（2098 行，声明 203 条用例 / 修订记录称 242 条）
**审计日期**：2026-08-05
**审计人**：独立协议审计员（与 v1.1 深审报告 `audit/17-a2a-audit-deep.md` 的审计员无交叉）
**审计依据**（全部实拉验证）：
1. A2A spec v0.2.2 `specification/json/a2a.json` + `docs/specification.md`（https://raw.githubusercontent.com/a2aproject/A2A/v0.2.2/...）
2. A2A spec v0.2.5 `specification/json/a2a.json`（https://raw.githubusercontent.com/a2aproject/A2A/v0.2.5/...）
3. A2A spec v0.2.6 `docs/specification.md`（https://raw.githubusercontent.com/a2aproject/A2A/v0.2.6/...）
4. A2A spec v0.3.0 `specification/json/a2a.json` + `docs/specification.md`（https://raw.githubusercontent.com/a2aproject/A2A/v0.3.0/...）
5. A2A spec v1.0.0 / v1.0.1 `docs/specification.md`（https://raw.githubusercontent.com/a2aproject/A2A/v1.0.0/...）
6. JSON-RPC 2.0（https://www.jsonrpc.org/specification）
7. `CLAUDE.md` 测试策略 8 条强制规则

> 注：任务要求对照 "A2A spec v0.3.0"（可用 `https://raw.githubusercontent.com/google/A2A/main/specification/json/a2a.json` 核实）。该路径已 404（a2a.json 是构建产物，不入库，仓库已迁移至 a2aproject/A2A），故改拉历史 tag 的 `a2a.json` 与 `docs/specification.md` 逐版本核验。

**审计方法**：
- 通读 v2.0.0 全文 2098 行
- 逐字段核对 7 个方法名 / Agent Card 路径 / Part kind / 事件类型 / 9 个状态枚举 / SSE 格式 / JSON-RPC 信封
- 对每个 HexDump 场景的 JSON body 实际计算字节数验证 Content-Length
- 统计测试用例数量、负向占比、编号连续性
- 核对 Validate 规则 V1-V15 与测试用例声称行为的对应关系
- 默认"有 bug"，除非证据确凿

---

## 1. 审计概览

### 1.1 协议骨架核对结果（重点检查项）

| 重点检查项 | 结果 | 依据 |
|-----------|------|------|
| 方法名 `message/send` | ✅ 正确 | v0.2.2/v0.2.5/v0.3.0 `a2a.json`：`"const": "message/send"` |
| 方法名 `message/stream` | ✅ 正确 | 同上，`"const": "message/stream"` |
| 方法名 `tasks/get` | ✅ 正确 | 同上，`"const": "tasks/get"`（params=TaskQueryParams{id 必填}） |
| 方法名 `tasks/cancel` | ✅ 正确 | 同上，`"const": "tasks/cancel"`（params=TaskIdParams{id 必填}） |
| 方法名 `tasks/resubscribe` | ✅ 正确 | 同上，`"const": "tasks/resubscribe"`（params=TaskIdParams） |
| 方法名 `tasks/pushNotificationConfig/set` | ✅ 正确 | 同上，`"const": "tasks/pushNotificationConfig/set"`（params=TaskPushNotificationConfig{taskId, pushNotificationConfig 必填}） |
| 方法名 `tasks/pushNotificationConfig/get` | ✅ 正确 | 同上，`"const": "tasks/pushNotificationConfig/get"`（params=TaskIdParams；v0.3.0 加可选 pushNotificationConfigId） |
| v0.3.0 新方法 list/delete/getAuthenticatedExtendedCard | ✅ 正确 | v0.3.0 `a2a.json` 确认 `tasks/pushNotificationConfig/list`、`tasks/pushNotificationConfig/delete`、`agent/getAuthenticatedExtendedCard` |
| Agent Card 路径 `/.well-known/agent.json` | ⚠️ 设计选择对 v0.2.x 正确，但 v1.0 事实陈述错误（见 H-1） | v0.2.2/v0.2.5/v0.2.6：`/.well-known/agent.json`；v0.3.0/v1.0.0/v1.0.1：`/.well-known/agent-card.json` |
| Part kind 仅 text/data/file | ✅ 正确 | v0.2.2/v0.2.5/v0.3.0 `Part.anyOf` = TextPart/FilePart/DataPart；FilePart 仅 file/kind/metadata |
| TaskArtifactUpdateEvent | ✅ 类型正确（字段/必填齐全） | v0.2.2/v0.3.0 required = artifact/contextId/kind/taskId；append/lastChunk 可选 |
| Task 状态 9 枚举 | ✅ 正确 | v0.2.2/v0.3.0 `TaskState.enum` = submitted/working/input-required/completed/canceled/failed/rejected/auth-required/unknown |
| SSE 未命名事件 | ✅ 正确 | v0.2.2/v0.3.0 spec §3.3.1：SSE data 字段含完整 JSON-RPC 响应，无 event 命名规定 |
| 错误码 -32700~-32603、-32001~-32006、-32007 | ✅ 代码数值正确 | v0.2.2 确认 -32001~-32006；v0.3.0 确认 -32007（`AuthenticatedExtendedCardNotConfiguredError`） |

**结论：v1.1 深审报告（D-C1~D-L5）指出的 5 项 CRITICAL 协议骨架错误（方法名/路径/Part kind）已在 v2.0.0 全部修复且经实拉验证属实。** 本文档的协议骨架（方法名、Part kind、事件类型、状态枚举、SSE 格式）与 spec v0.2.2/v0.2.5/v0.3.0 严格一致，未发现新的 CRITICAL 级别骨架错误。

### 1.2 严重度分布

| 严重度 | 数量 | 编号 |
|--------|------|------|
| CRITICAL | 0 | — |
| HIGH | 3 | H-1, H-2, H-3 |
| MEDIUM | 7 | M-1 ~ M-7 |
| LOW | 7 | L-1 ~ L-7 |
| **合计** | **17** | |

### 1.3 最终结论

**有条件通过——文档主体（协议骨架）可进入实现阶段，但须先修复 3 项 HIGH 问题（其中 H-2 是必填字段 omitempty 问题，会直接导致生成的字节流违反 spec），并更正 7 项 MEDIUM 的文档数字/内部一致性错误。**

---

## 2. HIGH 问题（3 项）

### H-1：Agent Card 路径的 v1.0 事实陈述错误（§1.3、§10.6 #6、V13）

- **严重度**：HIGH
- **位置**：§1.3 L51-53（"v0.3.0 临时改为 `agent-card.json`（v1.0 已撤回恢复为 `agent.json`）"、"本设计取主流稳定值 `agent.json`"）、§10.6 #6 L1973、V13 L1818
- **描述**：文档声称 "v0.3.0 release notes #841 临时改为 agent-card.json，但 v1.0 已恢复为 agent.json"，并称 agent.json 是 "主流稳定值"。
- **依据**（实拉 v1.0.0/v1.0.1 `docs/specification.md`）：
  - v1.0.0 §8.2：`Accessing https://{server_domain}/.well-known/agent-card.json`
  - v1.0.0 §14.3（IANA 注册）：`URI suffix: agent-card.json`；"The `.well-known/agent-card.json` URI provides a standardized location for discovering an A2A agent's capabilities..."
  - v1.0.1 §8.2 同 v1.0.0：`/.well-known/agent-card.json`
  - 各版本路径汇总：v0.2.2/v0.2.5/v0.2.6 用 `agent.json`；**v0.3.0/v1.0.0/v1.0.1 全部用 `agent-card.json`**，v1.0 从未"恢复为 agent.json"
- **影响**：设计选择 agent.json 对 v0.2.x 目标正确（且 V13 允许 AgentCardPath 覆盖），但 "v1.0 已撤回" 是错误事实，实现者会误判该路径与最新协议版本兼容。真实 A2A v0.3.0/v1.0 Agent 的发现路径是 agent-card.json，默认配置下无法发现此类 Agent。
- **修复建议**：更正 §1.3 与 §10.6 #6 的陈述为 "v0.2.x 用 agent.json；v0.3.0 起（含 v1.0）用 agent-card.json 并已完成 IANA 注册，agent.json 仅存在于 v0.2.x"；默认值保持 agent.json（v0.2.x 目标）并强调 AgentCardPath 可覆盖；V13 的警告提示同步更新。

### H-2：TaskStatusUpdateEvent.final 是 spec 必填字段，设计标为可选且结构体 omitempty（§2.7、§5.5）

- **严重度**：HIGH
- **位置**：§2.7 表 L382（"final | boolean | 否 | false"）、§5.5 `A2ATaskStatusUpdateEvent` L959（`Final bool \`json:"final,omitempty"\``）、V9 L1804
- **描述**：spec 的 `TaskStatusUpdateEvent` required 数组为 `['contextId', 'final', 'kind', 'status', 'taskId']`——**final 是必填字段**（v0.2.2 与 v0.3.0 完全一致）。设计文档将其标为"否（可选），默认 false"，且 Go 结构体用 `json:"final,omitempty"`——当 Final=false 时序列化会**省略该字段**，生成的 SSE 事件 JSON 将违反 spec 必填性。
- **依据**：
  - v0.2.2 `a2a.json` `TaskStatusUpdateEvent.required`: `["contextId","final","kind","status","taskId"]`
  - v0.3.0 `a2a.json` 同：`["contextId","final","kind","status","taskId"]`
  - 文档自身所有 status-update 示例（S3 L1159、S6 L1233、S10 L1310/L1313）都显式写出 `"final":false` / `"final":true`——恰好证明 final 应当总是出现
- **影响**：实现者按 §5.5 结构体序列化，Final=false 的中间状态事件会缺 final 字段，无法通过真实 A2A 客户端/服务端的 schema 校验（final required）。T133（"status-update final=false | 正向"）正是该路径，测试会生成不合法字节。
- **修复建议**：§2.7 表改"final | boolean | 是（spec required）"；§5.5 结构体改为 `Final bool \`json:"final"\``（去 omitempty）；V9 增加"所有 status-update 事件必须含 final 字段"。

### H-3：SSE data 行只能是 JSONRPCSuccessResponse 的表述与 spec 及文档自身 §9.5 矛盾（§2.3）

- **严重度**：HIGH
- **位置**：§2.3 L133（"每个 `data:` 字段含一个完整的 `JSONRPCSuccessResponse`"）
- **描述**：spec 规定 SSE data 字段含完整 JSON-RPC Response 对象（`SendStreamingMessageResponse` = `JSONRPCErrorResponse | SendStreamingMessageSuccessResponse` 的 anyOf 联合）。文档 §2.3 把 data 行限定为成功响应，但 §9.5 L1889-1893 又说"SSE 流中的错误通过 JSONRPCErrorResponse 投递"——同一文档自相矛盾，且 §2.3 与 spec 不符。
- **依据**：v0.2.2 spec §3.3.1（L75）："Each SSE data field contains a complete JSON-RPC 2.0 Response object (specifically, a SendStreamingMessageResponse)"；v0.2.2 `a2a.json` `SendStreamingMessageResponse` = anyOf[JSONRPCErrorResponse, SendStreamingMessageSuccessResponse]
- **影响**：实现者若按 §2.3 只允许成功响应生成 SSE data，则无法生成 §9.5 描述的错误事件场景；T187-T203 中涉及流式错误的事件缺失生成路径。
- **修复建议**：§2.3 改为"每个 data: 字段含一个完整的 JSON-RPC Response（成功 `JSONRPCSuccessResponse` 或错误 `JSONRPCErrorResponse`，result 为 Task/Message/TaskStatusUpdateEvent/TaskArtifactUpdateEvent 之一）"。

---

## 3. MEDIUM 问题（7 项）

### M-1：测试数量声明不一致（§7 L1412 声称 203 条，实际 242 条）

- **位置**：§7 L1412（"共 **203 条**"）vs §11 修订记录 L2056（"增至 **242 条**"）
- **描述**：全文用例编号 T001-T242 连续无缺号，实际 242 条；§7 声称 203 条。两处数字矛盾。
- **依据**：统计 §7.1-§7.21 全部用例行 = 242 条，编号 001-242 无缺号无重复。
- **修复建议**：§7 改为 "共 242 条"。

### M-2：负向用例占比声称 ≥30%，实际 23.1%

- **位置**：§7 L1412（"负向用例占比 ≥ 30%"）
- **描述**：按用例类型列统计：正向 147 / 负向 56 / 边界 29 / 集成 8 / 并发 2 = 242。负向占比 56/242 = **23.1%**，不满足文档自声明的 ≥30%。
- **影响**：与 CLAUDE.md 测试策略规则 2（覆盖失败路径）的宣称力度不符；若实现阶段以此验收，负向覆盖不足。
- **修复建议**：补充负向用例至 ≥30%（至少增加 17 条），或更正声明为 ≥23%。

### M-3：Validate 规则缺口——T002/T138 声称的 Validate 行为在 V1-V15 中无对应规则

- **位置**：§7.1 T002（"同时设 result 与 error，Validate 拒绝"）、§7.12 T138（"status-update 缺 status，Validate 拒绝"）、§8 V1-V15
- **描述**：两处测试用例声称 Validate 会拒绝非法输入，但 §8 的 V1-V15 规则集中没有对应规则：
  - T002：V1-V15 中无"Result 与 Error 互斥"规则（§2.2 描述了互斥语义，但 Validate 规则集未编码）
  - T138：V9 只要求"artifact-update 事件必须含 Artifact.Parts（≥1）"和"末事件 Final=true"，没有"status-update 必须含 Status"规则
- **影响**：实现者按 V1-V15 实现 Validate，T002/T138 测试将失败（或测试被跳过），违反 CLAUDE.md 测试策略规则 3（每个分支都需要测试）与规则 5（断言可观察结果）。
- **修复建议**：新增 V16（Result/Error 互斥）、V17（status-update 事件必须含 Status）或并入现有规则。

### M-4：PushNotificationConfig.id 的"服务端分配（v0.3.0+）"标注与 v0.3.0 语义相反

- **位置**：§2.9 L434（"id | string | 否 | 服务端分配的配置标识（v0.3.0+）"）、§3.2.6 S7 L1276（"响应 result.pushNotificationConfig.id 由服务端分配"）、T084 L1536
- **描述**：v0.3.0 中 `PushNotificationConfig.id` 描述为 **"A unique ID for the push notification configuration, set by the client to support multiple notification callbacks"**（客户端设置，用于多回调），v0.2.2 才是 "created by server"。文档跟随 v0.2.2 语义（服务端分配）却在括号中标注 "(v0.3.0+)"，版本归属错误。
- **依据**：v0.3.0 `a2a.json` `PushNotificationConfig.properties.id.description`；v0.2.2 同文件（"created by server"）
- **影响**：S7/T084 断言"id 由服务端分配"在 v0.3.0 目标下不成立；且设计未说明客户端可在请求中设置 id（v0.3.0 语义）。
- **修复建议**：改为"id | string | 否 | v0.2.2 由服务端创建；v0.3.0 起由客户端设置以支持多回调"。S7/T084 断言相应标注版本。

### M-5：AgentCard 字段覆盖率声称 100% 不实——遗漏 v0.2.5+ 的 additionalInterfaces/preferredTransport、v0.3.0 的 signatures、mutualTLS 安全方案

- **位置**：§2.4 AgentCard 表（L194-212）、§5.2 A2AAgentCard、§2.4 SecurityScheme 表（L235-242）、§11 L2043（"覆盖率从 65% 提升至 100%"）
- **描述**：
  - v0.2.5/v0.3.0 AgentCard 含 `additionalInterfaces`（AgentInterface[]：{url, transport} 必填）与 `preferredTransport`，设计文档两者均无
  - v0.3.0 AgentCard 含 `signatures`（AgentCardSignature[]，JWS 签名），设计文档无
  - v0.3.0 `SecurityScheme` anyOf 有 **5** 种（新增 `MutualTLSSecurityScheme`，type=`mutualTLS`），设计文档 §2.4 只列 4 种
- **依据**：v0.2.5/v0.3.0 `a2a.json` AgentCard.properties / SecurityScheme.anyOf
- **影响**：若实现者声称"覆盖 spec v0.2.2+ 全部字段"，生成的 Agent Card 对 v0.2.5+ 缺接口声明字段；配置 mutualTLS 方案时文档无据可依（A2ASecurityScheme 是 map[string]any 不会拒绝，但文档未声明）。
- **修复建议**：§2.4 补 additionalInterfaces/preferredTransport（v0.2.5+）/signatures（v0.3.0）；SecurityScheme 表补 mutualTLS 行并标注版本；"100%" 声明改为"覆盖本设计目标版本（v0.2.2 核心 + v0.2.5 protocolVersion）的全部必填字段"。

### M-6：HexDump 场景 Content-Length 与展示 JSON body 不符（S1/S2）

- **位置**：§6.2 S1 L1067（`Content-Length: 612`）、S2 请求 L1094（`Content-Length: 187`）、S2 响应 L1116（`Content-Length: 215`）
- **描述**：按文档展示的 JSON 字节逐字节计算：
  - S1 Agent Card body（第 1069-1081 行展示的 JSON）= **546 字节**（紧凑序列化 501，2 空格缩进 703），声称 612——三种格式均不匹配
  - S2 请求 body（含 "kind":"message"、configuration）= **258 字节**，声称 187
  - S2 响应 body（含 artifacts/kind/timestamp）= **257 字节**，声称 215
  - 尝试去掉 kind/configuration/artifacts 等字段的变体（176/193/161 等）均不匹配声称值
- **影响**：HexDump 场景是字节级参考，Content-Length 是 HTTP 层硬数值；实现者按文档生成包时数值自相矛盾，字节级断言（tshark 校验）必然失败。§11 声称"所有 JSON 字段完整"不成立。
- **修复建议**：S1/S2/S3 等所有含 Content-Length 的场景，按展示 JSON 的实际字节数重算 Content-Length（或明确标注 JSON 为示意、以生成器输出为准）。

### M-7：SSE 响应缺 Content-Length 且缺 Transfer-Encoding: chunked，HTTP/1.1 消息边界无法确定（S3/S6/S10）

- **位置**：§6.2 S3 L1152-1156（SSE 响应头：Content-Type/Cache-Control/Connection: keep-alive，无 Content-Length 无 Transfer-Encoding）、§10.6 #4 L1971（"planner 默认省略，但接受用户显式设置"）、§1.5 L70（"可被任何真实 A2A 服务端/客户端互操作"）
- **描述**：HTTP/1.1 中响应体长度必须由 Content-Length、Transfer-Encoding: chunked 或连接关闭三者之一确定。S3/S6/S10 的 SSE 响应三者皆无（Connection: keep-alive 又排除了连接关闭），真实 HTTP 客户端无法确定 SSE 流边界。
- **影响**：与 §1.5 互操作目标矛盾；实现者默认生成该头组合，被真实客户端解析时挂起/超时。
- **修复建议**：明确 SSE 响应默认带 `Transfer-Encoding: chunked`（或 `Connection: close`），或明确声明该场景为"模拟流量、不保证 HTTP 层语义完整"。

---

## 4. LOW 问题（7 项）

### L-1：-32007 错误名错误（§3.4 L653）

- spec v0.3.0 名称为 **`AuthenticatedExtendedCardNotConfiguredError`**，设计文档写 `ExtendedAgentCardNotConfiguredError`。
- 依据：v0.3.0 `a2a.json` definitions 键名。
- 建议：更正名称（虽然标 v2 路线图，错误名会误导后续实现）。

### L-2：S4-S7 HexDump 请求缺 Accept 头（§6.2）

- V14 要求非流式方法 `Accept: application/json`，S2/S3 展示了 Accept 头，但 S4-S7 的请求行/头列表省略了 Accept。展示不一致。
- 建议：S4-S7 补 `Accept: application/json`（或统一省略并在 V14 注明示例省略）。

### L-3：T199/T200 与 T194/T195 完全重复（§7.17）

- T194（pushNotifications=false 调 set → -32003）与 T200 同验证点；T195（streaming=false 调 message/stream → -32004）与 T199 同验证点。7.17 声称 18 条实际 17 条，疑似重复导致计数虚高。
- 建议：删除 T199/T200 中重复者，或改为不同输入（如 capabilities 声明与实际响应不一致的跨层断言），并修正计数。

### L-4：T004 描述含糊（§7.1）

- "请求 id 缺失时，响应 id=null"——按 JSON-RPC 2.0 与 A2A spec §6.11.2，请求缺 id 属 Invalid Request（-32600），错误响应 id 为 null。T004 未说明响应为错误响应，易被实现为"成功响应 id=null"。
- 建议：改为"请求缺 id → 响应 -32600 且 id=null"。

### L-5：A2ATask.Streaming 与 Method 无一致性校验（§5.3、§8）

- Method=message/stream 但 Streaming=false（或反之）的冲突配置无 Validate 规则。V2/V3 只校验 Method 枚举与 capabilities。
- 建议：V8 增加"Streaming=true 时 Method 必须为 message/stream"（或删除冗余字段，以 Method 为准）。

### L-6：§6.1 "同步路径：单包 JSON-RPC 响应" 与 §2.10 允许 1MB text 矛盾

- 同步路径 Task 响应可含 1MB 级别 artifact（T174 合法），不可能"单包"承载（MSS 1460）。"1 或多个 PSH-ACK 下行包"已允许多包，但"单包"措辞误导。
- 建议：改为"同步路径：JSON-RPC 响应（超过 MSS 时按 MSS 分段）"。

### L-7：§4.2 禁止转换列举不完整

- 只明确列出 input-required → completed 拒绝；auth-required → completed / submitted → completed 等同理未定义的转换未列举（"如"字暗示非穷举，但实现者可能只拒绝列举项）。
- 建议：V10 明确"仅 §4.2 转换表列举的转换合法，其余一律拒绝"。

---

## 5. 与 CLAUDE.md §Testing Policy 的符合性评估

| 规则 | 评估 |
|------|------|
| 规则 1（spec-driven） | 基本符合。用例按 spec §5-§9 章节组织，字段覆盖较全；但"100% 字段覆盖"声明不实（M-5） |
| 规则 2（失败路径） | 部分符合。负向 56 条覆盖全部 13 个错误码 + 非法输入；但占比声称 ≥30% 实际 23.1%（M-2），7.17 错误码维度有重复用例（L-3） |
| 规则 3（每路径一测试） | 有缺口。T002/T138 声称的 Validate 行为无规则支撑（M-3）；T004 描述含糊（L-4）；Streaming/Method 冲突无覆盖（L-5） |
| 规则 4（集成测试） | 符合。T204-T211 有 8 条端到端用例（发现→发送→流式→webhook→resubscribe→认证→tshark） |
| 规则 5（断言可观察结果） | 基本符合。多数用例断言响应内容/状态/字节；但 S1/S2 的 Content-Length 断言依据本身错误（M-6） |
| 规则 6（并发正确性） | 符合。T167（100 流聚合包数）、T168（100 流聚合速率 ≤ bps）测量聚合可观察行为 |
| 规则 7（failing-test-first） | 修订记录 D-* 修复均配有验证用例（T228-T242），符合精神 |
| 规则 8（测试质量对抗审查） | 本文档即为该维度的产物；发现 T194/T199 重复、T004 含糊等质量问题（L-3/L-4） |

---

## 6. 与 v1.1 深审报告（D-* 24 项）的复核

逐项实拉验证 v2.0.0 对 24 项问题的修复：

| 编号 | 修复验证结果 |
|------|-------------|
| D-C1（tasks/send → message/send） | ✅ 已修复，全版本验证 |
| D-C2（tasks/sendSubscribe/tasks/subscribe → message/stream） | ✅ 已修复，全版本验证 |
| D-C3（pushNotification → pushNotificationConfig） | ✅ 已修复，v0.2.2/v0.2.5/v0.3.0 全对 |
| D-C4（agents.json → agent.json） | ✅ 已修复（v0.2.x 正确），但 v1.0 理由陈述错误（新问题 H-1） |
| D-C5（data-stream/file-stream 幻觉） | ✅ 已修复，spec 任何版本无此 kind |
| D-H1（userId → id） | ✅ 已修复，但 id 语义版本标注错误（新问题 M-4） |
| D-H2（authentication → securitySchemes/security） | ✅ 已修复，OpenAPI 风格正确 |
| D-H3（TaskStatusUpdateEvent 塞 artifact） | ✅ 已修复，独立事件类型正确；但 final 必填性遗漏（新问题 H-2） |
| D-H4（event: update → 未命名事件） | ✅ 已修复，与 spec 一致 |
| D-H5（遗漏 rejected/auth-required） | ✅ 已修复，9 枚举全对 |
| D-H6（-32004 窄化 → 通用） | ✅ 已修复；新增 -32006/-32007 数值正确，但 -32007 名称错误（新问题 L-1） |
| D-M1~D-M8、D-L1~D-L5 | ✅ 全部修复（V4 互斥、命名统一、input-required→completed 拒绝、schemes 大小写、protocolVersion 默认、类型拆分、params.id 删除、TaskID 注释、omitempty、skill 必填、contextId、Content-Length 措辞、编号重排） |

---

## 7. 详细证据附录（关键 Spec 引文）

### 7.1 方法名（v0.3.0 `a2a.json`）

```
SendMessageRequest.method.const = "message/send"
SendStreamingMessageRequest.method.const = "message/stream"
GetTaskRequest.method.const = "tasks/get"
CancelTaskRequest.method.const = "tasks/cancel"
TaskResubscriptionRequest.method.const = "tasks/resubscribe"
SetTaskPushNotificationConfigRequest.method.const = "tasks/pushNotificationConfig/set"
GetTaskPushNotificationConfigRequest.method.const = "tasks/pushNotificationConfig/get"
DeleteTaskPushNotificationConfigRequest.method.const = "tasks/pushNotificationConfig/delete"
ListTaskPushNotificationConfigRequest.method.const = "tasks/pushNotificationConfig/list"
GetAuthenticatedExtendedCardRequest.method.const = "agent/getAuthenticatedExtendedCard"
```

### 7.2 TaskState（v0.3.0 `a2a.json`）

```
enum = ["submitted","working","input-required","completed","canceled","failed","rejected","auth-required","unknown"]
```

### 7.3 TaskStatusUpdateEvent.required（v0.2.2 与 v0.3.0 相同）

```
required = ["contextId","final","kind","status","taskId"]
```

### 7.4 TaskArtifactUpdateEvent.required（v0.2.2 与 v0.3.0 相同）

```
required = ["artifact","contextId","kind","taskId"]
```

### 7.5 Part（v0.2.2/v0.2.5/v0.3.0 相同）

```
Part.anyOf = [TextPart, FilePart, DataPart]
TextPart: kind=text, text 必填
FilePart: kind=file, file 必填（FileWithBytes: bytes 必填 | FileWithUri: uri 必填）
DataPart: kind=data, data 必填
```

### 7.6 Agent Card 路径（各版本 `docs/specification.md`）

| 版本 | 路径 |
|------|------|
| v0.2.2 §5.3 | `https://{server_domain}/.well-known/agent.json` |
| v0.2.5 §5.3 | 同上 |
| v0.2.6 §5.3 | 同上 |
| v0.3.0 §5.3 | `https://{server_domain}/.well-known/agent-card.json` |
| v1.0.0 §8.2 / §14.3（IANA） | `https://{server_domain}/.well-known/agent-card.json`（URI suffix: agent-card.json） |
| v1.0.1 §8.2 | `/.well-known/agent-card.json` |

### 7.7 AgentCard required（v0.2.5/v0.3.0 相同）

```
required = ["capabilities","defaultInputModes","defaultOutputModes","description","name","protocolVersion","skills","url","version"]
```
（v0.2.2 无 protocolVersion；设计文档默认 "0.3.0" 合理）

### 7.8 PushNotificationConfig.id 语义

- v0.2.2：`Push Notification ID - created by server to support multiple callbacks`
- v0.3.0：`A unique ID for the push notification configuration, set by the client to support multiple notification callbacks`

### 7.9 SecurityScheme anyOf（v0.3.0）

```
[APIKeySecurityScheme, HTTPAuthSecurityScheme, OAuth2SecurityScheme, OpenIdConnectSecurityScheme, MutualTLSSecurityScheme]
```

### 7.10 SSE（v0.2.2 spec §3.3.1）

```
Each SSE data field contains a complete JSON-RPC 2.0 Response object
(specifically, a SendStreamingMessageResponse).
```

---

## 8. 最终结论

**本文档是否可以进入实现阶段：有条件通过（是，但需先修复 3 项 HIGH）。**

- **CRITICAL：0**。v1.1 深审的 5 项 CRITICAL（方法名/Agent Card 路径/Part kind 幻觉）已全部修复并经三个历史 tag + v1.0 实拉验证。
- **HIGH：3**。其中 **H-2（TaskStatusUpdateEvent.final 必填性 + omitempty）会直接导致生成的 SSE 字节违反 spec**，必须在实现前修复；H-1（v1.0 路径事实错误）影响兼容性判断；H-3（SSE data 成功/错误响应表述矛盾）影响流式错误场景生成。
- **MEDIUM：7 / LOW：7**。均为文档数字准确性、内部一致性、Validate 规则缺口与字段覆盖问题，修复成本低，建议与实现同步修订。

修复优先级建议：H-2 → H-3 → H-1 → M-3（Validate 缺口，直接影响测试用例实现）→ M-4/M-5/M-6/M-7 → 其余。
