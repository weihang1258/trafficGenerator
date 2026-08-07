# A2A 设计文档独立复审报告（v2.0.1 复审，r2-v2）

**审计对象**：`docs/protocol-designs/17-a2a-design.md` v2.0.1（2179 行，声明 246 条用例）
**审计日期**：2026-08-05
**审计人**：独立协议审计员（与 r1-v2 复审报告 `audit/17-a2a-audit-r1-v2.md` 无交叉）
**审计依据**（全部实拉验证）：
1. A2A spec v0.2.2 `specification/json/a2a.json`（79651 B）+ `docs/specification.md`（86950 B）
2. A2A spec v0.2.5 `specification/json/a2a.json`（91502 B）+ `docs/specification.md`（91975 B）
3. A2A spec v0.3.0 `specification/json/a2a.json`（103940 B）+ `docs/specification.md`（85298 B）
4. A2A spec v1.0.1 `docs/specification.md`（155498 B）
5. JSON-RPC 2.0（https://www.jsonrpc.org/specification）
6. `CLAUDE.md` 测试策略 8 条强制规则
7. 上轮复审报告 `audit/17-a2a-audit-r1-v2.md`（17 项问题：0 CRITICAL / 3 HIGH / 7 MEDIUM / 7 LOW）

> 注：任务要求对照 "Google A2A spec"，可用 WebFetch github.com/a2aproject/A2A 核实。本审计实拉 raw.githubusercontent.com/a2aproject/A2A 的 v0.2.2/v0.2.5/v0.3.0/v1.0.1 四个历史 tag 的 schema 与规范文档逐版本核验（仓库已从 google/A2A 迁移至 a2aproject/A2A）。

**审计方法**：
- 通读 v2.0.1 全文 2179 行
- 对 r1-v2 报告的 17 项问题逐项核实修复是否落地（H-1/H-2/H-3 逐条对照规范原文）
- 对全部 246 条测试用例编号连续性、各节计数、类型分类做程序化统计
- 对 S1/S2 的 Content-Length 按紧凑 JSON 序列化逐字节计算
- 逐字段核对方法名 / Agent Card 路径 / Part kind / 事件类型 / 9 个状态枚举 / SSE 格式 / 错误码 / PushNotificationConfig 语义
- 检查 Validate 规则 V1-V16 与测试用例声称行为的对应关系
- 默认"有 bug"，除非证据确凿

---

## 1. 审计概览

### 1.1 重点检查项（任务指定 11 项）核对结果

| 重点检查项 | 结果 | 依据 |
|-----------|------|------|
| H-2：`TaskStatusUpdateEvent.final` 必填 + Go 结构体去 omitempty | ✅ 已正确修复 | §2.7 表（L391）"final \| boolean \| 是（spec required）"并注明 false 也必须显式输出；§5.5（L979）`Final bool \`json:"final"\``（去 omitempty）；V9（L1841）"所有 Kind=status-update 事件必须含 Final 字段"。实拉 v0.2.2/v0.3.0 schema `TaskStatusUpdateEvent.required = [contextId, final, kind, status, taskId]` 确认 |
| H-1：Agent Card 路径版本事实 | ✅ 已正确修复 | §1.3（L51-54）、§10.6 #6（L2011）、V13（L1853）统一为"v0.2.x 用 agent.json；v0.3.0 起（含 v1.0.0/v1.0.1）用 agent-card.json 并已完成 IANA 注册，v1.0 从未恢复 agent.json"。实拉 v1.0.1 §8.2 用 `/.well-known/agent-card.json`、§14.3 IANA 注册（URI suffix: agent-card.json）确认 |
| H-3：SSE data 为成功\|错误联合 | ✅ 已正确修复 | §2.3（L134）"`SendStreamingMessageResponse`，是成功与错误的 anyOf 联合：`JSONRPCErrorResponse \| SendStreamingMessageSuccessResponse`"；§2.3 SSE 规则表（L156）"错误 data"行；§3.2.2（L547）同步。实拉 v0.2.2 schema `SendStreamingMessageResponse = anyOf[JSONRPCErrorResponse, SendStreamingMessageSuccessResponse]` 确认 |
| M-1/M-2：测试数量 246、负向占比 23.2% | ⚠️ 部分修复 | 总数 246 ✅、编号 T001-T242 连续无缺号 ✅、负向 57/246≈23.2% ✅；但 §7（L1441）类型细分"边界 28"与实拉统计的 **30** 不符（149+57+30+8+2=246，见 M-A） |
| M-3：V16（Result/Error 互斥） | ⚠️ 部分修复 | V16（L1863-1864）已新增 ✅；但修订记录声称"V9 新增 status-update 事件必须含 Status（支撑 T138）"**未落地**——实际 V9 只强化了 Final 字段，无任何规则要求 status-update 含 status，T138 仍无规则支撑（见 M-B） |
| M-4：PushNotificationConfig.id 语义 | ✅ 已正确修复 | §2.9（L443）"v0.2.2 由服务端创建；v0.3.0 起由客户端设置（多回调）"；S7 断言（L1302）、T084 同步。实拉 v0.2.2 schema id 描述 "created by server to support multiple callbacks"、v0.3.0 "set by the client to support multiple notification callbacks" 确认 |
| M-5：additionalInterfaces/preferredTransport/signatures/mutualTLS | ⚠️ 部分修复 | 字段全部补齐 ✅（§2.4 L214-216、§5.2 L804-806）；但 mutualTLS 必填字段标注错误（实际 required=['type']，文档称"无必填字段"，见 L-A）；preferredTransport/additionalInterfaces 示例值与 schema 不符（见 L-B） |
| M-6：Content-Length 与 JSON 字节（501/258/257） | ✅ 已正确修复 | 逐字节计算：S1 Agent Card 紧凑序列化 **501** B、S2 请求 **258** B、S2 响应 **257** B，全部吻合 |
| M-7：SSE 补 Transfer-Encoding: chunked | ✅ 已正确修复 | S3（L1175）、S6（L1255）响应头均含 `Transfer-Encoding: chunked`；§10.6 #4（L2009）改为"SSE 响应默认带 chunked" |
| 方法名/Part kind/状态枚举/错误码骨架 | ✅ 全部正确 | 7 个 JSON-RPC 方法名 v0.2.2/v0.2.5/v0.3.0 schema const 全对；Part.anyOf = TextPart/FilePart/DataPart（3 种）；TaskState.enum 9 值全对；错误码 -32700~-32603、-32001~-32006（v0.2.2/v0.2.5）、-32007（v0.3.0 `AuthenticatedExtendedCardNotConfiguredError`）全对；v0.3.0 新增 list/delete/getAuthenticatedExtendedCard 标注正确 |
| 测试用例符合 CLAUDE.md §Testing Policy | ⚠️ 基本符合 | 负向 57 条覆盖全部 13 个错误码 + 非法输入；集成 8 条、并发 2 条；但 §7.19 存在与 §7.2/§7.5/§7.13 重复的验证点（见 L-C），T138 声称的 Validate 行为无规则支撑（见 M-B），T160/V15 基于对规范的过度解读（见 M-E） |

### 1.2 严重度分布

| 严重度 | 数量 | 编号 |
|--------|------|------|
| CRITICAL | 0 | — |
| HIGH | 0 | — |
| MEDIUM | 5 | M-A ~ M-E |
| LOW | 3 | L-A ~ L-C |
| **合计** | **8** | |

### 1.3 最终结论

**有条件通过——协议骨架（方法名/路径/Part kind/事件类型/状态枚举/错误码）与 spec v0.2.2/v0.2.5/v0.3.0 严格一致，r1-v2 的 3 项 HIGH 全部正确修复且经实拉验证。但 5 项 MEDIUM 需在实现前修复**：其中 M-B（T138 无 Validate 规则）、M-C（V8 规则误伤 tasks/resubscribe）直接影响实现者的 Validate 逻辑，M-D（遗漏 v0.2.x 的 agent/authenticatedExtendedCard 端点）影响协议骨架完整性，M-E（将 SHOULD 提升为 MUST）导致拒绝规范允许的配置，M-A 为文档数字错误（r1-v2 M-2 修复不完整）。

---

## 2. r1-v2 修复验证（17 项逐项复核）

### 2.1 已确认正确修复（13 项）

| 编号 | 验证结果 |
|------|---------|
| H-1（Agent Card 路径 v1.0 事实） | ✅ 全部位置（§1.3 L51-54、§10.6 #6 L2011、V13 L1853）表述一致正确；实拉 v1.0.1 §8.2/§14.3 验证 |
| H-2（final 必填 + omitempty） | ✅ §2.7 表、§5.5 结构体（去 omitempty）、V9 三处一致；实拉 v0.2.2/v0.3.0 schema required 验证 |
| H-3（SSE data 成功\|错误联合） | ✅ §2.3/§3.2.2/§2.3 规则表一致；实拉 v0.2.2 `SendStreamingMessageResponse` anyOf 验证 |
| M-1（测试数量 246） | ✅ 全表 246 行、编号 T001-T242 + T212a-d 无缺号无重复；各节标题计数与实际行数全对 |
| M-4（PushNotificationConfig.id 语义） | ✅ §2.9/S7/T084/§10.6 #15 一致；实拉 v0.2.2/v0.3.0 描述验证 |
| M-6（Content-Length 501/258/257） | ✅ 逐字节计算全部吻合 |
| M-7（SSE chunked） | ✅ S3/S6 响应头补 `Transfer-Encoding: chunked`；§10.6 #4 更新 |
| L-1（-32007 错误名） | ✅ L662 改为 `AuthenticatedExtendedCardNotConfiguredError`；实拉 v0.3.0 schema 验证 |
| L-2（S4-S7 Accept 头） | ✅ S4/S5/S7/S8/S11/S13 请求全部补 `Accept: application/json` |
| L-3（T199/T200 与 T194/T195 重复） | ✅ 改为 capabilities 声明与实际配置冲突的跨层一致性断言（"区别于 T195/T194"），语义已区分 |
| L-4（T004 描述） | ✅ 改为"请求缺 id 属 Invalid Request（JSON-RPC 2.0 §6.11.2），响应 -32600 且 id=null" |
| L-6（§6.1 "单包"措辞） | ✅ 改为"JSON-RPC 响应（超过 MSS 时按 MSS 分段）" |
| L-7（V10 禁止转换列举不完整） | ✅ V10 明确"仅 §4.2 转换表列举的转换合法，其余一律拒绝" |

### 2.2 修复不完整（4 项）

| 编号 | 问题 | 验证结果 |
|------|------|---------|
| M-2 | 负向占比 23.2% 已如实标注，但边界计数错误 | ✅ 占比修复；❌ §7（L1441）"正向 149 / 负向 57 / 边界 28 / 集成 8 / 并发 2 = 246"中边界应为 **30**（149+57+30+8+2=246），文档写 28 导致求和自相矛盾（244≠246）——见 M-A |
| M-3 | V16 已新增（支撑 T002） | ✅ V16；❌ 修订记录（L2049）声称"V9 新增 status-update 事件必须含 Status（支撑 T138）"未落地——V9（L1835-1841）实际只加了 Final 必含，T138 仍无规则支撑——见 M-B |
| M-5 | 字段已补齐（additionalInterfaces/preferredTransport/signatures/mutualTLS） | ✅ 字段补齐；❌ mutualTLS 必填字段标注错误（见 L-A）、preferredTransport 示例值错误（见 L-B） |
| L-5 | V8 新增 Streaming/Method 一致性 | ✅ 规则已加；❌ 表述"Streaming=true 时 Method 必须为 message/stream"遗漏 `tasks/resubscribe`（同为流式方法、需 streaming=true、产生 SSE 流）——见 M-C |

---

## 3. MEDIUM 问题（5 项）

### M-A：§7 类型细分"边界 28"错误，实际 30（r1-v2 M-2 修复不完整）

- **位置**：§7（L1441）
- **描述**：§7 声明"按类型统计：正向 149 / 负向 57 / 边界 28 / 集成 8 / 并发 2 = 246"。程序化统计全部 246 行：正向 149 / 负向 57 / **边界 30** / 集成 8 / 并发 2。文档的"边界 28"使求和 149+57+28+8+2=**244≠246**，与"共 246 条"自相矛盾。
- **依据**：逐行提取 246 条用例类型标注统计（边界用例为 T007/T018/T019/T022/T024/T062/T063/T104/T112/T115/T142/T144/T145/T159/T173-T186/T212c/T212d 共 30 条）。r1-v2 M-2 修复正是为纠正此类数字错误，v2.0.1 声称"如实标注"却仍留一处错误。
- **影响**：实现验收时若按文档数字核对测试产出会困惑；与 r1-v2 审计主题（数字准确性）直接相关的未完成修复。
- **修复建议**：§7 L1441 改为"边界 30"。

### M-B：T138 声称的 Validate 行为仍无规则支撑（r1-v2 M-3 修复未落地）

- **位置**：§7.12 T138（L1639）、§8 V9（L1835-1841）、§11 v2.0.1 修订记录 M-3（L2049）
- **描述**：T138 为"status-update 缺 status | 负向 | 事件无 status 字段，Validate 拒绝"。修订记录 M-3 声称修复为"V9 新增'status-update 事件必须含 Status'（支撑 T138）"。但实际 V9 内容为："所有 `Kind=status-update` 事件必须含 `Final` 字段（spec required；`Final=false` 的中间状态事件也必须显式输出 `"final":false`，不得省略）"——这条规则关于 **Final**，不关于 **Status**。全文档检索无任何规则要求 status-update 事件含 status 字段。
- **依据**：V9 原文逐句核对（L1835-1841）；全文 grep "含 Status"/"缺 status" 无 V 规则命中。spec v0.2.2 schema `TaskStatusUpdateEvent.required = [contextId, final, kind, status, taskId]`——status 是必填字段，T138 的负向断言（缺 status 应被拒绝）本身是正确的测试意图，但 Validate 规则集没有对应规则。
- **影响**：实现者按 V1-V16 实现 Validate 时，T138 测试将失败（或需临时豁免）；违反 CLAUDE.md 测试策略规则 3（每个分支都需要测试）与规则 5（断言可观察结果）。这正是 r1-v2 M-3 报告的同一问题在修复后的残留。
- **修复建议**：V9 增加"所有 `Kind=status-update` 事件必须含 `Status`（spec required）"规则；并修正修订记录 M-3 的表述使其与实际内容一致。

### M-C：V8 Streaming/Method 一致性规则遗漏 tasks/resubscribe（r1-v2 L-5 修复不完整）

- **位置**：§8 V8（L1833）、§5.3 A2ATask.Streaming 注释（L874）
- **描述**：V8 规则"`Streaming=true` 时 `Method` 必须为 `message/stream`；`Streaming=false` 时 `Method` 必须为 `message/send`"。但 `tasks/resubscribe` 同样是流式方法（§3.1 方法表 L483：需 capabilities.streaming=true、响应为 SSE 流；§6.2 S6 展示其 SSE 响应；§1.6 不变式 #8 L84 明确"message/stream 与 tasks/resubscribe 走 SSE 路径"）。用户为 tasks/resubscribe 任务设置 `Streaming=true` + `SSEEvents`（S6 展示的响应格式）是完全合理的配置，却被 V8 规则拒绝。
- **依据**：§1.6 #8（L84）与 V8（L1833）自相矛盾；§5.3 L874 注释"true=message/stream，false=message/send"未说明 resubscribe 如何取值。
- **影响**：实现者按 V8 实现后，合法的 resubscribe 场景（S6）无法通过 Validate；或实现者自行放宽规则导致与文档不一致。
- **修复建议**：V8 改为"`Streaming=true` 时 `Method` 必须为 `message/stream` 或 `tasks/resubscribe`；`Streaming=false` 时 `Method` 必须为 `message/send`"；§5.3 L874 注释同步说明。

### M-D：遗漏 v0.2.x 的 `agent/authenticatedExtendedCard` HTTP GET 端点

- **位置**：§1.6 不变式 #3（L79）、§3.1 方法表（L475-495）
- **描述**：v0.2.2/v0.2.5 规范除 7 个 JSON-RPC 方法外，还有第 8 个端点 `agent/authenticatedExtendedCard`——**HTTP GET 端点，非 JSON-RPC 方法**（v0.2.2 §7.8：Endpoint URL `{AgentCard.url}/../agent/authenticatedExtendedCard`，需要 `supportsAuthenticatedExtendedCard: true`，401/403/404 错误语义）。文档 §1.6 #3 声称"spec v0.2.2+ 共 7 个核心方法"，§3.1 方法表只列了 v0.3.0 的 `agent/getAuthenticatedExtendedCard`（JSON-RPC 方法，v2 路线图），对 v0.2.x 的 `agent/authenticatedExtendedCard` 既未列入 v1 实现、也未标注 v2 路线图。
- **依据**：实拉 v0.2.2 §7.8（L726-752）、v0.2.5 §7.10（L788-792）确认该端点存在且为 HTTP GET；v0.3.0（L1945）仍保留。文档 §5.2 有 `SupportsAuthenticatedExtendedCard` 字段（L803）、T024 测试该字段，但无对应端点的场景/方法表条目。
- **影响**：目标版本（v0.2.x）下协议骨架枚举不完整；实现者若以"7 个方法"为准，无法生成 `GET /a2a/agent/authenticatedExtendedCard` 流量，且 `SupportsAuthenticatedExtendedCard=true` 的 Agent Card 与端点缺失之间出现覆盖断裂。
- **修复建议**：§3.1 方法表补充 `agent/authenticatedExtendedCard`（HTTP GET，v0.2.x 端点，标注 v1 不实现或 v2 路线图）；§1.6 #3 改为"7 个 JSON-RPC 核心方法 + 1 个 HTTP GET 扩展卡片端点"。

### M-E：V15/T160 将规范的 SHOULD 误作 MUST，"spec 要求 HTTPS"表述错误

- **位置**：§8 V15（L1860-1861）、§7.14 T160（L1671）、§10.6 #9（L2014）
- **描述**：V15"`PushNotificationConfig.URL` 必须 `https://` 前缀（spec 要求 HTTPS）"、T160"webhook URL 非 HTTPS | PushNotificationConfig.url=http://，Validate 拒绝"、§10.6 #9"pushNotification URL HTTPS：spec 要求 HTTPS，Validate 拒绝 HTTP"。但规范对 webhook URL 的 HTTPS 要求是 **SHOULD** 而非 MUST：v1.0.1（L3125/L3129）"Clients **SHOULD** use HTTPS endpoints for webhook URLs"；v0.2.2/v0.3.0 schema 对 `PushNotificationConfig.url` 无任何格式约束（type: string）；规范的 HTTPS 强制要求（"production deployments MUST use HTTPS"）针对 A2A 传输层（§4.1），不针对客户端 webhook URL。
- **依据**：实拉 v0.2.2 schema `PushNotificationConfig.properties.url = {type: string}`；v0.3.0 同；v1.0.1 §4.3.1 + L3125/L3129 SHOULD 表述。
- **影响**：Validate 拒绝规范允许的配置（HTTP webhook），生成的流量无法覆盖真实 v0.2.x A2A 服务端可接受的行为；且文档把设计决策包装成"spec 要求"，重蹈 v1.1 "基于猜测的 spec 引用"覆辙（文档 L2159 教训）。
- **修复建议**：V15/T160/§10.6 #9 改为"HTTPS 为规范建议（SHOULD），Validate 默认警告不拒绝，或明确标注为本设计的安全加固选择（拒绝 HTTP 属超出规范的设计决策）"。

---

## 4. LOW 问题（3 项）

### L-A：MutualTLSSecurityScheme 必填字段标注错误

- **位置**：§2.4 SecurityScheme 表（L249）
- **描述**：文档称 mutualTLS"（v0.3.0 新增，**无必填字段**）"。实拉 v0.3.0 schema：`MutualTLSSecurityScheme.required = ["type"]`（type const="mutualTLS"），与其它 4 种子类型一样 type 必填。
- **依据**：v0.3.0 a2a.json `MutualTLSSecurityScheme`（required: ["type"]）。
- **影响**：实现者按"无必填字段"生成/校验 mutualTLS 方案时缺 type 字段。
- **修复建议**：改为"必填 type（const=mutualTLS）"。

### L-B：preferredTransport / additionalInterfaces 示例值与 schema 不符

- **位置**：§2.4 AgentCard 表（L214-215）
- **描述**：文档 preferredTransport 示例 `"http"`/`"SSE"`、additionalInterfaces 示例 `{"url":".../sse","transport":"SSE"}`。实拉 v0.3.0 schema：preferredTransport/additionalInterfaces 的 transport 示例为 `["JSONRPC", "GRPC", "HTTP+JSON"]`（且 preferredTransport 默认 `"JSONRPC"`）。schema 中不存在 `"http"` 或 `"SSE"` 作为 transport 取值示例。
- **依据**：v0.3.0 a2a.json AgentCard.properties.preferredTransport（default: "JSONRPC"、examples: ["JSONRPC","GRPC","HTTP+JSON"]）、AgentInterface.properties.transport（examples 同上）。v0.2.5 无此字段。
- **影响**：实现者按文档示例生成 additionalInterfaces/preferredTransport 时，会写出 schema 未列出的 transport 值；虽 schema 无 enum 约束（不构成违规），但与规范示例不一致。
- **修复建议**：示例改为 `"JSONRPC"`/`"HTTP+JSON"` 等 schema 实际示例值。

### L-C：§7.19 存在与既有章节重复的测试验证点

- **位置**：§7.19（L1744-1761）
- **描述**：§7.19 与既有章节存在 7 组同名/同验证点用例：T015/T212（AgentCard.protocolVersion）、T016/T213（securitySchemes map）、T017/T214（security 数组）、T073/T207（resubscribe 断线重连）、T141/T217（messageId 必填）、T143/T218（contextId 关联）、T146/T219（kind=message）。其中 T073（单元）vs T207（集成）有层级区分尚可；T015 vs T212、T016 vs T213、T017 vs T214、T141 vs T217、T143 vs T218、T146 vs T219 为同一验证点的重复断言。
- **依据**：程序化提取 246 条用例名称对比。
- **影响**：测试清单存在冗余，虚增"字段覆盖补全"的独立覆盖价值；实现阶段可能重复实现同一断言。
- **修复建议**：§7.19 中与既有章节重复的条目（T212/T213/T214/T217/T218/T219）改为引用既有用例（如"见 T015"）或删除，或将其验证点差异化。

---

## 5. 其它观察（不构成问题）

- **§2.10 长度约束**：全部长度限制（1MB text、10MB bytes、128 字节 id、1024 skills 等）均为文档设计决策，规范 schema 无任何 maxLength/maxItems 约束。文档未明示其为设计约束，建议在表注中注明，避免实现者误认为协议兼容性要求。
- **§4.2 状态转换表**：规范（v0.2.2/v1.0.1）未定义正式的状态转换表，仅定义状态枚举与使用模式。文档的转换表是合理的设计约束，但"input-required→completed spec 未定义"的表述宜改为"本设计未定义"。
- **spec 内部 final 矛盾**：v0.2.2 规范 markdown §7.2.2 表称 final 为"否（可选，默认 false）"，而 v0.2.2/v0.3.0 JSON schema 的 required 数组含 final。文档选择 schema（required）是正确的，但可注明规范文本与 schema 的差异来源，避免实现者按 markdown 表质疑。

---

## 6. 与 CLAUDE.md §Testing Policy 的符合性评估

| 规则 | 评估 |
|------|------|
| 规则 1（spec-driven） | 符合。用例按 spec §5-§9 组织，字段覆盖较全；但 §7.19 存在冗余重复（L-C） |
| 规则 2（失败路径） | 符合。负向 57 条覆盖全部 13 个错误码 + 非法输入 + 状态机非法转换；占比如实标注 23.2%（边界计数错误见 M-A） |
| 规则 3（每路径一测试） | 有缺口。T138 声称的 Validate 行为无规则支撑（M-B）；V8 规则与 resubscribe 冲突（M-C） |
| 规则 4（集成测试） | 符合。T204-T211 有 8 条端到端用例 |
| 规则 5（断言可观察结果） | 符合。Content-Length 字节级断言已修正（M-6）；S1-S15 断言可观察 |
| 规则 6（并发正确性） | 符合。T167/T168 测量聚合包数与聚合速率 |
| 规则 7（failing-test-first） | 符合。r1-v2 修复均配有验证用例或文档修订 |
| 规则 8（测试质量对抗审查） | 本文档为该维度产物；发现 §7.19 重复（L-C）、T160 基于错误规范解读（M-E） |

---

## 7. 详细证据附录（关键 Spec 引文，全部实拉）

### 7.1 TaskStatusUpdateEvent.required（v0.2.2 与 v0.3.0 相同）

```
required = ["contextId","final","kind","status","taskId"]
```
（v0.2.2 markdown §7.2.2 表却标 final 为"No，默认 false"——规范内部矛盾，schema 为权威）

### 7.2 SendStreamingMessageResponse（v0.2.2 schema）

```
anyOf = [JSONRPCErrorResponse, SendStreamingMessageSuccessResponse]
```

### 7.3 Agent Card 路径（各版本）

| 版本 | 路径 |
|------|------|
| v0.2.2 §5.3 | `/.well-known/agent.json` |
| v0.2.5 §5.3 | `/.well-known/agent.json` |
| v0.3.0 §5.3 | `/.well-known/agent-card.json` |
| v1.0.1 §8.2 / §14.3（IANA） | `/.well-known/agent-card.json`（URI suffix: agent-card.json，Status: Permanent） |

### 7.4 MutualTLSSecurityScheme（v0.3.0）

```
required = ["type"], type const = "mutualTLS"
```

### 7.5 preferredTransport / AgentInterface（v0.3.0）

```
preferredTransport: default "JSONRPC", examples ["JSONRPC","GRPC","HTTP+JSON"]
AgentInterface.transport: examples ["JSONRPC","GRPC","HTTP+JSON"]
```

### 7.6 PushNotificationConfig.id 语义

- v0.2.2：`Push Notification ID - created by server to support multiple callbacks`
- v0.3.0：`A unique ID for the push notification configuration, set by the client to support multiple notification callbacks`

### 7.7 PushNotificationConfig.url 的 HTTPS 要求

- v0.2.2/v0.3.0 schema：url 无格式约束（type: string）
- v1.0.1：`Clients SHOULD use HTTPS endpoints for webhook URLs`（SHOULD，非 MUST）

### 7.8 v0.2.x 扩展卡片端点

- v0.2.2 §7.8：`agent/authenticatedExtendedCard`，HTTP GET 端点（非 JSON-RPC），URL `{AgentCard.url}/../agent/authenticatedExtendedCard`，需 `supportsAuthenticatedExtendedCard: true`，401/403/404 错误语义
- v0.3.0：保留（L1945），另有 JSON-RPC 方法 `agent/getAuthenticatedExtendedCard`（-32007）

### 7.9 错误码（v0.2.2/v0.3.0 schema code.const）

- v0.2.2/v0.2.5：-32700/-32600/-32601/-32602/-32603/-32001/-32002/-32003/-32004/-32005/-32006
- v0.3.0：另加 -32007 `AuthenticatedExtendedCardNotConfiguredError`

### 7.10 测试用例统计（程序化）

```
总数 246；编号 T001-T242 连续 + T212a-T212d；无缺号
正向 149 / 负向 57 / 边界 30 / 集成 8 / 并发 2 = 246
负向占比 57/246 ≈ 23.2%
各节标题计数（12/12/16/14/10/8/8/12/12/18/8/8/12/10/12/14/17/8/14/6/15）与实际行数全对
```

### 7.11 Content-Length 字节计算（紧凑序列化，json.Marshal 无缩进）

```
S1 Agent Card body  = 501 字节 ✅
S2 请求 body        = 258 字节 ✅
S2 响应 body        = 257 字节 ✅
```

---

## 8. 最终结论

**本文档是否可以进入实现阶段：有条件通过（是，但需先修复 5 项 MEDIUM）。**

- **CRITICAL：0**。协议骨架（方法名/Agent Card 路径/Part kind/事件类型/状态枚举/错误码）经四个历史 tag 实拉验证与 spec 严格一致。
- **HIGH：0**。r1-v2 的 3 项 HIGH（final 必填+omitempty、路径版本事实、SSE data 联合）全部正确修复并验证。
- **MEDIUM：5**。M-B（T138 无规则支撑，r1-v2 M-3 修复未落地）与 M-C（V8 规则误伤 tasks/resubscribe，r1-v2 L-5 修复不完整）直接影响实现者的 Validate 逻辑，必须在实现前修复；M-D（遗漏 v0.2.x agent/authenticatedExtendedCard 端点）影响协议骨架完整性；M-E（将 SHOULD 误作 MUST 拒绝合法配置）影响流量代表性；M-A（边界计数 28 vs 30）为文档数字错误。
- **LOW：3**。均为文档细节准确性（mutualTLS 必填、transport 示例值、测试重复）。

修复优先级建议：M-B → M-C → M-D → M-E → M-A → L-A/L-B/L-C。
