# #93 a2a（Agent2Agent，Agent 间互操作协议）设计契约

> 版本：v1.0.0（P-PIPE 文档轨 P1–P3）
> 日期：2026-09-28
> 车道：A 文档轨（Lane A，#93 a2a 续号）
> 旧基线：`docs/protocol-designs/17-a2a-design.md` v2.0.3（2232 行，无独立 testcase 文件）+ `#52 a2a P1–P3 报告`（`/tmp/pipe/52-a2a/p123-report.md`，门1 十四行 + 11 项缺口 G-A2A-1…G-A2A-11）
> 存量用例：`trafficgen/test/protocol_pcap/cases/a2a.json`（185 例，**本版保持原样**；改写版已产出并存 patch，见 §12.1；现状 185/185 带顶层扁平四元组 + 顶层 `a2a` 子映射，153/185 另带空壳 `layers:[{tcp:{}},{a2a:{}}]`——**全为违规过渡形**（§1.4/§1.11 判死），见 §12.1 缺口登记）
> 规范基线：① A2A spec v0.2.2（本版目标版本，方法名/Agent Card 路径/Part kind/事件类型以它为准）；② A2A spec v0.2.5 / v0.3.0 / v1.0.0 / v1.0.1（差异面，只记不实现）；③ JSON-RPC 2.0；④ RFC 8615（well-known URI）/ RFC 7235（HTTP 认证）；⑤ 本仓库落码（`internal/protocol/a2a/` 八文件 + 接线 5 处，§11.1）；⑥ 本机 tshark 3.6.14 实测（**`a2a.*` 字段 0 个、`json.*` 29 个**，断言通道走 `http.*`/`json.*`/`tcp.*`/frames，§3.5）
> 白话一句：**两个 AI 代理隔着网线说话，说的话是 HTTP 快递盒里装的 JSON 小纸条；引擎里它是一层薄皮——把配置里写好的每个 task 编成"一个请求盒 + 一个响应盒"，握手、分段、挥手全交给 TCP 层。**
> **阶段命名**：本文中 **P4 = 代码阶段**（`docs-first-workflow` 新顺序：文档全部定稿后才批量改代码）、**P5 = 跑测阶段**；P1–P3 为本文档轨。

## 0. 17→93 沿革与旧稿状态校正（门1 必答：基线继承关系）

本 #93 与旧稿 `17-a2a-*` 是**同一协议的重做契约**，不是新协议。旧稿保留只读参考，本契约逐条校正旧稿状态声明：

| # | 旧稿说法（17-* / #52 报告） | HEAD 实测（2026-09-28） | 校正结论 |
|---|---|---|---|
| 1 | #52 报告称 "`a2a` 层已注册（`registry.go:205-207`）" | `registry.go:245` 注册 `a2a`（`CategoryTerminal`、`DependsOn ["tcp"]`、**无 `Fields`/`FieldContract`/`TransportOn`**）；生成表 127 层中 `a2a` = `{"category":"terminal","depends_on":["tcp"],"fields":{}}`（机读实测） | 已注册；**行号漂移**（205→245），本契约以 HEAD 行号为准 |
| 2 | #52 报告称 "`main.go:622` 只注册 ChainPlanner" | `cmd/server/main.go:20` 空导入 a2a 包、`:630` `RegisterPlanner(layers.NewChainPlanner("a2a"))`；`internal/core/layers/legacy_migrate_test.go:126` 已有 a2a 链冒烟（`a2aMinimalSpec`，`:183`） | 接线已通；行号漂移（622→630） |
| 3 | #52 报告称 "`cases/a2a.json` 185 例全旧扁平形（185/185 带顶层 `a2a`）" | 实测：185/185 带顶层 `a2a` 子映射 + 顶层四元组；**153 例另带空壳 `layers:[{tcp:{}},{a2a:{}}]`**（两层 config 恒 `{}`，既不校验也不消费），32 例无 `layers` | 旧形 = **违规过渡形**（§1.4/§1.11 判死）；**本版保持原样**（改写版已产出存 patch，落地须先补代码，§12.1/G-A2A-1） |
| 4 | 旧稿 §5.1 `A2AConfig` 含 `HTTP`/`TCP`/`FlowControl` 三个子结构 | `types.go:23-33` `A2AConfig` **字段齐在**（`BaseURL/AgentCardPath/Discover/AgentCard/Tasks/Auth/HTTP/TCP/FlowControl`）；但存量 185 例**零例使用** `tcp`/`http`/`flowControl` 三键（机读：`tcp` 0 例、`http` 0 例、`flowControl` 0 例） | 三键已落码但**无用例面** → A′ 立项（§13）；**注**：三键的迁层去向仍在 G-A2A-1（层内化）之后，非「无迁移量」 |
| 5 | 旧稿 §7 称"246 条测试用例" | 存量 JSON **185 例**（唯一 ID 185）；#52 报告 §② 自审已核为"167 合入 + 9 等价 + 9 作废"，即**设计行 246 ≠ 存量 185**（差 87 条无存量例，G-A2A-9） | 计数口径继承 #52 结论；本契约 §9 以**存量 185** 为 JSON 权威、246 为设计行台账 |
| 6 | #52 报告称 "`Fields` 空表 + 无 translate 分支 → `layers[].a2a` 今日判死（G-A2A-1）" | 三重确认：① `chain_planner_translate.go` **无 `case "a2a"`**（`grep -c` = 0 实测）；② `chain_planner_translate.go:852` **`if len(s.Fields) == 0 { return }` 位于整个 `switch term.Name` 之前**——空壳层**连 case 都到不了，层内配置根本不被解码**；③ `complete.go:293`（`ValidateLayerConfig`）对 `Fields` 为空的层报 `layers: layer "a2a": unknown field %q` | **G-A2A-1 确认成立**：层为空壳，目标形状需先补代码（§1.9 口径） |
| 7 | #52 报告称 "`a2a.*`=0、`jsonrpc.*`=0" | 本机 tshark 3.6.14 复测：`a2a.*` = **0**、`json.*` = **29**（`jsonrpc.*` 前缀 0，JSON-RPC 字段住 `json.*`） | 实测一致；断言通道定案见 §3.5 |
| 8 | #52 报告称 "8080 端口可被 HTTP 解析器自动解码" | 存量 185/185 显式 `dst_port=8080`；HTTP dissector 按 8080 自动解码（自造探针实测，无需 `decode_as`） | 端口 fixture 继承有效 |
| 9 | 旧稿（17-design）**无独立 testcase 文件**，#52 报告称"ID 权威已在 design §7，另起文件=双头维护" | `ls docs/protocol-designs/ \| grep a2a` = 仅 `17-a2a-design.md`；本批次交付契约为 **design + testcase + cases JSON 三件套**（`protocol-doc-requirements.md` §1） | 双头顾虑**不成立**：#93 两份文档职责分离（design 管代码生成、testcase 管测试保障），不是同一份 ID 表抄两遍（§7 方法论） |

**依赖链判定纪律**：以上均为可判题（旧文→代码→用例三级对照），直接判定，不问偏好。不可判的（真实商业 Agent 平台的现网行为）标"待确认"并写清确认方式（G-A2A-4）。

## 1. 范围、profile 与实现状态边界

本版定义客户端 Agent 与远程 Agent 之间的 **A2A over HTTP/1.1 over TCP**：TCP payload 是完整 HTTP 报文（请求行 + 头 + `Content-Type: application/json` 的 JSON-RPC 2.0 body，或 `text/event-stream` 的 SSE body）。**无自定义二进制帧、无长度前缀**——每个 task 恰好一个 HTTP 请求盒 + 一个 HTTP 响应盒。

| profile | 承载 | 本版允许内容 | 不从 profile 推导 |
|---|---|---|---|
| `a2a_v022_core`（主） | HTTP/1.1 明文 over TCP（fixture `dst_port=8080`） | 7 个 JSON-RPC 方法 + Agent Card 发现 GET + SSE 流式响应 + 9 状态 + 12 错误码 | TLS/HTTPS、HTTP/2、真实 Agent 平台的处理时序 |
| `a2a_v022_auth` | 同上 + 请求头 | `none/bearer/basic/apikey(header|query|cookie)/oauth2/openIdConnect` 六种认证写法 | 真实令牌签发/校验、OAuth2 授权码流程 |
| `a2a_ipv6` | 同上，仅外层 IPv6 | 同主 profile | 从 IPv4 fixture 推导 IPv6 地址 |

**显式边界（"不实现、不声称、不许静默转换"）**：① v0.3.0+ 的 `tasks/pushNotificationConfig/list|delete`、`agent/getAuthenticatedExtendedCard`（JSON-RPC，-32007）、`/.well-known/agent-card.json` 路径、`A2A-Version` 头、分页——**v2 路线图**（G-A2A-11），Validate 按 `ValidMethods`（`types.go:351`）拒绝；② webhook 反向连接（Agent → 客户端 webhook）**不生成**——本引擎的链是单向发起（客户端建连），反向连接需第二个 flow 且方向相反，`driven_by` 关联今日无处可住（G-A2A-5，§12.3 关联关系）；③ 真实 SSE 分块时序（`Transfer-Encoding: chunked` 的实际 chunk 边界）不声称与真实服务端一致，只保证事件序列与字节内容；④ MutualTLSSecurityScheme 的 Agent Card 声明可承载（`A2ASecurityScheme` 是 `map[string]any`），但不生成 mTLS 握手。

**实现状态（2026-09-28 实测）**：`a2a` 层已注册（`registry.go:245`）、planner/validator/生成器已落码（`internal/protocol/a2a/` 八文件共 5741 行，`wc -l` 实测；95 个 `Test*` 函数，`grep -c` 实测）、`allowedProtocols["a2a"]=true`（`protocols.go:22`）、185 语义用例已落 `cases/a2a.json`。旧稿"待实现"描述对**骨架**已过时。

**层为空壳（本协议最关键的现状事实，门1 §1 行的核心）**：

- `registry.go:245` 的 `a2a` 注册**无 `Fields`**（生成表 `layers.a2a = {"category":"terminal","depends_on":["tcp"],"fields":{}}`，机读实测）。
- `chain_planner_translate.go:852` 的 `if len(s.Fields) == 0 { return }` **位于整个 `switch term.Name` 之前** → 空壳层**连 translate case 都到不了**，层内 config **根本不被解码**（`translateTerminalConfig` 亦无 `case "a2a"`，`grep -c` = 0）。
- 故层内写任何键的今日行为是 `complete.go:293` 报 `layers: layer "a2a": unknown field %q`；而唯一能承载 `A2AConfig` 的通道是**顶层 `a2a` 子映射**（`strategy_convert.go:1633` → `spec.Payload` → `chain_planner_translate.go:48` `FlowMeta.Payload` 直传生成器）。

**合规层链形需代码阶段补三件**（G-A2A-1，文档阶段改不动）：① registry `Fields` 补 a2a 键表（否则 `:852` 提前返回，后续一切不可达）；② `translateTerminalConfig` 补 `case "a2a"`（层内 config → `spec.Payload`，层优先/已存在不覆盖）；③ `mapToFlowSpec` 顶层 `a2a` 兼容支收敛 + `CheckProtoFlat` presence 判死。**本协议 185 例现全为违规过渡形**（§12.1）。

**探针实测取证（2026-09-28，非推理；探针文件跑完即删，仓库零改动）**：

| 探针 | 输入 | 实际错误原文 | 出处 |
|---|---|---|---|
| ① 改写后形状（配置在 `a2a` 层） | `[{"ip":{src,dst}},{"tcp":{src_port,dst_port}},{"a2a":{"baseUrl":"…","tasks":[…]}}]` → `layers.ValidateLayers(raw,"a2a")` | **`layers: layer "a2a": unknown field "baseUrl"`** | `complete.go:293`（`ValidateLayerConfig`） |
| ① 对照：空壳层 | `[{"ip":{…}},{"tcp":{…}},{"a2a":{}}]` | `err=<nil>`（config 为空不触发；但配置也进不去） | 同上 |
| ② 存量形状（未改写） | `{layers:[{tcp:{}},{a2a:{}}], count:1, src_ip, dst_ip, src_port, dst_port, a2a:{…}}` → `schema.ValidateStrategy("synth","a2a",…)` | **`protocol a2a no longer accepts flat config field src_ip (use a layers chain: ip.src/ip.dst for addresses, tcp/udp src_port/dst_port for ports, flow_control for the flow count)`** + **`config mixes layers with flat four-tuple field src_ip (…)`** | `schema/semantic.go:130`（`CheckProtoFlat`）+ `checkLayerFlatConflict` |

**结论**：两条路今日都不通——存量形状经 MCP 建策略 **400**，改写形状被 `unknown field "baseUrl"` 硬拒。**合规层链形必须先补代码**。

**输出契约（pcap/NIC 双输出）**：两路径共用同一 cases JSON 与断言集（`tcp.srcport/dstport`、`tcp.flags/len`、`http.content_type`、frames offset 54/74 原始字节）；NIC 经 tcpdump 捕获（`nic_capture` 用例级开关）；不设仅单路径可用的断言。

## 2. 协议栈、端口和固定偏移

推荐层链为 `[ip, tcp, a2a]`（引擎自动补 `ip`；最小链 `[tcp, a2a]`）。a2a 报文是 **TCP payload 的完整 HTTP 报文**——**HTTP 报文边界不是 TCP 段边界**：一个请求盒可跨多段（超 MSS 自动分段，`segmentByMSS`，`a2a.go:1234`），接收端按 TCP 序号重组。

端口：fixture 统一 `dst_port=8080`（存量 185/185 显式写，断言纳入）。**registry `a2a` 无 `FieldContract`** → 缺省端口走通用缺省 80（`strategy_convert.go:341`，`DefaultDstPort=80` `:54`），**8080 只是用例 fixture、不是引擎缺省**（G-A2A-2，§14）。

固定偏移：无 VLAN/IP options/TCP options 时，**HTTP 报文首字节起点为 IPv4 offset 54（14+20+20）、IPv6 offset 74**（14+40+20）。

目标形状 spec_json 样例（严格层链形，顶层仅 `layers` + `flow_control`；**目标形状声明**：registry `a2a` `Fields` 今日为空，层内任何键今日被 `complete.go:293` 判 `layers: layer "a2a": unknown field %q`，故此形**今天跑不通，需先补代码** G-A2A-1，§1.9 口径）：

```json
{
  "layers": [
    {"ip": {"src": "10.0.0.1", "dst": "20.0.0.1"}},
    {"tcp": {"src_port": 51001, "dst_port": 8080}},
    {"a2a": {
      "baseUrl": "http://agent.example.com/a2a",
      "discover": true,
      "agentCard": {"name": "example-agent", "description": "An example A2A agent",
                    "url": "http://agent.example.com/a2a", "version": "1.0.0",
                    "protocolVersion": "0.3.0",
                    "capabilities": {"streaming": true, "pushNotifications": true,
                                     "stateTransitionHistory": true},
                    "skills": [{"id": "skill-1", "name": "greeting",
                                "description": "Greets users", "tags": ["chat"]}],
                    "defaultInputModes": ["text"], "defaultOutputModes": ["text"]},
      "tasks": [{"method": "message/send", "requestId": "req-001",
                 "message": {"role": "user", "parts": [{"kind": "text", "text": "hello"}],
                             "messageId": "m-001", "contextId": "ctx-abc", "kind": "message"},
                 "configuration": {"acceptedOutputModes": ["text"], "blocking": true},
                 "response": {"result": {"id": "task-001", "contextId": "ctx-abc",
                                         "status": {"state": "completed",
                                                    "timestamp": "2026-08-05T10:00:00Z"},
                                         "artifacts": [{"artifactId": "art-1", "name": "reply",
                                                        "parts": [{"kind": "text", "text": "hi there"}]}],
                                         "kind": "task"}}}]
    }}
  ],
  "flow_control": {"flows": 1}
}
```

多流样例（S4 目标形，数量只走 `flow_control`，四元组留空走 worker 保底递增 §12.12）：

```json
{
  "layers": [
    {"ip": {"src": "10.0.0.1", "dst": "20.0.0.1"}},
    {"tcp": {"dst_port": 8080}},
    {"a2a": {"tasks": [{"method": "message/send", "requestId": "req-001",
                        "message": {"role": "user", "parts": [{"kind": "text", "text": "hello"}],
                                    "messageId": "m-001", "kind": "message"},
                        "response": {"result": {"id": "task-001", "kind": "task",
                                                "status": {"state": "completed"}}}}]}}
  ],
  "flow_control": {"flows": 3}
}
```

## 3. 线格式编码（逐项标注出处）

### 3.1 信封与两条路径

A2A 的全部报文都是 JSON-RPC 2.0 信封（spec v0.2.2 §7）：

- **请求**：`{"jsonrpc":"2.0","method":<string>,"params":<object>,"id":<string|integer>}`（`builder.go:14` `BuildJSONRPCRequest`）
- **成功响应**：`{"jsonrpc":"2.0","result":<object>,"id":<同请求>}`
- **失败响应**：`{"jsonrpc":"2.0","error":{"code":<int>,"message":<string>,"data":<any>?},"id":<同请求>}`
- **A2A 不使用 JSON-RPC 通知**（无 id 的请求）；所有方法均为请求-响应模式（spec v0.2.2 §7）

两条投递路径（同一 HTTP 方法 `POST`）：

| 路径 | 方法 | 响应 `Content-Type` | 响应体 |
|---|---|---|---|
| 同步 | `message/send`、`tasks/get`、`tasks/cancel`、`tasks/pushNotificationConfig/{set,get}` | `application/json` | 单盒 JSON-RPC 响应（`Content-Length` 定界） |
| 流式 | `message/stream`、`tasks/resubscribe` | `text/event-stream` | SSE 事件序列（`Transfer-Encoding: chunked` 定界） |

**Agent Card 发现是第三条路径、不是 JSON-RPC**：HTTP `GET {AgentCardPath}`（spec v0.2.2 §5.3），响应 `200` + `application/json` 的 Agent Card 对象（`a2a.go:722` `buildAgentCardRequest`）。

### 3.2 方法表（spec v0.2.2 §3.1；代码 `types.go:319-327` + `ValidMethods` `:351`）

| 方法 | params 必填 | result 类型 | 说明 |
|---|---|---|---|
| `message/send` | `message` | `Task` \| `Message` | 发送消息（同步），发起或继续交互 |
| `message/stream` | `message` | SSE 流（4 种事件） | 发送消息并订阅 SSE 流 |
| `tasks/get` | `id` | `Task` | 查询任务当前状态 |
| `tasks/cancel` | `id` | `Task` | 取消任务（仅非终态可取消） |
| `tasks/resubscribe` | `id` | SSE 流 | 断线重连已有任务的 SSE 流 |
| `tasks/pushNotificationConfig/set` | `taskId`, `pushNotificationConfig` | `TaskPushNotificationConfig` | 设置推送通知配置 |
| `tasks/pushNotificationConfig/get` | `id` | `TaskPushNotificationConfig` | 查询推送通知配置 |

**v0.2.x 非 JSON-RPC 端点**：`GET {url}/../agent/authenticatedExtendedCard`（扩展 Agent Card，401/403/404 语义）——本版不生成（v2 路线图）。

**v0.3.0+ 方法**（`tasks/pushNotificationConfig/list|delete`、`agent/getAuthenticatedExtendedCard`）——`ValidMethods` 不含 → `V2` 拒绝（锚词 `not in valid set`）。

**Streaming 与 Method 必须一致**（`a2a.go:73-81`，规则 V8）：`Streaming=true` 只允许 `message/stream`/`tasks/resubscribe`；`Streaming=false` 只允许 5 个同步方法。冲突 = `a2a validate: V8: Streaming=true but Method=%q is not a streaming method`。

### 3.3 SSE 流格式（spec v0.2.2 §3.3.1；代码 `a2a.go:998` `buildSSEResponse`）

- **未命名事件**：只有 `data:` 行，**无 `event:` 字段**（spec 用 payload 的 `kind` 区分类型）。
- **事件边界**：两个 `\n`（空行）分隔。
- **每个 `data:` 行** = 一个完整 JSON-RPC 响应对象：成功 `JSONRPCSuccessResponse`（`result` 为 4 种事件之一）或错误 `JSONRPCErrorResponse`（spec 称二者联合为 `SendStreamingMessageResponse`）。
- **4 种事件类型**（`result.kind` 判别）：

| kind | 必填字段 | 说明 |
|---|---|---|
| `task` | `id`, `contextId`, `status`, `kind` | 首事件（Task 对象快照） |
| `message` | `role`, `parts`, `messageId`, `kind` | Message-only 流的唯一事件 |
| `status-update` | `taskId`, `contextId`, `kind`, `status`, **`final`** | `final` 必填，`false` 时也必须显式输出（spec required） |
| `artifact-update` | `taskId`, `contextId`, `kind`, `artifact`（`parts` ≥1） | `append`/`lastChunk` 可选，默认 false |

**SSE 序列约束**（`a2a.go:186-251`，规则 V9/V10；`if task.Streaming` 起于 `:186`）：首事件 kind ∈ {task, message}；末事件若为 status-update 则 `final=true`；事件 kind ∈ 4 种；状态转换按 §4.2 表逐跳校验。

### 3.4 对象字段表

**Agent Card**（spec v0.2.2 §5.5；`types.go:76-96`）：必填 `name`/`description`/`url`/`version`/`protocolVersion`/`capabilities`/`defaultInputModes`/`defaultOutputModes`/`skills`；可选 `provider`/`iconUrl`/`documentationUrl`/`securitySchemes`(map)/`security`(array)/`supportsAuthenticatedExtendedCard`/`additionalInterfaces`(v0.2.5+)/`preferredTransport`(v0.2.5+)/`signatures`(v0.3.0，保留字段不生成)。

**Task**（`types.go:227`，`A2ATaskObject`）：`id`/`contextId`/`status`/`kind` 必填；`artifacts`/`history`/`metadata` 可选。`kind` 恒 `"task"`。

**TaskStatus**（`types.go:238`）：`state` 必填（9 值，§4.1）；`message`/`timestamp` 可选。

**Message**（`types.go:188`）：`role` ∈ {user, agent}/`parts`(≥1)/`messageId`/`kind` 必填；`taskId`/`contextId`/`referenceTaskIds`/`extensions`/`metadata` 可选。

**Part**（oneof，`types.go:201`）：`kind` ∈ {**text, data, file**}（spec 任何版本都无 `data-stream`/`file-stream`）+ 对应内容字段互斥（`a2a.go:98-106` 规则 V4）：

| kind | 内容字段 | 互斥校验 |
|---|---|---|
| `text` | `text` | `data`/`file` 必须为空 |
| `data` | `data`（对象） | `text`/`file` 必须为空 |
| `file` | `file`（`bytes` base64 或 `uri` 二选一，`a2a.go:109-117`） | `text`/`data` 必须为空 |

**Artifact**（`types.go:245`）：`artifactId`/`parts`(≥1) 必填。

**PushNotificationConfig**（`types.go:276`）：`url` 必填；`id`（v0.2.2 服务端创建 / v0.3.0+ 客户端设置）/`token`/`authentication{schemes[],credentials}` 可选。**无 `userId` 字段**（spec 无此字段）。

### 3.5 tshark 断言通道（本机实测，tshark 3.6.14）

| 通道 | 实测 | 用途 |
|---|---|---|
| `a2a.*` | **0 字段** | **不得使用**——本机无 a2a dissector |
| `json.*` | 29 字段 | JSON body 解析（`json.value.string` 等） |
| `http.*` | 在册 | `http.content_type`（`application/json` vs `text/event-stream`）、`http.request.method`、`http.response.code`、`http.request.uri` |
| `tcp.*` | 在册 | `tcp.srcport`/`dstport`/`flags`/`len`/`seq` |
| frames | 在册 | `offset`/`hex` 原始字节（HTTP 报文首字节 offset 54/74） |

**端口 8080 的 HTTP 解码**：8080 是 HTTP dissector 的备选端口，自造 pcap 探针实测可自动解码（无需 `decode_as`）。**SSE 无专用解析器**——整段落 `http.file_data`，事件序只能靠 frames hex 钉（T205/T207 已用）。

## 4. 业务场景分析（现网典型场景与五层覆盖）

**定性**：**声明式剧本回放**——配置是剧本（`tasks[]` 逐条声明方法 + 请求体 + 响应体），引擎按序产出 HTTP 报文事件，TCP 层按 MSS 分段。

| 现网场景 | 事务交互 | 对应用例 |
|---|---|---|
| ① Agent 发现 + 单次对话 | `GET /.well-known/agent.json` → `POST message/send` → `200 OK` | S1/S2/T204 |
| ② 流式对话 | `POST message/stream` → SSE 4 类事件 → `final:true` | S3/S10/T205 |
| ③ 任务生命周期管理 | `message/send` → `tasks/get` 轮询 → `tasks/cancel` | S4/S5/T208 |
| ④ 断线重连 | `message/stream` 中断 → `tasks/resubscribe` 续传 | S6/T207 |
| ⑤ 推送通知配置 | `tasks/pushNotificationConfig/set` → `get` | S7/T231/T089 |
| ⑥ 认证对话 | Agent Card `securitySchemes` → 请求 `Authorization` 头 | S8/S8b/S8c/T096–T098/T012 |
| ⑦ 多任务串行/多会话并发 | 同连接 2 task 串行；`flows=3` 三连接并发 | T208/T164/T165/T168 |
| ⑧ 大载荷 | 1MB text / 10MB file base64 跨 MSS 分段 | T174/T177 |

**五层覆盖逐层结论**：
- **功能层**——7 方法各正例（S2/S3/S4/S5/S6/S7 + S1 发现）；9 状态各正例（T105–T115）；12 错误码各正例（T187–T198；**-32007 零例**——v2 路线图，设计 §1 显式不支持，见 §13 A′）；4 事件 kind 各正例（T043/T044/T124–T138）；Part 3 kind 各正例（T147/T148/T149 三 kind + T222/T223/T224 互斥正例）；6 认证写法（T096–T098/T012/T103）；负例 32 条覆盖配置/线格式/状态机/关联/长度/载体六类（§7）。
- **性能层**——1MB text（T174，`min_packets=700`）、10MB file（T177，`min_packets=9000`）跨 MSS 分段；1024 skills / 1024 parts（T180/T181）；4096B description（T183）；3 流聚合（T165/T168）、10 task 同连接（T167）。
- **数据场景层**——长度边界 128/1024/4096/1MB/10MB 逐项（T174–T183）；id 类型 string/integer/null 三态（T003/T004/T179）；9 状态逐值（机读实测：submitted 34 / working 41 / input-required 6 / auth-required 4 / completed 134 / canceled 8 / failed 3 / rejected 2 / unknown 1）；12 错误码中 **11 值有例、-32007 零例**（v2 路线图）；Part 互斥三向（T222–T227）。
- **地址与流层**——IPv4 基线 + **IPv6 独立用例**（T-S6 族，offset 74）；单流基线；多流总包数断言（T164/T165/T168，**今日无端口聚合断言**——跨流包序随机交织；A′ 候选补 `distinct_values`，testcase §6.2）。
- **业务层**——发现→对话→查询→取消的完整链（T204/T208）；多轮交互（T106 `input-required→working→completed`）；并发多会话（T165/T168）；复合大场景 = T205（stream 全流程：SSE 3 事件 × final × 流关闭）。

**次要合法行为显式不适用声明（不设正例、亦不得进负例）**：① webhook 反向连接（G-A2A-5，需反向 flow，本引擎链单向）；② `agent/authenticatedExtendedCard` 端点（v2 路线图）；③ `signatures` JWS 签名（v0.3.0，保留字段不生成）；④ MutualTLS 实际握手（Agent Card 可声明，不生成 mTLS）。

## 5. 消息/事务模型与状态机

**事务定义**：一个 task = 一个 HTTP 请求 + 一个 HTTP 响应（Agent Card 发现是独立事务）。**多事务** = 同一 TCP 连接内 `tasks[]` 按序执行：T208（2 task 串行）、T167（10 task 串行）、T164（3 task 串行）。

a2a 层**无自有状态**（`layer_gen.go:90` 的 `for taskIdx, task := range cfg.Tasks` 循环，每 task 两个事件）：握手/seq-ack/挥手/分段全在 tcp 层；a2a 层是"按 `tasks[]` 顺序把配置翻译成 HTTP 报文事件"的纯函数驱动。**唯一例外**：`cfg.TCP`（`mss`/`initialSeq`/`handshake`/`termination`）经 `RegisterLayerValidator`（`layer_gen.go:211`（函数体至 `:244`））校准进 `spec.TCP`，由 tcp 层执行 legacy 语义。

| 状态（tcp 层拥有） | a2a 层动作 | 用例 |
|---|---|---|
| `ESTABLISHED`（数据阶段） | 每 task → `(up, 请求字节)` 事件 + `(down, 响应字节)` 事件 | 全部正例 |
| 终止（FIN 四包 / RST） | 事件流关闭 → tcp 层挥手；RST 为框架能力 | 全正例 FIN |

**Task 状态机**（spec v0.2.2 §4；`types.go:377` `validTaskTransitions`，规则 V10）：

9 个状态：`submitted` / `working` / `input-required`（暂停）/ `auth-required`（暂停）/ `completed`（终态）/ `canceled`（终态）/ `failed`（终态）/ `rejected`（终态）/ `unknown`（终态）。

合法转换（**仅此表，其余一律拒**，含 `input-required→completed`、`submitted→completed`）：

| 起点 → 终点 | 说明 |
|---|---|
| `submitted` → `working` / `canceled` / `failed` / `rejected` / `auth-required` | 提交后五种去向 |
| `working` → `completed` / `failed` / `canceled` / `input-required` / `auth-required` | 处理中五种去向 |
| `input-required` → `working` / `canceled` / `failed` | 补输入后恢复/取消/失败 |
| `auth-required` → `working` / `canceled` / `failed` | 补认证后恢复/取消/失败 |
| 任意非终态 → `unknown` | 异常：taskId 过期/失效 |

**终态不可变**：`completed`/`canceled`/`failed`/`rejected`/`unknown` → 任意 = 拒绝（锚词 `V10: illegal state transition`）。

**自动派生规则**：① `method` 缺省 → `message/send`（`DefaultMethod`）；② `accept` 缺省 → `application/json, text/event-stream`；流式方法强制 `text/event-stream`；③ `connection` 缺省 → `keep-alive`；**最后一个 task 且 termination 生效时 → `close`**（`layer_gen.go:112-118`）；④ `response.statusCode` 缺省 → 200；⑤ `message.kind` 缺省 → `"message"`；⑥ TCP 握手/FIN 由 tcp 层自动补；⑦ 超 MSS 报文自动分段。

**多会话展开**：`flow_control {"flows": N}` = N 条独立 TCP 连接（各自四元组、各自 task 序列）。**同一 flow 内 `sessions[]` 数组不支持**（`A2AConfig` 无该字段，G-A2A-6：多会话语义由 flows 承载，显式声明缺失为**明确不解决**+ 现状够用）。

## 6. 性能设计与验收（CORE_MEMORY §6.1–6.8）

- **目标与边界**：单流单 task 全链 9 包（3 握手 + 1 请求 + 1 响应 + 4 挥手）；带发现 11 包（+2）；N task 串行 = 3 + 2N + 4 包（T167：10 task → 27 包）；3 流并发 27 包。最大单报文 = 10MB file base64（T177，`min_packets=9000` 段）。**吞吐数字待 P4 基准，本版不写承诺**（§6.5）。
- **依据**：逐 task 事件 emit（`layer_gen.go:90-175` 循环，每 task 两个事件，无全量收集）；每报文内存 = 报文长度 + TCP 段开销（O(报文)）；`segmentByMSS`（`a2a.go:1234`）逐段切片，不复制整块；无跨流共享状态；无锁；`spec.TCP` 校准在 validator 单次执行（`layer_gen.go:211`）。
- **验收两路**：pcap（`/tmp/mcp-pcaps/a2a/`）与 NIC（`enp135s0f0np0`，`nic_capture` 开关）共用同一断言集；断言实际 `tcp.len`/`http.content_type`/frames hex，不只断言"任务没报错"。
- **六类场景落点**：基线（S2，9 包）/ 目标规模（T167，10 task 27 包）/ 压力上限（T177，10MB 跨 9000+ 段）/ 长时间运行（T164/T165/T168 多流展开）/ 并发交错（T165/T168 三流 `directional` + 总包数 27）/ 背压（`packet_count` 精确计数守卫段数漂移 + `min_packets` 下界）。

## 7. 错误处理（负例锚词表，与 testcase §4 一一对应、同序）

以下输入必须由 planner/validator 拒绝并传播为 task error，不得产出成功 PCAP、`completed/0 packet` 或只剩 TCP 外壳的假成功。锚词取自 `a2a.go` / `layer_gen.go` 字面值（32 条负例，按规则族归并）：

| 规则 | 锚词 | 故障输入示例 | 代码出处 |
|---|---|---|---|
| V1 | `V1: invalid task state` | `status.state="bogus"` | `a2a.go:88` |
| V2 | `V2: method %q not in valid set` | `method="tasks/sendSubscribe"` / `"tasks/subscribe"` / `"pushNotificationConfig/list"` | `a2a.go:69` |
| V4 | `V4: Part kind=%q not in {text,data,file}` | `kind="data-stream"` | `a2a.go:96` |
| V4 | `V4: text/data/file Part has extra fields` | text Part 带 `data`；data Part 带 `file`；file Part 带 `text` | `a2a.go:99/102/105` |
| V4 | `V4: file Part ... must carry Bytes or URI` | `file={}`（bytes/uri 全空） | `a2a.go:117` |
| V5 | `V5: PushNotificationConfig.URL is required` | `url=""` | `a2a.go:168` |
| V6 | `V6: AgentCard.<字段> is required` | 缺 `name`/`description`/`url`/`version`/`protocolVersion`/`capabilities`/`defaultInputModes`/`defaultOutputModes` | `a2a.go:283-305` |
| V6 | `V6: Security[%d] references scheme %q not present in SecuritySchemes` | `security` 引用未定义方案 | `a2a.go:326` |
| V7 | `V7: Message.messageId is required` / `role must be user or agent` / `parts must have at least 1 element` / `kind must be "message"` | `role="system"`；`parts=[]`；`kind="data-stream"` | `a2a.go:124-133` |
| V8 | `V8: Streaming=true but Method=%q is not a streaming method` / `Streaming=false but ...` | `message/stream` + `streaming=false`；`tasks/resubscribe` + `streaming=false` | `a2a.go:75/79` |
| V8 | `V8: RequestID (JSON-RPC id) is required` | 缺 `requestId` | `a2a.go:141` |
| V8 | `V8: TaskID is required for method %q` | `tasks/get`/`cancel`/`resubscribe`/`pnc/get` 无 `taskId` | `a2a.go:153/158` |
| V8 | `V8: PushNotificationConfig is required for method %q` | `pnc/set` 无 `pushNotificationConfig` | `a2a.go:161` |
| V9 | `V9: invalid SSE event kind` / `first SSE event kind must be task or message` / `status-update event missing Status` / `artifact-update event missing Artifact.Parts` / `last status-update event must have Final=true` | SSE 事件缺字段 / 末事件 `final=false` | `a2a.go:191-250` |
| V10 | `V10: illegal state transition %q -> %q` | `completed→working`；`failed→working`；`canceled→working`；`rejected→working`；`input-required→completed` | `a2a.go:241` |
| V11 | `V11: invalid error code %d` | `error.code=-99999` | `a2a.go:274` |
| V12 | `V12: <字段> exceeds <上限>` / `JSON-RPC id ...` | `name>128B`；`description>4096B`；`skills>1024`；`parts>1024`；`text>1MB` | `a2a.go:310-415` |
| V16 | `V16: result and error are mutually exclusive` | 同时设 `result` 与 `error` | `a2a.go:261` |
| 载体 | `a2a: invalid source IP` / `invalid destination IP` | 非法 IP 字面 | `a2a.go:32/37` |
| 载体 | `a2a: MSS %d too small (min 536 per RFC 879)` | `tcp.mss=100` | `a2a.go:42/59` |
| 生成器 | `a2a generator: no tasks configured` | `tasks=[]`（空连接显式拒绝） | `layer_gen.go:67` |
| 生成器 | `a2a generator: no config (spec.Payload must carry A2AConfig JSON)` | 无配置 | `layer_gen.go:59` |

**负例原子性**：每例单一故障注入；单次执行不得混注。32 条负例 `expect` 键集合**严格为** `{expect_error, error_contains}` + `notes`（机器契约两键纯净，`notes` 为人工可读注记）。

**不得误报的合法协议事件**：`tasks=[]` 以外的所有合法配置；`input-required`/`auth-required` 暂停态（正例 T036/T078/T106/T113 与 T104/T110/T112/T114，机读实测 4+4 例）；HTTP URL 的 webhook（spec 为 SHOULD 建议，非 MUST）；`mutualTLS` 方案声明。

## 8. 边界

- **报文长与分段**：1MB text → 700+ 段（T174 `min_packets=700`）；10MB file base64 → 9000+ 段（T177）；`mss` 有效下界 536（RFC 879，`MinMSS` `a2a.go:1307`）。
- **长度上限**（spec §2.10）：`id` string ≤128B / integer ≥0；`taskId`/`contextId`/`messageId` 1–128B；`name`/`version` 1–128B；`description` 0–4096B；`Part.text` 0–1MB；`File.bytes` 解码后 ≤10MB；`skills` 0–1024；`parts` 1–1024；`history` 0–1000。
- **状态机**：9 值 × 转换表（§5）；终态不可变；`unknown` 不带 `message`。
- **Part 互斥**：三向互斥（V4）；`file` 必须 `bytes` 或 `uri` 至少一个。
- **地址族**：IPv4 fixture 全正例 + IPv6 独立用例（offset 74）；**异族混写今日零用例**（a2a validator 只校验 `net.ParseIP` 逐字段合法性，无 a2a 专属异族分支，通用链级异族检查仅部分协议有）→ A′ 补例（§13）。
- **端口**：8080 显式全正例；**缺省端口今日无 FieldContract → 落通用缺省 80** → A′ 补例（G-A2A-2，§13/§14）。
- **`cfg.TCP`/`cfg.HTTP`/`cfg.FlowControl` 三键**：已落码、零用例面 → A′ 补例（§13）。
- **RST 异常中断**：框架 tcp 层能力，本层零断言 → A′ 补例（G-A2A-10）。
- **SSE 中间事件为 0**：T186（task → status-update(final) 仅 2 事件）。
- 不得产生回绕长度或超量分配（10MB 显式声明，不隐式放大）。

## 9. 原子 ID 与完成定义（185 个唯一语义 ID，顺序为权威）

**ID 命名族**：`a2a_sN_*` = 场景族（18 例，对应旧稿 §6.2 S1–S15）；`a2a_tNNN_*` = 设计行族（167 例，对应旧稿 §7 T001–T242）。

| 族 | 例数 | 正 | 负 | 覆盖 |
|---|---:|---:|---:|---|
| `a2a_s*`（场景族 S1–S15） | 18 | 18 | 0 | 旧稿 §6.2 全部 HexDump 场景 |
| `a2a_t*`（设计行族） | 167 | 135 | 32 | 旧稿 §7 的报文/发现/方法/流式/状态机/事件/边界/异常/集成/字段补全 |
| **合计** | **185** | **153** | **32** | — |

`packet_count` 分布（148 例带 `packet_count` 的正例）：9 包 ×122 / 11 包 ×22 / 13 包 ×1（T164，3 task）/ 27 包 ×3（T165/T167/T168）；另 **5 例改用 `min_packets`**（T174=700 / T177=9000 / T180=40 / T181=31 / T183=14），122+22+1+3+5 = **153 正例**。

**T167 包数裁定（2026-09-28 探针实测，非推理）**：该例 `packet_count=27` **正确**，其 `notes` 自述「36 包 = 3 握手 + 10×2 + 3 挥手」**双重错误**（① 算术本身 3+20+3 = 26 ≠ 36；② 挥手是 4 包非 3 包）。实测 1/2/3/10 task 分别产 9/11/13/27 包，**公式 `3 + 2N + 4` 全中**（N=10 → 27）。该例 `frames` 钉帧 4 与帧 22 亦与 10-task 结构自洽（task k 的请求帧 = `4 + 2(k-1)` → k=1 帧 4、k=10 帧 22）。故 `packet_count` 为权威、`notes` 文本待代码阶段先跑后钉时修正。

完成定义：`tcp→a2a` 层链注册已落码；7 方法 + 4 事件 + 9 状态 + 12 错误码（-32007 除外）+ 3 Part kind 全部可观测；发现/流式/多任务/多流/v4/v6 全部有例；185 ID 正负断言与错误传播完成；不声称真实 Agent 平台处理时序与 webhook 反向连接。

**完成度现状（诚实口径）**：**文档面完成，代码面与用例面未完成**——层为空壳（§1），185 例全为违规过渡形（§12.1 / G-A2A-12）；`packet_count`/锚词等断言值本身有效但今日**不可执行**（MCP 建策略即 400）。

## 10. P1 规范矩阵（CORE_MEMORY §4 八项：规范要求→业务场景→代码现状→缺口）

### 10.1 八项规范矩阵

| # | 八项 | 规范要求 | 业务场景 | 代码现状 | 缺口 |
|---|---|---|---|---|---|
| 1 | 连接模型 | HTTP/1.1 over TCP；客户端主动建连；keep-alive 复用，最后一 task `Connection: close`（spec §3.1；旧 §6.1） | 场景①–⑧ | `DependsOn ["tcp"]` 单值（`registry.go:245`）；`connection` 派生（`layer_gen.go:105`） | 无 |
| 2 | 命令/消息表 | 7 JSON-RPC 方法 + 1 HTTP GET 端点（spec §3.1） | 场景①–⑦ | `ValidMethods` 7 项（`types.go:351`）+ `buildAgentCardRequest` | `list`/`delete`/`authenticatedExtendedCard` **明确不支持**（G-A2A-11） |
| 3 | 状态机 | 9 状态 + 转换表（spec §4） | T105–T115 | `validTaskTransitions`（`types.go:377`）逐跳校验（V10） | 无 |
| 4 | 字段表 | Agent Card/Task/Message/Part/事件/PushConfig 全字段（spec §2/§5） | 数据场景层 | `types.go:23-296` 全量 + V1–V16 校验 | `signatures` 保留不生成 |
| 5 | 错误处理 | 12 错误码（spec §3.4） | T187–T198 | `validCodes` 12 值（`a2a.go:264-273`） | 无（锚词已钉死） |
| 6 | 超时与活性 | HTTP keep-alive；无协议级保活/重试报文 | 场景⑦ | `connection` 头派生；TCP 层能力 | **显式不适用**（A2A 无 ping/keepalive 报文） |
| 7 | NAT/代理/被动 | 无被动模式；webhook 是反向连接 | 场景⑤ | **webhook 不生成**（链单向） | G-A2A-5（明确不解决） |
| 8 | 版本/方言 | v0.2.2 目标；v0.2.5/v0.3.0/v1.0 差异面 | S1/T212a | `protocolVersion` 字段 + `agentCardPath` 可覆盖 | `agent-card.json`/`A2A-Version`/分页 **明确不支持**（G-A2A-11） |

### 10.2 子表①：方法 × 响应终态矩阵（逐格已覆/立项/不适用）

适配声明：A2A 是请求-响应协议，"响应终态"= 同步 JSON 响应 / SSE 流 / 错误响应三类。

| 方法 | T1 同步 JSON 响应 | T2 SSE 流响应 | T3 错误响应 |
|---|---|---|---|
| `message/send` | 已覆（S2/T035/T036） | 不适用（非流式方法） | 已覆（T187/T188/T190 代表例） |
| `message/stream` | 不适用（流式方法） | 已覆（S3/S10/T205） | 已覆（T050 代表例） |
| `tasks/get` | 已覆（S4/T060/T057） | 不适用 | 已覆（T059 负例 V8） |
| `tasks/cancel` | 已覆（S5/T071/T072） | 不适用 | 已覆（T066/T068/T067） |
| `tasks/resubscribe` | 不适用 | 已覆（S6/T078/T207/T080） | 已覆（T075/T076/T077） |
| `tasks/pushNotificationConfig/set` | 已覆（S7/T231） | 不适用 | 已覆（T085/T087/T088） |
| `tasks/pushNotificationConfig/get` | 已覆（T089） | 不适用 | 已覆（T091/T092） |
| `GET` Agent Card | 已覆（S1/T014/T204） | 不适用 | 已覆（T021 404 / T234 复数路径） |

**逐格重数**：8 行 × 3 列 = 24 格——已覆 18 / 不适用 6，零空格。**注**：旧稿 T 号 `T013`/`T033`/`T058`/`T061`/`T192`/`T194`/`T195`/`T232` **无存量例**（G-A2A-9 的 87 条设计行缺口之一）；本表所列 ID 均为**存量实际存在**的用例（机读核过），缺口号不冒充覆盖。

### 10.3 子表②：数据形态变体表（协议相关全部形态逐项）

共 **26 行**，每行均有正例/负例落点或立项/不适用结论：

| # | 变体 | 落点 |
|---:|---|---|
| 1 | JSON-RPC id = string | 覆（T003/T179） |
| 2 | JSON-RPC id = integer | 覆（T003 族） |
| 3 | JSON-RPC id 缺（null） | 覆（T004 负例：V8 拒） |
| 4 | Part kind=text | 覆（T147/T222） |
| 5 | Part kind=data | 覆（T148/T223） |
| 6 | Part kind=file + bytes | 覆（T149/T224） |
| 7 | Part kind=file + uri | 覆（T030） |
| 8 | Part kind=data-stream（非法） | 覆（T040/T203/T236 负例） |
| 9 | Part kind=file-stream（非法） | 覆（T054/T237 负例） |
| 10 | Part 互斥三向违例 | 覆（T225/T226/T227 负例） |
| 11 | Message.role=user | 覆（T139） |
| 12 | Message.role=agent | 覆（T140） |
| 13 | Message.role=system（非法） | 覆（T038 负例） |
| 14 | Message.parts 空 | 覆（T039/T053 负例） |
| 15 | SSE 未命名事件（无 `event:`） | 覆（T005/T240） |
| 16 | SSE 多行 data 拼接 | 覆（T007） |
| 17 | SSE 事件边界 `\n\n` | 覆（T006） |
| 18 | SSE 4 kind 逐值 | 覆（T043/T044/T124/T131） |
| 19 | SSE 中间事件 0 个 | 覆（T186） |
| 20 | SSE 末事件 final=true | 覆（T132/T133） |
| 21 | SSE 末事件 final=false（非法） | 覆（T133 正例中间事件；末事件违例 → A′ 补例） |
| 22 | 9 状态逐值 | 覆（T105–T115 全 9 值，机读计数见 §4） |
| 23 | 12 错误码逐值 | 覆 11/12（T187–T198 覆盖 -32700…-32006；**-32007 零例** = v2 路线图不实现） |
| 24 | 长度边界（128/1024/4096/1MB/10MB） | 覆（T174–T183） |
| 25 | 6 认证写法 | 覆（T096–T098/T012/T103） |
| 26 | IPv6 载体 | 覆（T-S6 族） |

24 覆 + 1 立项 + 1 不适用（HTTP keep-alive 无报文级变体）= 26。✓

### 10.4 子表③：商业行为→用例映射表

| # | 商业行为（出处） | 用例映射 | 结论 |
|---:|---|---|---|
| 1 | Agent 能力发现（spec §5.3 well-known） | S1/T013/T204 | 已覆 |
| 2 | 同步对话（`message/send`） | S2/T025–T036 | 已覆 |
| 3 | 流式对话（SSE） | S3/S10/T041–T049 | 已覆 |
| 4 | 任务轮询（`tasks/get`） | S4/T055–T064 | 已覆 |
| 5 | 任务取消（`tasks/cancel`） | S5/T065–T072 | 已覆 |
| 6 | 断线重连（`tasks/resubscribe`） | S6/T073–T080 | 已覆 |
| 7 | 推送通知配置 | S7/T081–T092 | 已覆 |
| 8 | 认证（6 写法） | S8/S8b/S8c/T096–T104 | 已覆 |
| 9 | 多任务/多会话并发 | S9/T161–T172 | 已覆 |
| 10 | **webhook 反向通知**（Agent → 客户端） | — | **明确不解决**（G-A2A-5：链单向，无反向 flow 承载） |
| 11 | 真实 Agent 平台处理时序 | — | 待确认（G-A2A-4：查官方文档或抓现网包，二选一） |
| 12 | v0.3.0+ 扩展（list/delete/扩展卡片/分页） | — | **明确不解决**（G-A2A-11，v2 路线图） |

9 覆 + 2 不适用 + 1 待确认 = 12。✓无映射无确认即缺口——本表零缺口。

### 10.5 三路对照与候选方案对比（§4.12–4.15 / §4.17）

三路：①**规范原文**（A2A spec v0.2.2，定"必须是什么"：7 方法名/`agent.json` 路径/3 Part kind/未命名 SSE 事件/9 状态/12 错误码）；②**商业化软件实际行为**（真实 Agent 平台行为——**未达验证级**，G-A2A-4 待确认；间接证据 = `a2a-python` SDK 默认卡片路径 `agent-card.json`，与 v0.2.2 spec 的 `agent.json` 不一致 → 按 §4.15 以 spec 为底线保留 v0.2.x 默认，路径可用 `agentCardPath` 覆盖）；③**可靠开源实现思路**（本仓库同族先例：`tds`/`dnp3` 的"tcp 终结层 + 事件流 + Payload 直传"、`moxa` 的"层内化 + FieldContract"，只借鉴思路）。三路一致点：HTTP/JSON-RPC over TCP + 单连接多 task 串行 + SSE 流式。不一致点 = 默认卡片路径（取舍见上）。

| 方案 | 走法（借鉴来源） | 取舍 | 结论 |
|---|---|---|---|
| A | 独立 `a2a` 终结层 + `spec.Payload` 携带 A2AConfig（本版；tds/dnp3 同构先例） | 7 方法/SSE/9 状态/32 负例全可声明可断言；代价 = 一个终结层 + Payload 通道（已落码 5741 行） | **采用** |
| B | 复用 `http` 层 + 顶层 payload 注入 JSON-RPC 字节 | 无 JSON-RPC 信封校验、无状态机、无 SSE 事件序 → 185 例中的 32 负例与全部 SSE 例不可表达 | **否决** |
| C | 与 `jsonrpc` 共用层（把 a2a 当 jsonrpc 方言） | a2a 有 Agent Card 发现（HTTP GET，非 JSON-RPC）+ SSE 流 + 9 状态机，jsonrpc 层无这些语义 | **否决** |
| D | 层内化（`Fields` 补全，配置住 `layers[].a2a`）——**目标形状** | 层链是唯一配置真相（§1）；代价 = 需补 registry `Fields` + translate 分支（G-A2A-1） | **目标（P4 落码）** |

## 11. P2 D-A2A-1 代码设计（CORE_MEMORY §8 八要素；门1 获批 = 定稿）

> 状态说明：实现已落码（`internal/protocol/a2a/` 八文件），本 P2 条目为 P-PIPE 文档轨对既有实现的**逆向定稿**（as-built 定稿），供门1 批准后作为后续改动的唯一入口；P4 在本协议内为"层内化"（§14），不另开新层。

### 11.1 文件清单（实测，非计划）

| 文件 | 职责 | 行数 |
|---|---|---:|
| `trafficgen/internal/protocol/a2a/types.go` | `A2AConfig` 全类型树（Agent Card/Task/Message/Part/事件/PushConfig）+ 常量 + `ValidMethods`/`ValidTaskStates`/`validTaskTransitions`/`StreamingMethods`/`SyncMethods` | 417 |
| `trafficgen/internal/protocol/a2a/a2a.go` | `Planner.Validate`（V1–V16 + 载体 + 长度）+ `Planner.Plan`（legacy 包序列）+ 报文构造函数（`buildA2ARequest`/`buildHTTPResponse`/`buildSSEResponse`/`segmentByMSS`…） | 1307 |
| `trafficgen/internal/protocol/a2a/builder.go` | 独立可测的报文构造器（`BuildJSONRPCRequest`/`BuildSSEStream`/`BuildAgentCard`…21 个导出函数） | 296 |
| `trafficgen/internal/protocol/a2a/layer_gen.go` | 终结层生成器（`RegisterLayerGenerator("a2a")` + `RegisterLayerValidator("a2a")`，`init()`）+ `Generate` 逐 task 事件 emit + `spec.TCP` 校准 | 247 |
| `trafficgen/internal/protocol/a2a/parser.go` | 报文解析辅助 | 205 |
| `trafficgen/internal/protocol/a2a/a2a_test.go` | 77 个 `Test*` | 2611 |
| `trafficgen/internal/protocol/a2a/layer_gen_test.go` | 16 个 `Test*` | 594 |
| `trafficgen/internal/protocol/a2a/review_probe_test.go` | 2 个 `Test*`（复审探针） | 64 |
| 接线 5 处 | registry 注册（`layers/registry.go:245`）/ Payload 搬运（`strategy_convert.go:1633` `case "a2a"`）/ `FlowMeta.Payload` 直传（`chain_planner_translate.go:48`）/ protocols 准入（`protocols.go:22`）/ main 注册（`cmd/server/main.go:20` 空导入 + `:630` ChainPlanner） | — |

### 11.2 接口签名

- `Validate(spec core.FlowSpec) error`（`a2a.go:29`）：IP 字面 → MSS ≥536 → Payload JSON 解码 → 逐 task 规则 V1/V2/V4/V5/V7/V8/V9/V10/V11/V12/V16 → AgentCard 规则 V6/V12 → 长度约束。错误文案与 §7 锚词逐字一致。
- `Plan(ctx, spec) (<-chan core.PacketConfig, error)`（`a2a.go:422`）：先 `Validate`；legacy 包序列（握手 → Discover → 逐 task 请求/响应 → 挥手，含独立 ACK 与 3 包挥手）。
- 生成器：`Name() "a2a"`（`layer_gen.go:40`）；`Generate(ctx, req)` 逐 task emit `MessageEvent{Up, Bytes}`（`:53`）；`GenEvents()` 事件生产者标记（`:198`）；`EmitEvent` 未接线显式错（`:203`，防误调）。
- `RegisterLayerValidator("a2a", ...)`（`layer_gen.go:211`）：跑 `Planner.Validate` + 把 `cfg.TCP` 的 `MSS`/`InitialSeq`/`Handshake`/`Termination` 校准进 `spec.TCP`（nil = 未设置 = 默认 true，必须写进 `spec.TCP` 否则 tcp 层读到零值 false 会跳过握手/挥手）。

### 11.3 数据结构

`A2AConfig{BaseURL, AgentCardPath, Discover, AgentCard, Tasks[], Auth, HTTP, TCP, FlowControl}`（`types.go:23-33` 全量，无新增）；`A2ATask{Method, RequestID, Message, Configuration, ParamsMetadata, TaskID, HistoryLength, PushNotificationConfig, Response, Streaming, SSEEvents}`（`:144`）；`A2APart{Kind, Text, Data, File, Metadata}`（`types.go:201`）。

### 11.4 主流程

配置 → validator（V1–V16 十六组规则 + 载体 2 分支 + 生成器 2 守卫）→ 生成器（逐 task 事件：请求字节 + 响应字节；Discover 时先 GET + 200）→ tcp 层生成器（握手 / MSS 分段 / seq-ack / 挥手）→ ip 层 → writer（PCAP/NIC）。

### 11.5 错误分支

§7 表 32 条负例覆盖的规则族全部为 validator 同步拒绝（`Planner.Validate`），生成器另有两道守卫（`no tasks configured` / `no config`）防"空连接假成功"。全部传 task error（零假成功）。

### 11.6 性能边界

见 §6（逐 task 流式、per-flow 局部状态、无跨流共享、无锁；吞吐数字待 P4 基准）。

### 11.7 与现有逻辑的冲突点

- **`CheckProtoFlat` 无 a2a 分支**（`grep -c 'protocol == "a2a"'` = 0 实测）：顶层 `a2a` 子映射 presence 今日**不判死**——属缺口 G-A2A-1 后半（禁加单协议黑名单分支，等框架级 unknown-key 白名单；kingbase/moxa 记忆裁定）。
- **registry `a2a` `Fields` 为空**（生成表 `fields: {}` 实测）+ `translateTerminalConfig` 无 `case "a2a"` → 层内任何键今日 `unknown field`（`complete.go:293`），目标形状（§2）需 P4 补 `Fields` + translate 分支（G-A2A-1）。
- **端口无 `FieldContract`**：缺省落通用 80（G-A2A-2）；存量用例显式 8080 不受影响。
- **动态 allowlist**（`internal/core/layer_dyn.go:17-21`）：`ip`/`tcp`/`udp`/`eth` 四层开；**a2a 零命中** → 层内业务字段动态对象即拒（G-A2A-7）。见 §12.12。
- **Payload 双入口**：`strategy_convert.go:1633`（flat 顶层 `a2a` → `spec.Payload`）与 `chain_planner_translate.go:48`（`spec.Payload` → `FlowMeta.Payload`）今日分工明确；P4 补层内分支后需"层优先、Payload 已存在则不覆盖"守卫（tds `chain_planner_translate.go:3029` 同款）。

### 11.8 回滚方式

本协议文件独立成包，回滚 = revert 本协议 8 文件 + 接线 5 处（registry/convert/translate/protocols/main）；不触及其他协议。**cases 无需回滚**（本版 `cases/a2a.json` 保持原样；改写版存 `/tmp/pipe/a2a-layerchain-rewrite.patch`，代码阶段套用后若需回退，`git checkout` 该文件即可）。

## 12. 门1 §1–§14 十四行对照表（CORE_MEMORY §15.1–15.3）

| § | 本协议怎么满足 | 证据 |
|---|---|---|
| §1 层链唯一真相 | 见 §12.1 强制展开：存量 185/185 顶层 = `layers + src_ip/dst_ip/src_port/dst_port + count + a2a`（**违规过渡形，本版保持原样、改写版存 patch**，顶层残留 1081 处）；层为空壳（§1 三条实测），合规形需代码阶段补 G-A2A-1 三项；目标形状见 §2 样例（今日跑不通）；presence 判死缺口 G-A2A-1 后半 | §12.1 + §1；`cases/a2a.json` 机读实测 |
| §2 策略/任务 | 策略 = 单 a2a 流量模板（`tasks[]` 有序事务序列），自带 `flow_control`；任务 = 多策略合跑 + 总量封顶；框架语义未动 | 设计 §2 样例 |
| §3 五件套 | 见 §12.3 强制展开：会话表/事务序列/关联（webhook 反向连接诚实声明不解决）/插入位置（终结层）/时间线。有长连接，不豁免 | §12.3 + §5 |
| §4 查规范 | spec v0.2.2（主）+ v0.2.5/v0.3.0/v1.0 差异面 + JSON-RPC 2.0 + RFC 8615/7235 + a2a-python SDK 间接证据 + tshark 实测（`a2a.*`=0）；八项矩阵 + 子表①②③ | §10 |
| §5 依赖与错误 | `DependsOn ["tcp"]` 单值（`registry.go:245`）；V1–V16 + 载体 + 生成器 2 守卫；失败传 task error | §5/§7/§11.5 |
| §6 性能 | 见 §6（6.1–6.8 要素齐；吞吐数字标待 P4 基准，不写承诺） | §6 |
| §7 三份文档 | `93-a2a-{design,testcase}.md` v1.0.0 + D-A2A-1（§11，门1 获批 = 定稿）+ T-A2A（testcase §2，185 ID）+ 旧稿 17-* 为历史层 | 修订记录 |
| §8 设计先行 | P1–P3 先于 P4 层内化；门1 获批 = D-A2A-1 定稿 = 开工门 | 提交序 |
| §9 测试三源 | 三源 = spec v0.2.2（§10）+ D-A2A-1（§11）+ a2a-python SDK/tshark 实测（替代"已确认现网行为"档，未到抓包级 → G-A2A-4，不冒充第三源）；185 ID 逐项回指；存量审计去向 testcase §8 | `93-a2a-testcase.md` §2/§5/§8 |
| §10 评审闭环 | 每阶段对抗自重审（结论见本车道报告 §2）+ 收官隔离复审；红先绿后 | 自审记录 |
| §11 白话 | 每阶段白话一句先行（见本文首节） | 汇报 |
| §12 动态清单 | 见 §12.12 强制展开：四元组全开（allowlist 实测）；业务字段逐个列开/不开 + 理由；序号算法实读行号 | §12.12 |
| §13 schema 派生 | `a2a` 已在 `registry.go:245` 注册（**不新增层**）；`allowedProtocols["a2a"]=true`（`protocols.go:22`）；Payload 已直传；**P4 补 registry `Fields` 必须重跑 schemagen** | §11.1 |
| §14 真实流程 | suite 经 MCP 建策略建任务 → 引擎真实生成 → tshark `http.*`/`json.*`/frames 三通道 → 先跑后钉；pcap 落 `/tmp/mcp-pcaps/a2a/`。**今日存量 185 例经 MCP 建策略即 400**（§12.1 堵点 3），真实流程待 G-A2A-1 落码后方可执行 | testcase §7 |

### 12.1 §1 强制展开：旧键去向 + 缺口登记（本协议**用例未改**，裁定依据）

**本版口径（2026-09-28）**：本版 `cases/a2a.json` **保持原样**（层空壳，合规化属代码阶段）。**车道已产出完整层链改写版**——185/185 全量改写完成、质量经主线程 `git show` 逐项复核（顶层残留 914 → 0、顶层键集只剩 `['layers']`、expect/summary/notes/strategy_fc 保真），存于 `/tmp/pipe/a2a-layerchain-rewrite.patch`（主线程另存 `/tmp/pipe/patches/a2a-layerchain.json`），**待代码阶段套用**。

之所以本版不落地：a2a 层是**空壳**（§1 三条实测）——层内配置无处可住（`unknown field`），仍带顶层旧键则经 MCP 建策略 400，故合规层链形**必须先补代码**（G-A2A-1）方可落地。本节只登记去向与缺口，不声称已迁移。

**存量实测（逐例机读，2026-09-28）**：

| 文件 | 例数 | 顶层键分布 | 链形 | 负例 expect 纯净 |
|---|---|---|---|---|
| `cases/a2a.json` | 185 | `{layers, src_ip, dst_ip, src_port, dst_port, count, a2a}` ×151 + 同形无 `layers` ×7 + `{layers, src_ip, dst_ip, dst_port, a2a}` ×2（T165/T168 带 `strategy_fc`）+ `{src_ip, dst_ip, src_port, dst_port, a2a}` ×25 | 空壳 `[tcp,a2a]` ×153 / 无 layers ×32 | ✅ 32/32 只有 `{expect_error,error_contains,notes}` |

**顶层残留计数**：`src_ip` 185 / `dst_ip` 185 / `dst_port` 185 / `src_port` 183 / `count` 158 / 顶层 `a2a` 子映射 185 = **合计 1081 处**（非负例 914 处 + 负例 167 处）。

**旧键去向表（§15.3 要求"每个键写去向"）**：

| 旧键 | 出现例数 | 去向（代码阶段落地后执行） | 今日状态 |
|---|---:|---|---|
| `src_ip` | **185** | 迁 `layers[0].ip.src` | **未迁**（保留顶层） |
| `dst_ip` | **185** | 迁 `layers[0].ip.dst` | **未迁** |
| `src_port` | **183** | 迁 `layers[1].tcp.src_port`（2 例 T165/T168 无 `src_port`，走 worker 保底递增） | **未迁** |
| `dst_port` | **185** | 迁 `layers[1].tcp.dst_port`（值 8080 保留） | **未迁** |
| `count` | **158** | 删除（值恒 1；数量走 `flow_control`） | **未迁** |
| 顶层 `a2a` 子映射 | **185** | 迁 `layers[2].a2a`（**前置 = G-A2A-1 三项全落**） | **未迁**（唯一有效通道） |
| `strategy_fc`（顶层 Case 字段） | 2 | 保留（`pcaptest.Case.StrategyFC`；可转 spec 内 `flow_control`） | 保留 |

**为什么现在改不动（三重堵死，逐条有证据）**：

| # | 堵点 | 证据 | 后果 |
|---|---|---|---|
| 1 | 层内键无处可住 | `registry.go:245` 无 `Fields` → `complete.go:293` 报 `unknown field` | 目标形状（层内 a2a 配置）被拒 |
| 2 | 层内配置不被解码 | `chain_planner_translate.go:852` `if len(s.Fields)==0 { return }` **在 switch 之前** + 无 `case "a2a"` | 即使绕过 ①，层内配置也被静默丢弃 |
| 3 | 顶层旧键经 MCP 即 400 | `schema/semantic.go:130` 无条件 `CheckProtoFlat` → 顶层四元组/count 任一出现即拒 | 存量 185 例**今日既非绿也非红，而是跑不起来**（MCP 路径） |

**注**：离线套件（`layer_chain_suite_test.go:225-231`）剥离 `layers` 后把顶层扁平键直传 `MapToFlowSpec`，**绕过 `CheckProtoFlat`**——故存量例在离线套件里是绿的、在 MCP 里是 400 的。两种口径都不是合规层链形。

**结论**：本协议**用例侧迁移量为 185 例全额待办**（非 0）。迁移前置 = G-A2A-1 三项（registry `Fields` + translate `case` + `mapToFlowSpec` 收敛/presence 判死）+ G-A2A-2（`FieldContract`）。目标形状样例见 §2（顶层仅 `layers` + `flow_control`），**今日跑不通**（§1.9 口径）。

### 12-P2 判死负例形状（链级红例必含清单①③④）

- ① presence 形状 `{"layers":[…],"a2a":{}}` 今日**不会被拒**（`CheckProtoFlat` 无 a2a 分支，`grep -c` = 0 实测）→ **P4 建该负例前须先补判死分支**（moxa G-MOXA-2 同款纪律：先实测再建例，建了会真绿 = 假通过）→ 缺口 G-A2A-1 后半登记。② 白名单外游离键判死（`unknown field`）P4 建一条（A′）。③ 32 负例每条带锚词（已齐，§7）。④ 收官自查「非负例顶层键 = 0」——**今日红**（非负例顶层残留 **914 处**，全量 1081 处）；**不得作为「今日已过」申报**，待 G-A2A-1 落码 + 185 例改写后方可转绿。

### 12.3 §3 强制展开：五件套

**会话表**：`s1` 单连接单 task 基线（S2/S3/S5/S6/S7，各自四元组，SYN→请求→响应→FIN 四包挥手）/ `s2` 发现+对话会话（S1/T204，GET 卡片 → POST 消息）/ `s3` 多 task 串行会话（T208 两 task；T167 十 task）/ `s4` 多流三会话（T165/T168，`flows=3`，`src_port` 保底 12345/12346/12347）。**注**：`a2a_t164_multi_flow_count3` 的 ID 名与语义不符（实为 3 task 串行），语义以本表为准。

**事务序列**（每事务四件事）：

| # | 事务 | 前置条件 | 触发动作 | 成功分支 | 失败分支 |
|---|---|---|---|---|---|
| t1 | Agent Card 发现 | 无（`discover=true`） | `GET {agentCardPath}` | 200 + Agent Card JSON → t2 | 404/错误（T021/T234 负例） |
| t2 | 发消息（同步） | t1 可选；`message/send` + `message` 必填 | `POST` JSON-RPC 请求 | result=Task/Message → t3/t4 | -32600/-32602（T037–T040 负例） |
| t3 | 发消息（流式） | `message/stream` + `streaming=true` | `POST` + `Accept: text/event-stream` | SSE 4 类事件 → `final:true` → 流关闭 | -32004（T050 负例） |
| t4 | 查任务 | `tasks/get` + `taskId` | `POST` JSON-RPC | result=Task（含 history/artifacts） | -32001（T058/T192 负例） |
| t5 | 取消任务 | `tasks/cancel` + 非终态 `taskId` | `POST` JSON-RPC | result.status.state=canceled | -32002 终态不可取消（T066/T193 负例） |
| t6 | 断线重连 | `tasks/resubscribe` + `taskId` | `POST` + `Accept: text/event-stream` | SSE 续传后续事件 | -32004/-32001（T075/T077 负例） |
| t7 | 推送配置 | `tasks/pushNotificationConfig/{set,get}` | `POST` JSON-RPC | result=`TaskPushNotificationConfig` | -32003（T085/T194 负例） |

**关联关系**：**无 `driven_by` 派生流**（诚实声明：A2A 的 task 全部住同一 TCP 连接，无控制/数据流分离；唯一的多流关联场景 = webhook 反向连接，**本版不生成**——G-A2A-5，理由：链单向发起，反向连接需第二个 flow 且方向相反，`driven_by` 关联字段今日无处可住）。**会话关联靠 `contextId`**（非 `sessionId`）：同 `contextId` 的多 Task 与 Message 属同一上下文（T162/T163 正例：2 Task 共享/区分 contextId）。

**插入位置**：终结层（`[ip,tcp,a2a]`，无中间层）。**不采用** `[ip,tcp,http,a2a]`——`http` 是终结层且无层依赖它，`complete.go` 会拒绝该链（#52 报告 R2 已逐行复核）。

**时间线**：连接内严格串行（HTTP/1.1 无流水线，task-2 请求在 task-1 响应后，T208 断言）；多流顺序展开（`flows=N` 整块 per-flow，跨流不假设全局包序，今日只断言总包数 `directional`；端口聚合断言为 A′ 候选）；无交错（A2A 无 `concurrent` 路径）。

### 12.12 §12 强制展开：动态字段清单与序号算法

**四元组 `ip.src/dst`、`tcp.src_port/dst_port` 五策略全开**（allowlist `internal/core/layer_dyn.go:17-21` 实测：`ip`/`tcp`/`udp`/`eth` 四行）；保底 `DefaultSrcPort+i`（`worker.go:308`；`DefaultSrcPort=12345`，`strategy_convert.go:49`）；dst 动态与 8080 显式共存（显式值非零即不触发缺省补齐）。

**业务字段 5 项全关**（allowlist 无 `a2a` 行，`grep` 零命中实测；对象即拒 `does not support dynamic`）：

| 业务字段 | 开/不开 | 理由 |
|---|---|---|
| `tasks[]`（会话剧本） | **不开** | 剧本整体是结构数组，逐流变体需整本替换；`flows=N` 已由四元组区分流身份 |
| `requestId`（JSON-RPC 信封 id） | **不开** | 现有做法是用例内静态写死（`req-001`/`req-t205`…），逐流变体需求未出现 |
| `message.messageId` / `contextId` | **不开** | 同上（`m-001`/`ctx-abc` 静态） |
| `response.result`（Task 对象快照） | **不开** | 是响应剧本，不是请求参数；逐流变体等于换剧本 |
| `auth.token` / `baseUrl` / `agentCardPath` | **不开** | 会话级标量，逐流变体无现网需求 |

序号算法实读：`parseLayerDyn`（`layer_dyn.go:78`）/ `layerDynAllowlist`（`layer_dyn.go:17`）/ `TupleGenerator.Next`（`tuple_generator.go:26`）/ 保底自增（`worker.go:308` + `strategy_convert.go:49`）——**`a2a` 无块**（grep 实测零命中），即层内任何业务对象值 → `does not support dynamic`（G-A2A-7）。

## 13. P3 对接清单（T-A2A 草稿输入；正文落 testcase 文件）

185 ID（153 正 + 32 负）+ `packet_count`/`min_packets`/锚词 + fixture 常量 + 双通道断言基线 + 存量审计（testcase §2–§5/§8 全量）。

**前置（硬门）**：G-A2A-1 三项落码前，本协议**无法产生任何合规层链用例**（§12.1 三重堵死）；下列 A′ 例全部挂在代码阶段。

**A′ 候选补例**（P4 落码后补，今日不冒充覆盖）：

| # | 候选 ID | 内容 | 依赖 |
|---:|---|---|---|
| 1 | `a2a_neg_top_a2a_presence_reject` | 层链 + 顶层空 `a2a` 子映射并存 = 判死负例（§12-P2 ①） | G-A2A-1 后半（`CheckProtoFlat` 分支） |
| 2 | `a2a_neg_stray_src_ip` | 白名单外游离顶层键（`layers` + `src_ip`）判死 | 同上（已由通用 `src_ip` 分支覆盖） |
| 3 | `a2a_default_port` | 删 `tcp.dst_port` 不设断言值，只断言 FieldContract 补齐行为 | G-A2A-2（`FieldContract`） |
| 4 | `a2a_neg_mixed_family` | 异族地址混写拒绝 | 通用链级异族检查 |
| 5 | `a2a_tcp_config_layer` | `tcp` 层 `mss`/`handshake`/`termination` 经 `cfg.TCP` 校准生效（`layer_gen.go:211`） | G-A2A-1（层内化后 `cfg.TCP` 才有住处） |
| 6 | `a2a_http_config_layer` | `http` 层 `userAgent`/`accept`/`connection`/`extraHeaders` 生效 | 同上 |
| 7 | `a2a_abort_rst` | `tcp.rst` 非正常中断（§3.15②后半） | 框架 tcp 层能力（本层零断言） |
| 8 | `a2a_sse_last_final_false` | SSE 末事件 `final=false` 拒绝（变体 21） | 现有 V9 分支（今日无例） |

## 14. 缺口立项清单（有缺口写「缺口立项」，不许空着）

| 缺口 | 内容 | 去向 |
|---|---|---|
| G-A2A-1 | **层为空壳（本协议头号缺口，挡用例改写）**：① `registry.go:245` 无 `Fields`；② `chain_planner_translate.go:852` `if len(s.Fields)==0 { return }` **在 switch 之前** + 无 `case "a2a"` → 层内配置**根本不被解码**；③ `complete.go:293` 层内任何键报 `unknown field`；④ `CheckProtoFlat` 无 a2a 分支 → 顶层 `a2a` presence 今日不判死。**后果：185 例全为违规过渡形且经 MCP 建策略即 400**（§12.1） | 代码阶段首动作，**三项同批**：补 `Fields` + 补 `case "a2a"`（层内→`spec.Payload`，层优先/已存在不覆盖）+ `mapToFlowSpec` 顶层 `a2a` 兼容支收敛 + presence 判死 + schemagen 重跑；**禁加单协议黑名单分支**（等框架级 unknown-key 白名单）。落地后 185 例方可改写 |
| G-A2A-2 | 端口契约缺失（无 `FieldContract`）→ 缺省落通用 80；fixture 8080 只是用例值 | P4 与 G-A2A-1 同批；端口值待主线程批准 |
| G-A2A-3 | V3/V13/V14/V15 设计行已声明、代码未实装（`grep` 实测 `a2a.go` 只有 V1/V2/V4–V12/V16） | **裁决（2026-09-28）：保留设计行，登记为代码阶段实装，不删条**——CORE_MEMORY §1「设计是契约、代码向契约看齐」，删设计行 = 降档，禁止。代码阶段按设计行补实装 |
| G-A2A-4 | 商业平台基线未确认（真实 Agent 平台现网行为） | 待确认：查官方文档对应章节，或抓现网 Agent 包（三选一已写清）；确认前不写死进实现 |
| G-A2A-5 | webhook 反向连接流未生成（T151–T159 设计行无落点） | **明确不解决**（链单向；迁入计划 = 若未来需多向链则随框架 `driven_by` 扩展一并落） |
| G-A2A-6 | 同 flow 内 `sessions[]` 显式声明缺失（多会话语义由 `flows` 承载） | **明确不解决**（现状够用，不扩展；设计 §5 已声明） |
| G-A2A-7 | 业务字段动态全关（allowlist 无 `a2a` 行） | A′ 候选，不冒充已覆盖（§9.36 口径）；逐字段理由见 §12.12 |
| G-A2A-8 | `coverage_gate.py` 未登记 a2a | 主线程合并时补（车道不碰共享文件） |
| G-A2A-9 | 覆盖缺口：旧稿 §7 的 246 条设计行中 87 条无存量例 | P4 casegen 并入 + 全量重跑；A′ 清单见 §13 |
| G-A2A-10 | 真中断/无终态收尾（FIN/RST mid-task、SSE 无终态事件） | A′ 补例 `a2a_abort_rst` + `a2a_sse_last_final_false`（§13） |
| G-A2A-11 | v0.3.0+/v1.0 扩展（list/delete/扩展卡片/`agent-card.json`/`A2A-Version`/分页） | **明确不支持**（v2 路线图；`ValidMethods` 拒绝） |
| G-A2A-12 | **用例侧迁移全额待办**：185 例顶层残留 1081 处（非负例 914 处）未迁；本车道按裁定**不改 JSON** | 与 G-A2A-1 同批（代码落码后改写 185 例 + 补 A′ 例）；收官自查行「非负例顶层键 = 0」**今日红，不得申报已过** |

## 15. 修订记录

- v1.0.0（2026-09-28）：P-PIPE #93 文档轨 P1–P3。续号重做：17→93 沿革与 9 项状态校正（§0）；存量 185 例机读审计（顶层残留 1081 处 / 非负例 914 处）；**§1 层为空壳三条实测 + 合规形需代码阶段补三件**；§12.1 改为缺口登记（含三重堵死证据表）+ §12.3/§12.12 强制展开 + 12-P2；D-A2A-1 as-built 定稿（§11）；缺口 G-A2A-1…G-A2A-12。
- **改写成果与落地时点（同日）**：车道已完成 `cases/a2a.json` **185/185 全量层链改写**（顶层残留 914 → 0，顶层键集只剩 `['layers']`），经主线程 `git show` 复核确认完整正确。因 a2a 层为空壳（§1），合规化属代码阶段，**本版 JSON 保持原样**；改写版存 `/tmp/pipe/a2a-layerchain-rewrite.patch` 与 `/tmp/pipe/patches/a2a-layerchain.json`（同内容，主线程亦存一份），**待 G-A2A-1 落码后套用**。文档本版取缺口登记口径。
