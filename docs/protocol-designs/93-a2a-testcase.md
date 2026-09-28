# #93 a2a（Agent2Agent，Agent 间互操作协议）测试用例契约

> 版本：v1.0.0（P-PIPE 文档轨 P1–P3）
> 日期：2026-09-28
> 配套设计：`docs/protocol-designs/93-a2a-design.md` v1.0.0（D-A2A-1）
> 旧基线：`docs/protocol-designs/17-a2a-design.md` v2.0.3 §7（246 条设计行台账）+ `/tmp/pipe/52-a2a/p123-report.md`（#52 门1 十四行 + 11 项缺口）
> 机器契约：`trafficgen/test/protocol_pcap/cases/a2a.json`（185/185 ID 与本版 §2 一致，顺序一致；**本版保持原样**（改写版已产出存 patch，见 §9）——存量全为违规过渡形，顶层残留 1081 处，落地须先补代码，见 §8 缺口登记）
> 白话一句：**一百八十五条检查：一百五十三条看正常说话（发现、发消息、收流、查任务、取消、重连、设推送、认证、多任务、大载荷），三十二条看胡来能不能被拦下；每条只查一件事。**

## 1. 测试原则和形状基线

用例从设计 §3–§9 逐项派生，共 **185 个唯一语义 ID：153 正 + 32 负**（继承存量计数）。派生规则：设计 §3 每个报文条款、§5 每个状态/转换、§7 每行错误处理在本文有对应断言；断言不得超出设计声明范围。**一个用例只验证一个协议行为**。

**形状基线（2026-09-28 机读实测，存量原样）**：185/185 例顶层键 = `{expect,id,proto,spec_json,summary}`（+`strategy_fc` ×2，T165/T168）；`spec_json` 顶层键 = `{layers, src_ip, dst_ip, src_port, dst_port, count, a2a}` ×151 + 同形无 `layers` ×7 + `{layers, src_ip, dst_ip, dst_port, a2a}` ×2（T165/T168）+ `{src_ip, dst_ip, src_port, dst_port, a2a}` ×25；153 例的 `layers` 恒为空壳 `[{tcp:{}},{a2a:{}}]`（两层 config 均 `{}`，真实配置住顶层 `a2a` 子映射）；148 正例 `expect` 含 `packet_count` + 5 例用 `min_packets`（T174/T177/T180/T181/T183）= 153 正例；32 负例 `expect` 键集合**严格为** `{expect_error, error_contains, notes}`（机器契约两键纯净）。

**⚠ 存量形状全为违规过渡形（不得作为范本照抄）**：`layers` 与顶层四元组/`count` 混用 = §1.4/§1.11 判死；且经链路实读，**该形状今日经 MCP 建策略即 400**（`schema/semantic.go:130` 无条件 `CheckProtoFlat`）。故存量 185 例**今日既非绿也非红，而是跑不起来**（离线套件剥离 `layers` 后绕过该检查，故离线绿、MCP 红）。合规层链形**改不动**——a2a 层是空壳（`registry.go:245` 无 `Fields`；`chain_planner_translate.go:852` 空 `Fields` 提前 return 使层内配置**根本不被解码**），改写前置 = 代码阶段补三项（§8.2）。

**输出契约（pcap/NIC 双输出）**：两路径共用同一 cases JSON 与断言集（`tcp.srcport/dstport`、`tcp.flags/len`、`http.content_type`、frames offset 54/74 原始字节）；NIC 经 tcpdump 捕获（`nic_capture` 用例级开关）；不设仅单路径可用的断言。

**TSHARK 基线**：本机无 a2a dissector（`tshark -G fields | grep '^a2a\.'` = **0 行**，tshark 3.6.14 实测）——**不得使用任何 `a2a.*` 字段**。可用通道：① `json.*`（29 字段，实测）；② `http.*`（`http.content_type`/`http.request.method`/`http.response.code`/`http.request.uri`）；③ `tcp.*`（`srcport`/`dstport`/`flags`/`len`/`seq`）；④ frames `offset/hex`（HTTP 报文首字节，IPv4 offset 54 / IPv6 offset 74）。**SSE 无专用解析器**（整段落 `http.file_data`，事件序只能靠 frames hex 钉——T205/T207 已用此法）。端口 8080 可被 HTTP dissector 自动解码（自造探针实测，无需 `decode_as`）。

**动态字段禁止硬编码**：存量 185 例**未使用** `same_as_packet`/`distinct_values`（机读实测零命中）；`nonzero` 仅 `a2a_t211_tshark_sse` 一处（`http.file_data` 存在且非零）。多流例（T165/T168）以**总包数**证明会话数，不做端口聚合断言（跨流包序随机交织）——**A′ 候选**：补 `tcp.srcport` 的 `distinct_values:["12345","12346","12347"]` + `distinct_exclude:["8080"]` 聚合断言（§6.2）。

**包数约定**（2026-09-28 探针实测校准：1/2/3/10 task → 9/11/13/27 包，公式全中）：单流单 task = 3（握手）+ 1（请求）+ 1（响应）+ 4（FIN 四包挥手）= **9**；带 Agent Card 发现 = **11**（+2）；N task 串行 = **3 + 2N + 4**（T164 三 task = 13；T167 十 task = 27）。数据帧从帧 4 起；实现期以实际输出校准 `packet_count`，断言以 fields/frames 为准；负例无 `packet_count`。

**保活/重试/RST 口径**：A2A 无协议级 ping/keepalive 报文（设计 §4 显式不适用）；RST 为框架 tcp 层能力，本协议层不新增断言（A′ 补例 G-A2A-10 除外）；正例恒 FIN 优雅终止。

## 2. 原子用例索引（185 ID = 153 正 + 32 负，顺序为权威）

### 2.1 场景族 `a2a_s*`（18 例，对应旧稿 §6.2 HexDump 场景 S1–S15）

| # | ID | 类型 | 覆盖（设计 §） | packet_count |
|---:|---|---|---|---:|
| 1 | `a2a_s1_agent_card` | 正 | §3.1/§3.2：Agent Card 发现（GET + 200） | 11 |
| 2 | `a2a_s2_message_send` | 正 | §3.2：message/send 同步 | 9 |
| 3 | `a2a_s2b_result_message` | 正 | §3.4：result=Message（简单交互） | 9 |
| 4 | `a2a_s3_message_stream` | 正 | §3.3：message/stream SSE | 9 |
| 5 | `a2a_s4_tasks_get` | 正 | §3.2：tasks/get | 9 |
| 6 | `a2a_s5_tasks_cancel` | 正 | §3.2：tasks/cancel | 9 |
| 7 | `a2a_s6_resubscribe` | 正 | §3.2/§3.3：tasks/resubscribe | 9 |
| 8 | `a2a_s7_push_set` | 正 | §3.2：pushNotificationConfig/set | 9 |
| 9 | `a2a_s8_bearer_auth` | 正 | §3.4/§10.4：Bearer 认证 | 9 |
| 10 | `a2a_s8b_basic_auth` | 正 | §10.4：Basic 认证 | 9 |
| 11 | `a2a_s8c_apikey_header` | 正 | §10.4：API Key（header） | 9 |
| 12 | `a2a_s9_multi_task_serial` | 正 | §5：多 task 同连接串行 | 11 |
| 13 | `a2a_s10_sse_5events` | 正 | §3.3：5 事件混合流 | 9 |
| 14 | `a2a_s11_error_32001` | 正 | §7：-32001 响应 | 9 |
| 15 | `a2a_s12_artifact_append` | 正 | §3.3：artifact-update append/lastChunk | 9 |
| 16 | `a2a_s13_multi_part` | 正 | §3.4：text+data+file 三 Part | 9 |
| 17 | `a2a_s14_webhook` | 正 | §10.4 #10：webhook 配置侧（**响应体生成**，非反向连接） | 9 |
| 18 | `a2a_s15b_edge_skills_empty` | 正 | §8：skills=[] 边界 | 11 |

### 2.2 设计行族 `a2a_t*`（167 例 = 135 正 + 32 负）

按旧稿 §7 章节分组（ID 顺序 = JSON 顺序）：

| 组 | ID 区间 | 例数 | 正 | 负 | 覆盖（设计 §） |
|---|---|---:|---:|---:|---|
| 报文格式与序列化 | `a2a_t001`–`a2a_t012` | 11 | 9 | 2 | §3.1/§3.3/§3.5（信封/SSE 行/Content-Type/keep-alive/Authorization） |
| Agent Card 发现 | `a2a_t014`–`a2a_t024` | 5 | 5 | 0 | §3.4 Agent Card 字段/路径/404/畸形 JSON |
| message/send | `a2a_t027`–`a2a_t040` | 9 | 5 | 4 | §3.2/§3.4（文本/多 Part/文件/configuration/状态/负例 V7） |
| message/stream | `a2a_t043`–`a2a_t054` | 6 | 3 | 3 | §3.3（事件序/final/append/负例 V8/V7） |
| tasks/get | `a2a_t057`–`a2a_t064` | 5 | 4 | 1 | §3.2（history/artifacts/historyLength 边界/负例 V8） |
| tasks/cancel | `a2a_t066`–`a2a_t072` | 6 | 5 | 1 | §3.2/§5（状态转换/负例 V8） |
| tasks/resubscribe | `a2a_t075`–`a2a_t080` | 5 | 3 | 2 | §3.2/§3.3（续传/未命名事件/负例 V8） |
| pushNotificationConfig | `a2a_t085`–`a2a_t092` | 7 | 3 | 4 | §3.2/§3.4（set/get/负例 V5/V8） |
| 认证 | `a2a_t096`–`a2a_t104` | 7 | 7 | 0 | §3.4/§10.4（oauth2/oidc/securitySchemes/none/auth-required） |
| 状态机 | `a2a_t105`–`a2a_t122` | 14 | 9 | 5 | §5 转换表（9 值/多轮/终态不可变/未定义转换） |
| TaskArtifactUpdateEvent | `a2a_t124`–`a2a_t130` | 3 | 2 | 1 | §3.3（append 语义/字段/负例 V9） |
| TaskStatusUpdateEvent | `a2a_t131`–`a2a_t138` | 3 | 3 | 0 | §3.3（final 语义/字段） |
| Message/Part 字段 | `a2a_t139`–`a2a_t150` | 16 | 16 | 0 | §3.4（role/messageId/contextId/referenceTaskIds/3 kind） |
| Push webhook | `a2a_t151`–`a2a_t160` | 1 | 1 | 0 | §10.4 #10（配置侧字段/HTTP URL 合法） |
| 多任务/多会话/并发 | `a2a_t161`–`a2a_t172` | 6 | 6 | 0 | §5/§6（串行/contextId/多流/100 流/Connection 头） |
| 边界场景 | `a2a_t173`–`a2a_t186` | 11 | 11 | 0 | §8（skills/text/parts/长度/historyLength/SSE 0 中间事件） |
| 异常场景 | `a2a_t187`–`a2a_t203` | 13 | 10 | 3 | §7 错误码 12 值 + 负例 V2/V4 |
| 集成与端到端 | `a2a_t204`–`a2a_t211` | 7 | 7 | 0 | §4 场景①–⑥ |
| 字段覆盖补全 | `a2a_t212`–`a2a_t221` | 12 | 12 | 0 | §3.4（v0.2.5/v0.3.0 保留字段/事件完整字段） |
| Part kind 互斥 | `a2a_t222`–`a2a_t227` | 6 | 3 | 3 | §3.4 互斥三向（V4） |
| v2.0.0 审计修复验证 | `a2a_t228`–`a2a_t242` | 14 | 11 | 3 | §0 表 #9 方法名/路径/kind 验证 |

**族小计校验（机读逐区间统计，2026-09-28）**：11+5+9+6+5+6+5+7+7+14+3+3+16+1+6+11+13+7+12+6+14 = **167**（= 实际 `a2a_t*` ID 数，无未归类 ID）；正例合计 **135**、负例合计 **32**。区间按 ID 数值切分（`a2a_t212a` 归入 `t212` 组），与 JSON 顺序无关（ID 顺序 = JSON 顺序，保持稳定）。

T-编号对照：`a2a_sN_*` ≡ 旧稿 §6.2 S1–S15；`a2a_tNNN_*` ≡ 旧稿 §7 T001–T242（同号者一一对应）。

### 2.3 ID 名与语义不符注记（历史遗留，**ID 保留不改**）

以下 2 个 ID 的**名称**与**实际语义**不符，系旧稿命名遗留。**ID 保留不改**（稳定性优先——跨 design §9 / 本版 §2 / cases JSON 三处引用一致）；**语义以本表为准**：

| ID | 名称暗示 | 实际语义 | 依据 |
|---|---|---|---|
| `a2a_t167_100_flows` | 100 流并发 | **10 task 同连接串行**（27 包 = 3+2×10+4） | 探针实测；`frames` 钉帧 4/22 |
| `a2a_t164_multi_flow_count3` | 3 流并发 | **3 task 同连接串行**（13 包 = 3+2×3+4） | 探针实测；`frames` 钉帧 4/6/8 |

**真正的多流并发例**是 `a2a_t165_multi_session_taskid` 与 `a2a_t168_multi_flow_concurrency`（`strategy_fc={"type":"flows","value":3}`，3 流 27 包）。

## 3. 正例逐项断言契约（最低断言集，实现期可增不可减）

以下为**存量 JSON 实际断言**（机读摘录，非设计推导）；每例均含载体断言 + 报文首字节 frames 断言。**注意**：断言值与 `packet_count` 本身有效（形状问题不影响其正确性），但**用例形状为违规过渡形**（§1/§8），改写须待 G-A2A-1 落码。报文 hex 可由 fixture 精确预算（HTTP 请求行 `POST /a2a HTTP/1.1` = `50 4f 53 54 20 2f 61 32 61 20 48 54 54 50 2f 31 2e 31`；GET 卡片 = `47 45 54 20 2f 2e 77 65 6c 6c 2d 6b 6e 6f 77 6e 2f 61 67 65 6e 74 2e 6a 73 6f 6e 20 48 54 54 50 2f 31 2e 31`；SSE 行首 = `64 61 74 61 3a 20`）。

### 3.1 `a2a_s1_agent_card`（11）

`tcp.src_port=51001`/`dst_port=8080`。帧 4（offset 54）hex 起 = GET 请求行；帧 4 `tcp.len=138`/`tcp.flags=0x18`；帧 5 `tcp.len=596`/`tcp.srcport=8080`（卡片 200 响应下行）；帧 6 `tcp.len=445`/`tcp.srcport=51001`（消息请求）；帧 7 `tcp.len=353`/`tcp.dstport=51001`；`has_handshake`/`has_payload`/`negotiated`/`terminates` 全 true。

### 3.2 `a2a_s2_message_send`（9）

`tcp.src_port=51002`/`dst_port=8080`。帧 4（offset 54）hex 起 = `POST /a2a HTTP/1.1\r\nHost: 20.0.0.1\r\n`；帧 4 offset 220 hex = `Connection: close`（末 task 且 termination 生效）；帧 4 `tcp.len=445`/`tcp.flags=0x18`/`tcp.srcport=51002`；帧 5 `tcp.len=353`/`tcp.dstport=51002`（下行端口对换）。

### 3.3 `a2a_s3_message_stream`（9）

`tcp.src_port=51004`/`dst_port=8080`，`streaming=true` + `sseEvents[]` 3 事件（task → artifact-update → status-update(final=true)）。帧 4 offset 122 hex = `Accept: text/event-stream`；帧 4 offset 223 hex 起 = 请求 JSON-RPC body（`{"id":"req-002","jsonrpc":"2.0","method":"message/stream",...`）；帧 5 `tcp.len=732`/`tcp.dstport=51004`。

### 3.4 `a2a_t205_stream_full_flow`（9，唯一 `http.content_type` 断言）

帧 5 `http.content_type=text/event-stream`；帧 5 `tcp.len=663`；帧 5 offset 188 hex = `64 61 74 61 3a 20`（SSE `data: ` 行首）；`has_handshake`/`terminates` true。

### 3.5 `a2a_t211_tshark_sse`（9，唯一 `nonzero` 断言）

帧 5 `http.file_data` **存在且非全零**（`nonzero:true`）——SSE 无专用解析器，整段落 `http.file_data`，只能断"有载荷"不能断内部字段序。

### 3.6 `a2a_t165_multi_session_taskid`（27，`strategy_fc={"type":"flows","value":3}`）

`layers[1].tcp` **只写 `dst_port=8080`**（`src_port` 留空走 worker 保底递增）。3 流 × 9 包 = 27；`directional=true`；**不逐包定位、不断言端口聚合**（跨流包序由分片 hash 随机交织，多次运行流序不同）；27 包总数即证明 3 会话。`a2a_t168_multi_flow_concurrency` 同形同断言。

### 3.7 `a2a_t167_100_flows`（27）

**实为 10 task 同连接串行**（ID 名与语义不符，保留不改，见 §2.3 注记）：`tcp.src_port=51635`/`dst_port=8080`；帧 4 与帧 22（offset 54）hex 均为 `POST /a2a HTTP/1.1`（第 1 与第 10 个 task 的请求）；`packet_count=27`。

**包数裁定（2026-09-28 探针实测）**：`packet_count=27` **正确**；该例 `notes` 自述「36 包 = 3 握手 + 10×2 + 3 挥手」**双重错误**（① 算术本身 3+20+3 = 26 ≠ 36；② 挥手是 4 包非 3 包）。实测 1/2/3/10 task → 9/11/13/27 包，公式 `3 + 2N + 4` 全中。`frames` 钉帧 4/帧 22 与 10-task 结构自洽（task k 请求帧 = `4 + 2(k-1)`）。**故 `packet_count` 权威，`notes` 待代码阶段先跑后钉时修正。**

### 3.8 `a2a_t174_text_1mb` / `a2a_t177_file_10mb`（`min_packets`）

1MB text → `min_packets=700`；10MB file（base64 后 ≈13.3MB）→ `min_packets=9000`。用 `min_packets` 而非 `packet_count`（段数随实现细节微调，下界才是契约）。`a2a_t180_skills_1024`=40 / `a2a_t181_parts_1024`=31 / `a2a_t183_description_4096`=14 同理。

### 3.9 `a2a_t164_multi_flow_count3`（13）

**实为 3 task 同连接串行**（ID 名与语义不符，同 T167 情形）：3 + 2×3 + 4 = 13 包（探针实测 3 task → 13 包，与公式一致）；帧 4/6/8（offset 54）hex 均为 `POST /a2a HTTP/1.1`；`tcp.src_port=51634`/`dst_port=8080`。

**正例总则**：`input-required`/`auth-required` 暂停态、HTTP URL 的 webhook、`mutualTLS` 方案声明均为合法形态；只有配置/线格式/状态机/关联/长度/载体错误进入负例。

## 4. 负例契约

负例必须在 planner/validator 阶段失败并传播为 task error，不得产生成功 PCAP、`completed/0 packet` 或只剩 TCP 外壳的假成功；`expect` 键集合**严格为** `{expect_error, error_contains, notes}`。锚词与设计 §7 表一一对应：

| ID | 故障输入 | `error_contains` | 设计 §7 行 |
|---|---|---|---|
| `a2a_t002_both_result_error` | 同时设 `result` 与 `error` | `V16` | V16 |
| `a2a_t004_neg_missing_request_id` | 缺 `requestId` | `V8` | V8 |
| `a2a_t037_neg_no_message` | `message/send` 无 `message` | `V7` | V7 |
| `a2a_t038_neg_role_system` | `role="system"` | `V7` | V7 |
| `a2a_t039_neg_parts_empty` | `parts=[]` | `V7` | V7 |
| `a2a_t040_neg_kind_datastream` | `message.kind="data-stream"` | `V7` | V7 |
| `a2a_t050_neg_streaming_false` | `message/stream` + `streaming=false` | `V8` | V8 |
| `a2a_t053_neg_stream_no_parts` | `message/stream` + `parts=[]` | `V7` | V7 |
| `a2a_t054_neg_stream_kind_filestream` | `message/stream` + `kind="file-stream"` | `V7` | V7 |
| `a2a_t059_neg_get_no_id` | `tasks/get` 无 `taskId` | `V8` | V8 |
| `a2a_t067_neg_cancel_no_id` | `tasks/cancel` 无 `taskId` | `V8` | V8 |
| `a2a_t075_neg_resubscribe_sync` | `tasks/resubscribe` + `streaming=false` | `V8` | V8 |
| `a2a_t076_neg_resubscribe_no_id` | `tasks/resubscribe` 无 `taskId` | `V8` | V8 |
| `a2a_t086_neg_set_no_taskid` | `pnc/set` 无 `taskId` | `V8` | V8 |
| `a2a_t087_neg_set_no_config` | `pnc/set` 无 `pushNotificationConfig` | `V8` | V8 |
| `a2a_t088_neg_set_url_empty` | `pnc/set` 的 `url=""` | `V5` | V5 |
| `a2a_t092_neg_get_no_id` | `pnc/get` 无 `taskId` | `V8` | V8 |
| `a2a_t116_neg_terminal_completed` | SSE `completed→working` | `V10` | V10 |
| `a2a_t117_neg_terminal_failed` | SSE `failed→working` | `V10` | V10 |
| `a2a_t118_neg_terminal_canceled` | SSE `canceled→working` | `V10` | V10 |
| `a2a_t119_neg_terminal_rejected` | SSE `rejected→working` | `V10` | V10 |
| `a2a_t120_neg_input_required_completed` | SSE `input-required→completed` | `V10` | V10 |
| `a2a_t130_neg_artifact_missing` | artifact-update 缺 `artifact` | `V9` | V9 |
| `a2a_t196_neg_pnc_list_method` | `method="tasks/pushNotificationConfig/list"` | `V2` | V2 |
| `a2a_t202_neg_sendsubscribe` | `method="tasks/sendSubscribe"` | `V2` | V2 |
| `a2a_t203_neg_part_datastream` | Part `kind="data-stream"` | `V4` | V4 |
| `a2a_t225_neg_part_text_data` | text Part 带 `data` | `V4` | V4 |
| `a2a_t226_neg_part_data_file` | data Part 带 `file` | `V4` | V4 |
| `a2a_t227_neg_part_file_text` | file Part 带 `text` | `V4` | V4 |
| `a2a_t230_neg_subscribe` | `method="tasks/subscribe"` | `V2` | V2 |
| `a2a_t236_neg_kind_datastream` | `message.kind="data-stream"`（同 T040 不同 ID 组） | `V7` | V7 |
| `a2a_t237_neg_kind_filestream` | `message.kind="file-stream"` | `V7` | V7 |

**负例原子性**：每例单一故障注入；单次执行不得混注。

**覆盖分布**：V2 ×3 / V4 ×4 / V5 ×1 / V7 ×7 / V8 ×10 / V9 ×1 / V10 ×5 / V16 ×1 = **32**。✓

## 5. 覆盖与对账

### 5.1 三源回指行

A2A spec v0.2.2（方法名/卡片路径/Part kind/SSE 事件/9 状态/12 错误码，设计 §10 八项矩阵）+ D-A2A-1（设计 §11）+ tshark 通道实测（`http.*`/`json.*`/`tcp.*`/frames，`a2a.*` 零字段）→ 185 ID（本契约 §2）。第三源"已确认现网行为"当前 = **未确认级**（G-A2A-4：真实商业 Agent 平台行为未达抓包级；间接证据 = `a2a-python` SDK 默认卡片路径 `agent-card.json`，与 v0.2.2 spec 的 `agent.json` 不一致，按 §4.15 以 spec 为底线，路径可用 `agentCardPath` 覆盖）。

### 5.2 9.52 对账两行 + 清单出处声明

- **清单出处声明**：本清单来源 = **A2A spec v0.2.2 反推 + 旧基线契约（17-design §7 的 246 条设计行）+ 仓库落码反推 + tshark 通道实测**，**以规范反推为主**（A2A 有公开 spec，`a2a.*` 零字段只影响断言通道选择、不影响清单来源）。
- **对账两行**：**要求逻辑点总数 = 246**（旧稿 §7 设计行台账：报文 12 + 发现 12 + send 16 + stream 14 + get 10 + cancel 8 + resubscribe 8 + push 12 + 认证 12 + 状态机 18 + artifact 8 + status 8 + Message/Part 12 + webhook 10 + 多任务 12 + 边界 14 + 异常 17 + 集成 8 + 字段补全 14 + Part 互斥 6 + v2.0.0 修复 15 = 246）；**用例覆盖数 = 185**（153 正 + 32 负）；**差额 = 61**：#52 报告已核为"167 合入 + 9 等价覆盖 + 9 作废（重复第二条）+ 87 设计行无存量例"——本版以 **185 为 JSON 权威、246 为设计行台账**，87 条缺口立项 G-A2A-9（A′ 清单见设计 §13）。
  **粒度声明**：行/格粒度每点 1 计；G-A2A-1…G-A2A-11 不折进 246。**反查全绿 ≠ 覆盖全**（§9.52 原文）。
- **门3 抽查候选**：最复杂用例 = **`a2a_t205_stream_full_flow`**（stream 全流程：SSE 3 事件 × `final:true` × 流关闭 × frames hex 钉事件序）；交织维度 = 事件(3)×kind(3)×终态(final)×载体(SSE chunked)。若按 9.49/9.50 下限偏弱在"多流并发"面，**建议门3 抽 `a2a_t205` + `a2a_t168`**（三流并发 `directional` + 聚合断言）。

### 5.3 T-编号与旧 id 对照（设计 §9 全表摘要）

`a2a_sN_*` ≡ 旧稿 §6.2 场景 S1–S15（S8 拆 S8/S8b/S8c 三条认证；S15 拆 S15b 边界）；`a2a_tNNN_*` ≡ 旧稿 §7 T001–T242 同号（T140/T142/T146/T147/T148/T149/T196/T219 各有 2 个同号 ID，见 §8.3）。

## 6. P3 固定动作（CORE_MEMORY 管线：§3.15 三项 + A′/B′ 两分类 + 3.14 豁免）

### 6.1 §3.15 三项逐项一例或立项

| # | 三项 | 本协议对照 | 用例/立项 |
|---|---|---|---|
| ① | 同连接/同流内的多轮操作 | 单 TCP 连接多 task 串行（T208 两 task；T167 十 task）；多轮交互（T106 `input-required→working→completed`） | 已覆 T208/T167/T106 |
| ② | 非正常结束 | 正常 FIN 全正例；应用层终止报文 = SSE `final:true`（T132/T205）；网络层异常 = RST | SSE 侧已覆（T132/T205/T186）；RST → A′ 补例 `a2a_abort_rst`（G-A2A-10） |
| ③ | 长保活 | HTTP keep-alive（`Connection: keep-alive`，最后一 task `close`，T011/T171/T172）；无协议级 ping | 已覆 T011/T171/T172 |

无空项：① 有已覆例；② 有已覆例 + 1 条 A′ 补例；③ 有 T011/T171/T172。

### 6.2 A′/B′ 两分类表

**A′（代码阶段接线；前置 = G-A2A-1 三项全落）**：

| 类 | 内容 | 落点 |
|---|---|---|
| 层内化 | registry `Fields` 补 a2a 键表 + translate `case "a2a"` 分支 + `CheckProtoFlat` presence 判死 | G-A2A-1，用例 #1–#185 全依赖 |
| 端口面 | `FieldContract` 补 `tcp.dst_port` | G-A2A-2；A′ 补例 `a2a_default_port` |
| presence 判死 | 层链 + 顶层空 `a2a` 子映射并存 = 判死负例 | §12-P2 ①；**须先补判死分支**（建了会真绿 = 假通过） |
| 游离键判死 | 白名单外顶层键（`layers` + `src_ip`） | §12-P2 ②（通用分支已覆盖） |
| 地址族面 | 异族混写拒绝 | A′ 补例 `a2a_neg_mixed_family` |
| 配置面 | `cfg.TCP`/`cfg.HTTP` 层内化后生效 | A′ 补例 `a2a_tcp_config_layer` / `a2a_http_config_layer` |
| 非正常结束 | `tcp.rst` 补例 | G-A2A-10 |
| SSE 边界 | 末事件 `final=false` 拒绝 | A′ 补例 `a2a_sse_last_final_false` |
| 现网面 | 商业平台基线实证 | G-A2A-4 |

**B′（框架面）**：`CheckProtoFlat` a2a presence 分支（G-A2A-1 后半，等框架级 unknown-key 白名单，不单独立项）/ 业务字段动态（G-A2A-7，allowlist 无 `a2a` 行）/ webhook 反向连接（G-A2A-5，**明确不解决**）/ v0.3.0+ 扩展（G-A2A-11，**明确不支持**）。进设计 §14。

### 6.3 3.14 豁免边界审计

**有长连接载体 → `sessions[]` 不豁免**（设计 §12.3 会话表 s1–s4；多会话语义由 `flow_control flows` 承载，同 flow 内 `sessions[]` 显式声明缺失 = G-A2A-6 **明确不解决**）；多流并发 T164/T165/T168；单包多载荷 = **已覆**（T013 `a2a_s13_multi_part`：单 Message 三 Part；T010 `a2a_s10_sse_5events`：单响应多事件——A2A 有此类形态，不适用"不适用"声明）。

## 7. 实现后执行建议

1. **代码阶段顺序**：G-A2A-1（registry `Fields` + translate `case "a2a"` + `mapToFlowSpec` 收敛 + `CheckProtoFlat` 判死 + schemagen 重跑）→ G-A2A-2（`FieldContract`）→ **185 例改写**（顶层残留 1081→0，改写补丁参考 `/tmp/pipe/a2a-layerchain-rewrite.patch`（38232 行，含 185 例完整 diff；主线程另存 `/tmp/pipe/patches/a2a-layerchain.json`））→ 先跑后钉 → 补 A′ 例 → 全量复跑。**今日不可执行**（建策略即 400，§8.2 #4）。
2. **实测顺序**：先 S2/S1（9/11 包基线 + frames hex），再 S3/S10（SSE `http.content_type` 与 `data: ` 行首），再 S4/S5（状态字段），最后 T174/T177（跨段 `min_packets`）、T165/T168（多流聚合）。
3. 二进制与 HEAD 同代确认（门2③：`find trafficgen -name '*.go' -newer <server-binary>` 无输出）；门2② 全量（`CASE_PROTO=a2a` 全量不是增量）；门2④ 反查绿后进 P6。
4. 任何商业平台行为的具体断言须有独立文档证据和失败优先测试（设计 §1 边界纪律）。

## 8. 存量审计与缺口登记（185 例逐条去向）

> **本版 `cases/a2a.json` 保持原样**（层空壳，合规化属代码阶段；**改写版已产出存 patch**，待 G-A2A-1 落码后套用，见 §9）。本节按"缺口登记表"口径写：列出每例现状 + 需代码阶段落地后才能改写。**改写待办 = 185 例全额**，今日**不申报任何已迁移**。

### 8.1 存量实测面（2026-09-28，原样）

`cases/a2a.json` **185 例**（唯一 ID 185）。185/185 带顶层 `a2a` 子映射 + 顶层 `src_ip`/`dst_ip`/`dst_port`；183 带 `src_port`；158 带 `count=1`；153 带空壳 `layers:[{tcp:{}},{a2a:{}}]`（两层 config 恒 `{}`，真实配置住顶层 `a2a`）；32 例无 `layers`。**顶层残留合计 1081 处**（`src_ip` 185 + `dst_ip` 185 + `dst_port` 185 + `src_port` 183 + `count` 158 + 顶层 `a2a` 185 = 1081）；其中**非负例 914 处**、负例 167 处。32 负例 `expect` 键集合严格 `{expect_error,error_contains,notes}`。148 正例 `packet_count` + 5 `min_packets` = 153 正例。

### 8.2 缺口登记表（三要素：现象 / 证据行号 / 归属阶段）

> **取证方式**：下表 #1 与 #4 附**探针实测原文**（2026-09-28，临时探针文件跑完即删、仓库零改动），非代码推理。两条探针合证：**存量形状 MCP 400 / 改写形状 `unknown field "baseUrl"`，两条路今日都不通**。

| # | 现象 | 证据行号 | 归属阶段 |
|---:|---|---|---|
| 1 | `a2a` 层无 `Fields` → 层内任何键报 `unknown field`。**探针实测**：改写形状走 `ValidateLayers` 返回 `layers: layer "a2a": unknown field "baseUrl"`（原文，非推理） | `registry.go:245`（Register 无 Fields）；生成表 `layers.a2a.fields = {}`；`complete.go:293` | 代码阶段（G-A2A-1 ①） |
| 2 | 空 `Fields` 使 `translateTerminalConfig` **在 switch 前提前 return** → 层内配置**根本不被解码** | `chain_planner_translate.go:852` `if len(s.Fields) == 0 { return }`（位于 `switch term.Name` 之前） | 代码阶段（G-A2A-1 ②） |
| 3 | `translateTerminalConfig` 无 `case "a2a"`（即便解开 ② 也无落点） | `grep -c 'case "a2a"' internal/core/layers/` = 0 | 代码阶段（G-A2A-1 ②） |
| 4 | 顶层四元组/`count` 经 MCP 建策略即 400 → **存量 185 例今日跑不起来**。**探针实测**（`schema.ValidateStrategy` 原文两条）：`protocol a2a no longer accepts flat config field src_ip (use a layers chain: ip.src/ip.dst for addresses, tcp/udp src_port/dst_port for ports, flow_control for the flow count)` + `config mixes layers with flat four-tuple field src_ip (…)` | `schema/semantic.go:130` 无条件 `CheckProtoFlat` → `strategy_convert.go:8632` 五键判死；`checkLayerFlatConflict` | 代码阶段（G-A2A-1 ③ + G-A2A-12 用例改写） |
| 5 | 离线套件绕过上述检查（故存量"离线绿"是假象，非合规证据） | `layer_chain_suite_test.go:225-231` 剥离 `layers` 后把顶层扁平键直传 `MapToFlowSpec`，不经 `CheckProtoFlat` | 口径声明（不得据此申报已过） |
| 6 | 顶层 `a2a` presence 今日**不判死** → 该负例建了会真绿 = 假通过 | `grep -c 'protocol == "a2a"' strategy_convert.go` = 0（对比 moxa = 2） | 代码阶段（G-A2A-1 ④）；**先补分支再建例** |
| 7 | 无 `FieldContract` → 缺省端口落通用 80；8080 只是用例 fixture | `strategy_convert.go:341`（`DefaultDstPort`，`:54` = 80） | 代码阶段（G-A2A-2） |
| 8 | 业务字段动态全关（allowlist 无 `a2a` 行） | `layer_dyn.go:17-21`（仅 ip/tcp/udp/eth） | 代码阶段（G-A2A-7） |
| 9 | V3/V13/V14/V15 设计行声明无代码 | `grep` 实测 `a2a.go` 只有 V1/V2/V4–V12/V16 | 口径裁决（G-A2A-3） |
| 10 | 旧稿 §7 的 246 条设计行中 87 条无存量例 | #52 报告 §②（167 合入 + 9 等价 + 9 作废 + 87 缺） | 代码阶段 casegen（G-A2A-9） |

### 8.3 逐例去向表（185 例按族，去向统一为"代码阶段改写"）

| 存量族 | 例数 | 今日状态 | 代码阶段动作（前置 G-A2A-1 三项全落） |
|---|---:|---|---|
| `a2a_s1`–`a2a_s15b` | 18 | 违规过渡形（顶层残留） | 地址迁 `layers[0].ip`、端口迁 `layers[1].tcp`、`a2a` 子映射迁 `layers[2].a2a`；`packet_count` 不变 |
| `a2a_t*` 正例 | 135 | 同上 | 同上；断言值不变 |
| `a2a_t*` 负例 | 32 | 同上 | 同上；锚词不变（§4 表逐条对码，8/8 不同锚词在源码逐字命中） |
| 同号重复 8 组（T140/142/146/147/148/149/196/219） | 16（含于上两行） | 同上 | **保留两条**（等价覆盖，ID 稳定性优先） |

**0 作废 / 0 等价覆盖删除**（全部保留待改写）；**待改写 = 185/185**。

### 8.4 覆盖反查门建议断言行（**今日红项如实标红**，不得作为"今日已过"申报）

| # | 建议断言 | 今日状态 | 转绿条件 |
|---:|---|---|---|
| 1 | 非负例 `spec_json` 顶层键 ⊆ `{layers, flow_control, strategy_fc, output, output_config, group_id}` | **红**（914 处残留） | G-A2A-1 三项 + 185 例改写 |
| 2 | 非负例顶层协议子映射数 = 0 | **红**（185 处顶层 `a2a`） | 同上 |
| 3 | 正例层链形 == `[ip,tcp,a2a]` 且 a2a 层 config 非空 | **红**（153 例为空壳层 + 32 例无层） | 同上 |
| 4 | 32 负例 `expect` 键 ⊆ `{expect_error,error_contains,notes}` 且无 `packet_count` | **绿**（32/32 已合规） | — |
| 5 | 32 锚词在 `a2a.go`/`layer_gen.go` 逐字命中 | **绿**（8/8 不同锚词命中） | — |
| 6 | presence 判死负例（层链 + 顶层空 `a2a` 并存被拒）存在 | **缺**（今日不可建，建了会真绿） | G-A2A-1 ④ 落码后 |
| 7 | 全量经 MCP 真实流程跑绿 | **不可执行**（今日建策略即 400） | G-A2A-1 三项 + 改写 |

**口径**：红项（1/2/3/6/7）**不得申报为"今日已过"**；绿项（4/5）为存量已具备的合规面，不因形状问题失效。

## 9. 修订记录


- v1.0.0（2026-09-28）：P-PIPE #93 文档轨 P1–P3。旧稿 17-design §7 的 246 条设计行台账与存量 185 例对齐（#52 报告 §② 自审结论继承）；形状基线机读实测（§1）、TSHARK 基线（§1）、P3 固定动作（§6）、执行建议（§7）、**存量审计改为缺口登记表（§8，含 10 条缺口三要素 + 7 行覆盖反查门建议断言，红项如实标红）**。
- **裁定更正（同日）**：初稿曾把 185 例改写为纯层链形并提交；主线程复核后更正定性——**改写本身正确、质量高**（914→0、顶层键集只剩 `['layers']`、185/185 完整），仅因中途改口径而需回退；JSON 已还原，改写成果存 patch，**待代码阶段套用**。
- **两条裁决落实（同日）**：① G-A2A-3 保留设计行、登记代码阶段实装（不删条，CORE_MEMORY §1 契约纪律）；② T167/T164 命名与语义不符 —— `packet_count` vs `notes` 矛盾经**探针实测裁定 `packet_count` 正确**（notes 双重错误），ID 名保留不改 + 本版 §2.3 加显式注记。
