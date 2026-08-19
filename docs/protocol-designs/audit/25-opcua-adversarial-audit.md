# OPC UA（25）设计文档与用例文档对抗审查报告

> 审查日期：2026-08-19
> 审查对象：25-opcua-design.md v1.0.0 / 25-opcua-testcase.md v1.0.0 / cases/opcua.json
> 审查类型：文档阶段（设计自洽性 + 用例覆盖 + 三件套一致性）

---

## 审查结论概要

| 维度 | 结论 |
|------|------|
| 设计规范自洽性 | **存在 CRITICAL 缺陷**：HEL 消息缺少 EndpointUrl 字段，AuthToken 编码偏移错误，CLO 响应方向理解错误，SecurityPolicy URI 域名错误 |
| 三件套一致性 | **存在 CRITICAL 不一致**：design ↔ testcase 包数大面积不匹配；testcase ↔ JSON 帧断言、包数、spec_json 多处冲突 |
| 用例覆盖完整性 | **存在 MAJOR 缺口**：T4(opcua_read) 和 T8(opcua_keepalive) 在 JSON 中缺失 |
| 待实现边界 | 已标注，合理 |

**严重度分布**：CRITICAL 8 | MAJOR 5 | MINOR 5

---

## 1. 代码设计逻辑审查 Findings

### CRITICAL-01：HEL 消息缺少 EndpointUrl 字段（设计 §3.2）

**文件**：25-opcua-design.md §3.2，第 300-311 行

**问题描述**：设计文档 HEL 表格仅列出 5 个 UInt32 字段（ProtocolVersion/ReceiveBufferSize/SendBufferSize/MaxMessageSize/MaxChunkCount），共 20 字节，MessageSize=28。但 OPC UA Part 6 §7.1.2.3 定义 HelloMessage 包含第 6 个字段 `EndpointUrl: String`（Int32 长度前缀 + UTF-8 字节）。即使空字符串也至少有 4 字节长度前缀，最小 MessageSize=8+20+4=32。

**影响**：
- 设计 §6 S1 的 HexDump 全部缺失 EndpointUrl，MessageSize 标注为 28（实际应为 32）
- 设计 §3.5 大小计算表 HEL 行 MessageSize=28 错误
- 设计 §7 映射表 T1 覆盖点 "MessageSize=28" 错误
- 该错误已传播到 testcase 文档 T1 的帧断言（`1c000000`=28）

**修复建议**：
1. HEL 表格增加第 6 行 `EndpointUrl`（String 类型），说明空串至少 4 字节
2. 修正所有 MessageSize=28 为 32（`0x20`）
3. §6 S1 HexDump 增加 `7c  00 00 00 00`（EndpointUrl 长度 0 的空串）
4. 重新计算 §3.5 大小表

**交叉验证**：JSON 中 `opcua_hello_ack` 的帧断言正确使用了 `20000000`（32），说明 JSON 作者意识到了 EndpointUrl 的存在，但 design 和 testcase 文档未同步更新。

---

### CRITICAL-02：AuthToken 编码偏移错误（设计 §6 S3R1）

**文件**：25-opcua-design.md §6 S3R1，第 853-874 行

**问题描述**：设计文档将无会话的 AuthenticationToken（TwoByte NodeId 0）编码为单字节 `00`（偏移 72），但 OPC UA Part 6 §5.2.2.9 定义 TwoByte NodeId 格式为 `00`（掩码字节）+ `id`（标识符字节），共 2 字节。id=0 时线上为 `00 00`。

**交叉核实**：设计文档 §2.8 NodeId 表中明确写着 "TwoByte（两字节）：id: Byte（1B，ns=0）"，即设计文档自身承认 TwoByte 是掩码+id 共 2 字节。掩码 0x00 + id 0 在线上为 `00 00`。设计内部自相矛盾。

**佐证**：设计文档 §2.13 编码示例汇总中 `NodeId ns=0;i=1` = `00 01`（2 字节）——同一文档内部确认 TwoByte NodeId 是 2 字节。而 S3R1 中又把 TwoByte 0 写成 1 字节 `00`，直接矛盾。

**影响**：
- 偏移 72 标注为 `00`（1 字节），实际应为 `00 00`（2 字节）
- 后续 Timestamp 偏移从 73 变为 74，此后所有偏移 +1
- 设计文档载荷计算 "1（AuthToken）" 应为 "2（AuthToken）"，总载荷从 80 变为 81
- testcase 文档 T4 的 `offset 99`（`0100e903`）引用自设计文档 S3R1，按修正后偏移应为 100 而非 99

**修复建议**：
1. 修正 S3R1 HexDump 中 AuthToken 为 `00 00`，调整后续所有偏移
2. 修正载荷计数公式
3. testcase 文档 T4 的 `offset 99` 同步修正为 `offset 100`

---

### CRITICAL-03：CLO 响应误解（设计 §6 S5）

**文件**：25-opcua-design.md §6 S5，第 886-899 行；§6.1 速查表

**问题描述**：设计文档将 CLO（CloseSecureChannel）描述为双向（包 22 CLO 请求 + 包 23 CLO 响应），但 OPC UA Part 4 §5.13.3 定义 CloseSecureChannel 为**单向服务**（one-way）：客户端发送请求后，服务器直接关闭 TCP 连接，没有响应消息。

**影响**：
- 所有涉及 CLO 的包数计算多算了 1 个包（CLO 响应）
- §6.1 速查表 S2/S3/S5 的"末段"列多算了 1 包
- 设计 §6 S5 序列中包 23 不应存在

**修复建议**：
1. 删除所有 CLO 响应包（如 S5 的包 23）
2. 修正所有场景的包数重新计算
3. §6 S5 序列改为：CLO（包 22）→ FIN（包 23）/ FIN-ACK（包 24）/ ACK（包 25）

**交叉验证**：JSON `opcua_subscribe` 的 notes 明确标注 "CLO is one symmetric message and has no CLO response"，且包数 21 不含 CLO 响应。JSON 正确，design 错误。

---

### CRITICAL-04：Testcase T1 vs JSON T1——HEL MessageSize 冲突

**文件**：25-opcua-testcase.md §2.1 vs cases/opcua.json 第 1 条

**问题描述**：testcase 文档 T1 的帧断言写 `48454c46 1c000000`（MessageSize=28），但 JSON 写 `48454c46 20000000`（MessageSize=32）。两者直接冲突。

**影响**：如果按 testcase 文档实现，会生成错误断言；如果按 JSON 实现，testcase 文档成为错误指导。

**修复建议**：统一为 `20000000`（32），并同步修正 testcase 文档中所有"MessageSize=28"的说法。

---

### CRITICAL-05：Testcase 包数与 JSON 大面积不匹配

**文件**：25-opcua-testcase.md §2 各用例 vs cases/opcua.json 各用例

**问题描述**：testcase 文档的 `packet_count` 与 JSON 大面积不一致，详见下表：

| 用例 | testcase 文档 | JSON | 差异原因 |
|------|-------------|------|---------|
| T1 opcua_hello_ack | 10 | 11 | 文档可能漏算 CLO 或 FIN 包 |
| T2 opcua_open_none | 10 | 13 | 文档漏算 Read 服务对（2 包）和 CLO 响应方向 |
| T3 opcua_open_sign | 8 | 11 | 文档漏算 TCP 关闭 3 包 |
| T5 opcua_write | 12 | 13 | 文档漏算 1 包（CLO 响应方向） |
| T6 opcua_browse | 12 | 13 | 同上 |
| T7 opcua_subscribe | 26 | 21 | 文档多算了 CLO 响应 + 订阅包数计算错误 |
| T9 opcua_bad_node | 10 | 13 | 文档漏算 Read 服务对 + CLO 方向 |
| T10 opcua_denied | 10 | 13 | 同上 |
| T11 opcua_ipv6 | 10 | 13 | 同上 |
| T12 opcua_multi_session | 20 | 17 | 文档多算了 CLO 响应和 FIN 包数 |

**影响**：testcase 文档作为测试设计和验收依据不可信。

**修复建议**：统一以 JSON 为准（JSON 已经过生成器验证），逐用例修正 testcase 文档的 `packet_count`。

---

### CRITICAL-06：JSON 缺失 opcua_read（T4）用例

**文件**：cases/opcua.json

**问题描述**：testcase 文档定义 T4 "opcua_read" 为独立测试 Read 多 NodeId 的用例，但 JSON 中没有对应的 `opcua_read` 条目。Read 功能仅作为 `opcua_open_none` 的附属被间接测试，不是一个独立的原子用例。

**影响**：
- Read 多 NodeId 没有独立的原子断言
- 无法单独验证 Read 请求的 AttributeId、NodesToRead 数组、ResponseHeader 回显
- 违反"原子化"原则（综合 case 掩盖独立分支）

**修复建议**：在 JSON 中增加 `opcua_read` 用例，独立验证 Read 多 NodeId、AttributeId=13、偏移 99/100 的黄金锚点。

---

### CRITICAL-07：JSON 缺失 opcua_keepalive（T8）用例

**文件**：cases/opcua.json

**问题描述**：testcase 文档定义 T8 "opcua_keepalive" 为独立测试 keep-alive 空转的用例，但 JSON 中没有对应的 `opcua_keepalive` 条目。keep-alive 行为仅作为 `opcua_subscribe` 的附属（`publish_count:2, keep_alive:true`）被间接测试。

**影响**：
- keep-alive 空转（无 Notification，SequenceNumber 不变）没有独立断言
- 无法验证 `max_keep_alive_count` 配置行为
- 违反"原子化"原则

**修复建议**：在 JSON 中增加 `opcua_keepalive` 用例，使用 `publish_count:1, keep_alive:true, max_keep_alive_count:3` 等配置独立验证 keep-alive 行为。

---

### CRITICAL-08：SecurityPolicy URI 域名错误且长度不符实际

**文件**：25-opcua-design.md §4.2，第 457-461 行

**问题描述**：设计文档声称 SecurityPolicy URI 使用 `opc.tcp://` 协议前缀，且 None 为 70 字节、Basic256Sha256 为 102 字节。但 OPC Foundation 规范（Part 7 §6.2）和 open62541 实际使用的 URI 为 `http://opcfoundation.org/UA/SecurityPolicy#None`（47 字节）和 `http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256`（57 字节）。

实际字节长度验证：
- `http://opcfoundation.org/UA/SecurityPolicy#None` = 47 字节
- `http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256` = 57 字节
- 设计声称 None=70 字节、Basic256Sha256=102 字节（均错误）

**影响**：
- 设计 §4.2 表格中 SecurityPolicyUri 长度字段全部错误
- 设计 §3.5 大小计算表 OPN 请求/响应的 MessageSize 全部错误
- 设计 §6 S2R1/S2R2 的 HexDump 偏移标注全部错误（PolicyUri 实际 47B 而非 70B）
- 实现如按设计文档编码，会生成不被 Wireshark 识别的 SecurityPolicy URI

**修复建议**：
1. 修正 SecurityPolicy URI 为标准的 `http://opcfoundation.org/UA/SecurityPolicy#None`（47B）和 `#Basic256Sha256`（57B）
2. 重新计算 §3.5 大小表
3. 重新计算 §6 S2R1/S2R2 的 HexDump 偏移
4. 补充黄金向量中的 URI 编码示例

**文件**：25-opcua-design.md §5.2，第 558-585 行

**问题描述**：设计文档的 `OPCUAConfig` 结构体没有 `error_inject` 字段，但 testcase 文档 T9/T10 和 JSON 中使用了 `"error_inject": { "op": "bad_node" / "denied" }`。设计文档也未定义 `error_inject` 的配置结构和语义。

**影响**：T9/T10 的配置在设计中无定义，实现阶段可能遗漏。

**修复建议**：在 §5.2 增加 `ErrorInject *ErrorInjectConfig` 字段，并定义 `ErrorInjectConfig` 结构体（含 `op` 枚举和 `node` 参数）。

---

### MAJOR-02：T13 spec_json 不一致（close 策略）

**文件**：25-opcua-testcase.md §2.13 vs cases/opcua.json 第 11 条

**问题描述**：testcase 文档 T13 的 spec_json 有 `"close": true`，但 JSON 设为 `"close": false`。负例中 `close: false` 更合理（错误字节导致无法正常关闭），两者不一致。

**修复建议**：统一为 `"close": false`，并确保 testcase 文档和 JSON 一致。

---

### MAJOR-03：T14 spec_json 缺少 read 服务

**文件**：25-opcua-testcase.md §2.14 vs cases/opcua.json 第 12 条

**问题描述**：testcase 文档 T14 的 spec_json 只有 `"skip_channel": true`，没有 `read` 服务；但 JSON 明确包含 `"read": [{ "node_ids": ["ns=0;i=1001"], "attribute_id": 13 }]`。没有 read 服务则"未建通道即服务调用"的语义无法触发。

**修复建议**：testcase 文档增加 `read` 服务配置，与 JSON 一致。

---

### MAJOR-04：设计文档无 error_inject 配置段（设计 §9）

**文件**：25-opcua-design.md §9

**问题描述**：§9.2 提到"error_inject 配置段"，但未定义其结构。§9.6 的 walkthrough 描述了 error_inject 的行为，但没有给出正式的配置结构定义。

**修复建议**：在 §5.2 或 §9 新增 ErrorInject 配置结构的正式定义。

---

### MAJOR-05：T9/T10 缺少 StatusCode 帧断言

**文件**：25-opcua-testcase.md §2.9/§2.10 vs cases/opcua.json §7/§8

**问题描述**：T9（BadNodeIdUnknown）和 T10（BadUserAccessDenied）的帧断言只验证了 MSG 头部存在，没有断言 StatusCode 的具体值。JSON 的 notes 承认 "absolute offset is intentionally not hard-coded"，但缺乏 field 断言或替代验证手段。

**影响**：用例退化为"结构存在"，未证明错误码被正确注入。

**修复建议**：
1. 增加 `fields` 断言用 `opcua.statuscode`（若 tshark 支持）或
2. 通过定向计算增加 `frames` 偏移断言 `00 00 34 80` / `00 00 1f 80` 或
3. 使用 `nonzero` 或 `same_as_packet` 跨包断言 ServiceResult 差异

---

## 2. 用例覆盖审查 Findings

### COVERAGE-01：无 SecurityPolicyUri 字节级断言

**覆盖缺口**：设计 §4.2 定义了 None（70 字节）和 Sign（102 字节）两种 SecurityPolicyUri，但没有任何用例通过 `frames` 断言 URI 的具体字节内容。

**影响**：如果实现将 None URI 写错（如少写字节、用错 URI），现有断言无法捕获。

**建议**：T2 增加 `offset 66` 处的前几个 URI 字节断言（如 `6f 70 63 2e` = "opc."），T3 增加 URI 前缀断言。

---

### COVERAGE-02：无多流（多 TCP 连接）用例

**覆盖缺口**：设计 §1.5 提到"多会话"（同一 TCP 连接上的多个逻辑会话），但没有覆盖"多流"（多个独立的 TCP 连接）。ENIP 等其他协议有双流用例。

**影响**：多流场景的并发行为未验证。

**建议**：在 testcase 中增加双流用例（两个独立的 TCP 连接同时进行 OPC UA 会话）。

---

### COVERAGE-03：ERR 消息无独立用例

**覆盖缺口**：设计 §3.2 和 §6 S1R2 定义了 ERR 消息格式，但 T13 只验证了"坏 MessageSize 被 expect_error 捕获"，没有独立用例验证 ERR 消息的生成（ErrorCode + ErrorReason 的线格式）。

**建议**：增加 T15 验证 ERR 消息的线格式（`45 52 52 46` + ErrorCode + ErrorReason String）。

---

### COVERAGE-04：Write/Read 响应值无断言

**覆盖缺口**：T5（Write）和 T4（Read）的帧断言只验证了请求头部，没有断言响应体中的写结果（UInt32[] 的 Good=0）或读结果（DataValue 的 Variant 值）。

**建议**：T5 增加对 WriteResponse Results 数组的断言，T4 增加对 ReadResponse DataValue 结构的断言。

---

### COVERAGE-05：订阅周期订阅 ID 和通知序列号无断言

**覆盖缺口**：T7 只断言了各请求的 MSG 头部存在，没有断言 CreateSubscription 响应中的 SubscriptionId，也没有断言 Publish 通知中的 SequenceNumber 递增。

**建议**：增加对两个 Publish 通知的 SequenceNumber 相对断言（`same_as_packet` 或 `nonzero`）。

---

### COVERAGE-06：IPv6 下端口/协议字段无断言

**覆盖缺口**：T11 验证了帧偏移 74 处的 MessageHeader，但没有验证 `frame.protocols` 包含 IPv6 或 `ip.version==6`。

**建议**：T11 增加 `{ "field": "ip.version", "value": "6" }` 断言。

---

## 3. 待实现边界清单

| 编号 | 内容 | 说明 |
|------|------|------|
| B1 | OPC UA 层注册（registry.go） | 尚无 `"opcua"` 层注册，`CategoryTerminal` + `DependsOn: ["tcp"]` |
| B2 | planOpcuaSession 生成器 | 四阶段状态机（S1-S4）尚未实现 |
| B3 | uaBuffer 编码器 | 两遍编码 + 小端写尚未实现 |
| B4 | OPCUAConfig 解析 | strategy_convert.go 尚无 `case "opcua"` |
| B5 | ValidateOPCUAConfig | validate.go 尚无校验逻辑 |
| B6 | 真实密码学（Sign 模式） | 设计已标注"零填充占位"，实现阶段不要求真实 RSA 签名 |
| B7 | ERR 消息生成 | 生成器当前不产生 ERR 消息，仅靠 expect_error 捕获 |
| B8 | 多流双 TCP 连接 | 设计未覆盖，需后续补 |
| B9 | tshark opcua 解码器 | 当前 Wireshark 无 packet-opcua.c，所有断言靠 FrameAssert 原始字节。搜索确认：Wireshark 官方 dissectors 列表中无 `opcua` 条目，`-d tcp.port==4840,opcua` 在当前版本无效。这与 testcase 文档 §4.1 的描述一致。

---

## 4. 交叉一致性校验总表

| 检查项 | design | testcase | JSON | 结论 |
|--------|--------|----------|------|------|
| HEL MessageSize | 28（错误） | 28（错误） | 32（正确） | 不一致，design/testcase 错误 |
| ACK MessageSize | 28（正确） | 28（正确） | 28（正确） | 一致 |
| T1 packet_count | – | 10 | 11 | 不一致 |
| T2 packet_count | – | 10 | 13 | 不一致 |
| T3 packet_count | – | 8 | 11 | 不一致 |
| T4 存在 | ✓ | ✓ | ✗（缺失） | 不一致 |
| T5 packet_count | – | 12 | 13 | 不一致 |
| T6 packet_count | – | 12 | 13 | 不一致 |
| T7 packet_count | – | 26 | 21 | 不一致 |
| T8 存在 | ✓ | ✓ | ✗（缺失） | 不一致 |
| T9 packet_count | – | 10 | 13 | 不一致 |
| T10 packet_count | – | 10 | 13 | 不一致 |
| T11 packet_count | – | 10 | 13 | 不一致 |
| T12 packet_count | – | 20 | 17 | 不一致 |
| T13 close | – | true | false | 不一致 |
| T14 read service | – | 无 | 有 | 不一致 |
| CLO 响应 | 有（错误） | 有（错误） | 无（正确） | 不一致，JSON 正确 |
| error_inject 配置 | 未定义 | 使用 | 使用 | 不一致 |

---

## 5. 修复优先级建议

### 第一优先（阻塞实现）
1. **CRITICAL-01**：修正 HEL EndpointUrl 缺失——所有 MessageSize 偏移都会变，是最基础的修复
2. **CRITICAL-02**：修正 AuthToken 编码偏移——影响所有帧断言偏移
3. **CRITICAL-03**：修正 CLO 响应方向——影响所有包数计算
4. **CRITICAL-05**：统一包数——以 JSON 为准修正 testcase 文档

### 第二优先（用例完整性）
5. **CRITICAL-06**：JSON 增加 opcua_read 用例
6. **CRITICAL-07**：JSON 增加 opcua_keepalive 用例
7. **MAJOR-01/MAJOR-04**：设计文档增加 error_inject 配置定义

### 第三优先（同步修复）
8. **CRITICAL-04**、**MAJOR-02**、**MAJOR-03**：testcase 与 JSON 的 spec_json 差异
9. **MAJOR-05**：T9/T10 增加 StatusCode 断言
10. COVERAGE-01~06 覆盖缺口

---

*本报告基于设计文档 v1.0.0 / testcase 文档 v1.0.0 / cases/opcua.json 生成，审查结论为"文档阶段存在 CRITICAL 不一致，需修复后进入实现阶段"。*