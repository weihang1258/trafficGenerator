# MQTT 设计文档复审审计报告（v2.0.0 / R1-v2）

**审计对象**：`docs/protocol-designs/14-mqtt-design.md`（v2.0.0，3235 行）
**审计日期**：2026-08-05
**审计人**：独立协议审计（复审；v2.0.0 声称已修复 deep-r2 审计 17 问题）
**审计依据**：
1. MQTT 3.1.1（OASIS Standard 2014 / ISO 20922:2016）
2. MQTT 5.0（OASIS Standard 2018）
3. 上一轮审计（deep-r2，`docs/protocol-designs/audit/14-mqtt-audit-deep.md`，17 问题）
4. `CLAUDE.md` 测试策略 8 条强制规则

**审计方法**：逐节核对 + 所有 HexDump 逐字节独立核算（不信任文档自带核算）+ 关键规范条款 WebFetch 核实。

---

## 1. 审计概览

### 1.1 总体结论

**否**——文档**不能**直接进入实现阶段。

v2.0.0 修复了 deep-r2 审计的 17 个问题中的大部分（属性 ID 表已全部对照规范核实无误：0x18=Will Delay Interval、0x1A=Response Information、0x15=Authentication Method、0x19=Request Response Information、0x21=Receive Maximum、0x13=Server Keep Alive、0x1F=Reason String、0x22=Topic Alias Maximum 全部正确；148/141 仅 DISCONNECT 的区分正确；5.0 CONNACK 22 个代码表与规范完全一致；DISCONNECT 31 个代码表与规范完全一致）。

但本轮审计发现 **v2.0.0 新引入或未根治的硬错误 12 处**，其中：

- **2 处 CRITICAL**：§6 S2 的 CONNECT Remaining Length 错误（`0x12` 应为 `0x1a`）；§6 S3/S4 的 PUBLISH Remaining Length 错误（`0x0f`/`0x10` 应为 `0x15`）。这些是 T-182/T-183 等"字节级完整场景"测试的断言基准，将直接导致实现产出畸形包。
- **2 处 CRITICAL**（HexDump 大量字节与声明的 Remaining Length 不自洽）：S7/S9/S10 CONNECT 与 S9 Will PUBLISH 的 Remaining Length 全部错误（详见 §2）。
- **1 处 HIGH**：UTF-8 字符串长度上限表述与规范不符——文档声称"最大 0xFFFE（65534 字节）、0xFFFF 保留"，规范实际允许 0-65535（0xFFFF）全范围。
- **1 处 HIGH**：T-021 期望字节错误（`30 06 00 01 74 00 70` 的 Remaining Length 实际为 5，非 6）。
- **1 处 HIGH**：T-160/T-161 内容重复（同一条测试编号重复定义），且与 T-037/T-197 重复。
- **1 处 HIGH**：文档自相矛盾——T-083 期望 Topic 长度字段 `0xFF 0xFF`（65535）"Validate 通过"，与 §2.4 声称"0xFFFF 保留/最大 0xFFFE"直接冲突；且 65535 字节 topic 的 PUBLISH 无法单包承载（VBI 上限 268435455 可容纳，但 packet 层面 MSS 分段可以处理，矛盾在于长度字段语义）。
- **多处 MEDIUM/LOW**：见 §3-§4。

### 1.2 严重度分布

| 严重度 | 数量 | 说明 |
|--------|------|------|
| CRITICAL | 4 | S2/S3/S4/S7/S9/S10 HexDump Remaining Length 系统性错误（T-182/T-183/T-184 断言基准错误）；T-021 期望字节错误 |
| HIGH | 4 | UTF-8 长度上限与规范不符；T-160/T-161 重复定义；T-083 与 §2.4 自相矛盾；S15 的 CONNECT 省略 Remaining Length 字节违反"逐字节核算"原则 |
| MEDIUM | 3 | T-004/T-132 重复（同一件事两条测试）；§4.4 will 状态机与 planner 实现矛盾（RST 场景 will 在 RST 前发布 vs 规范 will 在断开后才发布）；KeepAlive 继承语义未定义（session 空 vs 显式 0） |
| LOW | 1 | §8.7.4 字段计数错误（MQTTTopicFilter 标"全部 4 字段"但列出 5 个字段名；MQTTSession 标"13 字段"但 struct 仅 12 个字段名） |
| **合计** | **12** | |

---

## 2. CRITICAL 问题

### C-R1：§6 S2 CONNECT Remaining Length 错误（`0x12` → 应为 `0x1a`）

**位置**：§6 S2（行 1094）CONNECT 字节 `10 12 00 04 4d 51 54 54 04 02 00 3c 00 0e 74 65 6d 70 2d 73 65 6e 73 6f 72 2d 30 31`；同场景行 1103 的自带核算也错误。

**描述**：文档声称 Remaining Length = 18（0x12），核算为 `10 (VH) + 2 (ClientID Len) + 14 ("temp-sensor-01") = 18`。但实际字节数：VH=10 + ClientID 长度字段 2 + ClientID 14 = **26 字节**（0x1a）。文档自己的字节序列 `... 00 0e 74 65 6d 70 2d 73 65 6e 73 6f 72 2d 30 31` 含 2 字节长度前缀 + 14 字节 ClientID。文档把"2 (ClientID Len)"写进了 10 字节 VH，同时又把 14 字节算进 payload——**双重计算错误**：VH=10 已含协议名 2+4、Level 1、Flags 1、KeepAlive 2，**不含** ClientID 长度字段。

**依据**：MQTT 3.1.1 §3.1（CONNECT 格式）：Variable Header = Protocol Name (2+4) + Protocol Level (1) + Connect Flags (1) + Keep Alive (2) = **10 字节**；Payload 从 ClientID 长度字段开始（2 字节长度 + N 字节）。Remaining Length = 10 + 2 + 14 = **26 = 0x1a**。文档输出 `10 12` 的包会被任何 broker 判为 Malformed Packet（内容 26 字节与 RL=18 不符，字节流解析错位，ClientID 会被读成 "m-sensor" 之类）。

**修复建议**：S2 CONNECT 改为 `10 1a 00 04 4d 51 54 54 04 02 00 3c 00 0e 74 65 6d 70 2d 73 65 6e 73 6f 72 2d 30 31`；核算行改为 `= 10 (VH) + 2 (ClientID Len) + 14 (ClientID) = 26`。T-182（S2 完整字节序列）的断言基准同步修正。注意 T-001（默认 CONNECT `10 0e ... 00 02 63 31`）是**正确**的（10+2+2=14），说明这是 S2 单独引入的错误——VH 计算时把 ClientID 长度字段算进了 VH。

### C-R2：§6 S3/S4 PUBLISH Remaining Length 错误（`0x0f`/`0x10` → 应为 `0x15`）

**位置**：§6 S3（行 1143）PUBLISH QoS1 字节 `32 0f 00 0a 61 6c 65 72 74 2f 66 69 72 65 00 64 57 41 52 4e 49 4e 47`；§6 S4（行 1184）PUBLISH QoS2 字节 `34 10 00 0a 62 69 6c 6c 69 6e 67 2f 74 78 00 07 54 58 31 32 33 34 35`。

**描述**：
- S3：文档核算 `2 (Topic Len) + 10 (topic) + 2 (PacketID) + 7 (payload) = 15`（0x0f）。但实际字节：Topic 长度字段 2 + topic 10 + PacketID 2 + payload 7 = **21 字节 = 0x15**。文档把 "2 (Topic Len)" 也算在 10 字节 topic 内又单独列出——重复计算 2 字节。实际字节序列长度 21 与 RL=15 不符。
- S4：同样问题：`2 + 10 + 2 + 7 = 21 = 0x15`，文档写 `0x10`（16）。文档自带核算 `2 + 10 + 2 + 7 = 16` 把 2 (Topic Len) 与 10 (topic) 写成相加 10——实际应为 2+10+2+7=21。

**依据**：MQTT 3.1.1 §3.3（PUBLISH 格式）：Variable Header = Topic Name（2 字节长度 + N 字节）+ [Packet Identifier 2 字节 if QoS>0] + 5.0 Properties。Remaining Length = 2+10+2+7 = 21 = `0x15`。对照：S2 的 PUBLISH QoS0（`30 11 00 0b ...`，RL=17=2+11+4）是**正确**的（v2.0.0 已修复 deep-r2 C-D2），说明 S3/S4 是 v2.0.0 重写时新引入的错误——"2 (Topic Len)"被算进了 topic 长度基数。

**修复建议**：S3 PUBLISH 改为 `32 15 00 0a 61 6c 65 72 74 2f 66 69 72 65 00 64 57 41 52 4e 49 4e 47`；S4 PUBLISH 改为 `34 15 00 0a 62 69 6c 6c 69 6e 67 2f 74 78 00 07 54 58 31 32 33 34 35`。T-055/T-056/T-183 断言基准同步修正。

### C-R3：§6 S7 CONNECT Remaining Length 错误（`0x0c` → 应为 `0x13`）

**位置**：§6 S7（行 1279）CONNECT 字节 `10 0c 00 04 4d 51 54 54 04 02 00 1e 00 07 70 69 6e 67 2d 30 31`。

**描述**：文档未给出此 CONNECT 的核算（只核算了 KeepAlive 字段），但 Remaining Length=0x0c（12）与实际字节不符：VH 10 + ClientID 长度字段 2 + "ping-01" 7 = **19 = 0x13**。字节序列本身是完整的（`00 07` 长度 + 7 字节 "ping-01"），只是 RL 字段错了。

**依据**：同 C-R1，RL = 10 + 2 + 7 = 19 = `0x13`。

**修复建议**：改为 `10 13 00 04 4d 51 54 54 04 02 00 1e 00 07 70 69 6e 67 2d 30 31`。T-062 断言基准同步。

### C-R4：§6 S9 CONNECT 与 Will PUBLISH Remaining Length 错误（`0x1d`/`0x14` → 应为 `0x2d`/`0x18`），且自带核算错误

**位置**：§6 S9（行 1339）CONNECT 字节 `10 1d ...`；行 1341 Will PUBLISH 字节 `32 14 ...`；行 1347-1368 自带核算。

**描述**：
- CONNECT：文档核算 `= 10 (VH) + 2 (ClientID Len) + 9 (ClientID) + 2 (Will Topic Len) + 13 (Will Topic) + 2 (Will Payload Len) + 7 (Will Payload) = 29`（0x1d）。但实际：10 + (2+9) + (2+13) + (2+7) = **45 = 0x2d**。文档把 "2 (ClientID Len)" 错算进 VH（10 里没有它），又单独列出——与 C-R1 同型错误，此场景为 will 版本。字节序列 45 字节 vs RL=29。
- Will PUBLISH：文档核算 `= 2 (Topic Len) + 13 (topic) + 2 (PacketID) + 7 (payload) = 20`（0x14）。实际 = 2+13+2+7 = **24 = 0x18**。同样的"长度字段被算进字段本身"重复错误。

**依据**：MQTT 3.1.1 §3.1：CONNECT Payload 顺序 = Client Identifier (2-len + bytes) + [Will Topic (2-len + bytes)] + [Will Payload (2-len + bytes)]...每个长度前缀独立。RL = 10 + 11 + 15 + 9 = 45 = `0x2d`。PUBLISH RL = 2+13+2+7 = 24 = `0x18`。

**修复建议**：CONNECT 改为 `10 2d ...`（RL 0x1d → 0x2d），核算行改为 `= 10 (VH) + (2+9) (ClientID) + (2+13) (Will Topic) + (2+7) (Will Payload) = 45`；Will PUBLISH 改为 `32 18 ...`（0x14 → 0x18）。T-184 断言基准同步。

### C-R5：§6 S10 CONNECT Remaining Length 错误（`0x0b` → 应为 `0x0e`）

**位置**：§6 S10（行 1407）Flow 1 CONNECT 字节 `10 0b 00 04 4d 51 54 54 04 02 00 3c 00 02 73 31`。

**描述**：RL=0x0b（11）但实际：VH 10 + ClientID 长度字段 2 + "s1" 2 = **14 = 0x0e**。文档未给核算。同 C-R1 型错误。

**依据**：同前。`10 0e 00 04 4d 51 54 54 04 02 00 3c 00 02 73 31`。

**修复建议**：改为 `10 0e ...`。T-063 断言基准同步（注意此错误已在 S1 中正确，说明 v2.0.0 重写时 Flow 1 示例是复制粘贴后未更新 RL）。

### C-R6：T-021 期望字节错误（`30 06` → 应为 `30 05`）

**位置**：§7.1 T-021（行 1795）"5.0 PUBLISH 无属性 Properties Length=0x00 必填"：期望 `30 06 00 01 74 00 70`。

**描述**：`30 06 00 01 74 00 70`：Remaining Length=6，但内容 = Topic 长度字段 2 + topic "t" 1 + Properties Length 1 + payload "p" 1 = **5 字节 = 0x05**。文档自身注释写 "RemainingLen=6"，但 5.0 QoS0 PUBLISH（无属性）RL = 2+1+1+1 = 5。6 是错的。

**依据**：MQTT 5.0 §3.3：RL = Topic Name (2+1) + Properties Length (1) + Payload (1) = 5 = `0x05`。正确字节应为 `30 05 00 01 74 00 70`。

**修复建议**：T-021 期望改为 `30 05 00 01 74 00 70`。

---

## 3. HIGH 问题

### H-R1：UTF-8 字符串长度上限表述与规范不符（0xFFFF 保留的说法错误）

**位置**：§2.4（行 157）"长度字段不得为 0xFFFF（保留），最大 0xFFFE（65534 字节）"；§8.1 第 9 条 "Topic 长度 ≤ 65535"；T-083 与 T-167。

**描述**：文档声称 UTF-8 字符串长度字段 0xFFFF 保留、最大 0xFFFE。MQTT 5.0 §1.5.4 原文："the maximum size of a UTF-8 Encoded String is 65,535 bytes"、"all UTF-8 encoded strings can have any length in the range 0 to 65,535 bytes"。**0xFFFF（65535）完全合法**，没有保留值。该错误来自对 MQTT 3.1.1 早期草案或与 MQTT-SN 的混淆。

**影响链**：
1. §8.1 Validate 第 9 条写 "Topic 长度 ≤ 65535"（正确），与 §2.4 "最大 0xFFFE" 自相矛盾。
2. T-083（topic 65535 字节）期望"Topic Name 长度字段 `0xFF 0xFF`；Validate 通过"——按 §2.4 的规则 65535 应报错，测试自相矛盾。
3. T-167 更混乱："topic 长度 65535。断言：Validate 通过（65535 ≤ 65535 Binary Data 限制，但 UTF-8 字符串限制是 65534——设计选择：planner 接受 65535 但 65536 报错）"——把 Binary Data 限制（最大 65535）与 UTF-8 限制（也最大 65535）混为一谈，还声称 65534 是 UTF-8 上限，自相矛盾。

**依据**：MQTT 5.0 §1.5.4（已 WebFetch 核实）；MQTT 3.1.1 §1.5.3 同样无 0xFFFF 保留。

**修复建议**：§2.4 改为 "长度字段 2 字节大端，最大 0xFFFF（65535 字节）"；删除"0xFFFF 保留"说法；T-167 重写为单一断言（65535 通过、65536 报错）。

### H-R2：T-160 与 T-161 重复编号

**位置**：§7.14 T-160（行 2567）"PUBLISH QoS0 + PacketID 报错"；T-161（行 2572）"PUBLISH QoS=3 报错"。

**描述**：T-160 的场景是 `qos: 0, packet_id: 1`，但**断言写的却是 QoS=3**（"planner 忽略 PacketID...；或 Validate 报错"），与 T-161 的断言完全重复。T-160 的实际应测行为（QoS0 + PacketID 是否忽略/报错）没有明确断言，仅"设计选择：planner 忽略"一句。另外 T-161 与 T-037（QoS=3 被拒绝）、T-197（PUBLISH QoS=11 报错——注意 T-197 场景写 `qos: 3` 却叫 "QoS=11"，编号名错误）内容重复。

**依据**：测试质量规则（CLAUDE.md §1/§8）：每条测试必须测一个明确行为，不重复、不空转。

**修复建议**：T-160 改为明确断言"QoS0 + 显式 packet_id → Validate 报错（或 planner 忽略并丢弃该字段）"，二选一明确；T-197 编号名改为 "PUBLISH QoS=3 报错" 或合并到 T-161。

### H-R3：S15 CONNECT 缺 Remaining Length 实际字节，违反"逐字节核算"原则

**位置**：§6 S15（行 1601）CONNECT 字节 `10 <len> 00 04 4d 51 54 54 05 02 00 1e <PropertiesLen=0x00> 00 0a 74 69 6d 65 6f 75 74 2d 30 31`；行 1606-1616 核算 `10 / <RemainingLen> / ...`。

**描述**：S15 是 v2.0.0 新增的"Keep Alive 超时（5.0 DISCONNECT Reason=0x8D）"场景，但 CONNECT 的 Remaining Length 没有给出数值（占位符 `<len>`/`<RemainingLen>`），且 Properties Length 写为 `<PropertiesLen=0x00>` 与核算部分 `00` 不一致（占位符未替换）。这与本场景宣称的"逐字节核算"自洽性要求冲突——T-187 只断言 DISCONNECT 字节，但 T-185 类"完整字节序列"测试若覆盖 S15 将无基准。实际 RL = 10 (VH) + 1 (Properties Length) + 2 + 10 ("timeout-01" 10 字节) = 23 = `0x17`。

**依据**：文档 §6 引言（行 1037）"每个场景包含：输入 spec、完整 PacketConfig 序列表、关键 MQTT 字节 HexDump、逐字节核算"。

**修复建议**：S15 CONNECT 改为 `10 17 00 04 4d 51 54 54 05 02 00 1e 00 00 0a 74 69 6d 65 6f 75 74 2d 30 31` 并补核算。

### H-R4：Will 状态机与 planner 行为矛盾（RST 场景 will 在 RST 前发布 vs 规范语义）

**位置**：§4.4（行 731-748）will 状态机；T-169（行 2614-2617）"RST=true + will message：will PUBLISH 在 RST 之前；包总数 = 8（3 握手 + CONNECT + CONNACK + will PUBLISH + PUBACK + RST）"。

**描述**：T-169 期望 will PUBLISH 在**客户端自己发出的 RST 之前**——即客户端"模拟断开后 broker 发 will"的序列。但 RST 是客户端发的（trafficgen 模拟客户端），而规范中 will 由 broker 在检测到连接异常断开后**替客户端**发布。客户端先发 RST、随后同一方向再发 will PUBLISH（down 方向）与 PUBACK（up 方向）——按 QoS1 流程这要求"server→client 的 will PUBLISH"在客户端 RST 之后仍可交换，这在 TCP 语义上不成立（RST 后该 TCP 连接已终止，不能继续在 4-tuple 上传包）。§4.4 的 planner 简化说"于 TCP 挥手前插入 will PUBLISH 下行段"，但 T-169 说 RST 是最后一个包、will 在 RST 前——与"断开后才发 will"的规范语义矛盾：如果 will PUBLISH 在 RST 之前，那么 RST 时连接还没"异常断开"，will 不该发；如果 will 在 RST 之后，TCP 已死无法传包。S9（FIN 变体）同样问题：will PUBLISH 在 FIN 前发出，而规范中 FIN 是客户端主动正常断开——正常断开时 broker **不发布** will（§4.4 自己写了"正常 DISCONNECT ──► Will 被 broker 丢弃"；FIN 挥手是客户端发起的正常关闭，等同主动断开）。文档 §1.4 说"不发真正的 broker 转发逻辑；will/retain 场景由 planner 直接编排为'客户端断线 → broker 发 will PUBLISH'的字节序列"——但编排的字节序列把 will 放在了断开**之前**，与"断线后 broker 代发"的语义在字节序上矛盾（真实 pcap 中 will PUBLISH 确实出现在 FIN/RST 之后由 broker 从**对端**发出，trafficgen 无法建模跨连接，但至少应在文档中说明该简化并给出与规范一致的时序：FIN/RST 之后无 MQTT 包）。

**依据**：MQTT 3.1.1 §3.1.2.5（Will Flag）/ §4.1；5.0 §3.1.3.2（Will 在连接异常关闭后发布）；TCP 语义（RST/FIN 终止连接，之后无数据）。

**修复建议**：明确 will 场景是"broker 视角的单向字节序列建模"（同一 4-tuple 上 broker 在断开后发出 will PUBLISH + 收 PUBACK 是模拟而非真实 TCP 语义），并在文档中标注此简化为已知模型偏差；或将 will PUBLISH 编排在 FIN 之前的理由（"模拟 broker 已收到断开事件"）写明。至少 T-169 的"will 在 RST 前"需要一句理由说明，否则实现者无法判断意图。

---

## 4. MEDIUM 问题

### M-R1：T-004 与 T-132 内容重复

**位置**：T-004（行 1676-1680）"CONNACK 5.0 Reason Code 域"表驱动 22 个代码；T-132（行 2415-2418）"CONNACK 5.0 全部 22 个有效代码"表驱动 22 行。

**描述**：两条测试完全同场景、同断言（Validate 通过 + CONNACK byte[2] 匹配 + Code≠0 无后续）。T-004 在 §7.1，T-132 在 §7.8 "5.0 Reason Code 域完整测试"，声称"完整"但内容与 T-004 相同。§7.21 计数把两者都算入 200 条，虚增数量。另外 §7.8 标题为"5.0 Reason Code 域完整测试"但 T-133 是 DISCONNECT 31 个代码、T-134 是 SUBACK——命名混乱。

**依据**：CLAUDE.md §8 测试质量审查：重复测试虚增覆盖率。

**修复建议**：删除 T-132 或将 T-132 扩展为"每条代码独立测试文件/独立测试函数"（表驱动外显式列出），T-004 保留为 Validate 域测试、T-132 改为逐条独立断言。

### M-R2：KeepAlive 继承语义未定义（session 显式 0 vs 空）

**位置**：§5.6 MQTTSession（行 983）`KeepAlive *int`；§8.6 继承规则表（行 2900）"标量（KeepAlive/...）session 字段为零值/nil → 继承顶层"。

**描述**：KeepAlive 是 `*int`，顶层语义是 nil→60、*0→禁用。§8.6 说 session 字段"为零值/nil → 继承顶层"——但 `*int` 的"零值"是 nil，无法表达"显式 0"。若 session 设 `keep_alive: 0`（意图禁用保活），按 §8.6 的规则是 nil 继承顶层 60 还是显式 0 覆盖？文档未定义 `*int` 的显式 0 在 session 层的语义。T-177（Session KeepAlive 继承）只测了"顶层 120、session 不设 → 继承 120"，没测"session 显式 0"。

**依据**：§5.1 KeepAlive 注释明确了 `*int` 的三态语义（nil/0/N），该语义必须在继承层同样定义。

**修复建议**：§8.6 明确：`*int` 类型 session 字段 nil → 继承顶层；非 nil（含 0）→ 覆盖。并补一条测试：顶层 KeepAlive=60 + session `keep_alive: 0` → session CONNECT 输出 `00 00`。

### M-R3：T-115 与 T-020/T-021/T-022/T-023 重复且范围混乱

**位置**：T-115（行 2314-2321）"v5 无属性四包型 Properties Length=0x00"表驱动 4 行（CONNECT/CONNACK/PUBLISH/SUBACK）。

**描述**：T-115 的 4 行与 T-020（CONNACK）、T-021（PUBLISH）、T-022（SUBACK）、T-023（Will Delay，不同）、T-002（CONNECT 含属性）**重叠**——CONNECT 无属性版在 T-115 第 1 行，但 §7.1 没有单独的"CONNECT 无属性 Properties Length=0x00"测试（T-002 是含属性的）；CONNACK/PUBLISH/SUBACK 无属性版已在 T-020/021/022 全覆盖。T-115 唯一新增的是 CONNECT 无属性一行。表驱动 4 行中 3 行是重复。

**依据**：CLAUDE.md §8：测试不重复。

**修复建议**：T-115 精简为 1 行（CONNECT 无属性 Properties Length=0x00），或标注与 T-020/021/022 的差异点。

---

## 5. LOW 问题

### L-R1：§8.7.4 字段计数错误

**位置**：§8.7.4（行 2952）"MQTTTopicFilter 全部 4 字段（Filter/QoS/NoLocal/RetainAsPublished/RetainHandling）覆盖"——MQTTTopicFilter struct（§5.4）实际有 **5 个字段**（Filter/QoS/NoLocal/RetainAsPublished/RetainHandling），此处列了 5 个字段名却标"4 字段"，计数错误。（对照：MQTTProperty 标 3 字段 = Identifier/Format/Value，正确；MQTTSession 标 13 字段 = ClientID/KeepAlive/CleanSession/Username/Password/Will/Subscriptions/Messages/PingAfterMessages/Disconnect/Properties/SrcPort/DstPort，正确。）

**修复建议**：改 "MQTTTopicFilter 全部 5 字段"。

---

## 6. 核验通过项（本轮确认无问题）

以下重点检查项经独立核算或规范 WebFetch 核实**全部正确**：

1. **固定头部结构**（§2.1）：Type 高 4 位 + Flags 低 4 位 + VBI RL，`0x10`/`0x20`/`0x33`/`0x62`/`0xE0`/`0xF0` 示例全部正确。
2. **Packet Type 枚举 1-15**（§2.2）：0 Reserved、1 CONNECT...15 AUTH，flags 列与规范 Table 2-2 完全一致（PUBREL/SUBSCRIBE/UNSUBSCRIBE=0010，其余=0000，已 WebFetch 核实）。
3. **CONNECT 结构**（§2.5/§3.1）：Connect Flags 位布局（bit7 Username / bit6 Password / bit5 Will Retain / bit4-3 Will QoS / bit2 Will Flag / bit1 Clean Session / bit0 Reserved）正确；5.0 允许 Password 无 Username、3.1.1 禁止——已 WebFetch 核实（5.0 §3.1.2.9 注释）。
4. **CONNACK 结构**（§2.6）：3.1.1 2 字节 VH（SP + Return Code）+ 5.0 3+ 字节（SP + Reason Code + Properties Length）；Return Code 0-5 表正确；5.0 22 个 CONNACK 代码表与规范逐项一致（已 WebFetch 核实）；148/141 仅 DISCONNECT 的标注正确；Session Present 互斥规则正确。
5. **PUBLISH 结构**（§2.7/§3.3）：QoS>0 才有 Packet Identifier；DUP/QoS/Retain 位正确；Topic Name 禁通配符；payload 0 字节合法。
6. **QoS 2 流程**（§2.9）：PUBLISH→PUBREC→PUBREL→PUBCOMP 四包、方向矩阵（上行：PUBREC/PUBCOMP 反向、PUBREL 同向）、PUBREL flags=0x02 强制——全部正确。
7. **SUBSCRIBE/SUBACK**（§2.10/§3.5）：SUBSCRIBE flags=0x02、Options 位布局（bit0-1 QoS / bit2 NoLocal / bit3 RAP / bit4-5 RH / bit6-7 Reserved）正确；SUBACK 3.1.1 0x00/0x01/0x02/0x80 + 5.0 扩展码正确；通配符规则与 `$share` 规则正确。
8. **VBI 编码**（§2.3）：算法、8 个边界值、最小编码原则全部正确（128→`80 01`、16383→`FF 7F`、16384→`80 80 01`、2097151→`FF FF 7F`、2097152→`80 80 80 01`、268435455→`FF FF FF 7F`，T-008 期望值全部正确）。
9. **Property ID 表**（§2.14）：28 个属性 ID/名称/类型/适用包逐项与规范 Table 2-4 一致（已 WebFetch 核实）；0x18=Will Delay Interval、0x1A=Response Information、0x15=Authentication Method、0x19=Request Response Information、0x21=Receive Maximum、0x13=Server Keep Alive、0x1F=Reason String、0x22=Topic Alias Maximum——全部正确。
10. **Property 白名单**（§8.4）：CONNECT/CONNACK/PUBLISH/Will/SUBSCRIBE/SUBACK/ACK/DISCONNECT/AUTH 各包型集合与规范"适用包"列逐一对照正确。
11. **DISCONNECT**（§2.12/§3.6）：5.0 31 个 Reason Code 表与规范一致（已 WebFetch 核实）；Reason=4=Disconnect with Will Message 正确；5.0 Properties Length 必填（可为 0）正确；3.1.1 仅 C→S 的方向标注正确。
12. **S1 CONNECT**（`10 0e ... 00 02 63 31`）：RL=14 正确（10+2+2）。
13. **S2 PUBLISH**（`30 11 00 0b ...`）：RL=17 正确（2+11+4）——deep-r2 C-D2 的修复保持正确。
14. **S5 SUBSCRIBE/SUBACK**：`82 0d ...` RL=13、`90 03 00 01 00` RL=3 全部正确。
15. **S10 PUBLISH**（`30 06 00 03 74 2f 31 61`）：RL=6 正确。
16. **S13 CONNECT**（`10 26 ...`）：RL=38 正确（10+13+7+8）。
17. **S14 CONNACK 拒绝**：`20 02 00 05` 正确；拒绝后跳过后续的逻辑正确。
18. **T-008 VBI 边界**：8 个期望值全部正确。
19. **T-011/T-012/T-013/T-014 Connect Flags 字节**：0xC2/0x0E/0x2E/0x16 全部正确。
20. **T-019/T-020**：5.0 DISCONNECT `E0 02 00 00`、CONNACK `20 03 00 00 00` 正确。
21. **T-023 Will Delay**：`05 18 00 00 00 05` 正确（0x18 修正已生效）。
22. **Property 编码示例**（§3.7）：`23 00 01`、`11 00 00 0E 10`、`26 00 01 6b 00 01 76`、`0B C8 01` 全部正确。
23. **T-026 vbi 属性**：`0x0B 0xC8 0x01`（200 的 VBI）正确。

---

## 7. 测试用例对照 CLAUDE.md §Testing Policy 评估

### 7.1 符合项（v2.0.0 明显改进）

- **失败路径覆盖**：T-069（DUP+QoS0）、T-071（`#` 不在末尾）、T-072/073（空 topic）、T-075（超长 topic）、T-085-090（非法域）、T-093/094（非法属性值）、T-099-104（Reason Code 域）、T-105/106（Session Present 互斥）、T-108/109（Property 白名单/重复）、T-110（v4+v5-only）、T-112（$share 非法）、T-116（VBI 解码负向）、T-144/145（encodeVBI 负向）、T-155（RH=3）、T-171-175（属性溢出）——负向用例覆盖充分。
- **边界值**：VBI 8 边界（T-008/009/142/143）、QoS 0/1/2/3、Version 3/4/5/6、PacketID 0/65535、topic 0/65535/65536、MSS MinMSS 边界——覆盖到位。
- **集成测试**：T-121~T-127 覆盖 strategy_convert→默认端口→RegisterPlanner→全链路→ValidationErrors 透传→多会话→PacketWorkers=8，符合 CLAUDE.md §4。
- **并发测试**：T-128（5 task 不串包）+ T-129（-race）符合 CLAUDE.md §6（T-128 测了可观见行为而非仅 race）。
- **失败测试先行**：§7 引言明确"先写 reproducing failing test，再修代码使其通过"。
- **字段覆盖清单**：§8.7.4 提供了 MQTTConfig 15 字段、MQTTWill 5 字段、MQTTMessage 8 字段等逐字段覆盖清单——符合 CLAUDE.md §1 的"spec 字段表驱动测试派生"。

### 7.2 不符合项

1. **T-160 断言空转**（见 H-R2）：断言内容与场景不符（场景 QoS0+PacketID，断言却测 QoS=3），属于"测试了错误的东西"。
2. **T-167 断言混乱**（见 H-R1）：把 Binary Data 与 UTF-8 上限混谈，断言与文档自身规则矛盾。
3. **字节级场景测试的基准错误**（C-R1~C-R6）：T-182/T-183/T-184 等"完整字节序列"测试的期望字节来自错误的 HexDump，若照文档实现，测试会"绿"但产出畸形包——正是 CLAUDE.md 警告的"测试通过但测错东西"模式。
4. **T-083 无法自洽**：65535 字节 topic 的 PUBLISH 单包 RL = 2+65535+1+payload > 65538，VBI 可编码但需 4 字节 RL——测试只断言"长度字段 0xFF 0xFF + 跨多段"，可行但依赖上述 UTF-8 上限修正。
5. **T-119 的 wrap 语义未定义**：PacketID 自增 65535→1 的 wrap 规则合理，但 §5.7 未写明（仅测试断言隐含），建议在 §5.7 默认值表补一行。

---

## 8. 结论

**本文档不能直接进入实现阶段（否）。**

v2.0.0 相对 v1.1 的协议知识层修复是扎实的：属性 ID 表、Reason Code 域、包类型 flags、VBI 编码、5.0 结构差异全部经独立核实无误，deep-r2 的 17 个问题基本闭环。但 **§6 HexDump 场景存在系统性 Remaining Length 错误**（6 处场景中的 CONNECT/PUBLISH 字节，S2/S3/S4/S7/S9/S10），且这些错误字节正是 T-181~T-187"字节级完整场景测试"的断言基准——照文档实现将产出被任何合规 broker 拒绝的畸形包，而测试仍会通过。此外 UTF-8 长度上限表述与规范不符、两条测试重复编号、will 时序语义矛盾等 6 处 HIGH/MEDIUM 问题需一并修正。

**建议修复顺序**：
1. 先修 C-R1~C-R6 六个 Remaining Length（用独立核算工具重算 §6 全部 HexDump，不信任文档自带核算）。
2. 修 H-R1（UTF-8 上限 0xFFFF 合法）并连带修正 T-167/T-083。
3. 修 H-R2/H-R3（测试重复、S15 占位符）。
4. 修 M-R1~M-R3、L-R1。
5. 重跑一次全文档字节自洽性检查（可写脚本：提取所有 HexDump 字节，校验 RL = 内容字节数）。
