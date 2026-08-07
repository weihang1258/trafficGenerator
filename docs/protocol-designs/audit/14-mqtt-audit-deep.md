# MQTT 设计文档深度对抗审计报告（第二轮）

**审计对象**：`docs/protocol-designs/14-mqtt-design.md`（v1.1, 2101 行）
**审计日期**：2026-08-04
**审计人**：独立协议审计（与 v1.0 审计者无交叉）
**审计依据**：
1. MQTT 3.1.1（OASIS Standard 2014 / ISO 20922:2016）
2. MQTT 5.0（OASIS Standard 2018 / RFC 9560）
3. v1.0 审计报告（`docs/protocol-designs/audit/14-mqtt-audit.md`，声称 32 问题已闭环）
4. `CLAUDE.md` 测试策略 8 条强制规则

---

## 1. 审计概览

### 1.1 审计方法

本轮审计在 v1.0 审计声称 32 问题已"闭环"的前提下，逐节核查文档，侧重三方面：
1. **属性标识符表（§2.12/§10.2）与 MQTT 5.0 规范 §2.2.2.2 原文逐项比对**（发现 §2.12/§10.2 大量属性 ID 错配）
2. **v1.0 未覆盖的字节计算点**（如 §5.1 表 Index 5 的 PUBLISH 字节从未被审计）
3. **Reason Code 域与 CONNACK/DISCONNECT 包型的归属**（发现 148（Topic Alias invalid）被错归为 CONNACK 代码）

### 1.2 总体结论

**否**——文档**不能**直接进入实现阶段。

v1.1 修复了 v1.0 的 32 个问题（Remaining Length/Length 字段字节修正、空 Topic Name 政策统一、Reason Code 表纠正、will 序列确定性化、KeepAlive 改 `*int`、扩展表对照新增、下行方向矩阵补全等），但本轮审计发现 **新增或未根治的硬错误仍有 17 处**，其中：
- 1 处 CRITICAL 属性 ID 错误（Will Delay Interval 0x18 被错标为 0x1A，将产生畸形 CONNECT+Will 数据包）
- 4 处 CRITICAL/HIGH 字节长度字段错误（§5.1 PUBLISH "sensor/temp" 长度字段应为 11 而非 10，剩余长度应为 17 而非 12）
- 3 处 HIGH 属性 ID 错误（0x15/0x19/0x21 在 §2.12 与 §10.2 错配）
- 1 处 HIGH Reason Code 域归属错误（148 仅用于 DISCONNECT 不用于 CONNACK）
- 1 处 HIGH §2.5 表格列结构错误（5.0 列对代码 1-5 给出"含义"，暗示 5.0 中有效）
- 多处 MEDIUM/LOW（5.0 CONNACK 域范围过于宽松、字段计数小错等）

**核心系统性缺陷**：
1. **属性 ID 表与规范原文大面积错配**：§2.12（行 274-292）和 §10.2（行 2049-2064）共 8 处 ID-名称对应错误，且 TC-086 直接引用了错误的 ID 编码字节。这不是简单的表格错位——TC-086 期望字节 `0x1A` 编码 Will Delay Interval，按此实现的 CONNECT+Will 数据包会被任何合规 MQTT 5.0 broker 视为协议错误。
2. **v1.0 审计遗漏的字节计算点**：§5.1 表 Index 5（PUBLISH）的"sensor/temp"长度字段 `0x0a`（10）实际应该是 `0x0b`（11），剩余长度 `0x0c`（12）应该是 `0x11`（17）。该 PUBLISH 是默认场景（TC-016/TC-022/TC-065 等十余条用例的基底），错误传染范围广。

### 1.3 严重度分布

| 严重度 | 数量 | 说明 |
|--------|------|------|
| CRITICAL | 2 | 属性 ID 0x1A 误用为 Will Delay Interval；§5.1 PUBLISH 字节长度双错 |
| HIGH | 4 | §2.12/§10.2 4 处属性 ID 错配；Reason Code 148 错归 CONNACK；§2.5 表格列结构误导 |
| MEDIUM | 6 | 5.0 Reason Code 验证域过宽（0/128-160 含多个无效值）；扩展表字段计数 27→28；剩余一处 v1.0 未闭环问题 |
| LOW | 5 | 表格列名与含义的小幅不精确 |
| **合计** | **17** | |

### 1.4 v1.1 修复成效评估

| v1.0 问题 | v1.1 状态 | 评估 |
|----------|----------|------|
| C-1（TC-001 Remaining Length） | ✓ 修正为 `0e` | 通过 |
| C-2（TC-010 Remaining Length） | ✓ 修正为 `26` | 通过 |
| C-3（TC-012/§6.4 SUBSCRIBE 双错） | ✓ 修正为 `0d` + `00 08` | 通过 |
| H-1（TC-015 自相矛盾） | ✓ 统一为 `E0 02 00 00` | 通过 |
| H-2（§6.8 空 Topic 违规） | ✓ 改为两步序列，新增 TC-043a/b | 通过 |
| H-3（§2.5 Reason Code 表错） | ✓ 130/135/144/148 含义改正 | 部分通过（仍错归 148 为 CONNACK） |
| H-4（§6.5 will 非确定性） | ✓ 改为确定性 FIN 10 包 + §6.5a RST 8 包 | 通过 |
| H-5（MinMSS 矛盾） | ✓ 统一为 536 + 新增 TC-022b1 | 通过 |
| H-6（§8.4 虚假声明） | ✓ 补 28 条用例 + 修正清单 | 通过 |
| H-7（KeepAlive `int`歧义） | ✓ 改 `*int` + TC-095 | 通过 |
| H-8（扩展表对照缺失） | ✓ 新增 §9.7 | 通过（但字段计数 27→28） |
| H-9（下行 QoS ack 方向） | ✓ 补 §2.7/§2.8 矩阵 + TC-096/097 | 通过 |
| M-1（v5 无属性 0x00 必填） | ✓ 新增 TC-113 覆盖 4 包型 | 通过 |
| M-2（CONNACK 域/Present 互斥） | ✓ TC-099/100/101/103 | 部分通过（域过宽+148 错归） |
| M-3（CleanSession+Present 校验） | ✓ TC-102 | 通过 |
| M-4（AUTH 不可配置） | △ §1.4 未列入，仍属 §2.2 | 部分通过 |
| M-5（UNSUBSCRIBE 清单不可验） | △ §8.1 仍含 UNSUBSCRIBE flags 项 | 未闭环 |
| M-6（PUBLISH 禁通配符） | ✓ TC-104 | 通过 |
| M-7（Property ID×包型/重复） | ✓ TC-105/106 | 通过 |
| M-8（VBI 解码负向） | ✓ TC-098 | 通过 |
| M-9（v5 Will Properties Length=0x00） | ✓ TC-089 | 通过 |
| M-10（v5-only v4 政策一致） | ✓ 统一为报错 + TC-107 | 通过 |
| M-11（ClientID 确定性） | ✓ 改 atomic counter + TC-074 | 通过 |
| M-12（slice 继承/替换） | ✓ TC-092/108 | 通过 |
| M-13（PacketID=0 自动分配） | △ 文档自洽（"0=自动分配"），TC-053 仍标"显式 0" | 部分通过 |
| L-1（DISCONNECT 方向标"双向"） | △ §2.2 仍标"双向"（虽加了"3.1.1: C→S; 5.0: 双向"注解） | 形式通过 |
| L-2（`#` 匹配所有/$share） | △ §2.9 文案已改；新增 TC-109/110 | 通过 |
| L-3（DUP=1 首次未标注） | △ TC-005 加了"负向流量建模"注释 | 通过 |
| L-4（§7.8 计数错误） | ✓ 重新计数对齐 116 | 通过 |
| L-5（§4.2 timer 伪状态） | ✓ §4.2 已加"本节为 RFC 语义参考"注解 | 通过 |
| L-6（空 ClientID+Clean=false） | ✓ 新增 TC-111 | 通过 |
| L-7（UTF-8 校验/TC-046 表述） | △ 新增 TC-112 | 通过 |

**v1.1 修复率**：32 问题中 29 项完全通过、3 项部分通过（H-3 部分、M-5 部分、M-13 部分）。

### 1.5 与 v1.0 审计的差异

v1.0 审计遗漏了以下关键问题（本轮新发现）：
- **§2.12/§10.2 属性 ID 表 4 处错配**（v1.0 只审计了 §2.12 一行 0x1A "Will Delay Interval"未与规范对照其他项）
- **§5.1 PUBLISH 字节计算错误**（v1.0 只审计了 TC-001/010/012 三条独立测试的字节，未审计 §5.1 表格本身的字节列）
- **148 (Topic Alias invalid) 仅适用 DISCONNECT 不适用 CONNACK**（v1.0 接受了 §2.5 表中 148 作为 CONNACK 代码的归类）
- **§2.5 表格列结构误导**（v1.0 接受了"5.0 含义"列对代码 1-5 给出含义的做法）

---

## 2. CRITICAL 问题

### C-D1：§2.12/§10.2 中 Will Delay Interval 属性 ID 错为 0x1A（应为 0x18），TC-086 直接引用错误字节

- **位置**：
  - §2.12 表格（line 288）：`0x1A | Will Delay Interval | 4-byte int | CONNECT`
  - §10.2 速查表（line 2060）：`0x1A | Will Delay Interval | uint32`
  - TC-MQTT-086 期望字节（line 1579）：`0x05 0x1A 0x00 0x00 0x00 0x05`（Will Properties 段）
  - §8.4 覆盖清单（line 1799）声称 DelayInterval 由 TC-086 覆盖
- **问题**：
  - MQTT 5.0 规范 §2.2.2.2 Table 2-4：**Will Delay Interval = 0x18 (24)**，Four Byte Integer，**仅适用于 Will Properties**。
  - 文档将 Will Delay Interval 标注为 `0x1A`，但规范中 `0x1A (26) = Response Information`，UTF-8 Encoded String，**仅适用于 CONNACK**。
  - TC-086 期望 Will Properties 段编码为 `0x05 0x1A 0x00 0x00 0x00 0x05`（Length=5，ID 0x1A + uint32 5）。按此实现，CONNECT 数据包的 Will Properties 段包含一个 ID 0x1A，而真实 broker 会按 Response Information 解析（在 Will Properties 段中是不允许的），从而判定此包为协议错误，关闭连接。
  - v1.0 审计的 H-6 提到"DelayInterval 零测试"——v1.1 补了 TC-086，但 TC-086 本身编码的就是错误 ID。
- **RFC 依据**：MQTT 5.0 §2.2.2.2 Table 2-4（Property Identifier 表）；§3.1.3.2.3（Will Properties 定义）。
- **影响**：实现者按 TC-086 期望编码 Will Delay Interval → 产生畸形 CONNECT+Will 数据包 → 任何合规 MQTT 5.0 broker 拒收。这是设计文档**最大的事实错误**——所有 5.0 Will Properties 编码路径若按此文档实现都是错的。
- **修复**：
  1. §2.12 表格：`0x1A | Will Delay Interval` → `0x18 | Will Delay Interval`；适用包从 `CONNECT` 改为 `Will Properties`
  2. §10.2 速查表同步修正
  3. TC-086 期望字节改为 `0x05 0x18 0x00 0x00 0x00 0x05`
  4. §3.1 注释 line 143 "Will Delay Interval" 提到的 ID 引用（如有）一并修正

### C-D2：§5.1 表 Index 5 PUBLISH 字节双错（topic 长度 10 应为 11、剩余长度 12 应为 17）

- **位置**：§5.1 默认配置表（line 623）Index 5 PUBLISH：`30 0c 00 0a 73 65 6e 73 6f 72 2f 74 65 6d 70 32 33 2e 35`
- **问题**：
  1. **Topic Name 长度字段 `0x0a` (10) 错误**：`sensor/temp` 是 11 个字节（s-e-n-s-o-r-/-t-e-m-p），长度字段应为 `0x0b` (11)。
  2. **Remaining Length `0x0c` (12) 错误**：实际剩余字节 = 2 (长度字段) + 11 (topic) + 4 (payload `23.5`) = 17 = `0x11`。Remaining Length 应为 `0x11`。
  3. §6.8 断言 line 910："第一条 PUBLISH 固定头低 4 位 flags = QoS0、Retain=0；Topic Name 长度字段=10（`sensor/temp` 字节数）"——文本自相矛盾，"sensor/temp 字节数"是 11 不是 10。
- **RFC 依据**：MQTT 3.1.1 §2.2.3（Remaining Length 定义）；§3.3.2.2（PUBLISH Topic Name）。
- **影响**：
  - §5.1 默认场景是 TC-016/TC-022/TC-065 等 10 余条用例的基底。
  - v1.0 审计的 C-1~C-3 修复了 TC-001/010/012 三处独立测试字节，但未审查 §5.1 表格本身的字节列——这是 v1.0 审计遗漏的盲点。
  - 按 §5.1 当前字节实现的 PUBLISH：`30 0c 00 0a sensor/tem p23.5`（topic=`sensor/tem`，payload=`p23.5`）—— topic 和 payload 都错位，Wireshark 解析为畸形 PUBLISH。
- **修复**：
  1. §5.1 Index 5 字节改为 `30 11 00 0b 73 65 6e 73 6f 72 2f 74 65 6d 70 32 33 2e 35`
  2. §6.8 line 910 "Topic Name 长度字段=10（`sensor/temp` 字节数）" 改为 "Topic Name 长度字段=11（`sensor/temp` 字节数）"
  3. §5.1 Index 5 字节更新后，新增 TC 或修订 TC-028 的 byte 断言

---

## 3. HIGH 问题

### H-D1：§2.12/§10.2 中 0x15 被错标为 "Topic Alias Maximum"（应为 Authentication Method）

- **位置**：
  - §2.12（line 286）：`0x15 | Topic Alias Maximum | 2-byte int | CONNECT, CONNACK`
  - §10.2（line 2058）：`0x15 | Topic Alias Maximum | uint16`
- **问题**：MQTT 5.0 §2.2.2.2：`0x15 (21) = Authentication Method`，UTF-8 Encoded String，适用 CONNECT/CONNACK/AUTH。**Topic Alias Maximum = 0x22 (34)**，Two Byte Integer，适用 CONNECT/CONNACK。
- **影响**：文档未提供任何 0x15 或 0x22 的测试用例，故暂无直接字节错误。但任何按此表实现 Topic Alias Maximum 编码的实现者会写出错误字节。
- **修复**：§2.12/§10.2 两处表格同步修正：`0x15 → Authentication Method`，新增 `0x22 → Topic Alias Maximum`，删除错误的 "Topic Alias Maximum | 0x15" 行。

### H-D2：§2.12/§10.2 中 0x19 被错标为 "Server Keep Alive"（应为 Request Response Information）

- **位置**：
  - §2.12（line 289）：`0x19 | Server Keep Alive | 2-byte int | CONNACK`
  - §10.2（line 2059）：`0x19 | Server Keep Alive | uint16`
- **问题**：MQTT 5.0 §2.2.2.2：`0x19 (25) = Request Response Information`，Byte，适用 CONNECT。**Server Keep Alive = 0x13 (19)**，Two Byte Integer，适用 CONNACK。
- **影响**：同 H-D1，目前无直接测试用例引用 0x19 或 0x13，故无即时字节错误，但表格错配会导致后续实现/测试时使用错误 ID。
- **修复**：§2.12/§10.2 同步修正：`0x19 → Request Response Information`，新增 `0x13 → Server Keep Alive`。

### H-D3：§2.12/§10.2 中 0x21 被错标为 "Reason String"（应为 Receive Maximum）

- **位置**：
  - §2.12（line 290）：`0x21 | Reason String | UTF-8 string | 多包`
  - §10.2（line 2061）：`0x21 | Reason String | string`
- **问题**：MQTT 5.0 §2.2.2.2：`0x21 (33) = Receive Maximum`，Two Byte Integer，适用 CONNECT/CONNACK。**Reason String = 0x1F (31)**，UTF-8 Encoded String，适用多个包型。
- **修复**：§2.12/§10.2 同步修正：`0x21 → Receive Maximum`，新增 `0x1F → Reason String`。

### H-D4：TC-100 将 148（Topic Alias invalid）作为有效 CONNACK 代码——148 仅适用于 DISCONNECT

- **位置**：TC-MQTT-100（line 1662-1666）
- **问题**：
  - 测试在 `version: 5` 下将 connect_ack_code=148 视为有效，断言 "Validate 通过；CONNACK byte[1]=`0x94`"。
  - 但 MQTT 5.0 §2.4 Reason Code 表：Topic Alias invalid = 0x94 (148)，**仅适用于 DISCONNECT**，不适用于 CONNACK。
  - v1.0 审计 H-3 将 130/135/144/148 全部作为有效 CONNACK 代码列出，v1.1 沿用了这个错误归类。
- **RFC 依据**：MQTT 5.0 §2.4 Table 2-6（CONNACK Reason Codes 列）；§3.2.2.3（CONNACK Reason Code）。
- **影响**：按 TC-100 实现的 CONNACK 包含 byte[1]=0x94——任何合规 MQTT 5.0 broker 判定为协议错误并关闭连接。
- **修复**：TC-100 改用 4 个真实有效的 CONNACK 代码，例如：130（Protocol Error）、131（Implementation specific error）、137（Server busy）、140（Bad authentication method）。删除 148。

### H-D5：§2.5 CONNACK 表格列结构误导：5.0 列对代码 1-5 给出含义，暗示其在 5.0 中有效

- **位置**：§2.5（line 157-165）
- **问题**：
  - 表格 "Code | 3.1.1 含义 | 5.0 含义" 对代码 1-5 都在"5.0 含义"列给出含义。
  - 但 MQTT 5.0 中 CONNACK 原因代码 1-5 **不是有效的 CONNACK 代码**（仅 0 和 128-160 中的特定值有效）。
  - 例如：3.1.1 代码 1 = "不可接受的协议版本"，5.0 列写 "不支持的协议版本"——但在 MQTT 5.0 中，CONNACK 原因代码 1 是未分配的；正确代码是 132 (Unsupported Protocol Version)。
- **RFC 依据**：MQTT 5.0 §2.4 Table 2-6（CONNACK Reason Codes 仅为 0、128-140 中部分、144、149、151、153-157、159）。
- **影响**：实现者按表格推断"代码 1 在 5.0 中表示不支持的协议版本"，可能错误接受 ConnectAckCode=1 for Version=5。Validate 范围"0/128-160"确实拒绝了 1-5（因为 1-5 不在 0/128-160 范围内），所以 Validate 不会出错——但表格本身具有误导性，且代码 1-5 在 3.1.1/5.0 之间不存在一对一的语义对应关系。
- **修复**：§2.5 表格改为 "Code | 3.1.1 含义 | 5.0 对应码 (Code) | 5.0 对应含义"，或对 3.1.1 的 1-5 在 "5.0" 列写 "N/A（5.0 使用不同代码域）"，并补充说明 "3.1.1 代码 1 ↔ 5.0 代码 132（Unsupported Protocol Version）" 等。

---

## 4. MEDIUM 问题

### M-D1：§3.1 ConnectAckCode 5.0 验证域"0/128-160"过于宽松，包含多个无效值

- **位置**：§3.1 ConnectAckCode 注释（line 342）："5.0 合法集 0/128-160（其他报错）"；§6.12 表（line 1038）；TC-101 断言"5.0 合法集 0/128-160"
- **问题**：
  - MQTT 5.0 §2.4 CONNACK 原因代码的有效集合是：0、128、129、130、131、132、133、134、135、136、137、138、140、144、149、151、153、154、155、156、157、159（共 22 个值）。
  - 文档的 "0/128-160" 范围**过于宽松**，包含了多个无效值，如：141（Packet ID not found）、142（Topic Filter invalid）、143（Topic Name invalid 实际是 144 而非 143）、145-147、150、152、158、160。
  - 例如：值 142 在 MQTT 5.0 中不是任何包型的有效 Reason Code；值 146 也未分配；值 160 及以上完全无效。
- **RFC 依据**：MQTT 5.0 §2.4 Table 2-6（Reason Codes 完整列表）。
- **影响**：实现者按"0/128-160"实现 Validate → 接受无效值 → 生成无效 CONNACK。
- **修复**：
  1. 改为枚举白名单或精确稀疏集：`map[int]bool{0:true, 128:true, 129:true, 130:true, ...}`；
  2. 或者文档化宽松策略（"接受 128-160 范围内的所有值，对应'实现自定义错误'"），并显式声明这是流量生成器的宽松行为；
  3. 推荐方案：精确枚举 22 个有效值。

### M-D2：§9.7 扩展表字段计数 27 实际为 28

- **位置**：§9.7 表（line 1982-2010，列了 28 个字段）；TC-093（line 1620）"27 字段"；§9.7 末段（line 2016）"上述 27 字段"
- **问题**：逐条计数 §9.7 表：tx_id、version、type、dup、qos_level、retain、reason_codes、connack_session_present、client_id、keep_alive、clean_session、will_flag、will_topic、will_qos、will_retain、username、password_set、direction、topic、payload_len、subscriptions_count、filters_count、messages_count、ping_count、disconnect_flag、sessions_count、properties_count、topic_alias_used = **28 个**。
- **影响**：TC-093 断言"27 字段"，实际少覆盖了 1 个。
- **修复**：将所有"27 字段"改为"28 字段"，TC-093 断言同步修正。

### M-D3：v1.0 M-5 未闭环——§8.1 仍含 UNSUBSCRIBE flags 校验项但 planner 不实现 UNSUBSCRIBE

- **位置**：§8.1（line 1770）"SUBSCRIBE/UNSUBSCRIBE flags 必须 0x02（bit1=1）。UNSUBSCRIBE 本期不实现（见 §1.4）"
- **问题**：§8.1 审计清单项要求 UNSUBSCRIBE flags 必须 0x02，但 §1.4 明确"UNSUBSCRIBE 本期不实现"。清单项对一个 planner 不产出的包型要求 flags 校验——无法验证。
- **影响**：审查者按 §8.1 走查时，无法验证 UNSUBSCRIBE flags=0x02，因为代码中根本没有 UNSUBSCRIBE 生成路径。
- **修复**：§8.1 删除 "UNSUBSCRIBE" 字样，改为 "SUBSCRIBE flags 必须 0x02（bit1=1）"；或显式标注 "[UNSUBSCRIBE 本期不实现，清单项不可达]"。

### M-D4：v1.0 M-13 部分通过——TC-053 表述仍暗示"显式 0"与"省略"不同

- **位置**：TC-MQTT-053（line 1426-1429）
- **问题**：
  - 文档 §3.7 第 539 行明确"MQTTMessage.PacketID | 1 起步自增 | 0 = 自动分配"。
  - §6.12 第 1025 行："PacketID=0 (QoS>0) → Validate 报错"——与 §3.7 自相矛盾。
  - TC-053 标题与场景用"packet_id: 0"，暗示"显式 0"是有意触发的输入。但因 `omitempty` 标签，显式 0 与省略在 JSON 中无法区分——都会得到 PacketID=0，且都应触发"自动分配"。
- **修复**：
  1. §6.12 line 1025 改为 "PacketID=0 → 自动分配（等同于省略）"
  2. TC-053 标题改为 "PacketID 省略/显式 0 自动分配"，场景用 `messages: [...]`（不显式设 packet_id）

### M-D5：v1.0 M-4 部分通过——AUTH 包仍在 §2.2/§10.1 中文档化但 §1.4 未明确"不实现"

- **位置**：§2.2（line 92）AUTH 行；§10.1（line 2045）；§1.4（line 50）
- **问题**：
  - §1.4 仅写"AUTH 包（5.0 Enhanced Authentication）：MQTTConfig 无对应字段产生 AUTH 包，本期不实现"。
  - 但 §2.2 表格、§10.1 速查表都将 AUTH 作为正式包型列出，无"未实现"标注。
  - §8.4 字段覆盖清单也不包含 AUTH，暗示 AUTH 不在覆盖范围。
- **修复**：§1.4 已基本闭环。但 §2.2 AUTH 行可加 "（本期不实现）" 后缀；§10.1 同。

### M-D6：§2.12 表中 "适用包" 列多处不完整

- **位置**：§2.12 表（line 277-292）
- **问题**：表中多行的"适用包"列仅列了部分适用包：
  - `0x01 Payload Format Indicator`：仅标 "PUBLISH"，应补充 "PUBLISH, Will Properties"
  - `0x02 Message Expiry Interval`：标 "PUBLISH, Will"，正确
  - `0x11 Session Expiry Interval`：标 "CONNECT, DISCONNECT"，应补充 "CONNECT, CONNACK, DISCONNECT"
  - `0x27 Maximum Packet Size`：标 "CONNECT, CONNACK"，正确
- **RFC 依据**：MQTT 5.0 §2.2.2.2 Table 2-4（适用包列完整列表）。
- **影响**：表格不完整可能导致实现者漏掉适用包型——例如实现者可能不为 Will Properties 写 Payload Format Indicator。
- **修复**：§2.12 表格逐行比对规范 Table 2-4 补全"适用包"列。

---

## 5. LOW 问题

### L-D1：§6.5 will 场景中 PUBACK(up) 语义不自洽

- **位置**：§6.5 期望序列 step 7（line 782）："PUBACK (up, 同 PacketID) — 客户端在断开前回 ACK"
- **问题**：文档已承认 will 是 broker 发给"其他订阅者"的消息（line 761），但 step 7 又让当前客户端回 PUBACK。这语义上矛盾——will PUBLISH 不是发给当前客户端的，当前客户端不应回 PUBACK。
- **影响**：语义不一致，但作为流量生成器的建模选择可接受（planner 不模拟真实 broker），应在文档中更明确说明"此 PUBACK 是为字节序列完整性而添加，与真实 will 语义不一致"。

### L-D2：§10.1 PUBLISH QoS2 Retain DUP 字节与 §10.1 注释不完全自洽

- **位置**：§10.1（line 2033）：`PUBLISH QoS2 Retain DUP | 0x3D | 0011 1101`
- **问题**：注释仅列出 0011 1101，未与 §2.6 的 DUP/QoS/Retain 位布局公式对照。校验：DUP=1 (bit3=1)，QoS=2 (bit2=1, bit1=0)，Retain=1 (bit0=1) → 0011 1101 = 0x3D ✓。正确，但文档无验算过程，读者难以校验。

### L-D3：§4.1 状态机图中"下行 PUBLISH"与上行在同一图但未明确边界

- **位置**：§4.1（line 549-573）
- **问题**：状态机图用单条路径 `[PUBLISH (up/down) ► ...]`，未单独画下行路径。中段方向翻转（§2.8 矩阵）在状态机图中不可见。
- **影响**：读者从状态机图无法看出下行 QoS1/2 的 ack 方向翻转——必须读 §2.8 才知。

### L-D4：§6.8 输入 JSON 中 User Property value 格式特殊未说明

- **位置**：§6.8（line 878）：`{"identifier": 38, "format": "stringpair", "value": "k\x00v"}`
- **问题**：value 字段用 `\x00` 作为键值分隔符，但 §3.5 MQTTProperty.Value 注释（line 484）写 `"k\x00v" for stringpair`，与 JSON 序列化兼容性未说明。`\x00` 在 JSON 中作为字符串字面量是非法的——必须用 `" "`。
- **影响**：实现者照抄此 JSON 输入会因非法 JSON 而解析失败。
- **修复**：§6.8 输入示例的 value 改为 `"k v"`；§3.5 注释同步。

### L-D5：§5.3 中 `buildUnsubscribe` 列入函数清单但 §1.4 声明不实现

- **位置**：§5.3（line 652）：`func buildUnsubscribe(...) // 预留（本期不强制实现 UNSUBSCRIBE）`
- **问题**：函数签名已列出，但实现要求"预留"——实现者可能误以为必须实现该函数才能符合设计。
- **修复**：§5.3 中 `buildUnsubscribe` 行删除，或标注 "[不实现，仅占位]"。

---

## 6. RFC 一致性逐项核查表（第二轮）

| # | 核查项 | RFC 要求 | v1.1 状态 |
|---|--------|---------|---------|
| 1 | 固定头 = Type(4)<<4 \| Flags(4) | 3.1.1 §2.1 | ✓ |
| 2 | CONNECT=0x10, CONNACK=0x20, ... | 3.1.1 §2.1 | ✓ |
| 3 | PUBREL flags=0x02 强制 | 3.1.1 §2.1 | ✓ |
| 4 | SUBSCRIBE flags=0x02 强制 | 3.1.1 §2.1 | ✓ |
| 5 | PUBLISH flags 位布局 | 3.1.1 §3.3.1 | ✓ |
| 6 | QoS=3 非法 | 3.1.1 §3.3.1 | ✓ |
| 7 | VBI 1-4 字节、最大 268,435,455 | 3.1.1 §2.2.3 | ✓ |
| 8 | VBI 解码负向（5 字节/非最小/第 4 字节续位） | 5.0 §1.5.5 | ✓（TC-098） |
| 9 | CONNECT 协议名 "MQTT" + 级别 4/5 | 3.1.1 §3.1.2 | ✓ |
| 10 | Connect Flags 位布局 | 3.1.1 §3.1.2.3 | ✓ |
| 11 | CONNECT payload 顺序 | 3.1.1 §3.1.3 | ✓ |
| 12 | CONNACK 3.1.1 = SessionPresent + ReturnCode | 3.1.1 §3.2.2 | ✓ |
| 13 | CONNACK 5.0 = flags + Reason + Properties（0x00 必填） | 5.0 §3.2.2 | ✓（TC-113） |
| 14 | CleanSession=1 时 SessionPresent=0 | 3.1.1 §3.2.2.1 | ✓（TC-102） |
| 15 | CONNACK Reason≠0 时 SessionPresent=0 | 5.0 §3.2.2.2 | ✓（TC-103） |
| 16 | PUBLISH QoS0 无 PacketID；QoS1/2 必有 | 3.1.1 §3.3.2.2 | ✓ |
| 17 | PUBLISH Topic 禁通配符 | 3.1.1 §4.7.1 | ✓（TC-104） |
| 18 | DUP 仅重传置 1 | 3.1.1 §3.3.1.1 | △（L-3 加注） |
| 19 | QoS1：PUBLISH→PUBACK 同 PacketID | 3.1.1 §3.4 | ✓ |
| 20 | QoS2：4 包交换同 PacketID | 3.1.1 §3.5 | ✓ |
| 21 | QoS2 下行方向矩阵 | 3.1.1 §3.5 | ✓（TC-096/097） |
| 22 | SUBSCRIBE payload 结构 | 3.1.1 §3.8.3 | ✓ |
| 23 | SUBACK payload = 每 filter 一个 reason code | 3.1.1 §3.9 | ✓ |
| 24 | PINGREQ/PINGRESP 无 payload | 3.1.1 §3.12/§3.13 | ✓ |
| 25 | DISCONNECT 3.1.1 仅 C→S | 3.1.1 §3.14.1 | △（L-1 注解） |
| 26 | DISCONNECT 5.0 = Reason + Properties（0x00 必填） | 5.0 §3.14.2 | ✓（TC-015） |
| 27 | Properties Length VBI 不含自身 | 5.0 §2.2.2 | ✓ |
| 28 | Topic Alias 首包非空 Topic Name | 5.0 §3.3.2.3.4 | ✓ |
| 29 | `#` 不匹配 `$` 开头 | 3.1.1 §4.7.2 | ✓ |
| 30 | Shared Subscriptions $share/group/filter | 5.0 §4.8.2 | ✓（TC-109/110） |
| 31 | AUTH 仅 5.0 | 5.0 §3.15 | △（M-D5） |
| 32 | 5.0 Reason Code 表 | 5.0 §2.4 | **✗ H-D4 + H-D5 + M-D1** |
| 33 | KeepAlive=0 禁用保活 | 3.1.1 §3.1.2.5 | ✓（` *int`） |
| 34 | 空 ClientID 仅 CleanSession=1 | 3.1.1 §3.1.3.1 | ✓（TC-080/111） |
| 35 | Will 触发条件 = 异常断开 | 3.1.1 §3.1.2.5 | △（L-D1） |
| 36 | **5.0 Property Identifier 表完整正确** | 5.0 §2.2.2 | **✗ C-D1 + H-D1 + H-D2 + H-D3** |
| 37 | §5.1 PUBLISH 默认字节长度字段正确 | 3.1.1 §3.3.2.2 | **✗ C-D2** |
| 38 | §6.5 will 场景包序列确定性 | — | △（L-D1） |

核查表结论：38 项中 **30 项正确、8 项存在问题**（2 CRITICAL、3 HIGH、2 MEDIUM、3 LOW/△）。

---

## 7. 测试用例质量审计（CLAUDE.md §1-§8）

### 7.1 符合策略的方面

- **§1 从 spec 派生**：v1.1 补全 28 条用例后，§7 共 116 条用例覆盖 §2（报文格式）、§3（Config）、§4（状态机）、§5（Plan）、§6（业务场景）各节。TC-086~TC-113 直接对应审计 32 问题的修复。
- **§2 覆盖失败路径**：负向用例覆盖全面（QoS=3、CONNACK 拒绝码 1-5、Username 空+Password 非空、v4+Properties、v4+DelayInterval、decodeVBI malformed、ID×包型/重复、PUBLISH 通配符等）。
- **§3 每个代码路径独立测试**：QoS0/1/2、上下行、3.1.1/5.0、will/retain/auth/keepalive 各有独立用例。
- **§4 集成测试**：TC-067~073 覆盖 strategy_convert → 端口默认 → RegisterPlanner → 全链路 pcap → 错误透传 → SubFlow 4-tuple → PacketWorkers=8，跨层完整。
- **§5 断言可观见结果**：绝大多数断言是字节级/包数级；TC-098 要求 error 信息含具体关键词（"length"/"malformed"/"continuation"）合规。
- **§6 并发测正确性**：TC-073（8 worker 包序）、TC-074（并发 task 字节互斥）测的是可观见行为。
- **§7 失败测试先行**：文档声明每条用例失败先行。
- **§8 对抗性审查测试质量**：v1.1 §8.4/§8.7 清单相对完整，覆盖了各 Config 字段的用例引用。

### 7.2 不符合策略的方面

1. **TC-086 期望字节本身错误（C-D1）**：`0x1A` 编码 Will Delay Interval 违反规范。属性 ID 错配导致该用例一旦实现就产出畸形包——比"测错路径"更基础。
2. **§5.1 表 Index 5 字节双错（C-D2）**：默认场景的 PUBLISH 长度字段 `0x0a` 应为 `0x0b`、剩余长度 `0x0c` 应为 `0x11`。§5.1 是 TC-016/022/065 的基底，错误传染广。
3. **TC-100 期望 148 作为 CONNACK 原因码（H-D4）**：148 仅适用于 DISCONNECT，不适用于 CONNACK。该用例期望被 Validate 通过并发出 byte[1]=0x94 的 CONNACK——任何合规 broker 都会拒收。
4. **§2.5 表格列结构误导（H-D5）**：5.0 列对代码 1-5 给出含义，暗示其在 5.0 中有效——实际 5.0 不接受 1-5 作为 CONNACK 代码。
5. **§2.12/§10.2 4 处属性 ID 错配（C-D1 + H-D1~H-D3）**：表格自洽性差，导致 §2.12 与 §10.2 同时错，且 TC-086 直接引用错误 ID。
6. **M-D4 未完全闭环**：PacketID=0 自动分配语义仍存疑（§6.12 与 §3.7 表述差异）。

### 7.3 用例-场景覆盖率统计

| 功能域 | 用例数 | 覆盖评估 |
|--------|--------|---------|
| CONNECT 构造 | TC-001/002/010/011/045/080/092 ≈ 7 | 优秀（字节已正确） |
| CONNACK | TC-003/017/038/039/094/100/101/102/103 ≈ 9 | 优秀，但 TC-100 字节错 |
| PUBLISH 构造 | TC-004/005/028/029/030/040 ≈ 6 | 优秀 |
| QoS ack 链（含下行） | TC-018/030/031/096/097 ≈ 5 | 优秀（含下行方向矩阵） |
| SUBSCRIBE/SUBACK | TC-012/013/031/041/042/109/110 ≈ 7 | 优秀 |
| PING/DISCONNECT | TC-014/015/019/020 ≈ 4 | 优秀 |
| VBI 编解码 | TC-007/008/009/046-050/098 ≈ 11 | 优秀（含负向） |
| 5.0 Properties | TC-002/035/061/062/063/086/090/091/105/106/107/113 ≈ 12 | 优秀，但 TC-086 字节错 |
| 业务场景 | TC-032/033/034/036/087/088/089 ≈ 7 | 优秀 |
| 多会话 | TC-037/037a/072/092/108 ≈ 5 | 优秀 |
| 边界 | TC-022-027/051/052/065/066/079/095/111/112 ≈ 14 | 优秀 |
| 校验负向 | TC-021/040/042-044/053-060/099/102/103/104/107 ≈ 15 | 优秀 |
| 集成/并发 | TC-067-080 ≈ 14 | 优秀 |
| 审计补充 | TC-086-113 ≈ 28 | 优秀 |

统计结论：116 条用例覆盖全面，主要缺口已由 v1.1 补齐。剩余问题集中在**属性 ID 引用错误**（C-D1、H-D4）和**字节计算错误**（C-D2）。

---

## 8. 字段覆盖率审计（扩展表 28）

逐字段对照 §9.7（28 字段）与 Config/生成流量：

| 扩展表字段 | Config 来源 | 编码侧 | 上报侧 | 评估 |
|-----------|-------------|--------|--------|------|
| tx_id | PacketID（自动分配/显式） | ✓ TC-053/079 | ✓ §9.7 | ✓ |
| version | Version 4/5 | ✓ TC-001/002 | ✓ §9.7 | ✓ |
| type | 固定头 Type | ✓ TC-004~006 | ✓ §9.7 | ✓ |
| dup | DUP bit3 | ✓ TC-005/040 | ✓ §9.7 | ✓ |
| qos_level | QoS 0/1/2 | ✓ TC-021 | ✓ §9.7 | ✓ |
| retain | Retain bit0 | ✓ TC-033 | ✓ §9.7 | ✓ |
| reason_codes | ConnectAckCode + AckReasonCodes | ✓ TC-003/013/100 | ✓ §9.7 | 错误归类 148 |
| connack_session_present | ConnectAckSessionPresent | ✓ TC-094/102/103 | ✓ §9.7 | ✓ |
| client_id | ClientID | ✓ TC-001/045/074 | ✓ §9.7 | ✓ |
| keep_alive | KeepAlive | ✓ TC-036/095 | ✓ §9.7 | ✓ |
| clean_session | CleanSession | ✓ TC-102 | ✓ §9.7 | ✓ |
| will_flag | Will != nil | ✓ TC-011/080 | ✓ §9.7 | ✓ |
| will_topic | Will.Topic | ✓ TC-032 | ✓ §9.7 | ✓ |
| will_qos | Will.QoS | ✓ TC-088 | ✓ §9.7 | ✓ |
| will_retain | Will.Retain | ✓ TC-087 | ✓ §9.7 | ✓ |
| username | Username | ✓ TC-010/034 | ✓ §9.7 | ✓ |
| password_set | Password != "" | ✓ TC-056 | ✓ §9.7 | ✓ |
| direction | Direction up/down | ✓ TC-031/096/097 | ✓ §9.7 | ✓ |
| topic | Topic | ✓ TC-028/104 | ✓ §9.7 | ✓ |
| payload_len | len(Payload) | ✓ TC-051 | ✓ §9.7 | ✓ |
| subscriptions_count | len(Subscriptions) | ✓ TC-031/041 | ✓ §9.7 | ✓ |
| filters_count | sum(Filters) | ✓ TC-031 | ✓ §9.7 | ✓ |
| messages_count | len(Messages) | ✓ TC-028 | ✓ §9.7 | ✓ |
| ping_count | PingAfterMessages | ✓ TC-019/036 | ✓ §9.7 | ✓ |
| disconnect_flag | Disconnect | ✓ TC-026 | ✓ §9.7 | ✓ |
| sessions_count | len(Sessions) | ✓ TC-037/072 | ✓ §9.7 | ✓ |
| properties_count | sum(Properties) | ✓ TC-002/035 | ✓ §9.7 | ✓ |
| topic_alias_used | Topic Alias ID 0x23 | ✓ TC-043a/b | ✓ §9.7 | ✓ |

**结论**：28 字段全部覆盖。但 `reason_codes` 字段因 148 错归 CONNACK 而有错误字节（TC-100）。

---

## 9. 多会话场景正确性

### 9.1 机制正确性（已核验，与 v1.0 一致）

每个 session 独立 4-tuple、独立 FlowID、共享 GroupID——与 socks5 `:udp` 子流先例一致。

### 9.2 未决点（与 v1.0 比较）

1. **ClientID 唯一性（M-11）**：v1.1 改用 atomic counter，TC-074 字节互斥断言通过确定性生成保证 ✓
2. **继承语义（M-12）**：v1.1 明确定义"scalar 继承、slice 替换/继承"，TC-092/108 覆盖 ✓
3. **SrcPort 基址**：从默认 36164 起步自增，TC-037 验证 ✓

### 9.3 状态机审计补遗

主状态机、子状态机、QoS1/2、上行/下行方向、死锁防护均完整，与 v1.0 一致。

---

## 10. 总体评分

### 10.1 分维度评分

| 维度 | 评分 | 说明 |
|------|------|------|
| RFC 一致性 | 5.5/10 | v1.1 修复了 v1.0 字节错，但新增属性 ID 错配（C-D1 + H-D1~H-D3）、§5.1 PUBLISH 字节错（C-D2）、148 错归（H-D4）、§2.5 表格结构错（H-D5） |
| 状态机完整性 | 9/10 | 主/子状态机、上下行方向矩阵、死锁防护均完整 |
| Config 字段设计 | 8/10 | 结构清晰，KeepAlive `*int`、Session/slice 继承、will/Properties 完整 |
| 测试用例质量 | 7.5/10 | 116 条体量可观、集成/并发/负向优秀；但 TC-086/100 字节错 |
| 多会话正确性 | 8.5/10 | 机制正确，ClientID 确定性生成、继承语义明确 |
| 扩展表覆盖 | 8/10 | §9.7 完整，但字段计数 27→28（M-D2） |
| **总体** | **6.8/10** | 修复显著但引入新硬错误；**必须修复 C-D1 + C-D2 + H-D4 后才能进入实现** |

### 10.2 实现前必改清单（按优先级）

1. **C-D1**：§2.12/§10.2 Will Delay Interval ID 改 0x1A → 0x18，TC-086 期望字节同步。
2. **C-D2**：§5.1 Index 5 PUBLISH 字节改 `30 0c 00 0a` → `30 11 00 0b`，§6.8 长度字段注解同步。
3. **H-D4**：TC-100 删除 148，改用 130/131/137/140 等真实 CONNACK 代码。
4. **H-D1~H-D3**：§2.12/§10.2 修正 0x15/0x19/0x21 ID 错配。
5. **H-D5**：§2.5 表格列结构修正，避免误导。
6. **M-D1**：ConnectAckCode 5.0 验证域改为精确枚举或显式声明宽松策略。
7. **M-D2**：扩展表字段计数 27→28。
8. **M-D3**：§8.1 删除 UNSUBSCRIBE flags 校验项或标注不可达。
9. **M-D4**：§6.12 PacketID=0 表述与 §3.7 统一。
10. **M-D5/M-D6/L-D1~L-D5**：低优先级清理。

### 10.3 审计问题统计

| 严重度 | 数量 | 编号 |
|--------|------|------|
| CRITICAL | 2 | C-D1, C-D2 |
| HIGH | 5 | H-D1, H-D2, H-D3, H-D4, H-D5 |
| MEDIUM | 6 | M-D1, M-D2, M-D3, M-D4, M-D5, M-D6 |
| LOW | 5 | L-D1, L-D2, L-D3, L-D4, L-D5 |
| **合计** | **17**（未含 v1.0 沿用问题） | |

（另：v1.0 的 32 问题 v1.1 中 29 项完全通过、3 项部分通过。）

---

## 11. 最终结论

**本文档不能直接进入实现阶段。**

文档在 v1.0 基础上修复了 29/32 个原有问题，但本轮审计发现 17 处新增或未根治的问题，其中：

- **C-D1**（CRITICAL）：Will Delay Interval 属性 ID 误标为 0x1A（应为 0x18），TC-086 直接引用错误字节——按此实现的 CONNECT+Will 数据包会被任何合规 MQTT 5.0 broker 判定为协议错误。
- **C-D2**（CRITICAL）：§5.1 表 Index 5 PUBLISH 字节长度字段 `0x0a` 应为 `0x0b`、剩余长度 `0x0c` 应为 `0x11`——该 PUBLISH 是默认场景的基底，错误传染 10 余条用例。
- **H-D4**（HIGH）：TC-100 将 148（Topic Alias invalid）作为有效 CONNACK 代码——148 仅适用于 DISCONNECT，不适用于 CONNACK。

实现者按当前文档直接编码会产生至少 3 类畸形 MQTT 数据包（Will Delay Interval ID 错、PUBLISH 长度字段错、CONNACK 原因码 148 错归）。

**必须先返工解决的问题编号**（按修复顺序）：
1. C-D1（Will Delay Interval ID 0x18 + TC-086 字节）
2. C-D2（§5.1 PUBLISH 字节 + §6.8 长度字段注解）
3. H-D4（TC-100 改用真实 CONNACK 代码）
4. H-D1/H-D2/H-D3（§2.12/§10.2 属性 ID 表 3 处错配）
5. H-D5（§2.5 表格列结构修正）
6. M-D1（5.0 Reason Code 验证域改为精确枚举）

修复上述 9 项后，建议复审计一轮以确认所有问题闭环。

---

**审计版本**：deep-r2
**审计日期**：2026-08-04
**对照版本**：14-mqtt-design.md v1.1 (2101 行)
**依据规范**：MQTT 3.1.1 (OASIS 2014 / ISO 20922:2016)；MQTT 5.0 (OASIS 2018 / RFC 9560)