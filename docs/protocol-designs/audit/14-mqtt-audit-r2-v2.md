# MQTT 设计文档复审审计报告（v2.0.1 / R2-v2）

**审计对象**：`docs/protocol-designs/14-mqtt-design.md`（v2.0.1，3290 行）
**审计日期**：2026-08-05
**审计人**：独立协议审计（复审；v2.0.1 声称已修复 R1-v2 复审审计 12 问题）
**审计依据**：
1. MQTT 5.0（OASIS Standard 2018，`mqtt-v5.0-os.html` 全文 137 页已下载并逐节检索）
2. MQTT 3.1.1（OASIS Standard 2014，WebFetch 核实关键条款）
3. 上一轮审计（R1-v2，`docs/protocol-designs/audit/14-mqtt-audit-r1-v2.md`，12 问题）
4. `CLAUDE.md` 测试策略 8 条强制规则

**审计方法**：逐节核对 + **所有 HexDump 独立逐字节核算**（脚本重新计算每一段 HexDump 的 Remaining Length 与内容字节数，不信任文档自带核算）+ 规范关键条款从 PDF 全文检索核实（属性 ID 表、Reason Code 表、Subscription Identifier 重复规则、SUBACK 完整 Reason Code 集、Topic Alias 规则、DISCONNECT Properties 节号等）。

---

## 1. 审计概览

### 1.1 总体结论

**是（附条件）**——文档可以进入实现阶段，前提是 H-1 在实现开始前选定修复方案。

v2.0.1 已完整修复 R1-v2 复审审计的全部 12 个问题，且修复经独立核算与规范核实**全部正确落地**：

- **6 处 CRITICAL HexDump Remaining Length**（S2 CONNECT `0x1a`、S3/S4 PUBLISH `0x15`、S7 CONNECT `0x13`、S9 CONNECT `0x2d`、S9 will PUBLISH `0x18`、S10 CONNECT `0x0e`）经脚本独立核算全部自洽（RL 字节 == 内容字节数），无一错误。
- **T-021** 期望字节已修为 `30 05 00 01 74 00 70`（RL=5），核算正确。
- **H-R1 UTF-8 上限**：§2.4/§2.7 已改为"0-65535 全范围无保留值"，与规范 5.0 §1.5.4 原文（"any length in the range 0 to 65,535 bytes"）一致；T-167 表驱动 65535 通过/65536 报错，T-083 与 §2.4 不再矛盾。
- **H-R2**：T-160 已明确断言"QoS0 + 显式 packet_id → Validate 报错"；T-197 编号名已改为 "PUBLISH QoS=3 报错"，无重复定义。
- **H-R3**：S15 CONNECT 已补全 `10 17 ...` 实际字节与核算（RL=23），占位符全部替换。
- **H-R4**：§4.4 增加"broker 视角单向字节序列建模"模型偏差说明，S9 断言与 T-169/T-170 措辞统一，不再声称与 TCP 语义一致。
- **M-R1**：T-132 改为逐条独立断言并注明与 T-004 的分工。
- **M-R2**：§8.6 明确 `*int` "nil 继承、非 nil（含 0）覆盖"，新增 T-177b（顶层 60 + session 0 → `00 00`）。
- **M-R3**：T-115 精简为 CONNECT 无属性一行并注明分工。
- **L-R1**：§8.7.4 MQTTTopicFilter 改 5 字段、MQTTSession 13 字段，核对无误。

### 1.2 严重度分布

| 严重度 | 数量 | 说明 |
|--------|------|------|
| CRITICAL | 0 | |
| HIGH | 1 | H-1：§2.14/§2.4 表行 435/§5.5 把 Subscription Identifier（0x0B）标为"适用 PUBLISH 且可重复"，违反 5.0 §3.3.4 [MQTT-3.3.4-6]（client→server PUBLISH 不得含 Sub ID）与 §3.8.2.1.2（SUBSCRIBE 中 0x0B 不得重复） |
| MEDIUM | 2 | M-1：S12 CONNECT 未声明 Topic Alias Maximum 即使用 Topic Alias=1，违反 5.0 §3.3.2.3.4/§3.1.2.11.5；M-2：§2.10 SUBACK 5.0 Reason Code 列表不完整（漏 0x91/0x97），与 §7.8 T-134 及规范 Table 3-8 不一致 |
| LOW | 3 | L-1：S14 标题"6 包"与正文"8 包"并存 + 旧章节号引用残留（§6.4/§6.6/§6.11/§6.12/§6.13 在 v2.0.0 重编号后无锚点）；L-2：T-041 断言"CONNACK payload = `0x01 0x00`"漏固定头 `20 02` 前缀；L-3：T-043 MSS 分段断言未考虑"PUBLISH 应用层包不可跨 TCP 段拆成多个独立 MQTT 包"约束 |
| **合计** | **6** | |

---

## 2. v2.0.1 修复项独立核验（全部通过）

### 2.1 HexDump Remaining Length 全量独立核算（C-R1~C-R6）

对文档中全部 42 段 HexDump 用脚本独立核算"RL 字节 == 固定头之后内容字节数"：

| 场景 | 字节 | RL | 核算 | 结果 |
|------|------|-----|------|------|
| S1 CONNECT | `10 0e ... 63 31` | 0x0e=14 | 10+2+2 | ✓ |
| S2 CONNECT | `10 1a ...`（client_id=temp-sensor-01） | 0x1a=26 | 10+2+14 | ✓ |
| S2 PUBLISH q0 | `30 11 00 0b ... 32 33 2e 35` | 0x11=17 | 2+11+4 | ✓ |
| S3 PUBLISH q1 | `32 15 00 0a ... 00 64 ...` | 0x15=21 | 2+10+2+7 | ✓ |
| S4 PUBLISH q2 | `34 15 00 0a ... 00 07 ...` | 0x15=21 | 2+10+2+7 | ✓ |
| S5 SUBSCRIBE | `82 0d 00 01 00 08 sensor/+ 00` | 0x0d=13 | 2+2+8+1 | ✓ |
| S5 SUBACK | `90 03 00 01 00` | 0x03=3 | 2+1 | ✓ |
| S6 UNSUBSCRIBE | `a2 0c 00 02 00 08 sensor/+` | 0x0c=12 | 2+2+8 | ✓ |
| S7 CONNECT | `10 13 ... ping-01` | 0x13=19 | 10+2+7 | ✓ |
| S9 CONNECT(will) | `10 2d ... 00 09 device-01 00 0d client/status 00 07 offline` | 0x2d=45 | 10+11+15+9 | ✓ |
| S9 will PUBLISH | `32 18 00 0d client/status 00 01 offline` | 0x18=24 | 2+13+2+7 | ✓ |
| S10 Flow1 CONNECT | `10 0e ... 73 31` | 0x0e=14 | 10+2+2 | ✓ |
| S10 Flow1 PUBLISH | `30 06 00 03 74 2f 31 61` | 0x06=6 | 2+3+1 | ✓ |
| S12 CONNECT | `10 22 ... 0c <props> 00 09 v5-client` | 0x22=34 | 10+1+12+2+9 | ✓ |
| S12 PUBLISH1 | `30 2b 00 0b ... 16 <props> 7b...` | 0x2b=43 | 2+11+1+22+7 | ✓ |
| S12 PUBLISH2 | `30 0d 00 00 03 23 00 01 7b...` | 0x0d=13 | 2+0+1+3+7 | ✓ |
| S13 CONNECT | `10 26 ... admin secret` | 0x26=38 | 10+13+7+8 | ✓ |
| S15 CONNECT | `10 17 ... 00 00 0a timeout-01` | 0x17=23 | 10+1+2+10 | ✓ |
| S15 CONNACK | `20 03 00 00 00` | 0x03=3 | 1+1+1 | ✓ |
| S15 DISCONNECT | `e0 02 8d 00` | 0x02=2 | 1+1 | ✓ |
| T-001/T-011/T-016/T-021 | 各期望字节 | — | — | ✓（T-021 = `30 05`，正确） |

**结论**：R1-v2 的 6 处 CRITICAL 全部正确修复，且未引入新错误。所有 HexDump 的 Remaining Length 均等于固定头之后字节数，文档自带核算也与独立核算一致。

### 2.2 T-021（C-R6）

`30 05 00 01 74 00 70`：RL=5 = 2（TopicLen）+ 1（"t"）+ 1（PropertiesLen）+ 1（"p"）。正确。

### 2.3 H-R1（UTF-8 上限）

- §2.4 现文："长度字段为 2 字节大端无符号整数，**合法范围 0-65535（0xFFFF）全范围，无保留值**；字符串最大 65,535 字节"。与规范 5.0 §1.5.4 逐字一致（"the maximum size of a UTF-8 Encoded String is 65,535 bytes"、"any length in the range 0 to 65,535 bytes"）。
- §2.7 Topic Name 长度字段同步改为 0-65535 全范围。
- T-167 表驱动两行：65535 → Validate 通过；65536 → 报错。与 §2.4 一致，无矛盾。
- T-083：topic 65535 字节，期望长度字段 `0xFF 0xFF`，Validate 通过，RL 核算含 4 字节 VBI。正确。
- §8.5 "string" Format 校验、§8.7.5 topic 65535/65536 边界——一致。

### 2.4 H-R2（T-160/T-161/T-197）

- T-160：场景 `qos: 0, packet_id: 1`，断言明确"Validate 报错（QoS0 PUBLISH 必须无 Packet Identifier，5.0 §3.3.2.2/3.1.1 §3.3.2.2）"，`err` 含 "packet_id"。不再空转。
- T-161：PUBLISH QoS=3 报错（与 T-037 同场景但属合理冗余——T-037 在状态机节、T-161 在规范一致性节，断言相同；两处并存可接受，非重复编号）。
- T-197：编号名已改为 "PUBLISH QoS=3 报错"，场景 `qos: 3` 与名称一致。

### 2.5 H-R3（S15）

S15 CONNECT 已补全 `10 17 00 04 4d 51 54 54 05 02 00 1e 00 00 0a 74 69 6d 65 6f 75 74 2d 30 31` 并附逐字节核算（RL=23 = 10 + 1 + 2 + 10）。T-187 断言基准同步。占位符全部替换。

### 2.6 H-R4（will 时序模型偏差）

§4.4 新增模型偏差说明：明确 will 场景是"broker 视角的单向字节序列建模"——will PUBLISH（down）在客户端断开动作（FIN/RST）**之前**插入同一 4-tuple；标注为**已知模型偏差**（真实 pcap 中 will PUBLISH 由对端在 FIN/RST 后发出）；声明"测试断言（T-169/T-170）以'will PUBLISH 在断开包之前'为基准，不再声称与 TCP 语义一致"。S9 关键断言第 5 条、T-169、T-170 措辞与之一致。§8.7.2 "Will message 场景"清单项一致。

**评估**：该偏差说明诚实、自洽、可执行，是流量生成器约束下的合理建模选择。规范侧（5.0 §3.1.2.5 / 3.1.1 §3.1.2.5）will 确实在异常断开后由 broker 发布，文档不再声称与其一致——满足 H-R4 修复要求。

### 2.7 M-R1（T-004/T-132）

T-132 已改为"每条代码独立测试函数/独立子测试（非表驱动合并）"，并注明与 T-004（表驱动）的分工。符合 CLAUDE.md §8"表驱动不掩盖字段缺漏"。

### 2.8 M-R2（KeepAlive *int 显式 0）

§8.6 指针标量行明确："`*int`/`*bool` 类型 session 字段 nil → 继承顶层；**非 nil（含显式 0）→ 覆盖**"；KeepAlive 三态语义（nil→60、*0→禁用、*N→N）在 session 层成立。T-177b 新增：顶层 60 + session `keep_alive: 0` → 该 session CONNECT KeepAlive 字段 `00 00`。§7.21 计数已含 T-177b（201 条）。

### 2.9 M-R3（T-115）

T-115 已精简为 CONNECT 无属性一行，注明 CONNACK/PUBLISH/SUBACK 无属性版分别由 T-020/T-021/T-022 覆盖。无重复。

### 2.10 L-R1（§8.7.4 字段计数）

MQTTTopicFilter 标"全部 5 字段"（Filter/QoS/NoLocal/RetainAsPublished/RetainHandling），与 §5.4 struct 一致；MQTTSession 标 13 字段，与 §5.6 struct 逐一核对一致（ClientID/KeepAlive/CleanSession/Username/Password/Will/Subscriptions/Messages/PingAfterMessages/Disconnect/Properties/SrcPort/DstPort = 13）。MQTTConfig 15 字段、MQTTWill 5 字段、MQTTMessage 8 字段、MQTTSubscribe 3 字段、MQTTProperty 3 字段——全部与 struct 一致。

---

## 3. 本轮新增问题

### 3.1 HIGH

#### H-1：§2.14/§2.4 表行 435/§5.5 将 Subscription Identifier（0x0B）标为"适用 PUBLISH 且可重复"，违反规范 [MQTT-3.3.4-6] 与 §3.8.2.1.2

**位置**：§2.14 行 435 表行"11 | 0x0B | Subscription Identifier | Variable Byte Integer | PUBLISH, SUBSCRIBE（可重复）"；§2.14 行 468"Property 重复规则：除 User Property（0x26，可重复）和 Subscription Identifier（0x0B，可重复）外，同包内同 ID 不得重复"；§5.5 Validate 规则 2 同。

**描述**：MQTT 5.0 对 Subscription Identifier 的规则比"可重复"复杂得多，文档的两处标注均与规范不符：

1. **client→server 的 PUBLISH 根本不允许携带 Sub ID**。规范 §3.3.4（PUBLISH Actions）："It is a Protocol Error for a PUBLISH packet to contain any Subscription Identifier other than those received in SUBSCRIBE packet which caused it to flow. **A PUBLISH packet sent from a Client to a Server MUST NOT contain a Subscription Identifier** [MQTT-3.3.4-6]"（已从规范 PDF 逐字核实）。Sub ID 是**服务端在向订阅者转发 PUBLISH 时**添加的属性（§3.3.4："the Server MUST send those Subscription Identifiers in the message which is published as the result of the subscriptions"）。trafficgen 的 planner 是客户端视角字节生成器，其 `direction:"up"` 的 PUBLISH 若携带 Sub ID（T-026 正是此配置：`messages: [{properties: [{identifier: 11, format: "vbi", value: "200"}]}]` 方向默认 up）将产出**协议违规流量**。
2. **SUBSCRIBE 中 0x0B 不得重复**。§3.8.2.1.2："It is a Protocol Error to include the Subscription Identifier more than once"（逐字核实）。文档把它与 User Property 并列"可重复"，若 Validate 照此实现，同包两个 0x0B 会被放过，产出 Malformed Packet。
3. **"多个 Sub ID"唯一合法场景**是服务端因一条 PUBLISH 命中多个订阅而向下转发时（§3.3.2.3.8："Multiple Subscription Identifiers will be included if the publication is the result of a match to more than one subscription"），且 [MQTT-3.3.4-4]/[MQTT-3.3.4-5] 限定为服务端转发语义——不是"客户端可在 PUBLISH/SUBSCRIBE 中重复"。

**后果链**：T-026（Property Format=vbi 正测）按当前文档期望"PUBLISH Properties 段含 `0x0B 0xC8 0x01`（ID 0x0B + VBI 200）"且方向为默认 up——这是被 [MQTT-3.3.4-6] 明文禁止的字节序列，测试会"绿"但产出畸形流量（CLAUDE.md §5 警告的模式）；§8.4 PUBLISH 白名单含 0x0B 与规范 Table 2-4 一致（那是"服务端视角"的适用包列），但文档未区分方向，Validate 无从判断。

**依据**：5.0 §3.3.4（[MQTT-3.3.4-6] 逐字）；§3.8.2.1.2（"more than once"逐字）；§3.3.2.3.8（多 Sub ID 的转发语义）。

**修复建议**（三选一，需在设计层面定夺）：
- **方案 A（推荐）**：planner 禁止 up 方向 PUBLISH 携带 0x0B——Validate 报错；down 方向 PUBLISH（模拟 broker 转发）允许 0x0B 且允许重复（多订阅匹配）。§2.14 重复规则改为"除 User Property（0x26）外，同包同 ID 不得重复；down 方向 PUBLISH 的 0x0B 例外（多订阅匹配转发，§3.3.4）"。T-026 改为 down 方向或改为 SUBSCRIBE 携带 0x0B（SUBSCRIBE 中 0x0B 合法但不得重复）。新增测试：up PUBLISH 含 0x0B → 报错；SUBSCRIBE 两个 0x0B → 报错。
- **方案 B**：维持现状但 T-026/S12 场景标注"已知负向建模"（与 T-006 同类注释）。
- **方案 C**：planner 完全禁止 0x0B（本期不实现 Sub ID 语义），Validate 对任何包型的 0x0B 报错。

### 3.2 MEDIUM

#### M-1：S12 使用 Topic Alias=1，但 CONNECT 未声明 Topic Alias Maximum（0x22），违反 5.0 §3.3.2.3.4/§3.1.2.11.5

**位置**：§6 S12（行 1454-1549）。

**描述**：S12 的 CONNECT Properties 只有 Session Expiry（0x11）+ User Property（0x26），**没有 Topic Alias Maximum（0x22）**。按 5.0 §3.1.2.11.5："If the Topic Alias Maximum property is absent, the default value is 0"、"A value of 0 indicates that the Client does not accept any Topic Aliases on this connection"、"If Topic Alias Maximum is absent or zero, the Server MUST NOT send any Topic Aliases to the Client"。随后两条 PUBLISH 携带 Topic Alias=1（0x23）是**客户端→服务端**方向：按 5.0 §3.3.2.3.4 的约束，客户端发送 Topic Alias 受**服务端在 CONNACK 中声明的 Topic Alias Maximum** 限制（"A Client MUST NOT send a PUBLISH packet with a Topic Alias greater than the Topic Alias Maximum value returned by the Server in the CONNACK"），而该场景 CONNACK 为 `20 02 00 00`（无属性）——CONNACK 无 Topic Alias Maximum 时默认 0，即服务端不接受任何 Topic Alias。因此 S12 的字节序列在真实 broker 上会被判 Topic Alias invalid（0x94）断开，是**协议违规序列**。

**依据**：5.0 §3.1.2.11.5（CONNECT 侧 Topic Alias Maximum 缺省 0，值 0 表示客户端不接受任何 Topic Alias——该条约束的是**服务端发给客户端的** alias）；5.0 §3.2.2.3.8（CONNACK 侧缺省 0，值 0 表示服务端不接受任何 Topic Alias，"If Topic Alias Maximum is absent or 0, the Client MUST NOT send any Topic Aliases on to the Server"——**约束客户端**）；5.0 §3.3.2.3.4 与 [MQTT-3.3.2-9]（客户端不得发送超过服务端 CONNACK 所声明 Topic Alias Maximum 的 alias）。

**修复建议**：S12 输入 CONNECT properties 增加 `{"identifier": 34, "format": "uint16", "value": "1"}`（Topic Alias Maximum=1），CONNECT 字节随之更新（Properties Length 0x0c → 0x11，Remaining Length 34 → 39，字节数核算同步）；或在场景中注明"已知负向建模：CONNACK 未声明 Topic Alias Maximum，alias=1 超出服务端能力，属测试 broker 容错的负向流量"（与 T-006 负向建模注释同类）。同时 §8.1 Validate 第 10 条可补充："CONNECT 未设 Topic Alias Maximum 且 PUBLISH 使用 Topic Alias → 警告/报错"（设计选择）。T-185 断言基准随字节同步。

#### M-2：§2.10 SUBACK 5.0 Reason Code 列表不完整（漏 0x91/0x97），与 §7.8 T-134 及规范不一致

**位置**：§2.10 行 339-340 SUBACK 5.0 扩展码列表"0x83=Implementation error | 0x87=Not authorized | 0x8F=Topic Filter invalid | 0x9E=Shared Sub not supported | 0xA1=Sub ID not supported | 0xA2=Wildcard Sub not supported"。

**描述**：规范 5.0 §3.9.3 Table 3-8（Subscribe Reason Codes）完整集为：0x00/0x01/0x02（granted）、0x80（Unspecified error）、0x83、0x87、0x8F、**0x91（Packet Identifier in use）**、**0x97（Quota exceeded）**、0x9E、0xA1、0xA2。文档漏了 0x91 和 0x97。后果链：T-134 只测 {0x80, 0x83, 0x87, 0x8F, 0x9E, 0xA1, 0xA2}；若实现者按 §2.10 列表做 Validate 白名单，用户配 0x91/0x97 会被误拒（或反向——白名单只含表内项，0x91/0x97 未验证即接受，产生非法 SUBACK 字节）。CLAUDE.md §1 要求"每个规范行转换为至少一个测试"，此处规范表 11 行只有 7 行被覆盖。

**依据**：5.0 §3.9.3 Table 3-8 完整 11 行（已从规范 PDF 逐字核实）；5.0 §2.4 Table 2-6 中 0x91/0x97 的"Packets"列含 SUBACK（0x91: "PUBACK, PUBREC, SUBACK, UNSUBACK"；0x97: "CONNACK, PUBACK, PUBREC, SUBACK, DISCONNECT"）。

**修复建议**：§2.10 列表补 0x91、0x97；T-134 的集合补 0x91/0x97（共 9 项）；§8.4 SUBACK 白名单（Property ID）不受影响（那是属性不是 Reason Code）。

### 3.3 LOW

#### L-1：S14 包数自相矛盾 + 多处旧章节号引用残留

**位置**：§6 S14（行 1592"期望包序列（拒绝后跳过后续，6 包）"与行 1612"但实际 planner 发 3 握手 + 2 MQTT + 3 挥手 = 8 包；本场景以 planner 实现为准，最小 6 包"）；T-057 行 2041"见 §6.4"、T-059 行 2051"见 §6.6"、T-002 行 1693"见 §6.12 输入"、§7.5 标题"（§6.11/§6.12）"、§5.1 行 790"see §6.12 boundary"。

**描述**：S14 标题"6 包"与正文"8 包"并存，且表格只列 3 行 MQTT 段（Index 3/4/5），实现者无法判断断言基准（T-032/T-067/T-068 以 PSH-ACK 段数=2 为准，与"8 包"不冲突，但 S14 自身数字应先统一）。章节号：v2.0.0 已将 §6 重编号为 S1-S15，但 T-002/T-057/T-059/§7.5/§5.1 仍引用旧号 §6.4/§6.6/§6.11/§6.12/§6.13——这些引用在文档内无锚点（当前文档无 §6.4/§6.6/§6.11/§6.12/§6.13 小节），实现者无法定位。属文档卫生问题，不影响字节正确性。

**修复建议**：S14 标题改"8 包"或删除"6 包"字样；T-002"§6.12 输入"改"§6 S12 输入"；T-057"§6.4"改"§6 S5"；T-059"§6.6"改"§6 S9/S10"；§7.5 标题"（§6.11/§6.12）"改"（§7.5 自身/§6 边界场景）"或直接删括号。

#### L-2：T-041 断言字节缺固定头前缀

**位置**：§7.2 T-041 行 1946"断言：CONNACK payload = `0x01 0x00`"。

**描述**：CONNACK 完整字节为 `20 02 01 00`（固定头 + 2 字节 VH）。T-041 断言写 `0x01 0x00` 是 VH 部分（正确值），但按 §7.18 系列测试（T-181~T-187）的断言风格是**完整包字节**。若实现者的测试按"payload[0]==0x01 && payload[1]==0x00"取 PSH-ACK 段偏移 2 起，则正确；若按 `bytes.Equal(payload, []byte{0x01,0x00})` 则误。此处未标注"仅 VH 部分"，存在歧义。

**修复建议**：改为"CONNACK 字节 = `20 02 01 00`（固定头 + SP=1 + Code=0）"或明确"VH 部分 = `0x01 0x00`"。

#### L-3：T-043 MSS 分段断言与 MQTT 应用层包不可跨段约束冲突

**位置**：§7.3 T-043（行 1956-1960）："PUBLISH payload 4000 字节，MSS=1460。期望：PUBLISH 拆成 3 段（1460+1460+1080）……3 段 payload 拼接 = 原 4000 字节"。

**描述**：MQTT 是字节流上的应用层协议，PUBLISH 包（含固定头+VH+payload）是一个**完整的应用层消息**，TCP 分段是传输层透明行为——从 MQTT 语义看"PUBLISH 拆成 3 段"是 TCP 层把 4017+ 字节的 PUBLISH 报文按 MSS 切分，每个 TCP 段仍是**同一个 PUBLISH 包的片段**（首个段含 MQTT 固定头），不是 3 个独立 PUBLISH。若实现按 socks5 模板的 `segmentByMSS` 把 payload 切成 3 段、每段各写一个完整 MQTT 固定头，则会产出 3 个畸形 PUBLISH（每段都有 RL 字段但内容不完整）——重放时 broker 会判 Malformed。socks5/RADIUS 等协议的 segmentByMSS 切的是**负载数据**（每个 TCP 段可独立成包），MQTT 的 PUBLISH 整包不可切。T-043 断言"3 段 payload 拼接 = 原 4000 字节"本身暗示分段可拼接，未区分"TCP 层切段"与"应用层拆包"。

**依据**：MQTT 5.0 §2.1.4（Control Packet 定义："Control Packets MUST be sent in a Network Connection and MUST be sent in their entirety"）；TCP 语义（MSS 分段是传输层行为，段内字节是连续流的一部分）。

**修复建议**：T-043/T-044 改为断言"单个 PUBLISH 报文（含固定头）在 TCP 层被切为 N 个段，段首仅第一个含 MQTT 固定头；各段 TCP payload 拼接 = 完整 PUBLISH 字节；接收端按 Remaining Length 重组"；或明确设计决策：PUBLISH 超过 MSS 时**整体**按大包发（单段超 MSS，或依赖内核分段）。实现时在 §10.3.4 的"emit 辅助函数参考 socks5 segmentByMSS"处加注"MQTT PUBLISH 整包不拆，仅 TCP 层分段"。

---

## 4. 规范对照核验通过项（本轮重点复查，全部正确）

1. **属性 ID 表**（§2.14 28 行）：逐行与规范 Table 2-4 比对（含 0x18=Will Delay Interval、0x1A=Response Information、0x15=Authentication Method、0x19=Request Response Information、0x21=Receive Maximum、0x13=Server Keep Alive、0x1F=Reason String、0x22=Topic Alias Maximum、0x27=Maximum Packet Size、0x28/0x29/0x2A 三 Available）全部一致。0x0B 适用包"PUBLISH, SUBSCRIBE"正确（重复规则问题见 M-2）。
2. **5.0 CONNACK 22 个 Reason Code**（§2.6/§8.2）：与规范 Table 3-1 逐项一致；148/141 排除正确（仅 DISCONNECT）；"3.1.1 的 1-5 在 5.0 中不是有效 CONNACK 代码"正确（T-135）。
3. **DISCONNECT 31 个 Reason Code**（§2.12）：与规范 Table 3-10 逐项一致（含 160/161/162）。T-133"表驱动 31 行"与实际 31 项吻合。
4. **CONNACK Session Present 互斥**（§2.6）：CleanStart=1 → SP=0、非零 Reason Code → SP=0，与规范 [MQTT-3.2.2-2]/[MQTT-3.2.2-6] 一致。T-105/T-106 正确。
5. **PUBLISH 第一字节完整表**（§10.1）：12 行全部正确（0x30~0x3D 逐位验算通过）。
6. **VBI 8 边界值**（§2.3/T-008）：128→`80 01`、16383→`FF 7F`、16384→`80 80 01`、2097151→`FF FF 7F`、2097152→`80 80 80 01`、268435455→`FF FF FF 7F` 全部正确。
7. **Will Properties 结构**（§2.5/§3.1/§6 S9、T-023/T-024）：Will Flag=1 时 Will Properties 是 Payload 中 ClientID 之后第一个字段、无属性也写 0x00，与规范 §3.1.3.2/§3.1.3.2.1 一致；T-023 的 `05 18 00 00 00 05` 编码正确。
8. **5.0 各包型 Properties Length 必填**（§2.14/T-019~T-022/T-115）：与规范一致（"If the Remaining Length is less than 4 there is no Property Length and the value of 0 is used"——DISCONNECT RL=2 时省略 Reason Code 和 Property Length 是合法的**最小编码**，文档固定输出 `e0 02 00 00` 4 字节也合法）。注意 §3.6/S8 的 `e0 02 00 00` 与规范"RL=0 的 DISCONNECT 也合法"不冲突。
9. **5.0 3.1.1 字段差异**（§2.5）：Protocol Level 4/5、Clean Session/Clean Start、Password 无 Username（5.0 允许/3.1.1 禁止 [MQTT-3.1.2-22]）全部正确。
10. **Keep Alive=0 语义**（§5.1/T-053/T-177b）："A Keep Alive value of 0 has the effect of turning off the Keep Alive mechanism"——"服务端视为无限保活"表述正确。
11. **Will QoS=3 Malformed**（T-015/T-085）：与规范 [MQTT-3.1.2-12] 一致；RetainHandling=3 Protocol Error（T-155）与规范一致；NoLocal 3.1.1 禁用（T-152）正确（3.1.1 无订阅选项位）。
12. **Topic Alias 规则**（§2.7/T-072~T-074）：空 Topic Name + 无 alias = Protocol Error；alias=0 非法；首次携带某 alias 的 PUBLISH 必须有非空 Topic Name——与规范 §3.3.2.1/[MQTT-3.3.2-8] 一致。T-073/T-074 边界正确。
13. **$share 规则**（§2.10/§8.3/T-111/T-112）：`$share/{ShareName}/{filter}`，ShareName 至少 1 字符、不含 `/`/`+`/`#`、其后必须跟 `/`+filter——与规范 §4.8.2 [MQTT-4.8.2-1]/[MQTT-4.8.2-2] 一致。
14. **PUBLISH 禁通配符**（§2.7/§8.3/T-107）：与规范 [MQTT-4.7.0-1] 一致。
15. **UTF-8 禁止 U+0000/代理区**（§2.4/T-114）：与规范 §1.5.4 [MQTT-1.5.4-1]/[MQTT-1.5.4-2] 一致。
16. **CONNACK/CONNECT/SUBSCRIBE/PUBLISH 各 Properties 白名单**（§8.4）：与规范 Table 2-4 逐项一致（CONNECT 9 项、CONNACK 17 项、PUBLISH 8 项、Will 7 项、SUBSCRIBE 2 项、SUBACK 2 项、ACK 2 项、UNSUBSCRIBE 1 项、UNSUBACK 2 项、DISCONNECT 4 项、AUTH 4 项）。
17. **PUBREL flags=0x02 强制**（T-007/T-193）：与规范 §3.6.1 [MQTT-3.6.1-1] 一致。
18. **QoS2 方向矩阵**（§2.9/T-038）：下行 PUBLISH(down)→PUBREC(up)→PUBREL(down)→PUBCOMP(up) 正确。
19. **3.1.1 CONNACK 4 字节 / 5.0 CONNACK 5 字节**（§3.2/T-020）：正确。
20. **S15 场景语义**：broker 发 DISCONNECT 0x8D down——5.0 允许 Server 发 DISCONNECT（§3.14 双向），Keep Alive timeout 是 Server 侧检测，语义正确。

---

## 5. 测试用例对照 CLAUDE.md §Testing Policy 评估

### 5.1 符合项

- **失败路径覆盖充分**：T-069/071/072/073/075/085-095/099-106/108-110/112/114/116/144/145/155/171-175/189/190——负向用例覆盖全面。
- **边界值**：VBI 8 边界（T-008/009/142/143）、QoS 0/1/2/3、Version 3/4/5/6、PacketID 0/65535、topic 0/65535/65536、MSS MinMSS/±1——覆盖到位。
- **集成测试**：T-121~T-127 覆盖 strategy_convert→默认端口→RegisterPlanner→全链路→ValidationErrors 透传→多会话→PacketWorkers=8——符合 CLAUDE.md §4。
- **并发测试**：T-128（5 task 不串包，断言可观见行为）+ T-129（-race）符合 CLAUDE.md §6。
- **失败测试先行**：§7 引言明确。
- **字段覆盖清单**：§8.7.4 逐字段清单，修复后计数全部正确。
- **字节级场景测试基准**：T-181~T-187 的期望字节经独立核算全部正确（R1-v2 的"测试绿但字节错"问题已根治）。
- **T-160/T-167 修复**：断言明确、与文档规则自洽（见 §2.3/§2.4）。

### 5.2 不符合项（随 H-1/M-1/M-2/L-3 提出）

1. **Sub ID 适用包与重复规则错误**（H-1）：§5.5 规则 2 将 0x0B 列为可重复，§2.14 表行 435 标"可重复"。修复后需补"up PUBLISH 含 0x0B → 报错"、"SUBSCRIBE 两个 0x0B → 报错"测试；T-026 当前期望字节本身违反 [MQTT-3.3.4-6]，需改方向或改场景。
2. **SUBACK Reason Code 白名单覆盖不全**（M-2）：T-134 只测 7 项，规范 Table 3-8 有 11 项（含 0x91/0x97）。修复后 T-134 扩到 9 项（3.1.1 的 0x00/0x01/0x02/0x80 已由 T-017/T-192 覆盖）。
3. **T-043 MSS 分段断言测错层面**（L-3）：见 §3.3 L-3。这是 CLAUDE.md §5"断言可观见结果"的边界案例——按当前断言实现可能产出畸形 PUBLISH 且测试通过。

---

## 6. 结论

**本文档可以进入实现阶段（是，附条件）。**

v2.0.1 将 R1-v2 复审审计的 12 个问题全部正确修复：6 处 HexDump Remaining Length 经独立脚本核算全部自洽（42 段 HexDump 无一错误）、T-021 期望字节正确、UTF-8 上限表述与规范一致、T-160/T-197 断言修正、S15 占位符补全、will 时序模型偏差说明自洽、T-004/T-132 与 T-115 分工明确、KeepAlive `*int` 继承语义定义完整、字段计数正确。规范对照方面，属性 ID 表、CONNACK/DISCONNECT Reason Code 表、Session Present 互斥、$share 规则、Topic Alias 首包规则、UTF-8 规则、VBI 边界等核心内容全部与 MQTT 5.0/3.1.1 原文一致。

本轮发现 **1 HIGH + 2 MEDIUM + 3 LOW**，均为文档表述/白名单完整性问题，不涉及字节级硬错误：

- **H-1**（Sub ID 适用包与"可重复"标注错误）——规范对照层错误，实现前必改，否则会产出畸形流量且测试通过（CLAUDE.md §5 警告模式）。
- **M-1**（S12 缺 Topic Alias Maximum 声明）——协议语义瑕疵，需在实现前定夺（补 CONNECT 属性或标注负向建模），但字节级计算本身正确，不影响其余场景。
- **M-2**（SUBACK 5.0 Reason Code 缺 0x91/0x97）——白名单/测试集合补两项即可。
- **L-1~L-3** 文档卫生与断言歧义，实现时顺手修正。

**建议实现前处理顺序**：先改 H-1（§2.14/§2.4/§5.5 重复规则 + T-026 场景决策 + 补测试）→ M-2（§2.10 列表 + T-134 扩展）→ M-1（S12 场景决策）→ L-1~L-3（文字修正）。H-1 涉及规范对照与测试用例设计抉择（方案 A/B/C），需设计层面定夺；其余为增量修正，不触及文档其余 99% 已核验内容。若团队接受"实现时按本报告修正项处理"且 H-1 选定方案，可直接进入实现。
