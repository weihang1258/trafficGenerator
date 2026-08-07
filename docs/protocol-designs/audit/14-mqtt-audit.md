# MQTT 设计文档对抗审计报告

**审计对象**：`docs/protocol-designs/14-mqtt-design.md`（1760 行，声称 85 条用例）
**审计日期**：2026-08-03
**审计人**：独立协议审计（与设计者无交叉）
**审计依据**：
1. MQTT 3.1.1（OASIS Standard 2014，ISO/IEC 20922:2016）§2.1/§2.3/§3.x/§4.7
2. MQTT 5.0（OASIS Standard 2018，RFC 9560 信息参考）§1.5.5/§3.x/§4.x
3. `CLAUDE.md` 测试策略 8 条强制规则
4. `trafficgen/internal/protocol/socks5/socks5.go`（Planner 参考实现模式）
5. 同目录 13-modbus-design.md §9.4「与扩展表对照」先例（对照项）

---

## 1. 审计概览

### 1.1 审计方法

- 通读全文 1760 行（§1 概述 → §10 速查表），对每一处字节级期望值逐字节验算（Remaining Length、长度字段、VBI 边界），共发现 **3 处测试期望字节与实际内容不符**（全部在固定头 Remaining Length 字段）。
- 对 §2.5 Reason Code 表、§2.9 通配符语义、§6.8 Topic Alias 场景逐条对照 RFC 原文，发现 **2 处事实性 RFC 错误**（5.0 Reason Code 135/144 含义错配；`#` 匹配"所有主题"表述错误）。
- 对 §8.4 覆盖清单逐字段对照 §7 用例清单，发现 **4 类"声称覆盖但零测试"字段**（Will DelayInterval、Property vbi/byte Format、ConnectAckSessionPresent、MQTTSession 会话级覆盖字段）。
- 对 §7.8 计数表逐节重数，发现分类计数与实际条目不符（§7.3 实为 10 条声称 11；§7.5 实为 29 条声称 28，"045a/b 等子项"不存在）。

### 1.2 总体结论

设计文档**结构完整**：状态机、业务场景、边界表、集成点、对抗性测试（TC-073/074/076）均覆盖，多会话 FlowID/GroupID 机制与 socks5 先例一致，这是本仓库协议设计中较好的部分。但存在三类系统性缺陷：

1. **字节级期望错误（CRITICAL ×3）**：TC-MQTT-001/010/012 的期望 payload 内部自相矛盾（声明的 Remaining Length 与实际字节数不符）。若实现者照抄测试期望，将产出 Wireshark 标记为 malformed 的 CONNECT/SUBSCRIBE 包，且测试会因 `bytes.Equal` 永远失败——这正是 CLAUDE.md 审计史上"测试测了错误期望还全绿"的反向变体（此处是测试期望本身就是错的）。
2. **内部矛盾（HIGH ×5）**：同一文档内 §6.8 vs §6.12 vs TC-043 对"空 Topic Name"三处矛盾；TC-022b(512) vs MinMSS=536 矛盾；KeepAlive"0→60"与"显式 0=禁用"矛盾；TC-MQTT-015 期望文本与断言矛盾；v4 对 v5-only 字段"忽略 vs 报错"政策矛盾。
3. **虚假覆盖声明（HIGH ×1，M ×4）**：§8.4 声称全字段有测试，实际 5 个字段（DelayInterval、Will.Retain=1、ConnectAckSessionPresent、Property byte/vbi Format、会话级 Username/Will/Properties 覆盖）零用例。

### 1.3 严重度分布

| 严重度 | 数量 | 说明 |
|--------|------|------|
| CRITICAL | 3 | 测试期望字节错误 → 实现照抄即产出畸形包 |
| HIGH | 9 | RFC 事实错误 / 内部矛盾 / 虚假覆盖声明 |
| MEDIUM | 13 | 缺失校验规则、缺失必填字段测试、语义未定义 |
| LOW | 7 | 表述不精确、计数不符、政策未声明 |
| **合计** | **32** | |

### 1.4 设计中的亮点（予以肯定）

- TC-073（PacketWorkers=8 不乱序）、TC-074（并发 task 不串包）、TC-076（ctx 取消）、TC-071（ValidationErrors 透传 task 失败）直接命中 CLAUDE.md §4/§6/§7 的历史教训。
- §8.8 已知陷阱清单（PUBREL flags=0x02 强制、VBI 跃迁点、FlowID 独立、Properties Length 不含自身）吸取了已实现协议（SOCKS5/LDAP/OpenVPN/MySQL）的踩坑记录，方向正确。
- §1.4 明确"不实现真实 broker 行为"的作用域声明，诚实且必要。
- 多会话机制（§5.4/§5.5）与 socks5 `:udp` 子流先例一致，FlowID 隔离、GroupID 共享的设计正确，TC-072/037/037a 有对应用例。

### 1.5 RFC 一致性逐项核查表（维度 1 全量核对结果）

对设计 §2 报文格式每一行与 MQTT 3.1.1 / 5.0 原文逐项核对：

| # | 核查项 | RFC 要求 | 设计结论 | 状态 |
|---|--------|---------|---------|------|
| 1 | 固定头第一字节 = Type(4)<<4 \| Flags(4) | 3.1.1 §2.1 | §2.1/§2.2 正确 | ✓ |
| 2 | CONNECT=0x10, CONNACK=0x20, PUBACK=0x40, PINGREQ=0xC0, PINGRESP=0xD0, DISCONNECT=0xE0 | 3.1.1 §2.1 表 | 全部正确 | ✓ |
| 3 | PUBREL 固定头 flags=0x02 | 3.1.1 §2.1 / §3.6.1 | 写死强制，不接受用户覆盖（§4.3） | ✓ |
| 4 | SUBSCRIBE/UNSUBSCRIBE flags=0x02 | 3.1.1 §2.1 | 正确（§10.1） | ✓ |
| 5 | PUBLISH flags = DUP\QoS\Retain 布局（bit3/bit2-1/bit0） | 3.1.1 §3.3.1 | 正确（§2.6） | ✓ |
| 6 | QoS=3 非法（接收方须断连） | 3.1.1 §3.3.1 | Validate 拒绝（§4.3/TC-021） | ✓ |
| 7 | VBI 1-4 字节、最大 268,435,455 | 3.1.1 §2.2.3 | §2.3 表正确，7 边界值有测 | ✓ |
| 8 | VBI 非最小编码/5 字节 = malformed | 5.0 §1.5.5 | **无解码负向测试** | ✗ M-8 |
| 9 | CONNECT 协议名 "MQTT" 4 字节 + 级别 4/5 | 3.1.1 §3.1.2 | 正确 | ✓ |
| 10 | Connect Flags bit 布局（bit7 user/bit6 pass/bit5 will-retain/bit4-3 will-qos/bit2 will/bit1 clean/bit0 保留0） | 3.1.1 §3.1.2.3 | §2.4 正确 | ✓ |
| 11 | CONNECT payload 顺序 ClientID→Will→User→Pass | 3.1.1 §3.1.3 | §2.4 正确；TC-010/011 有测 | ✓（字节值有错见 C-2） |
| 12 | CONNACK 3.1.1 = SessionPresent(1) + ReturnCode(1) | 3.1.1 §3.2.2 | 正确 | ✓ |
| 13 | CONNACK 5.0 = flags + ReasonCode + Properties（Length 必填） | 5.0 §3.2.2 | **v5 CONNACK 无属性时 0x00 无测试** | ✗ M-1 |
| 14 | CleanSession=1 时 SessionPresent 必须 0 | 3.1.1 §3.2.2.1 | **无校验** | ✗ M-3 |
| 15 | CONNACK Reason≠0 时 SessionPresent 必须 0 | 5.0 §3.2.2.2 | **无校验** | ✗ M-2 |
| 16 | PUBLISH QoS0 无 PacketID；QoS1/2 必有 | 3.1.1 §3.3.2.2 | 正确（TC-028 断言无 PacketID） | ✓ |
| 17 | PUBLISH Topic 禁通配符 | 3.1.1 §4.7.1 | **无 Validate 规则** | ✗ M-6 |
| 18 | DUP 仅重传置 1（首次必须 0） | 3.1.1 §3.3.1.1 | 设计允许首次 DUP=1 未标注负向 | ✗ L-3 |
| 19 | QoS1：PUBLISH→PUBACK 同 PacketID | 3.1.1 §3.4 | 正确（TC-029） | ✓ |
| 20 | QoS2：PUBLISH→PUBREC→PUBREL→PUBCOMP 同 PacketID | 3.1.1 §3.5 | 正确（TC-030/018） | ✓ |
| 21 | QoS2 下行方向：PUBREC up/PUBREL down/PUBCOMP up | 3.1.1 §3.5 | **未定义、无测试** | ✗ H-9 |
| 22 | SUBSCRIBE payload = filter(2-len) + options(1) | 3.1.1 §3.8.3 | 正确 | ✓（字节值有错见 C-3） |
| 23 | SUBACK payload = 每 filter 一个 reason code | 3.1.1 §3.9 | 正确（TC-013） | ✓ |
| 24 | PINGREQ/PINGRESP 无 payload（0xC0 0x00 / 0xD0 0x00） | 3.1.1 §3.12/§3.13 | 正确（TC-014） | ✓ |
| 25 | DISCONNECT 3.1.1 仅 C→S | 3.1.1 §3.14.1 | §2.2 标"双向"**错误** | ✗ L-1 |
| 26 | DISCONNECT 5.0 = ReasonCode + Properties（Length 必填） | 5.0 §3.14.2 | TC-015 文本与断言矛盾 | ✗ H-1 |
| 27 | 5.0 Properties Length 是 VBI 且编码不含自身 | 5.0 §2.2.2 | 正确（§8.8 有记） | ✓ |
| 28 | Topic Alias 首次使用必须非空 Topic Name | 5.0 §3.3.2.3.4 | **§6.8 场景违规** | ✗ H-2 |
| 29 | 通配符 filter 不匹配 `$` 开头 topic | 3.1.1 §4.7.2 | §2.9"# 匹配所有主题"**错误** | ✗ L-2 |
| 30 | Shared Subscriptions `$share/group/filter` | 5.0 §4.8.2 | **零说明零用例** | ✗ L-2 |
| 31 | AUTH 仅 5.0 | 5.0 §3.15 | 正确标注 | ✓（不可配置见 M-4） |
| 32 | 5.0 Reason Code 表值 | 5.0 §2.4 | **135/144 两处错** | ✗ H-3 |
| 33 | KeepAlive=0 = 禁用保活 | 3.1.1 §3.1.2.5 | 语义正确但**不可表达**（int 歧义） | ✗ H-7 |
| 34 | 空 ClientID 仅允许 CleanSession=1 | 3.1.1 §3.1.3.1 | 正确（强制 Clean） | ✓（冲突组合未定义见 L-6） |
| 35 | Will 触发条件 = 异常断开（非 DISCONNECT） | 3.1.1 §3.1.2.5 | 正确（Disconnect=false 建模） | ✓（包序列有缺陷见 H-4） |

核查表结论：35 项中 **22 项正确、13 项存在问题**（3 CRITICAL 字节、3 事实错误、7 缺失规则/测试）。问题集中在"v5 必填字段的 0 值表示"与"负向/边界规则"两类。

---

## 2. CRITICAL 问题

### C-1：TC-MQTT-001 / §5.1 CONNECT 期望 payload 的 Remaining Length 错误（15 ≠ 14）

- **位置**：§5.1 表 Index 3（line 571）；TC-MQTT-001 期望 payload（line 952）。
- **问题**：期望字节 `10 0f 00 04 4d 51 54 54 04 02 00 3c 00 02 63 31` 中 Remaining Length 声明为 `0x0f`（=15），但剩余字节实际为 14 个：`00 04`(2) + `4d 51 54 54`(4) + `04`(1) + `02`(1) + `00 3c`(2) + `00 02`(2) + `63 31`(2) = **14**。
- **RFC 依据**：MQTT 3.1.1 §2.2.3 Remaining Length = 固定头之后所有字节数。正确值应为 `0x0e`。
- **影响**：TC-001 断言 `bytes.Equal(payload, wantBytes)`——按文档实现的 builder 要么产出畸形 CONNECT（Wireshark 报 malformed），要么测试永远失败。默认场景是 TC-016/022/065 等十余条用例的基底，错误会连锁传染。
- **修复**：改 `0f` 为 `0e`，并加一条"Remaining Length == 实际剩余字节数"的自洽断言辅助函数。

### C-2：TC-MQTT-010 CONNECT 认证 payload 的 Remaining Length 严重错误（23 ≠ 38）

- **位置**：TC-MQTT-010（line 1022-1026）。
- **问题**：期望字节 `10 17 00 04 4d 51 54 54 04 c2 00 3c 00 0b 61 75 74 68 2d 63 6c 69 65 6e 74 00 05 61 64 6d 69 6e 00 06 73 65 63 72 65 74` 声明 Remaining Length = `0x17`（=23），且正文明确写"Remaining Length 23"。实际剩余字节：协议名段 6 + level 1 + flags 1 + keepalive 2 + ClientID 长度字段 2 + `auth-client` 11 + Username 长度字段 2 + `admin` 5 + Password 长度字段 2 + `secret` 6 = **38**。正确值 `0x26`。
- **影响**：同 C-1。此用例是全认证路径（§6.7）的字节基准，错误直接产出畸形 CONNECT。
- **修复**：`0x17` → `0x26`，正文"Remaining Length 23" → 38。

### C-3：TC-MQTT-012 / §6.4 SUBSCRIBE 期望 payload 双错误（filter 长度 7≠8、Remaining Length 12≠13）

- **位置**：TC-MQTT-012（line 1037-1043）；§6.4 断言（line 705-706）。
- **问题**：期望字节 `82 0c 00 01 00 07 73 65 6e 73 6f 72 2f 2b 00`：
  1. 正文与 §6.4 均称"filter 长度 7"，但 `sensor/+` 是 **8 个字符**（s-e-n-s-o-r-/-+），长度字段 `00 07` 应为 `00 08`；
  2. 剩余字节 = PacketID 2 + 长度字段 2 + filter 8 + Options 1 = **13**，Remaining Length `0x0c`（=12）应为 `0x0d`。
- **影响**：按期望实现的 SUBSCRIBE 会少 1 字节或长度字段错，Wireshark 解析错位；TC-041（通配符用例）同样依赖 `sensor/+` 的字面量长度。
- **修复**：`82 0d 00 01 00 08 73 65 6e 73 6f 72 2f 2b 00`，两处正文同步改正。

---

## 3. HIGH 问题

### H-1：TC-MQTT-015 DISCONNECT 5.0 期望文本与断言自相矛盾

- **位置**：TC-MQTT-015（line 1057-1061）。
- **问题**：期望文本写 `E0 01 00`（RemainingLen=1, ReasonCode=0）+ "Properties Length=0"——RemainingLen=1 时根本没有空间放 Properties Length；随后断言又写 `bytes.Equal(payload, []byte{0xE0, 0x02, 0x00, 0x00})`（RemainingLen=2, Reason=0, PropLen=0）。两者互斥。
- **RFC 依据**：RFC 9560 §3.14.2：DISCONNECT 的 Variable Header = Reason Code + Properties，Properties Length 是**必填**字段（可为 0）。断言值 `E0 02 00 00` 正确，期望文本 `E0 01 00` 为畸形包。
- **影响**：实现者按文本还是按断言实现？文档内部打架，且无第三条用例澄清"v5 DISCONNECT 无 Properties 时也必须写 0x00"这一规则。
- **修复**：统一为 `E0 02 00 00`，并在期望文本中明确"Reason Code 与 Properties Length（=0x00）均必填"。

### H-2：§6.8 Topic Alias=1 + 空 Topic Name 违反 RFC 9560 §3.3.2.3.4，且与 §6.12/TC-043 三处矛盾

- **位置**：§6.8 输入 `"topic": ""`（line 801）与期望"PUBLISH 因 Topic Alias=1 可携带空 Topic Name（broker 用上次的 alias 映射）"（line 815）；§6.12"PUBLISH Topic=空 → Validate 报错"（line 906）；TC-MQTT-043（line 1250-1253）"报错（不含 Topic Alias 5.0 例外）"；§8.8（line 1551）。
- **问题**：
  1. RFC 9560 §3.3.2.3.4：**首个**携带某 Topic Alias 值的 PUBLISH 若 Topic Name 为空即协议错误——alias 映射必须先由非空 Topic Name 建立，之后的 PUBLISH 才能复用空 Topic Name。§6.8 是该连接的**第一条且唯一一条** PUBLISH，alias=1 从未建立过映射，"broker 用上次的 alias 映射"无上次可言。
  2. 文档内部三处矛盾：§6.8 期望空 topic 合法；§6.12 与 TC-043 断言空 topic 一律报错；TC-043 括号又承认"存在 Topic Alias 5.0 例外"但不测试它。实现者无法确定空 topic 何时放行。
- **影响**：按 §6.8 实现 → 产出被真实 broker 拒绝的协议错误流量（非刻意负向）；按 §6.12 实现 → §6.8 用例失败。且 alias 例外路径**零测试**（CLAUDE.md §3"分支存在即需测试"反模式）。
- **修复**：① §6.8 改为"先发一条 topic 非空的 PUBLISH 建立 alias=1，再发空 topic 复用"的两步序列；② §6.12/TC-043 明确空 topic + 无 alias 属性 → 报错，空 topic + 有 alias 且已建立映射 → 合法，并为两条路径各加独立用例。

### H-3：§2.5 5.0 Reason Code 表两处事实错误（135、144 错配）

- **位置**：§2.5 表（line 163）。
- **问题**：表列"5.0 扩展：128=未指定错误、129=畸形包、**135=协议错误**、**144=超出主题别名最大值**"。
  - RFC 9560 §2.4：`0x87`(135) = **Not authorized（未授权）**；Protocol Error（协议错误）= `0x82`(130)。
  - `0x90`(144) = **Topic Name invalid（主题名非法）**；Topic Alias invalid（主题别名非法）= `0x94`(148)。
- **影响**：ConnectAckCode 是 `int` 自由字段（§3.1），用户设 135/144 时按此表理解，产出与预期含义不同的 CONNACK；实现者若按表实现"语义常量"会直接错。
- **修复**：改正为 130=协议错误、135=未授权、144=主题名非法，并补 148=主题别名非法；同时为 130/135/144/148 各加一条 CONNACK 用例（当前 §7.5 只测 0-5）。

### H-4：§6.5 will 场景在 TCP 挥手后发 will PUBLISH——违反文档自身不变量，且断言非确定性

- **位置**：§6.5（line 709-731）；§4.3（line 549-556）。
- **问题**：
  1. §6.5 期望序列"3 握手 → CONNECT → CONNACK → **TCP RST 或 FIN** → broker 发 will PUBLISH(down) → PUBACK(up)"——在客户端 TCP 连接**已关闭之后**、同一 4-tuple 上继续发 MQTT 包。这直接违反 §4.3 自声明的"DISCONNECT 后无更多 MQTT 包"不变量（虽然这里是 FIN 不是 DISCONNECT，但"挥手后无更多数据"的语义同样被破坏），且挥手后的 seq/ack 记账（FIN 各消耗一个序号）文档完全未定义，实现者无从确定 broker 侧 PUBLISH 的 seq。
  2. "PUBACK(up, **模拟客户端在另一连接上回 ACK，或由 broker 内部完成**)"——"或"字使断言非确定性；RFC 语义上 will 是 broker 发给**其他订阅者**的消息（3.1.1 §3.1.3.2），不存在"死客户端回 ACK"。
  3. "共约 11 包"——"约"字违反 CLAUDE.md §5（断言可观见结果）。RST 变体 8 包、FIN 变体 10 包，"约 11"哪个都不对。
- **影响**：此场景是 will 业务（设计卖点之一）的唯一用例，非确定性断言 = 实现后可随意"通过"。
- **修复**：明确 RST 或 FIN 二选一；will PUBLISH 改为"客户端 FIN 前的下行段"（broker 在检测到断开前已缓存）或干脆定义挥手后下行段的 seq/ack 规则；PUBACK 去掉"或由 broker 内部完成"；给出精确包数。

### H-5：TC-MQTT-022b MSS=512 与 MinMSS=536 常量直接矛盾

- **位置**：TC-MQTT-022b（line 1116-1120）"TCP.MSS=512 → 接受，拆 8 段（512×7+416）"；§9.4 常量 `MinMSS = 536`（line 1618）；TC-MQTT-022c（line 1122-1126）"MSS=100（< MinMSS=536）→ 报错"。
- **问题**：512 < 536。TC-022b 的标题自称"MSS=MinMSS 强制下限"（仿佛 512 就是下限），与常量块 MinMSS=536 及 TC-022c 的判断条件自相矛盾。若实现 Validate 用 MinMSS=536 拒绝 <536，TC-022b 直接失败；若为通过 TC-022b 放开到 512，TC-022c 的"<536 报错"又失效。
- **影响**：下限值三处不一致，实现者无从取信。
- **修复**：统一口径（建议 MinMSS=512 或 536 二选一，两用例与常量同步），并补一条"恰好等于 MinMSS 时接受、MinMSS-1 时拒绝"的边界用例。

### H-6：§8.4 覆盖清单虚假声明——4 类字段声称覆盖但零用例

- **位置**：§8.4（line 1505-1512）vs §7 全部用例。
- **问题**（逐条核对 §7 用例清单，以下字段**没有任何测试**）：
  1. **MQTTWill.DelayInterval**（line 1508 声称"全部覆盖"）：全文无任何用例设置 `will.delay_interval`，其 5.0 Will Properties 编码（ID 0x18）零测试。
  2. **MQTTProperty 7 种 Format"各至少 1 条"**（line 1511 声称）：`byte`（0x01 Payload Format Indicator）与 `vbi`（0x0B Subscription Identifier）两种 Format **零正测**（TC-061 只有 binary 负测、TC-062 只有 uint32 负测）。
  3. **ConnectAckSessionPresent**（line 1507 声称"全部有至少 1 条测试"）：§7 无任何用例设置该字段（CONNACK byte[0] bit0=1 的字节断言不存在）。
  4. **MQTTSession"所有可覆盖字段"**（line 1512 声称）：TC-037/037a/072 只覆盖 client_id/messages/src_port；会话级 Username/Password/Will/Properties/PingAfterMessages/Disconnect 覆盖与继承**零用例**。
  5. 顺带：**MQTTWill.Retain=1**（Will Retain bit5 → flags 0x2E）与 **Will QoS=2**（bit4 → flags 0x16）也无正测（TC-011 只测 QoS1 且 retain=false）。
- **影响**：这正是 CLAUDE.md §1 明文记录的历史反模式（"FlowModel 28 字段 6 个零测试，永远静默零值"）在**设计文档自身的审计清单**里重演——清单变成不可信的摆设。
- **修复**：删除或修正清单声明；为上述字段各补 1 条正测（字节级断言），并在实现完成后由 reviewer 用脚本核对"每个 Config 字段 ≥1 条用例引用"。

### H-7：KeepAlive `int`+omitempty 无法区分"缺省→60"与"显式 0→禁用"，§3.7 自相矛盾

- **位置**：§3.7（line 478）"KeepAlive | 60 | **0 → 60**（单会话模式）；**显式 0 在 spec 中视为'禁用保活'**，planner 输出 0x00 0x00"；§3.1（line 294）。
- **问题**：`KeepAlive int` + `json:"keep_alive,omitempty"` 下，JSON 缺省与显式 `"keep_alive": 0` 解析结果**完全相同**（都是 0），无法区分"缺省（→60）"与"显式 0（→输出 0x00 0x00）"。§3.7 两行行为互斥却共用同一输入表示。且 §7 无任何 `keep_alive: 0` 用例验证"0x00 0x00 输出"这一声称行为（TC-036 只测 30）。
- **影响**：实现者必然二选一，另一行为无法达成；声称的"显式 0 禁用保活"功能实际不可实现。
- **修复**：改 `KeepAlive *int`（nil→60，*0→禁用），或删除"显式 0"行为声明；补 `keep_alive: 0` 用例断言 CONNECT 字节 `00 00`。

### H-8：扩展表（mqttProtRpt）27 字段映射完全缺失——无"与扩展表对照"章节

- **位置**：全文（§3/§5/§6 均无）；对照先例：13-modbus-design.md §9.4「与扩展表对照」明确列出"扩展表字段 | 来源"表并由 `internal/core/report.go` 聚合上报。
- **问题**：本文档仅在开头声明"扩展表节点：mqttProtRpt"（line 6），但从未定义 MQTT 相关上报字段（tx_id/version/type/dup/qos_level/retain/reason_codes/connack_session_present 等 27 字段体系）如何从 Config/生成流量映射到 report 输出。其中：
  - `tx_id` → 未说明（PacketID？SUBSCRIBE 的 PacketID？）；
  - `version` → MQTTConfig.Version ✓ 存在但无上报说明；
  - `type` → 包类型分布（CONNECT/PUBLISH/...）无聚合定义；
  - `dup`/`qos_level`/`retain` → MQTTMessage 字段 ✓ 存在但无上报说明；
  - `reason_codes` → ConnectAckCode + AckReasonCodes 双来源，合并规则未定义；
  - `connack_session_present` → ConnectAckSessionPresent ✓ 存在但无上报说明。
- **影响**：与 modbus（§9.4）等已设计文档的交付标准不一致；实现者无从实现 report 层，扩展表节点名成为空头支票。
- **修复**：仿 modbus §9.4 增加"与扩展表对照"章节，逐字段列出"扩展表字段 | 来源 | 聚合方式"，并在 §7 补 report 层集成用例（TC-070 已覆盖 pcap 字节，但未覆盖 report 字段值）。

### H-9：下行（direction="down"）QoS1/2 的 ack 链方向完全未定义、零测试

- **位置**：§3.3 Direction 注释（line 392）；§2.7/§2.8 方向图（line 181-201）仅画了 sender→receiver 泛化方向；TC-031 下行用例是 QoS0。
- **问题**：对"server→client"的 QoS1 PUBLISH，正确 ack 链为 PUBACK **up**（客户端回）；QoS2 为 PUBREC **up** → PUBREL **down**（服务端发）→ PUBCOMP **up**——**中段方向翻转**。文档对下行消息的 ack 方向只字未提，也无任何用例断言下行 QoS1/2 的每包方向。实现者极易照搬上行 ack 方向（SOCKS5 4 方对抗审查史已有同型教训：测试只测上行路径）。
- **影响**：下行 QoS1/2 的字节序列方向错误将静默通过全部现有用例。
- **修复**：§2.7/§2.8 补充"方向翻转表"（上行：PUBLISH up→PUBACK down；下行：PUBLISH down→PUBACK up；QoS2 四包方向矩阵）；新增 TC：down QoS1 断言 PUBACK 方向=up、down QoS2 断言 PUBREL 方向=down。

---

## 4. MEDIUM 问题

### M-1：v5 无 Properties 包的必填 Properties Length 0x00 无测试

- **位置**：TC-002（v5 CONNECT 含 Properties）、TC-015（DISCONNECT）、§2.5/§2.6。
- **问题**：RFC 9560 中 CONNECT/CONNACK/PUBLISH/SUBACK 的 Properties Length 均**必填**（可为 0）。文档只在 TC-015 间接覆盖了 DISCONNECT 的 0x00 情形；v5 CONNECT（无 properties）、v5 PUBLISH（无 properties）、v5 CONNACK、v5 SUBACK 的"必须写 0x00"均无字节级用例。§3.1 注释"nil = no properties segment"措辞含糊，可能被实现为"整个段省略"。
- **影响**：实现按"省略"理解 → 全部 v5 无属性包畸形。
- **修复**：补 4 条用例（v5 各包型无属性时的 `... 0x00` 字节断言）。

### M-2：CONNACK 5.0"reason≠0 时 Session Present 必须为 0"无校验；ConnectAckCode 取值域无校验

- **位置**：§3.1 ConnectAckCode/ConnectAckSessionPresent（line 308-315）；§6.12 表（line 874-938 无 ConnectAckCode 行）。
- **问题**：
  1. RFC 9560 §3.2.2.2：CONNACK Reason Code ≠ 0 时 Session Present 位**必须**为 0。设计无 Validate 规则，用户可配 ConnectAckCode=5 + SessionPresent=true → 产出协议错误包。
  2. ConnectAckCode 是自由 `int`，3.1.1 合法值仅 0-5（6-255 保留），5.0 合法集为 0/128-160 等；§6.12 无"ConnectAckCode=6（3.1.1）报错""ConnectAckCode=130 合法"等行，Validate 无取值域检查。
- **修复**：Validate 增加取值域与互斥规则；§6.12 补 3 行（6 报错 / 5.0 的 130 接受 / reason≠0+present 报错）+ 各 1 条用例。

### M-3：CleanSession=true + SessionPresent=1 是 3.1.1 协议错误，无校验

- **位置**：§3.1 ConnectAckSessionPresent 注释（line 313-315）。
- **问题**：3.1.1 §3.2.2.1：CleanSession=1 时服务端**必须**置 Session Present=0。设计仅用注释"Only meaningful when CleanSession=false"软约束，Validate 不强制、无负向用例。
- **修复**：Validate 拒绝"CleanSession 默认 true + SessionPresent=true"组合（或自动清零并文档化），补用例。

### M-4：AUTH 包（v5）文档化但不可配置、不可测试、无"不实现"声明

- **位置**：§2.2（line 90）、§10.1（line 1713）。
- **问题**：文档把 AUTH（type 15, `0xF0`）列为支持包型，但 MQTTConfig 无任何字段产生 AUTH（Enhanced Authentication 需要 CONNECT Authentication Method/Data + AUTH 交换），§7 零用例，且未列入 §1.4"不实现的范围"。§8.4 覆盖清单也不提它。文档化但不可达 = 实现验收时"文档功能缺失"争议点。
- **修复**：要么列入 §1.4 不实现范围，要么补 config 字段 + 正测 + v4 禁 AUTH 负测。

### M-5：UNSUBSCRIBE/UNSUBACK 文档化且进审计清单，但"预留不实现"

- **位置**：§2.10（line 226-228）、§10.1（line 1708-1709）、§5.3 `buildUnsubscribe`（line 602）"预留（本期不强制实现 UNSUBSCRIBE）"；§8.1 清单（line 1479）"SUBSCRIBE/UNSUBSCRIBE 固定头 flags 必须 0x02"。
- **问题**：§8.1 的强制清单项要求一个 planner **无法产出**的包型满足 flags=0x02——清单项不可验证。§2.10 对 UNSUBACK（5.0）"每个 filter 一个 Reason Code"的语义描述同样无实现载体。
- **修复**：从 §8.1 清单删除 UNSUBSCRIBE 项，或在 §1.4 明确"UNSUBSCRIBE 本期不实现"，二者择一保持一致。

### M-6：PUBLISH Topic 含通配符（`#`/`+`）RFC 禁止，无 Validate 规则、无用例

- **位置**：§6.11.3（line 890-902）只校验 SUBSCRIBE filter 语法。
- **问题**：3.1.1 §4.7.1：**PUBLISH 的 Topic Name 不得包含通配符**（"The Topic Name in the PUBLISH Packet MUST NOT contain wildcard characters"）。设计对 messages[].topic 无此校验，TC-041 之类的通配符用例只走 SUBSCRIBE 路径。
- **修复**：Validate 增加 PUBLISH topic 禁 `#`/`+` 规则 + 负向用例。

### M-7：Property Identifier × 包类型兼容性与重复标识符无校验

- **位置**：§2.12 表有"适用包"列（line 249-266），§3.5 MQTTProperty 无任何限制。
- **问题**：RFC 9560 中每类包只接受特定 Property ID（如 Session Expiry 0x11 仅 CONNECT/DISCONNECT；Topic Alias 0x23 仅 PUBLISH），且除 User Property（可重复）外同类 Property 不得重复。设计允许用户把任意 ID 放进任意包的 Properties 数组、允许重复，无 Validate、无负向用例（如"PUBLISH properties 含 0x11 → 报错"）。
- **修复**：Validate 增加 ID×包型白名单与重复检查；§6.12 补两行负向用例。

### M-8：VBI 解码负向路径零测试（5 字节、非最小编码、第 4 字节续位）

- **位置**：TC-007/008/009（line 994-1017）。
- **问题**：RFC 9560 §1.5.5 明文要求：接收方对 4 字节上限/第 4 字节续位/非最小编码（如 `0x80 0x00`）须按 malformed 处理。TC-009 只测 `encodeVBI(268435456)` 溢出；decodeVBI 的 error 路径（`decodeVBI([]byte{0x80,0x80,0x80,0x80,0x01})`、`decodeVBI([]byte{0x80,0x00})` 非最小、第 4 字节带续位）**零用例**——而 decodeVBI 是 §5.3 构造函数清单中的一等公民。
- **修复**：补 3 条 decode 负向用例（错误码断言而非仅 err!=nil，CLAUDE.md §5）。

### M-9：v5 Will Flag=1 时 Will Properties Length 必填字节未规定、未测试

- **位置**：§2.4 payload 顺序（line 130-137）"Will Properties (5.0, if Will Flag)"；§3.2 DelayInterval。
- **问题**：RFC 9560 §3.1.3.2.3：Will Flag=1 时 Will Properties 段**必填**（其长度可为 0）。设计未规定"Will 无属性时也要写 0x00 长度字节"；TC-032（will 场景）是默认 Version=4，v5 + will 的组合零用例。
- **修复**：§2.4 明确"Will Flag=1 且无属性 → 0x00 长度字节"；补 v5+will（有/无 DelayInterval 各一）字节级用例。

### M-10：v5-only 字段的 v4 行为政策自相矛盾（DelayInterval 忽略 vs Properties 报错）

- **位置**：§8.8（line 1552）"DelayInterval 在 Version=4 时必须忽略（不报错，silently skip）"；§6.12 末行（line 938）"Version=4 + Properties 非空 → Validate 报错"。
- **问题**：两个同为 v5-only 的配置项，一个静默忽略、一个报错。政策差异未解释，实现者须硬编码两种行为且无用例固化（TC-063 只测了 Properties 报错分支，v4+DelayInterval 的忽略分支零用例——§8.8 自身声称的行为无测试保障）。
- **修复**：统一政策（建议：v5-only 字段在 v4 一律 Validate 报错，或一律忽略并在文档声明），补 v4+DelayInterval 用例。

### M-11：多会话 client_id 唯一性依赖随机数，测试不可复现、真 broker 场景无防护

- **位置**：§3.1 ClientID（line 285-289）"trafficgen-<random6>（auto-generated per flow）"；TC-045/TC-074。
- **问题**：
  1. 自动生成无确定性规定（seed/哈希/计数器均未指定），TC-045 断言"前缀 trafficgen-"尚可，TC-074 断言"不含其他 task 的 ClientID"依赖随机值**恰好互异**——CLAUDE.md 明文要求"random strategies 设 seed 保证可复现"，文档未满足。
  2. 真 broker 语义：同 client_id 并发 = 后连接顶掉前连接（5.0 Reason 0x8E Session taken over）。Sessions 或并发 task 若因随机碰撞/用户配置重复 client_id，真实环境行为与生成字节无关但会误导联调。文档无任何去重/校验。
- **修复**：规定确定性生成（如 `fmt.Sprintf("trafficgen-%06x", atomic.AddUint64(&counter,1))` 或按 4-tuple 哈希）；Validate 检查 Sessions 内 client_id 唯一（显式重复 → 报错）。

### M-12：Sessions 继承语义歧义（slice 字段 inherit vs replace）与 SrcPort 自增基数未定义

- **位置**：§3.1 Sessions 注释（line 338-344）"top-level fields are used as defaults for each session; per-session fields override"；§5.4（line 611-619）"从 spec.SrcPort 起步自增"。
- **问题**：
  1. 顶层 `Messages`/`Subscriptions` 是 slice——session 未设置时"继承"顶层值 = **每条 session 重复发送父级消息**，这是设计意图还是意外？"override"对 slice 是"替换"还是"追加"？无示例、无用例。
  2. `spec.SrcPort=0`（未显式指定）时"从 spec.SrcPort 起步自增"= 0,1,2...——端口 1/2/3 是特权端口，且与 engine 的临时端口分配机制如何衔接未说明（TC-037 期望 36164 起，但 base 从哪来无定义）。
- **修复**：明确 slice 继承/替换语义并补 1 条"顶层 messages + 3 sessions"用例固化；定义 SrcPort=0 时的自增基址来源。

### M-13：PacketID=0 语义自相矛盾（"0=自动分配" vs "0=报错"），自动分配路径无正测

- **位置**：§3.3 注释（line 391）"0 = auto-increment from 1"；§3.7（line 491）"0 = 自动分配"；§6.12（line 928）"PacketID=0 (QoS>0) → Validate 报错"；TC-053。
- **问题**：用户省略 packet_id 时解析结果也是 0——按 §6.12 则所有省略 packet_id 的 QoS1/2 消息全部报错，自动分配永远走不到；按 §3.3 则 TC-053 的"显式 0"与"省略"无法区分。且 §7 中 QoS1/2 正测全部显式给 packet_id（TC-029=100、TC-030=7、TC-005=5、TC-040=5），**自动分配路径（省略 packet_id）无一条正测**。
- **修复**：明确"0=自动分配"（删 TC-053 或改为"显式 0 与省略等价，触发自动分配"），补 TC：省略 packet_id 的 QoS1 用例断言 PUBLISH/PUBACK 共享自增 ID。

---

## 5. LOW 问题

### L-1：§2.2 DISCONNECT 方向标"双向"，3.1.1 下不成立

- **位置**：§2.2 表（line 89）。
- **问题**：3.1.1 §3.14.1：DISCONNECT 是**客户端→服务端**的最终控制包，服务端不得发送 DISCONNECT（只能直接关 TCP）。"双向"仅 5.0 成立。文档未标注版本差异。
- **修复**：改为"3.1.1：C→S；5.0：双向"。

### L-2：§2.9 "`#` 单独匹配所有主题"表述错误；Shared Subscriptions（$share）零说明零用例

- **位置**：§2.9（line 224）；§1.1 宣称 5.0 新增 Shared Subscriptions（line 20）。
- **问题**：3.1.1 §4.7.2 / 5.0 §4.7.2.2：通配符开头的 filter **不得**匹配 `$` 开头 topic（如 `$SYS/...`），`#` 并非"匹配所有主题"。且设计在 §1.1 把 Shared Subscriptions 列为 5.0 特性、任务维度也点名，但全文对 `$share/{group}/{filter}` 语法零说明、零用例（订阅 filter 校验规则未提及 `$share` 的"必须还有至少一层"要求）。
- **修复**：§2.9 更正 `$` 语义；补 `$share` 合法/非法各 1 条用例（`$share/g/sensor/+` 合法、`$share/g` 非法）。

### L-3：DUP=1 于首次传输违反 RFC，文档将其作为正常场景未标注

- **位置**：§6.11.2（line 884-888）、TC-005/TC-040。
- **问题**：3.1.1 §3.3.1.1：**首次发送** PUBLISH 必须 DUP=0，DUP=1 仅重传时设置。设计允许用户对"首条且唯一一条"消息配 dup=true 并作为正常字节构造用例（TC-005 期望 0x3B），未标注这是"负向/畸形流量建模"。作为流量生成器支持 DUP=1 无可厚非，但应显式声明"QoS1+DUP=1 无前置重传 = 非真实语义，仅用于负向测试"。
- **修复**：TC-005 标注"负向流量"并补一条"DUP=1 时无对应重传语义说明"文档句。

### L-4：§7.8 分类计数与实际情况不符（总 85 巧合正确）

- **位置**：§7.8（line 1449-1462）。
- **问题**：逐条重数：§7.3 实为 **10** 条（022,022a,022b,022c,023,024,025,026,026a,027）声称 11；§7.5 实为 **29** 条（038-066）声称 28，且括号"含 045a/b 等子项"中的 **045a/b 不存在**（TC-045 是唯一项）。15+6+10+11+29+7+7 = 85，总数与声称的 85 巧合一致，但分类数字全部错位。
- **修复**：修正分类计数，删除幽灵子项引用。

### L-5：§4.2 QoS1/2 重传 timer 子状态机与 planner 实际行为不符

- **位置**：§4.2（line 527-547）。
- **问题**：§4.2 画出"timer: 未收到 PUBACK → 重发 PUBLISH (DUP=1)"等重传分支，但 §4.3 明言 planner"总是成对生成"，实际**不实现任何 timer/重传**。文档未声明"§4.2 描述真实 MQTT 语义、planner 不实现重传"，实现者或误实现计时器、或 reviewer 误判缺功能。
- **修复**：§4.2 加注"本节为 RFC 语义说明，planner 输出固定序列，不模拟重传"。

### L-6：ClientID 空 + 显式 CleanSession=false 的冲突政策未定义

- **位置**：§3.1（line 285-289）；TC-080（line 1443-1447）。
- **问题**：3.1.1 §3.1.3.1：空 ClientID 仅允许于 CleanSession=1。用户配 `client_id:""` + `clean_session:false` 时，planner 是"强制覆盖为 true"（§3.1 注释口径）还是 Validate 报错？TC-080 只测了空 ClientID + will 组合（CleanSession 默认 true），冲突组合零用例。
- **修复**：明确政策并补用例。

### L-7：TC-046 表述混乱；UTF-8/null 字符/ClientID 长度无负向校验

- **位置**：TC-046（line 1266-1269）"Topic=t(1 字节)+len 字段 2 + payload N + 2 字节固定头 = 127 + 2"——把固定头计入"剩余长度"等式，表述自相矛盾（N=124 的结论是对的）。
- **问题**：同条：RFC 3.1.1 §1.5.3 要求 UTF-8 字符串禁止 U+0000/代理区，且 3.1.1 建议 ClientID 1-23 字节（服务端可放宽）；设计对 topic/username/client_id 的 null 字节、非法 UTF-8、超长 ClientID（>65535）均无 Validate 规则与负向用例（TC-078 只有多字节正测）。
- **修复**：改写 TC-046 表述；补 null 字节 topic 负测。

---

## 6. 字段覆盖率审计（扩展表 27）

扩展表（mqttProtRpt）对应的 MQTT 关键字段与设计覆盖情况逐项核对：

| 扩展表字段 | 设计 Config 对应 | 生成/编码 | 测试 | 上报映射 |
|-----------|-----------------|----------|------|---------|
| tx_id（事务号） | MQTTMessage.PacketID / MQTTSubscribe.PacketID | ✓ 2 字节大端 | 部分（显式 ID 测了，自动分配未测，见 M-13） | ✗ 无 |
| version | MQTTConfig.Version（4/5） | ✓ Protocol Level 0x04/0x05 | ✓ TC-001/TC-002/TC-057/058 | ✗ 无 |
| type（包类型） | 固定头 Type 位 | ✓ | ✓ 各包型第一字节 | ✗ 无分布聚合 |
| dup | MQTTMessage.DUP | ✓ bit3 | ✓ TC-005/TC-040 | ✗ 无 |
| qos_level | MQTTMessage.QoS / MQTTWill.QoS / filter QoS | ✓ bits2-1 | ✓ 0/1/2/3 边界 | ✗ 无 |
| retain | MQTTMessage.Retain / MQTTWill.Retain | ✓ bit0 / bit5 | 部分（PUBLISH retain 测了；**Will Retain=1 未测**） | ✗ 无 |
| reason_codes | ConnectAckCode + AckReasonCodes | ✓ CONNACK/SUBACK | 部分（CONNACK 0-5 测了；**5.0 码 130-160 未测**；SUBACK 非 0x00 授予只测了 0x01/0x80 一次） | ✗ 无 |
| connack_session_present | ConnectAckSessionPresent | ✓ CONNACK byte[0] bit0 | **✗ 零测试** | ✗ 无 |

**结论**：27 字段体系中 MQTT 特有字段的**编码侧**覆盖约 7/8（缺 connack_session_present），**测试侧**覆盖约 5/8（缺 connack_session_present、5.0 reason code 域、will retain），**上报侧全部缺失**（无"与扩展表对照"章节、无 report.go 聚合定义、无 report 集成用例）。其中"上报侧全缺"为核心缺口（H-8）。

---

## 7. 测试用例质量审计（CLAUDE.md §1-§8）

### 7.1 符合策略的方面

- **§4 集成路径**：TC-067~073 覆盖 strategy_convert → 端口默认 → RegisterPlanner → 全链路 pcap → 错误透传 → SubFlow 4-tuple → PacketWorkers=8，跨层完整，明显吸取了"RegisterDualWriter 死代码"教训。
- **§6 并发可观见行为**：TC-073（8 worker 包序）、TC-074（并发 task 字节互斥）测的是可观见结果而非仅 `-race` 干净。
- **§7 失败优先**：文档声明每条用例"失败测试先行"，流程正确。
- **§2 负向路径**：QoS=3、DUP+QoS0、空 topic、超长 topic、PacketID=0、Will 无 topic、Username 空+Password 非空、Version 3/6、filters 空、长度不匹配等负向行较齐（§6.12 表多数行有用例）。

### 7.2 不符合策略的方面（按严重度）

1. **测试期望本身错误（CRITICAL，C-1/C-2/C-3）**：`bytes.Equal` 断言一个自相矛盾的字节串——这不是"测错路径"，是"期望值就是错的"，比 CLAUDE.md §1 记录的反模式更底层。三条用例恰是最基础的 CONNECT/认证 CONNECT/SUBSCRIBE。
2. **§8.4 覆盖清单虚假（H-6）**：清单声明"全部覆盖"，实际 5 字段零用例——设计文档自己违反 §1"每个 spec 字段至少一条用例"。
3. **非确定性断言（H-4）**："或由 broker 内部完成""共约 11 包""TCP RST 或 FIN"——CLAUDE.md §5"断言可观见结果"的直接违反。
4. **声称行为无测试固化（H-7/M-10/L-6）**：显式 0 保活、v4+DelayInterval 忽略、空 ClientID+CleanSession=false 冲突——文档声称的行为全部无用例。
5. **分支存在但无测试（H-2 的 alias 例外、H-9 下行 QoS1/2、M-8 VBI 解码错误、M-1 v5 无属性包）**：全部是"存在代码路径/规格分支，零用例"。
6. **表驱动掩盖缺漏（M-2）**：CONNACK Return Code 表驱动只测 0-5，5.0 的 130-160 域与非法 6-255 域无行。

### 7.3 建议新增用例清单（实现前补齐）

| 新增用例 | 对应问题 |
|---------|---------|
| v5 CONNECT/PUBLISH/CONNACK/SUBACK 无属性时 Properties Length=0x00 | M-1 |
| 下行 QoS1 PUBACK 方向=up；下行 QoS2 PUBREL 方向=down | H-9 |
| ConnectAckCode=6（3.1.1）报错；=130（5.0）接受；reason≠0+SessionPresent=1 报错 | M-2/M-3 |
| PUBLISH topic 含 `#`/`+` 报错 | M-6 |
| PUBLISH properties 含 0x11（Session Expiry）报错；重复 Content Type 报错 | M-7 |
| decodeVBI 5 字节 / 非最小编码 / 第 4 字节续位 → error | M-8 |
| v5 + will（有/无 DelayInterval）CONNECT 字节，含 Will Properties Length=0x00 | M-9 |
| v4 + DelayInterval（silently ignore 或报错，按修复后政策） | M-10 |
| 顶层 messages + 3 sessions 的继承/替换语义 | M-12 |
| 省略 packet_id 的 QoS1 自动分配正测 | M-13 |
| Will Retain=1（flags 0x2E）、Will QoS=2（flags 0x16） | H-6 |
| ConnectAckSessionPresent=true 时 CONNACK byte[0]=0x01 | H-6 |
| Property Format=byte（0x01）、vbi（0x0B）正测 | H-6 |
| `$share/g/sensor/+` 合法 / `$share/g` 非法 | L-2 |
| keep_alive=0 → CONNECT `00 00` | H-7 |
| topic 含 U+0000 报错 | L-7 |

### 7.4 按 CLAUDE.md 八条规则逐条裁定

| 规则 | 裁定 | 依据 |
|------|------|------|
| §1 测试必须从 spec 派生 | **部分违反** | 大多数用例确实从 RFC 章节/字段表派生（文档头声明）；但 §8.4 声称覆盖的 5 个字段（DelayInterval/ConnectAckSessionPresent/byte/vbi Format/会话级字段）从 Config 表派生却无对应用例——"从 spec 派生"只做到了一半 |
| §2 覆盖失败路径 | **部分违反** | 负向用例数量可观（TC-040/042/043/044/053-063 等）；但失败路径集中在校验层，**字节构造层的失败路径**（VBI 解码 malformed、v5 必填字段缺失）全部缺失 |
| §3 每个代码路径独立测试 | **部分违反** | 主路径各包型均有独立用例；但 Topic Alias 例外路径（H-2）、下行 QoS1/2 ack 方向（H-9）、自动分配 PacketID（M-13）、v4+DelayInterval 忽略路径（M-10）均为"存在但零测试"的分支 |
| §4 集成测试 | **遵守** | TC-067~073 覆盖 strategy_convert→注册→全链路→pcap→错误透传→8 worker 乱序，是全文档最强部分 |
| §5 断言可观见结果 | **部分违反** | 绝大多数断言是字节级/包数级（合规）；H-4 的"或由 broker 内部完成""约 11 包"、§6.5"TCP RST 或 FIN"是明确的非确定性断言 |
| §6 并发测正确性 | **遵守** | TC-073（8 worker 包序）、TC-074（并发 task 字节互斥）测的是可观见行为，非仅 `-race` |
| §7 失败测试先行 | **遵守（流程声明）** | 文档声明每条用例失败先行；但 C-1~C-3 的期望字节本身就是错的，"失败测试"会因期望错误而失败，属于先例未校准 |
| §8 对抗性审查测试质量 | **违反** | §8.7 清单自查了测试质量，但 §8.4 覆盖声明虚假（H-6）、§7.8 计数错误（L-4）——自查清单自身未被对抗性核验 |

八条规则裁定：**2 条遵守、4 条部分违反、1 条流程性遵守、1 条违反**。与仓库历史审计（33 问题 7 CRITICAL 的教训）对照：本设计在 §4/§6 上明显吸取了教训，但在 §1/§3 的"字段级覆盖"与"分支级覆盖"上重蹈覆辙。

### 7.5 用例-场景覆盖率统计

对 85 条用例按"设计场景维度"分类统计（与 §7.8 分类不同，此处按功能域）：

| 功能域 | 用例数 | 覆盖评估 |
|--------|--------|---------|
| CONNECT 构造（3.1.1/5.0/认证/will） | TC-001/002/010/011/045/080 ≈ 6 | 好，但字节有错（C-2） |
| CONNACK（各码/session present） | TC-003/017/038/039 ≈ 4 | 码 0-5 覆盖；5.0 码域、SessionPresent 缺失 |
| PUBLISH 构造（QoS0/1/2/retain/dup） | TC-004/005/028/029/030/040 ≈ 6 | 好，但 DUP 语义未标注 |
| QoS ack 链（含下行） | TC-018/030/031 ≈ 3 | 上行完整；**下行 QoS1/2 缺失** |
| SUBSCRIBE/SUBACK | TC-012/013/031/041/042 ≈ 5 | 好，但字节有错（C-3） |
| PING/DISCONNECT | TC-014/015/019/020 ≈ 4 | 好，但 TC-015 自相矛盾 |
| VBI 编解码 | TC-007/008/009/046-050 ≈ 8 | 编码侧优秀；**解码负向缺失** |
| 5.0 Properties | TC-002/035/061/062/063 ≈ 5 | 编码正确；包型兼容性/重复校验缺失 |
| 业务场景（will/retain/auth/keepalive） | TC-032/033/034/036 ≈ 4 | will 场景非确定（H-4）；retain 只测 flags 不测语义 |
| 多会话 | TC-037/037a/072 ≈ 3 | 4-tuple 独立覆盖好；继承/唯一性缺失 |
| 边界（MSS/topic 长/包数/seq） | TC-022-027/051/052/065/066 ≈ 11 | 好；MSS 下限矛盾（H-5） |
| 校验负向 | TC-021/040/042-044/053-063 ≈ 17 | 数量足；域缺 ConnectAckCode/PUBLISH 通配符/Property 兼容 |
| 集成/并发/对抗 | TC-067-080 ≈ 14 | 优秀 |

统计结论：体量分布合理，主要缺口集中在**下行方向**、**v5 必填 0 值**、**v5 码域**与**会话继承**四个角落。

---

## 8. 多会话场景正确性

### 8.1 机制正确性（已核验）

设计的多会话骨架（§3.1 Sessions、§5.4、§5.5）方向正确：每个 session 独立 4-tuple、独立 FlowID（`:mqtt-<i>` 后缀）、独立 TCP seq/ack、独立 PacketIndex、共享 GroupID——与 socks5 `:udp` 子流先例一致，resequencer 隔离性有保障（TC-072/037/037a 覆盖）。

与任务维度 4 的"4-tuple 与 client_id 唯一性"逐项核对：

| 唯一性维度 | 设计状态 | 评估 |
|-----------|---------|------|
| 4-tuple 唯一 | SrcPort 自增 + FlowID 后缀（§5.4） | ✓ 机制正确 |
| client_id 唯一（同 task 内 Sessions） | 无 Validate 检查 | ✗ 显式重复无拦截 |
| client_id 唯一（跨 task/自动生成） | random6 概率保证 | △ 非确定性（M-11） |
| DstPort 统一 1883 | §3.7 默认 | ✓ |

### 8.2 未决点（按风险排序）

1. **client_id 唯一性（M-11）**：Sessions 内显式重复 client_id 无 Validate 校验；自动生成的 random6 无确定性规定，TC-074 的"互斥断言"依赖概率。真 broker 联调时重复 id = session takeover（5.0 Reason 0x8E）。
2. **继承语义（M-12）**：顶层 Messages/Subscriptions 被"作为 defaults"继承——N 个 session 会把父级消息各发一遍，还是 session 一旦有自己的 Messages 就整体替换？设计未定，直接决定 TC-037 变体（顶层 message + sessions）的期望包数。
3. **SrcPort 基址（M-12）**：`spec.SrcPort=0` 时"自增 1"从 0 起步 → 端口 1/2/3，与 engine 临时端口分配机制未衔接。
4. **会话间相对时序（§5.5）**：GroupID 保证同 PacketWorker，但同 worker 内多 flow 的 emit 顺序是"session1 全部包 → session2 全部包"（串行循环，§9.4 第 4 步），与真实 IoT 场景"各客户端交错发包"的时序形态不同——文档未声明这一简化。影响：pcap 中同一时刻只有单客户端在活跃，与"N 设备并发"的业务意图有差距（流量形态上仍合法，属建模选择，但应声明）。

### 8.3 状态机审计补遗（维度 3）

主状态机（§4.1）完整：CONNECT→CONNACK→(SUBSCRIBE/SUBACK)×N→(PUBLISH/ack)×M→(PINGREQ/PINGRESP)→DISCONNECT→挥手，拒绝路径提前退出，均正确。

子状态机（§4.2）两处问题：
- **重传 timer 是伪状态**：QoS1/2 的"未收到 ack → 重发"分支（§4.2）planner 实际不实现（§4.3 自证"总是成对生成"），文档未声明"本节为 RFC 语义说明、planner 不模拟重传"——L-5。
- **缺"下行 QoS2 子状态机"**：§4.2 只有泛化 sender→receiver 图，没有"down 方向 PUBREC up / PUBREL down / PUBCOMP up"的方向矩阵——H-9。

死锁/缺响应防护（§4.3）四条均合理，但 **"DISCONNECT 后无更多 MQTT 包"不变量被 §6.5 will 场景自身违反**（挥手后发 will PUBLISH）——H-4。防护清单自身与业务场景矛盾，是文档级不一致。

---

## 9. 总体评分

### 9.1 分维度评分

| 维度 | 评分 | 说明 |
|------|------|------|
| RFC 一致性 | 6.5/10 | 结构正确，但 3 处字节期望错误 + Reason Code 表 2 处事实错误 + Topic Alias 场景违规 |
| 状态机完整性 | 8/10 | 主状态机/QoS0/1/2/拒绝路径完整，死锁防护明确；仅下行 ack 方向未定义 |
| Config 字段设计 | 7/10 | 结构清晰；KeepAlive 0 语义不可实现、PacketID 0 语义矛盾、v5-only 政策不一致 |
| 测试用例质量 | 6/10 | 85 条体量可观、集成/并发设计优秀；但期望字节错、覆盖声明虚假、非确定性断言 |
| 多会话正确性 | 8/10 | 机制正确；client_id 唯一性、继承语义、SrcPort 基址 3 个未决点 |
| 扩展表覆盖 | 3/10 | 上报侧映射完全缺失 |
| **总体** | **6.3/10** | 结构优秀、可执行性不足；**实现前必须先修复 C-1~C-3 与 H-2/H-5/H-7** |

### 9.2 实现前必改清单（按优先级）

1. C-1/C-2/C-3：修正三处 Remaining Length / 长度字段字节（含 §5.1 表、§6.4 正文）。
2. H-2：重写 §6.8 Topic Alias 场景（先建映射再复用），统一空 topic 政策。
3. H-3：修正 §2.5 5.0 Reason Code 表。
4. H-5：统一 MinMSS 与 TC-022b。
5. H-7：KeepAlive 改 `*int` 或删"显式 0"声明。
6. H-6：按 §7.3 新增用例清单补齐 16 条缺失用例，并修正 §8.4 声明。
7. H-8：新增"与扩展表对照"章节（仿 modbus §9.4）。
8. H-9：定义下行 QoS1/2 ack 方向矩阵。

### 9.3 审计问题统计

| 严重度 | 数量 | 编号 |
|--------|------|------|
| CRITICAL | 3 | C-1, C-2, C-3 |
| HIGH | 9 | H-1 ~ H-9 |
| MEDIUM | 13 | M-1 ~ M-13 |
| LOW | 7 | L-1 ~ L-7 |
| **合计** | **32** | |

**结论**：本设计文档骨架与测试方法论（集成/并发/负向）为仓库内中上水平，但字节级期望存在 3 处直接导致畸形包的硬错误、内部存在 5 处行为矛盾、§8.4 覆盖清单存在虚假声明——按当前文档直接实现，TC-001/010/012 将产出 malformed 包或测试必败，且 will、Topic Alias、下行 QoS2 三个卖点场景的期望不可实现/不可验证。建议实现者按 §9.2 清单修订后再进入开发，修订后文档可复审计。
