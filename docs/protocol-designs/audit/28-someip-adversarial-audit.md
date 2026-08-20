# SOME/IP (28) 三件套对抗审查报告

> 审查日期：2026-08-19
> 审查范围：`28-someip-design.md` / `28-someip-testcase.md` / `cases/someip.json`
> 审查口径：文档阶段（Go 代码未实现，不审查代码逻辑）
> 审查结论：**12 findings (2 CRITICAL, 4 HIGH, 3 MEDIUM, 3 LOW)**

---

## C1 [CRITICAL] S5 OfferService hexdump -- Entry 15 字节而非 16 字节

**文件**: `28-someip-design.md:§6 S5` (第465行 hexdump)

**问题**: S5 OfferService 包2的 Entry 十六进制为 `01 02 12 34 00 01 01 00 00 03 00 00 00 00 00`，共 15 字节。AUTOSAR SOME/IP-SD Entry 固定 16 字节（Type 1B + Index1/NumOpts1 1B + Index2/NumOpts2 1B + Reserved 1B + ServiceID 2B + InstanceID 2B + MajorVersion 1B + TTL 3B + MinorVersion 4B = 16B）。末尾缺失第 16 字节（Reserved，0x00）。

**证据**: tshark 实测 `someipsd.entry.reserved`（byte 3）和 `someipsd.entry.minorver`（bytes 12-15）均为独立字段，16 字节布局下 tshark 正确解析 FindService entry。

**修复建议**: 将 OfferService Entry hex 改为 16 字节：`01 02 12 34 00 01 01 00 00 03 00 00 00 00 00 00`（末尾补 `00`）。

---

## C2 [CRITICAL] S5 OfferService hexdump -- Option Length 字段字节序错误

**文件**: `28-someip-design.md:§6 S5` (第467行 hexdump)

**问题**: Design 的 Option 十六进制为 `01 09 00 00 14 00 00 c8 77 12`（10 字节）。按 AUTOSAR 规范，Option 结构为 Type(1B) + Length(2B BE) + Reserved(1B) + data。该 hex 中 bytes 1-2 = `09 00`，按大端解析为 0x0900 = 2304，但设计文档自身说 Length 应为 9（IPv4 Endpoint len=9）。正确的大端编码应为 `00 09`。

**证据**: tshark `someipsd.option.length` 为 `FT_UINT16 BASE_DEC`，即 16 位大端无符号整数。设计文档 §2.5 明确 "Length=2B" 和 "IPv4 Endpoint len=9"。tshark 实测 `01 09 00 00...` 触发 Malformed Packet 专家提示。

**修复建议**: 将 Option hex 改为 `01 00 09 00 14 00 00 c8 77 12`（11 字节，Length=0x0009=9）。若包含 proto 字节则再加 `11`（UDP=17）在 port 前：`01 00 09 00 14 00 00 c8 11 77 12`（12 字节，proto 字节位置由实现决定，需同步更新 design 描述）。

---

## H1 [HIGH] S5 OfferService hexdump -- Length 字段 (0x38) 与实际 payload 不符

**文件**: `28-someip-design.md:§6 S5` (第462行 hexdump)

**问题**: SOME/IP 头 Length 字段标注为 `00 00 00 38` = 56。但 Length = 8(RequestID..RC) + 全部 payload。payload = SD 头(8B) + Entry(16B) + Option(11B) = 35B。所以 Length = 8 + 35 = 43 = 0x2B，不是 0x38。

同理，Entries Length 字段标注为 `00 00 00 1c` = 28，但单个 Entry 只有 16 字节（或 15 字节含缺失第16字节），与 28 不匹配。

**证据**:
- 设计文档 §2.2 Length 口径："Length = 8 + len(Payload)"
- Payload = 8(SD头) + 16(Entry) + 11(Option) = 35
- 期望 Length = 0x2B, 实际标注 0x38

**修复建议**: 重算 S5 全部字段长度。若标准 OfferService 含 1 个 Entry(16B) + 1 个 Option(11B)：SD payload = 8 + 16 + 11 = 35，Length = 8 + 35 = 43 = 0x2B。Entries Length = 16。更新 hexdump 中所有长度字段。

---

## H2 [HIGH] TP 用例 payload 声明不符 -- design 说 2500B 但 JSON 写 4 字节

**文件**: `28-someip-design.md:§6 S8` (第494行) 与 `cases/someip.json` `someip_tp_segments` (第678行)

**问题**: Design §6 S8 明确声明"载荷 2500B 分 2 段（segment_size=1400 + 余 1100）"，但 JSON 的 `payload` 字段仅为 `[0, 1, 2, 3]`（4 字节）。TP 分段需要 payload 足够大才能触发分段（2500B > 1400B 才能分 2 段），4 字节 payload 不会产生任何分段。

JSON 中 `tp.payload_length` 设为 `2500` 但这只是声明值，实际 wire 字节只有 4 个。OfferedLength = 16 + 2500 = 2516，但实际 payload 只有 4B，这会触发 tshark 的 `someip.tp.fragment.error` 或重组失败。

**证据**: JSON 第 678 行 `"payload": [0, 1, 2, 3]` 只有 4 字节。若要产生真正的 2500B 分段，payload 必须填充为 2500 字节。

**修复建议**: 二选一：(a) 将 payload 改为 2500 字节的随机/填充数组，配合 `tp.enabled` 触发真实分段；或 (b) 如果框架支持 `payload_length` 自动填充，需在 design 和 testcase 文档中明确说明该机制，并将断言调整为验证真正的 2 段输出。

---

## H3 [HIGH] SubscribeEventgroup Ack 用例缺少 Option 要索

**文件**: `28-someip-testcase.md:§4.7` (第327行) / `cases/someip.json` `someip_sd_subscribe` (第487行)

**问题**: SubscribeEventgroupAck 的配置仅包含 `eventgroup_id` 和 `counter`，没有 Option 字段。但在 AUTOSAR SOME/IP-SD 标准中，SubscribeEventgroupAck 通常包含 Option（如 IPv4 Endpoint 或 SD Endpoint）来指定事件通知的目标端点。缺少 Option 可能导致 tshark 警告或 SD 解析不完整。

**证据**: Design §6 S6 的 hexdump 注释中未明确写出 Ack 的 Option 布局。与 S5 OfferService 对比（S5 明确包含 Option IPv4 Endpoint），S6 缺少了对应的 Option。

**修复建议**: 在 SubscribeEventgroupAck 中添加 Option（IPv4 Endpoint 或 SD Endpoint），例如 `"options": [{"type": 1, "ip": "20.0.0.200", "port": 30490}]`，并在 design §6 S6 hexdump 中明确写出 Option 字节。

---

## H4 [HIGH] 缺少 IPv6 SD Option 用例

**文件**: `28-someip-testcase.md:§4.10` / `cases/someip.json` `someip_ipv6` (第722行)

**问题**: `someip_ipv6` 用例仅测试了 IPv6 地址层下的 REQUEST/RESPONSE 方法调用，没有测试 IPv6 SD Option（type 0x06 IPv6 Endpoint）。Design §6 S9 明确提到"IPv6 载体 + IPv6 Endpoint Option（0x06）"，但 testcase 和 JSON 中未实现 SD IPv6 部分的断言。

**证据**: `someip_ipv6` JSON 的 spec 中仅包含 `"service_id": 4660, "method_id": 1, "message_type": "request"`，没有 `sd` 子块，也没有 IPv6 Endpoint Option 断言。

**修复建议**: 增加一个 `someip_sd_ipv6` 用例（或扩展 `someip_ipv6`），使其包含 SD OfferService 并带上 IPv6 Endpoint Option（type 0x06, addr 2001:db8::1, port 30490），断言 `someipsd.option.type=6`、`someipsd.option.ipv6address=2001:db8::1`。

---

## M1 [MEDIUM] S5 FindService 缺少 Minor Version 断言

**文件**: `28-someip-testcase.md:§4.6` / `cases/someip.json` `someip_sd_find_offer` (第416行)

**问题**: FindService 和 OfferService 的 Entry 都包含 Minor Version 字段（bytes 12-15, 32-bit BE），但 `someip_sd_find_offer` 的两个方向都没有断言 `someipsd.entry.minorver`。Design §6 S5 明确提到"Minor Version"是断言要点，但 testcase 缺少该字段断言。

**证据**: 设计 §6 S5 断言列表："entry.type=0x00/0x01、entry.serviceid=0x1234、entry.instanceid=0x0001、majorver=1、ttl=16777215/3、option.type=1"——未列出 minorver。但设计 §2.5 Entry 表中包含 Minor Version（offset 11-14, 4B）。

**修复建议**: 在 `someip_sd_find_offer` 的包1和包2中添加 `someipsd.entry.minorver` 断言。注意 tshark 将该字段显示为十进制（`BASE_DEC`）。

---

## M2 [MEDIUM] SubscribeEventgroup 缺少 Instance ID 断言

**文件**: `cases/someip.json` `someip_sd_subscribe` (第516行)

**问题**: `someip_sd_subscribe` 只断言了 `entry.type`、`entry.serviceid`、`entry.eventgroupid`、`entry.counter`，但缺少 `entry.instanceid` 断言。配置中设置了 `instance_id: 1`，但未验证。

**证据**: JSON 第 508 行 `"instance_id": 1` 被设置，但 fields 断言列表中没有 `someipsd.entry.instanceid`。

**修复建议**: 在包1（Subscribe）中添加 `someipsd.entry.instanceid` 断言。

---

## M3 [MEDIUM] 负路径用例 `someip_neg_session` 触发机制不明确

**文件**: `cases/someip.json` `someip_neg_session` (第876行)

**问题**: `someip_neg_session` 设置 `"session_start": 0` 来触发 `"invalid session_id"` 错误。但 session_start 是起始会话号，不同的实现可能将 0 解释为合法值或仅在运行时检测非递增。Design §9 V2 的描述是"非法 Session ID（0 或非递增）"，但 `session_start=0` 可能被 Validate 视为非法，也可能在运行时才被检测到。

**证据**: 负路径用例应当触发明确的、确定性的 Validate 拒绝。`session_start=0` 是否被 Validate 拒绝取决于实现，可能被解释为"从 0 开始计数"（0 本身是合法的 SOME/IP Session ID 值）。

**修复建议**: 将触发方式改为更明确的非法值，如 `session_start=0` 且 `session_inc=0`（非递增），或增加一个 `message_type=0x05` 的负路径分开测试。同时更新 design §9 的描述，明确 session_start=0 就是被 Validate 拒绝的。

---

## L1 [LOW] someipsd.entry.ttl 在 tshark 中为十进制（BASE_DEC），但 design 断言未注明进制

**文件**: `28-someip-design.md:§6` / `28-someip-testcase.md:§6`

**问题**: tshark 字段 `someipsd.entry.ttl` 为 `FT_UINT24 BASE_DEC`（十进制输出）。FindService 的 TTL=0xFFFFFF = 16777215（十进制），OfferService 的 TTL=3（十进制）。JSON 断言中已正确使用 `"value": "16777215"` 和 `"value": "3"`（十进制串），但 design 文档和 testcase 文档的字段速查表（§6）未明确注明 `someipsd.entry.ttl` 为十进制，而 `someipsd.entry.serviceid` 为十六进制。这可能导致未来编写断言时进制混淆。

**证据**: tshark 实测 `someipsd.entry.ttl` 输出为十进制（16777215），而 `someipsd.entry.serviceid` 输出为十六进制（0x1234）。

**修复建议**: 在 testcase §6 字段断言速查表中增加 `someipsd.entry.ttl` 的进制标注，明确为十进制。

---

## L2 [LOW] SD 用例缺少 `someip.serviceid` 断言

**文件**: `cases/someip.json` `someip_sd_find_offer` (第416行) / `someip_sd_subscribe` (第514行)

**问题**: SD 报文的消息头中 ServiceID 固定为 0xFFFF（设计 §3.4），但两个 SD 用例都没有断言 `someip.serviceid` = 0xFFFF。SD 报文的鉴别特征之一就是 ServiceID=0xFFFF + MethodID=0x8100 + MessageType=0x02，缺少 ServiceID 断言意味着测试无法验证 SD 报文头的最外层标识。

**证据**: JSON 中 `someip_sd_find_offer` 断言了 `someip.methodid`=0x8100 和 `someip.messagetype`=0x02，但缺少 `someip.serviceid`=0xFFFF。

**修复建议**: 在两个 SD 用例的包1（FindService/Subscribe）中添加 `someip.serviceid`=0xFFFF 断言。

---

## L3 [LOW] TCP 载体用例 `someip_tcp_swap` 包位硬编码风险

**文件**: `cases/someip.json` `someip_tcp_swap` (第789行)

**问题**: TCP 载体用例将 SOME/IP 数据包硬编码为包4和包5（`"packet": 4` 和 `"packet": 5`），依赖 TCP 握手恰好 3 包的假设。但 TCP 握手可能因 MSS 协商、窗口缩放选项、或 SYN 携带数据而扩展。testcase 文档 §4.11 已标注该风险，但 JSON 仍使用硬编码包位。

**证据**: JSON 第 832 行 `{"packet": 4, "field": "someip.messagetype", "value": "0x00"}` 等。

**修复建议**: 将 TCP 用例的 SOME/IP 断言改为 `nonzero` 存在性断言 + tcp.seq 推进关系，而非硬编码包位。或增加 `"has_handshake": true` + `min_packets` 守卫后，用 `"packet": 0`（最后包）或基于 tcp.flags 的包选择器替代硬编码索引。

---

## 汇总

| 等级 | 数量 | 编号 |
|------|------|------|
| CRITICAL | 2 | C1, C2 |
| HIGH | 4 | H1, H2, H3, H4 |
| MEDIUM | 3 | M1, M2, M3 |
| LOW | 3 | L1, L2, L3 |
| **合计** | **12** | |

### 关键要点

1. **S5 hexdump 严重错误（C1+C2+H1）**：OfferService 的 Entry 缺 16 字节（15B），Option Length 字节序错（`09 00` 应为 `00 09`），Length 字段值 0x38 与实际 payload 不符。这三个问题关联了同一个 hexdump 块，应整体重算。
2. **TP 用例 payload 假声明（H2）**：JSON payload 仅 4 字节但声称 2500B，无法触发真实分段——这是测试有效性的根本问题。
3. **SubscribeAck 缺 Option（H3）**：S6 场景缺少 Option（IPv4 Endpoint），这与 S5 的对称性不符。
4. **IPv6 SD Option 未覆盖（H4）**：IPv6 用例只测了 REQUEST/RESPONSE，未测 SD IPv6 Endpoint Option。
5. 其余 finding 均为断言补充、进制标注、包位风险等，可在实现阶段一并修复。
---

## 修复状态（文档阶段，2026-08-20）

| Finding | 状态 | 处理与边界 |
|---------|------|-----------|
| C1 | 已修复 | design §6 S5 与 testcase/JSON FrameAssert 使用 16B Entry；Entry Array Length=0x10，Entry 末字节 Reserved 明确为 00。 |
| C2 | 已修复 | IPv4 Endpoint Option 使用大端 Length `00 09`；12B 完整 Option 为 `01 00 09 00 14 00 00 c8 00 11 77 1a`。 |
| H1 | 已修复 | S5 包1 Length=0x20（32），包2 Length=0x2c（44）；两包 SD Entries Length=0x10（16），并逐字节写出计算式。 |
| H2 | 已修复（文档/用例） | `someip_tp_segments` 的 JSON payload 改为 2500 个显式、可复现的 0..255 循环字节，`tp.payload_length=2500` 与数组长度一致；设计与 testcase 不再以 4B 骨架冒充 2500B。Go 层未实现，未宣称运行期通过。 |
| H3 | 已澄清边界 | 按当前设计选择规范允许的最小 SubscribeEventgroupAck：Ack 不引用 Option。design/testcase/JSON 均明确这是无 Option 原子行为；带 Endpoint Option 的 Ack 未覆盖，不能从本 case 推导已覆盖。 |
| H4 | 已修复（文档/用例） | 新增独立 `someip_sd_ipv6` 原子 case，验证 IPv6 载体上的 OfferService 与 Option type=0x06、地址、端口；不与 IPv6 方法调用混合。Go 层/运行期注册仍是待实现边界。 |
| M1 | 已修复 | S5 Find/Offer 两个 Entry 均补 `minorver=0` 断言，并在字段表注明 tshark 十进制。 |
| M2 | 已修复 | Subscribe 包补 `instanceid=0x0001`。 |
| M3 | 已修复（断言输入） | `someip_neg_session` 改为 `session_start=0` 且 `session_inc=0`，并在文档说明非递增触发；实际 Validate 行为待 Go 实现。 |
| L1 | 已修复 | testcase 字段速查表明确 `someipsd.entry.ttl` 为十进制，`0xFFFFFF` 写作 `16777215`；design 同步。 |
| L2 | 已修复 | `someip_sd_find_offer`、`someip_sd_subscribe` 的 SD 报文均补 `someip.serviceid=0xffff`。 |
| L3 | 已修复（框架边界） | TCP case 删除硬编码 packet 4/5 的 SOME/IP 断言，保留握手、SYN、端口、`min_packets` 等可靠 observable assertions；文档明确框架不能按 SOME/IP 字段选择包，未伪造“packet 1 是数据包”。 |

### 未决待实现边界

1. SOME/IP 尚未在 Go layer registry/运行期 planner 中注册；因此本阶段只验收三件套内部规范、字节计算、原子用例与断言可观察性，不把未注册视为文档缺陷。
2. `someip_sd_ipv6` 的 IPv6 Option wire/解析是否在未来实现中与当前 schema 完整接线，需实现阶段以 tshark 与 builder 端到端核验；本阶段不伪造通过结果。
3. S6 仅覆盖无 Option 的最小 Ack；带 Endpoint Option 的 SubscribeEventgroupAck 是未覆盖的独立变体，未来需单独 case 并重算长度/索引。
4. TCP SOME/IP 数据段按内容筛选的断言器当前缺失；本阶段只保留稳定的 TCP 握手/端口/包数观测，不把 packet 序号当作协议语义。

> 本表是修复状态而非“所有问题已 clean”声明；以上待实现边界仍保持未决。
