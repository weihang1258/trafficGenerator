# Dameng（达梦数据库 DM8）设计契约

> 版本：v1.0.2（P6 对账修订；#81 dameng）
> 日期：2026-10-01
> 车道：并发管线车道 A（文档轨）｜协议号：**81**（ledger 队列位；文件按既有命名序 `81-dameng-*.md`）
> 配套文件：`docs/protocols/dameng/testcase.md`、`trafficgen/test/protocol_pcap/cases/dameng.json`（现存 34 例：13 正 + 21 负）
> 旧基线：`docs/protocol-designs/33-dameng-design.md` + `33-dameng-testcase.md`（v1.0.0，2026-08-20）——逐节比对见 §12 门1 表 §10 行与本契约 §15
> **层链唯一真相**：本契约全文示例只有纯 `layers` 形——地址只住 `ip` 层（`src`/`dst`）、端口只住 `tcp` 层（`src_port`/`dst_port`）、数量只走 `flow_control`；顶层只允许 `layers`/`flow_control` 家族/`output`（CORE_MEMORY §1.11–1.13）。任何顶层 `src_ip`/`dst_ip`/`src_port`/`dst_port`/`count`/`dameng` 子映射都判违规。
> **注册现状**：`dameng` 层**已注册**（`layers/registry.go:821-841`，`CategoryTerminal` + `DependsOn ["tcp"]` + `TransportOn ["tcp"]` + `FieldContract {"tcp.dst_port":"5236"}`），且 `allowedProtocols["dameng"]=true`（`core/protocols.go:23`）、`NewChainPlanner("dameng")` 已在 `cmd/server/main.go:516` 注册（P1 写作时 515）、空白导入在 `main.go:72`。本文**不宣称本次跑过 suite、不启动服务器**；所有"已落码/未落码"结论均标实测出处。
> **与 kingbase #35 的关系**：dameng 是**独立终结层 / 独立协议**，不是任何层的 dialect 变体。判定依据见 §10.6（裁定 DM-A，与 PG-A 五条实测同构、结论相反）。

---

## 1. 范围、证据等级与已落码边界

本设计定义 Dameng DM8 客户端经 TCP 5236 连接数据库服务的**会话事件**生成契约：CONNECT → 认证序列 → SQL 请求/响应 → 会话结束。

**证据等级三档（本契约纪律）**：

| 档 | 可写内容 | 是否固定线字节 |
|---|---|---|
| ①公开资料级 | TCP 载体、默认目的端口 5236、SYSDBA 默认用户、四元组会话、IPv4/IPv6 | 否——只断言传输层字段 |
| ②dissector 实测级 | 本机 TShark 对 Dameng 私有协议**无 dissector**（`tshark -G fields` 零 `dameng.*` 命中；`dm8.*` 命中 11 个全是航空 ATN-CPDLC 字段，与达梦无关） | 否——断言通道只有 `tcp.*`/`ip.*` + frames 占位长度 |
| ③实现现状级 | 本仓库 `internal/protocol/dameng/*` 的已落码能力边界（哪些事件 kind 有 builder、哪些配置键被消费） | 是——作为"今日可达/不可达"的判据 |

**已落码边界（实测，2026-09-26 HEAD）**：

- 校验器：`internal/protocol/dameng/planner.go`（253 行）——`Validate`（`planner.go:43-90`）+ 状态机 `validateEventSequence`（`:97-154`）+ `Plan`（`:167-224`，自产握手/挥手）+ `runSession`（`:228-251`）。
- 字节构造：`internal/protocol/dameng/builder.go`（57 行）——`buildPacket` 只取 `ev.Profile` 当字节（`:17-19`）；`profilePayload` 空 profile 回退 `"dm8"`（`:26-31`）；`knownProfiles` 仅 2 值（`:11-14`）；`checkWireFault` 2 有效 kind（`:42-58`）。
- 生成器：`internal/protocol/dameng/layer_gen.go`（79 行）——事件/`sessions[]` 逐事件 `EmitMsg`（`:20-66`），经 `Meta.Dameng` 直传（`chain_planner_translate.go:190`、`layers/generator.go:369`）；`init` 注册生成器+校验器（`:77-79`）。
- 单测：`dameng_test.go` 40 个 Test + `dameng_direction_test.go` 1 个（`grep -c '^func Test'` 实测），覆盖 builder/wire_fault/validator/Plan/生成器/方向守卫。

当前 `cases/dameng.json` 共 **34 例**（13 正 + 21 负，`proto` 全=`dameng`），构成当前审计基线（testcase §8）。

---

## 2. 推荐配置、层链与事件形状

### 2.1 层链

唯一合法链形：**`[ip, tcp, dameng]`**（IPv6 地址族同住 `ip` 层，不新增层）。`dameng` 是**终结层**（`CategoryTerminal`，`DependsOn ["tcp"]` + `TransportOn ["tcp"]`，`registry.go:821-841`）——registry 实测见该段。

```json
{
  "layers": [
    {"ip": {"src": "10.0.0.1", "dst": "20.0.0.1"}},
    {"tcp": {"src_port": 12345}},
    {"dameng": {
      "wire_profile": "dm8_profile_pending",
      "events": [
        {"kind": "connect", "direction": "c2s", "profile": "connect_default"},
        {"kind": "auth_request", "direction": "c2s", "profile": "auth_default"},
        {"kind": "auth_response", "direction": "s2c", "profile": "auth_default", "result": "success"},
        {"kind": "sql_request", "direction": "c2s", "profile": "sql_select_default", "sql": "SELECT 1"},
        {"kind": "sql_response", "direction": "s2c", "profile": "sql_select_default", "result": "success"}
      ]
    }}
  ],
  "flow_control": {"flows": 1}
}
```

> **`tcp.dst_port` 不写**：由 `dameng` 层 `FieldContract {"tcp.dst_port": "5236"}`（`registry.go:826`）经通用 FieldContract 块（`chain_planner.go:706-737`）补齐。用户显式写端口时走通用回填 + planner 域校验（`planner.go:56-58`），不等 5236 即拒。

### 2.2 层内配置键（当前已接线）

`DamengConfig` 是 Go struct（`core/types.go:1294-1300`，严格解码 `UnmarshalJSON` `:1305-1314`）：`WireProfile` / `Events` / `Sessions` / `PayloadSize` / `WireFault`；`DamengEvent`（`:1278-1285`）：`Kind`/`Direction`/`Profile`/`Username`/`Result`/`SQL`；`DamengSession`（`:1288-1291`）：`SrcPort`/`Events`。

**当前实现（已接线）**：registry 已登记五键（`registry.go:827-841`），`translateTerminalConfig` 已有 `dameng` 往返分支（`chain_planner_translate.go:2921-2950`，含 `DisallowUnknownFields` 严格解码）；层链配置由上述两处接收；34 例中 33 例为纯层链形，另 1 例是故意的层链+顶层 presence 负例。`G-DM-2` 已关闭；不再把旧的顶层映射描述为现状。

### 2.3 事件形状与已知无效字段清单（已确认）

`buildEventPayload` 等价物（`builder.go:17-19`）与 `validateEventSequence`（`planner.go:97-154`）**实际消费**：

| 事件键 | 被消费？ | 消费点 / 备注 |
|---|---|---|
| `kind` | ✅ | `planner.go:100-102` kind 白名单（6 值）；`builder.go:17-19` 经 Profile 取字节 |
| `direction` | ✅ | `planner.go:108-112` 按 kind 自然方向（`kindUp` `:33-41`）校验显式值；不一致返回 `inconsistent`，缺省按 kind 自然方向 |
| `profile` | ✅（弱） | `builder.go:18` **直接当 payload 字节**——profile 名即线上字节（占位语义，非 DM8 真实字节） |
| `result` | ✅ | `planner.go:129-136`（auth_response 置 authOK，非法值 `auth`）/`:148-150`（sql_response 合法值） |
| `sql` | ✅ | `planner.go:141-143` 非空校验 |
| `username` | ❌ **死字段** | 全仓库生成器/校验器零读取（除测试外 `Username` 零命中）→ G-DM-3 |
| `wire_profile` | ✅ | `planner.go:50-55` 登记表（仅 2 值） |
| `payload_size` | ✅ | `planner.go:65-67` 仅接受 `profile_minimum_nonempty` |
| `wire_fault` | ✅ | `builder.go:42-58` 2 有效 kind + 未知 kind 拒 |

`username` remains an unconsumed input (zero reads outside tests). It is not used as a wire assertion. A future credential-aware fixture must either consume it or remove it; this remains a documented implementation gap (G-DM-3).

### 2.4 wire_profile 登记值与能力边界（实测）

| wire_profile | 语义 | 今日状态 |
|---|---|---|
| `dm8_profile_pending` | DM8 待版本化主模板 | ✅ 可生成（当前 JSON 31 例在用，机读） |
| `length_boundary` | 最小合法非空编码边界 | ✅ 可生成（存量 1 例在用，需配 `payload_size`） |
| 其他名称 | 未登记版本或模式 | ❌ planner 拒绝，错误包含 `profile`（`planner.go:53-55`） |

**关键现状**：`wire_profile` 登记值当前在 34 例中使用；`dm8_profile_pending` 为主模板，`length_boundary` 为边界模板。

---

## 3. 线格式权威（诚实版：传输层事实 + 占位字节声明）

DM8 私有应用消息头、长度字段、认证摘要、SQL 编码**无公开线格式**（旧基线 33-design §1 结论，本契约 P1 复核维持）。本节只固定三类可断言事实：

### 3.1 TCP/IP 外层（唯一可断言通道）

无 VLAN、无 IP option、无 TCP option 时，IPv4 TCP payload 起点为 Ethernet 14 + IPv4 20 + TCP 20 = **frame offset 54**；IPv6 起点为 14 + 40 + 20 = **74**。这两个数字只描述 TCP 载荷起点，不表示 Dameng 应用头起点（旧基线 §2.2 结论延续）。

### 3.2 占位 payload 语义（P4 builder 硬对照表）

| 事件 kind | 自然方向 | 线上字节（今日） | 出处 |
|---|---|---|---|
| `connect` | c2s | `[]byte(ev.Profile)`，缺省 `"dm8"` | `builder.go:17-31` |
| `auth_request` | c2s | 同上 | 同上 |
| `auth_response` | s2c | 同上 | 同上 |
| `sql_request` | c2s | 同上（`sql` 文本**不进字节**，只做非空校验） | `planner.go:133-135` |
| `sql_response` | s2c | 同上 | 同上 |
| `close` | c2s（`kindUp`） | 同上 | `planner.go:33-41` |

> **铁律**：占位字节**不是** DM8 wire。用例不得断言其值为"DM8 正确性证据"，只断言非空（`tcp.len` nonzero）与方向。取得版本化 fixture 后按 G-DM-1 替换。

### 3.3 包数公式（实测：Plan 单测逐例通过）

小 payload、每个事件一个 TCP 数据段时：

```text
packet_count = 3（SYN/SYN-ACK/ACK）+ N（事件数）+ 4（FIN-ACK 四way）= N + 7
```

`runSession` 实测（`planner.go:228-251`）：握手 3 包（`:229` SYN/SYN-ACK/ACK）+ 逐事件 1 包（`:232-243`）+ 挥手 4 包（`:246-249` FIN/ACK c2s → ACK s2c → FIN/ACK s2c → ACK c2s）。多会话 = 各会话独立经此公式后求和（`dameng_multi_session` 2×3 事件 → 2×10 = **20** ✓，`dameng_test.go:681` `TestPlanDamengMultiSession` 实测）。

---

## 4. 会话状态机与自动派生（设计权威）

### 4.1 状态集合

```text
Init ──connect──▶ Connected ──auth_request/auth_response──▶ Authed
                                                              │
                              ┌──── sql_request/sql_response ──┤
                              │                                │
                           Authed ◀────────(success/error)──────┘
                              │
                    close ─▶ Closed ──FIN──▶ End
```

- `Init → Connected`：首事件必须是 `connect`（`planner.go:103-105`）。
- `auth_response` 之前必须有 `auth_request`（`planner.go:116-118`）；`auth_response(result=error)` 后 `authOK=false`（`:132-136`）。
- SQL（请求与响应）只允许在 `authOK=true` 后（`planner.go:138-150`）；`sql_request` 要求非空 `sql`（`:141-143`）。
- `close` 只允许为末事件（`planner.go:113-115`，`auth_response` 无前置守卫 `:116-118`）；`connect` 只允许为首事件（`:103-105` + `:120-123`）。
- `events` 与 `sessions` 互斥（`planner.go:62-64`）；每 session 非空事件（`:71-79`，独立校验 `:76-78`）。

### 4.2 非法转移（拒绝 + 锚词，全部实测字面值）

| 非法转移 | 锚词 | 触发点 |
|---|---|---|
| 未登记 `wire_profile` / 缺 `wire_profile` | `profile` / `wire_profile is required` | `planner.go:50-55` |
| 非默认 `DstPort` | `5236` | `planner.go:56-58` |
| 未登记 kind | `unknown kind` | `planner.go:100-102` |
| 首事件非 connect / connect 非首位 | `state` | `planner.go:103-105` / `:120-127` |
| close 非末位 | `state` | `planner.go:113-115` |
| auth_response 无前置 auth_request | `state` | `planner.go:116-118` |
| 未认证即 SQL | `auth` | `planner.go:138-147` |
| `auth_response`/`sql_response` 非法 result | `auth` / `sql` | `planner.go:129-131` / `:148-150` |
| 空 SQL | `sql` | `planner.go:141-143` |
| `wire_fault` truncate / over_limit / 未知 kind / 非对象形 | `truncated` / `limit` / `unknown kind` / `invalid wire_fault` | `builder.go:48-57` |

### 4.3 自动派生帧（生成器自动补的内容，逐条列出）

| 派生内容 | 触发条件 | 内容 |
|---|---|---|
| TCP 握手 3 包 | 每 session 起始（`runSession`） | SYN / SYN-ACK / ACK（flags `0x02`/`0x12`/`0x10`） |
| TCP 挥手 4 包 | 每 session 收尾 | FIN/ACK、ACK、FIN/ACK、ACK（`planner.go:246-249`） |
| 多会话端口 | `sessions[].src_port` 非零 | 该 session 全包用此源端口（`layer_gen.go:53-59` 经 `SrcPort` 上报，tcp 层切连接） |
| 缺省 profile 字节 | 事件缺 `profile` | `"dm8"`（`builder.go:27-29`） |
| P0b 空配置默认流 | `spec.Dameng == nil` | 单 `connect` 事件（`layer_gen.go:27` + `planner.go:45-49/161-164`） |

> **「自动应答」不存在**：本层是**声明式脚本化回放**，不因收到 `auth_request` 自动补 `auth_response`。每个方向的报文都必须在 `events[]` 里显式声明。

---

## 5. 依赖声明与端口契约

**依赖（§5.1）**：依赖 `tcp` 层（唯一载体，`DependsOn ["tcp"]` registry.go:821）；**无 `udp` 语义**——链夹 udp 时通用 tcp-only 逻辑拒（`complete.go:448-466`，报错含 `tcp`，存量 `dameng_neg_udp` 锚词即此）；无外部密钥/证书依赖（认证字节为占位名，不做真实密码学）。

**端口契约**：`FieldContract {"tcp.dst_port": "5236"}`（`registry.go:826`）→ 通用 FieldContract 块补齐（`chain_planner.go:598-629`）→ planner 域校验强制 5236（`planner.go:56-58`）。用户显式写非契约端口 → 拒（锚词含 `5236`）。

---

## 6. 性能设计与验收（CORE_MEMORY §6.1–6.8）

- **6.1/6.2 目标与预算**：本层为**事件驱动流式渲染**——逐事件构造占位字节并立即 `EmitMsg`，无全量聚合、无按包增长的结构（`layer_gen.go:20-66` + `planner.go:159-218` channel 流式）；零可变状态（无计数器）。帧长上界：单事件 ≤ `len(profile)` 字节（配置输入，天然有界）。并发面：每个 flow 一个新 generator 实例（`layer_gen.go:77` 工厂），**无共享可变状态、无需锁**。速率与队列上限由框架（Pacer / 有界队列）承担，本层不重复定义。
- **6.3 双路验收**：**pcap 路** = suite 落盘 `/tmp/mcp-pcaps/dameng/`，用 tshark `tcp.*`/`ip.*` 字段校对；**NIC 路** = `output_type=port_group` + 网口 `enp135s0f0np0` 抓包，断言 TCP/应用字段一致（记忆 `testing-interface` 指定网口）。
- **6.4 依据**：流式路径如 6.1 所述；每条流新增内存 = 一个 generator 实例 + 当前事件字节切片；无共享状态、无锁；限速与多 worker 总速率正确性由框架 pacer（共享桶）保证，本层不引入第二套速率语义。
- **6.5 诚实待确认**：**吞吐（包/秒、bit/秒）、并发流数、内存上限的具体数字待 P4 基准实测后钉**，本文不写承诺数字（§6.5「没有代码路径或基准数据支撑的性能数字只能标为待确认」）。
- **6.6 六类场景**：基线（单会话单连接）/ 目标规模（多会话 `sessions[]`）/ 压力上限（长 SQL 逼近 MSS 分段，A′）/ 长时间运行（长会话多轮 SQL，A′）/ 并发交错（多流 `flows=N` × 多会话）/ 背压（下游消费慢时队列积压行为，沿用框架既有测试面）。
- **6.7 断言口径**：断言**实际输出值**（`tcp.dstport`/`tcp.srcport`/`tcp.len`/`ip.version` + 包数公式），**不许只断言"任务没失败"**；负例断言锚词。
- **6.8 失败边界**：功能正确但超预算视为设计不合格——本层的预算面即"单 flow 常驻内存 O(1)"，若 P4 引入按流缓存报文数组即违反本条。

---

## 7. 错误处理与错误传播

- 所有校验错误必须在 **planner/validator 边界**抛出并传播为 **task error**，**不许**产出成功 PCAP、`completed + 0 packet`、或只剩 TCP 外壳的假成功（CORE_MEMORY §14.11/§14.12）。
- 负例执行期 `expect` 键集合**严格**为 `{"expect_error", "error_contains"}`。
- **`wire_fault` 的当前实现边界（实测）**：`checkWireFault`（`builder.go:42-58`）只接受**对象**形 `{"kind": ..., "value": ...}`，两个 kind（`truncate_message`→锚词 `truncated`；`message_limit`→锚词 `limit`）；其它 kind → `unknown kind`；字符串/数字/数组形 → `invalid wire_fault`。空（nil raw）= **无故障**。故障在 validator 期即被拒绝，走"配置被拒"通道而非"产出截断包"通道（§14.11 要求坏配置必须被拒）。

---

## 8. 存量审计口径

`cases/dameng.json` **34 例**（逐例机读：13 正、21 负），逐例契约见 testcase §2–§4。

| 1 | 14/14 旧扁平例已迁移 | 当前 `cases/dameng.json` 33 例业务配置为纯层链；唯一顶层 `dameng` 出现处是 #34 故意 presence 负例（`CheckProtoFlat` 判死）；非负例顶层键仅 `layers`（多流例另含 `strategy_fc`） | 当前 JSON 机读；`strategy_convert.go:8807-8810` |
| 2 | 8/8 旧正例包数 | 迁移后的既有正例包数仍与契约一致；新增例按 JSON 断言登记 | testcase §2–§3 |
| 3 | 6/6 旧负例纯净 | 当前 21/21 负例仅含 `expect_error` + `error_contains` | JSON 机读 |

---

## 9. 用例集合摘要（ID 权威在 testcase §2）

**当前机读分布**：34 例 = 13 正 + 21 负。旧 14 例已完成迁移；新增 `dameng_neg_direction_mismatch` 与 presence 负例已落盘并有错误锚词。

- 正例 13：连接/认证/SQL 基线 8（存量改写）/ `close` 正常结束 1 / 认证错误分支 1 / 多流动态 1 / MSS 分段 1 / NIC 双路 1。
- 负例 21：存量 6（改写）+ kind 面 1 + SQL 空值 1 + 状态机 5 + 事件/会话互斥 2 + `wire_fault` 非法形 2 + `payload_size` 1 + 层内未知字段 1 + 方向一致守卫 1 + 顶层 presence 1。

逐 ID、逐 `packet_count`、逐断言见 testcase §2–§4。

---

## 10. P1 规范矩阵（CORE_MEMORY §4 八项：规范要求→业务场景→代码现状→缺口）

> 深度口径（§4.19–4.22）：矩阵三张子表——①事件×会话状态矩阵（§10.2）②数据形态变体表（§10.3）③商业行为→用例映射表（§10.5）。条目三选一：已实现 / 明确不支持 / 不适用 + 对应用例号，**不留白**。
> **公开资料边界（本设计铁律）**：DM8 私有 wire（应用消息头、长度字段宽度/字节序、认证摘要算法、SQL 编码、响应状态码）**无公开规范**——只校验存在性/方向/顺序；**不编造字节、不验证凭证语义**。SYSDBA 默认用户与 5236 默认端口有公开资料支撑（多源一致，见 §10.5）。

### 10.1 八项规范矩阵

| # | 规范要求（条款+本契约节） | 业务场景 | 代码现状（实测） | 缺口 |
|---|---|---|---|---|
| 1 | 连接模型：单 TCP 长连接承载全部会话事件；无控制/数据分离；客户端主动建连（公开资料：DM8 客户端经 TCP 连服务端 5236；本契约 §4） | 应用直连 DM8（默认 Oracle 兼容模式）建连+认证+查询 | ✅ `dameng` 已注册（`registry.go:821-841`）；✅ 生成器事件驱动（`layer_gen.go`）；✅ 多会话经 `sessions[].src_port` 复用同一 TCP 层多连接（`layer_gen.go:48-59`） | 无（A′ 已覆盖连通性） |
| 2 | 事件表：connect / auth_request / auth_response / sql_request / sql_response / close（6 kind；旧基线语义契约；本契约 §3.2） | 全事件族覆盖 | ✅ 6 kind 全有校验分支（`planner.go:96-146`）；⚠️ 字节全为占位名（`builder.go:17-19`） | 私有字节 → B′ G-DM-1；`close` 零用例 → 新增正例 |
| 3 | 状态机：connect 首位 → 认证 → SQL → close 末位；非法转移拒（本契约 §4.1） | 客户端乱序发包、未认证即查询 | ✅ 首/末/认证/顺序守卫及显式 direction 一致性守卫全（`planner.go:102-139`）；#33 覆盖方向不一致拒绝 | 无；G-DM-5 已实现并由 #33 覆盖 |
| 4 | 字段表：事件字段全为配置语义字段（无公开字节序/长度语义；本契约 §2.3） | 跨部署互操作 | ✅ Kind/Direction/Profile/Result/SQL 全消费；⚠️ `Username` **死字段**（零读取）；`sql` 文本不进字节 | `Username` → G-DM-3（删或接线） |
| 5 | 错误处理：认证失败（`result=error`）后禁 SQL；截断/超限走 `wire_fault` 拒（本契约 §7） | 登录失败、超大报文 | ✅ `authOK=false` 分支（`planner.go:132-136`）；✅ `wire_fault` 2 kind（`builder.go:50-58`）；✅ 认证失败后继续 SQL 负例（`dameng_neg_sql_after_auth_error`，锚 `before successful authentication`） | 无 |
| 6 | 超时与活性：**DM8 协议层无公开 keepalive/超时语义**——由 TCP 承担 | 长连接空闲复用 | ✅ 协议层无自有定时器（生成器不含 sleep）；✅ TCP 保活由 `tcp` 层承担 | **不适用**（显式声明：无此语义，不硬凑用例；长保活用例由"同连接多轮 SQL"承载） |
| 7 | NAT/代理：DM8 无应用层 NAT 遍历（无 PORT/PASV 类衍生连接）；无第二类关联连接 | 直连 / 代理转发 | ✅ 无派生流形态（生成器只有单连接事件流） | **不适用**（显式声明：无关联流形态；`driven_by` 不适用，见 §10.4） |
| 8 | 版本/方言：DM8 不同补丁/兼容模式/认证方式可能选择不同私有布局（旧基线 §1 结论延续） | DM8 多版本并存 | ⚠️ `wire_profile` 仅 2 登记值且**不参与字节构造**；`length_boundary` 需配 `payload_size` | 缺口 → B′ G-DM-1（版本化 fixture） |

### 10.2 子表①：事件×会话状态矩阵（逐格已覆/缺失/不适用）

> 行 = 事件族（4 行）；列 = 5 个会话状态面。 verdict：✅用例 / Ⓡ共享规则已覆（无专属用例）/ N-A / 缺口→ID。

| 事件族 \ 状态 | Pre-connect | Authenticating | Authenticated | After-auth-error | Closed（close 后） |
|---|---|---|---|---|---|
| connect | ✅ 正例 | Ⓡ（`connect_not_first` 规则） | Ⓡ（同左） | Ⓡ（同左） | Ⓡ（同左） |
| auth | Ⓡ（首事件必 connect 规则） | ✅ 正例（成功+错误） | 现状允许（重认证不拦，无专属用例，注记） | ✅（`auth_error_then_close`） | Ⓡ（close-last 规则） |
| sql | Ⓡ（首事件必 connect 规则） | 缺口→`dameng_neg_sql_before_auth` | ✅ 正例（成功+错误） | 缺口→`dameng_neg_sql_after_auth_error` | Ⓡ（close-last 规则） |
| close | Ⓡ（首事件必 connect 规则） | 缺口→`dameng_neg_close_not_last` | ✅（`dameng_close_clean`） | ✅（`auth_error_then_close` 收尾） | N-A（close 后无事件可配） |

**逐格机械重数（可复核）**：表体 **4 行 × 5 列 = 20 格** = **✅6 + Ⓡ9 + N-A1 + 现状允许注记1 + 缺口3**（6+9+1+1+3 = 20 ✓ 无空格）。缺口 3 格 → 新负例 3 条（`neg_sql_before_auth` / `neg_sql_after_auth_error` / `neg_close_not_last`）。`neg_auth_response_without_request`（#25）与 `neg_connect_not_first`（#26）为已覆格内深度负例（同格不同上下文，§9.21），不占缺口格。

### 10.3 子表②：数据形态变体表（协议相关全部形态逐项）

| # | 变体维度 | 形态 | 对应用例 | 备注（实测锚） |
|---|---|---|---|---|
| 1 | 地址族 | IPv4 / IPv6（同住 `ip` 层） | 存量改写（ipv4/ipv6） | IPv6 起点 74；`net.ParseIP` 校验（`planner.go:83-88`） |
| 2 | 目的端口 | 默认 5236 / 非默认显式 | 存量 + `neg_port` | 非默认即拒（`planner.go:56-58`）；链路径走 FieldContract |
| 3 | 认证结果 | success / error | `dameng_auth_success` / `dameng_auth_error_then_close` | error 后 authOK=false（`planner.go:132-136`） |
| 4 | SQL 结果 | success / error | `dameng_sql_success` / `dameng_sql_error` | 错误响应独立 profile（旧基线 S4 延续） |
| 5 | SQL 文本 | 非空正常 / 空（拒）/ 长 SQL（分段 A′） | `dameng_sql_success` / `dameng_neg_empty_sql` / `dameng_long_sql_mss` | 空拒（`planner.go:141-143`）；文本不进字节 |
| 6 | 认证用户 | 缺省 / 显式 SYSDBA | `auth_success` | `username` 死字段（G-DM-3），不断言语义 |
| 7 | 事件方向 | c2s / s2c 显式；缺省按 kind | 全正例显式；不一致拒绝 | `dameng_neg_direction_mismatch`（`inconsistent`） |
| 8 | profile 名 | 已登记模板名 / 空（回退 `dm8`） | 全正例 / 注记 | 空回退（`builder.go:27-29`）；profile 名即字节 |
| 9 | wire_profile | 2 登记值 / 未登记（拒） | 正例 / `neg_profile` | 不参与字节（§2.4） |
| 10 | payload_size | 缺省 / `profile_minimum_nonempty` / 非法值（拒） | `length_boundary` / `neg_payload_size` | 仅 1 合法值（`:65-67`） |
| 11 | 会话数 | 单会话 events / 多会话 sessions | 基线 / `multi_session` | 互斥（`:62-64`）；空 session 拒 |
| 12 | 分段 | 单事件单段 / 长事件跨 MSS（A′） | 基线 / `long_sql_mss` | TCP 层分段（`mss` 默认 1460） |
| 13 | 多流 | `flows=N` 多流并发 | `multi_flow_dynamic` | `worker.go:307-308` 保底；动态见 §12 |
| 14 | 动态字段 | ip/tcp 四元组 × 五策略 | `multi_flow_dynamic` | §12 清单；dameng 层无 allowlist |
| 15 | 输出路 | pcap / NIC（port_group） | 基线 / `pcap_nic_consistency`（A′） | 双路验收 §6.3 |
| 16 | wire_fault | 2 有效 kind / 未知 kind / 非对象形 / 空（no-op） | 2 存量负例 / 2 新负例 / 注记 | `builder.go:42-58` |
| 17 | 死字段 | 事件内 `username` | 当前 JSON 无实例；实现缺口 G-DM-3 | §2.3 |
| 18 | 未知 kind/非法 result/空事件表 | 各拒 | `neg_unknown_kind` + result 面 + `neg_state` 系 | `planner.go:99-101/121-123/140-142/59-61` |

### 10.4 关联关系专节（§3.8–3.10）：无派生流的边界

Dameng **没有**控制流派生数据流的形态：认证与 SQL 复用**同一条 TCP 连接**，响应与请求靠事件顺序关联（无 transactionId/CorrelationID 字段）。

| 关联三件事（§3.9） | Dameng 的取值 |
|---|---|
| 归属哪个会话 | 同一 session（`sessions[]` 元素内顺序）；跨 session 状态不串用（validator 按 session 独立校验 `:71-79`） |
| 归属哪个事务 | 无事务标识——靠"请求后紧跟响应"的**顺序**关联（设计声明，非 wire 字段） |
| 由哪个字段决定 | `kind` 的请求/响应配对（auth_request→auth_response，sql_request→sql_response）+ `authOK` 门 |

**结论**：`driven_by` 今日**不适用**（无派生流），且**不许**用"同一模板连续重复发射"冒充编排（§3.13）。多轮 SQL 在同一连接内顺序展开（A′ `multi_query_rounds`）。

### 10.5 候选方案对比（§4.17）与三路对照（§4.12–4.15）

**三路对照**：

① **规范/官方资料**：DM8 无公开 RFC；公开资料只支撑"TCP 载体 + 默认端口 5236 + SYSDBA 默认用户 + Oracle 兼容模式"（多源一致：dameng 官方社区安装文档默认端口 5236；CSDN/博客园/掘金多源同值；`PORT_NUM` 缺省 5236）。私有 wire **无出处** → 本契约不固定（旧基线结论延续，§5.5）。
② **现网行为**：Dameng 官方管理工具/驱动按上述默认建连；**抓包级确认未做** → G-DM-4（确认方式：本机 DM8 + 官方驱动抓包核对端口与建连序）。
③ **开源实现思路**：本仓库 `internal/protocol/dameng`（已落码 40 单测）+ postgresql #82 的事件面扩展范本（方案 A 同构）。

**候选方案对比（§4.17）**：

| 方案 | 走法 | 优 | 劣 | 结论 |
|---|---|---|---|---|
| **A 事件面补齐 + flat→层链迁移** | 保留现有事件校验器/生成器，registry 补 `Fields` + translate 补分支 + 存量 14 例改写纯层链 | 与已收官族同构；40 单测保留；零新框架机制 | 需 1 次批量迁移 | **采用** |
| B 另起 DM8 wire 解析 | 按猜测固定私有头字节 | 无 | 无规范支撑 = 编造（§5.4 禁止） | 不选 |
| C 生 hex 回放 | 事件内 `body_hex` 逃生口 | 最简单 | 字段不可结构化断言、动态面全失 | 仅作特殊形逃生口（不采用） |
| D 只覆盖 connect 冒烟 | 收缩到连接面 | 工作量最小 | 状态机/错误面全失；违反 §9.20 | 不选 |

### 10.6 裁定 DM-A：独立终结层（**dameng = 独立协议，不是 dialect 变体**）

**判定依据（逐条实测，不问偏好——依赖链判定：标准→设计→代码→测试）**：

1. **注册面**：`dameng` 在 registry 唯一注册（`registry.go:821-841`）；`allowedProtocols["dameng"]=true`（`protocols.go:23`）；且**不在** `negativeOnly` 名单（`protocols_test.go:94-108` 点名 kingbase 必须 stay rejected，dameng 在受准名单 `:20`）。与 kingbase"registry 零命中 + negativeOnly"**镜像相反**。
2. **用例面**：`cases/dameng.json` 34 例 `proto` **全部 = `dameng`**（实测逐例）；跑法 = `CASE_PROTO=dameng`。与 kingbase"15 例全 `proto=postgresql`，`CASE_PROTO=kingbase` 装载 0 例"**镜像相反**。
3. **端口面**：dameng 端口由**自有** `FieldContract {"tcp.dst_port":"5236"}`（`registry.go:826`）声明，不是改父层契约值的常量覆盖（kingbase 式 `dialectFieldContract`）。
4. **代码面**：`internal/protocol/dameng` **包存在**（planner/builder/layer_gen 三文件 + 40 单测）；`types.go` 有 `DamengConfig/DamengEvent/DamengSession`（`:1277-1314`）+ `FlowSpec.Dameng`（：`types.go:1723`）；`layers/generator.go:369` 有 `FlowMeta.Dameng`；`main.go:72` 空白导入 + `main.go:518` 注册 ChainPlanner。与 kingbase"包不存在、零残留"**镜像相反**。
5. **测试面**：P0b 空配置默认流测试含 `{"dameng", 5236}`（`chain_planner_p0b2_emptyconfig_test.go:25`），即测试面认 dameng 为一等层。

**裁定**：**dameng 是独立协议（#81），与 kingbase 退役案无类比适用**。任何 `dialect` 化 dameng 的方案（如并入 postgresql 层）都不合法——DM8 私有语义与 PG v3 外层无共享字节。反向声明：`{"dameng":{}}` 层保持合法注册层；`protocol:"kingbase"` 式陷阱在本协议不存在。

**残留洞（已收口）**：`CheckProtoFlat` 已接入 `dameng` 分支（`strategy_convert.go:581-585`），层链+顶层空 `dameng` 映射会被通用门拒绝；G-DM-6 closed。

---

## 11. P2 D-DAMENG-1 代码设计（CORE_MEMORY §8 八要素；门1 获批 = 定稿）

> 体裁：文件清单 / 接口签名 / 数据结构 / 主流程 / 错误分支 / 性能边界 / 冲突点 / 回滚。**依赖建模沿 §10.6 裁定 DM-A（独立层）**；私有 wire 面一律占位（§10 铁律）。

### 11.1 文件清单（当前实现与剩余立项）

| 文件 | 动作 | 职责 |
|---|---|---|
| `internal/core/layers/registry.go`（`:821-841`） | **已扩展（G-DM-2 closed）** | dameng 层已补 `Fields` 五键（`wire_profile`/`events`/`sessions`/`payload_size`/`wire_fault`，`registry.go:827-841`）；`FieldContract` 保持 5236（`:826`） |
| `internal/core/layers/chain_planner_translate.go` | **已完成** | 补 `case "dameng"`（`:2921-2950`，postgresql `:2243-2280` JSON 往返同款）；**flat 优先**语义同款（`spec.Dameng != nil` 时层 config 忽略，防双头） |
| `internal/protocol/dameng/planner.go` | **已实现** | ①方向一致守卫（G-DM-5）；②P0b 默认化保留 |
| `internal/protocol/dameng/builder.go` | **不变**（占位字节已定） | `username` 去留见 G-DM-3 |
| `internal/core/types.go:1277-1314` | **已接线** | `Username` 去留见 G-DM-3 |
| `trafficgen/test/protocol_pcap/cases/dameng.json` | **已迁移+新增** | 34 例总计：33 例业务配置为纯层链形（13 正 + 20 负），第 34 例为故意 presence 负例；本任务仅同步文档 |
| `trafficgen/tools/coverage_gate.py` | **扩展** | 新增 `check_dameng` 反查块（B 轨编写，M1 登记认领） |

### 11.2 接口签名（当前实现）

```go
// dameng（事件校验 + 占位字节，无 core 外依赖除 types）
func (Planner) Validate(spec core.FlowSpec) error            // 已有，补方向守卫
func (p Planner) Plan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) // 已有
func buildPacket(ev core.DamengEvent) ([]byte, error)        // 已有（占位）
func profilePayload(profile string) []byte                   // 已有
func checkWireFault(raw json.RawMessage) error               // 已有
```

### 11.3 数据结构（当前）

当前结构为 `DamengEvent{Kind, Direction, Profile, Username, Result, SQL}`；`Username` 未被消费，列为 G-DM-3，其他字段由校验器或 builder 消费。

### 11.4 主流程

```text
strategy config(layers)
  → ValidateLayers（未知层/未知字段 V9/层链完整性；P4 后 dameng 层 config 合法）
  → ChainPlanner.ValidateSpec（FieldContract 端口契约 + carrier 校验 + translateTerminalConfig dameng 分支 + dameng validator 状态机/kind/方向/profile/wire_fault）
  → worker 逐流：resolveLayerTuple（动态）→ ChainPlanner.Generate
  → DamengGenerator.Generate（逐 session → 逐 event → buildPacket → EmitMsg{Up, Bytes, SrcPort}）
  → tcp 层（握手/分段/seq/挥手 + 多连接）→ ip 层 → 输出（pcap / port_group）
```

### 11.5 错误分支（§5.2）

三档：①**链级**（`ValidateLayers`/`ChainPlanner.ValidateSpec`）——未知层、`unknown field`、carrier 非 tcp、端口 ≠ 契约端口、presence 混用（G-DM-6 已关闭）；②**配置级**（dameng `Validate`）——wire_profile/kind/direction/状态机/sql 非空/wire_fault/payload_size；③**生成期**（`buildPacket` 永不返回错误——占位字节总成功；若未来 fixture 化后出错，即为实现 bug）。全部传播为 **task error**，**零假成功**。

### 11.6 性能边界（§6.1–6.8 摘要，详见本契约 §6）

单 flow 常驻内存 O(1)；无锁无共享；逐事件流式；速率归框架 pacer。**不新增任何按流缓存**。

### 11.7 与现有逻辑的冲突点（§8.7）

1. **flat/层链双头风险（已收口）**：flat 路径（`strategy_convert.go:1719-1725` 为层链翻译旁路，`:581-585` 域校验 + `:8807-8810` 判死）与层链路径今日并存；`CheckProtoFlat` 已加 dameng 门——`CheckProtoFlat` 拦截顶层 `dameng` 键，层链内 config 为唯一真相，**不存在两套真相并存**。
2. **事件内死字段**：`username`（当前 JSON 已无实例）仍未被 builder/planner 消费，记录为 G-DM-3 实现缺口。
3. **`CheckProtoFlat` 已接线**：顶层 `dameng` 子映射由通用门拒绝（§10.6）；G-DM-6 已关闭。
4. **方向一致守卫已实现**：planner 拒绝显式 direction 与 kind 自然方向不一致，#33 `dameng_neg_direction_mismatch` 以 `inconsistent` 覆盖。

### 11.8 回滚方式（§8.8）

按提交序 `git revert`：registry/translate/validator 扩展类提交可逐提交回退；**存量 14 例改写提交是唯一的"数据面"提交**——回退它必须与字段删除提交**同批回退**（否则 `DisallowUnknownFields` 与用例配置失配）。registry/schemagen 生成文件随提交对齐（dameng 在生成表 `trafficgen/schemas/v1/generated/layers.generated.json:428-464`，五键 + `transport_on` + `field_contract` 已落定；schemagen 已重跑）。

---

## 12. 门1 §1–§14 十四行对照表（CORE_MEMORY §15.1–§15.3）

> 证据三选一（§15.2）：文档章节 / 代码行 / 用例号。写不出 = 缺口立项，不许空着。§1/§3/§12 三行按 §15.3 强制展开（§12.1/§12.3/§12.12）。

| § | 本协议怎么满足 | 证据 |
|---|---|---|
| §1 层链唯一真相 | 见 §12.1 强制展开：旧稿 14 例已全部迁移；当前 JSON 33 例业务配置为纯层链，#34 为故意 presence 负例；非负例顶层键仅为允许键 | 本契约 §2.1 + §12.1；`cases/dameng.json` 34 例实测 |
| §2 策略/任务 | 策略 = 单 dameng 流量模板，自带 `flow_control`（flows/bps/time）；任务 = 多策略合跑 + 总量封顶；框架语义未动（dameng 不在 worker/task 特判名单） | `internal/core/worker.go:307-308`；本契约 §2.1 |
| §3 五件套 | 见 §12.3 强制展开：会话表 / 事务序列 / 关联关系（无派生流的诚实边界）/ 插入位置 / 时间线；**有长连接载体（单 TCP 承载全部事件），不豁免** | 本契约 §12.3 + §10.4；用例 `dameng_multi_session` |
| §4 查规范 | 公开资料（DM8 默认端口 5236 + SYSDBA，多源一致）+ 旧基线语义契约 + 本仓库实测面；tshark **零 Dameng dissector**（实测）；P1 矩阵 8 行 + 三子表（§10.1–§10.3）+ 候选方案对比（§10.5） | 本契约 §3/§10 |
| §5 依赖与错误 | 依赖 = `DependsOn ["tcp"]` 单值（`registry.go:821`）+ `TransportOn ["tcp"]`（`registry.go:825`）；端口契约 `FieldContract{"tcp.dst_port":"5236"}`（`registry.go:826`）；`wire_fault` 2 有效 kind + 3 类非法形（`builder.go:42-58`）；失败全部传 task error（零假成功） | 本契约 §5/§7 + §11.5 |
| §6 性能 | 见本契约 §6「性能设计与验收」（6.1–6.8 要素）：逐事件流式、单 flow O(1) 内存、无锁无共享、零可变状态；pcap/NIC 双路验收（NIC = `enp135s0f0np0`）；吞吐数字标「待 P4 基准」（§6.5 不写承诺） | 本契约 §6 |
| §7 三份文档 | `81-dameng-design.md` v1.0.0 + `81-dameng-testcase.md` v1.0.0（per-protocol 草稿层，§7.4；append 进 CODE_DESIGN.md/TEST_CASES.md 的条目为唯一权威文本）+ D-DAMENG-1（本契约 §11，门1 获批 = 定稿）+ T-DAMENG（testcase §2）+ generated schema（dameng 已在层数内，P4 改 `Fields` 后重跑） | 修订记录 |
| §8 设计先行 | 本条目 P1–P3 先于 P4 实现；门1 获批 = D-DAMENG-1 定稿 = 开工门（§8.9） | 提交序 |
| §9 测试三源 | 三源 = 公开资料条款（§3/§10 逐表列出处）+ D-DAMENG-1（§11）+ 已确认现网行为（**未到抓包级 → G-DM-4**，不冒充第三源）；当前 JSON 34 例（13 正 + 21 负）逐项回指；旧版统计仅作历史修订记录；存量 14 例审计去向 §8 + testcase §8 | `81-dameng-testcase.md` §2/§5/§6/§8 |
| §10 评审闭环 | 每阶段对抗自重审（结论见 `/tmp/pipe/81-dameng/p123-report.md` §3）+ 收官隔离复审 + 修轮；红先绿后 | 报告 §3 |
| §11 白话 | 汇报首句先行白话结论 | 报告 §0 |
| §12 动态清单 | 见 §12.12 强制展开：四元组 = `ip`/`tcp` 层（五策略全支持，allowlist `layer_dyn.go:17-21`；`dameng` **不在** allowlist → 业务字段对象必拒）；业务字段逐个列开/不开 + 理由；序号算法实读行号（`layer_dyn.go:78/369/770`；`tuple_generator.go:26/290/300`；`worker.go:307-308`） | 本契约 §12.12 |
| §13 schema 派生 | `dameng` 已在 registry 注册（`registry.go:821-841`，五键；生成表 `layers.generated.json:428-464`，**不新增层**）；`allowedProtocols["dameng"]=true`（`protocols.go:23`）；`main.go:518` 已注册 ChainPlanner；**P4 改 registry `Fields` 后必须重跑 schemagen**（§13.18/13.19）；struct 标签字面量锁定（§13.13） | 本契约 §11.1 |
| §14 真实流程 | suite 经 MCP 建策略建任务 → 引擎真实生成 → tshark `tcp.*`/`ip.*` + 包数公式双通道 → 先跑后钉（§9.31/§14.20）；pcap 落 `/tmp/mcp-pcaps/dameng/` | testcase §7 |

### 12.1 §1 强制展开：旧键去向 + 完整 spec_json 样例

**存量基线审计（历史快照，非当前 JSON）**：旧稿为 14 例；当前 `cases/dameng.json` 已迁移并扩展为 34 例。

| 文件 | 例数 | 顶层键分布 | 链形 | 负例 expect 纯净 |
|---|---:|---|---|---|
| `cases/dameng.json`（当前） | 34 | 33/34 为纯层链业务/成功形；第 34 例为故意 presence 负例 | `[ip,tcp,dameng]`×32 + `[ip,udp,dameng]`×1 + presence 负例×1 | ✅ 21/21 仅 `{expect_error,error_contains}` |

**旧键去向表（历史迁移记录；当前 JSON 已无这些顶层键）**：

| 旧键 | 存量出现例数 | 去向 |
|---|---:|---|
| `src_ip` | **14** | 迁 `layers[i].ip.src`（P4 改写） |
| `dst_ip` | **14** | 迁 `layers[i].ip.dst` |
| `src_port` | **14** | 迁 `layers[i].tcp.src_port`（多会话例的顶层 `src_port` 与 `sessions[].src_port` 重复，改写时只留会话级） |
| `dst_port` | **14** | **删除**——由 FieldContract 补齐 5236，存量刻意不再写（`neg_port` 改写为层内 `tcp.dst_port=5237` 显式坏形） |
| `count` | **0**（存量未用） | 走 `flow_control`（改写时 `multi_flow` 例写 `flows=3`） |
| 顶层 `dameng` 子映射 | **14** | 迁入 `dameng` 层 config（`wire_profile/events/sessions/payload_size/wire_fault` 五键；P4 先补 registry `Fields`，G-DM-2） |
| 事件内 `username`（死字段） | 9 例 10 处（auth_request；`dameng_multi_session` 含 2 处） | **P4 删键或接线**（§1.12；G-DM-3） |

**结论**：本协议 §1 门已收口：旧稿 14 例全部迁移，当前 34 例中 33 例为纯层链；第 34 例是故意 presence 负例；非负例顶层键为 0。

**目标形状 spec_json 样例（纯 layers，顶层仅 `layers` + `flow_control`）**：见本契约 §2.1（`dameng_sql_success` 改写形）。

**presence 负例形状说明（本协议必须点名）**：`{"layers":[…],"dameng":{}}`（层链 + 顶层空子映射并存）由 `CheckProtoFlat` 通用门拒绝（`strategy_convert.go:581-585`），因此纳入当前 34 例作为故意 presence 负例，覆盖 `CheckProtoFlat` 判死；G-DM-6 已关闭。

### 12.3 §3 强制展开：五件套

**会话表**：

| 会话 | 四元组 | 生命周期 | 用例 |
|---|---|---|---|
| `s1`（单会话基线） | `ip.src/dst` + `tcp.src_port→5236` | SYN/SYN-ACK/ACK → connect → 认证序列 → SQL* → close → FIN-ACK 四way | `dameng_sql_success` / `dameng_close_clean` |
| `s2`（多会话展开） | 第二 src_port（`sessions[].src_port`） | 与 s1 完全独立的握手→认证→挥手；**整块回放不交错**（术语表「多会话展开」） | `dameng_multi_session` |
| `s3`（并发多流） | `flows=3` 三条独立四元组 | 框架逐流并行；断言各自独立 | `dameng_multi_flow_dynamic`（A′ 落盘） |

**事务序列（单事务四件事 §3.4–3.7）**：

| 事务 | 前置条件 | 触发动作 | 成功分支 | 失败分支 |
|---|---|---|---|---|
| `t1` 建连 | TCP 握手完成 | c2s connect 事件 | s2c 无（connect 是单向声明事件）→ 进入认证 | 缺 connect：后继事件全拒（`state`） |
| `t2` 认证 | `t1` 已发 connect | c2s auth_request → s2c auth_response | `result=success` → authOK → 允许 SQL | `result=error` → authOK=false → SQL 全拒（`auth`）；后接 close（`auth_error_then_close`） |
| `t3` SQL 查询 | authOK=true | c2s sql_request + SQL 文本 → s2c sql_response | `success`（结果集占位）/ `error`（独立 profile） | 空 SQL 拒（`sql`）；未认证拒（`auth`） |
| `t4` 结束 | 任意已认证态 | c2s close（必须末位） | 无响应 + TCP 挥手 | 非末位 close 拒（`state`） |

**关联关系（§3.8–3.10）**：见 §10.4 专节——**会话内无派生流**（诚实声明）；响应靠顺序关联，无事务标识。因此 `driven_by` 今日**不适用**，且**不许**用"同一模板连续重复发射"冒充编排（§3.13）。

**插入位置**：终结层（`CategoryTerminal`，`DependsOn ["tcp"]`）——占位字节直接落 TCP payload；链上**无中间层**。

**时间线**：**单会话严格顺序**（t1→t2→t3→t4，每步依赖前一步结果，`validateEventSequence` 已强制）；**多会话整块顺序**（s1 全流程跑完再跑 s2）；**多流并发**（`flows=N`，跨流不假设全局包序，只断言流内序与各流独立）。无"长传输分片让位"面（无数据流）；控制可中插动作 = 无。

### 12.12 §12 强制展开：动态字段清单与序号算法

**四元组（`ip`/`tcp` 层，五策略全开）**：

| 字段 | 住处 | 开策略 | 依据 |
|---|---|---|---|
| `src`（src_ip） | `ip` 层 | fixed/inc/rand/list/pattern 全开 | allowlist `layer_dyn.go:18` |
| `dst`（dst_ip） | `ip` 层 | 同上 | 同上 |
| `src_port` | `tcp` 层 | 同上 + 未写动态保底 `12345+i`（`worker.go:307-308`，`DefaultSrcPort = 12345`，`strategy_convert.go:46-49`） | allowlist `layer_dyn.go:19` |
| `dst_port` | `tcp` 层 | 同上，**但域校验强制 = 契约端口** 5236（`planner.go:56-58` + 链路通用契约）——动态 dst_port 与端口契约冲突 → **实际不可用**，如实声明 | 同上 + 端口契约 |

**业务字段（`dameng` 层，逐个列开/不开 + 理由）**：

| 字段 | 开 | 理由 |
|---|---|---|
| `wire_profile` | ❌ 关 | 版本选择器，逐流变无业务意义 |
| `events[]` 整块 | ❌ 关 | 事件序列是会话剧本；逐流变等价于"多套剧本"，应由多策略表达（§2.2 策略=单一模板） |
| `sessions[]` 整块 | ❌ 关 | 同上；多会话的内部展开已由 `sessions[].src_port` 承担 |
| 事件内 `profile` | ❌ 关 | 占位字节名，逐流变无断言意义（且 fixture 化后更须固定） |
| 事件内 `sql` | ❌ 关（今天） | 多 SQL 模板逐流变可想象（多查询压测），但会引入 per-flow 事件重写路径 → 列 A′ 补例候选（需先登记 allowlist；`dameng` **不在** `layerDynAllowlist`，对象必拒） |
| 事件内 `username` | ❌ 关 | 死字段（G-DM-3），先处置死语义再谈动态 |
| 事件内 `result` | ❌ 关 | 会话内结构性取值，逐流变破坏会话自洽 |
| `wire_fault` | ❌ 关 | 负例唯一注入口，非业务字段 |
| `payload_size` | ❌ 关 | 全局边界开关，非逐流面 |

**序号算法代码位置（实读，不编行号——§5.7）**：

- 层内字段动态解析入口：`internal/core/layer_dyn.go:78` `parseLayerDyn` → `:369` `checkDynShape` → `:770` `resolveLayerTuple(spec, i)`（**逐流解析并覆写**）。
- 值算法：`internal/core/tuple_generator.go:26` `TupleGenerator.Next(index)`；inc 回绕 `:164` `genIP6Inc`；rand 可复现 `:181` `genIP6Rand`（seed+index）；端口 `:194` `genPort`；单值解析 `:290` `ResolveIPValue` / `:300` `ResolvePortValue`。
- 保底自增：`internal/core/worker.go:307-308`（`flowCount > 1 && !spec.HasExplicitSrcPort` → `DefaultSrcPort + i`）。
- allowlist 白名单：`internal/core/layer_dyn.go:17-21`——**`dameng` 无块**，即层内任何对象值 → `does not support dynamic`。

### 12-P2 判死负例形状（链级红例必含清单①③④）

- **①层链+顶层空子映射并存**：由 `CheckProtoFlat` 通用门拒绝（`strategy_convert.go:581-585`），当前不重复建可执行负例，G-DM-6 已关闭。
- **②白名单外游离键判死（1.11–1.13）**：P4 已由通用层字段白名单覆盖；本协议当前 JSON 无游离键。
- **③一切负例 `expect_error` 带错误锚词**：20 个负例逐条锚词见 testcase §4。
- **④收官自查行**：「非负例顶层键 = 0」——当前 JSON 机读通过（动态流正例仅含允许的 `strategy_fc`）。
- **载体负例**：链夹 `udp`（`[ip,udp,dameng]`）判死，锚词 `tcp`（通用 tcp-only 逻辑 `complete.go:448-466` 实测；存量 `dameng_neg_udp` 即此形）。

---

## 13. P3 对接清单（T-DAMENG 草稿输入；正文落 testcase 文件）

- §3.15 三项：见 testcase §6.1（①同连接多轮操作→`sql_success` + A′ 补例「同连接多轮查询」；②非正常结束→`auth_error/sql_error` + 20 条负例 + A′「服务端 RST」；③长保活→多轮 A′（协议层无 keepalive 语义已显式声明不适用）。
- A′/B′ 两分类表：见 testcase §6.2。
- 9.52 对账两行：见 testcase §5.2（**规范逻辑点总数 = 46** = 八项 8 行 + 矩阵 20 格 + 变体 18 行；**用例覆盖数 = 38**；**不适用/注记 = 3**；**缺口 = 5**；38 + 3 + 5 = 46 ✓；清单出处 = 公开资料+旧基线反推）。
- 3.14 豁免边界审计：见 testcase §6.3（**有长连接载体 → `sessions[]` 不豁免**；多流并发 + 单包多载荷（本协议无此形态，显式不适用）。
- 三源回指行：见 testcase §5.1（第三源"已确认现网行为"当前 = 未确认级，挂 G-DM-4）。

---

## 14. 缺口立项清单（有缺口写「缺口立项」，不许空着）

| 立项号 | 缺口 | 确认方式（三选一：查文档 / 抓包 / 问人） | 去向 |
|---|---|---|---|
| **G-DM-1** | 私有 wire 无版本化 fixture：应用消息头、长度字段、认证摘要、SQL 编码、响应状态全部未定稿；占位字节不得冒充实现 | **抓包**：DM8 明确版本 + 官方驱动，tcpdump 抓 5236 标应用消息边界；或官方字节文档章节 | **B′**→D-DAMENG-1；当前正例只断言传输层，后续以 DM8 版本化抓包 fixture 验证私有 wire |
| **G-DM-2** | 链路径层 config 不生效：registry `Fields` 空 + 无 translate 分支（§2.2 实测） | `registry.go:821-841` + `chain_planner_translate.go:2921-2950` | **closed**（P4 已补 Fields 五键 + translate `case "dameng"` JSON 往返 + 存量改写同批；当前 JSON 33/33 业务配置可层链） |
| **G-DM-3** | 事件内死字段 `username`（当前 JSON 已无实例，零读取） | 读 `builder.go`/`planner.go`（`Username` 零命中）+ 当前 JSON 机读 | **记录为实现缺口**（删或接线） |
| **G-DM-4** | 现网行为未到抓包级：DM8 真实建连序与认证序列只有公开资料描述，无本机抓包证据 | **抓包**：本机回环起 DM8（或容器）+ 官方驱动连接，tcpdump 抓 5236 | P4 前置确认项，不挡开工；确认前相关条目按 §5.5 标"待确认" |
| **G-DM-5** | 方向一致守卫已实现：显式 direction 与 kind 自然方向不一致时拒绝 | 读 `planner.go` 的 `validateEventSequence` 方向比较分支 + #33 | **已覆盖**（planner 方向一致守卫 + 负例 `dameng_neg_direction_mismatch`，锚词 `inconsistent`） |
| **G-DM-6** | 顶层白名单执法：`CheckProtoFlat` 已有 `dameng` 分支 → 顶层 `dameng` 子映射被拒绝 | 读 `strategy_convert.go:577-585`（dameng 命中） | **closed** |
| **G-DM-7** | 空 profile 回退语义未钉例：事件缺 `profile` 时字节为 `"dm8"`（`builder.go:27-29`） | 读 `builder.go:26-31` + 单测 `TestBuildPacketDefaultProfile` | **A′**（P4 补正例钉现状，或随 fixture 化重定） |
| **G-DM-8** | MSS 分段与服务端 RST 未覆盖 | 长 SQL fixture + `tcp.rst` 配置面确认 | **A′**（P4 落 `long_sql_mss` + `server_abort_rst` 补例） |

---

## 15. 修订记录

- v1.0.2（2026-10-01）：按实际 `CheckProtoFlat` 能力确认顶层 presence 已接线拒绝；当前 JSON 34 例（13 正 + 21 负），同步修正文档计数、状态与覆盖说明。
- v1.0.1（2026-09-28，P6 M2 回填 + 主线程接管注记）：M2 行号回填（registry 642-643→702-707、generated 354→379、main 515→516）；G-DM-2 标 closed；32 ID→33 例口径差注记（新增 G-DM-5 负例，presence 形后来由 G-DM-6 接线拒绝）；M1 注释漂移随 chain_planner 注释收敛关闭。
- v1.0.0（2026-09-26）：P1–P3 文档轨产物（车道 A）。建立历史 P1/P2/P3 契约与缺口清单；后续修订完成层链迁移、registry/translate 接线及 presence 通用门。**未跑 suite、不启动服务器**。
