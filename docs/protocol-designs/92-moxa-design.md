# #92 moxa（Moxa NPort 串口透传）设计契约

> 版本：v1.0.0（P-PIPE 文档轨 P1–P3）
> 日期：2026-09-27
> 车道：A 文档轨（Lane A，#92 moxa RESUME）
> 旧基线：`docs/protocol-designs/27-moxa-design.md` v1.0.0 + `27-moxa-testcase.md` v1.0.0（13 例 = 6 正 + 7 负；本 #92 为 P-PIPE 重做，思路继承、不搬码——旧稿"代码未写/规划中"状态已过时，见 §0）
> 存量用例：`trafficgen/test/protocol_pcap/cases/moxa.json`（13/13 ID 与旧稿一致，顺序一致，已机读实测；顶层旧键残留待 P4 迁移，G-MOXA-1）
> 规范基线：① Moxa NPort 5100 系列官方 datasheet（operation modes：TCP Server / TCP Client / UDP / Pair Connection / Ethernet Modem，下称 **spec**，§I）；② 旧基线设计文档（内部契约，非外部规范）；③ 本仓库落码（planner/validator/生成器/接线，§11.1）；④ 本机 tshark 实测（无 moxa dissector，断言走 `tcp.*`/frames 通道）；⑤ 公开资料 + 假设（TCP 4800 数据默认口、UDP 4800 配置口，逐处标注，未达验证级 → G-MOXA-4）
> 白话一句：**串口服务器把串口上的字节原样装进 TCP 来回送，本身没有报文格式；引擎里它是一层薄皮——只管把几段字节排好序，握手分段挥手都由 TCP 层干。**

## 0. 27→92 沿革与旧稿过期声明校正（门1 必答：基线继承关系）

本 #92 与旧稿 `27-moxa-*` 是**同一协议的重做契约**，不是新协议。旧稿保留在磁盘只读参考，本契约逐条校正旧稿已过时的状态声明：

| # | 旧稿说法（27-*） | HEAD 实测（2026-09-27） | 校正结论 |
|---|---|---|---|
| 1 | "实现位置：……（终结层生成器 + 校验器，规划中）"（design §0 头注） | `trafficgen/internal/protocol/moxa/` 四文件已落码：`layer_gen.go` 87 行、`planner.go` 143 行、`types.go` 8 行、`moxa_test.go` 556 行（`wc -l` 实测）；33 个 `Test*` 函数（`grep -c` 实测） | "规划中"已过时；本契约 §11 为 as-built 逆向定稿 |
| 2 | "层注册，规划中"（design §8 I2） | `registry.go:610` 已注册 `moxa`（`CategoryTerminal`，`DependsOn ["tcp"]`，无 `Fields`）；生成表 126 层中 `moxa` 条目 `fields: {}`（机读实测） | 已注册；"not registered"类说法作废 |
| 3 | "`MOXAConfig` 定义，规划中"（design §8 I1） | `internal/core/types.go:741-750` 已定义 `MOXAConfig`/`MOXAStreamBlock`；`FlowSpec.MOXA` 槽位（`:1690`）已存在 | 已落码 |
| 4 | "`moxa` flat 键解析，规划中"（design §8 I3） | `strategy_convert.go:1421-1423` 已有 `case "moxa"`（`parseSubconfigJSON` 搬运）；`chain_planner.go:881` 源端口保持、`:1144` 目的端口默认 4800；`chain_planner_translate.go:119` Meta 直传 `MOXA: spec.MOXA` | 平面接线已通；缺的是**层内化**（G-MOXA-1） |
| 5 | 旧稿 spec_json 样例全部顶层扁平键（design §5.6：`src_ip/dst_ip/dst_port` + 顶层 `moxa`） | 存量 13/13 例含 `src_ip`/`dst_ip`（机读实测）；其中 `moxa_neg_no_handshake` 另带顶层 `tcp`，`moxa_sessions_multi` 另带 `strategy_fc`；13/13 均无 `src_port` | 旧样例形 = **过渡态违规形**（§1.4/§1.11），P4 按 §12.1 迁移；本契约 §2 样例只给纯层链形 |
| 6 | 旧稿包数公式 `3+N+4`（事件模式无独立 ACK） | HEAD `moxa_test.go` Plan 单测断言同值：S1=8（`:178`）、S2=9（`:219`）、S3=11（`:255`）、S5/S6=8（`:297/:319`）；存量 JSON `packet_count` 同值（机读 8/9/11/24/8/8） | 公式继承有效；实现期仍须先跑后钉复核（§9.31） |
| 7 | 旧稿"UDP 4800 配置协议字节布局待定，不编造"（design §3.2） | 无新资料进入；tshark 3.6.14 `moxa` 前缀字段数 = **0**（实测） | 待定状态继承；探针拒绝（N-2）保留，收窄待 G-MOXA-6 |

**依赖链判定纪律**：以上均为可判题（旧文→代码→用例三级对照），直接判定，不问偏好。不可判的（现网 NPort 默认口实证）标"待确认"并写清确认方式（G-MOXA-4）。

## 1. 范围、profile 与实现状态边界

本版定义主站（miner 侧类比：采集程序/PLC 上位机）与 NPort 之间的 **TCP 明文长连接裸字节流**：连接建立后 TCP payload 即串口数据，**无应用层帧、无长度前缀、无记录头**（spec §I operation modes；旧基线 §1.1）。

| profile | 承载 | 本版允许内容 | 不从 profile 推导 |
|---|---|---|---|
| `moxa_transparent_v1`（主） | TCP 明文裸字节（fixture 4800，可配置覆盖） | 块序列全部形态（单块/多块/双向/分段/二进制/多流/v6） | 真实串口波特率、字节到达时刻、NPort 固件分段 |
| `moxa_ipv6_v1` | 同上，仅外层 IPv6 | 同主 profile | 从 IPv4 fixture 推导 IPv6 地址 |

显式边界（"不实现、不声称、不许静默转换"）：TCP Client 模式（NPort 主动建连）不在本版；UDP 模式不在本版；Pair Connection 不在本版；UDP 4800 配置管理面不在本版（字节布局待定，§3 诚实边界）；不声称任何块与真实串口字节的到达时序一致（生成器只保证块序列 + 可选速率）。

**实现状态（2026-09-27 实测，与旧稿"规划中"已不同）**：`moxa` 层已注册（`registry.go:610`）、planner/validator/生成器已落码（`internal/protocol/moxa/` 四文件共 794 行）、`allowedProtocols["moxa"]=true`（`protocols.go:44`）、13 语义用例已落 `cases/moxa.json`。旧稿"代码未写"描述已过时（§0 表）。

**输出契约（pcap/NIC 双输出）**：两路径共用同一 cases JSON 与断言集（`tcp.dstport/srcport`、`tcp.flags/seq`、offset 54/74 frames）；NIC 经 tcpdump 捕获（`nic_capture` 用例级开关）；不设仅单路径可用的断言。

## 2. 协议栈、端口和固定偏移

推荐层链为 `[ip, tcp, moxa]`（引擎自动补 `ip`；最小链 `[tcp, moxa]`）。moxa 报文是 TCP payload 的**裸字节内容**——**段边界不是块边界**：一块可跨多段（超 MSS），多块可各成段；接收端按 TCP 序号重组（旧基线 §3.4–§3.5）。

端口：NPort 数据监听口 **TCP 4800**（⑤ 标注：旧基线称部分型号出厂默认，未达验证级 → G-MOXA-4；planner 缺省 4800 已落码 `chain_planner.go:1144`）。fixture 统一 `dst_port=4800`；用例一律显式写端口并纳入断言（旧 §1.4 纪律继承）。UDP 4800 为配置管理口（⑤ 标注，同 G-MOXA-4），本版不生成。

固定偏移：无 VLAN/IP options/TCP options 时，**每块首字节起点为 IPv4 offset 54（14+20+20）、IPv6 offset 74**（14+40+20）。**TCP 分段边界不是块边界**：超 MSS 块跨段（S2：1460+540），多块各成段（S3：4 块各 1 段）。

目标形状 spec_json 样例（严格层链形，顶层仅 `layers` + `flow_control`；**目标形状声明**：registry `moxa` Fields 今日为空，层内 `stream` 键今日无处可住，故此形**今天跑不通，需先补代码** G-MOXA-1，§1.9 口径）：

```json
{
  "layers": [
    {"ip": {"src": "10.0.0.1", "dst": "20.0.0.1"}},
    {"tcp": {"src_port": 12345, "dst_port": 4800}},
    {"moxa": {"stream": [{"payload": "hello"}]}}
  ],
  "flow_control": {"flows": 1}
}
```

多流样例（S4 目标形，数量只走 `flow_control`，四元组留空走 worker 保底递增 §12.12）：

```json
{
  "layers": [
    {"ip": {"src": "10.0.0.1", "dst": "20.0.0.1"}},
    {"tcp": {"dst_port": 4800}},
    {"moxa": {"stream": [{"payload": "hello"}]}}
  ],
  "flow_control": {"flows": 3}
}
```

## 3. 线格式编码（逐项标注出处）

### 3.1 块与方向

- **块（StreamBlock）**：一段连续串口字节 + 方向。字段：`payload`（文本，原样字节）/ `payload_b64`（二进制，与 `payload` 互斥，`payload_b64` 优先）/ `direction`（`""`/`up` 默认主站→NPort；`down` = NPort→主站，TCP 段端口对换）（`types.go:741-750`；旧基线 §2.1）。
- **无帧**：块之间不注入任何应用层字节；块与 TCP 段不必一一对应（旧基线 §3.1）。
- **长度上限**：单块 ≤ 2048 字节（`MaxBlockBytes`，`types.go` 配套常量 `planner.go`/`layer_gen.go` 共用；旧基线 §2.3）。超 MSS 合法（tcp 层分段）；超 2048 拒绝（E-B1）。

### 3.2 配置/管理面：UDP 4800（字节布局：待定，继承旧 §3.2）

NPort 配置协议为 Moxa 私有协议，无公开字节级规范。本设计**不编造任何字节**，仅记录：端口 UDP 4800（⑤ 标注，待 G-MOXA-4 确认）；用途设备搜索/参数读写（旧基线记载）；载荷结构待定。v1 不生成；负路径 N-2 做身份区分（§7）。

### 3.3 tcp 层联动语义

| tcp 字段 | 本协议语义 |
|---|---|
| `handshake`（默认 true） | 必须 true；显式 false = 拒绝（E-T5，`planner.go` Validate） |
| `termination`（默认 true） | 可 false（长连接不主动挥手）；默认 true = 发完即断 |
| `mss` | 分段粒度：超 MSS 块多段（S2/S3 覆盖）；有效范围走通用校验 |
| `src_port` 缺席 + `flows>1` | worker 保底 `12345+i`（`strategy_convert.go:49`；S4 断言锚点） |

## 4. 业务场景分析（现网典型场景与五层覆盖）

**定性**：**声明式剧本回放**——配置是剧本（`stream[]` 逐块声明方向与字节），引擎按序产出事件，tcp 层按 MSS 分段。

| 现网场景 | 事务交互 | 对应用例 |
|---|---|---|
| ① 点对点轮询 | 主站发 up 块 → NPort 回 down 块 | S3（`moxa_bidirectional`） |
| ② 多串口并发 | 多条独立 TCP 连接，各自透传 | S4（`moxa_sessions_multi`，flows=3） |
| ③ 二进制仪表 | 任意字节透传（base64 注入口） | S5（`moxa_binary_payload`） |
| ④ IPv6 产线 | 同 ①，仅外层 IPv6 | S6（`moxa_ipv6`） |
| ⑤ 大块串口数据 | 超 MSS 单块分段发送 | S2（`moxa_multi_segment`，2000B→1460+540） |

**五层覆盖逐层结论**：功能层——块六形态每类正例 + 拒绝分支 7 类负例；性能层——大块跨 MSS（2000B/2 段）、多流 3 连接 24 包、最小块边界（5B "hello"）；数据场景层——空/超限/非法 b64/非法方向/异族地址/ sessions 越界/探针前缀；地址与流层——v4/v6 独立用例、单流基线、多流三四元组、端口显式 4800；**流关联（控制流派生数据流）显式不适用**：单 TCP 连接承载全部块，无副连接；**多流（会话内并发流）显式不适用**：单连接串行收发，多会话语义由 `flow_control flows` 承载。业务层——轮询问答链（up→down 交替，S3 四块）。

**次要合法行为显式不适用声明（不设正例、亦不得进负例）**：① `pack_ms` 块间停顿（字段存在、v1 未实现，G-MOXA-7）；② `termination=false` 长连接不断开（tcp 层能力，本层不断言）；③ RST 异常中断（框架 tcp 层能力，本层零断言，A′ 补例 G-MOXA-5）；④ 块合并（连续同向块合并一段，今日实现为各成段，旧 §4.6 已记 divergence）。

## 5. 消息/事务模型与状态机

**事务定义**：同一 TCP 连接内一个块的发送（up）或接收（down）。**多事务** = 一连接内多块按序执行：S3（up→down→up→down 四事务）。

moxa 层无自有状态（旧 §4.1 继承）：握手/seq-ack/挥手/分段全在 tcp 层；moxa 层是"按配置顺序把块翻译成事件"的纯函数驱动。

| 状态（tcp 层拥有） | moxa 层动作 | 用例 |
|---|---|---|
| `ESTABLISHED`（数据阶段） | up 块 → `(up, 0x18)` 事件；down 块 → `(down, 0x18)` 事件（端口对换） | S1–S6 |
| 终止（FIN 四包 / RST） | 事件流关闭 → tcp 层挥手；RST 为框架能力 | 全正例 FIN；RST → G-MOXA-5 |

**多会话展开**：`sessions>1` 由 validator + 生成器双拒绝（E-S3）；多会话语义由策略级 `flow_control {"flows": N}` 表达（S4，worker 递增 `src_port` 12345/12346/12347）。单 flow 内 sessions 数组=**明确不解决**（v1 范围，迁入计划 = 现状已够用，不扩展）。

**自动派生规则**：① `stream` 缺省 → 单块 up "hello"（冒烟，`planner.go` Plan + `layer_gen.go` Generate 双默认）；② TCP 握手/FIN 由 tcp 层自动补；③ 超 MSS 块自动分段（`planner.go` 按 mss 切片；事件路径由 tcp 层分段）。

## 6. 性能设计与验收（CORE_MEMORY §6.1–6.8）

- **目标与边界**：单流全链 ≤9 包（含握手挥手，S2 最大）；大块 2000B 跨 2 段为最大单块压力；多流 3 流 24 包顺序展开。吞吐数字待 P4 基准，**本版不写承诺**（§6.5）。
- **依据**：块序列流式展开（`Plan` goroutine + chan 32 缓冲；`layer_gen.go` 逐块 emit，无全量收集）；每块内存 = 块长 + TCP 段开销（O(块)）；无跨流共享状态；无锁（`MaxBlockBytes` 常量只读）。
- **验收两路**：pcap（`/tmp/mcp-pcaps/moxa/`）与 NIC（`enp135s0f0np0`，`nic_capture` 开关）共用同一断言集；断言实际 `tcp.len` 序列与块 hex，不只断言"任务没报错"。
- **六类场景落点**：基线（S1，8 包）/ 目标规模（S3，11 包双向）/ 压力上限（S2，2000B 跨段）/ 长时间运行（S4 多流展开）/ 并发交错（顺序多流承载语义，并发路径为例外不启用）/ 背压（MSS 分段 + `packet_count` 精确计数守卫段数漂移）。

## 7. 错误处理（负例锚词表，与 testcase §4 一一对应、同序）

以下输入必须由 planner/validator 拒绝并传播为 task error，不得产出成功 PCAP、`completed/0 packet` 或只剩 TCP 外壳的假成功：

| # | 负例 ID | 故障输入 | `error_contains` 锚词 |
|---:|---|---|---|
| N-1 | `moxa_neg_empty_payload` | 空 stream / 空 payload | `moxa: empty stream block or payload required` |
| N-2 | `moxa_neg_config_packet` | 前 3 字节 `0x5a 0x5a 0x5a` 受控探针 | `moxa: config-packet bytes in stream are not supported` |
| N-3 | `moxa_neg_sessions_multi` | `sessions=3` | `moxa: sessions=3>1 not supported` |
| N-4 | `moxa_neg_no_handshake` | `tcp.handshake=false` | `moxa: tcp.handshake must be true` |
| N-5 | `moxa_neg_bad_b64` | `payload_b64="%%%"` | `moxa: invalid payload_b64` |
| N-6 | `moxa_neg_oversize` | 3000B 单块（>2048） | `moxa: block 0 payload 3000 exceeds max 2048` |
| N-7 | `moxa_neg_bad_direction` | `direction="sideways"` | `moxa: invalid direction` |

**负例原子性**：每例单一故障注入；单次执行不得混注。N-2 为受控探针（§3.2 诚实边界传导），正式魔数核定后收窄（G-MOXA-6）。

**不得误报的合法协议事件**：超 MSS 但 ≤2048 的块（S2 正例）；`down` 方向块（S3 正例）；`payload_b64` 合法值（S5 正例）。

## 8. 边界

- **块长与分段**：2000B 在 MSS1460 下拆 1460+540（S2，`moxa_test.go:219-220` 同值）；`MaxBlockBytes=2048` 为合法上界；2048 精确边界今日无例 → A′ 补例（§13）。
- **方向**：`direction` 缺省 = up；非法值拒绝（E-T2）；纯 down 单块 / 纯 up 多块今日无例 → A′ 补例（§13）。
- **sessions**：`sessions>1` 拒绝；多会话语义只走 `flow_control flows`。
- **地址族**：v4/v6 独立用例；异族混写拒绝（validator 有分支，今日无例 → A′ 补例）。
- **端口**：显式 4800 全正例；缺省 4800（由 `chain_planner.go:1144` 补齐）今日无例 → A′ 补例。
- **`pack_ms`**：字段存在、v1 未实现 → **明确不解决**（G-MOXA-7；策略级 bps 覆盖 95% 用途，旧 §4.5 理由继承）。
- **RST**：框架 tcp 层能力，本层零断言 → A′ 补例（G-MOXA-5）。
- 不得产生回绕长度或超量分配（大块显式声明 2000B，不隐式放大）。

## 9. 原子 ID 与完成定义（13 个唯一语义 ID，顺序为权威）

| # | ID | 类型 | 覆盖 | packet_count |
|---:|---|---|---|---:|
| 1 | `moxa_single_up` | 正 | §3.1：up 单块基线（IPv4） | 8 |
| 2 | `moxa_multi_segment` | 正 | §3.1/§8：2000B 跨段（1460+540） | 9 |
| 3 | `moxa_bidirectional` | 正 | §5：双向四事务交替 | 11 |
| 4 | `moxa_sessions_multi` | 正 | §5：三流展开（flows=3） | 24 |
| 5 | `moxa_binary_payload` | 正 | §3.1：b64 二进制透传 | 8 |
| 6 | `moxa_ipv6` | 正 | §2：IPv6 独立用例 | 8 |
| 7 | `moxa_neg_empty_payload` | 负 | §7：N-1 空块 | — |
| 8 | `moxa_neg_config_packet` | 负 | §7：N-2 探针拒绝 | — |
| 9 | `moxa_neg_sessions_multi` | 负 | §7：N-3 sessions 越界 | — |
| 10 | `moxa_neg_no_handshake` | 负 | §7：N-4 载体违例 | — |
| 11 | `moxa_neg_bad_b64` | 负 | §7：N-5 非法 b64 | — |
| 12 | `moxa_neg_oversize` | 负 | §7：N-6 超限 | — |
| 13 | `moxa_neg_bad_direction` | 负 | §7：N-7 非法方向 | — |

完成定义：`tcp→moxa` 层链注册已落码；块六形态逐块生成验证；方向交替/分段/多流/v4/v6、全部边界可观测；13 ID 正负断言与错误传播完成；不声称串口时序。

## 10. P1 规范矩阵（CORE_MEMORY §4 八项：规范要求→业务场景→代码现状→缺口）

### 10.1 八项规范矩阵

| # | 八项 | 规范要求 | 业务场景 | 代码现状 | 缺口 |
|---|---|---|---|---|---|
| 1 | 连接模型 | TCP Server：主站主动建连，单连接裸字节流（spec §I；旧 §1.1） | 场景①–⑤ | `DependsOn ["tcp"]` 单值（`registry.go:610`）；多会话整块展开（S4） | 无 |
| 2 | 命令/消息表 | 无应用层命令——适配为块方向×终态矩阵（§10.2，15 格逐格结论，NTLM §14.2 适配先例） | 场景①–⑤ | `planner.go` Validate 全分支 + `layer_gen.go` Generate 全分支 | 立项 7 格（A′，§13） |
| 3 | 状态机 | 建连—数据—释放 3 态（§5 表；moxa 层无自有状态，旧 §4.1） | S3 四事务 | tcp 层拥有状态；moxa 纯驱动 | 无 |
| 4 | 字段表 | 块 3 键 + 会话 2 键 + tcp 联动 3 键（§3.1/§3.3；`types.go:741-750`） | 数据场景层 | builder 直传 + 长度/方向/b64 校验 | 无（`pack_ms` 见 G-MOXA-7） |
| 5 | 错误处理 | 7 类负例（§7 表） | 负例 N-1…N-7 | planner 7 种拒绝分支（`planner.go:17-73`） | 无（锚词已钉死 7/7） |
| 6 | 超时与活性 | 串口透传无保活/重试语义（旧 §3.3；长连接静默 keep-alive 不在包级体现） | — | 协议层无（框架 tcp 层能力） | **显式不适用**（§4 声明），无缺口 |
| 7 | NAT/代理/被动 | 无被动模式概念（单连接直连） | S4 三四元组 | `sessions[].src_port` 无（本协议走 `flows` 保底递增） | **显式不适用**被动模式；NAT 穿透为框架面 |
| 8 | 版本/方言 | TCP Server 唯一 profile；Client/UDP/Pair 明确不解决；IPv6 扩展已覆（S6） | 正例 6 | 缺省 4800 已落码（`:1144`） | 出厂默认口实证 → G-MOXA-4 |

### 10.2 子表①：块×终态矩阵（逐格已覆/立项/不适用；适配声明：moxa 无命令—响应码，块形态×传输终态为等价口径）

| 块形态 | T1 正常 FIN 终态 | T2 配置拒绝 | T3 RST 异常终态 |
|---|---|---|---|
| B1 up 单块 | 已覆（S1） | 已覆（N-1/N-5/N-6/N-7 代表例，拒绝与块位置无关） | A′ 立项（G-MOXA-5） |
| B2 up 连续多块 | A′ 立项（补例 `moxa_up_multi`） | 同上代表已覆 | A′ 立项（G-MOXA-5） |
| B3 down 单块 | A′ 立项（补例 `moxa_down_only`） | 同上代表已覆 | A′ 立项（G-MOXA-5） |
| B4 双向交替 | 已覆（S3） | 已覆（N-7 方向违例即本行） | A′ 立项（G-MOXA-5） |
| B5 超 MSS 块 | 已覆（S2） | 已覆（N-6 超限即本行） | A′ 立项（G-MOXA-5） |

**逐格重数**：5 行 × 3 列 = 15 格——已覆 8 / A′ 立项 7，零空格。

### 10.3 子表②：数据形态变体表（协议相关全部形态逐项）

共 **20 行**，每行均有正例/负例落点或立项/不适用结论：

| # | 变体 | 落点 |
|---:|---|---|
| 1 | 空 stream | 覆（N-1） |
| 2 | 空 payload 串 | 覆（N-1） |
| 3 | `payload_b64` 合法 | 覆（S5） |
| 4 | 非法 base64 | 覆（N-5） |
| 5 | 单块 >2048 | 覆（N-6，3000B） |
| 6 | 单块 =2048 精确边界 | A′ 立项（补例 `moxa_block_max`，先跑后钉段数） |
| 7 | 单块 >MSS 且 ≤2048 | 覆（S2，2000B） |
| 8 | MSS=536 短块多段 | 覆（S3） |
| 9 | 非法 direction | 覆（N-7） |
| 10 | direction 缺省（=up） | 覆（S1） |
| 11 | sessions>1 | 覆（N-3） |
| 12 | sessions 缺省（=1） | 覆（全正例） |
| 13 | handshake=false | 覆（N-4） |
| 14 | dst_port 显式 4800 | 覆（全正例断言 `tcp.dstport=4800`） |
| 15 | dst_port 缺省（补齐 4800） | A′ 立项（补例 `moxa_default_port`：删 `dst_port` 不设断言值，只断言补齐行为） |
| 16 | 异族地址混写 | A′ 立项（补例 `moxa_neg_mixed_family`；validator 有分支，今日无例） |
| 17 | 非法 IP 字面 | A′ 立项（并入 #16 同例第二形状；validator 有分支，今日无例） |
| 18 | 配置探针前缀（`0x5a`×3） | 覆（N-2） |
| 19 | `pack_ms` 非零 | **明确不适用**（v1 未实现，G-MOXA-7；用例不得携带该键） |
| 20 | IPv6 载体 | 覆（S6） |

15 覆 + 4 立项 + 1 不适用 = 20。✓

### 10.4 子表③：商业行为→用例映射表

| # | 商业行为（出处） | 用例映射 | 结论 |
|---:|---|---|---|
| 1 | 点对点轮询（spec §I TCP Server；旧 §1.6） | S3 `moxa_bidirectional` | 已覆 |
| 2 | 多串口并发（NPort 多口型号；旧 §4.3） | S4 `moxa_sessions_multi` | 已覆 |
| 3 | 二进制仪表透传（RS-485 仪表；旧 §1.6） | S5 `moxa_binary_payload` | 已覆 |
| 4 | IPv6 产线（新产线网段；旧 §1.6） | S6 `moxa_ipv6` | 已覆 |
| 5 | TCP Client 模式（NPort 主动外连） | — | **明确不解决**（v1 范围外） |
| 6 | UDP 模式（无连接数据报） | — | **明确不解决**（v1 范围外） |
| 7 | Pair Connection（串口线延长） | — | **明确不解决**（v1 范围外） |
| 8 | UDP 4800 配置管理（设备搜索/参数读写） | N-2（身份区分侧） | 待确认（G-MOXA-4/G-MOXA-6：字节未核实前只做拒绝面） |

4 覆 + 3 不适用 + 1 待确认 = 8。✓无映射无确认即缺口——本表零缺口。

### 10.5 三路对照与候选方案对比（§4.12–4.15 / §4.17）

三路：①规范原文（Moxa datasheet operation modes，定"必须是什么"：TCP Server 主站建连透明传）；②商业化软件实际行为（NPort 设备：固件合并/拆包自由、无段边界契约——旧 §4.6 divergence 表继承；出厂默认口待确认 G-MOXA-4）；③可靠开源实现思路（本仓库同族先例：enip/modbus/doip 的"TCP 终结层 + 事件流 + flat 键直传"，只借鉴思路）。三路一致点：透明透传 = 纯 TCP + 裸字节 + 事件多段；不一致点 = 默认端口号（取舍：以 planner 缺省实现为准，用例显式写端口不断言"出厂"）。

| 方案 | 走法（借鉴来源） | 取舍 | 结论 |
|---|---|---|---|
| A | 独立 `moxa` 终结层（本版；enip/modbus 同构先例） | 段数/方向/结构配置/块级校验四事可声明可断言；代价 = 一套薄层（已落码 794 行） | **采用** |
| B | 直接 tcp 层 + 顶层 payload（旧 §1.5 反对意见） | 单段单向、无块级校验 → S3/S4/负例 7 条不可表达 | **否决**（§1.5 对照表逐项） |
| C | 与 modbus 合并为"串口族"（同为 RS-485 透传） | modbus 有应用层帧（功能码/事务），moxa 无帧——文法不兼容，合并即错 | **否决** |

## 11. P2 D-MOXA-1 代码设计（CORE_MEMORY §8 八要素；门1 获批 = 定稿）

> 状态说明：实现已落码（`internal/protocol/moxa/` 四文件），本 P2 条目为 P-PIPE 文档轨对既有实现的**逆向定稿**（as-built 定稿），供门1 批准后作为后续改动的唯一入口；P4 在本协议内为"缺口收敛"（§14），不另开新层。

### 11.1 文件清单（实测，非计划）

| 文件 | 职责 | 行数 |
|---|---|---:|
| `trafficgen/internal/core/types.go`（§741-750 + `:1690`） | `MOXAConfig/Stream/Pack/Sessions` 配置类型 + `FlowSpec.MOXA` 槽位 | —（共享文件） |
| `trafficgen/internal/protocol/moxa/planner.go` | `Planner.Validate`（7 种拒绝）+ `Plan`（握手→分段→挥手） | 143 |
| `trafficgen/internal/protocol/moxa/layer_gen.go` | 终结层生成器（`RegisterLayerGenerator("moxa")` + validator 注册，`init()`） | 87 |
| `trafficgen/internal/protocol/moxa/types.go` | 类型别名 + `MaxBlockBytes=2048` | 8 |
| `trafficgen/internal/protocol/moxa/moxa_test.go` | 33 个 `Test*`（Validate 拒绝面 + Plan 包数面 + 生成器面） | 556 |
| 接线 5 件 | registry 注册（`layers/registry.go:610`）/ translate Meta 直传（`chain_planner_translate.go:119`）/ convert 子配置搬运（`strategy_convert.go:1421-1423`）/ protocols 准入（`protocols.go:44`）/ validateSpecBase 端口开关（`chain_planner.go:881/:1144`） | — |

### 11.2 接口签名

- `Validate(spec core.FlowSpec) error`（`planner.go:17`）：`MOXA==nil` 通过（空配置默认流）；`Sessions>1`、`handshake=false`、IP 非法/异族、空块、非法方向、非法 b64、超限、探针前缀各归一分支，错误文案与 §7 锚词逐字一致。
- `Plan(ctx, spec) (<-chan core.PacketConfig, error)`（`planner.go:75`）：先 Validate；`DstPort==0` 补 4800；空 stream 补默认块；按 mss 切片 emit（SYN/SYN-ACK/ACK → 数据段 → FIN 四包）。
- 生成器：`Name() "moxa"`；`GenEvents()` 事件生成器；`EmitEvent` 未接线显式错（防误调）；`Generate` 逐块校验 + emit（`layer_gen.go:19-73`）。

### 11.3 数据结构

`MOXAConfig{Stream[], Pack, Sessions}`；`MOXAStreamBlock{Direction, Payload, PayloadB64}`（`types.go:741-750` 全量，无新增）。

### 11.4 主流程

配置 → validator（块级 7 分支 + 载体 2 分支）→ planner（事件展开为段序列，按 mss 切片）→ worker（TCP 分段：默认每块一段，>MSS 自动分段；多流按 `flows` 复制四元组递增）→ writer（PCAP/NIC）。

### 11.5 错误分支

7 种 validator 拒绝各对应 planner/生成器双层守卫（§7 表）；全部传 task error（零假成功——N 系列守卫）。`pack_ms` 非零今日**不拒绝亦不生效**（G-MOXA-7：用例不得携带）。

### 11.6 性能边界

见 §6（逐块流式、per-flow 局部状态、无跨流共享、无锁；吞吐数字待 P4 基准）。

### 11.7 与现有逻辑的冲突点

- `CheckProtoFlat`（`strategy_convert.go:8322` 起）**无 moxa 分支**（`grep -c 'protocol == "moxa"'` = 0 实测）：顶层 `moxa` 子映射 presence 不判死——与 D-NTLM-1 等已登记协议不同，属缺口 G-MOXA-2（禁加单协议黑名单分支，等框架级 unknown-key 白名单；kingbase 记忆裁定）。
- 动态 allowlist（`internal/core/layer_dyn.go` 头部）：`moxa` 零命中实测 → 业务字段动态对象即拒；四元组 `ip`/`tcp` 全开。见 §12.12。
- registry `moxa` Fields 为空（生成表 `fields: {}` 实测）→ 层内 `stream` 键无处可住，目标形状（§2）需 P4 补 Fields + translate 分支（G-MOXA-1）。

### 11.8 回滚方式

本协议文件独立成包，回滚 = revert 本协议 4 文件 + 接线 5 处（registry/protocols/translate/convert/chain_planner）；不触及其他协议。cases 回滚 = 恢复 13 例 JSON（产物文件，非文档）。

## 12. 门1 §1–§14 十四行对照表（CORE_MEMORY §15.1–15.3）

| § | 本协议怎么满足 | 证据 |
|---|---|---|
| §1 层链唯一真相 | 见 §12.1 强制展开：存量 13/13 顶层 = `layers + src_ip/dst_ip/dst_port + moxa`（旧扁平残留，P4 迁移 G-MOXA-1）；目标形状见 §2 样例；presence 判死形状缺口 G-MOXA-2 | §12.1；`cases/moxa.json` 机读实测 |
| §2 策略/任务 | 策略 = 单 moxa 流量模板，自带 `flow_control`；任务 = 多策略合跑 + 总量封顶；框架语义未动 | 设计 §2 样例 |
| §3 五件套 | 见 §12.3 强制展开：会话表/事务序列/关联（无派生流诚实声明）/插入位置（终结层）/时间线。有长连接，不豁免 | §12.3 + §5 |
| §4 查规范 | datasheet modes + 旧基线 + tshark 零 dissector 实测 + 落码反推；八项矩阵 + 子表①②③ | §10 |
| §5 依赖与错误 | `DependsOn ["tcp"]` 单值（`registry.go:610`）；7 种拒绝分支；失败传 task error | §5/§7/§11.5 |
| §6 性能 | 见 §6（6.1–6.8 要素齐；吞吐数字标待 P4 基准，不写承诺） | §6 |
| §7 三份文档 | `92-moxa-{design,testcase}.md` v1.0.0（草稿层）+ D-MOXA-1（§11，门1 获批 = 定稿）+ T-MOXA（testcase §2，13 ID）+ 旧稿 27-* 为历史层 | 修订记录 |
| §8 设计先行 | P1–P3 先于 P4 缺口收敛；门1 获批 = D-MOXA-1 定稿 = 开工门 | 提交序 |
| §9 测试三源 | 三源 = datasheet modes（§10）+ D-MOXA-1（§11）+ tshark 通道实测（替代"已确认现网行为"档，未到抓包级 → G-MOXA-4，不冒充第三源）；13 ID 逐项回指；存量 13 例审计去向 testcase §8 | `92-moxa-testcase.md` §2/§5/§8 |
| §10 评审闭环 | 每阶段对抗自重审（结论见 p123 报告 §2）+ 收官隔离复审；红先绿后 | p123 报告 §2 |
| §11 白话 | 每阶段白话一句先行（见本文首节） | 汇报 |
| §12 动态清单 | 见 §12.12 强制展开：四元组全开（allowlist 实测）；业务字段逐个列开/不开 + 理由；序号算法实读行号 | §12.12 |
| §13 schema 派生 | `moxa` 已在 `registry.go:610` 注册（**不新增层**）；`allowedProtocols["moxa"]=true`（`protocols.go:44`）；Meta 已直传；**P4 补 registry Fields 必须重跑 schemagen** | §11.1 |
| §14 真实流程 | suite 经 MCP 建策略建任务 → 引擎真实生成 → tshark `tcp.*` + frames 双通道 → 先跑后钉；pcap 落 `/tmp/mcp-pcaps/moxa/` | testcase §7 |

### 12.1 §1 强制展开：旧键去向 + 完整 spec_json 样例

**存量实测（逐例机读，2026-09-27）**：

| 文件 | 例数 | 顶层键分布 | 链形 | 负例 expect 纯净 |
|---|---|---|---|---|
| `cases/moxa.json` | 13 | `{layers, src_ip, dst_ip, dst_port, moxa}` ×11 + 同形+`strategy_fc` ×1（S4）+ 同形+顶层 `tcp` ×1（N-4） | `[tcp,moxa]` ×13（S2/S3 带 `mss`；N-4 带 `handshake:false`） | ✅ 7/7 只有 `{expect_error,error_contains}` |

**旧键去向表（§15.3 要求"每个键写去向"）**：

| 旧键 | 存量出现例数 | 去向 |
|---|---:|---|
| `src_ip` | **13** | 迁 `layers[i].ip.src`（G-MOXA-1） |
| `dst_ip` | **13** | 迁 `layers[i].ip.dst` |
| `src_port` | **0** | 本已 absent（保底 `12345+i`）；目标形按需迁 `layers[i].tcp.src_port` |
| `dst_port` | **13** | 迁 `layers[i].tcp.dst_port`；**或删**（由 4800 缺省补齐，A′ `moxa_default_port` 验证） |
| `count` | **0** | 走 `flow_control`（S4 已用 `strategy_fc` 过渡形，P4 转正） |
| 顶层 `moxa` 子映射 | **13** | **迁 `layers[i].moxa`**（须先补 registry `Fields`，G-MOXA-1） |
| 顶层 `tcp` 子映射（N-4） | **1** | **迁 `layers[i].tcp`**（同上） |

**结论**：本协议有实质迁移工作量——§1 门的动作 = ①补 registry `Fields`（stream/direction/payload/payload_b64/sessions）；②加 translate 分支（层内 moxa→`spec.MOXA`）；③13 例整体改写；④新增 6 A′ 例全部纯 layers 形；⑤收官自查行「非负例顶层键 = 0」由 **5 键 → 0**。

目标形状样例见 §2（顶层仅 `layers`+`flow_control`）。

### 12-P2 判死负例形状（链级红例必含清单①③④）

- ① presence 形状 `{"layers":[…],"moxa":{}}` 今日**不会被拒**（`CheckProtoFlat` 无 moxa 分支，`grep -c` = 0 实测）→ **P4 不建该负例**（建了会真绿 = 假通过）→ 缺口 G-MOXA-2 登记。② 白名单外游离键判死（`unknown field`）P4 建一条（A′）。③ 7 负例每条带锚词（已齐，§7）。④ 收官自查「非负例顶层键 = 0」（P4 迁移后执行）。

### 12.3 §3 强制展开：五件套

会话表：`s1` 单连接基线（S1/S2/S5/S6，各自四元组，SYN→数据→FIN 四包挥手）/ `s2` 双向会话（S3，四事务交替）/ `s3` 多流三会话（S4，`flows=3`，`src_port` 12345/12346/12347）。事务：`t1` 建连（握手，tcp 层）/ `t2` 发块（up 事件）/ `t3` 收块（down 事件，端口对换）/ `t4` 终止（FIN；RST 为 A′）；每事务四件事（前置/触发/成功/失败）见 §5 状态机 + §4 场景表。关联关系：**无派生流**（诚实声明：单 TCP 连接承载全部块，无 `driven_by`；CancelRequest 类关联不适用）。插入位置：终结层（`[ip,tcp,moxa]`，无中间层）。时间线：块内严格顺序 / 多流顺序展开（S4 整块 per-flow，跨流不假设全局包序，只断言聚合）/ 无交错（`concurrent` 为例外路径不启用）。

### 12.12 §12 强制展开：动态字段清单与序号算法

四元组 `ip.src/dst`、`tcp.src_port/dst_port` 五策略全开（allowlist `internal/core/layer_dyn.go` 头部四行实测：`ip`/`tcp`/`udp`/`eth`；保底 `DefaultSrcPort+i`（`strategy_convert.go:49`）；dst 动态与 4800 缺省和平共处——显式/动态值非零即不触发补齐）。

**业务字段 5 项全关**（allowlist 无 `moxa` 行，`grep` 零命中实测；对象即拒）：`stream[]`（会话剧本）/ `direction`（会话内结构）/ `payload`·`payload_b64`（剧本载荷）/ `sessions`（结构选择器）/ `pack_ms`（未实现键）——逐流变体需求列 A′ 候选（testcase §6.2；今日按 §9.36 口径不冒充覆盖）。

序号算法实读：`parseLayerDyn`（`layer_dyn.go:78`）/ `TupleGenerator.Next`（`tuple_generator.go`）/ 保底自增（`strategy_convert.go:49` + worker 注入）/ allowlist 白名单（`layer_dyn.go` 头部）——**`moxa` 无块**（grep 实测零命中），即层内任何对象值 → `does not support dynamic`。

## 13. P3 对接清单（T-MOXA 草稿输入；正文落 testcase 文件）

13 ID（6 正 + 7 负）+ packet_count/锚词 + fixture 常量 + 双通道断言基线 + 存量审计（testcase §2–§5/§8 全量）。A′ 候选 6 例：`moxa_up_multi`（B2）/ `moxa_down_only`（B3）/ `moxa_block_max`（变体 6）/ `moxa_default_port`（变体 15）/ `moxa_neg_mixed_family`（变体 16+17）/ `moxa_abort_rst`（G-MOXA-5）。

## 14. 缺口立项清单（有缺口写「缺口立项」，不许空着）

| 缺口 | 内容 | 去向 |
|---|---|---|
| G-MOXA-1 | registry `moxa` Fields 为空 + 无 translate 层内分支 → 顶层 `moxa`/`tcp` 子映射迁层内 + 13 例改写 + schemagen 重跑 | P4 首动作；收官「非负例顶层键=0」 |
| G-MOXA-2 | `CheckProtoFlat` 无 moxa 分支 → presence 形今日不判死 | P4 先实测再建例；**禁加单协议黑名单分支**（等框架级 unknown-key 白名单） |
| G-MOXA-3 | 业务字段动态全关（allowlist 无 `moxa` 行） | A′ 候选，不冒充已覆盖（§9.36 口径） |
| G-MOXA-4 | 出厂默认口（TCP 4800）/ UDP 4800 配置口说法未达验证级 | 待确认：查 Moxa 官方手册对应型号章节，或抓现网 NPort 包（三选一已写清）；确认前不写死进实现 |
| G-MOXA-5 | RST 非正常结束补例（§3.15②后半） | A′ 补例 `moxa_abort_rst`（`tcp.rst` 框架能力，本层零断言） |
| G-MOXA-6 | N-2 探针前缀（`0x5a`×3）待配置协议字节核定后收窄 | 配置面资料到位后收窄拒绝面；修订触发 |
| G-MOXA-7 | `pack_ms` 字段存在但 v1 未实现 | **明确不解决** + 迁入计划（实现则补驱动/用例，不实现则 P4 删键裁定；用例今日不得携带） |

## 15. 修订记录

- v1.0.0（2026-09-27）：P-PIPE #92 文档轨 P1–P3。RESUME 续写：27→92 沿革与 7 项过期校正（§0）；存量 13 例机读审计（顶层残留形状、expect 形状、ID 顺序一致）；§12.1/12.3/12.12 强制展开 + 12-P2；D-MOXA-1 as-built 定稿（§11）；缺口 G-MOXA-1…G-MOXA-7。P1 自审 2 轮 / P2 自审 2 轮 / P3 自审 2 轮，末轮干净（结论见 p123 报告 §2）。
