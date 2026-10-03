# IEC 60870-5-104（IEC104，电力远动）设计契约

> 版本：v1.0.0（79 车道 P1–P3 产物）
> 日期：2026-09-26
> 状态：P1 八项规范矩阵（§11）+ 三子表 + 三路对照与候选方案对比（§12）+ 依赖/性能（§13）+ 八要素/动态字段（§14）+ 门1对照与缺口迁入（§15）已落盘；**`iec104` 层已注册，builder/planner/层生成器及 chain translate 已落码，当前仅保留 G-IEC104-9 的 suite/pcap 校准工作；存量已迁移为层链形，新增链级负例覆盖结构门**——本文件只记录静态设计与代码现状，不宣称当前 suite、PCAP 或 NIC 验证已完成。本契约不修改 Go 实现。
> 配套文件：`docs/protocol-designs/79-iec104-testcase.md`、`trafficgen/test/protocol_pcap/cases/iec104.json`（21 例（12 正 + 9 负）层链形，P4 已按层链去向表改写）
> 规范基线：IEC 60870-5-104（公开帧定义；精确章节号待 G-IEC104-1 对原文复核，本契约只引用标准名不编章节号）+ tshark 3.6.14 dissector 实测 + 已落码 builder wire 真相。现有静态证据不等同于 suite、PCAP 或 NIC 验证。
> 与 22- 基线关系：`22-iec104-design/testcase.md`（v1.0.0，2026-08-18）作为历史参考；其中 §4.3（k/w 窗口）、§4.7（poll 模板）、§5.2（k/w/send_seq/recv_seq/auto_s_ack/close_mode/allow_peer_startdt）、§5.3（originator）、§5.5（COT/originator 编码）描述的配置面**均未落码**（`IEC104Config` 实测见 §1），以本件 P1 矩阵与 §8 为准；§3 线格式与 §3.6 HexDump 的字节结论采用（I 帧_hex_按 §4 注记待 P5 落盘校准，U 帧 6 条已由落盘 pcap 实证）。

## 1. 范围、证据等级和已注册边界

本阶段将 iec104 严格限定为 **TCP 2404 单载体终结层**：APCI 三帧型（I/S/U）+ 8 类 ASDU（TypeID 1、3、9、30、34、45、59、100）+ STARTDT/STOPDT/TESTFR 显式事件。不把任意 TCP payload 标成 iec104。

**已注册/已落码现状（P1 实测，行号真实）**：

| 件 | 位置 | 内容 |
|---|---|---|
| 层注册 | `registry.go:1100` | `Name "iec104"`，`CategoryTerminal`，`DependsOn ["tcp"]`，`FieldContract {"tcp.dst_port":"2404"}`，17 个层字段（transport/common_address/events/commands/type_id/cause/ioa/value/siq/qds/diq/sco/dco/qoi/select/time/max_apdu_length） |
| 配置结构 | `types.go:143/167/185` | `IEC104Config`（Transport/Role/CommonAddress/StartDT/StopDT/Events/Commands/TypeID/Cause/IOA/Value/SIQ/QDS/DIQ/SCO/DCO/QOI/Select/Time/MaxAPDULength/Repeat）+ `IEC104Event`（Direction/Kind/TypeID/Cause/IOA/Value/RX/SIQ/QDS/DIQ/SCO/DCO/QOI/Select/Time）+ `IEC104Command`（TypeID/Cause/CommonAddress/IOA/Value） |
| wire 编码 | `internal/protocol/iec104/builder.go` | `BuildUFrame`（:9）/`BuildSFrame`（:18）/`BuildInformation`（:27）/`buildASDU`（:45）/`encodeCP56Time2a`（:107）/`validType`（:126，8 白名单） |
| 校验+规划 | `internal/protocol/iec104/planner.go` | `Planner.Validate`（:13，10 锚词行见 §9）/`Plan`（:58，legacy flat 路径） |
| 层生成器 | `internal/protocol/iec104/layer_gen.go` | `Generate`（:15，events 路逐事件序号 :34–52；commands 默认路 :56–88）+ `init` 注册 generator/validator（:127–129） |
| 子配置解析 | `chain_planner_translate.go:3301-3329` | `case "iec104"` 使用 JSON `DisallowUnknownFields` 严格解码；未知字段在层校验阶段拒绝 |
| Meta 直传 | `chain_planner_translate.go:109` + `generator.go:339` | `IEC104: spec.IEC104` / `FlowMeta.IEC104 *core.IEC104Config`（已接线） |
| 端口契约 | `chain_planner.go:599/1155` | iec104 在 FieldContract 通用化名单内（P0b-1：`tcp.dst_port` 由契约补 2404） |
| 白名单 | `protocols.go:40` + `protocols_test.go:27` | `"iec104"` 已登记 |
| 生成表 | `schemas/v1/generated/layers.generated.json` | `iec104: {terminal, ["tcp"], contract 2404, 17 fields}`（schemagen 已含，P4 只验证无过期） |
| 单测 | `internal/protocol/iec104/iec104_test.go` | 305 行；U/S/I 编码 + 4 否定 kind/type/IOA/length + transport/type/cause + 非法 CP56 时间（2026-09-26 `go test` 全绿实测） |

**当前待办（P1 实测，不美化）**：全量 suite/pcap 校准与 NIC 验收尚未在本轮运行（G-IEC104-9）。静态链路测试已覆盖 `iec104` translate、registry、generator、validator、事件序列、双向序号、presence、端口契约和 UDP 载体拒绝。

不变式：

1. iec104 终结层只能位于 TCP 后；缺 TCP、UDP 载体、显式错端口必须错误（预检 P4 新增，见 §14；planner 现有 `transport` 守卫见 §9）。
2. U 帧只接受 §3.3 六控制字；S 帧只确认不带 ASDU；I 帧 TypeID 只接受 §4 白名单 8 类。
3. `L` 最大 253；ASDU 超长、IOA 越界（>0xffffff）、cause 非法（0 或 >63）必须在 Validate 阶段拒绝。
4. 错误必须传播到 task error 终态，不产生空成功任务（§9）。
5. T3 空闲自动测试、冗余双连接通道切换、IEC 62351 TLS（19998）列为未实现能力并建立 G-IEC104-3/G-IEC104-5 迁入计划（§10）。

## 2. 推荐配置和层链

目标形状（纯 `layers` 形；地址住 `ip` 层、端口住 `tcp` 层、数量走 `flow_control`；顶层只允许 `layers`/`flow_control`/`output`）：

```json
{
  "layers": [
    {"ip": {"src": "10.104.0.1", "dst": "10.104.0.2"}},
    {"tcp": {"src_port": 31001, "dst_port": 2404}},
    {"iec104": {
      "common_address": 1,
      "events": [
        {"direction": "up", "kind": "startdt_act"},
        {"direction": "down", "kind": "startdt_con"},
        {"direction": "up", "kind": "i", "type_id": 1, "cause": 3, "ioa": 1, "siq": 1},
        {"direction": "down", "kind": "s", "rx": 1},
        {"direction": "up", "kind": "stopdt_act"},
        {"direction": "down", "kind": "stopdt_con"}
      ]
    }}
  ],
  "flow_control": {"flows": 1}
}
```

| 配置键 | 住处 | 约束 |
|---|---|---|
| `src`/`dst` | ip 层 | 主站/厂站 fixture；IPv6 地址同住 `ip` 层（ntlm 先例，仓库无 `ipv6` 层） |
| `src_port`/`dst_port` | tcp 层 | dst 正例固定 2404（FieldContract；用例显式写，不依赖默认化）；src 未写动态时保底 `12345+i`（`worker.go:300-307`） |
| `common_address` | iec104 层 | ASDU CA，0..65535；事件缺省继承顶层 CA（`layer_gen.go:93` 取 `cfg.CommonAddress`） |
| `events[]` | iec104 层 | 有序；`kind` 8 值（§8），`direction` up/down；I 帧带 TypeID/Cause/IOA/体字段，S 帧带 `rx`，U 帧仅 kind+direction |
| `commands[]` | iec104 层 | 默认路输入（TypeID/Cause/CA/IOA/Value）；层链正例以 `events[]` 为主，默认路仍为兼容输入 |
| `type_id/cause/ioa/value/siq/qds/diq/sco/dco/qoi/select/time` | iec104 层 | 顶层单对象快捷键（legacy）；目标形中事件内联，顶层残留按 §17 改写时并入事件或删除 |
| `max_apdu_length` | iec104 层 | 仅负例探针（>253 即拒，`planner.go:46`）；不是合法长度声明 |
| `flow_control` | 顶层 | `flows` = 独立 TCP 会话数（strategy_fc 同口径）；`bps/time` 离线不支持 |
| `wire_fault` | — | 本协议无此键；负例走自然非法输入（§9），不伪造 fault 面 |

**存量形状声明（P4 已迁移）**：T-001–T-016 已改为严格层链；T-017–T-021 是新增结构/承载负例。旧扁平地址、端口、协议子映射和 count 不出现在正例；旧字段只在对应失败输入中保留以证明结构门拒绝。

## 3. APCI/APDU 线格式

每个 APDU 从 `0x68` 起始，第二字节为后续长度 `L`（不含前二字节本身）；控制域 4B 低两位区分帧型（`builder.go` 编码真相）：

```text
+--------+--------+----------------------+----------------------+
| 0x68   | L      | 控制域 C[0..3]       | ASDU（仅 I 帧）      |
| 1B     | 1B     | 4B                   | 0..249B              |
+--------+--------+----------------------+----------------------+
```

I 帧（`BuildInformation` :27–43）：`C[0..1] = N(S)<<1` 小端，`C[2..3] = N(R)<<1` 小端；`L = 4 + len(ASDU)`。S 帧（`BuildSFrame` :18–24）：`C = 01 00 + (N(R)<<1)` 小端，无 ASDU，固定 6B。U 帧（`BuildUFrame` :9–16）：低两位 `11`，仅六控制字：

| 语义 | 方向 | 控制域 | 完整 APDU（落盘实证） |
|---|---|---|---|
| STARTDT act | up | `07 00 00 00` | `68 04 07 00 00 00` |
| STARTDT con | down | `0b 00 00 00` | `68 04 0b 00 00 00` |
| STOPDT act | up | `13 00 00 00` | `68 04 13 00 00 00` |
| STOPDT con | down | `23 00 00 00` | `68 04 23 00 00 00` |
| TESTFR act | up | `43 00 00 00` | `68 04 43 00 00 00` |
| TESTFR con | down | `83 00 00 00` | `68 04 83 00 00 00` |

offset 规则：IPv4 无 option 时 `14 + 20 + 20 = 54`；IPv6 无扩展头时 `14 + 40 + 20 = 74`；同一帧内 TypeID=APDU+6、VSQ+7、COT+8、CA+10、IOA+12。**TCP 分段面 = 不适用**：MSS 下限 536（`chain_planner.go`）> APDU 上限 253，单 APDU 永不触发分段；多 APDU 同段为 TCP 行为，不断言（3.14 审计见 testcase §9.4）。

## 4. ASDU 与 TypeID 白名单

ASDU 前缀（`buildASDU` :45–104 实测）：`TypeID(1) | VSQ=1(1，恒定：SQ=0、对象数=1) | COT=cause(1) | OA=0(1，恒定：originator 未建模) | CA(2，小端) | IOA(3，小端)`，后接信息体：

| TypeID | 名称 | 信息体（不含 IOA） | 方向 | 线约束 |
|---|---|---|---|---|
| 1 | M_SP_NA_1 单点信息 | 1B SIQ（bit0=SPI） | down | P01/P02/P10 |
| 3 | M_DP_NA_1 双点信息 | 1B DIQ（bit0-1=DPI） | down | P11（IPv6） |
| 9 | M_ME_NA_1 归一化测量 | 2B NVA 小端 + 1B QDS | down | P03（`34 12`=0x1234 小端） |
| 30 | M_SP_TB_1 带时标单点 | 1B SIQ + 7B CP56Time2a | down | P05 |
| 34 | M_ME_TD_1 带时标归一化 | 2B NVA + 1B QDS + 7B CP56Time2a | down | P04 |
| 45 | C_SC_NA_1 单点命令 | 1B SCO（bit0=值，bit7=SE；`select` 置 SE，`layer_gen.go:93` 透传） | up（con down） | P06（COT 6/7） |
| 59 | C_DC_TA_1 带时标双点命令 | 1B DCO + 7B CP56Time2a | up（con down） | P07 |
| 100 | C_IC_NA_1 总召唤 | 1B QOI | up | P02/P09（QOI=20） |

CP56Time2a（`encodeCP56Time2a` :107–124）：空串 → 7 零字节；否则 RFC3339Nano 解析（毫秒小端 + 分/时/日/月/年 + 星期位），非法 → `invalid CP56Time2a time`（单测已覆，cases 负例缺 → A′ T-18）。**已核验 Hex（U 帧 6 条由 `/tmp/mcp-pcaps/iec104/iec104_u_frames.pcap` 实证；I 帧行为 builder 真值推导，P5 落盘校准）**：见 testcase §3；长度式 `L = 4 + 6 + 3 + 体宽`（如 Type1 单对象 `L=14`）。

## 5. 状态机（as-built 诚实版）

```
TCP_ESTABLISHED -- up STARTDT act --> START_SENT -- down STARTDT con --> DATA_TRANSFER
DATA_TRANSFER -- up/down I/S, up TESTFR act, up STOPDT act --> DATA_TRANSFER / STOPPING
STOPPING -- down STOPDT con --> CLOSED --> TCP FIN/RST
```

as-built 语义（`layer_gen.go:15-88` 实测）：`events[]` 非空 → 逐事件按 `direction != "down"` 定上下行，up/down 各自 `N(S)` 从 0 递增（:34–52），`N(R)` 取对向已收数；`events` 为空 → 默认路（STARTDT 对 + `commands[]`，空则单条 M_SP，:56–88；注意默认路每命令**上下行各发一份相同字节**，legacy 语义）。**未实现的状态强制（→ G-IEC104-3）**：STARTDT 前 I 帧不拒；S `rx` 与 `recv_seq` 不核对；k/w 窗口无（`k/w/send_seq/recv_seq/auto_s_ack/close_mode/allow_peer_startdt` 等 22- 基线 §4–§5 键在 `IEC104Config` 中不存在）；STOPDT 后事件不拒；序号按 `uint16` 自然回绕（非 mod 32768，注记）。

## 6. 包序列场景（T-001–T-012）

除特别说明外均为 IPv4、`dst_port=2404`、TCP 握手（3 包）+ FIN 挥手（4 包）；公式 `包数 = 3 + 事件数 + 4`（P1 逐例验算，见 testcase §3）：T-001 STARTDT+单点遥信（E=6，13 包）；T-002 三轮总召唤（E=13，20 包）；T-003 类型 9（13 包）；T-004 类型 34（13 包）；T-005 类型 30（13 包）；T-006 单点命令选/执（E=7，14 包）；T-007 双点时标命令（14 包）；T-008 U 序列六帧（13 包）；T-009 S 确认（E=7，14 包）；T-010 突发上送 COT=3 + up S（13 包）；T-011 IPv6（offset 74，13 包）；T-012 三会话扇出（`strategy_fc flows=3`，min 39 包，端口聚合，不锁交织包号）。

## 7. 21 个语义场景与包数映射

设计、测试契约和 JSON 按**同一顺序**使用 21 个唯一 ID（T 编号为本件权威）：T-001–T-012 为 12 个正例；T-013–T-021 为 9 个负例，具体输入与锚词见 testcase §4。包数值 P5 全量重跑校准（G-IEC104-9），不照抄旧期望之外的算法则；U 帧已实证。

## 8. Validate 规则（as-built）

`Planner.Validate`（`planner.go:13-57`）逐条：`spec.IEC104 == nil` → 通过（P0b-2 默认流）；`transport` 非空且非 `tcp` → 拒；顶层 `type_id != 0` 且非白名单 → `invalid type`；`cause > 63` 或（`type_id != 0` 且 `cause == 0`）→ `invalid cause`；事件 `kind` 非 8 值（startdt_act/con、stopdt_act/con、testfr_act/con、s、i）→ `invalid control event kind`；I 事件 TypeID 非白名单 → `unknown type_id`；I 事件 cause 非法 → `invalid cause`；I 事件 `IOA > 0xffffff` → `IOA … exceeds 24-bit range`；`max_apdu_length > 253` → `APDU too long`；commands 的 type/cause 同顶层规则。**幽灵键（JSON 可写、零消费，`parseSubconfigJSON` 无严格解码故静默通过）**：顶层 `role/startdt/stopdt/poll{request,response}/testfr/originator`、事件内 `control/repeat`（neg 探针形：锚词实际来自 kind/max_apdu_length 守卫，键本身未读）、顶层 `value` 负值/>65535（`uint16(cfg.Value)` 截断，无守卫 → G-IEC104-8）、事件 `direction` 非法值（按 up 处理 → G-IEC104-4）、`rx` 越界仅 builder 拒（>32767）。

## 9. 错误处理

| ID | 故障输入 | `error_contains` | 代码锚点（实测） |
|---|---|---|---|
| T-013 | 非法 kind（`u` + control 形） | `control` | `planner.go:31`（`invalid control event kind`；U 白名单 `builder.go:13` 同源） |
| T-014 | TypeID=250 | `unknown type_id` | `planner.go:35` |
| T-015 | `max_apdu_length=254`（>253） | `APDU too long` | `planner.go:46` |
| T-016 | IOA=16777216 | `IOA` | `planner.go:41`（builder `:53` 同源） |

自然守卫（单测已覆，cases 未单列）：`transport≠tcp`（:20）、顶层非法 type/cause（:24/:27）、S `rx>32767`（`builder.go:20`）、非法 CP56 时间（`builder.go:113` → A′ T-18）、commands 非法 type/cause（:50/:53）。全部经 API→engine→task 传播为 task error，零假成功；负例 `expect` 严格只有 `expect_error` + `error_contains`。

## 10. 扩展字段映射

v1 只实现 §4 白名单；以下一律 `unknown type_id`/未建模，扩展须新增独立 TypeID + 体宽 + 方向/COT + 负例：M_ME_NB_1/NC_1（标度/浮点）、M_ST_NA_1（步位置）、M_IT_NA_1（累积量 BCR）、C_SE 系列（设点）、C_RC（步调节）、CP24Time2a 带时标体、SQ=1 连续地址压缩（显式拒绝）、多对象 VSQ>1（VSQ 恒 1）、C_CS_NA_1 对时（→ G-IEC104-5）、IEC 62351 TLS（19998，`optional_on` 预留）、冗余双连接切换语义。

## 11. P1 规范矩阵（CORE_MEMORY §4 八项：规范要求→业务场景→代码现状→缺口）

> 深度口径（CORE_MEMORY §4.19–4.22）：三张子表——①帧型×方向矩阵（§11.2，15 行 × 2 列 = 30 格）②数据形态变体表（§11.3，14 行）③商业行为→用例映射表（§15.1）。条目三选一：已覆 / B′（G 立项）/ 不适用 + 对应用例号；无遗漏留白。

### 11.1 八项规范矩阵

| # | 规范要求（IEC 60870-5-104 + 本契约节） | 业务场景 | 代码现状 | 缺口 |
|---|---|---|---|---|
| 1 | 连接模型：单 TCP 连接（2404），控制站主动建连；STARTDT 激活后传 I 帧；STOPDT 可选停止；TCP FIN/RST 关闭（§1/§5） | 调度主站—厂站 RTU 点对点；多厂站多连接 | 已落码：registry tcp 载体 + 契约端口；layer 生成器事件序；legacy Plan 握手/挥手 | chain 接线 → G-IEC104-9；k/w/重连面 → G-IEC104-3 |
| 2 | 命令消息表：U 六控制字 + S 确认 + I 八 ASDU（§3/§4） | 启动/停止/测试/总召唤/遥信/遥测/遥控 | 已落码：builder 全帧型 + 8 TypeID 体 | 子表① 30 格：覆 18 / B′ 11 / 不适用 1 |
| 3 | 状态机：STARTDT→DATA→STOPDT；N(S)/N(R) 15bit；S 确认；TESTFR 保活显式（§5） | 激活会话；序号连续；链路测试 | 已落码：事件序 + 双向序号计数（`layer_gen.go:34-52`） | 强制面（序/rx/窗口/STOPDT 后）→ G-IEC104-3 |
| 4 | 字段表：68/L/控制域小端/CA/IOA/NVA/SIQ/DIQ/SCO/DCO/QOI/CP56Time2a（§3/§4） | 开关/电流电压/命令/时标 | 已落码：小端全域 + CP56 编解码 | 子表② 14 行：覆 11 / B′ 3；value 截断 → G-IEC104-8 |
| 5 | 错误处理：非法 kind/未知 Type/超长/IOA 越界/transport（§8/§9） | 脏配置、越界输入一律 task error | 已落码：4 cases 锚词 + 自然守卫 | direction/QOI/OA/长度实算 → G-IEC104-4；幽灵键 → G-IEC104-2 |
| 6 | 超时活性：T0/T1/T2/T3 语义；v1 无运行时计时器，TESTFR 显式事件（§1/§5） | 长在线链路测试 | 显式 TESTFR 对（T-008） | T3 自动 → 明确不支持（非缺口，显式声明） |
| 7 | NAT/代理：无专属语义；NAT 只影响 TCP/IP 寻址，APDU 字节不变 | NAT 后厂站上送 | 不适用（显式声明）：无 iec104 层语义可测，无用例 | 无缺口（显式不适用 ≠ 缺口） |
| 8 | 版本方言：单版本；厂商私有用 TypeID 不收；VLAN/双栈由承载层表达 | 新建 IPv6 站；VLAN 隔离厂站 | 白名单 8 + 未知拒；IPv6 同住 ip 层（T-011） | IPv6 多流对称 → A′ T-17；扩展 Type → G-IEC104-5 |

### 11.2 子表①：帧型×方向矩阵（15 行 × 2 列 = 30 格，逐格有结论）

| 帧 \ 方向 | up | down |
|---|---|---|
| STARTDT act | 覆 T-001 | B′（被控站主动面 → G-IEC104-3） |
| STARTDT con | B′（同上） | 覆 T-001 |
| STOPDT act | 覆 T-001 | B′（同上） |
| STOPDT con | B′（同上） | 覆 T-001 |
| TESTFR act | 覆 T-008 | B′（同上） |
| TESTFR con | B′（同上） | 覆 T-008 |
| S | 覆 T-001/T-002/T-009 | 覆 T-001 |
| I T1 M_SP | B′（方向约束未强制 → G-IEC104-4） | 覆 T-001/T-010 |
| I T3 M_DP | B′（同上） | 覆 T-011 |
| I T9 M_ME | B′（同上） | 覆 T-003 |
| I T30 M_SP_TB | B′（同上） | 覆 T-005 |
| I T34 M_ME_TD | B′（同上） | 覆 T-004 |
| I T45 C_SC | 覆 T-006 | 覆 T-006（ActCon） |
| I T59 C_DC | 覆 T-007 | 覆 T-007（ActCon） |
| I T100 C_IC | 覆 T-002 | 不适用（C_IC 无 down 语义，显式声明） |

**逐格重数**：覆 18（U 6 + S 2 + I down 7 + I up 3）+ B′ 11（U 对向 6 + M_* up 5）+ 不适用 1 = 30 ✓。

### 11.3 子表②：数据形态变体表（14 行）

| # | 变体 | 对应用例 | 备注 |
|---|---|---|---|
| 1 | U 固定 6B（L=4） | T-008（apdulen=4 断言） | 覆 |
| 2 | S 固定 6B，N(R)<<1 小端 | T-001/T-009（`68 04 01 00 02 00`） | 覆 |
| 3 | I 变长 `L=4+ASDU` | T-001（L=0x0e）/T-003（L=0x10） | 覆 |
| 4 | 序号/CA/IOA 小端 | frames 全正例 | 覆 |
| 5 | IOA 3B 上界 + 越界拒 | T-016（16777216 → `IOA`） | 覆 |
| 6 | NVA 小端有符号 | T-003（`34 12`） | 覆；负值/>65535 截断 → G-IEC104-8 |
| 7 | SIQ/SPI | T-001（SIQ/SPI 由 frames 主通道断言；未声称存在专用字段） | 覆 |
| 8 | DIQ/DPI | T-011 | 覆 |
| 9 | SCO select/execute + COT 6/7 | T-006 | 覆 |
| 10 | DCO + CP56Time2a | T-007 | 覆 |
| 11 | QOI=20 | T-002 | 覆；QOI 20..36 范围 → B′（G-IEC104-4） |
| 12 | CP56Time2a 7B 结构 | T-004/T-005（前缀 + nonzero，墙钟不定值） | 覆；非法时间 cases 负例缺 → A′ T-18 |
| 13 | L>253 拒收 | T-015 | 覆；事件实算长度（多对象/A
...[truncated 6154 chars]

## 12. 三路依据与候选方案（D1/D2）

规范依据为 IEC 60870-5-104 APCI/ASDU 帧定义；商业行为以 Siemens SICAM 与 Schneider EcoStruxure 的公开 IEC-104 配置及 2404/TCP、STARTDT、总召唤行为为待确认项（G-IEC104-1，确认方式：对应版本双向 pcap）；开源实现参考 lib60870-C v2.x 的 CS104 状态机与 InformationObject 编码组织。规范是底线，当前显式 events 语义是已实现范围。

|规范要求|业务场景|代码现状|缺口|
|---|---|---|---|
|单 TCP/2404、STARTDT/STOPDT|站点建链与释放|builder/layer_gen；T-001|chain 接线 G-IEC104-9|
|I/S/U 与 8 TypeID|遥信、遥测、遥控、总召唤|builder.go；T-001–T-011|扩展 Type G-IEC104-5|
|T0/T1/T2/T3 活性|长在线 TESTFR|显式 TESTFR；T-008|自动计时器 G-IEC104-3|

|方案|走法|优点|代价|结论|
|---|---|---|---|---|
|A|显式 events 顺序生成（layer_gen.go:15-88）|可复现、逐帧断言|状态拒绝和超时不自动化|采用|
|B|poll/command 高层自动编排（planner.go:58）|配置短|状态隐式、难复现|仅兼容|

## 13. 依赖、错误与性能（D3/D4）

依赖链为 ip 地址→tcp 可靠载体/2404→iec104 终结编码；缺载体、UDP、错端口失败。非法 kind/TypeID/IOA/APDU 长度返回 task error，中断且不重试；协议层不提供超时重试。APDU 上限 253B，逐事件流式生成，受 worker、队列和 buffer 上限约束。pcap 验收逐帧检查 APCI L、方向、序号和字段；网卡验收用 tcpdump 检查 2404、校验和、丢包和队列积压；基线、目标 flows、压力、长时、交错、背压六类列入 G-IEC104-9，未实测数字不作承诺。

## 14. 八要素与动态字段（D5/D6）

文件为 `internal/protocol/iec104/{builder,planner,layer_gen}.go` 及 chain translate/validate；接口是 IEC104Config generator 与 error validator；结构是 `[ip,tcp,iec104]`，流程为 TCP 建连→events 顺序→关闭；错误为 task error；性能边界为 APDU≤253B；冲突是 chain 接线、状态强制、方向/QOI/CP56 校验，分别 G-IEC104-3/4/9；回滚为恢复本三文件。

动态清单：ip.src/dst 与 tcp.src_port/dst_port 支持通用 fixed/inc/rand/list/pattern；未写动态时仅 src_port 有 12345+i 保底。common_address、ioa、value、cause、type_id、qoi、siq/diq/sco/dco、time 当前是静态业务字段，动态入口列 G-IEC104-8。事件序号算法在 `layer_gen.go:34-52`，CP56 编码在 `builder.go:107-124`；T-012 只证明四元组 inc。

## 15. 门1对照与缺口迁入（D7/D8）

§1：地址→ip、端口→tcp、数量→flow_control、业务→iec104；完整严格形 spec_json 见 §2/T-001。§3：每个 flow 是独立 TCP 会话，events 是事务序列，无派生数据流，事件位置即插入点，跨 flow 可交错；T-002/T-008/T-012。§12：四元组动态见 §14，业务动态 G-IEC104-8。

缺口迁入计划：G-IEC104-1 商业 pcap；G-IEC104-3 状态/窗口/活性；G-IEC104-4 方向/QOI/OA/时间边界；G-IEC104-5 扩展 TypeID；G-IEC104-8 业务动态；G-IEC104-9 chain 接线及 pcap 校准。缺口字段不进入顶层或正例。

### 15.1 子表③：商业行为→用例映射表

| 商业行为 | 现网确认状态/方式 | 用例映射 | 结论 |
|---|---|---|---|
| Siemens SICAM/Schneider EcoStruxure 以 TCP/2404 建链并 STARTDT | 待 G-IEC104-1；采对应版本双向 pcap | T-001/T-008 | 显式 events 已覆盖帧序 |
| 总召唤后返回遥信并确认 | 待 G-IEC104-1；采集 C_IC 往返 pcap | T-002/T-009 | C_IC/M_SP/S 已覆盖 |
| 错端口或 UDP 配置被拒 | 代码/schema 可直接确认 | T-020/T-021 | 负例真拒绝 |
| 顶层旧键与层链混用被拒 | schema 结构门可直接确认 | T-017/T-018/T-019 | 门2白名单覆盖 |

**D8**：T-017–T-021 的失败输入仅在负例中出现，未作为正例或保留配置；每个仍有明确锚词与迁移/拒绝去向。

## 16. 代码设计草稿与 D-entry（D-IEC104-1 P2 摘要）

文件边界：`internal/protocol/iec104/{types,builder,planner,layer_gen}.go`（wire 编码 / 校验与 legacy 规划 / 层链生成器）；接线点在 `internal/core/layers/{chain_planner_translate,generator,validate_layers}.go` 与 `cmd/server/main.go`。

D-entry 清单（静态核对结果）：① chain 生成器分发接线已完成；② `validate_layers.go` 的通用 presence/白名单/carrier 门已覆盖 IEC104 结构拒绝；③ `coverage_gate.py` 的 IEC104 检查已存在；④ 存量 21 例按去向表改写为层链形（已完成）。剩余 G-IEC104-9 是全量 suite/pcap 校准与 NIC 验收。

## 17. 幽灵键裁决与迁移去向（G-IEC104-2）

顶层 `role/startdt/stopdt/poll{request,response}/testfr/originator`、事件内 `control/repeat` 在 builder/planner/layer_gen 三处零消费（§8 实测）。裁决：**删除，不接线**——layer schema 已移除 `role/startdt/stopdt/repeat`（`registry.go` iec104 行；`coverage_gate.check_iec104` 反查此项），`transport` 与 `value` 保留（有真实消费）。新配置一律走 §2 层链形；旧扁平配置的四个顶层键由 `CheckProtoFlat` 判死（testcase §4 的 T-018/T-019），顶层同名业务键（`iec104`）由 presence 门判死（T-017）。

## 18. 缺口全量台账（最终状态）

| G 号 | 内容 | 当前状态 |
|---|---|---|
| G-IEC104-1 | 商业实现（SICAM/EcoStruxure）双向 pcap 确认 | 开放（第三源=待确认级） |
| G-IEC104-2 | 幽灵键 role/startdt/stopdt/repeat | **关闭**：裁决删除，schema 已移除（§17） |
| G-IEC104-3 | STARTDT 前 I 拒 / S rx 核对 / k-w 窗口 / STOPDT 后拒 / 被控站主动 U / T3 自动活性 | 开放，作为实现迁入项；当前显式 events 仍按顺序编码 |
| G-IEC104-4 | 方向强制、QOI 20..36 范围、OA 建模、CP56 非法时间负例 | 开放 |
| G-IEC104-5 | 扩展 TypeID（C_CS 对时、M_ME_NB/NC、M_ST/M_IT、C_SE/C_RC、SQ=1、VSQ>1） | 开放（§10 白名单外一律 `unknown type_id`） |
| G-IEC104-8 | 业务字段动态（common_address/ioa/value/cause/type_id/qoi/体字段/time） | **部分关闭**：`value` 越界已加 Validate 守卫（`planner.go:54/63`，负值/>65535 拒收）；其余动态入口仍开放 |
| G-IEC104-9 | 全量 suite/pcap 重跑校准（包数值）与 NIC 验收 | 开放；chain 接线与静态链路测试已完成，pcap 校准与 suite/NIC 实跑待办 |

> 结果诚实声明：以上「已落码/已完成/已关闭」均为**静态取证**（读文件 + `grep`），非 suite 通过、非 PCAP 落盘、非 NIC 实测。Packets 数值、PCAP 落盘与 NIC 测试均未在本轮执行。

## 19. 静态闭环 D1–D8

| ID | 结论 | 证据/缺口去向 |
|---|---|---|
| D1 | 规范边界已收敛为 TCP/2404、I/S/U、8 个 TypeID；规范→业务→代码→用例链已建立 | §1、§4、§11；T-001–T-012 |
| D2 | 三路依据和方案取舍已登记；商业行为仍是待确认，不冒充已验证 | §12、§15.1；G-IEC104-1 |
| D3 | 依赖、失败传播、中断/不重试边界已写明 | §13；非法输入必须 task error |
| D4 | 流式生成、有界队列、APDU 上限及 pcap/NIC 双路验收已登记；性能数字未实测，不作承诺 | §13；G-IEC104-9 |
| D5 | 文件、接口、结构、流程、错误、边界、冲突、回滚八要素齐全 | §14 |
| D6 | 四元组动态已由通用层承接；业务字段动态未实现，登记缺口，不把静态值当动态覆盖 | §14；G-IEC104-8 |
| D7 | 严格层链目标形、五件套和旧字段去向已对照 | §2、§15；T-017–T-019 |
| D8 | 5 个新增负例仅作为负例输入，均有真实锚词；幽灵键、Fields 或 translate 缺口均有删除或迁入计划 | §17、§20；T-017–T-021 |

### 19.1 Fields / translate 静态核对

- registry.go 的 `iec104` 注册表已提供 17 个字段及 `tcp.dst_port=2404` 契约；未发现应迁入正例却缺注册的字段。
- `chain_planner_translate.go:3301-3329` 已有 `case "iec104"`，并使用 `DisallowUnknownFields`；因此不登记 translate 或未知键静默忽略缺失假缺口。
- `iec104` 层只消费注册字段；旧文档中的 `role/startdt/stopdt/poll/testfr/originator/repeat` 不机械迁入，按 §17 删除或保持负例探针。

## 20. 静态审查清单 C1–C6

| ID | 审查结论 |
|---|---|
| C1 | `iec104.json` 解析成功，21 个 ID 唯一且顺序与本文 §7、testcase §2 一致；12 正、9 负。 |
| C2 | 12 个正例顶层仅 `layers`、`flow_control`；层链均为 `[ip,tcp,iec104]`；结构/承载违规键仅在对应负例中出现。 |
| C3 | 正例地址只在 `layers[].ip`，端口只在 `layers[].tcp`，业务只在 `layers[].iec104`，数量只在 `flow_control`；无旧扁平字段残留。 |
| C4 | 正例均有包数或最小包数及 frames/fields 可观察断言；T-013–T-021 的 expect 恰为 `expect_error` 与 `error_contains` 两键。 |
| C5 | D1–D8、T1–T6、G-IEC104-1/3/4/5/8/9 逐项有去向；Fields/translate 已按现有 registry 与 translate 分支核对，未虚登记缺口。 |
| C6 | 本轮只作三文件静态闭环，不改 Go、其他协议文档、LAYERCHAIN_INDEX，不运行 suite，不提交 commit；两轮自审最后一轮干净。 |

## 21. 修订记录

- v1.1.0（2026-10-01）：按 JSON 实际 21 例（12 正 + 9 负）补齐 D1–D8、Fields/translate 静态核对与 C1–C6；确认 translate 使用严格解码，chain 接线已完成；确认 T-017–T-021 五个新增负例仅负例保留且 expect 恰双键。
