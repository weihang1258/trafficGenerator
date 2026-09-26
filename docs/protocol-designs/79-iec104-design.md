# IEC 60870-5-104（IEC104，电力远动）设计契约

> 版本：v1.0.0（79 车道 P1–P3 产物）
> 日期：2026-09-26
> 状态：P1 八项规范矩阵（§11）+ 三子表 + 三路对照与候选方案对比（§12）+ 门1 §1–§14 十四行表（§13，§1/§3/§12 强制展开）+ P2 D-IEC104-1 代码设计草稿（§14）+ P3 对接清单与缺口立项（§15/§16/§18）已落盘；**`iec104` 层已注册、builder/planner/层生成器已落码，但 chain 路径生成器未接线（2026-09-26 离线实测 16/16 红：`generator not implemented for layer "iec104"`），且 16 例存量全为旧扁平形**——P4 落码前以门1 获批版为准，不宣称当前 suite 可运行。本契约不修改 Go 实现。
> 配套文件：`docs/protocol-designs/79-iec104-testcase.md`、`trafficgen/test/protocol_pcap/cases/iec104.json`（16 例旧扁平形，P4 按 §17 去向表改写）
> 规范基线：IEC 60870-5-104（公开帧定义；精确章节号待 G-IEC104-1 对原文复核，本契约只引用标准名不编章节号）+ tshark 3.6.14 dissector 实测 + 已落码 builder wire 真相。
> 与 22- 基线关系：`22-iec104-design/testcase.md`（v1.0.0，2026-08-18）保留为历史参考；其中 §4.3（k/w 窗口）、§4.7（poll 模板）、§5.2（k/w/send_seq/recv_seq/auto_s_ack/close_mode/allow_peer_startdt）、§5.3（originator）、§5.5（COT/originator 编码）描述的配置面**均未落码**（`IEC104Config` 实测见 §1），以本件 P1 矩阵与 §8 为准；§3 线格式与 §3.6 HexDump 的字节结论保留（I 帧_hex_按 §4 注记待 P5 落盘校准，U 帧 6 条已由落盘 pcap 实证）。

## 1. 范围、证据等级和已注册边界

本阶段将 iec104 严格限定为 **TCP 2404 单载体终结层**：APCI 三帧型（I/S/U）+ 8 类 ASDU（TypeID 1、3、9、30、34、45、59、100）+ STARTDT/STOPDT/TESTFR 显式事件。不把任意 TCP payload 标成 iec104。

**已注册/已落码现状（P1 实测，行号真实）**：

| 件 | 位置 | 内容 |
|---|---|---|
| 层注册 | `registry.go:855` | `Name "iec104"`，`CategoryTerminal`，`DependsOn ["tcp"]`，`FieldContract {"tcp.dst_port":"2404"}`，21 字段（transport/role/common_address/startdt/stopdt/events/commands/type_id/cause/ioa/value/siq/qds/diq/sco/dco/qoi/select/time/max_apdu_length/repeat） |
| 配置结构 | `types.go:143/167/185` | `IEC104Config`（Transport/Role/CommonAddress/StartDT/StopDT/Events/Commands/TypeID/Cause/IOA/Value/SIQ/QDS/DIQ/SCO/DCO/QOI/Select/Time/MaxAPDULength/Repeat）+ `IEC104Event`（Direction/Kind/TypeID/Cause/IOA/Value/RX/SIQ/QDS/DIQ/SCO/DCO/QOI/Select/Time）+ `IEC104Command`（TypeID/Cause/CommonAddress/IOA/Value） |
| wire 编码 | `internal/protocol/iec104/builder.go` | `BuildUFrame`（:9）/`BuildSFrame`（:18）/`BuildInformation`（:27）/`buildASDU`（:45）/`encodeCP56Time2a`（:107）/`validType`（:126，8 白名单） |
| 校验+规划 | `internal/protocol/iec104/planner.go` | `Planner.Validate`（:13，10 锚词行见 §9）/`Plan`（:58，legacy flat 路径） |
| 层生成器 | `internal/protocol/iec104/layer_gen.go` | `Generate`（:15，events 路逐事件序号 :34–52；commands 默认路 :56–88）+ `init` 注册 generator/validator（:127–129） |
| 子配置解析 | `strategy_convert.go:1386-1389` | `case "iec104"` 经 `parseSubconfigJSON`（`strategy_convert_helpers.go:21`，json roundtrip**无** `DisallowUnknownFields`——未知键静默忽略，见 §8） |
| Meta 直传 | `chain_planner_translate.go:109` + `generator.go:339` | `IEC104: spec.IEC104` / `FlowMeta.IEC104 *core.IEC104Config`（已接线） |
| 端口契约 | `chain_planner.go:599/1155` | iec104 在 FieldContract 通用化名单内（P0b-1：`tcp.dst_port` 由契约补 2404） |
| 白名单 | `protocols.go:40` + `protocols_test.go:27` | `"iec104"` 已登记 |
| 生成表 | `schemas/v1/generated/layers.generated.json` | `iec104: {terminal, ["tcp"], contract 2404, 21 fields}`（schemagen 已含，P4 只验证无过期） |
| 单测 | `internal/protocol/iec104/iec104_test.go` | 305 行；U/S/I 编码 + 4 否定 kind/type/IOA/length + transport/type/cause + 非法 CP56 时间（2026-09-26 `go test` 全绿实测） |

**未接线（P1 实测，不美化）**：

1. chain 路径生成器分发缺 `iec104`——离线执行器 16/16 红（`generator not implemented for layer "iec104"`，2026-09-26 实测，见 p123 报告 §6）；MCP suite 拥有 iec104（服务端路径至少 1 例落盘实证：`/tmp/mcp-pcaps/iec104/iec104_u_frames.pcap`，3 握手 + 6 U + 4 挥手 = 13 包，与公式一致）。→ **G-IEC104-9（P4 必办）**。
2. `validate_layers.go` 无 iec104 预检（presence/白名单/carrier 面均无）→ D-entry 新增（§14）。
3. `tools/coverage_gate.py` 无 `check_iec104`（`grep -c` = 0）→ P4 登记（M1 认领）。

不变式：

1. iec104 终结层只能位于 TCP 后；缺 TCP、UDP 载体、显式错端口必须错误（预检 P4 新增，见 §14；planner 现有 `transport` 守卫见 §9）。
2. U 帧只接受 §3.3 六控制字；S 帧只确认不带 ASDU；I 帧 TypeID 只接受 §4 白名单 8 类。
3. `L` 最大 253；ASDU 超长、IOA 越界（>0xffffff）、cause 非法（0 或 >63）必须在 Validate 阶段拒绝。
4. 错误必须传播到 task error 终态，不产生空成功任务（§9）。
5. T3 空闲自动测试、冗余双连接通道切换、IEC 62351 TLS（19998）**明确不支持**（§10）。

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
| `commands[]` | iec104 层 | legacy 默认路输入（TypeID/Cause/CA/IOA/Value）；层链目标形以 `events[]` 为主，commands 保留兼容 |
| `type_id/cause/ioa/value/siq/qds/diq/sco/dco/qoi/select/time` | iec104 层 | 顶层单对象快捷键（legacy）；目标形中事件内联，顶层残留按 §17 改写时并入事件或删除 |
| `max_apdu_length` | iec104 层 | 仅负例探针（>253 即拒，`planner.go:46`）；不是合法长度声明 |
| `flow_control` | 顶层 | `flows` = 独立 TCP 会话数（strategy_fc 同口径）；`bps/time` 离线不支持 |
| `wire_fault` | — | 本协议无此键；负例走自然非法输入（§9），不伪造 fault 面 |

**存量形状声明（P1 实测，不美化）**：16/16 同一旧扁平形——`spec_json` 顶层键 `['dst_ip','dst_port','iec104','layers','src_ip','src_port']`（multi_flow 缺 `src_port`，带顶层 `strategy_fc`）；`layers=[{"tcp":{}},{"iec104":{}}]` 空条目（无 `ip` 层、无层内地址端口）；16/16 无 `flow_control`；16/16 顶层 `iec104` 子映射与 `layers` 并存（门2-1 黄线，D-entry 登记过渡，P4 按 §17 改写）。顶层键中 `role`（16 例）、`startdt/stopdt`（2 例）、`poll`（1 例）、`testfr`（1 例）、事件内 `control`/`repeat`（各 1 例）为**当前无消费的键**（§8 幽灵键表），P4 按 G-IEC104-2 去向（消费落地或删除），不搬运。

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

## 7. 16 个语义场景与包数映射

设计、测试契约和 JSON 按**同一顺序**使用 16 个唯一 ID（T 编号为本件权威，括号内为 22- 基线 P/N 对照）：T-001 `iec104_startdt_msp`（P01，正，13）；T-002 `iec104_polling`（P02，正，20）；T-003 `iec104_m_me_na_type9`（P03，正，13）；T-004 `iec104_timed_measurement`（P04，正，13）；T-005 `iec104_timed_single_point`（P05，正，13）；T-006 `iec104_single_command`（P06，正，14）；T-007 `iec104_double_command_timed`（P07，正，14）；T-008 `iec104_u_frames`（P08，正，13）；T-009 `iec104_s_ack`（P09，正，14）；T-010 `iec104_spontaneous_event`（P10，正，13）；T-011 `iec104_ipv6`（P11，正，13）；T-012 `iec104_multi_flow`（P12，正，min 39）；T-013 `iec104_neg_control`（N01，负，`control`）；T-014 `iec104_neg_unknown_type`（N02，负，`unknown type_id`）；T-015 `iec104_neg_oversize_apdu`（N03，负，`APDU too long`）；T-016 `iec104_neg_ioa`（N04，负，`IOA`）。包数值 P5 全量重跑校准（G-IEC104-9），不照抄旧期望之外的算法则——公式已验算，u_frames 已实证。

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

> 深度口径（§4.19–4.22）：三张子表——①帧型×方向矩阵（§11.2，15 行 × 2 列 = 30 格）②数据形态变体表（§11.3，14 行）③商业行为→用例映射表（§12.2）。条目三选一：已覆 / B′（G 立项）/ 不适用 + 对应用例号；无遗漏留白。

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
| 7 | SIQ/SPI | T-001（`siq.spi` 字段面见 §12 基线，frames 主通道） | 覆 |
| 8 | DIQ/DPI | T-011 | 覆 |
| 9 | SCO select/execute + COT 6/7 | T-006 | 覆 |
| 10 | DCO + CP56Time2a | T-007 | 覆 |
| 11 | QOI=20 | T-002 | 覆；QOI 20..36 范围 → B′（G-IEC104-4） |
| 12 | CP56Time2a 7B 结构 | T-004/T-005（前缀 + nonzero，墙钟不定值） | 覆；非法时间 cases 负例缺 → A′ T-18 |
| 13 | L>253 拒收 | T-015 | 覆；事件实算长度（多对象/A
...[truncated 6154 chars]