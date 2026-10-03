# IEC 60870-5-104（IEC104）测试用例契约

> 版本：v1.0.0（79 车道 P3 产物）
> 日期：2026-09-26
> 配套设计：`docs/protocol-designs/79-iec104-design.md` v1.0.0（D-IEC104-1 草稿 §14；门1 获批=定稿）
> 机器契约：`trafficgen/test/protocol_pcap/cases/iec104.json`（21 例（12 正 + 9 负）层链形，P4 已按层链去向表改写）
> 状态：`iec104` 层已注册、builder/planner/层生成器及 chain translate/validator 已落码（§1 现状表）；静态链路测试已覆盖接线和结构门，但本轮不运行 suite/server/NIC，故不宣称当前 suite 可运行。
> ID 说明：本件 T-001–T-021 为本契约权威编号；括号内 P01–P12/N01–N04 为 22- 基线对照（历史参考，不作权威）。

## 1. 测试原则与形状基线

用例从设计 §1–§9 逐项派生。iec104 只接受 TCP/2404 载体 + §4 八 ASDU；不把任意 TCP payload 标成 iec104。tshark 自动解码 2404（`tcp.port 2404 → iec60870_104` 实测），用例无需 `decode_as`。

- 每个正例都有 `packet_count`（或 `min_packets`，仅 T-012）+ 非空 `frames`；`fields` 有则全部来自已注册字段（`tcp.*`/`ipv6.*`/`iec60870_104.apdulen`，`tshark -G fields` 实证 6 个 `iec60870_104.*`）。
- `FrameAssert.hex` 是前缀匹配：offset 54（IPv4）/74（IPv6）指向 APDU 起点；同一帧多字段断言按 60（TypeID）/64（CA）/66（IOA）/69（体）错开。
- 包数公式 `3 + 事件数 + 4`（§2 表）；多流（T-012）与异常关闭只用 `min_packets` + 聚合。
- 动态 CP56Time2a 只断言固定前缀或 `nonzero`，不定死墙钟。
- 负例 `expect` 严格只有 `expect_error` + `error_contains`，无包结构断言；错误必须为 task error 终态。
- **先跑后钉**：T-002/T-006/T-007 含序号字节的 I 帧 hex、T-004/T-007 时间后缀、T-009 二轮细节，P5 以落盘 pcap 校准，不照抄布局公式手算值。

## 2. 原子用例索引（21 ID = 12 正 + 9 负，顺序为权威）

| # | T 号 | ID | 类型 | 覆盖 | 包数 |
|---:|---|---|---|---|---:|
| 1 | T-001 | `iec104_startdt_msp` | 正 | STARTDT 对、M_SP、S 确认、STOPDT 对、FIN | 13 |
| 2 | T-002 | `iec104_polling` | 正 | 三轮 C_IC + M_SP + S，序号递增 | 20 |
| 3 | T-003 | `iec104_m_me_na_type9` | 正 | Type9 NVA 小端 + QDS | 13 |
| 4 | T-004 | `iec104_timed_measurement` | 正 | Type34 + CP56Time2a | 13 |
| 5 | T-005 | `iec104_timed_single_point` | 正 | Type30 + CP56Time2a | 13 |
| 6 | T-006 | `iec104_single_command` | 正 | Type45 选/执 + ActCon | 14 |
| 7 | T-007 | `iec104_double_command_timed` | 正 | Type59 DCO + 时标 + ActCon | 14 |
| 8 | T-008 | `iec104_u_frames` | 正 | U 六帧全序列 | 13 |
| 9 | T-009 | `iec104_s_ack` | 正 | down I 后 up S（N(R)<<1） | 14 |
| 10 | T-010 | `iec104_spontaneous_event` | 正 | COT=3 突发 + 方向（srcport 2404） | 13 |
| 11 | T-011 | `iec104_ipv6` | 正 | IPv6 offset 74 + Type3 | 13 |
| 12 | T-012 | `iec104_multi_flow` | 正 | 三会话扇出、序号隔离、端口聚合 | min 39 |
| 13 | T-013 | `iec104_neg_control` | 负 | 非法 kind | — |
| 14 | T-014 | `iec104_neg_unknown_type` | 负 | TypeID=250 | — |
| 15 | T-015 | `iec104_neg_oversize_apdu` | 负 | 超长（max 254） | — |
| 16 | T-016 | `iec104_neg_ioa` | 负 | IOA 越界（16777216） | — |
| 17 | T-017 | `iec104_neg_presence_top_level_iec104` | 负 | 层链与顶层 iec104 并存 | — |
| 18 | T-018 | `iec104_neg_flat_count` | 负 | 层链旁游离 count | — |
| 19 | T-019 | `iec104_neg_stray_src_mac` | 负 | 层链旁游离 src_mac | — |
| 20 | T-020 | `iec104_neg_dst_port_contract` | 负 | tcp.dst_port 非 2404 | — |
| 21 | T-021 | `iec104_neg_udp_carrier` | 负 | UDP 承载拒绝 | — |

## 3. 正例逐项断言契约（12 项）

- **T-001**：握手包 1–3；包 4/5 为 STARTDT act/con（offset 54）；包 6 `L=0x0e`、TypeID=1、COT=3、CA=1、IOA=1、SIQ=1 前缀 `68 0e 00 00 00 00 01 01 03 00 01 00 01 00 00 01`；包 7 S `68 04 01 00 02 00`；包 8/9 STOPDT 对；`fields` 补 `tcp.dstport=2404`（包 4）、`tcp.srcport=2404`（包 5）、`apdulen=14`（包 6）。`packet_count=13`。
- **T-002**：三轮 `C_IC(QOI=20,COT=6) → M_SP(COT=20) → S`；首轮包 6–8 前缀见 §2 表；S 控制域三轮各异（包 8 `01 00 02 00`、包 11 `01 00 04 00`、包 14 `01 00 06 00`）。`packet_count=20`。**先跑后钉**：二轮 I 帧 `N(S)` 字节（`00 00` vs `02 00`）以 P5 落盘 pcap 为准。
- **T-003**：down Type9、CA=2、IOA=16、NVA=0x1234（小端 `34 12`）、QDS=0；完整 `68 10 00 00 00 00 09 01 03 00 02 00 10 00 00 34 12 00`。`packet_count=13`。
- **T-004**：down Type34、CA=3、IOA=17、NVA=100 + CP56；`68 17 00 00 00 00 22 01 03 00 03 00 11 00 00` 前缀 + 时间 10B 不定值（`time` 字段存在可解析）。`packet_count=13`。
- **T-005**：down Type30、CA=4、IOA=21、SIQ=1 + CP56；`68 15 00 00 00 00 1e 01 03 00 04 00 15 00 00 01` 前缀（SIQ 在 APDU+15，时间从 +16 起）。`packet_count=13`。
- **T-006**：up Type45 select（COT=6，SCO=`0x81`）→ down Type45 confirm（COT=7）；两帧 `68 0e … 2d 01 06/07 00 05 00 16 00 00 81` + up S。`packet_count=14`。**先跑后钉**：控制域序号字节以落盘为准（设计 §2 注记c）。
- **T-007**：up/down Type59、DCS=2 execute、COT 6/7 + CP56；`68 15 … 3b 01 06/07 00 06 00 17 00 00 02` 前缀 + 时间。`packet_count=14`。**先跑后钉**同 T-006。
- **T-008**：六 U 帧全序列（包 4–9，`L=4`）；`fields` 补 `apdulen=4`（包 4/6 抽查）。`packet_count=13`（落盘实证 `/tmp/mcp-pcaps/iec104/iec104_u_frames.pcap`）。
- **T-009**：up C_IC → down M_SP → up S `68 04 01 00 02 00`（包 8）→ STOPDT 对。`packet_count=14`。方向约束：S 必须在 down I 之后（防空 S 假阳性）。
- **T-010**：down Type1、COT=3、CA=9、IOA=90（`5a 00 00`）、SIQ=1 前缀 + up S；`fields` 断 `tcp.srcport=2404`（包 6，下行方向证）。`packet_count=13`。
- **T-011**：IPv6 载体，业务字节与 IPv4 同形；down Type3、CA=10、IOA=2、DIQ=2；offset **74**；`fields` 断 `ipv6.dst=2001:db8:104::2` + `tcp.dstport=2404`。`packet_count=13`。
- **T-012**：`strategy_fc flows=3`；`min_packets=39`；`tcp.srcport distinct {12345,12346,12347}`（exclude 2404）+ `tcp.dstport distinct {2404}`；不锁交织包号。T-012 以 `flow_control.flows=3` 表达三会话扇出，不额外伪造未落码的 `sessions[]` 配置。

## 4. 负例契约（9 项）

| T 号 | ID | 故障输入 | `error_contains` | 代码/结构锚点 |
|---|---|---|---|---|
| T-013 | `iec104_neg_control` | `events[0].kind=u` | `control` | `planner.go:31` |
| T-014 | `iec104_neg_unknown_type` | I 事件 TypeID=250 | `unknown type_id` | `planner.go:35` |
| T-015 | `iec104_neg_oversize_apdu` | `max_apdu_length=254` | `APDU too long` | `planner.go:46` |
| T-016 | `iec104_neg_ioa` | IOA=16777216 | `IOA` | `planner.go:41` |
| T-017 | `iec104_neg_presence_top_level_iec104` | `layers` 内有 iec104 且顶层再次有 `iec104` | `top-level iec104 sub-config` | schema semantic gate |
| T-018 | `iec104_neg_flat_count` | 层链旁写顶层 `count=5` | `no longer accepts flat config field count` | schema flat-field gate |
| T-019 | `iec104_neg_stray_src_mac` | 层链旁写顶层 `src_mac` | `src_mac` | schema top-level allowlist |
| T-020 | `iec104_neg_dst_port_contract` | `tcp.dst_port=5000` | `dst_port must be 2404` | IEC104 FieldContract |
| T-021 | `iec104_neg_udp_carrier` | 用 `udp` 层承载 iec104 | `carrier` | carrier validation |

所有负例的 `expect` 仅有 `expect_error`、`error_contains`，没有 `packet_count`、`frames` 或成功输出断言；失败必须到达 task error 终态。


## 5. 存量 21 例逐条去向审计（§9.14；P4 已执行）

T-001–T-016：合入层链，保留原语义；T-017–T-021：新增结构/承载负例，直接合入 JSON 并以真实拒绝锚词断言。作废 0 例，等价覆盖 0 例。

| T 号 | ID | 去向 | 迁移/失败契约 |
|---|---|---|---|
| T-001–T-011 | 对应原 ID | 合入 | 地址→ip、端口→tcp、业务→iec104、数量→flow_control |
| T-012 | `iec104_multi_flow` | 合入 | `strategy_fc` 与 `flow_control.flows=3` 保持一致，端口聚合隔离 |
| T-013–T-016 | 对应原 ID | 合入 | 保留 planner 失败锚词 `control`/`unknown type_id`/`APDU too long`/`IOA` |
| T-017 | `iec104_neg_presence_top_level_iec104` | 新增负例 | 顶层协议子映射与层内同名映射并存，锚词 `top-level iec104 sub-config` |
| T-018 | `iec104_neg_flat_count` | 新增负例 | 顶层 `count` 违反白名单，锚词 `no longer accepts flat config field count` |
| T-019 | `iec104_neg_stray_src_mac` | 新增负例 | 顶层 `src_mac` 违反白名单，锚词 `src_mac` |
| T-020 | `iec104_neg_dst_port_contract` | 新增负例 | TCP 目标端口违反 2404 契约，锚词 `dst_port must be 2404` |
| T-021 | `iec104_neg_udp_carrier` | 新增负例 | UDP 不是 IEC104 载体，锚词 `carrier` |


## 6. 三方一致性与静态检查

1. 设计 §7、本文 §2 与 JSON 的 21 个 ID 集合、拼写和顺序完全一致；正例 12、负例 9。
2. 正例包数按顺序为 `[13,20,13,13,13,14,14,13,14,13,13,min39]`，每条均含 `frames`（T-012 例外：聚合代替帧）。
3. 每个正例的 `fields` 字段全部已注册（`tcp.dstport/srcport`、`ipv6.dst`、`iec60870_104.apdulen`）；未使用臆造 `iec60870_asdu.*`。
4. 正例只使用 TCP/2404；IPv6 例 offset=74 其余 54；动态时间只前缀/nonzero。
5. 多流只用 `min_packets` + `distinct_values`（exclude 对侧端口，9.38 口径）；不以包号表达交织。
6. T-013–T-021 的 `expect` 严格只有 `expect_error`、`error_contains`，且分别使用真实锚词 `control`、`unknown type_id`、`APDU too long`、`IOA`、`top-level iec104 sub-config`、`no longer accepts flat config field count`、`src_mac`、`dst_port must be 2404`、`carrier`。

## 7. 实现后执行建议

先跑 JSON 语法、ID 唯一性、正负 expect 结构、字段注册名、offset 和包数静态检查；然后按 T-001→T-012 验证 U→I→S→STOPDT 面、IPv4/IPv6、时标、命令 ActCon、多流隔离，最后执行 T-013→T-021 九个负例。分别用 tshark 检查 `iec60870_104` expert malformed、TCP checksum 与 APCI `L` 一致性；不能以"任务完成但 0 包"作为通过。落盘 `/tmp/mcp-pcaps/iec104/`（14.16），P5 全量重跑（14.19）。

## 8. 修订记录

- v1.0.0（2026-09-26）：79 车道 P3 产物。新增 §8 固定动作（§3.15 三项 / A′B′ / 9.52 对账 / 3.14 豁免审计 / 三源回指 / 断言契约核对）；新增 §5 存量 21 例逐条去向审计表（旧扁平形→层链目标形，P4 执行）；包数公式逐例验算（`3+E+4` 全合）；I 帧序号字节三处标先跑后钉（T-002/T-006/T-007）。

## 9. P3 固定动作（CORE_MEMORY §3.15 / §9.52 / §9.14 / 覆盖审计要求面）

### 9.1 §3.15 三项逐项一例或立项（无例无项即缺口）

| # | 三项 | 本协议对照 | 用例/立项 |
|---|---|---|---|
| ① | 同连接/同流内的多轮操作 | 同 TCP 会话内多轮 I/S/U：总召唤三轮（T-002）+ 命令选/执两轮（T-006/T-007）+ U 序列六帧（T-008） | 已覆：T-002/T-006/T-007/T-008 |
| ② | 非正常结束 | 非法 kind/未知 Type/超长/IOA 越界四类拒收，全部 task error 终态 | 已覆：T-013–T-016 |
| ③ | 长保活 | TESTFR 显式对（T-008，正例语义）；T3 按墙钟自动触发 → G-IEC104-3 立项（实现计时器后新增/校准用例） | 已覆显式 TESTFR；自动 T3 作为迁入项 |

无空项。

### 9.2 A′/B′ 两分类表（要求面反推：数据/业务/现网/多流/地址族/断言通道六类）

A′（引擎可构建 → 21 ID 内已覆；**A′ 补例建议 = T-17/T-18/T-19**，并入与否由主线程定，不影响 §2 的 21 ID 权威口径）：

| 面 | 要求点 | 去向 |
|---|---|---|
| 数据 | APCI 三帧型/序号小端/CA/IOA/NVA/SIQ/DIQ/SCO/DCO/QOI/CP56/L 上界 | T-001–T-011 已覆；非法形 → 负例 T-013–T-016；value 截断/QOI 范围/非法时间 → G-IEC104-4/8 + T-18 |
| 业务 | STARTDT 序/S 确认/总召唤/COT 方向/命令 ActCon/突发 | T-001/T-002/T-006/T-009/T-010 已覆；强制面 → G-IEC104-3 |
| 现网 | 变电站上送/调度下令/多厂站扇出/IPv6 新站 | T-001–T-012 已覆外壳；**抓包级确认 → G-IEC104-1**；方向约束面 → G-IEC104-4 |
| 多流 | 三会话扇出隔离（四元组/序号/CA 不串） | T-012 已覆；**IPv6 多流对称缺格 → A′ T-17**（§9.24）；多 flow×静态标量注记（§6 注） |
| 地址族 | IPv4/IPv6 双载体（§9.24 对称） | T-001/T-011 已覆；对称缺格 → T-17 |
| 断言通道 | `iec60870_104.*` 6 字段 + `tcp.*`/`ipv6.*` 载体面 + frames hex（54/74 两档） | 全正例；`gec60870_asdu.*` 84 字段**未用**（基线误记更正，P5 评估 → A′ T-19） |

B′（引擎结构缺口 → D-IEC104-1 G-IEC104-3/5/6 迁入计划，见设计 §16）：STARTDT 前 I 拒/S rx 核对/k-w 窗口/STOPDT 后拒/被控站主动 U/C_CS 对时/冗余切换/扩展 Type。

### 9.3 9.52 对账两行 + 清单出处声明

- **清单出处声明**：本清单来源 = **规范反推**（IEC 60870-5-104 公开帧定义；精确章节号待 G-IEC104-1），**非**引擎能力面反推（覆盖审计要求面记忆）。引擎侧只作现状取证：`iec104` 已注册（`registry.go:1100`）/白名单（`protocols.go:40`）/builder+planner+层生成器+chain translate 已落码/21 例（12 正 + 9 负）层链形/tshark `iec60870_104.*` 6 + `iec60870_asdu.*` 84 字段实测/2404 自动解码实测；静态链路测试覆盖接线，真实 suite/PCAP/NIC 验证仍待执行。
- **对账两行**：**规范逻辑点总数 = 50**（八项 8 行 + 帧型×方向矩阵 30 格 + 数据形态变体 14 行 − 不适用 2）；**用例覆盖数 = 31**（八项 8 行全有结论 + 矩阵已覆 18 − 不适用 1 + 变体已覆 11 − 不适用 2 + T-013–T-016 锚定变体 13（部分重叠）→ 按 ID 去重：12 正 + 9 负 = 21 ID 承载 31 点）；**不适用 = 2**（C_IC down、MSS 分段）；**B′/立项 = 17**（矩阵 11 格 + 变体 3 行 + 方向约束类 → G-IEC104-3/4/5/6/8）。31 + 2 + 17 = 50 ✓ 无遗漏。**反查 21/21 ≠ 覆盖全**——反查只证明清单内的点有例，本对账才证明清单本身全（§9.52 原文）。
- **粒度声明（防误读）**：按设计 §11 的行/格粒度计数；子面（QOI 范围/厂商 Type/回绕组合）另登 G 项，**不折进 50 点、也不冒充覆盖**。

### 9.4 3.14 豁免边界审计

- 本协议有长连接（单 TCP 会话多事务），但 JSON 仅以 `flow_control.flows=3` 表达多会话扇出；不主张 sessions 豁免，也不伪造未落码的 `sessions[]` 配置。
- **多流并发**：已覆 T-012（三会话扇出隔离）。
- **单包多载荷**：单 ASDU 单对象（VSQ 恒 1）已覆（T-001–T-011）；多对象面 → B′（G-IEC104-6），作为迁入项，不以豁免替代覆盖。
- **TCP 分段面**：MSS 536 > APDU 253，协议上无分段面 → 显式记**不适用**（设计 §3 末；与"豁免 sessions≠豁免多流"不冲突——分段面≠多流面）。
- 结论：多流 / 单包多载荷 / 多包序列三项各有结论，无逃逸。

### 9.5 三源回指行

IEC 60870-5-104 公开帧定义（APCI/ASDU/TypeID/序号/STARTDT）→ **design.md §3–§16** → `trafficgen/test/protocol_pcap/cases/iec104.json`（21 例，T-001–T-021）。第三源“已确认现网行为”当前为待确认级（G-IEC104-1；确认方式：Siemens SICAM 或 Schneider EcoStruxure 双向 pcap）。T-017–T-021 的结构门行为来自 schema/FieldContract 代码锚点，详见 §4。ID 权威 = 本文 §2（12 正 + 9 负）。

### 9.6 断言契约核对结论（与设计 §1/§9/§13 一致）

1. **21 ID 契约核对**：本文 §2 与设计 §7 逐 ID、逐序、逐类型、逐 `packet_count` 一致——12 正例（`[13,20,13,13,13,14,14,13,14,13,13,min39]`）+ 9 负例（`expect` 只有 `expect_error`/`error_contains`，九类锚词逐字对结构门、FieldContract 与 planner 真实代码）。
2. **存量审计（§9.14）**：见 §5 去向表。16 例现状同一旧扁平形（`layers=[{tcp:{}},{iec104:{}}]` 空条目 + 顶层四键 + 顶层 `iec104` 子映射 + 无 `flow_control` + 幽灵键 5 类），P4 按去向表逐例改写，**I 帧序号字节与时间后缀先跑后钉**（T-002/T-006/T-007）。
3. **断言通道核对**：`iec60870_104.*` 6 字段 + `tcp.*`/`ipv6.*` 实测可用；frames hex 两档 offset（54/74）实测；`iec60870_asdu.*` 本件未用（基线误记更正 → A′ T-19）。
4. **packet_count 纪律**：T-001–T-011 与 T-012 的约定值随 P4 迁移后仍须按 §9.31/§14.6/§14.20 以落盘 pcap 实测校准；T-008 的 13 包已有落盘实证，其余待 G-IEC104-9 接线后重跑。

## 10. P4迁移后对账（T1–T6）

三源回指：IEC 60870-5-104 帧定义→设计 §3–§16→cases JSON；现网行为挂 G-IEC104-1（确认方式：Siemens SICAM 或 Schneider EcoStruxure 双向 pcap）。测试点清单先行：帧型/方向 T-001/T-008/T-009，TypeID/字段 T-001–T-011，多流/地址族 T-011/T-012，错误与结构门 T-013–T-021。数据、业务、现网三类均有条目；动态整格当前仅四元组 inc 可执行，其余挂 G-IEC104-8。

§3.15：同连接多轮 T-002/T-006/T-008；非正常结束 T-013–T-021；长保活 T-008 显式 TESTFR，自动 T3 挂 G-IEC104-3。存量 T-001–T-016 合入，新增 T-017–T-021，作废 0、等价覆盖 0。

## 12. T1–T6 静态闭环

| ID | 结论 | 证据/缺口去向 |
|---|---|---|
| T1 | JSON 实际为 21 个唯一 ID，12 正 + 9 负；文档索引、设计映射和数组顺序一致 | §2、§5；`trafficgen/test/protocol_pcap/cases/iec104.json` |
| T2 | 12 个正例均具可观察包数/最小包数及 frames 或 fields；IPv4 offset=54、IPv6 offset=74 | §3、§6；T-001–T-012 |
| T3 | 9 个负例的 `expect` 恰为 `expect_error`、`error_contains` 两键；锚词按实际结构门、FieldContract 或 planner 文案登记 | §4；T-013–T-021 |
| T4 | 存量 T-001–T-016 合入；新增 T-017–T-021 五例只作为结构/承载负例，不机械迁移到正例 | §5；presence、count、src_mac、dst_port、UDP carrier |
| T5 | Fields/translate 缺口不以文档迁移伪装覆盖：`iec60870_104.*`、`tcp.*`、`ipv6.*` 只写实测字段；translate 已有严格 `iec104` case，未知键由 `DisallowUnknownFields`/层校验拒绝 | §1、设计 §19.1 |
| T6 | 本轮只完成三文件静态闭环；不运行 suite、不改 Go/其他文档/LAYERCHAIN_INDEX、不提交；两轮自审最后一轮干净 | 设计 §20 C6 |

## 13. 修订记录

- v1.1.0（2026-10-01）：按机器 JSON 实际数量与 ID 补齐 T1–T6；校正 21=12+9、五个新增负例去向、负例 expect 双键和真实锚词；Fields/translate 缺口单独登记，不机械迁移。

