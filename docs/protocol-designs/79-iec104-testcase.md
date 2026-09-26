# IEC 60870-5-104（IEC104）测试用例契约

> 版本：v1.0.0（79 车道 P3 产物）
> 日期：2026-09-26
> 配套设计：`docs/protocol-designs/79-iec104-design.md` v1.0.0（D-IEC104-1 草稿 §14；门1 获批=定稿）
> 机器契约：`trafficgen/test/protocol_pcap/cases/iec104.json`（16 例旧扁平形，P4 按 §5 去向表改写）
> 状态：`iec104` 层已注册、builder/planner/层生成器已落码（§1 现状表），但 chain 路径未接线（离线 16/16 红，见设计 §1）——P4 落码前以门1 获批版为准，不宣称当前 suite 可运行。
> ID 说明：本件 T-001–T-016 为本契约权威编号；括号内 P01–P12/N01–N04 为 22- 基线对照（历史参考，不作权威）。

## 1. 测试原则与形状基线

用例从设计 §1–§9 逐项派生。iec104 只接受 TCP/2404 载体 + §4 八 ASDU；不把任意 TCP payload 标成 iec104。tshark 自动解码 2404（`tcp.port 2404 → iec60870_104` 实测），用例无需 `decode_as`。

- 每个正例都有 `packet_count`（或 `min_packets`，仅 T-012）+ 非空 `frames`；`fields` 有则全部来自已注册字段（`tcp.*`/`ipv6.*`/`iec60870_104.apdulen`，`tshark -G fields` 实证 6 个 `iec60870_104.*`）。
- `FrameAssert.hex` 是前缀匹配：offset 54（IPv4）/74（IPv6）指向 APDU 起点；同一帧多字段断言按 60（TypeID）/64（CA）/66（IOA）/69（体）错开。
- 包数公式 `3 + 事件数 + 4`（§2 表）；多流（T-012）与异常关闭只用 `min_packets` + 聚合。
- 动态 CP56Time2a 只断言固定前缀或 `nonzero`，不定死墙钟。
- 负例 `expect` 严格只有 `expect_error` + `error_contains`，无包结构断言；错误必须为 task error 终态。
- **先跑后钉**：T-002/T-006/T-007 含序号字节的 I 帧 hex、T-004/T-007 时间后缀、T-009 二轮细节，P5 以落盘 pcap 校准，不照抄布局公式手算值。

## 2. 原子用例索引（16 ID = 12 正 + 4 负，顺序为权威）

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
- **T-012**：`strategy_fc flows=3`；`min_packets=39`；`tcp.srcport distinct {12345,12346,12347}`（exclude 2404）+ `tcp.dstport distinct {2404}`；不锁交织包号。P4 按 §5 改写为 `flow_control` + `sessions[]` 三会话显式化。

## 4. 负例契约（4 项）

| ID | 故障输入 | `error_contains` | 锚点 |
|---|---|---|---|
| `iec104_neg_control` | kind=`u`（+ `control` 幽灵键） | `control` | `planner.go:31`（kind 白名单；`control` 键本身未读 → G-IEC104-2） |
| `iec104_neg_unknown_type` | TypeID=250 | `unknown type_id` | `planner.go:35` |
| `iec104_neg_oversize_apdu` | `max_apdu_length=254` + `repeat` 幽灵键 | `APDU too long` | `planner.go:46`（`repeat` 键未读 → G-IEC104-2） |
| `iec104_neg_ioa` | IOA=16777216（max+1） | `IOA` | `planner.go:41`（`builder.go:53` 同源） |

负例 `expect` 仅此二键；错误须为 task error（零假成功）。

## 5. 存量 16 例逐条去向审计（§9.14；P1 存量实测，P4 按本表执行）

存量现状（2026-09-26 实测）：16/16 同一旧扁平形——`spec_json` 顶层键 `['dst_ip','dst_port','iec104','layers','src_ip','src_port']`（multi_flow 缺 `src_port` 另带顶层 `strategy_fc`）；`layers=[{"tcp":{}},{"iec104":{}}]` 空条目（无 `ip` 层、无层内地址端口）；16/16 无 `flow_control`；16/16 顶层 `iec104` 子映射与 `layers` 并存。

| # | ID | 去向 | 改写要点 |
|---:|---|---|---|
| 1 | `iec104_startdt_msp` | 合入 | 四键→`ip`/`tcp` 层（src_port 31001）；`iec104` 子映射→`layers[2].iec104`（`common_address`+`events` 迁入；`role` 删除）；补 `flow_control.flows=1`；hex 先跑后钉 |
| 2 | `iec104_polling` | 合入 | 同上（src_port 31002）+ **`poll` 对象删除**（幽灵键，事件已显式 13 个）；`startdt/stopdt` 删除 |
| 3 | `iec104_m_me_na_type9` | 合入 | 同 #1；`role` 删除 |
| 4 | `iec104_timed_measurement` | 合入 | 同 #1；`time` 保留（RFC3339 fixture），断言只前缀 |
| 5 | `iec104_timed_single_point` | 合入 | 同 #1 |
| 6 | `iec104_single_command` | 合入 | 同 #1；控制域序号字节先跑后钉 |
| 7 | `iec104_double_command_timed` | 合入 | 同 #6 |
| 8 | `iec104_u_frames` | 合入 | 同 #1 + **`testfr` 删除**（幽灵键，事件已显式） |
| 9 | `iec104_s_ack` | 合入 | 同 #1 |
| 10 | `iec104_spontaneous_event` | 合入 | 同 #1 |
| 11 | `iec104_ipv6` | 合入 | `ip` 层填 v6 地址（ntlm 先例）；offset 74 保持；`role` 删除 |
| 12 | `iec104_multi_flow` | 合入 | `strategy_fc`→`flow_control.flows=3`；`sessions[]` 三会话显式化（G-IEC104-1）；无 `src_port` 缺键由 `12345+i` 保底实证 |
| 13 | `iec104_neg_control` | 合入 | 负例形状同正例；`events[0]` 改写为非法 `kind`（P4 与 P6 协商 `control` 形，G-IEC104-2 未决前保留 `kind:"u"`）；`role` 删除 |
| 14 | `iec104_neg_unknown_type` | 合入 | 同上；锚词 `unknown type_id` 对 `planner.go:35` |
| 15 | `iec104_neg_oversize_apdu` | 合入 | 同上；`repeat` 删除（幽灵键）；锚词对 `planner.go:46` |
| 16 | `iec104_neg_ioa` | 合入 | 同上；锚词对 `planner.go:41` |

作废 0 例，等价覆盖 0 例（无重复语义可合并）。P4 另新增 4 链级红例（§8.7）+ 收官自查行「非负例顶层键=0」。

## 6. 三方一致性与静态检查

1. 设计 §7、本文 §2 与 JSON 的 16 个 ID 集合、拼写和顺序完全一致；正例 12、负例 4。
2. 正例包数按顺序为 `[13,20,13,13,13,14,14,13,14,13,13,min39]`，每条均含 `frames`（T-012 例外：聚合代替帧）。
3. 每个正例的 `fields` 字段全部已注册（`tcp.dstport/srcport`、`ipv6.dst`、`iec60870_104.apdulen`）；未使用臆造 `iec60870_asdu.*`。
4. 正例只使用 TCP/2404；IPv6 例 offset=74 其余 54；动态时间只前缀/nonzero。
5. 多流只用 `min_packets` + `distinct_values`（exclude 对侧端口，9.38 口径）；不以包号表达交织。
6. 负例 `expect` 仅有 `expect_error`、`error_contains`。

## 7. 实现后执行建议

先跑 JSON 语法、ID 唯一性、正负 expect 结构、字段注册名、offset 和包数静态检查；然后按 T-001→T-012 验证 U→I→S→STOPDT 面、IPv4/IPv6、时标、命令 ActCon、多流隔离，最后执行四个负例。分别用 tshark 检查 `iec60870_104` expert malformed、TCP checksum 与 APCI `L` 一致性；不能以"任务完成但 0 包"作为通过。落盘 `/tmp/mcp-pcaps/iec104/`（14.16），P5 全量重跑（14.19）。

## 8. 修订记录

- v1.0.0（2026-09-26）：79 车道 P3 产物。新增 §8 固定动作（§3.15 三项 / A′B′ / 9.52 对账 / 3.14 豁免审计 / 三源回指 / 断言契约核对）；新增 §5 存量 16 例逐条去向审计表（旧扁平形→层链目标形，P4 执行）；包数公式逐例验算（`3+E+4` 全合）；I 帧序号字节三处标先跑后钉（T-002/T-006/T-007）。

## 9. P3 固定动作（CORE_MEMORY §3.15 / §9.52 / §9.14 / 覆盖审计要求面）

### 9.1 §3.15 三项逐项一例或立项（无例无项即缺口）

| # | 三项 | 本协议对照 | 用例/立项 |
|---|---|---|---|
| ① | 同连接/同流内的多轮操作 | 同 TCP 会话内多轮 I/S/U：总召唤三轮（T-002）+ 命令选/执两轮（T-006/T-007）+ U 序列六帧（T-008） | 已覆：T-002/T-006/T-007/T-008 |
| ② | 非正常结束 | 非法 kind/未知 Type/超长/IOA 越界四类拒收，全部 task error 终态 | 已覆：T-013–T-016 |
| ③ | 长保活 | TESTFR 显式对（T-008，正例语义）；T3 按墙钟自动触发 → **明确不支持**（设计 §1/§10） | 已覆 + 明确不支持（显式声明，不用"待确认"逃逸） |

无空项。

### 9.2 A′/B′ 两分类表（要求面反推：数据/业务/现网/多流/地址族/断言通道六类）

A′（引擎可构建 → 16 ID 内已覆；**A′ 补例建议 = T-17/T-18/T-19**，并入与否由主线程定，不影响 §2 的 16 ID 权威口径）：

| 面 | 要求点 | 去向 |
|---|---|---|
| 数据 | APCI 三帧型/序号小端/CA/IOA/NVA/SIQ/DIQ/SCO/DCO/QOI/CP56/L 上界 | T-001–T-011 已覆；非法形 → 负例 T-013–T-016；value 截断/QOI 范围/非法时间 → G-IEC104-4/8 + T-18 |
| 业务 | STARTDT 序/S 确认/总召唤/COT 方向/命令 ActCon/突发 | T-001/T-002/T-006/T-009/T-010 已覆；强制面 → G-IEC104-3 |
| 现网 | 变电站上送/调度下令/多厂站扇出/IPv6 新站 | T-001–T-012 已覆外壳；**抓包级确认 → G-IEC104-1**；方向约束面 → G-IEC104-4 |
| 多流 | 三会话扇出隔离（四元组/序号/CA 不串） | T-012 已覆；**IPv6 多流对称缺格 → A′ T-17**（§9.24）；多 flow×静态标量注记（§6 注） |
| 地址族 | IPv4/IPv6 双载体（§9.24 对称） | T-001/T-011 已覆；对称缺格 → T-17 |
| 断言通道 | `iec60870_104.*` 6 字段 + `tcp.*`/`ipv6.*` 载体面 + frames hex（54/74 两档） | 全正例；`gec60870_asdu.*` 84 字段**未用**（基线误记更正，P5 评估 → A′ T-19） |

B′（引擎结构缺口 → D-IEC104-1「明确不解决 + 迁入计划」，见设计 §16 G-IEC104-3/5/6）：STARTDT 前 I 拒/S rx 核对/k-w 窗口/STOPDT 后拒/被控站主动 U/C_CS 对时/冗余切换/扩展 Type。

### 9.3 9.52 对账两行 + 清单出处声明

- **清单出处声明**：本清单来源 = **规范反推**（IEC 60870-5-104 公开帧定义；精确章节号待 G-IEC104-1），**非**引擎能力面反推（覆盖审计要求面记忆）。引擎侧只作现状取证：`iec104` 已注册（`registry.go:855`）/白名单（`protocols.go:40`）/builder+planner+层生成器已落码/16 例旧扁平形/tshark `iec60870_104.*` 6 + `iec60870_asdu.*` 84 字段实测/2404 自动解码实测/chain 未接线 16/16 红实测。
- **对账两行**：**规范逻辑点总数 = 50**（八项 8 行 + 帧型×方向矩阵 30 格 + 数据形态变体 14 行 − 不适用 2）；**用例覆盖数 = 31**（八项 8 行全有结论 + 矩阵已覆 18 − 不适用 1 + 变体已覆 11 − 不适用 2 + T-013–T-016 锚定变体 13（部分重叠）→ 按 ID 去重：12 正 + 4 负 = 16 ID 承载 31 点）；**不适用 = 2**（C_IC down、MSS 分段）；**B′/立项 = 17**（矩阵 11 格 + 变体 3 行 + 方向约束类 → G-IEC104-3/4/5/6/8）。31 + 2 + 17 = 50 ✓ 无遗漏。**反查 16/16 ≠ 覆盖全**——反查只证明清单内的点有例，本对账才证明清单本身全（§9.52 原文）。
- **粒度声明（防误读）**：按设计 §11 的行/格粒度计数；子面（QOI 范围/厂商 Type/回绕组合）另登 G 项，**不折进 50 点、也不冒充覆盖**。

### 9.4 3.14 豁免边界审计

- 本协议**有长连接**（单 TCP 会话多事务），`sessions[]` 由设计 §13.3 会话表显式声明——**不主张 sessions 豁免**（T-012 用 `strategy_fc`→`flow_control` + P4 `sessions[]` 显式化）。
- **多流并发**：已覆 T-012（三会话扇出隔离）。
- **单包多载荷**：单 ASDU 单对象（VSQ 恒 1）已覆（T-001–T-011）；多对象面 → B′（G-IEC104-6），非豁免逃逸。
- **TCP 分段面**：MSS 536 > APDU 253，协议上无分段面 → 显式记**不适用**（设计 §3 末；与"豁免 sessions≠豁免多流"不冲突——分段面≠多流面）。
- 结论：多流 / 单包多载荷 / 多包序列三项各有结论，无逃逸。

### 9.5 三源回指行

IEC 60870-5-104 公开帧定义（APCI/ASDU/TypeID/序号/STARTDT）→ **D-IEC104-1**（设计 §14）→ `trafficgen/test/protocol_pcap/cases/iec104.json`（16 例）。第三源"已确认现网行为"当前为**未确认级**（设计 §12.1 ②），挂 G-IEC104-1 且按 §5.5 不写死进实现。ID 权威 = 本文 §2（12 正 + 4 负）。

### 9.6 断言契约核对结论（与设计 §1/§9/§13 一致）

1. **16 ID 契约核对**：本文 §2 与设计 §7 逐 ID、逐序、逐类型、逐 `packet_count` 一致——12 正例（`[13,20,13,13,13,14,14,13,14,13,13,min39]`）+ 4 负例（`expect` 只有 `expect_error`/`error_contains`，锚词 `control/unknown type_id/APDU too long/IOA` 逐字对 planner 真实代码行）。
2. **存量审计（§9.14）**：见 §5 去向表。16 例现状同一旧扁平形（`layers=[{tcp:{}},{iec104:{}}]` 空条目 + 顶层四键 + 顶层 `iec104` 子映射 + 无 `flow_control` + 幽灵键 5 类），P4 按去向表逐例改写，**I 帧序号字节与时间后缀先跑后钉**（T-002/T-006/T-007）。
3. **断言通道核对**：`iec60870_104.*` 6 字段 + `tcp.*`/`ipv6.*` 实测可用；frames hex 两档 offset（54/74）实测；`iec60870_asdu.*` 本件未用（基线误记更正 → A′ T-19）。
4. **packet_count 纪律**：§2 的约定值随 P4 **先跑后钉**（§9.31/§14.6/§14.20），以落盘 pcap 实测校准；T-008 的 13 包已有落盘实证（`/tmp/mcp-pcaps/iec104/iec104_u_frames.pcap`），其余待 G-IEC104-9 接线后重跑。
