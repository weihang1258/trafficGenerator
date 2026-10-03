# probe_smb（SMB 轻量探测诊断族）测试用例契约

> 版本：v1.1.0（静态闭环）
> 日期：2026-10-01
> 机器契约：`trafficgen/test/protocol_pcap/cases/probe_smb.json`
> 本轮仅做三文件静态审计；未执行 suite/MCP/NIC，不宣称运行通过。

## 1. 测试原则与归属边界

用例从设计 §3–§13 逐项派生，共 **12 个唯一语义 ID**：9 个正例和 3 个负例。当前 JSON 已含 12 例；9 个正例采用层链目标形，3 个负例保留各自的非法顶层键或静态复制输入，专门验证拒绝规则。

**三条口径（防误读）**：

1. **诊断族不进覆盖率分母**：本族 ID 一律 `probe_` 前缀，`deep_audit.py:138-145` 已按 "diagnostics, not suite cases" 处置，明确"probe cases are not part of the 296-case suite"；smb 反查块（`coverage_gate.py` `check_smb`，归 #50 车道）不把本族计入分母。
2. **每例一个诊断目标**：本族不建命令/方言/错误码全矩阵（那是 `cases/smb.json` 296 例的职责），只建"层链接线回归 + 支路定向诊断"面。
3. **断言钉可观察输出**（9.43）：正例断言 `packet_count` + `smb2.cmd` 序 + `smb2.msg_id` + `smb2.nt_status` + 载体端口；**不许**只断言"任务没失败"。负例 `expect` 严格两键 `{"expect_error","error_contains"}`，锚词逐字取自实读代码（§4）。

**运行归属**：`flowb_run_protocol_suite` 的 proto 过滤按 **case 字段**（`internal/mcp/tools_testdrive.go:814-816`），故 `CASE_PROTO=smb` 会连带加载本文件（`smb.json` 296 + 本文件 12 = 308 例）；单跑本族用 `CASE_PROTO=probe_smb`。

## 2. 原子用例索引

| # | ID | 类型 | 覆盖（诊断目标） | 约定 packet_count |
|---:|---|---|---|---:|
| 1 | `probe_explicit_close` | 正 | 显式单 close：CLOSE 恰一对，无隐式重复（存量例迁移） | 25 |
| 2 | `probe_default_session` | 正 | 零负载默认保底会话（默认单 read + 隐式 CLOSE） | 29 |
| 3 | `probe_ops_multi_round` | 正 | 同连接多轮操作 read→write→close | 31 |
| 4 | `probe_error_on_close` | 正 | 非正常结束：`error_on_command=close` 注入后拆解继续 | 25 |
| 5 | `probe_echo_liveness` | 正 | 同连接多轮 ECHO（0x000D）活性探测 | 29 |
| 6 | `probe_netbios_139` | 正 | 139 NetBIOS Session Service 载体 | 29 |
| 7 | `probe_ipv6_session` | 正 | IPv6 载体独立 fixture | 29 |
| 8 | `probe_multi_flow_dynamic` | 正 | 多流（flows=2 + 端口动态对象） | 58 |
| 9 | `probe_neg_flat_keys` | 负 | 顶层扁平键判死 | — |
| 10 | `probe_neg_layers_flat_mix` | 负 | `layers` + 顶层四元组混用判死 | — |
| 11 | `probe_neg_static_copy` | 负 | 静态复制判死（flows>1） | — |
| 12 | `probe_pcap_nic_consistency` | 正 | pcap / NIC 双输出一致 | 25 |

**当前 JSON 对账（2026-10-01）**：12 例 = 9 正 + 3 负；正例包数按 JSON 实际值为 25/29/31/25/29/29/29/58/25（多流例 58 = 2×29），负例均仅含 `expect_error` 与 `error_contains`。

## 3. 正例逐项断言契约

1. **`probe_explicit_close`**：严格层链形（`layers` 三段，业务键位于 `layers[].smb`）；断言 `tcp.dstport=445`、`smb2.cmd` 序含 0（NEGOTIATE）/1×6（SESSION_SETUP 双向一轮一对）/3（TREE_CONNECT）/5（CREATE）/**6 恰一对**/4（TREE_DISCONNECT）/2（LOGOFF）；`smb2.msg_id` 单调递增；`frames` 钉 CLOSE 体首字段 offset 122（请求 `18 00 00 00 00 00 00 00` / 响应 `3c 00 00 00`）；`packet_count=25`（P5 复算）。
2. **`probe_default_session`**：`layers[].smb` 空负载 `{}` → 走引擎缺省（默认单 read 4096，`validate.go:307-309`）；断言八阶段全序 + READ(0x0008) 恰一对 + CLOSE 恰一对（隐式保底，不得双发）；`packet_count=29`。
3. **`probe_ops_multi_round`**：`operations=[read,write,close]` 三操作同连接；断言 `smb2.cmd` 依次出现 8、9、6（各一对）且 msg_id 连续不退（8→9→6 方向正确、无重置）；`packet_count=31`。
4. **`probe_error_on_close`**：`error_on_command="close"` + `error_response_status` 非零；断言 CLOSE 响应帧 `smb2.nt_status` 非零、CLOSE 对**恰一**（错误命令即该 CLOSE，不得再补隐式）、其后仍有 TREE_DISCONNECT(4) 与 LOGOFF(2)；`packet_count=25`。
5. **`probe_echo_liveness`**：`operations=[echo,echo]`；断言 `smb2.cmd=13`（0x000D）恰两对、msg_id 递增、会话不重协商（无第二条 NEGOTIATE）；`packet_count=29`。活性声明：本生成器不产 TCP keepalive 探测包，活性由会话内 PDU 轮次体现。
6. **`probe_netbios_139`**：`smb.transport="netbios"`；断言 `tcp.dstport=139`（缺省化 `chain_planner.go:1249-1258`）+ 与 445 例同一 PDU 序；`packet_count=29`。
7. **`probe_ipv6_session`**：使用 `ip` 层承载 IPv6 字面量（注册表没有独立 `ipv6` 层），断言 `ipv6.src/dst` 与 SMB2 NEGOTIATE；本 fixture 未钉 NBSS/SMB2/CLOSE 偏移 frames；`packet_count=29`。
8. **`probe_multi_flow_dynamic`**：`strategy_fc.flows=2` + `layers[].tcp.src_port` **动态对象**（9.39：flows>1 时静态标量必被拒）+ 固定 `group_id`；断言 `tcp.stream` 两条 distinct、每流会话八阶段完整、每流 `smb2.msg_id` 各自从首值起算（不跨流续号）；`packet_count=58`（2×29）。
9. **`probe_pcap_nic_consistency`**：同 fixture 走 `output_type=pcap` 与 `port_group + nic_capture` 两路；断言两路 `smb2.cmd` 序、载体端口、包数一致，并记录 NIC 面 checksum offload 与 `nbss.length` 口径；`packet_count=25`。

**所有正例共用的断言纪律**：`directional=true`（请求上/响应下成对）；断言以 `smb2.*`/`nbss.*` 实测存在的字段为限（设计 §17 列名）；`frames` 只钉稳定字节（CLOSE 体 StructureSize/Flags/Reserved），不钉随机 FileId（GUID 随机，`validate.go:311-313`）。

## 4. 负例契约

每个负例必须在建策略/建任务处被拒并传播为 task error；不得产出成功 PCAP、`completed/0 packet` 或只剩 TCP 外壳的假成功。`expect` 键集合严格为 `{"expect_error","error_contains"}`，锚词逐字取自下列实读位置：

| # | ID | 故障输入 | 目标 `error_contains` | 锚词出处（实读） |
|---:|---|---|---|---|
| 9 | `probe_neg_flat_keys` | 顶层 `src_ip`（存量例原文形状） | `no longer accepts flat config field src_ip` | `internal/core/strategy_convert.go:8641-8644`（`CheckProtoFlat`，函数起点约 `:8634`，经 `schema/semantic.go:131` 进入） |
| 10 | `probe_neg_layers_flat_mix` | `layers` + 顶层 `src_port` 并存 | `config mixes layers with flat four-tuple field src_port` | `internal/core/schema/semantic.go:186-190` |
| 11 | `probe_neg_static_copy` | `layers` 内静态标量四元组 + `flows=2` | `layers pin a static four-tuple but flows > 1` | `internal/core/schema/semantic.go:138-145`（静态复制函数 `:198`） |

**错误面去向**：`op_type` 非法与 `auth_rounds` 越界分别由 `smb_tneg_T233_optype_invalid` / `smb_tneg_T230_rounds_oob` 覆盖；两 ID 实测存在于 `cases/smb.json`（279 正 + 17 负，共 296）。

presence 负例 `probe_neg_flat_keys` 与 `probe_neg_layers_flat_mix` 保留为框架拒绝规则证据：前者是层链加顶层游离 `src_ip`，后者是层链加顶层游离 `src_port`；二者均不得清理或改写为正例。SMB 顶层同名子映射的 presence 判死已有真实锚点 `internal/core/strategy_convert.go:8829-8833`，并由 `internal/core/layers/smb_chain_test.go:247-248` 交叉印证，因此 G-PROBE-SMB-2 关闭，不登记缺口。

合法的目标形仅保留 `layers[].smb` 业务键；判死对象是扁平五键、白名单外游离键及顶层协议子映射。

## 5. 存量审计（CORE_MEMORY 9.14）

当前 JSON 已含 12 例；下表保留迁移前唯一存量例的审计快照：

| 存量 ID | 现形状 | 去向 | 理由 |
|---|---|---|---|
| `probe_explicit_close` | 迁移前扁平形快照：顶层 `src_ip/dst_ip` + 顶层 `smb` 子映射，无 `layers`，`expect` 仅 `{"packet_count":24}` | **改写合入**（现为本族编号 1，严格层链 + 全字段断言） | 形状已违规且包数已按现 JSON 重钉为 25；不再作为当前存量形状 |
| 其 `packet_count: 24` | 过期值 | **作废重钉** | 与同形 smb 存量例 pin 25（`smb_tpos101_close`）矛盾；24 = legacy 3 包握手/挥手时代的残值（链上 TCP 生成器为 4 包拆解，`tcp.go:330-400` 实测 4 帧）。换分支 commit `34a52d4` 曾改 24→25 并判"probe_smb 漏同步"，但**该 commit 不在 HEAD**（`git branch --contains 34a52d4` 仅 `feat/68-hl7`）。P5 先跑后钉（9.31） |

**无其它存量可审**：迁移前文件仅 1 例；当前 JSON 已扩为 12 例。`cases/smb.json` 296 例归 #50 smb 车道（本族不搬运、不代审）。legacy 单测面（`internal/protocol/smb/*_test.go`）保留为回归面，不计入本族覆盖。

## 6. 三源回指与 9.52 对账

**三源回指（9.2/9.3/9.4，缺一不可）**：

| 源 | 本族内容 | 回指行 |
|---|---|---|
| ①规范/官方文档（9.2） | MS-SMB2：会话八阶段状态机、SYNC 头 64B、CLOSE 请求体（StructureSize=24）/响应体（=60） | 设计 §4/§7；`07-smb-design.md:140/479-500/751-757` |
| ②设计条目（9.3） | D-PROBE-SMB-1（§15）+ 本族契约（§2–§13） | 设计 §15；本文 §2/§3/§4 |
| ③现网/实测（9.4） | tshark 3.6.14 字段实测（`smb.` 652 + `smb2.` 533 = 1185；`nbss.*` 10）；smb 存量 pin 25/27；`deep_audit.py:127-152` 伪影定性；生成器 emit 序实读 | 设计 §7/§13/§17；本文 §2/§3 |

**9.52 对账两行**：

- **规范逻辑点总数 = 24**（probe 家族口径，逐面列举）：会话状态机八阶段 **8**（NEGOTIATE/SESSION_SETUP/TREE_CONNECT/CREATE/Operations/CLOSE/TREE_DISCONNECT/LOGOFF）+ CLOSE 支路 **3**（显式/隐式保底/错误注入抑制）+ 载体 **2**（445/139）+ 地址族 **2**（IPv4/IPv6）+ 多流 **1** + 双输出 **2**（pcap/NIC）+ 活性 **1** + 形状执法 **3**（扁平键/混用/静态复制；presence 判死已有代码锚点）+ 错误面 **2**（op_type/rounds）= **24**。
- **用例覆盖数 = 22 建例代表 + 2 归 smb 套件 = 24/24 对账平**。分项：八阶段 8→由编号 1/2 全序代表；CLOSE 3/3→编号 1/2/4；载体 2/2→编号 6（139）+ 其余例（445）；地址族 2/2→编号 7（IPv6）+ 其余例（IPv4）；多流 1/1→编号 8；双输出 2/2→编号 12（NIC）+ 全部（pcap）；活性 1/1→编号 5；形状执法 3→建例编号 9/10/11（presence 判死为代码证据，不另立项）；错误面 2→归 smb 套件 2 例（T233/T230）。

**台账粒度声明（防误读）**：上表按"行为面"计数（一个面一行），不按用例数计数；同一用例可代表多个面（如编号 1 同时代表八阶段与 CLOSE 显式面）——**面内子格缺口不得折进分母**。命名的文件级默认操作（空 `operations` 走默认 read）与方言/命令全矩阵**不在本族口径内**，其计数归 `cases/smb.json` 台账。

**清单出处声明**：本对账清单出处＝**MS-SMB2 会话状态机与 CLOSE 体结构 + 本仓库 smb 生成器 emit 序反推**（设计 §4），**非**从现有用例反查得来；probe 家族的口径是在 smb 全矩阵之上做"诊断族裁剪"，裁剪判据见设计 §5 分工表。

## 7. A′/B′ 两分类表与 §3.15 三项

**A′（补建例，覆盖缺口 → 例号）**：

| 编号 | 缺口面 | 补例 |
|---|---|---|
| A′-1 | 同连接多轮操作面（3.15①） | 编号 3 `probe_ops_multi_round` |
| A′-2 | 非正常结束面（3.15②） | 编号 4 `probe_error_on_close` |
| A′-3 | 长保活/活性面（3.15③） | 编号 5 `probe_echo_liveness` |
| A′-4 | 139 载体面 | 编号 6 `probe_netbios_139` |
| A′-5 | IPv6 地址族对称面（9.24） | 编号 7 `probe_ipv6_session` |
| A′-6 | 多流并发面（9.49） | 编号 8 `probe_multi_flow_dynamic` |
| A′-7 | 双输出一致性面（14.16） | 编号 12 `probe_pcap_nic_consistency` |
| A′-8 | 零负载默认路径面 | 编号 2 `probe_default_session` |

**B′（注记/立项，不建例 → 去向）**：

| 编号 | 边界面 | 去向 |
|---|---|---|
| B′-1 | 独立 `probe` 层/协议 | 裁定 P1 **归并 smb**（设计 §1.1 三问实读），立项面＝无 |
| B′-2 | SMB3 加密（TRANSFORM_HEADER 52B）下的 probe 面 | 已归 `cases/smb.json` 加密套件覆盖；probe 诊断族不重复建例 |
| B′-3 | compound / 多 PDU 并入一条 NBSS | 当前生成器一 message 一 PDU；若需编排，新增 smb 套件用例与代码缺口 |
| B′-4 | TCP 层 keepalive 探测包 | 注记（生成器不产；`tcp.go` 只用 SYN/ACK/PSH\|ACK/RST/FIN\|ACK） |
| B′-5 | SMB3 多通道（Multichannel）派生副流（3.8 关联面） | 注记：本生成器单连接，`driven_by` 不适用；接多通道时另立条目 |
| B′-6 | presence 判死 | `probe_neg_flat_keys` 与 `probe_neg_layers_flat_mix` 保留为故意的框架 flat/游离键负例；presence judge 已由 `strategy_convert.go:8831-8833` 独立核实，G-PROBE-SMB-2 关闭 |
| B′-7 | 现网真客户端探测形态 | 立项 **G-PROBE-SMB-5**（待确认：抓现网 445 首会话 pcap） |

**§3.15 三项落表**（每项一例或一立项，无例无项即缺口）：

| 项 | 落地 | 断言要点 |
|---|---|---|
| ①同连接多轮操作 | 编号 3 | 同一 `tcp.stream` 内 0x0008→0x0009→0x0006 各一对，msg_id 连续 |
| ②非正常结束 | 编号 4 | `smb2.nt_status` 非零 + 拆解阶段仍完整（0x0004/0x0002 仍在） |
| ③长保活 | 编号 5 | 同连接多轮 0x000D，无重协商；TCP keepalive 不产生（注记 B′-4） |

## 8. 三方一致性与静态检查

1. 设计 §13 表、本文 §2 表、注册后的 `cases/probe_smb.json` 必须保持同一 12 个唯一 ID、同一顺序（9 正 + 3 负）；当前 JSON 已满足。
2. 9 正例均有 `packet_count` + `directional` + 稳定字段断言；3 负例 `expect` 只含 `expect_error` + `error_contains`。
3. 固定偏移：IPv4 NBSS 起点 54 / SMB2 头 58 / CLOSE 体 122；若按 IPv6 帧布局推导，三者分别为 74 / 78 / 142；本族 IPv6 fixture 未用 `frames` 断言这些偏移。
4. 动态值（FileId GUID、ClientGuid、SessionId）用 `presence`/`nonzero`/`distinct_values`，禁止硬编码随机常量。
5. 断言字段只用实测存在的 `smb2.*`/`nbss.*`（设计 §17 列名），不自创字段名。
6. `python3 -m json.tool trafficgen/test/protocol_pcap/cases/probe_smb.json` 应成功；改写后每例 `proto="smb"`、ID 以 `probe_` 开头。
7. 门 2-1 口径：非负例的 `spec_json` 顶层键只允许 `layers`/`flow_control`/`group_id` 等结构键；业务键全部位于 `layers[].smb`，扁平五键与顶层协议子映射零残留。

## 10. T1-T6 静态迁移审计

| ID | 结论 | 证据 |
|---|---|---|
| T1 | 12 个 ID 唯一、顺序与 JSON 一致且 JSON 可解析 | `probe_smb.json` 机读对账 |
| T2 | 9 个正例使用严格 `[ip,tcp,smb]`；负例仅保留故意违规输入 | 全量 `spec_json.layers` 审计 |
| T3 | 3 个负例 `expect` 严格为 `{expect_error,error_contains}` | 键集合审计 |
| T4 | 地址/端口/业务字段分别住 ip/tcp/smb 层；多流动态端口不静态复制 | 全量字段审计；`probe_multi_flow_dynamic` |
| T5 | 旧 flat 存量例已迁移；SMB registry、planner、translate 已有接线 | 设计 §1/附 A，代码静态回指 |
| T6 | 本轮只改三文件，未执行 suite/MCP/NIC，不能把静态闭环写成运行通过 | 任务边界 |

## 11. 六项覆盖清单（C1-C6）

| ID | 覆盖要求 | 当前结论 |
|---|---|---|
| C1 | 12 条 JSON 清单、ID、顺序、解析 | 12/12 静态一致 |
| C2 | 严格层链、旧 flat 审计、三负例双键 | 9 正例目标形正确；3 负例保留单一故障 |
| C3 | 八阶段与 close/default/multi-round/error/echo/139/IPv6/multi-flow 行为面 | 9 正例逐项对应 §2–§3 |
| C4 | 负例锚词与失败传播 | 3/3 锚词静态回指；未真实建任务验证 |
| C5 | SMB 代码接线与不新增 Go/schema | registry/planner/translate 已接线；本轮无代码改动 |
| C6 | pcap/NIC 双输出契约 | 编号 12 共用断言；本轮未跑双输出 |

## 12. 静态闭环结论

旧 flat 存量、9 例正例目标层形、3 个严格双键负例和 SMB 代码接线均已静态对账；运行证据（suite/MCP/NIC/PCAP）留待后续 P5，不在本轮范围内。

## 13. 与 smb 联验清单（P5 必做，与设计 §17 同表）

| # | 联验项 | 判据 |
|---|---|---|
| J1 | 同批加载：`CASE_PROTO=smb` 应加载 308 例（296 + 12） | `tools_testdrive.go:814-816` 按 case 字段过滤；结果 `total` 含本族 12 例 |
| J2 | close 族包数对账：编号 1 vs `smb_tpos101_close` | 两落盘 pcap 包数一致（复算后的同值）；不等即一条错 |
| J3 | 错误注入对账：编号 4 vs `smb_terr132_close_error` | CLOSE 对各 1 对 + 拆解完整 |
| J4 | 偏移对账：CLOSE 体 offset | 与 smb close 族 frames 同偏移（IPv4 122） |
| J5 | 反查归属：`coverage_gate.py` `check_smb` | 归 #50 车道；本族 12 例不进分母，出口仍须 0 |
| J6 | 伪影口径：probe 帧 NTLMSSP 越界读 | `deep_audit.py:127-152` 定性对改写后帧仍成立（notes 声明） |
| J7 | 迁移顺序：目标形（`layers[].smb` 业务键） | 当前 JSON 已使用目标形；SMB registry/planner/translate 接线已有静态证据，运行复跑留待 P5 |

## 14. 实现后执行建议

1. 直接使用严格层链形状；`cases/probe_smb.json` 12 例的业务键均位于 `layers[].smb`，负例锚词按 §4 填。
2. 跑法：`cd trafficgen/test/protocol_pcap && CASE_PROTO=probe_smb go test . -run TestProtocolPcapDrive -count=1 -timeout 20m`；联验批用 `CASE_PROTO=smb`（308 例）。
3. **先跑后钉**（9.31/14.20）：包数、`smb2.msg_id` 首值、frames 偏移一律从落盘 pcap 取；尤其编号 1 的 24↔25 争议必须先复算再改 `expect`。
4. 负例先验红：三负例必须先确认今日确被拒且锚词命中（`probe_neg_flat_keys` 用存量例原文即可复现红）。
5. 全量而非增量：本文件 12 例应全量执行；本轮未运行 suite/MCP/NIC，不能宣称全绿。联验批 J1–J7 逐项落档。
6. 服务器二进制须与 HEAD 同代（14.18/门 2-3）；跑批前确认 `/tmp/mcp-pcaps/smb/` 已清（避免旧 pcap 冒充新产物）。

## 15. 修订记录

- v1.1.0（2026-10-01）：对账当前 12 例严格层链 JSON，更新 SMB 套件总量 296、联验总量 308、实际包数与 presence 判死状态。
