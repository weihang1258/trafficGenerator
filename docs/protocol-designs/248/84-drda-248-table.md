# DRDA（D-DRDA-1 #84）P6 248 条款逐条比对表

> 口径：docs/CORE_MEMORY.md（2026-09-27 读；行号体裁同 enip#56 248 表）。落点=drda#84 实测证据（P5 lane-green suite 13/13＋P6 隔离终审独立重跑 13/13、链级红例 8/8 离线、反查 51/51；P1 门2-3 已在新 canonical 二进制上复验转绿→closed）→ P6 判词：通过（1 P1 closed＋4 M open，主线程裁定见下）。判定：PASS=满足，GAP(n)=缺口编号（open follow-up），NOTE=注记，N/A=单载体无此面（有结论非缺口）。
> 文档面：design v1.0.0＋testcase v1.0.0（门1 获批 D-DRDA-1，冻结零改动）；终态 13 例=9 正＋4 负（A′ T-11 chained 已入 suite 为第 9 正例；新增 presence＋端口契约为第 3/4 负例）。
> 主线程裁定（本表据此标去向）：M1 `session_start` 已删（本轮落地）（死配置，planner/builder/layer_gen 零引用，design §14 权威）；M2 `sql.statement` 已删（本轮落地）（零消费，无 CPSQLSTT 发射点）；M3 离线执行器 ip 层→framework backlog；M4 三未覆盖面（security_token 编码／correlator_inc≠1／dss_segments 多段）→open follow-ups。G-DRDA-4 本车道 closed（CheckProtoFlat＋ValidationErrors）；`transport` legacy 别名有消费保留（planner.go:174-179）；G-DRDA-3/5 保持立项。

| 条款 | 要求 | drda 落点 | 判定 |
|---|---|---|---|
| 1.1 | 地址只写 ip 层 | 9 正例 `layers[i].ip.src/dst`（192.0.2.84→198.51.100.84；#7 IPv6 同住 ip 层）；无顶层地址键 | PASS |
| 1.2 | 端口只写 tcp/udp 层 | `tcp.src_port=12345` 显式；`tcp.dst_port` 缺省由 drda 层 FieldContract 补 446 | PASS |
| 1.3 | 流数量只写 flow_control | 9 正例顶层键机核穷尽=`[flow_control, layers]`（cases/drda.json 机读） | PASS |
| 1.4 | 禁 layers 与顶层五键混用 | 门2-1 绿（无顶层旧键残留）；链例 `PresenceAndStrayTopLevelKeys`（顶层空 drda 子映射＋五游离键判死） | PASS |
| 1.5 | 混用示例/用例/文档都算跑偏 | 无混用示例；design v1.0.0 样例为纯 layers（§2.1） | PASS |
| 1.6 | 门①层链能跑通 | suite 13/13（P5 lane-green＋P6 canonical 8081 独立重跑 6.51s） | PASS |
| 1.7 | 门②旧格式彻底移除 | 过渡形（顶层七键）10 例全改写；presence 判死两路（strategy_convert.go:8693-8698／:476-480） | PASS |
| 1.8 | 示例只给严格层链形 | 用例 spec_json 全严格层链形（13/13；链形 `[ip,tcp,drda]`，负例 `[ip,udp,drda]` 为判死形状） | PASS |
| 1.9 | 暂不支持时标注目标形状 | G-DRDA-3/5 立项＋notes 披露（现网确认／失败终止与重连） | PASS |
| 1.10 | 汇报分开说跑通/清旧字段 | p4-report §2（suite）/§4（用例改写）/§8（自审）分节 | PASS |
| 1.11 | 顶层白名单（layers/flow_control 家族/output） | 正例穷尽断言；唯一并存=`drda_neg_presence_top_level_drda`（判死负例形状，14-P2 口径） | PASS |
| 1.12 | 无可住层时立项补层，不许豁免 | 业务三键已得层（registry.go:718-731：＋association/dss_length/sessions，G-DRDA-1 本车道关闭）；无"登记保留"豁免 | PASS |
| 1.13 | 门2①按白名单执行 | 同 1.11；pipe_gate.sh presence 红线已登记 drda | PASS |
| 2.1 | 策略=单模板自带 flow_control | `flow_control.flows=1`（9 正例显式）；drda 不在 worker/task 特判名单 | PASS |
| 2.2 | 任务=多策略合跑+总量封顶 | 框架语义未动（suite 走策略路径） | PASS |
| 2.3 | 策略先限速任务再封顶 | 未动 | PASS |
| 2.4 | 任务 ID={taskID}-{strategyID} | 未动 | PASS |
| 2.5 | flows=N 复制 N 条 | 未动；drda 语料未开 flows>1（见 12.4） | PASS |
| 2.6 | spec 不管数量 | 未动 | PASS |
| 2.7 | 按流变化走动态字段 | 四元组动态住 ip/tcp（framework）；drda 业务键多值动态未开例（M4） | NOTE(M4) |
| 2.8 | 未写动态 src_port 保底 12345+i | 框架既有语义；#8 双会话显式 12345/12346 | PASS |
| 2.9 | 其余按流变化必须写动态 | testcase §6.2 业务清单（correlator_start/inc 开、association 不开等）；零用例面诚实缺口（M4） | PASS/M4 |
| 2.10 | 讲数量分清策略复制/任务封顶 | p123 门1 §2 行 | PASS |
| 2.11 | 讲变化动态按 §12 | 本表 12.x | PASS |
| 3.1 | 多会话 sessions[]/flows[] 显式 | `sessions=[{id:s1,…},{id:s2,…}]` 显式（#8，18 包=9+9） | PASS |
| 3.2 | 每会话独立 ID/四元组/生命周期 | s1/s2 各自四元组（srcport 12345/12346，dstport 恒 446）＋correlator 各从 1 起＋独立状态机 | PASS |
| 3.3 | 会话内事务有序序列 | EXCSAT→ACCSEC→SECCHK→ACCRDB→SQLDTA 有序（#4 五轮；correlator 逐对递增且请求响应同值） | PASS |
| 3.4 | 事务前置条件 | design §4 状态机（EXCHANGED→…→RDB_ASSOCIATED） | PASS |
| 3.5 | 触发动作 | association 四档截断（excsat/security/database/sql，planner.go:154-223 实读） | PASS |
| 3.6 | 成功分支 | SQLCARD SQLCODE=0＋SQLSTATE"00000"（#4，offset 64 参数字节钉） | PASS |
| 3.7 | 失败分支 | SQLCODE=-204＋SQLSTATE"42704"应用错误不断链（#5）；4 负例 task error 锚；SECCHKRM/ACCRDBRM 失败终止→G-DRDA-5 | PASS |
| 3.8 | 控制关联数据流显式字段 | 单载体无副流：N/A（差异声明；correlator 请求/响应配对逐对断言替代） | N/A |
| 3.9 | 关联写清会话/事务/决定字段 | correlator 配对（same_as_packet 逐对）＋#8 会话隔离；无 from_response 面（单载体） | PASS |
| 3.10 | 被关联流独立 ID/四元组/握手 | 无副流（单载体），不适用 | N/A |
| 3.11 | 各流顺序/并发/交错写清 | session 顺序确定性输出（#8 先 s1 后 s2）；流内请求/响应严格配对 | PASS |
| 3.12 | 可交错写清调度+时间戳 | 无交错面（sessions 顺序展开） | N/A |
| 3.13 | 不许连续重复冒充编排 | 关联四阶段＋SQL 编排（1→3→4→5 轮递进）非模板重复 | PASS |
| 3.14 | 无长连接豁免≠多流豁免 | 有长连接载体（TCP 446 单连接四阶段＋SQL 多轮），不主张豁免；单包多载荷由 T-11 chained（format 0x41）覆盖 | PASS |
| 3.15 | 多轮/非正常结束/长保活各一例或立项 | ①多轮 #4（5 轮）②非正常结束 #5/#9/#10＋SECCHKRM失败→G-DRDA-5 ③长保活 #4/#5 形状＋reconnect→G-DRDA-5 | PASS |
| 3.16 | CWMP 范本照补 | 差异声明：无 driven_by（单载体无副流） | PASS |
| 3.17 | 多流设计五件套 | testcase §6.1 设计映射（会话表/事务序列/关联/插入/时间线） | PASS |
| 4.1 | 连接模型 | design §2（TCP 446 单载体，DDM 即数据段） | PASS |
| 4.2 | 命令/消息表 | design §3.3（11 码点表，builder.go:8-22 常量实读） | PASS |
| 4.3 | 状态机 | design §4（CLOSED→…→RDB_ASSOCIATED→CLOSED） | PASS |
| 4.4 | 字段表 | design §3.1/§3.2（DDM 头 10 字节逐字段＋参数 TLV） | PASS |
| 4.5 | 错误处理表 | design §7（V1–V6）＋用例面 4 负例锚 | PASS |
| 4.6 | 超时与活性 | 设计未单列超时节；活性面=每正例正常终止（terminates 9/9 true，FIN-ACK 四way） | NOTE(未单列) |
| 4.7 | NAT/代理/被动 | 设计未声明（无面，未主张） | NOTE(未声明) |
| 4.8 | 版本/方言 | DRDA V5 Vol.1–3；CCSID 1208 vs EBCDIC→G-DRDA-3 | PASS/G3 |
| 4.9 | 有 RFC 查 RFC 注章节 | 无 RFC：The Open Group DRDA V5 Vol.1–3（design §10 各条＋节号） | PASS |
| 4.10 | 无 RFC 以官方规范为准 | 同上（章节级落点 design §10） | PASS |
| 4.11 | 不许博客二手代替原文 | p123 三路对照（官方文档＋DB2 现网形态＋dissector 实测） | PASS |
| 4.12 | 规范原文 | design §10 逐表（29 逻辑点口径见 9.52） | PASS |
| 4.13 | 商业软件实际行为 | IBM DB2 Connect 行为形态（未确认级→G-DRDA-3，不冒充） | PASS/G3 |
| 4.14 | 可靠开源实现思路 | Wireshark packet-drda.c dissector（18 字段断言通道，不搬码） | PASS |
| 4.15 | 三路不一致取舍写清 | design §3.4：实现侧参数码点与 dissector 展示名对应关系 P4 抓包钉死，不编造映射表 | PASS |
| 4.16 | 商业行为逐条映射用例号 | testcase §5 三源回指行 | PASS |
| 4.17 | 关键决策候选方案对比表 | p123 P1-R1（A 声明式回放／B 生 hex／C 完整 DDM 编译器） | PASS |
| 4.18 | 不许单方案自说 | 同上三方案优劣＋结论 | PASS |
| 4.19 | 每表格行/字段/错误码三选一 | design §10 矩阵（8 行＋请求×响应 7 格＋变体 14 行）；用例面 13 例承接 | PASS |
| 4.20 | 每条目对应至少一用例 | 29 点 24 覆＋5 立项（B′逐个去向 G-DRDA-1/3/5） | PASS/B′ |
| 4.21 | 动手前缺口矩阵 | p123 门1 表＋G-DRDA-1–5 | PASS |
| 4.22 | 三张子表齐 | design §10.1/§10.2/§10.3 | PASS |
| 4.23 | 设计评审先看矩阵 | 门1 获批（D-DRDA-1 定稿） | PASS |
| 4.24 | 规范实现冲突先改实现 | 旧 planner 响应无参数→layer_gen 语义收敛（P4 修钉）；显式 5000 静默放行→回填块修复（P5 探针实红） | PASS |
| 5.1 | 设计写明依赖 | `DependsOn ["tcp"]`（registry.go:718）＋design §5 | PASS |
| 5.2 | 写明出错处理 | V1–V6（§7）＋端口契约域校验（planner.go）＋载体校验（complete.go:465） | PASS |
| 5.3 | 无依赖/错误分支不许实现 | 有（依赖＋六分支全有出处） | PASS |
| 5.4 | 无依据不许定字段流程缺省 | 端口 446（FieldContract）／11 码点／六参数名（text2pcap＋tshark 实测）均有出处 | PASS |
| 5.5 | 不确定标待确认+确认方式 | G-DRDA-3（抓包级确认，不挡开工，不写死） | PASS |
| 5.6 | 回答结论指章节/代码行 | p6 (a)(e)(f) 逐条 HEAD 行号（registry.go:718-731／planner.go:35,42,46／strategy_convert.go:8693-8698 等） | PASS |
| 5.7 | 指不出直说不知道 | 未覆盖面诚实声明（p4 §9.5＝p6 (f)⑤：token 未消费／inc 零用／多段无专例） | PASS |
| 5.8 | 回复前自查出处 | p4-report §8 自审 4+3 轮 | PASS |
| 5.9 | 抽查三条定位不到打回 | 门3 三条 ≡ p6-review (a)（三条均点行/例号，零漂移打回） | PASS |
| 6.1 | 性能目标/预算/边界 | design §6（O(n) 流式，emitSegments 逐段 emit，out 缓冲 32） | PASS |
| 6.2 | 六指标列全 | 吞吐数字诚实待基准（§6.5 不写承诺数字） | PASS |
| 6.3 | pcap/NIC 分别验收 | pcap 路：9 正例 pcap＋2 负 `.neg.pcap` 落盘＋suite 全绿；**NIC 路本轮未跑** | NOTE |
| 6.4 | 性能依据结合实现路径 | 逐段 emit、无全量聚合（layer_gen.go／旧 Plan()） | PASS |
| 6.5 | 无依据数字标待确认 | 已标（§6 数字待 P4 基准） | PASS |
| 6.6 | 六类性能场景 | 清单未跑基准 | NOTE |
| 6.7 | 断言实际指标不只无报错 | packet_count 9 例＋字段/frames 双钉（含 SQLCARD offset 64 参数字节） | PASS |
| 6.8 | 超预算仍不合格 | 无预算基线（待定） | NOTE |
| 7.1–7.3 | 三份文档定位 | design＋testcase＋D-DRDA-1；未碰 CODE_DESIGN/TEST_CASES | PASS |
| 7.4 | 历史文档保留参考 | 29-* 不删除（testcase §8.6／design §13.2 去向审计） | PASS |
| 7.5 | cases 是产物回指编号 | 13 例回指 T-DRDA-001–010＋T-11＋2 新增负例 | PASS |
| 7.6–7.7 | 三者关系/冲突序 | 门1 获批=定稿=开工门 | PASS |
| 7.8–7.9 | 先核心→设计→用例 | 门1 先行（P1–P3 先于 P4/P5） | PASS |
| 8.1 | 八要素（文件/接口/结构/流程/错误/性能/冲突/回滚） | design §11（D-DRDA-1，门1 获批=定稿） | PASS |
| 8.2–8.8 | 同上逐项 | §11（translate 加 case／Meta 直传／回滚=纯加法可删） | PASS |
| 8.9 | 未定稿不开工 | 门1 获批=开工（P4 基线 9bc0c2a＞门1 批） | PASS |
| 8.10 | 需求变先改设计 | A′ T-11＋端口契约域校验均为设计 §2.1/§7 口径内动作 | PASS |
| 8.11 | 不许代码先行文档后补 | P1–P3 先行 | PASS |
| 8.12–8.13 | 开工贴条目/无条目打回 | D-DRDA-1 条目在案 | PASS |
| 9.1 | 用例登记（回指编号） | testcase §2（ID 权威；顺序/类型/packet_count 与 design §9 逐值一致） | PASS |
| 9.2–9.4 | 三源（规范/设计/现网） | DRDA V5＋D-DRDA-1＋DB2 形态（未确认级→G-DRDA-3）＋tshark 18 字段 | PASS |
| 9.5 | 每行每字段每错误码有用例 | 11 码点 #1–#5 逐值；DDM 头 6 子面 #1/#6；V1–V4 有例、V5/V6→G-DRDA-5/边界 | PASS/B′ |
| 9.6 | 一例一行为 | 13 例无重复 id（机核） | PASS |
| 9.7 | 修 bug 先复现变红 | P5 端口契约探针实红（显式 5000 静默放行 9 包）→修回填块＋补链级红例与用例；P4 translate 注释谎称严格解码→修 | PASS |
| 9.8 | 数据场景六变体（正常/边界/空值/超长/非法/大小端） | 边界（dss_min_length 10/4）＋非法（4 负例）＋大小端（SQLCODE 有符号 U32 BE：0／0xffffff34）＋空 data 产 4 字节空参数 | PASS |
| 9.9 | 业务场景序列/乱序/中断/交错 | 四阶段序列＋#5 应用错误不断链；乱序/中断（RM 失败终止）=G-DRDA-5 | PASS |
| 9.10 | 现网场景；复杂度 9.50 下限 | DB2 标准序 #1–#5；复杂度见 9.50 | NOTE(9.50) |
| 9.11 | 多动作组合流≥2 条×≥3 动作 | #2（3 轮）/#3（4 轮）/#4（5 轮）≥2 条 ✓ | PASS |
| 9.12 | 清单先行 | P1 矩阵先行（p123 门1 §2） | PASS |
| 9.13 | 清单无遗漏是目标 | 5 立项登记在案（24＋5＝29 ✓） | PASS |
| 9.14 | 存量逐条审计去向 | testcase §8：10/10 合入零作废＋新增 3 例（T-11/presence/端口契约）=13 | PASS |
| 9.15–9.19 | A/B/C 三分类 | A′ T-11 已覆入 suite；B′ G-DRDA-1 closed／G-DRDA-2 M1M2／G-DRDA-3／G-DRDA-5；无 C 类面 | PASS |
| 9.20 | 取值表每值一例 | 11 码点逐值（请求 6＋响应 5，#1–#5）；DDM format 两值（0x01＋0x41 T-11） | PASS |
| 9.21 | 分支级审计 | 负例按分支铺（长度/载体/presence/端口四分支） | PASS |
| 9.22 | 扫遍全部承载位置 | drda 层为唯一终结承载；DSSSegments 直编 vs 默认序列双路径（planner.go:106-110／layer_gen.go:62-66） | PASS |
| 9.23 | 正交矩阵逐格标记 | design §10 矩阵 | PASS |
| 9.24 | 地址族对称（IPv4/IPv6 逐格） | **对称**：#7 IPv6（offset 74）与 #1 逐字节等价（pkt4 在 IPv6 头后同字节） | PASS |
| 9.25 | 地址族扩展随矩阵扩 | 无缺格（v4 #1–#6/#8＋负例／v6 #7） | PASS |
| 9.26 | 补齐顺序 | 最小实现→高频→全量（T-11 最后补） | PASS |
| 9.27 | harness 做不到逐项注明 | 包序靠 packet 级字段＋frames offset 双钉（54/74 铁律） | PASS |
| 9.28 | 不许字段出现冒充顺序 | correlator 逐对配对断言（请求响应同值，非仅字段出现） | PASS |
| 9.29 | 补齐后全量全绿 | 全量 13/13 绿（P5＋P6 双跑，非增量） | PASS |
| 9.30 | 只写不跑/只跑增量=未完成 | 全量跑（CASE_PROTO=drda 全载入 13 例） | PASS |
| 9.31 | 断言以真实 pcap 校准 | 先跑后钉（P5 SQLCARD offset 64 参数字节从落盘 pcap 提取钉入；包数公式 2N＋7 逐例复算） | PASS |
| 9.32–9.35 | 动态整格（五策略×字段） | 四元组 framework 面在案；#8 四元组 distinct 断言；业务键多值动态零例（M4） | PASS/M4 |
| 9.36 | 不支持格标 B/C+注记 | G-DRDA-3/5 notes 披露 ✓；CPSQLSTT 零发射诚实声明（M2） | PASS |
| 9.37 | 派生编号撞车 | 无派生子流面（sessions 显式 id s1/s2） | PASS |
| 9.38 | 聚合断言排除固定/派生口 | `tcp.srcport distinct_values [12345,12346]`＋`distinct_exclude [446]`（#8） | PASS |
| 9.39 | 多流×静态标量互斥 | #8 sessions 各自显式 src_port（非 flows 复制，确定性按 session 顺序输出） | PASS |
| 9.40 | 共享流序号动态字段 | 无动态序号面（correlator 缺省 1 路径诚实缺口，M4） | NOTE(M4) |
| 9.41–9.45 | 测试评审五件事 | 本报告 §1–§4（登记/三源/锚词/包数公式/先跑后钉） | PASS |
| 9.46 | 数据场景全表扫 | 变体 14 行 12 覆＋2 立项（SECMEC 值面／失败 RM 参数面→G-DRDA-3/5） | PASS/B′ |
| 9.47 | 取值集合逐值枚举 | 11 码点逐值；SECMEC 值面未逐值（→G-DRDA-3） | PASS/G3 |
| 9.48 | 业务场景规范反推 | design §10 三子表；出处声明 testcase §5.2（规范反推非用例反推） | PASS |
| 9.49 | 多连接/多会话/多事务各一例+真实编排 | 多会话 #8（双连接 18 包）＋多事务 #4（5 轮同连接）✓ | PASS |
| 9.50 | 复合大场景≥3 类交织 | 未显式声明三类交织复合例（最大 #8=双会话×单轮档；#4=单会话×五轮） | GAP(9.50) |
| 9.51 | 组合矩阵满格 | design §10 矩阵；用例面组合维度有限（多段×非1 步长×token 三面 open） | PASS/M4 |
| 9.52 | 审计声明出处+对账两行 | testcase §5.2：规范逻辑点 29＝24 覆＋5 立项；出处=规范反推非用例反推 | PASS |
| 9.53 | 门3 至少一条抽最复杂用例+点数 | 最复杂 #4/#5：17 包、pkt12 SQLDTA／pkt13 SQLCARD＋offset 64 参数字节双钉；P6 (b) 逐字节复核 ✓ | PASS |
| 10.1 | 文档对规范逐条核对 | p123 §2 末＋testcase §8.6（29 点逐点结论＋用例号） | PASS |
| 10.2 | 改需求先对旧需求 | 29-* §1–§12/testcase §1–§8 逐条核对，无静默删除 | PASS |
| 10.3 | 代码逐行走读 | P4 4 轮＋P5 3 轮自审（p4-report §8；末轮干净） | PASS |
| 10.4 | 构建+vet+测试含 race | build/vet 双 OK；`-race` layers＋drda 双绿 | PASS |
| 10.5 | 修完再审 | 每轮 fix 后再审（P4 R4/P5 R3 末轮干净） | PASS |
| 10.6–10.10 | 测试评审 | P6 隔离终审（只读，三源对账＋锚词核＋点数） | PASS |
| 10.11 | 改审测修再审闭环+结论 | p4-report §8＋p6 判词：通过 | PASS |
| 11.1–11.5 | 白话 | p6 §0／p4 §0 一句白话 | PASS |
| 12.1 | 五策略全开 | 四元组五策略 framework 在案 | PASS |
| 12.2 | 动态覆盖四元组 | 同上（#8 双 src_port 实证） | PASS |
| 12.3 | 业务字段清单逐协议 | testcase §6.2 动态清单；`association` 不开（形状选择器）／`dss_length` 不开（负例注入口）／三 M4 面诚实缺口 | PASS/M4 |
| 12.4 | flows=N 确定性+seed+回绕 | 无 flows>1 例可验（#8 走 sessions 非 flows 复制） | NOTE(无例) |
| 12.5 | 不写动态按 fixed | 13 例层内业务键全静态（correlator 缺省 1 路径） | PASS |
| 12.6–12.8 | 任务级动态不丢/只截断/跨策略 | framework 未动 | PASS |
| 12.9 | 静态复制拒绝/告警 | framework 守卫在案（drda 无多流例，未取用） | NOTE |
| 12.10 | src_port 保底≠动态 | #8 显式双端口（非保底冒充动态） | PASS |
| 12.11–12.13 | 动态住层链/不另起顶层/对齐 tuples | 四元组住 ip/tcp；无顶层动态键 | PASS |
| 12.14–12.16 | 清单+序号算法可定位 | 序号语义=correlator（planner.go:56-59／layer_gen.go:29-32 起始＋递增，可定位）；业务无逐流序号算法诚实"不适用" | PASS |
| 13.1–13.6 | schema 文件 | registry drda 行 12 键（关单轮删 session_start 后）＋FieldContract 446；generated json 机读逐键一致（P5 schemagen 重跑无 diff） | PASS |
| 13.7–13.10 | 校验入口唯一 | ValidateStrategy/TaskCreate 同入口（suite 走 MCP） | PASS |
| 13.11–13.16 | 派生只读下游 | flowb_query_layers 实时视图 | PASS |
| 13.17 | 改语义先改 schema | registry 先行（P4 登记三键＋translate 加 case） | PASS |
| 13.18 | 注册表变更重跑生成 | generated 已重跑入版（merge 内，无 diff） | PASS |
| 13.19 | 过期测试变红 | schemagen 重跑无 diff 即一致；schema 包测试全绿（p4 §7） | PASS |
| 13.20–13.21 | 缺席走缺省/null 拒 | V9 白名单制（未知层内键拒 `unknown field`）；`DRDAConfig` 无 UnmarshalJSON——把关在 V9，注释已诚实修正（P4 R1） | PASS |
| 13.22–13.23 | schema 是机器源不算第四文档 | — | PASS |
| 13.24–13.26 | 评审先查 schema/手写/null 兼容 | 无手写形状、无 null 兼容分支；`session_start` Min:0 Max:0=V9 无界（已删，本轮落地） | PASS/M1 |
| 14.1 | 用例 spec 即 MCP 任务配置 | spec_json=layers 直驱＋flow_control 封包（9 正例） | PASS |
| 14.2 | 不许两套写法 | 单权威（flat 旧写法已迁，`case "drda"` 收敛为缺省端口 446） | PASS |
| 14.3 | 执行工具直接消费用例 | suite 经 MCP 直消（P5 lane16＋P6 canonical 双跑） | PASS |
| 14.4 | 旧用例随层链迁移改写 | 10 例全改写＋新增 3 例=13（testcase §8） | PASS |
| 14.5 | 历史口径不带入 | 包数公式重校（2N＋7）、SQLCARD 参数面重建（旧 planner 语义收敛） | PASS |
| 14.6 | 先跑拿 pcap 再钉 | P5 实跑重锚（SQLCARD offset 64）；P6 重跑产出新 pcap 复核 | PASS |
| 14.7–14.9 | MCP 建任务→生成→tshark 校对 | lane16 MCP＋canonical MCP＋tshark 字段/frames 双通道 | PASS |
| 14.10 | 离线/无失败/只数包不算测 | 字段＋frames 双钉（不只看 packet_count；链级 8 红例离线全绿） | PASS |
| 14.11 | 负例经 MCP 被拒+锚词 | 4 负例全 error_contains（`dss_length`／`tcp`／`top-level drda sub-config`／`dst_port must be 446`，validator 逐字命中） | PASS |
| 14.12 | 假成功同级 bug | 无假成功：mismatch/presence/端口契约=create 期拒；udp=Build 期拒（锚 carrier）；P5 探针抓到过静默放行真红已修 | PASS |
| 14.13–14.15 | 聚端口/派生口/方向想清 | distinct 聚合排除 446；方向 up/down 由请求/响应对显式 | PASS |
| 14.16 | 全绿+落盘可复查 | 13/13＋11 pcap 文件（9 正＋2 负 `.neg.pcap` 0 字节；presence/端口契约 create 期拒无 pcap，与契约一致） | PASS |
| 14.17 | 抽查 spec/字段/锚词 | p6 (b)(e) 逐包逐字节 | PASS |
| 14.18 | 二进制与 HEAD 同代 | P1 复验绿（fresh binary 重跑门2-3 转绿，P1 closed） | PASS |
| 14.19 | 全量全绿 | 13/13（非增量；P5＋P6 双全量） | PASS |
| 14.20 | 包号/端口从 pcap 拿 | 先跑后钉（5000 拒/446 放行 9 包双向覆盖，先实跑后钉锚词） | PASS |
| 15.1 | 门1 十四行表+证据 | p123-report §2 | PASS |
| 15.2 | 证据三选一；写不出=立项 | G-DRDA-1…5 在案（G-DRDA-1/4 本车道关闭，3/5 立项，2→M1M2） | PASS |
| 15.3 | §1/§3/§12 强制展开 | design §12＋testcase §6.1/§6.2 | PASS |
| 15.4 | 门2①顶层零残留 | 旧键绿；presence 红线已接（pipe_gate.sh 名单含 drda） | PASS |
| 15.5 | 门2②全量绿+负例锚词 | 13/13＋4 锚词（机核＋validator 逐字对） | PASS |
| 15.6 | 门2③二进制同代 | 绿（P1 复验后；lane16 与 HEAD 同代／canonical 复编后绿） | PASS |
| 15.7 | 门2④反查绿后进 P6 | 51/51 绿 | PASS |
| 15.8 | D-条目挂门1表（回填证据号） | design §11（D-DRDA-1 门1 获批=定稿；八要素齐） | PASS |
| 15.9 | 抽查三条点到行/例号 | p6-review (a)（三条均点行/例号） | PASS |
| 15.10 | 白话+三门证据 | p6-review §0/（c)/（d) | PASS |
| 15.11 | 任一门红停 | 唯一红 P1 已复验绿；判词通过 | PASS |

## 注记（backlog，判定口径）

- **判定口径**：`GAP(9.50)`＝覆盖未达、无对应 D-条目承接的唯一 open 缺口（下轮补三类交织复合例或立项）；`NOTE(M4)`／`PASS/M4` 类＝M4 三未覆盖面（security_token 编码待 G-DRDA-3 现网确认／correlator_inc 非1 专例／dss_segments 多段专例），open follow-ups；`PASS/G3`＝G-DRDA-3 立项承接；`N/A`＝单载体无此面（有结论非缺口）。
- **M1（已删，本轮落地；裁定=删除）**：`session_start`——registry 曾有键＋types 曾有字段，planner/builder/layer_gen 零引用（本表撰写时 grep 再证：drda 包内仅 builder.go:20 常量 CPSQLSTT 无发射点；SessionStart 命中仅 types.go:1387＋someip 他协议），cases 出现 0 次。
- **M2（已删，本轮落地；裁定=删除二选一之删除项）**：`sql.statement`——`DRDASQLConfig.Statement` 在 drda 包内零引用；strategy_convert.go:4853 的 `Statement: getString(m,"statement")` 经核为他协议分支（postgresql/tds 面），非 drda 消费。
- **M3（framework backlog）**：离线执行器剥 layers[] 后直调 MapToFlowSpec 不消费 layers[ip]（IPv6 例在该执行器下失真；smtp/dns 同涉，不挡本协议）。
- **M4（open follow-ups）**：上-verbal 三面，cases 实证——security_token 在 2 例出现但生成器只编码 security_user（planner.go:199）；correlator_inc cases 出现 0 次；dss_segments 3 次均为单段。
- **已关闭**：G-DRDA-1（registry 三键＋translate case"drda"＋chain 回填白名单）、G-DRDA-4（CheckProtoFlat＋ValidationErrors）、P1（门2-3 fresh binary 复验绿）；`transport` 别名保留（planner.go:174-179 有消费）。
- **G-DRDA-3/G-DRDA-5 保持立项**：planner/layer_gen 无 SECCHKRM/ACCRDBRM 失败分支、无 reconnect 键（grep 无功能性命中）。
- **机核Created by**: suite cases/drda.json 13 例（正例顶层键全 `[flow_control, layers]`；4 负例 expect 键集合严格二键；presence 例顶层含 drda 三键）；registry drda 行 12 键（transport/association/ccsid/correlator_start/correlator_inc/security_user/security_token/rdb_name/sql/dss_segments/dss_length/sessions）。
