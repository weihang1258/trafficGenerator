# #81 dameng（D-DAMENG-1）P6 248 条款逐条比对表

> 口径：P6 隔离终审 `p6-review.md`（判词**通过**，无 P0/P1；M 级 2 项注释漂移）+ P4/P5 报告。落点=dameng#81 实测证据（集成点 `2c176b0`：suite **34/34**、门2静态、反查 **63/63**、`-race` 触及包绿）+ 门3抽查三条 + §9.53 双例逐包核。判定：PASS=满足，GAP(n)=缺口编号（G-DM-x 均维持 open，去向见注记），NOTE=注记，N/A=本协议无此形态（设计已显式声明不适用）。
> 实测基线：suite 34/34（13 正 + 21 负；14 存量改写 + 20 新例）；coverage 反查 63/63（接线 14 + 行为面 12 + 用例在案 34 + 4）；pcap 落盘 `/tmp/pipe/lanes/lane13/pcaps/dameng/`（13 正例）；规范逻辑点 46 = 八项 8 + 矩阵 20 + 变体 18，用例覆盖 38 + 不适用/注记 3 + 缺口 5（38+3+5=46 ✓，testcase §5.2）。

| 条款 | 要求 | dameng 落点 | 判定 |
|---|---|---|---|
| 1.1 | 地址只写 ip 层 | 34 例 `layers[i].ip.src/dst`（10.0.0.1→20.0.0.1；ipv6 例 2001:db8::1→::2）；无顶层地址键 | PASS |
| 1.2 | 端口只写 tcp/udp 层 | `tcp.src_port=12345`（sessions 12345/12346；multiflow inc 12345–12347）；`dst_port` 不写由 FieldContract 补 5236；显式 5237→`dameng_neg_port` 拒 | PASS |
| 1.3 | 流数量只走 flow_control | spec_json 顶层键穷尽 = `layers`（13/13 正例机核）；数量面走 case 级 `strategy_fc`（flows=3，pk=24=8×3） | PASS |
| 1.4 | 禁 layers 与顶层五键混用 | 门2-1 绿（无顶层旧键残留）；链例 `dameng_chain_test.go:119` 游离五键+MAC 判死 | PASS |
| 1.5 | 混用示例/用例/文档都算跑偏 | 无混用示例；design §2.1 样例为纯 layers | PASS |
| 1.6 | 门①层链能跑通 | suite 34/34（lane13 MCP 18116 独立重跑，4.682s）；pcap 13 正例齐落盘 | PASS |
| 1.7 | 门②旧格式彻底移除 | 14 存量旧扁平全改写（p4-report §8）；presence 判死两路（strategy_convert.go:8584-8586 + :511-515 ValidationErrors 兼容块，空 map 也死） | PASS |
| 1.8 | 示例只给严格层链形 | 用例 spec_json 全严格层链形（34/34；唯一并存=`dameng_neg_top_dameng_presence_reject`） | PASS |
| 1.9 | 暂不支持时标注目标形状 | 私有 wire 占位 + B′ G-DM-1 注记（design §2.4/§3.2 铁律：占位字节只断非空） | PASS |
| 1.10 | 汇报分开说跑通/清旧字段 | p4-report §2（suite）/§3（接线）/§8（改写）分节 | PASS |
| 1.11 | 顶层白名单（layers/flow_control 家族/output） | 正例穷尽断言；唯一并存 = presence 判死负例（14-P2 口径） | PASS |
| 1.12 | 无可住层时立项补层，不许豁免 | 业务五键已得层（registry.go:702-707 Fields）；`username` 死字段按 G-DM-3 删键关闭，无"登记保留" | PASS |
| 1.13 | 门2①按白名单执行 | 同 1.11；presence 黄豁免（门2-1 绿 + presence 黄说明） | PASS(NOTE presence 黄) |
| 2.1 | 策略=单模板自带 flow_control | `strategy_fc {"type":"flows","value":3}` 在案（`dameng_multi_flow_dynamic`）；其余缺省单流 | PASS |
| 2.2 | 任务=多策略合跑+总量封顶 | 框架语义未动（suite 走策略路径） | PASS |
| 2.3 | 策略先限速任务再封顶 | 未动 | PASS |
| 2.4 | 任务 ID={taskID}-{strategyID} | 未动 | PASS |
| 2.5 | flows=N 复制 N 条 | flows=3 → pk=24=8×3 ✓（connect 单事件基线） | PASS |
| 2.6 | spec 不管数量 | 未动 | PASS |
| 2.7 | 按流变化走动态字段 | 四元组动态住 ip/tcp（layer_dyn.go:17-20）；dameng 业务字段全关（G-DM-8 面） | NOTE(G-DM-8) |
| 2.8 | 未写动态 src_port 保底 12345+i | 框架既有语义（worker.go:308；其余正例 12345，多会话显式 12345/12346） | PASS |
| 2.9 | 其余按流变化必须写动态 | design §12.12 业务清单 9 项全关+理由；sql 逐流变列 A′ 候选 | PASS/A′ |
| 2.10 | 讲数量分清策略复制/任务封顶 | p4-report §1 门1 回填行 | PASS |
| 2.11 | 讲变化动态按 §12 | 本表 12.x | PASS |
| 3.1 | 多会话 sessions[]/flows[] 显式 | `sessions[]` 两会话整块展开（#10）；多流面 = strategy_fc flows（#11） | PASS |
| 3.2 | 每会话独立 ID/四元组/生命周期 | sessions[].src_port 12345/12346，各自握手→3 事件→挥手（20 包=(3+7)×2，无交错） | PASS |
| 3.3 | 会话内事务有序序列 | t1→t2→t3→t4 单会话严格顺序（`validateEventSequence` planner.go:96-146）；`initial_seq` 框架面 | PASS |
| 3.4 | 事务前置条件 | design §12.3 事务表 t1–t4（connect 首位/authOK 门/close 末位） | PASS |
| 3.5 | 触发动作 | 事件数组逐条（connect/auth/sql/close 六 kind） | PASS |
| 3.6 | 成功分支 | auth_response success→authOK→SQL 放行（planner.go:121-128） | PASS |
| 3.7 | 失败分支 | `auth_error_then_close` + `sql_error` + 21 负例 task error 锚 | PASS |
| 3.8 | 控制关联数据流显式字段 | 同连接无派生流，响应靠"请求后紧跟响应"顺序关联（design §10.4 诚实声明） | PASS |
| 3.9 | 关联写清会话/事务/决定字段 | kind 请求/响应配对 + authOK 门；`driven_by` 不适用（无事务标识） | PASS |
| 3.10 | 被关联流独立 ID/四元组/握手 | 无副流（单连接复用），不适用（design §10.4） | N/A |
| 3.11 | 各流顺序/并发/交错写清 | 单会话严格顺序；多会话整块顺序（第二会话 SYN 包号=11）；多流跨流不假设全局包序 | PASS |
| 3.12 | 可交错写清调度+时间戳 | 无交错面（整块回放） | N/A |
| 3.13 | 不许连续重复冒充编排 | 建连→认证→SQL→close 生命周期编排，非模板重复 | PASS |
| 3.14 | 无长连接豁免≠多流豁免 | 有长连接载体→`sessions[]` 不豁免（testcase §6.3）；单包多载荷显式不适用（每事件一 TCP 段） | PASS |
| 3.15 | 多轮/非正常结束/长保活各一例或立项 | ①多轮 SQL = A′ 补例未落 ②非正常 = auth_error/sql_error + 19 负例 ✓ ③长保活 = 协议层无 keepalive（不适用声明）+ 随①同批 | GAP(A′-多轮/长保活) |
| 3.16 | CWMP 范本照补 | 差异声明：无 driven_by（单载体无副流） | PASS |
| 3.17 | 多流设计五件套 | design §12.3（会话表 s1–s3/事务/关联/插入/时间线） | PASS |
| 4.1 | 连接模型 | design §2/§4（TCP 5236 单长连接，无控制/数据分离，客户端主动建连） | PASS |
| 4.2 | 命令/消息表 | design §3.2 六 kind 表（connect/auth_request/auth_response/sql_request/sql_response/close） | PASS |
| 4.3 | 状态机 | design §4.1（Init→Connected→Authed→Closed） | PASS |
| 4.4 | 字段表 | design §2.3 事件键消费表（kind/direction/profile/result/sql ✅，username 死字段已删） | PASS |
| 4.5 | 错误处理表 | design §4.2 非法转移表 + §7；用例面 21 负例锚 | PASS |
| 4.6 | 超时与活性 | design §10.1 行 6（协议层无 keepalive/超时语义，由 TCP 承担；显式不适用） | PASS |
| 4.7 | NAT/代理/被动 | design §10.1 行 7：无应用层 NAT 遍历、无派生流形态，显式不适用 | N/A |
| 4.8 | 版本/方言 | `wire_profile` 仅 2 登记值且不参与字节构造；版本化 fixture 零支持 | GAP(G-DM-1) |
| 4.9 | 有 RFC 查 RFC 注章节 | 无 RFC：公开资料（官方社区 5236 + SYSDBA，多源一致）+ 旧基线语义契约（design §10.5） | PASS |
| 4.10 | 无 RFC 以官方规范为准 | 同上（私有 wire 无出处→本契约不固定，§5.5） | PASS |
| 4.11 | 不许博客二手代替原文 | design §10.5 三路对照（官方资料/现网/开源实现思路） | PASS |
| 4.12 | 规范原文 | design §2–§4 逐表（46 逻辑点口径见 9.52） | PASS |
| 4.13 | 商业软件实际行为 | DM8 默认端口/用户/Oracle 兼容模式（design §10.5）；抓包级确认未做 | PASS/GAP(G-DM-4) |
| 4.14 | 可靠开源实现思路 | 本仓库 `internal/protocol/dameng`（40 单测）+ postgresql #82 事件面范本（方案 A 同构，不搬码） | PASS |
| 4.15 | 三路不一致取舍写清 | design §10.5（三路对照 + A/B/C/D 候选对比，B 编造字节被否） | PASS |
| 4.16 | 商业行为逐条映射用例号 | testcase §5.1 三源回指；G-DM-4 确认方式在案 | PASS |
| 4.17 | 关键决策候选方案对比表 | design §10.5（A 采用/B/C/D 否决 + 理由） | PASS |
| 4.18 | 不许单方案自说 | 同上 | PASS |
| 4.19 | 每表格行/字段/错误码三选一 | design §10 矩阵 8 行 + 三子表；用例面 34 例承接 | PASS |
| 4.20 | 每条目对应至少一用例 | 38 覆盖 + 3 注记 + 5 缺口 = 46 ✓；kind 6/6、result、profile 2 值、wire_fault 2 kind 全有例 | PASS/A′ |
| 4.21 | 动手前缺口矩阵 | 门1 获批（design §14 八项 + p4-report §1 回填） | PASS |
| 4.22 | 三张子表齐 | §10.1 八项 + §10.2 事件×状态矩阵 + §10.3 变体表（+§10.5 映射） | PASS |
| 4.23 | 设计评审先看矩阵 | 门1 获批 | PASS |
| 4.24 | 规范实现冲突先改实现 | `username` 死字段删（G-DM-3 关闭）；neg_port 回填修轮红→修→绿按实修锚 | PASS |
| 5.1 | 设计写明依赖 | `DependsOn ["tcp"]`（registry.go:702）+ `TransportOn ["tcp"]`（:707）+ design §5 | PASS |
| 5.2 | 写明出错处理 | wire_fault 2 有效 kind + 3 类非法形（builder.go:42-58）+ planner 域校验 | PASS |
| 5.3 | 无依赖/错误分支不许实现 | 有（无多余分支） | PASS |
| 5.4 | 无依据不许定字段流程缺省 | 端口 5236/六 kind/状态机均有公开资料或旧基线出处；私有字节不固定（G-DM-1） | PASS |
| 5.5 | 不确定标待确认+确认方式 | G-DM-1/4/7/8 在案（design §14 确认方式逐项） | PASS |
| 5.6 | 回答结论指章节/代码行 | design/testcase v1.0.0 在仓；引用行号漂移 M2 待刷新 | PASS(NOTE M2) |
| 5.7 | 指不出直说不知道 | 吞吐数字诚实"待 P4 基准"（design §6.5） | PASS |
| 5.8 | 回复前自查出处 | p4-report §5 自审（P4 3 轮 + P5 2 轮，末轮干净） | PASS |
| 5.9 | 抽查三条定位不到打回 | 门3 三条 ≡ p6-review §(a)（§5/§12/§13 均点行，漂移逐条写明） | PASS |
| 6.1 | 性能目标/预算/边界 | design §6（逐事件流式、单 flow O(1)、无锁无共享、零可变状态） | PASS |
| 6.2 | 六指标列全 | 吞吐数字标待确认（G-DM 缺口未细化） | PASS |
| 6.3 | pcap/NIC 分别验收 | pcap 路：13 正例落盘 + suite 全绿；**NIC 路本轮未跑**（`pcap_nic_consistency` 仅 pcap 侧，无 port_group 输出） | NOTE(NIC open) |
| 6.4 | 性能依据结合实现路径 | 逐事件构造 + EmitMsg 流式、无共享状态（layer_gen.go:20-66） | PASS |
| 6.5 | 无依据数字标待确认 | 已标（§6.5 不写承诺） | PASS |
| 6.6 | 六类性能场景 | 清单 design §6.6；P5 未跑基准 | NOTE |
| 6.7 | 断言实际指标不只无报错 | packet_count 13 例 + tcp 端口/tcp.len 非空/方向序三钉 | PASS |
| 6.8 | 超预算仍不合格 | 预算面 = 单 flow 常驻 O(1)；P4 未引入按流缓存 | PASS |
| 7.1–7.3 | 三份文档定位 | design + testcase + D-DAMENG-1；未碰 CODE_DESIGN/TEST_CASES | PASS |
| 7.4 | 历史文档保留参考 | 旧基线 33-design/testcase 保留逐节比对 | PASS |
| 7.5 | cases 是产物回指编号 | 34 例回指 testcase §2（32 ID → 34 例，P6 以实测为准） | PASS |
| 7.6–7.7 | 三者关系/冲突序 | — | PASS |
| 7.8–7.9 | 先核心→设计→用例 | 门1 先行（P1–P3 先于 P4/P5） | PASS |
| 8.1 | 八要素（文件/接口/结构/流程/错误/性能/冲突/回滚） | design §11（11.1–11.8）；实现面逐件在码 | PASS |
| 8.2–8.8 | 同上逐项 | translate/validate/backfill/types 落点见 p6-review §(g) | PASS |
| 8.9 | 未定稿不开工 | 门1 获批 = 定稿 = 开工门 | PASS |
| 8.10 | 需求变先改设计 | G-DM-5/6 接管新增经 p4 §7 裁定，P6 契约入版以实测 34 为准 | PASS |
| 8.11 | 不许代码先行文档后补 | P1–P3 先行 | PASS |
| 8.12–8.13 | 开工贴条目/无条目打回 | — | PASS |
| 9.1 | 用例登记（回指编号） | testcase §2（32 ID）+ P6 实测 34 例；ID↔design §9 一致 | PASS |
| 9.2–9.4 | 三源（规范/设计/现网） | 公开资料 + D-DAMENG-1 + 现网（未确认→G-DM-4，不冒充第三源） | PASS |
| 9.5 | 每行每字段每错误码有用例 | 38/46 命中；缺口 5 逐个去向（A′/B′/框架级） | PASS/A′ |
| 9.6 | 一例一行为 | 34 例无重复 id（机核） | PASS |
| 9.7 | 修 bug 先复现变红 | neg_port 回填修轮红→修→绿实证；direction 守卫 failing-test-first 单测（`dameng_direction_test.go`） | PASS |
| 9.8 | 数据场景六变体（正常/边界/空值/超长/非法/大小端） | 正常/边界（length_boundary)/空值（empty_sql/empty events；空 profile→G-DM-7)/超长（long_sql_mss)/非法（21 负）/大小端（N/A，无长度字段） | PASS(G-DM-7) |
| 9.9 | 业务场景序列/乱序/中断/交错 | 生命周期序列 + 乱序负例族；中断（RST）A′ 未落；交错 = 整块不交错 | PASS(A′-RST) |
| 9.10 | 现网场景；复杂度 9.50 下限 | 无三类交织复合例（最复杂 = #4 单会话 5 事件 12 包） | NOTE |
| 9.11 | 多动作组合流≥2 条×≥3 动作 | sql_success（5 事件）/close_clean（6 事件）/auth_error_then_close（4 事件）✓ | PASS |
| 9.12 | 清单先行 | P1 矩阵先行（design §10） | PASS |
| 9.13 | 清单无遗漏是目标 | 5 缺口登记在案（38+3+5=46 ✓） | PASS |
| 9.14 | 存量逐条审计去向 | testcase §8 逐条 14 例（14 改写，无作废不注原因）+ 20 新例 | PASS |
| 9.15–9.19 | A/B/C 三分类 | design §10 矩阵 verdict（✅/Ⓡ/N-A/缺口）+ testcase §6.2 A′/B′ 表（本协议无 C 面） | PASS |
| 9.20 | 取值表每值一例 | kind 6/6 + result success/error + wire_profile 2 值 + payload_size 单值 + wire_fault 2 kind ✓ | PASS |
| 9.21 | 分支级审计 | 负例按分支铺（state/auth/sql/profile/5236/unknown field/invalid wire_fault…） | PASS |
| 9.22 | 扫遍全部承载位置 | 事件数组唯一承载全覆盖 | PASS |
| 9.23 | 正交矩阵逐格标记 | design §10.2 矩阵（20 格 = ✅6+Ⓡ9+N-A1+注记1+缺口3 ✓） | PASS |
| 9.24 | 地址族对称（IPv4/IPv6 逐格） | IPv4（#8）+ IPv6（#9，frames 起点 74）两格满格 | PASS |
| 9.25 | 地址族扩展随矩阵扩 | 已满格，无扩展缺口 | PASS |
| 9.26 | 补齐顺序 | 最小实现→高频→全量（testcase §7 落盘顺序①→④） | PASS |
| 9.27 | harness 做不到逐项注明 | 包序/方向靠 fields + 包号组合钉（tshark 面） | PASS |
| 9.28 | 不许字段出现冒充顺序 | 方向序断言（#4 门3逐包核：包4/5/7 c2s dstport + 包6/8 s2c srcport） | PASS |
| 9.29 | 补齐后全量全绿 | 34/34 全量（3 轮 FULL rerun，非增量） | PASS |
| 9.30 | 只写不跑/只跑增量=未完成 | 全量跑 | PASS |
| 9.31 | 断言以真实 pcap 校准 | 先跑后钉（20 新例首跑即绿；11 负例锚词离线探针实测文本） | PASS |
| 9.32–9.35 | 动态整格（五策略×字段） | 四元组 framework 面在案；#11 含动态 src_port inc；业务动态面维持立项（G-DM-8） | PASS/A′ |
| 9.36 | 不支持格标 B/C+注记 | B′ G-DM-1 注记 ✓；本协议无 C 面、无单包多载荷面（显式不适用） | PASS |
| 9.37 | 派生编号撞车 | 无派生子流面 | PASS |
| 9.38 | 聚合断言排除固定/派生口 | #10 distinct_exclude 含 5236/客户端口（§9.38 口径原样保留）；#11 同款 | PASS |
| 9.39 | 多流×静态标量互斥 | #11 flows=3 + 动态 src_port inc（静态复制面→G-DM-8 open） | PASS(G-DM-8) |
| 9.40 | 共享流序号动态字段 | 无动态面 | NOTE |
| 9.41–9.45 | 测试评审五件事 | p6-review（独立重跑 + 双门 + 锚词抽验 + 残留裁定）+ 本表 | PASS |
| 9.46 | 数据场景全表扫 | 变体表 18 行逐项有落点/去向（testcase §6.2） | PASS |
| 9.47 | 取值集合逐值枚举 | 同 9.20 | PASS |
| 9.48 | 业务场景规范反推 | design §10 三子表；出处声明 testcase §5.2（公开资料+旧基线反推，非引擎反推） | PASS |
| 9.49 | 多连接/多会话/多事务各一例+真实编排 | 多会话 ✓（#10）+ 多流 ✓（#11 flows=3）+ 会话内认证→SQL 真实编排；多轮 SQL A′ 未落 | PASS(A′) |
| 9.50 | 复合大场景≥3 类交织 | 无 t180 式复合例（协议简单性注记；A′ 补例 multi_query_rounds/server_abort_rst 未落） | GAP(A′-复合例) |
| 9.51 | 组合矩阵满格 | design §10.2 矩阵；用例面组合维度 = 矩阵格 | PASS/A′ |
| 9.52 | 审计声明出处+对账两行 | testcase §5.2：规范 46（8+20+18）vs 用例 38；38+3+5=46 ✓；出处=规范反推非用例反推 | PASS |
| 9.53 | 门3 至少一条抽最复杂用例+点数 | #4 `dameng_sql_success`（12 包=5+7，包4/6/8 端口+len 逐点）+ #10 `dameng_multi_session`（20 包，distinct 双断言） | PASS |
| 10.1 | 文档对规范逐条核对 | design §10 三路对照 + p123-report §3 对抗自重审 | PASS |
| 10.2 | 改需求先对旧需求 | 旧基线 33-design/testcase 逐节比对（design §12 门1 表 §10 行 + §15 修订） | PASS |
| 10.3 | 代码逐行走读 | P4 3 轮 + P5 2 轮（p4-report §5）；P6 接线复核 §(g) | PASS |
| 10.4 | 构建+vet+测试含 race | `go build ./...` + vet 净；`-race` 触及包绿（p4-report §4） | PASS |
| 10.5 | 修完再审 | 每轮 fix 后再审（末轮干净） | PASS |
| 10.6–10.10 | 测试评审 | p6-review（三源对账 + 锚词核 + 点数 + 双门独立跑） | PASS |
| 10.11 | 改审测修再审闭环+结论 | p4-report §5 + p6 判词通过 | PASS |
| 11.1–11.5 | 白话 | p4-report 首节白话 + p6-review 白话一句 | PASS |
| 12.1 | 五策略全开 | 四元组五策略 framework 在案（layer_dyn.go:17-20） | PASS |
| 12.2 | 动态覆盖四元组 | #11 取用 inc（12345–12347 回绕）；rand/list/pattern framework 面 | PASS |
| 12.3 | 业务字段清单逐协议 | design §12.12（9 项全关 + 理由逐条） | PASS |
| 12.4 | flows=N 确定性+seed+回绕 | framework 语义；#11 inc 回绕实证（pk=24） | PASS |
| 12.5 | 不写动态按 fixed | 13 例中 12 例全静态；动态仅 #11 | PASS |
| 12.6–12.8 | 任务级动态不丢/只截断/跨策略 | framework 未动 | PASS |
| 12.9 | 静态复制拒绝/告警 | framework 守卫在案；dameng 无层内 dyn 触发面 + 无 `neg_static_duplicate` | NOTE(G-DM-8) |
| 12.10 | src_port 保底≠动态 | 诚实声明（design §12.12；保底 worker.go:308） | PASS |
| 12.11–12.13 | 动态住层链/不另起顶层/对齐 tuples | 四元组住 ip/tcp；无顶层动态键 | PASS |
| 12.14–12.16 | 清单+序号算法可定位 | 序号算法四处实读行号（layer_dyn.go:78/369/770；tuple_generator.go:26/290/300；worker.go:308），门3逐字命中零漂移 | PASS |
| 13.1–13.6 | schema 文件 | registry dameng 行六键（terminal/DependsOn tcp/TransportOn tcp/FieldContract 5236/Fields 五键）+ generated.json:379 逐键一致（门3机核） | PASS |
| 13.7–13.10 | 校验入口唯一 | ValidateStrategy/TaskCreate 同入口（suite 走 MCP） | PASS |
| 13.11–13.16 | 派生只读下游 | flowb_query_layers 实时视图 | PASS |
| 13.17 | 改语义先改 schema | registry 先行（P4） | PASS |
| 13.18 | 注册表变更重跑生成 | generated 已重跑入版（merge 内，p4-report §4.7 schemagen 127 层） | PASS |
| 13.19 | 过期测试变红 | P6 未单独跑 `TestLayersGeneratedMatchesRegistry`；门3逐字命中 generated 块 | NOTE |
| 13.20–13.21 | 缺席走缺省/null 拒 | 严格解码双层（translate decD + `DamengConfig.UnmarshalJSON` types.go:1296-1306 均 DisallowUnknownFields）；空层→P0b 缺省流（planner.go:45-49/:172-176，无静默空流） | PASS |
| 13.22–13.23 | schema 是机器源不算第四文档 | — | PASS |
| 13.24–13.26 | 评审先查 schema/手写/null 兼容 | 无手写形状、无 null 兼容分支 | PASS |
| 14.1 | 用例 spec 即 MCP 任务配置 | spec_json=layers 直驱 + strategy_fc 封包（flows=3 例） | PASS |
| 14.2 | 不许两套写法 | 单权威（flat 优先 + presence 判死，双头已封） | PASS |
| 14.3 | 执行工具直接消费用例 | suite 经 MCP 直消（lane13 18116 独立重跑） | PASS |
| 14.4 | 旧用例随层链迁移改写 | 14 例全改写 + 20 新例 = 34 | PASS |
| 14.5 | 历史口径不带入 | 包数 N+7 逐例复算、断言面重建（username 死字段同批删） | PASS |
| 14.6 | 先跑拿 pcap 再钉 | P5 实跑重锚；11 负例锚词探针实测 | PASS |
| 14.7–14.9 | MCP 建任务→生成→tshark 校对 | lane13 MCP 18116 + tshark 载体字段（`tcp.*`/`ip.*`，零 dissector 实测）双通道 | PASS |
| 14.10 | 离线/无失败/只数包不算测 | 端口 + tcp.len 非空 + 方向序三钉（不只看 packet_count） | PASS |
| 14.11 | 负例经 MCP 被拒+锚词 | 21 负例全 error_contains（门3抽 6/6 与代码字面逐字一致） | PASS |
| 14.12 | 假成功同级 bug | 零假成功：neg_port 修轮实证（无回填则假通过）；空层走 P0b 缺省流非静默空流 | PASS |
| 14.13–14.15 | 聚端口/派生口/方向想清 | distinct 聚合排除口（#10/#11）+ 方向 up/down 显式 | PASS |
| 14.16 | 全绿+落盘可复查 | 34/34 + 13 正例 pcap 落盘 lane13（可 tshark 复查） | PASS |
| 14.17 | 抽查 spec/字段/锚词 | p6-review §(a)(b)(e) | PASS |
| 14.18 | 二进制与 HEAD 同代 | 门2-3：同二进制 34/34；时间戳红 = 评审沙箱 artifact，已裁定非代码缺陷 | PASS(NOTE) |
| 14.19 | 全量全绿 | 34/34（3 轮 FULL rerun） | PASS |
| 14.20 | 包号/端口从 pcap 拿 | 先跑后钉（门3 #4/#10 逐包核） | PASS |
| 15.1 | 门1 十四行表+证据 | design §12 门1 表（§1/§3/§12 强制展开 §12.1/§12.3/§12.12） | PASS |
| 15.2 | 证据三选一；写不出=立项 | G-DM-1…8 在案（design §14） | PASS |
| 15.3 | §1/§3/§12 强制展开 | design §12.1/§12.3/§12.12 | PASS |
| 15.4 | 门2①顶层零残留 | 旧键绿；presence 红线已接（pipe_gate.sh:107 名单含 dameng），presence 负例豁免黄 | PASS |
| 15.5 | 门2②全量绿+负例锚词 | 34/34 + 21 锚词（抽 6 逐字） | PASS |
| 15.6 | 门2③二进制同代 | 绿（artifact 裁定见 14.18） | PASS |
| 15.7 | 门2④反查绿后进 P6 | 63/63 绿（check_dameng:1406-1520） | PASS |
| 15.8 | D-条目挂门1表（回填证据号） | D-DAMENG-1（design §11）；设计引用的旧行号漂移 M2 待本次契约入版刷新 | PASS(NOTE M2) |
| 15.9 | 抽查三条点到行/例号 | p6-review §(a)（三条均点行/例号） | PASS |
| 15.10 | 白话+三门证据 | p6-review 白话 + §(c)(d) | PASS |
| 15.11 | 任一门红停 | 门2 静态绿；门2-3 红 = artifact 已裁定；suite 34/34 | PASS |

## 注记（backlog，判定口径）

- **判定口径**：`GAP(G-DM-x)` = 缺口已按 design §14 + testcase §6.2 立项承接（A′/B′/框架级），非挂账；`NOTE` = 信息性注记；`N/A` = 本协议无此形态且设计已显式声明不适用（3.10 无派生流 / 3.12 无交错面 / 4.7 无 NAT 遍历形态；大小端、单包多载荷面在 9.8/3.14 行内注记，不另立条款）。
- **G-DM-1（B′，私有 wire 版本化 fixture）**：占位字节不得冒充实现；正例只断言传输层（4.8/9.36 行）。去向 D-DAMENG-1「明确不解决 + 迁入计划」。
- **G-DM-4（现网抓包未确认）**：第三源当前为未确认级（4.13/9.2–9.4 行）。确认方式：本机 DM8 + 官方驱动抓 5236。
- **G-DM-7（A′，空 profile 回退未钉例）**：`builder.go:27-29` 缺省 `"dm8"` 字节无专属正例（9.8 行）。
- **G-DM-8（open，静态复制拒绝面）**：cases 全文无 `static`；dameng 不在 layerDynAllowlist（无层内 dyn 入口），静态复制门只看层内 dyn——无触发面（2.7/9.32–9.35/9.39/12.9 行）。维持 open 正确，去向框架 backlog。
- **NIC 双路（port_group）open**：`dameng_pcap_nic_consistency` 仅 pcap 侧（无 port_group 输出、无 NIC 路断言），去向 canonical 侧补 NIC 路或记 open，不挡提交（6.3 行）。
- **A′ 补例未落**：`multi_query_rounds`（同连接多轮 SQL）、`server_abort_rst`（服务端 RST 中断）、`neg_static_duplicate`（3.15/9.9/9.49/9.50 行 GAP/A′ 注记）。
- **M1（注释漂移，随手修）**：chain_planner.go:628 通用 FieldContract 注释列 dameng 为 switch 未覆盖层，但 dameng 实际有显式 `case "dameng"`（:1081）+ 豁免登记（:676）——注释宽于现实，行为无影响。
- **M2（文档行号漂移，本次入版刷新）**：设计 §5/§13 引用的 registry:642-643、generated:354、main:515 已漂移为 :702-707、:379、:516（5.6/15.8 行）。
- **32 ID vs 34 例**：差 2 负例 = `dameng_neg_direction_mismatch`（G-DM-5 接管新守卫）+ `dameng_neg_top_dameng_presence_reject`（G-DM-6 接管落码）；P6 契约入版以实测 34 为准（7.5 行）。
- **端口三处 5236 一致**：validateSpecBase DstPort switch（:1081-1085）+ 豁免名单（:676-678）+ flat `setDefaultDstPort(5236)`（strategy_convert.go:1550）+ Plan 兜底（planner.go:172）+ 域校验（:56）闭环；层值回填块（chain_planner.go:320，neg_port 实证链）。
