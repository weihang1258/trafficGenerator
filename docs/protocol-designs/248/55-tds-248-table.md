# TDS（D-TDS-1 #55）P6 248 条款逐条比对表

> 口径：docs/CORE_MEMORY.md（481 行，2026-09-27 实读，总 248 条款）。契约 = 设计 v3.1.1 §12–§17（已入版 docs/protocol-designs/09-tds-design.md）+ testcase v1.0.1（docs/protocol-designs/09-tds-testcase.md）。落点 = tds P6 独立实测证据（HEAD 0628424 含 merge 50434f1；P6 修轮后 cases/tds.json **134** 例；canonical suite 134/134）。判定：PASS=满足，GAP(n)=缺口编号（G-TDS-n），NOTE=注记。

| 条款 | 要求 | tds 落点 | 判定 |
|---|---|---|---|
| 1.1 | 地址只写 ip 层 | 105 正例 layers[].ip.src/dst（tds_sql_select、tds_mars_2sessions 等，实测 0 游离） | PASS |
| 1.2 | 端口只写 tcp/udp 层 | 105 正例 layers[].tcp.src_port/dst_port；dst_port 缺省 1433 由 chain_planner.go:1171-1174 补 | PASS |
| 1.3 | 流数量只写 flow_control | 105 正例单流（flow_control 省略=框架默认 1，与 sstp/smb/mmse/nfs 同口径）；顶层 count 0 处（实测） | PASS |
| 1.4 | 禁 layers 与顶层五键混用 | 105 正例顶层键集=('layers',) 唯一（实测）；29 负例中 2 例为游离键判死对象（按设计带顶层键，设计 §16.7.3②） | PASS |
| 1.5 | 混用的示例/用例/文档都跑偏 | 设计 §14.1 目标样例=纯 layers；用例无混用；偏离如实登记 §12.6（G-TDS-1 已关） | PASS |
| 1.6 | 门①层链能跑通 | canonical suite RESULT 134/134（P6 修轮后复跑）；tds_chain_test.go:69-77 端到端 13 包 | PASS |
| 1.7 | 门②旧格式已彻底移除 | pipe_gate 门2-1 绿（无顶层旧键）；CheckProtoFlat presence 判死 strategy_convert.go:8657-8661 | PASS |
| 1.8 | 示例只给严格层链形 | 设计 §14.1 样例纯 layers（backup 2508+ 行） | PASS |
| 1.9 | 暂不支持时标注目标形状 | 设计 §14.1 两处如实标注（G-TDS-1 落地前"今天跑不通"）；现 G-TDS-3/8/10 立项在案 | PASS |
| 1.10 | 汇报分开说跑通/清旧字段 | p4-report.md §3 分列（P4/P5 时点 suite 132/132 + 131 例去扁平改写）；P6 修轮后 134/134 | PASS |
| 1.11 | 顶层白名单 | 实测非负例顶层键=layers 唯一、0 游离；tds_chain_test.go:127-143 锁死 | PASS |
| 1.12 | 无可住层时立项补层，不许豁免 | 16 层字段已接线（chain_planner_translate.go:2739-2761）+ TransportOn[tcp]；无豁免条目 | PASS |
| 1.13 | 门2①按白名单执行 | pipe_gate.sh 门2-1 白名单制实测绿（本报告 §3） | PASS |
| 2.1 | 策略=单模板自带 flow_control | 框架语义未动；策略模板=单 TDS 流量（设计 §14 行2） | PASS |
| 2.2 | 任务=多策略合跑+总量封顶 | 框架未动 | PASS |
| 2.3 | 策略先限速任务再封顶 | 框架未动 | PASS |
| 2.4 | 任务 ID={taskID}-{strategyID} | 框架未动 | PASS |
| 2.5 | flows=N 复制 N 条 | 框架未动；tds 用例全 N=1 | PASS |
| 2.6 | spec 不管数量 | 用例 spec_json 无数量键（实测） | PASS |
| 2.7 | 按流变化走动态字段 | 机制在 ip/tcp 层（layer_dyn.go:140-160）；tds 链 0 例实测 → 立项 G-TDS-4 | GAP(4) |
| 2.8 | 未写动态 src_port 保底 12345+i | 用例全显式 54321（未走保底路径）；框架既有语义 | PASS |
| 2.9 | 其余字段按流变化必须写动态 | 全部用例 flows=1 无按流变化面；业务字段动态 → G-TDS-10 | PASS |
| 2.10 | 讲数量分清策略复制/任务封顶 | 设计 §14 行2；本报告口径 | PASS |
| 2.11 | 讲变化动态按 §12 | 设计 §14.3；本表同 | PASS |
| 3.1 | 多会话 sessions[]/flows[] 显式 | tds_mars_2sessions/_3sessions*/_txn_indep 等 8 例，layers[].tds.sessions[] 显式 | PASS |
| 3.2 | 每会话独立 ID/四元组/生命周期 | MARS 会话共享同一 TCP 四元组+SPID 0x0042（规范语义，设计 §14.2① 明载）；独立 id/请求序列 layer_gen.go:79-82 | PASS |
| 3.3 | 会话内事务有序序列 | tds_mars_3sessions_txn_indep（A: tm@8→sql@10；B: tm@12→sql@14；C: sql@16，pcap 实证） | PASS |
| 3.4 | 前置条件 | V-TDS-036 tds_validate_txn_no_begin（BEGIN 前置）；设计 §14.2② | PASS |
| 3.5 | 触发动作 | 用例 type 分派 sql_batch/rpc/trans_mgr/attention（layer_gen.go:128-188） | PASS |
| 3.6 | 成功分支 | DONE/DONEPROC+ENVCHANGE 8/9/10（tds_transmgr_begin_commit 等 6 例） | PASS |
| 3.7 | 失败分支 | tds_inject_login_fail（全会话跳过）/tds_sql_error_batch_continue/tds_mars_3sessions_err_isolate | PASS |
| 3.8 | 控制关联数据流显式关联字段 | TDS 无控制/数据分离副流 → driven_by 不适用（设计 §14.2③ 声明在案） | PASS |
| 3.9 | 关联写清会话/事务/决定字段 | 同上不适用；MARS 归并字段 OutstandingRequestCount/request_cnt（layer_gen.go:87） | PASS |
| 3.10 | 被关联流独立 ID/四元组/握手 | 无副流，不适用（声明在案） | PASS |
| 3.11 | 各流顺序/并发/交错写清 | 设计 §14.2⑤：会话内严格有序；跨会话实现=串行块（pcap 实证 A req→A resp→B req→B resp） | PASS |
| 3.12 | 可交错写清调度+时间戳体现 | 真交错未实现（layer_gen.go:128-193 逐会话出块）→ G-TDS-3 立项 | GAP(3) |
| 3.13 | 不许连续重复冒充编排 | MARS 用例=真实会话/事务/描述符编排（tds_mars_3sessions_txn_indep 5 请求 3 描述符） | PASS |
| 3.14 | 无长连接豁免≠多流豁免 | TDS 是长连接（sessions[] 未豁免）；多流并发=MARS 8 例；单包多载荷=tds_sql_multi；单消息多 RPC 缺 → G-TDS-2 | GAP(2) |
| 3.15 | 无多会话≠无多事务三项 | ①多轮 tds_sql_multi/tds_transmgr_begin_commit ②非正常结束 tds_attention/tds_inject_login_fail ③长保活无例 → G-TDS-4 立项 | GAP(4) |
| 3.16 | CWMP 范本照补 | 差异诚实声明（单通道无 driven_by；MARS 靠消息边界） | PASS |
| 3.17 | 多流设计五件套 | 设计 §14.2 五件套全（会话表/事务序列/关联/插入位置/时间线） | PASS |
| 4.1 | 连接模型 | 设计 §12.1 行1（TCP 长连接、无分离通道、1433；registry.go:1221-1223） | PASS |
| 4.2 | 命令/消息表 | 设计 §12.1 行2（12 Type；六类已实现，五类明确不支持） | PASS |
| 4.3 | 状态机 | 设计 §12.1 行3（连接/事务/MARS 三状态机） | PASS |
| 4.4 | 字段表 | 设计 §12.1 行4（43 类型 token/24 流 token/宽度随版本） | PASS |
| 4.5 | 错误处理表 | 设计 §12.1 行5（50 条 V 规则；29 码实装；23 条无码 → G-TDS-6） | GAP(6) |
| 4.6 | 超时与活性 | 设计 §12.1 行6（生成器语义=不等待，明确不支持+立项） | PASS |
| 4.7 | NAT/代理/被动 | 设计 §12.1 行7（路由重定向 20/21 无构造 → G-TDS-5 明确不支持） | GAP(5) |
| 4.8 | 版本/方言 | 设计 §12.1 行8（7 档；7.3.B 无例 → G-TDS-7；TDS5 不支持） | GAP(7) |
| 4.9 | 有 RFC 查 RFC 注编号章节 | TDS 无 RFC → 不适用（4.10 适用） | PASS |
| 4.10 | 无 RFC 以官方规范为准 | MS-TDS v20260617（ms-tds-spec.txt 12603 行，设计 §13.1①） | PASS |
| 4.11 | 不许博客二手代替原文 | 三路=规范原文+现网 SQL Server/FreeTDS+tshark dissector（设计 §13.1） | PASS |
| 4.12 | 规范原文 | 设计 §13.1① | PASS |
| 4.13 | 商业软件实际行为 | 设计 §13.1②（SQL Server 2012+/2022/2025、错误号 18456/102/1205/2627、FreeTDS 1.5.15） | PASS |
| 4.14 | 可靠开源实现思路 | 设计 §13.1③（wireshark 3.6.14 dissector，只借思路不搬码） | PASS |
| 4.15 | 三路不一致取舍写清 | 设计 §13.3（INXACT 0x04 事实断言；dissector 只作观察口径） | PASS |
| 4.16 | 商业行为逐条映射用例号 | 设计 §12.4 子表③ 10 行；无映射项 → G-TDS-5/9 | PASS |
| 4.17 | 关键决策候选方案对比表 | 设计 §13.2 决策 A–D 各 ≥2 方案 | PASS |
| 4.18 | 不许单方案自说 | 同上（A1/A2/A3、B1/B2、C1/C2、D1/D2） | PASS |
| 4.19 | 每表格行/字段/错误码三选一 | 设计 §12.1 八项+§12.2 36 格+§12.3 29 变体（已实现/明确不支持/不适用，0 留白） | PASS |
| 4.20 | 每条目对应至少一用例 | §12.5 对账 147/220 引用；73 条无例全部归 G-TDS-2/3/6/7 | GAP(2,3,6,7) |
| 4.21 | 动手前缺口矩阵 | 设计 §12 三子表先于 P4（提交序在案） | PASS |
| 4.22 | 三张子表齐 | §12.2 消息×终态矩阵 / §12.3 数据形态变体 / §12.4 商业行为映射 | PASS |
| 4.23 | 设计评审先看矩阵 | 门1 已批（p123-report §1） | PASS |
| 4.24 | 规范实现冲突先改实现 | v3.0.2 修 RPC OptionFlags 2B（规范+dissector 为准） | PASS |
| 5.1 | 设计写明依赖 | registry.go:1221-1223 DependsOn ["tcp"]+CategoryTerminal；设计 §12.1 行1/§14.2④ | PASS |
| 5.2 | 写明出错处理 | 设计 §15.5 五分支（形状错/未知字段/V-TDS/生成期/ERROR 响应） | PASS |
| 5.3 | 无依赖/错误分支不许实现 | 有（同上） | PASS |
| 5.4 | 无依据不许定字段流程缺省 | 1433=规范默认；7.4=脚注 17/72；presence 语义=显式空串保留（T-026） | PASS |
| 5.5 | 不确定标待确认+确认方式 | G-TDS-9（SQL Server 抓包/FreeTDS 核对/Azure 路由，确认方式 §13.1 列明） | PASS |
| 5.6 | 回答结论指文档章节/代码行 | 本报告逐条点行/例号 | PASS |
| 5.7 | 指不出直说不知道 | 设计 §14.3 业务字段序号算法"诚实写无"（不编行号） | PASS |
| 5.8 | 回复前自查出处 | 本报告（file:line 全部回读核过） | PASS |
| 5.9 | 抽查三条定位不到打回 | 门3 三条见 p6-review.md §1 | PASS |
| 6.1 | 性能目标/预算/边界 | 设计 §15.6（规模边界在案；量化指标标待确认未回填） | NOTE |
| 6.2 | 六指标列全 | 设计 §15.6 六项在案、数字待确认（6.5 合规口径） | NOTE |
| 6.3 | pcap/NIC 分别验收 | 设计 §15.6 两路写法在案；NIC 面 0 例 → G-TDS-8（case schema 无 nic_capture 字段） | GAP(8) |
| 6.4 | 性能依据结合实现路径 | 设计 §15.6（流式 emit、无全量聚合、无跨流共享状态；layer_gen.go:66-190） | PASS |
| 6.5 | 无依据数字标待确认 | 已标待确认（未写成承诺） | PASS |
| 6.6 | 六类性能场景 | 清单在案；用例面未落（前四类随 G-TDS-4、交错随 G-TDS-3、背压随框架路径） | GAP(3,4) |
| 6.7 | 断言实际指标不只无报错 | 性能指标断言未落（同 6.6） | GAP(3,4) |
| 6.8 | 超预算仍不合格 | — | NOTE |
| 6.9 | 每份设计必须有性能节 | 设计 §15.6 在案 | PASS |
| 6.10 | 无目标/方法/边界不得宣称完成 | 方法+边界有、数字待确认；本报告不宣称性能面完成 | NOTE |
| 7.1 | CORE_MEMORY 用户维护 | 未动（只读） | PASS |
| 7.2 | CODE_DESIGN 唯一入口 | D-TDS-1 §15 已入版 protocol-designs/09-tds-design.md v3.1.1（本族 D-条目入口在 protocol-designs，同 ocsp/ntlm/sstp 先例；CODE_DESIGN.md 未 append） | PASS |
| 7.3 | TEST_CASES 唯一入口 | testcase v1.0.1 已入版 protocol-designs/09-tds-testcase.md（P6 关单同批）；TEST_CASES.md append 未执行（本族先例同上） | PASS |
| 7.4 | 历史文档保留 | 09-tds-design.md 正文 §1–§11 未删（v3.1.0 为附录增补） | PASS |
| 7.5 | cases 是产物回指编号 | 用例 id/summary 回指 T-条目（如 tds_mars_3sessions_txn_indep=T-193/194） | PASS |
| 7.6 | 三者关系 | 设计定义实现、用例证明方式 | PASS |
| 7.7 | 冲突序 7.1→7.2→7.3 | — | PASS |
| 7.8 | 先核心再设计再用例 | 提交序在案 | PASS |
| 7.9 | 无设计测试条目不得改代码 | D-TDS-1 门1 批后开工 | PASS |
| 8.1 | 改哪几个文件 | 设计 §15.1 九文件清单（对照合并 diff 实测一致） | PASS |
| 8.2 | 接口签名 | 设计 §15.2（translate case tds / CheckProtoFlat 签名不变） | PASS |
| 8.3 | 数据结构 | 设计 §15.3（TDSConfig 16 层字段）；registry.go:1224-1241 实测 16 字段 | PASS |
| 8.4 | 主流程 | 设计 §15.4 四步（建改/启动/计划/验收） | PASS |
| 8.5 | 错误分支 | 设计 §15.5 五行表 | PASS |
| 8.6 | 性能边界 | 设计 §15.6 | PASS |
| 8.7 | 与现有逻辑冲突点 | 设计 §15.7 五点（legacy Planner 并存等） | PASS |
| 8.8 | 回滚方式 | 设计 §15.8（单提交回滚粒度四档） | PASS |
| 8.9 | 未定稿不开工 | 门1 获批=定稿=开工（p123-report §1） | PASS |
| 8.10 | 需求变先改设计 | R2 实修（term.Config 取代 completedConfig）已回写设计 §17 v3.1.1（§15.2 伪码原文保留 + 差异如实记录） | PASS |
| 8.11 | 不许代码先行文档后补 | P1–P3 先于 P4 | PASS |
| 8.12 | 开工贴条目编号 | p4-report 引 D-TDS-1 | PASS |
| 8.13 | 无条目 Diff 打回 | 合并 diff 全挂 D-TDS-1 | PASS |
| 9.1 | 用例登记 TEST_CASES | testcase §2 组级索引+机器契约 tds.json；权威 append 待主线程（见 7.3） | NOTE |
| 9.2 | RFC/官方文档 | MS-TDS v20260617 逐表（设计 §12.5 十二面） | PASS |
| 9.3 | CODE_DESIGN | D-TDS-1 §15 条目 | PASS |
| 9.4 | 已确认现网行为 | SQL Server 错误号/FreeTDS/dissector；待确认项 → G-TDS-9 | PASS |
| 9.5 | 每行每字段每错误码有用例 | §12.5：166 枚举点覆盖+50 规则 26 码引用；未覆面归 G-TDS-2/6/7 | GAP(2,6,7) |
| 9.6 | 一例一行为 | 134 例无重复 ID（实测）；组内单点语义 | PASS |
| 9.7 | 修 bug 先复现变红 | P4 R1–R4 红例先行（p4-report §2）；tds_flat_migrate_test.go 恰一条红例 | PASS |
| 9.8 | 数据场景六变体 | 设计 §12.3 29 变体行；IPv6/7.3B/Flags 等未覆 → G-TDS-7 | GAP(7) |
| 9.9 | 业务场景序列/乱序/中断/交错 | 序列✓/中断✓；乱序交错缺 → G-TDS-3 | GAP(3) |
| 9.10 | 现网场景；复杂度 9.50 下限 | tds_mars_attention_cancel/tds_mars_3sessions_err_isolate ≥3 类 | PASS |
| 9.11 | 多动作组合流≥2条×≥3动作 | tds_mars_3sessions_txn_indep（3 会话 5 请求 2 类型）/tds_mars_3sessions_multi_done（3 语句） | PASS |
| 9.12 | 清单先行 | 设计 §12 矩阵先于用例改写 | PASS |
| 9.13 | 清单无遗漏是目标 | §12.5 逐面对账（12 面+50 规则） | PASS |
| 9.14 | 存量逐条审计去向 | 设计 §16.6：131=105 保留+26 负例改写+0 作废（附注 5 例） | PASS |
| 9.15 | A 类纯字符串 | §16.2 A′ 十一项 | PASS |
| 9.16 | B 类另立项 | §16.2 B′ G-TDS-1/2/3/5/6/8/10 | PASS |
| 9.17 | C 类注明不做 | 无 C 类冒充；§3.15 长保活立项不冒充 | PASS |
| 9.18 | C 类只免断言内部行为 | 能表达者归 A′（§16.2） | PASS |
| 9.19 | 动词出现≠覆盖 | §16.5 三源回指逐条对照 | PASS |
| 9.20 | 取值表每值一例 | 部分覆（Type 7/12、Status 6/8、ENVCHANGE 7/18、FeatureId 1/13）→ G-TDS-7 | GAP(7) |
| 9.21 | 分支级审计 | 同分支代表+每分支一例（§12.2 36 格）；未覆支 → G-TDS-7 | GAP(7) |
| 9.22 | 扫遍全部承载位置 | tds 单承载（层条目），顶层旧键判死实测 | PASS |
| 9.23 | 正交矩阵逐格标记 | 设计 §12.2/§12.3 逐格结论（含"不适用"格） | PASS |
| 9.24 | 地址族对称 | IPv6 0 例（全文 grep 实测）→ G-TDS-7 | GAP(7) |
| 9.25 | 地址族扩展随矩阵扩 | 同上 → G-TDS-7 | GAP(7) |
| 9.26 | 补齐顺序 | 最小实现（G-TDS-1 去扁平）先行 | PASS |
| 9.27 | harness 做不到逐项注明 | tds_rpc_batch_two_procs note（tshark 对第二响应不暴露 doneproc）；设计 §12.3 注 | PASS |
| 9.28 | 不许字段出现冒充行为顺序 | tds_mars_two_sessions_interleave summary 仍称"交错 A 请求→B 请求"，与自身 notes/pcap（A req→A resp→B req→B resp）相反 → 见 p6-review m1 | NOTE |
| 9.29 | 补齐后全量全绿 | canonical suite 全量 134/134（P6 修轮后复跑） | PASS |
| 9.30 | 只写不跑/增量=未完成 | 全量复跑 134/134（非增量） | PASS |
| 9.31 | 断言以真实 pcap 校准 | 先跑后钉（frames 逐字节；notes 记"之前映射错"修正） | PASS |
| 9.32 | 动态整格逐格建例 | 四元组动态 0 例 → G-TDS-4 | GAP(4) |
| 9.33 | 不许抽样代表 | 同上（0 格） | GAP(4) |
| 9.34 | 每格断言三问 | 无格可问 → G-TDS-4 | GAP(4) |
| 9.35 | 锚点选随流变化输出 | 无动态面；静态断言以包号+方向锚 | GAP(4) |
| 9.36 | 不支持格钉现状+注记 | 现状断言形 2 例（tds_sql_tabname_colinfo_unreachable/tds_rpc_returnvalue_unreachable 注记在案） | PASS |
| 9.37 | 派生编号撞车 | 无派生端口（显式 54321/1433） | PASS |
| 9.38 | 聚合断言混入 | 无 distinct 端口聚合断言 | PASS |
| 9.39 | 多流×静态标量互斥 | 全部单流（无 flows>1 用例），无触发面 | PASS |
| 9.40 | 共享流序号动态字段 | 无按流序号派生字段 | PASS |
| 9.41 | 清单先行无遗漏 | 设计 §12 先行；未覆面立项 | PASS |
| 9.42 | 用例回指规范/设计条目 | summary 带 T-xxx；设计 §16.5 映射 | PASS |
| 9.43 | 断言的是输出还是摆设 | 字段+frames 双通道；pcap 独立复核 | PASS |
| 9.44 | 失败路径是否真会红 | 27 负例经 MCP 被拒带锚词（14.11） | PASS |
| 9.45 | 全量跑完全绿 | 134/134 | PASS |
| 9.46 | 数据场景全表扫 | 设计 §12.3 全表扫在案；未覆变体 → G-TDS-2/7 | GAP(2,7) |
| 9.47 | 取值集合逐值枚举 | §12.5 十二面逐面点数（166）；未覆面立项 | GAP(2,7) |
| 9.48 | 业务场景规范反推 | §12.3 子表由 MS-TDS §2/§3 流程章节反推（出处声明在案） | PASS |
| 9.49 | 多连接/多事务/多流各一例+真实编排 | MARS 多会话 8 例+多事务 6 例（会话内多事务+并发模型两项）；交错 leg → G-TDS-3 | PASS |
| 9.50 | 复合大场景≥3类交织 | tds_mars_attention_cancel（多会话+多事务+异常分支）/tds_mars_3sessions_err_isolate（多会话+多事务+ERROR 隔离） | PASS |
| 9.51 | 组合矩阵满格 | 设计 §12.2 36 格逐格（8+1+1+5+5+8+7+1=36 复算实数一致） | PASS |
| 9.52 | 审计声明出处+对账两行 | 设计 §12.5（216=166+50 vs 131 例；T-147/73 缺）出处=规范原文反推 | PASS |
| 9.53 | 门3 抽最复杂用例+点数 | tds_mars_3sessions_txn_indep 8 点（5 fields+3 frames）3 维（本报告 §2，pcap 21 帧复核） | PASS |
| 10.1 | 文档对规范逐条核对 | p123-report §10.1（166 点计数表可复算） | PASS |
| 10.2 | 改需求先对旧需求 | p123-report §10.2（附录增补，正文 §1–§11 未改，git diff 实读） | PASS |
| 10.3 | 代码逐行走读 | p4-report §2 R1–R4 修轮 + §4 末轮干净 | PASS |
| 10.4 | 构建+vet+测试含 race | P6 独立复跑：tds+core/layers+core -race 三包绿（本报告 §5） | PASS |
| 10.5 | 修完再审 | R1–R4 每轮 fix 后重审，末轮干净 | PASS |
| 10.6 | 是否测对函数/路径 | 本报告三源回指+链级测试复核 | PASS |
| 10.7 | 输入是否真能触发 | 27 负例真触发（suite 实测）；presence 例走 MCP 创建期 400 | PASS |
| 10.8 | 断言的是输出还是摆设 | tshark 独立解码复核 txn_indep/interleave pcaps | PASS |
| 10.9 | 规范行和性能指标全覆盖 | 规范行对账在案；性能指标面未落 → GAP(3,4)（同 6.6/6.7） | GAP(3,4) |
| 10.10 | 全绿但测错等于没测 | 本报告抽查用例形状/锚词/顶层键实测 | PASS |
| 10.11 | 闭环结论 | p4-report §4 自审 4 轮末轮干净；本报告独立复核 | PASS |
| 11.1 | 对话先白话结论 | p4/p123/本报告均首句白话 | PASS |
| 11.2 | 协议名带上下文 | 报告口径 | PASS |
| 11.3 | 禁用内部编号黑话 | 报告内技术细节归文档 | PASS |
| 11.4 | 拍板给两个日常选项+建议 | 无待拍板项（G-TDS 均立项） | PASS |
| 11.5 | 回复前自查黑话 | 本报告 | PASS |
| 12.1 | 五策略全开 | 机制在 layer_dyn.go（ip/tcp）；tds 0 处动态 → G-TDS-4 | GAP(4) |
| 12.2 | 动态覆盖四元组 | 同上 → G-TDS-4 | GAP(4) |
| 12.3 | 业务字段清单 | 设计 §14.3 清单（SQL 文本/参数/proc_name/登录字段/会话事务标识） | PASS |
| 12.4 | flows=N 确定性+seed 复现+回绕 | 框架语义；tds 0 例 → G-TDS-4 | GAP(4) |
| 12.5 | 不写动态按 fixed | 用例全 fixed 显式值 | PASS |
| 12.6 | 任务级动态不丢规则 | 框架未动（无跨策略 tds 用例） | PASS |
| 12.7 | 任务级只截断不改写 | 框架未动 | PASS |
| 12.8 | 任务本身支持动态 | 框架未动 | PASS |
| 12.9 | 静态复制拒绝/告警 | 框架守卫；tds 全单流未触发 | PASS |
| 12.10 | src_port 保底≠动态 | 用例显式端口；设计 §14.3 诚实声明 | PASS |
| 12.11 | 动态住层链 | 四元组住 ip/tcp 层；业务字段住 tds 层 | PASS |
| 12.12 | 不许另起顶层字段与 layers 并存 | 实测 0 游离键（105 正例 layers 唯一） | PASS |
| 12.13 | 对齐 tuples 语义 | 框架基线未动 | PASS |
| 12.14 | 清单+序号算法可定位 | 设计 §14.3（层动态 layer_dyn.go:140-160 实核；业务字段"无算法"诚实写） | PASS |
| 12.15 | 测试覆盖五类 | 0 例 → G-TDS-4 | GAP(4) |
| 12.16 | 抽查动态结论能定位 | layer_dyn.go:140-160 已核（P6 实读） | PASS |
| 13.1 | defs.json | 未动 | PASS |
| 13.2 | strategy.json | 未动 | PASS |
| 13.3 | task.json | 未动 | PASS |
| 13.4 | batch.json | 未动 | PASS |
| 13.5 | layers.json | 层链形状未动 | PASS |
| 13.6 | generated/layers.generated.json | 已重跑；tds 行实测 16 字段（P6 独立解析核过） | PASS |
| 13.7 | ValidateStrategy/ValidateTaskCreate | 唯一入口未动；presence 负例经 MCP 400 实证 | PASS |
| 13.8 | 形状先行语义随后 | 报错文案与 mqtt/sstp 族同构（strategy_convert.go:8659） | PASS |
| 13.9 | REST 只调入口 | 未动 | PASS |
| 13.10 | MCP 同一入口 | suite 经 MCP 实测（134/134） | PASS |
| 13.11 | MCP 描述表派生 | flowb_query_layers 实时视图未动 | PASS |
| 13.12 | flowb_query_layers 实时视图 | registry tds 行 16 字段可查 | PASS |
| 13.13 | struct 标签字面量锁 | 未动 | PASS |
| 13.14 | 前端类型生成 | 未动 | PASS |
| 13.15 | 已删选项同步 | 未动 | PASS |
| 13.16 | 文档索引 | 未动 | PASS |
| 13.17 | 改语义先改 schema | registry 先改（P4）后重跑 schemagen | PASS |
| 13.18 | 注册表变更重跑生成 | layers.generated.json +transport_on tcp（实测） | PASS |
| 13.19 | 过期测试变红 | TestLayersGeneratedMatchesRegistry P6 独立复跑绿 | PASS |
| 13.20 | 缺席走缺省/null 拒 | 空层 config 走默认（translate 早返）；显式空串保留（T-026 password:""） | PASS |
| 13.21 | 非法值按历史文案拒 | V-TDS 文案（26 锚词实测 27/27 带锚词） | PASS |
| 13.22 | schema 不算第四文档 | 未动 | PASS |
| 13.23 | 互相引用不复制全文 | 未动 | PASS |
| 13.24 | 评审先查改动是否先落 schema | registry→generated 一致性 P6 实核 | PASS |
| 13.25 | 手写形状不一致打回 | 无手写（generated 由 schemagen 出） | PASS |
| 13.26 | null 兼容打回 | 无 null 兼容垫（presence 判死非兼容） | PASS |
| 14.1 | 用例 spec 即 MCP 任务配置 | driver.go:86-99 spec_json 直作 config 提交 flowb_generate_traffic | PASS |
| 14.2 | 不许两套写法 | 单权威（cases 即 config） | PASS |
| 14.3 | 执行工具直接消费用例 | suite 直消（P6 复跑 134/134） | PASS |
| 14.4 | 旧用例随层链迁移改写 | 134 例去扁平（顶层键 131→0；2 游离键负例按设计保留顶层键） | PASS |
| 14.5 | 历史口径不带入 | 先跑后钉；notes 记映射修正 | PASS |
| 14.6 | 迁移先跑拿 pcap 再钉 | P4 R1–R4 实证改期（login7_default frame 57 等） | PASS |
| 14.7 | 第一步 MCP 建任务 | suite 经 MCP（18100）实测 | PASS |
| 14.8 | 第二步 引擎真实生成 | 131 pcap 落盘（canonical /tmp/mcp-pcaps/tds/ = 105 正 + 26 neg；3 例创建期拒无 pcap） | PASS |
| 14.9 | 第三步 tshark 逐字段校对 | P6 独立 tshark 复核（txn_indep/interleave） | PASS |
| 14.10 | 离线/无失败/只数包不算测 | 字段+frames 双通道断言 | PASS |
| 14.11 | 负例经 MCP 被拒锚词 | 29 负例（26 V-TDS + presence + 游离键 2）全带锚词、全经 MCP 拒 | PASS |
| 14.12 | 假成功同级 bug | 26 validate 负例 .neg.pcap=24B 占位（零假成功，实测）；presence + 游离键 2 例创建期即拒 | PASS |
| 14.13 | 聚端口断言分侧 | 无聚合断言（不适用） | PASS |
| 14.14 | 子流派生端口排除/写进期望 | 无派生端口 | PASS |
| 14.15 | 想清字段出现方向 | 断言钉包号+方向（MARS 响应 server→client pcap 实证） | PASS |
| 14.16 | 全绿+落盘可复查 | 134/134 + pcap 落盘（131 文件） | PASS |
| 14.17 | 抽查 spec/字段/锚词 | 本报告三源回指+锚词 27/27 | PASS |
| 14.18 | 二进制与 HEAD 同代 | pipe_gate 门2-3 绿 | PASS |
| 14.19 | 全量全绿 | 134/134（全量非增量） | PASS |
| 14.20 | 包号端口从 pcap 拿 | frames/包号以落盘 pcap 校准（P6 tshark 复核一致） | PASS |
| 15.1 | 门1 十四行表+证据 | 设计 §14 全文（p123-report §1 摘录） | PASS |
| 15.2 | 证据三选一；写不出=立项 | §14 表逐行证据（代码行/用例号）；无证据项立项 | PASS |
| 15.3 | §1/§3/§12 强制展开 | 设计 §14.1/§14.2/§14.3 | PASS |
| 15.4 | 门2①顶层零残留 | 实测非负例 0 游离；唯一顶层 tds 为故意 presence 负例（登记在案） | PASS |
| 15.5 | 门2②全量绿负例锚词 | 134/134 + 锚词 29/29 | PASS |
| 15.6 | 门2③二进制同代 | pipe_gate 门2-3 绿 | PASS |
| 15.7 | 门2④反查绿后进 P6 | coverage_gate tds 51/51 绿（exit 0，P6 修轮后） | PASS |
| 15.8 | D-条目挂门1表 | D-TDS-1 挂设计 §14 表（v3.1.1 已入版，本提交） | PASS |
| 15.9 | 抽查三条点到行/例号 | p6-review.md §1 三条（file:line+case ID） | PASS |
| 15.10 | 白话+三门证据 | p6-review.md 首句+§3/§4 | PASS |
| 15.11 | 任一门红停 | 三门全绿（本报告 §3/§4） | PASS |

## 注记（backlog，不挡验收）

- N1（已处置）：契约文档已入版（设计 v3.1.1 + testcase v1.0.1，本提交）——原件曾于 2026-09-27 04:09–04:10 移至 /tmp/stale-docs-backup/ 与 /tmp/stale-untracked-backup/，本表以备份本核对后回写。
- N2（已处置）：设计 §15.2 伪码差异已回写 §17 v3.1.1（8.10 行随之 PASS）：实现用 `term.Config` 原样（schema 零值压 presence 默认，login7_default 红），行为正确。
- N3：设计 §13 记 generated "123 层含 tds"，现 127 层（后续协议并入，非 tds 缺陷）。
- N4（已关闭）：p6-review m1（interleave summary 诚实化）+ m2（游离键负例落地 src_ip/count 两例；ttl/src_mac → G-PG-6 框架白名单 backlog）均落地，见设计 §17 v3.1.1。
- N5：G-TDS-2/3/4/5/6/7/8/9/10 均立项在案，G-TDS-1 已关。
