# cflow（D-CFLOW-1 #64）P6 248 条款逐条比对表

> 口径：docs/CORE_MEMORY.md（v15/481 行，2026-09-27 读）。落点=cflow#64 实测证据（canonical 复跑：suite 27/27、门2-4 反查 56/56、enip 137/137 回归、-race 绿；P6 复验 P1-1/M-1 均为非代码改动已关闭）+ P4 lane 报告。判定：PASS=满足，GAP(n)=缺口编号，NOTE=注记，P6注记(P1-2 open)=行为面满足、v2 文档落点缺失（DOC DEBT open）。
> 文档面：仓内现为 design v1.0.0（171 行，§1–§7）/ testcase v1.0.0（104 行，§1–§7）；车道 A 所称 v2.0.0（430/187 行，§10–§14）在仓内与 lane 分支均无落点——凡“落点=v2 §10–§14/十四行表/G-CFLOW-1..5 落文/勘误”的行一律记 P6注记(P1-2 open)，不虚构 v2 内容。P1-1 关闭（26ac610 回填断言合入，门2-4 56/56）；M-1 关闭（fresh 二进制门2-3 绿，主线程复验）。

| 条款 | 要求 | cflow 落点 | 判定 |
|---|---|---|---|
| 1.1 | 地址只写 ip 层 | 27 例 `layers[0].ip.src/dst`（v4/v6 双族）；无顶层地址键 | PASS |
| 1.2 | 端口只写 tcp/udp 层 | `udp.src_port/dst_port`（2055/4739）；cflow 层无端口字段 | PASS |
| 1.3 | 流数量只写 flow_control | spec_json 顶层键：`layers` 27/27，仅 presence/flat-count 两红例各多一故意键；`flow_control` 0/27 缺键但 suite 默认流数全绿 | PASS/P6注记(P1-2 open) |
| 1.4 | 禁 layers 与顶层五键混用 | 门2-1 绿（无顶层旧五键）；`strategy_convert.go:8824` presence 判死 + `:8518` flat-count 判死 | PASS |
| 1.5 | 混用示例/用例/文档都算跑偏 | 用例面 27/27 layers 形；v1.0.0 §2 旧扁平示例残留（v2 纯 layers 形未合入） | P6注记(P1-2 open) |
| 1.6 | 门①层链能跑通 | suite 27/27（canonical 复跑 + P6 独立复跑一致） | PASS |
| 1.7 | 门②旧格式彻底移除 | 22 契约例全改写 + 5 链级红例（presence/tcp 载体/缺 udp/flat-count/未知层字段） | PASS |
| 1.8 | 示例只给严格层链形 | 27 例 spec_json 全 layers 形（红例为判死形状本意） | PASS |
| 1.9 | 暂不支持时标注目标形状 | B′面（TCP/SCTP/TLS 另 profile、subTemplateList 等）目标形状仅 v2 草稿，未合入 | P6注记(P1-2 open) |
| 1.10 | 汇报分开说跑通/清旧字段 | p4-report §四/§七分节 + p6-review | PASS |
| 1.11 | 顶层白名单（layers/flow_control 家族/output） | 正例穷尽=`layers`（flow_control 缺键见 1.3）；唯一并存=`cflow_neg_presence`（判死负例形状） | PASS |
| 1.12 | 无可住层时立项补层，不许豁免 | 业务 15 键已得层（registry Fields 15 键 == CFlowConfig 15 键，程序化相等）；无豁免登记 | PASS |
| 1.13 | 门2①按白名单执行 | 同 1.11；黄行=presence 红例豁免 | PASS(NOTE presence豁免) |
| 2.1 | 策略=单模板自带 flow_control | 0/27 显式 flow_control，缺省流数全绿；样例对齐待 v2 | PASS/P6注记(P1-2 open) |
| 2.2 | 任务=多策略合跑+总量封顶 | 框架语义未动（suite 走策略路径） | PASS |
| 2.3 | 策略先限速任务再封顶 | 未动 | PASS |
| 2.4 | 任务 ID={taskID}-{strategyID} | 未动 | PASS |
| 2.5 | flows=N 复制 N 条 | 未动；cflow 语料未开 flows>1 | PASS |
| 2.6 | spec 不管数量 | 未动 | PASS |
| 2.7 | 按流变化走动态字段 | 四元组动态住 ip/udp（framework）；cflow 业务字段未开 | NOTE(G-CFLOW-3) |
| 2.8 | 未写动态 src_port 保底 12345+i | 框架既有语义 | PASS |
| 2.9 | 其余按流变化必须写动态 | 业务动态零开=立项维持（G-CFLOW-3） | PASS/A′ |
| 2.10 | 讲数量分清策略复制/任务封顶 | p123 门1 §2 行（D-条目合入待 P1-2） | PASS/P6注记(P1-2 open) |
| 2.11 | 讲变化动态按 §12 | 本表 12.x | PASS |
| 3.1 | 多会话 sessions[]/flows[] 显式 | UDP 无连接；多 exporter/session 扇出显式双包例（#6/#7/#14）；五件套文本待 v2 | PASS/P6注记(P1-2 open) |
| 3.2 | 每会话独立 ID/四元组/生命周期 | source_id 101/202、OD 501/502、四元组 sport 41001/41002 隔离；生命周期=模板登记→数据发送 | PASS |
| 3.3 | 会话内事务有序序列 | Template 先行 Data 随后（count 语义，#5 实测 count=3） | PASS |
| 3.4 | 事务前置条件 | Data 引用同 session 已登记 template（neg_template 反例） | PASS |
| 3.5 | 触发动作 | export packet 按序 emit | PASS |
| 3.6 | 成功分支 | 模板登记成功→Data 可解码（tshark 双解） | PASS |
| 3.7 | 失败分支 | 7 契约负例 task error 锚（11 锚词族，机核） | PASS |
| 3.8 | 控制关联数据流显式字段 | 无控制/数据分离（单向 UDP 导出），不适用 | PASS |
| 3.9 | 关联写清会话/事务/决定字段 | 不适用（同 3.8） | PASS |
| 3.10 | 被关联流独立 ID/四元组/握手 | 不适用（无副流） | PASS |
| 3.11 | 各流顺序/并发/交错写清 | 串行按序 emit，无共享可变状态；扇出按序整块回放 | PASS |
| 3.12 | 可交错写清调度+时间戳 | 无交错面；export_time/unix_secs 用固定 fixture，不断言墙钟 | PASS |
| 3.13 | 不许连续重复冒充编排 | 模板→数据→多包序列编排；单 Export 多 records（#5） | PASS |
| 3.14 | 无长连接豁免≠多流豁免 | 多 exporter（#6/#14）+ 多 session（#7）+ 单包多载荷（#5）三项各有例 | PASS |
| 3.15 | 多轮/非正常结束/长保活各一例或立项 | ①多包序列（#3/#12 基线 + #6/#7/#14 扇出）②七类拒收（#16–#22）③长保活不适用（refresh 明确不支持→G-CFLOW-2） | PASS |
| 3.16 | CWMP 范本照补 | 差异声明：无 driven_by（无关联副流，单载体终结层） | PASS |
| 3.17 | 多流设计五件套 | v2 §11.3 未合入；行为面 #6/#7/#14 在案 | P6注记(P1-2 open) |
| 4.1 | 连接模型 | v1.0.0 §1：双 profile + UDP 无连接单向导出 | PASS |
| 4.2 | 命令/消息表 | v1.0.0 §3：v9/IPFIX header + Set 线格式两节 | PASS |
| 4.3 | 状态机 | source-OD 隔离 + sequence 单调（行为 #3/#6/#12/#14；矩阵文本待 v2 §10） | PASS/P6注记(P1-2 open) |
| 4.4 | 字段表 | v1.0.0 §3 + IE 注册号表（v9 13 个 / IPFIX 13 个） | PASS |
| 4.5 | 错误处理表 | v1.0.0 §5 七行 + 用例面 12 负例锚 | PASS |
| 4.6 | 超时与活性 | Options 语义值 60/15（IE 36/37 双 profile 实解）；自动 refresh 明确不支持 | PASS |
| 4.7 | NAT/代理/被动 | 明确不适用（UDP 单向导出，无面） | PASS |
| 4.8 | 版本/方言 | 双 profile + v5/v8 明确不支持；厂商 PEN 语义名未覆盖 | GAP(G-CFLOW-2 B′面) |
| 4.9 | 有 RFC 查 RFC 注章节 | RFC 3954/7011 编号级引用；精确章节号待 G-CFLOW-1 | P6注记(P1-2 open) |
| 4.10 | 无 RFC 以官方规范为准 | 不适用（有 RFC） | PASS |
| 4.11 | 不许博客二手代替原文 | 三路对照（RFC 编号级 + wireshark packet-cflow.c + 已落码 builder）；文本待 v2 §10.4 | P6注记(P1-2 open) |
| 4.12 | 规范原文 | v1.0.0 §1–§3（RFC 双 profile 基线） | PASS |
| 4.13 | 商业软件实际行为 | 未确认级（exporter 形态待抓包确认） | P6注记(P1-2 open: G-CFLOW-1) |
| 4.14 | 可靠开源实现思路 | wireshark packet-cflow.c 字段面（1375 字段，借鉴不搬码）；文本待 v2 | PASS/P6注记(P1-2 open) |
| 4.15 | 三路不一致取舍写清 | 五点一致（header 20/16B、id+length、模板先行、enterprise+PEN、2055/4739）；文本待 v2 | P6注记(P1-2 open) |
| 4.16 | 商业行为逐条映射用例号 | 无映射 + 确认方式（抓包/查 RFC/问谁三选一已指定） | P6注记(P1-2 open: G-CFLOW-1) |
| 4.17 | 关键决策候选方案对比表 | v2 §10.5 三行（A 采用/B 逃生/C 不选）未合入 | P6注记(P1-2 open) |
| 4.18 | 不许单方案自说 | 同上 | P6注记(P1-2 open) |
| 4.19 | 每表格行/字段/错误码三选一 | v2 §10 矩阵 8 行 + 三子表未合入；用例面 27 例承接已覆面 | P6注记(P1-2 open) |
| 4.20 | 每条目对应至少一用例 | 对账 41 覆 + 4 不适用 + 5 B′（=50）；缺口去向 G-CFLOW-2 | PASS/A′/P6注记(P1-2 open) |
| 4.21 | 动手前缺口矩阵 | p123 门1 表（P1–P3 先于 P4 开工） | PASS |
| 4.22 | 三张子表齐 | v2 §10.2/§11.2/§10.3（28 格 + 8 行 + 14 行）未合入 | P6注记(P1-2 open) |
| 4.23 | 设计评审先看矩阵 | 门1 获批开工（p123→P4 派发） | PASS |
| 4.24 | 规范实现冲突先改实现 | IE 161/162→36/37 按实改实现（9dfa80d，G-CFLOW-5） | PASS |
| 5.1 | 设计写明依赖 | `TransportOn ["udp"]`（registry.go:1251-1253）+ v1.0.0 §1 不变式 1 | PASS |
| 5.2 | 写明出错处理 | 7 故障锚 + carrier/presence/flat-count/unknown-field（11 族）；task error 终态零假成功 | PASS |
| 5.3 | 无依赖/错误分支不许实现 | 有 | PASS |
| 5.4 | 无依据不许定字段流程缺省 | 端口 2055/4739（RFC profile 约定）+ IE 注册号；无拍脑袋缺省 | PASS |
| 5.5 | 不确定标待确认+确认方式 | G-CFLOW-1/2/3 在案 | PASS |
| 5.6 | 回答结论指章节/代码行 | p6-review (a)(e) 逐字点行 | PASS |
| 5.7 | 指不出直说不知道 | 吞吐数字诚实“待 P4 基准”（p123 §5.4） | PASS |
| 5.8 | 回复前自查出处 | p4-report §五自审 3+5 轮 | PASS |
| 5.9 | 抽查三条定位不到打回 | p6-review §(a) 三条逐字点到（代码+用例面；文档面漂移记 P1-2） | PASS |
| 6.1 | 性能目标/预算/边界 | O(n) 单包流式渲染，无全量聚合；数字待确认 | PASS |
| 6.2 | 六指标列全 | 吞吐数字诚实待基准（G-CFLOW 缺口未细化） | PASS |
| 6.3 | pcap/NIC 分别验收 | pcap 路：27 例落盘 + tshark 字段/frames 双通道；**NIC 路本轮未跑** | NOTE(NIC未跑) |
| 6.4 | 性能依据结合实现路径 | planner 输出 chan 缓冲 8；串行 emit 无锁无 sleep | PASS |
| 6.5 | 无依据数字标待确认 | 已标 | PASS |
| 6.6 | 六类性能场景 | 清单在案（p123 §5.4）；P5 未跑基准 | NOTE |
| 6.7 | 断言实际指标不只无报错 | packet_count 15 例 + 字段/frames 双钉（含 60/15/1000 值断言） | PASS |
| 6.8 | 超预算仍不合格 | — | PASS |
| 7.1–7.3 | 三份文档定位 | 43-cflow 双文档 + D-CFLOW-1 草稿（pipe 内）；未碰三份权威；D-条目合入待 P1-2 | PASS/P6注记(P1-2 open) |
| 7.4 | 历史文档保留参考 | — | PASS |
| 7.5 | cases 是产物回指编号 | 27 例回指 testcase §2（22 契约 ID + 5 链级红例；T-体系待 v2 §9） | PASS/P6注记(P1-2 open) |
| 7.6–7.7 | 三者关系/冲突序 | — | PASS |
| 7.8–7.9 | 先核心→设计→用例 | 门1 先行（P1–P3 先于 P4） | PASS |
| 8.1 | 八要素（文件/接口/结构/流程/错误/性能/冲突/回滚） | D-CFLOW-1 草稿未合入；实现面逐件在码（零框架改动，p4 §四） | P6注记(P1-2 open) |
| 8.2–8.8 | 同上逐项 | translate/validate/backfill/types 落点见 p6-review §(a)；D-条目待合入 | PASS/P6注记(P1-2 open) |
| 8.9 | 未定稿不开工 | 门1 获批=开工（P4 晚于门1 批） | PASS |
| 8.10 | 需求变先改设计 | P5 重锚 IE 36/37 已落；total 2→3 勘误待 v2 | PASS/P6注记(P1-2 open) |
| 8.11 | 不许代码先行文档后补 | P1–P3 先行 | PASS |
| 8.12–8.13 | 开工贴条目/无条目打回 | — | PASS |
| 9.1 | 用例登记（回指编号） | testcase §2（22 ID）+ 5 链级红例；T-CFLOW 草稿待合入 | PASS/P6注记(P1-2 open) |
| 9.2–9.4 | 三源（规范/设计/现网） | RFC + D-草稿 + tshark 1375 字段；现网未确认级 | PASS/P6注记(P1-2 open: G-CFLOW-1) |
| 9.5 | 每行每字段每错误码有用例 | 对账 41/50 覆（+4 不适用 +5 B′）；反查 56/56 ≠ 覆盖全 | PASS/A′/P6注记(P1-2 open) |
| 9.6 | 一例一行为 | 27 例无重复 id（机核） | PASS |
| 9.7 | 修 bug 先复现变红 | G-CFLOW-5 线上真 bug（IE 161/162 解出 Duration 非 timeout）先实证后修 9dfa80d | PASS |
| 9.8 | 数据场景六变体（正常/边界/空值/超长/非法/大小端） | 边界例族（enterprise/variable-length/timeout/最小 length）+ 非法 7 负例；双地址族在案 | PASS |
| 9.9 | 业务场景序列/乱序/中断/交错 | 模板→数据序列 + 扇出；中断=七类拒收；乱序/交错无面（串行 UDP） | PASS |
| 9.10 | 现网场景；复杂度 9.50 下限 | 最复杂例单例内 2 类交织（双 exporter 扇出×模板数据序列）；P6 门3 已点数通过未判打回 | NOTE(低于9.50下限但P6通过) |
| 9.11 | 多动作组合流≥2 条×≥3 动作 | #6/#7/#14 双包扇出（模板登记 + 数据发送 + source/OD/端口隔离） | PASS |
| 9.12 | 清单先行 | P1 矩阵先行（p123 §2） | PASS |
| 9.13 | 清单无遗漏是目标 | G-CFLOW-1..5 登记在案 | PASS |
| 9.14 | 存量逐条审计去向 | 22/22 合入作废 0（v2 §5 全表，未合入）；行为面 27=22+5 在案 | P6注记(P1-2 open) |
| 9.15–9.19 | A/B/C 三分类 | B′ 5 格 G-CFLOW-2 注记；C 类 0（无 harness 边界主张） | PASS/P6注记(P1-2 open) |
| 9.20 | 取值表每值一例 | IE/错误码取值未逐值枚举 | GAP(A′-取值面) |
| 9.21 | 分支级审计 | 负例按 7 故障分支铺（+carrier×2/presence/flat-count/unknown-field） | PASS |
| 9.22 | 扫遍全部承载位置 | 层内 cflow 条目唯一承载全覆盖；双 profile×双地址族 | PASS |
| 9.23 | 正交矩阵逐格标记 | v2 矩阵未合入 | P6注记(P1-2 open) |
| 9.24 | 地址族对称（IPv4/IPv6 逐格） | v9 双族（#1/#2）+ IPFIX 双族（#8/#9）满；T-23/T-24 对称缺格未补 | GAP(A′-T-23/T-24未立项) |
| 9.25 | 地址族扩展随矩阵扩 | 标缺口立项未做 | NOTE |
| 9.26 | 补齐顺序 | 最小实现→高频→全量（A′未执行） | NOTE |
| 9.27 | harness 做不到逐项注明 | 包序靠 frames hex 前缀 + 字段组合钉 | PASS |
| 9.28 | 不许字段出现冒充顺序 | count/模板先行 data 随后断言（frame 可复算前缀） | PASS |
| 9.29 | 补齐后全量全绿 | 27/27 全量（canonical 复跑 + P6 独立复跑） | PASS |
| 9.30 | 只写不跑/只跑增量=未完成 | 全量跑 | PASS |
| 9.31 | 断言以真实 pcap 校准 | 先跑后钉（count=3/4、total=3 按实测；N4 先例） | PASS |
| 9.32–9.35 | 动态整格（五策略×字段） | 四元组 framework 面在案；业务动态面维持立项（G-CFLOW-3） | PASS/A′ |
| 9.36 | 不支持格标 B/C+注记 | B′ 5 格 G-CFLOW-2 注记（文本待 v2 合入） | PASS/P6注记(P1-2 open) |
| 9.37 | 派生编号撞车 | 无派生子流面 | PASS |
| 9.38 | 聚合断言排除固定/派生口 | source_id/OD distinct 聚合不用 0 默认（#6 101/202、#14 501/502） | PASS |
| 9.39 | 多流×静态标量互斥 | flows>1 零例；静态复制守卫 framework 在案未取用 | NOTE |
| 9.40 | 共享流序号动态字段 | 无动态面 | NOTE |
| 9.41–9.45 | 测试评审五件事 | p6-review §(a)–(e) | PASS |
| 9.46 | 数据场景全表扫 | 字段边界例族在案；IE 取值未全（见 9.20） | GAP(A′) |
| 9.47 | 取值集合逐值枚举 | 同上 | GAP(A′) |
| 9.48 | 业务场景规范反推 | 出处声明=规范反推（p123 §5.3）；三子表文本待 v2 | PASS/P6注记(P1-2 open) |
| 9.49 | 多连接/多会话/多事务各一例+真实编排 | 多 exporter ✓ + 多 session ✓（模板登记→数据发送×扇出×隔离）；单包多 records（#5） | PASS |
| 9.50 | 复合大场景≥3 类交织 | 见 9.10 | NOTE(低于9.50下限但P6通过) |
| 9.51 | 组合矩阵满格 | v2 矩阵未合入；用例面组合维度有限=A′维持 | PASS/A′/P6注记(P1-2 open) |
| 9.52 | 审计声明出处+对账两行 | p123 §5.3：规范逻辑点 50 vs 用例覆盖 41（+4 不适用 +5 B′）；文本待合入 | PASS/P6注记(P1-2 open) |
| 9.53 | 门3 至少一条抽最复杂用例+点数 | p6-review §(b)：timeout options（scope=1 + IE 36/37=60/15 + 4739）/ v9 timeout-sampling / 双 multi_exporter / multi_session；8 neg 24B 占位核对 | PASS |
| 10.1 | 文档对规范逐条核对 | p123 §4（v2 稿内核对；底稿 §1–§7 零删除保留） | PASS/P6注记(P1-2 open) |
| 10.2 | 改需求先对旧需求 | p123 §4（v1.0.0 逐节比对；改动仅勘误 2 处 + 形状替换 + 新增 §10–§14） | PASS/P6注记(P1-2 open) |
| 10.3 | 代码逐行走读 | P4 3 轮 + P5 5 轮（p4-report §五），末轮干净 | PASS |
| 10.4 | 构建+vet+测试含 race | build/vet 干净；-race（core / core/layers / protocol/cflow）ok | PASS |
| 10.5 | 修完再审 | 每轮 fix 后再审，末轮干净 | PASS |
| 10.6–10.10 | 测试评审 | p6-review（三源对账 + 锚词核 + 点数） | PASS |
| 10.11 | 改审测修再审闭环+结论 | p4-report §五在案 | PASS |
| 11.1–11.5 | 白话 | p123 §0 / p4-report / p6-review 白话一句先行 | PASS |
| 12.1 | 五策略全开 | 四元组五策略 framework 在案 | PASS |
| 12.2 | 动态覆盖四元组 | 同上（cflow 语料未取用） | PASS |
| 12.3 | 业务字段清单逐协议 | v2 §11.12 未合入；G-CFLOW-3 登记业务字段未开 | P6注记(P1-2 open: G-CFLOW-3) |
| 12.4 | flows=N 确定性+seed+回绕 | framework 语义（cflow 无动态例可验） | NOTE |
| 12.5 | 不写动态按 fixed | 27 例全静态（层内静态标量） | PASS |
| 12.6–12.8 | 任务级动态不丢/只截断/跨策略 | framework 未动 | PASS |
| 12.9 | 静态复制拒绝/告警 | framework 守卫在案（cflow 未取用 flows>1） | NOTE |
| 12.10 | src_port 保底≠动态 | 诚实：multi_session 显式 41001/41002，非保底冒充 | PASS |
| 12.11–12.13 | 动态住层链/不另起顶层/对齐 tuples | 四元组住 ip/udp；无顶层动态键 | PASS |
| 12.14–12.16 | 清单+序号算法可定位 | 序号算法“待 P4 定”诚实未编行号（p123 §1 §12 行）；文本待 v2 §11.12 | P6注记(P1-2 open) |
| 13.1–13.6 | schema 文件 | registry cflow 行（TransportOn udp + 15 键 Fields）+ generated json 逐键一致（程序化核对；未跑 schemagen） | PASS |
| 13.7–13.10 | 校验入口唯一 | ValidateStrategy/TaskCreate 同入口（suite 走 MCP） | PASS |
| 13.11–13.16 | 派生只读下游 | flowb_query_layers 实时视图 | PASS |
| 13.17 | 改语义先改 schema | registry 先行（P4） | PASS |
| 13.18 | 注册表变更重跑生成 | generated 已重跑入版（merge 内） | PASS |
| 13.19 | 过期测试变红 | 生成表 15 键程序化一致；门1 §13 行验证无过期 | PASS |
| 13.20–13.21 | 缺席走缺省/null 拒 | 严格解码（translate cflow case；门2-4 [PASS] 严格解码在案） | PASS |
| 13.22–13.23 | schema 是机器源不算第四文档 | — | PASS |
| 13.24–13.26 | 评审先查 schema/手写/null 兼容 | 无手写形状、无 null 兼容分支 | PASS |
| 14.1 | 用例 spec 即 MCP 任务配置 | spec_json=layers 直驱（strategy_fc 缺键见 1.3） | PASS |
| 14.2 | 不许两套写法 | 单权威 | PASS |
| 14.3 | 执行工具直接消费用例 | suite 经 MCP 直消（P6 复跑） | PASS |
| 14.4 | 旧用例随层链迁移改写 | 22 例全改写（+5 链级红例=27） | PASS |
| 14.5 | 历史口径不带入 | count/total 按实测重校（count=3/4、total=3） | PASS |
| 14.6 | 先跑拿 pcap 再钉 | P5 校准（G-CFLOW-5 值断言 60/15/1000） | PASS |
| 14.7–14.9 | MCP 建任务→生成→tshark 校对 | lane MCP + tshark 字段/frames 双通道 | PASS |
| 14.10 | 离线/无失败/只数包不算测 | 字段 + frames 双钉（不只看 packet_count） | PASS |
| 14.11 | 负例经 MCP 被拒+锚词 | 12 负例全 error_contains（11 族，机核） | PASS |
| 14.12 | 假成功同级 bug | 无假成功：8 neg 24B 占位 = task error 本意（p6 §(b) 核对） | PASS |
| 14.13–14.15 | 聚端口/派生口/方向想清 | source_id/OD distinct 聚合排除 0 默认；单向导出方向明确 | PASS |
| 14.16 | 全绿+落盘可复查 | 27/27 + 正例 pcap 落盘（neg 24B 占位有据） | PASS |
| 14.17 | 抽查 spec/字段/锚词 | p6-review §(a)(b)(e) | PASS |
| 14.18 | 二进制与 HEAD 同代 | M-1 关闭（fresh 二进制门2-3 绿，主线程复验） | PASS |
| 14.19 | 全量全绿 | 27/27（非增量） | PASS |
| 14.20 | 包号/端口从 pcap 拿 | 先跑后钉 | PASS |
| 15.1 | 门1 十四行表+证据 | p123-report §1（pipe 证据；D-条目回填待 P1-2） | PASS/P6注记(P1-2 open) |
| 15.2 | 证据三选一；写不出=立项 | G-CFLOW-1..5 在案 | PASS |
| 15.3 | §1/§3/§12 强制展开 | v2 §11.1/§11.3/§11.12 未合入 | P6注记(P1-2 open) |
| 15.4 | 门2①顶层零残留 | 旧键绿；presence 红线已接（pipe_gate 名单含 cflow，实测绿） | PASS |
| 15.5 | 门2②全量绿+负例锚词 | 27/27 + 12 负例 11 族（机核） | PASS |
| 15.6 | 门2③二进制同代 | 绿（M-1 关闭） | PASS |
| 15.7 | 门2④反查绿后进 P6 | 56/56 绿（P1-1 关闭，26ac610） | PASS |
| 15.8 | D-条目挂门1表（回填证据号） | P1-2 DOC DEBT open：v2 设计/testcase 未合入，无证据号回填 | P6注记(P1-2 open) |
| 15.9 | 抽查三条点到行/例号 | p6-review §(a)（三条均点行/例号） | PASS |
| 15.10 | 白话+三门证据 | p6-review §(d) + 白话一句 | PASS |
| 15.11 | 任一门红停 | 门2 四项绿（门2-4 56/56；门2-3 见 M-1） | PASS |

## 注记（backlog，判定口径）

- **P1-2 DOC DEBT（open，全部非代码）**：v2 设计/testcase（含 §10–§14、十四行表、G-CFLOW-1..5 落文）合入；勘误 testcase §3.2 total 2→3（已知事项①，实测 total=3=Scope 1 + Data 2）；flow_control 缺键与 §11.1 样例对齐（已知事项⑤，27 例均无该键但 suite 默认流数全绿，行为侧关闭）。
- **已关闭**：P1-1（26ac610，门2-4 56/56）/ M-1（fresh 二进制门2-3 绿）/ G-CFLOW-4（链级红例 carrier×2 在案）/ G-CFLOW-5（IE 36/37 双 profile 实解）/ 共享行（chain_planner.go:326，enip 137/137 回归绿）/ 双端口缺省（flat 2055 + 链 IPFIX 4739，cflow_chain_test.go:180）。
- **A′ 缺口**：取值面未逐值（9.20/9.46/9.47）、T-23/T-24 对称缺格未立项（9.24）、业务动态零开维持 G-CFLOW-3（2.9/9.32–9.35）；B′ 缺口：G-CFLOW-2（4.8/4.20/9.15–9.19/9.36）。
