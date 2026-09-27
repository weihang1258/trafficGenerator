# AMQP（D-AMQP-1 #70）P6 248 条款逐条比对表

> 口径：docs/CORE_MEMORY.md（248 条，2026-09-26）。落点 = amqp @ HEAD 实测证据（代码行号自核；用例号 = cases/amqp.json）。**本表已按 P6 修轮后状态更新（分支 `pipe/amqp-p6fix` 集成 `113603e`；scoped 复评关单）：GAP(1)/GAP(2)/GAP(3)/GAP(4)/GAP(5)/GAP(6) 全部关闭（见下注记行）。** 判定：PASS=满足，NOTE=注记（n1–n9 见 p6-review.md §十）。

| 条款 | 要求 | amqp 落点 | 判定 |
|---|---|---|---|
| 1.1 | 地址只写 ip 层 | 14 正例 layers[0].ip.src/dst（cases #1–#14，machine 核 14/14） | PASS |
| 1.2 | 端口只写 tcp/udp 层 | layers[1].tcp.src_port/dst_port（24 例全） | PASS |
| 1.3 | 流数量只写 flow_control | spec 顶层无数量键；单流模板（族惯例未用 flow_control，n3） | PASS |
| 1.4 | 禁 layers 与顶层五键混用 | 正例顶层键=layers 唯一；#22 `src_ip` 判死负例 | PASS |
| 1.5 | 混用示例/用例/文档都跑偏 | design §2/§13.1 纯层链样例；#21 判死 | PASS |
| 1.6 | 门①层链能跑通 | suite 24/24（本报告独立复跑 RESULT 行） | PASS |
| 1.7 | 门②旧格式彻底移除 | 门2-1 绿（0 残留）；#21/#22 执法负例 | PASS |
| 1.8 | 示例只给严格层链形 | design §13.1 样例 {layers,[ip,tcp,amqp]} | PASS |
| 1.9 | 暂不支持明确标注 | G-AMQP-1（AMQPS/TLS 5671）；AMQP 1.0 明确不支持 | PASS |
| 1.10 | 汇报分开说 | p4-report §二/§七 分节 | PASS |
| 1.11 | 顶层白名单 | 14 正例顶层键=layers 唯一；#22 负例；chain ⑩ schema 门拒 src_mac | PASS |
| 1.12 | 无可住层时立项不许豁免 | 无游离字段；amqp 6 键住层链条目；TLS→G-AMQP-1 | PASS |
| 1.13 | 门2① 白名单制 | pipe_gate 门2-1 绿（presence 黄=执法对象） | PASS |
| 2.1 | 策略=单模板自带 flow_control | 单 AMQP 连接模板（design §12 行）；suite 直消 spec_json | PASS |
| 2.2 | 任务=多策略合跑+封顶 | 框架语义未动 | PASS |
| 2.3 | 策略先限速任务再封顶 | 未动 | PASS |
| 2.4 | 任务 ID={taskID}-{strategyID} | 未动 | PASS |
| 2.5 | flows=N 复制 N 条 | 未动；本协议用例单流 | PASS |
| 2.6 | spec 不管数量 | spec_json 无数量键 | PASS |
| 2.7 | 按流变化走动态字段 | 四元组住 ip/tcp 层（框架）；#12 第二连接 src_port 12346 | PASS |
| 2.8 | 未写动态 src_port 保底 12345+i | tcp 层既有语义；用例显式 12345 | PASS |
| 2.9 | 其余按流变化必须写动态 | design §13.12 逐字段开/不开+理由 | PASS |
| 2.10 | 讲数量分清两层 | design §12 | PASS |
| 2.11 | 讲变化按 §12 | §13.12 | PASS |
| 3.1 | 多会话显式声明 | connections[] 显式（#12 双连接）；connection=会话（§13.3 会话表） | PASS |
| 3.2 | 独立 ID/四元组/生命周期 | §13.3；#12 声明 src_port 12345/12346（线上同流 G-AMQP-2，n7） | PASS |
| 3.3 | 会话内事务有序序列 | #8 五轮序；#10 tx 三轮 | PASS |
| 3.4 | 事务前置条件 | §13.3 事务表 t1–t6 逐行 | PASS |
| 3.5 | 触发动作 | 同上 | PASS |
| 3.6 | 成功分支 | 同上 | PASS |
| 3.7 | 失败分支 | 同上（各守卫→task error）+ #15–#20 | PASS |
| 3.8 | 控制关联数据流显式关联字段 | 无副流（§13.3 声明）；修轮后 tag 关联两钉（`consumer_tag=ctag1` p13/p15 同值、`delivery_tag=1` p15/p18 同值，#8） | PASS |
| 3.9 | 关联写清三件事 | §13.3 关联段（归属连接/channel/tag 字段） | PASS |
| 3.10 | 被关联流独立 ID/四元组/握手 | 无副流，不适用（声明在案） | PASS |
| 3.11 | 顺序/并发/交错写清 | §13.3 时间线（连接内序/连接间不假设/心跳中插） | PASS |
| 3.12 | 调度方式+时间戳 | 事件序逐包 Emit（planner.go:20-134） | PASS |
| 3.13 | 不许连续重复冒充编排 | #3–#10 真编排（多轮方法序逐包钉） | PASS |
| 3.14 | 豁免边界 | 不主张豁免：多流 #12、单包多载荷 #11/#7（testcase §9.4） | PASS |
| 3.15 | 三项（多轮/非正常/长保活） | ①#3–#10 ②#15–#20 ③#4/#11/#14；周期调度明确不支持 | PASS |
| 3.16 | CWMP 范本 | 差异诚实声明（无 driven_by/副流） | PASS |
| 3.17 | 五件套 | design §13.3 全 | PASS |
| 4.1 | 连接模型 | §12.1 行1（client→server 单 TCP 5672） | PASS |
| 4.2 | 命令/消息表 | §4.1 表 + §12.1 行2；cancel/deliver 表体已勘误（basic.cancel=30 / basic.deliver=60，修轮 m2） | PASS |
| 4.3 | 状态机 | §5 表 + planner.go:196-417 | PASS |
| 4.4 | 字段表 | §4 编码节（frame/shortstr/properties/BodySize/frame_max） | PASS |
| 4.5 | 错误处理表 | §9 九行锚词表（实测化） | PASS |
| 4.6 | 超时与活性 | §12.1 行6（heartbeat 显式事件；周期调度不支持） | PASS |
| 4.7 | NAT/代理 | §12.1 行7 显式不适用 | PASS |
| 4.8 | 版本/方言 | §12.1 行8（0-9-1+RabbitMQ 扩展；1.0 不支持；TLS→G-AMQP-1） | PASS |
| 4.9 | 有 RFC 查 RFC 注章节 | 无 RFC→0-9-1 官方规范；精确章节挂 G-AMQP-1（§5.5 合规） | PASS |
| 4.10 | 无 RFC 以官方规范为准 | 0-9-1 wire-level spec | PASS |
| 4.11 | 不许博客二手 | 三路=规范原文/tshark/现网形态 | PASS |
| 4.12 | 规范原文 | §12.4 ① | PASS |
| 4.13 | 商业软件行为 | §12.4 ② RabbitMQ（未确认级→G-AMQP-1） | PASS |
| 4.14 | 开源实现思路 | §12.4 ③ wireshark packet-amqp.c 493 字段 | PASS |
| 4.15 | 三路不一致取舍 | §12.4 取舍段 | PASS |
| 4.16 | 商业行为→用例映射 | §13.2 十行表 | PASS |
| 4.17 | 候选方案对比 | §12.5 A/B/C | PASS |
| 4.18 | 不许单方案 | 三案 | PASS |
| 4.19 | 每行/字段/错误码三选一 | §12.1/§12.2/§12.3 逐格行；重数句桶界（n8） | PASS |
| 4.20 | 每条目≥1 用例 | §12.3 各行对 20 ID；get-ok/cancel/cancel-ok 零出现登记在案（修轮 m3，machine 枚举 UNUSED） | PASS |
| 4.21 | 动手前缺口矩阵 | §12 先行（P1） | PASS |
| 4.22 | 三张子表 | §12.2/§12.3/§13.2 | PASS |
| 4.23 | 评审先看矩阵 | 门1 获批 ef124e3 | PASS |
| 4.24 | 规范实现冲突先改实现 | p123 勘误按 builder 常量改文档 | PASS |
| 5.1 | 依赖声明 | design §14（tcp+ip；无 udp/tls）+ registry.go:487 | PASS |
| 5.2 | 出错处理 | §14 错误分支三类 | PASS |
| 5.3 | 无依赖/错误分支不许实现 | 有 | PASS |
| 5.4 | 无依据不许定字段 | 5672（RabbitMQ 现网+FieldContract）；常量对 0-9-1 §4.2.4 | PASS |
| 5.5 | 不确定标待确认+确认方式 | G-AMQP-1（抓包/原文/官方文档三选一） | PASS |
| 5.6 | 结论指章节/行号 | 本报告逐条 | PASS |
| 5.7 | 指不出直说 | P1 序号算法"待 P4 定"诚实；修轮后已回填 §13.12（框架面，layer_dyn 解析 + 业务字段全关声明） | PASS |
| 5.8 | 自查出处 | 三层回指（本报告） | PASS |
| 5.9 | 抽查三条定位 | 本报告 §二 | PASS |
| 6.1 | 性能目标/预算/边界 | §14 性能节（O(n)/双路） | PASS |
| 6.2 | 六指标列全 | 数字待基准（§6.5 合法待确认） | PASS |
| 6.3 | pcap/NIC 双路验收 | §14 双路（落盘实测+NIC `tcp port 5672`） | PASS |
| 6.4 | 性能依据结合实现路径 | 流式 EmitMsg/无锁无 sleep/无聚合 | PASS |
| 6.5 | 无依据数字标待确认 | 已标 | PASS |
| 6.6 | 六类性能场景 | 清单在案 + P5 跑测声明 | PASS |
| 6.7 | 断言实际指标 | packet_count 精确 + 字段双钉 | PASS |
| 6.8 | 超预算不合格 | 声明在案 | PASS |
| 6.9 | 每份设计有性能节 | §14 有 | PASS |
| 6.10 | 无目标不许实现/宣称 | 目标+方法+失败边界在案 | PASS |
| 7.1 | CORE_MEMORY 地位 | 未碰（只读） | PASS |
| 7.2 | CODE_DESIGN 唯一入口 | 未碰（车道声明） | PASS |
| 7.3 | TEST_CASES 唯一入口 | 未碰；cases 回指 testcase §2 | PASS |
| 7.4 | 历史文档保留 | v2.0.0 双文档保留 | PASS |
| 7.5 | cases 回指编号 | 24 例回指 §2（20 ID）+§13-P2 四红 | PASS |
| 7.6 | 三者关系 | 契约→实现→用例 顺序 | PASS |
| 7.7 | 冲突序 | 无冲突 | PASS |
| 7.8 | 先核心再设计再用例 | 门1 先行 | PASS |
| 7.9 | 无设计/测试条目不许改码 | D-AMQP-1 §14 定稿=开工 | PASS |
| 8.1 | 改哪几个文件 | §14 文件清单 | PASS |
| 8.2 | 接口签名 | §14 签名段 | PASS |
| 8.3 | 数据结构 | §14（AMQPConfig 6 键） | PASS |
| 8.4 | 主流程 | §14 主流程段 | PASS |
| 8.5 | 错误分支 | §14 三类 | PASS |
| 8.6 | 性能边界 | §14 性能节 | PASS |
| 8.7 | 与现有逻辑冲突点 | §14 三条（5672 双通道/校验面/parseSubconfigJSON） | PASS |
| 8.8 | 回滚方式 | §14（P4 差量全 revert） | PASS |
| 8.9 | 未定稿不开工 | 门1 获批=定稿 | PASS |
| 8.10 | 需求变先改设计 | P4 差量均在 §14 内 | PASS |
| 8.11 | 不许代码先行 | P1–P3 先行 | PASS |
| 8.12 | 开工贴条目 | p4-report 引 D-AMQP-1 | PASS |
| 8.13 | 无条目 diff 打回 | 有条目 | PASS |
| 9.1 | 用例登记 | 回指 testcase §2（ID 权威） | PASS |
| 9.2 | RFC/官方文档源 | 0-9-1 线规范 | PASS |
| 9.3 | CODE_DESIGN 源 | D-AMQP-1 §14 | PASS |
| 9.4 | 现网行为源 | 未确认级→G-AMQP-1（§5.5 不写死） | PASS |
| 9.5 | 每行/字段/错误码有用例 | §12 对账 50 点；channel-0 reserved 已增 `TestValidateChannelAndStateGuards`（12 子例，修轮 m1） | PASS |
| 9.6 | 一例一行为 | 20 ID 唯一语义 + 4 链红 | PASS |
| 9.7 | 修 bug 先复现变红 | P5 修轮①三红例先红后绿 | PASS |
| 9.8 | 数据场景六变体 | §12.3（frame 四型/channel/分段/BodySize/properties/参数/族） | PASS |
| 9.9 | 业务场景 | t1–t6 + 状态机 + close 后守卫 | PASS |
| 9.10 | 现网场景+9.50 下限 | 编排骨架在；复杂度口径见 9.50 | NOTE |
| 9.11 | 多动作组合流≥2×≥3 | #8（5 轮）/#10（tx 三轮）/#3–#7 | PASS |
| 9.12 | 清单先行 | P1 §12 矩阵先行 | PASS |
| 9.13 | 清单无遗漏是目标 | 50 点对账 | PASS |
| 9.14 | 存量逐条审计去向 | §5 去向表 20/20 合入；legacy 钉子已回补（字段 66→191，30 项点名钉子脚本复验 30/30） | PASS |
| 9.15 | A 类直写 | 20 ID 直写 | PASS |
| 9.16 | B 类立项 | 无 B 类 | PASS |
| 9.17 | C 类注明 | 无 C 类 | PASS |
| 9.18 | C 类只免引擎内部 | 无 C 类 | PASS |
| 9.19 | 动词出现≠覆盖 | 方法序逐包钉回（修轮 M1：#3/#5/#6/#7/#9/#10/#11/#14） | PASS |
| 9.20 | 取值表每值一例 | frame type 四值全覆盖；get-ok 60/71、cancel 60/30、cancel-ok 60/31 已登记并入 G-AMQP-3（修轮 m3） | PASS |
| 9.21 | 分支级审计 | channel-0 保留位及全族守卫分支已覆盖（12 子例单测 + #18） | PASS |
| 9.22 | 扫遍承载位置 | 单承载（layers amqp 条目） | PASS |
| 9.23 | 正交矩阵逐格 | §12.3 十二行逐格有例号 | PASS |
| 9.24 | 地址族对称 | #1/#13 双族（契约自注册格满）；IPv6 仅一格（n9） | PASS |
| 9.25 | 地址族扩展随矩阵 | #13 独立 IPv6 fixture（offset 74） | PASS |
| 9.26 | 补齐顺序 | 最小→高频→全量 | PASS |
| 9.27 | harness 边界逐项注明 | §3.7 注明包序/方向；tag 关联两钉交付（ctag1 p13/p15、delivery_tag=1 p15/p18） | NOTE |
| 9.28 | 不许字段出现冒充顺序 | 方法序逐包 index 钉 | PASS |
| 9.29 | 补齐后全量全绿 | 24/24 全量（本报告独立复跑） | PASS |
| 9.30 | 只跑增量=未完成 | 全量复跑 | PASS |
| 9.31 | 断言以真实 pcap 校准 | packet_count/包号先跑后钉（notes 记旧值） | PASS |
| 9.32 | 动态字段×策略整格 | 业务字段不开（理由在案）；四元组走框架（族级） | PASS |
| 9.33 | 不抽样代表 | 同上 | PASS |
| 9.34 | 动态三问 | 无业务动态（不适用声明） | PASS |
| 9.35 | 锚点选可观察输出 | 四元组锚点走框架 | PASS |
| 9.36 | 不支持标 B/C | 序号算法已回填（§13.12 框架面 + 业务全关声明） | PASS |
| 9.37 | 派生编号撞车 | 无派生端口（单流） | PASS |
| 9.38 | 聚合断言混入 | 无 distinct 断言（G-AMQP-2 立项） | PASS |
| 9.39 | 多流×静态标量互斥 | flows=1 静态 fixture | PASS |
| 9.40 | 共享流序号 | 无按流序号业务字段 | PASS |
| 9.41 | 清单先行无遗漏 | P1 矩阵 + §9 固定动作 | PASS |
| 9.42 | 用例回指规范/设计 | 三源回指（本报告 §一） | PASS |
| 9.43 | 断言输出不是摆设 | 6 正例（#3/#5/#6/#7/#9/#10/#11/#14）响应帧/关联已逐帧钉回 | PASS |
| 9.44 | 失败路径真会红 | 10 负例锚词 10/10；链红 4 例（P5 先红后绿） | PASS |
| 9.45 | 全量全绿 | 24/24 | PASS |
| 9.46 | 数据场景全表扫 | 128/4096/200B/override/BodySize 0/6/200 在；shortstr 255/256→T-20 | PASS |
| 9.47 | 取值集合逐值枚举 | get-ok/cancel/cancel-ok 已枚举并入 G-AMQP-3；wire_fault 5 余值立项维持 | PASS |
| 9.48 | 业务场景规范反推 | §13.3 t1–t6 自 0-9-1 §2.2 反推 | PASS |
| 9.49 | 多流/多会话/多事务必查 | 多事务 #8/#10/#11；多会话 #12（同流 G-AMQP-2）；多流 N/A（声明） | PASS |
| 9.50 | 复合大场景≥3 类 | #8 三类交织齐（多事务 5 轮逐帧 + 内容序列三帧 + tag 跨帧关联），断言 28 点（27 fields + 1 frame） | PASS |
| 9.51 | 组合矩阵满格 | §12.3 逐格有例号 | PASS |
| 9.52 | 对账两行+出处声明 | §9.3 修轮后口径 50=8+28+14、29+10+11=50（strict 四桶互斥，与 design §12.2 同口径）；§9.8 同口径对齐（94b01b6） | PASS |
| 9.53 | 门3 抽最复杂+点数 | 修轮后 #8=28 点；scoped 复评复核关单 | PASS |
| 10.1 | 文档对规范逐条核对 | §17.1/17.2；§4.1 两行已勘误回正 | PASS |
| 10.2 | 改需求先对旧需求 | §17.2 v1.0.0 逐条（无静默删除） | PASS |
| 10.3 | 代码逐行走读 | P4 自审 3 轮 + P5 2 轮 | PASS |
| 10.4 | 构建+vet+测试含 race | 本报告独立补证（build/vet/-race 全 exit 0） | PASS |
| 10.5 | 修完再审 | P5 修轮后复审在案 | PASS |
| 10.6 | 测对函数/路径 | channel-0 守卫分支有单测 12 子例 | PASS |
| 10.7 | 输入真能触发 | 单测命中 :293 及全族守卫分支 | PASS |
| 10.8 | 断言输出还是摆设 | 8 正例响应帧/关联已逐帧钉回（字段 66→191） | PASS |
| 10.9 | 规范行/性能全覆盖 | 见 9.x | PASS |
| 10.10 | 全绿但测错=没测 | M1/M2 修轮后已钉实（#5/#8/#10 复评逐值对） | PASS |
| 10.11 | 闭环结论 | P4 3 轮/P5 2 轮末轮干净 + 本终审 | PASS |
| 11.1 | 白话先行 | p4-report + 本报告判词 | PASS |
| 11.2 | 协议名带上下文 | 在案 | PASS |
| 11.3 | 禁黑话 | 用语合规 | PASS |
| 11.4 | 拍板给两选项 | 无待拍板项（G-AMQP-2 已裁定） | PASS |
| 11.5 | 自查黑话 | 已自查 | PASS |
| 12.1 | 五策略全开（每流可变字段） | §13.12：src 全开；dst/dst_port fixed+理由 | PASS |
| 12.2 | 动态覆盖四元组 | 住 ip/tcp 层（框架） | PASS |
| 12.3 | 业务字段清单 | §13.12 逐字段开/不开+理由 | PASS |
| 12.4 | flows=N 确定性/seed/回绕 | 框架语义（层链四元组） | PASS |
| 12.5 | 不写动态按 fixed | 用例显式 12345/5672 | PASS |
| 12.6 | 任务级不丢动态 | 未动 | PASS |
| 12.7 | 任务级只截断 | 未动 | PASS |
| 12.8 | 任务级动态 | 未动 | PASS |
| 12.9 | 静态复制拒/告警 | flows=1 单流；框架守卫 | PASS |
| 12.10 | src_port 保底≠动态 | 诚实声明 | PASS |
| 12.11 | 动态住层链 | 地址 ip/端口 tcp | PASS |
| 12.12 | 不许另起顶层 | 顶层键=layers 唯一 | PASS |
| 12.13 | 对齐 tuples 语义 | 框架基线 | PASS |
| 12.14 | 清单+序号算法 | 序号算法已回填 §13.12（框架面 + 业务全关声明，修轮 m4） | PASS |
| 12.15 | 动态测试五类 | 无业务动态；四元组框架面 | PASS |
| 12.16 | 抽查定位打回 | 序号算法可定位（layer_dyn.go:770 / tuple_generator.go:290/:300） | PASS |
| 13.1 | defs.json | 未动 | PASS |
| 13.2 | strategy.json | 未动 | PASS |
| 13.3 | task.json | 未动 | PASS |
| 13.4 | batch.json | 未动 | PASS |
| 13.5 | layers.json 形状 | 层链形状遵守 | PASS |
| 13.6 | generated 注册表生成 | amqp 行在（machine 核） | PASS |
| 13.7 | 校验入口唯一 | ValidateStrategy/TaskCreate（#21/#22 走 shape 门） | PASS |
| 13.8 | 形状先行语义随后 | 锚词与老接口一致 | PASS |
| 13.9 | REST 只调入口 | 未动 | PASS |
| 13.10 | MCP 同入口 | suite 经 MCP 同入口 | PASS |
| 13.11 | MCP 描述表 | flowb_query_layers 实时 | PASS |
| 13.12 | flowb_query_layers 实时视图 | amqp 6 字段可视（registry 同源） | PASS |
| 13.13 | struct 标签字面量 | types.go:286-330 字面量 | PASS |
| 13.14 | 前端类型 | 未动（webgen 派生） | PASS |
| 13.15 | 前端 cps/ratio | 未动 | PASS |
| 13.16 | 文档索引 | 未动 | PASS |
| 13.17 | 改语义先改 schema | registry 先行（f59509c）；P4 无注册表变更 | PASS |
| 13.18 | 注册表变更重跑生成 | 无变更；generated 含 amqp | PASS |
| 13.19 | 过期测试变红 | TestLayersGeneratedMatchesRegistry PASS（独立复跑） | PASS |
| 13.20 | 缺席走缺省/null 拒 | MCP 省略键；显式 null 拒在入口（框架面） | PASS |
| 13.21 | 非法值语义拒 | planner 自然守卫 + 形状门 | PASS |
| 13.22 | schema 不算第四文档 | 未动 | PASS |
| 13.23 | schema 为准 | registry 为真相 | PASS |
| 13.24 | 评审先查 schema | 本报告 §六 | PASS |
| 13.25 | 手写形状打回 | 无手写 | PASS |
| 13.26 | null 兼容打回 | 未加 null 兼容 | PASS |
| 14.1 | 用例即 MCP 任务配置 | spec_json 直驱 suite | PASS |
| 14.2 | 不许两套写法 | 单权威 | PASS |
| 14.3 | 工具直消用例 | suite 读 cases 目录 | PASS |
| 14.4 | 旧用例随层链迁移 | 20 例层链整形（§5 去向表） | PASS |
| 14.5 | 历史口径不带入 | packet_count/包号先跑后钉 | PASS |
| 14.6 | 先跑 pcap 再钉 | casegen 全链回放 + P5 落盘校准 | PASS |
| 14.7 | MCP 建任务 | suite 走 MCP 18106 | PASS |
| 14.8 | 引擎真实生成 | 落盘 23 pcap | PASS |
| 14.9 | tshark 逐字段校对 | 本报告独立 tshark 抽查 | PASS |
| 14.10 | 只数包不算测 | packet_count+fields+frames 三通道 | PASS |
| 14.11 | 负例经 MCP 被拒锚词 | 10 负例锚词 10/10（coverage_gate） | PASS |
| 14.12 | 假成功同级 bug | 负例终态 error；无 completed/0 包；udp_carrier Build 期拒 | PASS |
| 14.13 | 聚合断言区分侧别 | 无 distinct（G-AMQP-2） | PASS |
| 14.14 | 派生端口排除 | 无派生 | PASS |
| 14.15 | 字段方向想清 | 方向经 tshark 实证（#4/#14 双向） | PASS |
| 14.16 | 全绿+落盘可复查 | 落盘在；陈旧 646B 两文件（n5） | PASS |
| 14.17 | 抽查三点 | 复评 §三/§五；#5/#8/#10 钉子逐值对 | PASS |
| 14.18 | 二进制同代 | 门2-3 绿 | PASS |
| 14.19 | 全量非增量 | 24/24 全量复跑 | PASS |
| 14.20 | 包号端口从 pcap 拿 | 先跑后钉 | PASS |
| 15.1 | 门1 14 行表 | design §13 | PASS |
| 15.2 | 证据三选一 | G-AMQP-1/2/3/4 | PASS |
| 15.3 | 三行强制展开 | §13.1/§13.3/§13.12 | PASS |
| 15.4 | 门2① 零残留 | pipe_gate 绿 | PASS |
| 15.5 | 门2② 全量绿锚词 | 24/24 + 锚词 10/10 | PASS |
| 15.6 | 门2③ 二进制同代 | 绿 | PASS |
| 15.7 | 门2④ 反查绿进 P6 | 68/68 绿（独立复跑 exit 0） | PASS |
| 15.8 | D-条目挂门1表 | §13 | PASS |
| 15.9 | 抽查三条点到 | 本报告 §二 | PASS |
| 15.10 | 白话+三门证据 | 本报告 | PASS |
| 15.11 | 门红停 | 全绿（GAP 为终审新发现，修轮内闭环） | PASS |
