# IGMP（D-IGMP-1 #69）P6 248 条款逐条比对表

> 口径：docs/CORE_MEMORY.md（v15/481 行，2026-09-28 读）。落点=igmp#69 实测证据（canonical 现网复跑 suite 25/25、门2 静态项、反查 25/25、-race 绿；P6 隔离终审 `p6-review.md` 判词**通过**，2 M 观察项，无复验指令）。判定：PASS=满足，GAP(A′…)=覆盖未达但按 testcase §9.2 A′ / D-IGMP-1 立项承接（非缺口挂账，enip #56 同口径），NOTE=注记（含 M1/M2/G-IGMP）。
> 文档面：design v2.0.0（534 行）/ testcase v2.0.0（192 行）门1 获批版；P4 提交 `a367807`（11 文件，+2052/−939）；P6 时 HEAD `62ad5f6`（行号漂移见 p6-review §a，锚词逐字命中）。

| 条款 | 要求 | igmp 落点 | 判定 |
|---|---|---|---|
| 1.1 | 地址只写 ip 层 | 25 例地址全住 `layers[0].ip.src/dst`（fixture `192.0.2.10`；目的四档 `224.0.0.1`/组地址/`224.0.0.2`/`224.0.0.22`）；无顶层地址键 | PASS |
| 1.2 | 端口只写 tcp/udp 层 | raw-IP 族：无端口语义（`[ip,igmp]` 直挂，`chain_planner_translate.go:1119 case "igmp"`）；`[ip,tcp,igmp]`/`[ip,udp,igmp]` 判死（锚 `carrier`，链级红例） | PASS |
| 1.3 | 流数量只写 flow_control | spec_json 顶层键实测穷尽 = `['layers']`（25/25，p6-review §a-1）；多包例包数由层内 `events[]` 事件数定（3/3/4），不由 flows 复制 | PASS(NOTE M1) |
| 1.4 | 禁 layers 与顶层五键混用 | 门2-1 绿（无顶层旧键残留）；`CheckProtoFlat` presence 判死块（`strategy_convert.go:8868-8872`）+ 在库旧策略 `ValidationErrors` 块（`:546-552`） | PASS |
| 1.5 | 混用示例/用例/文档都算跑偏 | 无混用示例；design §14.1 样例三则均为纯 layers 形 | PASS |
| 1.6 | 门①层链能跑通 | suite 25/25（canonical 8081 复跑 9.68s；lane4 二跑 14.44s）；17 正例 pcap 齐落盘 | PASS |
| 1.7 | 门②旧格式彻底移除 | 存量 25 例全量改写（旧扁平→层链，testcase §5 去向表）；presence/在库两路执法在码（见 1.4） | PASS |
| 1.8 | 示例只给严格层链形 | 用例 spec_json 全严格层链形（25/25，`[ip,igmp]`；事件例 `events` 住 `layers[1].igmp` 内） | PASS |
| 1.9 | 暂不支持时标注目标形状 | 三支拒绝有目标形状声明：IPv6/MLD（§8 显式非变体，拒绝通道）/TCP-UDP 载体（`carrier` 判死）/动态组地址池（→G-IGMP-3） | PASS |
| 1.10 | 汇报分开说跑通/清旧字段 | p4-report §2（suite）/§4（六缺口闭环）分节 | PASS |
| 1.11 | 顶层白名单（layers/flow_control 家族/output） | 非负例顶层键=0（仅 `layers`，M1 注记见 1.3）；唯一并存 = presence 判死负例形状（14-P2 口径，链级红例①） | PASS |
| 1.12 | 无可住层时立项补层，不许豁免 | IPv6 无可住层 → 按拒绝通道表达（`address_family=ipv6` 留层内走拒，无"登记保留"豁免）；单载体无 OptionalOn 面 | PASS |
| 1.13 | 门2①按白名单执行 | 同 1.11（门2-1 三绿；顶层 `igmp:{}` 空子映射并存形判死） | PASS |
| 2.1 | 策略=单模板自带 flow_control | 单 IGMP 报文模板语义；框架语义未动。用例不落 `flow_control` 键（事件数定包数），偏离已登记 `casegen_test.go:23-30` 文件头 | PASS(NOTE M1) |
| 2.2 | 任务=多策略合跑+总量封顶 | 框架语义未动（suite 走策略路径） | PASS |
| 2.3 | 策略先限速任务再封顶 | 未动 | PASS |
| 2.4 | 任务 ID={taskID}-{strategyID} | 未动 | PASS |
| 2.5 | flows=N 复制 N 条 | 未动；igmp 语料未开 flows>1（探针实证 flows=3 产 9 包，故事件例不写该键，见 M1） | PASS |
| 2.6 | spec 不管数量 | 未动 | PASS |
| 2.7 | 按流变化走动态字段 | `src` 全策略开（framework ip 层在案）；`dst/group` 等不开 + 理由（`dstFor` 仲裁；动态组地址池 → G-IGMP-3）；多组扇出走 `events[]` 显式 | NOTE(G3) |
| 2.8 | 未写动态 src_port 保底 12345+i | raw-IP 无端口语义，不适用（诚实声明，无虚构保底） | PASS |
| 2.9 | 其余按流变化必须写动态 | design §14.12 业务清单（10 行逐字段开/不开+理由）；业务动态零开=立项维持（G-IGMP-3） | PASS/A′ |
| 2.10 | 讲数量分清策略复制/任务封顶 | p123 门1 §2 行 | PASS |
| 2.11 | 讲变化动态按 §12 | 本表 12.x | PASS |
| 3.1 | 多会话 sessions[]/flows[] 显式 | igmp 无顶层 `sessions[]`（§3.14 诚实口径：建连面无）；多会话由 `events[].session` 显式声明（#15 a/b/c 三会话四事件） | PASS |
| 3.2 | 每会话独立 ID/四元组/生命周期 | 会话 a/b/c 独立 group/profile/生命周期（§14.3 会话表 s1/s2/s3）；四元组诚实无端口无握手 | PASS |
| 3.3 | 会话内事务有序序列 | t1 query 应答→t2 report 加组→t3 leave 离组（§14.3 事务表）；#14 三包重传相等性 | PASS |
| 3.4 | 事务前置条件 | design §14.3 t1–t4 前置列（member/querier 触发/已发 t1 等） | PASS |
| 3.5 | 触发动作 | 发 Query（general/group-specific/source-specific）/Report/Leave（v2）或 mode-change Record（v3） | PASS |
| 3.6 | 成功分支 | tshark Type/目的双通道命中（§(b) 逐包 hex 核对：`12 00`/`16 00`/`22 00`/`17 00`） | PASS |
| 3.7 | 失败分支 | 8 负例 task error 锚（`IPv6/multicast/TTL/Protocol 2/checksum/record/profile/source count`） | PASS |
| 3.8 | 控制关联数据流显式字段 | 无控制流驱动数据流（无 `driven_by` 派生流）；同事件序 query→report 语义关联由 `session`+`group` 决定——与 CWMP 范本差异诚实声明 | PASS |
| 3.9 | 关联写清会话/事务/决定字段 | 归属会话 `events[].session`、归属报文组（同 group）、由 `group` 字段决定（§14.3 关联段） | PASS |
| 3.10 | 被关联流独立 ID/四元组/握手 | 无副流（单载体），不适用（G-IGMP-2 同源：交织序不假设） | PASS |
| 3.11 | 各流顺序/并发/交错写清 | 会话内 t1→t2→(t3) 严格报文序；会话间不假设全局包序（`directional=false` 17/17） | PASS |
| 3.12 | 可交错写清调度+时间戳 | 交织序不假设 → G-IGMP-2；调度="按事件序逐包 Emit"（`layer_gen.go:90-103`） | PASS |
| 3.13 | 不许连续重复冒充编排 | 生命周期编排（Query→Report→Leave；mode-change/allow/block 过滤变迁）非模板重复 | PASS |
| 3.14 | 无长连接豁免≠多流豁免 | 不主张豁免：多会话并发 #15（4 包三会话）+ 单包多载荷 #11/#12（双记录）+ 多包序列 #14 各有结论；Aux 非零全组合 → B′（G-IGMP-2）非逃逸 | PASS |
| 3.15 | 多轮/非正常结束/长保活各一例或立项 | ①多轮 #14 + 多会话 #15 ②非正常结束 #18–#25（8 负例）③长保活=不适用（无连接）+ querier 周期刷新明确不支持（design §13.1 #6，引擎调度器面） | PASS |
| 3.16 | CWMP 范本照补 | 差异声明：无 driven_by（单载体无副流；`events[]` 承载多报文有序序列） | PASS |
| 3.17 | 多流设计五件套 | design §14.3（会话表/事务序列/关联关系/插入位置/时间线全件） | PASS |
| 4.1 | 连接模型 | design §13.1 #1（组播成员管理；querier→host 单向 Query，host→router 单向 Report/Leave；无连接无握手；一报文=一 frame） | PASS |
| 4.2 | 命令/消息表 | design §13.1 #2（v1 `0x11/0x12`；v2 `0x11/0x16/0x17`；v3 `0x11`+MRC/QRV/QQIC+N×source / `0x22`+M×Group Record；Type-profile 互斥） | PASS |
| 4.3 | 状态机 | design §13.1 #3（主机侧唯一有序面 General Query→Report→Leave；v3 Record 状态表达过滤变迁；多会话隔离） | PASS |
| 4.4 | 字段表 | design §13.1 #4（v1/v2 8B；v3 Query `12+4N`；v3 Report `8+Σ(8+4N_i)`；6 种 Record Type 全量；MRC/QQIC 直接/浮点双编码；checksum 全报文 one's-complement） | PASS |
| 4.5 | 错误处理表 | design §13.1 #5 + §10 八类拒收；用例面 8 负例锚逐字对 `planner.go` 落码行 | PASS |
| 4.6 | 超时与活性 | design §13.1 #6（周期定时器明确不支持；`retransmit=true` 只重发完全相同语义，#14） | PASS |
| 4.7 | NAT/代理/被动 | 明确不适用（链路本地组播 TTL=1 不跨路由；无 IGMP 层可测语义，无用例——显式声明非逃逸） | PASS |
| 4.8 | 版本/方言 | design §13.1 #8（三 profile 并存；MLD 明确非 IGMP 变体；无端口/无 TCP-UDP 封装变体） | PASS |
| 4.9 | 有 RFC 查 RFC 注章节 | RFC 1112/2236/3376（编号级引用；精确章节待 G-IGMP-1，§5.5 不写死） | PASS(NOTE G1) |
| 4.10 | 无 RFC 以官方规范为准 | 有 RFC，本条不适用 | PASS |
| 4.11 | 不许博客二手代替原文 | p123 §②13.4 三路对照（RFC 原文 + 现网形态 + wireshark/已落码实现思路） | PASS |
| 4.12 | 规范原文 | design §1/§4–§7 逐节（Type/头长/目的/状态四面） | PASS |
| 4.13 | 商业软件实际行为 | 现网通用形态（querier 周期 Query/host 加组离组/SSM 源过滤）；未到确认级 → G-IGMP-1（抓 querier 回环包） | NOTE(G1) |
| 4.14 | 可靠开源实现思路 | wireshark `packet-igmp.c`（本机 3.6.14 实测 `igmp.*` 44 字段=断言通道权威）+ 已落码 builder wire 真相；只借鉴语义不搬码 | PASS |
| 4.15 | 三路不一致取舍写清 | design §13.4（三路六点一致声明 + querier 差异面 → G-IGMP-1 不写死）+ §13.5 | PASS |
| 4.16 | 商业行为逐条映射用例号 | design §14.2 映射表 7 行（已映射；未落抓包证据的一律挂 G-IGMP-1） | PASS |
| 4.17 | 关键决策候选方案对比表 | design §13.5（A 结构化声明式回放√ / B 生 hex / C 通用组播编译器，优劣+性能/复杂度/兼容性） | PASS |
| 4.18 | 不许单方案自说 | §13.5 三方案实存 | PASS |
| 4.19 | 每表格行/字段/错误码三选一 | design §13 矩阵 8 行 + 三子表（§13.2 报文×状态 28 格逐格结论 12+7+8+1=28 / §13.3 变体表 14 行 / §14.2 映射表）；无空格 | PASS |
| 4.20 | 每条目对应至少一用例 | 9.52 对账：50 点 = 已覆 41 + 不适用 8 + B′ 1（G-IGMP-2 S 位面），由 25 语义 ID 承载；A′ 补例 T-26/T-27 建议在案 | PASS/A′ |
| 4.21 | 动手前缺口矩阵 | p123 门1 表 + design §13 矩阵（P1–P3 先于 P4） | PASS |
| 4.22 | 三张子表齐 | §13.2/§13.3/§14.2（三表齐，缺表即缺口——齐） | PASS |
| 4.23 | 设计评审先看矩阵 | 门1 获批（p123 §①） | PASS |
| 4.24 | 规范实现冲突先改实现 | P5 按实重锚（`max_response_code=255→igmp.max_resp=31744` 为 tshark 实测口径非手算；frames 只钉可复算前缀） | PASS |
| 5.1 | 设计写明依赖 | `DependsOn ["ip"]` 单载体（`registry.go:1114` HEAD；P1 引 `:863`，漂移 +251 系 merge 插入）+ `FieldContract ip.protocol=2` + 无端口依赖声明（§15） | PASS |
| 5.2 | 写明出错处理 | planner 八锚 + `validate_layers` 三支同步预检（tcp/udp 夹层拒、缺 ip 拒，锚 `carrier`）+ 全部 task error 终态零假成功（§1 不变式 9） | PASS |
| 5.3 | 无依赖/错误分支不许实现 | 有（两面俱全） | PASS |
| 5.4 | 无依据不许定字段流程缺省 | TTL=1/Protocol=2/目的四档/Type 四值均有 RFC + `dstFor`/`builder` 出处；TTL 固写 1（`layer_gen.go:76`） | PASS |
| 5.5 | 不确定标待确认+确认方式 | G-IGMP-1（抓包+查 RFC 原文）/G-IGMP-2（查 RFC+抓包）/G-IGMP-3（查序号算法现状）/G-IGMP-4（查 helpers 现状+实测）在案 | PASS |
| 5.6 | 回答结论指章节/代码行 | design §13–§15 + 代码行（builder/planner/layer_gen/routing/chain_planner_util）+ 用例号；P6 三条抽查均点行/例号 | PASS |
| 5.7 | 指不出直说不知道 | 吞吐数字诚实"待 P4 基准"（testcase §9.7）；序号算法位置诚实"待 P4 定"不编行号（§14.12） | PASS |
| 5.8 | 回复前自查出处 | p4-report §7 自审 3+2 轮（registry 逐键机核 diff=∅ / 接线块对先例逐字比对 / 死键修正 / T-23 收紧） | PASS |
| 5.9 | 抽查三条定位不到打回 | 门3 三条 ≡ p6-review §(a)（§14.1 强制展开 / §14.12 动态清单 / §13 schema 派生，均点行+例号） | PASS |
| 6.1 | 性能目标/预算/边界 | design §15（O(n) 流式；逐包渲染直发无全量聚合；单报文最大 `8+Σ(8+4N)` fixture 级字节；无锁无 sleep） | PASS |
| 6.2 | 六指标列全 | 吞吐数字诚实待基准（G-IGMP 未细化；不写承诺数字） | PASS |
| 6.3 | pcap/NIC 分别验收 | pcap 路：17 正例 pcap + suite 全绿（canonical + lane4）；**NIC 路本轮未跑**（过滤器 `ip proto 2` + 网口 `enp135s0f0np0`  testing-interface 记忆） | NOTE |
| 6.4 | 性能依据结合实现路径 | 事件序 for 直发（`layer_gen.go:90-103`）、无缓冲增长结构、确定性内存 | PASS |
| 6.5 | 无依据数字标待确认 | 已标（§6.5 不写承诺） | PASS |
| 6.6 | 六类性能场景 | 清单在案（基线/目标规模/压力上限/长运行时/并发交错/背压，testcase §9.7）；P5 跑测覆盖但无基准数字 | NOTE |
| 6.7 | 断言实际指标不只无报错 | packet_count 17 例 + 138 等值钉 + 24 nonzero + 1 same_as_packet；零 existence-only 断言（p4 §7 R3 机核） | PASS |
| 6.8 | 超预算仍不合格 | —（失败边界诚实待确认，见 6.2） | PASS |
| 7.1–7.3 | 三份文档定位 | design+testcase+D-IGMP-1（design §15 草稿，门1 获批=定稿）；未碰 CODE_DESIGN/TEST_CASES | PASS |
| 7.4 | 历史文档保留参考 | v1.0.0 旧契约逐条核对保留（design §18.2，无静默删除） | PASS |
| 7.5 | cases 是产物回指编号 | 25 例回指 design §9（逐 ID/逐序/逐类型/逐 packet_count 一致，testcase §9.6 核对结论） | PASS |
| 7.6–7.7 | 三者关系/冲突序 | — | PASS |
| 7.8–7.9 | 先核心→设计→用例 | 门1 先行（P1–P3 先于 P4/P5 整形与跑测） | PASS |
| 8.1 | 八要素（文件/接口/结构/流程/错误/性能/冲突/回滚） | design §15（已落码 5 + P4 新建 1 + 接线/守卫 3，行号实测；回滚=P4 差量全量 revert，wire 面不动） | PASS |
| 8.2–8.8 | 同上逐项 | §15（translate/validate/backfill 落点见 p6-review §a；冲突点 §8.7 顶层 events 过渡分支 + `parseSubconfigJSON` 静默面） | PASS |
| 8.9 | 未定稿不开工 | 门1 获批=开工（P4 提交 `a367807` 契约基线 `8c88fef` 之后） | PASS |
| 8.10 | 需求变先改设计 | 死键收敛（#23/#25）+ T-23 收紧已落 p4/testcase §1 注记；M1 设计正文注记后补（pending） | PASS(NOTE M1) |
| 8.11 | 不许代码先行文档后补 | P1–P3 契约先行（门1 获批=定稿） | PASS |
| 8.12–8.13 | 开工贴条目/无条目打回 | — | PASS |
| 9.1 | 用例登记（回指编号） | testcase §2/§9；ID↔design §9↔JSON 机器对账（coverage"25 例 ID 同序"PASS） | PASS |
| 9.2–9.4 | 三源（规范/设计/现网） | RFC（编号级，精确章节 → G-IGMP-1）+ D-IGMP-1 + tshark `igmp.*` 44 字段实证 + builder wire 真相；第三源现网=未确认级（G-IGMP-1） | PASS |
| 9.5 | 每行每字段每错误码有用例 | 9.52 对账 41/50 已覆（8 不适用显式声明 + 1 B′ 立项）；A′ T-26/T-27 补例建议在案 | PASS/A′ |
| 9.6 | 一例一行为 | 25 唯一 ID（机核无重复；coverage ID 同序 PASS） | PASS |
| 9.7 | 修 bug 先复现变红 | T-23 弱检查收紧实红（键存在→数值型 `record_type` 必验；字符串静默通过解码，`casegen_test.go:593`）；#23/#25 死键修正后全量二跑 25/25 | PASS |
| 9.8 | 数据场景六变体（正常/边界/空值/超长/非法/大小端） | 边界例 #17（QRV=7/MRC=255→31744/QQIC=255/三源）+ 8 负例非法面；空值/超长/大小端=二进制定长字段不适用（诚实口径） | PASS |
| 9.9 | 业务场景序列/乱序/中断/交错 | 生命周期序列 #13/#14/#15 + 重传；乱序/中断/交错不假设 = G-IGMP-2（B′ 明确不解决+迁入计划） | PASS |
| 9.10 | 现网场景；复杂度 9.50 下限 | 最复杂例 `igmp_multi_group_sessions`：多会话(a/b/c)×多版本事务(v1/v2/v3)×离组收尾(b-leave)=**3 类**达下限（p6-review §b 逐包点数 4 包） | PASS |
| 9.11 | 多动作组合流≥2 条×≥3 动作 | #15（v1-report/v2-report/v3-report/leave 四种互不兼容编码）+ #14（三包状态序列）≥2 条 ✓（profile 互斥见 design §1，不同 profile 报文=不同动作） | PASS |
| 9.12 | 清单先行 | P1 矩阵先行（p123 门1 §4；§13 矩阵 + 三子表） | PASS |
| 9.13 | 清单无遗漏是目标 | G-IGMP-1–4 + A′ T-26/T-27 登记在案；28 格逐格有结论无空格 | PASS |
| 9.14 | 存量逐条审计去向 | testcase §5 去向表 25/25（17 正+8 负全**合入**，作废 0，等价覆盖 0；期望值不照抄先跑后钉） | PASS |
| 9.15–9.19 | A/B/C 三分类 | B′（AuxData/S 位/交织序/数值形扩展/未知键守卫 → G-IGMP-2/G-IGMP-4）逐项 notes；动词出现≠覆盖（序列矩阵逐条对照） | PASS |
| 9.20 | 取值表每值一例 | Record Type 1–6 全量（frames `03/04/05/06` 实测）✓；Type 五值全覆 ✓；**QRV 0–7 仅 2 值（2/7）、MRC/QQIC 仅直接值+255 边界**：余值零例 | GAP(A′-取值面) |
| 9.21 | 分支级审计 | 负例按分支铺（address_family/dst/ttl/protocol/checksum/record/profile/source-count 八分支） | PASS |
| 9.22 | 扫遍全部承载位置 | 层内 igmp 条目 + `events[]`（唯一承载）全覆盖；顶层 events 已层内化 | PASS |
| 9.23 | 正交矩阵逐格标记 | design §13.2 矩阵逐格 + testcase §9.2 六面表（数据/业务/现网/多流/地址族/断言通道） | PASS |
| 9.24 | 地址族对称（IPv4/IPv6 逐格） | **IPv6 零正例 = 显式设计决策**（design §8：MLD 非 IGMP 变体，另协议另议），不是缺口、不抽样代表 | PASS |
| 9.25 | 地址族扩展随矩阵扩 | IPv6 面按设计决策不扩（非立项未做）；动态组地址池面 → G-IGMP-3 | NOTE |
| 9.26 | 补齐顺序 | 最小实现→高频→全量；A′ T-26/T-27 并入与否主线程定（不影响 25 ID 权威口径） | NOTE |
| 9.27 | harness 做不到逐项注明 | 包序靠逐包 fields+frames 钉（#13/#14/#15 packet 1..N）；方向 `directional=false` 17/17 显式 | PASS |
| 9.28 | 不许字段出现冒充顺序 | 事件序断言（多包例逐包 Type/group/source；#14 `same_as_packet` 重传相等性） | PASS |
| 9.29 | 补齐后全量全绿 | 全量 25/25（canonical 复跑 + lane4 二跑，非增量） | PASS |
| 9.30 | 只写不跑/只跑增量=未完成 | 全量跑（CASE_PROTO=igmp 全文件） | PASS |
| 9.31 | 断言以真实 pcap 校准 | 先跑后钉（`num_src`/`max_resp=31744`/frames 八档偏移均来自落盘 pcap 实测；P5 复核） | PASS |
| 9.32–9.35 | 动态整格（五策略×字段） | `src` 五策略 framework 面在案（ip 层）；**语料 25 例全静态，动态格零建例**（9.34 三问无从验证；9.35 锚点未立） | GAP(A′-动态面) |
| 9.36 | 不支持格标 B/C+注记 | B′ 五面（AuxData 非零/S 位跨会话/交织序/数值形扩展/未知键守卫）testcase §9.2 + design §17 注记 ✓ | PASS |
| 9.37 | 派生编号撞车 | 无派生子流/端口面（raw-IP 单报文），不适用 | PASS |
| 9.38 | 聚合断言排除固定/派生口 | 无 distinct 聚合用例 | PASS |
| 9.39 | 多流×静态标量互斥 | 事件例 `ip.dst` 保持缺席（静态 dst 会与 `dstFor` 仲裁打架，§14.1 显式）；单报文例静态 dst 钉死（flows=1） | PASS |
| 9.40 | 共享流序号动态字段 | 无动态面（零动态例） | NOTE |
| 9.41–9.45 | 测试评审五件事 | 本表 + p6-review（清单先行/回指/输出断言/失败真红/全量全绿五项可验） | PASS |
| 9.46 | 数据场景全表扫 | 字段边界部分在案（MRC/QRV/QQIC/N/六态记录）；取值未全（见 9.20）；空值/超长/字符集=定长二进制不适用 | GAP(A′) |
| 9.47 | 取值集合逐值枚举 | 同 9.20（扩展与保留值域未入清单） | GAP(A′) |
| 9.48 | 业务场景规范反推 | design §13 三子表 + testcase §9.3 出处声明（规范反推**非**用例/引擎反推；9.52 专项防线） | PASS |
| 9.49 | 多连接/多会话/多事务各一例+真实编排 | 多事务 ✓（#14 状态序列 + #11 mode-change）+ 多会话 ✓（#15 三会话四包）；多连接=不适用（无连接）；编排=会话内多事务×多会话扇出 | PASS |
| 9.50 | 复合大场景≥3 类交织 | `igmp_multi_group_sessions` = 多会话×多事务（report+leave）×多版本（v1/v2/v3）**3 类**（NAT 不适用：TTL=1 链路本地） | PASS |
| 9.51 | 组合矩阵满格 | design §13.2 矩阵（已入版）；用例面组合维度有限=A′ 维持（T-26/T-27 对称缺格） | PASS/A′ |
| 9.52 | 审计声明出处+对账两行 | testcase §9.3：出处=规范反推；对账 50 点（41 已覆+8 不适用+1 B′）vs 用例 25 语义 ID；粒度声明防误读（46/41/8/1 vs 50） | PASS |
| 9.53 | 门3 至少一条抽最复杂用例+点数 | p6-review §(b)：`multi_group_sessions` 4 包逐包点数（`ip.dst/igmp.type` 序列 + ttl/proto + hex）+ v3 0x22 双源 + SSM 0x11 + leave 0x17 | PASS |
| 10.1 | 文档对规范逐条核对 | design §18.1（RFC 1112/2236/3376 逐条→§1/§4–§7 落点；精确章节挂 G-IGMP-1） | PASS |
| 10.2 | 改需求先对旧需求 | design §18.2（v1.0.0 §1–§12 逐条：保留/扩/更正，无静默删除） | PASS |
| 10.3 | 代码逐行走读 | P4 3 轮 + P5 校准 2 轮（p4-report §7；末轮干净） | PASS |
| 10.4 | 构建+vet+测试含 race | 本审：build/vet 清；`-race ./internal/core/... ./internal/protocol/igmp/...` 绿；链例 5/5 | PASS |
| 10.5 | 修完再审 | 每轮 fix 后再审（死键修轮→二跑 25/25；T-23 收紧→复核；末轮干净） | PASS |
| 10.6–10.10 | 测试评审 | 本表（三源对账+7 锚词核+最复杂例点数；8 锚词逐字对落码文案） | PASS |
| 10.11 | 改审测修再审闭环+结论 | p4-report §7 + p6 判词（通过；M1/M2 观察项无复验指令） | PASS |
| 11.1–11.5 | 白话 | p6-review §11 白话一句（"报名/退订"组播组单报文协议）+ 判词先行 | PASS |
| 12.1 | 五策略全开 | `src` 五策略 framework 在案（ip 层，§14.12"全开"） | PASS |
| 12.2 | 动态覆盖四元组 | `src` 覆盖；`dst` 固定（仲裁面）/端口 N/A（raw-IP）；§14.12 逐字段理由 | PASS |
| 12.3 | 业务字段清单逐协议 | design §14.12（10 行：profile/kind/group/MRT-MRC/s/qrv/qqic/sources/records/events 开与否+理由）；业务零开 → G-IGMP-3 | PASS |
| 12.4 | flows=N 确定性+seed+回绕 | framework 语义（igmp 无动态例可验） | NOTE |
| 12.5 | 不写动态按 fixed | 25 例全静态（fixture 钉死字节；多组靠显式 events 非动态冒充） | PASS |
| 12.6–12.8 | 任务级动态不丢/只截断/跨策略 | framework 未动 | PASS |
| 12.9 | 静态复制拒绝/告警 | framework 守卫在案（igmp 无多流例，未取用） | NOTE |
| 12.10 | src_port 保底≠动态 | N/A（无端口语义）；诚实声明（design §14.12，不虚构保底） | PASS |
| 12.11–12.13 | 动态住层链/不另起顶层/对齐 tuples | 动态地址住 ip 层；无顶层动态键（顶层穷尽 `layers`） | PASS |
| 12.14–12.16 | 清单+序号算法可定位 | 清单 §14.12 在案；序号算法位置诚实"待 P4 定"不编行号（§5.7 口径；动态零用例故未钉死文件+行号） | PASS(NOTE) |
| 13.1–13.6 | schema 文件 | registry igmp 行 15 键（`registry.go:1114-1131`，与 `core.IGMPConfig` json 标签对齐，coverage PASS）+ `FieldContract ip.protocol=2`；generated `layers.generated.json:1585 "igmp"` 块 15 键对齐 PASS | PASS |
| 13.7–13.10 | 校验入口唯一 | ValidateStrategy/TaskCreate 同入口（suite 走 MCP；MCP 不再验一遍） | PASS |
| 13.11–13.16 | 派生只读下游 | flowb_query_layers 实时视图（门3抽查 §(a)-3 落点） | PASS |
| 13.17 | 改语义先改 schema | registry 先行（P4 补 15 键 → schemagen 重生成同步） | PASS |
| 13.18 | 注册表变更重跑生成 | generated 已重跑入版（P4 提交内，空 `{}`→15 键） | PASS |
| 13.19 | 过期测试变红 | `TestLayersGeneratedMatchesRegistry` 验证无过期（P4 门内） | PASS |
| 13.20–13.21 | 缺席走缺省/null 拒 | 框架面；子映射未知键静默面 → G-IGMP-4（`parseSubconfigJSON` 普通 `json.Unmarshal`，`strategy_convert_helpers.go:21-30`） | NOTE(G4) |
| 13.22–13.23 | schema 是机器源不算第四文档 | — | PASS |
| 13.24–13.26 | 评审先查 schema/手写/null 兼容 | 无手写形状；未知键守卫缺席按 13.26 口径应显式拒绝 → G-IGMP-4（跨协议共享面，车道按契约停手正确） | NOTE(G4) |
| 14.1 | 用例 spec 即 MCP 任务配置 | spec_json=layers 直驱（25/25 顶层穷尽 `layers`）；`strategy_fc` 封包面见 M1（`flow_control` 死配置不落键，登记 `casegen_test.go:23-30`） | PASS(NOTE M1) |
| 14.2 | 不许两套写法 | 单权威（层 config 经 `ParseIGMPConfigFromMap` 单一真相解码，`chain_planner_translate.go:1119`） | PASS |
| 14.3 | 执行工具直接消费用例 | suite 经 MCP 直消（canonical + lane4 两路实跑） | PASS |
| 14.4 | 旧用例随层链迁移改写 | 25 例全改写（testcase §5 去向表逐例改写要点；§14.1 逐键去向表执行） | PASS |
| 14.5 | 历史口径不带入 | 包号/字段面重建（`max_resp=31744` 实测重锚；frames 只钉可复算前缀；checksum 不固化 hex） | PASS |
| 14.6 | 先跑拿 pcap 再钉 | P5 实跑重锚 + P6 §(b) tshark 直读复核（非用例断言复述） | PASS |
| 14.7–14.9 | MCP 建任务→生成→tshark 校对 | lane4 MCP 18097/18098 + canonical 8081 + tshark 字段/frames 双通道 | PASS |
| 14.10 | 离线/无失败/只数包不算测 | 字段+frames 双钉（138 等值 + 24 nonzero + 1 same_as_packet；零空转断言） | PASS |
| 14.11 | 负例经 MCP 被拒+锚词 | 8 负例全 `expect_error`+`error_contains`（双键 8/8）；7 锚词逐字对 `planner.go` 落码文案 + profile 锚（`:113/117`） | PASS |
| 14.12 | 假成功同级 bug | 零假成功：8 类拒收全 task error 终态（§1 不变式 9；负例无 PCAP 输出契约） | PASS |
| 14.13–14.15 | 聚端口/派生口/方向想清 | 无 distinct 聚合；无派生口面；方向 `directional=false` 17/17 显式（会话隔离不断言包序） | PASS |
| 14.16 | 全绿+落盘可复查 | 25/25 + 17 正例 pcap 落盘（`/tmp/mcp-pcaps/igmp/` canonical；lane4 `/tmp/pipe/lanes/lane4/pcaps/igmp/` 25 文件；neg 占位有据） | PASS |
| 14.17 | 抽查 spec/字段/锚词 | p6-review §(a)(b)(e)（spec 顶层键实测/字段 14 去重/offsets 八档/锚词 8 个定位原文） | PASS |
| 14.18 | 二进制与 HEAD 同代 | lane 二进制陈旧（编自 `a367807`，HEAD 后 4 次 merge 触碰同目录）→ 门2-3 伪红；功能面由 canonical 现网 HEAD 同代 25/25 覆盖 | PASS(NOTE M2) |
| 14.19 | 全量全绿 | 25/25（非增量；canonical + lane4 二跑） | PASS |
| 14.20 | 包号/端口从 pcap 拿 | 先跑后钉（多包例 3/3/4 由事件数×落盘 pcap 校准；无手算端口，raw-IP 无端口） | PASS |
| 15.1 | 门1 十四行表+证据 | p123 门1 §1–§14 表（design §14；§1/§3/§12 强制展开 §14.1/§14.3/§14.12） | PASS |
| 15.2 | 证据三选一；写不出=立项 | G-IGMP-1…4 在案（design §17 四行：缺口/确认方式/去向） | PASS |
| 15.3 | §1/§3/§12 强制展开 | design §14.1（旧键去向表 + 3 样例）/§14.3（五件套）/§14.12（动态清单 10 行） | PASS |
| 15.4 | 门2①顶层零残留 | 旧键绿；presence 红线已接（链级红例①；`strategy_convert.go:8868-8872`） | PASS |
| 15.5 | 门2②全量绿+负例锚词 | 25/25 + 8 锚词（7 行锚 + profile 锚；T-23 数值型触发源 `casegen_test.go:593`） | PASS |
| 15.6 | 门2③二进制同代 | 红（伪红，M2：lane 二进制陈旧；重编重跑即绿，功能面已由 canonical 覆盖） | NOTE(M2) |
| 15.7 | 门2④反查绿后进 P6 | 25/25 绿（含反查负控 4 类扰动全捕获：顶层泄漏/包数错/锚词改宽/五项缺一） | PASS |
| 15.8 | D-条目挂门1表（回填证据号） | design §14 门1 表 + P6 三条抽查回填实际证据号（registry/translate/strategy_convert 行号 + 用例 ID） | PASS |
| 15.9 | 抽查三条点到行/例号 | p6-review §(a)（三条均点行/例号：`registry.go:1114`/`chain_planner_translate.go:1119`/`strategy_convert.go:546-552/:8868-8872` + `igmp_v2_leave`/`igmp_multi_group_sessions`） | PASS |
| 15.10 | 白话+三门证据 | p6-review §11 白话 + §(c)(d)（suite RESULT + 双门输出） | PASS |
| 15.11 | 任一门红停 | 门2 静态项绿；门2-3 红已定性为陈旧二进制伪影（M2），canonical 现网 25/25 为过门证据 | PASS(NOTE M2) |

## 注记（backlog，判定口径）

- **判定口径**：`GAP(A′…)` = 覆盖未达但按 testcase §9.2 A′ / D-IGMP-1 立项承接，**非缺口挂账**（enip #56 同口径）；`NOTE(M1/M2)` = P6 观察项（M1 设计 §14.1 `count→flow_control.flows` 文案 drift，用例不落该键，偏离登记 `casegen_test.go:23-30` 文件头，设计正文注记后补 pending；M2 lane 二进制陈旧致门2-3 伪红，重编重跑即绿）；`NOTE(G1–G4)` = D-IGMP-1 open 缺口（G-IGMP-1 现网证据+RFC 精确章节 / G-IGMP-2 B′ 行为面 / G-IGMP-3 动态组地址池+T-26/T-27 / G-IGMP-4 跨协议共享面未知键静默，车道按契约停手正确）。
- **GAP(A′-取值面)**（9.20/9.46/9.47）：QRV 0–7 仅 2 值（2/7）、MRC/QQIC 仅直接值+255 边界有例；余值零例。Record Type 1–6 与 Type 五值已全覆，不在此列。
- **GAP(A′-动态面)**（9.32–9.35）：`src` 五策略 framework 在案但语料零动态例，9.34 三问无从验证；归宿待主线程定（A′ 补例或维持静态语料口径）。其余字段不开=设计决策（§14.12），非缺口。
- **载体面**：raw-IP 族（无端口/无握手，`has_handshake` 0/25）；offsets 八档全命中（34/38/42/46/50/54/58/62，#11 占 58、#12 占 54+62）；checksum 零字面量（24×nonzero）；字段去重 14（`igmp.*` 11 + `ip.*` 3，tshark 44 字段口径 14/14 命中）；链级 5/5（4 红 + translate 正例）。
