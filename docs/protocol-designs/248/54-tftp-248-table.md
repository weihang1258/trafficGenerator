# TFTP（D-TFTP-1 #54）P6 248 条款逐条比对表

> 口径：docs/CORE_MEMORY.md（481 行，v15 拆分版；用户单独维护，本表只读引用）。落点=tftp#p6 隔离复评实测证据（证据行号/用例号/脚本尾巴见 `/tmp/pipe/54-tftp/p6-review.md`）+ P6 修轮（分支 `pipe/tftp-p6fix` 集成 `4ad86ad`：GAP(9)/GAP(10) 关闭）→ focused 复评关单（p6fix-scoped-review.md：(a) 三式复算闭合 (b) notes 纯文案 (c) 门2-1 执法有效 (d) §18 五动作有实物）。判定：PASS=满足，GAP(n)=缺口编号，NOTE=注记（不挡验收）。

| 条款 | 要求 | tftp 落点 | 判定 |
|---|---|---|---|
| 1.1 | 地址只写 ip 层 | 222 例 `layers[i].ip.src/dst`（vlan 2 例为 `[eth,vlan,ip,udp,tftp]` 第 3 层） | PASS |
| 1.2 | 端口只写 tcp/udp 层 | `layers[i].udp.src_port/dst_port`；dst 缺省 69 由 `chain_planner.go:976-980` 补 | PASS |
| 1.3 | 流数量只写 flow_control | 17 例 `strategy_fc`（case 级封包）；spec_json 无数量键 | PASS |
| 1.4 | 禁 layers 与顶层五键混用 | 正例顶层键=layers 唯一（189/189 机器实测零游离） | PASS |
| 1.5 | 混用示例/用例/文档都算跑偏 | 正例零混用；负例游离键=执法对象（§13-P2 点名形状） | PASS |
| 1.6 | 门①层链能跑通 | suite RESULT: 224 pass, 0 fail, 0 error (of 224)（lane3 实跑） | PASS |
| 1.7 | 门②旧格式彻底移除 | 门2① 绿：无顶层旧键；226→224 全量改写（D 删 7 + A′/负例增 5） | PASS |
| 1.8 | 示例只给严格层链形 | design §13.2 两样例=纯 layers（+flow_control） | PASS |
| 1.9 | 暂不支持时标注目标形状 | P1–P3 已标注"今日全红需补 G-TFTP-1"；P5 后已可达 | PASS |
| 1.10 | 汇报分开说跑通/清旧字段 | p4-report 分节 + p6-review §1/§4 | PASS |
| 1.11 | 顶层白名单 | 正例顶层零游离；E 族 2 负例顶层 tcp/http=游离键执法对象（N1） | PASS |
| 1.12 | 无可住层立项补层，不许豁免 | 23 键全部住 tftp 层（registry 23 Fields）；无豁免项 | PASS |
| 1.13 | 门2①按白名单执行 | `pipe_gate.sh tftp` 门2-1 绿（无顶层旧键；3 条并存进黄线登记，N3） | PASS |
| 2.1 | 策略=单模板自带 flow_control | 用例 spec_json 即策略 config，strategy_fc 即封包（14.1 同口径） | PASS |
| 2.2 | 任务=多策略合跑+总封顶 | 框架语义零改动（报告"未动跨协议框架语义"） | PASS |
| 2.3 | 策略先限速任务再封顶 | 未动；`tftp-e2e-bps` 1Mbps 例在案 | PASS |
| 2.4 | 任务 ID={taskID}-{strategyID} | 未动 | PASS |
| 2.5 | flows=N 复制 N 条 | B 族 11 例 flows 2/3/8/100（如 `tftp-multiflow-100flows-tuple-unique`） | PASS |
| 2.6 | spec 不管数量 | 同 1.3 | PASS |
| 2.7 | 按流变化走动态字段 | 四元组走层动态（`udp.src_port` inc 对象）；业务 23 键不开（§13.4 理由） | PASS |
| 2.8 | 未写动态 src_port 保底 12345+i | 框架既有（`strategy_convert.go:49` DefaultSrcPort=12345 + `chain_planner.go:1428` worker 按流注入注释）；tftp 多流例全部显式动态 | PASS |
| 2.9 | 其余字段按流变化必须写动态 | 契约 §13.4 逐键列开/不开+理由；实现 `layer_dyn.go` 无 tftp 行 | PASS |
| 2.10 | 讲数量分清策略/任务 | 报告 §P5 分族计数 | PASS |
| 2.11 | 讲变化动态按 §12 | 本表 12.x 行 | PASS |
| 3.1 | 多会话 sessions[]/flows[] 显式 | TFTP 无会话结构（UDP 无状态，一笔传输=一条流）→ 形式豁免=多流 flows=N 显式声明 | PASS |
| 3.2 | 每会话独立 ID/四元组/生命周期 | 每流独立四元组（100 流实测 100 个互异 src_port 49152..49251） | PASS |
| 3.3 | 会话内事务有序序列 | 单流内：请求轮→OACK 轮→ACK#0→数据轮→终止轮（design §13.3 事务表） | PASS |
| 3.4 | 事务前置条件 | §13.3 t0/t0b/t1..tN 前置列（前轮 ACK 已发；锁步） | PASS |
| 3.5 | 触发动作 | 同上（发 RRQ/WRQ、OACK、DATA#i） | PASS |
| 3.6 | 成功分支 | 同上（进 t(i+1)；末块后结束） | PASS |
| 3.7 | 失败分支 | ERROR 注入族 36 例 + 40→35 负例 task error（Validate 族锚词） | PASS |
| 3.8 | 控制关联数据流显式关联字段 | TFTP 单通道无副流（无 driven_by）→ design §13.3 显式声明非漏写（CWMP 范本差异声明） | PASS |
| 3.9 | 关联写清会话/事务/字段 | 不适用（无被关联流）；传输内关联=Block# 配对 DATA#i↔ACK#i | PASS |
| 3.10 | 被关联流独立 ID/四元组/握手 | 不适用（声明在案） | PASS |
| 3.11 | 各流顺序/并发/交错写清 | §13.3 时间线：单流严格顺序（锁步）；多流并发可交错 | PASS |
| 3.12 | 可交错写清调度+时间戳 | 跨流包序不假设（`tftp-multiflow-3flows-interleave` 只断言分组正确/流内连续） | PASS |
| 3.13 | 不许连续重复冒充编排 | TFTP 编排=流内锁步轮+协商轮+终止轮（同流有序发生） | PASS |
| 3.14 | 无长连接豁免≠多流豁免 | §15.4：多流 16 例（改写后并入）+ 单包多载荷=多选项对（`tftp-oack-multiopt-35b` 4 选项） | PASS |
| 3.15 | 多轮/非正常/长保活各一例或立项 | §15.1：①回执多轮≥4 例 ②非正常结束：WRQ 双盲区→A′ 补例 2 ③长保活=同 TID 长块序列（100 块），无保活语义已声明 | PASS |
| 3.16 | CWMP 范本照补 | 差异点显式声明（无 driven_by/无握手挥手/无 sessions[]） | PASS |
| 3.17 | 多流设计五件套 | design §13.3 会话表/事务序列/关联关系/插入位置/时间线五件齐 | PASS |
| 4.1 | 连接模型 | §12.1-1 双阶段 TID 语义（69 → ServerTID 换轨，RFC 1350 §4） | PASS |
| 4.2 | 命令/消息表 | §12.1-2 六 opcode 全覆盖（builder.go:17/47/58/68/85/142） | PASS |
| 4.3 | 状态机 | §12.1-3 RRQ/WRQ 双状态机 + OACK 子状态机 + ERROR 终止（plan.go:52/57-67/73-86/88-100/129-226/226） | PASS |
| 4.4 | 字段表 | §12.1-4 + §12.3 逐行（大端/ASCII/值域常量 types.go:31-47） | PASS |
| 4.5 | 错误处理表 | §12.1-5 九码 + 默认 ErrMsg 映射（types.go:51-61）；code=5 双语义写死 | PASS |
| 4.6 | 超时与活性 | §12.1-6：重传=丢包式结果序列（RFC 1350 §6 时序）；timeout 仅语义标记，真实计时重传明确不支持（C 类声明） | PASS |
| 4.7 | NAT/代理/被动模式 | §12.1-7：server_tid_change 扩展（非 RFC，互操作负向声明）；真实 NAT 无出处→G-TFTP-5 | PASS |
| 4.8 | 版本/方言差异 | §12.1-8：RFC 1350 Rev.2 单版本 + 选项四扩展 RFC；msft window 方言明确不支持；IPv6 由 A′ 补 | PASS |
| 4.9 | 有 RFC 查 RFC 注编号章节 | RFC 1350/2347/2348/2349/7440/6335 逐节引用（§2–§6） | PASS |
| 4.10 | 无 RFC 以官方规范为准 | 不适用（有 RFC） | PASS |
| 4.11 | 不许博客二手代替原文 | 三路对照=RFC 原文 + 本机 tshark 3.6.14 探针 + dissector 字段表 | PASS |
| 4.12 | 规范原文 | §12.4 路① | PASS |
| 4.13 | 商业软件实际行为 | §12.4 路② 诚实缺口（无产品级出处→G-TFTP-5，不编造） | PASS |
| 4.14 | 可靠开源实现思路 | §12.4 路③ Wireshark packet-tftp.c（31 字段 + 4 探针，不搬码） | PASS |
| 4.15 | 三路不一致取舍写清 | §12.4 不一致三条（丢包式语义/ S9 扩展不在 RFC 覆盖内 / wrap Block#=0 互操作负向） | PASS |
| 4.16 | 商业行为逐条映射用例号 | §12.5 映射表（PXE/固件/配置下发/NAT/错误面）；无出处项=G-TFTP-5 三选一确认方式 | PASS |
| 4.17 | 候选方案对比表 | §12.6 A/B/C/D 四案（真实走法 + 优劣 + 取舍） | PASS |
| 4.18 | 不许单方案自说 | A/B/C/D 在案，B 选定有理由 | PASS |
| 4.19 | 每表格行/字段/错误码三选一 | §12.2 24 格逐格、§12.3 19 行逐行、S14 25 行错误面 | PASS |
| 4.20 | 每条目对应至少一用例 | §12.2 14 格→用例号；§12.3 18 行→用例号（P5 后 19 行全覆盖）；余 3 格=G-TFTP-3 立项 | PASS |
| 4.21 | 动手前缺口矩阵 | §12 三子表先行（P1 产物，门1 获批） | PASS |
| 4.22 | 三张子表齐 | ①§12.2 ②§12.3 ③§12.5 齐 | PASS |
| 4.23 | 设计评审先看矩阵 | 门1 14 行对照表获批=开工门 | PASS |
| 4.24 | 规范与实现冲突先改实现 | E 族实跑校正锚词口径（锚词未漂移→保留并登记）；range 5 例锚词按实测改 | PASS |
| 5.1 | 设计写明依赖 | DependsOn ["udp"] + dst 69 缺省 + 0 合法名单（§13.5 链路可达性） | PASS |
| 5.2 | 写明出错处理 | D-TFTP-1.5 五类错误分支（Validate 族/互斥/ERROR 注入抑制/链级结构/框架缺口 G-TFTP-7） | PASS |
| 5.3 | 无依赖/错误分支不许实现 | 均有 | PASS |
| 5.4 | 无依据不许定字段流程缺省 | 字段/值域/缺省逐条挂 RFC 章节；S9 扩展明标非 RFC | PASS |
| 5.5 | 不确定标待确认+确认方式 | G-TFTP-5（抓包/手册/问运维三选一）、§15.7 性能数字待 P6 基准 | PASS |
| 5.6 | 回答结论指文档章节/代码行 | p6-review 逐条点行/例号 | PASS |
| 5.7 | 指不出直说不知道 | 路②诚实缺口不编造产品行为 | PASS |
| 5.8 | 回复前自查出处 | 本表逐行出处 | PASS |
| 5.9 | 抽查三条定位不到整批打回 | 门3 三条见 p6-review §2（行号/例号可定位） | PASS |
| 6.1 | 性能目标/预算/边界 | §15.7 六要素；单流最大报文 65510B 结构面可给；吞吐数字待 P6 基准（不写承诺） | PASS |
| 6.2 | 六指标列全 | §15.7 6.2（吞吐待确认/并发 flows/最大报文/内存 O(1)/队列 256/CPU 框架面） | PASS |
| 6.3 | pcap/NIC 分别验收 | 6.3：pcap 路=suite 落盘 + tshark；**NIC 路缺**（登记 §17 相邻项，框架面已有 nic_drive_test.go） | GAP(n)=NIC 用例未补（登记在案） |
| 6.4 | 性能依据结合实现路径 | 全流式 chan(256)/无锁无 sleep/FNV-1a 确定性/共享 pacer | PASS |
| 6.5 | 无依据数字标待确认 | 已标（6.5） | PASS |
| 6.6 | 六类性能场景 | 6.6：基线/目标规模/并发交错有例；**压力上限/长时/背压无例**（登记缺口） | GAP(n) 登记在案（不挡本验收） |
| 6.7 | 断言实际指标不只无报错 | 包数+字段值双钉（224 例均 packet_count + fields/frames） | PASS |
| 6.8 | 超预算仍不合格 | 资源预算未测→不得宣称性能达标（6.8 自认口径） | PASS（口径诚实） |
| 7.1–7.3 | 三份文档定位 | design/testcase/D-TFTP-1/T-TFTP 在案；未碰 CODE_DESIGN/TEST_CASES 正文 | PASS |
| 7.4 | 历史文档保留参考 | v2.0.2 全保留（§1–§11 历史层） | PASS |
| 7.5 | cases 是产物回指编号 | tftp.json 224 例回指 testcase §2 + design §16 | PASS |
| 7.6–7.7 | 三者关系/冲突序 | 回指不复制全文 | PASS |
| 7.8–7.9 | 先核心再设计再用例 | 门1 先行=P1–P3 产物 | PASS |
| 8.1 | 改哪几个文件 | D-TFTP-1.1 表（registry/strategy_convert/translate/semantic/strategy.json/cases） | PASS |
| 8.2 | 接口签名 | D-TFTP-1.2 全签名 + 新增 ParseTFTPConfigFromMap（core/tftp.go 实读在案） | PASS |
| 8.3 | 数据结构 | D-TFTP-1.3（TFTPConfig 23 键 + MessageEvent）；层 Fields=注册表 map | PASS |
| 8.4 | 主流程 | D-TFTP-1.4 现状/目标双流程（translate case 实读 chain_planner_translate.go:2676） | PASS |
| 8.5 | 错误分支 | D-TFTP-1.5 五类；presence 判死锚词实测命中 | PASS |
| 8.6 | 性能边界 | D-TFTP-1.6（O(n) 流式） | PASS |
| 8.7 | 与现有逻辑冲突点 | D-TFTP-1.7 五条（A1 端口保留现状裁定 + tid 读层 G-TFTP-2 已闭环） | PASS |
| 8.8 | 回滚方式 | D-TFTP-1.8（revert 改写提交；层数 123 不变） | PASS |
| 8.9 | 未定稿不开工 | 门1 获批=定稿=P4 开工 | PASS |
| 8.10 | 需求变先改设计 | 契约先于 P5 改写 | PASS |
| 8.11 | 不许代码先行文档后补 | P1–P3 → P4/P5 次序在案 | PASS |
| 8.12–8.13 | 开工贴条目/无条目打回 | 报告贴 D-TFTP-1 条目 | PASS |
| 9.1 | 用例登记 TEST_CASES | 回指 testcase §2（ID 权威）+ design §16 去向表 | PASS |
| 9.2–9.4 | 三源 | RFC + D-TFTP-1 + 已确认现网行为（产品级缺→G-TFTP-5；tshark 实测代位声明） | PASS |
| 9.5 | 每行/字段/错误码有用例 | §12.2 14 格 + §12.3 18 行（P5 后 19）+ S14 25 行错误面逐条 | PASS |
| 9.6 | 一例一行为 | 224 例 ID 唯一（脚本核 0 重复） | PASS |
| 9.7 | 修 bug 先复现变红 | P5 range 锚词 5 例首跑红→改→复跑绿（报告自述）；T-105/R2-MED-4 类已按实际行为订正 | PASS |
| 9.8 | 数据场景六变体 | §12.3 19 行（正常/边界/空/超长/非法/大小端逐项） | PASS |
| 9.9 | 业务场景序列/乱序/中断/交错 | 锁步多轮/重传丢包式/ERROR 中断/多流交错 | PASS |
| 9.10 | 现网场景+复杂度 9.50 下限 | §12.5 现网映射 5 行；复合大场景见 9.50 行 | PASS |
| 9.11 | 多动作组合流≥2 条×≥3 动作 | `tftp-rrq-all4opts-tidchange`（协商+数据+换轨+异常）、`tftp-matrix-allopts-retx-err`（选项+窗口+重传+ERROR） | PASS |
| 9.12 | 清单先行 | §12 矩阵先行（P1） | PASS |
| 9.13 | 清单无遗漏是目标 | 51 点复算（本表 9.52 行），无遗漏闭合 | PASS |
| 9.14 | 存量逐条审计去向 | §16 分族逐 ID 点名：226 = A175+B11+C40（D 删 7 逐 ID 表）；P6 机器复核差值=7 删/5 增闭合 | PASS |
| 9.15–9.19 | A/B/C 三分类 | G-TFTP-3=B′ 立项；动词≠覆盖（§12.2 逐格口径） | PASS |
| 9.20 | 取值表每值一例 | 错误码 0–8 逐值（error1-19b 逐字节 + err0/2/3/4/5/7/8 + 默认映射逐码 + 截断） | PASS |
| 9.21 | 分支级审计 | 同分支代表口径在契约明写（选项 16 组合→零/单/双/三/四五档） | PASS |
| 9.22 | 扫遍全部承载位置 | 单载体协议（UDP 唯一）无多承载位置；36 例错误面覆盖注入六态 | PASS |
| 9.23 | 正交矩阵逐格标记 | §12.2/§12.3 逐格（模式×方向×地址族×流数×异常） | PASS |
| 9.24 | 地址族对称 | IPv4 全族 + IPv6 补例 `tftp-v6-basic`（ipv6.nxt=17 实测）；见 N4 措辞注 | PASS |
| 9.25 | 地址族扩展随矩阵扩 | 动态地址/多流在 v6 面未单列（tftp A′ 仅基础 v6 例）→ 登记为可扩展项 | NOTE |
| 9.26 | 补齐顺序 | 最小实现→高频→全量（P5 序） | PASS |
| 9.27 | harness 做不到逐项注明 | 巨例 short-circuit/min_packets 口径注明（F 族） | PASS |
| 9.28 | 不许字段出现冒充顺序 | 重传序/窗口序/换轨序用逐包 fields 钉（如 all4opts-tidchange 12 钉） | PASS |
| 9.29 | 补齐后全量全绿 | RESULT: 224 pass, 0 fail, 0 error (of 224) | PASS |
| 9.30 | 只写不跑/只跑增量=未完成 | 全量复跑（非增量） | PASS |
| 9.31 | 断言以真实 pcap 校准 | 先跑后钉（A′ 3 例 + 巨例包数=落盘实读）；P6 复验 3/8/9 包吻合 | PASS |
| 9.32–9.36 | 动态整格 | tftp 业务 23 键**全不开**（理由在案）；四元组动态五策略由框架层承载，inc 逐值实证（49152..49251） | PASS |
| 9.37 | 派生编号撞车 | 多流例端口显式拉开（100 流 49152..49251；3 流 49152..49162）；server_tid 互异 | PASS |
| 9.38 | 聚合排除固定/派生口 | 用例断言层面未用聚合（逐流字段钉）；100 流例只断包数+互异已核 | PASS |
| 9.39 | 多流×静态标量互斥 | B 族全部层内动态对象（静态+flows>1 被 checkLayerChainStaticCopy 拒）；`tftp-tid-conflict-batch` 即该守卫实例（server_tid 固定被拒） | PASS |
| 9.40 | 共享流序号动态字段 | 不适用（无子实体共享序号面） | PASS |
| 9.41–9.45 | 测试评审五件事 | 本报告（三源回指/清单/断言/红例/全量） | PASS |
| 9.46 | 数据场景全表扫 | §12.3 19 行逐项（类型/上下界/边界/空/超长/非法/编码/字节序/必选缺席） | PASS |
| 9.47 | 取值集合逐值枚举 | 错误码 0–8、opcode 1–6、选项四键逐值域；保留值域（非法 opcode 0/7+）→G-TFTP-3 | PASS（缺口已立项） |
| 9.48 | 业务场景规范反推 | §15.2 五分类（数据/业务/现网/多流/地址族）清单来源=规范反推 | PASS |
| 9.49 | 多连接/多事务/多方/多流各一例+真实编排 | 多事务（锁步轮）✓ + 多流（8/100 流）✓；多方/多连接不适用（单客户端-单服务器模型） | PASS |
| 9.50 | 复合大场景≥3 类交织 | `tftp-rrq-all4opts-tidchange`：多事务轮≥4 + 异常分支(ERROR5) + NAT(TID 漂移) = 3 类交织（12 包逐包实测） | PASS |
| 9.51 | 组合矩阵满格 | §12.2 24 格 + 选项组合五档 + 模式×方向 10.3 表 | PASS |
| 9.52 | 审计声明出处+对账两行 | 出处声明在案；修轮后订正：§12.3 实数 **19 行** → 总数 **51**、覆盖 **40**；P5 后 43/3/5 闭合（两式复算 =51）；§15.3/§15.2 同步订正（190f313） | PASS |
| 9.53 | 门3 至少一条抽最复杂用例+点数 | 抽 `tftp-rrq-all4opts-tidchange`（3 类交织 ≥ 下限 3）；三条抽查=§1/§12/§3 行（见 p6-review §2） | PASS |
| 10.1 | 文档对规范逐条核对 | v2.0.2 修订记录四轮审计（35/24/17/11 问题）在案 | PASS |
| 10.2 | 改需求前对旧需求逐条核对 | 契约 §18 勘误汇总（对 v2.0.2 三处口径订正） | PASS |
| 10.3 | 代码逐行走读 | P4 自审 3 轮 + P5 校准 3 轮（末轮干净）；本 P6 复核关键件 | PASS |
| 10.4 | 构建+vet+测试含 race | P6 复核：`go test ./internal/core/layers/ -run TestTFTP` + `./internal/core/` 绿（0.037s/0.019s） | PASS |
| 10.5 | 修完再审 | 每轮 fix 后复跑全量（报告） | PASS |
| 10.6–10.10 | 测试评审 | 本报告（测对路径/输入可触发/断言输出非摆设） | PASS |
| 10.11 | 改审测修再审闭环+结论 | 报告自审轮数在案；P6 本判词 | PASS |
| 11.1–11.5 | 白话 | p6-review §0 白话结论 | PASS |
| 12.1 | 五策略全开（每流可变字段） | 四元组五策略由框架层（layer_dyn）提供；tftp 业务键不开有逐键理由 | PASS |
| 12.2 | 动态至少覆盖四元组 | ip/udp 层（layer_dyn.go:18-20 allowlist） | PASS |
| 12.3 | 协议关键业务字段清单 | §13.4 表：23 键逐个列（全不开）+ 理由（一链一流，四元组即身份；YAGNI） | PASS |
| 12.4 | flows=N 确定性+可复现+回绕 | FNV-1a(FlowID) 决定 server TID；inc 端口逐值实测（49152..49251 与声明 range 一致） | PASS |
| 12.5 | 不写动态按 fixed | 单流 189 例静态层值 | PASS |
| 12.6–12.8 | 任务级动态不丢规则/只截断/跨策略 | 框架语义未动 | PASS |
| 12.9 | 静态复制拒绝/告警 | `checkLayerChainStaticCopy`（schema/semantic.go:198-219）+ `checkTFTPServerTID`（tftp 特有加严）双守卫 | PASS |
| 12.10 | src_port 保底≠动态 | 报告/契约明示保底仅防撞（12345+i）；多流例显式动态 | PASS |
| 12.11–12.13 | 动态住层链/不另起顶层/对齐 tuples | 地址住 ip、端口住 udp、数量住 flow_control | PASS |
| 12.14–12.16 | 清单+序号算法可定位 | 序号算法行号：resolveLayerTuple/layer_dyn.go；tftp 协议内序号=plan.go:356 wireBlockNum / tftp.go:365 deterministicTID；评审抽查②已定位 | PASS |
| 13.1–13.6 | schema 文件 | registry.go:192 tftp 行（23 Fields）+ generated tftp 条目 23 字段机器比对三向同数 | PASS |
| 13.7–13.10 | 校验入口唯一 | ValidateStrategy 同入口；MCP 继承（suite 经 MCP 实跑） | PASS |
| 13.11–13.16 | 派生只读下游 | flowb_query_layers 实时视图（P4 未改 schemagen 以外派生） | PASS |
| 13.17 | 改配置语义先改 schema | registry Fields 先行 + 生成表同批提交 | PASS |
| 13.18 | 注册表变更重跑生成并提交 | layers.generated.json 已随 P4 提交（merge 17554db 含） | PASS |
| 13.19 | 过期测试变红 | TestLayersGeneratedMatchesRegistry 未跑（P6 禁跑 schemagen）；机器三向比对代替，零漂移 | PASS |
| 13.20–13.23 | 缺席走缺省/null 拒/不算第四文档 | 层 config 缺键走 TFTPConfig 零值 + Plan 默认化（translate 期不重复默认化，D-TFTP-1.7⑤） | PASS |
| 13.24–13.26 | 评审先查 schema/手写/null 兼容 | 本 P6 抽查② | PASS |
| 14.1 | 用例 spec 即 MCP 任务配置 | spec_json=策略 config 直驱（suite 实跑 224/224） | PASS |
| 14.2 | 不许两套写法 | 单权威（层链唯一） | PASS |
| 14.3 | 执行工具直接消费用例 | flowb_run_protocol_suite 直消（车道跑法） | PASS |
| 14.4 | 旧扁平用例随层链迁移改写 | 226→224 全量改写（7 删/5 增逐 ID 在案） | PASS |
| 14.5 | 历史口径不带入 | 旧包数公式全废；全部先跑后钉 | PASS |
| 14.6 | 先跑拿实际 pcap 再钉 | A′ 3 例 + 巨例包数=落盘 tshark 实读（P6 复验 3/8/9 吻合） | PASS |
| 14.7–14.9 | MCP 建任务→引擎生成→tshark 校对 | P6 隔离复跑同路径（MCP 18096 → pcap 落盘 → tshark 逐字段） | PASS |
| 14.10 | 只跑离线/只断任务不失败/只数包不算测 | 224 例均含 packet_count + fields/frames 双钉 | PASS |
| 14.11 | 负例经 MCP 被拒锚词 | 35/35 严格 {expect_error, error_contains}（脚本复核）；锚词 ∈ 代码锚词集 | PASS |
| 14.12 | 假成功同级 bug | 负例走真实流程被拒（suite 绿=锚词命中）；G-TFTP-7 框架面单独立项 | PASS |
| 14.13–14.15 | 聚端口/派生口/方向想清 | 逐流字段钉（src/dstport 按方向断言）；TID 交换 srcport≠69 断言在案 | PASS |
| 14.16 | 全绿+落盘可复查 | 224 包 pcap 落 /tmp/pipe/lanes/lane3/pcaps/tftp/（216 落盘 + 8 无 pcap 负例） | PASS |
| 14.17 | 抽查 spec/字段/锚词 | 本报告 §1/§7 | PASS |
| 14.18 | 二进制与 HEAD 同代 | 关门口径=canonical 二进制同代 + canonical 复跑 224/224（lane 副本时间戳红系后续协议合并所致、tftp 面 diff 零行；由 canonical 等效承担，GAP(10) 关闭） | PASS |
| 14.19 | 全量全绿（非增量） | RESULT 224/224 | PASS |
| 14.20 | 包号/端口基准从 pcap 拿 | 先跑后钉；P6 复验 | PASS |
| 15.1 | 门1 十四行对照表+证据 | design §13 全表（证据三选一） | PASS |
| 15.2 | 证据写不出=立项 | 缺口 G-TFTP-1..8 逐条立项 | PASS |
| 15.3 | §1/§3/§12 强制展开 | §13.1 九键去向+§13.2 样例 / §13.3 五件套 / §13.4 动态清单 | PASS |
| 15.4 | 门2①顶层零残留 | 门2-1 绿（黄线 3 条=已登记过渡，N1/N3） | PASS |
| 15.5 | 门2②全量绿+负例锚词 | RESULT 224/224 + 35/35 锚词 | PASS |
| 15.6 | 门2③二进制同代 | canonical 同代绿（lane 副本红已按上条口径关闭） | PASS |
| 15.7 | 门2④反查绿后进 P6 | coverage_gate 53/53 exit 0 | PASS |
| 15.8 | D-条目挂门1表+回填证据 | design §13 表 + P6 本表回填 | PASS |
| 15.9 | 抽查三条点到行/例号 | p6-review §2（strategy_convert.go:8559-8561 / layer_dyn.go:18-20 / semantic.go:444+473 + 例号） | PASS |
| 15.10 | 白话+三门证据 | p6-review §0/§4/§5 | PASS |
| 15.11 | 任一门红停 | 复评通过（C0/M1/m3）+ 修轮（文档订正/notes 订正/presence 登记）+ canonical 复跑关门 | PASS |

## 注记（backlog，不挡验收）

- **N1（E 族过渡登记，裁定：诚实）**：`tftp-e2e-tcp-reject` / `tftp-http-coexist-reject` 保留顶层 tcp/http 子映射 + 原 V20 锚词（实测 V20 经 universal 读路径仍可达，契约 §14.7④ 原写"改锚词"未触发）；二例均为负例（游离键=执法对象），门2① 黄线点名。无需打回。
- **N2（strategy.json 过渡登记，裁定：诚实）**：D-TFTP-1 §14.1 明文允许"或登记为过渡"；运行时真相=CheckProtoFlat 判死。schema 形状是否收敛属主线程裁定（p4-report 已点名）。
- **N3（pipe_gate presence 未登记 tftp）**：presence 红线 case 名单无 tftp（nfs 有专条 commit）；该形状仍被门2①黄线覆盖 + coverage_gate presence 检查 + 链级红例。建议按 nfs 先例补一行。
- **N4（契约措辞）**：design §12.3 注"`ipv6` 层同族注册"与事实不符（注册表仅 `ip`/`eth`；房型=ip 层写 v6 字面量，全库 175 例同款）；A′ 覆盖已达成，措辞随 G-TFTP-9 同批订正。
- **N5（文案）**：`tftp-multiflow-100flows-tuple-unique` notes"src 12345..12444 自动递增"与实测（层动态 inc 生效 49152..49251）不符；断言正确，notes 订正。
- **N6（WRQ TID 叙事）**：WRQ 侧换轨序列（DATA#N 即指新 TID、ERROR(5) 作标记）与 §4.3 的 RRQ 视角叙事形态不同；plan.go 两方向各自实现，用例标互操作负向。建议 D-条目补 WRQ 侧一句。
- G-TFTP-3/5/6/7：按 p123 登记（非法 opcode 三格 / 现网出处 / RFC §4 合规 TID 序列不实现 / 驱动 error→空流收敛），出本车道。
- G-TFTP-1/2/4/8：已闭环（本 P6 复验）。
- G-TFTP-9（9.52 行）与 G-TFTP-10（14.18/15.6 行）**均已关闭**：文档订正随修轮入版（190f313）；门2③以 canonical 二进制同代 + 复跑关门（lane 重编复跑由 canonical 等效承担）。
