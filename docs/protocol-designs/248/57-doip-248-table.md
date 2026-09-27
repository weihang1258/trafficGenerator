# DOIP（D-DOIP-1 #57）P6 248 条款逐条比对表

> 口径：docs/CORE_MEMORY.md（v15/481 行，2026-09-27 读）。落点=doip#57 实测证据（lane1 独立重跑：suite 80/80=50 正+30 负、门2 静态四项、反查 60/60、-race 绿；P6 隔离终审独立复跑一致，判词通过，无 P0/P1/M）→ 集成点 `3c82df2`（HEAD 已前移 `2c176b0`，doip 锚行号零漂移）。判定：PASS=满足，GAP(n)=缺口编号，NOTE=注记。
> 文档面（P6 契约入版待落仓）：design v3.0.0（2063 行，`/tmp/stale-docs-backup/docs_protocol-designs_05-doip-design.md`）+ testcase v1.0.0（194 行，`/tmp/pipe/57-doip/05-doip-testcase.md`）；仓内现仍为 v2.0.1（1568 行）。凡“落点=design §12–§19 / testcase §x”的行现指 v3.0.0 备份件，标 P6 契约入版。

| 条款 | 要求 | doip 落点 | 判定 |
|---|---|---|---|
| 1.1 | 地址只写 ip 层 | 80 例 `layers[i].ip.src/dst`（192.168.1.100→192.168.1.200；IPv6 例走 `ipv6` 层）；无顶层地址键 | PASS |
| 1.2 | 端口只写 tcp/udp 层 | `tcp.src_port`/`dst_port=13400`；doip 层 FieldContract 补 13400 缺省（`chain_planner.go:1038-1041`） | PASS |
| 1.3 | 流数量只写 flow_control | 77 例顶层键唯 `layers`（机核）；3 例故意非纯 layers 负例见 1.11 | PASS |
| 1.4 | 禁 layers 与顶层五键混用 | 门2-1 绿（无顶层旧键残留）；`CheckProtoFlat` doip 判死分支在案 | PASS |
| 1.5 | 混用示例/用例/文档都算跑偏 | 无混用示例；design v3.0.0 §14.1 样例为纯 layers（P6 契约入版） | PASS |
| 1.6 | 门①层链能跑通 | suite 80/80（P6 独立重跑 12.392s，EXIT=0）；50 正例 pcap 齐落盘 | PASS |
| 1.7 | 门②旧格式彻底移除 | 115→80 收敛（F1/F2 47 例作废，design §18）；presence/游离键判死两路 | PASS |
| 1.8 | 示例只给严格层链形 | 用例 spec_json 77/80 严格层链形（3 例为故意判死负例形状） | PASS |
| 1.9 | 暂不支持时标注目标形状 | UDP 三键链级拒绝 + design §13.3 候选 A/B/C/D（P6 契约入版） | PASS |
| 1.10 | 汇报分开说跑通/清旧字段 | p4-report §2/§3 分节 | PASS |
| 1.11 | 顶层白名单（layers/flow_control 家族/output） | 唯一并存 = `doip_neg_presence`（判死负例形状，14-P2 口径）+ `doip_neg_stray_src_ip`/`doip_neg_stray_count`（游离键负例形状） | PASS |
| 1.12 | 无可住层时立项补层，不许豁免 | 业务七键+UDP 三键=十键已得层（registry.go:270 实测；文档写 224-226，漂移系先合入所致）；vin/eid/gid 不入册=G-DOIP-7 死配置删键，非豁免 | PASS |
| 1.13 | 门2①按白名单执行 | 同 1.11；黄行=`doip_neg_presence` 负例本身（D-条目登记豁免，G-DOIP-5 已解） | PASS(NOTE) |
| 2.1 | 策略=单模板自带 flow_control | `strategy_fc` 在案（multiflow_dynamic flows=2，其余缺省） | PASS |
| 2.2 | 任务=多策略合跑+总量封顶 | 框架语义未动（suite 走策略路径） | PASS |
| 2.3 | 策略先限速任务再封顶 | 未动 | PASS |
| 2.4 | 任务 ID={taskID}-{strategyID} | 未动 | PASS |
| 2.5 | flows=N 复制 N 条 | multiflow_dynamic flows=2 → 2×9=18 包实证（P6 §9.53 深审） | PASS |
| 2.6 | spec 不管数量 | 未动 | PASS |
| 2.7 | 按流变化走动态字段 | 四元组动态住 ip/tcp（layer_dyn.go:18-63）；doip 业务字段未开（G-DOIP-8） | NOTE(G8) |
| 2.8 | 未写动态 src_port 保底 12345+i | worker.go:298-311 保底递增实证（P6 A1 点行） | PASS |
| 2.9 | 其余按流变化必须写动态 | design v3.0.0 §14.12 业务清单（P6 契约入版）；业务动态零开=立项维持（G-DOIP-8） | PASS |
| 2.10 | 讲数量分清策略复制/任务封顶 | p123 门1 §2 行 | PASS |
| 2.11 | 讲变化动态按 §12 | 本表 12.x | PASS |
| 3.1 | 多会话 sessions[]/flows[] 显式 | doip 无 sessions[] 结构；多会话=flows=N 展开，每会话独立 4-tuple/逻辑地址/生命周期（design §14.3，P6 契约入版） | PASS |
| 3.2 | 每会话独立 ID/四元组/生命周期 | multiflow_dynamic 两会话串行（包 1-9 srcport 40000，包 10-18 srcport 40001）+ s1/s2 会话表 | PASS |
| 3.3 | 会话内事务有序序列 | 激活→诊断×N→探活→挥手固定分支序（layer_gen.go:112-245）；full_flow 18 包事件序 | PASS |
| 3.4 | 事务前置条件 | design §14.3 事务表 t1/t1'/t2..tn/tm/tz 四件事（P6 契约入版） | PASS |
| 3.5 | 触发动作 | messages[] 显式序列（禁模板重复冒充编排） | PASS |
| 3.6 | 成功分支 | 0x0006 RC=0x10→进诊断；0x8002 Ack（PrevDiag=被确认副本） | PASS |
| 3.7 | 失败分支 | 0x8003 Nack + UDS 7F NRC；激活拒绝钉现状负例（G-DOIP-3） | PASS |
| 3.8 | 控制关联数据流显式字段 | 单连接协议无控制/数据分离，driven_by 不适用（三证据：16 型表无数据面型 + doip.go 单 configChan + scapy DoIPSocket 单连接，design §14.3） | PASS |
| 3.9 | 关联写清会话/事务/决定字段 | 不适用（同上） | PASS |
| 3.10 | 被关联流独立 ID/四元组/握手 | 无副流（单载体）；flows=N 多会话各独立 4-tuple/握手/挥手 | PASS |
| 3.11 | 各流顺序/并发/交错写清 | 单会话严格有序、跨会话并发（design §14.3 时间线，P6 契约入版） | PASS |
| 3.12 | 可交错写清调度+时间戳 | 同连接 UDS 请求-响应严格串行不交错；时间戳由 worker Pacer 产生 | PASS |
| 3.13 | 不许连续重复冒充编排 | messages[] 显式序列 + alive_check 对象，非模板重复 | PASS |
| 3.14 | 无长连接豁免≠多流豁免 | 有长连接载体（TCP 13400）不豁免；多流=multiflow_dynamic + 单消息多载荷=0x36 分段/PrevDiag 副本/full_flow | PASS |
| 3.15 | 多轮/非正常结束/长保活各一例或立项 | ①多轮有例（UDS 多轮+full_flow）②非正常半程→G-DOIP-3（拒绝钉现状）③长保有例（alive_check+termination 开关） | PASS |
| 3.16 | CWMP 范本照补 | 差异声明：无 driven_by（单载体无副流） | PASS |
| 3.17 | 多流设计五件套 | design §14.3（P6 契约入版）；multiflow_dynamic 落多流面 | PASS |
| 4.1 | 连接模型 | design §12.1 行 4.1（ISO §7；TCP 13400 单载体 + UDP 面 G-DOIP-2，P6 契约入版） | PASS |
| 4.2 | 命令/消息表 | design §2.2（16 项）+ §12.2 子表① 16 格（P6 契约入版；§2 正文仓内 v2.0.1 原样保留） | PASS |
| 4.3 | 状态机 | design §4 七阶段 + §12.1 行 4.3（P6 契约入版） | PASS |
| 4.4 | 字段表 | design §2.1/§2.3–§2.16 + §3.2 默认值表 | PASS |
| 4.5 | 错误处理表 | design §2.3/§2.9/§2.15/§8/§9 + §15.5 E1–E10 锚词表；用例面 30 负例锚 | PASS |
| 4.6 | 超时与活性 | design §4.1/§4.5/§6.14 + §12.1 行 4.6；超时单边归 tcp 层 termination 标明确不解决 | PASS |
| 4.7 | NAT/代理/被动 | 广播改写 doip.go:473-482/:554-563；NAT 现网无证据→G-DOIP-9（B′ 登记） | PASS |
| 4.8 | 版本/方言 | design §1.3/§8.1（V1/V2 双态；0x03/0x04 明确不支持）；V1 正例 `doip_tcp_activation_v1` 在案 | PASS |
| 4.9 | 有 RFC 查 RFC 注章节 | 无 RFC：ISO 13400-2:2019 + ISO 14229-1（design §13.1，P6 契约入版） | PASS |
| 4.10 | 无 RFC 以官方规范为准 | 同上（章节级落点 design §2–§4） | PASS |
| 4.11 | 不许博客二手代替原文 | p123 §②10.1 逐条回指规范表行 | PASS |
| 4.12 | 规范原文 | design §2–§4 逐表（54 逻辑点口径见 9.52） | PASS |
| 4.13 | 商业软件实际行为 | 无实测证据→G-DOIP-9（确认方式三选一已写死，design §13.1 路②，不冒充定论） | PASS |
| 4.14 | 可靠开源实现思路 | scapy 2.7.0 doip.py 525 行关键行逐条核对（design §13.1 路③，借鉴不搬码） | PASS |
| 4.15 | 三路不一致取舍写清 | design §13.1 三路一致性 + §13.3 取舍理由（P6 契约入版） | PASS |
| 4.16 | 商业行为逐条映射用例号 | design §13.2 子表③ B1–B7（P6 契约入版）；B1/B2/B7 无映射标待确认 | PASS |
| 4.17 | 关键决策候选方案对比表 | design §13.3 A/B/C/D 四方案（P6 契约入版） | PASS |
| 4.18 | 不许单方案自说 | 同上 | PASS |
| 4.19 | 每表格行/字段/错误码三选一 | design §12 矩阵 54 点三选一（P6 契约入版）；用例面 80 例承接 | PASS |
| 4.20 | 每条目对应至少一用例 | 38 覆盖 + 4 明确不支持 + 12 立项 = 54（testcase §8.3，P6 契约入版） | PASS |
| 4.21 | 动手前缺口矩阵 | p123 门1 表 + design §12 矩阵 | PASS |
| 4.22 | 三张子表齐 | design §12.1/§12.2/§12.3 + §13.2 子表③（P6 契约入版） | PASS |
| 4.23 | 设计评审先看矩阵 | 门1 获批（p123 §①） | PASS |
| 4.24 | 规范实现冲突先改实现 | V1 最小子集链例 + P5 先跑后钉 2 处误钉修正（doip.data→uds.sid；alive_check 单向语义） | PASS |
| 5.1 | 设计写明依赖 | `DependsOn ["tcp"]` + `TransportOn ["tcp"]`（registry.go:270 实测；design §13.4/§15，P6 契约入版） | PASS |
| 5.2 | 写明出错处理 | 值域校验 doip.go:26-232 + 链级拒绝 layer_gen.go:63-69/149/304 + carrier 冲突 complete.go:447-480 + create 期预检 validate_layers.go:613-650 双路闭合 | PASS |
| 5.3 | 无依赖/错误分支不许实现 | 有 | PASS |
| 5.4 | 无依据不许定字段流程缺省 | 端口 13400/16 型表/值域均有 ISO+scapy 出处（design §13.1） | PASS |
| 5.5 | 不确定标待确认+确认方式 | G-DOIP-9 三选一在案 | PASS |
| 5.6 | 回答结论指章节/代码行 | design §12–§19（P6 契约入版待落仓，引用暂指备份件） | PASS(NOTE 入版) |
| 5.7 | 指不出直说不知道 | 吞吐数字诚实“待基准”（design §15.6/§16） | PASS |
| 5.8 | 回复前自查出处 | p4-report §6 自审 4+3 轮 | PASS |
| 5.9 | 抽查三条定位不到打回 | 门3 三条≡p6-review(a)（A1/A2/A3 均点行/例号） | PASS |
| 6.1 | 性能目标/预算/边界 | design §16 + §15.6（P6 契约入版）；声明式事件流 O(1) 内存 | PASS |
| 6.2 | 六指标列全 | 吞吐跟 tcp 层同档；并发=flows；单流最大=MSS；内存 O(1)/流；队列 256；CPU=PacketWorkers；数字标待确认 | PASS |
| 6.3 | pcap/NIC 分别验收 | pcap 路：50 正例 pcap + suite 全绿；**NIC 路本轮未跑** | NOTE |
| 6.4 | 性能依据结合实现路径 | 逐事件 EmitMsg、无聚合、无锁、无新增桶（layer_gen.go 头注） | PASS |
| 6.5 | 无依据数字标待确认 | 已标 | PASS |
| 6.6 | 六类性能场景 | 清单在案（§16）；P5 未跑基准 | NOTE |
| 6.7 | 断言实际指标不只无报错 | packet_count 50 例 + 字段/frames 双钉 | PASS |
| 6.8 | 超预算仍不合格 | — | PASS |
| 7.1–7.3 | 三份文档定位 | design+testcase+D-DOIP-1；未碰 CODE_DESIGN/TEST_CASES | PASS |
| 7.4 | 历史文档保留参考 | — | PASS |
| 7.5 | cases 是产物回指编号 | 80 例回指 testcase §2 T-DOIP 41-ID 目标集；口径差→**P6 以实测 80 例为准**（enip 先例；文件内 T-DOIP 提及 21 处，仅 10 例 summary 以 T-DOIP 开头） | PASS(NOTE 口径差，P6 契约入版对齐) |
| 7.6–7.7 | 三者关系/冲突序 | — | PASS |
| 7.8–7.9 | 先核心→设计→用例 | 门1 先行（P1–P3 先于 P4/P5） | PASS |
| 8.1 | 八要素（文件/接口/结构/流程/错误/性能/冲突/回滚） | design v3.0.0 §15 8.1–8.8（P6 契约入版）；实现面逐件在码 | PASS |
| 8.2–8.8 | 同上逐项 | design §15（P6 契约入版）；translate/validate/backfill 落点见 p6-review(a) | PASS |
| 8.9 | 未定稿不开工 | 门1 获批=开工 | PASS |
| 8.10 | 需求变先改设计 | P5 重锚 2 处误钉修正回填断言（非需求变） | PASS |
| 8.11 | 不许代码先行文档后补 | P1–P3 先行 | PASS |
| 8.12–8.13 | 开工贴条目/无条目打回 | — | PASS |
| 9.1 | 用例登记（回指编号） | testcase §2 T-DOIP 41-ID 目标集 vs 实测 80；**P6 以实测为准** | PASS(NOTE) |
| 9.2–9.4 | 三源（规范/设计/现网） | ISO+scapy/tshark+D-DOIP-1；现网缺证据→G-DOIP-9，不冒充第三源 | PASS |
| 9.5 | 每行每字段每错误码有用例 | 38/54 命中；缺口逐个去向（G-DOIP-2/3/4/7 + 明确不解决） | PASS |
| 9.6 | 一例一行为 | 80 例无重复 id（机核）；正例 packet_count 全有、负例 error_contains 全有（双不变量零违规） | PASS |
| 9.7 | 修 bug 先复现变红 | P5 先跑后钉抓 2 处误钉并修正 | PASS |
| 9.8 | 数据场景六变体（正常/边界/空值/超长/非法/大小端） | 边界例族（OEM 变长/BlockSeq 回绕/NRC/SID/方向非法/MSS 下限）+ 非法 30 负例 | PASS |
| 9.9 | 业务场景序列/乱序/中断/交错 | 生命周期序列 + 激活确认/安全访问/传输依赖链；乱序/中断=G-DOIP-3 | PASS |
| 9.10 | 现网场景；复杂度 9.50 下限 | 最复杂例 multiflow_dynamic 深审通过（多会话×逐流 4-tuple×动态 inc×多断言交织）；异常分支在负例族，未同例交织 | NOTE(9.50 分担覆盖) |
| 9.11 | 多动作组合流≥2 条×≥3 动作 | full_flow（激活→诊断×N→探活→挥手）/transfer（0x34→0x36×N→0x37）≥2 条 ✓ | PASS |
| 9.12 | 清单先行 | P1 矩阵先行（p123 门1 §4） | PASS |
| 9.13 | 清单无遗漏是目标 | 54 点 38+4+12 无遗漏 | PASS |
| 9.14 | 存量逐条审计去向 | design §18 逐族点名 115 例（F1 40/F2 7/F3 22/F4 33/F5 6/F6 6/F7 1=115 ✓，P6 契约入版）+ P5 收敛 47 例作废 | PASS |
| 9.15–9.19 | A/B/C 三分类 | G 立项承接（G-DOIP-2/3 等）；F1 整族作废论证不冒充覆盖 | PASS |
| 9.20 | 取值表每值一例 | 0x8003 正例仅 0x03/0x04/0x06 三值（0x02/0x05/0x07/0x08 无正例）；RC/AT/NRC/SID 值域面已覆 | GAP(A′-取值面) |
| 9.21 | 分支级审计 | 负例按分支铺（激活/UDS/方向/MSS/载体） | PASS |
| 9.22 | 扫遍全部承载位置 | 层内 doip 十键（唯一承载）全覆盖 | PASS |
| 9.23 | 正交矩阵逐格标记 | design §12 矩阵（P6 契约入版） | PASS |
| 9.24 | 地址族对称（IPv4/IPv6 逐格） | IPv6 有例（ipv6_activation/ipv6_alive 在 80 例内；目标形 ipv6_tcp_flow，P6 契约入版） | PASS |
| 9.25 | 地址族扩展随矩阵扩 | IPv6 面已覆（起点 74 断言口径见 testcase §3） | PASS |
| 9.26 | 补齐顺序 | 最小实现→高频→全量（testcase §2 最小实现条目优先） | PASS |
| 9.27 | harness 做不到逐项注明 | 包序/方向靠 frames+字段组合钉 | PASS |
| 9.28 | 不许字段出现冒充顺序 | full_flow 事件序列断言（messages[] 位置体现顺序） | PASS |
| 9.29 | 补齐后全量全绿 | 全量 80/80 绿（lane1 + P6 独立重跑） | PASS |
| 9.30 | 只写不跑/只跑增量=未完成 | 全量跑 | PASS |
| 9.31 | 断言以真实 pcap 校准 | 先跑后钉（169 字段 + 56 frames + 80 packet_count 三通道复算，零偏差） | PASS |
| 9.32–9.35 | 动态整格（五策略×字段） | 四元组 framework 面在案；multiflow_dynamic 含动态 src_port inc；业务动态面维持立项（G-DOIP-8） | PASS/A′ |
| 9.36 | 不支持格标 B/C+注记 | G-DOIP-2/3 钉现状负例（UDP 三键/激活拒绝锚取真实 validator 文案） ✓ | PASS |
| 9.37 | 派生编号撞车 | s2 会话与 s1 拉开间隔（design §14.3） | PASS |
| 9.38 | 聚合断言排除固定/派生口 | multiflow_dynamic distinct 排除 13400（verifier 聚合语义，P6 §9.53 深审） | PASS |
| 9.39 | 多流×静态标量互斥 | multiflow_dynamic 按口径交付（flows=2 + tcp.src_port 动态 inc） | PASS |
| 9.40 | 共享流序号动态字段 | 无跨子实体共享断言面 | NOTE |
| 9.41–9.45 | 测试评审五件事 | p6-review(c)(d)(e) | PASS |
| 9.46 | 数据场景全表扫 | 字段边界例族在案；码值未全（见 9.20） | GAP(A′) |
| 9.47 | 取值集合逐值枚举 | 同上 | GAP(A′) |
| 9.48 | 业务场景规范反推 | design §12 三子表（P6 契约入版）；出处声明 testcase §8.3 | PASS |
| 9.49 | 多连接/多会话/多事务各一例+真实编排 | 多事务 ✓ + 多会话 ✓（flows=2）；真实编排（同连接多轮×多会话×探活插入） | PASS |
| 9.50 | 复合大场景≥3 类交织 | multiflow_dynamic（多会话×多事务×动态）深审通过；异常分支未同例交织（见 9.10） | NOTE |
| 9.51 | 组合矩阵满格 | design §12 矩阵（P6 契约入版）；用例面组合维度有限=A′ 维持 | PASS/A′ |
| 9.52 | 审计声明出处+对账两行 | testcase §8.3：规范逻辑点 54 vs 用例覆盖 38（+4 明确不支持+12 立项）；出处=规范反推非用例反推 | PASS |
| 9.53 | 门3 至少一条抽最复杂用例+点数 | multiflow_dynamic：18 包（2×9 公式逐包成立）、3 断言逐包成立（P6 §9.53 深审） | PASS |
| 10.1 | 文档对规范逐条核对 | p123 §②10.1 | PASS |
| 10.2 | 改需求先对旧需求 | p123 §②10.2（v2.0.1 结论原样保留，补位新增 §12–§19） | PASS |
| 10.3 | 代码逐行走读 | P4 4 轮 + P5 3 轮（p4-report §6）；P6 只读复审 | PASS |
| 10.4 | 构建+vet+测试含 race | build/vet 干净；-race 链相关包绿；全仓扫唯一红=ftp 性能门抖动（与 doip 无关） | PASS |
| 10.5 | 修完再审 | 每轮 fix 后再审（末轮干净） | PASS |
| 10.6–10.10 | 测试评审 | p6-review(c)(d)(e)（三源对账+锚词核+点数） | PASS |
| 10.11 | 改审测修再审闭环+结论 | p4-report §6 在案 | PASS |
| 11.1–11.5 | 白话 | p123 首节/p4-report/p6-review §0 | PASS |
| 12.1 | 五策略全开 | 四元组五策略 framework 在案（layer_dyn.go:18-63） | PASS |
| 12.2 | 动态覆盖四元组 | 同上（multiflow_dynamic 取用 inc） | PASS |
| 12.3 | 业务字段清单逐协议 | design §14.12（P6 契约入版）；G-DOIP-8 登记业务字段未开 | PASS |
| 12.4 | flows=N 确定性+seed+回绕 | framework 语义（tuple_generator.go:194-236 inc 回绕/rand seed+index 可复现）；multiflow_dynamic inc 实证 | PASS |
| 12.5 | 不写动态按 fixed | 79 静态例全静态（multiflow 四元组动态属 §12 面） | PASS |
| 12.6–12.8 | 任务级动态不丢/只截断/跨策略 | framework 未动 | PASS |
| 12.9 | 静态复制拒绝/告警 | framework 守卫在案（testcase §3 #15 静态复制被拒面；multiflow 已绕开） | PASS |
| 12.10 | src_port 保底≠动态 | 诚实声明（design §14.12） | PASS |
| 12.11–12.13 | 动态住层链/不另起顶层/对齐 tuples | 四元组住 ip/tcp；无顶层动态键 | PASS |
| 12.14–12.16 | 清单+序号算法可定位 | 序号算法四元组 layer_dyn + tuple_generator + worker 保底在码可定位；业务动态面维持立项（G-DOIP-8） | PASS |
| 13.1–13.6 | schema 文件 | registry doip 行十键 + FieldContract 13400 + TransportOn[tcp] + DependsOn[tcp]；generated json 127 层 doip 条目逐键一致（P6 A2 实测） | PASS |
| 13.7–13.10 | 校验入口唯一 | ValidateStrategy/TaskCreate 同入口（suite 走 MCP） | PASS |
| 13.11–13.16 | 派生只读下游 | flowb_query_layers 实时视图 | PASS |
| 13.17 | 改语义先改 schema | registry 先行（P4） | PASS |
| 13.18 | 注册表变更重跑生成 | generated 已重跑（127 层，只动 doip 条目） | PASS |
| 13.19 | 过期测试变红 | P6 以 json 内容机核代查；`TestLayersGeneratedMatchesRegistry` 未单跑 | NOTE |
| 13.20–13.21 | 缺席走缺省/null 拒 | 缺席走引擎缺省（空层 `{}` 走 legacy 缺省对齐，design §15.3）；未知键走 unknown field 拒（E1） | PASS |
| 13.22–13.23 | schema 是机器源不算第四文档 | — | PASS |
| 13.24–13.26 | 评审先查 schema/手写/null 兼容 | 无手写形状、无 null 兼容分支；翻译复用扁平 parse（JSON 往返 base64 误读实证后改道，裁定②a 准予偏离） | PASS(NOTE 偏离) |
| 14.1 | 用例 spec 即 MCP 任务配置 | spec_json=layers 直驱 + strategy_fc 封包 | PASS |
| 14.2 | 不许两套写法 | 单权威（翻译复用扁平 parse 仅实现路径不同，语义单真相，裁定②a） | PASS(NOTE 偏离) |
| 14.3 | 执行工具直接消费用例 | suite 经 MCP 直消（P6 独立重跑） | PASS |
| 14.4 | 旧用例随层链迁移改写 | 115→80 全改写（F1–F7 逐族，§18 W1–W8，P6 契约入版） | PASS |
| 14.5 | 历史口径不带入 | 包号实测重校（先跑后钉；2 处误钉修正） | PASS |
| 14.6 | 先跑拿 pcap 再钉 | P5 实跑重锚；P6 深审复核 multiflow 18 帧逐包 | PASS |
| 14.7–14.9 | MCP 建任务→生成→tshark 校对 | lane1 MCP + tshark 字段/frames 双通道 | PASS |
| 14.10 | 离线/无失败/只数包不算测 | 字段+frames 双钉；离线执行器未纳入 doip（口径不一致已回滚，MCP 为权威通道，非缺口） | PASS(NOTE 离线未纳) |
| 14.11 | 负例经 MCP 被拒+锚词 | 30 负例全 error_contains（抽 5 逐字一致 + presence/carrier 加核） | PASS |
| 14.12 | 假成功同级 bug | 无假成功（Validate 同步拒绝双路闭合；驱动吞错红线 design §15.5 在案） | PASS |
| 14.13–14.15 | 聚端口/派生口/方向想清 | distinct 排除 13400；方向 up/down 显式 | PASS |
| 14.16 | 全绿+落盘可复查 | 80/80 + 50 正例 pcap 落盘（102 文件：76 .pcap + 26 .neg.pcap） | PASS |
| 14.17 | 抽查 spec/字段/锚词 | p6-review(a)(b)(e) | PASS |
| 14.18 | 二进制与 HEAD 同代 | 门2-3 绿 | PASS |
| 14.19 | 全量全绿 | 80/80（非增量；P6 独立重跑 EXIT=0） | PASS |
| 14.20 | 包号/端口从 pcap 拿 | 先跑后钉（multiflow 2×9=18 逐包复算） | PASS |
| 15.1 | 门1 十四行表+证据 | p123-report §1 | PASS |
| 15.2 | 证据三选一；写不出=立项 | G-DOIP-1…9 在案 | PASS |
| 15.3 | §1/§3/§12 强制展开 | design §14.1/§14.3/§14.12（P6 契约入版） | PASS |
| 15.4 | 门2①顶层零残留 | 旧键绿；presence 黄=doip_neg_presence 负例本身（登记豁免） | PASS |
| 15.5 | 门2②全量绿+负例锚词 | 80/80 + 30 锚词（抽 5 机核） | PASS |
| 15.6 | 门2③二进制同代 | 绿 | PASS |
| 15.7 | 门2④反查绿后进 P6 | 60/60 绿（3c82df2 干净树；主分支 gbt32960 冲突致本机不可跑，与 doip 无关） | PASS(NOTE) |
| 15.8 | D-条目挂门1表（回填证据号） | design v3.0.0 §14 门1 表（P6 契约入版待落仓；落版后确认回填） | PASS(NOTE 入版) |
| 15.9 | 抽查三条点到行/例号 | p6-review(a) 三条均点行/例号 | PASS |
| 15.10 | 白话+三门证据 | p6-review §0 + (c)(d) | PASS |
| 15.11 | 任一门红停 | 门2 静态四项绿（exit 0）；P6 无打回项 | PASS |

## 注记（backlog，判定口径）

- **判定口径**：`GAP(A′…)` 类 = 覆盖未达但已按 testcase §8.2 A′/B′ 与 D-DOIP-1 立项承接，非打回项；P6 判词通过（无 P0/P1/M），三条已裁定项落实（①41-ID 对 80 实测以实测为准 ②a 翻译复用扁平 parse 准予偏离 ②b UDP 三键入册 + vin/eid/gid 不入册 ③G-DOIP-2 维持 open）。
- **G-DOIP-2（open 框架 backlog）**：UDP 三阶段链上不可达（47 例作废，115→80 收敛账见 p4 §2）；当前 UDP 三键在册但链级同步拒绝（validate_layers create 期 + layer_gen drive 期双路）；候选 A/B/C/D 未裁定，不挡 TCP 面。
- **G-DOIP-3（钉现状）**：激活拒绝路径 6 例负例钉现状（RC 0x00/01/04/05/07 + 0x11 无确认，锚取真实 validator 文案）。
- **G-DOIP-4（迁入计划）**：0x11 被拒收尾 schema 不可表达（单 ResponseCode），无用例，加字段不挡开工。
- **G-DOIP-8（默认不开）**：业务字段零动态（四元组动态走 ip/tcp 层，已有多流动态例 T-DOIP #15）；取证后可开。
- **G-DOIP-9（待确认）**：现网行为无实测证据，不写定论；确认方式三选一（design §13.1 路②，P6 契约入版）。
- **P6 契约入版（待办）**：v3.0.0 设计（2063 行）+ testcase v1.0.0（194 行）落仓内 `docs/protocol-designs/`；T-DOIP 41-ID 对齐若要求则另起重命名轮（enip 先例：以实测 80 例为准即可）。
- **离线执行器未纳入 doip**：离线路径游离键口径与 MCP 不一致，已回滚；MCP 套件为权威验收通道，非缺口。
- **NIC 路本轮未跑**：pcap 路全绿；NIC 路待补（同 enip 口径 NOTE）。
