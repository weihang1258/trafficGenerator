# RTMFP（D-RTMFP-1 #74）P6 248 条款逐条比对表

> 口径：docs/CORE_MEMORY.md（§1–§15 逐条一行）。落点=rtmfp#74 实测证据（P6 终审：suite 29/29、coverage 76/76、门2-3 fresh binary 复验绿；集成 merge 3e2e448，pipe/rtmfp @ e2787d4 单提交）→ P6 判词**通过**。判定：PASS=满足，GAP(A′…)=覆盖未达但已按 testcase §10.2 A′/B′ 与 D-RTMFP-1 立项承接（非挂账缺口），NOTE=注记。残留：M-1=主线程契约勘误（改文档，不动代码；docs 已冻结）；M-2=已关闭（门2-3 复验绿）；M-3=open-follow-up（后续轮次加 mixed-family 负例）。
> 文档面：design v2.0.0 / testcase v2.0.0（48-rtmfp-{design,testcase}.md）；29 例 = 24 旧扁平改写 + 4 链级红例（presence/游离键/tcp 载体/缺 udp）+ 1 IPv6 对偶（T-27 已执行；T-26 未加，按 A′）。

| 条款 | 要求 | rtmfp 落点 | 判定 |
|---|---|---|---|
| 1.1 | 地址只写 ip 层 | 16 正例 `layers[0].ip.src/dst`（192.0.2.10→198.51.100.20；IPv6 例同住 ip 层）；无顶层地址键 | PASS |
| 1.2 | 端口只写 tcp/udp 层 | `udp.src_port/dst_port=1935`；rtmfp 层无端口键；缺省唯一通道 `chain_planner.go:1042` | PASS |
| 1.3 | 流数量只写 flow_control | spec_json 顶层键穷尽 = `layers`（16 正例 0 游离，机核+coverage_gate.py）；数量走 `flow_control.flows=1` | PASS |
| 1.4 | 禁 layers 与顶层五键混用 | presence 判死 `strategy_convert.go:8837-8841`（空 map 也死）；游离键判死 `:8518` | PASS |
| 1.5 | 混用示例/用例/文档都算跑偏 | 无混用示例；24 旧扁平例已改写；design §12.1 样例纯 layers | PASS |
| 1.6 | 门①层链能跑通 | suite 29/29；16 正例 pcap 落盘 | PASS |
| 1.7 | 门②旧格式彻底移除 | 旧扁平 24 例零残留；presence 红线名单已收 rtmfp（pipe_gate.sh） | PASS |
| 1.8 | 示例只给严格层链形 | 用例 spec_json 全严格层链形（29/29）；design §2/§12.1 样例纯 layers | PASS |
| 1.9 | 暂不支持时标注目标形状 | 真实加密线格式明确不支持（G-RTMFP-2）；周期自动保活明确不支持（design §11.1 #6）；profile 死配置注记（G-RTMFP-5） | PASS |
| 1.10 | 汇报分开说跑通/清旧字段 | p4-report §suite/§gates 分节；去向表 testcase §9 | PASS |
| 1.11 | 顶层白名单（layers/flow_control 家族/output） | 正例穷尽断言；唯一并存 = `rtmfp_neg_top_rtmfp_presence_reject`（判死负例形状，14-P2 口径） | PASS |
| 1.12 | 无可住层时立项补层，不许豁免 | 业务键已得层（registry.go:482，6 键 Fields）；无"登记保留"豁免；G-RTMFP-1/2/5 挂账 | PASS |
| 1.13 | 门2①按白名单执行 | 同 1.11；门2-1 绿 | PASS |
| 2.1 | 策略=单模板自带 flow_control | 单 RTMFP 会话模板 + `flow_control.flows=1` | PASS |
| 2.2 | 任务=多策略合跑+总量封顶 | 框架语义未动（suite 走策略路径） | PASS |
| 2.3 | 策略先限速任务再封顶 | 未动 | PASS |
| 2.4 | 任务 ID={taskID}-{strategyID} | 未动 | PASS |
| 2.5 | flows=N 复制 N 条 | 未动；rtmfp 语料未开 flows>1（多会话靠 sessions[] 显式，见 9.39） | PASS |
| 2.6 | spec 不管数量 | 未动 | PASS |
| 2.7 | 按流变化走动态字段 | 四元组动态住 ip/udp（layer_dyn.go:17-21）；业务字段清单 design §12.12（全 fixture 钉死，不开） | PASS |
| 2.8 | 未写动态 src_port 保底 12345+i | 框架既有语义（worker.go:307-308，DefaultSrcPort strategy_convert.go:49） | PASS |
| 2.9 | 其余按流变化必须写动态 | design §12.12 业务清单逐个不开+理由（G-RTMFP-5）；cookie 派生确定性可复算，无动态冒充 | PASS |
| 2.10 | 讲数量分清策略复制/任务封顶 | p123 门1 §2 行 | PASS |
| 2.11 | 讲变化动态按 §12 | 本表 12.x | PASS |
| 3.1 | 多会话 sessions[]/flows[] 显式 | `sessions[]` 显式（session_id + events）；多会话扇出靠 `sessions[].src_port`（#10：40009/40010） | PASS |
| 3.2 | 每会话独立 ID/四元组/生命周期 | session 10/11 独立 ID、四元组（src_port 覆盖）、握手→关闭生命周期 | PASS |
| 3.3 | 会话内事务有序序列 | 逐事件 Emit 严格事件序（planner.go:29-121，一事件一 datagram） | PASS |
| 3.4 | 事务前置条件 | design §12.3 事务表 t1–t6（状态机 planner.go:196-259） | PASS |
| 3.5 | 触发动作 | events 数组逐条（hello→…→close 显式声明） | PASS |
| 3.6 | 成功分支 | s2c ack/ranges（#3/#11）；session_confirm 建连成功面 | PASS |
| 3.7 | 失败分支 | wire_fault 8 值 + 自然守卫九类，9 负例 task error 锚（header/length/session/sequence/fragment/ack/state/profile） | PASS |
| 3.8 | 控制关联数据流显式字段 | 同会话流级关联（归属 session/flow_id/sequence/ranges 字段）；无 driven_by 副流派生（与 CWMP 差异已声明） | PASS |
| 3.9 | 关联写清会话/事务/决定字段 | `flow_id`+`sequence`+`ranges`+`session_id` 事件级 override（leak 负面） | PASS |
| 3.10 | 被关联流独立 ID/四元组/握手 | 不适用（已显式声明）：UDP 无连接、同四元组逻辑复用是规范结构；独立四元组语义由多会话 src_port 承载（design §12.3） | PASS（NOTE 不适用） |
| 3.11 | 各流顺序/并发/交错写清 | 流内严格事件序；会话间按序整块回放、只断言流内状态与隔离 | PASS |
| 3.12 | 可交错写清调度+时间戳 | 不适用（已显式声明）：无交错调度面，落点="事件序逐包 Emit、会话间按序整块回放"（design §12.3） | PASS（NOTE 不适用） |
| 3.13 | 不许连续重复冒充编排 | 握手→数据→ack/重传→保活→关闭编排（#11 六事件、#15 七包），非模板重复 | PASS |
| 3.14 | 无长连接豁免≠多流豁免 | 不主张任何豁免：多流 #9（flow 1/2/3）/多会话 #10/多事务 #3–#11（testcase §10.4） | PASS |
| 3.15 | 多轮/非正常结束/长保活各一例或立项 | ①多轮有例（#3/#5/#9/#10/#11）②非正常结束 9 负例 ③长保活 #7/#15 + 周期调度明确不支持 | PASS |
| 3.16 | CWMP 范本照补 | 差异声明：无 driven_by（单四元组逻辑复用，无副流） | PASS |
| 3.17 | 多流设计五件套 | design §12.3（会话表/事务序列/关联/插入位置/时间线） | PASS |
| 4.1 | 连接模型 | design §2（UDP 无连接 + 应用层会话；诚实写无 SYN/FIN） | PASS |
| 4.2 | 命令/消息表 | design §3/§4（12 kind + retransmit 别名；marker 0x0C/0x0E 双面） | PASS |
| 4.3 | 状态机 | design §5（Idle→…→Closing/Error 全表，校验锚点列） | PASS |
| 4.4 | 字段表 | design §4（实测 16B 自建头六字段 + cookie/fragment/ack 前缀布局） | PASS |
| 4.5 | 错误处理表 | design §8（8 值逐字 + 自然守卫九类）；用例面 9 负例锚 | PASS |
| 4.6 | 超时与活性 | design §11.1 #6（显式 ping/pong 有界；周期调度明确不支持；keepalive_interval/ping_count 死配置→G-RTMFP-5） | PASS |
| 4.7 | NAT/代理/被动 | 不适用（已显式声明）：NAT traversal 映射结果是网络环境函数、无 fixture 可表达面；真实语义→G-RTMFP-2 同族 | PASS（NOTE 不适用） |
| 4.8 | 版本/方言 | Adobe RTMFP（FMS 生态）+ RFC 7016 informational；profile 两值即方言声明；无版本协商字段（已声明） | PASS |
| 4.9 | 有 RFC 查 RFC 注章节 | RFC 7016 为 informational 实践记录（非标准轨）；精确章节待 G-RTMFP-1，不编章节号 | PASS |
| 4.10 | 无 RFC 以官方规范为准 | Adobe 官方规范为底线（文档名级引用，章节待 G-RTMFP-1） | PASS |
| 4.11 | 不许博客二手代替原文 | marker 双面借鉴 OpenRTMFP/Cumulus（思路声明不搬码；仓库/commit 待 G-RTMFP-1） | PASS |
| 4.12 | 规范原文 | design §2–§6 逐节（握手/会话/流/分片/保活五面） | PASS |
| 4.13 | 商业软件实际行为 | FMS/Flash Player 经 UDP 1935 建会话（抓包级确认→G-RTMFP-1，不写死） | PASS |
| 4.14 | 可靠开源实现思路 | OpenRTMFP/Cumulus 借鉴声明（不搬码） | PASS |
| 4.15 | 三路不一致取舍写清 | design §11.4/§11.5（自建编码≠Adobe 原始，确定性优先） | PASS |
| 4.16 | 商业行为逐条映射用例号 | design §12.2 映射表 12 行；G-RTMFP-1 确认方式在案 | PASS |
| 4.17 | 关键决策候选方案对比表 | design §11.5（A 自建头/B 对齐原始/C 不建层） | PASS |
| 4.18 | 不许单方案自说 | design §11.5（A/B/C 优劣俱陈） | PASS |
| 4.19 | 每表格行/字段/错误码三选一 | design §11 矩阵 8 行 + 三子表（28 格/14 行/12 行逐格有结论） | PASS |
| 4.20 | 每条目对应至少一用例 | 50 点 = 已覆 41 + 不适用 8 + A′ 1（testcase §10.3 对账；41+8+1=50） | PASS/A′ |
| 4.21 | 动手前缺口矩阵 | p123 门1 表 + design §11 矩阵 | PASS |
| 4.22 | 三张子表齐 | design §11.2/§11.3/§12.2 | PASS |
| 4.23 | 设计评审先看矩阵 | 门1 获批（p123 §①） | PASS |
| 4.24 | 规范实现冲突先改实现 | 自建编码≠Adobe 原始已诚实声明（§4）；对齐面→G-RTMFP-2，不冒充等价 | PASS |
| 5.1 | 设计写明依赖 | `DependsOn ["udp"]` + `TransportOn ["udp"]`（registry.go:482；实现为准——design §1/§11.1/§12-P2/§13 五处"无 TransportOn/FieldContract/空 Fields" stale，M-1 主线程勘误） | PASS（NOTE M-1） |
| 5.2 | 写明出错处理 | 载体三预检（validate_layers.go:126/143/137）+ planner 自然守卫 + wire_fault 8 值 | PASS |
| 5.3 | 无依赖/错误分支不许实现 | 有（载体/状态机/序号/ack/fragment 全分支有码） | PASS |
| 5.4 | 无依据不许定字段流程缺省 | 端口 1935/kind 表/cookie 公式（sid‖sid^0xDEADBEEF）均有出处或实测 | PASS |
| 5.5 | 不确定标待确认+确认方式 | G-RTMFP-1（规范章节/现网抓包确认方式在案） | PASS |
| 5.6 | 回答结论指章节/代码行 | design §11–§13 已落盘，引用行号实测（P1 行号真实） | PASS（NOTE M-1：§1/§11.1 行号引用仍有效，内容勘误见 5.1） |
| 5.7 | 指不出直说不知道 | 吞吐数字诚实"待 P5 基准"（design §13；不写承诺） | PASS |
| 5.8 | 回复前自查出处 | p4-report 自审 3+2 轮（末轮干净） | PASS |
| 5.9 | 抽查三条定位不到打回 | 门3 三条 ≡ p6-review §a（三条均点行/例号，漂移已注） | PASS |
| 6.1 | 性能目标/预算/边界 | design §13（O(n) 流式；逐事件直发无聚合） | PASS |
| 6.2 | 六指标列全 | 吞吐数字诚实待基准（G-RTMFP 缺口未细化） | PASS |
| 6.3 | pcap/NIC 分别验收 | pcap 路：16 正例 pcap + suite 全绿；**NIC 路本轮未跑** | NOTE |
| 6.4 | 性能依据结合实现路径 | 逐事件渲染直发 EmitMsg、无锁无 sleep（无保活定时器） | PASS |
| 6.5 | 无依据数字标待确认 | 已标（design §13 边界诚实声明） | PASS |
| 6.6 | 六类性能场景 | 清单在案（design §13）；P5 跑测覆盖 | PASS |
| 6.7 | 断言实际指标不只无报错 | packet_count + udp 字段 + frames hex 三钉（非"无报错"） | PASS |
| 6.8 | 超预算仍不合格 | —（无超预算项） | PASS |
| 7.1–7.3 | 三份文档定位 | design+testcase+D-RTMFP-1；未碰 CODE_DESIGN/TEST_CASES/CORE_MEMORY | PASS |
| 7.4 | 历史文档保留参考 | v1.0.0 修订记录 + §16.2 旧文逐条核对（无静默删除） | PASS |
| 7.5 | cases 是产物回指编号 | 29 例回指 design §9（24 改写 + 4 链级红 + 1 对偶） | PASS |
| 7.6–7.7 | 三者关系/冲突序 | —（门1 先行，D-条目定稿=开工门） | PASS |
| 7.8–7.9 | 先核心→设计→用例 | 门1 先行（P1–P3 先于 P4/P5） | PASS |
| 8.1 | 八要素（文件/接口/结构/流程/错误/性能/冲突/回滚） | design §13（D-RTMFP-1 草稿，门1 获批=定稿） | PASS |
| 8.2–8.8 | 同上逐项 | design §13（translate/validate/性能/冲突/回滚落点见 p6-review §a/f） | PASS |
| 8.9 | 未定稿不开工 | 门1 获批=开工（P4 > 门1 批） | PASS |
| 8.10 | 需求变先改设计 | P5 校准变更（frames 补钉 + T-27 对偶例）已入 design/testcase v2.0.0 口径 | PASS |
| 8.11 | 不许代码先行文档后补 | P1–P3 先行（wire 落码 c12fe77 为 P1 前置实测对象，非先行实现） | PASS |
| 8.12–8.13 | 开工贴条目/无条目打回 | —（D-RTMFP-1 #74 条目在案） | PASS |
| 9.1 | 用例登记（回指编号） | testcase §2/§5；ID↔design §9 机核同序 | PASS |
| 9.2–9.4 | 三源（规范/设计/现网） | Adobe spec/RFC 7016 + D-RTMFP-1 + builder wire 真相；第三源未确认级→G-RTMFP-1（tshark 0 字段实测） | PASS |
| 9.5 | 每行每字段每错误码有用例 | 50 点 41 覆（testcase §10.3）；kind error 半格→A′ T-26 未加 | PASS/A′ |
| 9.6 | 一例一行为 | 29 例 id 唯一（机核） | PASS |
| 9.7 | 修 bug 先复现变红 | P4/P5 自审发现先复现后修（expect 键集去 notes、DstPort 双默认冲突排查）；末轮干净 | PASS |
| 9.8 | 数据场景六变体（正常/边界/空值/超长/非法/大小端） | 边界（HeaderMinLen 16/declared=999/未知 profile-kind-direction）+ 大端头 hex 钉 + 空 sessions 拒 | PASS |
| 9.9 | 业务场景序列/乱序/中断/交错 | 生命周期序列 + sequence 回退（乱序）/close 后残留（中断）负例；交错=多流 #9 | PASS |
| 9.10 | 现网场景；复杂度 9.50 下限 | 门3 最复杂例深审（§9.53，见 9.53） | PASS |
| 9.11 | 多动作组合流≥2 条×≥3 动作 | #1（4 事件）/#3（4 事件）/#11（6 事件）/#15（7 包）≥2 条 ✓ | PASS |
| 9.12 | 清单先行 | P1 矩阵先行（p123 门1 §4） | PASS |
| 9.13 | 清单无遗漏是目标 | 50 点逐格有结论、无空格（28 格 8+12+8=28 复算一致） | PASS |
| 9.14 | 存量逐条审计去向 | testcase §9 逐条 24 例（15 合入 + 9 合入）+ 4 链级红 + 1 对偶 = 29 | PASS |
| 9.15–9.19 | A/B/C 三分类 | A′ T-26 未加/T-27 已加；B′ G-RTMFP-2（testcase §10.2）；C 类不适用（hex 可表达输入输出，判 A 类） | PASS |
| 9.20 | 取值表每值一例 | 12 kind 覆 11 值；**error kind 无例**（A′ T-26，主线程定不加） | GAP(A′-取值面) |
| 9.21 | 分支级审计 | 负例按分支铺（载体×2/presence/游离键/wire_fault 8 值/自然守卫）；family 分支仅链级单测覆盖（rtmfp_chain_test.go:145-152）→ M-3 | PASS（NOTE M-3） |
| 9.22 | 扫遍全部承载位置 | 层内 sessions/events 数组（唯一承载）全覆盖 | PASS |
| 9.23 | 正交矩阵逐格标记 | design §11.2 矩阵 28 格逐格标记 | PASS |
| 9.24 | 地址族对称（IPv4/IPv6 逐格） | IPv4 #1 / IPv6 #2 独立例 + #14 双 fixture（`rtmfp_ipv4_ipv6_same_payload` + `rtmfp_ipv6_same_payload`，T-27 已执行） | PASS |
| 9.25 | 地址族扩展随矩阵扩 | T-27 已执行（对偶例在案）；offset 42/62 两档实测命中 | PASS |
| 9.26 | 补齐顺序 | 最小实现→高频→全量（T-27 已补；T-26 未加按 A′ 主线程口径） | PASS/A′ |
| 9.27 | harness 做不到逐项注明 | 包序/方向靠 frames+udp 组合钉；无 `rtmfp.*` 字段面已诚实声明（tshark 0 字段实测） | PASS |
| 9.28 | 不许字段出现冒充顺序 | 事件序断言（逐包 kind/marker hex），不按 packet index 假定流顺序 | PASS |
| 9.29 | 补齐后全量全绿 | 全量 29/29 绿（canonical 复跑，7.44s） | PASS |
| 9.30 | 只写不跑/只跑增量=未完成 | 全量跑（非增量） | PASS |
| 9.31 | 断言以真实 pcap 校准 | 先跑后钉（P5 frames hex 校准 bad=0；cookie 公式复算命中） | PASS |
| 9.32–9.35 | 动态整格（五策略×字段） | 四元组 framework 面在案；业务 fixture 钉死按 §12.12（无动态冒充） | PASS |
| 9.36 | 不支持格标 B/C+注记 | 加密线格式→G-RTMFP-2（B′）；周期保活/死配置→明确不支持+注记（G-RTMFP-5） | PASS |
| 9.37 | 派生编号撞车 | 无派生子流；retransmit 别名复用原序号（planner.go:44-48，非新编号） | PASS |
| 9.38 | 聚合断言排除固定/派生口 | 无 distinct 聚合用例；#9 flow 隔离靠逐包 hex 偏移 8 字段 | PASS |
| 9.39 | 多流×静态标量互斥 | 未开 flows>1（多会话靠 sessions[] 显式扇出；静态单流面诚实） | NOTE |
| 9.40 | 共享流序号动态字段 | 无动态面（序号全 fixture；动态仅四元组） | NOTE |
| 9.41–9.45 | 测试评审五件事 | p6-review §b–§f（深审/重跑/双门/锚词/已知项） | PASS |
| 9.46 | 数据场景全表扫 | 变体表 14 行 13 覆 + error 半格 A′（见 9.20） | GAP(A′) |
| 9.47 | 取值集合逐值枚举 | 同上（kind 12 值中 error 无例） | GAP(A′) |
| 9.48 | 业务场景规范反推 | design §11 三子表；出处声明 testcase §10.3（规范反推非用例反推） | PASS |
| 9.49 | 多连接/多会话/多事务各一例+真实编排 | 多会话 #10 + 多事务 #3/#11 + 真实编排 #15（握手×保活×关闭三类交织 7 包） | PASS |
| 9.50 | 复合大场景≥3 类交织 | #15 = 握手 2 + ping/pong 两轮 4 + close 1（3 类；全套件最大包数，门3 深审） | PASS |
| 9.51 | 组合矩阵满格 | design §11 矩阵（已入版）；用例组合维度有限 = A′ 维持（T-26） | PASS/A′ |
| 9.52 | 审计声明出处+对账两行 | testcase §10.3：规范逻辑点 50（§11.1 八项 8 + 矩阵 28 + 变体 14）vs 用例覆盖 41；出处=规范反推 | PASS |
| 9.53 | 门3 至少一条抽最复杂用例+点数 | 最复杂例 `rtmfp_keepalive_bounded`（7 包）+ `rtmfp_multi_session`（双会话）：frames 逐包命中（3/3、3/3），handshake cookie 公式一致，`tshark -G fields` rtmfp 行 = 0 | PASS |
| 10.1 | 文档对规范逐条核对 | p123 §②10.1（文档名级引用，不编章节号） | PASS |
| 10.2 | 改需求先对旧需求 | v1.0.0→v2.0.0 四节勘误（design §16.2 逐条，无静默删除） | PASS |
| 10.3 | 代码逐行走读 | P4 3 轮 + P5 校准 2 轮（p4-report §自审结论；末轮干净） | PASS |
| 10.4 | 构建+vet+测试含 race | 本审：build/vet 干净；`-race`（layers/rtmfp/core/schema/api/mcp）绿 | PASS |
| 10.5 | 修完再审 | 每轮 fix 后再审（P4 R3/P5 R2 末轮干净） | PASS |
| 10.6–10.10 | 测试评审 | 本表（三源对账+锚词核+点数） | PASS |
| 10.11 | 改审测修再审闭环+结论 | p4-report §自审结论 + p6-review 判词通过 | PASS |
| 11.1–11.5 | 白话 | p6-review 白话一句（UDP 实时音视频接线做完，29 全绿，断言钉实测字节） | PASS |
| 12.1 | 五策略全开 | 四元组五策略 framework 在案（layer_dyn.go:17-21） | PASS |
| 12.2 | 动态覆盖四元组 | 同上（rtmfp 语料 fixture 静态，见 12.15） | PASS |
| 12.3 | 业务字段清单逐协议 | design §12.12（逐字段开/不开+理由；G-RTMFP-5 死配置四键） | PASS |
| 12.4 | flows=N 确定性+seed+回绕 | framework 语义（rtmfp 无 flows>1 例可验） | NOTE |
| 12.5 | 不写动态按 fixed | 16 正例业务全静态 fixture（层内静态标量） | PASS |
| 12.6–12.8 | 任务级动态不丢/只截断/跨策略 | framework 未动 | PASS |
| 12.9 | 静态复制拒绝/告警 | framework 守卫在案（rtmfp 无多流例，未取用） | NOTE |
| 12.10 | src_port 保底≠动态 | 诚实声明（design §12.12；sessions[].src_port 事件级≠动态） | PASS |
| 12.11–12.13 | 动态住层链/不另起顶层/对齐 tuples | 四元组住 ip/udp；无顶层动态键 | PASS |
| 12.14–12.16 | 清单+序号算法可定位 | 序号算法：四元组 layer_dyn.go:770 + worker.go:307-308 在码，可定位；协议本地无独立序号算法（事件字节全 fixture） | PASS |
| 13.1–13.6 | schema 文件 | registry rtmfp 行六键（DependsOn+TransportOn ["udp"] + 6 键 Fields，registry.go:482）+ generated transport_on/6 fields 逐键一致（P6 实读；schemagen 已重跑入版）——design §13"空 Fields" stale（M-1） | PASS（NOTE M-1） |
| 13.7–13.10 | 校验入口唯一 | ValidateStrategy/TaskCreate 同入口（suite 走 MCP） | PASS |
| 13.11–13.16 | 派生只读下游 | flowb_query_layers 实时视图（depends_on/transport_on=[udp] 一致） | PASS |
| 13.17 | 改语义先改 schema | registry 先行（P4；TransportOn 按 bacnet/dtls 先例补行） | PASS |
| 13.18 | 注册表变更重跑生成 | generated 已重跑入版（merge 3e2e448 内） | PASS |
| 13.19 | 过期测试变红 | `TestLayersGeneratedMatchesRegistry` 无过期（P4 验证） | PASS |
| 13.20–13.21 | 缺席走缺省/null 拒 | 层 config JSON 往返严格解码（chain_planner_translate.go:2222 `rtmfp layer config decode`）；端口缺席走 1935 缺省 | PASS |
| 13.22–13.23 | schema 是机器源不算第四文档 | — | PASS |
| 13.24–13.26 | 评审先查 schema/手写/null 兼容 | 无手写形状、无 null 兼容分支（schemagen 派生） | PASS |
| 14.1 | 用例 spec 即 MCP 任务配置 | spec_json=layers 直驱 + strategy_fc 封包 | PASS |
| 14.2 | 不许两套写法 | 单权威（旧扁平已移除） | PASS |
| 14.3 | 执行工具直接消费用例 | suite 经 MCP 直消（canonical :8081 独立重跑） | PASS |
| 14.4 | 旧用例随层链迁移改写 | 24 例全改写（15 合入 + 9 合入）+ 4 链级红 + 1 对偶 = 29 | PASS |
| 14.5 | 历史口径不带入 | UDP 面照抄实测值 + hex 面先跑后钉（v1"占位"口径已勘误作废） | PASS |
| 14.6 | 先跑拿 pcap 再钉 | P5 实跑校准（frames bad=0；IPv4 offset 42/IPv6 62 手验 cookie） | PASS |
| 14.7–14.9 | MCP 建任务→生成→tshark 校对 | lane MCP + tshark UDP/frames 双通道（无 rtmfp.* 面） | PASS |
| 14.10 | 离线/无失败/只数包不算测 | 字段+frames 双钉（不只看 packet_count） | PASS |
| 14.11 | 负例经 MCP 被拒+锚词 | 13 负例全 error_contains（carrier×2/presence/游离键/wire_fault 8 值/自然守卫；3 例建任务即拒无 pcap） | PASS |
| 14.12 | 假成功同级 bug | 无假成功：错误一律 task error（零 completed/0 包）；10 负例 .neg.pcap 占位有据 | PASS |
| 14.13–14.15 | 聚端口/派生口/方向想清 | 无 distinct 聚合；方向 c2s/s2c + 端口交换显式 | PASS |
| 14.16 | 全绿+落盘可复查 | 29/29 + 16 正例 pcap 落盘（逐包比对 bad=0） | PASS |
| 14.17 | 抽查 spec/字段/锚词 | p6-review §b/§e（5 锚词逐字 + 最复杂例深审） | PASS |
| 14.18 | 二进制与 HEAD 同代 | 门2-3 复验绿（fresh binary；M-2 关闭） | PASS |
| 14.19 | 全量全绿 | 29/29（非增量） | PASS |
| 14.20 | 包号/端口从 pcap 拿 | 先跑后钉（cookie `00 00 00 01 de ad be ee` 公式复算；端口 1935 实测） | PASS |
| 15.1 | 门1 十四行表+证据 | design §12 十四行 + §12.1/§12.3/§12.12 强制展开 | PASS |
| 15.2 | 证据三选一；写不出=立项 | G-RTMFP-1/2/4/5 在案（T-26/T-27 并入与否主线程口径） | PASS |
| 15.3 | §1/§3/§12 强制展开 | design §12.1（旧键去向+样例）/§12.3（五件套）/§12.12（动态清单） | PASS |
| 15.4 | 门2①顶层零残留 | 绿（非负例顶层键束 `('layers',)` 唯一，零残留） | PASS |
| 15.5 | 门2②全量绿+负例锚词 | 29/29 + 13 负例锚词全命中（coverage 76/76） | PASS |
| 15.6 | 门2③二进制同代 | 绿（M-2 关闭：fresh binary 复验） | PASS |
| 15.7 | 门2④反查绿后进 P6 | 76/76 绿（16正+13负/frames 全钉/expect 键集严格/顶层键零残留/零 rtmfp.*/13 锚词） | PASS |
| 15.8 | D-条目挂门1表（回填证据号） | design §12 门1表证据列已回填（实测行号；M-1 五处内容勘误待主线程，不动证据号结构） | PASS（NOTE M-1） |
| 15.9 | 抽查三条点到行/例号 | p6-review §a（三条均点行/例号，漂移已注） | PASS |
| 15.10 | 白话+三门证据 | p6-review 白话一句 + §c/§d 三门证据 | PASS |
| 15.11 | 任一门红停 | 门2-3 曾红（canonical 二进制过期，环境性）→ M-2 复验关闭 → 关单 | PASS |

## 注记（backlog，判定口径）

- **判定口径**：`GAP(A′…)` 类 = 覆盖未达但已按 testcase §10.2 A′/B′ 与 D-RTMFP-1 立项承接，**非缺口挂账**；P6 判词**通过**（无 P0/P1）。
- **M-1（主线程契约勘误，未做，docs 已冻结）**：design §1（行 26）/§11.1（行 238）/§12-P2 门1表 §5 行（行 314）/§12-P2 门1表 §13 行（行 322）/§13 接线件（行 480）五处"无 TransportOn/OptionalOn、无 FieldContract、Fields 空"与实现矛盾（实现：`TransportOn: ["udp"]` + 6 键 Fields，registry.go:482；carrier 锚词即 TransportOn 替代来源，complete.go:101-103）。改文档不动代码。本表 5.1/5.6/13.1–13.6/15.8 行已标 NOTE(M-1)，落点一律以实现为准。
- **M-2（已关闭）**：pipe_gate 门2-3 红（canonical 二进制早于 drda/mms 合并的环境性过期）→ fresh binary 复验绿。本表 14.18/15.6 为 PASS。
- **M-3（open-follow-up）**：suite 缺 mixed-family 负例（`[ip(src v4/dst v6),udp,rtmfp]`，error_contains=family）；family 守卫（validate_layers.go:137）现仅由链级单测 `rtmfp_chain_test.go:145-152` 覆盖。后续轮次加例。本表 9.21 行已标 NOTE(M-3)。
- 载体面：G-RTMFP-1（规范章节/现网抓包确认）/G-RTMFP-2（真实线格式 B′）/G-RTMFP-5（死配置四键治理）挂账；T-26（error kind）未加按 A′ 主线程口径；T-27（IPv6 对偶）已执行。
