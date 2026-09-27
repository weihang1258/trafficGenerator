# ENIP（D-ENIP-1 #56）P6 248 条款逐条比对表

> 口径：docs/CORE_MEMORY.md（v15/481 行，2026-09-27 读）。落点=enip#56 实测证据（修后 canonical 复跑：suite 137/137、门2 静态四项、反查 49/49、-race 绿；scoped 复评独立复跑一致）+ P6 修轮（分支 `pipe/enip-p6fix` 集成 `3eb57ae`：C1/M1/m1/m2/m3/n3 关闭）→ scoped 复评关单。判定：PASS=满足，GAP(n)=缺口编号/判词编号（修轮前编号，现均关闭，除显式 open 缺口外），NOTE=注记。
> 文档面（修轮后更新）：design v2.1.1（3053 行）/ testcase v1.0.1（318 行）已入版（`7e994ac`/`6ea037e`）；"增量丢失"经机核证伪（备份=基线+完整增量，缺失清单=空）；M1 关闭。凡"落点=design §12–§17 / testcase §x"的行现指仓内实文件。

| 条款 | 要求 | enip 落点 | 判定 |
|---|---|---|---|
| 1.1 | 地址只写 ip 层 | 137 例 `layers[i].ip.src/dst`（10.0.0.1→20.0.0.1）；无顶层地址键 | PASS |
| 1.2 | 端口只写 tcp/udp 层 | `tcp.src_port=12345/dst_port=44818`；enip 层 FieldContract 补 44818 缺省 | PASS |
| 1.3 | 流数量只写 flow_control | spec_json 顶层键穷尽 = `layers`（正例 0 游离，机核+coverage_gate.py:1953） | PASS |
| 1.4 | 禁 layers 与顶层五键混用 | 门2-1 绿（无顶层旧键残留）；链例 `enip_chain_test.go:219-248` 五键+MAC 判死 | PASS |
| 1.5 | 混用示例/用例/文档都算跑偏 | 无混用示例；design v2.1.1（已入版）样例为纯 layers | PASS |
| 1.6 | 门①层链能跑通 | suite 137/137（canonical 8081 复跑）；pcap 82 正例齐落盘 | PASS |
| 1.7 | 门②旧格式彻底移除 | 重锚 6 例实证（v005/v006/t104/t105/t117/t118）；presence 判死两路（strategy_convert.go:8666-8670/:435-442） | PASS |
| 1.8 | 示例只给严格层链形 | 用例 spec_json 全严格层链形（137/137） | PASS |
| 1.9 | 暂不支持时标注目标形状 | 三支拒绝（io_data/udp/多单元）+ notes 披露（B 12/C 10 逐例） | PASS |
| 1.10 | 汇报分开说跑通/清旧字段 | p4-report §2/§3 分节 | PASS |
| 1.11 | 顶层白名单（layers/flow_control 家族/output） | 正例穷尽断言；唯一并存 = `enip_neg_presence`（判死负例形状，14-P2 口径） | PASS |
| 1.12 | 无可住层时立项补层，不许豁免 | 业务六键已得层（registry.go:229-240）；无"登记保留"豁免 | PASS |
| 1.13 | 门2①按白名单执行 | 同 1.11；黄行措辞见 m2 | PASS(NOTE m2) |
| 2.1 | 策略=单模板自带 flow_control | `strategy_fc` 在案（14 例显式 flows=1，其余缺省） | PASS |
| 2.2 | 任务=多策略合跑+总量封顶 | 框架语义未动（suite 走策略路径） | PASS |
| 2.3 | 策略先限速任务再封顶 | 未动 | PASS |
| 2.4 | 任务 ID={taskID}-{strategyID} | 未动 | PASS |
| 2.5 | flows=N 复制 N 条 | 未动；enip 语料未开 flows>1（见 9.50） | PASS |
| 2.6 | spec 不管数量 | 未动 | PASS |
| 2.7 | 按流变化走动态字段 | 四元组动态住 ip/tcp（layer_dyn.go:17-21）；enip 业务字段未开（G-ENIP-4） | NOTE(G4) |
| 2.8 | 未写动态 src_port 保底 12345+i | 框架既有语义 | PASS |
| 2.9 | 其余按流变化必须写动态 | design §14.12 业务清单（已入版）；业务动态零开=立项维持（G-ENIP-4） | PASS/A′ |
| 2.10 | 讲数量分清策略复制/任务封顶 | p123 门1 §2 行 | PASS |
| 2.11 | 讲变化动态按 §12 | 本表 12.x | PASS |
| 3.1 | 多会话 sessions[]/flows[] 显式 | enip 无 sessions[] 结构（多会话展开 = G-ENIP-1 拒）；多流面 = framework flows（修轮 C1 复合例 t180） | PASS |
| 3.2 | 每会话独立 ID/四元组/生命周期 | 单载体链内会话生命周期有例（listidentity/registersession_session_state） | PASS |
| 3.3 | 会话内事务有序序列 | 3 命令有序（0x63→0x65→0x66；Report 同款），`initial_seq` 钉死 | PASS |
| 3.4 | 事务前置条件 | design §14.3 五件套（已入版）；from_response 依赖显式 | PASS |
| 3.5 | 触发动作 | 命令数组逐条（t172/t173 from_response 族） | PASS |
| 3.6 | 成功分支 | 响应 down 命令注入（t174/t175） | PASS |
| 3.7 | 失败分支 | `enip_error_response_status`（CIP 0x0E）；负例 55 例 task error 锚 | PASS |
| 3.8 | 控制关联数据流显式字段 | 同连接协议：from_response{session_handle/o2t/t2o/conn_serial} 三类引用在案 | PASS |
| 3.9 | 关联写清会话/事务/决定字段 | `source_command_index`+`from_response_field` 双字段（enip_chain_test.go:109-134 字节钉） | PASS |
| 3.10 | 被关联流独立 ID/四元组/握手 | 无副流（单载体），不适用（G-ENIP-1 同源） | PASS |
| 3.11 | 各流顺序/并发/交错写清 | 流内严格顺序断言（命令 i+1 恒在 i 后，t179 notes） | PASS |
| 3.12 | 可交错写清调度+时间戳 | 无交错面（单流） | PASS |
| 3.13 | 不许连续重复冒充编排 | 生命周期编排（发现→注册→注销；请求→响应→引用）非模板重复 | PASS |
| 3.14 | 无长连接豁免≠多流豁免 | 单包多载荷 = `enip_multiple_service_packet`（MSP 2 子请求）；**多流并发仅剩负例**（C 类）→ 契约 §6.3 旧表述 stale（n2） | NOTE(n2) |
| 3.15 | 多轮/非正常结束/长保活各一例或立项 | ①有例（listidentity/registersession/MSP）②半程 → G-ENIP-7 ③有例（`enip_nop_heartbeat`） | PASS |
| 3.16 | CWMP 范本照补 | 差异声明：无 driven_by（单载体无副流） | PASS |
| 3.17 | 多流设计五件套 | design §14.3（已入版）；修轮 C1 复合例落多流面 | PASS |
| 4.1 | 连接模型 | design §2 行（TCP 44818 单载体，命令即数据段） | PASS |
| 4.2 | 命令/消息表 | design §2.2（10 行）/§2.5（服务码三表） | PASS |
| 4.3 | 状态机 | design §4.1/4.2/4.3（命令推导） | PASS |
| 4.4 | 字段表 | design §2.1/§2.4/§2.7 + §3.x 结构表 | PASS |
| 4.5 | 错误处理表 | design §2.3/§2.3.1/§2.3.2 + §9.1/§9.2；用例面 55 负例锚 | PASS |
| 4.6 | 超时与活性 | design §6.16（S15 心跳）；`timeout_multiplier` 边界例在案 | PASS |
| 4.7 | NAT/代理/被动 | 明确不解决（B′ 登记：无面）；G-ENIP-5 待核对 | PASS |
| 4.8 | 版本/方言 | design §2.2/§2.5.3；G-ENIP-6（Logix/PCCC 零断言） | GAP(6) |
| 4.9 | 有 RFC 查 RFC 注章节 | 无 RFC：ODVA CIP Vol.1/Vol.2 + Rockwell 出版物（design §13 头注） | PASS |
| 4.10 | 无 RFC 以官方规范为准 | 同上（章节级落点 design §2–§4） | PASS |
| 4.11 | 不许博客二手代替原文 | p123 §②10.1 逐条回指规范表行 | PASS |
| 4.12 | 规范原文 | design §2–§4 逐表（317 逻辑点口径见 9.52） | PASS |
| 4.13 | 商业软件实际行为 | Rockwell ENET-AT002E-EN-P/ENET-UM006/471230（design §13.1） | PASS |
| 4.14 | 可靠开源实现思路 | OpENer/libplctag 借鉴声明（不搬码） | PASS |
| 4.15 | 三路不一致取舍写清 | design §13.1（UDP/IO 面取舍） | PASS |
| 4.16 | 商业行为逐条映射用例号 | design §13.2 映射表（已入版）；G-ENIP-5/6 确认方式在案 | PASS |
| 4.17 | 关键决策候选方案对比表 | design v2.1.1 §13.3（已入版） | PASS |
| 4.18 | 不许单方案自说 | design v2.1.1 §13.3（已入版） | PASS |
| 4.19 | 每表格行/字段/错误码三选一 | design v2.1.1 §12 矩阵 8 行+三子表（已入版）；用例面 137 例承接 | PASS |
| 4.20 | 每条目对应至少一用例 | 110 T 命中 + 122 缺口逐个去向（A′/B′ 立项维持） | PASS/A′ |
| 4.21 | 动手前缺口矩阵 | p123 门1 表 + design §12 矩阵 | PASS |
| 4.22 | 三张子表齐 | design v2.1.1 §12（已入版） | PASS |
| 4.23 | 设计评审先看矩阵 | 门1 获批（p123 §①） | PASS |
| 4.24 | 规范实现冲突先改实现 | Forward_Close Reserved 字节修复（056edb0 前史）+ P5 按实修重锚 | PASS |
| 5.1 | 设计写明依赖 | `DependsOn ["tcp"]`（registry.go:230）+ design §15 5.x（v2.1.1 已入仓） | PASS |
| 5.2 | 写明出错处理 | 三支同步预检（validate_layers.go:550-587）+ drive 期错误（worker.go:421） | PASS |
| 5.3 | 无依赖/错误分支不许实现 | 有 | PASS |
| 5.4 | 无依据不许定字段流程缺省 | 端口 44818/命令表/服务码均有 ODVA 出处 | PASS |
| 5.5 | 不确定标待确认+确认方式 | G-ENIP-5/6 在案 | PASS |
| 5.6 | 回答结论指章节/代码行 | design §12–§17 已入版，引用不再断链（M1 关闭） | PASS |
| 5.7 | 指不出直说不知道 | 吞吐数字诚实"待 P5 基准"（design §15 8.6） | PASS |
| 5.8 | 回复前自查出处 | p4-report §5 自审 3+2 轮 | PASS |
| 5.9 | 抽查三条定位不到打回 | 门3 三条 ≡ p6-review §2（三条均点行/例号） | PASS |
| 6.1 | 性能目标/预算/边界 | design v2.1.1 §15（已入版）；O(n) 流式 | PASS |
| 6.2 | 六指标列全 | 吞吐数字诚实待基准（G-ENIP 缺口未细化） | PASS |
| 6.3 | pcap/NIC 分别验收 | pcap 路：82 正例 pcap + suite 全绿（canonical 复跑）；**NIC 路本轮未跑** | NOTE |
| 6.4 | 性能依据结合实现路径 | 逐命令构建、EmitMsg 事件流、无锁（layer_gen.go 头注） | PASS |
| 6.5 | 无依据数字标待确认 | 已标 | PASS |
| 6.6 | 六类性能场景 | 清单在案；P5 未跑基准 | NOTE |
| 6.7 | 断言实际指标不只无报错 | packet_count 81 例 + 字段/frames 双钉 | PASS |
| 6.8 | 超预算仍不合格 | — | PASS |
| 7.1–7.3 | 三份文档定位 | design+testcase+D-ENIP-1；未碰 CODE_DESIGN/TEST_CASES | PASS |
| 7.4 | 历史文档保留参考 | — | PASS |
| 7.5 | cases 是产物回指编号 | 137 例回指 design §7 T 号（111 命中/121 缺口登记，复评机核） | PASS |
| 7.6–7.7 | 三者关系/冲突序 | — | PASS |
| 7.8–7.9 | 先核心→设计→用例 | 门1 先行（P1–P3 先于 P4/P5） | PASS |
| 8.1 | 八要素（文件/接口/结构/流程/错误/性能/冲突/回滚） | design v2.1.1 §15 8.1–8.8（已入版）；实现面逐件在码 | PASS |
| 8.2–8.8 | 同上逐项 | design §15（已入版）；translate/validate/backfill/types 落点见 p6-review §2 | PASS |
| 8.9 | 未定稿不开工 | 门1 获批=开工（P4 08:13 > 门1 批） | PASS |
| 8.10 | 需求变先改设计 | P5 重锚清单 design §14.13（已入版） | PASS |
| 8.11 | 不许代码先行文档后补 | P1–P3 先行 | PASS |
| 8.12–8.13 | 开工贴条目/无条目打回 | — | PASS |
| 9.1 | 用例登记（回指编号） | testcase 契约 §2/§5；ID↔design §7 机器对账（本审 §1） | PASS |
| 9.2–9.4 | 三源（规范/设计/现网） | ODVA+Rockwell+tshark 99 字段（testcase §6.3 行2） | PASS |
| 9.5 | 每行每字段每错误码有用例 | 111/232 命中（t180 落 T-180/179/217）；缺口逐个去向（A′/B′ 立项维持） | PASS/A′ |
| 9.6 | 一例一行为 | 137 例无重复 id（机核） | PASS |
| 9.7 | 修 bug 先复现变红 | T-115 假绿复现例实红（p6-review §6）；P5 R1 五例重锚不伪造绿 | PASS |
| 9.8 | 数据场景六变体（正常/边界/空值/超长/非法/大小端） | 边界例族（t121/124/125/127/129/131-142/144-160）+ 非法 55 负例 | PASS |
| 9.9 | 业务场景序列/乱序/中断/交错 | 生命周期序列 + from_response 族；乱序/中断 = G-ENIP-7 | PASS |
| 9.10 | 现网场景；复杂度 9.50 下限 | 修轮 C1 复合例 t180 达下限（多流×多事务×异常 3 类） | PASS |
| 9.11 | 多动作组合流≥2 条×≥3 动作 | listidentity（3 命令）/t173（3 命令）≥2 条 ✓ | PASS |
| 9.12 | 清单先行 | P1 矩阵先行（p123 门1 §4） | PASS |
| 9.13 | 清单无遗漏是目标 | 122 缺口登记在案 | PASS |
| 9.14 | 存量逐条审计去向 | testcase §5 逐条 135 例（A69/B12/C10/D44）＋presence/t180 净增 2 例=137，与复评机核一致 | PASS |
| 9.15–9.19 | A/B/C 三分类 | B 12/C 10/D 44 逐例 notes 披露（机核 G-ENIP-1 ×12 / G-ENIP-2 ×10） | PASS |
| 9.20 | 取值表每值一例 | 命令码/服务码/状态码**未逐值**：CIP 服务码余 24 值、CM 扩展状态 20 值零例（A′） | GAP(A′-取值面) |
| 9.21 | 分支级审计 | 负例按分支铺（tc/class/rpi/reserved/…） | PASS |
| 9.22 | 扫遍全部承载位置 | 层内命令数组（唯一承载）全覆盖 | PASS |
| 9.23 | 正交矩阵逐格标记 | design §12 矩阵（已入版） | PASS |
| 9.24 | 地址族对称（IPv4/IPv6 逐格） | **IPv6 0 例**（A′ 未补；链可构建性待实跑） | GAP(A′-IPv6) |
| 9.25 | 地址族扩展随矩阵扩 | 标缺口立项未做（IPv6 面 B′ 未列） | NOTE |
| 9.26 | 补齐顺序 | 最小实现→高频→全量（A′ 未执行） | NOTE |
| 9.27 | harness 做不到逐项注明 | 包序/方向靠 frames+字段组合钉（tshark 面） | PASS |
| 9.28 | 不许字段出现冒充顺序 | packets 级命令序断言（enip.command 逐包） | PASS |
| 9.29 | 补齐后全量全绿 | 全量 137/137 绿（canonical 复跑＋复评独立复跑） | PASS |
| 9.30 | 只写不跑/只跑增量=未完成 | 全量跑 | PASS |
| 9.31 | 断言以真实 pcap 校准 | 先跑后钉（P5 五例实跑重锚；包号基准来自落盘 pcap） | PASS |
| 9.32–9.35 | 动态整格（五策略×字段） | 四元组 framework 面在案；修轮后 t180 含动态 src_port 对象；业务动态面维持立项（G-ENIP-4） | PASS/A′ |
| 9.36 | 不支持格标 B/C+注记 | C 10 例 G-ENIP-2 注记 ✓；D 类 3 例（t108/109/110→io_data+G-ENIP-2 披露）+ t117/118（0 包锚+G-ENIP-8 披露）notes 已对齐实锚（修轮 m1） | PASS |
| 9.37 | 派生编号撞车 | 无派生子流面 | PASS |
| 9.38 | 聚合断言排除固定/派生口 | 无 distinct 聚合用例 | PASS |
| 9.39 | 多流×静态标量互斥 | 修轮 C1 复合例按口径交付（flows=2 + tcp.src_port 动态 inc + group_id fixed） | PASS |
| 9.40 | 共享流序号动态字段 | 无动态面 | NOTE |
| 9.41–9.45 | 测试评审五件事 | 本报告 §1–§4 | PASS |
| 9.46 | 数据场景全表扫 | 字段边界例族在案；命令码/服务码值域未全（见 9.20） | GAP(A′) |
| 9.47 | 取值集合逐值枚举 | 同上（响应码/错误码表未逐值） | GAP(A′) |
| 9.48 | 业务场景规范反推 | design §12 三子表（已入版）；出处声明 testcase §6.3 | PASS |
| 9.49 | 多连接/多会话/多事务各一例+真实编排 | 多事务 ✓ + 多流 ✓（修轮 C1 复合例 t180：flows=2）；真实编排（会话内多事务×多流×异常） | PASS |
| 9.50 | 复合大场景≥3 类交织 | 修轮 C1 复合例 `enip_t180_multiflow_txn_error_branch` = 多流×多事务×异常 **3 类** 达下限 | PASS |
| 9.51 | 组合矩阵满格 | design §12 矩阵（已入版）；用例面组合维度有限=A′ 维持 | PASS/A′ |
| 9.52 | 审计声明出处+对账两行 | testcase §6.3：规范逻辑点 317（§2 163+§3 52+§4 14+§6 15+§8 55+§9 18） vs 用例覆盖 137（135+presence+t180）；出处=规范反推非用例反推 | PASS |
| 9.53 | 门3 至少一条抽最复杂用例+点数 | 修轮后最复杂例 t180：20 包、20 fields + 4 frames；scoped 复评复核关单 | PASS |
| 10.1 | 文档对规范逐条核对 | p123 §②10.1 | PASS |
| 10.2 | 改需求先对旧需求 | p123 §②10.2（v2.0.1 结论原样保留） | PASS |
| 10.3 | 代码逐行走读 | P4 3 轮 + P5 2 轮（p4-report §5）；本审复核 T-115/预检/解码 | PASS |
| 10.4 | 构建+vet+测试含 race | 本审：build/vet 干净；`-race` 链例 9/9 绿；enip 包测试绿 | PASS |
| 10.5 | 修完再审 | 每轮 fix 后再审（P4 R3/P5 R2 末轮干净） | PASS |
| 10.6–10.10 | 测试评审 | 本报告（三源对账+锚词核+点数） | PASS |
| 10.11 | 改审测修再审闭环+结论 | p4-report §5 在案 | PASS |
| 11.1–11.5 | 白话 | p123 §⑥/p4-report + 本报告 §10 | PASS |
| 12.1 | 五策略全开 | 四元组五策略 framework 在案（layer_dyn.go:17-21） | PASS |
| 12.2 | 动态覆盖四元组 | 同上（enip 语料未取用，见 12.15） | PASS |
| 12.3 | 业务字段清单逐协议 | design §14.12（v2.1.1 已入仓，M1 关闭）；G-ENIP-4 登记业务字段未开 | PASS |
| 12.4 | flows=N 确定性+seed+回绕 | framework 语义（enip 无动态例可验） | NOTE |
| 12.5 | 不写动态按 fixed | 137 例全静态（层内静态标量；t180 四元组动态属 §12 面） | PASS |
| 12.6–12.8 | 任务级动态不丢/只截断/跨策略 | framework 未动 | PASS |
| 12.9 | 静态复制拒绝/告警 | framework 守卫在案（enip 无多流例，未取用） | NOTE |
| 12.10 | src_port 保底≠动态 | 诚实声明（design §14.12） | PASS |
| 12.11–12.13 | 动态住层链/不另起顶层/对齐 tuples | 四元组住 ip/tcp；无顶层动态键 | PASS |
| 12.14–12.16 | 清单+序号算法可定位 | 序号算法：四元组 layer_dyn + SenderContext（layer_gen.go:95-96 声明 / :145 消费 / :169 递增）在码，可定位；业务动态面维持立项（G-ENIP-4） | PASS/A′ |
| 13.1–13.6 | schema 文件 | registry enip 行六键 + FieldContract 44818；generated json:603-630 **逐键一致**（本审机核；未跑 schemagen） | PASS |
| 13.7–13.10 | 校验入口唯一 | ValidateStrategy/TaskCreate 同入口（suite 走 MCP） | PASS |
| 13.11–13.16 | 派生只读下游 | flowb_query_layers 实时视图 | PASS |
| 13.17 | 改语义先改 schema | registry 先行（P4） | PASS |
| 13.18 | 注册表变更重跑生成 | generated 已重跑入版（merge 内） | PASS |
| 13.19 | 过期测试变红 | `go test ./internal/core/schema/ -run TestLayersGenerated` = ok（本审） | PASS |
| 13.20–13.21 | 缺席走缺省/null 拒 | 严格解码：ENIPConfig/ENIPCommand `DisallowUnknownFields`（types.go:10153/10169） | PASS |
| 13.22–13.23 | schema 是机器源不算第四文档 | — | PASS |
| 13.24–13.26 | 评审先查 schema/手写/null 兼容 | 无手写形状、无 null 兼容分支 | PASS |
| 14.1 | 用例 spec 即 MCP 任务配置 | spec_json=layers 直驱 + strategy_fc 封包（14 例） | PASS |
| 14.2 | 不许两套写法 | 单权威 | PASS |
| 14.3 | 执行工具直接消费用例 | suite 经 MCP 直消（本审重跑） | PASS |
| 14.4 | 旧用例随层链迁移改写 | 135 例全改写（A/B/C/D 四类）+1 presence +1 复合例=137 | PASS |
| 14.5 | 历史口径不带入 | 包号 +3 重校、断言面重建（frames 77 例） | PASS |
| 14.6 | 先跑拿 pcap 再钉 | P5 实跑重锚五例；本审复跑产出新 pcap（10:12） | PASS |
| 14.7–14.9 | MCP 建任务→生成→tshark 校对 | lane6 MCP 18102 + tshark 字段/frames 双通道 | PASS |
| 14.10 | 离线/无失败/只数包不算测 | 字段+frames 双钉（不只看 packet_count） | PASS |
| 14.11 | 负例经 MCP 被拒+锚词 | 55 负例全 error_contains（55 例 40 种，复评机核；t117/t118 0 包锚已披露 G-ENIP-8） | PASS |
| 14.12 | 假成功同级 bug | 无假成功：0 包锚 = task error（worker.go:421）；G-ENIP-8 留缺口 | PASS |
| 14.13–14.15 | 聚端口/派生口/方向想清 | 无 distinct 聚合；方向 up/down 显式 | PASS |
| 14.16 | 全绿+落盘可复查 | 137/137 + 82 正例 pcap 落盘（neg 24B 占位有据；t180 20 包 tshark 逐点核） | PASS |
| 14.17 | 抽查 spec/字段/锚词 | 本报告 §1/§2 | PASS |
| 14.18 | 二进制与 HEAD 同代 | 门2-3 绿（lane6 二进制与 HEAD 同代） | PASS |
| 14.19 | 全量全绿 | 137/137（非增量） | PASS |
| 14.20 | 包号/端口从 pcap 拿 | 先跑后钉（t115 端口域实红佐证） | PASS |
| 15.1 | 门1 十四行表+证据 | p123-report §① | PASS |
| 15.2 | 证据三选一；写不出=立项 | G-ENIP-1…7 在案 | PASS |
| 15.3 | §1/§3/§12 强制展开 | design §14.1/§14.3/§14.12（已入版） | PASS |
| 15.4 | 门2①顶层零残留 | 旧键绿；presence 红线已接（pipe_gate.sh:97 名单含 enip，复评实测「无顶层 enip presence 残留」绿，m2 关闭） | PASS |
| 15.5 | 门2②全量绿+负例锚词 | 137/137 + 55 锚词 40 种（复评机核） | PASS |
| 15.6 | 门2③二进制同代 | 绿 | PASS |
| 15.7 | 门2④反查绿后进 P6 | 48/48 绿 | PASS |
| 15.8 | D-条目挂门1表（回填证据号） | design v2.1.1 §14 门1 表证据号已回填（复评抽 3 条全中＋加查 6 处；worker.go 行号勘误 v2.1.2 回正） | PASS |
| 15.9 | 抽查三条点到行/例号 | p6-review §2（三条均点行/例号） | PASS |
| 15.10 | 白话+三门证据 | p6-review §4/§10 | PASS |
| 15.11 | 任一门红停 | 门2 静态四项绿（exit 0）；C1 由 9.53 判出 | PASS |

## 注记（backlog，判定口径）

- **判定口径（修轮后）**：`GAP(A′…)`/`GAP(6)` 类 = 覆盖未达但已按 testcase §6.2 A′/B′ 与 D-ENIP-1 立项承接，**非缺口挂账**；本轮打回项 **C1（9.50/9.53）**、修轮项 m1/m2/m3、入版项 M1 **均已关闭**（集成 `3eb57ae`，scoped 复评关单）。
- **C1（打回级，已关闭）**：修法照做——`enip_t180_multiflow_txn_error_branch`（flows=2 + 动态 src_port + 3 命令含 status=0x0064 down 响应）交付，137/137 全量重跑（lane6 ×3 + canonical）。
- **M1（入版级，已关闭）**：testcase 契约 + design v2.1.1 增量（§11.3+§12–§17）双文档已入仓；「磁盘丢失」经复评机核**证伪**——备份用扁平文件名（`docs_protocol-designs_*`），前 2666 行与库内 v2.0.1 逐行一致＋全量增量；门1 表证据号已回填（行号勘误 v2.1.2 回正）。
- **m1（已关闭）**：t108/t109/t110/t117/t118 五例 notes 已与实锚对齐（复评逐条核实）。
- **m2（已关闭）**：`pipe_gate.sh` `_pres_key` 已收 enip（:97 名单），presence 行实测绿。
- **m3（已关闭）**：`coverage_gate.py:1904-1907` 已改 `A and B and C`（复评删支模拟：旧式假绿复现、新式正确红）。
- 载体面：G-ENIP-1/2/4/5/6/7/8 挂账（D-ENIP-1 迁入计划）；T 缺口 122 个（A′/B′）。
