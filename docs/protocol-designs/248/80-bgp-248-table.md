# D-BGP-1 #80 bgp P6 248 条款逐条比对表

> 口径：docs/CORE_MEMORY.md。落点=bgp#80 实测证据（HEAD `11c509f`：suite 43/43、门2 静态四项绿、反查 59/59、-race 三包绿；P6 隔离独立复跑一致：116 断言 pin 逐字节全中 + 7 负例锚词实测探针三方闭合）+ P6 判词（通过，0 C / 3 M / 5 m；M 全为文档回填项，代码/用例/字节三层全绿）。判定：PASS=满足，GAP(n)=缺口编号/判词编号，NOTE=注记（含观察项），PASS/A′=覆盖未达但已按 testcase §6.2 A′/B′ 与 D-BGP-1 立项承接（非挂账）。
> 文档面（P6 时点，M1/M2/M3 待主线程回填）：design v1.0.0（509 行）/ testcase v1.0.0（179 行）仍写 P1–P3 时点证据号；M1：`registry.go:1012→1081-1105` 漂移 + 11→13 键 + `chain_planner 598-629→614-641`；M2：testcase `builder.go` 行号 +34 漂移（`BuildOpen :261→:295` 等，planner/layer_gen 未漂移）；M3：testcase §2 补登 5 条新负例（38→43 ID）。凡"落点=design §x / testcase §y"的行指仓内实文件（行号以 P6 HEAD 实测为准）。

| 条款 | 要求 | bgp 落点 | 判定 |
|---|---|---|---|
| 1.1 | 地址只写 ip 层 | 20 正例 `layers[i].ip.src/dst`（T8 住 IPv6 字面）；无顶层地址键（门2-1 绿 + 反查正例顶层键=0） | PASS |
| 1.2 | 端口只写 tcp 层 | `tcp.src_port` + 契约补 `tcp.dst_port=179`（`registry.go:1081-1105` FieldContract，M1 回填；写作时 `:1012`）；层显式值优先实测（5000 赢契约） | PASS(NOTE M1) |
| 1.3 | 流数量只写 flow_control | spec_json 正例顶层键穷尽 = `layers`（×20）+ `group_id`×1（#16 多流框架键，enip/h323 先例豁免）；数量只走 `flow_control.flows` | PASS |
| 1.4 | 禁 layers 与顶层五键混用 | 门2-1 绿（无顶层旧键残留）；链例 `bgp_chain_test.go` 7 函数 + `CheckProtoFlat` bgp presence 分支判死 | PASS |
| 1.5 | 混用示例/用例/文档都算跑偏 | 无混用示例；43 例 spec_json 全严格层链形 | PASS |
| 1.6 | 门①层链能跑通 | suite 43/43（lane12 + P6 独立复跑 15.24s 一致）；pcap 20 正例齐落盘 | PASS |
| 1.7 | 门②旧格式彻底移除 | 存量 19/19 全改写 `[ip,tcp,bgp]` 纯层链（旧 `[tcp,bgp]` 空层链 + 顶层四元组 + 顶层 bgp 子映射清零）；presence 判死两路（空子映射亦死） | PASS |
| 1.8 | 示例只给严格层链形 | 用例 spec_json 全严格层链形（43/43）；目标形状 design §2.1 | PASS |
| 1.9 | 暂不支持时标注目标形状 | `events`/`sessions` 进层今日跑不通按 §1.9 标注（design §2.1 P4 门标注；G-BGP-5/6/7 登记） | PASS |
| 1.10 | 汇报分开说跑通/清旧字段 | p4-report §12.1（旧键去向表逐键计数）/ §8（存量审计）分节 | PASS |
| 1.11 | 顶层白名单（layers/flow_control 家族/output） | 正例穷尽断言；唯一并存 = `bgp_neg_presence_top_level_bgp`（判死负例形状：层链+顶层空子映射并存，14-P2 口径） | PASS |
| 1.12 | 无可住层时立项补层，不许豁免 | `events`/`sessions` 已得层（registry 增键 + nil Default 二态可区分；无"登记保留"豁免） | PASS |
| 1.13 | 门2①按白名单执行 | 同 1.11；黄行 = presence 负例本身（nfs/tftp/smb/enip 同款豁免） | PASS |
| 2.1 | 策略=单模板自带 flow_control | 策略 = 单 bgp 流量模板自带 `flow_control`（#16 `flows=3`；其余缺省单流） | PASS |
| 2.2 | 任务=多策略合跑+总量封顶 | 框架语义未动（suite 走策略路径；bgp 不在 worker/task 特判名单） | PASS |
| 2.3 | 策略先限速任务再封顶 | 未动 | PASS |
| 2.4 | 任务 ID={taskID}-{strategyID} | 未动 | PASS |
| 2.5 | flows=N 复制 N 条 | #16 `flows=3` → 33 包 = 11×3；T9 双会话 22 = 11×2；#12 23 包（12+11） | PASS |
| 2.6 | spec 不管数量 | 未动 | PASS |
| 2.7 | 按流变化走动态字段 | 四元组动态住 ip/tcp（allowlist `layer_dyn.go:17-21`；**bgp 不在表内**→业务字段动态必拒） | PASS/A′ |
| 2.8 | 未写动态 src_port 保底 12345+i | `worker.go:307-309` 自增（`DefaultSrcPort=12345`，`:316` resolveLayerTuple；P6 抽查精确命中） | PASS |
| 2.9 | 其余按流变化必须写动态 | design §12.12 业务清单（逐字段开/关+理由）；业务动态零开=维持关（allowlist 未登记） | PASS/A′ |
| 2.10 | 讲数量分清策略复制/任务封顶 | p123 门1 §2 行 | PASS |
| 2.11 | 讲变化动态按 §12 | 本表 12.x | PASS |
| 3.1 | 多会话 sessions[]/flows[] 显式 | 层内 `sessions[]`（T9/#12/#20）+ `flows` 面（#16 `flows=3`）；包数 22/23/21/33 实测钉死 | PASS |
| 3.2 | 每会话独立 ID/四元组/生命周期 | `sessions[].src_port` 独立四元组；逐 session 独立握手→事件→挥手（`layer_gen.go:35-42`；单测 `:429-445`） | PASS |
| 3.3 | 会话内事务有序序列 | t1–t4 四件事严格顺序（状态机强制；`planner.go:65-108`） | PASS |
| 3.4 | 事务前置条件 | design §12.3 会话表/事务表 + `validateEventSequence` 全分支 | PASS |
| 3.5 | 触发动作 | 事件数组逐条（open×2→ka/update→[notif]；#11 S2+3 UPDATE） | PASS |
| 3.6 | 成功分支 | Established（双 OPEN 齐）→ 会话继续 → TCP 挥手 | PASS |
| 3.7 | 失败分支 | 23 负例 task error 锚（`state`/`last`/`exactly two` 等 20 族全覆盖） | PASS |
| 3.8 | 控制关联数据流显式字段 | 单 TCP 连接内无派生流——**无 `driven_by`，不适用**（design §10.4 诚实声明，非缺口） | PASS |
| 3.9 | 关联写清会话/事务/决定字段 | 不适用（同上；无派生流） | PASS |
| 3.10 | 被关联流独立 ID/四元组/握手 | 不适用（同上） | PASS |
| 3.11 | 各流顺序/并发/交错写清 | 会内严格顺序 + 多会话整块顺序 + 多流并发（`flows=N` 跨流不假设包序；9.39 互斥） | PASS |
| 3.12 | 可交错写清调度+时间戳 | `concurrent` 面不适用（无该键，testcase §6.3 注记） | PASS |
| 3.13 | 不许连续重复冒充编排 | #11 真多事件 3 轮 UPDATE（不同 NLRI 三前缀）非模板重复 | PASS |
| 3.14 | 无长连接豁免≠多流豁免 | 有长连接载体 → `sessions[]` 不豁免（§12.3 s1/s2）；单包多载荷 #19（withdrawn+属性+NLRI 同包） | PASS |
| 3.15 | 多轮/非正常结束/长保活各一例或立项 | ①#11 三轮 UPDATE ②T5 NOTIF + #18 RST（8 包 + `tcp.flags@8=0x0014`）③T6/T10 + #11 + #16（hold 90/0 两档 + 多轮/多流） | PASS |
| 3.16 | CWMP 范本照补 | 差异声明：无 driven_by（单连接无副流） | PASS |
| 3.17 | 多流设计五件套 | design §12.3（会话表/事务序列/关联/插入位置/时间线） | PASS |
| 4.1 | 连接模型 | design §10.1#1（TCP 单连接双向对等，默认 179；`DependsOn ["tcp"]`） | PASS |
| 4.2 | 命令/消息表 | design §3.1–§3.5（头/OPEN/KA/UPDATE/NOTIF 四报文逐字段） | PASS |
| 4.3 | 状态机 | design §3.6/§4.1（OPEN 成对/乱序拒/NOTIF 末位/多会话独立机） | PASS |
| 4.4 | 字段表 | design §3 全表（大端 + 长度回填 + 前缀截断 + 六属性编码） | PASS |
| 4.5 | 错误处理表 | design §7 十四行 + §4.2 非法转移（锚词逐行；用例面 23 负例锚） | PASS |
| 4.6 | 超时与活性 | 定时器/协商不模拟 = N/A 声明（§10.1#6 + §10.5 取舍；KEEPALIVE 只作显式事件） | PASS |
| 4.7 | NAT/代理/被动 | 无被动模式；NAT 下 `sessions[].src_port` + distinct 断言 | PASS |
| 4.8 | 版本/方言 | BGP-4；MP_REACH/能力/4-octet ASN 扩展面全拒 → B′（B1–B4） | PASS/A′ |
| 4.9 | 有 RFC 查 RFC 注章节 | RFC 4271 §4/§5/§6/§8/§9 节号级 + RFC 2545（传输）+ RFC 4760/5492/6793（B′边界） | PASS |
| 4.10 | 无 RFC 以官方规范为准 | RFC 即官方（无二手解读） | PASS |
| 4.11 | 不许博客二手代替原文 | 现网口径直指 Cisco/JunOS/FRR 文档（design §10.5；180/60 默认值不硬编码） | PASS |
| 4.12 | 规范原文 | design §3 逐表（OPEN 金向量/NOTIF 4-0/全属性 UPDATE 三金向量与单测三方一致） | PASS |
| 4.13 | 商业软件实际行为 | Cisco hold 180/ka 60、JunOS hold 90/ka 30、FRR OPEN 带能力（design §10.5；字节面 T2/T6 取 90/0 两档） | PASS |
| 4.14 | 可靠开源实现思路 | FRR bgpd 走法参照（事件回放 vs FSM 全仿真 vs pcap 回放三选一，借鉴声明不搬码） | PASS |
| 4.15 | 三路不一致取舍写清 | design §10.5（现网定时器协商 vs 生成器无定时器 → 事件全显式，hold 只作字节面） | PASS |
| 4.16 | 商业行为逐条映射用例号 | design §10.6 六行映射（C1/C2/C5 ✅；C3 N/A；C4/C6 B′） | PASS |
| 4.17 | 关键决策候选方案对比表 | design §10.5 A/B/C 走发表（采用 A 事件面显式回放） | PASS |
| 4.18 | 不许单方案自说 | 同上（B/C 否决理由在案） | PASS |
| 4.19 | 每表格行/字段/错误码三选一 | §10 矩阵 8+20+22+6（testcase §5.2 对账 70 行无遗漏） | PASS |
| 4.20 | 每条目对应至少一用例 | 61 覆行多对多；3 缺口 + 4 B′ + 1 N/A 立项维持（testcase §5.2） | PASS/A′ |
| 4.21 | 动手前缺口矩阵 | p123 门1 表 + design §10 矩阵 | PASS |
| 4.22 | 三张子表齐 | ①报文×状态 20 格 ②变体 22 行 ③商业映射 6 行（design §10.2/§10.3/§10.6） | PASS |
| 4.23 | 设计评审先看矩阵 | 门1 获批（p123 §①） | PASS |
| 4.24 | 规范实现冲突先改实现 | hold 1–2 按 RFC 补拒（G-BGP-7 `builder.go` 两面同锚词）；4096 校验面补足（`validateUpdateEvent`，P5 轮3） | PASS |
| 5.1 | 设计写明依赖 | `DependsOn ["tcp"]` 单值（HEAD `registry.go:1081`；M1 回填，写作时 `:1012`）+ design §5 | PASS(NOTE M1) |
| 5.2 | 写明出错处理 | planner/validator 拒 → 任务错误终态；`wire_fault` 三 kind 校验层直拒永不产字节（`builder.go:140-157`） | PASS |
| 5.3 | 无依赖/错误分支不许实现 | 有（§5/§7/§11.5 全链） | PASS |
| 5.4 | 无依据不许定字段流程缺省 | 端口 179/报文表/属性表均有 RFC 出处；`wire_profile` 不参与字节构造诚实声明 | PASS |
| 5.5 | 不确定标待确认+确认方式 | G-BGP-8 观察项登记（框架名单超协议本地块，不动名单） | PASS |
| 5.6 | 回答结论指章节/代码行 | design §12–§14 已成文；M1/M2 回填后引用不再断链 | PASS(NOTE M1/M2) |
| 5.7 | 指不出直说不知道 | 吞吐数字诚实"待 P4 基准"（design §6.5/§11.6） | PASS |
| 5.8 | 回复前自查出处 | p4-report §5 自审 3+2 轮（末轮干净） | PASS |
| 5.9 | 抽查三条定位不到打回 | 门3 三条 ≡ p6-review §1/§7（两条精确命中；第三条 M1 按字面点不到→回填） | PASS |
| 6.1 | 性能目标/预算/边界 | design §6/§11.6（单流事件 ≤6/常规 ≤10；单报文 ≤4096 硬拒；单 flow O(1)：`emitEvents` 循环 + `Plan` 通道 16） | PASS |
| 6.2 | 六指标列全 | 吞吐数字诚实待基准（B′缺口未细化） | PASS |
| 6.3 | pcap/NIC 分别验收 | pcap 路：20 正例 pcap + suite 全绿（lane + P6 独立复跑）；**NIC 路本轮未跑** | NOTE |
| 6.4 | 性能依据结合实现路径 | 逐事件流式（`layer_gen.go:66-77`）、无锁无共享（唯一可变=循环下标）、限速框架 `SharedTokenBucket` | PASS |
| 6.5 | 无依据数字标待确认 | 已标 | PASS |
| 6.6 | 六类性能场景 | 清单在案（基线/目标规模/压力上限/长时间/并发交错/资源耗尽；§6.6）；P5 未跑基准 | NOTE |
| 6.7 | 断言实际指标不只无报错 | packet_count 20 正例 + 26 frames + 70 fields 双钉（116/116 逐字节全中） | PASS |
| 6.8 | 超预算仍不合格 | 4096 硬拒已落码（`builder.go:381-384` + 校验面 `:417/:238`） | PASS |
| 7.1–7.3 | 三份文档定位 | design+testcase+D-BGP-1；未碰 CODE_DESIGN/TEST_CASES | PASS |
| 7.4 | 历史文档保留参考 | 旧基线 `36-bgp-*` 保留；design §8 逐节比对（延续 + 3 类变化，无删改矛盾） | PASS |
| 7.5 | cases 是产物回指编号 | 43 例回指 testcase §2（M3 补登 5 条后 38→43 对齐；ID 权威=testcase §2） | PASS(NOTE M3) |
| 7.6–7.7 | 三者关系/冲突序 | — | PASS |
| 7.8–7.9 | 先核心→设计→用例 | 门1 先行（P1–P3 先于 P4/P5；时序 G-BGP-5→改写→G-BGP-6 无中间全红态） | PASS |
| 8.1 | 八要素（文件/接口/结构/流程/错误/性能/冲突/回滚） | design §11 八要素齐；实现面逐件在码（p4-report §4 三处框架本地块声明） | PASS |
| 8.2–8.8 | 同上逐项 | translate/validate/backfill/types 落点见 p4-report §4 + p6-review §4.2（`chain_planner_translate.go:695/705-728` `if term.Name=="bgp"`，m2 措辞待正） | PASS(NOTE m2) |
| 8.9 | 未定稿不开工 | 门1 获批=开工 | PASS |
| 8.10 | 需求变先改设计 | P5 轮2 `#16` 策略替换（ttl pattern/src_port list 被拒→ip.dst rand）summary/notes 同步改写，不声明跑不到的维度 | PASS |
| 8.11 | 不许代码先行文档后补 | P1–P3 先行 | PASS |
| 8.12–8.13 | 开工贴条目/无条目打回 | — | PASS |
| 9.1 | 用例登记（回指编号） | testcase 契约 §2/§5；ID↔`cases/bgp.json` 机读对账（M3 后 43=20 正+23 负） | PASS(NOTE M3) |
| 9.2–9.4 | 三源（规范/设计/现网） | RFC 4271 + D-BGP-1 + Cisco/JunOS/FRR 口径；dissector `bgp.*` 784 字段实测通道 | PASS |
| 9.5 | 每行每字段每错误码有用例 | 61/70 覆行多对多（矩阵 20 全 + 变体 17 + 三路 3 + 错误 13 + 单测 8；V18 例外注记）；缺口逐个去向 | PASS/A′ |
| 9.6 | 一例一行为 | 43 例无重复 id（机核） | PASS |
| 9.7 | 修 bug 先复现变红 | 4 轮红→修→全量重跑（p4-report §6 轮次表；P5 首轮 18 mismatch 系自查脚本 0-based 口径错，未改 case 只修正脚本） | PASS |
| 9.8 | 数据场景六变体（正常/边界/空值/超长/非法/大小端） | T10 length=19 下界 / T7 /32 / #35 超 4096 / #36/#37 非法 / 大端回填 + 23 负例 | PASS |
| 9.9 | 业务场景序列/乱序/中断/交错 | 生命周期序列 + 乱序负例族（#30–#33/#38）+ 整块多会话；交错 concurrent 不适用 | PASS |
| 9.10 | 现网场景；复杂度 9.50 下限 | #20 复合大场景 4 类交织（会话×事务×异常×地址）达下限 | PASS |
| 9.11 | 多动作组合流≥2 条×≥3 动作 | T2（双向 OPEN+双向 KA 4 事件）/ #11（S2+3 UPDATE 7 事件）≥2 条 ✓ | PASS |
| 9.12 | 清单先行 | P1 矩阵先行（p123 门1） | PASS |
| 9.13 | 清单无遗漏是目标 | 70 = 61 覆行 + 3 缺口 + 4 B′ + 1 N/A + 1 重复隙（V6/#10），机算 ✓ | PASS |
| 9.14 | 存量逐条审计去向 | testcase §8 19/19（10 合入正 + 9 合入负，0 作废；事件内死字段无） | PASS |
| 9.15–9.19 | A/B/C 三分类 | A′ 19（§2 #11–#20 + #30–#38）+ 判死 4 + hold 小值 1；B1–B5 D 条目"明确不解决 + 迁入计划" | PASS |
| 9.20 | 取值表每值一例 | ORIGIN 0/1/2（T3/#13/#14）/ type 1–4 / version / AS 边界 / MED 有值缺席 / LOCAL_PREF / COMMUNITIES 两 well-known；SET/能力/4-octet 面 → B′ | PASS/A′ |
| 9.21 | 分支级审计 | 负例按分支铺（`tcp`/`profile`/`marker`/`length`/`type`/`version`/`as`/`state`/`address`/`identifier`/`next_hop`/`4096`/`error_code`/`last`/`exactly two`） | PASS |
| 9.22 | 扫遍全部承载位置 | 层内 `events`/`sessions`（唯一承载）全覆盖；`wire_fault` 三 kind 全覆（N3/N4/N5） | PASS |
| 9.23 | 正交矩阵逐格标记 | testcase §5.2 正交矩阵（模式×方向×地址族×会话数×异常；§2 表体即格→ID 映射） | PASS |
| 9.24 | 地址族对称（IPv4/IPv6 逐格） | T8 IPv6 transport ✅；IPv6 NLRI → N9 拒（MP_REACH B′）；v6+多会话组合 → P4 实测后立项 | PASS/A′ |
| 9.25 | 地址族扩展随矩阵扩 | v6+多会话组合标缺口立项未做 | NOTE |
| 9.26 | 补齐顺序 | 最小实现→高频→全量（B′未执行） | NOTE |
| 9.27 | harness 做不到逐项注明 | 包序/方向靠 frames+字段组合钉（tshark 面；1-based 口径 `verify.go:142`） | PASS |
| 9.28 | 不许字段出现冒充顺序 | packets 级事件序断言 + 状态机强制顺序 | PASS |
| 9.29 | 补齐后全量全绿 | 43/43 全量绿（lane12 + P6 独立复跑；每轮 FULL rerun 非增量） | PASS |
| 9.30 | 只写不跑/只跑增量=未完成 | 全量跑（4 轮每轮 FULL rerun） | PASS |
| 9.31 | 断言以真实 pcap 校准 | 先跑后钉（P6 pcap 自跑自钉；OPEN/UPDATE 金向量与单测三方一致） | PASS |
| 9.32–9.35 | 动态整格（五策略×字段） | #16 四元组多策略同例（`ip.src` inc 回绕 / `ip.dst` rand seed=42 复现 / `tcp.src_port` list 轮转实测钉死；`ttl pattern` 被拒已诚实删除）；`distinct_values` 三值 + 同 seed 跨运行 same | PASS/A′ |
| 9.36 | 不支持格标 B/C+注记 | prefix-0 / extended-length 立项无 ID 注记 ✓（锚词真实存在 `builder.go:255/:515`）；#18 RST 面 P4 实测钉现状（8 包 + RST+ACK） | PASS |
| 9.37 | 派生编号撞车 | 无派生子流面 | PASS |
| 9.38 | 聚合断言排除固定/派生口 | #12/#20 `tcp.srcport distinct` 排除 179（9.38 复核） | PASS |
| 9.39 | 多流×静态标量互斥 | 未写动态保底 `12345+i` 已防全同（§12.9 不触发）；显式写死端口 + `flows>1` → `static_copy_multiflow` 负例锚 `static four-tuple`（`schema/semantic.go:285`） | PASS |
| 9.40 | 共享流序号动态字段 | 无动态面 | NOTE |
| 9.41–9.45 | 测试评审五件事 | p6-review §1–§5（门3 抽查/字节复核/双门/三源/残留裁定） | PASS |
| 9.46 | 数据场景全表扫 | V1–V22 全表扫（design §10.3；覆 10 + 缺 10 行 + B′ 2 行 = 22 ✓）；/0 与扩展长度立项（见 9.20） | PASS/A′ |
| 9.47 | 取值集合逐值枚举 | 同上（NOTIF 仅 4/0，其余码拒 + B′） | PASS/A′ |
| 9.48 | 业务场景规范反推 | design §10 三子表；出处声明 testcase §5.2（规范反推非用例反推；引擎侧只作现状取证） | PASS |
| 9.49 | 多连接/多会话/多事务各一例+真实编排 | 多会话 T9/#12/#20 + 多事务 #11 + 真实编排 #20（会话×事务×异常×地址） | PASS |
| 9.50 | 复合大场景≥3 类交织 | #20 `bgp_a_notification_multi_session` = 会话(2 整块)×事务×异常(NOTIF vs 正常)×地址 4 类 ✓ | PASS |
| 9.51 | 组合矩阵满格 | design §10.2 20 格（覆 7 + 缺 13 → 7 ID，同分支合并）+ testcase §5.2 正交矩阵；组合维度有限=A′ 维持 | PASS/A′ |
| 9.52 | 审计声明出处+对账两行 | testcase §5.2：规范 70 vs 已覆 61 + 缺口 3 + B′ 4 + N/A 1 + 重复隙 1；出处=规范反推；反查全绿≠覆盖全 | PASS |
| 9.53 | 门3 至少一条抽最复杂用例+点数 | 文档预判 #11（7 事件 3 轮）；实测 pin 最多 T2（6 fields+4 frames=10 pins/11 包）、包数最多 #16（33 包/3 流）、矩阵最宽 #17（9 pins/13 包）；P6 五例（T2/#11/#16/#17/T9）116/116 全中 | PASS |
| 10.1 | 文档对规范逐条核对 | p123 §②10.1（RFC 节号级回指） | PASS |
| 10.2 | 改需求先对旧需求 | design §8（旧基线 `36-bgp-*` 逐节比对：延续 + 3 类变化，未删条目无矛盾） | PASS |
| 10.3 | 代码逐行走读 | P4 3 轮 + P5 2 轮（p4-report §5）；P6 复核 builder/planner/translate/strategy_convert 行号 | PASS |
| 10.4 | 构建+vet+测试含 race | HEAD 快照：build 干净；vet 三包 exit 0；`-race` 三包 ok（14.0s/1.1s/18.0s） | PASS |
| 10.5 | 修完再审 | 每轮 fix 后再审（P4 R3/P5 R2 末轮干净；P6 独立复核） | PASS |
| 10.6–10.10 | 测试评审 | p6-review（三源对账 + 7 锚词探针 + 116 点数） | PASS |
| 10.11 | 改审测修再审闭环+结论 | p4-report §5/§6 + p6-review §6（判词通过） | PASS |
| 11.1–11.5 | 白话 | p123 §0 / p4-report §0 / p6-review §0 首句白话结论 | PASS |
| 12.1 | 五策略全开 | 四元组五策略 framework 在案（allowlist `layer_dyn.go:17-21`） | PASS |
| 12.2 | 动态覆盖四元组 | #16 实测取用（inc/rand/list 三策略同例钉死） | PASS |
| 12.3 | 业务字段清单逐协议 | design §12.12（逐字段开/关+理由；`bgp` 不在 allowlist → 对象必拒） | PASS |
| 12.4 | flows=N 确定性+seed+回绕 | #16 同 seed 跨两次运行 same（seed=42 复现实测）；inc 回绕（`tuple_generator.go:164`） | PASS |
| 12.5 | 不写动态按 fixed | 除 #16 外全静态（层内静态标量） | PASS |
| 12.6–12.8 | 任务级动态不丢/只截断/跨策略 | framework 未动 | PASS |
| 12.9 | 静态复制拒绝/告警 | framework 守卫在案（`static_copy_multiflow` 负例实测命中） | PASS |
| 12.10 | src_port 保底≠动态 | 诚实声明（design §12.12；保底自增在前、动态覆盖在后 `worker.go:307-316`） | PASS |
| 12.11–12.13 | 动态住层链/不另起顶层/对齐 tuples | 四元组住 ip/tcp；无顶层动态键 | PASS |
| 12.14–12.16 | 清单+序号算法可定位 | 序号算法：`layer_dyn.go:78` parse → `:369` checkShape → `:770` resolveLayerTuple + `tuple_generator.go:26/164/181/194/290/300/310`；业务动态面维持关 | PASS/A′ |
| 13.1–13.6 | schema 文件 | registry bgp 行 13 键 + FieldContract 179；generated json 逐键一致（P6 `schemagen` 后 diff byte-identical，127 层；`events`/`sessions` 无 default） | PASS(NOTE M1) |
| 13.7–13.10 | 校验入口唯一 | ValidateStrategy/TaskCreate 同入口（suite 走 MCP） | PASS |
| 13.11–13.16 | 派生只读下游 | flowb_query_layers 实时视图（registry 派生） | PASS |
| 13.17 | 改语义先改 schema | registry 先行（P4 落 G-BGP-5①） | PASS |
| 13.18 | 注册表变更重跑生成 | generated 已重跑入版（bgp 13 键） | PASS |
| 13.19 | 过期测试变红 | `schemagen` 后 diff byte-identical（P6 实测）；shape 门拒未知键（`complete.go:293`） | PASS |
| 13.20–13.21 | 缺席走缺省/null 拒 | 严格往返解码 `DisallowUnknownFields`（translate）；缺键→默认 6 事件流 vs 显式 `[]`→connect-only vs `null`≡缺键（`TestBGPChain_EventsKeyAbsentVsEmpty` 守护） | PASS |
| 13.22–13.23 | schema 是机器源不算第四文档 | — | PASS |
| 13.24–13.26 | 评审先查 schema/手写/null 兼容 | 无手写形状；null 兼容分支已测（见 13.20） | PASS |
| 14.1 | 用例 spec 即 MCP 任务配置 | spec_json=layers 直驱 + flow_control 封包 | PASS |
| 14.2 | 不许两套写法 | 单权威（层优先、flat 判死；G-BGP-5③时序收敛） | PASS |
| 14.3 | 执行工具直接消费用例 | suite 经 MCP 直消（lane12 + P6 独立重跑） | PASS |
| 14.4 | 旧用例随层链迁移改写 | 19 例全改写 + 24 新增（10 A′正 + 10 A′负 + 4 判死含 hold 小值）= 43 | PASS |
| 14.5 | 历史口径不带入 | 包数公式重校（`3+事件数+4`；多会话求和）+ 断言面重建（frames 26 + fields 70） | PASS |
| 14.6 | 先跑拿 pcap 再钉 | P5 实跑重锚（#19 同包双区改双长度断言；#18 补 8 包 + RST+ACK；#16 跨运行复现钉） | PASS |
| 14.7–14.9 | MCP 建任务→生成→tshark 校对 | lane MCP + tshark 字段/frames 双通道（P6 自写脚本复核，不复用仓库校验器） | PASS |
| 14.10 | 离线/无失败/只数包不算测 | 字段+frames 双钉（不只看 packet_count；#18 前车"包数 P4 钉"已补死） | PASS |
| 14.11 | 负例经 MCP 被拒+锚词 | 23 负例全 error_contains；7 条实测探针（故意错锚词读服务端原文）锚词↔源码↔线上三方闭合 | PASS |
| 14.12 | 假成功同级 bug | 无假成功：链路径生成期错误吞零包面（`worker.go:421`）已补校验面 4096（P5 轮3）；G-BGP-8 留观察 | PASS |
| 14.13–14.15 | 聚端口/派生口/方向想清 | distinct 排除 179（#12/#20）；方向 c2s/s2c 显式逐事件 | PASS |
| 14.16 | 全绿+落盘可复查 | 43/43 + 20 正 `.pcap` + 18 负空(24B 头) `.neg.pcap` + 5 例无文件（创建期拒绝 5 条；m1 措辞修正"无数据包落盘"） | PASS(NOTE m1) |
| 14.17 | 抽查 spec/字段/锚词 | p6-review §1/§2/§4 | PASS |
| 14.18 | 二进制与 HEAD 同代 | 门2-3 绿（P6 HEAD 快照现编二进制补验；canonical 二进制 mtime 口径见 m5） | PASS(NOTE m5) |
| 14.19 | 全量全绿 | 43/43（非增量；P6 独立复跑一致） | PASS |
| 14.20 | 包号/端口从 pcap 拿 | 先跑后钉（T2 pkt4 OPEN 29B / #11 pkt8-10 全属性 UPDATE 66B 逐字节一致） | PASS |
| 15.1 | 门1 十四行表+证据 | design §12 十四行（p123 门1） | PASS |
| 15.2 | 证据三选一；写不出=立项 | G-BGP-5/6/7 + B1–B5 在案（design §14；testcase §6.2） | PASS |
| 15.3 | §1/§3/§12 强制展开 | design §12.1/§12.3/§12.12 + §12-P2 判死清单 | PASS |
| 15.4 | 门2①顶层零残留 | 旧键绿；presence 红线已接（`pipe_gate.sh` bgp 登记；P6 实测绿；黄项=presence 负例本身豁免） | PASS |
| 15.5 | 门2②全量绿+负例锚词 | 43/43 + 23 锚词（反查负例锚词 20 族全覆盖；7 条探针三方闭合） | PASS |
| 15.6 | 门2③二进制同代 | 绿（HEAD 现编补验；见 m5） | PASS |
| 15.7 | 门2④反查绿后进 P6 | 59/59 绿（用例 43 + 正例键穷尽 + 负例纯净 + 锚词 20 族 + 先跑后钉） | PASS |
| 15.8 | D-条目挂门1表（回填证据号） | M1（registry/chain_planner 行号 + 11→13 键）/ M2（builder +34）/ M3（补登 5 ID + 38→43 口径）关单前必办，主线程回填 | GAP(M1/M2/M3) |
| 15.9 | 抽查三条点到行/例号 | p6-review §1/§7（三条均点行/例号；第 3 条触发 M1） | PASS |
| 15.10 | 白话+三门证据 | p6-review §0/§3/§4/§7 | PASS |
| 15.11 | 任一门红停 | 门2 静态四项绿（exit 0）；0 C 级打回 | PASS |

## 注记（backlog，判定口径）

- **判定口径**：`GAP(M1/M2/M3)` = P6 关单前必办的文档回填项（证据本体真实唯一可定位，不触及代码/用例/字节正确性）；`PASS/A′` = 覆盖未达但已按 testcase §6.2 A′/B′ 与 D-BGP-1 立项承接，非挂账；`NOTE` = 观察/措辞项。
- **M1（文档回填）**：设计 §12「§13 schema 派生」/「§5 依赖」行与 §2.2 表题写 `registry.go:1012(-1027)`、实测 11 键；HEAD 实际 **`registry.go:1081-1105`**（bgp 注册 1081、FieldContract 1082、11 原键 1084-1094、新键 `events`/`sessions` 1101-1102），实为 **13 键**。同族：`chain_planner.go:598-629` → HEAD **614-641**。根因：写作提交 fc2211e 处逐字命中，漂移由后续他协议车道 merge 造成（非本车道错误）。
- **M2（文档回填）**：testcase §4/§3 的 `builder.go:509/:383/:119-121/:191-193` → HEAD 实为 `:543/:417(+:238)/:124/:201`；设计 §1 builder 行号统一 +34（`BuildOpen :261→:295`、`BuildKeepalive :281→:315`、`BuildEvent :292→:326`、`BuildUpdate :351→:385`、`encodePrefix :394→:428`、`appendPathAttr :479→:513`、`BuildNotification :507→:541`）。锚词全命中，只改号。`planner.go :14/:39/:65/:110`、`layer_gen.go :15/:52/:85/:101-104` 未漂移。
- **M3（文档回填）**：testcase §2（ID 权威）38 ID（20 正+18 负）→ 机读 43（20 正+23 负）；补登 5 条：`bgp_neg_presence_top_level_bgp`、`bgp_neg_flat_count`、`bgp_neg_stray_src_mac`、`bgp_neg_static_copy_multiflow`、`bgp_a_neg_hold_time_small`（前四 = §12-P2 判死形状 + 白名单门固化，后一 = G-BGP-7 pcap 例）；design §9「目标 38 例」口径同步对齐 43。
- **m1**：p4-report §3「23 负例无落盘」不准 → 实为 20 正 `.pcap` + 18 负空(24B 头) `.neg.pcap` + 5 例无文件（presence/flat_count/stray_src_mac/static_copy_multiflow/udp 创建期拒绝）；应为"无数据包落盘"。
- **m2**：设计 §11.1⑥「增 `case "bgp"`」措辞待正 → 实现为 `translateTerminalConfig` 内 `if term.Name == "bgp"` 块（`chain_planner_translate.go:695/705-728`，pcep/ldp/isis 同款），语义等价。
- **m3**：复审期间主工作树处于他人 merge 中途（s7→doip，3 文件冲突标记，树不可编译）；P6 在 `git archive 11c509f` 只读快照执行，结论可信；建议 merge 落定后重跑一次门 2 存档。
- **m4**：仓库 `trafficgen/docs/protocol-pcap-test/bgp.md` 仍 `Cases: 19`（suite 生成物，车道按约束复原未提交）；关单提交时刷新。
- **m5**：canonical 二进制 mtime 口径无 vcs 戳；P6 以 HEAD 快照现编二进制补验门 2-3（绿）；后续门 2 统一用 HEAD 现编二进制。
- **G-BGP-8（观察，open）**：`validateBaseDstPortHandled`（`chain_planner.go:659`）未收 bgp；两条路径今日均得 179（flat 路径 `strategy_convert.go:1467` `setDefaultDstPort(179)`；链路径 FieldContract `registry.go:1082`；线上 tshark 实测命中）。不动框架名单（超协议本地块），登记观察。
- **立项（无 pcap 例，保持）**：prefix length 0（锚词 `builder.go:255` 真实存在）/ extended-length（锚词 `:515`，单测 `:514-526` 覆盖）——契约判立项无 ID，不建例符合契约。
- **B′（明确不解决 + 迁入计划，保持）**：B1 MP_REACH / B2 能力协商 / B3 4-octet ASN / B4 refresh-graceful-auth-MD5 / B5 AS_SET+扩展长度（`capabilities` 非空即拒 `builder.go:88`；源码无实现符号；用例 0 条涉 B′）。
