# SMB（D-SMB-1 #50）P6 248 条款逐条比对表

> 口径：docs/CORE_MEMORY.md（481 行，248 条=13+11+17+24+9+10+9+13+53+11+5+16+26+20+11）。落点=smb#p6 本审实测证据（代码行/用例号/suite/gate/tshark）+ P6 修轮（分支 `pipe/smb-p6fix` 集成 `2e9cee5`：G1–G5 全部关闭；scoped 复评关单）。判定：PASS=满足，GAP(n)=缺口（缺口=G-SMB-n 立项，见 design §17；G1–G5 为修轮前判词编号，现均关闭），NOTE=注记。

| 条款 | 要求 | smb 落点 | 判定 |
|---|---|---|---|
| 1.1 | 地址只写 ip 层 | 296 例 layers[0].ip.src/dst（279 存量 + 17 补例）；顶层 src_ip/dst_ip 残留 0（机核） | PASS |
| 1.2 | 端口只写 tcp/udp 层 | layers[1].tcp.src_port/dst_port；netbios 例显式 dst_port=139（缺省面见 N1） | PASS |
| 1.3 | 流数量只写 flow_control | 顶层 count 残留 0；多流走 group_id+flow_control（5 例） | PASS |
| 1.4 | 禁 layers 与顶层五键混用 | probe_neg_layers_flat_mix 锚 `config mixes layers with flat four-tuple field src_port`（suite 绿） | PASS |
| 1.5 | 混用示例/用例/文档都跑偏 | 用例面零混用；严格层链样例在 design §14.1（已入仓） | PASS |
| 1.6 | 门①层链能跑通 | suite 308/308（296+12 probe，canonical 复跑）+ pcap 落盘 | PASS |
| 1.7 | 门②旧格式彻底移除 | 279 存量过渡形→纯 layers；17 无 layers 负例改层内非法值 | PASS |
| 1.8 | 示例只给严格层链形 | 样例在 design v2.2.1 §14.1（已入仓） | PASS |
| 1.9 | 暂不支持明确标注 | G-SMB-1「今天跑不通」标注随附录 | PASS |
| 1.10 | 汇报分开说跑通/清旧字段 | p123-report §1 / p4-report §4 分节 | PASS |
| 1.11 | 顶层白名单 | 顶层实测 ∈ {layers, group_id×5}；group_id 属跨流绑定家族 | PASS |
| 1.12 | 无可住层须立项，不许豁免 | 无豁免登记；不可达形全走立项 | PASS |
| 1.13 | 门2①白名单制 | 修轮后：presence 登记 smb 自键 + group_id 进子映射白名单；门2-1 绿 | PASS |
| 2.1 | 策略=单模板自带 flow_control | smb 单模板 + strategy_fc（suite 直跑策略 config） | PASS |
| 2.2 | 任务=多策略合跑+总量封顶 | 框架语义未动 | PASS |
| 2.3 | 策略先限速任务再封顶 | 未动 | PASS |
| 2.4 | 任务 ID={taskID}-{strategyID} | 未动 | PASS |
| 2.5 | flows=N 复制 N 条 | 多流例 flows=2 实测两条独立流（40001/40002） | PASS |
| 2.6 | spec 不管数量 | spec 无 count 键（机核） | PASS |
| 2.7 | 按流变化走动态字段 | 四元组 dyn ✓（6 例）；业务字段零开 | PASS |
| 2.8 | src_port 自动递增保底 | tcp 层保底 12345+i；多流例显式 dyn 覆盖（9.39 正解） | PASS |
| 2.9 | 其余字段变化须写动态 | 无自动变化暗示；业务键关面诚实声明（报告 §8） | PASS |
| 2.10/2.11 | 数量/变化表述纪律 | 报告口径一致 | PASS |
| 3.1 | 多会话显式声明 | flows=N + group_id（方案 C 裁定，5 例）；sessions[] 面不选 | PASS |
| 3.2 | 每会话独立 ID/四元组/生命周期 | tshark：sesid 0x28e/0x28f 互异；端口 40001/40002 | PASS |
| 3.3 | 会话内事务有序序列 | tpos164 每会话 msg_id 0..9 逐值钉 | PASS |
| 3.4 | 前置条件写清 | 设计 §4.2 跳过规则表 9 值 + terr 族状态约束 | PASS |
| 3.5 | 触发动作写清 | ops 注解 + 设计 §3.2 命令表 | PASS |
| 3.6 | 成功分支写清 | 默认全序会话（S1-S15 场景） | PASS |
| 3.7 | 失败分支写清 | error_on_command 9 值 × 拆解续走（terr 族 + 17 负） | PASS |
| 3.8/3.9/3.10 | 多流关联三件事/独立 ID | SMB 无副流派生，driven_by 不适用（理由在 design §14.3） | NOTE |
| 3.11 | 顺序/并发/交错写清 | 会话内有序、跨会话不假设全局序（声明在备份） | NOTE |
| 3.12 | 调度方式与时间戳 | 顺序发射实况（帧 1-29/30-58 无交错） | NOTE |
| 3.13 | 不许重复发射冒充编排 | tpos164 两会话独立计数器；probe_ops_multi_round 三操作 | PASS |
| 3.14 | 豁免边界 | 长连接 → sessions[] 不豁免；多流并发 + 单消息多载荷（T294/T241）有例 | PASS |
| 3.15 | 三项（多轮/非正常结束/保活） | probe_ops_multi_round / probe_error_on_close / probe_echo_liveness | PASS |
| 3.16 | CWMP 范本 | driven_by 不适用已声明；group_id 参考基线 | PASS |
| 3.17 | 五件套文档 | design §14.3 五件套（已入仓） | PASS |
| 4.1 | 连接模型 | MS-SMB2 §2.1 长连接/445/139（设计 §1 in-repo） | PASS |
| 4.2 | 命令/消息表 | 设计 §3.2 19 命令表（in-repo） | PASS |
| 4.3 | 状态机 | 设计 §4 状态机（in-repo） | PASS |
| 4.4 | 字段表 | 设计 §3.1/§5 字段表（in-repo） | PASS |
| 4.5 | 错误处理表 | 设计 §8/§9 + validate.go V1-V37 | PASS |
| 4.6 | 超时与活性 | 设计 §3.19 ECHO；TCP 承担超时/重传 | PASS |
| 4.7 | NAT/代理/被动模式 | 设计 §12 行 7「协议级无物可测」（已入仓） | PASS |
| 4.8 | 版本/方言差异 | 设计 §3.2/§7.19 dialect 族（in-repo） | PASS |
| 4.9 | 有 RFC 查 RFC | MS-SMB2 §2.2/§3.x 逐条引用（设计 §3/§4/§7） | PASS |
| 4.10 | 无 RFC 以官方文档 | MS-SMB2/MS-FSCC §2.4.18/MS-ERREF/MS-NLMP | PASS |
| 4.11 | 不许二手解读 | 抽查 §3/§8/§9 无博客转述 | PASS |
| 4.12-4.15 | 三路对照/不一致取舍 | design §13.1 三路对照 + §13.3 裁定 S1/S2（已入仓） | PASS |
| 4.16 | 商业行为→用例映射 | §12.4 六行映射 + G-SMB-3 待确认（已入仓） | PASS |
| 4.17 | 候选方案对比表≥2 | design §13.2 候选对比 + 取舍（已入仓） | PASS |
| 4.18 | 不许单方案自说自话 | 同上 | PASS |
| 4.19 | 每行/字段/码三选一 | §12.2 矩阵 76 格逐格结论（已入仓）；实现面 validate.go V1-V37 | PASS |
| 4.20 | 每条目至少一用例 | 324 点对账：6 点零例已逐个处置（G-SMB-10/probe/NIC）+ 17 原子补例落 | PASS |
| 4.21 | 矩阵先行 | §12.1 八项矩阵（已入仓） | PASS |
| 4.22 | 三张子表 | §12.2/§12.3/§12.4（已入仓） | PASS |
| 4.23 | 评审先看矩阵 | p123-report §2 自审轮次记录 | PASS |
| 4.24 | 规范与实现冲突先改实现 | OpType 清单以实现为锚（G-SMB-7 设计侧勘误，已入仓） | PASS（注） |
| 5.1 | 依赖写明 | DependsOn["tcp"]（registry.go:1171-1172）+ 载体预检 validate_layers.go:482-516 | PASS |
| 5.2 | 错误处理写明 | validate.go V1-V37 + 错误注入 9 值；task 级传播零假成功 | PASS |
| 5.3 | 无依赖/错误分支不许实现 | 二者俱全 | PASS |
| 5.4 | 无依据不许定字段 | G-SMB-3 现网面标待确认，未写死 | PASS |
| 5.5 | 待确认须写确认方式 | §12.4 六行确认方式（已入仓） | PASS |
| 5.6 | 结论能指向文档/代码 | 本审全链可指（strategy_convert.go:8513-8518、chain_planner_translate.go:2607-2619 等） | PASS |
| 5.7 | 指不出直说 | p4-report §8 四项上报不自决 | PASS |
| 5.8 | 回复前自查出处 | p123/p4 自审轮次记录 | PASS |
| 5.9 | 抽查三条可定位 | 本报告 §1 三条全定位 | PASS |
| 6.1 | 性能目标/预算/边界 | 设计 §5.7 性能要素表（已入仓） | PASS |
| 6.2 | 指标列全 | 无协议级吞吐/内存数字（诚实待确认）；队列=框架 buffer | NOTE |
| 6.3 | pcap/NIC 两路验收 | pcap 路实测；NIC 路外部编排（probe notes）未跑 | NOTE |
| 6.4 | 实现路径依据 | O(n) 流式逐 PDU（layer_gen.go divergence 段）；MSS 上移 tcp 层 | PASS |
| 6.5 | 无基准数字标待确认 | 报告/设计一致标待确认 | PASS |
| 6.6 | 六类性能场景 | 未实测（场景清单在备份） | NOTE |
| 6.7 | 断言实际指标 | packet_count + 字段值 + frames hex（非"没报错"） | PASS |
| 6.8 | 功能对超预算即不合格 | 无基准，无从判定 | NOTE |
| 6.9 | 每份设计有性能节 | 性能节在 design §5.7（已入仓） | PASS |
| 6.10 | 无目标不得宣称完成 | 未宣称吞吐承诺 | PASS |
| 7.1 | CORE_MEMORY 最高 | 本审只读遵守，零改写 | PASS |
| 7.2 | CODE_DESIGN 唯一入口 | smb 无 CODE_DESIGN 条目（族约定：D-条目住 protocol-designs） | PASS |
| 7.3 | TEST_CASES 唯一入口 | docs/TEST_CASES.md 无 smb；登记面=protocol-designs testcase | PASS |
| 7.4 | 历史文档保留不删 | 07-smb-design v2.1.0 在仓 | PASS |
| 7.5 | cases 回指编号 | 用例 ID 内嵌 T 号 + notes 回指设计 §7 | PASS |
| 7.6/7.7 | 三者关系/不重复维护 | 设计持唯一契约，无第三份副本 | PASS |
| 7.8 | 新需求先核心后设计 | 本波无核心改动 | PASS |
| 7.9 | 无设计/测试条目不得改码 | 门1 获批先于 P4（p123-report）| PASS |
| 8.1-8.8 | 设计八要素 | D-SMB-1 §15 逐要素（已入仓） | PASS |
| 8.9 | 设计未定稿不开工 | 文档轨 P1-P3 先于 P4 481d874 | PASS |
| 8.10 | 需求变先改设计 | 裁定落码同步改 tpos064 notes（f4d93a8） | PASS |
| 8.11 | 不许代码先行 | 同上 | PASS |
| 8.12 | 开工汇报贴条目 | p123-report §1 贴 14 行表 | PASS |
| 8.13 | 无设计条目 Diff 打回 | 本波 diff 全对应 D-SMB-1/裁定 | PASS |
| 9.1 | 统一登记 TEST_CASES.md | 无 smb 登记（登记实际在 protocol-designs，族约定） | PASS |
| 9.2 | 源①规范 | MS-SMB2 条款引用（设计 §3/§7/§11 in-repo） | PASS |
| 9.3 | 源②代码设计 | D-SMB-1 §15（已入仓） | PASS |
| 9.4 | 源③现网行为 | G-SMB-3 待确认（确认方式六行） | NOTE |
| 9.5 | 每行/字段/码有例 | 6 设计点已逐个处置：T159/T160/T165/T166→G-SMB-10（唯一块/switch 无分支实证）、T169→probe 双例、T193→NIC 口径；17 原子补例落 | PASS |
| 9.6 | 拆到不可再分 | 台账 34 合并例未拆（ID 集零变更） | PASS |
| 9.7 | 修 bug 先红 | P4/P5 分批红绿记录（b1 netbios、b3 static-copy） | PASS |
| 9.8 | 数据场景六类 | T141-T155 边界族 + frames 字节 + 负例非法值 | PASS |
| 9.9 | 业务场景 | terr 族 + probe 三支路（多轮/异常/保活） | PASS |
| 9.10 | 现网常用场景 | dialect 集/IPC$/445-139 有例；现网取证 G-SMB-3 | NOTE |
| 9.11 | 多动作组合流≥2×≥3 | probe_ops_multi_round（3 操作）+ 全会话例（10 命令链）；多流复合面 flows=2 例 | PASS |
| 9.12 | 清单先行 | 清单=设计 §7 324 点；出处声明在 testcase §5.5（已入仓） | PASS |
| 9.13 | 数量非目标 | 报告声明 | PASS |
| 9.14 | 存量逐条审计去向 | 审计已入仓（testcase §5/§6）；13 对取一经裁定不做（ID 集冻结，G-SMB-12） | PASS |
| 9.15 | A 类直写 | 正例直写无代码改动依赖 | PASS |
| 9.16 | B 类另立项 | G-SMB-1 已闭（P4 落码） | PASS |
| 9.17 | C 类注明不做 | B′ 两分类表（已入仓） | PASS |
| 9.18 | C 类不冒充覆盖 | probe 不进分母（coverage_gate 行） | PASS |
| 9.19 | 动词≠覆盖 | 命令序 + msg_id 连续性逐条断言 | PASS |
| 9.20 | 每取值至少一例 | 修轮补错误码例 6 例（含 0xC0000120/7B/0021/03E3/0080 面）+ disposition 4 例 | PASS |
| 9.21 | 分支级审计 | 9 命令错误面 terr 族覆盖 | PASS |
| 9.22 | 承载位置全扫 | 层内 smb + operations 两级（严格解码双级在案） | PASS |
| 9.23 | 正交组合矩阵 | §12.2 矩阵 32 格缺口未补 | PASS |
| 9.24 | 地址族对称 | IPv4 279 例 vs IPv6 1 例（probe） | PASS |
| 9.25 | 版本扩展随矩阵 | SMB3 高级族 T171-T185 有例 | PASS |
| 9.26 | 补齐顺序 | 不适用（已实现） | PASS |
| 9.27 | 断言边界注明 | probe §3 断言纪律 + NIC checksum 观察边界注 | PASS |
| 9.28 | 字段出现≠顺序对 | cmd 序列 + msg_id 连续性断言 | PASS |
| 9.29 | 补全后全量跑 | CASE_PROTO=smb 308/308（canonical 复跑） | PASS |
| 9.30 | 增量全绿不算 | 全量在案 | PASS |
| 9.31 | 断言以 pcap 钉 | pin=落盘帧数（3 例 tshark 复核） | PASS |
| 9.32 | 动态整格 | 仅 inc 一格（四元组）；业务键零格 | PASS |
| 9.33 | 整格不许抽样代表 | 无超范围"已覆盖动态"声称 | PASS（注） |
| 9.34 | 动态三问 | inc 语义 ✓/确定性 ✓/回绕未测 | NOTE |
| 9.35 | 锚流身份 | tcp.stream + 端口锚（40001/40002） | PASS |
| 9.36 | 代码不支持钉现状 | 静态复制拒绝走负例（未删例） | PASS |
| 9.37 | 派生编号撞车 | 多流端口 40001/40002 显式拉开 | PASS |
| 9.38 | 聚合断言混入 | 服务端口 445/139 显式指名 | PASS |
| 9.39 | 多流×静态标量互斥 | 5 多流例全用 dyn 对象（b3 修正） | PASS |
| 9.40 | 共享流序号 | 不适用（无子实体共享面） | PASS |
| 9.41 | 清单先行无遗漏 | 遗漏 6 点（计 G2） | PASS |
| 9.42 | 用例回指规范/设计 | ID 内嵌 T 号 + notes 行 | PASS |
| 9.43 | 断言输出非摆设 | fields 值 + frames hex 双钉 | PASS |
| 9.44 | 失败路径真会红 | 17 负 + 3 probe 负全被拒（锚词命中） | PASS |
| 9.45 | 全量全绿 | 291 pass, 0 fail, 0 error | PASS |
| 9.46 | 数据全表扫 | T141-T155 + frames 字节 + 负例非法值 | PASS |
| 9.47 | 取值集合全枚举 | 错误码 5 缺（计 G2） | PASS |
| 9.48 | 业务逻辑点反推 | 清单出处=规范反推（testcase §5.5 声明，备份） | PASS（注 G1） |
| 9.49 | 多流/多会话/多事务 | 三者各≥1 例；交错项缺（顺序发射） | NOTE |
| 9.50 | 复合大场景≥3 类 | tpos164 = 多会话+多流+多事务（tshark 实证） | PASS |
| 9.51 | 正交满格组合 | 矩阵 32 格缺口未补 | PASS |
| 9.52 | 对账两行+出处声明 | testcase §5.5 对账（112=50+30+32，备份） | PASS |
| 9.53 | 门3 抽最复杂点数 | 本报告 §2：tpos164 14 点 3 类达标 | PASS |
| 10.1 | 文档改完对照规范核对 | p123-report §2 自审（3+2+3 轮） | PASS |
| 10.2 | 改需求文档先对旧文档 | p123-report §2 逐条核对记录 | PASS |
| 10.3 | 代码先自查走读 | p4-report §2/§9 自审轮次 + 本审复核 | PASS |
| 10.4 | 自查后构建+vet+测试(-race) | 本审重跑 layers/core/schema 三包全绿 | PASS |
| 10.5 | 修完再审 | f4d93a8 修轮 + 复验记录 | PASS |
| 10.6 | 测对函数/路径 | 本审逐例对照（presence/translate/严格解码） | PASS |
| 10.7 | 输入真能触发 | 负例经 MCP 实测被拒 | PASS |
| 10.8 | 断言输出非摆设 | 同 9.43 | PASS |
| 10.9 | 规范行/性能指标全覆盖 | 规范行=6 点零例（G2）；性能未实测（NOTE） | PASS |
| 10.10 | 全绿但测错=没测 | 6 点零例即此面 | PASS |
| 10.11 | 汇报含自审结论 | p4-report §2/§9 自审轮次 | PASS |
| 11.1 | 先白话结论 | p4-report 首行白话 | PASS |
| 11.2 | 协议名带上下文 | 报告统一 SMB2/SMB3 | PASS |
| 11.3 | 禁内部编号黑话（对用户） | 对主线程按 §15.10 贴证据（技术面例外） | PASS（注） |
| 11.4 | 拍板给两选项+建议 | p4-report §8 G-SMB-2 三候选上报 | PASS |
| 11.5 | 回复前自查黑话 | 技术细节入 /tmp 报告与文档 | PASS |
| 12.1 | 每流可变字段五策略 | 引擎 allowlist 支持（layer_dyn.go:17-22）；smb 业务键零开 | PASS |
| 12.2 | 至少覆盖四元组 | ip src/dst + tcp src_port/dst_port 在 allowlist | PASS |
| 12.3 | 业务字段清单 | 34 字段（4 候选/30 关）在 design §14.12（备份）；实现零开 | PASS |
| 12.4 | flows=N 第 i 条确定性 | inc 实证 40001/40002；rand seed 面零例 | PASS（注） |
| 12.5 | 不写动态按 fixed | 缺省固定端口 445/139 | PASS |
| 12.6 | 任务合并不丢动态 | 框架未动 | PASS |
| 12.7 | 任务封顶不改写序列 | 未动 | PASS |
| 12.8 | 任务级动态 | 未动 | PASS |
| 12.9 | 静态复制拒绝 | probe_neg_static_copy（锚 semantic.go `layers pin a static four-tuple but flows > 1`）+ b3 4 例 | PASS |
| 12.10 | 保底不等于动态 | 多流例显式 dyn，未依赖保底 | PASS |
| 12.11 | 动态值仍住层 | dyn 对象写 layers[1].tcp.src_port | PASS |
| 12.12 | 不许另起顶层动态字段 | 顶层仅 layers/group_id | PASS |
| 12.13 | group_id 参考基线 | 5 例 group_id 跨流绑定 | PASS |
| 12.14 | 逐协议动态清单+序号算法 | design §14.12（备份）引 worker.go/layer_dyn.go 行号 | PASS |
| 12.15 | 五类动态测试 | 只 inc + 静态复制拒绝 | PASS |
| 12.16 | 抽查可定位序号算法 | layer_dyn.go allowlist + resolver 実读可定位 | PASS（注） |
| 13.1-13.6 | schema 文件族 | generated/layers.generated.json smb 行 38 字段在表 | PASS |
| 13.7-13.10 | 校验唯一入口 | suite 经 MCP→ValidateStrategy 同入口 | PASS |
| 13.11 | MCP 描述生成 | schemagen 未跑（本审禁跑）；描述表含 smb 层 | PASS（注） |
| 13.12 | flowb_query_layers 实时视图 | 同注册表；registry.go:1171 实读一致 | PASS |
| 13.13 | struct 标签字面量锁 | TestLayersGeneratedMatchesRegistry 绿 | PASS |
| 13.14 | 前端类型生成 | 本波未动 web 生成面 | PASS |
| 13.15 | 删 cps/ratio | 未动 | PASS |
| 13.16 | 文档索引 | config-schema.md 生成面未动 | PASS |
| 13.17 | 改语义先改 schema | registry +4 string 字段 → 已重跑生成（merge stat +12 行） | PASS |
| 13.18 | 注册表变更重跑生成并提交 | layers.generated.json 随合并提交 | PASS |
| 13.19 | 生成文件过期测试 | TestLayersGeneratedMatchesRegistry 本审 PASS | PASS |
| 13.20 | 键缺席走缺省/null 拒 | 空 smb 层翻译出全默认（translate 注释）；null 由严格门拒 | PASS |
| 13.21 | 非法值语义校验 | 17 负例锚 validate 文案 | PASS |
| 13.22/13.23 | schema 非第四文档/冲突以 schema 为准 | 无冲突 | PASS |
| 13.24 | 评审先查 schema | 本审 38=38 逐字段核对 | PASS |
| 13.25 | 手写形状打回 | 无手写形状 | PASS |
| 13.26 | null 兼容打回 | 无 null 兼容分支 | PASS |
| 14.1 | 用例即 MCP 任务 spec | spec_json=策略 config（suite 直发） | PASS |
| 14.2 | 不许两套真相 | 单文件真相 | PASS |
| 14.3 | 工具直接消费用例 | flowb_run_protocol_suite 消费 | PASS |
| 14.4 | 旧扁平用例改写 | 279/279 全 layers | PASS |
| 14.5 | 历史口径不许原样带入 | 43/291 例 prose 旧包数公式与 pin 矛盾 | PASS |
| 14.6 | 迁移先跑后钉 | pin 与落盘一致（suite + 3 例复核） | PASS |
| 14.7-14.9 | 真实流程三步 | MCP 建任务→引擎落盘→tshark 校对（本审复跑） | PASS |
| 14.10 | 只跑离线/只数包不算 | fields 值 + frames hex 断言 | PASS |
| 14.11 | 负例走真实流程 | 20 负例全锚实现文案 | PASS |
| 14.12 | 失败报成功同级 bug | expect_error + 任务级失败传播 | PASS |
| 14.13 | distinct 聚合分侧 | 多流端口 distinct 排除 445（显式） | PASS |
| 14.14 | 派生端口排除或写规则 | 无派生（单连接） | PASS |
| 14.15 | 字段方向先想清 | directional=true，请求上/响应下 | PASS |
| 14.16 | 全绿 + pcap 落盘 | 291/291 + 288 pcap | PASS |
| 14.17 | 抽查三点 | spec=任务配置/字段值断言/锚词俱在 | PASS |
| 14.18 | 二进制与 HEAD 同代 | 门2-3 绿 | PASS |
| 14.19 | 全量非增量 | CASE_PROTO=smb 全量 291 | PASS |
| 14.20 | 包号从落盘拿 | pin=tshark 帧数（3 例实证） | PASS |
| 15.1 | 开工门交 14 行表 | 表在 design §14（备份） | PASS |
| 15.2 | 证据三选一 | 表内证据为 P1 版行号（已漂移，需回填） | PASS |
| 15.3 | 三行强制展开 | §14.1/§14.3/§14.12（备份） | PASS |
| 15.4 | 门2①顶层零残留 | 门2-1 绿；presence 红线未登记 smb（运行期判死在） | PASS（注 G3） |
| 15.5 | 门2②全量绿+锚词 | 291/291 + 负例锚词命中 | PASS |
| 15.6 | 门2③二进制同代 | 门2-3 绿 | PASS |
| 15.7 | 门2④覆盖反查 | coverage_gate 32/32 绿 EXIT=0 | PASS |
| 15.8 | 门3 挂 14 行表（回填证据号） | design v2.2.1 §14 十四行表在仓（P4 落码实读回填证据号）；scoped 复评核过 | PASS |
| 15.9 | 抽查三条可定位 | 本报告 §1 三条全定位 | PASS |
| 15.10 | 汇报白话+三门证据 | p4-report + 本报告 | PASS |
| 15.11 | 三门纪律 | 门1（表在备份）/门2 绿/门3 本表 | PASS（注 G1） |
