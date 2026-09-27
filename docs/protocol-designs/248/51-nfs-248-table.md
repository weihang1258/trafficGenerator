# NFS（D-NFS-1 #51）P6 248 条款逐条比对表

> 口径：docs/CORE_MEMORY.md（15 节 481 行，本审实读条款全文）。落点=nfs #51 实测证据（file:line / 用例号 / 机核数字）。**本表已按 P6 修轮后状态更新（分支 `pipe/nfs-p6fix` 集成 `3b9968a`；scoped 复评关单）：GAP(1)/GAP(3)/GAP(4)/m1/m2 全部关闭（除显式 open 缺口外）。** 判定：PASS=满足，GAP(n)=缺口（缺口=本审 C/M/m 编号或已登记 G-NFS-x/A′项），NOTE=注记。

| 条款 | 要求 | nfs 落点 | 判定 |
|---|---|---|---|
| 1.1 | 地址只写 ip 层 | 用例不显式写地址（194×[tcp,nfs]+4×[udp,nfs]，缺省四元组）；顶层地址键唯一出现=判死负例（src_ip 锚 flat） | PASS |
| 1.2 | 端口只写 tcp/udp 层 | 端口住 tcp/udp 层条目；显式端口仅 nfs_neg_static_copy_multiflow（tcp.src_port=40000，判死负例） | PASS |
| 1.3 | 流数量只写 flow_control | 用例零 `count`（门2-1 绿）；修轮后多流复合例 `nfs_t195_v3_multiflow_composite`（flows=3）交付 | PASS |
| 1.4 | 禁 layers 与顶层五键混用 | 194 例顶层仅 layers；4 红例执法键=count×2/src_ip×1/nfs×1 | PASS |
| 1.5 | 混用示例/用例/文档都算跑偏 | 无混用示例；p123 §1.1 旧键去向逐条 | PASS |
| 1.6 | 门①层链能跑通 | 197/197 经 MCP 真跑（lane4 + canonical 复跑；含 167 正例与 63 包复合大例） | PASS |
| 1.7 | 门②旧格式彻底移除 | 顶层 count/nfs 清零；CheckProtoFlat presence 判死（strategy_convert.go:8543-8546） | PASS |
| 1.8 | 示例只给严格层链形 | 全量层链形（168 存量改写 + 33 扁平补齐） | PASS |
| 1.9 | 暂不支持时标注目标形状 | G-NFS-7/8/9 登记（MOUNT 分连接/回调/交错保活重传） | PASS |
| 1.10 | 汇报分开说跑通/清旧字段 | p4-report §2/§3 分节 | PASS |
| 1.11 | 顶层白名单（layers/flow_control 家族/output） | 修轮后两红例恢复契约形状（`src_mac` 走 `checkLayerFlatConflict` 锚词、`ttl:300` 走 `ValidateConfigRanges` 锚词）+ 门2-1 逐键豁免；group_id 框架键白名单在案 | PASS |
| 1.12 | 无可住层须立项补层，不许豁免 | 无游离字段；四元组动态住 ip/tcp/udp（layer_dyn.go:18-20） | PASS |
| 1.13 | 门2①按白名单执行 | 门2-1 脚本按白名单 + 豁免（presence "top-level" / 扁平 "flat 或点名键"逐键豁免 + group_id 框架键） | PASS |
| 2.1 | 策略=单模板自带 flow_control | nfs 策略模板；spec_json 即策略 config（197 例） | PASS |
| 2.2 | 任务=多策略合跑+总量封顶 | 框架语义未动 | PASS |
| 2.3 | 策略先限速任务再封顶 | 未动 | PASS |
| 2.4 | 任务 ID={taskID}-{strategyID} | 未动 | PASS |
| 2.5 | flows=N 复制 N 条 | 框架；nfs 正例多流面交付（flows=3 复合例） | PASS |
| 2.6 | spec 不管数量 | 用例 spec 无 count | PASS |
| 2.7 | 按流变化走动态 | 框架面在；nfs 业务字段零动态（G-NFS-4 挂账） | NOTE |
| 2.8 | 未写动态 src_port 保底 12345+i | 框架 | PASS |
| 2.9 | 其余字段按流变化必须写动态 | nfs 14 业务键全关（`grep '"nfs"' layer_dyn.go` 零命中） | GAP(G-NFS-4) |
| 2.10 | 讲数量分清策略复制/任务封顶 | p123 §1.1 | PASS |
| 2.11 | 讲变化按 §12 | 同上 | PASS |
| 3.1 | 多会话 sessions[]/flows[] 显式 | registry 标量 `sessions` >1 链上双拒绝；多流口径=flow_control——复合例 flows=3 交付 | PASS |
| 3.2 | 每会话独立 ID/四元组/生命周期 | 单 flow 语义全线在（XID/clientid 派生）；多流面由复合例 3 流定序（group_id fixed） | PASS |
| 3.3 | 会话内事务有序序列 | t191 MOUNT→GETATTR/LOOKUP/READ/WRITE/REMOVE→UMOUNT（21 包）；t192 SETCLIENTID→CONFIRM→2 COMPOUND | PASS |
| 3.4 | 事务前置条件 | MOUNT fh 继承（nfs.go:512 buildOpSequence）；OPEN stateid 引用 nfs.go:1248 | PASS |
| 3.5 | 触发动作 | 同上逐 op 展开 | PASS |
| 3.6 | 成功分支 | 168 正例 | PASS |
| 3.7 | 失败分支（重试/跳过/中断） | COMPOUND 截断 t155、单 op 失败 t156、RPC 层 t158-t167、全局 t151 | PASS |
| 3.8 | 控制关联数据流显式字段 | v3 MOUNT 同连接（G-NFS-7 登记）；v4 无副流 | PASS(登记) |
| 3.9 | 关联写清会话/事务/决定字段 | applyOpenReplyStateid（nfs.go:1248）+ same_as 断言（t090/t093/t118） | PASS |
| 3.10 | 被关联流独立 ID/四元组/握手 | 无副流（G-NFS-7 声明在案） | PASS(不适用) |
| 3.11 | 各流顺序/并发/交错写清 | 单流严格有序（planSession）；交错不支持（G-NFS-9） | PASS |
| 3.12 | 可交错写清调度+时间戳 | 不支持（G-NFS-9 登记） | PASS(登记) |
| 3.13 | 不许连续重复冒充编排 | t191/t192 为真实编排（含自动补全语义） | PASS |
| 3.14 | 无长连接豁免≠多流豁免 | 有长连接；单包多载荷已覆；多流并发面复合例交付 | PASS |
| 3.15 | 无多会话≠无多事务（三项各一例或立项） | ①t191 ②t152/t155/t156+t158-t167 ③长保活立项 G-NFS-9 | PASS |
| 3.16 | CWMP 范本照补 | 差异诚实声明（无 driven_by；MOUNT 同连接） | NOTE |
| 3.17 | 多流设计五件套 | design v2.1.1 §13.2（已入版） | PASS |
| 4.1 | 连接模型 | design §1.1/§1.2（v3 TCP/UDP、v4 仅 TCP） | PASS |
| 4.2 | 命令/消息表 | design §2.2/§2.3/§2.4/§2.5 逐表 | PASS |
| 4.3 | 状态机 | design §4.1（v4）/§4.2（v3）/§4.3（多会话） | PASS |
| 4.4 | 字段表 | design §3.1-§3.4（含 §2.8 sattr3/fattr4 编码） | PASS |
| 4.5 | 错误处理表 | design §2.9/§9.1-§9.3 | PASS |
| 4.6 | 超时与活性 | design §5.6/§9.5#3（不模拟重传，G-NFS-9） | PASS |
| 4.7 | NAT/代理/被动 | 无 NAT 面（G-NFS-8 登记） | NOTE |
| 4.8 | 版本/方言差异 | design §1.2 v3/v4.0/v4.1 对比；v4.1 仅对照 | PASS |
| 4.9 | 有 RFC 查 RFC 注编号章节 | RFC 1813/7530/7531/5531/4506 逐节引用 | PASS |
| 4.10 | 无 RFC 以官方规范为准 | 不适用（有 RFC） | PASS |
| 4.11 | 不许博客二手代替原文 | 三路原始（RFC 原文 + Linux nfs(5) + MS Learn NFS overview） | PASS |
| 4.12 | 规范原文 | p123 §2 10.1（RFC 原文实取核实） | PASS |
| 4.13 | 商业软件实际行为 | Linux nfs(5) / MS Learn 7 行映射（p123 §2） | PASS |
| 4.14 | 可靠开源实现思路 | tshark 3.6.14 `nfs.*` 648/`rpc.*` 82 字段实测；不搬码 | PASS |
| 4.15 | 三路不一致取舍写清 | design §9.5 偏离登记；xprtsec 待确认 | PASS |
| 4.16 | 商业行为逐条映射用例号 | p123 §12.4 映射；G-NFS-7/8 确认方式在案 | PASS |
| 4.17 | 关键决策候选方案对比表 | design §12.6 五候选 | PASS |
| 4.18 | 不许单方案自说 | 五案在案 | PASS |
| 4.19 | 每表格行/字段/错误码三选一 | design §12.2-§12.4 96 格逐格结论；错误码逐值面见 9.47 | PASS/交叉 GAP(G-NFS-2) |
| 4.20 | 每条目对应至少一用例 | 73 点=63 覆+10 缺口立项（G-NFS-2） | PASS(缺口立项) |
| 4.21 | 动手前缺口矩阵 | design §12 先行（P1 产物） | PASS |
| 4.22 | 三张子表齐 | ①73 格 ②16 行 ③7 行=96 格 | PASS |
| 4.23 | 设计评审先看矩阵 | 门1 获批（14 行表 p123 §1） | PASS |
| 4.24 | 规范实现冲突先改实现 | sessions 拒绝顺序前移（commit 79cd069，layer_gen.go:201-203） | PASS |
| 5.1 | 设计写明依赖 | design §13-P2 依赖声明 + registry DependsOn/TransportOn | PASS |
| 5.2 | 写明出错处理 | design §8/§9 + layer_gen.go 锚词（no config/multi-stream） | PASS |
| 5.3 | 无依赖/错误分支不许实现 | 有 | PASS |
| 5.4 | 无依据不许定字段/流程/缺省 | 字段均有 RFC 出处；2049 缺省=legacy 同源 | PASS |
| 5.5 | 不确定标待确认+确认方式 | xprtsec 待确认；G-NFS-1..10 立项 | PASS |
| 5.6 | 结论指文档章节/代码行 | 本报告逐条点行 | PASS |
| 5.7 | 指不出直说不知道 | G-NFS-4/5/6 曾挂裁定，已裁 | PASS |
| 5.8 | 回复前自查出处 | — | PASS |
| 5.9 | 抽查三条定位不到打回 | p6-review §2 三条点行/例号 | PASS |
| 6.1 | 性能目标/预算/边界 | design §14.6（O(ops) 流式、pcap/NIC 双路） | PASS |
| 6.2 | 六指标列全 | testcase §7.3 六类场景表；数字待基准（诚实声明） | PASS/待确认 |
| 6.3 | pcap/NIC 两路分别验收 | pcap 路本轮已验（198/198 落盘）；NIC 路本轮未跑 | NOTE |
| 6.4 | 依据结合实现路径 | 流式事件、无全量收集、无共享锁 | PASS |
| 6.5 | 无依据数字标待确认 | testcase §7.3 末段"无任何性能用例"诚实声明 | PASS |
| 6.6 | 六类性能场景 | testcase §7.3 表（多为立项） | PASS |
| 6.7 | 断言实际指标不只无报错 | 168 正例 packet_count + 字段双钉 | PASS |
| 6.8 | 超预算仍不合格 | — | PASS |
| 6.9 | 设计须含性能节 | design §14.6 | PASS |
| 6.10 | 无目标不得宣称完成 | 已诚实声明 | PASS |
| 7.1–7.3 | 三份文档定位 | design v2.1.1 + testcase v1.1.0 已入版（修轮 02df15b）；未碰 CODE_DESIGN/TEST_CASES | PASS |
| 7.4 | 历史文档保留参考 | — | PASS |
| 7.5 | cases 是产物回指编号 | 192 例带 T 号回指 design §7；6 红例为红例族无 T 号 | PASS |
| 7.6–7.7 | 三者关系/冲突序 | — | PASS |
| 7.8–7.9 | 先核心再设计再用例 | 门1 先行（P1→P2→P3→P4） | PASS |
| 8.1 | 改哪几个文件 | design §14.1/§14.7 清单逐字（translate/convert/layer_gen/coverage_gate/pipe_gate） | PASS |
| 8.2–8.8 | 签名/结构/流程/错误/性能/冲突/回滚 | design v2.1.1 §14 八要素（已入版） | PASS |
| 8.9 | 未定稿不开工 | 门1 获批=定稿=开工门 | PASS |
| 8.10 | 需求变先改设计 | — | PASS |
| 8.11 | 不许代码先行文档后补 | P1–P3 先行 | PASS |
| 8.12–8.13 | 开工贴条目/无条目打回 | p4-report 挂 D-NFS-1 §14 | PASS |
| 9.1 | 用例登记 TEST_CASES | 回指 testcase v1.1.0 §2/§3（已入版） | PASS |
| 9.2–9.4 | 三源生成 | RFC + D-NFS-1 + 现网（Linux nfs(5)/MS Learn）+ tshark 实测 | PASS |
| 9.5 | 每行/字段/错误码有用例 | 73 点对账 63/73；错误码仅 7 值入例 | GAP(G-NFS-2) |
| 9.6 | 一例一行为；拆分到底 | 197 ID 唯一；T-154/T-158 按 §3.3 合并删除（m1） | PASS |
| 9.7 | 修 bug 先复现变红 | P5 三处失败先行（sessions 顺序/ttl 锚词/门豁免） | PASS |
| 9.8 | 数据场景六变体 | 空值 t038/t051/t185、超长 t026/t028/t040/t065、非法 t050/t055b/t088a/b、边界 t025/t027/t142/t189；边界 4 例缺（A′-5） | PASS/交叉 A′-5 |
| 9.9 | 业务序列/乱序/中断/并发 | t191/t192 序列、t155 截断；交错不支持（G-NFS-9） | PASS |
| 9.10 | 现网场景；复杂度 9.50 下限 | 复合大场景达下限（多流×多事务×异常 3 类，nfs_t195_v3_multiflow_composite） | PASS |
| 9.11 | 多动作组合流≥2 条×≥3 动作 | t191（7 动作）/t192（4 往返） | PASS |
| 9.12 | 清单先行 | design §12 矩阵先行 | PASS |
| 9.13 | 清单无遗漏是目标 | 96 格逐格结论 | PASS |
| 9.14 | 存量逐条审计去向 | testcase §3 逐族 201→198 逐条去向（14 缺号逐个交代） | PASS |
| 9.15–9.19 | A/B/C 三分类；动词≠覆盖 | A′/B′ 清单在案；序列矩阵逐条对照 | PASS |
| 9.20 | 取值表逐值建例 | NFS 错误码仅 7/25+ 值 | GAP(G-NFS-2) |
| 9.21 | 分支级审计每分支一例 | share_access/deny 各分支、COMPOUND 截断分支、accept 0-5/reject 0-1 全值 | PASS |
| 9.22 | 扫遍全部承载位置 | v3/v4 双版本 × TCP/UDP 双载体 × accept/reject 双面 | PASS |
| 9.23 | 正交矩阵逐格标记 | 流数维复合例交付；地址族维维持 open（IPv6 零例，A′-4） | PASS/GAP(A′-4) |
| 9.24 | 地址族对称覆盖 | IPv6 实测 0 例 | GAP(A′-4) |
| 9.25 | 地址族扩展随矩阵扩 | G-NFS-10 立项 | PASS(立项) |
| 9.26 | 补齐顺序 | A′ 顺序在案 | PASS |
| 9.27 | harness 做不到逐项注明 | 方向/包序以 tshark 断言表达 | PASS |
| 9.28 | 不许字段出现冒充顺序 | t191/t192 断言 `nfs.opcode` 序列（24,9 / 35,36,24,9,22,4,25）+ same_as | PASS |
| 9.29 | 补齐后全量全绿 | 197/197（lane4 + canonical 复跑） | PASS |
| 9.30 | 只跑增量=未完成 | 全量 | PASS |
| 9.31 | 断言以真实 pcap 校准 | P5 先跑后钉（189/192→192/192 三轮校准） | PASS |
| 9.32–9.36 | 动态整格（字段×策略） | nfs 业务字段全关（G-NFS-4）；四元组框架面 | GAP(G-NFS-4) |
| 9.37–9.38 | 派生编号/聚合排除 | 单流无派生口、无 distinct 聚合断言 | PASS(不适用) |
| 9.39 | 多流×静态标量互斥 | nfs_neg_static_copy_multiflow（flows=2+静态端口判死）即执法实例 | PASS |
| 9.40 | 共享流序号动态字段 | 不适用（无多流） | PASS |
| 9.41–9.45 | 测试评审五件事 | 本报告 | PASS |
| 9.46 | 数据场景规范全表扫 | 部分缺（A′-5 四例） | GAP(A′-5) |
| 9.47 | 取值集合逐值枚举 | NFS4ERR_* 未逐值（7 值）；testcase §8 已自认并入 G-NFS-2 | GAP(G-NFS-2) |
| 9.48 | 业务场景规范反推 | design §12.1/§12.2 逐格（出处=RFC 反推，非用例反推） | PASS |
| 9.49 | 多流/多会话/多事务各一例+真实编排 | 多事务✓；**多流零例**（多会话按 N1 结构性拒绝） | GAP(1) |
| 9.50 | 复合大场景≥3 类交织 | 未达（t191=1 类；t154_err/t155=2 类） | GAP(1) |
| 9.51 | 组合矩阵满格 | 流数维缺格 | GAP(1) |
| 9.52 | 审计声明出处+对账两行 | testcase §8（73 vs 63；96 格逐格；出处=RFC/官方反推） | PASS |
| 9.53 | 门3 至少一条抽最复杂用例+当场点数 | t191=21 包/7 往返/1 流/0 异常 ⇒ **1 类** < 9.49/9.50 下限 | **GAP(1)（打回本体）** |
| 10.1 | 文档改完对规范逐条核对 | p123 §2 10.1 | PASS |
| 10.2 | 改需求先对旧需求逐条核对 | p123 §2 10.2（v2.0.4 对照，§1–§11 零删除行） | PASS |
| 10.3 | 代码改完逐行走读自查 | P4 三轮/P5 两轮；**但 M1 重复块漏检**（自审查了错误配对） | NOTE(GAP(2)) |
| 10.4 | 构建+vet+测试含 -race | p4-report §5 记录 go build/vet/-race 绿；本轮 lane suite 复跑绿；本审只读未独立跑 -race | NOTE |
| 10.5 | 修完再审（fix 本身也要审） | P5 修轮 → 复评在案 | PASS |
| 10.6–10.10 | 测试评审（测对路径/真触发/断输出/全绿≠测对） | 本报告 | PASS |
| 10.11 | 闭环+结论（自审轮数） | P4 3 轮/P5 2 轮末轮干净（p4-report §5） | PASS |
| 11.1–11.5 | 白话（先结论/带上下文/反黑话/给选项/自查） | p4-report 首段 + p6-review 首段 | PASS |
| 12.1 | 五策略全开（四元组） | layer_dyn.go:335-347/382-394（fixed/list/pattern/inc/rand 五种实测在码）；业务键全关 | PASS(框架)/NOTE |
| 12.2 | 动态覆盖四元组 | layer_dyn.go:18-20（ip.src/dst/ttl + tcp/udp.src_port/dst_port） | PASS |
| 12.3 | 业务字段清单 | G-NFS-4 未裁定未开 | GAP(G-NFS-4) |
| 12.4 | flows=N 按序号确定性+seed 可复现+回绕 | 框架级（LCG seed+序号） | PASS |
| 12.5 | 不写动态按 fixed | 框架 | PASS |
| 12.6–12.8 | 任务级动态不丢规则/只截断/跨策略 | 框架语义未动 | PASS |
| 12.9 | 静态复制拒绝或告警 | nfs_neg_static_copy_multiflow 实例（锚 "static copy"） | PASS |
| 12.10 | src_port 保底≠动态 | 框架 | PASS |
| 12.11–12.13 | 动态住层链/不另起顶层/对齐 tuples 语义 | 地址住 ip、端口住 tcp/udp、数量 flow_control | PASS |
| 12.14 | 逐协议清单+序号算法可定位 | XID：layer_gen.go:91-97/136、nfs.go:497；clientid：nfs.go:114/443（p123） | PASS |
| 12.15 | 测试五类（回绕/复现/轮转/替换/静态复制拒） | 静态复制拒有例；余四类为框架级且 nfs 无业务动态面 | NOTE |
| 12.16 | 抽查动态结论能否定位代码 | 本审 §2 抽 XID 定位成功 | PASS |
| 13.1–13.6 | schema 文件（defs/strategy/task/batch/layers/generated） | registry nfs 行 14 字段 ↔ generated 14 字段（名/型/缺省逐键一致，机核） | PASS |
| 13.7–13.10 | 校验入口唯一 | 未动 | PASS |
| 13.11–13.16 | 派生只读下游（schemagen/query_layers/webgen/索引） | generated 123 层含 nfs；flowb_query_layers 实时视图 | PASS |
| 13.17 | 改语义先改 schema | registry 先行（P4a 注册行既有） | PASS |
| 13.18 | 注册表变更重跑生成 | 本次未改 registry；generated 与 registry 一致（机核）；schemagen 未跑（本审要求不跑） | PASS |
| 13.19 | 过期测试变红 | 未运行 TestLayersGeneratedMatchesRegistry（本审只读约束）；以字段级机核替代 | NOTE |
| 13.20–13.21 | 缺席走缺省/null 拒/非法值语义拒绝 | UnmarshalJSON 严格面（N3 数组形） | PASS |
| 13.22–13.23 | schema 非第四文档/冲突以 schema 为准 | — | PASS |
| 13.24–13.26 | 评审先查 schema/手写形状/null 兼容 | 本审 §7 | PASS |
| 14.1 | 用例 spec 即 MCP 任务配置 | spec_json 直驱（lane4 198 例真建任务） | PASS |
| 14.2 | 不许两套写法 | 单权威 | PASS |
| 14.3 | 执行工具直接消费用例 | flowb_run_protocol_suite | PASS |
| 14.4 | 旧用例随层链改写 | 168 改写 + 33 处置（9 删/3 改锚/其余去扁平） | PASS |
| 14.5 | 历史口径不带入 | 先跑后钉（锚词三修、packet_count 实测重钉） | PASS |
| 14.6 | 先跑拿 pcap 再钉 | P5 校准轮记录在案 | PASS |
| 14.7–14.9 | MCP 建任务→引擎生成→tshark 校对 | lane4 suite 198/198 全链真跑 | PASS |
| 14.10 | 离线/只数包/只断言不失败都不算测 | 字段+frames 双面断言 | PASS |
| 14.11 | 负例经 MCP 被拒锚词入断言 | 30/30 带真锚词；expect 严格双键（机核零残留） | PASS |
| 14.12 | 假成功与失败同级 bug | 6 红例创建期拒（无 pcap）+24 引擎期 .neg.pcap 占位 | PASS |
| 14.13–14.15 | 端口聚合分侧/派生排除/方向想清 | 单流无聚合断言；方向按 tshark 断言 | PASS(不适用) |
| 14.16 | 全绿+落盘可复查 | 198/198 + lane4 pcaps（168 .pcap + 24 .neg.pcap） | PASS |
| 14.17 | 抽查 spec/字段值/负例锚词 | 本报告 §2/§5 | PASS |
| 14.18 | 二进制与 HEAD 同代 | 门2-3 绿（无 .go 新于二进制） | PASS |
| 14.19 | 全量全绿（非增量） | 全量两跑（-v 与非 -v） | PASS |
| 14.20 | 包号端口从落盘 pcap 拿 | 先跑后钉 | PASS |
| 15.1 | 门1 十四行表+证据 | p123 §1 全文在案；**证据行号漂移 + design 载体未入版** | GAP(4) |
| 15.2 | 证据三选一（文档章节/代码行/用例号） | 表内逐行给证据 | PASS |
| 15.3 | §1/§3/§12 强制展开 | p123 §1.1/§1.2/§1.3 | PASS |
| 15.4 | 门2①顶层零残留 | 门2-1 绿（presence 负例豁免） | PASS |
| 15.5 | 门2②全量绿+负例锚词 | 198/198 + 30 锚词 | PASS |
| 15.6 | 门2③二进制与 HEAD 同代 | 门2-3 绿 | PASS |
| 15.7 | 门2④反查绿后进 P6 | coverage_gate 28/28 | PASS |
| 15.8 | D-条目挂门1 14 行表（回填实际证据号） | 表在报告；证据号未回填（registry.go:1000-1018→现 1143-1161；layer_gen.go:84-89→现 88-90） | GAP(4) |
| 15.9 | 抽查三条点到行/例号 | p6-review §2 三条 | PASS |
| 15.10 | 白话+三门证据 | p6-review §4/§5/§8 | PASS |
| 15.11 | 任一门红停 | 四门绿；但 9.53 抽查命中打回 → 本批停 | GAP(1) |

## 注记（本批判定与挂账，详见 p6-review.md）

- **GAP(1)=打回本体**：§9.49 多流 leg / §9.50 ≥3 类 / §9.53 最复杂用例点数（t191=1 类）未达下限；可达下限=3 类（flow_control 多流+多事务+异常分支），补 A′ 类复合用例（flows≥2）后全量重跑即可翻绿；不补则按 testcase §8 口径"重建后再关单"。
- **GAP(2)**：strategy_convert.go nfs ValidationErrors 块重复（:428-434 与 :458-464，a74ae7b 引入），worker.go:210-211 join 后错误串重复两遍。
- **GAP(3)**：红例②形状收窄（src_mac/ttl→src_ip/count），两例 ID 与内容不符；§1.11-1.13"黑名单漏点照样红"证据面消失（根因=门 2-1 豁免只认锚词含 "flat"）。
- **GAP(4)**：design v2.1.0（§12–§15=D-NFS-1）与 08-nfs-testcase.md 均未入版（全分支扫描零命中）⇒ N2/N3 文档侧回修在库内不可验证；门1 表证据号未回填。
- **已登记挂账（不重复打回）**：G-NFS-2 十点（COMMIT/MOUNT 0/2/4/5/v4 3/11/19/26/27）、G-NFS-4（动态 3 键未裁未开）、G-NFS-10/A′-4（IPv6 0 例）、A′-5（边界 4 例）、T-119；G-NFS-7/8/9 为"明确不支持"登记（MOUNT 分连接/回调/交错保活重传）。
- **NOTE**：T-154/T-158 同 T 双例未按契约 §3.3 合并（m1）；coverage_gate.py check_nfs docstring 仍写"192 例=168 正+24 负"（实断言 198=168+30）；NIC 路与 -race 本轮未独立重跑（3/6/10 相关行已按此标注）。
