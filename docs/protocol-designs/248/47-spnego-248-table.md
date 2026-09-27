# SPNEGO（D-SPNEGO-1 #47）P6 248 条款逐条比对表

> 口径：docs/CORE_MEMORY.md（v15/481 行，2026-09-26）。落点=spnego#47 实测证据（首审 p6-review.md 判打回 C1/C2 → 修轮集成 `ae2ae47` → scoped 复评关单；门3 三条见 p6-review.md §1）。**本表已按修轮后状态更新**：GAP(1)/GAP(2) 关闭（除下文显式保留的 NOTE）。判定：PASS=满足，GAP(n)=缺口编号，NOTE=注记不挡。
> 契约文本：门1 十四行表 + D-SPNEGO-1 正文存于 `/tmp/pipe/47-spnego/p123-report.md`（§1/§3/§4）；ID 权威=testcase §2。scoped 复评=关单（p6fix-scoped-review.md），残留 nit 已清扫。

| 条款 | 要求 | spnego 落点 | 判定 |
|---|---|---|---|
| 1.1 | 地址只写 ip 层 | 20 例 layers ip.src/dst（casegen sLayers；#13 实测 ip 层 192.0.2.61→198.51.100.61） | PASS |
| 1.2 | 端口只写 tcp/udp 层 | tcp.src_port/dst_port（裸 TCP 45061→445；HTTP 45062→80） | PASS |
| 1.3 | 流数量只写 flow_control | 20 例顶层 flow_control.flows；工作 spec 无 count | PASS |
| 1.4 | 禁 layers 与顶层五键混用 | 机核 20 例顶层键 = {layers, flow_control} 唯一，0 混用 | PASS |
| 1.5 | 混用示例/用例/文档都跑偏 | 设计 §2 样例与 p123 §1.1 目标形状均为严格层链；无混用示例 | PASS |
| 1.6 | 门①层链能跑通 | suite 20/20（本审重跑 RESULT 行）；正例 pcap 全部落盘 | PASS |
| 1.7 | 门②旧格式已彻底移除 | 占位 `spnego_neg_unregistered` 已移除；CheckProtoFlat presence 判死 + schema 游离键门（链测 :799-835） | PASS |
| 1.8 | 示例只给严格层链形 | design §2/p123 §1.1 样例严格层链（v1.0.0 扁平示例已作废去向表在案） | PASS |
| 1.9 | 暂不支持时标注目标形状 | 双 profile 双链均可达（实测）；无暂不支持项 | PASS |
| 1.10 | 汇报分开说跑通/清旧字段 | p4-report §2/§5 分节；本报告分列 | PASS |
| 1.11 | 顶层白名单（layers/flow_control 家族/output） | 机核：正例顶层键=layers+flow_control；0 游离（presence 负例形状=链测 :799-813 判死） | PASS |
| 1.12 | 无可住层时立项补层，不许豁免 | 无游离字段（地址/端口住层）；无豁免登记 | PASS |
| 1.13 | 门2①按白名单执行 | pipe_gate 门2-1 两道全绿（本审重跑） | PASS |
| 2.1 | 策略=单模板自带 flow_control | 用例 spec=单 SPNEGO 模板，flow_control.flows 自带 | PASS |
| 2.2 | 任务=多策略合跑+总量封顶 | 框架语义未动（用例经 MCP 建策略+任务） | PASS |
| 2.3 | 策略先限速任务再封顶 | 未动 | PASS |
| 2.4 | 任务 ID={taskID}-{strategyID} | 未动 | PASS |
| 2.5 | flows=N 复制 N 条 | 未动（用例 flows=1） | PASS |
| 2.6 | spec 不管数量 | 用例 spec 顶层仅 layers+flow_control | PASS |
| 2.7 | 按流变化走动态字段 | 四元组动态住 ip/tcp 层（layer_dyn allowlist :18-19）；协议业务面=会话级覆盖 | PASS |
| 2.8 | 未写动态 src_port 保底 12345+i | 框架既有语义（未动） | PASS |
| 2.9 | 其余字段按流变化必须写动态 | p123 §1.3 十行矩阵逐字段开/不开+理由 | PASS |
| 2.10 | 讲数量分清策略复制/任务封顶 | p123 §1 第 2 行 + 本报告 | PASS |
| 2.11 | 讲变化动态按 §12 | 12.x 行 | PASS |
| 3.1 | 多会话 sessions[]/flows[] 显式 | spnego 层 sessions[] 显式（#13 每流 s1/s2 两会话；数量走 `flow_control.flows=2`） | PASS |
| 3.2 | 每会话独立 ID/四元组/生命周期 | 会话 ID 独立；跨流四元组隔离已交付（flows=2，`distinct_values=[45061,45062]`，#13）；同会话内端点覆盖受 planner.go:36-43 约束（裁定见 design v1.5.0） | PASS |
| 3.3 | 会话内事务有序序列 | 事件 kind 状态机 advance（planner.go:261-293）逐消息序 | PASS |
| 3.4 | 事务前置条件 | p123 §1.2 事务表 t1–t4（前置列） | PASS |
| 3.5 | 触发动作 | 同上（发 init/收 resp/补 MIC/targ） | PASS |
| 3.6 | 成功分支 | 同上（supportedMech∈列表→completed） | PASS |
| 3.7 | 失败分支 | 降级拒/终止 + 6 负例 task error（零假成功） | PASS |
| 3.8 | 控制关联数据流须显式关联字段 | 无副流（诚实声明 p123 §1.2）；请求-响应由 supportedMech+MIC 输入双字段关联 | PASS |
| 3.9 | 关联写清会话/事务/决定字段 | 归属 sN/tM + supportedMech/MIC 输入（p123 §1.2） | PASS |
| 3.10 | 被关联流独立 ID/四元组 | 无副流，不适用（声明在案） | PASS |
| 3.11 | 各流顺序/并发/交错写清 | p123 §1.2 时间线：会话内严格序、会话间自称并发 | PASS |
| 3.12 | 可交错写清调度+时间戳 | 实际无交错机制（Generate 顺序发射）→ 声明与实况差见 GAP(2) | GAP(2) |
| 3.13 | 不许连续重复冒充编排 | #13 修轮后：两流×每流两会话，s1（krb+mskrb→accept_completed）与 s2（NTLM→reject(2)）候选列表/negState 逐包不同且有异常终止；非重复冒充 | PASS |
| 3.14 | 无长连接豁免≠多流豁免 | 多流面交付：`flow_control.flows=2` + `tcp.src_port` inc 动态 → 两条四元组独立流（45061/45062），跨流 `distinct_values` 聚合断言 | PASS |
| 3.15 | 多轮/非正常/长保活各一例或立项 | ①#13 每流两会话多轮 ②#13 s2 reject 异常终止 + #12/#15–#19 ③#13 流生命周期；服务端主动异常形 G-SPNEGO-2 维持立项 | PASS |
| 3.16 | CWMP 范本照补 | 差异点诚实声明（无 driven_by/无副流） | PASS |
| 3.17 | 多流设计五件套 | p123 §1.2 会话表/事务序列/关联关系/插入位置/时间线 五件齐 | PASS |
| 4.1 | 连接模型 | p123 §10 行 1（双 profile：HTTP carrier / 裸 TCP 字节流） | PASS |
| 4.2 | 命令/消息表 | p123 §10 行 2 + §10.2 事件×进展矩阵 35 格 | PASS |
| 4.3 | 状态机 | p123 §10 行 3 + planner advance 四态（initial→init→responded→(mic)→terminal） | PASS |
| 4.4 | 字段表 | p123 §10 行 4 + §10.3 变体表 15 行（逐 tag/length） | PASS |
| 4.5 | 错误处理表 | p123 §10 行 5 + §8 六负例锚词表（6 值 6 锚词逐字） | PASS |
| 4.6 | 超时与活性 | p123 §10 行 6（keep-alive/carrier 中断面 → G-SPNEGO-2） | PASS |
| 4.7 | NAT/代理/被动 | p123 §10 行 7（代理 407 形 → G-SPNEGO-2 立项） | PASS |
| 4.8 | 版本/方言 | p123 §10 行 8（RF 2478 旧式 targ 互操作档显式声明） | PASS |
| 4.9 | 有 RFC 查 RFC 注编号章节 | RFC 4178 §4.2/§4.2.1/§4.2.2/§5/App A/App D；RFC 2743 §3.1；RFC 4121；RFC 2478 §3.2.1；RFC 4559 §1/§4.2；X.690 | PASS |
| 4.10 | 无 RFC 以官方规范为准 | 不适用（有 RFC） | PASS |
| 4.11 | 不许博客二手代替原文 | 三路对照均注出处（本机 RFC 原文+tshark 源码值+Samba/impacket 形态） | PASS |
| 4.12 | 规范原文 | p123 §10.4 ① | PASS |
| 4.13 | 商业软件实际行为 | p123 §10.4 ②（Windows/AD 两轮、Samba/impacket OID 序）→ 未确认级挂 G-SPNEGO-1 | PASS |
| 4.14 | 可靠开源实现思路 | p123 §10.4 ③（wireshark/tshark 41 字段实测；不搬码） | PASS |
| 4.15 | 三路不一致取舍写清 | p123 §10.4（dissector 形↔RFC 形取裁定2 A 方案+通道分流） | PASS |
| 4.16 | 商业行为逐条映射用例号 | p123 §11.2 映射表；无映射挂 G-SPNEGO-1 并写确认方式 | PASS |
| 4.17 | 关键决策候选对比表 | 裁定1（依赖建模）A 案+先证三条；裁定2（dissector↔RFC 形）A/B 两案 | PASS |
| 4.18 | 不许单方案自说 | 两裁定均带候选与取舍理由 | PASS |
| 4.19 | 每表格行/字段/错误码三选一 | §10.2 35 格逐格（已覆/缺口→G-2）；§10.3 15 行 | PASS |
| 4.20 | 每条目对应至少一用例 | 对账 58 = 38 覆盖 + 20 B′（p123 §3.3） | PASS |
| 4.21 | 动手前缺口矩阵 | p123 §10 三子表先行 | PASS |
| 4.22 | 三张子表齐 | ①§10.2 ②§10.3 ③§11.2 | PASS |
| 4.23 | 设计评审先看矩阵 | 门1 获批 | PASS |
| 4.24 | 规范与实现冲突先改实现 | P5 按落盘 pcap dissector 实测修线形（先跑后钉；M-shape-1 锚为准） | PASS |
| 5.1 | 设计写明依赖 | registry.go:904-906（DependsOn tcp/OptionalOn http/TransportOn tcp）+ p123 §1.4 可达性证据 | PASS |
| 5.2 | 写明出错处理 | planner.go 全锚词出口 + 6 负例 task error（零假成功） | PASS |
| 5.3 | 无依赖/错误分支不许实现 | 有 | PASS |
| 5.4 | 无依据不许定字段流程缺省 | OID/端口(445/80)/取值集合均有出处（RFC+门1 §13） | PASS |
| 5.5 | 不确定标待确认+确认方式 | G-SPNEGO-1/2/3（p123 §5 确认方式三选一） | PASS |
| 5.6 | 回答结论指文档章节/代码行 | 本报告逐条点行 | PASS |
| 5.7 | 指不出直说不知道 | 序号算法 P1 诚实"待 P4 定"；P4 已回填 builder.go 行号 | PASS |
| 5.8 | 回复前自查出处 | — | PASS |
| 5.9 | 抽查三条定位不到打回 | 门3 三条全命中（p6-review §1） | PASS |
| 6.1 | 性能目标/预算/边界 | p123 §3.4（O(n) 流式/无锁/无全量聚合） | PASS |
| 6.2 | 六指标列全 | 清单在案；数字待基准后定（诚实待确认，未承诺） | PASS |
| 6.3 | pcap/NIC 分别验收 | pcap 路实测（本审重跑）；NIC 路注记（p123 §3.4）→ 见 NOTE N3 | NOTE |
| 6.4 | 性能依据结合实现路径 | 流式 EmitMsg/事件级常量内存/无共享状态 | PASS |
| 6.5 | 无依据数字标待确认 | 已标待确认 | PASS |
| 6.6 | 六类性能场景 | 清单在案；P4/P5 未贴基准数字（同族惯例） | NOTE |
| 6.7 | 断言实际指标不只无报错 | 功能面 packet_count+字段/frames 双通道；性能数字未测 | NOTE |
| 6.8 | 超预算仍不合格 | — | PASS |
| 7.1–7.3 | 三份文档定位 | design/testcase + D-SPNEGO-1（p123）+ T-SPNEGO；未碰 CODE_DESIGN/TEST_CASES | PASS |
| 7.4 | 历史文档保留参考 | — | PASS |
| 7.5 | cases 是产物回指编号 | 回指 testcase §2（机核同序） | PASS |
| 7.6–7.7 | 三者关系/冲突序 | — | PASS |
| 7.8–7.9 | 先更新核心再设计再用例 | 门1 先行；但门1 版本文档未落盘 → GAP(3) | GAP(3) |
| 8.1 | 八要素-文件清单 | p123 §4 行 8.1（新建 5+接线 9，实测在案） | PASS |
| 8.2 | 接口签名 | GenerateInitialContextToken 等 6 函数（p123 §4） | PASS |
| 8.3 | 数据结构 | SPNEGOConfig/Session/Event 等 6 型（core/spnego.go 实读） | PASS |
| 8.4 | 主流程 | validateSpec→walker→render→EmitMsg（builder.go:438-496） | PASS |
| 8.5 | 错误分支 | §5.2 三条（注入拒/自然守卫/预检）+ 锚词表 | PASS |
| 8.6 | 性能边界 | p123 §3.4 | PASS |
| 8.7 | 与现有逻辑冲突点 | http 透传（layer_gen.go:81）、OptionalOn 供给、双层端口契约、schemagen 127 层 | PASS |
| 8.8 | 回滚方式 | revert 新建+接线件；无数据迁移（p123 §4） | PASS |
| 8.9 | 未定稿不开工 | 门1 获批=定稿=开工 | PASS |
| 8.10 | 需求变先改设计 | — | PASS |
| 8.11 | 不许代码先行文档后补 | P1–P3 先于 P4（提交序） | PASS |
| 8.12–8.13 | 开工贴条目/无条目打回 | — | PASS |
| 9.1 | 用例登记 | 回指 testcase §2（ID 权威） | PASS |
| 9.2–9.4 | 三源 | RFC+门1 契约+现网（第三源未确认级→G-1） | PASS |
| 9.5 | 每行每字段每错误码有用例 | 对账 58=38+20（p123 §3.3，本审复算） | PASS |
| 9.6 | 一例一行为 | 20 ID 唯一语义（机核同序） | PASS |
| 9.7 | 修 bug 先复现变红 | P5-R1 10/20→按落盘 pcap 重钉（先跑后钉） | PASS |
| 9.8 | 数据场景六变体 | p123 §10.3 变体表 15 行 + 负例 #15–#17 | PASS |
| 9.9 | 业务场景序列/乱序/中断/交错 | #13 跨流并行（两流独立四元组）+ 流内有序 + s2 reject 中断；服务端主动中断/乱序归并维持 G-SPNEGO-2 | PASS |
| 9.10 | 现网场景；复杂度 9.50 下限 | #13 三类交织（多会话×多流×异常）达标；#1/#2 两轮基线 | PASS |
| 9.11 | 多动作组合流≥2 条×≥3 动作 | #13 两流×每流多动作（challenge/init/resp 序列 + s2 reject）；3.13 复核通过（非重复冒充） | PASS |
| 9.12 | 清单先行 | P1 矩阵先行（p123 §10） | PASS |
| 9.13 | 清单无遗漏是目标 | 对账 58 点闭环 | PASS |
| 9.14 | 存量逐条审计去向 | 占位逐键去向表（p123 §1.1）；注册后移除 | PASS |
| 9.15–9.19 | A/B/C 三分类 | A′=T-21（已裁定不入约）；B′=G-SPNEGO-2；C 类无 | PASS |
| 9.20 | 取值表每值一例 | negResult 0/1/2/3 逐值（#12/#6/#10/#1 线字节或字段）+ 三 OID 全枚举 | PASS |
| 9.21 | 分支级审计 | 同分支代表 + 分支各一例（resp/targ 两枝） | PASS |
| 9.22 | 扫遍全部承载位置 | 裸 TCP / HTTP carrier 两档（#3/#4 vs #1/#2/#14） | PASS |
| 9.23 | 正交矩阵逐格标记 | p123 §10.2/§10.3 | PASS |
| 9.24 | 地址族对称 | IPv4/IPv6 × 双 profile 四格满（#1/#2/#3/#4；链测 IPv6 独立 fixture :777-794） | PASS |
| 9.25 | 地址族扩展随矩阵扩 | IPv6 独立 fixture | PASS |
| 9.26 | 补齐顺序 | 最小实现→高频→全量 | PASS |
| 9.27 | harness 做不到逐项注明 | 裸 TCP `-V` 无 OID 行→frames hex 通道（p123 §3.7） | PASS |
| 9.28 | 不许字段出现冒充顺序 | OID 列表序逐字节断言（链测 :302-311） | PASS |
| 9.29 | 补齐后全量全绿 | suite 20/20（本审重跑）+ Go 测试全绿 | PASS |
| 9.30 | 只写不跑/只跑增量=未完成 | 全量重跑 | PASS |
| 9.31 | 断言以真实 pcap 校准 | casegen 全链回放取真值（先跑后钉）；本审 tshark 复核 | PASS |
| 9.32–9.36 | 动态整格 | 四元组=框架 allowlist；业务面=会话级覆盖+取值枚举（layer_dyn 无 spnego 行，见 NOTE N5） | NOTE |
| 9.37 | 派生编号撞车 | 两会话同四元组（无派生口）；无撞号面 | PASS |
| 9.38 | 聚合排除固定/派生口 | #13 无 distinct 端口聚合断言（未触陷阱） | PASS |
| 9.39 | 多流×静态标量互斥 | 用例均 flows=1（未触）；flows>1 路径未建例 | NOTE |
| 9.40 | 共享流序号动态字段 | 无按流序号动态字段（会话级覆盖按会话序，非流序） | PASS |
| 9.41–9.45 | 测试评审五件事 | 本报告 §1/§7 + 9.43 → GAP(2)、9.44 → PASS | GAP(2) |
| 9.46 | 数据场景全表扫 | §10.3 15 行 + DER 边界 #11（短/长 length/空可选） | PASS |
| 9.47 | 取值集合逐值枚举 | 四 negResult 值 + 三 OID + REQ flags 位 | PASS |
| 9.48 | 业务场景规范反推 | p123 §1.2 t1–t4（RFC 反推） | PASS |
| 9.49 | 多连接/多事务/多流各一例+真实编排 | 多会话✓（每流两会话）多流✓（flows=2 双四元组）真实编排✓（多流×异常 ≥2 项） | PASS |
| 9.50 | 复合大场景≥3 类交织 | #13 = 3 类（多会话×多流×异常分支）达下限 | PASS |
| 9.51 | 组合矩阵满格 | §10.2 35 格逐格（16 覆盖+19→G-2） | PASS |
| 9.52 | 审计声明出处+对账两行 | p123 §3.3：出处=规范反推；58=8+35+15；38+20=58（本审复算） | PASS |
| 9.53 | 门3 抽最复杂用例+点数 | 修轮后 #13 点数 **11**（5 fields 含跨流 distinct + 6 frames 逐包），交织 3 类；scoped 复评复核关单 | PASS |
| 10.1 | 文档对规范逐条核对 | p123 §2.4 逐条 + G1 修复 | PASS |
| 10.2 | 改需求先对旧需求 | v1.0.0→v1.4.0 勘误①②–⑫逐条（p123 §2.4）；**v1.4.0 文件未落盘** → GAP(3) | GAP(3) |
| 10.3 | 代码逐行走读 | P4 二轮/P5 三轮末轮干净；本审独立重跑构建+测试 | PASS |
| 10.4 | 构建+vet+测试含 race | `go build ./...` EXIT=0；spnego+layers 测试全 ok（本审） | PASS |
| 10.5 | 修完再审 | G1 修后复检干净（p123）；本审复核 | PASS |
| 10.6–10.10 | 测试评审 | C2 修轮后 #13 summary 与 spec/pcap 逐句相符、p4-report §7 偏离披露在案 | PASS |
| 10.11 | 改审测修再审闭环+结论 | 自审轮数在案（P4 2 轮/P5 3 轮） | PASS |
| 11.1–11.5 | 白话 | p6-review 白话节 | PASS |
| 12.1 | 五策略全开（四元组） | ip.src/dst + tcp.src_port/dst_port 在 layer_dyn allowlist（:18-19） | PASS |
| 12.2 | 动态覆盖四元组 | ip/tcp 层 | PASS |
| 12.3 | 业务字段清单 | p123 §1.3 十行矩阵（mech_types/mech_token/MIC/neg_hints/negResult/supportedMech） | PASS |
| 12.4 | flows=N 确定性+seed 可复现+回绕 | 框架语义（未动） | PASS |
| 12.5 | 不写动态按 fixed | 框架 resolvePlan 缺省链 | PASS |
| 12.6–12.8 | 任务级动态不丢规则/只截断/跨策略 | 框架语义 | PASS |
| 12.9 | 静态复制拒绝/告警 | 框架静态复制守卫；spnego 用例 flows=1（未触） | PASS |
| 12.10 | src_port 保底≠动态 | 诚实声明（p123 §1.3） | PASS |
| 12.11–12.13 | 动态住层链/不另起顶层/对齐 tuples | 地址住 ip、端口住 tcp | PASS |
| 12.14–12.16 | 清单+序号算法可定位 | builder.go:282-315 三函数行号已回填；评审可定位 | PASS |
| 13.1–13.6 | schema 文件 | registry spnego 行 :903-922；generated 127 层·12 字段一致（本审对账） | PASS |
| 13.7–13.10 | 校验入口唯一 | ValidateStrategy/TaskCreate 同入口 | PASS |
| 13.11–13.16 | 派生只读下游 | flowb_query_layers 实时视图 | PASS |
| 13.17 | 改语义先改 schema | registry 先行 | PASS |
| 13.18 | 注册表变更重跑生成 | generated 含 spnego（127 层），未手写 | PASS |
| 13.19 | 过期测试变红 | `TestLayersGeneratedMatchesRegistry` 本审独立重跑绿 | PASS |
| 13.20–13.21 | 缺席走缺省/null 拒 | 六级 UnmarshalJSON 严格面（unknown key 拒） | PASS |
| 13.22–13.23 | schema 是机器源不算第四文档 | — | PASS |
| 13.24–13.26 | 评审先查 schema/手写/null 兼容 | 本审 | PASS |
| 14.1 | 用例 spec 即 MCP 任务配置 | spec_json=layers 直驱（suite 实跑） | PASS |
| 14.2 | 不许两套写法 | 单权威 | PASS |
| 14.3 | 执行工具直接消费用例 | suite 直消（本审重跑） | PASS |
| 14.4 | 旧用例随层链迁移改写 | 占位移除+20 例层链形 | PASS |
| 14.5 | 历史口径不带入 | 先跑后钉（包号按落盘 pcap 重钉） | PASS |
| 14.6 | 先跑拿 pcap 再钉 | casegen 全链回放取真值 | PASS |
| 14.7–14.9 | MCP 建任务→引擎生成→tshark 校对 | 本审独立 tshark 复核（#5 字段逐项、#13 双会话 OID） | PASS |
| 14.10 | 离线/无失败/只数包不算测 | 字段+frames 双通道 | PASS |
| 14.11 | 负例经 MCP 被拒锚词 | 6 负例 error_contains（der/length/choice/oid/mic/carrier）实测拒收 | PASS |
| 14.12 | 假成功同级 bug | 零 completed/0-packet（.neg.pcap 24B 占位，本审实测） | PASS |
| 14.13–14.15 | 聚端口/派生口/方向想清 | 无 distinct 端口聚合；方向按 kind 派生（链测） | PASS |
| 14.16 | 全绿+落盘可复查 | 20/20 + pcap 落盘 /tmp/pipe/lanes/lane1/pcaps/spnego/ | PASS |
| 14.17 | 抽查 spec/字段/锚词 | p6-review §1/§7 | PASS |
| 14.18 | 二进制与 HEAD 同代 | canonical 绿；lane1 二进制落后（N4） | NOTE |
| 14.19 | 全量全绿 | 20/20 全量（非增量） | PASS |
| 14.20 | 包号端口从 pcap 拿 | 先跑后钉（p4-report §4 + 本审复核） | PASS |
| 15.1 | 门1 十四行表+证据 | p123 §1 十四行齐（14 行零缺口） | PASS |
| 15.2 | 证据三选一；写不出=立项 | 全文件/行/例；G-1/2/3 立项在案 | PASS |
| 15.3 | §1/§3/§12 强制展开 | p123 §1.1/§1.2/§1.3；**展开所依附的 v1.4.0 文档未落盘** → GAP(3) | GAP(3) |
| 15.4 | 门2①顶层零残留 | pipe_gate 门2-1 绿（本审重跑） | PASS |
| 15.5 | 门2②全量绿负例锚词 | suite 20/20（本审重跑） | PASS |
| 15.6 | 门2③二进制同代 | canonical 绿（本审重跑） | PASS |
| 15.7 | 门2④反查绿后进 P6 | coverage_gate 84/84 EXIT=0（本审重跑） | PASS |
| 15.8 | D-条目挂门1表 | p123 §1 表在案 | PASS |
| 15.9 | 抽查三条点到行/例号 | p6-review §1 三条全命中 | PASS |
| 15.10 | 白话+三门证据 | p6-review 白话+§4/§5 | PASS |
| 15.11 | 任一门红停 | 修轮后复评关单：suite 20/20、coverage 84/84、pipe_gate 四项绿 | PASS |

## 缺口汇总

- **GAP(1)**（=C1）**已关闭**：修轮集成 `ae2ae47`——#13 三类交织/11 点断言（先跑后钉 22 包）；复评见 p6fix-scoped-review.md。
- **GAP(2)**（=C2）**已关闭**：summary 改回实况 + p4-report §7 披露补齐；载体口径裁定（同例双载体不可表达 → 跨用例覆盖）随文档入版（design v1.5.0/testcase v1.3.0，集成 a9be76f）。
- **GAP(3)**（=M1）：门1 契约文档（v1.4.0/v1.2.0）未落盘；p123 §6 交付清单与实况不符；与 ocsp #46 同形。
- **GAP(4)**（=m1）**已关闭**：#8 resp 包 5 帧钉（`supportedMech=NTLM`）已交付（修轮）；复评逐字节 EXACT + 变异命中。

## 注记（backlog，不挡验收）

- N1：verify.go BER 白名单 case-scoped 接受（p6-review §9-N1）。
- N2：T-21（negHints 字段断言面）已裁定不入约，不重开；字节面链测已钉。
- N3：NIC 半未执行（p123 §3.4 注记；与 ocsp/ntlm 同形）。
- N4：lane1 二进制落后仓 HEAD（canonical 同代绿）。
- N5：业务字段动态面=会话级静态覆盖+取值枚举（layer_dyn 无 spnego 行）；与 ocsp 同形。
- N6（已处置）：#13 packet_count 修轮后按实测重钉 22（先跑后钉）。
