# MMS（D-MMS-2 #88）P6 248 条款逐条比对表

> 口径：docs/CORE_MEMORY.md（v15/481 行，2026-09-28 读）。落点=mms#88 实测证据（P6 终审判词**通过**，无 P0/P1、仅观察项、无复验指令；merge commit `62ad5f6` 即 HEAD，无前移；suite canonical 独立复跑 **19/19**（11 正+8 负）、coverage_gate **50/50**、pipe_gate HEAD 现编二进制门 2-1/2-3/2-4 全绿、`-race` 绿、go vet 干净）→ P6 关单。判定：PASS=满足，GAP(x)=缺口立项号（非挂账，去向在案），NOTE=注记/观察项。
> 文档面：design v1.0.0（423 行）+ testcase v1.0.0（154 行）入版；载体 = `trafficgen/test/protocol_pcap/cases/mms.json` 19 例（T-MMS-1..11 存量合入 + mms_domain_overlong（A′ T-MMS-18）+ mms_multiflow（G-MMS-8 flow_control 补例）+ 8 负例）。
> 关键事实：TCP 102；层链 `[ip, tcp, mms]`；sub-session 与主配置同 gate（members 两入口判死）；死 sequence/stepGap/injectOn 键判死；validType 收窄拒 float/binaryTime/structure；multiSession 副会话端口 `40000+i`；12 业务键动态全关（对象即 `does not support dynamic`）；A′ 仅 T-MMS-18 在册；B′ 明确不实现（builder default `ber(0x80,nil)` 保留、拒收侧落地）。

| 条款 | 要求 | mms 落点 | 判定 |
|---|---|---|---|
| 1.1 | 地址只写 ip 层 | 19 例 `layers[i].ip.src/dst`（192.0.2.88→198.51.100.88）；mms_ipv6 同层住 IPv6（2001:db8::1/2，offset 74）；mms_multiflow ip.src 层内 inc 动态（10.0.1.1 起）；无顶层地址键 | PASS |
| 1.2 | 端口只写 tcp/udp 层 | `tcp.dst_port=102`（mms 无 FieldContract，显式≠102 不拒，设计 §5 如实披露）；缺省链路径 `chain_planner.go:978` 补 102 | PASS |
| 1.3 | 流数量只写 flow_control | mms_multiflow `strategy_fc={type:flows,value:2}`；正例 0 游离（19/19 顶层仅 layers[+fc]，机核=coverage_gate 50/50） | PASS |
| 1.4 | 禁 layers 与顶层五键混用 | 门 2-1 绿；`mms_neg_stray_src_ip` 判死（`strategy_convert.go:8518` `no longer accepts flat config field src_ip`）；链测试 `TestMMSChain_PresenceAndStrayTopLevelKeys` 另断言 dst_ip/src_port/dst_port/count 四键同拒 | PASS |
| 1.5 | 混用示例/用例/文档都算跑偏 | 无混用示例；19 例 spec_json 全纯 layers；T-9 flat 残留已重写（`ip` 层 `2001:db8::1/2`） | PASS |
| 1.6 | 门①层链能跑通 | suite 19/19（canonical 8081 P6 独立复跑，EXIT=0）；17 pcap 落盘（2 纯配置负例计划期拒、无产物=预期） | PASS |
| 1.7 | 门②旧格式彻底移除 | presence 判死两路：`strategy_convert.go:8878`（`no longer accepts a top-level mms sub-config`）+ `:554` mapToFlowSpec 同口径；pipe_gate.sh presence 红线已收 mms；mms_neg_presence 绿 | PASS |
| 1.8 | 示例只给严格层链形 | 19/19 严格 `[ip,tcp,mms]`；design §2.1 样例纯 layers+flow_control | PASS |
| 1.9 | 暂不支持时标注目标形状 | B′ 缺口（AARE 拒绝/Conclude/分页/粘包分片/S7 混跑）design §14 G-MMS-4/5/6 逐条立项声明 | PASS |
| 1.10 | 汇报分开说跑通/清旧字段 | p4-report「Suite RESULT」「框架层改动声明」分节；P6 报 §(a)-(f) 分节 | PASS |
| 1.11 | 顶层白名单（layers/flow_control 家族/output） | 正例穷尽断言（19/19 机核）；唯一并存=`mms_neg_presence`（判死负例形状，14-P2 口径）；check_mms 顶层键检查在 coverage_gate | PASS |
| 1.12 | 无可住层时立项补层，不许豁免 | 业务 12 键已得层（registry.go:702 mms 行 12 Fields：iedName/objects/5 enables/multiSession/association/sequence/errorClassName/errorValue）；无「登记保留」豁免；死键走判死非豁免（planner.go:55/58/61） | PASS |
| 1.13 | 门2①按白名单执行 | 同 1.11；pipe_gate 门 2-1 绿（HEAD 现编二进制复跑）；黄行措辞无 | PASS |
| 2.1 | 策略=单模板自带 flow_control | mms_multiflow `strategy_fc` 在案（其余 18 例缺省=flows 1）；框架语义未动 | PASS |
| 2.2 | 任务=多策略合跑+总量封顶 | 框架语义未动（suite 走策略路径；mms 无 task 级例，无特化声明） | PASS |
| 2.3 | 策略先限速任务再封顶 | 未动（SharedTokenBucket 框架面） | PASS |
| 2.4 | 任务 ID={taskID}-{strategyID} | 未动 | PASS |
| 2.5 | flows=N 复制 N 条 | mms_multiflow flows=2 实证（14 包=2×7；tshark 双流 src 10.0.1.1:12345 / 10.0.1.2:12346 双断言） | PASS |
| 2.6 | spec 不管数量 | 未动 | PASS |
| 2.7 | 按流变化走动态字段 | 四元组动态住 ip/tcp（layer_dyn.go:17 allowlist ip{src,dst,ttl}/tcp{src_port,dst_port}）；mms_multiflow ip.src inc 逐流递增落线实证；mms 业务键全关=见 12.x | PASS |
| 2.8 | 未写动态 src_port 保底 12345+i | `strategy_convert.go:49` DefaultSrcPort=12345 + `worker.go:308` `DefaultSrcPort+uint16(i)`；mms_multiflow 12345/12346 落线实证 | PASS |
| 2.9 | 其余按流变化必须写动态 | design §12.12 业务 12 键逐个列开/不开；全关=配动态即 `does not support dynamic` 拒；不冒充自动 | PASS |
| 2.10 | 讲数量分清策略复制/任务封顶 | design §12 §2 行（策略=单 MMS 模板自带 flow_control；任务=多策略合跑+总量封顶，框架语义未动） | PASS |
| 2.11 | 讲变化动态按 §12 | 本表 12.x | PASS |
| 3.1 | 多会话 sessions[]/flows[] 显式 | mms 无通用 sessions[] 结构；多会话=层内 `multiSession[]` 显式键（registry 12 键在册）+ `concurrent=true`（chain_planner_chain.go:502-516）；多流面=framework flows（mms_multiflow） | PASS |
| 3.2 | 每会话独立 ID/四元组/生命周期 | 主会话默认流 + 副会话独立 TCP 连接（副端口 `40000+i`=`40001` SYN 102 实测，layer_gen.go:53）；独立生命周期（CR_B=帧8 独立 CR） | PASS |
| 3.3 | 会话内事务有序序列 | 关联→Read/Write/GetNameList/Identify→Report/Error 全序；tshark 实测包 9/10 双 CC→11/12 双 DT1→13/14 双 DT2→15/17 服务（阶段序 CR全→CC全→DT1全→DT2全→服务串行，layer_gen.go:32-34 注释+:55-100） | PASS |
| 3.4 | 事务前置条件 | 前置=ASSOCIATED（CR/CC/DT1/DT2 先行）；noAssociate 跳关联=mms_no_associate 反向实证（帧 4 起 `a0` 直发，无 CR/CC）；testcase §6.1 四件事 | PASS |
| 3.5 | 触发动作 | `enableXxx` 五开关 × `sequence.steps` 交集才发（layer_gen.go:149/:232-247）；T-2..6 逐服务触发 | PASS |
| 3.6 | 成功分支 | 请求→响应自动配对（Read `a1{a4}`、Write `81 00`、GetNameList/Identify）；T-3 Write 成功项 `a5 04 81 00 81 00` 帧钉 | PASS |
| 3.7 | 失败分支 | `mms_service_error`（Confirmed-Error `a2 0a 80 01 01 a2 05 a0 03 87 01 02`，access/object-non-existent）；配置级失败=8 负例 task error 锚 | PASS |
| 3.8 | 控制关联数据流显式字段 | 无派生流——诚实声明（design §10.4：单 TCP 连接内全序，无 driven_by；CancelRequest 式跨连接语义不适用）；多会话=独立连接端口隔离 | PASS |
| 3.9 | 关联写清会话/事务/决定字段 | 同上声明 + 关联=会话内事务序（t1-t5，design §12.3）+ `40000+i` 端口隔离（layer_gen.go:49-54） | PASS |
| 3.10 | 被关联流独立 ID/四元组/握手 | 无派生副流（声明无关联流），不适用；多会话双路各自完整握手（CR_A 帧4/CR_B 帧8 同字节、双 SYN 独立连接） | PASS |
| 3.11 | 各流顺序/并发/交错写清 | 会内严格全序；双会话并发=阶段序（CR全→CC全→DT1全→DT2全→服务串行，layer_gen 注释+实测包序）；多流 flows=2 并发（concurrent=true） | PASS |
| 3.12 | 可交错写清调度+时间戳 | 无交错面（无分片让位/中插动作；G-MMS-5 粘包/半包 B′ 声明 harness 单 TPKT/段假设） | PASS |
| 3.13 | 不许连续重复冒充编排 | 生命周期编排（建连→关联→服务对→ErrorPDU 负向；双会话阶段调度）非模板重复；t1-t5 事务四件事逐一 | PASS |
| 3.14 | 无长连接豁免≠多流豁免 | 长连接载体在案（TCP 102 长连接）；多流=mms_multiflow ✓ + 单包多载荷=T-2 五对象一次读/T-3 多对象写/T-5 名列表多名 ✓；三项 3.15 见下 | PASS |
| 3.15 | 多轮/非正常结束/长保活各一例或立项 | ①多轮同连接=A′ T-MMS-13 立项（testcase §6.1 ①）②非正常结束=有例（T-7 ErrorPDU/T-8 未关联直发/T-11 配置拒；AARE 拒绝/Conclude=G-MMS-4 B′）③长保活=协议层无 keepalive 显式不适用（design §10.1 行 6，TCP 层兜底）+ T-1 关联常驻 | PASS |
| 3.16 | CWMP 范本照补 | 差异声明：无 driven_by（单载体无派生流，design §10.4 诚实声明） | PASS |
| 3.17 | 多流设计五件套 | design §12.3 强制展开（会话表 s1/s2/s3、事务 t1-t5、关联关系 §10.4、插入位置=终结层 TCP 载荷起点 54/74、时间线=会内全序+双会话阶段序） | PASS |
| 4.1 | 连接模型 | design §1/§10.1 行 1（客户端-服务器确认服务；TCP 长连接，控制数据不分离，客户端建连） | PASS |
| 4.2 | 命令/消息表 | design §3.4（a0/a1/a2/a3 顶层 + read a4/write a5/getNameList a1/identify a2 服务标签 + 帧结构逐字段）；规范行=旧基线 §1.3/§3.3-3.5 | PASS |
| 4.3 | 状态机 | design §4.1（CLOSED→TCP_ESTABLISHED→COTP_ESTABLISHED→ASSOCIATED→DATA_EXCHANGE；noAssociate 跳态）+ §4.2 非法转移表 | PASS |
| 4.4 | 字段表 | design §3.1-§3.5/§3.7（TPKT 4B/COTP CR-CC-DT/SPDU-CP-CPA-ACSE/BER Data CHOICE 标签表/OID 汇总）；名 ≤32B 门 | PASS |
| 4.5 | 错误处理表 | design §3.6 错误类表（access 0x87/definition 0x82/service 0x84）+ §4.2 拒绝面锚词表 + §7 四类错误传播 | PASS |
| 4.6 | 超时与活性 | design §10.1 行 6（协议层无保活/重传语义，显式不适用，TCP 层兜底；对端无响应照发本侧全序 §7） | PASS |
| 4.7 | NAT/代理/被动 | design §10.1 行 7（无被动模式；NAT 面框架语义；S7 共存零分流→G-MMS-6 B′ 声明不支持） | PASS |
| 4.8 | 版本/方言 | design §10.1 行 8（MMS 增强上下文 `1.0.9506.2.3` 固定，单栈无协商；servicesSupported 位串可覆盖）+ §2.4 wire_profile 无版本选择器如实声明 | PASS |
| 4.9 | 有 RFC 查 RFC 注章节 | RFC 1006（TPKT）+ ISO 8073/8650-1/8823/9506 + IEC 61850-8-1，章节级出处（design 头注+§3，旧基线 §2.2-§2.11 全文为底） | PASS |
| 4.10 | 无 RFC 以官方规范为准 | ISO/IEC 官方规范为准（同上）；字节权威=libiec61850 编码器+packet-mms.c+TShark 3.6.14 实测+三探针 | PASS |
| 4.11 | 不许博客二手代替原文 | p6-review 三条抽查均点到规范级出处；探针/tshark 仅作断言通道与缺口证据，不改写线真相（设计 §1 证据三档纪律） | PASS |
| 4.12 | 规范原文 | design §3 逐字段（只收代码/探针双证字节，旧基线全表继续有效）；§10.1 八项矩阵 | PASS |
| 4.13 | 商业软件实际行为 | libiec61850 参考抓包 canonical + TShark 3.6.14 dissector 面；真实 IED 抓包未到→G-MMS-8 观察项如实登记（不冒充第三源，testcase §5） | PASS |
| 4.14 | 可靠开源实现思路 | libiec61850 编码器行为，函数级对照（design §10.5 三路对照③；只借鉴不搬码） | PASS |
| 4.15 | 三路不一致取舍写清 | design §10.5 三路对照（①规范/旧基线②现网=libiec61850 canonical+TShark③开源=libiec61850 函数级）；旧基线三处过期以代码+探针为准并 §8 登记勘误（Write `81 00`/utcTime 8B/Read 响应） | PASS |
| 4.16 | 商业行为逐条映射用例号 | testcase §5 三源回指（旧基线 §2-§4→D-MMS-2→11 ID）；canonical 抓包字节逐帧钉（T-1 帧 4/6/7=探针 pkt2/3 逐字节同） | PASS |
| 4.17 | 关键决策候选方案对比表 | design §10.5 四决策候选 A/B 对比表（端口缺省 FieldContract 与否、float 三值修 builder 或拒收、死字段接线或删键、S7 共存分流与否） | PASS |
| 4.18 | 不许单方案自说 | 同上表（每行≥2 真实候选+取舍理由；P4 落地=拒收侧/删键判死/G-MMS-8 现状） | PASS |
| 4.19 | 每表格行/字段/错误码三选一 | design §10.2 矩阵 33 格（已覆 16/缺口 11/不适用 6，重数合账 ✓）+ §10.3 变体表 32 行（已覆 12/缺口 20）逐格三选一无留白 | PASS |
| 4.20 | 每条目对应至少一用例 | 已覆 16+12 格/行有例（T-1..11）；缺口 31 格=A′ 10 项（仅 T-MMS-18 在册，余主线程裁量）+B′ 4 项声明+G-MMS-2/8 过程债，逐个去向（testcase §6.2） | PASS/A′ |
| 4.21 | 动手前缺口矩阵 | design §10（P1 产物，门 1 获批前）+ §12 门 1 十四行表 | PASS |
| 4.22 | 三张子表齐 | ①PDU×状态 33 格（§10.2）②数据形态变体 32 行（§10.3）③商业行为→用例映射（§10.5 三路对照+testcase §5 回指）；AARE 拒绝/Conclude 商业面=G-MMS-4 | PASS |
| 4.23 | 设计评审先看矩阵 | 门 1 获批=D-MMS-2 定稿=开工门（design §11 头注；P4 08:13 后于门 1） | PASS |
| 4.24 | 规范实现冲突先改实现 | 旧基线三处过期（Write 成功项/utcTime 长度/Read 响应长度）以代码+探针实锚改文档并登记勘误（§8）——实现正确侧为准 | PASS |
| 5.1 | 设计写明依赖 | `DependsOn ["tcp"]` 单值（registry.go:702）；终结层之上不可再叠；前置状态链 §4.1 | PASS |
| 5.2 | 写明出错处理 | §4.2 六类拒绝面+锚词 + §7 四类错误传播（配置拒/服务拒绝/编码层/链路时序，失败一律 task error 零假成功） | PASS |
| 5.3 | 无依赖/错误分支不许实现 | 有（§5.1/§5.2 在案；builder/validator 双实现） | PASS |
| 5.4 | 无依据不许定字段流程缺省 | 端口 102=IANA iso-tsap；CR/CC/DT 字节=RFC 1006/ISO 8073+探针双证；Initiate 字节=libiec61850 canonical；`40000+i`=代码注释+实测 | PASS |
| 5.5 | 不确定标待确认+确认方式 | G-MMS-8 观察项（真实 IED 抓包确认位串/TSAP 现网值）+ float 三值空 datatype 语义未定（G-MMS-3，P4 已裁拒收侧） | PASS |
| 5.6 | 回答结论指章节/代码行 | design 全篇逐条带 registry.go/builder.go/planner.go/layer_gen.go 行号；P6 §(a) 三条抽查逐条点到 HEAD 行号（layer_dyn.go:17、registry.go:702、layer_gen.go:53 等） | PASS |
| 5.7 | 指不出直说不知道 | 吞吐数字诚实「待基准」（design §6 数字纪律：不写承诺 §6.5）；真实 IED 抓包「未到」直说（testcase §5） | PASS |
| 5.8 | 回复前自查出处 | p4-report 自审 P4 4 轮+P5 校准 2 轮（末轮干净，3 项关键自查发现已修）；P6 报 §自审只读声明 | PASS |
| 5.9 | 抽查三条定位不到打回 | 门 3 三条全点到（§12 动态清单/§13 schema 派生/§3.9 多会话端口与阶段序，p6-review §(a)，行号零漂移或漂移有锚词实证） | PASS |
| 6.1 | 性能目标/预算/边界 | design §6（单流默认 7 包+2 包/确认服务；DT1 165B/DT2 161B/CR-CC 20B；单流 O(1)、多会话 O(会话数)；planner 通道 32 上限） | PASS |
| 6.2 | 六指标列全 | design §6（包数/字节数/内存 O(1)/通道上限/无锁并行度；吞吐与并发上限数字待基准=6.5 纪律） | PASS |
| 6.3 | pcap/NIC 分别验收 | design §6 验收两路；pcap 路=17 pcap 落盘+suite 全绿（canonical 复跑）；**NIC 路本轮未跑**（enp135s0f0np0 约定在案） | NOTE |
| 6.4 | 性能依据结合实现路径 | 事件驱动直发无收集（layer_gen.Generate 逐事件 EmitMsg，:18-104）；invoke 栈上局部量无共享可变状态无锁；跨流速=框架 flow_control+SharedTokenBucket | PASS |
| 6.5 | 无依据数字标待确认 | 已标（design §6「数字待 P4 基准」；§6.5 不写承诺） | PASS |
| 6.6 | 六类性能场景 | design §6 清单在案（基线 7 包/目标规模多会话 18 包/压力上限大 objects+超长 TPKT 拒/长时间多轮 A′ T-MMS-13/并发交错 multiSession/资源耗尽 buffer 背压）；P5 基准未跑 | NOTE |
| 6.7 | 断言实际指标不只无报错 | packet_count 7/14/18 契约 + fields 20 项（T-1）+ frames 逐字节双钉（不只看包数） | PASS |
| 6.8 | 超预算仍不合格 | —（§6.8 纪律在案；无超预算面） | PASS |
| 7.1–7.3 | 三份文档定位 | design+testcase+D-MMS-2（design §12 §7 行）；未碰 CODE_DESIGN/TEST_CASES | PASS |
| 7.4 | 历史文档保留参考 | 旧基线 26-mms-design v1.1.1/testcase v1.0.1 保留为历史层，本契约逐节对照无静默删除（design §8） | PASS |
| 7.5 | cases 是产物回指编号 | 19 例回指 design §7/T 号 + testcase §2/§6.2 ID 权威（T-MMS-1..18 映射；负例锚=§4 表） | PASS |
| 7.6–7.7 | 三者关系/冲突序 | 旧基线 vs 新契约冲突以代码+探针为准并登记勘误（§8）；schema 以 registry 为机器真相（§12 §13 行） | PASS |
| 7.8–7.9 | 先核心→设计→用例 | P1–P3 文档轨先行于 P4 落码（77c1cfc 后于门 1 获批） | PASS |
| 8.1 | 八要素（文件/接口/结构/流程/错误/性能/冲突/回滚） | design §11.1-§11.8 逐件（文件清单/签名/数据结构/主流程/错误分支/性能边界/legacy 分叉冲突/回滚备份） | PASS |
| 8.2–8.8 | 同上逐项 | §11.2 签名不变声明、§11.3 MMSConfig 14 键、§11.4 双实现主流程、§11.5 锚词、§11.6 性能、§11.7 legacy Plan 双 FIN 分叉不「统一」、§11.8 备份+失败测试先行+同族回归（s7/opcua/fins） | PASS |
| 8.9 | 未定稿不开工 | 门 1 获批=D-MMS-2 定稿=开工门（P4 提交后于门 1） | PASS |
| 8.10 | 需求变先改设计 | G-MMS-2/3 二选一裁定在设计 §10.5 预置候选，P4 按表落地（拒收侧） | PASS |
| 8.11 | 不许代码先行文档后补 | P1–P3（design/testcase v1.0.0）先于 P4/P5 提交 | PASS |
| 8.12–8.13 | 开工贴条目/无条目打回 | 门 1 表 §12 十四行+获批记录；p4-report 提交表逐 commit 挂 G-MMS 号 | PASS |
| 9.1 | 用例登记（回指编号） | testcase §2（11 ID 权威表）+§6.2（A′ 10 ID）；cases 19 例逐例回指 | PASS |
| 9.2–9.4 | 三源（规范/设计/现网） | 旧基线 RFC/ISO 章节 + D-MMS-2 + libiec61850 canonical/TShark/三探针（真实 IED 未到→G-MMS-8 观察项，不冒充） | PASS |
| 9.5 | 每行每字段每错误码有用例 | 73 逻辑点对账 36 覆盖（testcase §5 §9.52 两行）；缺口 31 逐个去向（A′/B′/过程债） | PASS/A′ |
| 9.6 | 一例一行为 | 19 例无重复 id（机核=coverage_gate 总数 19）；每例单行为点（各服务/各负例锚） | PASS |
| 9.7 | 修 bug 先复现变红 | G-MMS-3 失败测试先行（契约 §11.8+testcase §7；mms_neg_unsupported_datatype 先红后绿锚词 `datatype`）；mms_neg_multisession_override 首跑红改正锚（p4-report 自查 3） | PASS |
| 9.8 | 数据场景六变体 | 正常（T-2 五类型）/边界（名 32B 门 T-11 超长侧、domain T-MMS-18 超长）/空值（mms 空层默认流 T-1）/超长（TPKT>65531 拒）/非法（datatype/steps/errorClass/负例族）/字节序（integer/unsigned 大端最小长度+utcTime 8B 大端秒） | PASS |
| 9.9 | 业务场景序列/乱序/中断/交错 | 完整序列=T-1..7；中断=T-7 ErrorPDU/T-8 未关联；交错=双会话阶段序 T-10；乱序面=协议单边全序无重传（§10.1 行 6） | PASS |
| 9.10 | 现网场景；复杂度 9.50 下限 | libiec61850 canonical 现网行为基线；复合面=mms_multi_session（双会话×双连接×阶段调度）+ mms_multiflow（双流×动态×逐流端口）——三方交织复合大场景面见 9.50 行 | PASS |
| 9.11 | 多动作组合流≥2 条×≥3 动作 | ①关联→读→写（T-1+T-2+T-3 同链序设计）②关联→名列表→标识→上送（T-4/5/6）≥2 条 ✓（testcase §6.1 ①） | PASS |
| 9.12 | 清单先行 | P1 矩阵先行（33 格+32 行+八项，design §10，门 1 前） | PASS |
| 9.13 | 清单无遗漏是目标 | 73 逻辑点清单 + 缺口 31 逐个去向登记（testcase §5 对账两行） | PASS |
| 9.14 | 存量逐条审计去向 | testcase §8 逐条 11 例（10 合入+1 改写+0 作废）；design §8 同账；19=11+T-MMS-18+multiflow+8 负例，机核一致 | PASS |
| 9.15–9.19 | A/B/C 三分类 | A′ 10 项（补例，仅 T-MMS-18 在册，余主线程裁量——testcase §6.2 原文）/B′ 4 项（G-MMS-4/5/6+三值编码，明确不实现声明 design §14）/C 类面=harness 单 TPKT/段假设（G-MMS-5 注明不做，不冒充覆盖）；动词≠覆盖：PDU×状态矩阵逐格对照 | PASS |
| 9.20 | 取值表每值一例 | Data CHOICE 六类已覆值（boolean/integer/unsigned/octetString/utcTime 各≥1+visibleString 零 cases=A′ T-MMS-12）；errorClass access=2 已覆/definition·service 未覆（A′ T-MMS-15/16）；errorValue 定制未覆（A′ T-MMS-17）——逐值缺口均 A′ 立项在案 | GAP(A′-取值面) |
| 9.21 | 分支级审计 | 负例按分支铺（presence/游离键/死 sequence 键/datatype/members/multiSession 覆盖键/domain 超长/name 超长 8 族锚词=coverage_gate 锚词 8 族逐字在案） | PASS |
| 9.22 | 扫遍全部承载位置 | mms 配置承载=单层 `mms` 层键全集（主配置+multiSession 子会话双入口均设门：planner.go:44 主/:91 子同 Validate 门/:117 deadMultiSessionKeys 12 键）；objects[].members 主/子双入口判死 | PASS |
| 9.23 | 正交矩阵逐格标记 | design §10.2/§10.3 逐格已覆/缺口/不适用（16/11/6 与 12/20 重数合账 ✓） | PASS |
| 9.24 | 地址族对称（IPv4/IPv6 逐格） | IPv4=T-1..8/10/11+负例族；IPv6=T-9（offset 74、同 CR/CC/DT 字节、ip.version=6 断言）；**IPv6 仅默认流 1 例，服务/多会话/负例格未逐格对照**（族对称未满，A′ 未列全） | GAP(A′-IPv6 逐格) |
| 9.25 | 地址族扩展随矩阵扩 | design §2.1「IPv6 同住 ip 层」+§10.3 行 2 已覆（改写后）；多会话/多流 IPv6 组合格未扩（矩阵未列该维度组合格） | NOTE |
| 9.26 | 补齐顺序 | A′ 清单在案但补齐未执行（仅 T-MMS-18）；最小实现→高频→全量顺序未走完 | NOTE |
| 9.27 | harness 做不到逐项注明 | 包序/方向=frames+offset+fields 组合钉（tshark 白名单 tpkt.*/cotp.* + 内层 frames hex）；内层 MMS 拒解→frames 原始字节断言（testcase §1 断言双通道+§6.4 白名单核对） | PASS |
| 9.28 | 不许字段出现冒充顺序 | 帧号逐包钉（CR=帧4/CC=帧5/DT1=帧6/DT2=帧7/服务=8+；双会话 CR_B=帧8、服务 A=15/B=17）；invoke 各自从 1（偏移 63 `02 01 01` 双钉） | PASS |
| 9.29 | 补齐后全量全绿 | 19/19 全量（P4 ×2 + P6 canonical 独立复跑，非增量） | PASS |
| 9.30 | 只写不跑/只跑增量=未完成 | 全量跑 ×3（P4 两代+P6）；跑后 SUMMARY 回写已 git restore（p6-review §(c)） | PASS |
| 9.31 | 断言以真实 pcap 校准 | 先跑后钉（P5 校准自审 2 轮；p6-review §(b) tshark 直读当日 23:50 回放产物逐点复核：14/18 包、12345/12346、40001、IED2 hex、invoke `02 01 01`） | PASS |
| 9.32–9.35 | 动态整格（五策略×字段） | 四元组 framework 面在案（allowlist 五行）；mms 实取=ip.src inc（mms_multiflow 落线实证）+保底 src_port；其余策略×字段格未逐格铺例（mms 语料未取用全格）；业务动态面=12 键全关（拒收侧即覆盖形状） | PASS/NOTE |
| 9.36 | 不支持格标 B/C+注记 | §10.3 变体表 20 缺口行逐行注记（G-MMS-3/4/5/6/A′ 各归其位）；死字段三键注记+判死负例；不冒充已覆盖 | PASS |
| 9.37 | 派生编号撞车 | 副会话端口 `40000+i` 与客户端保底 12345+i、服务端口 102 三域拉开；实测 40001 无撞 | PASS |
| 9.38 | 聚合断言排除固定/派生口 | 无 distinct 聚合用例（逐包 fields 断言 12345/12346 分钉） | PASS |
| 9.39 | 多流×静态标量互斥 | mms_multiflow 按口径交付（flows=2 + ip.src 动态 inc；tcp.dst_port=102 为服务固定口非四元组复制面）；静态复制拒绝=framework 守卫 | PASS |
| 9.40 | 共享流序号动态字段 | mms 语料无同流多子实体动态面（multiSession 副会话对象为静态标量，端口隔离 40000+i 非序号解析） | NOTE |
| 9.41–9.45 | 测试评审五件事 | p6-review 全篇（清单对账 73/36+锚词 5 条代码原文抽验+门 3 点数+tshark 实测复核） | PASS |
| 9.46 | 数据场景全表扫 | 字段边界例族（名/域 32B 门、TPKT 65531、datatype 白名单、errorClass 三值、steps 白名单、sequence 非负）在案；visibleString/float 三值/errorValue 定制值未全（A′） | GAP(A′) |
| 9.47 | 取值集合逐值枚举 | Data CHOICE 六类+errorClass 三类清单在案（design §3.5/§3.6）；逐值覆盖缺口=A′ T-MMS-12/15/16/17 立项（file 0x8B 未实现=G-MMS-4 同域声明） | GAP(A′) |
| 9.48 | 业务场景规范反推 | 矩阵/变体清单来源=规范/旧基线反推声明（testcase §5「非引擎能力面反推」原文）+八项矩阵 §10.1 | PASS |
| 9.49 | 多连接/多会话/多事务各一例+真实编排 | 多连接/多会话 ✓（T-10 双 TCP 连接+CR_A/CR_B 独立握手+阶段序真实编排）；多事务=各服务对例+多轮同连接 A′ T-MMS-13 立项；服务×多会话矩阵 10 格缺口=G-MMS-7（A′ 立项） | PASS/A′ |
| 9.50 | 复合大场景≥3 类交织 | mms_multi_session = 双会话×双连接×阶段调度×服务隔离（3 类：多会话+多事务+并发）；mms_multiflow = 多流×动态四元组×逐流端口（3 类）；达下限 | PASS |
| 9.51 | 组合矩阵满格 | design §10.2/§10.3 逐格在案；用例面组合维度有限=A′ 维持（G-MMS-7 矩阵 10 格登记） | PASS/A′ |
| 9.52 | 审计声明出处+对账两行 | testcase §5：出处=规范反推非用例反推；对账两行=73（8+33+32）vs 36 覆盖+6 不适用+31 缺口=73 ✓；G-MMS-1..8 不折进 73（粒度声明） | PASS |
| 9.53 | 门3 至少一条抽最复杂用例+点数 | 门 3 抽 mms_multiflow+mms_multi_session 深审（p6-review §(b)）：multiflow 14 包点数 ✓（flows=2×7+双流动态断言）；multi_session 18 包点数 ✓（双会话×独立连接×阶段序×双 invoke=多会话+多事务+并发 3 类） | PASS |
| 10.1 | 文档对规范逐条核对 | design §10 八项矩阵+33/32 格（P1 产物）+p123-report 门 1 §②核对 | PASS |
| 10.2 | 改需求先对旧需求 | design §8 逐节对照旧基线 26-mms v1.1.1/v1.0.1（旧条目无静默删除+三处过期勘误登记） | PASS |
| 10.3 | 代码逐行走读 | P4 自审 4 轮+P5 校准 2 轮（p4-report）+P6 独立复审（锚词 5 条原文定位、merge seam 检查、零消费 grep 复核） | PASS |
| 10.4 | 构建+vet+测试含 race | P6：go build/vet 干净；`-race` 三包 ok（p4-report+P6 复跑）；TestMMSChain 9 链测试绿 | PASS |
| 10.5 | 修完再审 | mms_neg_multisession_override 首跑红→改锚→复绿（p4-report 自查 3）；P4 三提交逐轮收口（members 判死=第三提交补门） | PASS |
| 10.6–10.10 | 测试评审 | p6-review（§(a)-(f)：锚词抽验逐条证伪式复核、零消费 grep 双查、负值/正值双锚并存核对） | PASS |
| 10.11 | 改审测修再审闭环+结论 | p4-report「P4 自审 4 轮+P5 校准自审 2 轮，末轮干净」在案 | PASS |
| 11.1–11.5 | 白话 | p6-review 首节白话一句+判词；p4-report 分节白话 | PASS |
| 12.1 | 五策略全开 | 四元组五策略 framework 在案（layer_dyn.go:17 allowlist ip/tcp 五行） | PASS |
| 12.2 | 动态覆盖四元组 | 同上；mms 实取 ip.src inc+multiflow 落线（其余格=framework 面，mms 语料未取用全格） | PASS |
| 12.3 | 业务字段清单逐协议 | design §12.12 强制展开：mms 层业务 12 键逐个列（全关——allowlist 无 mms 行，对象即 `does not support dynamic`，validate_layers.go 同文件 845/873/888/904/930 五处拒点） | PASS |
| 12.4 | flows=N 确定性+seed+回绕 | framework 语义（mms 实例 inc 步进 1 逐流递增实证；rand seed/回绕格 mms 语料未取用） | NOTE |
| 12.5 | 不写动态按 fixed | 17 静态例全静态（层内静态标量；multiflow 四元组动态属 §12 面） | PASS |
| 12.6–12.8 | 任务级动态不丢/只截断/跨策略 | framework 未动 | PASS |
| 12.9 | 静态复制拒绝/告警 | framework 守卫在案（mms_multiflow 已配动态绕开；无静态复制负例=framework 通用面） | NOTE |
| 12.10 | src_port 保底≠动态 | 诚实声明（design §12.12「保底 12345+i」+mms_multiflow fields 双钉实证） | PASS |
| 12.11–12.13 | 动态住层链/不另起顶层/对齐 tuples | 动态住 ip 层（mms_multiflow ip.src）；无顶层动态键；tuples/group_id=framework 基线未动 | PASS |
| 12.14–12.16 | 清单+序号算法可定位 | 序号算法四处实读（parseLayerDyn:78/resolveLayerTuple:770/tuple_generator.go:26 Next/CheckLayerDynShape:1037，P6 抽查 1 逐处零漂移）；业务动态面=全关登记 | PASS |
| 13.1–13.6 | schema 文件 | registry mms 行（registry.go:702，CategoryTerminal+DependsOn["tcp"]+12 Fields 无 FieldContract）；generated json 与 registry 一致（coverage_gate registry 12 键检查绿；无 schemagen 漂移红） | PASS |
| 13.7–13.10 | 校验入口唯一 | suite 经 MCP 同入口；strategy_convert 双口径（:554 mapToFlowSpec+:8873 presence）为校验分支非第二入口 | PASS |
| 13.11–13.16 | 派生只读下游 | flowb_query_layers 实时视图（mms 行可查） | PASS |
| 13.17 | 改语义先改 schema | registry 12 键先行（P1-P3 登记，P4 未改 Fields——MMSConfig 14 键保持，删键方案未取故无 schemagen 重跑义务） | PASS |
| 13.18 | 注册表变更重跑生成 | 本批 registry 零变更（mms 行 P1 前已在）→ 无重跑义务；merge seam 检查确认注册块完好（p6-review §(a) 抽查 2） | PASS |
| 13.19 | 过期测试变红 | `go test ./internal/core/schema/ -run TestLayersGenerated` 类门=coverage registry 检查绿；P6 跑 ./internal/core ok | PASS |
| 13.20–13.21 | 缺席走缺省/null 拒 | mms 空层 `{}` 默认流 7 包（T-1）；未知层键拒（complete.go:293 锚 `unknown field`，零漂移）；死键判死（sequence 三键/members/multiSession 覆盖键） | PASS |
| 13.22–13.23 | schema 是机器源不算第四文档 | — | PASS |
| 13.24–13.26 | 评审先查 schema/手写/null 兼容 | 无手写形状、无 null 兼容分支（P6 抽查 2 registry 块逐键在案） | PASS |
| 14.1 | 用例 spec 即 MCP 任务配置 | spec_json=layers 直驱+mms_multiflow strategy_fc 封包；suite 直接消费 | PASS |
| 14.2 | 不许两套写法 | 单权威（层链+registry 12 键唯一真相） | PASS |
| 14.3 | 执行工具直接消费用例 | run_protocol_suite 经 MCP 直消（P6 canonical 8081 独立重跑 19/19） | PASS |
| 14.4 | 旧用例随层链迁移改写 | 11 例全改写（10 合入+1 改写）+8 新例=19（testcase §8/design §8 双账） | PASS |
| 14.5 | 历史口径不带入 | 旧基线三过期处按现状重钉（Write `81 00`/utcTime `91 08`/Read `a1 1e`）；旧包数公式未带入 | PASS |
| 14.6 | 先跑拿 pcap 再钉 | P5 实跑校准+P6 复跑产出新 pcap（当日 23:50）复核一致 | PASS |
| 14.7–14.9 | MCP 建任务→生成→tshark 校对 | suite 三步走（canonical MCP+tshark 直读逐点：包数/端口/IP/IED2 hex/invoke 字节，p6-review §(b)） | PASS |
| 14.10 | 离线/无失败/只数包不算测 | fields+frames 双钉（20+字段/帧级 hex）；包数仅是契约之一 | PASS |
| 14.11 | 负例经 MCP 被拒+锚词 | 8 负例全 expect_error+error_contains（presence/flat/死键/datatype/members/multiSession 覆盖/domain/name——coverage 锚词 8 族逐字在案） | PASS |
| 14.12 | 假成功同级 bug | 无假成功：纯配置负例计划期即拒（无 pcap 产物=预期）；7 neg.pcap 落盘验证错误帧；mms_neg_multisession_override 假绿已修 | PASS |
| 14.13–14.15 | 聚端口/派生口/方向想清 | 无 distinct 聚合（12345/12346 逐包分钉）；40000+i 派生口显式进断言面（40001 SYN 实测）；方向=上行服务/down 行 report 单帧（帧 8 `a3` 无响应） | PASS |
| 14.16 | 全绿+落盘可复查 | 19/19 + 17 pcap 落盘 /tmp/mcp-pcaps/mms/（2 负例无产物有据） | PASS |
| 14.17 | 抽查 spec/字段/锚词 | p6-review §(a)/(b)/(e)（spec/字段/锚词三面抽查） | PASS |
| 14.18 | 二进制与 HEAD 同代 | 门 2-3 绿（共享陈旧二进制环境红因已甄别，HEAD 现编 /tmp/p6-mms-server 重跑全绿，p6-review §(d)） | PASS |
| 14.19 | 全量全绿 | 19/19（非增量，×3） | PASS |
| 14.20 | 包号/端口从 pcap 拿 | 先跑后钉（tshark 实测回填：CR 帧 4/副 SYN 40001/IED2 帧 17 偏移 78） | PASS |
| 15.1 | 门1 十四行表+证据 | design §12 §1–§14 十四行对照表+证据列（§12.1/§12.3/§12.12 三行强制展开） | PASS |
| 15.2 | 证据三选一；写不出=立项 | G-MMS-1..8 在案（§14 立项表，确认方式/去向列全） | PASS |
| 15.3 | §1/§3/§12 强制展开 | design §12.1（旧键去向+完整 spec_json 样例）/§12.3（五件套 s1-s3/t1-t5）/§12.12（12 键+四元组+序号算法行号） | PASS |
| 15.4 | 门2①顶层零残留 | 门 2-1 绿（presence 红线已收 mms；mms_neg_presence 豁免=判死负例形状） | PASS |
| 15.5 | 门2②全量绿+负例锚词 | 19/19 + 8 锚词族（coverage 50/50 负例锚词逐字在案） | PASS |
| 15.6 | 门2③二进制同代 | 绿（HEAD 现编复跑；陈旧共享二进制红因=并发车道五文件新于旧二进制，非 mms 缺陷，已甄别） | PASS |
| 15.7 | 门2④反查绿后进 P6 | coverage 50/50 绿（whitelist/translate/registry 12 键/接线/presence/链形/锚词 8 族/总数 19） | PASS |
| 15.8 | D-条目挂门1表（回填证据号） | design §12 十四行证据列在案（P6 抽查 3 条逐条点到 HEAD 行号验证） | PASS |
| 15.9 | 抽查三条点到行/例号 | p6-review §(a) 三条（§12.12 动态清单/§13 schema 派生/§3.9 端口与阶段序）逐条点行/例号，不空打回 | PASS |
| 15.10 | 白话+三门证据 | p6-review 首节白话+§(a)-(d) 三门证据+判词通过 | PASS |
| 15.11 | 任一门红停 | 门 2 静态四项绿（HEAD 二进制）；门 3 判词通过无打回；无跳门 | PASS |

## 注记（backlog，判定口径）

- **判定口径**：`GAP(A′…)` 类 = 覆盖未达但已按 testcase §6.2 A′/B′ 与 D-MMS-2 立项承接，**非缺口挂账**；P6 判词通过（无 P0/P1），无打回项，无修轮。
- **A′ 在册面（观察项 1，主线程裁量）**：19 例仅 `mms_domain_overlong`（T-MMS-18）入册；T-MMS-12/13/14/15/16/17/19/20/21（visibleString/multi_step/no_associate-B 列/definition/service/value_custom/assoc_params/services_bad/report_multi）未入册——testcase §6.2「并入与否由主线程定」原文，P6 复核与上报一致。是否并入由主线程定。
- **B′ 关闭声明（观察项 2）**：float/binaryTime/structure 真实编码 + loop/stepGap/injectOn 接线**明确不实现**——builder `default: ber(0x80,nil)` 错编码分支保留但拒收侧（validType 白名单）使其不可达；layer_gen 仅读 `over.Objects`；文档声明在 design §14，去向关闭。
- **sequence 双锚并存（观察项 3）**：`sequence values cannot be negative`（planner.go:49-50）与正值死键判死（:54-62）并存，语义无冲突；主线程若判冗余可并。
- **stale-ephemeral（观察项 4，忽略）**：`/tmp/mcp-pcaps/mms/mms_neg_presence.neg.pcap`（910B）为 presence 落码前旧形状残留——落码后该例计划期即拒、无产物、不再覆写；属 /tmp ephemeral，不在仓库，无需处理。
- **并发车道（观察项 5，无关）**：复审期间工作区 `coverage_gate.py` check_cflow 一行被并发车道修改（enip||cflow→dameng||cflow||drda）；check_mms 块零改动，50/50 有效；主线程集成时取各车道对 该文件改动的并集。
- **门 2-3 环境红因甄别**：默认共享二进制 `/tmp/tg-sv-p4-server` 早于 HEAD 合并，红因=并发车道 igmp/translate/validate_layers/registry/chain_planner 五文件新于该二进制；HEAD 现编二进制重跑门 2-1/2-3/2-4 全绿——非 mms 缺陷。
- **行号漂移说明**：契约引用行号 vs HEAD 有合并 seam 漂移（registry.go:596→702、chain_planner.go:914→978、translate:1700→1744、validate_layers:565/607→845-930 区段），锚词逐字命中=漂移非缺失；P6 §(a) 已逐条核对。
- **NIC 路**：design §6 验收两路之 NIC 路（enp135s0f0np0，tcp port 102）本轮未跑（6.3/6.6 NOTE 同源）。
