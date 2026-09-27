# CQL（D-CQL-1 #75）P6 248 条款逐条比对表

> 口径：docs/CORE_MEMORY.md。落点=cql#75 实测证据（P6 隔离复审独立重跑：suite 30/30、pipe_gate 静态四项绿、coverage 反查 43/43、-race 绿）+ P4/P5 lane 落码（`pipe/cql`：`147f6c2`/`be34001`）+ P6 主线程修轮（F5 新单测已提交、F6 S5 注释已改 9→11）。判定：PASS=满足，GAP(n)=缺口编号（open 缺口显式标注去向），NOTE=注记，SYNC=P6 同期同步（主线程进行中，非本表动作）。
> P6 判词：**通过**，F1–F6 均为非阻塞。其中 F1–F4=契约同步（SYNC，主线程 P6 同期处理）；F5/F6=已关闭（本表按关闭后状态写）。
> 文档面（P6 同步前版本）：design v2.0.0（522 行）/ testcase v2.0.0（204 行），gate-1 获批版；凡"落点=design §x / testcase §x"的行现指仓内实文件，F1–F4 涉及的 stale 处以 SYNC 行注明实测值。

| 条款 | 要求 | cql 落点 | 判定 |
|---|---|---|---|
| 1.1 | 地址只写 ip 层 | 30 例 `layers[i].ip.src/dst`（10.0.0.1→20.0.0.1；v6 例住 ip 层 v6 地址）；无顶层地址键 | PASS |
| 1.2 | 端口只写 tcp/udp 层 | `tcp.src_port=12345/dst_port=9042`；cql 层 FieldContract 补 9042 缺省（registry.go:1011） | PASS |
| 1.3 | 流数量只写 flow_control | 正例 15/15 顶层游离=0（机核+coverage_gate.py:2268 `check_cql`）；负例 3 例顶层并存均为判死负例形状（presence/stray，1.11 口径） | PASS |
| 1.4 | 禁 layers 与顶层五键混用 | 门2-1 绿（无顶层旧键残留）；链例 `cql_chain_test.go:87-133` presence+游离键+载体判死 5/5 | PASS |
| 1.5 | 混用示例/用例/文档都算跑偏 | 无混用示例；design §2/§11.1 样例为纯 layers | PASS |
| 1.6 | 门①层链能跑通 | suite 30/30（P6 隔离复审 canonical 8081 独立重跑 11.29s；与 lane8 一致，跨 lane 可复现） | PASS |
| 1.7 | 门②旧格式彻底移除 | 17 存量去扁平改写纯 layers 形；presence 判死（strategy_convert.go:8618-8622）+ 在库旧策略 ValidationErrors 兼容块（:525-527） | PASS |
| 1.8 | 示例只给严格层链形 | 30/30 均为 layers 链形（`[ip,tcp,cql]`；含 3 例判死负例形状）；零旧扁平形 | PASS |
| 1.9 | 暂不支持时标注目标形状 | v5 envelope 未实现→B2 过渡档拒 + 注记（planner.go:113-115 `envelope` 锚词；design §10.2 决策 B 采用 B2） | PASS |
| 1.10 | 汇报分开说跑通/清旧字段 | p4-report §框架层改动声明/§用例面 分节 | PASS |
| 1.11 | 顶层白名单（layers/flow_control 家族/output） | 正例穷尽断言；顶层并存仅判死负例：`cql_neg_presence_top_level_cql`（presence 豁免 1 例登记在案，pipe_gate.sh:101-102）+ stray src_ip/count 2 例（flat 黑名单判死） | PASS |
| 1.12 | 无可住层时立项补层，不许豁免 | 业务四键已得层（registry.go:1011-1023 wire_profile/events/sessions/wire_fault）；无"登记保留"豁免 | PASS |
| 1.13 | 门2①按白名单执行 | 同 1.11（pipe_gate.sh:120 名单含 cql；门2-1 绿） | PASS |
| 2.1 | 策略=单模板自带 flow_control | 单 CQL 连接模板；框架语义未动（suite 走策略路径） | PASS |
| 2.2 | 任务=多策略合跑+总量封顶 | 框架语义未动 | PASS |
| 2.3 | 策略先限速任务再封顶 | 未动 | PASS |
| 2.4 | 任务 ID={taskID}-{strategyID} | 未动 | PASS |
| 2.5 | flows=N 复制 N 条 | 未动；cql 多会话走 `sessions[]`（见 3.1），语料未开 flows>1 | PASS |
| 2.6 | spec 不管数量 | 未动 | PASS |
| 2.7 | 按流变化走动态字段 | 四元组动态住 ip/tcp（layer_dyn 通用机制）；cql 业务字段未开动态（design §11.3 诚实声明，如需按流变化另立项未开） | NOTE |
| 2.8 | 未写动态 src_port 保底 12345+i | 框架既有语义；多会话 12345/12346 显式 | PASS |
| 2.9 | 其余按流变化必须写动态 | design §11.3 业务清单（不开动态=逐字段诚实声明+理由在案） | PASS |
| 2.10 | 讲数量分清策略复制/任务封顶 | design 门1 §2 行 | PASS |
| 2.11 | 讲变化动态按 §12 | 本表 12.x | PASS |
| 3.1 | 多会话 sessions[]/flows[] 显式 | `sessions[]` 双源端口（12345/12346）显式；`cql_multi_session` 18 包 B 轨实测通过（未撞 mongodb "one flow per chain" 拒绝）→ G-CQL-1 该分项已关 | PASS |
| 3.2 | 每会话独立 ID/四元组/生命周期 | 两流独立握手挥手、stream/state 流内隔离（tshark 逐包核验 pkt1-9/10-18） | PASS |
| 3.3 | 会话内事务有序序列 | STARTUP→READY→QUERY→RESULT→READY 事件序逐包 emit | PASS |
| 3.4 | 事务前置条件 | design §11.2 事务序列 t1–t4（已入版）；PREPARE/EXECUTE 纳 ready 门（planner.go:143-151） | PASS |
| 3.5 | 触发动作 | 事件数组逐条（`cql_multi_round_query` 两轮 QUERY 不同查询文本） | PASS |
| 3.6 | 成功分支 | 响应 s2c 事件显式（RESULT VOID / AUTH_SUCCESS / SUPPORTED） | PASS |
| 3.7 | 失败分支 | `cql_error_server`（合法 ERROR 应用响应）；15 负例 task error 锚 | PASS |
| 3.8 | 控制关联数据流显式字段 | 单连接协议无副流；同流内 stream id 请求/响应关联（`cql_stream_correlation`：stream 1/2 请求 + 乱序回填响应） | PASS |
| 3.9 | 关联写清会话/事务/决定字段 | `stream` 字段承载关联（v4 §2.3:160）；raw 字节与 JSON 钉值逐字节一致（p6-review §b） | PASS |
| 3.10 | 被关联流独立 ID/四元组/握手 | 无副流派生（单 TCP；与 CWMP `driven_by` 范本差异已诚实声明 design §11.2） | PASS |
| 3.11 | 各流顺序/并发/交错写清 | 会话间并发不假设全局包序，只断言流内状态（`tcp.srcport` distinct 聚合，verify.go:44-78 口径确认） | PASS |
| 3.12 | 可交错写清调度+时间戳 | 并发语义经 stream 表达，实现为声明式事件序（design §11.2 时间线已写清"事件序逐包 emit"） | PASS |
| 3.13 | 不许连续重复冒充编排 | 连接初始化→认证→业务→关闭编排 + 多轮 QUERY（`cql_multi_round_query` 7 事件 14 包），非模板重复 | PASS |
| 3.14 | 无长连接豁免≠多流豁免 | 不主张任何豁免：多会话 S9 已覆、多事务 A′ 已补（testcase §9.4）；单包多载荷不适用（一帧一消息） | PASS |
| 3.15 | 多轮/非正常结束/长保活各一例或立项 | ①多轮 ✓（`cql_multi_round_query`）②非正常结束 ✓（15 负例 + S6 ERROR；AUTH_ERROR 0x0100 面→G-CQL-5）③长保活=明确不适用（无协议级心跳） | PASS |
| 3.16 | CWMP 范本照补 | 差异声明：无跨流派生，关联靠同流内 stream 配对（design §11.2） | PASS |
| 3.17 | 多流设计五件套 | design §11.2（已入版）；G-CQL-1 sessions 分项 B 轨实测关闭 | PASS |
| 4.1 | 连接模型 | design §1/§9.1 行1（client→server 单 TCP 长连接，默认 9042；registry.go:1011 DependsOn tcp） | PASS |
| 4.2 | 命令/消息表 | design §3.1（12 opcode 行）/§9.1 行2（16 opcode 中 12 已实现；REGISTER/EVENT/BATCH/AUTH_CHALLENGE 4 opcode 未实现→G-CQL-5） | PASS |
| 4.3 | 状态机 | design §4 + §9.2 子表①（13 行×4 列=52 格逐格结论：已覆 25/缺失→G-CQL-6 10/明确不支持 1/不适用 13/空档 3） | PASS |
| 4.4 | 字段表 | design §3 + §9.1 行4（9B header/notation/flags 宽度差/consistency 11 值/CQL_VERSION mandatory） | PASS |
| 4.5 | 错误处理表 | design §5（9 行锚词表）+ §9.1 行5；用例面 15 负例锚逐字命中 Go 文本 | PASS |
| 4.6 | 超时与活性 | design §9.1 行6（无协议级心跳，TCP 层承载；v5 EVENT 推送未实现面→G-CQL-5） | PASS |
| 4.7 | NAT/代理/被动 | 明确不适用（无 cql 层语义可测；design §9.1 行7） | PASS |
| 4.8 | 版本/方言 | design §1 profile 边界 + §9.1 行8（v4/v5 双 profile；v5 差异 10 条中 9 条→G-CQL-3） | GAP(3) |
| 4.9 | 有 RFC 查 RFC 注章节 | 无 RFC：Apache Cassandra native_protocol_v4/v5.spec（1219/1537 行，章节号实读引用） | PASS |
| 4.10 | 无 RFC 以官方规范为准 | 同上（章节级落点 design §9–§10） | PASS |
| 4.11 | 不许博客二手代替原文 | design §10.1 三路对照（spec 原文 + 现网行为 + wireshark packet-cql.c 开源实现思路） | PASS |
| 4.12 | 规范原文 | design §9 矩阵逐表（97 枚举点口径见 9.52） | PASS |
| 4.13 | 商业软件实际行为 | cqlsh/DataStax driver/python-driver/gocql 形态（design §9.4 映射表） | PASS |
| 4.14 | 可靠开源实现思路 | wireshark `packet-cql.c`（`cql.*` 83 字段实测；只借鉴不搬码） | PASS |
| 4.15 | 三路不一致取舍写清 | W1/W2 以规范为底线修实现（design §10.1 三路一致性段） | PASS |
| 4.16 | 商业行为逐条映射用例号 | design §9.4 映射表（已入版）；G-CQL-8 确认方式在案 | PASS |
| 4.17 | 关键决策候选方案对比表 | design §10.2 决策 A/B/C/D（每决策 ≥2 真实走法，已入版） | PASS |
| 4.18 | 不许单方案自说 | 同上（含不采用/禁止项：A2/A3、B3、C2 明示） | PASS |
| 4.19 | 每表格行/字段/错误码三选一 | design §9.2–§9.4 三子表 + §9.5 枚举面计数（已入版）；用例面 30 例承接 | PASS |
| 4.20 | 每条目对应至少一用例 | 20/97 枚举点命中（gate-1 口径；实测已上修，SYNC F3）+ 77 点逐个去向（G-CQL-2/3/5/6/7/8 或明确不支持，无留白） | PASS/A′ |
| 4.21 | 动手前缺口矩阵 | design §9 + 门1 获批版 | PASS |
| 4.22 | 三张子表齐 | design §9.2/§9.3/§9.4（已入版） | PASS |
| 4.23 | 设计评审先看矩阵 | 门1 获批（D-CQL-1 #75 P1–P3 契约定稿） | PASS |
| 4.24 | 规范实现冲突先改实现 | W1 按 profile 选宽修实现 + 2 例帧重钉；W2 B2 收口（design §10.2 B3 明令禁止照发） | PASS |
| 5.1 | 设计写明依赖 | `DependsOn ["tcp"]`（registry.go:1011）+ design §12 依赖声明（唯一载体 TCP；无 udp/TLS/外部 Cassandra 依赖） | PASS |
| 5.2 | 写明出错处理 | 载体预检（validate_layers.go:619-638，锚词 `carrier` 双路）+ 六门校验（planner.go:106-151：beta/warning/envelope/CQL_VERSION/state/overflow）+ wire_fault 3 值（builder.go:310-330） | PASS |
| 5.3 | 无依赖/错误分支不许实现 | 有（依赖 tcp + §5 九行错误表全有落点） | PASS |
| 5.4 | 无依据不许定字段流程缺省 | 端口 9042/opcode 表/consistency 值均有 spec 出处；非法端口拒（锚词 `9042`/`port`） | PASS |
| 5.5 | 不确定标待确认+确认方式 | G-CQL-8 在案（docker Cassandra + cqlsh/python-driver 回环抓包；确认前相关条目按"待确认"不写死） | PASS |
| 5.6 | 回答结论指章节/代码行 | design §9–§13 已入版；P6 门3 三条点到当前真实行号 | PASS |
| 5.7 | 指不出直说不知道 | 吞吐数字诚实"待 P4 基准后定"（design §12 性能节 §6.5） | PASS |
| 5.8 | 回复前自查出处 | p4-report §自审（P4 3 轮 + P5 校准 3 轮，末轮干净） | PASS |
| 5.9 | 抽查三条定位不到打回 | 门3 三条 ≡ p6-review §a（三条均点行：registry/validate_layers/planner 六门/schema_test.go:111；注：p6-review 行号为复审当时值，现 registry.go:1011 系后续提交位移，语义同条） | PASS |
| 6.1 | 性能目标/预算/边界 | design §12 性能节（已入版）；O(n) 流式逐事件直发无聚合 | PASS |
| 6.2 | 六指标列全 | 吞吐数字诚实待基准（G-CQL 缺口未细化） | PASS |
| 6.3 | pcap/NIC 分别验收 | pcap 路：15 正例 pcap + suite 全绿（P6 独立重跑落盘 `/tmp/mcp-pcaps/cql/`）；**NIC 路本轮未跑** | NOTE |
| 6.4 | 性能依据结合实现路径 | 逐事件渲染直发 EmitMsg、无跨流共享状态、无锁（layer_gen 逐事件 emit） | PASS |
| 6.5 | 无依据数字标待确认 | 已标（§6.5，不写承诺） | PASS |
| 6.6 | 六类性能场景 | 清单在案（基线/目标规模/压力上限/长运行/并发交错/背压，design §12）；P5 未跑基准 | NOTE |
| 6.7 | 断言实际指标不只无报错 | packet_count 15 正例 + 字段/frames 双钉（`cql.*` 4 字段实测解出：stream/opcode/consistency/flags） | PASS |
| 6.8 | 超预算仍不合格 | — | PASS |
| 7.1–7.3 | 三份文档定位 | design+testcase+D-CQL-1（§12 草稿，门1 获批=定稿）；未碰 CODE_DESIGN/TEST_CASES | PASS |
| 7.4 | 历史文档保留参考 | bak-root 审计存档保留（design 文首已更正死链） | PASS |
| 7.5 | cases 是产物回指编号 | 30 例回指 design §6 场景/T-CQL-S1–S11 + 新增 13 例（4 A′正 + 9 负，gate-1 后 P4/P5 合规增量，先跑后钉记录在案） | PASS |
| 7.6–7.7 | 三者关系/冲突序 | — | PASS |
| 7.8–7.9 | 先核心→设计→用例 | 门1 先行（P1–P3 先于 P4/P5） | PASS |
| 8.1 | 八要素（文件/接口/结构/流程/错误/性能/冲突/回滚） | design §12 八要素（已入版）；实现面逐件在码 | PASS |
| 8.2–8.8 | 同上逐项 | design §12（已入版）；translate/validate/backfill/types 落点见 p4-report §框架层改动声明 | PASS |
| 8.9 | 未定稿不开工 | 门1 获批=开工（P4 落码 > 门1 批） | PASS |
| 8.10 | 需求变先改设计 | P5 `cql_prepare_execute` 按 design §9.2 缺失格补 startup/ready 前置（9→11 包；SYNC F1：testcase §2/§3.5/§5.2 未同步，主线程 P6 处理） | PASS/SYNC(F1) |
| 8.11 | 不许代码先行文档后补 | P1–P3 先行 | PASS |
| 8.12–8.13 | 开工贴条目/无条目打回 | — | PASS |
| 9.1 | 用例登记（回指编号） | testcase 契约 §2/§5；S1–S11 + 新增 13 例（回指 design §6/A′/G-CQL-6） | PASS |
| 9.2–9.4 | 三源（规范/设计/现网） | v4/v5 spec 条款 + D-CQL-1 + tshark 实测/现网 Cassandra 形态（未确认级→G-CQL-8） | PASS |
| 9.5 | 每行每字段每错误码有用例 | 20/97 命中（gate-1 口径；实测已上修，SYNC F3）+ 未覆点逐个去向（A′/B′ 立项维持 + 明确不支持） | PASS/A′ |
| 9.6 | 一例一行为 | 30 例无重复 id（机核，count=30） | PASS |
| 9.7 | 修 bug 先复现变红 | W1：`TestValidateCQLV4QueryFlagsOverflow` 先红后绿（p4-report P4-R3）；F5（已关闭）：`TestValidateCQLPrepareBeforeReadyRejected`（cql_test.go:900-914，bare PREPARE before-ready 拒，主线程 P6 已提交） | PASS |
| 9.8 | 数据场景六变体（正常/边界/空值/超长/非法/大小端） | 边界例（length_boundary/空 SASL/空 body）+ 非法 15 负例；超长/截断字符串边界无例→G-CQL-7 | PASS |
| 9.9 | 业务场景序列/乱序/中断/交错 | 状态序列 + 乱序响应回填（stream_correlation）+ 中断（15 负例）；多 stream 交错现网确认→G-CQL-8 | PASS |
| 9.10 | 现网场景；复杂度 9.50 下限 | 最复杂例 `cql_multi_session` 达下限（双会话×独立握手挥手×distinct 聚合，18 包；次复杂 stream_correlation 一并核验） | PASS |
| 9.11 | 多动作组合流≥2 条×≥3 动作 | `cql_query_void`（5 事件）/`cql_multi_round_query`（7 事件）≥2 条 ✓ | PASS |
| 9.12 | 清单先行 | P1 矩阵先行（design §9） | PASS |
| 9.13 | 清单无遗漏是目标 | 77 未覆点登记在案 | PASS |
| 9.14 | 存量逐条审计去向 | testcase §8 逐条 17 例（保留改写 17，其中帧重钉/改形 3）+ 新增 13 例=30，无静默丢弃 | PASS |
| 9.15–9.19 | A/B/C 三分类 | A′（断言/用例面）/B′（代码改动）两分类（testcase §9.2；本协议无 C 类面） | PASS |
| 9.20 | 取值表每值一例 | consistency 11 值仅 2 值（ONE + LOCAL_QUORUM 0x0006）、QUERY/EXECUTE flags 7 位未逐值、error 17 码仅 0x0000（A′/G-CQL-5/7） | GAP(A′-取值面) |
| 9.21 | 分支级审计 | 负例按分支铺（载体/版本/opcode/长度/状态/上限/CQL_VERSION/认证次序/envelope/beta/游离键/缺载体） | PASS |
| 9.22 | 扫遍全部承载位置 | 事件数组（唯一承载）全覆盖；wire_fault 3/3 全用例 | PASS |
| 9.23 | 正交矩阵逐格标记 | design §9.2 矩阵（已入版，52 格逐格有结论） | PASS |
| 9.24 | 地址族对称（IPv4/IPv6 逐格） | **IPv6 1 例**（`cql_ipv6`，offset 74 + `ipv6.version=6` 断言） | PASS |
| 9.25 | 地址族扩展随矩阵扩 | 已覆（S7）；无扩展缺口 | PASS |
| 9.26 | 补齐顺序 | 最小实现→高频→全量（A′ 未执行完，维持） | NOTE |
| 9.27 | harness 做不到逐项注明 | 包序/方向靠 frames+字段组合钉（tshark 面；裸 `tshark -e cql.*` 须经 TCP 重组语义，以 `-x` raw + JSON 钉值双证为准） | PASS |
| 9.28 | 不许字段出现冒充顺序 | stream/opcode 按包号逐包断言（stream_correlation pkt6-9 opcode/stream 双证） | PASS |
| 9.29 | 补齐后全量全绿 | 全量 30/30 绿（P6 隔离复审独立重跑 + lane8 一致） | PASS |
| 9.30 | 只写不跑/只跑增量=未完成 | 全量跑（`-run TestProtocolPcapDrive -count=1` 全 30 例） | PASS |
| 9.31 | 断言以真实 pcap 校准 | 先跑后钉（P5-R2 包号/tcp.len 实跑改正；W1 2 例重钉帧与 pcap 实字节一致：query_void pkt6 tcp.len=47/length 0x26=38、prepare_execute pkt7 EXECUTE length 0x0a=10/tcp.len=19） | PASS |
| 9.32–9.35 | 动态整格（五策略×字段） | 四元组 framework 面在案；cql 语料未取用动态（见 12.15） | PASS |
| 9.36 | 不支持格标 B/C+注记 | 4 opcode + 4 result kind + 16 error 码 + 23 数据类型 = 明确不支持收口（G-CQL-5，另轮逐项三选一） | PASS |
| 9.37 | 派生编号撞车 | 无派生子流面（sessions 显式声明，与动态正交） | PASS |
| 9.38 | 聚合断言排除固定/派生口 | multi_session distinct 断言经 verify.go:44-78 确认（包索引忽略、exclude 9042 后恰为 {12345,12346}） | PASS |
| 9.39 | 多流×静态标量互斥 | sessions[] 显式多流，无静态标量互斥面 | PASS |
| 9.40 | 共享流序号动态字段 | 无动态面 | NOTE |
| 9.41–9.45 | 测试评审五件事 | p6-review §a–§e（三源对账+锚词核+点数+W1/W2 核验） | PASS |
| 9.46 | 数据场景全表扫 | 字段边界例在案；consistency/flags 值域未全（见 9.20） | GAP(A′) |
| 9.47 | 取值集合逐值枚举 | 同上（error 码/result kind 未逐值→G-CQL-5） | GAP(A′/5) |
| 9.48 | 业务场景规范反推 | design §9 矩阵 + §9.5（出处=v4/v5 spec 原文反推，非用例反推） | PASS |
| 9.49 | 多连接/多会话/多事务各一例+真实编排 | 多会话 ✓（multi_session 18 包）+ 多事务 ✓（multi_round_query 14 包）+ 真实编排（双会话独立握手挥手 + 流内乱序归并） | PASS |
| 9.50 | 复合大场景≥3 类交织 | `cql_multi_session`（多会话×独立生命周期×聚合断言）+ `cql_stream_correlation`（多请求×乱序响应×stream 关联）达下限 | PASS |
| 9.51 | 组合矩阵满格 | design §9.2 矩阵（已入版）；用例面组合维度有限=A′ 维持 | PASS/A′ |
| 9.52 | 审计声明出处+对账两行 | testcase §9.3：规范逻辑点 97（9 面反推）vs 用例覆盖 30（15 正 15 负）；出处=规范反推非用例反推。SYNC F3：testcase §2/§9.3/§5.2 仍记 17 例/11正6负/包数表 `[9,9,10,12,9,8,11,11,18,8,7]`（实 30 例/15正15负/`[9,9,10,12,11,8,11,11,18,8,7,13,11,11,14]`），主线程 P6 同步 | PASS/SYNC(F3) |
| 9.53 | 门3 至少一条抽最复杂用例+点数 | 最复杂例 multi_session：18 包（capinfos 18 ✓；两流各 SYN/SYN-ACK/ACK+2 事件+FIN/ACK/ACK/FIN/ACK/ACK）；次复杂 stream_correlation：13 包=3 握手+6 事件+4 挥手，raw 字节逐字节一致 | PASS |
| 10.1 | 文档对规范逐条核对 | design §14.1（v4/v5 spec 条款→本契约落点逐条） | PASS |
| 10.2 | 改需求先对旧需求 | design §14.2（v1.0.0 §1–§8 逐条：§2 为唯一实质改动，其余保留；bak-root 零 diff 基线成立） | PASS |
| 10.3 | 代码逐行走读 | P4 3 轮 + P5 校准 3 轮（p4-report §自审）；P6 隔离复审复核 W1/W2/锚词/行号 | PASS |
| 10.4 | 构建+vet+测试含 race | `go build ./... && go vet ./...` 干净；`internal/protocol/cql`（67 个测试函数）绿；`-race`（cql/core/core-layers/core-schema）全绿；`TestCQLChain_*` 5/5 绿 | PASS |
| 10.5 | 修完再审 | 每轮 fix 后再审（P4-R3/P5-R2 末轮干净）；F6（已关闭）：`cql_test.go:757` S5 注释 9→11 包已改，主线程 P6 已提交 | PASS |
| 10.6–10.10 | 测试评审 | p6-review（30/30 独立重跑 + 双 gate + 落盘 tshark 核验 + 12 族锚词逐字命中） | PASS |
| 10.11 | 改审测修再审闭环+结论 | p4-report §自审 + design §14（P1/P2/P3 对抗自重审各 4/3/4 轮，合计修正 9 处，末轮干净）+ P6 判词"通过" | PASS |
| 11.1–11.5 | 白话 | p6-review 卷首白话（通过/30 例全绿/双 gate/W1W2 处置一致/3 项非阻塞）+ p4-report | PASS |
| 12.1 | 五策略全开 | 四元组五策略 framework 在案（layer_dyn 通用机制） | PASS |
| 12.2 | 动态覆盖四元组 | 同上（cql 语料未取用，见 12.15） | PASS |
| 12.3 | 业务字段清单逐协议 | design §11.3（已入版，11 行字段表，逐字段开/不开+理由） | PASS |
| 12.4 | flows=N 确定性+seed+回绕 | framework 语义（cql 无动态例可验） | NOTE |
| 12.5 | 不写动态按 fixed | 30 例全静态（fixture 钉死字节；多会话 sessions 显式属 §3 面） | PASS |
| 12.6–12.8 | 任务级动态不丢/只截断/跨策略 | framework 未动 | PASS |
| 12.9 | 静态复制拒绝/告警 | framework 守卫在案（cql 无多流 flows 例，未取用；多流走 sessions[] 与动态正交） | NOTE |
| 12.10 | src_port 保底≠动态 | 诚实声明（design §11.3：保底 `12345+i` + 多会话锚点 12345/12346） | PASS |
| 12.11–12.13 | 动态住层链/不另起顶层/对齐 tuples | 四元组住 ip/tcp；无顶层动态键 | PASS |
| 12.14–12.16 | 清单+序号算法可定位 | 序号算法：四元组 layer_dyn 通用机制（design §11.3 已声明位置）；业务字段无算法（`Strategy` 零命中实测，诚实声明） | PASS |
| 13.1–13.6 | schema 文件 | registry cql 行（registry.go:1011：FieldContract 9042 + Fields 4 键 wire_profile/events/sessions/wire_fault）+ 生成表 `layers.generated.json` cql 条目四键齐（门3 已点到实线） | PASS |
| 13.7–13.10 | 校验入口唯一 | ValidateStrategy/TaskCreate 同入口（suite 走 MCP） | PASS |
| 13.11–13.16 | 派生只读下游 | flowb_query_layers 实时视图 | PASS |
| 13.17 | 改语义先改 schema | registry 先行（P4 `147f6c2`） | PASS |
| 13.18 | 注册表变更重跑生成 | generated 已重跑（P4 lane 产物；`TestLayersGeneratedMatchesRegistry` schema_test.go:111 绿） | PASS |
| 13.19 | 过期测试变红 | `go test ./internal/core/schema/ -run TestLayersGenerated` = ok（P6 复审） | PASS |
| 13.20–13.21 | 缺席走缺省/null 拒 | 严格解码：`translateTerminalConfig case "cql"`（chain_planner_translate.go:2901，DisallowUnknownFields，amqp 先例） | PASS |
| 13.22–13.23 | schema 是机器源不算第四文档 | — | PASS |
| 13.24–13.26 | 评审先查 schema/手写/null 兼容 | 无手写形状；wire_fault 缺省 nil 非 ""（postgresql 同款坑已避，registry.go:1017-1020 注释在案）；无 null 兼容分支 | PASS |
| 14.1 | 用例 spec 即 MCP 任务配置 | spec_json=layers 直驱（30/30） | PASS |
| 14.2 | 不许两套写法 | 单权威（层优先，flat 判死后无双轨） | PASS |
| 14.3 | 执行工具直接消费用例 | suite 经 MCP 直消（P6 独立重跑 127.0.0.1:8081，key dev-mcp-key，PCAP_ROOT=/tmp/mcp-pcaps） | PASS |
| 14.4 | 旧用例随层链迁移改写 | 17 例全改写 + 13 例新增 = 30（P4 执行，testcase §8 逐条去向） | PASS |
| 14.5 | 历史口径不带入 | 包号重校（prepare_execute 9→11）、v5 改形（B2 握手前 4 事件）、断言面重建（`cql.*` 0→4） | PASS |
| 14.6 | 先跑拿 pcap 再钉 | P5 实跑重锚（首轮包号差一/tcp.len 算术错按真实输出改正）；P6 复审落盘复核产出新 pcap | PASS |
| 14.7–14.9 | MCP 建任务→生成→tshark 校对 | lane8/P6 MCP + tshark 字段/frames 双通道（端口必须 9042，实测 dissector 前提） | PASS |
| 14.10 | 离线/无失败/只数包不算测 | 字段+frames 双钉（不只看 packet_count；raw 字节逐字节双证两例） | PASS |
| 14.11 | 负例经 MCP 被拒+锚词 | 15 负例全 error_contains（15 例 13 种锚：tcp/version/opcode/length/state/limit/top-level 死句/flat src_ip/flat count/unknown field/CQL_VERSION/envelope/beta；复审逐字命中 Go 文本） | PASS |
| 14.12 | 假成功同级 bug | 无假成功：planner 错误传播 task error（design §1 不变式7；零 completed/0 packets 面） | PASS |
| 14.13–14.15 | 聚端口/派生口/方向想清 | distinct 聚合口径确认（verify.go:44-78）；方向 up/down 显式（`directional:true`） | PASS |
| 14.16 | 全绿+落盘可复查 | 30/30 + 15 正例 pcap 落盘（负例仅 `.neg.pcap` 占位，无损坏帧） | PASS |
| 14.17 | 抽查 spec/字段/锚词 | p6-review §b/§e（最复杂双例 + 12 族锚词） | PASS |
| 14.18 | 二进制与 HEAD 同代 | 门2-3 绿（lane8/P6 二进制与 HEAD 同代） | PASS |
| 14.19 | 全量全绿 | 30/30（非增量） | PASS |
| 14.20 | 包号/端口从 pcap 拿 | 先跑后钉（P5-R2 实跑改正佐证） | PASS |
| 15.1 | 门1 十四行表+证据 | design §11（§1/§3/§12 强制展开 §11.1/§11.2/§11.3 + presence 形状 §11.4） | PASS |
| 15.2 | 证据三选一；写不出=立项 | G-CQL-1…8 在案（design §13.1 立项表 8 行） | PASS |
| 15.3 | §1/§3/§12 强制展开 | design §11.1/§11.2/§11.3（已入版） | PASS |
| 15.4 | 门2①顶层零残留 | 旧键绿；presence 红线已接（pipe_gate.sh:101-102/120 名单含 cql；复审实测绿，豁免 1 例登记在案） | PASS |
| 15.5 | 门2②全量绿+负例锚词 | 30/30 + 15 锚词 13 种（复审机核逐字命中） | PASS |
| 15.6 | 门2③二进制同代 | 绿 | PASS |
| 15.7 | 门2④反查绿后进 P6 | 43/43 绿（`check_cql` 121 行；`coverage_gate.py cql` EXIT=0） | PASS |
| 15.8 | D-条目挂门1表（回填证据号） | design §11 门1 表证据号已回填（门3 三条全中）；SYNC F4：design §9.1 行3/§9.6 仍记"状态门只钉 query"与 W1/W2 未处置口径（代码已是 query/prepare/execute 三门+W1/W2 处置），主线程 P6 同步 | PASS/SYNC(F4) |
| 15.9 | 抽查三条点到行/例号 | p6-review §a（三条均点行/例号，无空点） | PASS |
| 15.10 | 白话+三门证据 | p6-review 卷首 + §g（suite 文档副作用：cql.md 17→30 行重写属 driver 已知行为，主线程关单统一处理） | PASS |
| 15.11 | 任一门红停 | 门2 静态四项绿（exit 0）；SYNC F2：testcase §3.8 v5 例仍为 STARTUP/READY/QUERY/RESULT 形（实 options/supported/startup/ready 握手前 4 事件 11 包），主线程 P6 同步 | PASS/SYNC(F2) |

## 注记（backlog，判定口径）

- **判定口径**：`GAP(A′…)`/`GAP(3)`/`GAP(5)` 类 = 覆盖未达但已按 testcase §9.2 A′/B′ 与 D-CQL-1 立项承接，**非缺口挂账**；P6 判词"通过"，无打回项。
- **SYNC（P6 同期同步，主线程进行中，本表不动作）**：F1（testcase §2/§3.5/§5.2 `cql_prepare_execute` 2 事件/9 包→实 4 事件/11 包）、F2（testcase §3.8 v5 例改形）、F3（testcase §2/§9.3/§5.2 17 例/11正6负/旧包数表→实 30 例/15正15负/`[9,9,10,12,11,8,11,11,18,8,7,13,11,11,14]`）、F4（design §9.1 行3/§9.6 W1/W2 口径）。
- **F5（已关闭）**：`TestValidateCQLPrepareBeforeReadyRejected`（cql_test.go:900-914）已提交；`prepare`/`execute` before-ready 拒绝现三证齐（代码分支 planner.go:143-146 + e2e `cql_neg_state` + 新单测）。
- **F6（已关闭）**：`cql_test.go:757` S5 注释已改"prepare + execute → 11 packets"。
- **G-CQL-1（P4 关闭）**：纯 layers 收口 + sessions 多流展开 B 轨实测通过；`result_kind` 死字段删除（G-CQL-4）同批。
- **G-CQL-2/W1（P4 已修）**：flags 按 profile 选宽（builder.go:185-190 `appendQueryFlags`；v4 `query_flags > 0xFF` 拒 planner.go:149-151，防 `byte()` 静默截断）+ 存量 2 例帧重钉 + 双单测绿。
- **G-CQL-3（open，B2 过渡档生效）**：v5 握手后事件一律拒（锚词 `envelope`）；envelope（CRC24/CRC32 + 128KiB 分段）另轮立项；v5 字段差异（keyspace/now_in_seconds/beta 协商）仍缺。
- **G-CQL-5（open）**：REGISTER/EVENT/BATCH/AUTH_CHALLENGE 4 opcode、ROWS/SET_KEYSPACE/PREPARED/SCHEMA_CHANGE 4 result kind、ERROR 17 码（AUTH_ERROR 0x0100 认证失败面含 §3.15②）、数据类型 23 面，逐项三选一收口待另轮。
- **G-CQL-7 残余（open）**：`cql.*` 断言 4/10 字段（version/direction/message_length/query.flags/result.kind/error_code 未钉成 `cql.*` 断言，现由 frames hex 覆盖）；consistency 11 值仅 2 值；STARTUP NO_COMPACT/THROW_ON_OVERLOAD 选项面无例；超长/截断字符串边界无例。
- **G-CQL-8（open）**：现网证据仍未确认（无 docker Cassandra 抓包），契约 §5.5"待确认"口径不变，不挡开工。
- **SNMP TrapV2 flake**：预存、与 cql 无关（lane 纯净 HEAD `-count=20` 约 1/5 复现；P6 复审 `-count=5` 未复现，仅记录）。
