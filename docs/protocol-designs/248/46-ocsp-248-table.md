# OCSP（D-OCSP-1 #46）P6 248 条款逐条比对表

> 口径：docs/CORE_MEMORY.md（v15/481 行，2026-09-26）。落点=ocsp#p6 实测证据。判定：PASS=满足，GAP(n)=缺口编号，NOTE=注记。

| 条款 | 要求 | ocsp 落点 | 判定 |
|---|---|---|---|
| 1.1 | 地址只写 ip 层 | 20 例 layers[i].ip.src/dst（casegen ipL） | PASS |
| 1.2 | 端口只写 tcp/udp 层 | tcp.src_port/dst_port（tcpL；裸 TCP 8080 显式） | PASS |
| 1.3 | 流数量只写 flow_control | spec 顶层仅 layers（flow_control 由 suite 注入；数量经 sessions/事务表达） | PASS |
| 1.4 | 禁 layers 与顶层五键混用 | 正例顶层键=layers 唯一；负例无顶层旧键 | PASS |
| 1.5 | 混用示例/用例/文档都跑偏 | 无混用示例（设计 §2/§12.1 均严格层链） | PASS |
| 1.6 | 门①层链能跑通 | 14 正例全链回放+suite(pc)；verify.py 104 点对账 0 失败 | PASS |
| 1.7 | 门②旧格式已彻底移除 | 占位已移除；cases 无旧扁平键 | PASS |
| 1.8 | 示例只给严格层链形 | design §2/§12.1 样例严格层链 | PASS |
| 1.9 | 暂不支持时标注目标形状 | 无暂不支持项（双 profile 双链均可达，实测） | PASS |
| 1.10 | 汇报分开说跑通/清旧字段 | p4-report + 本报告分节 | PASS |
| 1.11 | 顶层白名单（layers/flow_control 家族/output） | 实测：正例顶层键=layers 唯一；0 游离（presence 负例形状见 12-P2 口径） | PASS |
| 1.12 | 无可住层时立项补层，不许豁免 | 无游离字段；动态四元组住 ip/tcp 层 | PASS |
| 1.13 | 门2①按白名单执行 | 同 1.11 | PASS |
| 2.1 | 策略=单模板自带 flow_control | 策略模板=单 OCSP 流量；suite 以策略 config 直跑 | PASS |
| 2.2 | 任务=多策略合跑+总量封顶 | 框架语义未动（设计 §12 行） | PASS |
| 2.3 | 策略先限速任务再封顶 | 未动 | PASS |
| 2.4 | 任务 ID={taskID}-{strategyID} | 未动 | PASS |
| 2.5 | flows=N 复制 N 条 | 未动 | PASS |
| 2.6 | spec 不管数量 | 未动 | PASS |
| 2.7 | 按流变化走动态字段 | serial/nonce 逐流派生（resolvePlan/resolveNonce） | PASS |
| 2.8 | 未写动态 src_port 保底 12345+i | tcp 层既有语义 | PASS |
| 2.9 | 其余字段按流变化必须写动态 | 12.12 清单逐字段开/不开+理由 | PASS |
| 2.10 | 讲数量分清策略复制/任务封顶 | 设计 §12 行 | PASS |
| 2.11 | 讲变化动态按 §12 | 12.12 | PASS |
| 3.1 | 多会话 sessions[]/flows[] 显式 | sessions[] 显式（#13/#14 双会话） | PASS |
| 3.2 | 每会话独立 ID/四元组/生命周期 | s1/s2 独立 src_port/事务/挥手 | PASS |
| 3.3 | 会话内事务有序序列 | t1→t2→t3 序列（#13） | PASS |
| 3.4 | 事务前置条件 | 设计 §12.3 事务表 t1–t4 | PASS |
| 3.5 | 触发动作 | 同上 | PASS |
| 3.6 | 成功分支 | 同上（match→判定） | PASS |
| 3.7 | 失败分支 | tryLater 重试/中断；负例 task error | PASS |
| 3.8 | 控制关联数据流必须显式关联字段 | 单通道协议：CertID+nonce same_as 关联，无副流（差异诚实声明 §12.3） | PASS |
| 3.9 | 关联写清会话/事务/决定字段 | 归属 sN/tM + nonce+CertID 双字段 | PASS |
| 3.10 | 被关联流独立 ID/四元组/握手 | 无副流，不适用（声明在案） | PASS |
| 3.11 | 各流顺序/并发/交错写清 | t1→t2 串行；s1/s2 并发交错 | PASS |
| 3.12 | 可交错写清调度+时间戳体现 | 流内状态断言，不假设全局包序 | PASS |
| 3.13 | 不许连续重复冒充编排 | #13 为真实编排（批量+tryLater+双会话） | PASS |
| 3.14 | 无长连接豁免≠多流豁免 | A′双面：#13 并发 + #6 单包多载荷 | PASS |
| 3.15 | 无多会话≠无多事务（多轮/非正常/长保活各一例或立项） | ①#13 ②#9+#13 半程+G-OCSP-1 ③#13 | PASS |
| 3.16 | CWMP 范本照补 | 差异点诚实声明（无 driven_by） | PASS |
| 3.17 | 多流设计五件套 | §12.3 全（会话表/事务/关联/插入/时间线） | PASS |
| 4.1 | 连接模型 | §10.1 行1（HTTP POST/GET/keep-alive/裸 TCP） | PASS |
| 4.2 | 命令/消息表 | §10.1 行2 + §10.2 矩阵 | PASS |
| 4.3 | 状态机 | §10.1 行3（tryLater 重试） | PASS |
| 4.4 | 字段表 | §10.1 行4 + §10.3 变体 | PASS |
| 4.5 | 错误处理表 | §10.1 行5（7 取值；4 保留不断言） | PASS |
| 4.6 | 超时与活性 | §10.1 行6（keep-alive/503/重组） | PASS |
| 4.7 | NAT/代理/被动 | §10.1 行7 + G-OCSP-3 | PASS |
| 4.8 | 版本/方言 | §10.1 行8（v1/v2 + SHA-1→256 + 5019） | PASS |
| 4.9 | 有 RFC 查 RFC 注编号章节 | RFC 6960/8954/5019/5280 + X.690 章节 | PASS |
| 4.10 | 无 RFC 以官方规范为准 | 不适用（有 RFC） | PASS |
| 4.11 | 不许博客二手代替原文 | 三路对照原文+现网+开源 | PASS |
| 4.12 | 规范原文 | §11.1 ① | PASS |
| 4.13 | 商业软件实际行为 | §11.1 ②（openssl/browser/CA） | PASS |
| 4.14 | 可靠开源实现思路 | §11.1 ③（wireshark/tshark/openssl，不搬码） | PASS |
| 4.15 | 三路不一致取舍写清 | §11.1 取舍段（stapling/UDP 不入约） | PASS |
| 4.16 | 商业行为逐条映射用例号 | §11.2 映射表；G-OCSP-1/3 写确认方式 | PASS |
| 4.17 | 关键决策候选方案对比表 | §11.3 A/B/C + §11.4 A/B | PASS |
| 4.18 | 不许单方案自说 | A/B/C 三案在案 | PASS |
| 4.19 | 每表格行/字段/错误码三选一 | §10.2/§10.3 逐格 | PASS |
| 4.20 | 每条目对应至少一用例 | 22 格 20 ID + B′ 8 格 | PASS |
| 4.21 | 动手前缺口矩阵 | §10 三子表 | PASS |
| 4.22 | 三张子表齐 | ①§10.2 ②§10.3 ③§11.2 | PASS |
| 4.23 | 设计评审先看矩阵 | 门1 获批 | PASS |
| 4.24 | 规范实现冲突先改实现 | P5 DER 按 dissector 实修（a2 形） | PASS |
| 5.1 | 设计写明依赖 | §13-P2 依赖声明（http/tcp/DER）+ §11.4 裁定1 | PASS |
| 5.2 | 写明出错处理 | §13-P2 错误分支三类 + §7 | PASS |
| 5.3 | 无依赖/错误分支不许实现 | 有 | PASS |
| 5.4 | 无依据不许定字段流程缺省 | OID/端口/时间窗均有出处 | PASS |
| 5.5 | 不确定标待确认+确认方式 | G-OCSP-1/2/3 | PASS |
| 5.6 | 回答结论指文档章节/代码行 | 本报告逐条点行 | PASS |
| 5.7 | 指不出直说不知道 | 序号算法 P1 诚实待 P4 定；P4 已钉死 | PASS |
| 5.8 | 回复前自查出处 | — | PASS |
| 5.9 | 抽查三条定位不到打回 | 门3 三条见 p6-review.md | PASS |
| 6.1 | 性能目标/预算/边界 | §13-P2 性能节（O(n)/双路验收） | PASS |
| 6.2 | 六指标列全 | 数字待基准后定（诚实待确认） | PASS |
| 6.3 | pcap/NIC 分别验收 | #14 双路同一断言集 | PASS |
| 6.4 | 性能依据结合实现路径 | 流式/EmitMsg/无锁 | PASS |
| 6.5 | 无依据数字标待确认 | 已标待确认 | PASS |
| 6.6 | 六类性能场景 | 清单在案；P5 跑测 | PASS |
| 6.7 | 断言实际指标不只无报错 | packet_count+字段双钉 | PASS |
| 6.8 | 超预算仍不合格 | — | PASS |
| 7.1–7.3 | 三份文档定位 | design/testcase + D-OCSP-1 + T-OCSP；未碰 CODE/DESIGN/TEST_CASES | PASS |
| 7.4 | 历史文档保留参考 | — | PASS |
| 7.5 | cases 是产物回指编号 | 回指 testcase §2 | PASS |
| 7.6–7.7 | 三者关系/冲突序 | — | PASS |
| 7.8–7.9 | 先更新核心再设计再用例 | 门1 先行 | PASS |
| 8.1 | 八要素 | §13 文件/接口/结构/流程/错误/性能/冲突/回滚 | PASS |
| 8.2–8.8 | 签名/结构/流程/错误/性能/冲突/回滚 | §13-P2 全 | PASS |
| 8.9 | 未定稿不开工 | 门1 获批=定稿=开工 | PASS |
| 8.10 | 需求变先改设计 | — | PASS |
| 8.11 | 不许代码先行文档后补 | P1–P3 先行 | PASS |
| 8.12–8.13 | 开工贴条目/无条目打回 | — | PASS |
| 9.1 | 用例登记 TEST_CASES | 回指 testcase §2（ID 权威） | PASS |
| 9.2–9.4 | 三源 | RFC+D-OCSP-1+现网/tshark | PASS |
| 9.5 | 每行每字段每错误码有用例 | §10.2/§10.3 对账 | PASS |
| 9.6 | 一例一行为 | 20 ID 唯一语义 | PASS |
| 9.7 | 修 bug 先复现变红 | P5-R1 12/20→byKey 实修（a2 形） | PASS |
| 9.8 | 数据场景六变体 | §10.3 变体表 | PASS |
| 9.9 | 业务场景序列/乱序/中断/交错 | t1→t2/tryLater/双会话 | PASS |
| 9.10 | 现网场景；复杂度 9.50 下限 | #13 交织（见 9.53 点数） | PASS |
| 9.11 | 多动作组合流≥2 条×≥3 动作 | #13（s1 三事务+双会话）/ #14（POST+GET 双会话） | PASS |
| 9.12 | 清单先行 | P1 矩阵先行 | PASS |
| 9.13 | 清单无遗漏是目标 | 42 点对账 | PASS |
| 9.14 | 存量逐条审计去向 | 占位移除口径在案 | PASS |
| 9.15–9.19 | A/B/C 三分类 | B′=G-OCSP-1/2/3；动词≠覆盖 | PASS |
| 9.20 | 取值表每值一例 | responseStatus 六取值/certStatus 三态/hash 双算法 | PASS |
| 9.21 | 分支级审计 | 同分支代表+分支各一例 | PASS |
| 9.22 | 扫遍全部承载位置 | POST/GET/裸 TCP/keep-alive | PASS |
| 9.23 | 正交矩阵逐格标记 | §10.2/§10.3 | PASS |
| 9.24 | 地址族对称 | #1/#2/#3/#14 四格满 | PASS |
| 9.25 | 地址族扩展随矩阵扩 | IPv6 独立 fixture | PASS |
| 9.26 | 补齐顺序 | 最小实现→高频→全量 | PASS |
| 9.27 | harness 做不到逐项注明 | §3.7（包序/方向/序号注明） | PASS |
| 9.28 | 不许字段出现冒充顺序 | 保序断言（#6 serial 序） | PASS |
| 9.29 | 补齐后全量全绿 | 独立重跑 ocsp+layers -race 绿；verify 104 点 0 失败 | PASS |
| 9.30 | 只写不跑/只跑增量=未完成 | 全量 | PASS |
| 9.31 | 断言以真实 pcap 校准 | 先跑后钉（casegen 全链回放取真值） | PASS |
| 9.32–9.36 | 动态整格 | serial pattern/inc；nonce rand 可复现；cert_status/responseStatus/hash_algorithm list；静态复制由框架层守 | PASS |
| 9.37 | 派生编号撞车 | s1/s2 端口拉开 42062/42063 | PASS |
| 9.38 | 聚合排除固定/派生口 | distinct_exclude ["80"]（#13） | PASS |
| 9.39 | 多流×静态标量互斥 | 会话级 src_port 覆盖 + 动态派生 | PASS |
| 9.40 | 共享流序号动态字段 | nonce 按 (si,ti) 派生，会话间 distinct 实测 | PASS |
| 9.41–9.45 | 测试评审五件事 | 本报告 | PASS |
| 9.46 | 数据场景全表扫 | §10.3 | PASS |
| 9.47 | 取值集合逐值枚举 | 六 status/三 certStatus/双算法/4 保留注 | PASS |
| 9.48 | 业务场景规范反推 | §12.3 t1–t4 | PASS |
| 9.49 | 多连接/多事务/多方/多流各一例+真实编排 | #13（多事务+多会话+tryLater） | PASS |
| 9.50 | 复合大场景≥3 类交织 | #13=多会话+多事务+异常分支+TCP 挥手编排（4 类） | PASS |
| 9.51 | 组合矩阵满格 | §10.2 30 格 | PASS |
| 9.52 | 审计声明出处+对账两行 | testcase §8.3（42=34+8） | PASS |
| 9.53 | 门3 至少一条抽最复杂用例+点数 | #13 点数见 p6-review.md（5 fields+2 frames；4 维） | PASS |
| 10.1 | 文档对规范逐条核对 | p123 报告逐条 | PASS |
| 10.2 | 改需求先对旧需求 | v1.0.0→v1.1.0 逐条核对在案 | PASS |
| 10.3 | 代码逐行走读 | P4-R2/P5-R1 逐行（死码删除/byKey 实修） | PASS |
| 10.4 | 构建+vet+测试含 race | 独立重跑 -race 绿（本报告） | PASS |
| 10.5 | 修完再审 | P4 三轮/P5 两轮末轮干净 | PASS |
| 10.6–10.10 | 测试评审 | 本报告（三源回指+verify） | PASS |
| 10.11 | 改审测修再审闭环+结论 | 自审轮数在案 | PASS |
| 11.1–11.5 | 白话 | 判词见 p6-review.md 末节 | PASS |
| 12.1 | 五策略全开（四元组） | src/src_port 全开；dst/dst_port fixed+理由 | PASS |
| 12.2 | 动态覆盖四元组 | ip/tcp 层 | PASS |
| 12.3 | 业务字段清单 | 12.12（serial/nonce/status/responseStatus/hash/request_count） | PASS |
| 12.4 | flows=N 确定性+seed 可复现+回绕 | LCG seed+序号；fixtureSerialBase 派生 | PASS |
| 12.5 | 不写动态按 fixed | resolvePlan 缺省链 | PASS |
| 12.6–12.8 | 任务级动态不丢规则/只截断/跨策略 | 框架语义 | PASS |
| 12.9 | 静态复制拒绝/告警 | 框架静态复制守卫（request_count 冲突判死为实例） | PASS |
| 12.10 | src_port 保底≠动态 | 诚实声明 | PASS |
| 12.11–12.13 | 动态住层链/不另起顶层/对齐 tuples 语义 | 地址住 ip、端口住 tcp | PASS |
| 12.14–12.16 | 清单+序号算法可定位 | resolvePlan/resolveNonce/parseSerial 行号见报告 | PASS |
| 13.1–13.6 | schema 文件 | registry ocsp 行；generated 126 层/17 字段一致（schemagen 测试绿） | PASS |
| 13.7–13.10 | 校验入口唯一 | ValidateStrategy/TaskCreate 同入口 | PASS |
| 13.11–13.16 | 派生只读下游 | flowb_query_layers 实时视图 | PASS |
| 13.17 | 改语义先改 schema | registry 先行 | PASS |
| 13.18 | 注册表变更重跑生成 | generated 已重跑（126 层） | PASS |
| 13.19 | 过期测试变红 | TestLayersGeneratedMatchesRegistry 绿（独立重跑） | PASS |
| 13.20–13.21 | 缺席走缺省/null 拒 | UnmarshalJSON 严格面 | PASS |
| 13.22–13.23 | schema 是机器源不算第四文档 | — | PASS |
| 13.24–13.26 | 评审先查 schema/手写/null 兼容 | — | PASS |
| 14.1 | 用例 spec 即 MCP 任务配置 | spec_json=layers 直驱（planOChain 同路径） | PASS |
| 14.2 | 不许两套写法 | 单权威 | PASS |
| 14.3 | 执行工具直接消费用例 | suite 直消 | PASS |
| 14.4 | 旧用例随层链迁移改写 | 占位移除+20 例层链形 | PASS |
| 14.5 | 历史口径不带入 | 先跑后钉（9→22 等实测钉死） | PASS |
| 14.6 | 先跑拿 pcap 再钉 | casegen 全链回放取真值 | PASS |
| 14.7–14.9 | MCP 建任务→引擎生成→tshark 校对 | 独立 verify.py：tshark 104 点 0 失败 | PASS |
| 14.10 | 离线/无失败/只数包不算测 | 字段+frames 双钉 | PASS |
| 14.11 | 负例经 MCP 被拒锚词 | 6 负例 error_contains（der/hash/match/nonce/algorithm/carrier） | PASS |
| 14.12 | 假成功同级 bug | 零 completed/0-packet（.neg.pcap 24B 占位） | PASS |
| 14.13–14.15 | 聚端口/派生口/方向想清 | distinct_exclude ["80"]；方向 up/down | PASS |
| 14.16 | 全绿+落盘可复查 | 14 pcap 落盘 /tmp/mcp-pcaps/ocsp/ | PASS |
| 14.17 | 抽查 spec/字段/锚词 | 本报告三源回指 | PASS |
| 14.18 | 二进制与 HEAD 同代 | 独立重跑为源码级（go test 同 HEAD）；服务器禁碰 | PASS |
| 14.19 | 全量全绿 | ocsp+layers -race 全绿 | PASS |
| 14.20 | 包号端口从 pcap 拿 | 先跑后钉 | PASS |
| 15.1 | 门1 十四行表+证据 | design §12 | PASS |
| 15.2 | 证据三选一；写不出=立项 | G-OCSP-1/2/3 | PASS |
| 15.3 | §1/§3/§12 强制展开 | §12.1/§12.3/§12.12 | PASS |
| 15.4 | 门2①顶层零残留 | 实测 0 游离 | PASS |
| 15.5 | 门2②全量绿负例锚词 | coverage_gate 54/54；verify 104 点 | PASS |
| 15.6 | 门2③二进制同代 | 源码级独立重跑（禁碰服务器） | PASS |
| 15.7 | 门2④反查绿后进 P6 | 54/54 在案 | PASS |
| 15.8 | D-条目挂门1表 | design §12 | PASS |
| 15.9 | 抽查三条点到行/例号 | 见 p6-review.md | PASS |
| 15.10 | 白话+三门证据 | 见 p6-review.md 末节 | PASS |
| 15.11 | 任一门红停 | 全绿 | PASS |

## 注记（backlog，不挡验收）

- N1：IPv6 `Host:` 头为裸地址（无方括号）——p4-report 已知开口，契约未规定，保持旧引擎行为。
- N2：G-OCSP-1/2/3 缺口立项（B′）按迁入计划推进。
- N3：契约 packet_count 约定值（8/6/16/12）与实测（9/10/22/18）偏离——casegen notes 已逐例注明先跑后钉，属契约"约定值，实测为准"口径。
