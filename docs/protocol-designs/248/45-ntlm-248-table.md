# #45 ntlm · P6 248 条款对照表（CORE_MEMORY §1–§15 逐条一行）

> 格式：条款 / 本协议落点 / 证据（代码行 | 用例号 | 文档节）。独立实测结论，M=major 缺口见 p6-review.md。

| 条款 | 本协议落点 | 证据 |
|---|---|---|
| 1.1 地址只写 ip 层 | 落点：`layers[i].ip.src/dst`，IPv6 同住 ip 层（无 ipv6 层） | ntlm.json 14 正例 spec 全 `[ip,tcp,ntlm]`；chain_test nIP/nIP6 |
| 1.2 端口只写 tcp/udp 层 | 落点：`tcp.src_port/dst_port`；udp 零值（判死） | strategy_convert case ntlm 端口缺省；validate_layers udp 拒 `(transport)` |
| 1.3 数量只写 flow_control | 落点：数量走顶层 flow_control 家族 | ntlm.json 正例无 count 键；CaseFileAudit 白名单检查 |
| 1.4 禁混用五键 | 落点：layers 与顶层五键混用判死 | CheckProtoFlat ntlm 分支 strategy_convert.go:8354；chain_test ⑩② |
| 1.5 混用示例/用例/文档算跑偏 | 落点：无混用示例；旧扁平占位已移除 | ntlm.json 20 例全纯 layers 形；CaseFileAudit 非负例顶层键=0 |
| 1.6 门①层链跑通 | 落点：suite 20/20 + pcap 落盘 | lane suite 日志；/tmp/mcp-pcaps/ntlm/ 14+6 落盘 |
| 1.7 门②旧格式彻底移除 | 落点：`ntlm_neg_unregistered` 占位已移除；入库门拦旧字段 | ntlm.json 无占位；门2-1 绿 |
| 1.8 示例只给严格层链形 | 落点：设计 §2/§16.1 样例均为纯 layers 形 | design §2 两样例；§16.1 P-SMB 全样例 |
| 1.9 暂不支持明确标注 | 落点：G-NTLM-1（smb 嵌套）明确标注不可达+立项 | design §15.4 先证1；§19 G-NTLM-1 |
| 1.10 汇报分开跑通/清旧字段 | 落点：p4 报告 §4 门2-1 单列顶层零残留 | p4-report §4 |
| 1.11 顶层白名单 | 落点：顶层仅 layers/flow_control/output；presence 空 map 也死 | CheckProtoFlat ntlm 分支；chain_test PresenceAndStrayTopLevelKeys |
| 1.12 无豁免登记保留 | 落点：无保留豁免；不可达形一律立项 | §19 G-NTLM-1…6；G-NTLM-2 已关闭注记 |
| 1.13 白名单制执行 | 落点：CaseFileAudit 按 allowlist {layers,flow_control,output} 检查 | ntlm_chain_test.go:925-948 |
| 2.1 策略=单模板自带封包 | 落点：单 NTLM 模板 + flow_control | design §16 §2 行 |
| 2.2 任务=多策略合跑+总量封顶 | 落点：框架语义未动 | design §2/§17 |
| 2.3 策略限速+任务封顶 | 落点：框架语义未动 | —（未改框架） |
| 2.4 任务 ID 与独立/共享桶 | 落点：框架语义未动 | —（未改框架） |
| 2.5 flows=N 复制 N 条流 | 落点：spec 不管数量（2.6） | design §2 键表 flow_control 行 |
| 2.6 spec 不管数量 | 落点：同上 | 同上 |
| 2.7 按流变化走动态字段 | 落点：四元组=ip/tcp 层动态；业务字段清单 §16.12 | design §16.12（序号算法待 P4 定→builder seedFor 落定） |
| 2.8 src_port 自动递增保底 | 落点：未写动态保底 12345+i | design §16.12 src_port 行 |
| 2.9 其余字段变化须写动态 | 落点：challenge 为 rand(seed+序号) 确定性派生 | builder.go:263-290 |
| 2.10/2.11 数量/变化表述纪律 | 落点：文档口径一致 | design §16.12 |
| 3.1 多会话显式声明 | 落点：`sessions[]` 显式，每会话独立 ID | core/ntlm.go:47 Sessions；#10/#11 双会话 |
| 3.2 会话独立 ID/四元组/生命周期 | 落点：部分满足——独立 ID+challenge+SessionId；**同 TCP 四元组**（m2 回修设计 s2 行） | builder seedFor(si)；chain_test MultiSessionIsolation:839-843 |
| 3.3 会话内有序序列 | 落点：NEGOTIATE→CHALLENGE→AUTHENTICATE→终态 | planner.go:262-290 advance |
| 3.4-3.7 单事务四件事 | 落点：t1-t4 前置/触发/成功/失败四件事 | design §16.3 事务表；#1/#12 |
| 3.8-3.10 多流关联字段 | 落点：不适用（无派生数据流，设计已诚实声明无 driven_by） | design §16.3 关联关系行 |
| 3.11 时间线顺序/并发/交错 | 落点：会话内有序、跨会话交错、只断言 stream 内重组后顺序 | design §16.3 时间线；§9 |
| 3.12 交错调度方式 | 落点：同上 | 同上 |
| 3.13 不许重复发射冒充编排 | 落点：#10 双会话独立 challenge，非重复发射 | 落盘 pcap 双 challenge 相异 |
| 3.14 豁免边界（多流/多载荷各一例） | 落点：多流 #10/#11；单消息多载荷 #5/#6/#7 | testcase §8.4；**#11 分段实际缺席见 M1** |
| 3.15 三项各一例或立项 | 落点：①#1/#2/#12；②#12+G-NTLM-5；③#11+T-22 | testcase §8.1；**T-22 去向未单列见 M2 注记** |
| 3.16 CWMP 范本 | 落点：差异点已诚实声明（无 driven_by） | design §16.3 |
| 3.17 五件套缺一不开工 | 落点：会话表/事务/关联/插入/时间线齐 | design §16.3 |
| 4.1 连接模型 | 落点：非独立连接协议，寄居 SMB2/HTTP | design §14.1 row 1；MS-SMB2/RFC4559 引文 |
| 4.2 命令/消息表 | 落点：Type1/2/3 + 载体事件（2/3 轮 SESSION_SETUP，401→2xx） | design §14.1 row 2；§14.2 矩阵 |
| 4.3 状态机 | 落点：Initial→…→Accepted/Rejected；重试语义 | planner.go advance；design §14.1 row 3 |
| 4.4 字段表 | 落点：Signature/Type/SB 三元组/AV_PAIR/Version/MIC/blob 全表 | design §4-§7；§14.1 row 4；§14.3 变体表 |
| 4.5 错误处理表 | 落点：6 负例 + 自然守卫 + 预检 | design §10；planner.go；testcase §4 |
| 4.6 超时与活性 | 落点：NTLM 自身无；载体承担；重试=同 session 重发 | design §14.1 row 6 |
| 4.7 NAT/代理/被动 | 落点：139 不生成；代理/CONNECT→G-NTLM-5 | design §14.1 row 7 |
| 4.8 版本/方言 | 落点：NTLMv2 正例；NTLMv1→G-NTLM-6 三选一 | design §14.1 row 8；validateProfile 拒 ntlmv1 |
| 4.9/4.10 规范出处 | 落点：MS-NLMP/MS-SMB2/RFC4178/4559/2743 章节注记 | design §14/§15.1 |
| 4.11 不许二手解读 | 落点：三路出处均为规范/抓包/源码 | design §15.1 |
| 4.12-4.14 三路对照 | 落点：规范/现网/开源三路 + 147 字段实测 | design §15.1；wireshark packet-ntlmssp.c |
| 4.15 不一致取舍 | 落点：outer 必选声明、裸/SPNEGO 双 fixture | design §15.1 末段；#1/#9 |
| 4.16 商业行为→用例映射 | 落点：映射表 + G-NTLM-4/5/6 确认方式 | design §15.2 |
| 4.17 候选方案对比 | 落点：A/B/C/D 四方案，A 采用 | design §15.3 |
| 4.18 不许单方案自说自话 | 落点：四方案齐 | 同上 |
| 4.19-4.21 矩阵三选一+用例对应 | 落点：八项行 + 三子表，逐条已实现/立项/不适用 | design §14 全节 |
| 4.22 三张子表 | 落点：①消息×载体终态 ②变体表 ③商业映射（含适配声明） | design §14.2/§14.3/§15.2 |
| 4.23/4.24 评审看矩阵 | 落点：P1 两轮自审记录 | p123-report |
| 5.1 依赖声明 | 落点：DependsOn[tcp]+OptionalOn[http]+TransportOn[tcp]（裁定 N1） | registry.go:790；design §15.4 |
| 5.2 错误分支 | 落点：6 注入+自然守卫+预检，全 task error 零假成功 | planner.go；design §17 错误分支 |
| 5.3 无依赖/错误分支不许实现 | 落点：齐 | 同上 |
| 5.4-5.5 有依据设计 | 落点：字段/流程/缺省均有规范或现网依据；待确认标 G-立项 | §19 六项 |
| 5.6 结论指文档/代码行 | 落点：本表即逐条指証 | 本表 |
| 5.7 指不出直说不知道 | 落点：IPv6 层名口径差异已诚实注记（chain_test nIP6 注释） | ntlm_chain_test.go:59-61 |
| 5.8/5.9 回复自查+抽查三条 | 落点：本报告抽查三条逐条点代码行/用例号 | p6-review 抽查节 |
| 6.1-6.3 性能目标/指标/两路验收 | 落点：O(n) 流式 + pcap/NIC 双路；数字待 P4 基准（诚实待确认） | design §17 性能段 |
| 6.4 性能依据 | 落点：逐事件渲染直发、无聚合、无锁、pacer 统一 | 同上 |
| 6.5 无依据数字标待确认 | 落点：已标待确认 | 同上 |
| 6.6-6.8 六类场景/断言/预算 | 落点：六类场景 P5 跑测覆盖声明 | 同上 |
| 6.9/6.10 性能节缺一不可 | 落点：设计有性能节 | design §17 |
| 7.1-7.9 三份文档定位 | 落点：60-design/testcase + D-NTLM-1(§17) + T-NTLM(§8)；ID 权威=testcase §2 | p123-report §1 |
| 8.1-8.8 设计八要素 | 落点：文件/签名/结构/流程/错误/性能/冲突/回滚齐 | design §17 |
| 8.9-8.11 定稿纪律 | 落点：门1 获批=定稿=开工门 | 提交序 |
| 8.12/8.13 开工汇报/Diff 门 | 落点：D-NTLM-1 条目号；接线清单逐字 | design §17 文件清单 |
| 9.1 登记 | 落点：ID 权威 testcase §2；cases/ntlm.json 为产物 | testcase §2 |
| 9.2-9.4 三源 | 落点：MS-NLMP/MS-SMB2/RFC + D-NTLM-1 + 现网 + tshark 147 字段 | testcase §8.5 三源回指行 |
| 9.5 每行每字段每错误码有用例 | 落点：47 点台账（8+16+23） | testcase §8.3；**T-21 虚报见 M2** |
| 9.6 颗粒度拆分 | 落点：20 ID 单行为点 | testcase §2 |
| 9.7 修 bug 先复现 | 落点：P5 7 项逐项先跑后钉 | p4-report §2 |
| 9.8 数据场景 | 落点：A′ 数据面→#4-#9/#13 + 负例 #15-#19 | testcase §8.2 |
| 9.9 业务场景 | 落点：#1/#2/#3/#10/#12 | 同上 |
| 9.10 现网场景 | 落点：#1/#3/#9 + G-NTLM-4；**复杂度下限见 9.50（未达）** | 同上 |
| 9.11 多动作组合流≥2 条×3 动作 | 落点：#1/#10/#12 均为 4 事件链 | ntlm.json |
| 9.12/9.13 清单先行 | 落点：P1 矩阵先行 | design §14 |
| 9.14 存量审计 | 落点：占位移除声明；无存量语义用例 | testcase §8.6 |
| 9.15-9.18 RFC 三分类 | 落点：B′=G-NTLM-1…6；C 类未滥用 | testcase §8.2 B′表 |
| 9.19 动词≠覆盖 | 落点：§14.2 逐格给用例号 | design §14.2 |
| 9.20-9.22 枚举/分支/承载全覆盖 | 落点：flags/AV/版本/outer 逐分支有例；承载位置为 sessions 树单形状 | #4/#5/#7/#8/#9 |
| 9.23-9.26 正交矩阵/地址族对称 | 落点：§14.3 row 1-4 地址族×profile；**IPv6×HTTP 缺格见 M2** | design §14.3 |
| 9.27/9.28 断言边界 | 落点：动态值只 presence/nonzero/distinct/same_as/length | design §12；testcase §1 |
| 9.29/9.30 全量全绿 | 落点：suite 20/20 全量重跑 | p4-report §2 |
| 9.31 先跑后钉 | 落点：包数/字段/frames 全按实测钉 | casegen 文件头注释；**⑪行注释错见 M1** |
| 9.32-9.36 动态整格 | 落点：challenge rand(seed+序号) 可复现；会话间相异已断言 | builder seedFor；#10 nonzero×2 |
| 9.37-9.40 通用陷阱 | 落点：mss 派生未撞号；聚合断言无 distinct 端口；静态复制经单流双会话绕开 | ntlm.json（#11 无 distinct 端口断言） |
| 9.41-9.45 测试评审五件事 | 落点：清单/回指/输出断言/失败红/全绿齐 | 本报告 + coverage 89/89 |
| 9.46 数据全表扫 | 落点：§14.3 23 行变体逐项有例或立项 | design §14.3 |
| 9.47 取值全枚举 | 落点：flags/AV/Version/MIC/outer 全枚举 | 同上 row 8-17 |
| 9.48 流程反推逻辑点 | 落点：t1-t4 + 状态机逐点有例 | design §16.3；#1/#12 |
| 9.49 多流/多会话/多事务必查 | 落点：**未达——#11 分段缺席（M1）** | p6-review 9.53 节 |
| 9.50 复合大场景三类交织 | 落点：**未达——最复杂 #11 实际 2 类（M1）** | 同上 |
| 9.51 正交满格组合 | 落点：部分——地址族一格缺失（M2） | design §14.3 row 4 |
| 9.52 对账两行 | 落点：47=40+2+5；**40 含未并入 T-21，数字不成立（M2）** | testcase §8.3 |
| 9.53 门3抽最复杂用例点数 | 落点：已执行——#11 点数 3（fields 2+frames 1），低于下限→打回 | p6-review 9.53 节 |
| 10.1 文档逐条核对 | 落点：P1-P3 逐轮核对记录 | p123-report §2 |
| 10.2 改需求先对旧文档 | 落点：v1.0.0 逐条核对记录（旧键去向/链形立项/§11§10§7 未删） | p123-report §2 |
| 10.3-10.5 代码自查+测试+再审 | 落点：P4 3 轮+P5 2 轮，末轮干净；-race | p4-report §5 |
| 10.6-10.10 测试评审 | 落点：路径/触发/输出断言/覆盖/全绿 | 本报告抽查+覆盖节 |
| 10.11 改审测修再审闭环 | 落点：结论"自审 N 轮末轮干净" | p4-report §5 |
| 11.1-11.5 白话纪律 | 落点：终审回复仅判词+发现数+路径（本报告文件内技术细节不进回复） | 最终回复 |
| 12.1-12.5 策略动态 | 落点：四元组动态；challenge rand 可复现；静态沿用 | design §16.12；builder.go |
| 12.6-12.8 任务动态 | 落点：框架语义未动 | — |
| 12.9/12.10 静态复制禁令 | 落点：单流双会话结构绕开；src_port 保底 | design §16.12 |
| 12.11-12.13 动态住处 | 落点：动态值仍住 ip/tcp/ntlm 层，无顶层并存 | ntlm.json |
| 12.14-12.16 设计清单/测试/评审 | 落点：§16.12 清单 + seedFor 代码位；**"序号算法待 P4 定"一行未回填（顺带修）** | design §16.12 末行；builder.go:263 |
| 13.1-13.6 schema 文件 | 落点：generated 124 层 ntlm 行（terminal/depends/transport/optional+10 字段） | generated layers.generated.json |
| 13.7-13.10 校验入口 | 落点：ValidateStrategy/任务入口；MCP 继承 | validate_layers.go ntlm 预检块 |
| 13.11-13.16 派生只读 | 落点：flowb_query_layers 实时视图一致；struct 标签字面量 | schemagen 一致性 PASS |
| 13.17-13.19 同步规则 | 落点：注册+生成文件同批提交；过期测试绿 | TestLayersGeneratedMatchesRegistry PASS |
| 13.20/13.21 缺席/非法值 | 落点：空 profile=缺省 smb2；非法值逐字拒 | planner.go validateProfile |
| 13.22/13.23 schema 定位 | 落点：机器真相，不抄契约全文 | — |
| 13.24-13.26 评审纪律 | 落点：本表逐条核对 | 本表 |
| 14.1-14.3 用例即 MCP 任务 | 落点：spec_json 即策略 config；无两套写法 | ntlm.json；suite 工具直消 |
| 14.4-14.6 历史迁移 | 落点：旧扁平占位移除；包数按实测重钉非手算 | ntlm.json；casegen 头注释 |
| 14.7-14.10 真实流程三步 | 落点：MCP 建任务→引擎生成→tshark 校对；非"只数包"（fields+frames 双通道） | lane suite；落盘 pcap |
| 14.11/14.12 负例真实流程 | 落点：6 负例 planner/validator 拒 + task error，零假成功 | casegen addNeg 实测锚词落盘 |
| 14.13-14.15 断言口径 | 落点：方向/包号按 pcap 实测；无 distinct 端口聚合陷阱 | p4-report 校准轮 |
| 14.16-14.20 验收纪律 | 落点：全量 20/20；二进制同代（门2-3）；包号取自落盘 | p4-report §2/§4 |
| 15.1/15.2 门1对照表 | 落点：§16 十四行表 + 三行强制展开（§1/§3/§12） | design §16 全节 |
| 15.3 强制展开 | 落点：§16.1 旧键去向+样例；§16.3 五件套；§16.12 动态清单；§16-P2 presence 形 | design §16 |
| 15.4 门2①顶层零残留 | 落点：绿 | p4-report §4 |
| 15.5 门2②全量绿 | 落点：绿（20/20） | 同上 |
| 15.6 门2③二进制同代 | 落点：绿 | 同上 |
| 15.7 门2④覆盖反查 | 落点：绿（89/89 + kerberos 回归 53/53） | 同上（独立复跑 ntlm 89/89） |
| 15.8 D-条目挂门1表 | 落点：待主线程（本终审为 P6 输入） | — |
| 15.9 抽查三条点代码行/用例号 | 落点：已执行，三条全点到 | p6-review 抽查节 |
| 15.10 白话+三门证据 | 落点：最终回复白话一句 + 本两报告为证据 | 最终回复 |
| 15.11 任一门红就停 | 落点：门3 红（M1/M2）→打回，不跳过 | p6-review 判词 |
