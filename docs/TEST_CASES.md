# 测试用例文档（唯一维护入口）

> 维护人：用户本人单独维护。AI 默认只读；未经用户明确指示，不得擅自改写。
> 本文档是项目测试设计、覆盖范围和验收标准的唯一维护入口。

## 1. 三份权威文档的关系

项目日常只维护三份权威文档：

1. `docs/CORE_MEMORY.md`：定义不能违反的原则；
2. `docs/CODE_DESIGN.md`：定义代码应该怎样实现；
3. `docs/TEST_CASES.md`：定义怎样证明设计和实现正确、完整且满足性能要求。

测试用例文档不能脱离规范和代码设计自行发明行为。每个测试点必须能够回指到 RFC/官方文档条款、代码设计条目或已确认的现网行为。

`test/`、`internal/**/*_test.go`、`test/protocol_pcap/cases/*.json` 等是可执行测试产物，不属于第四类权威文档；它们必须回指本文档中的测试点编号。既有协议测试文档保留为历史参考，新测试只登记在本文档。

## 2. 测试设计的最低要求

每个功能、协议或修复至少覆盖：

- 数据：正常值、空值、零值、最小值、最大值、边界相邻值、超长、截断、非法值、非法组合、编码/字节序和校验；
- 业务：完整操作序列、事务依赖、失败分支、重试、重连、超时、异常终止、长事务和中断后继续；
- 会话与流：单会话、多会话、并发会话、多事务、多数据/媒体流、控制流与数据流关联、顺序和交错；
- 网络承载：数据链路层、网络层、传输层的地址、端口、标识、序号、递增、回绕、显式覆盖和 IPv4/IPv6；
- 输出：pcap 文件与真实网卡/NIC 两条路径，断言实际线上字节和可观察行为；
- 性能：目标吞吐、目标并发、压力上限、长时间运行、内存、CPU、队列积压、背压、限速准确性、丢包和失败传播。

只断言“不 panic”“任务未报错”或“对象存在”不算覆盖。必须断言输出值、包序列、状态、资源和性能结果。

## 3. 原子用例原则

- 一个用例只验证一个主要行为点；多条件组合拆成多个用例。
- 一个规范字段的每个重要值域分别登记，不用一个“综合用例”代替整张字段表。
- 每个错误分支必须有真实会失败的输入，并验证错误从 planner/validator 传播到任务终态和 API/MCP 返回结果。
- 修复缺陷必须先登记能复现缺陷的 failing case，再改代码；不能先改代码再补一个只会通过的例子。
- 用例不得通过删除断言、放宽阈值、改变错误期望或把失败改成跳过来消除问题。

## 4. 测试点模板

新增测试点按下面结构登记。编号必须唯一且稳定，执行文件、pcap case 和测试代码都引用该编号。

```markdown
### T-<编号> <测试点名称>

**状态：** 草案 / 已批准 / 实现中 / 已通过 / 阻塞 / 已废弃
**级别：** unit / integration / pcap / NIC / performance / race
**来源：** RFC/官方文档章节；`docs/CODE_DESIGN.md` 的 D-编号；现网证据（如有）
**目标：** 只描述一个可观察行为。

**输入：** 严格层链配置、策略/任务配置、数据、并发规模和输出方式。
**前置条件：** 依赖服务、网卡、文件、环境变量、端口和资源预算。
**执行：** 精确命令、接口调用或任务流程。
**期望输出：** 包数、字段、字节、顺序、方向、状态和关联关系。
**错误期望：** 锚词、错误传播路径、任务终态、重试/中止和资源释放。
**性能期望：** 吞吐、延迟、内存、CPU、队列、丢包/失败阈值。
**实现位置：** 测试文件或 `test/protocol_pcap/cases/<proto>.json`。
```

## 5. 代码路径覆盖清单

测试评审必须逐项确认以下路径是否真实被触发：

- 配置解析、层链补全、字段校验、协议推断和旧字段拒绝；
- 策略到任务的转换、策略级数量/速率、任务级总上限和优先级；
- 每条流的四元组、分片、IP 标识、TCP/UDP/SCTP 序号和显式覆盖；
- 控制流/数据流的父子关系、流 ID、端口来源、握手、数据、终止和交错；
- planner/validator 错误是否真正终止任务，不能出现“completed/0 packet”的假成功；
- pcap 输出、真实网卡输出、多个 worker、队列背压、限速和取消路径；
- 并发正确性：既验证 `-race`，也验证总吞吐、顺序、关联和资源使用是否正确。

## 6. 性能测试规则

性能用例必须从 `docs/CODE_DESIGN.md` 的“性能设计与验收”章节派生，不能凭经验临时定数字。每个性能数字必须标明：

- 来源：现有基准、代码约束、设备能力或待确认；
- 测量对象：包/秒、比特/秒、端到端延迟、生成延迟、内存、CPU、队列长度、NIC 丢包；
- 测量窗口：短基线、目标持续时间、长时间运行和压力阶段；
- 并发模型：流数、会话数、worker 数、输出路径和限速配置；
- 通过条件与失败边界：不能只写“性能正常”。

性能用例至少包含：

1. 单流功能基线；
2. 目标并发和目标吞吐；
3. 压力上限与资源耗尽；
4. 长时间运行和队列背压；
5. 多 worker 总速率准确性；
6. pcap 与真实 NIC 输出对比；
7. `-race`、资源释放和取消后的无泄漏检查。

### T-SCHEMA-1 策略形状（strategy.json）

**状态：** 已通过
**级别：** unit
**来源：** `docs/CODE_DESIGN.md` D-SCHEMA-1 §1；`trafficgen/schemas/v1/strategy.json`
**目标：** 畸形策略形状被拒，合法最小/动态/回放/层链形状放行。

**输入：** `ValidateStrategyShape` 直接喂文档（缺 name、坏 mode、坏 FC 类型、0 值 FC、replay 带 layers、无 asset、越界 dscp/port、坏 MAC、坏 tftp mode/tid、multiplier 缺值、inc 缺 range；合法 dynamic/replay/layers 各一）。
**前置条件：** 无（纯内存）。
**执行：** `go test ./internal/core/schema/ -run 'TestValidMinimal|TestInvalidCases|TestValidDynamicAndReplay'`
**期望输出：** 14 个非法全红、3 个合法全绿。
**错误期望：** 锚词为 schema 叶消息（`required`/`enum`/`exclusiveMinimum`/MAC `pattern` 等）。
**性能期望：** 不适用。
**实现位置：** `internal/core/schema/schema_test.go`。

### T-SCHEMA-2 策略语义与历史文案对齐

**状态：** 已通过
**级别：** unit
**来源：** D-SCHEMA-1 §3/§5；`strategy_handler.go` 历史分支（createSynth/createReplay/Update）
**目标：** 语义错的报错字样与老接口逐字一致；形状与语义同错时语义优先。

**输入：** 坏 IP/MAC 格式、越界 dscp、未知协议、TFTP tid 碰撞（flows=2+server_tid）、replay 坏 speed/direction/checksum、replay 空 direction+checksum 放行、layers 推断 `[ip,tcp,http]`。
**前置条件：** 无。
**执行：** `go test ./internal/core/schema/ -run 'TestSemanticMatchesHandlerMessages|TestSemanticLayersInference'`
**期望输出：** 逐例子含指定子串（`invalid IP format: src_ip`、`server_tid 5000 conflicts`、`invalid speed mode`、`invalid direction`、`invalid checksum_mode` 等）；空可选项放行且推断出 protocol。
**错误期望：** 同上（断言“含子串”即文案锚）。
**性能期望：** 不适用。
**实现位置：** `internal/core/schema/semantic_test.go`。

### T-SCHEMA-3 显式 null 拒绝与 MCP 省略键

**状态：** 已通过
**级别：** unit + integration
**来源：** D-SCHEMA-1 §4/§5；用户裁决“有值与缺失是两回事，MCP 负责省略”
**目标：** replay 可选项显式 null 被人话拒绝（语义用例 nil 三键 speed/direction/checksum_mode；loop/rewrites/flow_scaling 同走一条 null 分支）；MCP 未填可选项时转发/存量均无占位键（断言 5 键缺席）。

**输入：** `ValidateStrategy` 喂 `speed/direction/checksum_mode=nil`；`handleReplayPcap` 全缺省调用后查库。
**前置条件：** MCP 测试库（`setupMCPTest`）+ pcap 资产。
**执行：** `go test ./internal/core/schema/ -run TestSemanticMatchesHandlerMessages`；`go test ./internal/mcp/ -run TestMCP_ReplayPcap_OmitsEmptyOptionals`
**期望输出：** null 用例报错含 `is null; omit`；MCP 用例存量 config 无 speed/direction/checksum_mode/rewrites/flow_scaling 键且有 pcap_asset_id。
**错误期望：** null 走语义翻译，不漏 reflect 行话（`has type "null"`）。
**性能期望：** 不适用。
**实现位置：** `internal/core/schema/semantic_test.go`、`internal/mcp/tools_workflow_test.go`。

### T-SCHEMA-4 任务与批量形状+语义

**状态：** 已通过
**级别：** unit
**来源：** D-SCHEMA-1 §3；`task.json`/`batch.json`
**目标：** 任务二选一、输出配对、封包文案、批量类规则、replay+bps 冲突皆按设计执行。

**输入：** 好任务（strategy_ids+pcap）放行；坏 6 例（无 ids 又无 batch、双带、空 ids、port_group 缺 id、pcap 缺 path、坏 FC）；批量好/坏 4 例（含 replay 缺 spec、replay null direction）；replay+bps 冲突（original 策略配 bps 任务封包）。
**前置条件：** 无。
**执行：** `go test ./internal/core/schema/ -run 'TestTaskShape|TestBatchShape|TestTaskCreateEntry'`
**期望输出：** 好放行、坏全红、冲突文案含 `cannot combine with bps`。
**错误期望：** 封包错用历史文案（`invalid flow_control type`），其余 schema 叶消息。
**性能期望：** 不适用。
**实现位置：** `internal/core/schema/semantic_test.go`。

### T-SCHEMA-5 注册表生成表与过期门

**状态：** 已通过
**级别：** unit
**来源：** D-SCHEMA-1 §1/§5；`layers.DefaultRegistry`
**目标：** 生成表与实时注册表一致；过期必红且指明重跑命令；层链形状合法/非法正确判定。

**输入：** `LayersGenerated` 对 `DefaultRegistry` 逐层比对（95 层：层数/分类/字段数/字段类型）；`ValidateLayersShape` 好链放行、空链/双键条目/裸字符串拒绝。
**前置条件：** 生成文件已提交。
**执行：** `go test ./internal/core/schema/ -run 'TestLayersGeneratedMatchesRegistry|TestLayersShape'`
**期望输出：** 全绿；造假（删一层）后变红，恢复后变绿（已实测）。
**错误期望：** 过期信息含 `regenerate via go run ./internal/core/layers/schemagen`。
**性能期望：** 不适用。
**实现位置：** `internal/core/schema/schema_test.go`；生成器 `internal/core/layers/schemagen/main.go`。

### T-SCHEMA-6 负例一致性横扫（REST vs MCP）

**状态：** 已通过
**级别：** integration
**来源：** D-SCHEMA-1 §5；MCP `callHandler` 转发语义（不自验、不改写 message）
**目标：** 同一坏配置走 REST 与走 MCP，失败且报错逐字一致。

**输入：** 策略 12 例（坏 IP/MAC、越界、未知协议、坏 FC 类型、replay 带 layers、坏 speed/checksum、null direction、未知层、层未知字段、空链）+ 任务 5 例（无 ids 又无 batch、未知策略、坏任务 FC、port_group 缺 id、批量 null direction），共 17 例；REST 喂 JSON body、MCP 喂等价输入结构。
**前置条件：** MCP 测试 env（含 DB/engine/Server）；REST 用 gin 测试路由。
**执行：** `go test ./internal/mcp/ -run TestNegativeParity`
**期望输出：** 17 例全绿（两边都失败且 `REST == MCP`）；横扫曾抓到起草用例错误（`tcp.mss=1` 实为合法）并已替换为真负例。
**错误期望：** 断言“逐字相等”，分叉即 wiring bug（MCP 改写/美化）。
**性能期望：** 不适用。
**实现位置：** `internal/mcp/negative_parity_test.go`。

### T-FTP-1 老形状零回归（sessions 缺席）【链化注记：cases 现为 `[ip,tcp,ftp]` 层链 JSON，经 `flowb_run_protocol_suite` 直接消费；链语义下数据通道 8 包（无冗余对端 ACK）、sessions_dual 46 包（CloseConn 内联挥手去重），Task 6 提交 c60e922 实测 21/21】

**状态：** 草案
**级别：** unit + pcap
**来源：** `docs/CODE_DESIGN.md` D-FTP-1；RFC 959 §4.1（CRLF 命令/响应对）
**目标：** `Sessions` 缺席时包序列与现实现逐包一致。

**输入：** 现有 ftp cases（banner+命令对+EmitDataChannel 单数据流）。
**前置条件：** 无。
**执行：** `go test ./internal/protocol/ftp/ -count=1`（既有 5 文件全量）
**期望输出：** 全绿；包数=3（握手）+banner 有无各 1/0+命令非空各 1 包+响应非空各 1 包+数据流包+4（teardown）。
**错误期望：** 无（回归项）。
**性能期望：** 不适用。
**实现位置：** `internal/protocol/ftp/ftp_*_test.go`（既有）。

### T-FTP-2 双会话操作序列（RETR+LIST）

**状态：** 草案
**级别：** unit
**来源：** D-FTP-1 §3；记忆 ftp-rfc-session-scheduling（操作序列+独立四元组）
**目标：** 两会话各走独立 TCP 连接，命令序列不串扰，序号空间隔离。

**输入：** spec `SrcIP=10.0.0.1,DstIP=20.0.0.1,DstPort=21` + `Sessions:[{SrcPort:20000,Banner:"220 s1",Transactions:[{Commands:[{USER..},{PASV(227→50001)},{RETR +EmitDataChannel}],DataChannel:{}}]},{SrcPort:20001,Banner:"220 s2",Transactions:[{Commands:[{CWD..},{PASV(227→50002)},{LIST +EmitDataChannel}],DataChannel:{}}]}]`（DataChannel 空对象=走端口推导；PASV 信令在命令对内给出，断言时可区分推导来源）。
**前置条件：** 无。
**执行：** `go test ./internal/protocol/ftp/ -run TestFTPMultiSession -count=1`
**期望输出：** 会话1 flowID=`10.0.0.1-20.0.0.1-20000-21`、会话2=`10.0.0.1-20.0.0.1-20001-21`（全串相等）；每会话独立 SYN 起始（serverSeq/clientSeq 不跨会话连续；InitialSeq 缺席时双会话 ISN 均随机且互异）；命令载荷按会话归属（RETR 只在会话1，LIST 只在会话2）。
**错误期望：** 会话2 SrcPort 缺席（0）时沿用 spec.SrcPort（覆盖规则）。
**性能期望：** 不适用。
**实现位置：** `internal/protocol/ftp/ftp_testpoints_test.go`（新增）。

### T-FTP-3 数据流挂载事务索引

**状态：** 草案
**级别：** unit
**来源：** D-FTP-1 §3；`internal/core/subflow.go:55`（`{parent}:sub-{idx}`）
**目标：** 同一会话内两条数据流的 parent 索引不同（替代 `sub-0` 碰撞）。

**输入：** spec `SrcIP=10.0.0.1,DstIP=20.0.0.1,SrcPort=22000,DstPort=21` + 单会话（Banner:"220 s"）双事务：事务1 `{PASV(227→50011),RETR +EmitDataChannel}`、事务2 `{PASV(227→50012),LIST +EmitDataChannel}`，DataChannel 皆空对象走推导。
**前置条件：** 无。
**执行：** `go test ./internal/protocol/ftp/ -run TestFTPDataChannelTxIndex -count=1`
**期望输出：** 数据流1 FlowID=`10.0.0.1-20.0.0.1-22000-21:sub-0`（client 22001→server 50011）、数据流2=`10.0.0.1-20.0.0.1-22000-21:sub-1`（client 22001→server 50012）；150→数据→226 交错顺序保持。
**错误期望：** DataChannel 为空时 EmitDataChannel=true 不发射（现有语义保留）。
**性能期望：** 不适用。
**实现位置：** `internal/protocol/ftp/ftp_testpoints_test.go`（新增）。

### T-FTP-4 跨事务 PASV 端口不串扰

**状态：** 草案
**级别：** unit
**来源：** D-FTP-1 §1（信令扫描域收窄）；`scanCommandsForDataPort` 全局扫描缺陷
**目标：** 后事务的数据流不用前事务 227 响应里的端口。

**输入：** spec `SrcIP=10.0.0.1,DstIP=20.0.0.1,SrcPort=21000,DstPort=21` + 单会话双事务：事务1 PASV 响应含端口 50001+RETR，事务2 PASV 响应含端口 50002+LIST；DataChannel 端口全 0（走推导：client=21001，server 取各事务 PASV）。
**前置条件：** 无。
**执行：** `go test ./internal/protocol/ftp/ -run TestFTPPASVIsolation -count=1`
**期望输出：** 数据流1（client 21001→server 50001）、数据流2（client 21001→server 50002）；全局扫描下两者 server 都会是 50001，测试能区分。
**错误期望：** 无 PASV 信令时回退 50000（现有语义保留）。
**性能期望：** 不适用。
**实现位置：** `internal/protocol/ftp/ftp_testpoints_test.go`（新增）。

### T-FTP-5 空会话边界（实现循环新增）

**状态：** 已通过
**级别：** unit
**来源：** `docs/CODE_DESIGN.md` D-FTP-1 §5（会话无事务=仅握手+banner+teardown）；实现自审探针转正
**目标：** 无事务会话只发握手 3 包+teardown 4 包=7 包。

**输入：** 单会话无事务（SrcPort=23001）。
**前置条件：** 无。
**执行：** `go test ./internal/protocol/ftp/ -run TestFTPEmptySession -count=1`
**期望输出：** 包数恰为 7。
**错误期望：** 无。
**性能期望：** 不适用。
**实现位置：** `internal/protocol/ftp/ftp_sessions_test.go`（TestFTPEmptySession）。

### T-FTP-6 DataChannel 无标记不发射（实现循环新增）

**状态：** 已通过
**级别：** unit
**来源：** D-FTP-1 §5（与老路径 `EmitDataChannel && dc != nil` 同判定）；实现自审探针转正
**目标：** 事务带 DataChannel 但无命令标记时不发射子流。

**输入：** 单事务 Commands={RETR,150} 无标记 + DataChannel 有负载。
**前置条件：** 无。
**执行：** `go test ./internal/protocol/ftp/ -run TestFTPDataChannelNoFlag -count=1`
**期望输出：** 输出中无任何 `:sub-` FlowID。
**错误期望：** 无。
**性能期望：** 不适用。
**实现位置：** `internal/protocol/ftp/ftp_sessions_test.go`（TestFTPDataChannelNoFlag）。

### T-FTP-7 策略四元组动态 inc（同键二态）【v2 留档：四元组部分被 v3 替代，实现代码未合并不执行】【v2 留档：四元组部分被 v3 替代，实现代码未合并不执行】

**状态：** 已通过
**级别：** unit
**来源：** CORE_MEMORY §12；`docs/CODE_DESIGN.md` D-FTP-2 §3/§4；批量基线 `internal/core/worker.go:737-763`
**目标：** 策略 config 四元组字段写动态对象时 worker 策略循环按流序号确定性产出四元组，与批量同语义。

**输入：** 策略 config `{"src_ip":{"strategy":"inc","range":["10.0.1.1","10.0.1.5"]},"src_port":{"strategy":"inc","range":[20000,20009]},"dst_port":80}`（同键二态：四元组字段直接写对象）+ flow_control flows=5；engine 进程内驱动（SubmitTask + spec 捕获 planner，同 `internal/core/engine_test.go` 现有写法）。
**前置条件：** 无。
**执行：** `go test ./internal/core/ -run TestWorkerStrategyTuplesInc -count=1`
**期望输出：** 第 i 流 `src_ip=10.0.1.(1+i)`、`src_port=20000+i`（i=0..4；未配动态的 dst_ip 保留 spec 默认 20.0.0.1、dst_port=80）；每流 Plan 收到的 spec 值即最终值。
**错误期望：** range 非法时（本例无）不适用。
**性能期望：** 不适用。
**实现位置：** `internal/core/worker_tuples_test.go`（新增）。

### T-FTP-8 rand 可复现 + 到尾回绕【v2 留档：四元组部分被 v3 替代，实现代码未合并不执行】【v2 留档：四元组部分被 v3 替代，实现代码未合并不执行】

**状态：** 已通过
**级别：** unit
**来源：** D-FTP-2 §4；CORE_MEMORY §12（seed+序号同结果、到尾回绕）
**目标：** rand 同 seed 同序号同值；inc/list/pattern 超尾回绕。

**输入：** ①config `src_ip` 写 `{"strategy":"rand","range":["10.0.0.1","10.0.0.254"],"seed":42}` flows=100 两次运行全量比对；②src_port 写 inc range [1,3] flows=5；③src_port 写 list ["1","2"] flows=4；④group_id 写 pattern "user{n}" n_range [1,2] flows=4（同键二态输入，无 tuples 键）。
**前置条件：** 无。
**执行：** `go test ./internal/core/ -run TestWorkerTuplesReproducible -count=1`
**期望输出：** ①两次 100 流四元组逐一相等；②inc 第 4/5 流回绕为 1/2；③list 序列 a,b,a,b；④pattern 序列 user1,user2,user1,user2。
**错误期望：** 无。
**性能期望：** 不适用。
**实现位置：** `internal/core/worker_tuples_test.go`。

### T-FTP-9 动态四元组覆盖（fixed 端点 + 分片一致）【v2 留档：四元组部分被 v3 替代，实现代码未合并不执行】【v2 留档：四元组部分被 v3 替代，实现代码未合并不执行】

**状态：** 已通过
**级别：** unit
**来源：** D-FTP-2 §1/§4（E1 决策）；批量覆盖序 worker.go:746-755
**目标：** 动态解析值非零才覆盖（不砸未配端点）；分片键反映最终四元组。

**输入：** config `dst_ip` 写 `{"strategy":"inc","range":["20.0.1.1","20.0.1.2"]}`、`src_port` 写 `{"strategy":"fixed","value":51000}` flows=2；断言 spec 终值（fixed=常量路径，兼验 fixed 策略；未配动态的 dst_port 保持默认）。
**前置条件：** 无。
**执行：** `go test ./internal/core/ -run TestWorkerTuplesOverridesOnlyNonzero -count=1`
**期望输出：** 两流 src_port 恒 51000；dst_ip=20.0.1.1/20.0.1.2；computeHashKey 收到的 spec 即上述终值（最终四元组进分片键）；FlowIndex 逐流 0/1。
**错误期望：** 无。
**性能期望：** 不适用。
**实现位置：** `internal/core/worker_tuples_test.go`。

### T-FTP-10 FTP 会话 src_port/banner 动态【v2 留档：四元组部分被 v3 替代，实现代码未合并不执行】【v2 保留：FTP 字段本就在层内，v3 沿用】

**状态：** 已通过
**级别：** unit
**来源：** D-FTP-2 §1/§3/§4；RFC 959 §3.x（多控制连接模型）
**目标：** 会话级动态端口按流序号解析并驱动独立四元组；banner 动态按会话替换。

**输入：** 单会话（sessions 数组 1 项，事务静态）+ 会话内 `"src_port":{"strategy":"inc","range":[21000,21001]}`、`"banner":{"strategy":"list","list":["220 a","220 b"]}`（同键二态：会话字段直接写对象）+ fc flows=2——流 i=0/1 的会话分别解析出 21000/21001 与 banner a/b（会话级动态按流序号逐流变，见 D-FTP-2 §3 索引域）。
**前置条件：** 无。
**执行：** `go test ./internal/protocol/ftp/ -run TestFTPSessionDynamicPortBanner -count=1`
**期望输出：** 会话 flowID `10.0.0.1-20.0.0.1-21000-21`、`10.0.0.1-20.0.0.1-21001-21`；down 首 PSH 载荷分别 `220 a`、`220 b`。
**错误期望：** 无。
**性能期望：** 不适用。
**实现位置：** `internal/protocol/ftp/ftp_dyn_test.go`（新增）。

### T-FTP-11 命令/响应动态（pattern）【v2 留档：四元组部分被 v3 替代，实现代码未合并不执行】【v2 保留：FTP 字段本就在层内，v3 沿用】

**状态：** 已通过
**级别：** unit
**来源：** D-FTP-2 §1/§4；CORE_MEMORY §12（业务字段逐协议清单：FTP=cmd/response/payload）
**目标：** cmd/response 动态按流序号替换，且响应替换后 PASV 端口推导仍取已解析文本。

**输入：** 单会话两事务 + fc flows=2：事务1 `"cmd":{"strategy":"pattern","pattern":"USER user{n}","range":[1,2]}`+response:"331"；事务2 PASV 响应（静态，含 195,73）+`"cmd":{"strategy":"pattern","pattern":"RETR f{n}","range":[1,3]}`+response:"150"+EmitDataChannel（同键二态）。
**前置条件：** 无。
**执行：** `go test ./internal/protocol/ftp/ -run TestFTPDynCommands -count=1`
**期望输出：** 流0 up 载荷含 `USER user1`、`RETR f1`；流1 含 `USER user2`、`RETR f2`（同一流的两个事务共用流序号解析，各自 pattern 独立取值）；流0 数据流 server 端口=49993（195·256+73，PASV 推导取已解析响应；两会话 PASV 同文本故两流数据端口同为 49993）。
**错误期望：** 无。
**性能期望：** 不适用。
**实现位置：** `internal/protocol/ftp/ftp_dyn_test.go`。

### T-FTP-12 数据负载动态 + FileSource 优先级【v2 留档：四元组部分被 v3 替代，实现代码未合并不执行】【v2 保留：FTP 字段本就在层内，v3 沿用】

**状态：** 已通过
**级别：** unit
**来源：** D-FTP-2 §4（DataChannel 优先级）；既有 FileSource 语义
**目标：** payload 动态解析生效；FileSource 存在时动态/静态文本 payload 均被忽略。

**输入：** ①单会话单事务（EmitDataChannel 标记）+ data_channel `"payload":{"strategy":"pattern","pattern":"FILE-{n}","range":[1,3]}`（同键二态）+ fc flows=2，断言两流载荷 `FILE-1/FILE-2`（会话内多事务共用同一流序号解析出同值——索引域规则，见 D-FTP-2 §3）；②同形状 + FileSource（literal）断言载荷=文件内容（既有 FileSource > payload 文本优先级不变）。
**前置条件：** 无。
**执行：** `go test ./internal/protocol/ftp/ -run TestFTPDynPayload -count=1`
**期望输出：** ①数据 PSH 载荷 `FILE-1`/`FILE-2`；②载荷=literal 文件内容（动态不生效）。
**错误期望：** 无。
**性能期望：** 不适用。
**实现位置：** `internal/protocol/ftp/ftp_dyn_test.go`。

### T-FTP-13 FTP 业务动态可复现性（seed+序号）【v2 留档：四元组部分被 v3 替代，实现代码未合并不执行】【v2 保留：FTP 字段本就在层内，v3 沿用】

**状态：** 已通过
**级别：** unit
**来源：** CORE_MEMORY §12；D-FTP-2 §4
**目标：** FTP 字段 rand 策略同 seed 两次 Plan 序列一致。

**输入：** 会话 `"banner":{"strategy":"rand","range":[1,100],"seed":7}`（同键二态；payload 侧用 cmd pattern 即可覆盖字符串五策略的另一路）flows=3，两次 Plan 全量比对 up/down 载荷序列。
**前置条件：** 无。
**执行：** `go test ./internal/protocol/ftp/ -run TestFTPDynReproducible -count=1`
**期望输出：** 两次载荷序列逐一相等（banner rand 解析为纯数字串，属五策略通用解析路径的有效取值）。
**错误期望：** 无。
**性能期望：** 不适用。
**实现位置：** `internal/protocol/ftp/ftp_dyn_test.go`。

### T-FTP-14 畸形动态配置拒绝（FTP Validate → 任务 error）【v2 部分保留：FTP 畸形部分有效，四元组扁平畸形部分被 v3 替代】【v2 留档：四元组部分被 v3 替代，实现代码未合并不执行】

**状态：** 已通过
**级别：** unit
**来源：** D-FTP-2 §5（F1 决策）；CORE_MEMORY §9（失败路径必须真红）
**目标：** 非法动态对象使 Plan 返回 error（不许静默回退静态）；批量路径逐流跳过计数。

**输入：** ①config `src_port` 写 `{"strategy":"inc"}`（range 缺失，走 mapToFlowSpec ValidationErrors）；②FTP 会话 src_port 写 `{"strategy":"inc"}`（走 Planner.Validate）；③会话 src_port 写 `{"strategy":"nope"}`；④cmd 写 `{"strategy":"list","list":[]}`；⑤pattern 缺 range。
**前置条件：** 无。
**执行：** `go test ./internal/protocol/ftp/ -run TestFTPDynInvalid -count=1`
**期望输出：** 各例返回 error 且错误信息含策略/字段名与原因锚词（①在 ValidationErrors，②..⑤在 Planner.Validate/Plan）；畸形对象绝不静默按静态/零值发射。策略路径（worker.go:210/222 预检）同 spec 以任务终态 error 结束、0 包。
**错误期望：** 批量路径同一 spec 计入 flowFailures（不中断整类）。
**性能期望：** 不适用。
**实现位置：** `internal/protocol/ftp/ftp_dyn_test.go`。

### T-FTP-15 flat 静态复制拒绝（create 语义层）【v2 留档：四元组部分被 v3 替代，实现代码未合并不执行】【v2 留档：四元组部分被 v3 替代，实现代码未合并不执行】

**状态：** 已通过
**级别：** unit + integration
**来源：** CORE_MEMORY §12（静态复制不许充数）；D-FTP-2 §5（C1 决策）
**目标：** flows>1 + 显式标量 src_port 在 create/Update 均 400；省略 src_port 或 src_port 改写动态对象通过。

**输入：** ①`config:{src_port:12345,tcp:{...}}` + fc flows=3；②同形状省略 src_port；③同形状 src_port 改写 `{"strategy":"fixed","value":12345}`（动态对象=逃生口）；④带 `layers` 的同语义配置（端口写在 tcp 层）不吃此门照常通过。
**前置条件：** REST 测试 env。
**执行：** `go test ./internal/api/rest/ -run TestStaticCopyRejection -count=1`（语义层单测走 schema.ValidateStrategy）
**期望输出：** ①400 文案含 src_port/自动递增/动态锚词；②③④201。
**错误期望：** 错误只走统一入口，REST/MCP 同文案（负例横扫覆盖）。
**性能期望：** 不适用。
**实现位置：** `internal/core/schema/semantic_test.go` + `internal/api/rest/strategy_testpoints_test.go`。

### T-FTP-16 FTP sessions 静态复制拒绝【v2 留档：四元组部分被 v3 替代，实现代码未合并不执行】【v2 保留：FTP 字段本就在层内，v3 沿用】

**状态：** 已通过
**级别：** unit
**来源：** D-FTP-2 §5；CORE_MEMORY §12
**目标：** spec.Count>1 且会话端口全静态（或全继承且显式写了 spec src_port）且无任何会话动态端口时 Validate 拒绝；任一会话动态/未显式继承即通过。

**输入：** ①两静态会话（src_port 显式）+ Count=2；②同会话+任一 src_port 改写动态对象；③单会话继承+Count=1；④显式 spec src_port+继承会话+Count=2；⑤单静态会话（src_port 显式）+Count=2（规则"存在静态会话端口"也命中单会话多流复制）。
**前置条件：** 无。
**执行：** `go test ./internal/protocol/ftp/ -run TestFTPStaticCopyRejection -count=1`
**期望输出：** ①④⑤Validate error（文案含静态复制锚词与三条出路）；②③通过。
**错误期望：** spec.Count=0（批量路径 Plan 语义）不触发拒绝（已知边界，批量类不受此门约束）；拒绝在任务启动的预检 Validate 触发（与 flat 规则的建策略 400 时机不同，见 D-FTP-2 §5）。
**性能期望：** 不适用。
**实现位置：** `internal/protocol/ftp/ftp_dyn_test.go`。

### T-FTP-17 老形状与存量集成回归 + 横扫扩容【v2 留档：四元组部分被 v3 替代，实现代码未合并不执行】【v2 留档：四元组部分被 v3 替代，实现代码未合并不执行】

**状态：** 已通过
**级别：** unit + integration
**来源：** T-FTP-1（既有回归项）+ 负例横扫 T-SCHEMA-6；D-FTP-2 §1（schema 同步）
**目标：** 老形状零回归；负例横扫补动态畸形与静态复制两例达 19 例。

**输入：** 既有 ftp 全套件 + 存量显式端口+flows>1 集成用例（按新规则更新输入）+ 横扫新增：`config:{"src_port":{"strategy":"inc"}}`（range 缺失，形状红）、`config:{src_port:12345}+fc flows=2`（语义红）。
**前置条件：** 无。
**执行：** `go test ./internal/... -count=1`；`go test ./internal/protocol/ftp/ ./internal/core/ ./internal/api/rest/ ./internal/mcp/ -race -count=1`；横扫 `go test ./internal/mcp/ -run TestNegativeParity -count=1`
**期望输出：** 全绿；横扫 19 例两边同文案。
**错误期望：** 存量显式端口+flows>1 的集成用例（如 flowcontrol_integration IT1/IT2）必须按新规则改为省略端口后转绿（规则变更的可视化）；离线 pcap 套件 count=1 不受影响。
**性能期望：** 回归耗时不超基线 +10%。
**实现位置：** 既有测试文件 + `internal/mcp/negative_parity_test.go`（+2 例）。

### T-FTP-7 层 ip/tcp 动态 inc（层形状）【v3 改版：输入从扁平键改为层字段】

**状态：** 已通过（D-FTP-3 步骤2-3/4，提交 a986ead+e8c807f；`TestWorkerLayerDynInc`+`TestParseLayerDyn` 全绿）
**级别：** unit
**来源：** D-FTP-3 §3/§4；CORE_MEMORY §12
**目标：** 层内 `ip.src`/`tcp.src_port` 写动态对象时 worker 策略循环按流序号产出四元组。

**输入：** layers `[{"ip":{"src":{"strategy":"inc","range":["10.0.1.1","10.0.1.5"]},"dst":"20.0.0.1"}},{"tcp":{"src_port":{"strategy":"inc","range":[20000,20009]},"dst_port":80}}]` + fc flows=5；engine 进程内驱动 spec 捕获。
**前置条件：** 无。
**执行：** `go test ./internal/core/ -run TestWorkerLayerDynInc -count=1`
**期望输出：** 第 i 流 spec.SrcIP=10.0.1.(1+i)、spec.SrcPort=20000+i；dst 端保持静态；Plan 收到的 spec 即终值。
**错误期望：** 无。
**性能期望：** 不适用。
**实现位置：** `internal/core/worker_tuples_test.go`（改版复用文件，函数改名）。

### T-FTP-8 层动态 rand 可复现 + 回绕（含 MAC/TTL）

**状态：** 已通过（D-FTP-3 步骤2-3，提交 a986ead；`TestWorkerLayerDynReproducible` 全绿）
**级别：** unit
**来源：** D-FTP-3 §4；CORE_MEMORY §12
**目标：** rand 同 seed 两次运行一致；inc/list 到尾回绕；MAC/TTL 名单字段动态生效。

**输入：** ①`ip.dst` 写 rand range ["20.0.0.1","20.0.0.10"] seed 42 flows=100 两次比对；②`tcp.src_port` inc [1,3] flows=5；③`tcp.src_port` list 轮换；④`eth.dst_mac` inc OUI 保留 flows=3；⑤`ip.ttl` inc [64,66] flows=4。
**前置条件：** 无。
**执行：** `go test ./internal/core/ -run TestWorkerLayerDynReproducible -count=1`
**期望输出：** ①两次逐流相等且至少 2 个不同值；②1,2,3,1,2；③轮换；④OUI 前 3 字节不变、后 3 字节递增；⑤64,65,66,64。
**错误期望：** 无。
**性能期望：** 不适用。
**实现位置：** `internal/core/worker_tuples_test.go`。

### T-FTP-9 层动态覆盖（fixed + 分片一致）

**状态：** 已通过（D-FTP-3 步骤2-3，提交 a986ead；`TestWorkerLayerDynOverride` 全绿）
**级别：** unit
**来源：** D-FTP-3 §4
**目标：** fixed 解析值覆盖；未配动态端点保持；分片键=终值；FlowIndex 逐流。

**输入：** `ip.dst` 写 inc range ["20.0.1.1","20.0.1.2"]、`tcp.src_port` 写 fixed 51000 flows=2。
**前置条件：** 无。
**执行：** `go test ./internal/core/ -run TestWorkerLayerDynOverride -count=1`
**期望输出：** dst_ip 逐流 20.0.1.1/20.0.1.2、src_port 恒 51000；computeHashKey 输入=终值；FlowIndex 0/1。
**错误期望：** 无。
**性能期望：** 不适用。
**实现位置：** `internal/core/worker_tuples_test.go`。

### T-FTP-10 会话级动态（层形状输入，不动）【v3：FTP 字段本就在 ftp 层内，输入不变】

**状态：** 已通过（v2 实现保留）
**级别：** unit
**来源：** D-FTP-3 §1；RFC 959
**目标：** 会话 `src_port`/`banner` 写对象时按流序号解析并驱动独立四元组与横幅。

**输入：** 见 v2 条目（会话字段同键二态，住处=ftp 层，方向正确）。
**前置条件：** 无。
**执行：** `go test ./internal/protocol/ftp/ -run TestFTPSessionDynamicPortBanner -count=1`
**期望输出：** 见 v2。
**错误期望：** 无。
**性能期望：** 不适用。
**实现位置：** `internal/protocol/ftp/ftp_dyn_test.go`。

### T-FTP-11 命令 pattern 逐流（不动）

**状态：** 已通过（v2 实现保留）
**级别：** unit
**来源：** D-FTP-3 §1
**目标：** cmd pattern 逐流 + PASV 推导取已解析响应。

**输入/执行/期望：** 见 v2（`TestFTPDynCommands`）。
**实现位置：** `internal/protocol/ftp/ftp_dyn_test.go`。

### T-FTP-12 负载动态 + 优先级（不动）

**状态：** 已通过（v2 实现保留）
**级别：** unit
**来源：** D-FTP-3 §1
**目标：** payload 动态逐流；FileSource > 文本。

**输入/执行/期望：** 见 v2（`TestFTPDynPayload`）。
**实现位置：** `internal/protocol/ftp/ftp_dyn_test.go`。

### T-FTP-13 可复现性（不动）

**状态：** 已通过（v2 实现保留）
**级别：** unit
**来源：** CORE_MEMORY §12
**目标：** rand 同 seed 两次 Plan 序列一致。

**输入/执行/期望：** 见 v2（`TestFTPDynReproducible`）。
**实现位置：** `internal/protocol/ftp/ftp_dyn_test.go`。

### T-FTP-14 畸形拒绝（v2 保留 + 补层动态畸形 2 例）

**状态：** 已通过（D-FTP-3 步骤4/6a，提交 e8c807f；层畸形以 `TestValidateLayersDynShape`+`TestParseLayerDyn_InvalidEndpoints` 落地，执行命令中的 `TestValidateLayersDynInvalid` 为笔误，实际函数名 DynShape）
**级别：** unit
**来源：** D-FTP-3 §5
**目标：** FTP 畸形 + 层动态畸形均拒绝。

**输入：** v2 ①..⑤ + ⑥`ip.src` 写 `{"strategy":"inc"}`（range 缺失，走 ValidateLayers）；⑦`tcp.mss` 写对象（非动态名单→拒绝）。
**前置条件：** 无。
**执行：** `go test ./internal/protocol/ftp/ -run TestFTPDynInvalid -count=1` + `go test ./internal/core/layers/ -run TestValidateLayersDynShape -count=1`
**期望输出：** 各例精确字段路径错误；绝不静默静态。
**错误期望：** 批量逐流跳过计 flowFailures。
**性能期望：** 不适用。
**实现位置：** `internal/protocol/ftp/ftp_dyn_test.go` + `internal/core/layers/validate_layers_test.go`。

### T-FTP-15 混用拒绝 + 扁平静态复制（v3 改版）

**状态：** 已通过（D-FTP-3 步骤1/5/6a，提交 8756423+65bea31+3edcc24；`TestStrategyMixedUseRejected`/`TestLayerChainStaticCopy`/`TestLayerFlatConflict`/`TestStaticCopyRejection`/`TestFlatFourTupleObjectRejected` 全绿；策略级 tuples 逃生口随 H2 撤销一并改版为拒绝；扁平四键收对象走 ValidationErrors，worker 预检终态 error）
**级别：** unit + integration
**来源：** D-FTP-3 §5
**目标：** layers 与顶层四元组任一共存→400；纯扁平静态复制仍 400；层形状豁免扁平规则。

**输入：** ①`config:{layers:[...],"src_ip":"10.0.0.1"}` + fc flows=1；②`config:{layers:[...],"src_port":12345}` + fc flows=2；③`config:{src_port:12345}+fc flows=3`（扁平规则保留）；④纯层链 `layers:[{"tcp":{}},{"http":{}}]`（无四元组字段）flows=3 → 201；⑤纯层链 `layers:[{"ip":{"src":"10.0.0.1"}},{"tcp":{}}]`（显式标量、无对象）flows=3 → 400（层链静态复制）；⑥⑤形状任一字段改对象 → 201。
**前置条件：** REST 测试 env。
**执行：** `go test ./internal/api/rest/ -run TestLayerFlatConflict -count=1`（+ 既有 TestStaticCopyRejection 回归）
**期望输出：** ①②400（文案含迁移指引锚词 ip 层/tcp 层）；③400；④201；⑤400（锚词"层内字段写成动态对象"）；⑥201。
**错误期望：** REST/MCP 同文案（横扫覆盖）。
**性能期望：** 不适用。
**实现位置：** `internal/core/schema/semantic_test.go` + `internal/api/rest/strategy_testpoints_test.go`。

### T-FTP-16 sessions 静态复制（不动）

**状态：** 已通过（v2 实现保留）
**级别：** unit
**来源：** D-FTP-3 §1
**目标：** Count>1 全静态会话端口→任务启动 error；动态/Count=1 通过。

**输入/执行/期望：** 见 v2（`TestFTPStaticCopyRejection` ①..⑤）。
**实现位置：** `internal/protocol/ftp/ftp_dyn_test.go`。

### T-FTP-17 回归 + 横扫（v3 重算）

**状态：** 已通过（D-FTP-3 步骤6，提交 88d3b0d+65bea31；横扫 15+5=20 例同文案全绿——T-FTP-17 原文"19-2+2=19"系 v2 口径误算，实际横扫基线为 14+5=19，v3 改版后 p13 改层混用并新增 p15，合计 15+5=20；`go test ./internal/...` 全绿，tls/rtmp 散发抖动与本次无关，基线可复现）
**级别：** unit + integration
**来源：** T-FTP-1 + T-SCHEMA-6；D-FTP-3 §1
**目标：** 老形状零回归；横扫补混用+层动态畸形两例。

**输入：** 既有 ftp 全套件 + 存量集成用例 + 横扫新增：`config:{layers:[...],"src_port":12345}`（混用红）、`config:{layers:[{"ip":{"src":{"strategy":"inc"}}}]}`（层动态 range 缺失红）。
**前置条件：** 无。
**执行：** `go test ./internal/... -count=1`；touched 包 -race；横扫 `go test ./internal/mcp/ -run TestNegativeParity -count=1`
**期望输出：** 全绿；横扫 15+5=20 例同文案（T-FTP-17 原文误算，见状态行）。
**错误期望：** 存量集成用例按新规则更新。
**性能期望：** 回归耗时不超基线 +10%。
**实现位置：** 既有测试文件 + `internal/mcp/negative_parity_test.go`。

### T-FTP-18 IPv6 动态地址四格（inc/rand/list/fixed）

**状态：** 已通过（实现提交 22a7d56；141/141 绿，断言按真实 pcap 钉死）（D-FTP-4 §1/§4/§7 步骤1；单测先行，套件随后）
**级别：** unit + pcap
**来源：** D-FTP-4 §4；RFC 4291 §2.2；CORE_MEMORY §9 地址族对称
**目标：** 层 `ip.src`/`ip.dst` 写 IPv6 动态对象时逐流产出 v6 地址，语义与 IPv4 格对称。

**输入：** ①inc：`{"ip":{"src":{"strategy":"inc","range":["2001:db8::1","2001:db8::3"]}}}` flows=3；②rand：range `["2001:db8::1","2001:db8::9"]` seed=7 flows=3（两次运行逐流相等）；③list：`["2001:db8::a","2001:db8::b"]` flows=3（a,b,a 轮转）；④fixed：`value "2001:db8::99"` flows=2（须配端口动态防静态复制）。
**前置条件：** 无。
**执行：** `go test ./internal/core/ -run 'TestGenIP_IPv6|TestValidIP' -count=1`；套件 `flowb_run_protocol_suite` proto=ftp。
**期望输出：** ①`2001:db8::1/2/3`；②三次值落区间内且两次运行一致；③a,b,a；④恒 `::99`。pcap 断言 `ipv6.src` distinct（distinct 聚合字段通用，任意 tshark 字段可用，见 verify.go:46-78）。
**错误期望：** 混族 range（如 `["10.0.0.1","2001:db8::9"]`）→ 400/任务 error（文案指明同族）。
**性能期望：** 不适用（单测）/ 回归 ±10%（套件）。
**实现位置：** `internal/core/tuple_generator_test.go` + `layer_dyn_test.go` + `test/protocol_pcap/cases/ftp.json`（ftp_ipv6_dyn_src_inc/rand/list/fixed 四例）。

### T-FTP-19 EPSV 被动下载（IPv6，RFC 2428 §3）

**状态：** 已通过（实现提交 22a7d56；141/141 绿，断言按真实 pcap 钉死）（D-FTP-4 §3/§7 步骤2；单测先行，套件随后）
**级别：** unit + pcap
**来源：** RFC 2428 §3；D-FTP-4 §3 事务序列
**目标：** `EPSV`→`229 (|||port|)`→`RETR`→数据（client 首 SYN→server 通告口）→`226`，数据通道端口=229 通告值。

**输入：** layers `[ip v6, tcp, ftp]`：commands `USER/PASS/TYPE I/EPSV/RETR(150,emit)/空+226/QUIT`，`229 Entering Extended Passive Mode (|||50010|)`，data_channel passive/down。
**前置条件：** `parseEPSVPort` 单测绿。
**执行：** `go test ./internal/protocol/ftp/ -run 'TestParseEPSVPort|TestScanTxForDataPort_EPSV' -count=1`；套件 proto=ftp。
**期望输出：** 数据 SYN dst=50010；pcap 断言 `ftp.request.command=EPSV` + `ftp.response.code=229` + `tcp.dstport=50010`（数据 SYN 包）。
**错误期望：** 畸形 229（无三元组/端口溢出）→ 回退 50000（与 PASV 畸形同语义，不断言 error）。
**性能期望：** 不适用。
**实现位置：** `internal/protocol/ftp/ftp_data_test.go` + `cases/ftp.json`（ftp_epsv_passive_download）。

### T-FTP-20 EPRT 主动上传（IPv6，RFC 2428 §4）

**状态：** 已通过（实现提交 22a7d56；141/141 绿，断言按真实 pcap 钉死）（D-FTP-4 §3/§7 步骤2；单测先行，套件随后）
**级别：** unit + pcap
**来源：** RFC 2428 §4；D-FTP-4 §3 事务序列
**目标：** `EPRT |2|addr|port|`→`200`→`STOR`→数据（server 首 SYN→client 通告口）→`226`，数据通道端口=EPRT 通告值。

**输入：** layers `[ip v6, tcp, ftp]`：commands `USER/PASS/EPRT |2|2001:db8::1|50011|(200)/STOR(150,emit)/空+226/QUIT`，data_channel active/up。
**前置条件：** `parseEPRTPort` 单测绿。
**执行：** `go test ./internal/protocol/ftp/ -run 'TestParseEPRTPort|TestScanTxForDataPort_EPRT' -count=1`；套件 proto=ftp。
**期望输出：** 数据首 SYN server→client 50011（ServerFirst）；pcap 断言 `ftp.request.command=EPRT` + 数据 SYN 包端口。
**错误期望：** af=1 的 EPRT 按 C 类不做（无用例，文档注明）；缺段 EPRT → 回退 20/client+1（与 PORT 畸形同语义）。
**性能期望：** 不适用。
**实现位置：** `internal/protocol/ftp/ftp_data_test.go` + `cases/ftp.json`（ftp_eprt_active_upload）。

### T-FTP-21 扩展模式失败分支 + IPv6 结构对称（RFC 2428 §5）

**状态：** 已通过（实现提交 22a7d56；141/141 绿，断言按真实 pcap 钉死）（D-FTP-4 §3/§5/§7 步骤3；套件）
**级别：** pcap
**来源：** RFC 2428 §5；CORE_MEMORY §9 地址族对称（双会话/多流格）
**目标：** ①EPSV→500 无数据通道（控制面失败，回退语义不断言重协商，只断 500+无数据）；②EPRT→522 同理；③IPv6 双会话（被动下载+主动上传各一会话，对标 ftp_sessions_mixed_mode）；④IPv6 多流（flows=2，每流一会话挂数据通道，对标 ftp_multiflow_multisession）。

**输入：** ①commands `EPSV/500 Command not understood` + QUIT；②commands `EPRT |2|...|50011|/522 Network protocol not supported` + QUIT；③sessions 双会话 v6（端口拉开间隔，§9 陷阱①）；④flows=2 + 会话端口动态对象（静态标量会触发静态复制拒绝，§9 陷阱③）。
**前置条件：** T-FTP-19/20 绿。
**执行：** 套件 proto=ftp 全量。
**期望输出：** ①②包序列=握手+命令对+挥手（无数据 SYN，包数按真实 pcap 钉）；③④多会话/多流端口隔离（distinct 钉，派生口排除，§9 陷阱②）。
**错误期望：** ①②不是任务 error（500/522 是合法控制面响应，有包序列断言）。
**性能期望：** 回归 ±10%。
**实现位置：** `cases/ftp.json`（ftp_epsv_500_fallback/ftp_eprt_522_reject/ftp_ipv6_sessions_mixed/ftp_ipv6_multiflow 四例）。

### T-HTTP-1 http 层校验器（握手 pin + MSS 门）【D-HTTP-1 §5】

**状态：** 草案
**级别：** unit
**来源：** `docs/CODE_DESIGN.md` D-HTTP-1 §5（mqtt `mqtt/layer_gen.go:236` 范式）；RFC 879（MSS 下界 536）
**目标：** 零值 TCP 配置的 http 链不断握手（pin 生效），非法 MSS 在 Plan 期同步失败。

**输入：** ①`[ip,tcp,http]` 链 + spec.TCP 零值（Handshake/Termination=false）；②`tcp.mss`=100 链。
**前置条件：** 无。
**执行：** ①`go test ./internal/protocol/http/ -run TestHTTPValidator -count=1`（P4 新增，先红后绿）；②同命令覆盖 MSS 分支。
**期望输出：** ①validator 把 spec.TCP.Handshake/Termination 写成 true，链产物含完整 3 次握手 + 4 次挥手；②返回 `MSS 100 too small` 类锚词（chain `chain_planner.go:845` 上界 65535 同理不断言字面、只断失败）。
**错误期望：** ②Plan 期同步返回错误，不进 drive（不断言任务终态，只断 validator/Plan 返回）。
**性能期望：** 不适用。
**实现位置：** `internal/protocol/http/layer_gen_test.go`（新增）。

### T-HTTP-2 FLV 变换器 version 裸值归一【D-HTTP-1 §4】

**状态：** 草案
**级别：** unit
**来源：** D-HTTP-1 §4（HLS `hls_transformer.go:40`/HDS `hds_transformer.go:25` 已有 prefix，FLV `layer_gen.go:163-166` 缺）；RFC 9112 §2.1（版本字面 `HTTP/1.1`）
**目标：** http 层 version 写裸 `1.1` 时，FLV 链请求行仍是完整 `HTTP/1.1`。

**输入：** `[http,http_flv]` 链 + http 层 config `{"method":"GET","uri":"/live/test.flv","version":"1.1"}`（裸值；对照组写 `HTTP/1.1`）。
**前置条件：** 无。
**执行：** `go test ./internal/protocol/http/ -run TestHTTPFLVVersionPrefix -count=1`（P4 新增，先红后绿）。
**期望输出：** 两组请求行首行均为 `GET /live/test.flv HTTP/1.1`（字节相等；tshark `http.request.version` 同理可断）。
**错误期望：** 无（回归项；现存 15 例全写完整版，改前改后字节零变化）。
**性能期望：** 不适用。
**实现位置：** `internal/protocol/http/layer_gen_test.go`（新增）。

### T-HTTP-3 载体检查 5 家补齐（gbt/getwork/hls/hds/http_flv）【D-HTTP-1 §5】

**状态：** 草案
**级别：** unit
**来源：** D-HTTP-1 §5（cwmp `:68`/doh `:74`/onvif `:80` 已有同款文案；dns `:106` 同款教训：drive 期报错变空流）；现网：doh/onvif 各有 1 个缺 http 负例
**目标：** 5 家错链（无 http 层）在 Validate 期同步拒绝，锚词与 3 家同族。

**输入：** `[ip,tcp,gbt]`、`[ip,tcp,getwork]`、`[tcp,hls]`、`[tcp,hds]`、`[ip,tcp,http_flv]`（载体检查跑在 CompleteChain 自动补全之前——以实现为准，5 链各 1 例）。
**前置条件：** 无。
**执行：** `go test ./internal/core/layers/ -run TestValidateCarrierHTTP -count=1`（P4 新增，先红后绿；位置 `validate_layers_test.go`）。
**期望输出：** 5 链全部失败，错误含 `requires the http carrier layer`（字面钉死，与 D-HTTP-1 §5 一致）。
**错误期望：** 即本条（Plan/Validate 期同步失败；对照组 `[ip,tcp,http,X]` 放行不断言包数）。
**性能期望：** 不适用。
**实现位置：** `internal/core/layers/validate_layers_test.go`（新增）。

### T-HTTP-4 ThinkTime 删键回归【D-HTTP-1 §7 E（用户裁定删）】

**状态：** 草案
**级别：** unit
**来源：** D-HTTP-1 §7 E；`types.go:2150` + `strategy_convert.go:396`
**目标：** 删字段 + 删解析后，http 全字段解析行为不变（少 ThinkTime 一行），旧配置带该键被忽略。

**输入：** `TestMapToFlowSpec_HTTPFullSubmap` 去掉 `"think_time":200` 输入行 + `ThinkTime` 断言 2 行；另加 1 行：带 `think_time` 键的旧 config 解析不报错且其余字段正确（config 节无 additionalProperties 约束佐证）。
**前置条件：** 无。
**执行：** `go test ./internal/core/ -run TestMapToFlowSpec_HTTPFullSubmap -count=1`；MCP 描述 `go test ./internal/mcp/ -run TestConfigTagsMatchSchemaBlurb -count=1`。
**期望输出：** 两命令绿；`schemaConfigBlurb` 不再含 `think_time,`（schemagen 重生成后 `TestConfigTagsMatchSchemaBlurb` 绿；`tools_schema_test.go` 未锁该字样）。
**错误期望：** 无（删键项；dnp3/mcp 自家 ThinkTime 不动，不断言它们）。
**性能期望：** 不适用。
**实现位置：** `internal/core/maptoflow_test.go`（改）；`internal/mcp/schemagen/main.go:92` + 重生成 `schema_descriptions_generated.go` + `tools_strategy.go:27`/`tools_workflow.go:20`（改）。

### T-HTTP-5 8 子女 suite 联验（http 自身无 cases）【D-HTTP-1 §8】

**状态：** 草案
**级别：** pcap
**来源：** D-HTTP-1 §8；RFC 9110/9112（请求行/状态行/头/体）；存量 554 例（cwmp150/doh110/onvif95/gbt81/getwork62/hls24/hds17/http_flv15）
**目标：** P4 改完后 8 子女文件全量全绿（增量绿不算），http 改动字节零漂移。

**输入：** 8 子女 cases 改写后形状（P5 按通用改写规则：删顶层四元组→地址进 ip 层、端口进 tcp 层、仅原 count>1 补 strategy_fc；hls/hds 缺 ip、http_flv 缺 ip/tcp 由 CompleteChain 补；doh/onvif 缺 http 负例锚词重钉载体文案）。
**前置条件：** T-HTTP-1…4 绿；服务器二进制与 HEAD 同代。
**执行：** 套件 CASE_PROTO=gbt/getwork/cwmp/doh/onvif/hls/hds/http_flv 逐个全量（`flowb_run_protocol_suite` 真实流程：MCP 建任务→引擎生成→tshark 校对），pcap 落 `/tmp/mcp-pcaps/<proto>/`。
**期望输出：** 8 文件全绿；断言钉请求行/状态行/头/体（tshark `http.request.method/uri/version`、`http.response.code`），包号/端口从落盘 pcap 拿、不手算；负例 116 例锚词逐例重钉（扁平判死先于业务锚，Step1 门）。
**错误期望：** 缺 http 载体 2 例（doh/onvif）+ P4 新增语义延续：错误含载体锚词，任务终态失败（§14 负例走真实流程）。
**性能期望：** 回归 ±10%（首次跑记录 554 例 suite 基线耗时并回填 D-HTTP-1 §6）。
**实现位置：** `cases/{gbt,getwork,cwmp,doh,onvif,hls,hds,http_flv}.json`。

### T-HTTP-6 存量单测 + 链测试回归【D-HTTP-1 §8】

**状态：** 草案
**级别：** unit + race
**来源：** D-HTTP-1 §8；存量 `protocol/http` 170 单测 + `chain_planner_http_test.go` 8 测试（9 包链、seq 推进、无独立 ACK、pipelined、TCPSeg 忽略、取消收敛）
**目标：** P4 四改（validator+prefix+载体+删键）后存量行为零回归。

**输入：** 存量测试不变（`http_test.go:4` + `layer_gen_test.go:3` + `http_filesource_test.go:6` + `http_chunked_test.go:31` + `http_testpoints_test.go:126`）。
**前置条件：** T-HTTP-1…4 绿。
**执行：** `go test ./internal/protocol/http/ -count=1` + `go test ./internal/core/layers/ -run TestChainPlanner_HTTP -count=1` + touched 包 `-race`（http、layers、core、mcp）+ `go vet`。
**期望输出：** 全绿；165→170 计数口径（`grep -c "^func Test"` 五文件求和）回填本条状态行。
**错误期望：** 无（回归项）。
**性能期望：** 不适用。
**实现位置：** `internal/protocol/http/*_test.go`（既有）+ `internal/core/layers/chain_planner_http_test.go`（既有）。

## 7. 用例审查与完成条件

测试用例完成前必须进行两条审查：

- **覆盖审查：** 从规范、代码设计和现网场景反向枚举遗漏，确认数据、业务、流、错误和性能覆盖；
- **可观察性审查：** 确认输入真的走到目标函数/分支，断言真的能区分正确和错误，性能指标真的被测量。

完成条件：

- 三份文档中的编号、配置形状、错误锚词和性能阈值一致；
- 可执行测试与本文档条目一一回指；
- 正常和失败路径均通过；
- 功能测试、集成测试、pcap/NIC 验证、性能测试和 `-race` 按设计要求完成；
- 测试 review 完成并记录“自审轮次、发现问题、修复结果”。

任何只写了功能、没有性能验收的测试集都不算完整。
