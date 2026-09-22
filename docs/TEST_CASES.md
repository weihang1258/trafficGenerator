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
**P5 校准注记（已验收实际形状）：** ①T-6 锚词=V9 先拦 `not a numeric value`（registry calls Min=0，legacy ">=0" 不可达）；②T-11 显式 crv=0x1000+display_name='t-h323-11'（9.21 显式格），CRV 0x1000→0x1001 逐呼叫递增 frame pin 实测（包4/包20 offset 54）；③T-15 tshark Q.931 方向性伪影：down 侧发起的消息不出 message_type 字段，方向翻转由 ip.src 翻转+frame.len 83/78 对称承担；④T-16 frame.len 83/83 与 smoke 全等=长度保持重写实证，字节级=C 类；⑤ras_only 的 legacy 合成 stub（8×60B）触发 tshark H.225.0 malformed=字节证据白名单条目 h323_scenario_ras（pcaptest verify.go，先例 doip_userdata_empty）。
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

**状态：** 已通过（P4 提交 64cc9d7：`TestHTTPValidator_PinHandshakeTermination`+`TestHTTPValidator_RejectsBadMSS` 先红后绿 + `http_neg_bad_mss` 真实流程锚词 `mss`；本次复核仍绿）
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

**状态：** 已通过（P4 提交 64cc9d7：`TestHTTPFLVVersionPrefix` 先红后绿 + `http_layer_version_bare` 真实流程归一；本次复核仍绿）
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

**状态：** 已通过（P4 提交 64cc9d7：`TestHTTPCarrierRequired_FiveFamilies` 先红后绿；`chain_planner_http_carrier_test.go` 新文件包 layers_test；本次复核仍绿）
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

**状态：** 已通过（P4 提交 64cc9d7：`TestMapToFlowSpec_HTTPFullSubmap` 去 think_time 输入+断言 + 旧键忽略行 + `TestConfigTagsMatchSchemaBlurb` 绿 + 前端 4 处词条删除 + `vite build` 本次验证绿；本次复核仍绿）
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

### T-HTTP-5 8 子女 + http.json 全量联验【D-HTTP-1 §8】

**状态：** 已通过（P5 实测 621/621 全绿：8 子女 554 + http.json 67；8 子女回归逐个重跑零漂移（本次只加 http 链内形状与用例，子女未动；回归在提交前重跑）；主库 http 策略/任务行 0/0，前已清零本次复核仍零；suite 文档噪音 `SUMMARY.md` 已恢复、`http.md` 未入库；落盘 `/tmp/mcp-pcaps-rework/http/` 60 正例 pcap 可查，7 负例 0 包是设计）
**级别：** pcap
**来源：** D-HTTP-1 §8；RFC 9110/9112（请求行/状态行/头/体）；9 文件 621 例（cwmp150/doh110/onvif95/gbt81/getwork62/hls24/hds17/http_flv15/http67）
**目标：** P4 改完后 9 文件全量全绿（增量绿不算），http 改动字节零漂移。

**输入：** 8 子女 cases 改写后形状（P5 按通用改写规则：删顶层四元组→地址进 ip 层、端口进 tcp 层、仅原 count>1 补 strategy_fc；hls/hds 缺 ip、http_flv 缺 ip/tcp 由 CompleteChain 补；doh/onvif 缺 http 负例锚词重钉载体文案）；http.json 67 例（T-HTTP-7…42：20 字段全覆盖 + 方法/状态/组合/分支/多流/TTL；T-HTTP-43…52：兼容键/file 余形态/正交对称/专属负例；T-HTTP-53…59：四元组动态整格 rand/list/fixed/回绕/复现/地址维/pattern 负例；T-HTTP-60…69：业务动态 6 开正例 uri list/pattern/fixed、body list、respbody list、status list/inc/rand、body_b64、respbody_b64；T-HTTP-70…72：业务负例 string 面 inc、关字段 method、顶层 http presence；T-HTTP-36 identity 单测覆盖、pcap 例删除；严格层链形）。
**前置条件：** T-HTTP-1…4 绿；服务器二进制与 HEAD 同代（实测：二进制 `/tmp/tg-http-rework-server` 与 HEAD 同代，`find -newer` 空）。
**执行：** 套件 CASE_PROTO=gbt/getwork/cwmp/doh/onvif/hls/hds/http_flv/http 逐个全量（`flowb_run_protocol_suite` 真实流程：MCP 建任务→引擎生成→tshark 校对），pcap 落 `/tmp/mcp-pcaps-rework/http/`（落盘路径由 suite 按 `PCAP_ROOT/<proto>/<case>.pcap` 定，用例不写路径）。
**期望输出：** 9 文件全绿（621/621；P5 实测 http 67/67 全绿）；断言钉请求行/状态行/头/体（tshark `http.request.method/uri/version`、`http.response.code`），包号/端口从落盘 pcap 拿、不手算；负例锚词逐例重钉（扁平判死先于业务锚，Step1 门；http 链专属 8 负例见 T-HTTP-1（MSS 门）、T-HTTP-50…52、T-HTTP-59（层地址 pattern 不支持）、T-HTTP-70（string 面 inc 不支持）、T-HTTP-71（关字段 method 不支持动态）、T-HTTP-72（顶层 http presence 判死））。
**错误期望：** 缺 http 载体 2 例（doh/onvif）+ P4 新增语义延续：错误含载体锚词，任务终态失败（§14 负例走真实流程）。
**性能期望：** 回归 ±10%（P5 实测 wall：http 67 例 16.6s，CASE_PROTO 逐文件串行、服务端内 parallel=4；已回填 D-HTTP-1 §6）。
**实现位置：** `cases/{gbt,getwork,cwmp,doh,onvif,hls,hds,http_flv,http}.json`。

### T-HTTP-6 存量单测 + 链测试回归【D-HTTP-1 §8】

**状态：** 已通过（P5 实测：http 包 173 单测绿 + `TestChainPlanner_HTTP` 绿 + `go vet` 净 + http/layers `-race` 绿 + core 关键测试 `-race` 绿 + 前端 `vite build` 12s 绿；8 子女回归逐个重跑零漂移）
**级别：** unit + race
**来源：** D-HTTP-1 §8；存量 `protocol/http` 173 单测 + `chain_planner_http_test.go` 8 测试（9 包链、seq 推进、无独立 ACK、pipelined、TCPSeg 忽略、取消收敛）
**目标：** P4 四改（validator+prefix+载体+删键）后存量行为零回归。

**输入：** 存量测试不变（`http_test.go:4` + `layer_gen_test.go:6` + `http_filesource_test.go:6` + `http_chunked_test.go:31` + `http_testpoints_test.go:126`）。
**前置条件：** T-HTTP-1…4 绿。
**执行：** `go test ./internal/protocol/http/ -count=1` + `go test ./internal/core/layers/ -run TestChainPlanner_HTTP -count=1` + touched 包 `-race`（http、layers、core 关键测试）+ `go vet` + 前端 `vite build`。
**期望输出：** 全绿；173 计数口径（`grep -c "^func Test"` 五文件求和：4+6+6+31+126）。
**错误期望：** 无（回归项）。
**性能期望：** 不适用。
**实现位置：** `internal/protocol/http/*_test.go`（既有）+ `internal/core/layers/chain_planner_http_test.go`（既有）。

### T-HTTP-7 http.json 独立用例——GET 基线【D-HTTP-1 §8；D-REWORK-1 整改：http_ttl_custom 顶层 ttl 影子迁除，ip.ttl 回填】

**状态：** 已通过（P5 实测 67/67 全绿；二进制与 HEAD 同代）
**级别：** pcap
**来源：** D-HTTP-1 §1（终结模式 builders：Host 仅 1.1 自动加）；RFC 9112 §2.1（请求行）、RFC 7230 §5.4（Host）
**目标：** 单事务 GET 的包序列与字节正确（9 包 = 3 握手 + 请求 + 响应分片 + 4 挥手）。

**输入：** `[ip,tcp,http]` + 顶层 `http{method GET,uri /,version HTTP/1.1}`（src_port 40010，dst 80）。
**前置条件：** 服务器二进制与 HEAD 同代。
**执行：** `CASE_PROTO=http go test -run TestProtocolPcapDrive ./test/protocol_pcap/ -v`（真实流程：MCP 建任务→引擎生成→tshark 校对）。
**期望输出：** 9 包；包 4 `http.request.method=GET`、`uri=/`、`version=HTTP/1.1`、`host=198.51.100.20`；包 8 `http.response.code=200`；`has_handshake/terminates/directional` 全真。
**错误期望：** 无。
**性能期望：** 回归 ±10%。
**实现位置：** `cases/http.json`（http_get_baseline）。

### T-HTTP-8 http.json 独立用例——POST 带体【D-HTTP-1 §1】

**状态：** 已通过（P5 实测 67/67 全绿；二进制与 HEAD 同代）
**级别：** pcap
**来源：** D-HTTP-1 §1（Content-Length 自动、Content-Type 嗅探 magic 优先）；RFC 9110 §8.6（Content-Length）
**目标：** POST 体 `{"k":"v"}`（9 字节）的长度与类型断言正确。

**输入：** 同 T-HTTP-7 链形（src_port 40011）+ `http{method POST,uri /api,body {"k":"v"}}`。
**前置条件：** T-HTTP-7 绿。
**执行：** 同 T-HTTP-7（CASE_PROTO=http 全量）。
**期望输出：** 9 包；包 4 `content_length=9`、`content_type=application/json; charset=utf-8`；包 8 `response.code=200`。
**错误期望：** 无。
**性能期望：** 不适用。
**实现位置：** `cases/http.json`（http_post_body）。

### T-HTTP-9 http.json 独立用例——keep-alive 3 事务【D-HTTP-1 §3】

**状态：** 已通过（P5 实测 67/67 全绿；二进制与 HEAD 同代）
**级别：** pcap
**来源：** D-HTTP-1 §3（终结模式交错循环；Connection 缺省 keep-alive 当且仅当 Transactions>1 或 KeepAlive）；RFC 9112 §6.3（持久连接）
**目标：** 同连接 3 对请求/响应不断链（13 包），Connection 头为 keep-alive。

**输入：** 同链形（src_port 40012）+ `http{transactions 3,keep_alive true}`。
**前置条件：** T-HTTP-7 绿。
**执行：** 同 T-HTTP-7。
**期望输出：** 13 包；包 4 `connection=keep-alive`。
**错误期望：** 无。
**性能期望：** 不适用。
**实现位置：** `cases/http.json`（http_keepalive_multi_transactions）。

### T-HTTP-10 http.json 独立用例——pipelined【D-HTTP-1 §3】

**状态：** 已通过（P5 实测 67/67 全绿；二进制与 HEAD 同代）
**级别：** pcap
**来源：** D-HTTP-1 §3（pipelined 分支：全请求后全响应）；RFC 9112 §6.3.2
**目标：** 3 请求先行后 3 响应同为 13 包，首包仍是 GET。

**输入：** 同链形（src_port 40013）+ `http{transactions 3,pipelined true}`。
**前置条件：** T-HTTP-9 绿（对照：同事务数不同排序）。
**执行：** 同 T-HTTP-7。
**期望输出：** 13 包；包 4 `http.request.method=GET`。
**错误期望：** 无。
**性能期望：** 不适用。
**实现位置：** `cases/http.json`（http_pipelined）。

### T-HTTP-11 http.json 独立用例——响应 404【D-HTTP-1 §1】

**状态：** 已通过（P5 实测 67/67 全绿；二进制与 HEAD 同代）
**级别：** pcap
**来源：** D-HTTP-1 §1（状态表 + `Status %d` 兜底；ResponseStatusCode 0→200）
**目标：** 自定义状态码 404 上线（响应有体时包 5 即完整、不重组）。

**输入：** 同链形（src_port 40014）+ `http{response_status_code 404,response_body "not here"}`。
**前置条件：** T-HTTP-7 绿。
**执行：** 同 T-HTTP-7。
**期望输出：** 9 包；包 5 `http.response.code=404`。
**错误期望：** 无。
**性能期望：** 不适用。
**实现位置：** `cases/http.json`（http_response_status_404）。

### T-HTTP-12 http.json 独立用例——响应 gzip【D-HTTP-1 §1】

**状态：** 已通过（P5 实测 67/67 全绿；二进制与 HEAD 同代）
**级别：** pcap
**来源：** D-HTTP-1 §1（gzip→chunked 先后顺序；Content-Length 计压缩后）；RFC 1952
**目标：** 响应体 gzip 压缩后 Content-Encoding 为 gzip。

**输入：** 同链形（src_port 40015）+ `http{response_body hello-gzip-body,response_content_encoding gzip}`。
**前置条件：** T-HTTP-7 绿。
**执行：** 同 T-HTTP-7。
**期望输出：** 9 包；包 5 `response.code=200`、`content_encoding=gzip`。
**错误期望：** 无。
**性能期望：** 不适用。
**实现位置：** `cases/http.json`（http_gzip_response）。

### T-HTTP-13 http.json 独立用例——响应 chunked【D-HTTP-1 §1】

**状态：** 已通过（P5 实测 67/67 全绿；二进制与 HEAD 同代）
**级别：** pcap
**来源：** D-HTTP-1 §1（chunked 时压制 Content-Length；chunk-size 十六进制）；RFC 7230 §4.1/§3.3.3
**目标：** 响应 Transfer-Encoding 为 chunked。

**输入：** 同链形（src_port 40016）+ `http{response_body chunked-body-bytes,response_transfer_encoding chunked}`。
**前置条件：** T-HTTP-7 绿。
**执行：** 同 T-HTTP-7。
**期望输出：** 9 包；包 5 `response.code=200`、`transfer_encoding=chunked`。
**错误期望：** 无。
**性能期望：** 不适用。
**实现位置：** `cases/http.json`（http_chunked_response）。

### T-HTTP-14 http.json 独立用例——HTTP/1.0 不自动 Host【D-HTTP-1 §1】

**状态：** 已通过（P5 实测 67/67 全绿；二进制与 HEAD 同代）
**级别：** pcap
**来源：** D-HTTP-1 §1（`isHTTP11` 门控 Host；用户 Host 任何版本都赢）；RFC 7230 §5.4（Host 为 1.1 强制）
**目标：** 1.0 请求行版本正确（Host 不自动加，不断言缺席、只断版本）。

**输入：** 同链形（src_port 40017）+ `http{version HTTP/1.0}`。
**前置条件：** T-HTTP-7 绿。
**执行：** 同 T-HTTP-7。
**期望输出：** 9 包；包 4 `http.request.version=HTTP/1.0`。
**错误期望：** 无。
**性能期望：** 不适用。
**实现位置：** `cases/http.json`（http_version_10_no_auto_host）。

### T-HTTP-15 http.json 独立用例——IPv6 Host 括号【D-HTTP-1 §1】

**状态：** 已通过（P5 实测 67/67 全绿；二进制与 HEAD 同代）
**级别：** pcap
**来源：** D-HTTP-1 §1（`bracketHost`：v6 加括号，v4/非 IP 原样）；RFC 7230 §5.4（IP-literal 括号）
**目标：** v6 目的地址的 Host 头带括号。

**输入：** `[ip(2001:db8::10→2001:db8::20),tcp,http]`（src_port 40019）+ `http{uri /v6}`。
**前置条件：** T-HTTP-7 绿。
**执行：** 同 T-HTTP-7。
**期望输出：** 9 包；包 4 `host=[2001:db8::20]`。
**错误期望：** 无。
**性能期望：** 不适用。
**实现位置：** `cases/http.json`（http_ipv6）。

### T-HTTP-16 http.json 独立用例——非默认端口【D-HTTP-1 §4】

**状态：** 已通过（P5 实测 67/67 全绿；二进制与 HEAD 同代）
**级别：** pcap
**来源：** D-HTTP-1 §4（用户显式 tcp.dst_port > FieldContract 80 > 报错）
**目标：** 显式 8080 优先于契约 80。

**输入：** 同链形（src_port 40020，tcp.dst_port 8080）+ `http{uri /alt}`。
**前置条件：** T-HTTP-7 绿。
**执行：** 同 T-HTTP-7。
**期望输出：** 9 包；包 4 `tcp.dstport=8080`。
**错误期望：** 无。
**性能期望：** 不适用。
**实现位置：** `cases/http.json`（http_nondefault_port）。

### T-HTTP-17 http.json 独立用例——自定义请求头与 Host 覆盖【D-HTTP-1 §1】

**状态：** 已通过（P5 实测 67/67 全绿；二进制与 HEAD 同代）
**级别：** pcap
**来源：** D-HTTP-1 §1（用户 RequestHeaders 任何版本都赢 + Host 自动对 1.1）
**目标：** 用户 Host `custom.test` 覆盖自动值 + 自定义头 `X-Trace: abc` 上线。

**输入：** 同链形（src_port 40022）+ `http{method GET,uri /hdr,request_headers {X-Trace abc,Host custom.test}}`。
**前置条件：** T-HTTP-7 绿。
**执行：** 同 T-HTTP-7。
**期望输出：** 9 包；包 4 `method=GET`、`host=custom.test`。
**错误期望：** 无。
**性能期望：** 不适用。
**实现位置：** `cases/http.json`（http_req_headers_custom）。

### T-HTTP-18 http.json 独立用例——请求 body_b64 优先【D-HTTP-1 §1】

**状态：** 已通过（P5 实测 67/67 全绿；二进制与 HEAD 同代）
**级别：** pcap
**来源：** D-HTTP-1 §1（resolveRequestBody：BodyB64 优先，非法回退 Body，见 T-HTTP-38 对照）
**目标：** `body_b64 aGVsbG8=` 解出 5 字节 `hello`（Content-Length=5），忽略文本 body。

**输入：** 同链形（src_port 40023）+ `http{method POST,uri /bin,body text-ignored,body_b64 aGVsbG8=}`。
**前置条件：** T-HTTP-7 绿。
**执行：** 同 T-HTTP-7。
**期望输出：** 9 包；包 4 `method=POST`、`content_length=5`。
**错误期望：** 无（回退语义不断 error，非法输入见 T-HTTP-38）。
**性能期望：** 不适用。
**实现位置：** `cases/http.json`（http_req_body_b64）。

### T-HTTP-19 http.json 独立用例——请求 gzip 编码【D-HTTP-1 §1】

**状态：** 已通过（P5 实测 67/67 全绿；二进制与 HEAD 同代）
**级别：** pcap
**来源：** D-HTTP-1 §1（请求侧 content_encoding=gzip 即压缩；响应侧对称见 T-HTTP-12）；RFC 1952
**目标：** 请求体压缩后 Content-Encoding 为 gzip。

**输入：** 同链形（src_port 40024）+ `http{method POST,uri /gz-req,body hello-gzip-request-body,request_content_encoding gzip}`。
**前置条件：** T-HTTP-7 绿。
**执行：** 同 T-HTTP-7。
**期望输出：** 9 包；包 4 `method=POST`、`content_encoding=gzip`。
**错误期望：** 无。
**性能期望：** 不适用。
**实现位置：** `cases/http.json`（http_req_gzip）。

### T-HTTP-20 http.json 独立用例——请求 chunked【D-HTTP-1 §1】

**状态：** 已通过（P5 实测 67/67 全绿；二进制与 HEAD 同代）
**级别：** pcap
**来源：** D-HTTP-1 §1（请求侧 transfer_encoding=chunked 即分块；响应侧对称见 T-HTTP-13）；RFC 7230 §4.1
**目标：** 请求 Transfer-Encoding 为 chunked。

**输入：** 同链形（src_port 40025）+ `http{method POST,uri /chunk-req,body chunked-request-body,request_transfer_encoding chunked}`。
**前置条件：** T-HTTP-7 绿。
**执行：** 同 T-HTTP-7。
**期望输出：** 9 包；包 4 `method=POST`、`transfer_encoding=chunked`。
**错误期望：** 无。
**性能期望：** 不适用。
**实现位置：** `cases/http.json`（http_req_chunked）。

### T-HTTP-21 http.json 独立用例——请求 chunk_size 多分块【D-HTTP-1 §1】

**状态：** 已通过（P5 实测 67/67 全绿；二进制与 HEAD 同代）
**级别：** pcap
**来源：** D-HTTP-1 §1（chunk_size>0 按该字节数切块；响应侧单测已 cover，pcap 钉请求侧字节）
**目标：** 16 字节体按 5 字节切 4 块（5/5/5/1），请求行字节用 frames 十六进制钉死（tshark 不解析分块数）。

**输入：** 同链形（src_port 40026）+ `http{method POST,uri /chunks,body 0123456789ABCDEF,request_transfer_encoding chunked,chunk_size 5}`。
**前置条件：** T-HTTP-7 绿。
**执行：** 同 T-HTTP-7。
**期望输出：** 9 包；包 4 `method=POST`、`transfer_encoding=chunked` + frames 包 4 偏移 54 十六进制=`POST /chunks HTTP/1.1 CRLF`。
**错误期望：** 无。
**性能期望：** 不适用。
**实现位置：** `cases/http.json`（http_req_chunk_size_multi）。

### T-HTTP-22 http.json 独立用例——响应头覆盖【D-HTTP-1 §1】

**状态：** 已通过（P5 实测 67/67 全绿；二进制与 HEAD 同代）
**级别：** pcap
**来源：** D-HTTP-1 §1（ResponseHeaders 覆盖默认 Content-Type；请求侧对称见 T-HTTP-17）
**目标：** 响应 Content-Type 被用户值 `text/custom` 覆盖。

**输入：** 同链形（src_port 40027）+ `http{method GET,uri /override,response_body hello,response_headers {Content-Type text/custom}}`。
**前置条件：** T-HTTP-7 绿。
**执行：** 同 T-HTTP-7。
**期望输出：** 9 包；包 5 `response.code=200`、`content_type=text/custom`。
**错误期望：** 无。
**性能期望：** 不适用。
**实现位置：** `cases/http.json`（http_resp_headers_override）。

### T-HTTP-23 http.json 独立用例——响应 body_b64 优先【D-HTTP-1 §1】

**状态：** 已通过（P5 实测 67/67 全绿；二进制与 HEAD 同代）
**级别：** pcap
**来源：** D-HTTP-1 §1（resolveResponseBody：ResponseBodyB64 优先；请求侧对称见 T-HTTP-18）
**目标：** 响应体 5 字节 `hello` 正常发出（状态 200），忽略文本 response_body。

**输入：** 同链形（src_port 40028）+ `http{method GET,uri /b64resp,response_body ignored,response_body_b64 aGVsbG8=}`。
**前置条件：** T-HTTP-7 绿。
**执行：** 同 T-HTTP-7。
**期望输出：** 9 包；包 5 `response.code=200`（响应体字节只 5 个，不断 content_length，tshark 重组口径见 T-HTTP-5）。
**错误期望：** 无。
**性能期望：** 不适用。
**实现位置：** `cases/http.json`（http_resp_body_b64）。

### T-HTTP-24 http.json 独立用例——响应自定义状态文本【D-HTTP-1 §1】

**状态：** 已通过（P5 实测 67/67 全绿；二进制与 HEAD 同代）
**级别：** pcap
**来源：** D-HTTP-1 §1（ResponseStatusText 非空则覆盖状态表文本；418 非标准码走自定义文本分支）
**目标：** 418 状态码 + 自定义 reason `Custom Phrase` 上线。

**输入：** 同链形（src_port 40029）+ `http{method GET,uri /teapot,response_status_code 418,response_status_text "Custom Phrase",response_body x}`。
**前置条件：** T-HTTP-7 绿。
**执行：** 同 T-HTTP-7。
**期望输出：** 9 包；包 5 `response.code=418`（reason 文本 tshark 不单独断，码对即文本分支走过）。
**错误期望：** 无。
**性能期望：** 不适用。
**实现位置：** `cases/http.json`（http_resp_status_text_override）。

### T-HTTP-25 http.json 独立用例——未知状态码兜底【D-HTTP-1 §1】

**状态：** 已通过（P5 实测 67/67 全绿；二进制与 HEAD 同代）
**级别：** pcap
**来源：** D-HTTP-1 §1（状态表未命中→`Status %d` 兜底；T-HTTP-24 是自定义文本版，本例是无文本兜底版）
**目标：** 599 无表码按 `Status 599` 兜底发出（不断 reason，只断码）。

**输入：** 同链形（src_port 40030）+ `http{method GET,uri /unknown,response_status_code 599,response_body x}`。
**前置条件：** T-HTTP-7 绿。
**执行：** 同 T-HTTP-7。
**期望输出：** 9 包；包 5 `response.code=599`。
**错误期望：** 无。
**性能期望：** 不适用。
**实现位置：** `cases/http.json`（http_resp_unknown_status）。

### T-HTTP-26 http.json 独立用例——响应空体无 Content-Type【D-HTTP-1 §1】

**状态：** 已通过（P5 实测 67/67 全绿；二进制与 HEAD 同代）
**级别：** pcap
**来源：** D-HTTP-1 §1（空响应体不压 Content-Type……不断 type、只断码与包位置）
**目标：** 无 response_body 时响应仍 200，且落在包 8（无体包位，对照有体包 5）。

**输入：** 同链形（src_port 40031）+ `http{method GET,uri /empty}`（无任何响应字段）。
**前置条件：** T-HTTP-7 绿。
**执行：** 同 T-HTTP-7。
**期望输出：** 9 包；包 8 `response.code=200`（不是包 5；包位本身就是断言——校准结论：响应无体时包 8、有体时包 5）。
**错误期望：** 无。
**性能期望：** 不适用。
**实现位置：** `cases/http.json`（http_resp_empty_no_content_type）。

### T-HTTP-27 http.json 独立用例——file_source 文件体【D-HTTP-1 §1】

**状态：** 已通过（P5 实测 67/67 全绿；二进制与 HEAD 同代）
**级别：** pcap
**来源：** D-HTTP-1 §1（file_source literal 经 PayloadCache 取体；请求体解析优先级最低一档）
**目标：** 14 字节 `file-bytes-123` 经 literal 源发出（Content-Length=14）。

**输入：** 同链形（src_port 40032）+ `http{method POST,uri /upload,file_source {source_type literal,literal file-bytes-123}}`。
**前置条件：** T-HTTP-7 绿。
**执行：** 同 T-HTTP-7。
**期望输出：** 9 包；包 4 `method=POST`、`content_length=14`。
**错误期望：** 无。
**性能期望：** 不适用。
**实现位置：** `cases/http.json`（http_file_source_literal）。

### T-HTTP-28 http.json 独立用例——响应 MSS 分段【D-HTTP-1 §3】

**状态：** 已通过（P5 实测 67/67 全绿；二进制与 HEAD 同代）
**级别：** pcap
**来源：** D-HTTP-1 §3（MSS 分段归 tcp 层；请求侧对称见 T-HTTP-39）；RFC 879
**目标：** MSS 536 下 600 字节响应体被切成多段（10 包），首请求仍 GET。

**输入：** 同链形（src_port 40033，tcp.mss 536）+ `http{method GET,uri /long,response_body A×600}`。
**前置条件：** T-HTTP-7 绿。
**执行：** 同 T-HTTP-7。
**期望输出：** 10 包；包 4 `method=GET`（段数本身由包数断，不单独断每段字节）。
**错误期望：** 无。
**性能期望：** 不适用。
**实现位置：** `cases/http.json`（http_mss_segments_long_response）。

### T-HTTP-29 http.json——PUT 方法【D-HTTP-1 §1】

**状态：** 已通过（P5 实测 67/67 全绿；二进制与 HEAD 同代）
**级别：** pcap
**来源：** D-HTTP-1 §1（builders 用户>默认>无；单测 TestBuildHTTPRequest_MultipleMethods 已 cover 方法表，pcap 钉 GET/POST 之外代表）
**目标：** PUT 请求行与 uri 上线。

**输入：** 同链形（src_port 40034）+ `http{method PUT,uri /item/1,body {"a":1}}`。
**前置条件：** T-HTTP-7 绿。
**执行：** 同 T-HTTP-7。
**期望输出：** 9 包；包 4 `method=PUT`、`uri=/item/1`。
**错误期望：** 无。
**性能期望：** 不适用。
**实现位置：** `cases/http.json`（http_put_method）。

### T-HTTP-30 http.json——DELETE 方法【D-HTTP-1 §1】

**状态：** 已通过（P5 实测 67/67 全绿；二进制与 HEAD 同代）
**级别：** pcap
**来源：** 同 T-HTTP-29
**目标：** DELETE 请求行上线。

**输入：** 同链形（src_port 40035）+ `http{method DELETE,uri /item/1}`。
**前置条件：** T-HTTP-7 绿。
**执行：** 同 T-HTTP-7。
**期望输出：** 9 包；包 4 `method=DELETE`。
**错误期望：** 无。
**性能期望：** 不适用。
**实现位置：** `cases/http.json`（http_delete_method）。

### T-HTTP-31 http.json——HEAD 方法【D-HTTP-1 §1】

**状态：** 已通过（P5 实测 67/67 全绿；二进制与 HEAD 同代）
**级别：** pcap
**来源：** 同 T-HTTP-29（单测 TestBuildHTTPRequest_HEADNoBody 已 cover 无体语义）
**目标：** HEAD 请求行上线。

**输入：** 同链形（src_port 40036）+ `http{method HEAD,uri /head}`。
**前置条件：** T-HTTP-7 绿。
**执行：** 同 T-HTTP-7。
**期望输出：** 9 包；包 4 `method=HEAD`。
**错误期望：** 无。
**性能期望：** 不适用。
**实现位置：** `cases/http.json`（http_head_method）。

### T-HTTP-32 http.json——响应 301 Location【D-HTTP-1 §1】

**状态：** 已通过（P5 实测 67/67 全绿；二进制与 HEAD 同代）
**级别：** pcap
**来源：** D-HTTP-1 §1（ResponseHeaders 覆盖；单测 TestHTTPPlan_StatusCode301WithLocation 已 cover）
**目标：** 301 状态码上线。

**输入：** 同链形（src_port 40037）+ `http{response_status_code 301,response_headers {Location /new},response_body moved}`。
**前置条件：** T-HTTP-7 绿。
**执行：** 同 T-HTTP-7。
**期望输出：** 9 包；包 5 `response.code=301`。
**错误期望：** 无。
**性能期望：** 不适用。
**实现位置：** `cases/http.json`（http_resp_301_location）。

### T-HTTP-33 http.json——响应 500【D-HTTP-1 §1】

**状态：** 已通过（P5 实测 67/67 全绿；二进制与 HEAD 同代）
**级别：** pcap
**来源：** D-HTTP-1 §1（单测 TestHTTPPlan_StatusCode500 已 cover）
**目标：** 500 状态码上线。

**输入：** 同链形（src_port 40038）+ `http{response_status_code 500,response_body boom}`。
**前置条件：** T-HTTP-7 绿。
**执行：** 同 T-HTTP-7。
**期望输出：** 9 包；包 5 `response.code=500`。
**错误期望：** 无。
**性能期望：** 不适用。
**实现位置：** `cases/http.json`（http_resp_500）。

### T-HTTP-34 http.json——响应 201 Created【D-HTTP-1 §1】

**状态：** 已通过（P5 实测 67/67 全绿；二进制与 HEAD 同代）
**级别：** pcap
**来源：** D-HTTP-1 §1（ResponseStatusCode 0→200；非零直用）
**目标：** 201 状态码与 POST 组合上线。

**输入：** 同链形（src_port 40039）+ `http{method POST,uri /items,body {"n":1},response_status_code 201,response_body {"id":9}}`。
**前置条件：** T-HTTP-7 绿。
**执行：** 同 T-HTTP-7。
**期望输出：** 9 包；包 4 `method=POST`；包 5 `response.code=201`。
**错误期望：** 无。
**性能期望：** 不适用。
**实现位置：** `cases/http.json`（http_resp_201_created）。

### T-HTTP-35 http.json——请求 gzip+chunked 复合【D-HTTP-1 §1】

**状态：** 已通过（P5 实测 67/67 全绿；二进制与 HEAD 同代）
**级别：** pcap
**来源：** D-HTTP-1 §1（gzip→chunked 先后顺序；单测 TestBuildHTTPResponse_ChunkedWithGzip 已 cover 响应侧，pcap 钉请求侧）
**目标：** 请求侧压缩后分块两头并存。

**输入：** 同链形（src_port 40040）+ `http{method POST,body gzip-then-chunk-body-bytes,request_content_encoding gzip,request_transfer_encoding chunked}`。
**前置条件：** T-HTTP-7 绿。
**执行：** 同 T-HTTP-7。
**期望输出：** 9 包；包 4 `content_encoding=gzip`、`transfer_encoding=chunked`。
**错误期望：** 无。
**性能期望：** 不适用。
**实现位置：** `cases/http.json`（http_req_gzip_chunked_composite）。

### T-HTTP-36 请求 transfer identity 字面直透【D-HTTP-1 §1】

**状态：** 已废弃（分支由单测覆盖；pcap 例因 tshark 对 `Transfer-Encoding: identity` 报 malformed 伪影、无白名单依据，按“不断言做不到的事”删除，用例不在 `cases/http.json`）
**级别：** unit（单测已 cover）
**来源：** D-HTTP-1 §1（非 chunked 值按字面头直透）；`http_chunked_test.go:225` `ResponseTransferEncoding: "identity"` 直透分支（请求侧同函数对称）
**目标：** 非 chunked 值按字面头发出、不做分块帧。

**输入：** `ResponseTransferEncoding: "identity"` + body `x`。
**前置条件：** 无。
**执行：** `go test ./internal/protocol/http/ -run TestBuildHTTPResponse_TransferEncoding -count=1`
**期望输出：** 含字面头 `Transfer-Encoding: identity`；体为原文 `x`、不做分块帧。
**错误期望：** 无。
**性能期望：** 不适用。
**实现位置：** `internal/protocol/http/http_chunked_test.go:225`。

### T-HTTP-37 http.json——请求非 gzip 编码直透【D-HTTP-1 §1】

**状态：** 已通过（P5 实测 67/67 全绿；二进制与 HEAD 同代）
**级别：** pcap
**来源：** D-HTTP-1 §1（非 gzip 的 content_encoding 按字面直透；单测 TestBuildHTTPRequest_RequestContentEncodingNonGzip 已 cover）
**目标：** `br` 编码值原样上头。

**输入：** 同链形（src_port 40042）+ `http{method POST,body abc,request_content_encoding br}`。
**前置条件：** T-HTTP-7 绿。
**执行：** 同 T-HTTP-7。
**期望输出：** 9 包；包 4 `content_encoding=br`。
**错误期望：** 无。
**性能期望：** 不适用。
**实现位置：** `cases/http.json`（http_req_encoding_non_gzip）。

### T-HTTP-38 http.json——请求坏 b64 回退 body【D-HTTP-1 §1】

**状态：** 已通过（P5 实测 67/67 全绿；二进制与 HEAD 同代）
**级别：** pcap
**来源：** D-HTTP-1 §1（resolveRequestBody：BodyB64 非法→回退 Body，不硬失败）
**目标：** 非法 b64 不报错，按文本体发出（13 字节）。

**输入：** 同链形（src_port 40043）+ `http{method POST,body fallback-text,body_b64 !!!not-base64!!!}`。
**前置条件：** T-HTTP-7 绿。
**执行：** 同 T-HTTP-7。
**期望输出：** 9 包；包 4 `content_length=13`。
**错误期望：** 无（回退语义不断 error）。
**性能期望：** 不适用。
**实现位置：** `cases/http.json`（http_req_body_invalid_b64_fallback）。

### T-HTTP-39 http.json——请求 MSS 分段【D-HTTP-1 §3】

**状态：** 已通过（P5 实测 67/67 全绿；二进制与 HEAD 同代）
**级别：** pcap
**来源：** D-HTTP-1 §3（MSS 分段归 tcp 层；单测 TestHTTPPlan_RequestMSSSegmentsLongBody 已 cover 切片语义，pcap 钉包数）；RFC 879
**目标：** MSS 536 下 3000 字节请求体分段，包数 14（响应侧 T-HTTP-28 的请求侧对称）。

**输入：** 同链形（src_port 40044，tcp.mss 536）+ `http{method POST,body B×3000}`。
**前置条件：** T-HTTP-7 绿。
**执行：** 同 T-HTTP-7。
**期望输出：** 14 包；包 9 `http.request.method=POST`（分片后重组仅包 9 可见）。
**错误期望：** 无。
**性能期望：** 不适用。
**实现位置：** `cases/http.json`（http_mss_req_segments_long_body）。

### T-HTTP-40 http.json——单事务 Connection close【D-HTTP-1 §3】

**状态：** 已通过（P5 实测 67/67 全绿；二进制与 HEAD 同代）
**级别：** pcap
**来源：** D-HTTP-1 §3（defaultConnection：单事务且非 keep-alive→close；T-HTTP-9 的对照端）
**目标：** 单事务默认 Connection 为 close。

**输入：** 同链形（src_port 40045）+ `http{uri /one}`。
**前置条件：** T-HTTP-9 绿（对照）。
**执行：** 同 T-HTTP-7。
**期望输出：** 9 包；包 4 `connection=close`。
**错误期望：** 无。
**性能期望：** 不适用。
**实现位置：** `cases/http.json`（http_conn_close_single）。

### T-HTTP-41 http.json——多流动态源端口【D-HTTP-1 §4】

**状态：** 已通过（P5 实测 67/67 全绿；二进制与 HEAD 同代）
**级别：** pcap
**来源：** D-HTTP-1 §4（多流变化只走 ip/tcp 层动态 + flow_control；§12 动态整格：inc 回绕/复现）；CORE_MEMORY §9 陷阱③（flows>1 时四元组须动态）
**目标：** flows=2 + tcp.src_port inc[41000,41001] 产 18 包，两流源端口聚合正确。

**输入：** `[ip,tcp(src_port inc[41000,41001],dst 80),http]` + `strategy_fc{flows 2}`。
**前置条件：** T-HTTP-7 绿。
**执行：** 同 T-HTTP-7。
**期望输出：** 18 包；`tcp.srcport distinct{41000,41001}（排除 80）`；`tcp.dstport distinct{80,41000,41001}`（tshark 双向聚合口径，见校验器语义）。
**错误期望：** 无。
**性能期望：** 不适用。
**实现位置：** `cases/http.json`（http_multiflow_dynamic_sport）。

### T-HTTP-42 http.json——TTL 注入路径【D-HTTP-1 §4】

**状态：** 已通过（P5 实测 67/67 全绿；二进制与 HEAD 同代）
**级别：** pcap
**来源：** D-HTTP-1 §4（applySpecToChain 回写覆盖层 ttl：spec.TTL 非零才注入；层直写 128 被 schema 默认 64 覆盖——框架行为，非 http 缺口；正确路径=顶层 `ttl:128`→spec.TTL→注入层）
**目标：** 顶层 ttl 128 落包（包 1 `ip.ttl=128`）。

**输入：** 同链形（src_port 40046）+ 顶层 `"ttl":128`（注意不是层内 ttl）。
**前置条件：** T-HTTP-7 绿。
**执行：** 同 T-HTTP-7。
**期望输出：** 9 包；包 1 `ip.ttl=128`。
**错误期望：** 无。
**性能期望：** 不适用。
**实现位置：** `cases/http.json`（http_ttl_custom）。

### T-HTTP-43 http.json——旧 headers 键兼容回退【D-HTTP-1 §1】

**状态：** 已通过（P5 实测 67/67 全绿；二进制与 HEAD 同代）
**级别：** pcap
**来源：** D-HTTP-1 §1（`strategy_convert.go:378` 通用读：`request_headers` 缺席时回退 `headers`，存量行防丢头）
**目标：** 只写旧 `headers` 键时 Host 覆盖与自定义头同样生效。

**输入：** 同链形（src_port 40050）+ `http{method GET,uri /hdr-old,headers {X-Trace abc,Host legacy.test}}`（注意不是 `request_headers`）。
**前置条件：** T-HTTP-7 绿。
**执行：** 同 T-HTTP-7。
**期望输出：** 9 包；包 4 `method=GET`、`host=legacy.test`。
**错误期望：** 无。
**性能期望：** 不适用。
**实现位置：** `cases/http.json`（http_req_headers_legacy）。

### T-HTTP-44 http.json——响应 content_encoding 新键【D-HTTP-1 §1】

**状态：** 已通过（P5 实测 67/67 全绿；二进制与 HEAD 同代）
**级别：** pcap
**来源：** D-HTTP-1 §1（层链口径：V9 只认注册表 21 键，旧 `content_encoding` 键在层内是未知字段、建任务即 `unknown field` 拒绝——单例探针已证；旧键回退只活在顶层通用读 `ParseHTTPConfigFromMap`（`strategy_convert.go:7713` `getStringWithFallback`），由单测 `TestMapToFlowSpec_LegacyHeadersKeyFallback` 同族覆盖在库旧行，不进层链。层内只写新键）
**目标：** `response_content_encoding: gzip` 时响应体照常压缩。

**输入：** 同链形（src_port 40051）+ `http{method GET,uri /ce-old,response_body hello-legacy-enc,response_content_encoding gzip}`（注意是新键——旧键在层链已判死，不是兼容）。
**前置条件：** T-HTTP-7 绿。
**执行：** 同 T-HTTP-7。
**期望输出：** 9 包；包 5 `response.code=200`、`content_encoding=gzip`。
**错误期望：** 无。
**性能期望：** 不适用。
**实现位置：** `cases/http.json`（http_req_content_encoding_legacy）。

### T-HTTP-45 http.json——file_source fill 形态【D-HTTP-1 §1】

**状态：** 已通过（P5 实测 67/67 全绿；二进制与 HEAD 同代）
**级别：** pcap
**来源：** D-HTTP-1 §1（`parseFileSource:1451`：`file_source{fill{byte,bytes}}` 经 PayloadCache 取体；单测 `http_filesource_test.go:6` 只 cover literal）
**目标：** fill 形态 16 字节 `A` 体正常发出。

**输入：** 同链形（src_port 40052）+ `http{method POST,uri /fill,file_source {fill {byte 65,bytes 16}}}`。
**前置条件：** T-HTTP-7 绿。
**执行：** 同 T-HTTP-7。
**期望输出：** 9 包；包 4 `method=POST`、`content_length=16`。
**错误期望：** 无。
**性能期望：** 不适用。
**实现位置：** `cases/http.json`（http_file_source_fill）。

### T-HTTP-46 http.json——file_source random 定长形态【D-HTTP-1 §1】

**状态：** 已通过（P5 实测 67/67 全绿；二进制与 HEAD 同代）
**级别：** pcap
**来源：** D-HTTP-1 §1（`parseFileSource:1463`：`file_source{random{min_bytes,max_bytes,seed}}`；seed 非零可复现——不断字节值，只断长度；`file` 形态需落盘文件、MCP 不可达，不建 pcap 例）
**目标：** random 定长 8 字节（min=max=8，seed=7）体正常发出。

**输入：** 同链形（src_port 40053）+ `http{method POST,uri /rand,file_source {random {min_bytes 8,max_bytes 8,seed 7}}}`。
**前置条件：** T-HTTP-7 绿。
**执行：** 同 T-HTTP-7。
**期望输出：** 9 包；包 4 `method=POST`、`content_length=8`。
**错误期望：** 无。
**性能期望：** 不适用。
**实现位置：** `cases/http.json`（http_file_source_random）。

### T-HTTP-47 http.json——IPv6 多流动态源端口【D-HTTP-1 §4】

**状态：** 已通过（P5 实测 67/67 全绿；二进制与 HEAD 同代）
**级别：** pcap
**来源：** D-HTTP-1 §4（正交矩阵 IPv6×多流格；T-HTTP-41 的 IPv4 对照端；多流交织非确定性——只断聚合，不断固定包号，见校验器 `verify.go:45` distinct 语义）
**目标：** v6 下 flows=2 + src_port inc[42000,42001] 产 18 包，两流端口聚合正确。

**输入：** `[ip(2001:db8::10→2001:db8::20),tcp(src_port inc[42000,42001],dst 80),http]` + `strategy_fc{flows 2}`。
**前置条件：** T-HTTP-7 绿。
**执行：** 同 T-HTTP-7。
**期望输出：** 18 包；`tcp.srcport distinct{42000,42001}（排除 80）`；`tcp.dstport distinct{80,42000,42001}`（tshark 双向聚合口径）。
**错误期望：** 无。
**性能期望：** 不适用。
**实现位置：** `cases/http.json`（http_ipv6_multiflow_dynamic）。

### T-HTTP-48 http.json——IPv6 响应 MSS 分段【D-HTTP-1 §3】

**状态：** 已通过（P5 实测 67/67 全绿；二进制与 HEAD 同代）
**级别：** pcap
**来源：** D-HTTP-1 §3（正交矩阵 IPv6×MSS 格；T-HTTP-28 的 v6 对照端）；RFC 879
**目标：** v6 下 MSS 536 + 600 字节响应体分段（10 包）。

**输入：** `[ip(2001:db8::10→2001:db8::20),tcp(src_port 40055,dst 80,mss 536),http]` + `http{method GET,uri /v6long,response_body A×600}`。
**前置条件：** T-HTTP-7 绿。
**执行：** 同 T-HTTP-7。
**期望输出：** 10 包；包 4 `method=GET`。
**错误期望：** 无。
**性能期望：** 不适用。
**实现位置：** `cases/http.json`（http_ipv6_mss_segments）。

### T-HTTP-49 http.json——请求 chunked×MSS 组合分段【D-HTTP-1 §1/§3】

**状态：** 已通过（P5 实测 67/67 全绿；二进制与 HEAD 同代）
**级别：** pcap
**来源：** D-HTTP-1 §1（chunked 分块）+ §3（MSS 分段归 tcp 层；实测：600 字节 chunked 体在 MSS 536 下产 10 包，请求在包 5——tshark 重组口径，不手算）
**目标：** chunked 编码体再经 MSS 切段，请求行在包 5 可见。

**输入：** 同链形（src_port 40056，tcp.mss 536）+ `http{method POST,uri /cm,body C×600,request_transfer_encoding chunked}`。
**前置条件：** T-HTTP-7 绿。
**执行：** 同 T-HTTP-7。
**期望输出：** 10 包；包 5 `method=POST`、`transfer_encoding=chunked`。
**错误期望：** 无。
**性能期望：** 不适用。
**实现位置：** `cases/http.json`（http_req_chunked_mss）。

### T-HTTP-50 http.json——http 链扁平判死负例【D-HTTP-1 §5】

**状态：** 已通过（P5 实测 67/67 全绿；二进制与 HEAD 同代）
**级别：** pcap（Validate-negative：真实流程拒绝）
**来源：** Step1 CheckProtoFlat（`strategy_convert.go:7609`；http 链专属例——框架级 T-FTP-15 覆通用形状，本例钉 http 链）
**目标：** 顶层 `src_ip` 与 `layers` 共存时建任务即被拒。

**输入：** 同链形（src_port 40057）+ 顶层 `"src_ip":"10.0.0.1"`（混用）+ `http{method GET,uri /,version HTTP/1.1}`。
**前置条件：** 无。
**执行：** 同 T-HTTP-7（suite 走 `flowb_generate_traffic`，MCP 即拒）。
**期望输出：** 任务失败；错误含 `no longer accepts flat config field src_ip`。
**错误期望：** 即本条（`expect_error` + `error_contains`）。
**性能期望：** 不适用。
**实现位置：** `cases/http.json`（http_neg_flat_src_ip）。

### T-HTTP-51 http.json——http 链静态复制拒绝负例【D-HTTP-1 §4】

**状态：** 已通过（P5 实测 67/67 全绿；二进制与 HEAD 同代）
**级别：** pcap（Validate-negative：真实流程拒绝）
**来源：** D-FTP-3 `checkLayerChainStaticCopy`（`schema/semantic.go:169`；http 链专属例——框架级规则在 http 链的落点）
**目标：** flows=2 + 全静态标量四元组时建策略即被拒。

**输入：** 同链形（src_port 40058）+ `strategy_fc{flows 2}`（四元组全标量、无动态对象）+ `http{method GET,uri /,version HTTP/1.1}`。
**前置条件：** 无。
**执行：** 同 T-HTTP-50。
**期望输出：** 任务失败；错误含 `static four-tuple`。
**错误期望：** 即本条；反例=T-HTTP-41（同 flows=2 但源端口写动态对象→通过）。
**性能期望：** 不适用。
**实现位置：** `cases/http.json`（http_neg_static_copy）。

### T-HTTP-52 http.json——gbt 缺 http 载体负例【D-HTTP-1 §5】

**状态：** 已通过（P5 实测 67/67 全绿；二进制与 HEAD 同代）
**级别：** pcap（Validate-negative：真实流程拒绝）
**来源：** D-HTTP-1 §5 载体检查 8 家（`validate_layers.go:86-98`；单测 `TestHTTPCarrierRequired_FiveFamilies` 覆 5 家离线断言，本例钉 gbt 真实流程落点）
**目标：** `[ip,tcp,gbt]` 无 http 层时建任务即被拒。

**输入：** `[ip(192.0.2.10→198.51.100.20),tcp(src_port 40059,dst 8332),gbt{}]` + 顶层 `http{method GET,uri /g,version HTTP/1.1}`。
**前置条件：** 无。
**执行：** 同 T-HTTP-50。
**期望输出：** 任务失败；错误含 `requires the http carrier layer`。
**错误期望：** 即本条。
**性能期望：** 不适用。
**实现位置：** `cases/http.json`（http_neg_missing_carrier_gbt）。

### T-HTTP-53 http.json——源端口 rand 可复现聚合【D-HTTP-1 §4】

**状态：** 已通过（P5 实测 67/67 全绿；二进制与 HEAD 同代）
**级别：** pcap
**来源：** CORE_MEMORY §12（rand 用 seed+序号，同序号同结果，可复现）+ D-HTTP-1 §4（序号算法沿框架 `genPort`，`tuple_generator.go:227`）；CORE_MEMORY §9 动态整格（三问①语义真发生）
**目标：** seed=7、range[43000,43009]、flows=4 的四流源端口聚合为 pcap 实测四值。

**输入：** 同链形 + `tcp.src_port{strategy rand,range[43000,43009],seed 7}` + `strategy_fc{flows 4}`。
**前置条件：** T-HTTP-7 绿。
**执行：** 同 T-HTTP-7。
**期望输出：** 36 包；`tcp.srcport distinct{43006,43008,43001,43004}（排除 80）`；`tcp.dstport distinct{80,43006,43008,43001,43004}`。值从落盘 pcap 回填，不手算。
**错误期望：** 无。
**性能期望：** 不适用。
**实现位置：** `cases/http.json`（http_dyn_sport_rand）。

### T-HTTP-54 http.json——源端口 list 轮转【D-HTTP-1 §4】

**状态：** 已通过（P5 实测 67/67 全绿；二进制与 HEAD 同代）
**级别：** pcap
**来源：** CORE_MEMORY §12（list 轮转）+ D-HTTP-1 §4（`genPort:202` 取 `list[index%len]`）；注意 list 端点是字符串（`StrategyConfig.List []string`，写数字报 `invalid object`，实测已证）
**目标：** list[43100,43101]、flows=4 时两端口各出现两次（各 10 包）。

**输入：** 同链形 + `tcp.src_port{strategy list,list["43100","43101"]}` + `strategy_fc{flows 4}`。
**前置条件：** T-HTTP-7 绿。
**执行：** 同 T-HTTP-7。
**期望输出：** 36 包；`tcp.srcport distinct{43100,43101}（排除 80）`；tshark 计数各 10（含重传）。
**错误期望：** 无。
**性能期望：** 不适用。
**实现位置：** `cases/http.json`（http_dyn_sport_list）。

### T-HTTP-55 http.json——源端口 fixed 单流【D-HTTP-1 §4】

**状态：** 已通过（P5 实测 67/67 全绿；二进制与 HEAD 同代）
**级别：** pcap
**来源：** CORE_MEMORY §12（不写动态即按 fixed 沿用静态值）+ D-HTTP-1 §4
**目标：** 显式标量 43200 单流不断聚合（fixed 对照端，证明动态对象与标量同住处）。

**输入：** 同链形（tcp.src_port 标量 43200）+ `http{method GET,uri /df}` + `strategy_fc{flows 1}`（注：flows=1 单流是 static-copy 门的豁免口径，见 `checkLayerChainStaticCopy:169` `int(flows)<=1` 早返；`strategy_fc` 显式写 1 是断言“单流不断言聚合”的形状证据，不是缺省省略）。
**前置条件：** T-HTTP-7 绿。
**执行：** 同 T-HTTP-7。
**期望输出：** 9 包；包 4 `method=GET`。
**错误期望：** 无。
**性能期望：** 不适用。
**实现位置：** `cases/http.json`（http_dyn_sport_fixed）。

### T-HTTP-56 http.json——源端口 inc 到尾回绕【D-HTTP-1 §4】

**状态：** 已通过（P5 实测 67/67 全绿；二进制与 HEAD 同代）
**级别：** pcap
**来源：** CORE_MEMORY §12（到尾回绕）+ D-HTTP-1 §4（`genPort:217` 取 `(index*step)%count`）；CORE_MEMORY §9 动态整格（三问③越界回绕）
**目标：** range[43300,43302]、flows=5 时第 4/5 流回绕为 43300/43301。

**输入：** 同链形 + `tcp.src_port{strategy inc,range[43300,43302]}` + `strategy_fc{flows 5}`。
**前置条件：** T-HTTP-7 绿。
**执行：** 同 T-HTTP-7。
**期望输出：** 45 包；`tcp.srcport distinct{43300,43301,43302}（排除 80）`；tshark 计数 43300×10/43301×10/43302×5（回绕证据）。
**错误期望：** 无。
**性能期望：** 不适用。
**实现位置：** `cases/http.json`（http_dyn_sport_inc_wrap）。

### T-HTTP-57 http.json——源端口 rand 复现对照【D-HTTP-1 §4】

**状态：** 已通过（P5 实测 67/67 全绿；二进制与 HEAD 同代）
**级别：** pcap
**来源：** CORE_MEMORY §12（rand 可复现）+ D-HTTP-1 §4；CORE_MEMORY §9 动态整格（三问②宣称可复现的是否复现）
**目标：** 与 T-HTTP-53 同 seed 同 range 再跑一次，四值完全相同（tshark 计数逐值相等：各 5）。

**输入：** 同 T-HTTP-53（`http{uri /dr2}` 以区分任务名）。
**前置条件：** T-HTTP-53 绿。
**执行：** 同 T-HTTP-7。
**期望输出：** 36 包；聚合四值与 53 完全相同（43006/43008/43001/43004，各 5 包）。
**错误期望：** 无。
**性能期望：** 不适用。
**实现位置：** `cases/http.json`（http_dyn_sport_rand_repro）。

### T-HTTP-58 http.json——源地址 rand 三流聚合【D-HTTP-1 §4】

**状态：** 已通过（P5 实测 67/67 全绿；二进制与 HEAD 同代）
**级别：** pcap
**来源：** CORE_MEMORY §12（至少覆盖 `src_ip`/`dst_ip`/`src_port`/`dst_port`）+ D-HTTP-1 §4（`genIP` 双栈分支，`tuple_generator.go`）；CORE_MEMORY §9 陷阱③（多流须动态——本例源端口写静态 43400 照样触发静态复制拒绝，故源端口同步动态？不——本例 ip.src 动态已满足“有对象”条件，静态复制门看全字段有任一对象即放行，实测通过）
**目标：** ip.src rand seed=7 range[10.1.0.1,10.1.0.9]、flows=3 的三流源地址聚合为 pcap 实测三值。

**输入：** `[ip(src{strategy rand,range[10.1.0.1,10.1.0.9],seed 7},dst 198.51.100.20),tcp(src_port 43400 标量,dst 80),http]` + `strategy_fc{flows 3}`（注：ip.src 单动态对象即满足 static-copy 门的逃逸口——门只认“任一对象”即放行，见 `checkLayerChainStaticCopy` hasDyn 分支；67/67 全绿是放行证据）。
**前置条件：** T-HTTP-7 绿。
**执行：** 同 T-HTTP-7。
**期望输出：** 27 包；`ip.src distinct{10.1.0.2,10.1.0.4,10.1.0.5}（排除 198.51.100.20）`。值从落盘 pcap 回填。
**错误期望：** 无。
**性能期望：** 不适用。
**实现位置：** `cases/http.json`（http_dyn_sip_rand）。

### T-HTTP-59 http.json——层地址端口 pattern 被拒负例【D-HTTP-1 §5】

**状态：** 已通过（P5 实测 67/67 全绿；二进制与 HEAD 同代）
**级别：** pcap（Validate-negative：真实流程拒绝）
**来源：** D-HTTP-1 §4 白名单（`layer_dyn.go:154`：pattern 只对字符串字段有意义，IP/端口/MAC/TTL 用类型算法无 pattern 分支——大声拒绝，不静默空解）
**目标：** `tcp.src_port{strategy pattern,…}` 建任务即被拒（pattern 在层地址端口维度=不支持，不是没测）。

**输入：** 同链形 + `tcp.src_port{strategy pattern,pattern "p{n}",range[1,2]}`。
**前置条件：** 无。
**执行：** 同 T-HTTP-50。
**期望输出：** 任务失败；错误含 `pattern strategy is not supported`。
**错误期望：** 即本条（`expect_error` + `error_contains`）。
**性能期望：** 不适用。
**实现位置：** `cases/http.json`（http_dyn_pattern_reject）。

### T-HTTP-60 http.json——业务 uri list 轮转【D-HTTP-1 §4】

**状态：** 已通过（P5 实测 67/67 全绿；二进制 `/tmp/tg-http-rework-server` 与 HEAD 同代，`find -newer` 空；落盘 `/tmp/mcp-pcaps-rework/http/`）
**级别：** pcap
**来源：** D-HTTP-1 §4（http 业务 6 开之 uri，string 面 fixed/list/pattern；序号算法与四元组同域 `ResolveStringValue(i)`，`tuple_generator.go:306`；生产真相是 `translateHTTPDyn` 在 `Plan→ValidateSpec→translate` 内按 `spec.FlowIndex` 直解，`chain_planner_translate.go:1010`）
**目标：** flows=2 时两流请求行 uri 分别为 /a、/b（业务动态真随流序号变化，不是静态复制）。

**输入：** 同链形 + `tcp.src_port{strategy list,list["41001","41002"]}`（注：tcp 动态对象是 static-copy 门的逃逸口——`checkLayerChainStaticCopy` 只扫 ip/tcp/udp 三层四元组字段，http 层动态对象不计入，flows>1 仍须四元组侧有对象）+ `http{method GET,uri{strategy list,list[/a,/b]},version 1.1}` + `strategy_fc{flows 2}`。
**前置条件：** T-HTTP-7 绿。
**执行：** 同 T-HTTP-7。
**期望输出：** 18 包；包 4 `http.request.uri distinct{/a,/b}`。tshark 落盘口径：`41001→/a`、`41002→/b`（四元组序号域与业务序号域同 i 对齐的证据）。
**错误期望：** 无。
**性能期望：** 不适用。
**实现位置：** `cases/http.json`（http_dyn_uri_list）。

### T-HTTP-61 http.json——业务 uri pattern 替换【D-HTTP-1 §4】

**状态：** 已通过（P5 实测 67/67 全绿；二进制与 HEAD 同代）
**级别：** pcap
**来源：** D-HTTP-1 §4（uri 开 pattern；`genStringValue` 的 `{n}` 替换与四元组 pattern 同算法，`shard_router.go:58/105` 单真相）
**目标：** pattern `/u{n}`、range[1,2]、flows=2 时两流 uri 为 /u1、/u2。

**输入：** 同 T-HTTP-60 形状（tcp list["41002","41003"]）+ `http{uri{strategy pattern,pattern /u{n},range[1,2]}}` + `strategy_fc{flows 2}`。
**前置条件：** T-HTTP-60 绿。
**执行：** 同 T-HTTP-7。
**期望输出：** 18 包；包 4 `http.request.uri distinct{/u1,/u2}`。tshark 落盘：`41002→/u1`、`41003→/u2`。
**错误期望：** 无。
**性能期望：** 不适用。
**实现位置：** `cases/http.json`（http_dyn_uri_pattern）。

### T-HTTP-62 http.json——业务 uri fixed 对照【D-HTTP-1 §4】

**状态：** 已通过（P5 实测 67/67 全绿；二进制与 HEAD 同代）
**级别：** pcap
**来源：** D-HTTP-1 §4（fixed 是动态形状的退化对照端：对象写法、标量效果；证明“对象≠多流”，单流 fixed 不触发 static-copy 门）
**目标：** `uri{strategy fixed,value /a}` 单流恒为 /a（flows 缺省 1）。

**输入：** 同链形（tcp.src_port 标量 41003）+ `http{uri{strategy fixed,value /a}}`（flows 缺省）。
**前置条件：** T-HTTP-60 绿。
**执行：** 同 T-HTTP-7。
**期望输出：** 9 包；包 4 `http.request.uri=/a`。tshark 落盘：单流 `/a`。
**错误期望：** 无。
**性能期望：** 不适用。
**实现位置：** `cases/http.json`（http_dyn_uri_fixed）。

### T-HTTP-63 http.json——业务 body list 轮转【D-HTTP-1 §4】

**状态：** 已通过（P5 实测 67/67 全绿；二进制与 HEAD 同代）
**级别：** pcap
**来源：** D-HTTP-1 §4（http 业务 6 开之 body；请求体经 `resolveRequestBody`，动态解析值同样进入 Content-Length 计算——不断体长，只断方法/uri/length 三元组，见可观察性注记）
**目标：** POST body list[AAA,BBB]、flows=2 时两流请求体分别为 AAA、BBB（重组后 `http.file_data` 口径）。

**输入：** 同链形 + `tcp.src_port{list["41004","41005"]}` + `http{method POST,uri /p,body{list[AAA,BBB]}}` + `strategy_fc{flows 2}`。
**前置条件：** T-HTTP-60 绿。
**执行：** 同 T-HTTP-7。
**期望输出：** 18 包；包 5 `method distinct{POST}`、`uri distinct{/p}`、`content_length distinct{3}`。tshark 落盘（TCP 重组）：`41004→AAA`、`41005→BBB`。注：包级 `data` 字段为空是 tshark 未重组分段所致，不是否证——断言以重组口径为准。
**错误期望：** 无。
**性能期望：** 不适用。
**实现位置：** `cases/http.json`（http_dyn_body_list）。

### T-HTTP-64 http.json——业务 response_body list 轮转【D-HTTP-1 §4】

**状态：** 已通过（P5 实测 67/67 全绿；二进制与 HEAD 同代）
**级别：** pcap
**来源：** D-HTTP-1 §4（http 业务 6 开之 response_body；响应侧动态，请求侧恒定——证明翻译只写回填字段、不碰其余 14 键）
**目标：** response_body list[R1,R2]、flows=2 时两流响应体分别为 R1、R2。

**输入：** 同链形 + `tcp.src_port{list["41005","41006"]}` + `http{method GET,uri /b,response_body{list[R1,R2]}}` + `strategy_fc{flows 2}`。
**前置条件：** T-HTTP-60 绿。
**执行：** 同 T-HTTP-7。
**期望输出：** 18 包；包 5 `http.response.code distinct{200}`（两流同码、体不同，码不断体）。tshark 落盘：`41005→R1`、`41006→R2`。
**错误期望：** 无。
**性能期望：** 不适用。
**实现位置：** `cases/http.json`（http_dyn_respbody_list）。

### T-HTTP-65 http.json——业务 status_code list 枚举【D-HTTP-1 §4】

**状态：** 已通过（P5 实测 67/67 全绿；二进制与 HEAD 同代）
**级别：** pcap
**来源：** D-HTTP-1 §4 裁定表 F（response_status_code 走 int 面 fixed/inc/rand/list；list 端点是字符串，经 `toPort` 数值化，与 tcp 端口 list 同算法 `tuple_generator.go:296`）
**目标：** status_code list["200","404"]、flows=2 时两流状态码分别为 200、404。

**输入：** 同链形 + `tcp.src_port{list["41006","41007"]}` + `http{response_status_code{list["200","404"]},response_body st}` + `strategy_fc{flows 2}`。
**前置条件：** T-HTTP-60 绿。
**执行：** 同 T-HTTP-7。
**期望输出：** 18 包；包 5 `http.response.code distinct{200,404}`。tshark 落盘：`41006→200`、`41007→404`。
**错误期望：** 无。
**性能期望：** 不适用。
**实现位置：** `cases/http.json`（http_dyn_status_list）。

### T-HTTP-66 http.json——业务 status_code inc 回绕【D-HTTP-1 §4】

**状态：** 已通过（P5 实测 67/67 全绿；二进制与 HEAD 同代）
**级别：** pcap
**来源：** D-HTTP-1 §4（int 面 inc：`(index*step)%count`，`tuple_generator.go` `genPort:217` 同款；CORE_MEMORY §9 动态整格三问③越界回绕在业务维的落点）
**目标：** range[200,201]、flows=2 时两流状态码为 200、201。

**输入：** 同链形 + `tcp.src_port{list["41007","41008"]}` + `http{response_status_code{strategy inc,range[200,201]}}` + `strategy_fc{flows 2}`。
**前置条件：** T-HTTP-65 绿。
**执行：** 同 T-HTTP-7。
**期望输出：** 18 包；包 5 `http.response.code distinct{200,201}`。tshark 落盘：`41007→200`、`41008→201`。
**错误期望：** 无。
**性能期望：** 不适用。
**实现位置：** `cases/http.json`（http_dyn_status_inc）。

### T-HTTP-67 http.json——业务 status_code rand 复现对照【D-HTTP-1 §4】

**状态：** 已通过（P5 实测 67/67 全绿；二进制与 HEAD 同代）
**级别：** pcap
**来源：** D-HTTP-1 §4（int 面 rand：`seed+index` 定源，`genPort` rand 分支；CORE_MEMORY §9 三问②“宣称可复现的是否复现”在业务维的落点；与 T-HTTP-66 同 range 的对照端）
**目标：** range[200,201]、seed=3、flows=2 时两流状态码确定可复现（实测 200、201）。

**输入：** 同链形 + `tcp.src_port{list["41008","41009"]}` + `http{response_status_code{strategy rand,range[200,201],seed 3}}` + `strategy_fc{flows 2}`。
**前置条件：** T-HTTP-66 绿。
**执行：** 同 T-HTTP-7。
**期望输出：** 18 包；包 5 `http.response.code distinct{200,201}`（值从落盘 pcap 回填，不手算）。tshark 落盘：`41008→200`、`41009→201`。
**错误期望：** 无。
**性能期望：** 不适用。
**实现位置：** `cases/http.json`（http_dyn_status_rand_repro）。

### T-HTTP-68 http.json——业务 body_b64 list 轮转【D-HTTP-1 §1/§4】

**状态：** 已通过（P5 实测 67/67 全绿；二进制与 HEAD 同代）
**级别：** pcap
**来源：** D-HTTP-1 §1（body_b64 是存量二进制体通道，store-only 进 builder；动态解析走 string 面，与 body 同例不同键）+ §4
**目标：** body_b64 list[QUJD,REVG]（=ABC/DEF）、flows=2 时两流解码体分别为 ABC、DEF（`http.file_data` 重组口径，length 恒 3）。

**输入：** 同链形 + `tcp.src_port{list["41009","41010"]}` + `http{method POST,uri /b,body_b64{list[QUJD,REVG]}}` + `strategy_fc{flows 2}`。
**前置条件：** T-HTTP-63 绿。
**执行：** 同 T-HTTP-7。
**期望输出：** 18 包；包 4 `http.content_length distinct{3}`。tshark 落盘：`41009→ABC`、`41010→DEF`。
**错误期望：** 无。
**性能期望：** 不适用。
**实现位置：** `cases/http.json`（http_dyn_body_b64_list）。

### T-HTTP-69 http.json——业务 response_body_b64 list 轮转【D-HTTP-1 §1/§4】

**状态：** 已通过（P5 实测 67/67 全绿；二进制与 HEAD 同代）
**级别：** pcap
**来源：** D-HTTP-1 §1（response_body_b64 存量通道）+ §4（响应侧 b64 动态；与 T-HTTP-68 的请求/响应对称端）
**目标：** response_body_b64 list[UjE=,UjI=]（=R1/R2）、flows=2 时两流响应体分别为 R1、R2。

**输入：** 同链形 + `tcp.src_port{list["41010","41011"]}` + `http{response_body_b64{list[UjE=,UjI=]}}` + `strategy_fc{flows 2}`。
**前置条件：** T-HTTP-64 绿。
**执行：** 同 T-HTTP-7。
**期望输出：** 18 包；包 5 `http.response.code distinct{200}`。tshark 落盘：`41010→R1`、`41011→R2`。
**错误期望：** 无。
**性能期望：** 不适用。
**实现位置：** `cases/http.json`（http_dyn_respbody_b64_list）。

### T-HTTP-70 http.json——业务 string 面 inc 被拒负例【D-HTTP-1 §5】

**状态：** 已通过（P5 实测 67/67 全绿；二进制与 HEAD 同代）
**级别：** pcap（Validate-negative：真实流程拒绝）
**来源：** D-HTTP-1 §4 裁定表 F（string 面 5 字段仅 fixed/list/pattern；inc/rand 无意义，形状层拒绝。`layer_dyn.go:157` `not supported for string field`；单测 `TestHTTPLayerDyn_StringSurfaceRejected` 覆 5 字段×2 策略离线断言，本例钉真实流程落点）
**目标：** `uri{strategy inc,…}` 建任务即被拒（string 维 inc 不是没测，是不支持）。

**输入：** 同链形（tcp.src_port 标量 41001）+ `http{uri{strategy inc,range[/a,/b]}}`。
**前置条件：** 无。
**执行：** 同 T-HTTP-50。
**期望输出：** 任务失败；错误含 `not supported for string field`。
**错误期望：** 即本条（`expect_error` + `error_contains`）。
**性能期望：** 不适用。
**实现位置：** `cases/http.json`（http_neg_dyn_uri_inc）。

### T-HTTP-71 http.json——关字段 method 对象被拒负例【D-HTTP-1 §5】

**状态：** 已通过（P5 实测 67/67 全绿；二进制与 HEAD 同代）
**级别：** pcap（Validate-negative：真实流程拒绝）
**来源：** D-HTTP-1 §4（21 键 6 开 15 关；method 关——方法枚举走不了序号算法。`checkLayerDynObjects` allowlist 门 `validate_layers.go:116` 报 `does not support dynamic`；单测 `TestHTTPLayerDyn_ClosedFieldsRejected` 覆 15 关字段离线断言，本例钉 method 真实流程落点）
**目标：** `method{strategy list,…}` 建任务即被拒。

**输入：** 同链形（tcp.src_port 标量 41001）+ `http{method{strategy list,list[GET,POST]},uri /b}`。
**前置条件：** 无。
**执行：** 同 T-HTTP-50。
**期望输出：** 任务失败；错误含 `does not support dynamic`。
**错误期望：** 即本条（`expect_error` + `error_contains`）。
**性能期望：** 不适用。
**实现位置：** `cases/http.json`（http_neg_dyn_closed_method）。

### T-HTTP-72 http.json——顶层 http presence 判死负例【D-HTTP-1 §5】

**状态：** 已通过（P5 实测 67/67 全绿；二进制与 HEAD 同代）
**级别：** pcap（Validate-negative：真实流程拒绝）
**来源：** Step1 CheckProtoFlat（`strategy_convert.go` http 族 9 协议分支；单测 `TestProtoFlat_TopHTTPSubConfigRejected` + `TestMapToFlowSpec_TopHTTPSubConfigRejected` 覆 9 家离线断言，本例钉 http 真实流程落点。锚词 `no longer accepts a top-level http sub-config`）
**目标：** 顶层 `http` 子映射与 `layers` 共存时建任务即被拒（迁入完成的执法证据：层内 21 键之外无第二住处）。

**输入：** 同链形（`http:{}` 空层）+ 顶层 `"http":{"method":"GET"}`。
**前置条件：** 无。
**执行：** 同 T-HTTP-50。
**期望输出：** 任务失败；错误含 `no longer accepts a top-level http sub-config`。
**错误期望：** 即本条（`expect_error` + `error_contains`）。注：门 2-1 顶层旧键扫描须豁免本例（presence 负例是执法对象，不是残留——`pipe_gate.sh` 按 `error_contains` 含 `top-level` 豁免）。
**性能期望：** 不适用。
**实现位置：** `cases/http.json`（http_neg_top_http）。

### T-TLS-1 tls.json——1.3 握手冒烟基线【D-TLS-1 §3】

**状态：** 已执行（P5，2026-09-14：9/9 绿）
**级别：** pcap
**来源：** D-TLS-1 §3（状态表：TCP 握手 3 归 tcp → TLS 握手 7 变换器先行注入 → 应用数据内层委托 → 挥手 4）；RFC 8446 §4/§5.1（握手序列/record 头）；既有例 `tls-handshake-basic`（tshark 校准过的 16 帧口径）
**目标：** `[ip,tcp,tls,http]` 链产完整序列（16 帧），TCP 握手/TLS 握手类型序/应用数据/挥手全部到位。

**输入：** `{"layers":[{"ip":{"src":"10.0.0.1","dst":"20.0.0.1"}},{"tcp":{"src_port":12345,"dst_port":443}},{"tls":{}},{"http":{}}]}`（`tls:{}` 空层走默认 1.3/client；严格层链形，顶层零扁平键）。
**前置条件：** 服务器二进制与 HEAD 同代；翻转已提交（`main.go` 走 ChainPlanner）。
**执行：** `CASE_PROTO=tls go test -run TestProtocolPcapDrive ./test/protocol_pcap/ -v`（真实流程：MCP 建任务→引擎生成→tshark 校对）。
**期望输出：** 16 包（3 握手 + 7 TLS 握手 + 2 应用数据 + 4 挥手；链化后应用数据恒由内层 http 委托，legacy 128B 合成/17 帧/close_notify 口径已过期）；包 4 `tls.handshake.type=1`（ClientHello）、`tls.record.content_type=22`；包 5 type=2、包 6 type=8、包 7 type=11、包 8 type=15、包 9/10 type=20；f11 frame offset 59 起 `GET / HTTP/1.1`（record len 53=0x35），f12 offset 59 起 `HTTP/1.1 200 OK`（record len 38=0x26）。包号/字节以落盘 pcap（tshark）校准钉死，不手算。
**错误期望：** 无。
**性能期望：** 回归 ±10%（翻转前 baseline wall 实测后回填 D-TLS-1 §6）。
**实现位置：** `cases/tls.json`（tls-handshake-basic 改写）。

### T-TLS-2 tls.json——SNI/ALPN 进 ClientHello 扩展【D-TLS-1 §1】

**状态：** 已执行（P5，2026-09-14：绿）
**级别：** pcap
**来源：** D-TLS-1 §1（sni string 缺省空=不发扩展；alpn list 缺省空→生成器默认 [h2,http/1.1]，`layer_gen.go:97-101`）；RFC 8446 §4（扩展块）；`t13_tls_test.go:398`（sni/alpn 进扩展的既有断言）
**目标：** 层 config 写 sni/alpn 时字节真实进入 ClientHello 扩展块（tshark `tls.handshake.extensions_server_name` / `tls.handshake.extensions_alpn_str`）。

**输入：** 同链形 + `tls{"sni":"example.com","alpn":["h2","http/1.1"]}`。
**前置条件：** T-TLS-1 绿。
**执行：** 同 T-TLS-1。
**期望输出：** 包 4 `tls.handshake.extensions_server_name=example.com`；包 4 `tls.handshake.extensions_alpn_str` 含 `h2,http/1.1`（ClientHello 双协议）；包 6 EncryptedExtensions ALPN 取首元素 `h2`（`layer_gen.go:110` buildEncryptedExtensions(alpn[0])）。SNI 扩展 wire 形按 RFC 6066 §3：ServerNameList=list_len(2)+ServerName[name_type(1)+name_len(2)+name]，example.com 的 ext len=16（type 0；2026-09-14 修过缺 list_len 的真 bug，planner.go:789-799）。包号以落盘 pcap 校准。
**错误期望：** 无。
**性能期望：** 不适用。
**实现位置：** `cases/tls.json`（tls-sni-alpn）。

### T-TLS-3 tls.json——顶层扁平五键判死负例【D-TLS-1 §5】

**状态：** 已执行（P5，2026-09-14：绿）
**级别：** pcap（Validate-negative：真实流程拒绝）
**来源：** Step1 CheckProtoFlat（`strategy_convert.go:7593` 全协议分支，tls 与全体协议同口径；单测 `TestProtoFlat_*` 家族已覆，本例钉 tls 真实流程落点。锚词 `no longer accepts flat config field`）
**目标：** tls 策略带顶层 `src_ip/dst_ip/src_port/dst_port/count` 任一建任务即 400。

**输入：** `{"layers":[...],"src_ip":"10.0.0.1"}`（层链+顶层旧键混用形状）。
**前置条件：** 无。
**执行：** 同 T-TLS-1（`expect_error` 路径：MCP 调用即拒）。
**期望输出：** 任务失败；错误含 `no longer accepts flat config field src_ip`。
**错误期望：** 即本条（`expect_error` + `error_contains`）。
**性能期望：** 不适用。
**实现位置：** `cases/tls.json`（tls_neg_flat）。

### T-TLS-4 tls.json——层链静态复制拒绝负例【D-TLS-1 §5】

**状态：** 已执行（P5，2026-09-14：绿）
**级别：** pcap（Validate-negative：真实流程拒绝）
**来源：** D-FTP-3 §5（`checkLayerChainStaticCopy`，`semantic.go:169`：层链显式标量四元组+无对象+flows>1 → 拒绝；逃生口=四元组侧写动态对象，http T-HTTP-60 tcp list 先例）
**目标：** flows=2 + 全静态标量四元组建任务即被拒（两流同四元组的静态复制反模式执法）。

**输入：** 同链形（tcp.src_port 标量 12345）+ `strategy_fc{flows 2}`。
**前置条件：** 无。
**执行：** 同 T-TLS-3。
**期望输出：** 任务失败；错误含 `static four-tuple`（`layers pin a static four-tuple but flows > 1`）。
**错误期望：** 即本条（`expect_error` + `error_contains`）。
**性能期望：** 不适用。
**实现位置：** `cases/tls.json`（tls_neg_static_copy）。

### T-TLS-5 tls.json——业务 sni list 轮转【D-TLS-1 §4】

**状态：** 已执行（P5，2026-09-14：绿）
**级别：** pcap
**来源：** D-TLS-1 §4（sni 开 string 面 fixed/list/pattern；序号算法与四元组同域 `ResolveStringValue(i)`，`tuple_generator.go:306`；生产真相=层 config 原生通道（标量）+ spec.TLS 通道（动态解析值，D-TLS-1 步骤 2），生成器 drive 期读 `layerCfg`（`translate.go:505`）+ legacy 兜底分支读 spec.TLS（`planner.go:389`）
**目标：** flows=2 时两流 ClientHello 的 SNI 分别为 a.com、b.com（业务动态真随流序号变化；四元组同 i 对齐证据=tcp list 端口与 SNI 一一对应）。

**输入：** 同链形 + `tcp.src_port{strategy list,list["41001","41002"]}`（static-copy 门逃逸口）+ `tls{"sni":{"strategy":"list","list":["a.com","b.com"]}}` + `strategy_fc{flows 2}`。
**前置条件：** T-TLS-2 绿。
**执行：** 同 T-TLS-1。
**期望输出：** 两流各 16 帧（多流交织总数 32，落盘实测）；流 1 ClientHello 在 f4（srcport 41001→SNI a.com）、流 2 ClientHello 在 f20（srcport 41002→SNI b.com）（distinct 聚合断言，f4/f20 以落盘 pcap 校准；交织故固定包位无意义）。
**错误期望：** 无。
**性能期望：** 不适用。
**实现位置：** `cases/tls.json`（tls_dyn_sni_list）。

### T-TLS-6 tls.json——业务 sni pattern 对照【D-TLS-1 §4】

**状态：** 已执行（P5，2026-09-14：绿）
**级别：** pcap
**来源：** D-TLS-1 §4（sni 开 pattern 面；`genStringValue` 的 `{n}` 替换与四元组 pattern 同算法，`shard_router.go:58` 单真相）
**目标：** pattern `host{n}.com`、range[1,2]、flows=2 时两流 SNI 为 host1.com、host2.com。

**输入：** 同 T-TLS-5 形状（tcp list["41002","41003"]）+ `tls{"sni":{"strategy":"pattern","pattern":"host{n}.com","range":[1,2]}}` + `strategy_fc{flows 2}`。
**前置条件：** T-TLS-5 绿。
**执行：** 同 T-TLS-1。
**期望输出：** 流 1 ClientHello 在 f4（srcport 41002→host1.com）、流 2 ClientHello 在 f20（srcport 41003→host2.com）（distinct 聚合，f4/f20 以落盘 pcap 校准）。
**错误期望：** 无。
**性能期望：** 不适用。
**实现位置：** `cases/tls.json`（tls_dyn_sni_pattern）。

### T-TLS-7 sni string 面 rand 拒绝（裁定表 F 同款）【D-TLS-1 §4】

**状态：** 已执行（P5，2026-09-14：单测锁定，suite 未设 rand 例）
**级别：** unit
**来源：** D-TLS-1 §4（sni 开 string 面 fixed/list/pattern；inc/rand 无意义——`genStringValue` 的 rand 分支产整数串（`shard_router.go:87-97`），域名要的是字符串表/模板，形状层拒绝；`layer_dyn.go:169-170` 锚词 `not supported for string field`，http 裁定表 F 同款）
**目标：** `tls{"sni":{"strategy":"rand",…}}` 在形状层即被拒，不进生成器。

**输入：** `CheckLayerDynShape("tls","sni",{"strategy":"rand","range":["a","b"]})`（单测直调；tls.json 不设 rand 用例——拒绝发生在 create 期形状门，T-TLS-8 同款负例口径）。
**前置条件：** 无。
**执行：** `go test ./internal/core/ -run TestTLSSNIDyn_StringSurfaceRejected`。
**期望输出：** 返回非空拒绝串，含 `not supported for string field`。
**错误期望：** 即本条（形状拒绝）。
**性能期望：** 不适用。
**实现位置：** `internal/core/tls_dyn_lock_test.go:42`（`TestTLSSNIDyn_StringSurfaceRejected`，inc/rand 双例）。

### T-TLS-8 tls.json——关闭字段 alpn/version/role 动态被拒负例【D-TLS-1 §4】

**状态：** 已执行（P5，2026-09-14：绿）
**级别：** pcap（Validate-negative：真实流程拒绝）
**来源：** D-TLS-1 §4（version/role 关——常量协商：链只实现 1.3/client，逐流变无意义。`checkLayerDynObjects` allowlist 门 `validate_layers.go:116` 报 `does not support dynamic`）
**目标：** `version{strategy list,…}` 或 `role{strategy …}` 建任务即被拒。

**输入：** 同链形 + `tls{"version":{"strategy":"list","list":["tls1.3","tls1.2"]}}`。
**前置条件：** 无。
**执行：** 同 T-TLS-3。
**期望输出：** 任务失败；错误含 `does not support dynamic`。
**错误期望：** 即本条（`expect_error` + `error_contains`）。
**性能期望：** 不适用。
**实现位置：** `cases/tls.json`（tls_neg_dyn_closed_version）。

### T-TLS-9 tls.json——https 套娃（tls+http 内层委托）【D-TLS-1 §3】

**状态：** 已执行（P5，2026-09-14：绿）
**级别：** pcap
**来源：** D-TLS-1 §3（内层委托：终结层事件经 tls 包成 ApplicationData record，方向保留；`layer_gen.go:130-173` 变换契约 + 16385 分片）；`t13_tls_test.go:218`（record 在 TCP payload 的既有断言）
**目标：** `[ip,tcp,tls,http]` 链产 TLS 握手 + 内层 http 请求/响应字节包进 ApplicationData record（tshark `tls.record.content_type=23` 且 record 内明文含 GET/HTTP 行）。

**输入：** `{"layers":[{"ip":{"src":"10.0.0.1","dst":"20.0.0.1"}},{"tcp":{"src_port":40000,"dst_port":443}},{"tls":{}},{"http":{"method":"GET","uri":"/tls-inner","version":"1.1"}}]}`。
**前置条件：** T-TLS-1 绿。
**执行：** 同 T-TLS-1。
**期望输出：** 16 帧（3 握手 + 7 TLS 握手 + 2 应用数据 + 4 挥手）；f11 frame offset 59 起 `GET /tls-inner`（record len 62=0x3e），f12 明文含 `HTTP/1.1 200`（frames hex 断言，包号/字节以落盘 pcap 校准）。
**错误期望：** 无。
**性能期望：** 不适用。
**实现位置：** `cases/tls.json`（tls_http_inner）。

### T-TLS-10 tls.json——cert 静态全填【D-TLS-2 §1】

**状态：** 已执行（P5，2026-09-14：绿，15/15）
**级别：** pcap
**来源：** D-TLS-2 §1（cert 5 键：subject/san/key_type/not_before/not_after；RFC 5280 X.509 v3 结构；探针实证 2026-09-14：真 DER tshark 干净解出、BER 伪影消失）
**目标：** 层 config 写完整 cert 块时，Certificate 帧（f7）携带可解析 X.509 DER，tshark 逐字段解出用户配置值（CN/O/C/SAN/有效期/序列号）。

**输入：** 同 T-TLS-1 链形 + `tls{"cert":{"subject":"CN=api.test.local,O=TestOrg,OU=QA,L=Beijing,ST=Beijing,C=CN","san":["api.test.local","www.test.local"],"key_type":"ecdsa-p256","not_before":"2026-01-01T00:00:00Z","not_after":"2036-01-01T00:00:00Z"}}`。
**前置条件：** T-TLS-1 绿。
**执行：** 同 T-TLS-1。
**期望输出：** 16 帧；f7 无 malformed 标记（白名单删除后 suite 仍绿的直接证据）；tshark x509 字段断言（字段名以落盘 pcap 实测定，候选：`x509af.rdnSequence`/`x509ce.dNSName`/`x509af.validity.notBefore` 等，不手猜）；序列号=SHA-256 派生（单测钉死算法，pcap 断言字段存在非零）。
**错误期望：** 无。
**性能期望：** 不适用。
**实现位置：** `cases/tls.json`（tls_cert_static）。

### T-TLS-11 tls.json——cert 缺席全默认（"缺省给全"执法）【D-TLS-2 §1】

**状态：** 已执行（P5，2026-09-14：绿——tls-handshake-basic 隐式覆盖，f7 默认 DER 无 malformed）
**级别：** pcap
**来源：** D-TLS-2 §1（用户裁定"缺省的时候数据也要给全"：cert 块缺席或单键缺席一律填完整默认值——CN=trafficgen-test,O=TrafficGen Test Lab,C=CN / SAN=[example.com] / ecdsa-p256 / 2026-01-01→2036-01-01，不报缺参错、不回退随机模板）
**目标：** `tls:{}` 空层（无 cert）的 Certificate 帧同样携带完整默认 DER——5 字段全部非零上 wire。

**输入：** 同 T-TLS-1 链形（`tls:{}`）。
**前置条件：** T-TLS-10 绿。
**执行：** 同 T-TLS-1。
**期望输出：** 16 帧；f7 无 malformed；tshark 解出默认 CN=trafficgen-test、O=TrafficGen Test Lab、SAN=example.com（字段断言以落盘 pcap 定）。
**错误期望：** 无。
**性能期望：** 不适用。
**实现位置：** `cases/tls.json`（tls_cert_default——既有 tls-handshake-basic 隐式覆盖本条，独立例只钉 x509 字段断言）。

### T-TLS-12 tls.json——cert.subject list 轮转【D-TLS-2 §4】

**状态：** 已执行（P5，2026-09-14：绿，41011→a.test f7 / 41012→b.test f23）
**级别：** pcap
**来源：** D-TLS-2 §4（cert.subject 开 string 面 list/pattern——CN 逐流变是现网真实场景；颗粒度=整 DN 串，用户写完整 DN）
**目标：** flows=2 时两流 Certificate 的 Subject CN 分别为 a.test/b.test（DN 整串替换语义，F1 决策）。

**输入：** 同 T-TLS-5 链形（tcp list 端口逃逸口）+ `tls{"cert":{"subject":{"strategy":"list","list":["CN=a.test,O=TrafficGen Test Lab,C=CN","CN=b.test,O=TrafficGen Test Lab,C=CN"]}}}` + `strategy_fc{flows 2}`。
**前置条件：** T-TLS-10 绿。
**执行：** 同 T-TLS-1。
**期望输出：** 32 帧；两流 f7（按 srcport 分流）Subject 分别含 a.test/b.test（tshark x509 字段 distinct 聚合；f 位以落盘 pcap 校准）。
**错误期望：** 无。
**性能期望：** 不适用。
**实现位置：** `cases/tls.json`（tls_cert_dyn_subject）。

### T-TLS-13 tls.json——cert.san list 轮转【D-TLS-2 §4】

**状态：** 已执行（P5，2026-09-14：绿）
**级别：** pcap
**来源：** D-TLS-2 §4（cert.san 开 string 面——SAN 逐流变同 sni 语义；单元素 list）
**目标：** flows=2 时两流 Certificate 的 SAN 分别为 a.test/b.test。

**输入：** 同 T-TLS-12 形状 + `tls{"cert":{"san":{"strategy":"list","list":["a.test","b.test"]}}}`。
**前置条件：** T-TLS-12 绿。
**执行：** 同 T-TLS-1。
**期望输出：** 32 帧；两流 f7 SAN 分别 a.test/b.test（distinct 聚合）。
**错误期望：** 无。
**性能期望：** 不适用。
**实现位置：** `cases/tls.json`（tls_cert_dyn_san）。

### T-TLS-14 tls.json——cert 关字段 key_type 动态被拒负例【D-TLS-2 §4/§5】

**状态：** 已执行（P5，2026-09-14：绿）
**级别：** pcap（Validate-negative：真实流程拒绝）
**来源：** D-TLS-2 §4（key_type 关——密钥类型一切换证书长度/签名算法全变，包长断言全得重钉，无逐流变需求；`checkLayerDynObjects` 下钻 cert 后报 `does not support dynamic`）
**目标：** `cert{"key_type":{"strategy":…}}` 建任务即被拒。

**输入：** 同链形 + `tls{"cert":{"key_type":{"strategy":"list","list":["ecdsa-p256"]}}}`。
**前置条件：** 无。
**执行：** 同 T-TLS-3。
**期望输出：** 任务失败；错误含 `does not support dynamic`。
**错误期望：** 即本条。
**性能期望：** 不适用。
**实现位置：** `cases/tls.json`（tls_cert_neg_dyn_keytype）。

### T-TLS-15 tls.json——key_type 未知值 + 坏日期拒绝负例【D-TLS-2 §5】

**状态：** 已执行（P5，2026-09-14：绿，2 例）
**级别：** pcap（Validate-negative：真实流程拒绝）
**来源：** D-TLS-2 §5（key_type 枚举仅 ecdsa-p256，锚词 `not supported yet`；日期 RFC3339 解析失败锚词；not_after ≤ not_before 锚词）
**目标：** key_type="rsa-2048" 或 not_before="不是日期" 建任务即被拒。

**输入：** 两例：①同链形 + `tls{"cert":{"key_type":"rsa-2048"}}`；②同链形 + `tls{"cert":{"not_before":"yesterday"}}`。
**前置条件：** 无。
**执行：** 同 T-TLS-3。
**期望输出：** ①错误含 `not supported yet (only "ecdsa-p256")`；②错误含 `invalid RFC3339 timestamp`。
**错误期望：** 即本条。
**性能期望：** 不适用。
**实现位置：** `cases/tls.json`（tls_cert_neg_keytype_value + tls_cert_neg_bad_date）。

### T-GRE-1 gre.json——层链冒烟基线（内层 IPv4/UDP/DNS）【D-GRE-1 §3】

**状态：** 已执行（P5，2026-09-14：绿，4/4）
**级别：** pcap
**来源：** D-GRE-1 §3（五件套豁免：单帧隧道封装；`layer_gen.go:1` 隧道契约——内层包字节自建 + L2.GRE 写 wire + 外层 proto 47）；RFC 2784 §3（GRE 头 flags/version + ProtocolType）；既有例 gre_basic_ipv4（tshark 校准过的 offset 34/58 口径）
**目标：** `[ip,gre,ip,udp,dns]` 链产 1 帧：外层 eth+IP proto47+GRE 基头（flags 0x0000，proto 0x0800），内层完整 IPv4 包（UDP 12345→80 + DNS 查询载荷）。

**输入：** `{"layers":[{"ip":{"src":"10.0.0.1","dst":"20.0.0.1"}},{"gre":{}},{"ip":{"src":"10.0.0.1","dst":"20.0.0.1"}},{"udp":{"src_port":12345,"dst_port":80}},{"dns":{}}]}`（严格层链形，顶层零扁平键；`gre:{}` 空配置走默认 key=0/checksum=false/sequence=false；末层 dns 终结层必需——裸 [ip,gre,ip,udp] 被 V4 拒，D-GRE-1 探针修订）。
**前置条件：** 服务器二进制与 HEAD 同代；翻转已提交（`main.go` 走 ChainPlanner）。
**执行：** `CASE_PROTO=gre go test -run TestProtocolPcapDrive ./test/protocol_pcap/ -v`（真实流程：MCP 建任务→引擎生成→tshark 校对）。
**期望输出：** 1 包；包 1 `gre.flags_and_version=0x0000`、`gre.proto=0x0800`、`udp.srcport=12345`、`udp.dstport=80`；f1 frame offset 34=`00 00 08 00`（GRE 头）、offset 58=`30 39 00 50`（内层 UDP 头）。整帧长与 legacy flat 形不等价（legacy 内层 28B 裸 UDP，层链形内层 57B 含 DNS 查询——D-GRE-1 范围如实声明），offset 34/58 两处 hex 与 udp 字段保持。包号/字节以落盘 pcap（tshark）校准钉死，不手算。
**错误期望：** 无。
**性能期望：** 回归 ±10%（翻转前 baseline wall 实测后回填 D-GRE-1 §6）。
**实现位置：** `cases/gre.json`（gre_basic_ipv4 改写）。

### T-GRE-2 gre.json——顶层扁平五键判死负例【D-GRE-1 §5】

**状态：** 已执行（P5，2026-09-14：绿）
**级别：** pcap（Validate-negative：真实流程拒绝）
**来源：** Step1 CheckProtoFlat（`strategy_convert.go:7593` 全协议分支，gre 与全体协议同口径；单测 `TestProtoFlat_*` 家族已覆，本例钉 gre 真实流程落点。锚词 `no longer accepts flat config field`）
**目标：** gre 策略带顶层 `src_ip/dst_ip/src_port/dst_port/count` 任一建任务即 400。

**输入：** `{"layers":[…同 T-GRE-1…],"count":2}`（层链+顶层旧键混用形状）。
**前置条件：** 无。
**执行：** 同 T-GRE-1（`expect_error` 路径：MCP 调用即拒）。
**期望输出：** 任务失败；错误含 `no longer accepts flat config field count`。
**错误期望：** 即本条（`expect_error` + `error_contains`）。
**性能期望：** 不适用。
**实现位置：** `cases/gre.json`（gre_neg_flat）。

### T-GRE-3 gre.json——层链静态复制拒绝负例【D-GRE-1 §5】

**状态：** 已执行（P5，2026-09-14：绿）
**级别：** pcap（Validate-negative：真实流程拒绝）
**来源：** D-FTP-3 §5（`checkLayerChainStaticCopy`，`semantic.go:169`：层链显式标量四元组+无对象+flows>1 → 拒绝；tls T-TLS-4 同款代表例）
**目标：** flows=2 + 全静态标量四元组建任务即被拒（两流同四元组的静态复制反模式执法）。

**输入：** 同 T-GRE-1 链形（ip/udp 全标量）+ `strategy_fc{"type":"flows","value":2}`。
**前置条件：** 无。
**执行：** 同 T-GRE-2。
**期望输出：** 任务失败；错误含 `static four-tuple`。
**错误期望：** 即本条（`expect_error` + `error_contains`）。
**性能期望：** 不适用。
**实现位置：** `cases/gre.json`（gre_neg_static_copy）。

### T-GRE-4 gre.json——关字段 key 动态被拒负例【D-GRE-1 §12】

**状态：** 已执行（P5，2026-09-14：绿）
**级别：** pcap（Validate-negative：真实流程拒绝）
**来源：** D-GRE-1 §12（key/checksum/sequence 3 键全关——tunnel 标识/开关语义逐流变无意义；`layer_dyn.go` allowlist 无 gre 行，对象在 `checkLayerDynObjects` 即拒，锚词 `does not support dynamic`）
**目标：** `gre{"key":{"strategy":…}}` 建任务即被拒。

**输入：** 同 T-GRE-1 链形 + gre 层 `{"key":{"strategy":"list","list":[100]}}`。
**前置条件：** 无。
**执行：** 同 T-GRE-2。
**期望输出：** 任务失败；错误含 `does not support dynamic`。
**错误期望：** 即本条。
**性能期望：** 不适用。
**实现位置：** `cases/gre.json`（gre_neg_dyn_key）。

### T-GRE-5 gre.json——v6-in-v6 纯 v6 隧道【D-GRE-2 §4】

**状态：** 已执行（P5，2026-09-15：绿，14/14）
**级别：** pcap
**来源：** D-GRE-2 §4（v6 外 v6 里矩阵格；RFC 2473；现状=结构段同步拒，探针 B）；D-GRE-2 §3（生成器族分派→buildInnerIPv6Packet+proto 0x86DD）
**目标：** `[ip(v6),gre,ip(v6),udp,dns]` 链产 1 帧：外层 IPv6（EtherType 0x86DD，next header 47）+ GRE proto 0x86dd + 内层完整 IPv6/UDP/DNS。

**输入：** `{"layers":[{"ip":{"src":"fd00::1","dst":"fd00::2"}},{"gre":{}},{"ip":{"src":"fd00::1","dst":"fd00::2"}},{"udp":{"src_port":12345,"dst_port":80}},{"dns":{}}]}`。
**前置条件：** T-GRE-1 绿；D-GRE-2 实现合入。
**执行：** 同 T-GRE-1。
**期望输出：** 1 包；`gre.proto=0x86dd`、`gre.flags_and_version=0x0000`、外层 `eth.type=0x86dd`、内层 `ipv6.version=6`、`udp.srcport=12345/udp.dstport=80`；内层 UDP 校验和非零（v6 UDP 不许零校验和，RFC 6936）。字段名/字节以落盘 pcap（tshark）校准。
**错误期望：** 无。
**性能期望：** 不适用。
**实现位置：** `cases/gre.json`（gre_v6_in_v6）。

### T-GRE-6 gre.json——v4 外 v6 里（6in4 异构）【D-GRE-2 §4】

**状态：** 已执行（P5，2026-09-15：绿，14/14）
**级别：** pcap
**来源：** D-GRE-2 §4（现状=静默覆盖 bug，探针 A：内层 v6 被换 v4 出包无告警）；RFC 2473
**目标：** 外层 v4、内层 ip 层显式写 v6：出包内层必须是用户写的 v6 地址（不被外层顶掉），GRE proto 0x86dd。

**输入：** 外层 `ip{"src":"10.0.0.1","dst":"20.0.0.1"}` + 内层 `ip{"src":"fd00::1","dst":"fd00::2"}`，余同 T-GRE-5。
**前置条件：** 同 T-GRE-5。
**执行：** 同 T-GRE-1。
**期望输出：** 1 包；外层 `ip.version=4`（10.0.0.1→20.0.0.1）；`gre.proto=0x86dd`；内层源=fd00::1、目的=fd00::2（`ipv6.src/ipv6.dst`）；断言内层字节含 fd00 前缀（frames hex，落盘校准）。
**错误期望：** 无。
**性能期望：** 不适用。
**实现位置：** `cases/gre.json`（gre_6in4）。

### T-GRE-7 gre.json——v6 外 v4 里（4in6 异构）【D-GRE-2 §4】

**状态：** 已执行（P5，2026-09-15：绿，14/14）
**级别：** pcap
**来源：** D-GRE-2 §4（外层 v6 现状被结构段拒）；现网 4in6 过渡常态
**目标：** 外层 v6、内层显式 v4：外层 EtherType 0x86DD + next header 47，内层 IPv4，GRE proto 0x0800。

**输入：** 外层 `ip{"src":"fd00::1","dst":"fd00::2"}` + 内层 `ip{"src":"10.0.0.1","dst":"20.0.0.1"}`，余同 T-GRE-1。
**前置条件：** 同 T-GRE-5。
**执行：** 同 T-GRE-1。
**期望输出：** 1 包；`eth.type=0x86dd`、`gre.proto=0x0800`、内层 `ip.src=10.0.0.1/ip.dst=20.0.0.1`。
**错误期望：** 无。
**性能期望：** 不适用。
**实现位置：** `cases/gre.json`（gre_4in6）。

### T-GRE-8 gre.json——sequence 多帧递增【D-GRE-2 §4】

**状态：** 已执行（P5，2026-09-15：绿，14/14）
**级别：** pcap
**来源：** D-GRE-2 §4（内层 TCP 链矩阵格；RFC 2890 §3.2 S 位+逐帧递增；链生成器 sequenceNum++ 既有，无例）
**目标：** `[ip,gre,ip,tcp,http]` + `gre{"sequence":true}` 产 9 帧，每帧 GRE 带序号 0→8，S 位（flags 0x1000）。

**输入：** `{"layers":[{"ip":{"src":"10.0.0.1","dst":"20.0.0.1"}},{"gre":{"sequence":true}},{"ip":{"src":"10.0.0.1","dst":"20.0.0.1"}},{"tcp":{"src_port":12345,"dst_port":80}},{"http":{}}]}`。
**前置条件：** 同 T-GRE-5。
**执行：** 同 T-GRE-1。
**期望输出：** 9 包（3 握手+2 数据+4 挥手，全 GRE 封装）；`gre.flags_and_version=0x1000`；首帧序号 0、末帧序号 8（`gre.sequence` 字段名以落盘 pcap 校准，逐帧 distinct 断言）。
**错误期望：** 无。
**性能期望：** 不适用。
**实现位置：** `cases/gre.json`（gre_sequence_multi）。

### T-GRE-9 gre.json——checksum C 位【D-GRE-2 §4】

**状态：** 已执行（P5，2026-09-15：绿，14/14）
**级别：** pcap
**来源：** RFC 2784 §3.1（可选校验和，C 位）；D-GRE-2 §4（K/C/S 单键矩阵格）
**目标：** `gre{"checksum":true}` 置 C 位（flags 0x8000）+ 4B 校验和且值正确。

**输入：** 同 T-GRE-1 链形 + `gre{"checksum":true}`。
**前置条件：** 同 T-GRE-5。
**执行：** 同 T-GRE-1。
**期望输出：** 1 包；`gre.flags_and_version=0x8000`；校验和字段存在且非零（值以落盘 pcap 校准，tshark 可复算）。
**错误期望：** 无。
**性能期望：** 不适用。
**实现位置：** `cases/gre.json`（gre_checksum）。

### T-GRE-10 gre.json——key K 位与值【D-GRE-2 §4】

**状态：** 已执行（P5，2026-09-15：绿，14/14）
**级别：** pcap
**来源：** RFC 2890 §3.1（K 位+4B Key）；D-GRE-2 §4
**目标：** `gre{"key":305419896}`（0x12345678）置 K 位且 Key 值上 wire。

**输入：** 同 T-GRE-1 链形 + `gre{"key":305419896}`。
**前置条件：** 同 T-GRE-5。
**执行：** 同 T-GRE-1。
**期望输出：** 1 包；`gre.flags_and_version=0x2000`；`gre.key=0x12345678`（字段名落盘校准；frames hex 断言 offset 38 起 4B `12 34 56 78`）。
**错误期望：** 无。
**性能期望：** 不适用。
**实现位置：** `cases/gre.json`（gre_key）。

### T-GRE-11 gre.json——K+C+S 三键组合【D-GRE-2 §4】

**状态：** 已执行（P5，2026-09-15：绿，14/14）
**级别：** pcap
**来源：** RFC 2890（三位组合头 16B：4 基+4 校验+4 键+4 序号）；D-GRE-2 §4
**目标：** 三键全开：flags 0xB000，GRE 头 16 字节，四可选域全上 wire。

**输入：** 同 T-GRE-1 链形 + `gre{"key":305419896,"checksum":true,"sequence":true}`。
**前置条件：** 同 T-GRE-5。
**执行：** 同 T-GRE-1。
**期望输出：** 1 包；`gre.flags_and_version=0xb000`；帧长=95+12（三可选域；以落盘 pcap 校准）；key/checksum/sequence 字段齐（字段名落盘校准）。
**错误期望：** 无。
**性能期望：** 不适用。
**实现位置：** `cases/gre.json`（gre_kcs_combo）。

### T-GRE-12 gre.json——内层 TTL 覆盖【D-GRE-2 §1】

**状态：** 已执行（P5，2026-09-15：绿，14/14）
**级别：** pcap
**来源：** D-GRE-2 §1（flat inner_ttl→内层 ip 层 ttl；生成器改读 pkt.L3.TTL）
**目标：** 内层 `ip{"ttl":60}` 时内层包 TTL=60（外层不受影响仍 64）。

**输入：** 同 T-GRE-1 链形，内层 ip 层改 `{"src":"10.0.0.1","dst":"20.0.0.1","ttl":60}`。
**前置条件：** 同 T-GRE-5。
**执行：** 同 T-GRE-1。
**期望输出：** 1 包；内层 `ip.ttl=60`；外层 `ip.ttl=64`（两个字段独立断言）。
**错误期望：** 无。
**性能期望：** 不适用。
**实现位置：** `cases/gre.json`（gre_inner_ttl）。

### T-GRE-13 gre.json——内层 ip 动态拒绝负例【D-GRE-2 §5/§12】

**状态：** 已执行（P5，2026-09-15：绿，14/14）
**级别：** pcap（Validate-negative：真实流程拒绝）
**来源：** D-GRE-2 §12（LayerDynValues 单套 ip 值，双层动态打架——探针 C 实锤外层被内层顶掉无告警；双侧拒绝）
**目标：** 内层 ip 层 src 写动态对象建任务即被拒。

**输入：** 同 T-GRE-1 链形，内层 ip 层改 `{"src":{"strategy":"list","list":["30.0.0.1","30.0.0.2"]}}`。
**前置条件：** 无。
**执行：** 同 T-GRE-2。
**期望输出：** 任务失败；错误含 `inner ip layer does not support dynamic`。
**错误期望：** 即本条。
**性能期望：** 不适用。
**实现位置：** `cases/gre.json`（gre_neg_inner_dyn）。

### T-GRE-14 gre.json——内层混族拒绝负例【D-GRE-2 §5】

**状态：** 已执行（P5，2026-09-15：绿，14/14）
**级别：** pcap（Validate-negative：真实流程拒绝）
**来源：** D-GRE-2 §5（内层两地址必须同族——一个 IP 包不可能 v4 源 v6 目的）
**目标：** 内层 ip 层 src=v4、dst=v6 建任务即被拒。

**输入：** 同 T-GRE-1 链形，内层 ip 层改 `{"src":"10.0.0.1","dst":"fd00::2"}`。
**前置条件：** 无。
**执行：** 同 T-GRE-2。
**期望输出：** 任务失败；错误含 `must be the same IP version`。
**错误期望：** 即本条。
**性能期望：** 不适用。
**实现位置：** `cases/gre.json`（gre_neg_inner_mixed）。

### T-GRE-15 gre.json——外层 VLAN tag 正例【D-GRE-3 §4】

**状态：** 已执行（P5，2026-09-15：绿，20/20）
**级别：** pcap
**来源：** IEEE 802.1Q §3（TPID 0x8100 + TCI=`priority<<13|id`）；`builder.go:1037`（tag 编码实现已就绪）；goose.json `goose_vlan`（`vlan.id/priority` 断言先例）
**目标：** 链首 `vlan{"id":100,"priority":4}` 时外层帧 eth14 后插 4B 802.1Q：offset 12:14=`81 00`（TPID），offset 14:16=`80 64`（TCI=`4<<13|100`=0x8064）；其余偏移 +4（GRE 头 offset 38，内层 UDP offset 62）。

**输入：** `[vlan{id:100,priority:4}, ip{10.0.0.1→20.0.0.1}, gre{}, ip{192.168.1.1→192.168.1.2}, udp{12345→80}, dns{}]`（内层地址已按 D-GRE-3 分离网段）。
**前置条件：** D-GRE-3 实现合入；T-GRE-1 绿。
**执行：** 同 T-GRE-1（min_packets=1；再加 `vlan.id=100` / `vlan.priority=4` 字段断言，字段名以落盘 pcap 校准）。
**期望输出：** 1 包；frames hex：offset 12 `81 00` + offset 14 `80 64` + GRE 头 offset 38 `00 00 08 00`；帧长=95+4=99（以落盘校准）。
**错误期望：** 无。
**性能期望：** 不适用。
**实现位置：** `cases/gre.json`（gre_vlan_tagged）。

### T-GRE-16 gre.json——外层 ip 动态正例【D-GRE-3 §12】

**状态：** 已执行（P5，2026-09-15：绿，20/20）
**级别：** pcap（multiflow：`strategy_fc{"type":"flows","value":2}`）
**来源：** D-GRE-3 §12 整格（外层隧道端点逐流变开）；形状同 http `http_multiflow_dynamic_sport`（层内 strategy 对象 + flows=2 + distinct 断言）
**目标：** 外层 `ip.src{"strategy":"list","list":["10.0.0.1","10.0.0.2"]}` + flows=2 时两流外层源 distinct（`10.0.0.1` / `10.0.0.2`），内层地址恒 `192.168.1.1`（内层静态不受外层动态影响——单四元组模型下内层是常量）。

**输入：** T-GRE-1 链形（内层已分离 `192.168.1.x`），外层 ip.src 改 list 对象；顶层 `strategy_fc` flows=2。
**前置条件：** 同 T-GRE-15。
**执行：** 建任务→生成→tshark；`ip.src` distinct_values 双值断言（聚合方向以落盘为准：外层/内层同名字段 distinct 会聚合，断言值以实测回钉）。
**期望输出：** 2 流各 1 包；外层源两值互异；内层源恒 `192.168.1.1`。
**错误期望：** 无（static-copy 门放行：链含动态对象非全静态）。
**性能期望：** 不适用。
**实现位置：** `cases/gre.json`（gre_outer_ip_dynamic）。

### T-GRE-17 gre.json——内层 udp 端口动态正例【D-GRE-3 §12】

**状态：** 已执行（P5，2026-09-15：绿，20/20）
**级别：** pcap（multiflow：flows=2）
**来源：** 同 T-GRE-16（内层传输端口逐流变开）
**目标：** 内层 `udp.src_port{"strategy":"inc","range":[41000,41001]}` + flows=2 时两流内层源端口 distinct（`41000` / `41001`）。

**输入：** T-GRE-1 链形（内层地址已分离），内层 udp.src_port 改 inc 对象；`strategy_fc` flows=2。
**前置条件：** 同 T-GRE-15。
**执行：** 同 T-GRE-16（`udp.srcport` distinct 双值断言，以落盘回钉）。
**期望输出：** 2 流各 1 包；内层 UDP 源端口两值互异。
**错误期望：** 无。
**性能期望：** 不适用。
**实现位置：** `cases/gre.json`（gre_inner_udp_dynamic）。

### T-GRE-18 gre.json——内层 tcp 端口动态正例【D-GRE-3 §12】

**状态：** 已执行（P5，2026-09-15：绿，20/20）
**级别：** pcap（multiflow：flows=2）
**来源：** 同 T-GRE-16（tcp 层端口同款白名单；内层 tcp 链由 T-GRE-8 sequence_multi 形状承载）
**目标：** T-GRE-8 链形（`[ip,gre,ip,tcp,http]`）内层 `tcp.dst_port{"strategy":"list","list":[80,8080]}` + flows=2 时两流内层目的端口 distinct（`80` / `8080`）。

**输入：** T-GRE-8 链形（内外层地址已分离），内层 tcp.dst_port 改 list 对象；`strategy_fc` flows=2；min_packets=18（每流 9 帧，T-GRE-8 口径）。
**前置条件：** 同 T-GRE-15。
**执行：** 同 T-GRE-16（`tcp.dstport` distinct 双值断言，以落盘回钉）。
**期望输出：** 2 流各 9 包；内层 TCP 目的端口两值互异。
**错误期望：** 无。
**性能期望：** 不适用。
**实现位置：** `cases/gre.json`（gre_inner_tcp_dynamic）。

### T-GRE-19 gre.json——gre sequence 动态拒绝负例【D-GRE-3 §12】

**状态：** 已执行（P5，2026-09-15：绿，20/20）
**级别：** pcap（Validate-negative：真实流程拒绝）
**来源：** D-GRE-3 §12（gre 业务 3 键全关沿 D-GRE-1；sequence 代表——checksum/key 同锚词，T-GRE-4 已锁 key）
**目标：** gre 层 `{"sequence":{"strategy":"list","list":[true]}}` 建任务即被拒。

**输入：** T-GRE-1 链形 + gre 层 sequence 对象。
**前置条件：** 无。
**执行：** 同 T-GRE-2。
**期望输出：** 任务失败；错误含 `does not support dynamic`。
**错误期望：** 即本条。
**性能期望：** 不适用。
**实现位置：** `cases/gre.json`（gre_neg_dyn_sequence）。

### T-GRE-20 gre.json——dns 业务动态拒绝负例【D-GRE-3 §12】【已作废，D-DNS-1 改判，2026-09-15】

**作废说明：** D-DNS-1 起 `dns.name` 动态在直连链合法（string 面 list，T-DNS-8 13/13 绿）；隧道内层仅内层 ip 三键静态，dns.name 不在内层静态之列——原"隧道内 dns 动态拒绝"依据作废。用例 `gre_neg_dyn_dns` 已删，替换为 `gre_neg_dyn_checksum`（T-GRE-22）。本编号保留作废注记，不复用。

**原状态：** 已执行（P5，2026-09-15：绿，20/20）
**级别：** pcap（Validate-negative：真实流程拒绝）
**来源：** D-GRE-3 §12（dns 不在 allowlist——`layer_dyn.go:17` 无 dns 行，对象天然关门；gre 链下首锁）
**目标：** 内层 `dns{"name":{"strategy":"list","list":["a.com","b.com"]}}` 建任务即被拒。

**输入：** T-GRE-1 链形 + dns 层 name 对象。
**前置条件：** 无。
**执行：** 同 T-GRE-2。
**期望输出：** 任务失败；错误含 `does not support dynamic`。
**错误期望：** 即本条。
**性能期望：** 不适用。
**实现位置：** `cases/gre.json`（gre_neg_dyn_dns，已删）。

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

### T-DNS-{n} dns.json——层链冒烟基线（单查询 A 记录）【D-DNS-1 §4】

**状态：** 已执行（P5，2026-09-15：绿，13/13）
**级别：** pcap
**来源：** RFC 1035 §4.1.1（头 ID/QR/RD/QDCOUNT）；D-DNS-1 §4
**目标：** 层链形 `[ip,udp,dns{name:example.com,query_type:1}]` 单查询 1 包：`udp.dstport=53`、`dns.id=0x1234`、`dns.flags=0x0100`、`dns.qry.name=example.com`、`dns.qry.type=1`。

**输入：** 既有 dns_smoke_01 改写：顶层 `dns` 子映射删，域名进 dns 层 `name`；补 ip 层（外层地址）。
**前置条件：** D-DNS-1 实现合入。
**执行：** 真实流程（MCP 建任务→生成→tshark）。
**期望输出：** 1 包；字段同上（落盘校准回钉）。
**错误期望：** 无。
**性能期望：** 不适用。
**实现位置：** `cases/dns.json`（dns_smoke_01 改写）。

### T-DNS-{n} dns.json——顶层 dns 子映射 presence 判死负例【D-DNS-1 §5】

**状态：** 已执行（P5，2026-09-15：绿，13/13）
**级别：** pcap（Validate-negative：真实流程拒绝）
**来源：** D-DNS-1 §5（http 族 presence 先例；空 map 也死）
**目标：** `{"layers":[…],"dns":{}}` 建任务即被拒。

**输入：** T-DNS-1 链形 + 顶层 `"dns":{}` 空映射。
**前置条件：** 无。
**执行：** 同 T-GRE-2（expect_error 路径）。
**期望输出：** 任务失败；错误含 `no longer accepts a top-level dns sub-config`。
**错误期望：** 即本条。
**性能期望：** 不适用。
**实现位置：** `cases/dns.json`（dns_neg_flat）。

### T-DNS-{n} dns.json——层链静态复制拒绝负例【D-DNS-1 §5】

**状态：** 已执行（P5，2026-09-15：绿，13/13）
**级别：** pcap（Validate-negative）
**来源：** §12 静态复制禁令（框架 `checkLayerChainStaticCopy`）
**目标：** 全静态标量 + flows=2 即被拒。

**输入：** T-DNS-1 链形 + `strategy_fc{"type":"flows","value":2}`。
**前置条件：** 无。
**执行：** 同 T-DNS-2。
**期望输出：** 任务失败；错误含 `static four-tuple`。
**错误期望：** 即本条。
**性能期望：** 不适用。
**实现位置：** `cases/dns.json`（dns_neg_static_copy）。

### T-DNS-{n} dns.json——AAAA 查询正例【D-DNS-1 §9】

**状态：** 已执行（P5，2026-09-15：绿，13/13）
**级别：** pcap
**来源：** RFC 1035 §3.4.1 + RFC 3596 §2.2（AAAA RDATA）
**目标：** `dns{query_type:28}` 查询 `dns.qry.type=28`。

**输入：** T-DNS-1 链形，dns 层改 `query_type:28`。
**前置条件：** 同 T-DNS-1。
**执行：** 同 T-DNS-1。
**期望输出：** 1 包；`dns.qry.type=28`。
**错误期望：** 无。
**性能期望：** 不适用。
**实现位置：** `cases/dns.json`（dns_aaaa）。

### T-DNS-{n} dns.json——响应包正例【D-DNS-1 §9】

**状态：** 已执行（P5，2026-09-15：绿，13/13）
**级别：** pcap
**来源：** RFC 1035 §4.1.1（响应 TXID 回显 MUST）；现网问答场景
**目标：** `dns{is_response:true,response_ip:1.2.3.4}` 产 2 包（up 查询 + down 响应），响应 txid=查询 txid，响应 A 记录=1.2.3.4。

**输入：** T-DNS-1 链形 + dns 层 `is_response:true,response_ip:1.2.3.4`。
**前置条件：** 同 T-DNS-1。
**执行：** 同 T-DNS-1（min_packets=2；响应包 `dns.flags.response=1` + `dns.a=1.2.3.4`，字段名落盘校准）。
**期望输出：** 2 包；响应回显 txid。
**错误期望：** 无。
**性能期望：** 不适用。
**实现位置：** `cases/dns.json`（dns_response）。

### T-DNS-{n} dns.json——NXDOMAIN + 权威节正例【D-DNS-1 §9】

**状态：** 已执行（P5，2026-09-15：绿，13/13）
**级别：** pcap
**来源：** RFC 1035 §4.1.1（RCODE）+ §6.2.5（NXDOMAIN 负缓存权威节 SOA）
**目标：** `dns{is_response:true,response_code:3,authority:[SOA]}` 响应 rcode=3 且带权威节。

**输入：** T-DNS-1 链形 + dns 层 `is_response:true,response_code:3,authority:[{name:example.com,type:6,…SOA 字段}]`。
**前置条件：** 同 T-DNS-1。
**执行：** 同 T-DNS-5（`dns.flags.rcode=3` + authority 存在，字段名落盘校准）。
**期望输出：** 2 包；rcode=3。
**错误期望：** 无。
**性能期望：** 不适用。
**实现位置：** `cases/dns.json`（dns_nxdomain_soa）。

### T-DNS-{n} dns.json——EDNS0 正例【D-DNS-1 §9】

**状态：** 已执行（P5，2026-09-15：绿，13/13）
**级别：** pcap
**来源：** RFC 6891（OPT 伪记录，ARCOUNT=1）
**目标：** `dns{edns0_enabled:true}` 查询带附加节（ARCOUNT=1）。

**输入：** T-DNS-1 链形 + dns 层 `edns0_enabled:true`。
**前置条件：** 同 T-DNS-1。
**执行：** 同 T-DNS-1（`dns.additional.count=1` 或 OPT 存在，字段名落盘校准）。
**期望输出：** 1 包；附加节存在。
**错误期望：** 无。
**性能期望：** 不适用。
**实现位置：** `cases/dns.json`（dns_edns0）。

### T-DNS-{n} dns.json——name list 动态正例【D-DNS-1 §12】

**状态：** 已执行（P5，2026-09-15：绿，13/13）
**级别：** pcap（multiflow：flows=2）
**来源：** D-DNS-1 §12（name string 面 list；tls sni 先例）
**目标：** `dns.name{"strategy":"list","list":["a.com","b.com"]}` + flows=2 →两流查询域名 distinct。

**输入：** T-DNS-1 链形，name 改 list 对象；`strategy_fc` flows=2。
**前置条件：** 同 T-DNS-1。
**执行：** `dns.qry.name` distinct 双值断言（落盘回钉）。
**期望输出：** 2 流各 1 包；域名两值互异。
**错误期望：** 无。
**性能期望：** 不适用。
**实现位置：** `cases/dns.json`（dns_name_dynamic）。

### T-DNS-{n} dns.json——query_type inc 动态正例【D-DNS-1 §12】

**状态：** 已执行（P5，2026-09-15：绿，13/13）
**级别：** pcap（multiflow：flows=2）
**来源：** D-DNS-1 §12（query_type int 面 inc）
**目标：** `dns.query_type{"strategy":"inc","range":[1,28],"step":27}` + flows=2 →两流类型 distinct（1/28）。

**输入：** T-DNS-1 链形，query_type 改 inc 对象；`strategy_fc` flows=2。
**前置条件：** 同 T-DNS-1。
**执行：** `dns.qry.type` distinct 双值断言（落盘回钉）。
**期望输出：** 2 流各 1 包；类型 1/28 互异。
**错误期望：** 无。
**性能期望：** 不适用。
**实现位置：** `cases/dns.json`（dns_qtype_dynamic）。

### T-DNS-{n} dns.json——txid inc 动态正例【D-DNS-1 §12】

**状态：** 已执行（P5，2026-09-15：绿，13/13）
**级别：** pcap（multiflow：flows=2）
**来源：** RFC 1035 §4.1.1（TxID 发包方自选）；D-DNS-1 §12（txid int 面）
**目标：** `dns.txid{"strategy":"inc","range":[1000,1001]}` + flows=2 →两流 txid distinct。

**输入：** T-DNS-1 链形，txid 改 inc 对象；`strategy_fc` flows=2。
**前置条件：** 同 T-DNS-1。
**执行：** `dns.id` distinct 双值断言（落盘回钉）。
**期望输出：** 2 流各 1 包；txid 两值互异。
**错误期望：** 无。
**性能期望：** 不适用。
**实现位置：** `cases/dns.json`（dns_txid_dynamic）。

### T-DNS-{n} dns.json——TCP 载体拒绝负例【D-DNS-1 §5】

**状态：** 已执行（P5，2026-09-15：绿，13/13）
**级别：** pcap（Validate-negative）
**来源：** RFC 7766（TCP 载体）；链上实现分叉（TCPGenerator 全握手 vs legacy 无握手）——明确不支持
**目标：** `dns{transport:"tcp"}` 建任务即被拒。

**输入：** T-DNS-1 链形 + dns 层 `transport:"tcp"`（载体保持 udp 层，值走 dns 层字段）。
**前置条件：** 无。
**执行：** 同 T-DNS-2。
**期望输出：** 任务失败；错误含 `tcp transport not supported`。
**错误期望：** 即本条。
**性能期望：** 不适用。
**实现位置：** `cases/dns.json`（dns_neg_tcp）。

### T-DNS-{n} dns.json——rcode 越界拒绝负例【D-DNS-1 §5】

**状态：** 已执行（P5，2026-09-15：绿，13/13）
**级别：** pcap（Validate-negative）
**来源：** RFC 1035 §4.1.1（RCODE 4 位）；`dns.go` validateDNSConfig
**目标：** `dns{response_code:16}` 即被拒。

**输入：** T-DNS-1 链形 + dns 层 `response_code:16`。
**前置条件：** 无。
**执行：** 同 T-DNS-2。
**期望输出：** 任务失败；错误含 `exceeds the 4-bit field`。
**错误期望：** 即本条。
**性能期望：** 不适用。
**实现位置：** `cases/dns.json`（dns_neg_rcode）。

### T-DNS-{n} dns.json——空域名拒绝负例【D-DNS-1 §5】

**状态：** 已执行（P5，2026-09-15：绿，13/13）
**级别：** pcap（Validate-negative）
**来源：** `dns.go` validateDNSConfig（空 QNAME 非法）
**目标：** `dns{name:""}` 即被拒。

**输入：** T-DNS-1 链形 + dns 层 `name:""`。
**前置条件：** 无。
**执行：** 同 T-DNS-2。
**期望输出：** 任务失败；错误含 `query_name (domain) is required`。
**错误期望：** 即本条。
**性能期望：** 不适用。
**实现位置：** `cases/dns.json`（dns_neg_empty_name）。

### T-GRE-21 gre.json——外层 ip rand 动态正例【D-DNS-1 范围⑥：GRE 备注②关闭】

**状态：** 已执行（P5，2026-09-15：绿，21/21）
**级别：** pcap（multiflow：flows=2）
**来源：** §12 rand 同 seed 可复现（框架 `resolveLayerTuple`；ipv6_dyn_test 单测已锁语义）；GRE 备注②缺口关闭
**目标：** 外层 `ip.src{"strategy":"rand","range":["10.0.0.1","10.0.0.2"],"seed":7}` + flows=2 →两流外层源 distinct（seed 固定可复现）。

**输入：** T-GRE-16 链形，src 改 rand 对象（seed=7）；`strategy_fc` flows=2。
**前置条件：** gre.json 20/20 基线绿。
**执行：** `ip.src` distinct 双值断言（聚合含内层值形同 T-GRE-16，落盘回钉）。
**期望输出：** 2 流各 1 包；外层源两值互异。
**错误期望：** 无。
**性能期望：** 不适用。
**实现位置：** `cases/gre.json`（gre_outer_ip_rand）。

### T-GRE-22 gre.json——checksum动态拒绝负例【D-DNS-1 §9：T-GRE-20作废替换】

**状态：** 已执行（P5，2026-09-15：绿，21/21）
**级别：** pcap（Validate-negative：真实流程拒绝）
**来源：** D-GRE-1 §12（gre业务3键全关；T-GRE-4锁key、T-GRE-19锁sequence，本例锁checksum三键齐）
**目标：** gre层 `{"checksum":{"strategy":"list","list":[true]}}` 建任务即被拒。

**输入：** T-GRE-1链形 + gre层checksum对象。
**前置条件：** 无。
**执行：** 同T-GRE-2。
**期望输出：** 任务失败；错误含 `does not support dynamic`。
**错误期望：** 即本条。
**性能期望：** 不适用。
**实现位置：** `cases/gre.json`（gre_neg_dyn_checksum）。

### T-DNS-14 dns.json——单包双问正例【D-DNS-1 补遗 §3 新规矩】

**状态：** 已执行（P5，2026-09-15：绿，15/15）
**级别：** pcap
**来源：** RFC 1035 §4.1.2（QDCOUNT 可 >1）；D-DNS-1 补遗
**目标：** `dns{questions:[{name:a.com,type:1},{name:b.com,type:28}]}` 单查询包带两问（QDCOUNT=2）。

**输入：** T-DNS-1 链形，dns 层改 questions 双问数组。
**前置条件：** D-DNS-1 已验收（字段翻译就绪，零代码改动）。
**执行：** 同 T-DNS-1（`dns.count.queries=2` + `dns.qry.name=a.com,b.com`/`dns.qry.type=1,28` 逗号聚合，落盘实测回钉）。
**期望输出：** 1 包；QDCOUNT=2。
**错误期望：** 无。
**性能期望：** 不适用。
**实现位置：** `cases/dns.json`（dns_multi_question）。

### T-DNS-15 dns.json——单包双答正例【D-DNS-1 补遗 §3 新规矩】

**状态：** 已执行（P5，2026-09-15：绿，15/15）
**级别：** pcap
**来源：** RFC 1035 §4.1.2（多 RR）；D-DNS-1 补遗
**目标：** `dns{is_response:true,answers:[{A 1.2.3.4},{A 5.6.7.8}]}` 响应包带两答（ANCOUNT=2）。

**输入：** T-DNS-1 链形 + dns 层 `is_response:true,answers` 双 A 数组。
**前置条件：** 同 T-DNS-14。
**执行：** 同 T-DNS-5（`dns.count.answers=2` + `dns.a=1.2.3.4,5.6.7.8` 逗号聚合，落盘实测回钉；包1查询包无answers计0）。
**期望输出：** 2 包（查询 + 双答响应）。
**错误期望：** 无。
**性能期望：** 不适用。
**实现位置：** `cases/dns.json`（dns_multi_answer）。

### T-DNS-16 dns.json——CNAME 链正例【D-DNS-1 补遗 §9 业务场景】

**状态：** 已执行（P5，2026-09-15：绿，19/19）
**级别：** pcap
**来源：** RFC 1035 §3.3.1（CNAME）；现网 CDN 别名链行为；D-DNS-1 补遗
**目标：** `dns{is_response:true,answers:[{CNAME www→alias},{A alias→1.2.3.4}]}` 响应包 ANCOUNT=2。

**输入：** T-DNS-1 链形 + dns 层 `is_response:true,answers` CNAME+A 数组。
**前置条件：** CNAME 编码路径（dns.go TypeCNAME）与多 RR 响应路径就绪，零代码改动。
**执行：** 同 T-DNS-5（`dns.count.answers=2` + `dns.cname=alias.example.com` + `dns.a=1.2.3.4`，落盘实测回钉）。
**期望输出：** 2 包（查询 + CNAME 链响应）。
**错误期望：** 无。
**性能期望：** 不适用。
**实现位置：** `cases/dns.json`（dns_cname_chain）。

### T-DNS-17 dns.json——超长域名拒绝负例【D-DNS-1 补遗 §9 数据场景】

**状态：** 已执行（P5，2026-09-15：绿，19/19）
**级别：** pcap + 单测（F4）
**来源：** RFC 1035 §2.3.4（全名≤255 线上字节）/§3.1（单 label≤63）；D-DNS-1 补遗
**目标：** 超长域名提交期拒绝，不产出畸形 QNAME。

**输入：** T-DNS-1 链形，dns 层 `name` 为 64 字节单 label 全域名。
**前置条件：** `validateDNSConfig` 长度门落地（dns.go）。
**执行：** MCP 提交即拒，锚词 `exceeds max 63 octets`；单测另覆全名超 253、超长 CNAME target 拒、63 字节边界放（dns_fix_test.go F4）。
**期望输出：** 任务失败（Validate-negative）。
**错误期望：** 有（锚词 `exceeds max 63 octets`）。
**性能期望：** 不适用。
**实现位置：** `cases/dns.json`（dns_neg_long_domain）+ `internal/protocol/dns/dns_fix_test.go`（F4）。

### T-DNS-18 dns.json——重传同 TxID 正例【D-DNS-1 补遗 §9 现网场景】

**状态：** 已执行（P5，2026-09-15：绿，19/19）
**级别：** pcap
**来源：** RFC 1035 §4.1.1（TxID 回显 MUST）；UDP 丢包重传同 TxID 现网语义；D-DNS-1 补遗
**目标：** 固定 `txid:1001` 时查询包与响应包 `dns.id` 同为 `0x03e9`。

**输入：** T-DNS-1 链形 + dns 层 `txid:1001,is_response:true,response_ip:1.2.3.4`。
**前置条件：** TxID 回显路径（T-DNS-5）已覆盖；零代码改动。
**执行：** 同 T-DNS-5（双包 `dns.id=0x03e9`，落盘实测回钉）。
**期望输出：** 2 包（查询 + 响应，同 TxID）。
**错误期望：** 无。
**性能期望：** 不适用。
**实现位置：** `cases/dns.json`（dns_retry_same_txid）。

### T-DNS-19 dns.json——IPv6 承载正例【D-DNS-1 补遗 §9 地址族矩阵】

**状态：** 已执行（P5，2026-09-15：绿，19/19，MCP 口径）
**级别：** pcap
**来源：** RFC 3596（AAAA）+ 地址族对称矩阵 v6 格；D-DNS-1 补遗
**目标：** v6 地址查询首包 `ipv6.version=6` + `dns.qry.type=28`。

**输入：** T-DNS-1 链形，ip 层改 `src:fd00::1,dst:fd00::2`，dns 层 `query_type:28`。
**前置条件：** 链上 EtherType 按 L3 源地址选族（builder + finalEmit）；UDP 无握手首包即断言。
**执行：** MCP 真实流程（`ipv6.version=6` 落盘实测回钉；UDP 单包直断口径，TCP 系 v6 例首包恒为握手需包 4 起不适用）。
**期望输出：** 1 包（v6 查询）。
**错误期望：** 无。
**性能期望：** 不适用。
**实现位置：** `cases/dns.json`（dns_v6_query）。
**口径注记：** 离线套件（runChainCase 经 MapToFlowSpec）v6 地址回退 v4，该例离线红、MCP 绿，以 MCP 为准（harness 表达力边界，不冒充）。

### T-DNS-20 dns.json——AAAA 响应正例【D-DNS-1 补遗 §9 问答配对】

**状态：** 已执行（P5：绿，25/25）
**级别：** pcap
**来源：** RFC 3596 §2.2（AAAA RDATA 16 字节）；D-DNS-1 补遗
**目标：** 问 AAAA、答 AAAA=2001:db8::1，问答类型配对。

**输入：** T-DNS-1 链形，dns 层 `query_type:28,is_response:true,response_ip:2001:db8::1`。
**前置条件：** A/AAAA 族校验（T-DNS-4 单测）已覆盖；零代码改动。
**执行：** 问包 `qry.type=28` + 答包 `resp.type=28` + `dns.aaaa=2001:db8::1`，落盘实测回钉。
**期望输出：** 2 包（查询 + AAAA 响应）。
**错误期望：** 无。
**性能期望：** 不适用。
**实现位置：** `cases/dns.json`（dns_aaaa_response）。

### T-DNS-21 dns.json——MX 响应正例【D-DNS-1 补遗 §9 问答配对】

**状态：** 已执行（P5：绿，25/25）
**级别：** pcap
**来源：** RFC 1035 §3.3.9（MX RDATA=preference+exchange）；D-DNS-1 补遗
**目标：** 问 MX、答 preference=10 + exchange=mail.example.com。

**输入：** T-DNS-1 链形，dns 层 `query_type:15,is_response:true,answers:[{MX preference/target}]`。
**前置条件：** MX 编码路径（dns.go TypeMX）已就绪；零代码改动。
**执行：** 问包 `qry.type=15` + 答包 `resp.type=15` + `mx.preference/mx.mail_exchange`，落盘实测回钉。
**期望输出：** 2 包（查询 + MX 响应）。
**错误期望：** 无。
**性能期望：** 不适用。
**实现位置：** `cases/dns.json`（dns_mx_response）。

### T-DNS-22 dns.json——TXT 响应正例【D-DNS-1 补遗 §9 问答配对】

**状态：** 已执行（P5：绿，25/25）
**级别：** pcap
**来源：** RFC 1035 §3.3.14（TXT character-string）；D-DNS-1 补遗
**目标：** 问 TXT、答文本 hello-world。

**输入：** T-DNS-1 链形，dns 层 `query_type:16,is_response:true,answers:[{TXT text}]`。
**前置条件：** TXT 编码路径已就绪；零代码改动。
**执行：** 问包 `qry.type=16` + 答包 `resp.type=16` + `dns.txt=hello-world`，落盘实测回钉。
**期望输出：** 2 包（查询 + TXT 响应）。
**错误期望：** 无。
**性能期望：** 不适用。
**实现位置：** `cases/dns.json`（dns_txt_response）。

### T-DNS-23 dns.json——NS 响应正例【D-DNS-1 补遗 §9 问答配对】

**状态：** 已执行（P5：绿，25/25）
**级别：** pcap
**来源：** RFC 1035 §3.3.11（NS RDATA=域名）；D-DNS-1 补遗
**目标：** 问 NS、答 ns1.example.com（授权链形状）。

**输入：** T-DNS-1 链形，dns 层 `query_type:2,is_response:true,answers:[{NS target}]`。
**前置条件：** NS 编码路径（TypeNS→encodeDomainName）已就绪；零代码改动。
**执行：** 问包 `qry.type=2` + 答包 `resp.type=2` + `dns.ns=ns1.example.com`，落盘实测回钉。
**期望输出：** 2 包（查询 + NS 响应）。
**错误期望：** 无。
**性能期望：** 不适用。
**实现位置：** `cases/dns.json`（dns_ns_response）。

### T-DNS-24 dns.json——PTR 反向正例【D-DNS-1 补遗 §9 问答配对】

**状态：** 已执行（P5：绿，25/25）
**级别：** pcap
**来源：** RFC 1035 §3.5（in-addr.arpa 反向）；D-DNS-1 补遗
**目标：** 问 PTR、答 host.example.com。

**输入：** T-DNS-1 链形，dns 层 `name:1.0.0.10.in-addr.arpa,query_type:12,is_response:true,answers:[{PTR target}]`。
**前置条件：** PTR 编码路径（TypePTR→encodeDomainName）已就绪；零代码改动。
**执行：** 问包 `qry.type=12` + 答包 `resp.type=12` + `dns.ptr.domain_name=host.example.com`，落盘实测回钉。
**期望输出：** 2 包（查询 + PTR 响应）。
**错误期望：** 无。
**性能期望：** 不适用。
**实现位置：** `cases/dns.json`（dns_ptr_response）。

### T-DNS-25 dns.json——SRV 响应正例【D-DNS-1 补遗 §9 问答配对】

**状态：** 已执行（P5：绿，25/25）
**级别：** pcap
**来源：** RFC 2782（SRV RDATA=priority/weight/port/target）；D-DNS-1 补遗
**目标：** 问 SRV、答 port=5060 + target=sip.example.com（微服务发现形状）。

**输入：** T-DNS-1 链形，dns 层 `name:_sip._tcp.example.com,query_type:33,is_response:true,answers:[{SRV 四字段}]`。
**前置条件：** SRV 编码路径（dns.go TypeSRV）已就绪；零代码改动。
**执行：** 问包 `qry.name/qry.type=33` + 答包 `resp.type=33` + `srv.port/srv.target`，落盘实测回钉。
**期望输出：** 2 包（查询 + SRV 响应）。
**错误期望：** 无。
**性能期望：** 不适用。
**实现位置：** `cases/dns.json`（dns_srv_response）。
**口径注记：** 不断言 `dns.srv.name`——该字段 tshark 取报文压缩指针末段恒为 `example.com`（线序全名正确，已逐字节核对），断言它等于全名必然红；问答配对由 `qry.name` + `resp.type` + RDATA 三元组承担。

### T-DNS-26 dns.json——v6 承载 AAAA 问答正例【D-DNS-1 补遗 §9 地址族矩阵】

**状态：** 已执行（P5：绿，29/29）
**级别：** pcap
**来源：** RFC 3596 + 地址族对称矩阵（承载 v6 × 答 v6）；D-DNS-1 补遗
**目标：** v6 承载问 AAAA、答 AAAA=2001:db8::1（T-DNS-19 只问不答，本例收口）。

**输入：** T-DNS-1 链形，ip 层改 `src:fd00::1,dst:fd00::2`，dns 层 `query_type:28,is_response:true,response_ip:2001:db8::1`。
**前置条件：** v6 承载（T-DNS-19）+ AAAA 回答（T-DNS-20）各已覆盖；零代码改动。
**执行：** 双包 `ipv6.version=6` + `dns.aaaa=2001:db8::1`，落盘实测回钉。
**期望输出：** 2 包（v6 查询 + v6 AAAA 响应）。
**错误期望：** 无。
**性能期望：** 不适用。
**实现位置：** `cases/dns.json`（dns_v6_aaaa_response）。

### T-DNS-27 dns.json——DS 响应正例【D-DNS-1 补遗 §9 问答配对】

**状态：** 已执行（P5：绿，29/29）
**级别：** pcap
**来源：** RFC 4034 §5（DS RDATA=keytag/algorithm/digest-type/digest）；D-DNS-1 补遗
**目标：** 问 DS、答 key_id=0x3039 + algorithm=8 + digest=aabbccddee。

**输入：** T-DNS-1 链形，dns 层 `query_type:43,is_response:true,answers:[{DS 四字段}]`。
**前置条件：** DS 编码路径（dns.go TypeDS）已就绪；零代码改动。
**执行：** 问包 `qry.type=43` + 答包 `resp.type=43` + `ds.key_id/ds.algorithm/ds.digest`，落盘实测回钉。
**期望输出：** 2 包（查询 + DS 响应）。
**错误期望：** 无。
**性能期望：** 不适用。
**实现位置：** `cases/dns.json`（dns_ds_response）。
**口径注记：** tshark 字段名是 `dns.ds.key_id`（十六进制 `0x3039`），不是配置键 `key_tag`。

### T-DNS-28 dns.json——DNSKEY 响应正例【D-DNS-1 补遗 §9 问答配对】

**状态：** 已执行（P5：绿，29/29）
**级别：** pcap
**来源：** RFC 4034 §2（DNSKEY RDATA=flags/protocol/algorithm/key）；D-DNS-1 补遗
**目标：** 问 DNSKEY、答 protocol=3 + algorithm=8。

**输入：** T-DNS-1 链形，dns 层 `query_type:48,is_response:true,answers:[{DNSKEY 四字段}]`。
**前置条件：** DNSKEY 编码路径（dns.go TypeDNSKEY）已就绪；零代码改动。
**执行：** 问包 `qry.type=48` + 答包 `resp.type=48` + `dnskey.protocol/algorithm`，落盘实测回钉。
**期望输出：** 2 包（查询 + DNSKEY 响应）。
**错误期望：** 无。
**性能期望：** 不适用。
**实现位置：** `cases/dns.json`（dns_dnskey_response）。
**口径注记：** 不断言 `dns.dnskey.flags`——tshark 按十六进制出 `0x0100`，改断 `protocol=3` 同等钉住 RDATA 头。

### T-DNS-29 dns.json——NAPTR 响应正例【D-DNS-1 补遗 §9 问答配对】

**状态：** 已执行（P5：绿，29/29）
**级别：** pcap
**来源：** RFC 3401 §4.1（NAPTR RDATA=order/preference/flags/service/regexp/replacement）；D-DNS-1 补遗
**目标：** 问 NAPTR、答 order=100 + preference=50 + service=sip+E2U。

**输入：** T-DNS-1 链形，dns 层 `query_type:35,is_response:true,answers:[{NAPTR 七字段}]`。
**前置条件：** NAPTR 编码路径（dns.go TypeNAPTR）已就绪；零代码改动。
**执行：** 问包 `qry.type=35` + 答包 `resp.type=35` + `naptr.order/preference/service`，落盘实测回钉。
**期望输出：** 2 包（查询 + NAPTR 响应）。
**错误期望：** 无。
**性能期望：** 不适用。
**实现位置：** `cases/dns.json`（dns_naptr_response）。

### T-MQTT-1…206 mqtt.json——存量审计 + 缺口矩阵【D-MQTT-1 P3 先行，P4/P5 已执行，业务流补遗】

**状态：** P5 已验收（2026-09-16；MCP 真实流程 206/206 全绿，同代二进制 /tmp/tg-mqtt-biz-server，pcap 落盘 /tmp/mcp-pcaps/mqtt/206 文件零孤儿）；预期空包负例落盘带 `.neg` 标记（66 例 `<id>.neg.pcap`，命名唯一真相 `pcaptest.CasePcapName`，suite/单例/离线三路同口径）
**级别：** pcap
**来源：** OASIS MQTT 3.1.1/5.0 + D-MQTT-1 §4 + 现网抓包待补
**存量去向（169 例 → 改写后 206 例）：**

| 形状 | 数量 | 去向 |
|---|---|---|
| `layers+顶层mqtt` 双轨（空 mqtt 层 + 顶层业务） | 89 | 合入：删顶层 mqtt→层内同名键，锚词/包数不变 |
| `layers+顶层mqtt+顶层tcp`（mss/rst/initial_seq 7 例：t043/t044/t052/t168/t169 + 2 扁平） | 5+2 | 合入：tcp 键（mss/rst/initial_seq）迁 `layers[tcp]` 同名键；RST 两例包数按链 4 包挥手重校准 |
| 纯 `{"mqtt"}` 扁平（含 17 sessions 例 + 54 负例） | 71 | 合入：补 `[ip,tcp,mqtt]` 链（缺 ip 层则补；mqtt 层 DependsOn tcp 连带补全）；sessions 17 例逐条拆单会话（继承值写全）；54 负例只换形状不换锚词 |
| `mqtt_over_tls`（扁平四键 + `[tcp,tls,mqtt]`） | 1 | 合入：四键迁 `layers[ip]/layers[tcp]`，目标形状见 D-MQTT-1 §1 |
| `group_id+{"mqtt"}`（t149） | 1 | 转负例：sessions 扇出形状已被 presence 门拒绝，改 expect_error（锚词 `no longer accepts a top-level mqtt sub-config`）；跨流保序任务级语义另立项 |
| 新增 v6/dyn（P4） | 4 | mqtt_v6_connect（v6 CONNECT，clientid 钉；ipv6 tshark 字段名待查，帧偏移断言降级注记）+ mqtt_dyn_client_id_list/topic_pattern/payload_list（flows=2 distinct 钉；§9④陷阱：ip 层留空防静态复制，dyn 对象即逐流有别证明） |
| 新增负例（P4，§5 缺口收口） | 8 | mqtt_neg_dup_qos0/bad_direction/unknown_prop_format/stringpair_nonul/vbi_overflow/sessions_rejected/string_nul/clientid_nul；surrogate 分支 JSON 不可达（孤立代理项无法编码），与 U+0000 同循环，注记不冒充 |
| 13 拆分例 frames 补钉（P5） | 13 | 原多流 frames/fields 只剩包数，逐例补 CONNECT(client_id，含 will/keepalive 标志位差异）+PUBLISH(topic/payload) 字节断言，全部落盘校准（4 例 CONNECT 手算错→ landed pcap 取实际值修正） |
| 业务流补遗（P5 后，§9 业务场景то薄弱项） | 3 | mqtt_biz_telemetry_subpub（遥测采集 18 包：auth+SUB 双过滤器+双 QoS1 PUBLISH+PING+正常下线）/mqtt_biz_abnormal_will_alarm（异常掉线 17 包：will+SUB+QoS2 指令+will 下发 down+无 DISCONNECT）/mqtt_biz_v5_session_full（v5 完整会话 17 包：props+SUB 双过滤器+QoS1/QoS0+PING+DISCONNECT reason）；包数离线预排后 MCP 落盘确认（alarm 例首版包数/帧号手算错→实测修正） |

**缺口矩阵（2026-09-16 P5 收口实测）：**

| 缺口 | 分类 | 计划 |
|---|---|---|
| v6/IPv6 零例（地址族矩阵空；正例 112 例全 v4） | B（需跑通 v6 链 + 落盘校准） | 已收口：mqtt_v6_connect（`[ip(v6),tcp,mqtt]` CONNECT 10 包，mqtt.clientid=v6-01 钉；ipv6.version 字段名 tshark 无回值，帧偏移断言降级注记，landed pcap 留查） |
| 业务动态零例（除 t149 的 group_id fixed 外无 strategy 对象；flows 全靠 sessions 扇出，无 strategy_fc） | B（allowlist + 翻译 + resolve，D-MQTT-1 §12） | 已收口：mqtt_dyn_client_id_list/topic_pattern/payload_list（flows=2，distinct 全绿；mqtt.msg 是 FT_BYTES，tshark 吐 hex，期望按 hex 钉） |
| 19 条 validator 分支无用例命中（DUP-QoS0/非法方向/IP 格式门×2/config nil×2/空配置/无效属性 id/未知属性格式/属性 string 三门/属性 vbi 越界×2/UTF-8 禁码点/session 包裹×3/session 端口撞/session SUBACK 码/源端口下限） | B（逐条补负例，锚词取字面子串） | 已收口 8 条链可达分支（见新增负例行）；剩余 11 条三分类注记：IP 格式门×2/config nil×2/空配置/session 包裹×3/端口撞/SUBACK/源端口下限——链上不可达（IP 来自 ip 层校验、空壳翻译保底、sessions 入口即拒），legacy 扁平路径覆盖，C 类（架构表达力边界，不冒充） |
| sessions 17 例链上拒（`one flow per chain`） | C（架构表达力边界，单流链无 N 流展开——RFC 只定一连接一会话，扇出是 legacy 批量形状） | 已收口：38 拆分单流例全绿（mqtt_neg_sessions_rejected 负例锁 `one flow per chain` 锚词） |
| 现网常用形薄弱（mqtts 1 例/will 全正常不断线对/down 3 例/认证 3 正例/keepalive=0 2 例/订阅选项各 1 例） | A（零代码，只建例 + 落盘校准） | P5 新增：异常断线 will 发布包序例、retain 新订阅即收例、down 转发例、PING 保活例 |
| 现网抓包对照（mosquitto/emqx；设计 doc 只有建议句无 pcap） | 待确认（确认方式：抓包比字节） | P5 补证据或如实注记未做 |
| S6 UNSUBSCRIBE / S8 AUTH 包 | 明确不支持（代码无 builder，只有 Type 常量 `mqtt.go:45-46`；设计 doc §1.4） | 不列缺口，D-MQTT-1 §4 已登记 |

**执行口径：** MCP 真实流程 206/206 全绿（2026-09-16，同代二进制 /tmp/tg-mqtt-biz-server，pcap 落盘 /tmp/mcp-pcaps/mqtt/206 文件零孤儿——16 个旧多会话名 24B 残留已删；frames hex 逐例落盘重钉——链挥手 4 包 vs legacy 3 包，t168 6→9、t169 8→11；门 2 三项）。
**实现位置：** `cases/mqtt.json`（203 例：165 存量改写 + 38 sessions 拆分 − 17 原扇出 + 4 v6/dyn + 8 负例 + t149 转负例）。

### T-SMTP-1… smtp.json——存量审计 + 测试点清单【D-SMTP-1 P3 先行，P4 未开工】

**状态：** P6 已验收（2026-09-17；43/43 全绿，反查 35/35；基线 25 例见 P5 落地偏差，补遗 18 例见⑨）
**级别：** pcap
**来源：** RFC 5321/5322/2045/2046/2183 + D-SMTP-1 §4 + 商业三家行为（Postfix banner/Gmail 587+530/Exchange 220 开头）
**存量去向（1 例 → 改写后初估 18–24 例）：**

| 形状 | 数量 | 去向 |
|---|---|---|
| 纯扁平（`src_ip/dst_ip/src_port/dst_port/count` + 顶层 `smtp:{}`） | 1 | 合入：`smtp-basic-session` 删 5 旧键→`[ip,tcp,smtp]` 链（`smtp:{}` 进层同名键）；锚词/包数不照抄，P5 落盘重钉 |
| legacy 单测（85 个：43 testpoints + 22 planner + 20 mime） | 85 | 不动：离线 planner 行为基线；pcap 层按本清单重建，不搬运子集充数 |

**测试点清单（规范行→用例，逐点登记）：**

| 规范行 | 用例 | 分类 |
|---|---|---|
| 默认会话（HELO/MAIL/RCPT/DATA/body/QUIT，改写存量冒烟） | T-SMTP-1 | A（改写，落盘重钉包数/字段） |
| 顶层 smtp presence 判死 | T-SMTP-2 | A（负例，新锚词 `no longer accepts a top-level smtp sub-config`） |
| EHLO 多行能力表（250-/SIZE/HELP） | T-SMTP-3 | A（`TestSMTP_1_2_2` 已有离线版，转 pcap） |
| 多 RCPT 群发（双收件人） | T-SMTP-4 | A |
| RSET 中断重来 | T-SMTP-5 | A（`TestSMTP_1_7_1` 离线版转 pcap） |
| NOOP 保活 | T-SMTP-6 | A（`TestSMTP_1_8_1` 离线版转 pcap） |
| VRFY 地址探查 | T-SMTP-7 | A（`TestSMTP_1_9_1` 离线版转 pcap） |
| EXPN 列表探查 | T-SMTP-8 | A（全仓零用例，复审 R4） |
| QUIT 中断（DATA 后直接 QUIT） | T-SMTP-9 | A（`TestSMTP_2_4_3` 离线版转 pcap） |
| Email 声明式纯文本 | T-SMTP-10 | A（`TestSMTPPlan_Email_SimpleText` 转 pcap） |
| Email multipart/alternative（文本+HTML） | T-SMTP-11 | A |
| Email 附件 base64（multipart/mixed） | T-SMTP-12 | A |
| 提交端口 587 显式通过 | T-SMTP-13 | A（validator 不强制端口，落盘钉 `tcp.dstport=587`） |
| SMTPS 端口 465 显式通过 | T-SMTP-14 | A（同上，明文链不断言 TLS 握手） |
| v6 承载冒烟（`[ip(v6),tcp,smtp]`） | T-SMTP-15 | A（mqtt_v6 先例：字段名 tshark 无回值则降级注记） |
| 现网形 banner（Postfix `$myhostname ESMTP` 形） | T-SMTP-16 | A（banner 逐字钉 `220 … ESMTP`） |
| 现网形 AUTH 登录序列（EHLO→AUTH→235） | T-SMTP-17 | A（台词序列，`TestSMTP_1_12_3` 离线版转 pcap） |
| 现网形 Gmail 587 口径（EHLO→STARTTLS→220 台词） | T-SMTP-18 | A（只到 220 台词，真升级另立项） |
| 坏 IP 拒绝（链上走框架 ip 层门） | T-SMTP-19 | A（负例，锚词 `invalid IP address: not-an-ip`；smtp validator 坏 IP 门由 legacy 扁平路径覆盖，C 类） |
| MSS<536 拒绝（tcp 层 V9 范围门） | T-SMTP-20 | A（负例，锚词 `out of range [536,65535]`；legacy planner 门由扁平路径覆盖） |
| boundary 超长/含 CRLF 拒绝 | T-SMTP-21 | A（负例，锚词 `Boundary` 字面） |
| 附件无数据拒绝 | T-SMTP-22 | A（负例，锚词 `neither Data nor DataB64`） |
| TURN 命令 | T-SMTP-23 | A（全仓零用例，复审 R4；回放台词，不断言状态机） |
| 全缺省双流放行（静态门反例：无显式标量不触发） | T-SMTP-24 | A（正例，40 包=2×20；src_port 保底+1） |
| 显式标量四元组 flows=2 拒绝 | T-SMTP-24b | A（负例，锚词 `static`；smtp 业务全关无动态逃生，与 T-024 对照） |
| 530 需认证拒绝 | T-SMTP-25 | A（台词版：回放语义不断引擎拦截，C 类边界） |
| 550 邮箱不可用 | T-SMTP-26 | A（台词版，同上） |
| 554 事务失败（超大拒收） | T-SMTP-27 | A（台词版，同上） |
| 452 存储不足 | T-SMTP-28 | A（台词版，同上） |
| 421 服务不可用 | T-SMTP-29 | A（台词版，同上） |
| 503 坏序列 | T-SMTP-30 | A（台词版，同上） |
| 535 认证失败 | T-SMTP-31 | A（台词版，真认证不做） |
| Email 纯 HTML 单体 | T-SMTP-32 | A（声明式注入，DATA/354 后自动体） |
| Email 双附件 mixed | T-SMTP-33 | A（包 13 首体块 Content-Type 整帧偏移 190 落盘钉） |
| Email 空正文 | T-SMTP-34 | A |
| Email 纯附件无正文 | T-SMTP-35 | A（包 13 附件块整帧偏移 190 落盘钉） |
| direction 下行改写 | T-SMTP-36 | A（包 7 源端口 25 + 载荷原文；tshark 不把下行包解成 req.command，§9 断言边界注记） |
| 同连接两封信 | T-SMTP-37 | A（多事务：同连接两次 DATA，28 包） |
| DATA 后无 QUIT 断线 | T-SMTP-38 | A（异常断线：SMTP 层无 QUIT，TCP 照常 FIN） |
| 三 NOOP 长保活 | T-SMTP-39 | A（同连接 3×NOOP，18 包） |
| 复合流（AUTH+RSET+两封信） | T-SMTP-40 | A（登录+两封信+RSET 一条流，36 包） |
| 现网 Gmail 形 banner | T-SMTP-41 | A（映射地板线：问候原文，真服务器对接另立项） |
| 现网 Exchange 形 banner | T-SMTP-42 | A（同上） |

**明确不列缺口：** 503/530 序列错（回放语义 C 类，脚本台词覆盖）；超时计时器（C 类，NOOP/大 body 覆盖可测部分）；STARTTLS 真升级/SMTPS 真握手（另立项）；DSN/SMTPUTF8（按需立项）；任务级跨策略动态池（D-FTP-2 同口径另立）。

**执行口径：** P5 `CASE_PROTO=smtp` 全量绿（2026-09-17 `RESULT: 43 pass, 0 fail, 0 error (of 43)`；二进制同代；门 2 四项全绿：旧键零残留 + 全量绿 + 同代 + 反查 35/35）；断言 `smtp.req.command/parameter` + `smtp.response.code` + 握手/挥手；包数落盘重钉禁手算；负例 `.neg.pcap` 口径沿 d323068。
**实现位置：** `cases/smtp.json`（43 例：1 例改写 + T-SMTP-2…24/24b 24 例 + T-SMTP-25…42 18 例）。

**P5 补遗落地偏差（2026-09-17，MCP 43/43 全绿，⑨）：** ①t036 direction 下行首版断 `smtp.req.command` 落空（tshark 不把下行载荷解成命令——下行包 7 源端口回到 25 即方向证据）→改断 `tcp.srcport=25` + 载荷原文 hex（§9 断言边界注记）；②t033/t035 首版 frames 用“载荷偏移”（136）手算→校验器口径是整帧偏移→落盘实测改 190（54 帧头 + 136 载荷）才绿（§14 禁手算的现行教训）；③离线链套件 39/43（t002/t019/t024b 三负例 MCP 层门离线未复刻 + t015 v6 离线回退 v4，同基线 4 红零新增，C 类 harness 边界以 MCP 为准）；落盘 40 文件零孤儿（3 超早拒绝无落盘系旧行为：t002/t020/t024b，mqtt 先例同款）；在库 smtp 清空（删前 strategies 176/tasks 399 → 删后 139/140，smtp 0/0，mqtt 139/140 全留，备份 /tmp/trafficgen.db.bak-smtp-p6-supplement）。

**P5 落地偏差（如实登记，2026-09-16，MCP 25/25 全绿，同代二进制 /tmp/tg-smtp-p5-server）：** ①包位首版全按 legacy 手算错→逐例落盘 tshark 重钉（Dialog 轮次各 2 包，banner 包 4 起）；②t018 STARTTLS 命令被 tshark 截断显示为 STAR（伪影）→不断该包原文，只断包序+220；③t009 QUIT 与 221 同段合并（tshark 不拆第二条命令）→不断 QUIT 字面，断 DATA/354/221 序列（离线 TestSMTP_2_4_3 钉原文）；④t019 改链上可达形（坏 dst 进 ip 层）→走框架门，smtp validator 门判链上不可达（mqtt IP 门先例）；⑤t020 走 tcp 层 V9 门（非 planner 门）；⑥t024 改名正例（全缺省双流 40 包放行）+ 增 t024b 真拒绝例（显式标量对照）；⑦t015 v6 `ipv6.version=6` 有回值（无需降级）；⑧离线链套件 4 红（t002/t019/t024b 三负例系 MCP 层门离线未复刻 + t015 v6 离线回退 v4，dns T-DNS-19 先例同款 C 类 harness 边界，以 MCP 为准）——smtp 空导入+协议集注册已补（layer_chain_suite_test.go）。

### T-POP3-1… pop3.json——存量审计 + 测试点清单【D-POP3-1 P3 先行，P4 未开工】

**状态：** P6 已验收（2026-09-17；50/50 全绿，反查 32/32；基线 37 例见 P5 落地偏差，补遗 13 例见⑥）
**级别：** pcap
**来源：** RFC 1939/2449/2595/879 + D-POP3-1 §4/§9 + 现网三家行为（Gmail `pop.gmail.com:995`/Outlook `outlook.office365.com:995`/Dovecot 默认问候）
**存量去向（2 例 → 改写后初估 34–36 例）：**

| 形状 | 数量 | 去向 |
|---|---|---|
| 纯扁平（`src_ip/dst_ip/src_port/dst_port/count` + 顶层 `pop3`） | 1（pop3_smoke_01） | 合入 T-POP3-1：删 5 旧键→`[ip,tcp,pop3]` 链（`pop3` 进层同名键；层内键名与 `POP3Config` JSON 键一致）；锚词/包数不照抄，P5 落盘重钉 |
| 混用（`layers:[tcp,tls,pop3]` + 顶层 4 旧键，无 `ip` 层） | 1（pop3_over_tls） | 合入 T-POP3-32：补 `ip` 层、删 4 旧键→`[ip,tcp,tls,pop3]`；包数不照抄，P5 落盘重钉 |
| legacy 单测（133 个：37 planner + 75 testpoints + 21 mime） | 133 | 不动：离线 planner 行为基线；pcap 层按本清单重建，不搬运子集充数 |

**测试点清单（规范行→用例，逐点登记）：**

| 规范行 | 用例 | 分类 |
|---|---|---|
| 默认会话（banner+USER+PASS+QUIT，改写存量冒烟；110 缺省不断端口） | T-POP3-1 | A（改写，落盘重钉包数/字段） |
| USER 空名跳过（空 Cmd 只发响应） | T-POP3-2 | A（转离线 `1_1_2`） |
| APOP 一条登录（banner 时间戳+摘要） | T-POP3-3 | A（转离线 `3_2_1`；摘要原文提供，planner 不主动算） |
| 空 USER 在 TRANSACTION 态照发（状态机不 enforcement） | T-POP3-4 | A（转离线 `1_1_3`；C 类注记：回放不断状态机） |
| STAT 空 maildrop（`+OK 0 0`） | T-POP3-5 | A（转离线 `1_4_1`/`4_1_1`） |
| LIST 多信（maildrop 合成 2 行体） | T-POP3-6 | A |
| LIST 越界（-ERR 台词） | T-POP3-7 | A（转离线 `1_5_4`；回放台词，锚词 `out of range` 类，C 类边界） |
| RETR maildrop 合成（headers+空行+body+点终结） | T-POP3-8 | A（转离线 `1_6_1`；MsgNum 2 空信附带空正文形态） |
| RETR 无此信（-ERR 台词） | T-POP3-9 | A（转离线 `1_6_6` 变体；回放台词，C 类边界） |
| DELE 删信（含越界 -ERR 台词） | T-POP3-10 | A（转离线 `1_7_1`/`1_7_2`） |
| TOP 合成（headers+前 N 行；N=0 仅头） | T-POP3-11 | A（转离线 `1_10_1`/`1_10_2`） |
| UIDL 多行/单行 + EmitTop 无 mailbox 拒/互斥拒 | T-POP3-12 | A（转离线 `1_11_1`/`1_11_2`；负例锚词 `but Mailbox is nil` + `mutually exclusive`） |
| RETR 点填充体（`.` 开头行补点） | T-POP3-13 | A（转离线 `3_10_3`；MIME 附件形态附带转离线 MIME 基线 21 单测） |
| USER 超长拒绝（>40） | T-POP3-14 | A（负例，锚词 `USER name length`；转离线 `USERTooLong`/`1_1_6`） |
| PASS 超长拒绝（>255，小载荷断文案） | T-POP3-15 | A（负例，锚词 `PASS password length`；mailbox 超限同口径不断全量构造） |
| 命令 CRLF 注入拒绝 | T-POP3-16 | A（负例，锚词 `contains CRLF`；转离线 `CRLFInjectionRejected`/`1_1_4`） |
| 单行响应 CRLF 拒绝（Multiline=false） | T-POP3-17 | A（负例，锚词 `Multiline=false`；转离线 `ResponseWithCRLFWithoutMultiline`） |
| UID 超长拒绝（>70） | T-POP3-18 | A（负例，锚词 `UID length`；转离线 `UIDTooLong`/`1_11_7`） |
| APOP 摘要非法拒绝（非 32 hex） | T-POP3-19 | A（负例，锚词 `APOP digest`；转离线 `APOPDigestLength`/`APOPDigestNotHex`/`1_3_2`/`1_3_3`） |
| RFC 1939 §10 官方示例序列全文抄 | T-POP3-20 | A（USER/PASS/STAT/LIST/RETR/QUIT 官方序列） |
| CAPA 扩展列表台词 | T-POP3-21 | A（台词版，转离线 `1_13_1`；RFC 2449，真协商不做） |
| STLS 台词（授权态+OK/事务态 -ERR） | T-POP3-22 | A（台词版，转离线 `1_14_1`/`2_6_1`；RFC 2595，真升级另立项） |
| AUTH 三机制台词（PLAIN/LOGIN/CRAM-MD5） | T-POP3-23 | A（台词版，转离线 `1_15_1`/`1_15_2`/`1_15_3`；真认证不做） |
| MSS<536 拒绝 | T-POP3-24 | A（负例，锚词 `out of range [536,65535]`（tcp 层 V9 门字面，smtp T-020 同款）；RFC 879） |
| 同连接多 RETR（多轮操作） | T-POP3-25 | A（§3 多事务①：同连接两次 RETR） |
| RETR 后无 QUIT 断线 | T-POP3-26 | A（§3 多事务②：POP3 层无 QUIT，TCP 照常 FIN） |
| 多 NOOP 长保活 | T-POP3-27 | A（§3 多事务③：同连接 3×NOOP，转离线 `3_15_1_NOOPx10` 缩量） |
| 现网 Gmail 形（995+recent 用户名） | T-POP3-28 | A（映射地板线：问候原文，真服务器对接另立项） |
| 现网 Outlook 形（995） | T-POP3-29 | A（映射地板线，同上） |
| 现网 Dovecot 形（问候/CAPA/QUIT） | T-POP3-30 | A（映射已亲验：问候原文+7 项能力集+退出回复） |
| 复合流（登录+STAT+RETR+DELE+QUIT 一条流） | T-POP3-31 | A（≥3 动作组合流） |
| POP3S 端口 995 显式通过（改写存量 over_tls；缺省 110 见 T-POP3-1） | T-POP3-32 | A（改写；明文不断言 TLS 握手细节，随形钉 `tcp.dstport=995`） |
| v6 承载冒烟（`[ip(v6),tcp,pop3]`） | T-POP3-33 | A（mqtt_v6/smtp_t015 先例：字段名 tshark 无回值则降级注记） |
| 坏 IP 拒绝（链上走框架 ip 层门） | T-POP3-34 | A（负例，锚词 `is not a valid IP address`；pop3 validator 坏 IP 门由 legacy 扁平路径覆盖，C 类） |
| 顶层 pop3 presence 判死 | T-POP3-35 | A（负例，新锚词 `no longer accepts a top-level pop3 sub-config`；failing 先行①） |
| 显式标量四元组 flows=2 拒绝 | T-POP3-36 | A（负例，锚词 `static`；pop3 业务全关无动态逃生，与 T-POP3-33 对照；failing 先行锁回归） |
| RETR 双附件下载（对标 smtp_t033） | T-POP3-37 | A（maildrop MIME 双附件合成；包 10 附件块整帧偏移 288 落盘钉） |
| RETR 空正文信（对标 smtp_t034） | T-POP3-38 | A（空体 size=0，包 10 状态行 `+OK 0 octets` 落盘钉） |
| RETR 纯附件无正文（对标 smtp_t035） | T-POP3-39 | A（无首体块；包 10 附件块整帧偏移 206） |
| PASS 密码错 -ERR（对标 smtp_t031） | T-POP3-40 | A（台词版，现网最常见失败，C 类边界） |
| 未知命令 -ERR（对标 smtp_t023） | T-POP3-41 | A（台词版，转离线 `3_16_1`） |
| RETR 合成无信箱拒绝 | T-POP3-42 | A（负例，锚词 `but Mailbox is nil`；与 T-012b 成对） |
| RETR 信号越界拒绝 | T-POP3-43 | A（负例，锚词 `out of range`） |
| TOP 信号越界拒绝 | T-POP3-44 | A（负例，锚词 `out of range`；与 T-043 分属不同分支） |
| 双合成互斥拒绝 | T-POP3-45 | A（负例，锚词 `mutually exclusive`） |
| 全缺省双流放行（对标 smtp_t024） | T-POP3-46 | A（正例，空会话 7 包×2=14；src_port 保底双流） |
| 未登录直接退出 | T-POP3-47 | A（转离线 `1_12_1`；AUTHORIZATION 态 QUIT） |
| LIST 单封单行（与 T-006 对称） | T-POP3-48 | A（转离线 `1_5_3`） |
| TOP 零行仅头（转离线 1_10_2） | T-POP3-49 | A |

**明确不列缺口：** 错序 -ERR（回放语义 C 类，脚本台词覆盖）；空闲 autologout 计时器（C 类，无时钟）；STLS 真升级/POP3S 真握手（另立项）；UIDL 自动生成（沿 `types.go` 注释不自动，用户原文提供）；超大 maildrop 全量构造（不断 10 万信，断上限文案变体）；任务级跨策略动态池（D-FTP-2 同口径另立）。

**执行口径：** P5 `CASE_PROTO=pop3` 全量绿（2026-09-17 `RESULT: 50 pass, 0 fail, 0 error (of 50)`；/tmp/tg-pop3-p5-server 与 HEAD 同代；门 2 四项全绿：旧键零残留 + 全量绿 + 同代 + 反查 32/32）；断言 `pop.request.command/parameter` + `pop.response.indicator/description` + 握手/挥手；包数落盘重钉禁手算；负例 `.neg.pcap` 口径沿 d323068。
**实现位置：** `cases/pop3.json`（50 例：2 例改写 + T-POP3-2…49 新建，含 T-POP3-12b）。

**P5 落地偏差（2026-09-17，MCP 37/37 全绿）：** ①POP3 短命令帧恒<80B→27 例去 `has_payload`（frame.len 代理不适用，不断摆设）；②t002 空 Cmd 包位手算错→落盘重钉（包 5 响应/包 6 QUIT）；③t024 改 tcp 层 V9 门字面（非 planner 门，smtp T-020 同款）；④t010 补 RSET（DELE 后撤销标记，转离线 3_11_1，包 9/11/13/15 落盘钉死）；⑤离线链套件 34/37（t034/t035/t036 三负例 MCP 层门离线未复刻，smtp/dns 先例同款 C 类 harness 边界，以 MCP 为准，pop3 空导入+协议集注册已补）；落盘 34 文件零孤儿（2 旧名残留已删；3 超早拒绝无落盘系旧行为：t024/t035/t036，mqtt/smtp 先例同款）；在库 pop3 清空（删前 strategies 166/tasks 323 → 删后 139/140，pop3 0/0，mqtt 140 全留，备份 /tmp/trafficgen.db.bak-pop3-p6，无跨协议引用）。

**P5 补遗落地偏差（2026-09-17，MCP 50/50 全绿，⑥）：** ①对标 SMTP 补 13 例（T-37…49：MIME 双附件/空正文/纯附件下载 + PASS -ERR/未知命令 + validator 四分支收口 + 全缺省双流 + QUIT/LIST/TOP 形状对称）；②t037/t039 首版 frames 用“载荷偏移”手算→校验器口径是整帧偏移（含 `+OK octets` 状态行）→落盘实测改 288/206（§14 禁手算的现行教训）；③t046 全缺省双流 14 包（空会话 7 包×2，src_port 保底 12345/12346）；④反查表 +6 项（26→32：双附件/PASS -ERR/三拒收口/双流）；⑤落盘 47 文件零孤儿（3 超早拒绝无落盘系旧行为：t024/t035/t036）。

### T-IMAP-1… imap.json——存量审计 + 测试点清单【D-IMAP-1 P3 先行，P4 未开工】

**状态：** P6 已验收（2026-09-17；门 1 已批→P4 4 红转绿→P5 84/84 + 反查 54/54；在库 imap 已清空，见 D-IMAP-1 §10 回填）
**级别：** pcap
**来源：** RFC 9051/2177/5161/6855/6851/7162/3501 §5.1.3/2045/2046/5322/2183/879 + D-IMAP-1 §4/§9 + 现网三家行为（Gmail `imap.gmail.com:993`/Outlook `outlook.office365.com:993`/Dovecot 默认问候）
**存量去向（1 例 → 改写后 84 例：T-1 改写 + T-2…71 + 复审补 T-72…84）：**

| 形状 | 数量 | 去向 |
|---|---|---|
| 纯扁平（`src_ip/dst_ip/src_port/dst_port/count` + 顶层 `imap`） | 1（imap_smoke_01） | 合入 T-IMAP-1：删 5 旧键→`[ip,tcp,imap]` 链（`imap` 进层同名键；层内键名与 `IMAPConfig` JSON 键一致）；tag 自动 A001…/包数不照抄，P5 落盘重钉 |
| legacy 单测（136 个：50 planner + 70 testpoints + 13 mime + 3 f2_done） | 136 | 不动：离线 planner 行为基线；pcap 层按本清单重建，不搬运子集充数 |

**测试点清单（规范行→用例，逐点登记）：**

| 规范行 | 用例 | 分类 |
|---|---|---|
| 默认会话（banner+LOGIN+LIST+LOGOUT，改写存量冒烟；143 缺省不断端口） | T-IMAP-1 | A（改写，落盘重钉包数/字段） |
| tag 显式 A001 | T-IMAP-2 | A（转离线 `1_1_1_1`） |
| tag 自动递增（空 tag→A001…） | T-IMAP-3 | A（转离线 `1_1_1_2`） |
| tag 点线数字三形（tag.42/X-Custom-1/001） | T-IMAP-4 | A（转离线 `1_1_1_3/4/5`） |
| 空 Cmd 服务端单轮（AUTH challenge `+`） | T-IMAP-5 | A（转离线 `1_1_2_4`；untagged+tagged 同轮附带） |
| 未认证态 SELECT 错序 NO 台词 | T-IMAP-6 | A（回放台词，C 类边界；PREAUTH 问候附带） |
| BYE 问候拒绝连接台词 | T-IMAP-7 | A（回放台词，C 类边界） |
| APPEND LiteralBody 上行 literal | T-IMAP-8 | A（转离线 `1_15_1`） |
| APPEND B64 / FETCH 响应占位替换 | T-IMAP-9 | A（转离线 `1_15_4`/`1_21_5`；空 literal 附带转离线 `3_19_6_*`） |
| 流水线双相位 vs 默认逐条对照 | T-IMAP-10 | A（双例；转离线 `3_19_5_1/2`） |
| CAPABILITY 任意态 | T-IMAP-11 | A（转离线 `1_2_1`） |
| NOOP 任意态 | T-IMAP-12 | A（转离线 `1_3_1`） |
| LOGOUT 任意态（附带 terminates） | T-IMAP-13 | A（转离线 `1_4_*`） |
| LOGIN 成功 | T-IMAP-14 | A（转离线 `1_7_1`；引号密码附带转离线 `1_7_3`） |
| LOGIN 失败 NO 台词 | T-IMAP-15 | A（转离线 `1_7_2`；C 类边界） |
| AUTHENTICATE PLAIN/LOGIN 双形 + 取消 `*` | T-IMAP-16 | A（转离线 `1_6_*/3_19_3_*`） |
| STARTTLS 台词（真升级另立项） | T-IMAP-17 | A（台词版） |
| ENABLE 台词（离线零覆盖） | T-IMAP-18 | A（台词版） |
| SELECT 成功（EXISTS+OK 同轮） | T-IMAP-19 | A（转离线 `1_9_1`） |
| SELECT 失败 NO 台词 | T-IMAP-20 | A（转离线 `1_9_2`；C 类边界） |
| EXAMINE 台词（离线零覆盖） | T-IMAP-21 | A（台词版） |
| CREATE 信箱 | T-IMAP-22 | A（转离线 `1_11_1`） |
| DELETE 信箱（含 INBOX 拒 NO） | T-IMAP-23 | A（转离线 `1_11_2/4`） |
| RENAME 信箱 | T-IMAP-24 | A（转离线 `1_11_3`） |
| SUBSCRIBE/UNSUBSCRIBE 台词（离线零覆盖） | T-IMAP-25 | A（台词版，双命令同例） |
| LIST 信箱列表 | T-IMAP-26 | A（转离线 `1_13_1`） |
| NAMESPACE 台词（离线零覆盖） | T-IMAP-27 | A（台词版） |
| STATUS 信箱状态 | T-IMAP-28 | A（转离线 `1_14_1`） |
| APPEND 带 flags | T-IMAP-29 | A（转离线 `1_15_2`） |
| CLOSE 已选择态 | T-IMAP-30 | A（转离线 `1_17_2`） |
| UNSELECT 已选择态 | T-IMAP-31 | A（转离线 `1_17_3`） |
| EXPUNGE 已选择态 | T-IMAP-32 | A（转离线 `1_18_1`） |
| SEARCH 非空结果 | T-IMAP-33 | A（转离线 `1_19_1`） |
| SEARCH 空结果 | T-IMAP-34 | A（转离线 `1_19_6`；空非失败，注记） |
| FETCH flags | T-IMAP-35 | A（转离线 `1_21_1`） |
| FETCH body literal 下行（占位替换+体+收尾 CRLF） | T-IMAP-36 | A（转离线 `1_21_5`） |
| STORE 加减 flag | T-IMAP-37 | A（转离线 `1_22_*`） |
| COPY 成功与失败 | T-IMAP-38 | A（转离线 `1_23_*`） |
| MOVE + UID FETCH | T-IMAP-39 | A（转离线 `1_24_1`；UID 逐字不断语义） |
| NO 失败码台词 | T-IMAP-40 | A（台词版，C 类边界） |
| 未知命令 BAD 台词 | T-IMAP-41 | A（台词版；回放不断言状态机） |
| RFC 9051 §8 官方示例会话全文抄 | T-IMAP-42 | A（§8 标题+目录已亲验，P5 逐字抄会话原文） |
| IDLE 有 push | T-IMAP-43 | A（转离线 `1_16_1`） |
| IDLE 无 push | T-IMAP-44 | A（转离线 `1_16_3`） |
| IDLE timeout close_after_idle | T-IMAP-45 | A（转离线 `3_19_2_1`） |
| IDLE timeout keep_idle | T-IMAP-46 | A（转离线 `3_19_2_2`） |
| IDLE timeout none | T-IMAP-47 | A（转离线 `3_19_2_3`） |
| CONDSTORE 尾注正例 | T-IMAP-48 | A（转离线 `3_19_9_2`；反例附带不断单独例） |
| UTF-8 开正例 | T-IMAP-49 | A（转离线 `3_19_7_1`） |
| UTF-8 关拒绝（non-ASCII 锚词） | T-IMAP-50 | A（负例，锚词 `non-ASCII`；ASCII 等价附带转离线 `3_19_7_3`） |
| FETCH MIMEBody 双附件下载（真实 README 附件，对标 smtp_t033） | T-IMAP-51 | A（simple 纯文本附带；整帧偏移落盘钉） |
| APPEND MIMEBody 上行 | T-IMAP-52 | A（自定义 boundary 附带） |
| MSS<536 拒绝 | T-IMAP-53 | A（负例，锚词 `out of range [536,65535]` tcp 层 V9 门字面，smtp T-020/pop3 T-24 同款；RFC 879） |
| 现网 Gmail 形（993 强制 SSL + Gimap ready 问候） | T-IMAP-54 | A（banner 台词地板线；问候原文 openssl 亲验列 P5） |
| 现网 Outlook 形（993 SSL/TLS） | T-IMAP-55 | A（banner 台词地板线） |
| 现网 Dovecot 形（问候/CAPABILITY） | T-IMAP-56 | A（telnet 亲验列 P5，POP3 口径同款） |
| 同连接多 FETCH | T-IMAP-57 | A（多事务①） |
| FETCH 后无 LOGOUT 断线 | T-IMAP-58 | A（多事务②：IMAP 层无 LOGOUT，TCP 照常 FIN） |
| 三 NOOP 长保活 | T-IMAP-59 | A（多事务③） |
| 复合流 A（LOGIN+SELECT+FETCH+STORE+COPY+LOGOUT 一条流） | T-IMAP-60 | A（≥3 动作；与 T-73 双例成对，§9 双组合流） |
| IMAPS 端口 993 显式通过 | T-IMAP-61 | A（明文不断言 TLS 握手细节，随形钉 `tcp.dstport=993`） |
| v6 承载冒烟（`[ip(v6),tcp,imap]`） | T-IMAP-62 | A（mqtt_v6/smtp_t015 先例：字段名 tshark 无回值则降级注记） |
| 坏 IP 拒绝（链上走框架 ip 层门） | T-IMAP-63 | A（负例，锚词 `is not a valid IP address`；imap validator 坏 IP 门由 legacy 扁平路径覆盖，C 类） |
| 顶层 imap presence 判死 | T-IMAP-64 | A（负例，新锚词 `no longer accepts a top-level imap sub-config`；failing 先行①） |
| 显式标量四元组 flows=2 拒绝 | T-IMAP-65 | A（负例，锚词 `static`；imap 业务全关无动态逃生；failing 先行锁回归） |
| Tag 含空格拒绝 | T-IMAP-72 | A（负例，锚词 `contains SP/CRLF`；转离线 `TestIMAPValidate_TagWithSpace`） |
| Tag 超长拒绝（>256） | T-IMAP-66 | A（负例，锚词 `Tag length`；转离线 `TestIMAPValidate_TagTooLong`） |
| 命令 CRLF 注入拒绝 | T-IMAP-67 | A（负例，锚词 `contains CRLF`；转离线 `TestIMAPValidate_CRLFInjectionRejected`） |
| 单行响应 CRLF 拒绝 | T-IMAP-73 | A（负例，锚词 `split into multiple entries`；转离线 `TestIMAPValidate_ResponseWithCRLFRejected`） |
| B64 解码错拒绝 | T-IMAP-68 | A（负例，锚词 `decode error`；转离线 `TestIMAPValidate_LiteralBodyB64Invalid`） |
| LiteralBody 与 B64 互斥拒绝 | T-IMAP-74 | A（负例，锚词 `mutually exclusive`；转离线 `TestIMAPValidate_LiteralBodyAndB64Mutex`） |
| EmitIDLE 无 IDLE 拒绝 | T-IMAP-69 | A（负例，锚词 `EmitIDLE=true but IMAPConfig.IDLE is nil`；转离线 `TestIMAPValidate_EmitIDLEWithoutIDLEConfig`） |
| CancelAfter 越界拒绝 | T-IMAP-75 | A（负例，锚词 `CancelAfterResponses`；转离线 `TestIMAPValidate_CancelAfterExceedsResponses`） |
| Push 含 CRLF 拒绝 | T-IMAP-76 | A（负例，锚词 `PushResponses[0] contains CRLF`；IDLE 块小载荷断文案） |
| Timeout 枚举错拒绝 | T-IMAP-70 | A（负例，锚词 `must be one of`；转离线 `TestIMAPValidate_ServerTimeoutBehaviorInvalid`） |
| DoneTag 含空格拒绝 | T-IMAP-77 | A（负例，锚词 `DoneTag` + `SP/CRLF`；IDLE 块小载荷断文案） |
| DoneResponse CRLF 拒绝 | T-IMAP-71 | A（负例，锚词 `DoneResponse contains CRLF`；IDLE 块小载荷断文案） |
| 全缺省双流放行（对标 smtp_t024/pop3_t046） | T-IMAP-78 | A（正例，`[{ip:{}},{tcp:{}},{imap:{}}]` 空会话 flows=2；src_port 保底+1；包数落盘钉） |
| 复合流 B（CREATE+APPEND+SEARCH+STORE+EXPUNGE+LOGOUT 一条流） | T-IMAP-79 | A（≥3 动作；与 T-60 路径不同，§9 双组合流成对） |
| FETCH MIME 空正文双附件（对标 pop3_t038 形态） | T-IMAP-80 | A（Text 空 + 双附件；整帧偏移落盘钉） |
| FETCH MIME 纯附件无正文（对标 pop3_t039/smtp_t035） | T-IMAP-81 | A（无首体块；整帧偏移落盘钉） |
| IMAPS 实链形 `[ip,tcp,tls,imap]` 993 | T-IMAP-82 | A（对标 pop3_t032；明文不断言 TLS 握手细节，随形钉 `tcp.dstport=993`） |
| MIMEBody 与 Literal 互斥拒绝 | T-IMAP-83 | A（负例，锚词 `MIMEBody is mutually exclusive`；离线零覆盖，小载荷断文案） |
| Responses 超 1 万拒绝（小载荷断上限文案） | T-IMAP-84 | A（负例，锚词 `Responses count`；离线零覆盖，不断全量构造，pop3 T-15 F1 同款） |

**明确不列缺口：** 错态 NO/BAD 台词外错序（回放语义 C 类，脚本台词覆盖）；空闲 autologout 计时器（C 类，无时钟）；STARTTLS 真升级/IMAPS 真握手（另立项）；UID 自动分配（用户原文提供）；超大 literal 全量构造（不断 100MB，断上限文案变体，pop3 T-15 F1 同款）；FileSource 链上可用（tftp 同款降级注记，真接通另立项）；任务级跨策略动态池（D-FTP-2 同口径另立）。
**实现位置：** `cases/imap.json`（P5 改写 1 例 + 新建 T-IMAP-2…84）。

**§1–§15 复审补项（2026-09-17，用户指令逐条复审）：** ①§9 双组合流缺第二条→补 T-79（与 T-60 路径不同成对）；②validator 23 分支 pcap 从 6 支补到 13 支→补 T-72/73/74/75/76/77/83（Tag SP/Response CRLF/Literal 互斥/Cancel 越界/Push CRLF/DoneTag SP/MIME 互斥；离线基线逐条回指，IDLE 三支离线零覆盖按小载荷断文案）；③大载荷三支（Responses/Push/Literal 上限）→补 T-84 一例不断全量构造（pop3 T-15 F1 同款），其余两支离线/设计注记；④缺全缺省双流→补 T-78（smtp T-24/pop3 T-46 对称）；⑤缺空正文/纯附件两格→补 T-80/81（pop3 T-38/39 对称）；⑥缺 IMAPS 实链形→补 T-82（pop3 T-32 对称）；⑦§8 先设计后代码程序倒置→门 1 批了即追认（本复审即追认评审）；⑧§10 自审查结论→P4 自审 2 轮（第 1 轮发现 4 处引用错：smtp 行号/case 数/banner 行/FlowIndex 行，已修；第 2 轮干净，见 P4 提交 1bead97）。
**P6 完成回填（2026-09-17）：** P5 `RESULT: 84 pass, 0 fail, 0 error (of 84)`（/tmp/tg-imap-p5-server 与 HEAD 同代；门 2 四项全绿；反查 54/54；smtp 43/43、pop3 50/50 无误伤）+ 落盘 81 文件零孤儿 + 在库 imap 清空（删前 strategies 63/tasks 130 → 删后 0/0，备份 `/tmp/trafficgen-pre-imap-clear.db`）+ P5 修真 bug 一件（层翻译分支 JSON 往返判死 → `ParseIMAPConfigFromMap` 单 parse 真相，failing 先行 2 红转绿，见 D-IMAP-1 §10 回填②）；门 3 抽查见 D-IMAP-1 §10 回填。T-053 锚词已按 V9 门字面更正（见上表）。

### T-MCP-1…103 mcp.json——存量审计 + 测试点清单【D-MCP-1 P3 先行，P4 未开工】

**状态：** P6 已验收（2026-09-18；P4 4 红转绿→P5 103/103 全绿 + 反查 65/65 + 门 2 四项绿，见 D-MCP-1；首跑 88/103 六类修记录在 D-MCP-1 范围（P5/P6）段）
**级别：** pcap
**来源：** JSON-RPC 2.0 + MCP spec 三版本 + `docs/protocol-designs/16-mcp-design.md`（历史参考）§2-§8 + D-MCP-1 §4/§9 + 现网（Claude Desktop/Cursor/flowB 服务端形）
**存量去向（79 例 → 改写后 103 例：T-1…79 改写 + T-80…103 新建）：**

| 形状 | 数量 | 去向 |
|---|---|---|
| `layers:[tcp,mcp]` + 顶层扁平 5 键 + 顶层 `mcp` 双轨（缺 ip 层） | 73 | 合入：补 `ip` 层、删 5 旧键→`[ip,tcp,mcp]`；`mcp` 子映射进层同名键（MCPConfig 同名 21 键）；包数/包号不照抄——链挥手 4 包 vs legacy 3 包、tpos2 无 dst_port 由 stdio 缺省 22 承接（legacy 扁平 80 是偏差，链上 22 是设计值），P5 落盘逐例重钉 |
| 纯扁平（无 layers，6 负例中 5 例 + tpos2 同形） | 6 | 合入：补 `[ip,tcp,mcp]` 链同上；负例只换形状不换锚词（validator 分支锚词原样） |
| 显式 `dst_port:8081`（78 例） | 78 | `tcp.dst_port:8081` 原样进层（M5 陷阱：丢了会被 stdio 缺省 22 顶掉变字节） |
| 无 `src_port`（t043/t044 flows=3） | 2 | `tcp` 层 src_port 留空（显式写会禁用 worker 12345+i 递增致四元组撞车，t043 notes 实录） |

**新建清单（P5 补例，编号定稿；全部 A 类零代码）：**

| 规范行 | 用例 | 分类 |
|---|---|---|
| §6 rounds 多轮（id 跨轮递增） | T-MCP-80（rounds=2，同 requests 两轮） | A |
| §4.1/§6.4 shutdown 开关（无挥手/无 DELETE） | T-MCP-81（shutdown:false，stdio，包数落盘钉） | A |
| §3.9 sampling 请求 multi-part content | T-MCP-82（messages[].content.parts） | A |
| §9 组合流 A 工具链（≥3 动作：tools/list 分页→tools/call 成功→tools/call 图片→progress 通知） | T-MCP-83 | A（双组合流①） |
| §9 组合流 B 资源链（≥3 动作：resources/list→read 文本→read blob→subscribe→updated→list_changed） | T-MCP-84 | A（双组合流②） |
| §7.15 长任务全程（working→input_required→继续→completed 一条走完） | T-MCP-85（state 全程） | A |
| §9 地址族 v6 承载 | T-MCP-86（`[ip(v6),tcp,mcp]`；mqtt_v6/smtp_t015 先例：字段名 tshark 无回值则帧偏移降级注记） | A |
| §2.5 streamable 全程（POST→JSON/SSE→DELETE/204 带内） | T-MCP-87（session_id 显式固定） | A（现网①） |
| §4.4 规则 4 auth 枚举 | T-MCP-88（非法 scheme 拒，锚词 `invalid auth scheme`） | A（负例） |
| §5.4 能力门控 sampling（未声明→-32601 台词） | T-MCP-89（t063 subscribe 门已有，本例补 sampling 对称面） | A |
| §1 顶层 mcp presence 判死 | T-MCP-90（负例，锚词 `no longer accepts a top-level mcp sub-config`；failing 先行①） | A（负例） |
| §9 全缺省双流放行（对标 smtp_t024/pop3_t046/imap_t078） | T-MCP-91（`[{ip:{}},{tcp:{}},{mcp:{}}]` flows=2；src_port 保底+1） | A |
| §9 静态复制拒绝（显式标量四元组 flows=2） | T-MCP-92（负例，锚词 `static four-tuple`） | A（负例） |
| §2.2 错误码 -32600 Invalid Request 台词 | T-MCP-93 | A（复审纠正：此前"六码全有"误判，实缺） |
| §2.2 错误码 -32603 Internal error 台词 | T-MCP-94（同上纠正） | A |
| §4.4 规则 2 transport 枚举 | T-MCP-95（`transport:"websocket"` 拒，锚词 `invalid transport`） | A（负例） |
| §4.4 规则 5 state 枚举 | T-MCP-96（`state.initial:"paused"` 拒，锚词 `invalid state.initial`；final 同枚举面同族注记） | A（负例） |
| §4.4 规则 8 负计数器 | T-MCP-97（`id_counter:-1` 拒，锚词 `must be >= 0`；rounds 同锚词族同族注记） | A（负例） |
| §4.4 规则 10 parts role 枚举 | T-MCP-98（`parts:[{role:"system"}]` 拒，锚词 `.role`；content.type 同循环同族注记） | A（负例） |
| §4.4 规则 12 通知 Step 越界 | T-MCP-99（`step:9` 越界拒，锚词 `.step=`；通知 method required 同循环同族注记） | A（负例） |
| §3.10 content audio（2025-06-18 新增） | T-MCP-100（tools/call 响应 audio content） | A |
| 现网 Claude Desktop 形 | T-MCP-101（clientInfo claude-desktop + roots/sampling caps） | A（映射地板线） |
| 现网 Cursor 形 | T-MCP-102（自定义 clientInfo + tools caps） | A（tpos4 notes cursor 字样附带） |
| 现网 flowB 服务端形 | T-MCP-103（serverInfo name=flowB + tools listChanged；16-mcp-design §1.1） | A |

**缺口矩阵（2026-09-18 P3 审计）：**

| 缺口 | 分类 | 计划 |
|---|---|---|
| rounds/shutdown/parts 请求侧/audio/错误码两码（-32600/-32603）零例 | A（零代码） | 已列 T-80/81/82/93/94/100 |
| 组合流不足（存量最长 3 步且 responses 全合成；无双条 ≥3 动作） | A | 已列 T-83/84 |
| 长任务只有四终态快照、无全程流 | A | 已列 T-85 |
| v6 零例 | A | 已列 T-86（M3 关单） |
| 现网复杂业务（streamable 全程/认证拒/能力门控 sampling/三家映射） | A | 已列 T-87/88/89/101/102/103 |
| validator 链可达 14 支仅 6 支有负例 | A | 已列 T-88/90/92/95/96/97/98/99；C 类 5 支注记（IP×2 走框架 ip 层门、config required 被翻译保底、legacy 空配置路径——链上不可达） |
| 多会话部分失败（设计 T45） | C（suite 每例单策略，flows=N 同模板复制无法逐流差异；任务级多策略另立项） | 注记不冒充 |
| JSON-RPC Batch（设计 §2.6/T81-85） | B（生成器无 batch builder；设计有、码无） | 另立项，不建例不冒充 |
| validate-only 五字段（context_id/parent_id/metadata/push_notification/parts 顶层）生成器不消费 | B（_meta 注入实现另立项；t046/47/69/70 证明 params 内联已可表达线形） | 注记，不删不冒充 |
| TLS 底座组合 `[ip,tcp,tls,mcp]` | B（M2 未验） | 另立，不登 OptionalOn |

**复审纠正记录（2026-09-18 场景审计）：** ①能力门控 subscribe 负例 t063 已有（此前"缺"误判），仅 sampling 门缺→T-89 补对称面；②错误码"六码全有"误判——-32600/-32603 实缺→T-93/94；③`_meta` 家族线形由 requests params 内联承载（t046/47/69/70），顶层五字段是 validate-only 面，属代码缺口非用例缺口。

**执行口径：** P5 已执行（2026-09-18）：MCP 真实流程全量（`flowb_run_protocol_suite`：MCP 建任务→引擎生成→tshark 校对）103/103 全绿 + 落盘 `/tmp/mcp-pcaps/mcp/` 零孤儿（89 正例 pcap + 13 `.neg` 空包标记，t090 presence create 阶段 400 无任务）+ 门 2 四项绿 + 反查 65/65 全绿（P4 探针 9/65 的 56 MISS 已由 24 新例 + 反查证据通道补齐）。
**实现位置：** `cases/mcp.json`（P5 改写 79 + 新建 24）。

### T-SRV6-1…74 srv6.json——存量审计 + 测试点清单【D-SRV6-1 P3 先行，P4 未开工；D-REWORK-1 整改：vp04 dst_mac 迁 eth 层、vn18/19 删伪配置】

**状态：** 已验收（2026-09-18；P5 提交 e041941：suite 74 pass/0 fail/0 error，落盘 pcap 零孤儿，coverage 反查 74/74，门 2 四项全绿；failing 先行 5 红例转绿见 srv6_migrate_test.go；P5 复盘锚词对真实执法门 2 处 + raw-IP 端口回退修复 1 处，详见 D-SRV6-1 状态行）
**级别：** pcap
**来源：** RFC 8754（§2/§2.1/§4.1/§4.1.1/§4.3.1.1/§8.2）+ RFC 8200（§3/§4.3/§4.4/§4.7/§8.1）+ RFC 8986（End* 命名）+ D-SRV6-1 §9 三子表 + `docs/protocol-designs/15-srv6-design.md` v2.0.2（历史参考）+ 现网 Linux seg6/厂商 SR Policy（待确认两项，见 D-SRV6-1 子表③）
**存量去向（68 例 → 改写后 74 例：67 改写 + vn01 作废 + T-69…74 新建 6+1）：**

| 存量 | 去向 | 依据 |
|---|---|---|
| tpos1…tpos21（21 正例） | 改写 `[ip,srv6]`；顶层端口删影（层内 inner 已有值 13 例）/显式迁 inner（bnd06 src_port→inner_src_port:2222）/count 删（tpos9/21 包数由 frames 承担）/tpos17 hop_by_hop→ip 层 | D-SRV6-1 §1 |
| vn02…vn17、vn20…vn24（22 负例） | 改写层链形，锚词字面不变 | 锚词=validator 字面 |
| vn18/vn19（mpls/gre 组合） | 改写，子映射顶层保留（链上静默忽略=legacy 同款，notes 已声明）；VR-16/17 锚词由 planner_test.go 覆盖=C 类 | D-SRV6-1 决策 B |
| vn01（无 srv6 config） | **作废**：VR-01 链上不可达（空层翻译保底非 nil→VR-02），与 vn02 等价覆盖 | 9.14 作废+原因；mcp C 类先例 |
| bnd01/02/04/06/10（边界 5 例） | 改写；bnd06 inner_src_port 显式迁 + 1000 帧压力锚保留 | D-SRV6-1 §6 |
| p18/vp03/vp04/vp06（4 例） | 改写（vp03=12 键全显式对照锚点；vp04 dst_mac 顶层保留） | D-SRV6-1 决策 D |
| new01…new14（12 例） | 改写（new03/04 内层端口回退/覆盖语义保字节） | 14.6 落盘重钉 |
| e2e04/mf03/mf04/mf05（多流 4 例） | 改写+ip.dst 改 fixed 策略对象（静态复制门逃生口，mcp t043/44 先例）；mf04 down 双换修复后 L3/MAC 断言落盘重钉 | 9.39；D-SRV6-1 §3 |
| exc01（1 例） | 改写 | — |

**新建用例（P5 执行，锚词=validator 字面）：**

| # | 测试点 | 形状/断言 | 类 |
|---|---|---|---|
| T-69 | VR-22：payload_protocol=none + 非空 inner_payload 拒 | validate-negative，锚词 `payload_protocol=none with non-empty inner_payload` | A |
| T-70 | reduced 显式 false（2 段，覆盖 SegType 默认反转面） | 正例，帧断言 last_entry=1+双段全列 | A |
| T-71 | TLV 保留类型 3 拒 | validate-negative，锚词 `reserved TLV type 3` | A |
| T-72 | 组合流 A：HBH 链+SRH+TLV+3 段（≥3 业务动作） | 正例，帧断言 NH 链 0→43+TLV 对齐 | A |
| T-73 | 组合流 B：down 反转+HMAC TLV+显式内层端口（≥3 业务动作） | 正例，L3 地址/List 反转/帧断言落盘钉 | A |
| T-74 | 顶层 srv6 presence 判死（failing 先行①同源） | validate-negative，锚词 `top-level srv6 sub-config` | A |
| T-75 | 静态复制拒（layers 静态 ip+flows=2） | validate-negative，锚词 `static four-tuple`（checkLayerChainStaticCopy） | A |

**测试点清单（规范行→用例，全部既有例改写后回指）：** 8754 §2 反序→tpos2/new08；§4.1 DA→tpos1；§4.1.1 reduced→tpos3/tpos20/p18/T-70；§2.1 TLV→tpos4/5/16/vn10-15/T-71；8200 §4.3 HBH→tpos17/T-72；§4.4 HdrExtLen→vn22/new07/bnd01/02/04；§4.7 none→tpos14/T-69；§8.1 伪头→tpos11；§4.3.1.1 视角→tpos7（单用例视角链=C 类注记）；8986 End*→tpos6/10/vp06/new01/01a/01b/new14/vp04/vn16（字符串合法口径=设计 §3.4）；DR 缺省链→new05/new06/vp03；DD down→tpos13/mf04/vn24/T-73；VR 全表→子表①（D-SRV6-1）；frames→tpos9/tpos21/bnd06/new09；tag→tpos15/18/19；多流→e2e04/mf03/04/05；内层端口→new03/04。
**正交矩阵：** 载荷 7×段数 8×reduced 3×TLV 6×方向 2×flows 3——已覆格见上，缺格无（地址族单族协议：v6 全量+v4 必拒 vn07，矩阵登记说明）。
**复审纠正记录（2026-09-18 P1 重审）：** ①vn22 自带 TLV→VR-20 实锚；②tpos18 tag=65535 帧断言 ffff→tag 最大无缺；③last_entry 显式 tpos7/vp03 已有；④vp03=全显式对照锚点；⑤vn18/19 不可达终审（gre/mpls 解析在 switch protocol 之内）；⑥suite spec.TTL 恒 0。
**执行口径：** P5 srv6 真实流程全量（`flowb_run_protocol_suite`：MCP 建任务→引擎生成→tshark 校对）74/74 全绿 + 落盘 `/tmp/mcp-pcaps/srv6/` 零孤儿 + 门 2 四项 + 反查 check_srv6 全绿（P4 登记）。断言包号/帧字节全部落盘重钉（down 双换修复、端口删影后 udp.srcport 以 pcap 为准）。
**实现位置：** `cases/srv6.json`（P5 改写 67 + 作废 1 + 新建 7）。

### T-FINS-1…45 fins.json——存量审计 + 测试点清单【D-FINS-1 P3 定稿，P5 已执行】

**状态：** 已验收（2026-09-18；suite 45/45 全绿，coverage 46/46，门 2 四项绿，在库 fins 行清空复核 0/0；权威=D-FINS-1 含 C1/C2/C3/**C4 缺省 ICF**。P5 修正 4 处：①T-39 锚词改 registry V9 范围门（"not a numeric value in [0,1000000]"，实测先于 planner "sessions must be >= 0"——锚词对真实执法门）；②**C4**：缺省 ICF 0x81/0xC1 违反自身 E-06（bit0=1=不需要响应），修正为 0x80/0xC0，历史 omron.icf 断言随落盘更新；③E-03 "dm does not support bit access" 由死代码转可达（dm 检查移到区码查表之前）；④0104 请求 tshark 怪癖入 malformed 白名单（设计 §3.9，帧字节经 frames 原始断言校验））

**三源：** ①标准=欧姆龙 W342-E1（FINS 无 RFC，4.10 官方规范口径；字节证据=W342 派生的 Wireshark packet-omron-fins + gofins 双转录交叉，历史 §1.5）②设计=D-FINS-1（C1 0103/0104 补齐、C2 clock 7B、C3 FINS/TCP length 26、E-06 cfg 级、E-10）③现网=开源双源行为（CX-Simulator 商业映射=待确认，确认方式：抓 CX-Simulator 报文比对或查 W342-E1 版本差异，D-FINS-1 立项①）。

**存量审计（19-fins-testcase.md T-001~T-040 → 去向，9.14 逐条）：**

| 旧号 | 去向 | 说明 |
|---|---|---|
| T-001~T-010、T-012、T-020、T-021、T-023 | 改写（12 例既有 cases + sessions_neg_area） | 顶层四元组→ip/udp/tcp 层、顶层 fins→层内；断言落盘重钉（14.6） |
| T-011 DM 字写 | 转正落盘 `fins_dm_write_word` | 0102 已实现，纯缺例 |
| T-013 Fill 0103 | 转正落盘 `fins_fill_dm` | D-FINS-1 C1 P4 实现后有效 |
| T-014 多区读 0104 | 转正落盘 `fins_multi_read` | 同上；请求断言 FrameAssert 原始字节（tshark NC 怪癖，§3.9 注） |
| T-015 ICF 方向位 | 拆分：响应 ICF=0xC1 断言=T-001 等价覆盖；显式 cfg.icf 半→`fins_icf_explicit` | 9.19 拆到不可再分 |
| T-016 SID 递增 01→02 | 转正落盘 `fins_sid_auto_incr` | 同会话双命令——兼补"多命令事务序列"缺口（门 1 重审 #5） |
| T-017 显式固定 SID | 转正落盘 `fins_sid_fixed` | `sid_auto:false` 显式可设（UnmarshalJSON 区分缺席/显式，实测 :32） |
| T-018 TCP/FINS 命令隔离 | 等价覆盖=T-002 | T-002 已同包断言 omron.tcp.command=2 与 omron.command=0101 |
| T-019 expect_response=false | 转正落盘 `fins_expect_response_false` | 1 包（仅请求） |
| T-022 多会话不同 4-tuple | 合入 T-020/T-021 改写 | sessions 派生口 1245+i 确定性——改写后加 distinct udp.srcport 断言（旧 notes"系统分配可能复用"说法纠正：端口是派生值非随机，落盘重钉） |
| T-024 结束码 0x1101 | 拆分：配置拒=T-023 已覆；响应面→`fins_down_endcode_1101`（down 带 response_end_code） | 结束码 9 值同一发包形状（值参数化），按 9.21 分支代表 1 例 + 0x0000 全例既有 |
| T-025~T-030、T-032 | 转正落盘负例 7 条 | E-04/E-06/E-02/E-03/E-05/E-07/E-09 各锚词一例 |
| T-031 响应长度缺失 | C 类注记 | E-08 配置面不可达：响应数据由生成器按 NC 自合成，长度恒一致；不冒充覆盖 |
| T-033 GCT 非法 | 转正落盘 `fins_vn_gct` | validate 已有（"invalid gct"）；历史 E 表未编号=D 表漏行，D-FINS-1 已收口 |
| T-034 DNA 非法 | 转正落盘 `fins_vn_dna` | "invalid dna"；SNA 同分支同形另立 `fins_vn_sna`（消息不同=行为点不同，9.6） |
| T-035 非 9600 端口 decode_as | C 类注记 | harness 无 decode_as 支持（grep 证实）；端口能力由 udp 层 dst_port 承担（框架职责），不冒充覆盖 |
| T-036/037 FrameAssert 头字节 | 合入改写例 frames pin | 落盘重钉，不照抄设计 offset 手算值（14.6） |
| T-038~T-040 汇总冒烟 | 等价覆盖=suite 全量口径 | suite 即冒烟，不单独建例 |

**新增测试点（规范行→用例，D-FINS-1 新面 + 枚举补口）：**

| 编号 | 名称 | 断言面 | 类 |
|---|---|---|---|
| T-25 | 结束码响应面 | down 命令 response_end_code=0x1101 → 响应帧结束码字节 11 01（wire pin 落盘钉） | A |
| T-26 | cfg 级 E-06 | cfg.icf=0x41（bit6 置位）→ "icf request direction bit must be clear" | A（D-FINS-1 E-06） |
| T-27 | E-10 read_areas 空 | 0104 无 read_areas → "read_areas" | A（组数>16 同分支同锚，9.21 代表） |
| T-28 | 0103 位口径拒 | fill+bit → "fill does not support bit access" | A |
| T-29 | 0103 填充模板 | fill dm NC=3 data=[0xAB,0xCD] → 请求尾 8 字节原始断言（02 帧） | A（C1） |
| T-30 | 0104 双组读 | dm+hr 各 1 字 → 请求原始字节 FrameAssert + 响应逐组数据（组内 uint16(i+1) BE） | A（C1） |
| T-31 | 组合流 A（TCP+多命令+SID 递增） | tcp 载体，读 DM→写 CIO→校时 3 命令，SID 01→02→03，握手+6 FINS 帧 | A（9.11 ≥3 动作） |
| T-32 | 组合流 B（UDP+双会话+全键+结束码） | sessions=2，位写+显式 icf/gct/da1/sa1 节点号+down 命令（response_end_code=0x1101）→ 两会话各出错误码响应（commands 逐会话同构，无会话级差异面——P3 重审修正） | A（9.11 ≥3 动作） |
| T-33 | tc_bit 字口径（0x09 码补口） | memory_area=tc_bit 字读 → 区码 0x09 | A（9.20 区码取值补口） |
| T-34 | wr 位读（0x31 码补口） | wr+bit → 区码 0x31 | A（9.20 补口；至此 11 个区码值全覆） |
| T-35 | 顶层 presence 判死 | 顶层 fins+layers → "top-level fins sub-config"（failing 先行①） | A |
| T-36 | 静态复制拒 | layers 静态四元组+flows=2 → 静态复制锚词 | A |
| T-37 | transport 非法 | "invalid transport" | A |
| T-38 | direction 非法 | "invalid direction" | A |
| T-39 | sessions 负值 | registry V9 范围门 "not a numeric value in [0,1000000]"（实测先于 planner 同义分支，锚词对真实执法门） | A |

**枚举取值覆盖（9.20-9.22 承载位置扫描）：** 区名×口径 11 组合（去重码值 10，0x09 位/字同码：字 0xB0/0xB1/0xB2/0x89/0x82/0xDC/0x09+位 0x30/0x31/0x32）全覆（T-033/034 补口后）；命令码 5 值（0101/0102/0103/0104/0701）正例全覆+未知码负例；结束码 9 值同形状分支代表（T-25+全例 0x0000）；ICF 方向位请求/响应双值（T-001 响应 0xC1 + 显式例）；载体 2×地址族 2（v4 全量+v6 代表——FINS 载荷与 IP 版本无关（G6），差异仅在 ip 层=框架职责，矩阵登记说明，srv6 单族声明同口径）。
**正交矩阵：** 载体 2×命令 5×位/字×sessions 3×direction 2——已覆格见上；缺格=TCP×sessions（TCP 多会话：tcp 层挥旧握新语义，B 类候选注记，P4 后评估是否落盘）；动态整格=N/A（fins 业务 16 键零动态，D-FINS-1 §12；四元组动态走框架三层 allowlist 既有格）。
**通用陷阱自查（9.37-9.40）：** 派生口 1245+i 确定性、distinct 断言排除服务端 9600 与派生口混入（T-022 断言只收客户端派生口集合）；多命令同会话共享 SID 序号=真实语义（T-31 断言递增非独立）；无 flows>1 静态标量例（T-36 拒绝面已锁）。
**断言边界（9.27）：** tshark 对 0104 请求组忽略 NC（FrameAssert 原始字节代偿）；FINS/TCP FIN/ACK 交织顺序由 TCP 载体决定（min_packets 口径）；包时序断言 harness 不支持（既有注记）。
**执行口径：** P5 fins 真实流程全量（MCP 建任务→引擎生成→tshark 校对）全绿 + 落盘 `/tmp/mcp-pcaps/fins/` + 门 2 四项 + 反查 check_fins（P4 登记）。断言数值一律落盘重钉（14.6/9.31）——含 C3 修正后的 omron.tcp.length=26、tcp min_packets 拆解不预写。
**实现位置：** `cases/fins.json`（P5 改写 14 + 转正/新建 31 = **45 例**；T-018 等价覆盖、T-031 E-08 配置面不可达 C 类、T-035 decode_as C 类、T-038~040 等价 suite 口径；P5 补 `fins_vn_fill_data_len`（0103 模板 2B 校验分支，9.5 补口））。

### T-GOOSE-1…33 goose.json——存量审计 + 测试点清单【D-GOOSE-1 P3 定稿，P6 已验收；D-REWORK-1 整改（32 例 src_mac 迁 eth 层，字节不变）】

**状态：** P6 已验收（2026-09-18；门 3 抽查三条见 D-GOOSE-1 状态行——①goose_vn_presence 真实服务拒 strategy_convert.go:7715 ②goose_vn_static_copy 拒 semantic.go:229 eth 门+layer_dyn 零 goose 行 ③goose_goid 帧 pin@109+heartbeat 落盘 sqNum 1,2,3；在库 goose tasks 570+strategies 27 清空复核 0/0）。已执行（2026-09-18；suite 33/33 全绿，coverage 反查 51/51，门 2 四项绿，fins 45/45 + srv6 74/74 零回归。**P5 复盘修正 5 处**：①**coverage 反查逮到 P3 清单漏例 3 个**——sqNum 上限（:46）/L2-only 载体门（V7b）/VLAN 越界（V9），补例 T-31/32/33（30→33 例）；②**锚词对真实执法门**（fins T-39 口径）——appid 越界改 V9 `out of range [0,16383]`（V9 范围门先于 validator 段位门）、stNum 改 validator 全字面 `stNum must not overflow`、sqNum 跳号改 `sqNum step`；③uint64 例 tshark `goose.unsigned` 是 FT_UINT32，2^32 截断为 0——删该 fields 断言，frames pin 为主证据；④**strategy_fc 必须在 case 顶层**（driver 读 case 级注入 generate_traffic 参数；放 spec_json 内 driver 不读=静态门不触发，fins 同款双写）；⑤static 例 src_mac 写 eth 层内（门查层内显式标量，顶层 src_mac 不触发⑥门）。落盘 29 正例 pcap + 11 neg，3 个 create-time 超早拒绝无落盘系旧行为（mqtt 先例同款），孤儿 pcap 3 个已清
**级别：** pcap
**来源：** ①标准=IEC 61850-8-1（4.10 官方规范口径；字节经 libiec61850 `goose_publisher.c` + Wireshark `packet-goose.c` 双转录交叉）②设计=D-GOOSE-1（⑥ static-eth 门/⑦ t0 C 类/count 层内/包数公式）③现网=libiec61850 示例行为（gocbRef/datSet 缺省串、goID 缺省=gocbRef、test/ndsCom 恒编码 `87 01 00`/`89 01 00`）
**存量去向（12 例 → P5 改写后 30 例：12 改写 + 16 新建（T-2/3 门面 + T-15…30，其中 T-1…14 为改写位号、T-2/3 与改写位不重例）：**

| 存量 | 去向 | 说明 |
|---|---|---|
| goose_heartbeat（S1 心跳 3 帧） | 改写 | 顶层 `count:3`→层内 count、`t0_ms` 删（⑦ 死键）、`goose:{}` 进层同名键；断言落盘重钉 |
| goose_retransmit（S2 退避 8 帧） | 改写 | `count:8`→层内、`t0_ms`/`tmax_ms` 删（⑦ 死键×2）、event_seq 留层内；`delay_ms` 现状死字段不断包间隔（9.27 注记） |
| goose_dataset_change（S2 变化 5 帧） | 改写 | 同上（`t0_ms`/`tmax_ms` 删）；sqNum=0 复位断言保留 |
| goose_test_flag（S3 test） | 改写 | `count:2`→层内、`t0_ms` 删 |
| goose_ndscom_flag（S3 ndsCom） | 改写 | 同上 |
| goose_vlan（S4） | 改写 | `count:2`→层内、`t0_ms` 删；vlan 三键留层内（顶层 `vlan_id` 不消费是 flat 旧口径，层内为准） |
| goose_multitype（S5 10 成员） | 改写 | `count:2`→层内、`t0_ms` 删；10 成员 hex 逐段落盘重钉（禁手算 9.31） |
| goose_multidataset（S7 6 成员） | 改写 | 同上 |
| goose_no_ip（S6） | 改写 | `count:3`→层内、`t0_ms` 删；`frame.protocols` nonzero 口径保留（环境相关不断 exact） |
| goose_neg_appid（NEG-01） | 改写 | 锚词 `appid`（substring，`goose.go:28` 全字面 `outside GOOSE range`，P5 对真实门） |
| goose_neg_sqnum（NEG-02） | 改写 | 锚词 `sqNum`（`goose.go:60`，`sqnum_step:2` 注入） |
| goose_neg_stnum（NEG-03） | 改写 | 锚词 `stNum`（`goose.go:43`，`start_stnum:0xFFFFFFFF`） |

**测试点清单（规范行→用例，逐点登记）：**

| 规范行/设计条目 | 用例 | 分类 |
|---|---|---|
| S1 静默心跳（stNum 恒 1、sqNum 递增，改写存量） | T-GOOSE-1 | A（改写，落盘重钉包数/字段/frames） |
| 顶层 goose presence 判死（空 map 也死，CheckProtoFlat） | T-GOOSE-2 | A（负例，新锚词 `top-level goose sub-config`；fins_vn_presence 同构，P4 failing 先行①） |
| 显式标量 eth MAC + flows=2 拒绝（⑥ 新门） | T-GOOSE-3 | A（负例，锚词 `static four-tuple`；fins_vn_static_copy 同构，eth 层显式 `src_mac`，P4 failing 先行④） |
| S2 快速重发退避（改写存量，retransmits=5） | T-GOOSE-4 | A（改写；首帧 stNum+1/sqNum=0 + 0..5 序列不断包间隔） |
| S2 数据集变化（改写存量，retransmits=2） | T-GOOSE-5 | A（改写；sqNum=0 复位 `86 01 00` 必断） |
| S3 test 置位（改写存量） | T-GOOSE-6 | A（改写；`87 01 01` 逐帧） |
| S3 ndsCom 置位（改写存量） | T-GOOSE-7 | A（改写；`89 01 01` 逐帧） |
| S4 VLAN（改写存量，TCI=0x8064） | T-GOOSE-8 | A（改写；TPID/TCI/EtherType 右移+4 落盘钉） |
| S5 多类型 10 成员（改写存量） | T-GOOSE-9 | A（改写；9.6 已拆到成员级，P5 只重钉 offset） |
| S7 多数据集 6 成员（改写存量） | T-GOOSE-10 | A（改写；`8a 01 06` + 成员数一致） |
| S6 无 IP 证明（改写存量） | T-GOOSE-11 | A（改写；`88 b8`@12 + `61`@22 双字节证据） |
| NEG-01 appid 越界（改写存量，0x4000） | T-GOOSE-12 | A（负例，锚词 `appid`） |
| NEG-02 sqNum 跳号（改写存量，sqnum_step=2） | T-GOOSE-13 | A（负例，锚词 `sqNum`） |
| NEG-03 stNum 回绕（改写存量，0xFFFFFFFF） | T-GOOSE-14 | A（负例，锚词 `stNum`） |
| 9.3 conf_rev=0 拒（设计 §9.3 点名 `goose_neg_confrev`，存量漏） | T-GOOSE-15 | A（负例，锚词 `conf_rev must be non-zero`；`goose.go:40`） |
| 空 data 拒（`goose.go:49`，存量漏） | T-GOOSE-16 | A（负例，锚词 `at least one allData member`；单测 `TestPlannerRejectsInvalidGOOSEConfiguration/no members` 同款行为 pcap 转正） |
| 非法 type 拒（`goose.go:53`，§3.8 矩阵外） | T-GOOSE-17 | A（负例，锚词 `unsupported data type`；type=`bogus`，单测 bad type 同款转正） |
| gocb_ref 空拒（`goose.go:31`，存量漏） | T-GOOSE-18 | A（负例，锚词 `gocb_ref and dat_set are required`；`gocb_ref:""`，单测 control block 同款转正） |
| 超长串拒（`goose.go:34`，9.8 超长格） | T-GOOSE-19 | A（负例，锚词 `exceed 255 bytes`；gocb_ref 256 字符） |
| tal_ms=0 拒（`goose.go:37`，9.8 空值/边界格） | T-GOOSE-20 | A（负例，锚词 `tal_ms must be in`） |
| go_id 显式值（§3.4 可选键，存量零覆盖） | T-GOOSE-21 | A（正例，`go_id` 显式≠gocbRef → `83` 段 hex 落盘钉；与缺省回填对照） |
| start_sqnum 非零起点（`goose.go:477`，存量零覆盖） | T-GOOSE-22 | A（正例，`start_sqnum:5` → 首帧 sqNum=5 序列 5/6/7；与 neg_sqnum 跳号门对照，正常值放行） |
| start_stnum 非零起点（`goose.go:473`，`goose_stnum_override` §10.1 立即支持已实现） | T-GOOSE-23 | A（正例，`start_stnum:10` → 首帧 stNum=10；与 0xFFFFFFFF 拒绝门对照） |
| int64 负值编码（§3.8 有符号分支，存量只有 int32） | T-GOOSE-24 | A（正例，`int64:-1` → `85 01 ff` 最小编码落盘钉；9.21 分支代表：int64 同分支） |
| uint64 大值编码（§3.8 无符号分支，存量只有 uint32） | T-GOOSE-25 | A（正例，`uint64:4294967296` → `86 05 01 00 00 00 00` 落盘钉；uint64 同分支代表） |
| octet_string（§3.8 ✓，存量零覆盖） | T-GOOSE-26 | A（正例，`octet_string:"AB"` → `89 02 41 42` 落盘钉；9.20 取值补口） |
| utc_time（§3.6 0x91，存量零覆盖） | T-GOOSE-27 | A（正例，`utc_time` → `91 08` tag+len 落盘钉，内容墙钟不断值；binary_time 存量已有，utc_time 为同表补口） |
| 组合流 A（heartbeat 鉴别面 + S3 双旗 + S4，≥3 动作，9.11） | T-GOOSE-28 | A（正例：test=true + nds_com=true + vlan_enabled 三键同帧 → `87 01 01`/`89 01 01`/TPID 同包断言；三动作同属 APDU/L2 不同字段，9.6 行为点=三旗同编不断包序） |
| 组合流 B（S2 事件 + S5 多类型 + S7 条目一致，≥3 动作，9.11） | T-GOOSE-29 | A（正例：event_seq burst + 6 成员数据集 + numDatSetEntries 一致 → stNum+1/sqNum=0 序列与 `8a 01 06` 同包断言） |
| 空层 `{goose:{}}` 保底分支（D-GOOSE-1 §1：零配置→gocb_ref 必填分支） | T-GOOSE-30 | A（负例，锚词 `gocb_ref and dat_set are required`；与 T-18 同锚不同形状=9.22 承载位置扫描：空层 vs 显式空串） |

**C 类注记（9.17，不冒充覆盖）：** ① pacing（t0 纯心跳间隔）：parse/GOOSEConfig/生成器三层全无 `t0_ms` 键，suite 无包间隔断言（9.27）→ D-GOOSE-1 ⑦，P5 删键；② `event_seq.delay_ms`/`data_idx`：parse 有键、生成器 `goose.go:532` 只读 `Retransmits`（DelayMs/DataIdx 零消费，grep 实证）→ 不断包间隔/成员切换语义，序列形状不断；③ `boolean` 顶层键：parse 有键（`strategy_convert.go:7597`）、生成器零消费（`c.Boolean` 全库零命中）→ 不建用例，P4 translate 不映射（设计 §1 已排除）；④ Length/APDU 自洽（§9.4）/条目数自洽（§9.5）：生成器自编码恒一致，配置面不可达（fins E-08 同款口径）；⑤ array/struct 0xA1/0xA2（§3.8 规划中/§10 待条件）：`isValidDataMember` 拒收 → 归入 T-17 非法 type 代表，不单独建规划中用例；⑥ 包时序/ wall-clock 内容（`t` 0x84/`binary_time`/`utc_time` 内容）：harness 不定值不断内容（既有 heartbeat `84 08` tag+len 口径）。
**枚举取值覆盖（9.20-9.22 承载位置扫描）：** 数据类型 9 ✓值（boolean/bit_string/int32/uint32/float32/octet_string/visible_string/binary_time/utc_time；int64/uint64 按 9.21 同分支代表 T-24/25；array/struct 规划中归 T-17）+ T-26/27 补口后 11 白名单类型行为全覆（9 ✓正例 + 2 代表 + 非法拒）；校验分支 13（`goose.go:24/28/31/34/37/40/43/46/49/53/60/64/67·70`，VLAN 双分支同锚 9.21 代表一例）；承载位置 2（层内键 vs 空层保底 T-30；顶层 `vlan_id` 不消费旧口径废止）。
**正交矩阵：** Static/EventSeq 2×VLAN 2×类型 11×方向 1（L2-only 无方向）——缺格=多事件 burst（EventSeq≥2：stNum+2 语义生成器支持 `goose.go:526` 循环，存量全单事件，B 类候选注记，P4 后评估是否落盘）；地址族 N/A（L2-only 无 IP，S6 即对称声明，fins v6 代表口径不适用）；动态整格=N/A（goose 业务 18 键零动态，allowlist 不加 goose 行，D-GOOSE-1 §1；eth 四元组动态走框架既有格）。
**通用陷阱自查（9.37-9.40）：** 无派生端口（L2-only 无端口）；无 distinct 聚合（sqNum/stNum 序列用 `value`/`same_as_packet`，multitype 多实例用 nonzero + frames 精确字节）；flows>1 静态标量只有 T-3 拒绝例（9.39 互斥遵守）；无共享序号动态字段。
**断言边界（9.27）：** 包间隔（DelayMs/t0）无断言面（C 类①②）；墙钟内容不断值（tag+len）；`frame.protocols` 只 nonzero（环境相关）；`goose.length`/`reserve` 随 APDU 变，P5 落盘重钉不预写。
**执行口径：** P5 goose 真实流程全量（MCP 建任务→引擎生成→tshark 校对）全绿 + 落盘 `/tmp/mcp-pcaps/goose/` + 门 2 四项 + 反查 check_goose（P4 登记）。断言数值（offset/hex/length）一律落盘重钉（14.6/9.31），不照抄存量手算值。
**实现位置：** `cases/goose.json`（**33 例**：改写 12——顶层 count→层内、删 `t0_ms`×12/`tmax_ms`×2、层内 goose 18 键；新建 T-15…30（含 T-2/3 门面）+ P5 补口 T-31/32/33；T-GSE-S1-02 并入 heartbeat Length 断言不单独建例。字节断言全部落盘复核：改写例帧布局与改写前逐字节一致（仅 spec 形状迁移）、新例预测 pin（offset 109/162/165/172/177/182）一次通过）。

### T-SV-1…30 sv.json——存量审计 + 测试点清单【D-SV-1 P3 定稿，P6 已验收；D-REWORK-1 整改（30 例 src_mac 迁 eth 层，字节不变）】

**状态：** P6 已验收（2026-09-19；门 3 抽查三条见 D-SV-1 状态行——①sv_vn_presence 真实服务拒 strategy_convert.go:7730 ②layer_dyn 零 sv 行+MAC 动态三策略实测（T-26/27/28）③sv_int32_neg 帧 pin@56+smpCnt 三证落盘复核；在库 sv tasks 314+strategies 8 清空复核 0/0）。已执行（2026-09-19；suite 30/30 全绿（RESULT 行），coverage 反查 42/42，门 2 四项绿（pipe_gate sv + 显式二进制），goose 33/fins 45/srv6 74 零回归，落盘 25（17 正+8 neg.pcap+5 create-time 无落盘）零孤儿。**P5 复盘 5 处**：①`expect.error_contains` 之外必须带 `expect_error:true`（driver 判定预期失败契约，goose 存量例皆有，P3 清单漏记——9 新负例首跑全 error）；②**worker.go:307 多流保底 × L2-only 假端口**——flows>1 时 12345+i 注入被 "Layer 2 only" 校验误伤（sv_mac_dyn_inc 实测 planning failed），⑥ 立项落地：mapToFlowSpec l2Only 恒置 HasExplicitSrcPort（红单测 TestL2OnlyHasExplicitSrcPort 先行，goose 同享）；③**genMAC 首八位 OUI 掩码语义**（0xFF0000000000 只保首八位、中间八位组清零）——mac_dyn 三例 range 按此对齐（aa:00:00:00:00:xx 形），rand seed7 落盘钉值 fb/97 可复现，list 策略逐字面不经掩码（实测全 MAC 保真）；④预测 pin 手算错 3 处（SV 长度 0x2a→0x30/0x51→0x4b、seqData offset 50→56）——9.31 再证，全部落盘重钉；⑤发现⑤再修正：float32 并非全库零覆盖（sv_custom_dataset 第二通道即 3f c0 00 00）——T-25 重新定位为"独立格专项钉值"，覆盖声明由"零覆盖补口"改为"有覆盖非独立格"）。P3 定稿（2026-09-19；存量 12 例逐条审计全改写（等价迁移，无作废无合入）+ 新建 18 例=30 例；锚词按真实执法门分级——create-time V9（appid 下界/vlan_id/static/presence/carrier 5 门无落盘）vs task-time validator（confRev/samples_per_cycle/smpSynch/svID/data/type/appid 显式 0 六门 .neg.pcap）。核心取值面：float32 通道全库零覆盖（T-25 补）、smpSynch 值 0/1 零覆盖（T-18/19 补）、dat_set 有形零覆盖（T-30 补，tag 0x81 条件编码首钉）、MAC 动态多流零覆盖（T-26/27/28 补，含 inc 回绕）。**P3"实锤断链"系假发现（P4 实读 sv.go:26 纠正）**：从 goose 单界外推"只查上界"——实为 `< 0x4000 || > 0x7fff` 双界既有执法，无断链无修；红例⑤ 转性为 V9 u==0 放行→validator 双界的回归锁，T-15/T-23 锚词与现状真门一致不变
**级别：** pcap
**来源：** ①标准=IEC 61850-9-2/-9-2LE（4.10 官方规范口径；字节经 libiec61850 `sv_publisher` + Wireshark `packet-sv.c` 双转录交叉）②设计=D-SV-1（appid V9 边界/period_us C 类/count 层内/MAC 动态多流/组合替代面）③现网=合并单元 9-2LE 4i4v 形（sv_4i4v 近似；抓现网 SV 组播包=待确认，子表③）
**存量去向（12 例 → P5 改写后 30 例）：**

| 存量 | 去向 | 说明 |
|---|---|---|
| sv_smp_seq（基线 13 fields+4 pins） | 改写 | 顶层 sv 11 键→`layers[sv]` 直迁、`count:3`→层内、`src_mac` 留顶层；`period_us` 保留（死键 C 类注记）；断言落盘重钉 |
| sv_double_send（smpCnt 0,0,1,1… fields） | 改写 | 同上（`double_send:true` 留层内）；共享 smpCnt 断言保留 |
| sv_smp_wrap（samples_per_cycle:4 回绕） | 改写 | 同上；**补回绕序列帧 pin**（smpCnt 0,1,2,3,0,1 逐帧）——存量 0 pin 缺口 |
| sv_neg_wrap（samples_per_cycle:0） | 改写 | 锚词收紧全字面 `sv samples_per_cycle must be >= 1`（V9 u==0 放行→validator task-time，.neg.pcap；complete.go:315 门序实测） |
| sv_smp_synch_global（smp_synch:2） | 改写 | 同上 |
| sv_neg_smp_synch（smp_synch:5） | 改写 | 锚词全字面 `sv smpSynch must be 0, 1 or 2`（.neg.pcap） |
| sv_4i4v（8 通道×int32+quality） | 改写 | 9-2LE 标准形；8 通道 seqData 布局 8×8B 落盘重钉 |
| sv_custom_dataset（无 smp_rate、2 通道 4B） | 改写 | 非 9-2LE 自定义形；无 dat_set 无 smp_rate 条件编码两面 |
| sv_vlan（vlan 三键） | 改写 | vlan_enabled/id/priority 层内；TPID/TCI 断言落盘重钉 |
| sv_period（period_us:250, count:100） | 改写 | **C 类注记**：pacing 未实现（生成器零消费，D-SV-1 ①），无包间隔断言面；用例保留=count=100 规模锚+字段断言 |
| sv_neg_confrev（conf_rev:0） | 改写 | 锚词全字面 `sv confRev must be non-zero`（.neg.pcap） |
| sv_neg_appid（appid:14745） | 改写 | 值 14745→**16383**（贴下界 0x3fff，边界价值）；锚词改 V9 `out of range [16384,32767]`（create-time 先火，无落盘；D-SV-1 ② 终审）；原 0x3999 同门等价注记 |

**新建例清单（T-13…30，P3 定稿）：**

| 测试点 | 用例 | 类别/说明 |
|---|---|---|
| 顶层 sv presence 判死（空 map 也死） | T-13 sv_vn_presence | A（负例，锚词 `top-level sv sub-config`；goose_vn_presence 同构；create-time 无落盘，P4 红例①） |
| 显式标量 eth MAC + flows=2 拒（12.9） | T-14 sv_vn_static_copy | A（负例，锚词 `static four-tuple`；eth 层显式 src_mac+case 级 strategy_fc flows=2；create-time 无落盘，P4 红例族外门面） |
| 空层 `{sv:{}}` 保底分支（D-SV-1 §3：零配置→appid 0x0000 下界首命中） | T-15 sv_vn_empty_layer | A（负例，锚词 `sv appid 0x0000 outside SV range 0x4000-0x7fff`——空层零配置 appid=0 首命中 :26 双界（位次先于 svID）；.neg.pcap；svID 必填分支=T-20 单点钉） |
| [ip,sv] carrier 拒（V7b） | T-16 sv_neg_ip_carrier | A（负例，锚词 `must not have an ip/transport carrier`；complete.go:352 create-time 无落盘） |
| vlan_id 越界（V9） | T-17 sv_neg_vlan | A（负例，锚词 `out of range [0,4095]`；vlan_id:4096；create-time 无落盘） |
| smpSynch 值 0（9.20 值域补口） | T-18 sv_smp_synch_0 | A（正例：`85 01 00` 断言；appid 取 **32767**=0x7fff 顺带钉上边界过） |
| smpSynch 值 1（9.20 值域补口） | T-19 sv_smp_synch_1 | A（正例：`85 01 01` 断言） |
| svID 超 255（validator 分支补口） | T-20 sv_neg_svid_255 | A（负例，256 字符 sv_id→`sv svID is required and must be <=255 bytes`；.neg.pcap） |
| data 缺失（validator 分支补口） | T-21 sv_neg_no_data | A（负例，`sv data is required`；.neg.pcap） |
| 非法 data type（validator 分支补口） | T-22 sv_neg_type | A（负例，type:"int64"→`sv data type "int64" unsupported; only int32 and float32 are supported`；.neg.pcap） |
| appid 显式 0（V9 u==0 放行→validator，13.20 零值语义钉） | T-23 sv_neg_zero_appid | A（负例，appid:0→`sv appid 0x0000 outside SV range 0x4000-0x7fff`；.neg.pcap；与非零越界走 V9 门=同分支按值分派两锚词；sv.go:26 双界既有执法（P3 假发现已纠正）） |
| int32 负数字节（9.8 大小端/符号） | T-24 sv_int32_neg | A（正例，inst_mag:-1 单通道 count=1→seqData `ff ff ff ff` 帧 pin；单测 TestBuildPayloadPreservesNegativeInt32Bytes 的 suite 对齐例） |
| float32 通道字节（9.8，全库零覆盖补口） | T-25 sv_float32 | A（正例，type:"float32" inst_mag:1.5→`3f c0 00 00` 帧 pin；BuildPayload 注释转录锚） |
| MAC 动态 inc 多流+回绕（12.15 五类之 inc/回绕） | T-26 sv_mac_dyn_inc | A（正例：eth.src_mac `{"strategy":"inc","range":["aa:bb:cc:00:00:01","aa:bb:cc:00:00:02"],"step":1}` + strategy_fc flows=3→第 3 流回绕 :01；逐流 MAC 断言；genMAC layer_dyn.go:585） |
| MAC 动态 list 轮转（12.15） | T-27 sv_mac_dyn_list | A（正例：list 2 MAC+flows=2→逐流轮转断言） |
| MAC 动态 rand 同 seed 可复现（12.15） | T-28 sv_mac_dyn_rand | A（正例：rand range+seed+flows=2→distinct+复跑同值断言） |
| 组合 A（9.11 替代面：vlan+double_send+quality，≥3 字段面） | T-29 sv_combo_vlan_double | A（正例：vlan_enabled+double_send:true+quality 通道+count:4 同包→TPID/共享 smpCnt/8B 通道三断言） |
| 组合 B（dat_set 有形+smp_rate+混型通道，≥3 字段面） | T-30 sv_combo_rate_dataset | A（正例：dat_set 首次有形→tag `0x81` 条件编码首钉+smp_rate `0x86`+int32/float32 混通道） |

**C 类注记（9.17，不冒充覆盖）：** ① pacing（period_us 周期）：配置面有 parse+struct、生成器 Generate（sv.go:162-184）零消费=行为未实现，suite 无包间隔断言（9.27）→ D-SV-1 ①（与 goose t0_ms 幽灵键不同级——sv 键面存在不删，T-10 注记）；② validator `sv is Layer 2 only...` 分支：链上 validateSpecBase L2-only 豁免使 spec 四元组恒空→分支不可达（goose 同款 C 类，单测 TestPlannerSVRejectsIPAndInvalidConfig 覆盖）；③ validator appid `outside SV range` 分支：非零越界被 V9 遮蔽（complete.go:321），显式 0 可达=T-23（:26 双界既有执法，P3 假发现已纠正）；④ MAC pattern 策略：genMAC（layer_dyn.go:585）仅 fixed/list/inc/rand 四策略，pattern 无→12.15 五类之 pattern=C；⑤ seqASDU 多 ASDU 折叠（0xa2>1）：D-SV-1 明确不解决；⑥ 包间隔/时间戳内容：harness 无断言面（C 类① 同源）。
**枚举取值覆盖（9.20-9.22 承载位置扫描）：** smpSynch 3 值 ✓（2=T-1/T-5、0=T-18、1=T-19）；data type 2 值 ✓（int32=T-7 等全量、float32=T-25/T-30）；appid 边界 4 值 ✓（0x4000 过=全量正例、0x7fff 过=T-18、0x3fff 拒=T-12、0x8000 拒=V9 同门 9.21 代表注记、0=T-23）；validator 9 分支 ✓（config required=T-15 同源保底/svID required=T-20/confRev=T-11/samples=T-4/smpSynch=T-6/data required=T-21/type=T-22/appid 下界=T-15+T-23（:26 双界既有）/L2 only=C②）；V9 门 5 ✓（appid 下界 T-12/vlan_id T-17/static T-14/presence T-13/carrier T-16）；dat_set 有/无 ✓（无=T-8、有=T-30）；smp_rate 有/无 ✓（无=T-8、有=全量）。
**正交矩阵：** smpSynch 3×smp_rate 2×quality 2（4i4v/4B）×dat_set 2×double_send 2×vlan 2×count {1,3,4,6,100}——已覆格见上表落点；地址族 N/A（L2-only 无 IP，MAC 面=组播缺省+单播 dst T-26 系即对称声明）；动态整格=eth MAC 1 字段×4 策略（fixed=静态 T-14 拒面、inc+回绕=T-26、list=T-27、rand=T-28、pattern=C④——9.32 整格无抽样）。
**通用陷阱自查（9.37-9.40）：** 无派生端口（L2-only）；无 distinct 聚合（smpCnt 序列逐帧 `value` 断言；MAC 逐流 exact）；flows>1 静态标量只有 T-14 拒绝例（9.39 互斥遵守——T-26/27/28 MAC 全走动态对象）；共享流序号语义=T-26/27/28 按"逐流不同"钉（同流内多帧共享同流序号=同 MAC，真实语义 9.40）。
**断言边界（9.27）：** 包间隔（period_us）无断言面（C①）；`frame.protocols` 只 nonzero（环境相关）；sv.length/APDU 长度随通道数变，P5 落盘重钉不预写；direction 恒 up（L2-only 单向发布）。
**执行口径：** P5 sv 真实流程全量（MCP 建任务→引擎生成→tshark 校对）全绿 + 落盘 `/tmp/mcp-pcaps/sv/` + 门 2 四项 + 反查 check_sv（P4 登记）。断言数值（offset/hex/length/smpCnt 序列）一律落盘重钉（14.6/9.31），不照抄存量手算值；改写例帧布局与改写前逐字节一致预期（仅 spec 形状迁移，goose 先例）。
**实现位置：** `cases/sv.json`（**30 例**：改写 12——顶层 sv 子映射/count 迁层内、`src_mac` 留顶层、锚词对真实门收紧 4 例、T-12 改值贴边界；新建 T-13…30；字节断言全部落盘复核）。

### T-ICMPV6-1…11 icmpv6.json——存量审计 + 测试点清单【D-ICMPV6-1 P3 定稿，P4 未开工】

**状态：** 已验收（2026-09-19，P5 全量绿 ×5 连跑+门2 四项+反查 18/18；P6 清库 150+11→0/0）。存量 1 例逐条审计改写（等价迁移：src/dst 迁 ip 层、icmpv6:{} 留层内空=缺省 ping 语义不变，fields 断言不动预期字节一致）+ 新建 10 例=11 例。锚词按真实执法门：create-time（presence/static 2 门无落盘）vs task-time validator（v4/type/code/pattern_step 4 门 .neg.pcap——legacy Validate v6 检查复用零新文案 icmpv6.go:60-79）。组合 2 条=Pattern 混型步/多变 data 步（D-ICMPV6-1 ④）。

**P5 校准注记（已验收实际形状）：** ①T-8 改显式 identifier=7/sequence=9/data="probe"（9.21 identifier 显式格落此例；id=0x0007≠seq=9 证非 0 回退路径，data.data=70726f6265）；②T-11 补 strategy_fc flows=2（用例漏传判缺省单流）+ 固定 group_id（srv6_mf03 先例：分片路由流序不定，固定后单 worker FIFO 确定序），源序列按 pcap 实钉 [::1,::9,::2,::9]（逐流成对：reply 源=该流 dst ::9，非对端流源）；③data.data 为 tshark 紧凑 hex 无冒号。
**级别：** pcap
**来源：** ①标准=RFC 4443 §2.3/§4.1+RFC 8200 §8.1（4.9 有 RFC）②设计=D-ICMPV6-1 ③现网=iputils ping6（待确认抓包，子表③）
**存量去向（1 例 → P5 改写后 11 例）：**

| 存量 | 去向 | 说明 |
|---|---|---|
| icmpv6_smoke_01 | 改写 | `src_ip/dst_ip`→`layers[ip].src/dst`、`icmpv6:{}`→`layers[icmpv6]:{}`（空层=缺省 ping：type 128/code 0/seq 1/data "ping"，决策 D1 镜像 parse）；fields 断言（type 128/129、id/seq 1、hlim 64、v6 地址）全部保留预期字节一致 |

**新建例清单（T-2…11）：**

| 测试点 | 用例 | 类别/说明 |
|---|---|---|
| 顶层 icmpv6 presence 判死 | T-2 icmpv6_vn_presence | A（负例，锚词 `top-level icmpv6 sub-config`；create-time 无落盘，P4 红例①） |
| ip 层显式地址 + flows=2 拒（12.9） | T-3 icmpv6_vn_static_copy | A（负例，锚词 `static four-tuple`；strategy_fc flows=2；create-time 无落盘） |
| v4 地址拒（② legacy 检查复用） | T-4 icmpv6_neg_v4 | A（负例，锚词 `must be IPv6`；task-time .neg.pcap；实现前链上无 validator=静默放行=红例④） |
| type 非法（validator 新分支） | T-5 icmpv6_neg_type | A（负例，type:130→`icmpv6 type must be 128 (Echo Request) or 129 (Echo Reply), got 130`；.neg.pcap） |
| code 非 0（Echo 语义） | T-6 icmpv6_neg_code | A（负例，code:1→`icmpv6 code must be 0 for Echo, got 1`；.neg.pcap） |
| pattern step type 非法 | T-7 icmpv6_neg_pattern_step | A（负例，pattern:[{type:0}]→`icmpv6 pattern step 1 type must be 128 or 129, got 0`；.neg.pcap） |
| type 129 单发（无 auto-reply） | T-8 icmpv6_type_129 | A（正例，type:129→1 包 up；packet_count 1+type 129 断言） |
| 组合 A：Pattern 混型步（128 步+129 步） | T-9 icmpv6_pattern_mixed | A（正例，pattern:[{type:128,sequence:1},{type:129,sequence:2}]→3 包（req+reply 对+单 reply）；identifier 缺省 0 回退语义同例覆盖） |
| 组合 B：Pattern 多步多变 data（≥3 动作） | T-10 icmpv6_pattern_data | A（正例，pattern 2 步 data "aa"/"bb"→4 包 seq 1/2 递增；data 字节 pin 落盘重钉） |
| ip.src 动态多流（3.14 逃生口） | T-11 icmpv6_ip_dyn_multi | A（正例，ip.src `{"strategy":"inc","range":["2001:db8::1","2001:db8::2"],"step":1}`+flows=2→4 包逐流源异（v6 inc 解析=ResolveIPValue 框架既有）；distinct 断言落盘重钉） |

**C 类注记（9.17）：** ① file_source 层链不可达（③ 立项，无用例需求不建例）；② Error 类 type（1-4 类，legacy 未实现不冒充）；③ Reply 即时性/时间差断言（9.27 引擎 auto-reply 无时间语义面）；④ identifier 0 回退语义单独格=T-9 同例覆盖（缺省 0→回退 sequence，断言 id=1）。
**枚举取值覆盖（9.20-9.22）：** type 2 值 ✓（128=T-1 缺省/129=T-8）；code ✓（0=全量；非 0 拒=T-6）；pattern 0/1/N 步 ✓（0=T-1/1 步=T-8 等价单 ping/2 步=T-9/T-10）；identifier 0 回退 ✓（T-9）/显式（T-1 id=1）；data 缺省/显式 ✓（T-1/T-10）；地址族 ✓（v6=全量/v4 拒=T-4）；validator 分支 ✓（config required=C 同源保底/type=T-5/code=T-6/pattern=T-7/v6 族=T-4）；门面 ✓（presence=T-2/static=T-3）。
**正交矩阵：** type 2×pattern {0,1,2 步}×data {缺省,显式}×identifier {0,显式}×地址 {v6,v4}——落格见上表；动态整格=业务 6 键全关，唯一开面=ip.src/dst（T-11 覆盖 inc；list/rand 属框架格随管线通用面）。
**通用陷阱自查（9.37-9.40）：** 无派生端口（raw-IP 无 L4 头）；多流=T-11 逐流源异（9.39 逃生态）；Sequence 缺省=index+1 按真实语义钉（9.40）。
**断言边界（9.27）：** Reply 即时性无时间断言面（C③）；伪头校验和 tshark checksum 字段（校验正确性由 builder 伪头路径既有，落盘重钉 checkok 口径视 tshark 支持而定，不预写）。
**执行口径：** P5 icmpv6 真实流程全量全绿+落盘 `/tmp/mcp-pcaps/icmpv6/`+门 2 四项+反查 check_icmpv6（P4 登记）。断言数值落盘重钉（14.6/9.31）；存量 fields 断言保留预期字节一致（v6 地址/缺省语义不变）。
**实现位置：** `cases/icmpv6.json`（**11 例**：改写 1+新建 10）。

### T-H323-1…17 h323.json——存量审计 + 测试点清单【D-H323-1 P3 定稿，P4 未开工】

**状态：** 已验收（2026-09-19，P5 全量绿 ×3 连跑+门2 四项+反查 24/24；P6 清库 216+15→0/0）。存量 1 例逐条审计改写（等价迁移：src/dst→ip 层、端口→h323 层、count 删、顶层 h323:{}→层内空；fields 断言保留等价——字节一致 suite 实证）+ 新建 16 例=17 例。锚词按真实执法门：create-time（presence/static 2 门无落盘）vs task-time validator（role/scenario/calls/display 4 门 .neg.pcap——legacy Validate 复用零新文案 h323.go:102-157）。包数公式代码精算（P4 红例③修正）：full=16/呼叫（3 握手+**10** Q.931+3 挥手——Q.931 序列 SETUP/CP/F↓/ALERTING↓/F↑/F↓/F↑/CONNECT↓/RELCOMP↑/RELCOMP↓=10 条，h323.go:322-341 逐行计数；存量例 min_packets=15 掩盖精确值）、tunnel_only=12（3+6+3）、ras_only=8（GRQ/GCF/RRQ/RCF/ARQ/ACF/DRQ/DCF，h323.go:492-499 实证）、data_only=frames（缺省 10）。**legacy 行为事实注记：Ras.Enabled 仅 ras_only 场景生效（full+Ras 不发 RAS 面，h323.go:194-199 分支实证）；Media.Enabled 在 full（CONNECT 后插帧）与 data_only 两处生效**）
**级别：** pcap
**来源：** ①标准=ITU-T H.225.0 §7/§7.3+Q.931+RFC 1006+RFC 3550（4.10 口径）②设计=D-H323-1 ③现网=参考 pcap 转录（types.go:5466，直呼无 GK）
**存量去向（1 例 → P5 改写后 17 例）：**

| 存量 | 去向 | 说明 |
|---|---|---|
| h323-q931-basic | 改写 | src_ip/dst_ip→layers[ip]、src_port/dst_port→layers[h323]、count 删（单流缺省）、顶层 h323:{}→层内空 map（缺省语义不变：caller/full/crv 0x2584/display Administrator）；expect.has_handshake/negotiated/terminates/min_packets 15+q931.message_type 9 序列断言全部保留 |

**新建例清单（T-2…17）：**

| 测试点 | 用例 | 类别/说明 |
|---|---|---|
| 顶层 h323 presence 判死 | T-2 h323_vn_presence | A（负例，锚词 `top-level h323 sub-config`；create-time 无落盘） |
| h323 层静态端口+flows=2 拒（12.9） | T-3 h323_vn_static_port | A（负例，锚词 `static four-tuple`；门扩扫 h323 层=P4 红例⑥同源；create-time） |
| role 非法 | T-4 h323_neg_role | A（负例，role:"gatekeeper"→`h323: invalid role`；.neg.pcap task-time） |
| scenario 非法 | T-5 h323_neg_scenario | A（负例，scenario:"bogus"→`h323: invalid scenario`；.neg.pcap） |
| calls 负数 | T-6 h323_neg_calls | A（负例，calls:-1→V9 create-time 拒（registry Min=0，`calls" = -1 invalid: not a numeric value in [0,65535]`）——legacy ">= 0" 锚词经层路径被 V9 先拦不可达，P5 校准注记） |
| display_name 超长 | T-7 h323_neg_display | A（负例，255 字节→`h323: display_name must be <=`；.neg.pcap） |
| scenario=tunnel_only | T-8 h323_scenario_tunnel | A（正例，12 包（3+6+3）：无 FACILITY 隧道面） |
| scenario=ras_only | T-9 h323_scenario_ras | A（正例，ras{enabled:true}→8 包 UDP 1719；无 TCP 握手（ras_only 跳过 TCP 实证）） |
| scenario=data_only | T-10 h323_scenario_data | A（正例，media{enabled:true}→10 包（frames 缺省）UDP 单向 up） |
| calls=2 多呼叫 | T-11 h323_calls_multi | A（正例，32 包（16×2）；CRV 逐呼叫+1（呼叫2 SETUP=包20，CRV 字节 0x2585）） |
| full+RTP 媒体面 | T-12 h323_media_full | A（正例，media{enabled:true,frames:2}→18 包（16+2）；RTP 插 CONNECT 后 RELCOMP 前（h323.go:336-338 实证序）） |
| dst_port 缺省 1720 | T-13 h323_dst_default | A（正例，空 h323 层→pkt1 tcp.dstport=1720（translate 镜像 setDefaultDstPort）） |
| h323.src_port 动态 inc+flows=2 | T-14 h323_port_dyn | A（正例，端口对象逐流异（30000/30001）+group_id 固定确定序（icmpv6 T-11 先例）；32 包逐流源端口 pin） |
| role=callee 方向翻转 | T-15 h323_role_callee | A（正例，握手仍 client 三包（h323.go:288-291 恒 client 发起——role 只翻 Q.931 面与 CRV 标志）；SETUP 从对侧发（ipv4.src 翻转断言）） |
| rewrite_addr 长度保持 | T-16 h323_rewrite_addr | A（正例，rewrite_addr:true→frame.len 序列与 T-1 全等（长度保持重写实证）；**字节级断言=C 类**（模板内嵌 IP 字节无 tshark 字段面+单测零覆盖实证 h323_test.go 30 测试无一涉及），注记不冒充） |
| v6 地址对照（9.24 对称） | T-17 h323_v6 | A（正例，ip 层 v6→16 包（legacy 无族强制=两族均可跑，EtherType 0x86DD 断言）） |

**C 类注记（9.17）：** ①rewrite_addr 字节级断言（T-16，模板内嵌 IP 无 tshark 字段面）；②GK 路由模式（明确不解决）；③MSS 链上覆盖（无住处，恒 1460 缺省=D-H323-1 ④）；④RAS PER 字节现网确认（规范编码已实现，抓 GK 现网包待确认）。
**枚举取值覆盖（9.20-9.22）：** role 2 值 ✓（caller=T-1/callee=T-15）；scenario 4 值 ✓（full=T-1/tunnel=T-8/ras=T-9/data=T-10）；calls {0缺省,1,2} ✓（T-13 空层/T-1/T-11）；media {off,on} ✓（T-1/T-10/T-12）；ras {off,on} ✓（T-1/T-9）；rewrite {off,on} ✓（T-1/T-16）；display {缺省,显式,超长拒} ✓（T-1/T-11 显式可并入/T-7）；ports {显式,缺省,动态} ✓（T-1/T-13/T-14）；地址族 ✓（v4=全量/v6=T-17）；validator 分支 ✓（IP parse 2/T-4 role/T-5 scenario/T-6 calls/T-7 display/nil-config=C 保底/MSS=C③）；门面 ✓（presence=T-2/static=T-3）。
**正交矩阵：** role 2×scenario 4×calls{1,2}×media{off,on}×ras{off,on}——落格见上表（全组合 64 格不逐格建例，按 9.21 分支级：每分支至少一例）；动态整格=业务 8 键全关（D-H323-1 §12），唯一开面=h323 端口 2 键（T-14 inc）+ip.src/dst（框架格）。
**通用陷阱自查（9.37-9.40）：** 派生端口：RTP 5062/5063 与信令 1720/RAS 1719 无撞（T-12 断言按各自端口面分侧 9.38）；多流=T-14 group_id 固定确定序（9.39 动态对象豁免门）；CRV 呼叫内递增=真实语义钉（9.40，非流序号）。
**断言边界（9.27）：** 包间隔/时间差无断言面；RTP payload 字节（G.711 静音模板）frame.len 面可钉、深字节无字段面注记。
**执行口径：** P5 h323 真实流程全量全绿+落盘 `/tmp/mcp-pcaps/h323/`+门 2 四项+反查 check_h323（P4 登记）。断言数值落盘重钉（14.6/9.31）；存量 fields 断言保留等价（包数/flags/消息序/端口不变）。
**实现位置：** `cases/h323.json`（**17 例**：改写 1+新建 16）。

### T-MPLS-1…13 mpls.json——存量审计 + 测试点清单【D-MPLS-1 P3 定稿，P4 未开工】

**状态：** 已验收（2026-09-19，P5 全量绿 ×4 连跑+门2 四项+反查 22/22；P6 清库 142+13→0/0 总量对账精确）。存量 1 例逐条审计改写（等价迁移：count 删、顶层 mpls→层内、补 ip 层显式地址+mpls 层显式端口 12345/80——存量靠扁平缺省，fields/frames 断言保留等价字节）+ 新建 13 例=14 例（P5 校准：反查 22/22 所需 T-1 补 inner_payload 显式格 data.data=70726f6265；最终 14 例=改写 1+新建 13，P3 原表 13 例+T-14）。锚词按真实执法门：create-time（presence/static 2 门无落盘）vs task-time validator（label 上界/TC 上界/S 栈底/InnerProto/Direction/Frames 6 门 .neg.pcap——legacy Validate 复用零新文案 planner.go:40-95）。包数=frames（缺省 1，模板面每流帧数）。**链路径语义注记：inner_proto=0（auto）在链上恒解析为 UDP（spec.TCP 链不可达）——枚举格 0 与 17 等价，0/17 双格仍各建一例钉合同**）
**级别：** pcap
**来源：** ①标准=RFC 3031 §3.12+RFC 3032 §2.1/§3.1/§3.9/§3.10+RFC 5462 ②设计=D-MPLS-1 ③现网=探针 pcap（/tmp/probe-iana/mpls.pcap，存量 notes 验证记录）
**存量去向（1 例 → P5 改写后 13 例）：**

| 存量 | 去向 | 说明 |
|---|---|---|
| mpls_single_label_ipv4 | 改写 | count 删、顶层 mpls→layers[mpls]、补 ip 层 src/dst 显式+mpls 层 src_port/dst_port 显式；fields（eth.type 0x8847/mpls.label 100/exp 0/bottom 1/ttl 64/udp.dstport 80）+frames（offset 14 `00 06 41 40`）全部保留等价——字节一致由 P5 实证 |

**新建例清单（T-2…13）：**

| 测试点 | 用例 | 类别/说明 |
|---|---|---|
| 顶层 mpls presence 判死 | T-2 mpls_vn_presence | A（负例，锚词 `top-level mpls sub-config`；create-time） |
| mpls 层静态端口+flows=2 拒 | T-3 mpls_vn_static_port | A（负例，锚词 `static four-tuple`；形状=[ip{},mpls{ports}] 最小证明形；create-time） |
| label 超 20bit | T-4 mpls_neg_label | A（负例，label:0x100000→`exceeds 20 bits`；.neg.pcap） |
| TC 超 3bit | T-5 mpls_neg_tc | A（负例，tc:8→`exceeds 3 bits`；.neg.pcap） |
| S 位非栈底 | T-6 mpls_neg_sbit | A（负例，labels:[{label:1,s:true},{label:2}]→`not the bottom of stack`；.neg.pcap） |
| InnerProto 非法 | T-7 mpls_neg_innerproto | A（负例，inner_proto:6→合法!改 1→`InnerProto 1 not in supported list`；.neg.pcap） |
| Direction 非法 | T-8 mpls_neg_direction | A（负例，direction:"sideways"→`not in supported list`；.neg.pcap） |
| frames 多帧 | T-9 mpls_frames_multi | A（正例，frames:3→3 包；IP ID 逐帧+1（ip.id 断言 1/2/3——首跑校准）） |
| direction=down 交换 | T-10 mpls_direction_down | A（正例，1 包；ip.src/dst 与 eth MAC 全交换（ip.src=20.0.0.1 实钉）） |
| multicast 0x8848 | T-11 mpls_multicast | A（正例，multicast:true→eth.type=0x8848） |
| 内层 TCP 裸头 | T-12 mpls_inner_tcp | A（正例，inner_proto:6→tcp.dstport 断言；**内层 TCP 无握手/seq 语义=裸头（链路径合同注记）**） |
| v6 内层对照（9.24） | T-13 mpls_v6 | A（正例，ip 层 v6→内层 IPv6（builder 内层双族 §3.9）；mpls.label 断言不变） |

**C 类注记（9.17）：** ①保留标签 0-15 不校验（legacy 合同，用例避开——T-4 用 0x100000 非 0-15）；②LDP/RSVP 控制面（明确不解决）；③内层 TCP 会话语义（④ C 类）；④中链 shim 表达（A2 否决）。
**枚举取值覆盖（9.20-9.22）：** label{100,0x100000 拒}✓；TC{0,8 拒}✓；S{缺省自动,非栈底拒}✓（T-1 自动/T-6 拒）；TTL{0→64,显式}——⚠️ P3 校准：TTL 显式格并入 T-13 或独立格→**缺独立格，补 T-1 notes 或视为 9.21 同分支代表（TTL 0 缺省=T-1 钉 64；显式 TTL 无独立格=接受为单分支代表，注记）**；multicast{off,on}✓；inner_proto{0,17,6,1 拒}✓；direction{up,down,非法拒}✓；frames{缺省 1,3}✓；端口{显式,缺省,动态}——显式=T-1、缺省=T-4?（无）、动态=**缺格→P4 后补一例 port_dyn（E1），或注记 E1 格随 h323 T-14 同构推迟**——**裁定：补 T-14 mpls_port_dyn（src_port inc+flows=2，32→3 包逐流，group_id 固定）→ 14 例**。
**正交矩阵：** 栈深{1,N}×族{v4,v6}×inner{udp,tcp}×direction×multicast——落格见上表；动态整格=业务 5 键全关+端口 2 键（T-14）。
**通用陷阱自查（9.37-9.40）：** 无派生端口；多流=T-14 group_id 固定；IP ID 逐帧递增=真实语义钉（9.40）。
**断言边界（9.27）：** 包间隔无面；内层 TCP 裸头无状态断言面（C③）。
**执行口径：** P5 mpls 真实流程全量全绿+落盘 `/tmp/mcp-pcaps/mpls/`+门 2 四项+反查 check_mpls；数值落盘重钉（14.6/9.31）。
**实现位置：** `cases/mpls.json`（**14 例**：改写 1+新建 13）。

### T-NGAP-1…17 ngap.json——存量审计 + 测试点清单【D-NGAP-1 P5 已验收】

**状态：** 已验收（2026-09-19 P6：RESULT 17 pass/0 fail ×2 连跑+反查 36/36（T-10 并入 global_ran_node_id 补缺口）；回归 icmpv6 11/h323 17/mpls 14/srv6 74/sv 30/goose 33 全绿；pcap 落盘 /tmp/mcp-pcaps/ngap/）。P3 定稿（2026-09-19）原注记：存量 1 例逐条审计改写（等价迁移：count 删、顶层空 `ngap:{}`→ngap 层空业务面+显式端口 12345/38412、补 ip 层显式地址——legacy 缺省面（AMF-TEST-01/MCC460 等）不进用例，断言 13 fields+2 frames pin 全保留等价字节）+ 新建 16 例=17 例。**P3 期修正回填 D-NGAP-1 §6**：UEContextRelease=Command+Complete 两包（ngap.go:387-398 实证），全开 16 包（非 15）。
**级别：** pcap
**来源：** ①标准=3GPP TS 38.413（procedureCode §9.2：NGSetup 21/InitialUE 15/DL NAS 4/UL NAS 46/PDU Setup 29/UE Release 41）+TS 38.412（PPID 60）+RFC 4960（SCTP 握手 §5/拆链 §9.2）②设计=D-NGAP-1 ③现网=参考 pcap SCTP_NAS.pcap 转录（ngap.go:40-41）+Wireshark packet-ngap（tshark 3.6.14 ngap.procedureCode 字段已验证存在）
**存量去向（1 例 → P5 改写后 17 例）：**

| 存量 | 去向 | 说明 |
|---|---|---|
| ngap-sctp-setup-basic | 改写 | count 删、顶层 `ngap:{}`→layers[ngap]（业务面空+src_port 12345/dst_port 38412 显式）、四元组→layers[ip] 显式 10.0.0.1/20.0.0.1；expect 13 fields（chunk 序列 1/2/10/11+proc 21 对+7/8/14）+frames 2 pin（offset 62：f5 `00 15`=initiatingMessage+21、f6 `01 15…41 4d 46…`=successfulOutcome+21+"AMF-TEST-01"）全部保留等价——字节一致由 P5 实证 |

**新建例清单（T-2…17）：**

| 测试点 | 用例 | 类别/说明 |
|---|---|---|
| 顶层 ngap presence 判死 | T-2 ngap_flat_presence | A（负例，锚词 `top-level ngap sub-config`；create-time） |
| ngap 层静态端口+flows=2 拒 | T-3 ngap_flat_static_port | A（负例，锚词 `static four-tuple`；形状=[ip{},ngap{ports}] 最小证明形；create-time） |
| InitialUEMessage | T-4 ngap_initial_ue | A（正例，initial_ue_message:true+initial_nas→10 包，p5=NGSetupReq proc 21、p7=proc 15 initiatingMessage） |
| DownlinkNASTransport | T-5 ngap_dl_nas | A（正例，downlink_nas→10 包，p7=proc 4 successfulOutcome，方向 down） |
| UplinkNASTransport | T-6 ngap_ul_nas | A（正例，uplink_nas→10 包，p7=proc 46 initiatingMessage，方向 up） |
| PDUSessionSetup 对 | T-7 ngap_pdu_session | A（正例，pdu_session_setup{pdu_session_id:1,sst:1,sd:"000001"}→11 包，p7/p8=proc 29（Command down+Complete up 同码）） |
| UEContextRelease 对 | T-8 ngap_ue_release | A（正例，ue_context_release:true→11 包，p7/p8=proc 41 双向） |
| 全可选全开 | T-9 ngap_all_procedures | A（正例，16 包=4 握手+2 NGSetup+1 IUE+1 DL+1 UL+2 PDU+2 UECR+3 拆链；chunk+procedureCode 全序列断言） |
| TA 列表+DRX | T-10 ngap_ta_drx | A（正例，supported_ta_list 2 项+default_paging_drx:2→NGSetupReq PDU 字节 pin（P5 校准 offset/hex）） |
| UE ID 显式 | T-11 ngap_ue_ids | A（正例，ran_ue_ngap_id/amf_ue_ngap_id 显式+initial_ue_message→IUE IE 断言（P5 校准 tshark ngap.RAN_UE_NGAP_ID 字段或 frames hex）） |
| AMF name 自定义 | T-12 ngap_amf_name | A（正例，amf_name:"AMF-EDGE-07"→f6 offset 62 hex 含 `41 4d 46 2d 45 44 47 45 2d 30 37`（"AMF-EDGE-07"）pin） |
| v6 拒（legacy v4-only） | T-13 ngap_neg_v6 | A（负例，ip 层 v6→`only IPv4 is supported`；task-time validator；.neg.pcap） |
| dst_port 缺省 38412 | T-14 ngap_default_port | A（正例，ngap 层无端口→sctp.dstport=38412 断言（translate 镜像 setDefaultDstPort；src worker 12345+i 保底）） |
| 端口动态 E1 | T-15 ngap_port_dyn | A（正例，src_port/dst_port 动态对象+strategy_fc flows=2→group_id 固定 2 流×9=18 包，端口逐流断言） |
| SST 越界 | T-16 ngap_neg_sst | A（负例，pdu_session_setup.sst:300→`SST 300 out of range [0,255]`；task-time；.neg.pcap） |
| NAS 超长 | T-17 ngap_neg_nas_len | A（负例，initial_nas 4097 字节→`InitialNAS too long`；task-time；.neg.pcap） |

| VSA 248B 超长拒 | T-22 radius_neg_vsa_len | A（负例，锚词 `exceeds the 247-byte field limit`；§9.8 超长×VSA 位型，与 T-16 的 253 门分锚） |
| 普通 attr 恰 253B | T-23 radius_attr_boundary | A（正例，边界等值格 253 过/254 拒对偶；avp.length=255 恰满 1 字节） |
| 现网 NAS 组合 | T-24 radius_nas_combo | A（正例，Service-Type/NAS-IP/Calling-Station/Message-Authenticator 四属性承载；MA 仅 opaque 字节位型） |
| CoA 43 白名单外拒 | T-25 radius_neg_coa | A（负例，RFC 5176 现网真实码比 T-10 假码 42 更现网；CoA 族支持=B′ 立项） |

**P5 校准实录（25/25 落盘重钉）：** ①tshark 同包多 AVP 字段逗号拼接（avp.type "1,8,5,6,26"、avp.length "6,6,6,4,10"）——length 按 value 实长+2 复算（user=4→6，非值域臆算）；②tshark 对 11→11/12→13 非标准对不标 rsp/reqframe（空）——方向改用 udp.srcport/dstport 交换钉；③port_dyn 4 包=2 流×(req+resp)，响应端口交换→src/dst 双向各聚 4 值 distinct_values（不钉包位）；④flow_control 键名实为 strategy_fc（sip 先例一致）。
**C 类注记（9.17）：** ①随机面 verTag/TSN/cookie/ip.id 断言避开（T-1 先例）；②SCTP IPv6 路径=明确不解决（T-13 负例钉）；③全合规 PER=不冒充（④ C 类）；④sctp 传输层机器（A2 否决，序号 28 另立项）；⑤链路径 src_port 缺省无格（worker 12345+i 保底=T-14 同例钉）。
**枚举取值覆盖（9.20-9.22）：** procedureCode{21,15,4,46,29,41}✓（T-1/4/5/6/7/8）；chunk{1,2,10,11,DATA,7,8,14}✓（T-1）；业务 12 键逐键≥1 格✓（T-4…T-12；ran/amf_ue_ngap_id=T-11）；端口{显式,缺省,动态}✓（T-1/T-14/T-15）；DRX{缺省,2}✓（T-1/T-10）；负例{s presence,static copy,v6,sst,nas 长度}✓。
**正交矩阵：** 可选流程{0,1,全}×端口{显式,缺省,动态}×方向面（IUE/UL=up、DL/UEC-Cmd=down 实钉）——落格见上表；动态整格=业务 12 键全关+端口 2 键（T-15）。
**通用陷阱自查（9.37-9.40）：** 无派生端口；多流=T-15 group_id 固定（h323 T-14/mpls T-14 先例）；包序=SCTP emit 线性+legacy 自管方向（force-up 防双换，链路径合同）。
**断言边界（9.27）：** 随机面不钉；DRX/MCC/MNC 进 PER 编码字节=P5 校准后钉（T-10/T-11 注记）；无包间隔面。
**执行口径：** P5 ngap 真实流程全量全绿+落盘 `/tmp/mcp-pcaps/ngap/`+门 2 四项+反查 check_ngap；数值落盘重钉（14.6/9.31）；**服务端验证=pcaptest 改动需服务器重编重启**（h323 教训）。
**实现位置：** `cases/ngap.json`（**17 例**：改写 1+新建 16）。

### T-TELNET-1…17 telnet.json——存量审计 + 测试点清单【D-TELNET-1 P5 已验收】

**状态：** 已验收（2026-09-19 P6：RESULT 17 pass/0 fail ×3 连跑（首跑 14/17→3 红全为推算校准按 pcap 重钉：login_full 登录段序偏 2/long_output 大响应首段偏 3/v6 帧 offset 74=IPv6 头 40B）+补键 2 例后反查 32/32；回归 ngap 17/h323 17/mpls 14/icmpv6 11 全绿；pcap 落盘 /tmp/mcp-pcaps/telnet/；min_packets 保守下界维持存量口径）。P3 定稿（2026-09-19）原注记：存量 1 例逐条审计改写（等价迁移：count 删、顶层空 `telnet:{}`→telnet 层空业务面+显式端口 12345/23、四元组→layers[ip] 显式；**断言面=8 fields+6 frames+4 标量（has_handshake/negotiated/terminates/min_packets:12）全保留**——12 为保守下界实际 13 包，P5 校准后可钉 13；存量 notes"Will Echo"注释与字节不符（ff fb 03=WILL SGA）不迁移错误注释）+ 新建 16 例=17 例。
**级别：** pcap
**来源：** ①标准=RFC 854（NVT+IAC 转义 §3）+RFC 855（选项/SB）+RFC 1091（TTYPE）+RFC 1073（NAWS）②设计=D-TELNET-1 ③现网=存量 pcap 13 帧实证（tshark telnet 解码器 frames hex 逐字节+telnet.data 伪影注记：IAC 帧空串/trim 尾空白/\r\n 字面转义）
**存量去向（1 例 → P5 改写后 17 例）：**

| 存量 | 去向 | 说明 |
|---|---|---|
| telnet-basic-session | 改写 | count 删、顶层 telnet:{}→layers[telnet]（业务面空+src_port 12345/dst_port 23 显式）、四元组→layers[ip]；8 fields（tcp.flags 0x002/0x012/0x010+telnet.data×4）+6 frames（offset 54：ff fb 03/ff fd 03/6c 6f 67 69 6e 3a 20/61 6c 69 63 65 0d 0a/24 20/65 78 69 74 0d 0a）+4 标量全保留等价——字节一致由 P5 实证 |

**新建例清单（T-2…17）：**

| 测试点 | 用例 | 类别/说明 |
|---|---|---|
| 顶层 telnet presence 判死 | T-2 telnet_flat_presence | A（负例，锚词 `top-level telnet sub-config`；create-time） |
| telnet 层静态端口+flows=2 拒 | T-3 telnet_flat_static_port | A（负例，锚词 `static four-tuple`；形状=[ip{},telnet{ports}]；create-time） |
| login_full 场景 | T-4 telnet_login_full | A（正例，scenario:login_full→33 包校准（26 事件段+7）；协商 11 IAC 事件+密码 echo 关闭 wont/dont+2 命令回显；断言 IAC 字节+login 字节） |
| login_fail 场景 | T-5 telnet_login_fail | A（正例，27 包校准；"Login incorrect\r\nlogin: " 重提示断言=失败路径 9.9） |
| multi_command 场景 | T-6 telnet_multi_command | A（正例，33 包；commands:["uname","pwd"] 显式双命令（9.11 多动作组合流）+commandResponse canned 输出断言） |
| long_output 场景 | T-7 telnet_long_output | A（正例，36 包校准；8197B 响应 MSS 1460 分段 6 段断言（段长 tcp.len=1460×5+末段）） |
| option_reject 场景 | T-8 telnet_option_reject | A（正例，28 包；DONT/WONT 拒绝路径字节断言（ff fe 39/ff fb 22→拒绝对）） |
| synch 场景 | T-9 telnet_synch | A（正例，38 包校准；IAC IP(ff f4)+IAC DM(ff f2) 中断序列断言；DM 无 URG=C 注记） |
| IAC data 转义 | T-10 telnet_iac_escape | A（正例，dialog 手动 data 含 0xFF→`61 ff ff 20` 翻倍字节 pin（RFC 854 §3 核心）；DataB64 形态同例覆盖） |
| sb 子协商 | T-11 telnet_sb_subneg | A（正例，dialog 手动 sb 事件+SubDataB64→`ff fa <opt> <data> ff f0` 框架字节 pin；SubData 内 0xFF 翻倍） |
| ttype_is/naws 缺省+显式 | T-12 telnet_ttype_naws | A（正例，dialog ttype_is+naws：缺省 xterm/80x24 字节 pin+显式值同例对照（19 事件类型枚举格代表）） |
| banner 前置 | T-13 telnet_banner | A（正例，banner:"Welcome\r\n"→p4 首数据段 banner 字节 pin（握手后第一 PSH-ACK down）） |
| v6 正例（IP 透明） | T-14 telnet_v6 | A（正例，ip 层 v6→eth.type 0x86DD+tcp.flags 断言（9.24 地址族对称：telnet v6=正例格）；事件字节面不变） |
| 缺省端口 23 | T-15 telnet_default_port | A（正例，telnet 层无端口→tcp.dstport=23 断言（translate 镜像 setDefaultDstPort；src worker 保底）） |
| 端口动态 E1 | T-16 telnet_port_dyn | A（正例，src_port/dst_port 动态对象+strategy_fc flows=2→group_id 固定 2 流×13=26 包，端口逐流断言） |
| unknown scenario 拒 | T-17 telnet_neg_scenario | A（负例，scenario:"telnet999"→`unknown scenario`；task-time validator；.neg.pcap） |

| VSA 248B 超长拒 | T-22 radius_neg_vsa_len | A（负例，锚词 `exceeds the 247-byte field limit`；§9.8 超长×VSA 位型，与 T-16 的 253 门分锚） |
| 普通 attr 恰 253B | T-23 radius_attr_boundary | A（正例，边界等值格 253 过/254 拒对偶；avp.length=255 恰满 1 字节） |
| 现网 NAS 组合 | T-24 radius_nas_combo | A（正例，Service-Type/NAS-IP/Calling-Station/Message-Authenticator 四属性承载；MA 仅 opaque 字节位型） |
| CoA 43 白名单外拒 | T-25 radius_neg_coa | A（负例，RFC 5176 现网真实码比 T-10 假码 42 更现网；CoA 族支持=B′ 立项） |

**P5 校准实录（25/25 落盘重钉）：** ①tshark 同包多 AVP 字段逗号拼接（avp.type "1,8,5,6,26"、avp.length "6,6,6,4,10"）——length 按 value 实长+2 复算（user=4→6，非值域臆算）；②tshark 对 11→11/12→13 非标准对不标 rsp/reqframe（空）——方向改用 udp.srcport/dstport 交换钉；③port_dyn 4 包=2 流×(req+resp)，响应端口交换→src/dst 双向各聚 4 值 distinct_values（不钉包位）；④flow_control 键名实为 strategy_fc（sip 先例一致）。
**C 类注记（9.17）：** ①随机面 serverSeq/clientSeq/ip.id 断言避开（seq/ack 相对关系 harness 不可断=9.27 注记）；②RFC 1143 协商状态机不做（legacy 合同逐字发射，不冒充真协商）；③MSS 链路径固定 1460（spec.TCP 不可达，1.12 口径）；④synch DM 无 URG（L4Config 无字段）；⑤validateLayer IP parse 锚词链不可达（schema 格式门先拦）=零死锚词。
**枚举取值覆盖（9.20-9.22）：** 19 事件类型{data,B64 合并/will/wont/do/dont/sb/ttype_send/ttype_is/naws/ip/dm/nop/ayt/brk/ao/ec/el/ga/synch}——T-1(will/do/data)+T-4(全协商面 wont/dont/ttype_send/ttype_is/naws)+T-9(ip/dm)+T-10(data/B64)+T-11(sb)+T-12(缺省对照)+**剩余 8 类型{nop/ayt/brk/ao/ec/el/ga}单字节命令**→**裁定：T-12 扩为 dialog 多事件例（nop/ayt/brk/ao/ec/el/ga 七单字节命令逐个入 dialog，一处覆盖七枚举）**；场景{6/6}✓（T-4…T-9）；端口{显式,缺省,动态}✓（T-1/T-15/T-16）；地址族{v4,v6}✓（9.24 双族）；负例{presence,static copy,unknown scenario}✓。
**正交矩阵：** 场景{6}×地址族{v4,v6}×端口{显式,缺省,动态}——v6 对照=T-14（基线 dialog 族）；动态整格=业务 10 键全关+端口 2 键（T-16）。
**通用陷阱自查（9.37-9.40）：** 无派生端口；多流=T-16 group_id 固定；tshark telnet.data 伪影三则=断言以 frames hex 为主、telnet.data 为辅（存量先例）。
**断言边界（9.27）：** seq/ack 只断 flags 面（ISN 随机）；IAC 帧 telnet.data 空串=已知伪影（frames 字节断言兜底）；包间隔无面。
**执行口径：** P5 telnet 真实流程全量全绿+落盘 `/tmp/mcp-pcaps/telnet/`+门 2 四项+反查 check_telnet；数值落盘重钉（14.6/9.31）；**服务端验证=服务器重编重启**（h323 教训）。
**实现位置：** `cases/telnet.json`（**17 例**：改写 1+新建 16）。

### T-SIP-1…57 sip.json——存量审计 + 测试点清单【D-SIP-1 P6 已验收 + 补充批 T-19…24 + 批二 T-25…43 + 批三 T-44…57】

**状态：** 已验收（2026-09-19 P6：首跑 9/18→9 红全为断言面校准按 pcap 重钉（包号偏 1/body 实长/末段 315=头补全计入分段对象/rtp.* 字段 tshark 3.6 无效改 frames pin offset 42/udp.port 双值改 srcport-dstport/SDP 端口超 65535 上界拒改 60070/空 dialog 低级错 3 例补 dialog）→18/18 ×2 连跑+反查 29/29；回归 telnet 17/ngap 17/h323 17/mpls 14/icmpv6 11 全绿；pcap 落盘 /tmp/mcp-pcaps/sip/）。P3 定稿（2026-09-19）原注记：存量 1 例逐条审计改写（等价迁移：count 删、顶层 sip{dialog}→sip 层、四元组→layers[ip] 显式+显式端口 12001/5060；断言面=14 fields（sip.Method/Request-Line/Status-Code/CSeq.seq/CSeq.method）+frames 4 pin offset 54+标量（negotiated/terminates）全保留）+ 新建 17 例=18 例。
**级别：** pcap
**来源：** ①标准=RFC 3261（§7/§8.1.1/§20.8/§8.1.1.4）+RFC 3550（§5.1 RTP）+RFC 3264（§5.1）②设计=D-SIP-1 ③现网=存量 pcap 12 帧实证（tshark SIP 解码器五字段+逐字节 frames）
**存量去向（1 例 → P5 改写后 18 例）：**

| 存量 | 去向 | 说明 |
|---|---|---|
| sip-basic-dialog | 改写 | count 删、顶层 sip→layers[sip]、四元组→ip 层显式+端口显式；五消息（INVITE/200/ACK/BYE/200）+14 fields+frames 4 pin（p4 INVITE 请求行/p5 200 状态行/p6 ACK/p7 BYE）保留等价——字节一致由 P5 实证 |

**新建例清单（T-2…18）：**

| 测试点 | 用例 | 类别/说明 |
|---|---|---|
| 顶层 sip presence 判死 | T-2 sip_flat_presence | A（负例，锚词 `top-level sip sub-config`；create-time） |
| sip 层静态端口+flows=2 拒 | T-3 sip_flat_static_port | A（负例，锚词 `static four-tuple`；[ip{},sip{ports}]；create-time） |
| 头补全：无头 INVITE 生成 | T-4 sip_hdr_completion | A（正例，dialog 仅 method+uri→Call-ID/Via/CSeq/Max-Forwards 全生成（RFC 3261 §8.1.1.4）；sip.CSeq.seq=1/Method=INVITE+Via/Call-ID 头存在断言=Wireshark-clean 格） |
| 头补全：user 头赢+响应回显 | T-5 sip_hdr_user_wins | A（正例，显式 Call-ID/From/To+CSeq:7→INVITE 保留+200 响应回显同值（lastFrom/To/CSeq 继承）；user>补全>无三态之 user 态） |
| REGISTER 枚举 | T-6 sip_register | A（正例，REGISTER+200；方法枚举格） |
| OPTIONS 枚举 | T-7 sip_options | A（正例，OPTIONS+200；方法枚举格） |
| 响应码枚举 | T-8 sip_status_codes | A（正例，100/180/200/404 逐响应（多 dialog 消息组）；sip.Status-Code 逐值断言） |
| SDP body+Content-Length 自动 | T-9 sip_sdp_body | A（正例，INVITE 带 SDP body 无 Content-Length 头→自动补 `Content-Length: N`（N=body 字节数）帧 pin；v=-o-m= 行+SIP 头数组） |
| 长消息 MSS 分段 | T-10 sip_mss_segment | A（正例，3000B body INVITE→3 段（1460/1460/80）；tcp.len 逐段断言；首跑校准） |
| RTP 媒体子流 | T-11 sip_rtp_media | A（正例，末消息 emit_media:true+media{frames:2,payload_type:0}→RTP 2 帧 UDP（udp.port 5004/rtp.pt 0/rtp 版本 0x80 断言）；**seq/ssrc 随机不钉**（RFC 3550 合同）；14 包=3+5+2+4） |
| RTP 方向 down+显式端口 | T-12 sip_rtp_down | A（正例，media{direction:"down",src_port:30000,dst_port:30001}→RTP down 帧 src=30001/dst=30000 交换断言（:846-856 换向合同）） |
| SDP 派生端口 | T-13 sip_sdp_port | A（正例，INVITE body m=audio 6007020→RTP src=6007020（scanSDPMediaPorts 合同 :776-796）；future-bleed=C 注记用例避开 re-INVITE） |
| RTP FileSource | T-14 sip_rtp_filesource | A（正例，media.file_source literal→RTP 帧 payload=literal 字节分块（frame_size 切）；payload 前 12B RTP 头+实字节断言） |
| v6 正例 | T-15 sip_v6 | A（正例，ip 层 v6→12 包同构+帧 offset 校准（74）；9.24 地址族对称） |
| 缺省端口 5060 | T-16 sip_default_port | A（正例，sip 层无端口→tcp.dstport=5060（translate 镜像 setDefaultDstPort）；src worker 保底） |
| 端口动态 E1 | T-17 sip_port_dyn | A（正例，src_port/dst_port 动态对象+flows=2→group_id 固定 2 流×12=24 包端口逐流） |
| 空 dialog 最小联结 | T-18 sip_empty_dialog | A（正例，sip 层空业务面（或 dialog:[]）→7 包=3 握手+0+4 挥手（nil-config 合同）；flags 序全断言） |
| re-INVITE 会话刷新 | T-19 sip_reinvite_refresh | A（补充批，§3.15 多轮操作+§9.9；INVITE→200→ACK→re-INVITE→200→ACK→BYE→200=8 消息 15 包；CSeq 递增钉） |
| CANCEL 取消未应答 | T-20 sip_cancel | A（补充批，RFC 3261 §9；INVITE→180→CANCEL→200→487→ACK=6 消息 13 包；无 BYE） |
| 486 Busy 非正常结束 | T-21 sip_busy_reject | A（补充批，§3.15 非正常结束②；INVITE→486→ACK=10 包；非 2xx 仍 ACK、无 BYE） |
| dialog 内 OPTIONS 保活 | T-22 sip_options_keepalive | A（补充批，§3.15 保活+§11；OPTIONS 中插 INVITE/BYE 之间；CSeq 2 钉） |
| 状态码大类枚举 | T-23 sip_status_class_enum | A（补充批，§9.20 5xx(500)/6xx(603) 补格，与 404/486 合成 4xx/5xx/6xx 全大类） |
| 组合流二 PRACK | T-24 sip_callflow_complete | A（补充批，§9.11 组合流≥2 富余化；RFC 3262 PRACK+RAck 关联钉） |
| REGISTER 摘要鉴权 | T-25 sip_register_digest_auth | A（批二，§22.1：401 WWW-Authenticate→Authorization 重发；现网注册规范面） |
| REGISTER 刷新注销 | T-26 sip_register_expire0 | A（批二，§10.2.2 Expires:0+Contact:*；注册生命周期） |
| 同流双呼 | T-27 sip_two_calls_sequential | A（批二，§3.2 独立 Call-ID 独立命运：呼A 成+B 486 拒；现实 UA 行为） |
| REFER 盲转 | T-28 sip_refer_transfer | A（批二，RFC 3515：Refer-To+NOTIFY sipfrag 进展+BYE；转移键语义） |
| MWI 留言灯 | T-29 sip_subscribe_notify_mwi | A（批二，RFC 3265/3842：SUBSCRIBE message-summary→NOTIFY MWI 体） |
| 183 早媒体 | T-30 sip_early_media_183 | A（批二，RFC 3262：183+SDP sendonly→PRACK/RAck；彩铃面） |
| HOLD 保持恢复 | T-31 sip_hold_resume | A（批二，RFC 3264 §6：re-INVITE sendonly→sendrecv 三轮事务） |
| INFO DTMF | T-32 sip_info_dtmf | A（批二，RFC 2976：dtmf-relay 体带外按键；IVR 面） |
| 302 呼转 | T-33 sip_302_redirect | A（批二，§8.1.3.4：Contact 目标重发 INVITE，Request-Line 钉） |
| UPDATE 会话刷新 | T-34 sip_update_session_timer | A（批二，RFC 3311/4028：Session-Expires；与 re-INVITE 对照） |
| INVITE 401 鉴权 | T-35 sip_invite_401_challenge | A（批二，§22.1 呼叫鉴权面：401→ACK→重发；与注册鉴权分格） |
| MESSAGE IM | T-36 sip_message_im | A（批二，RFC 3428 页模式；对话外单事务 min 联结） |
| 紧凑形头方言 | T-37 sip_compact_form | A（批二，§20 compact v=/f=/t=/i=/l=；方言透传） |
| 多跳 Via 链 | T-38 sip_via_chain | A（批二，3 Via+Record-Route/Route 代理拓扑头；Max-Forwards 68） |
| 超长头长 URI | T-39 sip_long_auth_uri | A（批二，§9.8：512B 级 Digest+226B URI；与 mss_segment 正交） |
| tel: URI+UTF-8 | T-40 sip_tel_uri_utf8 | A（批二，RFC 3966 互通+带引号 UTF-8 display name；E.164 面） |
| SDP 双流音视频 | T-41 sip_sdp_video_multistream | A（批二，多 m= 行 audio 0/8/101+video 96；§9.22 承载形状） |
| multipart 双体 | T-42 sip_body_multipart | A（批二，RFC 5621：SDP+octet-stream 双体；§3.14 单包多载荷） |
| 头名大小写混写 | T-43 sip_hdr_case_mix | A（批二，§7.3 头名不敏感：fRoM/cALL-iD 混写+解码双证） |
| 100 Trying+重传 | T-44 sip_100_trying_retrans | A（批三，§17.1.1.2 UDP 重传语义：同 CSeq 双 INVITE+100/180 provisional 类补格） |
| 并行分叉竞速 | T-45 sip_forked_invite | A（批三，多 tag 双支路 180×2→486 竞败+200 竞胜；多方同时振铃） |
| 会议加入+名册 | T-46 sip_conference_join | A（批三，RFC 4579/4575：焦点 URI+conference-info XML 名册 NOTIFY） |
| Replaces 询转 | T-47 sip_replaces_attended | A（批三，RFC 3891：Refer-To 内嵌 Replaces（URL 编码）+sipfrag 200；与盲转分面） |
| offerless 3PCC | T-48 sip_offerless_3pcc | A（批三，RFC 3725 流 I：无体 INVITE→200 带 offer→ACK 带 answer） |
| PUBLISH 在线状态 | T-49 sip_publish_presence | A（批三，RFC 3903：pidf 体+SIP-ETag/If-Match 软状态刷新） |
| Reason Q.850 | T-50 sip_reason_q850 | A（批三，RFC 3326：双 Reason 头 Q.850 cause16+SIP cause200） |
| IMS 私有头 | T-51 sip_ims_pheaders | A（批三，RFC 3325/3323：P-Preferred/P-Asserted+Privacy+P-CSCF Route） |
| History-Info 呼转链 | T-52 sip_history_info_fwd | A（批三，RFC 4244：302 后重发带历史条目；与素呼转分面） |
| 491 glare | T-53 sip_491_glare | A（批三，§14.2 re-INVITE 竞争收 491→ACK） |
| 并发交错双呼 | T-54 sip_interleaved_two_calls | A（批三，§9.9 并发交错字面：A/B 事务重叠序；与 T-27 顺序版分格） |
| 4xx 枚举长尾 | T-55 sip_status_enum_4xx | A（批三，§9.20：403/408/480/481/488 五格） |
| 5xx/6xx 枚举 | T-56 sip_status_enum_56xx | A（批三，§9.20：503+600；与 500/603 分格） |
| v6×多流矩阵 | T-57 sip_v6_port_dyn | A（批三，§9.23 地址族×结构：fd00+动态端口+flows=2；TCP 载体 9 包/流×2=18） |

**批三（2026-09-20，用户复审"多方同时通话没考虑全"→再核 RFC 3261 全方法/响应码表+CORE_MEMORY §9.9/§9.23=多方维度+方法收尾+矩阵补格 14 例=57 例，57/57 ×2 稳态+反查 68/68）：** 多方维度三面=并行分叉（流内多 tag 竞速）/会议（焦点+名册事件）/询转（Replaces）；方法面 12→13（+PUBLISH）；offer/answer 方向翻转（offerless）；响应码累计 1xx{100,180,183}/2xx/3xx{302}/4xx{401,403,404,408,480,481,486,487,488,491}/5xx{500,503}/6xx{600,603}（长尾冷码 405/406/410/412/413/415/416/420/421/423/482-485/489/493/494/501/502/504/505/513/580/604/606 等同构可表达=按需扩充注记）；§9.23 矩阵 v6×多流格落定（TCP 载体=引擎合同，9 包/流）。P5 校准 3 处：双重嵌套 JSON（工具脚本错）13 例 error、包位偏移 2 处、T-57 TCP 载体包数 18。

**补充批二（2026-09-20，用户复审"业务不够真实不复杂"→对照 ftp 面铺设现网业务 12 例+数据 7 例=43 例，43/43 ×2 稳态+反查 54/54）：** 方法面从 {INVITE,ACK,BYE,REGISTER,OPTIONS,PRACK,CANCEL} 扩到 +{REFER,NOTIFY,SUBSCRIBE,INFO,UPDATE,MESSAGE}=12 方法全主流面；新增引擎合同发现 2 条如实注记：①紧凑 i: 头不进头补全长形识别（引擎另补自动 Call-ID 双值并存=合同边界）；②application/isup 合成字节触发 tshark ISUP 解析器 malformed（改 octet-stream，不造假 expert 红）。P5 校准 5 处：包序偏移 4 处（BYE 位次按消息序重算）+Content-Length 248=引擎按 body 精确回填。

**补充批（2026-09-19，§3/§9 对抗复审后 A 类补例 6 例=24 例，24/24 一次全绿+反查 35/35）：** 触发原因=用户质询 sip 用例覆盖面。审计结论：文档无责（§3.15/§9.9/§9.10/§9.11/§9.25 条条明确），P3 枚举口径错位——拿 legacy 能力面当边界，而 dialog 是任意消息序列（method 任意串/status_code 任意整数），多事务/非正常结束/保活/状态码大类/组合流二全部现有引擎零改动可构建。B 类引擎结构缺口 5 项立项进 D-SIP-1"明确不解决"（sessions[] 多会话、每流 Call-ID/CSeq/branch 唯一化、NAT rport 方言、RTP 与 dialog 双向交错、SIPS/TLS 原有）。

| VSA 248B 超长拒 | T-22 radius_neg_vsa_len | A（负例，锚词 `exceeds the 247-byte field limit`；§9.8 超长×VSA 位型，与 T-16 的 253 门分锚） |
| 普通 attr 恰 253B | T-23 radius_attr_boundary | A（正例，边界等值格 253 过/254 拒对偶；avp.length=255 恰满 1 字节） |
| 现网 NAS 组合 | T-24 radius_nas_combo | A（正例，Service-Type/NAS-IP/Calling-Station/Message-Authenticator 四属性承载；MA 仅 opaque 字节位型） |
| CoA 43 白名单外拒 | T-25 radius_neg_coa | A（负例，RFC 5176 现网真实码比 T-10 假码 42 更现网；CoA 族支持=B′ 立项） |

**P5 校准实录（25/25 落盘重钉）：** ①tshark 同包多 AVP 字段逗号拼接（avp.type "1,8,5,6,26"、avp.length "6,6,6,4,10"）——length 按 value 实长+2 复算（user=4→6，非值域臆算）；②tshark 对 11→11/12→13 非标准对不标 rsp/reqframe（空）——方向改用 udp.srcport/dstport 交换钉；③port_dyn 4 包=2 流×(req+resp)，响应端口交换→src/dst 双向各聚 4 值 distinct_values（不钉包位）；④flow_control 键名实为 strategy_fc（sip 先例一致）。
**C 类注记（9.17）：** ①随机面 RTP seq/ts/ssrc+TCP ISN+ip.id 断言避开（RFC 3550 合同）；②SDP future-bleed（:769 全 dialog 扫描——用例避开 re-INVITE 后端口变化场景=T-13 注记）；③MSS 链路径固定 1460（spec.TCP 不可达 1.12）；④RFC 3261 Timer/重传不做（合成器合同）；⑤validateLayer IP parse/MSS 锚词链不可达（schema 先拦/spec.TCP 不可达）=零死锚词。
**枚举取值覆盖（9.20-9.22）：** 方法{INVITE,ACK,BYE,REGISTER,OPTIONS}✓（T-1/6/7）；响应码{100,180,200,404}✓（T-1/8）；头补全三态{user 赢,生成,纯响应 verbatim}✓（T-5/T-4/T-1 响应回显）；RTP PT{0,8?}——**PT 8 缺格→裁定：T-11 扩双值（media payload_type 0 断言+rtp.pt 单格）或视为单分支代表（0=PCMU 缺省）注记**——保持 T-11 PT0 单格+注记（PT 仅 1B 值拷贝 :865 同分支）；承载位置{dialog body/headers 数组/media 子结构}✓（T-9/T-5/T-11-14）；端口{显式,缺省,动态}✓（T-1/T-16/T-17）；地址族{v4,v6}✓（T-15）。
**正交矩阵：** 方法×响应×方向×{有/无 media}×地址族——落格见上表；动态整格=业务 2 键全关+端口 2 键（T-17）。
**通用陷阱自查（9.37-9.40）：** RTP 端口=SDP 派生非父+1（3.37 不适用）；T-17 group_id 固定；RTP 帧插在 EmitMedia 消息与下一条消息之间（wire order=emit order 同 worker 保序 :14）。
**断言边界（9.27）：** RTP seq/ssrc 随机不钉；MSS 分段末段长度=首跑校准；RTP 帧 payload 零填充面（无 FileSource 时 frameSize 字节零值占位 :851-853）不钉长度断言以外的内容。
**执行口径：** P5 sip 真实流程全量全绿+落盘 `/tmp/mcp-pcaps/sip/`+门 2 四项+反查 check_sip；数值落盘重钉（14.6/9.31）；**服务端验证=服务器重编重启**（h323 教训）。
**实现位置：** `cases/sip.json`（**18 例**：改写 1+新建 17）。

### T-RADIUS-1…25 radius.json——存量审计 + 测试点清单【D-RADIUS-1 P5 全绿 25/25】

**状态：** P5 全绿（2026-09-19，25/25 + 覆盖反查 44/44 + 门2 静态四项绿 + 五协议回归绿）。P3 定稿存量 1 例逐条审计改写（等价迁移：spec 仅 `{"radius":{}}` 本无扁平键→补 layers[ip] 显式 10.0.0.1/20.0.0.1+radius 层显式端口 12345/1812（worker/缺省缺省显式化，mpls 轮先例）；packet_count 2+14 fields（tshark radius.code/id/length/req/rsp/reqframe/authenticator nonzero+avp.type/length）全保留）+ 新建 20 例=21 例。
**级别：** pcap
**来源：** ①标准=RFC 2865（§3/§5）+RFC 2866（§3）②设计=D-RADIUS-1 ③现网=参考 pcap portion_Radius.pcap/start-stop.pcap（radius.go:17-18）+存量探针实测（length 26/20、id 复刻、authenticator nonzero）
**存量去向（1 例 → P5 改写后 21 例）：**

| 存量 | 去向 | 说明 |
|---|---|---|
| radius_smoke_01 | 改写 | 补 ip 层+显式端口+radius 层空业务面；packet_count 2+14 fields 保留等价——字节一致由 P5 实证（code1→2 auto/length 26/20/id 0 复刻） |

**新建例清单（T-2…21）：**

| 测试点 | 用例 | 类别/说明 |
|---|---|---|
| 顶层 radius presence 判死 | T-2 radius_flat_presence | A（负例，锚词 `top-level radius sub-config`；create-time） |
| radius 层静态端口+flows=2 拒 | T-3 radius_flat_static_port | A（负例，锚词 `static four-tuple`；create-time） |
| Accounting 分流 1813 | T-4 radius_acct_1813 | A（正例，code:4→dstport 1813+auto resp 5；**:770 顺序修正专项**（translate 自补覆盖预写 1812）；参考 start-stop.pcap 面） |
| Challenge 显式响应码 | T-5 radius_challenge | A（正例，code:11+response_code:11→对（3/11 无 auto 必须显式合同）；请求码 11+响应码 11 枚举格） |
| Status-Server/Client | T-6 radius_status | A（正例，code:12→auto 13；探询对） |
| Access-Reject 请求码格 | T-7 radius_code3 | A（正例，code:3+response_code:3→请求码 3 枚举格（requestCodes 含 3=legacy 合同）） |
| 失败分支 Reject 响应 | T-8 radius_reject | A（正例，code:1+response_code:3→Access-Request 被拒（失败分支 3.7/9.9）；radius.code 1→3 断言） |
| 无默认响应拒 | T-9 radius_neg_no_auto | A（负例，code:3 无 response_code→`has no default response code`；task-time） |
| 请求码非法 | T-10 radius_neg_reqcode | A（负例，code:42→`invalid request code`；task-time） |
| 响应码非法 | T-11 radius_neg_rspcode | A（负例，response_code:9→`invalid response code`；task-time） |
| fixed authenticator 钉值 | T-12 radius_auth_fixed | A（正例，authenticator:"000102...0f" 16B hex→请求帧 radius.authenticator **值断言**（唯一可钉值格）；响应侧 nonzero（恒随机）） |
| authenticator 非法 hex | T-13 radius_neg_auth_hex | A（负例，authenticator:"zz"→`invalid authenticator hex`；task-time） |
| authenticator 长度错 | T-14 radius_neg_auth_len | A（负例，15B hex→`must be 16 bytes, got 15`；task-time） |
| 属性四 format+VSA | T-15 radius_attr_formats | A（正例，attributes:[string "user"/ipv4 10.0.0.1/uint32 42/hex "aabb"/{type:1,vendor_id:9,value:"vs"}]→avp.type 逐断言+VSA type 26 外层（:432-445）；9.20-9.22 承载位置双列表 attributes/response_attributes 各≥1 格——response_attributes 并入本例响应面） |
| 属性超长 | T-16 radius_neg_attr_len | A（负例，string 254B→`exceeds the 253-byte field limit`；task-time） |
| format 非法 | T-17 radius_neg_format | A（负例，format:"dword"→`unknown format`；task-time） |
| rounds 多轮 | T-18 radius_rounds | A（正例，rounds:3+identifier:5→6 包；radius.id 5/6/7 递增断言（identifier+round 合同；rounds>256 uint8 回绕=C 注记用例避开）） |
| v6 正例 | T-19 radius_v6 | A（正例，ip 层 v6→2 包同构；9.24 地址族对称） |
| 缺省端口 1812 | T-20 radius_default_port | A（正例，radius 层无端口→udp.dstport=1812（translate 顺序修正覆盖路径）；src worker 保底） |
| 端口动态 E1 | T-21 radius_port_dyn | A（正例，src_port/dst_port 动态对象+flows=2→group_id 固定 2 流×2=4 包端口逐流） |

| VSA 248B 超长拒 | T-22 radius_neg_vsa_len | A（负例，锚词 `exceeds the 247-byte field limit`；§9.8 超长×VSA 位型，与 T-16 的 253 门分锚） |
| 普通 attr 恰 253B | T-23 radius_attr_boundary | A（正例，边界等值格 253 过/254 拒对偶；avp.length=255 恰满 1 字节） |
| 现网 NAS 组合 | T-24 radius_nas_combo | A（正例，Service-Type/NAS-IP/Calling-Station/Message-Authenticator 四属性承载；MA 仅 opaque 字节位型） |
| CoA 43 白名单外拒 | T-25 radius_neg_coa | A（负例，RFC 5176 现网真实码比 T-10 假码 42 更现网；CoA 族支持=B′ 立项） |

**P5 校准实录（25/25 落盘重钉）：** ①tshark 同包多 AVP 字段逗号拼接（avp.type "1,8,5,6,26"、avp.length "6,6,6,4,10"）——length 按 value 实长+2 复算（user=4→6，非值域臆算）；②tshark 对 11→11/12→13 非标准对不标 rsp/reqframe（空）——方向改用 udp.srcport/dstport 交换钉；③port_dyn 4 包=2 流×(req+resp)，响应端口交换→src/dst 双向各聚 4 值 distinct_values（不钉包位）；④flow_control 键名实为 strategy_fc（sip 先例一致）。
**C 类注记（9.17）：** ①随机面：响应 Authenticator 恒随机（:343）断言仅 nonzero；请求缺省随机（T-12 fixed 钉值方案）；ip.id 不断言；②响应 MD5 验证不做（legacy 随机合成=C 合同）；③IP parse/nil 两锚词链不可达（schema 先拦/translate 恒填）=零死锚；④rounds>256 uint8 回绕避开。
**枚举取值覆盖（9.20-9.22）：** 请求码{1(T-1),3(T-7/T-9),4(T-4),11(T-5),12(T-6)}✓5/5；响应码{2(T-1 auto),3(T-7/T-8),5(T-4),11(T-5),13(T-6)}✓5/5；format{string,ipv4,uint32,hex}✓4/4（T-15）+VSA✓；rounds{1,3}✓；端口{显式,缺省,动态}✓（T-1/T-20/T-21）；地址族{v4,v6}✓（T-19）；负例 11✓（T-2/3/9/10/11/13/14/16/17 + T-22 VSA 247 门 + T-25 CoA 43——全部 legacy 真门锚词）。
**正交矩阵：** 码×响应（auto/显式/无）×format×端口×地址族——落格见上；动态整格=业务 7 键全关+端口 2 键（T-21）。
**通用陷阱自查（9.37-9.40）：** 无派生端口；T-21 group_id 固定；id 复刻+递增=真实语义钉（存量先例）。
**断言边界（9.27）：** 响应 authenticator 恒随机仅 nonzero；包间隔无面。
**执行口径：** P5 radius 真实流程全量全绿+落盘 `/tmp/mcp-pcaps/radius/`+门 2 四项+反查 check_radius；数值落盘重钉（14.6/9.31）；**服务端验证=服务器重编重启**（h323 教训）。
**实现位置：** `cases/radius.json`（**25 例**：改写 1+新建 20+补充批 4）。

### T-SIP-58…71 sessions[] 多会话（D-SIP-2 WP-A P3 清单）

**状态：** P5 全绿（2026-09-20，71/71 ×2 稳态+落盘 66 正例 pcap 对账精确+门 2 静态四项绿）。P3 定稿（2026-09-20）：三源=RFC 3261 §12（dialog 标识）+D-SIP-2 WP-A+Kamailio 多 dialog 并存行为（子表③）。**P5 校准 5 处（14.6/9.31 落盘重钉）：** ①genPort 五策略合同补 pattern 口（12.1 缺口，T-68 即失败测试）②sessions 嵌套 dyn 扫描补 call_id 对象入 hasDyn（T-69/70 误拒修复）③rand seed=7 钉值 23187/23189④v6 派生 Call-ID 主机部括号形（sipHostOf RFC 19.1.1 口径）⑤list 项须字符串（StrategyConfig.List []string 合同，整型写法解析空落缺省）。
**级别：** pcap。**存量去向：** 57 例等价保留（dialog 路径零字节回归线）。

| 测试点 | 用例 | 类别/说明 |
|---|---|---|
| 双会话独立面 | T-58 sip_sessions_two_dialogs | A（正例：2 session 独立 call_id/独立端口/独立生命周期；2×(3+2+4)=18 包） |
| 派生 Call-ID | T-59 sip_sessions_derived_callid | A（call_id 缺省派生 `{flow}-{sess}@{srcIP}` 断言；12.4 可复现） |
| 显式赢 | T-60 sip_sessions_explicit_wins | A（消息内显式 Call-ID 头 > session.call_id > 派生；user-wins 保持） |
| 互斥判死 | T-61 sip_neg_sessions_dialog_mutex | A（负例，锚词 `sip: sessions and dialog are mutually exclusive`；create-time） |
| 空数组 | T-62 sip_neg_sessions_empty | A（负例，同锚词面） |
| 静态复制拒 | T-63 sip_neg_sessions_static | A（负例，sessions 内标量端口+flows=2→`static four-tuple`） |
| 端口动态整格 | T-64…68 sip_sessions_port_{inc,rand,list,fixed,pattern} | A（9.32/12.15 五策略逐格 flows=2；distinct 断言；rand seed 钉/回绕格） |
| call_id 动态 | T-69/70 sip_sessions_callid_{pattern,fixed} | A（flows=2 逐流 Call-ID 断言） |
| v6 对称 | T-71 sip_sessions_v6 | A（9.24：fd00 双栈双会话格） |

**动态整格（9.32）：** sessions[].src_port×五策略（T-64…68）+call_id×2（T-69/70）=7 格本 WP 落满；medias[].src_port 归 WP-B。**9.40 注记：** 同流多 session 共享 FlowIndex→动态对象同值=真实语义（session 差异锚派生缺省端口 base+M+idx 与 call_id 派生序，不锚 FlowIndex）。**断言边界：** 时间戳=发射序；branch 派生仅 sessions 模式（dialog 模式随机=零字节回归线）。
**实现位置：** cases/sip.json（71 例）。验收=CASE_PROTO=sip 全量绿+57 例零字节回归+门 2 四项+反查表扩条目。

### T-SIP-72…76 medias[] 多流双向+交错（D-SIP-2 WP-B P3 清单）

**状态：** P5 全绿（2026-09-20，76/76 ×2 稳态+落盘 70=76−6 对账精确+门 2 静态四项绿+反查 87/87）。三源=RFC 3550 §5.1（RTP 双向）+D-SIP-2 WP-B+现网双向通话面。**级别：** pcap。
**存量去向：** media 单流 5 例等价保留（单流路径字节等价由流重构守，emitSIPMedia=流对象包装）。

| 测试点 | 用例 | 类别/说明 |
|---|---|---|
| 双向交替 | T-72 sip_medias_bidirectional | A（up/down 同点 round-robin；显式端口分两流四元组；down wire 元组交换校准） |
| 交错调度 | T-73 sip_medias_interleave | A（T=4/G=3→2/1/1；包位 5,6 RTP/7 200/8 RTP/9 ACK/10 RTP 落盘钉） |
| 互斥判死 | T-74 sip_neg_medias_mutex | A（负例，锚词 `sip: media and medias are mutually exclusive`） |
| 端口动态 | T-75 sip_medias_port_dyn | A（medias src_port inc+flows=2；dyn>静态>SDP>5004 优先链） |
| file_source 沿用 | T-76 sip_medias_filesource | A（Task 12 FileSource>inline 合同经多流形态） |

**P5 校准 3 处（14.6 落盘重钉）：** ①down 方向 wire 元组交换（src=dstPort）②包位含 INVITE 自身偏移 ③udp 聚合不含 TCP 端口（9.38 口径）。**gap0 双发 bug** 单测捕获修正（媒体点不发射，hook/尾部分担 R+1 gap）。
**实现位置：** cases/sip.json（**76 例**）。

### T-SIP-77…80 NAT rport/received 回填（D-SIP-2 WP-C P3 清单）

**状态：** P5 全绿（2026-09-20，80/80 ×2 稳态+门 2 静态四项绿+反查 91/91）。三源=RFC 3581 §4（rport 参数对称回填）+D-SIP-2 WP-C+现网 NAT 穿越面。**级别：** pcap。
**存量去向：** 无（新增能力面；缺省透传例 T-79 兼作 57 例零漂移回归线的本格）。

| 测试点 | 用例 | 类别/说明 |
|---|---|---|
| bare rport 回填 | T-77 sip_nat_rport_fill | A（Via 带 bare `;rport`→发射期回填 `rport=12001;received=10.0.0.1`；响应侧回放原文零二次改写） |
| 开关强制 | T-78 sip_nat_switch_forces | A（`nat.rport=true` 且 Via 无标记→开关代客户端补参数对至尾部） |
| 缺省透传 | T-79 sip_nat_default_passthrough | A（无 nat 无标记→Via 原样；字节零漂移线） |
| 会话真值端口 | T-80 sip_nat_sessions_port | A（sessions 模式回填=会话实际端口 22001 非 spec 12001；单条 OPTIONS 无响应=8 包 pcap 校准） |

**P5 校准 1 处（14.6 落盘重钉）：** T-80 `min_packets` 9→8（单 session 单消息无响应=3 握手+1 消息+4 挥手，落盘 pcap 实测）。
**实现位置：** cases/sip.json（**80 例**）；`rewriteViaRPort`（internal/protocol/sip/sip.go）；`SIPNAT{RPort}`（internal/core/types.go）。

### T-SIP-81…86 SIPS/TLS 事件面（D-SIP-2 WP-D P3 清单）

**状态：** P5 全绿（2026-09-20，86/86 ×2 稳态+门 2 静态四项绿+反查 97/97）。三源=RFC 3261 §26.2.1/§26.2.2+RFC 5630 §2.6+D-SIP-2 WP-D。**级别：** pcap。
**存量去向：** 无（新载体面；[ip,sip] 自驱 80 例零回归线不动，isRawIPChain 增传输层守卫后逐字节复验）。

| 测试点 | 用例 | 类别/说明 |
|---|---|---|
| SIPS OPTIONS over TLS | T-81 sip_tls_options | A（[ip,tcp,tls,sip]；16 包=3 握手+7 TLS record+2 app-data+4 挥手 pcap 钉） |
| REGISTER over TLS | T-82 sip_tls_register | A（同形状；tls 缺省 cert 全数据） |
| 纯 tcp 事件面 | T-83 sip_tcp_options | A（明文线：sip.Method/CSeq/Via tshark 直查；响应 Via 回显=§8.1.3.2 same_as_packet） |
| tls×media 判死 | T-84 sip_neg_tls_media | N（锚词 `media is not supported on a tcp/tls sip chain`，RTP 裸 UDP 流不进传输） |
| sips 无 tls 判死 | T-85 sip_neg_sips_no_tls | N（锚词 `sip: sips uri requires a tls layer in the chain`，RFC 3261 §26.2.2） |
| tls×sessions 判死 | T-86 sip_neg_tls_sessions | N（锚词 `sessions are not supported on a tcp/tls sip chain`，一链一连接） |

**P5 校准 3 处（14.6 落盘重钉）：** ①isRawIPChain 红线修复——终层 sip 且链含 tcp/udp 时不得走 raw 自驱分支（事件面被拦截→TLS record 全丢，离线复现 tlsRecords=0 定位）；②drive 内联 meta 清单补 `SIP: spec.SIP`（此前 raw 分支走 flowMetaFor，事件面清单缺字段→空流）；③T-83 Via branch 随机不可跨跑钉值→same_as_packet 回显断言+确定性前缀由单测钉。
**实现位置：** cases/sip.json（**86 例**）；`event_gen.go`（新）/`InitChain` 钩子（chain_planner_chain.go）/`isRawIPChain` 守卫（chain_planner_util.go）/`checkSIPEventPlane`（semantic.go）；链级回归 `TestChainPlanner_SIP_TLSChain`（16 包形状离线钉）。

### T-SIP-87…96 场景覆盖强度补强批（CORE_MEMORY 9.46–9.53 增补后首批，用户裁定排在 #21 pppoe 之前）

**状态：** P5 全绿（2026-09-20，96/96 ×2 稳态+门 2 静态四项绿+反查 107/107）。三源=RFC 3261 §21 响应码全表+§22.3 代理鉴权+RFC 4028 §6 会话定时器+RFC 3265 §7 SUBSCRIBE+RFC 3312 §5 前置条件+9.46 数据边界。**级别：** pcap。
**存量去向：** 无（纯增量）。

| 测试点 | 用例 | 类别/说明 |
|---|---|---|
| 复合大场景（9.50） | T-87 sip_conf_burst_3party | A（五类交织单例：三方多会话+会话内多事务 re-INVITE/BYE+RTP 双向多流关联+486/CANCEL/487 异常+NAT rport；42 包 pcap 钉；**抓出 parse 真 bug**：ParseSIPSessions 漏 Medias/Interleave 接线，RTP 静默不发射，parse 层红例先行修复） |
| 2xx 非 200 分支值 | T-88 sip_resp_202_refer | A（REFER→202 Accepted；Refer-To 头形） |
| 3xx 列表数据形 | T-89 sip_resp_300_contacts | A（300 多 Contact 逗号列表三实体） |
| 代理鉴权头族 | T-90 sip_resp_407_proxy_auth | A（Proxy-Authenticate≠401 的 WWW 族；Digest realm/nonce/qop 形） |
| 扩展协商失败 | T-91 sip_resp_420_bad_extension | A（Require 未知扩展→420+Supported 头形） |
| 会话定时器协商失败 | T-92 sip_resp_422_session_timer | A（RFC 4028 §6：Session-Expires→422+Min-SE；与 update_session_timer 成败对称） |
| 同码不同上下文（9.21） | T-93 sip_resp_489_bad_event | A（SUBSCRIBE Event 未知→489；非 INVITE 无 ACK=9 包 vs INVITE 类 10 包） |
| Retry-After 头形 | T-94 sip_resp_503_retry_after | A（503 过载+Retry-After: 30 现网常见形） |
| 用户 CL 禁二次追加（9.46） | T-95 sip_hdr_cl_user_wins | A（body+精确 CL 并存→单 CL 行原值；与 T-78 双 Call-ID 契约边界同族） |
| 空条目跳过语义（9.46） | T-96 sip_msg_empty_entry_skipped | A（dialog 空消息条目不产包不报错=文档化语义钉；9.18 可表达=A 类） |

**P5 校准 3 处（14.6 落盘重钉）：** ①INVITE 终响应类（req+final+ACK）=10 包非 9（漏数 INVITE 自身）；②T-95 CL 与 body 长度不符→tshark malformed（配置自洽错误非引擎问题，python 算准 body 实长）；③T-87 down 流 wire 元组交换 src=dstPort（WP-B 校准同款陷阱复发）→down 流显式 dst_port=30006 分面。**parse 修复=1 处：** ParseSIPSessions += Medias/Interleave（parse 层红例 TestParseSIPSessionsPerSessionMedias 先红后绿；planner 直构 spec 的旧单测覆盖不到此层）。
**实现位置：** cases/sip.json（**96 例**）；strategy_convert.go ParseSIPSessions；sip_sessions_parse_test.go（新）。

**9.46/9.47 响应码全表对账（9.52 必答，清单出处=RFC 3261 §21+IANA 注册表，非现有用例反推）：**

| 分支 | 码 | 代表例/去向 |
|---|---|---|
| 1xx 暂态 | 100/180/183 | T-1/T-8/T-30（同分支同形状，199 RFC 6228 按分支注记） |
| 2xx 成功 | 200 | T-1；**202** → T-88；204 RFC 5839 按分支注记 |
| 3xx 重定向 | 302 | T-40；**300 多 Contact 列表** → T-89；301/305/380 同分支注记 |
| 4xx 客户错误 | 401/403/404/408/480/481/486/487/488/491 | T-47/T-42/T-8/T-9/T-53 区段/T-10/T-14/T-25/CANCEL 链 T-45/491 glare T-55；**407 代理族** → T-90；**420** → T-91；**422** → T-92；**489** → T-93；400/402/405/406/410/412/413/414/415/416/421/423/482/483/484/485/493 及深扩展（417/424/428/429/430/433/436/437/438/439/440/469/470/494）同分支注记（回放语义下与已建例同 wire 形状=9.21 分支代表） |
| 5xx 服务错误 | 500/503 | T-56 区段/94；501/502/504/505/513/580 RFC 3312 同分支注记 |
| 6xx 全局失败 | 600/603 | T-56 区段/603 decline；604/606/607 同分支注记 |

**对账两行：** RFC 3261 §21+IANA 响应码逻辑点总数≈57 项 → 分支代表建例 **25** 码（6 分支全覆盖）+ 32 码按 9.21 分支注记（同分支同 wire 形状，逐值扩充按需）= **57/57 对账平**。字节序 n/a（文本协议）；字符集=tel_uri_utf8 已覆。

### T-PPPOE-1…24 pppoe 层链收敛（D-PPPOE-1 P3 清单，2026-09-20；P5 已执行 24/24 ×2 全绿，2026-09-20）

**三源：** RFC 2516（§4/§5/§5.6/§7）+RFC 1661（§4/§5/§6/§8）+D-PPPOE-1+现网 BRAS 行为（AC-Name/Cookie/Host-Uniq）。**级别：** pcap。
**存量去向（9.14）：** `pppoe_discovery_session_lcp` 1 例扁平（`{"count":1,"pppoe":{}}`）→ 改写层链形合入 T-1（等价覆盖+PADT 重校准，原 7 帧→8 帧）。

**数据场景全表（9.46/9.47，出处=规范原文）：**

| 表 | 枚举 | 建例/去向 |
|---|---|---|
| Code 全表（RFC 2516 §5） | 0x00/0x09/0x07/0x19/0x65/0xa7 | 生命周期例逐帧断言（T-1…6/14）；非法码=builder 面 n/a 注记（planner 自管 code 不透出） |
| TLV 标签表（§5.1） | 0000/0101/0102/0104 发射+0110 builder 支持未编排+0103/0105/0201/0202/0203 未实现 | T-9/T-10 断言 0101/0102/0104 值；0103 Host-Uniq=B′ 注记（真实客户端关联标签）；0201 PADS 错误标签=B′ 注记 |
| PPP 协议字段（RFC 1661 §5） | 0x0021/0xc021/0xc023/0xc223 发射+0x8021 IPCP 未编排 | 生命周期例逐帧断言；**缺口 F：IPCP 阶段**（现网拨号先协商地址再传数据；引擎数据面地址来自配置非协商，v1=B′ 立项注记不实现） |
| LCP 选项（RFC 1661 §6） | MRU(type1)/Magic-Number(type5)/Auth-Protocol(type3 分支) | T-1 缺省 1492 断言/T-11 显式 MRU+Magic 钉值/T-4 无 auth 无 type3 分支/T-5 c023/T-6 c223 |

**边界（9.46）：** 空 Service-Name=零长标签 any-service（T-9）；cookie nil/显式（T-10）；MRU 0→缺省 1492（T-1）；data_frames 0=**缺省 1 数据帧**（P5 勘误：原写『无数据帧』与实现 frames==0→1 不符，T-8 按实现语义钉）；超大 data_payload（T-16 内）；字节序 n/a（协议字段网络序由 builder 恒定，注记）。

**业务场景（9.48/9.49）：** 全生命周期（T-1）/padt=false（T-2）/skip_discovery（T-3）/auth none（T-4）/pap（T-5）/chap（T-6）/data_direction down（T-7）/inner_proto UDP（T-18）/多会话派生 ID（T-12）/多会话显式 ID（T-13）/复合大场景（T-14：sessions[2]+chap+双向 data+PADT+skip 混杂 ≥3 类交织=9.50）。
**现网（9.10）：** BRAS 三标签形（T-10）/any-service（T-9）。
**负例（14.11，锚词全部真实流程断言）：** 非法 auth（T-19 既有锚词）/非法 inner_proto（T-20）/DataFrames<0（T-21）/内嵌 IPv6（T-22）/sessions×顶层键互斥（T-23 新锚词 `pppoe: sessions and top-level session config are mutually exclusive`）/duplicate session_id（T-24 新锚词 `pppoe: duplicate session_id`）。

**9.40 陷阱注记：** sessions 派生=**会话序号 i**（SessionID 1+i 逐会话递增，非流序号共享同值——与 sip 动态对象按 FlowIndex 解析语义不同，断言按会话真实语义钉）。
**实现位置：** cases/pppoe.json（**24 例**，T-1 改写+T-2…18 新建+T-19…24 负例）。

**9.52 对账两行：** RFC 2516/1661 逻辑点总数 **45**（code 6+TLV 10+PPP 协议 5+LCP 选项 3+边界 5+业务变体 8+现网 2+负例分支 6）→ 建例/分支代表 **39** + 注记 6（TLV 0103/0105/0110/0201/0202/0203 B′ + IPCP 缺口 F + 非法码 n/a）= **45/45 对账平**。清单出处=规范原文逐表反推，非现有用例总结。

**P5 执行记录（2026-09-20）：** cases/pppoe.json 24 例层链形（T-1 smoke 改写 7→8 帧重校准；T-15/16/17 为 P3 清单编号空洞的补定义：inner_proto 显式 TCP/data_payload 字节钉/data_frames=2 多帧——均属既有表行 inner_proto 分支与 data_payload 边界的落实，非新场景）；suite ×2 连续全绿 `RESULT: 24 pass, 0 fail, 0 error (of 24)`；pcap 19 正例+3 neg（T-21/23/24 create-time 拒绝无 pcap）；tshark 复查 T-1 八帧 code 序（09/07/19/65/00×3/00 21/a7）与 T-12 三会话独立 Discovery+PADT 1/2/3。**首跑抓真 bug 1：parsePPPoEConfig 漏接 padt 键（层链路径 padt:false 被静默丢弃恒发 PADT，ParseSIPSessions 漏 Medias 同型）→补 getBoolPtr 解析+parse 层锁例 TestParsePPPoEConfigPADTPtr**；byte 校准 4 处（Auth-Proto 选项 4B 非 6B→LCP len 0x12；tags 起点 offset 20 非 18；chal ppp proto 首字节 c2；payload offset 50）；cookie 用字节数组（getByteSlice 字符串=原文字节，hex 串被当 ASCII）；T-21 锚词随真实拦截面（registry V9 范围门先于 planner Validate）；T-22 改同族 IPv6（混族被 ip 层 same-IP-version 先拦）；T-14 auth 按裁定 4 归顶层模板键（sessions 不覆盖模板）。

**P3 复审（2026-09-20，对抗走查）：** 抓 2 项 errata 已并入：①**层 Fields 计数终值=16**（planner 实际消费 14 键实测：ACName/Auth/Cookie/DataDirection/DataFrames/DataPayload/InnerProto/MagicNumber/MRU/Password/ServiceName/SessionID/SkipDiscovery/Username + padt + sessions；wire 键 code/ppp_protocol/payload_length/discovery_tags 为 builder 每包面不被流程消费→**不登记层 Fields**（1.12 消费面裁定，ValidateLayerConfig 拒之=正确行为），修正 P2 errata② 的 20）；②**sessions 互斥键集合精确化**：互斥=会话级行为键 {session_id, skip_discovery, data_frames, data_payload, inner_proto, data_direction}，模板键 {ac_name, service_name, auth, username, password, mru, magic_number, cookie, padt} 允许与 sessions 共存共享（裁定4"模板键共享"落到键级，P4 semantic 检查按此集合）。验证通过项：T-11 Magic 钉值可行（MagicNumber 在消费清单）；T-12 派生 1/2/3 与单会话缺省 1 自洽；9.51 组合注记（地址族 n/a=内嵌 IPv4 only，IPv6 即 T-22 负例）。**复审结论：自审 1 轮 2 项修正，清单净，待批进 P4。**

### T-LDAP-1…22 ldap 层链收敛（D-LDAP-1 P3 清单，2026-09-20；P5 已执行 22/22 ×2 全绿，2026-09-20）

**三源：** RFC 4511（§4.1.1 BER+messageID/§4.2 bind/§4.3 unbind/§4.5 search/§4.1.9 resultCode/§5.2 传输）+D-LDAP-1+现网 AD RootDSE 形（参考 pcap 15 属性）。**级别：** pcap。
**存量去向（9.14）：** `ldap-bind-search-basic` 1 例扁平 → 改写层链形合入 T-1（等价覆盖：包数/字段断言随层链端口显式化重钉）。
**层 Fields=15**（LDAPConfig 全字段，ParseLDAPConfigFromMap 全接）：rounds/message_id_base/version/bind_dn/bind_password/search_base_dn/search_scope/size_limit/time_limit/filter_type/search_filter/filter_value/attributes/result_code/unbind。

| # | 用例 | 断言面 | 出处 |
|---|---|---|---|
| T-1 | smoke 改写（层链形） | 全会话形：握手 3+bind 2+search 3+unbind+挥手 4；protocolOp 六标签 {60,61,63,64,65,42} 逐帧；端口 12345/389 显式 | §4.2-4.5 全序 |
| T-2 | BER 长形长度字节 | 15 属性 RootDSE searchRequest >127B → 长形长度前缀字节钉（pcap 校准不手算） | §4.1.1 |
| T-3 | messageID 递增钉 | rounds=2 → bind id {1,4}/search id {2,5}/unbind id 3（base 缺省 1） | §4.1.1.1 |
| T-4 | 匿名 bind（缺省） | bindRequest name 空串+simple [0] 空 OCTET STRING | §4.2.1 |
| T-5 | simple bind | bind_dn/bind_password 字节入 bindRequest（name+0x80 密码串） | §4.2.1 |
| T-6 | version=2 | bindRequest version 字节 02（缺省 03 由 T-1 钉） | §4.2.1 |
| T-7 | scope=singleLevel(1) | searchRequest scope 字节 01 | §4.5.1.2 |
| T-8 | scope=wholeSubtree(2) | searchRequest scope 字节 02（缺省 0 由 T-1 钉） | §4.5.1.2 |
| T-9 | equality filter | filter_type=equality+search_filter/filter_value → 0xa3 CHOICE+断言值字节 | §4.5.1.7 |
| T-10 | result_code=49 | bindResponse+searchResDone resultCode 0x31（invalidCredentials 失败分支） | §4.1.9 |
| T-11 | rounds=2 多轮 | 两完整 bind/search 序+messageID 续编 | 9.49 |
| T-12 | attributes 自定义 | AttributeSelection 2 属性（cn,mail）非 RootDSE 15 | §4.5.1.8 |
| T-13 | unbind=false | 无 0x42 帧，末数据帧后径直挥手 | §4.3 |
| T-14 | 复合大场景（9.50） | rounds=2+equality filter+非匿名 bind+自定义属性 ≥3 类交织单例 | 9.50 |
| T-15 | search base DN | search_base_dn 显式（非 RootDSE 空串） | §4.5.1.1 |
| T-16 | size/time limit 显式 | size_limit=10/time_limit=60 INTEGER 字节钉 | §4.5.1.3/4 |
| T-17 | 负例 version=4 | 锚词 `invalid version` | §4.2.1 |
| T-18 | 负例 scope=3 | 锚词 `invalid scope` | §4.5.1.2 |
| T-19 | 负例 filter_type=substring | 锚词 `invalid filter type` | §4.5.1.7 |
| T-20 | 负例 result_code=128 | 锚词 `out of ENUMERATED range` | §4.1.9 |
| T-21 | 负例 size_limit=-1 | 锚词 `size_limit must be >= 0` | §4.5.1.3 |
| T-22 | 负例 messageID 超限 | base 0x7FFF+rounds 2 → 锚词 `exceeds 0x7FFF` | §4.1.1.1 |

**边界注记（9.46）：** 超长 bind_dn（BER 长形 OctetString 内）=B′ 注记（T-2 已钉长形面）；time_limit=-1 与 size_limit 同门（T-21 代表，锚词面同族——对账记 1 分支）；filter_value 空+equality=空断言值（BER 04 00，T-9 不含=B′ 注记）。**9.40 陷阱：** 无 sessions/dyn 形态（单连接协议），messageID 是唯一序号锚（静态 base+3r 公式，非 FlowIndex）。
**P3 复审（2026-09-20，对抗走查）：** 表六标签/scope 三枚举/filter 双 CHOICE/bind 三面/resultCode 两分支/messageID 双面/unbind 三态逐项过——1 项补强：传输分段逻辑点的承接面=参考形 15 属性 searchRequest ≈200B < MSS 1460 单段（T-1 包数间接钉+segmentByMSS 单测 ldap_test.go 已存），多段分段面属 TCP 框架不重复计；time_limit 负例与 size_limit 同锚词族合并 T-21（已注记）。**复审结论：自审 1 轮 1 项并入，清单净，待批进 P4。**

**P5 执行记录（2026-09-20）：** cases/ldap.json 22 例层链形（T-1 改写等价覆盖：13 包=握手3+5 消息+unbind+挥手4，原 min_packets 12 为下限非钉值）；suite ×2 连续全绿 `RESULT: 22 pass, 0 fail, 0 error (of 22)`；pcap 16 正例+5 neg（T-17…21 create-time 拒绝无 pcap，T-22 同）。**byte 校准（pcap 实测非手算）：包数笔算普遍 -1（挥手 4 帧面重数）；BER 恒长形语义钉（berWrap 0x84+4B 长度，不做短形优化——bindReq SEQ len 0x10/searchReq 0x158/bindReq 内层 protocolOp 60 84 00 00 00 07）；messageID 实测帧序钉（rounds=2：bindReq 1/4、searchReq 2/5、unbind 6=base+3(r-1)+2，notes 初稿"unbind id 3"为 rounds=1 值笔误已校正）；T-21 锚词随 registry V9 真实拦截面（size_limit=-1 被 "not a numeric value in [0,2147483647]" 拦先于 planner Validate）**；端口面：包4 tcp.srcport=12345（worker 逐流保底）恒 389 的断言面=tcp.dstport。coverage_gate check_ldap 43/43 绿。

**9.52 对账两行：** RFC 4511 逻辑点总数 **38**（BER 4+操作标签 6+bind 组成 3+search 组成 8+filter CHOICE 2+resultCode 2+messageID 1+unbind 1+传输 1+负例分支 7+业务变体多轮/匿名 2+现网 RootDSE 1）→ 建例代表 **36** + 注记 2（filter_value 空断言+超长 DN B′；time_limit 与 size_limit 同门合并计）= **38/38 对账平**。清单出处=RFC 4511 原文逐章反推，非现有用例总结。

### T-RTMP-1…16 rtmp 层链收敛（D-RTMP-1 P3 清单，2026-09-20；P5 已执行 16/16 ×2 全绿，2026-09-20）

**三源：** Adobe RTMP spec（§5 握手/§6 chunk/§7-8 命令）+D-RTMP-1+参考 pcap（llcj 镜像 play 会话）。**级别：** pcap。
**存量去向（9.14）：** `rtmp-connect-play-basic` 1 例扁平 → 改写层链形合入 T-1（等价覆盖+端口显式化重钉）。
**层 Fields=5**（app/tc_url/command/stream_name/data——data 项内 direction/msg_type/chunk_stream_id/payload(_b64) 随 list 项）。

| # | 用例 | 断言面 | 出处 |
|---|---|---|---|
| T-1 | smoke 改写（play 全会话） | 握手3+RTMP 握手（C0C1/S0S1S2/C2 按 MSS 分段）+命令序+挥手；恒 1935=tcp.dstport | spec §5-8 |
| T-2 | RTMP 握手分段数 | C0C1 1537B→2 段（MSS 1460）、S0S1S2 3073B→3 段、C2 1536B→2 段；包数间接钉 | §5.2/5.3 |
| T-3 | chunk 基本头+消息头钉 | connect chunk 头 `03`（fmt0 csid3）+11B 消息头（len3+type 0x14+streamID 4B 小端）frames 钉 | §6.1.1 |
| T-4 | AMF0 connect 钉 | `02 00 07 connect`+txn `00 3f f0 00 00 00 00 00 00`（1.0）+命令对象 app/tcUrl | §7.2.1 |
| T-5 | 协议控制四消息 | WindowAck(5)/SetPeerBW(6)/StreamBegin(4)/SetChunkSize(1) msgType 逐包（服务端响应段） | §5.4-5.6 |
| T-6 | publish 模式 | command=publish→第三阶段 `02 00 07 publish` 替代 play | §7.2.3 |
| T-7 | stream_name 自定义 | play/publish 参数字节入 AMF0 串 | §7.2.3 |
| T-8 | app/tc_url 自定义 | connect 命令对象属性字节钉 | §7.2.1 |
| T-9 | 数据面音频 | msg_type=8+csid=4 chunk 头钉 | §11.4 |
| T-10 | 数据面视频 | msg_type=9+csid=6 chunk 头钉 | §11.4 |
| T-11 | 数据面双向 | up+down 各一 chunk（publish 推+play 拉混合面） | spec |
| T-12 | payload 显式 | payload_b64 解码字节透传（chunk 数据段 frames 钉） | parse 双形面 |
| T-13 | 复合大场景（9.50） | publish+自定义 app+音视频混合数据面 ≥3 类交织 | 9.50 |
| T-14 | 负例 App 超长 | >255B → 锚词 `App exceeds` | Validate |
| T-15 | 负例 Command 非法 | 锚词 `invalid Command` | Validate |
| T-16 | 负例 MsgType 非法 | data[0].msg_type=5 → 锚词 `MsgType` | Validate |

**边界注记（9.46）：** MSS<536 负例链路径不可达（[ip,rtmp] 无 tcp 层）=B′ 注记（3 锚建例）；payload 缺省 100B 随机（T-9/10 用长度间接钉）；C1/S1 随机 1528B 不断言值只断言长度与回显关系（T-2）。**9.40 陷阱：** 恒 1935 断言面=tcp.dstport（worker srcport 12345+i）。
**P5 执行记录（2026-09-20）：** cases/rtmp.json 16 例层链形（T-1 改写 20 包全序钉：握手3+C0C1 两段+S0S1S2 三段+C2 两段+connect+服务端五连+客户端 winack+createStream+setBufferLen+_result+play+挥手4）；suite ×2 连续全绿 `RESULT: 16 pass, 0 fail, 0 error (of 16)`。**byte 校准（tshark 实测非手算）：分段序 1460/77、1460/1460/153、1460/76 三组钉（T-2）；connect chunk `03 00 00 00 00 00 41 14 00 00 00 00 02 00 07 63 6f 6e 6e 65 63 74`+txn double 1.0（offset 76）；winack chunk `02...05...00 26 25 a0`=2500000；play chunk streamID 01 00 00 00（createStream 后流号 1）**。**tshark RTMP dissector "Loop in AMF dissection" 伪影处置**：命令面 5 帧 malformed 报警（tshark 自身解析出 connect()/_result() 消息名=AMF 编码合法），按 rtmp-connect-play-basic 先例扩层链族条目（`strings.HasPrefix(caseID, "rtmp_")`）入 pcaptest IsMalformedWhitelisted——**注意白名单生效面=服务端二进制内的 pcaptest，suite 验证跑在 MCP 侧，改白名单必须重编重启服务端**（本轮 3 跑红即此因）。coverage_gate check_rtmp 29/29 绿（T-7 补 tc_url 显式例）。

**9.52 对账两行：** Adobe RTMP spec 逻辑点总数 **21**（握手 4+chunk 格式 3+协议控制 4+AMF0 命令 6+CSID 1+数据面 2+负例分支 4-1 合并 MSS+现网 1→实际枚举=握手 4+chunk 3+协议控制 4+命令 6+CSID 1+数据 2+负例 3+现网 1 = **24**，其中建例代表 **16**（T-1 承接握手回显+现网形）+B′ 注记 **8**（fmt1-3、AMF3、其余命令族、MSS 负例、pause/seek/deleteStream、extended ts、加密握手 RTMPE、edge 会话形）= **24/24 对账平**。清单出处=Adobe spec 原文反推。


### T-RTSP-1…12 rtsp 层链收敛（D-RTSP-1 P3 清单见 CODE_DESIGN D-RTSP-1；P5 已执行 12/12 ×2 全绿，2026-09-20）

**三源：** RFC 2326（§7 消息/§10 方法/§12 头）+D-RTSP-1+VLC play 会话形。**级别：** pcap。
**存量去向（9.14）：** `rtsp` 1 例扁平 OPTIONS → 改写层链形合入 T-1。

**P5 执行记录（2026-09-20）：** cases/rtsp.json 12 例层链形（T-1 改写 9 包；T-2 现网五方法全序 17 包；T-10 复合五方法+RTP+自定义头+SDP）；suite ×2 连续全绿 `RESULT: 12 pass, 0 fail, 0 error (of 12)`。**首跑 3 红=用例侧笔误（srcport/dstport 陷阱重犯 2 例——worker 12345 保底 vs 恒 554 断言面；PAUSE/TEARDOWN 包数 3+6+4=13 笔算 15 错），实现面零 bug**；554 协议级缺省=DstPort switch 新增 case（dns→53 同款）。coverage_gate check_rtsp 23/23 绿（场景 12+键 10+锚 1）。
**9.52 对账：** RFC 2326 逻辑点 16/16 对账平（方法 6+响应 2+头补全 3+body 1+RTP 1+URI 2+负例 1→建例 12 代表+注记 4：GET_PARAMETER/SET_PARAMETER、interleaved $ 块、Record 族、MSS 锚链路径不可达）。清单出处=RFC 2326 原文反推。


### T-VNC-1…21 vnc 层链收敛（D-VNC-1 P3 清单见 CODE_DESIGN D-VNC-1；P5 已执行 21/21 ×2 全绿，2026-09-20）

RFC 6143 RFB 反推 17 例：T-1 33 帧参考形（Tight 13 握手消息+客户端消息面+FBU 循环+5900）/T-2 握手字节钉（challenge/response 参考字节）/T-3 security_type=2/T-4 =1/T-5 认证失败分支（reason 逐字节+提前拆链）/T-6 share=false/T-7 raw 确定性像素/T-8 KeyEvent 显式（0xffe9=65513，笔误教训入档）/T-9 extras 三消息交织/T-10 colourmap/T-11 客户端消息关/T-12 rounds×interval 线性/T-13 pointer 缺省 507/320/T-14…17 负例四锚（security_type 枚举 planner、auth_result V9 区间、rect encoding planner、width=0 显式 0 过 V9 落 planner）。包数全部实测钉（首跑 3 红手估错已修正：T-3=29/T-4=27 均漏数 InteractionCaps 缺席）。在库 vnc 行已清（4+81，备份 -vnc-purge-20260920.db）。**追加对抗复审第 2 轮**：registry 26 键逐键反扫抓 10 键 suite 零覆盖→补 T-18…21 四复合例（ServerInit 定制/encodings+pointer 显式/caps 定制/seed 确定性字节，全部实测钉；T-20 修 nServer=0 解 tshark Malformed），21/21 ×2 全绿+反查 48/48。

### T-XMPP-1…11 xmpp 层链收敛（D-XMPP-1 P3 清单见 CODE_DESIGN D-XMPP-1；P5 已执行 11/11 ×2 全绿，2026-09-21）

RFC 6120/6121 反推 10 例：T-1 PLAIN 19 帧全序（10 阶段+5222）/T-2 DIGEST-MD5 21/T-3 SCRAM-SHA-1 23（参考 pcap 同机制）/T-4 ANONYMOUS 19（元素字节钉）/T-5 presence=false 18/T-6 messages 双向（message 节字节钉）/T-7 from/jid/resource/stream_id 定制（流头+bind 钉）/T-8 PLAIN 凭据 base64 钉/T-9…10 负例两锚（auth 枚举/direction 枚举，全落 planner Validate）。包数手算全中（SASL 线性差 +0/+2/+4）；'</stream:stream>' 白名单泛化 xmpp_ 前缀（旧例 id 精确匹配→前缀）。在库 xmpp 行已清（3+77，备份 -xmpp-purge-20260920.db）。**追加复审第 4 轮（改隔离 subagent 执行，用户指令）**：独立复审员抓 1 中（T-6 direction 值未钉→ip.src 双向钉）2 低（XEP-0199 ping B′ 立项/T-11 长 body 3 段分段例）+T-1 缺省凭据钉，11/11 ×2 全绿+反查 23/23。**追加复审第 3 轮**：断言值 vs 配置值逐键核对抓 T-7 stream_id/jid 值未钉（f5/f11 实测补钉）+normalizeAuthMech 大小写宽松 B′ 注记+2 既有 flaky（snmp/goose）记账；10/10 ×2 全绿。

### T-SCTP-1…10 sctp 层链收敛（D-SCTP-1 P3 清单见 CODE_DESIGN D-SCTP-1；P5 已执行 10/10 ×2 全绿，2026-09-21）

RFC 4960 反推 10 例：T-1 基线关联 7 帧（chunk_type 序 1/2/10/11/7/8/14）/T-2 4 握手字节钉（显式双 Tag 后 VTag 逐帧可验；cookie 随机=一致性归 legacy 单测）/T-3 DATA 双向（SID/SSN/PPID+payload 钉，TSN 随机不钉）/T-4 分片三 flags（fragment_size=16，100B→7 段+TSN 500 连续）/T-5 HEARTBEAT 主路径 2 对/T-6 AltPath 多宿主（备用 4 元组+INIT IPv4 参数）/T-7 ABORT 突断/T-8 显式 TSN/SID/SSN/PPID 20B 全头钉/T-9…10 负例两锚（AltPath IPv6=planner、fragment_size=V9 区间——P3 复审核准拦截点）。**新教训**：端口 38412/PPID 60 触发 tshark NGAP 启发式 dissector 误报 Malformed——现网特征值与字节断言面冲突时用中性值+注记；SCTP chunk 起点 offset 46。在库 sctp 行已清（1+9，备份 -sctp-purge-20260921.db）。

**追加（2026-09-21，隔离复审完整报告注记）：** T-11 fragment_size=1000001 上界负例补齐（9.46 上界面；同 V9 拦截点），sctp 11/11 全绿+反查 21/21。

### T-JT808-1…15 jt808 层链收敛（D-JT808-1 P3 清单见 CODE_DESIGN D-JT808-1；P5 已执行 15/15 ×2 全绿，2026-09-21）

JT/T 808-2019 反推 15 例（10 正+4 负+1 复合）：T-1 基线关联 10 帧（msgId 序 0100/8100/0102/8001，双 SN 空间）/T-2 帧头字节钉（0x7e 定界+XOR 校验和 b4+SN 002a）/T-3 双 SN 空间+4 自动绑定逐格（initial_sn=100/platform_initial_sn=200 独立递增；0x0201 绑 0x8201、0x0001 绑 0x8300、0x8100 绑 0x0100、0x8001 绑最近上行）/T-4 注册体字段钉（三段 pad+GBK 车牌 bea9…）/T-5 位置上报 28B+ACC 位合并+TLV 转义（[126,125]→7d02 7d01 帧长 +2）/T-6 版本 2011+加密位（props 0x8000）/T-7 down 面 TLV 三连（params 字符串=原文字节+数组双形）/T-8 GBK 文本（限速30公里=cfdecbd933 30b9abc0ef）/T-9 属性应答 17 字段 100B/T-10 分包（1024B 体→bit14+pkgNum/pkgTotal 0001/0002，SN 同值）/T-11…14 负例四锚（phone 12 位/auth 鉴权码/车牌互斥/ACKFlag≤3——全落 ValidateConfig，嵌套 V9 不下探）/T-15 身份面复合例（city_id/厂商 JT808/终端 ID 7777777/imei/software_version 显式+registration_result=2 失败路径无鉴权码；terminal_type builder 零消费诚实注记）。**教训**：raw 自驱端口缺省真住 mapToFlowSpec 协议 switch（链 spec 恒经 mapToFlowSpec，universal 80 先占位——缺 case 即 80 穿透）；getByteSlice 字符串=原文字节非 hex；短帧用例 has_payload 不适用；自组 pin 错位以落盘 pcap 重钉（不手算）。

### T-JT809-1…13 jt809 层链收敛（D-JT809-1 P3 清单见 CODE_DESIGN D-JT809-1（含 P4 线层勘误）；P5 13/13 ×2；P6 隔离复审修轮（H1 体钉偏移/M1 解析 panic 带/M2 pr 级校验旁路/M3 增 T-14）后 14/14 ×2 全绿，2026-09-21）

JT/T 809-2019 反推 14 例（11 正+3 负，修轮增 T-14）：T-1 基线关联 8 帧（msgId 序 1001/1003，首帧 5B 起 5D 止）/T-2 信封+头字节钉（2019 30B 头：MsgLength=整帧 84=1+30+50+2+1、SN/GNSS 00000123/Version 010000/Encrypt/Key/Time 定值 1700000000=000000006553f100、CRC 复算 7f6f、尾 5D——16 钉全落盘 pcap）/T-3 登录体 50B 钉（UserId/Password pad8/GNSSCenterID/DownLinkIP pad32/Port 226d，time_sec 显式钉 CRC 确定性）/T-4 keepalive 对（0x1005 SN=50 up→0x1006 SN=60 down 空体，分链分向 SN）/T-5 断开通知 0x1007 体 01/T-6 关闭通知 0x1008 体 02+encrypt_flag/key 占位面/T-7 从链路双流 14 帧（两 4 元组主 10.0.0.1:12345↔8812+从 20.0.0.1:8812↔10.0.0.1:8813 同 GroupID；时序=主链消息(4)→从链握手(5-7)→从链消息(8)→主链挥(9-11)→从链挥(12-14)；0x9001 SN=5+VerifyCode 12345678）/T-8 从链应答负路径 13 帧（0x9002 Result=1 体 01 帧 27B）/T-9 转义真字节（down_link_port=0x5B5D→线上 5a01 5e01 双 escape 形帧 74）**P4 勘误：原设计 0x5A5B 期望 5E 01 有误（5B 逃逸形=5A 01），改 0x5B5D**/T-10 注销 0x1003（UserId 0309+password 12B 体）/T-14 登录应答 0x1002（Result1+VerifyCode4 5B 体，修轮增例=全仓唯一 buildLoginRespBody wire 例，体钉 Result@77+VerifyCode@78）/T-11…13 负例三锚——**T-11/T-12 首拦截点=registry V9 区间（schema 先于 planner：`out of range [0,999999999]`/`out of range [0,2]`）；T-13 嵌套不下探落 planner（`ErrorCode 3 > 2`）；planner 同义锚由 ValidateConfig_Anchors 单测钉**。单测面：金向量 SmallChi 0x1001 例逐字节（jtcommon 四锚+CRC 6a91 复算）、2019 30B 头形、转义、解析负路径。**教训**：库 README 组包例三方互斥（MsgLength 146 vs 149/147/145）不可作锚——以库自带单测期望 hex 为权威；frames 钉 offset 基准=整以太帧（+54）；短帧 has_payload 不适用；time_sec 不显式钉则 CRC 逐跑漂移；**修轮教训**：frames 钉体首=payload[23]（5B 占位后，首钉误落 payload[22]=EncryptKey 末字节即 9.44"失败路径不会红"），钉必须带形状断言不纯转录。

### T-JTT905-1…14 jtt905 层链收敛（D-JTT905-1 P3 清单见 CODE_DESIGN D-JTT905-1；P5 12/12 ×2 全绿 + 修轮 T-14 后 13/13 ×2，2026-09-22）

JT/T 905.2-2014 出租汽车 ISU 反推 13 例（9 正+4 负；T-8 金向量=单测面不占号）：T-1 基线关联 12 帧（自动会话 MsgId 序 0B03/8001/0002/8001/0B04/8001——legacy 虚构 0x1001/0x1002 已废）/T-2 信封+头钉（7E 定界+DataLength=纯体长 0x2f=47 实证+ISU BCD6+XOR 尾字节）/T-3 签到体钉（license16\0/qual19\0/plate6\0/uptime BCD）/T-4 心跳对（0x0002 空+0x8001 应答 MsgNum=platform_initial_sn 0x3c 绑定面）/T-5 签退体 91B 钉（K值/双时间/BCD 位数族/总次数 u32/签退方式）/T-6 应答对（0x8001 绑最近上行 ReplySN=0005+ReplyMsgId=0B03 实证；0x0001 缺省应答 0x8300 面）/T-7 转义真字节（initial_sn=0x007E→线上 7D02——金向量 MsgNum 同款位，帧 16=15+1）/T-9 位置块（25B 基础位方向 1B，帧 87）/T-10…13 负例四锚（isu 11 位/plate 7 ASCII/result 3 超真枚举/uptime 位数错——全落 ValidateConfig；T-13 锚词须含 (yyyyMMddHHmm) 后缀与 T-10 区分）/T-14 Result 枚举正例（result=1/2 体尾双钉，修轮 M1 补例——枚举 0/1/2 线上全达）。单测面：金向量 0x0200 例逐字节（README 组包例上游 Assert 钉，含 7D02/7D01 双转义形+XOR 34 复算）。**教训**：jtt905 线面属 808 族（0x7e/XOR）非 809 5B 信封——jt809 裁定2"复用 CRC809"预设被 P1 证伪；DataLength=纯体长（808 式版本位为虚构）；coverage 锚词勿含裸引号（JSON blob 转义 \" 永不命中）。

### T-ARP-1…9 arp 层链收敛（#32，D-ARP-1 P3 清单见 CODE_DESIGN D-ARP-1；RFC 826 三源，L2-only [eth,arp] 族）

ARP（RFC 826）反推 9 例（4 正+4 负+T-9 单测面不占号）：T-1 基线配对（op=1 缺省地址 2 帧：帧1 广播 ff:ff:ff:ff:ff:ff+oper 0001+tha 全零；帧2 单播+oper 0002 spa/tpa、sha/tha 角色互换）/T-2 字节全钉（帧1 28B payload 全等：htype 0001+ptype 0800+hlen 06+plen 04+oper+sha/spa/tha/tpa；ethertype 0x0806——体首=帧偏移 14，L2-only 无 IP/TCP 头）/T-3 显式地址（sender_ip=192.168.10.5/target_ip=192.168.10.1 → spa/tpa 字节钉）/T-4 单发宣告（operation=2：1 帧，ether src=target_mac/dst=sender_mac 单播，oper 0002——裁定3 legacy 广播错位勘误后语义）/T-5 负例 operation=3（V9 registry 先火锚 `out of range [1,2]`）/T-6 负例 sender_ip 格式错（锚 `invalid sender_ip`）/T-7 负例 [eth,ip,arp] 承载混入（锚 sv 同款 `must not have an ip/transport carrier`）/T-8 presence 判死（层链+顶层 arp 子映射并存，锚 `no longer accepts a top-level arp`）/T-9 单测面：layer_gen 链级红例（[eth,arp] 最小链 2 帧=缺省地址全钉）+validator 锚直测。**9.52 对账：分项和 8=建例 8（T-1…8 各 1 点），可复算**。存量审计：arp 无存量 cases（零文件），legacy Planner 单测（arp_test/arp_testpoints）保留为回归面；legacy op=2 广播错位=重建勘误（裁定3），无用例迁移。
