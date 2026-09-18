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

### T-HTTP-7 http.json 独立用例——GET 基线【D-HTTP-1 §8】

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

**状态：** P4 已落地（4 红转绿，见 D-MCP-1）；P5 未开工（本文清单即 P5 补例依据）
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

**执行口径：** P5 MCP 真实流程全量（`flowb_run_protocol_suite`：MCP 建任务→引擎生成→tshark 校对）103/103 全绿 + 落盘 `/tmp/mcp-pcaps/mcp/` 零孤儿 + 门 2 四项（presence 红线已接）+ 反查 65 项全绿（探针 9/65，MISS 56 项=本清单）。
**实现位置：** `cases/mcp.json`（P5 改写 79 + 新建 24）。
