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

### T-FTP-1 老形状零回归（sessions 缺席）

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
