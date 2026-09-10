# 代码设计文档（唯一维护入口）

> 维护人：用户本人单独维护。AI 默认只读；未经用户明确指示，不得擅自改写。
> 本文档不是某个协议的临时方案，而是项目所有代码设计的唯一维护入口。

## 1. 三份权威文档的关系

项目日常只维护三份权威文档：

1. `docs/CORE_MEMORY.md`：最高优先级，记录不可违背的核心原则和协作要求。
2. `docs/CODE_DESIGN.md`：把需求和规范转换成可实现的代码设计。
3. `docs/TEST_CASES.md`：把规范、代码设计和实现转换成可验证的测试点与验收标准。

优先级为：核心要求 > 代码设计 > 实现代码；测试用例文档负责验证设计和实现是否一致。三份文档互相引用但不复制全文，避免出现多个版本的真实标准。

`docs/protocol-designs/`、`docs/design/`、`docs/requirements.md` 和其他既有文档保留为历史资料或参考资料，不作为新功能的日常维护入口；不因本规则自动删除。新需求、新设计和新测试只更新上述三份文档。

## 2. 代码设计文档的职责

本文档必须回答“代码应该怎样实现”，而不是只描述功能愿望。每个新功能、协议接入、架构调整或行为修复，都必须在本文档中形成可执行设计后，才能修改代码。

每个设计条目至少包含：

- 目标、范围和明确不做的内容；
- RFC、官方规范、现网抓包或现有代码依据；
- 数据结构、字段来源、层链位置和配置权威；
- 依赖关系：依赖哪些层、状态、接口、外部资源和前置条件；
- 主流程：输入、状态变化、输出、生命周期和资源释放；
- 多会话、多事务、多流及控制流/数据流关联关系；
- 数据链路层、网络层、传输层的地址、端口、标识、序号和递增规则；
- 正常分支、边界分支、错误分支、超时、重试、恢复和终止行为；
- 性能设计与验收：吞吐、并发、内存、队列、CPU、锁、背压、长时间运行和 pcap/NIC 两种输出路径；
- 受影响文件、接口、调用关系、迁移顺序和回滚方式；
- 与现有代码冲突的地方，以及旧行为保留还是移除的判定；
- 对应的测试用例文档条目和完成验收条件。

没有依赖、错误处理、性能边界或证据来源的设计，不得进入实现。

## 3. 统一设计条目模板

新增设计按下面结构写入本文档。协议名称、编号和版本必须唯一。

```markdown
### D-<编号> <功能或协议名称>

**状态：** 草案 / 待评审 / 已批准 / 实现中 / 已验收 / 暂停
**范围：** 本次解决什么；明确不解决什么。
**依据：** RFC/官方文档章节、现网证据、代码路径。
**配置权威：** 层链、策略、任务以及各字段的唯一来源。

#### 1. 数据与接口
- 输入结构、输出结构、字段类型、默认值和显式覆盖规则。
- 需要新增或修改的 Go 类型、函数、接口和调用点。

#### 2. 依赖与生命周期
- 前置条件、依赖层、依赖状态、资源所有权和释放时机。
- 初始化、运行、暂停/背压、恢复、完成和取消路径。

#### 3. 主流程与状态
- 状态表、事务顺序、会话边界、父子流关系和时间线。
- 控制流与数据流的关联字段、流 ID、四元组、序号空间和插入位置。

#### 4. 递增与覆盖规则
- 每流、每连接、每包、每段、每事件的递增字段。
- 随机起点、回绕规则、显式值优先级和不同承载层之间的继承关系。

#### 5. 错误与异常
- 输入错误、依赖未就绪、线格式错误、状态错误、超时、重试、重连、RST/FIN 和资源耗尽。
- 每类错误的返回值、任务终态、是否继续会话和是否释放资源。

#### 6. 性能设计与验收
- 目标吞吐、并发会话/流、报文大小、内存上限、队列上限和 CPU 并行度。
- 流式/批量选择、每包分配、锁竞争、限速、背压和长时间运行策略。
- pcap 与真实网卡分别测什么、如何测、通过和失败的阈值是什么。

#### 7. 实现顺序与回滚
- 先改哪些类型/解析/校验/生成器/接线，再改哪些用例。
- 每一步的 failing test、review、测试命令和回滚点。

#### 8. 验收
- 对应 `docs/TEST_CASES.md` 的测试点编号。
- 功能、数据、业务、性能和现网场景的完成条件。
```

## 4. 现有代码基线（只记录可由代码定位的事实）

| 主题 | 当前代码入口 | 设计时必须对齐的事实 |
|---|---|---|
| 层链规划 | `internal/core/layers/` | 层链负责依赖补全、字段校验、生成器接线和包序列包装；层链配置不得再与旧顶层地址/端口/count 混为真相 |
| 策略与任务 | `internal/core/strategy_convert.go`、`internal/core/worker.go`、`internal/core/engine.go` | 策略控制单一协议模板；任务合并多个策略并提供任务级总上限；策略桶先限速，任务父桶再限速 |
| 四元组变化 | `internal/core/tuple_generator.go`、`internal/core/worker.go` | `tuples` 当前在批量路径生效；策略/任务路径当前自动变化主要是未显式指定时的源端口 |
| 通用多流 | `internal/core/subflow.go` | 子流可独立握手、序号和终止，但当前 ID 由 `parent:sub-idx` 生成，调用方必须保证索引和关联关系正确 |
| 多会话范本 | `internal/core/cwmp.go`、`internal/protocol/cwmp/layer_gen.go` | `sessions[]`、事务序列、`flows[]` 和 `driven_by` 已形成可参考的控制流/数据流关联模式 |
| FTP 当前实现 | `internal/protocol/ftp/ftp.go`、`internal/core/types.go` | 当前是单控制流 + 共用 `DataChannel` 模板；正式多会话、多事务、多数据流关联仍属于待设计/待实现范围 |
| 性能约束 | `internal/core/worker.go`、`internal/core/engine.go`、`internal/core/layers/chain_planner_translate.go` | 设计必须明确是否全量收集、队列背压、worker 并行、限速和输出路径的资源影响，不能只验证包内容 |

这张表只用于定位代码事实；具体功能设计必须继续写完整的依赖、错误和性能章节。

### D-SCHEMA-1 统一配置 schema 与统一校验入口

**状态：** 已批准（用户指令：整体 schema 唯一存放、校验与接口描述皆从此出； layers.json 与注册表生成表指令；MCP 描述与前端派生指令）
**范围：** 本次解决：`trafficgen/schemas/v1/` 五份形状文件（defs/strategy/task/batch/layers）+ 注册表生成表 + Go 统一校验入口 + REST 接线 + MCP 描述派生 + 前端类型派生 + 负例一致性。不解决：40+ 协议子配置逐个 `$ref` 化（仅 tcp/udp/http/dns/icmp/icmpv6/arp/tftp 有形状，其余仍走 `ValidateProtocolSubConfigs`，属遗留清单）；FTP 多会话结构（另立条目）。
**依据：** 代码事实——校验曾散在 7 处（REST DTO、storage 文本 blob、engine 类型、validate/convert、layers 校验、handler 内联检查、MCP 手写 jsonschema 串），无 JSON Schema、无 OpenAPI；前端 `FlowControlRequest` 含后端已删的 cps/ratio，属已证分叉。
**配置权威：** `trafficgen/schemas/v1/*.json` 是唯一机器可读真相；Go 校验、REST/MCP 形状、MCP 描述、前端类型皆派生。`generated/layers.generated.json` 由注册表生成，不许手写。

#### 1. 数据与接口
- 形状文件：`trafficgen/schemas/v1/defs.json`（flow_control flows|bps|time 且 value>0；output_config 至少其一 port_group_id/pcap_path + interface2（anyOf 非互斥，output_type 侧规则定必填项）；dynamic_value fixed/inc/rand/pattern/list 条件必填；tuple_config；group_id）、`strategy.json`（name/config 必填；mode synth|replay 缺省 synth；protocol 可空供 layers 推断回填；replay 时 config 必带 pcap_asset_id 且禁 layers、flow_control 只收 time）、`task.json`（strategy_ids 非空 XOR batch；output_type 决定 output_config 必填项）、`batch.json`（classes 非空，id/type 必填；type=replay 必带 replay，反之 flow_count≥1）、`layers.json`（非空数组，单键对象）、`generated/layers.generated.json`（95 层：分类/依赖/字段/缺省/范围/契约）。
- Go 入口：`trafficgen/internal/core/schema/schema.go`（`ValidateStrategyShape/ValidateTaskShape/ValidateBatchShape/ValidateLayersShape`，`Descriptions/DescriptionMap` 描述导出，`LayersGenerated` 生成表读取）与 `semantic.go`（`ValidateStrategy` 形状+语义同跑、语义文案优先；`ValidateTaskCreate` 形状+封包文案+replay+bps 冲突+批量语义）。规则：schema 只拦畸形形状，语义错误一律用历史 handler 文案（REST/MCP/测试三方同字）。
- 调用点：`internal/api/rest/strategy_handler.go`（`schemaGate`，create/replay/update 三路；STRAT4-BR2 排序保留）与 `task_handler.go`（`taskCreateDoc/toAny/toAnySlice/toAnyBatch+pruneZero` 归一 gin 零值后进门；create/batch/start 三路；replay+bps 冲突 Start 内复查）。MCP 不自验，经 `callHandler` 转发继承（`tools_strategy.go/tools_task.go/tools_workflow.go`）。
- 生成器：`internal/core/layers/schemagen`（注册表→生成表，输出 JSON）与 `internal/mcp/schemagen`（schema 标题/说明→`schema_descriptions_generated.go` 五表 Strategy/Task/Batch/Defs/Layers + `schemaConfigBlurb`，自带 `go/format` 自格式化）。MCP struct 标签须为字面量（Go reflect 不求值拼接），`schema_derivation_test.go` 锁标签与生成文本一致。
- 前端：`web/src/api/schema-types.ts` 由 `tools/webgen.py` 从 schema 生成（FlowControl 无 cps/ratio、OutputConfig 含 interface2、Strategy/Task/Batch/CreateBatchRequest，附 key 注释）；`index.ts` 中 Strategy/FlowControlRequest/OutputConfigRequest/output_type 为纯别名，Task 为 `extends SchemaTask`（仅 stats 为 UI 实时快照附加字段，不在 task.json 内）。

#### 2. 依赖与生命周期
- 前置：`google/jsonschema-go v0.4.3`（已在间接依赖，无新增）；`schemas/schemas.go` embed 整棵 v1（含 generated）；跨文件 `$ref` 在内存合并+改写（defs 内联、batch 内联并剥离嵌套 `$id`），无需外部 loader。
- 初始化：`loadOnce` 一次合并解析五份形状；失败即整包不可用（返回装载错误，不降级）。
- 资源：只读内存规则+描述表，无锁外资源；生成器写文件仅本地运行/CI 重跑，不在线触发。

#### 3. 主流程与状态
- 策略建改：归一→形状→语义（replay：layers 拒绝→time-only→`ValidateReplaySpec`；synth：封包文案→IP/MAC 格式→`ValidateConfigRanges`→`ValidateLayers` 推断回填→协议白名单→子配置→TFTP tid）。任一步失败即 400，文案与老接口逐字一致。
- 任务建/批量建/启动：归一→task 形状（含 batch 形状）→封包文案→存在性/归属（handler 查库，非 schema 事）→replay+bps 冲突（建时查一次，Start 内对最新策略复查一次）。
- layers 出现即走层链分支：protocol 可空，推断值回填请求；层字段以注册表（生成表快照/`flowb_query_layers` 实时视图）为准，未知字段拒绝。

#### 4. 递增与覆盖规则
- 不适用（本条目不定值算法）。缺省语义：absent 用缺省（如 src_ip 10.0.0.1、direction single、checksum recompute）；显式 0/空按既有“presence-checked”接受；唯 replay 六键（speed/direction/checksum_mode/rewrites/flow_scaling/loop）显式 null 算调用方错误（`X is null; omit it`），MCP 负责省略未填键（`tools_workflow.go` 条件组装 replaySpec）。

#### 5. 错误与异常
- 形状错：schema 短错误（`splitError/shortError` 取叶消息，如 `enum`/`required`/`type`）；封包/网络/协议/回放错：历史 handler 文案优先（bad FC type、IP/MAC 格式、未知协议、TFTP tid、`invalid speed mode/direction/checksum_mode`、layers-replay 拒绝、time-only）。
- 显式 null：replay 六键收到 null 即语义拒绝（`X is null; omit it to use the engine default`），不漏 reflect 行话；调用方（MCP）负责省略未填键。后端不为 null 加兼容（CORE_MEMORY §13 评审红线）。
- MCP 透传：`backendError` 按 code 映射（400/403/404→InvalidParams 原文，500→InternalError），不改写 message（负例横扫锁死逐字一致）。
- 生成表过期：`TestLayersGeneratedMatchesRegistry` 逐层比对（层数/分类/字段数/字段类型），过期即红，修复=重跑生成器并提交；CI 另有重跑+`git diff --exit-code` 门（`.github/workflows/ci.yml`，跑 `layers/schemagen`、`mcp/schemagen`、`tools/webgen.py` 三台生成器）。

#### 6. 性能设计与验收
- 校验为纯内存形状+字段检查，无包级开销；回归以现有全量套件时间为准（`internal/...` 约 2 分钟量级），不新增性能门。生成器为离线工具，不计入在线路径。

#### 7. 实现顺序与回滚
1. defs+strategy.json+loader+形状单测 → 2. 策略 REST 接线（MCP 继承）+ Config 描述生成 → 3. task+batch.json+任务三路接线 → 4. layers.json+注册表生成器+过期门 → 5. 前端类型+文档索引 → 6. 负例横扫。每步 build+vet+相关套件，回滚点=按提交逆序 revert（逆序即 6a6d5c3 横扫与记忆 §13 → 4700461 layers 表 → 25a7d82 null 规则 → d3ac0b3 null 兼容试错 → bb14c05 派生；更早 07779fb/c5405f3/9667bc8 为入口搭建三步）。

#### 8. 验收
- 对应 `docs/TEST_CASES.md` T-SCHEMA-1（策略形状）、T-SCHEMA-2（语义文案）、T-SCHEMA-3（null 规则）、T-SCHEMA-4（任务批量）、T-SCHEMA-5（生成表过期门）、T-SCHEMA-6（负例横扫）。完成条件：五份形状+生成表入库；统一入口为唯一校验路径（在线路径无自写形状检查；`validateConfigNetwork`/`validateReplayBPSConflict` 已退役，仅测试/注释锚点保留待删）；MCP/前端无第二套手写形状（Task 的 stats 附加字段除外）；负例横扫 17 例全绿；`go build ./...`、`go vet`、`gofmt` 干净。

### D-FTP-1 FTP 多会话多事务静态结构（阶段一：结构先行，动态随后）

**状态：** 已验收（2026-09-06 用户批复；实现提交 db9b052，T-FTP-1..6 全绿，全套件/-race 干净）
**范围：** 本次只做静态结构：`FTPSession{SrcPort,Banner,Transactions[]}` + `FTPTransaction{Commands[],DataChannel}`，planner 按会话循环、每会话独立 TCP 四元组/序号/启停，数据流挂到触发它的事务下（`{parent}:sub-{tx-idx}` 索引，替代现 `{parent}:sub-0` 硬编码碰撞）。明确不做：动态值（阶段二）、TCP keepalive（tcp 层归属，FTP 不碰）、ABOR 中断传输（阶段三候选）。
**依据：** RFC 959（控制会话+独立数据连接）；记忆 ftp-rfc-session-scheduling（RETR/LIST/CWD/REST 操作序列、每数据连接独立四元组+生命周期、长传输控制活性归 tcp 层）；P0a 范本 `postgresql/layer_gen.go:48-58`（sessions 循环 + `SrcPort` 带上事件）；CODE_DESIGN §4 基线（FTP 当前单控制流+共用 DataChannel 模板）；CODE_DESIGN §2（设计必须含依赖/错误/性能/回滚）。
**配置权威：** 层链唯一真相；FTP 业务字段只落 `ftp` 层（将来注册表补 sessions 字段表，阶段一先走 `spec.FTP` 直传）；地址只落 `ip` 层、端口只落 `tcp` 层、数量只走 `flow_control`。

#### 1. 数据与接口
- 新增 `core/types.go`：`FTPSession{SrcPort uint16, Banner string, Transactions []FTPTransaction}`；`FTPTransaction{Commands []FTPCommand, DataChannel *FTPDataChannel}`；`FTPConfig` 加 `Sessions []FTPSession`（空=老形状：顶层 Banner/Commands/DataChannel 照旧，零回归）。
- planner（`internal/protocol/ftp/ftp.go:Plan`）：`Sessions` 非空时按会话循环——每会话独立 `flowID`（`{SrcIP}-{DstIP}-{SrcPort}-{DstPort}`，SrcPort 取 `session.SrcPort` 非零则覆盖、0 沿用 spec.SrcPort；DstPort 恒取 spec.DstPort=21，阶段一不做每会话目的端口）、独立 clientSeq/serverSeq/ipID/packetIndex/winSize/TTL 续号、独立握手/banner/事务序列/teardown；会话内按事务顺序执行；`EmitDataChannel` 的数据流改传真 `tx-idx`（`subflow.go:55` 格式为 `{parent}:sub-{idx}`，现调用处 `ftp.go:606` 传 0）。`spec.TCP.InitialSeq` 非零时首会话用其作 clientSeq、后续会话随机（同 ISN 发两次会被 DPI 判重传，实现时首会话优先、可测）。
- 端口推导沿用现有三级优先级（显式→信令 PASV/PORT 解析→回退 20/50000/+1），但信令扫描域收窄到本事务的命令对（现 `scanCommandsForDataPort(spec.FTP.Commands,…)` 全局扫描，多事务下后事务会误用前事务的 PASV 端口）。`emitFTPDataChannel` 的 `cmdIdx` 语义从“全局命令下标”变为“本事务内命令下标”，调用处传事务内索引、扫描本事务 `Commands`。
- 不新增文件、不改 `Plan` 签名；`strategy_convert.go:413` 加 `parseFTPSessions`（banner/commands/data_channel 复用现有解析）。

#### 2. 依赖与生命周期
- 前置：`spec.FTP.Sessions`（可空）；每会话 SrcPort（0=沿用 spec.SrcPort）；`EmitSubFlow` 已收 idx（`subflow.go:45-54`），ftp 调用处改传真值。
- 生命周期：会话=一条 TCP 连接（握手→banner→N 个事务→teardown）；事务=1..M 个命令/响应对+可选一条数据流；数据流生命周期嵌在触发事务内（150 与 226 之间，现有交错语义不变）。
- 取消：`Plan` 的 ctx 现仅用于 `PayloadCache.GetOrLoad`（`ftp.go:551-555`），emit 路径无 ctx 检查——阶段一保持现状（与现有行为一致，不扩范围）。

#### 3. 主流程与状态
- 会话循环（外）→事务循环（中）→命令对循环（内）；序号空间按会话隔离，跨会话不连续（各是独立 TCP 连接）。
- 控制/数据关联：数据流 `FlowID={parent}:sub-{tx-idx}`，GroupID 继承父 spec（同 Worker 保序，现有机制不变）。
- 时间线：会话串行（阶段一不做并发会话；并发属性能条目候选，不承诺）。

#### 4. 递增与覆盖规则
- 阶段一静态：SrcPort 显式覆盖（非零 wins，0 沿用）；其余沿用现有 spec 值。动态（inc/rand/pattern）为阶段二，不在本条目。

#### 5. 错误与异常
- `Sessions` 空→老路径（零行为变化）；会话无事务→仅握手+banner+teardown（空会话合法）；事务无命令但有 DataChannel→数据流仍按现有规则发射（复用 `EmitDataChannel` 判定）；`Validate` 阶段一不新增拒绝项（SrcPort 天然 uint16）。
- planner 错误继续返回 error 中断 Plan（现有语义不变）；超时/重试/恢复：阶段一无新增等待点（会话串行、无并发、无定时器），复用现有“错即停”语义，超时重传归 tcp 层（与 keepalive 同归属）。

#### 6. 性能设计与验收
- 包量=各会话包数之和，无额外分配（复用现有 emit 闭包与 256 chan）；会话串行故无新锁/竞争；长传输活性归 tcp 层 keepalive（FTP 不实现）。
- 验收：现有 ftp 5 个测试文件全绿（零回归）+ 新增多会话形状单测（包数=握手3+banner?+命令对+数据流+teardown4 之和断言）。

#### 7. 实现顺序与回滚
1. types 加二 struct + Sessions 字段 → 2. convert 加 parse（failing test 先行：sessions 形状解析） → 3. planner 会话循环+tx-idx+信令域收窄（failing test 先行：`TestFTPMultiSession` 会话隔离、`TestFTPDataChannelTxIndex` 索引区分、`TestFTPPASVIsolation` 端口隔离） → 4. 全量 ftp 套件+`go vet`。回滚=单提交 revert（阶段一独立提交，不碰阶段二）。

#### 8. 验收
- 对应 `docs/TEST_CASES.md` T-FTP-1…T-FTP-6（T-FTP-5/6 为实现循环新增的 §5 边界用例，已转正登记）。完成条件：老形状零回归；双会话（RETR+LIST）包序列断言通过；数据流 parent 索引区分事务；跨事务 PASV 端口不串扰；空会话 7 包；无标记 DataChannel 不发射；`go build/vet` 干净。

### D-FTP-2 动态值（阶段二：策略路径四元组动态 + FTP 会话/事务字段动态）

**状态：** 已验收（2026-09-10 用户批复"开工"后实施；T-FTP-7..17 全绿，触碰包 -race 绿，负例横扫 19 例）
**范围（2026-09-10 用户纠正后改版 v2）：** 用户裁定动态配置模型 = "静态字段原地加动态参数"——同一个字段，静态写普通值（int/string）、动态写变化规则对象（fixed/inc/rand/list/pattern 五策略，group_id 既有先例），不分模式、不另起键。本次解决：①四元组动态——strategy config 的 `src_ip`/`dst_ip`/`src_port`/`dst_port` 原地接受"标量或动态对象"，worker 策略循环按流序号解析；策略级 `tuples` 键撤销（v1 误设计，只留批量类 `classes[].tuples`）；②FTP 业务字段动态——`session.src_port`/`session.banner`、`command.cmd`/`command.response`、`data_channel.payload` 同字段二态（v1 的 `*_dyn` 平行键撤销）；③流序号贯通——worker 策略/批量两条循环向 FlowSpec 写入 FlowIndex；④畸形动态配置拒绝——四元组经 mapToFlowSpec 写 ValidationErrors（既有聚合失败机制）、FTP 经 Planner.Validate，任务终态 error，不许静默回退静态；⑤静态复制拒绝——create 语义层 flat 规则 + FTP planner sessions 规则（逃生口从"补 tuples"改为"把该字段写成动态对象"）；⑥schema/派生同步（strategy.json 四元组字段 anyOf 化、tuples 键删除，MCP 描述与前端类型重生成，负例横扫补动态畸形/静态复制两例）。明确不解决：任务级跨策略共用动态池（另立条目）；老形状（顶层 banner/commands）动态（零回归红线）；ftp 子配置 $ref 化（40+ 遗留清单）；批量路径 genIP/genPort 对畸形 range 的静默回退（遗留基线不改，批量类继续用 tuples 池）；批量类无 tuples 的静态复制拒绝（create 期无法审计）；并发会话、ABOR 中断、TCP keepalive；子流 group_id 预写 flowIdx=0 局限（既有已知项）。
**依据：** CORE_MEMORY §12 全文（策略/任务动态 mandate：五策略、seed+序号可复现、到尾回绕、静态复制必须拒绝或告警、批量 tuples 是参考基线、动态值只落 ip/tcp/udp/协议层）；批量基线代码 `internal/core/tuple_generator.go:34`（genIP）、`:79`（genPort）、`internal/core/shard_router.go:58`（genStringValue）、`:105`（applyPattern）、`internal/core/worker.go:737-763`（批量每流解析与覆盖顺序）；策略路径现状 `internal/core/worker.go:279-324`（仅 src_port 自动+1，其余字段全静态）；FTP 阶段一 `internal/protocol/ftp/ftp.go:277`（planSessions，实际 277 行确认）；schema `trafficgen/schemas/v1/defs.json:73`（dynamic_value）、`:191`（tuple_config）。
**配置权威：** 动态是"值的算法"，层链是"值的住处"：同键二态算出的地址仍只落 ip 层（src/dst）、端口仍只落 tcp/udp 层（经 spec 注入层链，与静态同一条路径）；FTP 业务字段仍只落 ftp 层；数量仍只走 flow_control。不新增与 layers 并存的第二套顶层字段（批量类 tuples 池照旧）。

#### 1. 数据与接口
- `internal/core/types.go`：`FlowSpec` 增四元组动态字段 `SrcIPDyn/DstIPDyn/SrcPortDyn/DstPortDyn *StrategyConfig json:"-"`（v1 的 `Tuples` 字段撤销）与 `FlowIndex int json:"-"`（worker 每流写入；0=直接调用/首流，planner 单测可手工设定）。
- `FTPSession` 增 `SrcPortDyn/BannerDyn *StrategyConfig json:"-"`；`FTPCommand` 增 `CmdDyn/ResponseDyn *StrategyConfig json:"-"`；`FTPDataChannel` 增 `PayloadDyn *StrategyConfig json:"-"`。并排字段（静态值字段语义零变化，动态仅在静态缺席/空时参与）；`json:"-"` 因 FlowSpec 不做存储往返，仅运行期对象。
- `internal/core` 导出解析包装（单真相，FTP planner 不复写算法）：`ResolveIPValue(s *StrategyConfig, i int) string`、`ResolvePortValue(s *StrategyConfig, i int) uint16`、`ResolveStringValue(s *StrategyConfig, i int) string`，分别包装 genIP/genPort/genStringValue；nil/空策略返回零值。IP/端口支持 fixed/list/inc/rand（与批量 genIP/genPort 完全一致，不支持 pattern）；字符串字段支持全部五种（genStringValue，pattern 含 {n}）。`TupleConfig.UnmarshalJSON`（v1 标量简写补丁）保留——批量类 tuples 池仍用。
- `internal/core/strategy_convert.go`：`mapToFlowSpec` 四元组四键二态解析（标量走既有路径、对象走 StrategyConfig；畸形对象写 `spec.ValidationErrors`——既有聚合失败机制，worker 预检即终态 error）；v1 `cfg["tuples"]` 解析块撤销。`parseFTPSessions/parseFTPCommands/parseFTPDataChannel` 同键二态：`m["src_port"]` 是 map → `SrcPortDyn`，是标量 → `SrcPort`（banner/cmd/response/payload 同理），`*_dyn` 键全部撤销。
- `internal/core/worker.go`：策略循环 `:308` 自动递增之后插入四元组动态解析（每字段 `Resolve*Value(i)` 非零才覆盖；批量循环同块，防类配置动态字段成死配置）；两条循环各写 `spec.FlowIndex`。
- schema：`trafficgen/schemas/v1/strategy.json` config 四元组四键 anyOf 化（`src_ip`/`dst_ip` anyOf[string, dynamic_value]；`src_port`/`dst_port` anyOf[integer 0-65535, dynamic_value]）；v1 `tuples` 属性撤销；重跑 `internal/mcp/schemagen`（描述表+Config 标签）与 `tools/webgen.py`（schema-types.ts、config-schema.md 生成表），门测试锁同步。
- 校验入口：`internal/core/schema/semantic.go` ValidateStrategy synth 语义新增 flat 静态复制拒绝（逃生口="src_port 写成动态对象"）；`internal/protocol/ftp/ftp.go` Planner.Validate 新增 sessions 静态复制拒绝与畸形动态拒绝。

#### 2. 依赖与生命周期
- 前置：阶段一 sessions 结构已验收（db9b052）；四元组四键此前 schema 收紧为纯标量——本阶段 anyOf 化后对象写法开始生效（存量策略不受影响，纯新增能力），登记于 §5。
- 解析时机：四元组动态在 worker 每流循环内 O(1) 解析（Resolve*Value 逐字段）；FTP 业务动态在 Plan 内每会话/每事务解析 O(字段数)；全部为确定性纯函数（同 i 同值），无锁、无共享可变状态、无额外 goroutine。
- 只读约束：worker 每流对 `task.Spec` 做浅拷贝（`worker.go:306`），Dyn 指针字段跨流共享——解析只读指针、绝不写回 Dyn 字段（否则跨流数据竞争，-race 必红）；resolveTx 产出的有效事务副本为 Plan 内局部对象，随流丢弃。
- 取消/背压：不新增等待点；Plan 的 ctx 语义不变（仍仅 PayloadCache 使用）。

#### 3. 主流程与状态
- 策略流循环 i（worker.go）：spec 副本 →（无显式 src_port 时 12345+i）→ 四元组各动态字段 Resolve(i) 非零覆盖 → FlowIndex=i → computeHashKey(spec,task,i)（顺序与批量 :746→:763 一致，分片键反映最终四元组）→ Plan(spec)。
- FTP 会话循环（planSessions）：会话级解析（src_port/banner，索引=本流 i；同一流的多个会话共用同一 i——同 range 会得到相同值，需要会话间差异时须用不同 range/list 或部分静态部分动态）→ 事务级 resolveTx（先把 cmd/response/payload 的动态解析为有效事务副本）→ 既有发射与 PASV/PORT 扫描逻辑零改动（扫描看到的是已解析响应，端口推导自动正确）。
- 索引域统一：四元组（worker 解析）与 FTP 业务字段（planner 解析）同用流序号 i；同 i 同值（rand=seed+i 可复现）；老形状路径不读任何 Dyn 字段，行为不变。

#### 4. 递增与覆盖规则
- 算法（与批量逐字同源，单真相在 core）：inc `start+((i·step) mod count)`，step≤0 视为 1；rand `rand.New(rand.NewSource(seed+i))` 取 [start,end]；list `list[i mod len]`；pattern `{n}`→`start+(i mod count)`；fixed 常量。超尾回绕。
- 覆盖优先级：①四元组——同键二态后"静态与动态互斥"（一个字段一种写法）：动态对象按流解析并覆盖（含覆盖引擎默认），未配动态端点走既有链（src_port 显式静态 > 自动递增 > 默认；src_ip/dst_ip/dst_port 无自动递增）；②FTP 会话——`src_port` 写标量=静态（非零覆盖 spec），写对象=动态（按流解析后覆盖），都缺=继承 spec.SrcPort；③字符串字段——banner/cmd/response/payload 写标量=静态原文，写对象=动态解析值，空=跳过发射（阶段一语义保持）；④DataChannel——FileSource > payload（静态原文或动态解析值，二者同一键互斥）。v1 的"静态非空 > 动态解析值"跨键优先级随平行键撤销而消失——同键二态天然无此歧义。
- InitialSeq 多会话规则（首会话独占、后续随机）与序号空间不受动态影响。

#### 5. 错误与异常
- 畸形动态配置（strategy 未知或空、inc/rand 的 range 非 2 元或 end<start、list 空、pattern 空或缺 2 元 range）：拒绝，不许静默回退静态（对比表 F；批量 genIP/genPort 静默回退为遗留，不改）。触发点分路径——四元组动态畸形：mapToFlowSpec 解析时写 `spec.ValidationErrors`（既有聚合失败机制）→ worker 预检（`worker.go:210`）终态 error；FTP 动态畸形：策略路径在 worker 循环前的 `planner.Validate(task.Spec)`（`worker.go:222`）→ 任务终态 error，一条流都不发；批量路径在每流 `p.Validate(spec)`（`worker.go:770`）→ 逐流跳过并计入 flowFailures。Plan 入口自身的 Validate（`ftp.go:88`）为直接调用方兜底。
- 静态复制拒绝：flat——`flow_control.type=flows 且 value>1 且 config 显式含顶层标量 src_port 且 src_port 不是动态对象`，create/Update 均 400（统一入口语义层，位置：TFTP tid 规则之后追加；适用所有 synth 协议；仅作用于无 `layers[]` 的 config——层链形状下端口在 tcp 层，检测需注册表字段表支撑，列入不解决）。逃生口：把 src_port 写成动态对象。存量此形状策略一旦编辑即被要求先修配置，属 §12 意图内行为变化。FTP sessions——`spec.Count>1 且存在静态会话端口（或全继承且用户显式写了 spec src_port）且无任何会话把 src_port 写成动态对象`，Planner.Validate 拒绝（批量路径 spec.Count=0 不触发，属已知边界）。触发时机与 flat 规则不同：flat 在建策略时 400，sessions 规则在任务启动时（worker 预检 Validate，`worker.go:222`）以任务终态 error 暴露——建策略时 ValidateProtocolSubConfigs 不审计会话端口形状（属既有子配置边界，不扩范围）。两条文案均给出出路（省略 src_port 走自动递增 / 把对应字段写成动态对象）。
- 兼容行为变化：存量"显式 src_port + flows>1"的策略自本阶段起在 create/Update 被拒；未编辑的存量策略任务不受影响照跑。回归面：现有显式端口+flows>1 的 REST/引擎集成用例需按新规则更新（省略 src_port 或补 tuples），随本阶段一并提交；离线 pcap 套件 `test/protocol_pcap/cases/ftp.json` 为 count=1 显式端口，不吃此门（Count>1 才触发），零改动。
- 依据边界：本阶段拒绝规则成立的前提是"策略路径没有任何 planner 能在无索引时自变四元组"（当前成立）；未来若某 planner 用 FlowIndex 自变，需重审该规则（登记为跟随项）。

#### 6. 性能设计与验收
- 每流新增 O(1) 解析（与批量已在产线的等价路径同量级）；TupleGenerator 每任务循环构造一次；resolveTx 先探测动态存在性、静态事务零分配（无副本）；FlowSpec 增指针+int 共 16B；无新锁、无新 chan、限速/背压路径不变。
- 验收：回归套件耗时相对基线 ±10% 内；不新增性能门；pcap 与真实网卡用例沿用既有 harness（enp135s0f0np0 冒烟沿用现跑法）。

#### 7. 实现顺序与回滚
（v1 步骤 71bed09/753c2e3/fad1138/1b3fe73/2ed5dda 已实施；v2 改版重做同序）1. schema：四元组四键 anyOf 化 + tuples 撤销 + 三台生成器重跑 + 形状用例改版 → 2. core：FlowSpec 四元组 Dyn 字段替换 Tuples + mapToFlowSpec 同键二态解析 + ValidationErrors 畸形拒绝（failing 先行）→ 3. worker 两循环动态解析块替换 tuples 块（T-FTP-7/8/9 改版）→ 4. FTP 同键二态解析（`*_dyn` 键撤销）+ resolveTx/Validate 不变（T-FTP-10..14 输入改版）→ 5. 双静态复制逃生口改版 + 横扫 p13 改版（T-FTP-15/16）→ 6. T-FTP-17 + 全量套件 + touched 包 -race + vet/gofmt + 文档状态回写。回滚=按提交逆序 revert。

#### 8. 验收
- 对应 `docs/TEST_CASES.md` T-FTP-7…T-FTP-17；回归项 T-FTP-1（老形状零回归）与负例横扫扩至 19 例全绿。完成条件：五策略（fixed/inc/rand/list/pattern）在四元组与 FTP 字段上全部有绿用例；rand 同 seed+序号可复现、inc/list/pattern 到尾回绕有断言；两条静态复制拒绝均有"同形状+动态即通过"的反例；畸形动态配置导致任务终态 error（不许静默静态）；`go build ./...`、`go vet`、gofmt 干净；touched 包 -race 绿。

#### 9. 关键决策对比

| 决策 | 候选 | 优劣 | 结论 |
|------|------|------|------|
| A 动态索引如何到达 planner | A1 FlowSpec.FlowIndex（worker 写入）；A2 改 Plan 签名加 idx；A3 planner 内部自计数 | A1 不改 95 个 planner 签名、策略/批量同域、单测可手工设；A2 回归面巨大；A3 不可行（每次 Plan 独立新 spec，无跨调用状态） | 选 A1 |
| B 动态字段形状 | B1（v1）JSON 平行键 `*_dyn`；B2（v2，用户裁定）同键二态（标量/对象），Go 内部仍并排字段由解析层映射 | v1 平行键让用户记两套键名，被用户否决；v2 JSON 单键二态（group_id 先例），Go 结构体并排字段保留（兼容 34 处字面量、-race 只读约束不变） | v2 裁定：JSON 同键二态 + Go 内部并排字段 |
| C 静态复制处置（flat） | C1 create/Update 拒绝；C2 服务端日志告警；C3 静默 | C1 fail-fast 且 §12 明文"不许静默发出 N 条重包"；C2 前端用户看不到告警等于半静默；C3 违背 §12 | 选 C1 |
| D FTP 业务动态解析位置 | D1 planner 内（planSessions/resolveTx）；D2 worker 预解析 | D1 工作器保持协议无关、扫描天然拿到已解析响应；D2 破坏分层 | 选 D1 |
| E 动态四元组覆盖顺序 | E1（v1）tuples 池 Next(i) 非零覆盖；E2（v2）同键二态字段逐字段 Resolve(i) 非零覆盖 | v2 同键二态下不再有池与平铺两处来源；逐字段非零覆盖与既有批量覆盖序一致 | v2：逐字段 Resolve(i)，批量循环同块 |
| F 畸形动态配置处置 | F1 拒绝→任务 error；F2 静默回退静态（批量 genIP/genPort 现状） | F1 失败路径可测、§5/§9 要求错误真红；F2 隐性静态输出=测不出的退化；批量静默回退属遗留基线，本阶段不改、已列入不解决 | 四元组走 ValidationErrors、FTP 走 Planner.Validate，均 F1 |
| G 策略级 tuples 池（v1 误设计） | G1 保留（策略 tuples + 同键二态并存）；G2 撤销策略 tuples，批量类 tuples 池不变 | G1 两套写法并存正是用户否决的"乱"；G2 单模型（字段二态），批量路径不动 | 选 G2（用户裁定） |

## 5. 设计评审闸门

代码设计完成后，必须按以下顺序评审：

1. 规范依据是否覆盖连接模型、消息/字段、状态机、错误、超时、载体和版本差异；
2. 配置权威是否只有一处，是否误把旧字段、测试便利字段或默认值当成新真相；
3. 多会话、多事务、多流的依赖、关联、交错和生命周期是否可执行；
4. 二层、三层、四层递增和显式覆盖规则是否逐字段说明；
5. 性能目标是否有代码依据、测量方法、资源预算和失败边界；
6. 每个设计条目是否已经登记到 `docs/TEST_CASES.md`；
7. 文档 review 是否完成并记录“自审轮次、发现问题、修复结果”。

未通过评审的设计不得改代码。需求变化时先改本文档，再改实现和测试。
