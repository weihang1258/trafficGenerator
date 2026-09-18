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

### D-FTP-2 动态值（阶段二：扁平四元组动态 + FTP 字段动态）【v3 改版留档：本条目四元组部分已被 D-FTP-3 替代（数据源从扁平键迁入层字段）；FTP 字段动态部分仍有效】

**状态：** 部分验收（FTP 字段动态 T-FTP-10..14/16 保留；四元组扁平动态 T-FTP-7/8/9/15 由 D-FTP-3 重做，v2 实现代码按 D-FTP-3 §7 回滚/改写）
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
- 畸形动态配置（strategy 未知或空、inc/rand 的 range 非 2 元或 end<start、list 空、pattern 空或缺 2 元 range）：拒绝，不许静默回退静态（对比表 F；批量 genIP/genPort 静默回退为遗留，不改）。触发点分路径——四元组动态畸形：mapToFlowSpec 解析时写 `spec.ValidationErrors`（既有聚合失败机制）→ worker 预检（`worker.go:210`）终态 error；FTP 动态畸形：策略路径在 worker 循环前的 `planner.Validate(task.Spec)`（`worker.go:222`（策略预检）→ 任务终态 error，一条流都不发；批量路径在每流 `p.Validate(spec)`（`worker.go:770`）→ 逐流跳过并计入 flowFailures。Plan 入口自身的 Validate（`ftp.go:88`）为直接调用方兜底。
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
| H 策略级 tuples 池（v1 误设计） | H1 保留（策略 tuples + 同键二态并存）；H2 撤销策略 tuples，批量类 tuples 池不变 | H1 两套写法并存正是用户否决的"乱"；H2 单模型（字段二态），批量路径不动 | 选 H2（用户裁定） |

### D-FTP-3 层字段动态 + 扁平四元组清退（阶段三：动态值的住处迁入层链）

**状态：** 已验收（2026-09-10；实现提交 8756423+a986ead+e8c807f+88d3b0d+65bea31+3edcc24，全量套件绿，touched 包 -race 绿，vet 干净；遗留：2369 双写离线用例改写另立迁移任务，tls/rtmp 散发抖动基线可复现与本次无关）
**范围：** 本次解决：①层字段动态——`ip.src`/`ip.dst`（对象=动态，IP 算法）、`tcp.src_port`/`tcp.dst_port`、`udp.src_port`/`udp.dst_port`（对象=动态，端口算法）、`eth.src_mac`/`eth.dst_mac`（对象=动态，MAC 递增在 scope 内唯一新增算法，其余字段沿用 gen 系）、`ip.ttl`（对象=动态，小整数算法）接受"标量或动态对象"同键二态（与 FTP 字段同一套二态规则：对象写法=动态，标量=静态；范围口径：IP 层取 type=ip 字段（src/dst），tcp/udp 取 type=uint16 端口字段，eth 取 type=mac 字段，ttl 取 type=uint8 且 max≤255 字段（vlan/tls/终结层业务字段不在本阶段名单，见 §4）；非动态字段如 mss/handshake/tcp.flags/ip.dscp 仍只收标量——见 §4 名单）；②FTP 注册表补 sessions/commands/data_channel 字段表（只登记、不删除，原有 username/password 不变；层 config 校验接受 sessions 事务结构，segments 级值校验仍归 planner）；③扁平四元组清退——strategy create/update 拒绝 `layers` 与顶层 `src_ip/dst_ip/src_port/dst_port` 混用（语义层拒绝，`schema/semantic.go`，跨键规则 schema 表达不了；存量策略不追溯）；④畸形动态拒绝——层字段动态对象走 ValidateLayers（策略未知/range 非 2 元/end<start/list 空/pattern 缺模板·range → 400；任务启动预检同口径终态 error；批量路径逐流跳过计 flowFailures）；⑤静态复制拒绝——扁平键方案冻结（保留已合入规则，不再新增口径）；层链形状下 `checkLayerChainStaticCopy`（显式标量四元组+无对象+flows>1，见 §5 口径）；⑥schema/派生同步（strategy.json 扁平四键 anyOf 化撤销为纯标量+混用拒绝说明、`layers.json` 二态规则说明、MCP 描述表与前端类型重生成、负例横扫补层动态畸形/混用两例）。明确不解决：2369 个双写离线用例改写（另立批量迁移任务，本阶段只给形状+拒绝+文档，不许静默改 2369 个文件冒充完成）；`applySpecToChain` 旧端口写回链（清退过渡期保留，见 §3 优先级链）；`translateTerminalConfig` 旧协议配置优先声明（保留，§3 优先级链）；任务级跨策略共用动态池；ftp 子配置 $ref 化；老形状顶层 banner/commands 动态；并发会话、ABOR 中断、keepalive。
**依据：** CORE_MEMORY §1（层链唯一真相、旧扁平字段必须退出；混用禁止+两道验收门）、§12（动态 mandate：五策略/seed+序号可复现/回绕/静态复制拒绝；"动态是值的算法、层链是值的住处"、批量 tuples 为参考基线）；代码基线 `internal/core/layers/chain_planner_chain.go:276`（applySpecToChain：spec 四元组注入层 config）、`strategy_convert.go:250`（extractLayerSrcDst）、`:281-289`（flat 默认读入）、`validate_layers.go:133`（ValidateLayers 入口）、`worker.go:307-337`（策略循环 auto-inc+拷贝+FlowIndex=i@337）、`:802`（批量预检 `p.Validate(spec)`）、`shard_router.go:58/105`（genStringValue/applyPattern 单真相）、`tuple_generator.go:34/79`（genIP/genPort）；注册表现状 `layers.generated.json`（ip.src/dst type=ip、tcp/udp.src_port/dst_port type=uint16、eth.mac、ip.ttl uint8 max 255）。
**配置权威：** 层链是唯一真相。动态字段的住处=层字段；扁平四键在带 `layers` 的 config 里是非法键（混用拒绝）；`flow_control` 仍是数量唯一来源。FTP 字段动态（D-FTP-2 已验收部分）住处=ftp 层，不动。

#### 1. 数据与接口
- 动态策略复用 `dynamic_value`（defs.json 已有：fixed/inc/rand/list/pattern 条件必填已具备，零改动）。层字段二态形状由 Go 层注册表+ValidateLayers 表达（schema layers.json 只加说明文字，不逐字段 anyOf——字段表是生成的，逐字段手写 anyOf 即第二套真相，禁止）。
- `internal/core/layers/validate_layers.go`：`ValidateLayers` 层 config 值遍历时——对象值→走 dynamic_value 形状检查（strategy 未知/range 非 2 元/list 空/pattern 缺模板·range/end<start → 精确字段路径错误 `layers[i](name).field: …`）；标量值→走既有 V9 类型范围检查（零行为变化）。非动态名单字段见对象值→拒绝（"字段 X 不支持动态"）。
- `internal/core/types.go`：`FlowSpec` 增层动态缓存 `LayerDyn *LayerDynValues json:"-"`（结构：`IP{Src,Dst *StrategyConfig} TCP{SrcPort,DstPort *StrategyConfig} UDP{SrcPort,DstPort *StrategyConfig} Eth{SrcMAC,DstMAC *StrategyConfig} TTL *StrategyConfig`；v2 的 `Tuples`/`SrcIPDyn` 等扁平 Dyn 字段按 §7 撤销——v2 代码未合并，撤销=不合入，只合入 FlowIndex）。`FlowIndex`（v2 已合入）保留。
- `internal/core/strategy_convert.go`：mapToFlowSpec 增 `parseLayerDyn(cfg["layers"])`（层数组→LayerDynValues：ip/src·dst、tcp·udp/src_port·dst_port、eth/src_mac·dst_mac、ip/ttl；对象→StrategyConfig，畸形→`spec.ValidationErrors`）；`extractLayerSrcDst` 保持（静态标量路径零改动）；flat 四键保持纯标量解析（动态对象输入→ValidationErrors："带 layers 时四元组请写层字段"，见 §5）。
- `internal/core/worker.go`：策略循环 auto-inc 之后插入层动态解析块（`resolveLayerTuple(spec, i)`：IP→spec.SrcIP/DstIP、端口→spec.SrcPort/DstPort、MAC→spec.SrcMAC/DstMAC、TTL→spec.TTL；Resolve* 非零才覆盖；批量循环同块插入——批量类 layers 配置此前无动态，属新增能力非行为变化）。v2 的扁平 Dyn 解析块按 §7 撤销（未合并则不合入）。
- `internal/core/layers/registry.go`：ftp 层加 `sessions`（type=list）、`commands`（type=list）、`data_channel`（type=object）字段（只登记形状，值语义归 planner；阶段一/二解析逻辑不动）。
- schema：`strategy.json` 扁平四键恢复纯标量 + 描述注明"带 layers 时禁止出现（混用拒绝）"；`layers.json` 描述加二态说明段落；v2 `tuples` 不存在（未实施）无需撤销。重跑三台生成器，门测试锁同步。
- 校验入口：`schema/semantic.go` ValidateStrategy synth 增混用拒绝（`layers` 与顶层 src_ip/dst_ip/src_port/dst_port 任一共存→400，位置：TFTP tid 规则之后，与 flat 静态复制规则并列；文案给迁移指引："地址写 ip 层 src/dst，端口写 tcp/udp 层 src_port/dst_port"）+ 层链静态复制 `checkLayerChainStaticCopy`（layers 存在 + 层内四元组字段全标量 + fc flows>1 → 拒绝，逃生口=层内字段写对象；位置同上）+ 批量路径 `core.ValidateBatchSpec` 逐类混用拒绝（自审发现 strategy 入口覆盖不到 batch 内联 classes；同文案，`convert.go` 内联 6 行——schema import core，反向复用成环）。FTP sessions 静态复制/畸形规则（v2 已合入）不动。

#### 2. 依赖与生命周期
- 前置：v2 FTP 字段动态已合入（03a175d/2ed5dda）；`dynamic_value` 条件必填已具备（allOf，schema 单测已覆盖）；`applySpecToChain` 与 `translateTerminalConfig` 保留（过渡期双写兼容，见 §3）。
- 解析时机：层动态在 worker 每流循环 O(1)（逐字段 Resolve）；ValidateLayers 在 create/update + 任务启动预检各跑一次（纯内存形状检查，无包开销）；LayerDyn 只读（跨流共享指针，v2 只读约束延续）。
- 存量策略：混用拒绝只拦新建/更新（create/update 语义层），已入库双写策略照跑（任务启动不复查混用——避免线上任务突然变红；迁移任务另行改写）。

#### 3. 主流程与状态
- 策略流循环 i：spec 副本 → auto-inc（既有条件：flowCount>1 且无显式扁平端口）→ 层动态 `resolveLayerTuple(i)` 非零覆盖 → FlowIndex=i → computeHashKey → Plan（顺序与批量同序；auto-inc 先跑后被覆盖是无害的，保持与批量"覆盖在后"同构，不加跳过条件）。
- 层动态→spec→链：`resolveLayerTuple` 写 spec 四元组/MAC/TTL → `applySpecToChain` 按既有规则注入层 config（spec 显式 wins；过渡期扁平端口写回链行为保留——无 layers 时唯一来源，有 layers 时 flat 已被混用拒绝拦掉，故写回只剩"层动态解析出的 spec 值"，无歧义）→ 生成器读层 config（零改动）。批量循环顺序：tuples 池 → 层动态（层声明 wins）→ FlowIndex → 分片。
- 优先级链（过渡期如实记录）：层动态解析值 > auto-inc > 扁平静态（无 layers 时）> 引擎默认；`translateTerminalConfig` 的"flat 优先"声明仅作用于终结层协议子配置（http/dns 等），不作用于四元组（四元组走 applySpecToChain），两者正交、无冲突。

#### 4. 递增与覆盖规则
- 算法单真相：IP/端口=genIP/genPort（fixed/list/inc/rand，不支持 pattern）；MAC=新增 `genMAC(s,i)`（OUI 保留前 3 字节、后 3 字节按 inc 语义递增回绕；rand 种子同规则；list 轮换；fixed 常值；pattern 不支持——MAC 模板无规范先例，拒绝）；TTL=新增 `genSmallInt(s,i,min,max)`（inc/list/rand/fixed，pattern 不支持）；字符串类（将来扩展）=genStringValue。全部确定性（seed+i）+到尾回绕。
- 动态名单（本阶段开放）：`ip.src/ip.dst`、`tcp.src_port/tcp.dst_port`、`udp.src_port/udp.dst_port`、`eth.src_mac/eth.dst_mac`、`ip.ttl`。非动态字段（见对象即拒绝）：`tcp.mss/handshake/termination/rst/retransmit/concurrent/initial_seq/window_size`、`ip.dscp/ecn/frag_offset`、`udp.*` 除端口外无他字段、`eth.*` 除 MAC 外、`vlan.*`、`tls.*`、全部终结层业务字段（除 ftp.sessions 系已验收）。名单写死在 validate 代码注释 + 本节，评审抽查。
- 覆盖：同键二态天然互斥（标量/对象二选一）；层动态解析值非零才覆盖 spec（零值回退既有链）。

#### 5. 错误与异常
- 混用拒绝（新增）：`layers` 与顶层 src_ip/dst_ip/src_port/dst_port 任一共存→400（create/update；文案含迁移指引；错误码 V-NEW）。存量双写策略已入库的不追溯（启动不查）。
- 层动态畸形（新增）：strategy 未知/range 非 2 元/end<start/list 空/pattern 缺模板·range/非动态名单字段见对象→ValidateLayers 精确路径错误（create 400；任务启动预检同口径终态 error；批量逐流跳过计 flowFailures）。
- 层链形状下"显式全静态+flows>1"：`checkLayerChainStaticCopy` 拒绝——仅当层内有任一四元组字段被显式写成标量（ip.src/dst、tcp/udp.src_port/dst_port 任一出现）且无任一写成对象且 fc flows>1；全缺省层（如 `[{tcp:{}},{http:{}}]` 无四元组字段）不触发（T-FTP-15 ④保持 201）。文案家族同 flat 规则，逃生口=层内字段写对象。
- 扁平四键收动态对象：REST 路径在形状层先 400（strategy.json 扁平四键纯标量，对象进不来）；引擎直调路径（mapToFlowSpec 直传对象）在 `spec.ValidationErrors` 拒绝（"四元组动态请写层字段：ip.src/ip.dst、tcp/udp.src_port/dst_port"）→ worker 预检（worker.go:210）终态 error。v2 扁平二态实现按 §7 不合入。
- planner 错误继续中断 Plan（既有语义）；超时/重传归 tcp 层（D-FTP-1 归属不变）。

#### 6. 性能设计与验收
- worker 每流新增 O(1) 逐字段 Resolve（与批量等价路径同量级）；parseLayerDyn 每任务一次 O(层数)；ValidateLayers 层 config 值遍历 O(字段数)；LayerDyn 只读无锁；resolveTx 零拷贝规则延续。回归套件耗时相对基线 ±10% 内；不新增性能门；pcap/网卡沿用既有 harness。

#### 7. 实现顺序与回滚
1. schema：strategy.json `tuples` 属性删除（v2 71bed09 误加，未合并则直接不合入；若已合入则 revert 该文件段）+ tuple_config 端点收紧保留与否按 §7-注决策 + 扁平四键描述加混用说明、layers.json 二态说明 + 三台生成器重跑 + 形状用例（failing：混用 4 键各 1 例 + 层动态畸形 4 例）→ 2. core：LayerDynValues + parseLayerDyn + genMAC/genSmallInt + 导出包装（failing：TestParseLayerDyn + MAC/TTL 单测）→ 3. worker 两循环 resolveLayerTuple（T-FTP-7/8/9 改版为层形状输入）→ 4. registry ftp sessions 登记 + ValidateLayers 二态校验（T-FTP-10..14 输入已是层形状，FTP 解析逻辑不动；T-FTP-14 补层畸形 2 例）→ 5. 混用拒绝 + 层链静态复制规则 + 横扫补 2 例（T-FTP-15/16 改版）→ 6. 全量套件 + touched 包 -race + vet/gofmt + 文档状态回写。v2 未合并代码处置：`Tuples`/`SrcIPDyn` 等扁平 Dyn 字段、扁平二态解析块、worker tuples 块、checkStaticCopy 扁平规则——按"冻结保留"评估：checkStaticCopy 防新扁平双写，予以保留（§9 F 行：保留+冻结口径）；其余不合入。回滚=按提交逆序 revert（schema 与派生同提交）。
- §7-注（tuple_config 收紧去留）：v2 把 tuple_config 四端点收紧为 anyOf[标量, dynamic_value]——该 $def 被 batch.json 共用。决策：保留收紧（批量 tuples 标量简写本就是 schema 描述承诺的；既有批量用例若有标量端点则此前穿透未验，收紧后变红的用例按"形状补对象写法"更新，随本阶段提交）。影响面已预查（2026-09-10）：离线 cases 批量 tuples 标量端点 0 处，收紧零回归。
- v2→v3 用例映射：T-FTP-7（输入改层形状）/8（同）/9（同）/10..14（输入已是层形状：FTP 会话字段本来就在 ftp 层内，不动；T-FTP-14 补层动态畸形）/15（p13 输入改 `src_ip` 对象→层内对象；p14 扁平静态复制保留；补混用例）/16（不动）/17（横扫数重算）。

#### 8. 验收
- 对应 `docs/TEST_CASES.md` T-FTP-7…T-FTP-17（v3 改版输入）。完成条件：五策略在层字段与 FTP 字段全绿；rand 可复现/回绕断言；两条拒绝（混用/层链静态复制）各有反例；畸形动态任务 error；`go build/vet` 干净；touched 包 -race 绿。
- §1 两道门进度如实记录：①层链动态跑通（本条目）；②扁平四键与 layers 混用拒绝上线（本条目）+ 2369 双写用例改写（另立迁移任务，不在本条目冒充完成）。

#### 9. 关键决策对比

| 决策 | 候选 | 优劣 | 结论 |
|------|------|------|------|
| A 动态住处 | A1 扁平键二态（v2）；A2 层字段二态（v3，用户裁定） | A1 在将被删除的键上加功能，方向错误；A2 动态落层字段=§1 唯一真相，扁平键只剩清退 | 选 A2 |
| B 层字段二态形状表达 | B1 schema 逐字段 anyOf；B2 Go 注册表+ValidateLayers（schema 只加说明） | B1 字段表是生成的，手写 anyOf 即第二套真相；B2 单真相在 Go，schema 不分叉 | 选 B2 |
| C MAC/TTL 动态 | C1 不做；C2 做（MAC 新增算法、TTL 小整数） | 用户示例含 MAC 动态需求的同类场景；MAC 无 pattern（无规范先例）；TTL 名单限定 | 选 C2（名单制） |
| D 非动态名单 | D1 全字段可动态；D2 名单制（开放 9 字段+ttl） | D1 把 mss/handshake 等开关变成动态=语义灾难；D2 评审可抽查 | 选 D2 |
| E 混用拒绝范围 | E1 建改都拦+启动复查；E2 只拦建改（存量照跑） | E1 让线上存量任务突然变红=事故；E2 迁移任务另行改写，风险可控 | 选 E2 |
| F 扁平静态复制 checkStaticCopy（v2 已合入） | F1 合入保留（防新扁平双写）；F2 回滚删除 | 扁平键已进入清退但仍是无 layers 策略的唯一写法，规则保留防静态复制回潮；口径冻结不再扩展 | 选 F1（保留+冻结口径） |
| G2 层链静态复制 checkLayerChainStaticCopy（新增） | G2a 显式标量触发（缺省层不触发）；G2b 任一四元组字段出现即触发 | G2b 会把 `[{tcp:{}},{http:{}}]` 无字段层也判死，误伤 T-FTP-15 ④；G2a 只拦显式写死的，缺省层放行 | 选 G2a |

### D-FTP-4 IPv6 对称覆盖 + 扩展被动/主动（RFC 2428）

**状态：** 已验收（实现提交 22a7d56；单测 `TestGenIP_IPv6*/TestValidIP_MixedFamily` + `TestParseEPSVPort/TestParseEPRTPort/TestScanTxForDataPort_EPSVEPRT` 全绿，三包回归绿，新单测 -race 绿，全量套件 141/141 绿；现网行为已抓包回填见依据行，不影响验收结论）
**范围：** 本次解决：①IPv6 动态地址——层 `ip.src`/`ip.dst` 动态对象接受 IPv6 端点（inc/rand/list/fixed，`::` 缩写与文档全写双向互通），`genIP` 从纯 IPv4 算法扩展为双栈（IPv4 保持 32 位整型递增/回绕口径零变化；IPv6 新增 128 位递增/随机/轮转，跨段进位与回绕口径与 IPv4 同构）；②IPv6 扩展被动/主动——`EPSV`（RFC 2428 §3，被动，服务端回 229 含纯端口）与 `EPRT`（RFC 2428 §4，主动，客户端发 `EPRT |2|addr|port|` 三元组）信令端口推导（`scanTxForDataPort` 新增两路解析，与既有 PASV/PORT last-wins 同序；数据通道四元组仍走既有 `dataChannelPorts` 优先级链，零改动）；③IPv6 对称用例——现 2 例（passive 下载/active 上传）之外，按 §9 地址族对称要求补齐动态地址×策略、双会话/多流、EPSV/EPRT 四格（T-FTP-18…21）。明确不解决：`LPSV/LPSX/LPAS` 等历史方言（RFC 1639/795，已被 2428 替代，主流服务端不实现，记 C 类）；`EPRT |1|` IPv4 承载（2428 允许但现网只用 PORT，记 C 类不做）；IPv6 数据通道源端口 20 沿用（active 服务端源端口与地址族正交，RFC 959 §5.2，不变）；批量路径 tuples 池 IPv6（策略+任务路径之外，另立条目）。
**依据：** RFC 2428 §3（EPSV→229 `(|||port|)`，只通告端口、地址沿用控制连接）、§4（EPRT `|af|addr|port|`，af=1 IPv4、af=2 IPv6）、§5（EPRT/EPSV 失败回退 PORT/PASV 语义，用例覆盖失败分支）；RFC 959 §4.1.2（PASV/PORT 六元组，IPv4 专用——v6 下服务端发 227 无意义，见 2428 §1 引言）；RFC 4291 §2.2（IPv6 文本表示：`::` 压缩、全写、混合表示法，解析必须三态互通）；现网行为（2026-09-12 本地实测，vsftpd 3.0.3，IPv4 实例 :21212 + IPv6 实例 :21222，匿名登录，原始问答逐字记录于本条目附录）：①EPSV 默认开——IPv4 连接上未登录发 EPSV 即进命令分发（回 530 是“未登录”不是“不支持”），FEAT 声明含 EPSV/EPRT，登录后 `EPSV`→`229 Entering Extended Passive Mode (|||21213|)`（v4 上可用，与 FileZilla“EPSV 只用于 IPv6”客户端策略不同——服务端侧 v4/v6 双开）；②EPRT 双栈同源——v4 连接上 `EPRT |1|127.0.0.1|50011|`→`200 EPRT command successful`（服务端认 af=1，本实现 af=1 记 C 类不做是“流量侧不生成”而非“服务端不支持”，文档口径以此为准）；v4 连接上 `EPRT |2|::1|50011|`→`500 Bad EPRT protocol`（族与连接不匹配即 500，不是 522——522 只用于服务端不支持的协议族）；③v6 下 PORT 判死、PASV 放空——v6 连接上 `PORT …`→`500 Illegal PORT command`（FileZilla 论坛“PORT is only for IPv4”同款），`PASV`→`227 Entering Passive Mode (0,0,0,0,82,237)`（地址全零无意义，印证 2428 §1“PASV 在 v6 下无意义”——本实现 v6 用例只用 EPSV/EPRT，不配 PASV/PORT）；④EPSV 真实下载打通——v4/v6 上 `EPSV`→229→`RETR`→数据（client 首 SYN→229 通告口）→226 全程 18 字节对账无误，数据通道端口=229 通告值（与本实现 `dataChannelPorts` 优先级 2 一致）；⑤ProFTPD（proftpd.org/docs/howto/FTP.html 命令表：EPSV/EPRT 均为支持命令，注释“可处理 IPv6 地址”）与 FileZilla Server（论坛 t=45943：v6 上 PORT 被拒“use EPRT instead”；客户端侧 v6 强制 EPSV）为文档依据，未本地起实例（行为与 vsftpd 实测一致，记“文档确认”）；代码基线 `internal/protocol/ftp/ftp.go:844`（portCmdRe）、`:830`（pasvPortRe）、`:744`（scanTxForDataPort）、`internal/core/tuple_generator.go:34`（genIP 纯 IPv4）、`internal/core/layer_dyn.go:186`（validIPv4 端点校验）。

附录：现网问答逐字记录（vsftpd 3.0.3，2026-09-12）
```
# IPv4 控制连接（:21212），匿名登录后：
>> FEAT            << 211-Features: EPRT / EPSV / MDTM / PASV（另有 211 End）
>> EPSV            << 229 Entering Extended Passive Mode (|||21213|)
>> PASV            << 227 Entering Passive Mode (127,0,0,1,82,227).
>> EPRT |2|::1|50011|      << 500 Bad EPRT protocol.
>> EPRT |1|127.0.0.1|50011| << 200 EPRT command successful. Consider using EPSV.
>> PORT 127,0,0,1,195,80   << 200 PORT command successful. Consider using PASV.
# IPv6 控制连接（:21222），匿名登录后：
>> EPSV            << 229 Entering Extended Passive Mode (|||21228|)
>> PASV            << 227 Entering Passive Mode (0,0,0,0,82,237).   # 地址全零，无意义
>> EPRT |2|::1|50011|      << 200 EPRT command successful. Consider using EPSV.
>> PORT 127,0,0,1,195,80   << 500 Illegal PORT command.              # v6 下 PORT 判死
# 真实下载（ftplib，TYPE I → EPSV → TYPE A → RETR test.txt）：
v4: EPSV → 229 (|||21218|)，18 字节对账无误；v6: EPSV → 229 (|||21224|)，18 字节对账无误。
# 线上抓包（mcp-socket-server，root 抓包机 10.12.131.35，lo 口，/home/tmp/ftp-epsv-lo.pcap，39504 字节——tcpdump 单流双写，包有重复，读数时以“首包”为准）：
v4 控制面（21212）：EPSV→229 (|||21213|)；PASV→227 (127,0,0,1,82,228)；EPRT|2|→500 Bad EPRT protocol；EPRT|1|→200；PORT→200。
v6 控制面（21222）：EPSV→229 (|||21225|)；PASV→227 (0,0,0,0,82,232)；EPRT|2|→200；PORT→500 Illegal PORT command。
v6 数据面（21229）：client 60382→server 21229 首 SYN（SYN 0x0002），server 回 SYN-ACK（0x0012），随后 server→client 发 18 字节 PSH（0x0018，内容 `hello epsv verify`），FIN/RST 收尾——与本实现“被动=client 首 SYN、载荷 server→client”一致，端口=229 通告值。
```
**配置权威：** 层链是唯一真相。IPv6 地址仍只落 `ip` 层（`src`/`dst` 标量或同键二态对象）；EPSV/EPRT 是 `ftp` 层命令字符串（commands[].cmd/response），不是新字段、不新增层；数量仍只走 `flow_control`。

#### 1. 数据与接口
- `internal/core/tuple_generator.go`：`genIP` 双栈——端点先判族（同流两端点必须同族，混族拒绝，走既有畸形拒绝通道）：IPv4 走既有 `ipToU32/u32ToIP`（零改动）；IPv6 新增 `ip6ToU128/u128ToIP`（16 字节 big-endian，加减/回绕与 IPv4 同构，step≤0 视为 1，rand 用 `seed+i` 同规则）。`asString` 端点渲染不变（IPv6 字符串原样透传）。
- `internal/core/layer_dyn.go`：端点校验 `validIPv4` 扩展为 `validIP`（v4 点分十进制 / v6 `net.ParseIP` 且 `To4()==nil`；混族 range/list（`10.0.0.1` 与 `2001:db8::1` 同 range）拒绝，文案指明两端须同族）。`checkDynShape` 的 pattern 拒绝保留（IP 无 pattern，与族无关）。
- `internal/protocol/ftp/ftp.go`：新增 `parseEPSVPort(response string) uint16`（`229` + `(|||port|)`，last-wins、溢出拒绝口径与 `parsePASVPort` 同款）与 `parseEPRTPort(cmd string) uint16`（`EPRT |2|addr|port|`，af 必须为 2——af=1 是 IPv4 承载记 C 类不做，见范围；addr 段只做透传不校验，端口段做数值合法性校验）。`scanTxForDataPort` 被动分支新增 EPSV 解析（与 227 同序 last-wins：同一事务既有 227 又有 229 时后者赢——与现网“后通告覆盖先通告”一致，待抓包确认）、主动分支新增 EPRT 解析（与 PORT 同序）。`scanCommandsForDataPort`（老形状遗留路径）同步新增两路（同函数体两处调用点）。
- `internal/protocol/ftp/layer_gen.go`：零改动（复用 `scanTxForDataPort`，已解析响应天然生效；`dataChannelPorts` 优先级链不动）。
- schema：零改动（layers.json 二态说明已覆盖“IP 算法”，不逐族列举；Error 文案经 Go 层返回，不进 schema）。

#### 2. 依赖与生命周期
- 前置：D-FTP-3 层动态（LayerDyn 解析/校验/逐流）已验收；IPv6 静态已通（ftp_ipv6_data/active，EtherType 0x86DD 路径已验收）。
- 解析时机：同既有——层动态每流 O(1)（genIP 双栈分支在流循环内，无额外分配：IPv6 用 16 字节数组栈上运算）；EPSV/EPRT 解析在 Plan 内事务扫描时（与 PASV/PORT 同频次，零新增遍历）。
- 只读约束延续：Dyn 指针跨流共享只读；正则预编译包级变量（与既有 pasvPortRe/portCmdRe 同款）。

#### 3. 主流程与状态
- IPv6 动态流循环 i：spec 副本 → `resolveLayerTuple(i)`（genIP 双栈分支产出 v6 字符串）→ spec.SrcIP/DstIP（v6）→ `applySpecToChain` 注入 ip 层 → IP 生成器按族装配（既有 v6 路径，零改动）→ finalEmit 按 `EtherTypeFor` 落 0x86DD（既有路径）。
- EPSV 被动事务：`EPSV`→`229 Entering Extended Passive Mode (|||50010|)`→`RETR`（150，emit）→数据（client 首 SYN→server 50010）→`226`。EPRT 主动事务：`EPRT |2|2001:db8::1|50011|`→`200`→`STOR`（150，emit）→数据（server 首 SYN→client 50011）→`226`。端口推导：信令解析值优先（既有优先级 2），无信令回退 50000/20（既有优先级 3，不变）。
- 失败分支（RFC 2428 §5）：EPSV→500（服务端不支持扩展模式，回退 PASV 同事务内重协商——本用例只断控制面 500 无数据通道）与 EPRT→522（网络协议不支持，同理）各一例。

#### 4. 递增与覆盖规则
- IPv6 inc：`2001:db8::1`→`::2` 低 128 位递增，跨段进位（如 `::ffff`→`::1:0`），end<start 拒绝（128 位比较）；step 口径与 IPv4 一致。rand：`seed+i` 在 [start,end] 区间内均匀（区间按 128 位差计，大区间只取低 64 位随机+高位保持——实现细节，单测锁定行为）。list：轮转（`::` 缩写与全写视为不同字符串但同地址——去重不做，断言按字符串钉，pcap 按地址验，双口径注明）。fixed：常量。
- EPSV/EPRT 覆盖：同键二态天然互斥不适用（命令是字符串，无动态对象）；信令 last-wins（后通告赢）与既有 PASV/PORT 一致；显式 `dc.SrcPort/DstPort` 仍最高优（优先级 1，不变）。
- v4/v6 混族：同一 range/list 两端异族→畸形拒绝（任务 error / 400），不静默取一族。

#### 5. 错误与异常
- 混族动态端点（v4+v6 同 range/list）：ValidateLayers 精确路径错误（create 400；任务启动预检同口径终态 error；批量逐流跳过计 flowFailures）。文案指明两端须同族。
- 畸形 EPSV/EPRT（`229` 无 `(|||port|)` / 端口溢出 / `EPRT` af≠2 / 缺段）：扫描返回 0→回退 50000/20（与既有 PASV/PORT 畸形同语义：信令解析失败≠任务失败，回退是正确行为，用例断言回退端口而非 error）。af=1 的 EPRT 按 C 类不做（不断言，文档注明）。
- EPSV→500 / EPRT→522：控制面失败分支用例（无数据通道，包序列=握手+命令对+挥手），错误码断言 500/522。
- planner 错误继续中断 Plan（既有语义）；超时/重传归 tcp 层（D-FTP-1 归属不变）。

#### 6. 性能设计与验收
- genIP 双栈：IPv4 路径零改动（热路径无新增分支：先判族一次，v4 直接走老代码）；IPv6 用 16 字节数组运算，无堆分配；EPSV/EPRT 扫描与既有同频次（每事务一次，零新增遍历）。回归套件耗时相对基线 ±10% 内；不新增性能门；pcap 沿用既有 harness（tshark `ipv6.src`/`ftp.request.command` 断言已验证可用）。
- pcap 与真实网卡分别测什么：pcap 断言地址/端口/命令序列；网卡冒烟（enp135s0f0np0 既有跑法）至少跑通 EPSV 被动下载一例（v6 组播/路由环境相关，跑不通则注明环境限制不算失败）。

#### 7. 实现顺序与回滚
1. core：`ip6ToU128/u128ToIP` + `genIP` 双栈分支 + `validIP`（failing 先行：`TestGenIP_IPv6Inc/Rand/List/Fixed` + `TestValidIP_MixedFamily_Rejected`，位置：`internal/core/tuple_generator_test.go` / `layer_dyn_test.go`）→ 2. ftp：`parseEPSVPort/parseEPRTPort` + 两处扫描接入（failing 先行：`TestParseEPSVPort/TestParseEPRTPort` + `TestScanTxForDataPort_EPSV/EPRT`，位置：`internal/protocol/ftp/ftp_data_test.go`）→ 3. 用例 T-FTP-18…21（§8 口径，先写后跑，真实 pcap 校准）→ 4. 全量套件 + touched 包 -race + vet/gofmt + 文档状态回写。回滚=按提交逆序 revert（core 双栈与 ftp 解析独立提交，可单独回滚）。
- 每步 failing test 先行（§9 修 bug 先红后绿）；单测断言 128 位边界（`::ffff`→`::1:0` 进位、`::` 缩写解析）必须有。

#### 8. 验收
- 对应 `docs/TEST_CASES.md` T-FTP-18…T-FTP-21。完成条件：IPv6 inc/rand/list/fixed 四格绿（rand 可复现/回绕断言）；EPSV 被动下载 + EPRT 主动上传绿（数据通道端口=信令通告值）；500/522 失败分支绿；混族拒绝红（任务 error）；`go build/vet` 干净；touched 包 -race 绿；FTP 全量套件绿（131+新增全绿）。
- §1 两道门进度如实记录：①IPv6 对称跑通（本条目）；②旧字段零新增（本条目不碰扁平，混用拒绝已由 D-FTP-3 上线）。

#### 9. 关键决策对比

| 决策 | 候选 | 优劣 | 结论 |
|------|------|------|------|
| A IPv6 递增算法 | A1 128 位整型递增（与 v4 同构）；A2 字符串后缀数字递增（如 `::1`→`::2` 只动末段） | A1 跨段进位正确（`::ffff`→`::1:0`）、回绕口径与 v4 一致；A2 末段溢出即错（`::ffff`+1 无定义），且与 rand 区间语义分裂 | 选 A1 |
| B 混族端点处置 | B1 拒绝；B2 按首端点族静默 | B1 失败路径可测（§5/§9 要求错误真红）；B2 隐性丢一族=测不出的退化 | 选 B1 |
| C EPSV/EPRT 解析位置 | C1 扫描函数内新增两路（与 PASV/PORT 同序）；C2 独立新函数+调用方分支 | C1 last-wins/回退语义自动继承，调用方（ftp.go/layer_gen.go 两处）零改动；C2 两处调用方各加分支，语义易分叉 | 选 C1 |
| D EPRT af=1（IPv4 承载） | D1 同做；D2 记 C 类不做 | D1 现网只用 PORT 传 v4（2428 §4 允许但无部署），做了无人用且多一分支待测；D2 文档注明不冒充 | 选 D2 |
| E 历史方言 LPSV/LPSX | E1 同做；E2 记 C 类不做 | E1 RFC 1639/795 已被 2428 替代，主流服务端不实现；做了无现网对照 | 选 E2 |

### D-HTTP-1 HTTP 底座契约固化（8 子女共用门厅）

**门 1 开工对照表（§1–§14，2026-09-13 http 重走，三道硬门之门 1；证据=文档节/代码行/用例号）：**

| § | 本协议怎么满足 | 证据 |
|---|---|---|
| §1 层链唯一真相 | 顶层旧键：`src_ip/dst_ip/src_port/dst_port/count` 零残留（门 2 脚本扫，扁平负例除外）；顶层 `http` 子映射是过渡载体（全协议普查：60+ 文件并存，ftp 已删为范本），本条目迁入层（`ParseHTTPConfigFromMap` + 见 §7 步骤 1–4）；目标形状见本表后例子 | `pipe_gate.sh http` 门 2-1 绿；`strategy_convert.go:378` 通用读；`chain_planner_translate.go:830` 层翻译 |
| §2 策略/任务分工 | http 无 sessions，Transactions 是单连接内序列；多流只走 `flow_control` + 层动态；任务合跑沿框架语义，不另设 | D-HTTP-1 §3；T-HTTP-9/10/40/41 |
| §3 五件套 | 豁免：http 链一次一流，无子流派生、无 sessions[]、无关联字段；Transactions=单连接内事务序列；时间线=同步产全部事件、无交错 | `layer_gen.go:45` 三路分发；`terminalLoop:266`；T-HTTP-9/10 |
| §4 规范矩阵 | RFC 9110/9112 §6.3/7230 §3.3.3 §4.1 §5.4/1952 + nginx 1.21.5 实测 + Go net/http 源码对照；重走范围见本条目范围①②③（原 P1 四缺口已提交 64cc9d7，不重议） | D-HTTP-1 依据行；§9 A–E 决策表 |
| §5 有错必处理 | 校验器调 Planner.Validate + pin 握手/挥手；载体 8 家同步拒绝；内层提前关闭排空后返回；扁平/混用沿 Step1 | `http.go:46`；`validate_layers.go:86-98`；T-HTTP-1/3/50/51/52 |
| §6 性能 | 事件流式无全量收集、无锁无 sleep；回归 ±10%（实测 wall 回填）；边界诚实声明（无吞吐/并发/内存目标，网卡未跑） | D-HTTP-1 §6；T-HTTP-5/6 |
| §7 三份文档 | 设计=本条目；用例=T-HTTP-1…72；cases 回指编号；schema 是机器契约不抄全文 | 本条目；TEST_CASES T-HTTP-* |
| §8 先设计后代码 | 本条目定稿（含门 1 表）后开工；本轮返工=设计先改（§7 步骤），代码随后 | 本条目 §7 |
| §9 三源+整格 | 三源每条回指；枚举分支代表；正交矩阵；动态整格（本表后清单）；断言边界注明 | T-HTTP-1…72；§4 矩阵 |
| §10 评审闭环 | 改→审→测→修→再审；自审 N 轮结论；测试四问 | T-HTTP-6；门 3 抽查 |
| §11 白话汇报 | 先一句结论；代号带解释；证据只贴路径与结论 | 每次汇报 |
| §12 动态清单 | 四元组沿框架白名单；业务 6 开 15 关（本表后清单；headers 两键闭：map 型无动态形状，见裁定表 F）；序号算法不重写 | `layer_dyn.go:17`；`tuple_generator.go:194`；T-HTTP-41/47/53…59/60…72 |
| §13 schema 同步 | 本轮改注册表 http Fields（5→21 键）必须重跑 `layers/schemagen` 并提交生成文件；MCP/前端派生同步验 | `generated/layers.generated.json`；门 2 脚本 |
| §14 真实流程 | cases 即任务 spec；MCP 建任务→引擎生成→tshark 校对；负例带锚词；全量绿；二进制同代；包落盘可查 | T-HTTP-5；门 2 三项 |

目标形状（§1 证据，顶层只留 `layers` + `flow_control`，ftp 范本同构）：`{"layers": [{"ip": {"src","dst"}}, {"tcp": {"src_port","dst_port"}}, {"http": {"method","uri","version","headers","request_headers","body","body_b64","keep_alive","transactions","response_headers","response_body","response_body_b64","response_status_code","response_status_text","response_content_encoding","request_content_encoding","request_transfer_encoding","response_transfer_encoding","chunk_size","pipelined","file_source"}}]}`（21 键全列，见 §7 步骤 1 表）。

业务动态清单（§12 证据，6 开 15 关；开=uri/body/body_b64/response_body/response_body_b64/response_status_code；关=method/version/headers/request_headers/keep_alive/transactions/response_headers/response_status_text/三编码开关/两transfer开关/chunk_size/pipelined/file_source——headers 两键闭是形状原因（map 型无动态形状，`StrategyConfig.List []string` 装不下 map，fixed 恒值又等价于静态），其余关是语义原因，理由见 §4 本节清单）。

**状态：** 已验收（2026-09-14：用户检查通过；http.json 67/67 绿，8 子女 suite 联验 621/621 绿，二进制同代，门 2/门 3 齐；门 3 抽查见本条目 §8）
**范围（重走版，2026-09-13）：** ①顶层 `http` 迁入层（注册表 http Fields 5→21 键 + `ParseHTTPConfigFromMap` 新建为翻译/通用读单一真相 + 层翻译改调用 + 顶层 `http` presence 判死，ftp 范本；`ParseFTPConfigFromMap` 同构先例）；②http 业务 6 字段开动态（uri/body/body_b64/response_body/response_body_b64/response_status_code，解析+回填+用例，15 关理由见 §4 本节清单）；③用例补齐（层内 21 键 + 业务动态整格 + 迁入回归；http.json 53 例顶层 `http`→层内合并——`http_layer_version_bare` 已是层内形为合并范本，`headers`/`content_encoding` 两兼容键随层走就是正键/`response_content_encoding`）+ 8 子女联验全绿。明确不解决：`strategy.json` 形状改动（config 节无 additionalProperties 约束）；`main.go` 接线（已是 ChainPlanner，零改动）；HTTP/1.0 之外的新版本方言；任务级跨策略共用动态池（与 D-FTP-2 同口径另立条目）。原 P1 四缺口（校验器+FLV prefix+5 家载体+删 ThinkTime，已提交 64cc9d7）保持已验收，不重议。
**依据：** RFC 9110（语义：请求行/状态行/头/体、Host、Connection）、RFC 9112 §6.3（持久连接与 pipelining）、RFC 7230 §3.3.3（Transfer-Encoding 优先于 Content-Length）/§4.1（chunk 帧）/§5.4（Host 为 1.1 强制）、RFC 1952（gzip）；现网行为（2026-09-13 本地实测，nginx 1.21.5 + Go 1.21 net/http 源码对照）：①无 Host 的 1.1 请求→`400 Bad Request`（有 Host→200；1.0 无 Host→200——与本实现 `isHTTP11` 门控一致）；②`Connection: keep-alive` 被接受→200（与 `defaultConnection` 多事务 keep-alive 一致）；③Go 源码 `request.go:Host` 字段注释（Host 头独立于 Header 表——与本实现 Host 单独处理一致）、`transfer.go:94`（ContentLength 0/-1 才发 chunked——与本实现 chunked 压制 Content-Length 一致）。开源对照：`net/http`（`request.go:Write` 请求行装配、`transfer.go` 分块；只借行为口径，不搬代码）。候选对比见 §9（A–E 五决策）。代码事实（见各节文件行）；存量（8 子女 554 例 + http.json 67 例 + http 单测 173 + `chain_planner_http_test.go` 8 测试）。
**配置权威：** 层链是唯一真相。地址只落 `ip` 层、端口只落 `tcp` 层、数量只走 `flow_control`；http 业务 20 字段只落 `http` 层（注册表 21 键含兼容旧 `headers`，翻译见 §1；`core.ParseHTTPConfigFromMap` 是层翻译与顶层通用读的单一真相，翻译侧多一步 version 裸值 prefix 归一）。顶层 `http` 子映射已判死（http 族 9 协议：`CheckProtoFlat` presence 拒绝 + `mapToFlowSpec` 在库 error，ftp 范本同构；`pipe_gate.sh` 门 2-1 见顶层 `http` 即红）。扁平四元组判死沿 Step1（`strategy_convert.go:7609` + `schema/semantic.go:128` + `convert.go:166`）。

#### 1. 数据与接口
- 注册表（`layers/registry.go:97`，本轮 5→21 键）：http 为 CategoryTerminal，`DependsOn:[tcp]`，`OptionalOn:[tls]`，`TransformEvents:true`，21 键（5 旧：method 默认 GET、uri 默认 /、version 默认裸 `1.1`、headers 默认 {}、body 默认 ""；16 新增：request_headers/body_b64/keep_alive/transactions/response_headers/response_body/response_body_b64/response_status_code/response_status_text/response_content_encoding/request_content_encoding/request_transfer_encoding/response_transfer_encoding/chunk_size/pipelined/file_source——类型与缺省见 §7 步骤 1 表），`FieldContract{"tcp.dst_port":"80"}`。8 子女全 `DependsOn:[http]`，契约端口：http/hls/hds/doh/onvif/http_flv=80、gbt/getwork=8332、cwmp=7547（`:395-502`）。改注册表后重跑 `layers/schemagen` 并提交生成文件（§13）。
- `core.HTTPConfig`（`types.go:2141-2220`）：20 键。字段全表（三选一：已实现/明确不支持/不适用；每行对应测试见 T-HTTP-43…52 与既有条目；层注册表 21 键=此 20 键 + 兼容旧 `headers`，翻译时旧键回退正键）：

  | # | 字段（JSON 键） | 实现/分支 | 对应用例 |
  |---|---|---|---|
  | 1 | method | 空→GET；任意字面直透（分支代表：GET/POST/PUT/DELETE/HEAD；OPTIONS/PATCH/TRACE/CONNECT 无 pcap 例——未建模分支，行为=同字面直透） | T-HTTP-7/8/29/30/31 |
  | 2 | uri | 空→/；字面直透 | T-HTTP-7/8/29 |
  | 3 | version | 空→HTTP/1.1；裸 `1.1` 归一；1.0 不自动 Host | T-HTTP-2/7/14 |
  | 4 | request_headers | 用户值任何版本都赢（含 Host/Content-Length/Content-Type 大小写不敏感覆盖） | T-HTTP-17 |
  | 5 | headers（旧键） | request_headers 缺席时回退兼容（存量行防丢头） | T-HTTP-43 |
  | 6 | body | 文本体；空→无 Content-Length/Content-Type | T-HTTP-8/26 |
  | 7 | body_b64 | 合法→解码优先于 body；非法→回退 body | T-HTTP-18/38 |
  | 8 | keep_alive | Transactions>1 或 true→keep-alive，否则 close | T-HTTP-9/40 |
  | 9 | transactions | ≤0→1；3 事务 13 包 | T-HTTP-9/10 |
  | 10 | response_headers | 覆盖默认 Content-Type/Location 等 | T-HTTP-22/32 |
  | 11 | response_body | 空→无长度无类型（包位 8）；有体包位 5 | T-HTTP-11/26 |
  | 12 | response_body_b64 | 优先于 response_body | T-HTTP-23 |
  | 13 | response_status_code | 0→200；表内码查表；表外码 `Status %d` 兜底 | T-HTTP-11/32/33/34 |
  | 14 | response_status_text | 非空覆盖表文本（含 418 自定义） | T-HTTP-24 |
  | 15 | response_content_encoding | gzip→压缩（长度计压缩后）；旧 `content_encoding` 键回退到此 | T-HTTP-12/44 |
  | 16 | request_content_encoding | gzip→压缩；非 gzip（br）字面直透 | T-HTTP-19/37 |
  | 17 | request_transfer_encoding | chunked→分块（压制 Content-Length）；非 chunked（identity）字面直透（单测 `TestBuildHTTPResponse_TransferEncodingNonChunked`；pcap 无例见 T-HTTP-36 注） | T-HTTP-20/35/36 |
  | 18 | response_transfer_encoding | chunked→分块；字面直透同请求侧 | T-HTTP-13 |
  | 19 | chunk_size | >0 按字节切块；0→整块单发 | T-HTTP-21 |
  | 20 | pipelined | true→全请求后全响应；Transactions≤1 时 no-op | T-HTTP-10 |
  | 21 | file_source | literal/file/fill/random 四形态（file 形态需落盘文件、MCP 不可达，不建 pcap 例，单测见 `http_filesource_test.go:6`） | T-HTTP-27/45/46 |

  层翻译管全 20 键（`chain_planner_translate.go:830-864` 重写：`core.ParseHTTPConfigFromMap(completedConfig(s,term.Config))` 单一真相 + version 裸值 prefix 归一 `HTTP/`；未写键经 `completedConfig` 取注册表缺省（5 旧键有缺省 + 16 新键零值），零值语义由 builder 接管；层 config `headers` 兼容键保留（注册表 21 键）。层内动态 6 对象剥离见 §4（`validate_layers.go:254` strip 后翻译读补全值；动态 6 键的静态底值仍进翻译，回填在 worker 侧逐流覆盖）。HTTPConfig 在 `types.go:2141` 无 `headers` 键（B 结构：struct 只留正键 `request_headers`，旧库顶层/旧层 `headers` 读时回退）。
- 生成器（`protocol/http/layer_gen.go:45-79`）：三路分发——`Meta.HTTPFLV/HLS/HDS` 非 nil 进帧变换器（内层产 body、http 包 GET/200）；`isHTTPRPCInner`（GBT/GetWork/CWMP/DOH/ONVIF）进透传变换器（事件已是完整帧，原样转）；否则终结模式（读 `req.Meta.HTTP`=层翻译产物，本轮重走后顶层 presence 判死、终结取值只有层翻译一条源）。注册 `RegisterHTTPGenerator`（`:359`）+ `RegisterLayerValidator("http",…)`（64cc9d7 已补，见 §5）。
- 变换器取参（本轮重走后 21 键全可读）：FLV 从 `req.Layer.Config` 读 method/uri/version（`:155-166`，flv 链专用默认 uri `/live/stream.flv`，rounds 取 `spec.HTTPFLV.Rounds` `:169-172`；重走后 keep_alive 等 16 新增键同样经 `completedConfig` 补全可读，变换器按需取，注意 `completedConfig` 只认识注册表键——动态对象在 ValidateLayers 已剥离，此处读到的是静态底值）；HLS（`hls_transformer.go:40`）/HDS（`hds_transformer.go:25`）读 version 带 prefix、uri 取自各 session。变换器 `Layer` 由驱动按 `chain[transportIdx+1+k]` 装配（`chain_planner_translate.go:505`），是已补全的层 config。
- builders（`http.go:552,739`）：用户>默认>无；Host 仅 1.1 自动加、IPv6 加括号（`:597,691`，`isHTTP11/bracketHost`）；Content-Type 嗅探（`:826`，magic 优先）；Content-Length 自动；Connection 缺省 keep-alive 当且仅当 Transactions>1 或 KeepAlive；gzip→chunked 先后顺序；头大小写不敏感覆盖；状态表 + `Status %d` 兜底（`:995`）；BodyB64 优先于 Body（`:635`）；FileSource 循环前解析一次、copy-on-write 防跨流串扰（`layer_gen.go:106,274`）。
- 端口补齐：`fieldContractDstPort` 读末层契约（`chain_planner_util.go:250`），经 `chain_planner.go:336,381` 写入；用户显式 tcp.dst_port 优先，无契约才报 `destination port is required`。http 自身与 8 子女的链缺层（hls/hds 缺 ip、http_flv 缺 ip/tcp）由 `CompleteChain`（`complete.go:90`）自动补，不手写。

#### 2. 依赖与生命周期
- 前置：tcp 层（握手/挥手/分段/序号归 tcp 生成器，`layers/generator.go:821` 默认 handshake/termination true）；tls 为可选（显式写才进变换器链，`chain_planner_translate.go:474-530`）。
- 8 子女依赖 http（注册表 `:395-502`）；载体检查 8 家（64cc9d7 已补齐，`validate_layers.go:86-98` 同款文案，见 §5）。
- 资源：无状态生成器（无字段）；事件通道 `transformCh` 级联（驱动 `:498-530`），关闭者=写者；结构性错误退出前排空输入（drain 纪律，FLV `:130`、HLS/HDS `drainEvents`）；`EmitMsg` nil 即报错不静默丢（`:292`）；取消走 ctx（每轮 select）。
- 初始化：`main.go:465` + 子女各 `NewChainPlanner` 已就位 + 空导入（hls `:59`、hds `:64`、gbt `:154`、getwork `:158`、doh `:170`、onvif `:174`、cwmp `:28`、http_flv `:54`），本轮不动接线。

#### 3. 主流程与状态
- 终结模式（`terminalLoop:266`）：transactions≤0→1；交错默认（请求紧跟响应）/pipelined（全请求后全响应，RFC 9112 §6.3.2）；FileSource 解析一次；请求/响应字节复用 builders，与 legacy `http.go:266-357` 逐字节一致。
- FLV 模式：每轮 GET(up)→读内层 body→200(down)；keepAlive=非末轮。HLS/HDS：按 sessions 数组序逐会话 GET→200，会话间不交错；无显式 body 时用内层 body 事件。
- 透传模式：逐事件 `EmitMsg` 原样转，流关闭即结束（tcp 照常分段/握手/挥手）。
- 会话—事务—多流：http 链一次一流（无子流派生、无 sessions[]）；Transactions 是单连接内事务序列；多会话/多流语义归各子女内层配置（hls/hds sessions、cwmp sessions/transactions），http 层不展开、不编号。
- 时间线：同步产全部事件，无交错调度；包时间戳由 ChainPlanner 回填。无等待点、无 sleep（ThinkTime 已删，见 §9 E）；超时/重传归 tcp 层（具体时长见 tcp 层设计，本条目不重复）。

#### 4. 递增与覆盖规则 + 正交组合矩阵 + 业务动态清单
- 动态白名单（`layer_dyn.go:17`，本轮扩到 http 业务 6 字段）：ip（src/dst/ttl）、tcp/udp（src_port/dst_port）、eth（mac）+ http（uri/body/body_b64/response_body/response_body_b64/response_status_code）；http 其余 15 字段写动态对象即 `does not support dynamic` 拒绝（`validate_layers.go:132`）。http 链的多流变化走 ip/tcp 层动态 + http 业务动态 + `flow_control` 数量。
- 业务 6 开 15 关（门 1 §12 清单，每行理由）：开=uri（路径是 §12 点名的关键业务字段）/body（负载是 §12 点名的关键业务字段）/body_b64（随 body，二选一同格不断两遍）/response_body（同 body）/response_body_b64（随 response_body）/response_status_code（状态分支批量覆盖，list 枚举最典型）；关=method（枚举语义，逐流变=不同测试点）/version（常量协商）/headers + request_headers（两键闭：map 型无动态形状——fixed 恒值等价静态、list 端点 `[]string` 装不下 map、pattern 替换进 map 无定义、inc/rand 数值区间对 map 无意义；Host/UA 逐流变走 body/uri 锚点覆盖）/keep_alive、transactions、三编码开关、两 transfer 开关（开关语义）/chunk_size（随 transfer 走）/pipelined（开关）/file_source（随 body 面）/response_status_text（随 status_code）。
- 合法策略集合（`layer_dyn.go:119` `checkDynShape`，本条定稿为准）：fixed（常量沿用）/inc（2 元 range，step≤0 视 1，到尾回绕）/rand（2 元 range + seed+序号，同序号同值）/list（非空轮转，端点类型须与字段一致——端口 list 端点是字符串，`StrategyConfig.List []string`，写数字报 `invalid object`）；pattern 在层地址端口维度不支持（类型算法无 pattern 分支，大声拒绝 `pattern strategy is not supported`，不是没测）。序号算法沿框架生成器（`tuple_generator.go:194 genPort` / `genIP` / `genMAC` / `genSmallInt` + `shard_router.go:58 genStringValue` 字符串面，本轮 http 业务动态新增，不重写算法只接线）。
- 动态整格落点（CORE_MEMORY §9/§12，每格一例，不抽样）：fixed=T-HTTP-55（标量单流对照）/inc=T-HTTP-41/47（聚合）+T-HTTP-56（到尾回绕计数证据）/rand=T-HTTP-53（聚合）+T-HTTP-57（同 seed 复现对照）+T-HTTP-58（ip.src 地址维）/list=T-HTTP-54（轮转计数）/pattern=T-HTTP-59（不支持=负例钉死）/静态复制拒绝=T-HTTP-51（http 链专属负例，反例=T-HTTP-41）。三问：①语义真发生（聚合值 pcap 回填）；②复现（53 vs 57 逐值相等）；③回绕（56 的 43300×10/43301×10/43302×5）。
- 端口优先级：用户显式 tcp.dst_port > FieldContract（80/8332/7547）> 报错。http_flv 首例 `{"http":{"method","uri","version"}}` 非空、余子女 `{"http":{}}` 走默认——P5 改写不碰此分工。
- version 单一真相：层写裸（schema 默认 `1.1`）、线上全完整（`HTTP/1.1`）；归一位置=层翻译（本轮重走后唯一归一处） + 变换器内已有 prefix 兼容（读已 prefix 值直通）。builder 空串→`HTTP/1.1`（`http.go:563`）保留。
- 显式覆盖：method/uri 空串留零走 builder 默认（GET///）；headers/body 同理。`completedConfig`（`:999`）用户值覆盖 schema 默认。
- 正交组合矩阵（已覆=例号；缺失=×，缺一格即缺口——本次补齐后剩余缺口如实列）：

  | 维度＼地址族 | IPv4 单流 | IPv4 多流 | IPv6 单流 | IPv6 多流 |
  |---|---|---|---|---|
  | 默认端口 80 | T-HTTP-7 | T-HTTP-41 | T-HTTP-15 | T-HTTP-47 |
  | 非默认端口 | T-HTTP-16（8080） | ×（未建例） | ×（未建例） | ×（未建例） |
  | MSS 分段 | T-HTTP-28/39 | ×（未建例） | T-HTTP-48 | ×（未建例） |
  | chunked×MSS | T-HTTP-49 | ×（未建例） | ×（未建例） | ×（未建例） |
  | 1.0×keep-alive | T-HTTP-14（单事务 close；1.0 配多事务未建例） | × | × | × |
  | TTL | T-HTTP-42 | ×（TTL 与流无关，未建例） | × | × |

#### 5. 错误与异常
- http 校验器（64cc9d7 已补，mqtt `mqtt/layer_gen.go:236` 范式）：调 `(&Planner{}).Validate(*spec)`（IP 格式 + MSS 下界）+ spec.TCP nil 则建、pin `Handshake/Termination=true`（防零值跳握手；legacy http 恒握手/挥手，链上同样不可关）。MSS 上界（65535）由链 `chain_planner.go:845` 覆盖，legacy `http.go:46` 只管下界——校验器复用 planner 即与现状一致，不另加。
- 载体检查 8 家（64cc9d7 已补，`validate_layers.go:86-98` 同款文案）：`gbt/getwork/hls/hds/http_flv/cwmp/doh/onvif: terminal layer requires the http carrier layer ([tcp, http, X]; tcp→X direct chain rejected)`。位置在 `CompleteChain` 前，Plan/Validate 期同步失败（drive 期报错会被吞成空流，dns `:106` 同款教训）。
- 内层流提前关闭：`inner %s stream closed before body event %d/%d`（FLV/HLS/HDS 各一，须排空后返回）。`Meta.HLS/HDS` nil 进变换器即错（配置与链不一致）。该分支无 pcap 负例（触发需内层中途断流，suite 表达力边界；单测亦未覆盖——缺口如实记录）。
- http 专属负例（T-HTTP-50/51/52/59/70/71/72，真实流程 error_contains）：①顶层 `src_ip` 扁平判死（Step1 CheckProtoFlat，锚词 `no longer accepts flat config field src_ip`）；②层链静态复制（`checkLayerChainStaticCopy`，锚词 `static four-tuple`，flows=2+全静态标量）；③gbt 缺 http 载体（锚词 `requires the http carrier layer`，载体检查 8 家代表）；④顶层 `http` presence 判死 T-HTTP-72（锚词 `no longer accepts a top-level http sub-config`，步骤 3）；⑤层地址 pattern T-HTTP-59；⑥string 面 inc T-HTTP-70；⑦关字段 method T-HTTP-71。五策略动态畸形（range 非 2 元/list 空等）由框架级 T-FTP-14 覆盖（同 ValidateLayers 入口，http 不重复）。
- planner 错误中断 Plan（既有语义）；超时/重传归 tcp 层。扁平/混用拒绝沿 Step1（CheckProtoFlat + checkLayerFlatConflict）；顶层 `http` presence 判死见步骤 3（本轮新增）。
- Failing 先行（64cc9d7 已做：validator 零值 TCP 链→握手包存在、FLV version 裸值→`HTTP/1.1`、载体 5 家 `[ip,tcp,X]`→载体锚词、删键回归 `think_time`；本轮新增见 §7 步骤 0）。

#### 6. 性能设计与验收
- 路径依据：事件流式（逐消息 Emit，无全量收集；FLV/HLS/HDS 每轮一读一写；透传零拷贝转发）；每消息一次 builder 字符串装配（请求/响应各一），FileSource 解析每流一次（PayloadCache 命中后内存读）；无锁（生成器无状态）、无 sleep；分段/限速/背压归 tcp 层与 worker（`worker.go/engine.go` 既有机制，本条目不另设）。
- 目标：不新增性能门；回归口径=现有套件耗时相对基线 ±10% 内（FTP D-FTP-4 §6 同款口径；P5 实测 wall：http_flv 4.9s/hls 6.5s/hds 5.2s/gbt 14.3s/getwork 15.2s/doh 41.3s/onvif 46.6s/cwmp 32.7s/http 67 例 16.6s，CASE_PROTO 逐文件串行、服务端内 parallel=4）。性能边界诚实声明：无目标吞吐/并发上限/内存上限数字（未测，标待确认，不承诺）；无压力/长跑/耗尽场景（缺口）；单流最大报文未声明边界（MSS 分段只测 536+600/3000 字节两档）。
- pcap 验收：9 文件 suite 全绿（8 子女 554 + http.json 67 = 621/621，P5 实测）+ 包落 `/tmp/mcp-pcaps-rework/http/`（本轮） 可复查（tshark 断言请求行/状态行/头/体，不手算包号；落盘路径由 suite 按 `PCAP_ROOT/<proto>/<case>.pcap` 定，用例不写路径）；网卡验收：本机无 enp135s0f0np0 发包口（`NIC_RUN` 测试需该物理口+root，本次未跑——缺口如实记录，pcap 一路已全绿）。

#### 7. 实现顺序与回滚（重走版，2026-09-13；P1 四缺口已提交 64cc9d7 不重做）

步骤 0（failing 先行，一步一红）：①层翻译 21 键红例（`chain_planner_http_test.go` 新测试：层 `{"http":{"response_status_code":201,"response_body":"hi"}}` + 空顶层→断言 `spec.HTTP.ResponseStatusCode==201` 且 `ResponseBody=="hi"`，当前 5 字段翻译即红）；②顶层 presence 判死红例（`schema/proto_flat_test.go`：`protocol=http, cfg={"layers":[…],"http":{"method":"GET"}}`→断言 `CheckProtoFlat` 非空；`maptoflow` 侧同条件断言 `ValidationErrors` 非空）；③业务动态红例（`layer_dyn_test.go`：层 `{"http":{"uri":{"strategy":"list","list":["/a","/b"]}}}`→断言 `parseLayerDyn` 出值且 `CheckLayerDynShape` 放行；`resolveLayerTuple` index1 回填 `spec.HTTP.URI=="/b"` 红例；15 关各一例断言 `does not support dynamic`）。

步骤 1（注册表 5→21 键 + schemagen）：`layers/registry.go:97` http Fields 补 16 键（`request_headers` map 默认 {} + 15 标量见下表；`headers` 旧键保留）→ `go run ./internal/core/layers/schemagen` 重跑 → 提交生成文件（§13）。字段类型/缺省表：

| 键 | 类型 | 缺省 | 备注 |
|---|---|---|---|
| request_headers | map | {} | 新正键；旧 `headers` 保留，读时正键优先 |
| body_b64 | string | "" | 与 body 二选一同格 |
| keep_alive | bool | false | 开关（V9 无界字段，bool 值直通） |
| transactions | int | 0（→1） | int 型（非 ftp 的 list 型同名键）；V9 无界，builder 归一 |
| response_headers | map | {} | |
| response_body | string | "" | |
| response_body_b64 | string | "" | 与 response_body 二选一同格 |
| response_status_code | int | 0（→200） | int 型；V9 无界（状态码表外兜底 `Status %d`，层侧不提前收）；动态开（list 枚举） |
| response_status_text | string | "" | 随 status_code，不开动态 |
| response_content_encoding | string | "" | 旧顶层 `content_encoding` 键读时回退（`ParseHTTPConfigFromMap` 内） |
| request_content_encoding | string | "" | |
| request_transfer_encoding | string | "" | |
| response_transfer_encoding | string | "" | |
| chunk_size | int | 0 | int 型；V9 无界（0=整块单发语义）；随 transfer，不开动态 |
| pipelined | bool | false | 开关（V9 无界字段） |
| file_source | object | nil | `Type:"object"`（有 strategy 键才走动态门——file_source 结构无该键，天然不触发；15 关之一） |

步骤 2（`ParseHTTPConfigFromMap` + 双调用点）：`strategy_convert.go`（`ParseFTPConfigFromMap:7654` 同构位置旁）新建 `ParseHTTPConfigFromMap(m map[string]interface{}) *HTTPConfig`——nil/非 map 输入→nil（缺席）；20 键全读（getString/getInt/getBool/getStringMap + `content_encoding` 回退 + BodyB64 不解码只存，解码归 builder；`file_source` 经既有 `parseFileSource(m)` 直读 `m["file_source"]`——map 内键，与通用读 `:1348` 同口）；空 map→`&HTTPConfig{}` 非 nil（presence 语义：`{"http":{}}` 走默认 GET///200，与 `{"http":{"method":"X"}}` 显式同路）；`version` 存裸值不 prefix（prefix 只在层翻译侧做，通用读侧裸值进 builder 由 builder 默认 `HTTP/1.1` 接管——与现状通用读 `getString(sub,"version")` 裸值语义一致，不改行为）。调用点 A 通用读（`:378`）：`if sub,ok:=cfg["http"].(map[string]interface{}); ok { spec.HTTP=ParseHTTPConfigFromMap(sub) }`（非 map→nil，旧行为保持）。调用点 B 层翻译（`chain_planner_translate.go:830` case http 重写）：删 5 字段手写，改 `cfg:=completedConfig(s,term.Config); hc:=core.ParseHTTPConfigFromMap(cfg); if hc.Version!=""&&!strings.HasPrefix(hc.Version,"HTTP/"){hc.Version="HTTP/"+hc.Version}; spec.HTTP=hc`（flat 权威早返保留：`spec.HTTP!=nil` 即顶层 presence，层翻译跳过——判死在 schema/convert 先报，翻译侧只做优先级）。

步骤 3（顶层 presence 判死，http 族 9 协议）：`CheckProtoFlat` 加族分支（`http/http_flv/hls/hds/gbt/getwork/cwmp/doh/onvif` 任一：`cfg["http"]` presence（`ok&&!=nil`，空 map 也判死——与 presence 语义一致）→ `"protocol X no longer accepts a top-level http sub-config (move it into the http layer …)"`，ftp 范本同构文案）；`mapToFlowSpec` 加同条件→`spec.ValidationErrors`（在库旧策略启动 error，覆盖 schema 未走路径）；`schema/semantic.go` 经 `CheckProtoFlat` 自动继承（create/update 400）。`pipe_gate.sh` 门 2-1 同步加顶层 `http` presence 检查（扁平负例除外；http 族 9 协议任一见 `http` 键即红）。

步骤 4（业务动态 6 开 15 关）：`layer_dyn.go:17` allowlist 加 `"http": {uri,body,body_b64,response_body,response_body_b64,response_status_code}`；`parseLayerDyn:29` 加 `case "http"` 分发（值出 `*StrategyConfig` 进 `LayerDynValues.HTTP` 新结构 6 指针 + `HasAny:3553` 扩展）；`checkDynShape:119`：6 开字段走形状门（string 面 5：`fixed/list/pattern`，inc/rand 拒绝见裁定表 F；`response_status_code` 走 int 面 `fixed/inc/rand/list`，pattern 拒绝）；15 关字段对象→`does not support dynamic`（`checkLayerDynObjects:116` 自动生效，allowlist 即真相）；`resolveLayerTuple` 加 HTTP 回填（6 字段：string 面 `ResolveStringValue`，status_code `genSmallInt(s,i,0,65535)` range 面；value 空→no-op 保留静态；回填目标 `spec.HTTP` nil 时建空补后再写——层翻译已建非 nil，防御性补建）。回填时机说明：回填点在 worker 侧每流 `Plan` 之前（现有点 `resolveLayerTuple(&spec,i)`，D-FTP-3 既有；`copy-on-write` 注意——`spec.HTTP` 是指针，回填前深拷贝再写，不污染模板，`generateTerminal:106` 已有同款拷贝语义）。`HasLayerDynIP` 不动（http 业务无 IP 面）。

步骤 5（自审 §10 + 构建测试）：自审走读（parse 分发 6 键齐/15 关拒、回填 6 路、翻译 prefix、判死 9 协议文案、空 map presence）；`go build ./...` + `go vet` + touched 包 `-race`（core/layers/http）→ P5 用例改写与 suite（另步）。回滚=本轮单提交逆序 revert（注册表+schemagen 生成文件+Parse+翻译+判死+动态，一提交整体回滚；与 P5 用例提交独立）。

工作量（估计）：代码约半天（5 文件 + 单测红例）；用例 http.json 53 例合并 + 业务动态整格新例 13（T-HTTP-60…72）+ 迁入回归；suite 9 文件（608 例基线 + 新例）全量重跑。

适用性（其他协议层复用结论）：本轮无协议无关的新机制——`ParseXConfigFromMap` 并列函数（ftp 已有）、allowlist 加行、回填加路，逐协议照抄；唯一要裁的是每协议自己的开/关清单与 string/int 面划分（http 是 string 面 5 + int 面 1，其余协议按字段类型重裁）。子女 8 协议走 P-PIPE 时只做“顶层 `http` 键搬层内 + 联验”，不动本条目。

裁定表 F（string 面动态策略集，`genStringValue` 已有五分支是依据）：uri/body/body_b64/response_body/response_body_b64 走 `fixed/list/pattern`（pattern `{n}` 替换是字符串天然语义，`applyPattern` 现成；inc/rand 的 range 端点是数值区间，对任意 URI/体字符串无意义——形状层拒绝 inc/rand，新锚词 `XXX strategy is not supported for string field`，用例钉死）；`response_status_code` 走 int 面 `fixed/inc/rand/list`（pattern 无意义→同门拒绝）。`checkDynEndpoints` 加 string 面分支（端点须 string，非 string 即 `invalid ... endpoint`）。request_headers/response_headers 两 map 键不在此表——map 型无动态形状（`List []string` 装不下 map），allowlist 直接关，对象即 `does not support dynamic`。

#### 8. 验收
- 对应 `docs/TEST_CASES.md` T-HTTP-7…72（P3 已交，P5 全绿回钉）。
- 完成条件（2026-09-14 实测）：http 包单测 + chain_http 测试绿；http.json 67/67 绿 + 8 子女 suite 联验 621/621 绿；`go vet` + touched 包 `-race` 绿；§1 两道门：①层链跑通；②旧字段移除（顶层五键判死 + 顶层 `http` presence 判死：新建 400 + 在库 error + 门 2-1 脚本绿）。
- 门 3 抽查见 P-PIPE #1 汇报（用户 2026-09-14 检查通过）。

#### 9. 关键决策对比

| 决策 | 候选 | 优劣 | 结论 |
|------|------|------|------|
| A http 校验器 | A1 按 mqtt 范式补（调 Planner.Validate + pin 握手/挥手）；A2 不补、靠 TCP 默认 true | A1 防零值跳握手（mqtt 同款陷阱已实证），失败在 Plan 期同步报；A2 少代码但零值链静默丢握手、无测试锚点 | 选 A1 |
| B FLV version | B1 补 prefix（HLS/HDS 同款 4 行）；B2 要求用例全写完整版 | B1 根治裸值上线上报（schema 默认 `1.1` 必经此路）；B2 现 15 例全完整所以没爆，但新人写裸值即错 | 选 B1 |
| C 翻译字段面（重走推翻，2026-09-13） | C1 保持 5 字段、全字段走顶层 http 载体；C2 翻译扩到 20 键 | C1 导致顶层 `http` 成为第二配置真相（门 1 §1 未达标，返工根因）；C2 以 `ParseHTTPConfigFromMap` 单一真相消除双源，`headers` 兼容键随层走（B 结构） | 推翻选 C1，改选 C2 |
| D 载体检查 | D1 扩到 8 家全覆盖；D2 保持 3 家 | D1 `[tcp,gbt]` 类错链同步拒绝（dns 同款教训：drive 期报错变空流）；D2 少 5 个分支但错链行为未定义 | 选 D1 |
| E ThinkTime（用户裁定删） | E1 删除字段（含解析+MCP 描述+前端+单测）；E2 留解析+文档写死不建模；E3 真实现 sleep | E1 字段零消费（grep 全仓：生成侧无 Sleep/Delay、无 Timestamp 步进；dnp3/mcp 协议自家 ThinkTime 不动），删后旧配置带该键走未知键忽略（config 节无 additionalProperties 约束，不 400）；E2 不删但语义永远假；E3 无包时间戳载体、sleep 只拖慢 suite | 选 E1 |

### D-TLS-1 TLS 隧道层翻转 + 链校验器（9 协议可选底座）

**门 1 开工对照表（§1–§14，2026-09-14 tls P-PIPE，证据=文档节/代码行/用例号）：**

| § | 本协议怎么满足 | 证据 |
|---|---|---|
| §1 层链唯一真相 | 顶层旧键 `src_ip/dst_ip/src_port/dst_port/count` 去向：地址进 `ip` 层、端口进 `tcp` 层、数量走 `flow_control`（P5 按通用改写规则）；顶层 `tls` 子映射本轮不迁入层（链上参数本就由层 config 驱动，`layer_gen.go:27` 不读 spec.TLS，迁入无消费方），D-条目“明确不解决”登记；目标形状 `{"layers":[{"ip":{"src","dst"}},{"tcp":{"src_port","dst_port"}},{"tls":{}}]}` | `pipe_gate.sh tls` 门 2-1 绿；`registry.go:869` tls 层；T-TLS-2 |
| §2 策略/任务分工 | 沿框架语义，不另设；tls 无 sessions，多流只走 `flow_control` + 层动态 | D-TLS-1 §3 |
| §3 五件套 | 豁免+内层委托：tls 无子流派生、无 sessions[]、无关联字段；单连接内序列=TCP 握手→TLS 握手→应用数据→挥手；内层委托=终结层事件经 tls 包成 ApplicationData record（方向保留），握手 record 先行注入；时间线=同步产全部事件、无交错 | `layer_gen.go:11` 变换器契约；`planner.go:371` legacy 序列；T-TLS-1 |
| §4 规范矩阵 | RFC 8446（握手/record/分片 §5.2）+ 现网 1.3 为主口径 + 帧结构思路借鉴；P1 矩阵已交（八项逐项，链上 1.2/AlertPath 差异已接受并登记） | D-TLS-1 依据行；P1 矩阵 |
| §5 有错必处理 | 校验器调 Planner.Validate + pin 握手/挥手（mqtt/D-HTTP-1 范式）；链结构性校验（version/role/SNI/ALPN）在 ValidateSpec 同步拒；扁平/混用沿 Step1 | `planner.go:158`；`chain_planner.go:221`；T-TLS-3/4 |
| §6 性能 | 事件流式无全量收集（变换器逐事件转发）、无锁无 sleep；回归 ±10%（实测 wall 回填）；边界诚实声明（无吞吐/并发/内存目标，网卡未跑） | D-TLS-1 §6；T-TLS-5 |
| §7 三份文档 | 设计=本条目；用例=T-TLS-*；cases 回指编号；schema 是机器契约不抄全文 | 本条目；TEST_CASES T-TLS-* |
| §8 先设计后代码 | 本条目定稿后开工 | 本条目 §7 |
| §9 三源+整格 | RFC 8446 条文 + 本条目 + 现网 1.3 口径；动态整格见 §4 清单 | T-TLS-*；§4 矩阵 |
| §10 评审闭环 | 改→审→测→修→再审；自审 N 轮结论；测试四问 | T-TLS-5；门 3 抽查 |
| §11 白话汇报 | 先一句结论；代号带解释；证据只贴路径与结论 | 每次汇报 |
| §12 动态清单 | 四元组沿框架白名单；业务 4 键：sni 开（string 面 fixed/list/pattern——rand/inc 无意义，`genStringValue` rand 产整数串，域名要字符串表/模板，形状层拒，T-TLS-7；本轮唯一开的业务键）/alpn 关（列表无允许的解析面且现状无轮转需求——开它只会加一个"固定串"的伪动态）/version 关（常量协商，链只 1.3）/role 关（常量，链只 client）；序号算法不重写 | `layer_dyn.go:17`；`tuple_generator.go`；T-TLS-5/6/7 |
| §13 schema 同步 | 本轮若改注册表 tls Fields 必须重跑 `schemagen` 并提交生成文件；顶层 `tls` 不迁入故 `strategy.json` 不动 | `generated/layers.generated.json`；门 2 脚本 |
| §14 真实流程 | cases 即任务 spec；MCP 建任务→引擎生成→tshark 校对；负例带锚词；全量绿；二进制同代；包落盘可查 | T-TLS-5；门 2 三项 |

目标形状（§1 证据）：`{"layers": [{"ip": {"src","dst"}}, {"tcp": {"src_port","dst_port"}}, {"tls": {"version","sni","alpn","role"}}]}`（4 键全列；`tls:{}` 空配置走默认 tls1.3/client）。

**状态：** 已验收（2026-09-14：tls.json 9/9 绿，二进制与 HEAD 同代，`pipe_gate.sh tls` 静态两项绿；门 3 抽查见本条目尾）
**范围（2026-09-14）：** ①`main.go:564` 翻转 `tls.NewPlanner()` → `layers.NewChainPlanner("tls")` + 空白导入（Step 2 同款一行）；②补 `RegisterLayerValidator("tls")`（mqtt/http 范式：`validateTLSSpec`=调 `(&Planner{}).Validate(*spec)` + spec.TCP nil 则建、pin `Handshake/Termination=true`；标量通道下生成器 drive 期直接读层 config（`layer_gen.go:80-101`），spec.TLS 只在动态 sni 时由本轮步骤 2 写入；failing 先行 3 红例直调 validator）；③tls.json 1 例 FLAT→层链改写（通用改写规则；`tls:{}` 空配置随层走就是正键）+ 负例（扁平五键判死 + static-copy 门代表，锚词钉死）；④§12 业务动态清单落地（sni 开 1 关 3：allowlist 加 `tls:{sni}` 1 行 + string 面形状门 + T-TLS-5/6/7 三例；alpn/version/role 关——对象即 `does not support dynamic` + T-TLS-8 一例钉死）。明确不解决：顶层 `tls` 子映射迁入层（链上无消费方，`layer_gen.go:27`；CheckProtoFlat 现不拦顶层 `tls`，与 http 当年不同——http 是有消费方才迁）；链上 1.2/1.1/1.0 路径（结构性只实现 1.3，同步拒绝；legacy 单测已覆字节）；链上 AlertPath/PSK/证书注入（层 schema 无字段，T13 不扩展）；任务级跨策略共用动态池（与 D-FTP-2 同口径另立条目）。等价证据：T13 链字节已由 `t13_tls_test.go` 钉死（16 帧=3 握手+7 TLS 握手+请求+响应+4 挥手，record 头/握手序列/分片上限）。T13 既有形 `[{"tls":{}},{"http":{}}]` 建链时 inner 有人，Build 出来的补全链翻转前后恒为 `[ip,tcp,tls,http]`——drv 侧走的本来就是链生成器；翻转只换入口（main.go 一行），字节零漂移可实测验证，漂移则按 FTP Task 1 先例扩展事件 flag、不猜。
**依据：** RFC 8446（握手序列 §4/§7、record 头 §5.1/ContentType §5.1、分片上限 §5.2 的 2^14+1、supported_versions/key_share/signature_algorithms_cert 扩展）；RFC 1035（SNI 253 上限，经 legacy 注释引用）；现网行为（1.3 为主、1.2 兼容主流形态；SNI/ALPN 为真实部署必带项）；开源对照（只借帧结构思路：record 头 ContentType+Version+Length、握手头 Type+3B Length；不搬加密实现——synth 密文是既定语义，`planner.go:21` 已声明是发包程序不是网络设备）。代码事实：legacy 全序列 `planner.go:371`（TCP 握手→TLS 握手→应用数据→挥手）+ Validate `planner.go:158`（IP/版本/role/SNI/AlertPath/PSK）+ 链变换器 `layer_gen.go:11`（事件变换、握手先行注入、16385 分片）+ 链结构性校验 `chain_planner.go:221`（version/role/SNI/ALPN 同步拒）+ 注册表 `registry.go:869`（tunnel 类、depends_on tcp、4 键）+ 接线 `main.go:564`（legacy 待翻转）。
**配置权威：** 层链是唯一真相。地址只落 `ip` 层、端口只落 `tcp` 层（FieldContract `tcp.dst_port=443`，`registry.go:871`）、数量只走 `flow_control`；tls 业务 4 字段只落 `tls` 层（version/sni/alpn/role）；顶层 `tls` 子映射是过渡载体（本轮不迁，见范围）。扁平五键判死沿 Step1（`strategy_convert.go:7593` CheckProtoFlat）。

#### 1. 数据与接口
- 输入：层链 `[ip,tcp,tls]`（tls 层 config 4 键：version string 缺省 tls1.3、sni string 缺省空、alpn list 缺省空→生成器默认 [h2,http/1.1]、role string 缺省 client）；spec 侧四元组由层值回填（Task 6 同款：层显式写才回填，dyn 对象跳过走 resolveLayerTuple）。
- 输出：PacketConfig 流（TCP 握手 3 + TLS 握手 7（ClientHello→ServerHello→EE→Certificate→CertVerify→ServerFinished→ClientFinished）+ 应用数据（内层委托逐事件包 record，链上 spec.HTTP 恒由 translate 建出）+ 挥手 4/RST）。16 帧口径（P5 落盘实测；legacy 合成 128B/17 帧/close_notify 口径链上已过期）。
- 新增/修改 Go 类型：无新类型（TLSConfig 已有，`types.go:8038` 12 键；层 schema 4 键是其子集，翻译不需要——链上不读 spec.TLS）。新增函数：`validateTLSSpec`（`internal/protocol/tls/layer_gen.go` 尾，mqtt `layer_gen.go:236` + http `validateHTTPSpec` 同款：调 `(&Planner{}).Validate(*spec)` + spec.TCP nil 则建、pin Handshake/Termination=true）+ `init` 内 `layers.RegisterLayerValidator("tls", validateTLSSpec)`。修改调用点：`main.go:564` 一行翻转 + 空白导入 `_ "…/protocol/tls"`（已有 `:178`，保留；翻转后 legacy planner 仍被 validator 复用，不删包）。
- 显式覆盖：tls 层 version/role 空串走链默认（1.3/client，与生成器 `:80` 同款）；sni 空=不发扩展；alpn 空=默认双协议。spec.TLS 非 nil 不代表 flat 权威（链上不读 spec.TLS，无 flat-wins 分支——与 http/dns 不同，`layer_gen.go:27` 已声明）。

#### 2. 依赖与生命周期
- 前置：tcp 层（depends_on，`registry.go:870`）。tls 是隧道层不能当末层——建链最小输入是 `[{"tls":{}},{"http":{}}]`（T13 既有形；裸 `[{"tls":{}}]` 被 ValidateLayers V4/V5 拒，`validate_layers_test.go:91` T20 锁死），补全后链恒为 `[ip,tcp,tls,http]`。"隧道层不产包"：tls 只做事件变换（握手先行注入+内层事件包 record），TCP 握手/挥手/分段/序号全归 tcp 层。应用数据恒来自内层 http 事件委托（`layer_gen.go:130-173`）；legacy 的合成 128B 路径（`planner.go:515` spec.HTTP nil 分支）链上不存在——链上 spec.HTTP 恒由 translate 建出（http 空层→默认 GET /），翻转前后字节对比以 T13 钉死的 16 帧为准。
- 依赖状态：握手/分段/seq 推进全归 tcp 层（tls 只包 record，不管 TCP）；SNI/ALPN 只影响 ClientHello 扩展块字节，不改变包数。
- 资源：无状态生成器（TLSGenerator 无字段）；无锁无 sleep；取消经 ctx.Done 传播（drain 纪律，`layer_gen.go:49`）。
- 释放：事件流关闭=内层数据结束，变换器退出；drive 关通道（既有契约）。

#### 3. 主流程与状态
- 状态表：TCP 握手（3，归 tcp）→ TLS 握手（7，tls 变换器先行注入）→ 应用数据（内层委托逐事件包 record，或合成 128B 双向）→ close_notify（无 AlertPath 时）→ 挥手 4 / RST（归 tcp）。
- 会话边界：单连接单会话，无 sessions[]；多流只走 `flow_control` + 层动态（四元组动态走 ip/tcp 层，业务动态走 §12 清单）。
- 父子流关系：无（tls 不派生子流；与 ftp 数据通道不同）。
- 时间线：同步产全部事件、无交错。序号空间：tcp 层推进（tls 只增 payload 长度，不碰 seq）。

#### 4. 递增与覆盖规则 + 正交组合矩阵 + 业务动态清单
- 动态白名单：`tls: {sni}` 开（`layer_dyn.go:17` 已加行）；`alpn/version/role` 关（常量/无轮转需求，对象即 `does not support dynamic`）。
- 开的理由：sni（域名是 §12 点名的关键业务字段，string 面 fixed/list/pattern——rand/inc 产整数串，无意义，形状层拒，T-TLS-7）。
- 序号算法不重写（沿 `tuple_generator.go` genStringValue 同款；sni 走 string 面）。
- 正交组合矩阵（已覆=例号；缺失=×，P5 落盘实测回填）：

  | 维度 | 单流 | 多流 |
  |---|---|---|
  | 默认 443 | T-TLS-1（16 帧） | T-TLS-5（32 帧，两流交织） |
  | SNI 标量 | T-TLS-2（example.com，ext len 16） | — |
  | SNI list | — | T-TLS-5（a.com/b.com，f4/f20） |
  | SNI pattern | — | T-TLS-6（host1/host2.com，f4/f20） |
  | SNI fixed | T-TLS-5 对照端（a.com 恒值） | — |
  | SNI rand/inc | T-TLS-7（形状层拒，无 pcap 例） | — |
  | https 套娃 | T-TLS-9（内层 GET /tls-inner 进 record） | — |
  | 1.2 方言 | legacy 单测已覆（链上不同步实现，T13 不扩展） | × |
  | AlertPath | legacy 单测已覆（链上不注入，T13 不扩展） | × |

- 端口优先级：用户显式 tcp.dst_port > FieldContract 443 > 报错。
- version 单一真相：层写裸（schema 默认 `tls1.3`）、线上为 record legacy_version 0x0303 + supported_versions 扩展 0x0304（生成器装配，`planner.go:279/807` 同款）。

#### 5. 错误与异常
- tls 校验器（本轮新补，mqtt/D-HTTP-1 范式）：调 `(&Planner{}).Validate(*spec)`（IP 格式 + MSS 下界 + 版本/role/SNI/AlertPath/PSK）+ spec.TCP nil 则建、pin `Handshake/Termination=true`（防零值跳握手；legacy tls 恒握手/挥手，链上同样不可关）。MSS 上界（65535）由链 `chain_planner.go:845` 覆盖（既有语义，与 http 同款）。
- 链结构性校验（已有，`chain_planner.go:221`）：version 非 1.3 / role 非 client / SNI 超 253 / ALPN 名超 255 → ValidateSpec 同步拒绝（drive 期报错会被吞成空流，dns `:106` 同款教训）。validator 与结构性校验的分工：validator 管 legacy 全量语义（含 1.2 版/AlertPath/PSK 形状），结构性校验管链上子集（1.3/client + 长度上限）；1.2 版走链被结构性校验拒（不是 validator 拒），锚词 `not supported in the layer chain yet`。
- tls 专属负例（T-TLS-3/4，真实流程 error_contains）：①顶层五键扁平判死（Step1 CheckProtoFlat，锚词 `no longer accepts flat config field`）；②层链静态复制（`checkLayerChainStaticCopy`，锚词 `static four-tuple`，flows=2+全静态标量）。顶层 `tls` presence 不判死（本轮明确不解决，见范围；CheckProtoFlat 现不拦顶层 `tls`）。
- planner 错误中断 Plan（既有语义）；超时/重传归 tcp 层。扁平/混用拒绝沿 Step1。
- Failing 先行：validator 零值 TCP 链→握手包存在（mqtt/D-HTTP-1 同款红例）；version tls1.2 链→结构性锚词（既有行为，新测钉死）；SNI 超 253→锚词（legacy Validate 与链校验双口径，各一例）。

#### 6. 性能设计与验收
- 路径依据：事件流式（变换器逐事件转发，无全量收集；每事件一次 record 装配 5B 头 + 载荷拷贝；握手 7 事件先行注入）；FileSource 无（tls 无文件载荷）；无锁（生成器无状态）、无 sleep；分段/限速/背压归 tcp 层与 worker（既有机制，本条目不另设）。
- 目标：不新增性能门；回归口径=现有套件耗时相对基线 ±10% 内（FTP D-FTP-4 §6 同款口径；P5 实测 wall 回填：tls 1 例基线待测，CASE_PROTO 逐文件串行、服务端内 parallel=4）。性能边界诚实声明：无目标吞吐/并发上限/内存上限数字（未测，标待确认，不承诺）；无压力/长跑/耗尽场景（缺口）；单流最大报文未声明边界（record 分片只测 16385 上限一档，`layer_gen.go:180`）。
- pcap 验收：tls.json 全绿（P5 实测）+ 包落惯例根 `/tmp/mcp-pcaps/<proto>/` 可复查（tshark 断言 TCP 握手 + `tls.handshake.type` + `tls.record.content_type`，不手算包号；落盘路径由 suite 按 `PCAP_ROOT/<proto>/<case>.pcap` 定）；网卡验收：本机无发包口（`NIC_RUN` 需物理口+root，本次未跑——缺口如实记录，pcap 一路已全绿）。

#### 7. 实现顺序与回滚（2026-09-14；P1 矩阵已交，无矩阵不开工已满足）

步骤 0（failing 先行，一步一红，口径：`layer_validate_test.go` 3 红例直调 `validateTLSSpec`（http `layer_gen_test.go:151` 同款——BuildLayersPlanner 建不了裸 tls 链，红例不走建链）：①零值 TCP 进 validator→断言 Handshake/Termination 被 pin true（当前无 validator 即红）；②spec.TLS{SNI:254B}→断言拒绝（legacy Validate 口径钉 validator 落点）；③spec.TLS{Version:"tls9.9"}→断言拒绝。翻转红例另计（`main.go` 仍 legacy 时已翻转检查即红）；动态红例另计（allowlist 无 tls 行时 parse 即红，`layer_dyn.go:17`）。

步骤 1（翻转 + 校验器）：`main.go:564` → `layers.NewChainPlanner("tls")`（空白导入已有 `:178`，保留）；`tls/layer_gen.go` 尾加 `validateTLSSpec` + `init` 注册（mqtt `layer_gen.go:236` + http `validateHTTPSpec` 同款，不读 spec.TLS——链上参数由层 config 驱动）。

步骤 2（业务动态 sni 开 1 关 3）：`types.go` 加 `LayerTLSDyn{SNI *StrategyConfig}` + `LayerDynValues.TLS` + `HasAny` 扩展 1 项；`layer_dyn.go:17` allowlist 加 `"tls": {"sni": true}`（alpn/version/role 全关）；`parseLayerDyn` 加 `case "tls"` 分发（sni 对象→`out.TLS.SNI`）；`checkDynShape` 加 tls 分支（sni 走 string 面 fixed/list/pattern，inc/rand/unknown 同 http 裁定表 F 锚词；alpn/version/role 因 allowlist 关门走 `does not support dynamic`，不进形状函数——`checkLayerDynObjects` 先拦）；worker `resolveLayerTuple` 加 TLS 回填段（sni 解析值写 `spec.TLS.SNI`，spec.TLS nil 则建——legacy `planner.go:389-398` 读 `spec.TLS` 兜底分支的同款写入点，与 http :528 段并列）；`chain_planner_translate.go` 加 TLS 消费段（`translateTerminalConfig` 内 `term.Name=="http"` 时读 p.chain 上 tls 层 config 的 sni：标量直写 `spec.TLS.SNI`，动态对象按 `spec.FlowIndex` 经 `CheckLayerDynShape+ResolveStringValue` 直解写入——与 http :845 段同构：读 p.chain 原始链、不读 term 补全链）。失败语义：`spec.TLS` 非 nil 空壳（SNI/Version/Role/ALPN 全空——worker 防御性补建产物）不触发"flat 权威"早返，tls 翻译继续（http :836 空壳例外同款）。机制一句话：标量 sni 零新增代码（层 config 原生进生成器）；动态 sni 走"worker 解析进 LayerDyn → resolveLayerTuple 按 FlowIndex 直解写 spec.TLS.SNI → translate 消费段把解析值再写回本流的层 config"——与 http `translateHTTPDyn` 同构（读 p.chain 原始链、按 FlowIndex 直解），不另发明机制。

步骤 3（门 2-1 脚本）：`pipe_gate.sh` 现只查五键 + http 族 presence；tls 本轮顶层 `tls` 不迁入，脚本零改动（http 族 presence 红线不适用于 tls——tls 不是 http 族 9 协议）。

步骤 4（自审 §10 + 构建测试）：自审走读（validator pin 握手/翻译无 flat-wins/动态 2 开 2 关/结构性校验分工、判死文案）；`go build ./...` + `go vet` + touched 包 `-race`（core/layers/tls）→ P5 用例改写与 suite（另步）。回滚=本轮单提交逆序 revert（翻转+validator+动态，一提交整体回滚；与 P5 用例提交独立）。

工作量（估计）：代码约半天（3 文件 + 单测红例）；用例 tls.json 1 例改写 + 业务动态/SNI/ALPN/负例新例约 8；suite 全量重跑。

适用性（其他协议层复用结论）：tunnel 层翻转范本（gre 照抄：翻转一行 + 校验器 + 层 config 即接口）；唯一要裁的是每协议自己的开/关清单与 string/list 面划分（tls 是 sni string 面 + alpn list 面）。

#### 8. 验收
- 对应 `docs/TEST_CASES.md` T-TLS-1…9（P3 已交，P5 全绿回钉）。
- 完成条件（2026-09-14 实测）：步骤 0 三红例先红后绿；tls 包单测 + T13 链测试绿；tls.json suite 9/9 绿（`RESULT: 9 pass, 0 fail, 0 error`，二进制与 HEAD 同代，`pipe_gate.sh tls` 静态两项绿）；`go vet` + touched 包 `-race` 绿；§1 两道门：①层链跑通（tls.json）；②旧字段移除（顶层五键判死：新建 400 + 在库 error + 门 2-1 脚本绿；顶层 `tls` 不迁入故无 presence 门）。
- 门 3 抽查（任抽三条，均点到证据）：①§1 顶层旧键去向→`pipe_gate.sh tls` 门 2-1 绿 + T-TLS-3 负例锚词 `no longer accepts flat config field src_ip`；②§12 sni 开 1 关 3→`layer_dyn.go:17` allowlist 行 + T-TLS-5/6 pcap（f4/f20 SNI 落盘）+ T-TLS-7 单测 `TestTLSSNIDyn_StringSurfaceRejected` + T-TLS-8 负例锚词 `does not support dynamic`；③§14 真实流程→`RESULT: 9 pass` + 落盘 `/tmp/mcp-pcaps-tls/tls/` 6 pcap（负例 0 包无落盘）+ T-TLS-1 16 帧口径。
- 缺口如实记录：①在库 tls 行清空未执行（P6 待办：count→备份→删→复核）；②8 子女回归未跑（tls 是 9 协议底座：http/dns/mqtt/smtp/pop3/imap/socks5/ftp/自身链回归逐个重跑，P6 待办）；③网卡验收未跑（本机无发包口，pcap 一路已全绿）；④Full 3588 + `go test ./internal/...` 待 123 协议全走完后 Step 8 执行。

#### 9. 关键决策对比

| 决策 | 候选 | 优劣 | 结论 |
|------|------|------|------|
| A 翻转 | A1 ChainPlanner 一行；A2 保持 legacy | A1 归位层链（Step 2 同款），A2 留双轨违反 §1 | 选 A1 |
| B 顶层 `tls` 去向 | B1 本轮不迁入、D-条目登记；B2 本轮迁入层 | B1 链上无消费方（`layer_gen.go:27`），迁入无收益；B2 动 schema 无收益 | 选 B1 |
| C 字节漂移 | C1 先实测 T13 现有链字节、漂移则扩展事件 flag（FTP Task 1 先例）；C2 直接断言等价 | C1 是 plan 原话，C2 赌运气 | 选 C1 |
| D 动态清单 | D1 sni 开 1 关 3（alpn/version/role 关），P3 逐格；D2 sni+alpn 双开；D3 全关 | D1 符合 §12 最小够用（alpn 开无解析面、无用例需求，见适用性）；D2 加一个"固定串"伪动态+一套无消费面的形状门；D3 偷懒（域名逐流变是真实需求） | 选 D1；alpn 将来有轮转需求时另立条目再开，不在本轮搭车 |
| E 回填目标 | E1 标量走层 config 原生通道（零新增）+ 动态 sni 经 LayerDyn→spec.TLS→写回本流层 config（http translateHTTPDyn 同构）；E2 只回填 spec.TLS（生成器不读，白写）；E3 只回填层 config（动态对象无处可存） | E1 两条通道各走各的；E2 动态值到不了生成器；E3 动态对象进不了层 config | 选 E1 |

### D-TLS-2 TLS 证书明文配置（cert 块 + 真 DER 替换 256B 随机模板）

**门 1 开工对照表（§1–§14，2026-09-14 D-TLS-2，证据=文档节/代码行/用例号）：**

| § | 本协议怎么满足 | 证据 |
|---|---|---|
| §1 层链唯一真相 | cert 是 tls 层内第 5 个字段（嵌套对象，与 sni/alpn 并列，用户裁定形状）：`{"tls":{"cert":{"subject","san","key_type","not_before","not_after"}}}`；顶层无新增任何键；目标形状 `{"layers":[{"ip":…},{"tcp":…},{"tls":{"sni","cert":{…}}},{"http":{}}]}` | `registry.go:869` tls Fields +cert 行（本轮加）；T-TLS-10 |
| §2 策略/任务分工 | 沿框架语义；tls 无 sessions，cert 逐流值走 `flow_control` + cert 动态（同 sni 口径） | D-TLS-1 §2 |
| §3 五件套 | 豁免同 D-TLS-1（无子流派生/sessions/关联）；cert 不改变包数（16/32 帧口径不变，Certificate record 变长不分段——DER ~4xx B < MSS 1460） | D-TLS-1 §3；T-TLS-1 |
| §4 规范矩阵 | RFC 5280（X.509 v3：TBSCertificate 序列/Issuer/Validity/Subject/SPKI/Extensions/Signature）+ RFC 8446 §4.4.2（Certificate 消息：ctx+list_len+entry[len+der+ext]）；P1 矩阵=本条目依据行 + 2026-09-14 探针实证（固定种子 P-256 标量 + 固定签名熵 reader → `x509.CreateCertificate` DER 逐字节确定，默认参数 465B，`x509.ParseCertificate` 回读 CN/O/C/SAN 完整） | 本条目依据行；/tmp/certprobe 探针（2026-09-14，Go 1.21.13） |
| §5 有错必处理 | cert 子键枚举校验（subject/san/key_type/not_before/not_after；未知子键拒绝）+ key_type 枚举（本轮仅 ecdsa-p256）+ 日期 RFC3339 解析失败拒绝——全部在 create 期（ValidateLayers/V9 路径）与链结构性校验同步拒，锚词钉死；drive 期防御（certgen 返回 error 中断 Plan） | `chain_planner.go:221` 同款结构性段（本轮扩 cert）；T-TLS-14/15 |
| §6 性能 | DER 生成带 sync.Map 缓存（同参数→同 DER，cache hit=map 查找）；首次生成=1 次 ECDSA 签名 ~100µs；无锁竞争（缓存只读命中）；回归 ±10% 沿 D-TLS-1 口径 | certgen.go（本轮新文件）§6 |
| §7 三份文档 | 设计=本条目；用例=T-TLS-10…15；cases 回指编号 | 本条目；TEST_CASES |
| §8 先设计后代码 | 本条目定稿（用户 2026-09-14 三轮裁定：形状可/缺省给全/公司名 TrafficGen Test Lab）后开工 | 本条目 |
| §9 三源+整格 | RFC 5280 条文 + 本条目 + tshark 实际解出的字段（P5 落盘校准）；动态整格：subject/san 各 fixed/list/pattern 三格 + 关字段负例 | T-TLS-10…15 |
| §10 评审闭环 | 改→审→测→修→再审；自审 N 轮；测试四问 | P6；门 3 |
| §11 白话汇报 | 先一句结论 | 每次汇报 |
| §12 动态清单 | cert 块内：subject 开（string 面 fixed/list/pattern——CN 逐流变是现网真实场景）/san 开（string 面 fixed/list/pattern——SAN 逐流变同 sni 语义）；key_type 关（密钥类型一切换证书长度/签名算法全变，包长断言全得重钉，无逐流变需求）/not_before 关（时间常量）/not_after 关（时间常量）——对象即 `does not support dynamic`；序号算法不重写（`genStringValue` 同域） | `layer_dyn.go` allowlist + cert 嵌套提取（本轮）；T-TLS-12/13/14 |
| §13 schema 同步 | tls Fields 4→5 键，必须重跑 `schemagen` 并提交生成文件；顶层 `tls` 不动 | `generated/layers.generated.json`；门 2 脚本 |
| §14 真实流程 | cases 即任务 spec；MCP→引擎→tshark；x509 字段断言（CN/O/SAN/有效期/序列号）以落盘 pcap 校准；负例带锚词；全量绿；二进制同代 | T-TLS-10…15 |

目标形状（§1 证据）：`{"tls":{"cert":{"subject":"CN=trafficgen-test,O=TrafficGen Test Lab,C=CN","san":["example.com"],"key_type":"ecdsa-p256","not_before":"2026-01-01T00:00:00Z","not_after":"2036-01-01T00:00:00Z"}}}`（5 键全列；块整体缺席或单键缺席一律填完整默认值——用户裁定"缺省时数据也要给全"，不报缺参错、不回退随机模板）。

**状态：** 已验收（2026-09-14：tls.json 15/15 绿，二进制与 HEAD 同代，`pipe_gate.sh tls` 静态两项绿；门 3 抽查见本条目 §8）
**范围（2026-09-14）：** ①`internal/protocol/tls/certgen.go` 新文件：固定测试密钥派生（SHA-256 种子 → P-256 标量，`ScalarBaseMult` 推公钥；私钥永不进配置/永不落盘）+ `BuildCertDER(ref *core.X509Ref) ([]byte, error)`（默认值填全 → DN 解析（CN/O/OU/L/ST/C）→ SAN → 固定有效期 → 序列号=SHA-256(subject|san|notBefore|notAfter|keyType) 前 8B → 固定模板（KeyUsage DigitalSignature|KeyEncipherment、ExtKeyUsage ServerAuth、BasicConstraintsValid、IsCA=false、自签 Issuer=Subject）→ `x509.CreateCertificate`（固定签名熵 reader，Go 1.21 ECDSA 需 reader 供 mixedCSPRNG，nil 会 panic——实证）→ sync.Map 缓存）；②`buildCertificate13/12`（`planner.go:997/1032`）弃 256B `rand.Read` 模板改用 `BuildCertDER`（serverCert nil → 默认 ref；`t.ServerCertificate` 死参数复活——legacy flat 路径的 X509Ref 配置首次真正上字节）；③层链侧：`registry.go` tls Fields +`"cert":{Type:"object"}`（重跑 schemagen）+ `chain_planner.go` 结构性校验扩 cert 段（子键枚举/key_type 枚举/日期解析/SAN 条目 ≤253/subject DN 合法性）+ `layer_gen.go` 生成器读 `cfg["cert"]` → `parseCertConfig`（RFC3339 日期→unix，subject/san/key_type 直读）→ `buildCertificate13(ref,false)`；④动态：`layer_dyn.go` allowlist tls 行扩 cert.subject/cert.san（嵌套提取——parseLayerDyn 下钻一层；`checkLayerDynObjects` 对 tls.cert 下钻：subject/san 对象走 string 面形状门，key_type/not_before/not_after 对象即 `does not support dynamic`，未知子键拒绝）+ `LayerTLSDyn` +CertSubject/CertSAN + `resolveLayerTuple` 回填 `spec.TLS.ServerCertificate` + `translateTLSCert`（chain 引擎路径，translateTLSSNI 同构）+ `applySpecToChain` tls 分支扩 cert（对象→注入 spec 解析值/空则剥离子键回默认）；⑤tls.json 新例 6 个（T-TLS-10…15）+ 既有 6 例 frame7 断言/notes 按 pcap 回钉（record 269→~4xx）+ `pcaptest/verify.go` 白名单删 6 个 tls 用例 ID（真 DER tshark 干净解出，BER 伪影消失——这是本条目的主要动机）。明确不解决：key_type 仅 ecdsa-p256（rsa-2048/rsa-4096/ecdsa-p384 拒绝，锚词 `not supported yet`——RSA 需嵌入 1.2KB 固定测试私钥常量或确定性素数搜索（~秒级），无需求先不做）；client cert/mTLS（链上无 CertificateRequest 序列）；extensions 可配（KeyUsage/ExtKeyUsage/BasicConstraints 固定模板）；issuer 可配（恒自签）；serial 可配（恒派生）；cert.file_source（层链 drive 期无证书文件注入通道，且与"明文可配"目标无关）；顶层 `tls.server_certificate` 迁移（沿 D-TLS-1 裁定，flat 载体本轮不动）。
**依据：** RFC 5280（X.509 v3 结构 §4.1：tbsCertificate 序列=version/serialNumber/signature/issuer/validity/subject/subjectPublicKeyInfo/extensions，签名值覆盖 TBS）；RFC 8446 §4.4.2（Certificate 消息：certificate_request_context(1)+certificate_list(3)+entry[cert_length(3)+cert_data+extensions(2)]——D-TLS-1 已钉的 wire 布局不动，只换 cert_data 内容）；RFC 5280 §4.2.1.6（SAN dNSName）；现网行为（真实 TLS 部署的 Certificate 恒为可解析 X.509 DER——tshark/Wireshark/浏览器都能解；我们旧 256B 随机模板被 tshark BER 解码报 `[Malformed Packet: TLS]`，是 D-TLS-1 白名单注释已承认的 dissector 伪影）；探针实证（2026-09-14，/tmp/certprobe，Go 1.21.13：①固定种子 P-256 标量 + `ScalarBaseMult` → 密钥跨进程稳定；②`x509.CreateCertificate(detReader, …)` 同参数两次调用 DER 逐字节相等；③默认参数 DER 465B；④`x509.ParseCertificate` 回读 CN/O/C/SAN 完整；⑤subject 变化 → DER 变化（序列号派生生效））。代码事实：`buildCertificate13/12` 现状 256B `rand.Read`（`planner.go:1005-1006/1033-1034`）+ `serverCert` 参数恒被忽略（死参数）+ `X509Ref`（`types.go:8081` Subject/San/NotBefore/NotAfter/KeyType/FileSource 六键，flat 侧解析齐全但无消费方）+ 白名单 `verify.go:534`（6 个 tls 用例 ID 挂 BER 伪影豁免）+ `layerDynAllowlist["tls"]={"sni"}`（`layer_dyn.go:29`）。
**配置权威：** 层链是唯一真相。cert 5 字段只落 `tls` 层的 `cert` 对象内；动态只开 subject/san（string 面）；私钥永不进配置（固定种子运行期派生）；默认值在 certgen 单点填全（subject="CN=trafficgen-test,O=TrafficGen Test Lab,C=CN"、san=["example.com"]、key_type="ecdsa-p256"、not_before=2026-01-01T00:00:00Z、not_after=2036-01-01T00:00:00Z——固定常量非 time.Now()，保 DER 逐字节确定）。

#### 1. 数据与接口
- 输入：tls 层 config 第 5 键 `cert`（嵌套对象，5 子键全可选——缺席填默认）；动态对象写在 `cert.subject`/`cert.san` 上（同键二态：标量=静态值，对象=逐流策略）。
- 输出：Certificate 帧的 cert_data 从 256B 随机 → 真 X.509 DER（默认 465B；record/handshake/list/entry 四层长度字段按 `len(der)` 算，`buildCertificate13` 现有长度装配代码不动）。包数不变（16/32）；frame 7 TCP len 274→~4xx。
- 新增：`certgen.go`（`fixedP256Key()`、`BuildCertDER(ref)`、`parseCertConfig(map) *core.X509Ref`、DER 缓存）；修改：`planner.go` 两函数换数据源、`registry.go` +1 字段、`chain_planner.go` 校验段、`layer_dyn.go` 嵌套提取、`chain_planner_translate.go` +`translateTLSCert`、`chain_planner_chain.go` tls 分支扩 cert、`layer_gen.go` 生成器读 cert、`verify.go` 删 6 白名单 ID。
- 显式覆盖：cert 子键空值=默认（"缺省给全"裁定）；`"cert":{}` 空对象=全默认（与缺席同效）；subject 只填 `CN=x` 时 O/C 仍给默认（DN 合并：用户键覆盖默认键，缺的键用默认——NOT 整串替换）。

#### 2. 依赖与生命周期
- 前置：无新依赖（Go 标准库 crypto/x509、crypto/ecdsa、crypto/sha256）。
- 资源：sync.Map 缓存（key=规范化参数串，value=[]byte DER；同参数恒同 DER，只读命中无竞争）；每唯一配置 ~500B 内存 + 一次 ~100µs 签名。
- 生命周期：包级缓存进程存活期有效（确定性保证跨任务复用安全）。

#### 3. 主流程与状态
- 静态：层 config cert 标量 → applySpecToChain 原样保留 → 生成器 `parseCertConfig` → `BuildCertDER`（缓存）→ `buildCertificate13` 装配。
- 动态：worker/translate 按 FlowIndex 解析 subject/san → `spec.TLS.ServerCertificate`（只写解析键，其余键留给 certgen 默认）→ `applySpecToChain` 把解析值注回层 cert map（对象剥离）→ 生成器同静态路径。
- flat 路径（legacy）：`spec.TLS.ServerCertificate`（X509Ref，flat 已有解析）直传 `BuildCertDER`——死参数复活，行为变化=flat tls 任务的 Certificate 帧也变真 DER。

#### 4. 递增与覆盖规则 + 正交组合矩阵 + 业务动态清单
- 动态白名单：`tls.cert.subject`、`tls.cert.san` 开（string 面 fixed/list/pattern）；`cert.key_type/not_before/not_after` 关（对象即 `does not support dynamic`）；cert 块外无新键。
- DN 合并语义：subject 标量是完整 DN 串（RFC 4514 风格 `CN=…,O=…,C=…`）；动态解析值同为完整 DN 串（用户在 list 里写完整 DN——不做子键级动态，颗粒度=整 DN）。默认 DN 的 O/C 与用户 DN 的 CN 合并规则：**用户 subject 完整替换默认 subject**（不合并——用户写了 subject 就是对 DN 的完整意图；没写才用默认整串）。修正：探针与 parseCertConfig 均按整串处理，合并语义不存在，避免"半个默认半个用户"的诡异 DN。
- 序列号派生：SHA-256(规范化参数串) 前 8B——同参数同序列号、参数变序列号变，pcap 断言可钉。
- 正交组合矩阵：

  | 维度 | 单流 | 多流 |
  |---|---|---|
  | cert 缺席（全默认） | T-TLS-11 | × |
  | cert 静态全填 | T-TLS-10 | × |
  | subject list | — | T-TLS-12 |
  | san list | — | T-TLS-13 |
  | key_type 动态 | T-TLS-14（负例） | — |
  | key_type 未知值 | T-TLS-15（负例） | — |

#### 5. 错误与异常
- create 期（ValidateLayers→checkLayerDynObjects 下钻 + V9）：未知 cert 子键 `unknown field`；key_type/not_before/not_after 对象 `does not support dynamic`；subject/san 对象形状坏（inc/rand）`not supported for string field`。
- 链结构性校验（`chain_planner.go` tls 段扩）：key_type 非 ecdsa-p256 → `key_type %q not supported yet (only "ecdsa-p256")`；not_before/not_after RFC3339 解析失败 → `invalid RFC3339 timestamp`；san 条目 >253B → 拒；subject 空串（显式空=走默认，不拒）；not_after ≤ not_before → 拒（`not_after must be after not_before`）。
- drive 期防御：`BuildCertDER` 错误（密钥/签名失败，理论不可达）中断 Plan——不吞成空流。

#### 6. 性能设计与验收
- 路径依据：DER 缓存命中=1 次 map 查找（~100ns）；未命中=DN 解析+SHA-256+1 次 ECDSA 签名（~100µs，P-256 签名实测微秒级）；无锁（sync.Map 读并发安全）；生成器每流 1 次调用。
- 验收：tls.json suite wall 与 D-TLS-1 基线（5.0s）±10%；16/32 帧包数不变（cert 变长不分段，DER < MSS）；单测断言缓存命中（第二次调用同指针/相等字节）。
- 边界诚实声明：无吞吐/并发/内存上限数字（未测，沿 D-TLS-1 口径）；缓存无上限（唯一配置数=任务内 subject/san 组合数，实际有界）。

#### 7. 实现顺序与回滚
- 步骤 0（failing 先行）：①tls 包单测：`BuildCertDER` 两次调用字节相等（确定性）；DER 可 `x509.ParseCertificate` 且 CN/O/C/SAN/有效期/序列号回读正确（明文真实上 wire 的验收本体）；默认 ref 5 字段全非零（"缺省给全"执法）；`parseCertConfig` RFC3339→unix、缺键→默认。②core 单测：`parseLayerDyn` 提取 cert.subject/san 对象；`checkLayerDynObjects` 下钻拒绝 key_type 对象（锚词）；`resolveLayerTuple` 回填 `spec.TLS.ServerCertificate`。③t13：frame 7 Certificate 记录含可解析 DER（`x509.ParseCertificate` 于 record 载荷）。
- 步骤 1：certgen.go + planner.go 换源 + 单测转绿（既有 256/261/265/269 钉死断言按新值回钉——长度从 `len(der)` 算术推导，非手算）。
- 步骤 2：registry + schemagen + 结构性校验 + layer_gen 生成器读 cert + 单测。
- 步骤 3：动态三件套（layer_dyn 嵌套提取 + translateTLSCert + applySpecToChain cert 分支）+ 红例转绿。
- 步骤 4：tls.json +6 例 + 既有例回钉 + verify.go 删白名单 + suite 全绿 + 门 2。
- 回滚：单提交整体 revert（certgen+换源+动态+用例一体）。

#### 8. 验收
- 对应 `docs/TEST_CASES.md` T-TLS-10…15（P3 先行）。
- 完成条件（2026-09-14 实测）：tls 包/core/layers/pcaptest 单测 + `-race` 四包绿；tls.json 15/15 绿（`RESULT: 15 pass, 0 fail, 0 error`，二进制与 HEAD 同代，`pipe_gate.sh tls` 静态两项绿）；白名单 6 ID 删除后 suite 仍绿（伪影消失的直接证据，`verify_whitelist_test.go` 反向钉死旧 ID 返回 false）；T1 notes 回钉新长度（record 479/handshake 475/certs 471/cert 466，DER 466B）；门 2 三项绿。
- 门 3 抽查（任抽三条，均点到证据）：①§1 cert 载体→`registry.go` tls Fields cert 行 + T-TLS-10 x509 字段断言；②§12 subject/san 开 key_type 关→`layer_dyn.go` allowlist + T-TLS-12/13 pcap + T-TLS-14 负例锚词 `does not support dynamic` + T-TLS-15 锚词 `not supported yet`/`invalid RFC3339 timestamp`；③§14 真实流程→`RESULT: 15 pass` + 落盘 `/tmp/mcp-pcaps/tls/` 11 pcap + f7 零 malformed。
- 缺口如实记录：①在库 tls 行 0（D-TLS-1 P6 已清，本轮无新增在库行）；②stun 24/24 回归未跑（over-tls 消费方，P6 待办）；③Full 3588 + `go test ./internal/...` 待 Step 8。
- 缺口如实记录（续）：④rsa-2048/rsa-4096/ecdsa-p384 key_type 未实现；⑤client cert/mTLS；⑥cert.file_source；⑦issuer/serial/extensions 可配。

#### 9. 关键决策对比

| 决策 | 候选 | 优劣 | 结论 |
|------|------|------|------|
| A 证书内容 | A1 真 X.509 DER（固定密钥+确定签名）；A2 固定假模板字节（手造"能解出骨架"的字节） | A1 用标准库单真相、参数真实上 wire（用户"明文配置"诉求的本体）、tshark 干净解出；A2 为 dissector 化妆、参数不上 wire（配置改了字节不变=假配置） | 选 A1 |
| B 密钥来源 | B1 固定种子运行期派生（SHA-256→P-256 标量）；B2 嵌入 PEM/DER 常量 | B1 零嵌入物、可审计、密钥派生逻辑即文档；B2 1.2KB 不透明常量（RSA 才需要） | 选 B1（RSA 将来开时再 B2） |
| C 确定性 | C1 固定日期常量+派生序列号+固定签名熵；C2 time.Now()+随机序列号 | C1 跨跑/跨机逐字节稳定（pcap 可 diff、缓存安全）；C2 每跑不同（断言钉不死、缓存失效） | 选 C1 |
| D cert 载体 | D1 tls 层嵌套对象（用户裁定形状）；D2 顶层 5 个平键（cert_subject 等） | D1 用户已批、语义聚合；D2 复用扁平机制但污染层顶且违背已批形状 | 选 D1 |
| E 动态面 | E1 只开 subject/san；E2 全开（含 key_type/日期） | E1 域名/CN 逐流变是真实场景，key_type/日期逐流变只破坏包长稳定性；E2 一开包长断言全废 | 选 E1 |
| F subject 合并 | F1 用户 DN 整串替换默认；F2 子键合并（用户 CN+默认 O/C） | F1 语义清晰（写了=完整意图）；F2 "半个默认半个用户"的诡异 DN、解析复杂 | 选 F1 |

### D-GRE-1 GRE 隧道层翻转 + 链校验器（tunnel 底座，P-PIPE #3）

**门 1 开工对照表（§1–§14，2026-09-14 gre P-PIPE #3，证据=文档节/代码行/用例号）：**

| § | 本协议怎么满足 | 证据 |
|---|---|---|
| §1 层链唯一真相 | 顶层旧键 `count` 去向：数量走 `flow_control`（本例 count=1 缺省即单流，删即可）；顶层 `gre` 子映射（`{}` 空对象）去向：gre 层 config（`{"gre":{}}` 空配置随层走就是正键，key=0/checksum=false/sequence=false 全默认）；目标形状 `{"layers":[{"ip":{"src","dst"}},{"gre":{}},{"ip":{"src","dst"}},{"udp":{"src_port","dst_port"}},{"dns":{}}]}`（外层 ip→gre→内层 ip→udp→dns；gre InnerRequired=[ip]，内层从 ip 开始缺了自动补；**内层必须以终结层收尾**——裸 [ip,gre,ip,udp] 被 V4 拒 `must end with a terminal layer`，2026-09-14 探针实证，dns 是最小 UDP 载荷终结层，T-GRE-1 即此形） | `pipe_gate.sh gre` 门 2-1；`registry.go:885` gre 层；T-GRE-1 |
| §2 策略/任务分工 | 沿框架语义，不另设；gre 无 sessions，多流只走 `flow_control` + 层动态（本轮不开业务动态） | D-GRE-1 §3 |
| §3 五件套 | 豁免：gre 无子流派生、无 sessions[]、无关联字段；单流=外层 1 帧（outer eth+ip proto47 + GRE头 + 内层完整 IPv4/UDP 包）；内层 L4 由内层终结层（udp）产出，gre 只做封装（与 tls 变换器不同：gre 是真隧道层，包内层字节）；时间线=同步产全部事件、无交错 | `layer_gen.go:1` 隧道契约；`planner.go:1` 封装语义；T-GRE-1 |
| §4 规范矩阵 | RFC 2784（GRE 头：flags/version + ProtocolType；§3 转发语义）+ RFC 2890（Key/SequenceNumber 扩展；C/R/K/S 位）+ 现网口径（GRE over IPv4 为主，proto 0x0800；tshark 自动解析）；P1 矩阵见本条目依据行 | 本条目依据行 |
| §5 有错必处理 | 校验器 `validateGRESpec` **nil 容忍**（2026-09-14 探针修订）：spec.GRE nil（纯层链合法态——链上不读 flat，mapToFlowSpec 只在顶层 gre 子映射时填充）→ 直传放行；非 nil（flat gre 子映射/在库旧行）→ legacy `(&Planner{}).Validate` 全量校验（vxlan/geneve/nvgre `ValidateConfig(nil)→nil` 同款先例）。无 pin（gre 无握手/挥手语义）；链结构性校验（内层 IPv4 必填，IPv6-over-GRE 链上不同步实现）在 ValidateSpec 同步拒（`chain_planner.go` gre 段既有）；扁平/混用沿 Step1 | `planner.go:50`；`chain_planner.go:200`；T-GRE-2/3 |
| §6 性能 | 单帧封装（内层包一次拷贝 + 外层头装配）；无锁无 sleep；回归 ±10%（实测 wall 回填）；边界诚实声明（无吞吐/并发/内存目标，网卡未跑） | D-GRE-1 §6；T-GRE-1 |
| §7 三份文档 | 设计=本条目；用例=T-GRE-*；cases 回指编号 | 本条目；TEST_CASES T-GRE-* |
| §8 先设计后代码 | 本条目定稿后开工 | 本条目 |
| §9 三源+整格 | RFC 2784/2890 条文 + 本条目 + 现网 GRE-over-IPv4 口径；本轮无动态整格（gre 业务 3 键全关） | T-GRE-* |
| §10 评审闭环 | 改→审→测→修→再审；自审 N 轮；测试四问 | P6；门 3 |
| §11 白话汇报 | 先一句结论 | 每次汇报 |
| §12 动态清单 | 四元组沿框架白名单（外层/内层 ip + udp 端口走通用动态）；业务 3 键全关：key 关（tunnel 标识常量，逐流变无意义）/checksum 关（开关语义）/sequence 关（开关语义）——对象即 `does not support dynamic`；序号算法不重写 | `layer_dyn.go`（本轮零改动）；T-GRE-4 |
| §13 schema 同步 | 本轮不改注册表 gre Fields（3 键不动），schemagen 零改动；顶层 `gre` 不迁入（空对象随层走，无迁移事项） | 门 2 脚本 |
| §14 真实流程 | cases 即任务 spec；MCP 建任务→引擎生成→tshark 校对；负例带锚词；全量绿；二进制同代；包落盘可查 | T-GRE-1；门 2 三项 |

目标形状（§1 证据）：`{"layers": [{"ip": {"src","dst"}}, {"gre": {"key","checksum","sequence"}}, {"ip": {"src","dst"}}, {"udp": {"src_port","dst_port"}}, {"dns": {}}]}`（gre 3 键全列；`gre:{}` 空配置走默认 key=0/无checksum/无sequence；末尾 dns 终结层必需——裸 [ip,gre,ip,udp] 末层是 transport 被 V4 拒，探针实证）。

**状态：** 已验收（2026-09-14，P6）
**完成回填（2026-09-14）：** 步骤 0 红例先红（`validateGRESpec` 未定义编译红）后绿（3/3：FlatRejected/NilTolerant/KeyDynamicRejected）；gre 包单测 + `-race` 绿、core/layers `-race` 绿；gre.json 4/4 绿（`RESULT: 4 pass, 0 fail, 0 error (of 4)`，`/tmp/tg-gre-p5-server` 与 HEAD 同代，门 2 三项绿）；pcap 落 `/tmp/mcp-pcaps/gre/gre_basic_ipv4.pcap`（1 帧 95B，tshark 实测 `gre.flags_and_version=0x0000`/`gre.proto=0x0800`/`udp.srcport=12345`/`udp.dstport=80`，offset 34=`00 00 08 00`、offset 58=`30 39 00 50` 与翻转前逐字节一致——整帧 95B vs legacy 66B 不等价已在本条目如实声明）；在库 gre 行清空（删前报数 tasks 95 + strategies 3 → 备份 `/tmp/trafficgen-gre-p6-backup.db` → 删 → 复核 0/0 + 悬空引用 0，含悬空 `4a168de5` 引用仅来自 gre 任务一并清除）；回归 ±10%（无 wall 基线数值，suite 2s 量级，诚实声明未测）。
**门 3 抽查三条：** ①§5→`layer_gen.go:193` `validateGRESpec` nil 直传放行 + 非 nil 走 `(&Planner{}).Validate`（`TestGRESpecValidator_FlatRejected/NilTolerant` 双向钉死）；②§1→`cases/gre.json` gre_basic_ipv4 spec_json 即目标形状 `[ip,gre,ip,udp,dns]`，顶层零扁平键（门 2-1 绿）；③§12→T-GRE-4 `gre_neg_dyn_key` 真实流程拒绝，锚词 `does not support dynamic`（allowlist 无 gre 行，`layer_dyn.go:17` 本轮零改动）。
**范围（2026-09-14）：** ①`main.go:551` 翻转 `gre.NewPlanner()` → `layers.NewChainPlanner("gre")` + 空白导入（Step 2 同款一行；`main.go:38` 已有非空导入 `gre`，翻转后改空白导入）；②补 `RegisterLayerValidator("gre")`（**2026-09-14 探针修订：nil 容忍**——spec.GRE nil（纯层链合法态，链上不读 flat，`layer_gen.go:38` 既有声明）直传放行；非 nil（flat gre 子映射/在库旧行）才走 legacy `(&Planner{}).Validate` 全量校验；vxlan/geneve/nvgre `ValidateConfig(nil)→nil` 同款先例。原设计"spec.GRE nil→拒绝"会打死纯层链路径（链上 spec.GRE 恒 nil），作废。failing 先行红例改为：非法 ProtocolType 进 validator 必拒（实现前符号未定义=编译红）+ nil 必放行（契约钉死））；③gre.json 1 例 FLAT→层链改写（`count` 删 + `gre:{}` 进层 + 外层/内层 ip + 内层 udp 端口；`gre_basic_ipv4` 断言沿用，包号以落盘 pcap 校准）+ 负例 2 个（扁平判死 T-GRE-2 + static-copy 门 T-GRE-3 代表，锚词钉死）+ 关字段动态负例 1 个（T-GRE-4，key 对象即 `does not support dynamic`）。明确不解决：ARP-over-GRE（链上 InnerRequired=[ip]，ARP 内层无链层等价物；legacy 单测已覆字节）；IPv6-over-GRE（链上结构性拒绝，`chain_planner.go:200` 既有；legacy 单测已覆）；InnerTTL/InnerIPID/TCPOptions 链层注入（层 schema 无字段，生成器走默认 64/自增/无选项）；内层 TCP 链（本轮用例只整形既有 UDP 内层，TCP 内层由子女按需覆盖）；gre 业务动态（3 键全关，无整格用例）。等价证据（2026-09-14 探针修订）：既有用例 frames hex（offset 34 `00 00 08 00` + offset 58 `30 39 00 50`）翻转前后逐字节保持；**整帧不等价且如实声明**——legacy flat 1 帧内层=28B 裸 UDP（无载荷），层链形 [ip,gre,ip,udp,dns] 1 帧内层=57B（20 IP+8 UDP+29 DNS 查询，探针实测头 `45 00 00 39`），T-GRE-1 断言只钉 GRE 头/内层 UDP 两处 hex（均保持）+ udp 字段，不钉总帧长；裸 [ip,gre,ip,udp]（无终结层）V4 拒绝即改形依据。
**依据：** RFC 2784（GRE 头 §3：Flags(2B，C/R/K/S/Recursion/Version)+ProtocolType(2B)；转发语义 §3）；RFC 2890（Key 扩展 §3.1：K 位置位时 4B Key；SequenceNumber §3.2：S 位置位时 4B Sequence；Checksum/Routing §3.3-3.4——本实现 checksum 布尔即 C 位）；现网行为（GRE-over-IPv4 为主、proto 0x0800、tshark 自动解析；Key=0 不置 K 位是既有语义）；开源对照（只借帧结构思路：外层 IP proto 47 + GRE 4B 基头 + 内层完整包；不搬实现）。代码事实：legacy 全序列 `planner.go:177`（外层头 + GRE 头 + 内层包）+ Validate `planner.go:50`（ProtocolType 枚举/InnerIP 版本一致性/ARP 矛盾）+ 链隧道生成器 `layer_gen.go:1`（内层包字节自建 + L2.GRE 写 wire 配置 + 外层 proto 47）+ 链结构性校验 `chain_planner.go:200`（内层 IPv4 必填）+ 注册表 `registry.go:885`（tunnel 类、depends_on ip、InnerRequired=[ip]、3 键）+ 接线 `main.go:551`（legacy 待翻转）+ 生成器已注册（`layer_gen.go:174`，缺的只是 validator）+ 2026-09-14 链路探针：[ip,gre,ip,udp,dns] + spec 12345/80 → 1 帧（L3 proto=47、L2.GRE 非空、内层 57B）；[ip,gre,ip,udp] → V4 拒 `must end with a terminal layer`；[ip,gre,ip,tcp,http] → 9 帧（内层 TCP 链可用，本轮不建例）；legacy 空配置同 spec → 内层 28B（头 `45 00 00 1c`）。
**配置权威：** 层链是唯一真相。地址只落内外层 `ip` 层、端口只落内层 `udp` 层、数量只走 `flow_control`；gre 业务 3 字段只落 `gre` 层（key/checksum/sequence）；顶层 `gre` 子映射是过渡载体（空对象随层走，无迁移事项）。扁平五键判死沿 Step1（`strategy_convert.go:7593` CheckProtoFlat）。

#### 1. 数据与接口
- 输入：层链 `[ip,gre,ip,udp]`（gre 层 config 3 键：key uint32 缺省 0、checksum bool 缺省 false、sequence bool 缺省 false；key=0 不置 K 位）；spec 侧四元组由层值回填（外层/内层 ip 同 spec 地址，legacy InnerSrcIP/InnerDstIP 默认即 spec 地址同款）。
- 输出：单帧（outer eth + outer ip proto47 + GRE 基头 4B[+Key 4B][+Seq 4B] + 内层完整 IPv4 包 20B + 内层 UDP 8B + 载荷）。包数=1（既有用例口径）。
- 新增/修改 Go 类型：无新类型（GREConfig 已有；层 schema 3 键齐全）。新增函数：`validateGRESpec`（`internal/protocol/gre/layer_gen.go` 尾：`spec.GRE == nil → return nil`（纯层链合法态）；非 nil → `(&Planner{}).Validate(*spec)` 直传——无 pin（gre 无握手语义），nil 容忍沿 vxlan/geneve/nvgre ValidateConfig 先例）+ `init` 内 `layers.RegisterLayerValidator("gre", validateGRESpec)`。修改调用点：`main.go:551` 一行翻转 + 空白导入。
- 显式覆盖：key 显式 0=不置 K 位（与缺席同效）；checksum/sequence 空串走链默认 false。spec.GRE 非 nil 不代表 flat 权威（链上不读 spec.GRE，无 flat-wins 分支——tls `layer_gen.go:27` 同款声明，gre 层 config 是接口）。

#### 2. 依赖与生命周期
- 前置：外层 ip（depends_on）+ 内层 ip（InnerRequired）+ 内层终结层（链必须以终结层收尾）。gre 是隧道层且不能当末层——建链最小输入含内层+终结层（`[{"gre":{}},{"ip":{}},{"udp":{}},{"dns":{}}]` 之类；裸 `[{"gre":{}}]` 补全成 [ip,gre,ip] 后被 V4 拒（末层 ip 是 network）、[ip,gre,ip,udp] 同拒（末层 udp 是 transport；2026-09-14 探针实证），补全后链恒为 `[ip,gre,ip,…,终结层]`。
- 资源：无状态生成器；内层 IPID 自持 counter（legacy `InnerIPID+i` 链版：从 0 起每帧自增，避免与外层 IPID 双写竞态）；无锁无 sleep；取消经 ctx.Done 传播。

#### 3. 主流程与状态
- 状态表：单帧封装（内层包字节自建→L2.GRE 写 wire 配置→外层 builder 序列化）。无握手/挥手/序号推进（隧道层不管传输语义）。
- 会话边界：单包单会话，无 sessions[]；多流只走 `flow_control` + 四元组层动态。
- 父子流关系：无（gre 不派生子流；封装≠派生）。
- 时间线：同步产全部包、无交错。

#### 4. 递增与覆盖规则 + 正交组合矩阵 + 业务动态清单
- 动态白名单：本轮零改动（`layer_dyn.go` 不加行——gre 业务 3 键全关；四元组沿框架白名单）。
- 关的理由：key（tunnel 标识常量；逐流变=不同隧道，应拆不同策略）/checksum（开关语义）/sequence（开关语义）。
- 序号算法不重写。
- 正交组合矩阵：

  | 维度 | 单流 | 多流 |
  |---|---|---|
  | 默认（无 flags） | T-GRE-1（1 帧，offset 34/58 hex） | ×（未建例：单帧隧道多流无需求） |
  | Key | ×（未建例：将来开条目再补） | × |
  | Checksum/Sequence | ×（未建例） | × |
  | ARP-over-GRE | legacy 单测已覆（链上无内层等价物） | × |
  | IPv6-over-GRE | legacy 单测已覆（链上结构性拒绝） | × |

#### 5. 错误与异常
- gre 校验器（本轮新补；**nil 容忍**修订）：spec.GRE nil → 放行（纯层链合法态，链上不读 flat）；非 nil → `(&Planner{}).Validate` 直传（ProtocolType 枚举/InnerIP 格式与隧道模式一致性/ARP 矛盾/InnerProto 枚举/Frames≥0/Direction 枚举——在库旧行启动期错误语义与 legacy 一致）。无 pin（gre 无握手/挥手语义）。
- 链结构性校验（已有，`chain_planner.go:200`）：内层 IPv4 必填（空/IPv6 同步拒绝，gre HIGH-2 先例）。
- gre 专属负例（T-GRE-2/3/4，真实流程 error_contains）：①顶层扁平判死（Step1 CheckProtoFlat，锚词 `no longer accepts flat config field`——既有用例 `count`+顶层 `gre` 即判死对象）；②层链静态复制（`checkLayerChainStaticCopy`，锚词 `static four-tuple`，flows=2+全静态标量）；③关字段动态（`checkLayerDynObjects` allowlist 门，锚词 `does not support dynamic`，`key{"strategy"…}` 即拒）。
- Failing 先行（修订）：①非法 ProtocolType 进 `validateGRESpec` 必拒（实现前符号未定义=编译红）；②`validateGRESpec` 对 spec.GRE nil 必放行（nil 容忍契约钉死，防将来误改回 nil 拒绝）；key 对象→`does not support dynamic` 是**既有 allowlist 门的回归锁**（当日已绿非红例——allowlist 无 gre 行，对象在 `checkLayerDynObjects` 即拒）。

#### 6. 性能设计与验收
- 路径依据：单帧封装（内层包一次构建 + 外层一次序列化；内层 L4 校验和内联计算）；无锁、无 sleep；分段/限速/背压归外层 ip 与 worker（既有机制）。
- 目标：不新增性能门；回归口径=现有套件耗时相对基线 ±10% 内。性能边界诚实声明：无目标吞吐/并发上限/内存上限数字（未测，标待确认，不承诺）。
- pcap 验收：gre.json 全绿（P5 实测）+ 包落 `/tmp/mcp-pcaps/gre/` 可复查（tshark 断言 `gre.flags_and_version` + `gre.proto` + 内层 UDP 端口 + frames hex offset 34/58，不手算包号）；网卡验收：本机无发包口（未跑，pcap 一路已全绿）。

#### 7. 实现顺序与回滚
- 步骤 0（failing 先行，2026-09-14 修订）：`internal/protocol/gre/layer_validate_test.go` 新文件 3 例：①`TestGRESpecValidator_FlatRejected`——非法 ProtocolType（0x9999）进 `validateGRESpec` 断言拒绝（实现前符号未定义=编译红）；②`TestGRESpecValidator_NilTolerant`——spec.GRE nil 断言放行（nil 容忍契约；若实现成 nil 拒绝此例红，钉住修订语义）；③`TestGRELayer_KeyDynamicRejected`——`gre{"key":{"strategy":"list"…}}` 经 `layers.ValidateLayers` 断言 `does not support dynamic`（既有 allowlist 门的回归锁，当日绿）。
- 步骤 1（翻转 + 校验器）：`main.go:551` → `layers.NewChainPlanner("gre")` + 空白导入；`gre/layer_gen.go` 尾加 `validateGRESpec` + `init` 注册。
- 步骤 2（门 2-1 脚本）：`pipe_gate.sh` 零改动（gre 无顶层协议子映射迁入事项）。
- 步骤 3（自审 §10 + 构建测试）：`go build ./...` + `go vet` + touched 包 `-race`（core/layers/gre）→ P5 用例改写与 suite（另步）。回滚=本轮单提交逆序 revert。
- 工作量（估计）：代码约 1 小时（2 文件 + 单测红例）；用例 gre.json 1 例改写 + 负例 3；suite 全量重跑。

#### 8. 验收
- 对应 `docs/TEST_CASES.md` T-GRE-1…4（P3 先行，见下）。
- 完成条件：步骤 0 红例先红后绿；gre 包单测绿；gre.json suite 全绿（`RESULT` 全量绿；二进制同代；门 2 三项绿）；`go vet` + touched 包 `-race` 绿；在库 gre 行清空（删前报数→备份→删→复核：tasks 95 + strategies 3）；§1 两道门：①层链跑通（gre.json）；②旧字段移除（顶层 `count`+`gre` 判死：新建 400 + 在库 error + 门 2-1 脚本绿）。
- 缺口如实记录：ARP/IPv6-over-GRE 链上实现；Key/Checksum/Sequence 整形例；内层 TCP 链例；Full 3588 + `go test ./internal/...` 待 Step 8。（前三项由 D-GRE-2 回补）

### D-GRE-2 GRE 隧道 v4/v6 全族 + 内层地址自治 + 静默覆盖修复【D-GRE-1 缺口回补】

**门 1 开工对照表（§1–§14，2026-09-15，证据=文档节/代码行/探针/用例号）：**

| § | 本协议怎么满足 | 证据 |
|---|---|---|
| §1 层链唯一真相 | 老 flat `gre` 子映射 16 字段逐键去向见本条目"flat 字段三选一表"（8 个此前无去向的字段本轮各归其位：inner 地址→内层 ip 层、inner_ttl→内层 ip 层 ttl、其余三选一登记）；目标形状两种族：`[ip(v4/v6), gre, ip(v4/v6), udp/tcp, 终结层]`——内外层地址各自独立、族可异 | 本条目 flat 表；T-GRE-5/6/7 |
| §2 策略/任务分工 | 沿框架语义；多流走 `flow_control`，内外四元组动态规则见 §12 行 | D-GRE-2 §3 |
| §3 五件套 | 豁免（同 D-GRE-1）：单帧封装无子流派生/无 sessions；内层 L4 由内层传输/终结层产出，gre 只封装 | D-GRE-1 §3；T-GRE-8 |
| §4 规范矩阵 | **地址族×位置矩阵**（下表）+ flat 字段三选一表——每格已实现/本轮补/明确不支持三选一，无留白；依据 RFC 2784 §2.2（ProtocolType 标识内层载荷）、RFC 2473（IPv6-in-IPv4 GRE）、现网 4in6/6in4 过渡隧道常态 | 本条目矩阵行 |
| §5 有错必处理 | 三处修复各带锚词：内层坏 IP / 内层混族 / 内层 ip 动态拒绝；静默覆盖（无错假成功）是本轮消灭对象——探针 A 实锤外 v4 内 v6 出包内层被换 v4 无告警 | §5 错误表；探针 A/B/C（2026-09-15） |
| §6 性能 | 修复均在单包路径（一次 To4 判族/一次 TTL 读取），无锁无分配增长；回归口径 suite ±10%，边界诚实声明（无吞吐/并发数字，未测） | §6 |
| §7 三份文档 | 设计=本条目；用例=T-GRE-5…14；cases 回指编号 | TEST_CASES T-GRE-5…14 |
| §8 先设计后代码 | 本条目定稿后开工 | 本条目 |
| §9 三源+整格 | 地址族对称覆盖矩阵（v4/v6 × 外/里 × 正负例）逐格登记，一族代表另一族的旧缺口即本条目起因 | §4 矩阵；T-GRE-5…14 |
| §10 评审闭环 | failing 先行 6 红例（探针转正）→ 改 → 审 → 测 → 再审 | §7 |
| §11 白话汇报 | 先一句结论 | 每次汇报 |
| §12 动态清单 | 外层 ip.src/dst 与端口动态开（既有白名单）；**内层 ip 层动态关**（新负例锚词 `inner ip layer does not support dynamic`）——LayerDynValues 只有一套 ip 值，双层动态打架（探针 C 实锤：外层对象被内层顶掉，无告警）；gre 业务 3 键关沿 D-GRE-1；序号算法不重写 | 探针 C；T-GRE-13 |
| §13 schema 同步 | 注册表 gre Fields 零改动（key/checksum/sequence 不动）；v6 靠内外 ip 层既有字段表达，无新键 | 门 2 脚本 |
| §14 真实流程 | cases 即任务 spec；MCP 建任务→生成→tshark 校对；断言数值以落盘 pcap 校准（gre.sequence 等字段名先跑后钉）；二进制同代 | T-GRE-5…14 |

**状态：** 已验收（2026-09-15，P6）
**完成回填（2026-09-15）：** 步骤 0 六红例先红后绿（InnerScalarRespected/V6InV6/InnerMixedFamilyRejected/InnerTTLOverride/InnerDynRejected/ParseLayerDyn_InnerIPDynamicRejected——红因即缺陷本身）；四处修改合入（applySpecToChain 内层自治 / 结构段重写 / 生成器族分派+TTL / 内层动态双侧拒绝）；存量 T12_GREInnerErrorPropagates 按 §9 审计改写（原"v6 必须拒"语义作废，正路径由 V6InV6 接管，结构性同步拒绝意图以空 spec 载体保留）；gre.json 14/14 全绿（`RESULT: 14 pass, 0 fail, 0 error (of 14)`，`/tmp/tg-gre-p5-server` 与 HEAD 同代，门 2 三项绿）；断言全按落盘 pcap 校准（v6 帧 135B `86 dd`+GRE `00 00 86 dd`+内层 v6+UDP 校验和 0xf374；6in4 ip.version="4,6" 双族同帧互证；4in6 帧 115B；sequence 9 帧首末序号 hex 0/8 双钉+tshark 3.6 无序号值字段的边界注明+生成器级递增单测补位；checksum 0x9637/key 0x12345678/combo 帧 107B 0xb000/内层 TTL 60 vs 外层 64 frames hex 双钉）；touched 包 `-race` 绿；回归 ±10%（suite 4.6s 量级 vs D-GRE-1 2.0s——用例数 4→14 所致，单例口径未测，诚实声明）。
**门 3 抽查三条：** ①§1 A1 决策→`chain_planner_chain.go` applySpecToChain ip case seenIP 标志 + innerIP 分支（用户标量保留/缺席回填/不注入外层值），`TestGREChain_InnerScalarRespected` 钉死；②§4 v6-in-v6 格→`cases/gre.json` gre_v6_in_v6 断言 `gre.proto=0x86dd`+`eth.type=0x86dd`+`ipv6.version=6,6`（落盘 pcap 校准）；③§12 内层动态关→`validate_layers.go` ValidateLayers 首非 ip 层守卫 + `layer_dyn.go` parseLayerDyn 同锚词，T-GRE-13 真实流程拒绝。
**范围（2026-09-15）：** ①`applySpecToChain` ip 注入规则改：spec 地址只注入**首个**（外层）ip 层；内层 ip 层用户标量保留、src/dst 缺席回填 spec 值（向后兼容 T-GRE-1：内层不写=外层值）；内层不注入 ttl/dscp/ecn（内层这些值只认内层层配置）。②`chain_planner.go` gre 结构段重写：外层 spec 地址任意族（非空+可解析）；内层有效地址=内层 ip 层显式值否则 spec；内层两地址必须同族；**外内族可异**（4in6/6in4 放行）。③`GREGenerator` 族分派：内层 To4 非空→`buildInnerIPv4Packet`+proto 0x0800；否则→`buildInnerIPv6Packet`（同包既有函数）+proto 0x86DD；内层 TTL 改读 `pkt.L3.TTL`（内层 ip 层生成器已写入，0 回退 64）。④内层 ip 层动态对象双侧拒绝（ValidateLayers + parseLayerDyn），锚词 `inner ip layer does not support dynamic`。builder 零改动（0x86DD 双位本就放行，2026-09-15 核查 `builder.go:492` validateGREConfig）。
**明确不支持（三选一登记，不冒充）：** ARP 内层（无 arp 链层，InnerRequired=[ip] 结构性排除）；MPLS/PPP 内层（0x8847/0x880B，从未实现）；GRE keepalive（非标扩展）；`inner_ipid` 基值（链版 0 起自增保逐字节可复现，基值无需求）；`tcp_options` 内层注入（需 MessageEvent 扩展，另立项）；`routing/routing_present`（RFC 2890 已弃用，原实现仅字节透传）；`frames`/`direction`（形状由层链取代：多帧=内层链包数，方向=内层事件方向）；`protocol_type` 显式值（自动推导：内层族→0x0800/0x86DD）；`sequence` 基值（恒 0）；同一策略 v4/v6 混族动态（全局混族 400 门，非 gre 专属）。
**依据：** RFC 2784 §2.2/§3.1（GRE 头 ProtocolType 标识内层载荷协议；IPv4=0x0800/ARP=0x0806）；RFC 2890（K/C/S 位语义）；RFC 2473（IPv6-over-IPv4 隧道——4in6 过渡场景的规范源头）；现网行为（6in4/4in6 过渡隧道是运营商现网常态，tshark 对两族 GRE 自动解析）；开源对照（借帧结构思路：外层 IP proto 47 + GRE 头 + 内层完整 IP 包，v4/v6 内层同构处理，不搬实现）。代码事实（2026-09-15 探针）：`extractLayerSrcDst` 只取首个 ip 层（`strategy_convert.go:255`，return 在循环内首 ip 层即返）；`applySpecToChain` spec 地址灌所有 ip 层（`chain_planner_chain.go:290` ip case）；探针 A：外 v4+内 v6 → 出包内层 v4 无告警（静默覆盖实锤）；探针 B：v6 链 → `IPv6-over-GRE not supported yet`（结构段 v4 钉死）；探针 C：双 ip 层动态 → parseLayerDyn 只留内层值外层被顶（打架实锤）；`buildInnerIPv6Packet`/`buildInnerL4` v6 伪头校验和齐备（`planner.go:395/429`）但链生成器不调；`GREGenerator` proto 硬编码 0x0800（`layer_gen.go:114`）、TTL 硬编码 64（`:108`）而内层 ip 生成器已写 `pkt.L3.TTL`（`generator.go` IPGenerator，2026-09-15 核查）。

**§4 地址族×位置矩阵（规范要求→业务场景→代码现状→去向）：**

| 场景 | 规范/现网依据 | 代码现状（2026-09-15） | 去向 |
|---|---|---|---|
| v4 外 v4 里 | RFC 2784 基本形 | 已实现（T-GRE-1） | 保持 |
| v4 外 v6 里 | RFC 2473 6in4 过渡 | **静默覆盖 bug**（探针 A：内层被换 v4 无告警） | 本轮修（T-GRE-6） |
| v6 外 v4 里 | 现网 4in6 过渡 | 同上 + 外层 v6 被结构段拒 | 本轮修（T-GRE-7） |
| v6 外 v6 里 | RFC 2473 纯 v6 隧道 | 结构段同步拒（探针 B） | 本轮修（T-GRE-5） |
| 内层 ARP | RFC 2784 0x0806 | 无 arp 链层（InnerRequired=[ip]） | 明确不支持 |
| 内层 MPLS/PPP | 0x8847/0x880B | 从未实现 | 明确不支持 |
| keepalive | 非标扩展 | 从未实现 | 明确不支持 |
| 内层 TCP 序列 | 内层 tcp 层既有 | 生成器支持（探针 9 帧）无例 | T-GRE-8 建例 |

**flat 字段三选一表（§1 逐键去向）：**

| flat `gre` 字段 | 去向 |
|---|---|
| 四元组/count | 外层 ip/udp 层 + flow_control（已迁，D-GRE-1） |
| inner_src_ip/inner_dst_ip | 内层 ip 层 src/dst（**本轮修通**） |
| inner_proto | 内层 tcp/udp 层（已迁） |
| inner_ttl | 内层 ip 层 ttl（**本轮修通**：生成器改读 pkt.L3.TTL） |
| inner_payload | 内层终结层载荷（已迁） |
| key/key_present | gre 层 key（已迁；K 位=key≠0） |
| sequence(+present) | gre 层 sequence（已迁；基值恒 0） |
| checksum | gre 层 checksum（已迁） |
| protocol_type | 自动推导（内层族→0x0800/0x86DD），显式值明确不支持 |
| inner_ipid | 明确不支持（链版 0 起自增保复现） |
| tcp_options | 明确不支持（需 MessageEvent 扩展，另立项） |
| routing/routing_present | 明确不支持（RFC 2890 弃用） |
| frames/direction | 明确不支持（形状由层链取代） |

**配置权威：** 层链唯一真相。外层地址只认首个 ip 层，内层地址只认内层 ip 层（缺席=外层值）；内层 TTL 只认内层 ip 层 ttl；GRE 头三键只认 gre 层。

#### 1. 数据与接口
- 输入：两种族层链 `[ip(v4/v6), gre{key,checksum,sequence}, ip(v4/v6), udp/tcp, 终结层]`；内外层地址独立。
- 输出：单帧（外层 eth+IP proto47 + GRE 头[+Key/Checksum/Sequence] + 内层完整 v4 或 v6 包）。
- 修改点四处（builder/注册表/schema 零改动）：`chain_planner_chain.go` applySpecToChain ip case（首个 ip 层标志位）；`chain_planner.go` gre 结构段（读内层层配置）；`gre/layer_gen.go` Generate（族分派 + TTL）；`validate_layers.go`+`layer_dyn.go`（内层动态拒绝）。新增函数：无。
- 显式覆盖：内层 ip 层 src/dst/ttl/dscp 用户显式值一律生效（本轮起不被顶）；内层 dscp/ecn/frag_offset 不注入 spec 值（只认层配置，缺省 0）。

#### 2. 依赖与生命周期
- 前置同 D-GRE-1（外层 ip + 内层 ip + 内层终结层）；新增：内层 ip 层是内层地址/TTL 的唯一权威，结构段按"内层 ip 层显式值否则 spec"解析有效内层地址。
- 资源：无状态生成器；族分派是逐包一次 To4 判定，无锁无分配增长；取消经 ctx.Done。

#### 3. 主流程与状态
- 单帧封装不变；生成器内层分派：`net.ParseIP(innerSrc).To4() != nil` → v4 builder+0x0800；否则 v6 builder+0x86DD（内外族独立，互不约束）；down 帧内层地址交换语义两族同款；内层 TTL=`pkt.L3.TTL`（0→64）。

#### 4. 递增与覆盖规则 + 正交组合矩阵 + 业务动态清单
- 内层 IPID 沿链 counter 0 起自增；GRE Sequence 沿 gre 层 sequence 键 0 起自增（多帧场景=内层链多包，T-GRE-8）。
- 动态：外层四元组开（既有）；内层 ip 层三键（src/dst/ttl）动态对象一律拒（单四元组模型）；gre 业务 3 键关沿 D-GRE-1。
- 正交组合矩阵：

  | 维度 | v4 内层 | v6 内层 |
  |---|---|---|
  | v4 外层 | T-GRE-1（既有） | T-GRE-6（新） |
  | v6 外层 | T-GRE-7（新） | T-GRE-5（新） |
  | K/C/S 单键 | T-GRE-9/10（新） | ×（族与键正交，v4 侧代表） |
  | K+C+S 组合 | T-GRE-11（新） | ×（同上） |
  | sequence 多帧递增 | T-GRE-8（新） | ×（同上） |
  | 内层 TTL 覆盖 | T-GRE-12（新） | ×（同上） |

#### 5. 错误与异常
- 结构段锚词（chain_planner.go gre 段）：外层空 `gre chain: outer ip addresses required (tunnel endpoints come from the outer ip layer)`；内层坏 IP `gre chain: inner ip layer src %q is not a valid IP address`；内层混族 `gre chain: inner ip layer addresses %s/%s must be the same IP version`。旧文案（`IPv6-over-GRE not supported yet`/`inner IPv4 addresses required`）随 v4 钉死一起作废。
- 内层动态锚词（双侧）：`layers[%d](ip).%s: inner ip layer does not support dynamic (tunnel inner addresses are static; vary the outer ip layer instead)`。
- 生成器防御：内层地址不可解析（防御路径，校验已拦）→ 报错不静默。
- Failing 先行 6 红例（探针转正，实现前全红）：内层标量保留 / v6-in-v6 放行 / 内层混族拒 / 内层 TTL 生效 / ValidateLayers 内层动态拒 / parseLayerDyn 内层动态拒。

#### 6. 性能设计与验收
- 修复均在单包路径：族分派一次 To4、TTL 一次读取、注入分支一个标志位——无锁、无 sleep、无每包新分配。回归口径：gre.json 全量 suite 耗时相对 D-GRE-1 基线 ±10%；边界诚实声明：无吞吐/并发/内存目标数字（未测，标待确认，不承诺）。
- pcap 验收：14/14 全绿 + 落盘可复查（v6 用例 tshark `gre.proto=0x86dd`+内层 `ipv6` 字段，字段名以落盘 pcap 校准）；网卡未跑（无发包口）。

#### 7. 实现顺序与回滚
- 步骤 0（failing 先行）：`internal/core/layers/gre_v6_test.go` 5 红例（BuildLayersPlanner 全链口径，`_ "protocol/gre"`+`_ "protocol/dns"` 空导入注册）+ `internal/core/layer_dyn_inner_test.go` 1 红例。
- 步骤 1：applySpecToChain 内层保留分支；步骤 2：结构段重写；步骤 3：生成器族分派+TTL；步骤 4：内层动态双侧拒绝；步骤 5：`go build ./...` + vet + touched 包 `-race`；P5：gre.json 增 10 例全量跑；P6：评审+提交+清库复核（D-GRE-1 已清空，无新增在库）。
- 回滚：单提交逆序 revert。

#### 8. 验收
- 对应 T-GRE-5…14（TEST_CASES P3 先行）。完成条件：6 红例先红后绿；gre.json 14/14 全绿（RESULT 全量；二进制同代；门 2 三项绿）；touched 包 `-race` 绿；新旧结构段文案切换无残留引用。
- 缺口如实记录：tcp_options 内层注入（另立项）；Full 3588 待 Step 8。

#### 9. 关键决策对比

| 决策 | 候选 | 优劣 | 结论 |
|------|------|------|------|
| A 内层地址权威 | A1 内层标量自治/缺席回填外层；A2 spec 广播（现状=静默 bug）；A3 内层必填 | A1 兼容 T-GRE-1（不写=外层值）且消灭静默覆盖；A2 已证错；A3 破坏既有用例 | 选 A1 |
| B v6 范围 | B1 全族+异构；B2 仅同族 | B1 覆盖 4in6/6in4 过渡场景（现网常态）；B2 省一半例仍留异构缺口 | 选 B1 |
| C inner_ttl 住处 | C1 内层 ip 层 ttl（生成器读 pkt.L3.TTL）；C2 gre 层新字段 | C1 零 schema 改动且合"值住其层"；C2 违背层链哲学 | 选 C1 |
| D 内层动态 | D1 拒绝+负例；D2 扩 LayerDynValues 双套 | D1 单四元组模型内自洽（打架已证）；D2 大改无需求 | 选 D1，将来需求另立条目 |
| E 旧结构段文案 | E1 重写（含 outer/inner 新锚词）；E2 保留 IPv4 字样 | E2 与全族语义矛盾 | 选 E1 |


#### 9. 关键决策对比

| 决策 | 候选 | 优劣 | 结论 |
|------|------|------|------|
| A 翻转 | A1 ChainPlanner 一行；A2 保持 legacy | A1 归位层链，A2 留双轨违反 §1 | 选 A1 |
| B validator 语义 | B1 Validate 直传无 pin；B2 照抄 tls pin 握手/挥手 | B1 gre 无握手语义，pin 无意义；B2 给隧道层 pin 握手是错语义 | 选 B1 |
| C 业务动态 | C1 3 键全关；C2 开 key | C1 tunnel 标识逐流变应拆策略，无用例需求；C2 加无消费面的形状门 | 选 C1；将来有需求另立条目 |
| D 内层协议 | D1 本轮只整形 UDP 内层（既有用例）；D2 顺手加 TCP 内层例 | D1 最小够用；D2 搭车加例无设计需求 | 选 D1 |


### D-GRE-3 GRE 用例内外分离 + VLAN 底座归位框架 + 隧道结构校验泛化 + 动态整格补齐【用户三项裁定 + 拼积木归位 A】

**门 1 开工对照表（§1–§14，2026-09-15，证据=文档节/代码行/探针/用例号）：**

| § | 本协议怎么满足 | 证据 |
|---|---|---|
| §1 层链唯一真相 | 目标形状扩一种：`[vlan{id,priority}?, ip, gre, ip, udp/tcp, 终结层]`（vlan 可选打头，缺省无 tag）；内外层地址新网段：v4 内层 `192.168.1.1→192.168.1.2`、v6 内层 `fd01::1→fd01::2`（外层 10.x/fd00 不动，6in4/4in6 已异构不碰）；顶层旧键零新增 | T-GRE-15…20；本条目 §4 |
| §2 策略/任务分工 | 沿框架语义；动态正例走 `flow_control` flows=2 + 层内 strategy 对象（http T-HTTP-60…72 同款形状） | T-GRE-16/17/18 |
| §3 五件套 | 豁免（同 D-GRE-1）：vlan 是 L2 占位 wrapper——不产包、不参事件流，只逐包透传（drive 级联不断）；tag 落定在 finalEmit（`l2For` 读 `spec.VLAN`，chain_planner_gen.go:207 既有分支）；单帧封装/时间线不变 | 本条目 §1 数据与接口；探针（2026-09-15） |
| §4 规范矩阵 | IEEE 802.1Q（TPID 0x8100 + TCI=`priority<<13\|id`，与 `builder.go:1037` 同算法）；现网 GRE 外层常带 VLAN tag；tshark `vlan.id/priority` 字段（goose_vlan 先例）；隧道结构规则 RFC 2784 §2.2 + RFC 2473 沿 D-GRE-2 | `builder.go:1037`；goose.json vlan 断言；T-GRE-15 |
| §5 有错必处理 | 锚词子串零变化（前缀 `gre chain:`→`tunnel chain:`，用例 `error_contains` 全是子串不断言前缀）：外层空 `outer ip addresses required` / 内层坏 IP `is not a valid IP address` / 内层混族 `must be the same IP version` / 内层动态 `inner ip layer does not support dynamic`；vlan id/prio 越界走既有 V9（schema Min/Max 4095/7）；vlan 进隧道内走既有 V7 拒（`must be in the outermost run`，存量单测已钉） | T-GRE-13/14；TestValidateLayers_L2Placement；T-GRE-19/20 |
| §6 性能 | vlan 提取=ValidateSpec 内一次链扫描；passthrough=逐包一次转发（无锁无分配）；隧道泛化=同等分支数（`l.Name!="gre"` 字面换成 CategoryTunnel 查表）；回归口径 suite ±10%，边界诚实声明（未测吞吐/并发） | 本条目 §6 |
| §7 三份文档 | 设计=本条目；用例=T-GRE-15…20；cases 回指编号 | TEST_CASES T-GRE-15…20 |
| §8 先设计后代码 | 本条目定稿后开工 | 本条目 |
| §9 三源+整格 | 802.1Q 条文 + builder.go:1037 + goose vlan 先例；动态整格见 §12 行（开 3 正例 / 关 2 负例 / 引用 1 / 注记不开 2） | §12 整格表 |
| §10 评审闭环 | failing 先行 3 红例（BuildLayersPlanner vlan 拒 / wire TCI / tunnel 前缀）→ 改 → 审 → 测 → 再审 | 本条目 §7 步骤 |
| §11 白话汇报 | 先一句结论 | 每次汇报 |
| §12 动态清单 | 整格见本条目 §12 表：外层 ip.src/dst 开（T-GRE-16 正例）/ 内外 udp/tcp 端口开（T-GRE-17/18 正例）/ gre checksum·sequence 关（T-GRE-19 负例，sequence 代表）/ dns 业务关（T-GRE-20 负例）/ http 业务引用 T-HTTP-60…72（同 parseLayerDyn 路径）/ vlan.id 关（allowlist 无 vlan 行天然关，不单建例）/ 外层 ttl·eth mac 注记不开（无业务语义/链值无翻译分支，F2 另立项） | T-GRE-16…20 |
| §13 schema 同步 | 注册表零改动（vlan/gre Fields 不动；只读 `CategoryTunnel` 分类）；schemagen/webgen 不跑 | 门 2 脚本 |
| §14 真实流程 | 20/20 全绿 + 落盘校准（checksum 值重钉——内层地址字节变了旧值作废；vlan TCI hex；distinct 聚合方向）；二进制同代；门 2 三项 | T-GRE-15…20 |

**状态：** 已验收（2026-09-15，P6）
**完成回填（2026-09-15）：** 步骤 0 三红例先红后绿（BuildPasses：`generator not implemented for layer "vlan"`→通过；TagOnWire：无 tag→12:14=`81 00`+14:16=`80 64` 全帧含 down；GenericPrefix：`gre chain:`→`tunnel chain:` 子串保持）；代码两文件（newGenerator vlan passthrough / ValidateSpec vlan 提取 id 显式才启用 + 隧道块泛化 CategoryTunnel×next==ip，tls 链天然豁免实测 PASS）；gre.json 12 例内层地址分离（192.168.1.x/fd01::，v6_in_v6 ipv6.src 聚合重钉 `fd00::1,fd01::1`）+ 6 新例；20/20 全绿（`RESULT: 20 pass, 0 fail, 0 error (of 20)`，/tmp/tg-gre-p7-server 与 HEAD 同代，门 2 静态两项绿）；落盘校准：checksum 0x9637→0xfb89、combo 0xfd8a→0x62dd（内层地址字节变旧值作废）、vlan.id=100/priority=4 tshark 实证、outer_ip distinct 聚合形 `10.0.0.1,192.168.1.1`/`10.0.0.2,192.168.1.1`、tcp dyn 端口 distinct_exclude 12345（down 流端口互换）；`go test ./internal/...` 122 包全绿 + layers/core `-race` 绿；在库 p7 gre 行清空（删前 tasks 62+strategies 13 → 删后 0/0，全库 0/0 复核）。
**门 3 抽查三条：** ①§1 vlan 正例→`cases/gre.json` gre_vlan_tagged 链首 `{"vlan":{"id":100,"priority":4}}`，tshark 实证 `vlan.id=100 vlan.priority=4 gre.proto=0x0800` 同帧；②隧道泛化→`chain_planner.go` 通用块（CategoryTunnel 查表 + next==ip 触发），红例3 钉 `tunnel chain:` 前缀 + T12/T13 tls 链回归全绿（tls 天然豁免实测）；③动态整格→gre_outer_ip_dynamic（外层源 distinct 双流）+ gre_neg_dyn_dns（dns 对象 `does not support dynamic`）真实流程执法。
**P5 落地偏差（如实登记）：** tcp 端口动态正例用 `inc{"range":[80,8080],"step":8000}` 替代设计稿 list[80,8080]——StrategyConfig.List 是 []string，数字端点 JSON 解码即 `invalid object`（形状层拒绝；端口 list 端点须字符串或走 inc）；distinct 断言以落盘 pcap 实测回钉（外层 ip.src 聚合含内层值、tcp.dstport 需 distinct_exclude 剔 down 流互换端口），与设计稿"以落盘为准回钉"一致。
**范围（2026-09-15）：** ①`newGenerator` 加 `vlan` 分支（passthrough 透传——消费 Inner 逐包 Emit 原样，eth `nil` 直返同款不可抄：eth 恒 chain[0] 非 wrapper，vlan 恒 wrapper，直返会 strand 包→静默空流）；②ValidateSpec 通用路径加 vlan 提取（补全链首个 vlan 层 id/priority→`spec.VLAN`；层值赢 flat `vlan_id`，缺席不动）；③`chain_planner.go` gre 结构段删块→通用隧道块（触发=链含 CategoryTunnel 层且其下一层是 ip；tls 链天然豁免——tls 后是终结层非 ip；锚词子串不变）；④gre.json 12 例改内层地址 + 6 例新增（T-GRE-15…20）+ 全量 20/20 校准。
**明确不解决：** eth 层 `src_mac/dst_mac` 链值无人消费（`applySpecToChain` 无 eth 分支 + `l2For` 只读顶层 spec MAC，另立项）；vlan 动态（allowlist 无 vlan 行，对象天然 `does not support dynamic`，不单建例）；内层 VLAN（V7 结构性拒）；MPLS/PPP inner·tcp_options·keepalive 沿 D-GRE-2。
**依据：** IEEE 802.1Q §3（TPID 0x8100 + TCI）；`builder.go:1037`（tag 编码 `priority<<13\|id`，实现已就绪只缺上游供给）；`chain_planner_gen.go:198`（`l2For` 的 `spec.VLAN` 传播分支已存在，供给即生效）；drive 级联语义（`chain_planner_translate.go` wrapper 循环：每层恰一关闭者，wrapper 必须消费输入——探针 2026-09-15：`generator not implemented for layer "vlan"` 是 BuildLayersPlanner 预检同步拒，ValidateLayers 面放行）；RFC 2784 §2.2 / RFC 2473 沿 D-GRE-2。

#### 1. 数据与接口
- 输入：`[vlan{id,priority}?, ip, gre, ip, udp/tcp, 终结层]`（vlan 缺席=无 tag；出现即打 tag，id=0 也打——presence 即意图，OptionalOn 已保证不写不打）。
- 输出：外层帧 eth14 后插 4B 802.1Q（TPID 0x8100 + TCI），其余偏移 +4；down 帧 tag 保留（只换 MAC，tag 与方向无关）。
- 修改点三处（builder/注册表/schema/drive/finalEmit 零改动）：`chain_planner_gen.go` newGenerator vlan 分支；`chain_planner.go` ValidateSpec（vlan 提取 + 隧道块泛化）。新增函数：无（passthrough 生成器 1 个小 struct，ethPlaceholderGenerator 同构）。
- 显式覆盖：vlan 层值→`spec.VLAN`（通用路径，所有链生效——http 链将来写 vlan 层直接生效，零新增）；flat `vlan_id` 无 vlan 层时沿 legacy（只动有层情形，不碰旧语义）。

#### 2. 依赖与生命周期
- 前置：vlan 层 DependsOn eth（缺 eth 自动补，补全链 `[eth,vlan,ip,…]`，V7 最外连续段通过）。
- 资源：passthrough 无状态；vlan 提取在 ValidateSpec 同步期（Plan 内复调无累积——`spec.VLAN` 覆盖写幂等）。

#### 3. 主流程与状态
- 级联：`[eth,vlan,ip,gre,ip,udp,dns]` 的 wrapper 环= vlan→外层ip→gre→内层ip（transportIdx=5，循环天然覆盖，无需改接线）；终结层事件流/变换器断言不受影响（vlan 非 EventTransformer 但它在 transport 之外，`assertEventWiring` 只查 transport…末层之间）。
- 通用隧道块伪形：`for i,l := range chain { schema:=reg.Get(l.Name); if schema.Category!=CategoryTunnel || i+1>=len(chain) || chain[i+1].Name!="ip" { continue }; …三检查…; break }`。

#### 4. 递增与覆盖规则 + 正交组合矩阵 + 业务动态清单
- 无新序号算法（vlan 无序号；GRE Sequence 沿 D-GRE-2）。
- 动态整格（§12）：

  | 层.字段 | 开/关 | gre 链语义 | 覆盖 |
  |---|---|---|---|
  | ip.src/dst（外层） | 开 | 隧道端点逐流变 | T-GRE-16（list 2 值 + flows=2，外层源 distinct） |
  | udp/tcp 端口 | 开 | 内层端口逐流变 | T-GRE-17（udp）/T-GRE-18（tcp+http 内层） |
  | ip.*（内层） | 关 | 单四元组模型 | T-GRE-13（沿 D-GRE-2） |
  | gre.checksum/sequence | 关 | 布尔开关无动态面 | T-GRE-19（sequence 对象拒，代表同锚词） |
  | dns.* | 关 | 不在 allowlist | T-GRE-20（name 对象 → does not support dynamic） |
  | http.* 6 字段 | 开 | 内层业务 | 引用 T-HTTP-60…72（同 parseLayerDyn 路径） |
  | vlan.id/priority | 关 | allowlist 无行 | 注记（不单建例） |
  | 外层 ttl / eth mac | — | 无语义/无翻译分支 | 注记不开（F2 另立项记） |
- 正交组合：vlan × v4（T-GRE-15）；vlan × v6 不单建（tag 与 L3 族正交，builder 侧 EtherType 照旧由 `EtherTypeFor` 定）；动态 × 6in4 不单建（dyn 走外层 spec，与内层族正交）。

#### 5. 错误与异常
- 通用隧道块锚词（前缀 `tunnel chain:`，子串与 D-GRE-2 一致）：外层空 `outer ip addresses required (tunnel endpoints come from the outer ip layer)`；内层坏 IP `inner ip layer %s %q is not a valid IP address`；内层混族 `inner ip layer addresses %s/%s must be the same IP version`。
- Failing 先行 3 红例：①`[{"vlan":{"id":100}},{"ip":…},{"gre":{}},…]` BuildLayersPlanner 通过（现状 `generator not implemented for layer "vlan"`）；②同链 Plan→builder 首帧 12:14=`81 00` + 14:16=`80 64`（id=100/prio=4，TCI=`4<<13\|100`=0x8064）且全帧（up+down）带 tag；③内层混族/外层空错误含 `tunnel chain:` 前缀（现状 `gre chain:`）。

#### 6. 性能设计与验收
- 单包路径增量：vlan 透传一次 channel 转发（与 gre/ip wrapper 同款，无新增分配）；ValidateSpec 提取一次短链扫描（≤8 层）。回归口径：gre.json 全量 suite 耗时相对 D-GRE-2 基线 ±10%；边界诚实声明：无吞吐/并发/内存目标数字（未测）。
- pcap 验收：20/20 全绿 + 落盘可复查（checksum 两值重钉——内层地址字节变旧值作废；vlan TCI hex 双钉；distinct 聚合方向以落盘为准）；网卡未跑。

#### 7. 实现顺序与回滚
- 步骤 0（failing 先行）：`internal/core/layers/gre_vlan_tunnel_test.go` 3 红例（BuildLayersPlanner 全链口径）。
- 步骤 1：newGenerator vlan passthrough；步骤 2：ValidateSpec vlan 提取 + 隧道块泛化（删 gre 专属块）；步骤 3：`go build ./...` + vet + touched 包 `-race`；P5：gre.json 12 例改地址 + 6 例新增，全量 20/20 跑 + 校准回钉；P6：评审+提交+清库复核（D-GRE-1 已清空，在库复核零新增）。
- 回滚：单提交逆序 revert。

#### 8. 验收
- 对应 T-GRE-15…20（TEST_CASES P3 先行）。完成条件：3 红例先红后绿；gre.json 20/20 全绿（RESULT 全量；二进制同代；门 2 三项绿）；touched 包 `-race` 绿；`gre chain:` 字面零残留（除注释/文档历史叙述）。

#### 9. 关键决策对比

| 决策 | 候选 | 优劣 | 结论 |
|------|------|------|------|
| A 归位 | A1 框架通用；A2 gre 专属抄两遍 | A1 下一条隧道零新增，A2 违背拼积木 | 选 A1（用户裁定） |
| B tag 路径 | B1 ValidateSpec 提 spec.VLAN 走 l2For；B2 vlan 生成器自写 L2 | B2 会被 finalEmit 全量重建覆盖（只保留 GRE），B1 用既有分支零新增装配 | 选 B1 |
| C wrapper 语义 | C1 passthrough 转发；C2 eth 同款 nil 直返 | C2 strand 包→静默空流（eth 恒 chain[0] 非 wrapper 才可直返） | 选 C1 |
| D 触发条件 | D1 tunnel 层且下一层是 ip；D2 p.name=="gre" | D2 即现状；D1 下 tls 链天然豁免（tls 后非 ip） | 选 D1 |
| E 缺席默认 | E1 出现即打（含 id 0）；E2 id 0 忽略 | E1 presence=意图（OptionalOn 已保不写不打） | 选 E1 |
| F eth mac | F1 本轮带出；F2 另立项 | F1 扩范围（无翻译分支要新建） | 选 F2，记明确不解决 |


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


### D-DNS-1 DNS 顶层 dns 子映射迁入层内 + 层动态放开 name/query_type/txid【P-PIPE #4 门1】

**门 1 开工对照表（§1–§15，2026-09-15，证据=文档节/代码行/用例号）：**

| § | 本协议怎么满足 | 证据 |
|---|---|---|
| §1 层链唯一真相 | 顶层旧键五键 dns 现用例零残留（dns.json 仅 `layers`+`dns` 双键）；顶层 `dns` 子映射 14 字段逐键去向见本条目"flat 字段三选一表"；目标形状 `{"layers":[{"ip":{"src","dst"}},{"udp":{"src_port","dst_port"}},{"dns":{"name","query_type","txid",…}}]}`（dns 层字段全集见 §13 行） | dns.json dns_smoke_01；本条目 flat 表 |
| §2 策略/任务分工 | 沿框架语义；多流走 `flow_control` + 层动态（§12 行） | D-DNS-1 §3 |
| §3 五件套 | 豁免：dns 无 sessions、无子流派生、无关联字段；单流=1 查询（up）+ 可选 1 响应（down，`is_response` 开关）；dns 只产报文事件（GenEvents），udp 层每事件一 datagram；时间线=查询先响应后、无交错 | `dns/layer_gen.go:29-89` |
| §4 规范矩阵 | RFC 1035 §4.1/§4.1.1/§4.1.2（报文/头/查询节）+ §4.2.1（UDP 载体）+ §3.2.1（RR）+ §3.4.1/§6（A/AAAA/权威节）；RFC 6891（EDNS0 OPT）；RFC 7766 + RFC 1035 §4.2.2（TCP 载体——明确不支持，链上同步拒）；现网 53/UDP 默认端口；三路对照见本条目依据行 | 本条目依据行 |
| §5 有错必处理 | 三类锚词：①顶层 dns presence 判死（新锚词 `no longer accepts a top-level dns sub-config`，http 族 9 协议先例）；②TCP 载体链上拒（既有 `dns: tcp transport not supported`）；③层未知字段拒（V9 既有）。无 pin | T-DNS-2/3；`dns/layer_gen.go:114` |
| §6 性能 | 单查询 1 包 / 响应 2 包；无锁无 sleep；回归 ±10%；边界诚实声明（未测吞吐/并发） | D-DNS-1 §6 |
| §7 三份文档 | 设计=本条目；用例=T-DNS-*；cases 回指编号 | TEST_CASES T-DNS-* |
| §8 先设计后代码 | 本条目定稿后开工 | 本条目 |
| §9 三源+整格 | RFC 条文 + 本条目 + 现网 53/UDP；测试点清单见本条目 §9 表（规范行→用例逐行登记）；动态整格见 §12 行 | §9 表；§12 表 |
| §10 评审闭环 | failing 先行（顶层 dns presence 拒 + 层 name 生效 + name 动态正例）→ 改 → 审 → 测 → 再审 | §7 |
| §11 白话汇报 | 先一句结论 | 每次汇报 |
| §12 动态清单 | 整格见本条目 §12 表：name 开 string 面（fixed/list/pattern；inc/rand 同 sni 裁定表 F 拒绝）/ query_type 开 int 面（fixed/inc/rand/list；pattern 拒绝，response_status_code 先例）/ txid 开 int 面（同 query_type）/ 其余 11 字段关（is_response 等开关语义 + response_ip 等响应静态 + questions/answers/authority 数组无动态形状 + transport 载体选择非逐流值） | T-DNS-8/9/10；`layer_dyn.go` allowlist |
| §13 schema 同步 | 注册表 dns Fields 扩到 14 键（name/query_type/txid/is_response/response_ip/edns0_enabled/udp_payload_size/dnssec_ok/transport/response_code/ttl/questions/answers/authority——类型/范围/默认见本条目 §13 表）；CheckProtoFlat 加 dns presence 分支；改完重跑 schemagen（生成表 95 层快照同步） | 门 2 脚本 |
| §14 真实流程 | dns.json 全量绿 + 落盘校准；二进制同代；门 2 三项 | T-DNS-* |
| §15 三道门 | 本表即门 1；门 2 脚本；门 3 挂表抽查 | 本条目 |

**状态：** 已验收（2026-09-15，P6）
**完成回填（2026-09-15）：** 步骤0三红例先红后绿（presence判死空map即拒/层14键翻译2包/txid族校验红例自修正IPv6回包）；代码六文件（注册表14键/翻译层优先+直解/判死presence/allowlist双面/静态门业务逃生口/回填三键）；dns.json 1→13例+T-GRE-21 rand+gre_neg_dyn_checksum替补；`RESULT: 13 pass, 0 fail, 0 error (of 13)` + `RESULT: 21 pass, 0 fail, 0 error (of 21)`（/tmp/tg-dns-p1-server与HEAD同代，门2静态两项双绿）；落盘校准：txid笔误0x03ea→0x03e9回钉、qtype distinct 1/28、name distinct双域名、rcode锚词V9口径`out of range [0,15]`；`go test ./internal/...` 123包全绿（tls单例抖动一次，复跑3连绿，全量终绿）+ touched -race绿；在库dns/gre清空（删前tasks 21+28/strategies 8+14 → 删后0/0）。
**门3抽查三条：** ①§1顶层迁入→dns.json零顶层dns键（门2-1绿，黄项dns_neg_flat系执法对象豁免）；②§5 presence→`strategy_convert.go` CheckProtoFlat dns分支（http族文案同构），T-DNS-2真实流程拒；③§12 name动态→T-DNS-8双流distinct + T-GRE-20作废改判（dns.name合法化证据）。
**P5落地偏差（如实登记）：** ①静态门误杀纯业务动态多流——`checkLayerChainStaticCopy`只认四元组对象，dns三动态例全军拒；修为业务层对象逃生口（http/tls既有动态例同益，回归全绿）；②T-GRE-20作废：D-DNS-1后dns.name动态合法，原"隧道内dns动态拒绝"依据消亡，例替换为checksum版（T-GRE-22），编号保留作废注记；③gre_6in4/4in6 notes旧地址残留两处已订正（fd01::1/192.168.1.1）；④GRE遗留死代码`_ = raw`三处顺手清（备注①关闭）；⑤注释`gre chain:`残留系历史叙述（"前缀A→B"说明句），非功能字面，保留。
**范围（2026-09-15）：**
**范围（2026-09-15）：** ①注册表 dns Fields 2→14 键；②translateTerminalConfig dns 分支改层优先（现 flat 优先 `if spec.DNS != nil return` 改为：顶层 dns 出现即判死后，层 config 全量翻译）；③CheckProtoFlat 加 dns presence 判死；④`layer_dyn.go` allowlist 加 `dns: name/query_type/txid` + checkDynShape 面（name 走 tls-sni 同款 string 面；query_type/txid 走 http-response_status_code 同款 int 面）；⑤dns.json 改写 + 新增 T-DNS-2…10 全量跑；⑥GRE 顺手项：gre.json 补 rand 正例 1 例（备注②缺口关闭）。
**明确不解决：** DNS-over-TCP 链化（TCPGenerator 全握手 vs legacy 无握手 PSH+ACK 语义分叉，另立项；链上同步拒保留）；DNS-over-TLS（doh 协议另有条目）；questions/answers/authority 数组动态（无动态形状）；gre 隧道内 dns 层动态（T-GRE-20 已锁关——隧道内层静态，内外有别不冲突：直连 dns 链开动态，gre 隧道内层 dns 关动态）。
**依据：** RFC 1035 §4.1（报文格式）/§4.1.1（头：ID/QR/RD/QDCOUNT）/§4.1.2（查询节 QDCOUNT 可 >1；RR 节）/§4.2.1（UDP 载体）/§4.2.2（TCP 载体——不支持依据）/§3.2.1（RR）/§3.4.1（A RDATA）/§6.2.5（NXDOMAIN 权威节）；RFC 6891（EDNS0 OPT）；RFC 7766（TCP 载体）；RFC 3596 §2.2（AAAA）；RFC 4033（DO 位）；现网行为（53/UDP 默认，strategy_convert 默认化）；开源对照（借报文结构思路，不搬实现）。代码事实：`dns/layer_gen.go:29-89`（事件产出；transport tcp 拒 `:35,:113-115`）；`dns.go:86` validateDNSConfig（transport 枚举/rcode≤15/域名必填/RR 族校验）；`types.go:2220` DNSConfig 14 字段；`chain_planner_translate.go` dns 翻译分支（flat 优先）；`strategy_convert.go:401` flat dns 14 键解析；registry dns 2 键（`:130-138`）。

**flat 字段三选一表（§1 逐键去向，共 14 键）：**

| flat `dns` 字段 | 去向 |
|---|---|
| domain | dns 层 `name`（字段名对齐层 schema；翻译分支改名） |
| query_type | dns 层 `query_type`（已在层内） |
| txid | dns 层 `txid`（新增，uint16，默认 0=0x1234 回退沿 legacy） |
| is_response/response | dns 层 `is_response`（新增，bool，默认 false） |
| response_ip | dns 层 `response_ip`（新增，string，默认空） |
| edns0_enabled | dns 层 `edns0_enabled`（新增，bool） |
| udp_payload_size | dns 层 `udp_payload_size`（新增，uint16，默认 4096 沿 flat `getIntDefault`） |
| dnssec_ok | dns 层 `dnssec_ok`（新增，bool） |
| transport | dns 层 `transport`（新增，string，默认 ""=udp；tcp 值链上同步拒沿既有） |
| rcode | dns 层 `response_code`（新增，uint8，`response_` 前缀防与传输层混淆；http response_status_code 先例） |
| ttl | dns 层 `ttl`（新增，uint32，默认 0=300 沿生成器） |
| questions | dns 层 `questions`（新增，object 数组；动态关） |
| answers | dns 层 `answers`（新增，object 数组；动态关） |
| authority | dns 层 `authority`（新增，object 数组；动态关） |

**§9 测试点清单（规范行→用例）：**

| 规范行 | 用例 |
|---|---|
| RFC 1035 §4.1.1 头（ID/QR/RD/QDCOUNT=1，默认 txid 0x1234） | T-DNS-1（既有 dns_smoke_01 改写，层链形） |
| 顶层 dns presence 判死 | T-DNS-2（负例，新锚词） |
| 静态复制拒绝（flows=2 全静态） | T-DNS-3（负例，`static four-tuple`） |
| query_type AAAA（28） | T-DNS-4（正例，`dns.qry.type=28`） |
| is_response 响应包（down，TXID 回显） | T-DNS-5（正例，2 包 + 响应 txid=查询 txid） |
| rcode NXDOMAIN（3）+ authority SOA | T-DNS-6（正例，现网负缓存场景） |
| EDNS0 OPT（ARCOUNT=1） | T-DNS-7（正例，`edns0_enabled:true`） |
| name list 动态（双流不同域名） | T-DNS-8（正例，distinct 双域名） |
| query_type inc 动态（1→28 双流） | T-DNS-9（正例，distinct 双类型） |
| txid inc 动态（双流不同 txid） | T-DNS-10（正例，distinct 双 txid） |
| transport=tcp 链上拒 | T-DNS-11（负例，既有锚词） |
| rcode>15 拒绝 | T-DNS-12（负例，`exceeds the 4-bit field`） |
| 空域名拒绝 | T-DNS-13（负例，`query_name (domain) is required`） |
| GRE 顺手 rand | T-GRE-21（gre.json，外层 ip.src rand 双流，备注②关闭） |

#### 1. 数据与接口
- 输入：`[ip, udp, dns{14 键}]`（dns 层缺席键走 schema 默认；`name` 默认 example.com 沿既有）。
- 输出：查询 1 包（up）+ 响应可选 1 包（down）；响应 TXID 回显查询值（RFC 1035 §4.1.1 MUST）。
- 修改点五处（builder/drive/finalEmit 零改动）：`registry.go` dns Fields 2→14；`chain_planner_translate.go` dns 翻译分支（flat 优先→层优先 + 14 键全量）；`strategy_convert.go` CheckProtoFlat dns presence 分支；`layer_dyn.go` allowlist + 双面形状；`dns/layer_gen.go` 零改动（读 spec.DNS 不变——翻译层已把层值灌进 spec）。新增函数：无。
- 显式覆盖：层值是 dns 全配置唯一真相；flat `cfg["dns"]` 出现即判死（presence，空 map 也死，http 族先例）。

#### 2. 依赖与生命周期
- 前置：udp 层（DependsOn 沿既有；tcp 显式覆盖走 TransportOn 沿既有，但 transport=tcp 值仍同步拒——载体 tcp ≠ 值 tcp，前者是层链形状，后者是 dns 报文封装选项）。
- 资源：无状态生成器；翻译在 ValidateSpec 同步期（幂等覆盖写）。

#### 3. 主流程与状态
- 翻译顺序：判死（顶层 dns 出现即拒）→ 层 config 全量翻译 → 协议 validator（transport/rcodes/域名/RR 族沿既有）。现 `flat 优先 return` 删除——flat 已死，无双轨。
- 动态解析：worker resolveLayerTuple 沿框架（name 走 string 面 list/pattern；query_type/txid 走 int 面 inc/rand/list；inc/rand 在 name 上同 sni 拒绝）。

#### 4. 递增与覆盖规则 + 正交组合矩阵 + 业务动态清单
- 无新序号算法（框架 resolveLayerTuple；TxID 回显是报文规则非序号算法）。
- 动态整格（§12）：

  | 层.字段 | 开/关 | 面 | 覆盖 |
  |---|---|---|---|
  | dns.name | 开 | string 面（fixed/list/pattern；inc/rand 拒） | T-DNS-8 |
  | dns.query_type | 开 | int 面（fixed/inc/rand/list；pattern 拒） | T-DNS-9 |
  | dns.txid | 开 | int 面（同 query_type） | T-DNS-10 |
  | dns.is_response/response_ip/edns0/transport/response_code/ttl | 关 | 开关/静态/载体选择 | 注记（开关语义逐流变无意义；transport 非逐流值） |
  | dns.questions/answers/authority | 关 | 数组无动态形状 | 注记 |
  | ip/udp 四元组 | 开 | 框架白名单沿既有 | T-DNS-8/9/10 附带（flows=2 双流四元组 distinct 由框架保底 `src_port+1`，不断言） |
- 正交组合：query_type × name 不单建组合例（两字段独立翻译，dyn 路径同一 parseLayerDyn；T-DNS-9 以 AAAA 域名附带覆盖）。

#### 5. 错误与异常
- 新锚词：`protocol dns no longer accepts a top-level dns sub-config (move it into the dns layer of an [ip,udp,dns] layers chain)`（http 族文案同构）。
- 既有锚词沿用：`dns: tcp transport not supported…`（T-DNS-11）；`dns rcode %d exceeds the 4-bit field`（T-DNS-12）；`dns query_name (domain) is required`（T-DNS-13）；`static four-tuple`（T-DNS-3）。
- Failing 先行 3 红例：①顶层 `{"dns":{}}` 空映射 BuildLayersPlanner/Validate 即拒（现状放行——presence 未判死）；②层 `{"dns":{"name":"a.com"}}` 翻译后 spec.DNS.Domain=a.com（现状：name 键未知字段 V9 拒绝——注册表仅 2 键）；③层 name list 动态双流 distinct（现状：allowlist 无 dns 行即 `does not support dynamic`）。

#### 6. 性能设计与验收
- 单包路径增量：翻译多 12 键取值（ValidateSpec 同步期一次）；动态解析走框架（零新增）。回归口径：dns.json 全量 suite 耗时相对基线 ±10%；边界诚实声明：无吞吐/并发/内存目标数字（未测）。
- pcap 验收：dns.json 全量绿 + 落盘可复查（`dns.qry.name/type` + 响应 txid 回显 + distinct 双值）；网卡未跑。

#### 7. 实现顺序与回滚
- 步骤 0（failing 先行）：`internal/core/layers/dns_migrate_test.go` 3 红例（BuildLayersPlanner 全链口径）。
- 步骤 1：注册表 dns Fields 2→14；步骤 2：翻译分支层优先 + 14 键；步骤 3：CheckProtoFlat dns presence；步骤 4：allowlist + 双面形状；步骤 5：`go build` + vet + touched 包 `-race` + schemagen 重跑；P5：dns.json 改写 + T-DNS-2…13 + gre.json T-GRE-21，全量跑 + 校准回钉；P6：评审+提交+清库复核。
- 回滚：单提交逆序 revert。

#### 8. 验收
- 对应 T-DNS-1…13 + T-GRE-21（TEST_CASES P3 先行）。完成条件：3 红例先红后绿；dns.json 全量绿 + gre.json 全量绿（RESULT 全量；二进制同代；门 2 三项绿）；touched 包 `-race` 绿；顶层 `dns` 字面零残留（cases 内；除注释/文档历史叙述）；schemagen 生成表已同步（`TestLayersGeneratedMatchesRegistry` 绿）。

#### 9. 关键决策对比

| 决策 | 候选 | 优劣 | 结论 |
|------|------|------|------|
| A 开工表范围 | A1 全字段表重做（14 键去向+清单）；A2 只搬域名 | A2 留 12 键无去向违反 §1 留白禁令 | 选 A1（用户裁定） |
| B name/query_type/txid 动态 | B1 三开（name string 面 + 双 int 面）；B2 全关 | B2 无依据（规范/代码均支持逐流变） | 选 B1 |
| C rcode 住处 | C1 层 `response_code`（`response_` 前缀）；C2 层 `rcode`（flat 原名） | C2 短但与传输层 RCODE 概念易混；C1 http response_status_code 先例 | 选 C1 |
| D 翻译语义 | D1 层优先（flat 判死后无双轨）；D2 flat 优先保留 | D2 留双轨违反 §1 唯一真相 | 选 D1 |
| E presence 口径 | E1 空 map 也判死；E2 仅非空判死 | E1 http 族先例（空即显式走默认）；E2 留空壳双轨 | 选 E1 |
| F 其余 11 字段动态 | F1 全关+理由；F2 全开 | F2 开关/数组无动态形状，开了测不出 | 选 F1 |

## 5. 设计评审闸门

#### D-DNS-1 补遗 T-DNS-14/15（单包多问多答，2026-09-15，§3 新规矩首落点）

- 范围：零代码改动（A 类用例）。`questions`/`answers` 字段翻译已在 D-DNS-1 落地（`chain_planner_translate.go` dns 分支 Questions/Answers 段）；构造器多问路径（`dns/layer_gen.go:48` `len(Questions)>0`→`buildDNSMessage`）与多 RR 路径（`:83` Answers 非空→`buildDNSResponseGeneral`）已就绪——本补遗只建例 + 落盘校准。
- T-DNS-14：`dns{questions:[{name:a.com,type:1},{name:b.com,type:28}]}` 单查询包 QDCOUNT=2（RFC 1035 §4.1.2 QDCOUNT 可 >1）。
- T-DNS-15：`dns{is_response:true,answers:[{A 1.2.3.4},{A 5.6.7.8}]}` 响应包 ANCOUNT=2（RFC 1035 §4.1.2 多 RR；单 RR 路径由 T-DNS-5 覆盖）。
- 验收：dns.json 13→15 例全量绿（RESULT 全量；二进制同代；门 2 三项绿）。

#### D-DNS-1 补遗 T-DNS-16/17/18/19（CNAME 链/域名长度门/重传/v6，2026-09-15，§3/§9 三场景收口）

- T-DNS-16（A 类，零代码）：`answers:[{CNAME→alias},{A 1.2.3.4}]` 响应 ANCOUNT=2，现网 CDN 别名链形状；CNAME 编码路径（`dns.go:482` TypeCNAME→`encodeDomainName(Target)`）+ 通用多 RR 响应路径已就绪。
- T-DNS-17（B 类，需 validator 改动）：超长域名提交期拒绝。根因：`encodeDomainName` 按 `byte(len)` 写长度，超长 label 静默回绕（如 300 字符→长度字节 0x2C）产出畸形 QNAME；旧 validator 只查空名/RR 族，无长度门。改动：`validateDNSConfig` 加长度门（全名>253 拒 §2.3.4；单 label>63 拒 §3.1；检查面=Domain+Questions 名+Answers/Authority 的 Name/Target/MName/RName），失败先行单测 `TestValidateDNSConfig_LongDomainRejected`（dns_fix_test.go F4：64 拒/253+拒/超长 CNAME target 拒/63 放）。
- T-DNS-18（A 类，零代码）：固定 `txid:1001` + `is_response` 双包同 `dns.id=0x03e9`（UDP 丢包重传同 TxID 语义；TxID 回显 MUST 由 T-DNS-5 覆盖，本例钉"重传不变"）。
- T-DNS-19（A 类，零代码）：v6 地址查询，`ipv6.version=6`（UDP 无握手首包即断言；TCP 系 v6 例首包恒为握手需包 4 起，见 doh/coap 先例——UDP 单包直断是正确口径）。
- 缺口诚实登记：①离线套件（`layer_chain_suite_test.go:runChainCase`）`MapToFlowSpec` 只提显式 flat/scalars，v6 地址在离线路径恒回退 v4——T-DNS-19 离线红、MCP 绿，以 MCP 为准（§14 真实流程）；②同文件两枚历史负例（`dns_neg_flat` 顶层 presence、`dns_neg_static_copy` 静态复制）在离线路径同样失守（MCP 层 400/拒绝门离线未复刻），属 harness 表达力边界（C 类），不冒充。
- 验收：dns.json 15→19 例 MCP 全量绿（RESULT 19/19；二进制已重编同代；门 2 静态两项绿）。

#### D-DNS-1 补遗 T-DNS-20..25（六类 RR 问答配对，2026-09-16，用户指漏补齐）

- 范围：零代码改动（A 类用例）。六类 RR 编码路径（AAAA/MX/TXT/NS/PTR/SRV）与问答配对断言面（`qry.name/qry.type` + `resp.type` + RDATA）均已就绪——本补遗只建例 + 落盘校准。
- T-DNS-20：AAAA 问答（`query_type:28` + `response_ip:2001:db8::1`，v4 承载问 v6 答；v6 承载由 T-DNS-19 覆盖）。
- T-DNS-21：MX 问答（preference=10 + exchange=mail.example.com）。
- T-DNS-22：TXT 问答（text=hello-world）。
- T-DNS-23：NS 问答（ns1.example.com，授权链形状）。
- T-DNS-24：PTR 反向（in-addr.arpa 问答）。
- T-DNS-25：SRV 问答（port=5060 + target=sip.example.com）。口径注记：不断言 `dns.srv.name`——tshark 对该字段取报文压缩指针末段（恒 `example.com`），线序全名已逐字节核对正确；配对由 `qry.name` + `resp.type` + RDATA 承担。
- 验收：dns.json 19→25 例 MCP 全量绿（RESULT 25/25；无代码改动二进制同代；门 2 静态两项绿）。

#### D-DNS-1 补遗 T-DNS-26..29（v6 问答配对 + DNSSEC/NAPTR，2026-09-16，用户指漏补齐之二）

- 范围：零代码改动（A 类用例）。v6 承载 AAAA 回答、DS/DNSKEY/NAPTR 编码路径均已就绪——本补遗只建例 + 落盘校准。
- T-DNS-26：v6 承载 × AAAA 回答（T-DNS-19 只问不答、T-DNS-20 只 v4 承载，矩阵缺的格）。
- T-DNS-27：DS 问答（key_id=0x3039 + algorithm=8 + digest；tshark 名 `key_id` 非配置键 `key_tag`）。
- T-DNS-28：DNSKEY 问答（不断 flags——tshark 十六进制 `0x0100`，改断 protocol=3）。
- T-DNS-29：NAPTR 问答（order=100 + preference=50 + service=sip+E2U）。
- 验收：dns.json 25→29 例 MCP 全量绿（RESULT 29/29；无代码改动二进制同代；门 2 静态两项绿）。

### D-MQTT-1 MQTT 顶层 mqtt 子映射迁入层内 + 层动态放开 client_id/topic/payload【P-PIPE #5 门1】

**门 1 开工对照表（§1–§14，2026-09-16，证据=文档节/代码行/用例号）：**

| § | 本协议怎么满足 | 证据 |
|---|---|---|
| §1 层链唯一真相 | 顶层旧键清单：`src_ip`→`layers[ip].src`、`dst_ip`→`layers[ip].dst`、`src_port`→`layers[tcp].src_port`、`dst_port`→`layers[tcp].dst_port`、`count`→删（走 `strategy_fc`）、顶层 `mqtt` 子映射→`layers[mqtt]`（全字段同名直迁，parseMQTTConfig 与层翻译同表）、顶层 `tcp` 子映射（mss/initial_seq/rst 7 例）→`layers[tcp]` 同名键、`group_id`（1 例）→见 §3 行。目标形状例：`{"layers":[{"ip":{"src":"10.0.0.1","dst":"20.0.0.1"}},{"tcp":{"src_port":13000,"dst_port":8883}},{"tls":{}},{"mqtt":{"client_id":"tls-client-1","keep_alive":60,"clean_session":true}}]}`（mqtt_over_tls 迁后形；mqtt 层 DependsOn tcp，tls 经 OptionalOn 显式启用）。零残留：71 纯 `{"mqtt"}` + 2 `{"mqtt","tcp"}` + 1 `mqtt_over_tls` 扁平四键 + 1 `group_id` 顶层键 | mqtt.json 169 例审计；`strategy_convert.go:1047`（mqtt flat 读）/`359`（universal tcp 读）；本条目 §1 |
| §2 策略/任务分工 | 沿框架语义；多流走 `flow_control` flows=N + §12 动态对象（D-DNS-1 同款）；`sessions[]` 多会话是 legacy 批量形状，链上按"一流一会话"逐条拆例（见 §3 行），不用 strategy_fc 复制充数 | 本条目 §3/§12 |
| §3 五件套 | 会话表：单会话=一 TCP 连接上一 client_id 的 CONNECT→CONNACK→[SUBSCRIBE/SUBACK]→[PUBLISH/ack]→[PING]→[DISCONNECT]（`mqtt/layer_gen.go:1-16` 顺序）；事务序列=包序列即事务（无跨包引用字段，会话内顺序发射）；关联关系：无（MQTT 数据面就在同一 TCP 流内，无独立子流——设计 doc 1.3 节明说，与 SIP/RTSP 对照）。"链上一流一会话"不是 RFC 规定，是本链架构约束：RFC 只说一连接一 ClientId，会话状态归属连接（OASIS §4.1）；legacy 用 sessions[] 一次扇出 N 流是批量便利形状，链 planner 一 task 一 flow 无扇出物，故 sessions 非空链上拒（`layer_gen.go:233` validator + `80` 生成器双保险，锚词 `one flow per chain`）；插入位置：终结层事件流直入 tcp 层（事件模式，tcp 管握手/分段）；时间线：单流顺序，无交错。17 sessions 例→逐条拆单会话层链例（同 client_id/messages/subscriptions/will；`mergeSession` 继承语义 `mqtt.go:917`：标量零值继承、slice 非 nil 替换——拆例时把继承后有效值写全，不依赖继承）；mqtt_t149 group_id 跨流同 worker 保序→任务级多策略/多流另立项（P-PIPE 外，batch group_id 语义，D-MQTT-1 不迁该例，注记保留）；mqtt_over_tls 的 TLS 底座=mqtts 组合层（tls 层已注册 OptionalOn，迁后 `[ip,tcp,tls,mqtt]`） | `layer_gen.go:1-16`；`mqtt.go:917` mergeSession；mqtt.json S10/T-149；本条目 §1 目标形状 |
| §4 规范矩阵 | OASIS MQTT 3.1.1（2014，等价 ISO/IEC 20922:2016）+ 5.0（2018，RFC 9560 信息参考）：①连接模型=TCP 长连接，一条 TCP 连接一会话（CONNECT ClientId §3.1，会话状态 §4.1），并发=N 条独立连接（设计 doc §1.2 多客户端并发）；②消息表=CONNECT/CONNACK/PUBLISH+QoS ack 链/SUBSCRIBE/SUBACK/PING/DISCONNECT（§2.2 码表；AUTH/UNSUBSCRIBE 本期不实现 §1.4——代码无 builder，只有 Type 常量 `mqtt.go:45-46`，属"明确不支持"非缺口）；③状态机=单会话主状态机 + QoS 子状态机 + will/keepalive（§4.1–4.5）；④字段表=MQTTConfig 全字段（`types.go:9631`）+ 5.0 Properties（§2.14/§8.4/§8.5）；⑤错误处理=CONNACK 拒绝码/版本门/QoS 门/主题别名门（mqtt.go Validate 全函数，57 负例已覆但 19 条分支无锚词，见 §5 行）；⑥超时与活性=keepalive PING + will delay + session expiry（§4.4/§4.5，S7/S15）；⑦NAT/代理=无（单 TCP 流，无被动模式）；⑧版本方言=3.1.1(4) 默认 vs 5.0(5)（version 门 `mqtt.go:96`）。三路对照缺口：规范底线=OASIS 原文有；现网准绳=mosquitto/emqx 抓包对照无实测（设计 doc §末只有建议句，无 pcap 证据，P5 必须补或如实注记）；开源借鉴=paho 行为无引用（待补）。候选对比：A 逐例迁入层（选：169 例多但机械）/ B 重写精简集（否：存量 57 负例是 Validate 全覆盖证据，丢不得） | 设计 doc `14-mqtt-design.md`（§1–§8，历史参考）；`mqtt.go:76` Validate；mqtt.json 169 例 |
| §5 有错必处理 | 依赖：mqtt 层 DependsOn tcp（缺 tcp 自动补，tcp DependsOn ip 连带补全）；validator 调 `(&Planner{}).Validate` + pin 握手/挥手（`layer_gen.go:236`，http/tls 范式）；sessions 非空链上拒（validator + 生成器双保险，锚词 `one flow per chain`）；flat 判死后无双轨（CheckProtoFlat 加 mqtt presence 門，见 §1）。出错：57 负例锚词harness口径（`strings.Contains(msg, ec)`）逐条命中已验；19 条 validator 分支无用例 ec 命中（2026-09-16 实审）：DUP-QoS0 门/非法方向门/IP 格式门×2/config nil 门×2/空配置门/无效属性 id 门/未知属性格式门/属性 string U+0000 门/属性 surrogate 门/属性 stringpair 分隔符门/属性 vbi 越界门×2/UTF-8 禁码点门/session 包裹错×3/session 端口撞 dst 门/session SUBACK 码门/自动源端口下限门——P4 每条补负例（锚词取消息字面子串），补不上的按三分类注记；RST/mss/initial_seq 走 tcp 层校验（既有）；驱动失败空流契约沿链（生成器 sessions 检查双保险已在注释写明） | `layer_gen.go:233-266`；`strategy_convert.go:7593` CheckProtoFlat；mqtt.json 57 负例 + 19 补例（P4） |
| §6 性能 | 单会话包数=3 握手+MQTT 帧+4 挥手（链 4 包挥手，legacy 3 包是文档化分歧 `layer_gen.go:19`）；多消息/多订阅线性增帧；sessions 拆例后无 N 流同任务放大；回归口径 suite ±10%；边界诚实声明（未测吞吐/并发） | `layer_gen.go:19` 分歧注记；mqtt.json S1 10 包/S2 11 包/S5 12 包 |
| §7 三份文档 | 设计=本条目；用例=T-MQTT-1…（P3 先行，存量 169 例逐条审计去向）；cases 回指编号 | TEST_CASES T-MQTT 起 |
| §8 先设计后代码 | 本条目定稿后开工 | 本条目 |
| §9 三源+整格 | 三源：OASIS 条文 + 本条目 + mosquitto/emqx 现网抓包（缺口，P5 补或注记）；颗粒度：169 例已拆到单行为点，迁入只换形状；三场景审计（2026-09-16 实数）：数据=57 负例（19 条分支无命中，见 §5 行）；业务=包序列 S1/S2/S3/S4/S5/S7/S9/S12/S13/S14/S15 全有正例 + S10/S11 多会话拆例（S6 UNSUBSCRIBE/S8 将在 §4 行明确不支持，不列缺口）；现网=薄弱——mqtts 只有 1 例（mqtt_over_tls）/ will 13 正例有但全是正常发布不断线对 / retain 8 例 / down 方向 3 例 / 认证 3 正例（s13/t088/t065）/ keepalive=0 2 例 / connack_properties 3 例 / no_local 等订阅选项各 1 例——P5 补现网常用形：异常断线 will 发布包序例、retain 新订阅即收例、down 转发例、长连接 PING 保活例（不断言包序只断字段，按断言边界注记）；枚举：QoS 0/1/2、CONNACK 码、版本 4/5、Properties 白名单（存量已覆，迁入审计不丢）；正交矩阵：版本×QoS×will/retain×地址族（v6 零例→缺口立项，新增 T-MQTT-v6）；断言边界：包序/方向沿 verify harness 注明（group_id t149 的保序断言 harness 做不到跨流，注记） | §12 整格表；P3 清单 |
| §10 评审闭环 | failing 先行（presence 判死红例 + sessions 链上拒红例 + 动态形状红例）→ 改 → 审 → 测 → 再审 | 本条目 §7 步骤 |
| §11 白话汇报 | 先一句结论 | 每次汇报 |
| §12 动态清单 | 开：`client_id`（string 面，/topic 同款逐流变）/`topic`（string 面，messages[].topic 逐流变）/`payload`（string 面，负载逐流变）——三字段 fixed/list/pattern（pattern `{n}` 模板，topic 最典型）+ inc/rand 关（域名/文本无意义，dns.name 先例）；`src_port/dst_port`（四元组整格，tcp 层已有）；关：`version`（常量协商）/`keep_alive`（数值开关语义）/`clean_session`（开关）/`username/password`（认证枚举语义，逐流变=不同测试点）/`will`（对象块，随 client_id 走）/`connect_ack_code`（枚举分支）/`subscriptions/messages`（数组块，随 topic 走）/`properties/connack_properties`（5.0 白名单块）/`sessions`（链上拒，动态无意义）/`disconnect/disconnect_reason`（开关/枚举）。序号算法：`resolveLayerTuple` + `ResolveStringValue`（`tuple_generator.go:306`，与 dns.name 同面） | `layer_dyn.go:17` allowlist；`tuple_generator.go:286-315`；T-MQTT 动态例 |
| §13 schema 同步 | 注册表 mqtt 层 17 键已登记（generated layers.generated.json mqtt 节）；改动：无字段增删（只迁形状）→ schemagen 不跑；strategy.json 无 mqtt 扁平（mqtt 只活在 config 子映射 + layers 层，CheckProtoFlat 管 presence） | generated `layers.mqtt` 节 |
| §14 真实流程 | mqtt.json 全量 169/169 + 落盘校准（frames hex/包数重钉——链 4 包挥手 vs legacy 3 包，包数差逐例校准）；二进制同代；门 2 三项 | mqtt.json |

**状态：** P5 已验收（2026-09-16；门 1 已批→P4 `db23bb6`→P5 MCP 203/203 全绿；门 3 抽查见本条目末）
**范围（P4，已执行）：** ①`CheckProtoFlat` 加 mqtt presence 门（`strategy_convert.go:7631`；`mapToFlowSpec` 在库旧行→ValidationErrors `strategy_convert.go:320`）；②`translateTerminalConfig` mqtt 分支层优先 + 空壳例外（http `:839` 同款，`chain_planner_translate.go:1143`）+ `translateMQTTDyn`（`:1266`，client_id 直解 + messages[] 逐槽下钻）；③`layer_dyn.go` allowlist mqtt 行（`:41`，顶行只登记 client_id，topic/payload 槽位键走三处下钻）+ string 面形状门（`:334`）+ `LayerMQTTDyn`（`types.go:3586`）+ parse 下钻（`layer_dyn.go:197/209`）+ resolve 回填（`:863`，直调口径；链引擎以 translateMQTTDyn 为真相）+ `stripMQTTMessagesDyn`（`validate_layers.go:208`，create 期 400 剥离）；④mqtt.json 169→203（双轨 94 合层补 ip；71 纯扁平 + 2 mqtt+tcp 补 `[ip,tcp,mqtt]`；mqtt_over_tls 四键迁层 `[ip,tcp,tls,mqtt]`；t149 转 presence 负例；sessions 17 例拆 38 单流，继承值写全）；⑤MCP 全量 203/203 + 门 2 + 清库（清库 P6 待执行）。
**明确不解决：** sessions 链上多流展开（validator+生成器双拒，锚词 `one flow per chain`，17 例拆单流 + `mqtt_neg_sessions_rejected` 锁锚词；group_id 跨流保序另立任务级项，t149 转负例注记）；RST 开关语义漂移（legacy 单 RST vs 链 FIN 4 包，t168 6→9、t169 8→11 按链校准，文档化分歧沿 `layer_gen.go:22`）；WebSocket/MQTT-SN/AUTH 包（设计 doc §1.4 不实现范围）；任务级跨策略动态池（D-FTP-2 同口径另立）；v6 `ipv6.version` tshark 字段名待查（mqtt_v6_connect 降级为 clientid 钉 + 偏移注记）。
**依据：** OASIS MQTT 3.1.1/5.0（设计 doc `14-mqtt-design.md` §1–§8 为历史参考，不作新权威）；`mqtt/layer_gen.go:233-266`（validator+生成器双拒+sessions 门）；`strategy_convert.go:1047/4524`（flat 读+parse）；`types.go:9631`（MQTTConfig 全字段）；`tuple_generator.go:306`（string 面算法）。

**门 3 抽查三条（2026-09-16）：** ①§1 顶层迁入→mqtt.json 202 例 `layers` 形零残留（门 2-1 内联 GREEN；t149 转负例是执法对象）；②§5 presence→`strategy_convert.go:7631` CheckProtoFlat mqtt 分支，mqtt_t149 真实流程拒（RESULT 203/203 含该负例 PASS）；③§12 client_id 动态→mqtt_dyn_client_id_list（flows=2，mqtt.clientid distinct 全绿）。

### D-SMTP-1 SMTP 顶层 smtp 子映射迁入层内【P-PIPE #6 门1】

**门 1 开工对照表（§1–§14，2026-09-16，证据=文档节/代码行/用例号）：**

| § | 本协议怎么满足 | 证据 |
|---|---|---|
| §1 层链唯一真相 | 顶层旧键清单：`src_ip`→`layers[ip].src`、`dst_ip`→`layers[ip].dst`、`src_port`→`layers[tcp].src_port`、`dst_port`→`layers[tcp].dst_port`（25 由 `FieldContract tcp.dst_port=25` 补，用户写 587/465 优先）、`count`→删（本例 `count:1` 缺省单流）、顶层 `smtp` 子映射→`layers[smtp]`（banner/email/dialog 同名直迁）。目标形状：`{"layers":[{"ip":{"src":"10.0.0.1","dst":"20.0.0.1"}},{"tcp":{"src_port":12345,"dst_port":25}},{"smtp":{}}]}`（空 smtp 走默认 banner+默认 Dialog）。P4 必修 4 项：①`translateTerminalConfig` 加 `case "smtp"`（全文 grep 零命中，层配置今天被忽略）；②CheckProtoFlat 加 smtp presence 门（mqtt `:7633`/dns `:7626` 同款文案）；③扁平侧补 `setDefaultDstPort(25)` 一行（xmpp/sip 同款，行为对齐非注释问题）；④删 registry 孤儿 `from/to`（见 §5 行）+ 重跑 schemagen | smtp.json 1 例；`registry.go:811`；`strategy_convert.go:870`；本条目 §1/§7 |
| §2 策略/任务分工 | 沿框架语义；`flows=N` 同模板复制；`src_port` 保 0 不默认化走 `12345+i`（chain_planner.go:653 与 legacy planner.go:215 同款） | 本条目 §3/§4 |
| §3 五件套 | 会话表：单 TCP 连接单会话，无 `sessions[]`（RFC 5321 长连接客户端主动建连，豁免多会话扇出）。事务序列：banner(220,down)→HELO/EHLO→MAIL→RCPT(可多)→DATA→354→body→250→QUIT→221，Dialog 逐条按序产事件（空 Cmd/Response 跳过，纯单向轮次）。关联关系：无（SMTP 无控制/数据双流，FTP PASV 类比不适用）。插入位置：终结层事件流直入 tcp 层（事件模式，tcp 管握手/seq-ack/挥手/MSS 分段）；Email 声明式在 DATA/354 后插 body+250。时间线：单流顺序无交错；多流=整会话复制 | `smtp/layer_gen.go:53-126`；`planner.go:117-340` |
| §4 规范矩阵 | RFC 5321（连接/命令/状态机/字段/错误；章节号凡非代码注释亲验的一律转引待亲验，见本条目依据行注记）+ 5322/2045/2046/2183（MIME）+ 879（MSS≥536）+ 6528（随机 ISN）+ 4954（AUTH）/3207（STARTTLS，台词覆盖，真升级另立项）。三路对照：规范底线✓；商业准绳=Postfix 默认 banner `$myhostname ESMTP $mail_name`（postconf.5 smtpd_banner）/ Gmail 587+STARTTLS 或 465、未 STARTTLS 先 AUTH 回 530 / Exchange 接收连接器 banner 须 220 开头（微软文档）；开源借鉴=Postfix 文档行为 + 本仓 legacy 回放基线（85 单测，不搬代码）。候选对比见本条目 §9 | P1 矩阵（会话记录）；`types.go:7225` |
| §5 有错必处理 | 依赖：smtp 层 DependsOn tcp / OptionalOn tls（registry.go:811）；配置经 Meta 直传终结层生成器（chain_planner_translate.go:172）；validator 调 `(&Planner{}).Validate`（layer_gen.go:153）。validator 真拦 4 类：坏 IP、MSS<536、boundary 超长/含 CRLF、附件无数据（planner.go:84-110，mime.go:332）；端口不强制 25（587/465 放行）。孤儿裁定：registry `smtp.from/to` 在 `SMTPConfig` 无对应字段、全仓无消费者（strategy_convert.go:3284 的 From 是 xmpp 的），P4 删除——FTP/POP3 的 banner 有真实消费不可类比 | `planner.go:84`；`registry.go:816`；本条目 §9 |
| §6 性能 | 单会话包数=3 握手+Dialog 帧+banner+4 挥手（链 4 包挥手，legacy 4 包同形，layer_gen.go:20-24 文档化分歧仅握手选项细节）；Email 附件线性增帧；回归口径 suite ±10%；边界诚实声明（未测吞吐/并发） | 本条目 §6 |
| §7 三份文档 | 设计=本条目；用例=T-SMTP-*（P3 先行，存量 1 例改写去向见 §9 前表）；cases 回指编号 | TEST_CASES T-SMTP（P3 建） |
| §8 先设计后代码 | 本条目定稿后开工 | 本条目 |
| §9 三源+整格 | 三源：RFC 条文 + 本条目 + 商业三家行为（上表）；颗粒度：legacy 85 单测已拆到单行为点，pcap 层仅 1 冒烟→P3 清单先行（初估 18–24 例）；三场景：数据=validator 4 类负例；业务=信封序列/EHLO 多行/多 RCPT/RSET/NOOP/VRFY/QUIT 中断/Email 三形态+附件；现网=Postfix 形 banner/EHLO 能力表/Gmail 587 口径/Exchange 220 开头（缺口，P3 补）；枚举：命令表逐条（EXPN/TURN 真缺，HELP/VRFY 已有——复审 R4 纠正）；正交：端口 25/587/465 × 地址族 v4/v6 × 单会话；断言边界：包序/超时计时器 harness 做不到处注记（回放语义不冒充状态机） | §4 整格表；P3 清单 |
| §10 评审闭环 | failing 先行 3 红例（见本条目 §5）→ 改 → 审 → 测 → 再审；`go vet` + touched 包 `-race` | 本条目 §7 |
| §11 白话汇报 | 先一句结论 | 每次汇报 |
| §12 动态清单 | 四元组开（ip/tcp 通用）；smtp 业务全关：banner 关（问候语无逐流变需求）/dialog 关（序列语义，逐流变破坏事务顺序）/email 关（MIME 构造无逐流变需求）——有序单连接会话，不冒充开；另立项口（信封地址逐流变若有批量需求）。序号算法沿框架（worker.go:300-321，mqtt 同款）；P4 验 flows=2 留空防静态复制（§9 陷阱③） | 本条目 §4 整格表 |
| §13 schema 同步 | 注册表 smtp Fields 2→0 键（删 from/to孤儿；banner/email/dialog 住 `SMTPConfig` 不进 registry——pop3 的 banner/commands 登记是其翻译分支消费，本仓 smtp 翻译走 JSON 往返读 `SMTPConfig` 字段，registry 只留契约端口）；删后重跑 schemagen 并提交生成文件（`TestLayersGeneratedMatchesRegistry` 绿）；CheckProtoFlat 加 smtp presence 分支 | 门 2 脚本 |
| §14 真实流程 | smtp.json 全量 + 落盘 tshark 校准（包号/端口不手算；空壳默认会话包数以落盘为准）；二进制同代；门 2 三项；负例 `.neg.pcap` 口径沿 d323068 | smtp.json |

**状态：** P6 已验收（2026-09-17；门 1 已批→P4 3 红先红后绿→P5 基线 25/25→P5R 补遗 18 例 43/43 + 反查 35/35；门 3 抽查见本条目末）
**完成回填（2026-09-16）：** P4 四改动（`case "smtp"` 翻译分支 pop3 同款 + presence 门 + `setDefaultDstPort(25)` + 删 from/to 孤儿重跑 schemagen）；smtp.json 1→25 例（存量冒烟迁层链 + T-SMTP-2…24/24b，包位逐例落盘 tshark 重钉）；`RESULT: 25 pass, 0 fail, 0 error (of 25)`（/tmp/tg-smtp-p5-server 与 HEAD 同代，门 2 静态两项绿）；落盘 22 文件零孤儿（6 负例中 3 超早拒绝无落盘系旧行为：t002/t020/t024b 在 writer 建文件前被拒，mqtt t045/t046/t149 先例同款）；`go test ./internal/...` 123 包绿（rtmp 单例偶发抖动一次，复跑 3 连绿，tls/rtmp 基线抖动口径）+ touched 包 `-race` 绿；在库 smtp 清空（删前 strategies 19/tasks 170 → 删后 0/0，备份 /tmp/trafficgen.db.bak-smtp-p6，无跨协议引用）。
**门3抽查三条（smtp 存档）：** ①§1 顶层迁入→smtp.json 43 例 `layers` 形零残留（门 2-1 绿，黄项 t002 系执法对象豁免）；②§5 presence→`strategy_convert.go` CheckProtoFlat smtp 分支，smtp_t002 真实流程拒；③§1 banner 翻译→`chain_planner_translate.go` `case "smtp"`，smtp_t016 落盘 banner 字节钉死。
**P5R 补遗回填（2026-09-17，零代码）：** 反查门首跑 17/35→补 T-SMTP-25…42 18 例→`RESULT: 43 pass, 0 fail, 0 error (of 43)` + 反查 35/35（/tmp/tg-smtp-p5-server 与 HEAD 同代，门 2 四项全绿）；落盘 40 文件零孤儿（3 超早拒绝无落盘系旧行为：t002/t020/t024b，mqtt 先例同款）；在库 smtp 清空（删前 strategies 176/tasks 399 → 删后 139/140，smtp 0/0，mqtt 139/140 全留，备份 /tmp/trafficgen.db.bak-smtp-p6-supplement，无跨协议引用）。
**范围（P4）：** ①`translateTerminalConfig` 加 `case "smtp"`（pop3 `:1127` 同款 JSON 往返解码 + 简单 nil 判 flat 权威——扁平侧条件创建无 ftp 式恒非 nil，空 `smtp:{}` 建空壳走 flat 权威与 presence 判死自洽，见复审 R6）；②CheckProtoFlat 加 smtp presence 门（mqtt 文案同构，空 map 也死）；③扁平侧补 `setDefaultDstPort(25)`；④删 registry `from/to` + 重跑 schemagen；⑤smtp.json 1 例改写层链形 + P3 新例（18–24 例）全量跑 + 校准回钉；⑥清库（smtp 行，删前计数→备份→删→复核）。
**明确不解决：** STARTTLS 真升级 / SMTPS `[tcp,tls,smtp]` 真握手链（台词覆盖已有 `TestSMTP_2_6_1`，真升级另立项）；状态机 enforcement（回放语义是架构选择，C 类如实注明，不冒充）；超时计时器（C 类，NOOP/RSET 序列+大 body 覆盖可测部分）；任务级跨策略动态池（D-FTP-2 同口径另立）；DSN/SMTPUTF8（按需立项）。
**依据：** RFC 5321（连接模型 §3.1/问候 220/命令 §4.1.1/顺序 §4.1.4/响应码 §4.2/终止符 §4.1.1.4/dot-stuffing §4.5.2——注：§2.3/§4.1.2/§4.5.3.2 具体数字转引自代码注释，P2 定稿时未亲验 RFC 原文，P4 动工前逐条亲验，验实则留验虚则删，复审 R2/R3）；RFC 5322 §3.6（消息头）/ RFC 2045 §6.8（base64）/ RFC 2046 §5.1.1（mixed/boundary≤70）§5.1.4（alternative）§4（缺省类型）/ RFC 2183（附件处置）/ RFC 879（MSS）/ RFC 6528（ISN）；商业：Postfix postconf.5 `smtpd_banner`（默认 `$myhostname ESMTP $mail_name`）、Gmail SMTP（587+STARTTLS/465，530 先 STARTTLS 语义）、Microsoft Exchange 接收连接器 banner 文档（须 220 开头）；代码事实：`smtp/planner.go:84-110`（validator 4 类）/`:117-340`（回放 Plan）/`:346/:364`（默认会话双范本）、`smtp/mime.go:51`（Email 构造）、`smtp/layer_gen.go:53-156`（事件生成器+注册）、`types.go:7251/7302/7366`（SMTPConfig/Email/Command）。

#### 1. 数据与接口
- 输入：`[ip, tcp, smtp{banner?,email?,dialog?}]`（smtp 层缺席键走 `SMTPConfig` 零值→生成器默认会话；`banner` 空自动 `220 <DstIP> ESMTP trafficgen` 沿既有）。
- 输出：3 握手 + banner(down) + Dialog 命令/响应对 + 4 挥手（链式，与 legacy 同形；MSS 切段/ISN 由 tcp 层与 planner 同款逻辑承担）。
- 修改点四处（builder/drive/finalEmit 零改动）：`chain_planner_translate.go` 加 `case "smtp"`（pop3 同款：`if spec.SMTP != nil return` + completedConfig + JSON 往返→`core.SMTPConfig`）；`strategy_convert.go` CheckProtoFlat 加 smtp presence 分支 + `case "smtp"` 内补 `setDefaultDstPort(25)`；`registry.go` 删 smtp Fields `from/to`；`layer_dyn.go` 零改动（smtp 业务全关，不进 allowlist）。新增函数：无。
- 显式覆盖：层值是 smtp 全配置唯一真相；flat `cfg["smtp"]` 出现即判死（presence，空 map 也死，mqtt 先例）。

#### 2. 依赖与生命周期
- 前置：tcp 层（DependsOn；缺 tcp 自动补，tcp DependsOn ip 连带补全）；tls 为 OptionalOn（声明保留，真升级另立项）。
- 资源：无状态生成器；翻译在 ValidateSpec 同步期（幂等覆盖写）；空层 config 翻译出 `&SMTPConfig{}` 非 nil（生成器走默认会话，与 legacy `smtpConfig==nil→&SMTPConfig{}` 同款 `planner.go:130`）。

#### 3. 主流程与状态
- 翻译顺序：判死（顶层 smtp 出现即拒）→ 层 config 翻译（JSON 往返，Email 嵌套自动）→ 协议 validator（4 类真拦沿既有）。flat 权威判据：简单 nil 判（扁平侧条件创建，复审 R6）。
- 回放语义：Dialog 逐条按序产事件，不做状态机 enforcement；503/530 类序列错由用户写 Response 台词表达（`TestSMTP_2_5_3` 先例），C 类如实注明。
- 动态解析：本期 smtp 业务无动态，worker resolveLayerTuple 只解四元组（flows=2 时 smtp 层留空防静态复制）。

#### 4. 递增与覆盖规则 + 正交组合矩阵 + 业务动态清单
- 无新序号算法（框架 resolveLayerTuple）。
- 业务动态整格（§12，本期全关）：

  | 层.字段 | 开/关 | 理由 |
  |---|---|---|
  | smtp.banner | 关 | 问候语逐流变无需求 |
  | smtp.dialog[].cmd/response | 关 | 序列语义，逐流变破坏事务顺序 |
  | smtp.email.* | 关 | MIME 构造逐流变无需求 |
  | ip/tcp 四元组 | 开 | 框架白名单沿既有（flows=2 留空防静态复制） |
- 正交组合：端口 25/587/465 × v4/v6 × 单会话；query×name 类组合不适用（smtp 无双独立翻译字段）。

#### 5. 错误与异常
- 新锚词：`protocol smtp no longer accepts a top-level smtp sub-config (move it into the smtp layer of an [ip,tcp,smtp] layers chain)`（mqtt 文案同构）。
- 既有锚词沿用（A 类直转 `.neg` 负例）：`smtp: invalid SrcIP/DstIP`、`smtp: TCP.MSS %d too small`、`Email.Boundary … exceeds max 70 chars / contains CRLF`、`Email.Attachments[%d] has neither Data nor DataB64`。
- 回放序列错（503/530/顺序错）属 C 类：不断言引擎拦截，用脚本序列覆盖。
- Failing 先行 3 红例：①顶层 `{"smtp":{}}` 空映射即拒（现状放行——presence 未判死）；②层 `{"smtp":{"banner":"220 x"}}` 翻译后 `spec.SMTP.Banner=220 x`（现状：层配置被忽略，spec.SMTP 保持 nil）；③扁平无端口时 `spec.DstPort=25`（现状：注释写默认 25，实际未调 setDefaultDstPort）。

#### 6. 性能设计与验收
- 单包路径增量：翻译 3 键取值（ValidateSpec 同步期一次）；动态解析零新增（业务全关）。回归口径：smtp.json 全量 suite 耗时相对基线 ±10%；边界诚实声明：无吞吐/并发/内存目标数字（未测）。
- pcap 验收：smtp.json 全量绿 + 落盘可复查（`smtp.req.command/parameter` + `smtp.response.code` + 握手/挥手）；网卡未跑。

#### 7. 实现顺序与回滚
- 步骤 0（failing 先行）：`internal/core/layers/smtp_migrate_test.go` 3 红例（BuildLayersPlanner 全链口径：presence 拒 + banner 翻译 + 25 缺省）。
- 步骤 1：`case "smtp"` 翻译分支；步骤 2：CheckProtoFlat presence + `setDefaultDstPort(25)`；步骤 3：删 from/to + schemagen 重跑；步骤 4：`go build` + vet + touched 包 `-race`；P5：smtp.json 改写 + T-SMTP 新例，全量跑 + 校准回钉；P6：评审+提交+清库复核。
- 回滚：单提交逆序 revert。

#### 8. 验收
- 对应 T-SMTP-*（TEST_CASES P3 先行）。完成条件：3 红例先红后绿；smtp.json 全量绿（RESULT 全量；二进制同代；门 2 三项绿）；touched 包 `-race` 绿；顶层 `smtp` 字面零残留（cases 内；除注释/文档历史叙述）；schemagen 生成表已同步（`TestLayersGeneratedMatchesRegistry` 绿）。

#### 9. 关键决策对比

| 决策 | 候选 | 优劣 | 结论 |
|------|------|------|------|
| A 翻译走法 | A1 pop3 同款 JSON 往返；A2 ftp 同款复用 parse | A2 需给 smtp 写 ParseSMTPConfigFromMap 新函数，Email 嵌套手写解码；A1 嵌套自动零分叉 | 选 A1 |
| B 空壳语义 | B1 简单 nil 判；B2 mqtt 同款逐字段空壳例外 | 扁平侧条件创建无恒非 nil 问题，B2 多余复杂度 | 选 B1（复审 R6） |
| C from/to 孤儿 | C1 删除+重跑生成表；C2 接线到信封 | C2 零消费者，接线属无依据设计（§5 禁止） | 选 C1 |
| D 业务动态 | D1 全关+理由；D2 开 banner/信封 | D2 有序会话无逐流变需求，开了测不出 | 选 D1，信封逐流变另立项口 |
| E legacy 25 缺省 | E1 补 setDefaultDstPort(25)；E2 维持现状 | E1 与 xmpp/sip 同款行为对齐；E2 留扁平无端口 DstPort=0 缺口 | 选 E1（理由按复审 R5：行为对齐） |
| F presence 口径 | F1 空 map 也判死；F2 仅非空判死 | F1 mqtt/dns 先例（空即显式走默认）；F2 留空壳双轨 | 选 F1 |

### D-POP3-1 POP3 顶层 pop3 子映射迁入层内 + 业务动态全关【P-PIPE #7 门1】

**门 1 开工对照表（§1–§15，2026-09-17，证据=文档节/代码行/用例号）：**

| § | 本协议怎么满足 | 证据 |
|---|---|---|
| §1 层链唯一真相 | 顶层旧键五键去向：`src_ip`→`layers[ip].src`、`dst_ip`→`layers[ip].dst`、`src_port`→`layers[tcp].src_port`、`dst_port`→`layers[tcp].dst_port`（110 由 `FieldContract tcp.dst_port=110` 补，用户写 995 优先）、`count`→删（缺省单流，走 `flow_control`）、顶层 `pop3` 子映射→`layers[pop3]`（banner/commands/mailbox 同名直迁；层内键名与 `POP3Config` JSON 键一致，见 `types.go:6660`）。目标形状：`{"layers":[{"ip":{"src":"10.0.0.1","dst":"20.0.0.1"}},{"tcp":{"src_port":13000,"dst_port":110}},{"pop3":{"banner":"+OK POP3 server ready","commands":[{"cmd":"USER alice","response":"+OK alice"},{"cmd":"PASS secret","response":"+OK Logged in"},{"cmd":"QUIT","response":"+OK bye"}]}}]}`。P4 必修 3 项：①`CheckProtoFlat` 加 pop3 presence 分支（mqtt/dns/smtp 同款文案，空 map 也死）；②扁平侧 `case "pop3"` 补 `setDefaultDstPort(&spec, cfg, 110)` 一行（注释有、调用无，smtp `:883` 同款行为对齐）；③pop3.json 2 例改写层链形（smoke_01 纯扁平→`[ip,tcp,pop3]`；over_tls 混用→`[ip,tcp,tls,pop3]`，旧键全删） | pop3.json 2 例；`registry.go:828`；`strategy_convert.go:788`；本条目 §1/§7 |
| §2 策略/任务分工 | 沿框架语义；多流走 `flow_control` + 层动态（§12 行）；`spec` 本身不管数量 | D-POP3-1 §3 |
| §3 五件套 | 会话表：单 TCP 长连接单会话，无 `sessions[]`（RFC 1939 §3–§6：客户端主动建连，豁免多会话扇出；pop3 代码无 sessions/driven_by 形状）。事务序列：banner（+OK，down，可空）→USER→PASS（或 APOP 一条）→STAT/LIST/RETR/DELE/NOOP/RSET/TOP/UIDL 任意轮→QUIT→UPDATE（服务端删标记信，dd 实为挥手）→FIN，命令/响应对逐条按序产事件（空 Cmd 跳过命令包=服务端单轮，空 Response 跳过响应包=客户端单轮）。关联关系：无（POP3 无控制/数据双流，FTP PASV 类比不适用）。插入位置：终结层事件流直入 tcp 层（事件模式，tcp 管握手/seq-ack/挥手/MSS 分段；POP3S 形 `[ip,tcp,tls,pop3]` 经 tls 层隧道）；maildrop/TOP 合成在命令轮内替响应（RETR/TOP 处）。时间线：单流顺序无交错；多流=整会话复制。豁免≠豁免多事务：多轮操作/异常断线/长保活各至少一例（§9 立项 T-POP3-25/26/27） | `pop3/planner.go:337`；`pop3/layer_gen.go:30`；`registry.go:828` |
| §4 规范矩阵 | RFC 1939 §3（连接模型：TCP 110 监听、状态机、`+OK`/`-ERR`、dot-stuffing、参数≤40 字符、响应≤512 字符、空闲定时器≥10 分钟）+ §4（AUTHORIZATION：USER/PASS/APOP/QUIT）+ §5（TRANSACTION：STAT/LIST/RETR/DELE/NOOP/RSET）+ §6（UPDATE：QUIT 进更新态删信）+ §7（可选：TOP/UIDL/USER/PASS/APOP 细则；USER 名≤40 字符、UID 1–70 字符）+ §10（示例会话）+ §11（消息格式）；RFC 879（MSS≥536）+ RFC 6528（随机 ISN）；RFC 2449（CAPA 扩展机制）/ RFC 2595（STLS/AUTH，台词覆盖，真升级另立项）。三路对照：规范底线✓；商业准绳=Gmail `pop.gmail.com:995` 强制 SSL（Google 帮助"用其他客户端读取 Gmail"）+ Outlook `outlook.office365.com:995` SSL/TLS（微软支持"POP、IMAP 和 SMTP 设置"）+ Dovecot 问候 `+OK Dovecot ready.`（官方 login_greeting 缺省 `Dovecot ready`）/CAPA 7 项（nmap 实扫）/QUIT 回 `+OK Logging out.`（已亲验，见 T-POP3-30 注记）；开源借鉴=本仓 legacy 回放基线（133 单测：37 planner + 75 testpoints + 21 mime，不搬代码）。候选对比见本条目 §9 | P1 矩阵（本条目 §9 三表）；`types.go:6660` |
| §5 有错必处理 | 依赖：pop3 层 DependsOn tcp / OptionalOn tls（registry.go:828）；配置经 Meta 直传终结层生成器（chain_planner_translate.go:pop3 分支）；validator 调 `(&Planner{}).Validate`（layer_gen.go:112）。validator 真拦 16 分支：坏 IP×2、MSS<536、mailbox 超 10 万、UID>70、命令含 CRLF、单行响应含 CRLF、EmitMailDrop 无 mailbox、MailDrop MsgNum 越界、EmitTop 与 MailDrop 互斥、EmitTop 无 mailbox、Top MsgNum 越界、USER>40、PASS>255、APOP 摘要长度错、APOP 摘要非 hex；端口不强制 110（995 放行） | `planner.go:101`；`registry.go:832`；本条目 §9 |
| §6 性能 | 单会话 14 包量级（3 握手 + banner + 3 命令×2 + 4 挥手）；无锁无 sleep（事件模式，tcp 层管分段）；回归口径：pop3.json 全量 suite 耗时相对基线 ±10%；边界诚实声明：无吞吐/并发/内存目标数字（未测）；网卡未跑 | D-POP3-1 §6 |
| §7 三份文档 | 设计=本条目；用例=T-POP3-*；cases 回指编号 | TEST_CASES T-POP3-* |
| §8 先设计后代码 | 本条目定稿后开工 | 本条目 |
| §9 三源+整格 | RFC 条文 + 本条目 + 现网三家；测试点清单见 TEST_CASES T-POP3-1…（规范行→用例逐行登记）；动态整格见 §12 行 | T-POP3-*；§12 表 |
| §10 评审闭环 | failing 先行（顶层 pop3 presence 拒 + `setDefaultDstPort(110)` 缺省 + 层 mailbox 翻译）→ 改 → 审 → 测 → 再审 | §7 |
| §11 白话汇报 | 先一句结论 | 每次汇报 |
| §12 动态清单 | 整格见本条目 §12 表：四元组开（ip/tcp 通用）；pop3 业务全关：banner 关（问候语无逐流变需求）/commands 关（序列语义，逐流变破坏事务顺序）/mailbox 关（maildrop 静态信箱；逐流变破坏 RETR/UIDL 确定性）——有序单连接会话，不冒充开；另立项口（信封/用户名逐流变若有批量需求）。序号算法沿框架（worker.go:316-321 + `resolveLayerTuple`，smtp 同款）；P4 验 flows=2 留空防静态复制（§9 陷阱③） | 本条目 §4 整格表 |
| §13 schema 同步 | 注册表 pop3 Fields 3 键齐（banner/commands/mailbox，无孤儿，零改动）；翻译分支已有（pop3 同款 JSON 往返 + flat 权威，`chain_planner_translate.go:1127`，零改动）；`main.go:543` 已翻 ChainPlanner（零改动）；本期只加：CheckProtoFlat pop3 presence 分支 + `setDefaultDstPort(110)`；改完重跑 schemagen（生成表快照同步，`TestLayersGeneratedMatchesRegistry` 绿）；allowlist 零改动（pop3 业务全关，不进 allowlist，smtp 先例） | 门 2 脚本 |
| §14 真实流程 | pop3.json 全量绿 + 落盘 tshark 校准（包号/端口不手算；空壳默认会话包数以落盘为准）；二进制同代；门 2 四项；负例 `.neg.pcap` 口径沿 d323068 | pop3.json |
| §15 三道门 | 本表即门 1；门 2 脚本；门 3 挂表抽查；P5R 反查 pop3 表在 P3 登记（`coverage_gate.py` 仿 smtp 表） | 本条目 |

**状态：** P6 已验收（2026-09-17；门 1 已批→P4 2 红转绿→P5 基线 37/37→补遗 13 例 50/50 + 反查 32/32；门 3 抽查见本条目末）
**范围（2026-09-17）：** ①`CheckProtoFlat` 加 pop3 presence 判死；②扁平侧补 `setDefaultDstPort(110)`；③pop3.json 2 例改写 + P3 新例全量跑 + 校准回钉；④清库（pop3 行，删前计数→备份→删→复核）。
**明确不解决：** STLS 真升级 / POP3S `[tcp,tls,pop3]` 真握手链（台词覆盖已有 `TestPOP3Point_1_14_*`，真升级另立项）；状态机 enforcement（回放语义是架构选择，C 类如实注明，不冒充）；空闲 autologout 计时器（RFC 1939 §3 ≥10 分钟，C 类：无时钟不断言）；任务级跨策略动态池（D-FTP-2 同口径另立）；APOP 摘要计算（`computeAPOPDigest` helper 已有，planner 不主动算，用户原文提供，C 类）。
**依据：** RFC 1939 §3（TCP 110 监听/三状态/`+OK`/`-ERR` 大写/dot-stuffing CRLF.CRLF/参数≤40 字符/响应≤512 字符/空闲定时器≥10 分钟）/§4（AUTHORIZATION：USER/PASS/APOP/QUIT）/§5（TRANSACTION：STAT/LIST/RETR/DELE/NOOP/RSET）/§6（UPDATE：QUIT 进更新态）/§7（可选命令：USER/PASS/APOP/TOP/UIDL；USER 名≤40/UID 1–70 字符）/§10（示例会话全文抄：USER/PASS/STAT/LIST/RETR/QUIT 官方序列）/§11（消息格式）；RFC 2449（CAPA 扩展机制）/ RFC 2595（STLS/AUTH；台词覆盖，真升级另立项）；RFC 879（MSS≥536）/ RFC 6528（ISN）；商业：Gmail POP（`pop.gmail.com:995` 强制 SSL + `recent:` 模式 + 留档/删档选项，Google 帮助文档）/ Outlook（`outlook.office365.com:995` SSL/TLS，微软支持文档）/ Dovecot（问候/CAPA/QUIT 回复均已亲验，见 T-POP3-30 注记）；代码事实：`pop3/planner.go:101-208`（validator 16 分支）/`:213-386`（回放 Plan）/`pop3/layer_gen.go:30-84`（事件生成器+注册+握手挥手校准）、`types.go:6660/6669/6718`（POP3Config/Command/Mailbox/Message/MIMEPart）。

**§9 规范矩阵（P1 先行，规范要求 → 业务场景 → 代码现状 → 缺口）：**

| 规范行 | 业务场景 | 代码现状 | 缺口→用例 |
|---|---|---|---|
| RFC 1939 §3 连接模型（TCP 110 监听，客户端主动建连） | 默认会话冒烟（banner+USER+PASS+QUIT） | 已实现（Plan 恒产握手/挥手；链上 FieldContract 110 缺省） | 改写 T-POP3-1（A） |
| RFC 1939 §4 AUTHORIZATION（USER/PASS/APOP/QUIT） | 登录三形：USER+PASS / APOP 一条 / 空 USER 跳过 | 已实现（回放 + APOP 摘要格式门） | T-POP3-2/3/4（A） |
| RFC 1939 §5 TRANSACTION（STAT/LIST/RETR/DELE/NOOP/RSET） | 每命令一例 + 组合流（STAT→LIST→RETR→DELE→QUIT 官方 §10 序列全文抄） | 已实现（回放；maildrop/TOP 合成） | T-POP3-5…10 + 官方序列例（A） |
| RFC 1939 §6 UPDATE（QUIT 进更新态删信） | QUIT 收尾（各例附带断言 terminates） | 已实现（链挥手） | 附带不断单独例（不适用单独例） |
| RFC 1939 §7 可选（TOP/UIDL） | TOP 合成（headers+前 N 行）/ UIDL 多行单行 | 已实现（EmitTop/EmitMailDrop + validator 互斥门） | T-POP3-11/12（A） |
| RFC 1939 §3 dot-stuffing（CRLF.CRLF，`.` 开头行补点） | RETR 点填充体 | 已实现（`buildMailDropResponse`） | T-POP3-13（A，转离线 `TestPOP3Point_3_10_3`） |
| RFC 1939 §3 响应≤512 / 参数≤40 / PASS≤255 / UID 1–70（USER>40 拒/PASS>255 拒/APOP 非 hex 拒/UID>70 拒/命令 CRLF 注入拒/单行响应 CRLF 拒） | 6 负例 | 已实现（validator 16 分支 16 处 return 中 8 类；离线 `TestPOP3Validate_USERTooLong/PASSTooLong/APOPDigest*/UIDTooLong/CRLFInjectionRejected/ResponseWithCRLFWithoutMultiline` 有基线） | T-POP3-14…19（A 负例，锚词取字面） |
| RFC 1939 §3 空闲定时器≥10 分钟 | 不做（无时钟，C 类） | 无 | C 类注记，不列用例 |
| RFC 1939 §10 示例会话 | 官方序列全文抄（USER/PASS/STAT/LIST/RETR/QUIT） | 回放 | T-POP3-20（A） |
| RFC 2449 CAPA / RFC 2595 STLS/AUTH | 台词覆盖（CAPA 列表/STLS→+OK/AUTH PLAIN 轮次）；真升级另立项 | 回放（离线 `TestPOP3Point_1_13_*`/`1_14_*`/`1_15_*` 有基线） | T-POP3-21/22/23（A 台词） |
| RFC 879 MSS≥536 / RFC 6528 ISN | MSS<536 拒；ISN 随机（不断言值） | 已实现 | T-POP3-24（A 负例，`too small`） |
| 现网 Gmail（995 强制 SSL + recent 模式） | banner 台词 + recent: 用户名形 | 回放 | T-POP3-28（A，映射地板线） |
| 现网 Outlook（995 SSL/TLS） | banner 台词 | 回放 | T-POP3-29（A，映射地板线） |
| 现网 Dovecot（问候/CAPA/QUIT） | banner 台词（已亲验：问候原文+7 项能力集+退出回复） | 回放 | T-POP3-30（A，映射已亲验） |
| 多事务三项（多轮/异常断线/长保活） | 同连接多 RETR / 无 QUIT 断线 / 多 NOOP | 已实现（回放天然支持） | T-POP3-25/26/27（A） |
| 复合流（登录+多动作一条流） | USER+PASS+STAT+RETR+DELE+QUIT 一条流 | 已实现 | T-POP3-31（A，≥3 动作） |
| 方向/端口/v6（995 显式通过/v6 承载/坏 IP 拒） | t13/t15/t19 同款三例 | 已实现（FieldContract 995 优先；框架 ip 门） | T-POP3-32/33/34（A） |
| 顶层 pop3 presence 判死 + 静态复制拒绝 | 2 负例 | 待 P4（本期修） | T-POP3-35/36（A，failing 先行） |

**命令×响应码矩阵（§4 子表①，逐格已覆/缺失；回放语义下响应码是用户写的 Response 原文，`+OK`/`-ERR` 两分支各至少一例）：**

| 命令 | 成功（+OK） | 失败（-ERR） | 状态 |
|---|---|---|---|
| USER | T-POP3-1 | T-POP3-19（-ERR 台词，C 类边界） | P3 建 |
| PASS | T-POP3-1 | 同上（共用 -ERR 台词格） | P3 建 |
| APOP | T-POP3-3 | T-POP3-17（摘要非 hex 拒，validator 真拦） | P3 建 |
| STAT | T-POP3-5 | —（空 maildrop 回 `+OK 0 0`，不断 -ERR） | P3 建 |
| LIST | T-POP3-6 | T-POP3-7（越界回 -ERR 台词） | P3 建 |
| RETR | T-POP3-8（maildrop 合成） | T-POP3-9（无此信 -ERR 台词） | P3 建 |
| DELE | T-POP3-10（含越界台词） | 同格 | P3 建 |
| NOOP | T-POP3-27（长保活） | —（NOOP 无失败分支，不适用） | P3 建 |
| RSET | T-POP3-10 附带 | —（RSET 无失败分支，不适用） | 附带 |
| TOP | T-POP3-11 | T-POP3-12（无 mailbox 拒，validator 真拦） | P3 建 |
| UIDL | T-POP3-12（多行） | T-POP3-18（UID>70 拒，validator 真拦） | P3 建 |
| QUIT | 各例附带 terminates | —（QUIT 无失败分支，不适用） | 附带 |
| CAPA/STLS/AUTH | T-POP3-21/22/23（台词） | T-POP3-22 附带（STLS 事务态 -ERR 台词，转离线 `2_6_1`） | P3 建 |

**数据形态变体表（§4 子表②，mailbox/响应形态逐项）：**

| 形态 | 说明 | 用例 |
|---|---|---|
| 空 maildrop（STAT 回 `+OK 0 0`） | 无信状态 | T-POP3-5 |
| 单信纯文本 RETR | headers+空行+body+点终结 | T-POP3-8 |
| 多信 maildrop（2 信 LIST/UIDL） | 多行响应两行体 | T-POP3-6/12 |
| MIME multipart 附件 | `mime_parts` + boundary 自动 | T-POP3-13 附带（转离线 MIME 基线 21 单测已有，pcap 建一例） |
| 空正文信 | headers+空 body | T-POP3-8 附带（MsgNum 2 空信） |
| 点填充体（`.` 开头行） | dot-stuffing | T-POP3-13 |
| TOP 前 N 行（N=0 仅头） | EmitTop/TopLines | T-POP3-11 |
| 超长信 MSS 切段 | 大 body 分段 | T-POP3-13 附带（转离线 `4_4_2`，pcap 不建大包例，C 类注记） |

**商业行为→用例映射表（§4 子表③）：**

| 商业行为 | 出处 | 用例 | 状态 |
|---|---|---|---|
| Gmail `pop.gmail.com:995` 强制 SSL | Google 帮助"用其他客户端读取 Gmail" | T-POP3-28 | P3 建（banner 台词地板线） |
| Gmail `recent:` 模式（近 30 天） | 同上 | T-POP3-28 附带（用户名 `recent:alice`） | P3 建 |
| Outlook `outlook.office365.com:995` SSL/TLS | 微软支持"POP、IMAP 和 SMTP 设置" | T-POP3-29 | P3 建（banner 台词地板线） |
| Dovecot 问候/CAPA/QUIT | 官方 login_greeting 缺省+nmap 实扫能力集+实录退出回复（已亲验） | T-POP3-30 | 已建（映射已亲验） |
| Postfix 无 POP3（不适用） | — | — | 不适用（Postfix 只做 SMTP） |

#### 1. 数据与接口
- 输入：`[ip, tcp, pop3{banner?,commands?[],mailbox?{messages[]}}]`（pop3 层缺席键走 `POP3Config` 零值→生成器默认空会话沿既有；`banner` 空跳过不像 smtp 自动补，沿既有 `planner.go:332`）；POP3S 形 `[ip,tcp,tls,pop3]`（tls 层隧道，pop3 事件直入）。
- 输出：3 握手 + banner(down，可空) + 命令/响应对 + 4 挥手（链式，与 legacy 同形；MSS 切段/ISN 由 tcp 层与 planner 同款逻辑承担）。
- 修改点两处（builder/drive/finalEmit 零改动）：`strategy_convert.go` CheckProtoFlat 加 pop3 presence 分支（mqtt/dns/smtp 文案同构，空 map 也死）+ `case "pop3"` 内补 `setDefaultDstPort(&spec, cfg, 110)`（注释已写行为对齐，调用缺失）；`registry.go`/`chain_planner_translate.go`/`layer_dyn.go`/`main.go` 零改动（已齐）。新增函数：无。
- 显式覆盖：层值是 pop3 全配置唯一真相；flat `cfg["pop3"]` 出现即判死（presence，空 map 也死，mqtt 先例）。

#### 2. 依赖与生命周期
- 前置：tcp 层（DependsOn；缺 tcp 自动补，tcp DependsOn ip 连带补全）；tls 为 OptionalOn（声明保留，真升级另立项）。
- 资源：无状态生成器；翻译在 ValidateSpec 同步期（幂等覆盖写）；空层 config 翻译出 `&POP3Config{}` 非 nil（生成器走默认空会话，与 legacy `pop3Config==nil→&POP3Config{}` 同款 `planner.go:226`；mailbox 嵌套 messages[] 逐个字段解码，见 `strategy_convert.go:1686`）。
- flat 权威判据：简单 nil 判（扁平侧条件创建，复审 smtp R6 同款：`if spec.POP3 != nil return`，扁平侧无 ftp 式恒非 nil，空 `pop3:{}` 建空壳走 flat 权威与 presence 判死自洽）。

#### 3. 主流程与状态
- 三状态：AUTHORIZATION（USER/PASS/APOP/QUIT，§4）→TRANSACTION（STAT/LIST/RETR/DELE/NOOP/RSET，§5；可选 TOP/UIDL，§7）→UPDATE（QUIT 进更新态删信，§6）。回放不 enforcement 状态机（smtp 同款架构选择，C 类如实注明）：错序由用户写 `-ERR` Response 台词表达（离线 `TestPOP3Point_3_16_1_UnknownCommand` 先例）。
- 翻译顺序：判死（顶层 pop3 出现即拒）→ 层 config 翻译（JSON 往返，mailbox 嵌套自动）→ 协议 validator（16 分支真拦沿既有）。
- 动态解析：本期 pop3 业务无动态，worker resolveLayerTuple 只解四元组（flows=2 时 pop3 层留空防静态复制）。

#### 4. 递增与覆盖规则 + 正交组合矩阵 + 业务动态清单
- 无新序号算法（框架 `resolveLayerTuple`（worker.go:318） + `spec.FlowIndex` 只读（worker.go:321）；pop3 planner 不读 FlowIndex，smtp 同款）。
- 动态整格（§12）：

  | 层.字段 | 开/关 | 面 | 覆盖 |
  |---|---|---|---|
  | pop3.banner | 关 | 问候语无逐流变需求 | 注记 |
  | pop3.commands | 关 | 序列语义，逐流变破坏事务顺序 | 注记 |
  | pop3.mailbox | 关 | maildrop 静态信箱；逐流变破坏 RETR/UIDL 确定性 | 注记 |
  | ip/udp 四元组 | 开 | 框架白名单沿既有 | T-POP3-33 附带（flows=2 双流四元组 distinct 由框架保底 `src_port+1`，不断言） |
- 正交组合：地址族×结构（IPv4 单会话×IPv6 单会话对称两格：T-POP3-1 v4 + T-POP3-33 v6）；端口档位（110 缺省/T-POP3-1 + 995 显式/T-POP3-32 + 空壳缺省/冒烟）；模式×方向（明文 `[ip,tcp,pop3]` + POP3S `[ip,tcp,tls,pop3]` 改写的 over_tls）。
- 静态门业务逃生口：pop3 业务全关→flows=2 例无动态逃生，留空防静态复制（T-POP3-33 同款 smtp T-024：无显式标量四元组，src_port 保底+1）。

#### 5. 错误与异常
- 新锚词：`protocol pop3 no longer accepts a top-level pop3 sub-config (move it into the pop3 layer of an [ip,tcp,pop3] layers chain)`（mqtt/dns/smtp 文案同构）。
- 既有锚词沿用 16 分支（字面子串）：`is not a valid IP address`（T-POP3-34）/`too small`（T-POP3-24）/`max`（mailbox 超限：离线无 10 万构造基线，pcap 负例不断全量构造，见 T-POP3-15 注记）/`UID length`（T-POP3-18）/`contains CRLF`（T-POP3-16/17）/`but Mailbox is nil`（T-POP3-12）/`out of range`（T-POP3-7/12）/`mutually exclusive`（T-POP3-12）/`USER name length`（T-POP3-14）/`PASS password length`（T-POP3-15 改小载荷断文案）/`APOP digest`（T-POP3-17）。
- Failing 先行 3 红例：①顶层 `{"pop3":{}}` 空映射 create 即 400（现状放行——presence 未判死）；②扁平 `{"dst_port":…}` 无 pop3 键 legacy 形 DstPort=0（现状：注释写默认 110 但无 `setDefaultDstPort` 调用）；③层 `{"pop3":{"mailbox":{…}}}` 翻译后 spec.POP3.Mailbox 非空（现状已绿——翻译分支齐，本例锁回归）。
- 超早拒绝无落盘口径沿 d323068（T-POP3-35/36/24 在 writer 建文件前被拒，`.neg.pcap` 24B 头或零文件，mqtt/smtp 先例同款）。
- 四件事：失败返回=策略创建期 400（presence/MsgNum 越界等，任务根本不启动）或任务启动期 error（在库旧策略经 ValidationErrors）；会话命运=合成期拒绝无会话可继续（不产包），回放错序不断言重试；重试=无（回放语义不重试不重连，RST/FIN 沿引擎既有挥手）；超时=空闲 autologout 无时钟不断言（C 类，见明确不解决）。

#### 6. 性能设计与验收
- 单包路径增量：presence 一次 map 查 + 缺省一行赋值（ValidateSpec/convert 同步期一次）；动态解析走框架（零新增）。回归口径：pop3.json 全量 suite 耗时相对基线 ±10%；边界诚实声明：无吞吐/并发/内存目标数字（未测）。
- pcap 验收：pop3.json 全量绿 + 落盘可复查（`pop.request.command/parameter` + `pop.response.indicator/description` + distinct 双值）；网卡未跑。
- 背压/长时间：沿引擎既有（本期无新状态、无新锁、无新 sleep；mailbox 上限 10 万防内存 blowup 沿既有 `MaxMessages`）；单流最大报文=点终结短命令级（MSS 切段由 tcp 层承担）；队列上限/CPU 并行度沿引擎既有（本期零新增不断言具体数）。

#### 7. 实现顺序与回滚
- 步骤 0（failing 先行）：`internal/core/pop3_migrate_test.go` 新建 3 红例（presence 拒/DstPort 缺省 110/层 mailbox 翻译回归）。
- 步骤 1：`strategy_convert.go` CheckProtoFlat 加 pop3 presence 分支；步骤 2：`case "pop3"` 补 `setDefaultDstPort(&spec, cfg, 110)`；步骤 3：`go build` + vet + touched 包 `-race` + schemagen 重跑（无变更则生成表不动）；P5：pop3.json 改写 + T-POP3-2…36 全量跑 + 校准回钉；P6：评审+提交+清库复核。
- 回滚：单提交逆序 revert（P4 代码与 P5 用例分两提交）。

#### 8. 验收
- 对应 T-POP3-1…36（TEST_CASES P3 先行）。完成条件：3 红例先红后绿；pop3.json 全量绿（RESULT 全量；二进制同代；门 2 四项绿：旧键零残留 + 全量绿 + 同代 + 反查绿）；touched 包 `-race` 绿；顶层 `pop3` 字面零残留（cases 内）；schemagen 生成表已同步（`TestLayersGeneratedMatchesRegistry` 绿）；在库 pop3 行清空（删前计数→备份→删→复核）。
- **完成回填（2026-09-17）：** pop3.json 2→37 例（存量改写 + T-POP3-2…36，包位逐例落盘重钉，t010 补 RSET）；`RESULT: 37 pass, 0 fail, 0 error (of 37)`（/tmp/tg-pop3-p5-server 与 HEAD 同代，门 2 四项全绿）；落盘 34 文件零孤儿（2 旧名已删；3 超早拒绝无落盘系旧行为）；`go test` 四包绿 + core/layers `-race` 绿；在库 pop3 清空（删前 166/323 → 删后 139/140，pop3 0/0，mqtt 全留，备份 /tmp/trafficgen.db.bak-pop3-p6）。
- **补遗回填（2026-09-17，对标 SMTP，零代码）：** 反查门 26 项→补 T-POP3-37…49 13 例→`RESULT: 50 pass, 0 fail, 0 error (of 50)` + 反查 32/32（门 2 四项全绿）；MIME 双附件下载与 smtp_t033 同结构成对（包 10 整帧偏移 288）；validator 16 分支 pcap 全收口；落盘 47 文件零孤儿（3 超早拒绝无落盘系旧行为）。
- **门3抽查三条：** ①§1 顶层迁入→pop3.json 37 例 `layers` 形零残留（门 2-1 绿；t035 系执法对象豁免）；②§5 presence→`strategy_convert.go` CheckProtoFlat pop3 分支，pop3_t035 真实流程拒；③§1 缺省 110→`case "pop3"` 内 `setDefaultDstPort(110)`，pop3_t001 包 1 `tcp.dstport=110` 落盘钉死。

#### 9. 关键决策对比

| 决策 | 候选 | 优劣 | 结论 |
|------|------|------|------|
| A presence 口径 | A1 空 map 也判死；A2 仅非空判死 | A1 mqtt/dns/smtp 先例（空即显式走默认）；A2 留空壳双轨 | 选 A1 |
| B 110 缺省走法 | B1 补 `setDefaultDstPort(110)`；B2 维持现状靠 FieldContract | B1 与 smtp `:883`/xmpp/sip 同款行为对齐（legacy 扁平路径 DstPort=0 缺口）；B2 链上虽有 FieldContract 但 legacy 扁平无端口仍 0 | 选 B1（理由按 smtp 复审 R5：行为对齐） |
| C 业务动态 | C1 全关+理由；C2 开 mailbox/用户名 | C2 有序会话+静态信箱，开了测不出（mailbox 逐流变破坏 RETR 确定性） | 选 C1，逐流变另立项口 |
| D 翻译走法 | D1 现状 JSON 往返不动；D2 改 ftp 同款复用 parse | D2 需重写 mailbox 嵌套解码，已有分支零分叉，动它违反 YAGNI | 选 D1（零改动） |
| E UIDL 语义 | E1 用户原文提供（planner 不自动）；E2 自动生成 | E2 与 `types.go` 注释"Empty = 不自动生成"冲突，属无依据设计 | 选 E1（沿既有注释） |
| F 超大 mailbox 负例 | F1 小载荷断上限文案变体；F2 构造 10 万+1 信 | F2 载荷上百 MB，MCP 建策略即卡死，测的是耐心不是门 | 选 F1（不断全量构造，见 T-POP3-15 注记） |

### D-IMAP-1 IMAP 顶层 imap 子映射迁入层内 + 业务动态全关【P-PIPE #8 门1】

**门 1 开工对照表（§1–§15，2026-09-17，证据=文档节/代码行/用例号）：**

| § | 本协议怎么满足 | 证据 |
|---|---|---|
| §1 层链唯一真相 | 顶层旧键五键去向：`src_ip`→`layers[ip].src`、`dst_ip`→`layers[ip].dst`、`src_port`→`layers[tcp].src_port`、`dst_port`→`layers[tcp].dst_port`（143 由 `FieldContract tcp.dst_port=143` 补，用户写 993 优先）、`count`→删（缺省单流，走 `flow_control`）、顶层 `imap` 子映射→`layers[imap]`（banner/commands/idle/pipelined_commands/allow_utf8_mailbox 同名直迁；commands 嵌套 tag/cmd/responses/literal_body/_b64/file_source/emit_idle/cancel_after/uid_cache/mime_body，idle 嵌套 push/done_tag/done_response/timeout，mime_body 嵌套 headers/boundary/text/parts(content_type+body)/attachments(filename+content_type+data)，层内键名与 `IMAPConfig` JSON 键一致，见 `types.go:4570/4622/4766/4853`）。目标形状：`{"layers":[{"ip":{"src":"10.0.0.1","dst":"20.0.0.1"}},{"tcp":{"src_port":14000,"dst_port":143}},{"imap":{"banner":"* OK IMAP ready","commands":[{"tag":"A001","cmd":"LOGIN alice secret","responses":["A001 OK LOGIN completed"]},{"tag":"A002","cmd":"LIST \"\" \"*\"","responses":["* LIST (\\Inbox) \"\" INBOX","A002 OK LIST completed"]},{"tag":"A003","cmd":"LOGOUT","responses":["* BYE Logging out","A003 OK LOGOUT completed"]}]}}]}`。P4 必修 5 项：①`CheckProtoFlat` 加 imap presence 分支（mqtt/dns/smtp/pop3 同款文案，空 map 也死）；②扁平侧 `case "imap"` 补 `setDefaultDstPort(&spec, cfg, 143)` 一行（pop3 `:799`/smtp `:883` 同款行为对齐；现状注释亦无）；③`registry.go:838` 补 imap Fields 5 键（现状零 Fields=层内业务键 V9 全拒）；④`translateTerminalConfig` 加 `case "imap"`（pop3 `:1127`/smtp `:1143` 同款 + flat 权威；P4 JSON 往返，P5 修为 `ParseIMAPConfigFromMap` 单 parse 真相，见本条目末完成回填②）；⑤imap.json 1 例改写层链形（smoke_01 纯扁平→`[ip,tcp,imap]`，5 旧键全删） | imap.json 1 例；`registry.go:838`；`strategy_convert.go:708`；本条目 §1/§7 |
| §2 策略/任务分工 | 沿框架语义；多流走 `flow_control` + 层动态（§12 行）；`spec` 本身不管数量 | D-IMAP-1 §3 |
| §3 五件套 | 会话表：单 TCP 长连接单会话，无 `sessions[]`（RFC 9051 §3：客户端主动建连，豁免多会话扇出；imap 代码无 sessions/driven_by 形状）。事务序列：greeting（`* OK`/`PREAUTH`/`BYE` 定初始态，down，可空）→各态命令：CAPABILITY/NOOP/LOGOUT（任意态 §6.1）、STARTTLS/AUTHENTICATE/LOGIN（未认证态 §6.2）、ENABLE/SELECT/EXAMINE/CREATE/DELETE/RENAME/SUBSCRIBE/UNSUBSCRIBE/LIST/NAMESPACE/STATUS/APPEND/IDLE（已认证态 §6.3）、CLOSE/UNSELECT/EXPUNGE/SEARCH/FETCH/STORE/COPY/MOVE/UID（已选择态 §6.4）→LOGOUT→挥手→FIN；tag 逐条（空 tag 自动 A001 递增，tag 复用服务器须接受、不校验）；命令/响应对逐条按序产事件（空 Cmd 跳过命令包=服务端单轮如 AUTH challenge，空 Responses 跳过响应包；sync literal `{N}` 占位替换+literal 体+收尾 CRLF：server→client 直接跟字节，client→server 须等 continuation `+`；MIMEBody>B64>Body 优先级，FileSource 链上不可用 tftp 同款降级）；IDLE 轮（RFC 2177：IDLE→`+ idling`→push→DONE→done response→可选 timeout BYE；DONE 裸发无 tag，tag 只在 done response）；cancel_after 表 AUTHENTICATE 取消 `*`；uid_cache_invalidation 尾注；pipelined 双相位 vs 默认逐条。关联关系：无（IMAP 无控制/数据双流，FTP PASV 类比不适用）。插入位置：终结层事件流直入 tcp 层（事件模式，tcp 管握手/seq-ack/挥手/MSS 分段；IMAPS 形 `[ip,tcp,tls,imap]` 经 tls 层隧道）。时间线：单流顺序无交错；多流=整会话复制。豁免≠豁免多事务：多轮操作/异常断线/长保活各至少一例（§9 立项 T-IMAP-57/58/59） | `imap/planner.go:296`；`imap/layer_gen.go:38`；`registry.go:838` |
| §4 规范矩阵 | RFC 9051 §2.1（TCP 143 明文/993 隐式 TLS 监听）+ §2.2.1（tag：客户端每命令不同 tag SHOULD、服务器 MUST 接受复用；空格/CRLF 语法错；Tag 上限见 §9 待确认项）+ §2.2.2（tagged/untagged `*`/continuation `+` 三响应；completion 带原 tag）+ §3（四状态：greeting 定初始态 OK/PREAUTH/BYE；错态命令回 BAD/NO；迁移图例①–⑦）+ §4.3（sync literal `{N}`CRLF+字节）+ §5.4（autologout 计时器：无时钟不断言，C 类）+ §5.5（pipelining 多命令并行）+ §6（命令分态表：6.1 任意态/6.2 未认证/6.3 已认证/6.4 已选择）+ §7（响应表：OK/NO/BAD/PREAUTH/BYE/CAPABILITY/LIST/STATUS/EXISTS/EXPUNGE/FETCH/`+`）+ §8（官方示例会话全文抄）；RFC 879（MSS≥536）+ RFC 6528（随机 ISN）；RFC 2177（IDLE：`+ idling`/DONE/timeout BYE；常量 `IDLEContuation/IDLEDone/IDLETimeoutBye`）/ RFC 5161（ENABLE）/ RFC 6855（UTF-8，AllowUTF8Mailbox）/ RFC 6851（MOVE）/ RFC 7162（CONDSTORE，UIDCacheInvalidationResponse）/ RFC 3501 §5.1.3（Modified UTF-7，C 类）；MIME：RFC 2045 §6.8（base64 76 换行）/ RFC 2046 §5.1.1（mixed/boundary）/ RFC 5322（消息头）/ RFC 2183（附件处置）。三路对照：规范底线✓；商业准绳=Gmail `imap.gmail.com:993` 强制 SSL（Google Workspace 文档）+ 问候 `* OK Gimap ready…`（双源现网实录，openssl 亲验列 P5）+ Outlook `outlook.office365.com:993` SSL/TLS + OAuth2/Modern（微软支持"POP、IMAP 和 SMTP 设置"）+ Dovecot 问候 `* OK [CAPABILITY IMAP4rev1 …] Dovecot ready.`（三份以上现网实录交叉，telnet 亲验列 P5，POP3 口径同款）；开源借鉴=本仓 legacy 回放基线（136 单测：50 planner + 70 testpoints + 13 mime + 3 f2_done（`grep -c ^func Test` 实数），不搬代码）。候选对比见本条目 §9 | P1 矩阵（本条目 §9 三表）；`types.go:4570` |
| §5 有错必处理 | 依赖：imap 层 DependsOn tcp / OptionalOn tls（registry.go:838）；配置经 Meta 直传终结层生成器（chain_planner_translate.go:183-185）；validator 调 `(&Planner{}).Validate`（layer_gen.go:256-260）。validator 真拦 23 分支：坏 IP×2、MSS<536、Tag>256、Tag 含 SP/CRLF、Cmd 含 CRLF、Cmd 非 ASCII（缺 allow_utf8）、Responses 超 1 万、Response 含 CRLF、LiteralBody 与 B64 互斥、LiteralBody 超长、B64 解码错、B64 解码超长、MIMEBody 与 Literal 互斥、MIMEBody 构造超长、EmitIDLE 无 IDLE、CancelAfter 越界、Push 超 1000、Push 含 CRLF、Timeout 枚举错、DoneTag 含 SP/CRLF、DoneTag 超长、DoneResponse 含 CRLF；端口不强制 143（993 放行）。P4 必修见 §1 行（Fields 补齐 + 翻译分支，缺任一层配置即死或静默空会话） | `planner.go:140`（23 处 return `:144-286`）；`registry.go:838`；本条目 §9 |
| §6 性能 | 单会话包数量级=3 握手 + banner + 命令/响应帧 + 4 挥手（literal/MIME 体线性增帧）；无锁无 sleep（事件模式，tcp 层管分段）；回归口径：imap.json 全量 suite 耗时相对基线 ±10%；边界诚实声明：无吞吐/并发/内存目标数字（未测）；网卡未跑 | D-IMAP-1 §6 |
| §7 三份文档 | 设计=本条目；用例=T-IMAP-*；cases 回指编号 | TEST_CASES T-IMAP-* |
| §8 先设计后代码 | 本条目定稿后开工 | 本条目 |
| §9 三源+整格 | RFC 条文 + 本条目 + 现网三家；测试点清单见 TEST_CASES T-IMAP-1…（规范行→用例逐行登记）；动态整格见 §12 行 | T-IMAP-*；§12 表 |
| §10 评审闭环 | failing 先行 4 红例（顶层 imap presence 拒 + `setDefaultDstPort(143)` 缺省 + registry Fields 收录 + 层 banner/commands 翻译）→ 改 → 审 → 测 → 再审 | §7 |
| §11 白话汇报 | 先一句结论 | 每次汇报 |
| §12 动态清单 | 整格见本条目 §12 表：四元组开（ip/tcp 通用）；imap 业务全关：banner 关（问候语无逐流变需求）/commands 关（序列语义 + tag 计数，逐流变破坏事务顺序）/idle 关（会话级单例）/mime_body 关（静态信体，逐流变破坏 FETCH 确定性）——有序单连接会话，不冒充开；另立项口（用户名/信箱名逐流变若有批量需求）。序号算法沿框架（worker.go:316 + `resolveLayerTuple` :774，smtp 同款）；P4 验 flows=2 留空防静态复制（§9 陷阱③） | 本条目 §4 整格表 |
| §13 schema 同步 | 注册表 imap Fields 0→5 键（banner/commands/idle/pipelined_commands/allow_utf8_mailbox；commands/idle/mime_body 嵌套对象/数组 V9 只验顶层键存在，值语义归翻译分支 + validator，smtp/pop3 同款）；翻译分支新增（pop3 `:1127`/smtp `:1143` 同款 + flat 权威；P4 JSON 往返，P5 修为 `ParseIMAPConfigFromMap` 单 parse 真相，见本条目末完成回填②）；`main.go:545` 已翻 ChainPlanner（零改动）；本期只加：CheckProtoFlat imap presence 分支 + `setDefaultDstPort(143)`；改完重跑 schemagen（生成表快照同步，`TestLayersGeneratedMatchesRegistry` 绿）；allowlist 零改动（imap 业务全关，不进 allowlist，smtp 先例） | 门 2 脚本 |
| §14 真实流程 | imap.json 全量绿 + 落盘 tshark 校准（包号/端口不手算；空壳默认会话包数以落盘为准）；二进制同代；门 2 四项；负例 `.neg.pcap` 口径沿 d323068 | imap.json |
| §15 三道门 | 本表即门 1；门 2 脚本（imap presence 红线已接：dns/mqtt/smtp/pop3/imap 五协议同口径，presence 负例豁免）；门 3 挂表抽查；P5R 反查 imap 表已登记（`coverage_gate.py:check_imap` 54 项：命令 28 + NO/BAD + literal/IDLE + 多事务三项 + 双复合流 + MIME 双附件 + validator 12 支 + 双流 + 三家；探针验证：复合 A/双流/gmail 三项 PASS，B 缺第二条 MISS 符合预期） | 本条目 |

**状态：** P6 已验收（2026-09-17；门 1 已批→P4 4 红转绿→P5 84/84 + 反查 54/54→门 3 抽查见本条目末；在库 imap 已清空）
**范围（P4+P5）：** ①`CheckProtoFlat` 加 imap presence 判死；②扁平侧补 `setDefaultDstPort(143)`；③`registry.go:838` 补 imap Fields 5 键；④`translateTerminalConfig` 加 `case "imap"`（P4 JSON 往返 + flat 权威；P5 修为 `ParseIMAPConfigFromMap` 单 parse 真相，见本条目末完成回填②）；⑤imap.json 1 例改写 + P3 新例（T-2…71 + 复审补 T-72…84，共 84 例）全量跑 + 校准回钉；⑥清库（imap 行，删前计数→备份→删→复核，见本条目末完成回填④）。
**明确不解决：** STARTTLS 真升级 / IMAPS `[tcp,tls,imap]` 真握手链（台词覆盖已有离线基线，真升级另立项）；状态机 enforcement（回放语义是架构选择，C 类如实注明，不冒充）；空闲 autologout 计时器（RFC 9051 §5.4，C 类：无时钟不断言）；UID 自动分配/序号语义（用户原文提供，不自动）；超大 literal 全量构造（不断 100MB，断上限文案变体，pop3 T-15 F1 同款）；FileSource 链上可用（tftp 同款降级注记：直通不断言可用，真接通另立项）；任务级跨策略动态池（D-FTP-2 同口径另立）。
**依据：** RFC 9051 §2.1（TCP 143 明文/993 隐式 TLS 监听）/§2.2.1（tag：每命令不同 SHOULD、复用 MUST 接受、空格/CRLF 语法错；上限数字 P2 亲验原文后统一，见 §9 待确认项）/§2.2.2（tagged/untagged `*`/continuation `+`；completion 带原 tag；错态 BAD/NO）/§3（四状态 + greeting 定初始态 OK/PREAUTH/BYE + 迁移图例①–⑦）/§4.3（sync literal `{N}`CRLF+字节；server→client 直接跟、client→server 等 `+`）/§5.4（autologout 计时器，C 类）/§5.5（pipelining）/§6（命令分态：6.1 任意态 CAPABILITY/NOOP/LOGOUT；6.2 未认证 STARTTLS/AUTHENTICATE/LOGIN；6.3 已认证 ENABLE/SELECT/EXAMINE/CREATE/DELETE/RENAME/SUBSCRIBE/UNSUBSCRIBE/LIST/NAMESPACE/STATUS/APPEND/IDLE；6.4 已选择 CLOSE/UNSELECT/EXPUNGE/SEARCH/FETCH/STORE/COPY/MOVE/UID）/§7（响应表）/§8（官方示例会话全文抄，标题已亲验、P5 逐字抄原文）；RFC 2177（IDLE：`+ idling`/DONE 裸发/timeout BYE）/ RFC 5161（ENABLE）/ RFC 6855（UTF-8）/ RFC 6851（MOVE）/ RFC 7162（CONDSTORE）/ RFC 3501 §5.1.3（Modified UTF-7，C 类）；RFC 2045 §6.8（base64 76 换行）/ RFC 2046 §5.1.1（mixed/boundary）/ RFC 5322（消息头）/ RFC 2183（附件处置）；RFC 879（MSS≥536）/ RFC 6528（ISN）；商业：Gmail IMAP（`imap.gmail.com:993` 强制 SSL，Google Workspace 文档；问候 `* OK Gimap ready…` 双源实录，openssl 亲验列 P5）/ Outlook（`outlook.office365.com:993` SSL/TLS + OAuth2/Modern，微软支持文档）/ Dovecot（问候 `* OK [CAPABILITY IMAP4rev1 …] Dovecot ready.` 三份以上实录交叉，telnet 亲验列 P5）；代码事实：`imap/planner.go:140`（validator 23 分支 `:144-286`）/`:296`（回放 Plan）/`:309`（nil→空会话）/常量 `MaxTagLen=256`(`:79`)/`MaxResponses=10000`(`:85`)/`MaxPush=1000`(`:90`)/`MaxLiteral=100MB`(`:96`)/`:678`（formatCommandLine）/`:689`（占位识别）/`:711`（占位替换）/`:821`（constructMIMEBody）、`imap/layer_gen.go:38`（事件生成器）/`:256`（init 注册 + 握手挥手校准）、`types.go:4570/4622/4766/4853`（IMAPConfig/Command/MIMEBody/IDLE）。

**§9 规范矩阵（P1 先行，规范要求 → 业务场景 → 代码现状 → 缺口）：**

| 规范行 | 业务场景 | 代码现状 | 缺口→用例 |
|---|---|---|---|
| RFC 9051 §2.1 连接模型（TCP 143 监听，客户端主动建连） | 默认会话冒烟（banner+LOGIN+LIST+LOGOUT，改写存量冒烟；143 缺省不断端口） | 已实现（Plan 恒产握手/挥手；链上 FieldContract 143 缺省；legacy DefaultPort=143） | 改写 T-IMAP-1（A） |
| RFC 9051 §2.2.1 tag（三形：显式/自动递增/点线数字） | 显式 A001 / 空 tag 自动 A001… / tag.42/X-Custom-1/001 | 已实现（autoTagCounter `A%03d`；Tag 长度/SP/CRLF 门） | T-IMAP-2/3/4（A，转离线 `1_1_1_*`） |
| RFC 9051 §2.2.2 三响应（tagged/untagged `*`/continuation `+`） | 空 Cmd 服务端单轮（AUTH challenge `+`）/ untagged + tagged 同轮 | 已实现（空 Cmd/空 Responses 跳过；回放） | T-IMAP-5（A，转离线 `1_1_2_4`） |
| RFC 9051 §3 四状态（greeting 定初始态；LOGIN→SELECT→业务→LOGOUT） | 状态序列正例 + 错序台词（未认证态 SELECT 回 NO，C 类边界） | 已实现回放（不 enforcement，C 类如实注明；离线 `3_19_4_1` 先例） | T-IMAP-6/7（A） |
| RFC 9051 §4.3 sync literal（`{N}`CRLF+字节） | APPEND LiteralBody / APPEND B64 / FETCH 响应占位替换 | 已实现（resolveLiteral 优先级 MIME>B64>Body；FileSource 链上不可用 tftp 同款） | T-IMAP-8/9（A，转离线 `1_15_*/1_21_5`） |
| RFC 9051 §5.4 autologout | 不做（无时钟，C 类） | 无 | C 类注记，不列用例 |
| RFC 9051 §5.5 pipelining | 流水线双相位 vs 默认逐条对照 | 已实现（PipelinedCommands；离线 `3_19_5_*`） | T-IMAP-10（A） |
| RFC 9051 §6.1 任意态（CAPABILITY/NOOP/LOGOUT） | 三命令各一例 | 已实现（离线 `1_2_1/1_3_1/1_4_*`） | T-IMAP-11/12/13（A） |
| RFC 9051 §6.2 未认证态（LOGIN/AUTHENTICATE/STARTTLS） | LOGIN 成功/失败 NO 台词；AUTHENTICATE PLAIN/LOGIN 双形 + 取消 `*`；STARTTLS 台词（真升级另立项） | 已实现（离线 `1_6_*/1_7_*`） | T-IMAP-14/15/16/17（A） |
| RFC 9051 §6.3 已认证态（ENABLE/SELECT/EXAMINE/CREATE/DELETE/RENAME/SUB/UNSUB/LIST/NAMESPACE/STATUS/APPEND/IDLE） | 逐命令一例：SELECT 成功/失败、EXAMINE 台词、CREATE/DELETE（含 INBOX 拒 NO）/RENAME、SUB/UNSUB 台词、LIST、NAMESPACE 台词、STATUS、APPEND 带 flags；ENABLE 台词（离线零覆盖，全仓零命中，下同）；IDLE 见 RFC 2177 行 | 已实现回放（SELECT/CREATE/DELETE/RENAME/LIST/STATUS/APPEND 离线有基线；ENABLE/EXAMINE/SUB/UNSUB/NAMESPACE 离线零覆盖→pcap 建台词例） | T-IMAP-18…29（A） |
| RFC 9051 §6.4 已选择态（CLOSE/UNSELECT/EXPUNGE/SEARCH/FETCH/STORE/COPY/MOVE/UID） | 逐命令一例：CLOSE/UNSELECT/EXPUNGE/SEARCH 非空与空结果/FETCH flags/FETCH body literal/STORE 加减 flag/COPY 成功与失败/MOVE + UID FETCH | 已实现（离线 `1_17_*/1_18_*/1_19_*/1_21_*/1_22_*/1_23_*/1_24_*` 全有基线） | T-IMAP-30…39（A） |
| RFC 9051 §7 响应表（OK/NO/BAD/BYE 等） | NO/BAD 失败码台词（C 类边界）+ 未知命令 BAD 台词 | 回放台词（回放不断言状态机） | T-IMAP-40/41（A） |
| RFC 9051 §8 官方示例会话 | 全文抄 | 回放 | T-IMAP-42（A；标题已亲验，P5 逐字抄原文） |
| RFC 2177 IDLE（`+ idling`/DONE/timeout BYE） | 有 push / 无 push / timeout 三形（close_after_idle/keep_idle/none，各一例） | 已实现（链冒烟 `TestChainPlannerIMAPIDLE`；离线 `1_16_*/3_19_2_*`） | T-IMAP-43/44/45/46/47（A） |
| RFC 7162 CONDSTORE（UIDCacheInvalidation 尾注） | 尾注正例（反例无尾注附带不断单独例） | 已实现（离线 `3_19_9_*`） | T-IMAP-48（A） |
| RFC 6855 UTF-8（AllowUTF8Mailbox 开/关） | 开正例 / 关拒绝（non-ASCII 锚词）/ ASCII 等价附带 | 已实现（离线 `3_19_7_*`） | T-IMAP-49/50（A 负例其一） |
| MIME（RFC 2045/2046/5322/2183：mixed/boundary/base64/附件） | FETCH MIMEBody 双附件下载（对标 smtp_t033/pop3_t037，真实 README 附件）/ APPEND MIME 上行 / 空正文双附件 / 纯附件无正文 | 已实现（constructMIMEBody；mime 13 单测） | T-IMAP-51/52/80/81（A，真实文件） |
| RFC 879 MSS≥536 / RFC 6528 ISN | MSS<536 拒；ISN 随机（不断言值） | 已实现 | T-IMAP-53（A 负例，`out of range [536,65535]` tcp 层 V9 门字面，smtp T-020/pop3 T-24 同款） |
| 现网 Gmail（993 强制 SSL + Gimap ready 问候） | banner 台词 | 回放 | T-IMAP-54（A，映射地板线；问候原文 openssl 亲验列 P5） |
| 现网 Outlook（993 SSL/TLS） | banner 台词 | 回放 | T-IMAP-55（A，映射地板线） |
| 现网 Dovecot（问候/CAPABILITY） | banner 台词（三份实录交叉能力集） | 回放 | T-IMAP-56（A；telnet 亲验列 P5，POP3 口径同款） |
| 多事务三项（多轮/异常断线/长保活） | 同连接多 FETCH / 无 LOGOUT 断线 / 多 NOOP | 已实现（回放天然支持） | T-IMAP-57/58/59（A） |
| 复合流（登录+多动作一条流，双路径成对） | LOGIN+SELECT+FETCH+STORE+COPY+LOGOUT（T-60）与 CREATE+APPEND+SEARCH+STORE+EXPUNGE+LOGOUT（T-79） | 已实现 | T-IMAP-60/79（A，各≥3 动作，§9 双组合流） |
| 方向/端口/v6/双流（993 实链+显式通过/v6 承载/坏 IP 拒/全缺省双流） | smtp t13/t15/t19 + pop3 T-32/T-46 同款四例 | 已实现（FieldContract 993 优先；框架 ip 门；空会话双流） | T-IMAP-61/62/63/78/82（A；T-61 明文钉端口，T-82 实链形） |
| 顶层 imap presence 判死 + 静态复制拒绝 | 2 负例 | 待 P4（本期修） | T-IMAP-64/65（A，failing 先行） |
| validator 23 分支收口（13 支进 pcap：Tag 超长/Tag SP/Cmd CRLF/Response CRLF/Literal-B64 互斥/B64 解码错/EmitIDLE 无 IDLE/Cancel 越界/Push CRLF/Timeout 枚举错/DoneTag SP/DoneResponse CRLF/MIME 互斥——另 Responses 上限 1 支小载荷断文案；其余 9 支离线有基线，大载荷两支按 F1 注记不断全量构造） | 13+1 负例 | 已实现 | T-IMAP-66…77/83/84（A 负例，锚词取字面） |

**待确认项（P2 定稿前亲验 RFC 原文后统一，smtp R2/R3 同款口径）：** ①Tag 上限：`planner.go:79` 256 vs `types.go:4622` 注释 128——以 RFC 9051 §2.2.1/§9 形式语法为准，错的一侧随 P4 改；②`MaxResponses=10000`/`MaxPush=1000`/`MaxLiteral=100MB` 三上限为本仓自定防 blowup 数（注释称 design doc 上限），无 RFC 条文，沿既有用例锁定行为不改口径。

**命令×响应码矩阵（§4 子表①，逐格已覆/缺失；回放语义下响应码是用户写的 Responses 原文，OK/NO/BAD 三分支各至少一例）：**

| 命令 | 成功（tagged OK） | 失败（NO/BAD 台词） | 状态 |
|---|---|---|---|
| CAPABILITY | T-IMAP-11 | —（无失败分支，不适用） | P3 建 |
| NOOP | T-IMAP-12（+T-59 长保活） | —（无失败分支，不适用） | P3 建 |
| LOGOUT | T-IMAP-13（各例附带 terminates） | —（无失败分支，不适用） | P3 建 |
| STARTTLS | T-IMAP-17（台词，真升级另立项） | — | P3 建 |
| AUTHENTICATE | T-IMAP-16（PLAIN/LOGIN 双形） | T-IMAP-16 附带取消 `*`（C 类） | P3 建 |
| LOGIN | T-IMAP-14 | T-IMAP-15（NO 台词，C 类边界） | P3 建 |
| ENABLE | T-IMAP-18（台词；离线零覆盖） | — | P3 建 |
| SELECT | T-IMAP-19 | T-IMAP-20（NO 台词） | P3 建 |
| EXAMINE | T-IMAP-21（台词；离线零覆盖） | — | P3 建 |
| CREATE | T-IMAP-22 | — | P3 建 |
| DELETE | T-IMAP-23 | T-IMAP-23 附带 NO（INBOX 不可删） | P3 建 |
| RENAME | T-IMAP-24 | — | P3 建 |
| SUBSCRIBE | T-IMAP-25（台词；离线零覆盖） | — | P3 建 |
| UNSUBSCRIBE | T-IMAP-25（台词；离线零覆盖） | — | P3 建 |
| LIST | T-IMAP-26 | — | P3 建 |
| NAMESPACE | T-IMAP-27（台词；离线零覆盖） | — | P3 建 |
| STATUS | T-IMAP-28 | — | P3 建 |
| APPEND | T-IMAP-29（+T-8/9 literal 双形） | — | P3 建 |
| IDLE | T-IMAP-43/44（+45/46/47 timeout 三形） | — | P3 建 |
| CLOSE | T-IMAP-30 | — | P3 建 |
| UNSELECT | T-IMAP-31 | — | P3 建 |
| EXPUNGE | T-IMAP-32 | — | P3 建 |
| SEARCH | T-IMAP-33 | T-IMAP-34（空结果，非失败，注记） | P3 建 |
| FETCH | T-IMAP-35/36（+T-51 MIME 双附件） | — | P3 建 |
| STORE | T-IMAP-37（加减 flag） | — | P3 建 |
| COPY | T-IMAP-38 | T-IMAP-38 附带失败（NONEXISTENT） | P3 建 |
| MOVE | T-IMAP-39 | — | P3 建 |
| UID | T-IMAP-39 附带（UID FETCH） | — | P3 建 |
| 未知命令 | — | T-IMAP-41（BAD 台词；回放不断言状态机） | P3 建 |

**数据形态变体表（§4 子表②，greeting/tag/响应/literal/IDLE 形态逐项）：**

| 形态 | 说明 | 用例 |
|---|---|---|
| 空 greeting（banner 空跳过） | 生成器跳过问候帧沿既有 | T-IMAP-1 附带（另立空 banner 例不断单独例） |
| `* OK` 问候 | 常规未认证 greeting | T-IMAP-1 |
| `PREAUTH` 问候台词 | 预认证连接（§3 图例②） | T-IMAP-6 附带 |
| `BYE` 问候台词 | 拒绝连接（§3 图例③） | T-IMAP-7 附带 |
| tag 自动递增（空 tag→A001…） | autoTagCounter `A%03d` | T-IMAP-3 |
| untagged `*` + tagged completion 同轮 | LIST/SELECT 响应对 | T-IMAP-19/26 |
| continuation `+` 单轮 | AUTH challenge（空 Cmd 跳过命令包） | T-IMAP-5 |
| sync literal 上行（APPEND `{N}`+体） | LiteralBody/B64 双形 | T-IMAP-8/9 |
| sync literal 下行（FETCH 占位替换+体+收尾 CRLF） | `{0}`→实际长重写 | T-IMAP-36 |
| 空 literal（零长 `{0}`） | 离线 `3_19_6_*` 转 pcap | T-IMAP-9 附带 |
| MIME simple 纯文本 | Text 单体 | T-IMAP-51 附带（首体块） |
| MIME multipart 双附件 | 真实 README 附件（对标 smtp_t033） | T-IMAP-51 |
| MIME 空正文双附件 | Text 空 + 双附件（对标 pop3_t038 形态） | T-IMAP-80 |
| MIME 纯附件无正文 | 无首体块（对标 pop3_t039/smtp_t035） | T-IMAP-81 |
| 自定义 boundary | 用户原文逐字 | T-IMAP-52 附带 |
| IDLE 有 push / 无 push | RFC 2177 双形 | T-IMAP-43/44 |
| IDLE timeout BYE 三形 | close_after_idle/keep_idle/none | T-IMAP-45/46/47 |
| 流水线双相位 vs 默认逐条 | PipelinedCommands 开/关对照 | T-IMAP-10（双例） |
| UTF-8 开/关/ASCII 等价 | AllowUTF8Mailbox 三形 | T-IMAP-49/50 |
| CONDSTORE 尾注有/无 | UIDCacheInvalidation 开关 | T-IMAP-48（反例附带） |

**商业行为→用例映射表（§4 子表③）：**

| 商业行为 | 出处 | 用例 | 状态 |
|---|---|---|---|
| Gmail `imap.gmail.com:993` 强制 SSL | Google Workspace 文档"IMAP、POP 和 SMTP" | T-IMAP-54 | P3 建（banner 台词地板线；问候原文 openssl 亲验列 P5） |
| Gmail 问候 `* OK Gimap ready…` | 双源现网实录（nylas 文档 + mintlify 排障手册） | T-IMAP-54 附带 | P3 建（openssl 亲验列 P5，不删） |
| Outlook `outlook.office365.com:993` SSL/TLS + OAuth2/Modern | 微软支持"POP、IMAP 和 SMTP 设置" | T-IMAP-55 | P3 建（banner 台词地板线） |
| Dovecot 问候/CAPABILITY（`IMAP4rev1 LITERAL+ SASL-IR … ID ENABLE IDLE AUTH=PLAIN` + `Dovecot ready.`） | 三份以上现网实录交叉（serverfault/roundcube 论坛/部署实录） | T-IMAP-56 | P3 建（telnet 亲验列 P5，POP3 口径同款，不删） |

#### 1. 数据与接口
- 输入：`[ip, tcp, imap{banner?,commands?[],idle?{},pipelined_commands?,allow_utf8_mailbox?}]`（imap 层缺席键走 `IMAPConfig` 零值→生成器默认空会话沿既有；`banner` 空跳过不像 smtp 自动补，沿既有 `planner.go:418` 空判断；IMAPS 形 `[ip,tcp,tls,imap]` 经 tls 层隧道）。
- 输出：3 握手 + banner(down，可空) + 命令/响应对（含 literal 体帧/IDLE 轮）+ 4 挥手（链式，与 legacy 同形；MSS 切段/ISN 由 tcp 层与 planner 同款逻辑承担）。
- 修改点四处（builder/drive/finalEmit 零改动）：`strategy_convert.go` CheckProtoFlat 加 imap presence 分支（mqtt/dns/smtp/pop3 文案同构，空 map 也死）+ `case "imap"` 内补 `setDefaultDstPort(&spec, cfg, 143)`；`registry.go` 补 imap Fields 5 键（banner/commands/idle/pipelined_commands/allow_utf8_mailbox；嵌套 V9 只验顶层键）；`chain_planner_translate.go` 加 `case "imap"`（pop3/smtp 同款：`if spec.IMAP != nil return` + completedConfig + JSON 往返→`core.IMAPConfig`，FileSource 键直通）；`layer_dyn.go` 零改动（imap 业务全关，不进 allowlist）。新增函数：无。
- 显式覆盖：层值是 imap 全配置唯一真相；flat `cfg["imap"]` 出现即判死（presence，空 map 也死，mqtt 先例）。

**§1–§15 复审结论（2026-09-17，用户指令逐条复审）：** P4 自审 2 轮（第 1 轮发现 4 处引用错：smtp `setDefaultDstPort` 行号 `:882`→`:883`、legacy 单测计数口径、`planner.go` banner 空判断 `:423`→`:418`、`worker.go` FlowIndex `:326`→`:321`，已修；第 2 轮干净）；§8 程序倒置由本复审追认（设计 P1 先行、P4 代码已合入待门 1 批）；§10 测试四问待 P5 全量后闭环；§11 本汇报先一句结论、白话优先。其余见 TEST_CASES 复审补项（T-72…84）。

#### 2. 依赖与生命周期
- 前置：tcp 层（DependsOn；缺 tcp 自动补，tcp DependsOn ip 连带补全）；tls 为 OptionalOn（声明保留，真升级另立项）。
- 资源：无状态生成器；翻译在 ValidateSpec 同步期（幂等覆盖写）；空层 config 翻译出 `&IMAPConfig{}` 非 nil（生成器走默认空会话，与 legacy `imapConfig==nil→&IMAPConfig{}` 同款 `planner.go:309`；commands/idle/mime_body 嵌套 JSON 往返自动，FileSource `file/literal/fill/random` 键与 `filesystem.FileSource` tags 对齐零分叉，见 `strategy_convert.go:1477`）。
- flat 权威判据：简单 nil 判（扁平侧条件创建，复审 smtp R6 同款：`if spec.IMAP != nil return`，扁平侧无 ftp 式恒非 nil，空 `imap:{}` 建空壳走 flat 权威与 presence 判死自洽）。

#### 3. 主流程与状态
- 四状态：NOT-AUTHENTICATED（STARTTLS/AUTHENTICATE/LOGIN，§6.2）→AUTHENTICATED（ENABLE/SELECT/…/IDLE，§6.3）→SELECTED（CLOSE/…/UID，§6.4）→LOGOUT（§3 图例⑦；BYE + tagged completion + 挥手）。回放不 enforcement 状态机（smtp 同款架构选择，C 类如实注明）：错序由用户写 NO/BAD Responses 台词表达（离线 `TestIMAPPoint_3_19_4_1_TagMismatchReplayed` 先例）。
- 翻译顺序：判死（顶层 imap 出现即拒）→ 层 config 翻译（JSON 往返，commands/idle/mime 嵌套自动）→ 协议 validator（23 分支真拦沿既有）。
- 动态解析：本期 imap 业务无动态，worker resolveLayerTuple 只解四元组（flows=2 时 imap 层留空防静态复制）。

#### 4. 递增与覆盖规则 + 正交组合矩阵 + 业务动态清单
- 无新序号算法（框架 `resolveLayerTuple`（worker.go:316） + `spec.FlowIndex` 只读（worker.go:321）；imap planner 不读 FlowIndex，smtp 同款）。
- 动态整格（§12）：

  | 层.字段 | 开/关 | 面 | 覆盖 |
  |---|---|---|---|
  | imap.banner | 关 | 问候语无逐流变需求 | 注记 |
  | imap.commands | 关 | 序列语义 + tag 计数，逐流变破坏事务顺序 | 注记 |
  | imap.idle | 关 | 会话级单例（push/done/timeout 与命令轮绑定） | 注记 |
  | imap.mime_body（经 commands[]） | 关 | 静态信体；逐流变破坏 FETCH 确定性 | 注记 |
  | ip/tcp 四元组 | 开 | 框架白名单沿既有 | T-IMAP-62 附带（flows=2 双流四元组 distinct 由框架保底 `src_port+1`，不断言） |
- 正交组合：地址族×结构（IPv4 单会话×IPv6 单会话对称两格：T-IMAP-1 v4 + T-IMAP-62 v6）；端口档位（143 缺省/T-IMAP-1 + 993 显式/T-IMAP-61 + 空壳缺省/冒烟）；模式×方向（明文 `[ip,tcp,imap]` + IMAPS `[ip,tcp,tls,imap]` 改写的 over_tls 对称）。
- 静态门业务逃生口：imap 业务全关→flows=2 例无动态逃生，留空防静态复制（smtp T-024 同款：无显式标量四元组，src_port 保底+1）。

#### 5. 错误与异常
- 新锚词：`protocol imap no longer accepts a top-level imap sub-config (move it into the imap layer of an [ip,tcp,imap] layers chain)`（mqtt/dns/smtp/pop3 文案同构）。
- 既有锚词沿用 23 分支（字面子串）：`is not a valid IP address`（T-IMAP-63）/`out of range [536,65535]`（T-IMAP-53，tcp 层 V9 门字面，smtp T-020/pop3 T-24 同款；`too small` 系 legacy planner 门，仅扁平路径覆盖）/`Tag length`（T-IMAP-66）/`contains SP/CRLF`（Tag SP 门 T-IMAP-72，转离线 `TestIMAPValidate_TagWithSpace`）/`contains CRLF`（T-IMAP-67，转离线 `TestIMAPValidate_CRLFInjectionRejected`）/`split into multiple entries`（Response CRLF 门 T-IMAP-73，转离线 `TestIMAPValidate_ResponseWithCRLFRejected`）/`non-ASCII`（T-IMAP-50）/`exceeds max`（Responses 上限 T-IMAP-84 小载荷断文案；Push/Literal 上限离线/设计注记，不断全量构造）/`decode error`（T-IMAP-68）/`mutually exclusive`（Literal 互斥 T-IMAP-74/MIME 互斥 T-IMAP-83）/`EmitIDLE=true but IMAPConfig.IDLE is nil`（T-IMAP-69）/`CancelAfterResponses`（越界 T-IMAP-75，转离线 `TestIMAPValidate_CancelAfterExceedsResponses`）/`PushResponses[0] contains CRLF`（T-IMAP-76，IDLE 块小载荷）/`must be one of`（T-IMAP-70）/`DoneTag` + `SP/CRLF`（T-IMAP-77，IDLE 块小载荷）/`DoneResponse contains CRLF`（T-IMAP-71）。
- Failing 先行 4 红例：①顶层 `{"imap":{}}` 空映射 create 即 400（现状放行——presence 未判死）；②扁平无端口 legacy 形 DstPort=0（现状：无 `setDefaultDstPort` 调用，注释亦无）；③层 `{"imap":{"banner":"…"}}` 报 unknown field 或包内无 banner（现状：registry 零 Fields + 无翻译分支）；④层 commands 翻译后 spec.IMAP.Commands 非空且包内见 tag（现状：无分支，生成器走默认空会话）。
- 超早拒绝无落盘口径沿 d323068（presence/静态门/MSS 门在 writer 建文件前被拒，`.neg.pcap` 24B 头或零文件，mqtt/smtp/pop3 先例同款）。
- 四件事：失败返回=策略创建期 400（presence/Tag 越界等，任务根本不启动）或任务启动期 error（在库旧策略经 ValidationErrors）；会话命运=合成期拒绝无会话可继续（不产包），回放错序不断言重试；重试=无（回放语义不重试不重连，RST/FIN 沿引擎既有挥手）；超时=autologout/IDLE 29 分钟无时钟不断言（C 类，见明确不解决；IDLE timeout BYE 只建台词形）。

#### 6. 性能设计与验收
- 单包路径增量：presence 一次 map 查 + 缺省一行赋值 + Fields 登记（ValidateSpec/convert 同步期一次）；动态解析走框架（零新增）。回归口径：imap.json 全量 suite 耗时相对基线 ±10%；边界诚实声明：无吞吐/并发/内存目标数字（未测）。
- pcap 验收：imap.json 全量绿 + 落盘可复查（`imap.line/tag/command/isrequest/response/status/response_tag` + 握手/挥手）；网卡未跑。
- 背压/长时间：沿引擎既有（本期无新状态、无新锁、无新 sleep；literal 上限 100MB/Responses 上限 1 万/IDLE push 上限 1000 防内存 blowup 沿既有常量）；单流最大报文=literal/MIME 体（MSS 切段由 tcp 层承担）；队列上限/CPU 并行度沿引擎既有（本期零新增不断言具体数）。

#### 7. 实现顺序与回滚
- 步骤 0（failing 先行）：`internal/core/layers/imap_migrate_test.go` 新建 4 红例（presence 拒/DstPort 缺省 143/registry Fields 收录/层 banner+commands 翻译）。
- 步骤 1：`strategy_convert.go` CheckProtoFlat 加 imap presence 分支；步骤 2：`case "imap"` 补 `setDefaultDstPort(&spec, cfg, 143)`；步骤 3：`registry.go` 补 imap Fields 5 键；步骤 4：`chain_planner_translate.go` 加 `case "imap"`（P4 JSON 往返 + flat 权威；P5 修为 `ParseIMAPConfigFromMap` 单 parse 真相）；步骤 5：`go build` + vet + touched 包 `-race` + schemagen 重跑；P5：imap.json 改写 + T-IMAP-2…84 全量跑 + 校准回钉；P6：评审+提交+清库复核。
- 回滚：单提交逆序 revert（P4 代码与 P5 用例分两提交）。

#### 8. 验收
- 对应 T-IMAP-1…84（TEST_CASES P3 先行）。完成条件：4 红例先红后绿；imap.json 全量绿（RESULT 全量；二进制同代；门 2 四项绿：旧键零残留 + 全量绿 + 同代 + 反查绿）；touched 包 `-race` 绿；顶层 `imap` 字面零残留（cases 内）；schemagen 生成表已同步（`TestLayersGeneratedMatchesRegistry` 绿）；在库 imap 行清空（删前计数→备份→删→复核）。

#### 10. P6 完成回填（2026-09-17，门 3 已过）

#### 9. 关键决策对比

| 决策 | 候选 | 优劣 | 结论 |
|------|------|------|------|
| A presence 口径 | A1 空 map 也判死；A2 仅非空判死 | A1 mqtt/dns/smtp/pop3 先例（空即显式走默认）；A2 留空壳双轨 | 选 A1 |
| B 143 缺省走法 | B1 补 `setDefaultDstPort(143)`；B2 维持现状靠 FieldContract | B1 与 pop3 `:799`/smtp `:883` 同款行为对齐（legacy 扁平路径 DstPort=0 缺口）；B2 链上虽有 FieldContract 但 legacy 扁平无端口仍 0 | 选 B1（理由按 smtp 复审 R5：行为对齐） |
| C 业务动态 | C1 全关+理由；C2 开 banner/信箱名 | C2 有序会话 + tag 计数，开了测不出（commands 逐流变破坏事务顺序与 tag 确定性） | 选 C1，逐流变另立项口 |
| D 翻译走法 | D1 pop3/smtp 同款 JSON 往返；D2 ftp 同款复用 parseIMAP* | D2 需 export 三 parse 函数 + MIME/IDLE 嵌套手写解码，改动面大；D1 嵌套自动、FileSource 键直通零分叉 | P4 选 D1；P5 推翻→D2（JSON 往返经 `[]byte` 语义判死：mime_body 附件 `data` 裸文本非法 base64 即整包解码失败、spec.IMAP 留 nil，T-051/52/80/81 实测 7 包空流；复用 `ParseIMAPConfigFromMap` 单 parse 真相，见本条目末完成回填②） |
| E FileSource 链上 | E1 直通不断言可用（tftp 同款降级注记）；E2 接 PayloadCache 到 drive | E2 改 drive 签名 + Meta 承载，改动面大且 tftp 同款缺口未收 | 选 E1，真接通另立项 |
| F 超大 literal 负例 | F1 小载荷断上限文案变体；F2 构造 100MB literal | F2 MCP 建策略即卡死，测的是耐心不是门 | 选 F1（pop3 T-15 同款，不断全量构造） |
| G 问候原文亲验 | G1 台词 + 待亲验注记不删；G2 删待亲验行 | G2 丢商业映射地板线；G1 POP3 Dovecot 亲验口径同款（openssl/telnet 亲验列 P5 执行项） | 选 G1 |

#### 10. P6 完成回填（2026-09-17，门 3 已过）
- **P5 落地偏差（MCP 84/84 全绿）：** ①首跑 55/29 fail 全是断言侧问题：SELECT 响应 untagged+tagged 两包致后续包号整体 +1（SELECT 系 20 例逐例 +1 重钉）；②literal 体与下条命令 tshark 重组伪影（包 8 无 CRLF 体被拼进行：T-009 包 10 `helloA003`、T-079 包 13 `helloA004`，线包纯净，帧字节断整帧偏移 54 钉死）；③untagged 包不解 `response.status`（T-011 包 6、T-019 包 8，改断 tagged 包 7/9）；④T-053 锚词错用 planner 门 `too small`，实为 tcp 层 V9 门 `out of range [536,65535]`（smtp T-020/pop3 T-24 同款）；⑤DONE 裸 continuation 无 tag，tshark `imap.command` 为空是口径所限，IDLE 五例改断 `imap.line DONE\r\n`（T-001 问候语同款转义）；⑥随机 boundary 致 literal 头 `{N}` 逐跑漂移（T-051 `{6029→6033}`/T-080/T-081 同款），包 11 不钉死，MIME 确定性由包 12 首段帧断言 + 离线 `{N}==len` 精确断言覆盖。
- **P5 修真 bug（翻译分支 Parse 单一真相）：** 层 `case "imap"` JSON 往返解码进 `IMAPConfig`，`IMAPAttachment.Data` 是 `[]byte`（Go JSON 语义只认 base64 文本）——附件 `data` 裸文本（如 T-052 `up-body`）即整包解码失败、`spec.IMAP` 留 nil，mime_body 经链恒 7 包空流而扁平同输入正常（`parseIMAPMIMEBody` 直解 `[]byte(raw)`）。修：新增 `ParseIMAPConfigFromMap`（与扁平 `cfg["imap"]` 同 parse、同缺省；`strategy_convert.go:2945`），层分支改调（`chain_planner_translate.go:1174`）；failing 先行 2 红转绿（`imap_mime_translate_test.go` A/B，C 锁扁平真相回归锚；commands 嵌套 `data` 裸文本语义 = SMTP DataB64 家族 `[]byte(raw)` 逐字，`data_b64` 经 imap 构造器 `wrapBase64` 折 76 行——与 smtp 构造器逐字是两家语义，各自构造器为准）。touched 三包绿 + `-race` 绿；smtp 43/43、pop3 50/50 无误伤。
- **落盘：** 81 文件零孤儿（68 正文 + 13 `.neg.pcap`；3 超早拒绝无落盘系旧行为：T-053/T-064/T-065，smtp/pop3 先例同款；旧 `imap_smoke_01.pcap` 已删）。
- **在库 imap 清空：** 删前 strategies 63/tasks 130 → 删后 imap 0/0（mqtt 139/140、pop3 37/376、smtp 38/222 全留；备份 `/tmp/trafficgen-pre-imap-clear.db`；tasks 无跨协议 `strategy_ids` 引用）。
- **门 3 抽查三条：** ①§1 顶层迁入→imap.json 84 例 `layers` 形零残留（门 2-1 绿；T-064 系执法对象豁免）；②§5 presence→`strategy_convert.go:7671` CheckProtoFlat imap 分支，imap_t064 真实流程拒；③§1 翻译→`chain_planner_translate.go:1174` `ParseIMAPConfigFromMap` 单 parse 真相，T-052 落盘 MIME 体包 8 首段 `From: a@b.c` 帧字节钉死（整帧偏移 54）。

### D-MCP-1 MCP 顶层 mcp 子映射迁入层内 + think_time 死字段删除【P-PIPE #9 门1】

**门 1 开工对照表（§1–§15，2026-09-17 用户已批，证据=文档节/代码行/用例号）：**

| § | 本协议怎么满足 | 证据 |
|---|---|---|
| §1 层链唯一真相 | 顶层旧键去向：`src_ip`→`layers[ip].src`、`dst_ip`→`layers[ip].dst`、`src_port`→`layers[tcp].src_port`、`dst_port`→`layers[tcp].dst_port`（78 例显式 8081 原样进层——链上 stdio 缺省 22，丢了即变字节；缺省语义 stdio→22/HTTP→8081 由 validateSpecBase mcp 分支 + 翻译分支补齐，用户显式优先）、`count`→删（79 例全 `count:1`，缺省即单流）、顶层 `mcp` 子映射→`layers[mcp]`（MCPConfig 同名 21 键直迁）。现状：73 例 `[tcp,mcp]+扁平5键+顶层mcp` 双轨（且缺 ip 层，改写补），6 例纯扁平无 layers。目标形状：`{"layers":[{"ip":{"src":"10.0.0.1","dst":"20.0.0.1"}},{"tcp":{"src_port":12345,"dst_port":8081}},{"mcp":{"transport":"stdio","requests":[{"method":"tools/list"},{"method":"tools/call","params":{"name":"ping"}}]}}]}`。P4 必修：①`CheckProtoFlat` 加 mcp presence 分支（imap 同款文案，空 map 也死）；②注册表 mcp 补 Fields 21 键（原零 Fields=层内业务键 V9 全拒）；③`translateTerminalConfig` 加 `case "mcp"`（pop3/smtp/imap 同款 + flat 权威）；④`pipe_gate.sh:67` presence 名单加 mcp | mcp.json 79 例审计；`strategy_convert.go:1103`（flat 读）；`chain_planner.go:829-838`（stdio→22/HTTP→8081）；`registry.go:241`（零 Fields）；`pipe_gate.sh:67` |
| §2 策略/任务分工 | 沿框架语义；策略=单会话模板自带 `flow_control`，任务=多策略合跑+总封顶（`{taskID}-{strategyID}` 独立桶）；`flows=N` 同模板复制 N 条流（多会话=M 条独立四元组，16-mcp-design §7.16）；`spec` 不管数量；未写动态时仅 `src_port` 自动+1 保底（worker 12345+i），其余逐流不变如实声明 | MCPConfig 无 sessions（types.go:1907）；t043/44 多流例 |
| §3 五件套 | 会话表：一 flow=一 TCP 连接上一 MCP 会话：initialize 请求(up)→initialize 响应(down，版本降级 §7.1/T11)→notifications/initialized(up)→requests 逐条请求/响应→可选 rounds 重复→收尾归 tcp 层（shutdown 校准 termination，`layer_gen.go:584-588`）。三传输各一序：stdio 逐行 JSON（`:145-240`）；http_sse（GET 建 SSE 流→POST→202→SSE 推送，`:247-378`）；streamable（POST→JSON/SSE→DELETE/204 带内终止，`:386-533`）。事务序列=包序列即事务；通知按 Step∈[0,len(Requests)] 定点插入（`:221-232`）。关联关系：无（数据面全在同一 TCP 流内，无独立子流）。插入位置：终结层事件流直入 tcp 层，tcp 管握手/分段/挥手（legacy 3 包挥手 vs 链 4 包——全部包数 P5 落盘重钉，M6）。时间线：单流严格顺序无交错；id 配对全 0 自动 vs 全显式、混用拒（`mcp.go:167-185`） | `layer_gen.go:145-533`；`mcp.go:61-` Validator 19 分支 |
| §4 规范矩阵 | `docs/protocol-designs/16-mcp-design.md`（§2 报文三传输/§3 方法表 14+通知 6/§4.4 校验规则/§5 状态机/§6 Plan/§7 场景 §7.1-§7.19/§8 测试清单 T1-T104）+ JSON-RPC 2.0（错误码保留段 [-32700,-32000]）+ MCP spec 三版本（2024-11-05/2025-03-26/2025-06-18，严格枚举）+ 现网（stdio 本地 22/HTTP 远端 8081）。P1 矩阵见本条目 §9 表 + 三张子表（方法×响应码/形态变体/商业→用例） | 16-mcp-design.md；本条目 §9 |
| §5 有错必处理 | 既有 6 负例锚词沿用（caps 重键 `must be a JSON object`/mixed-id/空 method/非法版本/error-code 越界）；P5 补 validator 分支负例（transport/auth/state/负计数器/parts role/step 越界，锚词取字面）；新增顶层 mcp presence 锚词（P4，imap 文案同构）；依赖：mcp 层 DependsOn tcp；validator 19 分支链可达 14 + C 类 5（IP×2 走框架 ip 层门、config required 被翻译保底、legacy 空配置路径） | mcp.json 6 负例；`mcp.go:61-185` |
| §6 性能 | 单会话包数=3 握手+3 初始化+2×len(requests)×rounds+通知帧+挥手（stdio 4 包链式/legacy 3 包）；HTTP 形 POST/202/SSE 帧线性增；无锁无 sleep（事件模式，tcp 层管分段）；回归口径：mcp.json 全量 suite 耗时相对基线 ±10%；边界诚实声明：无吞吐/并发/内存目标数字（未测）；网卡未跑 | 本条目 §6 |
| §7 三份文档 | 设计=本条目；用例=T-MCP-1…103（P3 先行，存量 79 逐条审计去向）；cases 回指编号；16-mcp-design.md 是历史参考非权威（§7 既有文档保留条款），冲突以本条目为准 | TEST_CASES T-MCP-* |
| §8 先设计后代码 | 门 1 表批复→P1 矩阵（本条目 §9）→P3 清单→failing 先行 4 红例→P4 代码；无设计条目 Diff 打回 | 本条目 |
| §9 三源+整格 | 三源：16-mcp-design + JSON-RPC 2.0 + 现网（stdio/HTTP）；P3 清单先行（TEST_CASES T-MCP 表，规范行→用例逐行）；三场景缺口（复审场景分析 2026-09-17）：数据 5 补（rounds/shutdown/parts 请求侧/sampling parts/audio）+ 业务 4 补（双组合流/长任务全程/错误码 -32600/-32603 台词）+ 现网 4 补（streamable 全程/认证拒/能力门控 sampling/三家映射）+ 负例 6 补（presence/静态复制/transport/state/负计数器/parts role/step）——多会话部分失败（T45）=C 类（suite 每例单策略，flows=N 同模板复制无法逐流差异，任务级多策略另立项）；枚举全覆盖见反查表 65 项；正交：传输×版本×地址族（v4 全量+v6 冒烟 1）；断言边界：包序/时序 harness 注记，frames hex 落盘钉 | T-MCP 清单；`coverage_gate.py check_mcp` 65 项 |
| §10 评审闭环 | failing 先行 4 红例（presence 拒/层键收录/层 requests 翻译/ThinkTime 删除）→改→审→测→再审；`go vet` + touched 六包 `-race` | P4 |
| §11 白话汇报 | 先一句结论 | 每次汇报 |
| §12 动态清单 | 四元组开（框架 ip/tcp 白名单既有）。业务 21 键全关（allowlist 不加 mcp 行，smtp/pop3/imap 先例）：transport（载体选择非逐流值）/protocol_version-auth-state（协商开关与枚举校验面）/requests-responses-notifications（有序事务配对+id 配对+Step 定位，逐流变破坏配对确定性；mqtt 开 topic/payload 是槽位值可独立变，本协议 req/resp 是配对结构，不对称有理）/client_info-server_info-caps-parts-metadata-push（结构化对象无逐流变形状；caps 缺省=省略字段，动态注入破坏线形）/id_counter-rounds（计数器）/session_id（缺省随机 32hex 不可逐流确定性，显式值即静态）/base_url-context_id-parent_id（字符串标注）/shutdown（收尾开关）。`think_time` 死字段 M1-E1 删除（生成器零消费，http ThinkTime E1 先例"语义永远假"；见本条目 §9 决策 A）。无业务序号算法（idCounter 是请求编号非流序号，`mcp.go` nextID）；四元组走框架 `resolveLayerTuple`。validate-only 字段注记：context_id/parent_id/metadata/push_notification/parts 顶层字段经 validator 校验但生成器不消费（_meta 家族靠 requests params 内联上線，t046/47/69/70 证据）——注入实现 B 类另立项，不删（不属本期范围） | `layer_dyn.go:17-50`（无 mcp 行）；`validate_layers.go:157`；`layer_gen.go:39-42` |
| §13 schema 同步 | 注册表 mcp Fields 0→21 键（一律不设 Default：零值即设计缺省 transport 空→stdio/version 空→2024-11-05/Shutdown nil→true/caps 空→{}；Default 注入会污染 RawMessage 破坏"caps 缺省=省略字段"线形）；CheckProtoFlat 加 mcp presence；`pipe_gate.sh` presence 名单加 mcp；改完重跑 schemagen（生成表 65 行 mcp 段同步，`TestLayersGeneratedMatchesRegistry` 绿）；MCPConfig 删 think_time 无派生面（schemas/web/mcp 描述零引用，实测 grep） | 门 2 脚本；`generated/layers.generated.json` |
| §14 真实流程 | mcp.json 全量绿 + 落盘 `/tmp/mcp-pcaps/mcp/` + 二进制与 HEAD 同代 + 门 2 四项（`pipe_gate.sh mcp`）；负例 `.neg.pcap` 口径沿 d323068；包号/端口全部落盘重钉不照抄（M5/M6：78 例显式 8081 进层、tpos2 无 dst_port 由 stdio 缺省 22 承接——legacy 扁平 80 是偏差，链上 22 才是设计值；挥手 3→4 包） | T-MCP-* |
| §15 三道门 | 本表即门 1（已批）；门 2 脚本（mcp presence 红线已接：dns/mqtt/smtp/pop3/imap/mcp 六协议同口径）；门 3 挂表抽查；P5R 反查 `check_mcp` 65 项已登记（探针 9/65，MISS 56 项=P5 补例清单） | 本条目 |

**状态：** P6 已验收（2026-09-18；门 1 已批→P4 4 红转绿→touched 六包 `-race` 绿→P5 首跑 88/103 六类修→103/103 + 反查 65/65 + 门 2 四项绿→在库 mcp 清空 88/9437→门 3 抽查见下）
**范围（P4）：** ①`CheckProtoFlat` 加 mcp presence 判死；②`registry.go` mcp Fields 21 键；③`translateTerminalConfig` 加 `case "mcp"`（JSON 往返 + flat 权威 + HTTP 形缺省端口修正）；④`MCPConfig` 删 `ThinkTime` 死字段（M1-E1）；⑤schemagen 重跑生成表同步；⑥`pipe_gate.sh` presence 名单 + `coverage_gate.py` check_mcp 65 项登记。
**范围（P5/P6）：** 79 存量例层链改写 + 24 新例（T-MCP-80…103）；首跑 88/103 六类修（①9 例帧钉从落盘 pcap 取包号/偏移重钉——响应帧在第 8 包非预测第 9、DELETE 在第 10 包、feature 字符串居 JSON 中段非帧首；②t081 shutdown:false 无挥手撤 terminates；③t083 ping 补 id:4 解混用拒；④t043/t044 显式标量四元组+flows>1 触静态复制门→tcp.dst_port 改 fixed 策略对象语义不变；⑤t091 strategy_fc 须在 case 顶层 suite 才读、spec_json 内不生效（t043 先例）→归位+全缺省空层 28 包；⑥t092 同⑤）；coverage_gate 版本证据补 wire 帧钉通道（t011 降级 2024-11-05 钉响应帧，与登记口径"t011 附带"对齐——wire 钉死强于配置回显）；在库 mcp 清空（删前 strategies 88/tasks 9437 报数→备份 bak-20260918-085145→删→复核 0/0，总任务 259941−9437=250504 恰合，非 mcp 任务引用 mcp 策略删前删后均 0）。
**门 3 抽查三条（14 行对照表抽 §1/§13/§14）：**
- §1 层链唯一真相：`strategy_convert.go:7676` mcp presence 分支（空 map 也死，t090 `mcp_t090_presence_reject` validate-negative 锚词 top-level 过）+ 门 2-1 绿（103 例 spec_json 顶层 src_ip/dst_ip/src_port/dst_port/count/mcp 零残留）+ 目标形状 tpos1 三层 `[ip,tcp,mcp]` 实测 14 包绿。
- §13 schema 同步：`registry.go:249` mcp LayerSchema 21 Fields 全无 Default（`:268-269` id_counter/rounds 负值交 validator Rule 8/9，t097/t098 锚词拒）+ `chain_planner_translate.go:1175` case "mcp"（flat 权威不覆盖）+ 生成表 `layers.generated.json` schemagen 重跑同步（TestLayersGeneratedMatchesRegistry 绿）。
- §14 真实流程：suite 103/103 经 flowb MCP 建任务→引擎→pcap 断言全链真实路径；帧钉全部从落盘 pcap 重钉（t011 `mcp_t011_stdio_protocol_version_downgrade` 帧断言 packet5 `"protocolVersion":"2024-11-05"` wire 钉死；t093 `mcp_t093_error_32600` packet8 offset94 `-32600` 台词）；负例 13 例 `.neg.pcap` 标记 + t090 presence create 阶段 400 无任务（对账 89+13=102 落盘零孤儿）。
**明确不解决：** TLS 底座组合 `[ip,tcp,tls,mcp]`（M2：未验不登 OptionalOn，验证后另立）；状态机 enforcement（回放语义 C 类，§5.6 禁止跳转靠 validator 分支负例锁不靠引擎）；validate-only 五字段（context_id/parent_id/metadata/push_notification/parts）的 _meta 注入实现（B 类另立项，t046/47/69/70 证明 params 内联已可表达）；任务级多策略"多会话部分失败"（T45，C 类：suite 每例单策略）；JSON-RPC Batch（§2.6，生成器无 batch builder，T81-85 设计有、码无——B 类另立项不冒充）；MCP over Unix socket/真 stdio 管道（TCP 承载即本协议语义）。
**依据：** `docs/protocol-designs/16-mcp-design.md`（历史参考：§2 报文/§3 方法表/§4.3 缺省/§4.4 Validate 14 规则/§5 状态机/§6 Plan/§7 场景/§8 T1-T104）；JSON-RPC 2.0 spec（错误码段）；MCP spec 2024-11-05/2025-03-26/2025-06-18（版本严格枚举依据）；代码事实：`mcp/layer_gen.go:61-139`（Generate 默认化+传输分发）/`:145-533`（三传输事件序）/`:567-591`（注册+握手挥手校准）、`mcp/mcp.go:61-185`（Validate 19 分支）、`mcp/plan.go:29-130`（legacy Plan 缺省+端口）、`mcp/http_plan.go:22-160`（HTTP 帧构造）、`types.go:1907`（MCPConfig 22 字段→删 think_time 后 21）、`chain_planner.go:829-838`（DstPort mcp 分支）。

**§9 规范矩阵（P1，规范要求 → 业务场景 → 代码现状 → 缺口→用例）：**

| 规范行 | 业务场景 | 代码现状 | 缺口→用例 |
|---|---|---|---|
| JSON-RPC 2.0 包结构（jsonrpc/id/method/params/result/error） | initialize→业务→收尾全序（T-1 改写冒烟） | 已实现（builder 纯函数+行分隔） | 改写 T-1 |
| §2.2 错误码保留段 [-32700,-32000]（+sampling -1 特例） | 六码台词：parse/invalid request/method not found/invalid params/internal/resource not found/reject | 已实现（responses 原文回放；Rule 13 拒正数） | t050/tpos6/t052/t092/t093 有；-32600/-32603 缺→T-93/94 |
| §2.3 stdio 行分隔 JSON | 默认序列/换行转义/teardown 序列 | 已实现 | t002/t029/t064/t071a/b/t077/t102a/b 有 |
| §2.4 HTTP+SSE（GET 先于 POST/endpoint 事件/202/Mcp-Session-Id） | 会话建立/认证头/auth in response | 已实现（http_plan.go 帧构造） | tpos7/t036/t038 有；全程含 DELETE→T-87 |
| §2.5 Streamable HTTP（POST→JSON/SSE/DELETE 204 带内） | 会话建立/Basic 认证 | 已实现 | tpos8/t037 有；全程→T-87 附带 |
| §3.1 生命周期（initialize 协商/降级/initialized 通知/ping） | 降级 t011/ping 三变体 t102 | 已实现（响应恒 2024-11-05） | t011/t024/t064/t102a/b 有 |
| §3.2 工具（tools/list 分页/tools/call/isError/image/未知工具） | 分页 t100/isError t015/image t016/-32602 t017 | 已实现 | t013-17/t072/t100/t104 有 |
| §3.3 资源（list/read 文本 blob 404/subscribe+updated/templates/unsubscribe 版本门） | t019-22/t038/t051/t063/t071/t072-73 | 已实现 | 已有；无缺口 |
| §3.4-3.5 提示词/补全（prompts list/get 多角色/parts 响应/complete） | t009/t023/t025/t026/t068 | 已实现 | 请求侧 parts（sampling）→T-82 |
| §3.6 日志（setLevel/message 推送） | t011/t066 | 已实现 | 已有 |
| §3.7 通知（cancelled requestId/progress token） | t029/t040/t047/t054/t080 | 已实现 | step 越界负例→T-99 |
| §3.8-3.9 roots/sampling（S→C 反查/全字段/stopReason/temperature/reject -1） | t032-34/t041/t053/t055/t062/t076/t086-89 | 已实现 | 能力门控 sampling 缺→T-89 |
| §3.10 扩展表 31 字段 | content 五类型/state 六值/auth 三方案/caps 双向 | 已实现（validator 枚举） | audio 缺→T-100；auth 拒→T-88；state 拒→T-96 |
| §4.4 Validate 14 规则（19 分支） | 正负各一 | 已实现 | 链可达 14 支收口→T-88/90/92/95/96/97/98/99 + 既有 6；C 类 5 支注记 |
| §5 状态机（会话五态/长任务六值） | 长任务四终态 t039-42 | 已实现（回放） | 全程流→T-85；state 负值→T-96 |
| §6 Plan（缺省序列/多轮/收尾开关） | rounds/shutdown | 已实现（layer_gen 默认化） | rounds>1→T-80；shutdown:false→T-81 |
| §7.16 多会话（M 条独立四元组/id 独立） | flows=3 t043/t044 | 已实现（引擎逐流 Plan） | 全缺省双流→T-91；部分失败 C 类注记 |
| §7.18-7.19 边界/异常 | caps 空对象/省略/重键 | 已实现 | t053/t065/t089/t090/t099 有 |

**方法×响应码矩阵（§4 子表①，回放语义：响应是用户写原文，逐方法成功例已覆、错误例按码收口）：** 14 业务方法各有 ≥1 成功例（T-1…79 改写面）；错误码七值——-32700 t050/-32601 tpos6+t063/-32602 t052+t062+t102b/-32002 t092/-1 t093 有，-32600→T-93、-32603→T-94（P5）；isError 工具层错 t015 与协议层 error 区分已锁。

**数据形态变体表（§4 子表②）：** stdio 行 JSON（t002 转义）｜SSE endpoint 事件（tpos7）｜streamable JSON vs SSE 响应（tpos8/t088 交错通知）｜caps 空/省略/对象/字符串含重键（t053/t065/t089/t090/t099）｜ping params 三变体（t102a/b）｜roots/list 无 params（t101）｜unsubscribe 双版本门（t071a/b）｜sampling 全字段/temperature/reject（t034/t062/t093）｜state 四终态+无 state progress（t039-42/t080）｜shutdown 开关（缺省+T-81）｜rounds（缺省+T-80）。

**商业行为→用例映射表（§4 子表③）：**

| 商业行为 | 出处 | 用例 | 状态 |
|---|---|---|---|
| Claude Desktop 客户端形（clientInfo claude-desktop + roots/sampling caps） | 16-mcp-design §3.1 示例 + Anthropic Desktop 文档 | T-MCP-101 | P3 建（台词地板线） |
| Cursor 客户端形（自定义 clientInfo/tools caps） | Cursor MCP 文档 | T-MCP-102 | P3 建（tpos4 notes 已含 cursor 字样附带） |
| flowB 服务端形（serverInfo name=flowB + tools listChanged） | 16-mcp-design §1.1（产品名 flowB 声明） | T-MCP-103 | P3 建（server_info 显式） |

#### 1. 数据与接口
- 输入：`[ip, tcp, mcp{21 键}]`（mcp 层缺席键走 MCPConfig 零值→生成器默认会话：缺省 requests=[tools/list, tools/call ping]、version 2024-11-05、transport stdio、rounds 1、shutdown true）。
- 输出：3 握手 + initialize 请求/响应 + initialized + requests×rounds 请求/响应 + 定点通知 + 挥手（链 4 包；streamable 另有 DELETE/204 带内帧；shutdown:false 无挥手帧）。
- 修改点四处（builder/emit/http_plan 零改动）：`strategy_convert.go` CheckProtoFlat 加 mcp presence 分支；`registry.go` mcp Fields 21 键；`chain_planner_translate.go` 加 `case "mcp"`；`types.go` 删 ThinkTime。新增函数：无（JSON 往返复用 pop3/smtp 形；MCPConfig 无 []byte 业务字段，无 imap 式判死）。
- 显式覆盖：层值是 mcp 全配置唯一真相；flat `cfg["mcp"]` 出现即判死（presence，空 map 也死）。

#### 2. 依赖与生命周期
- 前置：tcp 层（DependsOn；缺 tcp 自动补，连带补 ip）。tls 不登 OptionalOn（M2 未验）。
- 资源：无状态生成器（每 flow 一 MCPGenerator.Generate，sessionID 每会话一随机）；翻译在 ValidateSpec 同步期（幂等覆盖写）。

#### 3. 主流程与状态
- 翻译顺序：presence 判死（create 期 400）→ validateSpecBase（mcp DstPort 缺省：spec.MCP 为 nil 时按 stdio→22）→ translateTerminalConfig `case "mcp"`（JSON 往返 + HTTP 形缺省修正 8081）→ mcp validator（19 分支）→ tcp/udp 层值回填（用户显式 dst_port 最终覆盖）。
- 端口优先级：tcp 层显式 > 翻译后 transport 缺省（HTTP 8081/stdio 22）> validateSpecBase stdio 缺省。legacy 扁平路径 dst_port=80 是 universal default 偏差（tpos2 notes 实录），链上 22 才是设计值——P5 改写后该偏差消亡。
- 回放语义：requests/responses 原文回放，状态机不 enforcement（C 类如实注明）。

#### 4. 递增与覆盖规则 + 正交组合矩阵 + 业务动态清单
- 无新序号算法（框架 resolveLayerTuple；idCounter 是请求编号非流序号）。
- 业务动态整格（§12，21 键全关，理由见门 1 表 §12 行；allowlist 不加 mcp 行）。
- 正交组合：传输 3 × 版本 3（显式三值各 ≥1 例+缺省）× 地址族（v4 全量 + v6 冒烟 T-86）× flows（1/2/3）。

#### 5. 错误与异常
- 新锚词：`protocol mcp no longer accepts a top-level mcp sub-config (move it into the mcp layer of an [ip,tcp,mcp] layers chain)`（imap 文案同构）。
- 既有锚词沿用（P5 全量收口）：`must be a JSON object`/`mixed auto and explicit id assignment`/`requests[0].method is required`/`invalid protocol_version`/`responses[0].error.code=… out of JSON-RPC reserved range`；P5 新增负例锚词：`invalid transport`/`invalid auth scheme`/`invalid state.initial`/`id_counter must be >= 0`/`parts[0].role`/`notifications[0].step=`。
- Failing 先行 4 红例（已全红后转绿）：①顶层 `{"mcp":{}}` 空映射 presence 拒；②层 `{"mcp":{"transport":…,"requests":…}}` V9 放行（原 unknown field）；③层 requests 翻译上線（原 spec.MCP nil→"mcp config is required"）；④`MCPConfig` 无 ThinkTime（反射锁）。

#### 6. 性能设计与验收
- 单包路径增量：翻译 21 键 JSON 往返一次（ValidateSpec 同步期）；动态解析零新增（业务全关）。回归口径：mcp.json 全量 suite 耗时相对基线 ±10%；边界诚实声明：无吞吐/并发/内存目标数字（未测）。
- pcap 验收：mcp.json 全量绿 + 落盘可复查（stdio JSON 行帧 hex + HTTP 请求行/状态行 + SSE 事件 + tcp.dstport 8081/22）；网卡未跑。

#### 7. 实现顺序与回滚
- 步骤 0（failing 先行）：`internal/core/layers/mcp_migrate_test.go` 4 红例（已完成，全红确认）。
- 步骤 1：CheckProtoFlat mcp presence；步骤 2：registry 21 键；步骤 3：translate `case "mcp"`；步骤 4：删 ThinkTime；步骤 5：schemagen 重跑 + build/vet/touched 六包 `-race`；P5：mcp.json 79→103 改写+新建 + 全量跑 + 校准回钉；P6：评审+提交+清库复核（dev 库 mcp 0/0，删前重报）。
- 回滚：单提交逆序 revert（P4 代码与 P5 用例分两提交）。

#### 8. 验收
- 对应 T-MCP-1…103（TEST_CASES P3 先行）。完成条件：4 红例先红后绿；mcp.json 全量绿（RESULT 全量；二进制同代；门 2 四项绿）；touched 包 `-race` 绿；顶层 `mcp` 字面零残留（cases 内）；schemagen 生成表同步；在库 mcp 行清空复核。

#### 9. 关键决策对比

| 决策 | 候选 | 优劣 | 结论 |
|------|------|------|------|
| A think_time 去留（M1） | A1 删除（E1）；A2 留解析注记假语义（E2）；A3 真实现 sleep（E3） | 全仓零消费（生成器/引擎/派生面 grep 实证）；E2=http 教训"语义永远假"；E3 无包时间戳载体且拖慢 suite | 选 A1（http E1 先例；设计文档 16-mcp-design 系历史参考不绑定） |
| B 翻译走法 | B1 JSON 往返（pop3/smtp 同款）；B2 导出 ParseMCPConfigFromMap（imap 同款） | imap 判死根因是 []byte 附件；MCPConfig 无 []byte 业务字段（caps 是 RawMessage JSON 文本，往返无损且与扁平 parseMCPConfig 同路径字节一致） | 选 B1 |
| C 端口缺省 | C1 仅靠 validateSpecBase（stdio 22）；C2 translate 后按 transport 修正 HTTP 形 8081 | C1 对 http_sse/streamable 无显式端口的链给错 22（validateSpecBase 时 spec.MCP 尚 nil）；C2 与 legacy plan.go:61-68 对齐，tcp 层显式值由层值回填最终覆盖不抢占 | 选 C2 |
| D presence 口径 | D1 空 map 也判死；D2 仅非空判死 | D1 imap/mqtt/smtp/pop3/dns 先例（空即显式走默认）；D2 留空壳双轨 | 选 D1 |
| E OptionalOn tls | E1 本期登记；E2 不登（M2 验证后另立） | E2 诚实：链未验不承诺；E1 若链不可跑即虚假登记 | 选 E2 |
| F caps Default 注入 | F1 Fields 不设 Default；F2 设 Default `{}` | F2 completedConfig 注入使 RawMessage 恒非 nil，破坏"caps 缺省=省略字段"线形（16-mcp-design §4.3/规则 6）；F1 零值即设计缺省 | 选 F1 |

### D-SRV6-1 SRv6 顶层 srv6 子映射迁入层内（raw-IP 终结层）+ hop_by_hop 归 ip 层【P-PIPE #10 门1】

**门 1 开工对照表（§1–§15，2026-09-18 用户已批"开工"；P1 矩阵已复审，复审纠错 5 硬伤+2 不准已回填本条目；证据=文档节/代码行/用例号）：**

| § | 本协议怎么满足 | 证据 |
|---|---|---|
| §1 层链唯一真相 | 顶层旧键去向：`src_ip`→`layers[ip].src`、`dst_ip`→`layers[ip].dst`（vn07 的 v4 src 保留=VR-06 负例）、`src_port`/`dst_port`→`layers[srv6].inner_src_port/inner_dst_port`（内层端口是 SRH 载荷语义非链上传输层端口；层内已有 inner 值的 13 例删顶层影子端口；无 inner 影子的单流例 bnd06 显式迁 inner_src_port:2222）、`count`→删（2 例全 =1，包数由 frames 承担）、顶层 `srv6` 子映射→`layers[srv6]`（16 键直迁）、`hop_by_hop`→`layers[ip].hop_by_hop`（新字段，vlan 先例）、`dst_mac` 顶层保留（单例 vp04，raw-IP drive 读 spec.DstMAC；L2 字段不在扁平五键内）、`mpls`/`gre` 顶层保留（vn18/19，v1 不实现嵌套=设计 §1.4，链上与 legacy 同款静默忽略）、`group_id` 顶层保留（flow_control 家族非扁平四元组）。现状 68 例全扁平（50 例 v6+srv6/6 例带内层端口/2 例 group_id/1 例 count/1 例 HBH/1 例 dst_mac/mpls+gre 各 1/vn01 无 srv6）。目标形状：`{"layers":[{"ip":{"src":"2001:db8::1","dst":"2001:db8::2"}},{"srv6":{"segment_list":["2001:db8::2"],"seg_type":"end","payload_protocol":"udp","inner_dst_port":53,"inner_payload":"12345678"}}]}`。P4 必修：①`CheckProtoFlat` 加 srv6 presence 分支（mcp 同款文案 `[ip,srv6]`，空 map 也死）；②注册表 srv6 Fields 16 键全无 Default；③`translateTerminalConfig` 加 `case "srv6"`（复用扁平 parse 单一真相，非 JSON 往返——inner_payload []byte 的字符串语义 getByteSlice 直取原文，往返会 base64 误读）；④`pipe_gate.sh:67` presence 名单加 srv6 | srv6.json 68 例审计；`strategy_convert.go:1046`（flat 读）；`parseSRv6Config:5233`（getByteSlice 字符串=原文字节）；`registry.go` 无 srv6；`pipe_gate.sh:67` |
| §2 策略/任务分工 | 沿框架语义；策略=一条 SR Policy 模板（segment_list 等 16 键）自带 `flow_control`；任务=多策略合跑+总封顶（`{taskID}-{strategyID}` 独立桶）；`flows=N` 同模板复制 N 条流（内层端口 0→spec.SrcPort 逐流回退=worker 12345+i 保底，e2e04 实测 12345→12444 全唯一）；`spec` 不管数量；`frames` 是单流多帧（Hop Limit 递减序列）与 flows=N 复制是两个维度，如实分开声明 | SRv6Config 无 sessions（types.go:10168）；e2e04/mf03/mf05 多流例；bnd06 frames=1000 |
| §3 五件套 | **豁免+替代面**（单包载荷协议，设计 §1.3"不是会话状态机"）：会话表=豁免（SRH 无状态扩展头，一 flow=N 帧同模板）；事务序列=豁免（单包即全部，frames 多帧等间隔 Hop Limit 64,63,…,1,255 回绕永不 0——bnd06 帧断言）；关联关系=豁免（无控制/数据流分离）；插入位置=srv6 终结层自产完整包（raw-IP 驱动，nvgre/igmp 先例），builder 只按 L2 补 MAC；时间线=单流顺序无交错，"视角递增"按 RFC 8754 §4.3.1.1 由多条 FlowSpec 表达（设计 Frames NOTE 显式声明），单用例内不冒充。业务"多动作"以协议形态组合替代组合流：组合流A=HBH 链+SRH+TLV+多段（T-72 新建）、组合流B=down 反转+HMAC TLV+显式内层端口+多段（T-73 新建） | `planner.go:39-60`（每 flow N 帧）；`bnd06` 帧断言；设计 §1.4 |
| §4 规范矩阵 | `docs/protocol-designs/15-srv6-design.md` v2.0.2（历史参考非权威，§7.4 保留条款）：§2 反序存储/§3 消息结构/§4 处理视角/§5 配置/§6 S1-S16 HexDump/§8 VR-01–23+DR-01–13+DD-01–07 + RFC 8754（§2/§2.1/§4.1/§4.1.1/§4.3.1.1/§8.2）+ RFC 8200（§3/§4.3/§4.4/§4.7/§8.1）+ RFC 8986（End* 命名参考）。P1 矩阵（含复审纠错终版）见本条目 §9 表 + 三张子表 | 15-srv6-design.md；本条目 §9 |
| §5 有错必处理 | VR-01–23 全量锚词核对（子表①）：22/23 有例，仅 VR-22 缺（T-69 新建）；VR-01 链上不可达（空层翻译保底非 nil，mcp D-MCP-1 §5"config required 被翻译保底"同款 C 类）→vn01 作废合入 vn02；VR-16/17 链上不可达（gre/mpls 解析在 switch protocol :457 之内，universal 段 :380-455 不含——suite 路径子映射静默忽略与 legacy 一致，锚词由 planner_test.go 覆盖=C 类注记）；依赖：srv6 层 DependsOn ip（v6 地址判族），validator=RegisterLayerValidator("srv6", Validate) 23 分支链上同步拒 | `validate.go:13`（VR-01–23）；子表① |
| §6 性能 | 单流包数=frames（缺省 1；bnd06=1000 压力锚，Hop Limit 回绕序列帧断言）；生成器包装 legacy Plan（channel 流式 256 缓冲，无全量收集，无锁）；SRH 序列化每包 O(段数)+TLV 对齐；翻译一次（ValidateSpec 同步期）；回归口径：srv6.json 全量 suite 耗时相对基线 ±10%；边界诚实声明：无吞吐/并发/内存目标数字（未测）；网卡未跑 | planner.go channel 256；本条目 §6 |
| §7 三份文档 | 设计=本条目；用例=T-SRV6-1…74（P3 先行，存量 68 逐条审计去向：67 改写+vn01 作废+6 新建）；cases 回指编号；15-srv6-design.md 是历史参考非权威，冲突以本条目为准 | TEST_CASES T-SRV6-* |
| §8 先设计后代码 | 门 1 表批复→P1 矩阵+复审→P3 清单→failing 先行 5 红例→P4 代码；无设计条目 Diff 打回 | 本条目 |
| §9 三源+整格 | 三源：RFC 8754/8200/8986 + 15-srv6-design（历史）+ 现网（Linux seg6/厂商 SR Policy=待确认两项，确认方式：抓 Linux 内核发包+查 iproute2 文档版本）；P3 清单先行（T-SRV6 表规范行→用例逐行）；存量 68 例逐条审计（9.14）；枚举全覆盖=seg_type 29 值（重点 9+字符串合法口径，设计 §3.4）/payload 7 值全有/TLV 类型正 0,4,5,200+负 1,2,6（**3 缺→T-71**）/reduced 三态（显式 false 缺→T-70）/tag 三值/方向 2/frames 4 形/段数 0,1,2,3,5,126,127,128；正交：载荷×段数×reduced×TLV×方向×flows；地址族**单族协议**（v6 全量+v4 必拒负例 vn07，矩阵登记说明）；组合流 2 条=A（HBH+TLV+多段，T-72）B（down+HMAC+内层端口，T-73）；断言边界：包序/时序 harness 注记，SRH 帧字节落盘钉（tpos 系列已有帧 hex 先例） | T-SRV6 清单；`coverage_gate.py check_srv6`（P4 登记） |
| §10 评审闭环 | failing 先行 5 红例（presence 拒/层键 V9 放行/层翻译上线/inner_payload 字符串字节语义/down 不双换）→改→审→测→再审；`go vet`+touched 包 `-race` | P4 |
| §11 白话汇报 | 先一句结论 | 每次汇报 |
| §12 动态清单 | 四元组开（框架 ip 白名单既有；ip.src/dst 动态对象=多流例静态复制门逃生口，mcp t043/44 先例；内层端口 0→spec 逐流回退=worker 保底）。业务 16 键全关（allowlist 不加 srv6 行，mcp/smtp/pop3/imap 先例）：segment_list（SR Policy 路径本体，逐流变破坏路径语义）/segments_left-last_entry（指针三态=视角选择器）/reduced（同）/flags（RFC 全 0 硬约束 VR-08）/tag-seg_type-payload_protocol（枚举选择器非逐流值）/tlv（结构化对象）/src_ipv6-dst_ipv6（与 ip 层重复的显式覆盖键）/frames-direction（帧数与方向开关）。inner_payload/inner_src_port/inner_dst_port 三键同关（载荷与内层端口逐流变破坏 FlowID 配对语义；逐流差异化走 flows=N+worker 端口保底）。无业务序号算法（SegmentsLeft 是 SRH 字段值非流序号）；四元组走框架 resolveLayerTuple | `layer_dyn.go`（无 srv6 行）；types.go:10168 字段注释 |
| §13 schema 同步 | 注册表 srv6 Fields 16 键（一律不设 Default：mcp 决策 F 先例——SegmentList 缺省 [] 会污染空层"VR-02 必拒"线形；零值即设计缺省 SL=len-1/LE=len-1|len-2/reduced 按 seg_type/frames 1/dir up 由生成器 resolve* 承担）；ip 层加 `hop_by_hop` 字段（Type object，tpos17 承接）+ ValidateSpec ip 层回填 spec.HopByHop（finalEmit :345 既有消费点）+ 导出 `core.ParseHopByHopOptions`（layers 反向依赖禁忌，imap ParseIMAPConfigFromMap 先例）；导出 `core.ParseSRv6ConfigFromMap`（translate 复用扁平 parse 单一真相）；CheckProtoFlat 加 srv6 presence；`pipe_gate.sh` 名单加 srv6；改完重跑 schemagen（`TestLayersGeneratedMatchesRegistry` 绿） | 门 2 脚本；`generated/layers.generated.json` |
| §14 真实流程 | srv6.json 全量绿 + 落盘 `/tmp/mcp-pcaps/srv6/` + 二进制与 HEAD 同代 + 门 2 四项（`pipe_gate.sh srv6`）；负例 `.neg.pcap` 口径沿 d323068；包号/端口/帧字节全部落盘重钉不照抄（M5/M6：①顶层端口删影后 udp.srcport 断言以落盘为准——new03 回退链 spec.SrcPort=12345 与 legacy 同值、bnd06 显式迁 inner 后 2222 保持；②tpos2 inner_dst_port:8080 层内已有值，删顶层影子不改字节；③down 双换修复后 mf04/tpos13 的 L3 地址/MAC 以落盘重钉）；黄项登记：顶层 mpls/gre/group_id 三键与 layers 并存属"已登记保留"（本条目明确不解决段），非过渡债务 | T-SRV6-* |
| §15 三道门 | 本表即门 1（已批）；门 2 脚本（srv6 presence 红线接入：dns/mqtt/smtp/pop3/imap/mcp/srv6 七协议同口径）；门 3 挂表抽查；P5R 反查 `check_srv6` 登记（P4，锚词+枚举+多流+组合流+presence/静态复制负例） | 本条目 |

**状态：** 已验收（2026-09-18；实现+P5 提交 e041941；suite RESULT 74 pass/0 fail/0 error，coverage_gate 74/74，pipe_gate 静态四项全绿；touched 包 -race + vet 净；在库清空 tasks 6332 + strategies 43，备份 bak-srv6-clear-20260918-124941，复核 0/0。P5 复盘 2 处锚词对真实执法门（vn07 双 v4 同族放行家族门→VR-06 真触发；new09 V9 范围门先于 VR-21）+ raw-IP 分支补 meta.SrcPort/DstPort（10 例失败同根因：内层端口回退链恒 0）。门 3 抽查三条：①§1 层链唯一真相——srv6_t74_presence_reject 经真实服务拒绝，锚词 "top-level srv6 sub-config"（strategy_convert.go CheckProtoFlat srv6 分支）；②§12 动态清单——layer_dyn.go 无 srv6 行（业务 16 键全关），srv6_e2e04_multi_flow_100 flows=100 内层端口 12345..12444 逐流唯一（chain_planner.go raw-IP meta.SrcPort←worker 12345+i）；③§14 真实流程——srv6_tpos3_reduced 帧 pin "30 39 00 50 00 08" 即内层端口回退执法断言（notes inner_src_port_fallback，落盘 pcap 校准非手算））
**范围（P4）：** ①`CheckProtoFlat` srv6 presence 判死分支；②`registry.go` srv6 LayerSchema（CategoryTerminal+DependsOn ip+16 Fields 无 Default）+ ip 层 hop_by_hop 字段；③`chain_planner_translate.go` `case "srv6"`（raw 层 config→core.ParseSRv6ConfigFromMap，空层→非 nil 空 config 触 VR-02）+ ValidateSpec ip 层 hop_by_hop→spec.HopByHop 回填；④`generator.go` FlowMeta.SRv6 + `chain_planner.go` isRawIPChain 加 srv6 + raw-IP drive meta.SRv6 + validateSpecBase 无端口豁免加 srv6；⑤`srv6/layer_gen.go` 新建（SRV6Generator 包装 legacy Planner.Plan：direction 强制 up 防双换、L2 MAC 沿 legacy 已换值、Plan 复用零分叉）+ RegisterLayerGenerator/Validator；⑥`core.ParseSRv6ConfigFromMap`/`core.ParseHopByHopOptions` 导出（parseSRv6Config/parseHopByHopOptions 委托，零分叉）；⑦`main.go:579` 翻转 `layers.NewChainPlanner("srv6")`；⑧schemagen 重跑；⑨`pipe_gate.sh` 名单 + `coverage_gate.py` check_srv6 登记。
**P1 复审纠错记录（2026-09-18，防再漂）：** ①vn22 自带 TLV（type200）→VR-20 实锚撤销审计项；②tag=65535 tpos18 有帧断言 ffff→P3-1 撤销；③last_entry 显式 tpos7(2)/vp03(1) 有→P3-3 撤销；④src/dst_ipv6 全显式锚点=vp03（12 键+帧断言全钉）→P3-4 撤销；⑤vn18/19 可达性**二次纠正**：gre/mpls 解析在 switch protocol 之内+universal 段不含→suite 不可达（复审第 5 条系误纠，原始决策 B 成立）；⑥suite 路径 spec.TTL 恒 0 无注入→无字节影响。
**明确不解决：** SR-MPLS/GRE over SRv6 嵌套（设计 §1.4 v1 声明；vn18/19 子映射链上静默忽略=legacy 同款，顶层保留并登记）；VR-16/17 链可达化（须动 universal 段解析口，收益仅 2 例锚词，planner_test.go 已覆盖=C 类）；VR-01 链可达化（空层翻译保底非 nil，mcp 同款 C 类）；End* 节点行为语义执行（RFC 8986 控制面，trafficgen 只做报文形态）；HMAC 真实计算（KeyID+占位 digest，设计 §1.4）；视角递增单用例化（多条 FlowSpec 链表达，suite 单 spec 结构=C 类注记）；ip 层 ttl/dscp/ecn 对 srv6 链生效（raw-IP 驱动不跑 ip 生成器，用例零使用，用例出现时另立）；TLS 底座组合（未验不登）。
**依据：** `docs/protocol-designs/15-srv6-design.md` v2.0.2（历史参考：§2 编码/§3 结构/§5 配置/§6 S1-S16/§8 VR/DR/DD/§10 元数据）；RFC 8754 §2/§2.1/§4.1/§4.1.1/§4.3.1.1/§8.2；RFC 8200 §3/§4.3/§4.4/§4.7/§8.1；RFC 8986 §3.4/§4.x（命名）；代码事实：`srv6/planner.go:38-343`（Plan 全量+缺省+down 交换+ICMPv6 缺省）、`srv6/validate.go:13-197`（VR-01–23）、`srv6/serializer.go`（toCoreSRH/BuildFrame）、`core/types.go:10168-10256`（SRv6Config 16 用户键+指针三态）、`strategy_convert.go:5233`（parseSRv6Config）、`chain_planner_util.go:40`（isRawIPChain）、`chain_planner.go:1126-1173`（raw-IP 驱动）、`registry.go:974`（nvgre 先例）、`builder.go:268-277`（L3.SRH 装配）。

**§9 规范矩阵（P1 复审终版，规范要求 → 业务场景 → 代码现状 → 缺口→用例）：**

| 规范行 | 业务场景 | 代码现状 | 缺口→用例 |
|---|---|---|---|
| 8754 §2 反序存储 + §4.1 DA=首段 | S1/S2 单/多段，DstIP/List 字节断言 | 已实现（planner 反序+serializer） | tpos1/2/new08 有 |
| 8754 §4.1.1 Reduced（省末段/LE=len-2/D-bit） | S3/tpos3/tpos20（HMAC+reduced）/p18（red 默认 true） | 已实现（resolveReduced 三态） | 显式 reduced:false 缺→T-70 |
| 8200 §4.4 HdrExtLen 8 位 | vn22（127 段+TLV 溢出）/bnd01/02/04 边界/new07 字节 | VR-03/18/19/20 | vn22 实锚 VR-20（自带 TLV）✓ |
| 8754 §2.1/§8.2 TLV（Pad1=0/PadN=4 自动，HMAC=5 8n 对齐，1/2/3/6 保留禁设） | tpos4/5/16/20 正 + vn10–15 负 | VR-10–13 + builder 自动填充 | type3 负例缺→T-71 |
| 8200 §4.3 HBH 链（NH=0→43） | tpos17 一例 | builder L3.HopByHop 已支持；链上无住处 | ip 层 hop_by_hop 新字段（P4）+组合流 T-72 |
| 8200 §4.7 No Next Header（=59 包必弃） | tpos14（none 空载荷合法） | VR-22 有码 | 负例缺→T-69（none+非空 inner 拒） |
| 8200 §8.1 伪头 DstIP=最终目的 | tpos11（ICMPv6 S16 校验和） | planner 内联+builder 一致 | 已有 |
| 8754 §4.3.1.1 视角（SL 递减/DstIP 更新） | tpos7（midpoint SL=1/LE=2/addr 断言）/S15 | 帧断言已钉 | 单用例视角链=C 类（多 FlowSpec 表达） |
| 8986 §3.4 End* 行为（重点 9+字符串合法口径） | dx6/dx4/dt4/dt6/b6/b6.encaps(.red)/end.x/end.un + vn08 非法 | supportedSegTypes 29 值 | 已有（14 例 seg_type 面） |
| 设计 §5.3 DR-01–13 缺省链 | new05（SL 缺省）/new06（SL=0 显式）/tpos3（reduced）/new03/04（内层端口回退/覆盖）/vp03（12 键全显式锚点） | resolve* 已实现 | 已有（vp03 为全显式对照） |
| 设计 §8.3 DD down 反转 | tpos13/mf04（L3 地址/端口换向断言）+vn24（SL 显式拒） | DD-01–07+VR-23 | 已有；P4 防双换（生成器 direction 强制 up）→落盘重钉 |
| 设计 §8.1 VR-01–23 错误面 | 子表① 22/23 有例 | validate.go 23 分支 | VR-22→T-69；VR-01/16/17 链不可达=C 类注记；vn01 作废合入 vn02 |
| 设计 §Frames/bnd06 帧序 | frames=1/5/1000/-1 | Hop Limit 回绕序列 | bnd06 帧断言已有 |

**子表① VR×用例：** VR-01 vn01（作废：链不可达，合入 vn02）；VR-02 vn02；VR-03 vn03；VR-04 vn05；VR-05 vn06；VR-06 vn07；VR-07 vn08；VR-08 vn09；VR-09 vn04+new13；VR-10 vn10；VR-11 vn11；VR-12 vn12；VR-13 vn13/14/15（type3→T-71）；VR-14 vn16（拒）/vp04（过）；VR-15 vn17/vn20/vn21；VR-16/17 planner_test.go（C 类）；VR-18/19/20 vn22+new07；VR-21 new09；VR-22→T-69；VR-23 vn24。
**子表② 形态变体：** 段数 0/1/2/3/5/126/127/128 ｜ seg_type 12 值 ｜ 载荷 7 值 ｜ reduced 缺省/true/（false→T-70）｜ TLV HMAC/PadN/Pad1/exp200/保留负 ｜ HBH 有/无（+组合 T-72）｜ 方向 up/down ｜ frames 1/5/1000/-1 ｜ tag 零/中/最大 ｜ 内层端口 回退/覆盖 ｜ 多流 flows 10×3/100+down 多流 ｜ group_id fixed。
**子表③ 商业行为→用例（无映射标待确认+方式）：**

| 商业行为 | 出处 | 用例 | 状态 |
|---|---|---|---|
| Linux `ip -6 route … encap seg6 mode encap` 基础封装形 | iproute2 文档（版本待查）+抓 Linux 内核发包 | tpos1 近似 | 待确认：抓包核对 |
| Linux `mode inline`（D-bit reduced+HMAC 面貌） | 同上 | tpos20 近似 | 待确认：同上 |
| End.DX6/DX4/DT4/DT6 PE 解封装形 | RFC 8986 §4.4/§4.5/§4.8/§4.9+厂商文档（待查） | tpos6/new01/01a/01b | 近似；现网包待抓 |
| SR Policy 多段显式路径（控制器下发形） | 厂商 SR Policy 文档（待查） | tpos2/S15 | 待确认 |
| End.X 邻接改写目的 MAC 面貌 | 厂商文档（待查） | vp04 近似 | 待确认 |

#### 1. 数据与接口
- 输入：`[ip{src,dst,hop_by_hop?}, srv6{16 键}]`；srv6 层缺席键走 SRv6Config 零值→生成器 resolve* 缺省（SL=len-1、LE=len-1|len-2、reduced 按 seg_type、frames 1、dir up、PP 空→udp）。
- 输出：每 flow frames 帧 IPv6+SRH(+HBH)+内层 L4/载荷，完整包由 srv6 终结层生成器自产（raw-IP 驱动），builder 按 L2 补 MAC/EtherType、按 spec 补 DSCP/IPFlags/FragOffset。
- 修改点：`strategy_convert.go`（presence 分支+导出 ParseSRv6ConfigFromMap/ParseHopByHopOptions）；`registry.go`（srv6 层+ip.hop_by_hop）；`chain_planner_translate.go`（case "srv6"+ip 层 hop_by_hop 回填）；`generator.go`（FlowMeta.SRv6）；`chain_planner_chain.go`（isRawIPChain 加 srv6）；`chain_planner.go`（raw-IP meta.SRv6+validateSpecBase 豁免）；`srv6/layer_gen.go` 新建；`main.go:579` 翻转；`pipe_gate.sh`/`coverage_gate.py`。

#### 2. 依赖与生命周期
- 前置：ip 层（DependsOn；缺自动补）；无传输层（raw-IP 链，isRawIPChain 分支驱动）；validator 23 分支在 ValidateSpec 同步拒（drive 前零静默空流）。
- 资源：无状态生成器（每 flow 一 Generate，内部 goroutine channel 256）。

#### 3. 主流程与状态
- 顺序：presence 判死（create 400）→ ValidateLayers（V9 字段面）→ validateSpecBase（srv6 无端口豁免）→ translateTerminalConfig case "srv6"（raw 层 config→ParseSRv6ConfigFromMap→spec.SRv6；空层→非 nil 空 config）→ ip 层 hop_by_hop 回填 spec.HopByHop → srv6 validator（VR-01–23）→ Plan（raw-IP 分支）→ SRV6Generator.Generate（构造等价 FlowSpec 复用 legacy Planner.Plan→逐包 Direction 强制 "up" 转 Emit）。
- direction=down 双换修复：legacy Plan 内部已完成 MAC/IP/端口/List 反转全套换向并置 Direction="down"；raw-IP drive 对 "down" 包再换 L3 地址=双换错。生成器统一改写 Direction="up" 后转 Emit（L2 MAC legacy 已换好非空，drive l2For 跳过；L3 地址保持 legacy 换向结果），P5 落盘重钉 mf04/tpos13 断言。
- 内层端口回退：inner_*_port=0→spec.SrcPort/DstPort（链上=mapToFlowSpec 缺省 12345/80 或 worker 逐流值）；与 legacy 扁平语义同构（顶层端口本是回退源，链上回退源恒 spec）。

#### 4. 递增与覆盖规则 + 正交组合矩阵 + 业务动态清单
- 无新序号算法（SegmentsLeft 是 SRH 字段值非流序号；Hop Limit 帧序=64-i 回绕 1..255 永不 0，legacy 既有）；四元组走框架 resolveLayerTuple。
- 业务动态整格（§12，16 键全关+inner 三键关，理由见门 1 表 §12 行；allowlist 不加 srv6 行）。
- 正交组合：载荷 7 × 段数 8 形 × reduced 3 态 × TLV 6 形 × 方向 2 × flows（1/10/100）。

#### 5. 错误与异常
- 新锚词：`protocol srv6 no longer accepts a top-level srv6 sub-config (move it into the srv6 layer of an [ip,srv6] layers chain)`（mcp 文案同构）。
- 既有锚词全量沿用（23 分支字面，子表①）；failing 先行 5 红例：①presence 拒；②层 16 键 V9 放行（原 unknown field）；③层翻译上线（原 generator not implemented）；④inner_payload "12345678" 字节=原文（防 JSON 往返 base64 误读，决策 F 锁）；⑤direction=down 不双换（L3 地址=legacy 换向值）。

#### 6. 性能设计与验收
- 单包路径增量：翻译 16 键一次（ValidateSpec 同步期）；生成器=legacy Plan 包装零新增序列化；SRH 每包 O(段数+TLV)。压力锚=bnd06 frames=1000（既有）。回归口径：srv6.json 全量 suite 耗时 ±10%；诚实声明：无吞吐/并发/内存目标数字（未测）；网卡未跑。
- pcap 验收：全量绿+落盘可复查（ipv6.nxt=43/routing.type=4/segleft/last_entry/tag 帧断言+SRH 帧 hex）；网卡未跑。

#### 7. 实现顺序与回滚
- 步骤 0（failing 先行）：`internal/core/layers/srv6_migrate_test.go` 5 红例。
- 步骤 1 presence→2 导出 parse→3 registry+ip.hop_by_hop→schemagen→4 translate+回填→5 FlowMeta+isRawIPChain+drive+validateSpecBase→6 layer_gen+注册→7 main 翻转→8 build/vet/touched `-race`；P5：68→74 例整形+全量+落盘重钉；P6：评审+提交+清库（strategies 43/tasks 6332 删前重报）。
- 回滚：单提交逆序 revert（P4 代码与 P5 用例分两提交）。

#### 8. 验收
- 对应 T-SRV6-1…74。完成条件：5 红例先红后绿；srv6.json 全量绿（RESULT 全量；二进制同代；门 2 四项绿）；touched 包 `-race` 绿；顶层 `srv6` 字面零残留（mpls/gre/group_id 三键登记保留）；schemagen 同步；在库 srv6 行清空复核。

#### 9. 关键决策对比

| 决策 | 候选 | 优劣 | 结论 |
|------|------|------|------|
| A 链形状 | A1 `[ip,srv6]` raw-IP 终结（nvgre/igmp 先例）；A2 tunnel 形 `[ip,srv6,ip,…]`（gre 先例 InnerRequired） | SRH 是外层 IPv6 的扩展头非封装隧道，内层是裸载荷非完整 IP 包；A2 语义错位且 legacy Plan 全套复用落空 | 选 A1 |
| B vn18/19 mpls/gre 组合 | B1 正例形保留+注记（子映射链上静默忽略=legacy 同款）；B2 动 universal 段解析口转负例 | universal 段（:380-455）只收 tcp/http/dns/ftp/icmp/sctp，gre/mpls 解析在 switch protocol（:457）之内——suite 路径 spec.GRE/MPLS 恒 nil，VR-16/17 本就不可达；B2 收益仅 2 例锚词，planner_test.go 已覆盖 | 选 B1（复审第 5 条系误纠，本条目为终审） |
| C hop_by_hop 住处 | C1 ip 层新字段（vlan 先例）+ValidateSpec 回填 spec.HopByHop；C2 srv6 层收编 | HBH 是 IPv6 扩展头非 SRH 语义（设计 §1.2 链式关系），C1 归位正确且 tcp 链同享；C2 语义错位 | 选 C1 |
| D dst_mac 住处 | D1 顶层保留（单例 vp04）；D2 eth 层 | raw-IP drive 读 spec.DstMAC 零改动；D2 需动 drive 分支，单例不值 | 选 D1 |
| E 内层端口住处 | E1 srv6 层 inner_*_port（门 1 已批）；E2 链上 tcp/udp 层 | 链上无传输层可住；E2 破坏 raw-IP 形状 | 选 E1 |
| F 翻译走法 | F1 复用扁平 parse（导出 ParseSRv6ConfigFromMap，imap 先例）；F2 JSON 往返（mcp 先例） | inner_payload []byte 的字符串语义（getByteSlice 直取原文）会被 JSON 往返 base64 误读；指针三态（segments_left_ptr）也须扁平 parse 派生 | 选 F1 |
| G validator 接入 | G1 RegisterLayerValidator（dns/nvgre 先例）；G2 仅 legacy planner.Validate | 链上 ValidateSpec 不经 legacy planner，G2 则 23 分支全漏 | 选 G1 |

### D-FINS-1 FINS 顶层 fins 子映射迁入层内 + 0103/0104 补齐 + cfg 级 ICF 校验【P-PIPE #11 门1】

**状态：** 已验收（2026-09-18；实现+P5 提交 aaa3e27/ad4429a；suite 45/45 全绿 + srv6 回归 74/74，coverage 46/46，pipe_gate 静态四项绿；fins -race + vet 净；在库清空 tasks 638（strategies 0），备份 bak-fins-clear-20260918-162644，复核 0/0。依赖链判定 C1/C2/C3/C4 全落地：0103/0104 实现、clock 7B、FINS/TCP length=26、缺省 ICF 0x80/0xC0。P4 自审 2 轮修 3 缺陷（translate 覆盖/carrier、0104 校验顺序、read_areas 豁免），P5 复盘 4 处（T-39 V9 锚词、C4、E-03 死代码转可达、0104 白名单）。门 3 抽查三条：①§1 层链唯一真相——fins_vn_presence 经真实服务拒绝，锚词 "top-level fins sub-config"（strategy_convert.go CheckProtoFlat fins 分支）；②§12 动态清单——core/layer_dyn.go 无 fins 行（业务 16 键全关），fins_sessions_two 双会话派生口 1245/1246 逐流唯一（layer_gen.go:51-59 base+i）；③§14 真实流程——fins_multi_read 帧 pin "82 00 64 00 00 01 b2 00 10 00 00 01" 原始字节断言（tshark 0104 NC 怪癖白名单化，字节经套件落盘比对））

**权威链（§7）：** 标准=欧姆龙 W342-E1（SYSMAC CS/CJ 通信命令手册；FINS 系厂商专有协议无 RFC，按 4.10 走官方规范口径）→ 设计=本条目（权威；19-fins-design.md v1.0.1 降级历史参考，仅作 transcription 来源）→ 代码 → 测试。字节事实的标准证据=W342-E1 经 Wireshark packet-omron-fins 与 gofins 双转录交叉一致（历史文档 §1.5，两处字节值核对一致）。

**依赖链判定（P1 冲突终审——按"标准→设计→代码→测试"判对错，无选择题）：**

| # | 断链层 | 判定 | 处置 |
|---|---|---|---|
| C1 0103/0104 | 代码断链 | 标准定义命令（W342-E1，tshark 解码器同）→ 设计 G2 忠实宣称首版实现 → 代码零实现零配置面=**代码错** | P4 补齐：0103 Fill + 0104 Multiple Read（请求/响应体+E-10 校验+错误码面复活）；T-013/T-014 转正落盘 |
| C2 clock 字节数 | 设计断链 | 标准（tshark 按 W342 解析 0x0701 响应=7 字节 BCD 无世纪；实现与单测 fins_test.go:308 同为 7B）→ 历史设计文字"8 字节"=**设计错** | 本条目修订为 7 字节（年月日时分秒星期）；FINSClock.Century 保留配置面不序列化；历史文档 §3.3 加修订注记 |
| E-06 cfg 级 | 代码断链 | 设计 E-06（请求 ICF bit6=1/bit0=1/bit7=0 非法）适用于 ICF 全配置面 → 命令级三规则已实现（fins.go:70-82），cfg 级只查位合法（:50）=**代码缺** | P4 补 cfg 级方向一致性（cfg.ICF 系请求 ICF：bit6 必须清零、bit0 必须清零；bit7 由既有 validICF 查）。注：build 已强制自愈（:338-344），线面本安全，补校验是 E-06 完整性 |
| C3 FINS/TCP length | 设计断链 | 标准（tshark 解码 0x46494E53 帧长度字段=8+FINS 帧长，落盘用例实测 26=8+18；wrapTCP 同写 26）→ 历史设计 T-002 注"length=18"=**设计注错** | 本条目修订为 length=8+FINS 帧长（26）；P5 断言按落盘重钉 |
| C4 缺省 ICF | 代码断链（自相矛盾） | 标准位表（设计 §2.10 同文）：ICF bit0=0 才是"需要响应"→ E-06 校验点要求请求 bit0=0（命令级单测以 0x81|1 为非法值实测）→ 缺省 0x81/0xC1 携带 bit0=1=**违反自身校验规则**，且设计注"0x81=需要响应"自相矛盾 | P5 修正缺省为 **0x80（请求）/0xC0（响应）**；历史 cases 的 omron.icf 断言随落盘更新；设计注记以本条目为准 |
| Fields 缺省 | 架构规则 | 已接受架构谱系（D-MCP-1 决策 F：缺省单一真相在代码）| registry fins 全键**无 Default**；空层/缺省由 GetConfig 默认化承担（GCT=2/ICF 0x81/0xC1/SID 递增/默认 DM 读命令） |

#### 1. 文件清单
- Modify: `trafficgen/internal/protocol/fins/types.go`——新增 `FINSReadArea{MemoryArea string; Address uint16; Bit uint8; Items uint16}`（json 键 memory_area/address/bit/items）；`FINSCommand` 增 `ReadAreas []FINSReadArea json:"read_areas,omitempty"`（仅 0104 合法）
- Modify: `trafficgen/internal/protocol/fins/fins.go`——validate：E-02 支持集 +0103/0104、E-10（read_areas 空/组数>16/组内非法=同 E-01/E-04/E-05 规则）、0103 限定字口径+`Data` 恰 2 字节填充模板、cfg 级 E-06；BuildFrameWithConfig：0103 请求体（寻址 4B+NC 2B+填充字 2B，无 DC，响应=结束码）、0104 请求体（组数 1B+N×6B）与响应体（结束码+逐组合成数据：字=元素 uint16(i+1) BE 组内重起，位=i%2，与 0101 同款）
- Modify: `trafficgen/internal/core/layers/registry.go`——fins Fields 16 键（transport/commands/sessions/sid/sid_auto/icf/gct/dna/da1/da2/sna/sa1/sa2/handshake/termination/read_areas），一律无 Default
- Modify: `trafficgen/internal/core/layers/chain_planner_translate.go`——`case "fins"`：层 config map 直存 `spec.Metadata["fins"]`（GetConfig map 分支既有 types.go:159-168；Data []byte 经 JSON 数字数组无双语义，无 srv6 inner_payload 陷阱）。carrier 门序已验证安全：ValidateSpec :161 translate 先于 :369 门
- Modify: `trafficgen/internal/core/strategy_convert.go`——CheckProtoFlat fins presence 分支（mcp/srv6 先例，空 map 也死）
- Modify: `trafficgen/tools/pipe_gate.sh`（:67 名单+fins）、`trafficgen/tools/coverage_gate.py`（check_fins 登记）
- Modify: `trafficgen/schemas/v1/generated/layers.generated.json`（schemagen 重跑，13.19）
- Modify: `trafficgen/test/protocol_pcap/cases/fins.json`（14 例改写+新例，T-FINS 权威）
- Modify: `docs/protocol-designs/19-fins-design.md`——C2 修订注记（8B→7B，历史文档文字纠错，地位不变）
- Test: `trafficgen/internal/core/layers/fins_migrate_test.go`（failing 先行红例①②③）+ `trafficgen/internal/protocol/fins/fins_test.go` 增补（红例④⑤⑥：0103/0104 构造向量、cfg 级 E-06——现 validate 拒 0103/0104 为 E-02、cfg ICF 无方向检查，两处先红）

#### 2. 接口签名
- `type FINSReadArea struct { MemoryArea string `json:"memory_area"`; Address uint16 `json:"address"`; Bit uint8 `json:"bit,omitempty"`; Items uint16 `json:"items"` }`
- `FINSCommand.ReadAreas []FINSReadArea`（json:"read_areas,omitempty"）
- translate：`case "fins": spec.Metadata["fins"] = term.Config`（层优先，flat 判死后无双轨）
- presence 锚词：`protocol fins no longer accepts a top-level fins sub-config (move it into the fins layer of a layers chain: ip + udp/tcp carrier + fins)`

#### 3. 主流程
链路径：ValidateLayers（V9 16 键）→ validateSpecBase（ip/udp/tcp 补全；fins dst 9600 缺省既有 :726）→ **translateTerminalConfig case "fins"（:161，先于 carrier 门 :369，序安全）** → carrier 门（transport↔载体一致性，既有）→ protocolValidator（RegisterLayerValidator 既有 layer_gen.go:177）→ Plan → FINSGenerator（**零改动**）→ GetConfig→Validate（新增分支）→ emitSessionCommands（零改动，命令循环自然承载 0103/0104）→ BuildFrameWithConfig（新增 0103/0104 case）→ req.Emit。
wire 要点：0103 请求剩余长度恒 8（tshark 口径，历史 §3.8）；0104 请求组 6B（区码+地址 2+bit+NC 2），tshark 对请求组按 4B/组忽略 NC——**请求断言用 FrameAssert 原始字节，不做 omron.\* NC 字段断言**（历史 §3.9 怪癖注）。
会话语义不变：sessions=N 逐会话独立流（端口 base+i，layer_gen.go:51-59）、SID 会话内递增跨命令（fins.go:281-285）、carrier 门缺省跟随链载体。

#### 4. 增量步骤（failing 先行，逐项 review→test→fix→review）
1. 红例族 6 项（两处文件，见 §1 Test 行）：layers fins_migrate_test.go ①顶层 presence 判死 ②层 16 键 V9 放行 ③translate→Metadata→Plan 出包（含 sessions 端口/SID 断言）；fins 包 fins_test.go ④0103 构造向量（原始字节）⑤0104 构造向量（请求原始字节+响应数据合成）⑥cfg 级 E-06 红
2. validate+build 实现（C1 全量+E-06 cfg 级）→ 红转绿
3. registry Fields+translate case+CheckProtoFlat presence+pipe_gate/coverage_gate 登记+schemagen 重跑
4. cases 改写 14 例+新例（P3 清单驱动）→ suite 全量 → 门 2 四项

#### 5. 错误锚词（用例 error_contains 字面值）
presence="top-level fins sub-config"；E-01="invalid memory area"；E-02="unsupported command 0x"；E-03="dm does not support bit access"；E-04="address exceeds range"；E-05="items must be > 0"/"items exceeds range"；E-06 命令级="invalid icf"/"icf request direction bit must be clear"/"icf response-required bit must be clear"、cfg 级新增同族文案（"icf request direction bit must be clear" 复用）；E-07="data length"；E-09="clock field out of range"；0103 新增="fill data must be 2 bytes"/"fill does not support bit access"（设计 §3.8 仅字口径）；E-10 新增="read_areas"族（空/组数>16）。

#### 6. 性能设计与验收
包数公式：UDP=2×命令数×sessions；TCP 另加握手 3+挥手 4（tcp 层语义）；0104 响应 O(Σ组 NC×元素字节)。生成器 channel 流式、无全量收集、无锁（既有结构）；翻译一次（同步期）。回归口径：fins.json suite 全量耗时相对基线 ±10%。两路验收：pcap 全量绿+落盘可复查（/tmp/mcp-pcaps/fins/）；网卡路未跑，如实声明。无吞吐/并发/内存承诺数字（未测，不编造）。

#### 7. 顺序与回滚
红例→validate/build 实现→registry/translate/presence→cases→suite。回滚粒度=单提交：0103/0104 实现独立 diff（revert 不影响既有 0101/0102/0701）；presence 判死独立；cases 独立。

#### 8. 验收
对应 T-FINS（P3 定稿编号）。完成条件：6 红例先红后绿；fins.json 全量绿（RESULT 行+二进制同代+门 2 四项）；touched 包 `-race`+vet 净；顶层四元组与顶层 fins 字面零残留；schemagen 同步绿；门 1 对照表回填实际证据号（15.8）+ 抽查三条（15.9）；在库 fins tasks 638 清空（删前报数→备份→删→复核，strategies 现为 0 行）。

#### 9. 关键决策对比（依赖链判定 + 架构谱系）

| 决策 | 候选 | 优劣 | 结论 |
|------|------|------|------|
| C1 0103/0104 | A 补齐实现；B 降级非目标改设计 | A 兑现设计 G2、错误面（E-10/0x1102/0x2003）已备、SCADA 批量采集真实价值；B=自砍已宣称目标、须改三处设计文字 | **A**（链判：代码违反设计） |
| C2 clock 字节 | A 采 7B 修设计文字；B 改码发 8B | A 与标准证据（tshark/W342）、单测、实现三方一致；B 被 tshark 判 malformed、§14 真实流程必红 | **A**（链判：设计违反标准） |
| E-06 cfg 级 | A 补校验；B 注记 build 自愈即可 | A 补全 E-06 设计完整性，几行校验；B 留校验缺口（坏配置静默过 validate 靠运行期自愈兜底） | **A**（链判：代码违反设计） |
| Fields 缺省 | A 全键无 Default；B 注册表带 Default | A 缺省单一真相在代码（D-MCP-1 决策 F 谱系）；B 复制缺省值有分叉风险 | **A**（架构谱系既定） |
| F' 翻译走法 | A Metadata map 直存；B typed parse（导出 ParseFINSConfigFromMap）；C JSON 往返 spec 字段 | A 零新代码复用 GetConfig map 分支；fins 无 srv6 式 []byte 字符串陷阱，C 亦安全但多一层 | **A** |
