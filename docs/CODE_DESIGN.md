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

### D-GOOSE-1 GOOSE 顶层 goose 子映射迁入层内（L2-only 终结层）+ translate 真实现【P-PIPE #12 门1】

**状态：** 已验收（2026-09-18；实现+P5 提交 2553f1a/7bee24e；suite 33/33 全绿 + coverage 51/51 + 门 2 四项绿 + fins 45/45、srv6 74/74 零回归；P6 复跑 go vet 净 + layers/schema `-race` 绿。P4 提交 2553f1a——registry 18 键零 Default + translate 手工逐键 + presence 判死 + static-eth 门，4 红先红后绿。P5 复盘 5 处见 T-GOOSE 状态行。测试四问：①33 例全走 REST create→MCP task→引擎→tshark 落盘真路径（create-time 拒 4 例无落盘+task-time 拒 11 例 .neg.pcap，三段覆盖）②锚词全对真实执法门（P5 复盘②修正后）③正例帧 hex 全字节+fields 断言、负例 error_contains 精确锚词 ④coverage check_goose 51/51 反查（含反查逮出补例 T-31/32/33）。在库清空：删前重报 tasks 570 + strategies 27（§8 原记 498+9 系 P2 时点数，P4/P5 suite MCP 建任务追加），备份 /tmp/trafficgen-goose-p6-backup-20260918-224050.db，复核 0/0，双向交叉引用零交叉（注：fins 167/srv6 245 任务系 goose P5 回归跑复写，归属各自管线）。门 3 抽查三条：①§1 层链唯一真相——goose_vn_presence 经真实服务拒绝，锚词 "top-level goose sub-config"（strategy_convert.go:7715 CheckProtoFlat goose 分支，空 map 也死）；②§12 动态清单——core/layer_dyn.go 零 goose 行（L2-only 业务键全关动态），goose_vn_static_copy eth 层显式 src_mac + flows=2 经真实服务拒 "static four-tuple"（semantic.go:229 layerTupleFields 含 eth，sv 同享）；③§14 真实流程——goose_goid 帧 pin `83 09 74 65 73 74 2d 67 6f 69 64`@109（goID tag/len/ASCII 原始字节，落盘 pcap 校准非手算），goose_heartbeat.pcap tshark 复核 stNum 恒 1、sqNum 1,2,3（translate 语义执法断言））

**权威链（§7）：** 标准=IEC 61850-8-1（GOOSE 系标准组织协议，按 4.10 走官方规范口径）→ 设计=本条目（权威；23-goose-design.md 保留历史参考）→ 代码 → 测试。字节事实的标准证据=IEC 61850-8-1 经 libiec61850 `goose_publisher.c` + Wireshark `packet-goose.c` 双转录交叉（历史 §2 :187/:213，含初稿标签错误显式弃用记录）。

**依赖链判定（P1 冲突终审，无选择题）：**

| # | 断链层 | 判定 | 处置 |
|---|---|---|---|
| ⑥ 静态复制门 eth 缺口 | 代码断链（框架） | 12.9 要求"必须拒绝或告警" → `layerTupleFields` 只查 ip/tcp/udp 层，eth-only 链 flows>1 静默发 N 条重复流（sqNum 撞号损坏序列语义）=**框架未满足 12.9** | P4 扩 `layerTupleFields` 含 eth（src_mac/dst_mac）：通用修（sv/isis 同享；sv 12 + isis 25 = 37 例零 strategy_fc 无回归面）。L2-only 逃生口=eth 层 src_mac/dst_mac 动态对象（allowlist eth 行既有，`layer_dyn.go`；check 业务层对象豁免 loop 覆盖 eth）——拒绝文案只点名 ip/tcp/udp 属文案瑕疵，拒绝本身正确，注记即可 |
| ⑦ t0 心跳节拍 | 实现缺失（配置面死键） | EventSeq.DelayMs 已实现（重发退避 ✓）；纯心跳 pacing（t0_ms）三层全无——用例 heartbeat 的 `t0_ms:1000` 被 Go parse 静默忽略（parse 无该键）。同案 `tmax_ms`（12 例中多例携带，parse/GOOSEConfig/生成器三层全无此键）亦死键。suite 无包间隔断言（9.27）→ **C 类** | P3 审计删 `t0_ms` + `tmax_ms` 两键 + C 类注记"pacing 未实现，无断言面"（设计 §2 静默弃用，不入代码） |
| count 住处 | 架构规则 | 单流帧数语义=goose 层内（框架 `isL2OnlyProtocol` + `strategy_convert.go:568-578` 注记同口径） | 改写：顶层 count→层内 count；flows>1 由⑥新门拒绝 |
| S2 退避 vs t0 | 链判区分 | 重发退避有 DelayMs 实现 ✓，心跳 pacing 无 → 误报澄清（P1 重审 #4） | 本表即依据 |

#### 1. 文件清单
- Modify: `trafficgen/internal/core/layers/registry.go`——goose Fields 18 键（appid/gocb_ref/dat_set/go_id/tal_ms/conf_rev/start_stnum/start_sqnum/test/nds_com/boolean/data/event_seq/count/dst_mac/vlan_enabled/vlan_id/vlan_priority；**无 static——GOOSEConfig/types 无此字段、无生成器消费，为 P1 矩阵幽灵键，P2 重审删除**），**一律无 Default**（validate 要求 gocb_ref/dat_set 必填、conf_rev 非零=零缺省谱系；与 fins 16 键同款——dns 14 键带 Default 是例外非先例，因 dns 走"缺席=全默认合法"语义而 goose 走"缺席=validator 拒绝"语义）。无界字段（string/bool/object：gocb_ref/dat_set/data 等）走 V9 `Min==0&&Max==0` 跳过口径（`complete.go:ValidateLayerConfig`），非法值仍由 protocolValidator 拒收。L2-only 业务键全关动态（allowlist 不加 goose 行；eth 行既有不动）
- Modify: `trafficgen/internal/core/layers/chain_planner_translate.go`——`case "goose"` 真实现（现 `chain_planner_translate.go:725` no-op `return`→替换）：层优先（flat 判死后无双轨；fins 已有 `Metadata 缺席才落层值` 守卫先例，goose 无 flat 守卫历史故**不设守卫**——spec.GOOSE 缺席走翻译、已存在（引擎直调）则不覆盖，dns `spec.DNS != nil return` 同款已随 CheckProtoFlat 删除）。**不可跨包复用 `parseGOOSEConfig`**（strategy_convert.go:7590，未导出；dns/mqtt 手工逐键映射同款）：`cfg := completedConfig(s, term.Config)` + 手工逐键 `configUint16/configString/configBool` + data/event_seq 槽位下钻（`item["value"]` interface{} 透传，无 srv6 式 []byte 陷阱）。空层 `{}` 翻译出零配置（非 nil）→ validator 首命中 `GOCBRef/DatSet == ""` → "goose gocb_ref and dat_set are required"（"goose config is required"仅 spec.GOOSE==nil 命中，翻译后不可达；mcp 空层保底"config is required"/srv6 空层保底 VR-02 同款 C 类，goose 空层保底=gocb_ref 必填分支）
- Modify: `trafficgen/internal/core/schema/semantic.go`——`layerTupleFields` 扩 eth（src_mac/dst_mac）。文案注记 L2-only（⑥ 表已判）
- Modify: `trafficgen/internal/core/strategy_convert.go`——CheckProtoFlat goose presence 分支（srv6/fins 先例，空 map 也死）
- Modify: `trafficgen/tools/pipe_gate.sh`（名单+goose）、`trafficgen/tools/coverage_gate.py`（check_goose 登记）
- Modify: `trafficgen/schemas/v1/generated/layers.generated.json`（schemagen 重跑，13.19）
- Modify: `trafficgen/test/protocol_pcap/cases/goose.json`（12 例改写+新例，T-GOOSE 权威）
- Test: `trafficgen/internal/core/layers/goose_migrate_test.go`（failing 先行红例族）

#### 2. 接口签名
- presence 锚词：`protocol goose no longer accepts a top-level goose sub-config (move it into the goose layer of an [eth,goose] layers chain)`（srv6/fins 同款，空 map 也死，CheckProtoFlat :7706 后追加）
- translate 签名（dns 手工映射同款）：`raw := term.Config`（p.chain 原始层 config，对象完整）→ `cfg := completedConfig(s, term.Config)`（标量补全）→ `spec.GOOSE = &core.GOOSEConfig{...}` 逐键 `configUint16/configUint32/configString/configBool` + `data[]` 下钻 `GOOSEData{Name,Type,Value:item["value"],BitLength}` + `event_seq[]` 下钻 `GOOSEEventSeq{DataIdx,DelayMs,Retransmits,SqNumStep}`（parseGOOSEConfig:7590 逐键对照，不可跨包调用故手工复刻）

#### 3. 主流程
链路径：ValidateSpec（`chain_planner.go:ValidateSpec:149` validateSpecBase L2-only 既有：不填 src_ip/dst_ip/端口… → `:161` translateTerminalConfig **case "goose" 真实现，flat 判死后层优先** → protocolValidator RegisterLayerValidator 既有 goose.go:553）→ fins/nfs 同款 carrier/结构检查（goose 为 eth 单载体：`complete.go:352` V7b `[ip,goose]` 拒绝 "must not have an ip/transport carrier"，既有）→ Plan（L2-only 分支 `chain_planner.go:1002-1014`：生成器自装 L2 保留 + EtherType=0x88B8 回填 + `L3={}` 清零，既有）→ Generator（既有 goose.go:552，**零改动**，req.Meta.GOOSE=spec.GOOSE 经 `chain_planner_chain.go:flowMetaFor:28` carry）。
MAC 路径：src 由链 drive 经 flowMetaFor（spec.SrcMAC）→ req.Meta.SrcMAC → 生成器 `emitGooseFrames(c,count,st,sq,src)`（goose.go:480-487）；dst 由层内 dst_mac → spec.GOOSE.DstMAC → 生成器（空则 DefaultDstMAC）。eth 层 config 不直写 spec.SrcMAC——**顶层 `src_mac` 不迁入 eth 层**（mapToFlowSpec `strategy_convert.go:285` flat `src_mac`→spec.SrcMAC 消费口径既有；L2-only 用例 `layers:[{eth:{}},{goose:{...}}]` 空 eth 层占位 + 顶层 src_mac 供值，现状 12 例同款，保持）。validateSpecBase 不存在所谓"eth 层补全"（L2-only 直接 return，`chain_planner.go:567`）。

#### 4. 增量步骤（failing 先行，逐项 review→test→fix→review）
1. goose_migrate_test.go 红例族 5 项：①顶层 presence 判死 ②层 18 键 V9 放行 ③translate→spec.GOOSE→Plan 出包（heartbeat 3 帧，stNum 恒 1/sqNum 连续——纯链目前红）④⑥ eth 静态复制门（flows=2 eth 静态 MAC 拒绝）⑤12.9 sv 同享不回归（sv 链 flows=2 同门拒绝——同法则适用，sv 用例零 strategy_fc 保持）
2. translate 真实现+registry Fields+CheckProtoFlat presence+static eth+pipe_gate/coverage_gate 登记+schemagen 重跑 → 红转绿
3. cases 改写 12 例+新例（P3 清单驱动）→ suite 全量 → 门 2 四项

#### 5. 错误锚词（用例 error_contains 字面值）
presence="top-level goose sub-config"；"goose appid 0x... outside GOOSE range"；"goose gocb_ref and dat_set are required"；"goose control-block strings exceed 255 bytes"；"goose tal_ms must be in"；"goose conf_rev must be non-zero"；"goose stNum must not overflow"；"goose sqNum must not overflow"；"goose at least one data member is required"；"goose unsupported data type"；"goose sqNum step"；"goose is Layer 2 only and must not use IP or transport fields"；⑥新门="layers pin a static four-tuple...（含 eth，由 semantic.go static 锚词派生，P5 落盘钉死字面）"。

#### 6. 性能设计与验收
包数公式（`goose.go:emitGooseFrames` 实测语义）：count 帧 = 1 帧事件前心跳（仅 EventSeq 非空时；纯 Static 无此帧）+ Σ(每 event_seq：retransmits+1 帧，首帧 stNum+1/sqNum=0）+ 剩余心跳补足（sqNum 连续）。生成器 channel 流式、无全量收集、无锁（既有）；翻译一次（同步期）。回归口径：goose.json suite 耗时相对基线 ±10%。两路验收：pcap 全量绿+落盘（/tmp/mcp-pcaps/goose/）；网卡路未跑如实声明。无承诺数字（未测，不编造）。

#### 7. 顺序与回滚
红例→translate/Fields 核心（⑥ static 同批）→门登记→cases→suite。回滚粒度=单提交：translate 真实现独立（revert 回 no-op=纯链不可跑旧态，非退化）；static eth 独立；cases 独立。

#### 8. 验收
对应 T-GOOSE（P3 定稿编号）。完成条件：5 红例先红后绿；goose.json 全量绿（RESULT+二进制同代+门 2 四项）；touched 包 `-race`+vet 净；顶层 count/goose 字面零残留（**src_mac 留顶层**：flat `src_mac`→spec.SrcMAC 消费口径既有，非扁平键，不迁入 eth 层）；schemagen 同步绿；门 1 对照表回填实际证据号（15.8）+ 抽查三条（15.9）；在库 goose tasks 498 + strategies 9 清空（删前报数→备份→删→复核）。

#### 9. 关键决策对比（依赖链判定 + 架构谱系）

| 决策 | 候选 | 优劣 | 结论 |
|------|------|------|------|
| ⑥ static 修法 | A 扩 layerTupleFields 含 eth（通用）；B L2-only 特判拒 flows>1 | A 根因一处修全家共享、sv/isis 37 例实测零回归面；B 分叉逻辑 | **A**（链判：框架职责） |
| ⑦ t0 | A 实现 pacing；B C 类注记 | A 无包间隔断言面（9.27），实现不可验证；B 如实注记 | **B**（断言面不可达） |
| translate 走法 | A completedConfig+parseGOOSEConfig 复用；B 手工逐键映射 | **A 不可编译**（parse 未导出，layers 包不可见；dns/mqtt 均为手工映射先例）→ **B**：completedConfig 补全 + configUint*/configString/configBool 逐键 + data/event_seq 槽位下钻，parse:7590 逐键对照为单源口径 | **B**（dns 同款） |
| Fields 缺省 | A 全键无 Default；B 注册表带 Default | A 缺省单一真相在代码（D-MCP-1 决策 F 谱系）；validate 强制必填项与 Default 语义冲突 | **A** |

### D-SV-1 SV 顶层 sv 子映射迁入层内（L2-only 终结层）+ translate 真实现【P-PIPE #13 门1】

**状态：** 已验收（2026-09-19；实现+P5 提交 ac12415/afec0b2；suite RESULT 30/30 全绿 + coverage 42/42 + 门 2 四项绿 + goose 33/fins 45/srv6 74 零回归；touched 包 -race + vet 净；在库清空 tasks 314 + strategies 8（P6 删前重报，243135−314=242821 复核），备份 trafficgen-sv-p6-backup-20260919-110428，复核 0/0，双向交叉引用零交叉。P6 复测四问：①30 例全走 REST create→MCP task→引擎→tshark 真路径（create-time 拒 5 无落盘+task-time 拒 8 .neg.pcap）②锚词全对真实执法门（套件红绿实证）③正例帧 hex 全字节+负例精确锚词 ④check_sv 42/42 反查。P5 复盘 5 处见 T-SV 状态行（expect_error 契约/⑥ L2-only 多流保底修复/genMAC 首八位语义/pin 手算 3 处落盘重钉/发现⑤再修正）。P5 对抗重审：落盘抽查 smpCnt 三证（0,1,2/回绕/双发共享）+账目 25=17+8 零孤儿——0 新发现。门 3 抽查三条：①§1 层链唯一真相——sv_vn_presence 经真实服务拒绝，锚词 "top-level sv sub-config"（strategy_convert.go:7730 CheckProtoFlat sv 分支，空 map 也死），30 例顶层仅 layers+src_mac；②§12 动态清单——core/layer_dyn.go 零 sv 行（业务 15 键全关），MAC 动态唯一开启面实测：T-26 inc 回绕 :01,:02,:01 逐流、T-27 list 轮转、T-28 rand seed7 钉值 fb/97（genMAC layer_dyn.go:585 首八位 OUI 语义），静态标量 flows=2 拒（T-14，semantic.go:229）；③§14 真实流程——sv_int32_neg 帧 pin `87 04 ff ff ff ff`@56（int32 负数字节，落盘校准非手算），smpCnt 三证 tshark 落盘复核。原 P2 定稿记录：门 1 已批（用户"继续"）；CORE_MEMORY 237 条逐条复审完成——全过 + 6 处发现已回填本条目：①appid 现负值 0x3999 在 V9 [16384,32767] 注册后改 create-time 拒，锚词收紧 "out of range [16384,32767]"（goose P5 复盘②口径）②period_us 判"配置面有 parse+struct、行为面生成器零消费"死键，非幽灵键（与 goose t0_ms 幽灵键不同级）③MAC 动态多流例 sv P3 补 1（goose 33 例亦缺，注记对齐缺口）④smpSynch 第三值例 P3 补 ⑤float32 通道独立断言 P3 核对 ⑥组合流=字段正交组合 2 例替代（单消息协议无动作序列，9.11 豁免+替代面）。依赖链判定终审（⑤ 行 P3 假发现、P4 实读纠正）+ 设计八节 + 决策表 A–G（G 撤销）见下；P3 定稿（T-SV-1…30，TEST_CASES 2026-09-19；12 改写+18 新建）；P4 已执行（见下）。缺口立项 4：P4 四件套（registry 15 键/translate case/presence 分支/门登记）+ P5 改写 12 例。链路径已具备：main.go:526 翻转 + 生成器/校验器注册（sv.go:191-192）+ FlowMeta.SV carry（chain_planner_chain.go:28）+ EtherTypeSV 回填（chain_planner.go:1008）+ isL2OnlyProtocol（strategy_convert.go:224）+ static-eth 门已由 goose ⑥ 通用修带绿（TestSVChainStaticEthRejected）。在库基线（P2 时点）：sv tasks 314 + strategies 8（P6 删前重报）

**P5 执行记录（2026-09-19）：** 30 例落 JSON（12 改写迁移+18 新建）→ 重编服务真跑三回：①15/3/12——9 新负例缺 `expect_error:true`（driver 契约，P3 清单漏记）+3 mac_dyn 被 worker 多流保底误伤；②26/4——4 处预测 pin 手算错（9.31 落盘重钉）；③28/4——xxd 目测错位 1 字节修正；④**30/30 全绿**。P5 新增代码：mapToFlowSpec l2Only 恒置 HasExplicitSrcPort（⑥，红单测先行，genMAC 首八位 OUI 语义实测后 mac_dyn range 对齐）。coverage 42/42 + 门 2 四项绿（pipe_gate 需显式传二进制路径，默认值是 http 时代残留）+ goose/fins/srv6 回归绿 + core -race 绿 + 落盘 25 零孤儿。复盘 5 处详记 T-SV 状态行。

**P4 执行记录（2026-09-19）：** 5 红先红后绿——实现前逐条红因：①presence 放行 ②unknown field ③④⑤ translate no-op→"sv config is required"（④另 unknown field 锚不对）。实现：registry sv Fields 15 键（appid [0x4000,0x7fff]/period_us 无界 V9 skip）+translate case "sv"（14 标量逐键+data 双臂下钻 inst_mag/quality presence→HasQuality）+CheckProtoFlat sv presence（goose 后邻位）+pipe_gate.sh:67+coverage_gate check_sv 登记+schemagen 重跑 96 层；**sv.go 零改动**（⑤ 假发现撤销，:26 双界既有）。验证：build/vet 净；layers/core/schema/sv 四包 `-race` 绿；rest/mcp 回归绿；TestLayersGeneratedMatchesRegistry 绿。自审 1 轮：json.Number 臂差异与 goose 同构（该路径恒 float64 无分叉）、presence 无条件判死含纯扁平形（在库旧行启动 error=判死语义预期）、V9 list 类型不校验 item 内容（inst_mag 字符串静默 0=parse getInt 同口径）。

**权威链（§7）：** 标准=IEC 61850-9-2/-9-2LE（4.10 官方规范口径）→ 设计=本条目（权威；24-sv-design.md 保留历史参考，仅作 transcription 来源）→ 代码 → 测试。字节事实的标准证据=IEC 61850-9-2 经 libiec61850 `sv_publisher` + Wireshark `packet-sv.c` 双转录交叉（历史 §2；BuildPayload 注释 "tests/sv.json 1.5=0x3fc00000" 即 IEEE 754 转录锚）。

**依赖链判定（P1 预判→P2 定稿终审）：**

| # | 断链层 | 判定 | 处置 |
|---|---|---|---|
| ① period_us | 行为缺失（配置面死键） | 键有 parse（strategy_convert.go:7571）+struct（types.go PeriodUS），生成器 Generate（sv.go:162-184）零消费=无 pacing——配置面存在、行为面未实现（与 goose t0_ms 幽灵键不同级，同 C 类结论） | P3 审计注记 C 类"pacing 未实现，无断言面"；键保留不入代码改动 |
| ② appid V9 边界 | 门序（V9 vs validator） | validator "outside SV range 0x4000-0x7fff"（sv.go:27）语义范围应上移 V9 create-time（goose appid [0,0x3fff] 同款）；现用例负值 0x3999 会改由 V9 拒 | registry appid {uint16, Min 16384, Max 32767}；neg_appid 锚词收紧 V9 "out of range [16384,32767]"（.neg 无落盘=超早拒绝，mqtt 先例） |
| ③ MAC 动态多流 | 用例覆盖缺口 | 12.9 逃生口（eth.src_mac/dst_mac 动态对象，layer_dyn.go:21 allowlist）链路已通（resolveLayerTuple:741→spec.SrcMAC→Meta.SrcMAC→帧），sv 12 例零覆盖；goose 33 例亦无（对齐缺口注记） | P3 补 1 例 MAC 动态多流（A 类可达已验证）；goose 侧注记不回改 |
| ④ 组合流替代面 | 9.11 豁免判定 | sv 单消息协议（每帧完整 ASDU）无动作序列可组合 → 豁免+替代面：字段正交组合 2 例（goose combo_flags/combo_event 同构） | P3 定 2 条组合例（vlan×double_send×quality 布局 / smp_rate×dat_set×多通道） |
| ⑤ appid 下界（P3 假发现，P4 纠正） | 判定错误（P3 自审） | P3 从 goose 单界（`>0x3fff`）外推"sv 只查上界"——**未实读 sv.go:26**；P4 红例⑤ 逼出实读：sv.go:26 本就是双界 `< 0x4000 \|\| > 0x7fff`，appid<0x4000（含 0）一直被拒，无断链 | **零代码改动**；红例⑤ 保留=V9 u==0 放行→validator 双界执法的回归锁（实现前因 translate 缺失而红，转绿后恒绿）；T-15/T-23 锚词与现状真门一致不变 |

#### 门 1 开工对照表（§1–§15，2026-09-19，CORE_MEMORY 237 条逐条复审通过后交付；证据=文档节/代码行/用例号）

| § | 本协议怎么满足 | 证据 |
|---|---|---|
| §1 层链唯一真相 | L2-only 链 `[eth,sv]`：无 ip/端口概念（1.1/1.2 豁免：validateSpecBase 豁免+validator "Layer 2 only"）；顶层旧键去向——`sv` 子映射 15 键→`layers[sv]` 直迁、`count`→sv 层 count（单流帧数语义 sv.go:167）、`src_mac` 顶层保留（非扁平五键，flat src_mac→spec.SrcMAC 消费口径既有，goose 先例）、`strategy_fc`=唯一流数入口。现状 12 例全 MIXED（layers 空占位 + 顶层 sv/count/src_mac）=1.4 违规现状→P5 改写。目标形状：`{"layers":[{"eth":{}},{"sv":{"sv_id":"xxx","appid":16384,"conf_rev":1,"samples_per_cycle":80,"smp_synch":1,"smp_rate":80,"data":[{"name":"A","type":"int32","inst_mag":100}],"count":3}}]}`。P4 必修四件：①CheckProtoFlat sv presence 分支（goose :7715 同款文案 `[eth,sv]`，空 map 也死）②registry sv Fields 15 键全无 Default（appid Min 16384/vlan_id Max 4095/vlan_priority Max 7 语义边界）③translateTerminalConfig case "sv"（手工逐键——parseSVConfig:7571 未导出不可跨包；data 下钻 inst_mag 按 type 分流 int32/float64→InstMagF、quality presence→HasQuality）④pipe_gate.sh:67 名单+sv、coverage_gate check_sv 登记 | sv.json 12 例审计；registry.go:707（行在 fields 空）；strategy_convert.go:7715（插入点）；types.go:1646（SVConfig 15 键） |
| §2 策略/任务分工 | 沿框架语义；策略=一条 SV 发布流模板（15 键）自带 strategy_fc；任务=多策略合跑+总封顶（{taskID}-{strategyID} 独立桶）；flows=N 同模板复制 N 流（MAC 动态对象逐流异=唯一逐流变面）；spec 不管流数（Count 是单流帧数非流数，sv.go:167 n=c.Count 缺省 1——如实分开声明） | sv.go:162-170；chain_planner_chain.go:28 |
| §3 五件套 | **豁免+替代面**（周期采样值流，发布/订阅无握手无会话）：会话表=豁免（IEC 61850-9-2 无连接单向组播推流）；事务序列=豁免（单帧即完整 ASDU，0x60+0x30+0xa2 一层）；单事务四件事=豁免（无事务可拆）；关联关系=豁免（无控制/数据分离）；插入位置=sv 终结层自产完整包（chain_planner.go:992-1017 L2-only 分支：生成器 L2 保留+EtherTypeSV 回填+L3 清零，builder 只补缺省 MAC）；时间线=单流顺序发射（Generate 循环），多流并发=worker 逐流（框架 resolveLayerTuple）。多流覆盖（3.14）：静态 MAC flows>1 被 static-eth 门拒（正确行为）+ MAC 动态对象逃生口 P3 补例 1（③ 立项）。smpCnt 回绕序列是帧内样本语义非流间编排（3.13 如实分） | chain_planner.go:992-1017；sv.go:179（smpCnt (i/step)%SamplesPerCycle）；semantic.go:229（static-eth 门） |
| §4 规范矩阵 | IEC 61850-9-2/-9-2LE 官方口径（4.10）；24-sv-design.md 历史参考非权威（§7.4）；P1 矩阵见本条目 §9 表+三张子表（①命令×响应=豁免，单向无响应协议，以"字段×tag 矩阵"替代） | 24-sv-design.md；本条目 §9 |
| §5 有错必处理 | validator 9 分支全列锚词（sv.go:23-50：config required/appid range/svID required ≤255/confRev non-zero/samples_per_cycle ≥1/smpSynch 0,1,2/data required/type unsupported（仅 int32,float32）/L2 only）+carrier V7b（complete.go:352 [ip,sv] 拒）+presence（P4）+static-eth 门+V9 边界——负例锚词全对真实执法门（goose 复盘②口径）；依赖：eth 层 DependsOn（registry.go:707）、FlowMeta.SV carry、EtherType 回填——§2 依赖节全列 | sv.go:23-50；complete.go:352 |
| §6 性能 | 单流包数=count（缺省 1；现有 count=100 压力锚 sv_smp_seq 系）；生成器循环直发 Emit（sv.go:162-184，无缓冲聚合、无锁、channel 流式框架既有）；每帧 O(通道数) 序列化（BuildPayload 单遍）；翻译一次（ValidateSpec 同步期）；回归口径：sv.json suite 耗时相对基线 ±10%；边界诚实声明：无吞吐/并发/内存目标数字（未测不承诺，goose 同款）；网卡未跑 | sv.go:162-184；本条目 §6 |
| §7 三份文档 | 设计=本条目；用例=T-SV 清单（P3 先行，存量 12 逐条审计去向）；cases 回指编号；24-sv-design.md 历史参考非权威，冲突以本条目为准 | TEST_CASES T-SV-* |
| §8 先设计后代码 | 门 1 表批复→P1 矩阵→P3 清单→failing 先行红例→P4 代码；无设计条目 Diff 打回 | 本条目 |
| §9 三源+整格 | 三源：IEC 61850-9-2/-9-2LE + 24-sv-design（历史转录）+ 现网（继保测试仪/合并单元=待确认一项，确认方式：抓现网 SV 组播包）；P3 清单先行；存量 12 例逐条审计（9.14）；枚举全覆盖=smpSynch 3 值（③ 补第三值例）/data type 2 值（int32 负数+float32 0x3fc00000）/appid 边界 4 值（0x4000/0x7fff/0x3fff/0x8000）/quality 布局 2 形（4i4v vs 4B 自定义）/dat_set 有无/smp_rate 有无；正交：smpSynch×smp_rate×quality×dat_set×double_send×vlan×count；组合流 2 条=字段正交替代（④）；断言边界：包间隔（pacing 死键①）不可断=C 注记，smpCnt 序列逐帧 pin 断 | P1 矩阵子表①②③；coverage_gate check_sv（P4 登记） |
| §10 评审闭环 | failing 先行红例族（①presence 拒②层 15 键 V9 放行③translate 上线出包（smpCnt 序列）④MAC 动态多流逐流异）→改→审→测→再审；`go vet`+touched 包 `-race` | P4 |
| §11 白话汇报 | 先一句结论 | 每次汇报 |
| §12 动态清单 | L2-only 无四元组（1.2）；业务 15 键**全关动态**（allowlist 不加 sv 行——逐键理由：appid/conf_rev/sv_id/dat_set/samples_per_cycle/smp_synch/smp_rate/period_us/data/count/dst_mac/double_send/vlan_enabled/vlan_id/vlan_priority 逐流变破坏采样序列语义（smpCnt 配对+数据集一致性），采样值发布流无"逐流业务身份"概念）；唯一逐流变合法面=eth MAC 动态对象（allowlist eth 行既有，layer_dyn.go:21）——发布者身份逐流异合理+12.9 逃生口；序号算法两处：smpCnt=(i/step)%SamplesPerCycle（sv.go:179，step=double_send?2:1）+MAC genMAC(strategy,i)（layer_dyn.go:741-748） | layer_dyn.go（无 sv 行）；layer_dyn.go:21/:741；sv.go:179 |
| §13 schema 同步 | registry sv Fields 15 键全无 Default（mcp 决策 F 谱系；appid {uint16,Min 16384,Max 32767}/conf_rev {uint32,Max}/samples_per_cycle {uint16,Max 65535}（≥1 留 validator锚）/smp_synch {uint8}/smp_rate {uint16}/period_us {int 无界 V9 skip}/count {int,Max 1000000}/vlan_id {uint16,Max 4095}/vlan_priority {uint8,Max 7}/sv_id-dat_set string/double_send-vlan_enabled bool/dst_mac mac/data list）；validator 文案零改动（P4 不碰 sv.go）；改完重跑 schemagen（TestLayersGeneratedMatchesRegistry 绿） | 门 2 脚本；generated/layers.generated.json |
| §14 真实流程 | sv.json 全量绿 + 落盘 `/tmp/mcp-pcaps/sv/` + 二进制与 HEAD 同代 + 门 2 四项（pipe_gate.sh sv）；负例 .neg.pcap 口径沿 d323068（presence/appid 超早拒绝无落盘=既有行为）；包号/smpCnt/帧字节全部落盘重钉不照抄（14.6：12 例改写先跑拿 pcap 再钉，smp_seq/double_send/wrap 的 smpCnt 序列断言以落盘为准） | T-SV-* |
| §15 三道门 | 本表即门 1（待批）；门 2 脚本（pipe_gate.sh:67 名单+sv，八协议同口径）；门 3 挂表抽查；P5R 反查 check_sv 登记（P4，锚词+枚举+MAC 动态+presence/static/carrier 负例） | 本条目 |

#### 1. 文件清单（P2 定稿）
- Modify: `trafficgen/internal/core/layers/registry.go:707`——sv 行补 Fields 15 键（sv_id/dat_set string、appid {uint16, Min 0x4000, Max 0x7fff}、conf_rev {uint32, Min 0, Max 4294967295}、samples_per_cycle {uint16, Min 0, Max 65535}、smp_synch {uint8, Min 0, Max 255}、smp_rate {uint16, Min 0, Max 65535}、period_us {int}（无 Min/Max=V9 跳过口径）、data list、count {int, Min 0, Max 1000000}、dst_mac mac、double_send/vlan_enabled bool、vlan_id {uint16, Min 0, Max 4095}、vlan_priority {uint8, Min 0, Max 7}）——**一律无 Default**（决策 F）
- Modify: `trafficgen/internal/core/layers/chain_planner_translate.go`——`case "sv"`（case "goose" :725 邻位）：`if spec.SV == nil` 层优先（引擎直调不覆盖，goose 同款）；completedConfig + configUint16/configUint32/configUint8/configString/configBool/configUint64 逐键；data 槽位下钻——inst_mag **有符号**走原始数值断言 switch int/float64 双臂（configUint64 拒负不可用，决策 D）：`d.InstMag = int32(f)`，typ=="float32" 同源 `d.InstMagF = float32(f)`；quality presence→`HasQuality=true`（parse:7583 口径）+ configUint64→Quality。空层 `{}` 翻译出零配置→validator 首命中 appid 0x0000 下界（sv.go:26 双界既有）→ "sv appid 0x0000 outside SV range 0x4000-0x7fff"（svID 必填分支由超长例 T-20 单点钉；"sv config is required" 仅 spec.SV==nil 命中，翻译后不可达=C 类，mcp/goose 空层保底同款）
- Modify: `trafficgen/internal/core/strategy_convert.go`——CheckProtoFlat sv presence 分支（goose :7715 后追加，空 map 也死）
- Modify: `trafficgen/tools/pipe_gate.sh:67`（名单+sv）、`trafficgen/tools/coverage_gate.py`（check_sv 登记）
- Modify: `trafficgen/schemas/v1/generated/layers.generated.json`（schemagen 重跑，13.19）
- Modify: `trafficgen/test/protocol_pcap/cases/sv.json`（12 例改写+新例，T-SV 权威，P5）
- Test: `trafficgen/internal/core/layers/sv_migrate_test.go`（红例族 5 项）
- **零改动**：`internal/protocol/sv/sv.go`（validator :26 双界既有/BuildPayload/Generate/注册，字节事实不动）、`internal/core/types.go`（SVConfig/SVData 既有）——P3 假发现导致的"一行修"计划在 P4 实读后撤销

#### 2. 接口签名
- presence 锚词：`protocol sv no longer accepts a top-level sv sub-config (move it into the sv layer of an [eth,sv] layers chain)`（goose/srv6/fins 同款家族，空 map 也死，CheckProtoFlat goose 分支后追加）
- translate 签名（goose 手工逐键同款）：`raw := term.Config`（p.chain 原始层 config）→ `cfg := completedConfig(s, term.Config)`（标量补全；本层 15 键零 Default，补全即原值）→ `spec.SV = &core.SVConfig{...}` 逐键 + data 下钻 `SVData{Name, Type, InstMag int32(f), InstMagF float32(f)|type 分流, Quality, HasQuality}`
- V9 边界锚词：appid `out of range [16384,32767]`（create-time 先火，② 终审）；vlan_id `out of range [0,4095]`；validator 9 锚词原样（sv.go:23-50 零改动）

#### 3. 主流程
create 路径：ValidateStrategy → shape → semantic：ValidateLayers（V9 15 键+appid 语义边界）→ CheckProtoFlat sv presence（P4）→ checkLayerChainStaticCopy（flows>1 时 eth 显式标量拒，semantic.go:229 既有）→ 400 同文案 REST/MCP。
任务路径：mapToFlowSpec l2Only（strategy_convert.go:279）→ parseLayerDyn（eth MAC 动态对象→LayerDyn）→ ChainPlanner.ValidateSpec：validateSpecBase L2-only 豁免（chain_planner.go:499/:567）→ translateTerminalConfig `case "sv"`（spec.SV==nil 才翻译）→ protocolValidator（RegisterLayerValidator sv.go:192，9 分支）→ carrier 门（complete.go:352 V7b `[ip,sv]` 拒）→ Plan L2-only 分支（chain_planner.go:992 分支内 :1008 EtherTypeSV 回填+L3 清零）→ Generator.Generate（req.Meta.SV 经 flowMetaFor chain_planner_chain.go:28 carry；count 帧 smpCnt=(i/step)%SamplesPerCycle，sv.go:179）。
MAC 路径：src——链 drive `if pkt.L2.SrcMAC == ""` 时 l2For 补（生成器 packet() 已设 SrcMAC=req.Meta.SrcMAC 恒非空，l2For 不覆盖；goose 同款）；动态对象→worker resolveLayerTuple（layer_dyn.go:741 genMAC(i)→spec.SrcMAC）→Meta.SrcMAC→每帧。dst——层内 sv.dst_mac→sc.DstMAC→packet()（空则组播缺省）。

#### 4. 增量步骤（failing 先行，review→test→fix→review）
`sv_migrate_test.go` 红例族 5 项（goose_migrate_test.go 同构，package layers_test，import sv 包 init）：
① `TestSVChain_FlatPresenceRejected`——CheckProtoFlat("sv", {layers, sv:{}}) 返回含 "top-level sv sub-config"（空 map 也死）
② `TestSVChain_LayerFieldsAccepted`——15 键 ValidateLayers(raw, "sv") 放行（appid 取 16384 边界值）
③ `TestSVChain_LayerTranslateSmpSeq`——NewChainPlannerFromChain("sv", [eth, sv{appid:16384, sv_id, conf_rev:1, samples_per_cycle:80, data:[{name:"a",type:"int32",inst_mag:100}], count:3}]) → Validate+Plan → 3 帧 smpCnt 0,1,2（payload tag 0x82 最小编码解析，gooseStSq 同构 helper）
④ `TestSVChain_AppidBelowRangeRejected`——ValidateLayers appid 16383 → 含 "out of range [16384,32767]"
⑤ `TestSVChain_AppidZeroRejected`——链 Validate：层 config appid:0（V9 u==0 放行）→ validator 双界拒 `sv appid 0x0000 outside SV range 0x4000-0x7fff`（实现前因 translate 缺失报 "config is required"=红；转绿后恒绿=回归锁）
（V9 对 eth 显式标量放行的正交锁已在 goose_migrate_test.go TestSVChain_StaticEthRejected 恒绿，不重写）
步骤 2：registry Fields+translate case+presence 分支+pipe_gate/coverage_gate 登记+schemagen 重跑 → 5 红转绿。
步骤 3（P5）：cases 改写 12 例+新例（P3 清单驱动）→ suite 全量 → 门 2 四项。

#### 5. 错误锚词（用例 error_contains 字面值）
presence="top-level sv sub-config"；V9 appid="out of range [16384,32767]"；V9 vlan_id="out of range [0,4095]"；static="static four-tuple"；carrier="must not have an ip/transport carrier"；validator 全字面（P5 按真实执法门锚）：`sv svID is required and must be <=255 bytes`/`sv confRev must be non-zero`/`sv samples_per_cycle must be >= 1`/`sv smpSynch must be 0, 1 or 2`/`sv data is required`/`sv data type %q unsupported; only int32 and float32 are supported`/`sv is Layer 2 only and must not use IP or transport fields`。appid validator 锚词（`outside SV range 0x4000-0x7fff`）注册后对**非零**越界值被 V9 遮蔽（0x3fff→V9 create-time 拒）；**显式 0 仍达 validator**（V9 u==0 放行语义，complete.go:315-320，goose 复盘②同款分级注记）——appid 双界执法 sv.go:26 既有（P3 假发现 P4 纠正），锚词按值分派：非零越界→V9 create-time、显式 0→validator task-time。

#### 6. 性能设计与验收
单流包数=count（缺省 1，sv.go:167-170）；double_send 时 step=2（总帧数恒 n，两帧共享一 smpCnt）；生成器循环直发 Emit（sv.go:162-184，无缓冲聚合、无锁、channel 流式框架既有）；每帧 O(通道数) 序列化（BuildPayload 单遍，quality 布局分支 O(1)）；翻译一次（ValidateSpec 同步期）。回归口径：sv.json suite 耗时相对基线 ±10%。两路验收：pcap 全量绿+落盘（/tmp/mcp-pcaps/sv/）；网卡路未跑如实声明。无承诺数字（未测，不编造，goose 同款）。

#### 7. 顺序与回滚
红例→registry+translate 核心→presence→门登记→schemagen→绿；P5 cases→suite。回滚粒度=单提交：translate 真实现独立（revert 回无 case=纯链不可跑旧态，非退化）；presence 独立；cases 独立。sv.go 零改动=字节事实零风险。

#### 8. 验收
对应 T-SV（P3 定稿编号）。完成条件：5 红例先红后绿；sv.json 全量绿（RESULT+二进制同代+门 2 四项）；touched 包 `-race`+vet 净；顶层 count/sv 字面零残留（**src_mac 留顶层**：goose 同款口径，非扁平五键）；schemagen 同步绿；门 1 对照表回填实际证据号 + 抽查三条（门 3）；在库 sv 行清空（P2 时点 314+8，删前重报→备份→删→复核）。

#### §9' 关键决策对比（P2 定稿终审）

| 决策 | 候选 | 优劣 | 结论 |
|------|------|------|------|
| A appid V9 边界 | A1 {uint16, Min 0x4000, Max 0x7fff} 注册（V9 create-time 先火）；A2 只注册类型边界 Max 65535，范围留 validator task-time | A1 goose appid [0,0x3fff] 同款——锚词对真实执法门（先火门），负例超早拒无落盘=既有行为；A2 负例落 .neg.pcap 锚 validator 字面，两协议口径分裂 | **A1**（goose 复盘②谱系） |
| B period_us | B1 生成器实现 pacing；B2 C 类注记保留键 | B1 无包间隔断言面（9.27），实现不可验证；B2 如实注记 | **B2**（goose ⑦ 同判） |
| C translate 走法 | A 导出 ParseSVConfigFromMap（srv6 F1 先例）；B 手工逐键（goose/dns/mqtt 先例） | A 需新导出面；sv 无 srv6 式 []byte/指针三态陷阱，15 键手工量小且 goose 一致性优先 | **B**（goose 同款） |
| D inst_mag 有符号下钻 | A configUint64（负值静默丢弃）；B 原始数值断言 switch 双臂承接 int/float64（JSON 源恒 float64、单测 Go 字面 int 双源）→int32(f)/float32(f) | 负值是 9.8 数据场景（单测 TestBuildPayloadPreservesNegativeInt32Bytes 已锁负字节），A 破坏语义；configUint64 拒负（generator.go:571-573）不可用 | **B** |
| E MAC 动态多流例 | A sv P3 补 1；B 不补（goose 33 例也无） | B 满足"对齐"但违背 3.14 多流覆盖；A 补齐逃生口面且链路已验证可达 | **A**（goose 侧注记不回改） |
| F Fields 缺省 | A 全键无 Default；B 注册表带 Default | A 缺省单一真相在代码（D-MCP-1 决策 F 谱系）；validator 必填（svID/confRev）与 Default 语义冲突 | **A**（goose 同款） |
| G appid 下界修法 | A validator 一行修；B C 类钉现状 | **撤销**：P3 假发现——sv.go:26 双界既有，无修可做；红例⑤ 转性为回归锁 | **撤销**（P4 实读纠正） |



#### §9 规范矩阵（P1，规范要求 → 业务场景 → 代码现状 → 缺口→用例）

| 规范行 | 业务场景 | 代码现状 | 缺口→用例 |
|---|---|---|---|
| 9-2 APDU 结构（0x60+noAPDU 0x80=1+seqASDU 0xa2） | 全部正例 | 已实现（BuildPayload sv.go:109-160） | 帧字节 pin 已有（smp_seq 等） |
| ASDU 字段 tag 0x80 svID/0x81 datSet（可选）/0x82 smpCnt/0x83 confRev/0x85 smpSynch/0x86 smpRate（可选 >0）/0x87 seqData | 单字段断言面 | 已实现逐 tag（sv.go:109-160）；datSet/smpRate 条件编码 | 7 tag 字段断言 P3 逐项核对补齐（82/83/85 现有，80/81/86/87 核对） |
| 9-2LE seqData 4i4v（值 4B+quality 4B） | sv_4i4v | 已实现（HasQuality 分支） | 负 int32 字节断言（单测已有→suite 例 P3 对齐） |
| 自定义 dataset（无 datSet，4B/通道） | sv_custom_dataset | 已实现 | 已有 |
| smpSynch ∈ {0,1,2} | smp_seq/global 两值 | validator 3 值门 | 第三值例→P3 补 |
| smpCnt 周期回绕 ((i/step)%samples_per_cycle) | smp_wrap/double_send | 已实现（uint16 不截断先取模，单测 :108） | double_send 同 smpCnt 双帧断言已有；回绕序列帧 pin 已有 |
| appid 0x4000-0x7fff | 16384 正例边界 | validator sv.go:27 + V9 P4 边界 | 边界 4 值（0x4000 过/0x7fff 过/0x3fff 拒/0x8000 拒）P3 补 |
| confRev 非零 | neg_confrev | validator sv.go:33 | 已有 |
| samples_per_cycle ≥1 | neg_wrap | validator sv.go:36 | 已有 |
| 仅 int32/float32 | 4i4v | validator sv.go:46 | 非法 type 负例→P3 补 |
| L2-only（禁 IP/传输字段） | neg 类 | validator sv.go:50 + V7b carrier | [ip,sv] 负例→P3 补 |
| VLAN 802.1Q（vlan_enabled/id/priority） | sv_vlan | 已实现（生成器 L2.VLAN） | priority 3 值/ip_priority 越界负例 P3 补 |
| period_us 周期 | sv_period | **行为缺失**（生成器零消费） | C 类注记（① 立项） |

**子表① 命令×响应码矩阵：** 豁免——单向发布协议无请求-响应；替代面=上表"字段×tag"矩阵（7 tag 逐行）。
**子表② 形态变体表：** smpSynch 0/1/2 ｜ smp_rate 有/无 ｜ quality 布局 4i4v/4B ｜ dat_set 有/无 ｜ double_send 有/无 ｜ count 1/3/4/6/100 ｜ vlan 有/无（id×priority）｜ appid 边界 4 值 ｜ data type 2 值 ｜ MAC 动态/静态 。
**子表③ 商业行为→用例映射表：**

| 商业行为 | 出处 | 用例 | 状态 |
|---|---|---|---|
| 合并单元 9-2LE 4i4v 带质量形 | 继保测试仪/合并单元（抓现网 SV 组播包确认） | sv_4i4v 近似 | 待确认：抓包核对 |
| 自定义 dataset 小帧形 | 同上 | sv_custom_dataset 近似 | 待确认：同上 |

**P4 范围（预填，goose 同构）：** ①CheckProtoFlat sv presence 分支（:7715 后追加，文案 `[eth,sv]`）②registry.go:707 sv 行补 Fields 15 键 ③chain_planner_translate.go case "sv"（completedConfig+手工逐键+data 下钻 inst_mag 有符号双臂→InstMag/InstMagF、quality presence→HasQuality）④pipe_gate.sh:67+coverage_gate.py check_sv ⑤schemagen 重跑 ⑥红例族 5 项先行（sv.go 零改动——⑤ 假发现已撤销）。
**明确不解决：** 9-2 原版多 ASDU 折叠（seqASDU>1，现网合并单元单 ASDU 主流，无用例需求）；真实时间同步面（smpSynch 全局位只是字段值非时钟语义）；period_us pacing 实现（C 类①，断言面缺失不立项不冒充）；GOOSE/SV 混发编排（跨协议编排非单协议管线范围）。
**依据：** `docs/protocol-designs/24-sv-design.md`（历史参考）；IEC 61850-9-2/-9-2LE；代码事实：`sv/sv.go:20-192`（Validate 9 分支/BuildPayload/Generate/注册）、`core/types.go:1630-1680`（SVData/SVConfig 15 键）、`strategy_convert.go:7571`（parseSVConfig）、`strategy_convert.go:224`（isL2OnlyProtocol）、`chain_planner.go:992/:1008`（L2-only EtherType 回填）、`chain_planner.go:499/:567`（validateSpecBase 豁免）、`chain_planner_chain.go:28`（FlowMeta.SV）、`layer_dyn.go:21`（eth allowlist）/:741-748（genMAC→spec.SrcMAC）、`builder.go:17`（EtherTypeSV=0x88BA）、`complete.go:352`（V7b carrier）、`semantic.go:229`（static-eth 门，goose ⑥ 已含 sv）、`sv_test.go`（7 单测）。

### D-REWORK-1 顶层白名单整改：游离字段全迁层（CORE_MEMORY 1.11-1.13）【P-PIPE 返工，2026-09-19 用户指令】

**状态：** 已验收（2026-09-19；审计 13 已完成协议+ftp——goose 顶层 src_mac×32 / sv×30 / http 顶层 ttl×1 / srv6 顶层 dst_mac×1 + mpls/gre 伪配置×2；其余九协议顶层仅 presence/flat 拒绝负例=正当测试面，mqtt group_id=flow_control 家族框架键不属违规。整改后**已完成协议顶层游离字段零残留**）

**根因（自审）：** 1.4 五键清单被当成全集执行，"清单没点名"被当"允许"；且自创 CORE_MEMORY 无依据的"登记保留"豁免写进门1表——成本考量（字节不重钉/代码不动）越权到原则前面。用户裁定：黑名单漏点的键以白名单原则为准（1.11-1.13，用户授权增补）。

**整改内容：**
- 代码①：`extractLayerMACs`/`extractLayerIPTTL`（strategy_convert.go，extractLayerSrcDst 同构）——eth 层静态 src_mac/dst_mac → spec.SrcMAC/DstMAC、ip 层显式 ttl → spec.TTL；动态对象照旧走 resolveLayerTuple（零变化）
- 代码②：`checkLayerFlatConflict` 扩列 +src_mac/dst_mac（semantic.go）——layers 与顶层 MAC 并存=混用 400（1.4 例举非全集的执法化）
- 测试：3 红先红后绿（TestEthLayerStaticMACConsumed/TestIPLayerTTLConsumed/TestTopLevelMACWithLayersRejected，top_level_whitelist_test.go）
- 用例：goose 32 例+sv 30 例顶层 src_mac 迁入 eth 层（MAC 值不变，帧字节逐字节一致——suite pin 未动即证）；http_ttl_custom 删顶层 ttl 影子（ip.ttl 128 已在，回填链路补通）；srv6 vp04 顶层 dst_mac→链头新增 eth 层（[eth,ip,srv6]，isRawIPChain 按末层判定不受影响）；srv6 vn18/19 删 mpls/gre 伪配置键（1.12：不消费字段必须删除，功能不实现语义保留在"明确不解决"段）
- 门：pipe_gate.sh 门2① 禁列扩 +src_mac/dst_mac/ttl（黑名单为实现手段，白名单以 1.11 为准）
- 覆盖：D-GOOSE-1/D-SV-1 §8"src_mac 留顶层"与 D-SRV6-1 D1/D 决策（dst_mac 顶层保留）自本条目起**废止**；各 T-条目状态行已注记

**验证：** 三红转绿；四协议 suite 全绿（goose 33/sv 30/http 67/srv6 74，pin 零改动=字节一致性证明）；其余九已完成协议回归全绿（dns/mqtt/smtp/pop3/imap/mcp/fins/tls/gre）；core/schema -race 绿；门2 四协议全绿（新禁列下顶层零残留）；已完成协议顶层游离复核 0。

**影响后续管线：** 未完成协议（modbus src_mac/dst_mac×213、isis src_mac×24、dhcpv6 src_mac×1 等）的存量顶层 MAC/TTL 一律按 1.11 在各自 P-PIPE 迁入 eth/ip 层——门2① 新禁列已能拦截。

**依据：** CORE_MEMORY 1.11-1.13（2026-09-19 用户授权增补）；用户指令"将所有的已经完成的协议有问题的，全部整改，并重新测试"。

### D-ICMPV6-1 ICMPv6 层链化：raw-IP 终结层 + 新建 layer_gen/validator【P-PIPE #14 门1】

**状态：** 已验收（2026-09-19，P-PIPE #14 收官；自审 2 轮净）。**P4**（34fdf62）：5 红例先红后绿（①presence ②6键V9 ③translate Echo对 ⑤step缺省镜像parse ⑥D-FTP-4动态豁免，④v4拒），实现八件+门登记+schemagen 97层，touched 包 -race 净。**P5**：icmpv6.json 11 例（改写1+新建10）真实流程全量绿 ×5 连跑（含 2 稳定性复跑），落盘 /tmp/mcp-pcaps/icmpv6/（11 例 9 文件：7 正例 pcap+4 负例 .neg.pcap）；门2 四项绿（顶层零残留/全量绿/二进制同代/反查 18/18）；回归 srv6 74/74+sv+goose 绿（igmp 红=序号69 存量扁平待办，判死门正确执法非本次回归）。**P6**：在库清空 tasks 150+strategies 11→0/0 无孤儿（备份 /tmp/trafficgen-backup-icmpv6-p6-20260919-140741.db）。

**P4/P5 实现修正三注记（对 P2 预填的偏差，均不违设计决策）：**
- **validateLayer 补 D-FTP-4 豁免**（红例⑥）：ip.src/dst 层动态对象时 spec 解析前带 flat 缺省 10.0.0.1（异族），裸委托 legacy Validate 会误杀动态多流——与 validateSpecBase chain_planner.go:587 同口径 `HasLayerDynIP` 跳过静态判族（逐流同族性由 ValidateLayers 保证，generate 期 legacy Plan 内 Validate 按解析值复验）。T-4 静态 v4 拒绝不受影响（suite 实证）。
- **translate pattern step 缺省镜像**（红例⑤）：parse 的 step 级 type→128/seq==0→index+1/data→"ping" 缺省在 translate 侧同步镜像（P2 决策 D 的 step 级细化；自审第 1 轮抓到，failing 先行修）。
- **T-8 显式三键 + T-11 group_id/strategy_fc**（P5 校准）：T-8 改 identifier=7/sequence=9/data="probe" 显式（9.21 identifier 显式格落此例，id≠seq 证非回退）；T-11 补 strategy_fc flows=2（用例漏传致单流）+ 固定 group_id 强制单 worker FIFO 确定序（srv6_mf03 先例，分片路由流序不定），源序列 [::1,::9,::2,::9] 按 pcap 实钉。

**门3 抽查三条（门1 表抽 §1/§5/§12 行，逐条点行号/用例号）：**
1. §1 层链唯一真相 → registry.go icmpv6 行（CategoryTerminal+DependsOn ip+FieldContract "ip.protocol":"58"+Fields 6 键，registry.go:745-760）+ 用例 icmpv6_smoke_01 层形 `[{"ip":{...}},{"icmpv6":{}}]` ——表内"四件套"声明与代码实形一致 ✓
2. §5 有错必处理（锚词族）→ layer_gen.go validateLayer（type/code/pattern 分支 layer_gen.go:63-73+legacy 复用 :80）+ 用例 icmpv6_neg_type error_contains 全文匹配锚词 `icmpv6 type must be 128 (Echo Request) or 129 (Echo Reply), got 130`（suite PASS 实证）✓
3. §12 动态清单（业务 6 键全关+四元组开 ip.src/dst）→ layer_dyn.go allowlist 无 icmpv6 行（业务键零动态）+ 用例 icmpv6_ip_dyn_multi ip.src inc 对象逐流异（4 包源 [::1,::9,::2,::9] 实钉）✓

（原 P2 定稿记录：门 1 已批（用户"可以，连续推进"）；CORE_MEMORY 240 条逐条复审（含 1.11-1.13 增补）完成——全过 + 关键预判 4 项；依赖链② P2 实读修正（legacy Validate 已有 v6 强制 icmpv6.go:60-79，非无校验）+ 设计八节 + 决策表 A-F 定稿见下。链形判定：[ip,icmpv6] raw-IP 终结层（igmp/ospf/pim 同款，FieldContract ip.protocol=58））

**权威链（§7）：** 标准=RFC 4443（ICMPv6，4.9 有 RFC 直接适用：type 128/129 §4.1、校验和 §2.3 经 IPv6 伪头 RFC 8200 §8.1 nextHeader=58）→ 设计=本条目（权威）→ 代码 → 测试。字节事实经 Wireshark packet-icmpv6 + iputils ping6 双转录。

**依赖链判定（P1 预判，P2 定稿复核）：**

| # | 断链层 | 判定 | 处置 |
|---|---|---|---|
| ① 层链四件全缺 | 代码缺口（未翻转） | registry/translate/FlowMeta/注册全无；legacy 直挂 main.go:541 | P4 四件套+红例族（registry Fields 6 键+FieldContract ip.protocol=58、translate case 手工逐键、FlowMeta.ICMPv6+carry、layer_gen 包装 legacy Plan+RegisterLayerGenerator/Validator） |
| ② v4 拒绝（P1 预判修正，P2 实读） | 检查既有、层链未接 | legacy Validate **已有 v6 强制**（icmpv6.go:60-79，锚词 `must be IPv6 (got IPv4)`）——types.go:2860 注记是"为何要查"的背景说明非"无校验"声明；层链路径不经 legacy Validate=检查未接 | P4 layer validator 复用 legacy v6 检查（零新文案）+type/code/pattern 新分支；红例④ 经链路径先红 |
| ③ FileSource 层链不可达 | 配置面缺口 | parseFileSource 读顶层子映射（strategy_convert.go:1428）；扁平判死后 file_source 无住处；现网用例零使用 | P4 translate 不映射 file_source+C 类注记（需要时另立项）；不强迁 |
| ④ 组合流替代面 | 9.11 判定 | Echo 会话天然多动作：Pattern 多步（stepN request/reply、Sequence 递增）即组合序列本体 | 组合例=Pattern 多步 2 条（≥3 动作面） |

#### 门 1 开工对照表（§1–§15，2026-09-19，CORE_MEMORY 240 条逐条复审通过后交付；证据=文档节/代码行/用例号）

| § | 本协议怎么满足 | 证据 |
|---|---|---|
| §1 层链唯一真相 | 链形 `[ip,icmpv6]`（raw-IP 终结层，无传输层）：顶层旧键去向——`src_ip/dst_ip`→`layers[ip].src/dst`（v6 显式）、`icmpv6` 子映射 6 业务键→`layers[icmpv6]` 直迁（type/code/identifier/sequence/data/pattern）、count 无（包数=2×ping 步数由 type/pattern 语义决定）；无 MAC/TTL 顶层残留（用例无 src_mac）。目标形状：`{"layers":[{"ip":{"src":"2001:db8::1","dst":"2001:db8::2"}},{"icmpv6":{"type":128,"identifier":1,"sequence":1,"data":"ping"}}]}`。P4 四件：①registry icmpv6 行（CategoryTerminal+DependsOn ip+FieldContract "ip.protocol":"58"+Fields 6 键无 Default）②translateTerminalConfig case "icmpv6"（parse 未导出不可跨包，手工逐键+pattern 槽位下钻）③FlowMeta.ICMPv6+flowMetaFor carry+isRawIPChain 加 icmpv6+validateSpecBase 两处端口豁免清单加 icmpv6（chain_planner.go:505/:701）④layer_gen 新建包装 legacy Plan+注册 | icmpv6.json 1 例审计；strategy_convert.go:732（parse 现状）；types.go:2866（ICMPv6Config 6 键）；main.go:541 |
| §2 策略/任务分工 | 沿框架；策略=一条 ping 会话模板（type/pattern 语义定包数）自带 strategy_fc；任务=多策略合跑总封顶；flows=N 复制 N 条 ping 流（ip.src 动态对象逐流异=逃生口）；spec 不管数量（包数由 type/pattern 决定：单 ping=2 包，Pattern N 步=2N 包） | icmpv6.go:89（Plan 语义） |
| §3 五件套 | **单流多 ping 编排**（Echo 有真实事务语义，不清空豁免）：会话表=豁免（RFC 4443 Echo 无握手无多会话，一 flow=一 Identifier 会话）；事务序列=每 ping 一事务（request→auto-reply 两包对，up/down）；关联关系=Identifier 跨 step 共享标识会话（RFC 4443 §4.1）+Sequence 每步递增（step 缺省 index+1）；插入位置=icmpv6 终结层自产完整包（raw-IP 驱动 chain_planner.go:1147，builder 补 L2 MAC 与伪头校验和）；时间线=up/down 顺序交替、Pattern 逐 step 顺序推进 | types.go:2850-2865 注记；icmpv6.go:89 |
| §4 规范矩阵 | RFC 4443（4.9）：type/code §4.1、伪头校验和 §2.3+RFC 8200 §8.1、上包必须 v6；P1 矩阵见本条目 §9+三张子表（①命令×响应=Echo Request→Reply 对映 type 128↔129 替代面） | RFC 4443 §2.3/§4.1 |
| §5 有错必处理 | validator **P4 新建**（legacy 无校验）：锚词族——type 非法（非 128/129）、地址非 v6（requires IPv6，②）、pattern step 非法 type、code 范围；依赖：ip 层 DependsOn（FieldContract ip.protocol=58 框架既有）、FlowMeta.ICMPv6、raw-IP 驱动 down 交换既有（chain_planner.go:1168） | 依赖链①② |
| §6 性能 | 包数=2×ping 步数（单 ping 2 包；Pattern N 步 2N 包）；生成器=legacy Plan 包装（channel 流式既有，无全量收集、无锁）；翻译一次（ValidateSpec 同步期）；伪头校验和每包 O(len(data))；回归口径 suite 耗时 ±10%；无吞吐数字（未测不承诺）；网卡未跑 | icmpv6.go:89 |
| §7 三份文档 | 设计=本条目；用例=T-ICMPV6 清单（P3，存量 1 例逐条审计）；cases 回指编号 | TEST_CASES T-ICMPV6-* |
| §8 先设计后代码 | 门1 批复→P1 矩阵→P3 清单→failing 先行红例→P4 代码 | 本条目 |
| §9 三源+整格 | 三源：RFC 4443+iputils ping6 行为（现网，待确认抓包）+Wireshark 解码（开源转录）；枚举：type{128,129}、code{0}、Pattern 0/1/N 步、identifier 0 回退 sequence 语义、data 字节、v4 拒绝；正交：type×pattern×data×identifier/sequence；组合 2 条=Pattern 多步（④）；断言边界：Reply 即时性注记 | P1 矩阵子表 |
| §10 评审闭环 | failing 先行红例族（①presence 拒②层 6 键 V9 放行③translate 上线 2 包 Echo 对④v4 拒）→改→审→测→再审；vet+`-race` | P4 |
| §11 白话汇报 | 先一句结论 | 每次汇报 |
| §12 动态清单 | 业务 6 键全关动态（allowlist 不加 icmpv6 行——type/code/pattern 是报文类型与序列选择器，逐流变破坏 Echo 会话配对；identifier/sequence 是会话/序号语义非逐流身份；data 是载荷）+file_source 不映射（③）；四元组开：ip.src/dst 动态对象（框架 allowlist 既有，多流逃生口）；序号算法=Sequence 每步 +1（icmpv6.go Plan 内，缺省 step index+1） | layer_dyn.go（无 icmpv6 行）；icmpv6.go Plan |
| §13 schema 同步 | registry icmpv6 行（6 Fields 无 Default：type{uint8}/code{uint8}/identifier{uint16}/sequence{uint16}/data{string}/pattern{list}；128/129 与 v6 族约束留 validator）+FieldContract "ip.protocol":"58"（igmp=2/ospf=89/pim=103 同款框架块）；translate 6 键+pattern 下钻；schemagen 重跑（TestLayersGeneratedMatchesRegistry 绿） | registry.go igmp 先例 |
| §14 真实流程 | icmpv6.json 全量绿+落盘 `/tmp/mcp-pcaps/icmpv6/`+二进制同代+门 2 四项；负例 .neg.pcap 口径；包号/type/伪头校验和落盘重钉不手算（v6 地址不变预期字节一致） | T-ICMPV6-* |
| §15 三道门 | 本表即门1（待批）；门2 脚本（pipe_gate 名单+icmpv6、coverage_gate check_icmpv6 登记）；门3 挂表抽查 | 本条目 |

#### §9 规范矩阵（P1，规范要求 → 业务场景 → 代码现状 → 缺口→用例）

| 规范行 | 业务场景 | 代码现状 | 缺口→用例 |
|---|---|---|---|
| RFC 4443 §4.1 Echo type 128/129 code 0 | 冒烟例（存量） | 已实现（legacy Plan+auto-reply） | 存量 1 例改写+type 129 单独例 P3 补 |
| §2.3 伪头校验和（nextHeader=58） | 全部正例 | 已实现（builder 伪头） | v4 静默零校验和=①②→validator 拒+负例 P3 |
| Identifier 会话/Sequence 递增 | 多步 Pattern | 已实现（step 缺省 index+1） | Pattern 多步组合例×2（④）P3 |
| data 载荷（缺省 "ping"） | 存量例 | 已实现（getStringDefault） | data 显式字节 pin P3 |
| RFC 8200 §8.1 上包 v6 | 冒烟例 | 无校验 | v4 负例（②） |
| ip.protocol=58 | 框架 FieldContract | 既有块（igmp=2 同款） | 框架覆盖无缺口 |

**子表① 命令×响应矩阵：** 替代面=Echo Request(128)→Reply(129) 对映（无响应码表协议族）；Pattern 每步一对。
**子表② 形态变体：** type 2 值｜Pattern 0/1/N 步｜identifier 0 回退/显式｜sequence 缺省递增/显式｜data 缺省/显式/变长｜v4/v6 地址。
**子表③ 商业行为→用例：**

| 商业行为 | 出处 | 用例 | 状态 |
|---|---|---|---|
| Linux ping6 Echo 对（id/seq 递增） | iputils ping6+抓包确认 | 存量冒烟近似 | 待确认：抓 ping6 包核对 |

**P4 范围（预填）：** ①registry icmpv6 行（Fields 6 键+FieldContract ip.protocol=58）②translate case "icmpv6"（6 键+pattern 下钻；file_source 不映射③）③FlowMeta.ICMPv6+carry+isRawIPChain+validateSpecBase 两豁免清单 ④layer_gen 新建（包装 legacy Plan；RegisterLayerGenerator/Validator）⑤validator 新建（type 128/129、v6 族、pattern step、code）+CheckProtoFlat presence ⑥pipe_gate/coverage_gate 登记+schemagen ⑦红例族 4 项先行。
#### 1. 文件清单（P2 定稿）
- Modify: `internal/core/layers/registry.go`——icmpv6 行（CategoryTerminal+DependsOn ip+FieldContract `"ip.protocol":"58"`+Fields 6 键：type{uint8}/code{uint8}/identifier{uint16}/sequence{uint16}/data{string}/pattern{list}，一律无 Default——决策 F）
- Modify: `internal/core/layers/chain_planner_translate.go`——case "icmpv6"（spec.ICMPv6==nil 层优先；6 键逐映射+pattern 槽位下钻；**缺省镜像 parse**（决策 D）：type 缺省 128/code 0/sequence 1/data "ping"——空层=合法缺省 ping，存量例语义保持；data 字符串直转 []byte 无 []byte 陷阱）
- Modify: `internal/core/layers/generator.go`——FlowMeta.ICMPv6+flowMetaFor carry
- Modify: `internal/core/layers/chain_planner_util.go:40`——isRawIPChain 加 icmpv6
- Modify: `internal/core/layers/chain_planner.go:505/:701`——两处端口豁免清单加 icmpv6（raw-IP 同款；mapToFlowSpec 12345/80 缺省对 raw-IP 无 L4 头无害，igmp 同款）
- Modify: `internal/core/strategy_convert.go`——CheckProtoFlat icmpv6 presence 分支（sv 后邻位，空 map 也死）
- Create: `internal/protocol/icmpv6/layer_gen.go`——Generator 包装 legacy Plan（meta→等价 FlowSpec 复用零分叉）+validateLayer（复用 legacy v6 检查+新分支 type∈{128,129}/code==0/pattern step type）+init RegisterLayerGenerator/Validator
- Modify: `tools/pipe_gate.sh:67`+`tools/coverage_gate.py` check_icmpv6、`schemas/v1/generated/layers.generated.json`（schemagen）
- Modify: `test/protocol_pcap/cases/icmpv6.json`（1 例改写+新例，T-ICMPV6 权威，P5）
- Test: `internal/core/layers/icmpv6_migrate_test.go`（红例族 4）
- 零改动：`internal/protocol/icmpv6/icmpv6.go`（legacy Plan/Validate 字节事实）

#### 2. 接口签名
- presence 锚词：`protocol icmpv6 no longer accepts a top-level icmpv6 sub-config (move it into the icmpv6 layer of an [ip,icmpv6] layers chain)`
- validator 锚词：`icmpv6 config is required`（spec.ICMPv6==nil 翻译后不可达=C 类，与 translate 保底同款）/`icmpv6 type must be 128 (Echo Request) or 129 (Echo Reply), got %d`/`icmpv6 code must be 0 for Echo, got %d`/`icmpv6 pattern step %d type must be 128 or 129, got %d`/legacy 复用 `must be IPv6 (got IPv4)`（零新文案）

#### 3. 主流程
create：ValidateStrategy→ValidateLayers（V9 6 键）→CheckProtoFlat presence→checkLayerChainStaticCopy（ip 层显式+flows>1 拒，既有）→400。
任务：mapToFlowSpec（raw-IP 非 l2Only，spec 端口缺省 12345/80 对无 L4 头无害）→parseLayerDyn（ip.src/dst 动态）→ChainPlanner.ValidateSpec：validateSpecBase（icmpv6 端口豁免①②）→translate case "icmpv6"→validateLayer（注册后链上同步拒）→Plan：isRawIPChain→raw-IP 驱动（flowMetaFor+meta 补齐 SrcIP/DstIP/TTL→Generator.Generate→legacy Plan(ctx, 等价 spec)→包 relay；down 包 L3 交换 :1168 既有→builder L2 MAC 缺省+伪头校验和）。

#### 4. 增量步骤（failing 先行）
`icmpv6_migrate_test.go` 红例族 4（sv_migrate 同构）：①TestICMPv6Chain_FlatPresenceRejected ②TestICMPv6Chain_LayerFieldsAccepted（6 键 V9 放行）③TestICMPv6Chain_LayerTranslateEchoPair（链 [ip{v6},icmpv6{identifier:1,sequence:1}] 缺省 type 128→Validate+Plan→2 包，payload[0]==128/129）④TestICMPv6Chain_V4Rejected（链 v4 地址→Validate 拒 `must be IPv6`——实现前无 validator=静默放行红）。步骤 2 四件套→4 红转绿。

#### 5. 错误锚词
见 §2；另 static=`static four-tuple`（semantic.go 既有门）。

#### 6. 性能设计与验收
包数=2×ping 步数（单 ping 2 包/Pattern N 步 2N 包/type 129 单包）；legacy Plan 包装（channel 256 流式既有，无锁无收集）；翻译一次；伪头校验和每包 O(len(data))（builder 既有）；回归口径 suite 耗时 ±10%；无吞吐数字（未测不承诺）；网卡未跑。

#### 7. 顺序与回滚
红例→registry+translate→FlowMeta/isRawIPChain/豁免→layer_gen+注册→presence→门登记+schemagen→绿；P5 cases。回滚=单提交粒度（layer_gen revert=纯链不可跑旧态非退化；presence/cases 独立；icmpv6.go 零改动=字节事实零风险）。

#### 8. 验收
对应 T-ICMPV6（P3 定稿）。完成条件：4 红例先红后绿；icmpv6.json 全量绿（RESULT+二进制同代+门 2 四项）；touched 包 -race+vet 净；顶层 src_ip/dst_ip/icmpv6 字面零残留；schemagen 同步绿；门 1 表回填+抽查三条；在库 icmpv6 行清空（P6 删前重报→备份→删→复核）。

#### §9' 关键决策对比（P2 定稿终审）

| 决策 | 候选 | 优劣 | 结论 |
|------|------|------|------|
| A 链形 | A1 [ip,icmpv6] raw-IP 终结；A2 [eth,ip,icmpv6] 带 eth | MAC 无业务语义（存量例无 MAC 断言，builder 缺省即可）；A2 多一层无用形状 | **A1**（igmp/ospf/pim 同款） |
| B 生成器 | B1 包装 legacy Plan（等价 spec 复用）；B2 重写发射逻辑 | B1 Echo 配对/Pattern/伪头全复用零分叉、legacy Validate v6 检查同享；B2 重复实现风险 | **B1**（srv6 同款） |
| C 校验器 | C1 新建 validateLayer（type/code/pattern+复用 legacy v6）；C2 仅 legacy Validate | 层链 ValidateSpec 不经 legacy→C2 全漏；C1 层链同步拒 | **C1** |
| D translate 缺省 | D1 镜像 parse 缺省（type 128/code 0/seq 1/data "ping"，空层=合法缺省）；D2 无缺省必显式 | D1 保持存量 icmpv6:{} 语义+parse 单源对照口径；D2 破坏存量例 | **D1** |
| E file_source | E1 translate 映射；E2 不迁+C 类（③） | 零用例需求+parseFileSource 未导出复刻有风险 | **E2**（1.12：需要时立项） |
| F registry Fields | F1 注册 6 键（V9 键面）；F2 igmp 空层式（语义全默认） | F1 层可表达 type/pattern 等业务值+V9 域校验；F2 只能空层全缺省 | **F1**（GOOSE 谱系） |

**明确不解决：** RFC 4861 邻居发现（独立协议族非 Echo 语义）；file_source 层链化（③ C 类）；Error 消息类 type（1-4 类非 Echo 面，legacy 未实现不冒充）。
**依据：** RFC 4443 §2.3/§4.1；RFC 8200 §8.1；代码事实：`icmpv6/icmpv6.go:47/:89`（legacy Plan）、`core/types.go:2848-2883`（ICMPv6Config/Step 6 键+伪头注记）、`strategy_convert.go:732-743`（parse）、`:1428`（file_source）、`chain_planner_util.go:40`（isRawIPChain）、`chain_planner.go:505/:701`（端口豁免清单）、`:1168`（down 交换）、`layers/generator.go:215`（FlowMeta）、`main.go:541`（legacy 直挂现状）。


### D-H323-1 H.323 层链化：raw 自驱终层（三平面整包 relay）+ 端口住层【P-PIPE #15 门1】

**状态：** 已验收（2026-09-19，P-PIPE #15 收官；自审 2 轮净）。**P4**（7bc70a8）：6 红例先红后绿——红例③当场抓出包数公式手算错（15→16/呼叫，Q.931 实为 10 条）与 msg_type 偏移错（payload[8] 非 [7]），红例⑥直证静态复制门漏扫执法洞；touched 包 -race 净。**P5**：h323.json 17 例（改写 1+新建 16）真实流程全量绿 ×3 连跑，落盘 /tmp/mcp-pcaps/h323/（17 例 14 文件：11 正例 pcap+6 负例 .neg.pcap）；首跑 13/17 后实钉重校 3 例（T-11 显式 crv=0x1000→0x1001 逐呼叫递增 frame pin、T-15 tshark Q.931 方向性伪影——down 侧消息不出 message_type、T-16 frame.len=83/83 与 smoke 全等证长度保持重写）+T-6 锚词校准（V9 先拦，registry Min=0 使 legacy ">=0" 不可达）；ras_only 合成 stub 触发 tshark H.225.0 malformed=按字节证据（8×60B 五元组逐包验证）加白名单条目 h323_scenario_ras（legacy 合成器字节合同，先例 doip_userdata_empty）；门2 四项绿（反查 24/24）；回归 icmpv6/srv6/sv/goose 全绿。**P6**：在库清空 tasks 216+strategies 15→0/0（备份 /tmp/trafficgen-backup-h323-p6-redo-20260919-172347.db；**事故注记**：首次清库误在错误 cwd 的相对路径上执行（sqlite3 静默打开仓库根旧库读出 0），因对账（总行数 -216 吻合）复核发现后以绝对路径重做——删后总行数 241478→241262 精确对账）。

**门3 抽查三条（门1 表抽 §1/§5/§12 行）：**
1. §1 层链唯一真相 → registry.go h323 行（CategoryTerminal+DependsOn ip+Fields 10 键无 Default）+ 用例 h323_smoke_01 层形 `[{"ip":{...}},{"h323":{"src_port":12345,"dst_port":1720}}]`，存量断言字节等价保留（suite PASS 实证）✓
2. §5 有错必处理（锚词族）→ layer_gen.go validateLayer（required 保底+legacy Validate 复用）+ 用例 h323_neg_role error_contains `invalid role`（h323.go:125 零新文案，suite PASS 实证）✓
3. §12 动态清单（业务 8 键全关+端口 2 键开）→ layer_dyn.go allowlist "h323" 行（红例⑤实证）+ 用例 h323_port_dyn src_port inc 对象逐流异（32 包源口 30000/30001 pcap 实钉）✓

（原 P2 定稿记录：门 1 已批（用户"继续"）+ 待批三项同批（1.2 偏离批、端口动态开）；CORE_MEMORY 240 条逐条复审完成——**对抗重审 4 轮，抓到并改正 4 处事实错误**（Validate 锚词 6→8、parse 文案 6→7、包数公式手算错、在库数 94→95），末轮净；设计八节+决策 A-E 见下；P3 未开工）。现状：legacy planner 完整（h323.go:159，三平面一体：Q.931/TCP 1720 TPKT、H.245 隧道于 FACILITY、RAS/UDP 1719、RTP/UDP，自带握手/挥手与 seq/ack，参考 pcap 字节复刻 types.go:5455-5472），main.go:563 直挂 legacy，**层链四件全缺**（registry 无行/translate 无 case/FlowMeta 无字段/无 generator——grep 实证含 generator.go rc=1）。用例 1 例纯扁平（四元组+count+顶层 h323:{}）→P5 改写。

**架构裁定（门1 已批）：** **A1 [ip,h323] raw 自驱终层整包 relay**（icmpv6 包装法 + force-up 防双换）。可行性三点实证：①builder `if l4Len>0 {writeL4}` 链形无关（builder.go:404）；②raw-IP relay Emit→out 通道（chain_planner.go:1200）；③legacy 包自带 L2/L3/L4（协议 6/17 混合，h323.go:251/:460/:546），生成器逐包给全、drive 只补缺省。A2（事件重写）否决：RAS/RTP UDP 面单链无处安放、seq/ack 换框架破字节契约。端口住 h323 层（1.2 字面偏离已批，srv6 inner 端口先例）。

**权威链（§7）：** 标准=ITU-T H.225.0（Q.931 信令 TCP 1720 §7.3、RAS UDP 1719 §7、H.245 隧道）+ITU-T Q.931+RFC 1006（TPKT）+RFC 3550（RTP）→ 设计=本条目（权威）→ 代码 → 测试。字节事实=参考 pcap 转录（types.go:5466，直呼无 GK，4 quirk）+Wireshark packet-h225/h245 dissector。

**依赖链判定：**

| # | 断链层 | 判定 | 处置 |
|---|---|---|---|
| ① 层链四件全缺 | 代码缺口 | registry/translate/FlowMeta/layer_gen 全无；main.go:563 直挂 | P4 四件套+红例族（registry 10 键、translate case、FlowMeta.H323+carry、layer_gen 包装+注册） |
| ② legacy 校验已全 | 无缺口（icmpv6 式修正不适用——P1 重审实证 Validate 8 锚词覆盖 IP/nil/role/scenario/calls/display/MSS，parse 7 文案） | 层链路径只缺接线 | validateLayer=required 保底+复用 legacy Validate（零新文案） |
| ③ 静态复制门漏扫 | 执法洞 | checkLayerChainStaticCopy 只扫 ip/tcp/udp/eth（semantic.go:186），h323 层端口标量+flows>1 漏拒（12.9 违规面） | P4 扫描列表加 "h323"（layerTupleFields 默认分支恰返 src_port/dst_port）+红例⑥ |
| ④ MSS 链上不可达 | C 类 | spec.TCP.MSS 仅扁平路可达（扁平已死）；链上无 tcp 层=无 MSS 住处 | 明确不解决：syn options 恒 DefaultMSS 1460（legacy 合成器字节事实） |
| ⑤ 端口动态 | 用户已批开 | allowlist 无 h323 行=端口对象即 does not support dynamic | P4：LayerDynValues.H323+LayerH323Dyn{SrcPort,DstPort}+allowlist 行+parseLayerDyn case+resolveLayerTuple 块+HasAny（同键二态：对象解析值落 spec、translate 标量覆盖/对象放行） |

#### 门 1 对照表（已批，证据回填版）

§1 键去向：src_ip/dst_ip→layers[ip].src/dst；src_port/dst_port→layers[h323]（已批偏离）；count→删；顶层 h323 8 业务键→layers[h323] 直迁。目标形状 `{"layers":[{"ip":{"src":"10.0.0.1","dst":"20.0.0.1"}},{"h323":{"src_port":12345,"dst_port":1720}}]}`。§3 五件套：呼叫=会话（Calls 声明、Crv+callNum h323.go:283）、事务=SETUP→CP→FACILITY(TCS/TCSACK/MSDACK)→ALERTING→FACILITY→CONNECT→[RTP]→RELCOMP×2、无跨流关联（H.245 隧道在流内=豁免注记）、插入=h323 终层自产完整包、呼叫间串行。§12 动态：业务 8 键全关（结构选择器/会话语义，icmpv6 同判）；四元组=ip.src/dst（框架）+h323 端口（已批开）；序号=Crv+callNum+worker 12345+i。

#### 决策对比（4.17）

| 决策 | 候选 | 结论 |
|------|------|------|
| A 链形 | A1 [ip,h323] raw 自驱整包 relay vs A2 [ip,tcp,h323] 事件重写 | **A1**（三平面保真+字节契约；A2 RAS/RTP 断供） |
| B 端口住处 | B1 h323 层键+门扩扫 vs B2 假 tcp 层只作宿主 | **B1**（结构诚实；B2 形状欺骗） |
| C 翻译 | C1 手工逐键镜像 parse（icmpv6 法）vs C2 导出 parseH323Config | **C1** |
| D 校验 | D1 复用 legacy Validate 零新文案 vs D2 新写 | **D1**（8 锚词全覆盖） |
| E 端口动态 | E1 开 2 键（对象=逐流端口池）vs E2 关（只 worker 保底） | **E1**（用户已批；12.13 与 tcp/udp 语义对齐） |

**明确不解决：** GK 路由模式（仅直呼）；MSS 链上覆盖（④ C 类）；H.245 独立通道（非隧道形态）；RAS 现网字节确认（规范编码已实现，抓包待确认注记）。

#### 1. 文件清单（P2 定稿）
- Modify: `internal/core/layers/registry.go`——h323 行（CategoryTerminal+DependsOn ip+无 FieldContract+Fields 10 键无 Default：role/scenario{string}、crv{uint16}、display_name{string}、calls{int}、rewrite_addr{bool}、media/ras{object}、src_port/dst_port{uint16}——决策 F：缺省语义在 translate 镜像 parse）
- Modify: `internal/core/layers/chain_planner_translate.go`——case "h323"（spec.H323==nil 层优先；8 业务键逐映射+media/ras 子映射下钻；缺省镜像 parse：role caller/scenario full/crv getIntPresence 0x2584/display "Administrator"/calls 1/media{5062,5063,10,pt0,160}/ras{1719,"10.12.184.53","terminal"}；端口同键二态：src_port 标量→spec.SrcPort、dst_port 标量→spec.DstPort（缺席→1720 镜像 setDefaultDstPort）、对象→放行（resolveLayerTuple 已解析））
- Modify: `internal/core/layers/generator.go`——FlowMeta.H323+carry（chain_planner_chain.go flowMetaFor）
- Modify: `internal/core/layers/chain_planner_util.go`——isRawIPChain 加 h323
- Modify: `internal/core/layers/chain_planner.go`——validateBaseDstPortHandled+SrcPort 零保持两名单加 h323（端口经 translate 后到，base 检查期 spec 端口仍 0）
- Modify: `internal/core/strategy_convert.go`——CheckProtoFlat h323 presence 分支（sv/icmpv6 先例）
- Modify: `internal/core/schema/semantic.go`——checkLayerChainStaticCopy 扫描列表加 "h323"（③）
- Modify: `internal/core/layer_dyn.go`+`internal/core/types.go`——LayerH323Dyn/LayerDynValues.H323/HasAny/allowlist "h323" 行/parseLayerDyn case/resolveLayerTuple 块（⑤）
- Create: `internal/protocol/h323/layer_gen.go`——Generator 包装 legacy Plan（等价 FlowSpec：SrcIP/DstIP/TTL/MAC/端口/H323 直传；force Direction="up" 防双换——legacy 逐包自管方向/地址/seq-ack，drive down-swap 会错换；GenEvents 返 nil——chain_planner.go:1216 事件分支判定）+validateLayer（required 保底+legacy Validate 复用零新文案）+init 注册
- Modify: `cmd/server/main.go:563`——NewChainPlanner("h323")+空导入
- Modify: `tools/pipe_gate.sh`+`tools/coverage_gate.py`（check_h323）、schemagen 重跑
- Modify: `test/protocol_pcap/cases/h323.json`（P5 按 T-H323）
- Test: `internal/core/layers/h323_migrate_test.go`（红例①-⑤）+`internal/core/schema/h323_static_port_test.go`（红例⑥）
- 零改动：`internal/protocol/h323/h323.go`（字节事实）

#### 2. 接口签名（锚词）
- presence：`protocol h323 no longer accepts a top-level h323 sub-config (move it into the h323 layer of an [ip,h323] layers chain)`
- validator：`h323: H323Config is required`（translate 后不可达=C 类保底）；legacy 复用 8 锚词原样（`h323: invalid role %q (must be caller or callee)` 等）
- static：`static four-tuple`（semantic.go 既有门，扫描面扩 h323）

#### 3. 主流程
create：ValidateStrategy→ValidateLayers（V9 10 键）→CheckProtoFlat presence→checkLayerChainStaticCopy（含 h323 端口）→400。
任务：mapToFlowSpec→parseLayerDyn（h323 端口对象→LayerDynValues.H323）→worker resolveLayerTuple（逐流解析端口落 spec）→ChainPlanner.ValidateSpec：validateSpecBase（h323 端口豁免）→translate case "h323"（10 键+端口同键二态）→validateLayer（required+legacy Validate）→Plan：isRawIPChain→raw-IP 驱动（flowMetaFor+meta 补齐→Generator.Generate→legacy Plan(ctx, 等价 spec)→整包 relay；force up 防双换；drive 只补 L2 缺省/EtherType/DSCP）→builder 按 L2/L3/L4 装配（writeL4 l4Len>0 链形无关）。

#### 4. 增量步骤（failing 先行）
红例族 6（icmpv6_migrate 同构）：①TestH323Chain_FlatPresenceRejected ②TestH323Chain_LayerFieldsAccepted（10 键 V9 放行）③TestH323Chain_LayerTranslateCallCycle（链 [ip{v4},h323{ports}] → 15 包（full=3+9+3/呼叫，已实证）+flags 0x02/0x12/0x10+首 Q.931 payload[0]=0x03(TPKT)/[7]=0x05(SETUP)）④TestH323Chain_DstPortDefault1720（空层→pkt1 L4.DstPort==1720）⑤TestH323Chain_PortDynAccepted（h323.src_port 对象→ValidateLayers+CheckLayerDynShape 过=allowlist 生效）⑥TestH323Chain_StaticPortFlowsRejected（schema：h323 层静态 src_port+flows=2→"static four-tuple"）。

#### 5. 错误锚词
见 §2；parse 7 文案为扁平遗篱（链路径经 legacy Validate 8 锚词执法，零新文案）。

#### 6. 性能设计与验收
包数公式（P3 从代码精算钉死，不手算——P1 教训）：full=15/呼叫（3+9+3 实证）、tunnel_only=12/呼叫、ras_only/data_only=emitRASSignaling/emitRTPMedia 循环精算；整包 relay 流式（channel 256 既有）无全量收集无锁无新增分配热点（模板字节复用）；翻译一次（ValidateSpec 同步期）；回归口径 suite 耗时 ±10%；pcap 路=套件全绿，网卡路未跑注明。

#### 7. 顺序与回滚
红例→registry+translate→FlowMeta/isRawIPChain/豁免→门扩扫+layer_dyn→layer_gen+注册→presence→main 翻转→门登记+schemagen→绿；P5 cases。回滚=单提交粒度；h323.go 零改动=字节事实零风险。

#### 8. 验收
对应 T-H323（P3 定稿）。完成条件：6 红例先红后绿；h323.json 全量绿（RESULT+二进制同代+门 2 四项+反查）；touched 包 -race+vet 净；顶层 src_ip/dst_ip/src_port/dst_port/count/h323 字面零残留；schemagen 同步绿；门 1 表回填+抽查三条；在库 h323 行清空（P6 删前报数 tasks 95+strategies 3→备份→删→复核）。

### D-MPLS-1 MPLS 层链化：终层自驱（h323 机器整包 relay）+ 端口住层【P-PIPE #16 门1】

**状态：** 已验收（2026-09-19，P-PIPE #16 收官；自审 2 轮净）。**P4**（7e2ebb5）：6 红例先红后绿（红例②连带抓出 CategoryL2 outermost 校验冲突随占位行替换消解；红例④原断言写错当轮修正为翻译结果逐键断言）；registry 占位行替换终层行 8 键+schemagen 98 层；touched 包 -race 净。**P5**：mpls.json 14 例（改写 1+新建 13）真实流程全量绿 ×4 连跑（首跑即全绿），落盘 /tmp/mcp-pcaps/mpls/；门2 四项绿（反查 22/22——首验 20/22 抓出反查关键词失配+inner_payload 缺格，补 T-1 显式 payload 格 data.data=70726f6265 实钉后 22/22）；回归 h323/icmpv6/srv6/sv 全绿。**P6**：在库清空 tasks 142+strategies 13→0/0（**绝对路径+总量对账 241393-142=241251 精确吻合**——h323 事故后纪律执行；备份 /tmp/trafficgen-backup-mpls-p6-20260919-181657.db）。

**门3 抽查三条（门1 表抽 §1/§5/§12 行）：**
1. §1 层链唯一真相 → registry.go mpls 终层行（CategoryTerminal+DependsOn ip+Fields 8 键无 Default，占位行注记更新为 A1 裁定）+ 用例 mpls_single_label_ipv4 层形 `[{"ip":{src,dst}},{"mpls":{src_port,dst_port,labels}}]`，存量 fields/frames 断言保留（frames `00 06 41 40` suite PASS 实证）✓
2. §5 有错必处理（锚词族）→ layer_gen.go validateLayer（required 保底+legacy Validate 复用）+ 用例 mpls_neg_label error_contains `exceeds 20 bits`（planner.go:66 零新文案，suite PASS 实证）✓
3. §12 动态清单（业务 5 键全关+端口 2 键开）→ layer_dyn.go allowlist "mpls" 行（红例⑤实证）+ 用例 mpls_port_dyn src_port inc 对象逐流异（2 包源口 30000/30001 pcap 实钉）✓

（原 P2 定稿记录：门 1 已交+对抗自重审 2 轮（1 处行号修正+1 处语义注记补充+2 项框架排查落定，末轮净）；CORE_MEMORY 240 条逐条复审完成。裁定延续：端口住 mpls 层+端口动态 E1=h323 已批同款（用户"开工/继续处理"连续 mandate）。现状：legacy 完整（planner.go:104-223，Eth+标签栈+内层 IP/TCP/UDP 单帧发射，frames 缺省 1 逐帧 IP ID 递增，direction up/down 自交换，Validate **10 锚词** planner.go:40-95），main.go:556 直挂，**层链四件全缺**+registry 占位行 CategoryL2 带警告注记（registry.go:1196-1202，本设计裁定替换）。用例 1 例纯扁平（{"count":1,"mpls":{"labels":[{"label":100}]}}，地址/端口全靠扁平缺省）。在库 tasks 93+strategies 5（普查表 92 漂移注记））

**架构裁定（P2 定稿）：** **A1 [ip,mpls] 终层自驱整包 relay**（h323 已验证机器：wrap legacy Plan+force-up 防双换——legacy direction=down 自行交换地址+MAC，raw-IP 驱动 down-swap 会双换）。否决记录：①A2 中链 shim [eth,mpls,ip,tcp]（registry 占位注记设想）需框架级新机制（数组=线序+transport 终结面未定义），占位注记自评"属 P2 工作项"——本裁定以 A1 替代并在新行注记中更新；②B2 [ip,tcp,mpls] 端口住 tcp 层——**中链 tcp 静态端口无进 spec 通道**（extractLayer* 仅 ip 地址/eth MAC/ip TTL 三函数，strategy_convert.go:250-330），且"动态通静态不通"形状不一致——不可行。**链路径语义注记（重审补充）：inner_proto=0（auto）在链路径恒解析为 UDP**——spec.TCP 唯一来源是扁平顶层 tcp 子映射（strategy_convert.go:446），链配置下恒 nil，内层 TCP 恒裸头（无 seq/ack/flags，planner.go:112/:189-192 不可达）=legacy 合同链上面。

**权威链（§7）：** 标准=RFC 3031（架构 §3.12 in-place）+RFC 3032（标签编码 §2.1/§3.1、EtherType §3.10 按 builder.go:85 引用、内层双族 §3.9）+RFC 5462（TC）→ 设计=本条目（权威）→ 代码 → 测试。字节事实=探针 pcap 转录（存量用例 notes 引 /tmp/probe-iana/mpls.pcap）+Wireshark packet-mpls。

**依赖链判定：**

| # | 断链层 | 判定 | 处置 |
|---|---|---|---|
| ① 层链四件缺 | 代码缺口 | registry 占位行（CategoryL2 无字段）/translate 无 case/FlowMeta 无 MPLS（grep rc=1）/无 generator | P4：占位行替换 CategoryTerminal 终层行（DependsOn ip+Fields 8 键无 Default）+translate case+FlowMeta.MPLS+carry+layer_gen 包装+注册 |
| ② legacy 校验已全 | 无缺口 | Validate 10 锚词覆盖 nil/IP×2/空栈/label/TC/S/InnerProto/Frames/Direction | validateLayer=required 保底+legacy 复用零新文案 |
| ③ 静态复制门漏扫 | 执法洞 | 扫描列表无 mpls（semantic.go:187），mpls 层静态端口+flows>1 漏拒 | P4 扫描列表 += "mpls"（h323 同款）+红例⑥ |
| ④ inner TCP 裸头 | C 类 | spec.TCP 链不可达（上注） | 明确注记：链上内层 TCP 无握手/序号语义（legacy 单帧数据面合同） |
| ⑤ 端口动态 | E1 延续 | allowlist 无 mpls 行 | P4：LayerDynValues.MPLS+allowlist mpls 端口 2 键+parseLayerDyn case+resolveLayerTuple 块+HasAny |
| ⑥ 保留标签 0-15 未校验 | legacy 合同 | Validate 只查 >0xFFFFF（types.go:3280 文档与实现的边界差） | 诚实注记不冒充：用例避开保留值（P3），不新增文案 |

#### 门 1 对照表（已交，证据回填版）

§1 键去向：src_ip/dst_ip→layers[ip].src/dst（内层=流地址 RFC 3031 §3.12）；src_port/dst_port→layers[mpls]；count→删；顶层 mpls 6 业务键→layers[mpls] 直迁（labels 数组子键 label/tc/s/ttl 原样）。目标形状 `{"layers":[{"ip":{"src":"10.0.0.1","dst":"20.0.0.1"}},{"mpls":{"src_port":12345,"dst_port":80,"labels":[{"label":100}]}}]}`。§3 五件套：数据面豁免（无控制面/无事务/无跨流——planner.go:8-10），插入=mpls 终层自产完整包，时间线=frames 顺序帧 IP ID 逐帧+1（planner.go:160-164）。§12 动态：业务 5 键全关（labels=路径身份/multicast=EtherType 选择器/inner_proto=内层选择器/direction=方向选择器/inner_payload=载荷）；端口 2 键开（E1 延续）；序号=IP ID 逐帧+1+worker 12345+i。

#### 决策对比（4.17）

| 决策 | 候选 | 结论 |
|------|------|------|
| A 链形 | A1 [ip,mpls] 终层自驱 vs A2 中链 shim vs B2 [ip,tcp,mpls] 端口住 tcp | **A1**（A2 框架级大改否决；B2 静态端口无通道不可行） |
| B 端口住处 | B1 mpls 层键+门扩扫 | **B1**（h323 已批同款） |
| C 翻译 | C1 手工逐键零缺省映射（parse 零缺省，缺省全在 Plan——比 h323 更简） | **C1** |
| D 校验 | D1 复用 legacy Validate 10 锚词 | **D1** |
| E 端口动态 | E1 开 2 键（h323 已批延续） | **E1** |

**明确不解决：** LDP/RSVP 控制面（协议本质 out of scope）；内层 TCP 会话语义（④ C 类）；保留标签 0-15 校验（⑥ legacy 合同）；中链 shim 表达（A2 否决，若未来需要另立项）。

#### 1. 文件清单（P2 定稿）
- Modify: `internal/core/layers/registry.go`——占位行替换（CategoryL2→CategoryTerminal，DependsOn ["ip"]，Fields 8 键无 Default：labels{list}/multicast{bool}/inner_proto{uint8}/src_port{uint16}/dst_port{uint16}/frames{uint16}/direction{string}/inner_payload{string}；注记更新：A1 终层裁定替代 shim 设想）
- Modify: `internal/core/layers/chain_planner_translate.go`——case "mpls"（spec.MPLS==nil 层优先；6 业务键逐映射+端口同键二态（标量→spec/对象→放行）；parse 零缺省→translate 零缺省，缺省全在 legacy Plan 内填——比 h323 更简）
- Modify: `internal/core/layers/generator.go`+`chain_planner_chain.go`——FlowMeta.MPLS+carry
- Modify: `internal/core/layers/chain_planner_util.go`——isRawIPChain 加 mpls
- Modify: `internal/core/layers/chain_planner.go`——两端口豁免名单加 mpls
- Modify: `internal/core/strategy_convert.go`——CheckProtoFlat mpls presence 分支
- Modify: `internal/core/schema/semantic.go:187`——扫描列表 += "mpls"
- Modify: `internal/core/layer_dyn.go`+`internal/core/types.go`——LayerDynValues.MPLS/allowlist/parseLayerDyn case/resolveLayerTuple/HasAny（⑤）
- Create: `internal/protocol/mpls/layer_gen.go`——Generator 包装 legacy Plan（等价 FlowSpec：SrcIP/DstIP/TTL/MAC/端口/MPLS 直传；force Direction="up" 防双换——legacy down 自交换；GenEvents 返 nil）+validateLayer（required+legacy 10 锚词复用）+init 注册
- Modify: `cmd/server/main.go:556`——NewChainPlanner("mpls")+空导入
- Modify: `tools/pipe_gate.sh`+`tools/coverage_gate.py`（check_mpls）、schemagen 重跑
- Modify: `test/protocol_pcap/cases/mpls.json`（P5 按 T-MPLS）
- Test: `internal/core/layers/mpls_migrate_test.go`（红例①-⑤）+`internal/core/schema/mpls_static_port_test.go`（红例⑥）
- 零改动：`internal/protocol/mpls/planner.go`（字节事实）

#### 2. 接口签名（锚词）
- presence：`protocol mpls no longer accepts a top-level mpls sub-config (move it into the mpls layer of an [ip,mpls] layers chain)`
- validator：`mpls: MPLS config is required`（translate 后不可达=C 类保底）；legacy 10 锚词原样复用
- static：`static four-tuple`（既有门，扫描面扩 mpls）

#### 3. 主流程
create：ValidateStrategy→ValidateLayers（V9 8 键）→CheckProtoFlat presence→checkLayerChainStaticCopy（含 mpls 端口）→400。
任务：mapToFlowSpec→parseLayerDyn（mpls 端口对象）→worker resolveLayerTuple→ChainPlanner.ValidateSpec：validateSpecBase（mpls 端口豁免）→translate case "mpls"→validateLayer（required+legacy Validate）→Plan：isRawIPChain→raw-IP 驱动（meta 补齐+Generator.Generate→legacy Plan 整包 relay→force up 防双换）→builder：writeL2 强制 0x8847/0x8848+栈写入+offset 14（VLAN 18）→内层 L3/L4 正常装配。

#### 4. 增量步骤（failing 先行）
红例族 6（h323_migrate 同构）：①TestMPLSChain_FlatPresenceRejected ②TestMPLSChain_LayerFieldsAccepted（8 键 V9）③TestMPLSChain_LayerTranslateLabelFrame（链 [ip,mpls{src_port,dst_port,labels:[{label:100}]}]→1 帧（frames 缺省）+frames 字节 pin `00 06 41 40` 等价+udp.dstport 80）④TestMPLSChain_PlanDefaults（空 mpls 层→1 帧+dir up+auto=UDP（链上 spec.TCP 恒 nil 注记实证）+栈 TTL 0→64）⑤TestMPLSLayerPortDynAllowlisted（core：allowlist 2 键）⑥TestMPLSStaticPortFlowsRejected（schema：mpls 层静态端口+flows=2→"static four-tuple"；形状=[ip{},mpls{ports}]，ip 层空对门无贡献的最小证明形）。

#### 5. 错误锚词
见 §2；legacy 10 锚词为链路径唯一执法面（零新文案）。

#### 6. 性能设计与验收
帧数=frames（缺省 1，模板面）；整包 relay 流式（channel 256 既有）无收集无锁；翻译一次；标签栈字节复用（mplsCfg.Labels 复用 planner.go:133-139）；回归口径 suite ±10%；pcap 路=套件，网卡未跑注明。

#### 7. 顺序与回滚
红例→registry 替换+translate→FlowMeta/isRawIPChain/豁免→门扩扫+layer_dyn→layer_gen+注册→presence→main 翻转→门登记+schemagen→绿；P5 cases。回滚=单提交粒度；planner.go 零改动=字节事实零风险。

#### 8. 验收
对应 T-MPLS（P3 定稿）。完成条件：6 红例先红后绿；mpls.json 全量绿（RESULT+二进制同代+门 2 四项+反查）；touched 包 -race+vet 净；顶层 count/mpls 字面零残留；schemagen 同步绿；门 1 表回填+抽查三条；在库 mpls 行清空（P6 删前报数 93+5→备份→删→复核——**绝对路径+删后总量对账**）。

### D-NGAP-1 NGAP 层链化：终层自驱（SCTP 信令整包 relay）+ 端口住层【P-PIPE #17 门1】

**状态：** 已验收（2026-09-19 P6；P4 6红转绿 97813b9、P5 17/17+门2四项+反查36/36+回归六协议绿 45016f3、清库 128+16→0/0 总量对账精确 241266/707；门3 抽查三条：①13 fields chunk 序列断言=pcap 落盘 tshark 实证（ngap.json T-1 expect，suite RESULT 17/17）②translate 嵌套三件下钻=ngap_migrate_test.go TestNGAPChain_PresenceFilled 行 155-163（MCC460/GNBID4097/TAC100/PDUID7 逐槽）③v6 拒锚词=layer_gen.go validateLayer 复用 ngap.go:149-156（cases T-13 error_contains 命中，suite 绿）。原 P2 定稿注记：2026-09-19；门 1 已交+对抗自重审 3 轮（拆链随机条件疑点排除——`if shutdownTSN > 0` 只防 TSN 下溢三 emit 恒发；`ngap.procedureCode` 字段初查误判当场自纠；主体零事实错误，末轮净）；CORE_MEMORY 240 条逐条复审完成。裁定延续：端口住 ngap 层+端口动态 E1=h323/mpls 已批同款。现状：legacy 完整（ngap.go 895 行，SCTP 4 路握手+NGSetup 对恒发+5 可选流程+3 路拆链=**最小 9 包**，全 SCTP 包自产 L3 proto 132/验证标签存 Ack 槽），main.go:567 直挂，**层链四件全缺+registry 无行**（连占位都无）。用例 1 例纯扁平（min_packets 9+13 fields chunk 序列+frames 2 字节 pin——**断言全部避开随机面**（verTag/TSN/cookie 随机，ngap.go:259-279））。在库 tasks 92+strategies 3（普查 91 漂移））

**架构裁定（P2 定稿）：** **A1 [ip,ngap] 终层自驱整包 relay**（h323/mpls 三度验证机器：wrap legacy Plan+force-up 防双换——legacy 逐 emit 自管方向与地址，raw-IP 驱动 down-swap 会双换）。否决：A2 [ip,sctp,ngap] 事件面——registry 无 sctp 层（grep 计数 0，sctp 协议序号 28 待办），需先建 SCTP 传输层机器=两级新机制。**v4-only 语义注记（重审落定）**：legacy 强制 IPv4（ngap.go:146-156）与扁平缺省同族 → **validateLayer 无需 D-FTP-4 豁免**（h323 是 v6-only 异族才需要）；动态 ip 层给 v6 range 在逐流 Plan 时被拒=正确执法（P3 负例格）。**随机性注记**：verTag/TSN/cookie/ip.id 基址随机（ngap.go:259-279）——断言仅 chunk 类型/端口/PPID/procedureCode 面（存量用例已如此=先例），ip.id 不断言。

**权威链（§7）：** 标准=3GPP TS 38.413（NGAP，流程码 §9.2/criticality §9.1）+TS 38.412（SID）+RFC 4960（SCTP §5 握手/§9.2 拆链）→ 设计=本条目（权威）→ 代码 → 测试。字节事实=参考 pcap SCTP_NAS.pcap 转录（ngap.go:40-41，InitialUEMessage+Registration Request MCC460/MNC01）+Wireshark packet-ngap（tshark 3.6.14 有 ngap.procedureCode 字段，存量 pin 有效）。

**依赖链判定：**

| # | 断链层 | 判定 | 处置 |
|---|---|---|---|
| ① 层链四件缺 | 代码缺口 | registry 无行/translate 无 case/FlowMeta 无 NGAP/无 generator | P4：registry 新终层行（14 键：12 业务+2 端口，嵌套 object/list）+translate+FlowMeta.NGAP+carry+layer_gen 包装+注册 |
| ② legacy 校验已全 | 无缺口 | Validate 16 锚词（IP×4/端口×2/MCC·MNC×4/PDUSessionID/SST/DRX/NAS 长度×3） | validateLayer=required 保底+legacy 复用零新文案 |
| ③ 静态复制门漏扫 | 执法洞 | 扫描列表无 ngap | P4 扫描列表 += "ngap"（h323/mpls 同款）+红例⑥ |
| ④ 简化 PER | C 类 | ngap.go:35-38 自认非全合规（无约束长度决定项） | 明确注记：legacy 合同字节面，对照 Wireshark 解码深度=待确认不冒充 |
| ⑤ 端口动态 | E1 延续 | allowlist 无 ngap 行 | P4：LayerDynValues.NGAP+allowlist 2 键+parseLayerDyn case+resolveLayerTuple+HasAny |
| ⑥ v6 对照 | 负例格 | legacy 强制 v4 | v6=负例（非 h323/mpls 的正例对照）——P3 落格 |

#### 门 1 对照表（已交，证据回填版）

§1 键去向：src_ip/dst_ip→layers[ip]；src_port/dst_port→layers[ngap]；count→删；顶层 ngap 12 业务键→layers[ngap] 直迁（嵌套三件原样）。目标形状 `{"layers":[{"ip":{"src":"10.0.0.1","dst":"20.0.0.1"}},{"ngap":{"src_port":12345,"dst_port":38412,"initial_ue_message":true}}]}`。§3 五件套：联结=一条 gNB↔AMF SCTP 联结；事务序列=握手 4→NGSetup 对（恒发）→5 可选流程→拆链 3；无跨流关联（NAS 流内）=豁免注记；插入=ngap 终层自产完整 SCTP 包；时间线=emit 线性。§12 动态：业务 12 键全关（结构选择器/联结身份/载荷）；端口 2 键开（E1）；序号=ip.id 随机基址+1+worker 端口保底。

#### 决策对比（4.17）

| 决策 | 候选 | 结论 |
|------|------|------|
| A 链形 | A1 终层自驱 vs A2 [ip,sctp,ngap] 事件面 | **A1**（A2 需两级新机制） |
| B 端口住处 | B1 ngap 层键+门扩扫 | **B1** |
| C 翻译 | C1 手工逐键零缺省+嵌套下钻 | **C1** |
| D 校验 | D1 复用 16 锚词（无 D-FTP-4 豁免——v4-only 同族） | **D1** |
| E 端口动态 | E1 延续 | **E1** |

**明确不解决：** SCTP IPv6 路径（legacy 拒）；全合规 PER（④ C 类）；NGAP 6 流程之外的流程扩展（legacy 范围）；sctp 传输层机器（A2 否决，sctp 协议序号 28 另立项）。

#### 1. 文件清单（P2 定稿）
- Modify: `internal/core/layers/registry.go`——ngap 终层行（CategoryTerminal+DependsOn ip+Fields 14 键无 Default：global_ran_node_id{object}/supported_ta_list{list}/pdu_session_setup{object}/amf_name{string}/default_paging_drx{uint8}/ran_ue_ngap_id{uint32}/amf_ue_ngap_id{uint32}/initial_ue_message{bool}/ue_context_release{bool}/initial_nas{string}/downlink_nas{string}/uplink_nas{string}/src_port{uint16}/dst_port{uint16}）
- Modify: `internal/core/layers/chain_planner_translate.go`——case "ngap"（spec.NGAP==nil 层优先；12 业务键逐映射+嵌套三件下钻+NAS 三键 string→bytes+端口同键二态；parse 零缺省→translate 零缺省，缺省在 legacy Plan）
- Modify: `internal/core/layers/generator.go`+`chain_planner_chain.go`——FlowMeta.NGAP+carry
- Modify: `internal/core/layers/chain_planner_util.go`——isRawIPChain 加 ngap
- Modify: `internal/core/layers/chain_planner.go`——两端口豁免名单加 ngap
- Modify: `internal/core/strategy_convert.go`——CheckProtoFlat ngap presence 分支
- Modify: `internal/core/schema/semantic.go`——扫描列表 += "ngap"
- Modify: `internal/core/layer_dyn.go`+`internal/core/types.go`——LayerDynValues.NGAP/allowlist/parseLayerDyn/resolveLayerTuple/HasAny（⑤）
- Create: `internal/protocol/ngap/layer_gen.go`——Generator 包装 legacy Plan（等价 FlowSpec 直传；force Direction="up" 防双换；GenEvents nil）+validateLayer（required+legacy 16 锚词）+init 注册
- Modify: `cmd/server/main.go:567`——NewChainPlanner("ngap")+空导入
- Modify: `tools/pipe_gate.sh`+`tools/coverage_gate.py`（check_ngap）、schemagen 重跑
- Modify: `test/protocol_pcap/cases/ngap.json`（P5 按 T-NGAP）
- Test: `internal/core/layers/ngap_migrate_test.go`（红例①-⑤）+`internal/core/schema/ngap_static_port_test.go`（红例⑥）
- 零改动：`internal/protocol/ngap/ngap.go`（字节事实）

#### 2. 接口签名（锚词）
- presence：`protocol ngap no longer accepts a top-level ngap sub-config (move it into the ngap layer of an [ip,ngap] layers chain)`
- validator：`ngap: NGAP config is required`？——**legacy Validate 对 nil-config 返 nil（ngap.go:166-168 "minimal: SCTP handshake only"）！** translate 恒填非 nil（空层→零值 NGAPConfig=合法 9 包最小联结）——**无需 required 保底分支**（h323/mpls 不同：legacy 自身接受 nil）。validateLayer=纯 legacy 复用。
- static：`static four-tuple`（既有门，扫描面扩 ngap）

#### 3. 主流程
create：ValidateStrategy→ValidateLayers（V9 14 键）→CheckProtoFlat presence→checkLayerChainStaticCopy（含 ngap 端口）→400。
任务：mapToFlowSpec→parseLayerDyn→worker resolveLayerTuple→ChainPlanner.ValidateSpec：validateSpecBase（ngap 端口豁免）→translate case "ngap"→validateLayer（legacy Validate——v4-only 与缺省同族无冲突）→Plan：isRawIPChain→raw-IP 驱动（meta 补齐→Generator.Generate→legacy Plan 整包 relay→force up 防双换）→builder：SCTP L4 装配（CRC32c 既有 builder.go:427 路径）。

#### 4. 增量步骤（failing 先行）
红例族 6（P3 联动修正：全开 16 包）：①TestNGAPChain_FlatPresenceRejected ②TestNGAPChain_LayerFieldsAccepted（14 键 V9）③TestNGAPChain_LayerTranslateMinimalSession（链 [ip,ngap{ports}]→9 包+SCTP chunk 序列 1/2/10/11/DATA×2/7/8/14+dstport 38412）④TestNGAPChain_TranslateKeysFilled（业务键逐槽断言含嵌套 pdu_session_setup）⑤TestNGAPLayerPortDynAllowlisted（core）⑥TestNGAPStaticPortFlowsRejected（schema：[ip{},ngap{ports}]+flows=2）。

#### 5. 错误锚词
见 §2；legacy 16 锚词为链路径唯一执法面（零新文案）。

#### 6. 性能设计与验收
包数=9+N 可选（InitialUE/DL NAS/UL NAS 各 1、PDUSession 对 2、UEContextRelease 对 2（Command+Complete，ngap.go:387-398 实证——P3 修正：原误记 +1））；整包 relay 流式（channel 256）无收集无锁；翻译一次；回归口径 suite ±10%；pcap 路=套件；网卡未跑注明。

#### 7. 顺序与回滚
红例→registry+translate→FlowMeta/isRawIPChain/豁免→门扩扫+layer_dyn→layer_gen+注册→presence→main 翻转→门登记+schemagen→绿；P5 cases。回滚=单提交粒度；ngap.go 零改动=字节事实零风险。

#### 8. 验收
对应 T-NGAP（P3 定稿）。完成条件：6 红例先红后绿；ngap.json 全量绿（RESULT+二进制同代+门 2 四项+反查）；touched 包 -race+vet 净；顶层 count/ngap 字面零残留；schemagen 同步绿；门 1 表回填+抽查三条；在库 ngap 行清空（P6 删前报数 92+3→备份→删→复核——绝对路径+总量对账）。

### D-TELNET-1 telnet 层链化：终层自驱（TCP 信令整包 relay）+ 端口住层【P-PIPE #18 门1】

**状态：** 已验收（2026-09-19 P6；P4 6红转绿 f924972+file_source 契约修正 76c42cd、P5 17/17+门2四项+反查 32/32+回归四协议绿 d58bef9、清库 176+19→0/0 总量对账精确 241209/716（P1 普查 92+3 已漂移以实测为准）；门3 抽查三条：①13 包 flags 序+方向面 dst 交替断言=telnet_migrate_test.go TestTelnetChain_LayerTranslateMinimalDialog（wantFlags/wantDst 逐包序实钉，emit 调用序 telnet.go:283-339 回指）②file_source 零值→nil 契约=translate 镜像块（chain_planner_translate.go，parseFileSource strategy_convert.go:1545-1548 契约回指；P4 自审抓分叉修正实证）③v6 正例格=cases T-14（帧 offset 74=IPv6 头 40B P5 校准实测，IP 透明 telnet.go:30-31+builder.go:125 回指）。原 P2 定稿注记：2026-09-19；门 1 已交+对抗自重审 2 轮（存量断言计数 13→8 fields+4 标量自纠、包数校准值 3 处修正、notes"Will Echo"注释瑕疵发现；主体零事实错误，末轮净）；CORE_MEMORY 逐条复审完成。裁定延续：端口住 telnet 层+端口动态 E1=h323/mpls/ngap 四度已批。现状：legacy 完整（telnet.go 563+scenario.go 329 行，TCP 全托管自产——3 握手(MSS/WinScale/SACK 选项 synOptions:553)+可选 banner(:291)+FileSource(:297)+19 事件类型 dialog 循环(:307,IAC 转义 RFC 854 §3)+4 挥手；6 场景（scenario.go:54 login_full/login_fail/multi_command/long_output/option_reject/synch），包数公式=3+N 事件段+4（基线 defaultDialog 6 事件=13 包；场景校准值 login_full/multi_command 33、option_reject 28、login_fail 27、long_output 36、synch 38——P3/首跑校准），ISN 随机（serverSeq 恒随机:222，clientSeq 链路径不可控），ipID 随机基址——断言避开随机面。main.go:178 具名导入+:545 直挂，**层链四件全缺+registry 无行**。用例 1 例纯扁平（**8 fields+6 frames+4 标量断言**（has_handshake/negotiated/terminates/min_packets:12——12=保守下界实际 13,P5 校准）+tshark 伪影注记：telnet.data 对 IAC 帧空串/trim 尾空白/\r\n 字面转义；存量 notes"Will Echo"注释与字节不符（ff fb 03=WILL SGA）——P3 注记不迁移错误注释）。在库 tasks 92+strategies 3）

**架构裁定（P2 定稿）：** **A1 [ip,telnet] 终层自驱整包 relay**（h323/mpls/ngap 四度验证机器：wrap legacy Plan+force-up 防双换——legacy 逐 emit 自管方向与地址 telnet.go:227-271，raw-IP 驱动 down 包 L3 换向会双换）。否决：B2 [ip,tcp,telnet] 事件面——19 事件类型+IAC 转义+MSS 分段+TCP 选项须全量重写为 MessageEvent 流破坏字节等价，且 tcp 层无静态端口抽取通道（extractLayerSrcDst 仅 ip，mpls B2 已证死路）。**IP 版本透明注记（重审落定）**：Validate 无族强制（telnet.go:30-31+124-157 实证）+EtherTypeFor(builder.go:125) v6→0x86DD 框架既有 → **validateLayer 无需 D-FTP-4 豁免；v6=正例对照格**（9.24 地址族对称 v4/v6 双族逐格——与 ngap 负例格语义相反）。**随机性注记**：serverSeq 恒随机/clientSeq 链路径不可控/ipID 随机——断言仅 flags/端口/事件字节面（相对 seq 关系 harness 不可断=9.27 注记）；ip.id 不断言。**MSS 注记**：链路径 spec.TCP 恒 nil→MSS 恒 1460（1.12"不被消费"C 类；spec.TCP.InitialSeq 同不可达）；synch DM 无 URG（L4Config 无 UrgentPointer 字段，telnet.go:478-481 自认）同 C 类。

**权威链（§7）：** 标准=RFC 854（NVT+IAC §3）+RFC 855（选项协商/SB）+RFC 1091（TTYPE）+RFC 1073（NAWS）+RFC 1184/1572（选项码出处）→ 设计=本条目（权威）→ 代码 → 测试。字节事实=参考存量 pcap 13 帧实证（tshark telnet 解码器逐字节 frames hex）。

**依赖链判定：**

| # | 断链层 | 判定 | 处置 |
|---|---|---|---|
| ① 层链四件缺 | 代码缺口 | registry 无行/translate 无 case/FlowMeta 无 TELNET/无 generator | P4：registry 新终层行（14 键：10 业务+2 端口+dialog{list}+file_source{object}）+translate+FlowMeta.Telnet+carry（字段名随 spec 同名，NFS/CoAP 正常词先例）+layer_gen 包装+注册 |
| ② legacy 校验已全 | 无缺口 | Validate 5 锚词（IP parse×2/MSS×2 链不可达/scenario 白名单） | validateLayer=legacy 复用零新文案（nil-config 合法=空 telnet 层走 defaultDialog 13 包最小联结） |
| ③ 静态复制门漏扫 | 执法洞 | 扫描列表无 telnet | P4 扫描列表 += "telnet"+红例⑥ |
| ④ 协商状态机 | C 类 | RFC 1143 Q method 不做（telnet.go:18-21 合同：逐字发射非真协商） | 明确注记不冒充 |
| ⑤ 端口动态 | E1 延续 | allowlist 无 telnet 行 | P4：LayerDynValues.TELNET+allowlist 2 键+parseLayerDyn case+resolveLayerTuple+HasAny |
| ⑥ v6 对照 | 正例格 | IP 透明 | v4/v6 双族逐格（9.24）——P3 落格 |

#### 门 1 对照表（已交，证据回填版）

§1 键去向：src_ip/dst_ip→layers[ip]；src_port/dst_port→layers[telnet]；count→删；顶层 telnet 10 业务键→layers[telnet] 直迁（banner/dialog/terminal_type/window_cols/window_rows/file_source/scenario/username/password/commands）。目标形状 `{"layers":[{"ip":{"src":"10.0.0.1","dst":"20.0.0.1"}},{"telnet":{"src_port":12345,"dst_port":23,"scenario":"login_full","username":"alice"}}],"strategy_fc":{"type":"flows","value":1}}`。§3 五件套：会话表=豁免（单 TCP 连接 RFC 854）；事务序列=3 握手→[banner]→[FileSource]→dialog 事件序→4 挥手；关联=豁免（无子流）；插入=telnet 终层自产完整 TCP 包；时间线=emit 线性。§12 动态：业务 10 键全关（逐键理由见 P1 §12 表）；端口 2 键开（E1）；序号=layer_dyn resolveLayerTuple telnet 块（P4 新增）。

#### 决策对比（4.17）

| 决策 | 候选 | 结论 |
|------|------|------|
| A 链形 | A1 终层自驱 vs B2 [ip,tcp,telnet] 事件面 | **A1**（B2 全量重写破坏字节等价+无端口抽取通道） |
| B 端口住处 | B1 telnet 层键+门扩扫 | **B1** |
| C 翻译 | C1 手工逐键零缺省+dialog 直迁+file_source object 直传 | **C1** |
| D 校验 | D1 复用 5 锚词（无 D-FTP-4 豁免——v6 透明）；v6 正例 | **D1** |
| E 端口动态 | E1 延续 | **E1** |

**明确不解决：** RFC 1143 协商状态机（④ C 类）；MSS 链路径配置（1.12）；synch DM URG 位（L4Config 无字段）；telnet over TLS（tls 序号 2 另立项）。

#### 1. 文件清单（P2 定稿）
- Modify: `internal/core/layers/registry.go`——telnet 终层行（CategoryTerminal+DependsOn ip+Fields 14 键无 Default：banner{string}/dialog{list}/terminal_type{string}/window_cols{uint16}/window_rows{uint16}/file_source{object}/scenario{string}/username{string}/password{string}/commands{list}/src_port{uint16}/dst_port{uint16}）
- Modify: `internal/core/layers/chain_planner_translate.go`——case "telnet"（spec.TELNET==nil 层优先；10 业务键逐映射零缺省镜像 parse:1085+dialog/file_source 直迁+端口同键二态；dst_port 缺席→23 镜像 setDefaultDstPort）
- Modify: `internal/core/layers/generator.go`+`chain_planner_chain.go`——FlowMeta.Telnet+carry（字段名随 spec 同名，NFS/CoAP 正常词先例）
- Modify: `internal/core/layers/chain_planner_util.go`——isRawIPChain 加 telnet
- Modify: `internal/core/layers/chain_planner.go`——两端口豁免名单加 telnet
- Modify: `internal/core/strategy_convert.go`——CheckProtoFlat telnet presence 分支
- Modify: `internal/core/schema/semantic.go`——扫描列表 += "telnet"
- Modify: `internal/core/layer_dyn.go`+`internal/core/types.go`——LayerDynValues.TELNET/allowlist/parseLayerDyn/resolveLayerTuple/HasAny（⑤）
- Create: `internal/protocol/telnet/layer_gen.go`——Generator 包装 legacy Plan（force Direction="up" 防双换；GenEvents nil）+validateLayer（纯 legacy 5 锚词）+init 注册
- Modify: `cmd/server/main.go:178,545`——具名导入→空导入+NewChainPlanner("telnet")
- Modify: `tools/pipe_gate.sh`+`tools/coverage_gate.py`（check_telnet）、schemagen 重跑
- Modify: `test/protocol_pcap/cases/telnet.json`（P5 按 T-TELNET）
- Test: `internal/core/layers/telnet_migrate_test.go`（红例①-④）+`internal/core/telnet_layer_dyn_test.go`（红例⑤）+`internal/core/schema/telnet_static_port_test.go`（红例⑥）
- 零改动：`internal/protocol/telnet/telnet.go`/`scenario.go`（字节事实）

#### 2. 接口签名（锚词）
- presence：`protocol telnet no longer accepts a top-level telnet sub-config (move it into the telnet layer of an [ip,telnet] layers chain)`
- validator：legacy 5 锚词（`not a valid IP address`×2/`too small (min`/`too large (max`/`unknown scenario`）——nil-config 合法走 defaultDialog
- static：`static four-tuple`（既有门，扫描面扩 telnet）

#### 3. 主流程
create：ValidateStrategy→ValidateLayers（V9 14 键）→CheckProtoFlat presence→checkLayerChainStaticCopy（含 telnet 端口）→400。
任务：mapToFlowSpec→parseLayerDyn→worker resolveLayerTuple→ChainPlanner.ValidateSpec：validateSpecBase（telnet 端口豁免）→translate case "telnet"→validateLayer（legacy——v6 透明无冲突）→Plan：isRawIPChain→raw-IP 驱动（meta 补齐→Generator.Generate→legacy Plan 整包 relay→force up 防双换）→builder：TCP L4 装配（选项 synOptions 既有路径）。

#### 4. 增量步骤（failing 先行）
红例族 6：①TestTelnetChain_FlatPresenceRejected ②TestTelnetChain_LayerFieldsAccepted（14 键 V9）③TestTelnetChain_LayerTranslateMinimalDialog（链 [ip,telnet{ports}]→13 包+flags 序 0x02/0x12/0x10+事件字节 pin ff fb 03/ff fd 03）④TestTelnetChain_PresenceFilled（业务键逐槽+scenario 场景 dialog 生成断言包数 33）⑤TestTelnetLayerPortDynAllowlisted（core）⑥TestTelnetStaticPortFlowsRejected（schema：[ip{},telnet{ports}]+flows=2）。

#### 5. 错误锚词
见 §2；legacy 5 锚词为链路径执法面（零新文案）；MSS 两锚词链不可达=C 类注记。

#### 6. 性能设计与验收
包数=13 基线/33 场景缺省/36-38 长输出+synch（MSS 分段 6/5 段）；整包 relay 流式（channel 256）无收集无锁；翻译一次；回归口径 suite ±10%；pcap 路=套件；网卡未跑注明。长输出场景单流最大 8197B（scenarioLongOutputBytes:46）。

#### 7. 顺序与回滚
红例→registry+translate→FlowMeta/isRawIPChain/豁免→门扩扫+layer_dyn→layer_gen+注册→presence→main 翻转→门登记+schemagen→绿；P5 cases。回滚=单提交粒度；telnet.go/scenario.go 零改动=字节事实零风险。

#### 8. 验收
对应 T-TELNET（P3 定稿）。完成条件：6 红例先红后绿；telnet.json 全量绿（RESULT+二进制同代+门 2 四项+反查）；touched 包 -race+vet 净；顶层 count/telnet 字面零残留；schemagen 同步绿；门 1 表回填+抽查三条；在库 telnet 行清空（P6 删前报数 92+3→备份→删→复核——绝对路径+总量对账）。

### D-SIP-1 sip 层链化：终层自驱（TCP 信令+RTP 子流整包 relay）+ 端口住层【P-PIPE #19 门1 + 补充批 T-19…24 + 批二 T-25…43 + 批三 T-44…57】

**状态：** 已验收（2026-09-19 P6；P4 6红一次转绿 1ecbc23（translate round-trip 与 legacy 完全兼容，含 media.file_source 经 struct 标签等价覆盖 :1405 扁平两步合流）、P5 18/18+门2四项+反查 29/29+回归五协议绿 951c708、清库 139+24→0/0 总量对账精确 241167/726（P1 普查 91+4 漂移以实测为准）；门3 抽查三条：①12 包 flags 序+INVITE 首字节=sip_migrate_test.go TestSIPChain_LayerTranslateMinimalDialog（存量五消息等价形逐包实钉）②dialog/media round-trip 头数组保序=TestSIPChain_PresenceFilled（Headers[0]/[1] 逐串+CSeq 7 保留）③RTP 帧 offset=42 实测校准=cases T-11（byte0=0x80|RTP 头 12B+UDP8+IP20+Eth14；rtp.* 字段 tshark 3.6 无效改 frames pin 注记落档）。原 P2 定稿注记：2026-09-19；门 1 已交+对抗自重审 1 轮（presence 零命中复核/emitSIPMedia nil 风险排除——sipConfig==spec.SIP 同引用 :120-123:239；主体零事实错误，末轮净）；CORE_MEMORY 逐条复审完成。裁定延续：端口住 sip 层+端口动态 E1=五度已批。现状：legacy 完整（sip.go 1177 行，**本组首个带子流协议**——TCP 信令面全托管（3 握手 :194-201+dialog 逐消息 MSS 分段 PSH-ACK :215-242+4 挥手 :244-254）+**RTP UDP 子流**（emitSIPMedia :717：EmitMedia 标记关联点、独立四元组 rtpFlowID=parent+":rtp" :828、SDP m= 行端口推导 scanSDPMediaPorts+media.src_port/dst_port 显式覆盖、方向=SDP a= 属性推导 RFC 3264 §5.1、缺省 5004/frameSize 160/sampleRate 8000、RFC 3550 §5.1 seq/ts/ssrc 随机 :826-828、FileSource 优先 :751-754 无 cache 静默不发射）；dialogCtx 头补全状态机 :337-409（Call-ID 首现继承/生成 RFC 3261 §8.1.1.4、CSeq 推进、响应回显 lastFrom/To/Via、user 头>补全>无三态）；renderSIPMessage RFC 3261 §7 文本+Content-Length 自动 :308-314。Validate 3 锚词（IP parse×2/MSS min——无 large）。main.go:133 具名导入+:540 直挂，**层链四件全缺+registry 无行**。用例 1 例纯扁平（INVITE/200/ACK/BYE/200 五消息=12 包，tshark sip.Method/CSeq.seq/CSeq.method/Status-Code/Request-Line 五字段+frames 4 pin offset 54——每消息 1 包短消息面）。在库 tasks 91+strategies 4）。**P4 已执行（2026-09-19，提交 1501264）：** registry 9 键行/CheckProtoFlat presence/translate case radius（7 业务键+JSON round-trip+dst 缺席顺序修正覆盖）/**SrcPort 零保持名单 += radius**（validateSpecBase 先于 translate，src 缺席单流 0 上包=mcp/modbus 直传族语义，多流 worker 12345+i；本项 P4 构建期发现、推翻 P2 "不加名单"误判——链路径无 12345 保底，h323/sip 同构先例直接适用）/FlowMeta+carry/isRawIPChain/layer_dyn 五件套/layer_gen（force-up 防双换/GenEvents nil/validateLayer legacy 委托）/main 翻转/门登记+schemagen 102 层；5 红例全绿+touched 包 -race+vet 净。**P5 已执行（2026-09-19）：** cases 25/25 全绿（T-1 改写+T-2…21+A′ 补充批 T-22…25）；P5 校准 4 处见 T-RADIUS 状态行（多 AVP 逗号拼接/11→11 与 12→13 无 rsp/reqframe 改端口交换钉/port_distinct 双向聚合/strategy_fc 键名）；反查 check_radius 44/44+门 2 静态四项绿+五协议回归绿；落盘 /tmp/mcp-pcaps/radius/）。**P6 已验收（2026-09-19）：** 在库清空 tasks 165+strategies 19（删前实测重报，241334−165=241169/763−19=744 双总量对账精确），备份 /tmp/trafficgen-backup-radius-p6.db，复核 0/0+交叉引用 0；门 3 抽查三条：①§1 层链唯一真相——radius_flat_presence 经真实流程拒绝锚词 "top-level radius sub-config"（strategy_convert.go CheckProtoFlat radius 分支空 map 也死），25 例非负例顶层仅 layers+strategy_fc（presence-negative-case-shape：负例=层链+顶层空子映射并存，判死执法对象非残留）；②§12 动态清单——业务 7 键全关（layer_dyn.go 零 radius 业务行）+端口 2 键开（T-21 src/dst inc 双 group_id 实证 12001→12002/1812→1813 逐流），序号算法=resolveLayerTuple radius 块；③§14 真实流程——T-4 acct 1813 顺序修正专项经真实服务落盘实证 udp.dstport=1813（tshark 非 :770 预写路径），T-24 NAS 组合 avp.type "6,4,31,80" 逗号拼接落盘重钉。P4 构建期发现+ SrcPort 零保持名单修正（见 P4 记录）

**架构裁定（P2 定稿）：** **A1 [ip,sip] 终层自驱整包 relay**（五度验证机器：wrap legacy Plan+force-up 防双换——TCP down 包与 RTP down 帧均由 legacy 自换地址端口 MAC（:846-856 media 方向面同 h323 媒体保护），raw-IP 驱动换向会双换）。否决：B2 [ip,tcp,sip] 事件面——dialogCtx 头补全状态机（跨消息 Call-ID/CSeq 继承）+RTP 子流发射须全量重写为事件流，破坏字节等价。**关联语义注记（§3 落定）**：RTP 子流关联三件事 legacy 显式字段全齐——归属=EmitMedia 消息、触发=该消息后、端口方向=SDP m=/a= 推导+media 显式覆盖（CWMP driven_by 的 SIP 等价物）；被关联流独立 ID=parent+":rtp"（3.10 parent:sub-idx 形状天然满足）。**v6 正例格**（Validate 无族强制+EtherTypeFor）。**随机性注记**：RTP seq/ts/ssrc 随机（RFC 3550 合同）+TCP ISN 随机——断言仅 PT/帧长/端口/flags/SIP 文本面；ip.id 不断言。

**权威链（§7）：** 标准=RFC 3261（§7 文本格式/§8.1.1 强制头/§20.8 头定义/§8.1.1.4 Call-ID 生成）+RFC 3550（§5.1 RTP 头）+RFC 3264（§5.1 方向属性）→ 设计=本条目（权威）→ 代码 → 测试。字节事实=存量 pcap 12 帧实证（tshark SIP 解码器逐字节）。

**依赖链判定：**

| # | 断链层 | 判定 | 处置 |
|---|---|---|---|
| ① 层链四件缺 | 代码缺口 | registry 无行/translate 无 case/FlowMeta 无 SIP/无 generator | P4：registry 新终层行（4 键：dialog{list}/media{object}/src_port/dst_port）+translate（dialog/media JSON round-trip）+FlowMeta.SIP+carry+layer_gen 包装+注册 |
| ② legacy 校验已全 | 无缺口 | Validate 3 锚词（IP parse×2/MSS min；MSS 链不可达） | validateLayer=legacy 复用零新文案（nil-config 合法=空 dialog 7 包最小联结） |
| ③ 静态复制门漏扫 | 执法洞 | 扫描列表无 sip | P4 扫描列表 += "sip"+红例⑥ |
| ④ SDP future-bleed | C 类 | scanSDPMediaPorts 扫全 dialog（:769-773 自认），re-INVITE 后端口前渗 | 明确注记不冒充（修复需传 dialog index=大重构，明确不解决） |
| ⑤ 端口动态 | E1 延续 | allowlist 无 sip 行 | P4：LayerDynValues.SIP+allowlist 2 键+parseLayerDyn case+resolveLayerTuple+HasAny |
| ⑥ v6 对照 | 正例格 | IP 透明 | v4/v6 双族逐格（9.24）——P3 落格 |

#### 门 1 对照表（已交，证据回填版）

§1 键去向：src_ip/dst_ip→layers[ip]；src_port/dst_port→layers[sip]；count→删；顶层 sip 2 业务键（dialog/media）→layers[sip] 直迁。目标形状见门 1 提交（INVITE+200 dialog+media 示例）。§3 五件套：会话表=单 TCP 信令+可选 RTP 子流；事务序列=3 握手→dialog 消息序→[RTP 子流在 EmitMedia 消息后]→4 挥手；关联=EmitMedia+SDP m=/a=（三件事全齐）；插入=raw-IP 驱动整包 relay；时间线=emit 线性（RTP 同 worker 保序）。§12 动态：dialog/media 全关（会话结构/SDP 关联语义）；端口 2 键开（E1）；序号=layer_dyn resolveLayerTuple sip 块（P4 新增）。

#### 决策对比（4.17）

| 决策 | 候选 | 结论 |
|------|------|------|
| A 链形 | A1 终层自驱 vs B2 [ip,tcp,sip] 事件面 | **A1**（B2 破坏头补全状态机+RTP 字节等价） |
| B 端口住处 | B1 sip 层键+门扩扫 | **B1** |
| C 翻译 | C1 dialog/media JSON round-trip 直迁（SIPMessage/SIPMedia 带 json 标签） | **C1** |
| D 校验 | D1 复用 3 锚词（v6 正例；MSS 链不可达 C 注记） | **D1** |
| E 端口动态 | E1 延续 | **E1** |

**明确不解决：** SDP future-bleed（④ C 类）；RFC 3261 Timer/重传（合成器合同）；SIPS/TLS 传输（tls 序号 2 另立项）；MSS 链路径配置（1.12）。**补充批立项（2026-09-19 §3/§9 对抗复审，B 类 4 项，此前漏登记）：** sessions[] 多会话结构（同连接多 dialog 独立 Call-ID/四元组/生命周期——现 flows=2 只是同模板逐流复制，Call-ID 原样字节非独立会话，须 sessions[]+每流标识派生，另立条目）；每流标识唯一化（Call-ID/CSeq 起始/branch 逐流派生——现用户原文模板跨流同字节）；NAT 方言（rport/Received/Via 处理合成）；RTP 与 dialog 双向交错（现 EmitMedia 单挂点单向，双向靠两条 SIPMedia 各一条流表达，真交错须事件级编排另立）。

#### 1. 文件清单（P2 定稿）
- Modify: `internal/core/layers/registry.go`——sip 终层行（CategoryTerminal+DependsOn ip+Fields 4 键无 Default：dialog{list}/media{object}/src_port{uint16}/dst_port{uint16}）
- Modify: `internal/core/layers/chain_planner_translate.go`——case "sip"（spec.SIP==nil 层优先；dialog/media JSON round-trip 直迁镜像 parseSIPDialog/parseSIPMedia :5554/:5599 零缺省；端口同键二态；dst_port 缺席→5060 镜像 setDefaultDstPort）
- Modify: `internal/core/layers/generator.go`+`chain_planner_chain.go`——FlowMeta.SIP+carry
- Modify: `internal/core/layers/chain_planner_util.go`——isRawIPChain 加 sip
- Modify: `internal/core/layers/chain_planner.go`——两端口豁免名单加 sip
- Modify: `internal/core/strategy_convert.go`——CheckProtoFlat sip presence 分支
- Modify: `internal/core/schema/semantic.go`——扫描列表 += "sip"
- Modify: `internal/core/layer_dyn.go`+`internal/core/types.go`——LayerDynValues.SIP/allowlist/parseLayerDyn/resolveLayerTuple/HasAny（⑤）
- Create: `internal/protocol/sip/layer_gen.go`——Generator 包装 legacy Plan（force Direction="up" 防双换；GenEvents nil）+validateLayer（纯 legacy 3 锚词）+init 注册
- Modify: `cmd/server/main.go:133,540`——具名导入→空导入+NewChainPlanner("sip")
- Modify: `tools/pipe_gate.sh`+`tools/coverage_gate.py`（check_sip）、schemagen 重跑
- Modify: `test/protocol_pcap/cases/sip.json`（P5 按 T-SIP）
- Test: `internal/core/layers/sip_migrate_test.go`（红例①-④）+`internal/core/sip_layer_dyn_test.go`（红例⑤）+`internal/core/schema/sip_static_port_test.go`（红例⑥）
- 零改动：`internal/protocol/sip/sip.go`（字节事实）

#### 2. 接口签名（锚词）
- presence：`protocol sip no longer accepts a top-level sip sub-config (move it into the sip layer of an [ip,sip] layers chain)`
- validator：legacy 3 锚词（`invalid source IP`/`invalid destination IP`/`MSS %d too small`——后者链不可达）；nil-config 合法走空 dialog 7 包
- static：`static four-tuple`（既有门，扫描面扩 sip）

#### 3. 主流程
create：ValidateStrategy→ValidateLayers（V9 4 键）→CheckProtoFlat presence→checkLayerChainStaticCopy（含 sip 端口）→400。
任务：mapToFlowSpec→parseLayerDyn→worker resolveLayerTuple→ChainPlanner.ValidateSpec：validateSpecBase（sip 端口豁免）→translate case "sip"→validateLayer（legacy——v6 透明无冲突）→Plan：isRawIPChain→raw-IP 驱动（meta 补齐→Generator.Generate→legacy Plan 整包 relay 含 RTP 子流→force up 防双换）→builder：TCP 装配+RTP 帧直出（UDP 装配既有路径）。

#### 4. 增量步骤（failing 先行）
红例族 6：①TestSIPChain_FlatPresenceRejected ②TestSIPChain_LayerFieldsAccepted（4 键 V9）③TestSIPChain_LayerTranslateMinimalDialog（链 [ip,sip{ports}]→12 包（存量五消息等价）+flags 序+INVITE 字节 pin）④TestSIPChain_PresenceFilled（dialog/media round-trip 逐槽+SIPMessage 头数组保序）⑤TestSIPLayerPortDynAllowlisted（core）⑥TestSIPStaticPortFlowsRejected（schema：[ip{},sip{ports}]+flows=2）。

#### 5. 错误锚词
见 §2；legacy 3 锚词为链路径执法面（零新文案；MSS 锚词链不可达=C 注记零死锚）。

#### 6. 性能设计与验收
包数=3+N 消息段（MSS 分段）+frames（RTP）+4；基线 12（五消息）/空 dialog 7；整包 relay 流式（channel 256）无收集无锁；翻译一次；回归口径 suite ±10%；pcap 路=套件；网卡未跑注明。

#### 7. 顺序与回滚
红例→registry+translate→FlowMeta/isRawIPChain/豁免→门扩扫+layer_dyn→layer_gen+注册→presence→main 翻转→门登记+schemagen→绿；P5 cases。回滚=单提交粒度；sip.go 零改动=字节事实零风险。

#### 8. 验收
对应 T-SIP（P3 定稿）。完成条件：6 红例先红后绿；sip.json 全量绿（RESULT+二进制同代+门 2 四项+反查）；touched 包 -race+vet 净；顶层 count/sip 字面零残留；schemagen 同步绿；门 1 表回填+抽查三条；在库 sip 行清空（P6 删前报数 91+4→备份→删→复核——绝对路径+总量对账）。

### D-SIP-2 sip 引擎结构补全：sessions[] 多会话+媒体双向交错+NAT 合成+SIPS/TLS 事件面【D-SIP-1 B′ 四项收编，P2 定稿待批】

**状态：** **WP-A+WP-B+WP-C+WP-D 已验收（2026-09-20，D-SIP-2 全部四 WP 收官）**：WP-B P5=76/76 ×2 稳态+落盘对账 70=76−6+门 2 四项绿+反查 87/87；P5 校准 3 处（down wire 元组交换/包位偏移/udp 聚合口径）+gap0 双发 bug 单测捕获修正；T-SIP-72…76 见 TEST_CASES。WP-A：P5 71/71 ×2 稳态+落盘对账 66=71−5+门 2 四项绿+反查 82/82；校准 5 处见 T-SIP-58 状态行（genPort pattern 补口/嵌套 dyn 扫描 call_id/rand 钉值/v6 括号/list 字符串合同）。**门 3 抽查三条：** ①§1/§2——sip_neg_sessions_dialog_mutex 经真实 MCP create 拒绝，锚词 "sip: sessions and dialog are mutually exclusive"（semantic.go checkSIPSessionsMutex 空数组同锚词面）；②§12——sessions 端口五策略整格落盘实证（T-65 rand seed=7→23187/23189 可复现、T-68 pattern 260{n}→2601/2602、T-66 list→24001/24002；序号算法=genPort/deriveSIP* 派生 base+flowIdx*M+sessIdx）；③§14——T-58 双会话 tshark 实证两对独立 SYN（tcp.srcport 22001/22002）+逐会话 Call-ID req/resp 复刻，无数据库新增行（纯增量特性，P6 无清库项）。WP-C：P5 80/80 ×2 稳态+门 2 四项绿+反查 91/91（新增 4 个 NAT 反查点）；P5 校准 1 处（T-80 min_packets 9→8，落盘 pcap 实测单 session 单消息无响应=3 握手+1 消息+4 挥手）。**WP-C 门 3 抽查三条：** ①RFC 3581 §4——T-77 bare `;rport` 经真实 MCP create→落盘 pcap 包4 `rport=12001;received=10.0.0.1`（rewriteViaRPort 分号切参替换；包5 响应侧回放用户原文零二次改写，rport=9999 原样）；②§3.9 会话关联——T-80 sessions 模式回填=会话实际端口 22001 非 spec 12001（runSession 端口推导链末端取值，tshark 实证）；③§14——T-79 缺省透传包4/5 Via 原样 tshark 实证=零字节漂移线本格；无数据库新增行（纯增量特性，P6 无清库项）。WP-D：P5 86/86 ×2 稳态+门 2 四项绿+反查 97/97（6 个事件面反查点）；P5 校准 3 处（isRawIPChain 传输层守卫红线/drive meta 补 SIP 字段/T-83 same_as_packet 断言）。**WP-D 门 3 抽查三条：** ①RFC 3261 §26.2.1——T-81 落盘 pcap 实证 16 包形状（3 tcp 握手+7 TLS record tshark 解出 ClientHello/ServerHello/EncryptedExtensions/Certificate/CertificateVerify/Finished×2+2 app-data+4 挥手），生成 Via 传输令牌 TLS 由 TestSIPEventModeTLSViaTransport 单测钉（密文面 pcap 不可见=如实）；②§26.2.2——T-85 sips: URI 无 tls 层 create 400 锚词 `sip: sips uri requires a tls layer in the chain`（schema checkSIPEventPlane + event_gen.go 运行时同款双保险）；③§14——T-83 纯 tcp 事件面明文 tshark 直查 sip.Method=CSeq=Via（响应 Via same_as_packet 回显 §8.1.3.2），isRawIPChain 修复后 [ip,sip] 80 例全量复验字节零回归；无数据库新增行（纯增量特性，P6 无清库项）。**M2 纪律注记：** OptionalOn tls 与实现代码同提交（5abace3），pcap 证据随后续 P5 提交——同一 WP 原子评审单元内。**P6 存量清库补做（2026-09-20 全协议复审）：** 原 #19 P6 该项漏做，本次补齐——tasks 1106+strategies 75 （242231−1106=241125/797−75=722 双总量对账精确），备份 /tmp/trafficgen-backup-sip-p6.db，复核 0/0+交叉引用 0（他协议任务无 sip 策略引用）。原 P2/P5 记录：P5 已执行（71/71 ×2 稳态）；P2 设计（2026-09-20；CORE_MEMORY 240 条逐条重审完成——12 处缺口修正入条目：组合语义/四件事/三张子表/签名/性能口径/整格矩阵/spec 例等）。P2 设计（2026-09-20；用户指示"按核心记忆文档设计 D-SIP-1 剩余边界方案"；**CORE_MEMORY 240 条逐条重审完成——12 处缺口修正入条目**：组合语义/四件事/三张子表/签名/性能口径/整格矩阵/spec 例等）。四个独立 WP，各自 P-PIPE+独立提交；WP-D 风险最高可独立延期。现状代码事实：Media 单挂点（sip.go:239 `msg.EmitMedia && sipConfig.Media != nil`）；flows=2=同模板复制（Call-ID 同字节）；Via 原样透传（sip.go 零 rport/received 逻辑）；sip 终层自驱 GenEvents=nil（layer_gen.go:26）；框架已有 tls 事件变换器先例（chain_planner_chain.go:216 [ip→tcp→tls→http] 绿）+mqtt OptionalOn tls（registry.go:311）。

**权威链（§7）：** RFC 3261（§17 事务/§19.3 Via branch 合同）+RFC 3581（§4 rport/received 回填）+RFC 3264（§5-6 offer/answer）+RFC 3550（§5.1 RTP 双向）+RFC 4566（SDP）→ 设计=本条目（权威）→ 代码 → 测试。CORE_MEMORY 依据：§3.1-3.3（sessions 显式/独立四元组/独立生命周期）、§3.11-3.12（流间交错调度写清）、§9.9（并发交错/中断续作）、§9.23（地址族×会话×流矩阵）、1.12（字段必须住层）、12.9（静态复制拒绝）。

#### P1 现状→缺口矩阵（4.21）

**三路对照来源（4.12-4.15/4.17）：** 规范=RFC 3261/3581/3264/3550 原文；商业行为=Kamailio force_rport()/Asterisk chan_sip 多 dialog 并存/FreeSWITCHConference 焦点行为（官方文档出处，映射见子表③）；开源思路=kamailio（github.com/kamailio/kamailio，src/core/parser/msg_parser.c rport 解析思路）/opensips（tls 模块事件化思路），只借鉴不搬运。子表①②③（4.22）在每 WP 开工前随该 WP P1 全量落格——本条目 P2 先落全量框架：

**子表① 方法×响应码矩阵（已覆格=用例号）：** INVITE{100(T-44)/180(T-44,54)/183(T-30)/200(T-1等)/302(T-33)/401(T-35)/403(T-55)/404(T-7)/408(T-55)/480(T-55)/486(T-21,27)/487(T-20)/488(T-55)/491(T-53)/500(T-23)/503(T-56)/600(T-56)/603(T-23)}；REGISTER{200(T-5)/401(T-25)}；ACK/BYE/OPTIONS/INFO/UPDATE/MESSAGE/REFER/NOTIFY/SUBSCRIBE/PUBLISH{200 系}；CANCEL{200/487(T-20)}。分支级口径（9.21）：4xx 各码独立分支已逐格；同码异上下文（200×INVITE vs 200×BYE）已分例。

**子表② 数据形态变体表：** 紧凑形头(T-37)/多跳 Via+RR/Route(T-38)/超长头+URI(T-39)/tel:+UTF-8(T-40)/SDP 双流(T-41)/multipart 双体(T-42)/头名混写(T-43)/offerless(T-48)/pidf+conference-info XML 体(T-46,49)/sipfrag/dtmf-relay/MWI 体(T-20,28,29,32)/v6 端点+括号 URI(T-19,57)；大小端=SIP 文本协议 n/a（如实标注）；空值=空 dialog(T-18)。

**子表③ 商业行为→用例映射：** Kamailio rport 回填（WP-C 用例）/Asterisk 多 dialog 注册绑定订阅（T-29 同 Call-ID 面）/FreeSWITCH 会议名册（T-46）/运营商 IMS P 头（T-51）/摘机早媒体（T-30）/DTMF 带外（T-32）。逐条出处=各产品官方文档；无映射项标待确认（确认方式：抓 Kamailio 5.6 现网包，P3 前完成）。

#### P1 现状→缺口矩阵（4.21）

| 规范/文档要求 | 业务场景 | 代码现状 | 缺口 |
|---|---|---|---|
| §3.1-3.3 多会话显式声明独立 ID/四元组/生命周期 | UA 与服务器并发多 dialog（注册+通话+订阅并存） | SIPConfig.Dialog 单会话；flows=2 模板复制同 Call-ID | sessions[] 结构缺失（WP-A） |
| §3.8-3.10 RTP 关联三件事 | 双向通话媒体 | Media *SIPMedia 单向单挂点（types.go:2616 注释自认双向靠"用户建模两条"但配置只有一条槽位） | medias[] 双向+交错（WP-B） |
| RFC 3581 §4 NAT 回填 | NAT 穿越响应路由 | Via 用户原文透传，零合成 | rport/received 发射期合成（WP-C） |
| RFC 3261 SIPS URI/tls 底座 | 运营商加密信令 | GenEvents=nil 自驱拼完整包，无法插 tls 层 | 事件面双模式（WP-D） |

#### 架构裁定

**裁定 1（WP-A）：** sessions 语义=**每 session 一条独立 TCP 信令连接**（独立握手/挥手/四元组），沿 ftp sessions 范式（FTPSession:2435 先例：静态结构原地+Dyn 旁挂）。dialog 单会话形态零改动零回归；`sessions` 与 `dialog` 同给即 400（互斥锚词）。**flows×sessions 组合语义（2.5/2.8）：** flows=N × sessions=M = N×M 条信令连接（worker 流序号复制 sessions 模板）；session.src_port 缺省时按 `base(12345)+flowIdx*M+sessIdx` 派生防撞（2.8 保底口径扩展，写死则撞=用户责任，12.9 拒绝面只管"完全静态+多流"）；sessions 内标量端口+无动态+flows>1=静态复制拒绝（semantic.go 扩扫 sessions[].src_port/dst_port）。**端口住 sip 层=1.2 已批偏离延续**（D-SIP-1 七度已批，h323/sip 同款，semantic.go layerTupleFields 注记）。
**裁定 2（WP-B）：** medias[] 与 media 互斥（同给 400）；双向=同 EmitMedia 消息点 up/down 帧交替发射（A1 B2 交替，非两段纯流）；`interleave: true` 时后续 dialog 消息按"N 帧夹 1 信令"等分点插入（调度方式写死=可复现，§3.12）。
**裁定 3（WP-C）：** NAT 合成只作用于 **up 请求侧发射时**（down 响应=回放用户原文，RFC 3581 的 received 本就是服务端回填——引擎模拟的是"用户写的 src_ip 即 NAT 后地址"的发送侧事实，不做对端探测，诚实边界）。`nat:{rport:true}` 显式开启，缺省透传零变化。
**裁定 4（WP-D）：** 双模式——[ip,sip] 自驱保字节等价线（D-SIP-1 否决 B2 的教训只在 tls 模式局部化重演）；事件面=新 EventGenerator 把 dialog 翻成 MessageEvents，头补全 dialogCtx 状态机在事件面重写。**tls 链上 media 面=拒绝**（RTP 是 UDP 裸流不进 TLS，锚词 `media is not supported on a tls sip chain`）。

#### 决策对比

| 决策 | 候选 | 结论 |
|---|---|---|
| A 会话结构 | A1 sessions[]（ftp 范式） vs A2 多 FlowSpec 表达 vs A3 每流 dialog 派生 | **A1**（A2 用例表达不了并发不同内容=本轮起点缺口；A3 隐式魔法违 3.1） |
| B 标识派生 | B1 引擎自动 Call-ID/branch vs B2 用户全显式 | **B1 缺省+B2 覆盖**（session.call_id 显式赢，缺省 `{flow}-{sess}@{src_ip}`；branch 缺省 `z9hG4bK-<hash>`；模板内用户 CSeq 原样=回放合同不动） |
| C 双向媒体 | C1 medias[] 同点交替 vs C2 两条独立 media 流 | **C1**（C2 又回到"两段纯流"非真实交错） |
| D NAT 范围 | D1 仅 up 请求合成 vs D2 全消息合成 | **D1**（down=回放原文是全引擎合同；越界即违反回放语义） |
| E SIPS 路径 | E1 双模式事件面 vs E2 全量重写自驱为事件 | **E1**（E2 破坏 57 例字节等价线=D-SIP-1 已否决；E1 只在 tls 模式局部重写） |

#### WP-A sessions[] 多会话+标识唯一化（首批）

**依赖（5.1）：** legacy dialog 路径零改动为基线/头补全 dialogCtx（派生 Call-ID 注入点）/worker 流序号贯通（FlowIndex 既有）。**错误四件套（5.2）：** 失败返回=create 期 400（互斥/空数组/静态复制锚词）；会话命运=合成期拒绝无包产出；重试=无（回放合同）；超时=无时钟不断言（C 类）。**范围：** ①sip 层新增 `sessions:[{src_port?,dst_port?,call_id?,dialog:[...],media?}]`；②sessions/dialog 互斥 400（锚词 `sip: sessions and dialog are mutually exclusive`，空数组同锚词面）；③标识派生：call_id 缺省 `{flow}-{sess}@{src_ip}`、Via branch 缺省 `z9hG4bK-<hash(call_id,cseq)>`（头补全已有 Via 合成上叠 branch 缺省）；④每 session 独立 TCP 连接（独立 3 握 4 挥）；⑤静态复制门扩 sessions 内端口（语义层扫描 sessions[].src_port/dst_port 标量+flows>1 拒，D-FTP-3 同口径）。
**文件：** types.go（SIPSession+SIPConfig.Sessions）/strategy_convert.go（translate 解析+互斥检查）/protocol/sip/sip.go（planSessions 循环+标识派生）/core/schema/semantic.go（静态复制扩扫）/registry.go（registry 行加 sessions 键）/layer_dyn.go（session 端口动态位）。
**接口签名（8.2/8.3）：** `type SIPSession struct { SrcPort uint16; DstPort uint16; CallID string; Dialog []SIPMessage; Media *SIPMedia; SrcPortDyn/DstPortDyn/CallIDDyn *StrategyConfig(标签 json:"-") }`；`SIPConfig.Sessions []SIPSession json:"sessions,omitempty"`；派生函数 `deriveSIPCallID(flowIdx, sessIdx int, srcIP string) string`、`deriveSIPBranch(callID string, seq int) string`（sip.go 内未导出）。
**主流程（8.4）：** translate 解析 sessions（JSON round-trip）→FlowMeta.SIP.Sessions→Plan 循环 per flow：per session 建独立 dialogCtx（派生 Call-ID 注入）→独立 3 握→dialog 消息序→独立 4 挥→下一 session。
**冲突点（8.7）：** 头补全 dialogCtx 现按单 dialog 键控（Call-ID 继承）——sessions 后须 per-session ctx（改键=flow-sess 二元组，存量单 dialog 路径键不变零回归）；静态复制门扩扫与 D-FTP-3 层门共用 layerTupleFields 扩展点。
**验收：** 57 例零字节回归（sessions 缺省路径）+新例≥6（双会话独立 Call-ID/独立端口/交错生命周期/派生 Call-ID 断言/互斥负例/静态复制负例）。
**回滚：** 单提交粒度；dialog 路径零改动=存量零风险。

#### WP-B medias[] 双向+交错

**范围：** `medias:[{direction,frames,payload_type,src_port?,dst_port?,file_source?}]` 与 media 互斥；双 medias 同 EmitMedia 点交替；`interleave:true` 消息等分插入。
**文件：** types.go（SIPMedias+sip.go emitSIPMedia 改分段回调）/strategy_convert.go/registry.go/layer_dyn.go（medias[].src_port/dst_port 开动态）。
**验收：** 新例≥5（双向交替帧序断言/interleave 消息落点断言/互斥负例/动态端口/file_source 沿用）。
**回滚：** media 旧键不动=存量零风险。

#### WP-C NAT rport/received 合成

**范围：** `nat:{rport:true}`（received 随 rport 同开，RFC 3581 绑定语义）；up 请求发射期合成 `rport=<实际 src_port>;received=<src_ip>`；仅当 Via 含 rport 参数或 nat.rport=true。
**文件：** types.go（SIPNAT）/sip.go（emit 前 rewrite 一步）/strategy_convert.go/registry.go。
**验收：** 新例≥3（rport 回填值断言/缺省透传零变化回归/对 Via 无 rport 参数的 nat 开关语义格）。
**回滚：** 缺省关=存量零风险。

#### WP-D SIPS/TLS 事件面

**范围：** 事件模式 EventGenerator（dialog→MessageEvents，复用 render/补全状态机非重写）；[ip,tcp,(tls),sip] 链注册；tls 链 media/sessions 拒绝锚词；sips: URI 无 tls 拒绝锚词。
**P2 定稿补充（2026-09-20，裁定 4 细化 + 延期裁定撤销）：** 延期理由不成立——tls 链底座已在役（[ip,tcp,tls,http] 绿、mqtt OptionalOn 先例），字节回归面被模式分离限死。五个定稿决策：
1. **双模式分派=InitChain 链感知钩子**：GenEvents() 无参且 mqtt 无双模式先例，instantiateGens 同步调用可选接口 `InitChain([]Layer)`；sip Generator 记 eventMode=链含 tcp/tls、tlsMode=链含 tls；GenEvents 按 eventMode 返回（[ip,sip] 恒 nil=自驱字节零回归线）；Generate 以 req.EmitMsg!=nil 分派（mqtt 同款）。
2. **事件面形状拒绝**：sessions/media/medias 在事件面无等价物（一链一连接；RTP 是 UDP 裸流）→ 锚词 "sessions are not supported on a tcp/tls sip chain" / "media is not supported on a tcp/tls sip chain"；schema create-time + 生成器运行时双保险（mqtt 纪律）。interleave 不拒（无 media 即惰性）。
3. **Via 传输令牌按链面**：生成 Via TCP（自驱）/TLS（tls 链，RFC 3261 §26.2.1 SIPS 必须走 TLS）；实现=dialogCtx.viaTransport 单格式化点（自驱路径字节零漂移）；用户显式写 Via 恒赢不重写（引擎字节回放哲学=文档化边界）。
4. **sips: URI 无 tls 层判死**（RFC 3261 §26.2.2+RFC 5630）：只扫 dialog[].uri 与 sessions[].dialog[].uri 请求 URI 前缀 sips:；To/Contact 头内 sips 不扫=B′ 边界；锚词 "sip: sips uri requires a tls layer in the chain"。
5. **5061 缺省不自动注入**（B′ 边界如实记录）：tls 链 SIPS 端口由用户显式写 tcp.dst_port=5061（tls 层 FieldContract 是单值合同 "tcp.dst_port":"443"，不适用双载口协议）；后续需要可加变体。
**P1 矩阵增补行（SIPS/TLS 面）：** SIPS URI 语义（RFC 3261 §26.2.1：SIPS 要求端到端 TLS+Via TLS）→ 决策 3/4；TLS 传输承载（§26.2.4+RFC 5630 §2.6）→ 决策 2（RTP 不进 TLS）+事件面；5061 端口（IANA sips 注册口）→ 决策 5 显式边界。
**文件：** protocol/sip/event_gen.go（新）/layers/chain_planner_chain.go（InitChain 钩子 4 行）/registry.go（OptionalOn tls——M2 纪律：与验证通过的代码+pcap 证据同提交才算登记）/layer_gen.go（双模式分派）/sip.go（viaTransport 单格式化点）/schema/semantic.go（checkSIPEventPlane）。
**验收：** 6 例（T-81 OPTIONS over tls / T-82 REGISTER over tls / T-83 OPTIONS over 纯 tcp 面字节可见 / T-84 tls×media 拒 / T-85 sips 无 tls 拒 / T-86 tls×sessions 拒）+ [ip,sip] 80 例零回归；事件面单测≥5（基本流/TLS 令牌/形状拒/NAT 复用/双模式分派）。
**回滚：** OptionalOn 摘除+InitChain 钩子摘除=双模式不可达，[ip,sip] 自驱不受影响；单提交粒度。

#### §12 动态字段清单（新增面）

| 字段 | 开/关 | 理由 |
|---|---|---|
| sessions[].src_port/dst_port | 开（E1 同款） | 逐流逐会话端口池=多会话多流主用例面 |
| sessions[].call_id | 开（pattern/fixed） | 标识派生覆盖口（B2 决策） |
| medias[].src_port/dst_port | 开 | 与 T-21 同构 |
| sessions[].dialog 内容 | 关 | 会话结构=回放模板（D-SIP-1 既有裁定） |
| frames/payload_type/nat.* | 关 | 结构/行为面无逐流语义 |

#### 门 1 对照表（14 行）

| § | 满足方式+证据 |
|---|---|
| §1 顶层旧键 | 无新增顶层键——全部结构住 sip 层内（1.11-1.13 白名单：layers/flow_control/output 之外零游离）；sessions/medias/nat 均为层内键。**目标形状完整例（15.3，WP-A+B+C 合成像）：** `{"layers":[{"ip":{"src":"10.0.0.1","dst":"20.0.0.1"}},{"sip":{"sessions":[{"src_port":22001,"call_id":"a@10.0.0.1","dialog":[{"method":"INVITE","uri":"sip:callee@20.0.0.1"},{"status_code":200,"status_text":"OK"}],"medias":[{"direction":"up","frames":3},{"direction":"down","frames":3}]}},{"dst_port":5062,"dialog":[{"method":"OPTIONS","uri":"sip:callee@20.0.0.1"},{"status_code":200,"status_text":"OK"}]}],"nat":{"rport":true}}]}`（1.9：四 WP 已全部落地，此例即现网可跑形态） |
| §2 判死 | 既有 presence 判死不变；新增互斥负例锚词 3 条（sessions×dialog/medias×media/tls×media） |
| §3 五件套+四件事 | 会话表=sessions[]（每条独立 ID=call_id/四元组/生命周期）；事务序列=session 内 dialog 消息序；关联=medias[]→EmitMedia 消息点+SDP 推导（三件事不变；**双向子流 ID=parent:rtp-up / parent:rtp-down**（3.10 parent:sub-idx 形状）；插入=WP-B interleave 等分点；时间线=交错调度写死可复现，**包时间戳=发射序（引擎无时钟，断言面=帧序非绝对时间，3.12 口径如实）**。**单事务四件事（3.4-3.7）：** 前置=同 dialog 先行消息（401 的 nonce→重发、302 的 Contact→重发）；触发=dialog 消息发射；成功分支=2xx→下一消息；失败分支=非 2xx→ACK/重发/终止（T-25/33/53 用例面表达） |
| §4 规范矩阵 | 见 P1 表（RFC 3261/3581/3264/3550/4566 逐项） |
| §5 依赖与错误 | 互斥 400×3+空 sessions 400+静态复制拒（锚词全列）；错误返回=create 期 schema 拒/任务期 planner error（§5.6 四件套沿用） |
| §6 性能与验收 | 包数=session 数×(7+Σmsg)+媒体帧；**依据（6.4）：** 流式 channel（既有 256 缓冲）逐包发射不全量收集，session 仅增遍历循环零新增常驻内存，无共享状态无新锁；**六类场景（6.6）：** 并发交错=WP-A/B 用例面覆盖，基线/目标规模/压力/长跑/背压=引擎级性能测试（全协议共用，D-FTP-4 同款口径**缺口如实记录不冒充**）；无吞吐数字承诺（6.5 未测标待确认）；回归口径=57 例 ±10% + 字节零变化线；pcap+网卡两路（网卡未跑注明，6.3） |
| §7 顺序与回滚 | WP-A→B→C→D 逐 WP 独立提交；每 WP 回滚=单提交粒度；dialog/media 旧键零改动=存量零风险 |
| §8 定稿后开工 | 本条目 P2 待用户批 |
| §9 测试设计 | 每 WP 新例数已列（6/5/3/3）+存量 57 例回归面；T-SIP-58… 起编。**动态整格矩阵（9.32/12.15，P3 落格）：** sessions[].src_port×{inc,rand,list,fixed,pattern}+call_id×{pattern,fixed}+medias[].src_port×{inc,list}=**10 格逐格不抽样**；每格三问（9.34：语义发生/可复现/回绕）。**9.40 陷阱注记：** 同流多 session 共享 FlowIndex→动态同值=真实语义（session 差异锚 call_id/session 端口派生序，不锚 FlowIndex） |
| §10 自审闭环 | 每 WP 改→审→测→修→再审（CLAUDE.md 绑定） |
| §11 白话汇报 | 每 WP 收官一句结论+过门证据 |
| §12 动态清单 | 见上表 |
| §13 schema 先行 | registry 行同步+schemagen 重跑（102→103+ 键）；MCP 描述/前端类型重生成 |
| §14 全量门 | 每 WP：CASE_PROTO=sip 全量绿+落盘 pcap+门 2 四项+反查表扩条目 |

**明确不解决：** 对端探测式 NAT 行为模拟（真 NAT 穿越需收包回填=非合成器合同）；ICE/STUN/TURN 联动（独立协议面）；SIP over WebSocket（RFC 7118）；SRTP（媒体加密独立面）；会议焦点混音行为（RFC 4575 只承载名册不执行混音）。


### D-RADIUS-1 radius 层链化：终层自驱（UDP 无状态 Rounds 交换）+ 端口住层【P-PIPE #20 门1】

**状态：** P2 定稿（2026-09-19；门 1 已交+对抗自重审 2 轮（锚词计数 12→13 条修正、响应 Authenticator 恒随机边界补报（:343 每响应新 randomAuth，仅请求侧 fixed hex 可钉）、identifier+round uint8 回绕注记；主体零事实错误，末轮净）；CORE_MEMORY 逐条复审完成。裁定延续：端口住 radius 层+端口动态 E1=七度已批。现状：legacy 完整（radius.go 477 行，**UDP 无状态**——无握手挥手，Rounds×(请求 up→响应 down) 同四元组交换（:306-370）；20B 头 Code+ID+Length+Authenticator+TLV 属性（RFC 2865 §5；VSA type 26 外层 8B :432-445）；码面 8 码=请求{1,3,4,11,12}×响应{2,3,5,11,13}+auto{1→2,4→5,12→13}（:61-65），code 3/11 无 auto 必须显式 response_code（Validate :127-128）；缺省 dst 1812/code=4→1813、rounds 1、code 0→Access-Request、reqAttrs 缺省（User-Name "user"/acct Start+Session-Id）；Authenticator crypto/rand 随机（:459-468）或 fixed hex 16B；identifier+round uint8 回绕（:307）。Validate **13 条锚词**（:98/:103 IP parse/:107 nil 硬拒 `radius config is required`——与前六 nil 合法不同/:117 请求码/:125 响应码/:128 无默认响应/:135 hex/:138 16B/:171 长度超界/:178-:189 format 四态）。**v3 预留已在 chain_planner**（:525 dst-0 合法名单+：770 DstPort switch 1812/1813——但 validateSpecBase:149 先于 translate:161，:770 拿不到 code 恒 1812=**顺序缺陷，translate 自补覆盖修正**）。main.go:121 具名导入+:562 直挂，层链四件全缺。用例 1 例 `radius_smoke_01` spec 仅 `{"radius":{}}` **本无扁平键**（packet_count 2+14 fields tshark radius.code/id/length/req/rsp/reqframe/authenticator nonzero+avp.type/length 实证）。在库 tasks 91+strategies 4）。**P4 已执行（2026-09-19，提交 1501264）：** registry 9 键行/CheckProtoFlat presence/translate case radius（7 业务键+JSON round-trip+dst 缺席顺序修正覆盖）/**SrcPort 零保持名单 += radius**（validateSpecBase 先于 translate，src 缺席单流 0 上包=mcp/modbus 直传族语义，多流 worker 12345+i；本项 P4 构建期发现、推翻 P2 "不加名单"误判——链路径无 12345 保底，h323/sip 同构先例直接适用）/FlowMeta+carry/isRawIPChain/layer_dyn 五件套/layer_gen（force-up 防双换/GenEvents nil/validateLayer legacy 委托）/main 翻转/门登记+schemagen 102 层；5 红例全绿+touched 包 -race+vet 净。**P5 已执行（2026-09-19）：** cases 25/25 全绿（T-1 改写+T-2…21+A′ 补充批 T-22…25）；P5 校准 4 处见 T-RADIUS 状态行（多 AVP 逗号拼接/11→11 与 12→13 无 rsp/reqframe 改端口交换钉/port_distinct 双向聚合/strategy_fc 键名）；反查 check_radius 44/44+门 2 静态四项绿+五协议回归绿；落盘 /tmp/mcp-pcaps/radius/）。**P6 已验收（2026-09-19）：** 在库清空 tasks 165+strategies 19（删前实测重报，241334−165=241169/763−19=744 双总量对账精确），备份 /tmp/trafficgen-backup-radius-p6.db，复核 0/0+交叉引用 0；门 3 抽查三条：①§1 层链唯一真相——radius_flat_presence 经真实流程拒绝锚词 "top-level radius sub-config"（strategy_convert.go CheckProtoFlat radius 分支空 map 也死），25 例非负例顶层仅 layers+strategy_fc（presence-negative-case-shape：负例=层链+顶层空子映射并存，判死执法对象非残留）；②§12 动态清单——业务 7 键全关（layer_dyn.go 零 radius 业务行）+端口 2 键开（T-21 src/dst inc 双 group_id 实证 12001→12002/1812→1813 逐流），序号算法=resolveLayerTuple radius 块；③§14 真实流程——T-4 acct 1813 顺序修正专项经真实服务落盘实证 udp.dstport=1813（tshark 非 :770 预写路径），T-24 NAS 组合 avp.type "6,4,31,80" 逗号拼接落盘重钉。P4 构建期发现+ SrcPort 零保持名单修正（见 P4 记录）

**架构裁定（P2 定稿）：** **A1 [ip,radius] 终层自驱整包 relay**（八度验证机器：emit 逐包自管方向（:320-368 up/down 各 emit 自换地址端口）→force-up 防双换；stun/tftp 同组 UDP 无状态先例 main.go:502/:584 已链化）。**端口缺省顺序修正（本条目核心新裁定）**：validateSpecBase(:149) 先于 translate(:161) 执行，:770 预写的 `case "radius"` 拿不到 spec.Radius（恒 nil）恒落 1812——**translate 自补 dst 缺省：dst_port 层键缺席→code==4?1813:1812**（后写覆盖预写 1812；双态判断依据=层 config 键而非 spec.DstPort，不会被预写值误判"用户显式"）；扁平侧 strategy_convert:884-899 同款缺省保留（mapToFlowSpec 仍服务内部形状，两路各自闭合，:884"届时移除"注记裁定不移除）。**随机性注记**：请求 Authenticator 缺省随机/fixed hex 16B 可钉值；**响应 Authenticator 恒随机**（:343 即使请求 fixed）——断言仅 nonzero（存量先例）；ip.id 随机不断言。**v6 正例格**（ParseIP 通用无族强制）。

**权威链（§7）：** 标准=RFC 2865（§3 报文/§5 属性/§5.1-§5.79 TLV）+RFC 2866（§3 accounting 口）→ 设计=本条目（权威）→ 代码 → 测试。字节事实=参考 pcap portion_Radius.pcap（auth 1812）/start-stop.pcap（acct 1813）转录（radius.go:17-18）+存量探针实测（tshark radius.* 14 断言）。

**依赖链判定：**

| # | 断链层 | 判定 | 处置 |
|---|---|---|---|
| ① 层链四件缺 | 代码缺口 | registry 无行/translate 无 case/FlowMeta 无 Radius/无 generator | P4：registry 新终层行（9 键：7 业务+2 端口，attributes/response_attributes{list}）+translate（7 键逐映射+两列表 round-trip）+FlowMeta.Radius+carry+layer_gen 包装+注册 |
| ② legacy 校验已全 | 无缺口 | Validate 13 锚词（码白名单×2/无默认响应/hex/16B/长度/format 四态/IP×2/nil） | validateLayer=legacy 复用零新文案（nil 恒不可达：translate 恒填非 nil）；IP parse 链不可达（schema 先拦） |
| ③ 静态复制门漏扫 | 执法洞 | 扫描列表无 radius | P4 扫描列表 += "radius"+红例⑥ |
| ④ :770 顺序缺陷 | 代码缺口（v3 预留） | 预写 1812 拿不到 code | **本条目修正**：translate 自补 dst 缺省（见架构裁定）；:770 预写保留不动（无副作用） |
| ⑤ 端口动态 | E1 延续 | allowlist 无 radius 行 | P4：LayerDynValues.RADIUS+allowlist 2 键+parseLayerDyn case+resolveLayerTuple+HasAny |
| ⑥ v6 对照 | 正例格 | IP 透明 | v4/v6 双族逐格（9.24）——P3 落格 |

#### 门 1 对照表（已交，证据回填版）

§1 键去向：存量无扁平四元组/count（唯一顶层键 radius 子映射）→layers[radius] 直迁 7 业务键；端口住层。目标形状 `{"layers":[{"ip":{"src":"10.0.0.1","dst":"20.0.0.1"}},{"radius":{"src_port":12345,"dst_port":1812,"code":1,"identifier":0,"rounds":1,"attributes":[{"type":1,"value":"user"}]}}],"strategy_fc":{"type":"flows","value":1}}`。§3 五件套：会话表=豁免（UDP 无状态 RFC 2865）；事务序列=Rounds×(请求 up→响应 down)无握手挥手；关联=豁免；插入=raw-IP 驱动整包 relay；时间线=轮次线性 ID=identifier+round。§12 动态：业务 7 键全关（码面/轮数结构/鉴权/AVP 模板逐键理由见 P1 §12 表）；端口 2 键开（E1）；序号=layer_dyn resolveLayerTuple radius 块（P4 新增）。

#### 决策对比（4.17）

| 决策 | 候选 | 结论 |
|------|------|------|
| A 链形 | A1 终层自驱 vs 事件面 | **A1**（UDP 无状态最简形态；stun/tftp 同组先例） |
| B 端口住处 | B1 radius 层键+门扩扫 | **B1** |
| C 翻译 | C1 7 键逐映射+两列表 round-trip+**dst 缺省 translate 自补（顺序修正）** | **C1** |
| D 校验 | D1 复用 13 锚词（nil 恒不可达；v6 正例） | **D1** |
| E 端口动态 | E1 延续 | **E1** |

**明确不解决：** 响应 Authenticator MD5 验证（RFC 2865 §3 响应应为请求 Auth 的 MD5——legacy 随机合成=C 合同不冒充）；IP parse 链锚词（不可达）；rounds>256 回绕外语义；Message-Authenticator(80)/EAP-Message 属性特殊编码（通用 TLV 已覆盖）。**补充批立项（2026-09-19 §3/§9 对抗复审，B 类 3 项，此前漏登记）：** RFC 5176 CoA/Disconnect 码族（43/40/45/41——现 requestCodes 白名单不含，T-25 负例执法格，支持须扩白名单+autoResponse 表，另立条目）；Message-Authenticator HMAC-MD5 计算/校验与 EAP-Message 配对语义（现仅 opaque 字节承载 T-24 位型钉，RFC 2869 §3.2）；UDP 重传计时（RFC 2865 §2.4，同 SIP Timer C 类口径）。A′ 补例 4 例（T-22…25）见 TEST_CASES。

#### 1. 文件清单（P2 定稿）
- Modify: `internal/core/layers/registry.go`——radius 终层行（CategoryTerminal+DependsOn ip+Fields 9 键无 Default：code{uint8}/identifier{uint8}/authenticator{string}/attributes{list}/response_code{uint8}/response_attributes{list}/rounds{int 面 uint16}/src_port{uint16}/dst_port{uint16}）
- Modify: `internal/core/layers/chain_planner_translate.go`——case "radius"（spec.Radius==nil 层优先；7 键逐映射零缺省镜像 :884 parseRadiusConfig；attributes/response_attributes JSON round-trip；端口双态：标量→spec、**dst 缺席→code==4?1813:1812 顺序修正**、src 缺席不动 worker 保底、对象放行）
- Modify: `internal/core/layers/generator.go`+`chain_planner_chain.go`——FlowMeta.Radius+carry
- Modify: `internal/core/layers/chain_planner_util.go`——isRawIPChain 加 radius
- Modify: `internal/core/layers/chain_planner.go`——:525/:770 v3 预留已存在**不动**；两端口豁免名单按需（:707 SrcPort zero-keep **不加** radius——worker 保底正确语义）
- Modify: `internal/core/strategy_convert.go`——CheckProtoFlat radius presence 分支（:884-899 扁平缺省保留）
- Modify: `internal/core/schema/semantic.go`——扫描列表 += "radius"
- Modify: `internal/core/layer_dyn.go`+`internal/core/types.go`——LayerDynValues.RADIUS/allowlist/parseLayerDyn/resolveLayerTuple/HasAny（⑤）
- Create: `internal/protocol/radius/layer_gen.go`——Generator 包装 legacy Plan（force Direction="up" 防双换；GenEvents nil）+validateLayer（纯 legacy 13 锚词）+init 注册
- Modify: `cmd/server/main.go:121,562`——具名导入→空导入+NewChainPlanner("radius")
- Modify: `tools/pipe_gate.sh`+`tools/coverage_gate.py`（check_radius）、schemagen 重跑
- Modify: `test/protocol_pcap/cases/radius.json`（P5 按 T-RADIUS）
- Test: `internal/core/layers/radius_migrate_test.go`（红例①-④）+`internal/core/radius_layer_dyn_test.go`（红例⑤）+`internal/core/schema/radius_static_port_test.go`（红例⑥）
- 零改动：`internal/protocol/radius/radius.go`（字节事实）

#### 2. 接口签名（锚词）
- presence：`protocol radius no longer accepts a top-level radius sub-config (move it into the radius layer of an [ip,radius] layers chain)`
- validator：legacy 13 锚词（`invalid request code (allowed: 1, 3, 4, 11, 12)`/`invalid response code (allowed: 2, 3, 5, 11, 13)`/`has no default response code`/`invalid authenticator hex`/`must be 16 bytes`/`exceeds the %d-byte field limit`/`format=ipv4/uint32/hex`/`unknown format` 等——radius.go:98-189 实取）
- static：`static four-tuple`（既有门，扫描面扩 radius）

#### 3. 主流程
create：ValidateStrategy→ValidateLayers（V9 9 键）→CheckProtoFlat presence→checkLayerChainStaticCopy（含 radius 端口）→400。
任务：mapToFlowSpec→parseLayerDyn→worker resolveLayerTuple→ChainPlanner.ValidateSpec：validateSpecBase（radius 在 :525 dst-0 名单+:770 预写 1812 无害）→translate case "radius"（**覆盖 dst 1812/1813**）→validateLayer（legacy——IP/nil 锚词链不可达）→Plan：isRawIPChain→raw-IP 驱动（meta 补齐→Generator.Generate→legacy Plan Rounds×2 整包 relay→force up 防双换）→builder：UDP L4 装配。

#### 4. 增量步骤（failing 先行）
红例族 6：①TestRadiusChain_FlatPresenceRejected ②TestRadiusChain_LayerFieldsAccepted（9 键 V9 含 attributes 列表）③TestRadiusChain_LayerTranslateMinimalExchange（链 [ip,radius{ports,code:1}]→2 包（req up/rsp down）+radius.code 1/2+dstport 1812）④TestRadiusChain_PresenceFilled（7 键逐槽+attributes round-trip+VSA vendor_id）+**TestRadiusChain_AcctPort1813**（code:4→dstport 1813=顺序修正专项）⑤TestRadiusLayerPortDynAllowlisted（core）⑥TestRadiusStaticPortFlowsRejected（schema：[ip{},radius{ports}]+flows=2）。

#### 5. 错误锚词
见 §2；legacy 13 锚词为链路径执法面（零新文案）；IP parse/nil 两锚词链不可达=C 注记零死锚。

#### 6. 性能设计与验收
包数=Rounds×2；整包 relay 流式（channel 256）无收集无锁；翻译一次；回归口径 suite ±10%；pcap 路=套件；网卡未跑注明。
#### 7. 顺序与回滚
红例→registry+translate（含顺序修正专项红例）→FlowMeta/isRawIPChain→门扩扫+layer_dyn→layer_gen+注册→presence→main 翻转→门登记+schemagen→绿；P5 cases。回滚=单提交粒度；radius.go 零改动=字节事实零风险。
#### 8. 验收
对应 T-RADIUS（P3 定稿）。完成条件：7 红例先红后绿（含 1813 专项）；radius.json 全量绿（RESULT+二进制同代+门 2 四项+反查）；touched 包 -race+vet 净；顶层 radius 字面零残留（负例豁免）；schemagen 同步绿；门 1 表回填+抽查三条；在库 radius 行清空（P6 删前报数→备份→删→复核——绝对路径+总量对账）。

## D-PPPOE-1 pppoe 层链收敛（#21，2026-09-20 已验收：8b6c565 P4+P5/P6 同日收官）

**依据：** RFC 2516（PPPoE §4 会话/§5 Discovery+TLV/§5.6 PADT/§7 MTU 1492）+RFC 1661（§4 LCP/§5 PPP Protocol/§6 选项/§8 认证）+现网 BRAS 行为（AC-Name/AC-Cookie/Host-Uniq 标签，出处=运营商接入网通用抓包形，注记待确认方式=抓现网拨号包）。**现状代码事实：** legacy 完整 512 行（discovery 四步+LCP MRU/Magic+PAP/CHAP+IPv4 数据面，planner.go）；内嵌 IPv4 直读 spec.SrcIP/DstIP（:407-410，down 交换）；DefaultSessionID=1/DefaultACName="trafficgen"（:38/:46）；Validate 7 锚词（:100-158，含 DataDirection 枚举）；registry 占位行零字段（registry.go:1275）；main.go legacy 直挂（:555）；扁平 1 例 smoke `{"count":1,"pppoe":{}}`（7 帧，PADS session_id 0x0001）；**planner 零 PADT 流程**（builder 面有 0xa7）。

### 裁定（P2 定稿）

| # | 裁定 | 依据 |
|---|---|---|
| 1 | **层形状=[ip, pppoe]**：pppoe CategoryTerminal+DependsOn `["ip"]`（srv6 对称口径 registry.go:1100）；raw 自驱=终层自产完整帧（Eth+PPPoE+PPP+内嵌 IPv4，isRawIPChain 分支）；**ip 层值=内嵌 IPv4 语义**（帧无外层 IP 头，Validate :111-120 的 IP 检查即内嵌 IP）；eth 可选层（MAC 覆写，registry.go:47 字段已在；不写=spec 缺省 MAC） | 门1 复审错③裁定 |
| 2 | **翻转五件套（缺口 D）**：① isRawIPChain 名单 += pppoe（chain_planner_util.go:45）② validateSpecBase src 0-保持名单 += pppoe（chain_planner.go:710 区段，radius P4 同款先例）③ dst 分支同款豁免（:489）④ registry 行补 Fields（18 业务键）+translate `case "pppoe"` 复用 parsePPPoEConfig 单真相+FlowMeta carry ⑤ main.go 翻转 ChainPlanner+空白导入 | 门1 复审遗④ |
| 3 | **PADT 补齐（缺口 A）**：planner 数据面后发 PADT（code 0xa7、up、Session ID=已分配、零 TLV）；键 `padt` bool **缺省 true**（RFC 2516 §5.6 完整生命周期）；smoke 例重校准 7→8 帧（14.6 从 pcap 钉） | §5.6 要求面 |
| 4 | **多会话（缺口 B，9.49 硬要求）**：`sessions[]` 每项=完整生命周期（Discovery→LCP→Auth→Data→PADT），session_id 显式>派生（DefaultSessionID=1 逐项 +i，PADS 回显即派生值）；模板键（ac_name/service_name/auth/username/password/mru/data_frames…）共享；与顶层单会话键同给判死，锚词 `pppoe: sessions and top-level session config are mutually exclusive` | sip sessions 范式；RFC 2516 §5 每会话独立发现 |
| 5 | **流身份与 MAC（缺口 E）**：多流身份锚=Session ID（派生防撞=12.10 保底，不触 12.9 静态复制拒）；显式重复 session_id → Validate 拒，锚词 `pppoe: duplicate session_id`；MAC 恒 spec 值不递增（goose 现状一致，如实注记无先例） | 9.35 锚点+门1 复审错② |
| 6 | **场景强度（9.46–9.53 全额）**：数据=code 全表{00,09,07,19,65,a7}+非法码负例/TLV 标签表{0000,0101,0102,0103,0104,0110,0201,0202,0203}逐值/PPP 协议字段{0021,c021,8021,c023,c223}/LCP 选项表/边界（payload_length 覆写、空 Service-Name=any、cookie 有无、超大 data_payload）；业务=全生命周期/skip_discovery/pap/chap/data_direction 双向/PADT 拆断；现网=BRAS 三标签形/多会话并发；复合大场景=多会话+auth+data+PADT+异常 ≥3 类交织单例（9.50） | CORE_MEMORY 9.46–9.53 |

**文件：** protocol/pppoe/layer_gen.go（新，wrap legacy）+planner.go（PADT+sessions）/core/layers/chain_planner_util.go+chain_planner.go（名单）/registry.go（行补全）/chain_planner_translate.go（case+carry）/strategy_convert.go（sessions parse，单真相）/cmd/server/main.go（翻转）/cases/pppoe.json（改写+补强）。
**接口签名：** `ParsePPPoESessions(v any) []PPPoESession`（导出单真相）；`PPPoESession{SessionID uint16; SessionIDDyn *StrategyConfig; DataFrames int; ...}`；layer_gen 照 sip raw 自驱形（GenEvents nil，force-up 防双换）。
**性能（6.4-6.6）：** 流式 channel 256 逐帧发射无收集；包数=会话数×(4 Discovery+2 LCP+2×auth+DataFrames+1 PADT)；无共享状态无新锁；六类引擎级场景=全协议共用缺口如实记录；pcap 一路验收（网卡路=物理口直发，未跑注明 6.3）。
**回滚：** 单提交粒度；main.go 摘除空白导入即回 legacy；planner 增量（PADT/sessions）向后兼容（padt 缺省 true 改变 smoke 计数=唯一重校准点，如实）。
**门1 对照表：** 已交（2026-09-20），复审修正 4 项后为定稿版（锚词 7/内嵌 IP=[ip,pppoe]/翻转五件套/MAC 无递增先例），随 P6 回填证据号。
**P3 复审 errata（TEST_CASES T-PPPOE 节）：** 层 Fields 终值=**16**（wire 键 code/ppp_protocol/payload_length/discovery_tags 不登记，1.12 消费面裁定）；sessions 互斥键集合=会话级行为键 6 个，模板键 9 个可共存。**P2 复审（2026-09-20，对抗走查，用户指令每阶段必复审）：** 抓 4 项 errata，已并入上文：①文件清单漏 types.go（PPPoESession 结构+PPPoEConfig.Sessions 字段）与 schema/semantic.go（sessions 互斥+重复 session_id 两检查，sip checkSIPSessionsMutex 同构）；②registry Fields 计数 18→**20**（+padt+sessions，ValidateLayerConfig 拒未知字段故必须全登记）；③"eth 可选层 MAC 覆写"降级为 P4 验证项——extractLayerMACs 回填机制在扁平 mapToFlowSpec（strategy_convert.go:415-423）实存，但**链路径 eth MAC 注入点未证**（goose 用例只写 eth.src_mac 无 src MAC 值断言，goose 层 dst_mac 是业务键非链层），v1 口径=MAC 走 spec 缺省 02:00:00:00:00:01/02，链路 eth 覆写验证后再定；④门1 §3 "失败=PADI 重发"表述撤销——planner 零重发逻辑（grep 空），失败分支=回放表达（用户写 PADS Service-Name-Error 0x0201 错误标签=B′ 注记，逐值建例按需）。**复审结论：自审 1 轮 4 项修正，修正后定稿净，待批进 P3。**

**P4 已实现（2026-09-20）+ P4 复审 errata（对抗走查，2 实错 1 注记）：**
- 实装落点：planner.go（runSession 闭包提取+PADT+sessions 循环+Validate 背 door 三锚：sessions 互斥/空数组同锚/重复显式 ID）；types.go（PPPoESession 7 字段+PADT *bool+Sessions）；strategy_convert.go（ParsePPPoESessions+ParsePPPoEConfigFromMap 导出+parsePPPoEConfig 接 Sessions）；schema/semantic.go（checkPPPoESessionsMutex+numField 数值双形 int/float64）；registry.go（Terminal+DependsOn ip+16 Fields）+双 schemagen 重跑；chain_planner_util.go（isRawIPChain += pppoe，双名单）；chain_planner.go（src 0-keep+validateBaseDstPortHandled 两处）；chain_planner_translate.go（case "pppoe" 复用 ParsePPPoEConfigFromMap 单真相，data_payload 字符串=原文字节故不走 JSON 往返——srv6 inner_payload 同陷阱）；generator.go（FlowMeta.PPPoE）+raw 分支 carry；pppoe/layer_gen.go（新，srv6 防双换模式 Direction 统一 up）；main.go 翻转+空白导入。红例先行：planner 4（PADT 终止/抑制/sessions 多生命周期/显式 ID）+parse 2+schema 4+链级 2，全转绿；老测试 6 例 PADT 重校准（7→8 等裁定3 预告），-race 绿，vet 净。
- **复审修复①（R1）**：magic number 原 goroutine 级解析一次→多 session 共用同一 Magic，违 RFC 1661 §6.13 每链路独立随机——resolveMagic 移入 runSession，每生命周期各自掷值（显式 MagicNumber 测试钉值不受影响）。
- **复审修复②（R2）**：layer_gen 包注释误述"EtherType 无需写入"——实际 emitFrame 恒按 Code 写 EtherType（0x8863/0x8864），builder 强制是第二道兜底；注释改双保险表述。
- **注记（B′ 账本）**：链路径内层 L4 端口恒 0——链上无 tcp/udp 层可承载内嵌 IPv4 端口，pppoe 层 16 键亦无端口位（合成面合法：内层 UDP src/dst=0 上包）；现网形内层端口需求=B′ 立项候选（与 IPCP 缺口 F 同账本）。
- **实施期修教学件**：重构期 build 断（python 块切片吃掉 for 收口→作用域链下移→`runSession` 自引用 undefined——Go 短声明作用域始于声明末，闭包体内自引用不可见）；emit 闭包 FlowID 曾用外层 flowID 致多会话流身份相同（裁定5 违例，复审前自查抓出改 sessFlowID）；Go 字面量 int vs JSON float64 双形两次踩（schema numField、链测试 mustJSONMap——getUint16 族只认 float64/json.Number 与生产解码面一致）。
**复审结论：P4 自审 2 轮（实施自查 1+对抗复审 1），对抗轮抓 2 实错已修，修正后全绿。待批进 P5。**

**P5/P6 验收（2026-09-20）：** suite ×2 连续全绿 `RESULT: 24 pass, 0 fail, 0 error (of 24)`（负例 6 全带锚词真实流程断言）；pcap 落盘 19 正例+3 neg 可复查；tshark 抽查 T-1/T-12 帧序与 session 绑定全对；coverage_gate check_pppoe 登记 45/45 绿（场景 24+键 15+锚词 6）。**P5 抓真 bug 1：parsePPPoEConfig 漏接 padt（T-2 首跑抓出，层链路径 PADT 抑制被静默丢弃）→getBoolPtr 补接+锁例**，byte 校准与 T-8/T-14/T-21/T-22 口径修正详见 TEST_CASES P5 执行记录。
**门1 对照表回填（实际证据）：** §1 顶层旧键→cases 24 例零顶层四元组（pipe_gate 门2-1 绿）+地址入 ip 层（pppoe_lifecycle_full spec_json）；§3 五件套→单流豁免（无子流派生，Transactions=单会话帧序）+多会话 sessions 五件套（T-12/13/14）；§12 动态字段→session_id dyn=PPPoESession.SessionIDDyn（strategy_convert.go parseStrategyConfigDyn 旁挂）+ResolvePortValue 逐流解析（planner.go sessions 循环）+FlowIndex 透传（layer_gen.go spec.FlowIndex）；门 1 表其余行按 P2-P4 复审修正版执行。
**门3 抽查三条（每条点到代码行/用例号）：** ①裁定 3 PADT 缺省真→planner.go `if sessCfg.PADT == nil || *sessCfg.PADT`（emitFrame 前）+T-2 padt_suppressed 7 帧无 0xa7+T-1 第 8 帧 `11 a7 00 01 00 00`；②裁定 4 互斥→schema/semantic.go checkPPPoESessionsMutex 行为 6 键扫描+planner.go Validate 背 door 同锚词（T-23 真实流程 400 断言）+parse 锁例 TestParsePPPoEConfigPADTPtr；③裁定 5 流身份→planner.go emit 闭包 `cfgOut.FlowID = sessFlowID`（session 后缀）+T-12 派生 ID 1/2/3 tshark uniq 3×3 数据帧+TestChainPlanner_PPPOESessionsChain 2 distinct FlowIDs。
**9.53 门3 复杂度抽查：** 最复杂例=T-14 复合大场景，维度计数=多会话(2)×认证(chap 共享)×skip_discovery×方向(down)×多帧(data_frames 2)=5 类交织 ≥3 ✓（9.50 达标），19 包两生命周期形状逐帧钉。
**在库清库：** 删前 SELECT 报数→备份→删→对账（P6 收官段执行，见提交信息）。

## D-LDAP-1 ldap 层链收敛（#22，P1+P2 定稿 2026-09-20，待批）

### P1 规范矩阵（§4 八项→缺口）

**规范要求（RFC 4511 原文逐章反推，非现有用例总结）：**

| 规范点 | 出处 | 代码现状 | 缺口 |
|---|---|---|---|
| BER TLV：messageID INTEGER 最小字节编码（符号位补零） | §4.1.1 | berInt（ldap.go:130）实存 | 无 |
| BER 长度短形/长形（≤127 短形；>127 长形 0x81/0x82 前缀） | §4.1.1 | berWrap（:151）——15 属性 RootDSE searchRequest 走长形 | 无（pcap 钉） |
| protocolOp 应用标签 {bindReq 0x60, bindResp 0x61, unbind 0x42, searchReq 0x63, searchEntry 0x64, searchDone 0x65} | §4.2-4.5 | 常量全 + build* 全 | 无 |
| bindRequest：version(2/3)+name+simple [0] 认证 | §4.2.1 | buildBindRequest（:214），versionOf 缺省 3 | SASL bind=B′（RFC 4513 §5.2 另族） |
| searchRequest：baseObject+scope{0,1,2}+derefAliases+sizeLimit+timeLimit+typesOnly+Filter CHOICE+AttributeSelection | §4.5.1 | buildSearchRequest（:246）：scope/limit 可配；**derefAliases/typesOnly 恒定值** | deref/typesOnly 可配=B′（合成面语义弱） |
| Filter CHOICE：present [7] 0x87 / equality [3] 0xa3 | §4.5.1.7 | buildFilter（:231）双分支+filter_value | 其余 Filter 族（and/or/not/substr/ greaterOrEqual…7 种）=B′ |
| resultCode ENUMERATED 0-127（0 success/49 invalidCredentials） | §4.1.9 | ldapResult（:186）+Validate 上界锚 | 匹配码 10-16 全枚举=B′（值可透传） |
| messageID 递增：bind=base+3r / search=+1 / unbind=+2 | §4.1.1.1 | Plan 循环 rb/base+3r 编排 | 无 |
| unbind 无响应（单向） | §4.3 | buildUnbind+Unbind 指针三态缺省真 | 无 |
| 传输：TCP 389（IANA）+消息按段分段 | §5.2 | segmentByMSS（:441）+自建握手/挥手（rtsp 族） | 无 |

**三路对照：** ①规范=上表；②商业软件行为=AD 客户端 RootDSE 查询形（参考 pcap：15 属性 present filter objectclass、timeLimit 120、匿名 bind）——defaultAttributes（:53）逐名复刻；③开源实现思路=OpenLDAP ldapsearch 会话形 bind→search→entry→done→unbind 单连接有序消息——Plan 编排同构。
**候选方案：** (a) [ip,ldap] raw 自驱（radius D-RADIUS-1 对称：legacy 自建 TCP 握手原样 wrap，srv6 防双换模式）——零字节回归、最小分叉；(b) [ip,tcp,ldap] 事件面（tcp 层管握手，ldap 变 MessageEvents）——大改，legacy 自建 seq 编排需全拆。**裁定 (a)**：与 radius 对称口径，事件面=sip WP-D 先例 B′ 候选不立项（ldap 单连接消息面无 TLS 事件需求面，startTLS=B′ 注记）。

**门1 三行强制展开：**
- §1 顶层旧键：现存 1 例扁平 `src_ip/dst_ip/src_port/dst_port/count/ldap{}` 全删；目标形状 `{"layers":[{"ip":{"src","dst"}},{"ldap":{...15 键}}]}`+端口 389 语义住 ldap 层（FieldContract carrier dst_port 或 raw 0-keep 名单——**raw 分支 spec.SrcPort/DstPort 直传 legacy**，链上无 tcp 层故 0-keep+由生成器 spec 缺省 389？legacy Plan `if spec.DstPort == 0 { spec.DstPort = DefaultPort }` 实存 ✓ 0-keep+Plan 缺省自洽，validateBaseDstPortHandled += ldap）；
- §3 五件套：单流协议豁免声明（无子流派生、无 sessions，Transactions=单 TCP 连接内 rounds 消息序：bind→bindResp→search→entry→done ×rounds→unbind）；多流=worker 12345+i 端口面（FlowIndex）；
- §12 动态字段：四元组 worker 递增（12345+i）；业务字段动态面=attributes 列表/filter value（静态配置面，无 dyn 策略需求——LDAPConfig 无 dyn 旁挂，如实注记；MessageIDBase/rounds 静态）。序号算法=IPID randomIPID+ISN randomUint32（RFC 6528）/可 override（spec.TCP.InitialSeq）。

### 裁定（P2 定稿）

| # | 裁定 | 依据 |
|---|---|---|
| 1 | 层形状=[ip, ldap]：ldap CategoryTerminal+DependsOn `["ip"]`（radius 对称 registry 行）；raw 自驱=legacy Plan 原样 wrap（自建 TCP 握手/MSS 分段/挥手全保留） | radius D-RADIUS-1 对称；P1 候选 (a) |
| 2 | 翻转五件套：① isRawIPChain 名单 += ldap（双名单）② validateSpecBase src 0-keep += ldap ③ validateBaseDstPortHandled += ldap（Plan 内缺省 389 自洽）④ registry 行补 15 Fields+translate `case "ldap"` 复用 parseLDAPConfig（全 string/[]string，**JSON 往返安全但按 ParseLDAPConfigFromMap 单真相先例走导出包装**）+FlowMeta.LDAP carry+raw 分支注入 ⑤ main.go 翻转+空白导入 | pppoe 裁定 2 同构 |
| 3 | 端口语义：389 由 Plan 缺省（legacy :308 实存），层 config 无端口键（15 键无端口位）；测试用例显式 12345/389 走 spec（raw 分支 SrcPort/DstPort 注入已实存） | radius T 系先例 |
| 4 | 场景强度全额（9.46–9.53）：BER 面（长形长度钉+messageID 递增钉）/操作标签全表/bind 匿名 vs simple/scope 三枚举/filter 双 CHOICE/resultCode 49 失败分支/rounds 多轮/attributes 自定义/unbind 抑制/version 2/复合大场景（多轮+equality+非匿名+49+自定义属性 ≥3 类交织）；负例 7 锚（version/scope/filter_type/result_code/size_limit/time_limit/messageID 超限） | CORE_MEMORY 9.46–9.53 |
| 5 | B′ 注记账本：SASL bind、Filter 其余 7 CHOICE、derefAliases/typesOnly 可配、startTLS（tls 链组合候选）、modify/add/compare/abandon/extended 操作族、result 匹配码全枚举 | RFC 4511 要求面如实 |

**文件：** protocol/ldap/layer_gen.go（新，wrap legacy+防双换 Direction=up——注意 legacy emit 已带 L3/L4 与 MAC/EtherType，对齐 pppoe 模式）+core/layers/chain_planner_util.go+chain_planner.go（名单两处）+registry.go（行登记 15 Fields）+chain_planner_translate.go（case+carry）+generator.go（FlowMeta.LDAP）+strategy_convert.go（ParseLDAPConfigFromMap 导出）+cmd/server/main.go（翻转）+cases/ldap.json（改写+补强）。
**接口签名：** `ParseLDAPConfigFromMap(m map[string]interface{}) *LDAPConfig`（导出包装）；layer_gen 照 pppoe raw 模式（GenEvents nil stub，force-up 防双换，FlowIndex 透传）。
**性能（6.4-6.6）：** 流式 channel 256；包数=握手 3+Σrounds(2+分段子包)+unbind 段+挥手 4；无共享状态；pcap 验收路。
**回滚：** 单提交粒度；main.go 摘除空白导入即回 legacy；registry/名单行摘除即回。
**风险：** ldap 长形 BER 长度字节在多段 payload 下的 frames hex 断言偏移需 pcap 校准不手算；[ip,ldap] 0-keep 端口链路 SrcPort=0 时 worker 注入面（多流）与单流显式化的用例口径按 radius T 系对齐。

**P4 已实现+复审（2026-09-20，e4ada5d）：** 五件套全落（isRawIPChain 双名单/两处 0-keep/registry 15 Fields+双 schemagen/translate case+ParseLDAPConfigFromMap 导出+FlowMeta.LDAP+raw 分支注入/main.go 翻转）；ldap/layer_gen.go 新建（pppoe 防双换模式，FlowIndex 透传）；链级 2 例（rounds=2 18 包形状+六段 flags 序+每段 389+version=4 背 door 锚词）。**复审 1 轮对抗走查：registry 15 键类型面（int 0=缺省语义合法）/0-keep/raw 注入/translate 空层非 nil/防双换七项副作用（TTL/DSCP/Flags 全零值无副作用）/背 door 锚词逐查，0 新错（int 双形坑实施中被 mustJSONMap 口径拦）。**

**P5/P6 验收（2026-09-20）：** suite ×2 连续全绿 `RESULT: 22 pass, 0 fail, 0 error (of 22)`；BER 恒长形语义+messageID 帧序经 tshark 实测钉（详见 TEST_CASES P5 执行记录：bindReq SEQ 30 84 00 00 00 10/searchReq 0x158/unbind id 6）；coverage_gate check_ldap 43/43 绿（场景 22+键 15+锚 6）。
**门1 对照表回填（实际证据）：** §1 顶层旧键→cases 22 例零顶层四元组（pipe_gate 门2-1）+地址入 ip 层（ldap_session_full spec_json）；§3 单流豁免声明+rounds 消息序（T-11/T-14）；§12 动态字段=worker 12345+i 四元组面（包4 srcport=12345 实测钉）+IPID/ISN random（spec.TCP.InitialSeq 可 override，ldap.go randomUint32）。**门3 抽查三条：** ①裁定1 raw wrap→layer_gen.go Direction=up 防双换+T-1 包4-9 六标签 60/61/63/64/65/42 逐帧+TestChainPlanner_LDAPRawChain 18 包 flags 序；②裁定2 五件套→registry.go ldap 行 15 Fields+chain_planner_util.go isRawIPChain 双名单+T-1 frames BER 长形钉；③裁定3 端口语义→legacy Plan `if spec.DstPort == 0`（ldap.go:308）+validateBaseDstPortHandled "ldap" 行+链测试每段 389 断言。**9.53 复杂度抽查：** T-14 复合例=多轮(2)×equality filter×simple 认证×自定义属性 四类交织 ≥3 ✓。
**在库清库：** 删前报数→备份→删→对账（同日执行，见提交信息）。

## D-RTMP-1 rtmp 层链收敛（#23，P1+P2 定稿 2026-09-20，待批）

### P1 规范矩阵（Adobe RTMP spec 反推，非现有用例总结）

| 规范点 | 出处 | 代码现状 | 缺口 |
|---|---|---|---|
| 握手 C0/C1+S0/S1/S2+C2：版本 0x03；C1/S1=4B 时间+4B 零+1528B 随机；S2 回显 C1、C2 回显 S1 | Adobe RTMP spec §5.1-5.3 | buildC0C1/buildS0S1S2/buildC2（rtmp.go:422-476），分段按 MSS | 无 |
| chunk 基本头 fmt0：fmt(2b)+csid(6b)；消息头 11B=ts(3B)+len(3B)+type(1B)+streamID(4B 小端) | spec §6.1.1 | buildAMF0Chunk（:527）恒 type0 | 其他 fmt（1/2/3 省头）=B′ |
| 协议控制：Set Chunk Size(1)/Stream Begin(4)/Window Ack Size(5)/Set Peer Bandwidth(6) | spec §5.4-5.6 | buildServerResponse/buildWinAckSizePayload/buildSetBufferLength | 无 |
| AMF0 命令：connect(txn1+对象 app/tcUrl)/_result/createStream(txn2)/play/publish | spec §7.2/§8 | buildConnectAMF0/buildConnectResult/buildCreateStreamAMF0/buildPlayAMF0/buildPublishAMF0 | AMF3/其余命令（deleteStream/pause/seek）=B′ |
| CSID 分配：2 协议/3 命令/4 音频/6 视频 | 参考 pcap | 常量+使用 | 无 |
| 数据面：MsgType 8 音频/9 视频 chunk | spec §6.1/§11.4 | Data[]RTMPDataChunk 逐条 chunk | 无 |
| 传输：TCP 1935+自建握手/挥手/MSS 分段 | 参考 pcap | rtsp 族同款（segmentByMSS:720） | 无 |

**三路对照：** ①规范=上表；②商业行为=Adobe FMS/参考 pcap（llcj 镜像 play 会话：connect→窗口三件套→createStream→play）；③开源=librtmp 会话序同构（connect 事务→createStream→play）。**候选：** (a) [ip,rtmp] raw 自驱（ldap/radius 对称，legacy 自建 TCP wrap）；(b) [ip,tcp,rtmp] 事件面（大改不立项）。**裁定 (a)**。

**门1 三行：** §1 顶层旧键=1 例扁平全删，目标形 `{"layers":[{"ip":{"src","dst"}},{"rtmp":{"command":...,"data":[...]}}]}`+1935 由 Plan 缺省（raw 0-keep+validateBaseDstPortHandled）；§3 单流豁免（Transactions=单连接内握手→命令→数据序）；§12 动态=worker 四元组+IPID/ISN random（C1/S1 随机 1528B=crypto/rand，回显语义保证确定性关系）。

### 裁定（P2 定稿）

| # | 裁定 | 依据 |
|---|---|---|
| 1 | 层形状=[ip, rtmp]：CategoryTerminal+DependsOn `["ip"]`；raw 自驱 wrap legacy（自建 TCP/握手/分段原样保留），layer_gen 防双换 Direction=up | ldap D-LDAP-1 对称 |
| 2 | 翻转五件套：isRawIPChain 双名单+=rtmp；src 0-keep+=rtmp；validateBaseDstPortHandled+=rtmp（1935 Plan 缺省 :178 区段实存）；registry 行 5 Fields（app/tc_url/command/stream_name/data——data 子键随 list 项）+translate case 复用 ParseRTMPConfigFromMap 导出+FlowMeta.RTMP+raw 分支注入；main.go 翻转 | ldap 五件套同构 |
| 3 | 端口语义：1935 由 Plan 缺省（0-keep 自洽），测试显式 12345/1935 走 spec；恒 1935 断言面=tcp.dstport（worker srcport 陷阱） | ldap T 系先例 |
| 4 | 场景强度全额：握手回显面/chunk 头字节钉/AMF0 connect 钉/协议控制四消息/publish vs play/stream_name/app/数据面音视频双 MsgType/payload 显式/复合大场景（publish+app+音视频数据 ≥3 类）；负例 3 锚建例（App 超长/Command/MsgType）+MSS<536 链路径不可达=B′ 注记 | CORE_MEMORY 9.46–9.53 |
| 5 | B′ 账本：chunk fmt 1/2/3、AMF3、deleteStream/pause/seek、MSS<536 负例锚（无 tcp 层） | spec 要求面如实 |

**文件：** protocol/rtmp/layer_gen.go（新）+chain_planner_util.go+chain_planner.go（名单）+registry.go（行）+chain_planner_translate.go（case）+generator.go（FlowMeta.RTMP）+strategy_convert.go（ParseRTMPConfigFromMap）+cmd/server/main.go（翻转）+cases/rtmp.json（改写+补强）。
**回滚：** 单提交粒度，摘除空白导入/名单行/registry 行即回。

**P4 已实现+复审（2026-09-20，23305ac）：** 五件套全落（isRawIPChain 双名单/两处 0-keep/registry 5 Fields+双 schemagen/translate case+ParseRTMPConfigFromMap 导出（payload_b64 双形不走 JSON 往返）/FlowMeta.RTMP+raw 注入/main.go 翻转）；rtmp/layer_gen.go 新建（防双换模式）；链级 2 例（publish+音视频数据面形状+command=pause 背 door）。复审 1 轮：五件套接线点+防双换副作用逐查 0 新错。
**P5/P6 验收（2026-09-20）：** suite ×2 连续全绿 `RESULT: 16 pass, 0 fail, 0 error (of 16)`；分段序/connect chunk/AMF0 txn/流号小端 tshark 实测钉（详见 TEST_CASES P5 执行记录）；RTMP dissector 伪影按先例扩白名单族（服务端重编生效——suite 验证在 MCP 侧的机制注记）；coverage_gate check_rtmp 29/29 绿。
**门1 对照表回填（实际证据）：** §1 扁平键→cases 16 例零顶层四元组+地址入 ip 层；§3 单流豁免+命令序（T-1 20 包全序钉）；§12 动态=worker 四元组+C1/S1 crypto/rand（回显关系保证确定性）+IPID/ISN random。**门3 抽查三条：** ①裁定1 raw wrap→layer_gen.go 防双换+T-1 包 11-17 命令面帧序+TestChainPlanner_RTMPRawChain；②裁定2 五件套→registry rtmp 行 5 Fields+translate ParseRTMPConfigFromMap 单真相+T-11 payload_b64 双形例；③裁定3 端口语义→legacy Plan 1935 缺省+链测试每段 1935 断言+恒 1935 断言面=tcp.dstport。**9.53 复杂度抽查：** T-12 复合例=publish×自定义 app×流名×音视频双 chunk 四类交织 ≥3 ✓。
**在库清库：** 删前报数→备份→删→对账（见提交信息）。

## D-RTSP-1 rtsp 层链收敛（#24，P1+P2 定稿 2026-09-20，待批）

### P1 矩阵（RFC 2326 反推）：方法面（OPTIONS/DESCRIBE/SETUP/PLAY/PAUSE/TEARDOWN，RFC 2326 §10 逐节）+响应面（§7 status/status_text）+头补全（CSeq §12.3/Session §12.37/Transport §12.39 自动补）+SDP body（附录 C）+RTP 媒体子流（§2 rtp-info/AVP RFC 3550）+传输（§10 TCP 554，自建握手/挥手 rtsp 族）。实现全存（rtsp.go 974 行：renderRTSPMessage/completeRTSPHeaders/emitRTSPMedia）。缺口=B′：GET_PARAMETER/SET_PARAMETER 枚举面、嵌入式二进制 interleaved ($ 块)。
**三路对照：** 规范=§10 方法序；商业=VLC/ffplay play 会话形（OPTIONS 保活→DESCRIBE(SDP)→SETUP(Transport)→PLAY→TEARDOWN）；开源=live555 同构。**裁定 (a) [ip,rtsp] raw 自驱**（ldap/rtmp 对称）。
**门1 三行：** §1 扁平键全删，目标形 `{"layers":[{"ip":{...}},{"rtsp":{"dialog":[...]}}]}`+554 由 validateSpecBase DstPort switch 缺省（本轮新增 case "rtsp"→554，dns→53 同款——legacy 缺省住 mapToFlowSpec setDefaultDstPort，链路径等价承接）；§3 单流豁免（Transactions=dialog 消息序）；§12 动态=worker 四元组+IPID/ISN random。

### 裁定（P2 定稿）
| # | 裁定 | 依据 |
|---|---|---|
| 1 | 层形状=[ip, rtsp]：CategoryTerminal+DependsOn `["ip"]`；raw 自驱 wrap legacy | ldap/rtmp 对称 |
| 2 | 翻转五件套：isRawIPChain 双名单+=rtsp；src 0-keep+=rtsp；**DstPort switch += rtsp→554**（本轮新增，替代 validateBaseDstPortHandled 豁免——554 是协议级缺省非 0-keep）+validateBaseDstPortHandled+=rtsp；registry 行 2 Fields（dialog/media）+translate case 复用 ParseRTSPConfigFromMap 导出（镜像扁平 case 体）+FlowMeta.RTSP+raw 注入；main.go 翻转 | pppoe/rtmp 五件套同构+dns 端口缺省先例 |
| 3 | dialog 必需锚（空 dialog 拒）链上由 RegisterLayerValidator 背 door 承接（legacy Validate 同文案） | legacy Validate 实存 |
| 4 | 场景强度全额：方法序（OPTIONS 保活/DESCRIBE SDP/SETUP Session/PLAY/PAUSE/TEARDOWN）/响应码 200/404/头补全面/RTP 媒面子流/复合全方法形；负例=空 dialog | 9.46–9.53 |
| 5 | B′ 账本：GET_PARAMETER/SET_PARAMETER、interleaved $ 块、Record/ANNOUNCE/REDIRECT | RFC 2326 §10 要求面如实 |

**文件：** protocol/rtsp/layer_gen.go（新）+chain_planner_util.go+chain_planner.go（名单+DstPort switch）+registry.go（行）+chain_planner_translate.go（case）+generator.go（FlowMeta.RTSP）+strategy_convert.go（ParseRTSPConfigFromMap）+cmd/server/main.go（翻转）+cases/rtsp.json（改写+补强）。
**回滚：** 单提交粒度，摘除即回。

**P4 已实现+P5/P6 验收（2026-09-20，5cc20a0+收官提交）：** 五件套全落+DstPort switch rtsp→554；链级 2 例（四消息 11 包 554 面+空 dialog 背 door）；suite ×2 全绿 `RESULT: 12 pass, 0 fail, 0 error (of 12)`；coverage_gate check_rtsp 23/23 绿；**门3 抽查：①裁定2 DstPort switch→chain_planner.go case "rtsp"→554+T-1 包1 tcp.dstport=554；②裁定3 dialog 锚→RegisterLayerValidator+T-11 真实流程 400；③裁定1 raw wrap→layer_gen 防双换+T-2 五方法 17 包序**。9.53 复杂例=T-10 四类交织。在库清库见提交信息。复审 1 轮 0 新错（srcport 陷阱在用例侧重犯 2 例、包数笔算 1 例——全部用例侧，实现零 bug）。

### T-RTSP-1…12 清单（P3，RFC 2326 反推；9.52 对账 **16/16**：方法 6+响应 2+头补全 3+body 1+RTP 1+URI 2+负例 1+现网复合 1→建例 12+注记 4（GET_PARAMETER/SET_PARAMETER、interleaved、Record 族、MSS 锚链路径不可达））

| # | 用例 | 断言面 |
|---|---|---|
| T-1 | smoke 改写（OPTIONS 冒烟） | 9 包=握手3+req/resp+挥手4；恒 554=tcp.dstport |
| T-2 | play 会话全序 | OPTIONS/DESCRIBE/SETUP/PLAY/TEARDOWN 五方法+Session 头补全（现网形） |
| T-3 | DESCRIBE+SDP body | body 字节透传+Content-Length |
| T-4 | 404 响应面 | status_code 404+reason |
| T-5 | PAUSE/TEARDOWN 面 | 两方法请求/响应序 |
| T-6 | URI 显式+缺省构造 | method/uri 字节钉 |
| T-7 | 头显式覆盖 | headers 自定义（User-Agent 等）与自动补 CSeq 共存 |
| T-8 | RTP 媒面子流 | emit_media+media 配置→RTP 包序（复用 legacy 实测形） |
| T-9 | direction 显式 | up/down 覆盖推断 |
| T-10 | 复合大场景（9.50） | 全方法+emit_media+自定义头 ≥3 类交织 |
| T-11 | 负例空 dialog | 锚词 `dialog is required` |
| T-12 | 状态行缺省 text | status_text 空缺省 phrase（rtspReasonPhrase） |

## D-PPTP-1 pptp 层链收敛（#25，P1+P2 定稿 2026-09-20，待批）

### P1 规范矩阵（RFC 2637 反推，含三张子表要求 4.22）

| 规范点 | 出处 | 代码现状 | 缺口 |
|---|---|---|---|
| 控制连接：TCP 1723（§1.2）；控制消息头 8B（Length+Type+Magic 0x1a2b3c4d+ControlType） | §2 | controlHeader（planner.go:167）+15 消息类型常量 | 无 |
| 控制消息全表：SCCRQ/SCCRP/StopRQ/StopRP/ECRQ/ECRP/OCRQ/OCRP/ICRQ/ICRP/ICCN/CCRQ/CCDN/WEN/SLI（15 条，§2.1-2.16） | §2.1-2.16 | build* 全 15（:188-399），场景编排 full/control_only/tunnel_only/data_only | ICRQ/ICRP/ICCN= PAC 侧场景（incoming_call 键实存） |
| SCCRQ/SCCRP 字段：Protocol Version+Framing/Bearer Caps+Max Channels+Firmware+Host/Vendor Name（64B 定长） | §2.1/2.2 | buildSCCRQ/SCCRP+fixed64+Validate 64B 锚 | 无 |
| OCRQ/OCRP：Call ID/Serial+Min/Max BPS+Bearer/Framing Type+Window Size+Packet Delay+Phone/SubAddress | §2.4/2.5 | buildOCRQ/OCRP 全字段 | 无 |
| GRE 增强头：16B、flags 0x3081、proto 0x880B、Key=Len+peer Call ID、32bit Seq/Ack | §4.1 | PPP 数据面（包注释+pppFrame:893） | 无 |
| 数据面 PPP 帧：FF 03+0x0021+内嵌 IPv4 | §4.1 参考 | pppFrame+buildInnerIPv4Packet | 无 |
| 生命周期：SCCRQ/RP→OCRQ/RP→SLI→(数据)→CCRQ/CCDN→StopRQ/RP | §3.2.1-3.2.15 | full 场景编排（参考 pcap 逐字节） | 无 |
| 活性：ECRQ/ECRP Echo 保活 | §3.2.9-3.2.10 | buildECRQ/ECRP+echo 键 | 无 |

**①命令×响应矩阵：** SCCRQ→SCCRP/OCRQ→OCRP/ECRQ→ECRP/ICRQ→ICRP→ICCN/CCRQ→CCDN/StopRQ→StopRP 逐格已实现（15 消息 build 全存）；result/error 字段（scrp_result/ccdn_result/ocrp_result/stop_result 等）可配=失败分支面。
**②数据形态变体：** 定长 64B 字段（host/vendor name）、hex sub_address、inner_ip 嵌套配置（src/dst/proto/payload/ttl）、双数据方向（data_frames/down_data_frames）。
**③商业行为映射：** 参考 pcap（llcj 镜像 PNS 49194↔PAC 1723）逐字节复刻=③已映射（T-1 钉值）；MS Windows PPTP 客户端行为=Host Name "machine"+Vendor "Microsoft Windows NT"（实现缺省面，待确认方式=抓现网拨号包，B′ 注记）。
**三路对照：** ①RFC 2637 原文；②参考 pcap 形+MS 实现缺省注记；③Linux pptpclient（仓库思路借鉴：控制面+GRE 面单流编排）。**候选对比：** (a) [ip,pptp] raw 自驱 wrap（pppoe/ldap/rtmp/rtsp 对称，零字节回归）✓ vs (b) [ip,tcp,pptp]+[ip,gre] 双链事件面（控制/数据分链——GRE 数据面无独立生成器，大改）→裁定 (a)。
**门1 三行：** §1 扁平键全删，目标形 `{"layers":[{"ip":{...}},{"pptp":{"scenario":"full","calls":1,...}}]}`+1723 由 legacy Plan :404 缺省（validateBaseDstPortHandled 豁免，pppoe 模式）；§3 单流豁免注记——PPTP 会话=控制通道单 TCP 连接+GRE 数据面同流，calls>1=多 call 并发面（同流内多 call，非 sessions[] 形态）；§12 动态=worker 四元组+IPID/ISN random+call_id/call_serial 静态缺省面（无 dyn 旁挂，如实注记）。

### 裁定（P2 定稿）
| # | 裁定 | 依据 |
|---|---|---|
| 1 | 层形状=[ip, pptp]：CategoryTerminal+DependsOn `["ip"]`；raw 自驱 wrap legacy（自建 TCP+GRE 数据面原样保留），layer_gen 防双换 Direction=up | 四连协议对称 |
| 2 | 翻转五件套：isRawIPChain 双名单+=pptp；src 0-keep+=pptp；validateBaseDstPortHandled+=pptp（1723 Plan 缺省 :404）；registry 行 **51 Fields**（parsePPTPConfig 顶层键全集逐键登记，inner_ip=object 内嵌 srv6 先例）+translate case 复用 ParsePPTPConfigFromMap 导出+FlowMeta.PPTP+raw 注入；main.go 翻转 | pppoe 五件套同构 |
| 3 | 场景强度全额：15 消息面（full 场景逐消息+scenario 四枚举）/SLI 计数/calls 多 call/双数据方向/ECRQ 保活/result-error 失败分支字段/inner_ip 数据面/复合大场景（full+calls 2+echo+双数据 ≥3 类）；负例 7 锚（role/scenario/calls/sli_count/data_frames/down_data_frames/sub_address hex/64B 超长/inner IP） | 9.46–9.53 |
| 4 | B′ 账本：MS 客户端缺省 Host/Vendor 待确认、interleaved GRE over TCP（ uncontested）、ICRQ 族 PAC 侧现网形、动态字段旁挂 | RFC 2637+现网要求面如实 |

**文件：** protocol/pptp/layer_gen.go（新）+chain_planner_util.go+chain_planner.go（名单）+registry.go（51 Fields 行）+chain_planner_translate.go（case）+generator.go（FlowMeta.PPTP）+strategy_convert.go（ParsePPTPConfigFromMap）+cmd/server/main.go（翻转）+cases/pptp.json（改写+补强）。
**性能（6.4-6.6）：** 流式 channel 256；包数=场景编排段数（full 缺省实测 26=3 握手+4 控制+SLI×5+GRE×5+拆除段族；calls/SLI/data_frames 线性——T-7 calls2=31、T-8 SLI3=20、T-10 数据 3=24、T-13 复合=33 实测钉）；pcap 验收路（网卡路未跑注明 6.3）。
**回滚：** 单提交粒度，摘除即回。

**P4 已实现+复审（2026-09-20，8c941b0）：** 五件套全落（registry **51 Fields 实数复核**：parsePPTPConfig 顶层 50+data_frames=51，inner_ip=object 内嵌 7 子键）+layer_gen+链级 2 例。复审抓 1 断言口径错：GRE 数据面帧无 TCP 端口（IP proto 47），"每帧 1723"断言改为控制面帧限定——修正后链级净。
**P5 执行记录（2026-09-20）：** suite ×2 全绿 `RESULT: 20 pass, 0 fail, 0 error (of 20)`；实测钉：26 帧全序（3 握手+SCCRQ 156/SCCRP 156/OCRQ 168/OCRP 32+SLI×5+GRE×5+CCRQ/CCDN 合并 164/CCDN 148/StopRQ/RP+挥手 4）、控制头 12B（Length+MsgType 1+magic+ControlType）、GRE 头 30 81 88 0b。**P2 errata：tunnel_only=隧道建立+拆除无数据面（emitDataPlane 仅 full/data_only 触发 planner.go :665/:605——P1 矩阵初写"带数据面"错误已勘）**；首跑 4 红全用例侧（srcport 陷阱重犯/registry V9 锚词 2 例/data_only 断言面）。coverage_gate 见 P6。
**门3 抽查三条：** ①裁定2 51 Fields→registry.go pptp 行逐键+T-1 26 帧全序；②裁定3 负例锚→role 非法链级背 door+T-14…20 真实流程 400；③裁定1 raw wrap→layer_gen 防双换+T-2 控制头帧钉。9.53 复杂例=T-13 五类交织（多 call+echo+双数据+SLI+full 拆除）。在库清库见提交信息。

### T-PPTP-1…20 清单（P3，RFC 2637 反推；9.52 对账 **27/27**：控制头 1+控制消息 15+场景枚举 4+SLI/calls/echo 3+数据面 3+角色 1+失败分支 1+负例分支 7+现网 1 → 建例 20 代表（T-1 承接消息表 15 之 full 编排+现网形；T-3/4/5 承接场景枚举）+B′ 注记 7（MS 缺省待确认、interleaved GRE、ICRQ 族 PAC 现网形、动态旁挂、扩展 message、结果码全枚举、TCP 分段 GRE 边界））

| # | 用例 | 断言面 |
|---|---|---|
| T-1 | smoke 改写（full 22 包参考形） | 全生命周期逐段（SCCRQ 156B→SCCRP→OCRQ→OCRP→SLI×5→CCRQ/CCDN 合并→CCDN→StopRQ/RP） |
| T-2 | 控制头钉 | magic cookie 1a2b3c4d+Length+Type 字节 |
| T-3 | scenario=control_only | 控制面消息子集+包数 |
| T-4 | scenario=tunnel_only | 隧道建立+数据面（无控制拆除序） |
| T-5 | scenario=data_only | 纯 GRE 数据面 |
| T-6 | role=pac | PAC 侧换向（方向/Call ID 语义反转） |
| T-7 | calls=2 | 多 call 并发（OCRQ/OCRP 两轮+SLI 逐 call） |
| T-8 | sli_count=3 | SLI 条数钉（缺省 5 由 T-1 承接） |
| T-9 | echo=true | ECRQ/ECRP 保活对 |
| T-10 | 双数据方向 | data_frames+down_data_frames 逐帧 GRE 头钉 |
| T-11 | inner_ip 显式 | src/dst/proto/payload 字节透传 |
| T-12 | 失败分支字段 | scrp_result/ocrp_result 非 0 透传（错误码面） |
| T-13 | 复合大场景（9.50） | full+calls 2+echo+双数据+SLI ≥3 类交织 |
| T-14 | 负例 role 非法 | 锚词 `invalid pptp role` |
| T-15 | 负例 scenario 非法 | 锚词 `invalid pptp scenario` |
| T-16 | 负例 calls<0 | 锚词 `invalid pptp calls` |
| T-17 | 负例 sli_count<0 | 锚词 `invalid pptp sli_count` |
| T-18 | 负例 sub_address 非 hex | 锚词 `must be hex` |
| T-19 | 负例 64B 超长 | 锚词 `exceed 64 bytes` |
| T-20 | 负例 inner IP 非法 | 锚词 `invalid pptp inner src_ip` |

**P3 复审（2026-09-20 对抗走查）：** 15 消息面由 T-1 full 编排承接（SCCRQ/SCCRP/OCRQ/OCRP/SLI/CCRQ/CCDN/StopRQ/StopRP 9 消息逐包断言）+T-9 echo（ECRQ/ECRP）+T-6/T-7 角色与多 call（ICRQ/ICRP/ICCN 由 incoming_call 键 B′ 注记、T-6 承接 PAC 侧部分）；WEN（msg 14）无用例=WEN 键 B′ 注记（现网 WAN 错误事件低频，构建器实存 buildWEN）。对账 27/27 平。**清单净，待批进 P4。**

**P6 追加对抗复审（2026-09-20，用户指令"没复审就再复审一次"）：** 抓 2 实缺口已修：①T-3/4/5/6/7/9/12/13 八例包数"实测钉"占位未钉（9.31/14.6 校准义务未完成——跑过但实测值没写回断言）→pcap 逐一实测钉齐（21/16/4/21/31/23/21/33）+suite 复跑 ×2 全绿；②性能段"full≈22 包"P2 估值笔误与实测 26 不符→按实测修正。横扫项：registry↔parse 键集 51↔51 逐键零差、四名单齐、生成物同代（layers.generated/mcp 描述/config-schema 106 层/schema-types）、前四协议占位横扫零残留、负例 7 锚真实拦截面逐个核可达（role/scenario/sub_address/64B/inner IP=planner 锚；calls/sli_count=registry V9 先拦）。**复审结论：追加轮 2 实缺口+1 笔误全修，修正后 20/20 ×2 全绿，净。**

## D-VNC-1 vnc 层链收敛（#26，P1+P2 定稿 2026-09-20，待批）

### P1 规范矩阵（RFC 6143 RFB 反推，含三张子表要求 4.22）

| 规范点 | 出处 | 代码现状 | 缺口 |
|---|---|---|---|
| 传输载体：TCP 5900（范围 5900-5909），服务器先发言 | §1.1/§7.1 | DefaultPort=5900（vnc.go:27）+Plan :561 内部缺省；自建 TCP 握手/挥手 :718-723/:810-816 | 链路径翻转（main.go :565 legacy→ChainPlanner） |
| 版本协商：12B "RFB 003.008\n" 服务器→客户端双向 | §7.1 | versionString :54+交换 :726-727 | 无（raw wrap 零分叉继承） |
| 安全握手：secTypes=[count]+types；Tight(16) 附 TunnelCaps+AuthCaps+VNC-Auth 选择；VNC(2) challenge/response；None(1) 直通 | §7.2.1 | secTypesBytes :228+Tight 分支 :730-738；challenge/response 参考 pcap 字节+seed :617-624 | 无 |
| SecurityResult：u32；失败附 reasonLen+reason 且无 ServerInit 提前拆链 | §7.2.2 | buildSecurityResult :321+失败分支 :741-750 | 无 |
| ClientInit share flag / ServerInit（宽高+像素格式 16B+nameLen+name）/ Tight InteractionCaps | §7.3 | :752-761+buildServerInit :241+buildInteractionCaps :335 | 无 |
| 客户端消息：SetPixelFormat(00)/SetEncodings(02)/FBU-req(03)/KeyEvent(04)/PointerEvent(05)/ClientCutText(06) | §8 | build* :367-437+发射序 :764-777 | 无 |
| 服务器消息：FBU(00)/SetColourMapEntries(01)/Bell(02)/ServerCutText(03) | §9 | build* :441-476+extras 闭包 :781-805 | 无 |
| 编码：raw(0)/hextile(5)/xcursor(-240)；Tight zlib 不建模 | 附录/§7.4 | buildRect :480+hextileData :520+rawPixels 确定性填充 :508 | Tight zlib=B′ 注记（设计裁定） |
| 数据面编排：非增量全屏 FBU→initial FBU→rounds×(Pointer→fbuInterval×FBU)→增量 FBU | 参考 pcap 结构 | :773-808 | 无 |
| 方向换向：legacy Plan 包内置 Direction="down"，raw drive Emit 会二次换 L3 | — | — | **缺口：layer_gen.go 防双换（六连协议同款）** |
| 层链接线 | — | main.go :565 legacy Planner | **缺口：五件套+翻转+blank import** |
| 校验锚：security_type 枚举(1/2/16)/auth_result(0-2)/宽高(1-65535)/rounds≥1/pointer/fbu_interval/pixel bpp-depth/key u32/encoding 区间/rect 字段/colour hex | design §6 | Validate :119-198（13 锚族） | 无（validator 背 door 注册即达） |

**①命令×响应矩阵：** 版本 S→C→C echo / secTypes S→选择 C / [Tight]TunnelCaps+AuthCaps S→VNC-Auth 选择 C / challenge S→response C / SecurityResult S / ClientInit C→ServerInit(+Caps) S / 客户端 6 消息→FBU 应答逐格已实现；auth_result 1/2=失败分支面。
**②数据形态变体：** 像素格式 10 字段嵌套、InteractionCaps 4+记录嵌套、rect 7 键（含 hextile_tile_data/xcursor_blob hex 原文）、encodings 含负值伪编码、seed 双 u64。
**③商业行为映射：** 参考 pcap（TightVNC "QTMS:1 (ykaul)" 1024×768 32bpp）握手 13 消息逐字节复刻=③已映射（T-1/T-2 钉值）；真 Tight zlib 流=不建模（B′ 注记：DES 响应为确定性伪随机非真密文、参考 pcap garbage padding 不复刻）。
**三路对照：** ①RFC 6143 原文；②参考 pcap 形+TightVNC 行为注记；③TigerVNC/ltsp 开源思路（RFB 状态机单连接编排）。**候选对比：** (a) [ip,vnc] raw 自驱 wrap（五连协议对称，零字节回归）✓ vs (b) [ip,tcp,vnc] 事件面（需 TCP 传输层 server-first 事件化改造，大改）→裁定 (a)。
**门1 三行：** §1 扁平键全删（src_ip/dst_ip/src_port/dst_port/count+顶层 vnc 子映射），目标形 `{"layers":[{"ip":{"src":"10.0.0.1","dst":"20.0.0.1"}},{"vnc":{"initial_fbu":[...],"update_rects":[...],"rounds":1}}]}`+5900 由 legacy Plan :561 缺省（0-keep+validateBaseDstPortHandled 豁免，pptp 模式）；§3 单流豁免——VNC=单 TCP 连接会话（无 sessions/子流派生），Transactions=单连接内消息序（13 握手消息→客户端消息→FBU 循环→拆链），五件套=会话表(1 连接)/事务序(如上)/关联(无)/插入位置(n/a)/时间线(顺序)；§12 动态=worker 四元组+IPID/ISN random，业务键全静态单值（无 dyn 旁挂，challenge_seed/response_seed=静态种子如实注记），_flow_index 不消费。

### 裁定（P2 定稿）
| # | 裁定 | 依据 |
|---|---|---|
| 1 | 层形状=[ip, vnc]：CategoryTerminal+DependsOn `["ip"]`；raw 自驱 wrap legacy（自建 TCP 握手/挥手+RFB 全消息面原样保留），layer_gen 防双换 Direction=up | 五连协议对称 |
| 2 | 翻转五件套：isRawIPChain 双名单+=vnc；src 0-keep+=vnc；validateBaseDstPortHandled+=vnc（5900 Plan :561 缺省，不加 DstPort switch，pptp 同款）；registry 行 **26 Fields**（parseVNCConfig 顶层键全集逐键登记：19 标量+pixel_format/interaction_caps/set_colour_map_entries=object+key_events/encodings/initial_fbu/update_rects=list；security_type/challenge_seed/response_seed 无范围——枚举锚与负值列 V9 不误伤）+translate case 复用 ParseVNCConfigFromMap 导出+FlowMeta.VNC+raw 注入；main.go 翻转 | pppoe 五件套同构 |
| 3 | 场景强度全额：13 握手消息面（版本/secTypes/Tunnel/Auth caps/VNC-Auth 选择/challenge/response/SecurityResult/ClientInit/ServerInit/InteractionCaps）/安全路径三枚举（16/2/1）/认证失败分支/客户端 6 消息/服务器 4 消息/编码三形（raw 确定性像素/hextile/xcursor）/rounds×fbuInterval 线性/extras 交织；负例 4 锚（security_type 枚举/auth_result V9 区间/width 显式 0/rect encoding 枚举） | 9.46–9.53 |
| 4 | B′ 账本：Tight zlib 数据面不建模（§7.4 设计裁定）、auth response=确定性伪随机非真 DES、参考 pcap garbage padding 不复刻、5901 参考端口（参考 pcap 抓自 5901，配置面用缺省 5900） | RFC 6143+设计裁定如实 |

**文件：** protocol/vnc/layer_gen.go（新）+chain_planner_util.go+chain_planner.go（名单）+registry.go（26 Fields 行）+chain_planner_translate.go（case）+generator.go（FlowMeta.VNC）+strategy_convert.go（ParseVNCConfigFromMap）+cmd/server/main.go（翻转）+cases/vnc.json（改写+补强）+vnc_chain_test.go（新）。
**性能（6.4-6.6）：** 流式 channel 256；包数=13 握手消息段+客户端消息+2 FBU+rounds×fbuInterval 编排+4 拆链——缺省 initial_fbu 全屏 hextile 1024×768≈3072 tiles≈3.1MB→MSS 分段 ~2190 帧（T-1 冒烟形小矩形 33 帧实测钉，P5 校准）；pcap 验收路（网卡路未跑注明 6.3）。
**回滚：** 单提交粒度，摘除即回。

### T-VNC-1…21 清单（P3，RFC 6143 反推；9.52 对账 **27/27**：版本协商 1+安全路径 3+认证失败 1+init 面 2+客户端消息 6+服务器消息 4+编码 3+编排 2+端口 1+现网 1+负例 4 → 建例 21 代表（T-1 承接握手 13 消息+现网形+端口；T-2 钉字节；T-18…21 承接 ServerInit/encodings/pointer 显式/caps/seed 定制面——追加轮 2 逐键扫补）+B′ 注记 4（Tight zlib 不建模、DES 伪随机、garbage padding、参考 5901））

| # | 用例 | 断言面 |
|---|---|---|
| T-1 | smoke 改写（33 帧参考形） | 全生命周期逐段（3 握手+版本×2+secTypes+选择+caps+auth+result+init+客户端消息+FBU 循环+拆链 4）+5900 端口 |
| T-2 | 握手字节钉 | 版本 "RFB 003.008\n" 12B+secTypes `02 02 10`+TunnelCaps 00000000+AuthCaps 记录 |
| T-3 | security_type=2 | VNC Auth 路径（无 Tunnel/AuthCaps/无 InteractionCaps，challenge/response 16B） |
| T-4 | security_type=1 | None 路径（secTypes `01 01`，无 challenge，直通 init） |
| T-5 | auth_result=1 失败分支 | reason 串透传+无 ServerInit+提前拆链（4 帧终止） |
| T-6 | share_desktop=false | ClientInit 0x00 |
| T-7 | raw 编码矩形 | rawPixels 确定性 (n*13+1..4) 像素钉 |
| T-8 | key_events 显式 | key down 帧字节钉（tshark 不出 key_down 字段）+键值 0x0000ffe9 |
| T-9 | extras 交织 | Bell 02+ServerCutText 03+ClientCutText 06 三消息 |
| T-10 | set_colour_map_entries | 01 消息（first/num/6B 项） |
| T-11 | 客户端消息关 | client_set_pixel_format/encodings=false 缺省面 |
| T-12 | rounds=2+fbu_interval=2 | 编排线性（Pointer→FBU×2 两轮） |
| T-13 | pointer 坐标 | 507/320 缺省+button 字节钉 |
| T-14 | 负例 security_type=7 | 锚词 `invalid vnc security type`（planner 锚，V9 无范围不先拦） |
| T-15 | 负例 auth_result=3 | 锚词 `out of range [0,2]`（V9 区间先拦） |
| T-16 | 负例 rect encoding 非法 | 锚词 `invalid vnc rect encoding` |
| T-17 | 负例 width=0 | 锚词 `invalid vnc width`（V9 显式 0 放行→planner 锚） |
| T-18 | ServerInit 定制 | server_name/width/height/pixel_format 逐字节钉（宽 0140/高 00f0/pf 16B bpp16/nameLen+SRV-X） |
| T-19 | encodings+pointer 显式 | SetEncodings（3 项含 xcursor 负值）+PointerEvent（button 1/x 100/y 200）字节钉 |
| T-20 | interaction_caps 定制 | 头 0/2/0/pad+2 记录 40B 钉（nServer=0：tshark 记录数=三计数和） |
| T-21 | challenge/response seed | seed=1 确定性 16B 钉（同种子同字节，异于参考字节） |

**P3 复审（2026-09-20 对抗走查）：** 13 握手消息由 T-1 full 编排承接（逐包断言）+T-2 字节钉；客户端 6 消息=T-1（PixelFormat/Encodings/FBU-req×2/KeyEvent 缺省形）+T-8（KeyEvent 显形）+T-9（CutText 双向）+T-13（Pointer）；服务器 4 消息=T-1（FBU）+T-9（Bell/ServerCutText）+T-10（ColourMap）；安全路径三枚举=T-1（16）+T-3（2）+T-4（1）+T-5（失败分支）；编码三形=T-1（hextile/xcursor）+T-7（raw）；负例 4 锚拦截点逐一核（V9 显式 0 放行→width/rounds 落 planner；auth_result 区间 V9 先拦；security_type/rect encoding 无 V9 范围→planner）。InteractionCaps 11 记录=T-1 ServerInit 段承接（184B）。对账 27/27 平。**清单净，待批进 P4。**

**P4 已实现+复审（2026-09-20，284aaf4）：** 五件套全落（registry **26 Fields 实数复核**：parseVNCConfig 顶层 19 标量+3 object+4 list=26，逐键零差）+layer_gen 防双换+链级 2 例。复审抓 1 收敛点：parseVNCConfig errs 通道（encodings 列表非数值项）链面不外露——链路径无 ValidationErrors 消费点（translate :1901 注记 schema 层先拦），姊妹协议 wrapper 同单值形，B′ 账本注记残差（扁平面仍大声失败）。
**P5 执行记录（2026-09-20）：** suite 首跑 14/17（3 红全用例侧手估错：T-3 包数 33→实测 29、T-4 30→实测 27——两例都漏数 InteractionCaps 缺席、T-8 键值笔误 65265=0xFEE9≠0xFFE9=65513）→修正后 **17/17 ×2 全绿**。实测钉：T-1 33 帧全序（3 握手+版本×2+secTypes 02 02 10+选择+TunnelCaps 00000000+AuthCaps+VNC-Auth 选择+challenge/response 参考字节+result+ClientInit+ServerInit+InteractionCaps 11 记录+SP/SE+KeyEvent×6+FBU-req+initial FBU 2 矩形+Pointer 05 00 01 fb 01 40+FBU+增量 req+拆链 4）、T-5 认证失败 17 帧（result 帧 u32(1)+len+"denied" 逐字节）、T-7 raw 像素确定性 01 02 03 04/0e 0f 10 11。coverage_gate 见 P6。**教训：帧字节钉前先对自身配置键值做十六进制复算（0xffe9=65513 非 65265）。**
**P6 评审与提交（2026-09-20）：** 测试四问全过（T-1 测对路径=链 translate→validator→raw wrap 全链；真触发=MCP 建任务真流程；断言输出=字段+帧字节双面；规范覆盖=9.52 对账 27/27）。反查表 check_vnc **33/33 绿**。在库清库：strategies 4+tasks 81 删前报数→备份 trafficgen-vnc-purge-20260920.db→删→复核 0/0（总量 strategies 702/tasks 240595）。schemagen 三件套同代（107 层）。门3 抽查三条：①裁定2 26 Fields→registry vnc 行逐键+T-1 33 帧全序；②裁定3 负例锚→T-14…17 真实流程 400（planner/V9 拦截面各得其位）；③裁定1 raw wrap→layer_gen 防双换+T-2 握手字节钉。9.53 复杂例=T-9 五面交织（Bell+ServerCutText+ClientCutText+initial FBU+round FBU）。

**P6 追加对抗复审（2026-09-20，用户指令"没复审就再复审一次"）：** 抓 1 实缺口已修：①P3 复审声称"InteractionCaps 11 记录=T-1 ServerInit 段承接"实为**无任何断言**（T-1/T-2 均未钉 f16）→T-2 补钉 f16 头 16B（nServer 0/nClient 11/nEnc 0/pad+首记录 code 2 RRE STDV，tshark 实测）+challenge/response 钉扩全 16B，复跑 17/17 ×2 全绿。横扫项：registry↔parse 26↔26 逐键零差、四名单齐（util×2/chain_planner×2）、生成物同代（layers.generated 107 层 vnc 26 键/config-schema 计数行/schema-types/mcp 描述——终端层不单列=pptp 同形 by design）、包数 17 例全钉零占位、负例 4 锚拦截面核（T-15 V9 区间、T-14/16/17 planner——T-17 显式 0 过 V9 落 planner 与 P3 复审口径一致）、性能段 33 帧已实测（2190 帧缺省全屏保持 ≈ 估值标注）。**复审结论：追加轮 1 实缺口补钉，修正后 17/17 ×2 全绿，净。**

**P6 追加对抗复审·第 2 轮（2026-09-20，用户指令"没复审就再复审一次"）：** 本轮换角度=**registry 26 键逐键反扫 suite 发送面**，抓 1 大缺口：10 键 suite 从未发过（server_name/width/height/pixel_format/interaction_caps/encodings/pointer_x/y/button/challenge_seed/response_seed——前轮 T-list 只覆盖缺省形与部分显式形，违反 9.46 全表扫）→补 T-18…21 四复合例（每例多键交织：ServerInit 定制/encodings+pointer 显式/caps 定制/seed），全部 tshark 实测钉字节；T-20 顺带抓 tshark 形状约束（InteractionCaps 记录数=nServer+nClient+nEnc，nServer=1 无记录=Malformed Packet→改 0）；T-21 钉值证实同种子双 seed 产生同 16B（seededBytes 独立调用同输入）。修正后 suite **21/21 ×2 全绿**、反查 **48/48**（33→48：+例 4+键 11）、门2 四项复绿、全仓 vet 净+`go test ./internal/...` 122 包全绿。**复审结论：第 2 轮抓 1 大缺口（10 键零覆盖）+1 形状约束，补 4 例后全绿，净。**

## D-XMPP-1 xmpp 层链收敛（#27，P1+P2 定稿 2026-09-20，待批）

### P1 规范矩阵（RFC 6120 XMPP Core + RFC 6121 XMPP IM 反推，含三张子表要求 4.22）

| 规范点 | 出处 | 代码现状 | 缺口 |
|---|---|---|---|
| 传输载体：TCP 5222（client-to-server） | RFC 6120 §13.3 | DefaultPort=5222（xmpp.go:50）；**缺省住 flat setDefaultDstPort（:945），Plan 内无缺省** | **缺口：链路径 DstPort switch 承接 5222（rtsp 式，pptp 不同——legacy 无内部缺省）** |
| 流开启：`<stream:stream to=...>` 客户端先行，服务器回流头+features | §4.2 | buildStreamOpen :488+buildStreamFeatures :503 | 无 |
| features 面：STARTTLS/SASL 机制表/压缩/roster 版本 | §5.3.2 参考形 | featuresResp 一次性编码 | 无（字节面钉 T-1/T-2） |
| SASL 认证四机制：PLAIN(RFC 4616 单轮)/DIGEST-MD5(RFC 2831 四步)/SCRAM-SHA-1(RFC 5802 六步)/ANONYMOUS(RFC 4505 单轮) | §6 | switch mech :309-381，四分支全实现；Validate 枚举锚 :122-126 | 无 |
| 流重启：SASL 成功后客户端必须重开流 | §4.3.3.2 | streamRestart :386+postAuthFeatures :390 | 无 |
| 资源绑定：iq set/bind → iq result/jid | §7 | buildBindRequest :600/buildBindResult :609 | 无 |
| 会话建立：iq set/session → iq result | RFC 3921 §3（XEP-0045 遗产） | buildSessionRequest :619/Result :628 | 无 |
| Presence：初始存在状态，可关 | RFC 6121 §4.2 | *bool 三态 :410-417 | 无 |
| Messages：message 节双向（up/down） | RFC 6121 §5.2 | buildMessageStanza :636+方向循环 :420-446 | 无 |
| 流关闭：客户端 </stream:stream>，服务器回 | §4.4 | :450-455 | 无 |
| 方向换向：legacy 包内置 Direction="down"，raw drive 二次换 | — | — | **缺口：layer_gen 防双换（七连协议同款）** |
| 层链接线 | — | main.go :582 legacy Planner | **缺口：五件套+翻转+blank import** |
| 校验锚：auth 机制枚举（4 值）/message direction 枚举/MSS 下界 | design | Validate :99-144（3 锚族） | 无（validator 背 door 注册即达） |

**①命令×响应矩阵：** 流开→features/auth→success（或 challenge→response→…→success ×4 机制）/重启→postAuth features/bind req→result/sess req→result/presence 单向/message 双向/流关→回——逐格已实现；失败分支=SASL failure 未建模（参考 pcap 全为 invalid-authzid 失败会话，trafficgen 只出 happy path=B′ 注记）。
**②数据形态变体：** 机制四枚举×消息步数（2/4/6/2）、PLAIN base64（\0user\0pass）、messages 方向双值、jid/resource/stream_id/from 字符串定制面。
**③商业行为映射：** 参考 pcap（llcj dport=5222，SCRAM-SHA-1 失败会话）特性=流头/features 机制表/SCRAM 步序已映射（T-3 钉）；现网主流 ejabberd/prosody 行为=未逐项抓包（B′ 注记：确认方式=抓真实客户端登录包）；STARTTLS 与压缩（zlib）未建模=设计裁定 B′ 注记。
**三路对照：** ①RFC 6120/6121 原文；②参考 pcap 形+失败路径注记；③ejabberd/prosody 开源思路（流状态机单连接编排）。**候选对比：** (a) [ip,xmpp] raw 自驱 wrap（六连协议对称，零字节回归）✓ vs (b) [ip,tcp,xmpp] 事件面（XML 流需 TCP 传输层事件化，大改）→裁定 (a)。
**门1 三行：** §1 扁平键全删（src_ip/dst_ip/src_port/dst_port/count+顶层 xmpp 子映射），目标形 `{"layers":[{"ip":{"src":"10.0.0.1","dst":"20.0.0.1"}},{"xmpp":{"auth_mechanism":"PLAIN","messages":[{"direction":"down","to":"a@b.c","body":"hi"}]}}]}`+5222 由链路径 DstPort switch 缺省（legacy 缺省住 flat :945，Plan 无内部缺省——**必须 switch 承接**）；§3 单流豁免——XMPP=单 TCP 连接 XML 流会话（无 sessions/子流），Transactions=流内消息序（10 阶段见包注释），五件套=会话表(1 连接)/事务序(10 阶段)/关联(无)/插入位置(n/a)/时间线(顺序)；§12 动态=worker 四元组（src_port 自动递增=worker.go resolveLayerTuple/worker 分配面）+ISN random（xmpp.go:668 randUint32，RFC 6528），业务键全静态单值（username/password/jid 等=静态缺省面如实注记，无 dyn 旁挂）。

### 裁定（P2 定稿）
| # | 裁定 | 依据 |
|---|---|---|
| 1 | 层形状=[ip, xmpp]：CategoryTerminal+DependsOn `["ip"]`；raw 自驱 wrap legacy（自建 TCP+10 阶段全消息面零分叉），layer_gen 防双换 Direction=up | 六连协议对称 |
| 2 | 翻转五件套：isRawIPChain 双名单+=xmpp；src 0-keep+=xmpp；validateBaseDstPortHandled+=xmpp **且 DstPort switch+=case "xmpp": 5222**（与 pptp 唯一差异：legacy Plan 无内部缺省，switch 必须承接，rtsp 式）；registry 行 **9 Fields**（parseXmppConfig 顶层 9 键逐键：7 标量+presence bool+messages list 记录 3 键）+translate case 复用 ParseXmppConfigFromMap 导出+FlowMeta.Xmpp+raw 注入；main.go 翻转 | pppoe 五件套同构+rtsp 端口式 |
| 3 | 场景强度全额：10 阶段消息面（流开/features/SASL 四机制枚举各一例/重启/bind/session/presence/messages 双向/流关）/定制面（from/jid/resource/stream_id/username/password）/presence 三态关断；负例 2 锚（auth_mechanism 枚举/message direction 枚举） | 9.46–9.53 |
| 4 | B′ 账本：SASL 失败路径不建模（参考 pcap 全失败会话 vs trafficgen happy path——行为差异如实）、STARTTLS/压缩未建模（确认方式=抓现网）、SCRAM 内容为固定示例串非真算法输出、**XEP-0199 IQ ping 长保活未建模**（追加轮4 隔离复审立项：3.15 长保活项，需求来源=现网 XMPP 服务器空闲踢除面，确认方式=抓 ejabberd 空闲会话包；建模面=IQ get/result 事务对+空闲间隔编排）、normalizeAuthMech ToUpper 接受任意大小写（SASL 机制名 RFC 4422 区分大小写——legacy 宽松行为如实，不做行为变更） | RFC 6120+参考 pcap 如实 |

**文件：** protocol/xmpp/layer_gen.go（新）+chain_planner_util.go+chain_planner.go（名单+DstPort switch）+registry.go（9 Fields 行）+chain_planner_translate.go（case）+generator.go（FlowMeta.Xmpp）+strategy_convert.go（ParseXmppConfigFromMap）+cmd/server/main.go（翻转）+cases/xmpp.json（改写+补强）+xmpp_chain_test.go（新）。
**性能（6.4-6.6）：** 流式 channel 256；包数=19 帧基线（3 握手+13 数据+3 拆链），SASL 机制线性（PLAIN 19/DIGEST-MD5 21/SCRAM-SHA-1 23/ANONYMOUS 19），messages 每条+1；pcap 验收路（网卡路未跑注明 6.3，估值待 P5 实测钉）。
**回滚：** 单提交粒度，摘除即回。

### T-XMPP-1…11 清单（P3，RFC 6120 反推；9.52 对账 **19/19**（追加轮4 +超长分段 1）：流开启 1+features 1+SASL 枚举 4+重启 1+bind 1+session 1+presence 1+messages 双向 1+流关 1+端口 1+现网 1+定制面 3+负例 2 → 建例 10 代表（T-1 承接 10 阶段全序+现网形+端口；T-2…4 承接 SASL 四枚举；T-11 承接超长分段）+B′ 注记 4（SASL 失败路径、STARTTLS、压缩、SCRAM 内容））

| # | 用例 | 断言面 |
|---|---|---|
| T-1 | smoke 改写（PLAIN 19 帧参考形） | 10 阶段全序（3 握手+流开+features+auth+success+重启+postAuth+bind×2+sess×2+presence+流关×2+3 拆链）+5222 端口 |
| T-2 | auth_mechanism=DIGEST-MD5 | 四步质询应答（auth→challenge→response→success+rspauth）21 帧 |
| T-3 | auth_mechanism=SCRAM-SHA-1 | 六步交换（参考 pcap 同机制）23 帧 |
| T-4 | auth_mechanism=ANONYMOUS | 匿名单轮（buildAuthAnonymous 字节钉）19 帧 |
| T-5 | presence=false | presence 缺席 18 帧 |
| T-6 | messages 双向 | up/down message 节（to/body 透传字节钉） |
| T-7 | from/jid/resource/stream_id 定制 | 流头 to=+bind jid+流 id 字节钉 |
| T-8 | username/password 定制 | PLAIN base64(\0u\0p) 字节钉 |
| T-9 | 负例 auth_mechanism=NTLM | 锚词 `unsupported auth mechanism` |
| T-10 | 负例 message direction=left | 锚词 `invalid direction` |
| T-11 | 长 body 超 MSS 分段（追加轮4） | 3000 字符 body→3 段（1460+1460+146）22 帧+首段前缀钉 |

**P3 复审（2026-09-20 对抗走查）：** 10 阶段由 T-1 全序承接（逐帧断言）；SASL 四枚举=T-1（PLAIN）+T-2/3/4（各一例，9.21 分支级代表）；presence 三态=T-1（true）+T-5（false）；messages 双向=T-6（up+down 各一）；定制面=T-7/T-8（7 个字符串键全覆盖）；负例 2 锚拦截点=planner Validate（auth 枚举 :122-126 无 registry 范围、direction 枚举 :136-141——registry messages 记录不下探，两锚都落 planner）；端口 5222=T-1 dstport 字段。9.50 复合例=T-6（messages 双向+presence 开+全阶段）。对账 18/18 平。**清单净，待批进 P4。**

**P4 已实现+复审（2026-09-20，ef2352e）：** 五件套全落（registry **9 Fields 实数复核**：parseXmppConfig 顶层 9↔9 逐键零差）+layer_gen 防双换+链级 2 例+**DstPort switch 5222**（xmpp 与 pptp 唯一差异：legacy Plan 无内部缺省，缺省住 flat setDefaultDstPort :944——链路径必须 switch 承接，链级红例断言 validated.DstPort==5222 锁住）。touched 包 -race 绿。
**P5 执行记录（2026-09-20）：** suite 首跑 2/10（8 红全用例侧：PROV 占位 6 例+流关闭帧 malformed 白名单只匹配旧例 id 精确值）→①verify.go isMalformedWhitelisted 泛化 `strings.HasPrefix(caseID,"xmpp_")`（'</stream:stream>' 字节合法语义合法、dissector 必报 Closing an unopened tag——服务端重编重启生效）；②全部包数手算一次全中（19/21/23/19/18/21/19/19——SASL 机制线性差 PLAIN+0/DIGEST+2/SCRAM+4）无需修正；③字节实测钉（T-4 ANONYMOUS 元素/T-6 双向 message 节/T-7 流头 to='chat.x.cn'+bind resource bot7/T-8 base64(\0ops\0s3cret)=AG9wcwBzM2NyZXQ=）→**10/10 ×2 全绿**。
**P6 评审与提交（2026-09-20）：** 测试四问全过（链 translate→validator→raw wrap 全链/MCP 建任务真流程/字段+帧字节双面/9.52 对账 18/18）。反查表 check_xmpp **22/22 绿**（例 10+键 9+锚 3）。门2 四项绿（门2-1 顶层零残留/门2-2 RESULT 已贴/门2-3 同代/门2-4 22/22）。在库清库：strategies 3+tasks 77 删前报数→备份 trafficgen-xmpp-purge-20260920.db→删→复核 0/0（总量 strategies 699/tasks 240518）。门3 抽查三条：①裁定2 9 Fields→registry xmpp 行逐键+T-1 19 帧全序；②裁定3 负例锚→T-9/T-10 真实流程 400（两锚全落 planner Validate）；③裁定1 raw wrap+端口特例→layer_gen 防双换+DstPort switch 5222+链测试断言 validated.DstPort。9.53 复杂例=T-3（SCRAM 六步=参考 pcap 同机制+10 阶段全序交织）。

**P6 追加对抗复审（2026-09-20，两轮一次做完）：** 第 1 轮断言面：抓 1 实缺口——**T-1 沿用旧例 min_packets=16，实测 19 帧未钉**（pptp 追加轮同类：跑过但断言松）→改 packet_count 19+补 f4 缺省流头钉；T-2/T-3/T-5 只有包数无字节断言→实测补钉（T-2 四步：auth 枚举面/challenge 载荷/success+rspauth 载荷；T-3 六步：auth/空 challenge 参考 pcap 同形/success+verification；T-5 f14 位置证明 presence 缺席）；第 2 轮逐键反扫：registry 9 键 suite 发送面全覆（from/jid/resource/stream_id=T-7、auth=T-2/3/4、username/password=T-8、presence=T-5、messages 含记录 3 子键=T-6）零缺口。修正后 **10/10 ×2 全绿**、反查 22/22、门2 四项复绿。**复审结论：追加轮 1 实缺口（T-1 断言松）+3 例字节断言补强，两轮后净。**

**P6 追加对抗复审·第 3 轮（2026-09-21，用户指令"没复审就再复审一次"）：** 本轮角度=**断言值 vs 配置值逐键核对（键发过≠值被钉过，9.43 摆设断言面）**，抓 2 实缺口：①T-7 的 stream_id/jid **值**从未被断言——f4/f10 钉的是流头 to= 与 bind resource，stream_id 只出现在 f5 回流头 id='ff11ee22'、jid 只出现在 f11 bind result `<jid>ops@chat.x.cn/bot7</jid>`→实测补钉 f5/f11 两帧；②normalizeAuthMech ToUpper 接受任意大小写机制名（legacy 唯一测试只测规范大写形，SASL 机制名按 RFC 4422 区分大小写）——legacy 宽松行为如实 B′ 注记，不做行为变更。横扫项：全 `go test ./internal/...` 三轮=122 包绿，期间抓 2 既有 flaky（TestChainPlanner_SNMP_GetResponse/TestGOOSEDataMemberBitStringEncoding——不同包跨轮随机现形、单跑 ×5 全过、与本协议无关的既有随机钉，如实记账）；pipe_gate.sh 二进制路径加 TG_SERVER_BIN 环境变量覆盖（每协议显式传参 papercut）。修正后 **10/10 ×2 全绿**、反查 22/22、门2 复绿。**复审结论：第 3 轮抓 2 值断言缺口+2 既有 flaky 记账，T-7 补钉后净。**

**P6 追加对抗复审·第 4 轮（2026-09-21，用户指令复审改隔离 subagent 执行——首个隔离轮）：** 隔离复审员（零共享上下文）独立通读 CORE_MEMORY 248 条+实跑 suite/反查/门2/-race/生成表过期测试+tshark 抽 6 帧逐字节比对——判定门全过、无 CRITICAL/HIGH，抓 1 中 2 低三缺口全修：①**中（9.43/14.17）T-6 direction 值未钉**（stanza 字节不含方向，唯一 e2e 可观察=L3 侧别——raw 链防双换回归 suite 不会红）→f15/f16 补 ip.src 双向钉；②低（3.15）XEP-0199 IQ ping 长保活无例无项→B′ 立项（裁定4 账本+确认方式）；③低（9.46 超长）segmentByMSS 分段路径零覆盖→**T-11 新例**（3000 字符 body→3 段 1460+1460+146=22 帧实测钉+首段前缀钉）。备忘 5 项同轮处理：T-1 补缺省凭据钉（AHVzZXIAcGFzcw==）、门1 §12 行补 file:line、:944→:945 行号勘误、presence 显式 true 与 nil 同路 n/a、pipe_gate 门2-1 黑名单制 vs 1.13 白名单=repo 级旧账立项注记（非本协议引入）。修正后 **11/11 ×2 全绿**、反查 23/23。**复审结论：隔离轮 1 中 2 低全修+备忘 5 项处理，净。**
## D-SCTP-1 sctp 层链收敛（#28，P1+P2 定稿 2026-09-21，待批）

### P1 规范矩阵（RFC 4960 SCTP 反推，含三张子表要求 4.22）

| 规范点 | 出处 | 代码现状 | 缺口 |
|---|---|---|---|
| 传输载体：IP proto 132，SCTP 自成 L4（公共头含 src/dst 端口+VerificationTag），无 TCP 握手 | §3.1 | core.ProtocolSCTP+emit :225-248（verTag 复用 L4.Ack 槽）；端口=spec.SrcPort/DstPort | **缺口：端口无层可住（1.12 立项）——sctp 层补 src_port/dst_port 字段+translate 回填** |
| 4 路握手：INIT(VTag=0)→INIT-ACK(带 Cookie)→COOKIE-ECHO(回 Cookie)→COOKIE-ACK | §5.1 | :270-294，cookie 32B 随机；双 VTag 0=随机非零 | 无 |
| DATA 块：TSN/SID/SSN/PPID+用户载荷；双向 | §3.3.1 | buildDATAChunkWithFlags :567+方向循环 :318-380 | 无 |
| 分片：FragmentSize 拆分，B/E/middle flags+TSN 递增 | §3.3.1 | splitDATAChunk :593+flags :76-78；Validate 下界 16 | 无 |
| SACK：gap blocks+dup TSN | §3.3.4 | buildSACKChunk :689（builder 面，无编排触发=用例面注记） | SACK 编排无用例=B′（builder 已实测） |
| HEARTBEAT/HEARTBEAT-ACK：主路径或备用路径 | §3.5.1 | emitSCTPHeartbeats :751+Heartbeats.Count | 无 |
| 多宿主：AltPath 备用 4 元组子流+INIT 携带 IPv4 Address 参数(type 5)+同地址族约束 | §6/C5+§3.3.2.1 | AltPath :261-269+Validate 同族锚 :129-155 | 无 |
| 关闭：3 路 SHUTDOWN/ACK/COMPLETE 或 ABORT 突断 | §9.2/§9.1 | :391-421（Abort 替代非叠加） | 无 |
| ERROR 块：9 种 cause code | §3.3.10 | buildERRORChunk :718（builder 面） | ERROR 编排无用例=B′ |
| 校验和：SCTP 校验和算法 | 附录 B | 引擎 L3/SCTP 输出面承接（sctp_test 钉） | 无 |
| 方向换向：legacy 包内置 Direction="down"，raw drive 二次换 | — | — | **缺口：layer_gen 防双换（八连协议同款）** |
| 层链接线 | — | main.go :546 legacy Planner | **缺口：五件套+翻转+blank import（具名转空导入）** |
| 校验锚：AltPath IP 合法性/IPv6 拒/同族拒/FragmentSize 下界 | design | Validate :102-166（4 锚族） | 无（validator 背 door 注册即达） |

**①命令×响应矩阵：** INIT→INIT-ACK/COOKIE-ECHO→COOKIE-ACK/HEARTBEAT→HEARTBEAT-ACK/SHUTDOWN→SHUTDOWN-ACK→SHUTDOWN-COMPLETE/DATA→(SACK 未自动编排)/ABORT 单向——逐格已实现；SACK/ERROR=builder 实存无编排（B′）。
**②数据形态变体：** chunk data 双形（string/字节数组，扁平 parse :5864-5874 承接）、分片三 flags 形、TSN 显式起点 vs 自增、AltPath 4 键嵌套、VTag/InitiateTag 显式 vs 随机。
**③商业行为映射：** 无参考 pcap（9 tasks 在库为现网需求面：NGAP 38412/M3UA 2905 端口特征）；Linux kernel SCTP（lksctp）行为=开源思路参照；三路中"商业软件行为"一路=用户现网任务特征反推（9 tasks 在库），如实注记。
**三路对照：** ①RFC 4960 原文；②在库 9 tasks 端口/载荷特征（现网需求面）；③lksctp 工具集思路（4 握手+心跳+多宿主编排）。**候选对比：** (a) [ip,sctp] raw 自驱 wrap（七连协议对称，legacy 全消息面零分叉）✓ vs (b) [ip] 单层+sctp 作 L4 框架层改造（框架级大改）→裁定 (a)。
**门1 三行：** §1 扁平键全删（src_ip/dst_ip/src_port/dst_port/count+顶层 sctp 子映射），目标形 `{"layers":[{"ip":{"src":"10.0.0.1","dst":"20.0.0.1"}},{"sctp":{"dst_port":38412,"chunks":[{"direction":"down","ppid":60,"data":"payload"}]}}]}`+**端口住 sctp 层（src_port/dst_port 字段，1.12 立项补位；translate 回填 spec；无协议级缺省——flat 口径不静默改 80，链路径 0 合法（validateBaseDstPortHandled 豁免），用例一律显式）**；§3 单流豁免——SCTP=单关联（association，同 4 元组单 TSN 空间），AltPath 心跳=同 GroupID 子流（多宿主，唯一真子流面！），五件套=会话表(1 关联+可选 alt 子流)/事务序(4 握手→心跳→DATA→关闭)/关联(AltPath 子流独立 4 元组同 GroupID)/插入位置(心跳在 COOKIE-ACK 后首 DATA 前)/时间线(顺序)；§12 动态=worker 四元组+TSN/VTag random（sctp.go :200-220 rand 非 0），业务键全静态单值（chunks[].tsn 显式起点=静态钉，如实注记无 dyn 旁挂）。

### 裁定（P2 定稿）
| # | 裁定 | 依据 |
|---|---|---|
| 1 | 层形状=[ip, sctp]：CategoryTerminal+DependsOn `["ip"]`；raw 自驱 wrap legacy（4 握手/DATA/分片/心跳/多宿主/双关闭全保留），layer_gen 防双换 Direction=up | 七连协议对称 |
| 2 | 翻转五件套：isRawIPChain 双名单+=sctp；src 0-keep+=sctp；validateBaseDstPortHandled+=sctp（无协议级缺省，flat 同口径不静默改 80）；**registry 行 8 Fields**（parse 6 键+**src_port/dst_port uint16 补位**——1.12：端口无层可住必须立项，translate 回填 spec.SrcPort/DstPort=非零显式才覆盖框架缺面）+translate case 复用 ParseSCTPConfigFromMap 导出+FlowMeta.SCTP+raw 注入；main.go 具名导入转翻转 | pppoe 五件套+1.12 立项 |
| 3 | 场景强度全额：4 握手字节/DATA 双向（TSN/SID/SSN/PPID 钉）/分片三 flags/心跳主路径/多宿主 AltPath 子流/ABORT 突断/显式 TSN 起点；负例 2 锚（AltPath IPv6/同族拒、FragmentSize<16）——全落 planner Validate（V9 不下探嵌套） | 9.46–9.53 |
| 4 | B′ 账本：SACK/ERROR builder 实存无编排用例（builder 面已有 legacy 单测钉）、无参考 pcap（在库 9 tasks=现网需求面反推）、端口无协议级缺省（用户必显式）、多宿主子流计数与父流同 pcap 落盘、**chunks.file_source/alt_path.alt_src_mac/alt_dst_mac/chunks.data 字节数组形 case 零覆盖**（legacy 单测钉，隔离复审 F3 补登）、**SID 多流化（RFC 4960 §5.3 多流独立 SSN）零 case**（legacy SSN 独立性单测钉，隔离复审 F4 补登）、layerDynAllowlist/checkLayerChainStaticCopy 名单无 sctp（前者诚实拒绝、后者被 ip 层标量兜底遮蔽——12.9 仍拦，隔离复审 F5 探针实证） | RFC 4960 如实 |

**文件：** protocol/sctp/layer_gen.go（新）+chain_planner_util.go+chain_planner.go（名单）+registry.go（8 Fields 行）+chain_planner_translate.go（case+端口回填）+generator.go（FlowMeta.SCTP）+strategy_convert.go（ParseSCTPConfigFromMap）+cmd/server/main.go（翻转）+cases/sctp.json（新建）+sctp_chain_test.go（新）。
**性能（6.4-6.6）：** 流式 channel 256；包数=4 握手+DATA（分片线性）+心跳 2×对+3 关闭（ABORT 1）；基线 7 帧实测钉待 P5；pcap 验收路（网卡路未跑注明 6.3）。
**回滚：** 单提交粒度，摘除即回。

### T-SCTP-1…10 清单（P3，RFC 4960 反推；9.52 对账 **20/20**：公共头/端口 1+4 握手 1+DATA 面 2（双向+四标识）+分片 1+心跳 2（主路径+多宿主）+关闭 2（SHUTDOWN/ABORT）+TSN 语义 1+现网端口 1+负例 2 → 建例 10 代表（T-1 基线关联；T-2 握手字节）+B′ 4（SACK/ERROR 编排、无参考 pcap、端口显式、多宿主同 pcap））

| # | 用例 | 断言面 |
|---|---|---|
| T-1 | 基线关联（4 握手+3 关闭） | 7 帧+chunk_type 序 1/2/10/11/7/8/14+端口面 |
| T-2 | 4 握手字节钉 | INIT VTag=0/INIT-ACK Cookie 随机非空/COOKIE-ECHO 回同 Cookie/COOKIE-ACK |
| T-3 | DATA 双向 | chunks up+down（TSN 自增双空间/SID/SSN/PPID/data 字节钉） |
| T-4 | 分片（fragment_size=16） | 100B→7 段 B/middle×5/E flags+TSN 连续 |
| T-5 | HEARTBEAT 主路径 | count=2→4 帧（HEARTBEAT/ACK 对）插在 COOKIE-ACK 后 |
| T-6 | AltPath 多宿主 | 备用 4 元组子流落同 pcap+INIT 携带 IPv4 Address 参数 |
| T-7 | ABORT 突断 | abort=true→5 帧（4 握手+ABORT，无 SHUTDOWN 族） |
| T-8 | 显式 TSN/SID 钉 | ch.tsn=100 起点逐段递增 |
| T-9 | 负例 AltPath IPv6 | 锚词 `only IPv4 multi-homing` |
| T-10 | 负例 fragment_size=1 | 锚词 `below minimum` |

**P3 复审（2026-09-21 对抗走查）：** chunk_type 全枚举面=DATA(0)/INIT(1)/INIT_ACK(2)/SACK(3)/HB(4)/HB_ACK(5)/ABORT(6)/SHUTDOWN(7)/SHUTDOWN_ACK(8)/ERROR(9)/COOKIE_ECHO(10)/COOKIE_ACK(11)/SHUTDOWN_COMPLETE(14) 13 型中编排可达 10 型（SACK/ERROR=B′），T-1 钉 7 型+T-5 钉 HB 对+T-3 DATA；分片三 flags=T-4 全三形（B/middle/E）；双向=T-3；AltPath 同族锚=T-9（IPv6 拒）+Validate 同族分支（负例 2 锚=T-9/T-10，全落 planner Validate：嵌套对象 V9 不下探、fragment_size 显式 0 过 V9 落 planner）。9.50 复合例=T-6（多宿主子流+心跳+握手全序）。对账 20/20 平。**清单净，待批进 P4。**

**P4 已实现+复审（2026-09-21，fce6f41）：** 五件套全落（registry **8 Fields 实数复核**：parse 6 键+src_port/dst_port 补位）+layer_gen 防双换+链级 2 例。**1.12 立项补位**：SCTP 自成 L4（proto 132），端口无层可住→sctp 层 src_port/dst_port 字段+translate 回填 spec（tcp/udp 回填循环只认 tcp/udp 层名，sctp 需独立回填分支）；无协议级缺省（flat 同口径不静默改 80）。ParseSCTPConfigFromMap=universal 段读取等价形（SCTP 无 switch case，:517 读取）。touched 包 -race 绿。
**P5 执行记录（2026-09-21）：** suite 首跑 3/10（7 红全用例侧：PROV 占位+**PPID 60(NGAP)/端口 38412 触发 tshark 启发式 dissector 对任意载荷误报 Malformed**）→端口切中性 5000+PPID 换非启发值（现网 PPID 语义注记入 P1 矩阵）；包数手算一次全中（7/7/9/14/11/9/5/8）；T-2 补显式双 Tag（逐键反查抓 verification_tag/initiate_tag 零覆盖——vnc 第 2 轮教训生效）→VTag 公共头（offset 38）逐帧可钉（INIT=0/INIT-ACK 用 client Tag/COOKIE-ECHO 用 server Tag）；SCTP chunk 起点 offset 46（eth14+ip20+公共头 12，非 TCP 的 54）；cookie 32B 每轮随机=回显一致性静态钉不可为（legacy 单测钉+设计注记）→**10/10 ×2 全绿**。
**P6 评审与提交（2026-09-21）：** 测试四问全过（链 translate→端口回填→validator→raw wrap 全链/MCP 真流程/字段+帧字节双面/9.52 对账 20/20）。反查表 check_sctp **20/20 绿**（例 10+键 8+锚 2）。门2 四项绿。在库清库：strategies 1+tasks 9 删前报数→备份 trafficgen-sctp-purge-20260921.db→删→复核 0/0（总量 strategies 698/tasks 240509）。门3 抽查三条：①裁定2 8 Fields→registry sctp 行逐键+T-8 DATA 20B 全头钉；②裁定3 负例锚→T-9（planner Validate 嵌套锚）+T-10（V9 区间先拦——P3 复审核准拦截点生效）真实流程 400；③裁定1 raw wrap+端口补位→layer_gen 防双换+translate 回填+链测试断言 validated.DstPort==38412。9.50 复杂例=T-6（多宿主子流+心跳+握手全序）。

**P6 追加对抗复审（2026-09-21，隔离 subagent 执行——sctp 收官轮）：** 隔离复审员独立实跑全套验证+tshark 双帧复核+go test -overlay 探针，判**不净**，抓 2 实 findings+3 注记，全部处置：①**高（1.4/1.7/1.13）顶层 sctp 子映射混用不拦且静默赢层链**——CheckProtoFlat 19 presence 分支独缺 raw 自驱八协议（探针实证 {"layers":[ip,sctp],"sctp":{"abort":true}} 零错过校验、顶层 abort 静默生效）→**CheckProtoFlat 补 8 协议 presence 判死**（rawWrapChains 表）+TestProtoFlat_TopRawWrapSubConfigRejected 8 子测+pipe_gate presence 名单+8（七个姊妹协议 pppoe/ldap/rtmp/rtsp/pptp/vnc/xmpp 同洞同修）；②**中（5.6/9.5）"cookie 回显一致性由 legacy 单测钉"声明失实**（全库无此断言）→sctp_cookie_echo_test.go 补平凡断言（COOKIE-ECHO[4:36]==INIT-ACK[24:56]+参数头 0007/0024 钉），四处文档声明恢复为真；③F3/F4 B′ 补登（file_source/alt MAC/data 字节数组形、SID 多流化）④F5 注记（dyn/staticCopy 名单）。复验：sctp 10/10 ×2 全绿+vnc 21/21 无误伤抽查（presence 判死不误伤纯层链）+touched 包 -race 绿。**复审结论：隔离轮抓 1 高 1 中 3 注记全处置，净。隔离复审模式价值再次实证：主线程四轮未见的混搭缝被零上下文复审员一枪命中。**完整报告送达后补最后一条注记：9.46 上界负例缺（T-10 只测下界）→**T-11 fragment_size=1000001 上界负例**（同 V9 拦截点 out of range [16,1000000]），11/11 全绿+反查 21/21。

## D-JT808-1 jt808 层链收敛（#29，P1+P2 定稿 2026-09-21，待批）

### P1 规范矩阵（JT/T 808-2011/2013/2019 反推，含三张子表要求 4.22）

| 规范点 | 出处 | 代码现状 | 缺口 |
|---|---|---|---|
| 传输载体：TCP 长连接，3 次握手+3 次挥手包络，消息 0x7e 定界 | §5.3/设计 §10.5 | PlanWithConfig :171-380（3 握手→消息序→3 挥手；channel 256） | 无 |
| 帧结构：0x7e + 消息头(12/16B) + 体 + XOR 校验和 + **转义**(0x7e→0x7d02, 0x7d→0x7d01) + 0x7e | §5.4 | buildHeader :17/buildFrame :36（XORChecksum+Escape 后再定界，顺序正确） | 无 |
| 消息头：msgId(2B)+props(2B)+终端手机号 BCD(6B)+流水号(2B)[+分包 4B]；版本位 props bit10-12（2011=000/2013=001/2019=010）、加密 bit15、分包 bit14、体长 bit0-9 上界 1023 | §5.4/jtcommon :29-38,207 | EncodeMsgBodyProps/ParseVersionFlag/buildFragmentedFrames :287（bit14 强制+pkgNum/pkgTotal 重算 props） | 无 |
| 13 型消息面：0x0100 注册/0x0102 鉴权/0x0200 位置上报/0x0201 位置查询应答/0x0003 注销/0x0107 终端属性/0x0001 终端通用应答/0x8001 平台通用应答/0x8100 注册应答/0x8103 设置参数/0x8104 查询参数/0x8201 查询位置/0x8300 文本下发 | §7 全族 | emitProcedure jt808.go :400-497 全 13 型 dispatch；builder 13 个 body 构造 | 无（全编排可达） |
| 双流水号空间：终端上行 msgSN 与平台下行 platformMsgSN 独立计数、各自递增 | 设计 §6A.2 | :218-221 两计数器独立递增 | 无 |
| 自动绑定：0x8001 绑最近上行/0x0001 绑最近下行/0x0201 应答绑最近 0x8201/0x8100 绑最近 0x0100 | 设计 §5A M-05 | emitProcedure respSN=0 时回绑 :409-471 | 无 |
| 位置体 28B 固定面+附加信息 TLV+状态位合并（ACC/门/油路/运行 *bool OR 并入 StatusFlag） | §7.4.1/设计 §5A H-05 | buildLocationBody + 位合并 types.go | 无 |
| GBK 编码面：车牌/文本/鉴权码 GBK 落线 | §7 | builder GBK 编码（jtcommon.XORChecksumGBK 面） | 无 |
| 校验锚：手机号 ^\d{12}$/版本枚举/encrypt≤1/车牌色枚举+车牌互斥/鉴权码必备（ProcAuth）/方向<360/经纬度上界/ACKFlag≤3/注册结果≤4 | ValidateConfig :61-149 | 全部落 ValidateConfig（protocol 包独立校验器） | 无（validator 背 door 注册即达） |
| 加密：encrypt_flag=1 为占位，不做真加密 | 设计 §14 | props bit15 置位、体明文 | 如实注记 B′（无真加密=设计裁定） |
| legacy Plan 入口 | — | **Plan 直接报错**（:155 "Plan not supported, use PlanWithConfig"）——曾致任务 0 包静默完成，已改硬错 | **缺口：layer_gen 唯一入口=PlanWithConfig（非 Plan），九连协议首例** |
| 方向换向：legacy 包内置 Direction="down"，raw drive 二次换 | — | — | **缺口：layer_gen 防双换（八连协议同款）** |
| 层链接线 | — | main.go :589 legacy `jt808.NewPlanner()`+具名导入 :83 | **缺口：五件套+翻转+具名转空导入** |
| 配置类型归属 | — | JT808Config 族全在 protocol/jt808/types.go（302 行，core 零接线：FlowSpec/FlowMeta/parse/registry 全无） | **缺口：类型迁 core/types.go（vnc/xmpp 先例：core 独占类型），protocol 包 alias 保 888 行测试零改动** |

**①命令×响应矩阵：** 注册→注册应答/鉴权(→通用应答可选)/位置上报→(平台 0x8001)/查询位置→位置查询应答/文本下发→(终端 0x0001)/设置参数→(0x0001)/查询参数→(0x0001)/注销→(0x0001)/属性应答/通用应答族——13 型 dispatch 逐格已实现。
**②数据形态变体：** 版本三方言（props 版本位）、分包体（bit14+pkgNum/pkgTotal+体长重算）、*bool 位合并 vs StatusFlag 直设（直设优先，OR 并入）、ResponseSN=0 自动绑定 vs 显式、RegistrationResult/AuthCode/IMEI/SoftwareVersion 过程级覆盖 vs 顶层、ExtraItems TLV 长度自动补算、Params TLV、注册体三段 pad 规则（厂商 0x00 填充/型号 0x20 填充/终端 ID 0x00 填充）。
**③商业行为映射：** 无参考 pcap（在库 9 tasks=现网需求面：车载终端注册-鉴权-位置上报主链）；部标interpreted 实现思路（JT/T 808 开源测试工具集）=开源思路参照；三路中"商业软件行为"一路=在库 9 tasks 特征反推，如实注记。
**三路对照：** ①JT/T 808-2019 原文（含 2011/2013 方言位）；②在库 9 tasks 现网需求面；③开源部标测试工具思路（注册/鉴权/位置主链+分包+转义）。**候选对比：** (a) [ip, jt808] raw 自驱 wrap PlanWithConfig（八连协议对称，legacy 全消息面零分叉）✓ vs (b) 事件面重写（13 型逐消息事件化，工作量爆炸且分叉）→裁定 (a)。
**门1 三行：** §1 扁平键全删（src_ip/dst_ip/src_port/dst_port/count+顶层 jt808 子映射——CheckProtoFlat rawWrapChains 第 9 协议），目标形 `{"layers":[{"ip":{"src":"10.0.0.1","dst":"20.0.0.1"}},{"jt808":{"phone":"012345678901","version":"2019","initial_sn":0,"procedures":[{"type":"register"},{"type":"auth"},{"type":"location_report","location_data":{"latitude":39900000,"longitude":116390000,"speed":600,"direction":90,"time":"260921120000"}}]}}]}`+**端口=legacy 内部缺省 7611（vnc/pptp 变体：PlanWithConfig :166 spec.DstPort==0 内补，无 DstPort switch case、无协议层端口字段——缺省即真相零代码增量，链路径 0 合法（validateBaseDstPortHandled 豁免），用例断言面按 7611 钉）**；§3 单流豁免——JT808=单 TCP 连接会话（终端↔平台），无子流派生、无独立数据流（分包子帧同连接），五件套=会话表(1 TCP 连接)/事务序(procedures 数组顺序=消息线序)/关联(分包子帧同连接同 SN 递增)/插入位置(handshake 后 teardown 前)/时间线(顺序)；§12 动态=worker 四元组+ISN（serverSeq 随机、clientSeq 走 spec.TCP.InitialSeq=0 随机），业务键全静态单值（phone/procedures 全显式，如实注记无 dyn 旁挂——layerDynAllowlist 无 jt808）。

### 裁定（P2 定稿）
| # | 裁定 | 依据 |
|---|---|---|
| 1 | 层形状=[ip, jt808]：CategoryTerminal+DependsOn `["ip"]`；**layer_gen 唯一入口=PlanWithConfig**（legacy Plan 硬错——九连首例，防 0 包静默回归）；防双换 Direction=up | 八连协议对称+Plan 硬错事实 |
| 2 | 配置类型迁 core：JT808Config/JT808Procedure/JT808Location/JT808Extra/JT808Param/JT808Property 六结构（含 json tags）迁 core/types.go+FlowSpec.JT808 字段；protocol/jt808/types.go 结构定义改 `type X = core.X` **别名**（constants/DefaultJT808Config/DefaultPort 留 protocol 包——core parse 全 string/数值直传不需常量，core 不 import protocol 铁律）；888 行 legacy 测试零改动 | vnc/xmpp 先例（core 独占类型）+最小 diff |
| 3 | 翻转五件套：isRawIPChain 双名单+=jt808；src 0-keep+=jt808；validateBaseDstPortHandled+=jt808（内部缺省 7611，vnc 变体无 switch case）；**registry 行 18 Fields**（phone/version/encrypt_flag/license_color/license_plate/province_id/city_id/manufacturer_id/terminal_model/terminal_id/terminal_type/initial_sn/platform_initial_sn/auth_code/imei/software_version/registration_result 17 标量+procedures list；范围只设在 ValidateConfig 真校验键：encrypt_flag 0-1/license_color 0-9/registration_result 0-4/uint16 族 0-65535，phone/plate 等 string 不设——V9 不下探 procedures 嵌套，嵌套负例锚=ValidateConfig）+translate case 复用 ParseJT808ConfigFromMap 导出+FlowMeta.JT808+raw 注入；CheckProtoFlat rawWrapChains 第 9 协议+pipe_gate presence 名单+9；main.go :589 具名导入转翻转+空导入 | pppoe 五件套+八连对称 |
| 4 | 场景强度全额：13 型全枚举编排（T-1/T-3/T-5/T-7/T-9 合盖 13/13）、双 SN 空间独立递增钉、4 自动绑定逐格钉、escape 转义真字节（TLV value 含 0x7e/0x7d→7d02/7d01 帧变长钉）、分包（>1023 体 bit14+pkgNum/pkgTotal）、GBK 车牌/文本字节钉、版本方言 2011 位钉（2019 缺省覆盖于 T-1，2013 同机制 B′ 注记）、注册体三段 pad 规则；负例 4 锚全落 ValidateConfig（phone 11 位/auth 无鉴权码/车牌色 0+车牌非空/ACKFlag=99）——嵌套与顶层统一锚点=planner 校验器 | 9.46–9.53 |
| 5 | B′ 账本：无参考 pcap（在库 9 tasks=现网需求面反推）、encrypt_flag=1 无真加密（设计 §14 裁定，bit15 置位体明文）、terminal_type 0-2 语义校验缺（ValidateConfig 不查、registry 不设范围——诚实注记）、2013 方言位同机制不单列（单 bit 差，T-4 钉 2011+T-1 钉 2019 缺省双端点）、suite 无 JT/T808 tshark dissector→原始 TCP payload hex 偏移钉（sctp 同款）、layerDynAllowlist/checkLayerChainStaticCopy 无 jt808（前者诚实拒绝、后者 ip 标量兜底——sctp 隔离复审 F5 同款探针注记） | 如实 |

**文件：** core/types.go（六结构迁入+FlowSpec.JT808）+protocol/jt808/types.go（别名化）+protocol/jt808/layer_gen.go（新）+core/layers/{chain_planner_util.go,chain_planner.go（名单）,registry.go（18 Fields 行）,chain_planner_translate.go（case）,generator.go（FlowMeta.JT808）}+strategy_convert.go（ParseJT808ConfigFromMap+rawWrapChains+=jt808）+cmd/server/main.go（翻转）+cases/jt808.json（新建）+jt808_chain_test.go（新）+tools/{pipe_gate.sh,coverage_gate.py}。
**性能（6.4-6.6）：** 流式 channel 256；包数=3 握手+N 消息（分包线性）+3 挥手；T-1 基线 10 帧实测钉待 P5；pcap 验收路（网卡路未跑注明 6.3）。
**回滚：** 单提交粒度，摘除即回。

### T-JT808-1…16 清单（P3 定稿 14 例，P5 追加 T-15 身份面复合例，隔离复审 F4 追加 T-16 心跳例；9.52 对账（F3 勘误后可复算）：帧包络 1+帧头字节 1+双 SN 1+自动绑定 1+注册体 1+位置体 1+版本方言 1+down 面 1+GBK 文本 1+属性体 1+分包 1+心跳 1+身份面 1+负例 4 = **分项和 17**，T-1 一例承载 2 项（帧包络+msgId 序基线）→ **建例 16**）

| # | 用例 | 断言面 |
|---|---|---|
| T-1 | 基线关联（register→registration_response→auth→platform_general_response） | 10 帧=3 握手+4 消息+3 挥手；msgId 序 0100/8100/0102/8001；方向序 up/down/up/down |
| T-2 | 帧头字节钉 | 0x7e 首尾；msgId/props/phone BCD/SN 偏移钉；XOR 校验和复算；0x2019 版本位缺省 |
| T-3 | 双 SN 空间+4 自动绑定 | initial_sn=100/platform_initial_sn=200 独立递增；0x8201→0x0201 回绑 querySN/0x8300→0x0001 回绑 downSN/0x8100 绑 lastRegisterSN/0x8001 绑 lastSentSN |
| T-4 | 注册体字段钉 | province/city BE；厂商 5B 0x00 填充/型号 20B 0x20 填充/终端 ID 7B 0x00 填充；车牌色 1+GBK 车牌尾缀 |
| T-5 | 位置上报+位合并+TLV 转义 | 28B 固定面钉；ACC=true OR 并入 status bit0；extra TLV value 含 0x7e/0x7d→7d02/7d01 转义帧变长钉 |
| T-6 | 版本方言+加密位 | version="2011"→props 版本位 000；encrypt_flag=1→bit15 |
| T-7 | down 面 TLV（set_params/query_params/cancel） | 0x8103 参数 TLV 体钉；0x8104/0x0003 空体 |
| T-8 | 文本下发 GBK | 中文→GBK 字节钉；text_flag 位 |
| T-9 | 终端属性应答 | 0x0107 全字段体钉（17 字段形） |
| T-10 | 分包 | set_params 大 value→体>1023：props bit14=1+pkgNum/pkgTotal 递增+体长=分片长 |
| T-11 | 负例 phone 11 位 | 锚词 `must be 12 digits` |
| T-12 | 负例 auth 无鉴权码 | 锚词 `AuthCode is empty` |
| T-13 | 负例 车牌色 0+车牌非空 | 锚词 `LicenseColor=0 but LicensePlate non-empty` |
| T-14 | 负例 ACKFlag=99 | 锚词 `ACKFlag 99 invalid` |

**P3 复审（2026-09-21 对抗走查）：** 13 型覆盖核对：T-1（register/auth/registration_response/platform_general_response=4 型）+T-3（query_location/location_query_response/terminal_general_response/text_down=4 型）+T-7（set_params/query_params/cancel=3 型）+T-9（property_response=1 型）+T-5（location_report=1 型）=**13/13 全枚举**。数据形态变体：分包=T-10、位合并=T-5（ACC *bool）vs StatusFlag 直设优先注记（不单列——直设路径与 OR 合并同 builder 分支，legacy 单测钉+T-5 钉合并路径）、TLV 自动长度=T-5/T-10、pad 三规则=T-4、GBK=T-4/T-8、版本方言=T-4 2019 缺省/T-6 2011、自动绑定 4 格=T-3 逐格。负例 4 锚全落 ValidateConfig（嵌套 procedures V9 不下探→ACKFlag 锚点=planner，登记点核准确）。9.50 复合例=T-3（双 SN 空间+4 绑定格全序）。对账 22/22 平。**清单净，待批进 P4。**

**P5 执行记录（2026-09-21）：** cases 14 例新建。首跑 5/14（9 红四类）：①**dstport 80 穿透**——D-JT808-1 裁定 3 勘误：vnc/pptp 变体的"内部缺省"真实住 mapToFlowSpec 协议 switch（`setDefaultDstPort(&spec,cfg,5900)` 先于链路径执行——链 spec 恒经 mapToFlowSpec，universal 80 在 :334 已占位），链 validateSpecBase 无 case 只是"不二次缺省"；**补 `case "jt808": setDefaultDstPort(&spec,cfg,7611)`** 后绿。②getByteSlice 字符串形=**原文字节非 hex**（pppoe 教训重现）：T-5/T-7/T-10 二进制值改字节数组/原文字符串形。③has_payload=80B 载荷门：T-6/T-7/T-8 短帧用例摘 has_payload（诚实口径注记）。④T-4/T-9 pin 错位（自组 pin 多一个 00）——以落盘 pcap 重钉（不手算铁律第二次生效）。**过程教训登记：t7 修复脚本 hexstr_to_arr('61626364') 忘按 2 字符分组→整串单 hex 数 1633837924 落库，三轮排查"疑似管道打包"实为自伤**——落库 config 逐字节对照是定位关键。T-15 身份面复合例追加（逐键反扫抓 city_id/manufacturer_id/terminal_id/imei/software_version/registration_result 6 键零覆盖+terminal_type builder 零消费诚实注记——vnc 第 2 轮教训生效），**15/15 ×2 全绿**；反查 check_jt808 37/37 绿。

**P6 评审与提交（2026-09-21）：** 测试四问全过（链 translate→ParseJT808ConfigFromMap→validator 双段→PlanWithConfig raw wrap 全链/MCP 真流程 15 例/18 registry 键+帧字节双面/9.52 对账 24/24）。反查表 check_jt808 **37/37 绿**（例 15+键 18+锚 4）。门2 四项绿。在库清库：strategies 2+tasks 9 删前报数→备份 trafficgen-jt808-purge-20260921.db→删→复核 0/0（总量 strategies 696/tasks 240500）。门3 抽查三条：①裁定1 唯一入口=PlanWithConfig→layer_gen.go 直调+legacy Plan 硬错注释+T-1 帧序 0100/8100/0102/8001 tshark 复核；②裁定4 转义真字节→T-5 TLV [126,125]→7d02 7d01 帧变长 49B 落盘钉+XOR 校验 3c；③裁定3 registry 18 Fields→逐键反扫 37/37+T-15 复合例补 6 零覆盖键（vnc 第 2 轮教训移植）。9.50 复杂例=T-3（双 SN 空间+4 绑定格全序交错）。

### 隔离复审（收官轮，subagent 执行——按用户常设指令）

**隔离复审处置记录（2026-09-21，收官轮判不净→修复转净）：** 隔离复审员零上下文实跑（套件×2 可复现/tshark 独立复算 22 帧 XOR+转义双射/六探针/多流真流程/-race/文档声明核对），抓 **2 高 2 中 4 低 7 注记**，逐项处置：①**F1 高（4.12/4.24/9.31）分包封装项字段序反序**——规范=消息总包数 WORD@+12 在前、包数据序号 WORD@+14 在后，legacy builder/parser/legacy 测试/T-10 全链自洽地错（"绿但测错"型，三源交叉实证）→**9.7 先红后绿**：jt808_spec_shape_test.go 双红例→buildHeader/parser 对称换序→绿；T-10 重构为 5×210B 多参数（长度字节 uint8 上界内）+pcap 重钉，封装项 0002@+12/0001@+14 实测钉。②**F2 高（4.12/9.47）0x8103 体形偏离**——规范=参数总数 BYTE 前导+参数 ID DWORD，legacy 缺前导且 ID 1 字节→buildSetParamsBody 重写（总数+AppendUint32，>255 值/项数显式报错）、JT808Param.Id uint8→uint32（core）、parse 对称；T-7 重钉（体 17B=02+9B+7B）。③F3 中 9.52 对账算术 16≠24→本节头对账行重出（分项和 17=T-1 承载 2 项+建例 15…修正为 17=16+2-1 可复算）。④F4 中（9.47/3.15）0x0002 心跳缺维→**ProcHeartbeat "heartbeat" 补齐**（0x0002 空体上行，jt808.go dispatch）+T-16 建例（整帧 15B 含校验 82 钉）；0x0104/0x0108/0x8003 等未编排型登记 B′。⑤F5 低 0x8104 应答配对（规范 0x0104 vs 现编排 0x0001 通用应答）→B′ 登记偏差；⑥F6 低 IPv6 零覆盖→B′ 登记（raw 自驱 IPv4-only 面，地址族扩展立项注记）；⑦F7 低 9.50 复合例维度→9.50 复杂例改指 T-15（多事务+失败分支+身份面三维度）；⑧N1 terminal_type 零消费待办、N2 license_color 枚举值注记、N3 方言位原文核验注记、N4 网卡路未跑（沿 6.3 注记）、**N5 直构缺层链 Plan 挂起→validator 对 spec.JT808==nil 显式拒绝（"jt808: layer config required"）**、N6 门1 14 行表补挂（见下）、N7 suite 入库再增殖=现状接受。修复后：**16/16 ×2 全绿+反查 38/38+门2 四项绿+touched 包 -race 绿+vet 净**。legacy jt808_test.go 全量绿（builder/parser 对称换序后 roundtrip 自洽）。

### 门1 对照表（14 行，N6 补挂——canonical 行构 §1–§14 一行一条）

| § | 满足方式+证据 |
|---|---|
| §1 顶层旧键 | 扁平键全删、目标形 `{"layers":[{"ip":{…}},{"jt808":{…}}]}`（可跑形态，1.8/1.9）；顶层 jt808 子映射判死（CheckProtoFlat rawWrapChains 第 9 协议+TestProtoFlat_TopRawWrapSubConfigRejected jt808 子测）；顶层白名单净（1.11-1.13：15/16 例顶层仅 layers，隔离复审探针 E 顶层 src_port 400） |
| §2 判死 | 顶层 jt808 子映射+layers 混用 400 锚词 `no longer accepts a top-level jt808 sub-config`；纯层链不误杀（隔离复审探针 D/F） |
| §3 五件套+单流豁免 | 单 TCP 连接会话（终端↔平台）：会话表=1 连接/事务序=procedures 数组顺序/关联=分包子帧同连接（无独立子流）/插入=handshake 后 teardown 前/时间线=顺序；无子流派生无 sessions（豁免如实） |
| §4 规范矩阵 | 见 P1 表（JT/T 808-2019 八项+三张子表+三路对照+候选对比 (a)/(b)）；线格式保真 F1/F2 勘误后 builder/parser/用例对齐原文（jt808_spec_shape_test.go 双绿例+tshark 复算） |
| §5 依赖与错误 | 依赖 ip 层；ValidateConfig 锚族（phone 12 位/auth/车牌互斥/ACKFlag≤3）；0 包静默护栏=legacy Plan 硬错+validator nil 层拒绝（N5）+嵌套 V9 不下探 |
| §6 性能与验收 | 流式 channel 256；包数=3 握手+N 消息（分包线性）+3 挥手；依据（6.4）=raw wrap 零新增缓冲；pcap 路验收已跑（网卡路未跑注明 6.3）；无吞吐数字承诺（6.5 待确认口径） |
| §7 顺序与回滚 | P4→P5→修复轮逐提交（29608d6/3e7839b/5eafdc8）；单提交粒度摘除即回 |
| §8 定稿后开工 | D-JT808-1 P1+P2 定稿待批后进 P4；无设计条目的 diff 零 |
| §9 测试设计 | T-JT808-1…16（三源回指+清单先行+对账可复算：分项和 17=T-1 承载 2 项+建例 15→16）；全部 pin 从落盘 pcap 取（9.31，四轮重钉实证）；9.50 复杂例=T-15（多事务+失败分支+身份面三维度） |
| §10 自审闭环 | 每 P 阶段改→审→测→修→再审；touched 包 -race+vet 净（P4/P5/修复轮三轮）；隔离复审收官轮+定向复审两轮 subagent 隔离执行 |
| §11 白话汇报 | 收官一句结论+过门证据（见汇报） |
| §12 动态清单 | 四元组+ISN 动态（12.2/12.4 隔离复审多流探针：ip.src inc 逐流确定、src_port 保底 12345+i）；业务键全静态单值如实注记（无 dyn 旁挂，12.14）；12.9 静态四元组 flows>1 拒绝实探 |
| §13 schema 先行 | registry jt808 行 18 Fields+schemagen 重生成 110 层（13.18/13.19 同步测试绿）；MCP 描述/flowb_query_layers 同一注册表 |
| §14 全量门 | suite 16/16 ×2 全绿+pcap 落盘 16 份可人工复查+负例 4 锚真实 400+二进制与 HEAD 同代+反查 38/38 |

## D-JT809-1 jt809 层链收敛（#30，2026-09-21 已验收：82661a2 P4 / a00b3a0 P5 / P6 清库+门表，裁定=线层重建）

### P1 规范矩阵（JT/T 809-2019 反推，三源核验：SmallChi/JT809 权威开源实现源码+README 完整组包金向量例+标准文本；含三张子表要求 4.22）

| 规范点 | 出处 | 代码现状 | 缺口 |
|---|---|---|---|
| 帧模型：`5B` 头标识 + 转义(消息头+消息体+CRC16(2)) + `5D` 尾标识；转义 5B→5A 01/5A→5A 02/5D→5E 01/5E→5E 02 | §数据包结构（README 金向量逐字节例） | **32B 头无定界无转义无校验**（builder.go :36 buildFrame 直拼） | **缺口 F1 级：整信封重建** |
| 消息头 30B（2019）：MsgLength(4,=头+体)+MsgSN(4)+BusinessType(2)+**MsgGNSSCenterID(4 下级平台接入码)**+VersionFlag(3)+EncryptFlag(1)+EncryptKey(4)+**Time(8 UTC 秒，2019 增量)**；2011/2013=22B（无 Time） | JT809Header.cs FixedByteLength 22/30 双版 | 32B=MsgLength4+MsgSN4+MsgID2+**车辆颜色1+车牌21（错位：真在容器体前缀）**，无接入码/版本/加密/时间字段 | **缺口：头重建（版本条件 22/30）** |
| 校验：CRC-16 poly 0x1021 表驱动 init 0xFFFF，范围=5B 后至体尾（MessagePackReader.Decode 循环实录） | 同上 | 无校验 | **缺口：jtcommon 增 CRC809** |
| 消息族：主链路 0x1001 登录/0x1002 应答/0x1003 注销/0x1004 应答/0x1005 连接保持/0x1006 应答/0x1007 断开通知/0x1008 关闭通知；从链路 0x9001-0x9008 镜像；容器族 0x1200-0x1600/0x9200-0x9600 | README 消息对照表（全 60+ 型） | 13 过程混合：管理族 MsgId 部分对（缺 1004/1005/1006/1008）、虚拟子业务 0x01-0x0A 与真 SubBusinessType 不符 | **缺口：族重排 16 型；容器族 B′ 不编排（在库 9 tasks=probe 需求面 0x9001，已覆盖）** |
| 0x1001 体：UserId(4)+Password(pad8)+GNSSCenterID(4，2019)+DownLinkIP(pad32)+DownLinkPort(2)=50B | JT809_0x1001.Serialize | UserName(5)+Password(10)+GNSS4+Version1+Encrypt1+Key4=25B（错形） | **缺口：体重排** |
| 其余管理族体：0x1002=Result1+VerifyCode4/0x1003=UserId4+Password8/0x1004 空体/0x1005·0x1006 空体/0x1007=ErrorCode1/0x1008=ReasonCode1/0x9001=VerifyCode4/0x9002=Result1 | 各 JT809_0x*.Serialize | 全部错形或缺 | **缺口：16 型体重写** |
| 容器体前缀：车牌号(21 GBK 空格 pad)+车辆颜色(1)+子业务类型(2)+后续数据长度(4)+子业务体（0x1200/0x9400 例实证） | JT809_0x1200.Serialize | 车牌/色错住消息头 | 容器族不编排→随 B′ 关闭 |
| 双 TCP 链路：主 8812（下级→上级 0x1xxx 管理族）+从 8813（上级→下级 0x9xxx），同 GroupID 关联 | 包注释+规划 | 双链路已实现（slave_link_enabled，独立 SN 计数器，lazy slave 握手） | 无（§3 真子流面达标） |
| legacy Plan 入口 | — | Plan 硬错（同 jt808 型） | layer_gen 唯一入口=PlanWithConfig |
| 方向换向 | — | — | layer_gen 防双换 Direction=up（八连同款） |
| 层链接线 | — | main.go :590 legacy+具名导入 :84；core 零接线 | 五件套+翻转+类型迁 core |
| 校验锚 | ValidateConfig :56 | GNSSCenterId≤999999999/UserName≤5/Password≤10/VersionFlag≤2/EncryptFlag≤1/LoginResult≤4/DisconnectReason≤2 | 重建后按新体形调（password≤8 等） |

**①命令×响应矩阵：** 登录 0x1001→0x1002/注销 0x1003→0x1004/保持 0x1005→0x1006/断开 0x1007 单向/关闭 0x1008 单向/从链路 0x9001→0x9002/0x9003→0x9004/0x9005→0x9006/0x9007·0x9008 单向——16 型全编排可达；容器族=主链动态/报警/监管/静态交换（B′）。
**②数据形态变体：** 版本双头形（22/30B）、转义展开面（体值含 5A/5B/5D/5E → 5A01/5A02/5E01/5E02）、CRC 覆盖范围（预转义字节）、双向链路方向（main=下级发起/slave=上级发起——TCP 发起方向相反）、空体族（1004/1005/1006/9004/9005/9006）vs 定宽族。
**③商业行为映射：** 在库 9 tasks=probe3-jt809/probe3v2-jt809 冒烟探针（0x9001 msg_type，flat 旧形）=需求面仅从链路连接；无参考 pcap 如实注记。
**三路对照：** ①JT/T 809-2019 原文（经 SmallChi 源码+金向量例交叉落地）；②在库 probe 任务需求面；③开源实现（SmallChi/ewsq C# 库=权威参照）。**候选对比：** (a) 线层重建+编排层保留（双链路/流程/SN 计数复用）✓ vs (b) 信封偏离 B′ 登记（违反 4.12 整帧级，不容）→裁定 (a)。
**门1 三行：** §1 扁平键全删+顶层 jt809 子映射判死（rawWrapChains 第 10 协议），目标形 `{"layers":[{"ip":{"src":"10.0.0.1","dst":"20.0.0.1"}},{"jt809":{"gnss_center_id":291,"procedures":[{"type":"main_login"},{"type":"main_keepalive"}],"slave_link_enabled":true,"slave_procedures":[{"type":"slave_connect"}]}}]}`+**端口=主链 8812 内部缺省+mapToFlowSpec case（jt808 P5 勘误教训直接移植——80 穿透预防）；从链路 8813=生成器合成面**；§3 **真子流面（非豁免！）**：五件套=会话表(主从两条 TCP 连接)/事务序(主链 login→keepalive→logout，从链 connect 族)/关联(**两流同 GroupID**，从链 IP 交换面=0x1001 DownLinkIP/Port 字段)/插入位置(从链握手在主链 login 后)/时间线(主链先从链后，各自顺序)；§12 动态=worker 四元组+双链 ISN+MsgSN/Time 字段（生成时刻 UTC），业务键静态单值如实注记。

### 裁定（P2 定稿）
| # | 裁定 | 依据 |
|---|---|---|
| 1 | **线层重建**：`5B`+转义(30B 头+体+CRC16(2))+`5D`；头=MsgLength/MsgSN/BusinessType/GNSSCenterID(4)/VersionFlag(3 字面 010000 可配)/EncryptFlag/EncryptKey/Time(u64 UTC 秒，仅 version_flag=2)；version_flag 0/1→22B 头（无 Time）——**金向量红例**：README 0x9400 22B 形例逐字节复现为 protocol 包单测（CRC+转义+定界外部权威锚） | 4.12/4.24 整帧级偏离不容；三源交叉 |
| 2 | jtcommon 增 CRC809（poly 0x1021 init 0xFFFF 逐字节表式循环）+Escape809/Unescape809（5A/5B/5D/5E 族）；808 面 XOR/Escape 不动 | 单一真相共用（jtt905 #31 将复用） |
| 3 | 消息族重排 16 型：主 0x1001(50B)/0x1002(5B)/0x1003(12B)/0x1004 空/0x1005·0x1006 空/0x1007(1B)/0x1008(1B)+从 0x9001(4B)/0x9002(1B)/0x9003(12B)/0x9004 空/0x9005·0x9006 空/0x9007(1B)/0x9008(1B)；容器族 0x1200-0x1600/0x9200-0x9600 **B′ 登记不编排**（在库需求面=probe 0x9001 已覆盖；车牌/色体前缀随 B′ 关闭）；legacy 虚拟子业务 0x01-0x0A 废弃 | 在库 9 tasks 反推+README 对照表 |
| 4 | 类型迁 core（vnc 先例）+别名：JT809Config/JT809Procedure；procedures 子键重排（type/link/user_id/password/verify_code/down_link_ip/down_link_port/result/error_code/reason_code/version_bytes）；slave 流程独立键 slave_procedures（原 procedures 内 link 混排废弃——链路归属显式化）；888 行 legacy 测试按新形修钉（线层重建必然面） | jt808 裁定 2 同款+重建必需 |
| 5 | 翻转五件套：isRawIPChain 双名单/src 0-keep/validateBaseDstPortHandled+=jt809；registry 13 Fields（gnss_center_id/user_name/password/version_flag/version_bytes/encrypt_flag/encrypt_key/login_result/initial_sn/platform_initial_sn/procedures/slave_procedures/vehicle_color...收窄至消费面）；translate case+FlowMeta.JT809+meta 注入；CheckProtoFlat rawWrapChains 第 10 协议+pipe_gate 名单+10；main.go 翻转；**mapToFlowSpec `case "jt809": setDefaultDstPort(&spec,cfg,8812)`（jt808 80 穿透教训直接移植）** | jt808 P4/P5 全套先例 |
| 6 | 场景强度：信封字节钉（5B/5D/CRC 复算/30B 头逐字段含 Time 定值钉）、金向量单测（外部权威逐字节）、转义真字节（DownLinkPort=0x5A5B 值触发 5A01/5E01 双 escape）、keepalive 对（0x1005/1006——jt808 F4 教训预防性补齐）、双链路真子流（两 4 元组同 GroupID 落同 pcap）、从链应答负路径（result=1）；负例 4 锚（gnss>999999999=V9 区间/version_flag>2=V9 区间/disconnect error_code>2=planner 嵌套/password>8=planner） | 9.46-9.53+F4 预防 |
| 7 | B′ 账本：容器族（0x1200-0x1600/0x9200-0x9600 车辆动态/报警/监管/静态交换）不编排——真子业务表已三源登记、体前缀形状已明（车牌21+色1+子业务2+长度4），编排缺位立项待需求；无参考 pcap（probe 面）；头 22B 形为链路缺省（version_flag 缺省 0，隔离复审 M4 勘误：types 注释"缺省 2"失实已改）且为 suite 多数例形；2019 30B 形由 T-2/T-3 显式 version_flag=2 承载（含 50B 体），0x1003 Password pad 宽 8 按 0x1001 对称推定（单源，注记）；Time 语义=打包时刻 UTC 秒（生成器时钟面，钉定值保证确定性） | 如实 |

**文件：** jtcommon（CRC809/Escape809）+protocol/jt809/{types 别名化,builder 重建,parser 重建,jt809.go 流程保留+消息族重排,layer_gen 新}+core/types.go（JT809Config 迁入）+core/layers 五件+strategy_convert（Parse+mapToFlowSpec case+rawWrapChains）+main.go 翻转+cases/jt809.json 新+schemagen+pipe_gate/coverage_gate。
**性能（6.4-6.6）：** channel 256 流式；包数=主链(3+N+3)+从链可选(3+M+3)；pcap 路（网卡未跑注明）。
**回滚：** 单提交粒度，摘除即回。

### T-JT809-1…14 清单（P3 建 13 例；P6 隔离复审后修轮增 T-14；9.52 对账勘误 L1——原"分项和 14"算术不可复算，实算：T-1 基线 1+T-2 信封头 CRC 2+T-3 登录体 1+T-4 keepalive 1+T-5 断开 1+T-6 关闭通知 1+T-7 从链连接+双链路子流 2+T-8 应答负 1+T-9 转义 1+T-10 注销 1+T-11…13 负例 3+T-14 应答体 1 = **分项和 16 = 建例 14 + T-2/T-7 各承载 2 项（+2），可复算**；负例 password>8 锚=单测面（裁定6 声明），suite 负例 3）

| # | 用例 | 断言面 |
|---|---|---|
| T-1 | 基线关联（main_login→logout） | 8 帧=3 握手+2 消息+3 挥手；首帧 5B 起 5D 止 |
| T-2 | 信封+头字节钉 | 5B/5D；30B 头逐字段（MsgLength=30+体/SN/GNSSCenterID 00000123/Version 010000/Encrypt/Key/Time 定值）；CRC 复算=尾 2B |
| T-3 | 登录体 50B 钉 | UserId/Password pad8/GNSSCenterID/DownLinkIP pad32/Port 全字段 |
| T-4 | keepalive 对 | 0x1005→0x1006 空体+SN 递增（F4 预防面） |
| T-5 | 断开通知 0x1007 | ErrorCode 1B=01 |
| T-6 | 关闭通知 0x1008 | ReasonCode 1B=01 |
| T-7 | 从链路双流 | slave_link_enabled→两条 TCP 4 元组（8812/8813）同 GroupID 落同 pcap；0x9001 VerifyCode 钉 |
| T-8 | 从链应答负路径 | 0x9002 Result=1 |
| T-9 | 转义真字节 | DownLinkPort=0x5A5B→线上 5A 02 5E 01（两 escape 形）帧变长钉（**值勘误=勘误块 7**：实建 0x5B5D→5A 01 5E 01） |
| T-10 | 注销 0x1003 | UserId+Password 12B 体 |
| T-11 | 负例 gnss 超界 | 锚词 `GNSSCenterId 1000000000 > 999999999` |
| T-12 | 负例 version_flag=3 | 锚词 `VersionFlag 3 > 2`（V9 区间） |
| T-13 | 负例 error_code=3 | 锚词 `ErrorCode 3`（planner 嵌套锚） |

**P3 复审（2026-09-21 对抗走查；P6 隔离复审 M3 勘误：原"16 型全枚举合盖 16/16"表述失实，实为 9 型 suite wire 直达 + 7 型分支代表）：** 编排面=16 型族枚举表建立；suite wire 直达 9 型（0x1001/1002/1003/1005/1006/1007/1008/9001/9002，T-1/3/4/5/6/7/8/10/14）；其余 7 型按 9.21 分支代表口径登记——0x9003（12B 体=1003 同形）·0x9004/9005/9006（空体=1005/1006 同形）·0x9007/9008（1B 体=1007/1008 同形）·0x1004（空体族），且方向分支全覆盖（9001=从链 down 已达、9002=从链 up 已达，余 7 型均落同两分支），dispatch 表 16 项代码走查；金向量=单测面（外部权威 0x9400 例逐字节，不占 suite 号）；转义双形=T-9（5A02+5E01 两种 escape 并现）；双链路=§3 真子流唯一协议面=T-7 主断言；负例拦截点=gnss/version_flag 顶层 V9 区间、error_code 嵌套 planner（V9 不下探）——登记点核准。对账分项和 14=T-2 承载 2 项（信封+CRC 复算）+建例 13，可复算。**清单净，待批进 P4。**（此句对账数已被 :3433 修轮勘误取代——实算分项和 16，见 T 清单头）

### P4 线层勘误（2026-09-21，金向量实测——三处设计表述修正，原文保留备查）

SmallChi 0x1001 单测金向量（上游 Assert.Equal 钉死）逐字节核算 + 库源码
（JT809Package.Serialize/JT809MessagePackWriter.WriteCRC16/WriteEncode/
JT809_0x1001.Serialize）实录，对裁定 1/裁定 7/T-2 修正如下：

1. **MsgLength 语义修正**：非"头+体"（P1 矩阵行 2 / 裁定 1 原表述），实为
   **整帧总长=5B+头+体+CRC(2)+5D**。实证：金向量 头22+体46=68≠线上 0x48=72；
   库组包第 4 步 `WriteInt32Return(当前长度+3)`（+CRC2+5D1）；解包体存在性
   判断 `MsgLength - fixedByteLength(26/34) > 0` 同口径。2019 形 = 34+体。
2. **金向量替换**：裁定 1 原定 README 0x9400 组包例——经核算其 MsgLength=146
   与 帧长 149/内容 147/内容去 CRC 145 三方互斥，手拼不可靠，**弃用**；改用
   SmallChi 自带单测 0x1001 例（jt809wire_test.go 四锚：CRC 对未转义头+体
   计算=6A91、MsgLength 整帧语义、转义四规则单遍、反转义回程）。含转义字节
   的外权威整帧例未寻得，转义面以规则向量+单遍性质钉（B′ 注记）。
3. **CRC/转义次序实录**：CRC 先对未转义 头+体 计算（init 0xFFFF 表驱动
   poly 0x1021，与 bitwise 实现等价——金向量 6A91 复算过），随后对标识间
   整体（含 CRC 字节）单遍转义（WriteEncode 保首尾字节）。
4. **0x1001 体版本双形**：46B（2011/2013：UserId4+Password8+DownLinkIP32+
   Port2）/ **50B（2019：Password 后增 GNSSCenterID4）**——JT809_0x1001.cs
   `IJT809_2019_Version` 条件分支实录，金向量实证 2013 形 46B。suite 用例面
   （2019 主形态）按 50B 钉；22B/46B 形随裁定 7 B′ 仅单测覆盖。
5. **Time 基值 B′**：库 2019 Time=UInt64 大端秒（自库内 UTCBaseTime 起算，
   常量值未寻得——源文件抓取失败）；本引擎 `time_sec` 按原始秒直发
   （0=生成时刻 Unix 秒），线形 8B 不变，绝对基值差记 B′ 账本。
6. T-2 断言面随之修正：MsgLength=**整帧长**（=34+体），非原表述"30+体"。
7. **T-9 值勘误（L2）**：裁定 6 原"DownLinkPort=0x5A5B 触发 5A 01/5E 01 双 escape 形"双重失实——0x5A5B 的两字节逃逸形=5A 02+5A 01（5B 逃逸为 5A 01 非 5E 01）；实际建例值=0x5B5D→5A 01+5E 01（cases/jt809.json T-9 与单测 TestEscapeOnWire 同值）。
8. **裁定 5 registry 枚举勘误（L3）**：裁定 5 原"registry 13 Fields（…user_name/login_result/vehicle_color…）"为重形前陈旧枚举；实登记 **14 Fields**（gnss_center_id/user_id/password/version_flag/version_bytes/encrypt_flag/encrypt_key/time_sec/down_link_ip/down_link_port/initial_sn/platform_initial_sn/procedures/slave_procedures），以门 1 §13 行与提交 82661a2 为准。
9. **修轮补记（H1 教训二实录）**：frames 钉 offset 基准=整以太帧（+54）之外，体首字节=payload[23]（5B 占位后）——T-8 首钉误落 payload[22]（EncryptKey 末字节）即"失败路径不会红"（9.44），修轮重钉并 T-14 提取时同错再犯（断言 body=="0012345678" 拦截）。钉必须带形状断言，不许纯转录。

### 门 1 开工对照表（§1–§14，2026-09-21 jt809 P6 回填，证据=文档节/代码行/用例号）

| § | 本协议怎么满足 | 证据 |
|---|---|---|
| §1 层链唯一真相 | 顶层旧键 src_ip/dst_ip/src_port/dst_port/count 不存在（本协议从未有 flat 用例面）；顶层 jt809 子映射 presence 判死=rawWrapChains 第 10 协议（空 map 也死）；目标形状 `{"layers":[{"ip":{"src","dst"}},{"jt809":{"gnss_center_id":291,"procedures":[…],"slave_procedures":[…]}}]}`；端口=主链 8812（mapToFlowSpec case 先补——jt808 80 穿透教训移植；无层端口字段）+从链 8813 生成器合成面 | `strategy_convert.go` rawWrapChains+case "jt809"；cases/jt809.json 13 例；pipe_gate 门 2-1 绿 |
| §2 策略/任务分工 | 沿框架语义不另设；在库 2 probe 策略+9 任务已清库对账（696→694/240500→240491，备份 trafficgen-jt809-purge-20260921.db） | P6 清库对账记录 |
| §3 五件套（真子流面，非豁免） | 会话表=主从两条 TCP 连接（主 8812 下级发起/从 8813 上级发起，从链 4 元组下侧端口统一 8813——legacy SYN+ACK/FIN2 spec.SrcPort 错形 P4 修正）；事务序=16 型族按 procedures/slave_procedures 顺序；关联=两流同 GroupID（hashGNSS）；插入位置=从链握手在主链消息后；时间线=主链握手→主链消息→从链握手→从链消息→主挥→从挥 | `jt809.go` PlanWithConfig；T-7（14 帧全时序钉） |
| §4 规范矩阵 | JT/T 809-2019 反推八项三源（SmallChi 源码实录+单测金向量+标准文本）；P4 线层勘误 6 条（MsgLength 整帧语义/金向量替换/CRC 次序/0x1001 双形/Time 基值 B′/T-2 修正） | D-JT809-1 P1 矩阵+P4 勘误块 |
| §5 有错必处理 | ValidateConfig 全负路径锚（gnss 区间/version_flag/encrypt_flag/password≤8/down_link_ip≤32/version_bytes 形/16 型枚举/链路归属/Result≤4/ErrorCode·ReasonCode≤2）+ParseFrame 负路径（CRC/MsgLength/定界）+Plan 硬错防 0 包 | `jt809.go` ValidateConfig；`parser.go`；T-11…13；TestParseFrame_Negative |
| §6 性能 | channel 256 流式；包数公式=主链(6+M)+从链可选(6+K)；验收=pcap 落盘可复查（网卡未跑，如实注记） | D-JT809-1 性能行；/tmp/mcp-pcaps/jt809/ |
| §7 三份文档 | 设计=D-JT809-1；用例=T-JT809-1…13；cases 文件回指编号 | CODE_DESIGN/TEST_CASES/cases/jt809.json |
| §8 先设计后代码 | P2 定稿（9f1988f）先于 P4（82661a2） | git 历史 |
| §9 三源+整格 | 金向量逐字节（外部权威）+T-2 16 钉全格+单测面五锚 | jt809wire_test 四锚；T-2；TestBuildFrame_* |
| §10 评审闭环 | 自审 2 轮：轮1 抓 slave 4 元组错形（SYN+ACK/FIN2 用 spec.SrcPort）+DownLinkIP>32 静默截断+parser 死块；轮2 全绿后 -race/vet 复核；隔离对抗复审=收官独立轮（抓 H1 体钉偏移/M1 panic 带/M2 pr 校验旁路/M3 覆盖表述/M4 缺省矛盾——修轮全落，勘误块 7-9 条） | P4 记录；勘误块 7-9；修轮提交 |
| §11 白话汇报 | 先一句结论再证据；代号带解释 | 每次汇报 |
| §12 动态清单 | 四元组=框架白名单（worker 注入）；双链 ISN=randUint32；MsgSN=四计数器（分链分向，InitialSN/PlatformInitialSN 起点）；Time=time_sec 0→生成时刻 Unix 秒；业务键（verify_code/result/error_code 等）=静态单值如实注记（可配非逐包动态） | `jt809.go` 四计数器+rc 缺省化；D-JT809-1 门 1 §12 行 |
| §13 schema 同步 | registry jt809 14 Fields → schemagen 重生成 111 层 | `generated/layers.generated.json` diff（82661a2） |
| §14 真实流程 | MCP 建任务→引擎生成→tshark 校对全流程；14/14 ×2 全绿（修轮后）；负例带实际锚词；包号/端口从落盘 pcap 重钉（frames 钉 offset=整以太帧 +54，体首 payload[23]） | T-JT809-1…14；suite ×2（修轮后复跑绿） |

**门 3 抽查三条（P6）：** ①§3 关联面——T-7 pcap 实证两 4 元组（12345↔8812 / 8812↔8813）同 group_id 落同 pcap，包 5=从链 SYN dst 8813；②§12 动态面——`strategy_convert.go` case "jt809" setDefaultDstPort(8812)（80 穿透预防位）+`jt809.go` 四计数器分行可点；③§14 验收面——suite RESULT 13 pass ×2 连续（-count=1 两次独立跑）+coverage_gate 30/30+pipe_gate 静态四项绿。

**验收两门（§1）：** ①层链跑通=P5 绿；②旧格式移除=顶层子映射判死+无 flat 用例面+rawWrapChains 执法。两门全过。

**P6 收官结论（白话一句）：** jt809 线层重建后信封/头/体/校验/转义全对齐 JT/T 809-2019 权威实现（金向量逐字节），16 型链路管理族双 TCP 真子流可编排可校验，13 例 ×2 全绿、反查 30/30、门 2 四项绿、在库清零对账平。

## D-JTT905-1 jtt905 层链收敛（#31，2026-09-22 已验收：fb7f923 P4 / de31eb7 P5 / P6 清库+门表，裁定=体面重建+线面复用）

### P1 规范矩阵（JT/T 905.2-2014 反推，三源：SmallChi/JT905 源码+README 金向量（独立核算过）+标准目录结构；在库需求面=2 probe 策略（flat 80 端口，msg_id 0x0001）+9 任务）

| 规范点 | 出处 | 代码现状 | 缺口 |
|---|---|---|---|
| 帧模型：`7E`+转义(头+体+XOR(1))+`7E`；转义 7E→7D 02/7D→7D 01；XOR 对未转义内容算（金向量独立复算 34✓）；转义含头内 7E（金向量 MsgNum=007E 上线 7D02 实证） | SmallChi/JT905 README 组包例 | 同构已实现（jtcommon XORChecksum/Escape 共享） | 无（线面复用） |
| 消息头 12B：MsgId(2)+**DataLength(2)=纯消息体长度（无版本/加密/分包位——金向量 0x0023=35 纯值实证）**+ISU 标识(6 BCD 12 位)+MsgNum(2) | README 金向量逐字段核算 | EncodeMsgBodyProps 版本/加密位（808 面） | **缺口 F1：props 改纯长度** |
| MsgId 空间：0x0001 ISU 通用应答/0x8001 中心通用应答/0x0002 ISU 心跳/0x8103-0x0105 参数控制族/0x0200 位置族/0x8300-0x0302 文本事件族/0x8400-0x0500 电话车辆族/0x08xx-0x88xx 图像音频族/0x8B00-0x0B11 订单签到运营族（README 对照表 46 型） | 同上 | **0x1001 签到/0x1002 签退=虚构 MsgId**（真=0x0B03/0x0B04）；0x8300 有常量无过程 | **缺口 F2：MsgId 重排** |
| 0x0B03 上班签到体：Position(0x0200，可选≥25B)+企业经营许可证号(16 ASCII \0补)+从业资格证号(19 ASCII \0补)+车牌号(6 ASCII \0补)+开机时间(BCD6=yyyyMMddHHmm)+扩展(可选) | JT905_0x0B03.cs | 82B 虚构体（GBK 姓名/GBK 车牌/BCD yyMMddHHmmss） | **缺口 F3：体重建** |
| 0x0B04 下班签退体：Position(可选)+许可证16+资格证19+车牌6+计价器K值(BCD4=2B)+当班开机(6)+当班关机(6)+当班里程(BCD6=3B)+运营里程(3B)+车次(BCD4=2B)+计时(BCD6=3B)+总计金额(3B)+卡收金额(3B)+卡次(BCD4=2B)+班间里程(2B)+总计里程(BCD8=4B)+总运营里程(4B)+单价(BCD4=2B)+总运营次数(u32)+签退方式(1B)+扩展(可选) | JT905_0x0B04.cs | 74B 虚构体（mileage/income u32 等） | **缺口 F3 同** |
| 0x0001/0x8001 通用应答体：ReplyMsgNum(2)+ReplyMsgId(2)+Result(1)，Result 枚举 0/1/2（成功/失败/消息有误） | JT905_0x0001.cs | 5B 同形✓；ACKFlag 0-3（多一个"不支持"） | 缺口：Result 收窄 0-2 |
| 0x0002 心跳：空体 | README 对照表 | ✓ | 无 |
| 0x0200 位置基本体 25B：报警(4)+状态(4)+纬(4)+经(4)+速度(2)+方向(1——金向量算术钉死)+时间(BCD6=yyMMddHHmmss)+附加列表(可选) | 金向量+JT905_0x0200 | 无 | 新增 Position 可选块 |
| 单 TCP 连接（ISU→中心），ISU 上行/中心下行 | README/协议结构 | ✓ 单链 | 无 |
| legacy Plan 入口 | — | Plan 硬错✓ | layer_gen 唯一入口=PlanWithConfig |
| 方向换向 | — | — | layer_gen 防双换 Direction=up（十连同款） |
| 层链接线 | — | main.go :591 legacy+具名导入；零接线 | 五件套+翻转+类型迁 core |
| 端口缺省 10700 | legacy 自选（标准未定端口） | PlanWithConfig :162 内部缺省 | mapToFlowSpec case 先补（80 穿透预防；probe 面 dst_port=80 即病征） |
| 校验锚 | ValidateConfig :55 | phone 12 位/DriverId 20/GBK 面全虚构 | 重建后：isu_id 12 位数字/plate 6 ASCII/license 16/qual 19/BCD 位数族/result 0-2 |

**①命令×响应矩阵：** 签到 0x0B03→0x8001/心跳 0x0002→0x8001/签退 0x0B04→0x8001/ISU 应答 0x0001（对中心下行命令）——编排可达 5 型+Position 块；其余 41 型 B′ 登记（在库需求面仅 0x0001）。
**②数据形态变体：** 转义真字节（ISU/MsgNum/车牌值含 7E/7D）、BCD 位数族（4/6/8 位三档）、ASCII \0 补齐、Position 可选性（≥25B 判定）、体长纯值位。
**③商业行为映射：** 在库 probe=0x0001 通用应答冒烟（flat 80 端口=待修病征）；无参考 pcap 如实注记。
**三路对照：** ①JT/T 905.2-2014（经 SmallChi/JT905 源码+金向量交叉落地）②在库 probe 需求面 ③开源实现 SmallChi/JT905（同 JT809 作者，权威参照）。**候选对比：** (a) 体面重建+线面复用 jtcommon（XOR/Escape 已共享，props 改纯长度）✓ vs (b) 照 legacy 虚构 MsgId/体形 B′ 登记（4.12 整帧级虚构不容）→裁定 (a)。**jt809 裁定2 预设勘误：jtt905 线面属 808 族（0x7e/XOR），不复用 CRC809；jtcommon 的 808 族原语即共享点。**

### 裁定（P2 定稿）
| # | 裁定 | 依据 |
|---|---|---|
| 1 | **线面复用+props 纠偏**：7E+Escape(头+体+XOR)+7E 复用 jtcommon；消息头 12B，DataLength=纯体长（去 EncodeMsgBodyProps 版本/加密位——金向量 0x0023 实证）；XOR 对未转义内容、转义含校验码与头内特殊字节 | 金向量独立核算；4.12 |
| 2 | **MsgId 重排**：check_in=0x0B03/check_out=0x0B04/heartbeat=0x0002/isu_general_response=0x0001/center_general_response=0x8001；legacy 虚构 0x1001/0x1002 废弃；其余 41 型 B′（在库需求面=0x0001 已覆盖）；0x8300 常量随 B′ 关闭 | README 对照表 |
| 3 | **体重建**：0x0B03=Position?+license16 ASCII\0补+qual19+plate6+uptime BCD6(yyyyMMddHHmm)；0x0B04=Position?+license16+qual19+plate6+K值2+开机6+关机6+里程3+运营里程3+车次2+计时3+总金额3+卡金额3+卡次2+班间里程2+总里程4+总运营里程4+单价2+总次数u32+签退方式1；应答族 5B Result 0-2；Position 可选块（报警4/状态4/纬4/经4/速2/向1/时间6，附加列表 B′） | JT905_0x0B03/0x0B04/0x0001.cs+金向量 |
| 4 | **类型迁 core（jt808/809 先例）+重形**：JTT905Config{isu_id/initial_sn/platform_initial_sn/business_license/qualification_code/plate_no/position{...}/procedures}；过程 5 型{type/result/reply_sn/reply_msg_id}；废弃 phone/driver_id/driver_name/license_color/version/encrypt_flag/vehicle_model/load_capacity/on_time/off_time/mileage/income/passenger_count 全虚构面；auto 会话=签到→应答→(心跳→应答)×N→签退→应答（原 H-09 形保留） | 重建必需 |
| 5 | **翻转五件套**：isRawIPChain 双名单/src 0-keep/validateBaseDstPortHandled+=jtt905（第 11 协议）；registry Fields（新消费面）；translate case+FlowMeta.JTT905+meta 注入；CheckProtoFlat rawWrapChains 第 11 协议+pipe_gate 名单+1；main.go 翻转；**mapToFlowSpec `case "jtt905": setDefaultDstPort(&spec,cfg,10700)`** | jt809 全套先例 |
| 6 | **场景强度**：信封钉（7E/DataLength=体长/ISU BCD/SN）、金向量单测（0x0200 例反转义+XOR 复算+头核算，parse 面）、转义真字节（initial_sn=0x007E→线上 7D02——金向量同款位）、应答对（0x8001 down+0x0001 up）、负例锚（isu_id 11 位/plate 7 ASCII/result 3/BCD 位数错） | 9.46-9.53+F 系预防 |
| 7 | **B′ 账本**：其余 41 型（参数/位置查询/文本事件/电话/车辆控制/图像音频/订单族）不编排；Position 附加信息列表（0x01-0x26）不编排（基础 25B 已覆盖）；分包不存在面（header 无分包位）；加密不存在面（无加密位）；2011/2013 版本方言不存在（单版） | 如实 |

**文件：** protocol/jtt905/{types 别名化,builder 重建,parser 重建,jtt905.go 编排保留+MsgId 重排,layer_gen 新}+core/types.go（JTT905Config 迁入）+core/layers 五件+strategy_convert（Parse+case+rawWrapChains）+main.go 翻转+cases/jtt905.json 新+schemagen+pipe_gate/coverage_gate。
**性能（6.4-6.6）：** channel 256 流式；包数=3 握手+(1+Σ resp)+3 挥手；pcap 路验收（网卡未跑注明）。
**回滚：** 单提交粒度，摘除即回。

### T-JTT905-1…14 清单（P3+修轮；9.52 对账：T-1 基线 1+T-2 信封头 2+T-3 签到体 1+T-4 心跳对 1+T-5 签退体 1+T-6 应答对 1+T-7 转义 1+T-8 金向量 0（单测面）+T-9 位置块 1+T-10…13 负例 4+T-14 枚举 1 = **分项和 14 = 建例 13（其中 T-2 承载 2 项信封+体长纯值，余 12 例各 1 点），可复算**；suite 负例 4）

| # | 用例 | 断言面 |
|---|---|---|
| T-1 | 基线关联（签到→应答→心跳→应答→签退→应答） | 12 帧=3 握手+6 消息+3 挥手；MsgId 序 0B03/8001/0002/8001/0B04/8001 |
| T-2 | 信封+头字节钉 | 7E 首尾；DataLength=纯体长；ISU BCD；SN 起点；XOR 复算=尾 1B |
| T-3 | 签到体钉 | license16\0/qual19\0/plate6\0/uptime BCD 全字段 |
| T-4 | 心跳对 | 0x0002 空体+SN 递增 |
| T-5 | 签退体钉 | K值/双时间/BCD 位数族/总次数 u32/签退方式全字段 |
| T-6 | 应答对 | 0x8001 down+0x0001 up 各 5B；ReplySN/ReplyId 绑定 |
| T-7 | 转义真字节 | initial_sn=0x007E→线上 7D02（金向量同款位）帧变长钉 |
| T-8 | 金向量 | 单测面：0x0200 例反转义+XOR 复算 34+头核算（parse 面，不占 suite 号） |
| T-9 | 位置块 | position 配置→0x0B03 体含 25B 基础位（方向 1B 钉） |
| T-10 | 负例 isu_id 11 位 | 锚词 `ISUId "12345678901" must be 12 digits` |
| T-11 | 负例 plate 7 ASCII | 锚词 `PlateNo length 7 > 6` |
| T-12 | 负例 result=3 | 锚词 `Result 3 > 2` |
| T-13 | 负例 uptime 位数错 | 锚词 `OnDutyPowerOnTime "20240803" must be 12 digits (yyyyMMddHHmm)`（L3a 勘误：原列 `Uptime` 为 build 路径锚，e2e 不可达） |
| T-14 | Result 枚举正例（修轮 M1） | result=1（失败）+result=2（消息有误）体尾字节双钉；枚举 0/1/2 线上全达 |

### 门 1 开工对照表（§1–§14，2026-09-22 jtt905 P6 回填，证据=文档节/代码行/用例号）

| § | 本协议怎么满足 | 证据 |
|---|---|---|
| §1 层链唯一真相 | 顶层旧键不存在（probe 面 dst_port=80 即被 case "jtt905" 10700 先补取代——probe 已清库）；顶层 jtt905 子映射 presence 判死=rawWrapChains 第 11 协议；目标形 `{"layers":[{"ip":{"src","dst"}},{"jtt905":{"isu_id":"103456789012","procedures":[…]}}]}`；端口=10700 内部缺省+mapToFlowSpec case 先补 | SC rawWrapChains+case；cases/jtt905.json 12 例；pipe_gate 门2-1 绿 |
| §2 策略/任务分工 | 沿框架语义不另设；在库 2 probe 策略+9 任务清库对账（694→692/240491→240482，备份 jtt905-purge-20260922.db） | P6 清库记录 |
| §3 五件套 | 单流协议写豁免+内层委托：无子流派生/sessions；事务序=procedures 顺序（签到→应答→心跳→应答→签退→应答）；时间线=顺序（门1 §3 行五件齐全） | `jtt905.go` PlanWithConfig；T-1 12 帧全序 |
| §4 规范矩阵 | JT/T 905.2-2014 反推八项三源；jt809 裁定2 预设勘误（线面属 808 族）入 D- P1 表 | D-JTT905-1 P1 矩阵 |
| §5 有错必处理 | ValidateConfig 全锚（isu/plate/license/qual/result/BCD 位数族）+ParseFrame 负路径（XOR/DataLength 自洽/定界）+Plan 硬错 | `jtt905.go`；`parser.go`；T-10…13；TestParseFrame_Negative |
| §6 性能 | channel 256 流式；包数=3+(1+Σresp)+3；pcap 路验收（网卡未跑如实） | D- 性能行 |
| §7 三份文档 | 设计=D-JTT905-1；用例=T-JTT905-1…13；cases 回指编号 | 三文档 |
| §8 先设计后代码 | P2 定稿（D- 追加随 fb7f923）先于用例（de31eb7） | git 历史 |
| §9 三源+整格 | 金向量单测（外部权威 0x0200 例）+T-2/T-3/T-5 全格钉 | jtt905_test 金向量锚 |
| §10 评审闭环 | 自审轮次：builder/parser/jtt905 重建后全量自查（result 校验域错/DataLength 负例补 XOR 面两处即改）+隔离对抗复审=收官独立轮 | P4 记录；复审轮 |
| §11 白话汇报 | 先一句结论再证据 | 各阶段汇报 |
| §12 动态清单 | 四元组=框架白名单；双流水号（ISU/中心）=InitialSN/PlatformInitialSN 起点；业务键静态单值如实注记（无动态消费面） | 门1 §12 行；`jtt905.go` 双计数器 |
| §13 schema 同步 | registry 25 Fields → schemagen 重生成 112 层 | generated/layers.generated.json（fb7f923） |
| §14 真实流程 | MCP 建→引擎生成→tshark 校对；13/13 ×2（修轮 T-14 后）；负例带锚词；钉从落盘 pcap | T-JTT905-1…14；suite ×2 |

**门 3 抽查三条（P6）：** ①§3——T-1 自动会话 MsgId 序 0B03/8001/0002/8001/0B04/8001 六钉（pcap 实证）；②§12——双流水号 `jtt905.go` isuSN/centerSN 分行可点+T-4 platform_initial_sn=60→应答 SN 0x3c 钉；③§14——suite 12/12 ×2+反查 41/41+门2-3 二进制同代。

**验收两门：** ①层链跑通=P5 绿；②旧格式移除=presence 判死+probe 清库。两门全过。

**P6 收官结论（白话一句）：** jtt905 体面重建后 MsgId/体形/头语义全对齐 JT/T 905.2-2014 权威实现（金向量逐字节），5 型会话可编排可校验，12 例 ×2 全绿、反查 41/41、门2 四项绿、在库清零对账平。

### 修轮块（2026-09-22 收官隔离复审 PASS-WITH-FINDINGS → 处置，红先绿后）

| 级 | 发现 | 处置 |
|---|---|---|
| M1 | Result 枚举 1/2 全量缺例（9.46/9.47 逐值至少一例不满足） | T-14 wire 例新建（result=1/2 体尾双钉，rsn/rid 绑定同 T-6 面）；枚举 0/1/2 线上全达 |
| L1 | BCD 位数族只查长度不查数字性（等长非数字漏到 BCDEncode 才以他锚词失败） | ValidateConfig 位数族 12 项+三时间字段补逐位数字查（锚 `contains non-digit`）；红例先行（"12a4" 放行实录）修复转绿 |
| L2 | isu_general_response 无前置下行合成缺省：rsn=centerSN-1（0 时回绕 65535）、rid 缺省 0x8300 | **B′ 登记**：合成缺省面如实注记（MsgTextDownRef 注释已在码），边界例不建 |
| L3 | 文档措辞三处（T-13 锚词 `Uptime` 不可达/coverage docstring 1…10/分项和算术含混） | 三处同修（本块+TEST_CASES+coverage_gate.py） |
| L4 | 仅 IPv4 例 | **B′ 登记**：raw 家族通病，随家族级 IPv6 立项 |
| L5 | 线上 7D01 转义例缺 | **B′ 登记**：转义函数金向量单测逐字节钉（体尾 7D→7D01），wire 例不建 |
| L6 | initial_sn 0/65535 边界、heartbeat_count>1 无例 | **B′ 登记**：循环体走查平凡正确，边界例不建 |

修轮后：suite 13/13 ×2、反查 41/41、门2 四项绿（重编实录）、touched 包 -race 绿。任务书勘误：XORChecksum/Escape/BCDEncode 实住 protocol/jtcommon/jtcommon.go（非 jt808wire.go，该文件属 809 专用面），复用结论不变。


## D-ARP-1 arp 层链收敛（#32，2026-09-22 已验收：1f61887 P4 / ef3bfb5 P5 / P6 清库+门表，裁定=L2-only 族接入+线面复用重建）

### P1 规范矩阵（§4 八项；三源=RFC 826 + 本仓 legacy 行为面 + RFC 语义反推）

| 项 | 规范要求 | 业务场景 | 代码现状 | 缺口 |
|---|---|---|---|---|
| 1 连接模型 | 无连接：ARP 帧直接以太网承载（EtherType 0x0806），无 IP/端口/传输层；请求=链路层广播 ff:ff:ff:ff:ff:ff，应答=单播 | L2 探针面：地址解析探测 | legacy Planner 直发（main.go:538 arp.NewPlanner），无层链接线 | 五件套缺——本主体 |
| 2 命令/消息表 | oper=1 request / oper=2 reply（RFC 826 报文格式）；RARP/InARP（3/4/8/9）属他协议 | 请求-应答对 | ARPConfig.Operation 单键，无校验域 | registry 区间+validator 锚 |
| 3 状态机 | 无状态；一对 request/reply 语义绑定（spa/tpa、sha/tha 角色互换） | 解析问答 | legacy op=1 自动配对 request+reply | 保留（裁定3） |
| 4 字段表 | 28B=htype2(0001)+ptype2(0800)+hlen1(06)+plen1(04)+oper2+sha6+spa4+tha6+tpa4 | 全字段可配 | buildARPPacket/buildARPReply 字段序正确（RFC 826 对齐） | 线面复用（裁定1）；缺省地址面 |
| 5 错误处理表 | oper 非法拒；IP/MAC 格式非法拒 | 负例锚 | 零校验（legacy Validate 仅查 spec.ARP 非空） | registry [1,2] V9+validator 双层 |
| 6 超时与活性 | 不适用（无重传/保活语义） | — | 不适用 | 不适用（如实） |
| 7 NAT/被动 | 不适用 | — | 不适用 | 不适用（如实） |
| 8 版本方言 | RFC 826（1982）单一标准；gratuitous/代理 ARP 为行为模式非报文变体 | — | 单版 | B′ 注记 |

**三张子表：** ①消息×语义（request=广播问、reply=单播答）②形态变体（op=1 配对形/op=2 单发宣告形）③商业映射（无参考 pcap——在库 0 tasks，legacy 行为面替代，如实）。

### 裁定（P2 定稿）

| # | 裁定 | 依据 |
|---|---|---|
| 1 | **线面复用**：legacy buildARPPacket/buildARPReply 28B 字节面 RFC 826 字段序正确，重建为 layer_gen 事件面（goose Generator 型：Generate+req.Emit，GenEvents=nil）——不重写构造，重写编排与校验 | §4.4 现状行 |
| 2 | **层形状 [eth, arp]**，5 键 `{operation, sender_mac, sender_ip, target_mac, target_ip}`；无 registry Default（goose 决策 F 同款），缺省生成器侧补：sender_ip=10.0.0.1/target_ip=10.0.0.2/sender_mac←eth src_mac（常量兜底 aa:bb:cc:dd:ee:01）/target_mac←eth dst_mac（兜底 aa:bb:cc:dd:ee:02） | P0b 空配置默认流口径；goose DefaultDstMAC 先例 |
| 3 | **编排**：operation=1（缺省 0→1）→自动配对 request(up, 广播, tha 全零)+reply(down, 单播, 角色互换)；operation=2→单发 reply(down)（对端宣告形：sha=target_mac/spa=target_ip/tha=sender_mac/tpa=sender_ip/ether 单播）。**勘误**：legacy op=2 仍发"请求形广播帧"（buildARPPacket 硬编码广播+可变 oper）字节错位——重建修正 | RFC 826 语义；legacy 缺陷实录 |
| 4 | **校验双层**：registry operation uint16 [1,2]（V9 create-time 先火，锚 `out of range [1,2]`）；validator 拒 sender_ip/target_ip 格式错（锚 `invalid sender_ip`/`invalid target_ip`）+ IP/传输承载混入（锚 sv 同款 `must not have an ip/transport carrier`）；空层 {} 合法（零值→生成器缺省） | sv_neg_appid/sv_neg_ip_carrier 先例；P0b |
| 5 | **五件套（L2-only 族变体，非 raw IP 链）**：validateSpecBase :613 L2-only 豁免+=arp；validateBaseDstPortHandled+=arp；:1056 发射分支+=arp（EtherTypeARP）；flowMetaFor+=ARP；translateTerminalConfig case "arp" 手工映射（goose 同款）；FlowMeta+=ARP 字段；isL2OnlyProtocol+=arp（mapToFlowSpec 不填伪四元组）；rawWrapChains+="arp": "[eth,arp]"（presence 判死）；main.go 翻转（:538 legacy→NewChainPlanner，非空导入→空白）；registry 5 Fields→schemagen 113 层；pipe_gate/coverage_gate 接入 | goose/sv/isis 全套先例 |
| 6 | **B′ 账本**：RARP/InARP（oper 3/4/8/9）不实现；gratuitous ARP（spa=tpa 自宣告）不单列（oper=2 形可承载同等语义）；代理 ARP 不实现；IPv4 单一协议面（ptype 恒 0x0800）；无动态消费面——静态复制拒绝由框架层链门执法（checkLayerChainStaticCopy semantic.go:198，T-12 证，修轮 M2 补记） | 如实登记 |
| 7 | **回滚**：单提交粒度，摘除即回 | 家族口径 |

**文件清单：** core/types.go（ARPConfig +SenderMAC/SenderIP）+core/layers/{registry.go,chain_planner.go（:509/:613/:1056）,chain_planner_chain.go（flowMetaFor）,chain_planner_translate.go（case "arp"）,generator.go（FlowMeta.ARP）}+protocol/arp/{layer_gen.go 新,arp.go Planner 保留}+core/layers/arp_chain_test.go 链级红例 4 例（L1 勘误：原列 layer_gen_test.go 路径不实）+strategy_convert.go（isL2OnlyProtocol+rawWrapChains）+cmd/server/main.go 翻转+cases/arp.json 新+tools/{coverage_gate.py,pipe_gate.sh}+schemagen。

**性能（§6）：** 事件直发 channel 256（链框架）；包数=op1:2 帧/op2:1 帧（无握手挥手——L2-only）；pcap 路验收（网卡未跑如实）。
**接口签名：** `Generator{Name/GenEvents/Generate}`；`ValidateARPSpec(spec)` validator；ARPConfig{Operation,SenderMAC,SenderIP,TargetMAC,TargetIP}。

### 门 1 开工对照表（§1–§14，2026-09-22 arp P6 回填，证据=文档节/代码行/用例号）

| § | 本协议怎么满足 | 证据 |
|---|---|---|
| §1 层链唯一真相 | 顶层旧键不存在（L2-only 无端口面；顶层 arp 子映射 presence 判死=rawWrapChains "[eth,arp]"）；目标形 `{"layers":[{"eth":{"src_mac","dst_mac"}},{"arp":{"operation":1}}]}`；端口=不适用（L2-only，validateSpecBase 豁免） | SC rawWrapChains；cases/arp.json 8 例；pipe_gate 门2-1 绿 |
| §2 策略/任务分工 | 沿框架语义不另设；在库 0 策略+0 任务（新建协议无存量，报数对账平，备份 arp-purge-20260922.db） | P6 清库记录 |
| §3 五件套 | L2-only 单流协议写豁免：无子流派生/sessions/端口；事务序=op1 配对（request→reply）/op2 单发；时间线=帧序（门1 §3 行豁免声明） | `layer_gen.go` Generate；T-1 2 帧 |
| §4 规范矩阵 | RFC 826 反推八项三源；op=2 广播错位勘误（legacy buildARPPacket 硬编码广播）入 D- 裁定3 | D-ARP-1 P1 矩阵 |
| §5 有错必处理 | registry operation [1,2] V9 先火+ValidateARPSpec IP/MAC 格式锚+V-carrier 承载混入拒（complete.go 通用门） | `layer_gen.go`；T-5…7 |
| §6 性能 | 事件直发 channel 256；包数=op1:2/op2:1（无握手挥手）；pcap 路验收（网卡未跑如实） | D- 性能行 |
| §7 三份文档 | 设计=D-ARP-1；用例=T-ARP-1…9；cases 回指编号 | 三文档 |
| §8 先设计后代码 | P1/P2 定稿（D- 追加随 1f61887）先于用例（ef3bfb5） | git 历史 |
| §9 三源+整格 | RFC 826 字段序 28B 整格钉（T-2 五段全等）+T-3 显式四键 | arp.json |
| §10 评审闭环 | 自审轮次（钉位三轮红→pcap 修正实录/legacy op=2 勘误）+隔离对抗复审=收官独立轮 | P5 记录；复审轮 |
| §11 白话汇报 | 先一句结论再证据 | 各阶段汇报 |
| §12 动态清单 | 四元组=不适用（L2-only 无端口；MAC 进 eth 层）；业务键 operation/地址静态单值如实注记（无动态消费面）；flows>1 静态复制由框架层链门执法（checkLayerChainStaticCopy，T-12 证） | 门1 §12 行 |
| §13 schema 同步 | registry 5 Fields → schemagen 重生成 113 层 | generated/layers.generated.json（1f61887） |
| §14 真实流程 | MCP 建→引擎生成→tshark 校对；8/8 ×2；负例带锚词；钉从落盘 pcap（首轮 3 例红→重钉实录） | T-ARP-1…8；suite ×2 |

**门 3 抽查三条（P6）：** ①§3——T-1 配对帧序（帧1 广播 oper 0001/帧2 单播 oper 0002 角色互换）六钉 pcap 实证；②§5——T-5 锚 `out of range [1,2]`（V9 registry 先火）与 T-7 锚 `must not have an ip/transport carrier`（V-carrier 通用门，complete.go DependsOn eth 自动获得）双拦截点可点；③§14——suite 8/8 ×2+反查 17/17+门2-3 二进制同代（重编实录）。

**验收两门：** ①层链跑通=P5 绿；②旧格式移除=presence 判死+在库零行对账平。两门全过。

**P6 收官结论（白话一句）：** arp 接入 L2-only 族第 4 协议（goose/sv/isis 同型），RFC 826 28B 字节面逐格钉死，op=1 配对/op=2 宣告可编排可校验（legacy op=2 广播错位勘误），8 例 ×2 全绿、反查 17/17、门2 四项绿、在库零行对账平。

### 修轮块（2026-09-22 收官隔离复审 PASS-WITH-FINDINGS → 处置，红先绿后）

| 级 | 发现 | 处置 |
|---|---|---|
| M1 | 错误处理矩阵行5 的 MAC 半面（invalid sender_mac/target_mac）与 target_ip 无任何测试覆盖 | T-9/T-10/T-11 三负例补齐（validator 锚逐字）；反查 +3 |
| M2 | 静态复制拒绝例缺（12.9/12.15 面）且未入 B′ 账本 | T-12 补齐（eth 显式标量+flows=2 → 框架层链门锚 "static four-tuple"，sv_vn_static_copy 同款）；裁定6 补记。执法面勘误（定向复验修正）：checkLayerChainStaticCopy（semantic.go:198，:142 调用，eth 层扫 MAC）非 flat 兄弟 checkStaticCopy（:135） |
| L1 | 文件清单 layer_gen_test.go 路径不实（实为 core/layers/arp_chain_test.go） | 清单勘误（本块同批） |
| L2 | tools_integration_test.go 两处陈旧注释（arp.NewPlanner） | 两处改为 layers.NewChainPlanner("arp") |
| L3 | FlowID 不设（goose 实设 FlowID——"goose 同款"表述不准）；下游仅日志/透传面，pcap 字节与任务语义不受影响 | 如实注记（本行即登记）；不补 FlowID（无消费面，YAGNI） |
| L4 | EtherType 双写（layer_gen:82+CP:1081）同常量纯冗余 | 家族模式（goose/sv/isis 同分支同型），不改；本行登记 |
| L5 | CORE_MEMORY 13.6 "95 层字段表"计数过期（实 113 层） | 用户维护文档只报不改——已向用户报告 |

修轮后：suite 12/12 ×2、反查 22/22、门2 四项绿（重编实录）、touched 包 -race 绿、vet 净。

## D-ICMP-1 icmp 层链收敛（#33，2026-09-22 已验收：af02651 P4 / 1b4e440 P5 / P6 清库+门表，裁定=raw-IP 面线面复用+icmpv6 对称重建）

### P1 规范矩阵（§4 八项；三源=RFC 792 + legacy 行为面实录 + icmpv6/igmp 家族先例）

| 项 | 规范要求 | 业务场景 | 代码现状 | 缺口 |
|---|---|---|---|---|
| 1 连接模型 | 无连接：IPv4 直载（IPPROTO=1），Echo 请求/应答对 | 探针面 ping | legacy Planner 直发（main.go:537），无层链接线 | 五件套缺——本主体 |
| 2 命令/消息表 | type 8/0=Echo Request/Reply（RFC 792 §Echo）；3/5/11/12 等差错型 | ping 对/多轮 | ICMPConfig.Type 单键+Pattern 多轮（f7 面已有） | registry+validator 锚（裁定4） |
| 3 状态机 | 无状态；Echo 对靠 id/seq 绑定（RFC 792：Identifier 分组会话、Sequence 会话内递增；id=0 回退 Sequence） | ping 会话 | legacy 已实现（单 ping/Pattern 两路） | 保留（裁定1） |
| 4 字段表 | 8B 头=Type1+Code1+Checksum2+Identifier2+Sequence2+data（RFC 792） | 全字段可配 | buildICMPPayload 含校验和 | 线面复用（裁定1） |
| 5 错误处理表 | type/code 语义域校验 | 负例锚 | legacy Validate 仅查 IP 格式 | validator 逐步校验（裁定4） |
| 6 超时与活性 | 不适用（无重传语义） | — | 不适用 | 不适用（如实） |
| 7 NAT/被动 | 不适用 | — | 不适用 | 不适用（如实） |
| 8 版本方言 | RFC 792 单一（RFC 1122 增补注记）；ICMPv6 属姊妹协议（D-ICMPV6-1 已链化） | — | 单版 | B′ 注记 |

**三张子表：** ①type×语义（8=request/0=reply，auto-reply 面）②形态变体（单 ping/Pattern 多轮）③商业映射（无参考 pcap——在库 0 tasks，legacy 行为面替代，如实）。

### 裁定（P2 定稿）

| # | 裁定 | 依据 |
|---|---|---|
| 1 | **线面复用零字节分歧**：legacy Plan（Echo 配对/Pattern 多轮/FileSource 优先级/校验和）全保留，layer_gen 包装直传（icmpv6 Generator 同款：Meta.ICMP 直传、Direction 强制 "up" 防双换——legacy reply 已完成 L3 地址换向） | icmpv6 layer_gen 先例；D-ICMPV6-1 零字节分歧口径 |
| 2 | **层形状 [ip, icmp]**，6 键 `{type, code, identifier, sequence, data, pattern}`（file_source 不映射=③ C 类，icmpv6 同口径）；registry FieldContract `ip.protocol: 1`（IPPROTO_ICMP）；无 Default（缺省 translate 镜像 flat parse：type 8/code 0/seq 1/data "ping"，决策 D1） | icmpv6 registry 行；strategy_convert:507 flat parse |
| 3 | **编排**：单 ping（type=8 自动配对 reply=2 帧；type=0 单发 1 帧）；Pattern 非 0 逐步发射、8 步自动 reply、step seq 缺省 index+1（RFC 792 会话语义 legacy 已实现） | legacy Plan 两路面 |
| 4 | **validator 逐步校验**（icmpv6 §5 同款）：type∈{8,0}（锚 `icmp type must be 8 (Echo Request) or 0 (Echo Reply), got %d`）、code=0（锚 `icmp code must be 0 for Echo, got %d`）、pattern step type∈{8,0}（锚 `icmp pattern step %d type must be 8 or 0, got %d`）；IP 族检查复用 legacy Validate（HasLayerDynIP 豁免同 icmpv6 D-FTP-4 口径） | icmpv6 validateLayer 全对称 |
| 5 | **五件套（raw-IP 族变体）**：isRawIPChain 双名单+=icmp（第 24 协议）；FlowMeta.ICMP+flowMetaFor；translateTerminalConfig case "icmp" 手工映射（6 键+pattern 槽位下钻）；registry 6 Fields→schemagen 114 层；validateBaseDstPortHandled+=icmp；validateSpecBase raw-IP 端口豁免 switch+=icmp（:764——src/dst 端口 0 保持 0）；mapToFlowSpec case "icmp" 清端口（icmpv6 同款——L4 恒不发射）；rawWrapChains+="icmp": "[ip,icmp]"（顶层 icmp 子映射 presence 判死）；main.go 翻转（:537 legacy→NewChainPlanner+空白导入）；pipe_gate/coverage_gate 接入 | icmpv6 五件套全对称；raw 家族第 12 协议 |
| 6 | **B′ 账本**：非 Echo 型（3 目标不可达/5 重定向/11 超时/12 参数问题/13/14 时间戳）不编排（legacy 单发面保留但层链 validator 不放行——Echo 语义收窄同 icmpv6 决策）；FileSource 层链不映射（C 类，flat 判死后经 MCP 不可达，单测面保留）；广播/组播 ping 面不实现 | icmpv6 B′ 对称；如实登记 |
| 7 | **回滚**：单提交粒度，摘除即回 | 家族口径 |

**文件清单：** protocol/icmp/{layer_gen.go 新}+core/layers/{registry.go,chain_planner.go（:509/isRawIPChain 双名单经 util）,chain_planner_chain.go（flowMetaFor）,chain_planner_translate.go（case "icmp"）,generator.go（FlowMeta.ICMP）,icmp_chain_test.go 链级红例}+core/strategy_convert.go（isRawIPChain util 双名单+rawWrapChains+case "icmp" 清端口）+cmd/server/main.go 翻转+cases/icmp.json 新+tools/{coverage_gate.py,pipe_gate.sh}+schemagen。

**性能（§6）：** 复用 legacy Plan（channel 256 流式）；包数=单 ping 2 帧/type=0 单发 1 帧/Pattern 2×#8步；pcap 路验收（网卡未跑如实）。
**接口签名：** `Generator{legacy *Planner; Name/GenEvents/Generate}`；validateLayer（链路径）。

### T-ICMP-1…8 清单（P3；9.52 对账：分项和 8=建例 8（T-1…8 各 1 点），可复算；链级红例=单测面不占号）

| # | 用例 | 断言面 |
|---|---|---|
| T-1 | smoke 配对（缺省） | 2 帧；ip.proto=1；icmp.type p1=8/p2=0；角色互换（src/dst 换向） |
| T-2 | 头字节钉 | 8B 头整钉（type 08/code 00/校验和/id=seq=1 回退面）+data "ping"@42；体首=帧偏移 34（eth14+ip20） |
| T-3 | 显式 id/seq/data | identifier/sequence/data 覆盖 → 头钉 |
| T-4 | Pattern 多轮 | 2×echo 步 → 4 帧；seq 1/2 递增；data 逐字节 |
| T-5 | 负例 type=3 | 锚 `icmp type must be 8 (Echo Request) or 0 (Echo Reply), got 3` |
| T-6 | 负例 code=1 | 锚 `icmp code must be 0 for Echo, got 1` |
| T-7 | 负例 presence | 层链+顶层 icmp 子映射并存 → `no longer accepts a top-level icmp` |
| T-8 | 负例静态复制 | ip 层显式标量+flows=2 → 框架层链门 `static four-tuple`（icmpv6_vn_static_copy 同款） |

### 门 1 开工对照表（§1–§14，2026-09-22 icmp P6 回填，证据=文档节/代码行/用例号）

| § | 本协议怎么满足 | 证据 |
|---|---|---|
| §1 层链唯一真相 | 顶层旧键不存在（无端口面；顶层 icmp 子映射 presence 判死=rawWrapChains "[ip,icmp]" 第 24 协议）；目标形 `{"layers":[{"ip":{"src","dst"}},{"icmp":{"type":8}}]}`；端口=不适用（validateSpecBase raw-IP 豁免 :764） | SC rawWrapChains；cases/icmp.json 8 例；pipe_gate 门2-1 绿 |
| §2 策略/任务分工 | 沿框架语义不另设；在库 0 策略+0 任务（新建协议无存量，suite 产物自清，报数对账平，备份 icmp-purge-20260922.db） | P6 清库记录 |
| §3 五件套 | raw-IP 单流协议写豁免：无子流派生/sessions/端口/会话；事务序=单 ping Echo 对/Pattern 多轮；时间线=帧序（门1 §3 行豁免声明） | legacy Plan 两路面；T-1 2 帧/T-4 4 帧 |
| §4 规范矩阵 | RFC 792 反推八项三源；Echo 语义收窄（非 Echo 型 B′）入 D- 裁定4/6 | D-ICMP-1 P1 矩阵 |
| §5 有错必处理 | validator 逐步校验（type/code/pattern step 三锚）+registry V9+legacy IP 格式复用+HasLayerDynIP 豁免 | `layer_gen.go`；T-5/T-6 |
| §6 性能 | 复用 legacy Plan（channel 256）；包数=单 ping 2/type0 单发 1/Pattern 2×#8步；pcap 路验收（网卡未跑如实） | D- 性能行 |
| §7 三份文档 | 设计=D-ICMP-1；用例=T-ICMP-1…8；cases 回指编号 | 三文档 |
| §8 先设计后代码 | P1/P2 定稿（D- 追加随 af02651）先于用例（1b4e440） | git 历史 |
| §9 三源+整格 | 8B 头整格钉（T-2 五段+校验和预计算对拍）+T-3 显式四键+T-4 Pattern | icmp.json |
| §10 评审闭环 | 自审轮次（钉位两轮红→pcap 修正实录/端口豁免第五接线点补录）+隔离对抗复审=收官独立轮 | P5 记录；复审轮 |
| §11 白话汇报 | 先一句结论再证据 | 各阶段汇报 |
| §12 动态清单 | 四元组=不适用（无端口；ip 层地址）；业务键 type/地址静态单值如实注记；flows>1 静态复制由框架层链门执法（T-8 证） | 门1 §12 行 |
| §13 schema 同步 | registry 6 Fields → schemagen 重生成 114 层 | generated/layers.generated.json（af02651） |
| §14 真实流程 | MCP 建→引擎生成→tshark 校对；8/8 ×2；负例带锚词；钉从落盘 pcap（首轮 2 例红→重钉实录） | T-ICMP-1…8；suite ×2 |

**门 3 抽查三条（P6）：** ①§3——T-1 Echo 对帧序（p1 type=8/p2 type=0+src/dst 换向）pcap 实证；②§5——T-5 锚 `icmp type must be 8 (Echo Request) or 0 (Echo Reply), got 3`（validator 唯一产地 layer_gen.go）+T-8 锚 `static four-tuple`（checkLayerChainStaticCopy 层链门）双拦截点可点；③§14——suite 8/8 ×2+反查 18/18+门2-3 二进制同代（重编实录）。

**协议天花板豁免声明（修轮 L2 补记）：** icmp 为无连接 2 帧面 ping 协议（单 ping/Pattern 多轮即全部编排面），复合大场景交织维度天花板=多事务+自动应答（T-4 已达）——9.50 三类下限/9.53 抽最复杂例对 icmp 显式 N/A（goose/sv/igmp 无会话族同型，非偷懒豁免）。

**验收两门：** ①层链跑通=P5 绿；②旧格式移除=presence 判死+在库零行对账平。两门全过。

**P6 收官结论（白话一句）：** icmp 收官（raw-IP 族第 12 协议、icmpv6 全对称），RFC 792 Echo 面 8B 头逐格钉死（校验和预计算对拍），单 ping/Pattern 多轮可编排可校验，8 例 ×2 全绿、反查 18/18、门2 四项绿、在库零行对账平。

### 修轮块（2026-09-22 收官隔离复审 PASS-WITH-FINDINGS → 处置）

| 级 | 发现 | 处置 |
|---|---|---|
| M1 | P6 清库对账打在过期库上——live 库（服务端 cwd 相对路径 /tmp/tg-sv-p5/data/trafficgen.db，独立谱系 996 策略/4435 任务）含 icmp 套件产物 3 策略+24 任务，repo 根 187MB 库为 9-19 冻结旧谱系；"suite 产物自清"实测不成立（tools_testdrive.go:205-211 清理尽力而为） | **live 库补做清账**：报数 3 策略+24 任务 → 备份 /tmp/tg-sv-p5/data/trafficgen-icmp-purge-20260922.db → DELETE → 对账 0/0（总量 993/4411）；repo 根旧备份 trafficgen-icmp-purge-20260922.db 标记废弃（9-19 冻结快照，勿再用作对账证据）。**纪律增补：P6 清库对账必须打在 live 库（服务端 cwd 相对 DB 路径）** |
| M2 | 两个新增分支零 icmp 专属覆盖：HasLayerDynIP 豁免（layer_gen.go validateLayer）+translate pattern step seq==0 自动补 index+1 | 链级红例⑤⑥补齐（TestICMPChain_DynamicIPExempt 动态 ip 豁免 2 包/TestICMPChain_PatternSeqAutoFill 显式 0+缺省 → seq 1/2） |
| L1 | 门2-3 在提交时点实红（gofmt 三文件晚于二进制 15:12）——纯格式零语义，复审已按 HEAD 重编闭环 | 修轮重编重启再跑（本块实录）；纪律：提交前 gofmt -l 全 touched 目录 |
| L2 | 9.50/9.53 复合大场景下限未达标且未显式声明天花板豁免 | 门3 表后补显式 N/A 声明（无连接 2 帧面天花板，无会话族同型），不补例 |
| L3 | CORE_MEMORY 13.6 计数过期（113→114 层） | 用户维护文档只报不改——已向用户报告 |
| 观察项 | snmp maskSNMPVolatile（chain_planner_snmp_test.go:42）硬编码 02 04 BER 掩码，request-id<2^24 时编码 02 03 掩蔽落空 → 偶发对拍红（存量 flake，snmp 文件未被本协议触碰） | 登记转交 snmp P-PIPE（序号 120）优先修 |

修轮后：suite 8/8 ×2、反查 18/18、门2 四项绿（重编实录）、touched 包 -race 绿、vet 净、live 库 icmp 行 0/0 对账平。

## D-CWMP-1 cwmp 配置承载迁层（#34，P-PIPE 进行中：裁定=行为面零改动+B6 注入形迁层链唯一真相）

> 行为面权威=`docs/protocol-designs/64-cwmp-design.md` v2.2.2（TR-069 Issue 1 A6 Corr 1；150 例 clean 于 B6 40a479b）。本条目只管**配置承载面迁移**：顶层 `cwmp` 子映射（B6 注入形，"层 config 恒空"）→ cwmp 层 config，行为字节零改动。

### P1 规范矩阵（§4 八项确认形态——行为面 B6 已定，本 P-PIPE 逐项确认符合态 + 承载面缺口）

| 项 | 规范要求（B6 契约节） | 代码现状 | 缺口 |
|---|---|---|---|
| 1 连接模型 | HTTP/1.1 over TCP，CPE=HTTP client；acs_cr 反向会话（§1/§2） | layer_gen sessionRun role=cpe/acs_cr，DstIP/DstPort 逐会话覆盖 | 无（150 例覆盖双角色） |
| 2 命令/消息表 | Inform/InformResponse/GetRPCMethods/Download/Upload/TransferComplete/fault/empty POST（§3.5 Annex A） | builder.go kind 全枚举；150 例 kind 全落格 | 无 |
| 3 状态机 | 事务交替（一帧一事务侧）、cwmp:ID 请求自增/响应回显关联、Set-Cookie/Cookie 回显（§5） | sessionRun{lastWasUP,autoIDCtr,pendingReqID/Kind,cookie} | 无 |
| 4 字段表 | SOAP 1.1 envelope+Header(id/holdTime)+HTTP 头序（§3.1–3.3） | builder.go 钉死；T 契约 §3 偏移断言 | 无 |
| 5 错误处理 | 负例锚词表（§7） | validator validateConfig/Session/Flows；41 负例在案 | 无 |
| 6 超时与活性 | HTTP 面无重传语义（§8 边界） | 不适用如实 | 无 |
| 7 NAT/被动 | 不适用 | 不适用如实 | 无 |
| 8 版本方言 | namespace cwmp-1-0/1-1/1-2（SOAP 1.2 envelope 拒）；profile 三值（https 边界明文链拒）（§1/§3.7.4） | validateConfig 双 switch；负例在案 | 无 |
| **承载面** | §1 层链唯一真相：业务配置住层内 | 顶层 `cwmp` 子映射注入（registry"层 config 恒空"）×150 例；顶层子映射=1.11–1.13 白名单外游离字段 | **G1 迁层+判死+整形（本 P-PIPE 主体）** |

三源：TR-069 标准文本（B6 契约逐条标注出处）+ 本仓 legacy 实现面（builder/layer_gen/planner）+ B6 需求契约 v1.3（150 例行为面全枚举）。商业参考 pcap：无（B6 ③子表如实声明沿用）。

### 缺口清单（门1 输出，P4 逐项闭合）

- G1 配置承载：顶层 `cwmp` 子映射 ×150 例 → 迁入 cwmp 层 config；CheckProtoFlat 加 cwmp presence 判死（dns/mqtt/smtp 先例）；在库 0|0（2026-09-22 实测）无存量迁移面。
- G2 D-CWMP-1 条目缺失（§7 CODE_DESIGN 唯一入口）→ 本条目。
- G3 T-CWMP 节缺失（TEST_CASES）→ P3 补审计注记（150 例 B6 契约回指 + 承载面新负例）。
- G4 coverage_gate 无 check_cwmp → P3 补。
- G5 pipe_gate presence 组错位（cwmp 现挂 http 族 "http" 键组）→ P4 移自键组。
- G6 registry cwmp 层 Fields 缺失（层无法承载配置）→ P4 补六键 + schemagen 再生。

### 裁定（P2 定稿）

1. **行为字节零改动**：builder/layer_gen/planner/validator 的行为面代码零改动（150 例 pcap 基线不变=验收线）；迁移只动**配置解析路径**。
2. **层 Fields 六键**：`profile`(string)/`namespace`(string)/`concurrent`(bool)/`sessions`(list)/`flows`(list)/`auth`(object)——CWMPConfig 顶层键同名（smtp/ftp 同款：V9 只验顶层键存在，嵌套值语义归 translate JSON 往返 + validator）。
3. **translate case "cwmp"**：层 config → JSON 往返 → `spec.CWMP`（smtp `:2017` 同款；带 "flat 权优" 守卫镜照 smtp——在库 legacy 行若存顶层键由判死门 400/ValidationErrors 兜住，守卫纯防御）。空层 config 翻译出零值 config → 生成器/validator 走 P0b 基线单会话（现状口径，validator nil 放行 + 生成器 len==0 补基线，零改动）。
4. **判死双门**：CheckProtoFlat 加 `cwmp` 顶层子映射 presence 判死（文案 "protocol cwmp no longer accepts a top-level cwmp sub-config (move it into the cwmp layer of a [ip,tcp,http,cwmp] layers chain)"，presence 负例豁免口径与 http 族一致）；mapToFlowSpec 在库 switch（`:368` 区）加 cwmp → 存量行启动 ValidationErrors。mapToFlowSpec case "cwmp"（`:576`）保留（smtp/dns/mqtt 先例：新建路径已被判死，存量行由 switch 兜底）。
5. **150 例整形**：脚本化——`spec_json` 顶层 `cwmp` 值原样移入 `layers[3]["cwmp"]`（层槽恒在，现恒 `{}`）；字节面断言（packet_count/has_handshake/钉位）零变化。
6. **新负例**：①顶层 `cwmp` 子映射+layers 并存 → 400 presence 负例（锚 `top-level cwmp sub-config`）；②cwmp 层未知字段 → V9 锚 `unknown field`；③空层 cwmp = 基线单会话正例（13.20 缺省面钉）。
7. **gate**：pipe_gate cwmp 移自键组（presence 键="cwmp"）；coverage_gate 补 check_cwmp。
8. **动态面**：业务键（sessions/transactions/auth 全键）静态单值——B6 未做业务动态（会话端点覆盖=静态 per-session 值非策略），声明无动态消费面；四元组走 ip/tcp 层框架策略（150 例静态直发）。cwmp:ID 自增=序号算法（layer_gen autoIDCtr，B6 §9 ID 权威），非动态策略面。
9. **回滚**：单提交粒度摘除（registry Fields+translate case+判死+cases 整形各归一提交）。

### 门 1 开工对照表（§1–§14，2026-09-22 cwmp P6 回填，证据=文档节/代码行/用例号）

| § | 要求 | cwmp 怎么满足 + 证据 |
|---|---|---|
| §1 | 层链唯一真相 | 150 例顶层 `cwmp` 子映射迁入 cwmp 层六键（beec434）；presence 判死（SC CheckProtoFlat + T-151）；目标形 `{"layers":[ip,tcp,http,cwmp六键]}`（cases 首例）；在库 0\|0（live 库两清对账平） |
| §2 | 策略/任务分工 | 框架语义未动；T-153 空层缺省面=单策略模板可复用 |
| §3 | 五件套 | 会话表 sessions[]（一连接一会话）/事务序列 transactions[]（kind 定方向）/关联 flows[] driven_by 锚点+Set-Cookie 回显+id 关联/插入位置（副连接锚点后）/时间线（sequential|concurrent 轮转）——B6 设计 §5 + layer_gen sessionRun 状态机 |
| §4 | 规范矩阵 | TR-069 Issue 1 A6 Corr 1 基线，八项确认态+承载面缺口（本条目 P1 表）；B6 契约逐条标注出处 |
| §5 | 依赖与错误处理 | DependsOn http + FieldContract tcp.dst_port=7547（RG）；validator 双层 device_id 校验+profile/namespace 域+B6 §7 锚词表（41 负例在案） |
| §6 | 性能与验收 | 包数公式（每事务 1 帧+TCP 3+4）；pcap 路 suite ×2；网卡路框架级注记（家族口径） |
| §7 | 三份文档 | B6 契约（protocol-designs/64-cwmp-*）+ D-CWMP-1 + T-CWMP-1…153 |
| §8 | 设计先行 | B6 契约 v2.2.2 先于实现（历史）；本迁移 D-CWMP-1 裁定 9 条先于 P4 落地（6912ba5 同提交粒度，如实注记） |
| §9 | 测试三源+颗粒度 | 三源=TR-069 标准文本+D-CWMP-1+legacy 行为面；150 例 B6 契约全枚举（109 正+41 负）+3 新例；一例一行为点 |
| §10 | 评审闭环 | 每阶段自审+收官隔离复审（子代理）+修轮定向复审；红先绿后（链级红例 8+负例 153 例中 43） |
| §11 | 白话汇报 | 每阶段白话一句先行（P4/P5/P6 汇报口径） |
| §12 | 动态字段 | 四元组走 ip/tcp 层框架策略；业务键静态单值如实声明（裁定8）；cwmp:ID 自增=序号算法面（layer_gen autoIDCtr，B6 §9 ID 权威） |
| §13 | schema | registry 六键→schemagen 再生（TestLayersGeneratedMatchesRegistry 绿）；V9 只验顶层键、嵌套值语义归 translate+validator |
| §14 | 真实流程 | suite 153/153 ×2（MCP 建任务→引擎生成→tshark 校对）；pcap 落盘 /tmp/mcp-pcaps/cwmp/；负例 43 锚词真红 |

### P4 勘误块（2026-09-22，红先绿后——两处非承载面发现，处置实录）

1. **事务级 device_id 死配置（行为面，B6 遗留）**：validator 校验 tx.DeviceID（planner.go validateDeviceIDRef）但发射路径只读会话级 ifaceDevice(run.sess.DeviceID)——155 处事务级 device_id 静默忽略（套件 0 体字节钉位所以 B6 全绿未被察觉）。修复：tx 优先、回退会话级（layer_gen.go inform 分支一行）；链级红例⑤ 先红后绿。**裁定1 例外声明**：本勘误使带事务级 device_id 的用例 inform 体字节改变（DeviceIdStruct 按配置上线）——帧数/方向/事务结构零变化（packet_count 断言全部保持），属"配置意图得以执行"而非行为回退；B6 契约 §6 typedef 本就定义事务级 device_id 覆盖语义（validator 同证），此处是让死配置活过来。
2. **mss 死键删除（承载面）**：cwmp_mss_large_soap_200_params 旧顶层注入形下嵌套 `cwmp.tcp={"mss":1460}` 无任何消费者（CWMPConfig 无 Tcp 字段、全仓无 ["cwmp"]["tcp"] 读取点；mss 1460=引擎默认值）——迁入层后被 V9 硬拒，删除死键（行为零变化，packet_count 32 断言保持）。

3. **会话 URI 空请求行死缺省（修轮修3，行为面，主线程自主发现）**：`BuildRequest` 写 `method+" "+uri+" HTTP/1.1"` 无 URI 兜底——CWMPSession.URI 注释承诺缺省 `/`（emitFlow 对 fl.URI 有同款兜底 layer_gen.go:733，主会话侧漏兜），实际线上请求行=`"POST  HTTP/1.1"` 空 request-target，违反 RFC 7230 origin-form（真实 ACS 必 400）。零字段钉位（M1）使其不可见。修复：Generate 会话拷贝处补缺省 `/`（layer_gen.go session copy）；链级红例⑧ RequestLineTarget；红证据=修前 pcap 字节（tshark -x f4@54 `POST  HTTP/1.1` 实录）+突变可逆（回退 fix ⑧ 必红）。裁定1 例外同①：全部请求行获得合法 target，帧数/方向/事务结构零变化。

### 修轮块（2026-09-22 收官隔离复审 PASS-WITH-FINDINGS → 处置）

| 级 | 发现 | 处置 |
|---|---|---|
| M1 | 用例断言强度不足：153 例 `fields`=0/`frames`=0，B6 §4/§5 声明的字段/hex 断言面未落地 | 六行为族各取代表例按族抽钉（inform/get/set/download/CR/digest 六例，fields=http 方法/uri/响应码，frames=请求行/状态行/SOAP 方法元素/SerialNumber/WWW-Authenticate/Digest 全行，全部从修后落盘 pcap 钉）；其余例保持结构三件套，T-CWMP 如实登记「字段面按族抽钉」口径 |
| M2 | ValidateSpec 翻译守卫无链级红例（M4 突变：删守卫链级全绿） | 链级红例⑦ TranslateErrorGuard（uint32 溢出 delay_seconds→Validate 报 `cwmp layer config:` 前缀错误） |
| M3 | device_id 会话回退半边无例覆盖（M5c 突变全绿） | 链级红例⑥ SessionFallbackDeviceID（tx 无 device_id→会话级值上线） |
| M4 | 红例④与 registry 改动耦合（M3 突变以包数面貌红） | ④加注记：registry 六键存在性由红例③专断，④包数断言不重复该职责（深突变面貌误导已在注说明） |
| L1 | 门1 §10/§14 「负例 44」实为 43（has_payload 正例口径混入） | 已改 43 |
| L2 | 64-cwmp-testcase.md 头部计数 112+38 与实测 109+41 不符 + 状态行陈旧 | v3.1.2：头部状态/计数更新+修订记录 |
| L3 | 64-cwmp-design.md §6 typedef 仍旧顶层形状+wire_fault 未实现键 | v2.2.3：§6 改层链目标形，wire_fault 标注「设计期注入口未实现，负例经逐事务畸形值表达」 |
| L4 | coverage_gate device_id 行查用例 id 而泛锚 value | 用例锚词升级为 validator 具体文案 `not six uppercase hex digits`，gate 行改同锚 |
| L5 | in-store 防御分支无红例 | 本块登记：纯防御（在库 cwmp 0 条），不设红例 |

| N1（定向复验 NEW） | 红例⑧ RequestLineTarget 空断言（原实现 [:15] 切片与 14 字节串比相等恒 false——突变回退修3 后 ⑧ 仍绿） | 一行修：改 `strings.HasPrefix(payload, "POST  HTTP/1.1")`；突变自验：回退 URI 兜底→⑧ 红（报文 `empty request-target on the wire`）、本树 8/8 绿 |

修轮后：suite 153/153 ×2（含六例新钉）、反查 20/20、门2 四项绿、race/vet 绿；N1 修后链级 8/8（突变双向验证）。

### 文件清单（P4）

- Modify: `internal/core/layers/registry.go`（cwmp 层 Fields 六键）
- Modify: `internal/core/layers/chain_planner_translate.go`（case "cwmp"）
- Modify: `internal/core/strategy_convert.go`（CheckProtoFlat cwmp 分支 + `:368` 区在库 switch cwmp）
- Modify: `tools/pipe_gate.sh`（presence 组移位）
- Modify: `tools/coverage_gate.py`（check_cwmp）
- Regenerate: schemagen 产物（layers.generated 等）
- Reshape: `test/protocol_pcap/cases/cwmp.json`（150 例迁层 + 新增负例/缺省例）
- Test: 链级红例（`internal/core/layers/cwmp_chain_test.go`：层 config 注入 2 包对照 / presence 判死锚 / V9 未知字段锚 / 空层基线）
- 接口签名：`validateLayer` 零改动（validator 走 spec.CWMP）；`FlowMeta.CWMP` 零改动（translate 填充源变更）。

## D-KINGBASE-1 kingbase 协议身份退役·收敛 postgresql dialect（#35，P-PIPE 进行中：裁定=身份退役+死遗留删除+dialect 面确认）

> **P1/P2 期间裁定升级（2026-09-22）**：kingbase 作为协议身份**退役**——唯一合法形态 = postgresql 层 `dialect: "kingbase"`（执行序表"不独立接线"+ 18-layer-config-design.md §2.2/§4.3/§7 F4 收敛裁定的完成式）。依据三实：①15 例 cases 全部 `proto: "postgresql"`（`CASE_PROTO=kingbase` 装载 0 例）②`protocol: "kingbase"` 策略可建但执行期撞 V10（protocol≠最外层非脚手架层 postgresql → `does not match outermost layer`，红例实证）＝**可建不可跑陷阱** ③strategy.json 的 `protocol` 是裸 string 无 enum，schema 面从未承认过 kingbase（非"枚举被删"——复审措辞勘正）。退役 = 补上白名单这最后一块，使"不可跑"变成"不可建"（前置 400），消灭陷阱。
> 行为面权威 = 共享 PG v3 wire（postgresql 层 + pgwire）+ dialect 契约（54321/profile 域）+ 15 例。本条目 = 身份退役 + 死遗留删除 + dialect 面确认。

### P1 规范矩阵（§4 八项——dialect 面逐项确认符合态；协议身份面=退役裁定）

| 项 | 要求 | 现状 | 缺口 |
|---|---|---|---|
| 1 连接模型 | TCP；端口 54321（金仓默认，区别 pg 5432） | CP:457 dialect 分支+RG FieldContract dialect 映射（registry.go:1667） | 无 |
| 2 命令/消息表 | PG v3 消息族共享（startup/query/password/…） | 共享 pgwire；wire_profile 域（pg validate.go:17-19，含 kingbase_es_v8_pg_compatible/kingbase_native_pending） | 无 |
| 3 状态机 | c2s 需 ready 门 | pgSessionState（pg validate.go） | 无 |
| 4 字段表 | 共享 PG v3 编码 | pgwire 共享（dialect 对字节构造无感——pg layer_gen.go 注释） | 无 |
| 5 错误处理 | 变体负例锚词 | 6 负例全具体锚（tcp/54321/profile/state/length/limit） | 无 |
| 6 超时与活性 | 不适用（数据库请求-响应面） | 如实 | 无 |
| 7 NAT/被动 | 不适用 | 如实 | 无 |
| 8 版本方言 | dialect 双值+profile 域 | validator 双 switch（validate.go:38/47 特判 kingbase_native_pending） | 无 |
| **承载面** | 层链唯一真相 | **已合规**：15 例全层链形+dialect 键，顶层零残留（与 cwmp 相反，无迁移面） | 无 |
| **协议身份面** | 准入白名单=唯一权威 | **退役前现状：白名单仍收 kingbase → 可建不可跑陷阱** | G5（退役） |

三源：PostgreSQL v3 协议规范（共享层，P0a postgresql 范本已核）+ 人大金仓 KingbaseES PG 兼容行为面（15 例+wire_profile 域）+ 本仓 dialect 收敛设计（18-layer-config-design.md）。

### 缺口清单（门1 输出，P4 逐项闭合；G5 原判死补门方案被退役裁定取代）

- G1 D-KINGBASE-1 条目（§7 唯一入口）→ 本条目。
- G2 T-KINGBASE 节 → P3 补 15 例审计注记（含 proto=postgresql 跑法口径）。
- G3 coverage_gate check_kingbase 缺 → P4 补（退役面+dialect 承载面双检）。
- G4 pipe_gate kingbase 分支缺 → P4 补显式退役分支（无自键 presence 门，裁定4；kingbase.json 顶层残留=仅 layers 由通用检查覆盖）。
- **G5（裁定升级）协议身份退役**：`protocols.go` 白名单摘除 kingbase + `protocols_test.go` want 表同步 + kingbase 入 negativeOnly 拒绝清单（must remain rejected）。效果：`protocol: "kingbase"` create → 400 `invalid or missing protocol`（semantic.go:120 首拦）；在库旧行启动 `invalid protocol`（convert.go:111）。**原判死补门方案（CheckProtoFlat 加 kingbase 顶层子映射 presence 分支）作废**——protocol=kingbase 在白名单即死，CheckProtoFlat(kingbase,…) 创建路径不可达；**残留洞如实登记**：已准入协议（如 postgresql）配置里游离顶层 `kingbase` 键现状被静默忽略——此为 config 级 unknown-key 白名单缺失的**框架面缺口**（strategy.json config 无 additionalProperties:false），不属本协议可修范围，且按 1.11-1.13 口径禁加"kingbase 单键黑名单分支"（漏点照样红）；立项框架级补口（⬜ 登记）。复审附记两条全协议既有注记同批立项：①pipe_gate"顶层子映射并存"黄线只告警不置红；②coverage_gate 对未登记协议 exit 2 判黄不挡路。
- G6 死遗留面删除：`internal/protocol/kingbase` 包整删（builder/planner/layer_gen/kingbase_test，1838 行）+ `FlowSpec.KingBase`（types.go:1727）+ `KingBaseConfig/KingBaseSession/KingBaseEvent`（types.go:1291-1313）+ `FlowMeta.KingBase`（generator.go:370）+ translate `KingBase:` 行（chain_planner_translate.go:129）+ main.go:88 空导入。依据：①spec.KingBase 零写入点（case "kingbase" 已收敛，translate 无 case）②注册的 "kingbase" 层无 registry 行=链不可达（V9 unknown layer 即拒）③行为覆盖已由 pg 包测试+layers 链级测试（postgresql_kingbase_test.go）+15 例承载 ④删除即退役裁定的实体化。
- kingbase_chain_test.go（早前 P4 草稿 2 例）随裁定作废，未提交前已从工作区移除（从未入库）：①presence 红例依赖 CheckProtoFlat 分支=方案作废；②dialect 端口契约红例与 postgresql_kingbase_test.go 既有覆盖重复。退役守卫改住 core 包 protocols_test.go（negativeOnly 清单+want 表双点）。

### 候选方案对比（§4.17）

| 候选 | 内容 | 优劣 | 取舍 |
|---|---|---|---|
| (a) 身份退役（选定） | 白名单摘除 kingbase，唯一形态=postgresql 层 dialect=kingbase | 优：消灭"可建不可跑"陷阱（前置 400）；删除 1838 行死码；与 strategy.json/F4 收敛对齐。劣：protocol=kingbase 旧行在库启动报错（在库实测 0 行，无实害） | 三实证据支撑：cases 全 proto=postgresql / V10 执行期拒绝 / schema 面从未承认 |
| (b) 独立接线 | 补 ChainPlanner("kingbase") 注册+顶层支持 | 劣：与"不独立接线"裁定直接冲突；需反向复制 PG 层 15 例语义；维护面翻倍 | 违背 18-layer-config-design.md §2.2/§4.3/§7 F4，弃 |

### 裁定（P2 定稿）

1. **协议身份退役（G5）**：白名单摘除；kingbase 进 negativeOnly 拒绝清单；测试先行（want 表+negativeOnly 先改 → 红 → 摘白名单 → 绿）。
2. **死遗留删除（G6）**：整包+死 Meta/types/translate 行/空导入；预期编译期暴露全部引用点；删除后 "kingbase" 层名行为不变（无 registry 行=unknown layer，现状即如此）。
3. **dialect 面零改动**：postgresql 层 dialect=kingbase 行为不动，15 例 pcap 基线不变=验收线；suite 经 `CASE_PROTO=postgresql` 跑（postgresql.json+kingbase.json 同载，cases 自带 proto=postgresql）。
4. **gate（G3/G4）**：pipe_gate 加 kingbase 显式分支——**退役口径无自键 presence 门**（白名单即 400，CheckProtoFlat 创建路径不可达；顶层残留由门2-1 通用检查与"顶层子映射并存"黄线覆盖——复审 NOTE：黄线只告警不置红，系全协议既有行为，已在 G5 立项注记）；门2-2 文案声明退役跑法 CASE_PROTO=postgresql。coverage_gate 加 check_kingbase（退役面 7 项：白名单/negativeOnly/包/types/Meta/translate/导入零残留；dialect 面 11 项：15 例 proto=postgresql/dialect 键/FieldContract 54321/CP 分支/6 负例锚/顶层残留零/负例层配置非空防自满足）。
5. **动态面**：业务键（events 数组）静态单值如实声明；四元组走 ip/tcp 层框架；端口=per-dialect 契约（非动态策略面）。
6. **回滚**：单提交粒度摘除（退役+删除 / gate / 文档 各归一提交）。

### 文件清单（P4）

- Modify: `internal/core/protocols.go`（白名单摘 kingbase）
- Modify: `internal/core/protocols_test.go`（want 表摘 + negativeOnly 收）
- Delete: `internal/protocol/kingbase/`（整包）
- Delete: `internal/core/layers/kingbase_chain_test.go`（裁定作废）
- Modify: `internal/core/types.go`（删 KingBaseConfig/KingBaseSession/KingBaseEvent/FlowSpec.KingBase）
- Modify: `internal/core/layers/generator.go`（删 FlowMeta.KingBase）
- Modify: `internal/core/layers/chain_planner_translate.go`（删 KingBase 行）
- Modify: `cmd/server/main.go`（删 kingbase 空导入）
- Modify: `tools/pipe_gate.sh`（kingbase 显式退役分支：无自键 presence 门+门2-2 文案）
- Modify: `tools/coverage_gate.py`（check_kingbase）
- 不涉 registry/schema/layers.generated 变更（无 schemagen 面；strategy.json 本就无 kingbase）。

## D-MEGACO-1 megaco 层链接入（#36，RFC 3525/H.248.1 文本编码，79 例全绿）

> megaco（媒体网关控制协议 Megaco/H.248 v1，RFC 3525 / ITU-T H.248.1 (03/2002) 文本编码）= 终结层接入：`[ip,udp,megaco]` 一数据报一消息 / `[ip,tcp,megaco]` RFC 1006 TPKT 成帧。行为面权威 = B6 契约 `docs/protocol-designs/70-megaco-design.md` v1.2.0 + `70-megaco-testcase.md`（77 语义 ID = 46 正 + 31 wire_fault 负），旧分支参考实现（797af86/aa72e36）作 builder 编码与用例形状借鉴。

### P1 规范矩阵（§4 八项确认态）

| 项 | 要求 | 现状 | 缺口 |
|---|---|---|---|
| 1 连接模型 | UDP（D.1）/TCP（D.2）双载体 2944；mgcp 别名 2427 | registry 双 carrier FieldContract + chain carrier/端口域块 | 无 |
| 2 命令/消息表 | 八命令（Add/MF/S/MV/AV/AC/N/SC）+ 事务四形态 | builder 八命令域 + 四事务渲染 | 无 |
| 3 状态机 | 注册→编程→建连→拆连；初始状态规则（非 SC 开=Registered 等价态） | planner 状态机校验（validator） | 无 |
| 4 字段表 | 描述符族十三种（Media/LocalControl/Events/…/Error） | builder 描述符渲染全族 | 无 |
| 5 错误处理 | 31 wire_fault 负例锚词 + 2 事务级 error 边界 | wireFaultAnchors 闭环 31 值（与契约 §7 表同序） | 无 |
| 6 超时与活性 | 事务 Pending/IA/K 三方握手 | pending/reply/response_ack 渲染+validator | 无 |
| 7 NAT/被动 | 不适用（控制面协议） | 如实 | 无 |
| 8 版本方言 | Version 1*2DIGIT 起始行 + profile megaco_v1_text | builder 起始行双形 | 无 |
| **承载面** | 层链唯一真相 | B6 顶层 `megaco` 子映射注入形 → presence 判死（G5）；79 例层链形零残留 | 无 |
| **协议身份面** | 三名合一 | **收敛为 megaco 单准入名**（h248/mgcp 不独立注册；mgcp 别名=显式 2427 case 表达——kingbase 裁决同型：准入集只留真形态） | 无 |

### 缺口清单与裁定（P2）

- G1 D-MEGACO-1 条目（唯一入口）/ G2 T-MEGACO 节（79 审计）/ G3 coverage_gate check_megaco 25 项 → 全部分别落地。
- G4 pipe_gate megaco 自键组（presence 判死执法）→ binary 门实跑绿。
- **G5 承载面判死**：`CheckProtoFlat` megaco 分支（顶层 megaco 子映射+layers 并存即 400，锚 `no longer accepts a top-level megaco sub-config`）+ mapToFlowSpec 在库 switch（存量行启动 error；在库 0 行纯防御）。
- **裁定1 协议身份**：三名合一收敛 megaco 单准入名（protocols.go 白名单 + 同步 negativeOnly 摘除——红先绿后：negativeOnly 守卫先红→摘除→绿）。
- **裁定2 载体**：udp/tcp 双合法，TPKT 由生成器负责；会话 `transport` 显式声明与链载体不符 → validator 同步拒（`carrier`）。
- **裁定3 端口域**：2944 默认（FieldContract 双 carrier 常量）；2427（mgcp 别名）合法放行；2945+BINARY/text 声明混配 → 拒（`encoding`）；其余显式端口 → 拒（`port`）。
- **裁定4 wire_fault**：31 值闭环枚举，validator 即拒+主锚词（绝不静默放行成 0 包假成功）；B6 旧版 `Validate` 对已知 fault 放行的实现被 **aa72e36 起已改拒**，本分支沿用拒绝语义。
- **裁定5 初始状态规则**：注册前违规（neg56）不设自然面守卫——契约 §5.2 初始状态规则明确"首事件为 MG 注册类 SC 才从 Unregistered 起步，其余初始即 Registered 等价态"，自然配置下不可构造；该故障唯一入口 = wire_fault 命令（首版 planner 曾加自然面门，压测 32 例合法会话误红后撤除）。
- **裁定6 事务级 error**：aa72e36 边界 2 例（tx error 与 actions 并存 / tx error 在 request）+ validator 两处拒绝（锚 `both error descriptor and actions` / `only valid on type=reply`）。
- **裁定7 注释变体伪影**：tshark 3.6 megaco dissector 不实现 ABNF COMMENT（RFC 3525 Annex B.2 合法线格式）→ `_ws.malformed` 伪影进 `IsMalformedWhitelisted`（帧字节由用例 frames 六钉逐字节断言，仅 dissector 解析面受限）。
- **回滚**：提交次序 = 代码接入 → suite/gate → 文档；单提交粒度可摘。

### 文件清单（P4）

- Modify: `internal/core/protocols.go` + `protocols_test.go`（白名单收 megaco；negativeOnly 摘除）
- Create: `internal/core/megaco.go`（Megaco* 类型）+ `internal/protocol/megaco/`（builder/planner/layer_gen/builder_test）
- Modify: `internal/core/types.go`（FlowSpec.Megaco）、`layers/registry.go`（层行）、`layers/chain_planner.go`（carrier/端口域块）+ `chain_planner_util.go`（rawMegacoSessions）+ `chain_planner_translate.go`（case+flowMetaFor）+ `layers/generator.go`（FlowMeta.Megaco）
- Modify: `internal/core/strategy_convert.go`（CheckProtoFlat 判死+在库 switch）、`cmd/server/main.go`（ChainPlanner 接线）
- Test: `internal/core/layers/megaco_chain_test.go`（链级红例 15 例 = P4 八 + 修轮七；四突变实测，见 T-MEGACO P4 新增行）+ `internal/pcaptest/verify.go`（伪影白名单）
- Reshape: `test/protocol_pcap/cases/megaco.json`（B6 79 例层链整形：四元组进 ip/udp(tcp) 层、megaco 子映射进 megaco 层）
- Regenerate: `schemas/v1/generated/layers.generated.json`（114→115）+ webgen 产物
- Tools: `tools/pipe_gate.sh`（megaco 自键组）、`tools/coverage_gate.py`（check_megaco 25 项）

### 门 1 开工对照表（§1–§14，三道硬门之门 1；证据=文档节/代码行/用例号）

| § | 本协议怎么满足 | 证据 |
|---|---|---|
| §1 层链唯一真相 | 顶层旧键：`src_ip/dst_ip/src_port/dst_port/count` 零残留（门 2-1 脚本扫）；顶层 `megaco` 子映射 presence 判死（B6 注入形退役，kingbase 同型）；目标形状：`{"layers":[{"ip":{"src":"192.0.2.70","dst":"198.51.100.70"}},{"udp":{"src_port":40700}},{"megaco":{"profile":"megaco_v1_text","encoding":"text","version":1,"token_form":"long","whitespace":"","sessions":[{"role":"mg","mid":"[192.0.2.70]","peer_mid":"[198.51.100.70]","events":[{"kind":"message","direction":"c2s","transactions":[{"type":"request","id":"auto","actions":[{"context":"-","commands":[{"name":"ServiceChange","termination":"ROOT","descriptor":{"services":{"method":"Restart","reason":"901 Cold Boot"}}}]}]}]}]}],"wire_fault":""}}]}`（megaco 层七键全列；TCP 载体 = `[ip,tcp,megaco]`，TPKT 成帧） | `strategy_convert.go:8242` CheckProtoFlat megaco 分支（锚 `no longer accepts a top-level megaco sub-config`）；红例① TestMegacoChain_FlatPresenceRejected；门 2-1 绿 |
| §2 策略/任务分工 | megaco 无子流派生端口；多流只走 `flow_control`；会话编排住 megaco 层 `sessions[]`，任务合跑沿框架语义 | registry.go megaco 行（无 dyn 字段）；T-MEGACO 用例面 |
| §3 五件套 | 会话表=`sessions[]`（role/mid/peer_mid/transport/ports）；事务序列=`events[].transactions[]`（request/reply/pending/response_ack 四形态）；关联=`same_as_request:<i>` 引用 + `ack` 覆盖已确认事务 + ObservedEvents RequestID 关联（observedReqIDs）；插入位置=链终结层生成器每消息一 MessageEvent；时间线=会话内顺序回放，`concurrent:true` 按事件下标 round-robin 交错 | `layer_gen.go` sessionRun/sessionTxState.resolve（复评收口后唯一解析权威）；`planner.go` validateSession 状态机面；正例 45（concurrent） |
| §4 规范矩阵 | RFC 3525 / ITU-T H.248.1 (03/2002)：§7 命令与描述符、§8 事务、Annex B.2 文本 ABNF、Annex D.1 UDP / D.2 TPKT；B6 契约 70-megaco-design.md v1.2.1 为行为面权威 | 本条目 P1 矩阵 10 行 |
| §5 有错必处理 | 31 wire_fault 闭环锚词 validator 即拒（绝不 0 包假成功）+ 2 事务级 error 边界（裁定6）；载体双 carrier 校验；长度类拒绝在 Validate 同步面（Plan goroutine 空流契约不吞锚词） | `planner.go` wireFaultAnchors/Validate；`chain_planner.go` megaco 块 |
| §6 性能 | 事件流式渲染（无全量收集、无锁无 sleep）；UDP 单数据报 ≤1472 / TPKT ≤0xFFFF 天花板 Validate 面执法；边界诚实声明（无吞吐/并发目标，网卡未跑） | `planner.go` sessionRenderSizes + Validate 天花板块；T-MEGACO 跑法口径 |
| §7 三份文档 | 设计=70-megaco-design.md v1.2.1 + 本条目；用例=T-MEGACO（79 审计）；cases 回指语义 ID；schema 为机器契约 | T-MEGACO 三源回指行 |
| §8 先设计后代码 | P1 矩阵 + 缺口清单与裁定（G1–G5 + 裁定1–7）定稿后开工；修轮按隔离终审 F1–F15 处置后再复评 | 本条目两节 |
| §9 三源+整格 | 三源每条回指（RFC 行/B6 语义 ID/用例号）；wire_fault 31 值逐一单一注入；正例覆盖描述符族代表+双载体+双 token 形+空白变体 | T-MEGACO 存量审计行 |
| §10 评审闭环 | 改→审→测→修→再审：主线程逐相位对抗自审 + 收官隔离终审（FAIL 判定→修轮 F1–F15→同审查员范围复评）；测试四问逐例过 | 本条目修轮记录；门 3 抽查 |
| §11 白话汇报 | 先一句结论再贴证据；锚词/突变逐一实录（含证伪更正：旧"三突变"中"删 translate→②红"系伪证已废弃重测） | T-MEGACO P4 新增行 |
| §12 动态清单 | 四元组：ip 层 src/dst + udp/tcp 层 src_port/dst_port（链级）+ 会话级 src_port/dst_port 覆盖（域校验同链级，修轮 F3）；业务动态：`transactions[].id` `auto`（会话内计数器从 1 起）/`same_as_request:<i>`（第 i 个请求 id）——序号算法 `layer_gen.go` sessionTxState.resolve（validator 状态机/sessionRenderSizes/生成器三面共用）；megaco 层七键静态无 dyn 对象 | `layer_gen.go` sessionTxState；`chain_planner.go` 会话 dst_port 域；红例⑫ |
| §13 schema 同步 | registry 新增 megaco 行（七键，version Min 1/Max 99）→ schemagen/webgen 重跑提交（114→115 层） | `schemas/v1/generated/layers.generated.json` |
| §14 真实流程 | cases 即任务 spec；MCP 建任务→引擎生成→tshark 校对；负例带锚词 task error；79/79 全量 ×4；二进制同代；pcap 落盘 `/tmp/mcp-pcaps/megaco/` | T-MEGACO 跑法口径行；门 2 三项 |

### F6 逐值处置表（修轮+复评收口；隔离终审 F6 指控"31 负例自证循环"的完整裁定——23 值自然面守卫在位，8 值书面豁免）

自然面守卫 = 去掉 `wire_fault` 后用自然配置可表达同一故障且 validator 同步拒绝；书面豁免 = 故障无自然配置面（builder 恒产合法线格式 / 框架规则 / 合法测试目标），注入通道是唯一入口。

**守卫在位（23 值）：**

| wire_fault 值 | 锚 | 自然面表达 | 守卫证据 |
|---|---|---|---|
| encoding_text_as_ber | encoding | `{"encoding":"ber"}` | validateConfig 拒（修轮 F6-ber）；红例⑭ |
| encoding_port_mismatch | encoding | dst_port 2945 | 链块端口域（锚 encoding）；红例⑥ |
| syntax_version_three_digits | version | `version: 100` | validateConfig >99 拒 |
| syntax_mid_invalid | mid | `mid:"[bad mid with spaces]"` | validateMidForm 四形+ParseIP（修轮 F11）；红例⑭ |
| syntax_services_missing_params | message | SC 请求缺 method/reason | planner SC 块（:508-517） |
| command_reply_choose_all | command | reply 后 $-CHOOSE 上下文复用 | choseRequested 状态机（:413） |
| command_uncreated_context | command | 未创建 Context 数字引用 | createdContexts 状态机（:448） |
| pairing_reply_id_mismatch | transaction | reply 引用不存在请求 | resolveTxID/requestOrder |
| pairing_pending_id_mismatch | transaction | pending 引用不存在请求 | resolveTxID |
| pairing_duplicate_transid | transaction | 同会话两 id=7（修轮 F9） | seenTransIDs；红例⑬ |
| pairing_ack_unconfirmed | transaction | K 引用未确认事务（红例⑩ 数据面） | checkAckCoverage（:314） |
| pairing_ia_without_pending | transaction | ImmAckRequired 无前置 PN | eventsPending（:288-291） |
| pairing_observed_requestid | transaction | Notify OE RequestID 与生效 Events 不符 | observedReqIDs（:537） |
| length_termid_over_64 | length | termination >64 字符 | planner（:477） |
| length_transid_over_uint32 | length | `id:"4294967296"` | ParseUint 32 拒（修轮 F4）；红例⑫ |
| length_digitmap_timer | length | digit_map T>99 / S/L=0 | DigitMap 域校验（:525-536） |
| length_context_reserved | length | Context=0/0xFFFFFFFE/FFFFFFFF | contextIDReserved |
| carrier_layer_mismatch | carrier | udp 链会话 transport=tcp | 链块 transport vs 载体；红例⑧ |
| carrier_entry_port_encoding | carrier | dst_port 2945（自然面锚=encoding） | 链块端口域 |
| carrier_invalid_port | port | dst_port 9999 | 链块端口域；红例⑥⑪ |
| carrier_udp_mtu_exceeded | length | UDP 链 >1472 长消息 | sessionRenderSizes 天花板（修轮 F5）；红例⑨ |
| services_address_mgcidtotry_conflict | services | SC 同带 address+mgc_id_to_try | SC 块互斥（:519-521） |
| command_first_error_continues | command | reply 动作内首命令带 Error 描述符后继命令（复评 U4 反例） | validateAction 命令环 errCmdSeen 守卫；红例⑰ |

**书面豁免（8 值，wire_fault-only）：**

| wire_fault 值 | 锚 | 豁免理由 |
|---|---|---|
| syntax_start_line | message | builder 起始行恒由 buildStartLine 渲染，无配置键可产畸形行 |
| syntax_version_zero | version | 显式 0 的实际语义 = 采用缺省版本：V9 框架规则 `u==0` skip（complete.go:315）使 schema 面不报范围错（区间 [1,99] 不覆盖显式 0——复评 U3 证伪旧注释），planner 面 0 渲染为 1，线上与缺席完全同值、无故障可表达；契约 §6 "0 拒绝"不执法，registry 注释已按此如实改写 |
| syntax_mid_missing | mid | 空 mid 是合法缺省派生语义（pickMid 按角色+地址派生）；"消息无 mId"无自然配置面 |
| syntax_body_form | message | builder 恒产合法消息体结构 |
| command_pre_registration | command | 契约 §5.2 初始状态规则：非 SC-first 会话初始即 Registered 等价态，Modify-first 合法——自然配置下不可构造（裁定5，首版自然面门误红 32 合法会话后撤除） |
| command_modify_nonexistent | command | 终结点存在性属协议端状态，生成器无端侧状态面；对任意 termination 的 Modify 是合法流量场景（用户编排骨），拒之将断真实用法 |
| length_message_truncated | length | builder 恒产完整消息（长度域由 WrapTPKT/render 完整性保证），截断无配置面 |
| carrier_return_address | carrier | 环回地址是合法测试目标（本工具即本机自测场景），ip 层不拒 127.0.0.1 |

### 门 3 抽查三条（收官验收门；每条点到代码行或用例号）

1. **裁定3 端口域**：`chain_planner.go` megaco 块（2944/2427 放行、2945 锚 encoding、其余锚 port，会话级同域=修轮 F3）↔ 红例⑥ TestMegacoChain_PortContract + 红例⑪ TestMegacoChain_SessionDstPortDomain ↔ 用例 megaco_neg_carrier_invalid_port（锚 `port`）。
2. **修轮 F1/F5 长度天花板**：`planner.go` Validate 面 carrier 分支（UDP >1472 / TPKT n+4 >0xFFFF）+ sessionRenderSizes（:596）+ `chain_planner.go` megaco_carrier 元数据供给（先于 protocolValidator——修轮实证原顺序天花板空转）↔ 红例⑨ TestMegacoChain_TPKTOverflowRejected ↔ 用例 megaco_neg_carrier_udp_mtu_exceeded（锚 `length`）。
3. **修轮 F2 缩写 K**：`builder.go` 显式 reverseTokens 表（`"TransactionResponseAck": "K"`）+ renderResponseAck 长键改传 `"TransactionResponseAck"` ↔ 红例⑩ TestMegacoChain_AbbrevAckIsK（断言 `!/1` + `K { 5 }`、反断言无 `ResponseAck` 泄漏）↔ builder_test.go token 表测试。

### 复评收口（范围复评 rereview.md U1–U4，红先绿后）

- **U1（HIGH，修轮新回归）**：validator request 分支 `auto→"1"` 固定归一 ↔ 生成器逐请求计数不一致——auto+auto 误拒（32b3968 接受 1/2）、`"1"`+缺省撞号漏网（生成器落 1/1）。修法：**一处解析三面共用**——`sessionTxState.resolve`（auto/缺省逐请求计数、same_as_request 引用）为唯一权威，validateSession 先 `resolveSessionTransactions` 再在已解析 id 上走状态机，sessionRenderSizes 同函数出长度，生成器 sessionRun 同函数出线。红例⑯（auto+auto 落线 1/2）+ 红例⑯b（"1"+缺省拒，锚 transaction）先红后绿。
- **U2（MEDIUM-HIGH，同源）**：sessionRenderSizes 手抄副本一字节漂移即天花板静默失效（1472B 空流复现）。U1 的共享解析消掉 id 面副本；渲染面 pickMid/BuildMessageText 本已同函数，副本面收敛为单一调用序。
- **U3（MEDIUM）**：registry 注释"[1,99] 同锚词覆盖显式 0"伪声明（V9 `u==0` skip 先于范围检查）+ generated 文件缺 `"min":1`（F10 后未重跑 schemagen，freshness 测试不比 min/max 故绿）。修法：注释如实改写（显式 0=缺省渲染 1，豁免叙述同步）；schemagen 重跑（diff 恰一行）；`TestLayersGeneratedMatchesRegistry` 扩 min/max 比对（JSON float64 ↔ int64 数值比较）。
- **U4（LOW-MED）**：`command_first_error_continues` 豁免理由"无法自然表达"被反例证伪（reply 动作 Error 命令后续命令落线）。修法：validateAction 命令环 errCmdSeen 守卫（同动作首错后继命令拒，锚 command）——移入守卫表（23+8）。红例⑰先红后绿。
### 复评收口轮 2（第三轮范围复评 rereview2.md：PASS-WITH-FINDINGS，F1–F6）

U1/U2/U3 闭合经独立复现确认（四行矩阵/1472 边界逐字节/cmpBound 双向突变均真）。F1–F6 处置（红先绿后或突变实证）：

- **F1（中）**：U4 守卫不读 `cmd.Optional`——O- 命令跟在错误命令后被误拒，与设计 §8"首错停止（O- 可选命令豁免）"冲突。修法：`errCmdSeen && !cmd.Optional`；红例⑱ TestMegacoChain_OptionalAfterErrorAllowed（O- 放行 + 落线 `O-AuditValue = A1`）先红后绿。
- **F2（低，潜伏）**：BuildMessageText 双调用点漂移隐患——parity 守卫落地：`internal/protocol/megaco/parity_test.go` TestRenderParityWithGenerator（四形状 × 双载体，sizes ↔ 实发字节逐字节），生成器侧 1 字节漂移突变实测红（1301 vs 1296+4）。
- **F3（低）**：pending 空 id 错误补 `(transaction)` 锚词。
- **F4（低）**：freshness 测试 cmpDefault 落地（dump 缺失 ⇔ registry nil；在场 ⇔ 相等，数值 float64 归一 + map 长度比对）——registry default 0→1 突变实测红（dump=0 registry=1）。
- **F5（低，既有）**：空 sessions 基线流继承显式 version/token_form/whitespace（defaultFlow(from)）——`{"version":2}` 无会话渲染 MEGACO/2；红例⑲先红后绿。
- **F6（低，文档）**：CODE_DESIGN 两处 `resolveTransactionID` 存量名更新为 sessionTxState.resolve；设计 §7 neg50 行注记豁免（自然面不执法，仅注入通道）。

### 第四轮范围复评（rereview3.md：PASS-WITH-FINDINGS，可关单）+ 关单残项批

F1/F3/F4/F5/F6 五项闭合经独立复现确认（12 面探针/双向突变/8 面基线探针）。残项处置：

- **F-A（中，覆盖缺口）**：parity 守卫机制为真但 big-digitmap 形 render=1296，1472 天花板常量本身零自然面边界例——红例⑳ TestMegacoChain_UDPMtuBoundary（pad=1376 → render 恰 1472 收 1 包；pad=1377 → 拒锚 `length`）；天花板常量 1472→1471 突变实测红（1472 收例报 `exceeds the MTU budget`）。
- **F-B（低，文档）**：§3.1 正文（:67）"0 与 3 位数字拒绝"与 v1.2.2 豁免口径矛盾——正文改指 §6 version 行 v1.2.2 处置。
- **cosmetic**：本条目 tls flake 观察重复段删除（收口轮 2 插入与原有 bullet 重叠）；pending 空 id 自然面锚词补断言（TestValidate_PendingMissingIDAnchored）。
- **附带观察登记**：tls `planner_test.go:1172` 随机首字节 flake（自 1659a55 起既有）另行立项修断言。


