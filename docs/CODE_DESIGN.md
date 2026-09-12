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
# 方法注记：tcpdump 无抓包权限（lo: Operation not permitted），以上为应用层原始问答 + ftplib 字节对账； Идея pcap 断言仍以本机引擎生成 pcap + tshark 为准，不混用现网字节。
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
