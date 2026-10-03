# DRDA（DSS/DDM）设计契约

> 版本：v1.2.1（层链 as-built 审计版＋D1/D2 子表③/C5 逐例对账）
> 日期：2026-10-01
> 机器用例：`test/protocol_pcap/cases/drda.json`（13 例，9 正 + 4 负；ID 以 JSON 为准；静态已核对，真实 suite/pcap/NIC 待复跑）
> 历史基线：`docs/protocols/drda/_archive_29-drda-design.md`、`_archive_29-drda-testcase.md`（仅历史参考）
> 规范依据：The Open Group DRDA V5 Vol.1–3（DSS/DDM 头、代码点与状态机）；本机 TShark 3.6.14 `drda.*` 字段作为断言通道。

## 1. 范围与层链真相

DRDA 在 TCP 446 上承载 DSS/DDM。唯一合法正例链为 `[ip, tcp, drda]`；IPv6 仍使用 `ip` 层，地址写 `ip.src`/`ip.dst`；端口写 `tcp.src_port`/`tcp.dst_port`；数量写 `flow_control`。顶层不得出现协议业务映射、地址、端口或 `count`。

`drda` 是终结层，依赖 TCP，注册表契约将 `tcp.dst_port` 补为 446。`[ip, udp, drda]`、显式非 446 目标端口和顶层 `drda` 子映射均为拒绝形状。

当前实现证据：`internal/protocol/drda/{builder.go,planner.go,layer_gen.go}`；层注册和字段契约见 `internal/core/layers/registry.go`；机器契约见 cases 文件。本文不宣称本轮真实 suite/NIC 已运行。

### 1.1 旧键逐键去向

| 旧写法 | 目标写法 |
|---|---|
| 顶层 `src_ip`/`dst_ip` | `layers[].ip.src`/`dst` |
| 顶层 `src_port`/`dst_port` | `layers[].tcp.src_port`/`dst_port` |
| 顶层 `count` | `flow_control.flows` |
| 顶层 `drda` 子映射 | `layers[].drda` |
| 空 `layers[].tcp`/`layers[].drda` | 删除空壳，合并为有业务值的层 |

完整目标形：

```json
{"layers":[{"ip":{"src":"10.0.0.1","dst":"20.0.0.1"}},{"tcp":{"src_port":12345}},{"drda":{"association":"excsat","correlator_start":1,"ccsid":1208}}],"flow_control":{"flows":1}}
```

## 2. 配置与生成流程

业务字段由 drda 层携带：`association`（excsat/security/database/sql）、`ccsid`、`correlator_start`、`correlator_inc`、`security_user`、`security_token`、`rdb_name`、`sql`、`dss_segments`、`dss_length`、`sessions`。字段内部结构由 DRDA 配置类型约束；不支持的组合由 planner 拒绝。

生成顺序是 TCP 三拍握手、DSS 请求/响应对、TCP 挥手。默认阶段为 EXCSAT、ACCSEC、SECCHK、ACCRDB、SQLDTA/SQLCARD；`association` 截断阶段。`sessions` 中每个会话有独立四元组和 correlator 起点，按会话顺序生成。SQLCODE 为 0 或负值都保持连接并完成挥手；应用错误不是任务配置错误。

## 3. 线格式

DSS/DDM 头为 10 字节、大端：

| 偏移 | 长度 | 字段 | 约束 |
|---:|---:|---|---|
| 0 | 2 | length | 总长，最小 10 |
| 2 | 1 | magic | `0xd0` |
| 3 | 1 | format | `0x01`；chained 首段 `0x41` |
| 4 | 2 | correlator | 请求/响应配对 |
| 6 | 2 | length2 | `length - 6`，最小 4 |
| 8 | 2 | code point | U16 BE |

无参数 DDM 的最小字节为 `00 0a d0 01 00 01 00 04` 加 2 字节代码点。参数采用 `length(2)+codepoint(2)+data`。已覆盖代码点为 EXCSAT `0x1041`、EXCSATRD `0x1443`、ACCSEC `0x106d`、ACCSECRD `0x14ac`、SECCHK `0x106e`、SECCHKRM `0x1219`、ACCRDB `0x2001`、ACCRDBRM `0x2201`、SQLDTA `0x2412`、SQLCARD `0x2408`；SQLSTT `0x2414` 尚无可执行用例。

## 4. 规范依据、三路对照和候选方案

### 4.1 三路对照

| 来源 | 本契约采用的内容 | 边界 |
|---|---|---|
| DRDA V5 Vol.1–3 官方文档 | DSS/DDM 10B 头、BE 长度、代码点、请求/响应顺序、RDB/SQL 状态语义 | 规范定“必须是什么” |
| IBM DB2/DB2 Connect 行为形态 | 标准 EXCSAT→ACCSEC→SECCHK→ACCRDB→SQL 应用路径；RDB `SAMPLE`、CCSID 1208 占位 | 无本轮抓包证据，未确认项见 C1–C6 |
| 可靠开源与本机实现思路 | Wireshark `packet-drda.c` 只作 dissector 字段通道；本仓库 planner 按段流式生成 | 借行为/字段名，不复制受限代码 |

### 4.2 候选方案

| 方案 | 优点 | 代价 | 结论 |
|---|---|---|---|
| 每阶段聚合后一次编码 | 调用简单 | 破坏流式约束、放大内存 | 不选 |
| 逐 DSS 段生成请求/响应 | O(n) 内存、可复用状态机、适合背压 | 调度代码更细 | 选择，沿用 planner/layer_gen |

## 5. D1–D8 设计矩阵

| 编号 | 要求 | 规范要求→业务场景→代码现状→缺口 |
|---|---|---|
| D1 | 连接模型 | DSS/DDM over TCP 446→一次建连、多轮 DDM、正常释放→握手/业务/挥手均已实现→C5 待复跑证据 |
| D2 | 命令/响应 | 请求与 RM/结果成对→关联四阶段与 SQL→代码点映射和响应生成已实现→失败 RM 完整参数面 C2 |
| D3 | 状态机 | 必须依次建关联后 SQL→DB2 标准路径→planner 按 association 截断→失败终止/reconnect C2/C4 |
| D4 | 字段 | 10B 头、BE 长度、TLV、SQLCODE/SQLSTATE→逐字段断言→builder/planner 可编码→correlator_inc≠1 专例 C6 |
| D5 | 错误处理 | 非法长度/载体/端口拒绝→坏配置必须生成前失败→planner/validate 拒绝→四例已覆盖，文案以现有用例锚词为准 |
| D6 | 活性/释放 | 每业务阶段后正常 FIN→长会话多 SQL→每正例握手+挥手→空闲超时语义规范外，不实现 |
| D7 | 地址族/多会话 | IPv4/IPv6 对称；显式 sessions→隔离客户端连接→`ip`/`sessions` 已实现→IPv6 双会话组合矩阵另立项 C6 |
| D8 | 性能边界 | 大流量不聚合→高并发/背压→逐段生成不缓存全部帧→队列/内存/CPU 六场景基准 C6 |

### 5.1 请求×响应矩阵

| 请求 | 响应 | 用例 |
|---|---|---|
| EXCSAT `0x1041` | EXCSATRD `0x1443` | #1/#7/#9 |
| ACCSEC `0x106d` | ACCSECRD `0x14ac` | #2 |
| SECCHK `0x106e` | SECCHKRM `0x1219` | #2 |
| ACCRDB `0x2001` | ACCRDBRM `0x2201` | #3 |
| SQLDTA `0x2412` | SQLCARD `0x2408`（成功/负值） | #4/#5 |
| chained 首段 | `format=0x41` + `0x01` | #9 |
| 失败 RM | 终止 | C2，未覆盖 |

### 5.2 数据形态变体表

| 形态 | 现状 | 用例 |
|---|---|---|
| 最小无参数 DDM，length 10/length2 4 | 已覆 | #1/#6/#9 |
| 参数 TLV（CCSID/RDB/SQL） | 已覆 | #2/#3/#4/#5 |
| SQLCODE 0 与负 U32 BE + SQLSTATE | 已覆 | #4/#5 |
| IPv4/IPv6 地址族 | 已覆 | #1/#7 |
| 双 session 顺序生成 | 已覆 | #8 |
| IPv6 × 双 session | 未覆盖 | C6 |
| SQLSTT/多语句 | 未覆盖 | C1 |
| 多段 DSS 编排 | 未覆盖 | C6 |

### 5.3 商业行为→用例映射（D1/D2 子表③：规范行→用例 ID 逐例）

| 源行 | DB2 行为 | 用例 ID | 证据状态 |
|---|---|---|---|
| D1 | 一次建连、多轮 DDM、正常释放 | `drda_excsat`、`drda_security_check`、`drda_database_connect`、`drda_sql_success`、`drda_sql_error`、`drda_multi_session` | cases 字节与代码点；握手/挥手断言在 JSON |
| D2 | 请求与 RM/结果成对 | `drda_excsat`、`drda_security_check`、`drda_database_connect`、`drda_sql_success`、`drda_sql_error`、`drda_chained_format` | correlator 配对断言在 JSON |
| D1 | 最小 DDM 边界（length 10/length2 4） | `drda_dss_min_length`、`drda_chained_format` | JSON fields/frames |
| D1 | IPv6 地址族对称，DRDA 字节不变 | `drda_ipv6_excsat` | JSON offset 74 帧断言 |
| D2 | 两个独立 TCP session，correlator 各自起 | `drda_multi_session` | JSON `distinct_values` |
| D5 | 坏配置生成前拒绝 | `drda_dss_length_mismatch`、`drda_udp_rejected`、`drda_neg_presence_top_level_drda`、`drda_neg_dst_port_contract` | JSON 负例 `expect_error`/`error_contains` 锚词 |

上述 13 行逐 ID 对账：9 正例均含 packet count＋握手/终止/方向＋fields 或 frames 断言；4 负例 `expect` 严格只有 `expect_error` 与 `error_contains`。真实 suite/pcap/NIC 尚未运行，本表不冒充证据（C5）。

## 6. 依赖、错误、性能与回滚

- 依赖：`drda → tcp`，目标端口固定 446；UDP 载体拒绝。
- `dss_length` 小于 DSS 头或与段长度不一致时拒绝；DDM length/length2 越界时拒绝。
- SQL 负 SQLCODE 是应用结果，连接继续并完成释放；协议、配置和载体错误在生成前拒绝。
- 不实现重试、超时、NAT/被动模式；DRDA 本身不依赖这些能力，不写无依据流程。
- 流式生成，不聚合全部报文；队列和缓冲上限由通用引擎负责。性能验收覆盖基线、目标规模、压力上限、长连接、多流交错、队列背压/资源耗尽六类；断言包速率、失败数、内存、CPU、队列积压和丢包。本轮无基准数字。
- 回滚：文档改造独立于代码；cases 如后续调整，以现有 JSON 为基线局部回退，并同步本文件/testcase。
- 冲突点：共享 executor、presence 守卫与 flat 翻译路径不在本任务修改范围；本文件只登记缺口，不宣称共享面改动。

## 7. 动态字段清单

| 字段 | 动态策略 | 理由/证据 |
|---|---|---|
| `ip.src`/`ip.dst` | inc/rand/list/pattern | 通用 `ip` 层承担，不由 drda 另设顶层字段 |
| `tcp.src_port` | inc/list；`tcp.dst_port` 固定 446 | 由 tcp 层承担；446 契约禁止其他目标端口 |
| `correlator_start`/`correlator_inc` | 静态/逐流显式配置 | 当前用例覆盖 start；inc≠1 专例 C6 |
| `association` | 静态 | 形状选择器，不作为逐流随机值 |
| `security_user`/`rdb_name`/`sql.*` | 静态多值；不启用策略 | 保持业务语义可复查；多语句/完整编码 C1/C3 |
| `sessions[]` | 显式列表 | 每 session 独立四元组/counter，不用模板静默复制 |
| `dss_length`/`dss_segments` | 静态 | 负例和边界构造，不允许随机化后失去锚词 |

无 drda 专属序号算法：correlator 是逐会话业务关联值，由 session 配置和 planner 递增，不依赖流序号算法。

## 8. §15 门1 三行展开

| 门1 行 | 展开 |
|---|---|
| §1 旧键 | §1.1 逐键给出去向和完整 `spec_json`；现存 9 正例顶层仅 `layers`/`flow_control`，4 负例中仅 presence 负例故意含顶层 `drda` |
| §3 五件套 | 会话表＝每 TCP 446 session；事务序列＝EXCSAT→ACCSEC→SECCHK→ACCRDB→SQL；关联＝correlator 配对；插入＝关联成功后追加 SQL；时间线＝session 顺序串行。见 testcase §7 |
| §12 动态 | §7 四元组、业务字段和不开策略理由逐项列明；无专属流序号算法 |

## 9. C1–C6 缺口登记和迁入计划

| 编号 | 缺口 | 计划 |
|---|---|---|
| C1 | SQLSTT/多语句事务 | 先补配置字段消费和 SQLSTT 发射点，再增正例和失败例 |
| C2 | SECCHKRM/ACCRDBRM 失败参数面与终止 | 取得规范/现网字节证据后实现分支并增用例 |
| C3 | security_token/SECMEC 完整编码 | 完成现网确认，编码面和断言同步扩展 |
| C4 | reconnect 语义 | 另立状态机设计、用例和 pcap 基准，不能用重复模板代替 |
| C5 | pcap/NIC 全量重跑证据 | 真实 suite/NIC 六场景后回填，不提前宣称 |
| C6 | 性能基准、IPv6×双 session、correlator_inc≠1、多段 DSS | 按 C5 证据源统一扩用例并复核包数 |

### 9.1 C5 13 例逐例对账（静态契约验收；真实执行待复跑）

| ID | 类型 | 静态核对项 | 真实 suite/pcap/NIC |
|---|---|---|---|
| `drda_excsat` | 正 | 9 包；EXCSAT/EXCSATRD；fields+frames | 未运行 |
| `drda_security_check` | 正 | 13 包；五代码点顺序；fields+frames | 未运行 |
| `drda_database_connect` | 正 | 15 包；ACCRDB/RM；fields+frames | 未运行 |
| `drda_sql_success` | 正 | 17 包；SQLDTA/SQLCARD、SQLCODE=0；fields+frames | 未运行 |
| `drda_sql_error` | 正 | 17 包；SQLCODE=-204、SQLSTATE=42704；fields+frames | 未运行 |
| `drda_dss_min_length` | 正 | 9 包；length=10/length2=4；fields+frames | 未运行 |
| `drda_ipv6_excsat` | 正 | 9 包；IPv6 + offset 74；fields+frames | 未运行 |
| `drda_multi_session` | 正 | 18 包；双源端口/双 session；fields+frames | 未运行 |
| `drda_dss_length_mismatch` | 负 | 仅 `expect_error` + `error_contains=dss_length` | 未运行 |
| `drda_udp_rejected` | 负 | 仅 `expect_error` + `error_contains=tcp` | 未运行 |
| `drda_chained_format` | 正 | 9 包；format 0x41→0x01；fields+frames | 未运行 |
| `drda_neg_presence_top_level_drda` | 负 | 仅 `expect_error` + 顶层 drda 锚词 | 未运行 |
| `drda_neg_dst_port_contract` | 负 | 仅 `expect_error` + `dst_port must be 446` | 未运行 |

C5 当前结论是“13/13 静态契约已对账、0/13 真实运行”；不得将 cases 静态存在、文档断言或 JSON 解析通过写成 pcap/NIC/suite 证据。

## 10. 修订记录

- v1.2.0（2026-09-30）：补齐 §4 三路对照/候选方案、D1–D8 与三张子表、旧键去向、动态清单、门1 三行展开和 C1–C6 迁入计划；与 JSON 13 例对账。
- v1.1.0（2026-09-30）：按现有 13 例 JSON 和层链白名单重写；移除旧顶层过渡形和未执行 suite 的宣称。
