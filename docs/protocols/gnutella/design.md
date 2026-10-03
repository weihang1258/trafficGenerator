# Gnutella Wire Profile 设计契约

> 版本：v2.1.0（D1–D8 修订）；日期：2026-10-01；代码状态：registry/generator 已注册，terminal layer config translator 尚缺。
> 机器用例：`trafficgen/test/protocol_pcap/cases/gnutella.json`（14 正例、6 负例，已改为顶层仅 `layers`；业务配置进入生成器前仍受 GNT-D1 阻塞）。

## 1. 范围、规范和实现边界

本设计覆盖 Gnutella 0.6 邻居 TCP/6346 连接：CONNECT/200（或 503）握手、PING/PONG、QUERY/QUERY_HIT、PUSH、VENDOR、显式转发以及关闭。规范依据为 Gnutella 0.6 wire profile（handshake 与 message header/payload 约定）；本仓库实现入口为 `internal/protocol/gnutella/layer_gen.go:282-477` 与 `builder.go`。tshark 3.6.14 没有可用 Gnutella dissector，因此业务断言使用 TCP 字段和载荷帧字节。

承载只允许 TCP；`gnutella_v060` 地址字段为 IPv4，`gnutella_ipv6_v1` 为 IPv6。TLS 明文业务不解析。目的端口必须为 6346。所有配置使用严格层链：地址在 `ip`，端口在 `tcp`，业务在 `gnutella`，数量在 `strategy_fc`；本批用例不复制流。

## 2. P1 对照表（CORE §1–§14）

| 条款 | 本协议满足方式 | 证据 | 缺口/计划 |
|---|---|---|---|
| §1 层链 | 目标形状为 `ip.src/dst`、`tcp.src_port/dst_port`、终结层事件 | cases 20/20 顶层仅 `layers`，承载字段已归层 | GNT-D1：补 translator 后重验业务配置 |
| §2 策略/任务 | 事件模板在 gnutella 层；数量由 flow control | schema 入口与层规划 | 多流 flows 动态整格待后续任务 |
| §3 会话/事务/关联 | `connections[]` 独立四元组和生命周期；QUERY→HIT/PUSH 关联 | `layer_gen.go:305-438`；S7/S9/S10 | 无 |
| §4 规范矩阵 | §4.1–§4.4 与三张子表 | 本文 §4 | 商业行为以公开客户端文档为待确认项 |
| §5 错误 | validator 锚词传播 task error；状态、长度、关联拒绝 | `layer_gen.go:282-470`；N1–N6 | 无 |
| §6 性能 | 流式逐事件生成；MSS 由 TCP 层处理 | §6；S14 | 规模基准待 P5 实测 |
| §8 实现要素 | 文件、接口、流程、回滚均列于 §8 | 本文 §8 | 无 |
| §9 测试 | 20 个原子 ID 与 cases 同序 | testcase §2 与 JSON ID 同序；严格层链形状已迁移 | GNT-D1 解决后重跑 |
| §12 动态 | 四元组和业务字段逐项列于 §7 | `layer_gen.go:90-97`、builder | 动态业务字段需新增 schema 后立项 |
| §14 真实验收 | pcap 帧/字段断言；负例锚词 | cases `expect` | 本车道不启动 suite |
| §15 门1 | 完整 spec 示例、五件套、动态清单 | §3、§5、§7 | GNT-D1：层链入口未接线，不能宣称门2/门3 |

## 3. 严格配置形状与门1三行展开

完整成功配置如下（顶层只有 `layers`）：

```json
{"layers":[{"ip":{"src":"192.0.2.53","dst":"198.51.100.53"}},{"tcp":{"src_port":42059,"dst_port":6346}},{"gnutella":{"connections":[{"src_port":42059,"events":[{"kind":"connect"},{"kind":"ok"},{"kind":"ping","message_id":"AQIDBAUGBwgJCgsMDQ4PEA==","ttl":5,"hops":0}]}]}}]}
```

- **§1 去向**：目标形状将旧 `src_ip/dst_ip` 迁入 `ip.src/dst`，旧 `src_port/dst_port` 迁入 `tcp`，旧顶层 `gnutella` 迁入 `layers[].gnutella`；`count` 不属于 spec，数量使用 `strategy_fc`。**当前层链 translate 在 `translateTerminalConfig` 的 `switch term.Name` 中没有 `case "gnutella"`（`chain_planner_translate.go:916` 起），因此迁移例暂列缺口 GNT-D1，计划补 terminal config decode 后再迁移并真实校准。**
- **§3 五件套**：会话表为 `connections[]`（每项独立 ID 由索引和四元组确定）；事务序列为每项 `events[]`（CONNECT→OK→业务→关闭）；关联关系为 PONG→PING MessageID、QUERY_HIT→QUERY ID、PUSH→ServentID；插入位置是握手成功后、所属连接事件序列中；时间线按连接顺序生成，多连接可并发交错，跨连接不比较 packet index。该语义已有 `internal/protocol/gnutella/layer_gen.go`，但层链配置尚未能进入它。
- **§12 清单**：四元组动态字段见 §7；业务字段 `message_id/query_id/servent_id` 由事件显式提供并按关联校验，TTL/Hops 由事件提供并检查，results/vendor payload 原样编码；每项序号为 `connections[i].events[j]`，代码在 `layer_gen.go:315-438`。

## 4. 规范矩阵与三张子表

### 4.1 八项 P1 矩阵

| 规范要求 | 业务场景 | 代码现状 | 缺口 |
|---|---|---|---|
| 连接模型：长 TCP 邻居，主动 CONNECT | S1–S15 | Gnutella validator/generator 状态机，当前只能走旧直连配置 | GNT-D1：层链转换后重验 |
| 消息表：请求/响应及字段 | S2–S7 | 6 descriptor builder 与默认方向 | Vendor 私有语义不推断；GNT-D1 |
| 状态机：握手后业务、关闭终止 | S1、N1 | `validateHandshakeEvent` 与 closed 检查 | 层链入口未接线，GNT-D1 |
| 字段：23B 头、LE 长度、地址宽度 | S2–S15 | `builder.go` 编码及 profile | 层链入口未接线，GNT-D1 |
| 错误：截断、未知 descriptor、关联错误 | N1–N6 | wire_fault/validator 锚词 | 层链负例迁移后重验，GNT-D1 |
| 活性：TTL/Hops 与 TCP 关闭 | S6、S15 | TTL+Hops≤255、终止由 carrier | 自动重传不是本层行为 |
| NAT/代理/被动：显式地址/端口 | S10–S12 | 连接字段逐项使用 | NAT 实网互操作待 P5；GNT-D1 |
| 版本/方言：0.6 与 IPv6 profile | S1、S11、S12 | profile 白名单 | Vendor 方言待确认；GNT-D1 |

### 4.2 命令×响应码矩阵

| 请求/事件 | 合法响应/后继 | 已覆盖 |
|---|---|---|
| CONNECT | 200 OK | S1、S2–S7、S9–S15 |
| CONNECT | 503 refuse | 设计支持，未单列 JSON，待新增 |
| PING | PONG（同 MessageID） | S2、S10 |
| QUERY | QUERY_HIT（同 QueryID） | S3、S7、S14 |
| QUERY_HIT | PUSH（同 ServentID/FileIndex） | S4、S15 |
| VENDOR | Vendor payload | S5、S13 |
| 任意业务 | FIN/ACK 终止 | 所有正例 `terminates` |

### 4.3 数据形态变体

| 形态 | 正例/负例 | 结论 |
|---|---|---|
| IPv4/IPv6 outer | S1、S11、S12 | 已实现，payload 地址 profile 独立 |
| 空 payload PING | S2、S6、S15 | 已实现 |
| NUL criteria/多 results | S3、S7、S15 | 已实现 |
| binary Vendor/base64 输入 | S5、S13 | 已实现，线上为裸字节 |
| MSS 跨段 | S14 | TCP 重组覆盖 |
| TTL/Hops 边界与回绕 | S6、S15、N3 | 正负均覆盖 |
| 截断/未知 descriptor/地址长度 | N1、N2、N5 | validator 拒绝 |

### 4.4 商业行为→用例映射

| 可观察行为 | 来源/取舍 | 用例 |
|---|---|---|
| LimeWire/Gnutella 0.6 风格 CONNECT/200 能力头 | 公开 Gnutella 0.6 wire profile；只生成可观测头 | S1 |
| PING/PONG 邻居发现 | Gnutella 0.6 message 约定 | S2、S10 |
| QueryHit 后 Push 反向请求 | Gnutella 常见客户端行为；不自动生成下载流 | S3、S4 |
| TTL/Hops 转发 | Gnutella message header 约定 | S6 |
| Vendor 扩展 | BearShare/LimeWire 生态常见扩展形；payload 原样 | S5、S13 |
| IPv6、多连接、长消息 | 现网兼容性场景，需抓包复核 | S9–S14 |

### 4.5 三路对照

| 规范原文/章节 | 商业软件行为 | 开源实现思路 |
|---|---|---|
| Gnutella 0.6 handshake | LimeWire 风格能力头与 200/503 | gtk-gnutella 连接状态机：握手后进入消息循环 |
| Gnutella message header | GUID/descriptor/TTL/hops/LE length 固定 23B | mutella/gtk-gnutella 按流缓存后按长度取帧 |
| QUERY/QUERY_HIT/PUSH | 搜索命中后可发 Push | 开源实现以 QueryID/ServentID 映射关联 |

### 4.6 候选方案

| 方案 | 优点 | 代价 | 选择 |
|---|---|---|---|
| A：TCP 层分段，终结层仅产事件 | 复用 TCP/MSS/关闭，内存流式 | 需事件面接线 | **采用**，当前 `GenRequest.EmitMsg` 路径 |
| B：终结层自产完整 Ethernet/TCP 包 | 可完全控制 wire | 重复 TCP 状态、难以复用、内存高 | 不采用 |
| C：按固定消息模板循环 | 实现短 | 无法表达关联、转发和错误状态 | 不采用 |

## 5. 依赖与错误处理

依赖顺序为 `ip → tcp → gnutella`；tcp 完成三次握手、payload 分段和 FIN，gnutella 依赖其事件序列。缺少 CONNECT、OK 前业务、方向错误、关闭后业务、未知事件、TTL/Hops 回绕、未知 Query/Servent、Hits 与 results 不等、地址 profile 不符时返回带 `handshake`/`state`/`descriptor`/`ttl`/`query`/`address`/`port` 锚词的 error，中断该任务且不产成功 PCAP。实现没有自动重试；超时和 TCP 重传由承载层或外部任务策略处理。合法 503、空 QueryHit、重复 GUID 去重是业务事件，不当作 planner error。

## 6. 性能设计与验收

生成器按 connection/event 流式产出，不汇总全量消息；每个事件只保留当前帧和连接状态（GUID/Query/Servent 映射），队列使用统一有界 pipeline。目标基线为 20 例单连接与 S9/S10 两连接；压力规模、并发连接数、最大 payload、内存上限、队列上限和 CPU 并行度以 P5 基准测量后填写，不把未测数字当承诺。资源边界是 `frame_max` 和 TCP MSS，超界立即 error，不能按 `0xffffffff` 分配。

pcap 验收：逐例执行 suite，校验 packet_count/min_packets、TCP 端口、IP 版本、payload offset 和稳定 frame hex；负例只校验 error 锚词。网卡验收：使用同一 spec 经 tcpdump 捕获，校验四元组、握手方向、MessageID/TTL/Hops/业务 payload，比较 pcap 与网卡包数、丢包和错误；本任务未运行 suite/NIC。

## 7. 动态字段清单与序号算法

| 字段 | 策略 | 序号/代码 |
|---|---|---|
| ip.src/dst | 当前事件连接显式值；跨流动态对象未在本协议 schema 开放 | `chain_planner_util.go:90-97` 自驱判定；连接取值 `layer_gen.go` |
| tcp.src_port | 每 connection 显式值，缺省由承载保底 | `layer_gen.go`/TCP builder |
| tcp.dst_port | fixed 6346；其它值 validator 拒绝 | `layer_gen.go:461-469` |
| MessageID | fixed bytes；重复值用于转发/去重 | `layer_gen.go:375-397` |
| QueryID/ServentID | fixed bytes；必须引用当前 connection 状态 | `layer_gen.go:405-435` |
| TTL/Hops | fixed per event；转发要求 TTL−1/Hops+1 | `layer_gen.go:336-338,385-397` |
| criteria/results/vendor payload | fixed event data；原样编码，不自动随机 | `builder.go` |

本批没有 `flows>1` 用例；因此不把静态复制伪装成动态覆盖。需要 inc/rand/list/pattern 时先在 schema 给连接和业务字段定义策略，再增加整格用例。

## 8. 实现八要素与回滚

- 文件：`internal/core/layers/registry.go`、`chain_planner_util.go`、`generator.go`、`internal/protocol/gnutella/{layer_gen.go,builder.go}`；契约文件为本设计、`testcase.md`、cases JSON。
- 接口：terminal layer generator `Name/Build/GenRequest`，validator `ValidateSpec`；事件由 `connections[].events[]` 表达。
- 结构：`GnutellaConfig`、`GnutellaConn`、`GnutellaEvent`，每连接独立状态。
- 流程：层链解析→依赖补全→握手事件→消息校验/编码→TCP 分段→关闭。
- 错误：统一返回 task error，负例锚词见 §5；禁止 completed/0 packet 假成功。
- 性能边界：流式事件、`frame_max`、MSS 重组、有界 pipeline。
- 冲突点：tshark QUERY_HIT 伪 malformed 不能驱动生成器改帧；业务消息不自动产生下载流。
- 回滚：仅回滚本协议三份契约文件和对应实现提交；不得恢复旧顶层字段或旧断言。

## 9. 现状与验收索引

20 个语义 ID 与 `testcase.md §2`、cases JSON 同序：14 正（S1–S7、S9–S15，历史无 S8）+6 负（N1–N6）。完成判定须同时满足层链顶层旧键零残留、正例输出断言、负例真实拒绝和三源回指；本次文档改造不宣称 suite 已重跑。

## 10. D1–D8 / 门1状态

| 条目 | 结论 | 证据或缺口 |
|---|---|---|
| D1 层链配置 | 已迁移 cases 形状；未接线 | `chain_planner_translate.go` 无 `case "gnutella"`；GNT-D1 |
| D2 规范矩阵 | 已有 | §4.1–§4.5；wire profile、实现与现网取舍分列 |
| D3 状态/事务 | 已有 | §3、§5；每 connection 独立状态 |
| D4 错误契约 | 已有 | §5；错误锚词与 N1–N6 对账 |
| D5 性能 | 边界已定，基准待测 | §6；GNT-D5：P5 才测吞吐/内存/背压 |
| D6 三路/候选 | 已有 | §4.5/§4.6；规范、商业行为、开源思路分列 |
| D7 动态 | 明确不开放 | §7：当前仅显式 fixed；业务动态需 schema 立项 GNT-D7 |
| D8 八要素/回滚 | 已有 | §8；文件、接口、结构、流程、错误、性能、冲突、回滚齐全 |

门1：§1 旧字段去向、§3 五件套、§12 动态清单均已写明；层链入口仍未接线，故不宣称门2/门3通过。

## 11. 修订记录

- v2.1.0（2026-10-01）：补齐 D1–D8 状态与门1结论；cases 已迁严格层链但保留 GNT-D1 translator 待实现边界。
- v2.0.0（2026-09-30）：按 CORE §1–§15 补齐层链门1、规范矩阵、三张子表、三路对照、候选方案、依赖错误、性能、八要素和动态清单；20 个旧形状 cases 登记 GNT-D1，未伪迁。
