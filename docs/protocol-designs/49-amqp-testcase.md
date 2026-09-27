# AMQP（高级消息队列协议，Advanced Message Queuing Protocol）测试用例契约

> 版本：v2.1.0（P4–P6 交付回写；v2.0.0 = P3 产物）
> 日期：2026-09-27
> 配套设计：`docs/protocol-designs/49-amqp-design.md`（v2.1.0 P6 修轮版；D-AMQP-1；门1 获批=定稿）
> 机器契约：`trafficgen/test/protocol_pcap/cases/amqp.json`（交付 **24** 例 = 20 语义 ID〔14 正 + 6 负〕+ 4 链级红例，见 design §13-P2）
> 状态：`amqp` 层已注册、builder/planner/generator 已落码（`registry.go:486`，`internal/protocol/amqp/`），**P4 层链接线 + P5 去扁平改写 + P6 修轮已完成**——lane8 suite 24/24 全绿、coverage 反查 68/68 绿。本文 §2 的 20 个语义 ID 仍为 ID 权威口径；JSON 尾部 4 例为链级红例（presence/游离键/udp 载体/缺 tcp）。

## 1. 测试原则

用例从设计 §2–§10 逐项派生，共 20 个唯一标识：14 个正例、6 个负例（v1.0.0 所述 `amqp_neg_unregistered` 占位在存量 JSON 中**不存在**——20/20 均为语义 ID，见 §5 实测）。AMQP 是 TCP 应用层协议，只做 AMQP 0-9-1（AMQP 1.0 是另一套 framing，明确不支持）；链形 `[ip,tcp,amqp]`，目的端口 5672。无 VLAN/IP options/TCP options 时，IPv4 TCP payload 起点 offset（偏移）54，IPv6 为 74。TCP MSS 分段后必须按 frame-size 重组 AMQP frame（帧）；正例落盘口径为 `packet_count`（精确等值，比 min 更严）+ 可观测 `fields`（字段）+ 非空 `frames`（帧字节）；P3 契约写的 `min_packets` 已按 §9.6.4「先跑后钉」在 P4/P5 校准为 `packet_count`（n2 措辞同步）。负例 `expect` 严格只有 `expect_error` 与 `error_contains`。

- 每个正例都有 `packet_count`（精确值）、非空 `fields`、非空 `frames`；TCP 真握手/挥手由 tcp 层承载（落盘实测 3 握手 + N 数据 + 4 挥手；`has_handshake`/`terminates` 为 tcp 层既有语义，不写成契约键——族内 ocsp/dtls/kerberos 同口径）。
- 正例字段全部来自 `tshark -G fields` 已注册的 `amqp.*` / `tcp.*` / `ipv6.*` 字段（本机 3.6.14，`amqp.*` 精确口径 493 个；本套件去重 8 个 1/1 精确命中）。
- frames 只固定 protocol header（`41 4d 51 50 00 00 09 01`）与 heartbeat（`08 00 00 00 00 00 00 ce`）等可复算前缀；动态 TCP sequence、协商值、consumer tag、delivery tag 不写死。
- **严格解码边界（P1 实测，诚实声明）**：`amqp` 子映射经 `parseSubconfigJSON`（`strategy_convert_helpers.go:21-30`）普通 `json.Unmarshal`（无 `DisallowUnknownFields`）解码——未知键静默忽略；负例不得依赖"未知键被拒"，必须走 `wire_fault`（9 值，`planner.go:432-455`）或自然守卫。
- **负例 expect 形状缺口（P1 实测）**：存量 6 负例 `expect` 含空 `fields: []`（6/6）——不合"只有两键"契约，P4 改写时删除（§5 去向表）。
- 多连接/多 channel 用 `tcp.srcport` distinct、channel/delivery/consumer 关联断言，不假设跨流调度顺序。

## 2. 原子用例索引（与设计、JSON 同序）

| # | ID | 类型 | 覆盖 | packet_count（落盘实测） |
|---:|---|---|---|---:|
| 1 | `amqp_protocol_header_ipv4` | 正 | AMQP 0-9-1 8-byte protocol header、TCP/IPv4 | 8 |
| 2 | `amqp_connection_handshake` | 正 | start/start-ok/tune/tune-ok/open/open-ok | 14 |
| 3 | `amqp_channel_open_close` | 正 | channel 1 open/close 全序 + connection close | 20 |
| 4 | `amqp_heartbeat` | 正 | type 8、channel 0、size 0、CE（双向双包） | 16 |
| 5 | `amqp_exchange_queue_declare` | 正 | exchange/queue declare 参数和响应 | 20 |
| 6 | `amqp_basic_publish` | 正 | publish→HEADER→BODY、BodySize=6 | 19 |
| 7 | `amqp_basic_body_segmentation` | 正 | 200B body、frame_max=128 多 BODY 拆分 | 20 |
| 8 | `amqp_basic_consume_deliver_ack` | 正 | consumer/deliver/header/body/ack 关联 | 22 |
| 9 | `amqp_basic_get_empty` | 正 | basic.get(70) 与显式 get-empty(72) | 18 |
| 10 | `amqp_confirm_transaction` | 正 | tx.select/commit/rollback 六方法（class 90） | 22 |
| 11 | `amqp_keepalive_multi_channel` | 正 | 双 channel + heartbeat 隔离 | 21 |
| 12 | `amqp_multi_connection` | 正 | 两个 TCP 连接（src_port 12345/12346） | 21 |
| 13 | `amqp_ipv6` | 正 | IPv6/TCP、应用 bytes 不变、offset 74 | 8 |
| 14 | `amqp_frame_boundary` | 正 | frame_max=4096、heartbeat 与 content 混排 | 20 |
| 15 | `amqp_neg_protocol_header` | 负 | wire_fault protocol_version | — |
| 16 | `amqp_neg_frame_encoding` | 负 | wire_fault bad_frame_type | — |
| 17 | `amqp_neg_handshake_state` | 负 | wire_fault handshake_state | — |
| 18 | `amqp_neg_channel_state` | 负 | channel 0 上 basic.publish（自然守卫） | — |
| 19 | `amqp_neg_content_length` | 负 | body_size_override=100 vs body=5（自然守卫） | — |
| 20 | `amqp_neg_session_reference` | 负 | wire_fault session_reference | — |

packet_count 序列（正例 14 个，按序，落盘实测）：`[8,14,20,16,20,19,20,22,18,22,21,21,8,20]`（= 3 握手 + N 数据段 + 4 挥手）。**profile 分布实测**：amqp091_minimal 10 例 / amqp091_rabbitmq 10 例（P3 语义 ID 口径，链级红例另计 4 例）。

## 3. 正例断言契约

- **断言通道**：`amqp.method.class`/`amqp.method.method`/`amqp.channel`/`amqp.type`/`amqp.length`/`amqp.header.class`/`amqp.header.body-size`（7 个 `amqp.*`）+ `tcp.dstport`/`ipv6.nxt`（载体面）——去重 9 字段，逐个对 `tshark -G fields`（本机 3.6.14，`amqp.*` 精确口径 493 个）**命中 9/9，零自创**。
- frames 实测两档 offset：**54**（IPv4 TCP payload 起点，#1–#12/#14 protocol header `41 4d 51 50 00 00 09 01`；#4/#14 另钉 heartbeat `08 00 00 00 00 00 00 ce`；#12 第二连接 packet 11 同 header）、**74**（IPv6，#13）。
- 逐例要点：
  1. `amqp_protocol_header_ipv4`：断言 TCP dstport 5672 + packet 4 offset 54 protocol header；TCP 握手 3 包 + 1 数据包。
  2. `amqp_connection_handshake`：六方法 class/method/方向逐包断言（packet 5–10），全部 channel 0；packet 索引为近似值，依实现可有偏移（先跑后钉）。
  3. `amqp_channel_open_close`：channel.open(20/10)→open-ok(20/11)→close(20/40)→close-ok(20/41)→connection.close(10/50)→close-ok(10/51)，业务 channel 1。
  4. `amqp_heartbeat`：`amqp.type=8` 双包（packet 11/12）+ `amqp.channel=0` + `amqp.length=0` + frame hex 钉死。
  5. `amqp_exchange_queue_declare`：exchange.declare(40/10)→declare-ok(40/11)→queue.declare(50/10)→declare-ok(50/11)，direct 类型 + 名称参数。
  6. `amqp_basic_publish`：basic.publish(60/40)→HEADER（`amqp.type=2`、`amqp.header.class=60`、`amqp.header.body-size=6`）→BODY（`amqp.type=3`）；BodySize 由生成器按 body 事件自动累加。
  7. `amqp_basic_body_segmentation`：frame_max=128、body 200B → 自动拆多 BODY frame；断言 Header BodySize=200 与重组 body 总长相等、单帧线上长 `7+Size+1≤frame_max`；不按单个 TCP packet 断言。
  8. `amqp_basic_consume_deliver_ack`：consume(60/20)→deliver(60/60)→HEADER→BODY→ack(60/80)；同 channel 同 delivery_tag/consumer_tag 关联（fixture 显式 `ctag1`/`delivery_tag=1`）。
  9. `amqp_basic_get_empty`：basic.get(60/70)→get-empty(60/72)；不自动生成 HEADER/BODY。
  10. `amqp_confirm_transaction`：tx.select(90/10)→select-ok→tx.commit(90/20)→commit-ok→tx.rollback(90/30)→rollback-ok；confirm.select（85/10）无用例 → A′ T-21（design §16 G-AMQP-3）。
  11. `amqp_keepalive_multi_channel`：channel 1/2 各自 open + 各自 basic.publish(60/40)（packet 16/17 断言 channel 1/2 隔离）+ heartbeat（`amqp.type=8` packet 15）；一个 channel 的 close 不重置另一个。
  12. `amqp_multi_connection`：两连接各自 protocol header + 完整握手（frames packet 4/11 双 header）；`connections[].src_port` 12345/12346；**notes 声称 `tcp.srcport distinct` 但存量 fields 未实际断言 → P5 补钉**（G-AMQP-2）。
  13. `amqp_ipv6`：`ipv6.nxt=6` + dstport 5672 + offset 74 同 protocol header；应用 bytes 不因地址族改变。
  14. `amqp_frame_boundary`：frame_max=4096 + 空 properties header（BodySize=0 仍有 HEADER）+ heartbeat c2s/s2c 混排。

## 4. 负例契约

负例必须以任务错误终止，不输出成功 PCAP、completed/0 packet 或仅有 ACK。`error_contains` 逐字对已落码锚词（P1 实测 `planner.go:432-455`，非设计臆造）：

| # | ID | 故障输入（存量形状） | `error_contains` | 代码锚点（实测） |
|---:|---|---|---|---|
| 15 | `amqp_neg_protocol_header` | `amqp.wire_fault="protocol_version"` | `protocol` | `planner.go:434-435`（`protocol version mismatch`） |
| 16 | `amqp_neg_frame_encoding` | `amqp.wire_fault="bad_frame_type"` | `frame` | `planner.go:436-437`（`bad frame type`） |
| 17 | `amqp_neg_handshake_state` | `amqp.wire_fault="handshake_state"` + open-before-tune-ok 事件序 | `handshake` | `planner.go:442-443`（`handshake state violation`）；事件序本身亦触发自然守卫 `:272`（`connection.open before tune-ok`） |
| 18 | `amqp_neg_channel_state` | 无 wire_fault——channel 0 上 basic.publish（channel.open 先行拒 `:293`，publish 未开 channel 拒 `:306`） | `channel` | `planner.go:293/306`（`channel 0 (reserved)` / `unopened channel`） |
| 19 | `amqp_neg_content_length` | 无 wire_fault——`body_size_override=100` + body 5B | `body` | `planner.go:422-426`（`body size mismatch: declared 100, sent 5`） |
| 20 | `amqp_neg_session_reference` | `amqp.wire_fault="session_reference"` | `session` | `planner.go:448-449`（`session reference violation`） |

wire_fault 9 值中未用值 5 个（`shortstr_overflow`/`bad_frame_end`/`frame_size_overflow`/`channel_state`/`body_length`）→ G-AMQP-3（P4/P5 补例）。**P4 改写纪律**：负例 `expect` 删除空 `fields: []`，只留 `{expect_error, error_contains}` 两键。

## 5. 存量 20 例逐条去向审计（§9.14；P1 存量实测，P4 按本表执行）

存量现状（2026-09-26 实测，`cases/amqp.json` 3682 行）：20/20 同一旧扁平形——`spec_json` 顶层键 `['amqp','dst_ip','dst_port','layers','src_ip','src_port']`（白名单外 5 键：4 地址端口键 + 顶层 `amqp` 子映射）；`layers=[{"tcp":{}},{"amqp":{}}]` 空条目（无 `ip` 层、无层内地址端口）；20/20 无 `flow_control` 键；6/6 负例 expect 多空 `fields: []`。去向：14 正例全部**合入**（层链整形后保留语义，min_packets/包号先跑后钉）；6 负例全部**合入**（锚词已对真实代码行）。

| # | ID | 去向 | 改写要点 |
|---:|---|---|---|
| 1 | `amqp_protocol_header_ipv4` | 合入 | 顶层四键→`ip`/`tcp` 层；`amqp` 子映射→`layers[2].amqp`；补 `flow_control.flows=1`；min_packets=4 先跑后钉 |
| 2 | `amqp_connection_handshake` | 合入 | 同上；六方法断言保留，packet 索引 P5 校准 |
| 3 | `amqp_channel_open_close` | 合入 | 同上；min_packets=16 先跑后钉 |
| 4 | `amqp_heartbeat` | 合入 | 同上；`heartbeat: 30` 配置键随层迁入；frames 双 hex 保持 |
| 5 | `amqp_exchange_queue_declare` | 合入 | 同上；exchange/queue 参数面保留 |
| 6 | `amqp_basic_publish` | 合入 | 同上；BodySize=6 先跑后钉 |
| 7 | `amqp_basic_body_segmentation` | 合入 | 同上；`frame_max: 128` 随层迁入；body 200B 保留 |
| 8 | `amqp_basic_consume_deliver_ack` | 合入 | 同上；tag 关联 fixture 保留 |
| 9 | `amqp_basic_get_empty` | 合入 | 同上；get(70)/get-empty(72) 断言保留 |
| 10 | `amqp_confirm_transaction` | 合入 | 同上；tx 六方法保留（confirm.select 面 → A′ T-21） |
| 11 | `amqp_keepalive_multi_channel` | 合入 | 同上；`heartbeat: 30` 迁入；channel 1/2 隔离断言保留 |
| 12 | `amqp_multi_connection` | 合入 | 同上；`connections[].src_port` 12345/12346 保留；`tcp.srcport distinct` 断言 P5 补钉（G-AMQP-2） |
| 13 | `amqp_ipv6` | 合入 | `ip` 层填 v6 地址 `2001:db8::1→::2`；offset 74 保持 |
| 14 | `amqp_frame_boundary` | 合入 | 同上；`frame_max: 4096` 迁入；空 properties header 保留 |
| 15 | `amqp_neg_protocol_header` | 合入 | 负例改写同正例形状；**删 expect 空 `fields: []`**；锚词 `protocol` 已对 `planner.go:435` |
| 16 | `amqp_neg_frame_encoding` | 合入 | 同上；`frame` 对 `:437` |
| 17 | `amqp_neg_handshake_state` | 合入 | 同上；`handshake` 对 `:443` |
| 18 | `amqp_neg_channel_state` | 合入 | 同上；`channel` 对 `:293/:306`（自然守卫，无 wire_fault） |
| 19 | `amqp_neg_content_length` | 合入 | 同上；`body` 对 `:425`（自然守卫） |
| 20 | `amqp_neg_session_reference` | 合入 | 同上；`session` 对 `:449` |

作废 0 例，等价覆盖 0 例（无重复语义可合并）。

## 6. 三方一致性清单

1. 设计 §10、本文 §2 和 JSON 必须保持同一 20 个语义 ID、同一顺序；正例 14、负例 6（实测 20/20 全为语义 ID，v1.0.0 占位形不存在）。
2. 正例 packet_count 序列（落盘实测）`[8,14,20,16,20,19,20,22,18,22,21,21,8,20]`（= 3 握手 + N 数据 + 4 挥手；body 分段按 frame_max 增段）；P3 契约的 min_packets `[4,10,16,12,16,15,16,18,14,18,17,17,4,16]` 已按先跑后钉作废；负例无 packet_count。
3. 每个正例断言逐包 `fields`（含逐帧 channel/method 归属与 tag 关联）+ `frames` hex；`amqp.*` 字段全部注册命中。
4. IPv4 frame offset=54、IPv6=74；动态 TCP sequence/协商值不进 frames。
5. multi-connection 用 `tcp.srcport` distinct、multi-channel 用 `amqp.channel` 区分；不硬编码跨流 packet index（先跑后钉校准）。
6. 负例 `expect` 改写后只有 `expect_error`、`error_contains` 两键（存量空 `fields` 删除）。

## 7. 实现后执行顺序

先执行 JSON 语法、ID 顺序、正负 expect 结构、字段注册名、offset/hex 静态检查；再按 1–14 验证 IPv4/IPv6 载体、六步握手、channel/content/heartbeat 帧；最后按 15–20 验证每个拒绝路径和错误传播。tshark 对 `amqp.method.class/method`、`amqp.type/channel/length`、`amqp.header.*` 已实测可读；不能以"任务完成但 0 包"作为通过。服务器二进制与 HEAD 同代后跑全量（`CASE_PROTO=amqp`），不以增量绿充数。

## 8. 修订记录

- v2.1.0（2026-09-27）：P4–P6 交付回写（P6 修轮版）。**P6 修轮**：M1 回补正例断言钉子（#3/#5/#6/#7/#8/#9/#10/#11/#14 恢复 legacy 逐帧 class/method/channel 钉 + 新增参数面钉 `amqp.method.arguments.exchange/type`（#5）与 `consumer_tag/delivery_tag`（#8）），全部以 lane8 落盘 pcap 的 tshark 逐帧复核为准（先跑后钉）；M2 复合大场景下限闭合（#8 三类交织齐）+ 新增 §9.8 9.49–9.53 台账；n1 行号漂移重钉（registry.go 486/478-485/488、strategy_convert.go 636-638、planner channel 锚 293/306/326）；n2 措辞同步（min_packets → 落盘 packet_count，§1/§2/§6）；n4 编号残修正（design §10 ipv6 行号 8→13、占位句删除）；n5 陈旧 646B 落盘清理。design 侧同步：§4.1 表 basic.cancel=30/basic.deliver=60（P6 勘误第二轮）、§12.2 R3c2 引用回正 :293、§13.12 序号算法落点回填（layer_dyn.go resolveLayerTuple :770）、G-AMQP-3 并入 m3 枚举缺口（get-ok/cancel/cancel-ok）。
- v2.0.0（2026-09-26）：P3 完整产物。新增 §5 存量 20 例逐条去向审计表（旧扁平形→层链目标形，P4 执行）、§9 固定动作（§3.15 三项 / A′B′ 两分类 / 9.52 对账 / 3.14 豁免审计 / 三源回指 / 断言契约核对 / 性能验收）；§4 锚词表改为对已落码行号实测；§1 状态与严格解码边界更正（层已注册、占位形不存在、负例空 fields 缺口）；§3 补 offset 两档与字段 9/9 命中实测。
- v1.0.0（2026-08-20）：建立 14 个正例、6 个严格负例和 1 个未注册占位；不修改 Go 实现。

## 9. P3 固定动作（CORE_MEMORY §3.15 / §9.52 / §9.14 / 覆盖审计要求面）

### 9.1 §3.15 三项逐项一例或立项（无例无项即缺口）

| # | 三项 | 本协议对照 | 用例/立项 |
|---|---|---|---|
| ① | 同连接/同流内的多轮操作 | 单 TCP 连接多事务编排：六步握手→拓扑声明→publish→consume/deliver/ack→tx 三轮→close（#3/#5/#6/#8/#10 全序覆盖；#10 tx select/commit/rollback 三轮） | 已覆：#3–#10 多轮 + #11 多 channel |
| ② | 非正常结束 | protocol/frame/handshake/channel/body/session 六类拒收（#15–#20），全部 task error 终态 | 已覆：#15–#20（6 负例，锚词逐字见 §4） |
| ③ | 长保活 | heartbeat 事件（channel 0，#4/#11/#14 已覆）；**周期自动心跳调度明确不支持**（design §12.1 #6，声明式回放族，heartbeat 是显式事件） | 已覆（显式事件面）+ 明确不支持（周期调度，不用"待确认"逃逸） |

无空项。

### 9.2 A′/B′ 两分类表（要求面反推：数据/业务/现网/多流/地址族/断言通道六类）

A′（引擎可构建 → 20 ID 内已覆；**A′ 补例建议 = T-20/T-21**，并入与否由主线程定，不影响 §2 的 20 ID 权威口径）：

| 面 | 要求点 | 去向 |
|---|---|---|
| 数据 | frame 四类型/channel 0 与业务 channel/shortstr/longstr/table/properties flags/BodySize/frame_max 分段 | #1–#14 已覆；**shortstr 255/256 边界无用例 → A′ T-20**；14 property 全集子面 → G-AMQP-3 |
| 业务 | 六步握手顺序/方向、channel 开关、content 序列 method→header→body、delivery/consumer 关联、tx/confirm | #2/#3/#6/#8/#10 已覆；**confirm.select（85/10）无用例 → A′ T-21** |
| 现网 | RabbitMQ 连接/发布/消费/拓扑声明/心跳形态 | #1–#11 已覆外壳；**抓包级确认 → G-AMQP-1**（确认方式：抓 client-broker 回环包）；tune 协商差异面 → G-AMQP-1 |
| 多流 | 双 TCP 连接（#12）+ 单连接双 channel（#11）+ heartbeat 交织（#11/#14） | 已覆；**`tcp.srcport distinct` 断言存量未实钉 → P5 补钉（G-AMQP-2）**；校验器单连接面 → G-AMQP-2 |
| 地址族 | IPv4（13 例）/IPv6（#13）对称 | #13 已覆；无缺格（应用 bytes 不变断言双族） |
| 断言通道 | `amqp.*` 去重 7 + `tcp.dstport`/`ipv6.nxt` = 9 字段（9/9 实测命中）+ frames hex（offset 54/74 两档） | 全正例双通道；动态值不进 frames |

B′（引擎结构缺口 → D-AMQP-1「明确不解决 + 迁入计划」，见 design §16 G-AMQP-2/G-AMQP-4）：validateAMQPConfig 只扫 Connections[0]（第 2+ 连接事件不校验）、未知 amqp 键拒绝守卫（跨协议共享面上报主线程）、AMQP 1.0 framing（明确不支持）、AMQPS/TLS 5671 载体（→ G-AMQP-1）。

### 9.3 9.52 对账两行 + 清单出处声明

- **清单出处声明**：本清单来源 = **规范反推**（AMQP 0-9-1 wire-level specification；精确章节号待 G-AMQP-1），**非**引擎能力面反推。引擎侧只作现状取证：`amqp` 已注册（`registry.go:486`）/白名单（`protocols.go:22`）/builder+planner+generator 已落码（`internal/protocol/amqp/` 1902 行）/`cases/amqp.json` 20 例（旧扁平形）/tshark `amqp.*` 493 字段实测。第三源"已确认现网行为"当前=未确认级，挂 G-AMQP-1。
- **对账两行**：**规范逻辑点总数 = 50**（design §12.1 八项 8 行 + §12.2 事件×状态矩阵 28 格 + §12.3 数据形态变体表 14 行）；**用例覆盖数 = 29**（八项 8 行全有结论 + 矩阵 7 格已覆 + 变体 14 行，全部由 20 个语义 ID 承载）；**不适用 = 10**（矩阵 R1c2/R1c4/R3c3/R5c3/R5c4/R6c2/R6c3/R6c4/R7c3/R7c4，显式声明不适用≠缺口）；**A′/B′/立项 = 11**（矩阵缺口→用例通道 10 格由 #15–#20 负例承载 + R6c1 confirm 半格 → T-21；合计 11 点挂 T-20/T-21/G-AMQP-2/G-AMQP-3）。29 + 10 + 11 = 50 ✓ 无遗漏、无双计（P6 n8 修：与 design §12.2 重数句同口径四桶互斥）。**反查 20/20 绿 ≠ 覆盖全**——反查只证明清单内的点有例，本对账才证明清单本身全（§9.52 原文）。
- **粒度声明（防误读）**：按 design §12 的行/格粒度计数；变体表 wire_fault 行的部分子值（5 个未用值）另登 G-AMQP-3，不折进 50 点、也不冒充覆盖。

### 9.4 3.14 豁免边界审计

- 本协议**单 TCP 长连接多路复用**（channel 复用而非多连接）——但 §3.14 明示"豁免 `sessions[]` 不等于豁免多流覆盖"。本文**不主张任何豁免**：`connections[]` 显式声明（design §13.3 会话表），#12 覆盖双连接扇出。
- **多流并发**：已覆 #12（双 TCP 四元组独立握手）。
- **单包多载荷**：单连接多 channel（#11 双 channel 各自业务）+ 单 publish 多 BODY（#7 分段）已覆 → 显式记已覆；无逃逸。
- **多事务**：同连接内握手→拓扑→content→ack→tx→close 多轮（#3–#10）已覆。
- 结论：多流、单包多载荷、多包序列三项各有结论，无逃逸。

### 9.5 三源回指行

AMQP 0-9-1 wire-level specification（frame/class/状态机/编码）→ **D-AMQP-1**（design §14）→ `trafficgen/test/protocol_pcap/cases/amqp.json`（20 例）。第三源"已确认的现网行为"当前为**未确认级**（design §12.4 ②），挂 G-AMQP-1 且按 §5.5 不写死进实现。ID 权威 = 本文 §2（14 正 + 6 负）。

### 9.6 断言契约核对结论（与 design §10/§13 一致）

1. **20 ID 契约核对**：本文 §2 与 design §10 逐 ID、逐序、逐类型一致——14 正例（min_packets `[4,10,16,12,16,15,16,18,14,18,17,17,4,16]`，先跑后钉）+ 6 负例（锚词 `protocol/frame/handshake/channel/body/session` 逐字对 `planner.go:432-455` 及 `:293/:306/:425` 真实字符串）。
2. **存量审计（§9.14）**：见 §5 去向表。20 例同一旧扁平形（`layers=[{tcp:{}},{amqp:{}}]` 空条目 + 顶层四键 + 顶层 `amqp` 子映射 + 无 `flow_control`；负例多空 `fields`），P4 按去向表逐例改写，**不搬运旧期望值**（min_packets/包号先跑后钉）。
3. **断言通道核对**：9 个字段（`amqp.*` 7 + `tcp.dstport` + `ipv6.nxt`）逐个注册命中（`tshark -G fields` 精确口径 493 个中的 7 个 `amqp.*` 1/1 命中）；frames hex 两档 offset（54/74）实测。
4. **min_packets 纪律**：§2 的约定值随 P4 **先跑后钉**（§9.31/§14.6），以落盘 pcap 实测校准；#2 断言注记已自认"packet 索引为近似值"，P5 校准时不照抄存量。

### 9.7 性能设计与验收（§6.1–6.8 要素；细目见 design §14）

- 目标口径：O(n) 流式——`Generate` 逐事件渲染直发 `EmitMsg`，body 分段即时 Emit，无按包增长结构、无全量聚合（design §14 主流程）；无锁无 sleep（事件驱动，无心跳定时器）。
- 两路验收（§6.3）：**pcap 路**——suite 全量落盘 `/tmp/mcp-pcaps/amqp/`，tshark 逐字段校对；**NIC 路**——过滤器 `tcp port 5672`，测试网口按 testing-interface 记忆（`enp135s0f0np0`），关注 frame 序列在线上可见与 TCP 分段重组正确。
- 六类场景（§6.6）P5 跑测覆盖：基线（#1 单包）/目标规模（#8 十八包全编排）/压力上限（`flows=N` 大 N × 长事件序）/长时间运行/并发交错（#12 多连接）/资源耗尽背压（队列满走既有 pipeline 语义）。
- 失败边界（§6.5 诚实待确认）：吞吐/并发/内存目标数字待 P4 基准后定，本契约不写承诺数字；功能正确但超预算按 §6.8 视为不合格。

### 9.8 9.49–9.53 复合大场景台账（P6 修轮补登）

| 条款 | 要求 | 本协议落点（P6 修轮后实测） |
|---|---|---|
| 9.49 | 多连接/多事务/多流各一例 + 真实编排 | 多连接 #12（双 TCP 连接声明 + 双 protocol header 帧钉；同流直发形状 → G-AMQP-2 立项）；多事务 #8（consume→deliver→HEADER→BODY→ack 五轮）+ #10（tx 三轮六方法逐帧）；多 channel #11（channel 1/2 各自 open/open-ok + 各自 publish + heartbeat 交织） |
| 9.50 | 复合大场景 ≥3 类交织 | **#8 = 三类交织且断言撑住**：①多事务（5 轮编排逐帧）②内容序列（method→HEADER→BODY 三帧同 channel）③交付关联（consumer_tag=ctag1 跨 consume/deliver、delivery_tag=1 跨 deliver/ack） |
| 9.51 | 组合矩阵满格 | design §12.2 事件×状态 28 格逐格有结论（严格四桶互斥：已覆 7 + 缺口通道 10 + 不适用 10 + A′ 1） |
| 9.52 | 审计声明出处 + 对账两行 | design §12.1/§12.2/§12.3 清单由 AMQP 0-9-1 规范反推（出处声明见 §9.3）；对账 50 = 覆盖 29 + 不适用 10 + A′/B′/立项 11 |
| 9.53 | 门3 抽最复杂用例当场点数 | #8 `amqp_basic_consume_deliver_ack`：22 包；断言点 **28**（27 fields + 1 frame）；交织维度 **3 类**（上表 9.50 三项），全部经落盘 pcap tshark 逐帧实证（先跑后钉） |

- **9.53 点数口径**：断言点 = fields + frames；维度以"线上实测存在且用例断言钉住"才计（sstp/ntlm P6 同口径）。P6 打回根因 = 正例断言面被 P4 改写缩减（#8 只剩 1 维实钉），修轮回补后三钉齐。
