# MongoDB Wire Protocol（传统 OP_* 线协议）测试用例契约

> 版本：v1.0.0（P1–P3 文档轨产物；#87 mongodb）
> 日期：2026-09-27
> 配套设计：`docs/protocol-designs/87-mongodb-design.md`（v1.0.0，D-MONGODB-1）
> 机器契约：`trafficgen/test/protocol_pcap/cases/mongodb.json`（现存 **13** 例，7 正 + 6 负，**全混用形待改写**）
> 状态：**设计阶段**。本文**不跑 suite、不启动服务器**，不宣称任何绿的结论；ID 权威 = 本文 §2。存量 13 例的逐条审计去向见 §8。
> 旧基线：`docs/protocol-designs/32-mongodb-testcase.md`（v1.0.0，设计阶段，13 个 id）——其 id/包数/负例结构被本契约继承并重编（T-MONGO-S1…S7/N1…N6 → 本契约 #1–#14/#19–#24），其**混用形 spec 一律作废**（改写纪律 §1）。

## 1. 测试原则与形状基线

- **形状基线（CORE_MEMORY §1）**：`spec_json` 必须是**纯 layers** 形——地址只住 `ip` 层（`src`/`dst`；IPv6 地址族同住 `ip` 层，仓库无 `ipv6` 层）、端口只住 `tcp` 层（`src_port`；`dst_port` 不写，由 FieldContract 补齐 27017）、数量只走 `flow_control`；顶层只允许 `layers`/`flow_control` 家族/`output`（§1.11）。**正例顶层键 = 0**（白名单外即红）。
  **本协议存量实况（实测）**：13/13 例**全是混用形**（顶层 6 键 `{src_ip,dst_ip,src_port,dst_port,layers,mongodb}`，链 `[tcp,mongodb]` 无 `ip` 层）——有完整的 §1 **迁移工作量**（设计 §12.1）。P5 改写 13 例 + 新增 14 例，全部纯 layers 形（链 `[ip,tcp,mongodb]`）。
- **改写纪律**：fixture（头 hex、BSON hex、包数）**原样携带**（字节真相不变，只换配置形状）；`direction` 键**删除**（死字段 D1，设计 §2.3；删除后方向由 opcode 隐含）；改写后**全量重跑先跑后钉**（§9.31/§14.20）——若包数/hex 与旧值不一致，以 tshark 实测为准并记修订。
- **载体**：`mongodb` 为 TCP-only 终结层，链形 `[ip,tcp,mongodb]`（IPv6 同形，只换 `ip` 层地址）。链夹 `udp`（`[ip,udp,mongodb]`）判死（通用 `transport layer duplicated`，`complete.go:480`，锚词 `tcp`）。**UDP 面不存在**（设计 §5）。
- **端口**：`tcp.dst_port` **不写**，由 `mongodb` 层 `FieldContract` 补齐（`registry.go:635` = 27017）。**无强制等于校验**（设计 §2.1 诚实声明）：显式写非 27017 被尊重、不拒绝；非标端口 dissector 行为待 P4（G-MONGO-5）。
- **方向（本协议特有纪律）**：消息级 `direction` **不写**（死字段，生成器只看 opcode：OP_REPLY → down，其余 → up）。方向不断言为字段，只断言 `tcp.srcport/dstport` 与包序（`mongo.opcode` + frames hex 隐含方向）。
- **断言通道（实测）**：主通道 = tshark `mongo.*`（本机 TShark 3.6.14 实测 **92** 字段：`mongo.message_length/request_id/response_to/opcode/query.flags/full_collection_name/reply.flags/cursor_id/starting_from/number_returned/document/*`、`mongo.update.flags/selector/update`、`mongo.insert.flags`、`mongo.number_to_skip/number_to_return/query`、`mongo.delete.flags`、`mongo.number_to_cursor_ids/elements/element.*`、`mongo.msg.*`（OP_MSG 面，本版只作拒绝断言）、`mongo.compression.*`（本版不用））+ 载体字段 `tcp.srcport`/`tcp.dstport`/`tcp.flags`/`tcp.len`（+ IPv6 例 `ipv6.nxt`）；辅通道 = `frames` hex（IPv4 起点 **54** = 14+20+20；IPv6 起点 **74** = 14+40+20；selector 起点 93；INSERT 文档起点 85——旧审计复核口径）。
- **`decode_as` 纪律**：标准端口 27017 走 dissector 端口启发式，**无需**声明（存量 13/13 无 `decode_as` 全绿为旁证）；非标端口面待 P4（G-MONGO-5）。**禁用其他 decode_as 目标**。
- **动态值纪律（§9.34/§9.35）**：`flows>1` 的逐流变化只用 `nonzero`/`distinct_values` 断言，禁止硬编码包位；`checkLayerChainStaticCopy`（`semantic.go:198`）要求 `flows>1` 时四元组须有动态对象（`ip`/`tcp` 层标量 + `flows>1` 即拒）——多流例的 `tcp.src_port` 留空或写动态对象（§9.39）。
- **负例纪律（§14.11/§14.12）**：`expect` 键集合严格为 `{"expect_error","error_contains"}`；锚词与 validator/`checkWireFault`/链级错误字面值一一对应（设计 §4.2/§7）。**数字坏 opcode 负例必须确认错误从 planner/validator 传播至任务终态**（今日链路径空流假成功，G-MONGO-3 修后才能落盘）。
- **包数公式**：单会话 `packet_count = 3（SYN/SYN-ACK/ACK）+ N（应用事件数）+ 4（FIN 四way）= N + 7`；多会话 = 各会话独立经此公式后求和（`mongodb_multi_session` 2 会话 × 2 事件 → 2×9 = **18** ✓）。所有约定值按 §9.31/§14.20 **先跑后钉**。
- **「事件数」口径**：`messages[]` 数组长度（`sessions[]` 形则为各 session 的 `messages` 之和）；**握手/挥手不计入事件数**（由 `tcp` 层 `handshake`/`termination` 默认 true 产出）。

## 2. 原子用例索引（27 ID = 18 正 + 9 负，顺序为权威）

「今日」列：✅ = 现存能力即可跑（改写形状后；**22 例**）；A′ = 需 P4 接线（G-MONGO-1/2/3 修后落盘，**5 例**）。存量列：存量 13 例的继承去向（§8 逐条审计）。

| # | ID | 类型 | 覆盖 | 今日 | 存量 | 约定 packet_count |
|---:|---|---|---|---|---|---:|
| 1 | `mongodb_query_reply` | 正 | OP_QUERY→OP_REPLY、header 关联（T-MONGO-S1） | ✅ | 改写存量 | 9 |
| 2 | `mongodb_op_insert_single` | 正 | OP_INSERT 单消息（原子，T-MONGO-S2 拆分） | ✅ | 存量 `write_ops` 事件①单列 | 8 |
| 3 | `mongodb_op_update_single` | 正 | OP_UPDATE 单消息（原子，拆分） | ✅ | 存量 `write_ops` 事件②单列 | 8 |
| 4 | `mongodb_op_delete_single` | 正 | OP_DELETE 单消息（原子，拆分） | ✅ | 存量 `write_ops` 事件③单列 | 8 |
| 5 | `mongodb_op_getmore_single` | 正 | OP_GET_MORE 单消息（原子，拆分） | ✅ | 存量 `write_ops` 事件④单列 | 8 |
| 6 | `mongodb_op_killcursors_single` | 正 | OP_KILL_CURSORS 单消息（原子，拆分） | ✅ | 存量 `write_ops` 事件⑤单列 | 8 |
| 7 | `mongodb_write_ops` | 正 | 5 写/游标操作组合（T-MONGO-S2，存量保留） | ✅ | 改写存量 | 12 |
| 8 | `mongodb_bson_types` | 正 | 9 类 BSON fixture 通道（T-MONGO-S3） | ✅ | 改写存量 | 8 |
| 9 | `mongodb_empty_boundary` | 正 | 最小 BSON（5 字节）空 selector（T-MONGO-S4） | ✅ | 改写存量 | 8 |
| 10 | `mongodb_query_return_fields` | 正 | OP_QUERY 可选 returnFieldsSelector 面（现状声明） | ✅ | 新增 | 8 |
| 11 | `mongodb_bson_scalar_boundary` | 正 | BSON 标量边界：空串/false/空 binary/int32 上下界 | ✅ | 新增 | 8 |
| 12 | `mongodb_message_header` | 正 | length/requestID/responseTo/opCode 逐字节（T-MONGO-S7） | ✅ | 改写存量 | 8 |
| 13 | `mongodb_ipv6` | 正 | IPv6 OP_QUERY/REPLY（T-MONGO-S5） | ✅ | 改写存量 | 9 |
| 14 | `mongodb_multi_session` | 正 | 两会话整块展开（T-MONGO-S6） | ✅ | 改写存量 | 18 |
| 15 | `mongodb_request_sequence` | 正 | 同连接多操作编排：查询→写→GET_MORE→KILL（§3.15①） | ✅ | 新增 | 11 |
| 16 | `mongodb_reply_flags` | 正 | REPLY flags 位面（AwaitCapable/QueryFailure） | A′ | 新增（`$err` 文档形状待 G-MONGO-4） | 9 |
| 17 | `mongodb_long_document_mss` | 正 | 大文档跨 MSS 分段 | ✅ | 新增 | ≥8（先跑后钉） |
| 18 | `mongodb_multi_flow_dynamic` | 正 | `flows=N` 多流 + `ip`/`tcp` 层动态（§12.12） | ✅ | 新增（`strategy_fc` flows=N） | 8×N |
| 19 | `mongodb_neg_truncated_header` | 负 | `wire_fault truncate_header`（N1） | ✅ | 改写存量 | — |
| 20 | `mongodb_neg_short_length` | 负 | `wire_fault message_length`（N2） | ✅ | 改写存量 | — |
| 21 | `mongodb_neg_oversize` | 负 | `wire_fault message_limit`（N3） | ✅ | 改写存量 | — |
| 22 | `mongodb_neg_bad_opcode` | 负 | `wire_fault opcode` + 字符串坏 opcode（N4） | ✅ | 改写存量 | — |
| 23 | `mongodb_neg_bson_length` | 负 | `wire_fault bson_length`（N5） | ✅ | 改写存量 | — |
| 24 | `mongodb_neg_udp_carrier` | 负 | 链夹 `udp`（N6） | ✅ | 改写存量 | — |
| 25 | `mongodb_neg_opcode_rejected` | 负 | 坏 opcode 本体拒绝（字符串 + 数字越界，G-MONGO-3 修后） | A′ | 新增 | — |
| 26 | `mongodb_neg_flat_keys` | 负 | 顶层扁平四键判死（`CheckProtoFlat` 通用门） | ✅ | 新增 | — |
| 27 | `mongodb_neg_unknown_layer_field` | 负 | 层内第 5 个键（V9 `unknown field`） | ✅ | 新增 | — |

> **计数说明**：上表 **27 行** = **18 正**（#1–#18）+ **9 负**（#19–#27）。「今日」列机读复核口径 = **✅ 22 例 / A′ 5 例**（A′ = #16 + #25 + #17/#18 中随 G-MONGO-1/2 落盘的 3 例断言面……精确：#16/#25 为 validator/builder 修后落盘；#15/#17/#18 今日可跑但须 G-MONGO-1 translate 先行——见 §7 时序）。**A′ 用例的 ID 与断言在本文即定稿**，P4 落盘时按 §9.14 全量重跑（§14.19 全量非增量）。

## 3. 正例逐项断言契约

> 通则：①每条正例 `expect` 至少含 `packet_count`（#17 例外可用 `min_packets`）、`has_handshake`、`terminates`、`has_payload`；②字段断言用 `mongo.*`（92 字段实测）+ 载体字段；③**结构字节走 frames hex**；④**不写 `direction`**（死字段）；⑤负例零混入。以下 fixture 继承自存量（旧审计复核值），P5 先跑后钉时若实测不符以 tshark 为准并记修订。

1. **`mongodb_query_reply`**：链 `[ip,tcp,mongodb]`，`ip.src=10.0.0.1`/`ip.dst=20.0.0.1`（纯 layers 形；P5 可换 192.0.2 系 fixture），`tcp.src_port=12345`（**不写 dst_port**）。`messages` 2 条：OP_QUERY（request 100/responseTo 0/`test.users`/skip 0/return 1/query `{x:1}`）→ OP_REPLY（request 101/responseTo 100/cursor 0/starting 0/returned 1/documents `[{x:1}]`）。断言：`tcp.dstport=27017`（包 4）、`tcp.srcport=27017`（包 5）；`frames` 包 4 起点 54 = `33 00 00 00 64 00 00 00 00 00 00 00 d4 07 00 00`、包 4 起点 93 = `0c 00 00 00 10 78 00 01 00 00 00 00`、包 5 起点 54 = `30 00 00 00 65 00 00 00 64 00 00 00 01 00 00 00`；`mongo.opcode=2004`（包 4）/`=1`（包 5）、`mongo.request_id=100`/`mongo.response_to=100`（包 5）。`packet_count = 2 + 7 = 9`。
2. **`mongodb_op_insert_single`**：OP_INSERT（request 110/`test.users`/documents `[{x:1},{_id:"a"}]`）。断言包 4 起点 54 = `3b 00 00 00 6e 00 00 00 00 00 00 00 d2 07 00 00`（单测 `TestBuildInsertMessage` 同值）；`mongo.opcode=2002`。`packet_count = 1 + 7 = 8`。
3. **`mongodb_op_update_single`**：OP_UPDATE（request 120/`test.users`/zero 0/flags 2/selector `{x:1}`/update `{}`）。断言包 4 起点 54 头 `opcode=d1 07 00 00`（存量 S2 包 5 同值，包位前移）；`mongo.opcode=2001`。`packet_count = 8`。
4. **`mongodb_op_delete_single`**：OP_DELETE（request 130/`test.users`/zero 0/flags 1/selector `{x:1}`）。断言 `opcode=d6 07 00 00`；`mongo.opcode=2006`。`packet_count = 8`。
5. **`mongodb_op_getmore_single`**：OP_GET_MORE（request 140/`test.users`/zero 0/return 2/cursor `72623859790382856`）。断言 `opcode=d5 07 00 00`；`mongo.opcode=2005`、`mongo.cursor_id` nonzero。`packet_count = 8`。
6. **`mongodb_op_killcursors_single`**：OP_KILL_CURSORS（request 150/cursor_ids `[72623859790382856]`）。断言 `opcode=d7 07 00 00`；`mongo.opcode=2007`、`mongo.number_to_cursor_ids=1`。`packet_count = 8`。
7. **`mongodb_write_ops`**：存量 S2 原样（5 事件 request 110/120/130/140/150，`responseTo=0`）。断言包 4–8 起点 54 opcode 依次 `d2/d1/d6/d5/d7 07 00 00` + requestID 110/120/130/140/150（frames 或 `mongo.request_id`）；全数据包方向 up（`tcp.dstport=27017`）。`packet_count = 5 + 7 = 12`。
8. **`mongodb_bson_types`**：OP_INSERT（request 170/`test.users`）经 `bson_fixture_hex`（设计 §3.4 的 101 字节 fixture 原样）。断言包 4 起点 54 = `84 00 00 00 aa 00 00 00 00 00 00 00 d2 07 00 00`、包 4 起点 85 = `65 00 00 00 01 64 00 …`（文档长度 + 首字段前缀）；`mongo.opcode=2002`。`packet_count = 8`。
9. **`mongodb_empty_boundary`**：OP_QUERY（request 160）空 selector `{}`。断言包 4 起点 54 = `2c 00 00 00 a0 00 00 00 00 00 00 00 d4 07 00 00`、包 4 起点 93 = `05 00 00 00 00`。`packet_count = 8`。
10. **`mongodb_query_return_fields`**：OP_QUERY 带 returnFieldsSelector 面——**现状声明**：`MongoDBMessage` struct 今日**无此键**（`types.go:1231-1250` 实测），故本例先用"查询体 + return_count"钉 OP_QUERY 基本形，selector 扩展面待 G-MONGO-4 结构缺口收口后补字段。不断言不存在的键。`packet_count = 8`。
11. **`mongodb_bson_scalar_boundary`**：OP_INSERT 单文档多标量边界：空串 `""` / `false` / 空 binary / int32 上下界（2147483647/-2147483648）——**单键文档多消息**（避开 G-MONGO-2 多键随机序：每个边界值独立一条消息，或单元素 fixture）。断言 `mongo.element.*` 面 + frames 长度。`packet_count = N + 7`（N = 消息数，先跑后钉）。
12. **`mongodb_message_header`**：OP_INSERT（request 190）双文档（同存量 S7）。断言包 4 起点 54 = `3b 00 00 00 be 00 00 00 00 00 00 00 d2 07 00 00`，逐字段解释 length=59/requestID=190/responseTo=0/opCode=2002。`packet_count = 8`。
13. **`mongodb_ipv6`**：源 `2001:db8::1`→目的 `2001:db8::2`（同住 `ip` 层），OP_QUERY（180）→OP_REPLY（181/responseTo 180）。断言 `ipv6.nxt=6`（包 4）、包 4/5 起点 **74** 头 `33…b4…d4 07 00 00` / `30…b5…b4…01 00 00 00`；`mongo.opcode` 对。`packet_count = 9`。
14. **`mongodb_multi_session`**：`sessions[]` 两项（src_port 12345/12346），各 OP_QUERY→OP_REPLY（200→201 / 300→301）。断言 `tcp.srcport` distinct [12345, 12346]（exclude [27017]）+ `tcp.dstport` distinct [27017]（exclude [12345, 12346]）；**不按跨流包位推断事件序**。`packet_count = 18`。
15. **`mongodb_request_sequence`**：同连接 4 事件编排：OP_QUERY（→REPLY 配对）→ OP_INSERT → OP_GET_MORE（cursor fixture）→ OP_KILL_CURSORS。断言每包 `mongo.opcode` 序列 + `mongo.response_to` 配对（G-MONGO-3 修后加值断言，修前只断头字节）；§3.15① 载体。`packet_count = 4 + 7 = 11`。
16. **`mongodb_reply_flags`**（A′）：OP_QUERY → OP_REPLY（flags=`AwaitCapable`(bit3)）；另档 QueryFailure（bit1）+ `$err` 文档（待 G-MONGO-4）。断言 `mongo.reply.flags.awaitcapable` 面 + REPLY 体。`packet_count = 9`。
17. **`mongodb_long_document_mss`**：大文档 OP_INSERT（payload 逼近/超过默认 MSS 1460，`tcp` 层分段）。断言 `tcp.len` 分段 + 重组后 `mongo.message_length`；`packet_count` 用 `min_packets`（先跑后钉精确值）。
18. **`mongodb_multi_flow_dynamic`**：`strategy_fc={"type":"flows","value":N}` + `ip.src`/`tcp.src_port` 动态对象（inc/rand/list/pattern 四格至少各一档，§9.32 整格；rand 同 seed 可复现、inc 回绕三问 §9.34）。断言 `distinct_values`/`nonzero`（禁硬编码包位）；`tcp.src_port` **留空或动态**（§9.39 互斥）。`packet_count = 8×N`。

## 4. 负例契约

负例的 `expect` 严格只含两个键：

| # | id | 输入故障 | `error_contains` | 今日可跑 |
|---|---|---|---|---|
| 19 | `mongodb_neg_truncated_header` | `wire_fault={"kind":"truncate_header","value":10}` | `truncated` | ✅（存量改写） |
| 20 | `mongodb_neg_short_length` | `wire_fault={"kind":"message_length","value":15}` | `length` | ✅（存量改写） |
| 21 | `mongodb_neg_oversize` | `wire_fault={"kind":"message_limit","value":"over_limit"}` | `limit` | ✅（存量改写） |
| 22 | `mongodb_neg_bad_opcode` | `wire_fault={"kind":"opcode","value":2147483647}` + 消息 opcode `2147483647` | `opcode` | ✅（存量改写；注：今日拒绝由 wire_fault 承担，opcode 本体面见 #25） |
| 23 | `mongodb_neg_bson_length` | `wire_fault={"kind":"bson_length","value":1000}` | `bson` | ✅（存量改写） |
| 24 | `mongodb_neg_udp_carrier` | `layers=[ip,udp,mongodb]`（纯 layers 形坏链） | `tcp` | ✅（存量改写；链形修正：存量无 `ip` 层，改写补 `ip` 层） |
| 25 | `mongodb_neg_opcode_rejected` | opcode 本体：字符串 `"BOGUS"`（今日可拒）+ 数字 `2013`/`2003`/`2012`/`2147483647`（G-MONGO-3 修后拒，修前空流假成功——**修后落盘**） | `opcode`（数字形修后 `unknown opcode`，与字符串路径同文案） | A′（数字形） |
| 26 | `mongodb_neg_flat_keys` | 顶层 `src_ip`（或 `count`）与 `layers` 并存 | `flat config field` | ✅（`CheckProtoFlat:8329-8334` 通用门） |
| 27 | `mongodb_neg_unknown_layer_field` | `mongodb` 层内第 5 个键（如 `{"bogus_key":1}`） | `unknown field` | ✅（V9，`complete.go:293`） |

**不建**：`{"layers":[…],"mongodb":{}}` presence 形（今日不拒，G-MONGO-6 登记；建了会真绿 = 假通过）。故障注入仅用于校验错误传播；不能让任务"完成但 0 包"而通过（§14.11/§14.12；#25 数字形修前即此反面教材）。若实现采用不同稳定错误文本，必须先同步更新设计、本文和 JSON 三处，不能把断言放宽成任意失败。

## 5. 三方一致性检查与覆盖对账

### 5.1 三源回指行

MongoDB Manual Wire Protocol 页 + meta-driver legacy txt + BSON 规范（§3 逐表列出处）→ D-MONGODB-1（设计 §11）→ 27 ID（本文 §2）。第三源"已确认现网行为"当前 = **未确认级**（G-MONGO-7，按 §5.5 不写死进实现）。

### 5.2 9.52 对账两行 + 清单出处声明

- **清单出处声明**：本清单来源 = **规范/官方文档反推**（Wire Protocol opcode/头表逐值 + BSON 类型表逐值 + responseFlags 逐位），**非**引擎能力面反推。引擎侧只作现状取证（registry 4 键 + 7 kind + validator + 端口/载体契约 + tshark 92 字段）。
- **对账两行**：**规范逻辑点总数 = 62**（八项 8 行 + 矩阵 16 格 + 变体 19 行 + 动态 5 面 + 错误 14 面）；**用例覆盖数 = 45**（八项 8 + 矩阵已覆 11 + 矩阵用例通道 1 + 变体 19 + 动态 1（#18）+ 错误已覆 5（#19–#24 中 5 类 wire_fault/载体/扁平/V9……精确计数见 §8 去向表）；**不适用 = 17**。45 + 17 = 62 ✓。**粒度声明**：行/格粒度每点 1 计；G-MONGO-1…G-MONGO-8 不折进 62。**反查全绿 ≠ 覆盖全**（§9.52 原文）。
- **三方集合检查**：27 个 id 在设计 §9、本文 §2、JSON 文件必须集合相等且顺序相同；正例包数 = `[9,8,8,8,8,8,12,8,8,8,N+7,8,8,9,18,11,9,≥8,8×N]`（#11/#17 先跑后钉）；负例不出现 `packet_count`；所有正例 `has_handshake=true`、`terminates=true`。

## 6. P3 固定动作

### 6.1 §3.15 三项逐项一例或立项

| # | 三项 | 本协议对照 | 用例/立项 |
|---|---|---|---|
| ① | 同连接/同流内的多轮操作 | 同 TCP 连接：查询→响应→写→游标→KILL（§12.3 t1–t4） | 已建 #15（4 事件编排）；A′ 补例 `mongodb_multi_round_query`（>2 轮查询-响应往返，G-MONGO-3 配对守卫修后加值断言） |
| ② | 非正常结束 | 正常 FIN（全正例）；REPLY 错误位 + `$err`（#16）；负例 9 条；**服务端主动 RST** | 前半已覆/已建；后半 → 1 条 **A′ 补例**（`mongodb_server_abort_rst`，`tcp.rst=true` 面） |
| ③ | 长保活 | 协议层无 keepalive 语义（设计 §10.1 行 6 显式不适用）；长会话 = 同连接多轮操作 | 已建 #15；随 ① 的 A′ 补例同批 |

无空项：①③ 各有已建例 + 1 条 A′ 补例；② 有已建例 + 1 条 A′ 补例。

### 6.2 A′/B′ 两分类表

A′（P4 接线，testcase §2 已建例）：`translateTerminalConfig`（G-MONGO-1，阻塞 #15/#17/#18 落盘）/ BSON 保序（G-MONGO-2，#8 转结构化 + #11 扩展）/ 校验三缺（G-MONGO-3，#25 数字形 + #15/#1 配对值断言）/ `$err` 失败文档（#16 全形）/ RST 非正常结束（② A′）/ 多轮查询（① A′）/ NIC 双路例（§7）。
B′（G-MONGO-4/5，进设计 §14「明确不解决 + 迁入计划」）：BSON 越界·终止符·messageLength 上下界校验 / fixture 失败回退语义 / 未知类型处置 / 非标端口 dissector 面。
另 3 项（G-MONGO-6/7/8）为框架级缺口 / 现网确认项 / 死字段处置，去向见设计 §14。

### 6.3 3.14 豁免边界审计

**有 TCP 长连接载体 → `sessions[]` 不豁免**（设计 §12.3 会话表 s1–s3，#14 已建）；多流并发 #18；单包多载荷两形态（多文档单 INSERT #2/#8 + 单段多消息 #7/#15）各至少一例；三项各有结论，**无豁免逃逸**。

## 7. 实现后执行建议

时序（设计 §12.1 约束）：① `case "mongodb"` translate 落码（G-MONGO-1）→ ② 13 例改写纯 layers + 删 `direction` 键 → ③ 全量重跑先跑后钉（§9.31/§14.20；fixture 不符以 tshark 为准）→ ④ 新增 14 例落盘 → ⑤ 全量全绿 + 反查。先跑 #1/#12 验证头字节；随后 #8/#9 的 BSON fixture；再 #2–#7 原子 opcode、#13/#14 地址族与多会话；最后 #15/#17/#18 编排/分段/多流。负例 #19–#24 确认 validator 期拒绝；#25 数字形确认 task error（非空流）；#26/#27 确认 schema/链级 400。`OP_MSG`/`OP_COMPRESSED` 未在本批执行，待单独设计确定 section/压缩面后再加入。NIC 双路（`port_group` + `enp135s0f0np0`）随 A′ 落一例同 fixture 双路一致断言。

## 8. 存量审计（13 例逐条去向，§9.14）

| 存量 id | 去向 | 说明 |
|---|---|---|
| `mongodb_query_reply` | 改写 → #1 | 形状改纯 layers + 删 `direction`；fixture 原样 |
| `mongodb_write_ops` | 改写 → #7（保留）+ 拆分 → #2–#6 | 组合例保留；5 事件各单列一原子例（§9.6 一行为一点） |
| `mongodb_bson_types` | 改写 → #8 | fixture hex 原样（保序，G-MONGO-2 前不转结构化） |
| `mongodb_empty_boundary` | 改写 → #9 | fixture 原样 |
| `mongodb_ipv6` | 改写 → #13 | 地址 `2001:db8::1/::2` 原样；起点 74 |
| `mongodb_multi_session` | 改写 → #14 | `messages`→`sessions[]` 结构已是 sessions 形，只换顶层形状 |
| `mongodb_message_header` | 改写 → #12 | fixture 原样 |
| `mongodb_neg_truncated_header` | 改写 → #19 | wire_fault 原样 |
| `mongodb_neg_short_length` | 改写 → #20 | wire_fault 原样 |
| `mongodb_neg_oversize` | 改写 → #21 | wire_fault 原样 |
| `mongodb_neg_bad_opcode` | 改写 → #22 + 扩展 → #25 | wire_fault 面保留；opcode 本体面单列 #25（A′数字形） |
| `mongodb_neg_bson_length` | 改写 → #23 | wire_fault 原样 |
| `mongodb_neg_udp_carrier` | 改写 → #24 | 链形修正（补 `ip` 层，`[ip,udp,mongodb]`） |

**作废 0 例**（无"作废不注原因"；拆分/扩展均为显式去向）。旧 testcase 的 T-MONGO 编号对照：S1→#1、S2→#2–#7、S3→#8、S4→#9、S5→#13、S6→#14、S7→#12、N1–N6→#19–#24。

## 9. 修订记录

- v1.0.0（2026-09-27）：P1–P3 文档轨产物（车道 A）。建立 27 ID（18 正 + 9 负）原子索引（§2）+ 逐项断言（§3–§4）+ 存量 13 例逐条审计去向（§8）+ P3 固定动作（§6）+ 执行时序（§7）。**未修改任何 `.go`、未跑 suite、未启动服务器、未写共享文档/账本/canonical**。
