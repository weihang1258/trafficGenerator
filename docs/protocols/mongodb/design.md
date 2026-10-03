# MongoDB Wire Protocol（传统 OP_* 线协议）设计契约

> 版本：v1.2.0（静态 D/T/C 闭环；#87 mongodb）
> 日期：2026-09-27
> 车道：并发管线车道 A（文档轨）｜协议号：**87**
> 配套文件：`docs/protocols/mongodb/testcase.md`、`trafficgen/test/protocol_pcap/cases/mongodb.json`（现存 **31** 例：18 正 + 13 负）、旧基线 `docs/protocols/mongodb/_archive_32-mongodb-design.md` + `_archive_32-mongodb-testcase.md`（2026-08-20，设计阶段产物，`mongodb` 层未实现时所写）
> 规范基线：MongoDB Database Manual "MongoDB Wire Protocol"（标准消息头 + OP_MSG + Legacy Opcodes）[^1]；mongo-meta-driver `docs/source/legacy/mongodb-wire-protocol.txt`（MsgHeader / OP_UPDATE / OP_REPLY 布局）[^2]；BSON 规范（bsonspec.org，类型字节与文档布局）；TCP/IPv4/IPv6 参照 RFC 9293/8200。
> **层链唯一真相**：本契约全文示例只有纯 `layers` 形——地址只住 `ip` 层（`src`/`dst`；IPv6 地址族同住 `ip` 层，仓库无 `ipv6` 层），端口只住 `tcp` 层（`src_port`；`dst_port` 由 FieldContract 补齐，见 §2.1）、数量只走 `flow_control`；顶层只允许 `layers`/`flow_control` 家族/`output`（CORE_MEMORY §1.11–1.13）。任何顶层 `src_ip`/`dst_ip`/`src_port`/`dst_port`/`count`/`mongodb` 子映射都判违规。
> **注册现状**：`mongodb` 层**已注册**（`internal/core/layers/registry.go:634-641`，`CategoryTerminal` + `DependsOn ["tcp"]` + `FieldContract {"tcp.dst_port": "27017"}`），且 `allowedProtocols["mongodb"]=true`（`internal/core/protocols.go:44`）、`NewChainPlanner("mongodb")` 已在 `cmd/server/main.go:514` 注册、空白导入在 `main.go:107`。本文**不宣称本次跑过 suite、不启动服务器**；所有"已落码/未落码"结论均标实测出处（文件行号均为 2026-09-27 HEAD 实读）。
> **与旧基线 #32 的关系**：旧设计写于实现前（"`mongodb` 层尚未实现"），其线格式章节（16 字节头、7 opcode 表、BSON fixture）在本契约 §3 逐项继承并对码实现复核；其配置/用例章节（旧顶层 `src_ip`/`mongodb` 混用形、原 13 例）**整体作废**，由本契约 §12.1 与 testcase 重写。旧审计的字节复算结论（S1/S7 头、BSON 101 字节、offset 54/74/85/93）在 §3.3 逐条复用并标出处。

[^1]: https://www.mongodb.com/docs/manual/reference/mongodb-wire-protocol/（Standard Message Header：messageLength/requestID/responseTo/opCode；Opcodes：OP_MSG + Legacy Opcodes）
[^2]: https://github.com/mongodb/mongo-meta-driver/blob/master/docs/source/legacy/mongodb-wire-protocol.txt（MsgHeader 结构体；Request Opcodes 表：OP_REPLY=1 / OP_UPDATE=2001 / OP_INSERT=2002 / RESERVED=2003 / OP_QUERY=2004 / OP_GET_MORE=2005 / OP_DELETE=2006 / OP_KILL_CURSORS=2007；OP_REPLY body 布局；responseFlags 位定义）

---

## 1. 范围、证据等级与已落码边界

本设计定义 MongoDB **传统 OP_* 系列**（legacy opcodes）在 TCP 27017 上的生成契约：16 字节小端头 + 7 种 opcode body + BSON 文档载荷。**明确不含** `OP_MSG`（2013，现行手册值；旧 meta-driver legacy 文档作 1000，取值已变，本版范围外不展开）、`OP_COMPRESSED`（2012）：规范上二者是现行主协议，但本仓库 builder 无任何分支（`builder.go:249-266` switch 无此二值），`resolveOpcode` 字符串路径拒未知名；后续加入必须另增版本和用例，不改变本版传统 opcode 语义。

**证据等级三档（本契约纪律）**：

| 档 | 可写内容 | 是否固定线字节 |
|---|---|---|
| ①规范原文级 | 16 字节头四字段、7 opcode 值与 body 字段序、BSON 类型字节与文档布局 | 是——逐字节可断言 |
| ②dissector 实测级 | 本机 TShark 3.6.14 `mongo.*` **92** 字段（口径 `tshark -G fields \| awk '$3~/^mongo[.]/' \| wc -l`）、默认端口 27017 启发式 | 是——但仅作断言通道，不改写线真相 |
| ③实现现状级 | `internal/protocol/mongodb/*` 的已落码能力边界（哪些 opcode 有 builder、哪些配置键被消费、哪些校验缺失） | 是——作为"今日可达/不可达"的判据 |

**已落码边界（实测，2026-09-27 HEAD）**：

- 生成器：`internal/protocol/mongodb/layer_gen.go`（84 行）——`MongoDBGenerator.Generate` 读 `req.Meta.MongoDB`（`layer_gen.go:30`），单会话走 `Messages`、多会话走 `Sessions[].SrcPort`（P0a 模式，`layer_gen.go:40-55`）；方向判定**只看 opcode**（`opcodeDirection(op) != "s2c"`，`:48/:63`），**不读**消息的 `direction` 字段（§2.3 死字段 D1）。
- 字节构造：`internal/protocol/mongodb/builder.go`（446 行）——7 opcode 的 body 构造（`buildQueryBody`/`buildReplyBody`/`buildInsertBody`/`buildUpdateBody`/`buildDeleteBody`/`buildGetMoreBody`/`buildKillCursorsBody`，`:270-354`）+ 小端头（`buildHeader`，`:93-102`）+ BSON 编码（`buildBSON`/`bsonElement`，`:104-228`）+ fixture hex 解析（`parseBSONFixtureHex`，`:357-381`）+ `checkWireFault` 5 kind（`:404-426`）。
- 校验器：`internal/protocol/mongodb/planner.go`（168 行）——`Planner.Validate`（`:17-59`）：空配置放行（P0b-2）、messages/sessions 二选一、`checkWireFault`、**字符串 opcode** 合法性、IP 格式。注意**未校验**：responseTo 配对、messageLength/BSON 边界、端口值、数字 opcode 范围（§2.3/§7）。
- 旧 planner：`planner.go:61-143` 的 `Plan()`（自产 TCP 握手/挥手 + `PacketConfig` 直发）**没有任何非测试调用方**：链路径只走 `layer_gen.go`（`drive()` 经 `flowMetaFor`/`Meta.MongoDB` 直传，`chain_planner_translate.go:128`）。`Plan()` 由 `mongodb_test.go` 直调保留为回归面，**不构成线上能力**。本契约把它的行为（3+N+4 包数）列为"与链路径一致"的旁证，不列 A′。
- **未接线（关键现状，P4 必办）**：`translateTerminalConfig` **无 `case "mongodb"`**（`chain_planner_translate.go` 全文件 `case "mongodb"` 零命中；switch 自 `case "goose"` 起经 ~50 个 case 到 `case "socks5"` 收尾，无 mongodb）。后果：纯 layers 形下层内 `mongodb` 配置**不翻译进 `spec.MongoDB`**；生成器读到 nil → P0b-2 默认（1 条 OP_QUERY 事件）。即**今日纯层链形会静默产错流**（配 5 条只出 1 条默认），这是本协议 P4 第 1 顺位修复（G-MONGO-1）。

当前 `cases/mongodb.json` **31 例**（18 正 + 13 负）；原存量 13 例已按 §12.1 改为纯层链，新增 18 例覆盖原子 opcode、链级错误、动态与边界面。

---

## 2. 推荐配置、层链与事件形状

### 2.1 层链

唯一合法链形：**`[ip, tcp, mongodb]`**（IPv6 地址族同住 `ip` 层，不新增层）。`mongodb` 是**终结层**（`CategoryTerminal`），无 `TransformEvents`、无 `OptionalOn`、无 `TransportOn`、无 `InnerRequired`——registry 实测见 `registry.go:634-641`。

```json
{
  "layers": [
    {"ip": {"src": "192.0.2.87", "dst": "198.51.100.87"}},
    {"tcp": {"src_port": 45087}},
    {"mongodb": {
      "messages": [
        {"request_id": 100, "response_to": 0, "opcode": "OP_QUERY",
         "namespace": "test.users", "flags": 0, "skip": 0,
         "return_count": 1, "query": {"x": 1}},
        {"request_id": 101, "response_to": 100, "opcode": "OP_REPLY",
         "flags": 0, "cursor_id": 0, "starting_from": 0,
         "returned": 1, "documents": [{"x": 1}]}
      ]
    }}
  ],
  "flow_control": {"flows": 1}
}
```

> **`tcp.dst_port` 不写**：由 `mongodb` 层 `FieldContract {"tcp.dst_port": "27017"}`（`registry.go:635`）经通用 FieldContract 块（`chain_planner.go:597-627`，mongodb 在 13 层名单内）补齐。**与 postgresql 的差异（诚实声明）**：本层**无显式端口域校验**——用户显式写 `tcp.dst_port` 非 27017 时**被尊重、不拒绝**（通用块"用户显式 > FieldContract"，`chain_planner.go:608-619`；postgresql 另有 `chain_planner.go:586-589` 的强制等于校验，本层无此块）。非标准端口的 dissector 行为待 P4 实测（G-MONGO-5）。
> **`direction` 不写**：生成器按 opcode 定方向（OP_REPLY → down，其余 → up），消息级 `direction` 配上不生效（§2.3 死字段 D1）。用例不断言方向字段、只断言 `tcp.srcport/dstport` 与包序。

### 2.2 层内配置键（**唯一权威 = registry `Fields`，实测 4 键**）

| 键 | 类型 | 默认 | 语义 | 证据 |
|---|---|---|---|---|
| `messages` | list | `[]` | 单会话有序消息序列（与 `sessions` 二选一） | `registry.go:637`；`layer_gen.go:56-67` |
| `sessions` | list | `[]` | 多会话展开：每项 `{src_port, messages[]}`；非空时 `messages` 被忽略 | `registry.go:638`；`layer_gen.go:40-55` |
| `bson_fixture_hex` | string | `""` | ⚠️ **死字段**（层级）：registry 声明但生成器**零读取**（全仓库生成器侧唯一读取是**消息级** `msg.BSONFixtureHex`，`builder.go:300`） | `registry.go:639`；§2.3 死字段 D2 |
| `wire_fault` | object | nil | 负例故障注入口，**不是线上字段**（5 kind，`builder.go:404-426`） | `registry.go:640` |

**层字段范围校验（V9）**：白名单制——4 键之外的任何键 → `layers: layer "mongodb": unknown field %q`（`complete.go:293`）。消息内键（`request_id`/`opcode`/`query` 等）**不受 registry 约束**（`messages` 是 `list` 型无界字段）。

### 2.3 消息形状与「死字段 / 弱校验」清单（P4 必办，实测）

`MongoDBMessage` 是 Go struct（`core/types.go:1231-1250`），18 个 JSON 键。各 builder 实际消费如下（逐键实读 `builder.go:270-354`）：

| 消息键 | 被消费？ | 消费点 / 备注 |
|---|---|---|
| `opcode` | ✅ | `buildMessage:232-246`（string 查表 / int32·float64 透传） |
| `request_id` / `response_to` | ✅ 写字节 | `buildHeader:93-99`；但**配对关系无人校验**（§7，G-MONGO-3） |
| `namespace` | ✅ OP_QUERY/INSERT/UPDATE/DELETE/GET_MORE | 各 body 构造；OP_REPLY/KILL 不读 |
| `flags` / `skip` / `return_count` | ✅ | QUERY/REPLY/INSERT/UPDATE/DELETE/GET_MORE 各取所需 |
| `zero` | ✅ | UPDATE/DELETE/GET_MORE 首 4 字节（KILL 恒写 0，`:348`） |
| `query` / `selector` / `update` / `documents` | ✅ | BSON 编码（`buildBSON`） |
| `cursor_id` / `cursor_ids` / `starting_from` / `returned` | ✅ | REPLY/GET_MORE/KILL |
| `bson_fixture_hex`（消息级） | ✅ 仅 OP_INSERT | `buildInsertBody:300-305`；**解析失败静默回退**到 `documents`（`err == nil` 才用，错 hex 无报错，G-MONGO-4） |
| **`direction`** | ❌ **死字段 D1** | 生成器与 planner 一律 `opcodeDirection(op)` 定方向（`layer_gen.go:48,63`；`planner.go:115`），`m.Direction` 零读取。原存量 13 例的 `direction` 键已删除； |
| `bson_fixture_hex`（**层级**） | ❌ **死字段 D2** | registry 声明（`registry.go:639`）+ `MongoDBConfig` 透传（`types.go:1262`），但生成器/builder 零读取 |
| `MaxMessagePayload`（4MB 常量） | ❌ **死常量 D3** | `builder.go:40` 定义，全仓库零引用（`grep MaxMessagePayload` 仅定义处命中）；`message_limit` 负例只走 `wire_fault` 注入，无真实上限执法 |

**处置（§1.12）**：D1 `direction`——已删除（方向是 opcode 的函数）；D2 层级 `bson_fixture_hex`——已从 registry 删除；D3 `MaxMessagePayload` 仍需 P4 接线真实上限或删除常量，二选一，不许留着当"看起来有限制"。

### 2.4 BSON 可编码面（实测）

`bsonElement`（`builder.go:124-151`）类型分派：`float64`（整值且 int32 范围内 → int32，否则 double）、`int`/`int32` → int32、`int64` → int64、`string`、`bool`、`nil` → null、`map` → 内嵌文档、`[]interface{}` → 数组。**JSON 配置的 number 一律 float64**，故文档内 int64 **不可达**（仅 Go 直调可达；S3 的 int64 面由 fixture hex 覆盖）。未知 Go 类型 → **静默 null**（`:150`，G-MONGO-4 同类）。

**顺序非确定性（实测，P4 必修）**：`buildBSON` 用 `for k, v := range doc`（`:111`，Go map 随机序）→ **多键文档字段序随机**；`bsonArrayElement` 先转 `map[string]interface{}`（`:181-184`）→ **多元素数组顺序随机**。存量用例全部避开（单键文档 / fixture hex / 单元素数组），故今日全绿；任何新增多键/多元素断言必须先修（按键排序，G-MONGO-2）。

---

## 3. 线格式权威（逐字段，P4 builder 硬对照表）

### 3.1 通用 16 字节消息头（规范 [^1] Standard Message Header + [^2] MsgHeader）

| 相对偏移 | 字段 | 宽度 | 编码 | 约束 |
|---:|---|---:|---|---|
| +0 | `messageLength` | 4 | little-endian uint32 | `>=16`；含头含 body（"includes the 4 bytes that holds the message length"） |
| +4 | `requestID` | 4 | little-endian int32 线值 | 客户端/服务端生成；响应在 `responseTo` 中回显 |
| +8 | `responseTo` | 4 | little-endian int32 线值 | 请求为 0；`OP_REPLY` 置对应请求 ID（[^2]: "responseTo is set"） |
| +12 | `opCode` | 4 | little-endian uint32 | 只允许 §3.2 的值 |

以太网帧中消息头起点：IPv4 **54**（14 Eth + 20 IPv4 + 20 TCP，无 TCP option 的数据段），IPv6 **74**（14 + 40 + 20）。旧审计已复核（bak-root audit §2.3），本契约沿用。若 TCP option 或 IP 扩展头存在，测试必须改用解码字段，不得继续使用常量偏移。

### 3.2 传统 opcode（[^1] Legacy Opcodes + [^2] Request Opcodes 表）

| 名称 | 十进制 | body 布局（规范 + builder 对照） |
|---|---:|---|
| `OP_REPLY` | 1 | responseFlags(4) + cursorID(8) + startingFrom(4) + numberReturned(4) + 文档*（[^2] OP_REPLY 结构；`buildReplyBody:284-292` ✓） |
| `OP_UPDATE` | 2001 | zero(4) + collection CString + flags(4) + selector BSON + update BSON（[^2] OP_UPDATE 结构；`buildUpdateBody:312-320` ✓） |
| `OP_INSERT` | 2002 | flags(4) + collection CString + 文档+（`buildInsertBody:296-308` ✓） |
| `OP_QUERY` | 2004 | flags(4) + collection CString + numberToSkip(4) + numberToReturn(4) + query BSON（[^2]；`buildQueryBody:272-280` ✓） |
| `OP_GET_MORE` | 2005 | zero(4) + collection CString + numberToReturn(4) + cursorID(8)（`buildGetMoreBody:335-342` ✓） |
| `OP_DELETE` | 2006 | zero(4) + collection CString + flags(4) + selector BSON（`buildDeleteBody:324-331` ✓） |
| `OP_KILL_CURSORS` | 2007 | zero(4) + numberOfCursorIDs(4) + cursorID 数组（每项 8）（`buildKillCursorsBody:346-354` ✓） |

`RESERVED`（2003，原 OP_GET_BY_OID）与 `OP_MSG`（2013）、`OP_COMPRESSED`（2012）：字符串形 → `unknown opcode` 拒（`resolveOpcode`）；**数字形 → Validate 放行**（`resolveOpcode` int32/float64 路径只拒 0，`planner.go:154-164`），`buildMessage` default 拒 `unsupported opcode`（G-MONGO-3 同类，testcase §4 注记）。

`C-string` 是 UTF-8 字节 + 单 `0x00`；namespace 格式 `database.collection`。

### 3.3 OP_QUERY/OP_REPLY 确定样例（旧审计 §2.1 复核，本契约复用）

`OP_QUERY(requestID=100, flags=0, skip=0, return=1)` 在 `test.users` 上 51 字节（`33 00 00 00 64 00 00 00 00 00 00 00 d4 07 00 00` + body），selector `{x:1}` = `0c 00 00 00 10 78 00 01 00 00 00 00`，selector 起点 offset **93**（= 54+16+4+11+4+4）。`OP_REPLY(requestID=101, responseTo=100)` 48 字节（`30 00 00 00 65 00 00 00 64 00 00 00 01 00 00 00`）。样例只表达 wire 字段；不是对真实服务器游标分配的承诺。

### 3.4 BSON 编码契约（BSON 规范 + builder 对照）

文档 = `int32 length + elements + 0x00`，长度 ≥ 5；空文档 `05 00 00 00 00`（`buildBSON:106-109` ✓）。元素类型字节与 payload（`builder.go:23-34` 常量 + `bsonElement`）：`0x01` double（LE binary64）、`0x02` string（int32 长度含终止符 + UTF-8 + `0x00`）、`0x03` 内嵌文档、`0x04` 数组（键 `"0","1"…`）、`0x05` binary（int32 长度 + subtype，本版只产 `0x00` generic）、`0x08` bool（`0x00/0x01`）、`0x0a` null（无 payload）、`0x10` int32（LE）、`0x12` int64（LE）。未列类型（ObjectId/日期/正则/JS/Decimal128 等）**不在编码面**，不得静默当字符串（今日未知 Go 类型 → null，G-MONGO-4）。

多类型固定 fixture（101 字节，旧审计 §2.2 复核）：`{d:1.5,i:-7,l:0x0102030405060708,s:"A",b:true,n:null,bin:0102,arr:[7,"x"],doc:{b:null}}`，外层 `65 00 00 00`，数组体 21 字节，内嵌文档 8 字节。**P4 钉死纪律**：该 fixture 只走 `bson_fixture_hex` 原样通道（顺序确定），不得用 `documents` 结构化通道复述（map 随机序，§2.4）。

### 3.5 responseFlags 位（[^2] responseFlags 表，断言用）

bit0 `CursorNotFound` / bit1 `QueryFailure` / bit2 `ShardConfigStale` / bit3 `AwaitCapable` / bit4-31 保留忽略。dissector 面：`mongo.reply.flags.*`（92 字段内，§10.5）。

### 3.6 关键规范行为（"只有 QUERY/GET_MORE 有响应"，[^2] Client Request Messages）

> Only the `OP_QUERY` and `OP_GET_MORE` messages result in a response from the database. There will be no response sent for any other message.

**设计后果**：本契约的脚本是**声明式回放**——响应事件必须显式声明（实现不得为缺省响应猜测 ID，旧设计 §4.2 延续）；`mongodb_write_ops` 的 5 个写事件无响应是**符合规范**的形状，不是缺口。`OP_REPLY` 保留给服务端（客户端不得发送）——本契约的 s2c 方向即表达此约束（由 opcode 定方向，§2.1）。

---

## 4. 会话状态机与自动派生（设计权威）

### 4.1 状态集合

```text
Init ──SYN/SYN-ACK/ACK──▶ Established ──应用事件*──▶ Established … ──FIN 四way──▶ Closed
```

- 每 session = 独立 TCP 连接（独立四元组，`sessions[].src_port` 区分；`layer_gen.go:40-55` + planner `runSession:103-126`）。
- 事件按配置顺序生成，一事件一 TCP 数据段；TCP 小载荷不分段（超 MSS 分段由 tcp 层承担，包数公式需同步更新；本版正例无超 MSS 消息）。
- 正常脚本包数：`3（SYN/SYN-ACK/ACK） + 应用事件数 + 4（FIN 交换）`。纯 TCP ACK 不计为应用事件。
- **MongoDB 协议层无登录/认证/游标生命周期状态机**（传统 opcode 无 auth 报文；`cursorID` 是透传 int64 fixture，不做分配语义）。状态机守卫 = TCP 连接边界 + validator 的二选一/坏配置拒绝（§4.2）。**不虚构**"认证状态""游标打开状态"。

### 4.2 非法转移与拒绝（含今日缺口，实测）

| 非法/坏配置 | 今日行为 | 锚词 | 触发点 | 去向 |
|---|---|---|---|---|
| messages 与 sessions 并存 | 拒 | `mutually exclusive` | `planner.go:28` | ✅ 已有 |
| 空 messages + 空 sessions | 拒 | `at least one message` | `planner.go:25` | ✅ 已有 |
| session 内空 messages | 拒 | `empty messages` | `planner.go:37` | ✅ 已有 |
| 字符串未知 opcode | 拒 | `unknown opcode` | `planner.go:49`/`resolveOpcode` | ✅ 已有 |
| `wire_fault` 5 kind | 拒（各锚词） | `truncated`/`length`/`limit`/`opcode`/`bson` | `builder.go:404-426` | ✅ 已有 |
| 链夹 `udp` | 拒（通用路径） | `tcp`（`transport layer duplicated` 文案内含 "tcp"） | `complete.go:480` | ✅ 已有（无 mongodb 专属 carrier 块，见 §5） |
| 层内第 5 个键 | 拒（V9） | `unknown field` | `complete.go:293` | ✅ 已有 |
| 顶层扁平四键/五键 | 拒（通用） | `no longer accepts flat config field` | `CheckProtoFlat:8329-8334` | ✅ 已有 |
| messages 与 sessions 并存 | 拒 | `mutually exclusive` | `planner.go:28-29` | ✅ #28（当前 JSON 已登记） |
| responseTo 无对应请求 / request 非 0 | **不校验**（只写字节） | — | validator 无此检查 | ❌ 缺口 G-MONGO-3 |
| 数字 opcode 越界（2013/2003/2012/INT_MAX） | Validate 放行；`buildMessage` default 拒（链路径下错误被驱动吞成**空流**，见 §7） | `unsupported opcode` | `builder.go:265` | ❌ 缺口 G-MONGO-3 |
| message 超 4MB（D3 常量） | **不执法** | — | 零引用 | ❌ 缺口 G-MONGO-4 |
| BSON 越界/缺终止符 | **不校验**（只走 wire_fault） | — | — | ❌ 缺口 G-MONGO-4 |

### 4.3 自动派生帧（生成器自动补的内容，逐条列出）

| 派生内容 | 触发条件 | 内容 |
|---|---|---|
| 空配置默认流 | `mongodb` 配置 nil（P0b-2） | 1 条 OP_QUERY 报文事件（`layer_gen.go:34`；planner `planner.go:70` 同款） |
| 目的端口 | `tcp.dst_port` 未显式写 | 27017（FieldContract 通用块，`chain_planner.go:597-627`） |
| 源端口保底 | `flows>1` 且未显式 `src_port` | `12345+i`（`worker.go:307-308`） |
| 空 BSON | 空 map 文档 | `05 00 00 00 00`（`buildBSON:106-109`） |
| KILL 首 4 字节 | 总是 | 恒 0（`buildKillCursorsBody:348`，忽略 `zero` 输入） |
| TCP 握手/挥手 | 由 `tcp` 层决定 | `handshake`/`termination` 默认 true；不在本层内 |
| 会话边界 | `sessions[]` 每项 `src_port` | `MessageEvent.SrcPort` 上报（`layer_gen.go:49`），tcp 层挥旧握新 |

> **「自动应答」不存在**：本层是**声明式脚本化回放**，不因收到 QUERY 自动补 REPLY。每个方向的报文都必须在 `messages[]` 里显式声明。

---

## 5. 依赖声明与端口契约

**依赖（§5.1）**：依赖 `tcp` 层（唯一载体，`DependsOn ["tcp"]`，`registry.go:634`）；经 tcp 间接依赖 `ip` 层；**无 `TransportOn`/`OptionalOn`/`InnerRequired`**。UDP 语义不存在：链夹 udp 时 `DependsOn` 自动补 tcp → 通用 `transport layer duplicated` 拒（`complete.go:480`，锚词含 "tcp"）。**本层无专属 carrier 错误块**（`validate_layers.go` 无 mongodb 分支，实测零命中）——与 hl7/edp/xmrmining/ntlm 的专属块不同，如实登记（行为等价，文案通用）。

**端口契约（§1.3 R2 通用型）**：`FieldContract {"tcp.dst_port": "27017"}`（`registry.go:635`）→ 通用块补齐（`chain_planner.go:597-627`）。用户显式写端口 = **尊重用户值**（无 postgresql 式强制等于校验，§2.1）。`mongodb` 不在 `validateBaseDstPortHandled` 豁免名单（名单自 `chain_planner.go:639` 起，grep 全名单无 mongodb），故走通用块。

---

## 6. 性能设计与验收（CORE_MEMORY §6.1–6.8）

- **6.1/6.2 目标与预算**：本层为**事件驱动流式渲染**——逐消息构造一个 MongoDB 报文并立即 `EmitMsg`，无全量聚合（`layer_gen.go:40-68` 两循环直发；旧 planner 路径 `planner.go:61-143` 亦逐包发 `chan`）；单消息常驻内存 = 当前报文字节（≤ body + 16）；BSON 静态 fixture 为配置输入、天然有界。并发面：每个 flow 一个新 generator 实例（工厂 `layer_gen.go:82`），**无共享可变状态、无需锁**。速率与队列上限由框架（Pacer / 有界队列）承担，本层不重复定义。
- **6.3 双路验收**：**pcap 路** = suite 落盘 `/tmp/mcp-pcaps/mongodb/`，用 tshark `mongo.*`（92 字段）+ frames hex 双通道校对；**NIC 路** = `output_type=port_group` + 网口 `enp135s0f0np0` 抓包，断言 TCP/应用字段一致（记忆 `testing-interface` 指定网口）。
- **6.4 依据**：流式路径如 6.1 所述；每条流新增内存 = 一个 generator 实例（零字段结构体）+ 当前报文字节切片；无共享状态、无锁；限速与多 worker 总速率正确性由框架 pacer（共享桶）保证，本层不引入第二套速率语义。
- **6.5 诚实待确认**：**吞吐（包/秒、bit/秒）、并发流数、内存上限的具体数字待 P4 基准实测后钉**，本文不写承诺数字。
- **6.6 六类场景**：基线（单会话查询响应）/ 目标规模（多会话 `sessions[]`）/ 压力上限（大文档逼近 MSS 分段）/ 长时间运行（多轮写操作）/ 并发交错（多流 `flows=N` × 多会话）/ 背压（下游消费慢时队列积压）。前五类 P4/P5 落用例，背压类沿用框架既有测试面。
- **6.7 断言口径**：断言**实际输出值**（`mongo.opcode`/`mongo.request_id`/`mongo.response_to`/`mongo.message_length` + frames hex），**不许只断言"任务没失败"**；负例断言锚词。
- **6.8 失败边界**：功能正确但超预算视为设计不合格——本层的预算面即"单 flow 常驻内存 O(1)"，若 P4 引入按流缓存报文数组即违反本条。

---

## 7. 错误处理与错误传播

- 所有校验错误必须在 **planner/validator 边界**抛出并传播为 **task error**，**不许**产出成功 PCAP、`completed + 0 packet`、或只剩 TCP 外壳的假成功（CORE_MEMORY §14.11/§14.12）。
- **今日违反此条的路径（实测，P4 必修 G-MONGO-3）**：链路径下 `buildMessage` 的 `unsupported opcode`（数字越界 opcode）发生在 `Generate` 期（`layer_gen.go:43,58` 直接 `return err`）→ `drive()` 的驱动失败契约（`chain_planner.go:1486` 注释"驱动失败…包流为空"）→ **空流而非同步拒绝**。旧 planner 路径同类（`runSession` 遇错 `return false`，握手包已发出 → 3 包"成功"流）。即：**数字坏 opcode 今日 = 空流/残缺流假成功**，不是 task error。存量 `mongodb_neg_bad_opcode` 之所以绿，是因为它同时带了 `wire_fault.kind=opcode`（validator 期拒绝），**opcode 本体从未被单独拒绝过**。
- 负例执行期 `expect` 键集合**严格**为 `{"expect_error", "error_contains"}`。
- `wire_fault` 5 kind（`builder.go:404-426`）：`truncate_header`→`truncated` / `message_length`→`short message length`（锚 `length`）/ `message_limit`→`over limit`（锚 `limit`）/ `opcode`→`invalid opcode`（锚 `opcode`）/ `bson_length`→`bson length`（锚 `bson`）；未知 kind → `unknown kind`；空配置 = 无故障。`wire_fault` 只用于负例测试，不是生产配置。

---

## 8. 存量审计口径

`cases/mongodb.json` **31 例**（18 正 + 13 负）。原 13 例已完成层链迁移；逐例去向见 testcase §8，新增例的清单、负例锚词和断言见 testcase §2–§4。三条实测事实先行：

1. **迁移前基线（历史）**：原 13 例为混用形（顶层 6 键 `{src_ip, dst_ip, src_port, dst_port, layers, mongodb}`；链形 `[tcp,mongodb]` ×12 + `[udp,mongodb]` ×1；链内无 `ip` 层）。**当前实况（2026-09-30 机读）**：31/31 例为纯层链形（`[ip,tcp,mongodb]`，udp 载体负例为 `[ip,udp,mongodb]`），**非负例顶层键 = 0**（白名单外零残留）。
2. **31/31 无 `decode_as`**：默认端口 27017 走 dissector 端口启发式；非标端口面仍待实测（G-MONGO-5）。
3. **13/13 负例纯净**：`expect` 只有 `{expect_error,error_contains}`；其中 5 例拒绝由 `wire_fault` 承担（§7 注记），`mongodb_neg_udp_carrier` 由通用 transport 重复拒承担，`mongodb_neg_messages_sessions_conflict`/`mongodb_neg_flat_count` 由planner 互斥与扁平键门承担。

---

## 9. 用例集合摘要（ID 权威在 testcase §2）

**合计 31 个语义 ID = 18 正 + 13 负**（原存量 13 例已迁移，新增 18 例）。分布：

- 正例 18：查询响应 1（#1）/ 单 opcode 原子 5（#2–#6，`write_ops` 拆分）/ 写操作组合 1（#7，存量保留）/ BSON 类型与边界 4（#8–#11，存量 2 + 新增 2）/ 头字段 1（#12，存量）/ IPv6 1（#13，存量）/ 多会话 1（#14，存量）/ 请求编排 2（#15–#16，新增）/ 分段与多流动态 2（#17–#18，新增 A′）。
- 负例 13：`wire_fault` 5（#19–#23）/ 载体 1（#24）/ 坏 opcode 1（#25）/ 顶层扁平与层未知字段 2（#26–#27）/ 顶层 messages/sessions 互斥、count、孤儿响应、空层 4（#28–#31）。

逐 ID、逐 `packet_count`、逐断言见 testcase §2–§4。

---

## 10. P1 规范矩阵（CORE_MEMORY §4 八项：规范要求→业务场景→代码现状→缺口）

> 深度口径（§4.19–4.22）：矩阵三张子表——①opcode×方向矩阵（§10.2）②数据形态变体表（§10.3）③商业行为→用例映射表（§10.5）。条目三选一：已实现 / 明确不支持 / 不适用 + 对应用例号，**不留白**。
> **内层密码学边界**：本协议无认证报文（传统 opcode 无 auth 面），无密码学断言面。如实声明：无此维度，不硬凑。

### 10.1 八项规范矩阵

| # | 规范要求（条款+本契约节） | 业务场景 | 代码现状（实测） | 缺口 |
|---|---|---|---|---|
| 1 | 连接模型：TCP 长连接承载会话；客户端主动建连；无控制/数据分离（[^1] "socket-based, request-response"；本契约 §4） | 驱动/客户端建连 + 多轮操作 | ✅ 注册（`registry.go:634`）+ 生成器事件驱动（`layer_gen.go`）+ 多会话 `sessions[].src_port`（`:40-55`） | 无（连通性已覆盖；纯层链翻译缺口见 G-MONGO-1） |
| 2 | 消息表：标准头 + 7 legacy opcode（[^1]/[^2] 全枚举；本契约 §3.1–3.2） | 全 opcode 族覆盖 | ✅ 7 opcode 全有 builder（`builder.go:249-266`）；❌ OP_MSG/OP_COMPRESSED 零分支 | 缺口 → 明确不支持（本版范围外，用例 #25 钉死拒绝；数字形见 G-MONGO-3） |
| 3 | 状态机：请求→（可选）响应；只有 QUERY/GET_MORE 有响应（[^2]；本契约 §3.6/§4.1） | 客户端乱序、孤儿响应、无响应写操作 | ⚠️ 写操作无响应形状已覆（#7）；❌ responseTo 配对**无校验**；❌ 数字坏 opcode 非同步拒绝 | 缺口 → G-MONGO-3（validator 补守卫 + P4 建负例） |
| 4 | 字段表：全部 int 字段**小端**；length 含头；CString NUL 终止；BSON 内嵌长度自洽（[^1]/[^2]/BSON 规范；本契约 §3） | 跨实现互操作（各语言驱动） | ✅ 小端（`buildHeader`/`appendI32`）；✅ length 含头；⚠️ BSON 多键/多元素**顺序随机**（§2.4） | 顺序面 → G-MONGO-2（按键排序，P4 必修） |
| 5 | 错误处理：responseFlags 位语义（[^2]；本契约 §3.5）；查询失败单文档 `$err` | 查询报错、游标失效 | ⚠️ flags 透传 int32（可配任意位）；❌ `$err` 失败文档形状无专门用例 | 缺口 → A′ 补例（#16 的 QueryFailure 位 + 失败文档断言） |
| 6 | 超时与活性：**MongoDB 线协议层无 keepalive/超时/重传语义**——由 TCP 承担 | 驱动连接池长连接复用 | ✅ 协议层无自有定时器（生成器不含 sleep） | **不适用**（显式声明：协议无此语义，不硬凑用例；长会话由"同连接多轮操作"承载） |
| 7 | NAT/代理：线协议无应用层 NAT 遍历；无衍生连接形态 | 直连 / 代理转发 | ✅ 无关联流形态（单 TCP 承载全部报文） | **不适用**（无 PORT/PASV 类语义；`driven_by` 不适用，§12.3） |
| 8 | 版本/方言：legacy opcodes vs OP_MSG（[^1] 明确 legacy 定位）；BSON 类型全集 vs 本版类型面（BSON 规范；本契约 §3.4） | 新旧服务端并存（legacy/OP_MSG） | ⚠️ 9 种类型字节有常量（`builder.go:23-34`）；但结构化 `documents` 通道 binary **不可达**（JSON 无 []byte 分支，`builder.go:124-151`），int64 同不可达；❌ ObjectId/日期/正则等未实现（未知 Go 类型静默 null） | 缺口 → G-MONGO-4（B′：明确不支持 + 迁入计划；用例侧现状钉：binary/int64 只走 fixture 通道 #8） |

### 10.2 子表①：opcode×方向矩阵（逐格已覆/缺失/不适用）

> 适配声明：本协议无"响应码"概念。等价物 = **opcode × 方向**（规范的方向约束：客户端不得发 OP_REPLY；只有 QUERY/GET_MORE 有响应，§3.6）。

| opcode \ 方向 | c2s（客户端→服务端） | s2c（服务端→客户端） |
|---|---|---|
| OP_QUERY (2004) | 已覆 #1/#13/#14（请求） | **不适用**（客户端消息，服务端不发） |
| OP_REPLY (1) | **不适用**（[^2] reserved for database） | 已覆 #1/#13/#14（响应，`responseTo` 配对不断言值、只断头字节；配对校验缺口 G-MONGO-3） |
| OP_INSERT (2002) | 已覆 #2（单）/#7（组合）/#8（fixture 通道） | 不适用 |
| OP_UPDATE (2001) | 已覆 #3（单）/#7（组合） | 不适用 |
| OP_DELETE (2006) | 已覆 #4（单）/#7（组合） | 不适用 |
| OP_GET_MORE (2005) | 已覆 #5（单）/#7（组合） | 不适用 |
| OP_KILL_CURSORS (2007) | 已覆 #6（单）/#7（组合） | 不适用 |
| OP_MSG (2013) / OP_COMPRESSED (2012) | 缺口→负例 #25（字符串形今日可拒；数字形 G-MONGO-3） | 不适用 |

**逐格机械重数**：表体 **8 行 × 2 列 = 16 格**：已覆 11 / 不适用 4 / 缺口 1。11 + 4 + 1 = 16 ✓ 无空格。

### 10.3 子表②：数据形态变体表（协议相关全部形态逐项）

| # | 变体维度 | 形态 | 对应用例 | 备注（实测锚） |
|---:|---|---|---|---|
| 1 | 地址族 | IPv4 / IPv6（同住 `ip` 层） | #1/#13 | IPv6 起点 74 = 14+40+20；IPv4 起点 54 |
| 2 | 头四字段 | length/requestID/responseTo/opCode 逐字节 | #12 | LE；length=59/requestID=190/op=2002 |
| 3 | OP_QUERY 体 | flags/skip/return/query/可选 returnFieldsSelector | #1/#10 | returnFieldsSelector 今日**无配置面**（struct 无此键）→ 现状声明 |
| 4 | OP_REPLY 体 | flags/cursorID/startingFrom/returned/文档* | #1/#16 | flags 位面 #16（AwaitCapable/QueryFailure） |
| 5 | 写操作体 | INSERT/UPDATE/DELETE 字段序 | #2/#3/#4/#7 | UPDATE 的 selector+update 双 BSON；DELETE flags |
| 6 | 游标操作体 | GET_MORE 的 return+cursorID；KILL 的 count+ID 数组 | #5/#6/#7 | cursorID fixture `0x0102030405060708`（LE 线值 `08 07 06 05 04 03 02 01`），不宣称真实分配 |
| 7 | BSON 标量 | double/string/bool/null/int32/int64 | #8 | int64 只走 fixture 通道（JSON number 不可达，§2.4） |
| 8 | BSON 复合 | 内嵌文档/数组/binary | #8 | 多键/多元素顺序随机 → fixture 通道钉死（G-MONGO-2 修后转结构化） |
| 9 | BSON 边界 | 空文档（5B）/ 空串 / false / 空 binary / int32 上下界 | #9/#11 | 长度 4 非法面 → G-MONGO-4（今日无校验，现状钉） |
| 10 | namespace | `db.coll` / 空串 / 缺终止符 | #1 + G-MONGO-4 | 空 namespace 今日可配（validator 不拦）→ 现状声明 |
| 11 | requestID 编排 | 递增 / 跨消息配对 | #15 | 配对校验缺失 → 只断言字节（G-MONGO-3 修后加值断言） |
| 12 | 多会话 | `sessions[]` 两连接（各自 src_port） | #14 | 整块展开；`tcp.srcport` distinct 断言 |
| 13 | 多流 | `flows=N` 多流 | #18 | `ip`/`tcp` 层动态五策略（§12.12） |
| 14 | 分段 | 单报文跨 segment | #17 | tcp 层 MSS 分段（默认 1460） |
| 15 | 端口 | 默认 27017 / 显式非默认 | #1 + G-MONGO-5 | 显式值被尊重（无强制等于校验，§2.1）；dissector 非标端口行为待测 |
| 16 | `decode_as` | 标准端口免声明 | 全正例 | 非标端口面待 P4（G-MONGO-5） |
| 17 | wire_fault | 5 kind / 未知 kind / 非对象形 | 负例 #19–#23 + #25 注记 | `builder.go:404-426` |
| 18 | 死字段 | 消息 `direction` / 层 `bson_fixture_hex` | 已删键（§2.3） | 原 13 例的 `direction` 已随层链迁移删除 |
| 19 | 输出路 | pcap / NIC（port_group） | #1 pcap + A′ NIC 例 | 双路验收 §6.3 |

### 10.4 关联关系专节（§3.8–3.10）：无派生流的边界

MongoDB 传统协议**没有**控制流派生数据流的形态：查询响应与请求复用**同一条 TCP 连接**，游标后续 GET_MORE 亦在同一连接上（cursorID 是报文内字段，不是连接标识）。

| 关联三件事（§3.9） | 本协议取值 |
|---|---|
| 归属哪个会话 | 同一 TCP 会话（`sessions[]` 内序） |
| 归属哪个事务 | 同一"请求→响应"事务（由 requestID/responseTo 关联，今日无校验 G-MONGO-3） |
| 由哪个字段决定 | `responseTo` == 请求 `requestID` |

**结论**：`driven_by` **不适用**（无被关联流）。**不许**用"同一模板连续重复发射"冒充编排（§3.13）——多操作序列必须写清先后与配对（#15）。

### 10.5 候选方案对比（§4.17）与三路对照（§4.12–4.15）

**三路对照**：

① **规范原文**：MongoDB Manual Wire Protocol 页（头四字段语义、OP_MSG 结构、legacy 定位）+ meta-driver legacy txt（MsgHeader/opcode 值表/OP_UPDATE/OP_REPLY/responseFlags）+ BSON 规范（类型字节/文档布局）。**不引博客/二手解读**（§4.11）。

② **现网行为**（产品+行为+出处）：各语言驱动（C/mongo-shell/pymongo 行为：建连 TCP 27017、OP_QUERY→OP_REPLY 配对、无响应写操作）——出处为官方文档行为描述；**确认方式（G-MONGO-7）**：本机回环起 mongod（或容器）抓 27017 核对头/opcode/BSON 面——**当前未做**，故"现网行为"档仅到文档描述级，未到本机抓包级。

③ **开源实现思路**：Wireshark `packet-mongo.c`（本机 92 个 `mongo.*` 字段：`mongo.message_length/request_id/response_to/opcode/query.flags/full_collection_name/reply.flags/cursor_id/starting_from/number_returned/document/*` 等）——**只借鉴字段语义，不搬码**；本仓库 `builder.go` 已落码字节为双列互证（§3.2 表格右列）。

**三路一致性**：三路在「16 字节头/LE/7 opcode 值/body 字段序/length 含头」完全一致。**不一致点**：现网主力已是 OP_MSG，而本契约范围是 legacy——取舍按 §4.15：**本版只做 legacy（旧审计既定范围），OP_MSG 另立版本**，不偷换、不混写。

**候选方案对比（§4.17）**：

| 方案 | 走法（含借鉴来源） | 优 | 劣 | 性能/复杂度/兼容性 | 结论 |
|---|---|---|---|---|---|
| **A 存量翻译补齐 + validator 加固** | 补 `translateTerminalConfig` 的 mongodb JSON 往返（postgresql `chain_planner_translate.go:2006-2032` 同款）；`resolveOpcode` 数字路径收紧为已知集；`responseTo` 配对守卫；BSON 按键排序 | 与已收官族同构；改动集中三处；存量 13 例行为不变（只换形状） | 需动共享文件（translate）→ 主线程改（车道禁令） | O(n) 流式不变；兼容性最好 | **采用** |
| B 旧 planner 接线 | 把 `mongodb.Planner` 注册进 ChainPlanner | 零新码拿全能力 | planner 自产握手/挥手与 tcp 层重复；两套真相并存（违反 §1） | 复杂度高、双头配置 | 不选（其包数语义作旁证） |
| C 生 hex 回放 | 消息内 `body_hex` 逃生口 | 最简单 | 字段不可结构化断言、动态面全失 | 动态零分 | 仅作特殊形逃生口候选，不采用为主路径 |
| D 只覆盖 QUERY/REPLY | 收缩到查询冒烟面 | 工作量最小 | 5 opcode + BSON 面全失；违反 §9.20 枚举全覆盖 | 表达力骤降 | 不选 |

---

## 11. P2 D-MONGODB-1 代码设计（CORE_MEMORY §8 八要素；门1 获批 = 定稿）

> 体裁：文件清单 / 接口签名 / 数据结构 / 主流程 / 错误分支 / 性能边界 / 冲突点 / 回滚。**本轨道不执行**（车道 A 只写文档）。

### 11.1 文件清单（P4 动作）

| 文件 | 动作 | 职责 |
|---|---|---|
| `internal/core/layers/chain_planner_translate.go` | **扩展** | 增 `case "mongodb"`：层 config 经 JSON 往返解码为 `core.MongoDBConfig`（postgresql §11.1 同款，`completedConfig` + `json.Marshal/Unmarshal` + flat 优先守卫） |
| `internal/protocol/mongodb/planner.go:146-168` | **扩展** | `resolveOpcode` 数字路径收紧：只接受 {1,2001,2002,2004,2005,2006,2007}，其余 `unknown opcode`（与字符串路径同文案） |
| `internal/protocol/mongodb/planner.go:17-59` | **扩展** | `Validate` 加 `responseTo` 配对守卫（响应无对应请求 → 拒；请求非 0 → 拒；锚词 `responseTo`） |
| `internal/protocol/mongodb/builder.go:104-121` | **扩展** | `buildBSON` 按键排序（G-MONGO-2）；`bsonArrayElement` 保序（索引序直编，不经 map） |
| `internal/core/types.go:1231-1250` | **扩展** | 删死字段（`Direction`，D1）或接线二选一；`MongoDBConfig.BSONFixtureHex`（层级，D2）删除 |
| `internal/core/layers/registry.go:634-641` | **扩展** | 删层级 `bson_fixture_hex`（D2；删后重跑 schemagen，`TestLayersGeneratedMatchesRegistry` 会红） |
| `internal/protocol/mongodb/builder.go:39-40` | **扩展或删除** | `MaxMessagePayload` 接线（真实上限检查，D3）或删除常量 |
| `trafficgen/test/protocol_pcap/cases/mongodb.json` | **已改写** | 原 13 例已改纯 layers 形；当前共 31 例（18 正 + 13 负） |
| `tools/coverage_gate.py`（或 `trafficgen/tools/` 下实际位置） | **扩展** | `check_mongodb` 反查块（13+14 ID；门2 ④口径） |

### 11.2 接口签名（示意，P4 落码钉死）

```go
// translate（postgresql 同款，无新签名；case 体内 JSON 往返）
var mc core.MongoDBConfig  // json.Unmarshal(completedConfig(s, term.Config))

// planner
func resolveOpcode(op interface{}) (int32, error) // 数字路径收紧为已知集
func (Planner) Validate(spec core.FlowSpec) error // 加 responseTo 配对守卫

// builder
func buildBSON(doc map[string]interface{}) []byte // 按键排序后编码
```

### 11.3 数据结构（现状 + 扩展）

现状：`MongoDBMessage` 17 键（`types.go:1231-1250`，含死字段 `Direction`）、`MongoDBSession{SrcPort, Messages}`、`MongoDBConfig{Messages, Sessions, BSONFixtureHex†, WireFault}`（†层级死字段）。**扩展方向**：新增字段全部**可选且 omitempty**；删 `Direction`/层级 `bson_fixture_hex` 时**同批改写存量 13 例**（删 `direction` 键，否则"配置能建但语义无变化"的新假象——反向：删 struct 字段不影响 JSON 解码，旧用例仍可建，P4 必须同批删键以符 §1.12）。

### 11.4 主流程

```text
strategy config(layers [ip,tcp,mongodb])
  → ValidateLayers（未知层/未知字段 V9/层链完整性；DependsOn 补全）
  → schema 语义层（CheckProtoFlat 扁平判死 + checkLayerChainStaticCopy 多流静态复制拒）
  → ChainPlanner.ValidateSpec（FieldContract 端口补齐 27017 + translateTerminalConfig[P4 新增] + protocolValidator[mongodb.Planner.Validate]）
  → worker 逐流：resolveLayerTuple（动态）→ ChainPlanner.Generate → drive()
  → MongoDBGenerator.Generate（逐 session → 逐 message → buildMessage → EmitMsg{Up, Bytes, SrcPort}）
  → tcp 层（握手/分段/seq/挥手 + 多连接）→ ip 层 → 输出（pcap / port_group）
```

### 11.5 错误分支（§5.2）

三档：①**链级**（`ValidateLayers`/`CheckProtoFlat`/通用 FieldContract）——未知层、`unknown field`、扁平键、transport 重复；②**配置级**（`mongodb.Planner.Validate` + `checkWireFault`）——二选一/kind/方向隐含/opcode/配对（P4 新增）/IP 格式；③**生成期**（`buildMessage` 的 `unsupported opcode`——P4 收紧后**理论不可达**，因为数字 opcode 已由 ② 白名单化；若到达即为实现 bug）。全部经 `error` 传播为 **task error**，**零假成功**（G-MONGO-3 修后）。

### 11.6 性能边界（§6 摘要）

单 flow 常驻内存 O(1)；无锁无共享；逐消息流式；速率归框架 pacer。**不新增任何按流缓存**。

### 11.7 与现有逻辑的冲突点（§8.7）

1. **translate 无分支是最大冲突点**：今日纯 layers 形静默走 P0b-2 默认流（§1 的"缺口立项"实证）。P4 补 `case "mongodb"` 时**不得**与 flat 路径双轨并存——postgresql 同款"flat 优先"守卫（`if spec.MongoDB != nil { return }`）。
2. **旧 planner 的双头风险**：`planner.go:Plan()` 未被链路径引用（实测：非测试命中零），**不接线**（方案 A 已裁定）；其包数语义（3+N+4）与链路径一致，留作回归旁证。
3. **`CheckProtoFlat` 无 mongodb 分支**：顶层 `mongodb` presence 判死仍是框架缺口（G-MONGO-6）；本轮不伪造该能力，JSON 不登记该形状，#28 改为 validator 可执行的 messages/sessions 互斥负例。
4. **schemagen**：删 registry 键后必须重跑生成（`TestLayersGeneratedMatchesRegistry`，§13.18/13.19）；层数不变（不新增层）。

### 11.8 回滚方式（§8.8）

按提交序 `git revert`：translate/planner/builder/types/registry 各自独立提交可逐个回退；**存量 13 例改写提交是唯一的"数据面"提交**——回退它必须与字段删除提交**同批回退**（否则用例 `direction` 键与文档"已删除"声明失配）。registry 生成文件随提交对齐。

---

## 12. 门1 §1–§14 十四行对照表（CORE_MEMORY §15.1–15.3）

> 证据三选一（§15.2）：文档章节 / 代码行 / 用例号。写不出 = 缺口立项，不许空着。§1/§3/§12 三行按 §15.3 强制展开（§12.1/§12.3/§12.12）。

| § | 本协议怎么满足 | 证据 |
|---|---|---|
| §1 层链唯一真相 | 见 §12.1 强制展开：原存量 13/13 已迁移；当前 JSON 31 例全部纯层链，非负例顶层键 = 0；互斥/count 负例见 #28/#29 | 本契约 §2.1 + §12.1；cases 机读实测 |
| §2 策略/任务 | 策略 = 单 mongodb 流量模板，自带 `flow_control`（flows/bps/time）；任务 = 多策略合跑 + 总量封顶；框架语义未动（`mongodb` 不在 worker/task 特判名单） | `internal/core/worker.go:307-316`；本契约 §2.1 |
| §3 五件套 | 见 §12.3 强制展开：会话表 / 事务序列（请求→响应四件事）/ 关联关系（`responseTo` 配对，无 `driven_by`）/ 插入位置（终结层）/ 时间线（会内顺序 + 多会话整块 + 多流并发）。**有 TCP 长连接载体，不豁免** | 本契约 §12.3 + §10.4；用例 #14/#15/#18 |
| §4 查规范 | MongoDB Manual Wire Protocol 页 + meta-driver legacy txt + BSON 规范（节号级，无二手解读）+ RFC 9293/8200（载体）；tshark `mongo.*` **92** 字段实测；P1 矩阵 8 行 + 三子表（§10.1–10.3）+ 候选方案对比（§10.5） | 本契约 §3/§10 |
| §5 依赖与错误 | 依赖 = `DependsOn ["tcp"]` 单值（`registry.go:634`），无 TransportOn/OptionalOn/InnerRequired；端口契约 `FieldContract{"tcp.dst_port":"27017"}`（通用块补齐，无强制等于校验）；`wire_fault` 5 有效 kind；失败传 task error（零假成功，G-MONGO-3 修后） | 本契约 §5/§7 + §11.5 |
| §6 性能 | 见本契约 §6「性能设计与验收」（6.1–6.8 要素）：逐消息流式、单 flow O(1) 内存、无锁无共享；pcap/NIC 双路验收（NIC = `enp135s0f0np0`）；吞吐数字标「待 P4 基准」（§6.5 不写承诺） | 本契约 §6 |
| §7 三份文档 | `docs/protocols/mongodb/{design,testcase}.md` + D-MONGODB-1（本契约 §11）+ T-MONGODB（testcase §2，31 ID）+ generated schema | 本目录修订记录 |
| §8 设计先行 | 本条目 P1–P3 先于 P4 实现；门1 获批 = D-MONGODB-1 定稿 = 开工门（§8.9） | 提交序 |
| §9 测试三源 | 三源 = 规范条款（§3 逐表列出处）+ D-MONGODB-1（§11）+ 已确认现网行为（**未到抓包级 → G-MONGO-7**，不冒充第三源）；当前 JSON 31 个 ID 逐项回指；原存量 13 例审计去向见 testcase §8，新增 #28–#31 为顶层白名单、count、responseTo 配对和空层失败路径。 | `docs/protocols/mongodb/testcase.md` §2/§5/§8 |
| §10 评审闭环 | 每阶段对抗自重审（结论见 `/tmp/pipe/87-mongodb/p123-report.md` §3）+ 收官隔离复审 + 修轮；红先绿后 | 报告 §3 |
| §11 白话 | 汇报首句先行白话结论 | 报告 §0 |
| §12 动态清单 | 见 §12.12 强制展开：四元组 = `ip`/`tcp` 层（五策略全支持，allowlist `layer_dyn.go:17-21`；`mongodb` **不在** allowlist → 业务字段对象必拒）；业务字段逐个列开/不开 + 理由；序号算法实读行号 | 本契约 §12.12 |
| §13 schema 派生 | `mongodb` 已在 `registry.go:634-641` 注册（**不新增层**）；`allowedProtocols["mongodb"]=true`（`protocols.go:44`）；`main.go:514` 已注册 ChainPlanner；**P4 删键必须重跑 schemagen**（§13.18/13.19）；struct 标签字面量锁定 | 本契约 §11.1 |
| §14 真实流程 | suite 经 MCP 建策略建任务 → 引擎真实生成 → tshark `mongo.*`（92 字段）+ frames hex 双通道 → 先跑后钉（§9.31/§14.20）；pcap 落 `/tmp/mcp-pcaps/mongodb/` | testcase §7 |

### 12.1 §1 强制展开：旧键去向 + 完整 spec_json 样例

**存量迁移已完成（逐例机读，2026-09-30）**：原 13 例已全部改为 `[ip,tcp,mongodb]` 纯层链形；当前 JSON 共 31 例，非负例顶层仅有白名单结构性键。新增 #28–#31 覆盖 messages/sessions 互斥、count/responseTo/空层失败路径。

**旧键去向表（§15.3 要求"每个键写去向"）**：

| 旧键 | 存量出现例数 | 去向 |
|---|---:|---|
| `src_ip` | **原 13 例各 1** | 已迁入 `layers[i].ip.src` |
| `dst_ip` | **原 13 例各 1** | 已迁入 `layers[i].ip.dst` |
| `src_port` | **原 13 例各 1** | 已迁入 `layers[i].tcp.src_port` |
| `dst_port` | **原 13 例各 1** | 已删除，由 FieldContract 补齐 27017 |
| `count` | **原存量 0** | 走 `flow_control`；新增负例 #29 专门验证游离键拒绝 |
| 顶层 `mongodb` 子映射 | **原 13 例各 1** | 已迁入 `layers[i].mongodb`；新增负例 #28 验证并存拒绝 |
| 消息内 `direction`（死字段 D1） | 13 例全带 | **P4 删键**（§1.12；非顶层键，不属 §1 白名单面，但同属"配上不生效"） |

**时序记录（2026-09-30）**：translate 分支和层链迁移已落地；当前 31 例可供 suite 全量校准。原有“先补 translate 再改写”的约束已完成，不再把 JSON 标成待迁移。

**目标形状 spec_json 样例（纯 layers，顶层仅 `layers` + `flow_control`）**：见 §2.1（`messages` 双事件查询响应形；多会话形见 testcase §3.6）。

**互斥负例形状说明**：`layers[].mongodb` 同时含 `messages` 与 `sessions` 是本协议已落盘的**判死负例形状**（#28）；其错误锚词为真实 planner 文案 `mutually exclusive`。#26/#29 另覆盖通用扁平键拒绝，#27 覆盖层内未知字段（V9）。

### 12.3 §3 强制展开：五件套

**会话表**：

| 会话 | 四元组 | 生命周期 | 用例 |
|---|---|---|---|
| `s1`（单会话基线） | `ip.src/dst` + `tcp.45087→27017` | SYN/SYN-ACK/ACK → 应用事件* → FIN 四way | #1 |
| `s2`（多会话展开） | 第二 src_port（`sessions[].src_port`） | 与 s1 完全独立的握手→事件→挥手；**整块回放不交错** | #14 |
| `s3`（并发多流） | `flows=N` 独立四元组 | 框架逐流并行；断言每题各自独立 | #18 |

**事务序列（单事务四件事 §3.4–3.7）**：

| 事务 | 前置条件 | 触发动作 | 成功分支 | 失败分支 |
|---|---|---|---|---|
| `t1` 查询事务 | TCP 已建连 | c2s OP_QUERY | s2c OP_REPLY（`responseTo` 配对；今日只断字节，G-MONGO-3 修后断值） | 查询错：REPLY flags QueryFailure 位 + `$err` 文档（A′，#16） |
| `t2` 写事务 | TCP 已建连 | c2s INSERT/UPDATE/DELETE（**无响应**，§3.6 规范行为） | 连接保持，下一事件继续 | 连接级错误：TCP 断连（无协议内错误报文） |
| `t3` 游标事务 | 前序 REPLY 给出 cursorID ≠ 0 | c2s GET_MORE（带 cursorID） | s2c REPLY（更多文档）→ 用完 c2s KILL | 游标失效：REPLY CursorNotFound 位（A′，#16） |
| `t4` 终止 | 任意 Established 态 | TCP FIN 四way（`tcp.termination` 默认 true） | Closed | 非正常结束：RST（`tcp.rst=true`，A′） |

**关联关系（§3.8–3.10）**：见 §10.4——**同一连接内请求↔响应配对**（`responseTo` 字段），无派生流，故 `driven_by` **不适用**，且**不许**用"同一模板连续重复发射"冒充编排（§3.13）。

**插入位置**：终结层（`CategoryTerminal`，`DependsOn ["tcp"]`）——MongoDB 报文直接落 TCP payload；链上**无中间层**。

**时间线**：**单会话严格顺序**（事件按 `messages[]` 序）；**多会话整块顺序**（s1 全流程跑完再跑 s2）；**多流并发**（`flows=N`，跨流不假设全局包序，只断言流内序与各流独立）。无"长传输分片让位"面（无数据流）；控制可中插动作 = 无。

### 12.12 §12 强制展开：动态字段清单与序号算法

**四元组（`ip`/`tcp` 层，五策略全开）**：

| 字段 | 住处 | 开策略 | 依据 |
|---|---|---|---|
| `src`（src_ip） | `ip` 层 | fixed/inc/rand/list/pattern 全开 | allowlist `layer_dyn.go:18` |
| `dst`（dst_ip） | `ip` 层 | 同上 | 同上 |
| `src_port` | `tcp` 层 | 同上 + 未写动态保底 `12345+i`（`worker.go:307-308`） | allowlist `layer_dyn.go:19` |
| `dst_port` | `tcp` 层 | 同上，但**显式值被尊重**（无强制等于校验）——动态 dst_port 会偏离 27017，dissector 面待测（G-MONGO-5），如实声明 | 同上 + §2.1 |

**业务字段（`mongodb` 层，逐个列开/不开 + 理由）**：

| 字段 | 开 | 理由 |
|---|---|---|
| `messages[]` 整块 | ❌ 关 | 消息序列是会话剧本；逐流变等价于"多套剧本"，应由多策略表达（§2.2 策略=单一模板） |
| `sessions[]` 整块 | ❌ 关 | 同上；多会话的内部展开已由 `sessions[].src_port` 承担 |
| 消息内 `request_id`/`namespace`/`query` 等 | ❌ 关（今天） | 逐流变请求 ID/库表/查询是**可想象的**业务需求（多租户压测），但会引入 per-flow 消息重写路径 → 列 A′ 补例候选（需先登记 allowlist；`mongodb` **不在** `layerDynAllowlist`，对象必拒） |
| `wire_fault` | ❌ 关 | 负例唯一注入口，非业务字段 |
| 层级 `bson_fixture_hex` | ❌ 关（删除，D2） | 死字段，无业务语义 |

**序号算法代码位置（实读）**：层内字段动态解析入口 `internal/core/layer_dyn.go:78` `parseLayerDyn` → `:369` `checkDynShape` → `:770` `resolveLayerTuple(spec, i)`（`worker.go:316` 调用）；值算法 `internal/core/tuple_generator.go:26` `TupleGenerator.Next(index)`；保底自增 `internal/core/worker.go:307-308`；allowlist `internal/core/layer_dyn.go:17-21`（**`mongodb` 无块**，层内任何对象值 → `does not support dynamic`）。

### 12-P2 判死负例形状（链级红例必含清单①③④）

- **①层链内业务互斥**：本协议已建 #28（`layers[].mongodb` 同时含 `messages` 与 `sessions`），作为 planner 互斥拒绝负例，锚词为 `mutually exclusive`。
- **②白名单外游离键判死（1.11–1.13）**：顶层扁平四键（#26，走 `CheckProtoFlat` 通用五键门）+ 层内第 5 键（#27，走 V9 `unknown field`，`complete.go:293`）。
- **③一切负例 `expect_error` 带错误锚词**：13 个负例逐条锚词见 testcase §4。
- **④收官自查行**：「非负例顶层键 = 0」——当前 JSON 机读为 0；负例 #28/#29 专门覆盖messages/sessions 互斥/count。
- **载体负例**：链夹 `udp`（`[ip,udp,mongodb]`）判死，锚词 `tcp`（通用 `transport layer duplicated`，`complete.go:480`；存量 `mongodb_neg_udp_carrier` 即此形）。

---

## 13. P3 对接清单（T-MONGODB 草稿输入；正文落 testcase 文件）

- §3.15 三项：见 testcase §6.1（①同连接多轮操作→#15 + A′「同连接三轮以上」；②非正常结束→#16 + 负例面 + A′「服务端 RST」；③长保活→#15 长会话 + 显式声明协议层无 keepalive 语义）。
- A′/B′ 两分类表：见 testcase §6.2。
- 9.52 对账两行：见 testcase §5.2（**规范逻辑点总数 = 62** = 八项 8 行 + 矩阵 16 格 + 变体 19 行 + 动态 5 面 + 错误 14 面；**用例覆盖数 = 45**；**不适用 = 17**；45 + 17 = 62 ✓；清单出处 = 规范/官方文档反推）。
- 3.14 豁免边界审计：见 testcase §6.3（**有 TCP 长连接载体 → `sessions[]` 不豁免**；多流并发 #18 + 单包多载荷 #8/#11（多文档单 INSERT）各至少一例）。
- 三源回指行：见 testcase §5.1（第三源"已确认现网行为"当前 = 未确认级，挂 G-MONGO-7）。

---

## 14. 缺口立项清单（有缺口写「缺口立项」，不许空着）

| 立项号 | 缺口 | 确认方式（三选一：查文档 / 抓包 / 问人） | 去向 |
|---|---|---|---|
| **G-MONGO-1** | `translateTerminalConfig` 无 `case "mongodb"` → 纯 layers 形静默产 P0b-2 默认流（配 5 条只出 1 条） | 读 `chain_planner_translate.go`（`case "mongodb"` 零命中）+ `layer_gen.go:30-34` 默认分支对照 | **P4 第 1 步必办**（§11.1；时序约束 §12.1） |
| **G-MONGO-2** | BSON 多键文档/多元素数组编码顺序随机（`range doc` + 经 map 的数组） | 读 `builder.go:111` + `:181-184` | **P4 必修**（按键排序 + 数组保序；此后 S3 类断言可转结构化通道） |
| **G-MONGO-3** | 校验三缺：①responseTo 配对无守卫 ②数字 opcode 越界 Validate 放行（链路径空流/残缺流假成功，违反 §14.11/14.12）③OP_MSG/数字形拒绝无用例 | 读 `planner.go:146-168` + `builder.go:265` + §7 错误传播分析 | **P4 必修**（§11.1/§11.5；负例 #25 扩展数字形） |
| **G-MONGO-4** | BSON/长度四缺：①BSON 越界·缺终止符无校验 ②messageLength 上下界无校验（D3 常量零引用）③fixture hex 解析失败静默回退 ④未知 Go 类型静默 null | 读 `builder.go:39-40` + `:150` + `:300-305` | **B′**→D-MONGODB-1「明确不解决 + 迁入计划」（除 ② 的常量去留 P4 二选一）；用例侧现状钉 |
| **G-MONGO-5** | 非标准端口面：显式 `tcp.dst_port` ≠ 27017 被尊重（无强制等于校验）；dissector 非标端口行为、`decode_as` 需求均未实测 | **抓包**：配显式端口跑 suite，tshark 核对 `mongo.*` 是否可读 | P4 实测项；确认前相关条目按 §5.5 标"待确认" |
| **G-MONGO-6** | 顶层白名单洞：`CheckProtoFlat` 无 `mongodb` 分支 → 顶层 `mongodb` 子映射不判死 | 读 `strategy_convert.go:8322-`（分支列表无 mongodb） | **框架级缺口**（禁加单协议黑名单分支；上报主线程）；用例侧**不建**该负例 |
| **G-MONGO-7** | 现网行为未到抓包级：驱动真实 Startup 参数面与认证…（无，本协议无认证）→ 更正：驱动真实 query/reply 头与 BSON 面只有文档描述，无本机抓包证据 | **抓包**：本机回环起 mongod + 驱动查询，tcpdump 抓 27017 核对头/opcode/BSON | P4 前置确认项，不挡开工；确认前相关条目按 §5.5 标"待确认" |
| **G-MONGO-8** | 死字段处置：D1 `direction`（删/接线二选一）/ D2 层级 `bson_fixture_hex`（删）/ D3 常量（接线/删二选一） | 读 §2.3 双实证（零读取 + 存量携带） | **P4 必办**（§11.3 时序约束：与存量改写同批） |

---

## 15. 修订记录

- v1.1.0（2026-09-30）：对齐当前 JSON 31 例（18 正 + 13 负）与层链迁移实况；同步门1表、存量审计和缺口文字。未跑 suite，待 P5 真实流程校准。旧基线 #32 的线格式章节继承、配置/用例章节作废（§1/§8 对账）。

## 16. D1–D8 静态设计闭环

| 编号 | 结论 | 证据与边界 |
|---|---|---|
| D1 | 地址、端口、数量各归唯一层/流控；正例无游离顶层键 | `[ip,tcp,mongodb]` 形状见 §2.1；`flow_control` 承载数量；#26/#29 保留为扁平键负例 |
| D2 | MongoDB 是 TCP 终结层，IPv6 仍由 `ip` 层承载 | registry `DependsOn ["tcp"]`；正例 #1–#18 的链形与 #13 IPv6 |
| D3 | TCP 握手、分段、挥手由 `tcp` 层负责；MongoDB 只发消息事件 | §4.1 包数公式；#17 MSS 分段、所有正例握手/终止断言 |
| D4 | 业务配置只住 `layers[].mongodb`，消息/会话二选一 | §2.2–§2.3；#20 空层、#27 未知层字段负例 |
| D5 | messages/sessions 互斥 与扁平字段是拒绝面，不是正例入口 | #28 明确登记 互斥形状；#26/#29 登记通用扁平拒绝 |
| D6 | 7 legacy opcode、BSON、responseFlags 与头字段均有静态断言面 | §3、§10；#1–#12、#15–#16、#22–#26 覆盖或登记缺口 |
| D7 | 错误配置只用严格双键 `expect`，锚词必须来自真实 validator/wire_fault 文案 | §7；JSON 13 个负例均为 `expect_error` + `error_contains` |
| D8 | 动态只开通用 `ip`/`tcp` 五策略；MongoDB 业务字段动态保持关闭 | §12.12；#18 使用动态四元组，G-MONGO-1/2/3/5 明确未运行或待修 |

## 17. T/C 静态闭环索引

测试契约的六项静态检查（T1–T6）见 `testcase.md` §10；机器 cases 的六项对账（C1–C6）见 `testcase.md` §11。这里固定三文件边界：不把未运行 suite、MCP、NIC 或 PCAP 写成已验证证据。

### 17.1 四个新增 JSON ID 的去向

文档 §9 与 testcase §2 已覆盖并逐项描述 #1–#27（27 个 documented IDs）。JSON 另有 4 个新增 ID，共 31 例：

| 新增 ID | 类型 | 去向 |
|---|---|---|
| `mongodb_neg_messages_sessions_conflict` (#28) | 负 | testcase §4；设计 §12-P2；messages/sessions 互斥负例，锚词为真实 planner 文案 `mutually exclusive` |
| `mongodb_neg_flat_count` (#29) | 负 | testcase §4；设计 §12-P2；顶层 `count` 扁平键负例，锚词含 `flat config field count` |
| `mongodb_neg_orphan_reply` (#30) | 负 | testcase §4；设计 §4.2/G-MONGO-3；`responseTo` 配对负例（当前为待代码闭环面） |
| `mongodb_neg_empty_layer` (#31) | 负 | testcase §4；设计 §4.2；空 `mongodb` 层缺消息/会话负例 |

静态计数结论：JSON = 31（18 正 + 13 负）= 文档既有 27 + 新增 4；三文件 ID 集合以 JSON 为最终机器权威。四个新增负例仍只含 `expect_error`、`error_contains` 两键；未宣称其 suite 已运行。

## 18. C1–C6 缺口迁入计划

| 编号 | 缺口 | 迁入计划 |
|---|---|---|
| C1 | `translateTerminalConfig` 缺 `mongodb` 分支（G-MONGO-1） | P4 补层内 JSON 往返翻译，随后复跑 #1–#18 |
| C2 | BSON 多键/多元素顺序不稳定（G-MONGO-2） | 先按键排序并按索引保序，再把 #8/#11 的结构化断言扩全 |
| C3 | 数字 opcode/responseTo 配对错误传播不完整（G-MONGO-3） | validator 白名单化并让错误到 task 终态；按现有 #25（opcode 本体）与 #30（孤儿 `responseTo`）两条负例对账，不改机器例形 |
| C4 | BSON/长度边界与 fixture 回退校验不足（G-MONGO-4） | 作为 B′ 明确不解决项，另立 builder 约束与负例，不伪造现有支持 |
| C5 | 非标准端口 dissector、真实驱动抓包证据缺失（G-MONGO-5/7） | P4 用实际 suite/回环抓包确认；当前只保留规范与代码锚点 |
| C6 | messages/sessions 互斥 框架洞、死字段处置与性能基准（G-MONGO-6/8） | 上报共享框架；删/接线死字段与 schemagen 由代码轨另立变更；基准后补静态包数核对 |

以上为三文件静态闭环；未修改 Go、schema、其他文档或 `LAYERCHAIN_INDEX`，未运行 suite/MCP/NIC。
