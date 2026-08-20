# MongoDB Wire Protocol（MongoDB 有线协议）设计文档

> 版本：v1.0.0（设计阶段）  
> 日期：2026-08-20  
> 状态：仅设计与用例契约，`mongodb` 层尚未实现；本文不宣称当前 MCP（Model Context Protocol，模型上下文协议）套件可以运行。  
> 配套文件：`docs/protocol-designs/32-mongodb-testcase.md`、`trafficgen/test/protocol_pcap/cases/mongodb.json`、`docs/protocol-designs/audit/32-mongodb-adversarial-audit.md`

## 1. 范围和不变式

MongoDB Wire Protocol（MongoDB 有线协议）是在 TCP 上承载 MongoDB 客户端/服务端消息的二进制协议。本文选择**传统 OP_* 系列消息**作为第一版确定线格式：消息头为 16 字节、小端序；覆盖 `OP_QUERY`、`OP_REPLY`、`OP_INSERT`、`OP_UPDATE`、`OP_DELETE`、`OP_GET_MORE` 和 `OP_KILL_CURSORS`。默认 TCP 目的端口为 **27017**。

本版明确**不实现 `OP_MSG`（现代消息）、`OP_COMPRESSED`（压缩包装）**：二者需要协商/压缩算法及更细的 flag/section 规则，不能在没有实现约束或线上 fixture（固定抓包样本）的情况下臆造。后续加入时必须另增版本和用例，不改变本版传统 opcode 的语义。

不变式：

1. 每条消息的 `messageLength` 包含 16 字节头和完整 body，且 `messageLength >= 16`。
2. header（消息头）字段全部是 little-endian（小端序）：`messageLength`、`requestID`、`responseTo`、`opCode` 均为 32 位线值，按无符号值解释。
3. 一个应用消息由一个脚本事件生成一个 TCP payload；事件不隐式增加 ACK 或服务器响应。是否有响应只能由脚本显式放入反向事件，因此不编造服务器行为。
4. 传统 opcode 与 body 布局只在 TCP 27017 上使用；UDP、其他传输层和未知 opcode 在 planner/validator（规划器/校验器）边界拒绝。
5. BSON（Binary JSON，二进制 JSON）文档长度等于从长度字段开始到结尾 `0x00` 的总字节数；最小空文档为 `05 00 00 00 00`。

## 2. 线格式

### 2.1 通用 16 字节消息头

| 相对偏移 | 字段 | 宽度 | 编码 | 约束 |
|---:|---|---:|---|---|
| +0 | `messageLength` | 4 | little-endian uint32 | `>=16`；覆盖头和 body |
| +4 | `requestID` | 4 | little-endian int32 线值 | 脚本生成；同一会话不得无意重复 |
| +8 | `responseTo` | 4 | little-endian int32 线值 | 请求为 0；响应应等于对应请求 ID |
| +12 | `opCode` | 4 | little-endian uint32 | 只允许 §2.2 列出的值 |

以太网帧中消息头的起点固定为：IPv4 `54`（14 字节 Ethernet + 20 字节 IPv4 + 20 字节 TCP，无 TCP option 的数据段），IPv6 `74`（14 + 40 + 20）。若 TCP option 或 IP 扩展头存在，测试必须改用解码字段，不得继续使用常量偏移。

### 2.2 传统 opcode

| 名称 | 十进制 | body 起点 +16 | body 固定字段 |
|---|---:|---:|---|
| `OP_REPLY` | 1 | responseFlags(4) | cursorID(8)、startingFrom(4)、numberReturned(4)，之后 BSON 文档 |
| `OP_UPDATE` | 2001 | zero(4) | collection C-string、flags(4)、selector BSON、update BSON |
| `OP_INSERT` | 2002 | flags(4) | collection C-string、一个或多个 BSON |
| `OP_QUERY` | 2004 | flags(4) | collection C-string、numberToSkip(4)、numberToReturn(4)、query BSON；可选 returnFieldsSelector BSON |
| `OP_GET_MORE` | 2005 | zero(4) | collection C-string、numberToReturn(4)、cursorID(8) |
| `OP_DELETE` | 2006 | zero(4) | collection C-string、flags(4)、selector BSON |
| `OP_KILL_CURSORS` | 2007 | zero(4) | numberOfCursorIDs(4)、cursorID 数组（每项 8） |

`C-string`（C 字符串）是 UTF-8 字节加单个 `0x00` 终止符；namespace（命名空间）格式为 `database.collection`，不包含空字节。传统 opcode 的 body 均按表中顺序编码。

### 2.3 OP_QUERY/OP_REPLY 确定样例

`test.users` 的长度为 11（含终止符），selector `{ "x": 1 }` 的 BSON 为：

```text
0c 00 00 00 10 78 00 01 00 00 00 00
```

`OP_QUERY(requestID=100, flags=0, skip=0, return=1)` 的 51 字节 message（消息）为：

```text
33 00 00 00 64 00 00 00 00 00 00 00 d4 07 00 00
00 00 00 00 74 65 73 74 2e 75 73 65 72 73 00
00 00 00 00 01 00 00 00 0c 00 00 00 10 78 00 01 00 00 00 00
```

`OP_REPLY(requestID=101,responseTo=100,flags=0,cursorID=0,startingFrom=0,numberReturned=1)` 的 48 字节 message 为：

```text
30 00 00 00 65 00 00 00 64 00 00 00 01 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 01 00 00 00 0c 00 00 00 10 78 00 01 00 00 00 00
```

样例只表达可确定的传统 wire（线）字段；它不是对真实服务器查询结果或 cursor（游标）分配行为的承诺。

## 3. BSON 编码契约

### 3.1 元素类型

第一版 builder（构造器）至少支持下列基础类型，元素类型字节和 payload（载荷）均固定：

| 类型 | type byte | payload 编码 | 本版要求 |
|---|---:|---|---|
| double（双精度） | `0x01` | IEEE-754 binary64 little-endian | 支持有限值；NaN/Inf 待实现边界 |
| string（字符串） | `0x02` | int32 字节长度（含终止符）+ UTF-8 + `0x00` | 长度按编码后字节，不按字符数 |
| embedded document（嵌入文档） | `0x03` | BSON 文档 | 递归深度限制待实现边界 |
| array（数组） | `0x04` | BSON 文档，键为 `"0"`,`"1"`... | 键必须从 0 连续递增 |
| binary（字节串） | `0x05` | int32 长度 + subtype `0x00` + bytes | subtype 仅支持 generic `0x00` |
| boolean（布尔） | `0x08` | `0x00` 或 `0x01` | 其他值拒绝 |
| null（空值） | `0x0a` | 无 payload | 仅有类型和键 |
| int32（32 位整数） | `0x10` | little-endian int32 | 越界拒绝，不截断 |
| int64（64 位整数） | `0x12` | little-endian int64 | —— |

每个文档为 `int32 length + elements + 0x00`；元素序列必须以单个 `0x00` 结束，长度至少 5。元素键必须以 `0x00` 结束且不允许截断。未列入的 ObjectId、正则、JavaScript、Decimal128 等类型属于待实现边界，不得静默当作字符串。

### 3.2 多类型固定 fixture

文档 `{d:1.5,i:-7,l:0x0102030405060708,s:"A",b:true,n:null,bin:0102,arr:[7,"x"],doc:{b:null}}` 的 101 字节 BSON 为：

```text
65 00 00 00
01 64 00 00 00 00 00 00 00 f8 3f
10 69 00 f9 ff ff ff
12 6c 00 08 07 06 05 04 03 02 01
02 73 00 02 00 00 00 41 00
08 62 00 01
0a 6e 00
05 62 69 6e 00 02 00 00 00 00 01 02
04 61 72 72 00 15 00 00 00 10 30 00 07 00 00 00 02 31 00 02 00 00 00 78 00 00
03 64 6f 63 00 08 00 00 00 0a 62 00 00 00
00
```

## 4. 会话和事件模型

### 4.1 TCP 载体

- 默认 `dst_port=27017`；`src_port` 默认 12345。
- 每个 session（会话）为独立四元组；事件按配置顺序生成，事件方向为 `c2s` 或 `s2c`。
- TCP 小载荷假定一个 message 一个 segment。若实现允许 MSS（最大报文段长度）分段，设计和 JSON 的 `packet_count` 必须同步更新；本版正例不使用超过默认 MSS 的消息。
- 正常脚本包数：`3（SYN/SYN-ACK/ACK） + 应用事件数 + 4（FIN 交换）`。不把纯 TCP ACK 计为应用事件。

### 4.2 requestID/responseTo

请求事件的 `responseTo=0`；响应事件必须显式给出 `responseTo`，并匹配对应请求 `requestID`。实现不得为缺省响应猜测 ID。`requestID` 可跨消息递增，跨 session 只要求各自可追踪；多会话测试只断言每条流内部配对。

### 4.3 错误和截断

输入配置在 planner/validator 阶段拒绝：

| 错误 | 拒绝条件 | 稳定错误锚点 |
|---|---|---|
| 载体 | `layers` 使用 UDP 或缺少 TCP | `tcp` |
| 端口 | `dst_port` 不是 27017（除非显式 `allow_nonstandard_port=true`，本版未开放） | `27017`/`port` |
| header 长度 | `messageLength < 16` 或声明长度超过实际 message | `length` |
| 截断 | header 少于 16 字节，或 body 少于声明长度 | `truncated` |
| opcode | 不在 §2.2 | `opcode` |
| BSON | 文档长度小于 5、越过 message 边界、缺终止符或元素非法 | `bson` |
| 关联 | response 的 `responseTo` 无对应请求，或 request 的 responseTo 非 0 | `responseTo` |
| 上限 | message 超过实现声明的 `max_message_bytes`；默认值待实现，不在本版伪造具体数值 | `message`/`limit` |

`wire_fault`（线故障注入）只用于负例测试，不是生产配置；它代表 planner 在构造前执行的边界校验，不代表允许输出损坏的 PCAP（抓包文件）。

## 5. 配置契约

`spec_json` 使用层链：

```json
{
  "layers": [{"tcp": {"dst_port": 27017}}, {"mongodb": {}}],
  "src_ip": "10.0.0.1",
  "dst_ip": "20.0.0.1",
  "src_port": 12345,
  "dst_port": 27017,
  "mongodb": {
    "messages": [
      {"direction":"c2s", "request_id":100, "response_to":0,
       "opcode":"OP_QUERY", "namespace":"test.users",
       "flags":0, "skip":0, "return_count":1,
       "query":{"x":1}},
      {"direction":"s2c", "request_id":101, "response_to":100,
       "opcode":"OP_REPLY", "flags":0, "cursor_id":0,
       "starting_from":0, "returned":1, "documents":[{"x":1}]}
    ]
  }
}
```

支持 `messages` 和 `sessions` 二选一：单 session 使用 `messages`；多 session 使用 `sessions:[{"src_port":...,"messages":[...]}]`，每条 session 继承外层 IP/目的端口。结构化字段必须按 §2/§3 编码；测试可另置 `wire_fault` 进行拒绝路径。`bson_fixture_hex` 仅是 S3 这类测试 fixture 的原始 BSON 输入，必须先经过 BSON 长度/终止符校验，不能绕过 parser（解析器）直接发出任意字节。字段名、默认值和事件方向必须保持与 testcase 一致。

## 6. 场景映射与包数

| 场景 | JSON id | 应用事件 | packet_count | 主要锚点 |
|---|---|---:|---:|---|
| 查询响应 | `mongodb_query_reply` | 2 | 9 | OP_QUERY/REPLY 头、responseTo |
| 写操作原子集 | `mongodb_write_ops` | 5 | 12 | INSERT/UPDATE/DELETE/GET_MORE/KILL |
| BSON 基础类型 | `mongodb_bson_types` | 1 | 8 | 101 字节多类型文档 |
| 空文档边界 | `mongodb_empty_boundary` | 1 | 8 | BSON 长度 5 |
| IPv6 查询响应 | `mongodb_ipv6` | 2 | 9 | IPv6 + 同一头布局 |
| 多会话 | `mongodb_multi_session` | 4（2×2） | 18 | 两个源端口、各自 request/response |
| 头字段全量 | `mongodb_message_header` | 1 | 8 | length/requestID/responseTo/opCode |
| 截断头 | `mongodb_neg_truncated_header` | — | — | 负例 |
| 短长度 | `mongodb_neg_short_length` | — | — | 负例 |
| 超大长度 | `mongodb_neg_oversize` | — | — | 负例 |
| 非法 opcode | `mongodb_neg_bad_opcode` | — | — | 负例 |
| BSON 长度错 | `mongodb_neg_bson_length` | — | — | 负例 |
| UDP 载体 | `mongodb_neg_udp_carrier` | — | — | 负例 |

## 7. 断言偏移和实现完成定义

正例 frame（帧）断言使用消息头起点：IPv4 offset 54，IPv6 offset 74。头的前 16 字节按 little-endian 逐字节断言；BSON fixture 只在完整 TCP 数据段中断言。若 TCP option 或 IP 扩展头改变偏移，必须改为 tshark（抓包解析器）字段断言或重新计算偏移，不能保持旧常量。

实现完成定义：注册终结层 `mongodb`，硬依赖 TCP，默认目的端口 27017；每个 opcode 的 body 编解码与长度回填有单测，BSON 各列类型有正/负单测；planner 传播所有错误而不是生成 0 包成功；端到端 PCAP 对应 JSON 全部正例通过，负例在 planner 边界拒绝；至少一条 IPv6 和两条 session 的真实 packet 输出。OP_MSG/OP_COMPRESSED、未列 BSON 类型、真实服务器认证/游标生命周期在单独设计前保持未实现，不以默认行为填充。

## 8. 修订记录

- v1.0.0（2026-08-20）：建立传统 opcode 第一版范围；固定 16 字节头、BSON 基础类型、IPv4/IPv6、多会话、七种原子消息和负例边界；明确不纳入 OP_MSG/OP_COMPRESSED。
