# Apache Thrift（跨语言 RPC 框架）Binary Protocol（TBinaryProtocol，二进制协议）设计文档

> 版本：v1.0.0（设计稿）  
> 日期：2026-08-20  
> 范围：Apache Thrift Binary Protocol（Apache Thrift 二进制协议）的 TCP 流量规划；覆盖 TBinaryProtocol、RPC 消息类型、结构化字段、容器、IPv4/IPv6 与校验负路径。  
> 配套：`docs/protocol-designs/30-thrift-testcase.md`、`trafficgen/test/protocol_pcap/cases/thrift.json`、`docs/protocol-designs/audit/30-thrift-adversarial-audit.md`  
> 实现状态：**仅设计阶段，`trafficgen/internal/protocol/thrift/` 尚未实现；本文和用例不应被解释为已有运行能力。**

## 1. 目标与边界

Apache Thrift（跨语言 RPC 框架）将服务接口编译成客户端/服务端代码；TBinaryProtocol（大端二进制协议）只定义线上的类型编码和消息封装，不定义 TCP 握手。生成器应把应用字节交给公共 TCP 层，由 TCP 层生成 SYN/SYN-ACK/ACK、MSS 分段和 FIN 四次终止。

本版本覆盖：

- TCP 载体，默认服务端端口 `9090`；显式 `src_port`、`dst_port`，IPv4 与 IPv6；
- TBinaryProtocol 的**严格消息头**（version/type）、方法名、seqid；
- `CALL`、`REPLY`、`EXCEPTION`、`ONEWAY` 四种 Message Type（消息类型）；
- `BOOL`、`BYTE`、`DOUBLE`、`I16`、`I32`、`I64`、`STRING`、`BINARY`、`STRUCT`、`MAP`、`SET`、`LIST`；
- 服务方法参数、返回值和异常结构；长度、字段 ID、容器元素类型和大端字节序；
- 单次会话、多个策略 flow、MSS 分段及可观察的 payload 帧。

明确不在本版：CompactProtocol（紧凑协议）、JSONProtocol（JSON 协议）、反射式 `TApplicationException` 的全部语言绑定细节、HTTP/2、TLS、Unix domain socket、真实 IDL 编译器、服务注册发现、跨会话业务相关性。多会话仅作为独立 TCP 流规划，不声称实现服务端共享状态。

## 2. TBinaryProtocol 线格式

### 2.1 字节序与标量

所有多字节数值均为 network byte order（网络字节序，即大端）。`BOOL` 在线上占 1 字节，`false=0x00`、`true=0x01`；`BYTE` 为有符号 8 位补码；`DOUBLE` 为 IEEE-754 binary64（双精度浮点）大端；`I16/I32/I64` 分别为有符号 16/32/64 位补码大端。

| TType（类型码） | 数值 | 编码 | 备注 |
|---|---:|---|---|
| `STOP` | `0` | 无值 | struct 结束标记，仅字段头使用 |
| `BOOL` | `2` | 1B | 仅 0/1 是规范布尔值 |
| `BYTE` | `3` | 1B | 有符号字节 |
| `DOUBLE` | `4` | 8B | binary64，大端 |
| `I16` | `6` | 2B | 有符号大端 |
| `I32` | `8` | 4B | 有符号大端 |
| `I64` | `10` | 8B | 有符号大端 |
| `STRING` | `11` | `i32 length` + bytes | UTF-8 约定由 IDL/应用层负责；协议本身传字节 |
| `STRUCT` | `12` | fields + `STOP` | 每个 field 均含 type、field id |
| `MAP` | `13` | key type + value type + i32 count + entries | count 为有符号 i32 |
| `SET` | `14` | elem type + i32 count + values | 无序语义；线缆上按发送顺序出现 |
| `LIST` | `15` | elem type + i32 count + values | 有序语义 |

`STRING` 和 `BINARY` 都使用 i32 长度；`BINARY` 不因内容不可打印而改变编码，也不附加 NUL。长度为负数是非法输入，不能转成无符号后分配内存。

### 2.2 严格消息头

本设计只采用 strict write（严格写入）格式。一个消息的应用 payload 如下：

| 偏移（相对于 Thrift payload） | 长度 | 字段 | 值 |
|---:|---:|---|---|
| 0 | 4 | `version_type` | `0x80010000 | message_type`，大端 i32 |
| 4 | 4 + N | `method` | 大端 i32 字符串长度 N，随后 N 个方法名字节 |
| 8 + N | 4 | `seqid` | 大端 i32；请求与对应响应必须相等 |
| 12 + N | 可变 | message body（消息体） | `STRUCT` 字段序列，末尾 `STOP` |

四个 `message_type` 值：`CALL=1`、`REPLY=2`、`EXCEPTION=3`、`ONEWAY=4`。因此 `add` CALL 的头部开头是 `80 01 00 01 00 00 00 03 61 64 64`；不可把 strict 头误写成旧的 unversioned（无版本）`method + type + seqid` 格式。

消息体是一个隐式参数/结果 struct：每个字段为 `type (1B) + field_id (i16) + value`，所有字段后必须写 `STOP (0x00)`。字段 ID 可为负数（i16），但同一个 struct 中不得重复；实际 IDL 生成器通常使用正数。字段声明顺序可与 ID 数值顺序不同，读取方按 ID 匹配。

### 2.3 容器与嵌套

- `LIST`：`elem_type (1B) | count (i32) | value[0..count)`。
- `SET`：`elem_type (1B) | count (i32) | value[0..count)`；线缆顺序不是集合语义的一部分。
- `MAP`：`key_type (1B) | value_type (1B) | count (i32) | key,value` 交替出现。
- `count=0` 合法且仍须出现类型字节和零 count；`count<0` 非法。实现须在乘法/递归前做上限和负值校验。
- `STRUCT` 允许嵌套；每一层独立以 `STOP` 结束。未知 field type、未知容器元素 type 或字段值缺失均拒绝，不得猜测长度继续解析。

## 3. RPC 语义与状态机

### 3.1 方法调用

| 方向 | Message Type | body | 是否有响应 |
|---|---|---|---|
| 客户端→服务端请求 | `CALL=1` | 方法参数 struct | 是，通常 `REPLY` 或 `EXCEPTION` |
| 服务端→客户端成功 | `REPLY=2` | 返回结果 struct，成功返回字段通常 ID=0 | — |
| 服务端→客户端失败 | `EXCEPTION=3` | `TApplicationException` 风格 struct：ID=1 message STRING、ID=2 type I32 | — |
| 客户端→服务端单向 | `ONEWAY=4` | 方法参数 struct | 否；不能凭空生成响应 |

`REPLY`/`EXCEPTION` 必须复用对应 CALL 的 method 和 seqid。结果字段不存在也可表示 `void`，但消息仍需 struct 的 `STOP`。本设计用 `exception.type` 传递 TApplicationException 的数值，不将它误当作 Message Type。

### 3.2 会话包序

单次有响应的会话：TCP 三次握手（3 包）→ 每个应用方向 payload（按 TCP MSS 分段）→ TCP FIN 终止（通常 4 包）。因此一个未分段的 CALL+REPLY 最少为 9 包；ONEWAY 只有一个应用方向 payload，通常为 8 包。ACK 是否与数据段合并由公共 TCP planner（规划器）决定，应用层不额外插入 ACK。

多消息在同一连接中按 `messages` 顺序写出；CALL/REPLY 必须按 seqid 配对，ONEWAY 不消耗响应槽位。当前设计不承诺 pipeline（流水线）响应乱序、多连接交错的业务级顺序或服务端状态共享。

## 4. 配置设计

层链使用 `[{"tcp":{}},{"thrift":{}}]`，协议配置放在顶层 `thrift` 键。建议结构：

```json
{
  "layers": [{"tcp": {}}, {"thrift": {}}],
  "src_ip": "10.0.0.1",
  "dst_ip": "20.0.0.1",
  "dst_port": 9090,
  "thrift": {
    "messages": [
      {"type":"CALL", "method":"add", "seqid":1,
       "args":[{"id":1,"type":"I32","value":1}]},
      {"type":"REPLY", "method":"add", "seqid":1,
       "result":[{"id":0,"type":"I32","value":2}]}
    ]
  }
}
```

| 配置键 | 类型 | 默认/约束 | 线缆映射 |
|---|---|---|---|
| `messages` | array | 至少 1；按顺序发送 | 每个元素一个完整 message |
| `type` | enum/string | 必填，CALL/REPLY/EXCEPTION/ONEWAY | `version_type` 低 16 位 |
| `method` | string | 非空，UTF-8 字节长度 ≤ i32 最大值 | message method string |
| `seqid` | i32 | 有符号 32 位；请求/响应配对相同 | message seqid |
| `args` | fields[] | CALL/ONEWAY 使用 | body struct |
| `result` | fields[] | REPLY 使用；void 可为空 | body struct |
| `exception` | object | EXCEPTION 使用；message、type | ID=1/2 字段 |
| field `id` | i16 | struct 内不得重复 | field header |
| field `type` | enum | TType 表值 | field type byte |
| field `value`/`value_b64` | scalar/bytes | 与 type 相容；BINARY 用 base64（Base64，二进制文本表示） | 对应值编码 |
| `wire_fault` | test-only object | 仅负例注入截断/负长度/负 count 等原始错误 | 不代表合法业务配置 |

`count` 是套件的策略级 flow 数；多会话使用 `strategy_fc: {"type":"flows","value":N}`，不要把它写成 Thrift message 字段。默认 TCP 目标端口为 9090；端口、IP 和 MSS 校验由层/公共传输层共同负责。

## 5. 规范样例（与 JSON 用例同源）

以下十六进制均从 payload 偏移 0 开始；IPv4 无 TCP option 的数据偏移为 `14+20+20=54`，IPv6 为 `14+40+20=74`。

### 5.1 add CALL

```text
80 01 00 01 00 00 00 03 61 64 64 00 00 00 01
08 00 01 00 00 00 01
08 00 02 00 00 00 02
00
```

### 5.2 add REPLY

```text
80 01 00 02 00 00 00 03 61 64 64 00 00 00 01
08 00 00 00 00 00 03 00
```

### 5.3 容器

`describe` 样例同时展示 LIST<I16>、MAP<STRING,I32>、SET<STRING>；见 `cases/thrift.json` 的 `thrift_containers`，其中每个 count、元素 type、负 i16 `ff fe` 都有连续字节锚点。

## 6. 错误处理与安全界限

| 编号 | 输入 | 必须结果 | 对应用例 |
|---|---|---|---|
| E-01 | TCP 目标端口不在 1..65535 | Validate（校验）拒绝 | `thrift_neg_bad_port` |
| E-02 | message type 非 1..4 | 拒绝，不生成数据帧 | `thrift_neg_bad_message_type` |
| E-03 | field type 非 TType 表 | 拒绝，不猜测值宽度 | `thrift_neg_unknown_type` |
| E-04 | STRING/BINARY 负长度 | 拒绝，禁止无符号溢出/超大分配 | `thrift_neg_negative_length` |
| E-05 | LIST/SET/MAP 负 count | 拒绝，禁止遍历/分配 | `thrift_neg_negative_container_count` |
| E-06 | 应用帧在声明长度内截断 | 拒绝或任务 error；不得输出静默短帧 | `thrift_neg_truncated` |
| E-07 | CALL/REPLY method 或 seqid 不配对 | 拒绝规划 | 待实现扩展负例 |
| E-08 | struct 缺 STOP、重复 field ID、字段值截断 | 拒绝规划 | 待实现扩展负例 |

截断的精确原始字节依赖 planner 的注入位置与 TCP 分段策略；本阶段不在 JSON 中编造“截断后仍合法”的十六进制，而以 `wire_fault` 语义标明待实现边界。负例断言只使用 `expect_error` 与 `error_contains`，避免将实现尚未确定的错误文本当作 wire 事实。

## 7. 实现接线与 DoD（完成定义）

实现时新增 `internal/protocol/thrift/`：`Validate` 负责边界和语义配对，`Plan` 返回流式 packet config，builder 复用公共 TCP/IP/IPv6 层。需注册 Terminal（终结层） Thrift，硬依赖 TCP，默认端口 9090。DoD：

1. 正向 7 个场景在 IPv4/IPv6、CALL/REPLY/EXCEPTION/ONEWAY、容器/标量、多 flow 下产生与 JSON 断言一致的 pcap（数据包捕获文件）；
2. `tshark`（Wireshark 命令行解析器）或字节断言能确认严格版本头、方法名、seqid、字段类型和长度；
3. E-01..E-06 负向输入在 Validate/plan/task 任一边界返回错误，任务不得以 0 包“成功”结束；
4. `go test -race`（竞态检测）覆盖 planner 与 API→engine→output 集成路径；
5. MSS 分段只拆 TCP payload，不改变应用字节；多会话不能串用 seqid 或 4-tuple 状态。

## 8. 场景与三方索引

| 场景 | JSON id | packet_count | 关键断言 |
|---|---|---:|---|
| S1 CALL→REPLY | `thrift_call_reply` | 9 | 9090；payload 30/23B；严格头和 i32 |
| S2 CALL→EXCEPTION | `thrift_exception_reply` | 9 | type=3；seqid=7；异常字段 |
| S3 ONEWAY | `thrift_oneway_call` | 8 | 无响应；type=4；27B |
| S4 容器 | `thrift_containers` | 9 | LIST/MAP/SET；69B |
| S5 标量与 binary | `thrift_scalar_types` | 9 | 8 种标量；79B |
| S6 IPv6 echo | `thrift_ipv6_echo` | 9 | IPv6 字段；offset 74 |
| S7 多会话 | `thrift_multi_sessions` | 18 | srcport 12345/12346；每流 9 包 |
| N1..N6 负向 | 同名 `thrift_neg_*` | — | 仅 expect_error/error_contains |

## 9. 修订记录

- v1.0.0：首次形成设计、原子用例和对抗审查稿；明确严格消息头、TBinaryProtocol 大端编码、待实现负例注入边界和三方同步规则。
