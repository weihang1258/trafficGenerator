# #102 thrift（Apache Thrift Binary Protocol，TBinaryProtocol）设计契约

> 版本：v1.2.0（P-PIPE 文档轨：严格层链 + 负例边界登记）
> 日期：2026-09-30
> 车道：文档阶段（thrift #102，承 `30-thrift-*` 续号）
> 旧基线：`docs/protocol-designs/30-thrift-design.md` v1.0.0（设计稿，2026-08-20）+ `30-thrift-testcase.md` v1.0.0；本版逐条复核旧稿线格式与 RPC 语义，更新为当前实现边界，不声称代码改动。
> 机器契约：`trafficgen/test/protocol_pcap/cases/thrift.json`（18 例 = 7 正 + 11 负；7 条正例与 5 条 planner 负例为层链形，6 条 flat 拒绝负例故意保留旧键以验证门禁）
> 规范基线：① Apache Thrift 官方 TBinaryProtocol 规范（`thrift/doc/specs/thrift-binary-protocol.md`，下称 **spec**）；② 旧基线设计文档（内部契约，非外部规范）；③ 本仓库落码（planner/builder/生成器/接线，§11.1）；④ 本机 tshark 实测（**thrift dissector 存在，43 个 `thrift.*` 字段**，§3.4）；⑤ 公开资料 + 假设（逐处标注，未达验证级 → 缺口）
> 白话一句：**Thrift 是把一次远程调用写成一串大端字节——前面钉死"版本+消息类型+方法名+序号"，后面跟参数；引擎里它是一层薄皮，只管把这串字节按配置排好，握手分段挥手都由 TCP 层干。**

## 0. 30→102 沿革与旧稿过期声明校正（门1 必答：基线继承关系）

本 #102 与旧稿 `30-thrift-*` 是**同一协议的重审契约**，不是新协议。旧稿保留在磁盘只读参考，本契约逐条校正旧稿已过时的状态声明：

| # | 旧稿说法（30-*） | HEAD 实测（2026-09-28） | 校正结论 |
|---|---|---|---|
| 1 | "实现状态：**仅设计阶段**，`trafficgen/internal/protocol/thrift/` 尚未实现；本文和用例不应被解释为已有运行能力"（design 头注 §7） | `internal/protocol/thrift/` 四文件已落码：`builder.go` 256 行、`layer_gen.go` 85 行、`planner.go` 200 行、`thrift_test.go` 1320 行（`wc -l` 实测）；64 个 `Test*` 函数（`grep -c '^func Test'` 实测） | "仅设计阶段/尚未实现"已过时；本契约 §11 为 as-built 逆向定稿 |
| 2 | "需注册 Terminal Thrift，硬依赖 TCP，默认端口 9090"（design §7，语气为待办） | `registry.go:780-784` 已注册 `thrift`（`CategoryTerminal`，`DependsOn ["tcp"]`，`FieldContract {"tcp.dst_port":"9090"}`，Fields 2 键）；生成表 `layers.generated.json` `thrift` 条目同代 | 已注册；"待注册"类说法作废 |
| 3 | "新增 `internal/protocol/thrift/`"（design §7，语气为计划） | 四文件已落码（同 #1）；`main.go:163` 空白导入 + `main.go:513` `NewChainPlanner("thrift")` 已接线 | 已落码 |
| 4 | 旧稿 §4 配置样例全部顶层扁平键（`layers` + `src_ip/dst_ip/dst_port` + 顶层 `thrift`） | 旧 13 条历史用例的顶层键 = `{layers, src_ip, dst_ip, dst_port, count, thrift}`（`src_port` ×12）；层链 `[tcp, thrift]` **两层 config 均空 `{}`** ×13（机读实测） | 旧样例形 = **过渡态违规形**（§1.4/§1.11）；当前 JSON 已按目标形状改写，本契约 §2 样例只给纯层链形 |
| 5 | "默认 TCP 目标端口 9090"（design §4） | registry `FieldContract` 9090 + `planner.go:78-80` `DstPort==0 → 9090`（实测同值） | 继承有效 |
| 6 | 旧稿 §6 E-07（CALL/REPLY method/seqid 不配对）、E-08（缺 STOP/重复 field ID/字段值截断）标注"待实现扩展负例" | `planner.go:16-72` Validate 无 seqid 配对检查、无重复 field ID 检查（grep 实测）；`Plan` 对 `mt==MCall` 无显式响应时**自动补空 REPLY**（`planner.go:131-136`），配对语义由派生规则承接而非校验 | E-07/E-08 **仍是待实现边界**（G-THRIFT-3）；新增自动补 REPLY 派生规则（旧稿未写，§5 补） |
| 7 | 旧稿 §6 只写 `expect_error`+`error_contains` 断言，未给锚词字面值 | `planner.go` 六条拒绝分支锚词已落码，并由当前 JSON 的 5 条 planner 负例逐字对账；6 条 flat 负例验证门禁锚词 | 旧稿"待实现"锚词已定稿；本契约 §7 钉死 |
| 8 | 旧稿 §2/§3 线格式（严格消息头、TType 表、RPC 语义） | 与 `builder.go` 逐项对照一致（§3 三路对照） | **审计通过，继承** |

**依赖链判定纪律**：以上均为可判题（旧文→代码→用例三级对照），直接判定，不问偏好。不可判的（spec 原文条款号级引用）标"待确认"并写清确认方式（§14 缺口）。

**P5 产物验收记录**：`trafficgen/docs/protocol-pcap-test/thrift.md` 是旧 tracked 产物，写有 `Cases: 18 — pass 18, fail 0, error 0`，但早于本轮形状闭环，且 `trafficgen/docs/protocol-pcap-test/thrift/` 目录不存在（**0 个 pcap**）。**该产物不构成当前套件可跑证明，本轮文档阶段未重跑 MCP/pcap/NIC**；真实输出校准登记 G-THRIFT-10，待代码阶段 suite 重跑。

## 1. 范围、profile 与实现状态边界

本版定义 Thrift 客户端与服务端之间的 **TCP 明文连接上的 TBinaryProtocol 消息流**：连接建立后按 `messages[]` 顺序写出完整 message，**消息之间无额外分帧**（消息自带 `version_type` + method 长度前缀 + seqid 头，可自定界）。

| profile | 承载 | 本版允许内容 | 不从 profile 推导 |
|---|---|---|---|
| `thrift_binary_v1`（主） | TCP 明文（fixture 9090，可配置覆盖） | 四类 Message Type、全部 TType、容器嵌套、多消息、多流 | 真实服务端业务语义、IDL requiredness、语言绑定 |
| `thrift_ipv6_v1` | 同上，仅外层 IPv6 | 同主 profile | 从 IPv4 fixture 推导 IPv6 地址 |

显式边界（"不实现、不声称、不许静默转换"）：CompactProtocol（紧凑协议）不在本版；JSONProtocol 不在本版；HTTP/2、TLS、Unix domain socket 不在本版；真实 IDL 编译器与代码生成不在本版；服务注册发现不在本版；跨会话业务相关性不在本版（多会话仅作独立 TCP 流规划，不声称服务端共享状态）；**旧稿未列而落码存在的 `transport` 键与 BINARY 独立类型**见 §8 缺口（G-THRIFT-4/G-THRIFT-5）。

**实现状态（2026-09-28 实测，与旧稿"仅设计阶段"已不同）**：`thrift` 层已注册（`registry.go:780`）、planner/builder/生成器已落码（`internal/protocol/thrift/` 四文件共 1861 行）、`allowedProtocols["thrift"]=true`（`protocols.go:58`）、链规划器已注册（`main.go:513`）、18 条用例已落在 `cases/thrift.json`（7 条正例、6 条 flat 拒绝负例、5 条 planner 拒绝负例）。当前 cases 已完成 JSON 形状审计；真实 MCP/pcap/NIC 执行状态见 §0 与 G-THRIFT-10。旧稿"代码未写"描述已过时（§0 表）。

**输出契约（pcap/NIC 双输出）**：设计契约 = 两路径共用同一 cases JSON 与断言集（`tcp.dstport/srcport`、`tcp.len`、`ipv6.src/dst`、offset 54/74 frames hex），不设仅单路径可用的断言。**现状边界**：本轮只完成三文件静态闭环，未执行 MCP/pcap/NIC；真实输出校准登记 G-THRIFT-10，待代码阶段 suite 重跑。

## 2. 协议栈、端口和固定偏移

推荐层链为 `[ip, tcp, thrift]`（引擎自动补 `ip`；最小链 `[tcp, thrift]`）。thrift 消息是 TCP payload 的**自定界字节流**——段边界不是消息边界：一条 message 可跨多段（超 MSS），多条 message 可各成段；接收端按 TCP 序号重组后按 `version_type` + method 长度自定界。

端口：服务端监听口 **TCP 9090**（spec 常用默认口；registry `FieldContract {"tcp.dst_port":"9090"}` + `planner.go:78-80` 缺省补齐已落码）。fixture 统一 `dst_port=9090`；用例一律显式写端口并纳入断言（§1.4 纪律继承）。

固定偏移：无 VLAN/IP options/TCP options 时，**每帧应用 payload 起点为 IPv4 offset 54（14+20+20）、IPv6 offset 74**（14+40+20）。存量正例均未启用 TCP option/MSS 分段，偏移可直接复算；启用 MSS 分段的实现测试必须以重组 TCP payload 后的 Thrift 字节为裁判。

目标形状 spec_json 样例（严格层链形，顶层仅 `layers` + `flow_control`；translate 已将 thrift 层配置严格解码到 `spec.Thrift`，unknown 字段进入验证错误）：

```json
{
  "layers": [
    {"ip": {"src": "10.0.0.1", "dst": "20.0.0.1"}},
    {"tcp": {"src_port": 12345, "dst_port": 9090}},
    {"thrift": {"messages": [
      {"type": "CALL", "method": "add", "seqid": 1,
       "args": [{"id": 1, "type": "I32", "value": 1}]},
      {"type": "REPLY", "method": "add", "seqid": 1,
       "result": [{"id": 0, "type": "I32", "value": 2}]}
    ]}}
  ],
  "flow_control": {"flows": 1}
}
```

多流样例（数量只走 `flow_control`，四元组留空走 worker 保底递增 §12.12）：

```json
{
  "layers": [
    {"ip": {"src": "10.0.0.1", "dst": "20.0.0.1"}},
    {"tcp": {"dst_port": 9090}},
    {"thrift": {"messages": [
      {"type": "CALL", "method": "ping", "seqid": 1, "args": []},
      {"type": "REPLY", "method": "ping", "seqid": 1, "result": []}
    ]}}
  ],
  "flow_control": {"flows": 2}
}
```

## 3. 线格式编码（逐项标注出处）

> **审计声明（承 30 版）**：本节线格式结论经三路对照审计通过（① spec 原文；② 旧基线 design §2/§3；③ 落码 `builder.go` 逐函数实读），**结论继承不改**。以下重述为契约正文，并补旧稿未写的落码事实。

### 3.1 字节序与标量

所有多字节数值均为 network byte order（网络字节序，即大端）。`BOOL` 线上 1 字节（`false=0x00`/`true=0x01`）；`BYTE` 有符号 8 位补码；`DOUBLE` IEEE-754 binary64 大端；`I16/I32/I64` 有符号 16/32/64 位补码大端。

| TType（类型码） | 数值 | 编码 | 落码锚点 |
|---|---:|---|---|
| `STOP` | `0` | 无值（struct 结束标记） | `builder.go` `TStop` |
| `BOOL` | `2` | 1B（仅 0/1 规范） | `builder.go` `TBool` |
| `BYTE` | `3` | 1B（有符号） | `builder.go` `TByte` |
| `DOUBLE` | `4` | 8B（binary64 大端） | `builder.go` `TDouble` |
| `I16` | `6` | 2B（有符号大端） | `builder.go` `TI16` |
| `I32` | `8` | 4B（有符号大端） | `builder.go` `TI32` |
| `I64` | `10` | 8B（有符号大端） | `builder.go` `TI64` |
| `STRING` | `11` | `i32 length` + bytes | `builder.go` `TString` |
| `STRUCT` | `12` | fields + `STOP` | `builder.go` `TStruct` |
| `MAP` | `13` | key type + value type + i32 count + entries | `builder.go` `TMap` |
| `SET` | `14` | elem type + i32 count + values | `builder.go` `TSet` |
| `LIST` | `15` | elem type + i32 count + values | `builder.go` `TList` |

**BINARY 的落码事实（旧稿未写）**：`typeCode()`（`builder.go:41-67`）把 `"STRING"` 与 `"BINARY"` **同映射到 `TString=11`**——即 BINARY 在线上就是 STRING 编码（i32 长度 + 原始字节，不附加 NUL、不因内容不可打印而改变编码），配置侧以 `value_b64` 注入原始字节（`types.go` `ThriftField.ValueB64 []byte`）。旧稿 §2.1 称"`STRING` 和 `BINARY` 都使用 i32 长度"**与落码一致**，本版明确二者共用同一类型码 11（不是两个类型码）。

### 3.2 严格消息头

本设计只采用 strict write（严格写入）格式。一条 message 的应用 payload：

| 偏移（相对 Thrift payload） | 长度 | 字段 | 值 |
|---:|---:|---|---|
| 0 | 4 | `version_type` | `0x80010000 | message_type`，大端 i32 |
| 4 | 4 + N | `method` | 大端 i32 字符串长度 N，随后 N 个方法名字节 |
| 8 + N | 4 | `seqid` | 大端 i32；请求与对应响应必须相等 |
| 12 + N | 可变 | message body（消息体） | `STRUCT` 字段序列，末尾 `STOP` |

四个 `message_type` 值：`CALL=1`、`REPLY=2`、`EXCEPTION=3`、`ONEWAY=4`（`builder.go` `MCall/MReply/MException/MOneway`）。因此 `add` CALL 的头部开头是 `80 01 00 01 00 00 00 03 61 64 64`；不可把 strict 头误写成旧的 unversioned（无版本）`method + type + seqid` 格式。**消息总长度公式**：`4 + 4 + N + 4 + body_len`，其中 N = method 的 UTF-8 字节长度，body_len = 各字段编码长度之和 + 1（末尾 `STOP`）。

消息体是隐式参数/结果 struct：每个字段为 `type (1B) + field_id (i16 大端) + value`，所有字段后必须写 `STOP (0x00)`（`planner.go:189`）。字段 ID 可为负数（i16），但同一 struct 内不得重复；实际 IDL 生成器通常用正数。字段声明顺序可与 ID 数值顺序不同，读取方按 ID 匹配。

### 3.3 容器与嵌套

- `LIST`：`elem_type (1B) | count (i32) | value[0..count)`。
- `SET`：`elem_type (1B) | count (i32) | value[0..count)`；线缆顺序不是集合语义的一部分。
- `MAP`：`key_type (1B) | value_type (1B) | count (i32) | key,value` 交替。
- `count=0` 合法且仍须出现类型字节和零 count；`count<0` 非法。实现须在乘法/递归前做上限和负值校验。
- `STRUCT` 允许嵌套；每层独立以 `STOP` 结束。未知 field type、未知容器元素 type 或字段值缺失均拒绝，不得猜测长度继续解析。

配置侧容器声明键（`types.go` `ThriftField`）：`elem_type`（LIST/SET 元素类型）、`key_type`/`value_type`（MAP）、`values[]`（LIST/SET 值）、`entries[]`（MAP 键值对）。

### 3.4 tshark 断言通道（本机实测）

**本机 tshark 有 thrift dissector**：`tshark -G fields | awk -F'\t' '$3 ~ /^thrift\./'` = **43 个字段**（含 `thrift.mtype`/`thrift.method`/`thrift.seq_id`/`thrift.type`/`thrift.fid`/`thrift.i32`/`thrift.str_len`/`thrift.binary`/`thrift.exception.message` 等）。**当前 7 条正例只用 frames hex + `tcp.*`/`ipv6.*` 通道**，未使用 `thrift.*` 字段——这是增强候选而非缺口（§14 G-THRIFT-6：dissector 口径需先跑后钉，不许凭字段名臆造）。

| 通道 | 可用性 | 存量用例落点 |
|---|---|---|
| frames `offset/hex` | ✅（偏移 54/74） | 全部 7 正例 |
| `tcp.dstport`/`tcp.srcport`/`tcp.len` | ✅ | S1–S7 |
| `ipv6.src`/`ipv6.dst` | ✅ | S6 |
| `thrift.*`（43 字段） | ✅ 实测存在，**存量未用** | 增强候选 G-THRIFT-6 |

## 4. 业务场景分析（现网典型场景与五层覆盖）

**定性**：**声明式剧本回放**——配置是剧本（`messages[]` 逐条声明类型/方法/参数），引擎按序产出事件，tcp 层按 MSS 分段。

| 现网场景 | 事务交互 | 对应用例 |
|---|---|---|
| ① 同步 RPC 调用 | 客户端 CALL → 服务端 REPLY（同 method/seqid） | S1（`thrift_call_reply`） |
| ② 服务端异常返回 | 客户端 CALL → 服务端 EXCEPTION | S2（`thrift_exception_reply`） |
| ③ 单向通知 | 客户端 ONEWAY，无响应 | S3（`thrift_oneway_call`） |
| ④ 结构化参数 | CALL 携带 LIST/MAP/SET 嵌套参数 | S4（`thrift_containers`） |
| ⑤ 全标量参数 | CALL 覆盖 8 种标量 + BINARY | S5（`thrift_scalar_types`） |
| ⑥ IPv6 内网调用 | 同 ①，仅外层 IPv6 | S6（`thrift_ipv6_echo`） |
| ⑦ 多连接并发 | 多条独立 TCP 连接，各自 seqid 空间 | S7（`thrift_multi_sessions`，flows=2） |

**五层覆盖逐层结论**：功能层——四类 Message Type 各有正例（S1/S2/S3）+ 容器/标量/多消息，负例 6 类覆盖线格式与配置错误；性能层——多消息单连接（S4/S5 各 3 条 message）、多流 2 连接 18 包；数据场景层——TType 表 12 项（含 STOP）、容器三类、标量 8 种、BINARY base64、字段 ID 负值（S4 的 i16 `ff fe`）、非法 type code 99、非法 message type 9、负长度/负 count 注入；地址与流层——v4/v6 独立用例、单流基线、多流两会话、端口显式 9090；**流关联（控制流派生数据流）显式不适用**：Thrift 单 TCP 连接承载全部消息，无副连接；**多流（会话内并发流）显式不适用**：多会话语义由 `flow_control flows` 承载。业务层——RPC 请求响应链（CALL→REPLY/EXCEPTION，S1/S2）。

**次要合法行为显式不适用声明（不设正例、亦不得进负例）**：① 消息间 keep-alive/ping 帧（TBinaryProtocol 无内建保活帧，tcp 层 keepalive 为框架能力，本层零断言）；② 服务端共享状态（本版不声称，S7 只断言四元组与 seqid 隔离）；③ pipeline 响应乱序（本版不承诺，见 §5）；④ RST 异常中断（框架 tcp 层能力，本层零断言，A′ 补例）。

## 5. 消息/事务模型与状态机

**事务定义**：同一 TCP 连接内一组 `CALL/ONEWAY → REPLY/EXCEPTION` 交互。**多事务** = 一连接内多条 message 按序执行（S4/S5 各 3 条）。

thrift 层无自有状态：握手/seq-ack/挥手/分段全在 tcp 层；thrift 层是"按配置顺序把 `messages[]` 翻译成事件"的纯函数驱动（`planner.go:87-143` Plan goroutine）。

| 状态（tcp 层拥有） | thrift 层动作 | 用例 |
|---|---|---|
| `ESTABLISHED`（数据阶段） | `CALL`/`ONEWAY` → `(up, 0x18)` 事件；`REPLY`/`EXCEPTION` → `(down, 0x18)` 事件（端口对换） | S1–S7 |
| 终止（FIN 四包 / RST） | 事件流关闭 → tcp 层挥手；RST 为框架能力 | 全正例 FIN；RST → A′ |

**自动派生规则（落码实读，旧稿未写）**：

1. **无显式响应的 CALL 自动补空 REPLY**（`planner.go:131-136`）：`mt == MCall` 且 `messages[]` 中后续无匹配响应时，自动 emit 一条 `REPLY`（同 method/seqid，body 仅 `STOP`）。匹配判定见 `hasMatchingResponse`（`layer_gen.go:60`）。**这条是引擎的反应性成分**（§5 术语表：自动应答），用例若只写 CALL 会得到 CALL+空 REPLY 两帧。
2. **空配置默认流**（`planner.go:82-84`）：`spec.Thrift == nil`（层链空层 config 或引擎直调）时默认化为单条 `CALL ping seqid=1`。
3. **TCP 握手/FIN 由 tcp 层自动补**：3 包握手 + 4 包 FIN 四包挥手，thrift 层不插入 ACK。
4. **超 MSS 消息自动分段**：由 tcp 层按 mss 切片，不改变应用字节。

**多会话展开**：多会话语义由策略级 `flow_control {"flows": N}` 表达（S7，worker 递增 `src_port` 12345/12346）。单 flow 内多 `messages[]` 是**同连接多事务**（S4/S5），不是多会话。

## 6. 性能设计与验收（CORE_MEMORY §6.1–6.8）

- **目标与边界**：单流全链 ≤9 包（含握手挥手，S1/S4/S5/S6 最大；ONEWAY 8 包）；多消息单连接 3 条 message 为当前最大单流载荷（S4 69B / S5 79B）；多流 2 流 18 包顺序展开。吞吐数字待 P4 基准，**本版不写承诺**（§6.5）。
- **依据**：消息序列流式展开（`Plan` goroutine + chan 32 缓冲；逐条 emit，无全量收集）；每条消息内存 = 编码后字节 + TCP 段开销（O(消息)）；无跨流共享状态；无锁（`Planner` 空结构体，纯函数）。
- **验收两路**：pcap（`/tmp/mcp-pcaps/thrift/`）与 NIC（`enp135s0f0np0`，`nic_capture` 开关）共用同一断言集；断言实际 `tcp.len` 序列与 payload hex，不只断言"任务没报错"。
- **六类场景落点**：基线（S1，9 包）/ 目标规模（S4/S5，多消息单连接）/ 压力上限（超 MSS 单消息分段，**今日零用例** → A′ 立项 §13）/ 长时间运行（S7 多流展开）/ 并发交错（顺序多流承载语义，并发路径为例外不启用）/ 背压（`packet_count` 精确计数守卫段数漂移）。

## 7. 错误处理（负例锚词表，与 testcase §4 一一对应、同序）

以下输入必须由 planner/validator 拒绝并传播为 task error，不得产出成功 PCAP、`completed/0 packet` 或只剩 TCP 外壳的假成功。18 条负例分两组：**flat 拒绝组**带旧顶层键，先被 `CheckProtoFlat` 拦下，锚词统一为门禁文案；**planner 拒绝组**为纯层链，锚词才是本协议的校验文案。

### 7.1 flat 拒绝组（当前 JSON `error_contains` 实际值）

| # | 负例 ID | 故障输入 | `error_contains`（JSON 实际） | 落码锚点 |
|---:|---|---|---|---|
| N-1 | `thrift_neg_truncated` | `wire_fault.kind=truncate` + `at=string_bytes` + 旧扁平键 | `no longer accepts flat config field src_ip` | `CheckProtoFlat`（`strategy_convert.go:8625`）先于协议校验 |
| N-2 | `thrift_neg_unknown_type` | field `type_code=99` + 旧扁平键 | 同上 | 同上 |
| N-3 | `thrift_neg_negative_length` | `wire_fault.kind=negative_length` + 旧扁平键 | 同上 | 同上 |
| N-4 | `thrift_neg_negative_container_count` | `wire_fault.kind=negative_container_count` + 旧扁平键 | 同上 | 同上 |
| N-5 | `thrift_neg_bad_message_type` | `type_code=9` + 旧扁平键 | 同上 | 同上 |
| N-6 | `thrift_neg_bad_port` | `dst_port=70000`（超 uint16）+ 旧扁平键 | `port` | 层字段 schema 范围校验（`registry.go:67` tcp `dst_port` Max 65535 + `complete.go:325`）。**实测文案**（隔离审查）：`layers: layer "tcp" field "dst_port" = 70000 invalid: out of range [0,65535]` ——**含 "port"**，锚词 `port` **仍匹配，迁移后无需重钉** |

N-1–N-5 的协议级锚词（`truncated`/`unknown field type`/…）由下组 planner 负例覆盖；flat 组验证的是更早的迁移门，**不得**据此宣称协议校验已验证。

### 7.2 planner 拒绝组（纯层链，协议锚词）

| # | 负例 ID | 故障输入 | `error_contains` | 落码锚点 |
|---:|---|---|---|---|
| P-1 | `thrift_planner_truncated` | `wire_fault.kind=truncate` + `at=string_bytes` | `truncated` | `planner.go:56` |
| P-2 | `thrift_planner_unknown_type` | field `type_code=99` | `unknown field type` | `planner.go:43` |
| P-3 | `thrift_planner_negative_length` | `wire_fault.kind=negative_length` | `negative length` | `planner.go:58` |
| P-4 | `thrift_planner_negative_container_count` | `wire_fault.kind=negative_container_count` | `negative container count` | `planner.go:60` |
| P-5 | `thrift_planner_bad_message_type` | message `type_code=9` | `invalid message type` | `planner.go:30` |

**负例原子性**：每例单一故障注入；单次执行不得混注。锚词与落码逐字一致（机读核对通过）。

**未落码的负例分支（旧稿 E-07/E-08，仍为待实现边界 G-THRIFT-3）**：CALL/REPLY method 或 seqid 不配对；struct 缺 STOP、重复 field ID、字段值截断。`planner.go` Validate 无对应分支（grep 实测）——**今日不得建例**（建了会真绿 = 假通过），登记缺口。

**不得误报的合法协议事件**：`wire_fault` 缺席的正常配置（全正例）；BINARY 的 `value_b64` 合法值（S5）；`ONEWAY` 无响应（S3，是合法而非"缺响应"）；`EXCEPTION` 的 `exception.type=6`（是异常字段 I32 值，不是 message type，S2 专门防此混淆）。

## 8. 边界

- **消息长与分段**：超 MSS 单消息跨段今日无例 → A′ 补例（§13）。
- **Message Type**：四值 CALL/REPLY/EXCEPTION/ONEWAY 各有正例（S1/S2/S3）；越界值拒绝（N-5）。
- **TType**：12 项全表；标量 8 种正例（S5）；未知类型拒绝（N-2）；容器三类正例（S4）；负长度/负 count 拒绝（N-3/N-4）。
- **`transport` 键（registry 有、落码零消费）**：`registry.go:783` 注册 `transport` 键，`types.go:779` 有 `ThriftConfig.Transport` 字段，但 **planner/builder 全文零引用**（grep 实测）——**死配置**。按 CORE_MEMORY §1.12，零消费字段属"明确不解决"场景，**必须删键**（registry Fields 删 `transport` + struct 删字段 + 重跑 schemagen），**不许"登记保留"** → 缺口 G-THRIFT-4（P4 动作 = 删键，非二选一）。
- **BINARY 独立类型**：配置侧无 `BINARY` 专属类型码，与 `STRING` 共用 11（§3.1）→ 缺口 G-THRIFT-5（P4 裁定：明确共用并写进类型表，或补独立语义）。
- **地址族**：v4/v6 独立用例（S1/S6）；异族混写拒绝（validator 有 IP 分支 `planner.go:65-70`，今日无例 → A′ 补例）。
- **端口**：显式 9090 全正例；缺省 9090（`planner.go:78-80` 补齐）今日无例 → A′ 补例。**越界端口（>65535）**：迁移后由层字段 schema 范围校验拒绝（`registry.go:67` Max 65535 → `complete.go:325`），实测文案 `layers: layer "tcp" field "dst_port" = 70000 invalid: out of range [0,65535]` **含 "port"** → 存量 N-6 锚词 `port` 迁移后**仍匹配**（曾误判为需重钉，已撤销）。
- **seqid 配对**：`REPLY`/`EXCEPTION` 必须复用对应 CALL 的 method/seqid 是**规范要求**，但落码无校验（§7 G-THRIFT-3）。
- 不得产生回绕长度或超量分配（负长度/负 count 显式拒绝，N-3/N-4）。

## 9. 原子 ID 与完成定义（18 个 JSON ID：13 条历史语义 + 5 条 planner 负例）

| # | ID | 类型 | 覆盖 | packet_count |
|---:|---|---|---|---:|
| 1 | `thrift_call_reply` | 正 | §3.2/§5：CALL→REPLY 基线（严格头 + i32 + field id） | 9 |
| 2 | `thrift_exception_reply` | 正 | §3.2/§7：CALL→EXCEPTION（message/type 字段层级防混淆） | 9 |
| 3 | `thrift_oneway_call` | 正 | §5：ONEWAY 无响应 | 8 |
| 4 | `thrift_containers` | 正 | §3.3：LIST/SET/MAP 嵌套 | 9 |
| 5 | `thrift_scalar_types` | 正 | §3.1：8 种标量 + BINARY | 9 |
| 6 | `thrift_ipv6_echo` | 正 | §2：IPv6 载体 | 9 |
| 7 | `thrift_multi_sessions` | 正 | §5：两流展开（flows=2） | 18 |
| 8 | `thrift_neg_truncated` | 负 | §7：N-1 截断 | — |
| 9 | `thrift_neg_unknown_type` | 负 | §7：N-2 未知类型 | — |
| 10 | `thrift_neg_negative_length` | 负 | §7：N-3 负长度 | — |
| 11 | `thrift_neg_negative_container_count` | 负 | §7：N-4 负 count | — |
| 12 | `thrift_neg_bad_message_type` | 负 | §7：N-5 非法 message type | — |
| 13 | `thrift_neg_bad_port` | 负 | §7：N-6 非法端口 | — |

T-编号对照：T-THRIFT-S1…S7 ≡ #1…#7；T-THRIFT-N1…N6 ≡ #8…#13（与旧稿 §8 一一对应）。

完成定义：`tcp→thrift` 层链注册已落码（`registry.go:780`）+ 链规划器已接线（`main.go:513`）；translate 层内分支已落码并完成静态核验，剩余代码阶段工作为 G-THRIFT-2 presence 收口与全量输出校准；本轮仅完成 18 条 JSON ID、正负形状、断言与锚词的静态闭环，不宣称当前二进制全量验证；不声称服务端业务语义。

## 10. P1 规范矩阵（CORE_MEMORY §4 八项：规范要求→业务场景→代码现状→缺口）

### 10.1 八项规范矩阵

| # | 八项 | 规范要求 | 业务场景 | 代码现状 | 缺口 |
|---|---|---|---|---|---|
| 1 | 连接模型 | TCP 长连接，客户端主动建连，消息自定界（spec §Message）；旧 §3.2 | 场景①–⑦ | `DependsOn ["tcp"]` 单值（`registry.go:780`）；多流整块展开（S7） | 无 |
| 2 | 命令/消息表 | 四类 Message Type × 方向 × 响应形态（§10.2，15 格逐格结论）+ 配对维度（§10.3 #28/#29） | 场景①–③ | `planner.go` Validate 全分支 + `builder.go` `msgType` 四值 | 立项 5 格（A′，§13） |
| 3 | 状态机 | 建连—数据—释放 3 态（§5 表；thrift 层无自有状态） | S1/S4/S5 多事务 | tcp 层拥有状态；thrift 纯驱动 | 无 |
| 4 | 字段表 | 消息 5 键 + 字段 8 键 + 容器 4 键（§3.1/§3.3；`types.go:778-827`） | 数据场景层 | builder 逐类型编码 + Validate 类型/方法校验 | `transport` 死键 G-THRIFT-4；BINARY 合流 G-THRIFT-5 |
| 5 | 错误处理 | 6 类负例（§7 表） | 负例 N-1…N-6 | planner 6 种拒绝分支（`planner.go:23-70`） | E-07/E-08 未落码 G-THRIFT-3 |
| 6 | 超时与活性 | TBinaryProtocol 无内建保活/重试语义；tcp 层 keepalive 为框架能力 | — | 协议层无（框架 tcp 层能力） | **明确不解决**（§4 声明），无缺口 |
| 7 | NAT/代理/被动 | 无被动模式概念（客户端主动连服务端） | S7 四元组 | `src_port` 保底递增（`worker.go:308` `DefaultSrcPort+i`，常量 `strategy_convert.go:49`） | **明确不解决**被动模式；NAT 穿透为框架面 |
| 8 | 版本/方言 | strict write 唯一 profile；Compact/JSON Protocol 明确不解决；IPv6 已覆（S6） | 正例 7 | 缺省 9090 已落码（`planner.go:78`） | spec 条款号级引用待补（G-THRIFT-7） |

### 10.2 子表①：Message Type × 响应形态矩阵（逐格已覆/立项/不适用）

| Message Type | T1 正常 FIN 终态 | T2 配置/线格式拒绝 | T3 RST 异常终态 |
|---|---|---|---|
| M1 `CALL`（有显式响应） | 已覆（S1） | 已覆（N-1…N-5 代表例，拒绝与类型无关） | A′ 立项（RST 框架能力） |
| M2 `CALL`（无显式响应→自动补空 REPLY，§5 派生规则①） | 已覆（S7 `ping` 即此形） | 同上代表已覆 | A′ 立项 |
| M3 `REPLY`（成功返回） | 已覆（S1，result id=0） | 同上代表已覆 | A′ 立项 |
| M4 `EXCEPTION` | 已覆（S2，id=1 STRING + id=2 I32） | 同上代表已覆 | A′ 立项 |
| M5 `ONEWAY` | 已覆（S3，无响应） | 同上代表已覆 | A′ 立项 |

**逐格重数**：5 行 × 3 列 = 15 格——已覆 10 / A′ 立项 5，零空格。

**配对维度不在本表**（`CALL`↔`REPLY` 的 method/seqid 配对是跨消息校验，不是 Message Type 形态）：落 §10.3 变体表 #28/#29，今日落码无校验（G-THRIFT-3）。

### 10.3 子表②：数据形态变体表（协议相关全部形态逐项）

共 **29 行**，每行均有正例/负例落点或立项/不适用结论（计数脚本机读：**20 覆 + 9 立项 = 29**）：

| # | 变体 | 落点 |
|---:|---|---|
| 1 | `BOOL` true | 覆（S5 field id=1，帧 hex `02 00 01 01`） |
| 2 | `BOOL` false | A′ 立项（补例 `thrift_bool_false`；落码 `toBool` 支持，今日无例） |
| 3 | `BYTE` 负值（-1） | 覆（S5 field id=2，`03 00 02 ff`） |
| 4 | `DOUBLE`（3.5，大端 `40 0c 00…`） | 覆（S5 field id=3，`04 00 03 40 0c 00 00 00 00 00 00`） |
| 5 | `I16` 负值（-2） | 覆（S5 field id=4 `06 00 04 ff fe`）；容器内 `ff fe` 覆（S4） |
| 6 | `I32` 负值（-3） | 覆（S5 field id=5，`08 00 05 ff ff ff fd`） |
| 7 | `I64` 负值（-4） | 覆（S5 field id=6，`0a 00 06 ff…fc`） |
| 8 | `STRING`（UTF-8） | 覆（S5 field id=7 `0b 00 07 00 00 00 01 78`；S1 method `add`；S6 `hello`） |
| 9 | `BINARY`（`value_b64`） | 覆（S5 field id=8，`0b 00 08 00 00 00 02 00 ff`——与 STRING 同类型码 11，G-THRIFT-5） |
| 10 | `LIST` 非空 | 覆（S4，type=15/elem=6/count=2） |
| 11 | `SET` 非空 | 覆（S4，type=14/elem=11/count=2） |
| 12 | `MAP` 非空 | 覆（S4，type=13/key=11/value=8/count=1） |
| 13 | 容器 `count=0` | A′ 立项（补例 `thrift_empty_containers`；`count=0` 合法且仍须类型字节 + 零 count） |
| 14 | 容器负 `count` | 覆（N-4） |
| 15 | 未知 TType（99） | 覆（N-2） |
| 16 | 负 STRING 长度 | 覆（N-3） |
| 17 | 应用帧截断 | 覆（N-1） |
| 18 | field ID 负值（i16 `ff fe`） | 覆（S4，LIST 元素 -2） |
| 19 | field ID 重复（同 struct 内） | A′ 立项（G-THRIFT-3，落码无校验） |
| 20 | struct 缺 `STOP` | A′ 立项（G-THRIFT-3，落码无校验） |
| 21 | `STOP` 终止符（0x00） | 覆（**S1/S3/S4/S5/S6** body 末字节 `00`：S1 帧 4/5、S3、S4、S5、S6 帧 hex 末字节机读实测；**S2 帧断言为前缀，末字节非 STOP**——帧 4 末字节 `07`=seqid 尾、帧 5 末字节 `10`=STRING 长度，非 body 末字节） |
| 22 | `STRUCT` field type（12） | A′ 立项（`typeCode` 支持 `"STRUCT"`（`builder.go:59`），今日无例；嵌套 struct 未覆盖） |
| 23 | 非法 message type（9） | 覆（N-5） |
| 24 | 非法端口（70000） | 覆（N-6） |
| 25 | 非法 IP 字面（`net.ParseIP` 失败） | A′ 立项（validator 有分支 `planner.go:65-70`，今日无例） |
| 26 | 异族地址混写（v4/v6） | A′ 立项（通用 `validate_layers` same-version 检查有分支，今日无例） |
| 27 | IPv6 载体 | 覆（S6） |
| 28 | `CALL`/`REPLY` seqid 不配对 | A′ 立项（G-THRIFT-3，落码无校验，**今日建例会真绿**） |
| 29 | `CALL`/`REPLY` method 不配对 | A′ 立项（G-THRIFT-3，同上） |

**20 覆 + 9 立项 + 0 不适用 = 29**。✓（计数脚本 `/tmp/pipe/counts.py` 机读复核；行判定逐行可回指。）

### 10.4 子表③：商业行为→用例映射表

| # | 商业行为（出处） | 用例映射 | 结论 |
|---:|---|---|---|
| 1 | 同步 RPC 调用（spec；旧 §3.1） | S1 `thrift_call_reply` | 已覆 |
| 2 | 服务端异常传播（TApplicationException） | S2 `thrift_exception_reply` | 已覆 |
| 3 | 单向通知（oneway 方法） | S3 `thrift_oneway_call` | 已覆 |
| 4 | 结构化参数（IDL struct/list/map/set） | S4 `thrift_containers` | 已覆 |
| 5 | 全标量参数 + 二进制 blob | S5 `thrift_scalar_types` | 已覆 |
| 6 | IPv6 内网部署 | S6 `thrift_ipv6_echo` | 已覆 |
| 7 | 多连接并发（连接池） | S7 `thrift_multi_sessions` | 已覆 |
| 8 | CompactProtocol（生产常见压缩方言） | — | **明确不解决**（v1 范围外） |
| 9 | JSONProtocol / THeader / TCompact 传输层 | — | **明确不解决**（v1 范围外） |
| 10 | 服务端业务语义（方法实现、共享状态） | — | **明确不解决**（本版只做线格式与字节流） |

7 覆 + 3 不适用 = 10。✓无映射无确认即缺口——本表零缺口。

### 10.5 三路对照与候选方案对比（§4.12–4.15 / §4.17）

三路：①规范原文（Apache Thrift TBinaryProtocol spec，定"必须是什么"：strict write 头、TType 表、大端）；②商业化软件实际行为（Thrift 各语言官方库生成的 client/server：严格头 + 按 ID 匹配字段；旧 §3.2 divergence 声明本版不承诺 pipeline 乱序）；③可靠开源实现思路（本仓库同族先例：tns/drda/mongodb 的"TCP 终结层 + 事件流 + 层内配置"）。三路一致点：strict write 头 + TType 大端编码 + 消息自定界；不一致点 = 无（本协议线格式由 spec 单源钉死，无厂商方言分歧）。

| 方案 | 走法（借鉴来源） | 取舍 | 结论 |
|---|---|---|---|
| A | 独立 `thrift` 终结层（本版；tns/drda 同构先例） | 消息类型/字段/容器/错误面可声明可断言；代价 = 一套薄层（已落码 1861 行） | **采用** |
| B | 直接 tcp 层 + 顶层 payload 字节 | 无消息结构、无类型校验 → S1–S7 与 6 条负例不可表达 | **否决** |
| C | 与 tns/drda 合并为"RPC 族" | thrift 头格式（strict version_type）与 TNS 包头（包长+类型）、DRDA（DSS）互不兼容——文法不兼容，合并即错 | **否决** |

## 11. P2 D-THRIFT-1 代码设计（CORE_MEMORY §8 八要素；门1 获批 = 定稿）

> 状态说明：实现已落码（`internal/protocol/thrift/` 四文件），本 P2 条目为 P-PIPE 文档轨对既有实现的**逆向定稿**（as-built 定稿），供门1 批准后作为后续改动的唯一入口；P4 在本协议内为"缺口收敛"（§14），不另开新层。

### 11.1 文件清单（实测，非计划）

| 文件 | 职责 | 行数 |
|---|---|---:|
| `trafficgen/internal/core/types.go`（§777-831 + `:1716`） | `ThriftConfig`/`ThriftMessage`/`ThriftField`/`ThriftMapEntry`/`ThriftWireFault`/`ThriftException` 配置类型 + `FlowSpec.Thrift` 槽位 | —（共享文件） |
| `trafficgen/internal/protocol/thrift/planner.go` | `Planner.Validate`（6 种拒绝）+ `Plan`（握手→消息→自动补 REPLY→挥手） | 200 |
| `trafficgen/internal/protocol/thrift/builder.go` | 类型码表 + 消息/字段/值编码（纯函数） | 256 |
| `trafficgen/internal/protocol/thrift/layer_gen.go` | 终结层生成器（`RegisterLayerGenerator("thrift")` + `RegisterLayerValidator`，`init()`） | 85 |
| `trafficgen/internal/protocol/thrift/thrift_test.go` | 64 个 `Test*`（Validate 拒绝面 + 编码面 + 生成器面） | 1320 |
| 接线 5 件 | registry 注册（`layers/registry.go:780`）/ translate Meta 直传（`chain_planner_translate.go:122`）/ convert flat 兼容（`strategy_convert.go:1747`）/ protocols 准入（`protocols.go:58`）/ main.go 空白导入 + `NewChainPlanner("thrift")`（`:163`/`:513`） | — |

### 11.2 接口签名

- `Validate(spec core.FlowSpec) error`（`planner.go:16`）：`Thrift==nil` 通过（空配置默认流）；`Messages` 空、`TypeCode` 越界（1..4）、`Type` 非四值、`Method` 空、字段 `TypeCode` 非 TType 表、`WireFault` 三 kind 及未知 kind、IP 非法各归一分支，错误文案与 §7 锚词逐字一致。
- `Plan(ctx, spec) (<-chan core.PacketConfig, error)`（`planner.go:74`）：先 Validate；`DstPort==0` 补 9090；`cfg==nil` 补默认 `CALL ping`；emit 握手 3 包 → 逐消息编码（`buildMessage` + `buildMessageBody`）→ 无响应 CALL 自动补空 REPLY → FIN 四包。
- 生成器：`Name() "thrift"`；`GenEvents()` 返回自身；`EmitEvent` 未接线显式错（防误调，`layer_gen.go:15-17`）；`Generate` 逐消息 emit（`layer_gen.go:19`）。

### 11.3 数据结构

`ThriftConfig{Transport string, Messages []ThriftMessage, WireFault *ThriftWireFault}`；`ThriftMessage{Type, Method, SeqID, Args[], Result[], Exception, TypeCode}`；`ThriftField{ID, Type, Value, TypeCode, ElemType, KeyType, ValueType, Values[], Entries[], ValueB64}`；`ThriftException{Message, Type}`（`types.go:777-831` 全量，无新增）。

### 11.4 主流程

配置 → validator（消息级 5 分支 + wire_fault 4 分支 + IP 2 分支）→ planner（消息编码为事件，自动补 REPLY）→ worker（TCP 分段：默认每条消息一段，>MSS 自动分段；多流按 `flows` 复制四元组递增）→ writer（PCAP/NIC）。

### 11.5 错误分支

6 种 validator 拒绝各对应 planner/生成器双层守卫（§7 表）；全部传 task error（零假成功——N 系列守卫）。`transport` 键**不拒绝亦不生效**（G-THRIFT-4：用例不得携带）。

### 11.6 性能边界

见 §6（逐消息流式、per-flow 局部状态、无跨流共享、无锁；吞吐数字待 P4 基准）。

### 11.7 与现有逻辑的冲突点

- **translate 层内已具备 thrift 分支**：`translateTerminalConfig` 的 `switch term.Name` 在 `chain_planner_translate.go:964` 处理 `thrift`，经 `completedConfig` 补全 registry 字段后，以 `DisallowUnknownFields` 解码为 `core.ThriftConfig`，成功后赋值 `spec.Thrift`（`:967–981`）；编码/解码错误均进入 `spec.ValidationErrors`。因此层内 `thrift.messages` 不会静默丢弃，G-THRIFT-1 已关闭，严格层链可以进入实际规划路径。
- **`CheckProtoFlat`（`strategy_convert.go:8625`）无 thrift 分支**：顶层 `thrift` 子映射 presence **不判死**（grep 实测）——与 D-MOXA-1 等已登记协议不同，属缺口 G-THRIFT-2（**禁加单协议黑名单分支**，等框架级 unknown-key 白名单；kingbase 记忆裁定）。
- **`ValidateStrategy` 无条件调用 `CheckProtoFlat`**（`schema/semantic.go:130`，无 layers 短路）：存量 13 例的顶层 `src_ip/dst_ip/src_port/dst_port/count` **在策略创建即 400**——存量用例今日**不可经 MCP 跑通**（§12.1 实证链）。
- **`case "thrift"`（`strategy_convert.go:1747`）是 flat 遗留路径**：读顶层 `cfg["thrift"]`（无"配置住 thrift 层"注记，与 tns/mongodb/drda 的已收敛形不同）→ 层链化后此支仅守 out-of-band 配置（引擎直调）。
- 动态 allowlist（`internal/core/layer_dyn.go` 头部）：`thrift` 零命中实测 → 业务字段动态对象即拒；四元组 `ip`/`tcp` 全开。见 §12.12。
- `transport` 键注册但零消费（G-THRIFT-4）；BINARY 与 STRING 共用类型码 11（G-THRIFT-5）。

### 11.8 回滚方式

本协议文件独立成包，回滚 = revert 本协议 4 文件 + 接线 5 处（registry/protocols/translate/convert/main.go）；不触及其他协议。cases 回滚 = 恢复 13 例 JSON（产物文件，非文档）。

## 12. 门1 §1–§14 十四行对照表（CORE_MEMORY §15.1–15.3）

| § | 本协议怎么满足 | 证据 |
|---|---|---|
| §1 层链唯一真相 | 见 §12.1：7 条正例非负例顶层旧键 **0**；6 条 flat 负例故意保留 dirty 键；5 条 planner 负例纯层链；translate 消费已由 `case "thrift"` 覆盖；仅 G-THRIFT-2 仍待框架级 presence 判死 | §12.1；`cases/thrift.json` 机读审计 |
| §2 策略/任务 | 策略 = 单 thrift 流量模板，自带 `flow_control`；任务 = 多策略合跑 + 总量封顶；框架语义未动 | 设计 §2 样例 |
| §3 五件套 | 见 §12.3 强制展开：会话表/事务序列/关联（无派生流诚实声明）/插入位置（终结层）/时间线。有长连接，不豁免 | §12.3 + §5 |
| §4 查规范 | TBinaryProtocol spec + 旧基线 + tshark 43 字段实测 + 落码反推；八项矩阵 + 子表①②③ | §10 |
| §5 依赖与错误 | `DependsOn ["tcp"]` 单值（`registry.go:780`）；6 种拒绝分支；失败传 task error | §5/§7/§11.5 |
| §6 性能 | 见 §6（6.1–6.8 要素齐；吞吐数字标待 P4 基准，不写承诺） | §6 |
| §7 三份文档 | `docs/protocols/thrift/{design,testcase}.md` + D-THRIFT-1（本文 §11）+ JSON 18 ID；旧稿 30-* 为历史层 | 修订记录 |
| §8 设计先行 | P1–P3 先于 P4 缺口收敛；门1 获批 = D-THRIFT-1 定稿 = 开工门 | 提交序 |
| §9 测试三源 | 三源 = TBinaryProtocol spec（§10）+ D-THRIFT-1（§11）+ tshark 通道实测（43 字段存在但当前正例未用，§3.4 诚实标注）；18 ID 逐项回指；13 条历史 ID 与 5 条 planner 负例对账 | `testcase.md` §2/§5/§8 |
| §10 评审闭环 | 每阶段对抗自重审（结论见 /tmp/pipe/doc-lanes/thrift.md）+ 收官隔离复审；红先绿后 | 自审报告 |
| §11 白话 | 每阶段白话一句先行（见本文首节） | 汇报 |
| §12 动态清单 | 见 §12.12 强制展开：四元组全开（allowlist 实测）；业务字段逐个列开/不开 + 理由；序号算法实读行号 | §12.12 |
| §13 schema 派生 | `thrift` 已在 `registry.go:780` 注册（**不新增层**）；`allowedProtocols["thrift"]=true`（`protocols.go:58`）；Meta 已直传；**translate 分支已落码且不动 registry Fields，无需重跑 schemagen**（若改 Fields 则必须重跑） | §11.1 |
| §14 真实流程 | suite 经 MCP 建策略建任务 → 引擎真实生成 → tshark `tcp.*`/`ipv6.*` + frames 双通道 → 先跑后钉；pcap 落 `/tmp/mcp-pcaps/thrift/` | testcase §7 |

### 12.1 §1 强制展开：旧键去向 + 完整 spec_json 样例

**存量实测（逐例机读，2026-09-28）**：

| 文件 | 例数 | 顶层键分布 | 链形 | 负例 expect 纯净 |
|---|---|---|---|---|
| `cases/thrift.json` | 18 | 7 正例为 `[ip,tcp,thrift]`；6 flat 负例保留旧键；5 planner 负例为 `[tcp,thrift]` | 正例层内配置已填；flat 负例故意保留 dirty 键；planner 负例业务配置在 thrift 层 | ✅ 11/11 负例只有 `{expect_error,error_contains}` |

**合规判据与残留计数（按顶层白名单 `{layers, strategy_fc, ttl, flow_control, output, output_config, group_id}` 机读）**：

- **非负例顶层旧键 = 0**：7 条正例均只使用 `layers`（S7 另有 `strategy_fc`）；地址、端口、业务配置均已在对应层内。
- 6 条 flat 负例仍故意保留旧键，作为 `CheckProtoFlat` 拒绝输入；5 条 planner 负例为纯层链，故障配置在 `thrift` 层。
- **结论：正例形状已完成静态迁移审计**；真实策略创建、任务运行与输出校准仍留待代码阶段，不在本轮宣称。

**旧键去向表（13 条历史 ID 的迁移对照；当前 JSON 已按目标形状落位）**：

| 旧键 | 存量出现例数 | 去向 |
|---|---:|---|
| `src_ip` | **13** | 已迁入 `layers[i].ip.src` |
| `dst_ip` | **13** | 已迁入 `layers[i].ip.dst` |
| `src_port` | **12** | 已迁入 `layers[i].tcp.src_port`；S7 保留递增策略 |
| `dst_port` | **13** | 已迁入 `layers[i].tcp.dst_port`；负例 70000 保留在 tcp 层触发校验 |
| `count` | **13** | S7 由 `strategy_fc` 表达；其余单流不再携带顶层 count |
| 顶层 `thrift` 子映射 | **13** | 已迁入 `layers[i].thrift` |
| `layers[].tcp` 空壳 | **13** | 正例已填端口；planner 负例按故障阶段保留端口配置 |
| `layers[].thrift` 空壳 | **13** | 正例与 planner 负例已填业务配置 |

**结论**：本协议的静态迁移审计已完成：①translate 层内分支已存在并经静态核验，层内 `thrift.messages` 不会静默丢弃；②当前 JSON 7 条正例非负例顶层旧键已为 0；③新增 5 条 planner 负例均为纯层链；④6 条 flat 负例保留 dirty 键用于门禁拒绝。真实策略执行仍留待代码阶段。

目标形状样例见 §2（顶层仅 `layers`+`flow_control`）。

### 12-P2 判死负例形状（链级红例必含清单①③④）

- ① presence 形状 `{"layers":[…],"thrift":{}}` 今日**不会被拒**（`CheckProtoFlat` 无 thrift 分支，grep 实测）→ **P4 不建该负例**（建了会真绿 = 假通过）→ 缺口 G-THRIFT-2 登记。② 白名单外游离键判死（`unknown field`）P4 建一条（A′）。③ 6 负例每条带锚词（已齐，§7）。④ 收官自查「非负例顶层键 = 0」（P4 迁移后执行）。

### 12.3 §3 强制展开：五件套

会话表：`s1` 单连接基线（S1/S2/S3/S4/S5/S6，各自四元组，SYN→消息→FIN 四包挥手）/ `s2` 多流两会话（S7，`flows=2`，`src_port` 12345/12346）。事务：`t1` 建连（握手，tcp 层）/ `t2` 发 CALL/ONEWAY（up 事件）/ `t3` 收 REPLY/EXCEPTION（down 事件，端口对换）/ `t4` 自动补空 REPLY（§5 派生规则①）/ `t5` 终止（FIN；RST 为 A′）；每事务四件事（前置/触发/成功/失败）见 §5 状态机 + §4 场景表。关联关系：**无派生流**（诚实声明：单 TCP 连接承载全部消息，无 `driven_by`）。插入位置：终结层（`[ip,tcp,thrift]`，无中间层）。时间线：消息内严格顺序 / 多流顺序展开（S7 整块 per-flow，跨流不假设全局包序，只断言聚合）/ 无交错（`concurrent` 为例外路径不启用）。

### 12.12 §12 强制展开：动态字段清单与序号算法

四元组 `ip.src/dst`、`tcp.src_port/dst_port` 五策略全开（allowlist `internal/core/layer_dyn.go:18-21` 实测：`ip`/`tcp`/`udp`/`eth`；保底 `DefaultSrcPort+i`（`worker.go:308`，常量 `strategy_convert.go:49`）；dst 动态与 9090 缺省和平共处——显式/动态值非零即不触发补齐）。

**业务字段全关**（allowlist 无 `thrift` 行，grep 零命中实测；对象即拒）：`messages[]`（消息剧本）/ `type`·`method`·`seqid`（消息头字段）/ `args[]`·`result[]`·`exception`（载荷结构）/ `field.id`·`type`·`value`·`value_b64`（字段值）/ `wire_fault`（负例注入口）/ `transport`（死键）——逐流变体需求列 A′ 候选（testcase §6.2；今日按 §9.36 口径不冒充覆盖）。

序号算法实读：`parseLayerDyn`（`layer_dyn.go:78`）/ `TupleGenerator.Next`（`tuple_generator.go`）/ 保底自增（`worker.go:308` + 常量 `strategy_convert.go:49`）/ allowlist 白名单（`layer_dyn.go:18-21`）——**`thrift` 无块**（grep 实测零命中），即层内任何对象值 → `does not support dynamic`。

## 13. P3 对接清单（T-THRIFT 草稿输入；正文落 testcase 文件）

18 条 JSON ID（13 条历史语义 + 5 条 planner 负例）+ packet_count/锚词 + fixture 常量 + 双通道断言基线 + 逐条形状审计。A′ 候选 9 例：`thrift_bool_false`（变体 2）/ `thrift_empty_containers`（变体 13）/ `thrift_multi_messages`（同连接多事务）/ `thrift_oversize_segment`（超 MSS 单消息分段）/ `thrift_default_port`（删键断言补齐 9090）/ `thrift_neg_mixed_family`（变体 #25+#26）/ `thrift_neg_duplicate_field_id` + `thrift_neg_missing_stop`（G-THRIFT-3 落码后）/ `thrift_abort_rst`（RST 框架能力）。

## 14. 缺口立项清单（有缺口写「缺口立项」，不许空着）

| 缺口 | 内容 | 去向 |
|---|---|---|
| G-THRIFT-1 | ~~translate thrift 层内分支缺失~~ **已关闭**：`chain_planner_translate.go:964–981` 已将层内配置严格解码并赋值 `spec.Thrift` | 无后续动作；保留静态证据，真实输出仍受 G-THRIFT-10 约束 |
| G-THRIFT-2 | `CheckProtoFlat` 无 thrift 分支 → presence 形今日不判死 | P4 先实测再建例；**禁加单协议黑名单分支**（等框架级 unknown-key 白名单） |
| G-THRIFT-3 | E-07（CALL/REPLY method·seqid 不配对）、E-08（struct 缺 STOP、重复 field ID、字段值截断）落码无校验 | A′ 补例（先写失败测试，再补 Validate 分支）；**今日不建例** |
| G-THRIFT-4 | `transport` 键 registry 有、`types.go:779` 有字段、planner/builder 零消费（死配置） | P4 **删键**（registry Fields 删 `transport` + struct 删字段 + 重跑 schemagen）；CORE_MEMORY §1.12 不许登记保留 |
| G-THRIFT-5 | BINARY 与 STRING 共用类型码 11（`builder.go:57`），配置侧无独立 BINARY 语义 | P4 裁定：明确共用写进类型表（本版 §3.1 已声明）或补独立语义 |
| G-THRIFT-6 | 本机 tshark 有 43 个 `thrift.*` 字段，存量用例零使用 | A′ 增强候选：先跑后钉 dissector 口径（`thrift.mtype`/`thrift.method`/`thrift.seq_id`），不许凭字段名臆造 |
| G-THRIFT-7 | spec 条款号级引用缺失（本文引"spec"未到章节号） | 待确认：取 Apache Thrift 仓库 `doc/specs/thrift-binary-protocol.md` 原文核章节；确认前标注未达验证级 |
| G-THRIFT-8 | 业务字段动态全关（allowlist 无 `thrift` 行） | A′ 候选，不冒充已覆盖（§9.36 口径） |
| G-THRIFT-9 | ~~存量 N-6 锚词迁移后不匹配~~ **已撤销（假缺口）**：实测文案 `layer "tcp" field "dst_port" = 70000 invalid: out of range [0,65535]` **含 "port"**，锚词仍匹配 | 无需动作（隔离审查 F1 纠错） |
| G-THRIFT-10 | 旧结果文档不可作本轮证据：虽写有 18/18，但早于当前形状闭环且无 pcap 目录；本轮未重跑 | 代码阶段执行 18 例 suite，重新生成并核对结果文档与 pcap/NIC 证据 |

## D1–D8 层链迁移契约（文档阶段，2026-09-30）

| ID | 结论 | 证据/缺口 |
|---|---|---|
| D1 | 范围仍为 TCP 明文 TBinaryProtocol；strict header、四种 message type、TType/容器边界沿旧稿复核 | 本文 §1–§3；Apache TBinaryProtocol spec；旧稿 §2–§3 |
| D2 | 目标配置唯一采用 `[ip,tcp,thrift]`；地址在 `ip`，端口在 `tcp`，消息在 `thrift`，数量在 `flow_control` | 本文 §2、§12.1；cases 正例 7/7 严格层链；仅 G-THRIFT-2 仍需代码阶段闭环 |
| D3 | 层链迁移不得改变消息字节、packet_count、端口与 IPv6 offset 断言；6 条 flat 负例保留为故意拒绝输入 | testcase §2–§4；cases 18 条逐条审计 |
| D4 | 现有 6 类错误锚词继续登记：truncated、unknown field type、negative length、negative container count、invalid message type、port；未落码 E-07/E-08 不建假红例 | 本文 §7；planner.go 现状；G-THRIFT-3 |
| D5 | 动态只声明 `ip`/`tcp` 四元组支持；Thrift 业务字段动态无 allowlist，列为缺口，不冒充覆盖 | 本文 §12.12；G-THRIFT-8 |
| D6 | pcap/NIC 使用同一 cases 与断言集；当前文档阶段不宣称本轮 MCP/pcap/NIC 已执行 | 本文 §6；G-THRIFT-10 |
| D7 | 依赖链为 `ip → tcp → thrift`；协议层不拥有握手、挥手、RST、保活或重试状态 | 本文 §2、§5；registry/planner 现状 |
| D8 | 代码阶段需先补框架级 flat presence 判死，再全量跑 18 例并校准断言；translate 层分支已具备；回滚仅涉及 thrift 接线与 cases | 本文 §11.7–§11.8、§14；G-THRIFT-1/2 |

## T1–T6 / C1–C6 静态闭环（2026-10-01）

| ID | 静态检查 | 结论 |
|---|---|---|
| T1 | JSON 可解析；18 个 ID 唯一 | 通过；7 正例 + 11 负例 |
| T2 | 7 正例、5 planner 负例为严格层链；6 flat 负例保留旧键 | 通过；承载形状与拒绝阶段有意分开 |
| T3 | 地址、端口、业务配置分别归属 `ip`、`tcp`、`thrift` 层 | 通过；S7 数量仅由 `strategy_fc` 表达 |
| T4 | 正例包数/端口/IPv6 偏移/帧锚点与 JSON 对账 | 通过；负例不含成功包断言 |
| T5 | 负例 `expect` 恰为 `expect_error` + `error_contains` 两个判定键，锚词逐条与 §7 对账 | 通过；flat 六条命中门禁锚词，planner 五条命中协议锚词 |
| T6 | 本轮只做静态闭环，不宣称 suite、MCP、pcap 或 NIC 执行 | 通过；真实输出校准保留在 G-THRIFT-10 |

**13→18 对账**：历史 13 个 ID 为 S1–S7、N1–N6（全部保留并逐条改写）；当前机器契约另有 P1–P5 五个纯层链 planner 负例，分别复用 N1–N5 的故障语义但改变拒绝阶段。因此不是重复 ID，也不是删例：13 个历史语义 + 5 个新增 planner 形状 = JSON 实际 18 条。

**负例双键与锚词对账**：18 条中 11 条负例的 `expect` 均严格只有 `expect_error`、`error_contains`；N1–N5 flat 入口统一锚定 `no longer accepts flat config field src_ip`，N6 锚定 `port`，P1–P5 依次锚定 `truncated`、`unknown field type`、`negative length`、`negative container count`、`invalid message type`。说明性 `notes` 只在 case 顶层，不参与判定。

## C1–C6 文档审查结论（本轮不改代码）

| ID | 结论 |
|---|---|
| C1 | 三文件 JSON/文档 ID 集合与顺序一致；cases 当前 18 条（7 正、11 负）。 |
| C2 | 7 条正例和 5 条 planner 负例为严格层链；6 条 flat 负例故意保留 dirty 键，专用于旧格式拒绝验证。 |
| C3 | 正例顶层仅 `layers`（S7 另有兄弟 `strategy_fc`）；地址/端口/协议业务分别归属 `ip`/`tcp`/`thrift` 层。 |
| C4 | 11 条负例 `expect` 判定键均为 `expect_error`、`error_contains`；不以成功包结构冒充负例断言。 |
| C5 | CALL/REPLY、EXCEPTION、ONEWAY、容器、标量、IPv6、多流及六类错误锚点均有对应 ID；动态业务字段、E-07/E-08、NIC 复验保持缺口。 |
| C6 | 本轮仅改 thrift design/testcase/cases；不改 Go、全局索引、旧稿或其他协议；当前只完成文档与机器契约形状审计。 |

## 迁移后缺口与完成边界

- G-THRIFT-1：已关闭；`chain_planner_translate.go:964–981` 已确认消费 `thrift` 层配置。当前 JSON 的 7 条正例已完成静态层链形状审计，非负例顶层旧键为 0。
- G-THRIFT-2：顶层 `thrift` presence 判死应由框架级 unknown-key 白名单完成；不添加单协议黑名单补丁。
- G-THRIFT-3：CALL/REPLY 配对、重复 field ID、缺 STOP 等未落码分支先写失败测试再实现；本轮不新增假负例。
- G-THRIFT-4：`transport` 为零消费死键，代码阶段按 §1.12 删除并重生成 schema；cases 不携带。
- G-THRIFT-5/6/7/8/10：BINARY 合流、tshark thrift 字段、规范条款号、业务动态与 suite/NIC 实跑分别保留现有缺口登记。


- v1.0.0（2026-09-28）：P-PIPE #102 文档轨 P1–P3。承 30 版续号：30→102 沿革与 8 项过期校正（§0）；线格式三路对照审计通过（§3，结论继承）；存量 13 例机读审计（**非符合态实证**：层链空壳 + **非负例顶层键 41 处残留**，按顶层白名单判据）；§12.1/12.3/12.12 强制展开 + 12-P2；D-THRIFT-1 as-built 定稿（§11）；缺口 G-THRIFT-1…G-THRIFT-8。自审 6 轮（第 5 轮按主线程口径纠错；**第 6 轮按隔离审查打回修 5 项**：F3 定性改"静默假成功"、F1 撤销假缺口 G-THRIFT-9、F2 修正 Thrift 引用计数、F4/F5 修对账与矩阵计数、transport 死键改判直接删、nic_capture 诚实标注），末轮干净（结论见 `/tmp/pipe/doc-lanes/thrift.md`）。
- v1.0.1（2026-09-28）：补登记**结果文档过期**（**G-THRIFT-10**，车道间一致性缺口，照 pcep G-PCEP-11 先例）：§0 新增产物过期登记段、§14 缺口表新增 G-THRIFT-10 行。**只改本文 + testcase 文档，不动代码/JSON。**
