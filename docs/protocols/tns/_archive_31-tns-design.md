# TNS（Oracle Net/SQL*Net，Oracle 网络服务）协议设计与测试契约

> 版本：v1.0.0（设计阶段）  
> 日期：2026-08-20  
> 范围：TNS（Transparent Network Substrate，透明网络底层）在 TCP/IP 上的包头、连接控制包和基础数据会话；覆盖 CONNECT、ACCEPT、REFUSE、REDIRECT、DATA、TTC（Two-Task Common，两任务公共层）/SQL*Net 数据事件、IPv4/IPv6 和多会话。  
> 配套：`docs/protocol-designs/31-tns-testcase.md`、`trafficgen/test/protocol_pcap/cases/tns.json`、`docs/protocol-designs/audit/31-tns-adversarial-audit.md`  
> 实现状态：**仅设计阶段；当前未声称 `tns` 层已注册或 pcap（数据包捕获文件）已通过。**

## 1. 目标、范围与证据等级

Oracle Net 的公开、稳定外层是每个 TNS 包的 8 字节包头。CONNECT、ACCEPT、REFUSE、REDIRECT 的连接数据以及 DATA 内的 TTC/SQL*Net 内容受 Oracle 版本、协商能力和数据库配置影响；本稿不凭空指定其未核实的内部字节。

本设计把字段分为两级：

| 级别 | 内容 | 文档/用例处理 |
|---|---|---|
| 规范锚点 | 包长度、包校验和、类型、保留字节、头校验和；DATA 的 2 字节 data flags（数据标志） | 固定大端布局，并在 JSON 中用 offset（偏移）/字段断言观察 |
| 实现契约 | 事件顺序、端口、TCP/IP 载体、`payload_profile`（负载语义档案）、包数 | 供未来 planner（规划器）实现，包体字节不冒充 Oracle 版本事实 |

v1 覆盖：

- TCP 载体，服务器端口默认 1521，可显式覆盖；
- 单连接中的 CONNECT→ACCEPT/REFUSE/REDIRECT 和 DATA 往返；
- DATA 的基础 `data_flags=0x0000`，以及 TTC/SQL*Net 事件的顺序可观察性；
- IPv4、IPv6、多个独立 TCP 会话；
- 包头长度/校验和/类型/保留字段/头校验和的边界校验和负例。

v1 不声称实现：Oracle 原生认证、NTS 加密、Native Network Encryption、完整 CONNECT/ACCEPT 参数协商、TTC 数据字典、SQL 语句解析、TNS 分片/重组、压缩、Data flag 非零位语义、TNS over TLS、服务端 listener（监听器）行为。

### 1.1 关键不变量

1. TNS 只能叠在 TCP 上；默认目的端口为 1521，不能以 UDP 作为等价载体。
2. TNS 包头固定 8 字节，所有 16 位数值按 network byte order（网络字节序，即大端）编码。
3. `length` 是整个 TNS 包长度（包头加包体），最小为 8，不能截断或 16 位溢出。
4. 包类型是包头偏移 4 的 1 字节；CONNECT/ACCEPT/REFUSE/REDIRECT/DATA 的类型值分别为 `0x01/0x02/0x04/0x05/0x06`。
5. `packet_checksum` 和 `header_checksum` 为 0 时表示本设计的 checksum disabled（校验和禁用）确定性基线；非零校验算法和协商规则是待实现边界，不能在 v1 cases 中编造。
6. DATA 包的包体前 2 字节是 data flags；`0x0000` 作为基础数据事件的唯一固定值。非零位不在当前实现契约内。
7. TCP 三次握手、应用数据段和四次正常终止由公共 TCP 层负责；包数计算不把 TNS 头误算成 TCP 包。
8. 每个 session（会话）拥有独立的 4-tuple（四元组）和事件状态；不能把不同流的 ACCEPT、DATA 或序号交叉配对。

## 2. TNS 包头

### 2.1 8 字节公共头

偏移相对 TCP payload（TCP 负载）起点；IPv4、无 TCP option（选项）时以太网帧绝对偏移为 54，IPv6 为 74。

| 偏移 | 大小 | 字段 | 规范语义 | v1 约束 |
|---:|---:|---|---|---|
| 0 | 2 | `length` | 包头与包体的总长度 | `8..65535`，大端；必须等于实际包字节数 |
| 2 | 2 | `packet_checksum` | 包校验和 | `0x0000` 为确定性禁用基线；非零待实现 |
| 4 | 1 | `type` | 包类型 | 见 §2.2 |
| 5 | 1 | `reserved` | 保留字节 | v1 必须为 `0x00` |
| 6 | 2 | `header_checksum` | 包头校验和 | `0x0000` 为确定性禁用基线；非零待实现 |

长度计算只使用编码后的字节数。实现必须先检查 `8 <= length <= 65535`，再写入 U16（无符号 16 位）；不能把过长 payload 静默截短。

### 2.2 包类型表

| 数值 | 名称 | 方向/用途 | v1 状态 |
|---:|---|---|---|
| `0x01` | CONNECT | 客户端建立 TNS 连接并携带连接数据 | 头部确定；内部连接数据由 profile 负责 |
| `0x02` | ACCEPT | 服务端接受连接并返回协商数据 | 头部确定；内部协商由 profile 负责 |
| `0x03` | ACK | 确认/控制 | 不在 v1 event 中生成，保留扩展 |
| `0x04` | REFUSE | 服务端拒绝连接 | 头部确定；拒绝原因内部字段不在 v1 固定 |
| `0x05` | REDIRECT | 服务端要求客户端改连另一地址 | 头部确定；重定向地址编码不在 v1 固定 |
| `0x06` | DATA | TTC/SQL*Net 数据 | 头部和 flags 确定；TTC 字节待实现 |
| `0x07` | NULL | 空控制包 | 不在 v1 event 中生成 |
| `0x09` | ABORT | 异常中止 | 不在 v1 event 中生成 |
| `0x0b` | RESEND | 重发请求 | 不在 v1 event 中生成 |
| `0x0c` | MARKER | 标记包 | 不在 v1 event 中生成 |
| `0x0d` | ATTENTION | 注意事件 | 不在 v1 event 中生成 |
| `0x0e` | CONTROL | 控制包 | 不在 v1 event 中生成 |

“头部确定”不等于声称空包体是合法 Oracle listener 报文；future builder（未来构造器）必须依据 `payload_profile` 生成对应版本的包体，并重新计算 `length`。当前 JSON 的 frame（帧）断言只钉住不依赖包体版本的头部字节。

### 2.3 DATA 包的 flags

DATA 的 TCP payload 结构为：

```text
TNS header (8B) | data_flags (2B, big-endian) | TTC/SQL*Net bytes (N)
```

`data_flags=0x0000` 是基础、无附加标志的数据事件；本稿不把任何未核实的非零 bit 解释成 EOF、SENDMORE 或其他 Oracle 私有语义。若实现支持非零 flags，必须先补充规范来源、字节样例和独立负例，再扩展 cases。

## 3. 连接控制事件

### 3.1 CONNECT

CONNECT 包的类型锚点为 `0x01`。其包体含版本、兼容版本、服务选项、协议特征、连接数据长度/偏移和连接数据等字段，但字段顺序、固定区长度和连接描述字符串会随 Oracle Net 版本与配置变化。本 v1 使用：

```json
{"type":"CONNECT","payload_profile":"connect_basic"}
```

`connect_basic` 是实现契约名，不是 wire（线上）字符串；planner 必须选择已登记的版本模板，计算实际长度，不得把 profile 名直接写入线上。

### 3.2 ACCEPT

ACCEPT 包的类型锚点为 `0x02`。服务器在 CONNECT 之后发送 ACCEPT；其版本、服务选项和数据长度等内部协商字段不得由本稿用零字节猜测。使用 `accept_basic` profile 只要求未来实现产生一个可解析的、与 CONNECT 版本兼容的 ACCEPT 包。

### 3.3 REFUSE

REFUSE 包的类型锚点为 `0x04`。服务端发送 REFUSE 后，该 session 不得继续发送 DATA；TCP 正常终止仍由公共层负责。`refuse_basic` 只固定事件类型和终止状态，不固定原因码/原因文本的版本相关编码。

### 3.4 REDIRECT

REDIRECT 包的类型锚点为 `0x05`。服务端发送 REDIRECT 后，当前 session 不得在同一连接继续发送 DATA。v1 只观察包类型；重定向地址及服务名的内部编码属于待实现边界。`reconnect=false` 时不自动创建第二条连接。

## 4. DATA、TTC 与 SQL*Net 会话

### 4.1 事件模型

应用层事件按配置顺序写入同一 TCP 流：

```text
CONNECT → ACCEPT → DATA(ttc_connect) → DATA(ttc_accept) →
DATA(sqlnet_request) → DATA(sqlnet_response)
```

每个 DATA 事件必须有 TNS header 和 2 字节 data flags。`payload_profile` 只表达已选择的未来模板，例如 `ttc_connect`、`ttc_accept`、`sqlnet_request`、`sqlnet_response`；它不把未经核实的 TTC 类型码、长度或 SQL 编码写进设计固定字节。不同 profile 的准确 payload 需由后续实现文档和失败优先测试共同定稿。

### 4.2 基础会话语义

- CONNECT/ACCEPT 成功后才允许 DATA；
- DATA 请求与响应在同一 4-tuple 上按事件顺序配对；
- `data_flags` 默认 0；
- SQLNET/TTC 负载可以为空或由实现 profile 产生，但 TNS `length` 必须仍等于实际包长度；
- 本设计不声称 DATA payload 可由 Wireshark（网络分析器）解析为某个具体 SQL 语句，除非实现阶段补充对应版本的标准/实测来源。

## 5. TCP/IP 载体与包数

### 5.1 层链

```text
[ {"tcp": { ... }}, {"tns": { ... }} ]
```

`tns` 为 Terminal（终结层），硬依赖 TCP；`[udp,tns]`、缺少 TCP、或在 TNS 后再放另一个终结层都必须拒绝。默认 `dst_port=1521`。

### 5.2 IPv4/IPv6

IP 版本由地址决定，TNS 字节不变。默认无 TCP option 时：

- IPv4 TNS header 起点：以太网 14 + IPv4 20 + TCP 20 = offset 54；
- IPv6 TNS header 起点：以太网 14 + IPv6 40 + TCP 20 = offset 74；
- DATA flags 起点分别为 62 和 82。

启用 TCP option 或 MSS（最大报文段）分段后，frame offset 只用于固定头部所在 TCP segment（分段）；完整 TNS 长度必须以 TCP stream reassembly（流重组）验证。

### 5.3 包数公式

在公共 TCP planner 的小 payload、无独立应用 ACK 约定下：

```text
packet_count = 3（握手） + len(events)（每事件一段） + 4（正常 FIN 终止）
```

REFUSE/REDIRECT 仍是正常应用事件后终止；它们不能继续生成 DATA。MSS 分段、纯 ACK 或异常 RST 属于实现阶段，若改变包数必须同步修订 design/testcase/JSON 三方。

## 6. 配置契约

顶层使用 `layers`，协议字段放 `tns`：

```json
{
  "layers": [{"tcp": {}}, {"tns": {}}],
  "src_ip": "10.0.0.1",
  "dst_ip": "20.0.0.1",
  "dst_port": 1521,
  "tns": {
    "events": [
      {"type": "CONNECT", "payload_profile": "connect_basic"},
      {"type": "ACCEPT", "payload_profile": "accept_basic"},
      {"type": "DATA", "data_flags": 0, "payload_profile": "ttc_connect"}
    ]
  }
}
```

| 键 | 类型 | 默认/约束 | 语义 |
|---|---|---|---|
| `events` | array | 至少 1；按序发送 | TNS 应用事件 |
| `type` | enum | CONNECT/ACCEPT/REFUSE/REDIRECT/DATA | 包头 type |
| `payload_profile` | string | 控制包须为已注册 profile | 未来 builder 的版本化负载模板名，不直接上 wire |
| `data_flags` | U16 | DATA 默认 0；v1 只允许 0 | DATA 包体前 2 字节 |
| `checksum_mode` | enum | `disabled` | v1 生成 packet/header checksum=0；非零算法待实现 |
| `sessions` | array | 默认 1；每项独立流 | 多会话配置 |
| `reconnect` | bool | false | REDIRECT/失败后是否新建连接；v1 不自动重连 |
| `wire_fault` | object | 仅负例 | 注入非法 type/length/checksum/载体，不代表合法 Oracle payload |

校验规则：

- events 非空；CONNECT 必须是首事件；ACCEPT/REFUSE/REDIRECT 只能由服务端方向出现；
- ACCEPT 之后才能出现 DATA；REFUSE/REDIRECT 后不得有任何事件；
- 每个事件由 planner 计算实际 payload 后再验证 `8 <= length <= 65535`；
- `data_flags != 0`、未知 profile、负长度、UDP 载体和显式 checksum 不匹配必须返回 task/config error（任务/配置错误），不能输出 0 包后报告成功。

## 7. 场景和测试映射

| 场景 | JSON id | 应用事件数 | packet_count | 确定性重点 |
|---|---|---:|---:|---|
| S1 基础连接和数据 | `tns_connect_accept` | 4 | 11 | CONNECT/ACCEPT/DATA，头部类型、长度非零、校验和零 |
| S2 拒绝 | `tns_refuse` | 2 | 9 | CONNECT→REFUSE，不能出现 DATA |
| S3 重定向 | `tns_redirect` | 2 | 9 | CONNECT→REDIRECT，当前流不自动重连 |
| S4 TTC/SQL*Net 基础 | `tns_ttc_sqlnet_session` | 6 | 13 | 4 个 DATA 的 flags=0，profile 顺序 |
| S5 IPv6 | `tns_ipv6_connect` | 2 | 9 | IPv6、offset 74、端口 1521 |
| S6 多会话 | `tns_multi_session` | 2×2 | 18 | 两条流各自 CONNECT/ACCEPT、端口隔离 |
| S7 头部/flags 基线 | `tns_header_fields` | 4 | 11 | length、两种 checksum、reserved、type、DATA flags |
| N1-N5 负例 | `tns_neg_*` | — | — | 仅 expect_error/error_contains |

## 8. 错误处理与安全边界

| 编号 | 输入 | 必须结果 | 用例 |
|---|---|---|---|
| E-01 | `[udp,tns]` | 拒绝，错误包含 `tcp` | `tns_neg_udp` |
| E-02 | 未知 packet type | 拒绝，错误包含 `type` | `tns_neg_packet_type` |
| E-03 | length 小于 8 或超过 U16 | 拒绝，错误包含 `length` | `tns_neg_length` |
| E-04 | 显式非零 checksum 与 disabled 模式冲突 | 拒绝，错误包含 `checksum` | `tns_neg_checksum` |
| E-05 | DATA flags 非零（v1 未注册） | 拒绝，错误包含 `data_flags` | `tns_neg_data_flags` |

REFUSE 原因码、REDIRECT 地址、CONNECT 固定区、ACCEPT 协商字段和 TTC/SQLNET 解析不作为当前负例的错误文本来源；这些属于后续实现契约，避免把猜测的 payload 当成规范。

## 9. 实现完成定义与待实现边界

后续实现必须：

1. 注册 TCP→TNS layer（层）；
2. 对每个 profile 提供标准来源或可复现抓包依据，单独列出字段偏移和长度；
3. 先为每个 Validate（校验）负路径写失败测试，再实现拒绝逻辑；
4. 以重组后的 TCP stream 验证 TNS length，不只看单个 segment；
5. 用 `go test -race -count=1`（竞态检测）和 API→engine→pcap 集成测试证明错误能传播到 task 终态；
6. 若 tshark 字段名与本设计契约不同，先更新 testcase 的可观测性映射，不静默删除断言。

尚未定稿：非零 checksum 算法、TNS 分片/重组、完整 CONNECT/ACCEPT/REFUSE/REDIRECT 包体、TTC 类型和 SQLNET 语义、认证/加密、listener 重定向后的第二连接、TCP option 导致的动态 frame offset。

## 10. 修订记录

- v1.0.0（2026-08-20）：建立 TNS 三件套设计；固定 8 字节包头、五类包类型和 DATA flags=0 基线，覆盖控制事件、TTC/SQL*Net 事件、IPv4/IPv6、多会话与五个负例；显式隔离未核实的 Oracle 版本相关 payload。
